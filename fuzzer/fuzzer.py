#!/usr/bin/python

import sys
from optparse import OptionParser
from collections import deque
import os
import commands
import subprocess
import random
import time

# command line arguments
tshark = ""
editcap = ""
pin = ""
pintool = ""
menagerie = ""

# the destination directory of the fuzzed capture files
fuzzed_captures_dir = "/tmp"
# the destination directory of the crash capture files
crash_captures_dir = ""
# the error probability of Editcap
err_prob = 0.02
# the number of random fuzz per capture file of the fuzzing queue
total_rand_fuzz_per_cap = 2

# the fuzzing queue containing the capture files to fuzz
fuzzing_queue = deque()
# the branches we have already taken in the execution path of the fuzzed process
taken_branches = set()
# dictionary of dictionaries which keys are types of capture files.
# The value associated with each type of capture file is a dictionary which keys are names of capture files originating from a random fuzzing.
# The value associated with each capture file is a tuple containing the start and end offsets of the fuzzed region.
type_cap_region_dict = {}
# dictionary which keys are names of capture files.
# The value associated with each capture file is its type.
# (editcap overwrites the type of the capture files with a default value and does not support all the types of the menagerie capture files)
cap_type_dict = {}

## Read the execution path of a capture file and determine whether it is new.
#  @param[in]	branches	execution path of the capture file
#  @return		true if the execution path is new, false otherwise
def path_is_new(branches):
	for branch in branches:
		if branch not in taken_branches:
			return True			
	return False

## Read the execution path of a capture file.
#  @param[in]	cap	capture file to process
#  @return		the execution path of the capture file
def cap_path(cap):
	cmd = "%s -injection child -t %s -- %s -nVxr %s > /dev/null" % (pin, pintool, tshark, cap)	
	retcode = subprocess.call(cmd, shell=True)
	
	if (retcode > 0):
		print "\033[93mTShark returned %d while processing %s\033[0m" % (retcode, cap) # 139 for segmentation fault
		commands.getoutput("cp %s %s/%s" % (cap, crash_captures_dir, filename(cap)))
	
	branches = [line.strip() for line in open("MyPinTool.out")]
	return branches
	
## Read the execution path of a capture file, 
## queue the capture file in the fuzzing queue if the execution path is new
## and store the execution path in the global taken_branches set.
#  @param[in]	cap	capture file to process
#  @param[in]	src	source of the capture file: either menagerie or random (fuzzing) or smart (fuzzing)
def process_cap(cap, src):
	global fuzzing_queue, taken_branches
	
	cap_t = cap_type_dict[cap]
	if cap in type_cap_region_dict[cap_t]:
		print 'process_cap:\t %s (%s) [%d,%d]' % (cap, src, type_cap_region_dict[cap_t][cap][0], type_cap_region_dict[cap_t][cap][1])
	else:
		print 'process_cap:\t %s (%s)' % (cap, src)
	
	branches = cap_path(cap)
	
	if path_is_new(branches):
		print '\033[92mpath_is_new:\t %s (%s)\033[0m' % (cap, src)
		fuzzing_queue.append(cap)
	else:
		commands.getoutput("rm %s" % cap)
		
		del cap_type_dict[cap]
		
		# if the capture file originates from a random fuzzing we will not remember the region for further testing
		if cap in type_cap_region_dict[cap_t]:
			del type_cap_region_dict[cap_t][cap]
			
	taken_branches |= set(branches)

## Fuzz a region of a capture file using Editcap.
#  @param[in]	cap	capture file to fuzz
#  @param[in]	region_start	start offset of the region
#  @param[in]	region_end	end offset of the region
#  @return		the fuzzed capture file
def edit_cap_region(cap, region_start, region_end):
	new_cap = "%s/%s-%f" % (fuzzed_captures_dir, filename(cap), time.time())
	commands.getoutput("%s -E %f -X %d -Y %d %s %s" % (editcap, err_prob, region_start, region_end, cap, new_cap))
	
	cap_type_dict[new_cap] = cap_type_dict[cap]
	
	return new_cap
		
## Fuzz regions of a capture file, thus creating new capture files. 
## The regions are know to affect the execution path of TShark.
#  @param[in]	cap	capture file to fuzz
#  @return		the fuzzed capture files
def smartly_fuzz_cap(cap):
	new_captures = []
	
	cap_t = cap_type_dict[cap]
	print 'regions:\t %d' % len(type_cap_region_dict[cap_t])
	
	regions = type_cap_region_dict[cap_t].values()
	for region in regions:
		region_start, region_end = region		
		new_cap = edit_cap_region(cap, region_start, region_end)
		new_captures.append(new_cap)
	
	return new_captures

## Get file size in bytes.
#  @param[in]	cap	file to process
#  @return		the file size
def cap_size(cap):
	size = commands.getoutput("wc -c < %s" % cap)
	return int(size)
	
## Fuzz random regions of a capture file, thus creating new capture files.
#  @param[in]	cap	capture file to fuzz
#  @return		the fuzzed capture files
def randomly_fuzz_cap(cap):
	new_captures = []	
	
	cap_s = cap_size(cap)
	for i in range(total_rand_fuzz_per_cap):
		region_start = random.randint(0, cap_s)
		region_end = random.randint(0, cap_s)
		if region_start > region_end:
			region_start, region_end = region_end, region_start
			
		new_cap = edit_cap_region(cap, region_start, region_end)
		new_captures.append(new_cap)
		
		new_cap_type = cap_type_dict[new_cap]
		if new_cap_type not in type_cap_region_dict:
			type_cap_region_dict[new_cap_type] = {}
		type_cap_region_dict[new_cap_type][new_cap] = (region_start, region_end)
		
	return new_captures

## Fuzz a capture file, thus creating new capture files, and process them with TShark.
#  @param[in]	cap	capture file to fuzz
def fuzz_cap(cap):
	# randomly fuzz
	random_captures = randomly_fuzz_cap(cap)
	for capture in random_captures:
		process_cap(capture, "random")
	
	# smartly fuzz
	smart_captures = smartly_fuzz_cap(cap)
	for capture in smart_captures:
		process_cap(capture, "smart")
		
## Read the type of a capture file.
#  @param[in]	cap	capture file to process
#  @return		type of the capture file
def cap_type(cap):
	return commands.getoutput("capinfos %s | grep \"File type\" | sed 's/\s\s*/ /g' | cut -d \" \" -f3-" % cap)
		
## Extract file name from path.
#  @param[in]	f file path
#  @return		the file name
def filename(f):
	return f.rsplit('/', 1)[1]
	
## Process a capture file with Editcap (without options).
## The data of the capture file remains unchanged but the output file size is bigger.
#  @param[in]	cap	capture file to process
#  @return		Editcap	output file
def edit_cap(cap):
	new_cap = "%s/%s" % (fuzzed_captures_dir, filename(cap))	
	commands.getoutput("%s %s %s" % (editcap, cap, new_cap))	
	
	cap_type_dict[new_cap] = cap_type(cap)
	
	return new_cap
	
## Check if a file is a capture file.
#  @param[in]	f	file to process
#  @return		true if f is a capture file, false otherwise	
def file_is_cap(f):
	error = commands.getoutput("capinfos %s > /dev/null" % f)
	if error:
		return False		
	return True
		
## Process the menagerie capture files with Editcap (without options) and seed the fuzzing queue with the resulting captures files.
def seed_fuzzing_queue():
	global fuzzing_queue
	
	for dirpath, dirnames, filenames in os.walk(menagerie):
		for filename in filenames:
			f = os.path.join(dirpath, filename)
			if file_is_cap(f):
				fuzzing_queue.append(edit_cap(f))

## Run the fuzzing algoritm.		
def shinra_tensei():
	# seed the fuzzing queue with the menagerie capture files
	seed_fuzzing_queue()
	
	# get the next capture file to fuzz from the fuzzing queue until there is no more capture file to process
	while fuzzing_queue:
		f = fuzzing_queue.popleft()
		if file_is_cap(f):
			fuzz_cap(f)

## Parse command line options.			
def parse_cmd():
	global pin, pintool, menagerie, tshark, editcap

	parser = OptionParser()
	parser.add_option("-p", "--pin", dest="pin", help="location of pin")
	parser.add_option("-t", "--pintool", dest="pintool", help="location of the pintool")
	parser.add_option("-m", "--menagerie", dest="menagerie", help="location of the menagerie")
	parser.add_option("-b", "--tshark", dest="tshark", help="location of TShark")
	parser.add_option("-e", "--editcap", dest="editcap", help="location of Editcap")
	
	(options, args) = parser.parse_args()
	
	if (options.pin == None or options.pintool == None or options.menagerie == None or options.tshark == None or options.editcap == None):
		print "for help use --help"
		sys.exit(2)
		
	pin = options.pin
	pintool = options.pintool
	menagerie = options.menagerie
	tshark = options.tshark
	editcap = options.editcap
	
	crash_captures_dir = "%s/crash" % menagerie
	commands.getoutput("mkdir %s" % crash_captures_dir)

def main():
	parse_cmd()
	shinra_tensei()
	
if __name__ == "__main__":
    main()
