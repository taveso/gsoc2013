#!/usr/bin/python

import sys
from optparse import OptionParser
from os import listdir
from collections import deque
import commands
import random
import time

# command line arguments
tshark = ""
editcap = ""
pin = ""
pintool = ""
menagerie = ""

fuzzed_captures_dir = "fuzzed-captures"
err_prob = 0.02
AAA = 4

fuzzing_queue = None
taken_branches = set()
pcap_region_dict = {}

def edit_pcap(pcap, region_start, region_end):
	new_pcap = "%s/%s-%f" % (fuzzed_captures_dir, pcap, time.time())	
	commands.getoutput("%s -E %d -X %d -Y %d %s/%s %s/%s" % (editcap, err_prob, region_start, region_end, menagerie, pcap, menagerie, new_pcap))	
	return new_pcap
		
def smartly_fuzz_pcap(pcap):
	new_captures = []
	
	print 'regions:\t %d' % len(pcap_region_dict.values())
	
	for region in pcap_region_dict.values():
		region_start, region_end = region
		
		new_pcap = edit_pcap(pcap, region_start, region_end)
		if new_pcap != None:
			new_captures.append(new_pcap)
	
	return new_captures
	
def get_pcap_size(pcap):
	size = commands.getoutput("wc -c < %s/%s" % (menagerie, pcap))
	return int(size)
	
def randomly_fuzz_pcap(pcap):
	new_captures = []	
	
	pcap_size = get_pcap_size(pcap)	
	for i in range(AAA):
		region_start = random.randint(0, pcap_size)
		region_end = random.randint(0, pcap_size)
		if region_start > region_end:
			region_start, region_end = region_end, region_start
			
		new_pcap = edit_pcap(pcap, region_start, region_end)
		if new_pcap != None:
			new_captures.append(new_pcap)
			pcap_region_dict[new_pcap] = (region_start, region_end)
		
	return new_captures
	
def path_is_new(branches):
	for branch in branches:
		if branch not in taken_branches:
			return True			
	return False

def get_pcap_path(pcap):
	commands.getoutput("%s -injection child -t %s -- %s -nVxr %s/%s > /dev/null" % (pin, pintool, tshark, menagerie, pcap))	
	branches = [line.strip() for line in open("MyPinTool.out")]
	return branches
	
def process_pcap(pcap, test):
	global taken_branches
	
	if pcap in pcap_region_dict:
		print 'process_pcap:\t %s (%s) [%d,%d]' % (pcap, test, pcap_region_dict[pcap][0], pcap_region_dict[pcap][1])
	else:
		print 'process_pcap:\t %s (%s)' % (pcap, test)
	
	branches = get_pcap_path(pcap)
	
	if path_is_new(branches):
		if pcap in pcap_region_dict:
			print '\033[92mpath_is_new:\t %s (%s) [%d,%d]\033[0m' % (pcap, test, pcap_region_dict[pcap][0], pcap_region_dict[pcap][1])
		else:
			print '\033[92mpath_is_new:\t %s (%s)\033[0m' % (pcap, test)
		fuzzing_queue.append(pcap)
	else:
		if pcap in pcap_region_dict:
			del pcap_region_dict[pcap]
			
	taken_branches |= set(branches)

def fuzz_pcap(pcap):
	process_pcap(pcap, "menagerie")
	
	random_captures = randomly_fuzz_pcap(pcap)
	for capture in random_captures:
		process_pcap(capture, "random")
	
	smart_captures = smartly_fuzz_pcap(pcap)
	for capture in smart_captures:
		process_pcap(capture, "smart")
			
def file_is_pcap(filename):
	error = commands.getoutput("capinfos %s/%s > /dev/null" % (menagerie, filename))
	if error:
		return False		
	return True
			
def seed_fuzzing_queue():
	global fuzzing_queue

	files = listdir(menagerie)
	fuzzing_queue = deque(files)
			
def shinra_tensei():
	seed_fuzzing_queue()
	commands.getoutput("mkdir %s/%s" % (menagerie, fuzzed_captures_dir))	
	
	while fuzzing_queue:
		filename = fuzzing_queue.popleft()
		if file_is_pcap(filename):
			fuzz_pcap(filename)

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

def main():
	parse_cmd()
	shinra_tensei()
	
if __name__ == "__main__":
    main()
