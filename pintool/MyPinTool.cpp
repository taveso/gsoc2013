#include <vector>
#include <string>
#include <set>
#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <iostream>

#include "pin.H"

using namespace std;

// names of the application images (instrumented executable and shared libraries)
vector<string> app_imgs_names;
// lowest and highest addresses of the application images
vector<pair<ADDRINT, ADDRINT> > app_imgs_bound_addr;

set<ADDRINT> taken_branches;

/*!
 * Store the addresses of the taken branches into a file.
 * This function is called before the application exits.
 */
void store_addresses()
{
	ofstream outfile;
	
	// open the output file
	outfile.open("MyPinTool.out");
	if (!outfile) {
		perror("fopen");
  		exit(EXIT_FAILURE);
	}
	
	// store the addresses into the output file
	set<ADDRINT>::const_iterator first(taken_branches.begin()), last(taken_branches.end());
	while (first != last)
		outfile << hex << *first++ << endl;
	
	// close the output file
	outfile.close();
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Memorize branchAddress if it belongs to one of the application images.
 * This function is called for every taken branch.
 * @param[in]	branchAddress	application address of the taken branch
 */
VOID CollectJmp(ADDRINT branchAddress)
{
	vector<pair<ADDRINT, ADDRINT> >::const_iterator begin(app_imgs_bound_addr.begin()), end(app_imgs_bound_addr.end());
	for (; begin != end; ++begin)
	{
		if (branchAddress >= (*begin).first && branchAddress <= (*begin).second) {
			taken_branches.insert(branchAddress);
			break;
		}
	}
}

/* ===================================================================== */
// Instrumentation routines
/* ===================================================================== */

/*!
 * Get the lowest and highest addresses of the application images.
 * This function is called every time an image is loaded.
 * @param[in]	img		image to be instrumented
 * @param[in]	v		value specified by the tool in the IMG_AddInstrumentFunction function call
 */
VOID ImageLoad(IMG img, VOID *v)
{
	string img_name = IMG_Name(img);
	
	vector<string>::const_iterator first(app_imgs_names.begin()), last(app_imgs_names.end());
	for (; first != last; ++first)
	{
		if (img_name.find(*first) != string::npos) {
			app_imgs_bound_addr.push_back(make_pair(IMG_LowAddress(img), IMG_HighAddress(img)));
			break;
		}
	}
}

/*!
 * Insert a call to CollectJmp() after each branch. The call only executes if the branch is taken.
 * This function is called every time a new instruction is encountered.
 * @param[in]	ins		instruction to be instrumented
 * @param[in]	v		value specified by the tool in the INS_AddInstrumentFunction function call
 */
VOID Instruction(INS ins, void *v)
{
    if (INS_IsBranch(ins))
    {
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)CollectJmp, IARG_INST_PTR, IARG_END);       
    }
}

/*!
 * Store the addresses of the taken branches into a file.
 * This function is called immediately before the application exits.
 * @param[in]	code	O/S specific termination code for the application
 * @param[in]	v		value specified by the tool in the PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
	store_addresses();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
	cerr << "This Pintool collects the control flow of an application\n" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return EXIT_FAILURE;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

/*!
 * Initialize the names of the application images.
 */
void init_app_imgs_names()
{
	app_imgs_names.push_back("tshark");
	app_imgs_names.push_back("libwiretap");
	app_imgs_names.push_back("libwireshark");
	app_imgs_names.push_back("libwsutil");
}

int main(int argc, char* argv[])
{
	// initialize the names of the application images
	init_app_imgs_names();

	// initialize symbol processing
    PIN_InitSymbols();

	// initialize pin
	if (PIN_Init(argc, argv)) return Usage();
	
	// register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);
   	
   	// register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);
    
    // register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    	
    // start the program
    PIN_StartProgram();
    
    return 0;
}
