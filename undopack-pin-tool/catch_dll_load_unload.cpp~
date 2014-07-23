#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>

using namespace std;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "imageload.out", "specify file name");

ofstream TraceFile;

// Pin calls this function every time a new img is loaded
// It can instrument the image, but this example does not
// Note that imgs (including shared libraries) are loaded lazily

VOID ImageLoad(IMG img, VOID *v)
{
    if(!IMG_IsMainExecutable(img))
    {
        TraceFile << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) <<",Image Type: "<< IMG_Type(img)<<",Size :"<<IMG_SizeMapped(img)<<""<< endl;
        // IF UNIX
        TraceFile << "Start Address :" << hex <<IMG_StartAddress(img) <<"End Address :"<< hex <<IMG_HighAddress(img) << endl;
        // IF WINDOWS
        TraceFile << "Start Address :" << hex <<IMG_LowAddress(img)<< "End Address :"<< hex <<IMG_HighAddress(img)<< endl;
    }
}

// Pin calls this function every time a new img is unloaded
// You can't instrument an image that is about to be unloaded
VOID ImageUnload(IMG img, VOID *v)
{
    TraceFile << "Unloading " << IMG_Name(img) << endl;
}

// This function is called when the application exits
// It closes the output file.
VOID Fini(INT32 code, VOID *v)
{
    if (TraceFile.is_open()) { TraceFile.close(); }
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR("This tool prints a log of image load and unload events\n"
             + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize symbol processing
    PIN_InitSymbols();
    
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
    
    TraceFile.open(KnobOutputFile.Value().c_str());
    
    // Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}