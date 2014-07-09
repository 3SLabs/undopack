#include "pin.H"
#include "portability.H"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <map>
#include <unistd.h>
#include <vector>
#include <string>
#include <stdint.h>
#include <sstream>
#include <sys/mman.h>
#include <sys/types.h>
#include <cstdio>
#include <cstdlib>
#include <string.h>

#ifndef MAP_ANONYMOUS
#  define MAP_ANONYMOUS MAP_ANON
#endif

using namespace std;

unsigned int SIZE = 0xffffffff;
long long unsigned int OFFSET = 0X800000000000;
char *SHADOW;


/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "undopack.out", "specify trace file name");
KNOB<BOOL> KnobValues(KNOB_MODE_WRITEONCE, "pintool",
    "values", "1", "Output memory values reads and written");

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
        //TraceFile << "Start Address :" << hex <<IMG_LowAddress(img)<< "End Address :"<< hex <<IMG_HighAddress(img)<< endl;
        UINT32 Offset,position;
        UINT64 address = IMG_StartAddress(img);
        for(int i=0;i<IMG_SizeMapped(img);i++)
        {
            Offset = address>>3;
            position = 7 - (address&7);
            SHADOW[Offset] = (char )(SHADOW[Offset])&(~(1<<position));
            address++;
        }
    }
}

// Pin calls this function every time a new img is unloaded
// You can't instrument an image that is about to be unloaded
VOID ImageUnload(IMG img, VOID *v)
{
    TraceFile << "Unloading " << IMG_Name(img) << endl;
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR("This tool extracts the packed executable\n"
             + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

static VOID EmitMem(VOID * ea, INT32 size)
{
    if (!KnobValues)
        return;
    
    switch(size)
    {
      case 0:
        TraceFile << setw(1);
        break;
        
      case 1:
        TraceFile << static_cast<UINT32>(*static_cast<UINT8*>(ea));
        break;
        
      case 2:
        TraceFile << *static_cast<UINT16*>(ea);
        break;
        
      case 4:
        TraceFile << *static_cast<UINT32*>(ea);
        break;
        
      case 8:
        TraceFile << *static_cast<UINT64*>(ea);
        break;
        
      default:
        TraceFile.unsetf(ios::showbase);
        TraceFile << setw(1) << "0x";
        for (INT32 i = 0; i < size; i++)
        {
            TraceFile << static_cast<UINT32>(static_cast<UINT8*>(ea)[i]);
        }
        TraceFile.setf(ios::showbase);
        break;
    }
}

/// Loging memory operations

static VOID RecordMem(VOID * ip, CHAR r, VOID * addr, INT32 size, BOOL isPrefetch)
{
    TraceFile << ip << ": " << r << " " << setw(2+2*sizeof(ADDRINT)) << addr << " "
              << dec << setw(2) << size << " "
              << hex << setw(2+2*sizeof(ADDRINT));
    if (!isPrefetch)
        EmitMem(addr, size);
    TraceFile << endl;
}

static VOID * WriteAddr;
static INT32 WriteSize;

static VOID RecordWriteAddrSize(VOID * addr, INT32 size)
{
    WriteAddr = addr;
    WriteSize = size;
}


// Memory write instruction handler
static VOID RecordMemWrite(VOID * ip)
{
    UINT32 Offset,position ;
    UINT64 address = WriteAddr;
    for(int i=0;i<WriteSize;i++)
    {
        Offset = (address>>3);
        position = 7 - (address&7);
        SHADOW[Offset] = (char )(SHADOW[Offset]|(1<<position));
        address++;
    }
    RecordMem(ip, 'W', WriteAddr, WriteSize, false);
}

///////////////////////////////////////////////////////////////////////////////
////		Class for storing all exection flow change instructions			///
///////////////////////////////////////////////////////////////////////////////


class COUNTER
{
  public:
    UINT64 _call;
    UINT64 _call_indirect;
    UINT64 _return;
    UINT64 _syscall;
    UINT64 _branch;
    UINT64 _branch_indirect;    

    COUNTER() : _call(0),_call_indirect(0), _return(0), _branch(0), _branch_indirect(0)   {}

    UINT64 Total()
    {
        return _call + _call_indirect + _return + _syscall + _branch + _branch_indirect;
    }
};

COUNTER CountSeen;
COUNTER CountTaken;

//////////////////////////////////////////////////////////////////////////////////////
//							HANDLER FUNCTIONS 										//
//////////////////////////////////////////////////////////////////////////////////////

static VOID inc_return(VOID *ip,VOID *retn, BOOL istaken)	// handler for retn instruction
{
    if(istaken)
    {
       	TraceFile<< ip<<":"<< "RETN" <<""<<setw(2+2*sizeof(ADDRINT))<< hex << retn << endl;
        CountTaken._return++;
    }
    CountSeen._return++;
}
static VOID inc_call(VOID *ip,VOID *target, BOOL istaken)	// handler for call instruction
{
    if(istaken)
    {
        TraceFile<< ip<<":"<< "CALL" <<""<<setw(2+2*sizeof(ADDRINT))<< hex << target << endl;
        CountTaken._call++;
    }
    CountSeen._call++;
}
static VOID inc_call_indirect(VOID *ip,VOID *target, BOOL istaken)		// handler for indirect catch instruction
{
    if(istaken)
    {
        TraceFile<< ip<<":"<< "IND_CALL" <<""<<setw(2+2*sizeof(ADDRINT))<< hex << target << endl;
        CountTaken._call_indirect++;
    }
    CountSeen._call_indirect++;
}
static VOID inc_branch(VOID *ip,VOID *target, BOOL istaken)			// handler for branch instruction
{
    if(istaken)
    {
        TraceFile<< ip<<":"<< "JUMP" <<""<<setw(2+2*sizeof(ADDRINT))<< hex << target << endl;
        CountTaken._branch++;
    }
    CountSeen._branch++;
}
static VOID inc_branch_indirect(VOID *ip,VOID *target, BOOL istaken)	// handler for indirect branch instruction
{
    if(istaken)
    {
        TraceFile<< ip<<":"<< "IND_JUMP" <<""<<setw(2+2*sizeof(ADDRINT))<< hex << target << endl;
        CountTaken._branch_indirect++;
    }
    CountSeen._branch_indirect++;
}
static VOID inc_syscall(VOID *ip,VOID *sysno, BOOL istaken)				// handler for syscall instruction
{
    if(istaken)
    {
        TraceFile<< ip<<":"<< "syscall" <<""<<setw(2+2*sizeof(ADDRINT))<< hex << sysno << endl;
        CountTaken._syscall++;
    }
    CountSeen._syscall++;
}

    


/* ===================================================================== */

VOID Instruction(INS ins, VOID *v)
{
	// Instrumentation for Execution flow change
	if( INS_IsRet(ins) )		// Catching retn instruction
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_return, IARG_INST_PTR ,IARG_FALLTHROUGH_ADDR, IARG_BRANCH_TAKEN,  IARG_END);
    }
    else if( INS_IsSyscall(ins) )	// catching execution flow change through syscall
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_syscall,IARG_INST_PTR,IARG_SYSCALL_NUMBER , IARG_BRANCH_TAKEN,  IARG_END);
    }
    else if (INS_IsDirectBranchOrCall(ins))		// catching direct call or jump
    {
        if( INS_IsCall(ins) )
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_call,IARG_INST_PTR ,IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_END);
        else
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_branch,IARG_INST_PTR ,IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_END);
    }
    else if( INS_IsIndirectBranchOrCall(ins) )		// catching indirect call or jump
    {
        if( INS_IsCall(ins) )
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_call_indirect,IARG_INST_PTR ,IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_END);
        else
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) inc_branch_indirect,IARG_INST_PTR ,IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_END);
    }

    // instruments loads using a predicated call, i.e.
    // the call happens iff the load will be actually executed
        
    if (INS_IsMemoryRead(ins))	// catching memory read
    {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
            IARG_INST_PTR,
            IARG_UINT32, 'R',
            IARG_MEMORYREAD_EA,
            IARG_MEMORYREAD_SIZE,
            IARG_BOOL, INS_IsPrefetch(ins),
            IARG_END);
    }

    if (INS_HasMemoryRead2(ins))	// catching indirect memory read
    {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
            IARG_INST_PTR,
            IARG_UINT32, 'R',
            IARG_MEMORYREAD2_EA,
            IARG_MEMORYREAD_SIZE,
            IARG_BOOL, INS_IsPrefetch(ins),
            IARG_END);
    }

    // instruments stores using a predicated call, i.e.
    // the call happens iff the store will be actually executed
    if (INS_IsMemoryWrite(ins))				// catching memory write
    {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteAddrSize,
            IARG_MEMORYWRITE_EA,
            IARG_MEMORYWRITE_SIZE,
            IARG_END);
        
        if (INS_HasFallThrough(ins))		// checking for fall back address
        {
            INS_InsertCall(
                ins, IPOINT_AFTER, (AFUNPTR)RecordMemWrite,
                IARG_INST_PTR,
                IARG_END);
        }
        if (INS_IsBranchOrCall(ins))		// checking for call and jmp instruction
        {
            INS_InsertCall(
                ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordMemWrite,
                IARG_INST_PTR,
                IARG_END);
        }
        
    }
}
/* ===================================================================== */

#define OUT(n, a, b) TraceFile << n << " " << a << setw(16) << CountSeen. b  << " " << setw(16) << CountTaken. b << endl

// This function is called when the application exits
// It closes the output file.

VOID Fini(int n, void *v)
{
    SetAddress0x(1);


    TraceFile << "# JUMPMIX\n";
    TraceFile << "#\n";
    TraceFile << "# $dynamic-counts\n";
    TraceFile << "#\n";
    

    
    TraceFile << "4000 *total "  << setw(16) << CountSeen.Total() << " " << setw(16) << CountTaken.Total() << endl;
    
        
    OUT(4010, "call            ",_call);
    OUT(4011, "indirect-call   ",_call_indirect);
    OUT(4012, "branch          ",_branch);
    OUT(4013, "indirect-branch ",_branch_indirect);
    OUT(4014, "syscall         ",_syscall);
    OUT(4015, "return          ",_return);

    TraceFile << "#\n";
    TraceFile << "# eof\n";
    if (TraceFile.is_open())
    { 
    	TraceFile.close();
    }
    
}
// Instrumentation function - Called for each Basic Block only once
VOID bbladdress(VOID *Start , VOID *End)
{
	TraceFile << "Start Address :" << hex << Start << "Size :" << hex << End << endl;
}

// Pin calls this function every time a new basic block is encountered
// It inserts a call to docount

VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block  in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to docount before every bbl, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)bbladdress, BBL_Address(bbl),BBL_Size(bbl), IARG_END);
    }
}


/* ===================================================================== */
/* Main Function                                                                 */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize symbol processing
    PIN_InitSymbols();
    
    // Initialize pin
    if (PIN_Init(argc, argv)) 
    	return Usage();
    SHADOW = (char *)mmap((void *)OFFSET , (size_t)SIZE>>3 , PROT_READ | PROT_WRITE , MAP_SHARED|MAP_ANONYMOUS,4,0);
    memset((void *)SHADOW , 0 , (SIZE/8)*sizeof(char));
    if((caddr_t)SHADOW == (caddr_t)-1)
    {
        perror("SHADOW Memory mapping");
        return;
    }

    // File initialization	- For Logs
    TraceFile.open(KnobOutputFile.Value().c_str());

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register Instruction to be called when an instruction is executed
    INS_AddInstrumentFunction(Instruction, 0);
    
    // Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();

    RecordMemWrite(0);
    RecordWriteAddrSize(0, 0);
    
    
    return 0;
}
