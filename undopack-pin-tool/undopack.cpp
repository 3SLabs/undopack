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

#define MAP_START 0
#define MAP_END 0xffffffff

using namespace std;

//Appropriate Size of binary to be shadow mapped
// Currently its set according to the 32-bit system
UINT64 SIZE_ = 0xffffffff;

// Appropiate Offset for shadow image mapping can be set
// or set it to ZERO to let the mmap do its work and give
// us the appropriate address range
UINT64 OFFSET = 0;

// Pointer to SHADOW Memory array
// 1-to-1 mapping is used
char *SHADOW;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
		"o", "undopack.out", "specify trace file name");

// Output File stream
ofstream TraceFile;

// Pin calls this function every time a new img is loaded
// It can instrument the every image loaded
// Note that imgs (including shared libraries) are loaded lazily
VOID ImageLoad(IMG img, VOID *v)
{
	if(IMG_IsMainExecutable(img)==true)		// Check for main executable loading and logging it
	{
		TraceFile << "Main executable is loaded" << endl;
		return ;
	}
	if(!IMG_IsMainExecutable(img))			// Check for img ( other then main executable ) loading and logging it 
	{
		TraceFile << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) <<",Image Type: "<< IMG_Type(img)<<",Size :"<<IMG_SizeMapped(img)<< endl;
		// If Code is run on UNIX system
		TraceFile << "Start Address :" << hex <<IMG_StartAddress(img) <<"End Address :"<< hex <<IMG_HighAddress(img) << endl;
		// If Code is run on  WINDOWS system
		//TraceFile << "Start Address :" << hex <<IMG_LowAddress(img)<< "End Address :"<< hex <<IMG_HighAddress(img)<< endl;

		// position,Offset and address variable for main executable is 
		UINT64 Offset,position,address = 0;

		// Checking if the loading image's starting address and range 
		// belongs to the mapping of main executable
		if(IMG_StartAddress(img) > (UINT64)MAP_START && IMG_StartAddress(img) < (UINT64)MAP_END )
		{
			address = IMG_StartAddress(img) ;
			// Loop for setting the shadow memory of image getting loaded to
			// clean
			for(UINT64 i=0;i<IMG_SizeMapped(img);i++)
			{
				Offset = address>>3;
				position = 7 - (address&7);
				SHADOW[Offset] = (char )(SHADOW[Offset])&(~(1<<position));
				address++;
			}
		}
		else				// Logging if the image doesn't belong to main executable range
			TraceFile<<"Image doesn't lie in mapping range of main executable" << endl;
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

// function for logging the manupulation of memory
// Size , value and starting address of each memory manupulation
// is logged accoring to its Size
static VOID EmitMem(VOID * ea, INT32 size)
{
	switch(size)
	{
		case 0:
			TraceFile << setw(1) << endl;
			break;

		case 1:
			TraceFile << static_cast<UINT32>(*static_cast<UINT8*>(ea)) << endl;
			break;

		case 2:
			TraceFile << *static_cast<UINT16*>(ea) << endl;
			break;

		case 4:
			TraceFile << *static_cast<UINT32*>(ea)<<endl;
			break;

		case 8:
			TraceFile << *static_cast<UINT64*>(ea) << endl;
			break;

		default:
			TraceFile.unsetf(ios::showbase);
			TraceFile << setw(1) << "0x";
			for (INT32 i = 0; i < size; i++)
			{
				TraceFile << static_cast<UINT32>(static_cast<UINT8*>(ea)[i]) << endl;
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
		<< hex << setw(2+2*sizeof(ADDRINT)) << endl;
	if (!isPrefetch)
		EmitMem(addr, size);
	TraceFile << endl;
}

static VOID * WriteAddr;
static INT32 WriteSize;

// Function for recording the size and address of memory write
static VOID RecordWriteAddrSize(VOID * addr, INT32 size)
{
	WriteAddr = addr;
	WriteSize = size;
}


// Memory write instruction handler
static VOID RecordMemWrite(VOID * ip)
{
	UINT64 Offset,position ;
	UINT64 address = 0;
	// Checking if the write memory address belong to the mapping
	// of the main executable and if it is then change the corresponding
	// shadow memory bit to dirty [1]
	if((UINT64)WriteAddr > (UINT64)MAP_START && (UINT64)WriteAddr < (UINT64)MAP_END )
	{
		address = (UINT64)WriteAddr ;
		// Loop for setting the shadow memory address to dirty
		for(INT32 i=0;i<WriteSize;i++)
		{
			Offset = (INT32)(address>>3);
			position = 7 - (address&7);
			SHADOW[Offset] = (char )(SHADOW[Offset]|(1<<position));
			address++;
		}
		// Function call to log everything about the memory write
		RecordMem(ip, 'W', WriteAddr, WriteSize, false);
	}
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
//			HANDLER FUNCTIONS	 				//////
//////////////////////////////////////////////////////////////////////////////////////

// Handler function to track all execution flow change instruction 
// log their Instruction Pointer address and destination address
// and the type of instruction

// NOT USED AND CAN BE REMOVED

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
// logs about the syscall used , syscall no is logged.
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
/* Instrumentation function for Memory write and Execution flow change   */
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
		if (INS_IsBranchOrCall(ins))		// checking for direct and indirect memory branch
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

//// Incomplete

// Counter to count the number of layers dumped
int dumpno = 0;

// Function to Dump the unpacked layer of packed binary
// in a file . Only those memory address range is dump which
// has dirty bit[1] corresponding to the its address in shadow memory
VOID DumpBinary()       
{
	ofstream dumpfile;
	char dumpyfile[30] = "dump_",buff1[10];
	snprintf(buff1, sizeof(buff1), "%d", dumpno);
	strcat(dumpyfile,buff1);
	dumpno++;
	dumpfile.open(dumpyfile);
	UINT64 Offset,position ;
	TraceFile << "Dumping layer " << dumpno << "in file : " << dumpyfile << endl;
	for(UINT64 i=0;i<SIZE_; i++)
	{
		Offset = i>>3;
		position =  7 - (i & 7);
		if(((SHADOW[Offset] >> position)&1)!=0)
		{
			dumpfile<<(((unsigned char) *(unsigned char*)(i)));
		}
	}
	dumpfile.close();
	return;
}

// Instrumentation function - Called for each Basic Block only once
// this function checks if the present basic block address range has
// any dirty bit set in the corresponding SHADOW memory space and if
// it has dirty bit set then it dumps the layer
VOID bbladdress(VOID *Start , UINT32 End)
{
	TraceFile << "Start Address :" << hex << Start << "Size :" << hex << End << endl;
	UINT64 Offset,position ;
	UINT64 address = 0;
	// checking if the address belong to the mapping range of
	// main executable .
	if((UINT64)Start> MAP_START && (UINT64)Start < (UINT64)MAP_END )
	{
		address = (UINT64)Start ;
		for(UINT64 i=0;i<(UINT64)End;i++)
		{
			Offset = address>>3;
			position = 7 - (address&7);
			if(((SHADOW[Offset] >> position)&1)!=0)
			{
				/// Dump the next layer of the packed executables
				DumpBinary();               
				TraceFile << "Original Entry Point :" << hex << Start << endl;
				cout << "Original Entry Point : " << hex << Start << endl;
				// Setting the shadow memory to zero again after every
				// dump of unpacked layer
				memset((void *)SHADOW , 0 , (SIZE_/8)*sizeof(char));
				return;
			}
			address++;
		}
	}
}

// Pin calls this function every time a new basic block is encountered
// It inserts a call to bbladdress function after the end of every basic block execution
VOID Trace(TRACE trace, VOID *v)
{
	// Visit every basic block  in the trace
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		// Insert a call to docount before every bbl, passing the number of instructions
		BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)bbladdress,  IARG_ADDRINT,BBL_Address(bbl),IARG_UINT32 ,BBL_Size(bbl), IARG_END);
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

	// Mapping of shadow memory
	SHADOW = (char *)mmap((void *)NULL , (size_t)SIZE_>>3 , PROT_READ | PROT_WRITE , MAP_SHARED|MAP_ANONYMOUS,4,0);
	// setting shadow memory to ZERO as whole shadow memory is clean initially
	memset((void *)SHADOW , 0 , (SIZE_/8)*sizeof(char));
	if((caddr_t)SHADOW == (caddr_t)-1)
	{
		perror("SHADOW Memory mapping");
		return 0;
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
