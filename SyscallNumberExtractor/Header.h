#pragma once

#include "windows.h"


#define ulong unsigned long
#define ulonglong unsigned long long
#define longlong long long
#define ULONG unsigned long
#define ULONGLONG unsigned long long
#define ushort unsigned short
#define USHORT unsigned short
#define uchar unsigned char
#define UCHAR unsigned char


#define MAX_ARGS 20 // 18 == for ==> Windows 7/10, check KiSystemServiceCopyStart


//Limited to 20 arguments max
typedef longlong(*MYFUNC)(ulonglong A1,
					ulonglong A2,
					ulonglong A3,
					ulonglong A4,
					ulonglong A5,
					ulonglong A6,
					ulonglong A7,
					ulonglong A8,
					ulonglong A9,
					ulonglong A10,
					ulonglong A11,
					ulonglong A12,
					ulonglong A13,
					ulonglong A14,
					ulonglong A15,
					ulonglong A16,
					ulonglong A17,
					ulonglong A18,
					ulonglong A19,
					ulonglong A20);

MYFUNC CreateFunction(unsigned long SyscallNumber);
void ModifyFunction(MYFUNC pFunc,unsigned long SyscallNumber);
void DestroyFunction(MYFUNC pFunc);


struct _SYSCALL_EXTRACTOR_THREAD
{
	MYFUNC pFunc;
	unsigned long long* Args;
	ulonglong SyscallNo;
	int retValue;
};


struct _FOUND_SYSCALL_INFO
{
	ulonglong SyscallNumber;
	uchar* FunctionAddress;
	char* FunctionName;
};


ulonglong ExtractSyscallNumberFromCode(uchar* pCode);
unsigned long GetSyscallCount_i(MYFUNC pFunc,bool bWin32k);