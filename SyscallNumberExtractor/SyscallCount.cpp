#include "stdafx.h"
#include "windows.h"
#include "Header.h"

uchar* addr_ZwSetDefaultLocale;
ulonglong Syscall_ZwSetDefaultLocale;


void ThreadSyscall(_SYSCALL_EXTRACTOR_THREAD* pSyscallThread)
{
	memset(			pSyscallThread->Args,
					0xCC,
					MAX_ARGS*sizeof(ulonglong));

	pSyscallThread->retValue = 
					pSyscallThread->pFunc
					(pSyscallThread->Args[0],
					pSyscallThread->Args[1],
					pSyscallThread->Args[2],
					pSyscallThread->Args[3],
					pSyscallThread->Args[4],
					pSyscallThread->Args[5],
					pSyscallThread->Args[6],
					pSyscallThread->Args[7],
					pSyscallThread->Args[8],
					pSyscallThread->Args[9],
					pSyscallThread->Args[10],
					pSyscallThread->Args[11],
					pSyscallThread->Args[12],
					pSyscallThread->Args[13],
					pSyscallThread->Args[14],
					pSyscallThread->Args[15],
					pSyscallThread->Args[16],
					pSyscallThread->Args[17],
					pSyscallThread->Args[18],
					pSyscallThread->Args[19]);
	return;
}




//instrusive
//Cons ==> Blocking System Calls (Later use APC to unblock)
unsigned long GetSyscallCount_i(MYFUNC pFunc,bool bWin32k)
{
	MYFUNC pFuncX = 0;
	bool bAllocated = false;
	if(!pFunc)
	{
		pFuncX = CreateFunction(0);
		if(!pFuncX)
		{
			printf("Error allocating memory for dynamic function\r\n");
			return 0;
		}
		bAllocated = true;
	}
	else
	{
		pFuncX = pFunc;
	}


	ulong FinalCount = 0;

	unsigned long MinCall = 0x0;
	unsigned long MaxCall = 0x1000;

	if(bWin32k)
	{
		MinCall += 0x1000;
		MaxCall += 0x1000;
	}




	unsigned long long* Args = (ulonglong*)LocalAlloc(LMEM_ZEROINIT,MAX_ARGS*8);
	if(!Args)
	{
		printf("Error allocating arguments for system calls\r\n");
		return 0;
	}


	//--------- Temporary Code, remove later -------
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	addr_ZwSetDefaultLocale = (uchar*)GetProcAddress(hNtdll,"ZwSetDefaultLocale");
	Syscall_ZwSetDefaultLocale = ExtractSyscallNumberFromCode(addr_ZwSetDefaultLocale);
	//----------------------------------------------


	for(unsigned long c = MinCall; c<= MaxCall;c++)
	{

		if( c == Syscall_ZwSetDefaultLocale) continue;

		//printf("Syscall: %X\r\n",c);

		ModifyFunction(pFuncX,c);

		

		_SYSCALL_EXTRACTOR_THREAD SyscallThread = {0};
		SyscallThread.pFunc = pFuncX;
		SyscallThread.SyscallNo = c;
		SyscallThread.Args = Args;

		ulong tid = 0;
		HANDLE hThread = CreateThread(0,0x1000,(LPTHREAD_START_ROUTINE)(&ThreadSyscall),&SyscallThread,0,&tid);

		if( WaitForSingleObject(hThread,0x10) == WAIT_TIMEOUT)
		{
			printf("Warning: Syscall %X is a blocking syscall.\r\n",c);
		}


		int retValue = SyscallThread.retValue;
		if(retValue == 0xC000001C)//STATUS_INVALID_SYSTEM_SERVICE
		{
			FinalCount = c;
			break;
		}
	}

	
	LocalFree(Args);
	if(bAllocated) DestroyFunction(pFuncX);
	return FinalCount;
}
