#include "stdafx.h"

#include "Header.h"


MYFUNC CreateFunction(unsigned long SyscallNumber)
{
	char Sk[] = "\x4C\x8B\xD1\xB8\x10\x10\x00\x00\x0F\x05\xC3";
	//printf("size: %X\r\n",sizeof(Sk));
	char* pNew = (char*)VirtualAlloc(0,0x1000,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if(pNew)
	{
		memcpy(pNew,Sk,sizeof(Sk));
		*(unsigned long*)(pNew+4) = SyscallNumber;
	}
	return (MYFUNC)pNew;
}

void ModifyFunction(MYFUNC pFunc,unsigned long SyscallNumber)
{
	if(pFunc)
	{
		char* pFuncC = (char*)pFunc;
		*(unsigned long*)(pFuncC+4) = SyscallNumber;
	}
}

void DestroyFunction(MYFUNC pFunc)
{
	//if(pFunc) VirtualFree(pFunc,0x1000,MEM_DECOMMIT);
	if(pFunc) VirtualFree(pFunc,0x0,MEM_RELEASE);
}