// SyscallNumberExtractor.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "stdio.h"

#include "Header.h"

HMODULE hNtdll;





ulonglong ExtractSyscallNumberFromCode(uchar* pCode)
{
	if(pCode)
	{
		//assuming code has this pattern
		//"4C 8B D1 B8 8E 01 00 00 F6 04 25 08 03 FE 7F 01 75 03 0F 05 C3 CD 2E C3"
		ulong Syscall = *(ulong*)(&pCode[4]);
		return Syscall;
	}
	return -1;
}

//returns 0 upon failure
char* GetExportedFunctionNameFromAddress(ulonglong PeHeader,uchar* Address)
{
	if(PeHeader)
	{
		_IMAGE_DOS_HEADER* pDos = (_IMAGE_DOS_HEADER*)PeHeader;

		ulong rva_nt = pDos->e_lfanew;

		_IMAGE_NT_HEADERS64* pNT64 = (_IMAGE_NT_HEADERS64*)(PeHeader + rva_nt);

		ulong rva_export = pNT64->OptionalHeader.DataDirectory[0].VirtualAddress;
		ulong sz_export  = pNT64->OptionalHeader.DataDirectory[0].Size;

		_IMAGE_EXPORT_DIRECTORY* pExport = (_IMAGE_EXPORT_DIRECTORY*)(PeHeader + rva_export);


		ulong NumFunctions = pExport->NumberOfFunctions;
		ulong NumNames = pExport->NumberOfNames;
		ulong BaseX = pExport->Base;
		//printf("Base: %X\r\n",BaseX);

		ulong rva_AddressOfFunctions = pExport->AddressOfFunctions;
		ulong* pAddressOfFunctions = (ulong*)(PeHeader + rva_AddressOfFunctions);

		ulong rva_AddressOfNames = pExport->AddressOfNames;
		ulong* pAddressOfNames = (ulong*)(PeHeader + rva_AddressOfNames);

		ulong rva_AddressOfNameOrdinals = pExport->AddressOfNameOrdinals;
		ushort* pAddressOfNameOrdinals = (ushort*)(PeHeader + rva_AddressOfNameOrdinals);

		ulong rva = ((ulonglong)Address) - (PeHeader);

		for(ulong i=0;i<NumFunctions;i++)
		{
			if(pAddressOfFunctions[i] == rva)
			{
				for(ulong z=0;z<NumNames;z++)
				{
					if( pAddressOfNameOrdinals[z] == i)
					{
						uchar* ExportedName = (uchar*)( PeHeader + pAddressOfNames[z] );
						//printf("%s\r\n",ExportedName);
						return (char*)ExportedName;
					}
				}
			}
		}
	}
	return 0;
}

//returns -1 upon failure.
//0 upon success
int GetExportedFunctionNamesFromAddress(ulonglong PeHeader,uchar* Address,uchar** pNamesOut)
{
	ulong cNamesOut = 0;

	if(PeHeader)
	{
		_IMAGE_DOS_HEADER* pDos = (_IMAGE_DOS_HEADER*)PeHeader;

		ulong rva_nt = pDos->e_lfanew;

		_IMAGE_NT_HEADERS64* pNT64 = (_IMAGE_NT_HEADERS64*)(PeHeader + rva_nt);

		ulong rva_export = pNT64->OptionalHeader.DataDirectory[0].VirtualAddress;
		ulong sz_export  = pNT64->OptionalHeader.DataDirectory[0].Size;

		_IMAGE_EXPORT_DIRECTORY* pExport = (_IMAGE_EXPORT_DIRECTORY*)(PeHeader + rva_export);


		ulong NumFunctions = pExport->NumberOfFunctions;
		ulong NumNames = pExport->NumberOfNames;
		ulong BaseX = pExport->Base;
		printf("Base: %X\r\n",BaseX);

		ulong rva_AddressOfFunctions = pExport->AddressOfFunctions;
		ulong* pAddressOfFunctions = (ulong*)(PeHeader + rva_AddressOfFunctions);

		ulong rva_AddressOfNames = pExport->AddressOfNames;
		ulong* pAddressOfNames = (ulong*)(PeHeader + rva_AddressOfNames);

		ulong rva_AddressOfNameOrdinals = pExport->AddressOfNameOrdinals;
		ushort* pAddressOfNameOrdinals = (ushort*)(PeHeader + rva_AddressOfNameOrdinals);



		ulong rva = ((ulonglong)Address) - (PeHeader);

		for(ulong i=0;i<NumFunctions;i++)
		{
			if(pAddressOfFunctions[i] == rva)
			{
				for(ulong z=0;z<NumNames;z++)
				{
					if( pAddressOfNameOrdinals[z] == i)
					{
						uchar* ExportedName = (uchar*)( PeHeader + pAddressOfNames[z] );
						printf("%s\r\n",ExportedName);
						pNamesOut[cNamesOut] = ExportedName;
						cNamesOut++;
					}
				}
			}
		}

		return 0;
	}
	return -1;
}

bool IsSyscallPattern(uchar* pCode)
{
	if( memcmp(&pCode[0],"\x4C\x8B\xD1\xB8",4))
	{
		return false;
	}
	ulong Syscall_temp = *(ulong*)(&pCode[4]);
	if( memcmp(&pCode[8],"\xF6\x04\x25\x08\x03\xFE\x7F\x01\x75\x03\x0F\x05\xC3\xCD\x2E\xC3",16))
	{
		return false;
	}

	return true;
}


ulonglong GetBaseAndSizeOfCode(ulonglong PeHeader,ulong* pSizeOfCode)
{
	if(PeHeader)
	{
		_IMAGE_DOS_HEADER* pDos = (_IMAGE_DOS_HEADER*)PeHeader;

		ulong rva_nt = pDos->e_lfanew;

		_IMAGE_NT_HEADERS64* pNT64 = (_IMAGE_NT_HEADERS64*)(PeHeader + rva_nt);

		if(pSizeOfCode) *pSizeOfCode = pNT64->OptionalHeader.SizeOfCode;
		return pNT64->OptionalHeader.BaseOfCode;
	}
	return 0;
}





int _tmain(int argc, _TCHAR* argv[])
{
	hNtdll = GetModuleHandle(L"ntdll.dll");
	printf("ntdll at: %I64X\r\n",hNtdll);

	ulong CountSyscallsNt = GetSyscallCount_i(0,false);
	printf("Number Of NT Syscalls: %X\r\n",CountSyscallsNt);

	if(!CountSyscallsNt)
	{
		printf("Fatal Error: %X\r\n",-40);
		ExitProcess(0);
	}


	_FOUND_SYSCALL_INFO* pAllSyscallS = 
		(_FOUND_SYSCALL_INFO*)VirtualAlloc(0,CountSyscallsNt*sizeof(_FOUND_SYSCALL_INFO),MEM_COMMIT,PAGE_READWRITE);

	if(!pAllSyscallS)
	{
		printf("Error allocating memory\r\n");
		return -2;
	}


	ulong szOfCode_ntdll = 0;
	ulong baseOfCode_ntdll = GetBaseAndSizeOfCode((ulonglong)hNtdll,&szOfCode_ntdll);
	printf("Base Of Code: %X, Size Of Code: %X\r\n",szOfCode_ntdll,szOfCode_ntdll);

	uchar* StartScanningAddr = ((uchar*)hNtdll) + baseOfCode_ntdll;
	uchar* EndScanningAddr = StartScanningAddr + szOfCode_ntdll;

	printf("Start: %I64X, End: %I64X\r\n",StartScanningAddr,EndScanningAddr);

	uchar* i = StartScanningAddr;
	while(i<EndScanningAddr)
	{
		//Assuming this pattern
		////"4C 8B D1 B8 8E 01 00 00 F6 04 25 08 03 FE 7F 01 75 03 0F 05 C3 CD 2E C3"

		if( memcmp(&i[0],"\x4C\x8B\xD1\xB8",4))
		{
			i++;
			continue;
		}

		ulong Syscall_temp = *(ulong*)(&i[4]);

		if( memcmp(&i[8],"\xF6\x04\x25\x08\x03\xFE\x7F\x01\x75\x03\x0F\x05\xC3\xCD\x2E\xC3",16))
		{
			i++;
			continue;
		}

		ulong Syscall = Syscall_temp;
		printf("Syscall: %X found at: %I64X\r\n",Syscall,i);

		pAllSyscallS[Syscall].SyscallNumber = Syscall;
		pAllSyscallS[Syscall].FunctionAddress = i;
		pAllSyscallS[Syscall].FunctionName = GetExportedFunctionNameFromAddress((ulonglong)hNtdll,i);


		i += 24;
	}

	//getchar();


	char* pOutputString = (char*)VirtualAlloc(0,0x10000,MEM_COMMIT,PAGE_READWRITE);
	if(!pOutputString)
	{
		printf("Error allocating memory for output strings.\r\n");
		VirtualFree(pAllSyscallS,0,MEM_RELEASE);
		return -66;
	}

	strcat(pOutputString,"{");


	char* pOutputMacros = (char*)VirtualAlloc(0,0x10000,MEM_COMMIT,PAGE_READWRITE);
	if(!pOutputMacros)
	{
		printf("Error allocating memory for output macro strings.\r\n");
		VirtualFree(pOutputString,0,MEM_RELEASE);
		VirtualFree(pAllSyscallS,0,MEM_RELEASE);
		return -77;
	}
	
	for(ulong ix = 0; ix < CountSyscallsNt; ix++)
	{

		if( (pAllSyscallS[ix].SyscallNumber == 0) &&
			(pAllSyscallS[ix].FunctionAddress == 0) &&
			(pAllSyscallS[ix].FunctionName == 0))
		{
			//printf("Syscall: %X is patched or does not exist.\r\n",ix);
			pAllSyscallS[ix].SyscallNumber = ix;
			pAllSyscallS[ix].FunctionName = "NtNullSyscall**";
			pAllSyscallS[ix].FunctionAddress = 0;
		}
		else
		{
			if( ExtractSyscallNumberFromCode(pAllSyscallS[ix].FunctionAddress) != pAllSyscallS[ix].SyscallNumber)
			{
				printf("Major ntdll.dll change\r\n");
				ExitProcess(0);
			}
		}



		printf("Syscall: %X (%s) at: %I64X\r\n",
					pAllSyscallS[ix].SyscallNumber,
					pAllSyscallS[ix].FunctionName,
					pAllSyscallS[ix].FunctionAddress);

		strcat(pOutputString,"\"");
		strcat(pOutputString,pAllSyscallS[ix].FunctionName);
		strcat(pOutputString,"\",\r\n");

		strcat(pOutputMacros,"#define macr_");
		strcat(pOutputMacros,pAllSyscallS[ix].FunctionName);
		strcat(pOutputMacros," 0x");

		char wSyscallNummmm[0x50]={0};
		_ultoa(pAllSyscallS[ix].SyscallNumber,wSyscallNummmm,0x10);
		strcat(pOutputMacros,wSyscallNummmm);
		strcat(pOutputMacros,"\r\n");

		//printf("%s\r\n",pOutputMacros);
		//getchar();

		//if( strncmp(pAllSyscallS[ix].FunctionName,"Nt",2) )
		//{
			//Must be Zw Version
		//}

	}

	ulong lenX = strlen(pOutputString);
	lenX -= 3;
	pOutputString[lenX] = 0;
	strcat(pOutputString,"};");
	lenX += 2;

	printf("Text: %s\r\n",pOutputString);

	HANDLE hFile = CreateFile(L"syscalls.txt",GENERIC_ALL,FILE_SHARE_READ,0,CREATE_ALWAYS,0,0);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		ulong NumWritten = 0;
		if(!WriteFile(hFile,pOutputString,lenX,&NumWritten,0))
		{
			printf("Error writinf to file.\r\n");
			ExitProcess(0);
		}
		FlushFileBuffers(hFile);
		CloseHandle(hFile);
	}


	HANDLE hFileM = CreateFile(L"macros.txt",GENERIC_ALL,FILE_SHARE_READ,0,CREATE_ALWAYS,0,0);
	if(hFileM != INVALID_HANDLE_VALUE)
	{
		lenX = strlen(pOutputMacros);
		ulong NumWritten = 0;
		if(!WriteFile(hFileM,pOutputMacros,lenX,&NumWritten,0))
		{
			printf("Error writinf to file.\r\n");
			ExitProcess(0);
		}
		FlushFileBuffers(hFileM);
		CloseHandle(hFileM);
	}



	VirtualFree(pOutputMacros,0,MEM_RELEASE);
	VirtualFree(pOutputString,0,MEM_RELEASE);


	if(pAllSyscallS)
	{
		VirtualFree(pAllSyscallS,0,MEM_RELEASE);
	}

	return 0;
}

