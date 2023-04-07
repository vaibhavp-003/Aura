/*
*
*  Copyright (C) 2010-2011 Amr Thabet <amr.thabet@student.alx.edu.eg>
*
*  This program is free_emu software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to Amr Thabet 
*  amr.thabet@student.alx.edu.eg
*
*/

#include "pch.h"
#include "../x86emu.h"

int undefined_api(Thread* thread,dword* Args){
	free_emu(Args);
	return 0;
}
int System::define_dll(wchar_t* name,wchar_t* path, MAX_DWORD vAddr)
{
	if (GetDllIndex(name))
	{
		return GetDllIndex(name);
	}

	DLLs[dll_entries].name  = name;
	DLLs[dll_entries].vAddr = vAddr;

	wstring s=L"";

	s.append(path);

	s.append(name);

	DLLs[dll_entries].imagebase = PELoader(s);

	if ( DLLs[dll_entries].imagebase == 0)
	{
		return 0;
	}

	MAX_DWORD FileHandler = DLLs[dll_entries].imagebase;
	image_header* PEHeader;
	PEHeader=(image_header*)(((dos_header*)FileHandler)->e_lfanew + FileHandler);
	DLLs[dll_entries].size=PEHeader->optional.size_of_image;
	dll_entries++;

	return (dll_entries-1);
}


int System::define_api(wchar_t* name, DLL* lib, dword args, int (*emu_func)(Thread*,dword*))
{
	for (int i = 0; i < api_entries; i++)
	{
		if(!_tcsicmp(APITable[i].name, name))
		{
			APITable[i].lib = lib;
			APITable[i].emu_func = emu_func;
			return i;
		}
	}

	APITable[api_entries].name=name;
	APITable[api_entries].lib=lib;
	APITable[api_entries].args=args;
	APITable[api_entries].addr = GetAPI(APITable[api_entries].name,lib->imagebase);
	APITable[api_entries].emu_func = emu_func;
	api_entries++;
	return (api_entries-1);
}

//---------------------------------------------------------------------------------------------------
int System::init_apis(wchar_t* path)
{
	//define the dlls
	define_dll(L"kernel32.dll",path,enVars.kernel32);
	define_dll(L"ntdll.dll",path,enVars.ntdll);
	define_dll(L"user32.dll",path,enVars.user32);

	//the defined apis
	define_api(L"GetProcAddress",&DLLs[0],2,GetProcAddress_emu);

	//define_api(L"GetModuleHandleA",&DLLs[0],1,GetModuleHandleA_emu);
	define_api(L"LoadLibraryA",&DLLs[0],1,LoadLibraryA_emu);
	define_api(L"VirtualAlloc",&DLLs[0],4,VirtualAlloc_emu);
	//define_api(L"VirtualFree",&DLLs[0],3,VirtualFree_emu);
	//define_api(L"VirtualProtect",&DLLs[0],4,VirtualProtect_emu);
	//define_api(L"SetUnhandledExceptionFilter",&DLLs[0],1,SetUnhandledExceptionFilter_emu);
	//define_api(L"LocalAlloc",&DLLs[0],2,LocalAlloc_emu);
	//define_api(L"GetProcAddress",&DLLs[0],2,undefined_api);
	define_api(L"GetModuleHandleA",&DLLs[0],1,undefined_api);
	//define_api(L"LoadLibraryA",&DLLs[0],1,undefined_api);
	//define_api(L"VirtualAlloc",&DLLs[0],4,undefined_api);
	define_api(L"VirtualFree",&DLLs[0],3,undefined_api);
	define_api(L"VirtualProtect",&DLLs[0],4,undefined_api);
	define_api(L"SetUnhandledExceptionFilter",&DLLs[0],1,undefined_api);
	define_api(L"LocalAlloc",&DLLs[0],2,undefined_api);

	//undefined apis
	define_api(L"ExitProcess",&DLLs[0],1,undefined_api);
	define_api(L"MessageBoxA",&DLLs[2],4,undefined_api);
	define_api(L"GetCommandLineA",&DLLs[0],0,undefined_api);
	define_api(L"CreateProcessA",&DLLs[0],10,undefined_api);
	define_api(L"lstrlenA",&DLLs[0],1,undefined_api);
	define_api(L"GetTickCount",&DLLs[0],0,undefined_api);
	define_api(L"GetCurrentProcess",&DLLs[0],0,undefined_api);
	define_api(L"GetCurrentProcessId",&DLLs[0],0,undefined_api);
	define_api(L"GetCurrentThread",&DLLs[0],0,undefined_api);
	define_api(L"GetStartupInfoA",&DLLs[0],1,undefined_api);
	define_api(L"GetKeyboardType",&DLLs[2],1,undefined_api);
	define_api(L"GetModuleFileNameA",&DLLs[0],2,undefined_api);

	define_api(L"ReadFile",&DLLs[0],5,undefined_api);
	define_api(L"WriteFile",&DLLs[0],5,undefined_api);
	define_api(L"CreateFileA",&DLLs[0],7,undefined_api);
	define_api(L"GetFileSize",&DLLs[0],2,undefined_api);
	define_api(L"SetFilePointer",&DLLs[0],4,undefined_api);
	define_api(L"SetEndOfFile",&DLLs[0],2,undefined_api);
	define_api(L"GetLocaleInfoA",&DLLs[0],4,undefined_api);
	define_api(L"IsCharUpper",&DLLs[0],1,undefined_api);
	define_api(L"GetLastError",&DLLs[0],0,undefined_api);

	define_api(L"GetKeyState",&DLLs[2],1,undefined_api);
	define_api(L"GetFocus",&DLLs[2],0,undefined_api);
	define_api(L"GetForegroundWindow",&DLLs[0],0,undefined_api);
	define_api(L"GetDC",&DLLs[0],1,undefined_api);
	define_api(L"GetCursorPos",&DLLs[0],1,undefined_api);
	define_api(L"GetCursor",&DLLs[0],0,undefined_api);
	define_api(L"lstrcmpA",&DLLs[0],2,undefined_api);

	define_api(L"lstrcmpiA",&DLLs[0],2,undefined_api);
	define_api(L"ZwSetInformationProcess",&DLLs[1],4,undefined_api);
	define_api(L"ZwQueryInformationProcess",&DLLs[1],5,undefined_api);
	define_api(L"NtProtectVirtualMemory",&DLLs[1],5,undefined_api);
	define_api(L"NtQueryVirtualMemory",&DLLs[1],6,undefined_api);

	
	return 0;
}

int System::CallToAPI(Thread* thread,ins_disasm* s)
{
	try
	{
		dword retPtr = thread->stack->pop();		
		if (s->other > 0 && s->other < 100)
		{			
			int n = s->other-1;
			if (APITable[n].args>0)
			{
				dword* args=(dword*)malloc_emu(APITable[n].args*4);
				memset( args,0,APITable[n].args*4);
				for(DWORD i=0;i<APITable[n].args;i++)
				{
					args[i]=thread->stack->pop();
				}
				thread->Exx[0]=APITable[n].emu_func(thread,args);
			}
		}
		thread->Eip=retPtr;
		return 0;
	}
	catch(int iErr)
	{
		return iErr;
	}
}

bool System::IsApiCall(Thread& thread,ins_disasm*& s)
{
	DWORD ptr=thread.Eip;
	MAX_DWORD dwRealPointer = ptr;
	int entry=0;
	if ((ptr & 0xFFFF0000) == 0xBBBB0000)
	{
		return true;    
	}
	for (int i=0;i<thread.mem->vmem_length;i++)
	{
		if ( ptr >=thread.mem->vmem[i]->vmem && 
			ptr <= (thread.mem->vmem[i]->vmem + thread.mem->vmem[i]->size))
		{
			dwRealPointer -=thread.mem->vmem[i]->vmem;
			dwRealPointer +=thread.mem->vmem[i]->rmem;
			entry=i;
			break;
		}
	}
	if (thread.mem->vmem[entry]->flags ==MEM_DLLBASE)
	{
		s->flags |=API_CALL;
		for (int i=0;i<api_entries;i++)
		{
			if (APITable[i].addr == dwRealPointer)
			{
				s->other=i+1;            //because zero mean undefined :)
				break;
			}
		}
		return true;
	}
	else
	{
		return false;
	}
}
MAX_DWORD System::GetAPI(wchar_t* func, MAX_DWORD dll)
{
	MAX_DWORD	 hKernelModule = 0;
	dword		 dwFuncOffset = 0;
	dword		 dwNameOrdOffset = 0;
	dword		dwOffsetPE = 0, dwOffsetExport = 0;
	int		 i=0;
	dword	 dwNumberOfNames = 0, dwNamesOffset = 0;
	dword*   dwNameRVAs = NULL;
	dword*   dwFuncRVAs = NULL;
	short*   dwNameOrdRVAs = NULL;
	bool	 bApiFound;
	char	 szFuncName[MAX_PATH] = {0};

	sprintf_s(szFuncName, _countof(szFuncName), "%S", func);

	hKernelModule   = dll;
	if (dll==0)
	{
		return 0;
	}
	dwOffsetPE 	 = *(dword*)((dword)hKernelModule + 0x3C);
	dwOffsetExport  = *(dword*)((dword)hKernelModule + dwOffsetPE + 0x78);

	dwNumberOfNames = *(dword*)((dword)hKernelModule + dwOffsetExport + 0x18);

	dwFuncOffset	= *(dword*)(hKernelModule + dwOffsetExport + 0x1C);
	dwNamesOffset   = *(dword*)((dword)hKernelModule + dwOffsetExport + 0x20);
	dwNameOrdOffset = *(dword*)((dword)hKernelModule + dwOffsetExport + 0x24);
	dwNameRVAs 	  = (dword*)(hKernelModule + dwNamesOffset);
	dwFuncRVAs 	  = (dword*)(hKernelModule + dwFuncOffset);
	dwNameOrdRVAs = (short*)(hKernelModule + dwNameOrdOffset);
	bApiFound = false;
	DWORD dwTemp=0;
	for(dwTemp=0; dwTemp < dwNumberOfNames; dwTemp++)
	{
		if(!strcmp(((dword)hKernelModule + (char*)dwNameRVAs[dwTemp]), szFuncName))
		{
			bApiFound = true;
			break;
		}
	}

	if(!bApiFound) 
	{
		return 0;
	}	
	i=dwNameOrdRVAs[dwTemp];
	return (dll+dwFuncRVAs[i]);
}

char* System::GetAPIbyAddress(unsigned long ptr,unsigned long dll)
{
	dword	hKernelModule = 0;
	dword	dwFuncOffset = 0;
	dword	dwNameOrdOffset = 0;
	dword	dwOffsetPE = 0, dwOffsetExport = 0;
	dword	i=0;
	dword	l=0;
	dword	dwNumberOfNames = 0, dwNamesOffset = 0;
	dword*  dwNameRVAs = NULL;
	dword*  dwFuncRVAs = NULL;
	short*  dwNameOrdRVAs = NULL;
	bool	bApiFound;

	hKernelModule   = dll;
	if (dll==0)
	{
		return 0;
	}

	dwOffsetPE 	 = *(dword*)((dword)hKernelModule + 0x3C);
	dwOffsetExport  = *(dword*)((dword)hKernelModule + dwOffsetPE + 0x78);

	dwNumberOfNames = *(dword*)((dword)hKernelModule + dwOffsetExport + 0x18);

	dwFuncOffset	= *(dword*)(hKernelModule + dwOffsetExport + 0x1C);
	dwNamesOffset   = *(dword*)((dword)hKernelModule + dwOffsetExport + 0x20);
	dwNameOrdOffset = *(dword*)((dword)hKernelModule + dwOffsetExport + 0x24);
	dwNameRVAs 	  = (dword*)(hKernelModule + dwNamesOffset);
	dwFuncRVAs 	  = (dword*)(hKernelModule + dwFuncOffset);
	dwNameOrdRVAs = (short*)(hKernelModule + dwNameOrdOffset);

	bApiFound = false;

	for(i=0; i<dwNumberOfNames; i++)
	{ 
		if((dwFuncRVAs[i])==(ptr-dll))
		{
			bApiFound = true;
			break;
		}
	}
	if(!bApiFound) 
	{
		return 0;
	}
	for (l=0; l<dwNumberOfNames; l++)
	{
		if ((short)i==dwNameOrdRVAs[l])
		{
			i=l;
			break;                     
		}
	}
	return (char*)(dll+dwNameRVAs[i]);
}
char* System::GetTiggeredAPI(Thread& thread)
{
	int entry=0;
	dword ptr=thread.Eip;
	for (int i=0;i<thread.mem->vmem_length;i++)
	{
		if ( ptr >=thread.mem->vmem[i]->vmem && 
			ptr <= (thread.mem->vmem[i]->vmem + thread.mem->vmem[i]->size))
		{
			ptr -=thread.mem->vmem[i]->vmem;
			ptr +=thread.mem->vmem[i]->rmem;
			entry=i;
			break;
		}
	}

	dword dllbase=thread.mem->vmem[entry]->rmem;
	char* c=GetAPIbyAddress(ptr,dllbase);
	return c;
}
//-----------------------------------------------------------------------------------------------------------------------
MAX_DWORD System::GetDllBase(wchar_t* s)
{
	wstring str = to_lower_case(s);
	str = str.substr(0, str.size() - 1);      //sometimes converted wrong (from char* to string)

	for(int i=0;i<dll_entries;i++)
	{
		wstring name=DLLs[i].name;
		if (!wcscmp(str.c_str(),name.c_str()))
		{
			return DLLs[i].imagebase;
		}

		if (!wcscmp(str.c_str(),name.substr(0,str.size()).c_str()))
		{                                                         
			return DLLs[i].imagebase;
		}
	}

	return 0;
}

unsigned long System::GetDllIndex(wchar_t* s)
{
	wstring str = to_lower_case(s);

	for(int i=0; i<dll_entries; i++)
	{
		wstring name = DLLs[i].name;

		if(!wcscmp(str.c_str(),name.c_str()))
		{
			return i;
		}

		if(!wcscmp(str.c_str(),name.substr(0,str.size()).c_str()))
		{
			return i;
		}
	}

	return 0;
}
