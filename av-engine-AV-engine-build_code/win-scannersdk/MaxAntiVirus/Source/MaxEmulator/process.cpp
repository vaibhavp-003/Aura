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
#include "x86emu.h"

typedef struct _tagMemoryTable
{
	LPVOID lpMem;
	int iType;
	struct _tagMemoryTable * pNext;
}MEM_TBL, *LPMEM_TBL;

LPMEM_TBL		g_pMallocList = NULL;

//-----------------------------------------------------------------------------------------------------------------------
int Process::ImportTableFixup(MAX_DWORD FileHandler)
{
	image_header* PEHeader = (image_header*)(((dos_header*)FileHandler)->e_lfanew + FileHandler);

	if (PEHeader == NULL || PEHeader->optional.data_directory[1].virtual_address==0 ||
		PEHeader->optional.data_directory[1].virtual_address >((*((DWORD*)(*((DWORD*)(FileHandler+0x3C)) + 0x38 + 0x18+ FileHandler)))))
	{
		return 0;
	}

	image_import_descriptor* Imports=(image_import_descriptor*)(PEHeader->optional.data_directory[1].virtual_address+FileHandler);

	for (int i=0;i<10000;i++)
	{
		if((((MAX_DWORD)Imports) - FileHandler) > ((*((DWORD*)(*((DWORD*)(FileHandler+0x3C)) + 0x38 + 0x18+ FileHandler)))))
		{
			return 0;
		}

		if (Imports->name==0 || Imports->name >= (*((DWORD*)(*((DWORD*)(FileHandler+0x3C)) + 0x38 + 0x18+ FileHandler))))
		{
			break;
		}

		MAX_DWORD name = Imports->name + FileHandler;   

		wchar_t	szName[MAX_PATH] = {0};
		convert_cptr2wcptr((char*)name, szName, _countof(szName));

		MAX_DWORD dllbase = sys->GetDllBase(szName);
		APIsFixup(FileHandler,Imports,dllbase);
		Imports = (image_import_descriptor*)((MAX_DWORD)Imports + (dword)sizeof(image_import_descriptor));
	}
	return 0;
}

//-----------------------------------------------------------------------------------------------------------------------
int Process::APIsFixup(MAX_DWORD FileHandler,image_import_descriptor* Imports, MAX_DWORD dllbase)
{
	image_import_by_name** names;                                       //pointer to the names that we will get's address
	dword* pointers;  
	//pointer to the the place that we will put the addresses there                                 
	if (Imports->original_first_thunk!=0)
	{
		names = (image_import_by_name**)Imports->original_first_thunk;                                               
	}
	else
	{
		names=(image_import_by_name**)Imports->first_thunk;
	}
	if(((MAX_DWORD)names) > (*((DWORD*)(*((DWORD*)(FileHandler+0x3C)) + 0x38 + 0x18+ FileHandler))))
	{
		return 0;
	}
	names=(image_import_by_name**)((MAX_DWORD)names+FileHandler);
	if(((DWORD)Imports->first_thunk) > (*((DWORD*)(*((DWORD*)(FileHandler+0x3C)) + 0x38 + 0x18+ FileHandler))) ||
		((DWORD)Imports->first_thunk) < (*((DWORD*)(*((DWORD*)(FileHandler+0x3C)) + 0x3C + 0x18+ FileHandler))))
	{
		return 0;
	}

	pointers = (dword*)(Imports->first_thunk + FileHandler);
	if (Imports->first_thunk==0)
	{
		return 0;
	}
	DWORD *ptr = (DWORD*)(&names[0]);
	DWORD *ptr1 = (DWORD*)(&names[0]->name);

	for (int i=0;i<20000;i++)
	{
		if ((/*(DWORD)names*/ptr[i])==0 || (/*(DWORD)names[i]->name*/ptr[i]+2) > (*((DWORD*)(*((DWORD*)(FileHandler+0x3C)) + 0x38 + 0x18+ FileHandler))))
		{
			break;
		}
		if(!((dword)((/*(DWORD)names[i]->name*/ptr[i]+2)+FileHandler) & 0x80000000))
		{
			dword s = /*(dword)names[i]->name*/ptr[i] + 2;
			wchar_t szName[MAX_PATH] = {0};
			convert_cptr2wcptr((char*)(s+FileHandler), szName, _countof(szName));
			MAX_DWORD ptr = sys->GetAPI(szName,dllbase);
			dword n = this->SharedMem->get_virtual_pointer(ptr);
			
			if (n!=0)
			{
				ptr = n;
			}
			//originally not commented
			//else
			//{
			//	n = sys->DLLs[0].imagebase; //equal to the kernel32 base address    
			//}
			//memcpy(&pointers[i],&ptr,4);original
			memcpy(&pointers[i],&n, 4);
		}
	}
	return 0;
}
//-----------------------------------------------------------------------------------------------------------------------

Process::Process (System* sys, CMaxPEFile *pobjMaxPEFile, bool bHandleAPIs):
m_bHandleAPIs(bHandleAPIs)
{      
	m_dwEmulatorFileSize = 0;

	//1.open the file
	MAX_DWORD FileHandler = PELoader(pobjMaxPEFile, m_dwEmulatorFileSize);
	if(FileHandler==0)
	{
		throw (ERROR_FILENAME);
	}
	if(((dos_header*)FileHandler)->e_magic != 0x5A4D)
	{
		throw (ERROR_FILENAME);
	}

	//2.initialize the System 
	this->sys=sys;
	//3.initalize the Memory

	this->SharedMem = new VirtualMemory();

	image_header* PEHeader;
	
	if(((dos_header*)FileHandler)->e_lfanew > pobjMaxPEFile->m_stPEHeader.SizeOfImage)
	{
		throw (0);
	}

	PEHeader=(image_header*)(((dos_header*)FileHandler)->e_lfanew + FileHandler);
	Imagebase = PEHeader->optional.image_base; //the imagebase
	PEHeader->optional.size_of_image = pobjMaxPEFile->m_stPEHeader.SizeOfImage; //neeraj
	this->SharedMem->add_pointer(FileHandler, PEHeader->optional.image_base,
		PEHeader->optional.size_of_image,MEM_IMAGEBASE);

	for (int i=0; i<sys->dll_entries; i++)
	{
		if (sys->DLLs[i].vAddr!=0)
		{
			this->SharedMem->add_pointer(sys->DLLs[i].imagebase,
				sys->DLLs[i].vAddr,sys->DLLs[i].size,MEM_DLLBASE);
		}
		else
		{
			this->SharedMem->add_pointer(sys->DLLs[i].imagebase,
				sys->DLLs[i].imagebase,sys->DLLs[i].size,MEM_DLLBASE);
		}
	}

	if (PEHeader->header.characteristics & IMAGE_FILE_DLL)
	{
		IsDLL = true;
	}
	else
	{
		IsDLL = false;
	}
	// 4.fix the import table
	ImportTableFixup(FileHandler);
	nimports=0;

	//5.initialize the debugger
	debugger = new AsmDebugger(*this);

	peb = NULL;
	//6.initialize the PEB
	CreatePEB();

	//7.initialize the first thread
	nthreads=0;
	this->MaxIterations=sys->enVars.MaxIterations;
	CreateThread(PEHeader->optional.address_of_entry_point+PEHeader->optional.image_base);

	//8 .preparing the buffer for instructions
	ins = (ins_disasm*)malloc_emu(sizeof(ins_disasm)); 
}

Process::~Process()
{
	VirtualFree((void*)SharedMem->vmem[0]->rmem, 0/*SharedMem->vmem[0]->size*/, MEM_RELEASE);
	
	if(SharedMem)
	{
		delete SharedMem;
		SharedMem = NULL;
	}
	if(threads[0])
	{
		delete threads[0];
		threads[0] = NULL;
	}
	if(debugger)
	{
		delete debugger;
		debugger = NULL;
	}
	if(peb)
	{
		free_emu(peb);
		peb = NULL;
	}
	if(ins)
	{
		free_emu(ins);
		ins = NULL;
	}

	FreeTable();
}
//this proc copy all the shared memory entries on every thread memory to become visible for each thread
//all the threads will see the changes in the shared memory as the shared pointers in all threads point to the same location in memory

System* Process::getsystem()
{
	return sys;
}

ins_disasm* Process::GetLastIns()
{
	return ins;            
}

int Process::CreateThread(dword ptr)
{
	this->threads[nthreads] = new Thread(ptr,*this);
	nthreads++;  
	return (nthreads-1);
}
//n--> the Thread number
int Process::emulatecommand(int n)
{
	return 0;   
}

int Process::emulatecommand()
{
	//string str;

	//try 
	//{
	//	ins=sys->disasm(ins,(char*)SharedMem->read_virtual_mem(this->threads[0]->Eip));//,str
	//	bool IsApi=sys->IsApiCall(*threads[0],ins);
	//	bool bp=this->debugger->TestBp(*threads[0],ins);     
	//	if (bp && !TiggeredBreakpoint)
	//	{
	//		TiggeredBreakpoint=true;
	//		return EXP_BREAKPOINT;
	//	}
	//	else if (TiggeredBreakpoint)
	//	{
	//		TiggeredBreakpoint=false;
	//	}

	//	if (IsApi)
	//	{
	//		this->threads[0]->log->addlog(this->threads[0]->Eip);
	//		this->threads[0]->Eip+= ins->hde.len;
	//		sys->CallToAPI(threads[0],ins);
	//	}
	//	else
	//	{
	//		this->threads[0]->log->addlog(this->threads[0]->Eip);
	//		this->threads[0]->Eip+= ins->hde.len;
	//		ins->emu_func(*threads[0],ins);
	//	}
	//	return 0; 
	//} 
	//catch(int x) 
	//{
	//	if(x !=EXP_INVALID_OPCODE)
	//	{
	//		this->threads[0]->Eip-= ins->hde.len;   //because it's added before emulating the instruction
	//	}
	//	dword fsptr = *SharedMem->read_virtual_mem(threads[0]->GetFS());
	//	if (*SharedMem->read_virtual_mem(fsptr)!= 0xFFFFFFFF)
	//	{
	//		dword* ptr=(dword*)this->SharedMem->read_virtual_mem(threads[0]->GetFS());
	//		dword err_ptr = *ptr;
	//		dword* nextptr=(dword*)this->SharedMem->read_virtual_mem(err_ptr); //the next handler
	//		threads[0]->generateException(x);      
	//		*ptr=*nextptr;
	//		return 0;                                                   //save it        
	//	}
	//	else
	//	{
	//		return x;
	//	}
	//}
	return 0;
}



//------------------------------------------------------------------------------------------------------
///*
void AddeEmulatorLog(LPCTSTR szString)
{
	FILE * fp = 0;
	_tfopen_s(&fp, L"c:\\EmulatorLog.txt", L"a");
	if(fp)
	{
		_fputts(szString, fp);
		_fputts(L"\r\n", fp);
		fclose(fp);
	}
}

int Process::emulate(bool bCheckSecondBP)
{  
	int Error = 0; //Emulated Successfully
	int errorSEH = 0;
	
Continue_th:

	dword Max = MaxIterations;   
	for(DWORD i = 0; i < Max; i++)
	{
		char* ptr = NULL;
		ptr = (char*)SharedMem->read_virtual_mem(this->threads[0]->Eip);
		if (ptr == NULL)
		{
			Error = EXP_INVALIDPOINTER;
			break;
		}
		ins = sys->disasm(ins, ptr, strInstName);
		if ((ins->hde.flags & F_ERROR) && (ins->hde.flags & F_ERROR_OPERAND))
		{
			Error = EXP_INVALID_OPCODE;
			break;
		} 

		bool IsApi = sys->IsApiCall(*threads[0], ins);
		bool bp=this->debugger->TestBp(*threads[0], ins);
		if (bp && !TiggeredBreakpoint)
		{
			TiggeredBreakpoint=true;
			return EXP_BREAKPOINT;
		}
		else if (TiggeredBreakpoint)
		{
			TiggeredBreakpoint=false;
		}
		
		if (IsApi)
		{
			if ((threads[0]->Eip & 0xFFFF0000) == 0xBBBB0000)cout << "HERE2!!!!\n\n\n";
			this->threads[0]->log->addlog(this->threads[0]->Eip);
			this->threads[0]->Eip+= ins->hde.len;
			Error = sys->CallToAPI(threads[0],ins);
		}
		else
		{
			this->threads[0]->log->addlog(this->threads[0]->Eip);
			this->threads[0]->Eip+= ins->hde.len;
			Error = ins->emu_func(*threads[0],ins);
			/*_stprintf_s(szLogLine, 1024, L"%-8X   %-35S   EAX = %-8X   ECX = %-8X   EDX = %-8X   EBX = %-8X   ESP = %-8X   EBP = %-8X   ESI = %-8X   EDI = %-8X   ", this->threads[0]->Eip - ins->hde.len, strInstName.c_str(), this->threads[0]->Exx[0],this->threads[0]->Exx[1],this->threads[0]->Exx[2],this->threads[0]->Exx[3],this->threads[0]->Exx[4],this->threads[0]->Exx[5],this->threads[0]->Exx[6],this->threads[0]->Exx[7]);
			AddeEmulatorLog(szLogLine);*/
		}
		if (Error !=0)
		{
			break;
		}
		if(bCheckSecondBP)
		{
			bp=this->debugger->TestBp(*threads[0], ins);
			if (bp && !TiggeredBreakpoint)
			{
				TiggeredBreakpoint=true;
				return EXP_BREAKPOINT;
			}
			else if (TiggeredBreakpoint)
			{
				TiggeredBreakpoint=false;
			}
		}
		MaxIterations-=1;
		if (MaxIterations == 0)
		{
			return EXP_EXCEED_MAX_ITERATIONS;
		}
	}
	if(Error !=EXP_INVALID_OPCODE)
	{
		this->threads[0]->Eip-= ins->hde.len;   //because it's added before emulating the instruction
	}

	dword fsptr = *SharedMem->read_virtual_mem(threads[0]->GetFS());
	if (SharedMem->read_virtual_mem(fsptr) ==0)
	{
		return Error;
	}
	if (*SharedMem->read_virtual_mem(fsptr)!= 0xFFFFFFFF)
	{ 
		dword* ptr=(dword*)this->SharedMem->read_virtual_mem(threads[0]->GetFS());
		dword err_ptr = *ptr;
		dword* nextptr=(dword*)this->SharedMem->read_virtual_mem(err_ptr); //the next handler 
		if ((dword)nextptr ==0)
		{
			return Error;
		}
		threads[0]->generateException(Error);
		*ptr=*nextptr;                                                   //save it     
		errorSEH = 1;
		goto Continue_th; 
	}
	else
	{
		return Error;
	}    
}

Thread* Process::GetThread(int id)
{
	return this->threads[id];
}
dword Process::GetImagebase()
{
	return Imagebase;
}
void Process::CreatePEB()
{
	//Important Strings

	wchar_t* skernel32=L"Kernel32.dll";
	dword skernel32length=13*2;                  //the Size of kernel32.dll unicode string + null wide char
	wchar_t* sntdll=L"ntdll.dll";
	dword sntdlllength=10*2;                     //the Size of ntdll.dll unicode string + null wide char
	wchar_t* sprogram=L"program.exe";
	dword sprogramlength=12*2;                   //the Size of program.exe unicode string + null wide char

	//creating the PEB
	dword size=sizeof(PEB)+3*sizeof(_LDR_DATA_TABLE_ENTRY)+sizeof(_PEB_LDR_DATA);
	size+=skernel32length+sntdlllength+sprogramlength;                           //adding the strings
	MAX_DWORD ptr = (MAX_DWORD)malloc_emu(size);

	//Copying the Strings
	MAX_DWORD strs_ptr = ptr + sizeof(PEB) + 
						 3*sizeof(_LDR_DATA_TABLE_ENTRY) + sizeof(_PEB_LDR_DATA);

	memcpy((void*)strs_ptr,skernel32,13*2);
	skernel32=(wchar_t*)strs_ptr;

	size+=13*2;
	strs_ptr+=13*2;
	memcpy((void*)strs_ptr,sntdll,10*2);
	sntdll=(wchar_t*)strs_ptr;
	size+=10*2;
	strs_ptr+=10*2;
	memcpy((void*)strs_ptr,sprogram,12*2);
	sprogram=(wchar_t*)strs_ptr;
	size+=12*2;
	strs_ptr+=12*2;
	peb=(PEB*)ptr;

	//Preparing the Data Table Entry
	_PEB_LDR_DATA*  LoaderData=(_PEB_LDR_DATA*)(ptr+sizeof(PEB));
	_LDR_DATA_TABLE_ENTRY* program=(_LDR_DATA_TABLE_ENTRY*)(ptr+sizeof(PEB)+sizeof(_PEB_LDR_DATA));
	_LDR_DATA_TABLE_ENTRY* ntdll=(_LDR_DATA_TABLE_ENTRY*)(ptr+sizeof(PEB)+sizeof(_LDR_DATA_TABLE_ENTRY)+sizeof(_PEB_LDR_DATA));
	_LDR_DATA_TABLE_ENTRY* kernel=(_LDR_DATA_TABLE_ENTRY*)(ptr+sizeof(PEB)+2*sizeof(_LDR_DATA_TABLE_ENTRY)+sizeof(_PEB_LDR_DATA));
	memset(peb,0,sizeof(PEB)+3*sizeof(_LDR_DATA_TABLE_ENTRY)+sizeof(_PEB_LDR_DATA));

	//Create it
	this->SharedMem->add_pointer((dword)peb,0x7FFD5000,size);

	//Fill the PEB with the important formation
	peb->ImageBaseAddress = Imagebase;//

	//Filling the pointers
	peb->LoaderData=SharedMem->get_virtual_pointer((dword)LoaderData);

	//filling the entries
	program->DllBase = Imagebase;
	program->FullDllNameLength = sprogramlength;
	program->BaseDllNameLength=sprogramlength;

	program->BaseDllName=(char*)SharedMem->get_virtual_pointer((MAX_DWORD)sprogram);
	program->FullDllName=(char*)SharedMem->get_virtual_pointer((MAX_DWORD)sprogram);

	ntdll->DllBase = sys->DLLs[1].vAddr;
	ntdll->FullDllNameLength = sntdlllength;
	ntdll->BaseDllNameLength = sntdlllength;
	ntdll->BaseDllName=(char*)SharedMem->get_virtual_pointer((MAX_DWORD)sntdll);
	ntdll->FullDllName=(char*)SharedMem->get_virtual_pointer((MAX_DWORD)sntdll);

	kernel->DllBase=sys->DLLs[0].vAddr;
	kernel->FullDllNameLength=skernel32length;
	kernel->BaseDllNameLength=skernel32length;
	kernel->BaseDllName=(char*)SharedMem->get_virtual_pointer((MAX_DWORD)skernel32);
	kernel->FullDllName=(char*)SharedMem->get_virtual_pointer((MAX_DWORD)skernel32);

	//LoaderData
	LoaderData->InLoadOrderModuleList.Flink=SharedMem->get_virtual_pointer((MAX_DWORD)program);
	LoaderData->InLoadOrderModuleList.Blink=SharedMem->get_virtual_pointer((MAX_DWORD)kernel);

	LoaderData->InMemoryOrderModuleList.Flink=SharedMem->get_virtual_pointer((MAX_DWORD)program + 0x8);          //Here the FLink is directed to the InMemoryOrderModuleList inside Program data
	LoaderData->InMemoryOrderModuleList.Blink=SharedMem->get_virtual_pointer((MAX_DWORD)kernel + 0x8);

	LoaderData->InInitializationOrderModuleList.Flink=SharedMem->get_virtual_pointer((MAX_DWORD)ntdll + 0x10);//Here the FLink is directed to the InInitializationOrderModuleList inside ntdll data
	LoaderData->InInitializationOrderModuleList.Blink=SharedMem->get_virtual_pointer((MAX_DWORD)kernel + 0x10);

	//Program
	program->InLoadOrderLinks.Flink=SharedMem->get_virtual_pointer((MAX_DWORD)ntdll);
	//program->InLoadOrderLinks.Blink=SharedMem->get_virtual_pointer((dword)ntdll);

	program->InMemoryOrderLinks.Flink=SharedMem->get_virtual_pointer((MAX_DWORD)ntdll + 0x8);
	//program->InMemoryOrderLinks.Blink=SharedMem->get_virtual_pointer((dword)ntdll);

	program->InInitializationOrderLinks.Flink=0;
	program->InInitializationOrderLinks.Blink=0;
	//ntdll
	ntdll->InLoadOrderLinks.Flink=SharedMem->get_virtual_pointer((MAX_DWORD)kernel);
	ntdll->InLoadOrderLinks.Blink=SharedMem->get_virtual_pointer((MAX_DWORD)program);

	ntdll->InMemoryOrderLinks.Flink=SharedMem->get_virtual_pointer((MAX_DWORD)kernel + 0x8);
	ntdll->InMemoryOrderLinks.Blink=SharedMem->get_virtual_pointer((MAX_DWORD)program + 0x8);

	ntdll->InInitializationOrderLinks.Flink=SharedMem->get_virtual_pointer((MAX_DWORD)kernel + 0x10);
	//ntdll->InInitializationOrderLinks.Blink=SharedMem->get_virtual_pointer((dword)kernel);

	//kernel
	//kernel->InLoadOrderLinks.Flink=SharedMem->get_virtual_pointer((dword)program);
	kernel->InLoadOrderLinks.Blink=SharedMem->get_virtual_pointer((MAX_DWORD)ntdll);

	//kernel->InMemoryOrderLinks.Flink=SharedMem->get_virtual_pointer((dword)program);
	kernel->InMemoryOrderLinks.Blink=SharedMem->get_virtual_pointer((MAX_DWORD)ntdll + 0x8);

	//kernel->InInitializationOrderLinks.Flink=SharedMem->get_virtual_pointer((dword)program);
	kernel->InInitializationOrderLinks.Blink=SharedMem->get_virtual_pointer((MAX_DWORD)ntdll + 0x10);
}
dword Process::SkipIt()
{
	this->threads[0]->Eip+= ins->hde.len;
	ins=sys->disasm(ins,(char*)SharedMem->read_virtual_mem(this->threads[0]->Eip));//,str
	return 0;
}

bool AddToTable(void * ptr)
{
	LPMEM_TBL pTemp = (LPMEM_TBL)calloc(1, sizeof(MEM_TBL));
	if(pTemp)
	{
		pTemp->lpMem = ptr;
		pTemp->pNext = g_pMallocList;
		g_pMallocList = pTemp;
		return true;
	}

	return false;
}

bool FreeTable()
{
	while(g_pMallocList)
	{
		LPMEM_TBL pHold = g_pMallocList->pNext;
		if(100 != g_pMallocList->iType)
		{
			free(g_pMallocList->lpMem);
		}

		free(g_pMallocList);
		g_pMallocList = pHold;
	}

	return true;
}

bool DeleteFromTable(void * ptr)
{
	bool bFound = false;
	LPMEM_TBL pIterator = g_pMallocList;
	while(pIterator)
	{
		if(pIterator->lpMem == ptr)
		{
			pIterator->iType = 100; // delete memory
			bFound = true;
			break;
		}

		pIterator = pIterator->pNext;
	}

	return bFound;
}

void* realloc_emu(void* ptr, size_t size)
{
	DeleteFromTable(ptr);
	void * vptr = realloc(ptr, size);

	if(vptr)
	{
		AddToTable(vptr);
	}

	return vptr;
}

void* malloc_emu(size_t size)
{
	void * vptr = malloc(size);
	if(vptr)
	{
		AddToTable(vptr);
	}
	return vptr;
}

void free_emu(void* ptr)
{
	DeleteFromTable(ptr);
	free(ptr);
}

