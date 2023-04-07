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

int GetProcAddress_emu(Thread* thread,dword* Args)
{
	Process* c=thread->GetProcess();
	if(!c->m_bHandleAPIs)
	{
		free_emu(Args);
		return 0;
	}
	char* str=0;
	dword* readptr;
	API_READ_MEM(readptr,Args[1]);	
	str=(char*)readptr; 
	if (str[0]==0)return 0;                           //if the string begins with zero
	//invalid pointer return 0            
	//if valid don't return zero but return any address
	if (Args[0]==0)
	{
		if(c->nimports)
		{
			return 0xBBBB0000 + (c->imports[c->nimports-1]->napis << 8) + c->nimports;
		}
		return 0xBBBB0000; 
	}
	API_READ_MEM(readptr,Args[0]);
	dword dllhandle=(dword)readptr;
	wchar_t szwStr[MAX_PATH] = {0};
	convert_cptr2wcptr(str, szwStr, _countof(szwStr));
	dword ptr=thread->process->getsystem()->GetAPI(szwStr,dllhandle);
	ptr=thread->mem->get_virtual_pointer(ptr);
	if (c->imports[c->nimports-1]->napis == (MAX_NUM_APIS_PER_DLL -1))return ptr;
	c->imports[c->nimports-1]->apis[c->imports[c->nimports-1]->napis]=Args[1];
	c->imports[c->nimports-1]->napis++;
	if (ptr==0)
	{
		//A magic number to search again for it to reconstruct the import table
		//cout << (int*)(0xBBBB0000+((c->imports[c->nimports-1]->napis-1) << 8) +c->nimports-1)<<"\n";
		if(c->nimports)
		{
			return 0xBBBB0000+((c->imports[c->nimports-1]->napis-1) << 8) +c->nimports-1;
		}
		return 0xBBBB0000;
	}
	free_emu(Args);
	return ptr;
};

int GetModuleHandleA_emu(Thread* thread,dword* Args){
    if (Args[0]==0)return thread->GetProcess()->GetImagebase();
    dword* readptr;
    API_READ_MEM(readptr,Args[0]);
    char* str=(char*)readptr;
	wchar_t szwStr[MAX_PATH] = {0};
	convert_cptr2wcptr(str, szwStr, _countof(szwStr));
    dword ptr=thread->process->getsystem()->GetDllBase(szwStr);
    ptr=thread->mem->get_virtual_pointer(ptr);
    Process* c=thread->process;
    c->imports[c->nimports]=(Imports*)malloc_emu(sizeof(Imports));
    memset(c->imports[c->nimports],0,sizeof(Imports));
    c->imports[c->nimports]->name=Args[0];
    c->imports[c->nimports]->addr=ptr;
    c->imports[c->nimports]->defined=true;
    if(ptr==0){
               ptr=thread->process->getsystem()->DLLs[0].vAddr;
               c->imports[c->nimports]->addr=0xBBBBBB00+c->nimports;
               c->imports[c->nimports]->defined=false;
    }
    c->nimports++;
    return ptr;
};

int LoadLibraryA_emu(Thread* thread,dword* Args)
{
	if(!thread->process->m_bHandleAPIs)
	{
		free_emu(Args);
		return 0;
	}
    dword* readptr; 
    API_READ_MEM(readptr,Args[0]);
    char* str=(char*)readptr;
	wchar_t szwStr[MAX_PATH] = {0};
	convert_cptr2wcptr(str, szwStr, _countof(szwStr));
    dword ptr=thread->process->getsystem()->GetDllBase(szwStr);
    ptr=thread->mem->get_virtual_pointer(ptr);
    Process* c=thread->process;
    c->imports[c->nimports]=(Imports*)malloc_emu(sizeof(Imports));
    memset(c->imports[c->nimports],0,sizeof(Imports));
    c->imports[c->nimports]->name=Args[0];
    c->imports[c->nimports]->addr=ptr;
    c->imports[c->nimports]->defined=true;
    if(ptr==0){
               ptr=thread->process->getsystem()->DLLs[0].vAddr;
               c->imports[c->nimports]->addr=0xBBBBBB00+c->nimports;
               c->imports[c->nimports]->defined=false;
    }
    c->nimports++;
    return ptr;
};

int VirtualAlloc_emu(Thread* thread,dword* Args)
{    
	if(Args[1] > (20*1024*1024))
	{
		free_emu(Args);
		return 0;
	}

	if(!thread->process->m_bHandleAPIs)
	{
		free_emu(Args);
		return 0;
	}
    bool x=false;
    if((Args[1] & 0x0FFF) !=0)Args[1] = (Args[1] & 0xFFFFF000) +0x1000;      //round it to 0x1000
    dword ptr=(dword)malloc_emu(Args[1]);             //the size
    memset((void*)ptr,0,Args[1]);
    dword addr=Args[0];                    //the address      
        if (thread->mem->read_virtual_mem(addr) == 0)x=true;
        else x=false;
    if (addr==0 || (thread->mem->read_virtual_mem(addr) == 0)){
        addr=thread->mem->CommittedPages;
        thread->mem->CommittedPages+=0x10000+(Args[1]& 0xffff0000);
    };
    thread->mem->add_pointer(ptr,addr,Args[1]);
    return addr;
};
int VirtualFree_emu(Thread* thread,dword* Args){
    thread->mem->delete_pointer(Args[0]);
    return 1;
};
int VirtualProtect_emu(Thread* thread,dword* Args){
    dword vptr=Args[0];
    dword* readptr;
    API_READ_MEM(readptr,Args[0]);
    dword rptr=(dword)readptr;
    if((Args[1] & 0x0FFF) !=0)Args[1] = (Args[1] & 0xFFFFF000) +0x1000;      //round it to 0x1000
    dword size=Args[1];
    thread->mem->add_pointer(rptr,vptr,size,MEM_VIRTUALPROTECT);  
    return 1;
};
int SetUnhandledExceptionFilter_emu(Thread* thread,dword* Args){
    thread->stack->push(Args[0]);
    thread->stack->push(*thread->mem->read_virtual_mem(thread->GetFS()));
    *thread->mem->read_virtual_mem(thread->GetFS()) = thread->Exx[4];
	return 0;
};

int LocalAlloc_emu(Thread* thread,dword* Args)
{   
	if((Args[1] & 0x0FFF) !=0)
	{
		Args[1] = (Args[1] & 0xFFFFF000) +0x1000;      //round it to 0x1000
	}
    dword ptr =(dword)malloc_emu(Args[1]);             //the size
    memset((void*)ptr,0,Args[1]);
	thread->mem->add_pointer(ptr,ptr,Args[1]);
	return ptr;
}
