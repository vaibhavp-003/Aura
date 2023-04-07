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

bool is_negative(dword num,dword ins_flags);
char PF_Flags[256]={
                1,0,0,1,0,1,1,0,
                0,1,1,0,1,0,0,1,
                0,1,1,0,1,0,0,1,
                1,0,0,1,0,1,1,0,
                0,1,1,0,1,0,0,1,
                1,0,0,1,0,1,1,0,
                1,0,0,1,0,1,1,0,
                0,1,1,0,1,0,0,1,
                0,1,1,0,1,0,0,1,
                1,0,0,1,0,1,1,0,
                1,0,0,1,0,1,1,0,
                0,1,1,0,1,0,0,1,
                1,0,0,1,0,1,1,0,
                0,1,1,0,1,0,0,1,
                0,1,1,0,1,0,0,1,
                1,0,0,1,0,1,1,0,
                0,1,1,0,1,0,0,1,
                1,0,0,1,0,1,1,0,
                1,0,0,1,0,1,1,0,
                0,1,1,0,1,0,0,1,
                1,0,0,1,0,1,1,0,
                0,1,1,0,1,0,0,1,
                0,1,1,0,1,0,0,1,
                1,0,0,1,0,1,1,0,
                1,0,0,1,0,1,1,0,
                0,1,1,0,1,0,0,1,
                0,1,1,0,1,0,0,1,
                1,0,0,1,0,1,1,0,
                0,1,1,0,1,0,0,1,
                1,0,0,1,0,1,1,0,
                1,0,0,1,0,1,1,0,
                1,0,0,1,0,1,1,0,
};
Thread::Thread(){
            //this for the parser as we don't need anything from the thread just work in pointers    
}

Process* Thread::GetProcess(){
     return process;
};
Thread::Thread(dword neip,Process &s):
tls_callback_index(0)
{
	// initialize the thread
	stack = NULL;
	log = NULL;
	tib = NULL;
	process=&s;
	//create the stack
	//it's created from tests only and I didn't use the Heap Commit & Reserve
	//I use it from 0x00126000 to 0x0013000
	seh_enable=true;

	MAX_DWORD x = (MAX_DWORD)malloc_emu(0xA000);
	memset((void*)x,0,0xA000);

	stack = new Stack(*this);

	mem = process->SharedMem;
	mem->add_pointer(x, (DWORD)0x00126000, (DWORD)0xA000);
	memset(Exx, 0, sizeof(Exx)); 
	EFlags = 0;

	Exx[4]=0x0012FF90;                                //esp
	Exx[5]=0x0012FF94;                                //ebp

	tib = NULL;
	//preparing the TIB,TEB
	CreateTEB();
	still_tls=false;
	/**dword image=(dword)s.SharedMem->read_virtual_mem(s.GetImagebase());
	dword PEHeader_ptr=((dos_header*)image)->e_lfanew + image;
	image_header* PEHeader=(image_header*)PEHeader_ptr;
	if (PEHeader->optional.data_directory[IMAGE_DIRECTORY_ENTRY_TLS].virtual_address!=0)
	{
	_IMAGE_TLS_DIRECTORY* tlsheader= NULL;
	tlsheader=(_IMAGE_TLS_DIRECTORY*)((dword)PEHeader->optional.data_directory[IMAGE_DIRECTORY_ENTRY_TLS].virtual_address + image);
	if(tlsheader && tlsheader->AddressOfCallBacks != 0)
	{
	dword* callbacks=s.SharedMem->read_virtual_mem((dword)tlsheader->AddressOfCallBacks);
	if(callbacks && callbacks[0] != 0)
	{
	stack->push(0);
	stack->push(1);
	stack->push(0);
	stack->push(TLS_MAGIC);
	this->Eip=callbacks[0];
	log=new Log(this->Eip);
	still_tls=true;
	tls_callback_index++;
	}
	}
	}*/
	entry_point=neip;
	if (still_tls ==false)
	{
		this->Eip = neip;
		log = new Log(neip); 
		if (process->IsDLL)
		{
			stack->push(0);
			stack->push(1);
			stack->push(process->GetImagebase());
		}
		stack->push((DWORD)(mem->get_virtual_pointer(process->getsystem()->APITable[0].addr)));             //pushes the pointer to ExitProcess (some viruses get the kernelbase from it
	}
	//preparing FPU

	SelectedReg=0;
	for (int i=0;i<8;i++)
	{
		ST[i] = 0;    
	}
};

Thread::~Thread()
{
	if(stack)
	{
		delete stack;
		stack = NULL;
	}
	if(log)
	{
		delete log;
 		log = NULL;
	}
	if(tib)
	{
		free_emu(tib);
		tib = NULL;
	}
}

int Thread::updateflags(dword dest,dword src,dword result,int flags,dword ins_flags)
{
	bool CF=false;             //reserve The CF 

	if ((EFlags & EFLG_CF) && (flags != UPDATEFLAGS_ADD) && (flags != UPDATEFLAGS_SUB) && (flags != UPDATEFLAGS_CMP))
	{
		CF=true;    //save the CF before being deleted
	}
	this->EFlags=EFLG_SYS;
	//--------------------------------------------------
	//ZF & SF & OF
	if (result==0)
	{
		EFlags |=EFLG_ZF;//zero
	}
	if (is_negative(result,ins_flags)) 
	{
		EFlags |=EFLG_SF;                             //negative
	}
	if(flags == UPDATEFLAGS_CMP)
	{
		if((is_negative(dest,ins_flags) == true) && (is_negative(src,ins_flags) == false) && (is_negative(((~dest) + src + 1),ins_flags) == true))
		{			 		
			EFlags |=EFLG_OF;			
		}
		else if(((is_negative(dest,ins_flags) == false) && (is_negative(src,ins_flags) == true)) && (is_negative(((dest) + (~src) + 1),ins_flags) == true))
		{			
			EFlags |=EFLG_OF;
		}		
	}
	else if ((flags == UPDATEFLAGS_ADD || flags == UPDATEFLAGS_SUB) && is_negative(dest,ins_flags)==false && is_negative(result,ins_flags)==true)
	{
		EFlags |=EFLG_OF;        //From Positive to Negative
	}
	//--------------------------------------------------
	//CF & AF
	if ((flags == UPDATEFLAGS_ADD) && (dest > result))
	{
		EFlags |=EFLG_CF |EFLG_AF;        //overflow of positive
	}
	if (((flags == UPDATEFLAGS_SUB) || (flags == UPDATEFLAGS_CMP)) && (result > dest))
	{
		EFlags |=EFLG_CF |EFLG_AF;        //overflow of negative
	}
	//-------------------------------------------------
	//PF
	BYTE PFindex = result & 0xFF;
	if (PF_Flags[PFindex] == 1)
	{
		EFlags |=EFLG_PF;
	}

	if (CF) EFlags |= EFLG_CF;                                  //restore CF
	return 0;
}

//This function determines if this number is positive or negative based on the operand size
bool is_negative(dword num,dword ins_flags){
     
    if (ins_flags & DEST_BITS8)
    {
       if (num & 0x80)return true;
       else return false;
    }else if(ins_flags & DEST_BITS16)
    {
       if (num & 0x8000)return true;
       else return false;
    }else 
    {
         if (num & 0x80000000)return true;
       else return false; 
    }
//    return false;
};

void Thread::CreateTEB()
{
     tib = (TIB*)malloc_emu(sizeof(TEB)+sizeof(TIB));
     memset(tib,0,sizeof(TEB)+sizeof(TIB));

     teb=(TEB*)((MAX_DWORD)tib+(dword)sizeof(TIB));
     tib->ExceptionList=0x0012FFC4;

     int n=0xFFFFFFFF;                                              //End of SEH Chain

     mem->write_virtual_mem((dword)tib->ExceptionList,(dword)4,(char*)&n);
     mem->write_virtual_mem((dword)(tib->ExceptionList+4),(dword)4,(char*)&n);

     tib->TIB1=0x7FFDF000;                                           //pointer to SEH Chain
     teb->Peb=0x7FFD5000;
     this->fs=0x7FFDF000;                                          //set the fs segment to this place
     mem->add_pointer((MAX_DWORD)tib,0x7FFDF000,sizeof(TEB)+sizeof(TIB));
}

dword Thread::GetFS()
{
      return fs;
}

void Thread::TLSContinue()
{
    if (still_tls)
	{
        dword image=(dword)mem->read_virtual_mem(process->GetImagebase());
        dword PEHeader_ptr=((dos_header*)image)->e_lfanew + image;
        image_header* PEHeader=(image_header*)PEHeader_ptr;
        _IMAGE_TLS_DIRECTORY* tlsheader=(_IMAGE_TLS_DIRECTORY*)((dword)PEHeader->optional.data_directory[IMAGE_DIRECTORY_ENTRY_TLS].virtual_address + image);
        MAX_DWORD* callbacks=mem->read_virtual_mem((dword)tlsheader->AddressOfCallBacks);
        if (callbacks && callbacks[tls_callback_index] != 0)
		{
            stack->push(0);
            stack->push(1);
            stack->push(0);
            stack->push(TLS_MAGIC);
            this->Eip=callbacks[tls_callback_index];
            log=new Log(this->Eip);
            still_tls=true;
            tls_callback_index++;
        }
		else
		{
            still_tls=false;
            this->Eip=entry_point;
            log=new Log(entry_point);
        }
    }
}

BOOL  Thread::UpdateSpecifyRegister(DWORD dwRegIndex, DWORD dwNewValue)
{
	if(dwRegIndex >= 0x08)
	{
		return FALSE;
	}
	Exx[dwRegIndex] = dwNewValue;
	return TRUE;
}

