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


string Debugger::GetLastError(){
       return lasterror;     
};
void Debugger::RemoveBp(DWORD index){
     if (index<nbp){
        bp[index].state=BP_REMOVE;
        free_emu((dword*)bp[index].ptr);            
     
     };
};
void Debugger::PauseBp(DWORD index){
     if (index<nbp){
        bp[index].state=BP_PAUSE;          
     };
};
void Debugger::ActivateBp(DWORD index){
     if (index<nbp){
        if(bp[index].state!=BP_REMOVE)bp[index].state=BP_RUN;          
     };
};
Debugger::Debugger(){
};

bool Debugger::TestBp(Thread& thread,ins_disasm* ins){
    ins = ins;
    return false;
    
    };
int Debugger::AddBp(string s){
    return 0;
};

//Added By Adnan 25 Nov 2011
int Debugger::ModifiedBp(string s, DWORD n)
{
    return 0;
}
int Debugger::define_func(string name,int params,MAX_DWORD func,int flags){
  funcs[func_entries].name=name.append("(");
  funcs[func_entries].params=params;
  funcs[func_entries].dbg_func=func;
  funcs[func_entries].flags=flags;
  func_entries++;
	  return 0;
};
dword readfunc(Thread* thread,ins_disasm* ins,dword ptr){
     try{
         dword* ptr2 =(dword*)thread->mem->read_virtual_mem((dword)ptr);
         return *ptr2;
     }catch (...){
           return 0;
     }
};
bool isapi(Thread* thread,ins_disasm* ins){
     if (ins->flags & API_CALL)return true;
     return false;
};
bool isapiequal(Thread* thread,ins_disasm* ins,char* s){
     if (ins->flags & API_CALL){
         char* s2=(char*)to_lower_case(thread->process->getsystem()->GetTiggeredAPI(*thread)).c_str();
         if (!strcmp(s,s2))return true;           
     };
     return false;
};
bool lastaccessed(Thread* thread,dword ins,int index){
    //return thread->mem->get_memory_flags(ptr);
	//Adnan
	bool bRetStatus = false;
    if(0 != thread->mem->get_last_accessed(index))
	{
		bRetStatus = true;
	}
	return bRetStatus;
}; 
dword lastmodified(Thread* thread,dword ins,int index){
        return thread->mem->get_last_modified(index);                                 
};
int isinstruction(Thread* thread, ins_disasm* ins, char* s)
{
	if(strstr(thread->process->strInstName.c_str(),s))
	{
		return 1;		
	}
	return 0;
}
int isinstructionlength(Thread* thread, ins_disasm* ins)
{
	return (int)ins->hde.len;
}
dword dispfunc(Thread* thread,ins_disasm* ins){
      for (int i=0;i<ins->modrm.length;i++){
          if (ins->modrm.flags[i] & RM_DISP)return ins->modrm.items[i];
      }; 
      return 0;
};
dword immfunc(Thread* thread,ins_disasm* ins){
      if (ins->flags & DEST_IMM)return ins->ndest;
      if (ins->flags & SRC_IMM)return ins->nsrc;
      return 0;
};
int isdirty(Thread* thread,dword ins,int ptr){
    return thread->mem->get_memory_flags(ptr);
};
int Debugger::init_funcs(){
    define_func("isdirty",1,(MAX_DWORD)&isdirty,0);
    define_func("lastmodified",1,(MAX_DWORD)&lastmodified,0);
    define_func("lastwritten",1,(MAX_DWORD)&lastmodified,0);
    define_func("lastaccessed",1,(MAX_DWORD)&lastaccessed,0);
    define_func("isapi",0,(MAX_DWORD)&isapi,0);
    define_func("rm",0,(MAX_DWORD)&modrm_calc,0);
    define_func("disp",0,(MAX_DWORD)&dispfunc,0);
    define_func("imm",0,(MAX_DWORD)&immfunc,0);
    define_func("read",1,(MAX_DWORD)&readfunc,0);
    define_func("isapiequal",1,(MAX_DWORD)&isapiequal,0);
    define_func("isinstruction",1,(MAX_DWORD)&isinstruction,0);
    define_func("isinstructionlength",0,(MAX_DWORD)&isinstructionlength,0);
	  return 0;
};
