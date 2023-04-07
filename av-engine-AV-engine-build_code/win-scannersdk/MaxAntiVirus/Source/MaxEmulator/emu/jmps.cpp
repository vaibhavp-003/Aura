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

//this file for emulating the jmps and push &pop to stack


//PUSH & POP
int op_push(Thread& thread,ins_disasm* s){
    int dest=0;
    if (s->flags & DEST_IMM){
             if (s->hde.flags & F_IMM8 && (s->ndest & 0x80))s->ndest+=0xFFFFFF00;   
             dest=s->ndest;
    }else if (s->flags & DEST_REG){
          int dest2=thread.Exx[s->ndest];
          if (s->flags & DEST_BITS32)memcpy(&dest,&dest2,4);
          if (s->flags & DEST_BITS16)memcpy(&dest,&dest2,2);
          if (s->flags & DEST_BITS8)memcpy(&dest,&dest2,1); 
    }else if (s->flags & DEST_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          if (s->flags & DEST_BITS32)memcpy(&dest,ptr,4);
          if (s->flags & DEST_BITS16)memcpy(&dest,ptr,2);
          if (s->flags & DEST_BITS8)memcpy(&dest,ptr,1); 
    };
    if (s->hde.flags & F_PREFIX_66){
        EMU_WRITE_MEM(thread.Exx[4]-2,(dword)2,(char*)&dest) ;
        thread.Exx[4]-=2;
    }else
    thread.stack->push(dest);
    //cout << "src = " << dest << "\n";
    return 0;
};
//---------------
int op_pop(Thread& thread,ins_disasm* s)
{	
	dword src = 0;
	if (s->hde.flags & F_PREFIX_66)
	{
		dword* src2 = NULL;             
		EMU_READ_MEM(src2, thread.Exx[4]);
		src=(dword)src2;
		thread.Exx[4]+=2;
	}
	else
	{
		try
		{
			src=(dword)thread.stack->pop();
		}
		catch (int iErr)
		{
			return iErr;
		}
	}
	dword dest,result;

	if (s->flags & DEST_REG)
	{
		dest=thread.Exx[s->ndest];
		if (s->flags & DEST_BITS32)
		{
			memcpy(&thread.Exx[s->ndest],&src,4);
		}
		if (s->flags & DEST_BITS16)
		{
			memcpy(&thread.Exx[s->ndest],&src,2);
		}
		if (s->flags & DEST_BITS8)
		{
			memcpy(&thread.Exx[s->ndest],&src,1);
		}
		result=thread.Exx[s->ndest];
	}
	else if (s->flags & DEST_RM)
	{
		dword* ptr;
		EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
		dest=*ptr;
		if (s->flags & DEST_BITS32)
		{
			dword n=src;
			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&n);
		}
		if (s->flags & DEST_BITS16)
		{
			short n= (short)src;
			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&n);
		}
		if (s->flags & DEST_BITS8)
		{
			char n= (char)src;   
			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&n);
		}
		result=*ptr;
	}
	return 0;
};
//----------------------------------------------------------------------------------------
//PUSHAD & POPAD
int op_pushad(Thread& thread,ins_disasm* s)
{
	s = s;
    for (int i=0;i<8;i++)
	{
        thread.stack->push(thread.Exx[i]);
    }
    return 0;
}

int op_popad(Thread& thread,ins_disasm* s)
{
	try
	{
		for (int i=7; i>=0; i--)
		{
			if (i != 4)
			{
				thread.Exx[i]=thread.stack->pop();
			}
			else
			{
				thread.stack->pop();
			}
		}
	}
	catch(int iErr)
	{
		return iErr;
	}
	return 0;
}
//----------------------------------------------------------------------------------------
//PUSHFD & POPFD
int op_pushfd(Thread& thread,ins_disasm* s){
	s = s;
    thread.stack->push(thread.EFlags);
    return 0;
};
int op_popfd(Thread& thread,ins_disasm* s){
	s = s;
	try
	{
		thread.EFlags=thread.stack->pop();
	}
	catch(int iErr)
	{
		return iErr;
	}
    return 0;
};
//----------------------------------------------------------------------------------------
int op_enter(Thread& thread,ins_disasm* s){
    thread.stack->push(thread.Exx[5]);
        thread.Exx[5]=thread.Exx[4];
    for (int i=0;i<s->nsrc;i++){
        thread.stack->push(thread.Exx[5]);
        thread.Exx[5]=thread.Exx[4];
    };
    thread.Exx[4]-=s->ndest;
    //thread.Eip=thread.stack->pop();
    return 0;
};
//----------------------------------------------------------------------------------------
int op_leave(Thread& thread,ins_disasm* s){
	s = s;
    thread.Exx[4]=thread.Exx[5];
	try
	{
		dword src=(dword)thread.stack->pop();
		memcpy(&thread.Exx[5],&src,4);
	}
	catch(int iErr)
	{
		return iErr;
	}
    //thread.Eip=thread.stack->pop();
    return 0;
};
//=============================================================================================================
//JCC
int op_jcc(Thread& thread,ins_disasm* s){
    int dest=0;
    bool rel=false;
    if (s->flags & DEST_IMM){
             dest=s->ndest;
             //converting the negative imm8 to negative imm32
             if ((s->flags & DEST_BITS8) && (dest >> 7) ==1)dest+=0xFFFFFF00;
             rel=true; //that's mean that the dest will be added to or subtracted from the eip of the thread
    }else if (s->flags & DEST_REG){
           dest=thread.Exx[s->ndest];
    }else if (s->flags & DEST_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          memcpy(&dest,ptr,4);
    };
    //now we have the offset and now we need to chack if we will jump to it or not
    //cout <<s->opcode->substr(0,s->opcode->size()) <<"\n";
    if (s->opcode->substr(0,s->opcode->size()) =="jmp"){goto Yes_JmptoIt;
    }else if(s->opcode->substr(0,s->opcode->size()) =="ja" || s->opcode->substr(0,s->opcode->size()) =="jnbe"){
          if (!(thread.EFlags & EFLG_CF) && !(thread.EFlags & EFLG_ZF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jae" || s->opcode->substr(0,s->opcode->size()) =="jnb"){
          if (!(thread.EFlags & EFLG_CF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jnae" || s->opcode->substr(0,s->opcode->size()) =="jb"){
          if (thread.EFlags & EFLG_CF)goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jbe" || s->opcode->substr(0,s->opcode->size()) =="jna"){
          if ((thread.EFlags & EFLG_CF) || (thread.EFlags & EFLG_ZF))goto Yes_JmptoIt;
           
    }else if(s->opcode->substr(0,s->opcode->size()) =="je" || s->opcode->substr(0,s->opcode->size()) =="jz"){
          if (thread.EFlags & EFLG_ZF)goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jne" || s->opcode->substr(0,s->opcode->size()) =="jnz"){
          if (!(thread.EFlags & EFLG_ZF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jnp" || s->opcode->substr(0,s->opcode->size()) =="jpo"){
          if (!(thread.EFlags & EFLG_PF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jp" || s->opcode->substr(0,s->opcode->size()) =="jpe"){
          if (thread.EFlags & EFLG_PF)goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jg" || s->opcode->substr(0,s->opcode->size()) =="jnle"){
          if (!(((thread.EFlags & EFLG_SF) == EFLG_SF) ^ ((thread.EFlags & EFLG_OF) == EFLG_OF)) && !(thread.EFlags & EFLG_ZF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jnge" || s->opcode->substr(0,s->opcode->size()) =="jl"){
          if (((thread.EFlags & EFLG_SF) == EFLG_SF) ^ ((thread.EFlags & EFLG_OF) == EFLG_OF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jge" || s->opcode->substr(0,s->opcode->size()) =="jnl"){
          if (!((((thread.EFlags & EFLG_SF) == EFLG_SF)) ^ ((thread.EFlags & EFLG_OF) == EFLG_OF)))goto Yes_JmptoIt;                //not SF xor OF as 1 xor 1 == jump
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jle" || s->opcode->substr(0,s->opcode->size()) =="jng"){
          if (((thread.EFlags & EFLG_SF) == EFLG_SF) ^ ((thread.EFlags & EFLG_OF) == EFLG_OF) || (thread.EFlags & EFLG_ZF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jns"){
          if (!(thread.EFlags & EFLG_SF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="js"){
          if (thread.EFlags & EFLG_SF)goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jno"){
          if (!(thread.EFlags & EFLG_OF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="jo"){
          if (thread.EFlags & EFLG_OF)goto Yes_JmptoIt;
          
    }else if(s->hde.opcode==0xE3&& !(s->hde.flags & F_PREFIX_67)){
          if (thread.Exx[1]==0)goto Yes_JmptoIt;      
          
    }else if(s->hde.opcode==0xE3&& (s->hde.flags & F_PREFIX_67 )){
          if ((thread.Exx[1] & 0xffff)==0)goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="loop" ){
          thread.Exx[1]--;
           if (thread.Exx[1]!=0){       
              goto Yes_JmptoIt;
           };
    }else if(s->opcode->substr(0,s->opcode->size()) =="loope" || s->opcode->substr(0,s->opcode->size()) =="loopz"){
          thread.Exx[1]--;
          if (thread.EFlags & EFLG_ZF && thread.Exx[1]!=0){
             goto Yes_JmptoIt;
          };
    }else if(s->opcode->substr(0,s->opcode->size()) =="loopne" || s->opcode->substr(0,s->opcode->size()) =="loopnz"){
          thread.Exx[1]--;
          if (!(thread.EFlags & EFLG_ZF) && thread.Exx[1]!=0){
             goto Yes_JmptoIt;
          };
    };
    
    return 0;
Yes_JmptoIt:
            if (rel){
                     thread.Eip=(dword)((signed int)thread.Eip+(signed int)dest);
            }else{
                  thread.Eip=dest;//- s->hde.len;
            };
            
    return 0;
};
//=============================================================================================================
//SETCC
int op_setcc(Thread& thread,ins_disasm* s){
    char* ptr=0;
    //bool rel=false;
    if (s->flags & DEST_REG){
           if (s->ndest < 3)ptr=(char*)&thread.Exx[s->ndest];
           else{
                ptr=(char*)&thread.Exx[s->ndest-4];
                ptr++;
           }
    }else if (s->flags & DEST_RM){
          dword* ptr2;
          EMU_READ_MEM(ptr2,(dword)modrm_calc(thread,s));
          ptr = (char*)ptr2;
    };
    //now we have the offset and now we need to chack if we will jump to it or not
    //cout <<s->opcode->substr(0,s->opcode->size()) <<"\n";
    if(s->opcode->substr(0,s->opcode->size()) =="seta" || s->opcode->substr(0,s->opcode->size()) =="setnbe"){
          if (!(thread.EFlags & EFLG_CF) && !(thread.EFlags & EFLG_ZF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setae" || s->opcode->substr(0,s->opcode->size()) =="setnb"){
          if (!(thread.EFlags & EFLG_CF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setnae" || s->opcode->substr(0,s->opcode->size()) =="setb"){
          if (thread.EFlags & EFLG_CF)goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setbe" || s->opcode->substr(0,s->opcode->size()) =="setna"){
          if ((thread.EFlags & EFLG_CF) || (thread.EFlags & EFLG_ZF))goto Yes_JmptoIt;
           
    }else if(s->opcode->substr(0,s->opcode->size()) =="sete" || s->opcode->substr(0,s->opcode->size()) =="setz"){
          if (thread.EFlags & EFLG_ZF)goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setne" || s->opcode->substr(0,s->opcode->size()) =="setnz"){
          if (!(thread.EFlags & EFLG_ZF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setnp" || s->opcode->substr(0,s->opcode->size()) =="setpo"){
          if (!(thread.EFlags & EFLG_PF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setp" || s->opcode->substr(0,s->opcode->size()) =="setpe"){
          if (thread.EFlags & EFLG_PF)goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setg" || s->opcode->substr(0,s->opcode->size()) =="setnle"){
          if (!(thread.EFlags & EFLG_SF) ^(thread.EFlags & EFLG_OF) && !(thread.EFlags & EFLG_ZF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setnge" || s->opcode->substr(0,s->opcode->size()) =="setl"){
          if ((thread.EFlags & EFLG_SF) ^(thread.EFlags & EFLG_OF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setge" || s->opcode->substr(0,s->opcode->size()) =="setnl"){
          if (!((thread.EFlags & EFLG_SF) ^(thread.EFlags & EFLG_OF)))goto Yes_JmptoIt;                //not SF xor OF as 1 xor 1 == set
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setle" || s->opcode->substr(0,s->opcode->size()) =="setng"){
          if ((thread.EFlags & EFLG_SF) ^(thread.EFlags & EFLG_OF) || (thread.EFlags & EFLG_ZF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setns"){
          if (!(thread.EFlags & EFLG_SF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="sets"){
          if (thread.EFlags & EFLG_SF)goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="setno"){
          if (!(thread.EFlags & EFLG_OF))goto Yes_JmptoIt;
          
    }else if(s->opcode->substr(0,s->opcode->size()) =="seto"){
          if (thread.EFlags & EFLG_OF)goto Yes_JmptoIt;
          
    }else if(s->hde.opcode==0xE3&& !(s->hde.flags & F_PREFIX_67)){
          if (thread.Exx[1]==0)goto Yes_JmptoIt;      
          
    }else if(s->hde.opcode==0xE3&& (s->hde.flags & F_PREFIX_67 )){
          if ((thread.Exx[1] & 0xffff)==0)goto Yes_JmptoIt;
    };
    
    return 0;
Yes_JmptoIt:
            *ptr=1;
            
    return 0;
};
//=============================================================================================================
//CALL
int op_call(Thread& thread,ins_disasm* s){
    int dest=0;
    bool rel=false;
    if (s->flags & DEST_IMM){
             dest=s->ndest;
             rel=true; //that's mean that the dest will be added to or subtracted from the eip of the thread
    }else if (s->flags & DEST_REG){
           dest=thread.Exx[s->ndest];
    }else if (s->flags & DEST_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          memcpy(&dest,ptr,4);
    };
    //push the pointer to the next instruction
    //we work here as the process increase the eip before emulating the instruction so the eip now pointing to the next instruction
    thread.stack->push(thread.Eip);
    if (rel){       
       thread.Eip=(dword)((signed int)thread.Eip+(signed int)dest) ;//- s->hde.len+1;
    }else{
          thread.Eip=dest; //we subtract it because the process::emulate  will add it again
    };
    return 0;
};
//=============================================================================================================
//RET
int op_ret(Thread& thread,ins_disasm* s){
    //int bf = 0;
     //int dest=0;
    //this for the parameters of the function
	try
	{
		thread.Eip=thread.stack->pop();
	}
	catch(int iErr)
	{
		return iErr;
	}
    if (s->flags & DEST_IMM){
             thread.Exx[4]+=s->ndest;             
    };
    if (thread.Eip==TLS_MAGIC && thread.still_tls){
        thread.TLSContinue();
    }
#ifndef WIN64
    if (thread.Eip==SEH_MAGIC){                  
       thread.sehReturn();
    };
#endif

    return 0;
};
