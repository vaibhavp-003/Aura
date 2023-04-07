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
#include "../macros.h"

extern "C" int __stdcall SAR_32(int src, DWORD n, DWORD *m);
extern "C" int __stdcall SAR_16(int src, unsigned short n, DWORD *m);
extern "C" int __stdcall SAR_HIGH_8(int src, DWORD n, DWORD *m);
extern "C" int __stdcall SAR_LOW_8(int src, char n, DWORD *m);

extern "C" int __stdcall RCL_32(int src, DWORD n, DWORD *m);
extern "C" int __stdcall RCL_16(int src, WORD n, DWORD *m);
extern "C" int __stdcall RCL_HIGH_8(int src, DWORD n, DWORD *m);
extern "C" int __stdcall RCL_LOW_8(int src, char n, DWORD *m);

extern "C" int __stdcall RCR_32(int src, DWORD n, DWORD *m);
extern "C" int __stdcall RCR_16(int src, WORD n, DWORD *m);
extern "C" int __stdcall RCR_HIGH_8(int src, DWORD n, DWORD *m);
extern "C" int __stdcall RCR_LOW_8(int src, char n, DWORD *m);

//---------------------------------------------------------------------------------
//SHL
int op_shl(Thread& thread,ins_disasm* s){
    //first we will test the source and get the value that we will put in the dest in src variable
    dword dest = 0,result = 0;
    int src=0;
    if (s->flags & SRC_IMM){
             src=s->nsrc & 0x1F;        //not bigger than 31

    }else if (s->flags & SRC_REG){
          dword src2=thread.Exx[1];
          memcpy(&src,&src2,1);
    };
    // now we have the value of the src that we will put it in the dest now we will test the dest
    if (s->flags & DEST_REG){
          dest=thread.Exx[s->ndest];
          dword n=thread.Exx[s->ndest];
          n=n << src;
          if (s->flags & DEST_BITS32){memcpy(&thread.Exx[s->ndest],&n,4);result=thread.Exx[s->ndest];}
          if (s->flags & DEST_BITS16){memcpy(&thread.Exx[s->ndest],&n,2);result=thread.Exx[s->ndest] & 0xffff;}
          if (s->flags & DEST_BITS8){      
             char* dest2=(char*)&thread.Exx[s->ndest];
             if (s->ndest >3){
                          dest2=(char*)(&thread.Exx[s->ndest-4]);
                          dest2++;
             };
             *dest2 =*dest2 << src;
             result=*dest2 &0xff;        
          };
          
    }else if (s->flags & DEST_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          dword n=*ptr;
          dest=n;
          if (s->flags & DEST_BITS32){
             dword n=*ptr;
             n=(n & 0xffffffff) << src;
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&n);
             
          };
          if (s->flags & DEST_BITS16){
             unsigned short n= (unsigned short)*ptr;
             n=(n & 0xffff) << src;      
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&n);
          };
          if (s->flags & DEST_BITS8){
             char n= (char)*ptr;
             n=(n & 0xff) << src;
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&n);
          };
          result=*ptr;
    };    
    thread.updateflags(dest,0,result,0,s->flags);   
    thread.EFlags &= (EFLG_PF | EFLG_ZF | EFLG_SF |EFLG_SYS);
    //Set The CF with the last shifted out bit
    if (s->flags & DEST_BITS16){
       if ((dest >> (16- src)) & 1)thread.EFlags |=EFLG_CF;
    }else if (s->flags & DEST_BITS8){
         if ((dest >> (8 - src)) & 1)thread.EFlags |=EFLG_CF; 
    }else{
          if ((dest >> (32- src)) & 1)thread.EFlags |=EFLG_CF;
    }
    //cout << "dest= "<<(int*)dest << "\nresult= " << (int*)result<<"\nflags= "<< (int*)thread.EFlags << "\n";   
    return 0;
};
//---------------------------------------------------------------------------------
//SHR
int op_shr(Thread& thread,ins_disasm* s){
    //first we will test the source and get the value that we will put in the dest in src variable
    dword dest = 0,result = 0;
    int src=0;
    if (s->flags & SRC_IMM){
             src=s->nsrc & 0x1F;        //not bigger than 31
    }else if (s->flags & SRC_REG){
          dword src2=thread.Exx[1];
          memcpy(&src,&src2,1);
    };
    // now we have the value of the src that we will put it in the dest now we will test the dest
    if (s->flags & DEST_REG){
          dest=thread.Exx[s->ndest];
          dword n=thread.Exx[s->ndest];
          if (s->flags & DEST_BITS32){n=n >> src;memcpy(&thread.Exx[s->ndest],&n,4);result=thread.Exx[s->ndest];}
          if (s->flags & DEST_BITS16){n &= 0xffff;n=n >> src; memcpy(&thread.Exx[s->ndest],&n,2);result=thread.Exx[s->ndest];}
          if (s->flags & DEST_BITS8){      
             char* dest2=(char*)&thread.Exx[s->ndest];
             if (s->ndest >3){
                          dest2=(char*)(&thread.Exx[s->ndest-4]);
                          dest2++;
             };
             dest=*dest2;
             n=0;
             n=*dest2 & 0xff;
             *dest2 = (char)(n >> src);
             result=(*dest2) & 0xff;
          };
    }else if (s->flags & DEST_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          dword n=*ptr;
          dest=n;
          if (s->flags & DEST_BITS32){
             dword n=*ptr;
             n=(n & 0xffffffff) >> src;
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&n);
             
          };
          if (s->flags & DEST_BITS16){
             unsigned short n= (unsigned short)*ptr;
             n=(n & 0xffff) >> src;      
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&n);
          };
          if (s->flags & DEST_BITS8){
             char n= (char)*ptr;
             n=(n & 0xff) >> src;
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&n);
          };
          result=*ptr;
    };    
    thread.updateflags(dest,0,result,0,s->flags);   
    thread.EFlags &= (EFLG_PF | EFLG_ZF | EFLG_SF |EFLG_SYS);
    if ((dest >> (src -1)) & 1)thread.EFlags |=EFLG_CF;
    //cout << "dest= "<<(int*)dest << "\nresult= " << (int*)result<<"\nflags= "<< (int*)thread.EFlags << "\n";   
    return 0;
};
//---------------------------------------------------------------------------------
//ROL
int op_rol(Thread& thread,ins_disasm* s){
    //first we will test the source and get the value that we will put in the dest in src variable
    dword dest = 0,result = 0;
    int src=0;
    if (s->flags & SRC_IMM){
             src=s->nsrc;

    }else if (s->flags & SRC_REG){
          dword src2=thread.Exx[1];
          memcpy(&src,&src2,1);
    };
    // now we have the value of the src that we will put it in the dest now we will test the dest
    if (s->flags & DEST_REG){
          dest=thread.Exx[s->ndest];
          dword n=thread.Exx[s->ndest];
          if (s->flags & DEST_BITS32){
                       src=src & 0x1F;
                       n=((n & 0xffffffff) << src) | ((n & 0xffffffff) >> (32-src));
                       memcpy(&thread.Exx[s->ndest],&n,4);
                       result=thread.Exx[s->ndest];
                       };
          if (s->flags & DEST_BITS16){src=src & 0xF;
              n=((n & 0xffff) << src) | ((n & 0xffff)>> (16-src));
              memcpy(&thread.Exx[s->ndest],&n,2);
              result=thread.Exx[s->ndest];
          };
          if (s->flags & DEST_BITS8){      
             char* dest2=(char*)&thread.Exx[s->ndest];
             if (s->ndest >3){
                          dest2=(char*)(&thread.Exx[s->ndest-4]);
                          dest2++;
             };  
             n=*dest2;
             src=src & 7;
             *dest2=((n & 0xff)<< src) |((n & 0xff)>> (8-src));
             result=*dest2 &0xff; 
             };
          
    }else if (s->flags & DEST_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          dword n=*ptr;
          dest=n;
          if (s->flags & DEST_BITS32){
             src=src & 0x1F;
             dword n=*ptr;
             n=(n << src) | ((n & 0xffffffff)>> (32-src));
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&n);
             
          };
          if (s->flags & DEST_BITS16){
             src=src & 0xF;
             unsigned short n= (unsigned short)*ptr;
             n=(n << src) | ((n & 0xffff)>> (16-src));      
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&n);
          };
          if (s->flags & DEST_BITS8){
             src=src & 0x7;
             char n= (char)*ptr;
             n=(n << src) | ((n & 0xff)>> (8-src));
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&n);
          };
          result=*ptr;
    };    
    thread.updateflags(dest,0,result,0,s->flags);   
    thread.EFlags &= (EFLG_PF | EFLG_ZF | EFLG_SF |EFLG_SYS);
    if (s->flags & DEST_BITS16){
       if ((dest >> (16- src)) & 1)thread.EFlags |=EFLG_CF;
    }else if (s->flags & DEST_BITS8){
         if ((dest >> (8 - src)) & 1)thread.EFlags |=EFLG_CF; 
    }else{
          if ((dest >> (32- src)) & 1)thread.EFlags |=EFLG_CF;
    }
    
    //cout << "dest= "<<(int*)dest << "\nresult= " << (int*)result<<"\nflags= "<< (int*)thread.EFlags << "\n";   
    return 0;
};
//---------------------------------------------------------------------------------
//ROR
int op_ror(Thread& thread,ins_disasm* s){
    //first we will test the source and get the value that we will put in the dest in src variable
    dword dest = 0,result = 0;
    int src=0;
    if (s->flags & SRC_IMM){
             src=s->nsrc;

    }else if (s->flags & SRC_REG){
          dword src2=thread.Exx[1];
          memcpy(&src,&src2,1);
    };
    // now we have the value of the src that we will put it in the dest now we will test the dest
    if (s->flags & DEST_REG){
          dest=thread.Exx[s->ndest];
          dword n=thread.Exx[s->ndest];
          if (s->flags & DEST_BITS32){
                       src=src & 0x1F;
                       n=((n & 0xffffffff) >> src) | ((n & 0xffffffff)<<(32-src));
                       memcpy(&thread.Exx[s->ndest],&n,4);
                       result=thread.Exx[s->ndest];
          };
          if (s->flags & DEST_BITS16){
                       src=src & 0xF;
                       n=((n & 0xffff) >> src) | ((n & 0xffff)<< (16-src));
                       memcpy(&thread.Exx[s->ndest],&n,2);
                       result=thread.Exx[s->ndest];
                       };
          if (s->flags & DEST_BITS8){      
             char* dest2=(char*)&thread.Exx[s->ndest];
             if (s->ndest >3){
                          dest2=(char*)(&thread.Exx[s->ndest-4]);
                          dest2++;
             };  
             src=src & 0x7;
             *dest2=((*dest2 & 0xff)>> src) |((*dest2 & 0xff)<< (8-src));
             result=*dest2 &0xff; 
             };
    }else if (s->flags & DEST_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          dword n=*ptr;
          dest=n;
          if (s->flags & DEST_BITS32){
             src=src & 0x1F;
             dword n=*ptr;
             n=((n & 0xffffffff) >> src) | ((n & 0xffffffff)<< (32-src));
              EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&n);
             
          };
          if (s->flags & DEST_BITS16){
             src=src & 0xF;
             unsigned short n= (unsigned short)*ptr;
             n=((n & 0xffff) >> src )| ((n & 0xffff)<< (16-src));      
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&n);
          };
          if (s->flags & DEST_BITS8){
             src=src & 0x7;
             char n= (char)*ptr;
             n=((n & 0xff) >> src) | ((n & 0xff)<< (8-src));
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&n);
          };
          result=*ptr;
    };    
    thread.updateflags(dest,0,result,0,s->flags);   
    thread.EFlags &= (EFLG_PF | EFLG_ZF | EFLG_SF |EFLG_SYS);
    if ((dest >> (src -1)) & 1)thread.EFlags |=EFLG_CF;
    return 0;
};
//=====================================================================================================
//SAR
int op_sar(Thread& thread,ins_disasm* s)
{
	//first we will test the source and get the value that we will put in the dest in src variable
	dword dest = 0,result = 0;
	int src=0;
	if (s->flags & SRC_IMM)
	{
		src=s->nsrc & 0x1F;        //not bigger than 31

	}
	else if (s->flags & SRC_REG)
	{
		dword src2=thread.Exx[1];
		memcpy(&src,&src2,1);
	}

	// now we have the value of the src that we will put it in the dest now we will test the dest
	if (s->flags & DEST_REG)
	{
		dest=thread.Exx[s->ndest];
		dword n=thread.Exx[s->ndest];
		SAR_32(src, n, &n);
		/*__asm
		{		 
			mov ecx,src
			mov edx,n
			sar edx,cl
			mov n, edx
		}*/
		if (s->flags & DEST_BITS32)
		{
			memcpy(&thread.Exx[s->ndest],&n,4);
			result=thread.Exx[s->ndest];
		}
		if (s->flags & DEST_BITS16)
		{
			memcpy(&thread.Exx[s->ndest],&n,2);
			result=thread.Exx[s->ndest];
		}
		if (s->flags & DEST_BITS8)
		{
			if (s->ndest >3)
			{
				n=thread.Exx[s->ndest-4];  
				/*__asm
				{		 
					mov ecx,src
					mov edx,n
					sar dh,cl
					mov n, edx
				}*/
				SAR_HIGH_8(src, n, &n);
				memcpy(&thread.Exx[s->ndest-4],&n,2);          
			}
			else
			{           
				/*__asm
				{		 
					mov ecx,src
					mov edx,n
					sar edx,cl
					mov n, edx
				}*/
				SAR_32(src, n, &n);
				result=n &0xff;   
				memcpy(&thread.Exx[s->ndest],&n,1);
			}   

		}
	}
	else if (s->flags & DEST_RM)
	{
		dword* ptr;
		EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
		dword n=*ptr;
		dest=n;
		if (s->flags & DEST_BITS32)
		{
			dword n=*ptr;
			dword num=(n & 0xffffffff);
			/*__asm
			{		 
				mov ecx,src
				mov edx,n
				sar edx,cl
				mov num, edx
			}*/
			SAR_32(src, n, &num);
			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&num);

		}
		if (s->flags & DEST_BITS16)
		{
			unsigned short n= (unsigned short)*ptr;
			dword num=n & 0xffff;
			/*__asm
			{		 
				mov ecx,src
				mov dx,n
				sar dx,cl
				mov num,edx
			}*/
			SAR_16(src, n, &num);
			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&num);
		}
		if (s->flags & DEST_BITS8)
		{
			char n= (char)*ptr;
			dword num=n & 0xff;
			/*__asm
			{		 
				mov ecx,src
				mov dl,n
				sar dl,cl
				mov num, edx
			}*/
			SAR_LOW_8(src, n, &num);
			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&num);
		}
		result=*ptr;
	}
	thread.updateflags(dest,0,result,0,s->flags);   
	thread.EFlags &= (EFLG_PF | EFLG_ZF | EFLG_SF |EFLG_SYS);
	if ((dest >> (src -1)) & 1)
	{
		thread.EFlags |=EFLG_CF;
	}
	return 0;
}
//---------------------------------------------------------------------------------
//RCL
int op_rcl(Thread& thread,ins_disasm* s){
	//first we will test the source and get the value that we will put in the dest in src variable
	dword dest = 0,result = 0;
	int src=0;
	if (s->flags & SRC_IMM)
	{
		src=s->nsrc & 0x1F;        //not bigger than 31

	}
	else if (s->flags & SRC_REG)
	{
		dword src2=thread.Exx[1];
		memcpy(&src,&src2,1);
	}
	// now we have the value of the src that we will put it in the dest now we will test the dest
	if (s->flags & DEST_REG)
	{
		dest=thread.Exx[s->ndest];
		dword n=thread.Exx[s->ndest];
		if (s->flags & DEST_BITS32)
		{
			ReSetCarry();
			//__asm{clc}
			if (thread.EFlags & EFLG_CF)
			{
				//__asm{stc}
				SetCarry();
			}
			/*__asm
			{		 
				mov ecx,src
				mov edx,n
				rcl edx,cl
				mov n, edx
			}*/
			RCL_32(src, n, &n);
			memcpy(&thread.Exx[s->ndest],&n,4);
		}
		if (s->flags & DEST_BITS16)
		{
			//__asm{clc}
			ReSetCarry();
			if (thread.EFlags & EFLG_CF)
			{
				//__asm{stc}
				SetCarry();
			}
			/*__asm
			{		 
				mov ecx,src
				mov edx,n
				rcl dx,cl
				mov n, edx
			}*/
			RCL_16(src, (WORD)n, &n);
			memcpy(&thread.Exx[s->ndest],&n,2);
		}
		if (s->flags & DEST_BITS8)
		{
			if (s->ndest <4)
			{
				//__asm{clc}
				ReSetCarry();
				if (thread.EFlags & EFLG_CF)
				{
					//__asm{stc}             
					SetCarry();
				}
				/*__asm
				{		 
					mov ecx,src
					mov edx,n
					rcl dl,cl
					mov n, edx
				}*/
				RCL_LOW_8(src, (char)n, &n);
				memcpy(&thread.Exx[s->ndest],&n,1);
			}
			else
			{
				n=thread.Exx[s->ndest-4];
				//__asm{clc}  
				ReSetCarry();
				if (thread.EFlags & EFLG_CF)
				{
					SetCarry();
					//__asm{stc}  
				}
				/*__asm
				{		 
					mov ecx,src
					mov edx,n
					rcl dh,cl
					mov n,edx
				}*/
				RCL_HIGH_8(src, n, &n);
				memcpy(&thread.Exx[s->ndest-4],&n,4);
			}
		}
		result=thread.Exx[s->ndest];
	}
	else if (s->flags & DEST_RM)
	{
		dword* ptr;
		EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
		dword n=*ptr;
		dest=n;
		if (s->flags & DEST_BITS32)
		{
			dword n=*ptr;
			//__asm{clc}
			ReSetCarry();
			if (thread.EFlags & EFLG_CF)
			{
				//__asm{stc}
				SetCarry();
			}
			/*__asm
			{		 
				mov ecx,src
				mov edx,n
				rcl edx,cl
				mov n, edx
			}*/
			RCL_32(src, n, &n);
			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&n);

		}
		if (s->flags & DEST_BITS16)
		{
			unsigned short n= (unsigned short)*ptr;
			//__asm{clc}
			ReSetCarry();
			if (thread.EFlags & EFLG_CF)
			{
				//__asm{stc}
				SetCarry();
			}
			/*__asm
			{		 
				mov ecx,src
				mov dx,n
				rcl dx,cl
				mov n,dx
			}*/
			DWORD	num = 0;
			RCL_16(src, n, &num);
			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&num);
		}
		if (s->flags & DEST_BITS8)
		{
			char n= (char)*ptr;
			//__asm{clc}
			ReSetCarry();
			if (thread.EFlags & EFLG_CF)
			{
				//__asm{stc}
				SetCarry();
			}
			/*__asm
			{		 
				mov ecx,src
				mov dl,n
				rcl dl,cl
				mov n, dl
			}*/
			DWORD num = 0;
			RCL_LOW_8(src, n, &num);
			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&num);
		}
		result=*ptr;
	}    
	thread.updateflags(dest,0,result,0,s->flags);   
	thread.EFlags &= (EFLG_PF | EFLG_ZF | EFLG_SF |EFLG_SYS);
	if (s->flags & DEST_BITS16)
	{
		if ((dest >> (16- src)) & 1)
		{
			thread.EFlags |=EFLG_CF;
		}
	}
	else if (s->flags & DEST_BITS8)
	{
		if ((dest >> (8 - src)) & 1)
		{
			thread.EFlags |=EFLG_CF; 
		}
	}
	else
	{
		if ((dest >> (32- src)) & 1)
		{
			thread.EFlags |=EFLG_CF;
		}
	}
	return 0;
}
//---------------------------------------------------------------------------------
//RCR
int op_rcr(Thread& thread,ins_disasm* s)
{
	//first we will test the source and get the value that we will put in the dest in src variable
	dword dest = 0,result = 0;
	int src=0;
	if (s->flags & SRC_IMM)
	{
		src=s->nsrc & 0x1F;        //not bigger than 31

	}
	else if (s->flags & SRC_REG)
	{
		dword src2=thread.Exx[1];
		memcpy(&src,&src2,1);
	}
	// now we have the value of the src that we will put it in the dest now we will test the dest
	if (s->flags & DEST_REG)
	{
		dest=thread.Exx[s->ndest];
		dword n=thread.Exx[s->ndest];
		if (s->flags & DEST_BITS32)
		{
			//__asm{clc}
			ReSetCarry();
			if (thread.EFlags & EFLG_CF)
			{
				//__asm{stc}
				SetCarry();
			}
			/*__asm
			{		 
				mov ecx,src
				mov edx,n
				rcr edx,cl
				mov n, edx
			}*/
			RCR_32(src, n, &n);
			memcpy(&thread.Exx[s->ndest],&n,4);
		}
		if (s->flags & DEST_BITS16)
		{
			//__asm{clc}
			ReSetCarry();
			if (thread.EFlags & EFLG_CF)
			{
				//__asm{stc}
				SetCarry();
			}
		/*	__asm
			{		 
				mov ecx,src
					mov edx,n
					rcr dx,cl
					mov n, edx
			}*/
			RCR_16(src, (WORD)n, &n);
			memcpy(&thread.Exx[s->ndest],&n,2);
		}
		if (s->flags & DEST_BITS8)
		{
			if (s->ndest <4)
			{
				//__asm{clc}
				ReSetCarry();
				if (thread.EFlags & EFLG_CF)
				{
					//__asm{stc}
					SetCarry();
				}             
				/*__asm
				{		 
					mov ecx,src
						mov edx,n
						rcr dl,cl
						mov n, edx
				}*/
				RCR_LOW_8(src, (char)n, &n);
				memcpy(&thread.Exx[s->ndest],&n,1);
			}
			else
			{
				//__asm{clc}
				ReSetCarry();
				if (thread.EFlags & EFLG_CF)
				{
					//__asm{stc}
					SetCarry();
				}
				n=thread.Exx[s->ndest-4];
				/*__asm
				{		 
					mov ecx,src
						mov edx,n
						rcr dh,cl
						mov n, edx
				}*/
				RCR_HIGH_8(src, n, &n);
				memcpy(&thread.Exx[s->ndest-4],&n,4);
			}
		}
		result=thread.Exx[s->ndest];
	}
	else if (s->flags & DEST_RM)
	{
		dword* ptr;
		EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
		dword n=*ptr;
		dest=n;
		if (s->flags & DEST_BITS32)
		{
			dword n=*ptr;
			//__asm{clc}
			ReSetCarry();
			if (thread.EFlags & EFLG_CF)
			{
				//__asm{stc}
				SetCarry();
			}
			/*__asm
			{		 
				mov ecx,src
					mov edx,n
					rcr edx,cl
					mov n, edx
			}*/
			RCR_32(src, n, &n);

			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&n);

		}
		if (s->flags & DEST_BITS16)
		{
			short n= (short)*ptr;
			//__asm{clc}
			ReSetCarry();
			if (thread.EFlags & EFLG_CF)
			{
				//__asm{stc}
				SetCarry();
			}
			/*__asm
			{		 
				mov ecx,src
					mov dx,n
					rcr dx,cl
					mov n, dx
			}*/
			DWORD num = 0;
			RCR_16(src, n, &num);
			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&num);
		}
		if (s->flags & DEST_BITS8)
		{
			char n= (char)*ptr;
			//__asm{clc}
			ReSetCarry();
			if (thread.EFlags & EFLG_CF)
			{
				//__asm{stc}
				SetCarry();
			}
			/*__asm
			{		 
				mov ecx,src
					mov dl,n
					rcr dl,cl
					mov n,dl
			}*/
			DWORD num = 0;
			RCR_LOW_8(src, n, &num);
			EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&num);
		}
		result=*ptr;
	};    
	thread.updateflags(dest,0,result,0,s->flags);   
	thread.EFlags &= (EFLG_PF | EFLG_ZF | EFLG_SF |EFLG_SYS);
	if ((dest >> (src-1)) & 1)
	{
		thread.EFlags |=EFLG_CF;
	}
	return 0;
}
//----------------------------------------------------------------------
//STC
int op_stc(Thread& thread,ins_disasm* s){
    thread.EFlags |=EFLG_CF;
	s->hde.len = s->hde.len;
    return 0;
};
//CLC
int op_clc(Thread& thread,ins_disasm* s){
    thread.EFlags &= ~EFLG_CF;
	s->hde.len = s->hde.len;
    return 0;
};
