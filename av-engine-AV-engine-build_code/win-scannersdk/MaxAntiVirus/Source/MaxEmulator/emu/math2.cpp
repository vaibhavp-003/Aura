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

extern "C" int __stdcall MUL_32(DWORD ip1, DWORD ip2, DWORD *op1, DWORD *op2);
extern "C" int __stdcall MUL_16(DWORD ip1, DWORD ip2, DWORD ip3, DWORD *op1, DWORD *op2);
extern "C" int __stdcall MUL_8(DWORD ip1, DWORD ip2, DWORD ip3, DWORD *op1, DWORD *op2);

extern "C" int __stdcall IMUL_32(DWORD ip1, DWORD ip2, DWORD *op1, DWORD *op2);
extern "C" int __stdcall IMUL_16(DWORD ip1, DWORD ip2, DWORD ip3, DWORD *op1, DWORD *op2);
extern "C" int __stdcall IMUL_8(DWORD ip1, DWORD ip2, DWORD ip3, DWORD *op1, DWORD *op2);

extern "C" int __stdcall DIV_32(DWORD ip1, DWORD ip2, DWORD ip3, DWORD *op1, DWORD *op2);
extern "C" int __stdcall DIV_16(DWORD ip1, DWORD ip2, DWORD ip3, DWORD *op1, DWORD *op2);
extern "C" int __stdcall DIV_8(DWORD ip1, DWORD ip2, DWORD ip3, DWORD *op1, DWORD *op2);

extern "C" int __stdcall IDIV_32(DWORD ip1, DWORD ip2, DWORD *op1, DWORD *op2);
extern "C" int __stdcall IDIV_16(DWORD ip1, DWORD ip2, DWORD *op1, DWORD *op2);
extern "C" int __stdcall IDIV_8(DWORD ip1, DWORD ip2, DWORD *op1);

extern "C" int __stdcall BSWAP_EMUL(int ip1, int *op1);
// XCHG
int op_xchg(Thread& thread,ins_disasm* s){
    //first we will test the source and get the value that we will put in the dest in src variable
    dword dest,result;
    dword* src=0;
    if (s->flags & SRC_REG){
          src=&thread.Exx[s->nsrc];
          if (s->flags & SRC_BITS8 && s->nsrc>3){
              char* src2=(char*)&thread.Exx[s->nsrc-4]; 
              src2++;
              src=(dword*)src2;        
          };
    }else if (s->flags & SRC_RM){
          EMU_READ_MEM(src,modrm_calc(thread,s));
          //this place for checking for write access
          EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)src);
    };
    // now we have the value of the src that we will put it in the dest now we will test the dest
    if (s->flags & DEST_REG){
          dest=thread.Exx[s->ndest];
          if (s->flags & DEST_BITS32){ 
                       memcpy(&thread.Exx[s->ndest],src,4);
                       memcpy(src,&dest,4);
                       }
          if (s->flags & DEST_BITS16){ 
                       memcpy(&thread.Exx[s->ndest],src,2);
                       memcpy(src,&dest,2);
                       }
          if (s->flags & DEST_BITS8) { 
                          if (s->ndest>3){
                              char* dest2=(char*)&thread.Exx[s->ndest-4]; 
                              dest2++;
                              char dest3=*dest2;
                              memcpy(dest2,src,1);
                              memcpy(src,&dest3,1);
                           }else{
                               memcpy(&thread.Exx[s->ndest],src,1);
                               memcpy(src,&dest,1);
                           };
          };
          result=thread.Exx[s->ndest];
    }else if (s->flags & DEST_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          dest=*ptr;
          if (s->flags & DEST_BITS32){
             dword n=*src;
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&n);
             memcpy(src,&dest,4);
          };
          if (s->flags & DEST_BITS16){
             short n = (short)*src;          
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&n);
             memcpy(src,&dest,2);
          };
          if (s->flags & DEST_BITS8){
             char n = (char)*src;   
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&n);
             memcpy(src,&dest,1);
          };
          result=*ptr;
    };  
    //cout << "dest= "<<(int*)dest << "\nresult= " << (int*)result<<"\nflags= "<< (int*)thread.EFlags << "\n";     
    return 0;
};
//==============================================================================================================================
// BSWAP
int op_bswap(Thread& thread,ins_disasm* s){
        //dword dest = 0,result = 0;
          
          if (s->flags & DEST_BITS32){
                       int src=thread.Exx[s->ndest];
                      /*__asm
					   {
						   mov eax,src
						   bswap eax
						   mov src,eax
					   }*/
					   BSWAP_EMUL(src, &src);
                       memcpy(&thread.Exx[s->ndest],&src,4);
          };
          if (s->flags & DEST_BITS16){
                       short src= (short)thread.Exx[s->ndest];
                       short s2= (src &0xff)<<16;
                       //short s3=(src &0xff00)>>16;
                       src=s2+s2;
                       memcpy(&thread.Exx[s->ndest],&src,2);
          };
    return 0;
};
//==============================================================================================================================
// XADD
int op_xadd(Thread& thread,ins_disasm* s){
    //first we will test the source and get the value that we will put in the dest in src variable
    dword dest = 0,result = 0;
    dword* src=0;
    if (s->flags & SRC_REG){
          src=&thread.Exx[s->nsrc];
          if (s->flags & SRC_BITS8 && s->nsrc > 3){
             char* src2= (char*)&thread.Exx[s->nsrc-4];
             src2++;                               //this instruction for dword* will add 4 to the pointer rather than 1
             src=(dword*)src2;
          };
    }else if (s->flags & SRC_RM){
          EMU_READ_MEM(src,(dword)modrm_calc(thread,s));
          //this place for checking for write access
          EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)src);
    };
    // now we have the value of the src that we will put it in the dest now we will test the dest
    if (s->flags & DEST_REG){
          dest=thread.Exx[s->ndest];
          if (s->flags & DEST_BITS32){ 
                       thread.Exx[s->ndest]+=*src;
                       memcpy(src,&dest,4);
                       }
          if (s->flags & DEST_BITS16){ 
                       short addition = *src & 0xffff + thread.Exx[s->ndest] & 0xffff;
                       memcpy(&thread.Exx[s->ndest],&addition,2);
                       memcpy(src,&dest,2);
                       }
          if (s->flags & DEST_BITS8){
                       char* dest2=(char*)&thread.Exx[s->ndest];
                       if (s->ndest >3){
                          dest2=(char*)(&thread.Exx[s->ndest-4]);
                          dest2++;
                          dest = *dest2;
                       };
                       char addition = (*src & 0xff) + (dest & 0xff);
                       memcpy(dest2,&addition,1);
                       memcpy(src,&dest,1);
                       }
          result=thread.Exx[s->ndest];
    }else if (s->flags & DEST_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          dest=*ptr+*src;
          if (s->flags & DEST_BITS32){
             dword* readmem;
             EMU_READ_MEM(readmem,(dword)modrm_calc(thread,s));
             dword n=*src + *readmem;
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&n);
             memcpy(src,&dest,4);
          };
          if (s->flags & DEST_BITS16){
             dword* readmem;
             EMU_READ_MEM(readmem,(dword)modrm_calc(thread,s));
             short n=(*src & 0xffff) + (*readmem & 0xffff);          
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&n);
             memcpy(src,&dest,2);
          };
          if (s->flags & DEST_BITS8){
             dword* readmem;
             EMU_READ_MEM(readmem,(dword)modrm_calc(thread,s));          
             char n=(*src & 0xff) + (*readmem & 0xff);   
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&n);
             memcpy(src,&dest,1);
          };
          result=*ptr;
    };
    thread.updateflags(dest,0,result,UPDATEFLAGS_ADD,s->flags);
    return 0;
};
//==============================================================================================================================
//MUL

int op_mul(Thread& thread,ins_disasm* s){
	//first we will test the source and get the value that we will put in the dest in src variable
	int src=0;
	if (s->flags & DEST_REG)
	{
		int src2=thread.Exx[s->ndest];
		if (s->flags & DEST_BITS32)
		{
			memcpy(&src,&src2,4);
		}
		if (s->flags & DEST_BITS16)
		{
			memcpy(&src,&src2,2);
		}
		if (s->flags & DEST_BITS8)
		{
			if (s->ndest >3)
			{
				src2=thread.Exx[s->ndest-4] >> 8;          
			}
			memcpy(&src,&src2,1);  
		}
	}
	else if (s->flags & DEST_RM)
	{
		dword* ptr;
		EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
		if (s->flags & DEST_BITS32)
		{
			memcpy(&src,ptr,4);
		}
		if (s->flags & DEST_BITS16)
		{
			memcpy(&src,ptr,2);
		}
		if (s->flags & DEST_BITS8)
		{
			memcpy(&src,ptr,1); 
		}
	}
	DWORD dwValue1 = thread.Exx[0];
	DWORD dwValue2 = thread.Exx[2];
	if (s->flags & DEST_BITS32)
	{
		/*__asm
		{
			mov eax,dwValue1
			mov edx,src
			mul edx
			mov dwValue1,eax
			mov dwValue2,edx
		}*/
		MUL_32(dwValue1, src, &dwValue1, &dwValue2);
	}
	else if (s->flags & DEST_BITS16)
	{
		/*__asm
		{
			mov eax,dwValue1
				mov ecx,src
				mov edx,dwValue2
				mul cx
				mov dwValue1,eax
				mov dwValue2,edx
		}*/
		MUL_16(dwValue1, src, dwValue2, &dwValue1, &dwValue2);
	}
	else if (s->flags & DEST_BITS8)
	{
		/*__asm
		{
			mov eax,dwValue1
				mov ecx,src
				mov edx,dwValue2
				mul cl
				mov dwValue1,eax
				mov dwValue2,edx
		}  */
		MUL_8(dwValue1, src, dwValue2, &dwValue1, &dwValue2);
	}
	thread.Exx[0] = dwValue1;
	thread.Exx[2] = dwValue2;
	return 0;
}
//==============================================================================================================================
//IMUL
int op_imul1(Thread& thread,ins_disasm* s){
	//first we will test the source and get the value that we will put in the dest in src variable
	int src=0;
	if (s->flags & DEST_REG)
	{
		int src2=thread.Exx[s->ndest];
		if (s->flags & DEST_BITS32)
		{
			memcpy(&src,&src2,4);
		}
		if (s->flags & DEST_BITS16)
		{
			memcpy(&src,&src2,2);
		}
		if (s->flags & DEST_BITS8)
		{
			if (s->ndest >3)
			{
				src2=thread.Exx[s->ndest-4] >> 8;          
			}
			memcpy(&src,&src2,1);
		}
	}
	else if (s->flags & DEST_RM)
	{
		dword* ptr;
		EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
		if (s->flags & DEST_BITS32)
		{
			memcpy(&src,ptr,4);
		}
		if (s->flags & DEST_BITS16)
		{
			memcpy(&src,ptr,2);
		}
		if (s->flags & DEST_BITS8)
		{
			memcpy(&src,ptr,1); 
		}
	}
	dword dwValue1 = thread.Exx[0], dwValue2 = thread.Exx[2];

	if (s->flags & DEST_BITS32)
	{
		/*__asm
		{
			mov eax,dwValue1
				mov edx,src
				imul edx
				mov dwValue1,eax
				mov dwValue2,edx
		}*/
		IMUL_32(dwValue1, src, &dwValue1, &dwValue2);
	}
	else if (s->flags & DEST_BITS16)
	{
		/*__asm
		{
			mov eax,dwValue1
				mov ecx,src
				mov edx,dwValue2
				imul cx
				mov dwValue1,eax
				mov dwValue2,edx
		}     */
		IMUL_16(dwValue1, src, dwValue2, &dwValue1, &dwValue2);
	}
	else if (s->flags & DEST_BITS8)
	{
		/*__asm
		{
			mov eax,dwValue1
				mov ecx,src
				mov edx,dwValue2
				imul cl
				mov dwValue1,eax
				mov dwValue2,edx
		}*/		
		IMUL_8(dwValue1, src, dwValue2, &dwValue1, &dwValue2);
	}
	thread.Exx[0] = dwValue1;
	thread.Exx[2] = dwValue2;
	return 0;
}

//-------------------------------------------------------------------------------------------------------------------------
//IMUL 2
int op_imul2(Thread& thread,ins_disasm* s){
    dword dest,result;
    int src=0;
    if (s->flags & SRC_IMM){
             src=s->nsrc;
    }else if (s->flags & SRC_REG){
          int src2=thread.Exx[s->nsrc];
          if (s->flags & SRC_BITS32)memcpy(&src,&src2,4);
          if (s->flags & SRC_BITS16)memcpy(&src,&src2,2);
          if (s->flags & SRC_BITS8)memcpy(&src,&src2,1); 
    }else if (s->flags & SRC_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          if (s->flags & SRC_BITS32)memcpy(&src,ptr,4);
          if (s->flags & SRC_BITS16)memcpy(&src,ptr,2);
          if (s->flags & SRC_BITS8)memcpy(&src,ptr,1); 
    };
    // now we have the value of the src that we will put it in the dest now we will test the dest
    if (s->flags & DEST_REG){
          dest=thread.Exx[s->ndest];
          src*=thread.Exx[s->ndest];
          if (s->flags & DEST_BITS32) memcpy(&thread.Exx[s->ndest],&src,4);
          if (s->flags & DEST_BITS16) memcpy(&thread.Exx[s->ndest],&src,2);
          if (s->flags & DEST_BITS8) memcpy(&thread.Exx[s->ndest],&src,1);
          result=thread.Exx[s->ndest];
    }else if (s->flags & DEST_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          dword n=*ptr;
          dest=n;
          if (s->flags & DEST_BITS32){
             dword n=*ptr;
             n*=src;
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&n);
          };
          if (s->flags & DEST_BITS16){
             short n= (short)*ptr;
             n = (short)(n * src);          
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&n);
          };
          if (s->flags & DEST_BITS8){
             char n= (char)*ptr;
             n = (char)(n * src);   
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&n);
          };
          result=*ptr;
    };  
    //thread.updateflags(dest,0,result,UPDATEFLAGS_ADD);
    return 0;
};
//-------------------------------------------------------------------------------------------------------------------------
//IMUL 3
int op_imul3(Thread& thread,ins_disasm* s){
    dword dest,result;
    int src=0,imm=s->other;
    if (s->flags & SRC_IMM){
             src=s->nsrc;
    }else if (s->flags & SRC_REG){
          int src2=thread.Exx[s->nsrc];
          if (s->flags & SRC_BITS32)memcpy(&src,&src2,4);
          if (s->flags & SRC_BITS16)memcpy(&src,&src2,2);
          if (s->flags & SRC_BITS8)memcpy(&src,&src2,1); 
    }else if (s->flags & SRC_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          if (s->flags & SRC_BITS32)memcpy(&src,ptr,4);
          if (s->flags & SRC_BITS16)memcpy(&src,ptr,2);
          if (s->flags & SRC_BITS8)memcpy(&src,ptr,1); 
    };
    // now we have the value of the src that we will put it in the dest now we will test the dest
    if (s->flags & DEST_REG){
          dest=thread.Exx[s->ndest];
          src*=imm;
          if (s->flags & DEST_BITS32) memcpy(&thread.Exx[s->ndest],&src,4);
          if (s->flags & DEST_BITS16) memcpy(&thread.Exx[s->ndest],&src,2);
          if (s->flags & DEST_BITS8) memcpy(&thread.Exx[s->ndest],&src,1);
          result=thread.Exx[s->ndest];
    }else if (s->flags & DEST_RM){
          dword* ptr;
          EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
          dword n=*ptr;
          dest=n;
          if (s->flags & DEST_BITS32){
             dword n=*ptr;
             n=imm*src;
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)4,(char*)&n);
          };
          if (s->flags & DEST_BITS16){
             short n=(short)*ptr;
             n = (short)(imm*src);          
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)2,(char*)&n);
          };
          if (s->flags & DEST_BITS8){
             char n= (char)*ptr;
             n = (char)(imm*src);   
             EMU_WRITE_MEM((dword)modrm_calc(thread,s),(dword)1,(char*)&n);
          };
          result=*ptr;
    };  
    //thread.updateflags(dest,0,result,UPDATEFLAGS_ADD);
    return 0;
};
//==============================================================================================================================
//DIV

int op_div(Thread& thread,ins_disasm* s)
{
	//first we will test the source and get the value that we will put in the dest in src variable
	int src = 0;
	if (s->flags & DEST_REG)
	{
		int src2=thread.Exx[s->ndest];
		if (s->flags & DEST_BITS32)
		{
			memcpy(&src,&src2,4);
		}
		if (s->flags & DEST_BITS16)
		{
			memcpy(&src,&src2,2);
		}
		if (s->flags & DEST_BITS8)
		{
			if (s->ndest >3)
			{
				src2=thread.Exx[s->ndest-4] >> 8;        
			}
			memcpy(&src,&src2,1);
		}
	}
	else if (s->flags & DEST_RM)
	{
		dword* ptr;
		EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
		if (s->flags & DEST_BITS32)
		{
			memcpy(&src,ptr,4);
		}
		if (s->flags & DEST_BITS16)
		{
			memcpy(&src,ptr,2);
		}
		if (s->flags & DEST_BITS8)
		{
			memcpy(&src,ptr,1); 
		}
	}
	if (src==0)
	{
		return EXP_DIVID_BY_ZERO;
	}
	dword dwValue1 = thread.Exx[0], dwValue2 = thread.Exx[2];

	if (s->flags & DEST_BITS32)
	{
		if (thread.Exx[2] >= (DWORD)src)
		{
			return EXP_DIV_OVERFLOW;
		}		
		/*__asm
		{
		mov eax,dwValue1
		mov ecx,src
		mov edx,dwValue2
		div ecx
		mov dwValue1,eax
		mov dwValue2,edx
		}	*/
		//IMUL_16(dwValue1, src, dwValue2, &dwValue1, &dwValue2);
		DIV_32(dwValue1, src, dwValue2, &dwValue1, &dwValue2);
	}
	else if (s->flags & DEST_BITS16)
	{
		if ((thread.Exx[2] & 0xFFFF) >= (DWORD)(src & 0xFFFF))
		{
			return EXP_DIV_OVERFLOW;
		}
		/*__asm
		{
		mov eax,dwValue1
		mov ecx,src
		mov edx,dwValue2
		div cx
		mov dwValue1,eax
		mov dwValue2,edx
		}    */
		DIV_16(dwValue1, src, dwValue2, &dwValue1, &dwValue2);
	}
	else if (s->flags & DEST_BITS8)
	{
		if ((thread.Exx[2] & 0xFF) >= (DWORD)(src & 0xFF))
		{
			return EXP_DIV_OVERFLOW;
		}
		/*__asm
		{
		mov eax,dwValue1
		mov ecx,src
		mov edx,dwValue2
		div cl
		mov dwValue1,eax
		mov dwValue2,edx
		}       */ 
		DIV_8(dwValue1, src, dwValue2, &dwValue1, &dwValue2);
	}
	thread.Exx[0] = dwValue1;
	thread.Exx[2] = dwValue2;
	return 0;
}

void WriteLog1(LPCTSTR szString)
{
	FILE * fp = 0;
	_tfopen_s(&fp, L"C:\\VirusLog1.txt", L"a");
	if(fp)
	{
		_fputts(szString, fp);
		_fputts(L"\r\n", fp);
		fclose(fp);
	}
}
//==============================================================================================================================
//IDIV

int op_idiv(Thread& thread,ins_disasm* s)
{
/*	TCHAR szMsg[1024]={0};
	_stprintf_s(szMsg, 1024, L" thread.Exx[0]= %d thread.Exx[2] = %d", thread.Exx[0], thread.Exx[2]);
	WriteLog1(szMsg);*/
	//first we will test the source and get the value that we will put in the dest in src variable
	//dword dest,result;
	int src=0;
//	int a,b;
	if (s->flags & DEST_REG)
	{
		int src2=thread.Exx[s->ndest];
		if (s->flags & DEST_BITS32)memcpy(&src,&src2,4);
		if (s->flags & DEST_BITS16)memcpy(&src,&src2,2);
		if (s->flags & DEST_BITS8)
		{
			if (s->ndest >3)
			{
				src2=thread.Exx[s->ndest-4] >> 8;          
			}
			memcpy(&src,&src2,1);
		};
	}
	else if (s->flags & DEST_RM)
	{
		dword* ptr;
		EMU_READ_MEM(ptr,(dword)modrm_calc(thread,s));
		if (s->flags & DEST_BITS32)memcpy(&src,ptr,4);
		if (s->flags & DEST_BITS16)memcpy(&src,ptr,2);
		if (s->flags & DEST_BITS8)memcpy(&src,ptr,1); 
	}; 
	if (src==0)
	{
		return EXP_DIVID_BY_ZERO;
	}

	dword dwValue1 = thread.Exx[0], dwValue2 = thread.Exx[2];

	if (s->flags & DEST_BITS32)
	{
		if ((thread.Exx[2]<< 1) >= (DWORD)src)
		{
			return EXP_DIV_OVERFLOW;
		}       
		/*__asm
		{
			mov eax,dwValue1
			cdq
			mov ecx,src
			idiv ecx
			mov dwValue1,eax
			mov dwValue2,edx
		}*/
		IDIV_32(dwValue1, src, &dwValue1, &dwValue2);
	}
	else if (s->flags & DEST_BITS16)
	{
		if (((thread.Exx[2] & 0xFFFF)<< 1) >= (DWORD)(src & 0xFFFF))
		{
			return EXP_DIV_OVERFLOW;
		}
		/*__asm
		{
			mov eax,dwValue1
			cwd
			mov ecx,src
			idiv cx
			mov dwValue1,eax
			mov dwValue2,edx
		}  */
		IDIV_16(dwValue1, src, &dwValue1, &dwValue2);
	}else if (s->flags & DEST_BITS8)
	{
		//_stprintf_s(szMsg, 1024, L" thread.Exx[0]= %d thread.Exx[2] = %d src = %d", thread.Exx[0], thread.Exx[2], src);
		//WriteLog1(szMsg);
		
		if (((thread.Exx[2] & 0xFF)<< 1) >= (DWORD)(src & 0xFF))
		{
			return EXP_DIV_OVERFLOW;
		}
		/*__asm
		{
			mov eax,dwValue1
			cbw
			mov ecx,src
			idiv cl
			mov dwValue1,eax
		}  */    
		IDIV_8(dwValue1, src, &dwValue1);
	}
	thread.Exx[0] = dwValue1;
	thread.Exx[2] = dwValue2;
	return 0;
};
//==============================================================================================================================
//CDQ

int op_cdq(Thread& thread,ins_disasm* s){
	s = s;
    thread.Exx[2]=0; 
    return 0;
};
