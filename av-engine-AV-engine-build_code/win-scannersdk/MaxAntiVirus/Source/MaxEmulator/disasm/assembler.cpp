#define __DISASM__ 1
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
#include "disassembler.h"
#define REGISTERS_LENGTH 8
#define RM_SIZES_LENGTH  3
#define SEGEMENTS_LENGTH 6
#define PREFIXES_LENGTH  3

string reg32[8]={"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
string reg16[8]={"ax","cx","dx","bx","sp","bp","si","di"};
string  reg8[8]={"al","cl","dl","bl","ah","ch","dh","bh"};
string   seg[6]={"cs","ds","ss","es","fs","gs"}; 
string rm_sizes[3]={"byte","word","dword"};
string numbers[10]={"0","1","2","3","4","5","6","7","8","9"};
string prefixes[3]={"rep","repe","repne"};

bytes get_modrm(string,int&);
int bintodec(int);
//------------------------------------------------------------------------------------------------------------//
//-----                                                                                                  -----//
//-----                                                                                                  -----//
//-----                                     The Assembler                                                -----//
//-----                                                                                                  -----//
//-----                                                                                                  -----//
//------------------------------------------------------------------------------------------------------------//


// The Assembler
bytes* System::assembl(string instruction)
{
	int pos = 0;
	int flags = 0, ndest = 0, nsrc = 0;
	int ins_pos=0;               //the position in the ins bytes
	int op_flags=0;             //the flags that will be used in the search for the opcode
	int imul_imm=0;             //special case

	string opcode, dest, src;
	string src_test, dest_test;
	string ins;

	bytes modrm = {0};
	modrm.length=0;

	bytes *bIns = NULL;
	bIns=(bytes*)malloc_emu(sizeof(bytes));                   //the output of the assembler
	memset( bIns,0,sizeof(bytes));

	bool bits16 = false;
	bool no_imul_imm = true;      //special case

	if (instruction=="")
	{
		goto assemble_error;
	}

	// we will now cut the instruction to separate the opcode & rm & reg or imm or asnything in src & dest
	ins = trim(to_lower_case(instruction));                              // deleting the spaces and convert it into lower case (avoid any problems in comparing strings)
	if(strstr(ins.c_str(), "mov rax,"))
	{
		__int64 n = 0;
		ins = trim(ins.substr(ins.find_first_of(",")+1,ins.size()));
		sscanf_s(ins.c_str(), "%016p", &n);
		bIns->s[0] = (char)0x48;
		bIns->s[1] = (char)0xB8;
		*((unsigned __int64*)&bIns->s[2]) = n;
		bIns->length = 10;
		return bIns;
	}
	if(strstr(ins.c_str(), "mov r8,"))
	{
		__int64 n = 0;
		ins = trim(ins.substr(ins.find_first_of(",")+1,ins.size()));
		sscanf_s(ins.c_str(), "%016p", &n);
		bIns->s[0] = (char)0x49;
		bIns->s[1] = (char)0xB8;
		*((unsigned __int64*)&bIns->s[2]) = n;
		bIns->length = 10;
		return bIns;
	}
	if(strstr(ins.c_str(), "mov rcx,rsi"))
	{
		bIns->s[0] = (char)0x48;
		bIns->s[1] = (char)0x8B;
		bIns->s[2] = (char)0xCE;

		bIns->length = 3;
		return bIns;
	}
	if(strstr(ins.c_str(), "mov rdx,rdi"))
	{
		bIns->s[0] = (char)0x48;
		bIns->s[1] = (char)0x8B;
		bIns->s[2] = (char)0xD7;

		bIns->length = 3;
		return bIns;
	}

	if(strstr(ins.c_str(), "mov rsi,rcx"))
	{
		bIns->s[0] = (char)0x48;
		bIns->s[1] = (char)0x8B;
		bIns->s[2] = (char)0xF1;

		bIns->length = 3;
		return bIns;
	}

	if(strstr(ins.c_str(), "mov rdi,rdx"))
	{
		bIns->s[0] = (char)0x48;
		bIns->s[1] = (char)0x8B;
		bIns->s[2] = (char)0xFA;

		bIns->length = 3;
		return bIns;
	}
	//should the instruction look like opcode dest,src (with deleting the spaces) like mov eax,edx (eax-->dest ,edx-->src
Getting_Opcode:

	opcode = ins.substr(pos,ins.find_first_of(" "));                    //getting the opcode
	//testing the prefixes
	if (compare_array(opcode,prefixes,PREFIXES_LENGTH))
	{
		int i = compare_array(opcode,prefixes,PREFIXES_LENGTH);
		ins=trim(ins.substr(ins.find_first_of(" ")+1,ins.size()));
		if (i==1 || i==2)
		{
			bIns->s[ins_pos]=(BYTE)0xF3;
			ins_pos++;
		}
		else if (i==3)
		{
			bIns->s[ins_pos]=(BYTE)0xF2;
			ins_pos++;
		}
		goto Getting_Opcode;                                                         
	}                                                   
	if(ins.find_first_of(" ")!=0 && ins.find_first_of(" ")<=ins.size())
	{
		pos = ins.find_first_of(" ")+1;
		dest = trim(ins.substr(pos,ins.find_first_of(",")-pos));            //getting the dest (rm,reg or imm)
	}
	else
	{
		dest="";
	}
	if(ins.find_first_of(",")!=0 && ins.find_first_of(",")<=ins.size())
	{   // if there's "," so there's a src
		pos=ins.find_first_of(",")+1;
		src=trim(ins.substr(pos,ins.size()-pos));
	}
	else
	{
		src = "";
	}                                                  // else src will be null 
	//-------------------------------------------------------------------------------------------
	// Destination :
	if (dest=="")
	{
		flags=NO_SRCDEST;
	}
	else
	{
		dest_test=trim(dest.substr(0,dest.find_first_of(" ")));           // first string to be compared
		if (compare_array(dest_test,reg32,REGISTERS_LENGTH))
		{                    //is it a reg 32 buts
			flags |=DEST_REG | DEST_BITS32;
			ndest=compare_array(dest_test,reg32,REGISTERS_LENGTH)-1;             //the register                        
		}
		else if (compare_array(dest_test,reg16,REGISTERS_LENGTH))
		{              // 16 bits   
			flags |=DEST_REG | DEST_BITS16;
			ndest=compare_array(dest_test,reg16,REGISTERS_LENGTH)-1;             //the register                                
		}
		else if (compare_array(dest_test,reg8,REGISTERS_LENGTH))
		{               // 8 bits
			flags |=DEST_REG | DEST_BITS8;
			ndest=compare_array(dest_test,reg8,REGISTERS_LENGTH)-1;             //the register
		}
		else if(compare_array(dest_test,rm_sizes,RM_SIZES_LENGTH))
		{
			flags |=0x00000200;
			int n= compare_array(dest_test,rm_sizes,RM_SIZES_LENGTH);
			if (n==3)
			{
				flags |=DEST_BITS32;                                    // setting the size of rm depend on byte word or dword 
			}
			else if (n==2)
			{
				flags |=DEST_BITS16;
			}
			else if (n==1)
			{
				flags |=DEST_BITS8;
			}
			dest_test= trim(dest.substr(rm_sizes[n-1].size(),dest.size()-1));
			string s[]={"ptr"};                                              // check on ptr
			if (compare_array(dest_test,s,1,3) ==0)
			{                         
				goto assemble_error;
			}
			dest_test = trim(dest_test.substr(3,dest_test.size()-1));
			if(compare_array(dest_test,seg,SEGEMENTS_LENGTH,2) !=0)
			{                       // if there's a specific segement
				// writing the segement prefixes
				int n = compare_array(dest_test,seg,SEGEMENTS_LENGTH,2);
				if(n==1)
				{
					bIns->s[ins_pos]=0x2E;ins_pos++;
				}
				else if(n==2)
				{
					bIns->s[ins_pos]=0x3E;ins_pos++;
				}
				else if(n==3)
				{
					bIns->s[ins_pos]=0x36;ins_pos++;
				}
				else if(n==4)
				{
					bIns->s[ins_pos]=0x26;ins_pos++;
				}
				else if(n==5)
				{
					bIns->s[ins_pos]=0x64;ins_pos++;
				}
				else if(n==6)
				{
					bIns->s[ins_pos]=0x65;ins_pos++;
				}
				if(dest_test.find_first_of(":") !=2)
				{                         //it should be fs:[xxx]
					goto assemble_error;
				}
				dest_test = trim(dest_test.substr(3,dest_test.size()-1));
			}                                                     // check on the []
			if (dest_test.substr(0,1) !="[" || 
				dest_test.substr(dest_test.size()-1,dest_test.size()-1) !="]")
			{ 
				goto assemble_error;
			} 
			dest_test = trim(dest_test.substr(1,dest_test.size()-2));
			// now get the modrm  
			modrm = get_modrm(dest_test,flags);
			if(modrm.length==0)
			{
				goto assemble_error;
			}
		}
		else if(compare_array(dest_test,numbers,10,1))
		{                         // is it imm
			flags |=DEST_IMM;
			ndest = imm_to_dec(dest_test);
		}
	}
	if (src=="")
	{
		flags |=SRC_NOSRC;                                                               
	}
	else
	{
		if (src.find_first_of(",")!=0 && src.find_first_of(",")<=src.size())
		{
			imul_imm = imm_to_dec(src.substr(src.find_first_of(",")+1,src.size()));
			src = src.substr(0,src.find_first_of(","));
			no_imul_imm = false;

		}
		src_test = trim(src.substr(0,src.find_first_of(" ")));           // first string to be compared     
		if(compare_array(src_test,reg32,REGISTERS_LENGTH))
		{
			flags |=SRC_REG | SRC_BITS32;
			nsrc=compare_array(src_test,reg32,REGISTERS_LENGTH)-1;             //the register                        
		}
		else if (compare_array(src_test,reg16,REGISTERS_LENGTH))
		{              // 16 bits   
			flags |=SRC_REG;
			if (opcode=="movzx" || opcode=="movsx")
			{
				flags |=MOVXZ_SRC16;
			}
			else
			{
				flags |=SRC_BITS16;
			}
			nsrc=compare_array(src_test,reg16,REGISTERS_LENGTH)-1;             //the register                                
		}
		else if (compare_array(src_test,reg8,REGISTERS_LENGTH))
		{               // 8 bits
			flags |=SRC_REG;
			if (opcode=="movzx" || opcode=="movsx")
			{
				flags |=MOVXZ_SRC8;
			}
			else
			{
				flags |=SRC_BITS8;
			}
			nsrc=compare_array(src_test,reg8,REGISTERS_LENGTH)-1;             //the register
		}
		else if(compare_array(src_test,rm_sizes,RM_SIZES_LENGTH))
		{
			flags |=SRC_RM;
			int n = compare_array(src_test,rm_sizes,RM_SIZES_LENGTH);
			if (n==3)
			{
				flags |=SRC_BITS32;                                    // setting the size of rm depend on byte word or dword 
			}
			else if (n==2)
			{
				if (opcode=="movzx" || opcode=="movsz")
				{
					flags |=MOVXZ_SRC16;
				}
				else
				{
					flags |=SRC_BITS16;
				}
			}
			else if (n==1)
			{
				if (opcode=="movzx" || opcode=="movsz")
				{
					flags |=MOVXZ_SRC8;
				}
				else
				{
					flags |=SRC_BITS8;
				}
			}

			src_test = trim(src.substr(rm_sizes[n-1].size(),src.size()-1));
			string s[]={"ptr"};                                              // check on ptr
			if (compare_array(src_test,s,1,3) ==0)
			{                         
				goto assemble_error;
			}
			src_test= trim(src_test.substr(3,src_test.size()-1));
			if (compare_array(src_test,seg,SEGEMENTS_LENGTH,2) !=0)
			{                       // if there's a specific segement
				// writing the segement flags
				int n=compare_array(src_test,seg,SEGEMENTS_LENGTH,2);
				if(n==1)
				{
					bIns->s[ins_pos]=0x2E;ins_pos++;
				}
				else if(n==2)
				{
					bIns->s[ins_pos]=0x3E;ins_pos++;
				}
				else if(n==3)
				{
					bIns->s[ins_pos]=0x36;ins_pos++;
				}
				else if(n==4)
				{
					bIns->s[ins_pos]=0x26;ins_pos++;
				}
				else if(n==5)
				{
					bIns->s[ins_pos]=0x64;ins_pos++;
				}
				else if(n==6)
				{
					bIns->s[ins_pos]=0x65;ins_pos++;
				}
				if(src_test.find_first_of(":") !=2)
				{                         //it should be fs:[xxx]
					goto assemble_error;
				}
				src_test = trim(src_test.substr(3,src_test.size()-1));
			}                                                    // check on the []
			if(src_test.substr(0,1) !="[" || 
				src_test.substr(src_test.size()-1,src_test.size()-1) !="]")
			{ 
				goto assemble_error;
			} 
			src_test = trim(src_test.substr(1,src_test.size()-2));
			modrm = get_modrm(src_test,flags);
			if(modrm.length == 0)
			{
				goto assemble_error;
			}
		}
		else if(compare_array(src_test,numbers,10,1))
		{                         // is it imm
			flags |=SRC_IMM;
			nsrc = imm_to_dec(src_test);         
		}
	}
	if (flags & NO_SRCDEST)
	{
		op_flags=OP_ANY;
	}
	else if(flags & DEST_RM)
	{      
		if (flags & SRC_RM)
		{
			goto assemble_error;
		}
		else if (flags & SRC_NOSRC)
		{
			op_flags =OP_RM_ONLY;
		}
		else if (flags & SRC_REG)
		{   
			op_flags=OP_RM_R;
			int reg_flag=1 << nsrc;
			op_flags |=reg_flag;
			modrm.s[0] += (char)(nsrc << 3);
		}
		else if (flags & SRC_IMM)
		{
			op_flags=OP_RM_IMM;
		}
		else
		{
			goto assemble_error;
		}
	}
	else if (flags & DEST_IMM)
	{
		if (flags & SRC_NOSRC)
		{
			op_flags =OP_IMM_ONLY;
		}
		else
		{
			goto assemble_error;
		}
	}
	else if(flags & DEST_REG)
	{
		if (flags & SRC_RM)
		{
			op_flags =OP_R_RM;
			int reg_flag=1 << ndest;
			op_flags |=reg_flag;
			modrm.s[0]+= (char)(ndest << 3);
		}
		else if (flags & SRC_NOSRC)
		{
			op_flags =OP_REG_ONLY;
			int reg_flag=1 << ndest;
			op_flags |=reg_flag;
		}
		else if (flags & SRC_REG)
		{
			op_flags=OP_R_RM;
			int reg_flag=1 << ndest;
			op_flags |=reg_flag;
			modrm.length=1;
			modrm.s[0]=(char)(0xC0 + nsrc+ (ndest  << 3)); 
		}
		else if (flags & SRC_IMM)
		{
			op_flags=OP_R_IMM;
			int reg_flag=1 << ndest;
			op_flags |=reg_flag;
		}
		else
		{
			goto assemble_error;
		}
	}
	if (flags & DEST_BITS32)
	{
		op_flags|=OP_BITS32;
	}
	else if (flags & DEST_BITS16)
	{
		op_flags|=OP_BITS32;
		bits16=true;
		bIns->s[ins_pos]=0x66;           //the prefix
		ins_pos++;
	}
	else if (flags & DEST_BITS8)
	{     
		op_flags|=OP_BITS8;
	}
	if ((op_flags & OP_RM_IMM) || (op_flags & OP_R_IMM) ||
		(op_flags & OP_IMM_ONLY))
	{
		if (op_flags & OP_IMM_ONLY)
		{
			if (ndest <256)
			{
				op_flags |=OP_IMM8;
			}
			else
			{
				op_flags |=OP_IMM32;
			}
		}
		else
		{
			if (nsrc <256)
			{
				op_flags |=OP_IMM8;
			}
			else
			{
				op_flags |=OP_IMM32;
			}
		}
	}                         
	if (opcode=="mov" && modrm.s[0]==5 && modrm.length >=1)
	{
		if (((op_flags & OP_RM_R) && nsrc==0) || ((op_flags & OP_R_RM) && ndest==0))
		{
			op_flags |=OP_RM_DISP;
			//deleting the modrm byte and leave the disp32
			for (int l=1;l<modrm.length;l++)
			{
				modrm.s[l-1]=modrm.s[l];
			}
			modrm.length--;
			if (bits16==true)
			{
				if (bIns->s[ins_pos-1]==0x66)bIns->s[ins_pos-1]=0x67;
			}
		}
	}
	else if(opcode=="xchg" && (op_flags & OP_RM_R) &&
		(op_flags & OP_REG_EAX) && (op_flags & OP_BITS32))
	{
		op_flags= OP_REG_ONLY | OP_BITS32;
		int rm=(modrm.s[0] & 0x07);
		op_flags |= (1 << rm);
		modrm.length=0;
	}
	else if(opcode=="xchg" && (op_flags & OP_RM_R) &&
		(modrm.s[0] & 0x07)==0 && (op_flags & OP_BITS32))
	{
		op_flags &=0xFF;   //get the op_reg_exx
		op_flags |=OP_REG_ONLY | OP_BITS32;
		modrm.length=0; 
	}
	else if (opcode=="jcxz")
	{
		opcode="jecxz";
		bIns->s[ins_pos]=0x67;ins_pos++;
	}
	else if (opcode=="ret" && (op_flags & OP_IMM_ONLY))
	{
		bits16=true; 
		flags &=~OP_IMM8;
		flags &=OP_IMM32;
		//Imul exx,exx
	}
	else if (opcode=="imul" && !(flags & SRC_NOSRC))
	{
		if(no_imul_imm==true)op_flags |= OP_0F;
	}
	else if (opcode.size()==5 && opcode.c_str()[4]=='w')
	{
		opcode=opcode.substr(0,4);
		opcode.append("d");
		bIns->s[ins_pos]=0x66;
		ins_pos++;
		//movzx & movsx
	}
	else if (flags & MOVXZ_SRC8)
	{
		op_flags |=OP_SRC8;
	}
	else if (flags & MOVXZ_SRC16)
	{
		op_flags |=OP_SRC16;

	}
opcode_check:
	for (int i=0;i<dis_entries;i++)
	{
		if (FlagTable[i].opcode == 0 && FlagTable[i].flags==0)
		{
			continue;              //ignore invalid Entries
		}
		if (FlagTable[i].mnemonics==opcode.c_str())
		{
			int n= (op_flags & FlagTable[i].flags);
			if (n==op_flags)
			{                                             //this mean op_flags inside the flagtable.flaga
				if (FlagTable[i].flags & OP_0F)
				{
					bIns->s[ins_pos]=0x0F;
					ins_pos++;
				}
				bIns->s[ins_pos] = (char)FlagTable[i].opcode;
				ins_pos++;
				if (FlagTable[i].flags & OP_GROUP)
				{
					modrm.s[0] &=0xC7;  //deleting the reg
					modrm.s[0]+= (char)(FlagTable[i].reg  << 3);
				}
				if ((op_flags & OP_RM_IMM) || (op_flags & OP_R_IMM) ||
					(op_flags & OP_IMM_ONLY))
				{
					if (op_flags & OP_IMM_ONLY)
					{
						if ((op_flags & OP_IMM8) && !(FlagTable[i].flags & OP_IMM32))
						{
							memcpy(&modrm.s[modrm.length],&ndest,1);
							modrm.length++;
						}
						else if (bits16)
						{
							memcpy(&modrm.s[modrm.length],&ndest,2);
							modrm.length+=2;
						}
						else
						{
							memcpy(&modrm.s[modrm.length],&ndest,4); 
							modrm.length+=4;
						}      
					}
					else
					{
						if ((op_flags & OP_IMM8) && !(FlagTable[i].flags & OP_IMM32))
						{    //it's mean it's only for IMM8
							memcpy(&modrm.s[modrm.length],&nsrc,1);
							modrm.length++;
						}
						else if (bits16)
						{
							memcpy(&modrm.s[modrm.length],&nsrc,2);
							modrm.length+=2;
						}
						else
						{
							memcpy(&modrm.s[modrm.length],&nsrc,4); 
							modrm.length+=4;
						}
					}
				}
				if (FlagTable[i].opcode==0x69)
				{
					if (imul_imm <256)
					{
						memcpy(&modrm.s[modrm.length],&imul_imm,1);
						modrm.length++;
						bIns->s[ins_pos-1]=0x6B;
					}
					else
					{
						memcpy(&modrm.s[modrm.length],&imul_imm,4); 
						modrm.length+=4;
					}          
				}
				if (FlagTable[i].opcode==0xC0&& (op_flags & OP_RM_IMM) && (nsrc==1))
				{
					bIns->s[ins_pos-1]= (BYTE)0xD0;modrm.length=1;
				}
				if (FlagTable[i].opcode==0xC1 && (op_flags & OP_RM_IMM) && (nsrc==1))
				{
					bIns->s[ins_pos-1]= (BYTE)0xD1;modrm.length=1;
				}
				for (int l=0;l<modrm.length;l++)
				{
					bIns->s[ins_pos]=modrm.s[l];
					ins_pos++;
				}
				goto opcode_founded; 
			}
		}
	}
	//we will reach here if it didn't find so we will test other flags :)
	if (op_flags & OP_R_IMM)
	{
		op_flags &= (~OP_R_IMM);
		op_flags&=~(1<< ndest);
		op_flags |= OP_RM_IMM;
		modrm.length=1;
		modrm.s[0]= (char)(0xC0 + (ndest));
		goto opcode_check;

	}
	else if(op_flags & OP_REG_ONLY)
	{
		op_flags &= (~OP_REG_ONLY);
		op_flags&=~(1<< ndest);
		op_flags |= OP_RM_ONLY;
		modrm.length=1;
		modrm.s[0]= (char)(0xC0 + (ndest));
		goto opcode_check;
	}
	else if((flags & SRC_REG)&&(flags & DEST_REG)&& (op_flags & OP_R_RM))
	{
		op_flags &=~OP_R_RM;
		op_flags &=~(1 << ndest);
		op_flags|=OP_RM_R;
		int reg_flag=1 << nsrc;
		op_flags |=reg_flag;
		modrm.length=1;
		modrm.s[0]= (char)(0xC0 + ndest+ (nsrc  << 3)) ;
		goto opcode_check;
	}
opcode_founded:  
	bIns->length=ins_pos;
	return  bIns;       
assemble_error:
	bIns->length=0;
	return bIns;
}
//------------------------------------------------------------------------------------------------------------//
//-----                                                                                                  -----//
//-----                                                                                                  -----//
//-----                                     Get ModRM                                                    -----//
//-----                                                                                                  -----//
//-----                                                                                                  -----//
//------------------------------------------------------------------------------------------------------------//

//this procedure resolve the modrm that come from the assembler
bytes get_modrm(string rm,int& flags){
     int npos=0;
     int rm_flags[3];
     int n=0;                                                //the number of arguments
     bool neg=false;                                         //use "-" like [eax - 12345678h]
     int imm_size=0,reg1_place=100,reg2_place=100,imm_place=0;          // reg1--> normal reg2--> scaled index  100-->not initialized
     int reg_mul=0;                                         //the register multiplied by what? [eax*2] reg_mul-->2            
     bool imm=false;                                        
     int mod=0,nrm=0;                                  // nrm-->rm
     int modrm=0,sib=0;
     int ss=0,index=0,reg=0;
     for (int i=0;i<3;i++){
         if (rm.size()==0) break;
         if (compare_array(rm,reg32,REGISTERS_LENGTH,3)){ 
             //now the first argument is a register
             rm_flags[i]=compare_array(rm,reg32,REGISTERS_LENGTH,3)-1;       
             if (rm.size()<=3){                                              //no other element (avoiding errors)
                               n++;
                                if (i>0 && reg1_place !=100){                //reg1 initialized so we need the next reg will be sib **
                                   reg2_place=i;
                                   flags |=RM_SIB;
                                }else{
                                   reg1_place=i;};
                               break;};
             rm=trim(rm.substr(3,rm.size()-1));
             for (int l=0;l<2;l++){                         // check on all operators (like eax*2 + xxx) check on * & +
                 if(rm.substr(0,1)=="-"){
                      neg=true;
                      if (reg2_place !=i){         
                           if (i>0 && reg1_place !=100){
                                   reg2_place=i;}
                           else {reg1_place=i;
                           };
                       };
                      if (rm.size()<=1) break;
                      rm=trim(rm.substr(1,rm.size()-1));
                       break;
                 }else if (rm.substr(0,1)=="*"){
                       reg2_place=i;                    //there's a scaled index
                       if (rm.size()<=1) break;
                      rm=trim(rm.substr(1,rm.size()-1));
                      reg_mul=atoi(rm.substr(0,1).c_str());
                      flags |=RM_SIB;                      // surely there's sib if there's a mul
                      if (rm.size()<=1){
                                         rm="";
                                         break;};
                      rm=trim(rm.substr(1,rm.size()-1));          
                 }else if (rm.substr(0,1)=="+"){
                       if (reg2_place !=i){         
                           if (i>0 && reg1_place !=100){
                                   reg2_place=i;}
                           else {reg1_place=i;
                           };
                       };
                       if (rm.size()<=1){
                             break;
                       };
                      rm=trim(rm.substr(1,rm.size()-1));
                 };
             };      
             n++;
         }else if (compare_array(rm,numbers,10,1)) {
               //it's an imm
               imm_place=i;
               rm_flags[i]=imm_to_dec(rm);
               n++;
               imm=true;
               if (rm.find_first_of("+") >0 && rm.find_first_of("+" )< rm.size()){  // if there's another elements in rm (we can't get the imm size)
                  rm_flags[i]=imm_to_dec(trim(rm.substr(0,rm.find_first_of("+"))));
               }else {
                     break;}
                  rm=trim(rm.substr(rm.find_first_of("+")+1,rm.size()));         //check if there's another elements in the rm expression                      
         }else if (trim(rm)==""){
               if (i==0) goto get_modrm_error;                                   //nothing in the rm --> error
               break;
         };
     };

     if (n>2){
         flags |=RM_SIB;                                // 2 registers mean sib surely
     };
     if (n>1 && imm==true && rm_flags[reg1_place]==4){                    //[esp + xxxh]
          flags |=RM_SIB;                                                 //surely there's sib
          reg2_place=0;
     }else if (imm==false && rm_flags[reg1_place]==4){
          flags |=RM_SIB;
          reg2_place=0;                                                 //surely there's sib
     };
     if (n==1 && imm==false && rm_flags[reg1_place]==5){                  //dword ptr [ebp]
              imm=true;
              imm_size=8;
              n++;
              imm_place=n-1;
              rm_flags[imm_place]=0;
     };
     //------------------------------------------------
     // Creating the Mod:
     if (imm==false){
        mod=0;                                         //no disp
     }else{
           if (n==1 ){                                 //disp32 only
              mod=0;
              imm_size=32;
              if (neg){rm_flags[imm_place]=0xFFFFFFFF-rm_flags[imm_place]+1;};  
        }else if (rm_flags[imm_place]<256){
           imm_size=8;
           mod=1;                                     // disp8
           if(imm==true && n==2 && reg_mul !=0 && imm_size==8) {    //when (eax*2 +disp --> disp must be 32 coz there's no modrm for disp8  
               imm_size=32;
               if (neg){rm_flags[imm_place]=0xFFFFFFFF-rm_flags[imm_place]+1;};
           }else{
                 imm_size=8;
                 if (neg){rm_flags[imm_place]=256-rm_flags[imm_place];};
           };
        }else{
            mod=2;                                   // disp32
            imm_size=32;
            if (neg){rm_flags[imm_place]=0xFFFFFFFF-rm_flags[imm_place]+1;};
        };
     };
     //-------------------------------------------------------
     //Creating the RM
     if (flags & RM_SIB){
         nrm=4;
     }else{
         if (n==1 && imm==true){                              //disp only
            nrm=5;
         }else{
               nrm=rm_flags[reg1_place];
         };
     };
     // we will not create the reg because it depends on the src --> opcode dest,src
     //-------------------------------------------------------
     //Creating SIB
     //SS
     if (flags & RM_SIB){
         if (imm==false && n==1 && reg_mul !=0){              //[eax*2] must have disp32 with it **
             imm_size=32;
             imm=true;
             n++;
             imm_place=n;
             rm_flags[imm_place]=0;
         };
         reg_mul /=2;
         if (reg_mul==4) reg_mul=3;
         ss=reg_mul;
         //-------------------------------------------------------------
         //Creating the Index
         index=rm_flags[reg2_place];
         //-------------------------------------------------------------
         //Creating the reg
         if(n==2 && reg_mul !=0 && imm==true){                          //[eax*2 +xxx] for avoid any other register beside them reg=5 (if mod=1--> [eax*2 +ebp+disp8]
                 reg=5;
                 mod=0;
         }else if(n==2 && rm_flags[reg1_place]==4){                     //[esp + disp] n==2 & no multiply (could be missed) **
                 index=4;ss=0;reg=4; 
         }else{
                 reg=rm_flags[reg1_place];
         };
     };
     modrm = (mod << 6) + nrm;
     sib=(ss << 6) +(index << 3) + reg;
     imm_size/=8;
     bytes b;           
     b.length=1+imm_size;      //1 for modrm
     b.s[0]= (char)modrm;
     npos++;
     if (flags & RM_SIB){
           b.length++;
           b.s[1]= (char)sib;
           npos++;
     };
     if (imm==true)memcpy(&b.s[npos],&rm_flags[imm_place],imm_size);
     /*
     char buff[50];
     cout << imm_size << "\n";
     sprintf(buff,"%02X %02X %02X %02X %02X %02X %02X",b.s[0],b.s[1],b.s[2],b.s[3],b.s[4],b.s[5],b.s[6]);
     cout << buff << "\n";     
     cout << (int)b.s[0] << " "<< (int)b.s[1]<< " " << (int)b.s[2]<< " " << (int)b.s[3]<< " "<< (int)b.s[4]<< " " << (int)b.s[5];
     //*/
       return b;
     //return flags;
get_modrm_error: 
                 b.length=0;
                 b.s[0]=1;
                 return b;
};

//----------------------------------------------------------------------------------------------------
int imm_to_dec(string imm){
    int n;
    if (imm.substr(imm.size()-1,imm.size()-1)=="h"){                            //hex
        sscanf_s(imm.substr(0,imm.size()-1).c_str(),"%x",&n);
        return n;
    } else if (imm.substr(imm.size()-1,imm.size()-1)=="b"){                     //binary
          return bintodec(atoi(imm.substr(0,imm.size()-1).c_str()));
    }else {                                                                     //decimal
        return atoi(imm.c_str()); 
    };                             
};
// from www.dreamincode.net
int bintodec(int decimal)
{ 
     int total = 0;
     int power = 1;
     
 
     
     while(decimal > 0)
     {
          total += decimal % 10 * power;
          decimal = decimal / 10;
          power = power * 2;
          };

     return total;
};
string to_lower_case(string s){
       string str1=s;
        char i=0;
       for (DWORD n=0;n<=s.size()-1;n++){
           i=0;
           i=s.at(n);
           if (i >=65 && i <=90){
              i=32+i;
              char s2[2] ={(char)i};
              str1.replace(n,1,s2);
           };
       };
       return str1;
}

wstring to_lower_case(wstring s)
{
	wstring str1 = L"";
	wchar_t ch = 0, chDiff = (wchar_t)(L'a' - L'A');

	for(DWORD n = 0; n < s.size(); n++)
	{
		ch = s.at(n);
		ch += ch >= L'A' && ch <= L'Z'? chDiff: 0;
		str1.push_back(ch);
	}

	return str1;
}

string trim(string s){
        string str1=s;
        if (str1.find_first_not_of(" ") < str1.size()){
           str1=str1.substr(str1.find_first_not_of(" "),str1.size());
           str1=str1.substr(0,str1.find_last_not_of(" ")+1);
        };
        return str1;
};
int compare_array(string s1,string s2[],int length){
    bool found=0;
    int i=0;
    for (i=0;i<=length-1;i++){
        if(s1.compare(s2[i]) ==0){
                       found=true;
                       break;};
    };
    if(found==true){
                    return i+1;
    }else{return 0;};
   
};
int compare_array(string s1,string s2[],int length,int size){
    bool found=0;
    int i=0;
    for (i=0;i<=length-1;i++){
        if(s1.substr(0,size).compare(s2[i]) ==0){
                       found=true;
                       break;};
    };
    if(found==true){
                    return i+1;
    }else{return 0;};
   
};

wstring convert_a2w(string str)
{
	wstring wstr;
	wchar_t ch = 0;

	for(DWORD n = 0; n < str.size(); n++)
	{
		ch = str.at(n);
		wstr.push_back(ch);
	}

	return wstr;
}

string convert_w2a(wstring wstr)
{
	string str;
	char ch = 0;

	for(DWORD n = 0; n < str.size(); n++)
	{
		ch = (char)str.at(n);
		str.push_back(ch);
	}

	return str;
}

wstring convert_cptr2w(const char * str)
{
	wstring wstr;

	while(str && *str)
	{
		wstr.push_back(((wchar_t)*str++));
	}

	return wstr;
}

string convert_wcptr2s(const wchar_t * wstr)
{
	string str;

	while(wstr && *wstr)
	{
		str.push_back(((char)*wstr++));
	}

	return str;
}

char* convert_wcptr2cptr(const wchar_t * wstr, char * str, DWORD cbstr)
{
	memset(str, 0, cbstr);
	if(wstr && wcslen(wstr) < cbstr)
	{
		for(int i = 0; wstr[i]; i++)
		{
			str[i] = (char)wstr[i];
		}
	}

	return str;
}

wchar_t* convert_cptr2wcptr(const char * str, wchar_t * wstr, DWORD cchwstr)
{
	memset(wstr, 0, cchwstr * sizeof(WCHAR));
	if(str && strlen(str) < cchwstr)
	{
		for(int i = 0; str[i]; i++)
		{
			wstr[i] = str[i];
		}
	}

	return wstr;
}

