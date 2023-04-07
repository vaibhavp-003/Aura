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
#define __DISASM__ 1
#include "../x86emu.h"
//#include "./disassembler.h"
//int dis_entries=0;
//FLAGTABLE FlagTable[512*7];


int undefined_opcode(Thread& thread,ins_disasm* s){
	thread = thread;
	s = s;
    return 0;
};
int op_error(Thread& thread,ins_disasm* s){
	thread = thread;
	s = s;
    return EXP_INVALID_INSTRUCTION;
}

int System::define_opcodes(int opcode,int reg,int (*emu_func)(Thread&,ins_disasm*),string mnemonics,int flags){
  if (opcode > dis_entries)dis_entries=opcode;
  if (flags & OP_GROUP && dis_entries< 0x100)dis_entries = 0x100;
  if ((flags & OP_GROUP) && (flags & OP_FPU) && dis_entries < 500) dis_entries =1000;
  if((flags & OP_GROUP) && reg==0 && !(flags & OP_0F))FlagTable[opcode].reg = dis_entries;                    //set the reg with the index of its group
  if ((flags & OP_0F) && dis_entries < 500) dis_entries =500;
  
  FlagTable[dis_entries].opcode=opcode;
  FlagTable[dis_entries].reg=reg;
  FlagTable[dis_entries].emu_func=emu_func;
  FlagTable[dis_entries].mnemonics=mnemonics;
  FlagTable[dis_entries].flags=flags;
  dis_entries++;
	  return 0;
};
int System::opcodes_init(){
    //Group 1
    //--------
    define_opcodes(0x00,0,op_add,"add",OP_RM_R | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x01,0,op_add,"add",OP_RM_R | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x02,0,op_add,"add",OP_R_RM | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x03,0,op_add,"add",OP_R_RM | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x04,0,op_add,"add",OP_R_IMM | OP_BITS8 | OP_IMM8 | OP_REG_EAX);
    define_opcodes(0x05,0,op_add,"add",OP_R_IMM | OP_BITS32 | OP_IMM32 | OP_REG_EAX);
    //define_opcodes(0x06,0,undefined_opcode,"push",OP_BITS32);
    //define_opcodes(0x07,0,undefined_opcode,"pop",OP_BITS32);
    define_opcodes(0x08,0,op_or ,"or",OP_RM_R | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x09,0,op_or ,"or",OP_RM_R | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x0A,0,op_or ,"or",OP_R_RM | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x0B,0,op_or ,"or",OP_R_RM | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x0C,0,op_or ,"or",OP_R_IMM | OP_BITS8 | OP_IMM8 | OP_REG_EAX);
    define_opcodes(0x0D,0,op_or ,"or",OP_R_IMM | OP_BITS32 | OP_IMM32 | OP_REG_EAX);
    //define_opcodes(0x0E,0,undefined_opcode,"push",OP_BITS32);
    //define_opcodes(0x0F,0,undefined_opcode,"pop",OP_BITS32);
    define_opcodes(0x10,0,op_adc,"adc",OP_RM_R | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x11,0,op_adc,"adc",OP_RM_R | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x12,0,op_adc,"adc",OP_R_RM | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x13,0,op_adc,"adc",OP_R_RM | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x14,0,op_adc,"adc",OP_R_IMM | OP_BITS8 | OP_IMM8 | OP_REG_EAX);
    define_opcodes(0x15,0,op_adc,"adc",OP_R_IMM | OP_BITS32 | OP_IMM32 | OP_REG_EAX);
    //define_opcodes(0x06,0,undefined_opcode,"push",OP_BITS32);
    //define_opcodes(0x07,0,undefined_opcode,"pop",OP_BITS32);
    define_opcodes(0x18,0,op_sbb,"sbb",OP_RM_R | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x19,0,op_sbb,"sbb",OP_RM_R | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x1A,0,op_sbb,"sbb",OP_R_RM | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x1B,0,op_sbb,"sbb",OP_R_RM | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x1C,0,op_sbb,"sbb",OP_R_IMM | OP_BITS8 | OP_IMM8 | OP_REG_EAX);
    define_opcodes(0x1D,0,op_sbb,"sbb",OP_R_IMM | OP_BITS32 | OP_IMM32 | OP_REG_EAX);
    //define_opcodes(0x0E,0,undefined_opcode,"push",OP_BITS32);
    //define_opcodes(0x0F,0,undefined_opcode,"pop",OP_BITS32);
    define_opcodes(0x20,0,op_and,"and",OP_RM_R | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x21,0,op_and,"and",OP_RM_R | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x22,0,op_and,"and",OP_R_RM | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x23,0,op_and,"and",OP_R_RM | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x24,0,op_and,"and",OP_R_IMM | OP_BITS8 | OP_IMM8 | OP_REG_EAX);
    define_opcodes(0x25,0,op_and,"and",OP_R_IMM | OP_BITS32 | OP_IMM32 | OP_REG_EAX);
    //define_opcodes(0x06,0,undefined_opcode,"push",OP_BITS32);
    define_opcodes(0x27,0,undefined_opcode,"daa",OP_ANY);
    define_opcodes(0x28,0,op_sub,"sub",OP_RM_R | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x29,0,op_sub,"sub",OP_RM_R | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x2A,0,op_sub,"sub",OP_R_RM | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x2B,0,op_sub,"sub",OP_R_RM | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x2C,0,op_sub,"sub",OP_R_IMM | OP_BITS8 | OP_IMM8 | OP_REG_EAX);
    define_opcodes(0x2D,0,op_sub,"sub",OP_R_IMM | OP_BITS32 | OP_IMM32 | OP_REG_EAX);
    //define_opcodes(0x0E,0,undefined_opcode,"push",OP_BITS32);
    //define_opcodes(0x0F,0,undefined_opcode,"pop",OP_BITS32);
    define_opcodes(0x30,0,op_xor,"xor",OP_RM_R | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x31,0,op_xor,"xor",OP_RM_R | OP_BITS32 | OP_REG_ALL);
    define_opcodes(0x32,0,op_xor,"xor",OP_R_RM | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x33,0,op_xor,"xor",OP_R_RM | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x34,0,op_xor,"xor",OP_R_IMM | OP_BITS8 | OP_IMM8 | OP_REG_EAX);
    define_opcodes(0x35,0,op_xor,"xor",OP_R_IMM | OP_BITS32 | OP_IMM32 | OP_REG_EAX);
    //define_opcodes(0x06,0,undefined_opcode,"push",OP_BITS32);
    define_opcodes(0x37,0,undefined_opcode,"aaa",OP_ANY);
    define_opcodes(0x38,0,op_cmp,"cmp",OP_RM_R | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x39,0,op_cmp,"cmp",OP_RM_R | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x3A,0,op_cmp,"cmp",OP_R_RM | OP_BITS8 | OP_REG_ALL );
    define_opcodes(0x3B,0,op_cmp,"cmp",OP_R_RM | OP_BITS32 | OP_REG_ALL );
    define_opcodes(0x3C,0,op_cmp,"cmp",OP_R_IMM | OP_BITS8 | OP_IMM8 | OP_REG_EAX);
    define_opcodes(0x3D,0,op_cmp,"cmp",OP_R_IMM | OP_BITS32 | OP_IMM32 | OP_REG_EAX);
    //define_opcodes(0x0E,0,undefined_opcode,"push",OP_BITS32);
    //define_opcodes(0x0F,0,undefined_opcode,"pop",OP_BITS32);
    
    //Group 2
    //----------
    
    define_opcodes(0x40,0,op_inc,"inc",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX);
    define_opcodes(0x41,0,op_inc,"inc",OP_BITS32 | OP_REG_ONLY | OP_REG_ECX);
    define_opcodes(0x42,0,op_inc,"inc",OP_BITS32 | OP_REG_ONLY | OP_REG_EDX);
    define_opcodes(0x43,0,op_inc,"inc",OP_BITS32 | OP_REG_ONLY | OP_REG_EBX);
    define_opcodes(0x44,0,op_inc,"inc",OP_BITS32 | OP_REG_ONLY | OP_REG_ESP);
    define_opcodes(0x45,0,op_inc,"inc",OP_BITS32 | OP_REG_ONLY | OP_REG_EBP);
    define_opcodes(0x46,0,op_inc,"inc",OP_BITS32 | OP_REG_ONLY | OP_REG_ESI);
    define_opcodes(0x47,0,op_inc,"inc",OP_BITS32 | OP_REG_ONLY | OP_REG_EDI);
    define_opcodes(0x48,0,op_dec,"dec",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX);
    define_opcodes(0x49,0,op_dec,"dec",OP_BITS32 | OP_REG_ONLY | OP_REG_ECX);
    define_opcodes(0x4A,0,op_dec,"dec",OP_BITS32 | OP_REG_ONLY | OP_REG_EDX);
    define_opcodes(0x4B,0,op_dec,"dec",OP_BITS32 | OP_REG_ONLY | OP_REG_EBX);
    define_opcodes(0x4C,0,op_dec,"dec",OP_BITS32 | OP_REG_ONLY | OP_REG_ESP);
    define_opcodes(0x4D,0,op_dec,"dec",OP_BITS32 | OP_REG_ONLY | OP_REG_EBP);
    define_opcodes(0x4E,0,op_dec,"dec",OP_BITS32 | OP_REG_ONLY | OP_REG_ESI);
    define_opcodes(0x4F,0,op_dec,"dec",OP_BITS32 | OP_REG_ONLY | OP_REG_EDI);
    
    //Group 3
    //----------
    
    define_opcodes(0x50,0,op_push,"push",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX);
    define_opcodes(0x51,0,op_push,"push",OP_BITS32 | OP_REG_ONLY | OP_REG_ECX);
    define_opcodes(0x52,0,op_push,"push",OP_BITS32 | OP_REG_ONLY | OP_REG_EDX);
    define_opcodes(0x53,0,op_push,"push",OP_BITS32 | OP_REG_ONLY | OP_REG_EBX);
    define_opcodes(0x54,0,op_push,"push",OP_BITS32 | OP_REG_ONLY | OP_REG_ESP);
    define_opcodes(0x55,0,op_push,"push",OP_BITS32 | OP_REG_ONLY | OP_REG_EBP);
    define_opcodes(0x56,0,op_push,"push",OP_BITS32 | OP_REG_ONLY | OP_REG_ESI);
    define_opcodes(0x57,0,op_push,"push",OP_BITS32 | OP_REG_ONLY | OP_REG_EDI);
    define_opcodes(0x58,0,op_pop ,"pop",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX);
    define_opcodes(0x59,0,op_pop ,"pop",OP_BITS32 | OP_REG_ONLY | OP_REG_ECX);
    define_opcodes(0x5A,0,op_pop ,"pop",OP_BITS32 | OP_REG_ONLY | OP_REG_EDX);
    define_opcodes(0x5B,0,op_pop ,"pop",OP_BITS32 | OP_REG_ONLY | OP_REG_EBX);
    define_opcodes(0x5C,0,op_pop ,"pop",OP_BITS32 | OP_REG_ONLY | OP_REG_ESP);
    define_opcodes(0x5D,0,op_pop ,"pop",OP_BITS32 | OP_REG_ONLY | OP_REG_EBP);
    define_opcodes(0x5E,0,op_pop ,"pop",OP_BITS32 | OP_REG_ONLY | OP_REG_ESI);
    define_opcodes(0x5F,0,op_pop ,"pop",OP_BITS32 | OP_REG_ONLY | OP_REG_EDI);
    //----------
    // 6x
    define_opcodes(0x60,0,op_pushad,"pushad",OP_ANY);
    define_opcodes(0x60,0,op_pushad,"pusha",OP_ANY);     //the same meaning
    define_opcodes(0x61,0,op_popad ,"popad",OP_ANY);
    define_opcodes(0x61,0,op_popad ,"popa",OP_ANY);
    //define_opcodes(0x62,0,undefined_opcode,"bound",OP_BITS32);
    //define_opcodes(0x63,0,undefined_opcode,"arpl",OP_BITS32);
    //define_opcodes(0x64,0,undefined_opcode,"add",OP_BITS32);
    //define_opcodes(0x65,0,undefined_opcode,"add",OP_BITS32);
    //define_opcodes(0x66,0,undefined_opcode,"add",OP_BITS32);
    //define_opcodes(0x67,0,undefined_opcode,"add",OP_BITS32);
    define_opcodes(0x68,0,op_push,"push",OP_BITS32 | OP_IMM_ONLY | OP_IMM32);
    define_opcodes(0x69,0,op_imul3,"imul",OP_BITS32 | OP_R_RM | OP_IMM32 | OP_REG_ALL);
    define_opcodes(0x6A,0,op_push,"push",OP_BITS32 | OP_IMM_ONLY  | OP_IMM8);
    define_opcodes(0x6B,0,op_imul3,"imul",OP_BITS32 | OP_R_RM | OP_IMM8 | OP_REG_ALL);
    //define_opcodes(0x6C,0,undefined_opcode,"ins",OP_BITS32);
    //define_opcodes(0x6D,0,undefined_opcode,"ins",OP_BITS32);
    //define_opcodes(0x6E,0,undefined_opcode,"outs",OP_BITS32);
    //define_opcodes(0x6F,0,undefined_opcode,"outs",OP_BITS32);
    //----------
    //7x Jmps:
    define_opcodes(0x70,0,op_jcc,"jo",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x71,0,op_jcc,"jno",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x72,0,op_jcc,"jb",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x72,0,op_jcc,"jnae",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x73,0,op_jcc,"jnb",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x73,0,op_jcc,"jae",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x74,0,op_jcc,"jz",OP_IMM8 | OP_IMM_ONLY);
    define_opcodes(0x74,0,op_jcc,"je",OP_IMM8 | OP_IMM_ONLY);
    define_opcodes(0x75,0,op_jcc,"jnz",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x75,0,op_jcc,"jne",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x76,0,op_jcc,"jbe",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x76,0,op_jcc,"jna",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x77,0,op_jcc,"jnbe",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x77,0,op_jcc,"ja",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x78,0,op_jcc,"js",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x79,0,op_jcc,"jns",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7A,0,op_jcc,"jp",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7A,0,op_jcc,"jpe",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7B,0,op_jcc,"jnp",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7B,0,op_jcc,"jpo",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7C,0,op_jcc,"jl",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7C,0,op_jcc,"jnge",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7D,0,op_jcc,"jnl",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7D,0,op_jcc,"jge",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7E,0,op_jcc,"jle",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7E,0,op_jcc,"jng",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7F,0,op_jcc,"jnle",OP_IMM8| OP_IMM_ONLY);
    define_opcodes(0x7F,0,op_jcc,"jg",OP_IMM8| OP_IMM_ONLY);
    //----------
    //8x 
    //define_opcodes(0x80,0,undefined_opcode,"add",OP_BITS32);       //groups
    //define_opcodes(0x81,0,undefined_opcode,"add",OP_BITS32);
    //define_opcodes(0x82,0,undefined_opcode,"add",OP_BITS32);
    //define_opcodes(0x83,0,undefined_opcode,"add",OP_BITS32);
    define_opcodes(0x84,0,op_test,"test",OP_BITS8 | OP_RM_R | OP_REG_ALL_EXP_EAX);
    define_opcodes(0x85,0,op_test,"test",OP_BITS32 | OP_RM_R | OP_REG_ALL_EXP_EAX);
    define_opcodes(0x86,0,op_xchg,"xchg",OP_BITS8 | OP_RM_R | OP_REG_ALL);
    define_opcodes(0x87,0,op_xchg,"xchg",OP_BITS32 | OP_RM_R | OP_R_RM | OP_REG_ALL);
    define_opcodes(0x88,0,op_mov,"mov",OP_BITS8 | OP_RM_R | OP_REG_ALL);
    define_opcodes(0x89,0,op_mov,"mov",OP_BITS32 | OP_RM_R | OP_REG_ALL);
    define_opcodes(0x8A,0,op_mov,"mov",OP_BITS8 | OP_R_RM | OP_REG_ALL);
    define_opcodes(0x8B,0,op_mov,"mov",OP_BITS32 | OP_R_RM | OP_REG_ALL);
    //define_opcodes(0x8C,0,undefined_opcode,"mov",OP_BITS32);         //segement registers
    define_opcodes(0x8D,0,op_lea,"lea",OP_BITS32 | OP_R_RM | OP_REG_ALL);
    //define_opcodes(0x8E,0,undefined_opcode,"mov",OP_BITS32);
    define_opcodes(0x8F,0,op_pop ,"pop",OP_BITS32 | OP_RM_ONLY);         //segement registers
    //----------------
    // 9x
    define_opcodes(0x90,0,undefined_opcode,"nop",OP_ANY);
    define_opcodes(0x91,0,op_xchg,"xchg",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX | OP_REG_ECX);
    define_opcodes(0x92,0,op_xchg,"xchg",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX | OP_REG_EDX);
    define_opcodes(0x93,0,op_xchg,"xchg",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX | OP_REG_EBX);
    define_opcodes(0x94,0,op_xchg,"xchg",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX | OP_REG_ESP);
    define_opcodes(0x95,0,op_xchg,"xchg",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX | OP_REG_EBP);
    define_opcodes(0x96,0,op_xchg,"xchg",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX | OP_REG_ESI);
    define_opcodes(0x97,0,op_xchg,"xchg",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX | OP_REG_EDI);
    //define_opcodes(0x98,0,undefined_opcode,"add",OP_BITS32);
    define_opcodes(0x99,0,op_cdq,"cdq",OP_ANY);
    define_opcodes(0x9A,0,op_call,"call",OP_BITS32);  //far call
    define_opcodes(0x9B,0,undefined_opcode,"wait",OP_ANY);
    define_opcodes(0x9C,0,op_pushfd,"pushf",OP_ANY);
    define_opcodes(0x9C,0,op_pushfd,"pushfd",OP_ANY);
    define_opcodes(0x9D,0,op_popfd,"popf",OP_ANY);
    define_opcodes(0x9D,0,op_popfd,"popfd",OP_ANY);
    define_opcodes(0x9E,0,undefined_opcode,"sahf",OP_ANY);
    define_opcodes(0x9F,0,undefined_opcode,"lahf",OP_ANY);
    //----------------
    // Ax
    define_opcodes(0xA0,0,op_mov,"mov",OP_BITS8 | OP_REG_EAX | OP_R_RM | OP_RM_DISP);
    define_opcodes(0xA1,0,op_mov,"mov",OP_BITS32 | OP_REG_EAX | OP_R_RM | OP_RM_DISP);
    define_opcodes(0xA2,0,op_mov,"mov",OP_BITS8 | OP_REG_EAX | OP_RM_R | OP_RM_DISP);
    define_opcodes(0xA3,0,op_mov,"mov",OP_BITS32 | OP_REG_EAX | OP_RM_R | OP_RM_DISP);
    define_opcodes(0xA4,0,op_movs,"movsb",OP_ANY);
    define_opcodes(0xA5,0,op_movs,"movsd",OP_ANY);
    define_opcodes(0xA6,0,op_cmps,"cmpsb",OP_ANY);
    define_opcodes(0xA7,0,op_cmps,"cmpsd",OP_ANY);
    define_opcodes(0xA8,0,op_test,"test",OP_BITS8 | OP_REG_EAX | OP_R_IMM);
    define_opcodes(0xA9,0,op_test,"test",OP_BITS32 | OP_REG_EAX | OP_R_IMM);
    define_opcodes(0xAA,0,op_stos,"stosb",OP_ANY);
    define_opcodes(0xAB,0,op_stos,"stosd",OP_ANY);
    define_opcodes(0xAC,0,op_lods,"lodsb",OP_ANY);
    define_opcodes(0xAD,0,op_lods,"lodsd",OP_ANY);
    define_opcodes(0xAE,0,op_scas,"scasb",OP_ANY);
    define_opcodes(0xAF,0,op_scas,"scasd",OP_ANY);
    //----------------
    // Bx
    define_opcodes(0xB0,0,op_mov,"mov",OP_BITS8 | OP_R_IMM | OP_REG_EAX | OP_IMM8);
    define_opcodes(0xB1,0,op_mov,"mov",OP_BITS8 | OP_R_IMM | OP_REG_ECX | OP_IMM8);
    define_opcodes(0xB2,0,op_mov,"mov",OP_BITS8 | OP_R_IMM | OP_REG_EDX | OP_IMM8);
    define_opcodes(0xB3,0,op_mov,"mov",OP_BITS8 | OP_R_IMM | OP_REG_EBX | OP_IMM8);
    define_opcodes(0xB4,0,op_mov,"mov",OP_BITS8 | OP_R_IMM | OP_REG_ESP | OP_IMM8);
    define_opcodes(0xB5,0,op_mov,"mov",OP_BITS8 | OP_R_IMM | OP_REG_EBP | OP_IMM8);
    define_opcodes(0xB6,0,op_mov,"mov",OP_BITS8 | OP_R_IMM | OP_REG_ESI | OP_IMM8);
    define_opcodes(0xB7,0,op_mov,"mov",OP_BITS8 | OP_R_IMM | OP_REG_EDI | OP_IMM8);
    define_opcodes(0xB8,0,op_mov,"mov",OP_BITS32 | OP_R_IMM | OP_REG_EAX | OP_IMM);
    define_opcodes(0xB9,0,op_mov,"mov",OP_BITS32 | OP_R_IMM | OP_REG_ECX | OP_IMM);
    define_opcodes(0xBA,0,op_mov,"mov",OP_BITS32 | OP_R_IMM | OP_REG_EDX | OP_IMM);
    define_opcodes(0xBB,0,op_mov,"mov",OP_BITS32 | OP_R_IMM | OP_REG_EBX | OP_IMM);
    define_opcodes(0xBC,0,op_mov,"mov",OP_BITS32 | OP_R_IMM | OP_REG_ESP | OP_IMM);
    define_opcodes(0xBD,0,op_mov,"mov",OP_BITS32 | OP_R_IMM | OP_REG_EBP | OP_IMM);
    define_opcodes(0xBE,0,op_mov,"mov",OP_BITS32 | OP_R_IMM | OP_REG_ESI | OP_IMM);
    define_opcodes(0xBF,0,op_mov,"mov",OP_BITS32 | OP_R_IMM | OP_REG_EDI | OP_IMM);
    //----------------
    // Cx
    //define_opcodes(0xC0,0,undefined_opcode,"add",OP_BITS32);
    //define_opcodes(0xC1,0,undefined_opcode,"add",OP_BITS32);
    define_opcodes(0xC2,0,op_ret,"ret",OP_BITS32 | OP_IMM | OP_IMM_ONLY);
    define_opcodes(0xC3,0,op_ret,"ret",OP_ANY);
    define_opcodes(0xC4,0,undefined_opcode,"les",OP_BITS32 | OP_R_IMM | OP_IMM | OP_REG_ALL);
    define_opcodes(0xC5,0,undefined_opcode,"eds",OP_BITS32 | OP_R_IMM | OP_IMM | OP_REG_ALL);
    define_opcodes(0xC6,0,op_mov,"mov",OP_BITS8 | OP_RM_IMM | OP_IMM8);
    define_opcodes(0xC7,0,op_mov,"mov",OP_BITS32 | OP_RM_IMM | OP_IMM);
    define_opcodes(0xC8,0,op_enter,"enter",OP_BITS32 | OP_IMM | OP_IMM_ONLY);
    define_opcodes(0xC9,0,op_leave,"leave",OP_ANY);
    define_opcodes(0xCA,0,op_error,"ret far",OP_BITS32 | OP_IMM);
    define_opcodes(0xCB,0,op_error,"ret far",OP_ANY);
    define_opcodes(0xCC,0,op_error,"int3",OP_ANY);
    define_opcodes(0xCD,0,op_error,"int",OP_BITS8 | OP_IMM_ONLY | OP_IMM8);
    define_opcodes(0xCE,0,op_error,"into",OP_ANY);
    define_opcodes(0xCF,0,op_error,"iret",OP_ANY);
    //----------------
    // Dx
    define_opcodes(0xD4,0,undefined_opcode,"aam",OP_BITS8 | OP_IMM);
    define_opcodes(0xD5,0,undefined_opcode,"aad",OP_BITS8 | OP_IMM);
    define_opcodes(0xD6,0,undefined_opcode,"salc",OP_ANY);
    define_opcodes(0xD7,0,undefined_opcode,"xlat",OP_ANY);
    //all the next is the fpu & groups
    //----------------
    // Ex
    define_opcodes(0xE0,0,op_jcc,"loopnz",OP_BITS8 | OP_IMM8 | OP_IMM_ONLY);
    define_opcodes(0xE0,0,op_jcc,"loopne",OP_BITS8 | OP_IMM8 | OP_IMM_ONLY);
    define_opcodes(0xE1,0,op_jcc,"loopz",OP_BITS8  | OP_IMM8 | OP_IMM_ONLY);
    define_opcodes(0xE1,0,op_jcc,"loope",OP_BITS8  | OP_IMM8 | OP_IMM_ONLY);
    define_opcodes(0xE2,0,op_jcc,"loop",OP_BITS8  | OP_IMM8 | OP_IMM_ONLY);
    define_opcodes(0xE3,0,op_jcc,"jecxz",OP_BITS8  | OP_IMM8 | OP_IMM_ONLY);
    //define_opcodes(0xE4,0,undefined_opcode,"in",OP_BITS32);
    //define_opcodes(0xE5,0,undefined_opcode,"in",OP_BITS32);
    //define_opcodes(0xE6,0,undefined_opcode,"out",OP_BITS32);
    //define_opcodes(0xE7,0,undefined_opcode,"out",OP_BITS32);
    define_opcodes(0xE8,0,op_call,"call",OP_BITS32 | OP_IMM | OP_IMM_ONLY);
    define_opcodes(0xE9,0,op_jcc,"jmp",OP_BITS32 | OP_IMM32 | OP_IMM_ONLY);
    define_opcodes(0xEA,0,undefined_opcode,"jmp far",OP_BITS32 | OP_RM_DISP | OP_RM_ONLY);
    define_opcodes(0xEB,0,op_jcc,"jmp",OP_BITS8 | OP_IMM8 | OP_IMM_ONLY);
    //define_opcodes(0xEC,0,undefined_opcode,"in",OP_BITS32);
    //define_opcodes(0xED,0,undefined_opcode,"in",OP_BITS32);
    //define_opcodes(0xEE,0,undefined_opcode,"out",OP_BITS32);
    //define_opcodes(0xEF,0,undefined_opcode,"out",OP_BITS32);
    //----------------
    // Fx
    define_opcodes(0xF0,0,op_error,"lock",OP_ANY);
    define_opcodes(0xF1,0,op_error,"int1",OP_ANY);
    define_opcodes(0xF2,0,op_error,"repne",OP_ANY);
    define_opcodes(0xF3,0,op_error,"rep",OP_ANY);
    define_opcodes(0xF4,0,op_error,"hlt",OP_ANY);
    define_opcodes(0xF5,0,undefined_opcode,"cmc",OP_ANY);
    //define_opcodes(0xF6,0,undefined_opcode,"add",0);
    //define_opcodes(0xF7,0,undefined_opcode,"add",0);
    define_opcodes(0xF8,0,op_clc,"clc",OP_ANY);
    define_opcodes(0xF9,0,op_stc,"stc",OP_ANY);
    define_opcodes(0xFA,0,undefined_opcode,"cli",OP_ANY);
    define_opcodes(0xFB,0,undefined_opcode,"sti",OP_ANY);
    define_opcodes(0xFC,0,undefined_opcode,"cld",OP_ANY);
    define_opcodes(0xFD,0,undefined_opcode,"std",OP_ANY);
    //define_opcodes(0xFE,0,undefined_opcode,"add",0);
    //define_opcodes(0xFF,0,undefined_opcode,"add",0);
    //----------------
    // Group #1 80-83
    define_opcodes(0x80,0,op_add,"add",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x80,1,op_or ,"or",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x80,2,op_adc,"adc",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x80,3,op_sbb,"sbb",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x80,4,op_and,"and",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x80,5,op_sub,"sub",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x80,6,op_xor,"xor",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x80,7,op_cmp,"cmp",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    
    define_opcodes(0x81,0,op_add,"add",OP_BITS32 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x81,1,op_or ,"or",OP_BITS32 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x81,2,op_adc,"adc",OP_BITS32 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x81,3,op_sbb,"sbb",OP_BITS32 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x81,4,op_and,"and",OP_BITS32 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x81,5,op_sub,"sub",OP_BITS32 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x81,6,op_xor,"xor",OP_BITS32 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x81,7,op_cmp,"cmp",OP_BITS32 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    
	define_opcodes(0x82,0,op_add,"add",OP_BITS8 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x82,1,op_or ,"or",OP_BITS8 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x82,2,op_adc,"adc",OP_BITS8 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x82,3,op_sbb,"sbb",OP_BITS8 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x82,4,op_and,"and",OP_BITS8 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x82,5,op_sub,"sub",OP_BITS8 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x82,6,op_xor,"xor",OP_BITS8 | OP_RM_IMM | OP_IMM32 | OP_GROUP);
    define_opcodes(0x82,7,op_cmp,"cmp",OP_BITS8 | OP_RM_IMM | OP_IMM32 | OP_GROUP);

	/*define_opcodes(0x83,0,op_add,"add",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x83,1,op_or ,"or",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x83,2,op_adc,"adc",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x83,3,op_sbb,"sbb",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x83,4,op_and,"and",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x83,5,op_sub,"sub",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x83,6,op_xor,"xor",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0x83,7,op_cmp,"cmp",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);*/

	define_opcodes(0x83,0,op_add83,"add",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
	define_opcodes(0x83,1,op_or83,"or",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
	define_opcodes(0x83,2,op_adc83,"adc",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
	define_opcodes(0x83,3,op_sbb83,"sbb",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
	define_opcodes(0x83,4,op_and83,"and",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
	define_opcodes(0x83,5,op_sub83,"sub",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
	define_opcodes(0x83,6,op_xor83,"xor",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
	define_opcodes(0x83,7,op_cmp,"cmp",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);

    //-----------------
    // Group #2 (C0-C1)(D0-D3)
    define_opcodes(0xC0,0,op_rol,"rol",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC0,1,op_ror,"ror",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC0,2,op_rcl,"rcl",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC0,3,op_rcr,"rcr",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC0,4,op_shl,"shl",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC0,5,op_shr,"shr",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC0,6,op_shl,"sal",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC0,7,op_sar,"sar",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    
    define_opcodes(0xC1,0,op_rol,"rol",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC1,1,op_ror,"ror",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC1,2,op_rcl,"rcl",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC1,3,op_rcr,"rcr",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC1,4,op_shl,"shl",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC1,5,op_shr,"shr",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC1,6,op_shl,"sal",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xC1,7,op_sar,"sar",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    
    define_opcodes(0xD0,0,op_rol,"rol",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP); //for imm8=1
    define_opcodes(0xD0,1,op_ror,"ror",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD0,2,op_rcl,"rcl",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD0,3,op_rcr,"rcr",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD0,4,op_shl,"shl",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD0,5,op_shr,"shr",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD0,6,op_shl,"sal",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD0,7,op_sar,"sar",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    
    define_opcodes(0xD1,0,op_rol,"rol",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);//for imm8=1
    define_opcodes(0xD1,1,op_ror,"ror",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD1,2,op_rcl,"rcl",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD1,3,op_rcr,"rcr",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD1,4,op_shl,"shl",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD1,5,op_shr,"shr",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD1,6,op_shl,"sal",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xD1,7,op_sar,"sar",OP_BITS32 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    
    define_opcodes(0xD2,0,op_rol,"rol",OP_BITS8 | OP_RM_R | OP_REG_ECX | OP_GROUP);//for reg=1
    define_opcodes(0xD2,1,op_ror,"ror",OP_BITS8 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD2,2,op_rcl,"rcl",OP_BITS8 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD2,3,op_rcr,"rcr",OP_BITS8 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD2,4,op_shl,"shl",OP_BITS8 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD2,5,op_shr,"shr",OP_BITS8 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD2,6,op_shl,"sal",OP_BITS8 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD2,7,op_sar,"sar",OP_BITS8 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    
    define_opcodes(0xD3,0,op_rol,"rol",OP_BITS32 | OP_RM_R | OP_REG_ECX | OP_GROUP);//for reg=ecx
    define_opcodes(0xD3,1,op_ror,"ror",OP_BITS32 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD3,2,op_rcl,"rcl",OP_BITS32 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD3,3,op_rcr,"rcr",OP_BITS32 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD3,4,op_shl,"shl",OP_BITS32 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD3,5,op_shr,"shr",OP_BITS32 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD3,6,op_shl,"sal",OP_BITS32 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    define_opcodes(0xD3,7,op_sar,"sar",OP_BITS32 | OP_RM_R | OP_REG_ECX | OP_GROUP);
    //---------------------
    
    define_opcodes(0xF6,0,op_test,"test",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xF6,1,op_test,"test",OP_BITS8 | OP_RM_IMM | OP_IMM8 | OP_GROUP);
    define_opcodes(0xF6,2,op_not,"not",OP_BITS8 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xF6,3,op_neg,"neg",OP_BITS8 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xF6,4,op_mul,"mul",OP_BITS8 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xF6,5,op_imul1,"imul",OP_BITS8 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xF6,6,op_div,"div",OP_BITS8 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xF6,7,op_idiv,"idiv",OP_BITS8 | OP_RM_ONLY | OP_GROUP);
    
    define_opcodes(0xF7,0,op_test,"test",OP_BITS32 | OP_RM_IMM | OP_IMM | OP_GROUP);
    define_opcodes(0xF7,1,op_test,"test",OP_BITS32 | OP_RM_IMM | OP_IMM | OP_GROUP);
    define_opcodes(0xF7,2,op_not,"not",OP_BITS32 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xF7,3,op_neg,"neg",OP_BITS32 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xF7,4,op_mul,"mul",OP_BITS32 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xF7,5,op_imul1,"imul",OP_BITS32 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xF7,6,op_div,"div",OP_BITS32 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xF7,7,op_idiv,"idiv",OP_BITS32 | OP_RM_ONLY | OP_GROUP);
    //-------------
    define_opcodes(0xFE,0,op_inc,"inc",OP_BITS8 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xFE,1,op_dec,"dec",OP_BITS8 | OP_RM_ONLY | OP_GROUP);
    //------------
    
    define_opcodes(0xFF,0,op_inc,"inc",OP_BITS32 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xFF,1,op_dec,"dec",OP_BITS32 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xFF,2,op_call,"call",OP_BITS32 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xFF,3,undefined_opcode,"call far",OP_BITS32 | OP_IMM_ONLY | OP_IMM | OP_GROUP);
    define_opcodes(0xFF,4,op_jcc,"jmp",OP_BITS32 | OP_RM_ONLY | OP_GROUP);
    define_opcodes(0xFF,5,undefined_opcode,"jmp far",OP_BITS32 | OP_IMM_ONLY | OP_IMM32 | OP_GROUP);
    define_opcodes(0xFF,6,op_push,"push",OP_BITS32 | OP_RM_ONLY | OP_GROUP);
    //----------------------------------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------------------------------
    // 2 Bytes Opcodes
    define_opcodes(0x80,0,op_jcc,"jo",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x81,0,op_jcc,"jno",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x82,0,op_jcc,"jb",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x82,0,op_jcc,"jnae",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x83,0,op_jcc,"jnb",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x83,0,op_jcc,"jae",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x84,0,op_jcc,"jz",OP_IMM32 | OP_IMM_ONLY | OP_0F);
    define_opcodes(0x84,0,op_jcc,"je",OP_IMM32 | OP_IMM_ONLY | OP_0F);
    define_opcodes(0x85,0,op_jcc,"jnz",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x85,0,op_jcc,"jne",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x86,0,op_jcc,"jbe",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x86,0,op_jcc,"jna",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x87,0,op_jcc,"jnbe",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x87,0,op_jcc,"ja",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x88,0,op_jcc,"js",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x89,0,op_jcc,"jns",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8A,0,op_jcc,"jp",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8A,0,op_jcc,"jpe",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8B,0,op_jcc,"jnp",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8B,0,op_jcc,"jpo",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8C,0,op_jcc,"jl",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8C,0,op_jcc,"jnge",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8D,0,op_jcc,"jnl",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8D,0,op_jcc,"jge",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8E,0,op_jcc,"jle",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8E,0,op_jcc,"jng",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8F,0,op_jcc,"jnle",OP_IMM32| OP_IMM_ONLY | OP_0F);
    define_opcodes(0x8F,0,op_jcc,"jg",OP_IMM32| OP_IMM_ONLY | OP_0F);
    //-------------------
    define_opcodes(0x90,0,op_setcc,"seto",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x91,0,op_setcc,"setno",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x92,0,op_setcc,"setb",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x92,0,op_setcc,"setc",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x92,0,op_setcc,"setnae",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x93,0,op_setcc,"setae",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x93,0,op_setcc,"setnb",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x93,0,op_setcc,"setnc",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x94,0,op_setcc,"sete",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x94,0,op_setcc,"setz",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x95,0,op_setcc,"setne",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x95,0,op_setcc,"setnz",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x96,0,op_setcc,"setbe",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x96,0,op_setcc,"setna",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x97,0,op_setcc,"seta",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x97,0,op_setcc,"setnbe",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x98,0,op_setcc,"sets",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x99,0,op_setcc,"setns",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x9A,0,op_setcc,"setp",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x9B,0,op_setcc,"setpo",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x9B,0,op_setcc,"setnp",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x9C,0,op_setcc,"setl",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x9C,0,op_setcc,"setnge",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x9D,0,op_setcc,"setge",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x9E,0,op_setcc,"setle",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x9E,0,op_setcc,"setng",OP_BITS8 | OP_RM_ONLY | OP_0F);
    define_opcodes(0x9F,0,op_setcc,"setg",OP_BITS8 | OP_RM_ONLY | OP_0F);
    //-------------------
    define_opcodes(0xC8,0,op_bswap,"bswap",OP_BITS32 | OP_REG_ONLY | OP_REG_EAX | OP_0F);
    define_opcodes(0xC9,0,op_bswap,"bswap",OP_BITS32 | OP_REG_ONLY | OP_REG_ECX | OP_0F);
    define_opcodes(0xCA,0,op_bswap,"bswap",OP_BITS32 | OP_REG_ONLY | OP_REG_EDX | OP_0F);
    define_opcodes(0xCB,0,op_bswap,"bswap",OP_BITS32 | OP_REG_ONLY | OP_REG_EBX | OP_0F);
    define_opcodes(0xCC,0,op_bswap,"bswap",OP_BITS32 | OP_REG_ONLY | OP_REG_ESP | OP_0F);
    define_opcodes(0xCD,0,op_bswap,"bswap",OP_BITS32 | OP_REG_ONLY | OP_REG_EBP | OP_0F);
    define_opcodes(0xCE,0,op_bswap,"bswap",OP_BITS32 | OP_REG_ONLY | OP_REG_ESI | OP_0F);
    define_opcodes(0xCF,0,op_bswap,"bswap",OP_BITS32 | OP_REG_ONLY | OP_REG_EDI | OP_0F);
    //-------------------
    define_opcodes(0x31,0,undefined_opcode,"rdtsc",OP_0F | OP_ANY);
    //-------------------
    define_opcodes(0xC0,0,op_xadd,"xadd",OP_RM_R | OP_BITS8 | OP_REG_ALL  | OP_0F );
    define_opcodes(0xC1,0,op_xadd,"xadd",OP_RM_R | OP_BITS32 | OP_REG_ALL | OP_0F );
    //--------------------
    define_opcodes(0xAF,0,op_imul2,"imul",OP_BITS32 | OP_R_RM | OP_0F | OP_REG_ALL);
    define_opcodes(0xB6,0,op_movzx,"movzx",OP_R_RM | OP_BITS32 | OP_REG_ALL  | OP_0F | OP_SRC8 );
    define_opcodes(0xB7,0,op_movzx,"movzx",OP_R_RM | OP_BITS32 | OP_REG_ALL | OP_0F | OP_SRC16);
    define_opcodes(0xBE,0,op_movsx,"movsx",OP_R_RM | OP_BITS32 | OP_REG_ALL  | OP_0F |OP_SRC8 );
    define_opcodes(0xBF,0,op_movsx,"movsx",OP_R_RM | OP_BITS32 | OP_REG_ALL | OP_0F | OP_SRC16);
    //--------------------
    //-------------------------------------------------------------------------------------------------
    //FPU 
    define_opcodes(0xDA,1,op_fimul,"fimul",OP_FPU | FPU_BITS32 | FPU_DEST_RM | FPU_DEST_ONLY | OP_GROUP);
    
    define_opcodes(0xDB,0,op_fild,"fild",OP_FPU | FPU_BITS32 | FPU_DEST_RM | FPU_DEST_ONLY | OP_GROUP);
    define_opcodes(0xDB,3,op_fistp,"fistp",OP_FPU | FPU_BITS32 | FPU_DEST_RM | FPU_DEST_ONLY | OP_GROUP);
    
    define_opcodes(0xDE,0xC0,op_faddp,"faddp",OP_FPU | FPU_BITS32 | FPU_DEST_STi | FPU_SRCDEST | OP_REG_ST0 | OP_GROUP);
    define_opcodes(0xDE,0xC1,op_faddp,"faddp",OP_FPU | FPU_BITS32 | FPU_DEST_STi | FPU_SRCDEST | OP_REG_ST1 | OP_GROUP);
    define_opcodes(0xDE,0xC2,op_faddp,"faddp",OP_FPU | FPU_BITS32 | FPU_DEST_STi | FPU_SRCDEST | OP_REG_ST2 | OP_GROUP);
    define_opcodes(0xDE,0xC3,op_faddp,"faddp",OP_FPU | FPU_BITS32 | FPU_DEST_STi | FPU_SRCDEST | OP_REG_ST3 | OP_GROUP);
    define_opcodes(0xDE,0xC4,op_faddp,"faddp",OP_FPU | FPU_BITS32 | FPU_DEST_STi | FPU_SRCDEST | OP_REG_ST4 | OP_GROUP);
    define_opcodes(0xDE,0xC5,op_faddp,"faddp",OP_FPU | FPU_BITS32 | FPU_DEST_STi | FPU_SRCDEST | OP_REG_ST5 | OP_GROUP);
    define_opcodes(0xDE,0xC6,op_faddp,"faddp",OP_FPU | FPU_BITS32 | FPU_DEST_STi | FPU_SRCDEST | OP_REG_ST6 | OP_GROUP);
    define_opcodes(0xDE,0xC7,op_faddp,"faddp",OP_FPU | FPU_BITS32 | FPU_DEST_STi | FPU_SRCDEST | OP_REG_ST7 | OP_GROUP);
    
    
	  return 0;
};
