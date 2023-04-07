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
 
#pragma once
struct ins_disasm; 

//all emulation functions


int undefined_opcode(Thread&,ins_disasm*);
//math
int op_add(Thread&,ins_disasm*);
int op_or (Thread&,ins_disasm*);
int op_adc(Thread&,ins_disasm*);
int op_sbb(Thread&,ins_disasm*);
int op_and(Thread&,ins_disasm*);
int op_sub(Thread&,ins_disasm*);
int op_xor(Thread&,ins_disasm*);
int op_cmp(Thread&,ins_disasm*);
int op_test(Thread&,ins_disasm*);
int op_mov(Thread&,ins_disasm*);
int op_lea(Thread&,ins_disasm*);
int op_movzx(Thread&,ins_disasm*);
int op_movsx(Thread&,ins_disasm*);
//----------------
int op_inc(Thread&,ins_disasm*);
int op_dec(Thread&,ins_disasm*);
int op_not(Thread&,ins_disasm*);
int op_neg(Thread&,ins_disasm*);
//----------------
int op_xchg(Thread&,ins_disasm*);
int op_bswap(Thread&,ins_disasm*);
int op_xadd(Thread&,ins_disasm*);
int op_mul(Thread&,ins_disasm*);
int op_imul1(Thread&,ins_disasm*);
int op_imul2(Thread&,ins_disasm*);
int op_imul3(Thread&,ins_disasm*);
int op_div(Thread&,ins_disasm*);
int op_idiv(Thread&,ins_disasm*);
int op_cdq(Thread&,ins_disasm*);
//----------------
//stack
int op_push(Thread&,ins_disasm*);
int op_pop (Thread&,ins_disasm*);
int op_pushad(Thread&,ins_disasm*);
int op_popad (Thread&,ins_disasm*);
int op_pushfd(Thread&,ins_disasm*);
int op_popfd (Thread&,ins_disasm*);
int op_leave(Thread&,ins_disasm*);
int op_enter(Thread&,ins_disasm*);
//------------------
//jumps
int op_jcc (Thread&,ins_disasm*);
int op_setcc (Thread&,ins_disasm*);
int op_call(Thread&,ins_disasm*);
int op_ret (Thread&,ins_disasm*);
//--------------------
//strings
int op_lods(Thread&,ins_disasm*);
int op_stos(Thread&,ins_disasm*);
int op_movs(Thread&,ins_disasm*);
int op_cmps(Thread&,ins_disasm*);
int op_scas(Thread&,ins_disasm*);
//--------------------
//binary
int op_shl(Thread&,ins_disasm*);
int op_shr(Thread&,ins_disasm*);
int op_rol(Thread&,ins_disasm*);
int op_ror(Thread&,ins_disasm*);
int op_sar(Thread&,ins_disasm*);
int op_rcl(Thread&,ins_disasm*);
int op_rcr(Thread&,ins_disasm*);
//---------------------
//flags
int op_stc(Thread&,ins_disasm*);
int op_clc(Thread&,ins_disasm*);
//---------------------
//FPU
int op_faddp(Thread& thread,ins_disasm* s);
int op_fild(Thread& thread,ins_disasm* s);
int op_fistp(Thread& thread,ins_disasm* s);
int op_fimul(Thread& thread,ins_disasm* s);

int op_add83(Thread&,ins_disasm*);
int op_or83 (Thread&,ins_disasm*);
int op_adc83(Thread&,ins_disasm*);
int op_sbb83(Thread&,ins_disasm*);
int op_and83(Thread&,ins_disasm*);
int op_sub83(Thread&,ins_disasm*);
int op_xor83(Thread&,ins_disasm*);
