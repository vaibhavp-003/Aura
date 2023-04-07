#pragma once
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


#define byte char

#define SEH_MAGIC 0xBBBBBBBB

#define SIZEOF_387_REGS      80
#define MAXIMUM_EXTENSION    512

//Some exception codes

//Read or write memory violation
#define MEM_ACCESS 0xC0000005   

//Divide by zero
#define DIV_ZERO_EXCEPTION 0xC0000094   

//Divide overflow
#define DIV_OFLOW 0xC0000095   

//The stack went beyond the maximum available size
#define STACK_OVERFLOW 0xC00000FD   

//Violation of a guard page in memory set up using Virtual Alloc
#define GUARD_ERROR 0x80000001   


#define CONTINUABLE 0
#define NON_CONTINUABLE 1
#define STACK_UNWINDING 2

#define MAXIMUM_PARMS 15

struct EMU_EXCEPTION_RECORD {
   dword exceptionCode;
   dword exceptionFlags;
   dword exceptionRecord;  //struct _EXCEPTION_RECORD *ExceptionRecord
   dword exceptionAddress;
   dword numberParameters;
   dword exceptionInformation[MAXIMUM_PARMS];
};

struct EMU_EXCEPTION_POINTERS {
   EMU_EXCEPTION_RECORD *exceptionRecord;
   CONTEXT *contextRecord;
};

struct ERR {
   dword nextErr;  //struct _ERR *nextErr;
   dword handler;  //pointer to handler
}; 

#define MAXIMUM_SUPPORTED_EXTENSION     512
#define SIZE_OF_80387_REGISTERS      80

typedef struct MAX_FLOATING_SAVE_AREA {
    DWORD   ControlWord;
    DWORD   StatusWord;
    DWORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
    DWORD   Cr0NpxState;
} MAX_FLOATING_SAVE_AREA;

typedef MAX_FLOATING_SAVE_AREA *MAX_PFLOATING_SAVE_AREA;

typedef struct MCONTEXT {

    //
    // The flags values within this flag control the contents of
    // a CONTEXT record.
    //
    // If the context record is used as an input parameter, then
    // for each portion of the context record controlled by a flag
    // whose value is set, it is assumed that that portion of the
    // context record contains valid context. If the context record
    // is being used to modify a threads context, then only that
    // portion of the threads context will be modified.
    //
    // If the context record is used as an IN OUT parameter to capture
    // the context of a thread, then only those portions of the thread's
    // context corresponding to set flags will be returned.
    //
    // The context record is never used as an OUT only parameter.
    //

    DWORD ContextFlags;

    //
    // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
    // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
    // included in CONTEXT_FULL.
    //

    DWORD   Dr0;
    DWORD   Dr1;
    DWORD   Dr2;
    DWORD   Dr3;
    DWORD   Dr6;
    DWORD   Dr7;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
    //

    MAX_FLOATING_SAVE_AREA FloatSave;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_SEGMENTS.
    //

    DWORD   SegGs;
    DWORD   SegFs;
    DWORD   SegEs;
    DWORD   SegDs;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_INTEGER.
    //

    DWORD   Edi;
    DWORD   Esi;
    DWORD   Ebx;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_CONTROL.
    //

    DWORD   Ebp;
    DWORD   Eip;
    DWORD   SegCs;              // MUST BE SANITIZED
    DWORD   EFlags;             // MUST BE SANITIZED
    DWORD   Esp;
    DWORD   SegSs;

    //
    // This section is specified/returned if the ContextFlags word
    // contains the flag CONTEXT_EXTENDED_REGISTERS.
    // The format and contexts are processor specific
    //

    BYTE    ExtendedRegisters[512];

} MAX_CONTEXT;

typedef MAX_CONTEXT *MAX_PCONTEXT;

