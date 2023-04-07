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
 #ifndef __EMU__
 #define __EMU__

typedef unsigned long dword;

#define EXP_IGNORE 0
#define EXP_ERROR  -1
class Process;
class Log; 
class Thread;
//#if BUILDING_DLL
#include "hde28c/hde32.h"
#include "disasm/disassembler.h"
#include "apis/apis.h"
#include "emu/emu.h"
#include "seh.h"
#include "os/os.h"
#include "macros.h"
#include "MaxPEFile.h"
//#endif
//------
#include "tib.h"
#include "pe.h"
#include <iostream>
#include <string.h>
#include <string>
#include <winbase.h>

extern "C" int __stdcall CheckBreakPoint(MAX_DWORD mem, MAX_DWORD a, MAX_DWORD c, int *p);
extern "C" int __stdcall SetCarry();
extern "C" int __stdcall ReSetCarry();

//Flags
#define EFLG_OF (1<<11)
#define EFLG_SF (1<<7) 
#define EFLG_ZF (1<<6)
#define EFLG_AF (1<<4)
#define EFLG_PF (1<<2)
#define EFLG_CF (1<<0)
#define EFLG_SYS (0x202)
//-------
//CUSTOM FLAGS SETTING
#define UPDATEFLAGS_CMP 1
#define UPDATEFLAGS_ADD 2
#define UPDATEFLAGS_SUB 4
//------
//MEMORY FLAGS

#define MEM_READWRITE 0
#define MEM_READONLY 1
#define MEM_IMAGEBASE 2             //mixing readonly & readwrite so it needs to be check
#define MEM_DLLBASE 3
#define MEM_VIRTUALPROTECT 4
//--------
//EXCEPTIONS

#define EXP_EXCEED_MAX_ITERATIONS 0
#define EXP_INVALIDPOINTER 1
#define EXP_WRITEACCESS_DENIED 2
#define EXP_INVALID_OPCODE 3
#define EXP_DIVID_BY_ZERO 4
#define EXP_INVALID_INSTRUCTION 5
#define EXP_DIV_OVERFLOW 6
#define EXP_BREAKPOINT 7

#define ERROR_FILENAME 8
using namespace std;
#ifdef WIN32
#if BUILDING_DLL
    # define DLLIMPORT __declspec (dllexport)
#else /* Not BUILDING_DLL */
    # define DLLIMPORT __declspec (dllimport)
#endif /* Not BUILDING_DLL */
 #else
    #define DLLIMPORT
  #endif


struct ins_disasm;
struct bytes;
struct FLAGTABLE;
struct hde32s;
struct DLL;
struct API;
//==================================
//APIs
struct DLL{
       wchar_t*		name;
       MAX_DWORD	imagebase;
       dword		size;
	   MAX_DWORD	vAddr;
};
struct API{
       wchar_t* name;
       DLL*  lib;
       dword args;
       MAX_DWORD addr;
       int (*emu_func)(Thread*,dword*);
};
//===================================
//Debugger 

#define NO_OF_BP_FUNCTIONS 100
#define BP_RUN 0
#define BP_PAUSE 1
#define BP_REMOVE 2
struct BPFunction{ 
           int params;
           MAX_DWORD dbg_func;
           string name;
           int flags;
};

bool FreeTable();

//===================================
struct FLAGTABLE{ 
           int opcode;
           int reg;
           int (*emu_func)(Thread&,ins_disasm*);
           string mnemonics;
           int flags;
           };
struct Exception{
       int Type;
       char* error;
       dword ptr;
       };

struct EnviromentVariables
{
       dword	date;
       dword	time;

	   MAX_DWORD kernel32;
       MAX_DWORD ntdll;
       MAX_DWORD user32;

       wchar_t* dllspath;
       dword	MaxIterations;
};
#define MAX_NUM_APIS_PER_DLL 200
struct Imports{
       dword name;
       dword addr;
       bool defined;
       dword napis;
       dword apis[MAX_NUM_APIS_PER_DLL];                              //Maximum Number of Apis is 300 per 1 DLL
};
class System{
      public:
          int dis_entries;
          FLAGTABLE FlagTable[512*7];
          DLL DLLs[20];
          API APITable[100];
          int dll_entries;
          int api_entries;
          EnviromentVariables enVars;
          System(EnviromentVariables* v);
          System();
          ~System();
          string getversion();
          string getCopyrights();
          // Assembler
          bytes* assembl(string instruction);
          ins_disasm* disasm(ins_disasm* bIns,char* ins_bytes);
          ins_disasm* disasm(ins_disasm* bIns,char* ins_bytes,string& str);
          int define_opcodes(int opcode,int reg,int (*emu_func)(Thread&,ins_disasm*),string mnemonics,int flags);
          int opcodes_init();
          int init_vars(EnviromentVariables* v);
          //APIs
          int define_dll(wchar_t* name, wchar_t* path, MAX_DWORD vAddr);
          int define_api(wchar_t* name,DLL* lib,dword args,int (*emu_func)(Thread*,dword*));
          bool IsApiCall(Thread&,ins_disasm*&);
          int CallToAPI(Thread*,ins_disasm*);
          MAX_DWORD GetAPI(wchar_t* func, MAX_DWORD dll);
          char* GetAPIbyAddress(unsigned long ptr,unsigned long dll);
          MAX_DWORD GetDllBase(wchar_t*);
          unsigned long GetDllIndex(wchar_t* s);
          char* GetTiggeredAPI(Thread& thread);
          int init_apis(wchar_t* path);
};
class Debugger{
protected:
    struct {
             MAX_DWORD ptr;
             int state;
      } bp[1000];
      dword nbp;
      Process* process;
      BPFunction funcs[NO_OF_BP_FUNCTIONS];
      int func_entries;
      dword parser(string);
      string lasterror;
public:
     
     virtual bool TestBp(Thread& thread,ins_disasm* ins);
     virtual int AddBp(string s);
	 virtual int ModifiedBp(string s, DWORD n);

     void RemoveBp(DWORD index);
     void PauseBp(DWORD index);
     void ActivateBp(DWORD index);
     int define_func(string name,int params,MAX_DWORD func,int flags);
     int init_funcs();
     Debugger(Process&);
     Debugger();
     virtual ~Debugger();
     string GetLastError();
private:
    bool TestBp(int num,Thread& thread,ins_disasm* ins);
};
class AsmDebugger : public Debugger{
      MAX_DWORD parser(string);
      public:
             virtual bool TestBp(Thread& thread,ins_disasm* ins);
             virtual int AddBp(string s);
             virtual int ModifiedBp(string s, DWORD n);
             AsmDebugger(Process&);
             ~AsmDebugger();
      private:
            bool TestBp(int num,Thread& thread,ins_disasm* ins);
            //expressions solvers
            dword boolexp(string&);
            dword boolexp2(string&);
            dword mathexp(string&);
            dword mulexp(string&);
            dword getnum(string&);
            //math
            dword domul(string&);
            dword dodiv(string&);
            dword doand(string&);
            dword domod(string&);
            dword doadd(string&);
            dword dosub(string&);
            dword door(string&);
            dword doxor(string&);
            dword donot(string&);
            dword doneg(string&);
            //boolean
            dword dogreaterequal(string&);
            dword dolowerequal(string&);
            dword doequal(string&);
            dword donotequal(string&);
            dword dogreater(string&);
            dword dolower(string&);
            dword doandbool(string&);
            dword doorbool(string&);
            //Variables
            dword doreg32(int);
            //functions
            dword callfunc(string&);
            dword strfunc(string&);
            //---
            void add_to_buffer(bytes*);
      };
class VirtualMemory{
      struct vMem{
             dword vmem;
             MAX_DWORD rmem;
             dword size;
             dword flags;
             };    
      struct cMem{          //the changes in the memory during the emulation
             dword ptr;     //here the pointer to the virtual memory not the real pointer
             dword size;
             dword flags;
             };
      Log* last_accessed;
      Log* last_modified;
      public:
             dword CommittedPages;
             int vmem_length;
             int cmem_length;
             vMem** vmem;
             cMem** cmem;
             VirtualMemory ();
             ~VirtualMemory ();
             dword get_virtual_pointer(MAX_DWORD ptr);
             MAX_DWORD* read_virtual_mem(dword ptr);
             dword write_virtual_mem(dword ptr,dword size,char* buff); //ptr , size, buff -return-> valid or not
             bool get_memory_flags(dword ptr);
             dword set_memory_flags(dword ptr,int size);
             dword get_last_accessed(int index);
             dword get_last_modified(int index);
             dword add_pointer(MAX_DWORD rptr,dword vptr,dword size,int=MEM_READWRITE);
             dword delete_pointer(dword ptr);
             bool check_writeaccess(dword ptr,dword imagebase);
			 MAX_DWORD* read_file_mem(dword ptr);
      };


class Stack{
      Thread* thread;
      public:
             dword stackTop;
             dword stackBottom;
             Stack(Thread&);
             int push(dword);
             int pop();
      };
class Thread{
      TIB* tib;
      TEB* teb;
      dword fs;
      bool seh_enable;
      
      dword entry_point;
      dword tls_callback_index;
      public:
             class Process* process;
             Log* log;
             Stack* stack;
             VirtualMemory* mem;
             dword EFlags;
             dword Eip;
             bool still_tls;
             dword Exx[8];
             double ST[8];
             dword GetFS();
             Process* GetProcess();
             int updateflags(dword,dword,dword,int,dword);
             void generateException(dword code);
             int doException(dword rec);
             void sehReturn();
             void TLSContinue();
             Thread(dword,Process&);
             Thread();
             ~Thread();
             void CreateTEB();
			 BOOL UpdateSpecifyRegister(DWORD dwRegIndex, DWORD dwNewValue);
             ///*
             dword FPUControlWord; //(FCW)
             dword FPUStatusWord; //(FST)
             dword FPUTagWord;
             dword FPUDataPointer;
             dword FPUInstructionPointer;
             dword FPULastInstructionOpcode;
             
             int SelectedReg;               //the reg that will be the next to push in 
             //*/
      friend class Process;
      };

class Process {
      private:
              System* sys;
              Thread* threads[100];
              int nthreads;
              int error;
              int Imagebase;
              int ImportTableFixup(MAX_DWORD);
			  int APIsFixup(MAX_DWORD, image_import_descriptor*, MAX_DWORD);
              void CreatePEB();
              bool TiggeredBreakpoint;
      public:
			  bool m_bHandleAPIs;
             ins_disasm* ins;
			 string strInstName;
             bool IsDLL;
             dword MaxIterations;
             dword nimports;
             Imports* imports[20];
             PEB* peb;
             Debugger* debugger;
             VirtualMemory* SharedMem;
			 MAX_DWORD m_dwEmulatorFileSize;

             System* getsystem();
             int emulate(bool bCheckSecondBP);
             int emulate(string);
             int emulatecommand(int);
             int emulatecommand();
             int CreateThread(dword);
             Thread* GetThread(int);
             int GetNumOfThreads(){return nthreads;};
             ins_disasm* GetLastIns();
             dword GetImagebase();
             dword SkipIt();
             Process (System* sys, CMaxPEFile *pobjMaxPEFile, bool bHandleAPIs);
             ~Process();
      };
class Log {
      private:
              dword log[10];
              int cur;
      public:
             Log(dword);
             void addlog(dword);
             dword getlog(int);
      };
//strings
int compare_array(string,string[],int);
int compare_array(string,string[],int,int);
string to_lower_case(string);
wstring to_lower_case(wstring);
string trim(string); 
int  imm_to_dec(string);
wstring convert_a2w(string str);
string convert_w2a(wstring wstr);
wstring convert_cptr2w(const char * str);
string convert_wcptr2s(const wchar_t * wstr);
char* convert_wcptr2cptr(const wchar_t * wstr, char * str, DWORD cbstr);
wchar_t* convert_cptr2wcptr(const char * str, wchar_t * wstr, DWORD cchwstr);
//important functions

MAX_DWORD PELoader(CMaxPEFile *pobjMaxPEFile, MAX_DWORD &dwEmulatorFileSize);
MAX_DWORD PELoader(wstring filename);
dword PEDump(dword Eip,Process* c,wchar_t* filename);
dword FindAPI(Process* c,dword ApiName,dword DllHandle,dword napi,dword ndll,bool defined);
dword ReconstructImportTable(Process* c);
dword UnloadImportTable(Process* c);
dword modrm_calc(Thread&,ins_disasm*);
//==========================================
// Hacker Disassmbler Engine
#ifndef _HDE32_H_
#define _HDE32_H_
#include "pstdint.h"

#define F_MODRM         0x00000001
#define F_SIB           0x00000002
#define F_IMM8          0x00000004
#define F_IMM16         0x00000008
#define F_IMM32         0x00000010
#define F_DISP8         0x00000020
#define F_DISP16        0x00000040
#define F_DISP32        0x00000080
#define F_RELATIVE      0x00000100
#define F_2IMM16        0x00000800
#define F_ERROR         0x00001000
#define F_ERROR_OPCODE  0x00002000
#define F_ERROR_LENGTH  0x00004000
#define F_ERROR_LOCK    0x00008000
#define F_ERROR_OPERAND 0x00010000
#define F_PREFIX_REPNZ  0x01000000
#define F_PREFIX_REPX   0x02000000
#define F_PREFIX_REP    0x03000000
#define F_PREFIX_66     0x04000000
#define F_PREFIX_67     0x08000000
#define F_PREFIX_LOCK   0x10000000
#define F_PREFIX_SEG    0x20000000
#define F_PREFIX_ANY    0x3f000000

#define PREFIX_SEGMENT_CS   0x2e
#define PREFIX_SEGMENT_SS   0x36
#define PREFIX_SEGMENT_DS   0x3e
#define PREFIX_SEGMENT_ES   0x26
#define PREFIX_SEGMENT_FS   0x64
#define PREFIX_SEGMENT_GS   0x65
#define PREFIX_LOCK         0xf0
#define PREFIX_REPNZ        0xf2
#define PREFIX_REPX         0xf3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

#endif

#pragma pack(push,1)

 struct hde32sexport
 {
    uint8_t len;
    uint8_t p_rep;
    uint8_t p_lock;
    uint8_t p_seg;
    uint8_t p_66;
    uint8_t p_67;
    uint8_t opcode;
    uint8_t opcode2;
    uint8_t modrm;
    uint8_t modrm_mod;
    uint8_t modrm_reg;
    uint8_t modrm_rm;
    uint8_t sib;
    uint8_t sib_scale;
    uint8_t sib_index;
    uint8_t sib_base;
    union {
        uint8_t imm8;
        uint16_t imm16;
        uint32_t imm32;
    } imm;
    union {
        uint8_t disp8;
        uint16_t disp16;
        uint32_t disp32;
    } disp;
    uint32_t flags;
};
#pragma pack(pop)
//==============================
//Disassembler

//the register flags

#define OP_REG_EAX 0x00000001
#define OP_REG_ECX 0x00000002
#define OP_REG_EDX 0x00000004
#define OP_REG_EBX 0x00000008
#define OP_REG_ESP 0x00000010
#define OP_REG_EBP 0x00000020
#define OP_REG_ESI 0x00000040
#define OP_REG_EDI 0x00000080

//FPU Registers

#define OP_REG_ST0 0x00000001
#define OP_REG_ST1 0x00000002
#define OP_REG_ST2 0x00000003
#define OP_REG_ST3 0x00000004
#define OP_REG_ST4 0x00000005
#define OP_REG_ST5 0x00000006
#define OP_REG_ST6 0x00000007
#define OP_REG_ST7 0x00000008

//for all registers
#define OP_REG_ALL 0x000000FF
#define OP_REG_ALL_EXP_EAX 0x000000FE

//Opcode States
#define OP_IMM8     0x00000100
#define OP_IMM32    0x00000200
#define OP_IMM      0x00000300        //IMM8 or IMM32 
#define OP_BITS8    0x00000400 
#define OP_BITS32   0x00000800
#define OP_RM_R     0x00001000        //Eb,Gb or Ev,Gv
#define OP_R_RM     0x00002000        //Gb,Eb or Gv,Ev
#define OP_RM_IMM   0x00004000        //Eb,Ib
#define OP_R_IMM    0x00008000        //Gb,Ib
#define OP_REG_EXT  0x00010000        //reg used as an opcode extention
#define OP_REG_ONLY 0x00020000       // like inc or dec
#define OP_RM_ONLY  0x00040000
#define OP_IMM_ONLY 0x00080000       // for push & pop
#define OP_RM_DISP  0x00100000        //disp only
#define OP_GROUP    0x00200000
#define OP_LOCK     0x00400000
#define OP_0F       0x00800000        //for 2 bytes opcode
#define OP_SRC8     0x01000000        //for movzx
#define OP_SRC16    0x02000000        //for movzx
#define OP_ANY      0x04000000        //no source and no destination
#define OP_FPU      0x08000000        //FPU Instructions
#define OP_UNUSED   0x10000000        //ignored entry in the FlagTables

//Assembler states
#define NO_SRCDEST  0x80000000         // no opcodes     

#define DEST_REG    0x00000100
#define DEST_RM     0x00000200
#define DEST_IMM    0x00000400        //IMM8 or IMM32 
#define DEST_BITS32 0x00000800
#define DEST_BITS16 0x00001000
#define DEST_BITS8  0x00002000

#define SRC_REG     0x00004000
#define SRC_NOSRC   0x00008000
#define SRC_RM      0x00010000
#define SRC_IMM     0x00020000        //IMM8 or IMM32 
#define SRC_BITS32  0x00040000
#define SRC_BITS16  0x00001000        //the same as  DEST_BITS16
#define SRC_BITS8   0x00080000

#define RM_SIB      0x00100000       // it will not differ dest or src because it should be one rm
#define INS_UNDEFINED 0x00200000    //for the disasembler only
#define INS_INVALID 0x00400000       //invalid instruction (returned by hde32) 
#define MOVXZ_SRC16 0x00800000
#define MOVXZ_SRC8  0x01000000
#define EIP_UPDATED 0x02000000
#define API_CALL    0x04000000
//ModRM states
#define RM_REG      0x00000001
#define RM_DISP8    0x00000002
#define RM_DISP16   0x00000004
#define RM_DISP32   0x00000008
#define RM_DISP     0x00000010
#define RM_MUL2     0x00000020
#define RM_MUL4     0x00000040
#define RM_MUL8     0x00000080
#define RM_ADDR16   0x00000100

//FPU States

#define FPU_NULL        0x00000100       //no source or destinaion
#define FPU_DEST_ONLY   0x00000200       // Destination only 
#define FPU_SRCDEST     0x00000400        // with source and destination
#define FPU_DEST_ST     0x00000800        // destination == ST0
#define FPU_SRC_STi     0x00000800        // source == STi (the same as before)
#define FPU_DEST_STi    0x00001000        // destination == STi
#define FPU_SRC_ST      0x00001000        // source == ST0 (the same as before)
#define FPU_DEST_RM     0x00002000        // destination is RM
#define FPU_MODRM       0x00002000        // destination is RM & there's a ModRM
#define FPU_BITS32      0x00004000        
#define FPU_BITS16      0x00008000        



struct ins_disasm{
          hde32sexport hde;
          int entry;                 //the index of this opcode in the FlagTable
          string* opcode;
          int ndest;
          int nsrc;
          int other;      //used for mul to save the imm and used for any call to api to save the index of the api(it's num in APITable)
          struct {
                 int length;
                 int items[3];
                 int flags[3];
          } modrm;
          int (*emu_func)(Thread&,ins_disasm*);
          int flags;
    };
  //assembler & disassembler
   struct bytes {
           int length;
           char s[20];
   };

void* malloc_emu(size_t size);
void free_emu(void* ptr);
void* realloc_emu(void* ptr, size_t size);

/*
#ifdef WIN32
  #ifdef EXPORT_CLASS_FOO
    #define CLASS_FOO __declspec(dllexport)    //while building the dll
  #else
    #define CLASS_FOO __declspec(dllimport)    //while use the dll
  #endif
#else
  #define CLASS_FOO
#endif

class CLASS_Foo foo
{ ... };
//*/
#endif
