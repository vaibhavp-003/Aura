/*======================================================================================
FILE				: MaxDisassem.h
ABSTRACT			: Part of AuAVPMScan.dll module. It is build using Open Source code
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Vilas Suvarnakar
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 12 Jul 2010
NOTES				: This module disasembles the binary code for scanning based on CPU Instruction without executing.
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "pch.h"
#include "disasm.h"
#include "Variables.h"
#define DLL_EXPORT		extern "C" __declspec(dllexport)



class CMaxDisassem{
public:
	CMaxDisassem();
	
	void ResetRegister();
	
	ulong	Disasm(char *src,ulong srcsize,ulong srcip, t_disasm *disasm,int disasmmode);
	void	InitializeData() ;

private:
	//Assemble	
	int		Checkcondition(int code,ulong flags);
	int		Decodeaddress(ulong addr,char *symb,int nsymb,char *comment);
	ulong	Disassembleback(char *block,ulong base,ulong size,ulong ip,int n);
	ulong	Disassembleforward(char *block,ulong base,ulong size,ulong ip,int n);
	int		Isfilling(ulong addr,char *data,ulong size,ulong align);
	
	void Memadr(int defseg,const char *descr,long offset,int dsize);
	void DecodeRG(int index,int datasize,int type);
	void DecodeST(int index,int pseudoop);
	void DecodeMX(int index);
	void DecodeNR(int index);
	void DecodeMR(int type);
	void DecodeSO(void) ;
	void DecodeXL(void);
	void DecodeIM(int constsize,int sxt,int type);
	void DecodeVX(void) ;
	void DecodeC1(void);
	void DecodeIA(void);
	void DecodeCR(int index);
	void DecodeDE(void);
	void DecodeDR(int index);
	void DecodeJF(void);
	void DecodeSG(int index);
	void DecodeRJ(ulong offsize,ulong nextip);
	int Get3dnowsuffix(void);
	//Assembly code
	void Scanasm(int mode);
	void Parseasmoperand(t_asmoperand *op);
#ifdef USE_ASSEMBLE
	int Assemble(char *cmd,ulong ip,t_asmmodel *model,int attempt, int constsize,char *errtext);
#endif

	//all varialbles was unique 
	//all varialbles was unique 
	int       ideal;                // Force IDEAL decoding mode
	int       lowercase;            // Force lowercase display
	int       tabarguments;         // Tab between mnemonic and arguments
	int       extraspace;           // Extra space between arguments
	int       putdefseg;            // Display default segments in listing
	int       showmemsize;          // Always show memory size
	int       shownear;             // Show NEAR modifiers
	int       shortstringcmds;      // Use short form of string commands
	int       sizesens;             // How to decode size-sensitive mnemonics
	int       symbolic;             // Show symbolic addresses in disasm
	int       farcalls;             // Accept far calls, returns & addresses
	int       decodevxd;            // Decode VxD calls (Win95/98)
	int       privileged;           // Accept privileged commands
	int       iocommand;            // Accept I/O commands
	int       badshift;             // Accept shift out of range 1..31
	int       extraprefix;          // Accept superfluous prefixes
	int       lockedbus;            // Accept LOCK prefixes
	int       stackalign;           // Accept unaligned stack operations
	int       iswindowsnt;          // When checking for dangers, assume NT

	char      *asmcmd;              // Pointer to 0-terminated source line
	int       scan;                 // Type of last scanned element
	int       prio;                 // Priority of operation (0: highest)
	char      sdata[TEXTLEN];       // Last scanned name (depends on type)
	long      idata;                // Last scanned value
	long      double fdata;         // Floating-point number
	char      *asmerror;            // Explanation of last error, or NULL

	// Work variables of disassembler
	ulong     datasize;             // Size of data (1,2,4 bytes)
	ulong     addrsize;             // Size of address (2 or 4 bytes)
	int       segprefix;            // Segment override prefix or SEG_UNDEF
	int       hasrm;                // Command has ModR/M byte
	int       hassib;               // Command has SIB byte
	int       dispsize;             // Size of displacement (if any)
	int       immsize;              // Size of immediate data (if any)
	int       softerror;            // Noncritical disassembler error
	int       ndump;                // Current length of command dump
	int       nresult;              // Current length of disassembly
	int       addcomment;           // Comment value of operand

	// Copy of input parameters of function Disasm()
	char      *cmd;                 // Pointer to binary data
	char      *pfixup;              // Pointer to possible fixups or NULL
	ulong     size;                 // Remaining size of the command buffer
	t_disasm  *da;                  // Pointer to disassembly results
	int       mode;                 // Disassembly mode (DISASM_xxx)
};