/*======================================================================================
FILE				: MaxELF.h
ABSTRACT			: Scanner for File Type : ELF Files
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 22-Apr-2010
NOTES				: This class module keeps the information of virus names identifiers of signature loaded in memory.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#include "MaxPEFile.h"

const int ELF_BUFF_SIZE = 0x1000;

typedef struct ELF_HEADER_STRUCT
{
	DWORD ELF_MAGIC;
	BYTE ELF_CLASS;
	BYTE ELF_DATA;
	BYTE ELF_EIVERSION;
	BYTE ELF_OSABI;
	ULONG64 ELF_OSABIVER;
	WORD ELF_TYPE;
	WORD ELF_MACHINE;
	DWORD ELF_VER;
	DWORD ELF_ENTRY;//AEP
	DWORD ELF_PROG_HEADER_OFF;//Offset to the Program header
	DWORD ELF_SECTION_HEADER_OFFSET;//offset to section header table
	DWORD ELF_FLAGS;//check
	WORD  ELF_HEADER_SIZE;
	WORD  ELF_PROGHEADER_ELE_SIZE;//size of an entry in program header
	WORD  ELF_PNO_OF_ELE;//Total number of entries in program header
	WORD  ELF_SECHEADER_ELE_SIZE;//size of entry in section header
	WORD  ELF_SNO_OF_ELE;//total number of entries in section header
	WORD  ELF_SHEADER_STR_INDX;//
}ELF_HEADER;

typedef struct ELF_PROGRAM_HEADER
{
	DWORD P_TYPE;
	DWORD P_OFFSET;
	DWORD P_VADDR;
	DWORD P_PADDR;
	DWORD P_FILESZ;
	DWORD P_MEMSZ;
	DWORD P_FLAGS;
	DWORD P_ALIGN;

}PROGRAM_HEADER;

typedef struct
{
	DWORD SH_NAME;
	DWORD SH_TYPE;
	DWORD SH_FLAGS;
	DWORD SH_ADDR;
	DWORD SH_OFFSET;
	DWORD SH_SIZE;
	DWORD SH_LINK;
	DWORD SH_INFO;
	DWORD SH_ADDRALIGN;
	DWORD SH_ENTSIZE;

}SECTION_HEADER;

class CMaxELF
{
	PROGRAM_HEADER *m_pProgHeader;
	SECTION_HEADER *m_pSecHeader;
	ELF_HEADER		m_stFileHeader;
	DWORD	NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer);

public:
	CMaxELF();
	~CMaxELF();
	
	bool IsValidELFFile(CMaxPEFile *pMaxPEFile);
	bool ConvertBEFileHeaderToLE();
	bool ConvertBEProgramHeaderToLE();
	bool ConvertBESectionHeaderToLE();
	bool GetBuffer(LPBYTE byBuffer, DWORD& cbBuffer, CMaxPEFile *pMaxPEFile);
	bool GetFileBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD& cbBufSize, DWORD& dwNormalisedBUfSize, CMaxPEFile *pMaxPEFile);
};