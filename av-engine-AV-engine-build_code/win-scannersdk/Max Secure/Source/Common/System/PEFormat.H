/*=============================================================================
   FILE			: PEFormat.h.cpp
   DESCRIPTION	: PE Haeder Structures
   DOCUMENTS	: 
   AUTHOR		: Davies
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 17 Aug 2007
   NOTES		:
VERSION HISTORY	: 
============================================================================*/
#pragma once

#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00

typedef struct _PMS_IMAGE_DOS_HEADER
{											 // DOS.EXE header
	unsigned short int   e_magic;                     // Magic number
	unsigned short int   e_cblp;                      // Bytes on last page of file
	unsigned short int   e_cp;                        // Pages in file
	unsigned short int   e_crlc;                      // Relocations
	unsigned short int   e_cparhdr;                   // Size of header in paragraphs
	unsigned short int   e_minalloc;                  // Minimum extra paragraphs needed
	unsigned short int   e_maxalloc;                  // Maximum extra paragraphs needed
	unsigned short int   e_ss;                        // Initial (relative)SS value
	unsigned short int   e_sp;                        // Initial SP value
	unsigned short int   e_csum;                      // Checksum
	unsigned short int   e_ip;                        // Initial IP value
	unsigned short int   e_cs;                        // Initial (relative)CS value
	unsigned short int   e_lfarlc;                    // File address of relocation table
	unsigned short int   e_ovno;                      // Overlay number
	unsigned short int   e_res[4];                    // Reserved words
	unsigned short int   e_oemid;                     // OEM identifier (for e_oeminfo)
	unsigned short int   e_oeminfo;                   // OEM information; e_oemid specific
	unsigned short int   e_res2[10];                  // Reserved words
	signed long int		e_lfanew;                    // File address of new exe header
} PMS_IMAGE_DOS_HEADER;

typedef struct _PMS_IMAGE_FILE_HEADER
{
	unsigned short int   Machine;
	unsigned short int   NumberOfSections;
	unsigned long int	TimeDateStamp;
	unsigned long int	PointerToSymbolTable;
	unsigned long int	NumberOfSymbols;
	unsigned short int   SizeOfOptionalHeader;
	unsigned short int   Characteristics;
} PMS_IMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER             20

typedef struct _PMS_IMAGE_DATA_DIRECTORY
{
	unsigned long int   VirtualAddress;
	unsigned long int   Size;
} PMS_IMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _PMS_IMAGE_OPTIONAL_HEADER
{
	unsigned short int   Magic;
	unsigned char		MajorLinkerVersion;
	unsigned char		MinorLinkerVersion;
	unsigned long int	SizeOfCode;
	unsigned long int	SizeOfInitializedData;
	unsigned long int	SizeOfUninitializedData;
	unsigned long int	AddressOfEntryPoint;
	unsigned long int	BaseOfCode;
	unsigned long int	BaseOfData;

	//
	// NT additional fields.
	//

	unsigned long int	ImageBase;
	unsigned long int	SectionAlignment;
	unsigned long int	FileAlignment;
	unsigned short int   MajorOperatingSystemVersion;
	unsigned short int   MinorOperatingSystemVersion;
	unsigned short int   MajorImageVersion;
	unsigned short int   MinorImageVersion;
	unsigned short int   MajorSubsystemVersion;
	unsigned short int   MinorSubsystemVersion;
	unsigned long int	Win32VersionValue;
	unsigned long int	SizeOfImage;
	unsigned long int	SizeOfHeaders;
	unsigned long int	CheckSum;
	unsigned short int   Subsystem;
	unsigned short int   DllCharacteristics;
	unsigned long int	SizeOfStackReserve;
	unsigned long int	SizeOfStackCommit;
	unsigned long int	SizeOfHeapReserve;
	unsigned long int	SizeOfHeapCommit;
	unsigned long int	LoaderFlags;
	unsigned long int	NumberOfRvaAndSizes;
	PMS_IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} PMS_IMAGE_OPTIONAL_HEADER;

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _PMS_IMAGE_SECTION_HEADER
{
	unsigned char   Name[IMAGE_SIZEOF_SHORT_NAME];
	union	{
		unsigned long int   PhysicalAddress;
		unsigned long int   VirtualSize;
	} Misc;
	unsigned long int   VirtualAddress;
	unsigned long int   SizeOfRawData;
	unsigned long int   PointerToRawData;
	unsigned long int   PointerToRelocations;
	unsigned long int   PointerToLinenumbers;
	unsigned short int  NumberOfRelocations;
	unsigned short int  NumberOfLinenumbers;
	unsigned long int   Characteristics;
} PMS_IMAGE_SECTION_HEADER;

typedef struct _LE_HEADER
{
	unsigned char			Signature[2];
	unsigned char			UnusedBuf1[22];
	unsigned long int     	EIPObjectNo;
	unsigned long int		EIP;
	unsigned long int     	ESPObjectNo;
	unsigned long int		ESP;
	unsigned long int		PageSize;
	unsigned char			UnusedBuf2[20];
	unsigned long int		ObjectTableOffset;
	unsigned long int		NoOfObjects;
	unsigned char			UnusedBuf3[56];
	unsigned long int		DataPagesOffset;
}LEHEADER;

typedef struct _LE_OBJECT_TABLE_ENTRY
{
	unsigned long int	   	VirtualSize;
	unsigned long int		BaseAddress;
	unsigned long int		Flags;
	unsigned long int		PageTableIndex;
	unsigned long int		NoOfPageTableEntries;
	unsigned long int		Reserved;
}LE_OBJECT_TABLE_ENTRY;

typedef struct _PMS_IMAGE_NT_HEADERS {
	unsigned long int Signature;
	PMS_IMAGE_FILE_HEADER FileHeader;
	PMS_IMAGE_OPTIONAL_HEADER OptionalHeader;
} PMS_IMAGE_NT_HEADERS;

typedef struct _PMS_IMAGE_DEBUG_DIRECTORY {
	unsigned long int	Characteristics;
	unsigned long int	TimeDateStamp;
	unsigned short int  MajorVersion;
	unsigned short int  MinorVersion;
	unsigned short int  Type;
	unsigned long int	SizeOfData;
	unsigned long int   AddressOfRawData;
	unsigned long int   PointerToRawData;
} PMS_IMAGE_DEBUG_DIRECTORY;

typedef struct _PMS_IMAGE_IMPORT_DIRECTORY_TABLE {
	unsigned long int	ImportNameTableRVA;
	unsigned long int	TimeDateStamp;
	unsigned long int	ForwardChain;
	unsigned long int	NameRVA;
	unsigned long int	ImportAddressTableRVA;
} PMS_IMAGE_IMPORT_DIRECTORY_TABLE;
