/*======================================================================================
FILE             : MacStruct.h
ABSTRACT         : Collection of all MAC related binary structures
DOCUMENTS	     : 
AUTHOR		     : Tushar Kadam
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				without the prior written permission of Aura.	

CREATION DATE    : 07/2/2011 6:53:00 PM
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/
#pragma once

/********************* MAC UNIVERSAL BINARY FILE *********************/
typedef struct _fat_header
{
	DWORD 	magic;
	DWORD	nfat_arch; //No. of FAT_ARCH Structures
}FAT_HEADER,*LPFAT_HEADER;	

typedef struct _fat_arch
{
	DWORD	cputype;
	DWORD	cpusubtype;
	DWORD	offset; //Starting offset of the File
	DWORD	size; //Size of the File
	DWORD	align;
}FAT_ARCH,*LPFAT_ARCH;


/********************* MAC-O BINARY FILE *********************/
typedef struct _mac_header_32
{
	DWORD	magic;
	DWORD	cputype;
	DWORD	cpusubtype;
	DWORD	filetype;
	DWORD	ncmds;
	DWORD	sizeofcmds;
	DWORD	flags;
}MAC_HEADER_32,*LPMAC_HEADER_32;

typedef struct _mac_load_command
{
	DWORD	cmd;
	DWORD	cmdsize;
	DWORD	offset;
}MAC_LOAD_COMMAND,*LPMAC_LOAD_COMMAND;

typedef struct _mac_segment_command_32
{
	DWORD	cmd;
	DWORD	cmdsize;
	char	segname[16];
	DWORD	vmaddr;
	DWORD	vmsize;
	DWORD	fileoff;
	DWORD	filesize;
	DWORD	maxprot;
	DWORD	initprot;
	DWORD	nsects;
	DWORD	flags;
}MAC_SEGMENT_COMMAND_32,*LPMAC_SEGMENT_COMMAND_32;

typedef struct _mac_section_32
{
	char		sectname[16];
	char		segname[16];
	DWORD	addr;
	DWORD	size;
	DWORD	offset;
	DWORD	align;
	DWORD	reloff;
	DWORD	nreloc;
	DWORD	flags;
	DWORD	reserved1;
	DWORD	reserved2;
}MAC_SECTION_32,*LPMAC_SECTION_32;

typedef struct _mac_header_64
{
	DWORD	magic;
	DWORD	cputype;
	DWORD	cpusubtype;
	DWORD	filetype;
	DWORD	ncmds;
	DWORD	sizeofcmds;
	DWORD	flags;
	DWORD	reserved;
}MAC_HEADER_64,*LPMAC_HEADER_64;

typedef struct _mac_segment_command_64
{
	DWORD	cmd;
	DWORD	cmdsize;
	char	segname[16];
	ULONG64			vmaddr;
	ULONG64			vmsize;
	ULONG64			fileoff;
	ULONG64			filesize;
	DWORD	maxprot;
	DWORD	initprot;
	DWORD	nsects;
	DWORD	flags;
}MAC_SEGMENT_COMMAND_64,*LPMAC_SEGMENT_COMMAND_64;

typedef struct _mac_section_64
{
	char		sectname[16];
	char		segname[16];
	ULONG64		addr;
	ULONG64		size;
	DWORD		offset;
	DWORD		align;
	DWORD		reloff;
	DWORD		nreloc;
	DWORD		flags;
	DWORD		reserved1;
	DWORD		reserved2;
}MAC_SECTION_64,*LPMAC_SECTION_64;
