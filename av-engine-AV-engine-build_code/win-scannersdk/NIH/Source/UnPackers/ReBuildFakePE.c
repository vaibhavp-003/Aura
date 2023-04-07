
/*======================================================================================
FILE             : BuildFakePE.c
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Siddharam Pujari
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
	CREATION DATE    : 12/19/2009 4:50:35 PM
	NOTES		     : Defines the Functionality to Build Dummy PE File
	VERSION HISTORY  : 
	======================================================================================*/
#include <stdio.h>
#include <string.h>
#include "Packers.h"

struct IMAGE_PE_HEADER {
	uint32_t Signature;
	/* FILE HEADER */
	uint16_t    Machine;
	uint16_t    NumberOfSections;
	uint32_t   TimeDateStamp;
	uint32_t   PointerToSymbolTable;
	uint32_t   NumberOfSymbols;
	uint16_t    SizeOfOptionalHeader;
	uint16_t    Characteristics;
	/* OPTIONAL HEADER */
	uint16_t    Magic;
	uint8_t    MajorLinkerVersion;
	uint8_t    MinorLinkerVersion;
	uint32_t   SizeOfCode;
	uint32_t   SizeOfInitializedData;
	uint32_t   SizeOfUninitializedData;
	uint32_t   AddressOfEntryPoint;
	uint32_t   BaseOfCode;
	uint32_t   BaseOfData;
	/* NT additional fields. */
	uint32_t   ImageBase;
	uint32_t   SectionAlignment;
	uint32_t   FileAlignment;
	uint16_t    MajorOperatingSystemVersion;
	uint16_t    MinorOperatingSystemVersion;
	uint16_t    MajorImageVersion;
	uint16_t    MinorImageVersion;
	uint16_t    MajorSubsystemVersion;
	uint16_t    MinorSubsystemVersion;
	uint32_t   Win32VersionValue;
	uint32_t   SizeOfImage;
	uint32_t   SizeOfHeaders;
	uint32_t   CheckSum;
	uint16_t    Subsystem;
	uint16_t    DllCharacteristics;
	uint32_t   SizeOfStackReserve;
	uint32_t   SizeOfStackCommit;
	uint32_t   SizeOfHeapReserve;
	uint32_t   SizeOfHeapCommit;
	uint32_t   LoaderFlags;
	uint32_t   NumberOfRvaAndSizes;
	/* IMAGE_DATA_DIRECTORY follows.... */
};

#define HEADERS "\
\x4D\x5A\x90\x00\x02\x00\x00\x00\x04\x00\x0F\x00\xFF\xFF\x00\x00\
\xB0\x00\x00\x00\x00\x00\x00\x00\x40\x00\x1A\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xD0\x00\x00\x00\
\x54\x68\x69\x73\x20\x66\x69\x6c\x65\x20\x77\x61\x73\x20\x63\x72\
\x65\x61\x74\x65\x64\x20\x62\x79\x20\x4d\x61\x78\x20\x53\x65\x63\
\x75\x72\x65\x20\x66\x6f\x72\x20\x69\x6e\x74\x65\x72\x6e\x61\x6c\
\x20\x75\x73\x65\x2e\x0d\x0a\x20\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x50\x45\x00\x00\x4C\x01\xFF\xFF\x4d\x61\x78\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\xE0\x00\x83\x8F\x0B\x01\x00\x00\x00\x10\x00\x00\
\x00\x10\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x10\x00\x00\
\x00\x10\x00\x00\xFF\xFF\xFF\xFF\x00\x10\x00\x00\x00\x02\x00\x00\
\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x0A\x00\x00\x00\x00\x00\
\x00\x10\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\
\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00\
\x00\x00\x00\x00\x10\x00\x00\x00\
"

/*--------------------------------------------------------------------------------------
Function       : RebuildFakePE
In Parameters  : char *buffer, struct Max_Exe_Sections *sections, int sects, uint32_t base, uint32_t ep, uint32_t ResRva, uint32_t ResSize, void * file, 
Out Parameters : int 
Description    : Makes Dummy PE
Author & Date  :
--------------------------------------------------------------------------------------*/
int RebuildFakePE(char *buffer, struct Max_Exe_Sections *sections, int sects, uint32_t base, uint32_t ep, uint32_t ResRva, uint32_t ResSize, void * file)
{
	uint32_t datasize=0, rawbase=PESALIGN(0x148+0x80+0x28*sects, 0x200);
	char *pefile=NULL, *curpe;
	struct IMAGE_PE_HEADER *fakepe;
	int i, gotghost=(sections[0].rva > PESALIGN(rawbase, 0x1000));

	if (gotghost) rawbase=PESALIGN(0x148+0x80+0x28*(sects+1), 0x200);

	if(sects+gotghost > 96)
	{
		return 0;
	}

	for (i=0; i < sects; i++)
		datasize+=PESALIGN(sections[i].rsz, 0x200);

	if(datasize > MAX_ALLOCATION)
	{
		return 0;
	}

	if((pefile = (char *) MaxCalloc(rawbase+datasize, 1))) 
	{
		memcpy(pefile, HEADERS, 0x148);

		datasize = PESALIGN(rawbase, 0x1000);

		fakepe = (struct IMAGE_PE_HEADER *)(pefile+0xd0);
		fakepe->NumberOfSections = EC16(sects+gotghost);
		fakepe->AddressOfEntryPoint = EC32(ep);
		fakepe->ImageBase = EC32(base);
		fakepe->SizeOfHeaders = EC32(rawbase);
		memset(pefile+0x148, 0, 0x80);
		WriteInt32(pefile+0x148+0x10, ResRva);
		WriteInt32(pefile+0x148+0x14, ResSize);
		curpe = pefile+0x148+0x80;

		if (gotghost) 
		{
			_snprintf(curpe, 8, "empty");
			WriteInt32(curpe+8, sections[0].rva-datasize); /* vsize */
			WriteInt32(curpe+12, datasize); /* rva */
			WriteInt32(curpe+0x24, 0xffffffff);
			curpe+=40;
			datasize+=PESALIGN(sections[0].rva-datasize, 0x1000);
		}

		for (i=0; i < sects; i++) 
		{
			_snprintf(curpe, 8, ".maxs%.2d", i+1);
			WriteInt32(curpe+8, sections[i].vsz);
			WriteInt32(curpe+12, sections[i].rva);
			WriteInt32(curpe+16, sections[i].rsz);
			WriteInt32(curpe+20, rawbase);
			WriteInt32(curpe+0x24, 0xffffffff);
			memcpy(pefile+rawbase, buffer+sections[i].raw, sections[i].rsz);
			rawbase+=PESALIGN(sections[i].rsz, 0x200);
			curpe+=40;
			datasize+=PESALIGN(sections[i].vsz, 0x1000);
		}
		fakepe->SizeOfImage = EC32(datasize);
	}
	else
	{
		return 0;
	}

	i = (MaxWritten(file, pefile, rawbase)!=-1);
	free(pefile);
	return i;
}
