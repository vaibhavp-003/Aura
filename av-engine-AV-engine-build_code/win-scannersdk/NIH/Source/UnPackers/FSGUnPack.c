/*======================================================================================
FILE             :  FSGUnPack.c
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     :  Siddharam Pujari
COMPANY		     :  Aura 
COPYRIGHT(NOTICE):  (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura.	

CREATION DATE    :  12/19/2009 4:12:46 PM
NOTES		     :  Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include <stdlib.h>
#include "Packers.h"

/*--------------------------------------------------------------------------------------
Function       : UnPackFSG200
In Parameters  : char *source, char *dest, int ssize, int dsize, uint32_t rva, uint32_t base, uint32_t ep, void* file, 
Out Parameters : int 
Description    : Unpacks the given application Packed with FSG200
Author & Date  :
--------------------------------------------------------------------------------------*/
int UnPackFSG200(char *source, char *dest, int ssize, int dsize, uint32_t rva, uint32_t base, uint32_t ep, void* file) {

	struct Max_Exe_Sections section;

	if ( UnFSG(source, dest, ssize, dsize, NULL, NULL) ) return -1;

	section.raw=0;
	section.rsz = dsize;
	section.vsz = dsize;
	section.rva = rva;

	if (!RebuildFakePE(dest, &section, 1, base, ep, 0, 0, file)) 
	{
		DBGMessage("FSG: Rebuilding failed\n");
		return 0;
	}
	return 1;
}

/*--------------------------------------------------------------------------------------
Function       : UnPackFSG133
In Parameters  : char *source, char *dest, int ssize, int dsize, struct Max_Exe_Sections *sections, int sectcount, uint32_t base, uint32_t ep, void* file, 
Out Parameters : int 
Description    : Unpacks the given application Packed with FSG200
Author & Date  :
--------------------------------------------------------------------------------------*/
int UnPackFSG133(char *source, char *dest, int ssize, int dsize, struct Max_Exe_Sections *sections, int sectcount, uint32_t base, uint32_t ep, void* file) 
{
	char *tsrc=source, *tdst=dest;
	int i, upd=1, offs=0, lastsz=dsize;

	for (i = 0 ; i <= sectcount ; i++)
	{
		char *startd=tdst;
		if ( UnFSG(tsrc, tdst, ssize - (tsrc - source), dsize - (tdst - dest), &tsrc, &tdst) == -1 )
		{
			return -1;
		}

		sections[i].raw=offs;
		sections[i].rsz=tdst-startd;
		offs+=tdst-startd;
	}

	/* Sort out the sections */
	while ( upd )
	{
		upd = 0;
		for (i = 0; i < sectcount  ; i++) 
		{
			uint32_t trva,trsz,traw;

			if ( sections[i].rva <= sections[i+1].rva )
			{
				continue;
			}
			trva = sections[i].rva;
			traw = sections[i].raw;
			trsz = sections[i].rsz;
			sections[i].rva = sections[i+1].rva;
			sections[i].rsz = sections[i+1].rsz;
			sections[i].raw = sections[i+1].raw;
			sections[i+1].rva = trva;
			sections[i+1].raw = traw;
			sections[i+1].rsz = trsz;
			upd = 1;
		}
	}

	/* Cure Vsizes and debugspam */
	for (i = 0; i <= sectcount ; i++)
	{
		if ( i != sectcount )
		{
			sections[i].vsz = sections[i+1].rva - sections[i].rva;
			lastsz-= sections[i+1].rva - sections[i].rva;
		}
		else 
			sections[i].vsz = lastsz;

		DBGMessage("FSG: .SECT%d RVA:%x VSize:%x ROffset: %x, RSize:%x\n", i, sections[i].rva, sections[i].vsz, sections[i].raw, sections[i].rsz);
	}

	if (!RebuildFakePE(dest, sections, sectcount+1, base, ep, 0, 0, file))
	{
		DBGMessage("FSG: Rebuilding failed\n");
		return 0;
	}
	return 1;
}
