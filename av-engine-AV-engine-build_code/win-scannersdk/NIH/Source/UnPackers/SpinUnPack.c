
/*======================================================================================
FILE             : SpinUnPack.c
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
				  
	CREATION DATE    : 12/19/2009 4:39:31 PM
	NOTES		     : Defines the Functionality to Unpack the PESPIN
	VERSION HISTORY  : 
	======================================================================================*/
#include <stdlib.h>
#include <string.h>
#include "Packers.h"
/*--------------------------------------------------------------------------------------
Function       : Exec86
In Parameters  : uint8_t aelle, uint8_t cielle, char *curremu, int *retval, 
Out Parameters : static char 
Description    : Exec86 
Author & Date  :
--------------------------------------------------------------------------------------*/
static char Exec86(uint8_t aelle, uint8_t cielle, char *curremu, int *retval)
{
	int len = 0;
	*retval=0;
	while (len <0x24)
	{
		uint8_t opcode = curremu[len], support;
		len++;
		switch (opcode) 
		{
		case 0xeb:
			len++;
		case 0x0a:
			len++;
		case 0x90:
		case 0xf8:
		case 0xf9:
			break;

		case 0x02: 
			aelle+=cielle;
			len++;
			break;
		case 0x2a: 
			aelle-=cielle;
			len++;
			break;
		case 0x04: 
			aelle+=curremu[len];
			len++;
			break;
		case 0x2c: 
			aelle-=curremu[len];
			len++;
			break;
		case 0x32: 
			aelle^=cielle;
			len++;
			break;
		case 0x34: 
			aelle^=curremu[len];
			len++;
			break;

		case 0xfe: 
			if ( curremu[len] == '\xc0' ) aelle++;
			else aelle--;
			len++;
			break;

		case 0xc0: 
			support = curremu[len];
			len++;
			if ( support == 0xc0 ) MAX_ROL(aelle, curremu[len]);
			else MAX_ROR(aelle, curremu[len]);
			len++;
			break;

		default:
			DBGMessage("spin: bogus opcode %x\n", opcode);
			*retval=1;
			return aelle;
		}
	}
	if ( len!=0x24 || curremu[len]!='\xaa' )
	{
		DBGMessage("spin: bad emucode\n");
		*retval=1;
	}
	return aelle;
}


/*--------------------------------------------------------------------------------------
Function       : Summit 
In Parameters  : char *src, int size, 
Out Parameters : static uint32_t 
Description    : Summit
Author & Date  :
--------------------------------------------------------------------------------------*/
static uint32_t Summit (char *src, int size) 
{
	uint32_t eax=0xffffffff, ebx=0xffffffff;
	int i;

	while(size)
	{
		eax ^= *src++<<8 & 0xff00;
		eax = eax>>3 & 0x1fffffff;
		for (i=0; i<4; i++)
		{
			uint32_t swap;
			eax ^= ebx>>8 & 0xff;
			eax += 0x7801a108;
			eax ^= ebx;
			MAX_ROR(eax, ebx&0xff);
			swap = eax;
			eax = ebx;
			ebx = swap;
		}
		size--; 
	}
	return ebx;
}


/*--------------------------------------------------------------------------------------
Function       : UnPackSpin
In Parameters  : char *src, int ssize, struct Max_Exe_Sections *sections, int sectcnt, uint32_t nep, void* desc, 
Out Parameters : int 
Description    : Unpacks the PESPIN
Author & Date  :
--------------------------------------------------------------------------------------*/
int UnPackSpin(char *src, int ssize, struct Max_Exe_Sections *sections, int sectcnt, uint32_t nep, void* desc) 
{
	char *curr, *emu, *ep, *spinned;
	unsigned long int filesize = 0;
	char **sects;
	int blobsz=0, j;
	uint32_t key32, bitmap, bitman;
	uint32_t len;
	uint8_t key8;

	DBGMessage("in UnPackSpin\n");

	if ((spinned = (char *) MaxMalloc(sections[sectcnt].rsz)) == NULL )
	{
		return 1;
	}

	memcpy(spinned, src + sections[sectcnt].raw, sections[sectcnt].rsz); 
	ep = spinned + nep - sections[sectcnt].rva;

	curr = ep+0xdb;
	if ( *curr != '\xbb' )
	{
		free(spinned);
		DBGMessage("spin: Not spinned or bad version\n");
		return 1;
	}

	key8 = (uint8_t)*++curr;
	curr+=4;
	if ( *curr != '\xb9' ) 
	{
		free(spinned);
		DBGMessage("spin: Not spinned or bad version\n");
		return 1;
	}

	if ( (len = ReadInt32(curr+1)) != 0x11fe )
	{
		free(spinned);
		DBGMessage("spin: Not spinned or bad version\n");
		return 1;
	}

	DBGMessage("spin: Key8 is %x, Len is %x\n", key8, len);

	if (!CompareBuffer(spinned, sections[sectcnt].rsz, ep, len+0x1fe5-1))
	{
		free(spinned);
		DBGMessage("spin: len out of bounds, giving up\n");
		return 1;
	}

	if ( ep[0x1e0]!='\xb8' )
	{
		DBGMessage("spin: prolly not spinned, expect failure\n");
	}

	if ( (ReadInt32(ep+0x1e1) & 0x00200000) )
	{
		DBGMessage("spin: password protected, expect failure\n");
	}

	curr = ep+0x1fe5+len-1;
	while ( len-- ) 
	{
		*curr=(*curr)^(key8--);
		curr--;
	}

	if (!CompareBuffer(spinned, sections[sectcnt].rsz, ep+0x3217, 4))
	{
		free(spinned);
		DBGMessage("spin: key out of bounds, giving up\n");
		return 1;
	}

	curr = ep+0x26eb;
	key32 = ReadInt32(curr);
	if ( (len = ReadInt32(curr+5)) != 0x5a0)
	{
		free(spinned);
		DBGMessage("spin: Not spinned or bad version\n");
		return 1;
	}

	curr = ep+0x2d5;
	DBGMessage("spin: Key is %x, Len is %x\n", key32, len);

	while ( len-- ) 
	{
		if ( key32 & 1 ) 
		{
			key32 = key32>>1;
			key32 ^= 0x8c328834;
		} 
		else
		{
			key32 = key32>>1;
		}
		*curr = *curr ^ (key32 & 0xff);
		curr++;
	}

	len = ssize - ReadInt32(ep+0x429); /* sub size, value */
	if ( len >= (uint32_t)ssize ) 
	{
		free(spinned);
		DBGMessage("spin: crc out of bounds, giving up\n");
		return 1;
	}
	key32 = ReadInt32(ep+0x3217) - Summit(src,len);

	memcpy(src + sections[sectcnt].raw, spinned, sections[sectcnt].rsz); 
	free(spinned);
	ep = src + nep + sections[sectcnt].raw - sections[sectcnt].rva; 

	if (!CompareBuffer(src, ssize, ep+0x3207, 4))
	{ 
		DBGMessage("spin: key out of bounds, giving up\n");
		return 1;
	}
	bitmap = ReadInt32(ep+0x3207);
	DBGMessage("spin: Key32 is %x - XORbitmap is %x\n", key32, bitmap);

	DBGMessage("spin: Decrypting sects (xor)\n");
	for (j=0; j<sectcnt; j++) 
	{

		if (bitmap&1)
		{
			uint32_t size = sections[j].rsz;
			char *ptr = src + sections[j].raw;
			uint32_t keydup = key32;

			if (!CompareBuffer(src, ssize, ptr, size))
			{
				DBGMessage("spin: sect %d out of file, giving up\n", j);
				return 1;
			}

			while (size--) 
			{
				if (! (keydup & 1)) 
				{
					keydup = keydup>>1;
					keydup ^= 0xed43af31;
				} 
				else 
				{
					keydup = keydup>>1;
				}
				*ptr = *ptr ^ (keydup & 0xff);
				ptr++;
			}
		} 
		bitmap = bitmap >>1;
	}

	DBGMessage("spin: done\n");


	curr = ep+0x644;
	if ( (len = ReadInt32(curr)) != 0x180) 
	{
		DBGMessage("spin: Not spinned or bad version\n");
		return 1;
	}

	key32 = ReadInt32(curr+0x0c);
	DBGMessage("spin: Key is %x, Len is %x\n", key32, len);
	curr = ep+0x28d3;

	if (!CompareBuffer(src, ssize, curr, len))
	{ 
		DBGMessage("spin: key out of bounds, giving up\n");
		return 1;
	}
	while ( len-- )
	{
		if ( key32 & 1 )
		{
			key32 = key32>>1;
			key32 ^= 0xed43af32;
		}
		else
		{
			key32 = key32>>1;
		}
		*curr = *curr ^ (key32 & 0xff);
		curr++;
	}


	curr = ep+0x28dd;
	if ( (len = ReadInt32(curr)) != 0x1a1 ) 
	{
		DBGMessage("spin: Not spinned or bad version\n");
		return 1;
	}

	DBGMessage("spin: POLY1 len is %x\n", len);
	curr+=0xf; /* POLY1 */
	emu = ep+0x6d4;
	if (!CompareBuffer(src, ssize, emu, len))
	{
		DBGMessage("spin: poly1 out of bounds\n");
		return 1;
	}
	while (len)
	{
		int xcfailure=0;
		*emu=Exec86(*emu, len-- & 0xff, curr, &xcfailure); 
		if (xcfailure) {
			DBGMessage("spin: cannot exec poly1\n");
			return 1;
		}
		emu++;
	}


	bitmap = ReadInt32(ep+0x6f1);
	DBGMessage("spin: POLYbitmap is %x - Decrypting sects (poly)\n", bitmap);
	curr = ep+0x755;

	for (j=0; j<sectcnt; j++)
	{
		if (bitmap&1) 
		{
			uint32_t notthesamelen = sections[j].rsz;

			emu = src + sections[j].raw;

			if (!CompareBuffer(src,ssize,curr,0x24)) 
			{ 
				DBGMessage("spin: poly1 emucode is out of file?\n");
				return 1;
			}

			while (notthesamelen) 
			{
				int xcfailure=0;
				*emu=Exec86(*emu, notthesamelen-- & 0xff, curr, &xcfailure);
				if (xcfailure) 
				{
					DBGMessage("spin: cannot exec section\n");
					return 1;
				}
				emu++;
			}
		}
		bitmap = bitmap >>1;
	}

	DBGMessage("spin: done\n");

	bitmap = ReadInt32(ep+0x3061);
	bitman = bitmap;

	for (j=0; j<sectcnt; j++)
	{
		if (bitmap&1) {
			filesize += sections[j].vsz;
		}
		bitmap>>=1;
	}

	bitmap = bitman;
	//}

	DBGMessage("spin: Compression bitmap is %x\n", bitmap);
	if ( (sects= (char **) MaxMalloc(sectcnt*sizeof(char *))) == NULL )
	{
		return 1;
	}

	len = 0;
	for (j=0; j<sectcnt; j++) 
	{
		if (bitmap&1)
		{
			if ( (sects[j] = (char *) MaxMalloc(sections[j].vsz) ) == NULL ) 
			{
				DBGMessage("spin: malloc(%d) failed\n", sections[j].vsz);
				len = 1;
				break;
			}
			blobsz+=sections[j].vsz;
			memset(sects[j], 0, sections[j].vsz);
			DBGMessage("spin: Growing sect%d: was %x will be %x\n", j, sections[j].rsz, sections[j].vsz);
			if ( UnFSG(src + sections[j].raw, sects[j], sections[j].rsz, sections[j].vsz, NULL, NULL) == -1 ) 
			{
				len++;
				DBGMessage("spin: Unpack failure\n");
			}
		} 
		else 
		{
			blobsz+=sections[j].rsz;
			sects[j] = src + sections[j].raw;
			DBGMessage("spin: Not growing sect%d\n", j);
		}
		bitmap>>=1;
	}

	DBGMessage("spin: decompression complete\n");

	if ( len )
	{
		int t;
		for (t=0 ; t<j ; t++) 
		{
			if (bitman&1)
				free(sects[t]);
			bitman = bitman >>1 & 0x7fffffff;
		}
		free(sects);
		return 1;
	}


	key32 = ReadInt32(ep+0x2fee);
	if (key32) {

		for (j=0; j<sectcnt; j++) 
		{
			if (sections[j].rva <= key32 && sections[j].rva+sections[j].rsz > key32)
				break;
		}

		if (j!=sectcnt && ((bitman & (1<<j)) == 0)) { 
			{
				DBGMessage("spin: Resources (sect%d) appear to be compressed\n\tuncompressed offset %x, len %x\n\tcompressed offset %x, len %x\n", j, sections[j].rva, key32 - sections[j].rva, key32, sections[j].vsz - (key32 - sections[j].rva));
			}

			if ( (curr=(char *)MaxMalloc(sections[j].vsz)) != NULL )
			{
				memcpy(curr, src + sections[j].raw, key32 - sections[j].rva);
				memset(curr + key32 - sections[j].rva, 0, sections[j].vsz - (key32 - sections[j].rva)); 
				if ( UnFSG(src + sections[j].raw + key32 - sections[j].rva, curr + key32 - sections[j].rva, sections[j].rsz - (key32 - sections[j].rva), sections[j].vsz - (key32 - sections[j].rva), NULL, NULL) ) 
				{

					free(curr);
					DBGMessage("spin: Failed to grow resources, continuing anyway\n");
					blobsz+=sections[j].rsz;
				} 
				else 
				{
					sects[j]=curr;
					bitman|=1<<j;
					DBGMessage("spin: Resources grown\n");
					blobsz+=sections[j].vsz;
				}
			}
			else
			{

				blobsz+=sections[j].rsz;
			}
		}
		else 
		{
			DBGMessage("spin: No res?!\n");
		}
	}


	bitmap=bitman; 

	if ( (ep = (char *) MaxMalloc(blobsz)) != NULL ) 
	{
		struct Max_Exe_Sections *rebhlp;
		if ( (rebhlp = (struct Max_Exe_Sections *) MaxMalloc(sizeof(struct Max_Exe_Sections)*(sectcnt))) != NULL ) 
		{
			char *to = ep;
			int retval = 0;

			for (j = 0; j < sectcnt; j++) {
				rebhlp[j].raw = (j>0)?(rebhlp[j-1].raw + rebhlp[j-1].rsz):0;
				rebhlp[j].rsz = (bitmap &1) ? sections[j].vsz : sections[j].rsz;
				rebhlp[j].rva = sections[j].rva;
				rebhlp[j].vsz = sections[j].vsz;

				memcpy(to, sects[j], rebhlp[j].rsz);
				to+=rebhlp[j].rsz;
				if ( bitmap & 1 ) free(sects[j]);
				bitmap = bitmap >>1;
			}

			if (! RebuildFakePE(ep, rebhlp, sectcnt, 0x400000, 0x1000, 0, 0, desc)) { 
				DBGMessage("spin: Cannot write unpacked file\n");
				retval = 1;
			}
			free(rebhlp);
			free(ep);
			free(sects);
			return retval;
		}
		free(ep);
	}

	DBGMessage ("spin: free bitmap is %x\n", bitman);
	for (j=0; j<sectcnt; j++)
	{
		if (bitmap&1) free(sects[j]);
		bitman = bitman >>1 & 0x7fffffff;
	}
	free(sects);
	return 1;
}
