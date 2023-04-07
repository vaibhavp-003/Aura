
/*======================================================================================
FILE             : WWUnPack.c
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
				  
	CREATION DATE    : 12/19/2009 4:43:20 PM
	NOTES		     : Defines the Functionality to Unpack the WWPack
	VERSION HISTORY  : 
	======================================================================================*/

#include "Packers.h"

#define RESEED \
	if (CompareBuffer(compd, szd, ccur, 4)) { \
	bt = ReadInt32(ccur); \
	ccur+=4; \
	} else { \
	DBGMessage("WWPack: Out of bits\n"); \
	error=1; \
	} \
	bc = 32;


#define BIT \
	bits = bt>>31; \
	bt<<=1; \
	if(!--bc) { \
	RESEED; \
	}

#define BITS(N) \
	bits = bt>>(32-(N)); \
	if (bc>=(N)) { \
	bc -= (N); \
	bt<<=(N); \
	if (!bc) { \
	RESEED; \
	} \
	} else { \
	if (CompareBuffer(compd, szd, ccur, 4)) { \
	bt = ReadInt32(ccur); \
	ccur+=4; \
	bc += 32 - (N); \
	bits |= bt>>(bc); \
	bt <<= (32-bc); \
	} else { \
	DBGMessage("WWPack: Out of bits\n"); \
	error=1; \
	} \
	}

/*--------------------------------------------------------------------------------------
Function       : UnPackWWPack
In Parameters  : uint8_t *exe, uint32_t exesz, uint8_t *wwsect, struct Max_Exe_Sections *sects, uint16_t scount, uint32_t pe, int desc, 
Out Parameters : int 
Description    :  Unpacks the Apllication Packed by WWPACK
Author & Date  :
--------------------------------------------------------------------------------------*/
int UnPackWWPack(uint8_t *exe, uint32_t exesz, uint8_t *wwsect, struct Max_Exe_Sections *sects, uint16_t scount, uint32_t pe, void* desc) 
{
	uint8_t *structs = wwsect + 0x2a1, *compd, *ccur, *unpd, *ucur, bc;
	uint32_t src, srcend, szd, bt, bits;
	int error=0, i;

	DBGMessage("in UnPackWWPack\n");
	while (1) 
	{
		if (!CompareBuffer(wwsect, sects[scount].rsz, structs, 17)) 
		{
			DBGMessage("WWPack: Array of structs out of section\n");
			break;
		}
		src = sects[scount].rva - ReadInt32(structs); /* src delta / dst delta - not used / dwords / end of src */
		structs+=8;
		szd = ReadInt32(structs) * 4;
		structs+=4;
		srcend = ReadInt32(structs);
		structs+=4;

		unpd = ucur = exe+src+srcend+4-szd;
		if (!szd || !CompareBuffer(exe, exesz, unpd, szd)) 
		{
			DBGMessage("WWPack: Compressed data out of file\n");
			break;
		}
		DBGMessage("WWP: src: %x, szd: %x, srcend: %x - %x\n", src, szd, srcend, srcend+4-szd);
		if (!(compd = MaxMalloc(szd))) break;
		memcpy(compd, unpd, szd);
		memset(unpd, -1, szd); 
		ccur=compd;

		RESEED;
		while(!error) 
		{
			uint32_t backbytes, backsize;
			uint8_t saved;

			BIT;
			if (!bits) 
			{ 
				if(ccur-compd>=szd || !CompareBuffer(exe, exesz, ucur, 1))
					error=1;
				else
					*ucur++=*ccur++;
				continue;
			}

			BITS(2);
			if(bits==3) 
			{
				uint8_t shifted, subbed = 31;
				BITS(2);
				shifted = bits + 5;
				if(bits>=2)
				{
					shifted++;
					subbed += 0x80;
				}
				backbytes = (1<<shifted)-subbed; /* 1h, 21h, 61h, 161h */
				BITS(shifted); /* 5, 6, 8, 9 */
				if(error || bits == 0x1ff) break;
				backbytes+=bits;
				if(!CompareBuffer(exe, exesz, ucur, 2) || !CompareBuffer(exe, exesz, ucur-backbytes, 2)) 
				{
					error=1;
				} else
				{
					ucur[0]=*(ucur-backbytes);
					ucur[1]=*(ucur-backbytes+1);
					ucur+=2;
				}
				continue;
			}

			/* BLOCK backcopy */
			saved = bits; /* cmp al, 1 / pushf */

			BITS(3);
			if (bits<6)
			{
				backbytes = bits;
				switch(bits) 
				{
				case 4:
					backbytes++;
				case 3:
					BIT;
					backbytes+=bits;
				case 0:	case 1:	case 2:
					backbytes+=5;
					break;
				case 5:
					backbytes=12;
					break;
				}
				BITS(backbytes);
				bits+=(1<<backbytes)-31;
			} else if(bits==6)
			{
				BITS(0x0e);
				bits+=0x1fe1;
			} else 
			{
				BITS(0x0f);
				bits+=0x5fe1;
			}

			backbytes = bits;

			/* popf / jb */
			if (!saved) 
			{
				BIT;
				if(!bits) 
				{
					BIT;
					bits+=5;
				}
				else 
				{
					BITS(3);
					if(bits) 
					{
						bits+=6;
					}
					else 
					{
						BITS(4);
						if(bits) 
						{
							bits+=13;
						}
						else 
						{
							uint8_t cnt = 4;
							uint16_t shifted = 0x0d;

							do 
							{
								if(cnt==7) { cnt = 0x0e; shifted = 0; break; }
								shifted=((shifted+2)<<1)-1;
								BIT;
								cnt++;
							} while(!bits);
							BITS(cnt);
							bits+=shifted;
						}
					}
				}
				backsize = bits;
			} else 
			{
				backsize = saved+2;
			}

			if(!CompareBuffer(exe, exesz, ucur, backsize) || !CompareBuffer(exe, exesz, ucur-backbytes, backsize)) error=1;
			else while(backsize--) {
				*ucur=*(ucur-backbytes);
				ucur++;
			}
		}
		free(compd);
		if(error) 
		{
			DBGMessage("WWPack: decompression error\n");
			break;
		}
		if (error || !*structs++) 
		{
			break;
		}
	}

	if(!error) 
	{
		exe[pe+6]=(uint8_t)scount;
		exe[pe+7]=(uint8_t)(scount>>8);
		WriteInt32(&exe[pe+0x28], ReadInt32(wwsect+0x295)+sects[scount].rva+0x299);
		WriteInt32(&exe[pe+0x50], ReadInt32(&exe[pe+0x50])-sects[scount].vsz);

		structs = &exe[(0xffff&ReadInt32(&exe[pe+0x14]))+pe+0x18];
		for(i=0 ; i<scount ; i++)
		{
			WriteInt32(structs+8, sects[i].vsz);
			WriteInt32(structs+12, sects[i].rva);
			WriteInt32(structs+16, sects[i].vsz);
			WriteInt32(structs+20, sects[i].rva);
			structs+=0x28;
		}
		memset(structs, 0, 0x28);
		error = MaxWritten(desc, exe, exesz)!=exesz;
	}
	return error;
}
