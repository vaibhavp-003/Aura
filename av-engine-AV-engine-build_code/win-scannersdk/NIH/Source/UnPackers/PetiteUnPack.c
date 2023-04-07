
/*======================================================================================
FILE             : PetiteUnPack.c
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Siddharam Pujari
COMPANY		     : Aura 
COPYRIGHT(NOTICE): (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura.	

CREATION DATE    : 12/19/2009 4:56:06 PM
NOTES		     :Defines the Functionality to Unpack the PETITE
VERSION HISTORY  : 
======================================================================================*/
#include <stdlib.h>
#include <string.h>
#include "Packers.h"

/*--------------------------------------------------------------------------------------
Function       : Doubledl
In Parameters  : char **scur, uint8_t *mydlptr, char *buffer, uint32_t buffersize, 
Out Parameters : static int 
Description    : 
Author & Date  :
--------------------------------------------------------------------------------------*/
static int Doubledl(char **scur, uint8_t *mydlptr, char *buffer, uint32_t buffersize)
{
	unsigned char mydl = *mydlptr;
	unsigned char olddl = mydl;

	mydl*=2;
	if ( !(olddl & 0x7f))
	{
		if ( *scur < buffer || *scur >= buffer+buffersize-1 )
		{
			return -1;
		}
		olddl = **scur;
		mydl = olddl*2+1;
		*scur=*scur + 1;
	}
	*mydlptr = mydl;
	return (olddl>>7)&1;
}

/*--------------------------------------------------------------------------------------
Function       : PETITE_Inflate2x_1to9
In Parameters  : char *buf, uint32_t minrva, uint32_t bufsz, struct Max_Exe_Sections *sections, unsigned int sectcount, uint32_t Imagebase, uint32_t pep, int desc, int version, uint32_t ResRva, uint32_t ResSize, 
Out Parameters : int 
Description    : Unpacks the PETITE Packer
Author & Date  :
--------------------------------------------------------------------------------------*/
int PETITE_Inflate2x_1to9(char *buf, uint32_t minrva, uint32_t bufsz, struct Max_Exe_Sections *sections, unsigned int sectcount, uint32_t Imagebase, uint32_t pep, void* desc, int version, uint32_t ResRva, uint32_t ResSize)
{
	char *adjbuf = buf - minrva;
	char *packed = NULL;
	uint32_t thisrva=0, bottom = 0, enc_ep=0, irva=0, workdone=0, grown=0x355, skew=0x35;
	int j = 0, oob, mangled = 0, check4resources=0;
	struct Max_Exe_Sections *usects = NULL;
	void *tmpsct = NULL;

	if ( version == 2 )
	{
		packed = adjbuf + sections[sectcount-1].rva + 0x1b8;
	}
	if ( version == 1 ) {
		packed = adjbuf + sections[sectcount-1].rva + 0x178;
		grown=0x323;
		skew=0x34;
	}

	while (1)
	{
		char *ssrc, *ddst;
		uint32_t size, srva;
		int backbytes, oldback, backsize, addsize;

		if ( ! CompareBuffer(buf, bufsz, packed, 4))
		{
			if (usects)
				free(usects);
			return 1;
		}
		srva = ReadInt32(packed);

		if (! srva) 
		{
			int t, upd = 1;

			if ( j <= 0 ) 
				return 1;

			while ( upd )
			{
				upd = 0;
				for (t = 0; t < j-1 ; t++) {
					uint32_t trva, trsz, tvsz;

					if ( usects[t].rva <= usects[t+1].rva )
						continue;
					trva = usects[t].rva;
					trsz = usects[t].rsz;
					tvsz = usects[t].vsz;
					usects[t].rva = usects[t+1].rva;
					usects[t].rsz = usects[t+1].rsz;
					usects[t].vsz = usects[t+1].vsz;
					usects[t+1].rva = trva;
					usects[t+1].rsz = trsz;
					usects[t+1].vsz = tvsz;
					upd = 1;
				}
			}

			for (t = 0; t < j-1 ; t++) 
			{
				if ( usects[t].vsz != usects[t+1].rva - usects[t].rva )
					usects[t].vsz = usects[t+1].rva - usects[t].rva;
			}

			if (enc_ep) 
			{
				uint32_t virtaddr = pep + 5 + Imagebase, tmpep;
				int rndm = 0, dummy = 1;
				char *thunk = adjbuf+irva;
				char *imports;

				if ( version == 2 )
				{
					while ( dummy && CompareBuffer(buf, bufsz, thunk, 4) ) 
					{
						uint32_t api;

						if (! ReadInt32(thunk)) 
						{
							workdone = 1;
							break;
						}

						imports = adjbuf + ReadInt32(thunk);
						thunk+=4;
						dummy = 0;

						while ( CompareBuffer(buf, bufsz, imports, 4)) 
						{
							dummy = 0;

							imports+=4;
							if ( ! (api = ReadInt32(imports-4)) ) 
							{
								dummy  = 1;
								break;
							}
							if ( (api != (api | 0x80000000)) && mangled && --rndm < 0)
							{
								api = virtaddr;
								virtaddr +=5;
								rndm = virtaddr & 7;
							} 
							else
							{
								api = 0xbff01337; 
							}
							if (sections[sectcount-1].rva+Imagebase < api )
								enc_ep--;
							if ( api < virtaddr )
								enc_ep--;
							tmpep = (enc_ep & 0xfffffff8)>>3 & 0x1fffffff;
							enc_ep = (enc_ep & 7)<<29 | tmpep;
						}
					}
				} 
				else 
					workdone = 1;
				enc_ep = pep+5+enc_ep;
				if ( workdone == 1 ) 
				{
					DBGMessage("Petite: Old EP: %x\n", enc_ep);
				}
				else 
				{
					enc_ep = usects[0].rva;
					DBGMessage("Petite: In troubles while attempting to Decrypt old EP, using bogus %x\n", enc_ep);
				}
			}

			for (t = 0; t < j ; t++)
			{
				usects[t].raw = (t>0)?(usects[t-1].raw + usects[t-1].rsz):0;
				if (usects[t].rsz != 0 && CompareBuffer(buf, bufsz, buf + usects[t].raw, usects[t].rsz))
					memmove(buf + usects[t].raw, adjbuf + usects[t].rva, usects[t].rsz);
			}

			DBGMessage("Petite: Sections dump:\n");
			for (t = 0; t < j ; t++)
				DBGMessage("Petite: .SECT%d RVA:%x VSize:%x ROffset: %x, RSize:%x\n", t, usects[t].rva, usects[t].vsz, usects[t].raw, usects[t].rsz);
			if (! RebuildFakePE(buf, usects, j, Imagebase, enc_ep, ResRva, ResSize, desc)) 
			{
				DBGMessage("Petite: Rebuilding failed\n");
				free(usects);
				return 1;
			}
			free(usects);
			return 0;
		}


		size = srva & 0x7fffffff;
		if ( srva != size )
		{ 
			check4resources=0;

			if ( ! CompareBuffer(buf, bufsz, packed+4, 8) ) 
			{
				if (usects)
					free(usects);
				return 1;
			}
			bottom = ReadInt32(packed+8) + 4;
			ssrc = adjbuf + ReadInt32(packed+4) - (size-1)*4;
			ddst = adjbuf + ReadInt32(packed+8) - (size-1)*4;

			if ( !CompareBuffer(buf, bufsz, ssrc, size*4) || !CompareBuffer(buf, bufsz, ddst, size*4) )
			{
				if (usects)
					free(usects);
				return 1;
			}

			memmove(ddst, ssrc, size*4);
			packed += 0x0c;
		} 
		else 
		{
			uint32_t check1, check2;
			uint8_t mydl = 0;
			uint8_t goback;

			if ( ! CompareBuffer(buf, bufsz, packed+4, 8)) 
			{
				if (usects)
					free(usects);
				return 1;
			}

			size = ReadInt32(packed+4); 
			thisrva=ReadInt32(packed+8);
			packed += 0x10;

			if ( j >= 96 )
			{
				DBGMessage("Petite: maximum number of sections exceeded, giving up.\n");
				free(usects);
				return 1;
			}
			if ( ! (tmpsct = MaxRealloc(usects, sizeof(struct Max_Exe_Sections) * (j+1))) ) 
			{
				if (usects)
					free(usects);
				return 1;
			}

			usects = (struct Max_Exe_Sections *) tmpsct;
			usects[j].rva = thisrva;
			usects[j].rsz = size;
			if ( (int)(bottom - thisrva) >0 )
				usects[j].vsz = bottom - thisrva;
			else
				usects[j].vsz = size;
			usects[j].raw = 0; 

			if (!size) 
			{ 
				j++;
				continue;
			}

			ssrc = adjbuf + srva;
			ddst = adjbuf + thisrva;



			if (!check4resources) 
			{
				unsigned int q;
				for ( q = 0 ; q < sectcount ; q++ ) 
				{
					if ( thisrva <= sections[q].rva || thisrva >= sections[q].rva + sections[q].vsz)
						continue;
					usects[j].rva = sections[q].rva;
					usects[j].rsz = thisrva - sections[q].rva + size;
					break;
				}
			}

			j++;


			if ( size < 0x10000 ) 
			{
				check1 = 0x0FFFFC060;
				check2 = 0x0FFFFFC60;
				goback = 5;
			} else if ( size < 0x40000 ) 
			{
				check1 = 0x0FFFF8180;
				check2 = 0x0FFFFF980;
				goback = 7;
			} else
			{
				check1 = 0x0FFFF8300;
				check2 = 0x0FFFFFB00;
				goback = 8;
			}

			if ( (!CompareBuffer(buf, bufsz, ssrc, 1)) || (!CompareBuffer(buf, bufsz, ddst, 1))) 
			{
				free(usects);
				return 1;
			}

			size--;
			*ddst++=*ssrc++; 
			backbytes=0;
			oldback = 0;

			while (size > 0) 
			{
				oob = Doubledl(&ssrc, &mydl, buf, bufsz);
				if ( oob == -1 ) 
				{
					free(usects);
					return 1;
				}
				if (!oob) 
				{
					if ( !CompareBuffer(buf, bufsz, ssrc, 1) || !CompareBuffer(buf, bufsz, ddst, 1) ) 
					{
						free(usects);
						return 1;
					}
					*ddst++ = (char)((*ssrc++)^(size & 0xff));
					size--;
				} 
				else 
				{
					addsize = 0;
					backbytes++;
					while (1) 
					{
						if ( (oob = Doubledl(&ssrc, &mydl, buf, bufsz)) == -1 ) 
						{
							free(usects);
							return 1;
						}
						backbytes = backbytes*2 + oob;
						if ( (oob = Doubledl(&ssrc, &mydl, buf, bufsz)) == -1 ) 
						{
							free(usects);
							return 1;
						}
						if (!oob)
							break;
					}
					backbytes -= 3;
					if ( backbytes >= 0 ) 
					{
						backsize = goback;
						do
						{
							if ( (oob = Doubledl(&ssrc, &mydl, buf, bufsz)) == -1 ) 
							{
								free(usects);
								return 1;
							}
							backbytes = backbytes*2 + oob;
							backsize--;
						} while (backsize);
						backbytes^=0xffffffff;
						addsize += 1 + ( backbytes < (int) check2 ) + ( backbytes < (int) check1 );
						oldback = backbytes;
					}
					else 
					{
						backsize = backbytes+1;
						backbytes = oldback;
					}

					if ( (oob = Doubledl(&ssrc, &mydl, buf, bufsz)) == -1 ) 
					{
						free(usects);
						return 1;
					}
					backsize = backsize*2 + oob;
					if ( (oob = Doubledl(&ssrc, &mydl, buf, bufsz)) == -1 ) 
					{
						free(usects);
						return 1;
					}
					backsize = backsize*2 + oob;
					if (!backsize) 
					{
						backsize++;
						while (1) 
						{
							if ( (oob = Doubledl(&ssrc, &mydl, buf, bufsz)) == -1 ) 
							{
								free(usects);
								return 1;
							}
							backsize = backsize*2 + oob;
							if ( (oob = Doubledl(&ssrc, &mydl, buf, bufsz)) == -1 ) 
							{
								free(usects);
								return 1;
							}
							if (!oob)
								break;
						}
						backsize+=2;
					}
					backsize+=addsize;
					size-=backsize;
					if(!CompareBuffer(buf, bufsz, ddst, backsize) || !CompareBuffer(buf, bufsz, ddst+backbytes, backsize)) 
					{
						free(usects);
						return 1;
					}
					while(backsize--) 
					{
						*ddst=*(ddst+backbytes);
						ddst++;
					}
					backbytes=0;
					backsize=0;
				} 
			}
			if ( j ) 
			{
				int strippetite=0;
				uint32_t reloc;

				if ( usects[j-1].rsz > grown && 
					CompareBuffer(buf, bufsz, ddst-grown+5+0x4f, 8) &&
					ReadInt32(ddst-grown+5+0x4f) == 0x645ec033 &&
					ReadInt32(ddst-grown+5+0x4f+4) == 0x1b8b188b
					)
				{
					reloc = 0;
					strippetite = 1;
				}
				if ( !strippetite && 
					usects[j-1].rsz > grown+skew &&
					CompareBuffer(buf, bufsz, ddst-grown+5+0x4f-skew, 8) &&
					ReadInt32(ddst-grown+5+0x4f-skew) == 0x645ec033 &&
					ReadInt32(ddst-grown+5+0x4f+4-skew) == 0x1b8b188b
					) 
				{
					reloc = skew; 
					strippetite = 1;
				}

				if (strippetite && CompareBuffer(buf, bufsz, ddst-grown+0x0f-8-reloc, 8)) 
				{
					uint32_t test1, test2;

					test1 = ReadInt32(ddst-grown+0x0f-8-reloc)^0x9d6661aa;
					test2 = ReadInt32(ddst-grown+0x0f-4-reloc)^0xe908c483;

					DBGMessage("Petite: Found petite code in sect%d(%x). Let's strip it.\n", j-1, usects[j-1].rva);
					if (test1 == test2 && CompareBuffer(buf, bufsz, ddst-grown+0x0f-reloc, 0x1c0-0x0f+4)) 
					{
						irva = ReadInt32(ddst-grown+0x121-reloc);
						enc_ep = ReadInt32(ddst-grown+0x0f-reloc)^test1;
						mangled = ((uint32_t) ReadInt32(ddst-grown+0x1c0-reloc) != 0x90909090); 
						DBGMessage("Petite: Encrypted EP: %x | Array of imports: %x\n",enc_ep, irva);
					}
					usects[j-1].rsz -= grown+reloc;
				}
			}
			check4resources++;
		} 
	} 
}
