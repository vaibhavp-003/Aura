
/*======================================================================================
FILE             : UPackUnPack.c
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
				  
	CREATION DATE    : 12/19/2009 4:49:24 PM
	NOTES		     : Defines the Functionality to Unpack the UPACK
	VERSION HISTORY  : 
======================================================================================*/
#include <stdio.h>
#include "Packers.h"

#define EC32(x) le32_to_host(x) /* Convert little endian to host */
#define CE32(x) be32_to_host(x) /* Convert big endian to host */

int UnPackUPack399(char *, uint32_t, uint32_t, char *, uint32_t, char *, char *, uint32_t, char *);

enum { UPACK_399, UPACK_11_12, UPACK_0151477, UPACK_0297729 };

/*--------------------------------------------------------------------------------------
Function       : UnPackUPack
In Parameters  : int upack, char *dest, uint32_t dsize, char *buff, uint32_t vma, uint32_t ep, uint32_t base, uint32_t va, void* file, 
Out Parameters : int 
Description    : Unpacks the Appliction which is Packed by the UPACK
Author & Date  :
--------------------------------------------------------------------------------------*/
int UnPackUPack(int upack, char *dest, uint32_t dsize, char *buff, uint32_t vma, uint32_t ep, uint32_t base, uint32_t va, void* file)
{
	int j, searchval;
	char *loc_esi, *loc_edi, *loc_ebx, *end_edi, *save_edi, *alvalue;
	char *paddr, *pushed_esi, *save2;
	uint32_t save1,count, save3, loc_ecx, shlsize, original_ep, ret, loc_ebx_u;
	struct Max_Exe_Sections section;
	int upack_version = UPACK_399;

	if (upack)
	{
		uint32_t aljump, shroff, lngjmpoff;

		if (buff[5] == '\xff' && buff[6] == '\x36')
		{
			upack_version = UPACK_0297729;
		}
		loc_esi = dest + (ReadInt32(buff + 1) -  vma);

		if (!CompareBuffer(dest, dsize, loc_esi, 12))
		{
			return -1;
		}
		original_ep = ReadInt32(loc_esi);
		loc_esi += 4;
		loc_esi += 4;

		original_ep -= vma;
		DBGMessage("Upack: EP: %08x original:  %08X || %08x\n", ep, original_ep, ReadInt32(loc_esi-8));

		if (upack_version == UPACK_399)
		{
			loc_edi = dest + (ReadInt32(loc_esi) -  vma);
			if (!CompareBuffer(dest, dsize, dest+ep+0xa, 2) || dest[ep+0xa] != '\xeb')
			{
				return -1;
			}
			loc_esi = dest + *(dest + ep + 0xb) + ep + 0xc;

			alvalue = loc_esi+0x1a;
			if (!CompareBuffer(dest, dsize, alvalue, 2) || *alvalue != '\xeb')
			{
				return -1;
			}
			alvalue++;
			alvalue += (*alvalue&0xff) + 1 + 0xa;
			lngjmpoff = 8;
		}
		else
		{
			if (!CompareBuffer(dest, dsize, dest+ep+7, 5) || dest[ep+7] != '\xe9')
			{
				return -1;
			}
			loc_esi = dest + ReadInt32(dest + ep + 8) + ep + 0xc;
			alvalue = loc_esi + 0x25;
			lngjmpoff = 10;
		}

		if (!CompareBuffer(dest, dsize, alvalue, 2) || *alvalue != '\xb5')
		{
			return -1;
		}
		alvalue++;
		count = *alvalue&0xff;

		if (!CompareBuffer(dest, dsize, alvalue, lngjmpoff+5) || *(alvalue+lngjmpoff) != '\xe9')
		{
			return -1;
		}
		shlsize = ReadInt32(alvalue + lngjmpoff+1);
		if (upack_version == UPACK_399)
		{
			shlsize = shlsize + (loc_esi - dest) + *(loc_esi+0x1b) + 0x1c + 0x018;
		}
		else
		{
			shlsize = shlsize + (loc_esi - dest) + 0x035;
		}
		alvalue = dest+shlsize+43;

		aljump = 8;
		shroff = 24;
		if (!CompareBuffer(dest, dsize, alvalue-1, 2) || *(alvalue-1) != '\xe3')
		{
			alvalue = dest+shlsize+46;
			if (!CompareBuffer(dest, dsize, alvalue-1, 2) || *(alvalue-1) != '\xe3')
			{
				return -1;
			}
			else
			{
				if (upack_version != UPACK_0297729)
				{
					upack_version = UPACK_0151477;
				}
				aljump = 7;
				shroff = 26;
			}

		}
		alvalue += (*alvalue&0xff) + 1;
		if (!CompareBuffer(dest, dsize, alvalue, aljump+5) || *(alvalue+aljump) != '\xe9')
		{
			return -1;
		}
		ret = ReadInt32(alvalue+aljump+1);
		alvalue += ret + aljump+1+4 + 27;
		if (upack_version == UPACK_0297729)
			alvalue += 2;

		if (!CompareBuffer(dest, dsize, dest+shlsize+shroff, 3) || *(dest+shlsize+shroff) != '\xc1' || *(dest+shlsize+shroff+1) != '\xed')
		{
			return -1;
		}
		shlsize = (*(dest + shlsize + shroff+2))&0xff;
		count *= 0x100;
		if (shlsize < 2 || shlsize > 8)
		{
			DBGMessage ("Upack: context bits out of bounds\n");
			return -1;
		}
		DBGMessage("Upack: Context Bits parameter used with lzma: %02x, %02x\n", shlsize, count);
		if (upack_version == UPACK_0297729)
		{
			if (!CompareBuffer(dest, dsize, loc_esi+6, 10) || *(loc_esi+6) != '\xbe' || *(loc_esi+11) != '\xbf')
			{
				return -1;
			}
			if ((uint32_t)ReadInt32(loc_esi + 7) < base || (uint32_t)ReadInt32(loc_esi+7) > vma)
			{
				return -1;
			}
			loc_edi = dest + (ReadInt32(loc_esi + 12) - vma);
			loc_esi = dest + (ReadInt32(loc_esi + 7) - base);
		} 
		else
		{
			if (!CompareBuffer(dest, dsize, loc_esi+7, 5) || *(loc_esi+7) != '\xbe')
			{
				return -1;
			}
			loc_esi = dest + (ReadInt32(loc_esi + 8) - vma);
		}

		if (upack_version == UPACK_0297729)
		{
			if (!CompareBuffer(dest, dsize, loc_edi, (0x58 + 24 + 4*count)) || !CompareBuffer(dest, dsize, loc_esi, (0x58 + 0x64 + 4)))
			{
				return -1;
			}

			for (j=0; j<0x16; j++, loc_esi+=4, loc_edi+=4)
				WriteInt32(loc_edi, ReadInt32(loc_esi)); 
		} 
		else
		{
			if (!CompareBuffer(dest, dsize, loc_edi, (0x9c + 24 + 4*count)) || !CompareBuffer(dest, dsize, loc_esi, (0x9c + 0x34 + 4)))
			{
				return -1;
			}
			for (j=0; j<0x27; j++, loc_esi+=4, loc_edi+=4)
				WriteInt32(loc_edi, ReadInt32(loc_esi)); 
		}
		save3 = ReadInt32(loc_esi + 4);
		paddr = dest + ((uint32_t)ReadInt32(loc_edi - 4)) - vma;
		loc_ebx = loc_edi;
		WriteInt32(loc_edi, 0xffffffff);
		loc_edi+=4;
		WriteInt32(loc_edi, 0);
		loc_edi+=4;
		for (j=0; j<4; j++, loc_edi+=4)
			WriteInt32(loc_edi, (1));

		for (j=0; (unsigned int)j<count; j++, loc_edi+=4)
			WriteInt32(loc_edi, 0x400);

		loc_edi = dest + ReadInt32(loc_esi + 0xc) - vma;
		if (upack_version == UPACK_0297729)
		{
			loc_edi = dest+vma-base;
		}

		pushed_esi = loc_edi;
		end_edi = dest + ReadInt32(loc_esi + 0x34) - vma;
		if (upack_version == UPACK_0297729)
		{
			end_edi = dest + ReadInt32(loc_esi + 0x64) - vma;
			save3 = ReadInt32(loc_esi + 0x40);
		}
		/* begin end */
		DBGMessage("Upack: data initialized, before upack lzma call!\n");
		if ((ret = (uint32_t)UnPackUPack399(dest, dsize, 0, loc_ebx, 0, loc_edi, end_edi, shlsize, paddr)) == 0xffffffff)
		{
			return -1;
		}

	} 
	else 
	{
		int ep_jmp_offs, rep_stosd_count_offs, context_bits_offs;
		loc_esi = dest + vma + ep;

		if (buff[0] == '\xbe' && buff[5] == '\xad' && buff[6] == '\x8b' && buff[7] == '\xf8')
		{
			upack_version = UPACK_11_12;
		}

		if (upack_version == UPACK_11_12)
		{
			ep_jmp_offs = 0x1a4;
			rep_stosd_count_offs = 0x1b;
			context_bits_offs = 0x41;
			alvalue = loc_esi + 0x184;
		} 
		else 
		{
			ep_jmp_offs = 0x217;
			rep_stosd_count_offs = 0x3a;
			context_bits_offs = 0x5f;
			alvalue = loc_esi + 0x1c1;
		}

		if (!CompareBuffer(dest, dsize, loc_esi, ep_jmp_offs+4))
		{
			return -1;
		}
		save1 = ReadInt32(loc_esi + ep_jmp_offs);
		original_ep = (loc_esi - dest) + ep_jmp_offs + 4;
		original_ep += (int32_t)save1;
		DBGMessage("Upack: EP: %08x original %08x\n", ep, original_ep);

		count = (*(loc_esi + rep_stosd_count_offs))&0xff;
		shlsize = (*(loc_esi + context_bits_offs))&0xff;
		shlsize = 8 - shlsize;
		if (shlsize < 2 || shlsize > 8)
		{
			DBGMessage ("Upack: context bits out of bounds\n");
			return -1;
		}
		count *= 0x100;
		DBGMessage("Upack: Context Bits parameter used with lzma: %02x, %02x\n", shlsize, count);
		if (upack_version == UPACK_399)
		{
			loc_esi += 4;
			loc_ecx = ReadInt32(loc_esi+2);
			WriteInt32(loc_esi+2,0);
			if (!loc_ecx)
			{
				DBGMessage("Upack: something's wrong, report back\n");
				return -1;
			}
			loc_esi -= (loc_ecx - 2);
			if (!CompareBuffer(dest, dsize, loc_esi, 12))
			{
				return -1;
			}

			DBGMessage("Upack: %08x %08x %08x %08x\n", loc_esi, dest, ReadInt32(loc_esi), base);
			loc_ebx_u = loc_esi - (dest + ReadInt32(loc_esi) - base);
			DBGMessage("Upack: EBX: %08x\n", loc_ebx_u);
			loc_esi += 4;
			save2 = loc_edi = dest + ReadInt32(loc_esi) - base;
			DBGMessage("Upack: DEST: %08x, %08x\n", ReadInt32(loc_esi), ReadInt32(loc_esi) - base);
			loc_esi += 4;
			j = ReadInt32(loc_esi);
			if (j<0)
			{
				DBGMessage("Upack: probably hand-crafted data, report back\n");
				return -1;
			}
			loc_esi += 4;
			DBGMessage("Upack: ecx counter: %08x\n", j);

			if (!CompareBuffer(dest, dsize, loc_esi, (j*4)) || !CompareBuffer(dest, dsize, loc_edi, ((j+count)*4)))
			{
				return -1;
			}
			for (;j--; loc_edi+=4, loc_esi+=4)
				WriteInt32(loc_edi, ReadInt32(loc_esi));
			if (!CompareBuffer(dest, dsize, save2, 8))
			{
				return -1;
			}
			loc_ecx = ReadInt32(save2);
			save2 += 4;
			loc_esi = save2;
			do
			{
				loc_esi += loc_ebx_u;
				loc_esi += 4;
			} while (--loc_ecx);
			if (!CompareBuffer(dest, dsize, loc_esi, 4))
			{
				return -1;
			}
			save1 = ReadInt32(loc_esi); 
			loc_esi += 4;

			for (j=0; j<count; j++, loc_edi+=4) 
				WriteInt32(loc_edi, (save1));

			if (!CompareBuffer(dest, dsize, (loc_esi+0x10), 4))
			{
				return -1;
			}
			WriteInt32(loc_esi+0x10, (uint32_t)ReadInt32(loc_esi+0x10)+loc_ebx_u);
			loc_ebx = loc_esi+0x14;
			loc_esi = save2;
			save_edi = loc_edi = dest + ((uint32_t)ReadInt32(loc_esi) - base);
			loc_esi +=4;
			DBGMessage("Upack: before_fixing\n");
			
			if (!CompareBuffer(dest, dsize, loc_ebx-4, (12 + 4*4)) || !CompareBuffer(dest, dsize, loc_esi+0x24, 4) || !CompareBuffer(dest, dsize, loc_esi+0x40, 4))
			{
				return -1;
			}
			for (j=2; j<6; j++)
				WriteInt32(loc_ebx+(j<<2), ReadInt32(loc_ebx+(j<<2)));
			paddr = dest + ReadInt32(loc_ebx - 4) - base;
			save1 = loc_ecx;
			pushed_esi = loc_edi;
			end_edi = dest + ReadInt32(loc_esi+0x24) - base;
			vma = ReadInt32(loc_ebx); WriteInt32(loc_ebx, ReadInt32(loc_ebx + 4)); WriteInt32((loc_ebx + 4), vma);
		}
		else if (upack_version == UPACK_11_12) 
		{
			DBGMessage("Upack v 1.1/1.2\n");
			loc_esi = dest + 0x148; 
			loc_edi = dest + ReadInt32(loc_esi) - base;
			loc_esi += 4;
			save_edi = loc_edi;
			/* movsd */
			paddr = dest + ((uint32_t)ReadInt32(loc_esi)) - base;
			loc_esi += 4;
			loc_edi += 4;
			loc_ebx = loc_edi;

			if (!CompareBuffer(dest, dsize, loc_edi, ((6+count)*4)))
			{
				return -1;
			}
			WriteInt32(loc_edi, 0xffffffff);
			loc_edi += 4;
			WriteInt32(loc_edi, 0);
			loc_edi += 4;
			for (j=0; j<4; j++, loc_edi+=4)
				WriteInt32(loc_edi, (1));

			for (j=0; j<count; j++, loc_edi+=4)
				WriteInt32(loc_edi, 0x400);

			loc_edi = dest + ReadInt32(loc_esi) - base; 
			pushed_esi = loc_edi;
			loc_esi += 4;
			loc_ecx = 0;

			loc_esi += 4;

			end_edi = dest + ReadInt32(loc_esi-0x28) - base; 
			loc_esi = save_edi;
		}
		DBGMessage("Upack: data initialized, before upack lzma call!\n");
		if ((ret = (uint32_t)UnPackUPack399(dest, dsize, loc_ecx, loc_ebx, loc_ecx, loc_edi, end_edi, shlsize, paddr)) == 0xffffffff)
		{
			return -1;
		}
		if (upack_version == UPACK_399)
		{
			save3 = ReadInt32(loc_esi + 0x40);
		}
		else if (upack_version == UPACK_11_12)
		{
			save3 = ReadInt32(dest + vma + ep + 0x174);
		}
	}

	loc_ecx = 0;
	if (!CompareBuffer(dest, dsize, alvalue, 1)) 
	{
		DBGMessage("Upack: alvalue out of bounds\n");
		return -1;
	}

	searchval = *alvalue&0xff;
	DBGMessage("Upack: loops: %08x search value: %02x\n", save3, searchval);
	while(save3) 
	{
		if (!CompareBuffer(dest, dsize, pushed_esi + loc_ecx, 1))
		{
			DBGMessage("Upack: callfixerr %08x %08x = %08x, %08x\n", dest, dsize, dest+dsize, pushed_esi+loc_ecx);
			return -1;
		}
		if (pushed_esi[loc_ecx] == '\xe8' || pushed_esi[loc_ecx] == '\xe9')
		{
			char *adr = (pushed_esi + loc_ecx + 1);
			loc_ecx++;
			if (!CompareBuffer(dest, dsize, adr, 4))
			{
				DBGMessage("Upack: callfixerr\n");
				return -1;
			}
			if ((ReadInt32(adr)&0xff) != searchval)
				continue;
			WriteInt32(adr, EC32(CE32((uint32_t)(ReadInt32(adr)&0xffffff00)))-loc_ecx-4);
			loc_ecx += 4;
			save3--;
		} 
		else 
			loc_ecx++;
	}

	section.raw = 0;
	section.rva = va;
	section.rsz = end_edi-loc_edi;
	section.vsz = end_edi-loc_edi;

	if (!RebuildFakePE(dest + (upack?0:va), &section, 1, base, original_ep, 0, 0, file)) 
	{
		DBGMessage("Upack: Rebuilding failed\n");
		return 0;
	}
	return 1;
}


/*--------------------------------------------------------------------------------------
Function       : UnPackUPack399
In Parameters  : char *bs, uint32_t bl, uint32_t init_eax, char *init_ebx, uint32_t init_ecx, char *init_edi, char *end_edi, uint32_t shlsize, char *paddr, 
Out Parameters : int 
Description    : Unpacks the Appliction which is Packed by the UPACK
Author & Date  :
--------------------------------------------------------------------------------------*/
int UnPackUPack399(char *bs, uint32_t bl, uint32_t init_eax, char *init_ebx, uint32_t init_ecx, char *init_edi, char *end_edi, uint32_t shlsize, char *paddr)
{
	struct lzmastate p;
	uint32_t loc_eax, ret, loc_al, loc_ecx = init_ecx, loc_ebp, eax_copy = init_eax, temp, i, jakas_kopia;
	uint32_t state[6], temp_ebp;
	char *loc_edx, *loc_ebx = init_ebx, *loc_edi = init_edi, *loc_ebp8, *edi_copy;
	p.p0 = paddr;
	p.p1 = ReadInt32(init_ebx);
	p.p2 = ReadInt32(init_ebx + 4);

	DBGMessage("\n\tp0: %08x\n\tp1: %08x\n\tp2: %08x\n", p.p0, p.p1, p.p2);
	for (i = 0; i<6; i++)
		state[i] = ReadInt32(loc_ebx + (i<<2)),
		DBGMessage("state[%d] = %08x\n", i, state[i]);
	do 
	{
		loc_eax = eax_copy;
		loc_edx = loc_ebx + (loc_eax<<2) + 0x58;

		if ((ret = Lzma_UPack_ESI_00(&p, loc_edx, bs, bl)))
		{
			/* loc_483927 */
			loc_al = loc_eax&0xff;
			loc_al = ((loc_al + 0xf9) > 0xff)?(3+8):8;
			loc_eax = (loc_eax&0xffffff00)|(loc_al&0xff);
			loc_ebp = state[2];
			loc_ecx = (loc_ecx&0xffffff00)|0x30;
			loc_edx += loc_ecx;

			if (!(ret = Lzma_UPack_ESI_00(&p, loc_edx, bs, bl)))
			{

				loc_eax--;

				temp_ebp = loc_ebp;
				loc_ebp = state[4];
				state[4] = state[3];
				state[3] = temp_ebp;
				eax_copy = loc_eax;
				loc_edx = loc_ebx + 0xbc0;
				state[5] = loc_ebp;
				if (Lzma_UPack_ESI_54(&p, loc_eax, &loc_ecx, &loc_edx, &temp, bs, bl) == 0xffffffff)
				{
					return -1;
				}
				loc_ecx = 3;
				jakas_kopia = temp;
				loc_eax = temp-1;
				if (loc_eax >= loc_ecx)
					loc_eax = loc_ecx;
				loc_ecx = 0x40;
				loc_eax <<= 6; 
				loc_ebp8 = loc_ebx + ((loc_eax<<2) + 0x378);
				if (Lzma_UPack_ESI_50(&p, 1, loc_ecx, &loc_edx, loc_ebp8, &loc_eax, bs, bl) == 0xffffffff)
				{
					return -1;
				}
				loc_ebp = loc_eax;
				if ((loc_eax&0xff) >= 4)
				{
					loc_ebp = 2 + (loc_eax&1);
					loc_eax >>= 1;
					loc_eax--;
					temp_ebp = loc_eax; loc_eax = loc_ecx; loc_ecx = temp_ebp;
					loc_ebp <<= (loc_ecx&0xff);
					loc_edx = loc_ebx + (loc_ebp<<2) + 0x178;
					if ((loc_ecx&0xff) > 5)
					{
						loc_ecx = (loc_ecx&0xffffff00)|(((loc_ecx&0xff)-4)&0xff);
						loc_eax = 0;
						do 
						{
							uint32_t temp_edx;
							if (!CompareBuffer(bs, bl, p.p0, 4))
							{
								return -1;
							}
							temp_edx = ReadInt32((char *)p.p0);
							temp_edx = EC32(CE32(temp_edx));
							p.p1 >>= 1;
							temp_edx -= p.p2;
							loc_eax <<= 1;
							if (temp_edx >= p.p1)
							{
								temp_edx = p.p1;
								loc_eax++;
								p.p2 += temp_edx;
							}
							if(((p.p1)&0xff000000) == 0)
							{
								p.p2 <<= 8;
								p.p1 <<= 8;
								p.p0++;
							}
						} while (--loc_ecx);
						loc_ecx = (loc_ecx&0xffffff00)|4;
						loc_eax <<= 4;
						loc_ebp += loc_eax;
						loc_edx = loc_ebx + 0x18;
					}
					loc_eax = 1;
					loc_eax <<= (loc_ecx&0xff);
					loc_ebp8 = loc_edx;
					temp_ebp = loc_ecx; loc_ecx = loc_eax; loc_eax = temp_ebp;
					if (Lzma_UPack_ESI_50(&p, 1, loc_ecx, &loc_edx, loc_ebp8, &loc_eax, bs, bl) == 0xffffffff)
					{
						return -1;
					}
					loc_ecx = temp_ebp;
					temp_ebp = MAX_SRS((int32_t)loc_eax, 31); 

					do 
					{
						temp_ebp += temp_ebp;
						temp_ebp += (loc_eax&1);
						loc_eax >>= 1;
					} while (--loc_ecx);
					loc_ebp += temp_ebp;
				}

				loc_ebp++;
				loc_ecx = jakas_kopia;
			} else 
			{
				loc_edx += loc_ecx;
				if ((ret = Lzma_UPack_ESI_00(&p, loc_edx, bs, bl)))
				{
					loc_edx += 0x60;
					if ((ret = Lzma_UPack_ESI_00(&p, loc_edx, bs, bl)))
					{
						loc_edx += loc_ecx;
						ret = Lzma_UPack_ESI_00(&p, loc_edx, bs, bl);
						temp_ebp = loc_ebp;
						loc_ebp = state[4];
						state[4] = state[3];
						state[3] = temp_ebp;
						if (ret)
						{
							temp_ebp = loc_ebp; loc_ebp = state[5]; state[5] = temp_ebp;
						}
					} 
					else 
					{
						temp_ebp = loc_ebp; loc_ebp = state[3]; state[3] = temp_ebp;
					}
				}
				else
				{
					loc_edx += loc_ecx;
					if ((ret = Lzma_UPack_ESI_00(&p, loc_edx, bs, bl))) 
					{
					}
					else 
					{
						loc_eax |= 1;
						eax_copy = loc_eax;
						edi_copy = loc_edi;
						edi_copy -= state[2];
						loc_ecx = (loc_ecx&0xffffff00)|0x80;
						if (!CompareBuffer(bs, bl, edi_copy, 1) || !CompareBuffer(bs, bl, loc_edi, 1))
						{
							return -1;
						}
						loc_al = (*(uint8_t *)edi_copy)&0xff;
						*loc_edi++ = loc_al;
						continue;
					}
				}
				eax_copy = loc_eax;
				loc_edx = loc_ebx + 0x778;
				if (Lzma_UPack_ESI_54(&p, loc_eax, &loc_ecx, &loc_edx, &temp, bs, bl) == 0xffffffff)
				{
					return -1;
				}
				loc_eax = loc_ecx;
				loc_ecx = temp;
			}
			if (!CompareBuffer(bs, bl, loc_edi, loc_ecx) || !CompareBuffer(bs, bl, loc_edi-loc_ebp, loc_ecx+1))
			{
				return -1;
			}
			state[2] = loc_ebp;
			for (i=0; i<loc_ecx; i++, loc_edi++)
				*loc_edi = *(loc_edi - loc_ebp);
			loc_eax = (loc_eax&0xffffff00)|*(uint8_t *)(loc_edi - loc_ebp);
			loc_ecx = 0x80;
		}
		else 
		{
			do 
			{
				if ( (loc_al = (loc_eax&0xff)) + 0xfd > 0xff)
				{
					loc_al -= 3; 
				}
				else
				{
					loc_al = 0;
				}
				loc_eax = (loc_eax&0xffffff00)|loc_al;
			} while (loc_al >= 7);

			eax_copy = loc_eax;
			if (loc_edi > init_edi && loc_edi < bl+bs)
			{
				loc_ebp = (*(uint8_t *)(loc_edi - 1)) >> shlsize;
			} 
			else 
			{
				loc_ebp = 0;
			}
			loc_ebp *= (int)0x300; 
			loc_ebp8 = loc_ebx + ((loc_ebp<<2) + 0x1008);

			edi_copy = loc_edi;

			loc_eax = (loc_eax&0xffffff00)|1;
			if (loc_ecx) 
			{
				uint8_t loc_cl = loc_ecx&0xff;
				loc_edi -= state[2];
				if (!CompareBuffer(bs, bl, loc_edi, 1))
					return -1;
				do 
				{
					loc_eax = (loc_eax&0xffff00ff)|((*loc_edi & loc_cl)?0x200:0x100);

					loc_edx = loc_ebp8 + (loc_eax<<2);
					ret = Lzma_UPack_ESI_00(&p, loc_edx, bs, bl);
					loc_al = loc_eax&0xff;
					loc_al += loc_al;
					loc_al += ret;
					loc_al &= 0xff;
					loc_eax = (loc_eax&0xffffff00)|loc_al;
					loc_cl >>= 1;
					if (loc_cl)
					{
						uint8_t loc_ah = (loc_eax>>8)&0xff;
						loc_ah -= loc_al;
						loc_ah &= 1;
						if (!loc_ah)
						{
							loc_eax = (loc_eax&0xffff0000)|(loc_ah<<8)|loc_al;

							if (Lzma_UPack_ESI_50(&p, loc_eax, 0x100, &loc_edx, loc_ebp8, &loc_eax, bs, bl) == 0xffffffff)
								return -1;
							break;
						}
					} 
					else
						break;
				} while(1);
			} 
			else
			{
				loc_ecx = (loc_ecx&0xffff00ff)|0x100;
				if (Lzma_UPack_ESI_50(&p, loc_eax, loc_ecx, &loc_edx, loc_ebp8, &loc_eax, bs, bl) == 0xffffffff)
				{
					return -1;
				}
			}
			loc_ecx = 0;
			loc_edi = edi_copy;
		}
		if (!CompareBuffer(bs, bl, loc_edi, 1))
		{
			return -1;
		}
		*loc_edi++ = (loc_eax&0xff);
	} while (loc_edi < end_edi);

	return 1;
}
