
/*======================================================================================
FILE             : NsPackUnpack.c
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
				  
	CREATION DATE    : 12/19/2009 4:41:14 PM
	NOTES		     : Defines the Functionality to Unpack the Application Which Packed by NSPACK
	VERSION HISTORY  : 
	======================================================================================*/
#include <stdlib.h>
#include "Packers.h"

/*--------------------------------------------------------------------------------------
Function       : UnPackNSPack
In Parameters  : char *start_of_stuff, char *dest, uint32_t rva, uint32_t base, uint32_t ep, void* file 
Out Parameters : uint32_t 
Description    : To Unpack the Appliction which packed by NSPACK
Author & Date  : Siddharam Pujari & 23 Dec, 2009.
--------------------------------------------------------------------------------------*/
uint32_t UnPackNSPack(char *start_of_stuff, char *dest) 
{
	uint8_t c = *start_of_stuff;
	uint32_t i,firstbyte,tre,allocsz,tablesz,dsize,ssize;
	uint16_t *table;
	char *dst = dest;
	char *src = start_of_stuff+0xd;

	if (c>=0xe1) return 1;

	if (c>=0x2d) 
	{
		firstbyte = i = c/0x2d;
		do {c+=0xd3;} while (--i);
	} else firstbyte = 0;

	if (c>=9) 
	{
		allocsz = i = c/9;
		do {c+=0xf7;} while (--i);
	} else allocsz = 0;

	tre = c;
	i = allocsz;
	c = (tre+i)&0xff;
	tablesz = ((0x300<<c)+0x736)*sizeof(uint16_t);
	DBGMessage("unsp: table size = %d\n", tablesz);
	if (!(table = MaxMalloc(tablesz))) return 1;

	dsize = ReadInt32(start_of_stuff+9);
	ssize = ReadInt32(start_of_stuff+5);
	if (ssize <= 13) 
	{
		free(table);
		return 1;
	}

	tre = Very_Real_UnPack(table,tablesz,tre,allocsz,firstbyte,src,ssize,dst,dsize);
	free(table);
	if (tre) return 1;

	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : Very_Real_UnPack
In Parameters  : uint16_t *table, uint32_t tablesz, uint32_t tre, uint32_t allocsz, uint32_t firstbyte, char *src, uint32_t ssize, char *dst, uint32_t dsize, 
Out Parameters : uint32_t 
Description    : UnPack's the Buffer
Author & Date  : Siddharam Pujari & 23 Dec, 2009.
--------------------------------------------------------------------------------------*/
uint32_t Very_Real_UnPack(uint16_t *table, uint32_t tablesz, uint32_t tre, uint32_t allocsz, uint32_t firstbyte, char *src, uint32_t ssize, char *dst, uint32_t dsize) 
{
	struct UNSP read_struct;
	uint32_t i = (0x300<<((allocsz+tre)&0xff)) + 0x736;

	uint32_t previous_bit = 0;
	uint32_t unpacked_so_far = 0;
	uint32_t backbytes = 1;
	uint32_t oldbackbytes = 1;
	uint32_t old_oldbackbytes = 1;
	uint32_t old_old_oldbackbytes = 1;

	uint32_t damian = 0;
	uint32_t put = (1<<(allocsz&0xff))-1;

	uint32_t bielle = 0;

	firstbyte = (1<<(firstbyte&0xff))-1;

	if (tablesz < i*sizeof(uint16_t)) return 2;

	/* init table */
	while (i) table[--i]=0x400;

	/* table noinit */

	/* get_five - inlined */
	read_struct.error = 0;
	read_struct.oldval = 0;
	read_struct.src_curr = src;
	read_struct.bitmap = 0xffffffff;
	read_struct.src_end = src + ssize - 1; /*- 13;*/
	read_struct.table = (char *)table;
	read_struct.tablesz = tablesz;

	for ( i = 0; i<5 ; i++) read_struct.oldval = (read_struct.oldval<<8) | GetByte(&read_struct);
	if (read_struct.error) return 1;

	while (1)
	{
		uint32_t backsize = firstbyte&unpacked_so_far;
		uint32_t tpos;
		uint32_t temp = damian;

		if (read_struct.error)
		{
			return 1; /* checked once per mainloop, keeps the code readable and it's still safe */
		}

		if (!GetBit_From_Table(&table[(damian<<4) + backsize], &read_struct))
		{
			uint32_t shft = 8 - (tre&0xff);
			shft &= 0xff;
			tpos = (bielle>>shft) + ((put&unpacked_so_far)<<(tre&0xff));
			tpos *=3;
			tpos<<=8;

			if ((int32_t)damian>=4) 
			{
				if ((int32_t)damian>=0xa) {
					damian -= 6;
				} 
				else 
				{
					damian -= 3;
				}
			} else {
				damian=0;
			}

			if (previous_bit) 
			{
				if (!CompareBuffer(dst, dsize, &dst[unpacked_so_far - backbytes], 1)) 
				{
					return 1;
				}
				ssize = (ssize&0xffffff00) | (uint8_t)dst[unpacked_so_far - backbytes]; /* FIXME! ssize is not static */
				bielle = Get_100_Bits_From_Tablesize(&table[tpos+0x736], &read_struct, ssize);
				previous_bit=0;
			}
			else
			{
				bielle = Get_100_Bits_From_Table(&table[tpos+0x736], &read_struct);
			}

			/* unpack_one_byte - duplicated */
			if (!CompareBuffer(dst, dsize, &dst[unpacked_so_far], 1)) 
			{
				return 1;
			}
			dst[unpacked_so_far] = bielle;
			unpacked_so_far++;
			if (unpacked_so_far>=dsize) return 0;
			continue;

		}
		else
		{ /* got_mainbit */

			bielle = previous_bit = 1;

			if (GetBit_From_Table(&table[damian+0xc0], &read_struct))
			{
				if (!GetBit_From_Table(&table[damian+0xcc], &read_struct)) 
				{
					tpos = damian+0xf;
					tpos <<=4;
					tpos += backsize;
					if (!GetBit_From_Table(&table[tpos], &read_struct)) 
					{
						if (!unpacked_so_far) return bielle; 

						damian = 2*((int32_t)damian>=7)+9; /* signed */
						if (!CompareBuffer(dst, dsize, &dst[unpacked_so_far - backbytes], 1)) return 1;
						bielle = (uint8_t)dst[unpacked_so_far - backbytes];
						dst[unpacked_so_far] = bielle;
						unpacked_so_far++;
						if (unpacked_so_far>=dsize) return 0;
						continue;

					} 
					else 
					{ 
						backsize = Get_n_Bits_From_Tablesize(&table[0x534], &read_struct, backsize);
						damian = ((int32_t)damian>=7); /* signed */
						damian = ((damian-1) & 0xfffffffd)+0xb;
					}
				} else {
					if (!GetBit_From_Table(&table[damian+0xd8], &read_struct))
					{
						tpos = oldbackbytes;
					} 
					else
					{
						if (!GetBit_From_Table(&table[damian+0xe4], &read_struct)) 
						{
							tpos = old_oldbackbytes;
						} else {
							tpos = old_old_oldbackbytes;
							old_old_oldbackbytes = old_oldbackbytes;
						}
						old_oldbackbytes = oldbackbytes;
					}
					oldbackbytes = backbytes;
					backbytes = tpos;

					backsize = Get_n_Bits_From_Tablesize(&table[0x534], &read_struct, backsize);
					damian = ((int32_t)damian>=7); /* signed */
					damian = ((damian-1) & 0xfffffffd)+0xb;
				} 
			} 
			else 
			{ 

				old_old_oldbackbytes = old_oldbackbytes;
				old_oldbackbytes = oldbackbytes;
				oldbackbytes = backbytes;

				damian = ((int32_t)damian>=7); /* signed */
				damian = ((damian-1) & 0xfffffffd)+0xa;

				backsize = Get_n_Bits_From_Tablesize(&table[0x332], &read_struct, backsize);

				tpos = ((int32_t)backsize>=4)?3:backsize; /* signed */
				tpos<<=6;
				tpos = Get_n_Bits_From_Table(&table[0x1b0+tpos], 6, &read_struct);

				if (tpos>=4)
				{ /* signed */

					uint32_t s = tpos;
					s>>=1;
					s--;

					temp = (tpos & bielle) | 2;
					temp<<=(s&0xff);


					if ((int32_t)tpos<0xe)
					{
						temp += Get_bb(&table[(temp-tpos)+0x2af], s, &read_struct);
					} else
					{
						s += 0xfffffffc;
						tpos = Get_BitMap(&read_struct, s);
						tpos <<=4;
						temp += tpos;
						temp += Get_bb(&table[0x322], 4, &read_struct);
					}
				} 
				else
				{
					backbytes = temp = tpos;
				}
				backbytes = temp+1;
			}

			if (!backbytes) return 0;
			if (backbytes > unpacked_so_far) return bielle;

			backsize +=2;

			if (!CompareBuffer(dst, dsize, &dst[unpacked_so_far], backsize) ||
				!CompareBuffer(dst, dsize, &dst[unpacked_so_far - backbytes], backsize)
				) 
			{
				DBGMessage("%x %x %x %x\n", dst, dsize, &dst[unpacked_so_far], backsize);
				return 1;
			}

			do 
			{
				dst[unpacked_so_far] = dst[unpacked_so_far - backbytes];
				unpacked_so_far++;
			} while (--backsize && unpacked_so_far<dsize);
			bielle = (uint8_t)dst[unpacked_so_far - 1];

			if (unpacked_so_far>=dsize) 
			{
				return 0;
			}

		} 
	} 
}

/*--------------------------------------------------------------------------------------
Function       : GetByte
In Parameters  : struct UNSP *read_struct, 
Out Parameters : uint32_t 
Description    : Reads the Byte From Structure
Author & Date  : Siddharam Pujari & 23 Dec, 2009.
--------------------------------------------------------------------------------------*/
uint32_t GetByte(struct UNSP *read_struct) 
{

	uint32_t ret;

	if (read_struct->src_curr >= read_struct->src_end)
	{
		read_struct->error = 1;
		return 0xff;
	}
	ret = *(read_struct->src_curr);
	read_struct->src_curr++;
	return ret&0xff;
}

/*--------------------------------------------------------------------------------------
Function       : GetBit_From_Table
In Parameters  : uint16_t *intable, struct UNSP *read_struct, 
Out Parameters : int 
Description    : Get Bit From the Table
Author & Date  :  & 24 Dec, 2009.
--------------------------------------------------------------------------------------*/
int GetBit_From_Table(uint16_t *intable, struct UNSP *read_struct) 
{

	uint32_t nval;
	if (!CompareBuffer((char *)read_struct->table, read_struct->tablesz, (char *)intable, sizeof(uint16_t)))
	{
		read_struct->error = 1;
		return 0xff;
	}
	nval = *intable * (read_struct->bitmap>>0xb);

	if (read_struct->oldval<nval)
	{ /* unsigned */
		uint32_t sval;
		read_struct->bitmap = nval;
		nval = *intable;
		sval = 0x800 - nval;
		sval = MAX_SRS((int32_t)sval,5); /* signed */
		sval += nval;
		*intable=sval;
		if (read_struct->bitmap<0x1000000)
		{ /* unsigned */
			read_struct->oldval = (read_struct->oldval<<8) | GetByte(read_struct);
			read_struct->bitmap<<=8;
		}
		return 0;
	}

	read_struct->bitmap -= nval;
	read_struct->oldval -= nval;

	nval = *intable;
	nval -= (nval>>5); /* word, unsigned */
	*intable=nval;

	if (read_struct->bitmap<0x1000000) 
	{ /* unsigned */
		read_struct->oldval = (read_struct->oldval<<8) | GetByte(read_struct);
		read_struct->bitmap<<=8;
	}

	return 1;
}


/*--------------------------------------------------------------------------------------
Function       : Get_100_Bits_From_Tablesize
In Parameters  : uint16_t *intable, struct UNSP *read_struct, uint32_t ssize, 
Out Parameters : uint32_t 
Description    : Gets 100 bits from Table Size
Author & Date  :
--------------------------------------------------------------------------------------*/
uint32_t Get_100_Bits_From_Tablesize(uint16_t *intable, struct UNSP *read_struct, uint32_t ssize) 
{

	uint32_t count = 1;

	while (count<0x100)
	{
		uint32_t lpos, tpos;
		lpos = ssize&0xff;
		ssize=(ssize&0xffffff00)|((lpos<<1)&0xff);
		lpos>>=7;
		tpos = lpos+1;
		tpos<<=8;
		tpos+=count;
		tpos = GetBit_From_Table(&intable[tpos], read_struct);
		count=(count*2)|tpos;
		if (lpos!=tpos)
		{
			/* second loop */
			while (count<0x100)
				count = (count*2)|GetBit_From_Table(&intable[count], read_struct);
		}
	} 
	return count&0xff;
}


/*--------------------------------------------------------------------------------------
Function       : Get_100_Bits_From_Table
In Parameters  : uint16_t *intable, struct UNSP *read_struct, 
Out Parameters : uint32_t 
Description    : Gets 100 bits from Table Size
Author & Date  :
--------------------------------------------------------------------------------------*/
uint32_t Get_100_Bits_From_Table(uint16_t *intable, struct UNSP *read_struct) 
{
	uint32_t count = 1;

	while (count<0x100)
		count = (count*2)|GetBit_From_Table(&intable[count], read_struct);
	return count&0xff;
}


/*--------------------------------------------------------------------------------------
Function       : Get_n_Bits_From_Table
In Parameters  : uint16_t *intable, uint32_t bits, struct UNSP *read_struct, 
Out Parameters : uint32_t 
Description    : Gets n bits from Table
Author & Date  :
--------------------------------------------------------------------------------------*/
uint32_t Get_n_Bits_From_Table(uint16_t *intable, uint32_t bits, struct UNSP *read_struct)
{
	uint32_t count = 1;
	uint32_t bitcounter;

	bitcounter = bits;
	while (bitcounter--)
		count = count*2 + GetBit_From_Table(&intable[count], read_struct);
	
	return count-(1<<(bits&0xff));
}


/*--------------------------------------------------------------------------------------
Function       : Get_n_Bits_From_Tablesize
In Parameters  : uint16_t *intable, struct UNSP *read_struct, uint32_t backsize, 
Out Parameters : uint32_t 
Description    : Gets n bits from Table Size
Author & Date  :
--------------------------------------------------------------------------------------*/
uint32_t Get_n_Bits_From_Tablesize(uint16_t *intable, struct UNSP *read_struct, uint32_t backsize) 
{

	if (!GetBit_From_Table(intable, read_struct))
	{
		return Get_n_Bits_From_Table(&intable[(backsize<<3)+2], 3, read_struct);
	}

	if (!GetBit_From_Table(&intable[1], read_struct))
	{
		return 8+Get_n_Bits_From_Table(&intable[(backsize<<3)+0x82], 3, read_struct);
	}

	return 0x10+Get_n_Bits_From_Table(&intable[0x102], 8, read_struct);
}


/*--------------------------------------------------------------------------------------
Function       : Get_bb
In Parameters  : uint16_t *intable, uint32_t back, struct UNSP *read_struct, 
Out Parameters : uint32_t 
Description    : Gets bb from the table
Author & Date  :
--------------------------------------------------------------------------------------*/
uint32_t Get_bb(uint16_t *intable, uint32_t back, struct UNSP *read_struct)
{
	uint32_t pos = 1;
	uint32_t bb = 0;
	uint32_t i;

	if ((int32_t)back<=0) 
	{
		return 0;
	}

	for (i=0;i<back;i++)
	{
		uint32_t bit = GetBit_From_Table(&intable[pos], read_struct);
		pos=(pos*2) + bit;
		bb|=(bit<<i);
	}
	return bb;
}


/*--------------------------------------------------------------------------------------
Function       : Get_BitMap
In Parameters  : struct UNSP *read_struct, uint32_t bits, 
Out Parameters : uint32_t 
Description    : gets the BitMap
Author & Date  :
--------------------------------------------------------------------------------------*/
uint32_t Get_BitMap(struct UNSP *read_struct, uint32_t bits) 
{
	uint32_t retv = 0;

	if ((int32_t)bits<=0) return 0; 

	while (bits--) 
	{
		read_struct->bitmap>>=1; 
		retv<<=1;
		if (read_struct->oldval>=read_struct->bitmap) 
		{ 
			read_struct->oldval-=read_struct->bitmap;
			retv|=1;
		}
		if (read_struct->bitmap<0x1000000) 
		{
			read_struct->bitmap<<=8;
			read_struct->oldval = (read_struct->oldval<<8) | GetByte(read_struct);
		}
	}
	return retv;
}
