/*======================================================================================
FILE             : MewUnPack.c
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
				  
	CREATION DATE    : 12/19/2009 4:17:19 PM
	NOTES		     : To Unpack the Application Which is packed by MEW Packer
	VERSION HISTORY  : 
======================================================================================*/
#include <stdio.h>
#include "Packers.h"
#include "excpt.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define EC32(x) le32_to_host(x) /* Convert little endian to host */
#define CE32(x) be32_to_host(x) /* Convert big endian to host */
#define PEALIGN(o,a) (((a))?(((o)/(a))*(a)):(o))
#define PESALIGN(o,a) (((a))?(((o)/(a)+((o)%(a)!=0))*(a)):(o))

/*--------------------------------------------------------------------------------------
Function       : *lzma_bswap_4861dc
In Parameters  : struct lzmastate *p, char *old_edx, 
Out Parameters : static char 
Description    : Lzma Swap
Author & Date  :
--------------------------------------------------------------------------------------*/
static char *lzma_bswap_4861dc(struct lzmastate *p, char *old_edx)
{
	/* dumb_dump_start
	*

	old_edx was 'uint32_t *' before and in mew_lzma there was
	&new_edx where new_edx = var1C

	uint32_t loc_esi, loc_edi;
	uint8_t *loc_eax;

	p->p2 = loc_esi = 0;
	p->p0 = loc_eax = (uint8_t *)*old_edx;
	*old_edx = 5;
	do {
	loc_esi = p->p2 << 8;
	loc_edi = *(uint8_t *)((loc_eax)++);
	loc_esi |= loc_edi;
	(*old_edx)--;
	p->p2 = loc_esi;
	} while (*old_edx);
	p->p0 = loc_eax;
	p->p1 = 0xffffffff;

	* dumb_dump_end
	*/

	/* XXX, mine replacement */
	p->p2 = EC32(CE32(((uint32_t)ReadInt32(old_edx + 1))));
	p->p1 = 0xffffffff;
	p->p0 = old_edx + 5;

	return p->p0;
}

/*--------------------------------------------------------------------------------------
Function       : lzma_486248 
In Parameters  : struct lzmastate *p, char **old_ecx, char *src, uint32_t size, 
Out Parameters : static uint32_t 
Description    : Lzma Unpacks
Author & Date  :
--------------------------------------------------------------------------------------*/
static uint32_t lzma_486248 (struct lzmastate *p, char **old_ecx, char *src, uint32_t size)
{
	uint32_t loc_esi, loc_edi, loc_eax, loc_ecx, ret;
	if (!CompareBuffer(src, size, *old_ecx, 4) || !CompareBuffer(src, size, p->p0, 1))
	{
		return 0xffffffff;
	}
	loc_esi = p->p1;
	loc_eax = loc_esi >> 0xb;
	loc_ecx = ReadInt32(*old_ecx);
	ret = loc_ecx&0xffff;
	(loc_eax) *=  ret;
	loc_edi = p->p2;
	if (loc_edi < loc_eax)
	{
		p->p1 = loc_eax;
		loc_esi = ret;
		loc_edi = ((int32_t)(0x800 - ret) >> 5) + ((loc_eax&0xffff0000) | ret); 
		loc_ecx = (loc_ecx&0xffff0000)|(loc_edi&0xffff);
		WriteInt32(*old_ecx, loc_ecx);

		ret = 0;
	} 
	else 
	{
		loc_esi -= loc_eax;
		loc_edi -= loc_eax;
		p->p1 = loc_esi;
		p->p2 = loc_edi;
		loc_eax = (loc_eax & 0xffff0000) | ret;
		loc_esi = (loc_esi & 0xffff0000) | (ret >> 5);
		loc_eax -= loc_esi;

		loc_ecx = (loc_ecx&0xffff0000)|(loc_eax&0xffff);
		WriteInt32(*old_ecx, loc_ecx);

		ret = 1;
	}
	loc_eax = p->p1;
	if (loc_eax < 0x1000000)
	{
		*old_ecx = p->p0;
		loc_edi = (*(uint8_t *)(p->p0));
		loc_esi = ((p->p2) << 8) | loc_edi;
		(*old_ecx)++;
		loc_eax <<= 8;
		p->p2 = loc_esi;
		p->p1 = loc_eax;
		p->p0 = *old_ecx;
	}
	return ret;

}

/*--------------------------------------------------------------------------------------
Function       : lzma_48635C
In Parameters  : uint8_t znaczek, char **old_ecx, struct lzmastate *p, uint32_t *retval, char *src, uint32_t size, 
Out Parameters : static uint32_t 
Description    : Unpacks Lzma
Author & Date  :
--------------------------------------------------------------------------------------*/
static uint32_t lzma_48635C(uint8_t znaczek, char **old_ecx, struct lzmastate *p, uint32_t *retval, char *src, uint32_t size)
{
	uint32_t loc_esi = (znaczek&0xff) >> 7,
		loc_ebx, ret;
	char *loc_edi;
	znaczek <<= 1;
	ret = loc_esi << 9;
	loc_edi = *old_ecx;
	*old_ecx = loc_edi + ret + 0x202;
	if ((ret = lzma_486248 (p, old_ecx, src, size)) == 0xffffffff)
		return 0xffffffff;
	loc_ebx = ret | 2;

	while (loc_esi == ret)
	{
		if (loc_ebx >= 0x100)
		{
			ret = (ret&0xffffff00) | (loc_ebx&0xff);
			*retval = ret;
			return 0;
		}
		loc_esi = (znaczek&0xff) >> 7;
		znaczek <<= 1;
		ret = ((loc_esi + 1) << 8) + loc_ebx;
		*old_ecx = loc_edi + ret*2;
		if ((ret = lzma_486248 (p, old_ecx, src, size)) == 0xffffffff)
			return 0xffffffff;
		loc_ebx += loc_ebx;
		loc_ebx |= ret;
	}
	loc_esi = 0x100;
	while (loc_ebx < loc_esi)
	{
		loc_ebx += loc_ebx;
		*old_ecx = loc_edi + loc_ebx;
		if ((ret = lzma_486248 (p, old_ecx, src, size)) == 0xffffffff)
			return 0xffffffff;
		loc_ebx |= ret;
	}
	ret = (ret&0xffffff00) | (loc_ebx&0xff);
	*retval = ret;
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : lzma_4862e0 
In Parameters  : struct lzmastate *p, char **old_ecx, uint32_t *old_edx, uint32_t *retval, char *src, uint32_t size, 
Out Parameters : static uint32_t 
Description    : Lazma Unpacks
Author & Date  :
--------------------------------------------------------------------------------------*/
static uint32_t lzma_4862e0 (struct lzmastate *p, char **old_ecx, uint32_t *old_edx, uint32_t *retval, char *src, uint32_t size)
{
	uint32_t loc_ebx, loc_esi, stack_ecx, ret;
	char *loc_edi;

	loc_ebx = *old_edx;
	ret = 1;
	loc_edi = *old_ecx;
	if (loc_ebx && !(loc_ebx&0x80000000))
	{
		stack_ecx = loc_ebx;
		do
		{
			loc_esi = ret+ret;
			*old_ecx = loc_edi + loc_esi;
			if ((ret = lzma_486248 (p, old_ecx, src, size)) == 0xffffffff)
				return 0xffffffff;
			ret += loc_esi;
			stack_ecx--;
		} while (stack_ecx);
	} 
	*old_edx = 1 << (loc_ebx&0xff);
	ret -= *old_edx;
	*retval = ret;
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : lzma_4863da 
In Parameters  : uint32_t var0, struct lzmastate *p, char  **old_ecx, uint32_t *old_edx, uint32_t *retval, char *src, uint32_t size, 
Out Parameters : static uint32_t 
Description    : Lazma Unpacks
Author & Date  :
--------------------------------------------------------------------------------------*/
static uint32_t lzma_4863da (uint32_t var0, struct lzmastate *p, char  **old_ecx, uint32_t *old_edx, uint32_t *retval, char *src, uint32_t size)
{
	uint32_t ret;
	char *loc_esi = *old_ecx;

	if ((ret = lzma_486248 (p, old_ecx, src, size)) == 0xffffffff)
	{
		return -1;
	}
	if (ret)
	{
		*old_ecx = loc_esi+2;
		if ((ret = lzma_486248 (p, old_ecx, src, size)) == 0xffffffff)
		{
			return -1;
		}
		if (ret)
		{
			*old_edx = 8;
			*old_ecx = loc_esi + 0x204;
			if (lzma_4862e0 (p, old_ecx, old_edx, &ret, src, size) == 0xffffffff)
			{
				return -1;
			}
			ret += 0x10;
		}
		else 
		{
			ret = var0 << 4;
			*old_edx = 3;
			*old_ecx = loc_esi + 0x104 + ret;
			if (lzma_4862e0 (p, old_ecx, old_edx, &ret, src, size) == 0xffffffff)
			{
				return -1;
			}
			ret += 0x8;
		}
	}
	else 
	{
		ret = var0 << 4;
		*old_edx = 3;
		*old_ecx = loc_esi + 0x4 + ret;
		if (lzma_4862e0 (p, old_ecx, old_edx, &ret, src, size) == 0xffffffff)
		{
			return -1;
		}
	}
	*retval = ret;
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : lzma_486204 
In Parameters  : struct lzmastate *p, uint32_t old_edx, uint32_t *retval, char *src, uint32_t size, 
Out Parameters : static uint32_t 
Description    : 
Author & Date  :
--------------------------------------------------------------------------------------*/
static uint32_t lzma_486204 (struct lzmastate *p, uint32_t old_edx, uint32_t *retval, char *src, uint32_t size)
{
	uint32_t loc_esi, loc_edi, loc_ebx, loc_eax;
	char *loc_edx;
	loc_esi = p->p1;
	loc_edi = p->p2;
	loc_eax = 0;
	if (old_edx && !(old_edx&0x80000000))
	{
		/* loc_4866212 */
		loc_ebx = old_edx;
		do
		{
			loc_esi >>= 1;
			loc_eax <<= 1;
			if (loc_edi >= loc_esi)
			{
				loc_edi -= loc_esi;
				loc_eax |= 1;
			}
			if (loc_esi < 0x1000000)
			{
				if (!CompareBuffer(src, size, p->p0, 1))
				{
					return 0xffffffff;
				}
				loc_edx = p->p0;
				loc_edi <<= 8;
				loc_esi <<= 8;
				loc_edi |= (*loc_edx)&0xff; /* movzx ebp, byte ptr [edx] */
				p->p0 = ++loc_edx;
			}
			loc_ebx--;
		} while (loc_ebx);

	}
	p->p2 = loc_edi;
	p->p1 = loc_esi;
	*retval = loc_eax;
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : lzma_48631a 
In Parameters  : struct lzmastate *p, char **old_ecx, uint32_t *old_edx, uint32_t *retval, char *src, uint32_t size, 
Out Parameters : static uint32_t 
Description    : Lazma Unpacks
Author & Date  :
--------------------------------------------------------------------------------------*/
static uint32_t lzma_48631a (struct lzmastate *p, char **old_ecx, uint32_t *old_edx, uint32_t *retval, char *src, uint32_t size)
{
	uint32_t copy1, copy2;
	uint32_t loc_esi, loc_edi, ret;
	char *loc_ebx;

	copy1 = *old_edx;
	loc_edi = 0;
	loc_ebx = *old_ecx;
	*old_edx = 1;
	copy2 = (uint32_t)loc_edi;

	if (copy1 <= (uint32_t)loc_edi)
	{
		*retval = copy2;
		return 0;
	}

	do 
	{
		loc_esi = *old_edx + *old_edx;
		*old_ecx = loc_esi + loc_ebx;
		if ((ret = lzma_486248 (p, old_ecx, src, size)) == 0xffffffff)
		{
			return 0xffffffff;
		}
		*old_edx = loc_esi + ret;
		ret <<= (loc_edi&0xff);
		copy2 |= ret;
		loc_edi++;
	} while (loc_edi < copy1);

	*retval = copy2;
	return 0;
}


/*--------------------------------------------------------------------------------------
Function       : Mew_Lzma
In Parameters  : char *orgsource, char *buf, uint32_t size_sum, uint32_t vma, uint32_t special, 
Out Parameters : int 
Description    : Checks for Mew LZMA
Author & Date  :
--------------------------------------------------------------------------------------*/
int Mew_Lzma(char *orgsource, char *buf, uint32_t size_sum, uint32_t vma, uint32_t special)
{
	uint32_t var08, var0C, var10, var14, var20, var24, var28, var34;
	struct lzmastate var40;
	uint32_t new_eax, new_edx, temp;
	int i, mainloop;

	char var1, var30;
	char *source = buf, *dest, *new_ebx, *new_ecx, *var0C_ecxcopy, *var2C;
	char *pushed_esi = NULL, *pushed_ebx = NULL;
	uint32_t pushed_edx=0;

	uint32_t loc_esi, loc_edi;
	uint8_t *var18;

	if (special)
	{
		pushed_edx = ReadInt32(source);
		source += 4;
	}
	temp = ReadInt32(source) - vma;
	source += 4;
	if (!special) pushed_ebx = source;
	new_ebx = orgsource + temp;

	do
	{
		mainloop = 1;
		do
		{
			if (!special)
			{
				source = pushed_ebx;
				if (ReadInt32(source) == 0)
				{
					return 0;
				}
			}
			var28 = ReadInt32 (source);
			source += 4;
			temp = ReadInt32 (source) - vma;
			var18 = (uint8_t *)(orgsource + temp);
			if (special) pushed_esi = orgsource + temp;
			source += 4;
			temp = ReadInt32 (source);
			source += 5; /* yes, five */
			var2C = source;
			source += temp;
			if (special) pushed_ebx = source;
			else pushed_ebx = source;
			var1 = 0;
			dest = new_ebx;

			if(!CompareBuffer(orgsource, size_sum, dest, 0x6E6C))
				return -1;
			for (i=0; i<0x1b9b; i++)
			{
				WriteInt32(dest, 0x4000400);
				dest += 4;
			}
			loc_esi = 0;
			var08 = var20 = 0;
			loc_edi = 1;
			var14 = var10 = var24 = 1;

			lzma_bswap_4861dc(&var40, var2C);
			new_edx = 0;
		} while (var28 <= loc_esi); /* source = 0 */

		DBGMessage("MEWlzma: entering do while loop\n");
		do 
		{
			new_eax = var08 & 3;
			new_ecx = (((loc_esi << 4) + new_eax)*2) + new_ebx;
			var0C = new_eax;
			if ((new_eax = lzma_486248 (&var40, &new_ecx, orgsource, size_sum)) == 0xffffffff)
				return -1;
			if (new_eax)
			{
				new_ecx = new_ebx + loc_esi*2 + 0x180;
				var20 = 1;
				/* eax=1 */
				if ((new_eax = lzma_486248 (&var40, &new_ecx, orgsource, size_sum)) == 0xffffffff)
					return -1;
				if (new_eax != 1)
				{
					var24 = var10;
					var10 = var14;
					new_eax = loc_esi>=7 ? 10:7;
					new_ecx = new_ebx + 0x664;
					var14 = loc_edi;
					loc_esi = new_eax;
					if (lzma_4863da (var0C, &var40, &new_ecx, &new_edx, &new_eax, orgsource, size_sum) == 0xffffffff)
						return -1;
					var0C = new_eax;
					if (var0C >= 4)
						new_eax = 3;

					new_edx = 6;
					new_eax <<= 7;
					new_ecx = new_eax + new_ebx + 0x360;
					if (lzma_4862e0 (&var40, &new_ecx, &new_edx, &new_eax, orgsource, size_sum) == 0xffffffff)
						return -1;
					if (new_eax < 4)
					{ 
						loc_edi = new_eax;
					} else {
						uint32_t loc_ecx;
						loc_ecx = ((int32_t)new_eax >> 1)-1; /* sar */
						loc_edi = ((new_eax&1)|2) << (loc_ecx&0xff);
						if (new_eax >= 0xe)
						{
							new_edx = loc_ecx - 4;
							if (lzma_486204 (&var40, new_edx, &new_eax, orgsource, size_sum) == 0xffffffff)
								return -1;
							loc_edi += new_eax << 4;

							new_edx = 4;
							new_ecx = new_ebx + 0x644;
						} 
						else 
						{
							new_edx = loc_ecx;
							loc_ecx = loc_edi - new_eax;
							new_ecx =  new_ebx + loc_ecx*2 + 0x55e;
						}
						if (lzma_48631a (&var40, &new_ecx, &new_edx, &new_eax, orgsource, size_sum) == 0xffffffff)
							return -1;
						loc_edi += new_eax;
					}
					loc_edi++;
				}
				else 
				{
					new_ecx = new_ebx + loc_esi*2 + 0x198;
					if ((new_eax = lzma_486248 (&var40, &new_ecx, orgsource, size_sum)) == 0xffffffff)
						return -1;
					if (new_eax)
					{
						new_ecx = new_ebx + loc_esi*2 + 0x1B0;
						if ((new_eax = lzma_486248 (&var40, &new_ecx, orgsource, size_sum)) == 0xffffffff)
							return -1;
						if (new_eax)
						{
							new_ecx = new_ebx + loc_esi*2 + 0x1C8;
							if ((new_eax = lzma_486248 (&var40, &new_ecx, orgsource, size_sum)) == 0xffffffff)
								return -1;
							if (new_eax)
							{
								new_eax = var24;
								var24 = var10;
							} 
							else 
							{
								new_eax = var10;
							}
							var10 = var14;
						} 
						else
						{
							new_eax = var14;
						}
						var14 = loc_edi;
						loc_edi = new_eax;
					} 
					else
					{
						new_eax = ((loc_esi + 0xf) << 4) + var0C;
						new_ecx = new_ebx + new_eax*2;
						if ((new_eax = lzma_486248 (&var40, &new_ecx, orgsource, size_sum)) == 0xffffffff)
							return -1;
						if (!new_eax) {
							uint32_t loc_ecx;
							loc_ecx = var08;
							loc_ecx -= loc_edi;
							loc_esi = loc_esi>=7 ? 11:9;
							if (!CompareBuffer((uint8_t *)orgsource, size_sum, var18 + loc_ecx, 1))
								return -1;
							var1 = *(var18 + loc_ecx);
							loc_ecx = (loc_ecx&0xffffff00) | var1;
							new_edx = var08++;
							if (!CompareBuffer((uint8_t *)orgsource, size_sum, var18 + new_edx, 1))
								return -1;
							*(var18 + new_edx) = loc_ecx & 0xff;

							new_eax = var08;
							continue; /* !!! */
						}

					}
					new_ecx = new_ebx + 0xa68;
					if (lzma_4863da (var0C, &var40, &new_ecx, &new_edx, &new_eax, orgsource, size_sum) == 0xffffffff)
						return -1;
					var0C = new_eax;
					new_eax = loc_esi>=7 ? 11:8;
					loc_esi = new_eax;
				}
				if (!loc_edi)
				{
					break;
				} 
				else 
				{
					var0C += 2;
					new_ecx = (char *)var18;
					new_edx = new_eax = var08;
					new_eax -= loc_edi;
					if ( ((var0C < var28 - new_edx) &&
						(!CompareBuffer(orgsource, size_sum, (char*)(new_ecx + new_eax), var0C) || 
						!CompareBuffer(orgsource, size_sum, (char*)(new_ecx + new_edx), var0C))) ||
						(!CompareBuffer(orgsource, size_sum, (char*)(new_ecx + new_eax), var28 - new_edx) ||
						!CompareBuffer(orgsource, size_sum, (char*)(new_ecx + new_edx), var28 - new_edx)) )
						return -1;
					do
					{
						var1 = *(uint8_t *)(new_ecx + new_eax);
						*(uint8_t *)(new_ecx + new_edx) = var1;

						new_edx++;
						new_eax++;
						var0C--;
						if (var0C <= 0)
							break;
					} while (new_edx < var28);
					var08 = new_edx;
				}
			} else
			{
				new_eax = (((var1 & 0xff) >> 4)*3) << 9;
				new_ecx = new_eax + new_ebx + 0xe6c;
				var0C_ecxcopy = new_ecx;
				if (loc_esi >= 4)
				{
					if (loc_esi >= 10)
						loc_esi -= 6;
					else
						loc_esi -= 3;

				} else {
					/* loc_4864e4 */
					loc_esi = 0;
				}

				if (var20 == 0)	
				{
					new_eax = 1;
					do
					{
						new_eax += new_eax;
						new_ecx += new_eax;
						var34 = new_eax;
						if ((new_eax = lzma_486248(&var40, &new_ecx, orgsource, size_sum)) == 0xffffffff)
							return -1;
						new_eax |= var34;
						if (new_eax < 0x100)
						{
							new_ecx = var0C_ecxcopy;
						}
					} while (new_eax < 0x100);
					var1 = (uint8_t)(new_eax & 0xff);
				} 
				else 
				{
					int t;
					new_eax = var08 - loc_edi;
					if (!CompareBuffer((uint8_t *)orgsource, size_sum, var18 + new_eax, 1))
						return -1;
					t = *(var18+new_eax);
					new_eax = (new_eax&0xffffff00) | t;

					var30 = t;
					if (lzma_48635C (t, &new_ecx, &var40, &new_eax, orgsource, size_sum) == 0xffffffff)
						return -1;
					var20 = 0;
					var1 = new_eax&0xff;
				}

				new_edx = var08++;

				if (!CompareBuffer((uint8_t *)orgsource, size_sum, var18 + new_edx, 1))
					return -1;
				*(var18 + new_edx) = var1;
			}
			new_eax = var08;
		} while (new_eax < var28);

		if (special) 
		{
			uint32_t loc_ecx;
			loc_ecx = 0;
			
			if (!CompareBuffer(orgsource, size_sum, pushed_esi, pushed_edx))
				return -1;
			__try{
				do 
				{
					if (pushed_esi[loc_ecx] == '\xe8' || pushed_esi[loc_ecx] == '\xe9')
					{
						char *adr = (char *)(pushed_esi + loc_ecx + 1);
						loc_ecx++;

						WriteInt32(adr, EC32(CE32((uint32_t)ReadInt32(adr)))-loc_ecx);
						loc_ecx += 4;
					} 
					else 
						loc_ecx++;
				} while (loc_ecx < pushed_edx);//} while (loc_ecx != pushed_edx);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				printf("Exception in MEW:size_sum%d..loc_ecx:%d,pushed_edx:%d",size_sum,loc_ecx,pushed_edx);
				return -1;
			}
			return 0; 
		}
	} while (mainloop);

	return 0xbadc0de;
}

/*--------------------------------------------------------------------------------------
Function       : Lzma_UPack_ESI_00
In Parameters  : struct lzmastate *p, char *old_ecx, char *bb, uint32_t bl, 
Out Parameters : uint32_t 
Description    : Lzma Unpacks the ESI
Author & Date  :
--------------------------------------------------------------------------------------*/
uint32_t Lzma_UPack_ESI_00(struct lzmastate *p, char *old_ecx, char *bb, uint32_t bl)
{
	uint32_t loc_eax, ret, loc_edi;
	loc_eax = p->p1 >> 0xb;
	if (!CompareBuffer(bb, bl, old_ecx, 4) || !CompareBuffer(bb, bl, p->p0, 4))
	{
		if (!CompareBuffer(bb, bl, old_ecx, 4))
			printf("contain error! %08x %08x ecx: %08x [%08x]\n", bb, bl, old_ecx,bb+bl);
		else
			printf("contain error! %08x %08x p0: %08x [%08x]\n", bb, bl, p->p0,bb+bl);
		return 0xffffffff;
	}
	ret = ReadInt32(old_ecx);
	loc_eax *= ret;
	loc_edi = ReadInt32((char *)p->p0);
	loc_edi = EC32(CE32(loc_edi)); /* bswap */
	loc_edi -= p->p2;
	if (loc_edi < loc_eax)
	{
		p->p1 = loc_eax;
		loc_eax = (0x800 - ret) >> 5;
		WriteInt32(old_ecx, ReadInt32(old_ecx) + loc_eax);
		ret = 0;
	} else {
		p->p2 += loc_eax;
		p->p1 -= loc_eax;
		loc_eax = ret >> 5;
		WriteInt32(old_ecx, ReadInt32(old_ecx) - loc_eax);
		ret = 1;
	}
	if(((p->p1)&0xff000000) == 0)
	{
		p->p2 <<= 8;
		p->p1 <<= 8;
		p->p0++;
	}
	return ret;
}

/*--------------------------------------------------------------------------------------
Function       : Lzma_UPack_ESI_50
In Parameters  : struct lzmastate *p, uint32_t old_eax, uint32_t old_ecx, char **old_edx, char *old_ebp, uint32_t *retval, char *bs, uint32_t bl, 
Out Parameters : uint32_t 
Description    : Unpacks Lzma ESI 50
Author & Date  :
--------------------------------------------------------------------------------------*/
uint32_t Lzma_UPack_ESI_50(struct lzmastate *p, uint32_t old_eax, uint32_t old_ecx, char **old_edx, char *old_ebp, uint32_t *retval, char *bs, uint32_t bl)
{
	uint32_t loc_eax = old_eax, original = old_eax, ret;

	do
	{
		*old_edx = old_ebp + (loc_eax<<2);
		if ((ret = Lzma_UPack_ESI_00(p, *old_edx, bs, bl)) == 0xffffffff)
			return 0xffffffff;
		loc_eax += loc_eax;
		loc_eax += ret;
	} while (loc_eax < old_ecx);

	*retval = loc_eax - old_ecx;
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : Lzma_UPack_ESI_54
In Parameters  : struct lzmastate *p, uint32_t old_eax, uint32_t *old_ecx, char **old_edx, uint32_t *retval, char *bs, uint32_t bl, 
Out Parameters : uint32_t 
Description    : Upacks Lzma ESI 54
Author & Date  :
--------------------------------------------------------------------------------------*/
uint32_t Lzma_UPack_ESI_54(struct lzmastate *p, uint32_t old_eax, uint32_t *old_ecx, char **old_edx, uint32_t *retval, char *bs, uint32_t bl)
{
	uint32_t ret, loc_eax = old_eax;

	*old_ecx = ((*old_ecx)&0xffffff00)|8;
	ret = Lzma_UPack_ESI_00 (p, *old_edx, bs, bl);
	*old_edx = ((*old_edx) + 4);
	loc_eax = (loc_eax&0xffffff00)|1;
	if (ret)
	{
		ret = Lzma_UPack_ESI_00 (p, *old_edx, bs, bl);
		loc_eax |= 8;
		if (ret)
		{
			*old_ecx <<= 5;
			loc_eax = 0x11;
		}
	}
	ret = loc_eax;
	if (Lzma_UPack_ESI_50(p, 1, *old_ecx, old_edx, *old_edx + (loc_eax << 2), &loc_eax, bs, bl) == 0xffffffff)
	{
		return 0xffffffff;
	}

	*retval = ret + loc_eax;
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : UnPackMEW11
In Parameters  : int sectnum, char *src, int off, int ssize, int dsize, uint32_t base, uint32_t vadd, int uselzma, char **endsrc, char **enddst, void* filedesc, 
Out Parameters : int 
Description    : Unpacks the given Application which is packed by MEW
Author & Date  :
--------------------------------------------------------------------------------------*/
int UnPackMEW11(char *src, int off, int ssize, int dsize, uint32_t base, uint32_t vadd, int uselzma, void* filedesc)
{
	uint32_t entry_point, newedi, loc_ds=dsize, loc_ss=ssize;
	char *source = src + dsize + off; /*EC32(section_hdr[sectnum].VirtualSize) + off;*/
	char *lesi = source + 12, *ledi;
	char *f1, *f2;
	int i;
	struct Max_Exe_Sections *section = NULL;
	uint32_t vma = base + vadd, size_sum = ssize + dsize;

	entry_point  = ReadInt32(source + 4);
	newedi = ReadInt32(source + 8);
	ledi = src + (newedi - vma);
	loc_ds = size_sum - (newedi - vma);

	i = 0;
	loc_ss -= 12;
	loc_ss -= off;
	while (1)
	{
		DBGMessage("MEW unpacking section %d (%p->%p)\n", i, lesi, ledi);
		if (!CompareBuffer(src, size_sum, lesi, loc_ss) || !CompareBuffer(src, size_sum, ledi, loc_ds))
		{
			return -1;
		}
		if (UnPackMEW(lesi, ledi, loc_ss, loc_ds, &f1, &f2))
		{
			free(section);
			return -1;
		}

		/* we don't need last section in sections since this is information for fixing imptbl */
		if (!CompareBuffer(src, size_sum, f1, 4))
		{
			free(section);
			return -1;
		}

		loc_ss -= (f1+4-lesi);
		lesi = f1+4;

		ledi = src + (ReadInt32(f1) - vma);
		loc_ds = size_sum - (ReadInt32(f1) - vma);

		if (!uselzma)
		{
			uint32_t val = PESALIGN(f2 - src, 0x1000);
			void *newsect;

			if (i && val < section[i].raw) {
				DBGMessage("MEW: WTF - please report\n");
				free(section);
				return -1;
			}

			if (!(newsect=MaxRealloc(section, (i+2)*sizeof(struct Max_Exe_Sections))))
			{
				printf("MEW: Out of memory\n");
				free(section);
				return -1;
			}

			section = (struct Max_Exe_Sections *)newsect;
			section[0].raw = 0;
			section[0].rva = vadd;
			section[i+1].raw = val;
			section[i+1].rva = val + vadd;
			section[i].rsz = section[i].vsz = ((i)?(val - section[i].raw):val);
		}
		i++;

		if (!ReadInt32(f1))
			break;
	}

	if (uselzma) {
		free(section);

		i = 1;
		if (!CompareBuffer(src, size_sum, src+uselzma+8, 1))
		{
			printf("MEW: couldn't access lzma 'special' tag\n");
			return -1;
		}
		/* 0x50 -> push eax */
		DBGMessage("MEW: lzma %swas used, unpacking\n", (*(src + uselzma+8) == '\x50')?"special ":"");
		if (!CompareBuffer(src, size_sum, f1+4, 20 + 4 + 5))
		{
			DBGMessage("MEW: lzma initialization data not available!\n");
			return -1;
		}

		if(Mew_Lzma(src, f1+4, size_sum, vma, *(src + uselzma+8) == '\x50'))
		{
			return -1;
		}
		loc_ds=PESALIGN(loc_ds, 0x1000);

		section = MaxCalloc(1, sizeof(struct Max_Exe_Sections));
		if(!section)
		{
			printf("MEW: Out of memory\n");
			return -1;
		}

		section[0].raw = 0; section[0].rva = vadd;
		section[0].rsz = section[0].vsz = dsize;
	}
	if (!RebuildFakePE(src, section, i, base, entry_point - base, 0, 0, filedesc))
	{
		//DBGMessage("MEW: Rebuilding failed\n");
		free(section);
		return -1;
	}
	free(section);
	return 1;
}
