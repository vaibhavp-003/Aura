/*
* aPLib compression library  -  the smaller the better :)
*
* C safe depacker
*
* Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
* All Rights Reserved
*
* http://www.ibsensoftware.com/
*/

#include "depacks.h"

/* internal data structure */
typedef struct {
	const unsigned char *source;
	unsigned int srclen;
	unsigned char *destination;
	unsigned int dstlen;
	unsigned int tag;
	unsigned int bitcount;
} APDEPACKSAFEDATA;

static int aP_getbit_safe(APDEPACKSAFEDATA *ud, unsigned int *result, int iCType)
{
	unsigned int bit;
	unsigned int bit1;

	bit1=0;


	if(iCType==0x01 || iCType==0x04)
	{

		if(((ud->tag<<1)&0x000000FF)==0x00000000)
		{
			if (!ud->srclen--) return 0;

			/* load next tag */
			bit1=(ud->tag >> 7) & 0x01;
			ud->tag = *ud->source++;
			ud->bitcount = 7;
		}
	}
	else if(iCType==0x02)
	{
		if(((ud->tag<<1)&0xFFFFFFFF)==0x00)
		{
			if (!(ud->srclen-4)) return 0;
			ud->tag = *(unsigned int*)(ud->source);
			ud->source+=0x04;
			ud->bitcount = 7;
			bit1=0x01;
		}
		bit = (ud->tag >> 0x1F) & 0x01;
		ud->tag <<= 1;
		if(bit1)
		{
			ud->tag+=1;
		}
	}
	else
	{
		/* check if tag is empty */
		if (!ud->bitcount--)
		{
			if (!ud->srclen--) return 0;

			/* load next tag */
			ud->tag = *ud->source++;
			ud->bitcount = 7;
		}
	}

	/* shift bit out of tag */

	if(iCType!=0x02)
	{
		bit = (ud->tag >> 7) & 0x01;
		ud->tag <<= 1;
		ud->tag+=bit1;
	}



	*result = bit;

	return 1;
}

static int aP_getgamma_safe(APDEPACKSAFEDATA *ud, unsigned int *result,int iCType)
{
	unsigned int bit;
	unsigned int v = 1;

	/* input gamma2-encoded bits */
	do {

		if (!aP_getbit_safe(ud, &bit,iCType)) return 0;

		v = (v << 1) + bit;

		if (!aP_getbit_safe(ud, &bit,iCType)) return 0;

	} while (bit);

	*result = v;

	return 1;
}

unsigned int aP_depack_safe(const void *source,
							unsigned int srclen,
							void *destination,
							unsigned int dstlen,
							int iCType,
							unsigned int *ActualSrclen)
{
	APDEPACKSAFEDATA ud;
	unsigned int offs, len, R0 = 0xFFFFFFFF, LWM, bit;
	int done, i, iR0set = 0;

	if (!source || !destination) return APLIB_ERROR;

	ud.source = (const unsigned char *) source;
	ud.srclen = srclen;
	ud.destination = (unsigned char *) destination;
	ud.dstlen = dstlen;
	ud.bitcount = 0;

	LWM = 0;
	done = 0;

	/* first byte verbatim */
	if (!ud.srclen-- || !ud.dstlen--) return APLIB_ERROR;
	*ud.destination++ = *ud.source++;

	if(iCType==0x01 || iCType==0x04)
	{
		ud.tag=0x80;
	}
	else if(iCType==0x02)
	{
		ud.tag=0x00;
	}
	/* main decompression loop */
	while (!done)
	{
		if (!aP_getbit_safe(&ud, &bit,iCType)) return APLIB_ERROR;

		if (bit)
		{
			if (!aP_getbit_safe(&ud, &bit,iCType)) return APLIB_ERROR;

			if (bit)
			{
				if (!aP_getbit_safe(&ud, &bit,iCType)) return APLIB_ERROR;

				if (bit)
				{
					offs = 0;

					for (i = 4; i; i--)
					{
						if (!aP_getbit_safe(&ud, &bit,iCType)) return APLIB_ERROR;
						offs = (offs << 1) + bit;
					}

					if (offs)
					{
						if (offs > (dstlen - ud.dstlen)) return APLIB_ERROR;

						if (!ud.dstlen--) return APLIB_ERROR;

						*ud.destination = *(ud.destination - offs);
						ud.destination++;

					} else {

						if (!ud.dstlen--) return APLIB_ERROR;

						*ud.destination++ = 0x00;
					}

					LWM = 0;

				} else {

					if (!ud.srclen--) return APLIB_ERROR;

					offs = *ud.source++;

					len = 2 + (offs & 0x0001);

					offs >>= 1;

					if (offs)
					{
						if (offs > (dstlen - ud.dstlen)) return APLIB_ERROR;

						if (len > ud.dstlen) return APLIB_ERROR;

						ud.dstlen -= len;

						for (; len; len--)
						{
							*ud.destination = *(ud.destination - offs);
							ud.destination++;
						}
					} else done = 1;

					R0 = offs;
					iR0set = 1;
					LWM = 1;
				}

			} else {

				if (!aP_getgamma_safe(&ud, &offs,iCType)) return APLIB_ERROR;

				if ((LWM == 0||iCType==0x01||iCType==0x04) && (offs == 2))
				{
					if(!iR0set)
					{
						return APLIB_ERROR;
					}
					offs = R0;

					if (!aP_getgamma_safe(&ud, &len,iCType)) return APLIB_ERROR;

					if (offs > (dstlen - ud.dstlen)) return APLIB_ERROR;

					if (len > ud.dstlen) return APLIB_ERROR;

					ud.dstlen -= len;

					for (; len; len--)
					{
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}

				} else {

					if(iCType!=0x01 && iCType!=0x04)
					{
						if (LWM == 0) offs -= 3; else offs -= 2;
					}
					else
					{
						offs -= 2;
					}

					if (!ud.srclen--) return APLIB_ERROR;

					if(iCType==0x01 || iCType==0x04)
					{
						if(offs>0)
						{
							offs--;
						}
					}
					offs <<= 8;
					offs += *ud.source++;

					if(iCType==0x04)
					{
						//Just added temp
						if (!aP_getbit_safe(&ud, &bit,iCType)) return APLIB_ERROR;

						offs+=offs;
						if(bit)
						{
							offs+=1;
						}
					}
					if (!aP_getgamma_safe(&ud, &len,iCType)) return APLIB_ERROR;

					if (offs >= 32000) len++;
					if (offs >= 1280) len++;
					if (offs < 128) len += 2;

					if (offs > (dstlen - ud.dstlen)) return APLIB_ERROR;

					if (len > ud.dstlen) return APLIB_ERROR;

					ud.dstlen -= len;

					for (; len; len--)
					{
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}

					R0 = offs;
					iR0set = 1;
				}

				LWM = 1;
			}

		} else {

			if (!ud.srclen-- || !ud.dstlen--) return APLIB_ERROR;
			*ud.destination++ = *ud.source++;
			LWM = 0;
		}
	}

	if(ActualSrclen)
	{
		*ActualSrclen=ud.source - (unsigned char *) source;
	}
	return ud.destination - (unsigned char *) destination;
}

