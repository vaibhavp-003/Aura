
/*======================================================================================
FILE             : PackersLib.c
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

CREATION DATE    : 12/19/2009 4:21:16 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "Packers.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
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
Function       : UnFSG
In Parameters  : char *source, char *dest, int ssize, int dsize, char **endsrc, char **enddst, 
Out Parameters : int 
Description    : Unpacks the Application Packed by FSG
Author & Date  :
--------------------------------------------------------------------------------------*/
int UnFSG(char *source, char *dest, int ssize, int dsize, char **endsrc, char **enddst)
{
	uint8_t mydl=0x80;
	uint32_t backbytes, backsize, oldback = 0;
	char *csrc = source, *cdst = dest;
	int oob, lostbit = 1;

	if (ssize<=0 || dsize<=0) return -1;
	*cdst++=*csrc++;

	while ( 1 )
	{
		if ((oob=Doubledl(&csrc, &mydl, source, ssize))) 
		{
			if (oob == -1)
				return -1;
			/* 164 */
			backsize = 0;
			if ((oob=Doubledl(&csrc, &mydl, source, ssize)))
			{
				if (oob == -1)
					return -1;
				/* 16a */
				backbytes = 0;
				if ((oob=Doubledl(&csrc, &mydl, source, ssize)))
				{
					if (oob == -1)
						return -1;
					/* 170 */
					lostbit = 1;
					backsize++;
					backbytes = 0x10;
					while ( backbytes < 0x100 )
					{
						if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
							return -1;
						backbytes = backbytes*2+oob;
					}
					backbytes &= 0xff;
					if ( ! backbytes ) 
					{
						if (cdst >= dest+dsize)
							return -1;
						*cdst++=0x00;
						continue;
					}
				}
				else
				{
					/* 18f */
					if (csrc >= source+ssize)
						return -1;
					backbytes = *(unsigned char*)csrc;
					backsize = backsize * 2 + (backbytes & 1);
					backbytes = (backbytes & 0xff)>>1;
					csrc++;
					if (! backbytes)
						break;
					backsize+=2;
					oldback = backbytes;
					lostbit = 0;
				}
			}
			else 
			{
				/* 180 */
				backsize = 1;
				do 
				{
					if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
					{
						return -1;
					}
					backsize = backsize*2+oob;
					if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
					{
						return -1;
					}
				} while (oob);

				backsize = backsize - 1 - lostbit;
				if (! backsize)
				{
					/* 18a */
					backsize = 1;
					do
					{
						if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
						{
							return -1;
						}
						backsize = backsize*2+oob;
						if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
						{
							return -1;
						}
					} while (oob);

					backbytes = oldback;
				} 
				else
				{
					/* 198 */
					if (csrc >= source+ssize)
					{
						return -1;
					}
					backbytes = *(unsigned char*)csrc;
					backbytes += (backsize-1)<<8;
					backsize = 1;
					csrc++;
					do
					{
						if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
						{
							return -1;
						}
						backsize = backsize*2+oob;
						if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
						{
							return -1;
						}
					} while (oob);

					if (backbytes >= 0x7d00)
						backsize++;
					if (backbytes >= 0x500)
						backsize++;
					if (backbytes <= 0x7f)
						backsize += 2;

					oldback = backbytes;
				}
				lostbit = 0;
			}
			if (!CompareBuffer(dest, dsize, cdst, backsize) || !CompareBuffer(dest, dsize, cdst-backbytes, backsize))
			{
				return -1;
			}
			while(backsize--) 
			{
				*cdst=*(cdst-backbytes);
				cdst++;
			}

		}
		else 
		{
			/* 15d */
			if (cdst < dest || cdst >= dest+dsize || csrc < source || csrc >= source+ssize)
			{
				return -1;
			}
			*cdst++=*csrc++;
			lostbit=1;
		}
	}

	if (endsrc) *endsrc = csrc;
	if (enddst) *enddst = cdst;
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : UnPackMEW
In Parameters  : char *source, char *dest, int ssize, int dsize, char **endsrc, char **enddst, 
Out Parameters : int 
Description    : Unpacks the Application which is Packed by MEW
Author & Date  :
--------------------------------------------------------------------------------------*/
int UnPackMEW(char *source, char *dest, int ssize, int dsize, char **endsrc, char **enddst)
{
	uint8_t mydl=0x80;
	uint32_t myeax_backbytes, myecx_backsize, oldback = 0;
	char *csrc = source, *cdst = dest;
	int oob, lostbit = 1;

	*cdst++=*csrc++;

	while ( 1 ) 
	{
		if ((oob=Doubledl(&csrc, &mydl, source, ssize))) 
		{
			if (oob == -1)
			{
				return -1;
			}
			myecx_backsize = 0;
			if ((oob=Doubledl(&csrc, &mydl, source, ssize)))
			{
				if (oob == -1)
					return -1;
				myeax_backbytes = 0;
				if ((oob=Doubledl(&csrc, &mydl, source, ssize))) 
				{
					if (oob == -1)
					{
						return -1;
					}
					lostbit = 1;
					myecx_backsize++;
					myeax_backbytes = 0x10;
					while ( myeax_backbytes < 0x100 ) 
					{
						if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
						{
							return -1;
						}
						myeax_backbytes = myeax_backbytes*2+oob;
					}
					myeax_backbytes &= 0xff;
					if ( ! myeax_backbytes ) 
					{
						if (cdst >= dest+dsize)
						{
							return -1;
						}
						*cdst++=0x00;
						continue;
					}
				} 
				else
				{
					if (csrc >= source+ssize)
					{
						return -1;
					}
					myeax_backbytes = *(unsigned char*)csrc;
					myecx_backsize = myecx_backsize * 2 + (myeax_backbytes & 1);
					myeax_backbytes = (myeax_backbytes & 0xff)>>1;
					csrc++;
					if (! myeax_backbytes)
					{
						break;
					}
					myecx_backsize+=2;
					oldback = myeax_backbytes;
					lostbit = 0;
				}
			} 
			else
			{
				myecx_backsize = 1;
				do
				{
					if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
					{
						return -1;
					}
					myecx_backsize = myecx_backsize*2+oob;
					if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
					{
						return -1;
					}
				} while (oob);

				myecx_backsize = myecx_backsize - 1 - lostbit;
				if (! myecx_backsize) 
				{
					myecx_backsize = 1;
					do 
					{
						if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
						{
							return -1;
						}
						myecx_backsize = myecx_backsize*2+oob;
						if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
						{
							return -1;
						}
					} while (oob);

					myeax_backbytes = oldback;
				}
				else
				{
					/* 198 */
					if (csrc >= source+ssize)
					{
						return -1;
					}
					myeax_backbytes = *(unsigned char*)csrc;
					myeax_backbytes += (myecx_backsize-1)<<8;
					myecx_backsize = 1;
					csrc++;
					do {
						if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
						{
							return -1;
						}
						myecx_backsize = myecx_backsize*2+oob;
						if ((oob=Doubledl(&csrc, &mydl, source, ssize)) == -1)
						{
							return -1;
						}
					} while (oob);

					if (myeax_backbytes >= 0x7d00)
					{
						myecx_backsize++;
					}
					if (myeax_backbytes >= 0x500)
					{
						myecx_backsize++;
					}
					if (myeax_backbytes <= 0x7f)
					{
						myecx_backsize += 2;
					}

					oldback = myeax_backbytes;
				}
				lostbit = 0;
			}
			if (!CompareBuffer(dest, dsize, cdst, myecx_backsize) || !CompareBuffer(dest, dsize, cdst-myeax_backbytes, myecx_backsize))
			{
				DBGMessage("MEW: rete: %d %d %d %d %d || %d %d %d %d %d\n", dest, dsize, cdst, myecx_backsize,
					CompareBuffer(dest, dsize, cdst, myecx_backsize),
					dest, dsize, cdst-myeax_backbytes, myecx_backsize,
					CompareBuffer(dest, dsize, cdst-myeax_backbytes, myecx_backsize) );
				return -1;
			}
			while(myecx_backsize--)
			{
				*cdst=*(cdst-myeax_backbytes);
				cdst++;
			}

		}
		else 
		{
			if (cdst < dest || cdst >= dest+dsize || csrc < source || csrc >= source+ssize)
			{
				DBGMessage("MEW: retf %08x %08x+%08x=%08x, %08x %08x+%08x=%08x\n",
					cdst, dest, dsize, dest+dsize, csrc, source, ssize, source+ssize);
				return -1;
			}
			*cdst++=*csrc++;
			lostbit=1;
		}
	}

	*endsrc = csrc;
	*enddst = cdst;
	return 0;
}
