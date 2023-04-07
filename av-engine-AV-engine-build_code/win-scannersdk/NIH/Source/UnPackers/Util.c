
/*======================================================================================
FILE             : Util.c
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
				  
	CREATION DATE    : 12/19/2009 4:20:39 PM
	NOTES		     : Defines the Functionality to Allocate Memory
	VERSION HISTORY  : 
	======================================================================================*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Winsock2.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <io.h>
#include <malloc.h>
#include "Packers.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#if	defined(_MSC_VER) && defined(_DEBUG)
#include <crtdbg.h>
#endif

#ifdef _DEBUG
uint8_t Debug_Flag = 1, LeaveTemps_Flag = 0;
#else
uint8_t Debug_Flag = 0, LeaveTemps_Flag = 0;
#endif

static unsigned char name_salt[16] = { 16, 38, 97, 12, 8, 4, 72, 196, 217, 144, 33, 124, 18, 11, 17, 253 };

#define	S_IRWXU	(_S_IREAD|_S_IWRITE|_S_IEXEC)
#define CL_FLEVEL 23 /* don't touch it */
#define MSGCODE(x)					    \
	va_list args;					    \
	int len = sizeof(x) - 1;			    \
	char buff[BUFSIZ];				    \
	strncpy(buff, x, len);				    \
	va_start(args, str);				    \
	vsnprintf(buff + len, sizeof(buff) - len, str, args);   \
	buff[sizeof(buff) - 1] = '\0';			    \
	fputs(buff, stderr);				    \
	va_end(args)


/*--------------------------------------------------------------------------------------
Function       : WarningMsg
In Parameters  : const char *str, ..., 
Out Parameters : void 
Description    :  Displys Warning Msg
Author & Date  :
--------------------------------------------------------------------------------------*/
void WarningMsg(const char *str, ...)
{
    //MSGCODE("MaxThreadScan Warning: ");
}

/*--------------------------------------------------------------------------------------
Function       : ErrorMessage
In Parameters  : const char *str, ..., 
Out Parameters : void 
Description    :  Displays Error Msg
Author & Date  :
--------------------------------------------------------------------------------------*/
void ErrorMessage(const char *str, ...)
{
    //MSGCODE("MaxThreadScan Error: ");
}

/*--------------------------------------------------------------------------------------
Function       : DBGMessage
In Parameters  : const char *str, ..., 
Out Parameters : void 
Description    : Displays Debug mSg
Author & Date  :
--------------------------------------------------------------------------------------*/
void DBGMessage(const char *str, ...)
{
    /*if(Debug_Flag) {
	MSGCODE("MaxThreadScan debug: ");
    }*/
}

/*--------------------------------------------------------------------------------------
Function       : cl_debug
In Parameters  : void, 
Out Parameters : void 
Description    : Sets Debug Flag
Author & Date  :
--------------------------------------------------------------------------------------*/
void cl_debug(void)
{
    Debug_Flag = 1;
}

/*--------------------------------------------------------------------------------------
Function       : *MaxMalloc
In Parameters  : size_t size, 
Out Parameters : void 
Description    : Allocates the Memory using Malloc
Author & Date  :
--------------------------------------------------------------------------------------*/
void *MaxMalloc(size_t size)
{
	void *alloc;

	if(!size || size > MAX_ALLOCATION) 
	{
		return NULL;
	}

#if defined(_MSC_VER) && defined(_DEBUG)
	alloc = _malloc_dbg(size, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
	alloc = malloc(size);
#endif

	if(!alloc)
	{
		ErrorMessage("MaxMalloc(): Can't allocate memory (%u bytes).\n", size);
		perror("malloc_problem");
		return NULL;
	} 
	else
	{
		memset(alloc, 0, size);
		return alloc;
	}
}

/*--------------------------------------------------------------------------------------
Function       : *MaxCalloc
In Parameters  : size_t nmemb, size_t size, 
Out Parameters : void 
Description    : Allocates the Memory using Calloc
Author & Date  :
--------------------------------------------------------------------------------------*/
void *MaxCalloc(size_t nmemb, size_t size)
{
	void *alloc;

	if(!size || size > MAX_ALLOCATION)
	{
		return NULL;
	}

#if defined(_MSC_VER) && defined(_DEBUG)
	alloc = _calloc_dbg(nmemb, size, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
	alloc = calloc(nmemb, size);
#endif

	if(!alloc)
	{
		ErrorMessage("MaxCalloc(): Can't allocate memory (%u bytes).\n", nmemb * size);
		perror("calloc_problem");
		return NULL;
	}
	else 
	{
		memset(alloc, 0, size);
		return alloc;
	}
}

/*--------------------------------------------------------------------------------------
Function       : *MaxRealloc
In Parameters  : void *ptr, size_t size, 
Out Parameters : void 
Description    : Reallocates the Memory
Author & Date  :
--------------------------------------------------------------------------------------*/
void *MaxRealloc(void *ptr, size_t size)
{
	void *alloc;
	size_t nOffset = 0, nLength = 0;

	if(!size || size > MAX_ALLOCATION) 
	{
		return NULL;
	}

	if(ptr)
	{
		nOffset = _msize(ptr);
		if(size > nOffset)
		{
			nLength = size - nOffset;
		}
		else
		{
			nLength = 0;
		}
	}
	else
	{
		nOffset = 0;
		nLength = size;
	}

	alloc = realloc(ptr, size);

	if(!alloc)
	{
		ErrorMessage("MaxRealloc(): Can't re-allocate memory to %u bytes.\n", size);
		perror("realloc_problem");
		return NULL;
	}
	else
	{
		memset(((unsigned char*)alloc) + nOffset, 0, nLength);
		return alloc;
	}
}

/*--------------------------------------------------------------------------------------
Function       : *MaxRealloc2
In Parameters  : void *ptr, size_t size, 
Out Parameters : void 
Description    : Reallocates the Memory
Author & Date  :
--------------------------------------------------------------------------------------*/
void *MaxRealloc2(void *ptr, size_t size)
{
	void *alloc;
	size_t nOffset = 0, nLength = 0;

	if(!size || size > MAX_ALLOCATION)
	{
		return NULL;
	}

	if(ptr)
	{
		nOffset = _msize(ptr);
		if(size > nOffset)
		{
			nLength = size - nOffset;
		}
		else
		{
			nLength = 0;
		}
	}
	else
	{
		nOffset = 0;
		nLength = size;
	}

	alloc = realloc(ptr, size);

	if(!alloc)
	{
		ErrorMessage("MaxRealloc2(): Can't re-allocate memory to %u bytes.\n", size);
		perror("realloc_problem");
		if(ptr)
		{
			free(ptr);
		}
		return NULL;
	} 
	else 
	{
		memset(((unsigned char*)alloc) + nOffset, 0, nLength);
		return alloc;
	}
}

/*--------------------------------------------------------------------------------------
Function       : *Max_Strdup
In Parameters  : const char *s, 
Out Parameters : char 
Description    : 
Author & Date  :
--------------------------------------------------------------------------------------*/
char *Max_Strdup(const char *s)
{
	char *alloc;

	if(s == NULL)
	{
		return NULL;
	}

#if defined(_MSC_VER) && defined(_DEBUG)
	alloc = _strdup_dbg(s, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
	alloc = strdup(s);
#endif

	if(!alloc) 
	{
		ErrorMessage("Max_Strdup(): Can't allocate memory (%u bytes).\n", strlen(s));
		perror("strdup_problem");
		return NULL;
	}

	return alloc;
}

/*--------------------------------------------------------------------------------------
Function       : cl_settempdir
In Parameters  : const char *dir, short leavetemps, 
Out Parameters : 
void 
Description    : Sets the Global Temproary Directory
Author & Date  :
--------------------------------------------------------------------------------------*/
void cl_settempdir(const char *dir, short leavetemps)
{
	char *var;

	if(dir)
	{
		var = (char *) MaxMalloc(8 + strlen(dir));
		sprintf(var, "TMPDIR=%s", dir);
		if(!putenv(var))
		{
			DBGMessage("Setting %s as global temporary directory\n", dir);
		}
		else
		{
			WarningMsg("Can't set TMPDIR variable - insufficient space in the environment.\n");
		}

	}
	LeaveTemps_Flag = leavetemps;
}

/*--------------------------------------------------------------------------------------
Function       : GenTempfd
In Parameters  : const char *dir, char *name, int *fd, 
Out Parameters : int 
Description    : Creates the Temp File
Author & Date  :
--------------------------------------------------------------------------------------*/
int GenTempfd(const char *dir, char *name, int *fd)
{

	if(!name)
	{
		return CL_EMEM;
	}

	*fd = open(name, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU);
	if(*fd == -1) 
	{
		return CL_EIO;
	}
	return CL_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : Max_Readn
In Parameters  :  int fd, void *buff, unsigned int count, 
Out Parameters : int 
Description    : Try hard to read the requested number of bytes
Author & Date  :
--------------------------------------------------------------------------------------*/
int Max_Readn( int fd, void *buff, unsigned int count)
{
	int retval;
	unsigned int todo;
	unsigned char *current;

	todo = count;
	current = (unsigned char *) buff;

	do 
	{
		retval = read(fd, current, todo);
		if (retval == 0)
		{
			return (count - todo);
		}
		if (retval < 0) 
		{
			if (errno == EINTR) 
			{
				continue;
			}
			ErrorMessage("Max_Readn: read error: %s\n", strerror(errno));
			return -1;
		}
		todo -= retval;
		current += retval;
	} while (todo > 0);

	return count;
}


/*--------------------------------------------------------------------------------------
Function       : MaxWrittenMode
In Parameters  : int wfd, const void *buff, unsigned int count, 
Out Parameters : int 
Description    : Try hard to write the specified number of bytes
Author & Date  :
--------------------------------------------------------------------------------------*/
int MaxWrittenMode(int wfd, const void *buff, unsigned int count)
{
	int retval=0;
	unsigned int todo;
	const unsigned char *current;

	todo = count;
	current = (const unsigned char *) buff;
	do 
	{
		retval = write(wfd, current, todo);
		if (retval < 0) 
		{
			if (errno == EINTR) 
			{
				continue;
			}
			ErrorMessage("MaxWritten: write error: %s\n", strerror(errno));
			return -1;
		}
		todo -= retval;
		current += retval;
	} while (todo > 0);

	return count;
}

/*--------------------------------------------------------------------------------------
Function       : MaxWritten
In Parameters  : void* fd, const void *buff, unsigned int count, 
Out Parameters : int 
Description    : it Writes Specified no. of bytes 
Author & Date  :
--------------------------------------------------------------------------------------*/
int MaxWritten(void* fd, const void *buff, unsigned int count)
{
	DWORD retval = 0;
	DWORD todo;
	const unsigned char *current;

	todo = count;
	current = (const unsigned char *) buff;

	WriteFile ( (HANDLE)fd, (LPVOID)current, todo,&retval,NULL);
	return retval;
}

#define BITS_PER_CHAR (8)
#define BITSET_DEFAULT_SIZE (1024)

/*--------------------------------------------------------------------------------------
Function       : nearest_power
In Parameters  : unsigned long num, 
Out Parameters : unsigned long 
Description    : Calculate Nearset Power
Author & Date  :
--------------------------------------------------------------------------------------*/
unsigned long nearest_power(unsigned long num)
{
	unsigned long n = BITSET_DEFAULT_SIZE;

	while (n < num)
	{
		n <<= 1;
		if (n == 0) 
		{
			return num;
		}
	}
	return n;
}

/*--------------------------------------------------------------------------------------
Function       : *BitSet_init
In Parameters  : void, 
Out Parameters : bitset_t 
Description    : Initailize Bit Set
Author & Date  :
--------------------------------------------------------------------------------------*/
bitset_t *BitSet_init(void)
{
	bitset_t *bs;

	bs = MaxMalloc(sizeof(bitset_t));
	if (!bs)
	{
		return NULL;
	}
	bs->length = BITSET_DEFAULT_SIZE;
	bs->bitset = MaxCalloc(BITSET_DEFAULT_SIZE, 1);
	return bs;
}

/*--------------------------------------------------------------------------------------
Function       : BitSet_free
In Parameters  : bitset_t *bs, 
Out Parameters : void 
Description    : Frees Bitset
Author & Date  :
--------------------------------------------------------------------------------------*/
void BitSet_free(bitset_t *bs)
{
	if (!bs)
	{
		return;
	}
	if (bs->bitset) 
	{
		free(bs->bitset);
	}
	free(bs);
}

/*--------------------------------------------------------------------------------------
Function       : *bitset_realloc
In Parameters  : bitset_t *bs, unsigned long min_size, 
Out Parameters : static bitset_t 
Description    : Reallocate the memory for BitSet
Author & Date  :
--------------------------------------------------------------------------------------*/
static bitset_t *bitset_realloc(bitset_t *bs, unsigned long min_size)
{
	unsigned long new_length;
	unsigned char *new_bitset;

	new_length = nearest_power(min_size);
	new_bitset = (unsigned char *) MaxRealloc(bs->bitset, new_length);
	if (!new_bitset) 
	{
		return NULL;
	}
	bs->bitset = new_bitset;
	memset(bs->bitset+bs->length, 0, new_length-bs->length);
	bs->length = new_length;
	return bs;
}

/*--------------------------------------------------------------------------------------
Function       : BitSet_set
In Parameters  : bitset_t *bs, unsigned long bit_offset, 
Out Parameters : int 
Description    : it Sets the BitSet
Author & Date  :
--------------------------------------------------------------------------------------*/
int BitSet_set(bitset_t *bs, unsigned long bit_offset)
{
	unsigned long char_offset;

	char_offset = bit_offset / BITS_PER_CHAR;
	bit_offset = bit_offset % BITS_PER_CHAR;

	if (char_offset >= bs->length)
	{
		bs = bitset_realloc(bs, char_offset+1);
		if (!bs) 
		{
			return FALSE;
		}
	}
	bs->bitset[char_offset] |= ((unsigned char)1 << bit_offset);
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : BitSet_test
In Parameters  : bitset_t *bs, unsigned long bit_offset, 
Out Parameters : int 
Description    : Test the bitSet
Author & Date  :
--------------------------------------------------------------------------------------*/
int BitSet_test(bitset_t *bs, unsigned long bit_offset)
{
	unsigned long char_offset;

	char_offset = bit_offset / BITS_PER_CHAR;
	bit_offset = bit_offset % BITS_PER_CHAR;

	if (char_offset >= bs->length) 
	{	
		return FALSE;
	}
	return (bs->bitset[char_offset] & ((unsigned char)1 << bit_offset));
}

/*--------------------------------------------------------------------------------------
Function       : *MemStrCompare
In Parameters  : const char *haystack, int hs, const char *needle, int ns, 
Out Parameters : const char 
Description    : compares two Strings
Author & Date  :
--------------------------------------------------------------------------------------*/
const char *MemStrCompare(const char *haystack, int hs, const char *needle, int ns)
{
	const char *pt, *hay;
	int n;

	if(hs < ns)
	{
		return NULL;
	}

	if(haystack == needle)
	{
		return haystack;
	}

	if(!memcmp(haystack, needle, ns))
	{
		return haystack;
	}

	pt = hay = haystack;
	n = hs;

	while((pt = memchr(hay, needle[0], n)) != NULL)
	{
		n -= (int) (pt - hay);
		if(n < ns)
		{
			break;
		}

		if(!memcmp(pt, needle, ns))
		{
			return pt;
		}

		if(hay == pt)
		{
			n--;
			hay++;
		}
		else
		{
			hay = pt;
		}
	}

	return NULL;
}