/*======================================================================================
   FILE				: StringFunctions.cpp
   ABSTRACT			: This file contains string related functions
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 25/12/2003
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
========================================================================================*/
#include "StringFunctions.h"
#include <fcntl.h>
#include <sys/stat.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

unsigned char g_BufferBlock[IO_BUF_SIZE]={0};
/*-------------------------------------------------------------------------------------
Function		: MemStr
In Parameters	: const char*,const char*,LONGLONG,LONGLONG
Out Parameters	: bool
Purpose			: buffer searching function
Author			: Anand
Description		: search a buffer in another buffer
--------------------------------------------------------------------------------------*/
bool MemStr(const char *str1, const char *str2, LONGLONG Str1Len, LONGLONG Str2Len)
{
	LONGLONG lPos2 = 0, lPos3 = 0, lPos = (LONGLONG)*(&str1);
	str1 = (char *)memchr((char *)str1, str2[0], static_cast<size_t>(Str1Len - lPos3));
	while (NULL != str1)
	{
		if(memcmp((char *)str1,(char *)str2, static_cast<size_t>(Str2Len)) == 0)
		{
			return true;
		}
		lPos2 = (LONGLONG)*(&str1);
		lPos3 = (lPos2 - lPos);
		str1++;
		str1 = (char *)memchr((char *)str1, str2[0], static_cast<size_t>(Str1Len - lPos3));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: SearchString
In Parameters	: int,const char*,bool*
Out Parameters	: bool
Purpose			: buffer searching function
Author			: Anand
Description		: search a null terminated string in a ondisk file
--------------------------------------------------------------------------------------*/
bool SearchString(int hFile, const char * string, bool * found)
{
	DWORD BytesRead = 0, TotalBytesRead = 0, FileLength = 0;
	DWORD BytesToRead =0;
	DWORD length = 0;

	SecureZeroMemory(g_BufferBlock, sizeof(g_BufferBlock));
	length = (DWORD)strlen(string);

	FileLength = _lseek(hFile, 0, SEEK_END);
	_lseek(hFile, 0, SEEK_SET);

	while(!(*found) && TotalBytesRead < FileLength)
	{
		if(sizeof(g_BufferBlock)<(FileLength - TotalBytesRead))
		{
			BytesToRead = sizeof(g_BufferBlock);
		}
		else
		{
			BytesToRead = FileLength - TotalBytesRead;
		}

		_lseek(hFile, TotalBytesRead, SEEK_SET);

		BytesRead = _read(hFile, g_BufferBlock, BytesToRead);

		if(0 == BytesRead || (BytesToRead != BytesRead))
		{
			return (false);
		}

		*found = !!StrNIStr(g_BufferBlock, BytesRead, (UCHAR*)string, strlen(string));

		SecureZeroMemory(g_BufferBlock, sizeof(g_BufferBlock));
		TotalBytesRead += BytesRead;

		if(BytesRead == sizeof(g_BufferBlock))
		{
			TotalBytesRead -= length;
		}
	}

	return (true);
}

//Version: 19.0.0.20
//Resource: Anand
/*-------------------------------------------------------------------------------------
Function		: SearchString
In Parameters	: int,unsigned char*,DWORD, bool*
Out Parameters	: bool
Purpose			: buffer searching function
Author			: Anand
Description		: search a buffer in a ondisk file
--------------------------------------------------------------------------------------*/
bool SearchString(int hFile, unsigned char * string, DWORD length, bool * found)
{
	DWORD BytesRead = 0, TotalBytesRead = 0, FileLength = 0;
	DWORD BytesToRead =0;

	SecureZeroMemory(g_BufferBlock, sizeof(g_BufferBlock));
	FileLength = _lseek(hFile, 0, SEEK_END);
	_lseek(hFile, 0, SEEK_SET);

	while(!(*found) && TotalBytesRead < FileLength)
	{
		if(sizeof(g_BufferBlock)<(FileLength - TotalBytesRead))
		{
			BytesToRead = sizeof(g_BufferBlock);
		}
		else
		{
			BytesToRead = FileLength - TotalBytesRead;
		}

		_lseek(hFile, TotalBytesRead, SEEK_SET);

		BytesRead = _read(hFile, g_BufferBlock, BytesToRead);

		if(0 == BytesRead || (BytesToRead != BytesRead))
		{
			return (false);
		}

		*found = !!StrNIStr(g_BufferBlock, BytesRead, string, length);

		SecureZeroMemory(g_BufferBlock, sizeof(g_BufferBlock));
		TotalBytesRead += BytesRead;

		if(BytesRead == sizeof(g_BufferBlock))
		{
			TotalBytesRead -= length;
		}
	}

	return (true);
}

//Version 19.0.0.10
//Resource : Anand
//Case related Logic
/*-------------------------------------------------------------------------------------
Function		: MemIChr
In Parameters	: void*,int,size_t
Out Parameters	: void*
Purpose			: search a character in a buffer
Author			: Anand
Description		: search a character in a buffer
--------------------------------------------------------------------------------------*/
void* MemIChr(void * Buffer, int Char, size_t cbBuffer)
{
	char * ptr1 = 0, * ptr2 = 0;
	// avoid function call for checking alphabet
	if((Char >= 'a' && Char <= 'z') ||(Char >= 'A' && Char <= 'Z'))
	{
		ptr1 = (char*)memchr(Buffer, Char, cbBuffer);
		Char = Char >= 'a' && Char <= 'z' ? Char - 32 : Char + 32;
		ptr2 = (char*)memchr(Buffer, Char, cbBuffer);
		if(ptr1 && ptr2)
		{
			ptr1 = ptr1 < ptr2 ? ptr1 : ptr2;
		}
		else if(ptr2)
		{
			ptr1 = ptr2;
		}
	}
	else
	{
		ptr1 = (char*)memchr(Buffer, Char, cbBuffer);
	}
	return (ptr1);
}

//version: 15.5
//resource: anand
//Version: 19.0.0.040
/*-------------------------------------------------------------------------------------
Function		: StrNIStr
In Parameters	: UCHAR*,size_t,UCHAR*,size_t
Out Parameters	: UCHAR*
Purpose			: search a buffer in a buffer
Author			: Anand
Description		: search a buffer in a buffer by ignoring case
--------------------------------------------------------------------------------------*/
UCHAR* StrNIStr(UCHAR * HayStack, size_t cbHayStack, UCHAR * Needle, size_t cbNeedle)
{
	UCHAR * Ptr = NULL;
	if(!HayStack || !Needle)
	{
		return (false);
	}
	Ptr = (UCHAR*)MemIChr(HayStack, *Needle, cbHayStack);
	while(Ptr)
	{
		if((cbHayStack -(Ptr - HayStack))< cbNeedle)
		{
			return (NULL);
		}
		if(!_memicmp(Ptr, Needle, cbNeedle))
		{
			return (Ptr);//Version:19.0.0.040, //returns Pointer instead of Bool
		}
		Ptr = (UCHAR*)MemIChr(++Ptr, *Needle, cbHayStack -(Ptr - HayStack));
	}
	return (NULL);
}

/*-------------------------------------------------------------------------------------
Function		: StrcatW
In Parameters	: WCHAR*,DWORD,CHAR*
Out Parameters	: bool
Purpose			: string concatenate function
Author			: Anand
Description		: concatenate a char string to wchar string
--------------------------------------------------------------------------------------*/
bool StrcatW(WCHAR * Dst, DWORD cbDst, CHAR * Src)
{
	if(strlen(Src) + wcslen(Dst) >= cbDst)
	{
		return (false);
	}

	for(int i = (int)wcslen(Dst), j = 0; Dst[i] = Src[j]; i++, j++)
	{
	}
	return (true);
}

