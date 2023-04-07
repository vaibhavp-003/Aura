/*=============================================================================
   FILE		           : ZipBigFile.cpp
   ABSTRACT		       : mplementation of the CZipBigFile class.
   DOCUMENTS	       : 
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 
   NOTES		      : 
   VERSION HISTORY    :
				
=============================================================================*/

#include "stdafx.h"
#include "ZipBigFile.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function       : CZipBigFile
	Purpose		   : Constructor for class CZipBigFile
	Author		   : 
-------------------------------------------------------------------------------------*/
IMPLEMENT_DYNAMIC(CZipBigFile, CFile)

CZipBigFile::CZipBigFile()
{

}
/*-------------------------------------------------------------------------------------
	Function       : ~CZipBigFile
	Purpose		   : Destructor for class CZipBigFile
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipBigFile::~CZipBigFile()
{

}
/*-------------------------------------------------------------------------------------
	Function       : Seek
	In Parameters  : _int64 dOff, UINT nFrom
	Out Parameters : ULONGLONG
	Purpose		   : Seek at particular file pointer
	Author		   : 
-------------------------------------------------------------------------------------*/

ULONGLONG CZipBigFile::Seek(_int64 dOff, UINT nFrom)
{
	ASSERT_VALID(this);
	ASSERT(m_hFile != hFileNull);
	ASSERT(nFrom == begin || nFrom == end || nFrom == current);
	ASSERT(begin == FILE_BEGIN && end == FILE_END && current == FILE_CURRENT);
	LARGE_INTEGER li;
	li.QuadPart = dOff;

	li.LowPart  = ::SetFilePointer((HANDLE)m_hFile, li.LowPart, &li.HighPart, (DWORD)nFrom);
	DWORD dw = GetLastError();
	if ((li.LowPart == (DWORD)-1) && (dw != NO_ERROR))
	{
		CFileException::ThrowOsError((LONG)dw);
	}

	return li.QuadPart;

}
