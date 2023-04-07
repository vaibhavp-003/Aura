/*=============================================================================
   FILE		           : ZipBigFileA.cpp
   ABSTRACT		       : mplementation of the CZipBigFileA class.
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
#include "ZipBigFileA.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function       : CZipBigFileA
	Purpose		   : Constructor for class CZipBigFileA
	Author		   : 
-------------------------------------------------------------------------------------*/
IMPLEMENT_DYNAMIC(CZipBigFileA, CFile)

CZipBigFileA::CZipBigFileA()
{

}
/*-------------------------------------------------------------------------------------
	Function       : ~CZipBigFileA
	Purpose		   : Destructor for class CZipBigFileA
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipBigFileA::~CZipBigFileA()
{

}
/*-------------------------------------------------------------------------------------
	Function       : Seek
	In Parameters  : _int64 dOff, UINT nFrom
	Out Parameters : ULONGLONG
	Purpose		   : Seek at particular file pointer
	Author		   : 
-------------------------------------------------------------------------------------*/

ULONGLONG CZipBigFileA::Seek(_int64 dOff, UINT nFrom)
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
