/*=============================================================================
   FILE		           : ZipExceptionA.cpp
   ABSTRACT		       : implementation of the CZipExceptionA class.
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
#include "ZipExceptionA.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC( CZipExceptionA, CException)
/*-------------------------------------------------------------------------------------
	Function       : CZipExceptionA
	Purpose		   : Constructor for class CZipExceptionA
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipExceptionA::CZipExceptionA(int iCause, LPCTSTR lpszZipName):CException(TRUE)
{
	m_iCause = iCause;

	if (lpszZipName)
		m_szFileName = lpszZipName;	
}
/*-------------------------------------------------------------------------------------
	Function       : ~CZipExceptionA
	Purpose		   : Destructor for class CZipExceptionA
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipExceptionA::~CZipExceptionA()
{

}
/*-------------------------------------------------------------------------------------
	Function       : AfxThrowZipExceptionA
	In Parameters  : int iZipError, LPCTSTR lpszZipName
	Out Parameters : 
	Purpose		   : throw zip exception
	Author		   : 
-------------------------------------------------------------------------------------*/
void AfxThrowZipExceptionA(int iZipError, LPCTSTR lpszZipName)
{
	throw new CZipExceptionA(CZipExceptionA::ZipErrToCause(iZipError), lpszZipName);
}
/*-------------------------------------------------------------------------------------
	Function       : ZipErrToCause
	In Parameters  : int iZipError
	Out Parameters : int
	Purpose		   : convert zlib library and internal error code to a ZipExceptionA code
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipExceptionA::ZipErrToCause(int iZipError)
{
	switch (iZipError)
	{
	case 2://Z_NEED_DICT:
		return CZipExceptionA::needDict;
	case 1://Z_STREAM_END:
		return CZipExceptionA::streamEnd;
	case -1://Z_ERRNO:
		return CZipExceptionA::errNo;
	case -2://Z_STREAM_ERROR:
		return CZipExceptionA::streamError;
	case -3://Z_DATA_ERROR:
		return CZipExceptionA::dataError;
	case -4://Z_MEM_ERROR:
		return CZipExceptionA::memError;
	case -5://Z_BUF_ERROR:
		return CZipExceptionA::bufError;
	case -6://Z_VERSION_ERROR:
		return CZipExceptionA::versionError;
	case ZIP_BADZIPFILE:
		return CZipExceptionA::badZipFile;
	case ZIP_BADCRC:
		return CZipExceptionA::badCrc;
	case ZIP_ABORTED:
		return CZipExceptionA::aborted;
	case ZIP_NOCALLBACK:
		return CZipExceptionA::noCallback;
	case ZIP_NONREMOVABLE:
		return CZipExceptionA::nonRemovable;
	case ZIP_TOOMANYVOLUMES:
		return CZipExceptionA::tooManyVolumes;
	case ZIP_TOOLONGFILENAME:
		return CZipExceptionA::tooLongFileName;
	case ZIP_BADPASSWORD:
		return CZipExceptionA::badPassword;
	case ZIP_CDIR_NOTFOUND:
		return CZipExceptionA::cdirNotFound;


	default:
		return CZipExceptionA::generic;
	}
	
}
