/*=============================================================================
   FILE		           : ZipException.cpp
   ABSTRACT		       : implementation of the CZipException class.
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
#include "ZipException.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC( CZipException, CException)
/*-------------------------------------------------------------------------------------
	Function       : CZipException
	Purpose		   : Constructor for class CZipException
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipException::CZipException(int iCause, LPCTSTR lpszZipName):CException(TRUE)
{
	m_iCause = iCause;

	if (lpszZipName)
		m_szFileName = lpszZipName;	
}
/*-------------------------------------------------------------------------------------
	Function       : ~CZipException
	Purpose		   : Destructor for class CZipException
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipException::~CZipException()
{

}
/*-------------------------------------------------------------------------------------
	Function       : AfxThrowZipException
	In Parameters  : int iZipError, LPCTSTR lpszZipName
	Out Parameters : 
	Purpose		   : throw zip exception
	Author		   : 
-------------------------------------------------------------------------------------*/
void AfxThrowZipException(int iZipError, LPCTSTR lpszZipName)
{
	throw new CZipException(CZipException::ZipErrToCause(iZipError), lpszZipName);
}
/*-------------------------------------------------------------------------------------
	Function       : ZipErrToCause
	In Parameters  : int iZipError
	Out Parameters : int
	Purpose		   : convert zlib library and internal error code to a ZipException code
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipException::ZipErrToCause(int iZipError)
{
	switch (iZipError)
	{
	case 2://Z_NEED_DICT:
		return CZipException::needDict;
	case 1://Z_STREAM_END:
		return CZipException::streamEnd;
	case -1://Z_ERRNO:
		return CZipException::errNo;
	case -2://Z_STREAM_ERROR:
		return CZipException::streamError;
	case -3://Z_DATA_ERROR:
		return CZipException::dataError;
	case -4://Z_MEM_ERROR:
		return CZipException::memError;
	case -5://Z_BUF_ERROR:
		return CZipException::bufError;
	case -6://Z_VERSION_ERROR:
		return CZipException::versionError;
	case ZIP_BADZIPFILE:
		return CZipException::badZipFile;
	case ZIP_BADCRC:
		return CZipException::badCrc;
	case ZIP_ABORTED:
		return CZipException::aborted;
	case ZIP_NOCALLBACK:
		return CZipException::noCallback;
	case ZIP_NONREMOVABLE:
		return CZipException::nonRemovable;
	case ZIP_TOOMANYVOLUMES:
		return CZipException::tooManyVolumes;
	case ZIP_TOOLONGFILENAME:
		return CZipException::tooLongFileName;
	case ZIP_BADPASSWORD:
		return CZipException::badPassword;
	case ZIP_CDIR_NOTFOUND:
		return CZipException::cdirNotFound;


	default:
		return CZipException::generic;
	}
	
}
