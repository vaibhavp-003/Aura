/*======================================================================================
FILE             : stdafx.cpp
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 07/09/2008
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/

// stdafx.cpp : source file that includes just the standard includes
// NewService.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"
#include "ProductInfo.h"
#include <atlbase.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

DWORD	g_dwLoggingLevel = LOG_ERROR;

DWORD LoadLoggingLevel()
{
	CProductInfo objPrdInfo;
	CRegKey oRegKey;

	g_dwLoggingLevel = LOG_ERROR;
	if(ERROR_SUCCESS == oRegKey.Open(HKEY_LOCAL_MACHINE, objPrdInfo.GetProductRegKey(), KEY_READ))
	{
		oRegKey.QueryDWORDValue(LOGGING_LEVEL, g_dwLoggingLevel);
		oRegKey.Close();
	}
	return g_dwLoggingLevel;
}

/*--------------------------------------------------------------------------------------
Function       : AddLogEntry
In Parameters  : const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, 
Out Parameters : void oid 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, int iLogLevel)
{
	try
	{
		if((DWORD)iLogLevel > g_dwLoggingLevel)
			return;

		static CString csScanLogFullPath;
		FILE *pOutFile = NULL;
		
		if(csScanLogFullPath.GetLength()== 0)
		{
			CProductInfo objPrdInfo;
			CString csExeInstallPath = objPrdInfo.GetInstallPath();
			csScanLogFullPath = csExeInstallPath + _T("Log\\AuActMon.txt");
		}

		if(!pOutFile)
		{
			pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);
		}

		if(pOutFile != NULL)
		{
			CString szMessage;
			if(sFormatString && sEntry1 && sEntry2)
			{
				szMessage.Format(sFormatString, sEntry1, sEntry2);
			}
			else if(sFormatString && sEntry1)
			{
				szMessage.Format(sFormatString, sEntry1);
			}
			else if(sFormatString && sEntry2)
			{
				szMessage.Format(sFormatString, sEntry2);
			}
			else if(sFormatString)
			{
				szMessage = sFormatString;
			}
			if(isDateTime == true)
			{
				TCHAR tbuffer[9];
				TCHAR dbuffer[9];
				_wstrtime_s(tbuffer, 9);
				_wstrdate_s(dbuffer, 9);

				CString szOutMessage;
				szOutMessage.Format(_T("[%s %s] %s\n"), dbuffer, tbuffer, 
									static_cast<LPCTSTR>(szMessage));
				fputws((LPCTSTR)szOutMessage, pOutFile);
			}
			else
			{
				fputws((LPCTSTR)szMessage, pOutFile);
			}
			fflush(pOutFile);
			fclose(pOutFile);
			pOutFile = NULL;
		}
	}
	catch(...)
	{
	}
}