/*======================================================================================
FILE             : pch.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshit Kasliwal
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
					(C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura.	
CREATION DATE    : 5/12/2009
NOTES		     : Source file that includes just the standard includes
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "ProductInfo.h"
#include "SDConstants.h"
#include <atlbase.h>

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
Out Parameters : void
Description    :
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2,
				 bool isDateTime, int iLogLevel)
{
	try
	{
		if((DWORD)iLogLevel > g_dwLoggingLevel)
			return;

		static CString csScanLogFullPath;
		FILE *pRtktOutFile = NULL;
		if(csScanLogFullPath.GetLength() == 0)
		{
			CProductInfo objPrdInfo;
			CString csExeInstallPath = objPrdInfo.GetInstallPath();
			csScanLogFullPath = csExeInstallPath + L"Log\\WatchDog.txt";
		}

		if(!pRtktOutFile)
			pRtktOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);

		if(pRtktOutFile != NULL)
		{
			CString szMessage;
			if(sFormatString && sEntry1 && sEntry2)
				szMessage.Format(sFormatString, sEntry1, sEntry2);
			else if(sFormatString && sEntry1)
				szMessage.Format(sFormatString, sEntry1);
			else if(sFormatString && sEntry2)
				szMessage.Format(sFormatString, sEntry2);
			else if(sFormatString)
				szMessage = sFormatString;

			if(isDateTime)
			{
				TCHAR tbuffer[9]= {0};
				TCHAR dbuffer[9] = {0};
				_wstrtime_s(tbuffer, 9);
				_wstrdate_s(dbuffer, 9);

				CString szOutMessage;
				szOutMessage.Format(_T("[%s %s] %s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
				fputws((LPCTSTR)szOutMessage, pRtktOutFile);
			}
			else
			{
				fputws((LPCTSTR)szMessage, pRtktOutFile);
			}
			fflush(pRtktOutFile);
			fclose(pRtktOutFile);
		}
	}
	catch(...)
	{
	}
}