// stdafx.cpp : source file that includes just the standard includes
// LiveUpdateDLL.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
DWORD	g_dwLoggingLevel = LOG_ERROR;
/*--------------------------------------------------------------------------------------
Function       : DoEvents
In Parameters  : 
Out Parameters : void
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void DoEvents()
{
	MSG msg;

	// window message
	while (PeekMessage(&msg, NULL, NULL, NULL, PM_REMOVE))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}
DWORD LoadLoggingLevel()
{
	g_dwLoggingLevel = LOG_ERROR;
	/*
	CSDKSettings objSetting;
	g_dwLoggingLevel = objSetting.GetProductSettingsInt(PRODUCT_SETTINGS,LOGGINGLEVEL);
	*/
	return g_dwLoggingLevel;
}

#ifndef SDENTERPRISECLIENT
/*--------------------------------------------------------------------------------------
Function       : AddLogEntry
In Parameters  : const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, 
Out Parameters : void
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, int iLogLevel)
{
	if((DWORD)iLogLevel > g_dwLoggingLevel)
		return;
	try
	{
		static CString csScanLogFullPath;
		static FILE *pOutFile = NULL;

		if(sFormatString == 0 && sEntry1 == 0 && sEntry2 == 0)
		{
			if(pOutFile)
			{
				fclose(pOutFile);
			}
			pOutFile = NULL;
			return;
		}
		if(csScanLogFullPath.GetLength() == 0)
		{
			CProductInfo objPrdInfo;
			CString csExeInstallPath = objPrdInfo.GetInstallPath();
			csScanLogFullPath = csExeInstallPath + LIVEUPDATE_LOG_FILE;
		}

		if(!pOutFile)
			pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);

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
				szOutMessage.Format(_T("[%s %s] %s\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
				fputws((LPCTSTR)szOutMessage, pOutFile);
			}
			else
			{
				fputws((LPCTSTR)szMessage, pOutFile);
			}

			fflush(pOutFile);
		}
	}
	catch(...)
	{
	}
}

#endif //SDENTERPRISECLIENT