// stdafx.cpp : source file that includes just the standard includes
// MaxLiveUpdate.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"
#include "ProductInfo.h"
#include <time.h>
#include <io.h>
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


/*-----------------------------------------------------------------------------
	Function		: AddLogEntry
	In Parameters	: 
	Out Parameters	: const char *sFormatString	: This contains the format string to be 
												  logged according to param 2 and param 3
					  const char *sEntry1		: string to be replaced with first %s
					  const char *sEntry2		: string to be replaced with second %s
	Purpose			: Terminate a process
	Author			: 
-----------------------------------------------------------------------------*/
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, int iLogLevel)
{
	if((DWORD)iLogLevel > g_dwLoggingLevel)
		return;

	static CString csScanLogFullPath;
	if(csScanLogFullPath.GetLength() == 0)
	{
		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();
		csScanLogFullPath = csExeInstallPath + _T("Log\\AuUpdateMrg.txt");
	}

	FILE *pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);
	if(pOutFile != NULL)
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
			TCHAR tbuffer[9];
			TCHAR dbuffer[9];
			_wstrtime_s(tbuffer, 9);
			_wstrdate_s(dbuffer, 9);

			CString szOutMessage;
			szOutMessage.Format(_T("[%s %s][%05d][%05d] %s\r\n"), dbuffer, tbuffer, GetCurrentProcessId(), GetCurrentThreadId(), static_cast<LPCTSTR>(szMessage));                       					
			fputws((LPCTSTR)szOutMessage, pOutFile);
		}
		else
		{
			fputws((LPCTSTR)szMessage, pOutFile);
		}				  
		fclose(pOutFile);
	}
}

