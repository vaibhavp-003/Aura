// stdafx.cpp : source file that includes just the standard includes
// MaxDBServer.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"
#include "MaxConstant.h"
#include "SDConstants.h"

extern "C" IMAGE_DOS_HEADER __ImageBase;
CString GetInstallPath();

HANDLE m_hLoggingEvent = NULL;

DWORD	g_dwLoggingLevel = LOG_DEBUG;
DWORD LoadLoggingLevel(CString &m_strProductKey)
{
	CRegKey oRegKey;
	g_dwLoggingLevel = LOG_ERROR;
	if(ERROR_SUCCESS == oRegKey.Open(HKEY_LOCAL_MACHINE, m_strProductKey, KEY_READ))
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
Purpose			: Adds a entry to the log file
Author			: 
-----------------------------------------------------------------------------*/
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, int iLogLevel)
{
	if((DWORD)iLogLevel > g_dwLoggingLevel)
		return;

	if(m_hLoggingEvent == NULL)
	{
		m_hLoggingEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
	}

	if(WaitForSingleObject(m_hLoggingEvent, 5) == WAIT_TIMEOUT)
	{
		OutputDebugString(L"#################### Skipped logging this entry: " + CString(sFormatString));
		return;
	}

	static CString csScanLogFullPath;
	if(csScanLogFullPath.GetLength() == 0)
	{
		CString csExeInstallPath = GetInstallPath();
#ifdef WIN64
		csScanLogFullPath = csExeInstallPath + _T("Log\\AuDBServer64.txt");
#else
		csScanLogFullPath = csExeInstallPath + _T("Log\\AuDBServer32.txt");
#endif
	}

	FILE *pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);
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
	SetEvent(m_hLoggingEvent);
}

CString GetInstallPath()
{
	try
	{
        TCHAR sExeFileName[MAX_FILE_PATH]={0};
		GetModuleFileName((HINSTANCE)&__ImageBase, sExeFileName, MAX_FILE_PATH);

 		CString csInstallPath;
		csInstallPath = sExeFileName;

		int iPos = 0;
		iPos = csInstallPath.ReverseFind('\\');
		if(iPos == -1)
		{
			return (csInstallPath + BACK_SLASH);
		}
		else
		{
			csInstallPath = csInstallPath.Mid(0, iPos);
			return (csInstallPath + BACK_SLASH);
		}
	}
	catch(...)
	{
		
	}
	return CString(_T(""));
}
