// stdafx.cpp : source file that includes just the standard includes
// MaxSecure.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"
#include "SDConstants.h"
#include "ProductInfo.h"
#include "MaxConstant.h"
#include <time.h>
#include <io.h>
#include <atlbase.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CString g_csSDLog(L"");
CString g_csMD5Log(L"");
CString g_csEPLog(L"");
CString g_csGenPELog(L"");

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
		csScanLogFullPath = csExeInstallPath + _T("Log\\AuSecure.txt");
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

void AddLogEntry(int iTypeOfMessage, const TCHAR *sEntry1, const TCHAR *sEntry2, bool bStartingScan)
{
	CString csLogFileName(L"");
	CString szMessage(L"");
	if(iTypeOfMessage < SD_Message_Info_TYPE_REG) // Its a File system Message
	{
		if((iTypeOfMessage == MD5) || (iTypeOfMessage == MD5_Report))
		{
			if(g_csMD5Log.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csMD5Log = csExeInstallPath + MD5_LOG_FILE;
			}
			csLogFileName = g_csMD5Log;
		}
		else if((iTypeOfMessage == ExecPath) || (iTypeOfMessage == ExecPath_Report))
		{
			if(g_csEPLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csEPLog = csExeInstallPath + PESIG_LOG_FILE;
			}
			csLogFileName = g_csEPLog;
		}
		else if((iTypeOfMessage == GenPEScan) || (iTypeOfMessage == GenPEScan_Report))
		{
			if(g_csGenPELog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csGenPELog = csExeInstallPath + GENPE_LOG_FILE;
			}
			csLogFileName = g_csGenPELog;
		}
		else
		{
			if(g_csSDLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csSDLog = csExeInstallPath + _T("Log\\AuSecure.txt");;
			}
			csLogFileName = g_csSDLog;
		}
		if(sEntry1 && sEntry2)
			szMessage.Format(L"Found: %s - %s", sEntry2, sEntry1);
		else if(sEntry1)
			szMessage.Format(L"Found: %s", sEntry1);
		else if(sEntry2)
			szMessage.Format(L"Found: %s", sEntry2);
		else
			szMessage.Format(L"Found: [%d]", iTypeOfMessage);
	}
	else if(iTypeOfMessage < SD_Message_Info_TYPE_INFO) // Its a Registry Message
	{
		CString csHive;
		if(sEntry1)
		{
			if(sEntry1[0] == '.' || sEntry1[1] == '-')
				csHive = L"HKEY_USERS\\";
			else
				csHive = L"HKEY_LOCAL_MACHINE\\";
		}
		if(g_csSDLog.GetLength() == 0)
		{
			CProductInfo objPrdInfo;
			CString csExeInstallPath = objPrdInfo.GetInstallPath();
			g_csSDLog = csExeInstallPath + _T("Log\\AuSecure.txt");;
		}
		csLogFileName = g_csSDLog;
		if(sEntry1 && sEntry2)
			szMessage.Format(L"Found: %s%s - %s", csHive, sEntry1, sEntry2);
		else if(sEntry1)
			szMessage.Format(L"Found: %s%s", csHive, sEntry1);
		else if(sEntry2)
			szMessage.Format(L"Found: %s", sEntry2);
		else
			szMessage.Format(L"Found: [%d]", iTypeOfMessage);
	}
	else // Its a Information Message all other messages get logged in sdlog.txt
	{
		if(g_csSDLog.GetLength() == 0)
		{
			CProductInfo objPrdInfo;
			CString csExeInstallPath = objPrdInfo.GetInstallPath();
			g_csSDLog = csExeInstallPath + _T("Log\\AuSecure.txt");;
		}
		csLogFileName = g_csSDLog;
		if(bStartingScan)
		{
			if(sEntry1)
				szMessage.Format(L"Starting Scan: %s", sEntry1);
			else
				szMessage.Format(L"Starting Scan: [%d]", iTypeOfMessage);
		}
		else
		{
			if(sEntry1)
				szMessage.Format(L"Finished Scan: %s", sEntry1);
			else
				szMessage.Format(L"Finished Scan: [%d]", iTypeOfMessage);
		}
	}

    FILE *pOutFile = _wfsopen(csLogFileName, _T("a"), 0x40);
    if(pOutFile != NULL)
    {
		TCHAR tbuffer[9];
		TCHAR dbuffer[9];
		_wstrtime_s(tbuffer, 9);
		_wstrdate_s(dbuffer, 9);
		CString szOutMessage;
		szOutMessage.Format(_T("[%s %s][%05d][%05d] %s\r\n"), dbuffer, tbuffer, GetCurrentProcessId(), GetCurrentThreadId(), static_cast<LPCTSTR>(szMessage));
		fputws((LPCTSTR)szOutMessage, pOutFile);
		fclose(pOutFile);
    }
}