// stdafx.cpp : source file that includes just the standard includes
// SpecialSpyHandler.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"
#include <time.h>
#include  <io.h>
#include "productinfo.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, int iLogLevel)
{
	try
	{
		static CString csScanLogFullPath;
		static FILE *pOutFile = NULL;

		if(sFormatString == 0 && sEntry1 == 0 && sEntry2 == 0)
		{
			if(pOutFile)
				fclose(pOutFile);

			pOutFile = NULL;
			return;
		}

		if(csScanLogFullPath.GetLength() == 0)
		{
			CProductInfo objPrdInfo;
			CString csExeInstallPath = objPrdInfo.GetInstallPath();
			csScanLogFullPath = csExeInstallPath + SPLSPY_LOG_FILE;
		}

		if(!pOutFile)
			pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);

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

CString g_csSDLog(L"");

void AddLogEntry(int iTypeOfMessage, const TCHAR *sKeyPart, const TCHAR *sValuePart, const DWORD dwTypeOfData, const TCHAR *sDataPart, const TCHAR *sReplaceDataPart, bool bStartingScan)
{
	CString csLogFileName(L"");
	CString szMessage(L"");
	if(iTypeOfMessage < SD_Message_Info_TYPE_REG) // Its a File system Message
	{
		{
			if(g_csSDLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csSDLog = csExeInstallPath + SPLSPY_LOG_FILE;
			}
			csLogFileName = g_csSDLog;
		}
		if(sKeyPart && sValuePart)
			szMessage.Format(L"Found: %s - %s", sValuePart, sKeyPart);
		else if(sKeyPart)
			szMessage.Format(L"Found: %s", sKeyPart);
		else if(sValuePart)
			szMessage.Format(L"Found: %s", sValuePart);
		else
			szMessage.Format(L"Found: [%d]", iTypeOfMessage);
	}
	else if(iTypeOfMessage < SD_Message_Info_TYPE_INFO) // Its a Registry Message
	{
		CString csHive;
		if(sKeyPart)
		{
			if(sKeyPart[0] == '.' || sKeyPart[1] == '-')
				csHive = L"HKEY_USERS\\";
			else
				csHive = L"HKEY_LOCAL_MACHINE\\";
		}
		if(g_csSDLog.GetLength() == 0)
		{
			CProductInfo objPrdInfo;
			CString csExeInstallPath = objPrdInfo.GetInstallPath();
			g_csSDLog = csExeInstallPath + SPLSPY_LOG_FILE;
		}
		csLogFileName = g_csSDLog;
		if(dwTypeOfData != REG_NONE)
		{
			if(dwTypeOfData == REG_SZ)
			{
				if(sKeyPart && sValuePart && sDataPart && sReplaceDataPart)
					szMessage.Format(L"Found: %s%s - \"%s\" - \"%s\" - \"%s\"", csHive, sKeyPart, sValuePart, sDataPart, sReplaceDataPart);
				else if(sKeyPart && sValuePart && sDataPart)
					szMessage.Format(L"Found: %s%s - \"%s\" - \"%s\"", csHive, sKeyPart, sValuePart, sDataPart);
			}
			else if(dwTypeOfData == REG_DWORD)
			{
				DWORD dwData = 0, dwReplaceData = 0;
				if(sDataPart)
					memcpy_s(&dwData, sizeof(DWORD), sDataPart, sizeof(DWORD));
				if(sReplaceDataPart)
					memcpy_s(&dwReplaceData, sizeof(DWORD), sReplaceDataPart, sizeof(DWORD));
				if(sKeyPart && sValuePart && sDataPart && sReplaceDataPart)
					szMessage.Format(L"Found: %s%s - \"%s\" - \"%d\" - \"%d\"", csHive, sKeyPart, sValuePart, dwData, dwReplaceData);
				else if(sKeyPart && sValuePart && sDataPart)
					szMessage.Format(L"Found: %s%s - \"%s\" - \"%d\"", csHive, sKeyPart, sValuePart, dwData);
			}
			else if(sKeyPart && sValuePart)
				szMessage.Format(L"Found: %s%s - \"%s\"", csHive, sKeyPart, sValuePart);
			else if(sKeyPart)
				szMessage.Format(L"Found: %s%s", csHive, sKeyPart);
			else if(sValuePart)
				szMessage.Format(L"Found: %s", sValuePart);
			else
				szMessage.Format(L"Found: [%d]", iTypeOfMessage);
		}
		else if(sKeyPart && sValuePart)
			szMessage.Format(L"Found: %s%s - \"%s\"", csHive, sKeyPart, sValuePart);
		else if(sKeyPart)
			szMessage.Format(L"Found: %s%s", csHive, sKeyPart);
		else if(sValuePart)
			szMessage.Format(L"Found: %s", sValuePart);
		else
			szMessage.Format(L"Found: [%d]", iTypeOfMessage);
	}
	else // Its a Information Message all other messages get logged in sdlog.txt
	{
		if(g_csSDLog.GetLength() == 0)
		{
			CProductInfo objPrdInfo;
			CString csExeInstallPath = objPrdInfo.GetInstallPath();
			g_csSDLog = csExeInstallPath + SPLSPY_LOG_FILE;
		}
		csLogFileName = g_csSDLog;
		if(bStartingScan)
		{
			if(sKeyPart)
				szMessage.Format(L"Starting Scan: %s", sKeyPart);
			else
				szMessage.Format(L"Starting Scan: [%d]", iTypeOfMessage);
		}
		else
		{
			if(sKeyPart)
				szMessage.Format(L"Finished Scan: %s", sKeyPart);
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
		szOutMessage.Format(_T("[%s %s] %s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
		fputws((LPCTSTR)szOutMessage, pOutFile);
		fclose(pOutFile);
    }
}