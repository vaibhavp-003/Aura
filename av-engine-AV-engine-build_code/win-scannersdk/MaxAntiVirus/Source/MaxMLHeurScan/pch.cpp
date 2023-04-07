// stdafx.cpp : source file that includes just the standard includes
// MaxMLHeurScan.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"
#include <stdio.h>

/*
void AddScoreLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime)
{
	static TCHAR szScanLogFullPath[MAX_PATH] = {0};
	if(_tcslen(szScanLogFullPath) == 0)
	{
		///CString csExeInstallPath = GetInstallPath();
		//csScanLogFullPath = csExeInstallPath + _T("LOG\\AuMLHeurScan.log");
		
        TCHAR sExeFileName[MAX_PATH]={0};
		GetModuleFileName(0, sExeFileName, MAX_PATH);
		TCHAR *pTemp = _tcsrchr(sExeFileName, _T('\\'));
		if(pTemp)
		{
			*pTemp = '\0';
		}
		_stprintf(szScanLogFullPath,_T("%s\\LOG\\Score.log"),sExeFileName);
	}

	FILE *pOutFile = _wfsopen(szScanLogFullPath, _T("a"), 0x40);
	if(pOutFile != NULL)
	{
		TCHAR szMessage[MAX_PATH] ={0};
		if(sFormatString && sEntry1 && sEntry2)
		{
			//szMessage.Format(sFormatString, sEntry1, sEntry2);
			_stprintf(szMessage,sFormatString,sEntry1,sEntry2);
		}
		else if(sFormatString && sEntry1)
		{
			//szMessage.Format(sFormatString, sEntry1);
			_stprintf(szMessage,sFormatString,sEntry1);
		}
		else if(sFormatString && sEntry2)
		{
			//szMessage.Format(sFormatString, sEntry2);
			_stprintf(szMessage,sFormatString,sEntry2);
		}
		else if(sFormatString)
		{
			//szMessage = sFormatString;
			_stprintf(szMessage,sFormatString);
		}

		if(isDateTime)
		{
			TCHAR tbuffer[9];
			TCHAR dbuffer[9];
			_wstrtime_s(tbuffer, 9);
			_wstrdate_s(dbuffer, 9);

			TCHAR szOutMessage[MAX_PATH] = {0};
			//szOutMessage.Format(_T("[%s %s] %s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
			_stprintf(szOutMessage,_T("[%s %s] %s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
			fputws((LPCTSTR)szOutMessage, pOutFile);
		}
		else
		{
			fputws((LPCTSTR)szMessage, pOutFile);
		}
		fclose(pOutFile);
	}
}
*/
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime)
{
	static TCHAR szScanLogFullPath[MAX_PATH] = {0};
	if(_tcslen(szScanLogFullPath) == 0)
	{
		///CString csExeInstallPath = GetInstallPath();
		//csScanLogFullPath = csExeInstallPath + _T("LOG\\AuMLHeurScan.log");
		
        TCHAR sExeFileName[MAX_PATH]={0};
		GetModuleFileName(0, sExeFileName, MAX_PATH);
		TCHAR *pTemp = _tcsrchr(sExeFileName, _T('\\'));
		if(pTemp)
		{
			*pTemp = '\0';
		}
		_stprintf(szScanLogFullPath,_T("%s\\LOG\\AuMLHeurScan.log"),sExeFileName);
	}

	FILE *pOutFile = _wfsopen(szScanLogFullPath, _T("a"), 0x40);
	if(pOutFile != NULL)
	{
		TCHAR szMessage[MAX_PATH*2] ={0};
		if(sFormatString && sEntry1 && sEntry2)
		{
			//szMessage.Format(sFormatString, sEntry1, sEntry2);
			_stprintf(szMessage,sFormatString,sEntry1,sEntry2);
		}
		else if(sFormatString && sEntry1)
		{
			//szMessage.Format(sFormatString, sEntry1);
			_stprintf(szMessage,sFormatString,sEntry1);
		}
		else if(sFormatString && sEntry2)
		{
			//szMessage.Format(sFormatString, sEntry2);
			_stprintf(szMessage,sFormatString,sEntry2);
		}
		else if(sFormatString)
		{
			//szMessage = sFormatString;
			_stprintf(szMessage,sFormatString);
		}

		if(isDateTime)
		{
			TCHAR tbuffer[9];
			TCHAR dbuffer[9];
			_wstrtime_s(tbuffer, 9);
			_wstrdate_s(dbuffer, 9);

			TCHAR szOutMessage[MAX_PATH] = {0};
			//szOutMessage.Format(_T("[%s %s] %s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
			_stprintf(szOutMessage,_T("[%s %s] %s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
			fputws((LPCTSTR)szOutMessage, pOutFile);
		}
		else
		{
			fputws((LPCTSTR)szMessage, pOutFile);
		}
		fclose(pOutFile);
	}
}