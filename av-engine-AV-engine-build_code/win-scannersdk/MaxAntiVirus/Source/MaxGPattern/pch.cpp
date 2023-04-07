// stdafx.cpp : source file that includes just the standard includes
// MaxGPattern.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"

// TODO: reference any additional headers you need in STDAFX.H
// and not in this file
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, int iLogLevel)
{
	if(-1 != iLogLevel)
	{
		return;
	}

	static CString csScanLogFullPath;
	if(csScanLogFullPath.GetLength() == 0)
	{
		CString csExeInstallPath = GetInstallPath();
		csScanLogFullPath = csExeInstallPath + _T("LOG\\MaxRandomNamePtrn.log");
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
			szOutMessage.Format(_T("[%s %s] %s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
			fputws((LPCTSTR)szOutMessage, pOutFile);
		}
		else
		{
			fputws((LPCTSTR)szMessage, pOutFile);
		}
		fclose(pOutFile);
	}
}

CString GetInstallPath()
{
	try
	{
		TCHAR sExeFileName[MAX_PATH]={0};
		GetModuleFileName(0, sExeFileName, MAX_PATH);

 		CString csInstallPath;
		csInstallPath = sExeFileName;

		int iPos = 0;
		iPos = csInstallPath.ReverseFind('\\');
		if(iPos == -1)
		{
			return (csInstallPath + '\\');
		}
		else
		{
			csInstallPath = csInstallPath.Mid(0, iPos);
			return (csInstallPath + '\\');
		}
	}
	catch(...)
	{
		
	}
	return CString(_T(""));
}