// stdafx.cpp : source file that includes just the standard includes
// WhiteCerScan.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"

// TODO: reference any additional headers you need in STDAFX.H
// and not in this file
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime)
{
	//static TCHAR szScanLogFullPath[MAX_PATH] = {0};
	//if(szScanLogFullPath[0] == 0)
	//{
	//	GetModuleFileName(0, szScanLogFullPath, MAX_PATH);
	//	if(_tcsrchr(szScanLogFullPath, _T('\\')))
	//	{
	//		*_tcsrchr(szScanLogFullPath, _T('\\')) = 0;
	//	}
	//	_tcscat_s(szScanLogFullPath, MAX_PATH, _T("\\LOG\\AuAVPMScan.log"));
	//}

	//FILE *pOutFile = _wfsopen(szScanLogFullPath, _T("a"), 0x40);
	//if(pOutFile != NULL)
	//{
	//	TCHAR szMessage[MAX_PATH*4] = {0};
	//	if(sFormatString && sEntry1 && sEntry2)
	//	{
	//		swprintf(szMessage, MAX_PATH*4, sFormatString, sEntry1, sEntry2);
	//	}
	//	else if(sFormatString && sEntry1)
	//	{
	//		swprintf(szMessage, MAX_PATH*4, sFormatString, sEntry1);
	//	}
	//	else if(sFormatString && sEntry2)
	//	{
	//		swprintf(szMessage, MAX_PATH*4, sFormatString, sEntry2);
	//	}
	//	else if(sFormatString)
	//	{
	//		swprintf(szMessage, MAX_PATH*4, sFormatString);
	//	}

	//	if(isDateTime)
	//	{
	//		TCHAR tbuffer[9] = {0};
	//		TCHAR dbuffer[9] = {0};
	//		_wstrtime_s(tbuffer, 9);
	//		_wstrdate_s(dbuffer, 9);

	//		TCHAR szOutMessage[MAX_PATH*4] = {0};
	//		swprintf(szOutMessage, MAX_PATH*4, _T("[%s %s] %s\r\n"), dbuffer, tbuffer, szMessage);
	//		fputws(szOutMessage, pOutFile);
	//	}
	//	else
	//	{
	//		fputws((LPCTSTR)szMessage, pOutFile);
	//	}
	//	fclose(pOutFile);
	//}
}

void AddLogEntry(int iTypeOfMessage, const TCHAR *sKeyPart, const TCHAR *sValuePart, const DWORD dwTypeOfData, 
				 const DWORD dwTypeOfScanner, const TCHAR *sDataPart, const TCHAR *sReplaceDataPart, bool bStartingScan)
{
}