// stdafx.cpp : source file that includes just the standard includes
// PDFDecrypt.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"

// TODO: reference any additional headers you need in STDAFX.H
// and not in this file


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
void AddLogEntry(const TCHAR *sEntry1, const TCHAR *sEntry2)
{
	static TCHAR csScanLogFullPath[MAX_PATH] = {0};
	if(csScanLogFullPath[0] == 0)
	{
		TCHAR * Ptr = 0;

		GetModuleFileName(NULL, csScanLogFullPath, MAX_PATH);
		Ptr = _tcsrchr(csScanLogFullPath, _T('\\'));
		if(Ptr)
		{
			*Ptr = 0;
			_tcscat_s(csScanLogFullPath, MAX_PATH, _T("\\LOG\\AuAVDBScan.log"));
		}
	}

	FILE *pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);
	if(pOutFile != NULL)
	{
		TCHAR szString[50] = {0};
		TCHAR tbuffer[9] = {0};
		TCHAR dbuffer[9] = {0};

		_wstrtime_s(tbuffer, 9);
		_wstrdate_s(dbuffer, 9);

		_stprintf_s(szString, _countof(szString), _T("[%s %s] "), dbuffer, tbuffer);
		fputws(szString, pOutFile);

		if(sEntry1)
		{
			fputws(sEntry1, pOutFile);
		}

		if(sEntry2)
		{
			fputws(sEntry2, pOutFile);
		}

		fputws(L"\r\n", pOutFile);
		fclose(pOutFile);
	}
}
