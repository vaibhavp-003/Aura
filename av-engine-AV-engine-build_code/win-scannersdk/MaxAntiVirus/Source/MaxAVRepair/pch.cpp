#include "pch.h"
#include <stdio.h>

void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime)
{
}

void AddLogEntry(int iTypeOfMessage, const TCHAR *sKeyPart, const TCHAR *sValuePart, const DWORD dwTypeOfData, 
				 const DWORD dwTypeOfScanner, const TCHAR *sDataPart, const TCHAR *sReplaceDataPart, bool bStartingScan)
{
}

/*void WriteLogString(LPCTSTR szString)
{
	FILE * fpLogFile = 0;
	_tfopen_s(&fpLogFile, L"C:\\PolyVirusLog.txt", L"a");
	if(fpLogFile != NULL)
	{
		TCHAR szTime[9];
		_wstrtime_s(szTime, 9);
		
		TCHAR szDate[9];
		_wstrdate_s(szDate, 9);
	
		TCHAR szMsg[MAX_PATH] = {0};		
		_stprintf_s(szMsg, MAX_PATH, _T("[%s %s] %s\r\n"), szDate, szTime, szString);
	
		_fputts(szMsg, fpLogFile);
		fclose(fpLogFile);		
	}
}*/