// pch.cpp: source file corresponding to the pre-compiled header

#include "pch.h"

// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.
void AddLogEntry(const TCHAR* sFormatString, const TCHAR* sEntry1, const TCHAR* sEntry2, bool isDateTime, int iLogLevel)
{
	try
	{
		static CString csScanLogFullPath;
		static FILE* pOutFile = NULL;

		if (sFormatString == 0 && sEntry1 == 0 && sEntry2 == 0)
			return;

		if (csScanLogFullPath.GetLength() == 0)
		{
			TCHAR szTempFilePath[1024];
			GetTempPath(MAX_PATH, szTempFilePath);
			csScanLogFullPath = (CString)szTempFilePath;
			csScanLogFullPath += L"Uninstall.txt";
		}

		pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);

		if (pOutFile != NULL)
		{
			CString szMessage;
			if (sFormatString && sEntry1 && sEntry2)
				szMessage.Format(sFormatString, sEntry1, sEntry2);
			else if (sFormatString && sEntry1)
				szMessage.Format(sFormatString, sEntry1);
			else if (sFormatString && sEntry2)
				szMessage.Format(sFormatString, sEntry2);
			else if (sFormatString)
				szMessage = sFormatString;

			if (isDateTime == true)
			{
				TCHAR tbuffer[9] = { 0 };
				TCHAR dbuffer[9] = { 0 };
				_wstrtime_s(tbuffer, 9);
				_wstrdate_s(dbuffer, 9);

				CString szOutMessage;
				szOutMessage.Format(_T("[%s %s] (MainUI) %s\n"), dbuffer, tbuffer,
					static_cast<LPCTSTR>(szMessage));
				fputws((LPCTSTR)szOutMessage, pOutFile);
			}
			else
			{
				fputws((LPCTSTR)szMessage, pOutFile);
			}

			fflush(pOutFile);
			fclose(pOutFile);
		}
	}
	catch (...)
	{
	}
}