// pch.cpp: source file corresponding to the pre-compiled header

#include "pch.h"
//#include "ProductInfo.h"


void AddLogEntry(const TCHAR* sFormatString, const TCHAR* sEntry1, const TCHAR* sEntry2, bool isDateTime, int iLogLevel)
{
	/*
	try
	{
		static CString csScanLogFullPath;
		static FILE* pOutFile = NULL;

		if (sFormatString == 0 && sEntry1 == 0 && sEntry2 == 0)
		{
			if (pOutFile)
			{
				fclose(pOutFile);
			}
			pOutFile = NULL;
			return;
		}
		if (csScanLogFullPath.GetLength() == 0)
		{
			CProductInfo objPrdInfo;
			CString csExeInstallPath = objPrdInfo.GetInstallPath();
			csScanLogFullPath = csExeInstallPath + LIVEUPDATE_LOG_FILE;
		}

		if (!pOutFile)
			pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);

		if (pOutFile != NULL)
		{
			CString szMessage;
			if (sFormatString && sEntry1 && sEntry2)
			{
				szMessage.Format(sFormatString, sEntry1, sEntry2);
			}
			else if (sFormatString && sEntry1)
			{
				szMessage.Format(sFormatString, sEntry1);
			}
			else if (sFormatString && sEntry2)
			{
				szMessage.Format(sFormatString, sEntry2);
			}
			else if (sFormatString)
			{
				szMessage = sFormatString;
			}

			if (isDateTime == true)
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
	catch (...)
	{
	}
	*/
}
// When you are using pre-compiled headers, this source file is necessary for compilation to succeed.
