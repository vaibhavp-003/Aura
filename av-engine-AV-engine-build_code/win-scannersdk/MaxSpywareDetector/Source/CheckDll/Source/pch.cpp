// stdafx.cpp : source file that includes just the standard includes
// AntiRootKitDLL.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"
#include <time.h>
#include  <io.h>
#include "ProductInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

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
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime)
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
			TCHAR szTempFilePath[1024];
			GetTempPath(MAX_PATH, szTempFilePath);
			csScanLogFullPath = (CString)szTempFilePath;
			csScanLogFullPath += L"VirusPatch.txt";
			OutputDebugString(csScanLogFullPath);
			//CProductInfo objPrdInfo;
			//CString csExeInstallPath = objPrdInfo.GetInstallPath();
			//csScanLogFullPath = csExeInstallPath + LOG_FILE;
		}

		if(!pOutFile)
			pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);

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

