
// pch.cpp : source file that includes just the standard includes
// MaxUnpackExe.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "pch.h"

DWORD	g_dwLoggingLevel = LOG_ERROR;

DWORD LoadLoggingLevel()
{

	//CSDKSettings m_objSDKSettings;
	//g_dwLoggingLevel = m_objSDKSettings.GetProductSettingsInt(PRODUCT_SETTINGS,LOGGINGLEVEL);
	return g_dwLoggingLevel;
}

/*--------------------------------------------------------------------------------------
Function       : AddLogEntry
In Parameters  : const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, 
Out Parameters : void oid 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, int iLogLevel)
{
	try
	{
		if((DWORD)iLogLevel > g_dwLoggingLevel)
			return;

		static CString csScanLogFullPath;
		FILE *pOutFile = NULL;
		
		if(csScanLogFullPath.GetLength()== 0)
		{
			//CSDKSettings m_objSDKSettings;
			//CString csExeInstallPath = m_objSDKSettings.GetProductAppPath();
			CString csExeInstallPath(L"");
			csScanLogFullPath = csExeInstallPath + _T("Log\\AuUnpackerexe.txt");
		}

		if(!pOutFile)
		{
			pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);
		}

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
				szOutMessage.Format(_T("[%s %s] %s\n"), dbuffer, tbuffer, 
									static_cast<LPCTSTR>(szMessage));
				fputws((LPCTSTR)szOutMessage, pOutFile);
			}
			else
			{
				fputws((LPCTSTR)szMessage, pOutFile);
			}
			fflush(pOutFile);
			fclose(pOutFile);
			pOutFile = NULL;
		}
	}
	catch(...)
	{
	}
}
