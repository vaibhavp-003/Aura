/*======================================================================================
FILE             : pch.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshan Singh Virdi
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 8/1/2009 7:52:58 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"

CString g_csSDLog(L"");
CString g_csMD5Log(L"");
CString g_csEPLog(L"");
CString g_csGenPELog(L"");
CString g_csVirusLog(L"");

CString GetInstallPath();

//#ifdef _DEBUG
//#define new DEBUG_NEW
//#undef THIS_FILE
//static char THIS_FILE[] = __FILE__;
//#endif

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
		csScanLogFullPath = csExeInstallPath + _T("LOG\\AuAVDBScan.log");
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

void AddLogEntry(int iTypeOfMessage, const TCHAR *sKeyPart, const TCHAR *sValuePart, const DWORD dwTypeOfData, 
				 const DWORD dwTypeOfScanner, const TCHAR *sDataPart, const TCHAR *sReplaceDataPart, bool bStartingScan)
{
	//CString csLogFileName(L"");
	//CString szMessage(L"");
	//if(iTypeOfMessage < SD_Message_Info_TYPE_REG) // Its a File system Message
	//{
	//	if((iTypeOfMessage == MD5) || (iTypeOfMessage == MD5_Report))
	//	{
	//		if(g_csMD5Log.GetLength() == 0)
	//		{
	//			CString csExeInstallPath = GetInstallPath();
	//			g_csMD5Log = csExeInstallPath + MD5_LOG_FILE;
	//		}
	//		csLogFileName = g_csMD5Log;
	//	}
	//	else if((iTypeOfMessage == ExecPath) || (iTypeOfMessage == ExecPath_Report))
	//	{
	//		if(g_csEPLog.GetLength() == 0)
	//		{
	//			CString csExeInstallPath = GetInstallPath();
	//			g_csEPLog = csExeInstallPath + PESIG_LOG_FILE;
	//		}
	//		csLogFileName = g_csEPLog;
	//	}
	//	else if((iTypeOfMessage == GenPEScan) || (iTypeOfMessage == GenPEScan_Report))
	//	{
	//		if(g_csGenPELog.GetLength() == 0)
	//		{
	//			CString csExeInstallPath = GetInstallPath();
	//			g_csGenPELog = csExeInstallPath + GENPE_LOG_FILE;
	//		}
	//		csLogFileName = g_csGenPELog;
	//	}
	//	else
	//	{
	//		if(g_csSDLog.GetLength() == 0)
	//		{
	//			CString csExeInstallPath = GetInstallPath();
	//			g_csSDLog = csExeInstallPath + LOG_FILE;
	//		}
	//		csLogFileName = g_csSDLog;
	//	}
	//	if(sKeyPart && sValuePart)
	//	{
	//		szMessage.Format(L"Found: %s - %s", sValuePart, sKeyPart);
	//	}
	//	else if(sKeyPart)
	//	{
	//		szMessage.Format(L"Found: %s", sKeyPart);
	//	}
	//	else if(sValuePart)
	//	{
	//		szMessage.Format(L"Found: %s", sValuePart);
	//	}
	//	else
	//	{
	//		szMessage.Format(L"Found: [%d]", iTypeOfMessage);
	//	}
	//}
	//else if(iTypeOfMessage < SD_Message_Info_TYPE_INFO) // Its a Registry Message
	//{
	//	if((iTypeOfMessage == Virus_File_Repair) || (iTypeOfMessage == Virus_File_Repair_Report))
	//	{
	//		if(g_csVirusLog.GetLength() == 0)
	//		{
	//			CString csExeInstallPath = GetInstallPath();
	//			g_csVirusLog = csExeInstallPath + VIRUS_LOG_FILE;
	//		}
	//		csLogFileName = g_csVirusLog;
	//		if(sDataPart)
	//			szMessage.Format(L"Found: (Repair) %d - %d - %s - %s - %s", dwTypeOfData, dwTypeOfScanner, sDataPart, sKeyPart, sValuePart);
	//		else
	//			szMessage.Format(L"Found: (Repair) %d - %d - %s - %s", dwTypeOfData, dwTypeOfScanner, sKeyPart, sValuePart);

	//	}
	//	else if((iTypeOfMessage == Virus_File) || (iTypeOfMessage == Virus_File_Report))
	//	{
	//		if(g_csVirusLog.GetLength() == 0)
	//		{
	//			CString csExeInstallPath = GetInstallPath();
	//			g_csVirusLog = csExeInstallPath + VIRUS_LOG_FILE;
	//		}
	//		csLogFileName = g_csVirusLog;
	//		if(sDataPart)
	//			szMessage.Format(L"Found: (Quarantine) %d - %d - %s - %s - %s", dwTypeOfData, dwTypeOfScanner, sDataPart, sKeyPart, sValuePart);
	//		else
	//			szMessage.Format(L"Found: (Quarantine) %d - %d - %s - %s", dwTypeOfData, dwTypeOfScanner, sKeyPart, sValuePart);
	//	}
	//	else
	//	{
	//		CString csHive;
	//		if(sKeyPart)
	//		{
	//			if(sKeyPart[0] == '.' || sKeyPart[1] == '-')
	//			{
	//				csHive = L"HKEY_USERS\\";
	//			}
	//			else
	//			{
	//				csHive = L"HKEY_LOCAL_MACHINE\\";
	//			}
	//		}
	//		if(g_csSDLog.GetLength() == 0)
	//		{
	//			CString csExeInstallPath = GetInstallPath();
	//			g_csSDLog = csExeInstallPath + LOG_FILE;
	//		}
	//		csLogFileName = g_csSDLog;
	//		if(dwTypeOfData != REG_NONE)
	//		{
	//			if(dwTypeOfData == REG_SZ)
	//			{
	//				if(sKeyPart && sValuePart && sDataPart && sReplaceDataPart)
	//				{
	//					szMessage.Format(L"Found: %s%s - \"%s\" - \"%s\" - \"%s\"", csHive, sKeyPart, sValuePart,
	//																				sDataPart, sReplaceDataPart);
	//				}
	//				else if(sKeyPart && sValuePart && sDataPart)
	//				{
	//					szMessage.Format(L"Found: %s%s - \"%s\" - \"%s\"", csHive, sKeyPart, sValuePart, sDataPart);
	//				}
	//			}
	//			else if(dwTypeOfData == REG_DWORD)
	//			{
	//				DWORD dwData = 0, dwReplaceData = 0;
	//				if(sDataPart)
	//				{
	//					memcpy_s(&dwData, sizeof(DWORD), sDataPart, sizeof(DWORD));
	//				}
	//				if(sReplaceDataPart)
	//				{
	//					memcpy_s(&dwReplaceData, sizeof(DWORD), sReplaceDataPart, sizeof(DWORD));
	//				}
	//				if(sKeyPart && sValuePart && sDataPart && sReplaceDataPart)
	//				{
	//					szMessage.Format(L"Found: %s%s - \"%s\" - \"%d\" - \"%d\"", csHive, sKeyPart, 
	//																sValuePart, dwData, dwReplaceData);
	//				}
	//				else if(sKeyPart && sValuePart && sDataPart)
	//				{
	//					szMessage.Format(L"Found: %s%s - \"%s\" - \"%d\"", csHive, sKeyPart, sValuePart, dwData);
	//				}
	//			}
	//			else if(sKeyPart && sValuePart)
	//			{
	//				szMessage.Format(L"Found: %s%s - \"%s\"", csHive, sKeyPart, sValuePart);
	//			}
	//			else if(sKeyPart)
	//			{
	//				szMessage.Format(L"Found: %s%s", csHive, sKeyPart);
	//			}
	//			else if(sValuePart)
	//			{
	//				szMessage.Format(L"Found: %s", sValuePart);
	//			}
	//			else
	//			{
	//				szMessage.Format(L"Found: [%d]", iTypeOfMessage);
	//			}
	//		}
	//		else if(sKeyPart && sValuePart)
	//		{
	//			szMessage.Format(L"Found: %s%s - \"%s\"", csHive, sKeyPart, sValuePart);
	//		}
	//		else if(sKeyPart)
	//		{
	//			szMessage.Format(L"Found: %s%s", csHive, sKeyPart);
	//		}
	//		else if(sValuePart)
	//		{
	//			szMessage.Format(L"Found: %s", sValuePart);
	//		}
	//		else
	//		{
	//			szMessage.Format(L"Found: [%d]", iTypeOfMessage);
	//		}
	//	}
	//}
	//else // Its a Information Message all other messages get logged in sdlog.txt
	//{
	//	if(g_csSDLog.GetLength() == 0)
	//	{
	//		CString csExeInstallPath = GetInstallPath();
	//		g_csSDLog = csExeInstallPath + LOG_FILE;
	//	}
	//	csLogFileName = g_csSDLog;
	//	if(bStartingScan)
	//	{
	//		if(sKeyPart)
	//		{
	//			szMessage.Format(L"Starting Scan: %s", sKeyPart);
	//		}
	//		else
	//		{
	//			szMessage.Format(L"Starting Scan: [%d]", iTypeOfMessage);
	//		}
	//	}
	//	else
	//	{
	//		if(sKeyPart)
	//		{
	//			szMessage.Format(L"Finished Scan: %s", sKeyPart);
	//		}
	//		else
	//		{
	//			szMessage.Format(L"Finished Scan: [%d]", iTypeOfMessage);
	//		}
	//	}
	//}

	//FILE *pOutFile = _wfsopen(csLogFileName, _T("a"), 0x40);
	//if(pOutFile != NULL)
	//{
	//	TCHAR tbuffer[9];
	//	TCHAR dbuffer[9];
	//	_wstrtime_s(tbuffer, 9);
	//	_wstrdate_s(dbuffer, 9);
	//	CString szOutMessage;
	//	szOutMessage.Format(_T("[%s %s] %s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
	//	fputws((LPCTSTR)szOutMessage, pOutFile);
	//	fclose(pOutFile);
	//}
}

CString GetInstallPath()
{
	try
	{
        TCHAR sExeFileName[MAX_FILE_PATH]={0};
		GetModuleFileName(0, sExeFileName, MAX_FILE_PATH);

 		CString csInstallPath;
		csInstallPath = sExeFileName;

		int iPos = 0;
		iPos = csInstallPath.ReverseFind('\\');
		if(iPos == -1)
		{
			return (csInstallPath + BACK_SLASH);
		}
		else
		{
			csInstallPath = csInstallPath.Mid(0, iPos);
			return (csInstallPath + BACK_SLASH);
		}
	}
	catch(...)
	{
		
	}
	return CString(_T(""));
}