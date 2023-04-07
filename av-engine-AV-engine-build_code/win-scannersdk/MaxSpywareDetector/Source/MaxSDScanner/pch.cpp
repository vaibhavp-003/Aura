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
#include "SDConstants.h"
#include "ProductInfo.h"
#include "MaxConstant.h"
#include <time.h>
#include <io.h>
#include <atlbase.h>

CString g_csSDLog(L"");
CString g_csMD5Log(L"");
CString g_csEPLog(L"");
CString g_csGenPELog(L"");
CString g_csVirusLog(L"");
CString g_csLogCmd(L"");
CString g_csYaraLogCmd(L"");
DWORD	g_dwLoggingLevel = LOG_ERROR;
DWORD	g_dwLogType = 0;
DWORD	g_dwLogLevel = 0;

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

DWORD LoadLoggingLevel()
{
	CProductInfo objPrdInfo;
	CRegKey oRegKey;

	g_dwLoggingLevel = LOG_ERROR;
	if(ERROR_SUCCESS == oRegKey.Open(HKEY_LOCAL_MACHINE, objPrdInfo.GetProductRegKey(), KEY_READ))
	{
		oRegKey.QueryDWORDValue(LOGGING_LEVEL, g_dwLoggingLevel);
		oRegKey.Close();
	}
	return g_dwLoggingLevel;
}

void SetCmdLogPath(CString csLogPath, int iLogType, int iLogLevel)
{
	g_csLogCmd = csLogPath;
	g_dwLogType = iLogType;
	g_dwLogLevel = 0;
	if(iLogLevel == 1)
	{
		g_dwLogLevel =  1;
	}
}
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
	if((DWORD)iLogLevel > g_dwLoggingLevel)
		return;

	static CString csScanLogFullPath;
	if(csScanLogFullPath.GetLength() == 0)
	{
		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();
		csScanLogFullPath = csExeInstallPath + LOG_FILE;
	}

	FILE *pOutFile = _wfsopen(csScanLogFullPath, _T("a+"), 0x40);
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
			szOutMessage.Format(_T("[%s %s][%05d][%05d] %s\r\n"), dbuffer, tbuffer, GetCurrentProcessId(), GetCurrentThreadId(), static_cast<LPCTSTR>(szMessage));
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
				 const TCHAR *sDataPart, const TCHAR *sReplaceDataPart, bool bStartingScan)
{
	CString csLogFileName(L"");
	CString szMessage(L"");
	if(iTypeOfMessage < SD_Message_Info_TYPE_REG) // Its a File system Message
	{
		if((iTypeOfMessage == MD5) || (iTypeOfMessage == MD5_Report))
		{
			if(g_csMD5Log.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csMD5Log = csExeInstallPath + MD5_LOG_FILE;
			}
			csLogFileName = g_csMD5Log;
		}
		else if((iTypeOfMessage == ExecPath) || (iTypeOfMessage == ExecPath_Report))
		{
			if(g_csEPLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csEPLog = csExeInstallPath + PESIG_LOG_FILE;
			}
			csLogFileName = g_csEPLog;
		}
		else if((iTypeOfMessage == GenPEScan) || (iTypeOfMessage == GenPEScan_Report))
		{
			if(g_csGenPELog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csGenPELog = csExeInstallPath + GENPE_LOG_FILE;
			}
			csLogFileName = g_csGenPELog;
		}
		else
		{
			if(g_csSDLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csSDLog = csExeInstallPath + LOG_FILE;
			}
			csLogFileName = g_csSDLog;
		}
		if(sKeyPart && sValuePart)
		{
			szMessage.Format(L"Found: %s - %s", sValuePart, sKeyPart);
		}
		else if(sKeyPart)
		{
			szMessage.Format(L"Found: %s", sKeyPart);
		}
		else if(sValuePart)
		{
			szMessage.Format(L"Found: %s", sValuePart);
		}
		else
		{
			szMessage.Format(L"Found: [%d]", iTypeOfMessage);
		}
	}
	else if(iTypeOfMessage < SD_Message_Info_TYPE_INFO) // Its a Registry Message
	{
		if((iTypeOfMessage == Virus_File_Repair) || (iTypeOfMessage == Virus_File_Repair_Report))
		{
			if(g_csVirusLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csVirusLog = csExeInstallPath + VIRUS_LOG_FILE;
			}
			csLogFileName = g_csVirusLog;
			if(sDataPart)
				szMessage.Format(L"Found: (Repair) %d - %s - %s - %s", dwTypeOfData, sDataPart, sKeyPart, sValuePart);
			else
				szMessage.Format(L"Found: (Repair) %d - %s - %s", dwTypeOfData, sKeyPart, sValuePart);

		}
		else if((iTypeOfMessage == Virus_File) || (iTypeOfMessage == Virus_File_Report))
		{
			if(g_csVirusLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csVirusLog = csExeInstallPath + VIRUS_LOG_FILE;
			}
			csLogFileName = g_csVirusLog;
			if(sDataPart)
				szMessage.Format(L"Found: (Quarantine) %d - %s - %s - %s", dwTypeOfData, sDataPart, sKeyPart, sValuePart);
			else
				szMessage.Format(L"Found: (Quarantine) %d - %s - %s", dwTypeOfData, sKeyPart, sValuePart);
		}
		else if((iTypeOfMessage == Cookie_New))
		{
			if(g_csSDLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csSDLog = csExeInstallPath + LOG_FILE;
			}
			csLogFileName = g_csSDLog;

			szMessage.Format(L"Found: %s", sKeyPart);	
		}
		else
		{
			CString csHive;
			if(sKeyPart)
			{
				if(sKeyPart[0] == '.' || sKeyPart[1] == '-')
				{
					csHive = L"HKEY_USERS\\";
				}
				else
				{
					csHive = L"HKEY_LOCAL_MACHINE\\";
				}
			}
			if(g_csSDLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csSDLog = csExeInstallPath + LOG_FILE;
			}
			csLogFileName = g_csSDLog;
			if(dwTypeOfData != REG_NONE)
			{
				if(dwTypeOfData == REG_SZ)
				{
					if(sKeyPart && sValuePart && sDataPart && sReplaceDataPart)
					{
						szMessage.Format(L"Found: %s%s - \"%s\" - \"%s\" - \"%s\"", csHive, sKeyPart, sValuePart,
																					sDataPart, sReplaceDataPart);
					}
					else if(sKeyPart && sValuePart && sDataPart)
					{
						szMessage.Format(L"Found: %s%s - \"%s\" - \"%s\"", csHive, sKeyPart, sValuePart, sDataPart);
					}
				}
				else if(dwTypeOfData == REG_DWORD)
				{
					DWORD dwData = 0, dwReplaceData = 0;
					if(sDataPart)
					{
						memcpy_s(&dwData, sizeof(DWORD), sDataPart, sizeof(DWORD));
					}
					if(sReplaceDataPart)
					{
						memcpy_s(&dwReplaceData, sizeof(DWORD), sReplaceDataPart, sizeof(DWORD));
					}
					if(sKeyPart && sValuePart && sDataPart && sReplaceDataPart)
					{
						szMessage.Format(L"Found: %s%s - \"%s\" - \"%d\" - \"%d\"", csHive, sKeyPart, 
																	sValuePart, dwData, dwReplaceData);
					}
					else if(sKeyPart && sValuePart && sDataPart)
					{
						szMessage.Format(L"Found: %s%s - \"%s\" - \"%d\"", csHive, sKeyPart, sValuePart, dwData);
					}
				}
				else if(sKeyPart && sValuePart)
				{
					szMessage.Format(L"Found: %s%s - \"%s\"", csHive, sKeyPart, sValuePart);
				}
				else if(sKeyPart)
				{
					szMessage.Format(L"Found: %s%s", csHive, sKeyPart);
				}
				else if(sValuePart)
				{
					szMessage.Format(L"Found: %s", sValuePart);
				}
				else
				{
					szMessage.Format(L"Found: [%d]", iTypeOfMessage);
				}
			}
			else if(sKeyPart && sValuePart)
			{
				szMessage.Format(L"Found: %s%s - \"%s\"", csHive, sKeyPart, sValuePart);
			}
			else if(sKeyPart)
			{
				szMessage.Format(L"Found: %s%s", csHive, sKeyPart);
			}
			else if(sValuePart)
			{
				szMessage.Format(L"Found: %s", sValuePart);
			}
			else
			{
				szMessage.Format(L"Found: [%d]", iTypeOfMessage);
			}
		}
	}
	else // Its a Information Message all other messages get logged in sdlog.txt
	{
		if(g_csSDLog.GetLength() == 0)
		{
			CProductInfo objPrdInfo;
			CString csExeInstallPath = objPrdInfo.GetInstallPath();
			g_csSDLog = csExeInstallPath + LOG_FILE;
		}
		csLogFileName = g_csSDLog;
		if(bStartingScan)
		{
			if(sKeyPart)
			{
				szMessage.Format(L"Starting Scan: %s", sKeyPart);
			}
			else
			{
				szMessage.Format(L"Starting Scan: [%d]", iTypeOfMessage);
			}
		}
		else
		{
			if(sKeyPart)
			{
				szMessage.Format(L"Finished Scan: %s", sKeyPart);
			}
			else
			{
				szMessage.Format(L"Finished Scan: [%d]", iTypeOfMessage);
			}
		}
	}

	FILE *pOutFile = _wfsopen(csLogFileName, _T("a"), 0x40);
	if(pOutFile != NULL)
	{
		TCHAR tbuffer[9];
		TCHAR dbuffer[9];
		_wstrtime_s(tbuffer, 9);
		_wstrdate_s(dbuffer, 9);
		CString szOutMessage;
		szOutMessage.Format(_T("[%s %s][%05d][%05d] %s\r\n"), dbuffer, tbuffer, GetCurrentProcessId(), GetCurrentThreadId(), static_cast<LPCTSTR>(szMessage));
		fputws((LPCTSTR)szOutMessage, pOutFile);
		fclose(pOutFile);
	}
}

void AddLogEntry(SD_Message_Info eMessageInfo, LPCTSTR szFileToScan, LPCTSTR szFileSig, SD_Detected_BY eDetectedBY, const DWORD ulThreatID, LPCTSTR szThreatName)
{
	CString csLogFileName(L"");
	CString szMessage(L"");
	if(eMessageInfo < SD_Message_Info_TYPE_REG) // Its a File system Message
	{
		if((eMessageInfo == MD5) || (eMessageInfo == MD5_Report))
		{
			if(g_csMD5Log.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csMD5Log = csExeInstallPath + MD5_LOG_FILE;
			}
			csLogFileName = g_csMD5Log;
		}
		else if((eMessageInfo == ExecPath) || (eMessageInfo == ExecPath_Report))
		{
			if(g_csEPLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csEPLog = csExeInstallPath + PESIG_LOG_FILE;
			}
			csLogFileName = g_csEPLog;
		}
		else if((eMessageInfo == GenPEScan) || (eMessageInfo == GenPEScan_Report))
		{
			if(g_csGenPELog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csGenPELog = csExeInstallPath + GENPE_LOG_FILE;
			}
			csLogFileName = g_csGenPELog;
		}
		else
		{
			return;
		}
		szMessage.Format(L"Found: [%d][%d] %s - %s - %s", eDetectedBY, ulThreatID, szFileSig, szThreatName, szFileToScan);
	}
	else if(eMessageInfo < SD_Message_Info_TYPE_INFO) // Its a Registry Message
	{
		if((eMessageInfo == Virus_File_Repair) || (eMessageInfo == Virus_File_Repair_Report))
		{
			if(g_csVirusLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csVirusLog = csExeInstallPath + VIRUS_LOG_FILE;
			}
			csLogFileName = g_csVirusLog;
			szMessage.Format(L"Found: (Repair) [%d][%d] %s - %s - %s", eDetectedBY, ulThreatID, szFileSig, szThreatName, szFileToScan);
		}
		else if((eMessageInfo == Virus_File) || (eMessageInfo == Virus_File_Report))
		{
			if(g_csVirusLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csVirusLog = csExeInstallPath + VIRUS_LOG_FILE;
			}
			csLogFileName = g_csVirusLog;
			szMessage.Format(L"Found: (Quarantine) [%d][%d] %s - %s - %s", eDetectedBY, ulThreatID, szFileSig, szThreatName, szFileToScan);
		}
		else
		{
			return;
		}
	}
	else
	{
		return;
	}

	FILE *pOutFile = _wfsopen(csLogFileName, _T("a"), 0x40);
	if(pOutFile != NULL)
	{
		TCHAR tbuffer[9];
		TCHAR dbuffer[9];
		_wstrtime_s(tbuffer, 9);
		_wstrdate_s(dbuffer, 9);
		CString szOutMessage;
		szOutMessage.Format(_T("[%s %s][%05d][%05d] %s\r\n"), dbuffer, tbuffer, GetCurrentProcessId(), GetCurrentThreadId(), static_cast<LPCTSTR>(szMessage));
		fputws((LPCTSTR)szOutMessage, pOutFile);
		fclose(pOutFile);
	}
}

/*-------------------------------------------------------------------------------------
Function		: AddLogEntryToFile
In Parameters	: FILE*, const TCHAR *, const TCHAR *, const TCHAR *
Out Parameters	: void
Purpose			: Logs in the given File
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void AddLogEntryToFile(FILE *pLogFile, const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2)
{
	try
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

		TCHAR tbuffer[9];
		TCHAR dbuffer[9];
		_wstrtime_s(tbuffer, 9);
		_wstrdate_s(dbuffer, 9);

		CString szOutMessage;
		szOutMessage.Format(_T("[%s %s] %s\n"), dbuffer, tbuffer, szMessage);
		OutputDebugString(szOutMessage);
		fputws((LPCWSTR)szOutMessage, pLogFile);
		fflush(pLogFile);
	}
	catch(...)
	{
	}
}

/*-------------------------------------------------------------------------------------
Function		: AddMLearningLogEntry
In Parameters	: const WCHAR *sFormatString	: This contains the format string to be logged according to param 2 and param 3
				const char *sEntry1			: string to be replaced with first %s
				const char *sEntry2			: string to be replaced with second %s
Out	Parameters	: -
Purpose			: Logging will be enabled only if the MLearningLog.txt file exists in the local path!
Author			: Tushar Kadam
--------------------------------------------------------------------------------------*/
/*
void AddMLearningLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2)
{

	//return;
	static CString csMLLogFullPath;
	static FILE *pMLOutFile = NULL;

	if(sFormatString == 0 && sEntry1 == 0 && sEntry2 == 0)
	{
		if(pMLOutFile)
		{
			fclose(pMLOutFile);
		}
		pMLOutFile = NULL;
		return;
	}

	if(csMLLogFullPath.GetLength() == 0)
	{
		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();
		csMLLogFullPath = csExeInstallPath + _T("Log\\MLearningLog.txt");
	}

	if(!pMLOutFile)
	{
		pMLOutFile = _wfsopen(csMLLogFullPath, _T("a"), 0x40);
	}

	if(pMLOutFile != NULL)
	{
		//AddLogEntryToFile(pMLOutFile, sFormatString, sEntry1, sEntry2);

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

		TCHAR tbuffer[9];
		TCHAR dbuffer[9];
		_wstrtime_s(tbuffer, 9);
		_wstrdate_s(dbuffer, 9);

		CString szOutMessage;
		szOutMessage.Format(_T("[%s %s] %s\n"), dbuffer, tbuffer, szMessage);
		OutputDebugString(szOutMessage);
		fputws((LPCWSTR)szOutMessage, pMLOutFile);
		//fflush(pLogFile);

		fclose(pMLOutFile);
		pMLOutFile = NULL;
	}
}
*/
void AddMLearningLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2)
{
	static CString csScanLogFullPath;
	if(csScanLogFullPath.GetLength() == 0)
	{
		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();
		csScanLogFullPath = csExeInstallPath + _T("Log\\MLrngLog.txt");
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

		
		TCHAR tbuffer[9];
		TCHAR dbuffer[9];
		_wstrtime_s(tbuffer, 9);
		_wstrdate_s(dbuffer, 9);

		CString szOutMessage;
		szOutMessage.Format(_T("[%s %s] %s\n"), dbuffer, tbuffer, szMessage);

		fputws((LPCTSTR)szOutMessage, pOutFile);
		
		fclose(pOutFile);
	}
}
/*-----------------------------------------------------------------------------
Function		: AddLogEntryCmd
In Parameters	: 
Out Parameters	: const char *sFormatString	: This contains the format string to be 
logged according to param 2 and param 3
const char *sEntry1		: string to be replaced with first %s
const char *sEntry2		: string to be replaced with second %s
Purpose			: Adds a entry to the log file
Author			: 
-----------------------------------------------------------------------------*/
void AddLogEntryCmd(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, int iLogLevel)
{
	if(g_dwLogType <= 0)
		return;
	bool bRet = false;
	if((DWORD)iLogLevel > g_dwLoggingLevel)
		bRet = true;

	if(g_dwLogType== 1)
	{
		if(g_dwLogLevel == 1)
		{
			bRet = false;
		}
		else 
		{
			if(iLogLevel>0)
			{
				bRet = true;
			}
		}
	}
	if(bRet)
	{
		return;
	}
	
	if(g_csLogCmd.GetLength() == 0)
	{
		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();
		g_csLogCmd = csExeInstallPath + LOG_SCAN_RESULT_CMD;
	}
	
	FILE *pOutFile = _wfsopen(g_csLogCmd, _T("a"), 0x40);
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

		TCHAR tbuffer[9];
		TCHAR dbuffer[9];
		_wstrtime_s(tbuffer, 9);
		_wstrdate_s(dbuffer, 9);

		CString szOutMessage;
		szOutMessage.Format(_T("[%s %s]	%s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
		fputws((LPCTSTR)szOutMessage, pOutFile);

		fclose(pOutFile);
	}
}


void AddYaraLogEntryCmd(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, int iLogLevel)
{
	if(g_dwLogType <= 0)
		return;
	bool bRet = false;
	if((DWORD)iLogLevel > g_dwLoggingLevel)
		bRet = true;

	if(g_dwLogType== 1)
	{
		if(g_dwLogLevel == 1)
		{
			bRet = false;
		}
		else 
		{
			if(iLogLevel>0)
			{
				bRet = true;
			}
		}
	}
	if(bRet)
	{
		return;
	}

	if(g_csYaraLogCmd.GetLength() == 0)
	{
		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();
		g_csYaraLogCmd = csExeInstallPath + L"Log\\YrScanLog.txt";
	}
	
	FILE *pOutFile = _wfsopen(g_csYaraLogCmd, _T("a"), 0x40);
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

		TCHAR tbuffer[9];
		TCHAR dbuffer[9];
		_wstrtime_s(tbuffer, 9);
		_wstrdate_s(dbuffer, 9);

		CString szOutMessage;
		szOutMessage.Format(_T("[%s %s]	%s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
		fputws((LPCTSTR)szOutMessage, pOutFile);

		fclose(pOutFile);
	}
}