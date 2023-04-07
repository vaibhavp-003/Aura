/*======================================================================================
   FILE				: pch.h 
   ABSTRACT			: source file that includes just the standard includes
   DOCUMENTS		: 
   AUTHOR			: Darshan Singh Virdi
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 20 Jan 2008
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/

#include "pch.h"
#include <time.h>
#include <io.h>
#include <string>
#include "SDSAConstants.h"
#include "CPUInfo.h"
#include "ProductInfo.h"
#include "Registry.h"
#include "MaxConstant.h"
#include <atlbase.h>

CString g_csSDLog(L"");
CString g_csMD5Log(L"");
CString g_csEPLog(L"");
CString g_csGenPELog(L"");
CString g_csVirusLog(L"");
CString g_csYaraLog(L"");

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

DWORD	g_dwLoggingLevel = LOG_ERROR;

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
			szMessage.Format(sFormatString, sEntry1, sEntry2);
		else if(sFormatString && sEntry1)
			szMessage.Format(sFormatString, sEntry1);
		else if(sFormatString && sEntry2)
			szMessage.Format(sFormatString, sEntry2);
		else if(sFormatString)
			szMessage.Format(sFormatString);

		TCHAR tbuffer[9];
		TCHAR dbuffer[9];
		_wstrtime_s(tbuffer, 9);
		_wstrdate_s(dbuffer, 9);
		
		CString szOutMessage;
		szOutMessage.Format(_T("[%s %s] %s\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
		
		fputws((LPCWSTR)szOutMessage, pLogFile);
		fflush(pLogFile);
	}
	catch(...)
	{	
	}
}

/*-------------------------------------------------------------------------------------
	Function		: AddLogEntry
	In Parameters	: const WCHAR *sFormatString	: This contains the format string to be logged according to param 2 and param 3
					  const char *sEntry1			: string to be replaced with first %s
					  const char *sEntry2			: string to be replaced with second %s
	Out	Parameters	: -
	Purpose			: Logging will be enabled only if the SDLog.txt file exists in the local path!
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void AddLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, int iLogLevel)
{
	if((DWORD)iLogLevel > g_dwLoggingLevel)
		return;

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
		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();
		csScanLogFullPath = csExeInstallPath + _T("Log\\AuActMonDrvLog.txt");
	}

	if(!pOutFile)
		pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);

	if(pOutFile != NULL)
		AddLogEntryToFile(pOutFile, sFormatString, sEntry1, sEntry2);
}

void AddLogEntryUSBlog(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2)
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
		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();
		csScanLogFullPath = csExeInstallPath + _T("Log\\USBActivityLog.txt");
	}

	if(!pOutFile)
		pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);
	
	if(pOutFile!= NULL)
	{
		fseek (pOutFile, 0, SEEK_END); 
		DWORD dwSize = ftell(pOutFile);
		if(	dwSize> 10485760)
		{
			if(pOutFile)
				fclose(pOutFile);
			pOutFile = NULL;
			DeleteFile(csScanLogFullPath);
			if(!pOutFile)
				pOutFile = _wfsopen(csScanLogFullPath, _T("a"), 0x40);
		}
	}
	if(pOutFile != NULL)
	{
		AddLogEntryToFile(pOutFile, sFormatString, sEntry1, sEntry2);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: AddExecLogEntry
	In Parameters	: const WCHAR *sFormatString	: This contains the format string to be logged according to param 2 and param 3
					  const char *sEntry1			: string to be replaced with first %s
					  const char *sEntry2			: string to be replaced with second %s
	Out	Parameters	: -
	Purpose			: Logging will be enabled only if the ExecSDLog.txt file exists in the local path!
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void AddExecLogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2)
{
	static CString csExecLogFullPath;
	static FILE *pExecOutFile = NULL;

	if(sFormatString == 0 && sEntry1 == 0 && sEntry2 == 0)
	{
		if(pExecOutFile)
			fclose(pExecOutFile);
		pExecOutFile = NULL;
		return;
	}

	if(csExecLogFullPath.GetLength() == 0)
	{
		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();
		csExecLogFullPath = csExeInstallPath + _T("Log\\ActMonExecSDLog.txt");
	}

	if(!pExecOutFile)
			pExecOutFile = _wfsopen(csExecLogFullPath, _T("a"), 0x40);

	if(pExecOutFile != NULL)
		AddLogEntryToFile(pExecOutFile, sFormatString, sEntry1, sEntry2);
}

/*-------------------------------------------------------------------------------------
	Function		: AddMD5LogEntry
	In Parameters	: const WCHAR *sFormatString	: This contains the format string to be logged according to param 2 and param 3
					  const char *sEntry1			: string to be replaced with first %s
					  const char *sEntry2			: string to be replaced with second %s
	Out	Parameters	: -
	Purpose			: Logging will be enabled only if the MD5SDLog.txt file exists in the local path!
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void AddMD5LogEntry(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2)
{
	static CString csMD5LogFullPath;
	static FILE *pMD5OutFile = NULL;

	if(sFormatString == 0 && sEntry1 == 0 && sEntry2 == 0)
	{
		if(pMD5OutFile)
			fclose(pMD5OutFile);
		pMD5OutFile = NULL;
		return;
	}

	if(csMD5LogFullPath.GetLength() == 0)
	{
		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();
		csMD5LogFullPath = csExeInstallPath + _T("Log\\ActMonMD5SDLog.txt");
	}

	if(!pMD5OutFile)
			pMD5OutFile = _wfsopen(csMD5LogFullPath, _T("a"), 0x40);

	if(pMD5OutFile != NULL)
		AddLogEntryToFile(pMD5OutFile, sFormatString, sEntry1, sEntry2);
}


void AddReplicationLog(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, int toBlock)
{
	static CString csMD5LogFullPath;
	static FILE *pMD5OutFile = NULL;

	if(sFormatString == 0 && sEntry1 == 0 && sEntry2 == 0)
	{
		if(pMD5OutFile)
			fclose(pMD5OutFile);
		pMD5OutFile = NULL;
		return;
	}

	if(csMD5LogFullPath.GetLength() == 0)
	{
		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();
		csMD5LogFullPath = csExeInstallPath + _T("Log\\ActReplicatingLog.txt");
	}

	if(!pMD5OutFile)
			pMD5OutFile = _wfsopen(csMD5LogFullPath, _T("a"), 0x40);

	if(pMD5OutFile != NULL)
		AddLogEntryToFile(pMD5OutFile, sFormatString, sEntry1, sEntry2);
}


//
///*-------------------------------------------------------------------------------------
//	Function		: AddInLiveMonitorLog
//	In Parameters	: -
//	Out Parameters	: bool
//	Purpose			: To make Active monitor Log
//	Author			: Dipali Pawar.
//--------------------------------------------------------------------------------------*/
//void AddInLiveMonitorLog( const CString &csSpyware,const CString &csFullPath, CString csType )
//{
//#ifdef SDENTERPRISE // for SDEE
//	OutputDebugString(L"AddInLiveMonitorLog > " + csSpyware + L", csFullPath > " + csFullPath); 
//	CCPUInfo objCPUInfo;
//	CString csSystemLogFolderPath = objCPUInfo.GetSystemDir();
//	csSystemLogFolderPath += SYSTEM_FOLDER;
//	csSystemLogFolderPath +=  LIVE_MONITOR_LOG_FOLDER ;	 
//
//	//CREATE LOG FOLDER
//	CreateDirectory( csSystemLogFolderPath, NULL );
//	
//	COleDateTime	objOleDateTime =  COleDateTime::GetCurrentTime();
//	CString			csLogFileName;
//	csLogFileName.Format (_T("%d %s %d"),objOleDateTime.GetDay(), objCPUInfo.GetMonthName(objOleDateTime.GetMonth()) ,objOleDateTime.GetYear()); 
//	//csLogFileName += _T(".ips");
//	csLogFileName += _T(".bs");
//	csLogFileName = csSystemLogFolderPath + csLogFileName;
//	CFileFind			objFileFind;
//	CFile				objLogFile;
//	CFileException		objFileException;
//	CMapStringToString	logFileMap;
//	logFileMap.RemoveAll ();
//	if( objFileFind.FindFile( csLogFileName ) )
//	{
//		try
//		{			
//			if( !objLogFile.Open( csLogFileName,CFile::modeRead,&objFileException ) )
//			{
//				return;
//			}
//			CArchive	objReadArchive( &objLogFile,CArchive::load );
//			logFileMap.Serialize( objReadArchive );
//			objReadArchive.Flush();
//			objReadArchive.Close();
//			objLogFile.Close();			
//		}
//		catch(...)
//		{
//			return;
//		}
//	}
//	CTime objTime = CTime::GetCurrentTime();
//	CString		csBuffer;
//	csBuffer.Format(_T("[ %d %s %d "), objTime.GetDay(),objCPUInfo.GetMonthName(objTime.GetMonth()), objTime.GetYear());
//	csBuffer.AppendFormat(_T("%s ] - "), objTime.Format(_T("%H:%M:%S"))); 
//	csBuffer+= csSpyware + _T(" < ") + csFullPath + _T(" > ");
//	logFileMap.SetAt( csBuffer,csType/*_T("Network Connection")*/ );
//	try
//	{
//		if( !objLogFile .Open( csLogFileName ,CFile::modeCreate|CFile::modeNoTruncate|CFile::modeWrite,&objFileException ) )
//		{
//			return ;
//		}
//		csLogFileName.ReleaseBuffer ();
//		CArchive	objWriteArchive( &objLogFile, CArchive::store );
//		logFileMap.Serialize( objWriteArchive );
//		objWriteArchive.Flush();
//		objWriteArchive.Close();
//		objLogFile .Close();
//	}
//	catch(...)
//	{
//		return ;
//	}
//#endif
//}

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
				g_csSDLog = csExeInstallPath + _T("Log\\AuActiveProtection.txt");
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
			szMessage.Format(L"Found: (Repair) %s - %s", sValuePart, sKeyPart);
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
			szMessage.Format(L"Found: (Quarantine) %s - %s", sValuePart, sKeyPart);
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
				g_csSDLog = csExeInstallPath + _T("Log\\AuActiveProtection.txt");
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
			g_csSDLog = csExeInstallPath + _T("Log\\AuActiveProtection.txt");
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
		szOutMessage.Format(_T("[%s %s] %s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
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
		
		
		else if(eMessageInfo == File && ulThreatID == 121218 && eDetectedBY == Detected_BY_Max_Yara)
		{
			if(g_csYaraLog.GetLength() == 0)
			{
				CProductInfo objPrdInfo;
				CString csExeInstallPath = objPrdInfo.GetInstallPath();
				g_csYaraLog = csExeInstallPath + L"Log\\YrScanLog.txt";
			}
			csLogFileName = g_csYaraLog;
			//csLog.Format(L"%s	detected: %s	%s", pScanInfo->szFileToScan, csThreatName, pScanInfo->szFileSig);
			szMessage.Format(L"%s	detected: %s	%s", szFileToScan, szThreatName, szFileSig);
		}
		
		else
		{
			return;
		}
		if(eMessageInfo != File && ulThreatID != 121218 && eDetectedBY != Detected_BY_Max_Yara)
		{
			szMessage.Format(L"Found: [%d][%d] %s - %s - %s", eDetectedBY, ulThreatID, szFileSig, szThreatName, szFileToScan);
		}
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
		szOutMessage.Format(_T("[%s %s] %s\r\n"), dbuffer, tbuffer, static_cast<LPCTSTR>(szMessage));
		fputws((LPCTSTR)szOutMessage, pOutFile);
		fclose(pOutFile);
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
}

void AddYaraLogEntryCmd(const TCHAR *sFormatString, const TCHAR *sEntry1, const TCHAR *sEntry2, bool isDateTime, int iLogLevel)
{
	
}