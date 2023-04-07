/*======================================================================================
FILE             : ThreatManager.h
ABSTRACT         :
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE): 
                   (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be 
                   used, copied, reproduced, transmitted, or stored in any form or by any 
                   means, electronic, recording, photocopying, mechanical or otherwise, 
                   without the prior written permission of Aura.	
CREATION DATE    : 8/1/2009 6:51:30 PM
NOTES            : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include <shlwapi.h>
#include "ThreatManager.h"
#include "MaxConstant.h"
#include "BackupOperations.h"
#include "Enumprocess.h"
#include "SDSystemInfo.h"
#include "SDConstants.h"
#include "Registry.h"
#include "ZipArchive.h"
#include "HardDiskManager.h"
#include "CPUInfo.h"
#include "Shlwapi.h"
#include "ProductInfo.h"
#include "DirectoryManager.h"

#ifdef _SDSCANNER
#include "BufferToStructure.h"
#include "NetWorkUserValidation.h"
#include <Lmcons.h>
#include <lm.h>
#pragma comment(lib, "netapi32.lib")
#endif
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

ULONG CThreatManager::m_lFreeDiskSpace = 0;
#define IOCTL_DELETE_FILE			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x856, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
/*--------------------------------------------------------------------------------------
Function       : CThreatManager::CThreatManager
In Parameters  :
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CThreatManager::CThreatManager(SENDMESSAGETOUI lpSendMessaegToUI):m_lpSendMessaegToUI(lpSendMessaegToUI)
{
	m_bAutomationLab = false;
	m_pMaxDSrvWrapper = NULL;
	m_bRestartQuarantine = false;
	m_bRestartRequired = false;
	m_bRootkitFound = false;
	m_lFreeDiskSpace = GetHardDiskSpaceAvailable();
	CCPUInfo objCPU;
	m_bIs64Bit = objCPU.isOS64bit();
	m_csDesktopPath = oDBPathExpander.GetCurrentUserPath();
	m_csDesktopPath += L"\\Desktop";

	CRegistry objReg;
	DWORD dw = 0;
	CString csMaxDBPath;
	objReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("ThreatCommunity"), dw, HKEY_LOCAL_MACHINE);
	m_bThreatCommEnable = 1 == dw;
	m_bThreatCommDataFound = false;
	m_csRescanFilePath = L"";
	m_objSysFiles.LoadSysDB(csMaxDBPath);
	m_bIsFromFWUI = FALSE;
	m_bValidated = false;

}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::~CThreatManager
In Parameters  :
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CThreatManager::~CThreatManager()
{
	if(m_pMaxDSrvWrapper)
	{
		m_pMaxDSrvWrapper->DeInitializeVirusScanner();
		delete m_pMaxDSrvWrapper;
		m_pMaxDSrvWrapper = NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CheckHardDiskSpaceAvailable
In Parameters  : double dwDiskFreeSize, 
Out Parameters : BOOL 
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
ULONG CThreatManager::GetHardDiskSpaceAvailable()
{
	CRegistry objReg;
	CString csTemp;

	objReg.Get(CSystemInfo::m_csProductRegKey,_T("AppFolder"), csTemp,
		HKEY_LOCAL_MACHINE);
	int iCount = csTemp.Find (':');
	CString csInstalledDrive =  csTemp.Left(iCount + 1);

	CHardDiskManager objHardDiskManager;
	objHardDiskManager.CheckFreeSpace(csInstalledDrive);
	return (ULONG)(objHardDiskManager.GetTotalNumberOfFreeGBytes()*1024);
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::GetBackupFileName
In Parameters  : LPTSTR szBackupFilename,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CThreatManager::GetBackupFileName(LPTSTR szBackupFilename)
{
	GetTempFileName(static_cast<LPCTSTR>(CBackupOperations::GetQuarantineFolderPath()), 0,
					0, szBackupFilename);
}

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 4244)
#endif
/*--------------------------------------------------------------------------------------
Function       : CThreatManager::PerformQuarantine
In Parameters  : bool bCallFromRestart,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CThreatManager::PerformQuarantine(bool bCallFromRestart)
{
	CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
	if(::PathFileExists(strINIPath))
	{

		CFile oFile(strINIPath, CFile::modeRead);
		ULONGLONG ulFileLen = oFile.GetLength();

		LPBYTE lpbBuffer = new BYTE[ulFileLen];
		memset(lpbBuffer, 0, ulFileLen);
		oFile.Read((LPVOID)lpbBuffer, ulFileLen);
		oFile.Close();

		m_bRestartQuarantine = bCallFromRestart;

		if(m_bRestartQuarantine)
		{
			DeleteFile(strINIPath);
		}

		ProcessBuffer((PWCHAR)lpbBuffer, (ulFileLen/sizeof(TCHAR)));
		delete [] lpbBuffer;
		lpbBuffer = NULL;

		if(!m_bRootkitFound && (!m_bRestartRequired || m_bRestartQuarantine))
		{
			DeleteFile(strINIPath);
		}
	}

	if(bCallFromRestart)
	{
		CProductInfo objProductInfo;
		CString strAppPath = objProductInfo.GetAppInstallPath();
		CDirectoryManager oDirectoryManager;
		oDirectoryManager.MaxDeleteTempData(strAppPath + CString(L"\\TempData"));
		oDirectoryManager.MaxDeleteTempData(strAppPath + CString(L"\\TempFolder"));
	}
}
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning (default:4244)
#endif

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::ProcessBuffer
In Parameters  : PWCHAR pBuffer, ULONG ulSizeOfBuffer,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CThreatManager::ProcessBuffer(PWCHAR pBuffer, ULONG ulSizeOfBuffer)
{
	DWORD dwCtr = 0;
	DWORD dwFilePos = 0;
	WCHAR wsLineRead[MAX_PATH] = {0};

	if(!pBuffer)
	{
		return;
	}

	m_CurrRDType = RD_INVALID;
	for(; dwCtr < ulSizeOfBuffer && dwFilePos < MAX_PATH; dwCtr++)
	{
		if((pBuffer[dwCtr] == 0x0A) || (pBuffer[dwCtr] == 0x0D) || (pBuffer[dwCtr] == 0x00))
		{
			if(dwFilePos != 0)
			{
				ProcessLine(wsLineRead);
				memset(wsLineRead, 0, dwFilePos*2);
				dwFilePos = 0;
			}
		}
		else
		{
			wsLineRead[dwFilePos] = pBuffer[dwCtr];
			dwFilePos++;
		}
	}
	if(dwFilePos != 0)
	{
		ProcessLine(wsLineRead);
		memset(wsLineRead, 0, dwFilePos*2);
		dwFilePos = 0;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::ProcessLine
In Parameters  : PWCHAR wsLineRead,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CThreatManager::ProcessLine(PWCHAR wsLineRead)
{
	if(!wsLineRead)
	{
		return;
	}

	if(memcmp(wsLineRead, L"WormCnt", 7)== 0)
	{
		return;
	}

	if(wsLineRead[0] == '[')			// reset current section as new section is starting
	{
		m_CurrRDType = RD_INVALID;
	}

	if(wcscmp(wsLineRead, L"[File_Delete]")== 0)
	{
		m_CurrRDType = RD_FILE_DELETE;
		return;
	}

	if(wcscmp(wsLineRead, L"[File_Backup]")== 0)
	{
		m_CurrRDType = RD_FILE_BACKUP;
		return;
	}

	if(wcscmp(wsLineRead, L"[Folder]")== 0)
	{
		m_CurrRDType = RD_FOLDER;
		return;
	}

	if(wcscmp(wsLineRead, L"[RegistryKey]")== 0)
	{
		m_CurrRDType = RD_KEY;
		return;
	}

	if(wcscmp(wsLineRead, L"[RegistryValue]")== 0)
	{
		m_CurrRDType = RD_VALUE;
		return;
	}
	
	if(wcscmp(wsLineRead, L"[File_Rename]")== 0)
	{
		m_CurrRDType = RD_FILE_RENAME;
		return;
	}
	if(wcscmp(wsLineRead, L"[File_Replace]")== 0)
	{
		m_CurrRDType = RD_FILE_REPLACE;
		return;
	}
	if(wcscmp(wsLineRead, L"[Native_Backup]")== 0)
	{
		m_CurrRDType = RD_NATIVE_BACKUP;
		return;
	}

	switch(m_CurrRDType)
	{
	case RD_FILE_DELETE:
	case RD_FILE_BACKUP:
	case RD_NATIVE_BACKUP:
	case RD_FOLDER:
		{
			if(!m_bRestartQuarantine && (m_CurrRDType == RD_FILE_BACKUP || m_CurrRDType == RD_NATIVE_BACKUP))
			{
				m_bRestartRequired = true;
				break;
			}

			int iPos = 0;
			CString csLine(wsLineRead);
			csLine.Tokenize(L"=^", iPos);
			CString csSpyID = csLine.Tokenize(L"=^", iPos);
			CString csValue = csLine.Tokenize(L"=^", iPos);
			if(m_CurrRDType == RD_FILE_DELETE)
			{
				if(m_bRestartQuarantine)
				{
					csValue += L".sd";
				}

				if(_waccess(csValue, 0)== 0)
				{
					bool bRet = DeleteFile(csValue)? true : false;
					if(!bRet)
					{
						if(GetLastError()== ERROR_FILE_NOT_FOUND)
						{
							bRet = true;
						}
					}
					if(!bRet)
					{
						AddLogEntry(_T("@@@@@@ : Quarantine File failed %s"), csValue);
						m_bRestartRequired = true;
					}
				}
			}
			else if(m_CurrRDType == RD_FOLDER)
			{
				if(_waccess(csValue, 0)== 0)
				{
					if(!RecursiveDeleteFolder(csValue))
					{
						AddLogEntry(_T("@@@@@@ : Quarantine Folder failed %s"), csValue);
						m_bRestartRequired = true;
					}
				}
			}
			else
			{
				MAX_PIPE_DATA oMaxData = {0};
#pragma warning(disable: 4482)
				oMaxData.eMessageInfo = ((m_CurrRDType == RD_FILE_DELETE) || (m_CurrRDType == RD_FILE_BACKUP) || (m_CurrRDType == RD_NATIVE_BACKUP)? File : SD_Message_Info::Folder);
#pragma warning(default: 4482)
				oMaxData.ulSpyNameID = _wtoi((LPCTSTR)csSpyID);
				wcscpy_s(oMaxData.strValue, csValue);
				PerformDBAction(&oMaxData);
			}
		}
		break;
	case RD_KEY:
	case RD_VALUE:
		{
			int iPos = 0;
			CString csLine(wsLineRead);
			csLine.Tokenize(L"=^", iPos);
			csLine.Tokenize(L"=^", iPos);
			CString csKey = csLine.Tokenize(L"=^", iPos);
			CRegistry oRegistry;
			HKEY hMainKey = NULL;
			if(oRegistry.FormulatePath(csKey, hMainKey))
			{
				oRegistry.SetWow64Key(Is64BitKey(csKey));
				if(m_CurrRDType == RD_KEY)
				{
					if(oRegistry.KeyExists(csKey, hMainKey))
					{
						if(!oRegistry.DeleteRegKey(hMainKey, csKey))
						{
							AddLogEntry(_T("@@@@@@ : Quarantine RegKey failed %s"), csKey);
							m_bRestartRequired = true;
						}					
					}
				}
				else
				{
					int iFind = csKey.Find(L"\t#@#");
					if(iFind != -1)
					{
						CString csValue  = csKey.Mid(iFind + 4, csKey.GetLength());
						csKey = csKey.Mid(0, iFind);
						if(oRegistry.KeyExists(csKey, hMainKey))
						{
							if(!oRegistry.DeleteValue(csKey, csValue, hMainKey))
							{
								AddLogEntry(_T("@@@@@@ : Quarantine RegValue  failed %s %s "),
											csValue, csValue);
								m_bRestartRequired = true;
							}
						}
					}
				}
			}
		}
		break;

	case RD_FILE_RENAME:
	case RD_FILE_REPLACE:
		{
			m_bRestartRequired = true;
		}
		break;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::PerformDBAction
In Parameters  : LPMAX_PIPE_DATA pMaxPipeData,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::PerformDBAction(LPMAX_PIPE_DATA pMaxPipeData)
{
	bool bRet = false;

	if(!pMaxPipeData)
	{
		return false;
	}

	switch(pMaxPipeData->eMessageInfo)
	{
	case Process:
	case Process_Report:
	case Special_Process:
	case Special_Process_Report:
	case KeyLogger_Process:
	case KeyLogger_Process_Report:
	case Virus_Process:
	case Virus_Process_Report:
		{
			if(pMaxPipeData->eMessageInfo%2 == 0)
			{
				bRet = HandleProcesses(pMaxPipeData->strValue);
				if(bRet)
				{
					AddLogEntry(L"##### : %s", pMaxPipeData->strValue);
				}
				else
				{
					AddLogEntry(L"----- : %s", pMaxPipeData->strValue);
				}
			}
			else
			{
				bRet = true;
			}
			break;
		}
#pragma warning(disable: 4482)
	case SD_Message_Info::Folder:
#pragma warning(default: 4482)
	case Folder_Report:
	case Special_Folder:
	case Special_Folder_Report:
	case KeyLogger_Folder:
	case KeyLogger_Folder_Report:
		{
			DWORD dwDelFileSize = 0;
			if( CheckForDiskSpace(false, dwDelFileSize)  == false)
			{
				return false;
			}

			bRet = QuarantineFolder(pMaxPipeData);
			if(bRet)
			{
				AddLogEntry(L"##### : %s", pMaxPipeData->strValue);
			}
			else
			{
				AddLogEntry(L"----- : %s", pMaxPipeData->strValue);
			}
			break;
		}
	case File:
	case File_Report:
	case MD5:
	case MD5_Report:
	case ExecPath:
	case ExecPath_Report:
	case GenPEScan:
	case GenPEScan_Report:
	case /*Cookie*/Cookie_New:
	case Cookie_Report:
	case Special_File:
	case Special_File_Report:
	case KeyLogger_File:
	case KeyLogger_File_Report:
	case Recursive_Quarantine:
		{
			DWORD dwDelFileSize = 0;
			if(CheckForDiskSpace(true, dwDelFileSize, pMaxPipeData->strValue)  == false)
			{
				return false;
			}
			bRet = QuarantineFile(pMaxPipeData);
			if(bRet)
			{
				m_lFreeDiskSpace -= dwDelFileSize;
				AddLogEntry(L"##### : %s", pMaxPipeData->strValue);
			}
			else
			{
				AddLogEntry(L"----- : %s", pMaxPipeData->strValue);
			}
			break;
		}
	case Finished_Quarantine:
		{
			AddLogEntry(L"Finished Quarantine message received!", NULL, NULL, true, LOG_DEBUG);
			m_bRestartRequired = false;
			PerformQuarantine(false);
			if(m_bRootkitFound)
			{
				m_bRestartRequired = true;
			}
			if(m_pMaxDSrvWrapper)
			{
				m_pMaxDSrvWrapper->DeInitializeVirusScanner();
				delete m_pMaxDSrvWrapper;
				m_pMaxDSrvWrapper = NULL;
			}
			return m_bRestartRequired;
		}
	case Rootkit_Folder:
	case Rootkit_Folder_Report:
		{
			m_bRootkitFound = true;
			AddLogEntry(_T("rtkt folder: %s"), pMaxPipeData->strValue);
			if(!m_pMaxDSrvWrapper)
			{
				m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
				if(m_pMaxDSrvWrapper)
				{
					AddLogEntry(_T("rtkt folder, create dsrv: %s"), pMaxPipeData->strValue, 0, true, LOG_DEBUG);
					m_pMaxDSrvWrapper->InitializeVirusScanner();
				}
			}
			if(m_pMaxDSrvWrapper)
			{
				AddLogEntry(_T("rtkt folder exclude: %s"), pMaxPipeData->strValue, 0, true, LOG_DEBUG);
				m_pMaxDSrvWrapper->Exclude(pMaxPipeData->ulSpyNameID, _T("Rootkit_Entry"), pMaxPipeData->strValue);
			}
			AddLogEntry(_T("rtkt folder add in restart del list: %s"), pMaxPipeData->strValue, 0, true, LOG_DEBUG);
			AddInRestartDeleteList(RD_FOLDER, pMaxPipeData->ulSpyNameID, pMaxPipeData->strValue);
			AddLogEntry(L"----- : %s", pMaxPipeData->strValue);
			bRet = false;
			break;
		}
	case Rootkit_Process:
	case Rootkit_Process_Report:
	case Rootkit_File:
	case Rootkit_File_Report:
		{
			m_bRootkitFound = true;
			AddLogEntry(_T("rtkt file: %s"), pMaxPipeData->strValue, 0, true, LOG_DEBUG);
			if(!m_pMaxDSrvWrapper)
			{
				m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
				if(m_pMaxDSrvWrapper)
				{
					AddLogEntry(_T("rtkt file, create dsrv: %s"), pMaxPipeData->strValue, 0, true, LOG_DEBUG);
					m_pMaxDSrvWrapper->InitializeVirusScanner();
				}
			}
			if(m_pMaxDSrvWrapper)
			{
				AddLogEntry(_T("rtkt file exclude: %s"), pMaxPipeData->strValue, 0, true, LOG_DEBUG);
				m_pMaxDSrvWrapper->Exclude(pMaxPipeData->ulSpyNameID, _T("Rootkit_Entry"), pMaxPipeData->strValue);
			}
			AddLogEntry(_T("try del by driver: %s"), pMaxPipeData->strValue, 0, true, LOG_DEBUG);
			if(!DelFileUsingDriver(pMaxPipeData->strValue))
			{
				AddLogEntry(_T("del by driver fail, del file: %s"), pMaxPipeData->strValue, 0, true, LOG_DEBUG);
				DeleteFile(pMaxPipeData->strValue);
			}
			else
			{
				AddLogEntry(_T("del by driver success: %s"), pMaxPipeData->strValue, 0, true, LOG_DEBUG);
			}

			AddLogEntry(_T("adding in restart del llist: %s"), pMaxPipeData->strValue, 0, true, LOG_DEBUG);
			AddInRestartDeleteList(RD_FILE_BACKUP, pMaxPipeData->ulSpyNameID, pMaxPipeData->strValue);
			AddLogEntry(L"----- : %s", pMaxPipeData->strValue);
			bRet = false;
			break;
		}
	case System_File_Replace:
		{
			bRet = false;
			CString csMaxFormat;
			csMaxFormat = pMaxPipeData->strFreshFile;
			csMaxFormat += RENAME_FILE_SEPARATOR;
			csMaxFormat += pMaxPipeData->strValue;
			AddInRestartDeleteList(RD_FILE_REPLACE, pMaxPipeData->ulSpyNameID, csMaxFormat);
			AddLogEntry(L"----- : %s", csMaxFormat);

		}
		break;
	case Pattern_File:
		{
			bRet = false;
			DWORD dwDelFileSize = 0;
			if(CheckForDiskSpace(true, dwDelFileSize, pMaxPipeData->strValue)  == false)
			{
				return false;
			}
			bRet = QuarantineFile(pMaxPipeData);
			CheckFileForHiddenFolder(pMaxPipeData->strValue);

			if(bRet)
			{
				m_lFreeDiskSpace -= dwDelFileSize;
				AddLogEntry(L"##### : %s", pMaxPipeData->strValue);
			}
			else
			{
				AddLogEntry(L"----- : %s", pMaxPipeData->strValue);
			}

		}
		break;
	default:
		{
			return false;
			break;
		}
	}
	if(!bRet)
	{
		m_bRestartRequired = true;
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::HandleProcesses
In Parameters  : LPCTSTR strValue,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::HandleProcesses(LPCTSTR strValue)
{
	bool bRet = true;
	CEnumProcess objEnumProc;
	bRet = objEnumProc.IsProcessRunning(strValue, true);
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::RecursiveDeleteFolder
In Parameters  : LPCTSTR strValue,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::RecursiveDeleteFolder(LPCTSTR strValue)
{
	bool bRetVal = true;
	HANDLE hFindFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA FindFileData = {0};

	TCHAR *cSearchPath = new TCHAR[MAX_PATH];
	TCHAR *cFullPath = new TCHAR[MAX_PATH];
	wmemset(cSearchPath, 0, MAX_PATH);
	wmemset(cFullPath, 0, MAX_PATH);

	wcscpy_s(cSearchPath, MAX_PATH, strValue);
	wcscat_s(cSearchPath, MAX_PATH, L"\\*.*");

	hFindFile = FindFirstFile(cSearchPath, &FindFileData);
	if(INVALID_HANDLE_VALUE != hFindFile)
	{
		do
		{
			if((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) 
												== FILE_ATTRIBUTE_REPARSE_POINT)
			{
				continue;
			}

			wcscpy_s(cFullPath, MAX_PATH, strValue);
			wcscat_s(cFullPath, MAX_PATH, L"\\");
			wcscat_s(cFullPath, MAX_PATH, FindFileData.cFileName);

			if((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
												== FILE_ATTRIBUTE_DIRECTORY)
			{
				if((wcscmp(FindFileData.cFileName, L".") != 0) &&
											(wcscmp(FindFileData.cFileName, L"..") != 0))
				{
					bool bRet = RecursiveDeleteFolder(cFullPath);
					bRetVal = (!bRetVal ? false : bRet);
				}
			}
			else
			{
				bool bRet = DeleteFile(cFullPath)? true : false;
				bRetVal = (!bRetVal ? false : bRet);
			}
		}while(FindNextFile(hFindFile, &FindFileData));
		FindClose(hFindFile);

		// now remove this directory
		bool bRet = RemoveDirectory(strValue)? true : false;
		bRetVal = (!bRetVal ? false : bRet);
	}
	else
	{
		if(_waccess(strValue, 0) == 0)	//must be a hidden folder, FindFirstFile is not able to locate it!
		{
			bRetVal = false;
		}
	}

	delete [] cSearchPath;
	delete [] cFullPath;
	cSearchPath = NULL;
	cFullPath = NULL;
	return bRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::QuarantineFolder
In Parameters  : LPMAX_PIPE_DATA pMaxPipeData,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::QuarantineFolder(LPMAX_PIPE_DATA pMaxPipeData)
{
	bool bRet = false;
	if(m_bRestartQuarantine || _waccess_s(pMaxPipeData->strValue, 0)== 0)
	{
		AddFiletoRemoveDB(pMaxPipeData);
		if(pMaxPipeData->eMessageInfo%2 == 0)
		{
			DWORD dwAttrs = GetFileAttributes(pMaxPipeData->strValue);
			if(dwAttrs != INVALID_FILE_ATTRIBUTES &&  dwAttrs & FILE_ATTRIBUTE_READONLY)
			{
				SetFileAttributes(pMaxPipeData->strValue,dwAttrs ^ FILE_ATTRIBUTE_READONLY);
			}
			if(RemoveDirectory(pMaxPipeData->strValue))
			{
				bRet = true;
			}
			else
			{
				if(!m_bRestartQuarantine)
				{
					AddInRestartDeleteList(RD_FOLDER, pMaxPipeData->ulSpyNameID,
											pMaxPipeData->strValue);
				}
			}
		}
	}
	else
	{
		bRet = true;
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::QuarantineFile
In Parameters  : LPMAX_PIPE_DATA pMaxPipeData,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::QuarantineFile(LPMAX_PIPE_DATA pMaxPipeData)
{
	bool bRet = false;
	if(m_objSysFiles.CheckSystemFile((SD_Message_Info)pMaxPipeData->eMessageInfo, pMaxPipeData->strValue, pMaxPipeData->strFreshFile, _countof(pMaxPipeData->strFreshFile)))
	{
		AddLogEntry(_T("##### Skipped Quarantine SysFile: %s"), pMaxPipeData->strValue);
		return true;
	}

	if(m_bRestartQuarantine || _waccess_s(pMaxPipeData->strValue, 0)== 0)
	{
		bool bBackupFile = false;
		
		//Pavan : 10-Aug-2013--Added handling not to take Cookie's Backup
		if(pMaxPipeData->eMessageInfo == Recursive_Quarantine || pMaxPipeData->eMessageInfo == Cookie_New)
		{
			bBackupFile = true;
		}
		else
		{
			bBackupFile = BackupFile(pMaxPipeData);
			
			if(bBackupFile)
			{
				AddFiletoRemoveDB(pMaxPipeData);	
			}

		}
		if(bBackupFile)
		{
			if(pMaxPipeData->eMessageInfo%2 == 0)		// Virus file uses the _Report mechanism to backup the file and will handle the repair itself!
			{
				CString csFileName(pMaxPipeData->strValue);
				if(m_bRestartQuarantine)
				{
					csFileName += L".sd";
				}
				DWORD dwAttrs = GetFileAttributes(csFileName);
				if(dwAttrs != INVALID_FILE_ATTRIBUTES &&  dwAttrs & FILE_ATTRIBUTE_READONLY)
				{
					SetFileAttributes(csFileName,dwAttrs ^ FILE_ATTRIBUTE_READONLY);
				}

				if(pMaxPipeData->eMessageInfo == Rootkit_File)
				{
					DelFileUsingDriver(csFileName);
				}
				else
				{
					if(DeleteFile(csFileName))
					{
						bRet = true;
					}
					else
					{
						if(!m_bRestartQuarantine)
						{
							AddInRestartDeleteList(RD_FILE_DELETE, pMaxPipeData->ulSpyNameID,
								pMaxPipeData->strValue);
						}
					}
				}
			}
			else
				bRet = true;
		}
		else
		{
			if(!m_bRestartQuarantine)
			{
				AddInRestartDeleteList(RD_FILE_BACKUP, pMaxPipeData->ulSpyNameID,
										pMaxPipeData->strValue);
			}
		}
	}
	else
	{
		if(pMaxPipeData->eMessageInfo == Rootkit_File)
		{
			DelFileUsingDriver(pMaxPipeData->strValue);
		}
		bRet = true;
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::BackupFile
In Parameters  : LPMAX_PIPE_DATA pMaxPipeData,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::BackupFile(LPMAX_PIPE_DATA pMaxPipeData)
{
	bool bRet = false;
	DWORD dwAttrs = 0;
	CString csFileName(pMaxPipeData->strValue);
	bool bSkipBackup = false;
	if(m_bRestartQuarantine)
	{
		csFileName += L".sd";
	}
	else
	{
		if(csFileName.GetLength() > 3)		// as of now we are not taking a backup of file containing a ':' in them
		{
			CString csTemp = csFileName.Mid(2);
			if(csTemp.Find(L':') != -1)
			{
				AddLogEntry(L">>>>> SKIP-BACKUP: %s", csFileName);
				bSkipBackup = true;
			}
		}
	}

	AddLogEntry(L">>>>> BACKUPFILE : %s", csFileName, 0, true, LOG_DEBUG);
	dwAttrs = GetFileAttributes(csFileName);
	if(dwAttrs != INVALID_FILE_ATTRIBUTES &&  dwAttrs & FILE_ATTRIBUTE_READONLY)
	{
		SetFileAttributes(csFileName, dwAttrs ^ FILE_ATTRIBUTE_READONLY);
	}
	if((!m_bAutomationLab) && (!bSkipBackup))
	{
		GetBackupFileName(pMaxPipeData->strBackup);
		bRet = CBackupOperations::CopyNZipNCrypt(csFileName, pMaxPipeData->strBackup, File, true);
	}
	else
	{
		bRet = true;
	}
	if(!bRet)
	{
		DeleteFile(pMaxPipeData->strBackup);
	}
	else
	{
		if(!m_bRestartQuarantine)
		{
			csFileName.MakeLower();
			if((csFileName.Right(4)== L".exe") || (csFileName.Right(4)== L".tmp") ||
			   (csFileName.Right(4)== L".pif") || (csFileName.Right(4)== L".com") ||
			   (csFileName.Right(4)== L".scr"))
			{
				if(SafeToTerminiate(csFileName))
				{
					if(HandleProcesses(csFileName))
					{
						Sleep(500);
					}
				}
			}
		}
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::AddFiletoRemoveDB
In Parameters  : LPMAX_PIPE_DATA pMaxPipeData,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::AddFiletoRemoveDB(LPMAX_PIPE_DATA pMaxPipeData)
{
	if(m_bAutomationLab)
	{
		return true;
	}

	if(_waccess_s(pMaxPipeData->strBackup, 0) != 0)	// no file to add in recover list!
	{
		return true;
	}

	bool bRet = true;
	time_t ltime=0;
	time(&ltime);

	SYS_OBJ_FIXEDSIZE oSysObjFixedSize = {0};
	oSysObjFixedSize.u64DateTime = ltime;
	oSysObjFixedSize.dwType = pMaxPipeData->eMessageInfo;
	oSysObjFixedSize.dwSpywareID = pMaxPipeData->ulSpyNameID;
	_tcscpy_s(oSysObjFixedSize.szKey, pMaxPipeData->strValue);
	_tcscpy_s(oSysObjFixedSize.szBackupFileName, pMaxPipeData->strBackup);
	
	if(pMaxPipeData->eMessageInfo == Cookie_New)
	{
		_tcscpy_s(oSysObjFixedSize.szValue, pMaxPipeData->strFreshFile);
	}

	if(!m_pMaxDSrvWrapper)
	{
		m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
		if(m_pMaxDSrvWrapper)
		{
			m_pMaxDSrvWrapper->InitializeVirusScanner();
		}
	}
	if(m_pMaxDSrvWrapper)
	{
		bRet = m_pMaxDSrvWrapper->AddToRemoveDB(&oSysObjFixedSize);
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::CreateWormstoDeleteINI
In Parameters  : CString strINIPath,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CThreatManager::CreateWormstoDeleteINI(CString strINIPath)
{
	if(_waccess_s(strINIPath, 0) != 0)
	{
		// UTF16-LE BOM(FFFE)
		WORD wBOM = 0xFEFF;
		DWORD NumberOfBytesWritten;
		HANDLE hFile = ::CreateFile(strINIPath, GENERIC_WRITE, 0, NULL, CREATE_NEW,
									FILE_ATTRIBUTE_NORMAL, NULL);
		::WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, NULL);
		::CloseHandle(hFile);
		WritePrivateProfileStringW(L"File_Delete", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Backup", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"Folder", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryData", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryValue", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryKey", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Rename", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Replace", L"WormCnt", L"0", strINIPath);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::AddInRestartDeleteList
In Parameters  : RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID, LPCTSTR szValue,
Out Parameters : BOOL
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
BOOL CThreatManager::AddInRestartDeleteList(RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID,
											LPCTSTR szValue)
{
	BOOL bRet = false;

	//Invalid.Registry entries are Registry Scan entries....Restart not required for them.
	if(ulSpyNameID == 2890764)
		return bRet;

	CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
	WCHAR strCount[50] = {0};
	WCHAR strValue[MAX_PATH*4] = {0};

	WCHAR *szSection[9] = {
							L"File_Delete", L"File_Backup",
							L"Folder", L"RegistryKey",
							L"RegistryValue", L"RegistryData",
							L"File_Rename", L"File_Replace",
							L"Native_Backup"
						};

	LPTSTR lpszSection = NULL;

	if(eRD_Type == RD_FILE_DELETE)
	{
		lpszSection = szSection[0];
	}
	else if(eRD_Type == RD_FILE_BACKUP)
	{
		lpszSection = szSection[1];
	}
	else if(eRD_Type == RD_FOLDER)
	{
		lpszSection = szSection[2];
	}
	else if(eRD_Type == RD_KEY)
	{
		lpszSection = szSection[3];
	}
	else if(eRD_Type == RD_VALUE)
	{
		lpszSection = szSection[4];
	}
	else if(eRD_Type == RD_DATA)
	{
		lpszSection = szSection[5];
	}
	else if(eRD_Type == RD_FILE_RENAME)
	{
		lpszSection = szSection[6];
	}
	else if(eRD_Type == RD_FILE_REPLACE)
	{
		lpszSection = szSection[7];
	}
	else if(eRD_Type == RD_NATIVE_BACKUP)
	{
		lpszSection = szSection[8];
	}

	if(lpszSection == NULL)
	{
		return FALSE;
	}

	CreateWormstoDeleteINI(strINIPath);

	UINT ulWormCnt = GetPrivateProfileIntW(lpszSection, L"WormCnt", 0, strINIPath);
	wsprintf(strCount, L"%d", ++ulWormCnt);
	WritePrivateProfileStringW(lpszSection, L"WormCnt", strCount, strINIPath);

	wsprintf(strValue, L"%ld^%s", ulSpyNameID, szValue);
	WritePrivateProfileStringW(lpszSection, strCount, strValue, strINIPath);
	AddLogEntry(L"^^^^^: %s", szValue);

	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::PerformRecoverAction
In Parameters  : LPMAX_PIPE_DATA lpPipeData, bool bUpdateDB,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::PerformRecoverAction(LPMAX_PIPE_DATA lpPipeData, bool bUpdateDB)
{
	if(bUpdateDB)
	{
		return true;
	}
	if(!lpPipeData)
	{
		return false;
	}

	bool bRet = false;
	MAX_PIPE_DATA_REG sMaxPipeDataReg = {0};
	
	if(Quarantine_DB_Entry == lpPipeData->eMessageInfo || Quarantine_MailDB_Entry == lpPipeData->eMessageInfo)
	{		
		if(!m_pMaxDSrvWrapper)
		{
			m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
			if(m_pMaxDSrvWrapper)
			{
				m_pMaxDSrvWrapper->InitializeVirusScanner();
			}
		}
		if(m_pMaxDSrvWrapper)
		{
			if(Quarantine_DB_Entry == lpPipeData->eMessageInfo)
			{
				m_pMaxDSrvWrapper->GetRemoveDBData(lpPipeData->ulSpyNameID, &sMaxPipeDataReg);
			}
			else
			{
				m_pMaxDSrvWrapper->GetMailRemoveDBData(lpPipeData->ulSpyNameID, &sMaxPipeDataReg);
			}
		}
	}
	else
	{
		//Darshan: Changes for managing SDEE Quarantine & Recover feature!
		memcpy(&sMaxPipeDataReg, lpPipeData, SIZE_OF_MAX_PIPE_DATA_REG);
		//_tcscpy_s(m_szBackupFileName, (LPCTSTR)lpPipeData->strBackup);
	}

	switch(sMaxPipeDataReg.eMessageInfo)
	{
	case /*Cookie*/ Cookie_New:
	case File:
	case MD5:
	case ExecPath:
	case GenPEScan:
	case KeyLogger_File:
	case Special_File:
	case Virus_File:
	case Virus_File_Repair:
	case Pattern_File:
		{			
			bRet = RecoverFiles(sMaxPipeDataReg);
			if(bRet)
			{
				AddLogEntry(L"##### : %s", sMaxPipeDataReg.strKey);
			}
			else
			{
				AddLogEntry(L"----- : %s", sMaxPipeDataReg.strKey);
			}
			break;
		}
		break;
#pragma warning(disable: 4482)
	case SD_Message_Info::Folder:
#pragma warning(default: 4482)
	case KeyLogger_Folder:
	case Special_Folder:
		{
			if(sMaxPipeDataReg.strBackup[0] != 0)
			{
				bRet = RecoverFiles(sMaxPipeDataReg);
				if(bRet)
				{
					DeleteFile(sMaxPipeDataReg.strBackup);
				}
			}
			else
			{
				bRet = CZipArchive::ForceDirectory(sMaxPipeDataReg.strKey);
			}
			if(bRet)
			{
				AddLogEntry(L"##### : %s", sMaxPipeDataReg.strKey);
			}
			else
			{
				AddLogEntry(L"----- : %s", sMaxPipeDataReg.strKey);
			}
			break;
		}
	case RegKey:
	case BHO:
	case MenuExt_Key:
	case ActiveX:
	case Service:
	case Notify:
	case Special_RegKey:
	case Rootkit_RegKey:
	case Virus_RegKey:
		{
			if(sMaxPipeDataReg.eMessageInfo == Rootkit_RegKey)
			{
				m_bRootkitFound = true;
			}
			if(sMaxPipeDataReg.strBackup[0] != 0)
			{
				CString csKey(sMaxPipeDataReg.strKey), csBackupFile(sMaxPipeDataReg.strBackup);
				if(csBackupFile.Right(3)== L".sd")// only.sd extension backup file are encrypted and zipped
				{
					bRet = CBackupOperations::CopyAndEncryptFile(sMaxPipeDataReg.strBackup, sMaxPipeDataReg.strBackup);
				}
				else
				{
					bRet = true;
				}
				if(bRet)
				{
					CRegistry oRegistry;
					oRegistry.SetWow64Key(Is64BitKey(csKey));
					bRet = oRegistry.RestoreRegKeyPath(sMaxPipeDataReg.Hive_Type, csKey, csBackupFile);
					if(bRet)
					{
						DeleteFile(sMaxPipeDataReg.strBackup);
					}
				}
			}
			else
			{
				CRegistry oRegistry;
				HKEY hKey = NULL;
				oRegistry.SetWow64Key(Is64BitKey(sMaxPipeDataReg.strKey));
				if(oRegistry.CreateKey(sMaxPipeDataReg.strKey, hKey, sMaxPipeDataReg.Hive_Type))
				{
					if(sMaxPipeDataReg.iSizeOfData > 0)
					{
						RegSetValueEx(hKey, sMaxPipeDataReg.strValue, 0, REG_SZ,
										sMaxPipeDataReg.bData, sMaxPipeDataReg.iSizeOfData);
					}
					bRet = oRegistry.CloseKey(hKey);
				}
			}
			if(bRet)
			{
				AddLogEntry(L"##### : %s", sMaxPipeDataReg.strKey);
			}
			else
			{
				AddLogEntry(L"----- : %s", sMaxPipeDataReg.strKey);
			}
			break;
		}
	case SharedDlls:
	case SharedTask:
	case RegValue:
	case Toolbar:
	case Run1:
	case SSODL:
	case MenuExt_Value:
	case Special_RegVal:
	case ShellExecuteHooks:
	case Rootkit_RegVal:
	case Virus_RegVal:
	case RegFix:
	case Special_RegFix:
	case AppInit:
		{
			if(sMaxPipeDataReg.eMessageInfo == Rootkit_RegVal)
			{
				m_bRootkitFound = true;
			}
			CRegistry oRegistry;
			oRegistry.SetWow64Key(Is64BitKey(sMaxPipeDataReg.strKey));
			bRet = oRegistry.Set(sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue,
								sMaxPipeDataReg.bData, sMaxPipeDataReg.iSizeOfData,
								sMaxPipeDataReg.Type_Of_Data, sMaxPipeDataReg.Hive_Type);
			if(bRet)
			{
				AddLogEntry(L"##### : %s - %s", sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
			}
			else
			{
				AddLogEntry(L"----- : %s - %s", sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
			}
			break;
		}
	}

	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::RecoverFiles
In Parameters  : MAX_PIPE_DATA_REG &sMaxPipeDataReg,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::RecoverFiles(MAX_PIPE_DATA_REG &sMaxPipeDataReg)
{
	bool bRet = false;
	if(_waccess_s(sMaxPipeDataReg.strBackup, 0)== 0)
	{
		if(CBackupOperations::CopyAndEncryptFile(sMaxPipeDataReg.strBackup, sMaxPipeDataReg.strBackup))
		{
			CString csRootDir(sMaxPipeDataReg.strKey[0]);	
#ifdef _SDSCANNER
			if(csRootDir == L"\\")
			{
				ConfigForNetworkScan(sMaxPipeDataReg.strKey);
				CString csTempNetpath(sMaxPipeDataReg.strKey);
				csTempNetpath = csTempNetpath.Mid(0,csTempNetpath.ReverseFind(L'\\'));
				csRootDir = csTempNetpath;
				//csRootDir = L"\\\\";
			}
			else
			{
				csRootDir += L":";
			}
#else
			csRootDir += L":";
#endif
			if(_waccess_s(sMaxPipeDataReg.strKey, 0) == 0)	//Delete existing to handle recovering repaired file!
			{
				DeleteFile(sMaxPipeDataReg.strKey);
			}
			CString csFileToRecover(sMaxPipeDataReg.strKey);
			if(m_bIsFromFWUI)
			{
				WCHAR *ExtPtr = NULL;
				ExtPtr = wcsrchr(sMaxPipeDataReg.strKey, '\\');
				if(ExtPtr != NULL)
				{
					ExtPtr++;
					csFileToRecover = ExtPtr;
					*ExtPtr = '\0';
					bRet = CBackupOperations::ExtractFile(sMaxPipeDataReg.strBackup, m_csDesktopPath + L"\\RecoveredEmails", true, csFileToRecover);
				}
				else	//some thing is wrong!
				{
					bRet = false;
				}
			}
			else
			{
				bRet = CBackupOperations::ExtractFile(sMaxPipeDataReg.strBackup, csRootDir, true);
			}
		}
	}
	if(bRet)
	{
		DeleteFile(sMaxPipeDataReg.strBackup);
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CheckForDiskSpace
In Parameters  : bool bBoth, CString csFilePath, 
Out Parameters : bool 
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CThreatManager::CheckForDiskSpace(bool bBoth, DWORD & dwDelFileSize, CString csFilePath)
{
	ULONG dwFileSize = 0;
	dwFileSize = sizeof(SYS_OBJ);
	if(bBoth)
	{
		HANDLE hFile = CreateFile(csFilePath,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if(INVALID_HANDLE_VALUE != hFile)
		{
			dwDelFileSize = GetFileSize(hFile,NULL);
			dwFileSize += dwDelFileSize;

			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}
	}

	dwFileSize = dwFileSize/(1024*1024);
	dwDelFileSize = dwDelFileSize/(1024*1024);
	if(!m_lFreeDiskSpace || m_lFreeDiskSpace < dwFileSize)
	{
		if(m_lpSendMessaegToUI)
		{
			m_lpSendMessaegToUI(DiskFullMessage, eStatus_NotApplicable, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
		}
		else
		{
			AddLogEntry(L"Disk space full, message can not be sent because null message pointer");
		}
		return false;
	}
	m_lFreeDiskSpace -= dwFileSize;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::PerformRegAction
In Parameters  : LPMAX_PIPE_DATA_REG pMaxPipeDataReg,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::PerformRegAction(LPMAX_PIPE_DATA_REG pMaxPipeDataReg)
{
	if(!pMaxPipeDataReg)
	{
		return false;
	}
	DWORD dwDelFileSize = 0;
	if( CheckForDiskSpace(false, dwDelFileSize)  == false)
	{
		return false;
	}

	bool bRet = false;
	switch(pMaxPipeDataReg->eMessageInfo)
	{
	case Network:
	case Network_Report:
		{
			if(pMaxPipeDataReg->eMessageInfo%2 == 0)
			{
				bRet = HandleProcesses(pMaxPipeDataReg->strKey);
				if(bRet)
				{
					AddLogEntry(L"##### : %s", pMaxPipeDataReg->strKey);
				}
				else
				{
					AddLogEntry(L"----- : %s", pMaxPipeDataReg->strKey);
				}
			}
			else
			{
				bRet = true;
			}
			break;
		}
	case BHO:
	case BHO_Report:
	case ActiveX:
	case ActiveX_Report:
	case MenuExt_Key:
	case MenuExt_Key_Report:
	case RegKey:
	case RegKey_Report:
	case Service:
	case Service_Report:
	case Notify:
	case Notify_Report:
	case Virus_RegKey:
	case Virus_RegKey_Report:
	case Special_RegKey:
	case Special_RegKey_Report:
		{
			bRet = DeleteRegKey(pMaxPipeDataReg);
			if(bRet)
			{
				AddLogEntry(L"##### : %s", pMaxPipeDataReg->strKey);
			}
			else
			{
				AddLogEntry(L"----- : %s", pMaxPipeDataReg->strKey);
			}
			break;
		}
	case MenuExt_Value:
	case MenuExt_Value_Report:
	case SSODL:
	case SSODL_Report:
	case Run1:
	case Run1_Report:
	case Toolbar:
	case Toolbar_Report:
	case SharedTask:
	case SharedTask_Report:
	case SharedDlls:
	case SharedDlls_Report:
	case ShellExecuteHooks:
	case ShellExecuteHooks_Report:
	case RegValue:
	case RegValue_Report:
	case Virus_RegVal:
	case Virus_RegVal_Report:
	case Special_RegVal:
	case Special_RegVal_Report:
		{
			//size of structure
			bRet = DeleteRegValue(pMaxPipeDataReg);
			if(bRet)
			{
				AddLogEntry(L"##### : %s - %s", pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue);
			}
			else
			{
				AddLogEntry(L"----- : %s - %s", pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue);
			}
			break;
		}
	case RegData:
	case RegData_Report:
	case RegFix:
	case RegFix_Report:
	case Special_RegFix:
	case Special_RegFix_Report:
		{
			TCHAR szEntry[4096] = {0};
			bRet = FixRegData (pMaxPipeDataReg); // Fix registry data
			swprintf_s(szEntry, 4096, L"%s - %s - %s : %s", pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue, (LPCTSTR)pMaxPipeDataReg->bData, (LPCTSTR)pMaxPipeDataReg->bReplaceData);
			if(bRet)
			{
				//AddLogEntry(L"##### : %s - %s - %s : %s", pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue, (LPCTSTR)pMaxPipeDataReg->bData, (LPCTSTR)pMaxPipeDataReg->bReplaceData);
				AddLogEntry(L"##### : %s", szEntry);
			}
			else
			{
				//AddLogEntry(L"----- : %s - %s - %s : %s", pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue, (LPCTSTR)pMaxPipeDataReg->bData, (LPCTSTR)pMaxPipeDataReg->bReplaceData);
				AddLogEntry(L"----- : %s", szEntry);
			}
			break;
		}
	case AppInit:
	case AppInit_Report:
		{
			bRet = FixAppInitData(pMaxPipeDataReg); // Fix registry data
			if(bRet)
			{
				AddLogEntry(L"##### : %s - %s", pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue);
			}
			else
			{
				AddLogEntry(L"----- : %s - %s", pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue);
			}
			break;
		}
	case Rootkit_RegKey:
	case Rootkit_RegKey_Report:
	case Rootkit_RegVal:
	case Rootkit_RegVal_Report:
	case Module:
	case Module_Report:
		{
			bRet = false;
			break;
		}
	}
	if(!bRet)
	{
		m_bRestartRequired = true;
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::AddRegistrytoRemoveDB
In Parameters  : LPMAX_PIPE_DATA_REG pMaxPipeDataReg,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::AddRegistrytoRemoveDB(LPMAX_PIPE_DATA_REG pMaxPipeDataReg)
{
	if(m_bAutomationLab)
	{
		return true;
	}

	bool bRet = true;
	time_t ltime=0;
	time(&ltime);

	SYS_OBJ_FIXEDSIZE oSysObjFixedSize = {0};
	oSysObjFixedSize.dwType = pMaxPipeDataReg->eMessageInfo;
	oSysObjFixedSize.dwSpywareID = pMaxPipeDataReg->ulSpyNameID;
	_tcscpy_s(oSysObjFixedSize.szKey, pMaxPipeDataReg->strKey);
	_tcscpy_s(oSysObjFixedSize.szBackupFileName, pMaxPipeDataReg->strBackup);
	oSysObjFixedSize.u64DateTime = ltime;
	oSysObjFixedSize.ulptrHive = reinterpret_cast<ULONG_PTR>(pMaxPipeDataReg->Hive_Type);
	_tcscpy_s(oSysObjFixedSize.szValue, pMaxPipeDataReg->strValue);
	memcpy(oSysObjFixedSize.byData, pMaxPipeDataReg->bData, pMaxPipeDataReg->iSizeOfData);
	oSysObjFixedSize.dwRegDataSize = pMaxPipeDataReg->iSizeOfData;
	memcpy(oSysObjFixedSize.byReplaceData, pMaxPipeDataReg->bReplaceData, pMaxPipeDataReg->iSizeOfReplaceData);
	oSysObjFixedSize.dwReplaceRegDataSize = pMaxPipeDataReg->iSizeOfReplaceData;
	oSysObjFixedSize.wRegDataType = pMaxPipeDataReg->Type_Of_Data;
	if(!m_pMaxDSrvWrapper)
	{
		m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
		if(m_pMaxDSrvWrapper)
		{
			m_pMaxDSrvWrapper->InitializeVirusScanner();
		}
	}
	if(m_pMaxDSrvWrapper)
	{
		bRet = m_pMaxDSrvWrapper->AddToRemoveDB(&oSysObjFixedSize);
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::DeleteRegKey
In Parameters  : LPMAX_PIPE_DATA_REG pMaxPipeDataReg,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::DeleteRegKey(LPMAX_PIPE_DATA_REG pMaxPipeDataReg)
{
	HKEY hKey = NULL;
	CRegistry oRegistry;
	DWORD dwAccess = KEY_READ;
	bool bMaxMgrHandlingRequired = false;
	if(m_bIs64Bit)
	{
		if(Is64BitKey(pMaxPipeDataReg->strKey))
		{
			dwAccess |= KEY_WOW64_64KEY;
			oRegistry.SetWow64Key(true);
		}
	}
	//Sandip changes:Open key with only KEY_READ accesss.So that we will able to set permissions.
	if(m_bRestartQuarantine || oRegistry.Open(pMaxPipeDataReg->strKey, hKey,
												pMaxPipeDataReg->Hive_Type,dwAccess))
	{
		bool bAddedToRemoveDB = false;
		if(pMaxPipeDataReg->eMessageInfo%2 == 0)
		{
			DWORD dwSubKeyCount = 0;
			DWORD dwValueCount = 0;
			DWORD dwValueLen = 0;
			DWORD dwDataLen = 0;
			if(RegQueryInfoKey(hKey, 0, 0, 0, &dwSubKeyCount, 0, 0, &dwValueCount,
								&dwValueLen, &dwDataLen, 0, 0)== ERROR_SUCCESS)
			{
				if((dwSubKeyCount == 0) && (dwValueCount == 0))// if key is not empty we dont delete it!
				{
					// (Default)value in registry needs special handling
					if((dwValueCount == 1) && (dwValueLen == 0) && (dwDataLen != 0))
					{
						oRegistry.CloseKey(hKey);
						pMaxPipeDataReg->iSizeOfData = dwDataLen;
						oRegistry.Get(pMaxPipeDataReg->strKey, L"", REG_SZ,
										pMaxPipeDataReg->bData, dwDataLen,
										pMaxPipeDataReg->Hive_Type);
					}
					if((dwValueCount == 0) || ((dwValueCount == 1) 
						&& (dwValueLen == 0) && (dwDataLen != 0)))
					{
						bAddedToRemoveDB = AddRegistrytoRemoveDB(pMaxPipeDataReg);
						if(oRegistry.DeleteRegKey(pMaxPipeDataReg->Hive_Type, pMaxPipeDataReg->strKey))
						{
							return true;
						}
					}
				}
				else
				{
					//if(dwSubKeyCount == 0)	//If SubKey is there then Skip it.
					//{
					//	CStringArray objArrValues;
					//	oRegistry.EnumValues(pMaxPipeDataReg->strKey, objArrValues, pMaxPipeDataReg->Hive_Type);
					//	int iTotalValues = (int)objArrValues.GetCount();
					//	for(int iCount=0 ; iCount<iTotalValues ; iCount++)
					//	{
					//		CString csValue = objArrValues.GetAt(iCount);
					//		DWORD dwType;
					//		oRegistry.GetValueType(pMaxPipeDataReg->strKey, csValue, dwType, pMaxPipeDataReg->Hive_Type);

					//		if(dwType != REG_BINARY)	//If any Values type is non REG_BINARY then skip it
					//		{
					//			oRegistry.CloseKey(hKey);
					//			return false;
					//		}
					//	}

					//	for(int iCount=0 ; iCount<iTotalValues ; iCount++)
					//	{
					//		CString csValue = objArrValues.GetAt(iCount);

					//		MAX_PIPE_DATA_REG oMaxPipeDataReg = {0};
					//		memcpy_s(&oMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG), pMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));

					//		oMaxPipeDataReg.eMessageInfo = RegValue;
					//		oMaxPipeDataReg.Type_Of_Data = REG_BINARY;
					//		_tcscpy_s(oMaxPipeDataReg.strValue, MAX_PATH, csValue);
					//		oRegistry.Get(oMaxPipeDataReg.strKey, oMaxPipeDataReg.strValue, oMaxPipeDataReg.Type_Of_Data,
					//			oMaxPipeDataReg.bData, _countof(oMaxPipeDataReg.bData), oMaxPipeDataReg.Hive_Type);
					//		oMaxPipeDataReg.iSizeOfData = _countof(oMaxPipeDataReg.bData);

					//		AddRegistrytoRemoveDB(&oMaxPipeDataReg);
					//	}
					//}
					//else
					//	return false;

					bMaxMgrHandlingRequired = true;
				}
			}
			if(!m_bRestartQuarantine)
			{
				CString csRegKey;
				csRegKey.Format (_T("%s\\%s"), 
					(pMaxPipeDataReg->Hive_Type == HKEY_LOCAL_MACHINE ? 
					L"HKEY_LOCAL_MACHINE" : L"HKEY_USERS"), pMaxPipeDataReg->strKey);
				AddInRestartDeleteList(RD_KEY, pMaxPipeDataReg->ulSpyNameID, csRegKey);
			}
		}
		if(!bAddedToRemoveDB)
		{
			AddRegistrytoRemoveDB(pMaxPipeDataReg);
		}
		oRegistry.CloseKey(hKey);
		if(bMaxMgrHandlingRequired)
			return true;
		else
			return false;
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::DeleteRegValue
In Parameters  : LPMAX_PIPE_DATA_REG pMaxPipeDataReg,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::DeleteRegValue(LPMAX_PIPE_DATA_REG pMaxPipeDataReg)
{
	CRegistry objReg;
	objReg.SetWow64Key(Is64BitKey(pMaxPipeDataReg->strKey));
	if(objReg.ValueExists(pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue,
							pMaxPipeDataReg->Hive_Type))
	{
		AddRegistrytoRemoveDB(pMaxPipeDataReg);
		if(pMaxPipeDataReg->eMessageInfo%2 == 0)
		{
			if(objReg.DeleteValue(pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue,
									pMaxPipeDataReg->Hive_Type))
			{
				return true;
			}
		}
		if(!m_bRestartQuarantine)
		{
			CString csRegKey;
			csRegKey.Format (_T("%s\\%s\t#@#%s"),
							(pMaxPipeDataReg->Hive_Type == HKEY_LOCAL_MACHINE ?
							L"HKEY_LOCAL_MACHINE" : L"HKEY_USERS"),
							pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue);
			AddInRestartDeleteList(RD_VALUE, pMaxPipeDataReg->ulSpyNameID, csRegKey);
		}
		return false;
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::FixRegData
In Parameters  : LPMAX_PIPE_DATA_REG pMaxPipeDataReg,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::FixRegData(LPMAX_PIPE_DATA_REG pMaxPipeDataReg)
{
	CRegistry objRegistry;
	objRegistry.SetWow64Key(Is64BitKey(pMaxPipeDataReg->strKey));
	if(objRegistry.ValueExists(pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue,
								pMaxPipeDataReg->Hive_Type))
	{
		AddRegistrytoRemoveDB(pMaxPipeDataReg);
		if(pMaxPipeDataReg->sReg_Fix_Options.FIX_ACTION == FIX_ACTION_RESTORE 
							&& pMaxPipeDataReg->iSizeOfReplaceData)
		{
			if(objRegistry.Set(pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue,
								pMaxPipeDataReg->bReplaceData, pMaxPipeDataReg->iSizeOfReplaceData,
								pMaxPipeDataReg->Type_Of_Data, pMaxPipeDataReg->Hive_Type))
			{
				return true;
			}
		}
		else if(pMaxPipeDataReg->sReg_Fix_Options.FIX_ACTION == FIX_ACTION_REMOVE_DATA)
		{
			if(objRegistry.Set(pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue, 0, 0,
								pMaxPipeDataReg->Type_Of_Data, pMaxPipeDataReg->Hive_Type))
			{
				return true;
			}
		}
		return false;
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::FixAppInitData
In Parameters  : LPMAX_PIPE_DATA_REG pMaxPipeDataReg,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CThreatManager::FixAppInitData(LPMAX_PIPE_DATA_REG pMaxPipeDataReg)
{
	CRegistry objRegistry;
	objRegistry.SetWow64Key(Is64BitKey(pMaxPipeDataReg->strKey));
	if(objRegistry.ValueExists(pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue,
								pMaxPipeDataReg->Hive_Type))
	{
		AddRegistrytoRemoveDB(pMaxPipeDataReg);
		CString csNewValue((LPCTSTR)pMaxPipeDataReg->bData);
		CString csReplaceData((LPCTSTR)pMaxPipeDataReg->bReplaceData);
		objRegistry.Get(pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue, csNewValue,
						pMaxPipeDataReg->Hive_Type);
		csNewValue = oDBPathExpander.ExpandSystemPath(csNewValue);
		csNewValue.MakeLower();
		csReplaceData = oDBPathExpander.ExpandSystemPath(csReplaceData);
		csReplaceData.MakeLower();
		csNewValue.Replace(csReplaceData ,L"");
		if(objRegistry.Set(pMaxPipeDataReg->strKey, pMaxPipeDataReg->strValue,
							(LPBYTE)(LPCTSTR)csNewValue,
							(csNewValue.GetLength()*sizeof(TCHAR)) + sizeof(TCHAR),
							pMaxPipeDataReg->Type_Of_Data, pMaxPipeDataReg->Hive_Type))
		{
			return true;
		}
		return false;
	}
	return true;
}

bool CThreatManager::Is64BitKey(CString strValue)
{
	if(m_bIs64Bit)
	{
		if(StrStrI(strValue,L"Wow6432Node") == NULL)
		{
			return true;
		}
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : CheckForRescanZipFilesCount
In Parameters  : void
Out Parameters : bool
Description    : check and make sure there are less than 4 files
Author & Date  : Anand Srivastava & 29 Nov, 2010.
--------------------------------------------------------------------------------------*/
void CThreatManager::CheckForRescanZipFilesCount()
{
	CFileFind objFinder;
	BOOL bMoreFiles = FALSE;
	int iCnt = 0;
	CString csSearchPath;

	csSearchPath = CSystemInfo::m_strAppPath + THREAT_COMMUNITY_FOLDER + BACK_SLASH + RESCAN_FILES_NOEXT +_T("_*.zip");
	bMoreFiles = objFinder.FindFile(csSearchPath);
	if(!bMoreFiles)
	{
		return;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDots() || objFinder.IsDirectory())
		{
			continue;
		}
		if(iCnt > 3)
		{
			DeleteFile(objFinder.GetFilePath());
		}
		iCnt++;
	}
	objFinder.Close();
}

/*--------------------------------------------------------------------------------------
Function       : AddAllLogFilesToZip
In Parameters  : void
Out Parameters : bool
Description    : add all logs to collected data
Author & Date  : Anand Srivastava & 29 Nov, 2010.
--------------------------------------------------------------------------------------*/
void CThreatManager::AddAllLogFilesToZip()
{
	CFileFind objFinder;
	BOOL bMoreFiles = FALSE;
	int iCnt = 0;
	CString csPath;

	csPath = CSystemInfo::m_strAppPath + _T("Log\\*.txt");
	bMoreFiles = objFinder.FindFile(csPath);
	if(!bMoreFiles)
	{
		return;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDots() || objFinder.IsDirectory())
		{
			continue;
		}

		csPath = objFinder.GetFilePath();
		m_objRescanArc.AddNewFile(csPath, -1, false);
	}

	objFinder.Close();
	return;
}

/*--------------------------------------------------------------------------------------
Function       : AddFileToRescannedDB
In Parameters  : void
Out Parameters : bool
Description    : add all logs to collected data
Author & Date  : Anand Srivastava & 29 Nov, 2010.
--------------------------------------------------------------------------------------*/
void CThreatManager::AddFileToRescannedDB(LPCTSTR szFilePath, LPCTSTR szSpyName)
{
	//Threatcommunity removed
	/*if(m_bThreatCommEnable)
	{
		if(m_csRescanFilePath.GetLength() == 0)
		{
			m_csRescanFilePath = CSystemInfo::m_strAppPath;
			CreateDirectory(m_csRescanFilePath, 0);

			m_csRescanFilePath += THREAT_COMMUNITY_FOLDER;
			CreateDirectory(m_csRescanFilePath, 0);

			m_csRescanFilePath += _T("\\Analyze\\");
			CreateDirectory(m_csRescanFilePath, 0);
		}

		if(!IsFileLargerThanSize(szFilePath, 1024 * 1024 * 6))
		{
			TCHAR szFullFilePath[MAX_PATH] = {0};

			if(0 == GetTempFileName(m_csRescanFilePath, _T("an_"), 0, szFullFilePath))
			{
				AddLogEntry(_T("TC rescan file adding error: %s"), szFilePath, NULL, true, LOG_DEBUG);
				return;
			}
			DeleteFile(szFullFilePath);
			CString csTempPath(szFullFilePath);
			csTempPath.MakeLower();
			csTempPath.Replace(_T(".tmp"),_T(".zip"));
			m_objRescanArc.Open(csTempPath, CZipArchive::create);
			m_objRescanArc.SetPassword(_T("a@u$ecD!"));
			m_objRescanArc.AddNewFile(szFilePath, -1, false);
			m_objRescanArc.Close();
			m_bThreatCommDataFound = true;

			AddLogEntry(_T("TC rescan file added: %s"), szFilePath, NULL, true, LOG_DEBUG);
		}
		else
		{
			AddLogEntry(_T("TC rescan file skipped, large size: %s"), szFilePath, NULL, true, LOG_DEBUG);
		}
	}*/

	return;
}

/*--------------------------------------------------------------------------------------
	Function       : IsFileLargerThanSize
	In Parameters  : LPCTSTR szFilePath, DWORD dwMaxSize
	Out Parameters : bool
	Description    : check the file size, return true if larger than the specified size
	Author & Date  : Anand Srivastava & 26/Feb/2011
--------------------------------------------------------------------------------------*/
bool CThreatManager::IsFileLargerThanSize(LPCTSTR szFilePath, DWORD dwMaxSize)
{
	WIN32_FILE_ATTRIBUTE_DATA FileInfo = {0};

	if(!GetFileAttributesEx(szFilePath, GetFileExInfoStandard, &FileInfo))
	{
		return false;
	}

	return MKQWORD(FileInfo.nFileSizeHigh, FileInfo.nFileSizeLow) >= (ULONG64(dwMaxSize));
}

bool CThreatManager::GetRepairFileName(const TCHAR *sOriginalFileName, TCHAR *sDummyFileName)
{
	HANDLE hFile = CreateFile(sOriginalFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		if(!MaxCopyFile(sOriginalFileName, sDummyFileName))
		{
			return false;
		}
		return true;
	}
	CloseHandle(hFile);
	return false;
}

BOOL CThreatManager::MaxTempFileName(TCHAR *szTempFilename)
{
	TCHAR lpPathBuffer[1024] = {0};

	if(CSystemInfo::m_strAppPath.Trim().GetLength() == 0)
	{
		return FALSE;
	}

	wcscpy_s(lpPathBuffer, CSystemInfo::m_strAppPath);
	wcscat_s(lpPathBuffer, L"Quarantine");

	UINT uRetVal = GetTempFileName(lpPathBuffer, L"MAX_", 0, szTempFilename);
	if(uRetVal == 0)
	{
		return FALSE;
	}

	return TRUE;
}

BOOL CThreatManager::MaxCopyFile(LPCTSTR lpFileName, TCHAR *lpNewFileName)
{
	HANDLE		hExistingFile = INVALID_HANDLE_VALUE;
	HANDLE		hNewFile = INVALID_HANDLE_VALUE;
	DWORD		dwBytesRead = 0x01;
	DWORD		dwBytesWritten = 0x00;

	if(!MaxTempFileName(lpNewFileName))
	{
		return FALSE;
	}

	hExistingFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(INVALID_HANDLE_VALUE == hExistingFile)
	{
		return FALSE;
	}

	hNewFile = CreateFile(lpNewFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(INVALID_HANDLE_VALUE == hNewFile)
	{
		if(INVALID_HANDLE_VALUE != hExistingFile)
		{
			CloseHandle(hExistingFile);
		}
		return FALSE;
	}

	unsigned char	szByteBuffer[0x1000] = {0};
	while(dwBytesRead)
	{
		dwBytesRead = 0x00;
		memset(szByteBuffer, 0x00, 0x1000 * sizeof(unsigned char));
		ReadFile(hExistingFile, szByteBuffer, 0x1000, &dwBytesRead, NULL);
		WriteFile(hNewFile, szByteBuffer, dwBytesRead, &dwBytesWritten, NULL);
		if(dwBytesRead < 0x1000)
		{
			dwBytesRead = 0x00;
			break;
		}
	}
	if(INVALID_HANDLE_VALUE != hExistingFile)
	{
		CloseHandle(hExistingFile);
	}

	if(INVALID_HANDLE_VALUE != hNewFile)
	{
		CloseHandle(hNewFile);
	}
	return TRUE;
}

void CThreatManager::MakeRestartReplaceEntry(const TCHAR *sOriginalFileName, TCHAR *sDummyFileName)
{
	CString csMaxFormat;
	csMaxFormat = sDummyFileName;
	csMaxFormat += RENAME_FILE_SEPARATOR;
	csMaxFormat += sOriginalFileName;

	if(_waccess_s(sDummyFileName, 0) == 0)
	{
		AddInRestartDeleteList(RD_FILE_REPLACE, 0, csMaxFormat);
	}
	else
	{
		AddInRestartDeleteList(RD_FILE_DELETE, 0, sOriginalFileName);
	}
}

bool CThreatManager::CheckFileForHiddenFolder(LPCTSTR szFilePath)
{
	TCHAR szFolderPath[MAX_PATH] = {0};
	LPCTSTR pDot = 0;
	DWORD dwAttributes = 0;

	pDot = _tcsrchr(szFilePath, _T('.'));
	if(NULL == pDot)
	{
		return false;
	}

	if(pDot - szFilePath >= _countof(szFolderPath))
	{
		return false;
	}

	_tcsncpy_s(szFolderPath, _countof(szFolderPath), szFilePath, pDot - szFilePath);
	for(int i = (int)_tcslen(szFolderPath) - 1; i > -1; i--)
	{
		if(_T(' ') == szFolderPath[i])
		{
			szFolderPath[i] = 0;
		}
		else
		{
			break;
		}
	}

	dwAttributes = GetFileAttributes(szFolderPath);
	if(INVALID_FILE_ATTRIBUTES == dwAttributes)
	{
		return false;
	}

	if((dwAttributes & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY)
	{
		return false;
	}

	if((dwAttributes & FILE_ATTRIBUTE_SYSTEM) == FILE_ATTRIBUTE_SYSTEM)
	{
		dwAttributes ^= FILE_ATTRIBUTE_SYSTEM;
	}

	if((dwAttributes & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN)
	{
		dwAttributes ^= FILE_ATTRIBUTE_HIDDEN;
	}

	SetFileAttributes(szFolderPath, dwAttributes);
	AddLogEntry(L"System and Hidden attributes removed: %s", szFolderPath);
	return true;
}

bool CThreatManager::QuarantineFile(PMAX_SCANNER_INFO pScanInfo)
{
	#ifdef _SDSCANNER
	if( pScanInfo->szFileToScan[0] == L'\\')
	{
		ConfigForNetworkScan(pScanInfo->szFileToScan);
	}
	#endif
	bool bRet = false;
	if(m_objSysFiles.CheckSystemFile(pScanInfo->eMessageInfo, pScanInfo->szFileToScan, pScanInfo->szFreshFile, _countof(pScanInfo->szFreshFile)))
	{
		AddLogEntry(_T("Skipped Quarantine SysFile: %s"), pScanInfo->szFileToScan);
		return true;
	}

	if(_waccess_s(pScanInfo->szFileToScan, 0)== 0)
	{
		CString csFileName(pScanInfo->szFileToScan);
		csFileName.MakeLower();
		if((csFileName.Right(4)== L".exe") || (csFileName.Right(4)== L".tmp") ||
		   (csFileName.Right(4)== L".pif") || (csFileName.Right(4)== L".com") ||
		   (csFileName.Right(4)== L".scr"))
		{
			if(HandleProcesses(csFileName))
			{
				Sleep(500);
			}
		}
		DWORD dwAttrs = GetFileAttributes(csFileName);
		if(dwAttrs != INVALID_FILE_ATTRIBUTES &&  dwAttrs & FILE_ATTRIBUTE_READONLY)
		{
			SetFileAttributes(csFileName, dwAttrs ^ FILE_ATTRIBUTE_READONLY);
		}
		if(pScanInfo->eMessageInfo == Rootkit_File)
		{
			DelFileUsingDriver(csFileName);
		}
		else if(DeleteFile(csFileName))
		{
			int	iErr = GetLastError();

			if(_waccess_s(csFileName, 0)== 0)
			{
				DelFileUsingDriver(csFileName);
			}
			else
			{
				pScanInfo->ThreatQuarantined = true;
				bRet = true;
				AddLogEntry(L"##### AV-Q-S : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
		}
		else
		{
			if(!m_bRestartQuarantine)
			{
				AddInRestartDeleteList(RD_FILE_DELETE, pScanInfo->ulThreatID, pScanInfo->szFileToScan);
				AddLogEntry(L"----- AV-Q-F : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
		}
	}
	else
	{
		if(pScanInfo->eMessageInfo == Rootkit_File)
		{
			DelFileUsingDriver(pScanInfo->szFileToScan);
		}
		bRet = true;
	}
	return bRet;
}

bool CThreatManager::BackupFile(PMAX_SCANNER_INFO pScanInfo)
{
	SetFileAttributes(pScanInfo->szFileToScan, FILE_ATTRIBUTE_NORMAL);
	if(!m_bAutomationLab)
	{
		DWORD dwDelFileSize = 0;
		if(CheckForDiskSpace(true, dwDelFileSize, pScanInfo->szFileToScan)  == false)
		{
			return false;
		}
		TCHAR strFrom[MAX_PATH] = {0};
		if(pScanInfo->eScannerType == Scanner_Type_Max_Email_Scan)	// recover email files on user's desktop!
		{
			_tcscpy_s(strFrom, pScanInfo->szBackupFileName);
			::SecureZeroMemory(pScanInfo->szBackupFileName,sizeof(pScanInfo->szBackupFileName));
		}

		bool bSkipBackup = false;
		CString csFileName(pScanInfo->szFileToScan);
		if(csFileName.GetLength() > 3)		// as of now we are not taking a backup of file containing a ':' in them
		{
			CString csTemp = csFileName.Mid(2);
			if(csTemp.Find(L':') != -1)
			{
				AddLogEntry(L">>>>> SKIP-BACKUP: %s", csFileName);
				bSkipBackup = true;
			}
		}
		if(!bSkipBackup)
		{
			GetBackupFileName(pScanInfo->szBackupFileName);
			if(!CBackupOperations::CopyNZipNCrypt(pScanInfo->szFileToScan, pScanInfo->szBackupFileName, File, true))
			{
				DeleteFile(pScanInfo->szBackupFileName);
				return false;
			}
		}

		if(pScanInfo->eScannerType == Scanner_Type_Max_Email_Scan)	// recover email files on user's desktop!
		{
			MAX_PIPE_DATA_REG oMaxPipeDataReg = {0};

			oMaxPipeDataReg.eMessageInfo = pScanInfo->eMessageInfo;
			oMaxPipeDataReg.eStatus = eStatus_NotApplicable;
			oMaxPipeDataReg.ulSpyNameID = pScanInfo->ulThreatID;
			_tcscpy_s(oMaxPipeDataReg.strKey, _countof(oMaxPipeDataReg.strKey), pScanInfo->szFileToScan);
			_tcscpy_s(oMaxPipeDataReg.strBackup, _countof(oMaxPipeDataReg.strBackup), pScanInfo->szBackupFileName);
			_tcscpy_s(oMaxPipeDataReg.strValue, _countof(oMaxPipeDataReg.strValue), pScanInfo->szThreatName);
			//_tcscpy_s(oMaxPipeDataReg.szFreshFile, _countof(oMaxPipeDataReg.szFreshFile), pScanInfo->szFreshFile);
			memcpy_s(oMaxPipeDataReg.bReplaceData, MAX_PATH*4, (LPBYTE)strFrom, MAX_PATH);
			memcpy_s(oMaxPipeDataReg.bData, MAX_PATH*4, (LPBYTE)pScanInfo->szFreshFile, MAX_PATH);
			oMaxPipeDataReg.iSizeOfReplaceData = sizeof(oMaxPipeDataReg.bReplaceData);
			oMaxPipeDataReg.iSizeOfData = sizeof(oMaxPipeDataReg.bData);

			TCHAR strValue[MAX_PATH] = {0};
			WCHAR *ExtPtr = NULL;
			ExtPtr = wcsrchr(oMaxPipeDataReg.strKey, '\\');
			if(ExtPtr != NULL)
				swprintf_s(strValue, MAX_PATH, L"%s\\RecoveredEmails%s", m_csDesktopPath, ExtPtr);
			else
				swprintf_s(strValue, MAX_PATH, L"%s\\RecoveredEmails\\%s", m_csDesktopPath, oMaxPipeDataReg.strKey);
			ExtPtr = wcsrchr(strValue, '.');
			_tcscpy_s(oMaxPipeDataReg.strKey, strValue);
			AddMailEntrytoRemoveDB(&oMaxPipeDataReg);
			return true;
		}

		//if(pScanInfo->eDetectedBY <= Detected_BY_Max_FileSig)	// only need to save file info
		if(pScanInfo->eDetectedBY <= Detected_BY_Max_FullFileSig)
		{
			MAX_PIPE_DATA oMaxPipeData = {0};
			oMaxPipeData.eMessageInfo = pScanInfo->eMessageInfo;
			oMaxPipeData.eStatus = eStatus_NotApplicable;
			_tcscpy_s(oMaxPipeData.strBackup, _countof(oMaxPipeData.strBackup), pScanInfo->szBackupFileName);
			_tcscpy_s(oMaxPipeData.strFreshFile, _countof(oMaxPipeData.strFreshFile), pScanInfo->szFreshFile);
			_tcscpy_s(oMaxPipeData.strValue, _countof(oMaxPipeData.strValue), pScanInfo->szFileToScan);
			oMaxPipeData.ulSpyNameID = pScanInfo->ulThreatID;

			//if((pScanInfo->eMessageInfo == ExecPath) && (pScanInfo->eScannerType == Scanner_Type_Max_Email_Scan))	// recover email files on user's desktop!
			//{
			//	TCHAR strValue[MAX_PATH] = {0};
			//	WCHAR *ExtPtr = NULL;
			//	ExtPtr = wcsrchr(oMaxPipeData.strValue, '\\');
			//	if(ExtPtr != NULL)
			//		_swprintf(strValue, L"%s\\RecoveredEmails%s", m_csDesktopPath, ExtPtr);
			//	else
			//		_swprintf(strValue, L"%s\\RecoveredEmails\\%s", m_csDesktopPath, oMaxPipeData.strValue);
			//	ExtPtr = wcsrchr(strValue, '.');
			//	_tcscpy_s(oMaxPipeData.strValue, strValue);
			//}

			AddFiletoRemoveDB(&oMaxPipeData);
		}
		else 	// need to save file info & virus name info
		{
			MAX_PIPE_DATA_REG oMaxPipeDataReg = {0};

			oMaxPipeDataReg.eMessageInfo = pScanInfo->eMessageInfo;
			oMaxPipeDataReg.eStatus = eStatus_NotApplicable;
			oMaxPipeDataReg.ulSpyNameID = pScanInfo->ulThreatID;
			_tcscpy_s(oMaxPipeDataReg.strKey, _countof(oMaxPipeDataReg.strKey), pScanInfo->szFileToScan);
			_tcscpy_s(oMaxPipeDataReg.strBackup, _countof(oMaxPipeDataReg.strBackup), pScanInfo->szBackupFileName);
			_tcscpy_s(oMaxPipeDataReg.strValue, _countof(oMaxPipeDataReg.strValue), pScanInfo->szThreatName);

			//if(((pScanInfo->eMessageInfo == Virus_File) || (pScanInfo->eMessageInfo == Virus_File_Repair)) 
			//	&& (pScanInfo->eScannerType == Scanner_Type_Max_Email_Scan))	// recover email files on user's desktop!
			//{
			//	TCHAR strValue[MAX_PATH] = {0};
			//	WCHAR *ExtPtr = NULL;
			//	ExtPtr = wcsrchr(oMaxPipeDataReg.strKey, '\\');
			//	if(ExtPtr != NULL)
			//		_swprintf(strValue, L"%s\\RecoveredEmails%s", m_csDesktopPath, ExtPtr);
			//	else
			//		_swprintf(strValue, L"%s\\RecoveredEmails\\%s", m_csDesktopPath, oMaxPipeDataReg.strKey);
			//	ExtPtr = wcsrchr(strValue, '.');
			//	_tcscpy_s(oMaxPipeDataReg.strKey, strValue);
			//}
			AddRegistrytoRemoveDB(&oMaxPipeDataReg);
		}
	}

	CString csFileName(pScanInfo->szFileToScan);
	csFileName.MakeLower();
	if((csFileName.Right(4)== L".exe") || (csFileName.Right(4)== L".tmp") ||
	   (csFileName.Right(4)== L".pif") || (csFileName.Right(4)== L".com") ||
	   (csFileName.Right(4)== L".scr"))
	{
		if(SafeToTerminiate(csFileName))
		{
			if(HandleProcesses(csFileName))
			{
				Sleep(500);
			}
		}
	}
	return true;
}

bool CThreatManager::RestoreFile(PMAX_SCANNER_INFO pScanInfo)
{
	bool bRet = false;
	if(_waccess_s(pScanInfo->szBackupFileName, 0)== 0)
	{
		CString csDecryptedFile(pScanInfo->szBackupFileName);
		csDecryptedFile += L".dec";
		if(CBackupOperations::CopyAndEncryptFile(pScanInfo->szBackupFileName, csDecryptedFile))
		{
			CString csRootDir(pScanInfo->szFileToScan[0]);
			csRootDir += L":";
			if(_waccess_s(pScanInfo->szFileToScan, 0) == 0)	// Delete existing to handle recovering repaired file!
			{
				DeleteFile(pScanInfo->szFileToScan);
			}
			bRet = CBackupOperations::ExtractFile(csDecryptedFile, csRootDir, true);
		}
		DeleteFile(csDecryptedFile);	// clean up temp decrypted file, irrespective of recover success or failure!
	}
	if(bRet)
	{
		DeleteFile(pScanInfo->szBackupFileName);	// deleting orinigal backup after successfully retrival!
	}
	return bRet;
}

bool CThreatManager::SafeToTerminiate(CString csFileName)
{
	CString csSysPath(CSystemInfo::m_strSysDir);
	csSysPath.MakeLower();
	if((csSysPath + L"\\svchost.exe" == csFileName) || (csSysPath + L"\\csrss.exe" == csFileName)
		|| (csSysPath + L"\\lsass.exe" == csFileName) || (csSysPath + L"\\services.exe" == csFileName)
		|| (csSysPath + L"\\smss.exe" == csFileName) || (csSysPath + L"\\spoolsv.exe" == csFileName)
		|| (csSysPath + L"\\winlogon.exe" == csFileName))
	{
		AddLogEntry(L"##### UNSAFE-KILL: %s", csFileName, 0, true, LOG_DEBUG);
		return false;
	}

	AddLogEntry(L">>>>> SAFE-KILL  : %s", csFileName, 0, true, LOG_DEBUG);
	return true;
}

bool CThreatManager::DelFileUsingDriver(CString pPath2Del)
{
	bool	bRet = false;
	DWORD	dwReturn;
	WCHAR	szTemp[256] = {0};
	WCHAR	szRet[256] = {0};
	HANDLE	hFile = INVALID_HANDLE_VALUE;

	if (_tcslen(pPath2Del) > 256)
		return false;

	_stprintf_s(szTemp,256,_T("\\??\\%s"),pPath2Del);

	

	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatManager::AddMailEntrytoRemoveDB
In Parameters  : LPMAX_PIPE_DATA_REG pMaxPipeDataReg,
Out Parameters : bool
Description    :
Author & Date  : Siddharam Pujari & 03 Feb, 2012.
--------------------------------------------------------------------------------------*/
bool CThreatManager::AddMailEntrytoRemoveDB(LPMAX_PIPE_DATA_REG pMaxPipeDataReg)
{
	if(m_bAutomationLab)
	{
		return true;
	}

	bool bRet = true;
	time_t ltime=0;
	time(&ltime);

	SYS_OBJ_FIXEDSIZE oSysObjFixedSize = {0};
	oSysObjFixedSize.dwType = pMaxPipeDataReg->eMessageInfo;
	oSysObjFixedSize.dwSpywareID = pMaxPipeDataReg->ulSpyNameID;
	_tcscpy_s(oSysObjFixedSize.szKey, pMaxPipeDataReg->strKey);
	_tcscpy_s(oSysObjFixedSize.szBackupFileName, pMaxPipeDataReg->strBackup);
	oSysObjFixedSize.u64DateTime = ltime;
	oSysObjFixedSize.ulptrHive = reinterpret_cast<ULONG_PTR>(pMaxPipeDataReg->Hive_Type);
	_tcscpy_s(oSysObjFixedSize.szValue, pMaxPipeDataReg->strValue);
	memcpy(oSysObjFixedSize.byData, pMaxPipeDataReg->bData, pMaxPipeDataReg->iSizeOfData);
	oSysObjFixedSize.dwRegDataSize = pMaxPipeDataReg->iSizeOfData;
	memcpy(oSysObjFixedSize.byReplaceData, pMaxPipeDataReg->bReplaceData, pMaxPipeDataReg->iSizeOfReplaceData);
	oSysObjFixedSize.dwReplaceRegDataSize = pMaxPipeDataReg->iSizeOfReplaceData;
	oSysObjFixedSize.wRegDataType = pMaxPipeDataReg->Type_Of_Data;
	if(!m_pMaxDSrvWrapper)
	{
		m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
		if(m_pMaxDSrvWrapper)
		{
			m_pMaxDSrvWrapper->InitializeVirusScanner();
		}
	}
	if(m_pMaxDSrvWrapper)
	{
		bRet = m_pMaxDSrvWrapper->AddMailToRemoveDB(&oSysObjFixedSize);
	}
	return bRet;
}
void  CThreatManager::ConfigForNetworkScan(CString csScanDrive)
{
#ifdef _SDSCANNER
		if(!m_bValidated)
	{
	CString csAppPath =  CSystemInfo::m_strAppPath;
	CString csApplicationPath = csAppPath +_T("Tools\\");
	TCHAR szHostname[MAX_PATH]={0};
	DWORD dwSize = UNLEN + 1;
	CString csMachineName = csScanDrive.Left(csScanDrive.Find(L"\\",csScanDrive.Find(L"\\")+3));
	csMachineName = csMachineName.Mid(2);
	csMachineName.Trim();
	GetComputerName(szHostname,&dwSize);
	CString csHostname(szHostname);
	csHostname.Trim();
	if(csMachineName.CompareNoCase(csHostname) == 0 ) 
	{
		return;
	}			
	if(csScanDrive.GetAt(0)==L'\\')
	{		
		CRegistry objReg;				
		TCHAR  szUsername[MAX_PATH]= {0};
		CString csUsername;
		CString csProductKey =CSystemInfo::m_csProductRegKey;	           
		objReg.Get(csProductKey,L"CurrUser", csUsername,HKEY_LOCAL_MACHINE);
		_tcscpy_s(szUsername,MAX_PATH,csUsername);

		CS2S objUseraccounts(false);
		objUseraccounts.Load(csApplicationPath + CURR_USER_CRED);
		TCHAR *szPassword=NULL;
		objUseraccounts.SearchItem(szUsername,szPassword);

		CNetWorkUserValidation objNetValid;
		objNetValid.ImpersonateLocalUser(szUsername,szPassword);

		CString csMachineName;
		size_t iLen = csScanDrive.GetLength();
		if(iLen > 0)
		{
			CString csTemp(csScanDrive);			
			if(csTemp.Right(1) == L"\\")
			{
				csTemp = csTemp.Left((int)iLen -1);
			}
			if(csTemp.GetAt(0)==L'\\')
			{
				csMachineName = csTemp.Left(csTemp.Find(L"\\",csTemp.Find(L"\\")+3));
				csMachineName = csMachineName.Mid(2);			
			}
		}		
		TCHAR szMachineName[MAX_PATH]={0};
		_tcscpy_s(szMachineName,MAX_PATH,csMachineName);


		CBufferToStructure objNetworkCredentials(false, sizeof(TCHAR)*MAX_PATH, sizeof(NETCREDDATA));
		LPNETCREDDATA lpNetCredentials = NULL;				
		RevertToSelf();
		objNetworkCredentials.Load(csApplicationPath + NETWORK_SCAN_CRED);
	
		_tcslwr(szMachineName);
				if(objNetworkCredentials.SearchItem(szMachineName,(LPVOID&)lpNetCredentials))
				{
					objNetValid.ImpersonateLocalUser(szUsername,szPassword);
					objNetValid.NetworkValidation(szMachineName,lpNetCredentials->szUsername,lpNetCredentials->szPassword);					   
					m_bValidated = true;
				}					   
	}
	else
	{
		return;
	}
		}
#endif
}