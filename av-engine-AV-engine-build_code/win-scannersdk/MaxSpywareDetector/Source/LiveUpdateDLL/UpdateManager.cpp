#include "StdAfx.h"
#include "UpdateManager.h"
#include "HardDiskManager.h"
#include "BackupOperations.h"
#include "SDSystemInfo.h"
#include "LiveUpdate.h"

UpdateManager::UpdateManager(void)
{
	m_bMaxDBMergeSuccess = false;
}

UpdateManager::~UpdateManager(void)
{
}

bool UpdateManager::ExtractAndUpdateDownloads()
{
	CreateDirectory(_T("C:\\SDKDownload\\ExtractPath"), NULL);

	//CString csSDLiveUpdate;
	csSDLiveUpdate = m_csDownLoadPath + _T("\\") + TEMP_LIVEUPDATE;

	m_csServerVersionTXT = csSDLiveUpdate + _T("\\") + INI_FILE_NAME;
	m_csDeltaVersionINI = csSDLiveUpdate + _T("\\") + INI_DELTASERVER_FILE_NAME;

	m_bMaxDBMergeSuccess  = false;

	CHardDiskManager objHardDiskManager;
	CString csPath = CSystemInfo::m_strAppPath;
	objHardDiskManager.CheckFreeSpace(csPath.Left(csPath.Find(_T("\\"))));
	if(objHardDiskManager.GetTotalNumberOfFreeGBytes()< (double)0.21)
	{
		AddLogEntry(_T("Skipping merging delta and patches as disk space is less than 200MB"));
		return;
	}

	m_csDBFileNames.RemoveAll();
	BOOL bSDDatabase = CheckVersionNumber(m_csDeltaDetails);

	if(bSDDatabase)
	{
		MergeMaxDeltasEx();
	}

	return false;
}

bool UpdateManager::ReadAllSectionNameFromIni()
{
	CFile oFile;
	CFileException ex;
	
	// it may take some time to transfer the file while the event for new file is already
	if(!oFile.Open(m_csVersionINI, CFile::modeWrite, &ex))// generated and the update begins, the serverversion is not 
	{															// completely ready at this moment, hence we try to open
																// the file with write access until we are successfull!
		AddLogEntry(_T("##### File not ready: %s!"), m_csServerVersionTXT, 0, true, LOG_ERROR);
		return false;
	}
	oFile.Close();

	m_csDeltaDetails = m_objCommonFunctions.GetSectionName(_T("DELTADETAILS"));

	return true;
}

void UpdateManager::SetSDKParams(LIVEUPDATE_INFO *pUpdateInfo)
{
	m_csDownLoadPath = pUpdateInfo->szDowloadPath;
	m_csIniPath      = pUpdateInfo->szIniPath;
}

BOOL UpdateManager::CheckVersionNumber(const CString &csSectionName)
{
	if(csSectionName == _T(""))
	{
		return FALSE;
	}
	
	CString csLocalVersion = _T("0");
	CString csServerVersion = _T("");
	if(csSectionName == m_csDeltaDetails)
	{
		GetPrivateProfileString(csSectionName, _T("Max_Ver"), _T("0"), csServerVersion.GetBuffer(100), 100, m_csServerVersionTXT);
		csServerVersion.ReleaseBuffer();
	}

	if(csSectionName == m_csDeltaDetails)
	{
		if(!csLocalVersion.Replace(_T("."), _T("")))
		{
			AddLogEntry(_T("Invalid Local version no"));
			return FALSE;
		}
		if(!csServerVersion.Replace(_T("."), _T("")))
		{
			AddLogEntry(_T("Invalid Max version no"));
			return FALSE;
		}
		DWORD dwLocalVer = _wtoi(csLocalVersion);
		DWORD dwServerVer = _wtoi(csServerVersion);

		if(dwLocalVer < dwServerVer)
		{
			CString csBaseVersion = _T("");
			GetPrivateProfileString(csSectionName, _T("Base_Ver"), _T("0"), csBaseVersion.GetBuffer(100), 100, m_csServerVersionTXT);
			csBaseVersion.ReleaseBuffer();
			if(!csBaseVersion.Replace(_T("."), _T("")))
			{
				AddLogEntry(_T("Invalid Base version no"));
			}
			DWORD dwBaseVer =_wtoi(csBaseVersion);
			if(dwLocalVer < dwBaseVer)
			{
				// need to install full db patch!
				AddLogEntry(_T("Local Version Less Than Base Version! Need to install full database patch!"));
				return FALSE;
			}
			else
			{
				int iVerDiff = dwServerVer - dwLocalVer;
				if(iVerDiff > MAX_DELATAS)
				{
					iVerDiff = MAX_DELATAS;
				}
				for(int i=1; i <= iVerDiff; i++)
				{
					DWORD dwNewVer = dwLocalVer + i;

					CString csNewVerFileName = _T("");
					//csNewVerFileName.Format(_T("SDDatabase%d"), dwNewVer);		12-April-2016 Delta changes: Ravi
					csNewVerFileName.Format(_T("SDDatabaseDB%d"), dwNewVer);
					csNewVerFileName += _T(".db");
					CString csKeyName = m_pUpdateManager->GetDeltaVersion(csNewVerFileName);
					csKeyName += (L"_MD5");

					if(!CheckExistance(csSectionName, csKeyName, csNewVerFileName, 1))
					{
						m_bPartialDatabaseMerged = true;
						if(m_csDBFileNames.GetCount()==0)
						{
							continue;
						}
						break;	// required data files are missing
					}
					m_csDBFileNames.Add(csNewVerFileName);
				}
			}
			if(m_csDBFileNames.GetCount() > 0)
			{
				return TRUE;
			}
		}
	}

	return FALSE;
}

int UpdateManager::CheckExistance(const CString &csSectionName, LPCTSTR szKeyName, const CString &csFileName, int iType)
{
	CString csFileToCheck;
	if(iType == 0)			// Executables
		csFileToCheck = _T("C:\\SDKDownload\\ExtractPath") + BACK_SLASH + csFileName;
	else if(iType == 1)		//  Data
		csFileToCheck = _T("C:\\SDKDownload\\ExtractPath\\Data\\") /*+ _T("\\Data\\")*/ + csFileName;
	else
	{
		AddLogEntry(_T("##### Invalid Type: %s"), csFileName);
		return 0;
	}

	//if(_waccess(csFileToCheck, 0) != 0)
	//{
	//	if(iType == 0)			// Executables
	//	{
	//		AddLogEntry(_T("----- Missing File: %s"), csFileToCheck);
	//		csFileToCheck = m_csLocalBackupFolder + csFileName;
	//	}
	//}

	if(_waccess(csFileToCheck, 0) == 0)
	{
		CString csINIMD5;
		if(csSectionName.CompareNoCase(DELTADETAILS) == 0)
		{
			CString csDeltaVersionINI = m_csServerVersionTXT;
			CString csDeltaINI;
			csDeltaINI = INI_DELTASERVER_FILE_NAME;
			csDeltaVersionINI.Replace(INI_FILE_NAME,csDeltaINI);
			GetPrivateProfileString(csSectionName, szKeyName, L"", csINIMD5.GetBuffer(100), 100, csDeltaVersionINI);
			csINIMD5.ReleaseBuffer();
		}
		else
		{
			GetPrivateProfileString(csSectionName, szKeyName, L"", csINIMD5.GetBuffer(100), 100, m_csServerVersionTXT);
			csINIMD5.ReleaseBuffer();
		}

		if((iType == 2) && (csINIMD5.GetLength() == 0))
		{
			//AddLogEntry(_T("##### Skip File   : %s"), csFileToCheck, 0, true, LOG_WARNING);
			return 2;
		}

		CString csFileMD5;
		bool bMD5Status = GetMD5Signature(csFileToCheck, csFileMD5);
		if(bMD5Status && (csINIMD5.CompareNoCase(csFileMD5) == 0))
		{
			//AddLogEntry(_T("##### Found File  : %s"), csFileToCheck, 0, true, LOG_WARNING);
			return 1;
		}
		else
		{
			//AddLogEntry(_T("----- MD5 Failed  : %s - %s"), csFileToCheck, csINIMD5 + _T(" : ") + csFileMD5, true, LOG_WARNING);
			return 0;
		}
	}
	//AddLogEntry(_T("----- Missing File: %s"), csFileToCheck, 0, true, LOG_WARNING);
	return 0;
}

bool UpdateManager::GetMD5Signature(const CString &csFileName, CString &csMD5)
{
	CStringA csFileSigA(csFileName);
	char szMD5[33] = {0};
	if(GetMD5Signature32(csFileSigA, szMD5))
	{
		csMD5 = CString(szMD5);
		return true;
	}
	return false;
}

void UpdateManager::MergeMaxDeltasEx()
{
	
	m_bMaxDBMergeSuccess = false;
	m_csMaxDBVersionNo = _T("");

	bool bRetVal = true;
	CString csFileToMerge;
	CStringArray csarrIgnoreList;

	m_oDirectoryManager.MaxDeleteDirectory(_T("C:\\SDKDownload\\ExtractPath\\MergeTemp\\Data") /*+ _T("")*/, NULL, false, false);
	m_oDirectoryManager.MaxCreateDirectory(_T(_T("C:\\SDKDownload\\ExtractPath\\MergeTemp\\Data"));

	//HANDLE	hCopyThread = NULL;
	//DWORD	dwCopyThreadID  = 0x00;
	//hCopyThread = CreateThread(NULL,0x00,(LPTHREAD_START_ROUTINE)CopyDeltaThread,(LPVOID)this,0x00,&dwCopyThreadID);
	//if (hCopyThread != NULL)
	//{
	//	SetThreadPriority(hCopyThread, THREAD_PRIORITY_ABOVE_NORMAL);
	//	//AddLogEntry(L"Tushar : CopyDeltaThread Creation Success !!!");
	//}
	//else
	//{
	//	//AddLogEntry(L"Tushar : CopyDeltaThread Creation Failed !!!");	
	//}

	CString csDeltaPath = m_csFolderToMonitor + _T("\\Data\\");
	int iNoOFDeltas = (int)m_csDBFileNames.GetCount();
	
	/*WaitForSingleObject(hCopyThread, -1);
	if (hCopyThread != NULL)
	{
		CloseHandle(hCopyThread);
	}
	hCopyThread = NULL;*/

	if(m_bCopySuccess)
	{
		int iThreadCount = 0; 
		CString csMergePath =  _T("C:\\SDKDownload\\ExtractPath\\MergeTemp\\Data");
		CString csSourcePath;
		
		for(int iCtr = 0; iCtr < iNoOFDeltas; iCtr++)
		{
			csFileToMerge = m_csDBFileNames.GetAt(iCtr);
			csSourcePath = csDeltaPath + csFileToMerge + _T("e");
			AddLogEntry(L"Max Delta Merging: %s%s", csDeltaPath, csFileToMerge);
			if(ExtractDeltaFile(csDeltaPath + csFileToMerge))
			{
				CopyDBFilesToData(csSourcePath, csMergePath);
				m_oDirectoryManager.MaxDeleteDirectory(csSourcePath, true);
			}
			else
			{
				AddLogEntry(L"##### Extract Delta Failed: %s, %s", csDeltaPath, csFileToMerge);
				bRetVal = false;
				break;
			}
		}

	}

	m_bMaxDBMergeSuccess = bRetVal;
	if(m_bMaxDBMergeSuccess)
	{
		CDirectoryManager objDirMgr;
		objDirMgr.MaxDeleteDirectory(m_csFolderToMonitor + _T("\\MergeTemp\\Data\\*.tmp"), true, true);

		if(csFileToMerge.GetLength() > 0)
		{
			m_csMaxDBVersionNo = m_pUpdateManager->GetDeltaVersion(csFileToMerge);
			AddLogEntry(L"##### Max Database version : %s", m_csMaxDBVersionNo);
		}
	}
}

bool UpdateManager::ExtractDeltaFile(const CString &csDeltaFileName)
{
	DeleteFile(csDeltaFileName + _T("a"));
	if(CBackupOperations::CopyAndEncryptFile(csDeltaFileName, csDeltaFileName + _T("a")))
	{
		m_oDirectoryManager.MaxDeleteDirectory(csDeltaFileName + _T("e"), true);
		if(CBackupOperations::ExtractFile(csDeltaFileName + _T("a"), csDeltaFileName + _T("e")))
		{
			DeleteFile(csDeltaFileName + _T("a"));
			m_csDeltaFileName = csDeltaFileName + _T("e");
			return true;
		}
		else
		{
			m_oDirectoryManager.MaxDeleteDirectory(csDeltaFileName + _T("e"), true);
		}
	}
	else
	{
		DeleteFile(csDeltaFileName + _T("a"));
	}
	return false;
}