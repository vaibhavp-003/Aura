#include "pch.h"
#include "UpdateManagerEx.h"
#include "HardDiskManager.h"
#include "BackupOperations.h"
#include "SDSystemInfo.h"
#include "LiveUpdateDLL.h"
//#include "SDKSettings.h"

#define MAX_DELATAS 50000
bool GetMD5Signature32(const char *filepath, char *cMD5Signature);

//void CopyDeltaThread(LPVOID lpParam);

CUpdateManagerEx::CUpdateManagerEx(void)
{
	m_bMaxDBMergeSuccess = false;
	m_bCopySuccess = false;
	m_bPartialDatabaseMerged = false;
}

CUpdateManagerEx::~CUpdateManagerEx(void)
{
}

bool CUpdateManagerEx::ExtractAndUpdateDownloads()
{
	CreateDirectory(theApp.m_csWaitingForMergePath, NULL);

	CString csSDLiveUpdate;
	csSDLiveUpdate = m_csDownLoadPath + _T("\\") + TEMP_LIVEUPDATE;

	m_csServerVersionTXT = csSDLiveUpdate + _T("\\") + INI_FILE_NAME;
	m_csDeltaVersionINI = csSDLiveUpdate + _T("\\") + INI_DELTASERVER_FILE_NAME;

	m_bMaxDBMergeSuccess  = false;

	if(!ReadAllSectionNameFromIni())
		return false;

	m_csDBFileNames.RemoveAll();
	BOOL bSDDatabase = CheckVersionNumber(m_csDeltaDetails);

	if(bSDDatabase)
	{
		MergeMaxDeltasEx();
	}


	return true;
}

bool CUpdateManagerEx::ReadAllSectionNameFromIni()
{
	CFile oFile;
	CFileException ex;
	
	// it may take some time to transfer the file while the event for new file is already
	if(!oFile.Open(m_csServerVersionTXT, CFile::modeWrite, &ex))// generated and the update begins, the serverversion is not 
	{															// completely ready at this moment, hence we try to open
																// the file with write access until we are successfull!
		AddLogEntry(_T("##### File not ready: %s!"), m_csServerVersionTXT, 0, true, LOG_ERROR);
		return false;
	}

	oFile.Close();

	m_csDeltaDetails = m_objCommonFunctions.GetSectionName(_T("DELTADETAILS"));

	#ifdef WIN64
		m_csSDKDetails = m_objCommonFunctions.GetSectionNameForX64(_T("SDKDETAILS"));
	#else
		m_csSDKDetails = m_objCommonFunctions.GetSectionName(_T("SDKDETAILS"));
	#endif

	//m_csSDKDetails = m_objCommonFunctions.GetSectionName(_T("SDKDETAILS"));

	return true;
}

void CUpdateManagerEx::SetSDKParams()
{
	/*
	CSDKSettings objSettings;
	
	m_csDownLoadPath = objSettings.GetProductAppPath(); 
	m_csDownLoadPath = m_csDownLoadPath;// + SDKDOWNLOADFOLDER;
	m_csSettingIniPath = objSettings.GetProductAppPath() + SETTING_FOLDER + SDK_SETTINGS_INI;
	//m_csExtractFolderPath = m_csDownLoadPath + SDKEXTRACTPATH;
	*/

	CProductInfo objPrdInfo;
	CString m_csDownLoadPath = objPrdInfo.GetInstallPath();

	m_csSettingIniPath = objPrdInfo.GetInstallPath() + SETTING_FOLDER + "SDKSettings.ini";
}

BOOL CUpdateManagerEx::CheckVersionNumber(const CString &csSectionName)
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

	if(csSectionName == m_csSDKDetails)
	{
		GetPrivateProfileString(csSectionName, _T("VersionNo"), _T("0"), csServerVersion.GetBuffer(100), 100, m_csServerVersionTXT);
		csServerVersion.ReleaseBuffer();
	}

	if(csSectionName == m_csDeltaDetails)
	{
		GetPrivateProfileString(_T("ProductSetting"), _T("DatabaseVersion"), _T("0"), csLocalVersion.GetBuffer(100), 100, m_csSettingIniPath);
		csLocalVersion.ReleaseBuffer();
		
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
					/*if(theApp.m_iUseCloudScanning == 1)
					{
						csNewVerFileName.Format(_T("SDDatabaseCL%d"), dwNewVer);
					}
					else*/
					//{
						csNewVerFileName.Format(_T("SDDatabaseDB%d"), dwNewVer);
					//}
					csNewVerFileName += _T(".db");
					CString csKeyName = GetDeltaVersion(csNewVerFileName);
					csKeyName += (L"_MD5");

					//if(!CheckExistance(csSectionName, csKeyName, csNewVerFileName, 1))
					//{
					//	m_bPartialDatabaseMerged = true;
					//	if(m_csDBFileNames.GetCount()==0)
					//	{
					//		continue;
					//	}
					//	break;	// required data files are missing
					//}
					m_csDBFileNames.Add(csNewVerFileName);
				}
			}
			if(m_csDBFileNames.GetCount() > 0)
			{
				return TRUE;
			}
		}
		else if(dwLocalVer == dwServerVer)
		{
			AddLogEntry(L">>>>Deltas Are Upto Date With Latest Version:%s", csLocalVersion);
		}
	}

	if(csSectionName == m_csSDKDetails /*|| csSectionName == theApp.m_csSDKDetailsX64*/)
	{
		GetPrivateProfileString(_T("ProductSetting"), _T("SDKVersion"), _T("0"), csLocalVersion.GetBuffer(100), 100, m_csSettingIniPath);
		csLocalVersion.ReleaseBuffer();
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

		DWORD dwLocalVer=_wtoi(csLocalVersion);
		DWORD dwServerVer=_wtoi(csServerVersion);
		if(dwLocalVer < dwServerVer)
		{
			CString csFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csServerVersionTXT);

			if(csSectionName == theApp.m_csSDKDetails)
			{
				m_csSDKDetails = csFileName;
				//m_bSDK = true;
				return TRUE;
			}

			if(csSectionName == theApp.m_csSDKDetailsX64)
			{
				m_csSDKDetails = csFileName;
				//m_bSDKX64 = true;
				return TRUE;
			}
		}
	}

	return FALSE;
}

int CUpdateManagerEx::CheckExistance(const CString &csSectionName, LPCTSTR szKeyName, const CString &csFileName, int iType)
{
	CString csFileToCheck;
	if(iType == 0)			// Executables
		csFileToCheck = _T("C:\\SDKDownload\\ExtractPath\\") /*+ BACK_SLASH*/ + csFileName;
	else if(iType == 1)		// Max Data
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

bool CUpdateManagerEx::GetMD5Signature(const CString &csFileName, CString &csMD5)
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

void CUpdateManagerEx::MergeMaxDeltasEx()
{
	
	m_bMaxDBMergeSuccess = false;
	m_csMaxDBVersionNo = _T("");

	bool bRetVal = true;
	CString csFileToMerge;
	CStringArray csarrIgnoreList;

	CString csDeltaPath = theApp.m_csWaitingForMergePath + _T("\\MergeTemp\\Data\\");
	int iNoOFDeltas = (int)m_csDBFileNames.GetCount();

	m_bCopySuccess = true;
	if(m_bCopySuccess)
	{
		int iThreadCount = 0; 
		CString csMergePath;

		CProductInfo objPrdInfo;
		csMergePath = objPrdInfo.GetInstallPath();

		
		CString csDatabaseVersion;
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("DatabaseVersion"), csDatabaseVersion, HKEY_LOCAL_MACHINE);
		//GetPrivateProfileString(_T("ProductSetting"), _T("DatabaseVersion"), _T("0"), csDatabaseVersion.GetBuffer(100), 100, m_csSettingIniPath);
		csDatabaseVersion.ReleaseBuffer();

		csMergePath += _T("Data\\") + csDatabaseVersion + _T("\\");
		CString csSourcePath;
		
		for(int iCtr = 0; iCtr < iNoOFDeltas; iCtr++)
		{
			csFileToMerge = m_csDBFileNames.GetAt(iCtr);
			csSourcePath = csDeltaPath + csFileToMerge + _T("e");

			if(ExtractDeltaFile(csDeltaPath + csFileToMerge))
			{
				CopyDBFilesToData(csSourcePath, csMergePath);
				if(m_oDirectoryManager.MaxDeleteDirectory(csSourcePath, true))
				{
					bRetVal = true;
				}

				DeleteFile(csDeltaPath + csFileToMerge);
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
		objDirMgr.MaxDeleteDirectory(theApp.m_csWaitingForMergePath + _T("\\MergeTemp\\Data\\*.tmp"), true, true);

		if(csFileToMerge.GetLength() > 0)
		{
			m_csMaxDBVersionNo = GetDeltaVersion(csFileToMerge);
			RenameDataFolder(csFileToMerge);
			AddLogEntry(L"##### Max Database version : %s", m_csMaxDBVersionNo);
		}
	}
}

bool CUpdateManagerEx::ExtractDeltaFile(const CString &csDeltaFileName)
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

void CUpdateManagerEx::CopyDBFilesToData(CString csDbPath, CString csMergePath)
{
	BOOL bMoreFiles = FALSE;
	CFileFind objFinder;
	CDirectoryManager objDirMgr;
	bMoreFiles = objFinder.FindFile(csDbPath + _T("\\*.*"));
	if(!bMoreFiles)
	{
		return;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();

		if(objFinder.IsDots())
		{
			continue;
		}
		else if(objFinder.IsDirectory())
		{
			continue;
		}
		else
		{
			CString csFile = objFinder.GetFileName();
			int iPos = csFile.Find(L"YrScanDB_");	// For Yara signature db copy 22-jan-2019
			int iPosIcon = csFile.Find(L"IconDB");	// For Icon signature db copy 24-July-2019

			if( iPos!= -1 || iPosIcon != -1)
			{
				if(iPos!= -1)
				{
					CString csSrcPath = csDbPath + _T("\\")+ csFile;
					CString csYaraVer = csFile.Mid(iPos+12);
					iPos = csYaraVer.Find(L".");
					if(iPos != -1)
					{
						csYaraVer = csYaraVer.Left(iPos);
					}
					//CSDKSettings objSettings;	
					//CString csDescPath = objSettings.GetProductAppPath(); 
					CProductInfo objPrdInfo;
					CString csDescPath = objPrdInfo.GetInstallPath();
					if(iPos != -1)
					{
						csDescPath = csDescPath + _T("YrScanDB.yar");
						CopyFile(csSrcPath,csDescPath, false);
					}
					DeleteFile(csSrcPath);
					if(!csYaraVer.IsEmpty())
					{
						WritePrivateProfileString(_T("ProductSetting"), _T("YrScanVersion"), csYaraVer, m_csSettingIniPath);
					}
				}
				if(iPosIcon != -1)
				{	
					CString csSrcPath = csDbPath + _T("\\")+ csFile;
					//CSDKSettings objSettings;	
					CProductInfo objPrdInfo;
					CString csDescPath = objPrdInfo.GetInstallPath();

					csDescPath = csDescPath + _T("IconDB.DB");
					CopyFile(csSrcPath,csDescPath, false);
					DeleteFile(csSrcPath);

				}
			}
			else
			{
				CString csSrcPath = csDbPath + _T("\\")+ csFile;
				CString csDestPath = csMergePath + csFile;
				CopyFile(csSrcPath,csDestPath, false);
			}
		}
	
	}
objFinder.Close();
}

CString CUpdateManagerEx::GetDeltaVersion(const CString &csFileName)
{
	try
	{
		CString csDeltaVerNo = csFileName;
		//csDeltaVerNo.Replace(_T("SDDatabase"), _T(""));			12-April-2016 Delta changes: Ravi
		//csDeltaVerNo.Replace(_T("SDDatabaseCL"), _T(""));
		csDeltaVerNo.Replace(_T("SDDatabaseDB"), _T(""));
		csDeltaVerNo.Replace(_T(".db"), _T(""));
		csDeltaVerNo.Insert(2, _T("."));
		csDeltaVerNo.Insert(4, _T("."));
		csDeltaVerNo.Insert(6, _T("."));
		return csDeltaVerNo;
	}
	catch(...)
	{
		AddLogEntry(L"Error occoured in CUpdateManager::GetDeltaVersion");
	}
	return BLANKSTRING;
}

//void CopyDeltaThread(LPVOID lpParam)
//{
//	CUpdateManagerEx	*pInstance = (CUpdateManagerEx	*)lpParam;
//
//	pInstance->CopyDelta();
//
//	return;
//}

void CUpdateManagerEx::CopyDelta()
{
	m_bCopySuccess = false;
	//CString csMaxDBPath = L"";
	//CRegistry m_objRegistry;
	//m_objRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);

	//CStringArray csarrIgnoreList;
	//csarrIgnoreList.Add(L"*.tmp");
	//AddLogEntry(_T("Start copying DB Src: %s, Dst: %s"), csMaxDBPath, m_csFolderToMonitor + _T("\\MergeTemp\\Data"));
	//if(!m_oDirectoryManager.MaxCopyDirectory(m_csFolderToMonitor + _T("\\MergeTemp\\Data"), csMaxDBPath, false, true, &csarrIgnoreList))
	//{
	//	AddLogEntry(_T("Copying Failed: %s, Dst: %s"), csMaxDBPath, m_csFolderToMonitor + _T("\\MergeTemp\\Data"));
	//	return;
	//}

	///*AddLogEntry(_T("Start loading DB..."), 0, 0, true, LOG_WARNING);
	//int iThreadCount = 0;
	//for(iThreadCount = 0; iThreadCount < MERGING_THREAD_COUNT ; iThreadCount++)
	//{
	//	if(!m_pUpdateManager->LoadDBType(m_csFolderToMonitor + _T("\\MergeTemp\\Data\\"), iThreadCount, 0, true))
	//	{
	//		CString csTemp;
	//		csTemp.Format(L"%d", iThreadCount); 
	//		AddLogEntry(L"##### LoadDBType Failed for: %s", csTemp);
	//		return;
	//	}
	//}*/
	m_bCopySuccess = true;

	//AddLogEntry(_T("End loading DB..."), 0, 0, true, LOG_WARNING);
}

bool CUpdateManagerEx::RenameDataFolder(CString csFileToMerge)
{
	bool bRetVal = false;
	CString csCurrentPath;

	//CSDKSettings objSetting;
	CProductInfo objPrdInfo;
	csCurrentPath = objPrdInfo.GetInstallPath();

	CString csCurrentVersion;
	GetPrivateProfileString(_T("ProductSetting"), _T("DatabaseVersion"), _T("0"), csCurrentVersion.GetBuffer(100), 100, m_csSettingIniPath);
	csCurrentVersion.ReleaseBuffer();

	csCurrentPath += _T("Data\\") + csCurrentVersion + _T("\\");

	CString csNewVer = GetDeltaVersion(csFileToMerge);

	CString csNewDataPath = csCurrentPath;
	csNewDataPath.Replace(csCurrentVersion, csNewVer);

	if(_wrename(csCurrentPath, csNewDataPath) == 0)
	{
		WritePrivateProfileString(_T("ProductSetting"), _T("CurrentMDB"), csNewDataPath, m_csSettingIniPath);
		WritePrivateProfileString(_T("ProductSetting"), _T("DatabaseVersion"), csNewVer, m_csSettingIniPath);
		bRetVal = true;
	}

	return bRetVal;
}

bool CUpdateManagerEx::ExtractAndMergeZipFile(CString csZipFilePath)
{

	
	return false;
}

void CUpdateManagerEx::CopyZipFilesToFolder(CString csDbPath, CString csMergePath)
{
	BOOL bMoreFiles = FALSE;
	CFileFind objFinder;
	CDirectoryManager objDirMgr; 
	bMoreFiles = objFinder.FindFile(csDbPath + _T("\\*.*"));
	if(!bMoreFiles)
	{
		return;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();

		if(objFinder.IsDots())
		{
			continue;
		}
		else if(objFinder.IsDirectory())
		{
			continue;
		}
		else
		{
			CString csFile = objFinder.GetFileName();
			
			CString csFileCheck = csFile;
			csFileCheck.MakeLower();
			if(csFileCheck.Find(L"sd") != -1 && csFileCheck.Find(L".db") != -1)
			{
				//CSDKSettings objSDKSettings;
				CRegistry objReg;
				CString csMaxDBPath;
				objReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
				//CString csMaxDBPath = objSDKSettings.GetProductSettingsString(PRODUCT_SETTINGS, CURRENT_MAX_DB_VAL);
				CString csSrcPath = csDbPath + _T("\\") + csFile;
				CString csDestPath = csMaxDBPath + csFile;
				CString csRenamePath = csMaxDBPath + _T("_") + csFile;
				DeleteFile(csRenamePath);	

				if(_wrename(csDestPath, csRenamePath) == 0)
				{
					CopyFile(csSrcPath,csDestPath, false);
				}
				else if(!PathFileExists(csDestPath))
				{
					CopyFile(csSrcPath,csDestPath, false);
				}
			}
			else
			{
				CString csSrcPath = csDbPath + _T("\\") + csFile;
				CString csDestPath = csMergePath + _T("\\") + csFile;
				CString csRenamePath = csMergePath + _T("\\_") + csFile;

				DeleteFile(csRenamePath);
			
				if(/*MoveFileEx(csDestPath, csRenamePath, MOVEFILE_DELAY_UNTIL_REBOOT)*/_wrename(csDestPath, csRenamePath) == 0)
				{
					CopyFile(csSrcPath,csDestPath, false);
				}
				else if(!PathFileExists(csDestPath))
				{
					CopyFile(csSrcPath,csDestPath, false);
				}
			}
		}
	}
	objFinder.Close();
}