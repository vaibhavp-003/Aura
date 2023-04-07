#include "pch.h"
#include "Shlwapi.h"
#include "MaxProductMerger.h"
#include "ProcessSync.h"
#include "SDSAConstants.h"
#include "MaxCommunicator.h"
#include "MaxPipes.h"
#include "MaxDSrvWrapper.h"
#include "HardDiskManager.h"
#include "verinfo.h"
#include "ProductInfo.h"

#define MAX_DELATAS 50000

bool GetMD5Signature32(const char *filepath, char *cMD5Signature);

UINT MonitorThread(LPVOID lpParam);
UINT EnumerateThread(LPVOID lParam);
UINT RaiseInitialEventThread(LPVOID lpParam);
void BlackDBMergerThread(LPVOID pThis);
void CopyDeltaThread(LPVOID lpParam);

CMaxProductMerger::CMaxProductMerger(void):
					m_bMaxDBMergeSuccess(false), m_pUpdateManager(NULL),
					m_lpfnDisableWow64BitRedirection(NULL), m_pOldValue(NULL),
					m_lpfnRevert64BitRedirection(NULL), m_bIsWow64(FALSE)
{
	m_bCheckAndFixDB = false;
	m_bShowAutoUpdateSuccessMsg = false;
	m_bCopySuccess = false;
	m_bDownloaded = false;

	{
		IsOS64bit();
		m_objRegistry.SetWow64Key(m_bIsWow64?true:false);
		if(m_lpfnDisableWow64BitRedirection)
		{
			m_lpfnDisableWow64BitRedirection(&m_pOldValue);
		}
	}
}

CMaxProductMerger::~CMaxProductMerger(void)
{
	AddLogEntry(0, 0, 0);
	if(m_lpfnRevert64BitRedirection)
	{
		m_lpfnRevert64BitRedirection(m_pOldValue);
	}
}

BOOL CMaxProductMerger::IsOS64bit()
{
	m_bIsWow64 = FALSE;
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process = NULL;

	HMODULE hModule = NULL;
	hModule = GetModuleHandle(_T("kernel32"));
	if(hModule)
	{
		fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(hModule, "IsWow64Process");
	}

	if(fnIsWow64Process)
	{
		if(!fnIsWow64Process(GetCurrentProcess(),&m_bIsWow64))
		{
			m_bIsWow64 = FALSE;
		}
	}
	if(m_bIsWow64)
	{
		if(!m_lpfnDisableWow64BitRedirection)
		{
			m_lpfnDisableWow64BitRedirection = (LPFN_DISABLEWOW64REDIRECTION)GetProcAddress(hModule, "Wow64DisableWow64FsRedirection");
		}

		if(!m_lpfnRevert64BitRedirection)
		{
			m_lpfnRevert64BitRedirection = (LPFN_REVERTWOW64REDIRECTION)GetProcAddress(hModule, "Wow64RevertWow64FsRedirection");
		}
	}
	return m_bIsWow64;
}

void CMaxProductMerger::StartMonitoringThread()
{
	//LowerProcessPriorityIfUniProcessorCPU();
	m_bReceivedNewEvent = false;
	m_bReceivedQuitEvent = false;
	m_EnumerateEvent.SetEvent();
	m_QuitEvent.ResetEvent();
	AfxBeginThread(MonitorThread, (LPVOID)this);
	AfxBeginThread(RaiseInitialEventThread, (LPVOID)this);
}

void CMaxProductMerger::StopMonitoringThread()
{
	m_bReceivedQuitEvent = true;
	m_QuitEvent.SetEvent();
	GenerateFileEvent(_T("\\Quit.txt"));
}

UINT RaiseInitialEventThread(LPVOID lpParam)
{
	//SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
	Sleep(5000);
	CMaxProductMerger *pThis = (CMaxProductMerger*)lpParam;
	if(pThis == NULL)
		return 0;

	pThis->GenerateFileEvent(_T("\\Trigger.txt"));
	return 0;
}

void CMaxProductMerger::GenerateFileEvent(LPCTSTR szFileName)
{
	CString csTriggerFileName = m_csFolderToMonitor + szFileName;
	HANDLE hFile = CreateFile(csTriggerFileName, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL /*| FILE_FLAG_DELETE_ON_CLOSE*/, 0);
	if(INVALID_HANDLE_VALUE != hFile)
	{
		DWORD dwBytesWritten = 0;
		TCHAR szBuffer[MAX_PATH] = {0};
		_tcscpy_s(szBuffer, MAX_PATH, _T("Helloo"));
		WriteFile(hFile, szBuffer, _countof(szBuffer)* sizeof(TCHAR), &dwBytesWritten, 0);
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
		Sleep(5000);
		DeleteFile(csTriggerFileName);
	}
	return;
}

UINT MonitorThread(LPVOID lpParam)
{
	CMaxProductMerger *pThis = (CMaxProductMerger*)lpParam;
	if(pThis == NULL)
		return 0;

	pThis->StartMonitoring();
	return 0;
}

void CMaxProductMerger::StartMonitoring()
{
	DWORD dwReturn = 0, dwRetValue = 0;
	bool bKeepRunning = true;
	int iMaxFailLimit = 5, iFailCount = 0;
	HANDLE hDirectory = INVALID_HANDLE_VALUE;
	PFILE_NOTIFY_INFORMATION lpFileNotifyInfo = 0, lpFileInfo = 0;

	m_csFolderToMonitor = m_objSystemInfo.m_strAppPath + LIVEUPDATE_WAIT_FOR_MERGE;

	m_csLocalBackupFolder = m_objSystemInfo.m_strAppPath[0];
	m_csLocalBackupFolder += _T(":\\AuLiveUpdate\\");

	// to clean remaining files and folder
	CString csSDFileVer;
	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, csSDFileVer, HKEY_LOCAL_MACHINE);
	csSDFileVer.Replace(_T("."),_T(""));
	CleanUnwantedDelta(m_csFolderToMonitor + _T("\\Data"),csSDFileVer);
	//
	if(PathFileExists(m_csLocalBackupFolder + _T("Data\\DBVersion.ini")))
	{
		CString csVersion;
		GetPrivateProfileString(_T("Database"), _T("Version"), L"", csVersion.GetBuffer(100), 100, m_csLocalBackupFolder + _T("Data\\DBVersion.ini"));
		csVersion.ReleaseBuffer();
		if(csVersion.IsEmpty() || csVersion.GetLength()<10)
		{
			AddLogEntry(L"Setting local DBVersion.ini", 0, 0, true, LOG_WARNING);
			CString csMaxDBVersionNo;
			m_objRegistry.Get(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, csMaxDBVersionNo, HKEY_LOCAL_MACHINE);
			CString csDbfile = m_csLocalBackupFolder + _T("Data\\DBVersion.ini");
			CString csVersion  = csMaxDBVersionNo;
			WritePrivateProfileString(_T("Database"), _T("Version"), csVersion,  csDbfile);
			
		}
	}

	DWORD dwCheck = 0;
	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess", dwCheck, HKEY_LOCAL_MACHINE);
	if(dwCheck == 5 || dwCheck == 6)
	{
		CString csMaxDBVersionNo;
		m_objRegistry.Get(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, csMaxDBVersionNo, HKEY_LOCAL_MACHINE);
		m_oDirectoryManager.MaxDeleteDirectory(m_csFolderToMonitor + _T("\\MergeTemp\\Data"), NULL, false, false);
		CString csDbfile = m_csLocalBackupFolder + _T("Data\\DBVersion.ini");
		CString csVersion  = csMaxDBVersionNo;
		WritePrivateProfileString(_T("Database"), _T("Version"), csVersion,  csDbfile);
		//m_oDirectoryManager.MaxDeleteDirectory(m_csFolderToMonitor + _T("\\Data"), NULL, false, false);
		m_objRegistry.Set(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess",0, HKEY_LOCAL_MACHINE);
	}
	else
	{
		m_objRegistry.Set(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess", 0, HKEY_LOCAL_MACHINE);
	}

	CreateDirectory(m_objSystemInfo.m_strAppPath + LIVEUPDATE_WAIT_FOR_MERGE, NULL);

	AddLogEntry(L"Waiting for Merge Folder: %s", m_csFolderToMonitor, 0, true, LOG_WARNING);

	hDirectory = CreateFile(m_csFolderToMonitor, FILE_LIST_DIRECTORY, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
	if(INVALID_HANDLE_VALUE == hDirectory)
	{
		AddLogEntry(_T("Failed getting handle to directory: %s"), m_csFolderToMonitor, 0, true, LOG_WARNING);
		return;
	}

	lpFileNotifyInfo = (PFILE_NOTIFY_INFORMATION) malloc(1024 * 4);
	if(!lpFileNotifyInfo)
	{
		CloseHandle(hDirectory);
		AddLogEntry(_T("Failed getting memory to get event notifications: %s"), m_csFolderToMonitor, 0, true, LOG_WARNING);
		return;
	}

	AddLogEntry(_T("Monitoring Folder: %s"), m_csFolderToMonitor, 0, true, LOG_WARNING);
	AddLogEntry(_T("Backup Folder: %s"), m_csLocalBackupFolder, 0, true, LOG_WARNING);

	while(!m_bReceivedQuitEvent && bKeepRunning)
	{
		AddLogEntry(_T("Waiting for event"), 0, 0, true, LOG_WARNING);

		memset(lpFileNotifyInfo, 0, 1024 * 4);
		dwRetValue = ReadDirectoryChangesW(hDirectory, lpFileNotifyInfo, 1024 * 4, FALSE, FILE_NOTIFY_CHANGE_LAST_WRITE, &dwReturn, 0, 0);
		if(0 == dwRetValue || ERROR_NOTIFY_ENUM_DIR == dwRetValue)
		{
			bKeepRunning = iMaxFailLimit != iFailCount++;
			continue;
		}
		else
		{
			iFailCount = 0;
		}

		lpFileInfo = lpFileNotifyInfo;
		do
		{
			if(0 == _tcsicmp(lpFileInfo->FileName, _T("Trigger.txt")) || 0 == _tcsicmp(lpFileInfo->FileName, _T("ServerVersionEx.txt")))
			{
				AddLogEntry(_T("Received a change notification. process file: %s"), lpFileInfo->FileName, 0, true, LOG_WARNING);
				AfxBeginThread(EnumerateThread, (LPVOID)this);
			}
			else
			{
				AddLogEntry(_T("Received a change notification. ignore file: %s"), lpFileInfo->FileName, 0, true, LOG_WARNING);
			}

			if(lpFileInfo->NextEntryOffset)
			{
				AddLogEntry(_T("getting next name in list: %s"), lpFileInfo->FileName, 0, true, LOG_WARNING);
				lpFileInfo = (PFILE_NOTIFY_INFORMATION)((LPBYTE)lpFileInfo) + lpFileInfo->NextEntryOffset;
				AddLogEntry(_T("the next name in list is: %s"), lpFileInfo->FileName, 0, true, LOG_WARNING);
			}
		}while(lpFileInfo->NextEntryOffset);
	}

	free(lpFileNotifyInfo);
	CloseHandle(hDirectory);
	AddLogEntry(_T("Out of Monitoring Function!"), 0, 0, true, LOG_WARNING);
}

UINT EnumerateThread(LPVOID lParam)
{
	CMaxProductMerger *pThis = (CMaxProductMerger*)lParam;
	if(pThis == NULL)
		return 0;

	pThis->StartEnumerating();
	return 0;
}

void CMaxProductMerger::StartEnumerating()
{
	if(m_bReceivedNewEvent)	// already have a event waiting to restart!
		return;

	m_bReceivedNewEvent = true;
	AddLogEntry(_T("Waiting for EnumerateEvent to become signaled!"), 0, 0, true, LOG_WARNING);
	WaitForSingleObject(m_EnumerateEvent.m_hObject, INFINITE);

	m_bReceivedNewEvent = false;
	AddLogEntry(_T("EnumerateEvent is signaled!"), 0, 0, true, LOG_WARNING);

	EnumFolderAndPerformUpdate();

	AddLogEntry(0, 0, 0);
	m_EnumerateEvent.SetEvent();
}

void CMaxProductMerger::EnumFolderAndPerformUpdate()
{
	AddLogEntry(_T("In Check ServerVersion!"), 0, 0, true, LOG_WARNING);

	m_csServerVersionTXT = m_csFolderToMonitor;
	m_csServerVersionTXT += BACK_SLASH;
	m_csServerVersionTXT += INI_FILE_NAME;

	m_csLockFileName = m_objSystemInfo.m_strSettingPath;
	m_csLockFileName += _T("SyncLock.txt");

	CheckAndFixDB();
	if(_waccess(m_csServerVersionTXT, 0) == 0)
	{
		AddLogEntry(_T("Found %s"), m_csServerVersionTXT, 0, true, LOG_WARNING);
		StartUpdating();
	}

	AddLogEntry(_T("Out Check ServerVersion!"), 0, 0, true, LOG_WARNING);
}

void CMaxProductMerger::StartUpdating()
{
	AddLogEntry(_T("StartUpdating!"));
	CreateDirectory(m_csLocalBackupFolder, NULL);
	
	CString csFileName = m_csLocalBackupFolder + m_csProductDetails;


	BOOL bDoProcessCleanup = TRUE;
	m_bMergingLatestBase	= false;
	m_bDatabaseFullPatch	= false;
	m_bMaxDBMergeSuccess	= false;
	m_bVirusPatch			= false;
	m_bFirewallPatch		= false;
	m_bFirstPriorityPatch	= false;
	m_bProductPatch			= false;
	m_bRemoveSpyPatch		= false;
	m_bKeyLoggerPatch		= false;
	m_bRootKitPatch			= false;
	m_bPartialDatabaseMerged= false;
	m_bUpdateVersionPartial	= false;
	m_bUpdateVersionPatch	= false;

	CHardDiskManager objHardDiskManager;
	CString csPath = CSystemInfo::m_strAppPath;
	objHardDiskManager.CheckFreeSpace(csPath.Left(csPath.Find(_T("\\"))));
	if(objHardDiskManager.GetTotalNumberOfFreeGBytes()< (double)0.21)
	{
		AddLogEntry(_T("Skipping merging delta and patches as disk space is less than 200MB"));
		return;
	}

	if(!ReadAllSectionNameFromIni())
		return;

	if(m_bReceivedNewEvent)
		return;

	CProcessSync objProcessSync;
	if(!objProcessSync.SetLock(m_csLockFileName))
	{
		AddLogEntry(_T("Another application is updating the product! This call will be ignored!"));
		return;
	}
	DWORD dwCheck = 0;
	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess", dwCheck, HKEY_LOCAL_MACHINE);
	if(dwCheck ==  5 || dwCheck == 6)
	{
		AddLogEntry(L"Live Update process Checking 4", 0, 0, true, LOG_WARNING);
		CString csMaxDBVersionNo;
		m_objRegistry.Get(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, csMaxDBVersionNo, HKEY_LOCAL_MACHINE);
		
		m_oDirectoryManager.MaxDeleteDirectory(m_csFolderToMonitor + _T("\\MergeTemp\\Data"), NULL, false, false);
		CString csVersion  = csMaxDBVersionNo;
		WritePrivateProfileString(_T("Database"), _T("Version"), csVersion, m_csLocalBackupFolder + _T("Data\\DBVersion.ini"));
		//m_oDirectoryManager.MaxDeleteDirectory(m_csFolderToMonitor + _T("\\Data"), NULL, false, false);
		m_objRegistry.Set(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess",0, HKEY_LOCAL_MACHINE);
	}
			
	//////////////////////For Local Merging//////////////////////////////////
	m_objRegistry.Set(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess", 1, HKEY_LOCAL_MACHINE);
	AddLogEntry(L"Live Update process Check 1", 0, 0, true, LOG_WARNING);
	DWORD dwDabaseCorrupt = 0;
	DWORD dwDabaseCorruptRecheck = 0;
	AddLogEntry(_T("Local Merging Check!"), 0, 0, true, LOG_WARNING);
	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("AutoDatabasePatch"), dwDabaseCorrupt, HKEY_LOCAL_MACHINE);
	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("RecheckAutoDatabasePatch"), dwDabaseCorruptRecheck, HKEY_LOCAL_MACHINE);
	
	if(dwDabaseCorrupt && dwDabaseCorruptRecheck)
	{
		AddLogEntry(_T("Local Merging process"), 0, 0, true, LOG_WARNING);
		CString csMaxDBVersionNo;
		m_objRegistry.Get(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, csMaxDBVersionNo, HKEY_LOCAL_MACHINE);
		if(csMaxDBVersionNo.IsEmpty())
		{
			AddLogEntry(_T("Empty Data"), 0, 0, true, LOG_WARNING);
		}			
		CString csAVLiveUpdateBackup;
		csAVLiveUpdateBackup= CSystemInfo::m_strAppPath[0];
		csAVLiveUpdateBackup += _T(":\AuLiveUpdate\\Data");
		CStringArray csarrIgnoreList;
		csarrIgnoreList.Add(L"*.tmp");
		CDirectoryManager m_oDirectoryManager;

		//Need to check all deltas available
		if (PathFileExists(csAVLiveUpdateBackup) == FALSE)
		{
			m_objRegistry.Set(CSystemInfo::m_csProductRegKey, _T("AutoDatabasePatch"), 1, HKEY_LOCAL_MACHINE);
			m_objRegistry.Set(CSystemInfo::m_csProductRegKey, _T("RecheckAutoDatabasePatch"), 4, HKEY_LOCAL_MACHINE);

			return;
		}
		CMaxDSrvWrapper objMaxDSrvWrapper;
		objMaxDSrvWrapper.InitializeDatabase();
		objMaxDSrvWrapper.DeInitializeDatabase();
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, STOPPROTECTION, ON);

		Sleep(50);

		/*bool bCopyBackUP = m_oDirectoryManager.MaxMoveDirectory(m_objSystemInfo.m_strDBPath + L"\\_" + csMaxDBVersionNo, m_objSystemInfo.m_strDBPath + L"\\" + csMaxDBVersionNo, true, true);
		if(!bCopyBackUP)
		{
			AddLogEntry(_T("####Local Merging process copy failed, 0, 0, true, LOG_WARNING);
		}*/
		bool bCopyBackUP = m_oDirectoryManager.MaxCopyDirectory(m_objSystemInfo.m_strDBPath + L"\\" + csMaxDBVersionNo + L"\\", csAVLiveUpdateBackup, false, true, &csarrIgnoreList, NULL, true);
		//if(!bCopyBackUP)
		{
			AddLogEntry(_T("####Local Merging process copy failed"), 0, 0, true, LOG_WARNING);
		}
		if(bCopyBackUP)
		{
			m_objRegistry.DeleteValue(CSystemInfo::m_csProductRegKey, _T("DatabasePatch"), HKEY_LOCAL_MACHINE);
			m_objRegistry.DeleteValue(CSystemInfo::m_csProductRegKey, _T("AutoDatabasePatch"), HKEY_LOCAL_MACHINE);	
		}
		DeleteFile(m_objSystemInfo.m_strDBPath + L"\\" + csMaxDBVersionNo + L"\\DBVersion.ini");
		CString csVersion = csMaxDBVersionNo;
		WritePrivateProfileString(_T("Database"), _T("Version"), csVersion, m_csLocalBackupFolder + _T("Data\\DBVersion.ini"));
		
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RESTARTPROTECTION, ON);
		AddLogEntry(_T("Local Merging Finished!"), 0, 0, true, LOG_WARNING);
		return;
	}
	
////////////////////////////////////////////////////////////////////////////////////////

	if(CheckVersionNumber(m_csFirstPriorityDetails))
	{
		if(m_bFirstPriorityPatch)
		{
			m_bDownloaded = true;
			BackupPatch(m_csFirstPriorityFileName);
			ExecutePatch(m_csFirstPriorityFileName, true);
		}		
	}

	else
	{
		{
			m_csFullUpdateFileName = m_objCommonFunctions.GetFileName(m_csFullUpdateDetails, m_csServerVersionTXT);
			DWORD dwFullUpdate = 0;
			m_objRegistry.Get(CSystemInfo::m_csProductRegKey, L"FULLLIVEUPDATE", dwFullUpdate, HKEY_LOCAL_MACHINE);
			if(dwFullUpdate)
			{
				m_bFullUpdatePatch = (CheckExistance(m_csFullUpdateDetails, _T("MD5"), m_csFullUpdateFileName, 0) ? true : false);

				if(m_bFullUpdatePatch)
				{
					BackupPatch(m_csFullUpdateFileName);
					ExecutePatch(m_csFullUpdateFileName, true);
				}
			}
		}

		//
		// If a product patch is available we will execute this first and 
		// the rest of the merging will take place after this patch is installed
		// Also check if product has come due to FIC, then execute it even if versions are same

		CString csFileName = m_csLocalBackupFolder + m_csProductDetails;

	
		if(CheckVersionNumber(m_csProductDetails))
		{	
			m_bDownloaded = true;
			BackupPatch(m_csProductFileName);
		}

		if(m_bProductPatch)
		{
			if(ExecutePatch(m_csProductFileName, true))
			{
				m_objRegistry.DeleteValue(CSystemInfo::m_csProductRegKey, _T("ProductPatch"), HKEY_LOCAL_MACHINE);
				m_objRegistry.DeleteValue(CSystemInfo::m_csProductRegKey, _T("AutoProductPatch"), HKEY_LOCAL_MACHINE);
			}

			AddLogEntry(_T("Finished Updating!"));
			return;
		}
	}

	m_pUpdateManager = new CUpdateManager();

	m_csDBFileNames.RemoveAll();
	BOOL bSDDatabase = CheckVersionNumber(m_csDeltaDetails);
	if(bSDDatabase)
	{
		AddLogEntry(_T("Going to wait for scanners to shut down."));
		while(true)
		{
			ShutDownMailScannerIfRunning();
			Sleep(2000);
			if(IsReadyToMerge())
			{
				break;
			}			
			else
			{
				Sleep(10000);
			}
		}
		AddLogEntry(_T("All scanners are shut down. Going Ahead."));
		m_objRegistry.Set(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess", 2, HKEY_LOCAL_MACHINE);
		MergeMaxDeltasEx();
	}

	if(m_bMaxDBMergeSuccess)
	{
		m_objRegistry.Set(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess", 3, HKEY_LOCAL_MACHINE);
		AddLogEntry(_T("Merging Success!"));
		CStringArray csarrIgnoreList;
		csarrIgnoreList.Add(L"*.tmp");
		CString csAVLiveUpdateBackup;
		csAVLiveUpdateBackup= m_objSystemInfo.m_strAppPath[0];
		csAVLiveUpdateBackup += _T(":\\AuLiveUpdate\\Data");
		bool bCopyBackUP = m_oDirectoryManager.MaxCopyDirectory(csAVLiveUpdateBackup + L"\\", m_csFolderToMonitor + _T("\\MergeTemp\\Data"), false, true, &csarrIgnoreList, NULL, true);
		bool bCopy = m_oDirectoryManager.MaxCopyDirectory(m_objSystemInfo.m_strDBPath + L"\\" + GetDBFolderName() + L"\\", m_csFolderToMonitor + _T("\\MergeTemp\\Data"), false, true, &csarrIgnoreList, NULL, true);
		if(bCopyBackUP)
		{
			AddLogEntry(_T("AuLiveUpdate BackUp Success!"), 0, 0, true, LOG_WARNING);
		}
		else
		{
			AddLogEntry(_T("AuLiveUpdate BackUp Failed!"), 0, 0, true, LOG_WARNING);
		}
		if(bCopy)
		{
			m_objRegistry.Set(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess",4, HKEY_LOCAL_MACHINE);
			if(m_pUpdateManager->IsVirusDBUpdated())
			{
				ULONG ulCount = 0;
				CString csVirusDBUpdateCount;
				m_objRegistry.Get(CSystemInfo::m_csProductRegKey, VIRUSDBUPDATECOUNT, csVirusDBUpdateCount, HKEY_LOCAL_MACHINE);
				ulCount = _ttoi(csVirusDBUpdateCount);
				ulCount++;
				csVirusDBUpdateCount.Format(_T("%u"), ulCount);
				m_objRegistry.Set(CSystemInfo::m_csProductRegKey, VIRUSDBUPDATECOUNT, csVirusDBUpdateCount, HKEY_LOCAL_MACHINE);
				AddLogEntry(_T("Virus update count set by merger: %s"), csVirusDBUpdateCount, 0, true, LOG_WARNING);
			}

			bDoProcessCleanup = FALSE;
			for(int i = 1; i <= 10; i++)
			{
				bool b1 = m_objRegistry.Set(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, m_csMaxDBVersionNo, HKEY_LOCAL_MACHINE, true);
				bool b3 = m_objRegistry.Set(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, m_objSystemInfo.m_strDBPath + L"\\" + GetDBFolderName() + L"\\", HKEY_LOCAL_MACHINE, true);
				if(b1 && b3)
				{
					CString csDBVer, csDBPath;
					b1 = m_objRegistry.Get(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, csDBVer, HKEY_LOCAL_MACHINE);
					b3 = m_objRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csDBPath, HKEY_LOCAL_MACHINE);
					if(b1 && b3)
					{
						if((csDBVer.CompareNoCase(m_csMaxDBVersionNo) == 0) && 
							(csDBPath.CompareNoCase(m_objSystemInfo.m_strDBPath + L"\\" + GetDBFolderName() + L"\\") == 0))
						{
							m_objRegistry.Set(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess",5, HKEY_LOCAL_MACHINE);
							bDoProcessCleanup = TRUE;
							CString csLogStr;
							csLogStr.Format(_T("Attempt: %i. Success setting registry: %s, %s"), i, m_csMaxDBVersionNo, m_objSystemInfo.m_strDBPath + L"\\" + GetDBFolderName() + L"\\");
							AddLogEntry(csLogStr);
							break;
						}
					}
					else
					{
						CString csLogStr;
						csLogStr.Format(_T("Attempt GET: %i. Failed getting registry: %s, %s"), i, m_csMaxDBVersionNo, m_objSystemInfo.m_strDBPath + L"\\" + GetDBFolderName() + L"\\");
						AddLogEntry(csLogStr);
					}
				}
				else
				{
					CString csLogStr;
					csLogStr.Format(_T("Attempt SET: %i. Failed setting registry: %s, %s"), i, m_csMaxDBVersionNo, m_objSystemInfo.m_strDBPath + L"\\" + GetDBFolderName() + L"\\");
					AddLogEntry(csLogStr);
				}
				Sleep(100);
			}

			
		}
		else
		{
			AddLogEntry(L"Failed to Copy From: %s, To : %s", m_csFolderToMonitor + _T("\\MergeTemp\\Data"), m_objSystemInfo.m_strDBPath + L"\\" + GetDBFolderName() + L"\\");
		}
		m_objRegistry.Set(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess",6, HKEY_LOCAL_MACHINE);
		DeleteFile(m_objSystemInfo.m_strAppPath + RESCAN_FILES_DB);
		CMaxDSrvWrapper objMaxDSrvWrapper;
		objMaxDSrvWrapper.ReloadDatabase();
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RESTARTPROTECTION, ON);

		AddLogEntry(_T("Clean UP Temp DB: %s"), m_csFolderToMonitor + _T("\\MergeTemp\\Data"), 0, true, LOG_WARNING);

		//m_oDirectoryManager.MaxCopyDirectory(m_csLocalBackupFolder + _T("Data"), m_csFolderToMonitor + _T("\\MergeTemp\\Data"), false, true, &csarrIgnoreList, NULL, true);
		m_oDirectoryManager.MaxDeleteDirectory(m_csFolderToMonitor + _T("\\MergeTemp\\Data"), NULL, false, false);
		WritePrivateProfileString(_T("Database"), _T("Version"), m_csMaxDBVersionNo, m_csLocalBackupFolder + _T("Data\\DBVersion.ini"));
		//WritePrivateProfileString(NULL, NULL, NULL, m_csLocalBackupFolder + _T("Data\\DBVersion.ini"));

		CString csDeltaPath = m_csFolderToMonitor + _T("\\Data\\");
		int iNoOFDeltas = (int)m_csDBFileNames.GetCount();
		for(int iCtr = 0; iCtr < iNoOFDeltas; iCtr++)
		{
			CString csFileName = csDeltaPath + m_csDBFileNames.GetAt(iCtr);
			DeleteFile(csFileName);
		}
		m_objRegistry.Get(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess",dwCheck, HKEY_LOCAL_MACHINE);
		//if(dwCheck == 5)
		{
			//m_oDirectoryManager.MaxDeleteDirectory(m_csFolderToMonitor + _T("\\Data"), NULL, false, false);
			m_objRegistry.Set(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess",7, HKEY_LOCAL_MACHINE);
			//m_objRegistry.DeleteValue(CSystemInfo::m_csProductRegKey, L"LiveUpdateProcess", HKEY_LOCAL_MACHINE);
		}
	}

	delete m_pUpdateManager;
	m_pUpdateManager = NULL;

	// Check for available patches and copy them in backup folder!
	if(CheckVersionNumber(m_csDatabaseDetails))
	{
		m_bDownloaded = true;
		BackupPatch(m_csDatabaseFileName);
	}
	
	if(CheckVersionNumber(m_csSDDatabaseMiniDetails))
	{
		if(m_bSDDatabaseMiniPatch)
		{
			BackupPatch(m_csSDDatabaseMiniFileName);
			ExecutePatch(m_csSDDatabaseMiniFileName, true);
		}
	}

	
	if (CheckVersionNumber(m_csVirusDetails))
	{
		m_bDownloaded = true;
		BackupPatch(m_csVirusFileName);
	}

	if (CheckVersionNumber(m_csFirewallDetails))
	{
		BackupPatch(m_csFirewallFileName);
	}

	if (CheckVersionNumber(m_csRemoveSpyDetails))
	{
		BackupPatch(m_csRemoveSpyFileName);
	}

	if (CheckVersionNumber(m_csKeyloggerDetails))
	{
		BackupPatch(m_csKeyLoggerFileName);
	}

	if (CheckVersionNumber(m_csRootkitDetails))
	{
		BackupPatch(m_csRootKitFileName);
	}


	m_csArrUpdtVerFileName.RemoveAll();
	if (CheckVersionNumber(m_csUpdateVersionDetails))
	{
		m_bDownloaded = true;
		BackupPatch(m_csArrUpdtVerFileName);
	}

	if(!m_bPartialDatabaseMerged)
	{
		CString csBackupFileName = m_csLocalBackupFolder + INI_FILE_NAME;
		CopyFile(m_csServerVersionTXT, csBackupFileName, FALSE);
		CString csDeltaVersionINI = m_csServerVersionTXT;
		CString csDeltaINI;
		csDeltaINI = INI_DELTASERVER_FILE_NAME;
		csDeltaVersionINI.Replace(INI_FILE_NAME,csDeltaINI);
		csBackupFileName.Replace(INI_FILE_NAME,csDeltaINI);
		CopyFile(csDeltaVersionINI, csBackupFileName, FALSE);
	}

	// Now start executing patchs one by one
	//AddLogEntry(_T("Pavan 2: Before Executing db patch ==> if((m_bDatabaseFullPatch) && (!m_bReceivedNewEvent))"));
	if((m_bDatabaseFullPatch) && (!m_bReceivedNewEvent))
	{
		//AddLogEntry(_T("Pavan 2: Before Executing db patch ==> if(ExecutePatch(m_csDatabaseFileName, true))"));
		if(ExecutePatch(m_csDatabaseFileName, true))
		{
			m_objRegistry.DeleteValue(CSystemInfo::m_csProductRegKey, _T("DatabasePatch"), HKEY_LOCAL_MACHINE);
			m_objRegistry.DeleteValue(CSystemInfo::m_csProductRegKey, _T("AutoDatabasePatch"), HKEY_LOCAL_MACHINE);
			m_objRegistry.Set(CSystemInfo::m_csProductRegKey, _T("EPMD5UPDATE"), 0, HKEY_LOCAL_MACHINE);
			m_objRegistry.Set(CSystemInfo::m_csProductRegKey, _T("EPMD5UPDATETMP"), 0, HKEY_LOCAL_MACHINE);
		}
	}

	if(m_bUpdateVersionPatch)
	{
		ExecutePatch(m_csArrUpdtVerFileName, true);
	}

	if ((m_bVirusPatch) && (!m_bReceivedNewEvent))
	{
		ExecutePatch(m_csVirusFileName, true);
	}
	if ((m_bFirewallPatch) && (!m_bReceivedNewEvent))
	{
		ExecutePatch(m_csFirewallFileName, true);
	}
	if ((m_bRemoveSpyPatch) && (!m_bReceivedNewEvent))
	{
		ExecutePatch(m_csRemoveSpyFileName, true);
	}
	if ((m_bKeyLoggerPatch) && (!m_bReceivedNewEvent))
	{
		ExecutePatch(m_csKeyLoggerFileName, true);
	}
	if ((m_bRootKitPatch) && (!m_bReceivedNewEvent))
	{
		ExecutePatch(m_csRootKitFileName, true);
	}

	if(m_bDatabaseFullPatch || m_bMaxDBMergeSuccess || m_bVirusPatch || m_bFirewallPatch || m_bUpdateVersionPartial ||
		m_bRemoveSpyPatch || m_bKeyLoggerPatch || m_bRootKitPatch || m_bFirstPriorityPatch || m_bUpdateVersionPatch ||
		m_bShowAutoUpdateSuccessMsg)
	{
		m_bShowAutoUpdateSuccessMsg = true;
		if(!m_bReceivedNewEvent && m_bShowAutoUpdateSuccessMsg)
		{
			if(m_bDatabaseFullPatch || m_bVirusPatch || m_bRemoveSpyPatch || m_bKeyLoggerPatch || 
				m_bRootKitPatch || m_bFirstPriorityPatch)
			{
				DeleteFile(m_objSystemInfo.m_strAppPath + RESCAN_FILES_DB);
				CMaxDSrvWrapper objMaxDSrvWrapper;
				objMaxDSrvWrapper.ReloadDatabase();
				PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RESTARTPROTECTION, ON);
			}

			ShowAutoUpdateSuccessDlg();
			m_bShowAutoUpdateSuccessMsg = false;
		}
	}

	if((m_bPartialDatabaseMerged) && (!m_bReceivedNewEvent))
	{
		AddLogEntry(L"##### Partial database is merged! Skipped copying serverversion.txt to backup folder!", 0, 0, true, LOG_WARNING);
		DeleteFile(m_csServerVersionTXT);
		CString csDeltaVersionINI = m_csServerVersionTXT;
		CString csDeltaINI;
		csDeltaINI = INI_DELTASERVER_FILE_NAME;
		csDeltaVersionINI.Replace(INI_FILE_NAME,csDeltaINI);
		DeleteFile(csDeltaVersionINI);
		////m_oDirectoryManager.MaxDeleteDirectory(m_csFolderToMonitor + _T("\\Data"), NULL, false, false);
	}

	if(m_bUpdateVersionPartial)
	{
		AddLogEntry(L"##### Partial update version patches applied!", 0, 0, true, LOG_WARNING);
	}

	//bDoProcessCleanup set it to true if we don't want to perform cleanup 
	if(!m_bReceivedNewEvent && bDoProcessCleanup)
	{
		ProcessCleanups();
	}

	AddLogEntry(_T("Finished Updating!"));
}

void CMaxProductMerger::BackupPatch(const CString &csPatchFileName)
{
	CString csFileName = m_csFolderToMonitor + BACK_SLASH + csPatchFileName;
	CString csBackupFileName = m_csLocalBackupFolder + csPatchFileName;
	
	
	if(m_objEnumProcess.IsProcessRunning(csBackupFileName, true, true, true))
	{
		AddLogEntry(_T(">>>>> Terminated Already Running Patch: %s"), csFileName, 0, true, LOG_WARNING);
	}

	AddLogEntry(_T(">>>>> Backup Patch: %s -> %s"), csFileName, csBackupFileName, true, LOG_WARNING);
	

	if(CopyFile(csFileName, csBackupFileName, FALSE))
	{
		AddLogEntry(_T(">>>>> Successfully Backedup Patch: %s"), csFileName, 0, true, LOG_WARNING);
	}
	else
	{
		AddLogEntry(_T(">>>>> Failed To Backup Patch: %s"), csFileName, 0, true, LOG_WARNING);
	}

}

void CMaxProductMerger::BackupPatch(const CStringArray& csArrFileNames)
{
	for(INT_PTR i = 0, iTotal = csArrFileNames.GetCount(); i < iTotal; i++)
	{
		BackupPatch(csArrFileNames.GetAt(i));
	}
}

bool CMaxProductMerger::ExecutePatch(const CString &csPatchFileName, bool bWaitForUIToClose)
{
	CString csFileName = m_csFolderToMonitor + BACK_SLASH + csPatchFileName;
	CString csBackupFileName = m_csLocalBackupFolder + csPatchFileName;


	if(bWaitForUIToClose)
	{
		ShutDownMailScannerIfRunning();
		if(!IsReadyToInstall())
		{
			AddLogEntry(_T("Not ready to install skipping: %s"), csPatchFileName, 0, true, LOG_WARNING);
			return false;
		}
	}

	AddLogEntry(_T(">>>>> Executed Patch: %s"), csBackupFileName, 0, true);
	if(m_objExecutor.ExecuteCommandWithWait(csBackupFileName, _T("\"") + csBackupFileName + _T("\" /VERYSILENT /NORESTART")))
	{
		AddLogEntry(_T(">>>>> Successfully Executed Patch: %s"), csBackupFileName, 0, true, LOG_WARNING);
		return true;
	}
	else
	{
		AddLogEntry(_T(">>>>> Failed To Execute Patch: %s"), csBackupFileName, 0, true, LOG_WARNING);
		return false;
	}
}

bool CMaxProductMerger::ExecutePatch(const CStringArray &csPatchFileNames, bool bWaitForUIToClose)
{
	bool bFinalReturnValue = true;

	for(INT_PTR i = 0, iTotal = csPatchFileNames.GetCount(); i < iTotal; i++)
	{
		bFinalReturnValue = ExecutePatch(csPatchFileNames.GetAt(i), bWaitForUIToClose)? bFinalReturnValue: false;
	}

	return bFinalReturnValue;
}

bool CMaxProductMerger::IsReadyToInstall()
{
	bool bRet = false;
	while(!m_bReceivedNewEvent)
	{

		if (m_objEnumProcess.IsProcessRunning(UI_EXENAME, false, false, false)
			|| m_objEnumProcess.IsProcessRunning(_T("AUUSB.EXE"), false, false, false)
			|| m_objEnumProcess.IsProcessRunning(MAX_SCANNER, false, false, false))
		{
			bRet = false;
		}
		else
		{
			bRet = true;
		}
		
		if(bRet)
		{
			bRet = true;
			AddLogEntry(_T(">>>>> UI/Scanner/USBScan is not running! Ready To Install Patch!"), 0, 0, true, LOG_WARNING);
			return bRet;	
		}
		else
		{
			Sleep(10000);
			AddLogEntry(_T("##### UI/Scanner/USBScan is running! Wait for them to finish!"), 0, 0, true, LOG_WARNING);
		}
	}
	return bRet;
}

bool CMaxProductMerger::IsReadyToMerge()
{
	bool bRet = false;
	//while(true)
	//{		
		CString	csMutexName	= _T("Global\\AU_SCANNER_ON");
		HANDLE	hMutex		= NULL;
		hMutex				= OpenMutexW(SYNCHRONIZE, FALSE, csMutexName);
		if(hMutex == NULL)
		{
			bRet = true;
			AddLogEntry(_T(">>>>> AuScanner is not running! Ready To Merge Delta!"), 0, 0, true, LOG_WARNING);
			return bRet;	
		}
		else
		{
			AddLogEntry(_T("##### AuScanner is running! Wait for them to finish!"), 0, 0, true, LOG_WARNING);
			if (hMutex != NULL)
			{
				//WaitForSingleObject(hMutex, INFINITE);
				//::ReleaseMutex(hMutex);
				CloseHandle(hMutex);
			}
			hMutex = NULL;
		}
	return bRet;
}

bool CMaxProductMerger::ReadAllSectionNameFromIni()
{
	CFile oFile;
	CFileException ex;
	if(!oFile.Open(m_csServerVersionTXT, CFile::modeWrite, &ex))// generated and the update begins, the serverversion is not 
	{															// completely ready at this moment, hence we try to open
																// the file with write access until we are successfull!
		AddLogEntry(_T("##### File not ready: %s!"), m_csServerVersionTXT, 0, true, LOG_ERROR);
		return false;
	}
	oFile.Close();

	m_csDeltaDetails = m_objCommonFunctions.GetSectionName(_T("DELTADETAILS"));
	m_csProductDetails = m_objCommonFunctions.GetSectionName(_T("PRODUCTKEY"));
	m_csDatabaseDetails = m_objCommonFunctions.GetSectionName(_T("DATABASEKEY"));
	m_csUpdateVersionDetails = m_objCommonFunctions.GetSectionName(_T("UPDATEVERSION"));
	m_csSDDatabaseMiniDetails = m_objCommonFunctions.GetSectionName(_T("MINIDATABASEKEY"));

	m_csVirusDetails = m_objCommonFunctions.GetSectionName(_T("VIRUSKEY"));
	m_csFirewallDetails = m_objCommonFunctions.GetSectionName(_T("FIREWALLKEY"));
	m_csRemoveSpyDetails = m_objCommonFunctions.GetSectionName(_T("REMOVESPYKEY"));
	m_csKeyloggerDetails = m_objCommonFunctions.GetSectionName(_T("KEYLOGGERSPYKEY"));
	m_csRootkitDetails = m_objCommonFunctions.GetSectionName(_T("ROOTKITSPYKEY"));

	m_csFirstPriorityDetails = m_objCommonFunctions.GetSectionName(_T("SDFIRSTPRIORITYKEY"));
	m_csFullUpdateDetails = m_objCommonFunctions.GetSectionName(_T("SDUPDATEKEY"));
	return true;
}


void CMaxProductMerger::CopyDBFilesToData(CString csDbPath, CString csMergePath)
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
					CString csDescPath = m_csFolderToMonitor;
					iPos = csDescPath.ReverseFind('\\');
					if(iPos != -1)
					{
						csDescPath = csDescPath.Left(iPos);
						csDescPath = csDescPath + _T("\\YrScanDB.yar");
						CopyFile(csSrcPath,csDescPath, false);

					}
					DeleteFile(csSrcPath);

					if(!csYaraVer.IsEmpty())
					{
						m_objRegistry.Set(CSystemInfo::m_csProductRegKey, _T("YrScanVersion"), csYaraVer, HKEY_LOCAL_MACHINE);
					}

				}
				if(iPosIcon != -1)
				{
					CString csSrcPath = csDbPath + _T("\\")+ csFile;

					CString csDescPath = m_csFolderToMonitor;
					iPos = csDescPath.ReverseFind('\\');
					if(iPos != -1)
					{
						csDescPath = csDescPath.Left(iPos);
						csDescPath = csDescPath + _T("\\IconDB.DB");
						CopyFile(csSrcPath,csDescPath, false);
					}
					DeleteFile(csSrcPath);
				}
			}
			else
			{
				CString csSrcPath = csDbPath + _T("\\")+ csFile;
				CString csDescPath = csMergePath + _T("\\")+ csFile;
				CopyFile(csSrcPath,csDescPath, false);
			}
		}
	}
	objFinder.Close();
}
void CMaxProductMerger::MergeMaxDeltasEx()
{
	
	m_bMaxDBMergeSuccess = false;
	m_csMaxDBVersionNo = _T("");
	bool bRetVal = true;
	CString csFileToMerge;
	CStringArray csarrIgnoreList;

	CString csMaxDBPath;
	m_objRegistry.Get(m_objSystemInfo.m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);

	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, m_csMaxDBVersionNo, HKEY_LOCAL_MACHINE);
	
	m_oDirectoryManager.MaxDeleteDirectory(m_csFolderToMonitor + _T("\\MergeTemp\\Data"), NULL, false, false);
	m_oDirectoryManager.MaxCreateDirectory(m_csFolderToMonitor + _T("\\MergeTemp\\Data"));
	
	HANDLE	hCopyThread = NULL;
	DWORD	dwCopyThreadID  = 0x00;
	hCopyThread = CreateThread(NULL,0x00,(LPTHREAD_START_ROUTINE)CopyDeltaThread,(LPVOID)this,0x00,&dwCopyThreadID);
	if (hCopyThread != NULL)
	{
		SetThreadPriority(hCopyThread, THREAD_PRIORITY_ABOVE_NORMAL);
	}
	
	CString csDeltaPath = m_csFolderToMonitor + _T("\\Data\\");
	int iNoOFDeltas = (int)m_csDBFileNames.GetCount();
	
	WaitForSingleObject(hCopyThread, -1);
	if (hCopyThread != NULL)
	{
		CloseHandle(hCopyThread);
	}
	hCopyThread = NULL;

	if(m_bCopySuccess)
	{
		int iThreadCount = 0; 
		CString csMergePath = m_csFolderToMonitor + _T("\\MergeTemp\\Data");
		CString csSourcePath;
		
		for(int iCtr = 0; iCtr < iNoOFDeltas; iCtr++)
		{
			csFileToMerge = m_csDBFileNames.GetAt(iCtr);
			csSourcePath = csDeltaPath + csFileToMerge + _T("e");
			AddLogEntry(L"Delta Merging: %s%s", csDeltaPath, csFileToMerge);
			if(m_pUpdateManager->ExtractDeltaFile(csDeltaPath + csFileToMerge))
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
			AddLogEntry(L"##### Database version : %s", m_csMaxDBVersionNo);
		}
	}

}

void CMaxProductMerger::MergeMaxDeltas()
{
	m_bMaxDBMergeSuccess = false;
	m_csMaxDBVersionNo = _T("");
	bool bRetVal = true;
	CString csFileToMerge;
	CStringArray csarrIgnoreList;

	CString csMaxDBPath;
	m_objRegistry.Get(m_objSystemInfo.m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);

	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, m_csMaxDBVersionNo, HKEY_LOCAL_MACHINE);
	
	m_oDirectoryManager.MaxDeleteDirectory(m_csFolderToMonitor + _T("\\MergeTemp\\Data"), NULL, false, false);
	m_oDirectoryManager.MaxCreateDirectory(m_csFolderToMonitor + _T("\\MergeTemp\\Data"));
	
	HANDLE	hCopyThread = NULL;
	DWORD	dwCopyThreadID  = 0x00;
	hCopyThread = CreateThread(NULL,0x00,(LPTHREAD_START_ROUTINE)CopyDeltaThread,(LPVOID)this,0x00,&dwCopyThreadID);
	if (hCopyThread != NULL)
	{
		SetThreadPriority(hCopyThread, THREAD_PRIORITY_ABOVE_NORMAL);
	}

	CString csDeltaPath = m_csFolderToMonitor + _T("\\Data\\");
	int iNoOFDeltas = (int)m_csDBFileNames.GetCount();
	

	for(int iCtr = 0; iCtr < iNoOFDeltas; iCtr++)
	{
		csFileToMerge = m_csDBFileNames.GetAt(iCtr);
		AddLogEntry(L"Delta Extraction : %s%s", csDeltaPath, csFileToMerge);
		if(m_pUpdateManager->ExtractDeltaFile(csDeltaPath + csFileToMerge))
		{
		}
		else
		{
			AddLogEntry(L"##### Extract Delta Failed: %s, %s", csDeltaPath, csFileToMerge);
			bRetVal = false;
			break;
		}
	}

	WaitForSingleObject(hCopyThread, -1);
	if (hCopyThread != NULL)
	{
		CloseHandle(hCopyThread);
	}
	hCopyThread = NULL;

	if(m_bCopySuccess)
	{
		int iThreadCount = 0;
		for(int iCtr = 0; iCtr < iNoOFDeltas; iCtr++)
		{
			csFileToMerge = m_csDBFileNames.GetAt(iCtr);
			AddLogEntry(L"Delta Merging: %s%s", csDeltaPath, csFileToMerge);
			if(m_pUpdateManager->ExtractDeltaFileEx(csDeltaPath + csFileToMerge))
			{
				HANDLE	hThread = NULL;
				DWORD	dwThreadID  = 0x00;
				
				hThread = CreateThread(NULL,0x00,(LPTHREAD_START_ROUTINE)BlackDBMergerThread,(LPVOID)this,0x00,&dwThreadID);
				if (hThread != NULL)
				{
					SetThreadPriority(hThread, THREAD_PRIORITY_BELOW_NORMAL);
				}
				else
				{
					AddLogEntry(L"BlackDBMergerThread Creation Failed !!!");	
				}
				
				for(iThreadCount = 0; iThreadCount < MERGING_THREAD_COUNT ; iThreadCount++)
				{
					if (iThreadCount != 0x05)
					{
						if(!m_pUpdateManager->MergeDBType(iThreadCount, true))
						{
							CString csTemp;
							csTemp.Format(L"%d", iThreadCount); 
							AddLogEntry(L"##### MergeDBType Failed for: %s", csTemp);
						}
					}
				}
				
				WaitForSingleObject(hThread,-1);
				if (hThread != NULL)
				{
					CloseHandle(hThread);
				}
				hThread = NULL;
				m_oDirectoryManager.MaxDeleteDirectory(csDeltaPath + csFileToMerge + _T("e"), true);
			}
			else
			{
				AddLogEntry(L"##### Extract Delta Failed: %s, %s", csDeltaPath, csFileToMerge);
				bRetVal = false;
				break;
			}
		}

		/*-----------------------------------------------------------------------------*/

		
		for(iThreadCount = 0; iThreadCount < MERGING_THREAD_COUNT ; iThreadCount++)
		{
			if(!m_pUpdateManager->SaveDBType(m_csFolderToMonitor + _T("\\MergeTemp\\Data\\"), iThreadCount, true))
			{
				CString csTemp;
				csTemp.Format(L"%d",iThreadCount); 
				AddLogEntry(L"##### SaveDBType Failed for: %s", csTemp, 0, true, LOG_WARNING);
				bRetVal = false;
				break;
			}
		}
		
		m_pUpdateManager->ResetAllMembers();
		//int iThreadCount = 0;
		for(iThreadCount = 0; iThreadCount < MERGING_THREAD_COUNT ; iThreadCount++)
		{
			if(!m_pUpdateManager->LoadDBType(m_csFolderToMonitor + _T("\\MergeTemp\\Data\\"), iThreadCount, 0, true))
			{
				CString csTemp;
				csTemp.Format(L"%d", iThreadCount); 
				AddLogEntry(L"##### LoadDBType Failed in checking for: %s", csTemp);
				bRetVal = false;
				//set autodatabasepatch flag
				break;
			}
		}
		m_pUpdateManager->ResetAllMembers();
	}

	m_bMaxDBMergeSuccess = bRetVal;
	if(m_bMaxDBMergeSuccess)
	{
		CDirectoryManager objDirMgr;
		objDirMgr.MaxDeleteDirectory(m_csFolderToMonitor + _T("\\MergeTemp\\Data\\*.tmp"), true, true);

		if(csFileToMerge.GetLength() > 0)
		{
			m_csMaxDBVersionNo = m_pUpdateManager->GetDeltaVersion(csFileToMerge);
			AddLogEntry(L"##### Database version : %s", m_csMaxDBVersionNo);
		}
	}
}

int CMaxProductMerger::CheckExistance(const CString &csSectionName, LPCTSTR szKeyName, const CString &csFileName, int iType)
{
	CString csFileToCheck;
	if(iType == 0)			// Executables
		csFileToCheck = m_csFolderToMonitor + BACK_SLASH + csFileName;
	else if(iType == 1)		// Max Data
		csFileToCheck = m_csFolderToMonitor + _T("\\Data\\") + csFileName;
	else
	{
		AddLogEntry(_T("##### Invalid Type: %s"), csFileName);
		return 0;
	}

	if(_waccess(csFileToCheck, 0) != 0)
	{
		if(iType == 0)			// Executables
		{
			AddLogEntry(_T("----- Missing File: %s"), csFileToCheck);
			csFileToCheck = m_csLocalBackupFolder + csFileName;
		}
	}

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
			AddLogEntry(_T("##### Skip File   : %s"), csFileToCheck, 0, true, LOG_WARNING);
			return 2;
		}

		CString csFileMD5;
		bool bMD5Status = GetMD5Signature(csFileToCheck, csFileMD5);
		if(bMD5Status && (csINIMD5.CompareNoCase(csFileMD5) == 0))
		{
			AddLogEntry(_T("##### Found File  : %s"), csFileToCheck, 0, true, LOG_WARNING);
			return 1;
		}
		else
		{
			AddLogEntry(_T("----- MD5 Failed  : %s - %s"), csFileToCheck, csINIMD5 + _T(" : ") + csFileMD5, true, LOG_WARNING);
			return 0;
		}
	}
	AddLogEntry(_T("----- Missing File: %s"), csFileToCheck, 0, true, LOG_WARNING);
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: IsFileValidForThisProduct
In Parameters	: const CString& csSectionName
Out Parameters	: bool
Purpose			: check ProdID in given section and see if this is matching
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxProductMerger::IsFileValidForThisProduct(const CString& csSectionName)
{
	bool bValid = false;
	CString csServerProductNumberList;

	GetPrivateProfileString(csSectionName, _T("ProdID"), BLANKSTRING, csServerProductNumberList.GetBuffer(200), 200, m_csServerVersionTXT);
	csServerProductNumberList.ReleaseBuffer();

	if((BLANKSTRING != csServerProductNumberList) && (-1 != csServerProductNumberList.Find(CSystemInfo::m_csProductNumber)))
	{
		bValid = true;
	}

	return bValid;
}

BOOL CMaxProductMerger::CheckVersionNumber(const CString &csSectionName)
{
	if(csSectionName == _T(""))
	{
		return FALSE;
	}

	AddLogEntry(_T("CheckVersion :") + csSectionName);
	CString csLocalVersion = _T("0");
	CString csServerVersion = _T("");
	if(csSectionName == m_csDeltaDetails)
	{
		GetPrivateProfileString(csSectionName, _T("Max_Ver"), _T("0"), csServerVersion.GetBuffer(100), 100, m_csServerVersionTXT);
		csServerVersion.ReleaseBuffer();
	}
	else if(csSectionName == m_csUpdateVersionDetails)
	{
		GetPrivateProfileString(csSectionName, _T("Max_Ver"), _T("0"), csServerVersion.GetBuffer(100), 100, m_csServerVersionTXT);
		csServerVersion.ReleaseBuffer();
	}
	else
	{
		GetPrivateProfileString(csSectionName, _T("VersionNo"), _T("0"), csServerVersion.GetBuffer(100), 100, m_csServerVersionTXT);
		csServerVersion.ReleaseBuffer();
	}

	CString sRegKey;
	if(csSectionName == m_csProductDetails)
	{
		sRegKey = PRODUCTVERREGKEY;
	}
	else if(csSectionName == m_csDatabaseDetails || csSectionName == m_csDeltaDetails)
	{
		sRegKey = DATABASEREGKEY;
	}
	else if(csSectionName == m_csRemoveSpyDetails)
	{
		sRegKey = REMOVESPYREGKEY;
	}
	else if(csSectionName == m_csKeyloggerDetails)
	{
		sRegKey = KEYLOGGERREGKEY;
	}
	else if(csSectionName == m_csRootkitDetails)
	{
		sRegKey = ROOTKITREGKEY;
	}
	else if(csSectionName == m_csVirusDetails)
	{
		sRegKey = VIRUSREGKEY;
	}
	else if(csSectionName == m_csFirewallDetails)
	{
		sRegKey = FIREWALLREGKEY;
	}
	else if(csSectionName == m_csFirstPriorityDetails)
	{
		sRegKey = FIRSTPRIOTYREGKEY;
	}
	else if(csSectionName == m_csUpdateVersionDetails)
	{
		sRegKey = UPDATEVERSION;
	}
	else if(csSectionName == m_csSDDatabaseMiniDetails)
	{
		sRegKey = MINIDBREGKEY;
	}

	if(sRegKey.GetLength() == 0)
	{
		return FALSE;
	}

	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, sRegKey, csLocalVersion, HKEY_LOCAL_MACHINE);

	AddLogEntry(_T("Local version :") + csLocalVersion);
	AddLogEntry(_T("Server version :") + csServerVersion);

	if( csSectionName == m_csProductDetails || csSectionName == m_csRemoveSpyDetails ||
		csSectionName == m_csKeyloggerDetails || csSectionName == m_csRootkitDetails || 
		csSectionName == m_csVirusDetails || csSectionName == m_csFirewallDetails || 
		csSectionName == m_csDatabaseDetails || csSectionName == m_csFirstPriorityDetails ||
		csSectionName == m_csSDDatabaseMiniDetails)
	{
		if(csSectionName == m_csProductDetails)
			m_csProductFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csServerVersionTXT);

		csLocalVersion.Replace(_T("."), _T(""));
		csServerVersion.Replace(_T("."), _T(""));

		DWORD dwLocalVer = _wtoi(csLocalVersion);
		DWORD dwServerVer = _wtoi(csServerVersion);
		if(dwLocalVer < dwServerVer)
		{
			
			if(csSectionName == m_csDatabaseDetails)
			{
				AddLogEntry(m_csDatabaseFileName);
				m_csDatabaseFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csServerVersionTXT);
				m_bDatabaseFullPatch = (CheckExistance(csSectionName, _T("MD5"), m_csDatabaseFileName, 0) ? true : false);

			}
			else if(csSectionName == m_csRemoveSpyDetails)
			{
				m_csRemoveSpyFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csServerVersionTXT);
				m_bRemoveSpyPatch = (CheckExistance(csSectionName, _T("MD5"), m_csRemoveSpyFileName, 0) ? true : false);
			}
			else if(csSectionName == m_csKeyloggerDetails)
			{
				m_csKeyLoggerFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csServerVersionTXT);
				m_bKeyLoggerPatch = (CheckExistance(csSectionName, _T("MD5"), m_csKeyLoggerFileName, 0) ? true : false);
			}
			else if(csSectionName == m_csRootkitDetails)
			{
				m_csRootKitFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csServerVersionTXT);
				m_bRootKitPatch = (CheckExistance(csSectionName, _T("MD5"), m_csRootKitFileName, 0) ? true : false);
			}
			else if(csSectionName == m_csVirusDetails)
			{
				m_csVirusFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csServerVersionTXT);
				m_bVirusPatch = (CheckExistance(csSectionName, _T("MD5"), m_csVirusFileName, 0) ? true : false);
			}
			else if(csSectionName == m_csFirewallDetails)
			{
				m_csFirewallFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csServerVersionTXT);
				m_bFirewallPatch = (CheckExistance(csSectionName, _T("MD5"), m_csFirewallFileName, 0) ? true : false);
			}
			else if(csSectionName == m_csFirstPriorityDetails)
			{
				m_csFirstPriorityFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csServerVersionTXT);
				m_bFirstPriorityPatch = (CheckExistance(csSectionName, _T("MD5"), m_csFirstPriorityFileName, 0) ? true : false);
			}
			else if(csSectionName == m_csProductDetails)
			{
				m_bProductPatch = (CheckExistance(csSectionName, _T("MD5"), m_csProductFileName, 0) ? true : false);
			}
			else if(csSectionName == m_csSDDatabaseMiniDetails)
			{
				m_csSDDatabaseMiniFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csServerVersionTXT);
				m_bSDDatabaseMiniPatch = (CheckExistance(csSectionName, _T("MD5"), m_csSDDatabaseMiniFileName, 0) ? true : false);
			}

			return TRUE;
		}
		else if(csSectionName == m_csProductDetails)
		{
			
			DWORD dwValue1 = 0, dwValue2 = 0;

			m_objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("ProductPatch"), dwValue1, HKEY_LOCAL_MACHINE);
			m_objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("AutoProductPatch"), dwValue2, HKEY_LOCAL_MACHINE);
			if(1 == dwValue1 || 1 == dwValue2)
			{
				m_bProductPatch = (CheckExistance(csSectionName, _T("MD5"), m_csProductFileName, 0) ? true : false);
				return m_bProductPatch;
			}
		}
		else if(csSectionName == m_csDatabaseDetails)
		{
			//AddLogEntry(_T("Pavan : CheckversionNo"));
			DWORD dwValue1 = 0, dwValue2 = 0;

			m_objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("DatabasePatch"), dwValue1, HKEY_LOCAL_MACHINE);
			m_objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("AutoDatabasePatch"), dwValue2, HKEY_LOCAL_MACHINE);
			if(1 == dwValue1 || 1 == dwValue2)
			{
				AddLogEntry(_T("Auto Database Patch is TRUE !!!"), 0, 0, true, LOG_WARNING);
				AddLogEntry(m_csDatabaseFileName);
				m_csDatabaseFileName = m_objCommonFunctions.GetFileName(csSectionName, m_csServerVersionTXT);
				m_bDatabaseFullPatch = (CheckExistance(csSectionName, _T("MD5"), m_csDatabaseFileName, 0) ? true : false);
				if (m_bDatabaseFullPatch)
				{
					m_bDownloaded = true;
					
				}
				
				return m_bDatabaseFullPatch;
			}
		}
	}
	else if(csSectionName == m_csDeltaDetails)
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
	else if(csSectionName == m_csUpdateVersionDetails)
	{
		if(!csLocalVersion.Replace(_T("."), _T("")))
		{
			AddLogEntry(_T("Invalid local version no for UV"));
			return FALSE;
		}

		if(!csServerVersion.Replace(_T("."), _T("")))
		{
			AddLogEntry(_T("Invalid server max version no for UV"));
			return FALSE;
		}

		DWORD dwLocalVer = _wtoi(csLocalVersion);
		DWORD dwServerVer = _wtoi(csServerVersion);

		if(dwLocalVer < dwServerVer)
		{
			m_bDownloaded = true;
			DWORD dwServerProductVersion = 0, dwLocalProductVersion = 0;
			CString csLocalProductVersion = BLANKSTRING, csServerProductVersion = BLANKSTRING;

			m_objRegistry.Get(CSystemInfo::m_csProductRegKey, PRODUCTVERREGKEY, csLocalProductVersion, HKEY_LOCAL_MACHINE);
			GetPrivateProfileString(m_csProductDetails, _T("VersionNo"), _T("0.0.0.0"), csServerProductVersion.GetBuffer(100), 100, m_csServerVersionTXT);
			csServerProductVersion.ReleaseBuffer();

			if(!csServerProductVersion.Replace(_T("."), _T("")))
			{
				AddLogEntry(_T("Invalid product version no in ServerVersion"));
			}

			if(!csLocalProductVersion.Replace(_T("."), _T("")))
			{
				AddLogEntry(_T("Invalid local product version in registry"));
			}

			dwServerProductVersion = _wtoi(csServerProductVersion);
			dwLocalProductVersion = _wtoi(csLocalProductVersion);

			if(dwLocalProductVersion >= dwServerProductVersion)
			{
				bool bIs64Bit = false;
				int iMaxUpdateVersions = 0, iVerDiff = 0;
				CString csUVSecName, csUVFileName, csUVMD5, csUpdateVersionFileName;

				bIs64Bit = -1 != csSectionName.Find(_T("x64"));
				iMaxUpdateVersions = GetPrivateProfileInt(csSectionName, _T("Max_Updates"), 0, m_csServerVersionTXT);
				if(0 == iMaxUpdateVersions)
				{
					//20 should be a good number for maximum number of exe patches to be executed at one go
					iMaxUpdateVersions = 20;
				}

				iVerDiff = dwServerVer - dwLocalVer;
				iVerDiff = iVerDiff > iMaxUpdateVersions? iMaxUpdateVersions: iVerDiff;

				for(int i = 1; i <= iVerDiff; i++)
				{
					if(bIs64Bit)
					{
						csUVSecName.Format(_T("UPD_%ux64"), dwLocalVer + i);
					}
					else
					{
						csUVSecName.Format(_T("UPD_%u"), dwLocalVer + i);
					}

					csUVSecName.Insert(4 + 1, _T("."));
					csUVSecName.Insert(4 + 3, _T("."));
					csUVSecName.Insert(4 + 5, _T("."));
					csUVFileName.Format(_T("%s.exe"), csUVSecName);

					GetPrivateProfileString(csUVSecName, _T("md5"), _T("00"), csUVMD5.GetBuffer(100), 100, m_csServerVersionTXT);
					csUVMD5.ReleaseBuffer();

					csUpdateVersionFileName = csUVSecName + _T(".exe");
					if(IsFileValidForThisProduct(csUVSecName))
					{
						AddLogEntry(_T("###UV File Name: %s"), csUpdateVersionFileName);
						if(!CheckExistance(csUVSecName, _T("md5"), csUpdateVersionFileName, 0))
						{
							m_bUpdateVersionPartial = true;
							//break;	// required update version patch files are missing
						}
						else
						{
							m_csArrUpdtVerFileName.Add(csUpdateVersionFileName);
						}
					}
					else
					{
						AddLogEntry(_T("###UV File Skipped, N/A: %s"), csUpdateVersionFileName);
					}
				}

				if(m_csArrUpdtVerFileName.GetCount() > 0)
				{
					m_bUpdateVersionPatch = true;
					return TRUE;
				}
				else
				{
					m_bUpdateVersionPatch = m_bUpdateVersionPartial = false;
				}
			}
		}
	}

	return FALSE;
}

bool CMaxProductMerger::GetMD5Signature(const CString &csFileName, CString &csMD5)
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

void CMaxProductMerger::ShowAutoUpdateSuccessDlg()
{
	/// New changes for Delta Full Update
	CString csLocalVersion = _T("0");
	CString csServerVersion = _T("");
	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, csLocalVersion, HKEY_LOCAL_MACHINE);
	GetPrivateProfileString(m_csDeltaDetails, _T("Max_Ver"), _T("0"), csServerVersion.GetBuffer(100), 100, m_csServerVersionTXT);
	csServerVersion.ReleaseBuffer();
	csLocalVersion.Replace(_T("."), _T(""));
	csServerVersion.Replace(_T("."), _T(""));
	DWORD dwLocalVer = _wtoi(csLocalVersion);
	DWORD dwServerVer = _wtoi(csServerVersion);
	CString csPartiallyUpdate=_T("UPDATED");
	if(dwServerVer>dwLocalVer)
	{
		csPartiallyUpdate = _T("PARTIALLYUPDATE");
	}
	///
	CString csCnt;
	GetPrivateProfileString(SUMMARY,WORMCOUNTS,BLANKSTRING,csCnt.GetBuffer(MAX_PATH),MAX_PATH,CSystemInfo ::m_strAppPath + _T("\\") + (CString)WORMSCOUNTINI);
	csCnt.ReleaseBuffer();

	CString csAppPath = CSystemInfo ::m_strAppPath;
	csAppPath += _T("\\");
	csAppPath += ACT_MON_TRAY_EXE;
	CString csParam(_T("-"));
	csParam += CSystemInfo::m_csProductName;

	CString csUPD = L"UPD";
	csParam += _T(";") + csUPD + _T(";UPDATESUCCESS;") + csCnt +_T(";HYPERLINKFALSE;")+csPartiallyUpdate;

	CExecuteProcess objExecuteProcess;
	objExecuteProcess.StartProcessWithToken(csAppPath, csParam, EXPLORE_EXE);
}

void CMaxProductMerger::ProcessCleanups()
{
	AddLogEntry(_T("In ProcessCleanups!"), 0, 0, true, LOG_WARNING);
	CString csFolder = m_csFolderToMonitor + BACK_SLASH;
	DeleteFile(csFolder + m_csFullUpdateFileName);
	DeleteFile(csFolder + m_csFirstPriorityFileName);
	DeleteFile(csFolder + m_csDatabaseFileName);
	DeleteFile(csFolder + m_csVirusFileName);
	DeleteFile(csFolder + m_csFirewallFileName);
	DeleteFile(csFolder + m_csRemoveSpyFileName);
	DeleteFile(csFolder + m_csKeyLoggerFileName);
	DeleteFile(csFolder + m_csRootKitFileName);
	DeleteFile(csFolder + m_csProductFileName);

	for(INT_PTR i = 0, iTotal = m_csArrUpdtVerFileName.GetCount(); i < iTotal; i++)
	{
		AddLogEntry(_T("In ProcessCleanups, del uv file: %s"), csFolder + m_csArrUpdtVerFileName.GetAt(i), 0, true, LOG_WARNING);
		DeleteFile(csFolder + m_csArrUpdtVerFileName.GetAt(i));
	}

	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, m_csMaxDBVersionNo, HKEY_LOCAL_MACHINE);
	CString csDBFolderName = GetDBFolderName();
	if(csDBFolderName.GetLength() > 0)
	{
		AddLogEntry(_T("Clean Up: %s, IgnorePath: %s"), m_objSystemInfo.m_strDBPath, csDBFolderName);
		m_oDirectoryManager.MaxDeleteDirectory(m_objSystemInfo.m_strDBPath, csDBFolderName, true, false);
		m_csMaxDBVersionNo = _T("");
	}
	AddLogEntry(L"##### Clean Up: %s", m_csServerVersionTXT);
	DeleteFile(m_csServerVersionTXT);
}

bool CMaxProductMerger::PostMessageToProtection(UINT WM_Message, UINT ActMon_Message, UINT uStatus)
{
	bool bReply = true;
	AM_MESSAGE_DATA amMsgData={0};
	amMsgData.dwMsgType = WM_Message;
	amMsgData.dwProtectionType = ActMon_Message;
	amMsgData.bProtectionStatus = (BYTE)uStatus;
	CMaxCommunicator objComm(_NAMED_PIPE_ACTMON_TO_TRAY);
	if(objComm.SendData(&amMsgData, sizeof(AM_MESSAGE_DATA)))
	{
		if(!objComm.ReadData((LPVOID)&amMsgData, sizeof(AM_MESSAGE_DATA)))
		{
			return false;
		}
		//wait broken so read the result.
		bReply = (amMsgData.dwMsgType ? true : false); 
	}
	return bReply;
}

bool CMaxProductMerger::CheckAndFixDB()
{
	CString csLocalBackup, csCurrentDatabasePath, csMaxDBVersion;
	TCHAR szMaxDBVersionNo[50] = {0};
	DWORD dwIniVersion = 0, dwRegVersion = 0, dwEPMD5Update = 0;

	if(m_bCheckAndFixDB)
	{
		return true;
	}
	else
	{
		m_bCheckAndFixDB = true;
	}

	//get ini database version
	csLocalBackup = m_objSystemInfo.m_strAppPath[0];
	csLocalBackup += _T(":\\AuLiveUpdate\\Data");
	GetPrivateProfileString(_T("Database"), _T("Version"), _T(""), szMaxDBVersionNo, sizeof(szMaxDBVersionNo), csLocalBackup + _T("\\DBVersion.ini"));
	if(_tcslen(szMaxDBVersionNo) != 10)
	{
		AddLogEntry(_T("Invalid data read, Ini: %s, Version: %s"), csLocalBackup + _T("\\DBVersion.ini"), szMaxDBVersionNo, true, LOG_WARNING);
		return false;
	}

	csMaxDBVersion = szMaxDBVersionNo;
	csMaxDBVersion.Replace(_T("."), _T(""));
	dwIniVersion = _ttoi(csMaxDBVersion);

	AddLogEntry(_T("Ini version: %s"), szMaxDBVersionNo);
	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csCurrentDatabasePath, HKEY_LOCAL_MACHINE);
	AddLogEntry(_T("Registry db path: %s"), csCurrentDatabasePath);
	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, csCurrentDatabasePath, HKEY_LOCAL_MACHINE);
	AddLogEntry(_T("Registry db version: %s"), csCurrentDatabasePath);

	csMaxDBVersion = csCurrentDatabasePath;
	csMaxDBVersion.Replace(_T("."), _T(""));
	dwRegVersion = _ttoi(csMaxDBVersion);

	{
		if(dwIniVersion < dwRegVersion)
		{
			AddLogEntry(_T("backup folder is smaller version. backup: %s, product: %s"), szMaxDBVersionNo, csCurrentDatabasePath);
			return false;
		}
	}

	//read app path
	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, APP_FOLDER_KEY, csCurrentDatabasePath, HKEY_LOCAL_MACHINE);
	if(csCurrentDatabasePath.GetLength() <= 0)
	{
		AddLogEntry(_T("app folder path from reg failed, %s"), csCurrentDatabasePath);
		return false;
	}

	{
		//create product database path from version in local backup ini, and fix if mismatch
		csCurrentDatabasePath = csCurrentDatabasePath + _T("Data\\") + szMaxDBVersionNo + _T("\\");
	}

	m_objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("EPMD5UPDATE"), dwEPMD5Update, HKEY_LOCAL_MACHINE);

	if(CheckAndFixDBRequirements(csLocalBackup, csCurrentDatabasePath, 1 == dwEPMD5Update))
	{
		//missing or unhealthy database files were found so set the registry
		m_objRegistry.Set(CSystemInfo::m_csProductRegKey, DATABASEREGKEY, szMaxDBVersionNo, HKEY_LOCAL_MACHINE);
		m_objRegistry.Set(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csCurrentDatabasePath, HKEY_LOCAL_MACHINE);
		AddLogEntry(_T("missing files were found, setting registry, ver: %s, path: %s"), szMaxDBVersionNo, csCurrentDatabasePath);

		//restart the actmon and load databases again
		DeleteFile(m_objSystemInfo.m_strAppPath + RESCAN_FILES_DB);
		CMaxDSrvWrapper objMaxDSrvWrapper;
		objMaxDSrvWrapper.ReloadDatabase();
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RESTARTPROTECTION, ON);

		//reset the auto database update and auto product update to 0,
		//as they might have been set because of these db files being missing
		m_objRegistry.DeleteValue(CSystemInfo::m_csProductRegKey, _T("ProductPatch"), HKEY_LOCAL_MACHINE);
		m_objRegistry.DeleteValue(CSystemInfo::m_csProductRegKey, _T("AutoProductPatch"), HKEY_LOCAL_MACHINE);
		m_objRegistry.DeleteValue(CSystemInfo::m_csProductRegKey, _T("DatabasePatch"), HKEY_LOCAL_MACHINE);
		m_objRegistry.DeleteValue(CSystemInfo::m_csProductRegKey, _T("AutoDatabasePatch"), HKEY_LOCAL_MACHINE);

		{
			csCurrentDatabasePath.Replace(CString(szMaxDBVersionNo) + BACK_SLASH, BLANKSTRING);
			m_oDirectoryManager.MaxDeleteDirectory(csCurrentDatabasePath, szMaxDBVersionNo, true, true);
		}
	}

	return true;
}

bool CMaxProductMerger::CheckAndFixDBRequirements(const CString& csSource, const CString& csDestination, bool bSkipBlackDB)
{
	bool bFileMissing = false, bMisMatch = false;
	BOOL bMoreFiles = FALSE;
	CFileFind objFinder;
	CDirectoryManager objDirMgr;
	LPCTSTR szExt = NULL;
	CString csFileName, csFilePath;
	WIN32_FILE_ATTRIBUTE_DATA stFileInfo = {0};
	ULONGLONG ul64DstFileSize = 0, ul64SrcFileSize = 0;

	if(_taccess_s(csDestination, 0))
	{
		objDirMgr.MaxCreateDirectory(csDestination);
	}

	bMoreFiles = objFinder.FindFile(csSource + _T("\\*"));
	if(!bMoreFiles)
	{
		return false;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDots() || objFinder.IsDirectory())
		{
			continue;
		}

		csFilePath = objFinder.GetFilePath();
		csFileName = objFinder.GetFileName();
		szExt = _tcsrchr(csFileName, _T('.'));
		if(!szExt)
		{
			continue;
		}

		if(0 != _tcsicmp(szExt, _T(".db")) && 0 != _tcsicmp(szExt, _T(".id")) && 0 != _tcsicmp(szExt, _T(".nm")) &&
		   0 != _tcsicmp(szExt, _T(".ct")))
		{
			continue;
		}

		bMisMatch = false;
		memset(&stFileInfo, 0, sizeof(stFileInfo));

		if(bSkipBlackDB && 0 == csFileName.CompareNoCase(SD_DB_FS_BLK))
		{
			continue;
		}

		if(_taccess_s(csDestination + csFileName, 0))
		{
			bMisMatch = true;
			AddLogEntry(_T("file not found, dst: %s"), csDestination + csFileName, 0, true, LOG_WARNING);
		}
		else
		{
			if(_tcsicmp(csFileName, _T("Fic.db")))
			{
				if(0 != GetFileAttributesEx(csDestination + csFileName, GetFileExInfoStandard, &stFileInfo))
				{
					ul64DstFileSize = MKQWORD(stFileInfo.nFileSizeHigh, stFileInfo.nFileSizeLow);
					ul64SrcFileSize = objFinder.GetLength();
					if(ul64SrcFileSize != ul64DstFileSize)
					{
						AddLogEntry(_T("file size mismatch, dst: %s"), csDestination + csFileName, 0, true, LOG_WARNING);
						bMisMatch = true;
					}
				}
			}
		}

		if(bMisMatch)
		{
			bFileMissing = true;
			if(0 == CopyFile(csFilePath, csDestination + csFileName, FALSE))
			{
				AddLogEntry(_T("failure copy file, src: %s, dst: %s"), csFilePath, csDestination + csFileName);
			}
			else
			{
				AddLogEntry(_T("success copy file, src: %s, dst: %s"), csFilePath, csDestination + csFileName);
			}
		}
	}

	return bFileMissing;
}

void CMaxProductMerger::LowerProcessPriorityIfUniProcessorCPU()
{
	SYSTEM_INFO stSystemInfo = {0};

	GetSystemInfo(&stSystemInfo);
	if(1 == stSystemInfo.dwNumberOfProcessors)
	{
		AddLogEntry(_T("Setting priority to below normal"), 0, 0, true, LOG_WARNING);
		SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
	}
	else
	{
		AddLogEntry(_T("No priority set, remains as it is"), 0, 0, true, LOG_WARNING);
	}
}

bool CMaxProductMerger::ShutDownMailScannerIfRunning()
{
	AddLogEntry(_T("Sending request to Mail Scanner to exit"), 0, 0, true, LOG_WARNING);
	MAX_PIPE_DATA_REG sScanRequest = {0};
	sScanRequest.eMessageInfo = Finished_Scanning;
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_PLUGIN_TO_SCANNER, true);
	objMaxCommunicator.SendData(&sScanRequest, sizeof(MAX_PIPE_DATA_REG));
	return true;
}

CString CMaxProductMerger::GetDBFolderName()
{
	return m_csMaxDBVersionNo;
}

void CMaxProductMerger::StartBlkDBMerging()
{
	if(!m_pUpdateManager->MergeDBType(0x05, true))
	{
		CString csTemp;
		csTemp.Format(L"%d", 0x05); 
		AddLogEntry(L"##### MergeDBType Failed for: %s", csTemp);
	}	
	return;
}

void BlackDBMergerThread(LPVOID pThis)
{
	CMaxProductMerger	*pInstance = (CMaxProductMerger	*)pThis;

	pInstance->StartBlkDBMerging();

	return;
}

void CopyDeltaThread(LPVOID lpParam)
{
	CMaxProductMerger	*pInstance = (CMaxProductMerger	*)lpParam;

	pInstance->CopyDelta();

	return;
}

void CMaxProductMerger::CopyDelta()
{
	m_bCopySuccess = false;
	CString csMaxDBPath;
	m_objRegistry.Get(m_objSystemInfo.m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);

	CStringArray csarrIgnoreList;
	csarrIgnoreList.Add(L"*.tmp");
	AddLogEntry(_T("Start copying DB Src: %s, Dst: %s"), csMaxDBPath, m_csFolderToMonitor + _T("\\MergeTemp\\Data"));
	if(!m_oDirectoryManager.MaxCopyDirectory(m_csFolderToMonitor + _T("\\MergeTemp\\Data"), csMaxDBPath, false, true, &csarrIgnoreList))
	{
		AddLogEntry(_T("Copying Failed: %s, Dst: %s"), csMaxDBPath, m_csFolderToMonitor + _T("\\MergeTemp\\Data"));
		return;
	}

	/*AddLogEntry(_T("Start loading DB..."), 0, 0, true, LOG_WARNING);
	int iThreadCount = 0;
	for(iThreadCount = 0; iThreadCount < MERGING_THREAD_COUNT ; iThreadCount++)
	{
		if(!m_pUpdateManager->LoadDBType(m_csFolderToMonitor + _T("\\MergeTemp\\Data\\"), iThreadCount, 0, true))
		{
			CString csTemp;
			csTemp.Format(L"%d", iThreadCount); 
			AddLogEntry(L"##### LoadDBType Failed for: %s", csTemp);
			return;
		}
	}*/
	m_bCopySuccess = true;

	//AddLogEntry(_T("End loading DB..."), 0, 0, true, LOG_WARNING);
}

void CMaxProductMerger::CleanUnwantedDelta(CString csSource, CString csSDFile)
{
	BOOL bMoreFiles = FALSE;
	CFileFind objFinder;
	CDirectoryManager objDirMgr;
	bMoreFiles = objFinder.FindFile(csSource + _T("\\*"));
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
			AddLogEntry(objFinder.GetFilePath());
			objDirMgr.MaxDeleteDirectory(objFinder.GetFilePath(),true);
		}
		else
		{
			CString csFile = objFinder.GetFileName();
			csFile = csFile.Left(csFile.Find(_T(".")));
			csFile.Replace(_T("SDDatabase"),_T(""));
			if(csFile<=csSDFile)
			{
				AddLogEntry(objFinder.GetFilePath());
				if(DeleteFile(objFinder.GetFilePath()))
				{
					//AddLogEntry(_T("Delete"));
				}
			}
		}
	}
	objFinder.Close();

}



bool CMaxProductMerger::CheckAndCompareFileVersion(CString csName, CString csIniName)
{
	bool bRetVal = false;
	int iCount = csName.Find('_');
	csName = csName.Right(csName.GetLength() - (iCount + 1));
	
	iCount = csName.Find('.');
	csName = csName.Left(iCount);

	int iFileVersion = _ttoi(csName);

	iCount = csIniName.Find('_');
	csIniName = csIniName.Right(csIniName.GetLength() - (iCount + 1));
	
	iCount = csIniName.Find('.');
	csIniName = csIniName.Left(iCount);

	int iIniFileVersion = _ttoi(csIniName);

	if(iFileVersion < iIniFileVersion)
	{
		bRetVal = true;
	}

	return bRetVal;
}
