#include "pch.h"
#include "MaxInstallProduct.h"
#include "EnumProcess.h"
#include "AuUninstall.h"
#include "CPUInfo.h"

CMaxInstallProduct::CMaxInstallProduct(void):
					m_lpDllRegisterServer(NULL)
{
}

CMaxInstallProduct::~CMaxInstallProduct(void)
{
}

void CMaxInstallProduct::CleanUpPFFolder(LPCTSTR szProductName, LPCTSTR szRemovePath, LPCTSTR szIgnorePath, bool bAddRestartDelete, bool bRecursive)
{
	CFileFind oFile;
	HRESULT iResult = 0;
	TCHAR szTempRemovePath[MAX_PATH] = {0};

	//Clean firewall log file
	CString csLogFile;
	csLogFile = szRemovePath;
	csLogFile+= FWPNPDATA_FOLDER;
	csLogFile +=_T("\\pnpfirewall.txt");
	DeleteFile(csLogFile);	
	BOOL bRet = oFile.FindFile((CString)szRemovePath + (CString)QUARANTINEFOLDER + _T("\\*.tmp"));
	oFile.Close();
	m_oDirectoryManager.MaxDeleteDirectory(szRemovePath, L"", bRecursive, bAddRestartDelete);
	
#ifdef WIN64
		iResult = SHGetFolderPathAndSubDir(0, CSIDL_PROGRAM_FILESX86, 0, SHGFP_TYPE_CURRENT, szProductName, szTempRemovePath);
		if((iResult == S_OK) && szTempRemovePath[0])
		{
			AddLogEntry(L"Calling DeleteDirectory: %s", szTempRemovePath);
			m_oDirectoryManager.MaxDeleteDirectory(szTempRemovePath, _T(""), true, true);
		}
#endif

}

void CMaxInstallProduct::CleanUpStartMenu(LPCTSTR szProductName)
{
	HRESULT iResult = 0;
	TCHAR szRemovePath[MAX_PATH] = {0};

	if(SUCCEEDED(SHGetFolderPath(0, CSIDL_COMMON_PROGRAMS , NULL, 0, szRemovePath)))
	{
		_tcscat_s(szRemovePath, _countof(szRemovePath),_T("\\"));
		_tcscat_s(szRemovePath, _countof(szRemovePath), szProductName);
	}
	if(szRemovePath[0])
	{
		m_oDirectoryManager.MaxDeleteDirectory(szRemovePath, _T(""), true, true);
	}
}

void CMaxInstallProduct::CleanUpProdRegKey(LPCTSTR szProductName, LPCTSTR szProductRegKey)
{
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, szProductRegKey);

	AddLogEntry(L"Calling DeleteRegKey: %s", szProductRegKey);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, szProductRegKey);

	//For PNPFirewall registry Delete
	CCPUInfo	objCPUInfo;
	DWORD m_dwMajorOSVer = 0;
	DWORD m_dwMinorOSVer = 0;
	objCPUInfo.GetMajorAndMinorOSVersion(m_dwMajorOSVer, m_dwMinorOSVer);
	if(m_dwMajorOSVer > 5)
	{
		m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, FIREWALL_REG_KEY);
	}
	

	m_oReg.DeleteRegKey(HKEY_CLASSES_ROOT, _T("AppID\\{FD235A78-F294-4D06-B614-9716CABE90B0}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\Wow6432Node\\AppID\\{FD235A78-F294-4D06-B614-9716CABE90B0}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Wow6432Node\\Classes\\AppID\\{FD235A78-F294-4D06-B614-9716CABE90B0}"));
	m_oReg.DeleteRegKey(HKEY_CLASSES_ROOT, _T("CLSID\\{4B4EC112-A34D-40F2-B191-B4990B64F225}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\CLSID\\{A0EAC751-EFE8-4757-A7BA-1CA34A8341CB}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\AuShellExt.AuContextMenu"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\AuShellExt.AuContextMenu.1"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\TypeLib\\{914A6B25-7E95-4232-A46D-92382C294D2A}"));
	m_oReg.DeleteValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), _T("AuActiveMonitor"), HKEY_LOCAL_MACHINE);
	m_oReg.DeleteValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), _T("AutoScan"), HKEY_LOCAL_MACHINE);
	m_oReg.DeleteValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), _T("FULLSCAN"), HKEY_LOCAL_MACHINE);
	m_oReg.DeleteValue(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved"), _T("AuContextMenu extension"), HKEY_LOCAL_MACHINE);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers\\AuContextMenu"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\Folder\\shellex\\ContextMenuHandlers\\AuContextMenu"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\Interface\\{2C1A33A7-0613-476C-B32C-69B3BA18CA8D}"));
	m_oReg.DeleteRegKey(HKEY_CLASSES_ROOT, _T("TypeLib\\{3163A9D4-6473-4E93-B8D7-34ACD4D05A2A}"));
	m_oReg.DeleteRegKey(HKEY_CLASSES_ROOT, _T("Wow6432Node\\CLSID\\{4B4EC112-A34D-40F2-B191-B4990B64F225}"));
	m_oReg.DeleteRegKey(HKEY_CLASSES_ROOT, _T("Wow6432Node\\CLSID\\{6B156FB9-F6DA-4D30-8C01-51EB2637FDED}"));
	m_oReg.DeleteRegKey(HKEY_CLASSES_ROOT, _T("Wow6432Node\\CLSID\\{84B5762F-BAA0-4A35-B384-16793D9C0428}"));
	m_oReg.DeleteRegKey(HKEY_CLASSES_ROOT, _T("Wow6432Node\\TypeLib\\{3163A9D4-6473-4E93-B8D7-34ACD4D05A2A}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\TypeLib\\{3163A9D4-6473-4E93-B8D7-34ACD4D05A2A}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\Wow6432Node\\CLSID\\{4B4EC112-A34D-40F2-B191-B4990B64F225}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\Wow6432Node\\CLSID\\{6B156FB9-F6DA-4D30-8C01-51EB2637FDED}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\Wow6432Node\\CLSID\\{84B5762F-BAA0-4A35-B384-16793D9C0428}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\Wow6432Node\\TypeLib\\{3163A9D4-6473-4E93-B8D7-34ACD4D05A2A}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Wow6432Node\\Classes\\CLSID\\{4B4EC112-A34D-40F2-B191-B4990B64F225}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Wow6432Node\\Classes\\CLSID\\{6B156FB9-F6DA-4D30-8C01-51EB2637FDED}"));
	m_oReg.DeleteRegKey(HKEY_CLASSES_ROOT, _T("Wow6432Node\\TypeLib\\{3163A9D4-6473-4E93-B8D7-34ACD4D05A2A}"));
	m_oReg.DeleteRegKey(HKEY_CURRENT_USER, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MenuOrder\\Start Menu\\Programs\\") + (CString)szProductName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Shared Tools\\MSConfig\\startupreg\\AuActiveMonitor"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Shared Tools\\MSConfig\\startupreg\\AuAutoScan"));
	m_oReg.DeleteRegKey(HKEY_CLASSES_ROOT, _T("CLSID\\{6B156FB9-F6DA-4D30-8C01-51EB2637FDED}"));
	m_oReg.DeleteRegKey(HKEY_CLASSES_ROOT, _T("CLSID\\{84B5762F-BAA0-4A35-B384-16793D9C0428}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\CLSID\\{6B156FB9-F6DA-4D30-8C01-51EB2637FDED}"));
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Classes\\CLSID\\{84B5762F-BAA0-4A35-B384-16793D9C0428}"));
}

void CMaxInstallProduct::CleanUpService(LPCTSTR szName)
{
	m_oRemoteService.DeleteRemoteService(szName);

	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Services\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Enum\\Root\\LEGACY_")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Enum\\Root\\LEGACY_")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Enum\\Root\\LEGACY_")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Enum\\Root\\LEGACY_")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Enum\\Root\\LEGACY_")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Enum\\Root\\LEGACY_")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Enum\\Root\\LEGACY_")) + szName);

	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Control\\SafeBoot\\Minimal\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Control\\SafeBoot\\Network\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Control\\SafeBoot\\Network\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Control\\SafeBoot\\Network\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Control\\SafeBoot\\Network\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Control\\SafeBoot\\Network\\")) + szName);
	m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Control\\SafeBoot\\Network\\")) + szName);
}

void CMaxInstallProduct::CleanUpShortCut(LPCTSTR szProductName,LPCTSTR szProductRegKey)
{
	HRESULT iResult = 0;
	TCHAR szRemovePath[MAX_PATH] = {0};
	
	iResult = SHGetFolderPath(0, CSIDL_COMMON_DESKTOPDIRECTORY, 0, SHGFP_TYPE_CURRENT, szRemovePath);
	if((iResult == S_OK) && szRemovePath[0])
	{
		_tcscat_s(szRemovePath, _countof(szRemovePath), BACK_SLASH + (CString)szProductName + _T(".lnk"));
		DeleteFile(szRemovePath);
		
		if(!_taccess_s(szRemovePath, 0))
		{
			MoveFileEx(szRemovePath, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
		}
		
	}
	CRegistry objReg;
	CString csDesktopPath;
	CString csDesktopPathLnk;
	objReg.Get(szProductRegKey,L"USERPROFILE", csDesktopPath,HKEY_LOCAL_MACHINE);
	csDesktopPathLnk = csDesktopPath + L"\\Desktop\\";
	csDesktopPathLnk.Format(_T("%s\\Desktop\\%s.lnk"),csDesktopPath,szProductName);
	DeleteFile(csDesktopPathLnk);
	if(!_taccess_s(csDesktopPathLnk, 0))
	{
		MoveFileEx(csDesktopPathLnk, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
	}
}

void CMaxInstallProduct::KillProcesses(CStringArray& arrProcesses)
{
	CEnumProcess oEnumProcess;
	CString csFileName;
	for(int i = 0; i < arrProcesses.GetCount(); i++)
	{
		csFileName = arrProcesses.GetAt(i);
		csFileName.MakeLower();
		CString		csLog;
		csLog.Format(L"TERMINATE PROCESS : %s", csFileName);
		OutputDebugString(csLog);
		if (oEnumProcess.IsProcessRunning(csFileName, true, false) == false)
		{
			csLog.Format(L"TERMINATE PROCESS FAILED : %s", csFileName);
		}
	}
}


void CMaxInstallProduct::DllUnRegisterComponents(LPCTSTR szAppPath)
{
	
	HMODULE hModule =  NULL;
	hModule = LoadLibrary(CString(szAppPath) + L"AuAntiSpam.dll");
	if(!hModule)
	{
		AddLogEntry(L"###### Failed to load AuAntiSpam.dll");
		//return;
	}
	else
	{
		m_lpDllRegisterServer = (LPDLLREGISTER)GetProcAddress(hModule, "DllUnregisterServer");
		if(m_lpDllRegisterServer != NULL)
		{
			m_lpDllRegisterServer();
		}
		FreeLibrary(hModule);
	}

	hModule = NULL;
	hModule = LoadLibrary(CString(szAppPath) + L"AuShellExt.dll");
	if(!hModule)
	{
		AddLogEntry(L"###### Failed to load AuShellExt.dll");
		//return;
	}
	else
	{

		m_lpDllRegisterServer = (LPDLLREGISTER)GetProcAddress(hModule, "DllUnregisterServer");
		if(m_lpDllRegisterServer != NULL)
		{
			m_lpDllRegisterServer();
		}
		FreeLibrary(hModule);
		hModule = NULL;
	}


	//AMSI Provider
	hModule = NULL;
	hModule = LoadLibrary(CString(szAppPath) + L"\\AMSI\\AuAMSIProvider.dll");
	if(!hModule)
	{
		AddLogEntry(L"###### Failed to load AuAMSIProvider.dll");
		return;
	}
	else
	{
		m_lpDllRegisterServer = (LPDLLREGISTER)GetProcAddress(hModule, "DllUnregisterServer");
		if(m_lpDllRegisterServer != NULL)
		{
			m_lpDllRegisterServer();
		}
		FreeLibrary(hModule);
		hModule = NULL;
		
		m_oReg.DeleteKey(L"SOFTWARE\\Microsoft\\AMSI\\Providers",L"{992DACE9-4CBB-4208-889A-A42431FE4827}",HKEY_LOCAL_MACHINE);
		
	}
	
}

void CMaxInstallProduct::UninstallFirewall(LPCTSTR szAppPath)
{
	CString csAppPath(szAppPath);
	CString csFWDriverMgrPath = csAppPath + L"DriverMgr.exe";
	CRegistry oRegistry;
	if(oRegistry.KeyExists(FW_FIREWALL_UNINSTALL, HKEY_LOCAL_MACHINE) && PathFileExists(csFWDriverMgrPath))
	{
		AddLogEntry(_T("Starting uninstall process! Path: %s"), csFWDriverMgrPath);

		DeleteFile(csAppPath + CString(L"Setting\\FirewallLock.txt"));
		
		HANDLE handle = CreateFile(csAppPath + CString(L"Setting\\FirewallLock.txt"), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if(handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
			handle = INVALID_HANDLE_VALUE;
		}

		m_oExecProc.ExecuteCommandWithWait(csFWDriverMgrPath,L"-UNINSTALL");
				
		AddLogEntry(L"After ExecuteCommandWithWait");
		Sleep(200);
		int iCnt = 0;
		while(true)
		{
			HANDLE hLockFile = CreateFile(csAppPath + CString(L"Setting\\FirewallLock.txt"), GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

			if(iCnt == 6)
			{
				AddLogEntry(_T("Lock was not released in time! breaking the loop!"));
				break;
			}

			if(GetLastError() == ERROR_ALREADY_EXISTS)
			{
				AddLogEntry(_T("Waiting for lock to be Released"));
				CloseHandle(hLockFile);
				hLockFile = INVALID_HANDLE_VALUE;
				Sleep(1000*10);
				iCnt ++;
			}
			else if(hLockFile != INVALID_HANDLE_VALUE)
			{
				CloseHandle(hLockFile);
				hLockFile = INVALID_HANDLE_VALUE;
				DeleteFile(csAppPath + CString(L"Setting\\FirewallLock.txt"));
				AddLogEntry(_T("Lock has been Released"));
				break;
			}
		}
	}
	
}
void CMaxInstallProduct::CompleteUninst(CString csProductPath, CString csFolderInAppPath)
{
	TCHAR *drives;
	CString regDll, regMxs, regMxsDb, regDb, sysConf;
	CString csRegInfo;
	TCHAR szProgramDataPath[MAX_PATH];
	TCHAR szWindowsPath[MAX_PATH];
	SHGetFolderPath(0, CSIDL_COMMON_APPDATA, 0, SHGFP_TYPE_CURRENT, szProgramDataPath);
	
	CString csProgDataName = csFolderInAppPath;
	csProgDataName = csProgDataName.Mid(1);
	TCHAR szProdataAppdatapath[MAX_PATH];
	_tcscpy_s(szProdataAppdatapath,MAX_PATH,szProgramDataPath);
	PathAppend(szProdataAppdatapath, csProgDataName);
	GetWindowsDirectory(szWindowsPath,MAX_PATH);
	CString csOSDrive(szWindowsPath);
	csOSDrive.MakeLower();
	csOSDrive.Replace(_T("windows"),BLANKSTRING);


	CString csProDataAppDataPath(szProdataAppdatapath);
	CString csProDataPath(szProgramDataPath);
	CString csWindowPath(szWindowsPath);

	CArray<CString,CString> strIPAddresses;
	
	m_oDirectoryManager.MaxDeleteDirectory( csOSDrive + _T("AuLiveUpdate"), true);

	m_oDirectoryManager.MaxDeleteDirectory( csOSDrive + _T("netfilter2"), true);
	
	m_oDirectoryManager.MaxDeleteDirectory(csProDataAppDataPath + _T("Quarantine"), true);

	m_oDirectoryManager.MaxDeleteDirectory(csProDataAppDataPath + _T("BackUPData"), true);
	
	m_oDirectoryManager.MaxDeleteDirectory(csProDataAppDataPath + csProductPath, true);
	
	
	if(PathFileExists(csProDataAppDataPath + _T("LocalBackupRestore.DB")))
	{
		DeleteFile(csProDataAppDataPath +_T("LocalBackupRestore.DB"));
	}
	
	csProgDataName = csFolderInAppPath;
	int iPos = csProgDataName.Find(_T("\\"),1);
	if (iPos != -1)
	{
		csProgDataName = csProgDataName.Left(iPos);
	}
	//RemoveDirectory(csProDataPath+ csProgDataName);
	m_oDirectoryManager.MaxDeleteDirectory(csProDataPath + csProgDataName, true);

	
}

bool CMaxInstallProduct::CreateRansomBackupFolder()
{

	WCHAR csWinDir[MAX_PATH] = _T("");
	UINT uRetVal = 0;
	TCHAR	szDriveStrings[MAX_PATH] = {0x00};
	DWORD	dwBuffLen = MAX_PATH;
	TCHAR	*pDummy = NULL;
	GetLogicalDriveStrings(dwBuffLen,szDriveStrings);
	pDummy = szDriveStrings;
	int iCount= 0;
	DWORD dwData = 0;
	TCHAR	szDrive[0x10] = {0x00};
	while(pDummy)
	{
		_stprintf_s(szDrive,0x10,L"%s",pDummy);
		if (_tcslen(szDrive) == 0x00)
		{
			break;
		}
		DWORD dwDriveType = GetDriveType(szDrive);
		if(GetDriveType(szDrive) == DRIVE_FIXED)
		{
			CString csFolder;
			csFolder.Format(_T("%s!-"),szDrive);
			m_oDirectoryManager.MaxDeleteDirectory(csFolder, true);

			csFolder.Format(_T("%s~!-"),szDrive);
			m_oDirectoryManager.MaxDeleteDirectory(csFolder, true);

			csFolder.Format(_T("%s!-SCPGT01.DOC"),szDrive);
			DeleteFile(csFolder);
			csFolder.Format(_T("%s!-SCPGT02.XLSX"),szDrive);
			DeleteFile(csFolder);
			csFolder.Format(_T("%s!-SCPGT03.JPEG"),szDrive);
			DeleteFile(csFolder);
			csFolder.Format(_T("%s!-SCPGT04.PDF"),szDrive);
			DeleteFile(csFolder);
		}
		
		iCount++;
		pDummy+=(_tcslen(szDriveStrings) + 0x01);
	}
	return true;
}
bool CMaxInstallProduct::DeleteFilesFolders(CString csAppPath, CString csProdName)
{
	TCHAR szProgPath[MAX_PATH] = {0};
	if(!csProdName.IsEmpty())
	{
		if(SUCCEEDED(SHGetFolderPath(0, CSIDL_PROGRAM_FILES , NULL, 0, szProgPath)))
		{
			CString csPath;
			csPath.Format(_T("%s\\Common Files\\AV\\%s"),szProgPath,csProdName);
			OutputDebugString(csPath);
			m_oDirectoryManager.MaxDeleteDirectory(csPath, true);
		}
	}

	TCHAR szRemovePath[MAX_PATH] = {0};

	
	return true;
}