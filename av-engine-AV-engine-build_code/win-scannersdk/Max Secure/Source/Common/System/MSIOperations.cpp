#include "pch.h"
#include "MSIOperations.h"
#include "SDSystemInfo.h"
#include "DirectoryManager.h"
#include "RemoteService.h"
#include "ExecuteProcess.h"
#include "CPUInfo.h"
#include "Shlwapi.h"
#include "Registry.h"

CMSIOperations::CMSIOperations()
{

}

CMSIOperations::~CMSIOperations()
{

}

void CMSIOperations::CleanUpMSIComponents()
{
	CDirectoryManager oDirectoryManager;
	CSystemInfo oSystemInfo;

	
	oDirectoryManager.MaxDeleteDirectory(CSystemInfo::m_strAppPath + _T("Drivers"), true);

	DeleteFile(CSystemInfo::m_csX86AppPathIn64OS + L"\\AuFirewallDLL.dll");
	CString csOldFileName(CSystemInfo::m_csX86AppPathIn64OS + L"\\AuFirewallDLL.dll");
	CString csNewFileName(CSystemInfo::m_csX86AppPathIn64OS + L"\\-AuFirewallDLL.dll");
	_trename(csOldFileName, csNewFileName);
	DeleteFile(CSystemInfo::m_strAppPath + L"\\AuMailScanner.dll");
	DeleteFile(CSystemInfo::m_strAppPath + L"\\AuFirewallDLL.dll");
	DeleteFile(CSystemInfo::m_strAppPath + L"\\AuMailProxy.exe");
	DeleteFile(CSystemInfo::m_strAppPath + L"\\AuDriverMgr.exe");

	TCHAR lpszPath[MAX_PATH + 1]={0};
	GetSystemDirectory (lpszPath,MAX_PATH + 1);
	CString csSystem32Path = lpszPath;
	DeleteFile(csSystem32Path + L"\\drivers\\NetFilterIM.sys");

}

void CMSIOperations::ReInstallFirewallMSI(CString csAppPath)
{
	int iPos = csAppPath.ReverseFind('\\');
	CString csAppFolder = csAppPath.Mid(0, iPos);

	CreateAntiSpamSettingINIFile(csAppFolder + L"\\Setting\\AntiSpamSetting.ini");

	CExecuteProcess oExecuteProcess;
	CRemoteService oRemoteService;
	oRemoteService.StopRemoteService(L"InterSecSrv", false);
	TCHAR lpszPath[MAX_PATH + 1]={0};
	GetSystemDirectory(lpszPath,MAX_PATH + 1);
	wcscat_s(lpszPath, MAX_PATH, L"\\msiexec.exe");
	CString csParam = L" /i \"" + csAppPath + L"\"" + L" REINSTALL=ALL REINSTALLMODE=vsamu /norestart /qn TARGETDIR=\"" + csAppFolder + L"\"";
	oExecuteProcess.ExecuteCommandWithWait(lpszPath, csParam);
}

void CMSIOperations::InstallFirewallMSI(CString csAppPath)
{
	CreateAntiSpamSettingINIFile(csAppPath + L"\\Setting\\AntiSpamSetting.ini");

	BOOL bIs64bit = FALSE;
	CExecuteProcess oExecuteProcess;
	CCPUInfo oCPUInfo;
	bIs64bit = oCPUInfo.isOS64bit();
	CString csFileName;
	if(bIs64bit)
		csFileName = csAppPath + (CString)L"FirewallX64.msi";
	else
		csFileName = csAppPath + (CString)L"Firewall.msi";

	if(PathFileExists(csFileName))
	{
		TCHAR lpszPath[MAX_PATH + 1]={0};
		GetSystemDirectory(lpszPath,MAX_PATH + 1);
		wcscat_s(lpszPath, MAX_PATH, L"\\msiexec.exe");
		CString csParam = L" /i \"" + csFileName + L"\"" + L" /qn TARGETDIR=\"" + csAppPath + L"\"";
		oExecuteProcess.ExecuteCommandWithWait(lpszPath, csParam);
	}

}

void CMSIOperations::CreateAntiSpamSettingINIFile(CString strINIPath)
{
	if(PathFileExists(strINIPath))
		return;

	WritePrivateProfileString(L"Settings", L"MAIL_SCAN", L"0", strINIPath);
	WritePrivateProfileString(L"Settings", L"ENABLE_PLUGIN", L"OFF", strINIPath);
	WritePrivateProfileString(L"Settings", L"SCAN_ATTACHMENT", L"ON", strINIPath);
	WritePrivateProfileString(L"Settings", L"BLOCK_ATTACHMENT", L"OFF", strINIPath);
	WritePrivateProfileString(L"Settings", L"MY_ADDRESS", L"OFF", strINIPath);
	WritePrivateProfileString(L"Settings", L"SUSPICIOUS_URL", L"OFF", strINIPath);
	WritePrivateProfileString(L"Settings", L"BLOCKED_PHRASES", L"OFF", strINIPath);
	WritePrivateProfileString(L"Settings", L"PHISHING_ELT", L"OFF", strINIPath);
	WritePrivateProfileString(L"Settings", L"BLOCKED_SENDER", L"OFF", strINIPath);
	WritePrivateProfileString(L"Settings", L"ALLOWED_SENDER", L"OFF", strINIPath);
	WritePrivateProfileString(L"Settings", L"ALLOWED_PHRASES", L"OFF", strINIPath);
	WritePrivateProfileString(L"Settings", L"SET_MAILFOOTER", L"ON", strINIPath);

	WritePrivateProfileString(L"BLOCK_ATTACH_LIST", L"count", L"10", strINIPath);
	WritePrivateProfileString(L"BLOCK_ATTACH_LIST", L"0", L"exe", strINIPath);
	WritePrivateProfileString(L"BLOCK_ATTACH_LIST", L"1", L"dll", strINIPath);
	WritePrivateProfileString(L"BLOCK_ATTACH_LIST", L"2", L"cpl", strINIPath);
	WritePrivateProfileString(L"BLOCK_ATTACH_LIST", L"3", L"com", strINIPath);
	WritePrivateProfileString(L"BLOCK_ATTACH_LIST", L"4", L"cmd", strINIPath);
	WritePrivateProfileString(L"BLOCK_ATTACH_LIST", L"5", L"cla", strINIPath);
	WritePrivateProfileString(L"BLOCK_ATTACH_LIST", L"6", L"chm", strINIPath);
	WritePrivateProfileString(L"BLOCK_ATTACH_LIST", L"7", L"bin", strINIPath);
	WritePrivateProfileString(L"BLOCK_ATTACH_LIST", L"8", L"bat", strINIPath);
	WritePrivateProfileString(L"BLOCK_ATTACH_LIST", L"9", L"asp", strINIPath);

	WritePrivateProfileString(L"OUTLOOK_SETTING", L"SubjectName", L"[!!Spam]", strINIPath);
	CString csMsg = _T("This email was scanned by ");
	csMsg += CSystemInfo::m_csProductName;
	WritePrivateProfileString(L"OUTLOOK_SETTING", L"MailBodyText", csMsg, strINIPath);
}

void CMSIOperations::ExecuteFirewallSetup(CString csFirewallSetupPath)
{
	CExecuteProcess oExecuteProcess;
	oExecuteProcess.ExecuteCommandWithWait(csFirewallSetupPath, _T("\"") + csFirewallSetupPath + _T("\" /VERYSILENT /NORESTART"));
}

void CMSIOperations::UninstallFirewall(LPCTSTR szAppPath)
{
	UninstallFirewallUsingParam(szAppPath, true);
	UninstallFirewallUsingParam(szAppPath, false);
}
void CMSIOperations::UninstallFirewallSetup(LPCTSTR szAppPath)
{
	UninstallFirewallFromSetup(szAppPath, true);
	UninstallFirewallFromSetup(szAppPath, false);
}
void CMSIOperations::UninstallFirewall(LPCTSTR szAppPath, bool is64BitOs)
{
	UninstallFirewallUsingParam(szAppPath, true,is64BitOs);
	UninstallFirewallUsingParam(szAppPath, false,is64BitOs);
}

void CMSIOperations::UninstallFirewallUsingParam(CString csAppPath, bool bUsingGUID)
{
	CString csGuid;
	CString csFWMSIPath;
	CCPUInfo oCPUInfo;
	
	if(oCPUInfo.isOS64bit())
	{
		csGuid = _T("{5751F4A5-F55F-4E83-BCFA-9452FDF7CAC7}");
		csFWMSIPath = csAppPath + L"FirewallX64.msi";
	}
	else
	{
		csGuid = _T("{6DBE9C6E-368B-4EAC-8822-F076EA9E781E}");
		csFWMSIPath = csAppPath + L"Firewall.msi";
	}

	AddLogEntry(_T("Uninstall called! GUID: %s, Path: %s"), csGuid, csFWMSIPath);

	CRegistry oRegistry;
	if(oRegistry.KeyExists(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + csGuid, HKEY_LOCAL_MACHINE)
		&& PathFileExists(csFWMSIPath))
	{
		AddLogEntry(_T("Starting uninstall process! GUID: %s, Path: %s"), csGuid, csFWMSIPath);

		CRemoteService oRemoteService;
		oRemoteService.StopRemoteService(L"InterSecSrv", false);
		DeleteFile(csAppPath + CString(L"Setting\\FirewallLock.txt"));
		DeleteFile(csAppPath + CString(L"ManageUser.DB"));		// delete manage user db so that the unistall happens without asking for password!

		HANDLE handle = CreateFile(csAppPath + CString(L"Setting\\FirewallLock.txt"), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if(handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
			handle = INVALID_HANDLE_VALUE;
		}

		if(bUsingGUID)
		{
			ShellExecuteApp(csGuid);
		}
		else
		{
			ShellExecuteApp(csFWMSIPath);
		}

		AddLogEntry(L"After ShellExecuteApp");
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
void CMSIOperations::UninstallFirewallUsingParam(CString csAppPath, bool bUsingGUID,bool is64BitOs)
{
	CString csGuid;
	CString csFWMSIPath;
	CCPUInfo oCPUInfo;
	if(is64BitOs)
	{
		csGuid = _T("{5751F4A5-F55F-4E83-BCFA-9452FDF7CAC7}");
		csFWMSIPath = csAppPath + L"FirewallX64.msi";
	}
	else
	{
		csGuid = _T("{6DBE9C6E-368B-4EAC-8822-F076EA9E781E}");
		csFWMSIPath = csAppPath + L"Firewall.msi";
	}

	CString csLogLine;

	CRegistry oRegistry;
	oRegistry.SetWow64Key(is64BitOs);
	if(oRegistry.KeyExists(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + csGuid, HKEY_LOCAL_MACHINE)
		&& PathFileExists(csFWMSIPath))
	{
		csLogLine.Format(_T("Starting uninstall process! GUID: %s, Path: %s"), csGuid, csFWMSIPath);

		CRemoteService oRemoteService;
		oRemoteService.StopRemoteService(L"InterSecSrv", false);
		DeleteFile(csAppPath + CString(L"Setting\\FirewallLock.txt"));
		DeleteFile(csAppPath + CString(L"ManageUser.DB"));		// delete manage user db so that the unistall happens without asking for password!

		HANDLE handle = CreateFile(csAppPath + CString(L"Setting\\FirewallLock.txt"), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if(handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
			handle = INVALID_HANDLE_VALUE;
		}

		if(bUsingGUID)
		{
			ShellExecuteApp(csGuid);
		}
		else
		{
			ShellExecuteApp(csFWMSIPath);
		}

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
void CMSIOperations::ShellExecuteApp(CString csAppPath)
{
	TCHAR lpszPath[MAX_PATH + 1] = {0};
	GetSystemDirectory(lpszPath, MAX_PATH + 1);
	wcscat_s(lpszPath, MAX_PATH, L"\\msiexec.exe");

	CString csParam = L" /x \"" + csAppPath + L"\" /qn";

	CExecuteProcess oExecuteProcess;
	oExecuteProcess.ExecuteCommandWithWait(lpszPath, csParam);
}
void CMSIOperations::UninstallFirewallFromSetup(CString csAppPath, bool bUsingGUID)
{
	CString csGuid;
	CString csFWMSIPath;
	CCPUInfo oCPUInfo;
	CRegistry oRegistry;
	if(oCPUInfo.isOS64bit())
	{
		oRegistry.SetWow64Key(true);
		csGuid = _T("{5751F4A5-F55F-4E83-BCFA-9452FDF7CAC7}");
		csFWMSIPath = csAppPath + L"FirewallX64.msi";
	}
	else
	{
		csGuid = _T("{6DBE9C6E-368B-4EAC-8822-F076EA9E781E}");
		csFWMSIPath = csAppPath + L"Firewall.msi";
	}

	AddLogEntry(_T("Uninstall called! GUID: %s, Path: %s"), csGuid, csFWMSIPath);

	
	CString csReg;
	csReg.Format(_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\%s"),csGuid);
	
	if(oRegistry.KeyExists(csReg, HKEY_LOCAL_MACHINE) && (_taccess_s(csFWMSIPath,0)!= 0) || PathFileExists(csFWMSIPath))
	{
		AddLogEntry(_T("Starting uninstall process! GUID: %s, Path: %s"), csGuid, csFWMSIPath);

		CRemoteService oRemoteService;
		oRemoteService.StopRemoteService(L"InterSecSrv", false);
		DeleteFile(csAppPath + CString(L"Setting\\FirewallLock.txt"));
		DeleteFile(csAppPath + CString(L"ManageUser.DB"));		// delete manage user db so that the unistall happens without asking for password!

		HANDLE handle = CreateFile(csAppPath + CString(L"Setting\\FirewallLock.txt"), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if(handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
			handle = INVALID_HANDLE_VALUE;
		}

		if(bUsingGUID)
		{
			ShellExecuteApp(csGuid);
		}
		else
		{
			ShellExecuteApp(csFWMSIPath);
		}

		AddLogEntry(L"After ShellExecuteApp");
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
void CMSIOperations::UninstallNodeJSServer(LPCTSTR szAppPath)
{
	UninstallNodeJSServerUsingParam(szAppPath, true);
	//UninstallNodeJSServerUsingParam(szAppPath, false);
}
void CMSIOperations::UninstallNodeJSServerUsingParam(CString csAppPath, bool bUsingGUID)
{
	CString csGuid;
	CString csFWMSIPath;
	csGuid = _T("{199C6333-5B4F-44B4-9D9A-24E11DE86103}");
	csFWMSIPath = csAppPath ;

	AddLogEntry(_T("Uninstall called! GUID: %s, Path: %s"), csGuid, csFWMSIPath);

	CRegistry oRegistry;
	if((oRegistry.KeyExists(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + csGuid, HKEY_LOCAL_MACHINE)
		|| oRegistry.KeyExists(L"SOFTWARE\\WoW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + csGuid, HKEY_LOCAL_MACHINE))
		&& PathFileExists(csFWMSIPath))
	{
		AddLogEntry(_T("Starting uninstall process! GUID: %s, Path: %s"), csGuid, csFWMSIPath);
	
		if(bUsingGUID)
		{
			ShellExecuteApp(csGuid);
		}
		else
		{
			ShellExecuteApp(csFWMSIPath);
		}
		Sleep(200);		
	}
}