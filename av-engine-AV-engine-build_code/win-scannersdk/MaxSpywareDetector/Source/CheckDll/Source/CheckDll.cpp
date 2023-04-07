/*=============================================================================
	FILE			: CheckDll.cpp
	ABSTRACT		: Create Dll Fucntions
	DOCUMENTS	: 
	AUTHOR		: 
	COMPANY		: Aura
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work. All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura. Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE : 
 NOTES		:
VERSION HISTORY	:15 Jan 2008 : Milind Shete
				 Unicode Supported.
============================================================================*/
 
#pragma once
#include "pch.h"
#include "CommonFunctions.h"
#include "MaxExceptionFilter.h"
#include "ExecuteProcess.h"
#include "MaxProtectionMgr.h"
#include <strsafe.h>
#include <msiquery.h>

// WiX Header Files:
#include <wcautil.h>

//please enable below hash defie if you want restart pc after installation 
//#define ENABLE_RESTART_PROMPT 

typedef void (*LPENABLEWF)(BOOL bWF);
typedef void (*LPDLLREGISTER)(void);
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: DLLFunction
In Parameters	: HWND hWnd, UINT uType, CString chDownLoadLink, BOOL bIs64Setup
Out Parameters	: BOOL
Purpose			: This function check for reinstallation and aslo for supported OS.
Author			: Sandip Sanap.
--------------------------------------------------------------------------------------*/
BOOL __stdcall DLLFunction(HWND hWnd, UINT uType, TCHAR* chDownLoadLink, 
						   BOOL bIs64Setup, TCHAR* csProdRegKey)
{
	OutputDebugString(L"***** In DLLFunction()!");
	CMaxExceptionFilter::InitializeExceptionFilter();
	CCommonFunctions objCommon;
	BOOL bRet = objCommon.CheckDLLFunction(uType, (CString)chDownLoadLink,
		bIs64Setup, (CString)csProdRegKey);
	return bRet;
}

BOOL __stdcall DLLFunctionProductCompatibiltiy(HWND hWnd, UINT uType, TCHAR* chDownLoadLink,
						   BOOL bIs64Setup, TCHAR* csProdRegKey)
{
	OutputDebugString(L"***** In DLLFunctionProductCompatibiltiy()!");
	CMaxExceptionFilter::InitializeExceptionFilter();

	CCommonFunctions objCommon;
	return objCommon.ProductCompatibiltiy(uType, (CString)chDownLoadLink, 
		bIs64Setup, (CString)csProdRegKey);
}

/*-------------------------------------------------------------------------------------
Function		: EncryptDB
In Parameters	: TCHAR csFileNames[200]
Out Parameters	: BOOL
Purpose			: This function encrypt the given DB file.
Author			: Sandip Sanap.
--------------------------------------------------------------------------------------*/
BOOL __stdcall EncryptDB(TCHAR csFileNames[200])
{
	OutputDebugString(L"***** In EncryptDB()!");
	CCommonFunctions objCommon;
	return objCommon.EncryptFileDB(csFileNames);
}

/*-------------------------------------------------------------------------------------
Function		: EncryptDB
In Parameters	: TCHAR csFileNames[200]
Out Parameters	: BOOL
Purpose			: This function encrypt the given DB file.
Author			: Sandip Sanap.
--------------------------------------------------------------------------------------*/
BOOL __stdcall EncryptFullDB(TCHAR csFileNames[200], int iHeaderSize)
{
	OutputDebugString(L"***** In EncryptFullDB()!");
	CCommonFunctions objCommon;
	return objCommon.EncryptFileDB(csFileNames, iHeaderSize);
}

/*-------------------------------------------------------------------------------------
Function		: StopService
In Parameters	: int iService, char csFileNames[MAX_PATH]
Out Parameters	: BOOL
Purpose			: This function stop the given service.
Author			: Sandip Sanap.
--------------------------------------------------------------------------------------*/
BOOL __stdcall StopService(int iService, TCHAR csFileNames[MAX_PATH])
{
	OutputDebugString(L"***** In StopService()!");
	BOOL bRet = FALSE;
	CCommonFunctions objCommon;
	bRet = objCommon.StopSDService(iService, csFileNames);
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: DLLCloseFunction
In Parameters	: HWND hWnd, UINT uType, int iExeCheck
Out Parameters	: BOOL
Purpose			: This function closes the all applications.
Author			: Sandip Sanap.
--------------------------------------------------------------------------------------*/
BOOL __stdcall DLLCloseFunction(HWND hWnd, UINT uType, int iExeCheck, TCHAR* csProdName)
{
	OutputDebugString(L"***** In DLLCloseFunction()!");
	BOOL bRet = FALSE;
	CCommonFunctions objCommon;
	bRet = objCommon.CheckDLLCloseFunction(hWnd, uType, iExeCheck,(CString)csProdName);
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: RestartMachineWithPopUp
In Parameters	: BOOL bRestart, TCHAR szProgDirPath[MAX_PATH]
Out Parameters	: BOOL
Purpose			: This function prompt for restart and if yes then restart the machine.(launch another exe)
Author			: Sandip Sanap.
--------------------------------------------------------------------------------------*/
BOOL __stdcall RestartMachineWithPopUp(BOOL bRestart, TCHAR szProgDirPath[MAX_PATH])
{
	OutputDebugString(L"***** In RestartMachineWithPopUp()!");
	if(bRestart)
	{
		CProductInfo oProductInfo;
		//if(((oCPUInfo.GetOSVerTag()).Find(_T("XP")) != -1))
		{
			CString csMsg = oProductInfo.GetProductName() + _T(" needs to restart the system. Do you want to restart now?");
			CString csProductName = oProductInfo.GetProductName();
			int iRet = MessageBox(NULL, csMsg, csProductName, MB_YESNO|MB_ICONQUESTION|MB_TOPMOST);
			if(iRet == IDYES)
			{
				CEnumProcess objEnum;
				objEnum.RebootSystem();
				iRet = 1;
				return TRUE;
			}
		}
		return FALSE;
	}
	CString csProgDirPath(szProgDirPath);
	CExecuteProcess objExecuteProcess;
	csProgDirPath += _T("\\MigrateSD.exe");
	objExecuteProcess.ShellExecuteExW(csProgDirPath, _T("HIDE"));
	return TRUE;	
}

BOOL __stdcall UpdateFICDB(TCHAR *csAppPath)
{
	OutputDebugString(L"***** In UpdateFICDB()!");
	BOOL bRet = FALSE;
	CCommonFunctions objCommon;
	CString strAppPath(csAppPath);
	if (objCommon.UpdateFileIntegrityDB(strAppPath))
		bRet = TRUE;
	
	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.ResumeProtection();
	return bRet;
}

BOOL __stdcall CreateWow6432NodeKey(TCHAR csAppPath[MAX_PATH], TCHAR csProductName[MAX_PATH])
{
	OutputDebugString(L"***** In CreateWow6432NodeKey()!");
	BOOL bRet = TRUE;
	CString strAppPath(csAppPath);
	CString strAppName(csProductName);
	CString csSubKey ;
	CRegKey objRegKey;
	
	
	csSubKey.Format(_T("SOFTWARE\\Wow6432Node\\%s"), csProductName);
	if(objRegKey.Create(HKEY_LOCAL_MACHINE, csSubKey) != ERROR_SUCCESS)
	{
		bRet = FALSE;
	}
	objRegKey.SetStringValue(_T("AppPath"), strAppPath + UI_EXENAME);
	objRegKey.SetStringValue(_T("AppFolder"), strAppPath);
	objRegKey.Close ();
	return bRet;
}

BOOL __stdcall DeleteWow6432bitNodeKey(TCHAR csAppPath[MAX_PATH], TCHAR csProductName[MAX_PATH])
{
	OutputDebugString(L"***** In DeleteWow6432bitNodeKey()!");
	BOOL bRet = TRUE;
	CString strAppPath(csAppPath);
	CString strAppName(csProductName);
	CString csSubKey;
	CRegKey objRegKey;
	
	csSubKey.Format(_T("SOFTWARE\\Wow6432Node\\%s"), csProductName);

	if ( objRegKey.DeleteSubKey (csSubKey) != ERROR_SUCCESS )
	{
		RegDeleteKey (HKEY_LOCAL_MACHINE ,csSubKey);
	}
	objRegKey.Close ();
	return bRet;
}

BOOL __stdcall CopyAndCryptFileDB(TCHAR*szOrgFile, TCHAR*szNewFile, int dwMaxMemLimit, int dwStartOffset)
{
	OutputDebugString(L"***** In CopyAndCryptFileDB()!");
	bool bRet = false;
	CCommonFunctions objCommon;
	CString csOrgFileName(szOrgFile);
	CString csNewFileName = csOrgFileName + _T("__");

	_trename(csOrgFileName, csNewFileName);
	bRet = objCommon.CopyAndCryptFileDatabase(csNewFileName, csOrgFileName, dwMaxMemLimit, dwStartOffset);
	if(bRet)
	{
		DeleteFile(csNewFileName);
	}
	else
	{
		_trename(csNewFileName, csOrgFileName);
	}

	return bRet;
}

BOOL __stdcall PostRestartProtectionEventToTray()
{
	OutputDebugString(L"***** In PostRestartProtectionEventToTray()!");
	CCommonFunctions objCommon;
	objCommon.PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, STARTPROTECTION, ON);
	return TRUE;
}

BOOL __stdcall PostPauseActiveMonitorEventToTray(int iProduct)
{
	OutputDebugString(L"***** In PostPauseActiveMonitorEventToTray()!");
	CCommonFunctions objCommon;
	CRegistry oReg;
	CProductInfo oProductInfo;
	DWORD dwValue = 1;
	CCPUInfo oCPU;
	bool bis64OS = oCPU.isOS64bit()?true:false;
	if(bis64OS)
	{
		oReg.SetWow64Key(true);
	}
	
	oReg.Get(oProductInfo.GetActMonRegKey(), _T("ProcessMonitor"), dwValue,HKEY_LOCAL_MACHINE);
	if(dwValue)
	{
		objCommon.PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, STOPPROTECTION, ON);
		return TRUE;
	}
	return FALSE;
}

BOOL __stdcall AskForRestart(BOOL bIsAV, TCHAR szProgDirPath[MAX_PATH],BOOL bShowMessage)
{
	OutputDebugString(L"***** In AskForRestart()!");
	int iRet = 0;
	CRemoteService objRemoteSrc;
	CRegistry oReg;
	CProductInfo objProductInfo;
	TCHAR szDesc[MAX_PATH] = {0};
	CString csProductName;
	CString csAppPath (szProgDirPath);
	CCPUInfo objCpuInfo;		
	_tcscpy_s(szDesc, MAX_PATH, csProductName);
	_tcscat_s(szDesc, MAX_PATH, _T(" Services"));
	
	objRemoteSrc.StartRemoteService(MAXWATCHDOG_SVC_NAME, csAppPath + MAXWATCHDOG_SVC_EXE, 16, 2, false);
	objRemoteSrc.SetFailureActionToService(MAXWATCHDOG_SVC_NAME, szDesc);
	

	
	DWORD dwMajorVer = 0;
	DWORD dwMinorVer = 0;
	bool bWscSrv = false;
	objCpuInfo.GetMajorAndMinorOSVersion(dwMajorVer,dwMinorVer);
	if(dwMajorVer > 6 || (dwMajorVer == 6 && dwMinorVer >0))
	{
		bWscSrv = true;
	}

	csProductName = objProductInfo.GetProductName();
	if(bShowMessage)
	{
		CString csMessage = csProductName + _T(" needs to restart the system. Do you want to restart now?");
		iRet = MessageBox(NULL, csMessage, csProductName, MB_YESNO|MB_ICONQUESTION|MB_TOPMOST);

		if(iRet == IDYES)
		{
			CEnumProcess objEnum;
			objEnum.RebootSystem();
			iRet = 1;
		}
		else
		{
			iRet = 0;
		}
	}
	return iRet;
}

BOOL __stdcall IsRunningInBartPE()
{
	OutputDebugString(L"***** In IsRunningInBartPE()!");
	BOOL bRet = FALSE;
	CCommonFunctions objCommon;
	bRet = objCommon.CheckForBartPE();
	return bRet; 
}

BOOL __stdcall InstallProtectorDriver(BOOL is64bitSetup, TCHAR csAppFolderPath[MAX_PATH], TCHAR csTempPath[MAX_PATH], bool bIsBefore)
{
	if(!bIsBefore)
	{
		OutputDebugString(L"***** In InstallProtectorDriver()!");
		CString csAppPath(csAppFolderPath);
		CString csAppTempFile(csTempPath);

		CMaxProtectionMgr oMaxProtectionMgr;
		oMaxProtectionMgr.CopyProtectionDrivers(csAppTempFile, csAppPath);
		oMaxProtectionMgr.InstallProtectionBeforeMemScan(csAppPath);
		oMaxProtectionMgr.InstallProtectionAfterMemScan(csAppPath);
		oMaxProtectionMgr.SetBlockAutoRunStatus(1);
		oMaxProtectionMgr.SetProtectSysRegKeyStatus(1);
		oMaxProtectionMgr.StartProtection();
		oMaxProtectionMgr.ResumeProtection();
		oMaxProtectionMgr.RegisterProcessID(MAX_PROC_MAXAVSETUP);
	}
	return TRUE;
}


BOOL __stdcall SetSetting(int iSettingID)
{
	OutputDebugString(L"***** In SetSetting()!");
	if(iSettingID == 2003)
	{
		CMaxProtectionMgr oMaxProtectionMgr;
		oMaxProtectionMgr.RegisterProcessID(MAX_PROC_MAXAVSETUP);
		return TRUE;
	}
	return FALSE;
}

BOOL __stdcall RemoveMaxProtectorDriver()
{
	OutputDebugString(L"***** In RemoveProtectorDriver()!");
	BOOL bRet = FALSE;
	CCommonFunctions objCommon;
	objCommon.PauseMaxProtectorDriver(true);
	return bRet;
}

int __stdcall LaunchExeInUserContext(int iType, TCHAR* pszAppName, TCHAR* pszParam)
{
	OutputDebugString(L"***** In LaunchExeInUserContext()!");
	CCommonFunctions objCommon;
	return objCommon.LaunchNotificationsInUserContext(iType, pszAppName, pszParam);
}

BOOL __stdcall ConfigureFirewallAndDefenderSetting()
{
	OutputDebugString(L"***** In ConfigureFirewallAndDefenderSetting()!");
	//CCommonFunctions objCommon;
	//objCommon.CheckAndEnableFirewallSetting();
	return TRUE;
}

BOOL __stdcall CheckServerDatabaseVersion(TCHAR* pszNewVer)
{
	OutputDebugString(L"***** In CheckServerDatabaseVersion()!");
	CString csNewVer(pszNewVer);
	OutputDebugString(csNewVer);
	CCommonFunctions objCommon;
	return objCommon.CheckForDBVersion(csNewVer);
}

BOOL __stdcall ConfigureFireWall(TCHAR* pszFirewallPath, int iType)
{
	OutputDebugString(L"***** ConfigureFireWall()!");
	CString csFirewallPath(pszFirewallPath);
	CCommonFunctions objCommon;
	objCommon.ConfigureFirewallInstallation(csFirewallPath, iType);
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: DllRegisterComponents
In Parameters	: void
Out Parameters	: void
Purpose			: This function will Register AuShellExt.dll using DllRegisterServer
--------------------------------------------------------------------------------------*/
void __stdcall DllRegisterComponents(TCHAR *pszDllPath)
{
	CString csApppath(pszDllPath);
	LPDLLREGISTER lpDllRegisterServer = NULL;
	HMODULE hModule =  NULL;

	hModule = LoadLibrary(csApppath + L"AuShellExt.dll");
	if(!hModule)
	{
		AddLogEntry(L"###### Failed to load AuShellExt.dll");
		return;
	}
	lpDllRegisterServer = (LPDLLREGISTER)GetProcAddress(hModule, "DllRegisterServer");
	if(lpDllRegisterServer != NULL)
	{
		lpDllRegisterServer();
	}
	FreeLibrary(hModule);	
}

/*-------------------------------------------------------------------------------------
Function		: DllRegisterComponents
In Parameters	: void
Out Parameters	: void
Purpose			: This function will Cleanup Sunbelt Vipre Components
Author			: Siddharam Pujari
--------------------------------------------------------------------------------------*/
void __stdcall CleanupSV(TCHAR* pszFirewallAppPath, TCHAR* pszAppPath, bool bReinstall, bool bMigrate)
{
	CString csFolderPath(pszFirewallAppPath);
	CString csAppPath(pszAppPath);
	CCommonFunctions oCommonFunction;
	oCommonFunction.CleanUp(csFolderPath, csAppPath, bReinstall, bMigrate);

}

UINT LaunchWelcomePageThread(LPVOID lpvoid)
{
	OutputDebugString(L"IN LaunchWelcomePageThread");
	TCHAR* lpValue = (TCHAR*)lpvoid;
	CString	csLink(lpValue);
	csLink.MakeLower();
	
	OutputDebugString(csLink);
	if(!csLink.IsEmpty())
		ShellExecute(NULL, L"open", csLink, NULL, NULL, SW_SHOW);
	OutputDebugString(L"Out LaunchWelcomePageThread");
	delete lpValue;
	return 1;
}

void __stdcall LaunchWelcomePage(TCHAR* pszAppPath)
{
	OutputDebugString(L"IN LaunchWelcomePage");
	TCHAR *szLink = new TCHAR[MAX_PATH];
	_tcscpy_s(szLink, MAX_PATH, pszAppPath);
	AfxBeginThread(LaunchWelcomePageThread, (LPVOID)pszAppPath);
	OutputDebugString(L"Out LaunchWelcomePage");
}

BOOL __stdcall ReInstallDriverHook()
{
	OutputDebugString(L"***** In ReInstallDriverHook()!");
	CMaxProtectionMgr oMaxProtectionMgr;
	return oMaxProtectionMgr.ReloadINI();
}

BOOL __stdcall ParseSetupInfo(TCHAR* pszSetupFilePath)
{
	OutputDebugString(L"***** In ParseSetupInfo()!");
	CCommonFunctions oCommonFunction;
	return oCommonFunction.ParseInfo(CString(pszSetupFilePath));
}

BOOL __stdcall EnableAutoscanAndSchedular()
{
	OutputDebugString(_T("***** in EnableAutoscanAndSchedular"));
	CCommonFunctions oCommonFunctions;
	return oCommonFunctions.EnableAutoScnAndSchedular();
}

BOOL __stdcall PauseForDBPatch()
{
	OutputDebugString(_T("****** In PauseForDBPatch"));
	CCommonFunctions oCommonFunctions;
	return oCommonFunctions.PauseForDataBasePatch();
}

BOOL __stdcall ResumeAfterDBPatch(TCHAR szProgDirPath[MAX_PATH])
{
	OutputDebugString(_T("****** In ResumeAfterDBPatch"));
	//We need to restart WatchDog which takes care of Starting process : AuActMon.exe, AuDBServer.exe
	return AskForRestart(FALSE, szProgDirPath, FALSE);
}

BOOL __stdcall CheckDatabaseVersion(TCHAR* pszNewVer)
{
	OutputDebugString(L"***** In CheckDatabaseVersion()!");
	CString csNewVer(pszNewVer);
	OutputDebugString(csNewVer);
	CCommonFunctions objCommon;
	return objCommon.CheckForDataBaseVersion(csNewVer);
}

BOOL __stdcall OutputDebugStr(TCHAR *pszString)
{
	OutputDebugString(CString(pszString));
	return true;
}

BOOL __stdcall CheckForValidProduct()
{
	OutputDebugString(_T("***** In CheckForValidProduct"));
	CCommonFunctions objCommon;
	return objCommon.CheckForValidProductToProceed();
}
BOOL __stdcall CleanLocalDB()
{
	OutputDebugString(L"***** In CleanLocalDB()!");
	BOOL bRet = FALSE;
	CCommonFunctions objCommon;
	bRet = objCommon.CheckCleanLocalDB();
	return bRet;
}
/*-------------------------------------------------------------------------------------
Function		: CheckOSBit
In Parameters	: HWND hWnd, UINT uType, CString chDownLoadLink, BOOL bIs64Setup
Out Parameters	: BOOL
Purpose			: This function check for reinstallation and aslo for supported OS.
Author			: Ravindra Shelke.
--------------------------------------------------------------------------------------*/
BOOL __stdcall IsOS64(HWND hWnd,UINT uType, TCHAR* chDownLoadLink, BOOL bIs64Setup, TCHAR* csProdRegKey,BOOL bShowMsgBox)
{
	BOOL bRet = FALSE;
	CCommonFunctions objCommon;
	bRet = objCommon.Is64bitOSEx((CString)chDownLoadLink,bIs64Setup,(CString)csProdRegKey,bShowMsgBox);
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: NetFilterFirewall
Out Parameters	: BOOL
Purpose			: To check Netfilter is present and is it XP system.
Author			: Ravi.
--------------------------------------------------------------------------------------*/
BOOL __stdcall NetFilterFirewallCheck(TCHAR* pszAppPath)
{
	OutputDebugString(_T("***** In NetFilterFirewall"));
	CCommonFunctions objCommon;
	CString csAppPath(pszAppPath);
	return objCommon.NetFilterFirewall(csAppPath);
}

/*-------------------------------------------------------------------------------------
Function		: WinDefendSrvStop
Out Parameters	: BOOL
Purpose			: To disable WindDefender.
Author			: Ravi.
--------------------------------------------------------------------------------------*/
BOOL __stdcall WinDefenderSrvStop(int iOldVer, int iDefendServ)
{
	//return TRUE;

	OutputDebugString(_T("***** In WinDefendSrvStop"));
	CCommonFunctions objCommon;
	return objCommon.WinDefendSrvStop(iOldVer,iDefendServ);
}
BOOL __stdcall ConfigureNodeJS(TCHAR* pszMSIExecPath, TCHAR* pszPath, int iType, bool bIsSilentInstall)
{
	OutputDebugString(L"##### In ConfigureNodeJS!");
	CEnumProcess objSysProcess ;
	objSysProcess.IsProcessRunning(_T("node.exe"),true,false);
	return TRUE;
}
BOOL __stdcall InstallMaxProtectorDriverProdPatch(BOOL is64bitSetup, TCHAR csAppFolderPath[MAX_PATH], TCHAR csTempPath[MAX_PATH], bool bIsBefore)
{
	//if(!bIsBefore)
	{
		OutputDebugString(L"***** In InstallProtectorDriver()!");
		CString csAppPath(csAppFolderPath);
		CString csAppTempFile(csTempPath);

		CMaxProtectionMgr oMaxProtectionMgr;
		//oMaxProtectionMgr.CopyProtectionDrivers(csAppTempFile, csAppPath);
		//oMaxProtectionMgr.InstallProtectionBeforeMemScan(csAppPath);
		oMaxProtectionMgr.InstallProtectionAfterMemScan(csAppPath);
		oMaxProtectionMgr.SetBlockAutoRunStatus(1);
		oMaxProtectionMgr.SetProtectSysRegKeyStatus(1);
		oMaxProtectionMgr.StartProtection();
		//oMaxProtectionMgr.ResumeProtection();
		//oMaxProtectionMgr.RegisterProcessID(MAX_PROC_MAXAVSETUP);
	}
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: WinELDriver
Out Parameters	: BOOL
Purpose			: Install driver.
Author			: Ravi.
--------------------------------------------------------------------------------------*/
BOOL __stdcall WinELDriver()
{
	OutputDebugString(_T("***** In WinELDriver"));
	CCommonFunctions objCommon;
	return objCommon.WinELamDriver();
}
/*-------------------------------------------------------------------------------------
Function		: CreateRansomBackup
Out Parameters	: BOOL
Purpose			: Create Ransom backup folder.
Author			: Ravi.
--------------------------------------------------------------------------------------*/
BOOL __stdcall CreateRansomBackup(TCHAR* csProductPath)
{
	OutputDebugString(_T("***** In CreateRansomBackupFolder"));
	CCommonFunctions objCommon;
	return objCommon.CreateRansomBackupFolder((CString)csProductPath);
}
UINT __stdcall SetIniRegistriesEx(MSIHANDLE hInstall)
{
	CCommonFunctions objCommon;

	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;

	hr = WcaInitialize(hInstall, "SetIniRegistriesEx");
	ExitOnFailure(hr, "Failed to initialize");

	
	LPWSTR myProperty = NULL;
	hr = WcaGetProperty(L"MY_PROPERTY", &myProperty);
	OutputDebugString((LPCWSTR)myProperty);
	ExitOnFailure(hr, "Failure reading MY_PROPERTY");
	objCommon.SetIniRegistries();
	Sleep(1000);

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return 0;

}

UINT __stdcall DeinitWixInstaller(MSIHANDLE hInstall)
{
	CCommonFunctions objCommon;

	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;

	hr = WcaInitialize(hInstall, "SetIniRegistriesEx");
	ExitOnFailure(hr, "Failed to initialize");

	BOOL bRet = FALSE;
	objCommon.CheckCleanLocalDB();

	objCommon.CreateRansomBackupFolderEx();

	objCommon.EnableAutoScnAndSchedular();

	objCommon.EndInstallation();

	objCommon.LaunchUltraAV();
	 
	Sleep(1000);

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return 0;

}

UINT __stdcall InitWixInstaller(MSIHANDLE hInstall)
{
	OutputDebugString(L"Inside InitWixInstaller");
	CCommonFunctions objCommon;

	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;

	hr = WcaInitialize(hInstall, "SetIniRegistriesEx");
	ExitOnFailure(hr, "Failed to initialize"); 

	BOOL bRet = FALSE;
	objCommon.EnableProtectection();
	objCommon.StartInstallation();

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return 0;

}