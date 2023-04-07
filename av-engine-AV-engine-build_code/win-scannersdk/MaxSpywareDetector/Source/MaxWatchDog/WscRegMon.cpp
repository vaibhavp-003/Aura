#include "pch.h"
#include "WscRegMon.h"
#include "MaxWinSCManager.h"
#include "SDSystemInfo.h"
#include "Registry.h"
#include "CPUInfo.h"
#include "MaxProtectionMgr.h"
#include "ExecuteProcess.h"
#include "ProductInfo.h"
#include "WatchDogServiceApp.h"

//#include "windows.h"
#include "winnls.h"
#include "shobjidl.h"
#include "objbase.h"
#include "objidl.h"
#include "shlguid.h"

CWscRegMon::CWscRegMon(void)
{
	bWatchWscService = false;
}

CWscRegMon::~CWscRegMon(void)
{
}
bool CWscRegMon::StartStopMonitor(DWORD dwMonitorType, bool bStatus,bool bShutDown, int ProcessType, DWORD dwPID)
{
	if(dwMonitorType <= 0 && dwMonitorType >= PROTECTION_LAST_MESSAGE)
	{
		CString csTemp;
		csTemp.Format(L">>>>> Unknown message received StartStopMonitor: dwMonitorType: %d, bStatus: %d, bShutDown: %d, ProcessType: %d, dwPID: %d", dwMonitorType, bStatus, bShutDown, ProcessType, dwPID);
		AddLogEntry(csTemp, 0, 0, true, LOG_ERROR);
		return false;
	}
	
	bool bUpdate = LastUpdate();
	CRegistry objReg;
	DWORD dwRegister =0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dwRegister, HKEY_LOCAL_MACHINE);
	DWORD dwActPro = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("bActiveProtection"), dwActPro, HKEY_LOCAL_MACHINE);
	DWORD dwActMon = 0;
	objReg.Get(CSystemInfo::m_csActMonRegKey, PROCESS_KEY, dwActMon, HKEY_LOCAL_MACHINE);
				
		
	if(dwRegister == 0)
	{
		if((dwMonitorType == STOPPROTECTION))
		{
			if(dwActPro == 1)
			{
				RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_SNOOZED,bUpdate);
				RegisterToWSCSubUpdate(2,WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED);
			}

		}
		else if(dwMonitorType == RESTARTPROTECTION)
		{
			if(dwActPro == 0)
			{
				if(dwActMon == 1)
				{
					RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_ON,bUpdate);
					RegisterToWSCSubUpdate(2,(WSC_SECURITY_PRODUCT_SUBSTATUS)WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION);
				}
				else
				{
					RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_SNOOZED,bUpdate);
					RegisterToWSCSubUpdate(2,(WSC_SECURITY_PRODUCT_SUBSTATUS)WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED);
				}
			}
			else
			{
				RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_SNOOZED,bUpdate);
				RegisterToWSCSubUpdate(2,(WSC_SECURITY_PRODUCT_SUBSTATUS)WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED);
			}
		}
		else if((dwMonitorType == STARTPROTECTION))
		{
			if(dwActPro == 0 && dwActMon == 1)
			{
				RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_ON,bUpdate);
				RegisterToWSCSubUpdate(2,(WSC_SECURITY_PRODUCT_SUBSTATUS)WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION);
			}
		/*	else
			{
				RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_SNOOZED,bUpdate);
				RegisterToWSCSubUpdate(2,(WSC_SECURITY_PRODUCT_SUBSTATUS)WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED);
			}	*/		
		}
		else if((dwMonitorType == SETPROCESS))
		{
			if(dwActPro == 0)
			{
				if(bStatus == true)
				{
					RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_ON,bUpdate);
					RegisterToWSCSubUpdate(2,(WSC_SECURITY_PRODUCT_SUBSTATUS)WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION);
				}
				else
				{
					RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_SNOOZED,bUpdate);
					RegisterToWSCSubUpdate(2,(WSC_SECURITY_PRODUCT_SUBSTATUS)WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED);
				}
			}
			else
			{
				RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_SNOOZED,bUpdate);
				RegisterToWSCSubUpdate(2,(WSC_SECURITY_PRODUCT_SUBSTATUS)WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED);
			}			
		}
		VoucherStatusCheck(dwRegister);
	}
	else
	{
		RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_EXPIRED,bUpdate);
		RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_OFF,bUpdate);
		RegisterToWSCSubUpdate(2,WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_NEEDED);
	}
	if(bUpdate)
	{
		RegisterToWSCSubUpdate(3,(WSC_SECURITY_PRODUCT_SUBSTATUS)WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION);
	}
	else
	{
		RegisterToWSCSubUpdate(3,(WSC_SECURITY_PRODUCT_SUBSTATUS)WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED);
	}
	
	return true;
}
bool CWscRegMon::RegisterToWSC()
{
	CString csFilePath;
	CString csIniPath, csCurSetPath;
	CString csProductName = CSystemInfo::m_csProductName;
	CString csAppPath = CSystemInfo::m_strAppPath;
	
	csCurSetPath.Format(_T("%sSetting\\CurrentSettings.ini"), csAppPath);
	TCHAR szData[MAX_PATH] = { 0 };
	GetPrivateProfileString(SETTING_VAL_INI, _T("PRODUCTNAME"), _T(""), szData, MAX_PATH, csCurSetPath);
	CString csAV(szData);
	if (!csAV.IsEmpty())
	{
		csProductName = csAV;
	}

	csFilePath.Format(_T("%sAuWsRMsg.exe"),csAppPath);
	csIniPath.Format(_T("%sSetting\\WsSettings.ini"),csAppPath);
	if(csProductName.IsEmpty())
	{
		csProductName = _T("Aura");
	}
	int iStatus = 0;
	iStatus = GetPrivateProfileInt(L"MAX_STATUS", L"REG_STATUS",0, csIniPath);
	CMaxWinSCManager objWscMgr;
	theApp.m_csProductName = csProductName;
	theApp.m_RemediationPath = csFilePath;
	if(iStatus == 0)
	{
		BOOL bRet= FALSE;
		bRet = objWscMgr.RegisterAVwithWSC(csProductName,csFilePath);
		if(bRet == TRUE)
		{
			WritePrivateProfileString(L"MAX_STATUS", L"REG_STATUS",L"1", csIniPath);
			return true;
		}
		else
		{
			return false;
		}
	}
	return true;
}
bool CWscRegMon::UnRegisterToWSC()
{
	CMaxWinSCManager objWscMgr;
	objWscMgr.UnRegisterAVwithWSC();
	return true;
}
bool CWscRegMon::RegisterToWSCUpdate(int iProduct, bool bUpdate)
{
	CMaxWinSCManager objWscMgr;
	CString csLog;
	objWscMgr.RegisterAVStatuswithWSC((_WSC_SECURITY_PRODUCT_STATE)iProduct,bUpdate);
	return true;
}
bool CWscRegMon::RegisterToWSCSubUpdate(int iProduct, WSC_SECURITY_PRODUCT_SUBSTATUS eProductStaus)
{
	CMaxWinSCManager objWscMgr;
	objWscMgr.RegisterAVSUBStatuswithWSC(iProduct, eProductStaus);
	return true;
}
UINT WDConnectionThread(LPVOID lParam)
{
	return 1;
}
DWORD WINAPI OnSecurityCenterHealthChange(LPVOID lpParameter)
{
	CWscRegMon *pthis = (CWscRegMon *)lpParameter;
	if(pthis->bWatchWscService == false)
	{
		return 0;
	}
	HRESULT hr = S_OK;
    WSC_SECURITY_PROVIDER_HEALTH health = WSC_SECURITY_PROVIDER_HEALTH_GOOD;

    if (SUCCEEDED(hr))
    {
        hr = WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_SERVICE, &health);
        if (SUCCEEDED(hr))
        {
			if(S_FALSE != hr)
			{
				pthis->bWatchWscService = false;
				pthis->IniRegisterToWSC();
				pthis->UnRegisterForChangesWSC();
				
				
			}
        }
    }
    if (SUCCEEDED(hr))
    {
        hr = WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ALL, &health);
        if (SUCCEEDED(hr))
        {
          /*  wprintf(L"Security Center says the machines security health is %s, The Security Center service is %s\n", 
                    (WSC_SECURITY_PROVIDER_HEALTH_GOOD == health)?L"OK":L"Not OK",
                    (S_FALSE == hr)?L"Not Running":L"Running");*/
        }
    }
    if (FAILED(hr))
    {
        wprintf(L"Failed to get health status from Security Center: Error: 0x%X\n", hr);
    }
    return 0;
}
BOOL CWscRegMon::RegisterForChangesWSC()
{
	if(hWscCallbackRegistration != NULL)
	{
		return 1;
	}
	hWscCallbackRegistration = NULL;
	HRESULT hr = S_OK;

	if (SUCCEEDED(hr))
	{
		hr = WscRegisterForChanges(NULL, &hWscCallbackRegistration, OnSecurityCenterHealthChange, this);
		if(SUCCEEDED(hr))
		{
			bWatchWscService = true;
		}
		else
		if (FAILED(hr))
		{
			hWscCallbackRegistration = NULL;
		}
	}

	return 1;
}
BOOL CWscRegMon::UnRegisterForChangesWSC()
{
	HRESULT hr = S_OK;
	if (SUCCEEDED(hr))
	{
		hr = WscUnRegisterChanges(hWscCallbackRegistration);
		if(hr == S_OK)
		{
			hWscCallbackRegistration = NULL;
		}
		else
		{
			return 0;
		}
	}

	return 1;
}
DWORD GetElapsedHoursEx(ULONG64 ulCurTime, ULONG64 ulLastTime)
{
	ULONG64 ulDiffInSecs = 0;
	DWORD dwElapsedHours = 0;

	if(0 == ulCurTime || 0 == ulLastTime)
	{
		return dwElapsedHours;
	}

	if(ulCurTime <= ulLastTime)
	{
		return dwElapsedHours;
	}

	ulDiffInSecs = ulCurTime - ulLastTime;
	dwElapsedHours = (DWORD)(ulDiffInSecs / (60 * 60));
	return dwElapsedHours;
}
BOOL CWscRegMon::LastUpdate()
{
	ULONG64 ulCurTime;
	_time64((__time64_t*)&ulCurTime);
	ULONG64 ulLU_Last;
	CRegistry objReg;
	DWORD dwElapsedHours = 0;
	ulLU_Last =0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("LU_Last"), REG_BINARY, (LPBYTE)&ulLU_Last, sizeof(ulLU_Last), HKEY_LOCAL_MACHINE);
	if(ulLU_Last == 0)
	{
		return 0;
	}

	dwElapsedHours = GetElapsedHoursEx(ulCurTime, ulLU_Last);
	if(dwElapsedHours>72)
	{
		return 0;
	}
	return 1;
}
bool CWscRegMon::IniRegisterToWSC()
{
	RegisterToWSC();
	CRegistry objReg;
	DWORD dwVal = 1;
	DWORD dwRegister = 0;
	//objReg.Get(CSystemInfo::m_csProductRegKey, _T("bActiveProtection"), dwVal, HKEY_LOCAL_MACHINE);
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dwRegister, HKEY_LOCAL_MACHINE);
	RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_ON,true);
	RegisterToWSCSubUpdate(2,WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION);
	bool bUpdate = LastUpdate();
	if(dwRegister ==0)
	{
		VoucherStatusCheck(dwRegister);
		objReg.Get(CSystemInfo::m_csActMonRegKey, PROCESS_KEY, dwVal, HKEY_LOCAL_MACHINE);
		if(dwVal == 1)
		{
			RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_ON,bUpdate);
			RegisterToWSCSubUpdate(2,WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION);
		}
		else
		{
			RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_SNOOZED,bUpdate);
			RegisterToWSCSubUpdate(2,WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED);
		}
	}
	else
	{
		RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_EXPIRED,bUpdate);
		RegisterToWSCUpdate(WSC_SECURITY_PRODUCT_STATE_OFF,bUpdate);
		RegisterToWSCSubUpdate(2,WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_NEEDED);
	}
	RegisterToWSCSubUpdate(1,WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION);
	if(bUpdate)
	{
		RegisterToWSCSubUpdate(3,WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION);
	}
	else
	{
		RegisterToWSCSubUpdate(3,WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED);
	}
	return true;
}
bool CWscRegMon::NotifyExpireToWSC(DWORD dwDays)
{
	CMaxWinSCManager objWscMgr;
	objWscMgr.NotifyExpire(dwDays);
	return true;
}
bool CWscRegMon::VoucherStatusCheck(DWORD dwRegister)
{
	//Registration
	int iControlFlag = 1;
	CRegistry objReg;
	CCPUInfo  objCpuInfo;
	int iNoofRegDays = 0;
	
	try
	{
		if (dwRegister == 0)
		{
			NotifyExpireToWSC(30);
		}
		else
		{
			NotifyExpireToWSC(0);
		}
	}
	catch (...)
	{

	}
	return 1;
}

DWORD CreateLink(LPCWSTR lpszPathObj, LPCSTR lpszPathLink, LPCWSTR lpszDesc,LPCWSTR lpszIcoPath) 
{ 
	HRESULT hres; 
	IShellLink* psl; 

	// Get a pointer to the IShellLink interface. It is assumed that CoInitialize
	// has already been called.
	hres = CoInitialize(0);

	hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl); 
	if (SUCCEEDED(hres)) 
	{ 
		IPersistFile* ppf; 

		// Set the path to the shortcut target and add the description. 
		psl->SetPath(lpszPathObj); 
		psl->SetDescription(lpszDesc); 
		psl->SetIconLocation(lpszIcoPath,0);

		// Query IShellLink for the IPersistFile interface, used for saving the 
		// shortcut in persistent storage. 
		hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf); 

		if (SUCCEEDED(hres)) 
		{ 
			WCHAR wsz[MAX_PATH]; 

			// Ensure that the string is Unicode. 
			MultiByteToWideChar(CP_ACP, 0, lpszPathLink, -1, wsz, MAX_PATH); 

			// Save the link by calling IPersistFile::Save. 
			hres = ppf->Save(wsz, TRUE); 
			ppf->Release(); 
		} 
		psl->Release(); 
	}

	CoUninitialize();
	return 1; 
}


/*-----------------------------------------------------------------------------------------
AUTHOR			: Tushar Kadam
FUNCTION		: ManageWin10Upgrade
PURPOSE			: After Windows Upgrade (Win10), Watchdog and Protection not working
-----------------------------------------------------------------------------------------*/
BOOL CWscRegMon::ManageWin10Upgrade()
{
	BOOL	bRetValue = FALSE;
	//1 : Check for Watchdog File
	//2 : Check for AuSrvOpt File
	//3 : Check for Protection Drivers
	//4 : Copy missing files from backup (Folder created in App Path)
	//5 : Installed and Start Protection Drivers
	//6 : Launch MigrateSD with /RESTARTMSG 
	return bRetValue;
	//CString		csAppPath,csWatchDogPath,csMigrateSD,csLog;	
	//
	//csAppPath = CSystemInfo::m_strAppPath;
	//csWatchDogPath.Format(L"%sCoreBkp\\%s",csAppPath, MAXWATCHDOG_SVC_EXE);

	//if (_waccess(csAppPath + MAXWATCHDOG_SVC_EXE,0) != 0)
	//{
	//	AddLogEntry(L">>>>> Watchdog File Present [%s]!!!",csAppPath + MAXWATCHDOG_SVC_EXE);
	//	return bRetValue;
	//}
	//
	//AddLogEntry(L">>>>> Watchdog File MISSING [%s]!!!",csAppPath + MAXWATCHDOG_SVC_EXE);
	//
	//CopyFile(csWatchDogPath,csAppPath + MAXWATCHDOG_SVC_EXE,TRUE);
	//CopyFile(csAppPath + L"CoreBkp\\AuSrvOpt.exe",csAppPath + L"AuSrvOpt.exe",TRUE);
	//CopyFile(csAppPath + L"CoreBkp\\"+ LIVEUPDATE_EXE,csAppPath + LIVEUPDATE_EXE,TRUE);

	//CopyFile(csAppPath + L"CoreBkp\\" + ACT_MON_TRAY_EXE,csAppPath + ACT_MON_TRAY_EXE,TRUE);
	//
	//TCHAR	szSysDir[MAX_PATH] = {0x00};
	//bool	bIsWin64 = false;	
	//GetSystemDirectory(szSysDir,MAX_PATH);
	//if (_tcslen(szSysDir) != 0x00)
	//{
	//	TCHAR	*pTemp = NULL;
	//	pTemp = _tcsrchr(szSysDir,L':');
	//	if (pTemp != NULL)
	//	{
	//		pTemp++;
	//		*pTemp = L'\0';
	//	}
	//}

	//_tcscat(szSysDir,L"\\Program Files (x86)");
	//if (_waccess(szSysDir,0) == 0)
	//{
	//	csLog.Format(L">>>> Program Files (x86) : %s",szSysDir);
	//	AddLogEntry(csLog);
	//	bIsWin64 = true;
	//}

	//
	//CString			csProductName;
	//CSystemInfo		objSysInfo;
	//CProductInfo	objProductInfo;
	//
	//AddLogEntry(L">>>>> Copied missing files!!!");
	//
	//
	//CString csDebug;
	//DWORD dwLastErro = 0x0;;
	//CRegistry obj_Registry;
	///*if (bIsWin64)
	//{
	//	obj_Registry.SetWow64Key(true);
	//}*/

	//AddLogEntry(L">>>>> Checking for Post Win10 Upgrade");

	//CString csUserKey = CSystemInfo::m_csProductRegKey;
	//CString csDesktopPath,csDesktopPathLnk,csIconPath;

	//obj_Registry.Get(csUserKey,L"USERPROFILE", csDesktopPath,HKEY_LOCAL_MACHINE);

	//HRESULT iResult = 0;
	//TCHAR szRemovePath[MAX_PATH] = {0};
	//
	//iResult = SHGetFolderPath(0, CSIDL_COMMON_DESKTOPDIRECTORY, 0, SHGFP_TYPE_CURRENT, szRemovePath);
	//if((iResult == S_OK) && szRemovePath[0])
	//{
	//	///_tcscat_s(szRemovePath, _countof(szRemovePath), BACK_SLASH + (CString)szProductName + _T(".lnk"));
	//	csDesktopPathLnk = szRemovePath;
	//}
	//
	////char	szDesktopPath[MAX_PATH] = {0x00};
	////if(SUCCEEDED(SHGetFolderPathA(0, CSIDL_DESKTOPDIRECTORY, NULL, 0, szDesktopPath)))
	//{
	//	CString		csTargetFileName;
	//	CStringA	csShortcutPath;

	//	csTargetFileName = csAppPath + UI_EXENAME;
	//	csIconPath = csAppPath + L"MainIconNew.ico";

	//	csShortcutPath.Format("%s\\%s.lnk",csDesktopPathLnk, CSystemInfo::m_csProductName);
	//	
	//	csProductName = objProductInfo.GetProductName();
	//	//if (PathFileExists(csShortcutPath) == FALSE)
	//	{
	//		CreateLink(csTargetFileName,csShortcutPath,csProductName,csIconPath);
	//	}
	//	

	//	AddLogEntry(L">>>>> Created LNK File!!!");
	//}
	//
	//CExecuteProcess objExecProc;
	//CString			csExePath;

	//AddLogEntry(L">>>>> Launching Exe to Set Registry Permission !!!");


	//CRegistry objReg;
	//CString csProdKey;
	//csProdKey = CSystemInfo::m_csProductRegKey;
	//objReg.Set(csProdKey, _T("WIN_UPGRADEREG"), 1, HKEY_LOCAL_MACHINE);

	//objExecProc.ShellExecuteEx(csExePath, L"/VERYSILENT");
	//Sleep(2000);
	//

	//CMaxProtectionMgr	objMaxProc;
	//
	//AddLogEntry(L">>>>> Installing Drivers !!!");

	//objMaxProc.InstallProtectionBeforeMemScan(csAppPath);
	//objMaxProc.InstallProtectionAfterMemScan(csAppPath);

	//AddLogEntry(L">>>>> Before Starting !!!");

	//objMaxProc.StartProtection();

	//AddLogEntry(L">>>>> Starting AuSrvOpt !!!");

	//csMigrateSD = csAppPath + _T("AuSrvOpt.exe");

	//CExecuteProcess objExecProcess;

	//objExecProcess.ExecuteCommandWithWait(csMigrateSD, L"RESTARTMSG");

	//
	//objReg.Set(csProdKey, _T("AutoProductPatch"), 1, HKEY_LOCAL_MACHINE);
	//CString csLiveUpdateExePath;
	//csLiveUpdateExePath.Format(L"%s%s",csAppPath, LIVEUPDATE_EXE);
	//objExecProcess.ShellExecuteExW(csLiveUpdateExePath, L"-AUTOPRODUCTPATCH");
	//
	//
	//AddLogEntry(L">>>>> Finished 'Manage Win10 Upgrade'");
	return bRetValue;
}