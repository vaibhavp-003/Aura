#include "pch.h"
#include "MigrateRecover.h"
#include "MaxConstant.h"
#include "SDSystemInfo.h"
#include "RemoteService.h"
#include "CPUInfo.h"
#include "ProductInfo.h"
#include "EnumProcess.h"
#include "atlbase.h"
#include "DirectoryManager.h"

/*--------------------------------------------------------------------------------------
Function       : CMigrateRecover
In Parameters  : void
Out Parameters : 
Description    : Constructor for class CMigrateRecover
Author         : 
--------------------------------------------------------------------------------------*/
CMigrateRecover::CMigrateRecover(void)
{
	m_pSpyNameDb = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : ~CMigrateRecover
In Parameters  : void
Out Parameters : 
Description    : 
Author         : Destructor for class CMigrateRecover
--------------------------------------------------------------------------------------*/
CMigrateRecover::~CMigrateRecover(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : StartDriver
In Parameters  : LPCTSTR sDriverName, 
Out Parameters : bool 
Description    : This function is for Start Driver.
Author         : 
--------------------------------------------------------------------------------------*/
bool CMigrateRecover::StartDriver(LPCTSTR sDriverName)
{
	bool bRetVal = false;

	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hDriver = OpenService(hSrvManager, sDriverName, SERVICE_START);

	if(hDriver)
	{
		bRetVal = (StartService(hDriver, 0, 0) == FALSE ? false : true);
		if(!bRetVal)
		{
			if(GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
			{
				bRetVal = true;
			}
		}

		CloseServiceHandle(hDriver);
		CloseServiceHandle(hSrvManager);
	}
	return bRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : StartDriver
In Parameters  : LPCTSTR sDriverName, 
Out Parameters : bool 
Description    : 
Author         : 
--------------------------------------------------------------------------------------*/
bool CMigrateRecover::ChangeServiceStartType(LPCTSTR sDriverName, LPCTSTR sDriverPath, DWORD dwStartType)
{
	bool bRetVal = false;
	BOOL bRet = FALSE;

	SC_HANDLE hSCM = ::OpenSCManager(NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);
	if(hSCM == NULL)
	{
		return bRetVal;
	}
	// Maybe it's already there and installed, let's try to run
	SC_HANDLE hService =::OpenService(hSCM, sDriverName, SERVICE_ALL_ACCESS);
	bRet = ::ChangeServiceConfig(hService,16, dwStartType, SERVICE_ERROR_NORMAL,sDriverPath, NULL, NULL, NULL, NULL, NULL, NULL);
	if(!bRet)
	{
		CString csTemp;
		csTemp.Format(L"ChangeServiceConfig Falied with Errpr Code :%d", GetLastError());
		OutputDebugString(csTemp);
	}
	::CloseServiceHandle(hSCM);
	::CloseServiceHandle(hService);
	return bRetVal;
}
/*--------------------------------------------------------------------------------------
Function       : InstallSDDriver
In Parameters  : CString csName, CString csPath, 
Out Parameters : BOOL 
Description    : Installs the Manager Driver
Author         : 
--------------------------------------------------------------------------------------*/
BOOL CMigrateRecover::InstallSDDriver(CString csName, CString csPath)
{
	bool bRetVal = false;

	//create driver entry 
	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if(hSrvManager)
	{
		DWORD dwTagID = 6;
		SC_HANDLE hDriver = CreateService(hSrvManager, csName, csName, SERVICE_START | SERVICE_STOP, 
											SERVICE_KERNEL_DRIVER, SERVICE_BOOT_START, 
											SERVICE_ERROR_NORMAL, csPath, L"Boot Bus Extender", &dwTagID, 0, 0, 0);
		if(hDriver != INVALID_HANDLE_VALUE)
		{
			bRetVal = true;
			CloseServiceHandle(hDriver);
		}
		CloseServiceHandle(hSrvManager);
	}
	return bRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : InstallFilterDriver
In Parameters  : LPCTSTR strFilePath, LPCTSTR sDriverName, LPCTSTR sAltitudeID, 
Out Parameters : bool 
Description    : Installs various Mini File System Filter Drivers and sets its Altitude ID
Author         : 
--------------------------------------------------------------------------------------*/
bool CMigrateRecover::InstallFilterDriver(LPCTSTR strFilePath, LPCTSTR sDriverName, LPCTSTR sAltitudeID)
{
	bool bRetVal = false;
	//create service
	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if(hSrvManager)
	{
		SC_HANDLE hDriver = CreateService(hSrvManager, sDriverName, sDriverName, SERVICE_ALL_ACCESS,
								SERVICE_FILE_SYSTEM_DRIVER, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
								strFilePath, L"FSFilter Anti-Virus", 0, 0, 0, 0);
		if(hDriver != INVALID_HANDLE_VALUE)
		{
			bRetVal = true;
			if(hDriver)
			{
				CloseServiceHandle(hDriver);
				hDriver = NULL;
			}
		}
		CloseServiceHandle(hSrvManager);
	}

	if(bRetVal)// also create the altitude entries required by the mini-filter driver
	{
		bRetVal = false;
		CString csInstancePath = _T("system\\currentcontrolset\\services\\") + CString(sDriverName)+(_T("\\Instances"));
		CString csAltitudePath = csInstancePath + _T("\\")+ CString(sDriverName)+ _T(" Instance");

		CRegKey oReg;
		if(oReg.Create(HKEY_LOCAL_MACHINE, csInstancePath)== ERROR_SUCCESS)
		{
			oReg.SetStringValue(L"DefaultInstance", CString(sDriverName)+ _T(" Instance"));
			oReg.Close();
			if(oReg.Create(HKEY_LOCAL_MACHINE, csAltitudePath)== ERROR_SUCCESS)
			{
				oReg.SetStringValue(L"Altitude", sAltitudeID);
				oReg.SetDWORDValue(L"Flags", 0);
				oReg.Close();
				bRetVal = true;
			}
		}
	}
	return bRetVal;
}

bool CheckIfRegistryCallbackAvailable()
{
#ifdef WIN64
	return true;
#else

	CCPUInfo oCPU;
	if(oCPU.isOS64bit())
		return true;

	DWORD dwMajor, dwMinor = 0;
	oCPU.GetMajorAndMinorOSVersion(dwMajor, dwMinor);
	if(dwMajor == 6 && dwMinor == 2)
	{
		OutputDebugString(L"This is Windows 8 so return true");
		return true;
	}
	bool bReturnVal = false;

	HMODULE hModule = LoadLibrary(L"ntoskrnl.exe");
	if(!hModule)
		return bReturnVal;

	LPVOID lpVoid = GetProcAddress(hModule, "CmRegisterCallback");

	if(lpVoid)
		bReturnVal = true;

	FreeLibrary(hModule);
	return bReturnVal;
#endif
}

/*--------------------------------------------------------------------------------------
Function       : AfterInstallSetup
In Parameters  : bool bProductPatch
Out Parameters : void 
Description    : Starts the required drivers and watch dog after installation
Author         : 
--------------------------------------------------------------------------------------*/
void CMigrateRecover::AfterInstallSetup(bool bProductPatch, bool bSDNormalStart)
{	
	CRegistry oReg;
	CProductInfo objProductInfo;
	CRemoteService objRemoteSrc;
	TCHAR szDesc[MAX_PATH] = {0};
	BOOL bIsRunningInWinPE = FALSE;
	DWORD dwStartType = 0;

	bIsRunningInWinPE = CheckForBartPE();
	CString csCommandLine = GetCommandLine();
#ifndef FOR_MAXSECURE
	if(bSDNormalStart == false && csCommandLine.Find(L"NOUI") == -1 && csCommandLine.Find(L"PATCH") == -1)
	{
		oReg.Set(CSystemInfo::m_csProductRegKey, _T("SetupLaunch"), 1, HKEY_LOCAL_MACHINE);
	}
#endif	
	
		_tcscpy_s(szDesc, MAX_PATH, CSystemInfo::m_csProductName);
		_tcscat_s(szDesc, MAX_PATH, _T(" Services"));
		
		dwStartType = 0;
		DWORD dwVer = 0;
		oReg.Get(CSystemInfo::m_csProductRegKey, _T("Win10"), dwVer, HKEY_LOCAL_MACHINE);
		if(dwVer == 1)
		{
			HMODULE hMonitor;
			typedef bool(*PFSTARTPPLSRV)(TCHAR *szSrvName, TCHAR *szSrvPath);
			PFSTARTPPLSRV lpStartPPLSrv;
			bool bReturn= false;

			hMonitor = LoadLibrary(UI_PPLSRVNAME);
			if(hMonitor != NULL)
			{
				lpStartPPLSrv = (PFSTARTPPLSRV)GetProcAddress(hMonitor, "StartPPLSrv");
				if(lpStartPPLSrv)
				{
					TCHAR szSrvName[MAX_PATH] = {0};
					TCHAR szSrvPath[MAX_PATH] ={0};
					_stprintf(szSrvName,_T("%s"),MAXWATCHDOG_SVC_NAME);
					_stprintf(szSrvPath,_T("%s%s"),objProductInfo.GetAppInstallPath(),MAXWATCHDOG_SVC_EXE);
					bool bRet = lpStartPPLSrv(szSrvName,szSrvPath);
				}
				else
				{
					AddLogEntry(_T(" GetProcAddress failed for StartPPLSrv."));
					bReturn = false;
				}
				FreeLibrary(hMonitor);
				hMonitor = NULL;
				lpStartPPLSrv = NULL;
			}
			else
			{
				AddLogEntry(_T("PSrvOpt.dll Load library failed!"));
				bReturn = false;
			}
			
		}
		else
		{
			dwStartType = 0;
			oReg.Get(MAXWATCHDOG_SVC_PATH,L"Start", dwStartType, HKEY_LOCAL_MACHINE);
			if(dwStartType == 4)
			{
				OutputDebugString(L"WatchDogService Service is Disabled\n");
				ChangeServiceStartType(MAXWATCHDOG_SVC_NAME, objProductInfo.GetAppInstallPath() + MAXWATCHDOG_SVC_EXE, 2);
			}
			objRemoteSrc.StartRemoteService(MAXWATCHDOG_SVC_NAME, objProductInfo.GetAppInstallPath() + MAXWATCHDOG_SVC_EXE, 16, 2, true);
			objRemoteSrc.SetFailureActionToService(MAXWATCHDOG_SVC_NAME, szDesc);	
		}

		DWORD dwPT = 0;
		bool bNoPT = true;
		oReg.Get(CSystemInfo::m_csProductRegKey, _T("NoPT"), dwPT , HKEY_LOCAL_MACHINE);
		if(dwPT == 0)
		{
			bNoPT = false;
		}

		if(bProductPatch)
		{
			CSystemInfo oSystemInfo;
			InstallSDDriver(MAXMGR_DRIVE_TITLE, CSystemInfo::m_strSysDir + _T("\\drivers\\")+ MAXMGR_DRIVE_FILENAME);
		}

		dwStartType = 0;
		CCPUInfo objCpuInfo;
		DWORD dwMajorVer = 0;
		DWORD dwMinorVer = 0;
		bool bWscSrv = false;
		objCpuInfo.GetMajorAndMinorOSVersion(dwMajorVer,dwMinorVer);
		if(dwMajorVer > 6 || (dwMajorVer == 6 && dwMinorVer >0))
		{
			bWscSrv = true;
		}

		bool bRegCallbackAvailable = CheckIfRegistryCallbackAvailable();

		if (bRegCallbackAvailable)
		{
			OutputDebugString(L"bRegCallbackAvailable == true");
		}
		else
		{
			OutputDebugString(L"bRegCallbackAvailable == false");
		}

		StartDriver(MAXWATCHDOG_SVC_NAME);


		if(bProductPatch)
		{
			StartDriver(MAXMGR_DRIVE_TITLE);
		}

	return;
}

/*--------------------------------------------------------------------------------------
Function       : GetSpyTypeID
In Parameters  : CString &csSpyType, 
Out Parameters : DWORD 
Description    : It returns spy type id for the given name
Author         : 
--------------------------------------------------------------------------------------*/
DWORD CMigrateRecover::GetSpyTypeID(CString &csSpyType)
{
	if(csSpyType == FILEWORM)
	{
		return File;
	}
	else if(csSpyType == FOLDER)
	{
		return Folder;
	}
	else if(csSpyType == COOKIE)
	{
		return /*Cookie*/ Cookie_New;
	}
	else if(csSpyType == REGISTRYKEY)
	{
		return RegKey;
	}
	else if(csSpyType == REGISTRYDATA || csSpyType == REGISTRYVALUE)
	{
		return RegValue;
	}
	else if(csSpyType == REGVALFIX || csSpyType == REGDATAFIX)
	{
		return RegFix;
	}

	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : GetSpyNameID
In Parameters  : CString csSpyName, 
Out Parameters : ULONG 
Description    : returns spy id for the given name
Author         : 
--------------------------------------------------------------------------------------*/
ULONG CMigrateRecover::GetSpyNameID(CString csSpyName)
{
	csSpyName.MakeLower();
	DWORD dwSpyName = 0;
	if(m_pSpyNameDb == NULL)
	{
		m_pSpyNameDb = new CS2U(false);
		m_pSpyNameDb->Load(CSystemInfo::m_strDBPath + _T("\\") + SD_DB_NAMEDB);
	}

	if(m_pSpyNameDb)
	{
		m_pSpyNameDb->SearchItem(csSpyName, &dwSpyName);
	}
	return dwSpyName;
}

/*--------------------------------------------------------------------------------------
Function       : CheckForBartPE
In Parameters  : 
Out Parameters : BOOL
Description    : 
Author         :
--------------------------------------------------------------------------------------*/
BOOL CMigrateRecover::CheckForBartPE()
{
	HDESK       hdesk = NULL;
	HWINSTA     hwinsta = NULL;
	HWINSTA     hwinstaSave = NULL;

	// Save a handle to the caller's current window station.
	if ( (hwinstaSave = GetProcessWindowStation() ) == NULL)
	{
		return FALSE;
	}

	hwinsta = OpenWindowStation(
		_T("winsta0"),                   // the interactive window station 
		FALSE,							// handle is not inheritable
		READ_CONTROL);		// rights to read/write the DACL

	if (hwinsta == NULL) 
	{
		SetProcessWindowStation (hwinstaSave);
		return FALSE;
	}

	// To get the correct default desktop, set the caller's 
	// window station to the interactive window station.
	if (!SetProcessWindowStation( hwinsta ))
	{
		//OutputDebugString(_T("SetProcessWindowStation Failed"));
		CloseWindowStation(hwinsta);
		SetProcessWindowStation (hwinstaSave);
		return FALSE;
	}

	// Get a handle to the interactive desktop. default winlogon
	hdesk = OpenDesktop(
		_T("winlogon"),    // the interactive window station 
		1,				// no interaction with other desktop processes
		FALSE,			// handle is not inheritable
		READ_CONTROL | DESKTOP_READOBJECTS);	// request the rights to read and write the DACL

	if (hdesk == NULL) 
	{
		CloseWindowStation( hwinsta );
		SetProcessWindowStation (hwinstaSave);
		return FALSE;
	}
		
	CloseDesktop(hdesk);
	CloseWindowStation( hwinsta );
	SetProcessWindowStation (hwinstaSave);
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : InstallDriver
In Parameters  : LPCTSTR szFilePath, LPCTSTR szDriverName
Out Parameters : bool
Description    :
Author         :
--------------------------------------------------------------------------------------*/
bool CMigrateRecover::InstallDriver(LPCTSTR szFilePath, LPCTSTR szDriverName)
{
#ifndef _VS60
	bool bRetVal = false;
	DWORD dw = 1;
	OutputDebugString(L">>>>> Install Driver: " + CString(szDriverName) + L", File Path: " + CString(szFilePath));
	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if (NULL == hSrvManager) 
    {
        OutputDebugString(L"OpenSCManager failed");//\n", GetLastError());
        return false;
    }
	if(hSrvManager)
	{
		SC_HANDLE hDriver = CreateService(hSrvManager, szDriverName, szDriverName, SERVICE_START | SERVICE_STOP, 
											SERVICE_KERNEL_DRIVER, SERVICE_BOOT_START, 
											SERVICE_ERROR_NORMAL, szFilePath, L"Boot Bus Extender", &dw, 0, 0, 0);
		if(hDriver != INVALID_HANDLE_VALUE)
		{
			CString cs;
			cs.Format(L"Create Service Success : %d",::GetLastError());
			OutputDebugString(cs);
			bRetVal = true;
			if(hDriver)
			{
				CloseServiceHandle(hDriver);
				hDriver = NULL;
			}
		}
		else
		{
			CString cs;
			cs.Format(L"Create Service Failed with : %d",::GetLastError());
			OutputDebugString(cs);
		}
		CloseServiceHandle(hSrvManager);
	}
	return bRetVal;
#else
	return true;
#endif
}

/*--------------------------------------------------------------------------------------
Function       : AskForRestart
In Parameters  : CString csAppPath
Out Parameters : BOOL
Description    :
Author         :
--------------------------------------------------------------------------------------*/
BOOL CMigrateRecover::AskForRestart(CString csAppPath)
{
	OutputDebugString(L"***** In AskForRestart()!");
	int iRet = 0;
	CRemoteService objRemoteSrc;
	CRegistry oReg;
	CProductInfo objProductInfo;
	TCHAR szDesc[MAX_PATH] = {0};
	CString csProductName;
	CCPUInfo objCpuInfo;		
	_tcscpy_s(szDesc, MAX_PATH, csProductName);
	_tcscat_s(szDesc, MAX_PATH, _T(" Services"));
	DWORD dwVer = 0;
	oReg.Get(CSystemInfo::m_csProductRegKey, _T("Win10"), dwVer, HKEY_LOCAL_MACHINE);
	if(dwVer == 1)
	{
		HMODULE hMonitor;
		typedef bool(*PFSTARTPPLSRV)(TCHAR *szSrvName, TCHAR *szSrvPath);
		PFSTARTPPLSRV lpStartPPLSrv;
		bool bReturn= false;
		hMonitor = LoadLibrary(UI_PPLSRVNAME);
		if(hMonitor != NULL)
		{
			lpStartPPLSrv = (PFSTARTPPLSRV)GetProcAddress(hMonitor, "StartPPLSrv");
			if(lpStartPPLSrv)
			{
				TCHAR szSrvName[MAX_PATH] = {0};
				TCHAR szSrvPath[MAX_PATH] ={0};
				_stprintf(szSrvName,_T("%s"),MAXWATCHDOG_SVC_NAME);
				_stprintf(szSrvPath,_T("%s%s"),objProductInfo.GetAppInstallPath(),MAXWATCHDOG_SVC_EXE);
				bool bRet = lpStartPPLSrv(szSrvName,szSrvPath);
			}
			else
			{
				AddLogEntry(_T(" GetProcAddress failed for StartPPLSrv."));
				bReturn = false;
			}
			FreeLibrary(hMonitor);
			hMonitor = NULL;
			lpStartPPLSrv = NULL;
		}
		else
		{
			AddLogEntry(_T("PSrvOpt.dll Load library failed!"));
			bReturn = false;
		}

	}
	else
	{
		objRemoteSrc.StartRemoteService(MAXWATCHDOG_SVC_NAME, csAppPath + MAXWATCHDOG_SVC_EXE, 16, 2, false);
		objRemoteSrc.SetFailureActionToService(MAXWATCHDOG_SVC_NAME, szDesc);
	}
	
	
	DWORD dwMajorVer = 0;
	DWORD dwMinorVer = 0;
	bool bWscSrv = false;
	objCpuInfo.GetMajorAndMinorOSVersion(dwMajorVer,dwMinorVer);
	if(dwMajorVer > 6 || (dwMajorVer == 6 && dwMinorVer >0))
	{
		bWscSrv = true;
	}

	return iRet;
}
/*--------------------------------------------------------------------------------------
Function       : CleanUpService
In Parameters  : LPCTSTR szName
Out Parameters : void
Description    :
Author         :
--------------------------------------------------------------------------------------*/
void CMigrateRecover::CleanUpService(LPCTSTR szName)
{
	CRemoteService objRemoteSrc;
	objRemoteSrc.DeleteRemoteService(szName);
	CRegistry oReg;
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Services\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Enum\\Root\\LEGACY_")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Enum\\Root\\LEGACY_")) + szName);

	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Control\\SafeBoot\\Minimal\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet001\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet002\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet003\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet004\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet005\\Control\\SafeBoot\\Network\\")) + szName);
	oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, CString(_T("SYSTEM\\CurrentControlSet006\\Control\\SafeBoot\\Network\\")) + szName);
}