// MaxPPMigrateSD.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include "MaxPPMigrateSD.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif



BEGIN_MESSAGE_MAP(CMaxPPMigrateSDApp, CWinApp)
END_MESSAGE_MAP()


// CMaxPPMigrateSDApp construction

CMaxPPMigrateSDApp::CMaxPPMigrateSDApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CMaxPPMigrateSDApp object

CMaxPPMigrateSDApp theApp;


// CMaxPPMigrateSDApp initialization

BOOL CMaxPPMigrateSDApp::InitInstance()
{
	CWinApp::InitInstance();

	return TRUE;
}


bool CMaxPPMigrateSDApp::StartRemoteService(CString csServiceName, CString csAppPath,
	DWORD dwServiceType, DWORD dwStartType,
	bool bSleep, bool bRegister)
{
	SERVICE_LAUNCH_PROTECTED_INFO Info;
	// Open remote Service Manager
	SC_HANDLE hSCM = ::OpenSCManager(NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);
	if (hSCM == NULL)
	{
		//AfxMessageBox(L"OpenSCManager failed");
		return false;
	}

	// Maybe it's already there and installed, let's try to run
	SC_HANDLE hService = ::OpenService(hSCM, csServiceName, SERVICE_ALL_ACCESS);

	// Creates service on remote machine, if it's not installed yet
	if (hService == NULL)
	{
		Info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
		hService = ::CreateService(hSCM, csServiceName, csServiceName, SERVICE_ALL_ACCESS,
			dwServiceType, dwStartType, SERVICE_ERROR_NORMAL, csAppPath,
			NULL, NULL, NULL, NULL, NULL);

		if (ChangeServiceConfig2(hService,
			SERVICE_CONFIG_LAUNCH_PROTECTED,
			&Info) == FALSE)
		{
			DWORD dwResult = GetLastError();
			CString csLog;
			csLog.Format(L"Failed ChangeServiceConfig2 : %d", dwResult);
			//OutputDebugString(csLog);
		}
	}
	else
	{
		SERVICE_LAUNCH_PROTECTED_INFO Info;
		DWORD dwSize = 0;
		if (QueryServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, (LPBYTE)&Info, sizeof(Info), &dwSize) == TRUE)
		{
			if (Info.dwLaunchProtected != SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT)
			{
				Info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
				if (ChangeServiceConfig2(hService,
					SERVICE_CONFIG_LAUNCH_PROTECTED,
					&Info) == FALSE)
				{
					DWORD dwResult = GetLastError();
					CString csLog;
					csLog.Format(L"Failed ChangeServiceConfig2 : %d", dwResult);
					//OutputDebugString(csLog);
				}
			}
		}
		else
		{
			Info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
			if (ChangeServiceConfig2(hService,
				SERVICE_CONFIG_LAUNCH_PROTECTED,
				&Info) == FALSE)
			{
				DWORD dwResult = GetLastError();
				CString csLog;
				csLog.Format(L"Failed ChangeServiceConfig2 : %d", dwResult);
				//OutputDebugString(csLog);
			}
		}
	}

	if (hService == NULL)
	{
		::CloseServiceHandle(hSCM);
		return false;
	}
	// Start service
	if (!::StartService(hService, 0, NULL))
	{
		::CloseServiceHandle(hService);
		::CloseServiceHandle(hSCM);
		return false;
	}

	::CloseServiceHandle(hService);
	::CloseServiceHandle(hSCM);
	if (bSleep)
		Sleep(2000); //Give the service some time to Start up!

	return true;
}

bool CMaxPPMigrateSDApp::ChangeRemoteService(CString csServiceName)
{
	SERVICE_LAUNCH_PROTECTED_INFO Info;
	// Open remote Service Manager
	SC_HANDLE hSCM = ::OpenSCManager(NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);
	if (hSCM == NULL)
	{
		return false;
	}

	// Maybe it's already there and installed, let's try to run
	SC_HANDLE hService = ::OpenService(hSCM, csServiceName, SERVICE_ALL_ACCESS);

	// Creates service on remote machine, if it's not installed yet
	if (hService != NULL)
	{
		Info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_NONE;
		
		if (ChangeServiceConfig2(hService,
			SERVICE_CONFIG_LAUNCH_PROTECTED,
			&Info) == FALSE)
		{
			DWORD dwResult = GetLastError();
			CString csLog;
			csLog.Format(L"Failed ChangeServiceConfig2 : %d", dwResult);
			//OutputDebugString(csLog);
		}
		
	}
	if (hService == NULL)
	{
		::CloseServiceHandle(hSCM);
		return false;
	}
		
	::CloseServiceHandle(hService);
	::CloseServiceHandle(hSCM);

	return true;
}

bool CMaxPPMigrateSDApp::StartPPLService(TCHAR *szSrvName, TCHAR *szSrvPath)
{
	bool bReturn = false;

	HANDLE FileHandle = NULL;
	TCHAR lpszPath[MAX_PATH + 1] = { 0 };
	try
	{	
		GetSystemDirectory(lpszPath, MAX_PATH + 1);
	}
	catch (...)
	{
		OutputDebugString(_T("Exception caught in StartPPLService"));
	}
	CString csDriverPath;
	csDriverPath.Format(_T("%s\\drivers\\AuSecPPLElm.sys"), lpszPath);
	FileHandle = CreateFile(csDriverPath,
		FILE_READ_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (FileHandle == NULL)
	{
		OutputDebugString(L"HANDLE error: AuSecPPLElm");
	}
	else if (InstallELAMCertificateInfo(FileHandle) == FALSE)
	{
		DWORD Result = GetLastError();
		CString cslog;
		cslog.Format(L"Failed InstallElamCertificateInfo error:%d", Result);
		OutputDebugString(cslog);

	}
	
	bReturn = StartRemoteService(szSrvName, szSrvPath, 16, 2, true);
	return bReturn;
}
 
extern "C" __declspec(dllexport) bool StartPPLSrv(TCHAR *szSrvName, TCHAR *szSrvPath)
{
	return theApp.StartPPLService(szSrvName,szSrvPath);
}

extern "C" __declspec(dllexport) bool ChangePPLSrv(TCHAR *szSrvName)
{
	return theApp.ChangeRemoteService(szSrvName);
}