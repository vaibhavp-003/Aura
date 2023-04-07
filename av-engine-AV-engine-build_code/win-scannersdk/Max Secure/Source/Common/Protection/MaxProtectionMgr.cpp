#include "pch.h"
#include <atlbase.h>
#include <winsvc.h>
#include "MaxProtectionMgr.h"
#pragma warning(disable : 4996)
BOOL m_bIsWindows7;

const LPCTSTR BLOCKAUTORUN			= _T("BlockAutorun");
const LPCTSTR PROTECT_SYS_REG_VALUE	= _T("ProtectSystemRegistry");


CMaxProtectionMgr::CMaxProtectionMgr(void):
					m_lpfnDisableWow64BitRedirection(NULL), m_pOldValue(NULL),
					m_lpfnRevert64BitRedirection(NULL), m_bIs64BitOS(FALSE), m_bIsWindows8(FALSE)
{
	m_bIsWindows7 = FALSE;	
	IsOS64bit();
	DWORD dwMajorVersion = 0, dwMinorVersion = 0;
	GetMajorAndMinorOSVersion(dwMajorVersion, dwMinorVersion);
	if(dwMajorVersion == 6 && dwMinorVersion == 2)
	{
		m_bIsWindows8 = TRUE;		
	}
	if(dwMajorVersion < 6)
	{
		m_bIsWindows7 = TRUE;		
	}
	else if (dwMajorVersion == 6 && dwMinorVersion < 1)
	{
		m_bIsWindows7 = TRUE;		
	}

}

CMaxProtectionMgr::~CMaxProtectionMgr(void)
{
}

bool CMaxProtectionMgr::SendEventToDriver(LPCTSTR szDriverName, const int IOCTL_TO_SEND, const Max_Protected_Processes eRequestingProcess)
{
	HANDLE hDriver = CreateFile(szDriverName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if(hDriver != INVALID_HANDLE_VALUE)
	{
		OutputDebugString(L">>>>> Successfully Created a handle to the driver: " + CString(szDriverName));
		DWORD dw = (DWORD)eRequestingProcess;
		if(DeviceIoControl(hDriver, IOCTL_TO_SEND, &dw, sizeof(dw), 0, 0, &dw, 0))
		{	
			OutputDebugString(L">>>>> Successfully sent the message to the driver: " + CString(szDriverName));
		}
		else
		{	
			OutputDebugString(L">>>>> Failed to send the message to the driver: " + CString(szDriverName));
		}
		CloseHandle(hDriver);
		hDriver = INVALID_HANDLE_VALUE;
		return true;
	}
	else
	{
		OutputDebugString(L">>>>> Failed to create a handle to the driver: " + CString(szDriverName));
	}
	return false;
}

bool CMaxProtectionMgr::SendEventToFileSystemDriver(const int IOCTL_TO_SEND, const Max_Protected_Processes eRequestingProcess)
{
	SendEventToDriver(ACTMON_DRIVE_SYMBOLIC, IOCTL_TO_SEND, eRequestingProcess);
	return SendEventToDriver(MAXPROTECTOR_DRIVE_SYMBOLIC, IOCTL_TO_SEND, eRequestingProcess);
}

bool CMaxProtectionMgr::SendEventToFileSystemDriverCrypt(const int IOCTL_TO_SEND, const Max_Protected_Processes eRequestingProcess)
{
	SendEventToDriver(ACTMON_DRIVE_SYMBOLIC, IOCTL_TO_SEND, eRequestingProcess);
	return false;
}

bool CMaxProtectionMgr::SendEventToProcessProtectionDriver(const int IOCTL_TO_SEND, const Max_Protected_Processes eRequestingProcess)
{
	return false;
}

bool CMaxProtectionMgr::PauseProtection()
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_PAUSE_PROTECTION, MAX_PROC_MAXPROTECTOR);
	bStatus = (SendEventToProcessProtectionDriver(IOCTL_PAUSE_PROTECTION, MAX_PROC_MAXPROTECTOR) && bStatus ? true : false);
	return bStatus;
}
bool CMaxProtectionMgr::PauseProtectionCrypt()
{
	bool bStatus = SendEventToFileSystemDriverCrypt(IOCTL_PAUSE_CRYPT_PROTECTION, MAX_PROC_MAXPROTECTOR);
	return bStatus;
}
bool CMaxProtectionMgr::ResumeProtectionCrypt()
{
	bool bStatus = SendEventToFileSystemDriverCrypt(IOCTL_RESUME_CRYPT_PROTECTION, MAX_PROC_MAXPROTECTOR);
	return bStatus;
}

bool CMaxProtectionMgr::PauseProtectionNetwork()
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_PAUSE_NETWORK_PROTECTION, MAX_PROC_MAXPROTECTOR);
	return bStatus;
}
bool CMaxProtectionMgr::ResumeProtectionNetwork()
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_RESUME_NETWORK_PROTECTION, MAX_PROC_MAXPROTECTOR);
	return bStatus;
}

bool CMaxProtectionMgr::ResumeProtection()
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_RESUME_PROTECTION, MAX_PROC_MAXPROTECTOR);
	bStatus = (SendEventToProcessProtectionDriver(IOCTL_RESUME_PROTECTION, MAX_PROC_MAXPROTECTOR) && bStatus ? true : false);
	return bStatus;
}

bool CMaxProtectionMgr::StartFolderSecProtection()
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_RELOAD_INI, MAX_PROC_MAXPROTECTOR);
	return bStatus;
}

bool CMaxProtectionMgr::StopFolderSecProtection()
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_STOP_FOLDER_SECURE, MAX_PROC_MAXPROTECTOR);
	return bStatus;
}

bool CMaxProtectionMgr::RegisterProcessID(Max_Protected_Processes eProcessToRegister)
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_REGISTER_PROCESSID, eProcessToRegister);
	bStatus = (SendEventToProcessProtectionDriver(IOCTL_REGISTER_PROCESSID, eProcessToRegister) && bStatus ? true : false);
	return bStatus;
}

bool CMaxProtectionMgr::RegisterProcessSetup(Max_Protected_Processes eProcessToRegister)
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_INSTALL_PROTECTION, eProcessToRegister);
	return bStatus;
}
bool CMaxProtectionMgr::RegisterProcessSetupOFF(Max_Protected_Processes eProcessToRegister)
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_STOP_INSTALL_PROTECTION, eProcessToRegister);
	return bStatus;
}
bool CMaxProtectionMgr::RegisterProcessIDCrypt(Max_Protected_Processes eProcessToRegister)
{
	bool bStatus = SendEventToFileSystemDriverCrypt(IOCTL_REGISTER_PROCESSID, eProcessToRegister);
	return bStatus;
}

BOOL CMaxProtectionMgr::IsOS64bit(void)
{
	m_bIs64BitOS = FALSE;
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
		if(!fnIsWow64Process(GetCurrentProcess(),&m_bIs64BitOS))
		{
			m_bIs64BitOS = FALSE;
		}
	}
	if(m_bIs64BitOS)
	{
		OutputDebugString(L"##### IS x64 OS #####\n");
		if(!m_lpfnDisableWow64BitRedirection)
		{
			m_lpfnDisableWow64BitRedirection = (LPFN_DISABLEWOW64REDIRECTION)GetProcAddress(hModule, "Wow64DisableWow64FsRedirection");
		}

		if(!m_lpfnRevert64BitRedirection)
		{
			m_lpfnRevert64BitRedirection = (LPFN_REVERTWOW64REDIRECTION)GetProcAddress(hModule, "Wow64RevertWow64FsRedirection");
		}
	}
	return m_bIs64BitOS;
}

bool CMaxProtectionMgr::CopyProtectionDrivers(CString csSourcePath, CString csDestinationPath)
{
	if(m_lpfnDisableWow64BitRedirection)
	{
		m_lpfnDisableWow64BitRedirection(&m_pOldValue);
	}

	CopyFile(csSourcePath + MAXPROTECTOR_DRIVE_FILENAME, csDestinationPath + MAXPROTECTOR_DRIVE_FILENAME,false);
	CopyFile(csSourcePath + ACTMON_DRIVE_FILENAME, csDestinationPath + ACTMON_DRIVE_FILENAME, false);
	CopyFile(csSourcePath + MAXMGR_DRIVE_FILENAME, csDestinationPath + MAXMGR_DRIVE_FILENAME, false);
	
	if(m_lpfnRevert64BitRedirection)
	{
		m_lpfnRevert64BitRedirection(m_pOldValue);
	}
	return true;
}

bool CMaxProtectionMgr::InstallProtectionBeforeMemScan(CString csAppPath)
{
	InstallFilterDriverWithBootStart(CString(L"System32\\drivers\\") + ACTMON_DRIVE_FILENAME, ACTMON_DRIVE_TITLE, L"328600");
	return true;
}

bool CMaxProtectionMgr::InstallElamDriver()
{
	CString csDrvPath ;
	csDrvPath.Format(_T("System32\\drivers\\%s"), ELAM_DRIVE_FILENAME);
	CString csDrvTitle = ELAM_DRIVE_TITLE;
	#ifndef _VS60
	bool bRetVal = false;
	OutputDebugString(L">>>>> Install Driver: " + csDrvTitle + L", File Path: " + csDrvPath);
	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if (hSrvManager)
	{
		SC_HANDLE hDriver = CreateService(hSrvManager, csDrvTitle, csDrvTitle,
			SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_BOOT_START,
			SERVICE_ERROR_CRITICAL, csDrvPath, L"Early-Launch", 0, NULL, 0, 0);
		if (hDriver != INVALID_HANDLE_VALUE)
		{
			bRetVal = true;
			if (hDriver)
			{
				CloseServiceHandle(hDriver);
				hDriver = NULL;
			}
		}
		CloseServiceHandle(hSrvManager);
	}
	return bRetVal;
#else
	return true;
#endif
	return true;
}

bool CMaxProtectionMgr::InstallProtectionAfterMemScan(CString csAppPath)
{
	InstallSDManagerDriver(MAXMGR_DRIVE_TITLE,  CString(L"System32\\drivers\\") + MAXMGR_DRIVE_FILENAME);

	bool bIsFunctionAvailable = CheckIfRegisterCallbackAvailable();

	InstallFilterDriver(CString(L"System32\\drivers\\") + MAXPROTECTOR_DRIVE_FILENAME, MAXPROTECTOR_DRIVE_TITLE, MAXPROTECTOR_DRIVE_ALTITUDEID);
	return true;
}

bool CMaxProtectionMgr::StartProtection()
{
	StartDriver(MAXMGR_DRIVE_TITLE);
	StartDriver(ACTMON_DRIVE_TITLE);

	StartDriver(MAXPROTECTOR_DRIVE_TITLE);

	return true;
}
bool CMaxProtectionMgr::StartFSDriver()
{
	return true;
}

bool CMaxProtectionMgr::SetBlockAutoRunStatus(DWORD dwBlockingON)
{
	CRegKey objReg;
if(objReg.Create(HKEY_LOCAL_MACHINE, MAX_PROTECTOR_REG_KEY) != ERROR_SUCCESS)
	{
		return false;
	}
	
	
	objReg.SetDWORDValue(BLOCKAUTORUN, dwBlockingON);
	objReg.Close();
	return true;
}

bool CMaxProtectionMgr::GetBlockAutoRunStatus(DWORD &dwBlockingON)
{
	dwBlockingON = 0;
	CRegKey objReg;
if(objReg.Open(HKEY_LOCAL_MACHINE, MAX_PROTECTOR_REG_KEY, KEY_READ) != ERROR_SUCCESS)
	{
		return false;
	}
	
	objReg.QueryDWORDValue(BLOCKAUTORUN, dwBlockingON);
	objReg.Close();
	return true;
}

bool CMaxProtectionMgr::SetProtectSysRegKeyStatus(DWORD dwBlockingON)
{
	CRegKey objReg;
	if(objReg.Create(HKEY_LOCAL_MACHINE, MAX_PROTECTOR_REG_KEY) != ERROR_SUCCESS)
	{
		return false;
	}
	
	
	objReg.SetDWORDValue(PROTECT_SYS_REG_VALUE, dwBlockingON);
	objReg.Close();
	return true;
}

bool CMaxProtectionMgr::GetProtectSysRegKeyStatus(DWORD &dwBlockingON)
{
	dwBlockingON = 0;
	CRegKey objReg;
if(objReg.Open(HKEY_LOCAL_MACHINE, MAX_PROTECTOR_REG_KEY, KEY_READ) != ERROR_SUCCESS)
	{
		return false;
	}
	
	objReg.QueryDWORDValue(PROTECT_SYS_REG_VALUE, dwBlockingON);
	objReg.Close();
	return true;
}

bool CMaxProtectionMgr::StopProtection()
{
	StopDriver(MAXPROTECTOR_DRIVE_TITLE);

	StopDriver(ACTMON_DRIVE_TITLE);
	StopDriver(MAXMGR_DRIVE_TITLE);

	RemoveProtection();
	return true;
}

bool CMaxProtectionMgr::RemoveProtection()
{
	PauseProtection();

	UninstallDriver(MAXPROTECTOR_DRIVE_TITLE);
	UninstallDriver(ACTMON_DRIVE_TITLE);
	UninstallDriver(MAXMGR_DRIVE_TITLE);

	return true;
}

bool CMaxProtectionMgr::SendEventToDriver(LPCTSTR szDriverName, const int IOCTL_TO_SEND, LPCTSTR szDriveLetter)
{
	if(!szDriveLetter)
		return false;

	if(!szDriveLetter[0])
		return false;

	HANDLE hDriver = CreateFile(szDriverName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if(hDriver != INVALID_HANDLE_VALUE)
	{
		OutputDebugString(L">>>>> Successfully Created a handle to the driver: " + CString(szDriverName));
		DWORD dw = 0;
		WCHAR wDriveLetter[2] = {0};
		wDriveLetter[0] = szDriveLetter[0];
		if(DeviceIoControl(hDriver, IOCTL_TO_SEND, &wDriveLetter, sizeof(wDriveLetter), 0, 0, &dw, 0))
		{	
			OutputDebugString(L">>>>> Successfully sent the message to the driver: " + CString(szDriverName));
		}
		else
		{	
			OutputDebugString(L">>>>> Failed to send the message to the driver: " + CString(szDriverName));
		}
		CloseHandle(hDriver);
		hDriver = INVALID_HANDLE_VALUE;
		return true;
	}
	else
	{
		OutputDebugString(L">>>>> Failed to create a handle to the driver: " + CString(szDriverName));
	}
	return false;
}

bool CMaxProtectionMgr::SendEventToFileSystemDriver(const int IOCTL_TO_SEND, LPCTSTR szDriveLetter)
{
	return SendEventToDriver(MAXPROTECTOR_DRIVE_SYMBOLIC, IOCTL_TO_SEND, szDriveLetter);
}

bool CMaxProtectionMgr::SendEventToProcessProtectionDriver(const int IOCTL_TO_SEND, LPCTSTR szDriveLetter)
{
	return false;
}

bool CMaxProtectionMgr::BlockDriverLetter(LPCTSTR szDriveLetter)
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_BLOCK_USB_DRIVE, szDriveLetter);
	bStatus = (SendEventToProcessProtectionDriver(IOCTL_BLOCK_USB_DRIVE, szDriveLetter) && bStatus ? true : false);
	return bStatus;
}

bool CMaxProtectionMgr::AllowDriverLetter(LPCTSTR szDriveLetter)
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_UNBLOCK_USB_DRIVE, szDriveLetter);
	bStatus = (SendEventToProcessProtectionDriver(IOCTL_UNBLOCK_USB_DRIVE, szDriveLetter) && bStatus ? true : false);
	return bStatus;
}

bool CMaxProtectionMgr::DisconnectDriverLetter(LPCTSTR szDriveLetter)
{
	bool bStatus = SendEventToFileSystemDriver(IOCTL_DISCONNECT_USB_DRIVE, szDriveLetter);
	bStatus = (SendEventToProcessProtectionDriver(IOCTL_DISCONNECT_USB_DRIVE, szDriveLetter) && bStatus ? true : false);
	return bStatus;
}

bool CMaxProtectionMgr::InstallFilterDriver(LPCTSTR szFilePath, LPCTSTR szDriverName, LPCTSTR szAltitudeID)
{
#ifndef _VS60
	bool bRetVal = false;
	OutputDebugString(L">>>>> Install Driver: " + CString(szDriverName) + L", File Path: " + CString(szFilePath) + L", AltitudeID: " + CString(szAltitudeID));
	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if(hSrvManager)
	{
		SC_HANDLE hDriver = CreateService(hSrvManager, szDriverName, szDriverName, 
										SERVICE_ALL_ACCESS, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_BOOT_START, 
										SERVICE_ERROR_NORMAL, szFilePath, L"FSFilter Anti-Virus", 0, 0, 0, 0);
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
	if(bRetVal)
	{
		bRetVal = false;
		CString csInstancePath = _T("system\\currentcontrolset\\services\\") + CString(szDriverName) +(_T("\\Instances"));
		CString csAltitudePath = csInstancePath + _T("\\") + CString(szDriverName) + _T(" Instance");

		CRegKey objReg;
		if(objReg.Create(HKEY_LOCAL_MACHINE, csInstancePath) == ERROR_SUCCESS)
		{
			objReg.SetStringValue(L"DefaultInstance", CString(szDriverName) + _T(" Instance"));
			objReg.Close();
			if(objReg.Create(HKEY_LOCAL_MACHINE, csAltitudePath) == ERROR_SUCCESS)
			{
				objReg.SetStringValue(L"Altitude", szAltitudeID);
				objReg.SetDWORDValue(L"Flags", 0);
				objReg.Close();
				bRetVal = true;
			}
		}
	}
	return bRetVal;
#else
	return true;
#endif
}

bool CMaxProtectionMgr::InstallDriver(LPCTSTR szFilePath, LPCTSTR szDriverName)
{
#ifndef _VS60
	bool bRetVal = false;
	OutputDebugString(L">>>>> Install Driver: " + CString(szDriverName) + L", File Path: " + CString(szFilePath));
	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if(hSrvManager)
	{
		DWORD dwStartType = SERVICE_SYSTEM_START;
		//if(!IsCompatableOS())
		//	dwStartType = SERVICE_SYSTEM_START;
		SC_HANDLE hDriver = CreateService(hSrvManager, szDriverName, szDriverName, SERVICE_START | SERVICE_STOP, 
											SERVICE_KERNEL_DRIVER, dwStartType, 
											SERVICE_ERROR_NORMAL, szFilePath, L"Base", 0, 0, 0, 0);
		if(hDriver != INVALID_HANDLE_VALUE)
		{
			bRetVal = true;
			CloseServiceHandle(hDriver);
		}
		CloseServiceHandle(hSrvManager);
	}
	return bRetVal;
#else
	return true;
#endif
}

bool CMaxProtectionMgr::StartDriver(LPCTSTR szDriverName)
{
	bool bRetVal = false;
	OutputDebugString(L">>>>> Start Driver: " + CString(szDriverName));
	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hDriver = OpenService(hSrvManager, szDriverName, SERVICE_START);

	if(hDriver)
	{
		bRetVal =(StartService(hDriver, 0, 0) == FALSE ? false : true);
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

bool CMaxProtectionMgr::StopDriver(LPCTSTR szDriverName)
{
	bool bRetVal = false;
	OutputDebugString(L">>>>> Stop Driver: " + CString(szDriverName));
	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hDriver = OpenService(hSrvManager, szDriverName, SERVICE_STOP);

	if(hDriver)
	{
		SERVICE_STATUS_PROCESS ssp = {0};
		bRetVal =(ControlService(hDriver, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS) &ssp) == FALSE ? false : true);
		CloseServiceHandle(hDriver);
		CloseServiceHandle(hSrvManager);
	}
	return bRetVal;
}

bool CMaxProtectionMgr::UninstallDriver(LPCTSTR szDriverName)
{
	OutputDebugString(L">>>>> Uninstall Driver: " + CString(szDriverName));
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(hSCM == NULL)
	{
		return FALSE;
	}

	SC_HANDLE hService = ::OpenService(hSCM, szDriverName, SERVICE_ALL_ACCESS);
	if(hService == NULL)
	{
		::CloseServiceHandle(hSCM);
		return FALSE;
	}

	DeleteService(hService);
	::CloseServiceHandle(hSCM);
	::CloseServiceHandle(hService);
	return TRUE;
}

bool CMaxProtectionMgr::GetMajorAndMinorOSVersion(DWORD &dwMajorVersion, DWORD &dwMinorVersion)
{
	static DWORD dwMajor = 0;
	static DWORD dwMinor = 0;
	dwMajorVersion = dwMinorVersion = 0;
	if(dwMajor == 0)
	{
		LPOSVERSIONINFOEXW lpOSVersionInfo = new OSVERSIONINFOEX;
		ZeroMemory(lpOSVersionInfo, sizeof(OSVERSIONINFOEX));
		lpOSVersionInfo->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

		//To get extended information about the version of the operating system that currently running
		if(GetVersionEx((OSVERSIONINFO *)lpOSVersionInfo) == 0)
		{
			//this api fails in case of windows 98 first version so taking the os version from registry.
			delete lpOSVersionInfo;
			return false;
		}
	
		dwMajor = lpOSVersionInfo->dwMajorVersion;
		dwMinor = lpOSVersionInfo->dwMinorVersion;

		CString csTemp;
		csTemp.Format(L">>>>> Major: %d, Minor: %d", dwMajor, dwMinor);
		OutputDebugString(csTemp);

		delete lpOSVersionInfo;
		lpOSVersionInfo = NULL;
	}
	dwMajorVersion = dwMajor;
	dwMinorVersion = dwMinor;
	return true;
}

bool CMaxProtectionMgr::IsCompatableOS()
{
	DWORD dwMajorVersion = 0, dwMinorVersion = 0;
	if(!GetMajorAndMinorOSVersion(dwMajorVersion, dwMinorVersion))
	{
		return false;
	}

	if(dwMajorVersion < 5)
	{
		return false;
	}

	if((dwMajorVersion == 5) && (dwMinorVersion == 0))
	{
		return false;
	}

	if((dwMajorVersion == 5) && (dwMinorVersion == 1))	// XP - Handling with and without service pack!
	{
		DWORD dwType = 0;
		CRegKey objReg;
		if(objReg.Open(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\FltMgr"), KEY_READ) != ERROR_SUCCESS)
		{
			return false;
		}
		objReg.QueryDWORDValue(_T("Type"), dwType);
		objReg.Close();
		if(dwType == 0)	// type is filter driver
		{
			return false;
		}
	}
	return true;
}

bool CMaxProtectionMgr::InstallFilterDriverWithBootStart(LPCTSTR szFilePath, LPCTSTR szDriverName, LPCTSTR szAltitudeID)
{
#ifndef _VS60
	bool bRetVal = false;
	OutputDebugString(L">>>>> Install Driver: " + CString(szDriverName) + L", File Path: " + CString(szFilePath) + L", AltitudeID: " + CString(szAltitudeID));
	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if(hSrvManager)
	{
		SC_HANDLE hDriver = CreateService(hSrvManager, szDriverName, szDriverName, 
										SERVICE_ALL_ACCESS, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_BOOT_START, 
										SERVICE_ERROR_NORMAL, szFilePath, L"FSFilter Anti-Virus", 0, L"FltMgr\0\0", 0, 0);
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
	if(bRetVal)
	{
		bRetVal = false;
		CString csInstancePath = _T("system\\currentcontrolset\\services\\") + CString(szDriverName) +(_T("\\Instances"));
		CString csAltitudePath = csInstancePath + _T("\\") + CString(szDriverName) + _T(" Instance");

		CRegKey objReg;
		if(objReg.Create(HKEY_LOCAL_MACHINE, csInstancePath) == ERROR_SUCCESS)
		{
			objReg.SetStringValue(L"DefaultInstance", CString(szDriverName) + _T(" Instance"));
			objReg.Close();
			if(objReg.Create(HKEY_LOCAL_MACHINE, csAltitudePath) == ERROR_SUCCESS)
			{
				objReg.SetStringValue(L"Altitude", szAltitudeID);
				objReg.SetDWORDValue(L"Flags", 0);
				objReg.Close();
				bRetVal = true;
			}
		}
	}
	return bRetVal;
#else
	return true;
#endif
}

bool CMaxProtectionMgr::InstallSDManagerDriver(LPCTSTR csName, LPCTSTR csPath)
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

bool CMaxProtectionMgr::CheckIfRegisterCallbackAvailable()
{
	bool bReturnVal = false;
	if(m_bIsWindows8)
	{
		return true;
	}
#ifdef WIN64
	HMODULE hModule = LoadLibrary(L"ntoskrnl.exe");
	if(!hModule)
		return bReturnVal;

	LPVOID lpVoid = GetProcAddress(hModule, "CmRegisterCallback");

	if(lpVoid)
		bReturnVal = true;

	FreeLibrary(hModule);
#else
	//if(m_bIs64BitOS || m_bIsWindows8)
	{
		HMODULE hModule = LoadLibrary(L"ntoskrnl.exe");
		if(!hModule)
			return bReturnVal;

		LPVOID lpVoid = GetProcAddress(hModule, "CmRegisterCallback");

		if(lpVoid)
			bReturnVal = true;

		FreeLibrary(hModule);
	}
#endif
	return bReturnVal;
}


bool CMaxProtectionMgr::ReloadINI()
{
	return SendEventToDriver(MAXPROTECTOR_DRIVE_SYMBOLIC, IOCTL_RELOAD_INI, MAX_PROC_MAXPROTECTOR);
	
	return true;
}

bool CMaxProtectionMgr::StartStopLogging(BOOL bStart)
{
	if (bStart  == TRUE)
	{
		return SendEventToDriver(ACTMON_DRIVE_SYMBOLIC, IOCTL_START_LOGGING, MAX_PROC_MAXPROTECTOR);
	}
	else
	{
		return SendEventToDriver(ACTMON_DRIVE_SYMBOLIC, IOCTL_STOP_LOGGING, MAX_PROC_MAXPROTECTOR);
	}
}


bool CMaxProtectionMgr::InstallMaxTDSSDriver(LPCTSTR szFilePath, LPCTSTR szDriverName)
{
#ifdef WIN64
	return false;
#else
	if(m_bIs64BitOS || m_bIsWindows8)
		return false;

	DWORD dwMajorVer, dwMinorVer = 0;
	GetMajorAndMinorOSVersion(dwMajorVer, dwMinorVer);
	if(dwMajorVer == 5 && dwMinorVer > 0)	// only XP any service pack!
	{
#ifndef _VS60
      bool bRetVal = false;
      DWORD dw = 8;
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
                                                                  SERVICE_ERROR_NORMAL, szFilePath, L"Base", 0, 0, 0, 0);
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
#endif

	return false;
}

bool CMaxProtectionMgr::InstallNTSecureDriver(LPCTSTR szFilePath, LPCTSTR szDriverName)
{
#ifdef WIN64
	return false;
#else
	if(m_bIs64BitOS  || m_bIsWindows8)
		return false;

	DWORD dwMajorVer, dwMinorVer = 0;
	GetMajorAndMinorOSVersion(dwMajorVer, dwMinorVer);
	if(dwMajorVer == 5 && dwMinorVer > 0)	// only XP any service pack!
	{
#ifndef _VS60
      bool bRetVal = false;
      DWORD dw = 8;
      OutputDebugString(L">>>>> Install Driver: " + CString(szDriverName) + L", File Path: " + CString(szFilePath));
      SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
      if (NULL == hSrvManager) 
    {
        OutputDebugString(L"OpenSCManager failed");//\n", GetLastError());
        return false;
    }
      if(hSrvManager)
      {
          DWORD dwTagID = 8;  
		  SC_HANDLE hDriver = CreateService(hSrvManager, szDriverName, szDriverName, SERVICE_START | SERVICE_STOP, 
                                                                  SERVICE_KERNEL_DRIVER, SERVICE_BOOT_START, 
                                                                  SERVICE_ERROR_NORMAL, szFilePath, L"Boot Bus Extender", &dwTagID, 0, 0, 0);
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
#endif

	return false;
}
