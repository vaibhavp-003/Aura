#pragma once
#include <winioctl.h>
#include "MaxProtectionConst.h"

class CMaxProtectionMgr
{
	bool SendEventToFileSystemDriver(const int IOCTL_TO_SEND, const Max_Protected_Processes eRequestingProcess);
	bool SendEventToFileSystemDriverCrypt(const int IOCTL_TO_SEND, const Max_Protected_Processes eRequestingProcess);
	bool SendEventToProcessProtectionDriver(const int IOCTL_TO_SEND, const Max_Protected_Processes eRequestingProcess);
	bool SendEventToDriver(LPCTSTR szDriverName, const int IOCTL_TO_SEND, const Max_Protected_Processes eRequestingProcess);

	bool SendEventToFileSystemDriver(const int IOCTL_TO_SEND, LPCTSTR szDriveLetter);
	bool SendEventToProcessProtectionDriver(const int IOCTL_TO_SEND, LPCTSTR szDriveLetter);
	bool SendEventToDriver(LPCTSTR szDriverName, const int IOCTL_TO_SEND, LPCTSTR szDriveLetter);

	BOOL IsOS64bit(void);
	BOOL m_bIs64BitOS;
	BOOL m_bIsWindows8;
	PVOID m_pOldValue;
	typedef BOOL (WINAPI *LPFN_DISABLEWOW64REDIRECTION)(PVOID *OldValue);
	typedef BOOL (WINAPI *LPFN_REVERTWOW64REDIRECTION)(PVOID OlValue);
	LPFN_DISABLEWOW64REDIRECTION m_lpfnDisableWow64BitRedirection;
	LPFN_REVERTWOW64REDIRECTION m_lpfnRevert64BitRedirection;


	bool StopDriver(LPCTSTR szDriverName);
	bool StartDriver(LPCTSTR szDriverName);
	bool UninstallDriver(LPCTSTR szDriverName);
	bool InstallDriver(LPCTSTR szFilePath, LPCTSTR szDriverName);
	bool InstallFilterDriver(LPCTSTR strFilePath, LPCTSTR sDriverName, LPCTSTR sAltitudeID);
	bool InstallFilterDriverWithBootStart(LPCTSTR szFilePath, LPCTSTR szDriverName, LPCTSTR szAltitudeID);
	bool InstallSDManagerDriver(LPCTSTR szFilePath, LPCTSTR szDriverName);
	bool InstallMaxTDSSDriver(LPCTSTR szFilePath, LPCTSTR szDriverName);
	bool InstallNTSecureDriver(LPCTSTR szFilePath, LPCTSTR szDriverName);

	bool IsCompatableOS();
	bool GetMajorAndMinorOSVersion(DWORD &dwMajorVersion, DWORD &dwMinorVersion);
	bool CheckIfRegisterCallbackAvailable();

public:
	CMaxProtectionMgr(void);
	virtual ~CMaxProtectionMgr(void);

	bool RegisterProcessID(Max_Protected_Processes eProcessToRegister);
	bool RegisterProcessIDCrypt(Max_Protected_Processes eProcessToRegister);
	bool RegisterProcessSetup(Max_Protected_Processes eProcessToRegister);
	bool RegisterProcessSetupOFF(Max_Protected_Processes eProcessToRegister);
	bool PauseProtection();
	bool ResumeProtection();
	bool PauseProtectionCrypt();
	bool ResumeProtectionCrypt();

	bool ResumeProtectionNetwork();
	bool PauseProtectionNetwork();

	//Tushar : 12 Oct 2018 for Folder Secure control
	bool StartFolderSecProtection();
	bool StopFolderSecProtection();

	bool CopyProtectionDrivers(CString csSourcePath, CString csDestinationPath);
	bool InstallProtectionBeforeMemScan(CString csAppPath);
	bool InstallElamDriver();
	bool StartFSDriver();
	bool InstallProtectionAfterMemScan(CString csAppPath);
	bool StartProtection();

	// ********************
	// This function is implemented for MaxProtection.exe! 
	// Dont use this function in any other Module! You may get a blue screen!
	// Instead use RemoveProtection function to gracefully remove the protection driver!
	bool StopProtection();
	// ********************

	bool ReloadINI();
	bool StartStopLogging(BOOL bStart);
	bool RemoveProtection();

	bool GetBlockAutoRunStatus(DWORD &dwBlockingON);
	bool SetBlockAutoRunStatus(DWORD dwBlockingON);
	bool GetProtectSysRegKeyStatus(DWORD &dwBlockingON);
	bool SetProtectSysRegKeyStatus(DWORD dwBlockingON);
	bool BlockDriverLetter(LPCTSTR szDriveLetter);
	bool AllowDriverLetter(LPCTSTR szDriveLetter);
	bool DisconnectDriverLetter(LPCTSTR szDriveLetter);
};
