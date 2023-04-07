/*======================================================================================
FILE             : SDMonitor.h
ABSTRACT         : Class to handle all active monitor related operations
DOCUMENTS        : 
AUTHOR           : Avinash Bhardwaj
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 07/09/2008
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
#include "SDMonitor.h"
#include "SDActMonService.h"
#include <Tlhelp32.h>
#include "MaxExceptionFilter.h"
#include "SDSystemInfo.h"
#include "ProductInfo.h"
#include "UninstallProducts.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CSDMonitor
In Parameters  : 
Out Parameters : 
Description    : Constructor
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CSDMonitor::CSDMonitor():m_bLoadedSuccessfully(false)
{
	m_pProcHandler = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : ~CSDMonitor
In Parameters  : 
Out Parameters : 
Description    : Stops protection before destructing itself
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CSDMonitor::~CSDMonitor()
{
	StopProtection();
}

/*-------------------------------------------------------------------------------------
	Function		: SetQuarantineFlag
	In Parameters	: -
	Out	Parameters	: void
	Purpose			: to set the quarantine flag
	Author			: Nilesh Dorge
--------------------------------------------------------------------------------------*/
void CSDMonitor::SetRegistrationFlag(int iControlFlag)
{
	DWORD dw;
	CRegistry objReg;

	if(iControlFlag == 0)	//Evaluation period Expired		
	{	
		dw = 1;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
	}
	if(iControlFlag == -1)	//registered product and for evaluation
	{
		dw = 0;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
	}
	if(CSystemInfo::m_iVirusScanFlag)
	{
		if(iControlFlag > 0)	//registered product and for evaluation
		{
			dw = 0;
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
		}
	}
	else if(iControlFlag > 0)	//Evaluation period Expired
	{
		dw = 1;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
	}
}


/*-------------------------------------------------------------------------------------
	Function		: StartProtection
	In Parameters	: -
	Out	Parameters	: Bool : true if protection started else false
	Purpose			: starts active protection for registered user
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
BOOL CSDMonitor::StartProtection()
{
	//AddLogEntry(L">>>>> StartProtection!", 0, 0, true, LOG_WARNING);

	bool isRegistered =  CheckRegistration();
	m_bLoadedSuccessfully = LoadActiveMonitorDLL();
	if(!isRegistered)
	{
		SetActiveMonitorOff();
	}
	else //Enable Active Monitor
	{
		EnableMonitors();
	}
	//AddLogEntry(L"<<<<< StartProtection!", 0, 0, true, LOG_WARNING);
	return true ;
	
}

/*-------------------------------------------------------------------------------------
	Function		: SetActiveMonitorOn
	In Parameters	: -
	Out	Parameters	: void
	Purpose			: To set the value 1 of all active protection reg values
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CSDMonitor::SetActiveMonitorOff()
{
	DWORD dwValue = 0;
	CRegistry objRegistry;
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ActivexMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"BhoMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ExtensionMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"HomePage", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ProcessMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"RegistryMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"NetworkMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ServiceMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ShowKillPopup", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"StartupMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ToolbarMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"TrackingCookie", dwValue, HKEY_LOCAL_MACHINE);

	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"FileAssocMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"IERestrictionMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"WinRestrictionMonitor", dwValue, HKEY_LOCAL_MACHINE);
}

/*-------------------------------------------------------------------------------------
	Function		: CheckRegistration
	In Parameters	: -
	Out Parameters	: bool
	Purpose			: Checks registeration status of the Client
	Author			: Avinash Bhardwaj 
--------------------------------------------------------------------------------------*/
bool CSDMonitor::CheckRegistration()
{
	CRegistry objReg;
	DWORD iRegister = 0;
	bool isRegistered = false;

	{
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("QuarantinedCnt"),iRegister,HKEY_LOCAL_MACHINE);
		if(iRegister == 0)
		{
			isRegistered = true;
		}
		else
		{
			isRegistered = false;
		}
	}

	return isRegistered;
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

/*-------------------------------------------------------------------------------------
	Function		: LoadActiveMonitorDLL
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Load dll, Creates function pointers
	Author			: Avinash Bhardwaj 
--------------------------------------------------------------------------------------*/
bool CSDMonitor::LoadActiveMonitorDLL()
{
	try
	{
		bool bRegCallbackAvailable = CheckIfRegistryCallbackAvailable();

		/*if(bRegCallbackAvailable)
			AddLogEntry(L"bRegCallbackAvailable == true");
		else
			AddLogEntry(L"bRegCallbackAvailable == false");*/

		// Incase case if FltMgr service is NOT available we use the driver with kernel patching technique
		CRegistry oReg;
		CString strValue(L"");
		oReg.Get(L"SYSTEM\\CurrentControlSet\\Services\\FltMgr", L"ImagePath", strValue, HKEY_LOCAL_MACHINE);
		 // If the FltMgr Service is NOT available then we will use the kernel patch driver
		if((CSystemInfo::m_strOS == W2K) || (strValue.GetLength() == 0) || (bRegCallbackAvailable == false))
		{
			m_hActiveMon = LoadLibrary(_T("AuActiveProtection2K.dll"));
		}
		else
		{
			m_hActiveMon = LoadLibrary(_T("AuActiveProtection.dll"));
		}

		if(!m_hActiveMon)
		{
			AddLogEntry(_T("AuActiveMonitor2K.dll/AuActiveMonitor.dll Load library failed!"));
			return false;
		}
		lpSetActiveMonitor = (PFSETACTIVEMONITOR)GetProcAddress(m_hActiveMon, "SetActiveMonitor");
		if(!lpSetActiveMonitor)
		{
			AddLogEntry(_T(" GetProcAddress failed for SetActiveMonitor."));
			return false;
		}
		lpMonRanRegValue = (PFMONRANREGVALUE)GetProcAddress(m_hActiveMon, "MonRanRegValue");
		if(!lpMonRanRegValue)
		{
			AddLogEntry(_T(" GetProcAddress failed for MonRanRegValue."));
			return false;
		}
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSDMonitor::LoadActiveMonitorDLL"));
		return false;
	}
}

/*-------------------------------------------------------------------------------------
	Function		:  UnLoadActiveMonitorDLL
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Unloads dll
	Author			: Avinash Bhardwaj 
--------------------------------------------------------------------------------------*/
void CSDMonitor::UnLoadActiveMonitorDLL()
{
	__try
	{
		lpSetActiveMonitor = NULL;
		lpMonRanRegValue = NULL;
		if(m_hActiveMon)
		{
			FreeLibrary(m_hActiveMon);
			m_hActiveMon = NULL;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(_T("Exception caught in CSDMonitor::UnLoadActiveMonitorDLL"));
	}
	m_hActiveMon = NULL;
	lpSetActiveMonitor = NULL;
	lpMonRanRegValue = NULL;
	m_bLoadedSuccessfully = false;
}

/*-------------------------------------------------------------------------------------
	Function		: StopProtection
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Exits System tray
	Author			: Avinash Bhardwaj 
--------------------------------------------------------------------------------------*/
void CSDMonitor::StopProtection()
{
	__try
	{
		AddLogEntry(L">>>>> StopProtection!", 0, 0, true, LOG_WARNING);
		DisableMonitors();
		AddLogEntry(L">>>>> Start Sleeping!", 0, 0, true, LOG_WARNING);
		//Sleep(10000);
		int	iLoopCnt = 0x00;
		while (1)
		{
			iLoopCnt++;
			Sleep(100);
			if (iLoopCnt > 100)
			{
				break;
			}
		}
		AddLogEntry(L">>>>> Finished Sleeping!", 0, 0, true, LOG_WARNING);
		UnLoadActiveMonitorDLL();
		AddLogEntry(L"<<<<< StopProtection!", 0, 0, true, LOG_WARNING);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"##### Exception caught in StopProtection!", 0, 0, true, LOG_WARNING);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: StartStopMonitor
	In Parameters	: WPARAM : Operation type
					: LPARAM : On/Off
	Out Parameters	: LRESULT : status
	Purpose			: Message to handle on/off switch from maxshield
	Author			: Avinash Bhardwaj 
--------------------------------------------------------------------------------------*/
bool CSDMonitor::StartStopMonitor(DWORD dwMonitorType,bool bStatus,bool bShutDown,
									int ProcessType, DWORD dwPID)
{
	try
	{
		if(dwMonitorType <= 0 && dwMonitorType >= PROTECTION_LAST_MESSAGE)
		{
			CString csTemp;
			csTemp.Format(L">>>>> Unknown message received StartStopMonitor: dwMonitorType: %d, bStatus: %d, bShutDown: %d, ProcessType: %d, dwPID: %d", dwMonitorType, bStatus, bShutDown, ProcessType, dwPID);
			AddLogEntry(csTemp, 0, 0, true, LOG_ERROR);
			return false;
		}

		if(dwMonitorType == RESTARTPROTECTION)
		{
			DWORD dwVal = 0;
			CRegistry objReg;
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("bActiveProtection"), dwVal, HKEY_LOCAL_MACHINE);
			if(dwVal == 1)
			{
				return true;
			}
		}

		CString csTemp;
		csTemp.Format(L">>>>> StartStopMonitor: dwMonitorType: %d, bStatus: %d, bShutDown: %d, ProcessType: %d, dwPID: %d", dwMonitorType, bStatus, bShutDown, ProcessType, dwPID);
		AddLogEntry(csTemp, 0, 0, true, LOG_WARNING);
		if(!m_bLoadedSuccessfully)
		{
			m_bLoadedSuccessfully = LoadActiveMonitorDLL();
		}

		bool bReturnValue = true;
		if((dwMonitorType == STOPPROTECTION) || (dwMonitorType == RESTARTPROTECTION))
		{
			if(ProcessType == FSMonitorRestart)
			{
				if(lpMonRanRegValue)
				{
					lpMonRanRegValue();
				}
			}
			else
			{
				//DisableMonitors();	// Only stop all monitor threads
				StopProtection();		// This will also uload the AuCoreScanner.dll
			}
		}

		if(dwMonitorType == STOPPROTECTION)
		{
			csTemp.Format(L"<<<<< StartStopMonitor: dwMonitorType: %d, bStatus: %d, bShutDown: %d, ProcessType: %d, dwPID: %d", dwMonitorType, bStatus, bShutDown, ProcessType, dwPID);
			AddLogEntry(csTemp, 0, 0, true, LOG_WARNING);
			return bReturnValue;
		}

		if((dwMonitorType == STARTPROTECTION) || (dwMonitorType == RESTARTPROTECTION))
		{
			if(ProcessType == FSMonitorRestart)
			{
				if(lpMonRanRegValue)
				{
					lpMonRanRegValue();
				}
			}
			else
			{
				EnableMonitors();
			}
		}
		else
		{
			if(ProcessType == FSMonitorRestart)
			{
				if(lpMonRanRegValue)
				{
					lpMonRanRegValue();
				}
			}
			else if(lpSetActiveMonitor)
			{
				if(bStatus && ((dwMonitorType == SETHOMEPAGE) || (dwMonitorType == SETFILESYSTEMMONITOR)
								|| (dwMonitorType == SETFILEASSOCIATION) || (dwMonitorType == SETWINRESTRICTIONMONITOR)
								|| (dwMonitorType == SETIERESTRICTIONMONITOR) || (dwMonitorType == SETPROCESS)) || (dwMonitorType == SETGAMINGMODE))
				{
					if(!lpSetActiveMonitor(dwMonitorType, bStatus, (LPVOID)m_pProcHandler, (LPVOID)this, m_bPCShutDown))
					{
						bReturnValue  = false;
					}
				}
				else
				{
					if(!lpSetActiveMonitor(dwMonitorType, bStatus, NULL, NULL, bShutDown))
					{
						bReturnValue  = false;
					}
				}
			}
		}
		csTemp.Format(L"<<<<< StartStopMonitor: dwMonitorType: %d, bStatus: %d, bShutDown: %d, ProcessType: %d, dwPID: %d", dwMonitorType, bStatus, bShutDown, ProcessType, dwPID);
		AddLogEntry(csTemp, 0, 0, true, LOG_WARNING);
		return bReturnValue;
	}
	catch(...)
	{
		CString csTemp;
		csTemp.Format(L"<<<<< (EXCEPTION) StartStopMonitor: dwMonitorType: %d, bStatus: %d, bShutDown: %d, ProcessType: %d, dwPID: %d", dwMonitorType, bStatus, bShutDown, ProcessType, dwPID);
		AddLogEntry(csTemp, 0, 0, true, LOG_WARNING);
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : EnableMonitors
In Parameters  : 
Out Parameters : void 
Description    : Enable monitors according to user's selection saved in the registry
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CSDMonitor::EnableMonitors()
{
	AddLogEntry(L">>>>> EnableMonitors!", 0, 0, true, LOG_WARNING);
	if(!m_bLoadedSuccessfully)
	{
		LoadActiveMonitorDLL();
	}

	if(!lpSetActiveMonitor)
	{
		AddLogEntry(L"<<<<< EnableMonitors!", 0, 0, true, LOG_WARNING);
		return;
	}

	if (GetStatus(PROCESS_KEY))
	{
		AddLogEntry(L">>>>> EnableMonitors: SETPROCESS", 0, 0, true, LOG_WARNING);
		if (!lpSetActiveMonitor(SETPROCESS, true, (LPVOID)m_pProcHandler, (LPVOID)this, m_bPCShutDown))
		{
			AddLogEntry(_T("CSDMonitor::EnableMonitors()Failed for SETPROCESS"));
		}
	}

	if(GetStatus(SHOWPROCPOPUP))
	{
		AddLogEntry(L">>>>> EnableMonitors: SETNOTIFICATION", 0, 0, true, LOG_WARNING);
		if(!lpSetActiveMonitor(SETNOTIFICATION, true, NULL, NULL, m_bPCShutDown))
		{
			AddLogEntry(_T("CSDMonitor::EnableMonitors()Failed for SETNOTIFICATION"));
		}
	}

	if(GetStatus(HOME_PAGE_KEY))
	{
		AddLogEntry(L">>>>> EnableMonitors: SETHOMEPAGE", 0, 0, true, LOG_WARNING);
		if(!lpSetActiveMonitor(SETHOMEPAGE, true, (LPVOID)m_pProcHandler, (LPVOID)this, m_bPCShutDown))
		{
			AddLogEntry(_T("CSDMonitor::EnableMonitors()Failed for SETHOMEPAGE"));
		}
	}

	if(GetStatus(TRACKING_COOKIE))
	{
		AddLogEntry(L">>>>> EnableMonitors: SETCOOKIE", 0, 0, true, LOG_WARNING);
		if(!lpSetActiveMonitor(SETCOOKIE, true, NULL, NULL, m_bPCShutDown))
		{
			AddLogEntry(_T("CSDMonitor::EnableMonitors()Failed for SETCOOKIE"));
		}
	}



	if(GetStatus(FILEASSOC_MONITOR_KEY))
	{
		AddLogEntry(L">>>>> EnableMonitors: SETFILEASSOCIATION", 0, 0, true, LOG_WARNING);
		if(!lpSetActiveMonitor(SETFILEASSOCIATION, true, (LPVOID)m_pProcHandler, (LPVOID)this, m_bPCShutDown))
		{
			AddLogEntry(_T("CSDMonitor::EnableMonitors()Failed for FILEASSOC_MONITOR_KEY"));
		}
	}
	
	if(GetStatus(WIN_RESTRICTION_MONITOR_KEY))
	{
		AddLogEntry(L">>>>> EnableMonitors: SETWINRESTRICTIONMONITOR", 0, 0, true, LOG_WARNING);
		if(!lpSetActiveMonitor(SETWINRESTRICTIONMONITOR, true, (LPVOID)m_pProcHandler, (LPVOID)this, m_bPCShutDown))
		{
			AddLogEntry(_T("CSDMonitor::EnableMonitors()Failed for WIN_RESTRICTION_MONITOR_KEY"));
		}
	}

	if(GetStatus(IERESTRUCTION_MONITOR_KEY))
	{
		AddLogEntry(L">>>>> EnableMonitors: SETIERESTRICTIONMONITOR", 0, 0, true, LOG_WARNING);
		if(!lpSetActiveMonitor(SETIERESTRICTIONMONITOR, true, (LPVOID)m_pProcHandler, (LPVOID)this, m_bPCShutDown))
		{
			AddLogEntry(_T("CSDMonitor::EnableMonitors()Failed for SETIERESTRICTIONMONITOR"));
		}
	}
	

    if(GetStatus(HOST_MONITOR_KEY))
	{
		AddLogEntry(L">>>>> EnableMonitors: SETFILESYSTEMMONITOR", 0, 0, true, LOG_WARNING);
		if(!lpSetActiveMonitor(SETFILESYSTEMMONITOR, true, (LPVOID)m_pProcHandler, (LPVOID)this, m_bPCShutDown))
		{
			AddLogEntry(_T("CSDMonitor::EnableMonitors()Failed for SETFILESYSTEMMONITOR"));
		}
	}
		
	//if(GetStatus(NETWORK_MONITOR_KEY))
	//{
	//	AddLogEntry(L">>>>> EnableMonitors: SETNETWORKMONITOR", 0, 0, true, LOG_WARNING);
	//	if(!lpSetActiveMonitor(SETNETWORKMONITOR, true, NULL, NULL, m_bPCShutDown))
	//	{
	//		AddLogEntry(_T("CSDMonitor::EnableMonitors()Failed for SETNETWORKMONITOR"));
	//	}
	//}
	AddLogEntry(L"<<<<< EnableMonitors!", 0, 0, true, LOG_WARNING);
}

/*-------------------------------------------------------------------------------------
	Function		: DisableMonitors
	In Parameters	: -
	Out	Parameters	: 
	Purpose			: Disables monitors according to the user preferences.
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CSDMonitor::DisableMonitors()
{
	AddLogEntry(L">>>>> DisableMonitors!", 0, 0, true, LOG_WARNING);
	if(lpSetActiveMonitor)
	{
		if (GetStatus(PROCESS_KEY))
		{
			AddLogEntry(L">>>>> DisableMonitors: SETPROCESS", 0, 0, true, LOG_WARNING);
			if (!lpSetActiveMonitor(SETPROCESS, false, NULL, NULL, m_bPCShutDown))
			{
				AddLogEntry(_T("CSDMonitor::DisableMonitors()Failed for SETPROCESS"));
			}
		}
		if(GetStatus(HOME_PAGE_KEY))
		{
			AddLogEntry(L">>>>> DisableMonitors: SETHOMEPAGE", 0, 0, true, LOG_WARNING);
			if(!lpSetActiveMonitor(SETHOMEPAGE, false, NULL, NULL, m_bPCShutDown))
			{
				AddLogEntry(_T("CSDMonitor::DisableMonitors()Failed for SETHOMEPAGE"));
			}
		}
		if(GetStatus(TRACKING_COOKIE))
		{
			AddLogEntry(L">>>>> DisableMonitors: SETCOOKIE", 0, 0, true, LOG_WARNING);
			if(!lpSetActiveMonitor(SETCOOKIE, false, NULL, NULL, m_bPCShutDown))
			{
				AddLogEntry(_T("CSDMonitor::DisableMonitors()Failed for SETCOOKIE"));
			}
		}
		

		if(GetStatus(FILEASSOC_MONITOR_KEY))
		{
			AddLogEntry(L">>>>> DisableMonitors: SETFILEASSOCIATION", 0, 0, true, LOG_WARNING);
			if(!lpSetActiveMonitor(SETFILEASSOCIATION, false, NULL, NULL, m_bPCShutDown))
			{
				AddLogEntry(_T("CSDMonitor::DisableMonitors()Failed for SETREGISTRYMONITOR"));
			}
		}
		if(GetStatus(WIN_RESTRICTION_MONITOR_KEY))
		{
			AddLogEntry(L">>>>> DisableMonitors: SETWINRESTRICTIONMONITOR", 0, 0, true, LOG_WARNING);
			if(!lpSetActiveMonitor(SETWINRESTRICTIONMONITOR, false, NULL, NULL, m_bPCShutDown))
			{
				AddLogEntry(_T("CSDMonitor::DisableMonitors()Failed for SETREGISTRYMONITOR"));
			}
		}

		if(GetStatus(IERESTRUCTION_MONITOR_KEY))
		{
			AddLogEntry(L">>>>> DisableMonitors: SETIERESTRICTIONMONITOR", 0, 0, true, LOG_WARNING);
			if(!lpSetActiveMonitor(SETIERESTRICTIONMONITOR, false, NULL, NULL, m_bPCShutDown))
			{
				AddLogEntry(_T("CSDMonitor::DisableMonitors()Failed for SETREGISTRYMONITOR"));
			}
		}

		if(GetStatus(HOST_MONITOR_KEY))
		{
			AddLogEntry(L">>>>> DisableMonitors: SETFILESYSTEMMONITOR", 0, 0, true, LOG_WARNING);
			if(!lpSetActiveMonitor(SETFILESYSTEMMONITOR, false, NULL, NULL, m_bPCShutDown))
			{
				AddLogEntry(_T("CSDMonitor::DisableMonitors()Failed for SETFILESYSTEMMONITOR"));
			}
		}
		//if(GetStatus(NETWORK_MONITOR_KEY))
		//{
		//	AddLogEntry(L">>>>> DisableMonitors: SETNETWORKMONITOR", 0, 0, true, LOG_WARNING);
		//	if(!lpSetActiveMonitor(SETNETWORKMONITOR, false, NULL, NULL, m_bPCShutDown))
		//	{
		//		AddLogEntry(_T("CSDMonitor::DisableMonitors()Failed for SETNETWORKMONITOR"));
		//	}
		//}
	}

	AddLogEntry(L"<<<<< DisableMonitors!", 0, 0, true, LOG_WARNING);
}

/*--------------------------------------------------------------------------------------
Function       : GetStatus
In Parameters  : CString csKey, 
Out Parameters : bool 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CSDMonitor::GetStatus(CString csKey)
{
	DWORD dwVal = 0;
	CRegistry objReg;
	objReg.Get(CSystemInfo::m_csActMonRegKey, csKey, dwVal, HKEY_LOCAL_MACHINE);
	return (dwVal? true:false);
}

/*-------------------------------------------------------------------------------------
	Function		: GetExplorerProcessHandle
	In Parameters	: -
	Out Parameters	: HANDLE
	Purpose			: Needed to impersonate the logged in user...
	Author			:
--------------------------------------------------------------------------------------*/
HANDLE CSDMonitor::GetExplorerProcessHandle()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	ZeroMemory(&pe32, sizeof(pe32));
	HANDLE temp = NULL;
	try
	{
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		pe32.dwSize = sizeof(PROCESSENTRY32); 
		if(Process32First(hSnapshot, &pe32))
		{
			do
			{
				CString csExeName = pe32.szExeFile;
				if(csExeName.CompareNoCase(L"explorer.exe") == 0)
				{
					temp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID); 
					break;
				}
			}while(Process32Next(hSnapshot, &pe32));
		}
	}
	catch(...)
	{
		AddLogEntry(L"Exception caught in GetExplorerProcessHandle ");
	}
	return temp;
}

/*-------------------------------------------------------------------------------------
	Function		: SetHandler
	In Parameters	: ACTMON_MESSAGEPROCHANDLER pHandler : address of message handler
	Out	Parameters	: 
	Purpose			: sets the message handler to appropriate callback
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CSDMonitor::SetHandler(ACTMON_MESSAGEPROCHANDLER pHandler)
{
	m_pProcHandler = pHandler;
}

/*-------------------------------------------------------------------------------------
	Function		: StartActMonSwitch
	In Parameters	: 
	Out	Parameters	: 
	Purpose			: This is the main loop which continously monitors for new switch read events.
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CSDMonitor::StartActMonSwitch()
{
	__try
	{
		StartProtection();
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
				_T("AuActMon StartProtection Mode")))
	{
	}
}

/*-------------------------------------------------------------------------------------
	Function		: StopActMonSwitch
	In Parameters	: 
	Out	Parameters	: 
	Purpose			: Stops all monitors
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CSDMonitor::StopActMonSwitch()
{
	__try
	{
		StopProtection();
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
				_T("AuActMon StopProtection Mode")))
	{
	}
}

void CopyFileToDest(CString csSrcFile, CString csDestFile, bool bHideDest)
{
	//AddLogEntry(L"Copying File: " + csSrcFile + L" To: " + csDestFile);
	SetFileAttributes(csDestFile, FILE_ATTRIBUTE_NORMAL);
	CopyFile(csSrcFile, csDestFile, FALSE);
	if(bHideDest)
	{
		SetFileAttributes(csDestFile, FILE_ATTRIBUTE_HIDDEN);
	}
	else
	{
		SetFileAttributes(csDestFile, FILE_ATTRIBUTE_NORMAL);
	}
}


void CSDMonitor::GetBuyNowLink(CString &csBuyNow)
{
	
	return;
}

