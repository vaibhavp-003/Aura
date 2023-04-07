/*======================================================================================
FILE             : WatchDogService.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshit Kasliwal
COMPANY		     : Aura 
COPYRIGHT(NOTICE):
					(C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura.	
CREATION DATE    : 5/12/2009
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "WatchDogService.h"
#include "RemoteService.h"
#include "SDSAConstants.h"
#include "MaxCommunicator.h"
#include "MaxCommunicatorServer.h"
#include "MaxPipes.h"
#include "SDConstants.h"
#include "WatchDogServiceApp.h"
#include <dbt.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

HDEVNOTIFY m_hDevNotify = INVALID_HANDLE_VALUE;
unsigned long __stdcall DeviceEventNotify(DWORD evtype, PVOID evdata);
/*HDEVNOTIFY DoRegisterDeviceInterface(SERVICE_STATUS_HANDLE hServiceStatus);
DEFINE_GUID(GUID_CLASS_STORAGE_VOLUME, 0x53F5630DL, 0xB6BF, 0x11D0, 0x94, 0xF2, \
					0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B);*/

#define DEVICE_NOTIFY_ALL_INTERFACE_CLASSES  0x00000004



SERVICE_STATUS			CWatchDogService::m_ServiceStatus = {0};
SERVICE_STATUS_HANDLE	CWatchDogService::m_ServiceStatusHandle = NULL;
CString					CWatchDogService::m_csServiceName = L"";
DWORD					CWatchDogService::m_dwThreadCount = 0;

/*--------------------------------------------------------------------------------------
Function       : CWatchDogService
In Parameters  : void,
Out Parameters :
Description    : C'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CWatchDogService::CWatchDogService(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : ~CWatchDogService
In Parameters  : void,
Out Parameters :
Description    :D'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CWatchDogService::~CWatchDogService(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : InitService
In Parameters  : CString csServiceName,
Out Parameters : BOOL
Description    : Initializes the service status
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
BOOL CWatchDogService::InitService(CString csServiceName)
{
	m_csServiceName = csServiceName;
	BOOL bIsService	= FALSE;
	IsService(bIsService);
	m_ServiceStatus.dwCurrentState = (bIsService ? SERVICE_START_PENDING : SERVICE_STOPPED);
	return bIsService;
}

/*--------------------------------------------------------------------------------------
Function       : StartService
In Parameters  :
Out Parameters : void
Description    : Starts the Watchdog service
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CWatchDogService::StartService()
{
	SERVICE_TABLE_ENTRY	DispatchTable[]	=
	{{m_csServiceName.GetBuffer(m_csServiceName.GetLength()),
	(LPSERVICE_MAIN_FUNCTION)CWatchDogService::StartAdminService},
	{NULL, NULL}
	};

	m_csServiceName.ReleaseBuffer();
	StartServiceCtrlDispatcher(DispatchTable);
}

/*--------------------------------------------------------------------------------------
Function       : IsService
In Parameters  : BOOL& isService,
Out Parameters : DWORD
Description    : Checks if the Current Process running under Service mode
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
DWORD CWatchDogService::IsService(BOOL& isService)
{
	DWORD	dwPid				   = GetCurrentProcessId();
	HANDLE  hProcessToken		   = NULL;
	DWORD   dwgroupLength		   = 50;
	PTOKEN_GROUPS groupInfo		   = NULL;

	SID_IDENTIFIER_AUTHORITY siaNt = SECURITY_NT_AUTHORITY;
	PSID pInteractiveSid		   = NULL;
	PSID pServiceSid			   = NULL;
	DWORD dwRet					   = NO_ERROR;

	// reset flags
	BOOL	isInteractive		   = FALSE;
	isService					   = FALSE;

	DWORD dwdx = 0;

	HANDLE hProcess	= ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	// open	the	token
	if(!::OpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken))
	{
		dwRet =	::GetLastError();
		goto closedown;
	}

	// allocate	a buffer of	default	size
	groupInfo =	(PTOKEN_GROUPS)::LocalAlloc(0, dwgroupLength);
	if(groupInfo == NULL)
	{
		dwRet =	::GetLastError();
		goto closedown;
	}

	// try to get the info
	if(!::GetTokenInformation(hProcessToken, TokenGroups, groupInfo, dwgroupLength, &dwgroupLength))
	{
		// if buffer was too small,	allocate to	proper size, otherwise error
		if(::GetLastError() !=	ERROR_INSUFFICIENT_BUFFER)
		{
			dwRet =	::GetLastError();
			goto closedown;
		}

		::LocalFree(groupInfo);

		groupInfo =	(PTOKEN_GROUPS)::LocalAlloc(0, dwgroupLength);
		if(groupInfo == NULL)
		{
			dwRet =	::GetLastError();
			goto closedown;
		}

		if(!GetTokenInformation(hProcessToken, TokenGroups, groupInfo, dwgroupLength, &dwgroupLength))
		{
			dwRet =	::GetLastError();
			goto closedown;
		}
	}

	// create comparison sids
	if(!AllocateAndInitializeSid(&siaNt, 1, SECURITY_INTERACTIVE_RID, 0, 0, 0, 0, 0, 0, 0, &pInteractiveSid))
	{
		dwRet =	::GetLastError();
		goto closedown;
	}

	if(!AllocateAndInitializeSid(&siaNt, 1, SECURITY_SERVICE_RID, 0, 0, 0, 0, 0, 0, 0, &pServiceSid))
	{
		dwRet =	::GetLastError();
		goto closedown;
	}

	// try to match	sids
	for	(dwdx = 0; dwdx < groupInfo->GroupCount; dwdx	+= 1)
	{
		SID_AND_ATTRIBUTES sanda = groupInfo->Groups[dwdx];
		PSID pSid =	sanda.Sid;

		if(::EqualSid(pSid, pInteractiveSid))
		{
			isInteractive =	TRUE;
			isService	  =	FALSE;
			break;
		}
		else if	(::EqualSid(pSid, pServiceSid))
		{
			isService     =	TRUE;
			isInteractive =	FALSE;
			break;
		}
	}

	if(!(isService || isInteractive))
	{
		isService =	TRUE;
	}

closedown:
	if(pServiceSid)
	{
		::FreeSid(pServiceSid);
	}

	if(pInteractiveSid)
	{
		::FreeSid(pInteractiveSid);
	}

	if(groupInfo)
	{
		::LocalFree(groupInfo);
	}
	if(hProcessToken)
	{
		::CloseHandle(hProcessToken);
	}
	if(hProcess)
	{
		::CloseHandle(hProcess);
	}
	return dwRet;
}

/*--------------------------------------------------------------------------------------
Function       : RemoteAdminHandler
In Parameters  : DWORD dwOpcode,DWORD evtype, PVOID evdata, PVOID Context
Out Parameters : void
Description    : Control handler for our service.
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void WINAPI CWatchDogService::RemoteAdminHandler(DWORD dwOpcode, DWORD evtype, PVOID evdata, PVOID Context)
{
	DWORD	dwstatus = 0;
	switch(dwOpcode)
	{
	case SERVICE_CONTROL_STOP:
		{
			UnregisterDeviceNotification(m_hDevNotify);
			m_ServiceStatus.dwWin32ExitCode		=	0;
			m_ServiceStatus.dwCurrentState		=	SERVICE_STOPPED;
			m_ServiceStatus.dwCheckPoint		=	0;
			m_ServiceStatus.dwWaitHint			=	0;
			if(!SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus))
			{
				dwstatus = GetLastError();
			}
			
			theApp.ResetPermission();
			theApp.StopDrivers();
			theApp.SetWDShutDownStatus(0);
			theApp.SuspendAndTerminateAllThreads();
			while(m_dwThreadCount != 0)Sleep(2);

			return;
		}
	case SERVICE_CONTROL_PAUSE:
		break;

	case SERVICE_CONTROL_CONTINUE:
		break;

	case SERVICE_CONTROL_INTERROGATE:
		// Fall	through	to send	current	status.
		break;
	case SERVICE_CONTROL_SHUTDOWN:
		AddLogEntry(_T("WD Received the System Shutdown Event"));
		theApp.ResetPermission();
		theApp.EnableActiveProtection();
		theApp.SetWDShutDownStatus(0);
		break;
	case SERVICE_CONTROL_DEVICEEVENT:
		//OutputDebugString(_T("SERVICE_CONTROL_DEVICEEVENT"));
		
		DeviceEventNotify(evtype, evdata);
		break;
	}

	// Send	current	status.
	if(!SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus))
	{
		dwstatus = GetLastError();
	}
	return;
}

/*--------------------------------------------------------------------------------------
Function       : StartAdminService
In Parameters  : DWORD dwVal, LPWSTR *lpstrName
Out Parameters : void
Description    : Registers the Service Handler and sets the status of the service
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void WINAPI CWatchDogService::StartAdminService(DWORD dwVal, LPWSTR *lpstrName)
{
	DWORD	dwstatus			= 0;
	DWORD	specificError	= 0;

	m_ServiceStatus.dwServiceType				= SERVICE_WIN32_OWN_PROCESS;
	m_ServiceStatus.dwCurrentState				= SERVICE_START_PENDING;
	m_ServiceStatus.dwControlsAccepted			= 0;
	m_ServiceStatus.dwWin32ExitCode				= NO_ERROR;
	m_ServiceStatus.dwServiceSpecificExitCode	= 0;
	m_ServiceStatus.dwCheckPoint				= 0;
	m_ServiceStatus.dwWaitHint					= 3000;

	m_ServiceStatusHandle = RegisterServiceCtrlHandlerEx(m_csServiceName, (LPHANDLER_FUNCTION_EX)CWatchDogService::RemoteAdminHandler, 0);

	if(m_ServiceStatusHandle == (SERVICE_STATUS_HANDLE)0)
	{
		m_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		return;
	}

	if(!SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus))
	{
		dwstatus = GetLastError();
	}

	// Handle error	condition
	if(dwstatus != NO_ERROR)
	{
		m_ServiceStatus.dwCurrentState				= SERVICE_STOPPED;
		m_ServiceStatus.dwCheckPoint				= 0;
		m_ServiceStatus.dwWaitHint					= 0;
		m_ServiceStatus.dwWin32ExitCode				= dwstatus;
		m_ServiceStatus.dwServiceSpecificExitCode	= specificError;

		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
		return;
	}

	m_ServiceStatus.dwCurrentState		= SERVICE_RUNNING;
	m_ServiceStatus.dwCheckPoint		= 0;
	m_ServiceStatus.dwWaitHint			= 0;
	m_ServiceStatus.dwControlsAccepted	= SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	if(!SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus))
	{
		dwstatus = GetLastError();
	}

	DEV_BROADCAST_DEVICEINTERFACE NotificationFilter = {0};
	ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));
    NotificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
    NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
	memcpy( &(NotificationFilter.dbcc_classguid), &(GUID_DEVINTERFACE_CDROM), sizeof(struct _GUID));
	m_hDevNotify = RegisterDeviceNotification(m_ServiceStatusHandle, &NotificationFilter,
							DEVICE_NOTIFY_SERVICE_HANDLE | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);

	return;
}

/*--------------------------------------------------------------------------------------
Function       : SetWDServiceStopStatus
In Parameters  : bool bEnable,
Out Parameters : DWORD
Description    : Aloowing/Disallowing user to stop/start service from service panel
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
DWORD CWatchDogService::SetWDServiceStopStatus(bool bEnable)
{
	DWORD dwStatus = 0;
	if(bEnable)
	{
		m_ServiceStatus.dwControlsAccepted	= SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	}
	else
	{
		m_ServiceStatus.dwControlsAccepted	= SERVICE_ACCEPT_SHUTDOWN;
	}
	if(!SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus))
		dwStatus = GetLastError();
	return dwStatus;
}
/*--------------------------------------------------------------------------------------
Function       : SetWDServiceStopStatusPPL
In Parameters  : void,
Out Parameters : DWORD
Description    : Stop service from service panel
--------------------------------------------------------------------------------------*/
DWORD CWatchDogService::SetWDServiceStopStatusPPL()
{
	DWORD dwStatus = 0;
	UnregisterDeviceNotification(m_hDevNotify);
	m_ServiceStatus.dwWin32ExitCode		=	0;
	m_ServiceStatus.dwCurrentState		=	SERVICE_STOPPED;
	m_ServiceStatus.dwCheckPoint		=	0;
	m_ServiceStatus.dwWaitHint			=	0;
	if(!SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus))
	{
		dwStatus = GetLastError();
	}
	
	theApp.ResetPermission();
	theApp.StopDrivers();
	theApp.SetWDShutDownStatus(0);
	theApp.SuspendAndTerminateAllThreads();
	while(m_dwThreadCount != 0)Sleep(2);
	return dwStatus;
}
/*--------------------------------------------------------------------------------------
Function       : SetWDServiceChangeStatus
In Parameters  : void,
Out Parameters : DWORD
Description    : Change status 
--------------------------------------------------------------------------------------*/
DWORD CWatchDogService::SetWDServiceChangeStatus()
{
	DWORD dwStatus = 0;
	DWORD dwVer = 0;
	
	HMODULE hMonitor;
	typedef bool(*PFCHANGEPPLSRV)(TCHAR *szSrvName);
	PFCHANGEPPLSRV lpChangeStatusPPLSrv;
	bool bReturn= false;

	hMonitor = LoadLibrary(UI_PPLSRVNAME);
	if(hMonitor != NULL)
	{
		lpChangeStatusPPLSrv = (PFCHANGEPPLSRV)GetProcAddress(hMonitor, "ChangePPLSrv");
		if(lpChangeStatusPPLSrv)
		{
			TCHAR szSrvName[MAX_PATH] = {0};//MAXWATCHDOG_SVC_NAME
			_stprintf(szSrvName,_T("%s"),MAXWATCHDOG_SVC_NAME);
			bool bRet = lpChangeStatusPPLSrv(szSrvName);
			SetWDServiceStopStatusPPL();
			OutputDebugString(_T("ChangeWD Win10"));
		}
		else
		{
			AddLogEntry(_T(" GetProcAddress failed for ChangePPLSrv."));
			bReturn = false;
		}
		FreeLibrary(hMonitor);
		hMonitor = NULL;
		lpChangeStatusPPLSrv = NULL;

	}
	else
	{
		AddLogEntry(_T("AuPSrvOpt.dll Load library failed!"));
		bReturn = false;
	}


	return dwStatus;
}
unsigned long __stdcall DeviceEventNotify(DWORD evtype, PVOID evdata)
{

	switch (evtype)
	{
		case DBT_DEVICEREMOVECOMPLETE:
		{
		}
		break;
		case DBT_DEVICEARRIVAL:
		{
			PDEV_BROADCAST_DEVICEINTERFACE pDevHeader = (PDEV_BROADCAST_DEVICEINTERFACE)evdata;
		
			if(pDevHeader->dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
			{
				AM_MESSAGE_DATA sAMMsgData = {0};
				sAMMsgData.dwMsgType = NetworkEnableDisable;
				CMaxCommunicator objTrayBroadcast(_NAMED_PIPE_ACTMON_TO_TRAY);
				objTrayBroadcast.SendData(&sAMMsgData, sizeof(AM_MESSAGE_DATA));
			}
		}
		break;
	}

	return 0;
}