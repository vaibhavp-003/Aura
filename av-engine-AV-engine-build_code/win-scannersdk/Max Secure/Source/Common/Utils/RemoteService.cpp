/*=============================================================================
   FILE			: RemoteService.cpp
   DESCRIPTION	: This class provides the functionality related with the service of the remote machine
   DOCUMENTS	: 
   AUTHOR		: Sandip Sanap
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 05-12-2007
   NOTES		:
VERSION HISTORY	:
============================================================================*/
#include "pch.h"
#include "RemoteService.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

SERVICE_STATUS		     CRemoteService::m_ServiceStatus = {0};
SERVICE_STATUS_HANDLE	 CRemoteService::m_ServiceStatusHandle;
CString				     CRemoteService::m_csServiceName = _T("");
/*-------------------------------------------------------------------------------------
Function		: CRemoteService
In Parameters	: -
Out Parameters	: -
Purpose			: CRemoteService Constructor
Author			: sandip sanap
--------------------------------------------------------------------------------------*/
CRemoteService::CRemoteService(void)
{
}

/*-------------------------------------------------------------------------------------
Function		: ~CRemoteService
In Parameters	: -
Out Parameters	: -
Purpose			: CRemoteService Destructor
Author			: sandip sanap
--------------------------------------------------------------------------------------*/
CRemoteService::~CRemoteService(void)
{
}

/*-------------------------------------------------------------------------------------
Function		: InitService
In Parameters	: -
Out Parameters	: bool
Purpose			:
Author			: sandip sanap
--------------------------------------------------------------------------------------*/
BOOL CRemoteService::InitService(CString csServiceName)
{
	m_csServiceName = csServiceName;

	BOOL	bIsService	= FALSE;
	IsService(bIsService);

	return bIsService;
}

/*-------------------------------------------------------------------------------------
Function		: StartService
In Parameters	: -
Out Parameters	: bool
Purpose			:
Author			:
--------------------------------------------------------------------------------------*/
void CRemoteService::StartService()
{
	SERVICE_TABLE_ENTRY	DispatchTable[]	= {{m_csServiceName.GetBuffer(m_csServiceName.GetLength()), CRemoteService::StartAdminService},  {NULL, NULL}};
	m_csServiceName.ReleaseBuffer();

	StartServiceCtrlDispatcher(DispatchTable);
}

/*-------------------------------------------------------------------------------------
Function		: StartRemoteService
In Parameters	: -
Out Parameters	: -
Purpose			:
Author			:
--------------------------------------------------------------------------------------*/
void CRemoteService::StartRemoteService()
{
	SERVICE_TABLE_ENTRY	DispatchTable[]	= {{m_csServiceName.GetBuffer(m_csServiceName.GetLength()), CRemoteService::StartAdminService},  {NULL, NULL}};
	m_csServiceName.ReleaseBuffer();
	StartServiceCtrlDispatcher(DispatchTable);
}

/*-------------------------------------------------------------------------------------
Function		: IsRmoteServiceRunning
In Parameters	: CString csServiceName
Out Parameters	: bool
Purpose			: Check if the remote service is running or not
Author			: Sunil Apte
--------------------------------------------------------------------------------------*/
bool CRemoteService::IsRmoteServiceRunning(const CString &csServiceName)
{
	// Open remote Service Manager
	SC_HANDLE hSCM = ::OpenSCManager(NULL,
		NULL,
		GENERIC_READ);//SC_MANAGER_ALL_ACCESS);

	if(hSCM == NULL)
		return false;

	// Maybe it's already there and installed, let's try to run
	SC_HANDLE hService =::OpenService(hSCM, csServiceName, GENERIC_READ);//SERVICE_ALL_ACCESS);
	if(hService == NULL)
	{
		::CloseServiceHandle(hSCM);
		return false;
	}

	SERVICE_STATUS		  ServiceStatus;

	// Make	sure the service is	not	already	stopped
	if(!QueryServiceStatus(hService,	&ServiceStatus	))
	{
		::CloseServiceHandle(hSCM);
		::CloseServiceHandle(hService);
		return false;
	}

	if(ServiceStatus.dwCurrentState != SERVICE_RUNNING)
	{
		::CloseServiceHandle(hService);
		::CloseServiceHandle(hSCM);
		return false;
	}

	::CloseServiceHandle(hService);
	::CloseServiceHandle(hSCM);
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: StartRemoteService
In Parameters	: CString csServiceName,CString csAppPath,DWORD dwServiceType,DWORD dwStartType,
bool bSleep, bool bRegister
Out Parameters	: bool
Purpose			: Start the service on remote PC
Author			: sandip sanap
--------------------------------------------------------------------------------------*/
bool CRemoteService::StartRemoteService(CString csServiceName, CString csAppPath,
										DWORD dwServiceType,DWORD dwStartType,
										bool bSleep, bool bRegister)
{
	// Open remote Service Manager
	SC_HANDLE hSCM = ::OpenSCManager(NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);
	if(hSCM == NULL)
	{
		//AfxMessageBox(L"OpenSCManager failed");
		return false;
	}

	// Maybe it's already there and installed, let's try to run
	SC_HANDLE hService =::OpenService(hSCM, csServiceName, SERVICE_ALL_ACCESS);

	// Creates service on remote machine, if it's not installed yet
	if(hService == NULL)
	{
		hService = ::CreateService(hSCM, csServiceName, csServiceName, SERVICE_ALL_ACCESS,
			dwServiceType, dwStartType,SERVICE_ERROR_NORMAL, csAppPath,
			NULL, NULL, NULL, NULL, NULL);

	}
	if(hService == NULL)
	{
		::CloseServiceHandle(hSCM);
		return false;
	}

	// Start service
	if(!bRegister  && !::StartService(hService, 0, NULL))
	{
		::CloseServiceHandle(hService);
		::CloseServiceHandle(hSCM);
		return false;
	}

	::CloseServiceHandle(hService);
	::CloseServiceHandle(hSCM);
	if(bSleep)
		Sleep(2000); //Give the service some time to Start up!

	return true;
}

/*-------------------------------------------------------------------------------------
Function		: StopRemoteService
In Parameters	: CString csServiceName,bool bDeleteService = true
Out Parameters	: bool
Purpose			: Stops the service on remote PC
Author			: sandip sanap
--------------------------------------------------------------------------------------*/
bool CRemoteService::StopRemoteService(CString csServiceName,bool bDeleteService)
{
	// Open remote Service Manager
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(hSCM == NULL)
	{
		return FALSE;
	}

	// Open	service
	SC_HANDLE hService = ::OpenService(hSCM, csServiceName, SERVICE_ALL_ACCESS);
	if(hService  == 	NULL)
	{
		::CloseServiceHandle(hSCM);
		return FALSE;
	}

	SERVICE_STATUS		  ServiceStatus;
	DWORD	dwTimeout	  = 1000;
	DWORD	dwStartTime   =	GetTickCount();

	// Make	sure the service is	not	already	stopped
	if(!QueryServiceStatus(hService,	&ServiceStatus	))
	{
		if(bDeleteService)	// Deletes service from	service	database
			DeleteService(hService);
		::CloseServiceHandle(hSCM);
		::CloseServiceHandle(hService);
		return FALSE;
	}

	if(ServiceStatus.dwCurrentState == SERVICE_STOPPED)
	{
		//Sleep(3000);
		if(bDeleteService)	// Deletes service from	service	database
			DeleteService(hService);
		::CloseServiceHandle(hSCM);
		::CloseServiceHandle(hService);
		return TRUE;
	}

	// If a	stop is	pending, just wait for it
	while (	ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING)
	{
		Sleep(ServiceStatus.dwWaitHint);
		if(!QueryServiceStatus(hService,	&ServiceStatus	))
		{
			if(bDeleteService)	// Deletes service from	service	database
				DeleteService(hService);
			::CloseServiceHandle(hSCM);
			::CloseServiceHandle(hService);
			return FALSE;
		}

		if(ServiceStatus.dwCurrentState == SERVICE_STOPPED)
		{
			if(bDeleteService)	// Deletes service from	service	database
				DeleteService(hService);

			//Sleep(1000);
			::CloseServiceHandle(hSCM);
			::CloseServiceHandle(hService);
			return TRUE;
		}

		if(GetTickCount()	- dwStartTime >	dwTimeout)
		{
			if(bDeleteService)	// Deletes service from	service	database
				DeleteService(hService);

			::CloseServiceHandle(hSCM);
			::CloseServiceHandle(hService);
			return FALSE;
		}
	}

	// Send	a stop code	to the main	service
	if(!ControlService(hService,	SERVICE_CONTROL_STOP, &ServiceStatus)	)
	{
		if(bDeleteService)	// Deletes service from	service	database
			DeleteService(hService);

		::CloseServiceHandle(hSCM);
		::CloseServiceHandle(hService);
		return FALSE;
	}

	// Wait	for	the	service	to stop
	while (	ServiceStatus.dwCurrentState != SERVICE_STOPPED)
	{
		Sleep(ServiceStatus.dwWaitHint);
		if(!QueryServiceStatus(hService,	&ServiceStatus	))
		{
			if(bDeleteService)	// Deletes service from	service	database
				DeleteService(hService);

			::CloseServiceHandle(hSCM);
			::CloseServiceHandle(hService);
			return FALSE;
		}

		if(ServiceStatus.dwCurrentState == SERVICE_STOPPED)
		{
			break;
		}

		if(GetTickCount()	- dwStartTime >	dwTimeout)
		{
			if(bDeleteService)	// Deletes service from	service	database
				DeleteService(hService);

			::CloseServiceHandle(hSCM);
			::CloseServiceHandle(hService);
			return FALSE;
		}
	}

	if(bDeleteService)	// Deletes service from	service	database
		DeleteService(hService);

	::CloseServiceHandle(hSCM);
	::CloseServiceHandle(hService);
	//Sleep(3000);
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: StopRemoteService
In Parameters	: CString csServiceName,bool bDeleteService,CString &csServiceFileName
Out Parameters	: bool
Purpose			: Stops the service on remote PC
Author			: sandip sanap
--------------------------------------------------------------------------------------*/
bool CRemoteService::StopRemoteService(CString csServiceName, bool bDeleteService, CString &csServiceFileName)
{
	// Open remote Service Manager
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS	);
	if(hSCM == NULL)
		return FALSE;
	// Open	service
	SC_HANDLE hService = ::OpenService(hSCM, csServiceName, SERVICE_ALL_ACCESS);
	if(hService  == 	NULL)
	{
		::CloseServiceHandle(hSCM);
		return FALSE;
	}
	DWORD	dwTimeout			  = 30000;
	SERVICE_STATUS					ServiceStatus;
	DWORD	dwStartTime			  =	GetTickCount();

	//Get Service File Path
	LPQUERY_SERVICE_CONFIG lpqscBuf;
	DWORD dwBytesNeeded;
	lpqscBuf = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, 4096);
	// Get the configuration information.
	if(!QueryServiceConfig(hService,  lpqscBuf,  4096,  &dwBytesNeeded))
		return FALSE;
	//Get Service File Path
	if(lpqscBuf)
	{
		csServiceFileName = lpqscBuf->lpBinaryPathName;
	}

	// Make	sure the service is	not	already	stopped
	if(!QueryServiceStatus(hService,	&ServiceStatus	))
	{
		if(bDeleteService)	// Deletes service from	service	database
			DeleteService(hService);

		::CloseServiceHandle(hSCM);
		::CloseServiceHandle(hService);
		return FALSE;
	}

	if(ServiceStatus.dwCurrentState == SERVICE_STOPPED)
	{
		Sleep(3000);
		if(bDeleteService)	// Deletes service from	service	database
			DeleteService(hService);

		::CloseServiceHandle(hSCM);
		::CloseServiceHandle(hService);
		return TRUE;
	}

	// If a	stop is	pending, just wait for it
	while (	ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING)
	{
		Sleep(ServiceStatus.dwWaitHint);
		if(!QueryServiceStatus(hService,	&ServiceStatus	))
		{
			if(bDeleteService)	// Deletes service from	service	database
				DeleteService(hService);

			::CloseServiceHandle(hSCM);
			::CloseServiceHandle(hService);
			return FALSE;
		}

		if(ServiceStatus.dwCurrentState == SERVICE_STOPPED)
		{
			if(bDeleteService)	// Deletes service from	service	database
				DeleteService(hService);

			Sleep(3000);
			::CloseServiceHandle(hSCM);
			::CloseServiceHandle(hService);
			return TRUE;
		}

		if(GetTickCount()	- dwStartTime >	dwTimeout)
		{
			if(bDeleteService)	// Deletes service from	service	database
				DeleteService(hService);

			::CloseServiceHandle(hSCM);
			::CloseServiceHandle(hService);
			return FALSE;
		}
	}

	// Send	a stop code	to the main	service
	if(!ControlService(hService,	SERVICE_CONTROL_STOP, &ServiceStatus)	)
	{
		if(bDeleteService)	// Deletes service from	service	database
			DeleteService(hService);

		::CloseServiceHandle(hSCM);
		::CloseServiceHandle(hService);
		return FALSE;
	}

	// Wait	for	the	service	to stop
	while (	ServiceStatus.dwCurrentState != SERVICE_STOPPED)
	{
		Sleep(ServiceStatus.dwWaitHint);
		if(!QueryServiceStatus(hService,	&ServiceStatus	))
		{
			if(bDeleteService)	// Deletes service from	service	database
				DeleteService(hService);

			::CloseServiceHandle(hSCM);
			::CloseServiceHandle(hService);
			return FALSE;
		}

		if(ServiceStatus.dwCurrentState == SERVICE_STOPPED)
		{
			break;
		}

		if(GetTickCount()	- dwStartTime >	dwTimeout)
		{
			if(bDeleteService)	// Deletes service from	service	database
				DeleteService(hService);

			::CloseServiceHandle(hSCM);
			::CloseServiceHandle(hService);
			return FALSE;
		}
	}

	if(bDeleteService)	// Deletes service from	service	database
		DeleteService(hService);

	::CloseServiceHandle(hSCM);
	::CloseServiceHandle(hService);

	Sleep(3000);
	return  TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: IsService
In Parameters	: bool -isService
Out Parameters	: dwRet -The error value
Purpose			: Checks whether process	is a service or	not
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
DWORD CRemoteService::IsService(BOOL& isService)
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

	DWORD dwdx;

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

/*-------------------------------------------------------------------------------------
Function		: RemoteAdminHandler
In Parameters	:  DWORD Opcode
Out Parameters	: VOID
Purpose			: control service opration
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void WINAPI CRemoteService:: RemoteAdminHandler(DWORD Opcode)
{
	DWORD	dwstatus;
	switch(Opcode)
	{
	case SERVICE_CONTROL_STOP:
		{
			m_ServiceStatus.dwWin32ExitCode		=	0;
			m_ServiceStatus.dwCurrentState		=	SERVICE_STOPPED;
			m_ServiceStatus.dwCheckPoint		=	0;
			m_ServiceStatus.dwWaitHint			=	0;

			if(!SetServiceStatus(m_ServiceStatusHandle,
				&m_ServiceStatus))
			{
				dwstatus = GetLastError();
			}
			return;
		}
	case SERVICE_CONTROL_PAUSE:
		break;

	case SERVICE_CONTROL_CONTINUE:
		break;

	case SERVICE_CONTROL_INTERROGATE:
		// Fall	through	to send	current	status.
		break;
	}

	// Send	current	status.
	if(!SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus))
	{
		dwstatus = GetLastError();
	}
	return;
}

/*-------------------------------------------------------------------------------------
Function		: StartRemoteAdminService
In Parameters	:  DWORD, LPTSTR*
Out Parameters	: VOID
Purpose			: Start Remote Admin Service
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void WINAPI CRemoteService::StartAdminService(DWORD dwVal,	 LPWSTR* lpstrName)
{
	DWORD	dwstatus			= 0;
	DWORD	specificError	= 0;
	// Prepare the ServiceStatus structure that	will be	used for the
	// comunication	with SCM(Service Control Manager).
	// If you fully	under stand	the	members	of this	structure, feel
	// free	to change these	values :o)
	m_ServiceStatus.dwServiceType				= SERVICE_WIN32_OWN_PROCESS; // SERVICE_WIN32;	//SMA
	m_ServiceStatus.dwCurrentState			= SERVICE_START_PENDING;
	m_ServiceStatus.dwControlsAccepted		= 0;//SERVICE_ACCEPT_STOP;
	m_ServiceStatus.dwWin32ExitCode			= NO_ERROR; //0;
	m_ServiceStatus.dwServiceSpecificExitCode	= 0;
	m_ServiceStatus.dwCheckPoint				= 0;
	m_ServiceStatus.dwWaitHint				= 3000; //0;

	// Here	we register	the	control	handler	for	our	service.
	// We tell the SCM about a call	back function that SCM will
	// call	when user tries	to Start, Stop or Pause	your service.
	m_ServiceStatusHandle	= RegisterServiceCtrlHandler(m_csServiceName, CRemoteService::RemoteAdminHandler);
	//m_ServiceStatusHandle	= RegisterServiceCtrlHandler(m_csServiceName.GetBuffer(m_csServiceName.GetLength()), CRemoteService::RemoteAdminHandler);
	//m_ServiceStatusHandle	= RegisterServiceCtrlHandler(lpstrName, CRemoteService::RemoteAdminHandler);
	//m_csServiceName.ReleaseBuffer();
	if(m_ServiceStatusHandle  == (SERVICE_STATUS_HANDLE)0)
	{
		return;
	}

	if(!SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus))
	{
		dwstatus = GetLastError();
	}

	// Handle error	condition
	if(dwstatus != NO_ERROR)
	{
		m_ServiceStatus.dwCurrentState			= SERVICE_STOPPED;
		m_ServiceStatus.dwCheckPoint				= 0;
		m_ServiceStatus.dwWaitHint				= 0;
		m_ServiceStatus.dwWin32ExitCode			= dwstatus;
		m_ServiceStatus.dwServiceSpecificExitCode	= specificError;

		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
		return;
	}

	// Initialization complete - report	running	status.
	m_ServiceStatus.dwCurrentState	   = SERVICE_RUNNING;
	m_ServiceStatus.dwCheckPoint		   = 0;
	m_ServiceStatus.dwWaitHint		   = 0;
	m_ServiceStatus.dwControlsAccepted		= SERVICE_ACCEPT_STOP;

	if(!SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus))
	{
		dwstatus = GetLastError();
	}
	return;
}

bool CRemoteService::SetFailureActionToService(LPCTSTR strServiceName, LPTSTR strDescription)
{
	SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(hSCM != NULL)
	{
		// Need to acquire database lock before reconfiguring.
		SC_LOCK sclLock = LockServiceDatabase(hSCM);
		if(sclLock != NULL)
		{
			DWORD dwDefaultResetPeriod = 60*60*24*5; // 5 Days (or so)
			DWORD dwDefaultActionDelay = 3000; // 3 second

			SERVICE_FAILURE_ACTIONS sfa;
			SC_ACTION arrSCA[3];
			// The action to be performed.This member can be one of the following values.Value Meaning
			// SC_ACTION_NONE No action.
			// SC_ACTION_REBOOT Reboot the computer.
			// SC_ACTION_RESTART Restart the service.
			// SC_ACTION_RUN_COMMAND Run a command.
			arrSCA[0].Type = SC_ACTION_RESTART;
			// The time to wait before performing the specified action, in milliseconds.
			arrSCA[0].Delay = dwDefaultActionDelay;

			arrSCA[1].Type = SC_ACTION_RESTART;
			// The time to wait before performing the specified action, in milliseconds.
			arrSCA[1].Delay = dwDefaultActionDelay;

			arrSCA[2].Type = SC_ACTION_RESTART;
			// The time to wait before performing the specified action, in milliseconds.
			arrSCA[2].Delay = dwDefaultActionDelay;

			DWORD nActions = 3;
			//LPCTSTR strServiceName = _T("AuWatchDogService");
			LPWSTR strActionCommand = NULL;
			// The length of time, in seconds, after which to reset the failure count to zero if there are no failures.Specify INFINITE to indicate that this value should never be reset.
			sfa.dwResetPeriod = dwDefaultResetPeriod;
			// Message to broadcast to server users before rebooting in response to the SC_ACTION_REBOOT service controller action.
			sfa.lpRebootMsg = NULL;
			// Command line of the process for the CreateProcess function to execute in response to the SC_ACTION_RUN_COMMAND service controller action.This process runs under the same account as the service.
			// If this value is NULL, the command is unchanged.If the value is an empty string (""), the command is deleted and no program is run when the service fails.
			sfa.lpCommand = (arrSCA[0].Type != SC_ACTION_RUN_COMMAND ? NULL : strActionCommand);
			// Number of elements in the lpsaActions array.
			// If this value is 0, but lpsaActions is not NULL, the reset period and array of failure actions are deleted.
			sfa.cActions = nActions;
			// Pointer to an array of SC_ACTION structures.
			// If this value is NULL, the cActions and dwResetPeriod members are ignored.
			sfa.lpsaActions = arrSCA;

			SC_HANDLE hService = OpenService(hSCM, strServiceName, SERVICE_ALL_ACCESS);
			if(hService != NULL)
			{
				if(ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa))
				{
					AddLogEntry(L"SUCCESS: Configuration for Service \"%s\" changed!\n", strServiceName);
				}
				SERVICE_DESCRIPTION SD;
				//_tcscpy(SD.lpDescription, strDescription);
				SD.lpDescription = strDescription;
				::ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &SD);
				// Cleanup
				CloseServiceHandle(hService);
			}

			// Cleanup
			UnlockServiceDatabase(sclLock);
		}
		// Cleanup
		CloseServiceHandle(hSCM);
	}
	return true;
}

bool CRemoteService::SetServiceDescription(LPCTSTR lpstrServiceName, LPCTSTR lpstrDescription)
{
	bool bReturnVal = false;
	SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(hSCM != NULL)
	{
		SC_HANDLE hService = OpenService(hSCM, lpstrServiceName, SERVICE_ALL_ACCESS);
		if(hService != NULL)
		{
			SERVICE_DESCRIPTION SD;
			SD.lpDescription = (LPTSTR)lpstrDescription;
			if(::ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &SD))
			{
				bReturnVal = true;
			}
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hSCM);
	}
	return bReturnVal;
}


/*-------------------------------------------------------------------------------------
Function		: DeleteRemoteService
In Parameters	: CString csServiceName
Out Parameters	: bool
Purpose			: Delete the service on remote PC
Author			: Dipali
--------------------------------------------------------------------------------------*/
bool CRemoteService::DeleteRemoteService(CString csServiceName)
{
	// Open remote Service Manager
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(hSCM == NULL)
	{
		return FALSE;
	}

	// Open	service
	SC_HANDLE hService = ::OpenService(hSCM, csServiceName, SERVICE_ALL_ACCESS);
	if(hService  == 	NULL)
	{
		::CloseServiceHandle(hSCM);
		return FALSE;
	}

	DeleteService(hService);

	::CloseServiceHandle(hService);
	::CloseServiceHandle(hSCM);

	Sleep(3000);
	return TRUE;
}

void CRemoteService::DoUpdateSvcDesc(CString csServiceName, CString csDescription)
{
	SC_HANDLE schSCManager;
    SC_HANDLE schService;
    SERVICE_DESCRIPTION sd;
    LPTSTR szDesc = (LPTSTR)(LPCTSTR)csDescription;

    schSCManager = OpenSCManager( 
        NULL,                    // local computer
        NULL,                    // ServicesActive database 
        SC_MANAGER_ALL_ACCESS);  // full access rights 
 
    if (NULL == schSCManager) 
    {
        return;
    }

    // Get a handle to the service.

    schService = OpenService( 
        schSCManager,            // SCM database 
        csServiceName,               // name of service 
        SERVICE_CHANGE_CONFIG);  // need change config access 
 
    if (schService == NULL)
    { 
        CloseServiceHandle(schSCManager);
        return;
    }    

    // Change the service description.

    sd.lpDescription = szDesc;

    if( !ChangeServiceConfig2(
        schService,                 // handle to service
        SERVICE_CONFIG_DESCRIPTION, // change: description
        &sd) )                      // new description
    {
    }

    CloseServiceHandle(schService); 
    CloseServiceHandle(schSCManager);
}

bool CRemoteService::StartService(CString csServiceName)
{
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(hSCM == NULL)
	{
		return false;
	}

	SC_HANDLE hService = ::OpenService(hSCM, csServiceName, SERVICE_ALL_ACCESS);
	if(hService == NULL)
	{
		::CloseServiceHandle(hSCM);
		return false;
	}

	if(!::StartService(hService, 0, NULL))
	{
		::CloseServiceHandle(hService);
		::CloseServiceHandle(hSCM);
		return false;
	}

	::CloseServiceHandle(hService);
	::CloseServiceHandle(hSCM);

	return true;
}

bool CRemoteService::RegisterService(CString csServiceName,CString csAppPath,DWORD dwServiceType,DWORD dwStartType)
{
	bool bRet = false;
	SC_HANDLE hSCM = ::OpenSCManager(NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);
	if(hSCM == NULL)
	{
		return bRet;
	}

	// Maybe it's already there and installed, let's try to run
	SC_HANDLE hService =::OpenService(hSCM, csServiceName, SERVICE_ALL_ACCESS);

	// Creates service on remote machine, if it's not installed yet
	if(hService == NULL)
	{
		hService = ::CreateService(hSCM, csServiceName, csServiceName, SERVICE_ALL_ACCESS,
			dwServiceType, dwStartType,SERVICE_ERROR_NORMAL, csAppPath,
			NULL, NULL, NULL, NULL, NULL);

	}
	if(hService == NULL)
	{
		::CloseServiceHandle(hSCM);
		return bRet;
	}
	::CloseServiceHandle(hSCM);
	::CloseServiceHandle(hService);
	return true;
}