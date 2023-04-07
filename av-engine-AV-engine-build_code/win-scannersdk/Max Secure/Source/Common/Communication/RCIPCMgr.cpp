/*======================================================================================
   FILE				: RCIPCMgr.h (RC IPC Mgr)
   ABSTRACT			: 
   DOCUMENTS		: 
   AUTHOR			: Sunil Apte
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 6Nov2008
   NOTE				: 
   VERSION HISTORY	: 19 Nov. 2008 Added functions for various RC options for Vista Service. Ashwinee J.
====================================================================================== */

#include "stdafx.h"
#include "RemoteService.h"
#include "RCIPCMgr.h"

#include <aclapi.h>
//constructor
CRCIPCMgr::CRCIPCMgr(void)
{
	m_pEveryoneSID = NULL;
	m_pAdminSID = NULL;
	m_pACL = NULL;
	m_pSD = NULL;

	m_bIsServer = false;
	m_bMainServiceIsStarted = false;

	m_pSharedRCData = NULL;
	m_hSharedRCData = NULL;

	m_hRCMutex = NULL;

	m_hRCQuarantineEvent = NULL;

	m_hRCResultEvent = NULL;
	m_hRCRecoverEvent = NULL;
	m_hRCDefraggerEvent = NULL;
	m_hRCStopEvent = NULL;
	m_hRCOptionsEvent = NULL;
	m_hRCSetupEvent = NULL;

	InitSecurityAttribute();
}
//destructor
CRCIPCMgr::~CRCIPCMgr(void)
{
	if (m_pEveryoneSID) 
		FreeSid(m_pEveryoneSID);
	if (m_pAdminSID) 
		FreeSid(m_pAdminSID);
	if (m_pACL) 
		LocalFree(m_pACL);
	if (m_pSD) 
		LocalFree(m_pSD);
}
/*-------------------------------------------------------------------------------------
	Function		: CheckMainServiceStatus
	In Parameters	: -
	Out	Parameters	: void
	Purpose			: Check SDMainService status. 
	Author			: 
--------------------------------------------------------------------------------------*/

void CRCIPCMgr::CheckMainServiceStatus()
{
	CRemoteService rs;
	m_bMainServiceIsStarted = rs.IsRmoteServiceRunning(RC_VISTA_SERVICE_NAME);
}
/*-------------------------------------------------------------------------------------
	Function		: CreateEvent
	In Parameters	: const CString &csEventName - Event name
					  HANDLE &hEventHandle - Event handle
	Out	Parameters	: bool
	Purpose			: Create named shared event. 
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/

bool CRCIPCMgr::CreateEvent(const CString &csEventName, HANDLE &hEventHandle)
{
	hEventHandle = ::CreateEvent(&m_sa,FALSE,FALSE,csEventName);
	if(hEventHandle != INVALID_HANDLE_VALUE)
		return true;
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: CreateMutex
	In Parameters	: const CString &csMutexName - Mutex name
					  HANDLE &hMutexHandle - Mutex handle
	Out	Parameters	: bool
	Purpose			: Create named shared mutex. 
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CRCIPCMgr::CreateMutex(const CString &csMutexName, HANDLE &hMutexHandle)
{
	hMutexHandle = ::CreateMutex(&m_sa,FALSE,csMutexName);
	if(hMutexHandle != INVALID_HANDLE_VALUE)
		return true;
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: InitSecurityAttribute
	In Parameters	: -
	Out	Parameters	: bool
	Purpose			: Initialize security attribute. Give access to all
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CRCIPCMgr::InitSecurityAttribute()
{
	DWORD dwRes;
    EXPLICIT_ACCESS ea[2];
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
  
    // Create a well-known SID for the Everyone group.
    if(!AllocateAndInitializeSid(&SIDAuthWorld, 1,
								 SECURITY_WORLD_RID,
								 0, 0, 0, 0, 0, 0, 0,
								 &m_pEveryoneSID))
    {
        //printf("AllocateAndInitializeSid Error %u\n", GetLastError());
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);
		return;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow Everyone read access to the key.
    ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
    ea[0].grfAccessPermissions = KEY_ALL_ACCESS | SYNCHRONIZE;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance= NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName  = (LPTSTR) m_pEveryoneSID;

    // Create a SID for the BUILTIN\Administrators group.
    if(! AllocateAndInitializeSid(&SIDAuthNT, 2,
                     SECURITY_BUILTIN_DOMAIN_RID,
                     DOMAIN_ALIAS_RID_ADMINS,
                     0, 0, 0, 0, 0, 0,
                     &m_pAdminSID)) 
    {
        //printf("AllocateAndInitializeSid Error %u\n", GetLastError());
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);
		return;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow the Administrators group full access to
    // the key.
    ea[1].grfAccessPermissions = KEY_ALL_ACCESS;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance= NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName  = (LPTSTR) m_pAdminSID;

    // Create a new ACL that contains the new ACEs.
    dwRes = SetEntriesInAcl(2, ea, NULL, &m_pACL);
    if (ERROR_SUCCESS != dwRes) 
    {
        //printf("SetEntriesInAcl Error %u\n", GetLastError());
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);
		return;
	}

    // Initialize a security descriptor.  
    m_pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH); 
    if (NULL == m_pSD) 
    { 
        //printf("LocalAlloc Error %u\n", GetLastError());
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);
		return;
    } 
 
    if (!InitializeSecurityDescriptor(m_pSD, SECURITY_DESCRIPTOR_REVISION)) 
    {  
        //printf("InitializeSecurityDescriptor Error %u\n", GetLastError());
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);
		return;
    } 
 
    // Add the ACL to the security descriptor. 
    if (!SetSecurityDescriptorDacl( m_pSD, 
									TRUE,     // bDaclPresent flag   
									m_pACL, 
									FALSE))   // not a default DACL 
    {  
        //printf("SetSecurityDescriptorDacl Error %u\n",
          //      GetLastError());
		if (m_pEveryoneSID) 
			FreeSid(m_pEveryoneSID);
		if (m_pAdminSID) 
			FreeSid(m_pAdminSID);
		if (m_pACL) 
			LocalFree(m_pACL);
		if (m_pSD) 
			LocalFree(m_pSD);
		return;
    } 

    // Initialize a security attributes structure.
    m_sa.nLength = sizeof (SECURITY_ATTRIBUTES);
    m_sa.lpSecurityDescriptor = m_pSD;
    m_sa.bInheritHandle = FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: InitCommunication
	In Parameters	: 
	Out	Parameters	: 
	Purpose			: initialize shared object
	Author			: Sunil Apte
--------------------------------------------------------------------------------------*/
void CRCIPCMgr::InitCommunication()
{
	
	if(m_bIsServer == false)
	{
		CheckMainServiceStatus();
	}

	CreateMutex(RC_MUTEX_NAME,m_hRCMutex);

	//For Quarantine
	CreateEvent(RC_QUARANTINE_EVENT_NAME, m_hRCQuarantineEvent);

	m_hSharedRCData = ::CreateFileMapping(INVALID_HANDLE_VALUE,&m_sa,PAGE_READWRITE,0,
										sizeof(SHARED_RC_DATA),
										RC_SHAREDMEM_NAME);
	if (GetLastError() == ERROR_ALREADY_EXISTS) 
	{		
		m_hSharedRCData = ::OpenFileMapping(FILE_MAP_WRITE,FALSE,RC_SHAREDMEM_NAME);
	}
	if(NULL == m_hSharedRCData)
		AddLogEntry(_T("CreateFileMapping failed"));

	m_pSharedRCData = (PSHARED_RC_DATA)::MapViewOfFile(m_hSharedRCData ,FILE_MAP_WRITE,0,0,sizeof(SHARED_RC_DATA));
	if(NULL == m_pSharedRCData)
		AddLogEntry(_T("MapViewOfFile failed"));

	//For Result
	CreateEvent(RC_RESULT_EVENT_NAME, m_hRCResultEvent);
	//For Recover
	CreateEvent(RC_RECOVER_EVENT_NAME, m_hRCRecoverEvent);
	//For Defragger
	CreateEvent(RC_DEFRAGGER_EVENT_NAME, m_hRCDefraggerEvent);
	//For Stop
	CreateEvent(RC_STOP_EVENT_NAME, m_hRCStopEvent);
	//For Options
	CreateEvent(RC_OPTIONS_EVENT_NAME, m_hRCOptionsEvent);
	//RC setup
	if(!CreateEvent(RC_SETUP_EVENT_NAME, m_hRCSetupEvent))
		AddLogEntry(_T("Create event for RCSetupEvent failed"));

}

/*-------------------------------------------------------------------------------------
	Function		: DeInitCommunication
	In Parameters	: 
	Out	Parameters	: 
	Purpose			: Deinitialize shared object
	Author			: Sunil Apte
--------------------------------------------------------------------------------------*/
void CRCIPCMgr::DeInitCommunication()
{
	//For Quarantine
	if(m_hRCQuarantineEvent)
	{
		::CloseHandle(m_hRCQuarantineEvent);
		m_hRCQuarantineEvent = NULL;
	}
	if (m_hRCMutex)
	{
		::CloseHandle(m_hRCMutex);
		m_hRCMutex = NULL;
	}
	if(m_pSharedRCData)
	{
		::UnmapViewOfFile(m_pSharedRCData);
		m_pSharedRCData = NULL;
	}
	if(m_hSharedRCData)
	{
		::CloseHandle(m_hSharedRCData);
		m_hSharedRCData = NULL;
	}

	//For Result
	if(m_hRCResultEvent)
	{
		::CloseHandle(m_hRCResultEvent);
		m_hRCResultEvent = NULL;
	}
	//For Recover
	if(m_hRCRecoverEvent)
	{
		::CloseHandle(m_hRCRecoverEvent);
		m_hRCRecoverEvent = NULL;
	}

	//For Defragger
	if(m_hRCDefraggerEvent)
	{
		::CloseHandle(m_hRCDefraggerEvent);
		m_hRCDefraggerEvent = NULL;
	}
	//For Stop
	if(m_hRCStopEvent)
	{
		::CloseHandle(m_hRCStopEvent);
		m_hRCStopEvent = NULL;
	}
	//For Options
	if(m_hRCOptionsEvent)
	{
		::CloseHandle(m_hRCOptionsEvent);
		m_hRCOptionsEvent = NULL;
	}

	//For Privacy Setup
	if(m_hRCSetupEvent)
	{
		::CloseHandle(m_hRCSetupEvent);
		m_hRCSetupEvent = NULL;
	}

}


/*-----------------------------------------------------------------------------
	Function		:  ProcessUsingService()
	In Parameters	:  
	Out Parameters	: 
	Purpose			:  Quarantine
	Author			:  Sunil Apte
-----------------------------------------------------------------------------*/
bool CRCIPCMgr::ProcessUsingService(const CString &csKey,const CString &csValue,const CString &csData,
					const CString &csWormType,const bool bIsAdminEntry, const CString &csFilePath)
{
    bool bResult = false;
	HWND hMainWnd = NULL;
	hMainWnd = AfxGetMainWnd()->m_hWnd;
	if(hMainWnd == NULL)
		AddLogEntry(_T("handle hMainWnd is null in ProcessUsingService"));
	ASSERT(::IsWindow(hMainWnd));

    if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
	{
        //writing the data to shared buffer.
        if(csKey.GetLength() <=  MAX_RC_COMM_SIZE )
		    wcscpy_s(m_pSharedRCData->m_szKey, csKey);

        if(csValue.GetLength() <=  MAX_RC_COMM_SIZE )
            wcscpy_s(m_pSharedRCData->m_szValue, csValue);
       
        if(csData.GetLength() <=  MAX_RC_COMM_SIZE )
		    wcscpy_s(m_pSharedRCData->m_szData, csData);
        wcscpy_s(m_pSharedRCData->m_szWormType, csWormType);

        if(csFilePath.GetLength() <=  MAX_RC_COMM_SIZE )
            wcscpy_s(m_pSharedRCData->m_szFileName, csFilePath);        
		
		m_pSharedRCData->m_bIsAdminEntry = bIsAdminEntry;        
		m_pSharedRCData->m_hMainWnd = hMainWnd;
        //releasing the mutex.
		ReleaseMutex(m_hRCMutex);
		SetEvent(m_hRCQuarantineEvent);

		//waiting for the result 
		if(WaitForSingleObject(m_hRCResultEvent, INFINITE) == WAIT_OBJECT_0)
		{		
			if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
			{
				//reading the result.
				bResult = m_pSharedRCData->m_bResult;
				
				ReleaseMutex(m_hRCMutex);
			}
		}
	}
	return bResult;
}

/*-----------------------------------------------------------------------------
	Function		:  ProcessUsingService()
	In Parameters	:  
	Out Parameters	: 
	Purpose			:  FOR RC Option Recover Using Vista Service
	Author			:  Sunil Apte
-----------------------------------------------------------------------------*/
bool CRCIPCMgr::ProcessUsingService(const CString &csKey, const CString &csValue, const CString &csData,
		DWORD dwRegType, const CString &csFileName)
{
	bool bResult = false;

	if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
	{
		//writing the data to shared buffer.
        if(csKey.GetLength() <=  MAX_RC_COMM_SIZE )
		    wcscpy_s(m_pSharedRCData->m_szKey, csKey);
        if(csValue.GetLength() <=  MAX_RC_COMM_SIZE )
		    wcscpy_s(m_pSharedRCData->m_szValue, csValue);
        if(csData.GetLength() <=  MAX_RC_COMM_SIZE )
		    wcscpy_s(m_pSharedRCData->m_szData, csData);
        if(csFileName.GetLength() <=  MAX_RC_COMM_SIZE )
		    wcscpy_s(m_pSharedRCData->m_szFileName,csFileName);
		m_pSharedRCData->m_dwRegType = dwRegType;
		//releasing the mutex.
		ReleaseMutex(m_hRCMutex);

		SetEvent(m_hRCRecoverEvent);

		//waiting for the result 
		if(WaitForSingleObject(m_hRCResultEvent, INFINITE) == WAIT_OBJECT_0)
		{
			if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
			{
				//reading the result.
				bResult = m_pSharedRCData->m_bResult;
				
				ReleaseMutex(m_hRCMutex);
			}
		}
	}
	return bResult;
}

/*-----------------------------------------------------------------------------
	Function		:  ProcessUsingService()
	In Parameters	:  
	Out Parameters	: 
	Purpose			:  FOR RC Option Defrag Using Vista Service
	Author			:  Sunil Apte
-----------------------------------------------------------------------------*/
bool CRCIPCMgr::ProcessUsingService(ULONGLONG &ullSizeBefore, ULONGLONG  &ullSizeAfter, ULONGLONG &ullGain,
		bool bDefrag)
{
	bool bResult = false;

	if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
	{
		//writing the data to shared buffer.
		m_pSharedRCData->m_bDefrag = bDefrag;
		//releasing the mutex.
		ReleaseMutex(m_hRCMutex);

		SetEvent(m_hRCDefraggerEvent);

		//waiting for the result 
		if(WaitForSingleObject(m_hRCResultEvent, INFINITE) == WAIT_OBJECT_0)
		{
			if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
			{
				//reading the result.
				bResult = m_pSharedRCData->m_bResult;
				if(bResult)
				{
					ullSizeBefore = m_pSharedRCData->m_ullSizeBefore;
					ullSizeAfter = m_pSharedRCData->m_ullSizeAfter;
					ullGain = m_pSharedRCData->m_ullGain;
				}
				ReleaseMutex(m_hRCMutex);
			}
		}
	}
	return bResult;
}

//Stop
bool CRCIPCMgr::ProcessUsingService()
{
	SetEvent(m_hRCStopEvent);
	return true;
}

/*-----------------------------------------------------------------------------
	Function		:  ProcessUsingService()
	In Parameters	:  
	Out Parameters	: 
	Purpose			:  FOR RC Option Startup Entries (Change) Using Vista Service
	Author			:  Sunil Apte
-----------------------------------------------------------------------------*/
bool CRCIPCMgr::ProcessUsingService(const CString &csHive, const CString &csValue, CString &csNewValue)
{
	bool bResult = false;
	
	CString csSessionID = m_objExecuteProcess.GetCurrentUserSid();
//	AddLogEntry(csSessionID);
	if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
	{
		//writing the data to shared buffer.
		//wcscpy(m_pSharedRCData->m_szHive,csHive);
		wcscpy_s(m_pSharedRCData->m_szHive, csHive);

		//wcscpy(m_pSharedRCData->m_szValue,csValue);
        if(csValue.GetLength() <=  MAX_RC_COMM_SIZE )
		    wcscpy_s(m_pSharedRCData->m_szValue, csValue);

		//wcscpy(m_pSharedRCData->m_szNewValue,csNewValue);
        if(csNewValue.GetLength() <=  MAX_RC_COMM_SIZE )
		    wcscpy_s(m_pSharedRCData->m_szNewValue, csNewValue);

		//wcscpy(m_pSharedRCData->m_szID,csSessionID);
		wcscpy_s(m_pSharedRCData->m_szID, csSessionID);

		m_pSharedRCData->m_nOption = STARTUP_CHANGE;
		//releasing the mutex.
		ReleaseMutex(m_hRCMutex);

		SetEvent(m_hRCOptionsEvent);

		//waiting for the result 
		if(WaitForSingleObject(m_hRCResultEvent, INFINITE) == WAIT_OBJECT_0)
		{
			if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
			{
				//reading the result.
				bResult = m_pSharedRCData->m_bResult;
				
				ReleaseMutex(m_hRCMutex);
			}
		}
	}
	return bResult;
}


/*-----------------------------------------------------------------------------
	Function		:  ProcessUsingService()
	In Parameters	:  
	Out Parameters	: 
	Purpose			:  FOR RC Option Insert Startup entry, Delete startup entry,
					   Export entries,
					   Regisrty Backup Start, Restore, Delete using Vista Service
	Author			:  Sunil Apte
-----------------------------------------------------------------------------*/
bool CRCIPCMgr::ProcessUsingService(const CString &csEntry, RC_OPTION nOption)
{
	bool bResult = false;

	if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
	{
		//writing the data to shared buffer.
		switch(nOption)
		{
		case STARTUP_INSERT:
		case STARTUP_DELETE:
			{
				CString csSessionID = m_objExecuteProcess.GetCurrentUserSid();
				wcscpy_s(m_pSharedRCData->m_szID, csSessionID);
				wcscpy_s(m_pSharedRCData->m_szKey, csEntry);
				break;
			}
		case STARTUP_EXPORT:
			{
				CString csSessionID = m_objExecuteProcess.GetCurrentUserSid();
				wcscpy_s(m_pSharedRCData->m_szID, csSessionID);
				wcscpy_s(m_pSharedRCData->m_szFileName, csEntry);
				break;
			}
		case REGISTRYBACKUP_START:
		case REGISTRYBACKUP_RESTORE:
		case REGISTRYBACKUP_DELETE :
			{
				wcscpy_s(m_pSharedRCData->m_szFileName, csEntry);
				break;
			}
		default :
			{
				AddLogEntry(_T("Wrong entry caught in Switch Case of RCIPCMgr::ProcessUsingService()"));
				break;
			}
		}

		m_pSharedRCData->m_nOption = nOption;
		//releasing the mutex.
		ReleaseMutex(m_hRCMutex);

		SetEvent(m_hRCOptionsEvent);

		//waiting for the result 
		if(WaitForSingleObject(m_hRCResultEvent, INFINITE) == WAIT_OBJECT_0)
		{
			if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
			{
				//reading the result.
				bResult = m_pSharedRCData->m_bResult;
				
				ReleaseMutex(m_hRCMutex);
			}
		}
	}
	return bResult;
}
/*-----------------------------------------------------------------------------
	Function		:  ProcessUsingService()
	In Parameters	:  Internet Optimizer Settings Array
	Out Parameters	: 
	Purpose			:  FOR RC Option Internet Optimize/Rollback using Vista Service
	Author			:  Sunil Apte
-----------------------------------------------------------------------------*/
bool CRCIPCMgr::ProcessUsingService(const bool bInetOptiSettings[], RC_OPTION nOption)
{
	bool bResult = false;

	if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
	{
		m_pSharedRCData->m_nOption = nOption;
		for(int i=0; i<MAX_IO_SETTINGS; i++)
			m_pSharedRCData->m_bInternetOptimizerSettings[i] = bInetOptiSettings[i];
		//releasing the mutex.
		ReleaseMutex(m_hRCMutex);

		SetEvent(m_hRCOptionsEvent);

		//waiting for the result 
		if(WaitForSingleObject(m_hRCResultEvent, INFINITE) == WAIT_OBJECT_0)
		{
			if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
			{
				//reading the result.
				bResult = m_pSharedRCData->m_bResult;
				
				ReleaseMutex(m_hRCMutex);
			}
		}
	}
	return bResult;
}

/*-----------------------------------------------------------------------------
	Function		:  ProcessUsingService()
	In Parameters	:  
	Out Parameters	: 
	Purpose			:  FOR RC Option Create Restore Point Using Vista Service
	Author			:  Ashwinee J
-----------------------------------------------------------------------------*/
bool CRCIPCMgr::ProcessUsingService(const CString &csDesc, CString &csSeqNum, UINT &iRetNo)
{
	bool bResult = false;

    if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
    {
		//writing the data to shared buffer.
		wcscpy_s(m_pSharedRCData->m_szDesc, csDesc);
						
		m_pSharedRCData->m_nOption = RESTOREPOINT_CREATE;
		//releasing the mutex.
		ReleaseMutex(m_hRCMutex);

		SetEvent(m_hRCOptionsEvent);

		//waiting for the result 
		if(WaitForSingleObject(m_hRCResultEvent, INFINITE) == WAIT_OBJECT_0)
		{
			if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
			{
				//reading the result.
				iRetNo =  m_pSharedRCData->m_iRetNo;
				bResult = m_pSharedRCData->m_bResult;
				csSeqNum = m_pSharedRCData->m_szSeqNum;
				ReleaseMutex(m_hRCMutex);
			}
		}
    }
   return bResult;
}

/*-----------------------------------------------------------------------------
	Function		:  ProcessUsingService()
	In Parameters	:  
	Out Parameters	: 
	Purpose			:  FOR RC Option Remove Restore point using Vista Service
	Author			:  Ashwinee J
-----------------------------------------------------------------------------*/
bool CRCIPCMgr::ProcessUsingService(const CString &csID,bool bForLiveUpdate)
{
	bool bResult = false;

   if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
   {
	   if(bForLiveUpdate == false)
	   {
			//writing the data to shared buffer.
			wcscpy_s(m_pSharedRCData->m_szID, csID);
					
			m_pSharedRCData->m_nOption = RESTOREPOINT_REMOVE;
			//releasing the mutex.
			ReleaseMutex(m_hRCMutex);

			SetEvent(m_hRCOptionsEvent);
	   }
	   else
	   {
			//writing the data to shared buffer.
			wcscpy_s(m_pSharedRCData->m_szFileName, csID);
					
			//releasing the mutex.
			ReleaseMutex(m_hRCMutex);

			SetEvent(m_hRCSetupEvent);
	   }
		//waiting for the result 
		if(WaitForSingleObject(m_hRCResultEvent, INFINITE) == WAIT_OBJECT_0)
		{
			if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
			{
				//reading the result.
				bResult = m_pSharedRCData->m_bResult;
				ReleaseMutex(m_hRCMutex);
			}
		}
    }
   return bResult;
}


/*-----------------------------------------------------------------------------
	Function		:  ProcessUsingService()
	In Parameters	:  
	Out Parameters	: 
	Purpose			:  FOR RC Option Registry Backup Check Space for backup Using Vista Service
	Author			:  Ashwinee J
-----------------------------------------------------------------------------*/
bool CRCIPCMgr::ProcessUsingService(RC_OPTION nOption)  
{
	bool bResult = false;

	if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
	{
		//AddLogEntry(_T("Got RC Mutex"));
		m_pSharedRCData->m_nOption = nOption;
		//AddLogEntry(_T("after Set Option in shared data"));

		//releasing the mutex.
		ReleaseMutex(m_hRCMutex);
		//AddLogEntry(_T("After Release mutex"));

		SetEvent(m_hRCOptionsEvent);
		//AddLogEntry(_T("After set event"));

		//waiting for the result 
		if(WaitForSingleObject(m_hRCResultEvent, INFINITE) == WAIT_OBJECT_0)
		{
			//AddLogEntry(_T("Got result event"));

			if(WaitForSingleObject(m_hRCMutex, INFINITE) == WAIT_OBJECT_0)
			{
				//AddLogEntry(_T("Got RC Mutex for results"));

				//reading the result.
				bResult = m_pSharedRCData->m_bResult;
				ReleaseMutex(m_hRCMutex);
			}
		}
	}
	return bResult;
}

