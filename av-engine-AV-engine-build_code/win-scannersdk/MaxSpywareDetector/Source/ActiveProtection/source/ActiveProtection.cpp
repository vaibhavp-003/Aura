/*======================================================================================
   FILE				: ActiveProtection.cpp
   ABSTRACT			: Interface between Active Monitor UI and AuActiveProtectionDLL
   DOCUMENTS		: 
   AUTHOR			: Darshan Singh Virdi
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 20 Jan 2008
   NOTES			: 
   VERSION HISTORY	: 
					Version:19.0.063
					Resource:Sandip
					Description:Set Notification flag off for all monitor in StopMonitor Event
					Version:19.0.065
					Resource:Sandip
					Description:Add the Network monitor
=====================================================================================*/

#include "pch.h"
#include <Winsvc.h>
#include "ActiveProtection.h"
#include "MaxExceptionFilter.h"
#include "MaxPipes.h"
#include "MaxCommunicator.h"
#include "MaxDSrvWrapper.h"
#include <sys/types.h>
#include <sys/stat.h>
#include "MaxOnAccessOptimizer.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

HANDLE CActiveProtectionApp::m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);

#ifdef USING_FLTMGR

typedef struct _SDACTMON_MESSAGE
{
    FILTER_MESSAGE_HEADER MessageHeader;
    SDACTMON_NOTIFICATION Notification;
    OVERLAPPED Ovlp;
} SDACTMON_MESSAGE, *PSDACTMON_MESSAGE;

UINT StartMonitoring(LPVOID lpParam);
DWORD SDActMonWorker(__in PSDACTMON_THREAD_CONTEXT Context);

#else

const int MAX_BUFFER_SIZE					= 260;
const int REPLY_BYTE_IN_BUFFER				= 0;
const int IOCTL_COMMUNICATION_BUFFER		= CTL_CODE (FILE_DEVICE_UNKNOWN, 0x8001, 
														METHOD_BUFFERED, FILE_ANY_ACCESS);

// Global Buffer for Shared Memory communication with Driver
char g_sProcessCommunicationBuff[MAX_BUFFER_SIZE]			= {0};
char g_sRegistryKeyCommunicationBuff[MAX_BUFFER_SIZE]		= {0};
char g_sRegistryValueCommunicationBuff[MAX_BUFFER_SIZE]		= {0};

char g_sProcessCommunicationBuffParentProcName[MAX_BUFFER_SIZE]			= {0};
char g_sRegistryKeyCommunicationBuffParentProcName[MAX_BUFFER_SIZE]		= {0};
char g_sRegistryValueCommunicationBuffParentProcName[MAX_BUFFER_SIZE]	= {0};

#endif

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BEGIN_MESSAGE_MAP(CActiveProtectionApp, CWinApp)
END_MESSAGE_MAP()

/*-------------------------------------------------------------------------------------
	Function		: CActiveProtectionApp
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Constructor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CActiveProtectionApp::CActiveProtectionApp()
		:pProcMonitor(NULL), m_bDisplayNotification(false),m_bPauseIdleScan(false),

#ifndef USING_FLTMGR
		m_hDriver(INVALID_HANDLE_VALUE),
		m_bIsProcessLoopRunning(false), m_bIsRegistryKeyLoopRunning(false), 
		m_bMonitorDriverNeeded(false), m_bIsRegistryValueLoopRunning(false), pCookieMonitor(NULL),
		m_hEventProcessCommunicationRead(NULL), m_hEventRegKeyCommunicationRead(NULL),
		m_hEventRegValCommunicationRead(NULL), m_hEventProcessCommunicationWrite(NULL), 
		m_hEventRegKeyCommunicationWrite(NULL), m_hEventRegValCommunicationWrite(NULL),
		m_pProcMonitor(NULL), m_pRegKeyMonitor(NULL), m_pRegValueMonitor(NULL),
#endif
		pHomePageMonitor(NULL), pWinRestrictionMonitor(NULL), pIERestrictionMonitor(NULL),
		pNetworkConnectionMonitor(NULL), m_bLoadingMonitor(false), m_bPauseMonitor(false), 
		m_bPCShutDownStatus(false), pFileSystemMonitor(NULL),
		pFileAssociationMonitor(NULL), m_bRunningWin2k(false)
#ifdef USING_FLTMGR
		, m_hEventFilterDriver(NULL), m_pMonitoringThread(NULL)
#endif
{
	//link_psapi();
	_tcscpy(m_szLastUSBActivity,L"");
	GetDriveLetterList();
	m_szSharedFileName = L"";
	m_dwSharedFileCallCnt = 0x00;
	m_bRanRegValue = FALSE;
#ifndef USING_FLTMGR
	ZeroMemory(m_controlbuff, sizeof(m_controlbuff));
#endif
}

/*-------------------------------------------------------------------------------------
	Function		: ~CActiveProtectionApp()
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor - Does all the clean up job
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CActiveProtectionApp::~CActiveProtectionApp()
{
	CleanUp((CActiveMonitor *&)pProcMonitor);
	CleanUp((CActiveMonitor *&)pHomePageMonitor);
	CleanUp((CActiveMonitor *&)pFileSystemMonitor);
	CleanUp((CActiveMonitor *&)pFileAssociationMonitor);
	CleanUp((CActiveMonitor *&)pWinRestrictionMonitor);
	CleanUp((CActiveMonitor *&)pIERestrictionMonitor);
	CleanUp((CActiveMonitor *&)pCookieMonitor);
	CleanUp((CActiveMonitor *&)pNetworkConnectionMonitor);
	csArrLogicalDriver.RemoveAll();
	
#ifndef USING_FLTMGR
	CleanUpEvent(m_hEventProcessCommunicationRead);
	CleanUpEvent(m_hEventProcessCommunicationWrite);
	CleanUpEvent(m_hEventRegKeyCommunicationRead);
	CleanUpEvent(m_hEventRegKeyCommunicationWrite);
	CleanUpEvent(m_hEventRegValCommunicationRead);
	CleanUpEvent(m_hEventRegValCommunicationWrite);
	if(m_hDriver != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hDriver);
		m_hDriver = INVALID_HANDLE_VALUE;
	}
	if(m_pProcMonitor)
	{
		WaitForSingleObject(m_pProcMonitor->m_hThread, INFINITE);
		delete m_pProcMonitor;
		m_pProcMonitor = NULL;
	}
	if(m_pRegKeyMonitor)
	{
		WaitForSingleObject(m_pRegKeyMonitor->m_hThread, INFINITE);
		delete m_pRegKeyMonitor;
		m_pRegKeyMonitor = NULL;
	}
	if(m_pRegValueMonitor)
	{
		WaitForSingleObject(m_pRegValueMonitor->m_hThread, INFINITE);
		delete m_pRegValueMonitor;
		m_pRegValueMonitor = NULL;
	}
#else
	if(m_pMonitoringThread)
	{
		if(WaitForSingleObject(m_pMonitoringThread->m_hThread, 120000) == WAIT_TIMEOUT)
		{
			OutputDebugString(L"##### WaitForSingleObject Finish waiting for Main monitor thread TIMEDOUT!");
		}
		delete m_pMonitoringThread;
		m_pMonitoringThread = NULL;
	}
#endif
}

#ifndef USING_FLTMGR
/*-------------------------------------------------------------------------------------
	Function		: CleanUpEvent
	In Parameters	: HANDLE &hEvent
	Out Parameters	: -
	Purpose			: Calls CloseHandle for the provided event
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveProtectionApp::CleanUpEvent(HANDLE &hEvent)
{
	if(hEvent && hEvent != NULL)
	{
		CloseHandle(hEvent);
		hEvent = NULL;
	}
}
#endif

DWORD WINAPI ScanNwtkFileThread(LPVOID pParam)
{
	//CMaxScanner	*pTemp = (CMaxScanner *)pParam;	
	//pTemp->InitializeFullFileSigand();
	theApp.ScanNwtFile();
	return 0x0l;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanUp
	In Parameters	: CActiveMonitor *&pMonitor
	Out Parameters	: -
	Purpose			: Stops the provided monitor and deletes the objects
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveProtectionApp::CleanUp(CActiveMonitor *&pMonitor)
{
	__try
	{
		if(pMonitor)
		{
			if(pMonitor->IsMonitoring())
			{
				pMonitor->StopMonitor();
			}
			delete pMonitor;
			pMonitor = NULL;
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
										_T("CActiveProtectionApp::CleanUp")))
	{
	}
}

// The one and only CActiveProtectionApp object
CActiveProtectionApp theApp;

/*-------------------------------------------------------------------------------------
	Function		:  InitInstance
	In Parameters	: -
	Out Parameters	: BOOL 
	Purpose			: CActiveProtectionApp initialization
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
BOOL CActiveProtectionApp::InitInstance()
{
	CWinApp::InitInstance();
	CMaxExceptionFilter::InitializeExceptionFilter();
	LoadLoggingLevel();

	return TRUE;
}

/*-------------------------------------------------------------------------------------
	Function		:  ExitInstance
	In Parameters	: -
	Out Parameters	: int
	Purpose			: Forces all monitors to stop
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
int CActiveProtectionApp::ExitInstance()
{
	StopMonitor(SETPROCESS);
	StopMonitor(SETHOMEPAGE);
	StopMonitor(SETCOOKIE);
	StopMonitor(SETFILESYSTEMMONITOR);
	StopMonitor(SETHOSTMONITOR);
	StopMonitor(SETFILEASSOCIATION);
	StopMonitor(SETWINRESTRICTIONMONITOR);
	StopMonitor(SETIERESTRICTIONMONITOR);
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: SetActiveMonitor
	In Parameters	: int : Menu Item
					  bool :  Status
	Out Parameters	: bool: true,  if success
	Purpose			: Activates monitoring as per the status
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
extern "C" DLLEXPORT bool SetActiveMonitor(int iMonitorType, bool bStatus, LPVOID pMessageHandler,
										   LPVOID lpThis , bool bShutDownStatus)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	if(iMonitorType == SETGAMINGMODE && !bStatus && theApp.m_bPauseIdleScan)
	{
		return true;
	}
	bool bReturnVal = false;
	WaitForSingleObject(CActiveProtectionApp::m_hEvent, INFINITE);
	if(bStatus)
	{
		bReturnVal = theApp.StartMonitor(iMonitorType, pMessageHandler, lpThis);
	}
	else
	{
		bReturnVal = theApp.StopMonitor(iMonitorType, bShutDownStatus);
	}
	SetEvent(CActiveProtectionApp::m_hEvent);
	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
	Function		:  InitialiseMonitor
	In Parameters	: CActiveMonitor *pMonitor
	Out Parameters	: none
	Purpose			: Initialises the provided monitor and starts the protection
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::InitialiseMonitor(CActiveMonitor *&pMonitor)
{
	__try
	{
		if(!pMonitor)
		{
			return false;
		}

		bool bReturnVal = false;

		pMonitor->m_bDisplayNotification = m_bDisplayNotification;
		if(pMonitor->IsMonitoring())
		{
			bReturnVal = true;
		}
		else
		{
			if(pMonitor->StartMonitor())
			{
				if(pMonitor->IsMonitoring())
					bReturnVal = true;
				else
				{
					pMonitor->StopMonitor();
					delete pMonitor;
					pMonitor = NULL;
				}
			}
			else
			{
				delete pMonitor;
				pMonitor = NULL;
			}
		}
		return bReturnVal;
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
										_T("CActiveProtectionApp::InitialiseMonitor")))
	{
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		:  SetDisplayNotification
	In Parameters	: CActiveMonitor *pMonitor, bool bStatus
	Out Parameters	: none
	Purpose			: 
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveProtectionApp::SetDisplayNotification(CActiveMonitor *pMonitor, bool bStatus)
{
	if(pMonitor)
	{
		pMonitor->m_bDisplayNotification = bStatus;
	}
}

/*-------------------------------------------------------------------------------------
	Function		:  ReloadExcludeDatabase
	In Parameters	: CActiveMonitor *pMonitor
	Out Parameters	: none
	Purpose			: 
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::ReloadExcludeDatabase(CActiveMonitor *&pMonitor)
{
	if(pMonitor)
	{
		pMonitor->ReloadLoadExcludeDB();
		pMonitor->HandleExisting();
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		:  StartMonitor
	In Parameters	: int iMonitorType, LPVOID pMessageHandler, LPVOID lpThis
	Out Parameters	: bool: true,  if success
	Purpose			: Creates new object of the provided type and starts monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::StartMonitor(int iMonitorType, LPVOID pMessageHandler, LPVOID lpThis)
{
	bool bReturnVal = false;

	if(iMonitorType == PAUSEPROTECTION)
	{
		m_bPauseMonitor = true;
		return true;
	}

	if(m_bLoadingMonitor)
	{
		return false;
	}

	m_bLoadingMonitor = true;

	switch(iMonitorType)
	{
		case SETGAMINGMODE:
		{
			bReturnVal = SetGamingMode(true);
			m_bLoadingMonitor = false;
			return bReturnVal;
			//if(pProcMonitor)
			//{
			//	//pProcMonitor->ResumeIdleScan();
			//	//m_bPauseIdleScan = false;
			//}
			//m_bLoadingMonitor = false;
			//return true;
		}
		break;
		case SETPROCESS:
		{
			if(!pProcMonitor)
			{
				pProcMonitor = new CProcessMonitor();
				m_objScanQueMgr.SetProcMonHandle(pProcMonitor);
			}
			bReturnVal = InitialiseMonitor((CActiveMonitor *&)pProcMonitor);
			if(!bReturnVal)
			{
				m_bLoadingMonitor = false;
				return false;
			}
			else
			{
				pProcMonitor->SetHandler(pMessageHandler, lpThis);
			}
		}
		break;
		case SETFILEASSOCIATION:
		{
			if(!pFileAssociationMonitor)
			{
				pFileAssociationMonitor = new CFileAssociationMonitor();
			}
			bReturnVal = InitialiseMonitor((CActiveMonitor *&)pFileAssociationMonitor);
			if(!bReturnVal)
			{
				m_bLoadingMonitor = false;
				return false;
			}
			else
			{
				pFileAssociationMonitor->SetHandler(pMessageHandler, lpThis);
			}
		}
		break;
		case SETWINRESTRICTIONMONITOR:
		{
			if(!pWinRestrictionMonitor)
			{
				pWinRestrictionMonitor = new CWinRestrictionMonitor();
			}
			bReturnVal = InitialiseMonitor((CActiveMonitor *&)pWinRestrictionMonitor);
			if(!bReturnVal)
			{
				m_bLoadingMonitor = false;
				return false;
			}
			else
			{
				pWinRestrictionMonitor->SetHandler(pMessageHandler, lpThis);
			}
		}
		break;
		case SETIERESTRICTIONMONITOR:
		{
			if(!pIERestrictionMonitor)
			{
				pIERestrictionMonitor = new CIERestrictionMonitor();
			}
			bReturnVal = InitialiseMonitor((CActiveMonitor *&)pIERestrictionMonitor);
			if(!bReturnVal)
			{
				if(pWinRestrictionMonitor)
				{
					UnInitialiseMonitor((CActiveMonitor *&)pWinRestrictionMonitor);
				}
				m_bLoadingMonitor = false;
				return false;
			}
			else
			{
				pIERestrictionMonitor->SetHandler(pMessageHandler, lpThis);
			}
		}
		break;
		case SETHOMEPAGE:
		{
			if(!pHomePageMonitor)
			{
				pHomePageMonitor = new CHomePageMonitor();
			}
			bReturnVal = InitialiseMonitor((CActiveMonitor *&)pHomePageMonitor);
			if(!bReturnVal)
			{
				m_bLoadingMonitor = false;
				return false;
			}
			else
			{
				pHomePageMonitor->SetHandler(pMessageHandler, lpThis);
			}
		}
		break;
		case SETHOSTMONITOR:
		case SETFILESYSTEMMONITOR:
		{
			if(!pFileSystemMonitor)
			{
				pFileSystemMonitor = new CFileSystemMonitor();
			}
			bReturnVal = InitialiseMonitor((CActiveMonitor *&)pFileSystemMonitor);
			if(!bReturnVal)
			{
				m_bLoadingMonitor = false;
				return false;
			}
			else
			{
				pFileSystemMonitor->SetHandler(pMessageHandler, lpThis);
			}
		}
		break;
		case SETNOTIFICATION:
		{
			m_bDisplayNotification = true;
			SetDisplayNotification(pProcMonitor, true);
			SetDisplayNotification(pFileAssociationMonitor, true);
			SetDisplayNotification(pWinRestrictionMonitor, true);
			SetDisplayNotification(pIERestrictionMonitor, true);
			SetDisplayNotification(pHomePageMonitor, true);
			SetDisplayNotification(pFileSystemMonitor, true);
			SetDisplayNotification(pCookieMonitor, true);
			SetDisplayNotification(pNetworkConnectionMonitor, true);
			bReturnVal = true;
		}
		break;
		case SETCOOKIE:
		{
			if(!pCookieMonitor)
			{
				pCookieMonitor = new CCookieMonitor();
			}
			bReturnVal = InitialiseMonitor((CActiveMonitor *&)pCookieMonitor);
			if(!bReturnVal)
			{
				m_bLoadingMonitor = false;
				return false;
			}
		}
		break;
		//case SETNETWORKMONITOR:
		//{
		//	if(!pNetworkConnectionMonitor)
		//	{
		//		pNetworkConnectionMonitor = new CNetworkConnectionMonitor();
		//	}
		//	bReturnVal = InitialiseMonitor((CActiveMonitor *&)pNetworkConnectionMonitor);
		//	if(!bReturnVal)
		//	{
		//		m_bLoadingMonitor = false;
		//		return false;
		//	}
		//}
		//break;		
		case RELOADEXCLUDEDB:
		{
			// As Exclude DB is statically loaded in all the derived classes
			// reloading the database only once will refect for all derived classes
			if(!ReloadExcludeDatabase((CActiveMonitor *&)pProcMonitor))
			if(!ReloadExcludeDatabase((CActiveMonitor *&)pFileAssociationMonitor))
			if(!ReloadExcludeDatabase((CActiveMonitor *&)pWinRestrictionMonitor))
			if(!ReloadExcludeDatabase((CActiveMonitor *&)pIERestrictionMonitor))
				ReloadExcludeDatabase((CActiveMonitor *&)pFileSystemMonitor);
			
			bReturnVal = true;
		}
		break;
	}

	if(!bReturnVal)
	{
		m_bLoadingMonitor = false;
		return false; //For all unhandled monitors returning false!
	}

	if(iMonitorType == SETPROCESS)
	{
		pProcMonitor->HandleExisting();
	}
	else if(iMonitorType == SETHOMEPAGE)
	{
		pHomePageMonitor->HandleExisting();
	}
	else if((iMonitorType == SETFILESYSTEMMONITOR) || (iMonitorType == SETHOSTMONITOR))
	{
		pFileSystemMonitor->HandleExisting();
	}
	else if(iMonitorType == SETFILEASSOCIATION)
	{
		pFileAssociationMonitor->HandleExisting();
	}
	else if(iMonitorType == SETWINRESTRICTIONMONITOR)
	{
		pWinRestrictionMonitor->HandleExisting();
	}
	else if(iMonitorType == SETIERESTRICTIONMONITOR)
	{
		pIERestrictionMonitor->HandleExisting();
	}

	if((iMonitorType == SETPROCESS)  || (iMonitorType == SETFILEASSOCIATION) || (iMonitorType == SETWINRESTRICTIONMONITOR) 
		|| (iMonitorType == SETIERESTRICTIONMONITOR) || (iMonitorType == SETHOMEPAGE) 
		|| (iMonitorType == SETFILESYSTEMMONITOR) || (iMonitorType == SETHOSTMONITOR))
	{
		if(!m_bIsProcessLoopRunning || !m_bIsRegistryKeyLoopRunning || !m_bIsRegistryValueLoopRunning)
		{
			if(!SetupActiveMonitorDriver())
			{
				if(iMonitorType == SETPROCESS)
				{
					UnInitialiseMonitor((CActiveMonitor *&)pProcMonitor);
				}
				else if(iMonitorType == SETHOMEPAGE)
				{
					UnInitialiseMonitor((CActiveMonitor *&)pHomePageMonitor);
				}
				else if((iMonitorType == SETFILESYSTEMMONITOR) || (iMonitorType == SETHOSTMONITOR))
				{
					UnInitialiseMonitor((CActiveMonitor *&)pFileSystemMonitor);
				}
				else if(iMonitorType == SETFILEASSOCIATION)
				{
					UnInitialiseMonitor((CActiveMonitor *&)pFileAssociationMonitor);
				}
				else if(iMonitorType == SETWINRESTRICTIONMONITOR)
				{
					UnInitialiseMonitor((CActiveMonitor *&)pWinRestrictionMonitor);
				}
				else if(iMonitorType == SETIERESTRICTIONMONITOR)
				{
					UnInitialiseMonitor((CActiveMonitor *&)pIERestrictionMonitor);
				}

				m_bLoadingMonitor = false;
				return false;
			}
		}
	}

	

	m_bLoadingMonitor = false;
	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
	Function		: UnInitialiseMonitor
	In Parameters	: CActiveMonitor *&pMonitor
	Out Parameters	: bool, true if successfull else false
	Purpose			: stops the monitor and deletes the object
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::UnInitialiseMonitor(CActiveMonitor *&pMonitor)
{
	__try
	{
		if(!pMonitor)
		{
			return true;
		}

		pMonitor->SetShutDownStatus(m_bPCShutDownStatus);
		if(pMonitor->StopMonitor())
		{
			delete pMonitor;
			pMonitor = NULL;
			return true;
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
										_T("CActiveProtectionApp::UnInitialiseMonitor")))
	{
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: StopDriver
	In Parameters	: int iCurrentMonitorType
	Out Parameters	: none
	Purpose			: This function will unload the driver when all the monitors are 
						turned off.
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveProtectionApp::StopDriver(int iCurrentMonitorType)
{
	if(iCurrentMonitorType == SETPROCESS)
	{
		if((!pHomePageMonitor) && (!pWinRestrictionMonitor) && (!pIERestrictionMonitor)
			&& (!pFileSystemMonitor) && (!pFileAssociationMonitor))
		{
			if((!m_bRunningWin2k) || (m_bIsProcessLoopRunning) || (m_bIsRegistryKeyLoopRunning) || (m_bIsRegistryValueLoopRunning))
			{
				CleanUpActiveMonitorMonitor();
			}
		}
	}
	else if(iCurrentMonitorType == SETFILEASSOCIATION)
	{
		if((!pProcMonitor) && (!pHomePageMonitor) && (!pWinRestrictionMonitor) 
			&& (!pIERestrictionMonitor) && (!pFileSystemMonitor))
		{
			if((!m_bRunningWin2k) || (m_bIsProcessLoopRunning) || (m_bIsRegistryKeyLoopRunning) || (m_bIsRegistryValueLoopRunning))
			{
				CleanUpActiveMonitorMonitor();
			}
		}
	}
	else if(iCurrentMonitorType == SETWINRESTRICTIONMONITOR)
	{
		if((!pProcMonitor) && (!pHomePageMonitor) && (!pFileAssociationMonitor) 
			&& (!pIERestrictionMonitor) && (!pFileSystemMonitor))
		{
			if((!m_bRunningWin2k) || (m_bIsProcessLoopRunning) || (m_bIsRegistryKeyLoopRunning) || (m_bIsRegistryValueLoopRunning))
			{
				CleanUpActiveMonitorMonitor();
			}
		}
	}
	else if(iCurrentMonitorType == SETIERESTRICTIONMONITOR)
	{
		if((!pProcMonitor) && (!pHomePageMonitor) && (!pWinRestrictionMonitor) 
			&& (!pFileAssociationMonitor) && (!pFileSystemMonitor))
		{
			if((!m_bRunningWin2k) || (m_bIsProcessLoopRunning) || (m_bIsRegistryKeyLoopRunning) || (m_bIsRegistryValueLoopRunning))
			{
				CleanUpActiveMonitorMonitor();
			}
		}
	}
	else if(iCurrentMonitorType == SETHOMEPAGE)
	{
		if((!pProcMonitor) && (!pWinRestrictionMonitor) && (!pIERestrictionMonitor)
			&& (!pFileSystemMonitor) && (!pFileAssociationMonitor))
		{
			if((!m_bRunningWin2k) || (m_bIsProcessLoopRunning) || (m_bIsRegistryKeyLoopRunning) || (m_bIsRegistryValueLoopRunning))
			{
				CleanUpActiveMonitorMonitor();
			}
		}
	}
	else if((iCurrentMonitorType == SETFILESYSTEMMONITOR) || (iCurrentMonitorType == SETHOSTMONITOR))
	{
		if((!pProcMonitor) && (!pWinRestrictionMonitor) && (!pIERestrictionMonitor)
			&& (!pHomePageMonitor) && (!pFileAssociationMonitor))
		{
			if((!m_bRunningWin2k) || (m_bIsProcessLoopRunning) || (m_bIsRegistryKeyLoopRunning) || (m_bIsRegistryValueLoopRunning))
			{
				CleanUpActiveMonitorMonitor();
			}
		}
	}
}

/*-------------------------------------------------------------------------------------
	Function		:  StopMonitor
	In Parameters	: int iMonitorType , bool bPCShutDowbStatus
	Out Parameters	: bool: true,  if success
	Purpose			: Stops the driver and calls unitialise of the provided type
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::StopMonitor(int iMonitorType , bool bPCShutDowbStatus)
{
	if(iMonitorType == PAUSEPROTECTION)
	{
		m_bPauseMonitor = false;
		return true;
	}

	if(m_bLoadingMonitor)
	{
		return false;
	}

	bool bReturnVal = false;
	m_bLoadingMonitor = true;
	m_bPCShutDownStatus = bPCShutDowbStatus;

	if(iMonitorType != SETNOTIFICATION)
	{
		StopDriver(iMonitorType);
	}

	if(iMonitorType == SETGAMINGMODE)
	{
		bReturnVal = SetGamingMode(false);
		//m_bLoadingMonitor = false;
		//return bReturnVal;
		//if(pProcMonitor)
		//{
		//	pProcMonitor->SuspendIdleScan();
		//	m_bPauseIdleScan = true;
		//	m_bLoadingMonitor = false;
		//	return true;;
		//}
	}
	else if(iMonitorType == SETPROCESS)
	{
		bReturnVal = UnInitialiseMonitor((CActiveMonitor *&)pProcMonitor);
	}
	else if(iMonitorType == SETFILEASSOCIATION)
	{
		bReturnVal = UnInitialiseMonitor((CActiveMonitor *&)pFileAssociationMonitor);
	}
	else if(iMonitorType == SETWINRESTRICTIONMONITOR)
	{
		bReturnVal = UnInitialiseMonitor((CActiveMonitor *&)pWinRestrictionMonitor);
	}
	else if(iMonitorType == SETIERESTRICTIONMONITOR)
	{
		bReturnVal = UnInitialiseMonitor((CActiveMonitor *&)pIERestrictionMonitor);
	}
	else if(iMonitorType == SETHOMEPAGE)
	{
		bReturnVal = UnInitialiseMonitor((CActiveMonitor *&)pHomePageMonitor);
	}
	else if((iMonitorType == SETFILESYSTEMMONITOR) || (iMonitorType == SETHOSTMONITOR))
	{
		bReturnVal = UnInitialiseMonitor((CActiveMonitor *&)pFileSystemMonitor);
	}
	else if(iMonitorType == SETNOTIFICATION)
	{
		m_bDisplayNotification = false;
		SetDisplayNotification(pProcMonitor, false);
		SetDisplayNotification(pFileAssociationMonitor, false);
		SetDisplayNotification(pWinRestrictionMonitor, false);
		SetDisplayNotification(pIERestrictionMonitor, false);
		SetDisplayNotification(pHomePageMonitor, false);
		SetDisplayNotification(pFileSystemMonitor, false);
		SetDisplayNotification(pCookieMonitor, false);
		SetDisplayNotification(pNetworkConnectionMonitor, false);
		bReturnVal = true;
	}
	else if(iMonitorType == SETCOOKIE)
	{
		bReturnVal = UnInitialiseMonitor((CActiveMonitor *&)pCookieMonitor);
	}
	//else if (iMonitorType == SETNETWORKMONITOR)
	//{
	//	bReturnVal = UnInitialiseMonitor((CActiveMonitor *&)pNetworkConnectionMonitor);
	//}
	m_bLoadingMonitor = false;
	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
	Function		: InstallDriver
	In Parameters	: LCTSTR :  Driver path
					  LPCTSTR : Driver name
					  bool bAddAltitude
	Out Parameters	: bool : true if driver is installed successfully, false if failed
	Purpose			: Install Driver
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::InstallDriver(LPCTSTR sDriverFileName, LPCTSTR sDriverName, bool bAddAltitude)
{
	return false;
	
}

/*-------------------------------------------------------------------------------------
	Function		: UninstallDriver
	In Parameters	: LPCTSTR : Driver name
	Out Parameters	: bool : true if driver is unloaded
	Purpose			: Uninstall Driver
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::UninstallDriver(LPCTSTR sDriverName)
{
	bool bRetVal = false;
	SC_HANDLE hSrvManager = OpenSCManager(0, 0 , SC_MANAGER_ALL_ACCESS);
	SERVICE_STATUS sStatus = {0};
	SC_HANDLE hDriver = OpenService(hSrvManager, sDriverName, SERVICE_ALL_ACCESS);
	if(hDriver)
	{
		bRetVal = (ControlService(hDriver, SERVICE_CONTROL_STOP, &sStatus) == FALSE ? false : true);
		DeleteService(hDriver);
		CloseServiceHandle(hDriver);
		CloseServiceHandle(hSrvManager);
	}
	return bRetVal;
}

/*-------------------------------------------------------------------------------------
	Function		: UninstallDriver
	In Parameters	: LPCTSTR : Driver name
	Out Parameters	: bool : true if driver is unloaded
	Purpose			: Uninstall Driver
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::StopRunningDriver(LPCTSTR sDriverName)
{
	bool bRetVal = false;
	SC_HANDLE hSrvManager = OpenSCManager(0, 0 , SC_MANAGER_ALL_ACCESS);
	SERVICE_STATUS sStatus = {0};
	SC_HANDLE hDriver = OpenService(hSrvManager, sDriverName, SERVICE_ALL_ACCESS);
	if(hDriver)
	{
		bRetVal = (ControlService(hDriver, SERVICE_CONTROL_STOP, &sStatus) == FALSE ? false : true);
		CloseServiceHandle(hDriver);
		CloseServiceHandle(hSrvManager);
	}
	return bRetVal;
}

/*-------------------------------------------------------------------------------------
	Function		: StartDriver
	In Parameters	: LPCTSTR : Driver name
	Out Parameters	: bool : true if driver is started
	Purpose			: Start the driver
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::StartDriver(LPCTSTR sDriverName)
{
	bool bRetVal = false;
	SC_HANDLE hSrvManager = OpenSCManager(0, 0 , SC_MANAGER_ALL_ACCESS);
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

/*-------------------------------------------------------------------------------------
	Function		: StopDriver
	In Parameters	: LPCTSTR : Driver name
	Out Parameters	: bool : true if driver is stopped
	Purpose			: Stop the running driver
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::StopDriver(LPCTSTR sDriverName)
{
	if(m_hDriver != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hDriver);
		m_hDriver = INVALID_HANDLE_VALUE;
	}
	return TRUE;
}

#ifndef USING_FLTMGR
/*-------------------------------------------------------------------------------------
	Function		: ThreadProcessMonitorLoop
	In Parameters	: LPVOID
	Out Parameters	: -
	Purpose			: UINT
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
UINT ThreadProcessMonitorLoop(LPVOID lpVoid)
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	COINITIALIZE_OUTPUTDEBUGSTRING(hr);
	__try
	{
		CActiveProtectionApp *pThis = (CActiveProtectionApp*)lpVoid;
		if(pThis)
		{
			pThis->ProcessMonitorLoop();
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
		_T("AuActMon ThreadProcessMonitorLoop Mode")))
	{
	}
	CoUninitialize();
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ThreadRegistryKeyMonitorLoop
	In Parameters	: LPVOID
	Out Parameters	: -
	Purpose			: UINT
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
UINT ThreadRegistryKeyMonitorLoop(LPVOID lpVoid)
{	
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	COINITIALIZE_OUTPUTDEBUGSTRING(hr);
	__try
	{
		CActiveProtectionApp *pThis = (CActiveProtectionApp*)lpVoid;
		if(pThis)
		{
			pThis->RegistryKeyMonitorLoop();
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
		_T("AuActMon ThreadRegistryKeyMonitorLoop Mode")))
	{
	}
	CoUninitialize();
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ThreadRegistryValueMonitorLoop
	In Parameters	: LPVOID
	Out Parameters	: -
	Purpose			: UINT
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
UINT ThreadRegistryValueMonitorLoop(LPVOID lpVoid)
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	COINITIALIZE_OUTPUTDEBUGSTRING(hr);
	__try
	{
		CActiveProtectionApp *pThis = (CActiveProtectionApp*)lpVoid;
		if(pThis)
		{
			pThis->RegistryValueMonitorLoop();
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
		_T("AuActMon ThreadRegistryValueMonitorLoop Mode")))
	{
	}
	CoUninitialize();
	return 0;
}
#endif

/*-------------------------------------------------------------------------------------
	Function		: SetupActiveMonitorDriver
	In Parameters	: none
	Out Parameters	: bool, true if successfull else false
	Purpose			: Installs the driver and passes the communication buffer to the driver
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::SetupActiveMonitorDriver()
{
	if(m_bMonitorDriverNeeded)	// already running!
	{
		return true;
	}

//	// Incase case if FltMgr service is NOT available we use the driver with kernel patching technique
//#ifdef USING_FLTMGR
//	InstallDriver(ACTMON_DRIVE_FILENAME_64, ACTMON_DRIVE_TITLE, true);
//#else
//	InstallDriver(ACTMON_DRIVE_FILENAME_2K, ACTMON_DRIVE_TITLE, false);
//#endif //USING_FLTMGR

	
	if(!StartDriver(ACTMON_DRIVE_TITLE))
	{
		return false;
	}

	
#ifdef USING_FLTMGR

	m_bMonitorDriverNeeded = true;
	m_pMonitoringThread = AfxBeginThread(StartMonitoring, this, 0, 0, CREATE_SUSPENDED);
	if(m_pMonitoringThread)
	{
		m_pMonitoringThread->m_bAutoDelete = FALSE;
		m_pMonitoringThread->ResumeThread();
	}

	
#else
	DWORD dw = 0;
	DWORD controlbuff[12] = {0};

	//open device
	m_hDriver = CreateFile(ACTMON_DRIVE_SYMBOLIC, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0,
							OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

	if(m_hDriver == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	if(!CreateAllEvents())
	{
		CloseHandle(m_hDriver);
		m_hDriver = INVALID_HANDLE_VALUE;
		return false;
	}

	// First Start all threads and be ready to receive events 
	// as soon as the functions are hooked in the driver
	m_bMonitorDriverNeeded = true;
	m_pProcMonitor = AfxBeginThread(ThreadProcessMonitorLoop, (LPVOID)this, 0, 0, CREATE_SUSPENDED);
	if(m_pProcMonitor)
	{
		m_pProcMonitor->m_bAutoDelete = FALSE;
		m_pProcMonitor->ResumeThread();
	}
	m_pRegKeyMonitor = AfxBeginThread(ThreadRegistryKeyMonitorLoop, (LPVOID)this, 0, 0, CREATE_SUSPENDED);
	if(m_pRegKeyMonitor)
	{
		m_pRegKeyMonitor->m_bAutoDelete = FALSE;
		m_pRegKeyMonitor->ResumeThread();
	}
	m_pRegValueMonitor = AfxBeginThread(ThreadRegistryValueMonitorLoop, (LPVOID)this, 0, 0, CREATE_SUSPENDED);
	if(m_pRegValueMonitor)
	{
		m_pRegValueMonitor->m_bAutoDelete = FALSE;
		m_pRegValueMonitor->ResumeThread();
	}

	memset(g_sProcessCommunicationBuff, 0, MAX_BUFFER_SIZE);
	memset(g_sRegistryKeyCommunicationBuff, 0, MAX_BUFFER_SIZE);
	memset(g_sRegistryValueCommunicationBuff, 0, MAX_BUFFER_SIZE);
	memset(g_sProcessCommunicationBuffParentProcName, 0, MAX_BUFFER_SIZE);
	memset(g_sRegistryKeyCommunicationBuffParentProcName, 0, MAX_BUFFER_SIZE);
	memset(g_sRegistryValueCommunicationBuffParentProcName, 0, MAX_BUFFER_SIZE);

	controlbuff[0] = (DWORD)&g_sProcessCommunicationBuff[0];
	controlbuff[1] = (DWORD)(LPVOID)m_hEventProcessCommunicationRead;
	controlbuff[2] = (DWORD)(LPVOID)m_hEventProcessCommunicationWrite;
	controlbuff[3] = (DWORD)&g_sRegistryKeyCommunicationBuff[0];
	controlbuff[4] = (DWORD)(LPVOID)m_hEventRegKeyCommunicationRead;
	controlbuff[5] = (DWORD)(LPVOID)m_hEventRegKeyCommunicationWrite;
	controlbuff[6] = (DWORD)&g_sRegistryValueCommunicationBuff[0];
	controlbuff[7] = (DWORD)(LPVOID)m_hEventRegValCommunicationRead;
	controlbuff[8] = (DWORD)(LPVOID)m_hEventRegValCommunicationWrite;
	controlbuff[9] = (DWORD)&g_sProcessCommunicationBuffParentProcName[0];
	controlbuff[10] = (DWORD)&g_sRegistryKeyCommunicationBuffParentProcName[0];
	controlbuff[11] = (DWORD)&g_sRegistryValueCommunicationBuffParentProcName[0];

	//registry self first!
	m_controlbuff[0] = GetCurrentProcessId();

	if(!DeviceIoControl(m_hDriver, IOCTL_COMMUNICATION_BUFFER, controlbuff, sizeof(controlbuff), 0, 0, &dw, 0))
	{
		CloseHandle(m_hDriver);
		m_hDriver = INVALID_HANDLE_VALUE;
		CleanUpActiveMonitorMonitor();
		return false;
	}

#endif

	return true;
}

#ifndef USING_FLTMGR

/*-------------------------------------------------------------------------------------
	Function		: ProcessMonitorLoop
	In Parameters	: -
	Out Parameters	: -
	Purpose			: This is the main process monitor loop. driver writes data to the 
						shared buffer and triggers an event this breaks the signals the
						object and the data received is verified against the database
						if its a spyware entry the buffers frist byte is set to 1 else 
						its set to 0 which indicates the driver wether to block the 
						process which is being executed
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveProtectionApp::ProcessMonitorLoop()
{
	DWORD dwUserChoice = 0;
	m_bIsProcessLoopRunning = true;
	while(m_bMonitorDriverNeeded)
	{
		WaitForSingleObject(m_hEventProcessCommunicationRead, INFINITE);
		dwUserChoice = 1;
		if(!m_bMonitorDriverNeeded)
		{
			//write response to the buffer, and driver will get it
			memmove(&g_sProcessCommunicationBuff[REPLY_BYTE_IN_BUFFER], &dwUserChoice, 4);
			SetEvent(m_hEventProcessCommunicationWrite);
			break;
		}
		if((!m_bLoadingMonitor) && (!m_bPauseMonitor))
		{
			CString csParentProcessName(g_sProcessCommunicationBuffParentProcName);
			csParentProcessName.MakeLower();
			if(csParentProcessName.Find('\\') != -1)
			{
				csParentProcessName = csParentProcessName.Mid(csParentProcessName.ReverseFind('\\') + 1);
			}

			CString csProcessName(g_sProcessCommunicationBuff);
			csProcessName.MakeLower();
			if(pProcMonitor)
			{
				bool bStopEnum = false;
				MAX_SCANNER_INFO oScannerInfo = {0};
				oScannerInfo.eMessageInfo = Module;
				oScannerInfo.eScannerType = Scanner_Type_Max_ActMonModuleScan;
				_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), csProcessName);
				_tcscpy_s(oScannerInfo.szContainerFileName, _countof(oScannerInfo.szContainerFileName), csParentProcessName);
				pProcMonitor->CheckProcess(&oScannerInfo, CALL_TYPE_F_EXECUTE, bStopEnum);
				if((oScannerInfo.ThreatDetected == 1) || (oScannerInfo.ThreatSuspicious == 1))
				{
					dwUserChoice = 0;
				}
			}
			if(pFileSystemMonitor && dwUserChoice != 0)
			{
				if(pFileSystemMonitor->CheckFileEntry(csProcessName, csParentProcessName, 0))
					dwUserChoice = 0;
			}
		}
		//write response to the buffer, and driver will get it
		memmove(&g_sProcessCommunicationBuff[REPLY_BYTE_IN_BUFFER], &dwUserChoice, 4);
		SetEvent(m_hEventProcessCommunicationWrite);
	}
	m_bIsProcessLoopRunning = false;
}

/*-------------------------------------------------------------------------------------
	Function		: RegistryKeyMonitorLoop
	In Parameters	: -
	Out Parameters	: -
	Purpose			: This is the main Registry Key monitor loop. driver writes data to the 
						shared buffer and triggers an event this breaks the signals the
						object and the data received is verified against the database
						if its a spyware entry the buffers frist byte is set to 1 else 
						its set to 0 which indicates the driver wether to block the 
						Registry key which is being created
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveProtectionApp::RegistryKeyMonitorLoop()
{
	DWORD dwUserChoice;
	m_bIsRegistryKeyLoopRunning = true;
	while(m_bMonitorDriverNeeded)
	{
		WaitForSingleObject(m_hEventRegKeyCommunicationRead, INFINITE);
		dwUserChoice = 1;
		if(!m_bMonitorDriverNeeded) 
		{
			//write response to the buffer, and driver will get it
			memmove(&g_sRegistryKeyCommunicationBuff[REPLY_BYTE_IN_BUFFER], &dwUserChoice, 4);
			SetEvent(m_hEventRegKeyCommunicationWrite);
			break;
		}
		if((!m_bLoadingMonitor) && (!m_bPauseMonitor))
		{
			CString csParentProcessName(g_sRegistryKeyCommunicationBuffParentProcName);
			csParentProcessName.MakeLower();
			if(csParentProcessName.Find('\\') != -1)
			{
				csParentProcessName = csParentProcessName.Mid(csParentProcessName.ReverseFind('\\') + 1);
			}
			CString csRegistryKey(g_sRegistryKeyCommunicationBuff);
			csRegistryKey.MakeLower();
		}
		//write response to the buffer, and driver will get it
		memmove(&g_sRegistryKeyCommunicationBuff[REPLY_BYTE_IN_BUFFER], &dwUserChoice, 4);
		SetEvent(m_hEventRegKeyCommunicationWrite);
	}
	m_bIsRegistryKeyLoopRunning = false;
}

/*-------------------------------------------------------------------------------------
	Function		: RegistryValueMonitorLoop
	In Parameters	: -
	Out Parameters	: -
	Purpose			: This is the main Registry Value monitor loop. driver writes data to the 
						shared buffer and triggers an event this breaks the signals the
						object and the data received is verified against the database
						if its a spyware entry the buffers frist byte is set to 1 else 
						its set to 0 which indicates the driver wether to block the 
						Registry Value which is being created
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveProtectionApp::RegistryValueMonitorLoop()
{
	DWORD dwUserChoice;
	m_bIsRegistryValueLoopRunning = true;
	while(m_bMonitorDriverNeeded)
	{
		WaitForSingleObject(m_hEventRegValCommunicationRead, INFINITE);
		dwUserChoice = 1;
		if(!m_bMonitorDriverNeeded) 
		{
			//write response to the buffer, and driver will get it
			memmove(&g_sRegistryValueCommunicationBuff[REPLY_BYTE_IN_BUFFER], &dwUserChoice, 4);
			SetEvent(m_hEventRegValCommunicationWrite);
			break;
		}
		if((!m_bLoadingMonitor) && (!m_bPauseMonitor))
		{
			CString csParentProcessName(g_sRegistryValueCommunicationBuffParentProcName);
			csParentProcessName.MakeLower();
			if(csParentProcessName.Find('\\') != -1)
			{
				csParentProcessName = csParentProcessName.Mid(csParentProcessName.ReverseFind('\\') + 1);
			}
			CString csRegistryEntry(g_sRegistryValueCommunicationBuff);
			csRegistryEntry.MakeLower();
			if(pFileAssociationMonitor)
			{
				if(pFileAssociationMonitor->CheckRegistryEntry(csRegistryEntry, csParentProcessName))
					dwUserChoice = 0;
			}
			if(pHomePageMonitor && dwUserChoice != 0)
			{
				if(pHomePageMonitor->CheckRegistryEntry(csRegistryEntry, csParentProcessName))
					dwUserChoice = 0;
			}
			if(pWinRestrictionMonitor && dwUserChoice != 0)
			{
				if(pWinRestrictionMonitor->CheckRegistryEntry(csRegistryEntry, csParentProcessName))
					dwUserChoice = 0;
			}
			if(pIERestrictionMonitor && dwUserChoice != 0)
			{
				if(pIERestrictionMonitor->CheckRegistryEntry(csRegistryEntry, csParentProcessName))
					dwUserChoice = 0;
			}
		}
		//write response to the buffer, and driver will get it
		memmove(&g_sRegistryValueCommunicationBuff[REPLY_BYTE_IN_BUFFER], &dwUserChoice, 4);
		SetEvent(m_hEventRegValCommunicationWrite);
	}
	m_bIsRegistryValueLoopRunning = false;
}

#endif

/*-------------------------------------------------------------------------------------
	Function		: CleanUpActiveMonitorMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: breaks all the 3 loops and unloads the driver
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveProtectionApp::CleanUpActiveMonitorMonitor()
{
	if(!m_bMonitorDriverNeeded)	// already stopped!
	{
		return;
	}

#ifdef USING_FLTMGR
	if(m_bMonitorDriverNeeded)
	{
		m_bMonitorDriverNeeded = false;
		SetEvent(m_hEventFilterDriver);
	}
#else
	m_bMonitorDriverNeeded = false;
	SetEvent(m_hEventProcessCommunicationRead);
	SetEvent(m_hEventRegKeyCommunicationRead);
	SetEvent(m_hEventRegValCommunicationRead);
	while(m_bIsProcessLoopRunning || m_bIsRegistryKeyLoopRunning || m_bIsRegistryValueLoopRunning)
	{
		Sleep(10);
	}
	StopDriver(_T("SDActMon"));
#endif
}

#ifndef USING_FLTMGR
/*-------------------------------------------------------------------------------------
	Function		: CreateAllEvents
	In Parameters	: -
	Out Parameters	: bool, true if successfull else false
	Purpose			: Creats all evetns required for communication with the driver
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveProtectionApp::CreateAllEvents()
{
	m_hEventProcessCommunicationRead = CreateEvent(NULL, FALSE, FALSE, NULL);
	if(!m_hEventProcessCommunicationRead)
	{
		return false;
	}

	m_hEventProcessCommunicationWrite = CreateEvent(NULL, FALSE, FALSE, NULL);
	if(!m_hEventProcessCommunicationWrite)
	{
		return false;
	}

	m_hEventRegKeyCommunicationRead = CreateEvent(NULL, FALSE, FALSE, NULL);
	if(!m_hEventRegKeyCommunicationRead)
	{
		return false;
	}

	m_hEventRegKeyCommunicationWrite = CreateEvent(NULL, FALSE, FALSE, NULL);
	if(!m_hEventRegKeyCommunicationWrite)
	{
		return false;
	}

	m_hEventRegValCommunicationRead = CreateEvent(NULL, FALSE, FALSE, NULL);
	if(!m_hEventRegValCommunicationRead)
	{
		return false;
	}

	m_hEventRegValCommunicationWrite = CreateEvent(NULL, FALSE, FALSE, NULL);
	if(!m_hEventRegValCommunicationWrite)
	{
		return false;
	}

	return true;
}
#endif

bool CActiveProtectionApp::GetDriveLetterPath(CString &csDevicePath)
{
	int iCount = 0;
	int iPos= 0;
	bool bFound = false;
	while(iCount<csArrLogicalDriver.GetSize())
	{
		iPos= 0;
		CString csDevice = csArrLogicalDriver.GetAt(iCount);
		CString csPath =  csDevice.Tokenize(L";",iPos);
		if(csDevicePath.Find(csPath) != -1)
		{
			bFound = true;
			CString csDrive = csDevice.Tokenize(L";",iPos);
			csDevicePath.Replace(csPath,csDrive);
			break;
		}
		iCount++;
	}
	return bFound;
}
void CActiveProtectionApp::GetDriveLetterList()
{
	DWORD dwSize = MAX_PATH;
	TCHAR szLogicalDrives[MAX_PATH] = {0};
	csArrLogicalDriver.RemoveAll();
	DWORD dwResult = GetLogicalDriveStrings(dwSize,szLogicalDrives);	
	
	CString csDevice;
	DWORD	dwCount =0;
	if(dwResult>0 && dwResult< MAX_PATH)
	{
		while(dwCount <dwResult)
		{
			CString csDrive(szLogicalDrives[dwCount]);
			dwCount+=4;
			csDrive+=L":";
			CString csDevice = _T("");

			TCHAR Buffer[MAX_PATH + 1] = {0};
			
			QueryDosDevice(csDrive,Buffer,MAX_PATH);
			csDevice.Format(L"%s;%s",Buffer,csDrive);
			csDevice.MakeLower();
			csArrLogicalDriver.Add(csDevice);
			
		}
	}
}

#ifdef USING_FLTMGR

/*-------------------------------------------------------------------------------------
	Function       : StartMonitoring
	In Parameters  : LPVOID lpParam
	Out Parameters : VOID
	Purpose		   : Thread for starting the requested number of worker threads
	Author		   : Darshan Singh Virdi
-------------------------------------------------------------------------------------*/
UINT StartMonitoring(LPVOID lpParam)
{
    DWORD threadCount = SDACTMON_DEFAULT_THREAD_COUNT;
	HANDLE threads[SDACTMON_MAX_THREAD_COUNT] = {INVALID_HANDLE_VALUE};
	SDACTMON_THREAD_CONTEXT context = {0};
    HANDLE port = INVALID_HANDLE_VALUE, completion = NULL;
    PSDACTMON_MESSAGE msg = NULL;
    DWORD threadId;
    HRESULT hr;
    DWORD i;

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	COINITIALIZE_OUTPUTDEBUGSTRING(hr);

    hr = FilterConnectCommunicationPort(SDActMonPortName, 0, NULL, 0, NULL, &port);

    if(IS_ERROR(hr))
	{
		CoUninitialize();
        return 0;
    }

	
	completion = CreateIoCompletionPort(port, NULL, 0, threadCount);

	
    if(completion == NULL)
	{
        CloseHandle(port);
		CoUninitialize();
        return 0;
    }

	context.Port = port;
    context.Completion = completion;

	
	((CActiveProtectionApp*)lpParam)->m_hEventFilterDriver = CreateEvent(NULL, FALSE, FALSE, NULL);

	
	for(i = 0; i < threadCount; i++)
	{
		context.pThis = lpParam;
        threads[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SDActMonWorker, &context, 0, &threadId);
        if(threads[i] == NULL)
		{
            hr = GetLastError();
            goto cleanup_n_return;
        }

#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "msg will not be leaked because it is freed in SDActMonWorker")
		msg = NULL;
        msg = (PSDACTMON_MESSAGE)malloc(sizeof(SDACTMON_MESSAGE));
        if(msg == NULL)
		{
            hr = ERROR_NOT_ENOUGH_MEMORY;
            goto cleanup_n_return;
        }

		memset(&msg->Ovlp, 0, sizeof(OVERLAPPED));

        hr = FilterGetMessage(port, &msg->MessageHeader, FIELD_OFFSET(SDACTMON_MESSAGE, Ovlp), &msg->Ovlp);

		if(hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
		{
            free(msg);
            goto cleanup_n_return;
        }
    }

	hr = S_OK;

	

	WaitForSingleObject(((CActiveProtectionApp*)lpParam)->m_hEventFilterDriver, INFINITE);
	CloseHandle(((CActiveProtectionApp*)lpParam)->m_hEventFilterDriver);
	((CActiveProtectionApp*)lpParam)->m_hEventFilterDriver = NULL;

    CloseHandle(port);
	port = INVALID_HANDLE_VALUE;
    CloseHandle(completion);
	completion = NULL;

	if(WaitForMultipleObjectsEx(i, threads, TRUE, 60000, FALSE) == WAIT_TIMEOUT)
	{
		OutputDebugString(L"##### WaitForMultipleObjectsEx Finish waiting for worker thread TIMEDOUT!");
	}

cleanup_n_return:

	if(port != INVALID_HANDLE_VALUE)
	{
		CloseHandle(port);
		port = INVALID_HANDLE_VALUE;
	}
	if(completion)
	{
		CloseHandle(completion);
		completion = NULL;
	}
	CoUninitialize();
    return 0;
}

/*-------------------------------------------------------------------------------------
	Function       : SDActMonWorker
	In Parameters  : PSDACTMON_THREAD_CONTEXT Context
	Out Parameters : VOID
	Purpose		   : Thread receives all events generated in the system and logs it
					 in a file according to the parser requirements!
	Author		   : Darshan Singh Virdi
-------------------------------------------------------------------------------------*/
DWORD SDActMonWorker(__in PSDACTMON_THREAD_CONTEXT Context)
{
    PSDACTMON_NOTIFICATION notification = NULL;
    SDACTMON_REPLY_MESSAGE replyMessage;
    PSDACTMON_MESSAGE message = NULL;
    LPOVERLAPPED pOvlp = NULL;
    BOOL result = FALSE;
    DWORD outSize = 0x00;
    HRESULT hr;
    ULONG_PTR key = NULL;

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	COINITIALIZE_OUTPUTDEBUGSTRING(hr);

	CActiveProtectionApp *pThis = (CActiveProtectionApp *)Context->pThis;

	CString csTemp;
	csTemp.Format(_T("##### [%d] Worker Thread Ready!\n"), GetCurrentThreadId());
	OutputDebugString(csTemp);

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

    while(TRUE)
	{

#pragma warning(pop)

        result = GetQueuedCompletionStatus(Context->Completion, &outSize, &key, &pOvlp, INFINITE);

		if(!result)
		{
			message = NULL;
            hr = HRESULT_FROM_WIN32(GetLastError());
            break;
        }

		message = NULL;
		message = CONTAINING_RECORD(pOvlp, SDACTMON_MESSAGE, Ovlp);

		if (message == NULL)
		{
			break;
		}

        notification = &message->Notification;

		result = TRUE;
		if(pThis)
		{
			result = pThis->HandleNotification(notification);
		}

        replyMessage.ReplyHeader.Status = 0;
        replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;
        replyMessage.Reply.SafeToOpen = result;

		hr = FilterReplyMessage(Context->Port, (PFILTER_REPLY_HEADER) &replyMessage, sizeof(replyMessage));
		if(!SUCCEEDED(hr))
		{
            break;
        }

        memset(&message->Ovlp, 0, sizeof(OVERLAPPED));

        hr = FilterGetMessage(Context->Port, &message->MessageHeader, FIELD_OFFSET(SDACTMON_MESSAGE, Ovlp), &message->Ovlp);
        if(hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
		{
            break;
        }
    }
	if(message)
	{
		free(message);
		message = NULL;
	}

	CoUninitialize();

	return hr;
}

BOOL CActiveProtectionApp::IsFileofInterest(LPCTSTR pszFile2Check)
{
	BOOL	bRetValue = FALSE;
	TCHAR	szFile2Check[1024] = {0x00};

	/*
	if (pszFile2Check == NULL)
	{
		return bRetValue;
	}

	
	_tcscpy(szFile2Check,pszFile2Check);
	_tcslwr(szFile2Check);

	if ((_tcsstr(szFile2Check,L"\\windows\\") != NULL) || (_tcsstr(szFile2Check,L"\\program files") != NULL) || (_tcsstr(szFile2Check,L"\\~!") != NULL))
	{
		return bRetValue;
	}
	*/	
	if (pszFile2Check)
	{
		if (_tcslen(pszFile2Check) <= 0x06)
		{
			return FALSE;
		}
	}
	return TRUE;
}

BOOL CActiveProtectionApp::HandleNotification(PSDACTMON_NOTIFICATION pNotification)
{
	TCHAR	szLogEntry[1024] = {0x00};
	
	BOOL bAllowEntry = TRUE;
	BOOL bFileStatus = FALSE;
	if(pNotification == NULL)
	{
		return bAllowEntry;
	}

	if (pProcMonitor && pProcMonitor->m_bIsMonitoring == false)
	{
		return bAllowEntry;
	}

	if((!m_bMonitorDriverNeeded) || (m_bLoadingMonitor) || (m_bPauseMonitor))
	{
		return bAllowEntry;
	}

	CString csParentProcessName((LPCTSTR)pNotification->ProcessName);
	CString csParentProcessNameTemp((LPCTSTR)pNotification->ProcessName);
	csParentProcessName.MakeLower();
	csParentProcessNameTemp.MakeLower();
	if(csParentProcessName.Find('\\') != -1)
	{
		csParentProcessName = csParentProcessName.Mid(csParentProcessName.ReverseFind('\\') + 1);
	}
	
	CString csAccessed_1(L""), csAccessed_2(L""), csDisplay(L""), csProcessDrive(L"");

	csProcessDrive = csAccessed_1 = (LPCTSTR)pNotification->Accessed_1; csAccessed_1.MakeLower();
	csAccessed_2 = (LPCTSTR)pNotification->Accessed_2; csAccessed_2.MakeLower();
	csProcessDrive.MakeLower();

	CString csLog;
	if (pNotification->TypeOfCall == CALL_TYPE_U_CREATE || pNotification->TypeOfCall == CALL_TYPE_U_WRITE || pNotification->TypeOfCall == CALL_TYPE_U_EXECUTE)
	{
		if (!csProcessDrive.IsEmpty())
		{
			bool bRecheck = GetDriveLetterPath(csProcessDrive);
			if(!bRecheck)
			{
				GetDriveLetterList();
				GetDriveLetterPath(csProcessDrive);
			}
		}
	}

	if (pNotification->TypeOfCall == CALL_TYPE_F_NEW_FILE || pNotification->TypeOfCall == CALL_TYPE_F_EXECUTE || pNotification->TypeOfCall == CALL_TYPE_C_CREATE)
	{
		if (!csParentProcessNameTemp.IsEmpty())
		{
			if (csParentProcessNameTemp.Find(L":") == -1)
			{
				bool bRecheck = GetDriveLetterPath(csParentProcessNameTemp);
				if (!bRecheck)
				{
					GetDriveLetterList();
					GetDriveLetterPath(csParentProcessNameTemp);
				}
			}
		}
	}
	
	switch(pNotification->TypeOfCall)
	{
	case CALL_TYPE_F_KIDO_FILE:
		{
			if(pProcMonitor)
			{
				if(pProcMonitor->ScanThreads(csAccessed_1, csParentProcessName, csAccessed_2))
				{
					bAllowEntry = FALSE;
				}
			}
		}
	case CALL_TYPE_F_NEW_FILE:
		
		if(pProcMonitor)
		{
			//CMaxOnAccessOptimizer	objOptimizer;
			if (m_objMaxWhiteListMgr.SearchINBlackDB(csAccessed_1, true) == MAX_WHITELIST_BLOCK || m_objMaxWhiteListMgr.SearchINBlackDB(csParentProcessNameTemp, true) == MAX_WHITELIST_BLOCK)
			{
				bAllowEntry = FALSE;
			}
			/*
			else if (((csAccessed_1.Find(L"!-\\") != -1) || (csAccessed_1.Find(L"\\!-scpgt") != -1)  ||
				     (csAccessed_1.Find(L"\\documents\\") != -1) || (csAccessed_1.Find(L"\\videos\\") != -1) ||
					 (csAccessed_1.Find(L"\\music\\") != -1) || (csAccessed_1.Find(L"\\desktop\\") != -1) ||
				     (csAccessed_1.Find(L"\\pictures\\") != -1)) && (csAccessed_1.Find(L".dll") == -1 && csAccessed_1.Find(L".exe") == -1) )
			{
				bAllowEntry = m_objScanQueMgr.SendFileforRansomCheck(csAccessed_1, csParentProcessNameTemp, csParentProcessNameTemp, pNotification->TypeOfCall, (ULONG)pNotification->ProcessID, pNotification->TypeOfReplication);
				if (bAllowEntry)
				{
					m_objScanQueMgr.AddInScanQueue(csAccessed_1, csParentProcessName, csParentProcessNameTemp, pNotification->TypeOfCall, (ULONG)pNotification->ProcessID, pNotification->TypeOfReplication);
				}
			}
			//if (objOptimizer.SkipFileScanning(csAccessed_1,csParentProcessName) == FALSE)
			*/
			else
			{
				//m_objScanQueMgr.AddInScanQueue(csAccessed_1,csParentProcessName,L"",pNotification->TypeOfCall,(ULONG)pNotification->ProcessID,pNotification->TypeOfReplication);
				m_objScanQueMgr.AddInScanQueue(csAccessed_1,csParentProcessName,csParentProcessNameTemp,pNotification->TypeOfCall,(ULONG)pNotification->ProcessID,pNotification->TypeOfReplication);
				bAllowEntry = TRUE;
			}
			
		}
		
		break;
	case CALL_TYPE_F_EXECUTE:
		{
			if(pProcMonitor)
			{
				CMaxOnAccessOptimizer	objOptimizer;
				
				if (csAccessed_1.Find(L"dllhost.exe") != -1)
				{
					bAllowEntry = TRUE;
					return bAllowEntry;
				}

				if (m_objMaxWhiteListMgr.m_dwWhiteListEnable)
				{
					if (csAccessed_1.Find(L".exe") != -1)
					{
						int iAppWhiteListStatus = MAX_WHITELIST_NOTFOUND;
						iAppWhiteListStatus = m_objMaxWhiteListMgr.SearchDB(csAccessed_1);
						if (iAppWhiteListStatus == MAX_WHITELIST_BLOCK)
						{
							bAllowEntry = FALSE;
							return bAllowEntry;
						}
					}
				}

				if( (theApp.m_bRanRegValue || m_objMaxWhiteListMgr.m_dwWhiteListEnable ) && (m_objMaxWhiteListMgr.SearchINBlackDB(csAccessed_1,true) == MAX_WHITELIST_BLOCK || m_objMaxWhiteListMgr.SearchINBlackDB(csParentProcessNameTemp, true) == MAX_WHITELIST_BLOCK))
				{
					CString csTitle = _T("File Blocked");
					pProcMonitor->DisplayNotification( csTitle + ACTMON_DATA_SEPERATOR +csAccessed_1);
					bAllowEntry = FALSE;
				}
				//else if (objOptimizer.SkipFileScanningExecute(csParentProcessName) == TRUE)
				//{
				//	bAllowEntry = TRUE;
				//}
				else
				{
					if (csParentProcessNameTemp.Find(L":\\windows\\") != -1 && (csAccessed_1.Find(L":\\windows\\") != -1 && csAccessed_1.Find(L".dll") != -1))
					{
						m_objScanQueMgr.AddInScanQueue(csAccessed_1,csParentProcessName,csParentProcessNameTemp,pNotification->TypeOfCall,(ULONG)pNotification->ProcessID,pNotification->TypeOfReplication);
						bAllowEntry = TRUE;
					}
					else if (csParentProcessNameTemp.Find(L":\\windows\\") != -1 && csAccessed_1.Find(L"\\desktop\\") != -1 )
					{
						m_objScanQueMgr.AddInScanQueue(csAccessed_1, csParentProcessName, csParentProcessNameTemp, pNotification->TypeOfCall, (ULONG)pNotification->ProcessID, pNotification->TypeOfReplication);
						bAllowEntry = TRUE;
					}
					else if (csParentProcessNameTemp.Find(L"\\windowsapps\\") != -1)
					{
						m_objScanQueMgr.AddInScanQueue(csAccessed_1, csParentProcessName, csParentProcessNameTemp, pNotification->TypeOfCall, (ULONG)pNotification->ProcessID, pNotification->TypeOfReplication);
						bAllowEntry = TRUE;
					}
					else
					{
						if (csAccessed_1.Find(L".exe") != -1 || csAccessed_1.Find(L".dll") != -1)
						{
							if (m_objScanQueMgr.ScanProcessWithPriority(csAccessed_1, csParentProcessName, csParentProcessNameTemp, pNotification->TypeOfCall, (ULONG)pNotification->ProcessID, pNotification->TypeOfReplication) == FALSE)
							{
								bAllowEntry = FALSE;
							}
						}
						else
						{
							m_objScanQueMgr.AddInScanQueue(csAccessed_1, csParentProcessName, csParentProcessNameTemp, pNotification->TypeOfCall, (ULONG)pNotification->ProcessID, pNotification->TypeOfReplication);
							bAllowEntry = TRUE;
						}
					}
				}
			}
		}
		break;
	case CALL_TYPE_C_CREATE:
		{
			if (pProcMonitor)
			{
				if (m_objMaxWhiteListMgr.SearchINBlackDB(csAccessed_1, true) == MAX_WHITELIST_BLOCK || m_objMaxWhiteListMgr.SearchINBlackDB(csParentProcessNameTemp, true) == MAX_WHITELIST_BLOCK)
				{
					bAllowEntry = FALSE;
				}
				else 
				{
					//bAllowEntry = m_objScanQueMgr.SendFileforRansomCheck(csAccessed_1, csParentProcessNameTemp, csParentProcessNameTemp, pNotification->TypeOfCall, (ULONG)pNotification->ProcessID, pNotification->TypeOfReplication);
					m_objScanQueMgr.AddInScanQueue(csAccessed_1, csParentProcessName, csParentProcessNameTemp, pNotification->TypeOfCall, (ULONG)pNotification->ProcessID, pNotification->TypeOfReplication);
				}
			}
		}
		break;
	case CALL_TYPE_F_CREATE:
	case CALL_TYPE_F_OPEN:
	case CALL_TYPE_F_RENAME:
	case CALL_TYPE_F_DELETE:
	case CALL_TYPE_F_NEW_SYS_FILE:
	case CALL_TYPE_F_REN_SYS_FILE:
	case CALL_TYPE_F_DEL_SYS_FILE:
	case CALL_TYPE_F_MOD_SYS_FILE:
		{
			if(pFileSystemMonitor)
			{
				if(pFileSystemMonitor->CheckFileEntry(csAccessed_1, csParentProcessName, pNotification->TypeOfCall))
				{
					bAllowEntry = FALSE;
				}
				if(bAllowEntry && csAccessed_2.GetLength() > 0)
				{
					if(pFileSystemMonitor->CheckFileEntry(csAccessed_2, csParentProcessName, pNotification->TypeOfCall))
					{
						bAllowEntry = FALSE;
					}
				}
			}
		}
		break;
	case CALL_TYPE_R_SETVAL:
		{
			if (csParentProcessNameTemp.Find(L":\\windows\\") == -1 && csParentProcessNameTemp.Find(L"\\windowsapps\\") == -1)
			{
				csAccessed_1 += _T("\\") + csAccessed_2;
				if (pFileAssociationMonitor)
				{
					if (pFileAssociationMonitor->CheckRegistryEntry(csAccessed_1, csParentProcessName))
					{
						bAllowEntry = FALSE;
					}
				}
				if (pHomePageMonitor && bAllowEntry != FALSE)
				{
					if (pHomePageMonitor->CheckRegistryEntry(csAccessed_1, csParentProcessName))
					{
						bAllowEntry = FALSE;
					}
				}
				if (pWinRestrictionMonitor && bAllowEntry != FALSE)
				{
					if (pWinRestrictionMonitor->CheckRegistryEntry(csAccessed_1, csParentProcessName))
					{
						bAllowEntry = FALSE;
					}
				}
				if (pIERestrictionMonitor && bAllowEntry != FALSE)
				{
					if (pIERestrictionMonitor->CheckRegistryEntry(csAccessed_1, csParentProcessName))
					{
						bAllowEntry = FALSE;
					}
				}
			}
		}
		break;
	case CALL_TYPE_U_CREATE:
		csLog.Format(_T("USB_Create: %s, %s "),csProcessDrive,csParentProcessName);
		//AddLogEntryUSBlog(csLog);
		WriteUSBActivityLog(csLog);
		break;
	case CALL_TYPE_U_WRITE:
		csLog.Format(_T("USB_Write: %s, %s "),csProcessDrive,csParentProcessName);
		//AddLogEntryUSBlog(csLog);
		WriteUSBActivityLog(csLog);
		break;
	case CALL_TYPE_U_EXECUTE:
		csLog.Format(_T("USB_Execute: %s, %s "),csProcessDrive,csParentProcessName);
		//AddLogEntryUSBlog(csLog);
		WriteUSBActivityLog(csLog);
		break;
	case CALL_TYPE_N_CREATE:
		{
			TCHAR			szFile2Search[1024] = {0x00};

			bAllowEntry = TRUE;

			if(pProcMonitor)
			{
				if (csAccessed_1.IsEmpty())
				{
					bAllowEntry = TRUE;
					break;
				}

				if (csAccessed_1.GetLength() == 0x00)
				{
					bAllowEntry = TRUE;
					break;
				}

				_stprintf(szFile2Search,L"%s",csAccessed_1);

				if (IsFileofInterest(szFile2Search) == FALSE)
				{
					bAllowEntry = TRUE;
					break;
				}

				if (m_szSharedFileName.Find(szFile2Search) == -1)
				{
					m_szSharedFileName = szFile2Search;//csAccessed_1;
					m_dwSharedFileCallCnt++;
					bAllowEntry = TRUE;

					break;
				}
				else
				{
					m_dwSharedFileCallCnt++;
					if (m_dwSharedFileCallCnt >= 0x02)
					{
						//m_szNwtkFile2Scan = m_szSharedFileName;
						m_szSharedFileName.Format(L"");
						m_dwSharedFileCallCnt= 0x00;
					}
				}
				
				CMaxFileShareInfo	objMaxFileShareInfo;
				TCHAR				szUserName[MAX_PATH] = {0x00},szCompName[MAX_PATH] = {0x00},szIpv6Addr[MAX_PATH] = {0x00},szIpv4Addrs[MAX_PATH] = {0x00};
				
				BOOL bRetvalue = objMaxFileShareInfo.GetSharedFileInfo(szFile2Search,szUserName,szCompName,szIpv4Addrs,szIpv6Addr);
				if (bRetvalue)
				{
					//if (objOptimizer.SkipFileScanning(szFile2Search,L"system") == FALSE)
					{
						CString csNwtrNotify;
						csNwtrNotify.Format(L"Computer Name = %s \r\n IP Address = %s \r\n %s",szCompName,szIpv4Addrs,szFile2Search);
						m_objScanQueMgr.AddInScanQueue(szFile2Search,L"system",csNwtrNotify,pNotification->TypeOfCall,0x04,0x00);

						//objMaxFileShareInfo.DelUserSession(szUserName);
						bAllowEntry = TRUE;
					}
				}
				
			}
		}
		break;
	}

	return bAllowEntry;
}
#endif

bool CActiveProtectionApp::ScanNwtFile()
{
	TCHAR	szFile2Search[1024] = {0x00},szLogEntry[1024] = {0x00};
	CString csLog;
	HANDLE hMutex = INVALID_HANDLE_VALUE;

	_stprintf(szFile2Search,L"%s",m_objNwrkFile.szFile2Scan);
	if (_tcslen(szFile2Search) <= 0x00)
	{
		return false;
	}

	CMaxFileShareInfo	objMaxFileShareInfo;
	TCHAR				szUserName[MAX_PATH] = {0x00},szCompName[MAX_PATH] = {0x00},szIpv6Addr[MAX_PATH] = {0x00},szIpv4Addrs[MAX_PATH] = {0x00};

	_tcscpy(szCompName,m_objNwrkFile.szCompName);
	_tcscpy(szIpv4Addrs,m_objNwrkFile.szIPAddress);
	

	hMutex = NULL;
	hMutex = OpenMutex(SYNCHRONIZE,FALSE,L"_MAX_NWTR_SCAN_");
	if (hMutex)
	{
		WaitForSingleObject(hMutex,3000);
		CloseHandle(hMutex);
		hMutex = NULL;
	}
	hMutex = CreateMutex(NULL,TRUE,L"_MAX_NWTR_SCAN_");

	try
	{
		
		CMaxOnAccessOptimizer	objOptimizer;
		if (objOptimizer.SkipFileScanning(szFile2Search,L"system") == FALSE)
		{
			
			//if (bRetvalue)
			{

				//if (objOptimizer.SkipFileScanning(szFile2Search,csParentProcessName) == FALSE)
				//{
				
				bool bStopEnum = false;
				DWORD dwFileSize = 0;
				MAX_SCANNER_INFO oScannerInfo = {0};
				oScannerInfo.eMessageInfo = Process;
				oScannerInfo.eScannerType = Scanner_Type_Max_ProcScan;
				//if(pNotification->TypeOfReplication == 1)
				//{
					oScannerInfo.ulProcessIDToScan = 0x04;
					oScannerInfo.ulReplicatingProcess = 0x00;
				//}
					/*
				if(pNotification->TypeOfReplication == 2)
				{
					oScannerInfo.ulProcessIDToScan = (ULONG)pNotification->ProcessID;
					oScannerInfo.ulReplicatingProcess = pNotification->TypeOfReplication;
				}
				*/
				_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), szFile2Search);
				_tcscpy_s(oScannerInfo.szContainerFileName, _countof(oScannerInfo.szFileToScan), L"system");

				if(pProcMonitor->CheckProcess(&oScannerInfo, CALL_TYPE_N_CREATE, bStopEnum))
				{
					//if (bRetvalue)
					{

						if (hMutex)
						{
							CloseHandle(hMutex);
							hMutex = NULL;
						}

						CString csTitle = _T("Network Infection Found");
						csLog.Format(L"Computer Name = %s \r\n IP Address = %s \r\n %s",szCompName,szIpv4Addrs,szFile2Search);
						pProcMonitor->DisplayNotification( csTitle + ACTMON_DATA_SEPERATOR + csLog);
					}
				}
				//objMaxFileShareInfo.DelUserSession(szUserName);
			}
		}
	}
	catch(...)
	{
	}

	

	return true;
}

bool CActiveProtectionApp::SetGamingMode(bool bStatus)
{
	CMaxDSrvWrapper objMaxDSrvWrapper;
	bool bRetVal = objMaxDSrvWrapper.SetGamingMode(bStatus);

	MAX_PIPE_DATA_REG oPipeData = {0};
	oPipeData.eMessageInfo = GamingMode;
	oPipeData.ulSpyNameID = (ULONG)bStatus;
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
	objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG));

	return bRetVal;
}

bool CActiveProtectionApp::WriteUSBActivityLog(LPCTSTR pszEntry2Write)
{
	bool bRetVal = false;

	if (pszEntry2Write == NULL)
	{
		return bRetVal;
	}
	if (_tcslen(m_szLastUSBActivity) > 0x00)
	{
		if (_tcsstr(m_szLastUSBActivity,pszEntry2Write) == NULL)
		{
			_tcscpy(m_szLastUSBActivity,pszEntry2Write);
			AddLogEntryUSBlog(pszEntry2Write);
			bRetVal = true;
		}
	}
	else
	{
		_tcscpy(m_szLastUSBActivity,pszEntry2Write);
		AddLogEntryUSBlog(pszEntry2Write);
		bRetVal = true;
	}

	return bRetVal;
}
bool CActiveProtectionApp::ResetRanRegValue()
{
	theApp.m_bRanRegValue = FALSE;
	CRegistry objReg;
	DWORD dw = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("CryptMonitor"), dw, HKEY_LOCAL_MACHINE);
	if(dw)
	{
		theApp.m_bRanRegValue = TRUE;
	}
	return true;
}
/*-------------------------------------------------------------------------------------
	Function		: MonRanRegValue
	In Parameters	: int : Menu Item
					  bool :  Status
	Out Parameters	: bool: true,  if success
	Purpose			: Activates monitoring as per the status
--------------------------------------------------------------------------------------*/
extern "C" DLLEXPORT bool MonRanRegValue()
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	bool bReturnVal = theApp.ResetRanRegValue();
	return bReturnVal;
}
