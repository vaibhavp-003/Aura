/*======================================================================================
FILE             : SDActMonService.cpp
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE):(C)Aura
                   Created as an unpublished copyright work. All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura. Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 20 Jan 2008
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/

#include "pch.h"
#include "SDActMonService.h"
#include "RemoteService.h"
#include "MaxPipes.h"
#include "MaxCommunicator.h"
#include "MaxExceptionFilter.h"
#include "SDSystemInfo.h"
#include "MaxProtectionMgr.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

HANDLE CSDActMonServiceApp::m_hSingleMonitorHandler = NULL;
BOOL CALLBACK MessageProcHandler(int, LPCTSTR, LPCTSTR, LPCTSTR, LPVOID);

BEGIN_MESSAGE_MAP(CSDActMonServiceApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


/*--------------------------------------------------------------------------------------
Function       : CSDActMonServiceApp
In Parameters  : 
Out Parameters : 
Description    : Constructor of the main app
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CSDActMonServiceApp::CSDActMonServiceApp():
					m_objMaxCommunicatorServer(_NAMED_PIPE_TRAY_TO_ACTMON,
												CSDActMonServiceApp::OnDataReceivedCallBack,
												sizeof(SHARED_ACTMON_SWITCH_DATA)),
					m_objRegProcess(ALL_REG),
					m_objWDMaxCommunicator(_NAMED_PIPE_WATCHDOG_PROCESSES, false)
{
	m_pWinThread = NULL;
	m_hAppStopEvent = NULL;
	m_bRegWDThreadRunning = false;
	if(m_hSingleMonitorHandler == NULL)
	{
		m_hSingleMonitorHandler = CreateEvent(NULL, FALSE, TRUE, NULL);
	}
}

/*--------------------------------------------------------------------------------------
Function       : ~CSDActMonServiceApp()
In Parameters  : 
Out Parameters : 
Description    : Destructor of the main app
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CSDActMonServiceApp::~CSDActMonServiceApp()
{
	if(m_hAppStopEvent)
	{
		::CloseHandle(m_hAppStopEvent);
		m_hAppStopEvent = NULL;
	}
}

CSDActMonServiceApp theApp;

/*--------------------------------------------------------------------------------------
Function       : SingleInstance
In Parameters  : 
Out Parameters : bool true if not running else false
Description    : Checks if an instance of the app is already running
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CSDActMonServiceApp::SingleInstance()
{
	CString csGUID = _T("Global\\{C796j6A3-0E28-4daa-B78F-trtr1216FB465BD}");

	HANDLE hMutex = NULL;
	hMutex = ::CreateMutex(NULL, TRUE, csGUID);
	if(!hMutex)
	{
		return false;
	}

	if(GetLastError() == ERROR_ALREADY_EXISTS)
	{
		CloseHandle(hMutex);
		return false;
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : InitInstance
In Parameters  : 
Out Parameters : BOOL 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
BOOL CSDActMonServiceApp::InitInstance()
{
	CWinApp::InitInstance();

	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.RegisterProcessID(MAX_PROC_MAXACTMON);

	CSystemInfo objSDSystemInfo;

	if(SingleInstance() ==  false)
	{
		return TRUE;
	}

	LoadLoggingLevel();

	m_hAppStopEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	CMaxExceptionFilter::InitializeExceptionFilter();

	m_pWinThread = AfxBeginThread(CSDActMonServiceApp::WDConnectionThread, this);

	m_objSDMonitor.SetHandler(MessageProcHandler);
	m_objSDMonitor.StartActMonSwitch();
	m_objMaxCommunicatorServer.Run();

	WaitForSingleObject(m_hAppStopEvent, INFINITE);

	m_objSDMonitor.StopActMonSwitch();

	m_objRegProcess.WDRegisterProcess(eActMon, WD_StoppingApp, &m_objWDMaxCommunicator);

	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: MessageProcHandler
In Parameters	: 
Out Parameters	: BOOL : result of the user interaction
Purpose			: callback function which is called when user interaction is required
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
BOOL CALLBACK MessageProcHandler(int iType, LPCTSTR csOld, LPCTSTR csNew,
								 LPCTSTR csProcessName, LPVOID lpVoid)
{
	CString csTemp;
	csTemp.Format(L">>>>> MessageProcHandler: iType: %d, csOld: %s, csNew: %s, csProcessName: %s, lpVoid: 0x%08X", iType, csOld, csNew, csProcessName, lpVoid);
	AddLogEntry(csTemp, 0, 0, true, LOG_WARNING);

	BOOL bReply = TRUE;
	AM_MESSAGE_DATA amMsgData={0};
	_tcscpy_s(amMsgData.szOldValue, csOld);
	_tcscpy_s(amMsgData.szNewValue, csNew);
	_tcscpy_s(amMsgData.szParentProcessName, csProcessName);
	amMsgData.dwMsgType = iType;
	CMaxCommunicator objComm(_NAMED_PIPE_ACTMON_TO_TRAY);
	if(objComm.SendData(&amMsgData,sizeof(AM_MESSAGE_DATA)))
	{
		if(!objComm.ReadData((LPVOID)&amMsgData,sizeof(AM_MESSAGE_DATA)))
		{
			AddLogEntry(L"<<<<< MessageProcHandler!", 0, 0, true, LOG_WARNING);
			return FALSE;
		}
		//wait broken so read the result.
		bReply = amMsgData.dwMsgType; 
	}
	AddLogEntry(L"<<<<< MessageProcHandler!", 0, 0, true, LOG_WARNING);
	return bReply;
}

/*--------------------------------------------------------------------------------------
Function       : OnDataReceivedCallBack
In Parameters  : LPVOID lpMaxParam, 
Out Parameters : void 
Description    : All events sent by the tray or watch dog will be received here
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CSDActMonServiceApp::OnDataReceivedCallBack(LPVOID lpMaxParam)
{
	LPSHARED_ACTMON_SWITCH_DATA sMaxPipeData = (SHARED_ACTMON_SWITCH_DATA*)lpMaxParam;
	if(!sMaxPipeData)
	{
		return;
	}
	if(sMaxPipeData->eProcType == Register_WD_PID)
	{
		if(!theApp.m_bRegWDThreadRunning)
		{
			theApp.m_pWinThread = AfxBeginThread(CSDActMonServiceApp::WDConnectionThread, &theApp);
		}
		return;
	}
	if(sMaxPipeData->eProcType == WD_ShutdownSD)
	{
		if(theApp.m_hAppStopEvent)
		{
			SetEvent(theApp.m_hAppStopEvent);
		}
		return;
	}
	WaitForSingleObject(m_hSingleMonitorHandler, INFINITE);
	bool bResult = true;
	__try
	{
		bResult = theApp.m_objSDMonitor.StartStopMonitor(sMaxPipeData->dwMonitorType,
															sMaxPipeData->bStatus,
															sMaxPipeData->bShutDownStatus,
															sMaxPipeData->eProcType,
															sMaxPipeData->dwPID);
		sMaxPipeData->bStatus = bResult;
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
										_T("AuActMon CallBack Mode")))
	{
		sMaxPipeData->bStatus = false;
	}

	__try
	{
		theApp.m_objMaxCommunicatorServer.SendResponse(sMaxPipeData);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
										_T("AuActMon CallBack Mode")))
	{
	}
	SetEvent(m_hSingleMonitorHandler);
}

/*--------------------------------------------------------------------------------------
Function       : WDConnectionThread
In Parameters  : LPVOID lParam, 
Out Parameters : UINT 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
UINT CSDActMonServiceApp::WDConnectionThread(LPVOID lParam)
{
	__try
	{
		theApp.m_bRegWDThreadRunning = true;
		if(theApp.m_objRegProcess.WDRegisterProcess(eActMon,WD_StartingApp,
													&theApp.m_objWDMaxCommunicator))
		{
			theApp.m_bRegWDThreadRunning = false;
			return 0;
		}
		while(1)
		{
			DWORD dwWait = WaitForSingleObject(theApp.m_hAppStopEvent,3000);
			if(WAIT_OBJECT_0 == dwWait)
			{
				break;
			}
			else if(WAIT_TIMEOUT == dwWait)
			{
				if(theApp.m_objRegProcess.WDRegisterProcess(eActMon,WD_StartingApp,
															&theApp.m_objWDMaxCommunicator))
				{
					break;
				}
			}
			else
			{
				break;
			}
		}
		theApp.m_bRegWDThreadRunning = false;
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("AuActMon WDConnectionThread Mode")))
	{
	}
	return 0;
}