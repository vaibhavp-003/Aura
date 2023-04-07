/*======================================================================================
FILE             : MaxScanner.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshan Singh Virdi
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
CREATION DATE    : 8/1/2009 6:39:35 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "MaxScanner.h"
#include "MaxDBScanner.h"
#include "OptionHandler.h"
#include "RecoverHandler.h"
#include "ThreatCommunityHandler.h"
#include "MaxConstant.h"
#include "SDConstants.h"
#include "MaxExceptionFilter.h"
#include "MaxPipes.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// CMaxScannerApp
BEGIN_MESSAGE_MAP(CMaxScannerApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()

/*--------------------------------------------------------------------------------------
Function       : CMaxScannerApp::CMaxScannerApp
In Parameters  : 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CMaxScannerApp::CMaxScannerApp():m_objWatchDog(_NAMED_PIPE_WATCHDOG_PROCESSES),
												m_obgRegProcess(EWD_REG)
{
	SecureZeroMemory(&m_sMaxWDData, sizeof(MAX_WD_DATA));
	m_pObjMaxCommunicatorServer = NULL;
	m_hAppStopEvent = NULL;
	m_pWinThread = NULL;
	m_bRegWDThreadRunning = false;
	m_pScannerThread = NULL;
	m_bStandAlone = false;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxScannerApp::~CMaxScannerApp
In Parameters  : 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CMaxScannerApp::~CMaxScannerApp()
{
	Cleanup();
}

/*--------------------------------------------------------------------------------------
Function       : CMaxScannerApp::Cleanup
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CMaxScannerApp::Cleanup()
{
	__try
	{
		if(m_pObjMaxCommunicatorServer)
		{
			delete m_pObjMaxCommunicatorServer;
			m_pObjMaxCommunicatorServer = NULL;
		}
		if(m_hAppStopEvent)
		{
			::CloseHandle(m_hAppStopEvent);
			m_hAppStopEvent = NULL;
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner Cleanup")))
	{
	}
}

// The one and only CMaxScannerApp object
CMaxScannerApp theApp;

/*--------------------------------------------------------------------------------------
Function       : CMaxScannerApp::InitInstance
In Parameters  : 
Out Parameters : BOOL 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
BOOL CMaxScannerApp::InitInstance()
{
	CWinApp::InitInstance();
	CMaxExceptionFilter::InitializeExceptionFilter();	    
	m_objInitScanner.InitScanner();
	return FALSE;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxScannerApp::WDRegisterScanner
In Parameters  : int nMessageInfo, int nActionInfo, int nAction, int ProcessType, 
					LPCTSTR lpPipeName, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CMaxScannerApp::WDRegisterScanner(int nMessageInfo, int nActionInfo, int nAction, 
									   int ProcessType, LPCTSTR lpPipeName)
{
	m_sMaxWDData.eMessageInfo = nMessageInfo;
	m_sMaxWDData.dwProcessID = ::GetCurrentProcessId();
	m_sMaxWDData.eActionMsgInfo = nActionInfo;
	_tcscpy_s(m_sMaxWDData.szActionPipeName, lpPipeName);
	m_sMaxWDData.nAction = (WD_ACTION)nAction;	
	m_sMaxWDData.nProcessType = ProcessType;
	_tcscpy_s(m_sMaxWDData.szProcessName, MAX_SCANNER);
	if(nMessageInfo == WD_StartingApp)
	{
		//Do it from a thread
		m_pWinThread = AfxBeginThread(CMaxScannerApp::WDConnectionThread, this);
	}
	else
	{
		m_objWatchDog.SendData(&m_sMaxWDData, sizeof(MAX_WD_DATA));
	}
}

/*--------------------------------------------------------------------------------------
Function       : CMaxScannerApp::WDConnectionThread
In Parameters  : LPVOID lParam, 
Out Parameters : UINT 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
UINT CMaxScannerApp::WDConnectionThread(LPVOID lParam)
{
	theApp.m_bRegWDThreadRunning = true;
	if(theApp.m_obgRegProcess.WDRegisterProcess((E_TRUSTPID)theApp.m_sMaxWDData.nProcessType,
												theApp.m_sMaxWDData.eMessageInfo,
												&theApp.m_objWatchDog,
												theApp.m_sMaxWDData.eActionMsgInfo,
												theApp.m_sMaxWDData.szActionPipeName))
	{
		theApp.m_bRegWDThreadRunning = false;
		return 0;
	}
	while(true)
	{
		DWORD dwWait = WaitForSingleObject(theApp.m_hAppStopEvent, 3000);
		if(WAIT_OBJECT_0 == dwWait)
		{
			break;
		}
		else if(WAIT_TIMEOUT == dwWait)
		{
			if(theApp.m_obgRegProcess.WDRegisterProcess((E_TRUSTPID)theApp.m_sMaxWDData.nProcessType,
													theApp.m_sMaxWDData.eMessageInfo,
													&theApp.m_objWatchDog,
													theApp.m_sMaxWDData.eActionMsgInfo,
													theApp.m_sMaxWDData.szActionPipeName))
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
	return 0;
}

int CMaxScannerApp::ExitInstance()
{
	return CWinApp::ExitInstance();
}
