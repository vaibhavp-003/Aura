/*======================================================================================
FILE             : PluginHandler.cpp
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
CREATION DATE    : 8/1/2009 6:41:22 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "PluginHandler.h"
#include "MaxPipes.h"
#include "MaxScanner.h"
#include "MaxDSrvWrapper.h"

#include "MaxExceptionFilter.h"
#include "RemoveDB.h"
#include "SDSystemInfo.h"
#include "conio.h"

#include <SDDL.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

HANDLE					CPluginHandler::m_hExitEvent				= NULL;
CMaxCommunicatorServer *CPluginHandler::m_pPluginServer				= NULL;
CMaxCommunicator	   *CPluginHandler::m_pMaxCommunicatorPlugin	= NULL;
MAXSECUREDISPATCHER		CPluginHandler::m_pMaxSecureDispatcher		= NULL;
bool					CPluginHandler::m_bScannerIsReady			= false;
/*--------------------------------------------------------------------------------------
Function       : CPluginHandler::CPluginHandler
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CPluginHandler::CPluginHandler(void)
{
	m_hScanDll = NULL;
	m_pMaxSecureDispatcher = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : CPluginHandler::~CPluginHandler
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CPluginHandler::~CPluginHandler(void)
{
	if(m_hExitEvent)
	{
		CloseHandle(m_hExitEvent);
		m_hExitEvent = NULL;
	}
	if(m_pPluginServer)
	{
		delete m_pPluginServer;
		m_pPluginServer = NULL;
	}
	if(m_pMaxCommunicatorPlugin)
	{
		delete m_pMaxCommunicatorPlugin;
		m_pMaxCommunicatorPlugin = NULL;
	}
	DeInitScannerDLL();
}

/*--------------------------------------------------------------------------------------
Function       : CPluginHandler::InitScannerDLL
In Parameters  : 
Out Parameters : 
Description    : Initlaizes the AuScanner DLL
Author & Date  : Darshan Singh Virdi & 23 Apr, 2010.
--------------------------------------------------------------------------------------*/
void CPluginHandler::InitScannerDLL()
{
	m_hScanDll = ::LoadLibrary(_T("AuSecure.dll"));
	if(m_hScanDll)
	{
		m_pMaxSecureDispatcher = (MAXSECUREDISPATCHER)GetProcAddress(m_hScanDll, "MaxSecureDispatcher");
	}
	// INIT NOT REQUIRED FOR RECOVER! THIS LOADS THE FULL DB WHICH IS NOT REQUIRED!
	////if(m_pMaxSecureDispatcher)
	////{
	////	MAX_DISPATCH_MSG sMaxDispatchMessage;
	////	sMaxDispatchMessage.eDispatch_Type = eInitScanDll;
	////	sMaxDispatchMessage.pSendMessageToUI = NULL;
	////	m_pMaxSecureDispatcher(&sMaxDispatchMessage, NULL);
	////}
	// INIT NOT REQUIRED FOR RECOVER!
}

/*--------------------------------------------------------------------------------------
Function       : CPluginHandler::DeInitScannerDLL
In Parameters  : 
Out Parameters : 
Description    : DeInitlaizes the AuScanner DLL
Author & Date  : Darshan Singh Virdi & 23 Apr, 2010.
--------------------------------------------------------------------------------------*/
void CPluginHandler::DeInitScannerDLL()
{
	// DEINIT IS REQUIRED FOR RECOVER!
	if(m_pMaxSecureDispatcher)
	{
		MAX_DISPATCH_MSG sMaxDispatchMessage;
		sMaxDispatchMessage.eDispatch_Type = eDeInitScanDll;
		sMaxDispatchMessage.pSendMessageToUI = NULL;
		m_pMaxSecureDispatcher(&sMaxDispatchMessage, NULL);
		m_pMaxSecureDispatcher = NULL;
	}
	// DEINIT IS REQUIRED FOR RECOVER!
	if(m_hScanDll)
	{
		::FreeLibrary(m_hScanDll);
		m_hScanDll = NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CPluginHandler::StartPluginHandler
In Parameters  : MAX_PIPE_DATA *sMaxPipeData,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CPluginHandler::StartPluginHandler(MAX_PIPE_DATA *pMaxPipeData)
{
	m_hExitEvent = ::CreateEvent(NULL, true, false,NULL);    
	m_pPluginServer = new CMaxCommunicatorServer(_NAMED_PIPE_PLUGIN_TO_SCANNER, 
												CPluginHandler::OnCallbackDataPluginHandler, 
												sizeof(MAX_PIPE_DATA_REG));
	m_pMaxCommunicatorPlugin = new CMaxCommunicator(pMaxPipeData->szGUID);

	InitScannerDLL();

	//Toload AuScanner in AuScannerDll
	ScanDummyFile();

	if(!m_pPluginServer)
	{
		return;
	}
	m_pPluginServer->Run();

	if(m_hExitEvent)
	{
		::WaitForSingleObject(m_hExitEvent, INFINITE);
	}

	if(m_pPluginServer)
	{
		delete m_pPluginServer;
		m_pPluginServer = NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CPluginHandler::OnCallbackDataPluginHandler
In Parameters  : LPVOID lpParam,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CPluginHandler::OnCallbackDataPluginHandler(LPVOID lpParam)
{
	__try
	{
	
		LPMAX_PIPE_DATA_REG sMaxPipeData = (MAX_PIPE_DATA_REG*)lpParam;
		if(sMaxPipeData->eMessageInfo == Register_WD_PID)
		{
#ifndef _STANDALONE_
			if(!theApp.m_bRegWDThreadRunning)
			{
				theApp.WDRegisterScanner(WD_StartingApp, -1, RESTART_PROCESS, eOutlookPlugin, _NAMED_PIPE_PLUGIN_TO_SCANNER);
			}
#endif //_STANDALONE_
		}
		else if(Finished_Scanning == sMaxPipeData->eMessageInfo)
		{
#ifndef _STANDALONE_
			::SetEvent(m_hExitEvent);
#endif
		}
		else if(EmailReloadDataBase == sMaxPipeData->eMessageInfo)
		{
			OutputDebugString(L">>>>> SuccessFully got Reload event...");
			MAX_DISPATCH_MSG sMaxDispatchMessage;
			sMaxDispatchMessage.eDispatch_Type = eReloadMailScannerDB;
			sMaxDispatchMessage.pSendMessageToUI = NULL;
			m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);		
		}
		else if(ScanSingleFile == sMaxPipeData->eMessageInfo)
		{
			if(m_pMaxSecureDispatcher)
			{
				MAX_DISPATCH_MSG sMaxDispatchMessage;
				sMaxDispatchMessage.eDispatch_Type = eScanFile;
				sMaxDispatchMessage.pSendMessageToUI = NULL;
				MAX_PIPE_DATA_REG sPluginData;
				SecureZeroMemory(&sPluginData, sizeof(MAX_PIPE_DATA_REG));
				sPluginData.eMessageInfo = sMaxPipeData->eMessageInfo;
				_tcscpy_s(sPluginData.strValue, _countof(sPluginData.strValue), sMaxPipeData->strValue);
				_tcscpy_s(sPluginData.strKey, _countof(sPluginData.strKey), sMaxPipeData->strKey);
				_tcscpy_s(sPluginData.strBackup, _countof(sPluginData.strBackup), sMaxPipeData->strBackup);
				m_pMaxSecureDispatcher(&sMaxDispatchMessage, &sPluginData);

				MAX_PIPE_DATA_REG sResponse = {0};
				SecureZeroMemory(&sResponse,sizeof(MAX_PIPE_DATA_REG));
				sResponse.eStatus = sPluginData.eStatus;
				m_pPluginServer->SendResponse(&sResponse);
			}
		}
		else if(IsScanner_Ready == sMaxPipeData->eMessageInfo)	// AuScanner is ready to accept scanning calls!
		{
			MAX_PIPE_DATA_REG sResponse = {0};
			SecureZeroMemory(&sResponse,sizeof(MAX_PIPE_DATA_REG));
			sResponse.eStatus = (m_bScannerIsReady == true ? eStatus_NotApplicable : eStatus_Detected);
			m_pPluginServer->SendResponse(&sResponse);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner Plugin Callback Mode")))
	{
	}
}

void CPluginHandler::ScanDummyFile()
{
	MAX_DISPATCH_MSG sMaxDispatchMessage;
	sMaxDispatchMessage.eDispatch_Type = eScanFile;
	sMaxDispatchMessage.pSendMessageToUI = NULL;

	MAX_PIPE_DATA sPluginData;
	SecureZeroMemory(&sPluginData, sizeof(MAX_PIPE_DATA));
	sPluginData.eMessageInfo = ScanSingleFile;

	m_pMaxSecureDispatcher(&sMaxDispatchMessage, &sPluginData);
	m_bScannerIsReady = true;
}

bool CPluginHandler::IsThisFirstInstance()
{
	LPCTSTR szGUID = _T("Global\\{082EC6D8-8033-480e-AE90-4ACF823DF6E7}");
	HANDLE hMutex = NULL;
	SECURITY_ATTRIBUTES stSA = {0};
	LPCTSTR szDACL = _T("D:(A;OICI;GA;;;BG)(A;OICI;GA;;;AN)(A;OICI;GA;;;AU)(A;OICI;GA;;;BA)");

	stSA.bInheritHandle = FALSE;
	stSA.nLength = sizeof(SECURITY_ATTRIBUTES);
	if(0 == ConvertStringSecurityDescriptorToSecurityDescriptor(szDACL, SDDL_REVISION_1,&stSA.lpSecurityDescriptor, NULL))
	{
		if(stSA.lpSecurityDescriptor)
		{
			LocalFree(stSA.lpSecurityDescriptor);	
		}

		AddLogEntry(L"ERROR StringToSID failed in AuScanner-Plugin");
		return true;
	}

	hMutex = ::CreateMutex(&stSA, TRUE, szGUID);

	if(stSA.lpSecurityDescriptor)
	{
		LocalFree(stSA.lpSecurityDescriptor);
	}

	if(!hMutex)
	{
		AddLogEntry(L"Mutex creation failed in AuScanner-Plugin");
		return true;
	}

	if(GetLastError() == ERROR_ALREADY_EXISTS)
	{
		AddLogEntry(L"Not first instance of AuScanner-Plugin, quitting scanner", 0, 0, true);
		CloseHandle(hMutex);
		return false;
	}

	AddLogEntry(L"First instance of AuScanner-Plugin, running scanner", 0, 0, true);
	return true;
}
