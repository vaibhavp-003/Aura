/*======================================================================================
FILE             : QuarentineHandler.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Ramkrushna Shelke
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
CREATION DATE    : 9/12/2011 
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "MaxPipes.h"
#include "QuarentineHandler.h"
#include "MaxScanner.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

HANDLE				CQuarentineHandler::m_hExitEvent				= NULL;
MAX_PIPE_DATA		CQuarentineHandler::m_sMaxPipeData				= {0};
MAXSECUREDISPATCHER CQuarentineHandler::m_pMaxSecureDispatcher		= NULL;
DWORD				CQuarentineHandler::m_dwQSuccessCount			= 0;
DWORD				CQuarentineHandler::m_dwQFailedCount			= 0;
#ifndef _STANDALONE_
CMaxCommunicator*	CQuarentineHandler::m_pMaxCommunicatorScanner = NULL;
#else
#endif

/*--------------------------------------------------------------------------------------
Function       : CQuarentineHandler::CQuarentineHandler
In Parameters  : void,
Out Parameters :
Description    : Const'r
Author & Date  : Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
CQuarentineHandler::CQuarentineHandler(void)
{
	m_hScanDll = NULL;
	m_pMaxSecureDispatcher = NULL;
	m_pMaxCommunicatorScanner = NULL;
	InitScannerDLL();
}

/*--------------------------------------------------------------------------------------
Function       : ~CQuarentineHandler
In Parameters  : void,
Out Parameters :
Description    : Dest'r
Author & Date  : Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
CQuarentineHandler::~CQuarentineHandler(void)
{
	if(m_pMaxCommunicatorScanner)
	{
		delete m_pMaxCommunicatorScanner;
		m_pMaxCommunicatorScanner = NULL;
	}
	if(m_hExitEvent)
	{
		CloseHandle(m_hExitEvent);
		m_hExitEvent = NULL;
	}
	DeInitScannerDLL();
}

/*--------------------------------------------------------------------------------------
Function       : CSDServiceApp::InitScannerDLL
In Parameters  : 
Out Parameters : 
Description    : Initlaizes the AuScanner DLL
Author & Date  : Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CQuarentineHandler::InitScannerDLL()
{
	m_hScanDll = ::LoadLibrary(_T("AuSecure.dll"));
	if(m_hScanDll)
	{
		m_pMaxSecureDispatcher = (MAXSECUREDISPATCHER)GetProcAddress(m_hScanDll, "MaxSecureDispatcher");
	}
}

/*--------------------------------------------------------------------------------------
Function       : CSDServiceApp::DeInitScannerDLL
In Parameters  : 
Out Parameters : 
Description    : DeInitlaizes the AuScanner DLL
Author & Date  : Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CQuarentineHandler::DeInitScannerDLL()
{
	if(m_pMaxSecureDispatcher)
	{
		m_pMaxSecureDispatcher = NULL;
	}
	if(m_hScanDll)
	{
		::FreeLibrary(m_hScanDll);
		m_hScanDll = NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CSDServiceApp::StartScanningWithParams
In Parameters  : MAX_PIPE_DATA *pMaxPipeData
Out Parameters : 
Description    : Start scanning using AuSecure DLL
Author & Date  : Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CQuarentineHandler::StartQuarentineWithParams(MAX_PIPE_DATA *pMaxPipeData)
{
	m_hExitEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);

#ifndef _STANDALONE_
	theApp.m_pObjMaxCommunicatorServer  = new CMaxCommunicatorServer(_NAMED_PIPE_SERVICE_TO_MAXSCANNER, 
																CQuarentineHandler::OnDataReceivedCallBack,
																sizeof(MAX_PIPE_DATA_REG));
	m_pMaxCommunicatorScanner = new CMaxCommunicator(pMaxPipeData->szGUID);
	
	if(theApp.m_pObjMaxCommunicatorServer)
	{
		theApp.m_pObjMaxCommunicatorServer->Run();
	}
	MAX_PIPE_DATA sMaxPipeData = {0};
	sMaxPipeData.eMessageInfo = Perform_Quarentine;
	if(m_pMaxCommunicatorScanner)
	{
		m_pMaxCommunicatorScanner->SendData(&sMaxPipeData, sizeof(MAX_PIPE_DATA));
	}
#else

#endif
	if(!m_pMaxSecureDispatcher)
	{
		return;
	}
	// Wait for the UI to Exit the Scanner in ANY CASE !
	OutputDebugString(L"Wait for the UI to Exit the Scanner in ANY CASE !");
	if(m_hExitEvent)
	{
		::WaitForSingleObject(m_hExitEvent, INFINITE);
	}
	OutputDebugString(L"Event raised quitting application!");
}

/*--------------------------------------------------------------------------------------
Function       : CMaxDBScanner::OnDataReceivedCallBack
In Parameters  : LPVOID lpMaxParam, 
Out Parameters : void 
Description    : 
Author & Date  : Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CQuarentineHandler::OnDataReceivedCallBack(LPVOID lpMaxParam)
{
	LPMAX_PIPE_DATA_REG sMaxPipeData = (LPMAX_PIPE_DATA_REG)lpMaxParam;
	
	MAX_PIPE_DATA_REG sResponse = {0};
	SecureZeroMemory(&sResponse, sizeof(MAX_PIPE_DATA));

	if(!sMaxPipeData)
	{
		return;
	}

	if(!m_pMaxSecureDispatcher)
	{
		return;
	}

	MAX_DISPATCH_MSG sMaxDispatchMessage;
	switch(sMaxPipeData->eMessageInfo)
	{
	case Finished_Quarantine:
		{
			sMaxPipeData->ulSpyNameID = 0;
			sMaxDispatchMessage.eDispatch_Type = eSaveQuarantineDB;
			sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
			m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);

			sMaxPipeData->ulSpyNameID = m_dwQSuccessCount;
			bool bSplRestartNeeded = false;
			if(m_dwQFailedCount == 0)	// if db quarantine/repair nothing failed check if spl spy scan needs a restart!
			{
				ULONG ulNoOfEntries = sMaxPipeData->ulSpyNameID;
				sMaxDispatchMessage.eDispatch_Type = eRestartRequired;
				sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
				m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);
				bSplRestartNeeded = (sMaxPipeData->ulSpyNameID == 1);
				sMaxPipeData->ulSpyNameID = ulNoOfEntries;
			}

			// either spl spy needs a restart or quarantine/repair failed for atlease 1 file!
			if(bSplRestartNeeded || (m_dwQFailedCount > 0))
			{
				AddLogEntry(L"Sending restart required message to UI!", 0, 0, true, LOG_DEBUG);
#ifdef _STANDALONE_
				DisplayOnCMD(_T("\nPC Reboot is required..... \n\n >>> Please Restart Your Pc !!!"));
				Sleep (2000);
#else				
#endif // #ifndef _STANDALONE_
			}
			else
			{
				AddLogEntry(L"Sending restart not required message to UI!", 0, 0, true, LOG_DEBUG);				
			}
		}
		break;
	case eRecover:
		{
			MAX_DISPATCH_MSG sMaxDispatchMessage;
			sMaxDispatchMessage.eDispatch_Type = eRecover;
			sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
			m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);
		}
		break;
	case Exit_Scanner:
		{
			if(m_hExitEvent)
			{
				SetEvent(m_hExitEvent);
			}
			return;
		}
		break;
	case Stop_Exit_Scanner:
		{
			sMaxDispatchMessage.eDispatch_Type = eStopScanning;
			sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
			m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);

			if(m_hExitEvent)
			{
				SetEvent(m_hExitEvent);
			}
			return;
		}
		break;
	case Perform_SplQuarantine:
		{
			sMaxDispatchMessage.eDispatch_Type = eSpecialQuarantine;
			sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
			m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);
		}
		break;
	default:
		{
			sMaxDispatchMessage.eDispatch_Type = eQuarantine;
			sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
			m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);
			// After quarantine call if the status remains detected it means quarantine/repair failed!
			sResponse.eStatus = sMaxPipeData->eStatus;
			_tcscpy_s(sResponse.strBackup, MAX_PATH,  sMaxPipeData->strBackup);
			if(sMaxPipeData->eStatus == eStatus_Detected)	
				m_dwQFailedCount++;
			else
				m_dwQSuccessCount++;

				if(theApp.m_pObjMaxCommunicatorServer)
				{
					theApp.m_pObjMaxCommunicatorServer->SendResponse(&sResponse);
				}
		}
		break;		
	}
}

/*--------------------------------------------------------------------------------------
Function       : CMaxDBScanner::SendMessageToUI
In Parameters  : SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, const ULONG ulSpyName, HKEY Hive_Type, 
					const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, 
					int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
					int iSizeOfReplaceData, 
Out Parameters : BOOL CALLBACK 
Description    : 
Author & Date  : Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
BOOL CALLBACK CQuarentineHandler::SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, const ULONG ulSpyName, 
											 HKEY Hive_Type, const WCHAR *strKey, const WCHAR *strValue, 
											 int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, 
											 REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
											 int iSizeOfReplaceData)
{
	return TRUE;
}
