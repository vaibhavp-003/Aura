/*======================================================================================
FILE             : ThreatCommunityHandler.cpp
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
CREATION DATE    : 8/1/2009 6:41:54 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "ThreatCommunityHandler.h"
#include "MaxPipes.h"

#ifndef _STANDALONE_
#include "MaxScanner.h"
#else
#include "MaxCMDScanner.h"
#endif

#include "MaxExceptionFilter.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CMaxCommunicator*	CThreatCommunityHandler::m_pMaxCommunicatorScanner = NULL;
MAX_PIPE_DATA		CThreatCommunityHandler::m_sMaxPipeData = {0};
HANDLE				CThreatCommunityHandler::m_hExitEvent = NULL;
STOPSCANNING		CThreatCommunityHandler::m_lpStopScanning = NULL;

/*--------------------------------------------------------------------------------------
Function       : CThreatCommunityHandler::CThreatCommunityHandler
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CThreatCommunityHandler::CThreatCommunityHandler(void)
{
	m_pMaxCommunicatorScanner = new CMaxCommunicator(_NAMED_PIPE_SCANNER_TO_UI);
	m_hExitEvent = NULL;
	m_lpStartScanning = NULL;
	m_lpStopScanning = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatCommunityHandler::~CThreatCommunityHandler
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CThreatCommunityHandler::~CThreatCommunityHandler(void)
{
	delete m_pMaxCommunicatorScanner;
	m_pMaxCommunicatorScanner = NULL;
	if(m_hExitEvent)
	{
		CloseHandle(m_hExitEvent);
		m_hExitEvent = NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CThreatCommunityHandler::SendMessageToUI
In Parameters  : SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, const ULONG ulSpyName, HKEY Hive_Type, const WCHAR *strKey, 
					const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData,
Out Parameters : BOOL CALLBACK
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
BOOL CALLBACK CThreatCommunityHandler::SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, const ULONG ulSpyName,
													   HKEY Hive_Type, const WCHAR *strKey, const WCHAR *strValue, 
													   int Type_Of_Data, LPBYTE lpbData, int iSizeOfData)
{
	__try
	{
		// Fill Structure according to Type
		if(eTypeOfScanner < SD_Message_Info_TYPE_REG)// Its a File system Message
		{
			memset(&m_sMaxPipeData, 0, sizeof(MAX_PIPE_DATA));
			m_sMaxPipeData.eMessageInfo = eTypeOfScanner;
			m_sMaxPipeData.ulSpyNameID = ulSpyName;
			if(strKey)
			{
				_tcscpy_s(m_sMaxPipeData.strValue, MAX_PATH, strKey);
			}

			if(m_pMaxCommunicatorScanner)
			{
				m_pMaxCommunicatorScanner->SendData(&m_sMaxPipeData, sizeof(MAX_PIPE_DATA));
			}
			return TRUE;
		}
		else if(eTypeOfScanner < SD_Message_Info_TYPE_ADMIN)// Its a Information Message
		{
			memset(&m_sMaxPipeData, 0, sizeof(MAX_PIPE_DATA));
			m_sMaxPipeData.eMessageInfo = eTypeOfScanner;
			if(m_pMaxCommunicatorScanner)
			{
				m_pMaxCommunicatorScanner->SendData(&m_sMaxPipeData, sizeof(MAX_PIPE_DATA));
			}
		}
		else if(eTypeOfScanner > 200)// Its a Administrative task Message
		{
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
										_T("CThreatCommunityHandler::SendMessageToUI")))
	{
	}
	return FALSE;
}

/*--------------------------------------------------------------------------------------
Function       : CThreatCommunityHandler::OnCallbackDataHeuristicScan
In Parameters  : LPVOID lpParam,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CThreatCommunityHandler::OnCallbackDataHeuristicScan(LPVOID lpParam)
{
	__try
	{
		MAX_PIPE_DATA* sMaxPipeData = (MAX_PIPE_DATA*)lpParam;
		if(sMaxPipeData->eMessageInfo == Register_WD_PID)
		{
#ifndef _STANDALONE_
			if(!theApp.m_bRegWDThreadRunning)
			{
				theApp.WDRegisterScanner(WD_StartingApp, Exit_Scanner, NOTIFY_PIPE, eHeuristic, 
											_NAMED_PIPE_HEURISTICSCAN_TO_SCANNER);
			}
#endif //_STANDALONE_
			return;
		}
		if(sMaxPipeData->eMessageInfo == Exit_Scanner)
		{
			//Stop the scanning
			if(m_lpStopScanning)
			{
				m_lpStopScanning();
			}
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("HeuristicScan Mode")))
	{
	}
}

/*--------------------------------------------------------------------------------------
Function       : CThreatCommunityHandler::StartThreatCommunityScanning
In Parameters  : MAX_PIPE_DATA *sMaxPipeData,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CThreatCommunityHandler::StartThreatCommunityScanning(MAX_PIPE_DATA *sMaxPipeData)
{
	CMaxCommunicatorServer HeuristicScanServer(_NAMED_PIPE_HEURISTICSCAN_TO_SCANNER,
												CThreatCommunityHandler::OnCallbackDataHeuristicScan,
												sizeof(MAX_PIPE_DATA_REG));
	HeuristicScanServer.Run(false, true);
	m_hExitEvent = ::CreateEvent(NULL, true, false, NULL);

	HMODULE hScanDll  = NULL;
	hScanDll = ::LoadLibrary(_T("ThreatCommunity.dll"));
	if(hScanDll)
	{
		m_lpStartScanning = (STARTSCANNINGTH)GetProcAddress(hScanDll, "StartScanning");
		m_lpStopScanning  = (STOPSCANNING)GetProcAddress(hScanDll, "StopScanning");
	}

	if(m_lpStartScanning)
	{
		m_lpStartScanning((SENDMESSAGETOUI)SendMessageToUI, sMaxPipeData->sScanOptions, sMaxPipeData->strValue);
	}

	// The scannning is now complete.
	// Send a Finish Scanning Pipe Message to the User Interface
	if(hScanDll)
	{
		m_lpStopScanning = NULL;
		hScanDll = NULL;
	}
}
