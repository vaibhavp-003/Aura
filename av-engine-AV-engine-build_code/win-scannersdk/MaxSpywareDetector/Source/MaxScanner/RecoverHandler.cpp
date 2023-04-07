/*======================================================================================
FILE             : RecoverHandler.cpp
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
#include "RecoverHandler.h"
#include "MaxPipes.h"
#include "MaxScanner.h"
#include "MaxDSrvWrapper.h"

#ifdef _STANDALONE_
#include "MaxCMDScanner.h"
#include "MaxCommandLineFuctions.h"
#endif

#include "MaxExceptionFilter.h"
#include "RemoveDB.h"
#include "SDSystemInfo.h"
#include "conio.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

HANDLE CRecoverHandler::m_hExitEvent = NULL;
CMaxCommunicatorServer * CRecoverHandler::m_pRecoverServer				= NULL;
CMaxCommunicator	   * CRecoverHandler::m_pMaxCommunicatorRecover		= NULL;
MAXSECUREDISPATCHER		 CRecoverHandler::m_pMaxSecureDispatcher		= NULL;

/*--------------------------------------------------------------------------------------
Function       : CRecoverHandler::CRecoverHandler
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CRecoverHandler::CRecoverHandler(void)
{
	m_hScanDll = NULL;
	m_pMaxSecureDispatcher = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : CRecoverHandler::~CRecoverHandler
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CRecoverHandler::~CRecoverHandler(void)
{
	if(m_hExitEvent)
	{
		CloseHandle(m_hExitEvent);
		m_hExitEvent = NULL;
	}
	if(m_pRecoverServer)
	{
		delete m_pRecoverServer;
		m_pRecoverServer = NULL;
	}
	if(m_pMaxCommunicatorRecover)
	{
		delete m_pMaxCommunicatorRecover;
		m_pMaxCommunicatorRecover = NULL;
	}
	DeInitScannerDLL();
}

/*--------------------------------------------------------------------------------------
Function       : CRecoverHandler::InitScannerDLL
In Parameters  : 
Out Parameters : 
Description    : Initlaizes the AuScanner DLL
Author & Date  : Darshan Singh Virdi & 23 Apr, 2010.
--------------------------------------------------------------------------------------*/
void CRecoverHandler::InitScannerDLL()
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
Function       : CRecoverHandler::DeInitScannerDLL
In Parameters  : 
Out Parameters : 
Description    : DeInitlaizes the AuScanner DLL
Author & Date  : Darshan Singh Virdi & 23 Apr, 2010.
--------------------------------------------------------------------------------------*/
void CRecoverHandler::DeInitScannerDLL()
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
Function       : CRecoverHandler::StartRecoverHandler
In Parameters  : MAX_PIPE_DATA *sMaxPipeData,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRecoverHandler::StartRecoverHandler(MAX_PIPE_DATA *pMaxPipeData)
{
	m_hExitEvent = ::CreateEvent(NULL, true, false,NULL);    
	m_pRecoverServer = new CMaxCommunicatorServer(_NAMED_PIPE_UI_TO_RECOVER_SCANNER, 
												CRecoverHandler::OnCallbackDataRecoverHandler, 
												sizeof(MAX_PIPE_DATA_REG));
	m_pMaxCommunicatorRecover = new CMaxCommunicator(pMaxPipeData->szGUID);

	InitScannerDLL();
	if(!m_pRecoverServer)
	{
		return;
	}
	m_pRecoverServer->Run();

	MAX_PIPE_DATA sMaxPipeData = {0};
	sMaxPipeData.eMessageInfo = Perform_Recover;
	if(m_pMaxCommunicatorRecover)
	{
		m_pMaxCommunicatorRecover->SendData(&sMaxPipeData, sizeof(MAX_PIPE_DATA));
	}

	if(m_hExitEvent)
	{
		::WaitForSingleObject(m_hExitEvent, INFINITE);
	}

	if(m_pRecoverServer)
	{
		delete m_pRecoverServer;
		m_pRecoverServer = NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CRecoverHandler::OnCallbackDataRecoverHandler
In Parameters  : LPVOID lpParam,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRecoverHandler::OnCallbackDataRecoverHandler(LPVOID lpParam)
{
	__try
	{
		LPMAX_PIPE_DATA_REG sMaxPipeData = (MAX_PIPE_DATA_REG*)lpParam;
		if(sMaxPipeData->eMessageInfo == Register_WD_PID)
		{
#ifndef _STANDALONE_
			if(!theApp.m_bRegWDThreadRunning)
			{
				theApp.WDRegisterScanner(WD_StartingApp, Finished_Recovery, RESTART_PROCESS, eScanner3, 
										_NAMED_PIPE_UI_TO_RECOVER_SCANNER);
			}
#endif //_STANDALONE_
			return;
		}
		if(Finished_Recovery == sMaxPipeData->eMessageInfo)
		{
			if(m_pMaxSecureDispatcher)
			{
				MAX_DISPATCH_MSG sMaxDispatchMessage;
				sMaxDispatchMessage.eDispatch_Type = eDeInitScanDll;
				sMaxDispatchMessage.pSendMessageToUI = NULL;
				m_pMaxSecureDispatcher(&sMaxDispatchMessage, NULL);
			}

#ifndef _STANDALONE_
			MAX_PIPE_DATA sResponse;//={0};
			SecureZeroMemory(&sResponse,sizeof(MAX_PIPE_DATA));
			m_pRecoverServer->SendResponse(&sResponse);
			::SetEvent(m_hExitEvent);
#endif
		}
		else if(Quarantine_DB_Entry == sMaxPipeData->eMessageInfo)
		{
			/************************/
			// Peform Recovery Here!
			/************************/
			if(m_pMaxSecureDispatcher)
			{
				MAX_DISPATCH_MSG sMaxDispatchMessage;
				sMaxDispatchMessage.eDispatch_Type = eRecover;
				sMaxDispatchMessage.pSendMessageToUI = NULL;
				MAX_PIPE_DATA sRecoverData;
				SecureZeroMemory(&sRecoverData, sizeof(MAX_PIPE_DATA));
				sRecoverData.eMessageInfo = sMaxPipeData->eMessageInfo;
				sRecoverData.ulSpyNameID = sMaxPipeData->ulSpyNameID;
				m_pMaxSecureDispatcher(&sMaxDispatchMessage, &sRecoverData);
			}
#ifndef _STANDALONE_
			MAX_PIPE_DATA sResponse;
			SecureZeroMemory(&sResponse, sizeof(MAX_PIPE_DATA));
			m_pRecoverServer->SendResponse(&sResponse);
#endif
		}
		else if(sMaxPipeData->eStatus == eStatus_Recovered)
		{
			if(m_pMaxSecureDispatcher)
			{
				MAX_PIPE_DATA_REG objRegData = {0};				
				memcpy_s(&objRegData, sizeof(MAX_PIPE_DATA_REG), sMaxPipeData, sizeof(MAX_PIPE_DATA_REG));

				MAX_DISPATCH_MSG sMaxDispatchMessage;
				sMaxDispatchMessage.eDispatch_Type = eRecover;
				sMaxDispatchMessage.pSendMessageToUI = NULL;
				m_pMaxSecureDispatcher(&sMaxDispatchMessage, &objRegData);
				if(m_pRecoverServer)
				{
					m_pRecoverServer->SendResponse(&objRegData);
				}
			}
		}

	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner Recover Callback Mode")))
	{
	}
}

#ifdef _STANDALONE_
void CRecoverHandler::StartCMDRecoverHandler(MAX_PIPE_DATA *sMaxPipeData)
{
	AddLogEntry (_T("*****Starting Command Line Recover"));
	long lIndex;
	CString csTemp;
	bool bPromptToUser = false;
	bool bRecoverAll = false;
	const int SIZEOFBUFFER = 1024*4;
	TCHAR strDisplayValue[SIZEOFBUFFER] = {0};
	CMaxCommandLineFuctions objCommandLineFuctions;

	InitScannerDLL();

	if(sMaxPipeData->sScanOptions.PromptToUser == 1)
	{
		bPromptToUser = true;
	}
	printf("  \n\n >>>>>>>Performing Recover Action\n");

	CRemoveDB objDBRemove;
	objDBRemove.Load(CSystemInfo::m_strAppPath + SD_DB_REMOVE);

	MAX_PIPE_DATA_REG sMaxPipeDataReg = {0};
	MAX_PIPE_DATA sPipeData = {0};
	DWORD dwSizeMaxPipeData = sizeof(MAX_PIPE_DATA);

	SYS_OBJ oRemoveDB = {0};
	bool bFound = objDBRemove.GetFirst(oRemoveDB);

	while(bFound)
	{
		SecureZeroMemory(&sMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		SecureZeroMemory(&sPipeData, sizeof(MAX_PIPE_DATA));
		sMaxPipeDataReg.eMessageInfo = oRemoveDB.dwType;
		sMaxPipeDataReg.ulSpyNameID = oRemoveDB.dwSpywareID;
		sMaxPipeDataReg.Hive_Type = (HKEY)oRemoveDB.ulptrHive;
		if(oRemoveDB.szKey)
		{
			wcscpy_s(sMaxPipeDataReg.strKey, oRemoveDB.szKey);
		}
		if(oRemoveDB.szValue)
		{
			wcscpy_s(sMaxPipeDataReg.strValue, oRemoveDB.szValue);
		}
		if(oRemoveDB.byData)
		{
			memcpy_s(sMaxPipeDataReg.bData, MAX_PATH*4, oRemoveDB.byData, oRemoveDB.dwRegDataSize);
		}
		sMaxPipeDataReg.iSizeOfData = oRemoveDB.dwRegDataSize;
		if(oRemoveDB.byReplaceData)
		{
			memcpy_s(sMaxPipeDataReg.bReplaceData, MAX_PATH*4, oRemoveDB.byReplaceData, oRemoveDB.dwReplaceRegDataSize);
		}

		sMaxPipeDataReg.iSizeOfReplaceData = oRemoveDB.dwReplaceRegDataSize;
		sMaxPipeDataReg.Type_Of_Data = oRemoveDB.wRegDataType;
		sMaxPipeDataReg.ulSpyNameID = oRemoveDB.dwSpywareID;
		lIndex = oRemoveDB.iIndex;

		objDBRemove.SetDeleteFlag(lIndex, true);
		sPipeData.ulSpyNameID = lIndex;
		sPipeData.eMessageInfo = Quarantine_DB_Entry;

		if(sMaxPipeDataReg.eMessageInfo  < SD_Message_Info_TYPE_REG)// Its a File system Message
		{
			csTemp = sMaxPipeDataReg.strKey;
			printf ("\nRecovering...");
			DisplayOnCMD (csTemp);
			

		}
		else if(sMaxPipeDataReg.eMessageInfo  < SD_Message_Info_TYPE_INFO)// Its a Registry Message
		{
			objCommandLineFuctions.PrepareValueForDispaly(sMaxPipeDataReg, strDisplayValue, SIZEOFBUFFER);
			printf ("\nRecovering...");
			DisplayOnCMD (strDisplayValue);
		}

		if(!bRecoverAll)
		{
			if(bPromptToUser)
			{
				printf ("\nDo You Want Recover this Entry[Y / N]:");
				int iChar = _getche();
				while(iChar != 78  && iChar != 110)// check for No
				{
					if(iChar == 89 || iChar == 121)// if yes
					{
						OnCallbackDataRecoverHandler(&sPipeData);
						break;
					}
					printf("\nInvalid Input!!!Please type Y / N : ");
					iChar = _getche();
				}
			}
			else
			{
				bRecoverAll =true;
				printf (" \nDo You Want to Recover All the Entries[Y / N]");
				int iChar = _getche();
				while(iChar != 78  && iChar != 110)// check for No
				{
					if(iChar == 89 || iChar == 121)// if yes
					{
						break;
					}
					printf("\nInvalid Input!!!Please type Y / N : ");
					iChar = _getche();
				}
				if(iChar == 78 || iChar == 110)
				{
					return;
				}
			}
		}
		if(bRecoverAll)
		{
			OnCallbackDataRecoverHandler(&sPipeData);
		}
		memset(&oRemoveDB, 0, sizeof(SYS_OBJ));
		bFound = objDBRemove.GetNext(oRemoveDB);
	}

	objDBRemove.Save(CSystemInfo::m_strAppPath + SD_DB_REMOVE);
	CMaxDSrvWrapper objMaxDSrvWrapper;
	objMaxDSrvWrapper.InitializeDatabase();
	objMaxDSrvWrapper.ReloadRemoveDB();

	printf("\n\n##### All Entries are Successfully Recovered....");
	sPipeData.eMessageInfo = Finished_Recovery;
	OnCallbackDataRecoverHandler(&sPipeData);
	AddLogEntry (_T("All Entries has been Recovered Successfully"));
	Sleep (4000);
}

#endif