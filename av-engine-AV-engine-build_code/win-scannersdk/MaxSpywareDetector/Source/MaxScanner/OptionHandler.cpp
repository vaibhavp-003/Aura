/*======================================================================================
FILE             : OptionHandler.cpp
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
-------------------Created as an unpublished copyright work.  All rights reserved.
-------------------This document and the information it contains is confidential and
-------------------proprietary to Aura.  Hence, it may not be
-------------------used, copied, reproduced, transmitted, or stored in any form or by any
-------------------means, electronic, recording, photocopying, mechanical or otherwise,
-------------------without the prior written permission of Aura.
CREATION DATE   : 8/1/2009 6:40:31 PM
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
#include "pch.h"
#include "OptionHandler.h"
#include "MaxPipes.h"
#include "SDRestriction.h"

#ifndef _STANDALONE_
#include "MaxScanner.h"
#else
#include "MaxCMDScanner.h"
#endif

#include "MaxExceptionFilter.h"
#include "ProductInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

MAXSECUREDISPATCHER COptionHandler::m_pMaxSecureDispatcher = NULL;
HANDLE COptionHandler::m_hExitEvent = NULL;
STOPSCANNING COptionHandler::m_lpStopScanning = NULL;
PERFORMREGACTION	COptionHandler::m_lpPerformRegAction = NULL;
MAX_PIPE_DATA_REG	COptionHandler::m_sMaxPipeData_Reg = {0};
CMaxCommunicator*	COptionHandler::m_pMaxCommunicatorScanner = NULL;
CMaxCommunicatorServer *COptionHandler::m_pOptionObjServer = NULL;

/*--------------------------------------------------------------------------------------
Function       : COptionHandler
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
COptionHandler::COptionHandler(void)
{
	m_hScanDll = NULL;
	m_pMaxSecureDispatcher = NULL;
	InitScannerDLL();
	GetHostFilePath();
}

/*--------------------------------------------------------------------------------------
Function       : ~COptionHandler
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
COptionHandler::~COptionHandler(void)
{
	Cleanup();
	DeInitScannerDLL();
}

/*--------------------------------------------------------------------------------------
Function       : Cleanup
In Parameters  :
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void COptionHandler::Cleanup()
{
	__try
	{
		if(m_pMaxCommunicatorScanner)
		{
			delete m_pMaxCommunicatorScanner;
			m_pMaxCommunicatorScanner = NULL;
		}
		if(m_hScanDll)
		{
			FreeModule(m_hScanDll);
			m_hScanDll = NULL;
		}
		if(m_hExitEvent)
		{
			CloseHandle(m_hExitEvent);
			m_hExitEvent = NULL;
		}
		if(m_pOptionObjServer)
		{
			delete m_pOptionObjServer;
			m_pOptionObjServer = NULL;
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner Option Cleanup  Mode"), false))
	{
	}
}

/*--------------------------------------------------------------------------------------
Function       : GetHostFilePath
In Parameters  :
Out Parameters : void
Description    : return the host file path
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void COptionHandler::GetHostFilePath()
{
	CProductInfo objProductInfo;
	TCHAR lpszPath[MAX_PATH + 1] = {0};
	GetSystemDirectory(lpszPath, MAX_PATH + 1);

	m_csHostFilePath = lpszPath;
	m_csDummyHostFilePath  = objProductInfo.GetSettingPath();
	m_csHostFilePath += _T("\\drivers\\etc");
	m_csDummyHostFilePath += _T("hosts.txt");
	m_csHostFilePath += _T("\\hosts");
	SetFileAttributes(m_csHostFilePath, FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NORMAL);
}

/*--------------------------------------------------------------------------------------
Function       : StartRegFixScanner
In Parameters  : MAX_PIPE_DATA *sMaxPipeData,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void COptionHandler::StartRegFixScanner(MAX_PIPE_DATA *sMaxPipeData)
{
	m_hExitEvent = ::CreateEvent(NULL, true, false, NULL);
	if(NULL == m_hExitEvent)
	{
		return;
	}

	m_pOptionObjServer = new CMaxCommunicatorServer(_NAMED_PIPE_OPTIONTTAB_TO_SCANNER,
												COptionHandler::OnCallbackDataOptionTab,
												sizeof(MAX_PIPE_DATA_REG));
	if(!m_pOptionObjServer)
	{
		return;
	}

	m_pOptionObjServer->Run();

	// Copy Host File
	CopyHostFile(m_csHostFilePath, m_csDummyHostFilePath);

	::WaitForSingleObject(m_hExitEvent, INFINITE);
	if(m_pOptionObjServer)
	{
		delete m_pOptionObjServer;
		m_pOptionObjServer = NULL;
	}

	CopyHostFile(m_csDummyHostFilePath, m_csHostFilePath);
}

/*--------------------------------------------------------------------------------------
Function       : OnCallbackDataOptionTab
In Parameters  : LPVOID lpParam,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void COptionHandler::OnCallbackDataOptionTab(LPVOID lpParam)
{
	__try
	{
		MAX_PIPE_DATA* sMaxPipeData = (MAX_PIPE_DATA*)lpParam;

		if(sMaxPipeData->eMessageInfo >= MTS_Options)	// Handling ALL MTS Calls together
		{
			if(m_pMaxSecureDispatcher)
			{
				MAX_DISPATCH_MSG sMaxDispatchMessage;
				sMaxDispatchMessage.eDispatch_Type = GetDispatchMessageType((SD_Message_Info)sMaxPipeData->eMessageInfo);
				sMaxDispatchMessage.pSendVoidMessageToUI = SendVoidMessageToUI;
				m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);
			}
			return;
		}

		if(sMaxPipeData->eMessageInfo == Register_WD_PID)
		{
#ifndef _STANDALONE_
			if(!theApp.m_bRegWDThreadRunning)
			{
				theApp.WDRegisterScanner(WD_StartingApp, Exit_Scanner,
										RESTART_PROCESS, eScanner2,
										_NAMED_PIPE_OPTIONTTAB_TO_SCANNER);
			}
#endif //_STANDALONE_
			return;
		}
		if(sMaxPipeData->eMessageInfo == RegFix)//Registry Fix Message
		{
			/*if(m_lpPerformRegAction)
			{
				m_lpPerformRegAction((LPMAX_PIPE_DATA_REG)lpParam);
			}*/

			GetSetRegRestrictionOptions(sMaxPipeData);
			m_pOptionObjServer->SendResponse(sMaxPipeData);
		}
		else if(sMaxPipeData->eMessageInfo != Exit_Scanner)
		{
			COptionHandler::SetOption(sMaxPipeData->eMessageInfo,sMaxPipeData->strValue,sMaxPipeData->ulSpyNameID);
		}
		else
		{
			MAX_PIPE_DATA sResponse;//={0};
			SecureZeroMemory(&sResponse, sizeof(MAX_PIPE_DATA));
			m_pOptionObjServer->SendResponse(&sResponse);
			if(m_lpStopScanning)
			{
				//Stop the scanning after finished scanning event
				m_lpStopScanning();
				SendMessageToUI(Finished_Scanning);
			}
			::SetEvent(m_hExitEvent);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
											_T("AuScanner OptionTab Callback Mode")))
	{
	}
}

/*--------------------------------------------------------------------------------------
Function       : SetOption
In Parameters  : int iOperation, LPCTSTR lpValue,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void COptionHandler::SetOption(int iOperation, LPCTSTR lpValue,DWORD dwSpyID)
{
	COptionTabFunctions obj;
	obj.DllFunction(iOperation, lpValue, NULL,_T(""),dwSpyID);
}

/*--------------------------------------------------------------------------------------
Function       : CopyHostFile
In Parameters  : CString csHostFilePath, CString csDummyHostfilePath, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void COptionHandler::CopyHostFile(CString csHostFilePath, CString csDummyHostfilePath)
{
	CopyFile(csHostFilePath, csDummyHostfilePath, FALSE);
}

/*--------------------------------------------------------------------------------------
Function       : SendMessageToUI
In Parameters  : SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, const ULONG ulSpyName, HKEY Hive_Type,
					const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data,
					LPBYTE lpbData, int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options,
					LPBYTE lpbReplaceData, int iSizeOfReplaceData,
Out Parameters : BOOL CALLBACK
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
BOOL CALLBACK COptionHandler::SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, const ULONG ulSpyName,
											HKEY Hive_Type, const WCHAR *strKey, const WCHAR *strValue,
											int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, 
											REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
											int iSizeOfReplaceData)
{
	__try
	{
		// Is it a Registry Message
		if(eTypeOfScanner > SD_Message_Info_TYPE_REG && eTypeOfScanner < SD_Message_Info_TYPE_INFO)
		{
			memset(&m_sMaxPipeData_Reg, 0, sizeof(MAX_PIPE_DATA_REG));
			m_sMaxPipeData_Reg.eMessageInfo = eTypeOfScanner;
			m_sMaxPipeData_Reg.sScanOptions.RegFixOptionScan = 1;
			m_sMaxPipeData_Reg.ulSpyNameID = ulSpyName;
			m_sMaxPipeData_Reg.Hive_Type = Hive_Type;
			m_sMaxPipeData_Reg.iSizeOfData = iSizeOfData;
			m_sMaxPipeData_Reg.iSizeOfReplaceData = iSizeOfReplaceData;
			m_sMaxPipeData_Reg.Type_Of_Data = Type_Of_Data;
			if(strKey)
			{
				_tcscpy_s(m_sMaxPipeData_Reg.strKey, MAX_PATH, strKey);
			}
			if(strValue)
			{
				_tcscpy_s(m_sMaxPipeData_Reg.strValue, MAX_PATH, strValue);
			}
			if(lpbData)
			{
				memcpy_s(m_sMaxPipeData_Reg.bData, sizeof(m_sMaxPipeData_Reg.bData), lpbData, iSizeOfData);
			}
			if(psReg_Fix_Options)
			{
				memcpy_s(&m_sMaxPipeData_Reg.sReg_Fix_Options, sizeof(REG_FIX_OPTIONS), psReg_Fix_Options,
							sizeof(REG_FIX_OPTIONS));
			}
			if(lpbReplaceData)
			{
				memcpy_s(m_sMaxPipeData_Reg.bReplaceData, sizeof(m_sMaxPipeData_Reg.bReplaceData), 
							lpbReplaceData, iSizeOfReplaceData);
			}
			if(m_pMaxCommunicatorScanner)
			{
				m_pMaxCommunicatorScanner->SendData(&m_sMaxPipeData_Reg, sizeof(MAX_PIPE_DATA_REG));
			}
			return TRUE;
		}
		else if(eTypeOfScanner < SD_Message_Info_TYPE_ADMIN)// Its a Information Message
		{
			memset(&m_sMaxPipeData_Reg, 0, sizeof(MAX_PIPE_DATA_REG));
			m_sMaxPipeData_Reg.eMessageInfo = eTypeOfScanner;
			m_sMaxPipeData_Reg.sScanOptions.RegFixOptionScan = 1;
			if(m_pMaxCommunicatorScanner)
			{
				m_pMaxCommunicatorScanner->SendData(&m_sMaxPipeData_Reg, sizeof(MAX_PIPE_DATA_REG));
			}
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
										_T("AuScanner:COptionHandler::SendMessageToUI")))
	{
	}
	return FALSE;
}

/*--------------------------------------------------------------------------------------
Function       : GetSetRegRestrictionOptions
In Parameters  : MAX_PIPE_DATA* pstMaxPipeData
Out Parameters : bool
Description    : get and set registry restriction options
Author & Date  : Anand Srivastava & 3-June-2010
--------------------------------------------------------------------------------------*/
bool COptionHandler::GetSetRegRestrictionOptions(MAX_PIPE_DATA* pstMaxPipeData)
{
	bool bRetValue = false;
	BYTE byOptions[eRES_TotalCount] = {0};
	CSDRestriction objSDRestriction;

	if(REG_RES_GET_OPT == pstMaxPipeData->ulSpyNameID)
	{
		bRetValue = objSDRestriction.GetAllOptionsProperty(byOptions, _countof(byOptions));
		memcpy(pstMaxPipeData->strValue, byOptions, _countof(byOptions));
	}
	else if(REG_RES_SET_OPT == pstMaxPipeData->ulSpyNameID)
	{
		memcpy(byOptions, pstMaxPipeData->strValue, _countof(byOptions));
		bRetValue = objSDRestriction.SetAllOptionsProperty(byOptions, _countof(byOptions));
	}

	return bRetValue;
}

/*--------------------------------------------------------------------------------------
Function       : COptionHandler::InitScannerDLL
In Parameters  : 
Out Parameters : 
Description    : Initlaizes the AuScanner DLL
Author & Date  : Darshan Singh Virdi & 22 Oct, 2010.
--------------------------------------------------------------------------------------*/
void COptionHandler::InitScannerDLL()
{
	m_hScanDll = ::LoadLibrary(_T("AuSecure.dll"));
	if(m_hScanDll)
	{
		m_pMaxSecureDispatcher = (MAXSECUREDISPATCHER)GetProcAddress(m_hScanDll, "MaxSecureDispatcher");
	}
}

/*--------------------------------------------------------------------------------------
Function       : COptionHandler::DeInitScannerDLL
In Parameters  : 
Out Parameters : 
Description    : DeInitlaizes the AuScanner DLL
Author & Date  : Darshan Singh Virdi & 22 Oct, 2010.
--------------------------------------------------------------------------------------*/
void COptionHandler::DeInitScannerDLL()
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
Function       : COptionHandler::GetDispatchMessageType
In Parameters  : SD_Message_Info 
Out Parameters : Max_Dispatch_Type
Description    : DeInitlaizes the AuScanner DLL
Author & Date  : Darshan Singh Virdi & 22 Oct, 2010.
--------------------------------------------------------------------------------------*/
Max_Dispatch_Type COptionHandler::GetDispatchMessageType(SD_Message_Info eMessageType)
{
	return eOptionTab;
}

BOOL CALLBACK COptionHandler::SendVoidMessageToUI(LPVOID lpVoid, DWORD dwSize)
{
	if(!m_pMaxCommunicatorScanner)
	{
		m_pMaxCommunicatorScanner = new CMaxCommunicator(_NAMED_PIPE_SCANNER_TO_UI);
	}
	if(m_pMaxCommunicatorScanner)
	{
		MAX_PIPE_DATA_REG oRegData = {0};
		memcpy(&oRegData, lpVoid, dwSize);
		m_pMaxCommunicatorScanner->SendData(&oRegData, sizeof(MAX_PIPE_DATA_REG));
	}
	return TRUE;
}