/*======================================================================================
FILE             : MaxDBScanner.cpp
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
				  
CREATION DATE    : 8/1/2009 6:38:22 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include <shlwapi.h>
#include "MaxDBScanner.h"
#include "SDSystemInfo.h"
#include "Registry.h"
#include "MaxPipes.h"
#include "MaxDSrvWrapper.h"

#ifndef _STANDALONE_
#include "MaxScanner.h"
#include "MaxPipes.h"
#include "MaxCommunicatorServer.h"
#else
#include <list>
#include <windows.h>  //include all the basics
#include <conio.h>
#endif

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

HANDLE				CMaxDBScanner::m_hExitEvent = NULL;
MAX_PIPE_DATA		CMaxDBScanner::m_sMaxPipeData = {0};
MAX_PIPE_DATA_REG	CMaxDBScanner::m_sMaxPipeData_Reg = {0};
MAXSECUREDISPATCHER CMaxDBScanner::m_pMaxSecureDispatcher = NULL;
MAXSECURECMDLOG		CMaxDBScanner::m_pMaxSecureCmdLog = NULL;
bool				CMaxDBScanner::m_bAutoQuarantine = false;
DWORD				CMaxDBScanner::m_dwScanCount = 0;
DWORD				CMaxDBScanner::m_dwQSuccessCount = 0;
DWORD				CMaxDBScanner::m_dwQFailedCount = 0;
CString				CMaxDBScanner::m_csScannerID;
CMaxCommunicator*	CMaxDBScanner::m_pMaxWDCommunicator = NULL;
bool				CMaxDBScanner::m_bBackgroundScanner = false;

#ifndef _STANDALONE_
CMaxCommunicator*	CMaxDBScanner::m_pMaxCommunicatorScanner = NULL;
#else
bool				CMaxDBScanner::m_bPromptToUser  = false;
bool				CMaxDBScanner::m_bLogOnly  = false;
bool				CMaxDBScanner::m_bNoOutputInCMD = false;
bool				CMaxDBScanner::m_bDeleteTempIE  = false;
bool				CMaxDBScanner::m_bRegistered = false;
bool				CMaxDBScanner::m_bStartScan = false;
bool				CMaxDBScanner::m_bPauseScan = false;
bool				CMaxDBScanner::m_bExitStopEventThread = false;
CMaxCommandLineFuctions CMaxDBScanner::m_objCommandLineFuctions;
std::list<MAX_PIPE_DATA_REG> g_lstMaxSpywareData;
#endif


/*--------------------------------------------------------------------------------------
Function       : CMaxDBScanner::CMaxDBScanner
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CMaxDBScanner::CMaxDBScanner(void)
{
	m_hScanDll = NULL;
	m_pMaxSecureDispatcher = NULL;
	m_pMaxSecureCmdLog = NULL;
	m_pMaxWDCommunicator = NULL;
	InitScannerDLL();
}

/*--------------------------------------------------------------------------------------
Function       : CMaxDBScanner::~CMaxDBScanner
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CMaxDBScanner::~CMaxDBScanner(void)
{
#ifndef _STANDALONE_
	if(m_pMaxCommunicatorScanner)
	{
		delete m_pMaxCommunicatorScanner;
		m_pMaxCommunicatorScanner = NULL;
	}
#else
	if(m_hCMDUIEvent)
	{
		::CloseHandle(m_hCMDUIEvent);
		m_hCMDUIEvent = NULL;
	}
	if(m_hUICMDEvent)
	{
		::CloseHandle(m_hUICMDEvent);
		m_hUICMDEvent = NULL;
	}
#endif
	if(m_pMaxWDCommunicator)
	{
		delete m_pMaxWDCommunicator;
		m_pMaxWDCommunicator = NULL;
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
Description    : Initlaizes the MaxScanner DLL
Author & Date  : Darshan Singh Virdi & 23 Apr, 2010.
--------------------------------------------------------------------------------------*/
void CMaxDBScanner::InitScannerDLL()
{
	m_hScanDll = ::LoadLibrary(_T("AuSecure.dll"));
	if(m_hScanDll)
	{
		m_pMaxSecureDispatcher = (MAXSECUREDISPATCHER)GetProcAddress(m_hScanDll, "MaxSecureDispatcher");
		m_pMaxSecureCmdLog = (MAXSECURECMDLOG)GetProcAddress(m_hScanDll, "MaxSecureCmdLog");
	}
}

/*--------------------------------------------------------------------------------------
Function       : CSDServiceApp::DeInitScannerDLL
In Parameters  : 
Out Parameters : 
Description    : DeInitlaizes the MaxScanner DLL
Author & Date  : Darshan Singh Virdi & 23 Apr, 2010.
--------------------------------------------------------------------------------------*/
void CMaxDBScanner::DeInitScannerDLL()
{
	if(m_pMaxSecureDispatcher)
	{
		m_pMaxSecureDispatcher = NULL;
	}
	if(m_pMaxSecureCmdLog)
	{
		m_pMaxSecureCmdLog = NULL;
	}
	if(m_hScanDll)
	{
		::FreeLibrary(m_hScanDll);
		m_hScanDll = NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CSDServiceApp::StartScanningWithParams
In Parameters  : MAX_PIPE_DATA *sMaxPipeData
Out Parameters : 
Description    : Start scanning using AuSecure DLL
Author & Date  : Darshan Singh Virdi & 23 Apr, 2010.
--------------------------------------------------------------------------------------*/
void CMaxDBScanner::StartScanningWithParams(MAX_PIPE_DATA *sMaxPipeData, MAX_PIPE_DATA_CMD * sMaxPipeDataCmd)
{
	m_dwScanCount = 0;
	m_dwQSuccessCount = 0;
	m_dwQFailedCount = 0;

	m_bAutoQuarantine = sMaxPipeData->sScanOptions.AutoQuarantine;

#ifdef _STANDALONE_
	m_objCommandLineFuctions.PopulateScanTextLookup();
	m_hCMDUIEvent = ::CreateEvent(NULL, true, false, CMDUI_EVENT_NAME);
	m_hUICMDEvent = ::CreateEvent(NULL, true, false, CMDUI_EVENT_NAME);	
#endif

#ifndef _STANDALONE_

	if(!theApp.m_bStandAlone)
	{
		m_hExitEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	}
	_TUCHAR *guidStr = 0x00;
	GUID guid;
	CoCreateGuid(&guid);
	UuidToString(&guid, (RPC_WSTR*)&guidStr);
	m_csScannerID = CString(L"\\\\.\\pipe\\{") + guidStr + L"}";
	RpcStringFree((RPC_WSTR*)&guidStr);
	guidStr = NULL;

	OutputDebugString(L"Scanner GUID is: " + m_csScannerID);

	theApp.m_pObjMaxCommunicatorServer  = new CMaxCommunicatorServer(m_csScannerID, 
																CMaxDBScanner::OnDataReceivedCallBack,
																sizeof(MAX_PIPE_DATA_REG));
	m_pMaxCommunicatorScanner = new CMaxCommunicator(sMaxPipeData->szGUID);
	theApp.m_eTypeOfScanner = (sMaxPipeData->sScanOptions.IsUSBScanner == 1 ? eUSBScanner : eScanner1);

	MAX_PIPE_DATA oMaxPipeData = {0};
	oMaxPipeData.eMessageInfo = SendGuid;
	wcscpy_s(oMaxPipeData.strValue, m_csScannerID);
	m_pMaxCommunicatorScanner->SendData(&oMaxPipeData, sizeof(MAX_PIPE_DATA));

	m_pMaxWDCommunicator = new CMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE);

	MAX_PIPE_DATA_REG oMaxPipeDataReg = {0};
	oMaxPipeDataReg.eMessageInfo = SendGuid;
	wcscpy_s(oMaxPipeDataReg.strValue, m_csScannerID);
	m_pMaxWDCommunicator->SendData(&oMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));


	if(theApp.m_pObjMaxCommunicatorServer)
	{
		theApp.m_pObjMaxCommunicatorServer->Run();
	}
#else
	AddLogEntry (_T("*****Starting Command Line Scanner******"));
	AfxBeginThread(CheckForStopScanEvent,this);
	CMaxDBScanner::m_bStartScan = true;
	DisplayOnCMD(_T("\nPlease Press ESCAPE Key if You Want To Stop the Scan..... \r\n"));
	
    CTime		tsScanStartTime   = CTime::GetCurrentTime();
    CString csTimeStart =  tsScanStartTime.Format(_T("%H:%M:%S"));
    DisplayOnCMD(_T("@@@@@@Start Scan Time : %s \n\n"),csTimeStart);
	AddLogEntry(_T("Start Scan Time: %s"), csTimeStart);

	if( sMaxPipeData->sScanOptions .PromptToUser == 1 )
	{
		CMaxDBScanner ::m_bPromptToUser = true;
	}
	if( sMaxPipeData->sScanOptions.LogOnly == 1 )
	{
		CMaxDBScanner ::m_bLogOnly = true;
	}
    if( sMaxPipeData->sScanOptions .CleanTempIE == 1 )
	{
		CMaxDBScanner ::m_bDeleteTempIE = true;
	}
	if( sMaxPipeData->sScanOptions.NoOutputInCMD == 1 )
	{
		CMaxDBScanner ::m_bNoOutputInCMD = true;
	}

	if(m_hCMDUIEvent != INVALID_HANDLE_VALUE)
    {        
		AfxBeginThread(CMaxDBScanner::CheckForUIStartEventThread, this);    
    }
	CRegistry objReg;
    DWORD dwEval = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dwEval, HKEY_LOCAL_MACHINE);
	m_bRegistered = dwEval == 0 ?  true : false;
	
#endif // #ifdef _STANDALONE_

	if(!m_pMaxSecureDispatcher)
	{
		return;
	}
	if(m_pMaxSecureCmdLog)
	{
		m_pMaxSecureCmdLog(sMaxPipeDataCmd);
	}
	bool bMachineLearning =  sMaxPipeData->sScanOptions.MachineLearning ;
	bool bCmdScan = false;
	m_bBackgroundScanner = false;
	if(sMaxPipeDataCmd != NULL)
	{
 		bCmdScan=  sMaxPipeDataCmd->sScanOptionsCmd.LogType;
		m_bBackgroundScanner = sMaxPipeDataCmd->sScanOptionsCmd.BackGScanner;
	}
	MAX_DISPATCH_MSG sMaxDispatchMessage;
	sMaxDispatchMessage.eDispatch_Type = eInitScanDll;
	sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
	m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);

	sMaxDispatchMessage.eDispatch_Type = eStartScanning;
	sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
	m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);

	sMaxDispatchMessage.eDispatch_Type = eDeInitScanDll;
	sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
	m_pMaxSecureDispatcher(&sMaxDispatchMessage, NULL);

	// The scannning is now complete. 
	// Send a Finish Scanning Pipe Message to the User Interface
#ifdef _STANDALONE_
	DisplayOnCMD(_T("\nFinished Scanning........\n\n"));
	AddLogEntry(_T("Finished Scanning........"));
	CTime		tsScanEndTime   = CTime::GetCurrentTime();
    CString csTimeEnd =  tsScanEndTime.Format(_T("%H:%M:%S"));
    DisplayOnCMD(_T("@@@@@@ Scan End Time : %s \n"),csTimeEnd);
    CTimeSpan		tsScanElapsedTime = CTime::GetCurrentTime() - tsScanStartTime;
    CString csTime =  tsScanElapsedTime.Format(_T("%H:%M:%S"));
    DisplayOnCMD(_T("@@@@@@ Total Elapsed Time : %s \n"),csTime);	
	AddLogEntry(_T("Total Elapsed Time : %s"), csTime);
	Sleep (4000);
#endif
	
	if(bMachineLearning)
	{
		OutputDebugString(L"MachineLearning Exit Scanner in ANY CASE !");
		SetEvent(m_hExitEvent);
	}
	if(bCmdScan == true)
	{
		OutputDebugString(L"CmdScanner Exit Scanner in ANY CASE !");
		SetEvent(m_hExitEvent);
	}
	if(m_bBackgroundScanner)
	{
		CRegistry objReg;
		CString m_csScanStatusIni =L"";
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("AppFolder"),m_csScanStatusIni,HKEY_LOCAL_MACHINE);
		if(!m_csScanStatusIni.IsEmpty())
		{
			m_csScanStatusIni.Format(_T("%sSetting\\ScanStatusLastScan.ini"),m_csScanStatusIni);
		}
		int iStatus = 0;
		iStatus = GetPrivateProfileInt(L"MAX_SCAN_STATUS", L"SCAN_STATUS",0, m_csScanStatusIni);	
		if(iStatus == 0)
		{
			CTime ntCurrentTime = 0;
			ntCurrentTime = CTime::GetCurrentTime();
			CString csDate;
			csDate.Format (_T("%d/%d/%d"),ntCurrentTime.GetDay(),ntCurrentTime.GetMonth(),ntCurrentTime.GetYear());
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("LastBackGroundScan"),csDate, HKEY_LOCAL_MACHINE);
		}

		OutputDebugString(L"BackGround: Exit Scanner in ANY CASE !");
		SetEvent(m_hExitEvent);
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
Function       : CMaxDBScanner::Quarantine
In Parameters  : MAX_PIPE_DATA *sMaxPipeData, bool bInitDatabase
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CMaxDBScanner::RestartQuarantine(MAX_PIPE_DATA *sMaxPipeData)
{
	MAX_DISPATCH_MSG sMaxDispatchMessage;
	sMaxDispatchMessage.eDispatch_Type = eRestartQuarantine;
	sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
	m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);
}

/*--------------------------------------------------------------------------------------
Function       : CMaxDBScanner::SendMessageToUI
In Parameters  : SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, const ULONG ulSpyName, HKEY Hive_Type, 
					const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, 
					int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
					int iSizeOfReplaceData, 
Out Parameters : BOOL CALLBACK 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
BOOL CALLBACK CMaxDBScanner::SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, const ULONG ulSpyName, 
											 HKEY Hive_Type, const WCHAR *strKey, const WCHAR *strValue, 
											 int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, 
											 REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
											 int iSizeOfReplaceData)
{

#ifdef _STANDALONE_

	MAX_PIPE_DATA_REG pipeData = {0};
	const int SIZEOFBUFFER = 1024*4;
	TCHAR strDisplayValue[SIZEOFBUFFER] = {0};

	while(CMaxDBScanner::m_bPauseScan)
	{
		Sleep(10);
	}
    if(eTypeOfScanner == FilePath_Report || eTypeOfScanner == SplSpy_Report || eTypeOfScanner == Status_Bar_File || eTypeOfScanner == Status_Bar_File_Report)
	{
		return FALSE;
	}

	CString csSpyName;
	CString csThreatType;

	if((eTypeOfScanner < SD_Message_Info_TYPE_REG) || (eTypeOfScanner < SD_Message_Info_TYPE_INFO))
	{
		csThreatType = m_objCommandLineFuctions.GetWormType(eTypeOfScanner);

		if(ulSpyName != 0)
		{
			CMaxDSrvWrapper objMaxDSrvWrapper;
			objMaxDSrvWrapper.InitializeDatabase();
			BYTE  bThreatIndex;
			csSpyName = objMaxDSrvWrapper.GetSpyName(ulSpyName, bThreatIndex);
			objMaxDSrvWrapper.DeInitializeDatabase();
		}
		else
		{
			csSpyName = strValue;
			if(csSpyName.GetLength() == 0)
			{
				csSpyName = _T("Trojan.Agent");
			}
		}
	}
#endif

	// Fill Structure according to Type
	if(eTypeOfScanner < SD_Message_Info_TYPE_REG) // Its a File system Message
	{
		m_dwScanCount++;
		if(m_bAutoQuarantine)
		{
			// After quarantine call if the status remains detected it means quarantine/repair failed!
			if(eStatus == eStatus_Detected)	
				m_dwQFailedCount++;
			else
				m_dwQSuccessCount++;
		}
		memset(&m_sMaxPipeData, 0, sizeof(MAX_PIPE_DATA));
		m_sMaxPipeData.eMessageInfo = eTypeOfScanner;
		m_sMaxPipeData.eStatus = eStatus;
		m_sMaxPipeData.ulSpyNameID = ulSpyName;
		if(strKey)
		{
			_tcscpy_s(m_sMaxPipeData.strValue, MAX_PATH, strKey);
		}
		if(eTypeOfScanner == System_File_Replace)
		{
			if(strValue)
			{
				_tcscpy_s(m_sMaxPipeData.strFreshFile, MAX_PATH, strValue);
			}
		}
		if(eTypeOfScanner == Status_Bar_File_Report)
		{
			_tcscpy_s(m_sMaxPipeData.strFreshFile, MAX_PATH, strValue);
		}
		
#ifndef _STANDALONE_
		if(theApp.m_bStandAlone && eTypeOfScanner != Status_Bar_File_Report 
		   && eTypeOfScanner != Status_Bar_File && eTypeOfScanner != System_File_Replace)
		{
			CMaxDSrvWrapper objMaxDSrvWrapper;
			objMaxDSrvWrapper.InitializeDatabase();
			BYTE  bThreatIndex;
			CString csSpyName = objMaxDSrvWrapper.GetSpyName(ulSpyName, bThreatIndex);
			objMaxDSrvWrapper.DeInitializeDatabase();

			AddLogEntry(_T("##### DETECTED %s : Threat Name: %s"), strKey, csSpyName);
		}
		if(m_pMaxCommunicatorScanner)
		{
			m_pMaxCommunicatorScanner->SendData(&m_sMaxPipeData, sizeof(MAX_PIPE_DATA));
		}
#else
		if(true == m_objCommandLineFuctions.CheckReportedSpyMap(strKey, csThreatType))
		{
			return TRUE;
		}
		memcpy(&pipeData, &m_sMaxPipeData, sizeof(MAX_PIPE_DATA));
		g_lstMaxSpywareData.push_back(pipeData);
		while(CMaxDBScanner::m_bPauseScan)
		{
			Sleep(10);
		}
		if(!CMaxDBScanner::m_bNoOutputInCMD)
		{
			m_objCommandLineFuctions.ShowWormOnCmd(csThreatType, csSpyName, strKey);
		}
#endif
	}
	else if(eTypeOfScanner < SD_Message_Info_TYPE_INFO) // Its a Registry Message
	{
		m_dwScanCount++;
		if(m_bAutoQuarantine)
		{
			// After quarantine call if the status remains detected it means quarantine/repair failed!
			if(eStatus == eStatus_Detected)	
				m_dwQFailedCount++;
			else
				m_dwQSuccessCount++;
		}
		memset(&m_sMaxPipeData_Reg, 0, sizeof(MAX_PIPE_DATA_REG));
		m_sMaxPipeData_Reg.eMessageInfo = eTypeOfScanner;
		m_sMaxPipeData_Reg.eStatus = eStatus;
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
#ifndef _STANDALONE_
		if(theApp.m_bStandAlone && eTypeOfScanner != Status_Bar_File_Report 
			&& eTypeOfScanner != Status_Bar_File && eTypeOfScanner != System_File_Replace)
		{
			AddLogEntry(_T("##### DETECTED %s : Threat Name: %s"), strKey, strValue);
		}
		if(m_pMaxCommunicatorScanner)
		{
			m_pMaxCommunicatorScanner->SendData(&m_sMaxPipeData_Reg, sizeof(MAX_PIPE_DATA_REG));
		}
#else
		memcpy(&pipeData, &m_sMaxPipeData_Reg, sizeof(MAX_PIPE_DATA_REG));
		m_objCommandLineFuctions.PrepareValueForDispaly(pipeData, strDisplayValue, SIZEOFBUFFER);
		if(true == m_objCommandLineFuctions.CheckReportedSpyMap(strDisplayValue, csThreatType))
		{
			return TRUE;
		}
		g_lstMaxSpywareData.push_back(pipeData);
		while(CMaxDBScanner::m_bPauseScan)
		{
			Sleep(10);
		}
		if(!CMaxDBScanner::m_bNoOutputInCMD)
		{
			m_objCommandLineFuctions.ShowWormOnCmd(csThreatType, csSpyName, strDisplayValue);
		}
#endif

	}
	else if(eTypeOfScanner < SD_Message_Info_TYPE_ADMIN) // Its a Information Message
	{
		memset(&m_sMaxPipeData, 0, sizeof(MAX_PIPE_DATA));
		m_sMaxPipeData.eMessageInfo = eTypeOfScanner;

#ifndef _STANDALONE_
		if(m_bAutoQuarantine && (eTypeOfScanner == Finished_Scanning))
		{
			m_sMaxPipeData.ulSpyNameID = 0;
			m_sMaxPipeData.eMessageInfo = Finished_Quarantine;
			OnDataReceivedCallBack(&m_sMaxPipeData);
			m_sMaxPipeData.eMessageInfo = Finished_Scanning;
		}
		if(eTypeOfScanner == Finished_Scanning)
		{
			_tcscpy_s(m_sMaxPipeData.szGUID, sizeof(m_sMaxPipeData.szGUID), m_csScannerID);
		}

		if(m_pMaxCommunicatorScanner)
		{
			m_pMaxCommunicatorScanner->SendData(&m_sMaxPipeData, sizeof(MAX_PIPE_DATA));
		}
#else
		if(eTypeOfScanner == Finished_Scanning)
		{
 			keybd_event(VK_SPACE, 1, 0, 0);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  
			keybd_event(VK_SPACE, 1, KEYEVENTF_KEYUP, 0);
		}
		
		while(CMaxDBScanner::m_bPauseScan)
		{
			Sleep(10);
		}
		if(!CMaxDBScanner::m_bStartScan)
		{
			return TRUE;
		}
		pipeData.eMessageInfo = eTypeOfScanner;
		LPTSTR lpScanText = NULL;
		if(m_objCommandLineFuctions.m_objScanTextLookup.SearchItem(pipeData.eMessageInfo, &lpScanText))
		{
			printf ("\n");
			while(CMaxDBScanner::m_bPauseScan)
			{
				Sleep(10);
			}
			if(!CMaxDBScanner::m_bStartScan)
			{
				return TRUE;
			}
			DisplayOnCMD(lpScanText);
		}

		SecureZeroMemory(&pipeData, sizeof(MAX_PIPE_DATA_REG));
		if(eTypeOfScanner == Finished_Scanning )
		{
			//Case No Spyware Found
			if(g_lstMaxSpywareData.empty())
			{
				DisplayOnCMD(_T("\n\n>>>>> No Spyware Found on Your PC"));
				SecureZeroMemory(&pipeData, sizeof(MAX_PIPE_DATA_REG));
				DisplayOnCMD(_T("\n\n Exiting Scanner"));
				pipeData.eMessageInfo = Exit_Scanner;
				OnDataReceivedCallBack (&pipeData);
				Sleep(3000);
				return TRUE;
			}

			//Case Spyware Found
			printf ("\n\n >>>>>>>  %d Spyware Found", g_lstMaxSpywareData.size()); 

			// if /P == True :- Prompt to User For Quarantine
			if(CMaxDBScanner ::m_bPromptToUser)
			{
				DisplayOnCMD(_T("\n\n###### Do You Want to Quarantine (Y/N)? "));

				int iChar = _getch();
				printf("%c\n", iChar);
				while(iChar != 89 && iChar != 121) //Check for Yes
				{
					if(iChar == 78 || iChar == 110)
					{
						DisplayOnCMD(_T("\nExiting Scanner"));
						SecureZeroMemory(&pipeData, sizeof(MAX_PIPE_DATA_REG));
						Sleep(3000);
						pipeData.eMessageInfo = Exit_Scanner;
						OnDataReceivedCallBack(&pipeData);
						return TRUE;
					}
					printf("\nInvalid Input!!! Please type Y/N: ");				
					iChar = _getch();
				}
			}
			else if ( CMaxDBScanner::m_bLogOnly )
			{
				DisplayOnCMD(_T("\nExiting Scanner"));
				SecureZeroMemory(&pipeData, sizeof(MAX_PIPE_DATA_REG));
				Sleep(3000);
				pipeData.eMessageInfo = Exit_Scanner;
				OnDataReceivedCallBack(&pipeData);
				return TRUE;
			}
			// Do Quarantine Work
			if(false == m_bRegistered)
			{
				DisplayOnCMD(_T("\nPlease register your copy to quarantine.\n"));
				return FALSE;
			}

			DisplayOnCMD(_T("\n------ Performing Quarantine Work\n"));
			SecureZeroMemory(&pipeData, sizeof(MAX_PIPE_DATA_REG));
			DisplayOnCMD(_T("------ Performing Special Spyware Quarantine\n"));
			pipeData.eMessageInfo = Perform_SplQuarantine;
			OnDataReceivedCallBack (&pipeData);
			DisplayOnCMD(_T("------ Sending Entries for Quarantine:\n"));

			while(!g_lstMaxSpywareData.empty())
			{
				while(CMaxDBScanner::m_bPauseScan)
				{
					Sleep(10);
				}
				if(!CMaxDBScanner::m_bStartScan)
				{
					SetEvent(m_hExitEvent);
					return TRUE;
				}

				SecureZeroMemory(&pipeData, sizeof(MAX_PIPE_DATA_REG));
				pipeData = g_lstMaxSpywareData.front();
				OnDataReceivedCallBack (&pipeData);
				g_lstMaxSpywareData.pop_front();
			}

            if(m_bDeleteTempIE)
			{
			    m_objCommandLineFuctions.DeleteTemporaryAndInternetFiles();
			}

			DisplayOnCMD (_T("\n\n-------- Finished Quarantine Work\n"));
			pipeData.eMessageInfo = Finished_Quarantine;
			OnDataReceivedCallBack (&pipeData);
			DisplayOnCMD(_T("\nSending EXIT request to CMDScanner\n"));
			Sleep(3000);
			SecureZeroMemory(&pipeData, sizeof(MAX_PIPE_DATA_REG));
			pipeData.eMessageInfo = Exit_Scanner;
			OnDataReceivedCallBack (&pipeData);
			return TRUE;
		}
#endif

	}
	else if(eTypeOfScanner > 200) // Its a Administrative task Message
	{
		if(eTypeOfScanner == DiskFullMessage)
		{
			memset(&m_sMaxPipeData, 0, sizeof(MAX_PIPE_DATA));
			m_sMaxPipeData.eMessageInfo = eTypeOfScanner;
#ifndef _STANDALONE_
			if(m_pMaxCommunicatorScanner)
			{
				m_pMaxCommunicatorScanner->SendData(&m_sMaxPipeData, sizeof(MAX_PIPE_DATA));
			}
#else
			if(eTypeOfScanner == DiskFullMessage)
			{
				DisplayOnCMD (_T("\n CMD Scanner is unable to quarantine entries as there is not enough free space to create backup for recovery.\nPlease make free space on this drive and then try quarantine again."));
				CMaxDBScanner::m_bStartScan = false;
			}
#endif
		}
#ifndef _STANDALONE_
		if(eTypeOfScanner == Delete_TempFile)
		{
			memset(&m_sMaxPipeData, 0, sizeof(MAX_PIPE_DATA));
			m_sMaxPipeData.eMessageInfo = FilePath_Report;
			_tcscpy_s(m_sMaxPipeData.strValue,strKey);
			if(m_pMaxCommunicatorScanner)
			{
				m_pMaxCommunicatorScanner->SendData(&m_sMaxPipeData, sizeof(MAX_PIPE_DATA));
			}			
		}
#endif
	}
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxDBScanner::OnDataReceivedCallBack
In Parameters  : LPVOID lpMaxParam, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CMaxDBScanner::OnDataReceivedCallBack(LPVOID lpMaxParam)
{
	LPMAX_PIPE_DATA sMaxPipeData = (LPMAX_PIPE_DATA)lpMaxParam;
	MAX_PIPE_DATA sResponse;
	SecureZeroMemory(&sResponse, sizeof(MAX_PIPE_DATA));

	if(!sMaxPipeData)
	{
		return;
	}

#ifndef _STANDALONE_
	if(sMaxPipeData->eMessageInfo == Register_WD_PID)
	{
		if(!theApp.m_bRegWDThreadRunning)
		{
			theApp.WDRegisterScanner(WD_StartingApp, Report_Scanner_Failure, NOTIFY_PIPE, theApp.m_eTypeOfScanner,
									theApp.m_csGUID);
		}
		return;
	}
#endif

	MAX_DISPATCH_MSG sMaxDispatchMessage;
	switch(sMaxPipeData->eMessageInfo)
	{
	case Finished_Quarantine:
		{
			//m_dwScanCount;
			//m_dwQSuccessCount;
			//m_dwQFailedCount;

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
				AddLogEntry(L"Sending restart required message to UI!");
#ifdef _STANDALONE_
				DisplayOnCMD(_T("\nPC Reboot is required..... \n\n >>> Please Restart Your Pc !!!"));
				Sleep (2000);
#else
				sResponse.ulSpyNameID = m_dwQSuccessCount;
				sResponse.eMessageInfo = Restart_Required; 
#endif // #ifndef _STANDALONE_
			}
			else
			{
				AddLogEntry(L"Sending restart not required message to UI!");
				sResponse.eMessageInfo = Finished_Quarantine; 
			}
#ifndef _STANDALONE_
			if (!CMaxDBScanner ::m_bAutoQuarantine)
			{
				if(theApp.m_pObjMaxCommunicatorServer)
				{
					theApp.m_pObjMaxCommunicatorServer->SendResponse(&sResponse);
				}
			}
#endif
			return;
		}
		break;
	case Exit_Scanner:
		{
#ifndef _STANDALONE_
			//OutputDebugString(L"Exit_Scanner Event Received in AuScanner, m_csGUID: " + theApp.m_csGUID + L", m_csScannerID: " + m_csScannerID);
			m_sMaxPipeData_Reg.eMessageInfo = Exit_Scanner;
			wcscpy_s(m_sMaxPipeData_Reg.szGUID, MAX_PATH, m_csScannerID);
			m_pMaxWDCommunicator->SendData(&m_sMaxPipeData_Reg, sizeof(MAX_PIPE_DATA_REG));
#endif
			if(m_hExitEvent)
			{
				SetEvent(m_hExitEvent);
			}
			return;
		}
		break;
	case Stop_Exit_Scanner:
		{
#ifndef _STANDALONE_
			OutputDebugString(L"Stop_Exit_Scanner Event Received in AuScanner, m_csGUID: " + theApp.m_csGUID + L", m_csScannerID: " + m_csScannerID);
			m_sMaxPipeData_Reg.eMessageInfo = Exit_Scanner;
			wcscpy_s(m_sMaxPipeData_Reg.szGUID, MAX_PATH, m_csScannerID);
			m_pMaxWDCommunicator->SendData(&m_sMaxPipeData_Reg, sizeof(MAX_PIPE_DATA_REG));
#else

			printf("(AUSCANNER) - Stop__Exit_Scanner event received!\n");
#endif

#ifndef _STANDALONE_
			OutputDebugString(L"Sending StopScanning Event to AuSecure.dll, m_csGUID: " + theApp.m_csGUID + L", m_csScannerID: " + m_csScannerID);
#endif
			sMaxDispatchMessage.eDispatch_Type = eStopScanning;
			sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
			m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);

#ifndef _STANDALONE_
			OutputDebugString(L"Finished Sending StopScanning Event to AuSecure.dll, m_csGUID: " + theApp.m_csGUID + L", m_csScannerID: " + m_csScannerID);
#endif
			if(m_hExitEvent)
			{
#ifndef _STANDALONE_
				OutputDebugString(L"Event is set to EXIT this scanner, m_csGUID: " + theApp.m_csGUID + L", m_csScannerID: " + m_csScannerID);
#endif
				SetEvent(m_hExitEvent);
			}
#ifndef _STANDALONE_
			else
			{
				OutputDebugString(L"Event is NOT VALID to set it to EXIT this scanner, m_csGUID: " + theApp.m_csGUID + L", m_csScannerID: " + m_csScannerID);
			}
#endif
			return;
		}
		break;
	case Stop_Scanning:
		{
#ifndef _STANDALONE_
			OutputDebugString(L"Stop_Scanning Event Received in AuScanner, m_csGUID: " + theApp.m_csGUID + L", m_csScannerID: " + m_csScannerID);
#endif
			sMaxDispatchMessage.eDispatch_Type = eStopScanning;
			sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
			m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);
		}
		break;
#ifndef _STANDALONE_
	case Pause_Scanning:
		{
			theApp.m_pScannerThread->SuspendThread();
		}
		break;
	case Resume_Scanning:
		{
			theApp.m_pScannerThread->ResumeThread();
		}
		break;
#endif
	case Perform_SplQuarantine:
		{
			sMaxDispatchMessage.eDispatch_Type = eSpecialQuarantine;
			sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
			m_pMaxSecureDispatcher(&sMaxDispatchMessage, sMaxPipeData);
		}
		break;
	case Delete_TempFile:
		{
#ifndef _STANDALONE_
			AddLogEntry(L"Starting Temp File Cleaup!");
			WCHAR szBuff[1024] = {0};
			CString csTempPath;
			csTempPath = sMaxPipeData->strValue;
			if((csTempPath.GetLength() != 0) && (csTempPath.Find(L":") != -1))
			{
				csTempPath += _T("*.*");
				AddLogEntry(L"Cleanup: %s", csTempPath);
				DeleteTempFilesSEH(csTempPath,TRUE);
			}
			if((CSystemInfo::m_strOS != WME) && (CSystemInfo::m_strOS != W98))
			{
				if((CSystemInfo::m_strWinDir.GetLength() != 0) && (CSystemInfo::m_strWinDir.Find(L":") != -1))
				{
					csTempPath = CSystemInfo::m_strWinDir + _T("\\Temp\\*.*");
					AddLogEntry(L"Cleanup: %s", csTempPath);
					DeleteTempFilesSEH(csTempPath, TRUE);
				}
			}
			AddLogEntry(L"Finished Temp File Cleaup!");
			if(theApp.m_pObjMaxCommunicatorServer)
			{
				theApp.m_pObjMaxCommunicatorServer->SendResponse(&sResponse);
			}
#endif
		}
		break;
	case GamingMode:
		{
			if(m_bBackgroundScanner == false)
			{
				if(sMaxPipeData->ulSpyNameID)
					SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
				else
					SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
			}
		}
		break;
	case Skip_Folder:
		{
			sMaxDispatchMessage.eDispatch_Type = eSkipFolder;
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
			if(sMaxPipeData->eStatus == eStatus_Detected)	
				m_dwQFailedCount++;
			else
				m_dwQSuccessCount++;
		}
		break;
	}
}

#ifdef _STANDALONE_
UINT CMaxDBScanner::CheckForStopScanEvent(LPVOID pThis)
{
	CMaxDBScanner * ptrMaxDBScanner = (CMaxDBScanner *)pThis;
    if(ptrMaxDBScanner && ptrMaxDBScanner->m_bStartScan)
    {	   
		while(true)
        {
 			int nKey = _getch();
            if(nKey == VK_SPACE)
			{
				break;
			} 	
			if(VK_ESCAPE == nKey)
            {
				ptrMaxDBScanner->m_bPauseScan  =  true;
				DisplayOnCMD(_T("\n\n###### Do You Want to Exit Scanner Without Quarantine (Y/N) ?"));
				int iChar = _getch();
				printf("%c\n", iChar);

				while(true)
				{
					if(iChar == 89 || iChar == 121)
					{
						ptrMaxDBScanner->m_bPauseScan = false;
						ptrMaxDBScanner->m_bStartScan = false;
						DisplayOnCMD(_T("\nScanning Stopped by user\r\nSending Exit Request to CMDScanner\n"));
						MAX_PIPE_DATA_REG pipeData = {0}; 
						Sleep(2000);

						SecureZeroMemory(&pipeData, sizeof(MAX_PIPE_DATA_REG));
						pipeData.eMessageInfo = Stop_Exit_Scanner;
 						OnDataReceivedCallBack (&pipeData);
						break;	
					}
					else if(iChar == 78 || iChar == 110)
					{
						ptrMaxDBScanner->m_bPauseScan = false;
						break;
					}
					else
					{
						printf("Invalid input. Please press y or n: ");
						iChar = _getch();
					}
				}
			}
		}		
	}	      
   	return 0;
}

UINT CMaxDBScanner::CheckForUIStartEventThread(LPVOID pThis)
{
	CMaxDBScanner *pMaxDBScanner = NULL;
	pMaxDBScanner  = (CMaxDBScanner *)pThis;
	if(pMaxDBScanner)
    {  
		pMaxDBScanner->CheckForUIStartEvent();
	}
	return 1;
}

void CMaxDBScanner::CheckForUIStartEvent(void)
{
	if(::WaitForSingleObject(m_hUICMDEvent, INFINITE) == WAIT_OBJECT_0)
	{
		::CloseHandle(m_hUICMDEvent);
	}

	// Exit the Process
	DWORD dwProcessExitCode = 0;
	GetExitCodeProcess(GetCurrentProcess(), &dwProcessExitCode);
	ExitProcess(dwProcessExitCode);	
}
#endif

#ifndef _STANDALONE_
BOOL CMaxDBScanner::DeleteTempFilesSEH(LPCTSTR lpDirectoryName, BOOL bSubDir)
{
	__try
	{
		return DeleteTempFiles(lpDirectoryName, bSubDir);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception Caught in DeleteTempFilesSEH: %s", lpDirectoryName);
	}
	return FALSE;
}

BOOL CMaxDBScanner::DeleteTempFiles(LPCTSTR lpDirectoryName, BOOL bSubDir)
{
	CFileFind	oFileFind;
	BOOL		bContinue = FALSE;
	CString csFileName;
	if((bContinue = oFileFind.FindFile(lpDirectoryName)) != 0)
	{
		while(bContinue)
		{
			bContinue = oFileFind.FindNextFile();
			if(oFileFind.IsDots())
			{
				continue;
			}
			CString csFile = oFileFind.GetFilePath();
			if(csFile.GetLength() >= MAX_PATH)
			{
				AddLogEntry(L"Skipped Deleting file with long path: %s", csFile);
				continue;
			}
			if(csFile.GetLength() == 0)
			{
				AddLogEntry(L"Skipped Deleting file with zero length: %s", csFile);
				continue;
			}
			if(oFileFind.IsDirectory() && bSubDir)
			{
				WCHAR lpszSubDirPath[ MAX_PATH] = {0};
				wcscpy_s(lpszSubDirPath, MAX_PATH, oFileFind.GetFilePath());
				wcscat_s(lpszSubDirPath, MAX_PATH, _T("\\*.*"));
				DeleteTempFiles(lpszSubDirPath, TRUE);
			}
			if(oFileFind.IsDirectory())
			{
				csFileName = oFileFind.GetFileName();
				if(csFileName.CompareNoCase(_T("Quarantine")) != 0)
					RemoveDirectory(oFileFind.GetFilePath());	
			}
			else
			{
				CString csFileName = oFileFind.GetFilePath();
				CFileFind filefind;
				BOOL bPresent = filefind.FindFile(csFileName);
				if(!bPresent)
					return FALSE;
				filefind.FindNextFile();

				//csFileName
				//Remove Read only attri
				DWORD dwAttrs = GetFileAttributes(csFileName);
				if(dwAttrs != INVALID_FILE_ATTRIBUTES &&  dwAttrs & FILE_ATTRIBUTE_READONLY)
				{
					SetFileAttributes(csFileName, dwAttrs ^ FILE_ATTRIBUTE_READONLY);
				}
				if(csFileName.CompareNoCase(_T("ServerVersionEx.txt")) != 0)
				{
					csFileName.MakeLower();
					if(csFileName.Find(_T("exclude")) == -1)
					{
						CString csTemp;
						csTemp.Format(L"%s%s",_T("Deleting Temp/Temp IE-"),csFileName);
						if(m_pMaxCommunicatorScanner)
						{
							memset(&m_sMaxPipeData, 0, sizeof(MAX_PIPE_DATA));
							m_sMaxPipeData.eMessageInfo = FilePath_Report;
							_tcscpy_s(m_sMaxPipeData.strValue, MAX_PATH, csTemp);

							m_pMaxCommunicatorScanner->SendData(&m_sMaxPipeData, sizeof(MAX_PIPE_DATA));
						}
						DeleteFile(csFileName);
						//UpdateStatusBar(theApp.m_pResMgr->GetString(_T("IDS_DELETING_STATUS_EN")) + csFileName);
					}
				}
			}
		}
		oFileFind.Close();
	}
	return TRUE;
}
#endif