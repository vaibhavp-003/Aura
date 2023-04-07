/*======================================================================================
FILE             : SDScanner.cpp
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
CREATION DATE    : 8/1/2009 7:51:38 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "SDScanner.h"
#include "MaxExceptionFilter.h"
#include "SDSystemInfo.h"
#include "UserTrackingSystem.h"
#include "NetWorkUserValidation.h"
#include <Lmcons.h>
#include <lm.h>
#pragma comment(lib, "netapi32.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// The one and only CSDScannerApp object
CSDScannerApp theApp;

/*--------------------------------------------------------------------------------------
Function       : StartScanning
In Parameters  : SENDMESSAGETOUI lpSendMessaegToUI, SCAN_OPTIONS &sScanOptions, const TCHAR *strDrivesToScan, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void StartScanning(SENDMESSAGETOUIMS lpSendMessaegToUI, SCAN_OPTIONS &sScanOptions,
													const TCHAR *strDrivesToScan)
{

	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	theApp.StartScanning(lpSendMessaegToUI, sScanOptions, strDrivesToScan);
}

/*--------------------------------------------------------------------------------------
Function       : StartScanningForReferences
In Parameters  : SENDMESSAGETOUI lpSendMessaegToUI, SCAN_OPTIONS &sScanOptions, const TCHAR *strDrivesToScan, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void StartScanningForReferences(SENDMESSAGETOUIMS lpSendMessaegToUI,
																 SCAN_OPTIONS &sScanOptions,
																 const TCHAR *strDrivesToScan,
																 CS2U* pobjFilesList,
																 CS2U* pobjFoldersList)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	theApp.StartScanning(lpSendMessaegToUI, sScanOptions, strDrivesToScan, pobjFilesList, pobjFoldersList, true);
}

/*--------------------------------------------------------------------------------------
Function       : StopScanning
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void StopScanning()
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	theApp.StopScanning();
}

/*--------------------------------------------------------------------------------------
Function       : InitializeDLL
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void InitializeDLL(SENDMESSAGETOUIMS lpSendMessaegToUI, bool bIsUSBScan = false, bool bIsMachineLearning = false, LPMAX_PIPE_DATA_CMD lpMaxPipeDataCmd = NULL)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	theApp.m_bValidated = false;
	theApp.InitializeDLL(lpSendMessaegToUI,bIsUSBScan,bIsMachineLearning, lpMaxPipeDataCmd);
}

/*--------------------------------------------------------------------------------------
Function       : DeInitializeDLL
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void DeInitializeDLL()
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	theApp.DeInitializeDLL();
}

/*--------------------------------------------------------------------------------------
Function       : PerformQuarantine
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void PerformQuarantine(SENDMESSAGETOUI lpSendMessaegToUI)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	if(!theApp.m_pThreatManager)
	{
		theApp.m_pThreatManager = new CThreatManager(lpSendMessaegToUI);
		theApp.SetAutomationLabStatus();
	}
	theApp.m_pThreatManager->PerformQuarantine();
}

/*--------------------------------------------------------------------------------------
Function       : PerformDBAction
In Parameters  : LPMAX_PIPE_DATA lpPipeData, 
Out Parameters : bool 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool PerformDBAction(LPMAX_PIPE_DATA lpPipeData)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	if(!theApp.m_pThreatManager)
	{
		theApp.m_pThreatManager = new CThreatManager(NULL);
		theApp.SetAutomationLabStatus();
	}
	return theApp.m_pThreatManager->PerformDBAction(lpPipeData);
}

/*--------------------------------------------------------------------------------------
Function       : PerformRegAction
In Parameters  : LPMAX_PIPE_DATA_REG lpMaxregdata, 
Out Parameters : bool 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool PerformRegAction(LPMAX_PIPE_DATA_REG lpMaxregdata, PMAX_SCANNER_INFO pScanInfo)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	if(!theApp.m_pMaxScanner)
	{
		theApp.InitializeDLL(NULL);
		theApp.m_pMaxScanner->m_oLocalSignature.LoadLocalDatabase(L"C:", Scanner_Type_Max_SignatureScan);
	}
	if(theApp.m_pMaxScanner)
	{
		if((lpMaxregdata->eMessageInfo == Virus_File) 
			|| (lpMaxregdata->eMessageInfo == Virus_File_Repair)
			|| (lpMaxregdata->eMessageInfo == Module))
		{
			MAX_SCANNER_INFO oScanInfo = {0};
			if (pScanInfo != NULL)
			{
				memcpy(&oScanInfo, pScanInfo, sizeof(MAX_SCANNER_INFO));				
			}
			else
			{
				oScanInfo.eMessageInfo = File;
			}
			
			oScanInfo.AutoQuarantine = 1;
			_tcscpy_s(oScanInfo.szFileToScan, _countof(oScanInfo.szFileToScan), lpMaxregdata->strKey);
			theApp.m_pMaxScanner->ScanFile(&oScanInfo);
			if(oScanInfo.ThreatRepaired)
			{
				_tcscpy_s(lpMaxregdata->strBackup, oScanInfo.szBackupFileName);
				lpMaxregdata->eStatus = eStatus_Quarantined;
				return true;
			}
			if(oScanInfo.ThreatQuarantined)
			{
				_tcscpy_s(lpMaxregdata->strBackup, oScanInfo.szBackupFileName);
				lpMaxregdata->eStatus = eStatus_Quarantined;
				return true;
			}
			return false;
		}
		if(!theApp.m_pThreatManager)
		{
			theApp.m_pThreatManager = new CThreatManager(NULL);
			theApp.SetAutomationLabStatus();
		}
		return theApp.m_pThreatManager->PerformRegAction(lpMaxregdata);
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : PerformRecoverAction
In Parameters  : LPMAX_PIPE_DATA lpPipeData, bool bUpdateDB, 
Out Parameters : bool 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool PerformRecoverAction(LPMAX_PIPE_DATA lpPipeData, bool bUpdateDB)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	if(!theApp.m_pThreatManager)
	{
		theApp.m_pThreatManager = new CThreatManager(NULL);
		theApp.SetAutomationLabStatus();
	}	
	return theApp.m_pThreatManager->PerformRecoverAction(lpPipeData, bUpdateDB);	
}

extern "C" __declspec(dllexport) bool PerformScanFile(LPMAX_PIPE_DATA_REG lpPipeDataReg)
{
	if(!theApp.m_pMaxScanner)
	{
		theApp.InitializeDLL(NULL);
		theApp.m_pMaxScanner->m_oLocalSignature.LoadLocalDatabase(L"C:", Scanner_Type_Max_Email_Scan);
	}
	lpPipeDataReg->eStatus = eStatus_NotApplicable;
	return theApp.m_pSpyScanner->ScanFile(lpPipeDataReg);
}

/*--------------------------------------------------------------------------------------
Function       : DeInitializeDLL
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Ramkrushna Shelke & 12 May, 2012.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool ReLoadMailScanerDB()
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	if(!theApp.ReLoadMailScannerDB())
	{
		return false;
	}
	return true;
}

extern "C" __declspec(dllexport) void SkipFolder()
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	theApp.m_bSkipFolder = true;
}
// CSDScannerApp
BEGIN_MESSAGE_MAP(CSDScannerApp, CWinApp)
END_MESSAGE_MAP()

// CSDScannerApp construction
/*--------------------------------------------------------------------------------------
Function       : CSDScannerApp::CSDScannerApp
In Parameters  : 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CSDScannerApp::CSDScannerApp():m_pSpyScanner(NULL), m_pMaxScanner(NULL)
{
}

// CSDScannerApp initialization
/*--------------------------------------------------------------------------------------
Function       : CSDScannerApp::InitInstance
In Parameters  : 
Out Parameters : BOOL 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
BOOL CSDScannerApp::InitInstance()
{
	CWinApp::InitInstance();
	CMaxExceptionFilter::InitializeExceptionFilter();
	LoadLoggingLevel();
	CUserTrackingSystem oUserTrackingSystem;
	oUserTrackingSystem.SetProductKey(CSystemInfo::m_csProductName);
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : CSDScannerApp::ExitInstance
In Parameters  : 
Out Parameters : int 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
int CSDScannerApp::ExitInstance()
{
	__try
	{
		if(m_pMaxScanner)
		{
			delete m_pMaxScanner;
			m_pMaxScanner = NULL;
		}
		if(m_pThreatManager)
		{
			delete m_pThreatManager;
			m_pThreatManager = NULL;
		}
		if(m_pSpyScanner)
		{
			delete m_pSpyScanner;
			m_pSpyScanner = NULL;
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught Exception caught CSDScannerApp::ExitInstance")))
	{

	}
	return CWinApp::ExitInstance();
}

/*--------------------------------------------------------------------------------------
Function       : CSDScannerApp::StartScanning
In Parameters  : SENDMESSAGETOUI lpSendMessaegToUI, SCAN_OPTIONS &sScanOptions, const TCHAR *strDrivesToScan, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CSDScannerApp::StartScanning(SENDMESSAGETOUIMS lpSendMessaegToUI, SCAN_OPTIONS &sScanOptions,
								  const TCHAR *strDrivesToScan, CS2U* pobjFilesList,
								  CS2U* pobjFoldersList, bool bScanReferences)
{
	if(m_pSpyScanner)
	{
		m_pSpyScanner->m_bDatabaseScan = sScanOptions.DBScan;
		m_pSpyScanner->m_bSignatureScan = (sScanOptions.SignatureScan ? true : sScanOptions.CustomScan);
		m_pSpyScanner->m_bVirusScan = ((CSystemInfo::m_iVirusScanFlag == 1) ? true : sScanOptions.VirusScan);
		m_pSpyScanner->m_bDeepScan = sScanOptions.DeepScan;
		m_pSpyScanner->m_bRegFixScan = sScanOptions.RegFixScan;
		m_pSpyScanner->m_bRegFixForOptionTab = sScanOptions.RegFixOptionScan;
		m_pSpyScanner->m_bScanReferences = bScanReferences;
		m_pSpyScanner->m_bAutoQuarantine = sScanOptions.AutoQuarantine;
		m_pSpyScanner->m_bUSBScan = sScanOptions.IsUSBScanner;
		m_pSpyScanner->m_pobjFilesList = pobjFilesList;
		m_pSpyScanner->m_pobjFoldersList = pobjFoldersList;
		//m_pSpyScanner->m_bMachineLearning = sScanOptions.MachineLearning;
		if(sScanOptions.MachineLearning && sScanOptions.DBScan)
		{
			m_pMaxScanner->m_bMachineLearningQ = true;
		}
		m_pSpyScanner->StartScanning(strDrivesToScan);
	}

	CRegistry oRegistry;
	DWORD dwEPMD5 = 0, dwEPMD5Tmp = 0, dwAutoDBPatch = 0;
	oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("AutoDatabasePatch"), dwAutoDBPatch, HKEY_LOCAL_MACHINE);
	oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("EPMD5UPDATETMP"), dwEPMD5Tmp, HKEY_LOCAL_MACHINE);
	oRegistry.Get(CSystemInfo::m_csProductRegKey , _T("EPMD5UPDATE"), dwEPMD5, HKEY_LOCAL_MACHINE);
	if(1 == dwAutoDBPatch)
	{
		oRegistry.Set(CSystemInfo::m_csProductRegKey , _T("EPMD5UPDATETMP"), 0, HKEY_LOCAL_MACHINE);
		oRegistry.Set(CSystemInfo::m_csProductRegKey , _T("EPMD5UPDATE"), 0, HKEY_LOCAL_MACHINE);
	}
	else if(1 == dwEPMD5Tmp)
	{
		oRegistry.Set(CSystemInfo::m_csProductRegKey , _T("EPMD5UPDATE"), 1, HKEY_LOCAL_MACHINE);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CSDScannerApp::StopScanning
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CSDScannerApp::StopScanning()
{
	if(m_pSpyScanner)
	{
		m_pSpyScanner->StopScanning();
	}
}

/*--------------------------------------------------------------------------------------
Function       : CSDScannerApp::InitializeDLL
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 10 June, 2010.
--------------------------------------------------------------------------------------*/
void CSDScannerApp::InitializeDLL(SENDMESSAGETOUIMS lpSendMessaegToUI, bool bIsUSBScan, bool bIsMachineLearning, LPMAX_PIPE_DATA_CMD lpMaxPipeDataCmd)
{
	try
	{
		m_bBGScanner = false;
		CRegistry oReg;
		CSystemInfo oSysInfo;
		CString csMaxDBPath;
		oReg.Get(oSysInfo.m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
		if(!m_pMaxScanner)
		{
			m_pMaxScanner = new CMaxScanner;
			if(m_pMaxScanner)	// Load Virus scanner and db only for scanning!
			{
				m_pMaxScanner->m_bIsUsbScan = bIsUSBScan;
				m_pMaxScanner->m_bMachineLearning = bIsMachineLearning;
			
				bool bLogPathSet= false;
				if(lpMaxPipeDataCmd != NULL)
				{
					if (lpMaxPipeDataCmd->sScanOptionsCmd.ScanADStream == 1)	// 14-9-2022 changes done to restrict ADS scan
					{
						m_pMaxScanner->m_bADSScan = true;
					}
					if(lpMaxPipeDataCmd->sScanOptionsCmd.BackGScanner == 1)
					{
						m_bBGScanner = true;
					}
					else
					{
						m_bBGScanner = false;
					}
					if(lpMaxPipeDataCmd->strPath != NULL)
					{
						if(_tcslen(lpMaxPipeDataCmd->strPath) > 3)
						{
							bLogPathSet = true;
							SetCmdLogPath(lpMaxPipeDataCmd->strPath, lpMaxPipeDataCmd->sScanOptionsCmd.LogType, lpMaxPipeDataCmd->sScanOptionsCmd.LogLevel);
						}
						else if(lpMaxPipeDataCmd->sScanOptionsCmd.LogType == 1)
						{
							bLogPathSet = true;
							SetCmdLogPath(L"", lpMaxPipeDataCmd->sScanOptionsCmd.LogType, lpMaxPipeDataCmd->sScanOptionsCmd.LogLevel);
						}
					}
				}
				if(!bLogPathSet)
				{
					SetCmdLogPath(L"", 2, 0);
				}
				m_pMaxScanner->InitializeScanner(csMaxDBPath);
				
				if(lpMaxPipeDataCmd != NULL)
				{
					if(lpMaxPipeDataCmd->sScanOptionsCmd.LogType == 1)
					{
						if(lpMaxPipeDataCmd->sScanOptionsCmd.ArchiveScan == 1)
						{
							m_pMaxScanner->m_dwSkipCompressfiles = 0;
						}
						else
						{
							m_pMaxScanner->m_dwSkipCompressfiles = 1;
						}
					}
				}
			}
		}
		if(!m_pSpyScanner)
		{
			m_pSpyScanner = new CSpyScanner(lpSendMessaegToUI, m_pMaxScanner);
		}
		if(!m_pThreatManager)
		{
			m_pThreatManager = new CThreatManager(NULL);
			SetAutomationLabStatus();
		}
	}
	catch(...)
	{

	}
}

/*--------------------------------------------------------------------------------------
Function       : CSDScannerApp::DeInitializeDLL
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 10 June, 2010.
-----------------------------	---------------------------------------------------------*/
void CSDScannerApp::DeInitializeDLL()
{
	__try
	{
		if(m_pMaxScanner)
		{
			m_pMaxScanner->DeInitializeScanner();
			delete m_pMaxScanner;
			m_pMaxScanner = NULL;
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught CSDScannerApp::DeInitializeDLL(1)")))
	{
	}
	__try
	{
		if(m_pThreatManager)
		{
			delete m_pThreatManager;
			m_pThreatManager = NULL;
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught CSDScannerApp::DeInitializeDLL(2)")))
	{
	}
	__try
	{
		if(m_pSpyScanner)
		{
			delete m_pSpyScanner;
			m_pSpyScanner = NULL;
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught CSDScannerApp::DeInitializeDLL(3)")))
	{

	}
}

BOOL CSDScannerApp::IsAutoCleanActive()
{
	return m_pSpyScanner->m_bAutoQuarantine;
}

void CSDScannerApp::SetAutomationLabStatus()
{
	DWORD dwAutomationLab = 0;
	CRegistry oReg;
	oReg.Get(CSystemInfo::m_csProductRegKey, AUTOLATION_LAB_VAL, dwAutomationLab, HKEY_LOCAL_MACHINE);
	m_pThreatManager->m_bAutomationLab = (dwAutomationLab == 1 ? true : false);
	if(m_pMaxScanner)
	{
		m_pMaxScanner->SetAutomationLabStatus(m_pThreatManager->m_bAutomationLab);
	}

	SetGameMode();
}

bool CSDScannerApp::ReLoadMailScannerDB()
{
	if(m_pMaxScanner)
	{
		if(m_pMaxScanner->ReloadMailScannerDB())
		{	
			return true;
		}
	}	
	return false;
}

void CSDScannerApp::SetGameMode()
{
	DWORD dwData = 0;
	CRegistry oReg;

	oReg.Get(CSystemInfo::m_csActMonRegKey, GAMINGMODE_KEY, dwData, HKEY_LOCAL_MACHINE);
	if(dwData)
	{
		SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
	}
}
