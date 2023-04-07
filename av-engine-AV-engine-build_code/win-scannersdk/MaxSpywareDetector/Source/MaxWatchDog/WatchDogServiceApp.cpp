/*======================================================================================
FILE             : WatchDogServiceApp.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshit Kasliwal
COMPANY		     : Aura
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 5/12/2009
NOTES		     : Contains the implementation of the watchdog crash handling mechanism
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "WatchDogServiceApp.h"
#include "WatchDogService.h"
#include "EnumProcess.h"
#include "MaxCommunicator.h"
#include "MaxCommunicatorServer.h"
#include "MaxPipes.h"
#include "SDConstants.h"
#include "ExecuteProcess.h"
#include "MaxProcessReg.h"
#include "ExecuteProcess.h"
#include "atlbase.h"
#include <wininet.h>
#include "Registry.h"
#include "RemoteService.h"
#include "InternetOperation.h"
#include "RestorePoint.h"
#include "CPUInfo.h"
#include "ProductInfo.h"
#include "MaxExceptionFilter.h"
#include "HardDiskManager.h"
#include "SDSystemInfo.h"
#include "RegistryHelper.h"
#include "UninstallProducts.h"
#include "USBMonitor.h"
#include "BufferToStructure.h"
#include "MaxProtectionMgr.h"
#include "MaxDSrvWrapper.h"
#include <aclapi.h>
#include "DirectoryManager.h"
#include "MSIOperations.h"
#include "UserTrackingSystem.h"
#include <direct.h>
#include <stdio.h>
#include "FileSignatureDb.h"


const TCHAR *g_szMaxBroadcastPipeNames[8] =
{
	_NAMED_PIPE_TRAY_TO_ACTMON,
	_NAMED_PIPE_ACTMON_TO_TRAY,
	_NAMED_PIPE_SCANNER_TO_UI,
	_NAMED_ACTION_PIPE_UI_TO_SCANNER,
	_NAMED_PIPE_OPTIONTTAB_TO_SCANNER,
	_NAMED_PIPE_UI_TO_RECOVER_SCANNER,
	_NAMED_PIPE_HEURISTICSCAN_TO_SCANNER,
	_NAMED_PIPE_DBCLIENT_TO_DBSERVER
};

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

HANDLE CWatchDogServiceApp::m_hSingleEventHandler = NULL;
WCHAR CWatchDogServiceApp::m_strAppPath[MAX_PATH]={0};
bool CWatchDogServiceApp::m_bShutDown = false;
ProcessMapItem CWatchDogServiceApp::m_ProcessMapItem;

typedef enum _tagLiveUpdateActivity
{
	LU_ShowLUMessage,
	LU_DoBackGroundLU,
	LU_DownloadSigDB,
	LU_DownloadDBPatch,
	LU_DownloadProductPatch,
	LU_TrackMyLaptop
}LUACT;

//global variables
int		g_iRegister = 0;
//global functions
void	CheckScheduleTime();
//Thread Functions
UINT	WatchOtherAppsThread(LPVOID lpParam);
UINT	RestoreSystemDefaultsThread(LPVOID lpParam);
UINT	SchedulerThread(LPVOID lpParam);
UINT	LiveupdateThread(LPVOID lpParam);
UINT	AutoScanThread(LPVOID lpParam);
UINT	SetupAutoLaunchThread(LPVOID lpParam);
UINT	CreateDBForSystemFilesThread(LPVOID lpParam);
int		GetMonthIndex(CString cstr);
UINT	BackGroundScanThread(LPVOID lpParam);
UINT	CryptMonFolderCheckThread(LPVOID lpParam);
UINT	LoadMergerThread(LPVOID lpParam);
UINT	LaunchWscSrvThread(LPVOID lpParam);

bool GetMD5Signature32(const char *filepath, char *cMD5Signature);

BEGIN_MESSAGE_MAP(CWatchDogServiceApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()

/*--------------------------------------------------------------------------------------
Function       : CWatchDogServiceApp
In Parameters  :
Out Parameters :
Description    : c'tor Named pipe name and callback function provided in the initialization list
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CWatchDogServiceApp::CWatchDogServiceApp():m_objMaxWatchDogServer(_NAMED_PIPE_WATCHDOG_PROCESSES, CWatchDogServiceApp::OnWatchDogStatusReceiveCallback, sizeof(MAX_WD_DATA)),
m_objMaxCommunicatorServer(_NAMED_PIPE_UI_TO_SERVICE, CWatchDogServiceApp::OnDataReceivedCallBack, sizeof(MAX_PIPE_DATA_REG)),m_objMaxWscSrvServer(_NAMED_PIPE_UI_TO_WSCREGSERVICE,
												CWatchDogServiceApp::OnDataReceivedWscSrvCallBack,sizeof(SHARED_ACTMON_SWITCH_DATA)), m_objFileList(false, true),m_objHeurSysDb(false),m_objMD5List(true)
{
	m_nCapCount = 0;
	//m_pDevList = NULL;
	if(m_hSingleEventHandler == NULL)
	{
		m_hSingleEventHandler = CreateEvent(NULL, FALSE, TRUE, NULL);
	}
}

/*--------------------------------------------------------------------------------------
Function       : ~CWatchDogServiceApp
In Parameters  :
Out Parameters :
Description    : D'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CWatchDogServiceApp::~CWatchDogServiceApp()
{
	//SetWDShutDownStatus(0);
	//m_ProcessMapItem.clear();
	//static object, hence ignoring close handle call!
	//m_hSingleEventHandler
}

CWatchDogServiceApp theApp;

/*--------------------------------------------------------------------------------------
Function       : ThreadStart
In Parameters  : LPVOID lpVoid,
Out Parameters : UINT INT
Description    : Performing Entire Watchdog operation through the ThreadStart function
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
UINT ThreadStart(LPVOID lpVoid)
{
	CWatchDogServiceApp *pThis = (CWatchDogServiceApp *)lpVoid;
	if(pThis)
		pThis->ManageOther();
	return 0;
}

UINT StartUSBMonitor(LPVOID lpVoid)
{
	CUSBMonitor oUSBMonitor;
	oUSBMonitor.DoModal();
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : ManageOther
In Parameters  :
Out Parameters : void
Description    : Entry point function of the ThreadStart Thread.
Launches Active Monitor
Launches AuDBServer
Launches AuScanner in Quarantine mode to quarantine files that required restart
Launches Scheduler Thread
Launches Live Update Thread
Launches Autoscan Thread
Launches Restor point thread
Launches Threat Community thread

Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::ManageOther()
{
	CRegistry objReg;

	m_dwWin10 = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("Win10"), m_dwWin10, HKEY_LOCAL_MACHINE);
	
	//Making Watchdog Server an App Variable
	m_objMaxWatchDogServer.Run(true, false);
	m_objMaxCommunicatorServer.Run();
#ifdef WATCHDOGWSC				
	if(m_dwWin10 == 1)
	{
		m_objMaxWscSrvServer.Run();
	}
#endif


	//AddLogEntry(L"TEST >>> CWatchDogServiceApp : Started Communication");

	/************************ For WPD Device Blocking ************************/
	if (objReg.KeyExists(L"SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\{6AC27878-A6FA-4155-BA85-F98F491D4F33}",HKEY_LOCAL_MACHINE) == false || 
		objReg.KeyExists(L"SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}",HKEY_LOCAL_MACHINE) == false)
	{
		HKEY	hMyKey = NULL;
		objReg.CreateKey(L"SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices",hMyKey,HKEY_LOCAL_MACHINE);
		objReg.CreateKey(L"SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\{6AC27878-A6FA-4155-BA85-F98F491D4F33}",hMyKey,HKEY_LOCAL_MACHINE);
		objReg.CreateKey(L"SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}",hMyKey,HKEY_LOCAL_MACHINE);
	}
	/************************************************************************/
	
	CEnumProcess obj;
	CExecuteProcess oExecuteProcess;
	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.ResumeProtection();
	oExecuteProcess.RestoreEXE(m_strAppPath + CString(L"\\AuActMon.exe"));
	oExecuteProcess.RestoreEXE(m_strAppPath + CString(L"\\AuDBServer.exe"), 0, true);
	oMaxProtectionMgr.ResumeProtectionNetwork();
	DWORD dwAskForRestart = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey,_T("AskForRestart"), dwAskForRestart, HKEY_LOCAL_MACHINE);
	if(dwAskForRestart)
	{
		LaunchGUIApp(m_strAppPath + CString(L"\\AuNotifications.exe"), _T("1"));
		objReg.Set(CSystemInfo::m_csProductRegKey,_T("AskForRestart"), 0, HKEY_LOCAL_MACHINE);
	}

	CString strINIPath = m_strAppPath;
	strINIPath += _T("\\");
	strINIPath += MAXMANAGER_INI;
	//if(PathFileExists(strINIPath))
	{
		CString csFile = m_strAppPath;
		csFile += _T("\\");
		csFile += MAX_SCANNER;
		ShellExecute(0, L"open", csFile, L"/Q", 0, SW_HIDE);
	}

	CString csFileName;
	csFileName.Format(_T("\"%s\\%s\" -AUTO"), static_cast<LPCTSTR>(CWatchDogServiceApp::m_strAppPath), ACTMON_TRAY_NAME);
	objReg.Set(RUN_KEY_PATH, _T("AuActiveMonitor"), csFileName, HKEY_LOCAL_MACHINE);

	//Add other threads here
	//Start thread for restoring system default and check invalid run entries
	m_RestoreSystemDefaultsThread = AfxBeginThread(RestoreSystemDefaultsThread, NULL, THREAD_PRIORITY_NORMAL, NULL, NULL, NULL);
	//Start thread for Schedular
	m_SchedulerThread = AfxBeginThread(SchedulerThread, NULL, THREAD_PRIORITY_NORMAL, NULL, NULL, NULL);
	
	//Start thread for Live Update
	m_LiveupdateThread = AfxBeginThread(LiveupdateThread, NULL, THREAD_PRIORITY_NORMAL, NULL, NULL, NULL);

	//Start Thread for Auto scan
	m_AutoScanThread = AfxBeginThread(AutoScanThread, NULL, THREAD_PRIORITY_NORMAL, NULL, NULL, NULL);
	
	//Background scan
	//m_BackGroundScanThread = AfxBeginThread(BackGroundScanThread, NULL, THREAD_PRIORITY_IDLE, NULL, NULL, NULL);

	//Create CryptMonFolderCheckThread
	m_CryptMonFolderCheckThread = AfxBeginThread(CryptMonFolderCheckThread, NULL, THREAD_PRIORITY_LOWEST, NULL, NULL, NULL);
	//Create CryptMonFolderCheckThread
	
	//Start Auto launch thread
	m_SetupAutoLaunchThread = AfxBeginThread(SetupAutoLaunchThread, NULL, THREAD_PRIORITY_NORMAL, NULL, NULL, NULL);
	
	//Start Watch Other Applications Thread
	m_WatchOtherAppsThread = AfxBeginThread(WatchOtherAppsThread, NULL, THREAD_PRIORITY_NORMAL, NULL, NULL, NULL);

	
	//Update Merger
	m_LoadMergerThread = AfxBeginThread(LoadMergerThread, NULL, THREAD_PRIORITY_NORMAL, NULL, NULL, NULL);
	
	// Wsc Service code merged		//13-4-2022
#ifdef WATCHDOGWSC				
	m_csProductName = L"";
	m_RemediationPath = L"";
	//Launch Wsc manage thread
	m_LaunchWscSrvThread = AfxBeginThread(LaunchWscSrvThread, NULL, THREAD_PRIORITY_NORMAL, NULL, NULL, NULL);
#endif
	

	//Wsc Service end

	DWORD bStatus = 0;
	objReg.Get(FW_DRIVER_PATH, _T("EmailEnable"), bStatus , HKEY_LOCAL_MACHINE);
	
	if(bStatus == 1)
	{
		if(PathFileExists(CSystemInfo::m_strAppPath + _T("\\FWData\\AuAntiSpam.dll")) == TRUE)
		{
			if(CopyFile(CSystemInfo::m_strAppPath + _T("\\FWData\\AuAntiSpam.dll"), CSystemInfo::m_strAppPath + _T("\\AuAntiSpam.dll"), FALSE) == TRUE)
				DeleteFile(CSystemInfo::m_strAppPath + _T("\\FWData\\AuAntiSpam.dll"));
		}

		TCHAR lpCommandLine[MAX_PATH] = {0};
		swprintf_s(lpCommandLine,MAX_PATH, _T("/PL /B:%s /DRIVES:"), _NAMED_PIPE_SCANNER_TO_PLUGIN);
		CWatchDogServiceApp::LaunchScanner(static_cast<LPCTSTR>(lpCommandLine));
		if((CSystemInfo::m_strOS.Find(WVISTA) == -1) && (CSystemInfo::m_strOS.Find(WWIN7) == -1) && (CSystemInfo::m_strOS.Find(WWIN8) == -1))
		{
			AddLogEntry(_T(">>> Launching...%s"), CWatchDogServiceApp::m_strAppPath + CString(L"\\AuMailProxy.exe"));
			oExecuteProcess.RestoreEXE(CWatchDogServiceApp::m_strAppPath + CString(L"\\AuMailProxy.exe"), 0, true);
		}
	}

	
	//Check if earlier shutdown was abrupt
	DWORD dwValue = 0;
	if(!GetWDShutDownStatus(dwValue))
	{
		SetWDShutDownStatus(1);
	}
	else
	{
		if(dwValue == 1)
		{
			BroadcastToSDProcesses();
		}
		else
		{
			SetWDShutDownStatus(1);
		}
	}

}

/*--------------------------------------------------------------------------------------
Function       : InitInstance
In Parameters  :
Out Parameters : BOOL
Description    : Initialization function of the App.
                 Initializes Exception Filter and starts the service
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
BOOL CWatchDogServiceApp::InitInstance()
{
	CWinApp::InitInstance();

	CMaxExceptionFilter::InitializeExceptionFilter();

	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.RegisterProcessID(MAX_PROC_MAXWATCHDOG);

	GetModuleFileName(NULL, m_strAppPath, MAX_PATH);
	WCHAR *cExtPtr = wcsrchr(m_strAppPath, '\\');
	*cExtPtr = '\0';

	AfxBeginThread(StartUSBMonitor, NULL, THREAD_PRIORITY_NORMAL, NULL, NULL, NULL);
	AfxBeginThread(ThreadStart, this, THREAD_PRIORITY_NORMAL);

	LoadLoggingLevel();

	CWatchDogService objWatchDogService;
	objWatchDogService.InitService(MAXWATCHDOG_SVC_NAME);
	objWatchDogService.StartService();
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : OnDataReceivedCallBack
In Parameters  : LPVOID lpParam,
Out Parameters : void
Description    : Named Pipe Communication Callback function.It receives all WD
				 Scanner requests
				 Live Update request
				 Heuristics request
				 if one similar instance of scanner is running it will send stop request
				 to the earlier version
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::OnDataReceivedCallBack(LPVOID lpParam)
{
	//AddLogEntry(L"In CWatchDogServiceApp::OnDataReceivedCallBack()!");

	LPMAX_PIPE_DATA_REG sMaxPipeData = (MAX_PIPE_DATA_REG*)lpParam;
	if(sMaxPipeData)
	{
		if(sMaxPipeData->eMessageInfo == LaunchAppAsSystem)
		{
			CExecuteProcess objExecProc;
			objExecProc.ExecuteProcess(sMaxPipeData->strValue, sMaxPipeData->strBackup, true, 0);
			sMaxPipeData->eMessageInfo = Scanner_Is_Ready;
			theApp.m_objMaxCommunicatorServer.SendResponse(sMaxPipeData);
			return;
		}

		if(sMaxPipeData->eMessageInfo == Show_AUSuccessDlg)
		{
			ShowAutoUpdateSuccessDlg();
			return;
		}
		if(sMaxPipeData->eMessageInfo == Set_RegistrySetting)
		{
			CRegistry objReg;
			switch(sMaxPipeData->Type_Of_Data)
			{
			case REG_DWORD:
				objReg.Set(sMaxPipeData->strKey, sMaxPipeData->strValue, (DWORD)sMaxPipeData->ulSpyNameID, sMaxPipeData->Hive_Type);
				break;
			case REG_SZ:
				objReg.Set(sMaxPipeData->strKey, sMaxPipeData->strValue, sMaxPipeData->strBackup, sMaxPipeData->Hive_Type, false);
				break;
			default:
				AddLogEntry(L"##### Invalid option given to Set_RegistrySetting");
			}
			return;
		}		
		if(sMaxPipeData->eMessageInfo == LaunchAppAs_USER)
		{
			LaunchGUIApp(sMaxPipeData->strValue, sMaxPipeData->strBackup);
			return;
		}
		if(sMaxPipeData->eMessageInfo == Manage_SystemRestore)
		{
			CEnumProcess objEnum;
			if(CSystemInfo ::m_strOS.Find(WVISTA) != -1 || CSystemInfo ::m_strOS.Find(WWIN7) != -1)
			{
				if(sMaxPipeData->ulSpyNameID == 1)
				{
					objEnum.StartSystemRestore(false);
				}
				else
				{
					objEnum.StopSystemRestore(false);
				}
			}
			else if(sMaxPipeData->ulSpyNameID == 1)
			{
				objEnum.StartSystemRestore();
			}
			else
			{
				objEnum.StopSystemRestore();
			}
			return;
		}
		if(sMaxPipeData->eMessageInfo == Enable_Stop_WD)
		{
			CWatchDogService::SetWDServiceStopStatus();
			theApp.m_objMaxCommunicatorServer.SendResponse(sMaxPipeData);
			return;
		}
		else if(sMaxPipeData->eMessageInfo == Enable_Stop_WD_PPL)
		{
			CWatchDogService::SetWDServiceStopStatusPPL();
			theApp.m_objMaxCommunicatorServer.SendResponse(sMaxPipeData);
			return;
		}
		else if(sMaxPipeData->eMessageInfo == UnRegister_WD_PPL)
		{
			CWatchDogService::SetWDServiceChangeStatus();
			theApp.m_objMaxCommunicatorServer.SendResponse(sMaxPipeData);
			return;
		}
		else if(sMaxPipeData->eMessageInfo == Start_LiveUpdate_process)
		{
			CExecuteProcess objExecProc;
			objExecProc.ShellExecuteEx(m_strAppPath + CString(L"\\")+ LIVEUPDATE_EXE, sMaxPipeData->strValue);
			return;
		}
		else if (sMaxPipeData->eMessageInfo == Install_Firewall_Setup)
		{
		
			CString csAppPath = m_strAppPath + CString(L"\\DriverMgr.exe");		
			CExecuteProcess oExecuteProcess;
			//oExecuteProcess.ExecuteCommandWithWait(csAppPath, L"-REINSTALL");	
			CMSIOperations oMSIOperations;
#ifdef WIN64				
			oMSIOperations.ExecuteFirewallSetup(CSystemInfo::m_strAppPath + L"\\FirewallSetupX64.exe");
#else					
			oMSIOperations.ExecuteFirewallSetup(CSystemInfo::m_strAppPath + L"\\FirewallSetup.exe");
#endif

			oMSIOperations.CreateAntiSpamSettingINIFile(CSystemInfo::m_strAppPath + L"\\Setting\\AntiSpamSetting.ini");
			
			oExecuteProcess.ExecuteCommandWithWait(csAppPath, L"-INSTALL");	
			DeleteFile(CSystemInfo::m_strSettingPath + L"FirewallLock.txt");
			//CreateFile(CSystemInfo::m_strSettingPath + L"FirewallLock.txt"), 0, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			theApp.m_objMaxCommunicatorServer.SendResponse(sMaxPipeData);
			return;
		}
		else if (sMaxPipeData->eMessageInfo == Uninstall_Firewall_Setup)
		{
			CString csAppPath = m_strAppPath + CString(L"\\DriverMgr.exe");		
			CExecuteProcess oExecuteProcess;
			
			oExecuteProcess.ExecuteCommandWithWait(csAppPath, L"-UNINSTALL");	
			DeleteFile(CSystemInfo::m_strSettingPath + L"FirewallLock.txt");
			//CreateFile(CSystemInfo::m_strSettingPath + L"FirewallLock.txt"), 0, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			theApp.m_objMaxCommunicatorServer.SendResponse(sMaxPipeData);
			return;
		}
		else if (sMaxPipeData->eMessageInfo == Install_Firewall)
		{
			return;
		}
		else if (sMaxPipeData->eMessageInfo == DeleteLocalDB)
		{
			theApp.CheckCleanLocalDB();
			return;
		}
		else if(sMaxPipeData->eMessageInfo == ChangeFilesLocalDBValue)
		{
			theApp.RemoveEntryFromLocalDB(sMaxPipeData->strValue);
			return;
		}
		else if (sMaxPipeData->eMessageInfo == GamingMode)
		{
			ULONG ulVal = sMaxPipeData->ulSpyNameID;
			theApp.SetGamingMode(ulVal);
			return;
		}
		else if (sMaxPipeData->eMessageInfo == Exit_Scanner)
		{
			CString csData = sMaxPipeData->szGUID;
			theApp.RemoveScannerID(csData);
			return;
		}
		else if (sMaxPipeData->eMessageInfo == SendGuid)
		{
			CString csData = sMaxPipeData->strValue;
			theApp.AddScannerID(csData);
			return;
		}
		else if(sMaxPipeData->eMessageInfo == SetProxySetting)
		{
			theApp.CopyProxySetting();
			return;
		}
		else if(sMaxPipeData->eMessageInfo == SetNativeScanSetting)
		{
			ULONG ulVal = sMaxPipeData->ulSpyNameID;
			return;
		}
		else if(sMaxPipeData->eMessageInfo == SetCopyPasteSetting)
		{
			DWORD dwVal = (DWORD)sMaxPipeData->ulSpyNameID;
			theApp.SetRegCopyPasteSetting(dwVal);
			return;
		}
		else if(sMaxPipeData->eMessageInfo == Enable_Replication)
		{
			DWORD dwVal = (DWORD)sMaxPipeData->ulSpyNameID;
			theApp.ReplicationSetting(dwVal);
			return;
		}
		else if(sMaxPipeData->eMessageInfo == RegisterPlugin)
		{
			CString csCommand = L"regsvr32 ";
			if(!sMaxPipeData->ulSpyNameID)
				csCommand += L"-u ";
			csCommand += L"-s \"";
			csCommand += theApp.m_strAppPath;
			csCommand += L"\\AuAntiSpam.dll\"";

			CStringA csCmd(csCommand);
			system(csCmd);

			return;
		}
		else if(sMaxPipeData->eMessageInfo == ResetProToIS)
		{
			theApp.ProductResetIS();
			return;
		}

	}

	CString csCommandLineParams;

	if(sMaxPipeData->sScanOptions.IsUSBScanner == 1)	// this is a USB scan request!
		csCommandLineParams += " /u";
	if(sMaxPipeData->sScanOptions.SignatureScan == 1)
		csCommandLineParams += " /s";
	if(sMaxPipeData->sScanOptions.VirusScan == 1)
		csCommandLineParams += " /v";
	if(sMaxPipeData->sScanOptions.RootkitScan == 1)
		csCommandLineParams += " /r";
	if(sMaxPipeData->sScanOptions.KeyLoggerScan == 1)
		csCommandLineParams += " /k";
	if(sMaxPipeData->sScanOptions.HeuristicScan == 1)
		csCommandLineParams += " /h";
	if(sMaxPipeData->sScanOptions.DBScan == 1)
		csCommandLineParams += " /d";
	if(sMaxPipeData->sScanOptions.RegFixOptionScan == 1)
		csCommandLineParams += " /o";
	if(sMaxPipeData->sScanOptions.RecoverSpyware == 1)
		csCommandLineParams += " /x";
	if(sMaxPipeData->sScanOptions.CustomScan == 1)
		csCommandLineParams += " /c";
	if(sMaxPipeData->sScanOptions.DeepScan == 1)
		csCommandLineParams += " /e";
	if(sMaxPipeData->sScanOptions.PluginScan == 1)
		csCommandLineParams += " /pl";
	if(sMaxPipeData->sScanOptions.AutoQuarantine == 1)	//to provide auto quarantine during command line scanner
	{
		csCommandLineParams += " /a";
	}
	if(_tcslen(sMaxPipeData->szGUID))
	{
		CString csData;
		csData.Format(L" /B:%s", sMaxPipeData->szGUID);
		csCommandLineParams += csData;
	}

	csCommandLineParams += " /DRIVES:";
	csCommandLineParams.Append(sMaxPipeData->strValue);

	//Reject Heuristic Scan Request if main scanner is running
	bool bLaunchScanner = true;
	if((sMaxPipeData->sScanOptions.IsUSBScanner == false) && ((sMaxPipeData->sScanOptions.DBScan == 1) || (sMaxPipeData->sScanOptions.CustomScan == 1)))
	{
		//Check if Heuristic Scan is running
		if(IsScannerRunning(eHeuristic,true))
		{
			int nTryCount = 0;
			while(nTryCount <= 3)
			{
				if(IsScannerRunning(eHeuristic))
				{
					Sleep(2000);
					nTryCount++;
				}
				else
				{
					break;
				}
			}
		}
		//Check if Any Existing Scanner is in a Hang state.Just Kill it!
		IsScannerRunning(eScanner1,true);
	}
	if(sMaxPipeData->sScanOptions.RegFixOptionScan == 1)
	{
		//Check if Any Existing Scanner is in a Hang state.Just Kill it!
		IsScannerRunning(eScanner2,true);
	}

	if(sMaxPipeData->sScanOptions.RecoverSpyware == 1)
	{
		//Check if Any Existing Scanner is in a Hang state.Just Kill it!
		IsScannerRunning(eScanner3,true);
	}

	if(sMaxPipeData->sScanOptions.PluginScan == 1)
	{
		//Check if Any Existing Scanner is in a Hang state.Just Kill it!
		IsScannerRunning(eOutlookPlugin,true);
	}

	if(bLaunchScanner)
	{
		CEnumProcess objEnumPRocess;
		CWatchDogServiceApp::LaunchScanner(static_cast<LPCTSTR>(csCommandLineParams));
		sMaxPipeData->eMessageInfo = Scanner_Is_Ready;
		theApp.m_objMaxCommunicatorServer.SendResponse(sMaxPipeData);
	}

	if(sMaxPipeData->sScanOptions.PluginScan == 1 && (CSystemInfo::m_strOS.Find(WVISTA) == -1) && (CSystemInfo::m_strOS.Find(WWIN8) == -1))
	{
		CExecuteProcess oExecuteProcess;
		AddLogEntry(_T(">>> Launching...%s"), CWatchDogServiceApp::m_strAppPath + CString(L"\\AuMailProxy.exe"));
		oExecuteProcess.RestoreEXE(CWatchDogServiceApp::m_strAppPath + CString(L"\\AuMailProxy.exe"), 0, true);
	}
}

/*--------------------------------------------------------------------------------------
Function       : LaunchScanner
In Parameters  : LPCTSTR szCommandline,
Out Parameters : bool
Description    : Launch Scanner once WD receive the request
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CWatchDogServiceApp::LaunchScanner(LPCTSTR szCommandline)
{
	CString csAppPath;
	CExecuteProcess objExecProc;

	csAppPath.Format(L"%s\\%s", m_strAppPath, MAX_SCANNER);
	AddLogEntry(_T(">>> Launching Scanner ...%s"), szCommandline);
	return objExecProc.ExecuteProcess(csAppPath, szCommandline, true);
}

/*--------------------------------------------------------------------------------------
Function       : IsScannerRunning
In Parameters  : int nProcessType, bool bPerformAction,
Out Parameters : bool
Description    : Iterates the WD list for registered processes and 
                 also perfom specified Action
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CWatchDogServiceApp::IsScannerRunning(int nProcessType, bool bPerformAction, bool bKillHeuristic)
{
	DisplayProcessMap();
	
	WaitForSingleObject(m_hSingleEventHandler, INFINITE);
	ProcessMapItem::iterator iter;
	for(iter = m_ProcessMapItem.begin(); iter != m_ProcessMapItem.end(); iter++)
	{
		MAX_WD_DATA wdItem = {0};
		wdItem = (*iter).second;
		if(wdItem.nProcessType == nProcessType)
		{
			if(bPerformAction)
			{
				if(((nProcessType >= eScanner1) && (nProcessType <= eScanner3)) || (nProcessType == eOutlookPlugin))
				{
					//Kill The Existing Scanner
					m_ProcessMapItem.erase(iter);
					CEnumProcess objEnumProc;
					objEnumProc.KillProcess(wdItem.dwProcessID);
					DisplayProcessMap();
					SetEvent(m_hSingleEventHandler);
					//ResumeIdleScan();
					return true;
				}
				else
				{
					//Currrently Used for Heuristics
					if(bKillHeuristic)
					{
						m_ProcessMapItem.erase(iter);
						CEnumProcess objEnumProc;
						objEnumProc.KillProcess(wdItem.dwProcessID);
						DisplayProcessMap();
						SetEvent(m_hSingleEventHandler);
						//ResumeIdleScan();
						return true;
					}
					MAX_PIPE_DATA sMaxPipeData={0};
					sMaxPipeData.eMessageInfo = wdItem.eActionMsgInfo;
					CMaxCommunicator objCom(wdItem.szActionPipeName);
					objCom.SendData(&sMaxPipeData,sizeof(MAX_PIPE_DATA));
				}
			}
			DisplayProcessMap();
			SetEvent(m_hSingleEventHandler);
			return true;
		}
	}
	DisplayProcessMap();
	SetEvent(m_hSingleEventHandler);
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : OnWatchDogStatusReceiveCallback
In Parameters  : LPVOID lpParam,
Out Parameters : void
Description    : Receives/Auto recevies the WD connection callbacks for detecting
				NamePipe closure
				Auto detection of Application crash as the named pipe returns 
				Broken pipe
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::OnWatchDogStatusReceiveCallback(LPVOID lpParam)
{
	WaitForSingleObject(m_hSingleEventHandler, INFINITE);
	LPMAX_WD_DATA lpMaxPipeData = (LPMAX_WD_DATA)lpParam;
	ProcessMapItem::iterator iter;

	MAX_WD_DATA sWDData = {0};
	if(lpMaxPipeData)
	{
		//Update or insert
		sWDData = (MAX_WD_DATA)*lpMaxPipeData;
		if(sWDData.eMessageInfo == Custom_Field1)
		{
			SetEvent(m_hSingleEventHandler);
			return;
		}
		if(lpMaxPipeData->nProcessType == eScanner1 || lpMaxPipeData->nProcessType == eUSBScanner)
		{
			//PauseIdleScan();
		}
		m_ProcessMapItem.insert(ProcessMapItem::value_type(GetCurrentThreadId(), (MAX_WD_DATA)*lpMaxPipeData));
	}
	else
	{
		DisplayProcessMap();
		iter = m_ProcessMapItem.find(GetCurrentThreadId());
		if(iter != m_ProcessMapItem.end())
		{
			sWDData = (*iter).second;
			m_ProcessMapItem.erase(GetCurrentThreadId());
			sWDData.eMessageInfo = WD_AppCrashed;

			SetEvent(m_hSingleEventHandler);
			//ResumeIdleScan();
		}
		else
		{
			DisplayProcessMap();
			SetEvent(m_hSingleEventHandler);
			return;
		}
	}
	DisplayProcessMap();

	switch(sWDData.eMessageInfo)
	{
	case WD_StartingApp:
		{
		}
		break;
	case WD_StoppingApp:
		{
			iter = m_ProcessMapItem.find(GetCurrentThreadId());
			if(iter != m_ProcessMapItem.end())
			{
				sWDData = (*iter).second;
				m_ProcessMapItem.erase(GetCurrentThreadId());
				//CString csTemp;
				CEnumProcess objEnum;
				if(objEnum.KillProcess(sWDData.dwProcessID))
				{
				}
				SetEvent(m_hSingleEventHandler);
				//ResumeIdleScan();
			}
		}
		break;
	case WD_AppCrashed:
		HandleCrashEvent(sWDData);
		break;
	case WD_RestartAfterShutdown:
		{
			CEnumProcess objEnumRocess;
			if(objEnumRocess.IsProcessRunning(L"AuActMon.exe",false,false) == false)
			{
				CExecuteProcess objExecProc;
				if(objExecProc.ExecuteCommand(m_strAppPath + CString(L"\\AuActMon.exe"), L""))
				{
				}
			}
			m_bShutDown = false;
		}
		break;
	case WD_StartSD:
		{
			CEnumProcess oEnumProcess;
			if(!oEnumProcess.IsProcessRunning(UI_EXENAME, false, false, false))
			{
				LaunchGUIApp((CString)m_strAppPath + _T("\\") + (CString)UI_EXENAME, _T("-AUTOSCAN"));
			}
		}
		break;
	case WD_ShutdownSD:
		{
			m_bShutDown = true;
			m_ProcessMapItem.clear();
			CEnumProcess objEnumPRocess;
			objEnumPRocess.IsProcessRunning(LIVEUPDATE_EXE, true, false);
			objEnumPRocess.IsProcessRunning(UI_EXENAME, true, false);
			objEnumPRocess.IsProcessRunning(MAX_SCANNER, true, false);
			objEnumPRocess.IsProcessRunning(MAX_DSRV, true, false);

		}
		break;
	case TerminateCMDScanner:
		
		break;
	default:
		break;
	}
	DisplayProcessMap();
	SetEvent(m_hSingleEventHandler);
}

/*--------------------------------------------------------------------------------------
Function       : HandleCrashEvent
In Parameters  : MAX_WD_DATA &sWDData,
Out Parameters : void
Description    : Once WD detects that its a crash of the monitoring process
Registerd action is performed to handle the crash.
WD uses the registered list and send specific message to the designated
application/pipe
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::HandleCrashEvent(MAX_WD_DATA &sWDData)
{
	MAX_PIPE_DATA sMaxPipeData={0};
	if(sWDData.szProcessName)
	{
		AddLogEntry(_T(">>> SD Process Crashed!!!...%s"), sWDData.szProcessName);
	}

	bool bNotify = false;
	bool bServiceRestart = false;
	bool bProcessRestart = false;
	switch(sWDData.nAction)
	{
	case NOTIFY_PIPE:
		bNotify = true;
		break;
	case RESTART_PROCESS:
		bProcessRestart = true;
		break;
	case RESTART_SERVICE:
		bServiceRestart = true;
		break;
	default:
		break;
	}

	if(bNotify)
	{
		sMaxPipeData.eMessageInfo = sWDData.eActionMsgInfo;
		//Will be sending NULL if No Notify is required
		if(sWDData.szActionPipeName)
		{
			CMaxCommunicator objCom(sWDData.szActionPipeName);
			objCom.SendData(&sMaxPipeData,sizeof(MAX_PIPE_DATA));
		}
	}
	if(bProcessRestart)
	{
		CExecuteProcess objExecProc;
		TCHAR lpCommandLine[MAX_PATH] = {0};
		switch(sWDData.nProcessType)
		{
		case eActMon:
			objExecProc.ExecuteCommand(m_strAppPath + CString(L"\\AuActMon.exe"),_T("-Restart"));
			break;
		case eTrayID:
			LaunchGUIApp(m_strAppPath + CString(L"\\AuTray.exe"), _T("-NOSPL"));
			break;
		case eScanner2://Option Reg Fix Crashed
			_tcscpy_s(lpCommandLine,MAX_PATH,_T("/o /DRIVES:"));
			CWatchDogServiceApp::LaunchScanner(static_cast<LPCTSTR>(lpCommandLine));
			break;
		case eScanner3://Recovery crashed
			_tcscpy_s(lpCommandLine,MAX_PATH,_T("/x /DRIVES:"));
			CWatchDogServiceApp::LaunchScanner(static_cast<LPCTSTR>(lpCommandLine));
			break;
		case eOutlookPlugin:
			swprintf_s(lpCommandLine,MAX_PATH, _T("/PL /B:%s /DRIVES:"), _NAMED_PIPE_SCANNER_TO_PLUGIN);
			CWatchDogServiceApp::LaunchScanner(static_cast<LPCTSTR>(lpCommandLine));
			break;
		case eMaxDBServer:
			AddLogEntry(_T(">>> Launching...%s"), m_strAppPath + CString(L"\\AuDBServer.exe"));
			objExecProc.RestoreEXE(m_strAppPath + CString(L"\\AuDBServer.exe"), 0, true);
			break;
		case eMailProxy:
			if((CSystemInfo::m_strOS.Find(WVISTA) == -1) && (CSystemInfo::m_strOS.Find(WWIN8) == -1))
			{
				AddLogEntry(_T(">>> Launching...%s"), m_strAppPath + CString(L"\\AuMailProxy.exe"));
				objExecProc.RestoreEXE(m_strAppPath + CString(L"\\AuMailProxy.exe"), 0, true);
			}
			break;
		}
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetFilePathFromRegData
In Parameters	: LPCTSTR szRegData, CString& csFilePath
Out Parameters	: bool
Purpose			: get file path from given reg data read from run registry values
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool GetFilePathFromRegData(LPCTSTR szRegData, CString& csFilePath)
{
	bool bFilePathFound = false;
	TCHAR szFilePath[MAX_PATH] = {0};
	LPCTSTR Ptr = NULL, StartPtr = NULL, EndPtr = NULL;

	if(Ptr = _tcsstr(szRegData, _T("rundll32.exe\"")))
	{
		Ptr += _tcslen(_T("rundll32.exe\""));
	}
	else if(Ptr = _tcsstr(szRegData, _T("rundll32.exe")))
	{
		Ptr += _tcslen(_T("rundll32.exe"));
	}
	else if(Ptr = _tcsstr(szRegData, _T("rundll32\"")))
	{
		Ptr += _tcslen(_T("rundll32\""));
	}
	else if(Ptr = _tcsstr(szRegData, _T("rundll32")))
	{
		Ptr += _tcslen(_T("rundll32"));
	}
	else
	{
		Ptr = szRegData;
	}

	for(; Ptr && *Ptr; Ptr++)
	{
		if(NULL == StartPtr)
		{
			if((_T(' ') != *Ptr) && (_T('"') != *Ptr))
			{
				StartPtr = Ptr;
			}
		}
		else
		{
			if(_T('"') == *Ptr)
			{
				EndPtr = Ptr;
				break;
			}
			else if(!_tcsnicmp(Ptr, _T(".exe"),4)||!_tcsnicmp(Ptr, _T(".com"),4)||!_tcsnicmp(Ptr, _T(".scr"),4))
			{
				EndPtr = Ptr + 4;
				break;
			}
		}
	}

	if(!StartPtr || !EndPtr || StartPtr >= EndPtr)
	{
		return bFilePathFound;
	}

	if(EndPtr - StartPtr >= _countof(szFilePath))
	{
		return bFilePathFound;
	}

	_tcsncpy_s(szFilePath, _countof(szFilePath), StartPtr, EndPtr - StartPtr);

	if(_tcsrchr(szFilePath, _T('.')))
	{
		LPTSTR DotPtr = _tcsrchr(szFilePath, _T('.'));
		if(!_tcsnicmp(DotPtr, _T(".exe"), 4))
		{
			DotPtr [ 4 ] = 0;
		}
	}

	if(!_tcschr(szFilePath, _T('\\')))
	{
		_tsearchenv_s(szFilePath, _T("PATH"), szFilePath, _countof(szFilePath));
	}

	csFilePath = szFilePath;
	bFilePathFound = true;
	return bFilePathFound;
}

/*-------------------------------------------------------------------------------------
Function		: CheckInvalidRunEntry
In Parameters	: HKEY hHive, LPCTSTR szMainKey
Out Parameters	: bool
Purpose			: Remove invalid run entries from given hive
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CheckInvalidRunEntry(HKEY hHive, LPCTSTR szMainKey)
{
	CString csFilePath;
	CRegistry objRegistry;
	bool bFoundInvalidEntry = false, bSkip = false;
	CStringArray csArrValues, csArrData;
	CStringArray csArrExcludeValues, csArrExcludeData;

	csArrExcludeValues.Add(_T("ldm"));
	csArrExcludeValues.Add(_T("loadpowerprofile"));

	csArrExcludeData.Add(_T("http:"));
	csArrExcludeData.Add(_T("www"));

	if(!objRegistry.QueryDataValue(szMainKey, csArrValues, csArrData, hHive))
	{
		return bFoundInvalidEntry;
	}

	for(INT_PTR i = 0, iTotal = csArrValues.GetCount(); i < iTotal; i++)
	{
		bSkip = false;
		csArrData[i].MakeLower();
		csArrValues[i].MakeLower();

		for(INT_PTR j = 0, jTotal = csArrExcludeValues.GetCount(); !bSkip && j < jTotal; j++)
		{
			if(0 == csArrExcludeValues[j].CompareNoCase(csArrValues[i]))
			{
				bSkip = true;
			}
		}

		for(INT_PTR k = 0, kTotal = csArrExcludeData.GetCount(); !bSkip && k < kTotal; k++)
		{
			if(-1 != csArrData[i].Find(csArrExcludeData[k]))
			{
				bSkip = true;
			}
		}

		if(!bSkip)
		{
			if(GetFilePathFromRegData(csArrData[i], csFilePath))
			{
				if(_taccess_s(csFilePath, 0))
				{
					CString csReportString;
					csReportString.Format(_T("Invalid Run Entry: %s\\%s - %s - %s"),
											objRegistry.GetHiveName(hHive), szMainKey,
											csArrValues[i], csArrData[i]);
					AddLogEntry(csReportString);
					objRegistry.DeleteValue(szMainKey, csArrValues[i], hHive);
				}
			}
		}
	}

	return bFoundInvalidEntry;
}

/*-------------------------------------------------------------------------------------
Function		: RestoreSystemDefaultsThread
In Parameters	: LPVOID lpParam
Out Parameters	: UINT
Purpose			: Restore default system values if corrupted, remove invalid run entries
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
UINT RestoreSystemDefaultsThread(LPVOID lpParam)
{
	CRegistry objReg;
	CString csSubKey;
	CString csData = CSystemInfo::m_strSysDir + _T("\\userinit.exe,");

	if(CSystemInfo::m_strOS == WME || CSystemInfo::m_strOS == W98)
	{
		return 0;
	}

	/*
	commented from here as doing this from service is late. now this will be done from driver.

	objReg.Set(WINLOGON_REG_KEY, _T("Shell"), _T("Explorer.exe"), HKEY_LOCAL_MACHINE);
	objReg.Set(WINLOGON_REG_KEY, _T("Userinit"), csData, HKEY_LOCAL_MACHINE);
#ifdef WIN64
	objReg.Set(WINLOGON_REG_KEY_X64, _T("Shell"), _T("Explorer.exe"), HKEY_LOCAL_MACHINE);
	objReg.Set(WINLOGON_REG_KEY_X64, _T("Userinit"), csData, HKEY_LOCAL_MACHINE);
#endif
	*/

	csData = _T("");
	csSubKey = _T("SOFTWARE\\Classes\\.exe");
	objReg.Get(csSubKey, _T(""), csData, HKEY_LOCAL_MACHINE);
	if(csData.MakeLower() != _T("exefile"))
	{
		CString csFile = CSystemInfo::m_strAppPath + _T("Setting\\exe.dat");
		objReg.RestoreRegKeyPath(HKEY_LOCAL_MACHINE, csSubKey, csFile);
		AddLogEntry(L"Invalid data for HKLM\\SOFTWARE\\Classes\\.exe found: %s", csData);
	}

#ifdef WIN64
	csData = _T("");
	csSubKey = _T("SOFTWARE\\Wow6432Node\\Classes\\.exe");
	objReg.Get(csSubKey, _T(""), csData, HKEY_LOCAL_MACHINE);
	if(csData.MakeLower() != _T("exefile"))
	{
		CString csFile = CSystemInfo::m_strAppPath + _T("Setting\\exe.dat");
		objReg.RestoreRegKeyPath(HKEY_LOCAL_MACHINE, csSubKey, csFile);
		AddLogEntry(L"Invalid data for HKLM\\SOFTWARE\\Wow6432Node\\Classes\\.exe found: %s", csData);
	}
#endif

	csData = _T("");
	csSubKey = _T("SOFTWARE\\Classes\\exefile\\shell\\open\\command");
	objReg.Get(csSubKey, _T(""), csData, HKEY_LOCAL_MACHINE);
	if(csData.MakeLower() != _T("\"%1\" %*"))
	{
		csSubKey = _T("SOFTWARE\\Classes\\exefile");
		CString csFile = CSystemInfo::m_strAppPath + _T("Setting\\exefile.dat");
		objReg.RestoreRegKeyPath(HKEY_LOCAL_MACHINE, csSubKey, csFile);
		AddLogEntry(L"Invalid data HKLM\\SOFTWARE\\Classes\\exefile\\shell\\open\\command found: %s", csData);
	}

#ifdef WIN64
	csData = _T("");
	csSubKey = _T("SOFTWARE\\Wow6432Node\\Classes\\exefile\\shell\\open\\command");
	objReg.Get(csSubKey, _T(""), csData, HKEY_LOCAL_MACHINE);
	if(csData.MakeLower() != _T("\"%1\" %*"))
	{
		csSubKey = _T("SOFTWARE\\Wow6432Node\\Classes\\exefile");
		CString csFile = CSystemInfo::m_strAppPath + _T("Setting\\exefile.dat");
		objReg.RestoreRegKeyPath(HKEY_LOCAL_MACHINE, csSubKey, csFile);
		AddLogEntry(L"Invalid data HKLM\\SOFTWARE\\Wow6432Node\\Classes\\exefile\\shell\\open\\command found: %s", csData);
	}
#endif



	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: SchedulerThread
In Parameters	: LPVOID lpParam
Out Parameters	: UINT
Purpose			: Thread to check schedule time and start the application for scanning
Author			: 
--------------------------------------------------------------------------------------*/
UINT SchedulerThread(LPVOID lpParam)
{
	HANDLE hEvent = NULL;
	hEvent=CreateEvent(NULL,TRUE,FALSE,NULL);
	if(INVALID_HANDLE_VALUE == hEvent || NULL == hEvent)
		return 0;
	CRegKey objRegKey;
	CRegistry objReg;
	while(true)
	{
		WaitForSingleObject(hEvent, 58000);
		if(objRegKey.Open(HKEY_LOCAL_MACHINE, CSystemInfo::m_csSchedulerRegKey) == ERROR_SUCCESS)
		{
			objRegKey.Close();
			CheckScheduleTime();
		}
	}
	return 0;
}


//enum enScheduleType
//{
//	DAILYSCAN=8,
//	HOURLYSCAN,
//	MINUTESSCAN
//};

/*-------------------------------------------------------------------------------------
Function		: CheckScheduleTime
In Parameters	: -
Out Parameters	: void
Purpose			: This will check schedule time and day from registry
with current date and time and if matches it will start the application
Author			: 
--------------------------------------------------------------------------------------*/
void CheckScheduleTime()
{
	try
	{
		CTime curTime;
		CRegistry objReg;
		DWORD dwMTSLaunch = 0;
		CStringArray objValArr;
		objValArr.RemoveAll();
		CString csSchedulerRegKey;
		csSchedulerRegKey = CSystemInfo::m_csSchedulerRegKey;

		objReg.EnumValues(csSchedulerRegKey, objValArr, HKEY_LOCAL_MACHINE);
		if(objValArr.GetCount()< 4)
			return;

		{
			CString csTime;
			objReg.Get(csSchedulerRegKey, _T("Time"),csTime, HKEY_LOCAL_MACHINE);
			if(csTime.IsEmpty())
				return;
			int i=0;
			int hr  = _wtoi(csTime.Tokenize(_T(":"),i).Trim());
			int min = _wtoi(csTime.Tokenize(BLANKSTRING,i).Trim());

			curTime = CTime::GetCurrentTime();

			CString csDate;
			csDate.Format (_T("%d/%d/%d"),curTime.GetMonth(),curTime.GetDay(),curTime.GetYear());

			CString csLastSchDate;
			objReg.Get(csSchedulerRegKey, LASTSCANDATE,csLastSchDate, HKEY_LOCAL_MACHINE);

			DWORD dwScanOpt = 0;
			objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("ScanOption"), dwScanOpt, HKEY_LOCAL_MACHINE);
			CString csScanOpt =_T("");
			if (dwScanOpt == 0)
			{
				csScanOpt.Format(_T("%sQUICK"), SCHEDULAR_PARAM);
			}
			else if (dwScanOpt == 1)
			{
				csScanOpt.Format(_T("%sFULL"), SCHEDULAR_PARAM);
			}
			if (csScanOpt.IsEmpty())
			{
				return;
			}
			DWORD dwDay = 0;
			objReg.Get(csSchedulerRegKey, _T("Day"),dwDay, HKEY_LOCAL_MACHINE);

			CExecuteProcess objExecuteProcess;
			if((dwDay == DAILYSCAN) || (dwDay == curTime.GetDayOfWeek()))
			{
				if(csLastSchDate == csDate)
					return;

				if((hr < curTime.GetHour()))
				{
					CString csFileName;
					csFileName.Format(_T("%s\\%s"), static_cast<LPCTSTR>(CWatchDogServiceApp::m_strAppPath), UI_EXENAME);
					AddLogEntry(_T(" >>> Starting Scheduled Scan"));
					theApp.LaunchGUIApp(csFileName, csScanOpt);
					objReg.Set(csSchedulerRegKey, LASTSCANDATE, csDate, HKEY_LOCAL_MACHINE);
				}
				else if((hr == curTime.GetHour()) && (min <= curTime.GetMinute()))
				{
					CString csFileName;
					csFileName.Format(_T("%s\\%s"), static_cast<LPCTSTR>(CWatchDogServiceApp::m_strAppPath), UI_EXENAME);
					AddLogEntry(_T(">>> Starting Scheduled Scan"));
					theApp.LaunchGUIApp(csFileName, csScanOpt);
					objReg.Set(csSchedulerRegKey, LASTSCANDATE, csDate, HKEY_LOCAL_MACHINE);
				}
			}
			else if(dwDay == HOURLYSCAN || dwDay == MINUTESSCAN)
			{
				objReg.Get(csSchedulerRegKey, _T("NextScheduleTime"),csTime, HKEY_LOCAL_MACHINE);
				if(csTime.IsEmpty())
					return;

				i=0;
				hr		=	_wtoi(csTime.Tokenize(_T(":"),i).Trim());
				min		=	_wtoi(csTime.Tokenize(_T(":"),i).Trim());
				int day		=	_wtoi(csTime.Tokenize(_T(":"),i).Trim());
				int month	=	_wtoi(csTime.Tokenize(_T(":"),i).Trim());
				int year	=	_wtoi(csTime.Tokenize(BLANKSTRING,i).Trim());

				CTime NextSchTime(year, month, day, hr, min, 0);
				CString csNewTime = BLANKSTRING;

				DWORD dwHrsOrMins = 0;
				objReg.Get(csSchedulerRegKey, _T("HoursOrMins"),dwHrsOrMins, HKEY_LOCAL_MACHINE);

				int hrTimeSpan=0;
				int minTimeSpan=0;

				if(dwDay == HOURLYSCAN)
					hrTimeSpan=(int)dwHrsOrMins;
				else
					minTimeSpan=(int)dwHrsOrMins*10;

				CTimeSpan timespan(0, hrTimeSpan,minTimeSpan,0);
				if (NextSchTime <= curTime)
				{
					CString csFileName;
					CEnumProcess objEnumProc;
					csFileName.Format(_T("%s\\%s"), static_cast<LPCTSTR>(CWatchDogServiceApp::m_strAppPath), UI_EXENAME);
					AddLogEntry(_T(">>> Starting Scheduled Scan"));
					theApp.LaunchGUIApp(csFileName, csScanOpt);

					NextSchTime = curTime + timespan;
					csNewTime.Format(_T("%d:%d:%d:%d:%d"), NextSchTime.GetHour(), NextSchTime.GetMinute(), NextSchTime.GetDay(), NextSchTime.GetMonth(), NextSchTime.GetYear());
					objReg.Set(csSchedulerRegKey, _T("NextScheduleTime"), csNewTime, HKEY_LOCAL_MACHINE);
				}
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CheckScheduleTime"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: AutoScanThread
In Parameters	: LPVOID lpParam
Out Parameters	: UINT
Purpose			: Thread for Auto Scanning for unregister user
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
UINT SetupAutoLaunchThread(LPVOID lpParam)
{
	CRegistry objReg;
	DWORD dwLaunch = 0;
	DWORD dwLaunchReg = 0;
	CString csFileName;
	
	objReg.Get(CSystemInfo::m_csProductRegKey,_T("SetupLaunch"), dwLaunch, HKEY_LOCAL_MACHINE);
	objReg.Get(CSystemInfo::m_csProductRegKey,_T("SetupLaunchReg"), dwLaunchReg, HKEY_LOCAL_MACHINE);
	
	if(dwLaunchReg)
	{
		CWatchDogServiceApp::DeleteAppCompatFlagsValues();
		csFileName.Format(_T("%s\\%s"), static_cast<LPCTSTR>(CWatchDogServiceApp::m_strAppPath), UI_EXENAME);
		dwLaunchReg = 0;

		CEnumProcess oEnumProcess;
		if(!oEnumProcess.IsProcessRunning(UI_EXENAME, false, false, false))
		{
			theApp.LaunchGUIApp(csFileName, _T("-SETUPLAUNCH"));
		}

		//theApp.LaunchGUIApp(csFileName, _T(""));
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("SetupLaunchReg"), dwLaunch, HKEY_LOCAL_MACHINE);
	
		COleDateTime objOleDateTime;
		objOleDateTime = objOleDateTime.GetCurrentTime();
		CString csDate;
		csDate.Format (_T("%d/%d/%d"), objOleDateTime.GetMonth(),objOleDateTime.GetDay(),objOleDateTime.GetYear());
		
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoScanTime"), csDate, HKEY_LOCAL_MACHINE);

	}
	else if(dwLaunch)
	{
		CWatchDogServiceApp::DeleteAppCompatFlagsValues();
		csFileName.Format(_T("%s\\%s"), static_cast<LPCTSTR>(CWatchDogServiceApp::m_strAppPath), UI_EXENAME);
		dwLaunch = 0;

		CEnumProcess oEnumProcess;
		if(!oEnumProcess.IsProcessRunning(UI_EXENAME, false, false, false))
		{
			theApp.LaunchGUIApp(csFileName, _T("-AUTOSCAN"));
		}
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("SetupLaunch"), dwLaunch, HKEY_LOCAL_MACHINE);
	
		COleDateTime objOleDateTime;
		objOleDateTime = objOleDateTime.GetCurrentTime();
		CString csDate;
		csDate.Format (_T("%d/%d/%d"), objOleDateTime.GetMonth(),objOleDateTime.GetDay(),objOleDateTime.GetYear());
		
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoScanTime"), csDate, HKEY_LOCAL_MACHINE);

	}
	return 0;
}
/*-------------------------------------------------------------------------------------
Function		: AutoScanThread
In Parameters	: LPVOID lpParam
Out Parameters	: UINT
Purpose			: Thread for Auto Scanning for unregister user
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
UINT AutoScanThread(LPVOID lpParam)
{
	CRegistry objReg;
	int iSchedule = 0;
	while(true)
	{
		HKEY hKey = NULL;
		if(objReg.Open(CSystemInfo::m_csSchedulerRegKey,hKey,HKEY_LOCAL_MACHINE))
		{
			objReg.CloseKey(hKey);
			iSchedule = 1;
		}
		DWORD dwDay = 0;
		objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("Day"), dwDay, HKEY_LOCAL_MACHINE);

		if(dwDay != 0 && dwDay != 8)
			iSchedule = 1;
		DWORD dwAScan = 0;
		objReg.Get(CSystemInfo::m_csProductRegKey, AUAUTOSCAN, dwAScan, HKEY_LOCAL_MACHINE);
		
		DWORD dwEval = 0;
		objReg.Get(CSystemInfo::m_csProductRegKey,QUARANTINECNT, dwEval, HKEY_LOCAL_MACHINE);

		if(dwEval == 0)
			g_iRegister = 1;

		DWORD dwLaunch;
		objReg.Get(CSystemInfo::m_csProductRegKey,_T("SetupLaunch"), dwLaunch, HKEY_LOCAL_MACHINE);

		if(g_iRegister == 0 && dwAScan == 0 && iSchedule  == 0 && dwLaunch == 0)
		{
			COleDateTime objOleDateTime;
			objOleDateTime = objOleDateTime.GetCurrentTime();
			CString csDate;
			csDate.Format (_T("%d/%d/%d"), objOleDateTime.GetMonth(),objOleDateTime.GetDay(),objOleDateTime.GetYear());

			CString csLastCheckDate;
			objReg.Get(CSystemInfo::m_csProductRegKey,_T("AutoScanTime"), csLastCheckDate, HKEY_LOCAL_MACHINE);

			if(csLastCheckDate != csDate)
			{
				CString csFileName;
				csFileName.Format(_T("%s\\%s"), static_cast<LPCTSTR>(CWatchDogServiceApp::m_strAppPath), UI_EXENAME);

				CEnumProcess oEnumProcess;
				if(!oEnumProcess.IsProcessRunning(UI_EXENAME, false, false, false))
				{
					theApp.LaunchGUIApp(csFileName, _T("-AUTOSCAN"));
				}
				objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoScanTime"), csDate, HKEY_LOCAL_MACHINE);
			}
		
			dwEval = 0;
			objReg.Get(CSystemInfo::m_csProductRegKey, QUARANTINECNT, dwEval, HKEY_LOCAL_MACHINE);

			if(dwEval == 0)
				g_iRegister = 1;
		}
		if(dwAScan == 1 && dwLaunch == 0)
		{
			{
				//Sleep for 5 mins
				int iMins = 5;
				
				Sleep(iMins * 60 * 1000);			
			}
			
			CEnumProcess objEnumProcess;
			for(int iWait = 0; iWait < 240; iWait++)
			{
				if((objEnumProcess.IsProcessRunning(EXPLORE_EXE, false, false)))
				{
					Sleep(1000);
					break;
				}
				Sleep(1000);
			}
			Sleep(5000);
			COleDateTime objOleDateTime;
			objOleDateTime = objOleDateTime.GetCurrentTime();
			CString csDate;
			csDate.Format (_T("%d/%d/%d"), objOleDateTime.GetMonth(),objOleDateTime.GetDay(),objOleDateTime.GetYear());

			CString csLastCheckDate;
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("AutoScanTime"), csLastCheckDate, HKEY_LOCAL_MACHINE);
			
			if(csLastCheckDate != csDate)
			{
				CString csFileName;
				csFileName.Format(_T("%s\\%s"), static_cast<LPCTSTR>(CWatchDogServiceApp::m_strAppPath), UI_EXENAME);
				CEnumProcess oEnumProcess;
				if(!oEnumProcess.IsProcessRunning(UI_EXENAME, false, false, false))
				{
					theApp.LaunchGUIApp(csFileName, _T("-AUTOSCAN"));
				}
			}
			else
			{
				csDate = _T("");
				csDate.Format (_T("%d/%d/%d"), objOleDateTime.GetMonth(), objOleDateTime.GetDay() - 1, objOleDateTime.GetYear());
				objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoScanTime"), csDate, HKEY_LOCAL_MACHINE);
			}
		}
		Sleep(24*60*60*1000);
	}
	return 0;
}

time_t GetCurrentDateTime()
{
	time_t nTime = 0;
	time(&nTime);
	return nTime;
}

/*-------------------------------------------------------------------------------------
Function		: CheckForUpdate
In Parameters	: -
Out Parameters	: BOOL
Purpose			: To Check For Update.Get Serverversion.txt and compare serverversion with client version.
				  If Checkversion returns true start the liveupdate or prompt the user
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool DoLiveUpdateActivity(LUACT eLUActivity)
{
	DWORD dwEval = 0;
	CEnumProcess objEnumRocess;
	CRegistry oReg;
	CSystemInfo objSysInfo;
	CString	csLiveUpdateExePath = (CString)CWatchDogServiceApp::m_strAppPath + _T("\\") + (CString)LIVEUPDATE_EXE;
	CExecuteProcess objExecuteProcess;

	oReg.Get(objSysInfo.m_csProductRegKey, QUARANTINECNT, dwEval, HKEY_LOCAL_MACHINE);
	if(0 != dwEval)
	{
		if(eLUActivity == LU_DoBackGroundLU)
		{
			return false;
		}
	}
	
	if(objEnumRocess.IsProcessRunning(csLiveUpdateExePath, false))
	{
		return false;
	}

	if(LU_ShowLUMessage == eLUActivity)
	{
		CString csCnt;
		GetPrivateProfileString(SUMMARY,WORMCOUNTS,BLANKSTRING,csCnt.GetBuffer(MAX_PATH),MAX_PATH,(CString)CWatchDogServiceApp::m_strAppPath + _T("\\") + (CString)WORMSCOUNTINI);
		csCnt.ReleaseBuffer();
		CString csAppPath;
		csAppPath = (CString)CWatchDogServiceApp::m_strAppPath + _T("\\") + (CString)ACT_MON_TRAY_EXE;
		CString csParam(_T("-"));
		csParam += CSystemInfo::m_csProductName;
		csParam = csParam + _T(";") + csLiveUpdateExePath + _T(";LIVEUPDATE;") + csCnt + _T(";HYPERLINKFALSE");
		theApp.LaunchGUIApp(csAppPath, csParam);
	}
	else
	if(LU_DoBackGroundLU == eLUActivity)
	{
		objExecuteProcess.ShellExecuteExW(csLiveUpdateExePath, L"-Auto");
	}
	else
	if(LU_DownloadSigDB == eLUActivity)
	{
		objExecuteProcess.ShellExecuteExW(csLiveUpdateExePath, L"-EPMD5UPDATE");
	}
	else
	if(LU_DownloadDBPatch == eLUActivity)
	{
		objExecuteProcess.ShellExecuteExW(csLiveUpdateExePath, L"-AUTODATABASEPATCH");
	}
	else
	if(LU_DownloadProductPatch == eLUActivity)
	{
		objExecuteProcess.ShellExecuteExW(csLiveUpdateExePath, L"-AUTOPRODUCTPATCH");
	}
	else
	{
		return false;
	}

	return true;
}

DWORD GetElapsedHours(ULONG64 ulCurTime, ULONG64 ulLastTime)
{
	ULONG64 ulDiffInSecs = 0;
	DWORD dwElapsedHours = 0;

	if(0 == ulCurTime || 0 == ulLastTime)
	{
		return dwElapsedHours;
	}

	if(ulCurTime <= ulLastTime)
	{
		return dwElapsedHours;
	}

	ulDiffInSecs = ulCurTime - ulLastTime;
	dwElapsedHours = (DWORD)(ulDiffInSecs / (60 * 60));
	return dwElapsedHours;
}

/*-------------------------------------------------------------------------------------
Function		: LiveupdateThread
In Parameters	: LPVOID lpParam
Out Parameters	: UINT
Purpose			: Thread for Live Update.
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
UINT LiveupdateThread(LPVOID lpParam)
{
	DWORD dwOneSecond = 1000;
	DWORD dwOneMinute = 60 * dwOneSecond;
	DWORD dwOneHour = 60 * dwOneMinute;

	CRegistry objReg;
	DWORD dwDownloadDBPatch = 0, dwEval = 0, dwDownloadSigDB = 0;
	DWORD dwDelay = 0, dwAutoLUDoneOnce = 0, dwAutoLU = 0, dwAutoLUReminder = 0, dwElapsedHours = 0, dwDelayCheck = 0;
	CSystemInfo objSysInfo;
	CEnumProcess objEnum;
	bool bFirstRun = true, bAutoLUDone = false;
	ULONG64 ulALU_Last = 0, ulLUMSG_Last = 0, ulCurTime = 0;

	objReg.Get(objSysInfo.m_csProductRegKey, AUTO_UPDATE_DELAY, dwDelay, HKEY_LOCAL_MACHINE);
	//dwDelay = 0 == dwDelay? 6: dwDelay;
	dwDelay = 4;
	
	//Ravi: delay after system restart or watchdog service restart for Auto Liveupdate
	//Sleep(dwOneHour);
	//Ravindra : As told by mam Auto live update should check after 15 min : Date :31 March 2015
	Sleep(dwOneMinute * 7);

	while(true)
	{
		//AddLogEntry(_T("````````````````Waiting to check..."), 0, 0, true);
		Sleep(8 * dwOneMinute);

		ulALU_Last = ulLUMSG_Last = 0;
		dwEval = dwAutoLUDoneOnce = dwAutoLU = dwAutoLUReminder = dwDownloadSigDB = 0;

		//AddLogEntry(_T("````````````````Reading registry values..."), 0, 0, true);
		//objReg.Get(objSysInfo.m_csProductRegKey, QUARANTINECNT, dwEval, HKEY_LOCAL_MACHINE);
		objReg.Get(objSysInfo.m_csProductRegKey, _T("AutoLUDoneOnce"), dwAutoLUDoneOnce, HKEY_LOCAL_MACHINE);
		objReg.Get(objSysInfo.m_csProductRegKey, _T("AutoLiveupdate"), dwAutoLU, HKEY_LOCAL_MACHINE);
		objReg.Get(objSysInfo.m_csProductRegKey, _T("AutoLiveupdateOff"), dwAutoLUReminder, HKEY_LOCAL_MACHINE);
		objReg.Get(objSysInfo.m_csProductRegKey, _T("ALU_Last"), REG_BINARY, (LPBYTE)&ulALU_Last, sizeof(ulALU_Last), HKEY_LOCAL_MACHINE);
		objReg.Get(objSysInfo.m_csProductRegKey, _T("LUMSG_Last"), REG_BINARY, (LPBYTE)&ulLUMSG_Last, sizeof(ulLUMSG_Last), HKEY_LOCAL_MACHINE);
		objReg.Get(objSysInfo.m_csProductRegKey, _T("EPMD5UPDATE"), dwDownloadSigDB, HKEY_LOCAL_MACHINE);
		objReg.Get(objSysInfo.m_csProductRegKey, _T("AutoDatabasePatch"), dwDownloadDBPatch, HKEY_LOCAL_MACHINE);
		_time64((__time64_t*)&ulCurTime);

		if(1 == dwDownloadSigDB)
		{
			DoLiveUpdateActivity(LU_DownloadSigDB);
		}
		else
		if(1 == dwDownloadDBPatch)
		{
			DoLiveUpdateActivity(LU_DownloadDBPatch);
		}
		else	
		// 17-Jul-2013
		if(0 == dwAutoLUDoneOnce)
		{
			DoLiveUpdateActivity(LU_DoBackGroundLU);
			dwAutoLUDoneOnce = 1;
			objReg.Set(objSysInfo.m_csProductRegKey, _T("AutoLUDoneOnce"), dwAutoLUDoneOnce, HKEY_LOCAL_MACHINE);
			objReg.Set(objSysInfo.m_csProductRegKey, _T("ALU_Last"), (LPBYTE)&ulCurTime, sizeof(ulCurTime), REG_BINARY, HKEY_LOCAL_MACHINE);
			objReg.Set(objSysInfo.m_csProductRegKey, _T("LUMSG_Last"), (LPBYTE)&ulCurTime, sizeof(ulCurTime), REG_BINARY, HKEY_LOCAL_MACHINE);
		}
		else
		if(1 == dwAutoLU)
		{
			if(0 == ulALU_Last)
			{
				objReg.Set(objSysInfo.m_csProductRegKey, _T("ALU_Last"), (LPBYTE)&ulCurTime, sizeof(ulCurTime), REG_BINARY, HKEY_LOCAL_MACHINE);
			}

			dwElapsedHours = GetElapsedHours(ulCurTime, ulALU_Last);
			dwDelayCheck = dwDelay;
			if(dwElapsedHours >= dwDelayCheck * 1)
			{
				if(DoLiveUpdateActivity(LU_DoBackGroundLU))
				{
					objReg.Set(objSysInfo.m_csProductRegKey, _T("ALU_Last"), (LPBYTE)&ulCurTime, sizeof(ulCurTime), REG_BINARY, HKEY_LOCAL_MACHINE);
				}
			}
		}
		else
		{
			if(0 == ulLUMSG_Last)
			{
				objReg.Set(objSysInfo.m_csProductRegKey, _T("LUMSG_Last"), (LPBYTE)&ulCurTime, sizeof(ulCurTime), REG_BINARY, HKEY_LOCAL_MACHINE);
			}

			dwElapsedHours = GetElapsedHours(ulCurTime, ulLUMSG_Last);
			if(dwElapsedHours >= dwDelay * 4 && 0 != dwAutoLUReminder)
			{
				if(DoLiveUpdateActivity(LU_ShowLUMessage))
				{
					objReg.Set(objSysInfo.m_csProductRegKey, _T("LUMSG_Last"), (LPBYTE)&ulCurTime, sizeof(ulCurTime), REG_BINARY, HKEY_LOCAL_MACHINE);
				}
			}
		}
	}

	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: LaptopTrackerThread
In Parameters	: LPVOID lpParam
Out Parameters	: UINT
Purpose			: Thread for launching laptoptracker on every 4 hrs.
--------------------------------------------------------------------------------------*/
UINT LaptopTrackerThread(LPVOID lpParam)
{
	return 0;
	
	DWORD dwOneSecond = 1000;
	DWORD dwOneMinute = 60 * dwOneSecond;
	DWORD dwOneHour = 60 * dwOneMinute;

	CRegistry objReg;
	CSystemInfo objSysInfo;
	CEnumProcess objEnum;
	
	DWORD dwDelay = 4;

	Sleep(dwOneMinute * 7);

	while(true)
	{
		DWORD dwEval = 0;
		CEnumProcess objEnumRocess;
		CRegistry oReg;
		CSystemInfo objSysInfo;
		CString	csLiveUpdateExePath = (CString)CWatchDogServiceApp::m_strAppPath + _T("\\") + (CString)LIVEUPDATE_EXE;
		CExecuteProcess objExecuteProcess;

		oReg.Get(objSysInfo.m_csProductRegKey, QUARANTINECNT, dwEval, HKEY_LOCAL_MACHINE);
		if(0 != dwEval)
		{
			return false;
		}
		
		if(objEnumRocess.IsProcessRunning(csLiveUpdateExePath, false))
		{
			return false;
		}
		objExecuteProcess.ShellExecuteExW(csLiveUpdateExePath, L"-LaptopTracker");
		Sleep(dwOneHour * dwDelay);
	}
	
	return 0;
}


/*-------------------------------------------------------------------------------------
Function		: WatchOtherAppsThread
In Parameters	: LPVOID lpParam
Out Parameters	: UINT
Purpose			: Thread for watching over other apps
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
UINT WatchOtherAppsThread(LPVOID lpParam)
{
	CString csMigrateSD;
	CEnumProcess objEnumProcess;
	CExecuteProcess objExecProcess;
	CRegistry oReg;

	return 0;
}
UINT	CheckForFileIntegrity(CString csFolder,CString csAppPath,CString csINIPath)
{
	bool		bCopyFile = true;
	CFileFind	objFinder ;
	CString		csHoldFileName = csFolder;
	BOOL		bMoreFiles = FALSE ;
	bool		bIsMisMatch = false;
	TCHAR		szFileCount[10]={0};
	DWORD		dwMD5Len = 10;
	CDirectoryManager	objDirectoryMgr;

	GetPrivateProfileString(_T("Data"), _T("FileCnt"), L"0", szFileCount, dwMD5Len,csINIPath);
	int iFileCount = _wtoi(szFileCount);
	if(iFileCount >0)
	{
		int iCount = 0;
		int iFileFound = 0;	
		bCopyFile = false;
		bIsMisMatch = false;
		while(iCount < iFileCount)
		{
			iCount++;
			CString csDataFileName;
			csDataFileName.Format(_T("\\data%02d.*"),iCount);
			bMoreFiles = objFinder.FindFile(csHoldFileName + csDataFileName);
			while(bMoreFiles)
			{
				iFileFound++;
				bCopyFile = false;
				bMoreFiles = objFinder.FindNextFile() ;
				CString csFilePath = objFinder.GetFilePath();
				csFilePath.MakeLower();
				bIsMisMatch =theApp.CheckMD5MisMatch(csINIPath, csFilePath);
				if(bIsMisMatch)
				{
					bCopyFile = true;
					break;
				}
			}
			objFinder.Close();
			if(bCopyFile)
			{
				break;
			}
		}
		if(bCopyFile ||  (iFileFound != iFileCount))
		{
			objDirectoryMgr.MaxDeleteDirectoryContents(csFolder,true);
			CreateDirectory(csFolder, NULL);
			SetFileAttributes(csFolder,FILE_ATTRIBUTE_HIDDEN);
			objDirectoryMgr.MaxCopyDirectory(csFolder,csAppPath,true,true);
		}
	}	

	return 0x00;
}

UINT CryptMonFolderCheckThread(LPVOID lpParam)
{
	Sleep(2 * 1000);
	CRegistry objReg;
	CString csAppPath = CSystemInfo ::m_strAppPath;
	csAppPath += _T("\\RanFileData");
	CString csINIPath = csAppPath + _T("\\filedata.ini");

	while(true)
	{
		DWORD dwCryptFolder = 0;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("CryptFolder"), dwCryptFolder, HKEY_LOCAL_MACHINE);
		//CSDKSettings objSDKSettings;
		//dwCryptFolder = objSDKSettings.GetProductSettingsInt(PRODUCT_SETTINGS,_T("CryptFolder"));
		if(dwCryptFolder)
		{
			////Folder Creation
			WCHAR csWinDir[MAX_PATH] = _T("");
			UINT uRetVal = 0;
			TCHAR	szDriveStrings[MAX_PATH] = {0x00};
			DWORD	dwBuffLen = MAX_PATH;
			TCHAR	*pDummy = NULL;
			GetLogicalDriveStrings(dwBuffLen,szDriveStrings);
			pDummy = szDriveStrings;
			DWORD dwData = 0;
			TCHAR	szDrive[0x10] = {0x00};
			
			while(pDummy)
			{
				_stprintf_s(szDrive,0x10,L"%s",pDummy);
				
				if (_tcslen(szDrive) == 0x00)
				{
					break;
				}
				DWORD dwDriveType = GetDriveType(szDrive);
				if(GetDriveType(szDrive) == DRIVE_FIXED)
				{
					CString csFolder;
					csFolder.Format(_T("%s!-"),szDrive);
					CheckForFileIntegrity(csFolder,csAppPath,csINIPath);

					csFolder.Format(_T("%s~!-"),szDrive);
					CheckForFileIntegrity(csFolder,csAppPath,csINIPath);

					CString		csScapeGoatFile;
					csScapeGoatFile.Format(L"%s\\Data18.doc",csAppPath);
					csFolder.Format(_T("%s!-SCPGT01.DOC"),szDrive);
					CopyFile(csScapeGoatFile,csFolder,false);
					SetFileAttributes(csFolder,FILE_ATTRIBUTE_HIDDEN);

					csScapeGoatFile.Format(L"%s\\Data21.xlsx",csAppPath);
					csFolder.Format(_T("%s!-SCPGT02.XLSX"),szDrive);
					CopyFile(csScapeGoatFile,csFolder,false);
					SetFileAttributes(csFolder,FILE_ATTRIBUTE_HIDDEN);

					csScapeGoatFile.Format(L"%s\\Data26.jpeg",csAppPath);
					csFolder.Format(_T("%s!-SCPGT03.JPEG"),szDrive);
					CopyFile(csScapeGoatFile,csFolder,false);
					SetFileAttributes(csFolder,FILE_ATTRIBUTE_HIDDEN);

					csScapeGoatFile.Format(L"%s\\Data28.pdf",csAppPath);
					csFolder.Format(_T("%s!-SCPGT04.PDF"),szDrive);
					CopyFile(csScapeGoatFile,csFolder,false);
					SetFileAttributes(csFolder,FILE_ATTRIBUTE_HIDDEN);
					////////////Find File
								
				}
				pDummy+=(_tcslen(szDriveStrings) + 0x01);
			}
			Sleep(5 * 60 * 1000);
		}		
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: BackGroundScanThread
In Parameters	: LPVOID lpParam
Out Parameters	: UINT
Purpose			: Thread for BackGround Scanning.
Author			: Ravi
--------------------------------------------------------------------------------------*/
UINT BackGroundScanThread(LPVOID lpParam)
{
	CRegistry objReg;
	bool bScanDoneOnce = false;
	CTime ntCurrentTime = 0;
	DWORD dwEnableBGScan = 0;

	Sleep(45 * 60 * 1000); //wait 45 minutes to start activity
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("BackGroundScan"), dwEnableBGScan, HKEY_LOCAL_MACHINE);

	TCHAR	szDriveStrings[MAX_PATH] = {0x00};
	DWORD	dwBuffLen = MAX_PATH;
	TCHAR	*pDummy = NULL;
	TCHAR	szDrive[0x10] = {0x00};
	CString csDrive= L"";

	/*GetLogicalDriveStrings(dwBuffLen,szDriveStrings);
	pDummy = szDriveStrings;
	while(pDummy)
	{
		_stprintf_s(szDrive,0x10,L"%s",pDummy);
		if (_tcslen(szDrive) == 0x00)
		{
			break;
		}
		pDummy+=(_tcslen(szDriveStrings) + 0x01);
		if(csDrive.IsEmpty())
		{
			csDrive.Format(_T("%s"),szDrive);
		}
		else
		{
			csDrive.Format(_T("%s %s"),csDrive,szDrive);
		}
	}
	if(!csDrive.IsEmpty())
	{
		csDrive.Replace(_T("\\"),_T("|"));
	}*/
	DWORD dwRegister = 1;
	DWORD dwAutoQuarantine = 0;
	if(1 == dwEnableBGScan)
	{
		HANDLE hGlobalMutexBKG = NULL;
		CString csMutexNameBKG = _T("Global\\AU_BKGSCANNER_ON");
		hGlobalMutexBKG	= ::OpenMutex(SYNCHRONIZE, FALSE, csMutexNameBKG);
		if(hGlobalMutexBKG != NULL)
		{
			CloseHandle(hGlobalMutexBKG);
			hGlobalMutexBKG = NULL;
		}
		else
		{
			ntCurrentTime = CTime::GetCurrentTime();

			CString csDate;
			csDate.Format (_T("%d/%d/%d"),ntCurrentTime.GetDay(),ntCurrentTime.GetMonth(),ntCurrentTime.GetYear());

			CString csLastSchDate;
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("LastBackGroundScan"),csLastSchDate, HKEY_LOCAL_MACHINE);
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dwRegister, HKEY_LOCAL_MACHINE);
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), dwAutoQuarantine, HKEY_LOCAL_MACHINE);	
			CString m_csScanStatusIni =L"";
			objReg.Get(CSystemInfo::m_csProductRegKey,_T("AppFolder"),m_csScanStatusIni,HKEY_LOCAL_MACHINE);
			if(!m_csScanStatusIni.IsEmpty())
			{
				m_csScanStatusIni.Format(_T("%sSetting\\ScanStatusLastScan.ini"),m_csScanStatusIni);
			}

			int iStatus = 0;
			iStatus = GetPrivateProfileInt(L"MAX_SCAN_STATUS", L"SCAN_STATUS",0, m_csScanStatusIni);	
			DWORD dwDay = 2;

			int i=0;
			long nDays = 0;

			csLastSchDate.Trim();
			if(csLastSchDate.GetLength() < 5)
			{
				nDays = 8;
			}
			else
			{
				int iDate = _wtoi(csLastSchDate.Tokenize(_T("/"),i).Trim());
				int iMonth = _wtoi(csLastSchDate.Tokenize(_T("/"),i).Trim());
				int iYear = _wtoi(csLastSchDate.Tokenize(_T("/"),i).Trim());

				CTime NextSchTime(iYear, iMonth, iDate, 0, 0, 0);
				CTimeSpan timeDifference = ntCurrentTime - NextSchTime;
				nDays = timeDifference.GetDays();

				if(nDays < 0)
				{
					nDays = 0;
				}
			}
			/*
			if(csLastSchDate.GetLength() > 5)
			{
				int iDate = _wtoi(csLastSchDate.Tokenize(_T("/"),i).Trim());
				int iMonth = _wtoi(csLastSchDate.Tokenize(_T("/"),i).Trim());
				int iYear = _wtoi(csLastSchDate.Tokenize(_T("/"),i).Trim());

				CTime NextSchTime(iYear, iMonth, iDate, 0, 0, 0);
				CTimeSpan timeDifference = ntCurrentTime - NextSchTime;
				nDays = timeDifference.GetDays();

				if(nDays < 0)
				{
					nDays = 0;
				}
			}
			if(csLastSchDate.IsEmpty())
			{
				nDays = 8;
			}
			*/

			//if((((dwDay == ntCurrentTime.GetDayOfWeek()) && (csLastSchDate != csDate)) || (iStatus == 1)) && (dwRegister == 0) && (dwAutoQuarantine == 1))
			if(((nDays >=7) || (iStatus == 1)))
			{	
				if(theApp.IsScannerRunning(eScanner1))
				{
					OutputDebugString(L"BKG Scanner Skip");
					return 0;
				}
				OutputDebugString(L"BKG Scanner Start");
				CString csCmdLine;
				/*csCmdLine.Format(_T("/v /a /c /bg /DRIVES:%s"),csDrive);
				theApp.LaunchScanner(csCmdLine);*/
				WCHAR csWinDir[MAX_PATH] = _T("");
				UINT uRetVal = GetWindowsDirectory(csWinDir, MAX_PATH);
				if(0 != uRetVal)
				{
					csDrive = csWinDir;
					int iFind = csDrive.Find(_T(':'), 0);
					csDrive = csDrive.Mid(0, iFind + 1);
					csDrive += _T("|");
					if ((dwAutoQuarantine == 1) && (dwRegister == 0))
					{
						csCmdLine.Format(_T("/d /a /bg /DRIVES:%s"),csDrive);
					}
					else
					{
						csCmdLine.Format(_T("/d /bg /DRIVES:%s"),csDrive);
					}
					theApp.LaunchScanner(csCmdLine);
				}
			}
		}
	}

	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : GetWDShutDownStatus
In Parameters  : DWORD &dwValue,
Out Parameters : bool
Description    : Registry operation to check whether the last shutdown status was gracefulor abrupt
Broadcast is done to all registered apps to Re-register
if WD shutdown was abrupt
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CWatchDogServiceApp::GetWDShutDownStatus(DWORD &dwValue)
{
	bool bRet = false;
	CRegKey objRegKey;
	if(objRegKey.Open(HKEY_LOCAL_MACHINE, CSystemInfo::m_csProductRegKey) == ERROR_SUCCESS)
	{
		if(objRegKey.QueryDWORDValue(REG_WD_SHUTDOWN,dwValue) == ERROR_SUCCESS)
		{
			bRet = true;
		}
	}
	objRegKey.Close();
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : SetWDShutDownStatus
In Parameters  : DWORD dwValue,
Out Parameters : bool
Description    : Registry operation mainly used for setting the WD service status as
started or graceful shutdown
1: Service Started
0: Graceful Shutdown
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CWatchDogServiceApp::SetWDShutDownStatus(DWORD dwValue)
{
	{
		// Creating this object will trigger the DB Server to save the quarantine DB!
		CMaxDSrvWrapper objMaxDSrvWrapper;
	}

	bool bRet = false;
	CRegKey objRegKey;
	if(objRegKey.Open(HKEY_LOCAL_MACHINE, CSystemInfo::m_csProductRegKey) == ERROR_SUCCESS)
	{
		if(objRegKey.SetDWORDValue(REG_WD_SHUTDOWN,dwValue) == ERROR_SUCCESS)
		{
			bRet = true;
		}
	}
	objRegKey.Close();
	return bRet;
}
/*--------------------------------------------------------------------------------------
Function       : BroadcastToSDProcesses
In Parameters  :
Out Parameters : void
Description    : Whenever there is an abrupt shutdown/termination of service and Restart service
is automatically done Watchdog service recognizes that and sends a broadcast message
to all the Application pipes that are registered with WD.
We need to update g_szMaxBroadcastPipeNames array whenever we want to add a new pipe
for monitoring
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::BroadcastToSDProcesses()
{
	AM_MESSAGE_DATA sAMMsgData = {0};
	sAMMsgData.dwMsgType = Register_WD_PID;
	SHARED_ACTMON_SWITCH_DATA sAMData = {0};
	SecureZeroMemory(&sAMData,sizeof(SHARED_ACTMON_SWITCH_DATA));
	sAMData.eProcType = Register_WD_PID;

	for(int i = 2;i< MAX_BROADCAST_PIPES;i++)
	{
		MAX_PIPE_DATA sMaxPipeData = {0};
		SecureZeroMemory(&sMaxPipeData,sizeof(MAX_PIPE_DATA));
		sMaxPipeData.eMessageInfo = Register_WD_PID;
		CMaxCommunicator objBroadcast(g_szMaxBroadcastPipeNames[i]);
		if(objBroadcast.SendData(&sMaxPipeData,sizeof(MAX_PIPE_DATA)))
		{
			Sleep(1000);
		}
	}
	Sleep(1000);
	//Broadast to Actmon
	CMaxCommunicator objAMBroadcast(g_szMaxBroadcastPipeNames[0]);
	objAMBroadcast.SendData(&sAMData,sizeof(SHARED_ACTMON_SWITCH_DATA));
	//Broadast to Tray
	Sleep(1000);
	CMaxCommunicator objTrayBroadcast(g_szMaxBroadcastPipeNames[1]);
	objTrayBroadcast.SendData(&sAMMsgData,sizeof(AM_MESSAGE_DATA));

}

/*-------------------------------------------------------------------------------------
Function		: GetMonthIndex
In Parameters	: CString cstr
Out Parameters	: int
Purpose			: To get the index of month.
Author			: Tejas Kurhade.
--------------------------------------------------------------------------------------*/
int GetMonthIndex(CString cstr)
{
	int pos = 0;
	if((cstr.Find(_T("Jan"),pos))!= -1)
		return 1;
	else if((cstr.Find(_T("Feb"),pos))!= -1)
		return 2;
	else if((cstr.Find(_T("Mar"),pos))!= -1)
		return 3;
	else if((cstr.Find(_T("Apr"),pos))!= -1)
		return 4;
	else if((cstr.Find(_T("May"),pos))!= -1)
		return 5;
	else if((cstr.Find(_T("Jun"),pos))!= -1)
		return 6;
	else if((cstr.Find(_T("Jul"),pos))!= -1)
		return 7;
	else if((cstr.Find(_T("Aug"),pos))!= -1)
		return 8;
	else if((cstr.Find(_T("Sept"),pos))!= -1)
		return 9;
	else if((cstr.Find(_T("Oct"),pos))!= -1)
		return 10;
	else if((cstr.Find(_T("Nov"),pos))!= -1)
		return 11;
	else if((cstr.Find(_T("Dec"),pos))!= -1)
		return 12;
	
	return 0;
}

BOOL CWatchDogServiceApp::InstallSDDriver(CString csName, CString csPath)
{
	bool bRetVal = false;

	//create driver entry 
	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if(hSrvManager)
	{
		SC_HANDLE hDriver = CreateService(hSrvManager, csName, csName, SERVICE_START | SERVICE_STOP, 
											SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, 
											SERVICE_ERROR_NORMAL, csPath, L"Boot Bus Extender", 0, 0, 0, 0);
		if(hDriver != INVALID_HANDLE_VALUE)
		{
			bRetVal = true;
			CloseServiceHandle(hDriver);
		}
		CloseServiceHandle(hSrvManager);
	}
	return bRetVal;
}

bool CWatchDogServiceApp::StartDriver(LPCTSTR sDriverName)
{
	bool bRetVal = false;

	SC_HANDLE hSrvManager = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
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


bool CWatchDogServiceApp::ShellExecuteApp(CString csAppPath,int uType)
{
	bool bRet = false;
	CString csCurrentDir;
	CString csParam;
	CString csAppName;
	switch(uType)
	{
		
	case 1:
		{
			csParam = L"/i \"" + csAppPath + L"\"" + L" /qn TARGETDIR=\"" + CWatchDogServiceApp::m_strAppPath + L"\"";
			//csAppName = CSystemInfo::m_strSysDir + L"\\msiexec.exe";
			csAppName = L"msiexec.exe";
			bRet =true;
			break;
		}
	case 2:
		{
			break;
		}
	case 3:
		{
			//csParam = L"/x \"" + csAppPath + L"\"" + L" /qn";
			//csAppName = CSystemInfo::m_strSysDir + L"\\msiexec.exe";
			//csAppName = L"msiexec.exe";
			bRet = true;
			break;
		}
	case 4:
		{
			break;
		}
	}
	
	//CExecuteProcess oExecuteProcess;
	//oExecuteProcess.ExecuteCommandWithWait(csAppName, csParam);
	ShellExecute(NULL, L"open", csAppName, csParam, csCurrentDir, SW_NORMAL | SW_HIDE);
		
	if (uType == 1 )
	{
		if(CSystemInfo::m_bIs2kSevers || CSystemInfo::m_strOS == W2K)
		{
			CRegistry objReg;
			BYTE byRegData[1] = {0x00};
			objReg.Set(_T("SOFTWARE\\Microsoft\\Driver Signing"), _T("Policy"),byRegData,1,REG_BINARY,HKEY_LOCAL_MACHINE);
			objReg.Set(_T("SOFTWARE\\Microsoft\\Non-Driver Signing"), _T("Policy"),byRegData,1,REG_BINARY,HKEY_LOCAL_MACHINE);
		}
	}
	return bRet;
}

void CWatchDogServiceApp::ShowAutoUpdateSuccessDlg()
{
	CString csCnt;
	GetPrivateProfileString(SUMMARY,WORMCOUNTS,BLANKSTRING,csCnt.GetBuffer(MAX_PATH),MAX_PATH,CSystemInfo ::m_strAppPath + _T("\\") + (CString)WORMSCOUNTINI);
	csCnt.ReleaseBuffer();

	CString csAppPath = CSystemInfo ::m_strAppPath;
	csAppPath += _T("\\");
	csAppPath += ACT_MON_TRAY_EXE;
	CString csParam(_T("-"));
	csParam += CSystemInfo::m_csProductName;

	CString csUPD = L"UPD";
	
	csParam += _T(";") + csUPD + _T(";AUTOUPDATE;") + csCnt +_T(";HYPERLINKFALSE");

	LaunchGUIApp(csAppPath, csParam);
}

void CWatchDogServiceApp::SetGamingMode(ULONG ulVal)
{
	int iTotalCount = (int)m_csarrScannerIDs.GetCount();
	for(int iCount=0 ; iCount<iTotalCount ; iCount++)
	{
		MAX_PIPE_DATA oPipeData = {0};
		oPipeData.eMessageInfo = GamingMode;
		oPipeData.ulSpyNameID = ulVal;

		CMaxCommunicator objMaxCommunicator(m_csarrScannerIDs[iCount], false);
		objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA));
	}
}

void CWatchDogServiceApp::AddScannerID(CString &csData)
{
	m_csarrScannerIDs.Add(csData);
}

void CWatchDogServiceApp::RemoveScannerID(CString &csData)
{
	int iTotalCount = (int)m_csarrScannerIDs.GetCount();
	for(int iCount=0 ; iCount<iTotalCount ; iCount++)
	{
		if(m_csarrScannerIDs[iCount] == csData)
		{
			m_csarrScannerIDs.RemoveAt(iCount);
			break;
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : EnableActiveProtection
In Parameters  : void,
Out Parameters : void
Description    : Setting Active protection registry key to Zero.
Author         : Ramkrushna Shelke
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::EnableActiveProtection()
{
	try
	{
		CRegistry objReg;
		DWORD dwRestartRequired = 0;
		DWORD dwUnInstallRestartRequired = 0;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("bActiveProtection"), 0, HKEY_LOCAL_MACHINE);
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("FWRestartRequired"), dwRestartRequired, HKEY_LOCAL_MACHINE);
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("FWUninstallRestartRequired"), dwUnInstallRestartRequired, HKEY_LOCAL_MACHINE);
		if(dwRestartRequired)
		{
			dwRestartRequired = 0;
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("FWRestartRequired"), dwRestartRequired, HKEY_LOCAL_MACHINE);
			objReg.Set(FW_DRIVER_PATH, _T("FireWallEnable"), 1, HKEY_LOCAL_MACHINE);
		}
		if(dwUnInstallRestartRequired)
		{
			dwUnInstallRestartRequired = 0;
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("FWUninstallRestartRequired"), dwUnInstallRestartRequired, HKEY_LOCAL_MACHINE);
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("FWRestartRequiredTray"), 1, HKEY_LOCAL_MACHINE);
		}

	}
	catch(...)
	{
		AddLogEntry(_T("Exception In CWatchDogServiceApp::EnableActiveProtection"));
	}
}

void CWatchDogServiceApp::StopDrivers()
{
	CMaxProtectionMgr oMaxProtectionMgr;
	oMaxProtectionMgr.PauseProtection();
}

BOOL CWatchDogServiceApp::CopyProxySetting()
{
	CCPUInfo objSystem;
	CString csSourcePath = CSystemInfo::m_strAppPath + SETTING_FOLDER + PROXYSETTINGS_INI;
	CString csDestination = objSystem.GetSystemDir() + PROXYSETTINGS_INI;
	if(!CopyFile(csSourcePath, csDestination, FALSE))
	{
		AddLogEntry(_T("#### Copy File Failed : %s") , csSourcePath);
		return FALSE;
	}
	return TRUE;
}


void CWatchDogServiceApp::ReplicationSetting(DWORD dwVal)
{
	CRegistry objReg;
	objReg.Set(ACTMON_SERVICE_PATH, L"EnableReplicating", dwVal, HKEY_LOCAL_MACHINE);
}

void CWatchDogServiceApp::SetRegCopyPasteSetting(DWORD dwVal)
{
	CRegistry objReg;
	objReg.Set(ACTMON_SERVICE_PATH, L"EnableCopyPaste", dwVal, HKEY_LOCAL_MACHINE);
}

void CWatchDogServiceApp::DeleteAppCompatFlagsValues()
{
	CRegistry oReg;
	CStringArray arrValues;
	CString csAppFolder;
	CRegistryHelper	oRegHelper;
	CS2S			oAvailableUsers(false);
	oRegHelper.LoadAvailableUsers(oAvailableUsers);
	LPVOID posUserName = oAvailableUsers.GetFirst();
	oReg.Get(CSystemInfo::m_csProductRegKey, L"AppFolder", csAppFolder, HKEY_LOCAL_MACHINE);
	csAppFolder.MakeLower();
	while(posUserName)
	{
		LPTSTR strUserName = NULL;
		oAvailableUsers.GetKey(posUserName, strUserName);
		CString csProfilePath(strUserName);

		csProfilePath += WINNT_LAYAR_KEY;
		oReg.EnumValues(csProfilePath, arrValues, HKEY_USERS);
		for(INT_PTR i = 0, iTotal = arrValues.GetCount(); i < iTotal; i++)
		{
			if(arrValues[i].MakeLower().Find(csAppFolder) != -1)
			{
				oReg.DeleteValue(csProfilePath, arrValues[i], HKEY_USERS);
			}
		}
		posUserName = oAvailableUsers.GetNext(posUserName);
	}
	arrValues.RemoveAll();
	oReg.EnumValues(WINNT_LAYAR_KEY, arrValues, HKEY_LOCAL_MACHINE);
	for(INT_PTR i = 0, iTotal = arrValues.GetCount(); i < iTotal; i++)
	{
		if(arrValues[i].MakeLower().Find(csAppFolder) != -1)
		{
			oReg.DeleteValue(WINNT_LAYAR_KEY, arrValues[i], HKEY_LOCAL_MACHINE);
		}
	}
	arrValues.RemoveAll();
	oReg.EnumValues(WINNT_LAYAR_KEY, arrValues, HKEY_CURRENT_USER);
	for(INT_PTR i = 0, iTotal = arrValues.GetCount(); i < iTotal; i++)
	{
		if(arrValues[i].MakeLower().Find(csAppFolder) != -1)
		{
			oReg.DeleteValue(WINNT_LAYAR_KEY, arrValues[i], HKEY_LOCAL_MACHINE);
		}
	}	
}

void CWatchDogServiceApp::DisplayProcessMap()
{
	//CString csTemp;
	ProcessMapItem::iterator iter;
	
	for(iter = m_ProcessMapItem.begin(); iter != m_ProcessMapItem.end(); iter++)
	{
		MAX_WD_DATA wdItem = {0};
		wdItem = (*iter).second;
	}
}

void CWatchDogServiceApp::SuspendAndTerminateAllThreads()
{
	AddLogEntry(_T(" >>>Start SuspendAndTerminateAllThreads"));
	if( m_RestoreSystemDefaultsThread )
	{
		if( m_RestoreSystemDefaultsThread->m_hThread != NULL)
		{
			::SuspendThread(m_RestoreSystemDefaultsThread->m_hThread);
			TerminateThread(m_RestoreSystemDefaultsThread->m_hThread, 0);
		}
	}
	if( m_SchedulerThread )
	{
		if( m_SchedulerThread->m_hThread != NULL)
		{
			::SuspendThread(m_SchedulerThread->m_hThread);
			TerminateThread(m_SchedulerThread->m_hThread, 0);
		}
	}
	if( m_LiveupdateThread )
	{
		if( m_LiveupdateThread->m_hThread != NULL)
		{
			::SuspendThread(m_LiveupdateThread->m_hThread);
			TerminateThread(m_LiveupdateThread->m_hThread, 0);
		}
	}
	
	if( m_AutoScanThread )
	{
		if( m_AutoScanThread->m_hThread != NULL)
		{
			::SuspendThread(m_AutoScanThread->m_hThread);
			TerminateThread(m_AutoScanThread->m_hThread, 0);
		}
	}	

	if( m_BackGroundScanThread )
	{
		if( m_BackGroundScanThread->m_hThread != NULL)
		{
			::SuspendThread(m_BackGroundScanThread->m_hThread);
			TerminateThread(m_BackGroundScanThread->m_hThread, 0);
		}
	}

	if(m_CryptMonFolderCheckThread)
	{
		if(m_CryptMonFolderCheckThread->m_hThread != NULL)
		{
			::SuspendThread(m_CryptMonFolderCheckThread->m_hThread);
			TerminateThread(m_CryptMonFolderCheckThread->m_hThread, 0);
		}
	}
	
	if(m_CreateDBForSystemFilesThread)
	{
		if(m_CreateDBForSystemFilesThread->m_hThread != NULL)
		{
			::SuspendThread(m_CreateDBForSystemFilesThread->m_hThread);
			TerminateThread(m_CreateDBForSystemFilesThread->m_hThread, 0);
		}
	}
	if( m_SetupAutoLaunchThread )
	{
		if( m_SetupAutoLaunchThread->m_hThread != NULL)
		{
			::SuspendThread(m_SetupAutoLaunchThread->m_hThread);
			TerminateThread(m_SetupAutoLaunchThread->m_hThread, 0);
		}
	}
	
	if( m_WatchOtherAppsThread )
	{
		if( m_WatchOtherAppsThread->m_hThread != NULL)
		{
			::SuspendThread(m_WatchOtherAppsThread->m_hThread);
			TerminateThread(m_WatchOtherAppsThread->m_hThread, 0);
		}
	}
	
	if(m_LoadMergerThread)
	{
		if(m_LoadMergerThread->m_hThread != NULL)
		{
			::SuspendThread(m_LoadMergerThread->m_hThread);
			TerminateThread(m_LoadMergerThread->m_hThread, 0);
		}
	}
	if(m_LaunchWscSrvThread)
	{
		if(m_LaunchWscSrvThread->m_hThread != NULL)
		{
			::SuspendThread(m_LaunchWscSrvThread->m_hThread);
			TerminateThread(m_LaunchWscSrvThread->m_hThread, 0);
		}
	}
	UnLoadMerger();
	WscSrvStop();
}

void CWatchDogServiceApp::CreateWormstoDeleteINI(CString strINIPath)
{
	if(_waccess_s(strINIPath, 0) != 0)
	{
		// UTF16-LE BOM(FFFE)
		WORD wBOM = 0xFEFF;
		DWORD NumberOfBytesWritten;
		HANDLE hFile = ::CreateFile(strINIPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		::WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, NULL);
		::CloseHandle(hFile);
		WritePrivateProfileStringW(L"File_Delete", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Backup", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"Folder", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryData", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryValue", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryKey", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Rename", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Replace", L"WormCnt", L"0", strINIPath);
	}
}

BOOL CWatchDogServiceApp::AddInRestartDeleteList(RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID, LPCTSTR szValue)
{
	BOOL bRet = false;
	CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
	WCHAR strCount[50] = {0};
	WCHAR strValue[MAX_PATH*4] = {0};
	LPTSTR lpszSection = NULL;
	WCHAR *szSection[8] = {L"File_Delete", L"File_Backup", L"Folder", L"RegistryKey",
							L"RegistryValue",L"RegistryData", L"File_Rename", L"File_Replace"};

	if(eRD_Type == RD_FILE_DELETE)
		lpszSection = szSection[0];
	else if ( eRD_Type == RD_FILE_BACKUP)
		lpszSection = szSection[1];
	else if ( eRD_Type == RD_FOLDER )
		lpszSection = szSection[2];
	else if ( eRD_Type == RD_KEY )
		lpszSection = szSection[3];
	else if ( eRD_Type == RD_VALUE )
		lpszSection = szSection[4];
	else if ( eRD_Type == RD_DATA)
		lpszSection = szSection[5];
	else if ( eRD_Type == RD_FILE_RENAME)
		lpszSection = szSection[6];
	else if ( eRD_Type == RD_FILE_REPLACE)
		lpszSection = szSection[7];

	if(lpszSection == NULL)
		return FALSE;

	CreateWormstoDeleteINI(strINIPath);

	UINT ulWormCnt = GetPrivateProfileIntW(lpszSection, L"WormCnt", 0, strINIPath);
	wsprintf(strCount, L"%d", ++ulWormCnt);
	WritePrivateProfileStringW(lpszSection, L"WormCnt", strCount, strINIPath);

	wsprintf(strValue, L"%ld^%s", ulSpyNameID, szValue);
	WritePrivateProfileStringW(lpszSection, strCount, strValue, strINIPath);
	return bRet;
}

void CWatchDogServiceApp::AddAutoRunInINI()
{
	AddLogEntry(L"In AddAutoRunInINI!");
	for(int drive = 1; drive <= 26; drive++)
	{
		if(!_chdrive(drive))
		{
			CString csDrive, csAutoRun;
			csDrive.Format( _T("%c:\\"), (drive + 'A' - 1));
			csAutoRun.Format( _T("%c:\\AutoRun.inf"), (drive + 'A' - 1));
			AddLogEntry(L"Check: %s", csAutoRun);
			if(_waccess(csAutoRun, 0) == 0 && !::PathIsDirectory(csAutoRun))
			{
				UINT DriveType = GetDriveType(csDrive);
				if(DriveType == DRIVE_FIXED || DriveType == DRIVE_REMOVABLE)
				{
					AddLogEntry(L"Delete AutoRun.inf: %s", csAutoRun);
					if(::DeleteFile(csAutoRun) && DriveType == DRIVE_REMOVABLE)
					{
						::CreateDirectory(csAutoRun, 0);
					}
				}
			}
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : CWatchDogServiceApp::ResetPermission
In Parameters  : NONE
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 5 Jan, 2012.
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::ResetPermission()
{
	CString csCurrOsVer = CSystemInfo::m_strOS;
	csCurrOsVer.MakeUpper();

	CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
	if(!::PathFileExists(strINIPath))
	{
		AddAutoRunInINI();
		return;
	}

	CFile oFile(strINIPath, CFile::modeRead);
	ULONGLONG ulFileLen = oFile.GetLength();

	LPBYTE lpbBuffer = new BYTE[ulFileLen];
	memset(lpbBuffer, 0, ulFileLen);
	oFile.Read((LPVOID)lpbBuffer, ulFileLen);
	oFile.Close();

	TCHAR szErrorMsg[MAX_PATH] = {0};
	m_hProcessToken = NULL;
	// Open a handle to the access token for the calling process.
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &m_hProcessToken)) 
	{
		m_hProcessToken = NULL;
	}
	else
	{
		// Enable the SE_TAKE_OWNERSHIP_NAME privilege.
		if(!SetPrivilege(SE_TAKE_OWNERSHIP_NAME, TRUE)) 
		{
		}
		// Enable the SE_BACKUP_NAME privilege.
		if (!SetPrivilege(SE_BACKUP_NAME, TRUE)) 
		{
		}
	}

	// Calling twice to take care of the folder first and then inside files
	ProcessBuffer((PWCHAR)lpbBuffer, (ulFileLen/sizeof(TCHAR)), true);
	ProcessBuffer((PWCHAR)lpbBuffer, (ulFileLen/sizeof(TCHAR)), false);

	if(m_hProcessToken)
	{
		// Disable the SE_TAKE_OWNERSHIP_NAME privilege.
		if(!SetPrivilege(SE_TAKE_OWNERSHIP_NAME, FALSE)) 
		{
		}
		// Disable the SE_BACKUP_NAME privilege.
		if (!SetPrivilege(SE_BACKUP_NAME, FALSE)) 
		{
		}
		CloseHandle(m_hProcessToken);
	}

	delete [] lpbBuffer;
	lpbBuffer = NULL;

	AddAutoRunInINI();
}

/*--------------------------------------------------------------------------------------
Function       : CWatchDogServiceApp::ProcessBuffer
In Parameters  : PWCHAR pBuffer, ULONG ulSizeOfBuffer, bool bFoldersOnly
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 5 Jan, 2012.
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::ProcessBuffer(PWCHAR pBuffer, ULONG ulSizeOfBuffer, bool bFoldersOnly)
{
	DWORD dwCtr = 0;
	DWORD dwFilePos = 0;
	WCHAR wsLineRead[MAX_PATH] = {0};

	if(!pBuffer)
	{
		return;
	}

	m_CurrRDType = RD_INVALID;
	for(; dwCtr < ulSizeOfBuffer && dwFilePos < MAX_PATH; dwCtr++)
	{
		if((pBuffer[dwCtr] == 0x0A) || (pBuffer[dwCtr] == 0x0D) || (pBuffer[dwCtr] == 0x00))
		{
			if(dwFilePos != 0)
			{
				ProcessLine(wsLineRead, bFoldersOnly);
				memset(wsLineRead, 0, dwFilePos*2);
				dwFilePos = 0;
			}
		}
		else
		{
			wsLineRead[dwFilePos] = pBuffer[dwCtr];
			dwFilePos++;
		}
	}
	if(dwFilePos != 0)
	{
		ProcessLine(wsLineRead, bFoldersOnly);
		memset(wsLineRead, 0, dwFilePos*2);
		dwFilePos = 0;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CWatchDogServiceApp::ProcessLine
In Parameters  : PWCHAR wsLineRead, bool bFoldersOnly
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 5 Jan, 2012.
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::ProcessLine(PWCHAR wsLineRead, bool bFoldersOnly)
{
	if(!wsLineRead)
	{
		return;
	}

	if(memcmp(wsLineRead, L"WormCnt", 7)== 0)
	{
		return;
	}

	if(wsLineRead[0] == '[')			// reset current section as new section is starting
	{
		m_CurrRDType = RD_INVALID;
	}

	if(wcscmp(wsLineRead, L"[File_Delete]")== 0)
	{
		m_CurrRDType = RD_FILE_DELETE;
		return;
	}

	if(wcscmp(wsLineRead, L"[File_Backup]")== 0)
	{
		m_CurrRDType = RD_FILE_BACKUP;
		return;
	}

	if(wcscmp(wsLineRead, L"[Folder]")== 0)
	{
		m_CurrRDType = RD_FOLDER;
		return;
	}

	if(wcscmp(wsLineRead, L"[RegistryKey]")== 0)
	{
		m_CurrRDType = RD_KEY;
		return;
	}

	if(wcscmp(wsLineRead, L"[RegistryValue]")== 0)
	{
		m_CurrRDType = RD_VALUE;
		return;
	}
	
	if(wcscmp(wsLineRead, L"[File_Rename]")== 0)
	{
		m_CurrRDType = RD_FILE_RENAME;
		return;
	}
	if(wcscmp(wsLineRead, L"[File_Replace]")== 0)
	{
		m_CurrRDType = RD_FILE_REPLACE;
		return;
	}
	if(wcscmp(wsLineRead, L"[Native_Backup]")== 0)
	{
		m_CurrRDType = RD_NATIVE_BACKUP;
		return;
	}

	if((bFoldersOnly) && (m_CurrRDType != RD_FOLDER))	// first process all folder entries
		return;

	switch(m_CurrRDType)
	{
	case RD_FILE_DELETE:
	case RD_FILE_BACKUP:
	case RD_NATIVE_BACKUP:
	case RD_FOLDER:
		{
			int iPos = 0;
			CString csLine(wsLineRead);
			csLine.Tokenize(L"=^", iPos);
			CString csSpyID = csLine.Tokenize(L"=^", iPos);
			CString csValue = csLine.Tokenize(L"=^", iPos);
			HandleEntry(csValue);
		}
		break;
	case RD_FILE_RENAME:
	case RD_FILE_REPLACE:
		{
			int iPos = 0;
			CString csLine(wsLineRead);
			iPos = csLine.ReverseFind('>');
			if(iPos > 0)
			{
				CString csValue = csLine.Mid(iPos + 1);
				HandleEntry(csValue);
			}
		}
		break;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CWatchDogServiceApp::HandleEntry
In Parameters  : CString csFileToOwn		// file / folder name of that we want to own!
Out Parameters : BOOL TRUE if Successfull else FALSE
Description    :
Author & Date  : Darshan Singh Virdi & 5 Jan, 2012.
--------------------------------------------------------------------------------------*/
BOOL CWatchDogServiceApp::HandleEntry(CString csFileToOwn)
{
	BOOL bReturnVal = FALSE;

	LPTSTR szTemp = NULL;
	if(m_objFileList.SearchItem(csFileToOwn, szTemp))
	{
		return TRUE;
	}

	
	{
		m_objFileList.AppendItem(csFileToOwn, csFileToOwn);			// handle child entry
		
		if(TakeOwnership(csFileToOwn))
		{
			if(RemoveReparsePoint(csFileToOwn))
			{
				bReturnVal = TRUE;
			}
		}
	}
	return bReturnVal;
}

/*--------------------------------------------------------------------------------------
Function       : CWatchDogServiceApp::SetPrivilege
In Parameters  : LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
				 BOOL bEnablePrivilege   // to enable or disable privilege
Out Parameters : BOOL TRUE if Successfull else FALSE
Description    :
Author & Date  : Darshan Singh Virdi & 5 Jan, 2012.
--------------------------------------------------------------------------------------*/
BOOL CWatchDogServiceApp::SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp = {0};
	LUID luid = {0};
	TCHAR szErrorMsg[MAX_PATH] = {0};

	if(!m_hProcessToken)
	{
		return FALSE;
	}

	if(!LookupPrivilegeValue(NULL,				// lookup privilege on local system
							lpszPrivilege,		// privilege to lookup 
							&luid))				// receives LUID of privilege
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"LookupPrivilegeValue error: %u", GetLastError()); 
		AddLogEntry(szErrorMsg);
		return FALSE; 
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if(!AdjustTokenPrivileges(m_hProcessToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD)NULL))
	{ 
		swprintf_s(szErrorMsg, MAX_PATH, L"AdjustTokenPrivileges error: %u", GetLastError()); 
		AddLogEntry(szErrorMsg);
		return FALSE; 
	} 

	if(GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"The token does not have the specified privilege.");
		AddLogEntry(szErrorMsg);
		return FALSE;
	} 

	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : CWatchDogServiceApp::TakeOwnership
In Parameters  : LPCTSTR lpszFileToOwn		// file / folder name of that we want to own!
Out Parameters : BOOL TRUE if Successfull else FALSE
Description    :
Author & Date  : Darshan Singh Virdi & 5 Jan, 2012.
--------------------------------------------------------------------------------------*/
BOOL CWatchDogServiceApp::TakeOwnership(LPCTSTR lpszFileToOwn)
{
	BOOL bRetval = FALSE;
	PSID pSIDAdmin = NULL;
	PSID pSIDEveryone = NULL;
	PACL pACL = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	const int NUM_ACES  = 2;
	EXPLICIT_ACCESS ea[NUM_ACES];
	DWORD dwRes;

	TCHAR szErrorMsg[MAX_PATH] = {0};

	// Specify the DACL to use.
	// Create a SID for the Everyone group.
	if(!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSIDEveryone))
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"AllocateAndInitializeSid (Everyone) error %u, %s", GetLastError(), lpszFileToOwn);
		AddLogEntry(szErrorMsg);
		goto Cleanup;
	}

	// Create a SID for the BUILTIN\Administrators group.
	if(!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSIDAdmin))
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"AllocateAndInitializeSid (Admin) error %u, %s", GetLastError(), lpszFileToOwn);
		AddLogEntry(szErrorMsg);
		goto Cleanup;
	}

	ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

	// Set full control for Everyone.
	ea[0].grfAccessPermissions = GENERIC_ALL;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;			//SUB_OBJECTS_ONLY_INHERIT | INHERIT_ONLY;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR) pSIDEveryone;

	// Set full control for Administrators.
	ea[1].grfAccessPermissions = GENERIC_ALL;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;			//SUB_OBJECTS_ONLY_INHERIT | INHERIT_ONLY;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName = (LPTSTR) pSIDAdmin;

	if(ERROR_SUCCESS != SetEntriesInAcl(NUM_ACES, ea, NULL, &pACL))
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"Failed SetEntriesInAcl: %s", lpszFileToOwn);
		
		goto Cleanup;
	}

	// Try to modify the object's DACL.
	dwRes = SetNamedSecurityInfo(
		(LPTSTR)lpszFileToOwn,               // name of the object
		SE_FILE_OBJECT,              // type of object
		DACL_SECURITY_INFORMATION,   // change only the object's DACL
		NULL, NULL,                  // do not change owner or group
		pACL,                        // DACL specified
		NULL);                       // do not change SACL

	if(ERROR_SUCCESS == dwRes)
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"Successfully changed DACL: %s", lpszFileToOwn);
		AddLogEntry(szErrorMsg);
		bRetval = TRUE;
		// No more processing needed.
		goto Cleanup;
	}

	if(dwRes != ERROR_ACCESS_DENIED)
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"First SetNamedSecurityInfo call failed: %u, %s", dwRes, lpszFileToOwn);
		AddLogEntry(szErrorMsg);
		goto Cleanup;
	}

	// If the preceding call failed because access was denied, 
	// enable the SE_TAKE_OWNERSHIP_NAME privilege, create a SID for 
	// the Administrators group, take ownership of the object, and 
	// disable the privilege. Then try again to set the object's DACL.

	// Set the owner in the object's security descriptor.
	dwRes = SetNamedSecurityInfo(
		(LPTSTR)lpszFileToOwn,               // name of the object
		SE_FILE_OBJECT,              // type of object
		OWNER_SECURITY_INFORMATION,  // change only the object's owner
		pSIDAdmin,                   // SID of Administrator group
		NULL, NULL, NULL); 

	if(dwRes != ERROR_SUCCESS)
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"Could not set owner. Error: %u, %s", dwRes, lpszFileToOwn);
		AddLogEntry(szErrorMsg);
		goto Cleanup;
	}

	// Try again to modify the object's DACL,
	// now that we are the owner.
	dwRes = SetNamedSecurityInfo(
		(LPTSTR)lpszFileToOwn,               // name of the object
		SE_FILE_OBJECT,              // type of object
		DACL_SECURITY_INFORMATION,   // change only the object's DACL
		NULL, NULL,                  // do not change owner or group
		pACL,                        // DACL specified
		NULL);                       // do not change SACL

	if(dwRes == ERROR_SUCCESS)
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"Successfully changed DACL: %s", lpszFileToOwn);
		AddLogEntry(szErrorMsg);
		bRetval = TRUE; 
	}
	else
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"Second SetNamedSecurityInfo call failed: %u, %s", dwRes, lpszFileToOwn);
		AddLogEntry(szErrorMsg);
	}

Cleanup:

	if (pSIDAdmin)
		FreeSid(pSIDAdmin); 

	if (pSIDEveryone)
		FreeSid(pSIDEveryone); 

	if (pACL)
		LocalFree(pACL);

	return bRetval;
}

/*--------------------------------------------------------------------------------------
Function       : CWatchDogServiceApp::RemoveReparsePoint
In Parameters  : LPCTSTR lpszFileToOwn
Out Parameters : BOOL TRUE if Successfull else FALSE
Description    :
Author & Date  : Darshan Singh Virdi & 5 Jan, 2012.
--------------------------------------------------------------------------------------*/
BOOL CWatchDogServiceApp::RemoveReparsePoint(LPCTSTR lpszFileToOwn)
{
	BOOL bRetval = FALSE;
	TCHAR szErrorMsg[MAX_PATH] = {0};

	HANDLE hFile = CreateFile(lpszFileToOwn, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"CreateFile Success: %s", lpszFileToOwn); 
		AddLogEntry(szErrorMsg);

		DWORD dwRet = 0;
		DWORD dwSize = 0;
		REPARSE_GUID_DATA_BUFFER ReparseBuffer = {0};
		ReparseBuffer.ReparseTag = IO_REPARSE_TAG_SYMLINK;
		if(DeviceIoControl(hFile, FSCTL_DELETE_REPARSE_POINT, &ReparseBuffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &dwSize, NULL))
		{
			bRetval = TRUE;
			swprintf_s(szErrorMsg, MAX_PATH, L"DeviceIoControl Success: %s", lpszFileToOwn); 
			AddLogEntry(szErrorMsg);
		}
		else
		{
			swprintf_s(szErrorMsg, MAX_PATH, L"DeviceIoControl Failed: %s", lpszFileToOwn); 
			AddLogEntry(szErrorMsg);
		}
		CloseHandle(hFile);
	}
	else
	{
		swprintf_s(szErrorMsg, MAX_PATH, L"CreateFile Failed: %s", lpszFileToOwn); 
		AddLogEntry(szErrorMsg);
	}
	return bRetval;
}

/*--------------------------------------------------------------------------------------
Function       : CWatchDogServiceApp::PauseIdleScan
In Parameters  : 
Out Parameters : Pause Idle Scan
Description    :
Author & Date  : Siddharam Pujari & 31 Oct, 2012.
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::PauseIdleScan()
{
	CMaxCommunicator objComm(_NAMED_PIPE_TRAY_TO_ACTMON, true);
	SHARED_ACTMON_SWITCH_DATA ActMonSwitchData = {0};
	ActMonSwitchData.bStatus   = 0;
	ActMonSwitchData.dwMonitorType = SETGAMINGMODE;
	objComm.SendData(&ActMonSwitchData,sizeof(SHARED_ACTMON_SWITCH_DATA));
}

/*--------------------------------------------------------------------------------------
Function       : CWatchDogServiceApp::ResumeIdleScan
In Parameters  : 
Out Parameters : Resume Idle Scan
Description    :
Author & Date  : Siddharam Pujari & 31 Oct, 2012.
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::ResumeIdleScan()
{
	if(!IsScannerRunning(eScanner1, false) && !IsScannerRunning(eUSBScanner, false))
	{
		CMaxCommunicator objComm(_NAMED_PIPE_TRAY_TO_ACTMON, true);
		SHARED_ACTMON_SWITCH_DATA ActMonSwitchData = {0};
		ActMonSwitchData.bStatus  = 1;
		ActMonSwitchData.dwMonitorType = SETGAMINGMODE;
		objComm.SendData(&ActMonSwitchData,sizeof(SHARED_ACTMON_SWITCH_DATA));
	}	
}

void CWatchDogServiceApp::LaunchGUIApp(LPCTSTR szAppPath, LPCTSTR szParams)
{
	CExecuteProcess oExecuteProcess;
	oExecuteProcess.StartProcessWithToken(szAppPath, szParams, EXPLORE_EXE);
}

void CWatchDogServiceApp::LaunchAppAsUser(LPCTSTR szAppPath, LPCTSTR szParams)
{
	AM_MESSAGE_DATA sAMMsgData = {0};
	sAMMsgData.dwMsgType = LaunchAppAs_USER;
	_tcscpy_s(sAMMsgData.szParentProcessName, MAX_PATH, szAppPath);
	_tcscpy_s(sAMMsgData.szOldValue, MAX_PATH, szParams);
	
	CMaxCommunicator objAMBroadcast(g_szMaxBroadcastPipeNames[1]);
	if(!objAMBroadcast.SendData(&sAMMsgData, sizeof(AM_MESSAGE_DATA)))
	{
		LaunchGUIApp(szAppPath, szParams);
	}
}

void CWatchDogServiceApp::CheckCleanLocalDB()
{
	CCPUInfo objCpuInfo;
	CString csAppDataPath = objCpuInfo.GetAllUserAppDataPath();
	CStringArray csArrAppData;
	CString csPath = CSystemInfo::m_csFolderInAppPath;
	csArrAppData.Add(csAppDataPath+ csPath);
	CString csTempPath;
	BOOL bMoreFiles = FALSE;
	for(int i=0; i < csArrAppData.GetCount(); i++)
	{
		CFileFind objFinder;
		csTempPath = csArrAppData.ElementAt(i) + _T("*");
		bMoreFiles = objFinder.FindFile(csTempPath);
		while(bMoreFiles)
		{
			bMoreFiles = objFinder.FindNextFile();
			if(objFinder.IsDirectory() || objFinder.IsDots())
			{
				continue;
			}
			else
			{
				CString csFilePath = objFinder.GetFilePath();
				CString csExt = csFilePath.Right(4);
				if(csExt.CompareNoCase(_T(".txt")) == 0)
				{
					DeleteFile(csFilePath);
				}
			}
		}
		objFinder.Close();

	}
}
void CWatchDogServiceApp::RemoveEntryFromLocalDB(LPCTSTR pszFilePath)
{
	BOOL		bResult = FALSE;
	TCHAR		szDrivePath[0x03] = {0x00};
	TCHAR		szFilePathLower[1024] = {0x00};

	if (pszFilePath == NULL)
	{
		return ;
	}

	_tcscpy(szFilePathLower,pszFilePath);
	_tcslwr(szFilePathLower);

	//Scanner_Type_Max_SignatureScan
	szDrivePath[0x00] = pszFilePath[0x00];
	szDrivePath[0x01] = pszFilePath[0x01];
	szDrivePath[0x02] = 0x00;
	
	CFileSignatureDb	oLocalSignature;
	PESIGCRCLOCALDB		oPEFileSigLocal = {0};
	VIRUSLOCALDB		oVirusDBLocal = {0};
	bool				bFoundInLocalDB = false;

	if(oLocalSignature.LoadLocalDatabase(szDrivePath, Scanner_Type_Max_SignatureScan))
	{
		bFoundInLocalDB = oLocalSignature.GetFileSignature(szFilePathLower, oPEFileSigLocal, oVirusDBLocal);
		if (bFoundInLocalDB)
		{
			memset(&oPEFileSigLocal,0x00,sizeof(PESIGCRCLOCALDB));
			memset(&oVirusDBLocal,0x00,sizeof(oVirusDBLocal));

			if (oLocalSignature.SetFileSignature(szFilePathLower, oPEFileSigLocal, oVirusDBLocal))
			{
				oLocalSignature.UnLoadLocalDatabase();
			}
		}
		

	}
	return ;
}

bool CWatchDogServiceApp::ChangeServiceStartType(LPCTSTR sDriverName, LPCTSTR sDriverPath, DWORD dwStartType)
{
	bool bRetVal = false;
	BOOL bRet = FALSE;

	SC_HANDLE hSCM = ::OpenSCManager(NULL,
		NULL,
		SC_MANAGER_ALL_ACCESS);
	if(hSCM == NULL)
	{
		return bRetVal;
	}
	// Maybe it's already there and installed, let's try to run
	SC_HANDLE hService =::OpenService(hSCM, sDriverName, SERVICE_ALL_ACCESS);
	bRet = ::ChangeServiceConfig(hService,16, dwStartType, SERVICE_ERROR_NORMAL,sDriverPath, NULL, NULL, NULL, NULL, NULL, NULL);
	::CloseServiceHandle(hSCM);
	::CloseServiceHandle(hService);
	return bRetVal;
}

bool CWatchDogServiceApp::EnumDBForSystemFiles(CString csPath)
{
	CString csSysPath;
	csSysPath.Format(_T("%s\\*.*"),csPath);
	//AddLogEntry(csSysPath);
	CFileFind objFinder;
	BOOL bMoreFiles = FALSE;
	bMoreFiles = objFinder.FindFile(csSysPath);
	int iCount = 0;  //Testing purpose
	
	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile(); 
		if(objFinder.IsDots())
		{
			continue;
		}
		if(objFinder.IsDirectory())
		{
			CString csFolderPath = objFinder.GetFilePath();
			EnumDBForSystemFiles(csFolderPath);
		}
		CString csFileName = objFinder.GetFileName();
		int iPos = csFileName.ReverseFind('.');
		if(iPos != -1)
		{
			csFileName = csFileName.Mid(iPos);
			if(csFileName == _T(".exe") || csFileName == _T(".dll"))
			{
				csFileName = objFinder.GetFilePath();
				CStringA csFilePath(csFileName);
				char cMD5Signature[33] = {0};
				TCHAR		szMD5[33] = {0};
				m_objMD5List.RemoveAll();
				if(GetMD5Signature32((LPCSTR)csFilePath, cMD5Signature))
				{	CString csLog;
					CString csSignature(cMD5Signature);
					_tcscpy_s(szMD5, MAX_PATH, (LPCTSTR)csSignature);
					csFileName.MakeLower();
					m_objMD5List.AppendItem(csSignature,L"md5");
					m_objHeurSysDb.AppendItem(csFileName,&m_objMD5List);
					iCount++;
				}
				
				
			}
		}
		
	}
	return true;
}
bool CWatchDogServiceApp::CreateDBForSystemFiles()
{
	CString csDBPath = CSystemInfo::m_strAppPath + _T("Tools\\HeuristicSysDB.db");	
	int iCount = 0;
	if(_waccess_s(csDBPath, 0) == 0)
	{		
		return false;
	}
	
	m_objHeurSysDb.RemoveAll();
	m_objMD5List.RemoveAll();
	

	TCHAR	szSysPath[MAX_PATH] = {0x00};
	//GetSystemDirectory(szSysPath, _countof(szSysPath));
	UINT uRetVal = GetWindowsDirectory(szSysPath, MAX_PATH);	
	EnumDBForSystemFiles(szSysPath);
	m_objHeurSysDb.Save(csDBPath);

	m_objHeurSysDb.RemoveAll();
	m_objMD5List.RemoveAll();
	return false;
}
/*-------------------------------------------------------------------------------------
Function		: CreateDBForSystemFilesThread
In Parameters	: LPVOID lpParam
Out Parameters	: UINT
Purpose			: Thread for Creating SystemFiles DB and md5.
--------------------------------------------------------------------------------------*/

UINT CreateDBForSystemFilesThread(LPVOID lpParam)
{
	CRegistry objReg;
	Sleep(20 * 60 * 1000); 
	DWORD dwVal= 0;
	//objReg.Get(CSystemInfo::m_csProductRegKey, _T("DBForSystemFiles"), dwVal, HKEY_LOCAL_MACHINE);
	
	if(dwVal == 0)
	{
		theApp.CreateDBForSystemFiles();	
		//objReg.Set(CSystemInfo::m_csProductRegKey, _T("DBForSystemFiles"), 1, HKEY_LOCAL_MACHINE);
	}

	return 0;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckMD5MisMatch
	In Parameters	: CString csAppPath, const CString csFilePath
	Out Parameters	: bool
	Purpose			: Check files MD5 against MD5 from ini file
	Author			: Ravi
	Description		: Check MD5 of file for infection
--------------------------------------------------------------------------------------*/
bool CWatchDogServiceApp::CheckMD5MisMatch(CString csINIPath, const CString csFilePath)
{
	char szStrIniMD5[33] = {0};
	char szStrFileMD5[33] = {0};
	DWORD dwMD5Len = 33;
	CString csIniPath, csFileName;
	int iIndex = 0;
	
	bool bGotMD5 = GetMD5Signature32((CStringA)csFilePath, szStrFileMD5);

	if(!bGotMD5)
	{
		return true;
	}

	iIndex = csFilePath.ReverseFind(_T('.'));
	csFileName = csFilePath.Mid(iIndex - 6, 6);

	GetPrivateProfileStringA("Data", (CStringA)csFileName, "0", szStrIniMD5, dwMD5Len, (CStringA)csIniPath);
	
	if(_stricmp(szStrIniMD5, szStrFileMD5) != 0) //MD5 mismatch, file modified
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ProductResetIS
	In Parameters	: void
	Out Parameters	: bool
	Purpose			: Reset for ISPlatinum
	Author			: Ravi
	Description		: 
--------------------------------------------------------------------------------------*/
bool CWatchDogServiceApp::ProductResetIS()
{
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: LoadMergerThread
In Parameters	: LPVOID lpParam
Out Parameters	: UINT
Purpose			: Thread for merging updates.
--------------------------------------------------------------------------------------*/
UINT LoadMergerThread(LPVOID lpParam)
{
	theApp.LoadMerger();
	return 0;
}
/*-------------------------------------------------------------------------------------
	Function		: LoadMerger
	In Parameters	: void
	Out Parameters	: bool
	Purpose			: To load merger dll
	Author			: Ravi
	Description		: 
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::LoadMerger()
{
	// creating this object here so that all static members are initialized!
	while(true)
	{
		CSystemInfo oSysInfo;
		if(oSysInfo.m_strAppPath.Trim().GetLength() == 0)
		{
			Sleep(60000);
		}
		else
		{
			AddLogEntry(L"Application Installed Path: %s", oSysInfo.m_strAppPath, 0, true, LOG_DEBUG);
			break;
		}
	}

	CSystemInfo objSystemInfo;
	
	m_hMergerDll = ::LoadLibrary(_T("AuUpdateMrg.dll"));

	if(m_hMergerDll)
	{
		m_pMaxSecureDispatcher = (MAXSECUREDISPATCHER)GetProcAddress(m_hMergerDll, "MaxSecureDispatcher");
	}

	if(m_pMaxSecureDispatcher)
	{
		MAX_DISPATCH_MSG sMaxDispatchMessage;
		SecureZeroMemory(&sMaxDispatchMessage, sizeof(MAX_DISPATCH_MSG));
		sMaxDispatchMessage.eDispatch_Type = eLoadMerger;
		m_pMaxSecureDispatcher(&sMaxDispatchMessage, NULL);
	}
}

void CWatchDogServiceApp::UnLoadMerger()
{
	if(m_pMaxSecureDispatcher)
	{
		MAX_DISPATCH_MSG sMaxDispatchMessage;
		SecureZeroMemory(&sMaxDispatchMessage, sizeof(MAX_DISPATCH_MSG));
		sMaxDispatchMessage.eDispatch_Type = eUnLoadMerger;
		m_pMaxSecureDispatcher(&sMaxDispatchMessage, NULL);
		m_pMaxSecureDispatcher = NULL;
	}

	if(m_hMergerDll)
	{
		::FreeLibrary(m_hMergerDll);
		m_hMergerDll = NULL;
	}
}

/*-------------------------------------------------------------------------------------
Function		: LaunchWscSrvThread
In Parameters	: LPVOID lpParam
Out Parameters	: UINT
Purpose			: Thread for Wsc Service.
--------------------------------------------------------------------------------------*/
UINT LaunchWscSrvThread(LPVOID lpParam)
{
	theApp.WscSrvStart();
	return 0;
}

void CWatchDogServiceApp::WscSrvStart()
{
#ifdef WATCHDOGWSC				
	m_csProductName = L"";
	m_RemediationPath = L"";
	if(m_dwWin10 == 1)
	{
		//m_objWscRegMon.ManageWin10Upgrade();
		m_objWscRegMon.IniRegisterToWSC();
		m_objWscRegMon.RegisterForChangesWSC();
	}
#endif

}
void CWatchDogServiceApp::WscSrvStop()
{
#ifdef WATCHDOGWSC	
	if(m_dwWin10 == 1)
	{
		m_objWscRegMon.UnRegisterForChangesWSC();
	}
#endif
}
/*--------------------------------------------------------------------------------------
Function       : OnDataReceivedWscSrvCallBack
In Parameters  : LPVOID lpParam,
Out Parameters : void
Description    : Named Pipe Communication Callback function.
--------------------------------------------------------------------------------------*/
void CWatchDogServiceApp::OnDataReceivedWscSrvCallBack(LPVOID lpMaxParam)
{
	LPSHARED_ACTMON_SWITCH_DATA sMaxPipeData = (SHARED_ACTMON_SWITCH_DATA*)lpMaxParam;
	if(!sMaxPipeData)
	{
		return;
	}
	
	bool bResult = true;
	__try
	{
#ifdef WATCHDOGWSC	
		//Finished_LiveUpdate
		if(sMaxPipeData->eProcType == EnableDisablePlugin)
		{
			theApp.m_objWscRegMon.UnRegisterToWSC();
		}
		if(sMaxPipeData->eProcType == Finished_LiveUpdate)
		{
			theApp.m_objWscRegMon.IniRegisterToWSC();
		}
		if(sMaxPipeData->eProcType == AM_Notification)
		{
			theApp.m_objWscRegMon.NotifyExpireToWSC(sMaxPipeData->dwMonitorType);
		}
		else
		{
			OutputDebugString(L"Ws_SSMon");
			theApp.m_objWscRegMon.StartStopMonitor(sMaxPipeData->dwMonitorType,
															sMaxPipeData->bStatus,
															sMaxPipeData->bShutDownStatus,
															sMaxPipeData->eProcType,
															sMaxPipeData->dwPID);
		}
#endif		
		sMaxPipeData->bStatus = true;
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
										_T("MaxWscReg CallBack Mode")))
	{
		sMaxPipeData->bStatus = false;
	}

	__try
	{
		theApp.m_objMaxCommunicatorServer.SendResponse(sMaxPipeData);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
										_T("MaxWscReg CallBack Mode")))
	{
	}
}