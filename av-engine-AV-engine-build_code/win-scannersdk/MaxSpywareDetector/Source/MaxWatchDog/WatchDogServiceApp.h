/*======================================================================================
FILE             : WatchDogServiceApp.h
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
NOTES		     : Declaration of the WatchDog App Class for watchdog registration and crash handling mechanism
				   Launches Active Monitor
				   Launches AuScanner in Quarantine mode to quarantine files that required restart
				   Launches Scheduler Thread
				   Launches Live Update Thread
				   Launches Autoscan Thread
				   Launches Restor point thread
				   Launches Threat Community thread
VERSION HISTORY  : 
======================================================================================*/
#pragma once

#ifndef __AFXWIN_H__
#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include "MaxConstant.h"
#include "MaxCommunicatorServer.h"
#include "MaxCommunicator.h"
#include "S2S.h"
#include "SSS.h"
//#include <pcap.h>
#include <map>

#include "WscRegMon.h"

using namespace std;

typedef map<DWORD, MAX_WD_DATA> ProcessMapItem;
#define	MAX_SCANNER _T("AuScanner.exe")
const int MAX_BROADCAST_PIPES = 8;

class CWatchDogServiceApp : public CWinApp
{
public:
	CWatchDogServiceApp();
	~CWatchDogServiceApp();
	virtual BOOL InitInstance();

	void CreateWormstoDeleteINI(CString strINIPath);
	BOOL CWatchDogServiceApp::AddInRestartDeleteList(RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID, LPCTSTR szValue);
	void AddAutoRunInINI();
	void ResetPermission();

	static void DisplayProcessMap();

	// Static Methods
	static void OnDataReceivedCallBack(LPVOID sMaxPipeData);
	static void OnDataReceivedWscSrvCallBack(LPVOID sMaxPipeData);
	static bool LaunchScanner(LPCTSTR szCommandline);
	static bool IsScannerRunning(int nProcessType, bool bPerformAction = false, bool bKillHeuristic = false);
	static WCHAR m_strAppPath[MAX_PATH];
	static void OnWatchDogStatusReceiveCallback(LPVOID sMaxPipeData);
	static HANDLE m_hSingleEventHandler;
	static void HandleCrashEvent(MAX_WD_DATA &sWDData);

	static ProcessMapItem m_ProcessMapItem;
	static bool m_bShutDown;

	//static void ReloadAllDB();
	void ManageOther();
	bool SetWDShutDownStatus(DWORD dwValue);
	void SetGamingMode(ULONG ulVal);
	void CheckCleanLocalDB();
	void RemoveEntryFromLocalDB(LPCTSTR pszFilePath);
	void AddScannerID(CString &csData);
	void RemoveScannerID(CString &csData);
	CStringArray m_csarrScannerIDs;
	// Implementation
	DECLARE_MESSAGE_MAP()
private:
	bool GetWDShutDownStatus(DWORD &dwValue);
	void BroadcastToSDProcesses();

	CMaxCommunicatorServer m_objMaxCommunicatorServer;
	CMaxCommunicatorServer m_objMaxWatchDogServer;
	CMaxCommunicatorServer m_objMaxWscSrvServer;
	BOOL InstallSDDriver(CString csName, CString csPath);
	bool StartDriver(LPCTSTR sDriverName);

	DWORD m_CurrRDType;
	CS2S m_objFileList;
	CSSS m_objHeurSysDb;
	CS2S m_objMD5List;
	
	//pcap_t *m_pCapDev[NET_DEV_MAX];
	//pcap_if_t *m_pDevList;
	//CNetCapture *m_pCapThread[NET_DEV_MAX];
	int m_nCapCount;	
	static CWinThread *m_ParentalThread;
	static void ShowAutoUpdateSuccessDlg();	
	CWinThread *m_RestoreSystemDefaultsThread;
	CWinThread *m_SchedulerThread;
	CWinThread *m_LiveupdateThread;
	CWinThread *m_AutoScanThread;
	CWinThread *m_CreateDBForSystemFilesThread;
	CWinThread *m_SetupAutoLaunchThread;
	CWinThread *m_EnableFirewallThread;
	CWinThread *m_MemoryScanThread;
	CWinThread *m_WatchOtherAppsThread;
	CWinThread *m_BackGroundScanThread;
	CWinThread *m_CryptMonFolderCheckThread;
	CWinThread *m_LoadMergerThread;
	CWinThread *m_LaunchWscSrvThread;

	HMODULE m_hMergerDll;
	MAXSECUREDISPATCHER m_pMaxSecureDispatcher;

	void ProcessLine(PWCHAR wsLineRead, bool bFoldersOnly);
	void ProcessBuffer(PWCHAR pBuffer, ULONG ulSizeOfBuffer, bool bFoldersOnly);
	BOOL HandleEntry(CString csFileToOwn);
	BOOL TakeOwnership(LPCTSTR lpszFileToOwn);
	BOOL RemoveReparsePoint(LPCTSTR lpszFileToOwn);
	HANDLE m_hProcessToken;
	BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
	static void ResumeIdleScan();
	static void PauseIdleScan();

public:
	static void LaunchGUIApp(LPCTSTR szAppPath, LPCTSTR szParams);
	static void LaunchAppAsUser(LPCTSTR szAppPath, LPCTSTR szParams);
	static void EnableActiveProtection();
	void StopDrivers();
	static BOOL CopyProxySetting();
	void SetRegCopyPasteSetting(DWORD ulVal);
	static void DeleteAppCompatFlagsValues();
	static bool ShellExecuteApp(CString csAppPath,int uType);
	void SuspendAndTerminateAllThreads();
	void ReplicationSetting(DWORD dwVal);	
	bool ChangeServiceStartType(LPCTSTR sDriverName, LPCTSTR sDriverPath, DWORD dwStartType);
	bool CreateDBForSystemFiles();
	bool EnumDBForSystemFiles(CString csPath);
	bool CheckMD5MisMatch(CString csAppPath, const CString csFilePath);
	bool ProductResetIS();

	void LoadMerger();
	void UnLoadMerger();

	CString m_csProductName;
	CString m_RemediationPath;
	DWORD m_dwWin10;
	void WscSrvStart();
	void WscSrvStop();
	CWscRegMon m_objWscRegMon;
};

extern CWatchDogServiceApp theApp;