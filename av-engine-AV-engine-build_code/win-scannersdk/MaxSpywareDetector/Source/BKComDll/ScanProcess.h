/**
	\file ScanProcess.h
	\brief Header File of ScanProcess class
* FILE				 : ScanProcess.h
*
* AUTHOR		     : Core Development Team
* COMPANY		     : Aura 
*
* COPYRIGHT(NOTICE):
*				  (C) Aura
*				  Created in 2022 as an unpublished copyright work.  All rights reserved.
*				  This document and the information it contains is confidential and
*				  proprietary to Aura.  Hence, it may not be
*				  used, copied, reproduced, transmitted, or stored in any form or by any
*				  means, electronic, recording, photocopying, mechanical or otherwise,
*				  without the prior written permission of Aura.
*
* NOTES		     : Class to communicate with UI to start scanning
 */
#pragma once
#include "ExportLog.h"
#include "U2S.h"
#include "ThreadSync.h"
#include "CheckDuplicates.h"
#include "SDScannerDB.h"
#include "MaxReportQMGR.h"


 /** \class CScanProcess
	 \brief A Functional Class of UI for scanning.
  */
class CScanProcess
{
public:
	CScanProcess();   // standard constructor
	~CScanProcess();

	static bool	m_bQFullDiskError;
	UScanStartInfo m_objScanStartInfo;

	TCHAR m_szReportPathBuffer[MAX_PATH];
	CMaxReportQMGR	m_objReport;

	/** \fn StartScan(CString csDrive, bool bSignatureScan = false, bool bVirusScan = false, bool bRootkitScan = false, bool bKeyLoggerScan = false, bool bHeuristicScan = false, bool bDBScan = false, bool bCustomScan = false, bool bDeepScan = false, bool bAutoQuarantine = false)
  *	 \brief Function create a structure and send it to scanner
  *	 \param LPVOID sMaxPipeData (PIPE Data structure)
  */
	void StartScan(CString csDrive, bool bSignatureScan = false, bool bVirusScan = false, bool bRootkitScan = false, bool bKeyLoggerScan = false, bool bHeuristicScan = false, bool bDBScan = false, bool bCustomScan = false, bool bDeepScan = false, bool bAutoQuarantine = false);
	void CheckAndExitScanner(void);
	bool CallScanFromUI();
	void DestroyCommObject();
	void HandleScannerData(LPVOID lpParam);
	bool UICloseEvent();

	int IsScannerRunning();
	void DoQuarantineWork(DWORD dwQuarantineDataLength, DWORD* ptrQuarantineData, DWORD dwTotalCount, DWORD* ptrQuarantinedData);
	void ScanResumePause();
	void OnScanStop();

	bool AllocateMemoryForReport();
	bool DeallocateMemoryForReport();
	bool UpdateDetectionStatus(int iLoadMem);
	int CheckForStatus(eEntry_Status eStatus, SD_Message_Info eMessageInfo);

private:
	

	int			m_iScanType;
	bool		m_bScanInProgress;
	DWORD		m_dwSpywareFound;
	DWORD		m_dwQuarantineFailedCount;
	int			m_iPercentage;
	DWORD		m_dwFilesScanned;
	CString		m_csDriveNames;
	bool		m_bStopScanning;
	bool		m_bDoKeyLoggerScan;
	bool		m_bDoVirusScan;
	bool		m_bPauseScanning;
	bool		m_bCriticalScan;
	bool		m_bVirusScan;
	BOOL		m_bShutdown;
	bool		m_bDeepScan;
	bool		m_bSignatureScan;
	long		m_nRegKeyValueInspected;
	long		m_nFileFolderInspected;
	//DWORD		m_dwThreatDetected;

	bool		m_bAppClosing;
	CString		m_csActionQuarantine;
	CString		m_csActionSystemFile;
	CString		m_csActionVirus;
	CString		m_csActionRootkit;
	
	bool		m_bSplSpywareFound;
	char		m_chScanFromUIStage;		// 0 - no scan started, 1 - scan from ui going on, 2 - scan from ui done and service scan on
	bool		m_bQuarantineStopped;
	bool		m_bRestartRequired;
	bool		m_bRestartEntryFound;
	int			m_iSuspendProcessCnt;
	DWORD		m_dwarrProcessID[1024];
	int			m_iCountSpywareFound;
	CString		m_csStatusText;
	bool		m_bRegisteredSession;
	bool		m_bisDiskFull;
	int			m_iSelectedCnt;
	bool		m_bQuarantineProcess;
	bool		m_bIsFullScanRequired;
	CU2S		m_objScanTextLookup;
	CThreadSync			m_objThreadSync;
	CCheckDuplicates	m_objReportedSpyMap;
	CString		m_csFolderToScan;
	int			m_iShowScanStatus;
	MAX_PIPE_DATA_REG	m_sScanRequest;
	CWinThread* m_pQuarantineThread;
	CWinThread* m_pScanFromUIThread;

	MAXSECUREDISPATCHER m_pMaxSecureDispatcher;

	bool m_bScanningProcess;
	

	CSDScannerDB		m_objScannerDB;
	bool m_bUIClose;
	bool		m_bScanningClosed;
	long		m_nProcessInspected;
	long		m_nCookiesInspected;
	
	bool m_bReportMemAllocate;
	
	bool CanTheScannerGoAhead();
	static UINT WDExecutionThread(LPVOID lParam);
	bool GetLatestOSName(CString& csOsVersion);
	//Reply From service
	void OnScanningFinishedPostMessage(WPARAM, LPARAM);
	static void OnScanDataReceivedCallBack(LPVOID lpParam);
	void ShowScannedData(MAX_PIPE_DATA_REG& sMaxPipeDataReg);
	void ShowScannedData(MAX_PIPE_DATA& sMaxPipeData);
	void CheckIfSpecialSpyware(SD_Message_Info eMessageInfo);
	void DeleteTemporaryAndInternetFiles(void);
	void HandleQuarantineRestart(ULONG ulQuarantinedCount, ULONG ulTotalCount);
	void DeleteCache();
	bool StopScanner(int iType);
	void PrepareForScan();
	void CheckFreeDiskSpace();
	DWORD64 GetFolderSize(LPCTSTR szPath, DWORD* dwFiles = 0, DWORD* dwFolders = 0);
	BOOL Delete(LPCTSTR lpDirectoryName, BOOL bSubDir);
	bool OnCompleteScheduleScan();
	void WriteSpywareCounts();
	void StartAutoScan();
	void StartManualScan();
	
	
	void SendQuarantineData(DWORD dwQuarantineDataLength, DWORD* ptrQuarantineData, DWORD dwTotalCount, DWORD* ptrQuarantinedData);
	bool AddSpecialSpywareNames(CMapStringToString& objSpecialSpyMap);
	void SetPercentage(int iPercentage);
};

