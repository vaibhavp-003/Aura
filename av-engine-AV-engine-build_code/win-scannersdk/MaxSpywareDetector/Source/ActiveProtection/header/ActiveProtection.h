/*======================================================================================
FILE			: ActiveProtection.h
ABSTRACT		: 
DOCUMENTS		: 
AUTHOR			: Darshan Singh Virdi
COMPANY			: Aura 
COPYRIGHT NOTICE: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE	: 20 Jan 2008
NOTES			: 
VERSION HISTORY	: 
=====================================================================================*/

#pragma once
#include "SDSystemInfo.h"
#include "EnumProcess.h"
#include "ProcessMonitor.h"
#include "HomePageMonitor.h"
#include "WinRestrictionMonitor.h"
#include "IERestrictionMonitor.h"
#include "CookieMonitor.h"
#include "NetworkConnectionMonitor.h"
#include "FileSystemMonitor.h"
#include "FileAssociationMonitor.h"
#include "MaxWhiteListMgr.h"
#include "MaxFileShareInfo.h"
#include "ActMonScanQueueMgr.h"

#ifdef USING_FLTMGR
#include <fltuser.h>
#endif //USING_FLTMGR

#include "SDActMonConstants.h"
#include "resource.h"

const int MAX_TRUST_POOL = 7;

typedef struct _MAX_NWRK_SCAN_INFO
{
	TCHAR	szFile2Scan[1024];
	TCHAR	szCompName[MAX_PATH];
	TCHAR   szIPAddress[MAX_PATH];
}MAX_NWRK_SCAN_INFO,*LPMAX_NWRK_SCAN_INFO;

class CActiveProtectionApp : public CWinApp
{
public:	

	static HANDLE m_hEvent;
	bool m_bPauseIdleScan;

	bool GetDriveLetterPath(CString &csDevicePath);
	void GetDriveLetterList();
#ifdef USING_FLTMGR
	HANDLE m_hEventFilterDriver;
	
	BOOL HandleNotification(PSDACTMON_NOTIFICATION pNotification);
	CWinThread* m_pMonitoringThread;
#else
	void ProcessMonitorLoop();
	void RegistryKeyMonitorLoop();
	void RegistryValueMonitorLoop();
	CWinThread *m_pProcMonitor, *m_pRegKeyMonitor, *m_pRegValueMonitor;
#endif

	//	Active Monitor Driver related data members and functions

	CActiveProtectionApp();
	virtual ~CActiveProtectionApp();

	bool StartMonitor(int iMonitorType, LPVOID pMessageHandler, LPVOID lpThis);
	bool StopMonitor(int iMonitorType , bool bPCShutDowbStatus = false);

	// Overrides
	virtual BOOL InitInstance();
	virtual int ExitInstance();

	//For AppWhiteListing
	CMaxWhiteListMgr m_objMaxWhiteListMgr;
	bool ScanNwtFile();

	CStringArray csArrLogicalDriver;
	BOOL m_bRanRegValue;	
	bool ResetRanRegValue();

	DECLARE_MESSAGE_MAP()

private:
	bool						m_bRunningWin2k;
	bool						m_bDisplayNotification;
	CProcessMonitor				*pProcMonitor;
	CHomePageMonitor			*pHomePageMonitor;
	CWinRestrictionMonitor		*pWinRestrictionMonitor;
	CIERestrictionMonitor		*pIERestrictionMonitor;
	CCookieMonitor				*pCookieMonitor;
	CNetworkConnectionMonitor	*pNetworkConnectionMonitor;
	CFileSystemMonitor			*pFileSystemMonitor;
	CFileAssociationMonitor		*pFileAssociationMonitor;

	HANDLE m_hDriver;
	bool InstallDriver(LPCTSTR sDriverFileName, LPCTSTR sDriverName, bool bAddAltitude);
	bool UninstallDriver(LPCTSTR sDriverName);

	bool StartDriver(LPCTSTR sDriverName);
	bool StopDriver(LPCTSTR sDriverName);
	bool StopRunningDriver(LPCTSTR sDriverName);

#ifndef USING_FLTMGR
	bool CreateAllEvents();
	void CleanUpEvent(HANDLE &hEvent);
#endif

	bool SetGamingMode(bool bStatus);

	bool InitialiseMonitor(CActiveMonitor *&pMonitor);
	void CleanUp(CActiveMonitor *&pMonitor);
	void SetDisplayNotification(CActiveMonitor *pMonitor, bool bStatus);
	bool UnInitialiseMonitor(CActiveMonitor *&pMonitor );
	void StopDriver(int iCurrentMonitorType);
	bool ReloadExcludeDatabase(CActiveMonitor *&pMonitor);

	CEnumProcess m_objEnumProc;
	bool m_bPauseMonitor;
	bool m_bLoadingMonitor;
	bool m_bMonitorDriverNeeded;
	bool m_bPCShutDownStatus;
	bool m_bIsProcessLoopRunning;
	bool m_bIsRegistryKeyLoopRunning;
	bool m_bIsRegistryValueLoopRunning;	

#ifndef USING_FLTMGR
	//	Active Monitor Driver related data members and functions
	DWORD m_controlbuff[10];

	HANDLE m_hEventProcessCommunicationRead;
	HANDLE m_hEventRegKeyCommunicationRead;
	HANDLE m_hEventRegValCommunicationRead;
	HANDLE m_hEventProcessCommunicationWrite;
	HANDLE m_hEventRegKeyCommunicationWrite;
	HANDLE m_hEventRegValCommunicationWrite;
#endif

	bool SetupActiveMonitorDriver();
	void CleanUpActiveMonitorMonitor();

	bool	WriteUSBActivityLog(LPCTSTR pszEntry2Write);
	TCHAR	m_szLastUSBActivity[1024];

	CString		m_szSharedFileName;
	//CString		m_szNwtkFile2Scan;
	DWORD		m_dwSharedFileCallCnt;

	MAX_NWRK_SCAN_INFO	m_objNwrkFile;

	BOOL IsFileofInterest(LPCTSTR pszFile2Check);

	CActMonScanQueueMgr	m_objScanQueMgr;
};

extern CActiveProtectionApp theApp;