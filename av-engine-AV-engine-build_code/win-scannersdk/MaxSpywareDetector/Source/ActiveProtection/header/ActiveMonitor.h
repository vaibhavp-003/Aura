/*======================================================================================
   FILE				: ActiveMonitor.h
   ABSTRACT			: 
   DOCUMENTS		: 
   AUTHOR			: Darshan Singh Virdi
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
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

#include "EnumProcess.h"
#include "Registry.h"
#include "VerInfo.h"
#include "DBPathExpander.h"
#include "ExecuteProcess.h"
#include "SDSystemInfo.h"
#include "ResourceManager.h"
#include "S2U.h"
#include "S2S.h"
#include "RemoveDB.h"
#include "SUUU2Info.h"
#include "UUU2Info.h"
#include "UU2Info.h"
#include "U2Info.h"
#include "MaxScanner.h"
#include "ReferencesScanner.h"
#include "ThreatManager.h"
#include "SysFiles.h"
//#include "TextSpeaker.h"

#define AMTotalTypes 31

struct SpywareInfo
{
	int		eTypeOfScanner;
	TCHAR	strParentProcessName[MAX_PATH];
	TCHAR	strSpywareName[MAX_PATH];
	TCHAR	strMacroName[MAX_PATH];
	TCHAR	strSpywareValue[MAX_PATH];
	TCHAR	strTitle[MAX_PATH];
	ULONG	ulSpyID;
	int		nMsgInfo;
	int		nScannedBy;
	LPVOID	lpVoid;
	LPVOID  pMaxScanner;
	int		nAutoQuarantine;
	int		bDisplayNotification;
};

struct SpywareInfoEx
{
	int		eTypeOfScanner;
	TCHAR	strParentProcessName[MAX_PATH];
	TCHAR	strSpywareName[MAX_PATH];
	TCHAR	strMacroName[MAX_PATH];
	TCHAR	strSpywareValue[MAX_PATH];
	TCHAR	strTitle[MAX_PATH];
	ULONG	ulSpyID;
	int		nMsgInfo;
	int		nScannedBy;
	LPVOID	lpVoid;
	LPVOID  pMaxScanner;
	int		nAutoQuarantine;
	int		bDisplayNotification;
	PMAX_SCANNER_INFO pScanInfo;
};


class CActiveMonitor
{
public:	
	CEnumProcess				m_objEnumProc;
	CRegistry					m_objRegistry;
	//gds::CTextSpeaker			m_oTextSpeaker;

	CString						m_csMaxDBPath;

	CSystemInfo					m_objSysInfo;
	CResourceManager			m_objResourceManager;
	bool						m_bDisplayNotification;
	static HANDLE				m_hExcludeDBEvent;
	static HANDLE				m_hRecoverDBEvent;
	static HANDLE				m_hSingleScanAndRepair;
	
	CActiveMonitor();
	virtual ~CActiveMonitor();
	virtual bool StartMonitor() = 0;
	virtual bool StopMonitor() = 0;
	virtual bool HandleExisting() = 0;
	inline bool IsMonitoring(){return m_bIsMonitoring;}

	void SetShutDownStatus(bool bShutDownStatus);
	void DisplayNotification(CString csNotificationText);
	bool ReloadLoadExcludeDB();
	void LoadOldValues(CString csMainKey, CString csValue, CMapStringToString &valuesMap);
	void LoadAllOldValues(CString csMainKey, CMapStringToString &valuesMap);
	bool AddEntryInDB(LPSPY_ENTRY_INFO lpSpyEntry);
	bool m_bIsMonitoring;
	void SendScanStatusToUI(PMAX_SCANNER_INFO pScannerInfo, int iTypeOfCall, bool bDisplayPrompt = true);
	void RepairFile(SpywareInfoEx *pSpywareInfo);
	bool MakeNameSmall(LPCTSTR szName, LPTSTR szSmallName, DWORD cchSmallFilePath);

	static BOOL CALLBACK SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus = eStatus_NotApplicable, 
										const ULONG ulSpyName = 0, 
										HKEY Hive_Type = 0, const WCHAR *strKey = 0, const WCHAR *strValue = 0, 
										int Type_Of_Data = 0, LPBYTE lpbData = 0, int iSizeOfData = 0, 
										REG_FIX_OPTIONS *psReg_Fix_Options = 0, LPBYTE lpbReplaceData = 0, 
										int iSizeOfReplaceData = 0, PMAX_SCANNER_INFO pScanInfo= NULL);

	
protected:
	bool m_bAutoQuarantine = false;
	bool m_bPCShutDownStatus = false;
	CString m_csParentProcessName;

	void AddToThreadList(CWinThread *pThread);
	void CloseAllThreads();
	void CloseProcessedThreads();
	
	enum enumBackupType
	{
		NoBackup,
		TerminateProcess,
		TerminateProcessAndNotify,
		DeleteFile,
		BackupFileAndNotify,
		BackupRegistry
	};

	bool AddInExcludedApplication(CString &csSpyValue, DWORD  dwAllow);
    bool IsExcludedApplication(CString &csSpyValue , DWORD &dwAllow);
	bool AlreadyChecked(LPCTSTR csEntry, ULONG &ulSpyID, LPTSTR strSpyName);
	void SetEntryStatus(LPCTSTR csEntry, ULONG ulSpyID, LPCTSTR strSpyName);
	bool GetControlPath(CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID);
	bool GetSoftwarePath(CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID);
	bool GetSystemPath(CString &csRegistryEntry, CString &csReturnedPath);
	bool IsPathInteresting(CString &csRegistryEntry, int iBreakOffLen, LPCTSTR csInterestedPath);
	void ReportSpywareEntry(SD_Message_Info eTypeOfScanner, ULONG ulSpyID, CString csSpyValue, CString csTitle, int nAutoQurantine, enumBackupType eBackupType, int nMsgInfo, int nScannedBy, LPCTSTR strSpyName, LPCTSTR strMacroName, int iTypeOfCall, bool bDisplayPrompt = true, PMAX_SCANNER_INFO pScanInfo = NULL);
	
	bool AlreadyChecked(LPCTSTR csEntry, ULONG &ulSpyID, int &iMsgInfo, int &iScannedBy, LPTSTR strSpyName, LPTSTR strMacroName);
	void SetEntryStatus(LPCTSTR csEntry, ULONG &ulSpyID, int &iMsgInfo, int &iScannedBy, LPTSTR strSpyName, LPTSTR strMacroName);

	//For Home Page Notification
	void ReportSpywareEntry(SD_Message_Info eTypeOfScanner, CString strSpyName, CString csSpyValue, CString csTitle,int nAutoQurantine = 0, enumBackupType eBackupType = NoBackup);
	CString GetValueType(const long &lValueTypeID, bool bX64 = false);
	long GetValueTypeID(CString &csPath, CString &csFolderName);

	CMaxScanner *m_pMaxScanner = NULL;

	void FreeThreatManager();

private:
	CS2U m_objExistingStatus;
	CS2U m_objExistingMsgInfo;
	CS2U m_objExistingScannedBy;
	CS2S m_objExistingStatusThreatName;
	CS2S m_objExistingStatusMacroName;
	CExecuteProcess m_oExecuteProcess;
	static CThreatManager *m_pThreatManager;
	static CReferencesScanner *m_pReferencesScanner;
	static CSysFiles m_objSysFiles;

	void HandleHKLMOrUserPath(CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID);

	HANDLE m_hThreaadEvent = NULL;
	CPtrArray m_arrThreads;
	static CU2Info		m_objSpyFoundList;
	static ULONG		m_iIndex;

};
