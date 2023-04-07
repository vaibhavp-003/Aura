/*======================================================================================
FILE				: ActiveMonitor.cpp
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
				Resource : sandip
				Description : Save SDMonRemoveDB at application path
				Version:1.0.0.6

				Resource : sandip
				Description : Handle End Now Conditon on ShutDown
				Version:1.0.0.8
				Description : Change code to monitor 64 bit path
				Version : 1.0.0.12
				Version: 19.0.0.73
				Date: 4-Feb-2009

				Resource: Ashwinee Jagtap
				Description: Modification in code for MultiLanguage Support.
=====================================================================================*/
#include "pch.h"
#include "ActiveMonitor.h"
#include "MaxCommunicator.h"
#include "MaxPipes.h"
#include "U2OS2U.h"
#include "SDSystemInfo.h"
#include <Atlbase.h>
#include "ActiveProtection.h"
#include "UserTrackingSystem.h"
#include "ProcessSync.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

UINT ThreadNotifyUser(LPVOID lpVoid);
HANDLE CActiveMonitor::m_hExcludeDBEvent = NULL;
HANDLE CActiveMonitor::m_hRecoverDBEvent = NULL;
HANDLE CActiveMonitor::m_hSingleScanAndRepair = NULL;
CSysFiles CActiveMonitor::m_objSysFiles;
CThreatManager *CActiveMonitor::m_pThreatManager = NULL;
CReferencesScanner *CActiveMonitor::m_pReferencesScanner = NULL;
CU2Info				CActiveMonitor::m_objSpyFoundList(true);
ULONG				CActiveMonitor::m_iIndex					= 0;
/*-------------------------------------------------------------------------------------
Function		:  CActiveMonitor
In Parameters	: -
Out Parameters	: -
Purpose			: CSDActiveMonitorApp initialization
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CActiveMonitor::CActiveMonitor():m_bIsMonitoring(false), m_bPCShutDownStatus(false),
								m_objExistingStatus(false), m_csParentProcessName(L""),
								m_objExistingMsgInfo(false), m_pMaxScanner(NULL),
								m_objExistingScannedBy(false), m_objExistingStatusThreatName(false),
								m_objExistingStatusMacroName(false)
{
	if(m_hExcludeDBEvent == NULL)
	{
		m_hExcludeDBEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
	}
	if(m_hRecoverDBEvent == NULL)
	{
		m_hRecoverDBEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
	}
	if(m_hSingleScanAndRepair == NULL)
	{
		m_hSingleScanAndRepair = CreateEvent(NULL, FALSE, TRUE, NULL);
	}
	m_objRegistry.Get(m_objSysInfo.m_csProductRegKey, CURRENT_MAX_DB_VAL, m_csMaxDBPath, HKEY_LOCAL_MACHINE);

	m_hThreaadEvent = CreateEvent(NULL, FALSE, TRUE, NULL);

	// Static function to set product key only once!
	CUserTrackingSystem oUserTrackingSystem;
	oUserTrackingSystem.SetProductKey(CSystemInfo::m_csProductName);
}

/*-------------------------------------------------------------------------------------
Function		: ~CActiveMonitor
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CActiveMonitor::~CActiveMonitor()
{
	m_objExistingStatus.RemoveAll();
	m_objExistingMsgInfo.RemoveAll();
	m_objExistingScannedBy.RemoveAll();
	m_objExistingStatusThreatName.RemoveAll();
	m_objExistingStatusMacroName.RemoveAll();

	CloseAllThreads();
	if(m_hThreaadEvent)
	{
		CloseHandle(m_hThreaadEvent);
		m_hThreaadEvent = NULL;
	}

	//Static handles, hence not closing handles
	//m_hExcludeDBEvent
	//m_hRecoverDBEvent
	//m_hSingleScanAndRepair
}

/*-------------------------------------------------------------------------------------
Function		: AlreadyChecked
In Parameters	: LPCTSTR csEntry, ULONG &ulSpyID
Out Parameters	: bool returns true if already checked else false.
Purpose			: for performance this function checks if the given entry is already 
					scanned, if yes then returns the spyware id we used to report
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveMonitor::AlreadyChecked(LPCTSTR csEntry, ULONG &ulSpyID, LPTSTR strSpyName)
{
	WaitForSingleObject(m_hExcludeDBEvent, INFINITE);
	bool bReturnVal = false;
	ulSpyID = 0;
	if(m_objExistingStatus.SearchItem(csEntry, &ulSpyID))
	{
		bReturnVal = true;
	}

	if(m_objExistingStatusThreatName.SearchItem(csEntry, strSpyName))
	{
		bReturnVal = true;
	}
	SetEvent(m_hExcludeDBEvent);
	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
Function		: AlreadyChecked
In Parameters	: LPCTSTR csEntry, ULONG &ulSpyID
Out Parameters	: bool returns true if already checked else false.
Purpose			: for performance this function checks if the given entry is already 
					scanned, if yes then returns the spyware id we used to report
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveMonitor::AlreadyChecked(LPCTSTR csEntry, ULONG &ulSpyID, int &iMsgInfo, 
									int &iScannedBy, LPTSTR strSpyName, LPTSTR strMacroName)
{
	WaitForSingleObject(m_hExcludeDBEvent, INFINITE);
	bool bReturnVal = false;

	ulSpyID = 0;
	if(m_objExistingStatus.SearchItem(csEntry, &ulSpyID))
	{
		bReturnVal = true;
	}

	DWORD dwMsgInfo = 0;
	if(m_objExistingMsgInfo.SearchItem(csEntry, &dwMsgInfo))
	{
		bReturnVal = true;
	}
	iMsgInfo = dwMsgInfo;

	DWORD dwScannedBy = 0;
	if(m_objExistingScannedBy.SearchItem(csEntry, &dwScannedBy))
	{
		bReturnVal = true;
	}
	iScannedBy = dwScannedBy;

	if(m_objExistingStatusThreatName.SearchItem(csEntry, strSpyName))
	{
		bReturnVal = true;
	}

	if(m_objExistingStatusMacroName.SearchItem(csEntry, strMacroName))
	{
		bReturnVal = true;
	}
	SetEvent(m_hExcludeDBEvent);
	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
Function		: ReloadLoadExcludeDB
In Parameters	: none
Out Parameters	: bool, always returns true
Purpose			: reloads the exclude database. used when any entry is excluded using 
					the ui
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveMonitor::ReloadLoadExcludeDB()
{
	WaitForSingleObject(m_hExcludeDBEvent, INFINITE);
	
	m_objExistingStatus.RemoveAll();
	m_objExistingMsgInfo.RemoveAll();
	m_objExistingScannedBy.RemoveAll();
	m_objExistingStatusThreatName.RemoveAll();
	m_objExistingStatusMacroName.RemoveAll();

	SetEvent(m_hExcludeDBEvent);
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: AddInExcludedApplication
In Parameters	: CString &csSpyValue, DWORD & dwAllow
Out Parameters	: bool returns true if the entry is excluded else false.
Purpose			: sets the entry in our database to allow or block the provided entry
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveMonitor::AddInExcludedApplication(CString &csSpyValue , DWORD dwAllow)
{
	csSpyValue.MakeLower();
	CS2U objHostData(false);
	objHostData.Load(m_csMaxDBPath + SD_DB_APP_EXCLUDE);
	objHostData.AppendItem(csSpyValue, dwAllow);
	objHostData.Save(m_csMaxDBPath + SD_DB_APP_EXCLUDE);
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: IsExcludedApplication
In Parameters	: CString &csSpyValue, DWORD & dwAllow
Out Parameters	: bool returns true if the entry is excluded else false.
Purpose			: checks if the provided entry is in our exclude database, this helps 
					user to exclude spyware entry in our database for him to run
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveMonitor::IsExcludedApplication(CString &csSpyValue, DWORD & dwAllow)
{
	bool bRet = false;
	csSpyValue.MakeLower();
	CS2U objHostData(false);
	if(objHostData.Load(m_csMaxDBPath + SD_DB_APP_EXCLUDE))
	{
		DWORD dwSpyName = 0;
		bRet = objHostData.SearchItem(csSpyValue, &dwSpyName);
		if(bRet)
		{
			dwAllow = dwSpyName;
		}
	}        
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: SetEntryStatus
In Parameters	: LPCTSTR csEntry, ULONG ulSpyID
Out Parameters	: void
Purpose			: Stores the spyware entry along with the spyware id in our database,
					this is used to show the same message again for the same entry
					without scanning it against our database for performance
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveMonitor::SetEntryStatus(LPCTSTR csEntry, ULONG ulSpyID, LPCTSTR strSpyName)
{
	WaitForSingleObject(m_hExcludeDBEvent, INFINITE);
	m_objExistingStatus.AppendItem(csEntry, ulSpyID);
	m_objExistingStatusThreatName.AppendItem(csEntry, strSpyName);
	SetEvent(m_hExcludeDBEvent);
}

/*-------------------------------------------------------------------------------------
Function		: SetEntryStatus
In Parameters	: LPCTSTR csEntry, ULONG ulSpyID
Out Parameters	: void
Purpose			: Stores the spyware entry along with the spyware id in our database,
					this is used to show the same message again for the same entry
					without scanning it against our database for performance
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveMonitor::SetEntryStatus(LPCTSTR csEntry, ULONG &ulSpyID, int &iMsgInfo, 
									int &iScannedBy, LPTSTR strSpyName, LPTSTR strMacroName)
{
	WaitForSingleObject(m_hExcludeDBEvent, INFINITE);
	m_objExistingStatus.AppendItem(csEntry, ulSpyID);
	m_objExistingMsgInfo.AppendItem(csEntry, iMsgInfo);
	m_objExistingScannedBy.AppendItem(csEntry, iScannedBy);
	m_objExistingStatusThreatName.AppendItem(csEntry, strSpyName);
	m_objExistingStatusMacroName.AppendItem(csEntry, strMacroName);
	SetEvent(m_hExcludeDBEvent);
}

/*-------------------------------------------------------------------------------------
Function		: DisplayNotification
In Parameters	: - CString csNotificationText
Out Parameters	: - void
Purpose			: SendData ( _NAMED_PIPE_ACTMON_TO_TRAY )
Author			: Nitin Shekokar
--------------------------------------------------------------------------------------*/
void CActiveMonitor::DisplayNotification(CString csNotificationText)
{
	try
	{
		if(!m_bDisplayNotification)
		{
			return;
		}

		CString csTrayPath;
		csTrayPath = m_objSysInfo.m_strAppPath;
		csTrayPath += ACT_MON_TRAY_EXE;
		CString csParam(_T("-"));

		csParam += CSystemInfo::m_csProductName;
		csParam += _T(";") + csNotificationText + _T(";HYPERLINKFALSE");

		AM_MESSAGE_DATA sAMMsgData = {0};
		sAMMsgData.dwMsgType = AM_Notification;

		if(csParam.GetLength() <= MAX_PATH*2)
		{
			_tcscpy_s(sAMMsgData.szNewValue, MAX_PATH*2, csParam);
			CMaxCommunicator objTrayBroadcast(_NAMED_PIPE_ACTMON_TO_TRAY);
			objTrayBroadcast.SendData(&sAMMsgData, sizeof(AM_MESSAGE_DATA));
		}
	}
	catch(...)
	{
		AddLogEntry(_T("##### Exception caught in DisplayNotification: %s "),
					csNotificationText);
	}
	return;
}

/*-------------------------------------------------------------------------------------
Function		: HandleHKLMOrUserPath
In Parameters	: CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID
Out Parameters	: void
Purpose			: Removes the \registry\machine or \registry\user\sid from the given 
					registty entry
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveMonitor::HandleHKLMOrUserPath(CString &csRegistryEntry, CString &csReturnedPath,
										  CString &csUserSID)
{
	if(csRegistryEntry.Left(ACTMON_USER_LEN) == ACTMON_USER_KEY)
	{
		csReturnedPath = csRegistryEntry.Mid(ACTMON_USER_LEN);
		csUserSID = csReturnedPath.Left(csReturnedPath.Find('\\'));
		csReturnedPath = csReturnedPath.Mid(csReturnedPath.Find('\\') + 1);
	}
	else if(csRegistryEntry.Left(ACTMON_HKLM_LEN) == ACTMON_HKLM_KEY)
	{
		csReturnedPath = csRegistryEntry.Mid(ACTMON_HKLM_LEN);
	}
	else
	{
		csReturnedPath = csRegistryEntry;
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetControlPath
In Parameters	: CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID
Out Parameters	: bool return true if it is else false
Purpose			: This function will return true incase we find "CONTROL" in the 
					begning of the given registry entry
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveMonitor::GetControlPath(CString &csRegistryEntry, CString &csReturnedPath,
									CString &csUserSID)
{
	HandleHKLMOrUserPath(csRegistryEntry, csReturnedPath, csUserSID);

	if(csReturnedPath.Left(ACTMON_CTRL_LEN) == ACTMON_CTRL_KEY)
	{
		return true;
	}
	else
	{
		return false;
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetSoftwarePath
In Parameters	: CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID
Out Parameters	: bool return true if it is else false
Purpose			: This function will return true incase we find "SOFTWARE" in the 
					begning of the given registry entry
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveMonitor::GetSoftwarePath(CString &csRegistryEntry, CString &csReturnedPath,
									 CString &csUserSID)
{
	HandleHKLMOrUserPath(csRegistryEntry, csReturnedPath, csUserSID);

	if(csReturnedPath.Left(ACTMON_SOFT_LEN) == ACTMON_SOFT_KEY)
	{
		return true;
	}
	else
	{
		return false;
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetSystemPath
In Parameters	: CString &csRegistryEntry, CString &csReturnedPath
Out Parameters	: bool return true if it is else false
Purpose			: This function will return true incase we find "SYSTEM" in the 
					begning of the given registry entry
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveMonitor::GetSystemPath(CString &csRegistryEntry, CString &csReturnedPath)
{
	CString csUserSID;
	HandleHKLMOrUserPath(csRegistryEntry, csReturnedPath,csUserSID);

	if(csReturnedPath.Left(ACTMON_SYS_LEN) == ACTMON_SYS_KEY)
	{
		return true;
	}
	else
	{
		return false;
	}
}

/*-------------------------------------------------------------------------------------
Function		: IsPathInteresting
In Parameters	: CString &csRegistryEntry, int iBreakOffLen, LPCTSTR csInterestedPath
Out Parameters	: bool return true if it is else false
Purpose			: This function is used by all derieved class to check if the received
					event is interesting for their class to handle
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CActiveMonitor::IsPathInteresting(CString &csRegistryEntry, int iBreakOffLen,
										LPCTSTR csInterestedPath)
{
	if(csRegistryEntry.Left(iBreakOffLen) == csInterestedPath)
	{
		csRegistryEntry = csRegistryEntry.Mid(iBreakOffLen);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: ReportSpywareEntry
In Parameters	: ULONG ulSpyID, CString csSpyValue, CString csTitle, 
					enumBackupType eBackupType
Out Parameters	: UINT
Purpose			: This function is used by all derived classes to report any 
					entry to the UI
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveMonitor::ReportSpywareEntry(SD_Message_Info eTypeOfScanner, ULONG ulSpyID, CString csSpyValue, 
										CString csTitle, int nAutoQurantine, enumBackupType eBackupType,
										int nMsgInfo, int nScannedBy, LPCTSTR strSpyName, LPCTSTR strMacroName,
										int iTypeOfCall, bool bDisplayPrompt, PMAX_SCANNER_INFO pScanInfoOld)
{
	/////////////////////////////////// For ReportDB//////////////////////////////////////////////////
	m_objSpyFoundList.RemoveAll();
	m_iIndex = 0;
	time_t ltime=0;
	time(&ltime);

	SPY_ENTRY_INFO oDBObj = {0};
	oDBObj.eTypeOfEntry = eTypeOfScanner;
	oDBObj.dwSpywareID = ulSpyID;
	oDBObj.szKey = csSpyValue.GetBuffer();
	csSpyValue.ReleaseBuffer();
	oDBObj.szValue = (LPTSTR)strSpyName;
	oDBObj.ul64DateTime = ltime;
	oDBObj.byStatus = eStatus_Detected;
	m_objSpyFoundList.AppendItemAscOrder(++m_iIndex, &oDBObj);
	AddLogEntry(strSpyName);
	AddLogEntry(csSpyValue);
	try
	{
		CSUUU2Info objScanInfoR(false);
		CUUU2Info objDateInfoR(true);
		CUU2Info objTimeInfoR(true);
		
		CString csMachineID = L"";

		CRegistry objReg;
		if(!objReg.Get(CSystemInfo::m_csProductRegKey, L"MachineID", csMachineID, HKEY_LOCAL_MACHINE))
		{
			csMachineID = L"";
		}

		if(!m_objSpyFoundList.GetFirst())
		{
			AddLogEntry(_T("m_objSpyFoundList Empty"));
			SPY_ENTRY_INFO DummySpyInfo = {0};
			m_objSpyFoundList.AppendItem(((DWORD)-1), &DummySpyInfo);
		}

		time_t ltime = 0;
		time(&ltime);
		ULONG64 m_ulDate = 0;
		DWORD m_dwTime = 0;
		
		DateTimeForDB(ltime, m_ulDate, m_dwTime);
		SYSTEMTIME st;
		GetLocalTime(&st);
		m_dwTime = 1000*(m_dwTime)+st.wMilliseconds;
		
		objTimeInfoR.AppendItem(m_dwTime, m_objSpyFoundList);
		objDateInfoR.AppendItem(m_ulDate, objTimeInfoR);
		objScanInfoR.AppendItem(csMachineID, objDateInfoR);
		objScanInfoR.Balance();

		CSystemInfo objSysInfo;
		CString csExeInstallPath = objSysInfo.m_strAppPath;

		TCHAR szFullFilePath[MAX_PATH] = {0};
		swprintf(szFullFilePath, MAX_PATH, L"%s%s", CSystemInfo::m_strAppPath, L"ActmonDBLock.txt");
		//Lock Set to Saving SpyFoundActmon.DB
		CProcessSync oProcessSync;
		
		int	iCnt = 0x00;
		while(!oProcessSync.SetLock(szFullFilePath))
		{
			Sleep(5);
			iCnt++;
			if (iCnt++ > 25)
			{
				break;
			}
		}
		
		if(_waccess(csExeInstallPath + L"\\LogFolder" , 0) != 0)
		{
			::CreateDirectory(csExeInstallPath + L"\\LogFolder", NULL);
		}
		
		CSUUU2Info objFullScanInfo(false);
		objFullScanInfo.Load(csExeInstallPath + L"\\LogFolder\\SpyFoundAct.DB");
		objFullScanInfo.AppendObject(objScanInfoR);
		objFullScanInfo.Balance();
		objFullScanInfo.Save(csExeInstallPath + L"\\LogFolder\\SpyFoundAct.DB");
		m_objSpyFoundList.RemoveAll();
		m_iIndex = 0;
		
		//Releasing Lock 
		oProcessSync.ReleaseLock();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception in :: ActiveMonitor::SaveSpyFoundDB"));
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////

	if(m_csParentProcessName == BLANKSTRING)
	{
		m_csParentProcessName = _T("Explorer");
	}

	

	SpywareInfoEx *pSpywareInfo = new SpywareInfoEx;
	::ZeroMemory(pSpywareInfo,sizeof(SpywareInfoEx));
	if(pScanInfoOld != NULL && pSpywareInfo !=NULL)
	{
		pSpywareInfo->pScanInfo = new MAX_SCANNER_INFO;
		memcpy(pSpywareInfo->pScanInfo, pScanInfoOld, sizeof(MAX_SCANNER_INFO));
	}
	

	pSpywareInfo->lpVoid = this;
	pSpywareInfo->eTypeOfScanner = eTypeOfScanner;
	pSpywareInfo->pMaxScanner = m_pMaxScanner;
	pSpywareInfo->ulSpyID = ulSpyID;
	pSpywareInfo->nMsgInfo = nMsgInfo;
	pSpywareInfo->nScannedBy = nScannedBy;
	pSpywareInfo->nAutoQuarantine = nAutoQurantine;
	pSpywareInfo->bDisplayNotification = (m_bDisplayNotification && bDisplayPrompt);
	wcscpy_s(pSpywareInfo->strParentProcessName, MAX_PATH, m_csParentProcessName);
	wmemset(pSpywareInfo->strSpywareName, 0, MAX_PATH);
	wmemset(pSpywareInfo->strSpywareValue, 0, MAX_PATH);
	wmemset(pSpywareInfo->strTitle, 0, MAX_PATH);
	if(strSpyName)
	{
		wcscpy_s(pSpywareInfo->strSpywareName, MAX_PATH, strSpyName);
	}	
	if(strMacroName)
	{
		wcscpy_s(pSpywareInfo->strMacroName, MAX_PATH, strMacroName);
	}	
	//if SpyValue is greater than MAX_PATH then
	if(csSpyValue.GetLength() > MAX_PATH)
	{
		csSpyValue = csSpyValue.Left(MAX_PATH-2);
	}

	wcscpy_s(pSpywareInfo->strSpywareValue, MAX_PATH, csSpyValue);
	wcscpy_s(pSpywareInfo->strTitle, MAX_PATH, csTitle);
	
	AddLogEntry(L">>>>> Found Spyware Name: %s, Spyware Value %s", pSpywareInfo->strSpywareName, pSpywareInfo->strSpywareValue);

	if(eTypeOfScanner == Process)
	{
		time_t ltime=0;
		time(&ltime);
		SPY_ENTRY_INFO oDBObj = {0};
		oDBObj.eTypeOfEntry = eTypeOfScanner;
		oDBObj.dwSpywareID = ulSpyID;
		oDBObj.szKey = (LPTSTR)(LPCTSTR)csSpyValue;
		oDBObj.ul64DateTime = ltime;
		oDBObj.byStatus = eStatus_Detected;
		AddEntryInDB(&oDBObj);
	}

	CWinThread* pThread = NULL;
	switch(eBackupType)
	{
	case TerminateProcessAndNotify:
		{
			/*
			if(iTypeOfCall == CALL_TYPE_F_NEW_FILE)
			{
				ThreadNotifyUser((LPVOID)pSpywareInfo);
			}
			else
			{
				m_objEnumProc.IsProcessRunning(csSpyValue, true);
				pThread = AfxBeginThread(ThreadNotifyUser, (LPVOID)pSpywareInfo, THREAD_PRIORITY_LOWEST, NULL, CREATE_SUSPENDED, NULL);
			}
			*/
			if (iTypeOfCall != CALL_TYPE_F_NEW_FILE)
			{
				//m_objEnumProc.IsProcessRunning(csSpyValue, true);
			}
			
			ThreadNotifyUser((LPVOID)pSpywareInfo);

		}
		break;
	case TerminateProcess:
		{

			pSpywareInfo->bDisplayNotification = false;
			/*
			if(iTypeOfCall == CALL_TYPE_F_NEW_FILE)
			{
				ThreadNotifyUser((LPVOID)pSpywareInfo);
			}
			else
			{
				m_objEnumProc.IsProcessRunning(csSpyValue, true);
				pThread = AfxBeginThread(ThreadNotifyUser, (LPVOID)pSpywareInfo, THREAD_PRIORITY_LOWEST, NULL, CREATE_SUSPENDED, NULL);
			}
			*/
			if (iTypeOfCall != CALL_TYPE_F_NEW_FILE)
			{
				//m_objEnumProc.IsProcessRunning(csSpyValue, true);
			}

			ThreadNotifyUser((LPVOID)pSpywareInfo);
		}
		break;
	case NoBackup:
		{
			/*
			if(iTypeOfCall == CALL_TYPE_F_NEW_FILE || iTypeOfCall == CALL_TYPE_N_CREATE)
			{
				ThreadNotifyUser((LPVOID)pSpywareInfo);
			}
			else
			{
				pThread = AfxBeginThread(ThreadNotifyUser, (LPVOID)pSpywareInfo, THREAD_PRIORITY_LOWEST, NULL, CREATE_SUSPENDED, NULL);
			}
			*/
			ThreadNotifyUser((LPVOID)pSpywareInfo);
		}
		break;
	}
	/*
	if(pThread)
	{
		pThread->m_bAutoDelete = FALSE;
		pThread->ResumeThread();
		WaitForSingleObject(m_hThreaadEvent, INFINITE);
		m_arrThreads.Add(pThread);
		SetEvent(m_hThreaadEvent);
	}
	*/
	m_csParentProcessName = BLANKSTRING;
}

/*-------------------------------------------------------------------------------------
Function		: ReportSpywareEntry
In Parameters	: CString strSpyName, CString csSpyValue, CString csTitle, 
					enumBackupType eBackupType
Out Parameters	: UINT
Purpose			: This function is used by all derived classes to report any entry
					to the UI
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CActiveMonitor::ReportSpywareEntry(SD_Message_Info eTypeOfScanner,CString strSpyName, CString csSpyValue, 
										CString csTitle,int nAutoQurantine, enumBackupType eBackupType)
{
	if(m_csParentProcessName == BLANKSTRING)
	{
		m_csParentProcessName = _T("Explorer.exe");
	}

	SpywareInfo *pSpywareInfo = new SpywareInfo;
	::ZeroMemory(pSpywareInfo,sizeof(SpywareInfo));
	pSpywareInfo->lpVoid = this;
	pSpywareInfo->eTypeOfScanner = eTypeOfScanner;
	wcscpy_s(pSpywareInfo->strParentProcessName, MAX_PATH, m_csParentProcessName);
	wmemset(pSpywareInfo->strSpywareName, 0, MAX_PATH);
	pSpywareInfo->nMsgInfo = -1;
	pSpywareInfo->nScannedBy = -1;
	pSpywareInfo->nAutoQuarantine = 0;
	pSpywareInfo->bDisplayNotification = m_bDisplayNotification;

	//if SpyValue is greater than MAX_PATH then
	if(csSpyValue.GetLength() > MAX_PATH)
	{
		csSpyValue = csSpyValue.Left(MAX_PATH-2);
	}

	if(eTypeOfScanner == Process)
	{
		time_t ltime=0;
		time(&ltime);
		SPY_ENTRY_INFO oDBObj = {0};
		oDBObj.eTypeOfEntry = eTypeOfScanner;
		oDBObj.szSpyName = (LPTSTR)(LPCTSTR)strSpyName;
		oDBObj.szKey = (LPTSTR)(LPCTSTR)csSpyValue;
		oDBObj.ul64DateTime = ltime;
		oDBObj.byStatus = eStatus_Detected;
		AddEntryInDB(&oDBObj);
	}

	wmemset(pSpywareInfo->strSpywareValue, 0, MAX_PATH);
	wmemset(pSpywareInfo->strTitle, 0, MAX_PATH);
	wcscpy_s(pSpywareInfo->strSpywareName, MAX_PATH, strSpyName);
	wcscpy_s(pSpywareInfo->strSpywareValue, MAX_PATH, csSpyValue);
	wcscpy_s(pSpywareInfo->strTitle, MAX_PATH, csTitle);

	AddLogEntry(L">>>>> Found Spyware Name: %s, Spyware Value %s", pSpywareInfo->strSpywareName, pSpywareInfo->strSpywareValue);

	CWinThread* pThread = NULL;
	if(eBackupType == TerminateProcess)
	{
		m_objEnumProc.IsProcessRunning(csSpyValue, true);
		::ThreadNotifyUser((LPVOID)pSpywareInfo);
	}
	else if (eBackupType == NoBackup)
	{
		::ThreadNotifyUser((LPVOID)pSpywareInfo);
	}
	m_csParentProcessName = BLANKSTRING;
}

/*-------------------------------------------------------------------------------------
Function		: SetShutDownStatus
In Parameters	: bool bShutDownStatu
Out Parameters	: void
Purpose			: Set The Shut Down Status
Author			: Sandip
--------------------------------------------------------------------------------------*/
void CActiveMonitor::SetShutDownStatus(bool bShutDownStatus)
{
	m_bPCShutDownStatus = bShutDownStatus;
}

/*-------------------------------------------------------------------------------------
Function		: ThreadNotifyUser
In Parameters	: LPVOID lpVoid
Out Parameters	: UINT
Purpose			: using a thread to notify the user so multiple promots can be show at 
					the same time
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
UINT ThreadNotifyUser(LPVOID lpVoid)
{
	SpywareInfoEx *pSpywareInfo = (SpywareInfoEx *)lpVoid;
	if(pSpywareInfo)
	{
		CActiveMonitor *pThis = (CActiveMonitor *)pSpywareInfo->lpVoid;
		if(pThis)
		{
			try
			{
				if(pSpywareInfo->nAutoQuarantine)
				{
					pThis->RepairFile(pSpywareInfo);
				}

				TCHAR szShorPath[50] = {0};
				pThis->MakeNameSmall(pSpywareInfo->strSpywareValue, szShorPath, _countof(szShorPath));

				CString csSpywareValue, csSpyName, csTitle, csParentProc;
				csParentProc.Format(_T("%s"), pSpywareInfo->strParentProcessName);

				if((pSpywareInfo->nScannedBy == Detected_BY_Max_FileSig || pSpywareInfo->nScannedBy == Detected_BY_Max_FullFileSig || pSpywareInfo->nScannedBy == Detected_BY_Max_ML
					|| pSpywareInfo->nScannedBy == Detected_BY_Max_Yara || pSpywareInfo->nScannedBy == Detected_BY_Max_Pattern || pSpywareInfo->nScannedBy == Detected_BY_Max_Instant)
					&& (pSpywareInfo->ulSpyID > 0))
				{
					//pMaxScanner->GetThreatName(pSpywareInfo->ulSpyID, pSpywareInfo->strSpywareName);
					TCHAR		szMalwareName[100];
					_stprintf(szMalwareName,L"Trojan.Malware.%d.susgen",pSpywareInfo->ulSpyID);
					_tcscpy(pSpywareInfo->strSpywareName,szMalwareName);
				}

				csSpyName.Format(_T("%s"), pSpywareInfo->strSpywareName);
				csSpywareValue.Format(_T("%s"), szShorPath);
				csTitle.Format(_T("%s"), pSpywareInfo->strTitle);
				CMaxScanner *pMaxScanner = (CMaxScanner *)pSpywareInfo->pMaxScanner;


				if(pSpywareInfo->bDisplayNotification && pThis->m_bIsMonitoring)
				{
					//Display notification for System File Protection
					if(csTitle == _T("IDS_SYS_FILE_PROTECTION"))
					{
						CString csNotification;
						//csNotification.Format(pThis->m_objResourceManager.GetString(_T("IDS_SYS_FILE_PROTECTION_MSG")),csParentProc, csSpywareValue, csSpyName);
						csNotification.Format(pThis->m_objResourceManager.GetString(_T("IDS_SYS_FILE_PROTECTION_MSG")),csSpyName,csSpywareValue,csParentProc);
						csTitle = pThis->m_objResourceManager.GetString(csTitle);
						pThis->DisplayNotification(csTitle + ACTMON_DATA_SEPERATOR + csNotification);
					}
					else
					{
						DWORD dwLangCode = 0;
						pThis->m_objRegistry.Get(CSystemInfo::m_csProductRegKey, LANGUAGE, dwLangCode,
							HKEY_LOCAL_MACHINE);
						pThis->m_objResourceManager.UpdateCurrentLanguage(dwLangCode);
						csTitle = pThis->m_objResourceManager.GetString(csTitle);
						CString csText;
						if(!pSpywareInfo->nAutoQuarantine)
						{
							if(csSpywareValue != BLANKSTRING)
							{
								//csText.Format(pThis->m_objResourceManager.GetString(_T("IDS_SPYWARE_KILLED_MSG1")),csParentProc, csSpywareValue, csSpyName);
								csText.Format(pThis->m_objResourceManager.GetString(_T("IDS_SPYWARE_KILLED_MSG1")),csSpyName,csSpywareValue,csParentProc );
							}
							else
							{
								//csText.Format(pThis->m_objResourceManager.GetString(_T("IDS_SYS_FILE_PROTECTION_MSG")),csParentProc, csSpywareValue, csSpyName);
								csText.Format(pThis->m_objResourceManager.GetString(_T("IDS_SYS_FILE_PROTECTION_MSG")),csSpyName,csSpywareValue,csParentProc );
							}
						}
						else
						{
							//csText.Format(pThis->m_objResourceManager.GetString(_T("IDS_SPYWARE_KILLED_MSG2")),csParentProc, csSpywareValue, csSpyName);
							csText.Format(pThis->m_objResourceManager.GetString(_T("IDS_SPYWARE_KILLED_MSG2")),csSpyName, csSpywareValue, csParentProc);
						}
						pThis->DisplayNotification(csTitle + ACTMON_DATA_SEPERATOR + csText);
					}
				}
			}
			catch(...)
			{
				AddLogEntry(_T("ThreadNotifyUser: Exception caught at higher level! Notification may not have been shown!"));
			}
		}
		if (pSpywareInfo->pScanInfo != NULL)
		{
			delete pSpywareInfo->pScanInfo;
			pSpywareInfo->pScanInfo = NULL;
		}
		delete pSpywareInfo;
		pSpywareInfo = NULL;

	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: _LoadOldValues
In Parameters	:CString csMainKey : main key whose values have to be enumerated
CString csValue: value whose data is to be kept in map.
CtStringToString &valuesMap : map to store the enumerated values and their data
Out Parameters	: void
Purpose			: loads the value and data of a particular key
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CActiveMonitor::LoadOldValues(CString csMainKey, CString csValue, CMapStringToString &valuesMap)
{
	CRegistry objReg ;
	//read the hklm key.
	CString csData;
	objReg.Get(csMainKey,csValue,csData,HKEY_LOCAL_MACHINE);
	valuesMap.SetAt(L"hklm", csData);

	//read the .default data.
	csData = L"";
	objReg.Get(L".DEFAULT\\" + csMainKey,csValue,csData,HKEY_USERS);
	valuesMap.SetAt(L".default", csData);

	//get the list of profiles.
	CStringArray arrProfile ;
	objReg.EnumSubKeys(PROFILELIST_PATH,arrProfile,HKEY_LOCAL_MACHINE);
	if(arrProfile.GetCount() == 0)
	{
		return;
	}

	for(int iIndex = 0 ; iIndex < arrProfile.GetCount() ;iIndex++)
	{
		csData = L"";
		arrProfile[iIndex].MakeLower();
		objReg.Get(arrProfile[iIndex] + _T("\\") + csMainKey,csValue,csData,HKEY_USERS);
		valuesMap.SetAt(arrProfile[iIndex], csData);
	}
}

/*-------------------------------------------------------------------------------------
Function		: _LoadAllOldValues
In Parameters	:CString csMainKey : main key whose values have to be enumerated
CtStringToString &valuesMap : map to store the enumerated values and their data
Out Parameters	: void
Purpose			: loads all the values under a particular key
Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CActiveMonitor::LoadAllOldValues(CString csMainKey,CMapStringToString &valuesMap)
{
	CStringArray csArrValue, csArrData;	
	if(m_objRegistry.QueryDataValue(csMainKey, csArrValue, csArrData ,HKEY_LOCAL_MACHINE) == TRUE)
	{
		if(csArrValue.GetCount() == csArrData.GetCount())
		{
			for(int iCount=0;iCount<csArrValue.GetCount();iCount++)
			{
				valuesMap.SetAt(L"hklm-"+csMainKey.MakeLower() + csArrValue[iCount].MakeLower(),
								csArrData[iCount].MakeLower());
			}
		}	
	}
	//get the list of profiles.
	CStringArray arrProfile ;
	m_objRegistry.EnumSubKeys(PROFILELIST_PATH, arrProfile, HKEY_LOCAL_MACHINE);
	if(arrProfile.GetCount() == 0)
	{
		return;
	}

	for(int iNum = 0 ; iNum < arrProfile.GetCount() ;iNum++)
	{		
		csArrValue.RemoveAll();
		csArrData.RemoveAll();
		if(m_objRegistry.QueryDataValue(arrProfile[iNum] + _T("\\") + csMainKey, csArrValue,
										csArrData ,HKEY_USERS) == TRUE)
		{
			if(csArrValue.GetCount() == csArrData.GetCount())
			{
				for(int iCount=0;iCount<csArrValue.GetCount();iCount++)
				{
					valuesMap.SetAt(arrProfile[iNum].MakeLower() + L"-" + csMainKey.MakeLower() + 
									csArrValue[iCount].MakeLower(),csArrData[iCount].MakeLower());
				}
			}
		}
	}
}

bool CActiveMonitor::AddEntryInDB(LPSPY_ENTRY_INFO lpSpyEntry)
{
	CSUUU2Info objScanInfo(false);
	CUUU2Info objDate(true);
	CUU2Info objTime(true);
	CU2Info objSpyEntry(true);

	ULONG64 ulDate = 0;
	DWORD dwTime = 0, dwIndex = 1;
	LPSPY_ENTRY_INFO lpSpyEntryDummy = 0;

	TCHAR szMachineID[MAX_PATH]={0};
	ULONG ulBuffSize = MAX_PATH;
	CRegKey objRegKey;

	CSystemInfo objSysInfo;
	CString csDBPath = objSysInfo.m_strAppPath + _T("\\LogFolder\\ActMonSpyFound.DB");

	objScanInfo.Load(csDBPath);

	DateTimeForDB(lpSpyEntry->ul64DateTime, ulDate, dwTime);

	if(objScanInfo.SearchItem(szMachineID, objDate))
	{
		if(objDate.SearchItem(ulDate, objTime))
		{
			if(objTime.SearchItem(dwTime, objSpyEntry))
			{
				if(!objSpyEntry.SearchItem(dwIndex, lpSpyEntryDummy))
				{
					dwIndex = (objSpyEntry.GetCount() + 1);
					objSpyEntry.AppendItem(dwIndex, lpSpyEntry);
				}
			}
			else
			{
				objSpyEntry.AppendItem(dwIndex, lpSpyEntry);
				objTime.AppendItem(dwTime, objSpyEntry);
			}
		}
		else
		{
			objSpyEntry.AppendItem(dwIndex, lpSpyEntry);
			objTime.AppendItem(dwTime, objSpyEntry);
			objDate.AppendItem(ulDate, objTime);
		}
	}
	else
	{
		objSpyEntry.AppendItem(dwIndex, lpSpyEntry);
		objTime.AppendItem(dwTime, objSpyEntry);
		objDate.AppendItem(ulDate, objTime);
		objScanInfo.AppendItem(szMachineID, objDate);
	}
	objScanInfo.Balance();
	objScanInfo.Save(csDBPath);

	return true;
}

void CActiveMonitor::SendScanStatusToUI(PMAX_SCANNER_INFO pScannerInfo, int iTypeOfCall, bool bDisplayPrompt)
{
	if(pScannerInfo)
	{
		PMAX_SCANNER_INFO pHoldScanInfo = pScannerInfo;
		while(pScannerInfo)
		{
			if((!pScannerInfo->IsChildFile) && ((pScannerInfo->ThreatDetected == 1) || (pScannerInfo->ThreatSuspicious == 1)))
			{
				ReportSpywareEntry(pScannerInfo->eMessageInfo, pScannerInfo->ulThreatID, pScannerInfo->szFileToScan, _T("IDS_PROCESS_MONITOR"), 
						m_bAutoQuarantine, NoBackup, pScannerInfo->eScannerType, pScannerInfo->eDetectedBY, 
						pScannerInfo->szThreatName, pScannerInfo->szOLEMacroName, iTypeOfCall, bDisplayPrompt, pScannerInfo);
			}

			pScannerInfo = pScannerInfo->pNextScanInfo;
		}

		if(pHoldScanInfo->pNextScanInfo && pHoldScanInfo->FreeNextScanInfo)
		{
			pScannerInfo = pHoldScanInfo;
			pHoldScanInfo = pHoldScanInfo->pNextScanInfo;
			pScannerInfo->pNextScanInfo = NULL;
			pScannerInfo->FreeNextScanInfo = false;
			while(pHoldScanInfo)
			{
				pScannerInfo = pHoldScanInfo->pNextScanInfo;
				delete pHoldScanInfo;
				pHoldScanInfo = pScannerInfo;
			}
		}
	}
}

void CActiveMonitor::RepairFile(SpywareInfoEx *pSpywareInfo)
{
	WaitForSingleObject(m_hSingleScanAndRepair, INFINITE);
	MAX_SCANNER_INFO oScannerInfo = {0};
	_tcscpy_s(oScannerInfo.szFileToScan, pSpywareInfo->strSpywareValue);
	if (pSpywareInfo->pScanInfo != NULL)
	{
		memcpy(&oScannerInfo, pSpywareInfo->pScanInfo, sizeof(MAX_SCANNER_INFO));
	}
	oScannerInfo.AutoQuarantine = true;
	/////////oScannerInfo.eMessageInfo = Process;
	oScannerInfo.eScannerType = Scanner_Type_Max_ActMonProcScan;
	if((pSpywareInfo->nScannedBy == Detected_BY_Max_FileSig) || (pSpywareInfo->nScannedBy == Detected_BY_Max_FullFileSig) || (pSpywareInfo->nScannedBy == Detected_BY_Max_ML) || (pSpywareInfo->nScannedBy == Detected_BY_Max_Yara)
		&& (pSpywareInfo->ulSpyID > 0))
	{
		m_pMaxScanner->GetThreatName(pSpywareInfo->ulSpyID, pSpywareInfo->strSpywareName);
	}
	m_pMaxScanner->ScanFile(&oScannerInfo);

	if((oScannerInfo.eMessageInfo%2 == 0) && (oScannerInfo.eMessageInfo != Virus_File_Repair) && m_pMaxScanner->m_bRefScan )	// Changes done to avoid references at the time of execution
	{
		if(!m_pReferencesScanner)
		{
			m_pReferencesScanner = new CReferencesScanner();
			m_objSysFiles.LoadSysDB(m_csMaxDBPath);
		}
		m_pReferencesScanner->OldCheckAndReportReferences(pSpywareInfo->strSpywareValue, pSpywareInfo->ulSpyID, REF_ID_ALL, SendMessageToUI);
	}
	SetEvent(m_hSingleScanAndRepair);
}

/*--------------------------------------------------------------------------------------
Function       : CActiveMonitor::SendMessageToUI
In Parameters  : SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, 
					const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, 
					int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
					int iSizeOfReplaceData, 
Out Parameters : BOOL CALLBACK 
Description    : 
Author & Date  : Darshan Singh Virdi & 13 Feb, 2012.
--------------------------------------------------------------------------------------*/
BOOL CALLBACK CActiveMonitor::SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, 
											const ULONG ulSpyName, HKEY Hive_Type, const WCHAR *strKey, 
											const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, 
											int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, 
											LPBYTE lpbReplaceData, int iSizeOfReplaceData, PMAX_SCANNER_INFO pScanInfo)
{
	if(eTypeOfScanner%2 == 0)
	{
		TCHAR szReplaceFile[MAX_PATH] = {0};
		if(m_objSysFiles.CheckSystemFile(eTypeOfScanner, strKey, szReplaceFile, _countof(szReplaceFile)))
		{
			if(szReplaceFile[0])
			{
				//SendMessageToUI(System_File_Replace, eStatus, ulSpyName, 0, strKey, szReplaceFile);	// commented as we want to ignore infected files
				AddLogEntry(_T("SysFile-> %s"), strKey);
				AddLogEntry(_T("SysFile Replace-> %s"), szReplaceFile);
			}
			else
			{
				//SendMessageToUI(System_File_Replace_Report, eStatus, ulSpyName, 0, strKey);	// commented as we want to ignore infected files
				AddLogEntry(_T("SysFile: %s -> ReportOnly"), strKey);
			}
			return TRUE;
		}

		if(eTypeOfScanner < SD_Message_Info_TYPE_REG)		// Its a File system Message
		{
			MAX_PIPE_DATA pipeData = {0};
			pipeData.eMessageInfo = eTypeOfScanner;
			pipeData.ulSpyNameID = ulSpyName;
			pipeData.eStatus = eStatus;
			if(strKey)
			{
				_tcscpy_s(pipeData.strValue, MAX_PATH, strKey);
			}
			if(strValue)
			{
				_tcscpy_s(pipeData.strFreshFile, MAX_PATH, strValue);
			}
			if(!m_pThreatManager) m_pThreatManager = new CThreatManager(NULL);
			m_pThreatManager->PerformDBAction(&pipeData);
		}
		else if(eTypeOfScanner < SD_Message_Info_TYPE_INFO) // Its a Registry Message
		{
			MAX_PIPE_DATA_REG pipeData = {0};
			pipeData.eMessageInfo = eTypeOfScanner;
			pipeData.ulSpyNameID = ulSpyName;
			pipeData.eStatus = eStatus;
			pipeData.Hive_Type = Hive_Type;
			pipeData.iSizeOfData = iSizeOfData;
			pipeData.iSizeOfReplaceData = iSizeOfReplaceData;
			pipeData.Type_Of_Data = Type_Of_Data;
			if(strKey)
			{
				_tcscpy_s(pipeData.strKey, MAX_PATH, strKey);
			}
			if(strValue)
			{
				_tcscpy_s(pipeData.strValue, MAX_PATH, strValue);
			}
			if(lpbData)
			{
				if(iSizeOfData < sizeof(pipeData.bData))
				{
					memcpy_s(pipeData.bData, sizeof(pipeData.bData), lpbData, iSizeOfData);
				}
				else
				{
					return TRUE;
				}
			}
			if(psReg_Fix_Options)
			{
				memcpy_s(&pipeData.sReg_Fix_Options, sizeof(REG_FIX_OPTIONS), psReg_Fix_Options, sizeof(REG_FIX_OPTIONS));
			}
			if(lpbReplaceData)
			{
				if(iSizeOfReplaceData < sizeof(pipeData.bReplaceData))
				{
					memcpy_s(pipeData.bReplaceData, sizeof(pipeData.bReplaceData), lpbReplaceData, iSizeOfReplaceData);
				}
				else
				{
					return TRUE;
				}
			}
			if(!m_pThreatManager) m_pThreatManager = new CThreatManager(NULL);
			m_pThreatManager->PerformRegAction(&pipeData);
		}
	}
	return TRUE;
}

//Only process monitor can init Threat Manager, hence only he gets to free it
void CActiveMonitor::FreeThreatManager()
{
	if(m_pThreatManager)
	{
		delete m_pThreatManager;
		m_pThreatManager = NULL;
	}

	if(m_pReferencesScanner)
	{
		delete m_pReferencesScanner;
		m_pReferencesScanner = NULL;
		m_objSysFiles.UnloadSysDB();
	}
}

void CActiveMonitor::CloseAllThreads()
{
	WaitForSingleObject(m_hThreaadEvent, INFINITE);
	int iThreadCount = (int)m_arrThreads.GetCount();
	for(int iCount = iThreadCount; iCount > 0; iCount--)
	{
		CWinThread* pThread = (CWinThread*)m_arrThreads.GetAt(iCount-1);
		WaitForSingleObject(pThread->m_hThread, INFINITE);
		delete pThread;
		pThread = NULL;
	}
	m_arrThreads.RemoveAll();
	if(iThreadCount > 0)	// we have caught some trojan or virus need to save the quarantine DB!
	{
		// Creating this object will trigger the DB Server to save the quarantine DB!
		CMaxDSrvWrapper objMaxDSrvWrapper;
	}
	SetEvent(m_hThreaadEvent);
}

void CActiveMonitor::CloseProcessedThreads()
{
	WaitForSingleObject(m_hThreaadEvent, INFINITE);
	int iThreadCount = (int)m_arrThreads.GetCount();
	for(int iCount = iThreadCount; iCount > 0; iCount--)
	{
		CWinThread* pThread = (CWinThread*)m_arrThreads.GetAt(iCount-1);
		if(WaitForSingleObject(pThread->m_hThread, 5) == WAIT_OBJECT_0)
		{
			delete pThread;
			pThread = NULL;
			m_arrThreads.RemoveAt(iCount-1);
		}
	}
	if(iThreadCount > 0)	// we have caught some trojan or virus need to save the quarantine DB!
	{
		// Creating this object will trigger the DB Server to save the quarantine DB!
		CMaxDSrvWrapper objMaxDSrvWrapper;
	}
	SetEvent(m_hThreaadEvent);
}

bool CActiveMonitor::MakeNameSmall(LPCTSTR szName, LPTSTR szSmallName, DWORD cchSmallFilePath)
{
	try
	{
		DWORD dwRetValue = 0;

		if(cchSmallFilePath < 20)
		{
			return false;
		}
		else
		{
			TCHAR szFirstPath[] = _T("a:\\...");
			LPCTSTR szSecondPart = 0;

			for(szSecondPart = szName; szSecondPart;)
			{
				szSecondPart = _tcschr(szSecondPart + 1, _T('\\'));
				if(szSecondPart)
				{
					if(_tcslen(szSecondPart) + _tcslen(szFirstPath) < cchSmallFilePath)
					{
						break;
					}
				}
			}

			if(!szSecondPart)
			{
				szSecondPart = _tcsrchr(szName, _T('\\'));
				if(szSecondPart)
				{
					for(;szSecondPart && *szSecondPart; szSecondPart++)
					{
						if(_tcslen(szSecondPart) + _tcslen(szFirstPath) < cchSmallFilePath)
						{
							break;
						}
					}
				}
			}

			if(szSecondPart)
			{
				TCHAR szHoldName[MAX_PATH] = {0};

				if(_tcslen(szFirstPath) + _tcslen(szSecondPart) < _countof(szHoldName))
				{
					szFirstPath[0] = szName[0];
					_stprintf_s(szHoldName, _countof(szHoldName), _T("%s%s"), szFirstPath, szSecondPart);
					_tcscpy_s(szSmallName, cchSmallFilePath, szHoldName);
					return true;
				}
			}

			return false;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("##### Exception Caught in CActiveMonitor::MakeNameSmall!"));
		return false;
	}
}

void CActiveMonitor::AddToThreadList(CWinThread *pThread)
{
	WaitForSingleObject(m_hThreaadEvent, INFINITE);
	m_arrThreads.Add(pThread);
	SetEvent(m_hThreaadEvent);
}