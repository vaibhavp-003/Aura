/*=====================================================================================
   FILE				: CReferencesScanner.cpp
   ABSTRACT			: Reference scanner 
   DOCUMENTS		: Virus Scanner Design Document.doc
   AUTHOR			: Nitin Shekokar
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 19 Jan 2009
   VERSION HISTORY	:
=====================================================================================*/
#include "pch.h"
#include "ReferencesScanner.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*------------------------------------------------------------------------------------
Function		: CReferencesScanner
In Parameters	:
Out Parameters	:
Purpose			: Contructor for References scanner class
Author			: Nitin Shekokar
Description		: Contructor for References scanner class
--------------------------------------------------------------------------------------*/
CReferencesScanner::CReferencesScanner(void):m_oFileReferenceList(false)
{
	m_bStartReferencesCheck = false;
	m_bInitScanners = false;

	m_lpfnFileFound = NULL;
	m_lpThis = NULL;
	m_bStopScan = false;
}

CReferencesScanner::~CReferencesScanner(void)
{
	m_oFileReferenceList.RemoveAll();
}

void CReferencesScanner::DumpLog()
{
	WCHAR *wcsTemp = new WCHAR[MAX_PATH];
	wmemset(wcsTemp, 0, MAX_PATH);
	swprintf_s(wcsTemp, MAX_PATH, _T("TNF: %d, RIT: %d, RST: %d"), m_dwNoOfFilesSearched, m_dwRefInitTime, m_dwRefScanTime);
	AddLogEntry(wcsTemp, 0, 0, true, LOG_DEBUG);

	CTimeSpan ctTotalInitTime = (m_dwRefInitTime/1000);
	CTimeSpan ctTotalScanTime = (m_dwRefScanTime/1000);

	wmemset(wcsTemp, 0, MAX_PATH);
	swprintf_s(wcsTemp, MAX_PATH, _T("Total Reference Init Time : Hours: %02d, Minutes: %02d, Seconds: %02d\r\n\t\t\t\t  Total Reference Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d"),
				(DWORD)ctTotalInitTime.GetHours(), (DWORD)ctTotalInitTime.GetMinutes(), (DWORD)ctTotalInitTime.GetSeconds(),
				(DWORD)ctTotalScanTime.GetHours(), (DWORD)ctTotalScanTime.GetMinutes(), (DWORD)ctTotalScanTime.GetSeconds());
	AddLogEntry(wcsTemp, 0, 0, true, LOG_DEBUG);
	delete [] wcsTemp;
	wcsTemp = NULL;
}

void CReferencesScanner::SetCallbackForFiles(LPFN_FileFound lpfnFileFound, LPVOID lpThis)
{
	m_bStopScan = false;
	m_lpfnFileFound = lpfnFileFound;
	m_lpThis = lpThis;
}

/*-------------------------------------------------------------------------------
Function		: InitScanners
In Parameters	:
Out Parameters	: bool
Purpose			: Initialize Refrance Scanner
Author			: Nitin Shekokar
Description		: Initialize Refrance Scanner
-------------------------------------------------------------------------------*/
bool CReferencesScanner::InitScanners()
{
	m_dwRefInitTime = 0;
	m_dwRefScanTime = 0;
	m_dwNoOfFilesSearched = 0;
	m_lpRefSendMessageToUI = NULL;
	/*
	InitJobCheck();
	InitServicesCheck();
	InitAllUsersList();
	InitKeysList();
	InitImgFileExecOpt();
	InitMenuExtensionList();
	*/
	CWinThread *pInitThread = NULL;

	pInitThread = AfxBeginThread((AFX_THREADPROC)InitScannerThread,(LPVOID)this,THREAD_PRIORITY_NORMAL);
	if (pInitThread != NULL)
	{
		DWORD dwTimeOut = WaitForSingleObject(pInitThread->m_hThread,60000);
		if (dwTimeOut == WAIT_TIMEOUT)
		{
			if (pInitThread != NULL)
			{
				TerminateThread(pInitThread->m_hThread,0x00);
			}
		}
	}

	return (true);
}

int	InitScannerThread(LPVOID pThisptr)
{
	CReferencesScanner	*pTemp = (CReferencesScanner *)pThisptr;

	pTemp->InitReferenceScanner();

	return 0x0l;
}

bool CReferencesScanner::InitReferenceScanner()
{
	InitJobCheck();
	InitServicesCheck();
	InitAllUsersList();
	InitKeysList();
	InitImgFileExecOpt();
	InitMenuExtensionList();

	return true;
}

/*-------------------------------------------------------------------------------
Function		: OldCheckAndReportReferences
In Parameters	: LPCTSTR, LPCTSTR, DWORD, SENDSCANMESSAGE, LPVOID
Out Parameters	: bool
Purpose			: Function will Call refrances Functions
Author			: Nitin Shekokar
Description		: Check dwReferenceID and call respective function
-------------------------------------------------------------------------------*/
 bool CReferencesScanner::OldCheckAndReportReferences(LPCTSTR szInfectedFileName, ULONG ulSpyID,
												  DWORD dwReferenceID, SENDMESSAGETOUIMS lpSendMessageToUI)
{
	bool bRefFound = false;
	CString csFullKeyName = _T("");

	if(!szInfectedFileName || !*szInfectedFileName)
	{
		return true;
	}

	if(m_bStartReferencesCheck)
	{
		return true;
	}
	else
	{
		m_bStartReferencesCheck = true;
	}

	m_objFileUnderCheck = szInfectedFileName;
	m_objFileUnderCheck.MakeLower();

	if(!m_bInitScanners)
	{
		InitScanners();
		m_bInitScanners = true;
	}

	m_lpRefSendMessageToUI = lpSendMessageToUI;
	m_objRegHlp.SetReporter(lpSendMessageToUI);

	if(0 == ulSpyID)
	{
		ulSpyID = 295; // use trojan.agent when no id is available
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_INI))
	{
		if(CheckFileNameInIni(m_objFileUnderCheck, ulSpyID, _T("X:\\Autorun.inf")))
		{
			bRefFound = true;
		}
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_RUN))
	{
		CString csMainKey;

		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			for(INT_PTR j = 0, jTotal = m_csArrRunKeysList.GetCount(); j < jTotal; j++)
			{
				csMainKey = m_csArrUsersList[i] + BACK_SLASH + m_csArrRunKeysList[j];
				if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, csMainKey, HKEY_USERS))
				{
					bRefFound = true;
				}

				if(m_lpfnFileFound && m_bStopScan)
				{
					break;
				}
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}

		for(INT_PTR j = 0, jTotal = m_csArrRunKeysList.GetCount(); j < jTotal; j++)
		{
			csMainKey = m_csArrRunKeysList[j];
			if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID,csMainKey, HKEY_LOCAL_MACHINE))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_POL_EXP_RUN))
	{
		CString csMainKey;

		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + POL_EXPL_RUN_PATH;
			if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, csMainKey, HKEY_USERS))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

#ifdef WIN64
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + POL_EXPL_RUN_PATH_X64;
			if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, csMainKey, HKEY_USERS))
			{
				bRefFound = true;
			}
#endif
			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

		if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, POL_EXPL_RUN_PATH, HKEY_LOCAL_MACHINE))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, POL_EXPL_RUN_PATH_X64, HKEY_LOCAL_MACHINE))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_IMG_FILE))
	{
		for(INT_PTR i = 0, iTotal = m_csArrImgFileExecOptList.GetCount(); i < iTotal; i++)
		{
			if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, m_csArrImgFileExecOptList[i], HKEY_LOCAL_MACHINE))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_JOB))
	{
		if(CheckFileNameInJob(m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_SERVICES))
	{
		if(CheckForServices(m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_USER_INIT))
	{
		TCHAR szUserInitExe[MAX_PATH] = {0};

		GetSystemDirectory(szUserInitExe, _countof(szUserInitExe));
		_tcscat_s(szUserInitExe, _countof(szUserInitExe), _T("\\Userinit.exe,"));

		if(CheckFileNameInRegData(HKEY_LOCAL_MACHINE, WINLOGON_REG_KEY, _T("Userinit"), szUserInitExe,
									m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInRegData(HKEY_LOCAL_MACHINE, WINLOGON_REG_KEY_X64, _T("Userinit"), szUserInitExe,
									m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_SHELL))
	{
		if(CheckFileNameInRegData(HKEY_LOCAL_MACHINE, WINLOGON_REG_KEY, _T("Shell"), _T("Explorer.exe"),
									m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInRegData(HKEY_LOCAL_MACHINE, WINLOGON_REG_KEY_X64, _T("Shell"), _T("Explorer.exe"),
									m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_TASKMAN))
	{
		if(CheckFileNameInRegData(HKEY_LOCAL_MACHINE, WINLOGON_REG_KEY, _T("TaskMan"), _T(""),
									m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInRegData(HKEY_LOCAL_MACHINE, WINLOGON_REG_KEY_X64, _T("TaskMan"), _T(""),
									m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}
	
	if(CHECK_OPTION(dwReferenceID, REF_ID_BHO))
	{
		CString csMainKey;

		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + BHO_REGISTRY_PATH;
			if(CheckFileNameInCLSIDByRegKey(HKEY_USERS, csMainKey, m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

#ifdef WIN64
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + BHO_REGISTRY_PATH_X64;
			if(CheckFileNameInCLSIDByRegKey(HKEY_USERS, csMainKey, m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}
#endif

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

		if(CheckFileNameInCLSIDByRegKey(HKEY_LOCAL_MACHINE, BHO_REGISTRY_PATH, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInCLSIDByRegKey(HKEY_LOCAL_MACHINE, BHO_REGISTRY_PATH_X64, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_SSODL))
	{
		CString csMainKey;

		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + SSODL_PATH;
			if(CheckFileNameInCLSIDByRegData(HKEY_USERS, csMainKey, m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

#ifdef WIN64
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + SSODL_PATH_X64;
			if(CheckFileNameInCLSIDByRegData(HKEY_USERS, csMainKey, m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}
#endif

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

		if(CheckFileNameInCLSIDByRegData(HKEY_LOCAL_MACHINE, SSODL_PATH, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInCLSIDByRegData(HKEY_LOCAL_MACHINE, SSODL_PATH_X64, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_SEH))
	{
		CString csMainKey;

		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + SHELL_EXEC_HOOKS;
			if(CheckFileNameInCLSIDByRegValue(HKEY_USERS, csMainKey, m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

#ifdef WIN64
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + SHELL_EXEC_HOOKS_X64;
			if(CheckFileNameInCLSIDByRegValue(HKEY_USERS, csMainKey, m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}
#endif
			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

		if(CheckFileNameInCLSIDByRegValue(HKEY_LOCAL_MACHINE, SHELL_EXEC_HOOKS, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInCLSIDByRegValue(HKEY_LOCAL_MACHINE, SHELL_EXEC_HOOKS_X64, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_STS))
	{
		CString csMainKey;

		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + STS_PATH;
			if(CheckFileNameInCLSIDByRegValue(HKEY_USERS, csMainKey, m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

#ifdef WIN64
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + STS_PATH_X64;
			if(CheckFileNameInCLSIDByRegValue(HKEY_USERS, csMainKey, m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}
#endif
			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

		if(CheckFileNameInCLSIDByRegValue(HKEY_LOCAL_MACHINE, STS_PATH, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInCLSIDByRegValue(HKEY_LOCAL_MACHINE, STS_PATH_X64, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_APP_INIT))
	{
		if(CheckFileNameInRegData(HKEY_LOCAL_MACHINE, WNT_WINDOWS_PATH, _T("AppInit_Dlls"), _T("NoDefault"),
									m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInRegData(HKEY_LOCAL_MACHINE, WNT_WINDOWS_PATH_X64, _T("AppInit_Dlls"), _T("NoDefault"),
									m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_NOTIFY))
	{
		if(CheckFileNameInSubKey(m_objFileUnderCheck, ulSpyID, NOTIFY_MAIN_KEY, HKEY_LOCAL_MACHINE,	true))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInSubKey(m_objFileUnderCheck, ulSpyID, NOTIFY_MAIN_KEY_X64, HKEY_LOCAL_MACHINE,	true))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_TOOLBAR))
	{
		CString csMainKey;

		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			for(INT_PTR j = 0, jTotal = m_csArrToolbarList.GetCount(); j < jTotal; j++)
			{
				csMainKey = m_csArrUsersList[i] + BACK_SLASH + m_csArrToolbarList[j];
				if(CheckFileNameInCLSIDByRegValue(HKEY_USERS, csMainKey, m_objFileUnderCheck, ulSpyID))
				{
					bRefFound = true;
				}

				if(m_lpfnFileFound && m_bStopScan)
				{
					break;
				}
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}

		for(INT_PTR i = 0, iTotal = m_csArrToolbarList.GetCount(); i < iTotal; i++)
		{
			csMainKey = m_csArrToolbarList[i];
			if(CheckFileNameInCLSIDByRegValue(HKEY_LOCAL_MACHINE, csMainKey, m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_ACTIVEX))
	{
		if(CheckFileNameInCLSIDByRegKey(HKEY_LOCAL_MACHINE, ACTIVEX_REGISTRY_PATH, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInCLSIDByRegKey(HKEY_LOCAL_MACHINE, ACTIVEX_REGISTRY_PATH_X64, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_SHRD_DLLS))
	{
		if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, SHARED_DLLS_KEY_PATH, HKEY_LOCAL_MACHINE, true))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, SHARED_DLLS_KEY_PATH_X64, HKEY_LOCAL_MACHINE, true))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_MENU_EXT))
	{
		CString csKey;

		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			csKey = m_csArrUsersList[i] + BACK_SLASH + MEXT_CMD_KEY_PATH;
			if(CheckFileNameInCLSIDByRegValue(HKEY_USERS, csKey, m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

#ifdef WIN64
			csKey = m_csArrUsersList[i] + BACK_SLASH + MEXT_CMD_KEY_PATH_X64;
			if(CheckFileNameInCLSIDByRegValue(HKEY_USERS, csKey, m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}
#endif

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

		csKey = MEXT_CMD_KEY_PATH;
		if(CheckFileNameInCLSIDByRegValue(HKEY_LOCAL_MACHINE, csKey, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		csKey = MEXT_CMD_KEY_PATH_X64;
		if(CheckFileNameInCLSIDByRegValue(HKEY_USERS, csKey, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

		csKey = MENUEXTENSION_REGISTRY_INFO;
		if(CheckFileNameInCLSIDBySubKey(HKEY_LOCAL_MACHINE, csKey, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		csKey = MENUEXTENSION_REGISTRY_INFO_X64;
		if(CheckFileNameInCLSIDBySubKey(HKEY_LOCAL_MACHINE, csKey, m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_UNINSTALL))
	{
		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			csFullKeyName = m_csArrUsersList[i] + BACK_SLASH + UNINSTALL_PATH;
			if(CheckFileNameInSubKey(m_objFileUnderCheck, ulSpyID, csFullKeyName, HKEY_USERS, true))
			{
				bRefFound = true;
			}	

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

#ifdef WIN64
			csFullKeyName = m_csArrUsersList[i] + BACK_SLASH + UNINSTALL_PATH_X64;
			if(CheckFileNameInSubKey(m_objFileUnderCheck, ulSpyID, csFullKeyName, HKEY_USERS, true))
			{
				bRefFound = true;
			}
#endif

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

		if(CheckFileNameInSubKey(m_objFileUnderCheck, ulSpyID, UNINSTALL_PATH, HKEY_LOCAL_MACHINE, true))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInSubKey(m_objFileUnderCheck, ulSpyID, UNINSTALL_PATH_X64, HKEY_LOCAL_MACHINE, true))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_INST_COMP))
	{
		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			csFullKeyName = m_csArrUsersList[i] + BACK_SLASH + ACTIVESETUP_INSTALLCOMPONENTS;
			if(CheckFileNameInSubKey(m_objFileUnderCheck, ulSpyID, csFullKeyName, HKEY_USERS, true))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

#ifdef WIN64
			csFullKeyName = m_csArrUsersList[i] + BACK_SLASH + ACTIVESETUP_INSTALLCOMPONENTS_X64;
			if(CheckFileNameInSubKey(m_objFileUnderCheck, ulSpyID, csFullKeyName, HKEY_USERS, true))
			{
				bRefFound = true;
			}
#endif
			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

		if(CheckFileNameInSubKey(m_objFileUnderCheck, ulSpyID, ACTIVESETUP_INSTALLCOMPONENTS,
									HKEY_LOCAL_MACHINE, true))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInSubKey(m_objFileUnderCheck, ulSpyID, ACTIVESETUP_INSTALLCOMPONENTS_X64,
									HKEY_LOCAL_MACHINE, true))
		{
			bRefFound = true;
		}
#endif
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_HIDN_FLDR))
	{
		CheckFileForHiddenFolder(m_objFileUnderCheck);
	}

	if(m_lpfnFileFound && m_bStopScan)
	{
		m_bStartReferencesCheck = false;
		return false;
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_EXE_ASSOC))
	{
		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			csFullKeyName = m_csArrUsersList[i] + BACK_SLASH + EXE_ASSOC_COMMAND;
			if(CheckFileNameInRegData(HKEY_USERS, csFullKeyName, _T(""), _T("\"%1\" %*"),
									  m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

			csFullKeyName = m_csArrUsersList[i] + BACK_SLASH + EXEFILE_ASSOC_COMMAND;
			if(CheckFileNameInRegData(HKEY_USERS, csFullKeyName, _T(""), _T("\"%1\" %*"),
									  m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

#ifdef WIN64
			csFullKeyName = m_csArrUsersList[i] + BACK_SLASH + EXE_ASSOC_COMMAND_X64;
			if(CheckFileNameInRegData(HKEY_USERS, csFullKeyName, _T(""), _T("\"%1\" %*"),
									  m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

			csFullKeyName = m_csArrUsersList[i] + BACK_SLASH + EXEFILE_ASSOC_COMMAND_X64;
			if(CheckFileNameInRegData(HKEY_USERS, csFullKeyName, _T(""), _T("\"%1\" %*"),
									  m_objFileUnderCheck, ulSpyID))
			{
				bRefFound = true;
			}
#endif
		}

		if(CheckFileNameInRegData(HKEY_LOCAL_MACHINE, EXE_ASSOC_COMMAND, _T(""), _T("\"%1\" %*"),
								  m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}

#ifdef WIN64
		if(CheckFileNameInRegData(HKEY_LOCAL_MACHINE, EXE_ASSOC_COMMAND_X64, _T(""), _T("\"%1\" %*"),
								  m_objFileUnderCheck, ulSpyID))
		{
			bRefFound = true;
		}
#endif
	}

	if(CHECK_OPTION(dwReferenceID, REF_ID_LOAD_RUN))
	{
		if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, WNT_WINDOWS_PATH, HKEY_LOCAL_MACHINE))
		{
			bRefFound = true;
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			m_bStartReferencesCheck = false;
			return false;
		}

#ifdef WIN64
		if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, WNT_WINDOWS_PATH_X64, HKEY_LOCAL_MACHINE))
		{
			bRefFound = true;
		}
#endif

		CString csMainKey;
		for(INT_PTR i = 0, iTotal = m_csArrUsersList.GetCount(); i < iTotal; i++)
		{
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + WNT_WINDOWS_PATH;
			if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, csMainKey, HKEY_USERS))
			{
				bRefFound = true;
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}

#ifdef WIN64
			csMainKey = m_csArrUsersList[i] + BACK_SLASH + WNT_WINDOWS_PATH_X64;
			if(CheckFileNameInRegData(m_objFileUnderCheck, ulSpyID, csMainKey, HKEY_USERS))
			{
				bRefFound = true;
			}
#endif
			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}
	}

	m_bStartReferencesCheck = false;
	return bRefFound;
}

/*-----------------------------------------------------------------------------------
Function		: CheckFileNameInIni
In Parameters	: LPCTSTR, LPCTSTR, LPCTSTR
Out Parameters	: bool
Purpose			: Check infected file name in INI file
Author			: Nitin Shekokar
Description		: open Autorun.inf on root and envirment path and check infected file name in that
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::CheckFileNameInIni(LPCTSTR szInfectedFileName, 
											ULONG ulSpyID, LPCTSTR szINFFileName)
{
	bool bFound = false;
	TCHAR szValueList[MAX_PATH]={0};
	TCHAR szData [MAX_PATH]={0};
	TCHAR szFileFullPath[MAX_PATH]={0};
	CString csValueRead;
	CString csDataRead, csDataRead1;
	TCHAR* PtrValueList = NULL;
	CString csINFFileName = szINFFileName;
	CString csFileName = szInfectedFileName;

	csFileName.MakeLower();
	csINFFileName.SetAt(0, csFileName.GetAt (0));

	GetPrivateProfileString(_T("Autorun"), NULL, BLANKSTRING, szValueList, _countof (szValueList),
							csINFFileName);
	if(0 == szValueList[0])
	{
		return (false);
	}

	PtrValueList = szValueList;
	csValueRead = szValueList;
	while(csValueRead != BLANKSTRING)
	{
		memset(szData, 0, sizeof (szData));
		GetPrivateProfileString(_T("Autorun"), csValueRead, BLANKSTRING,
								szData, _countof (szData), csINFFileName);
		PtrValueList = PtrValueList +(csValueRead.GetLength() + 1);
		csValueRead = PtrValueList;

		if(0 == szData[0])
		{
			continue;
		}

		csDataRead = _T("");
		csDataRead.Format(_T("%c:\\%s"), csINFFileName.GetAt(0), szData);
		csDataRead.MakeLower();
		for(int i = 0, iMaxTry = 100; (i < iMaxTry) && (csDataRead.Replace(_T("\\\\"), _T("\\"))); i++);
		for(int i = 0, iMaxTry = 100; (i < iMaxTry) && (csDataRead.Replace(_T("//"), _T("\\"))); i++);

		csDataRead = m_objDBPathExpander.ExpandSystemPath(csDataRead, false);
		csDataRead.MakeLower();
		csDataRead1 = csDataRead;
		m_objRegPathExpander.DoesFileExist(csDataRead1);
		csDataRead1 = m_objRegPathExpander.m_csFileFound;
		csDataRead1.MakeLower();

		AddFileInList(csDataRead);
		AddFileInList(csDataRead1);
		//if(csDataRead.Find(csFileName) != -1)
		if((csDataRead == csFileName) || (csDataRead1 == csFileName))
		{
			RefSendMessageToUI(File, ulSpyID, csINFFileName);
			bFound = true;
			break;
		}

		memset(szFileFullPath, 0, sizeof (szFileFullPath));
		_tsearchenv_s(szData, _T("PATH"), szFileFullPath, _countof (szFileFullPath));
		if(0 == szFileFullPath[0])
		{
			continue;
		}

		csDataRead = szFileFullPath;
		csDataRead = m_objDBPathExpander.ExpandSystemPath(csDataRead, false);
		csDataRead.MakeLower();
		csDataRead1 = csDataRead;
		m_objRegPathExpander.DoesFileExist(csDataRead1);
		csDataRead1 = m_objRegPathExpander.m_csFileFound;
		csDataRead1.MakeLower();

		AddFileInList(csDataRead);
		AddFileInList(csDataRead1);
		//if(csDataRead.Find(csFileName) != -1)
		if((csDataRead == csFileName) || (csDataRead1 == csFileName))
		{
			RefSendMessageToUI (File, ulSpyID, csINFFileName);
			bFound = true;
			break;
		}
	}

	return bFound;
}

/*-----------------------------------------------------------------------------------
Function		: CheckFileNameInRegData
In Parameters	: LPCTSTR, LPCTSTR, LPCTSTR, bool
Out Parameters	: bool
Purpose			: Check infected file name in registry data
Author			: Anand
Description		: Check infected file name in registry data
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::CheckFileNameInRegData(HKEY hHive, LPCTSTR szRegKey, LPCTSTR szRegValue,
												LPCTSTR szDefaultRegData, LPCTSTR szFilePath,
												ULONG ulSpyID)
{
	int iContext = 0;
	bool bFound = false;
	CString csData;
	SD_Message_Info eEntryType = RegFix;
	CString csFileToSearch(szFilePath), csToken, csToken1, csOrgToken, csDataToReplace;
	REG_FIX_OPTIONS RegFixOpt = {FIX_TYPE_ALWAYS_FIX, FIX_ACTION_RESTORE};

	if(!m_objReg.Get(szRegKey, szRegValue, csData, hHive))
	{
		return false;
	}

	csData.MakeLower();
	csFileToSearch.MakeLower();
	csToken = csData.Tokenize(_T(",;"), iContext);
	while(BLANKSTRING != csToken)
	{
		csOrgToken = csToken;
		csToken = m_objDBPathExpander.ExpandSystemPath(csToken, false);

		csToken1 = csToken;
		m_objRegPathExpander.DoesFileExist(csToken1);
		csToken1 = m_objRegPathExpander.m_csFileFound;

		AddFileInList(csToken);
		AddFileInList(csToken1);

		if(m_lpfnFileFound)
		{
			m_lpfnFileFound(csToken, m_lpThis, m_bStopScan, 0, 0);
			m_lpfnFileFound(csToken1, m_lpThis, m_bStopScan, 0, 0);
		}
		else
		{
			if(((BLANKSTRING != csToken) && (csToken == csFileToSearch)) ||
			   ((BLANKSTRING != csToken1) && (csToken1 == csFileToSearch)))
			{
				bFound = true;
				if(0 == _tcscmp(szDefaultRegData, _T("NoDefault")))
				{
					if(0 == _tcscmp(szRegValue, _T("AppInit_Dlls")))
					{
						eEntryType = AppInit;
						csDataToReplace = csFileToSearch;
					}
					else
					{
						csDataToReplace = csData;
						csDataToReplace.Replace(csOrgToken + _T(","), _T(""));
						csDataToReplace.Replace(csOrgToken + _T(";"), _T(""));
						csDataToReplace.Replace(csOrgToken, _T(""));
					}
				}
				else
				{
					csDataToReplace = szDefaultRegData;
				}

				RefSendMessageToUI(eEntryType, ulSpyID, hHive, szRegKey, szRegValue, REG_SZ,
								(LPBYTE)(LPCTSTR)csData,(((int)_tcslen(csData))+1)*sizeof(TCHAR),
								&RegFixOpt, (LPBYTE)(LPCTSTR)csDataToReplace,
								(((int)_tcslen(csDataToReplace))+1)*sizeof(TCHAR));
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			break;
		}

		csToken = csData.Tokenize(_T(",;"), iContext);
	}

	return bFound;
}

/*-----------------------------------------------------------------------------------
Function		: CheckFileNameInRegData
In Parameters	: LPCTSTR szInfectedFileName, ULONG ulSpyID, LPCTSTR szRegKey, 
					HKEY hHive, bool bRecursive
Out Parameters	: bool
Purpose			: Check infected file name in registry data
Author			: Nitin Shekokar
Description		: enumerate all values of the key and check filename in regdata of all values
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::CheckFileNameInRegData(LPCTSTR szInfectedFileName, ULONG ulSpyID,
												LPCTSTR szRegKey, HKEY hHive, bool bCheckInValueAlso)
{
	CString csValue, csValue1, csData, csData1;
	vector<REG_VALUE_DATA> vecRegValues;
	bool bFound = false, bReportThis = false;

	m_objReg.EnumValues(szRegKey, vecRegValues, hHive);

	INT_PTR iKeyCount = vecRegValues.size();
	for(INT_PTR iKeyIndex = 0; iKeyIndex < iKeyCount; iKeyIndex++)
	{
		bReportThis = false;

		if(bCheckInValueAlso)
		{
			csValue = (TCHAR*)vecRegValues[iKeyIndex].strValue;
			if(csValue != BLANKSTRING)
			{
				csValue1 = csValue;

				csValue = m_objDBPathExpander.ExpandSystemPath(csValue, false);
				csValue.MakeLower();

				m_objRegPathExpander.DoesFileExist(csValue1);
				csValue1 = m_objRegPathExpander.m_csFileFound;
				csValue1.MakeLower();

				AddFileInList(csValue);
				AddFileInList(csValue1);

				if(m_lpfnFileFound)
				{
					m_lpfnFileFound(csValue, m_lpThis, m_bStopScan, 0, 0);
					m_lpfnFileFound(csValue1, m_lpThis, m_bStopScan, 0, 0);
				}
				else
				{
					if((csValue == szInfectedFileName) || (csValue1 == szInfectedFileName))
					{
						bReportThis = true;
					}
				}
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			break;
		}

		if(vecRegValues[iKeyIndex].Type_Of_Data == REG_SZ || vecRegValues[iKeyIndex].Type_Of_Data == REG_EXPAND_SZ)
		{
			csData = (TCHAR*)vecRegValues[iKeyIndex].bData;
			if(csData != BLANKSTRING)
			{
				csData1 = csData;

				csData = m_objDBPathExpander.ExpandSystemPath(csData, false);
				csData.MakeLower();

				m_objRegPathExpander.DoesFileExist(csData1);
				csData1 = m_objRegPathExpander.m_csFileFound;
				csData1.MakeLower();

				AddFileInList(csData);
				AddFileInList(csData1);

				if(m_lpfnFileFound)
				{
					m_lpfnFileFound(csData, m_lpThis, m_bStopScan, 0, 0);
					m_lpfnFileFound(csData1, m_lpThis, m_bStopScan, 0, 0);
				}
				else
				{
					if((csData == szInfectedFileName) || (csData1 == szInfectedFileName))
					{
						bReportThis = true;
					}
				}
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			break;
		}

		if(bReportThis)
		{
			RefSendMessageToUI(RegValue, ulSpyID, hHive, szRegKey, vecRegValues[iKeyIndex].strValue,
								vecRegValues[iKeyIndex].Type_Of_Data, vecRegValues[iKeyIndex].bData,
								vecRegValues[iKeyIndex].iSizeOfData);
			bFound = true;
		}
	}

	return bFound;
}

/*-----------------------------------------------------------------------------------
Function		: CheckFileNameInSubKey
In Parameters	: LPCTSTR szFilePath, ULONG ulSpyID, LPCTSTR szRegKey, HKEY hHive
Out Parameters	: bool
Purpose			: check filepath in subkeys
Author			: Anand
Description		: enumerate subkeys and call a function to check in each key
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::CheckFileNameInSubKey(LPCTSTR szFilePath, ULONG ulSpyID, LPCTSTR szRegKey,
											   HKEY hHive, bool bReportFullKey)
{
	CString csKey;
	bool bFound = false;
	CStringArray objSubKeyArr;

	if(!m_objReg.EnumSubKeys(szRegKey, objSubKeyArr, hHive))
	{
		return false;
	}

	for(INT_PTR i = 0, iTotal = objSubKeyArr.GetCount(); i < iTotal; i++)
	{
		csKey = CString(szRegKey) + BACK_SLASH + objSubKeyArr[i];

		if(CheckFileNameInRegData(szFilePath, ulSpyID, csKey, hHive, false))
		{
			bFound = true;

			if(bReportFullKey)
			{
				m_objRegHlp.EnumKeyNReportToUI(hHive, csKey, ulSpyID);
			}
		}
	}

	return bFound;
}

/*-----------------------------------------------------------------------------------
Function		: InitImgFileExecOpt
In Parameters	: void
Out Parameters	: bool
Purpose			: create list to scan
Author			: Anand Srivastava
Description		: create list of all ImageFileExecutionOptions subkeys to scan
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::InitImgFileExecOpt()
{
	CStringArray csArrSubKeys1, csArrSubKeys2;

	if(!m_objReg.EnumSubKeys(IMG_FILE_EXE_OPTS_PATH, csArrSubKeys1, HKEY_LOCAL_MACHINE))
	{
		return false;
	}

#ifdef WIN64
		m_objReg.EnumSubKeys(IMG_FILE_EXE_OPTS_PATH_X64, csArrSubKeys2, HKEY_LOCAL_MACHINE);
#endif

	m_csArrImgFileExecOptList.RemoveAll();

	for(INT_PTR i = 0, iTotal = csArrSubKeys1.GetCount(); i < iTotal; i++)
	{
		m_csArrImgFileExecOptList.Add(CString(IMG_FILE_EXE_OPTS_PATH) + BACK_SLASH + csArrSubKeys1[i]);
	}

	for(INT_PTR i = 0, iTotal = csArrSubKeys2.GetCount(); i < iTotal; i++)
	{
		m_csArrImgFileExecOptList.Add(CString(IMG_FILE_EXE_OPTS_PATH_X64) + BACK_SLASH + csArrSubKeys2[i]);
	}

	return true;
}

/*-----------------------------------------------------------------------------------
Function		: InitMenuExtensionList
In Parameters	: void
Out Parameters	: bool
Purpose			: create list to scan
Author			: Anand Srivastava
Description		: create list of all MenuExtension subkeys to scan
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::InitMenuExtensionList()
{
	CStringArray csArrSubKeys1, csArrSubKeys2;

	m_objReg.EnumSubKeys(MENUEXTENSION_REGISTRY_INFO, csArrSubKeys1, HKEY_LOCAL_MACHINE);
#ifdef WIN64
	m_objReg.EnumSubKeys(MENUEXTENSION_REGISTRY_INFO_X64, csArrSubKeys2, HKEY_LOCAL_MACHINE);
#endif

	m_csArrMenuExtList.RemoveAll();

	for(INT_PTR i = 0, iTotal = csArrSubKeys1.GetCount(); i < iTotal; i++)
	{
		m_csArrMenuExtList.Add(CString(MENUEXTENSION_REGISTRY_INFO) + BACK_SLASH + csArrSubKeys1[i]);
	}

	for(INT_PTR i = 0, iTotal = csArrSubKeys2.GetCount(); i < iTotal; i++)
	{
		m_csArrMenuExtList.Add(CString(MENUEXTENSION_REGISTRY_INFO_X64) + BACK_SLASH + csArrSubKeys2[i]);
	}

	return true;
}

/*-----------------------------------------------------------------------------------
Function		: InitKeysList
In Parameters	: void
Out Parameters	: bool
Purpose			: create list to scan
Author			: Anand Srivastava
Description		: create list of all keys to scan
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::InitKeysList()
{
	// Run keys
	m_csArrRunKeysList.Add(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
	m_csArrRunKeysList.Add(_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	m_csArrRunKeysList.Add(_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"));
	m_csArrRunKeysList.Add(_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
	m_csArrRunKeysList.Add(_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
#ifdef WIN64
	m_csArrRunKeysList.Add(_T("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"));
	m_csArrRunKeysList.Add(_T("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	m_csArrRunKeysList.Add(_T("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"));
	m_csArrRunKeysList.Add(_T("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
	m_csArrRunKeysList.Add(_T("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
#endif

	// Toolbar Keys
	m_csArrToolbarList.Add(_T("Software\\Microsoft\\Internet Explorer\\Toolbar"));
	m_csArrToolbarList.Add(_T("Software\\Microsoft\\Internet Explorer\\Toolbar\\Explorer"));
	m_csArrToolbarList.Add(_T("Software\\Microsoft\\Internet Explorer\\Toolbar\\ShellBrowser"));
	m_csArrToolbarList.Add(_T("Software\\Microsoft\\Internet Explorer\\Toolbar\\WebBrowser"));
#ifdef WIN64
	m_csArrToolbarList.Add(_T("Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar"));
	m_csArrToolbarList.Add(_T("Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar\\Explorer"));
	m_csArrToolbarList.Add(_T("Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar\\ShellBrowser"));
	m_csArrToolbarList.Add(_T("Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Toolbar\\WebBrowser"));
#endif

	return true;
}

/*-----------------------------------------------------------------------------------
Function		: InitAllUsersList
In Parameters	: void
Out Parameters	: bool
Purpose			: initialise all users
Author			: Anand Srivastava
Description		: initialise all users key list
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::InitAllUsersList()
{
	LPVOID lpContext = 0;
	CS2S objUsersList(false);
	LPTSTR szUserName = 0;

	m_objRegHlp.LoadAvailableUsers(objUsersList);

	lpContext = objUsersList.GetFirst();
	while(lpContext)
	{
		objUsersList.GetKey(lpContext, szUserName);
		if(szUserName)
		{
			m_csArrUsersList.Add(szUserName);
		}

		lpContext = objUsersList.GetNext(lpContext);
	}

	return true;
}

/*-----------------------------------------------------------------------------------
Function		: InitJobCheck
In Parameters	: void
Out Parameters	: bool
Purpose			: initialise job check
Author			: Nitin Shekokar
Description		: initialise job file names from.job files in win\task folder
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::InitJobCheck()
{
	CFileFind objFileFinder;
	BOOL bFileFound = FALSE;
	TCHAR szProgramFileName[MAX_PATH]={0};
	WORD wFileNameLength = 0;
	HANDLE hFile = NULL;
	DWORD dwBytesRead = 0;
	const DWORD dwFileNameLengthOffset = 0x46;
	const DWORD dwFileNameOffset = 0x48;
	CString csFullJobFileName, csFullJobFileName1;
	TCHAR szJobFileLocation[MAX_PATH] = {0};
	CString csFileName, csFileName1;

	GetWindowsDirectory(szJobFileLocation, _countof(szJobFileLocation));
	if(0 == szJobFileLocation[0])
	{
		return false;
	}

	if(_tcslen(szJobFileLocation) + _tcslen(_T("\\Tasks\\*.job")) >= _countof(szJobFileLocation))
	{
		return false;
	}

	_tcscat_s(szJobFileLocation, _T("\\Tasks\\*.job"));
	bFileFound = objFileFinder.FindFile(szJobFileLocation);
	if(bFileFound == FALSE)
	{
		return (false);
	}

	// loop for all job files
	while(bFileFound)
	{
		bFileFound = objFileFinder.FindNextFile();
		csFullJobFileName = objFileFinder.GetFilePath();

		// open the job file
		hFile = CreateFile(csFullJobFileName, GENERIC_READ, FILE_SHARE_READ, 0, 
							OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if(INVALID_HANDLE_VALUE == hFile)
		{
			continue;
		}

		// seek to filename length
		SetFilePointer(hFile, dwFileNameLengthOffset, 0, FILE_BEGIN);
		if(FALSE == ReadFile (hFile, &wFileNameLength, 2, &dwBytesRead, 0))
		{
			CloseHandle(hFile);
			continue;
		}

		if(dwBytesRead != 2)
		{
			CloseHandle(hFile);
			continue;
		}

		// check if buffer can hold the file name
		if((sizeof(szProgramFileName))< (wFileNameLength * 2))
		{
			CloseHandle(hFile);
			continue;
		}

		// seek to and read the filename
		SetFilePointer(hFile, dwFileNameOffset, 0, FILE_BEGIN);
		if(FALSE == ReadFile (hFile, szProgramFileName, wFileNameLength * 2, &dwBytesRead, 0))
		{
			CloseHandle(hFile);
			continue;
		}

		if(dwBytesRead != (wFileNameLength * 2))
		{
			CloseHandle(hFile);
			continue;
		}

		csFullJobFileName = m_objDBPathExpander.ExpandSystemPath(csFullJobFileName, false);
		csFullJobFileName.MakeLower();
		csFullJobFileName1 = csFullJobFileName;
		m_objRegPathExpander.DoesFileExist(csFullJobFileName1);
		csFullJobFileName1 = m_objRegPathExpander.m_csFileFound;
		csFullJobFileName1.MakeLower();
		AddFileInList(csFullJobFileName);
		m_csArrJobNames.Add(csFullJobFileName);
		AddFileInList(csFullJobFileName1);
		m_csArrJobNames.Add(csFullJobFileName1);

		csFileName = szProgramFileName;
		csFileName = m_objDBPathExpander.ExpandSystemPath(csFileName, false);
		csFileName.MakeLower();
		csFileName1 = csFileName;
		m_objRegPathExpander.DoesFileExist(csFileName1);
		csFileName1 = m_objRegPathExpander.m_csFileFound;
		csFileName1.MakeLower();
		AddFileInList(csFileName);
		m_csArrJobFileNames.Add(csFileName);
		AddFileInList(csFileName1);
		m_csArrJobFileNames.Add(csFileName1);

		CloseHandle(hFile);
	}

	objFileFinder.Close();
	return (true);
}

/*-----------------------------------------------------------------------------------
Function		: CheckFileNameInJob
In Parameters	: LPCTSTR, LPCTSTR
Out Parameters	: bool
Purpose			: Check infected file name in.job file
Author			: Nitin Shekokar
Description		: Check infected file name in.job file
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::CheckFileNameInJob(LPCTSTR szInfectedFileName, ULONG ulSpyID)
{
	for(INT_PTR iIndex = 0, iCount = m_csArrJobNames.GetCount(); iIndex < iCount; iIndex++)
	{
		if(!m_csArrJobFileNames.GetAt(iIndex).CompareNoCase(szInfectedFileName))
		{
			RefSendMessageToUI(File, ulSpyID, m_csArrJobNames.GetAt(iIndex));
		}
	}

	return (true);
}

/*-----------------------------------------------------------------------------------
Function		: RefSendMessageToUI
In Parameters	: const CString&, const CString&, ENUM_WORMTYPE
Out Parameters	: bool
Purpose			: Send infected file name, type to UI
Author			: Nitin Shekokar
Description		: Send infected file name, type to UI
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::RefSendMessageToUI(SD_Message_Info WormType, const ULONG ulSpyID,
											const CString& csFileName)
{
	if(NULL == m_lpRefSendMessageToUI)
	{
		return (false);
	}

	m_lpRefSendMessageToUI(WormType, eStatus_Detected, ulSpyID, 0, csFileName, 0, 0, 0, 0, 0, 0, 0, 0);
	AddLogEntry(_T("Found: %s"), csFileName);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : RefSendMessageToUI
In Parameters  : SD_Message_Info WormType, const ULONG ulSpyName, HKEY Hive_Type, const WCHAR *strKey, 
					const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, 
Out Parameters : bool 
Description    : 
Author         : Nitin Shekokar
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::RefSendMessageToUI(SD_Message_Info WormType, const ULONG ulSpyName, HKEY Hive_Type, 
											const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, 
											LPBYTE lpbData, int iSizeOfData)
{
	CString csLogString;

	if(NULL == m_lpRefSendMessageToUI)
	{
		return (false);
	}

	m_lpRefSendMessageToUI(WormType, eStatus_Detected, ulSpyName, Hive_Type, strKey, strValue, Type_Of_Data,
							lpbData, iSizeOfData, 0, 0, 0, 0);

	if(REG_SZ == Type_Of_Data && lpbData)
	{
		csLogString.Format(_T("Found: %s\\%s - %s - %s"), m_objReg.GetHiveName(Hive_Type),
							strKey, strValue, (LPCTSTR)lpbData);
	}
	else if(REG_DWORD == Type_Of_Data && lpbData)
	{
		csLogString.Format(_T("Found: %s\\%s - %s - %u"), m_objReg.GetHiveName(Hive_Type),
							strKey, strValue, *((LPDWORD)lpbData));
	}
	else
	{
		csLogString.Format(_T("Found: %s\\%s - %s"), m_objReg.GetHiveName(Hive_Type), strKey, strValue);
	}

	AddLogEntry(csLogString);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : RefSendMessageToUI
In Parameters  : SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type,
				 const TCHAR *strKey, const TCHAR *strValue, int Type_Of_Data,
				 LPBYTE lpbData, int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options,
				 LPBYTE lpbReplaceData, int iSizeOfReplaceData 
Out Parameters : bool 
Description    : report entry to UI
Author         : Anand
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::RefSendMessageToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName,
											HKEY Hive_Type, const TCHAR *strKey, const TCHAR *strValue,
											int Type_Of_Data, LPBYTE lpbData, int iSizeOfData,
											REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
											int iSizeOfReplaceData)
{
	CString csLogString;

	if(NULL == m_lpRefSendMessageToUI)
	{
		return (false);
	}

	m_lpRefSendMessageToUI(eTypeOfScanner, eStatus_Detected, ulSpyName, Hive_Type, strKey, strValue, Type_Of_Data,
							lpbData, iSizeOfData, psReg_Fix_Options, lpbReplaceData, iSizeOfReplaceData,0);

	if(REG_SZ == Type_Of_Data && lpbData)
	{
		csLogString.Format(_T("Found: %s\\%s - %s - %s:%s"), m_objReg.GetHiveName(Hive_Type), 
							strKey, strValue, (LPCTSTR)lpbData, (LPCTSTR)lpbReplaceData);
	}
	else if(REG_DWORD == Type_Of_Data && lpbData)
	{
		csLogString.Format(_T("Found: %s\\%s - %s - %u:%u"), m_objReg.GetHiveName(Hive_Type), 
							strKey, strValue, *((LPDWORD)lpbData), *((LPDWORD)lpbReplaceData));
	}
	else
	{
		csLogString.Format(_T("Found: %s\\%s - %s"), m_objReg.GetHiveName(Hive_Type), strKey, strValue);
	}

	AddLogEntry(csLogString);
	return (true);
}


/*-----------------------------------------------------------------------------------
Function		: InitServicesCheck
In Parameters	: void
Out Parameters	: bool
Purpose			: initialise Services check
Author			: Nitin Shekokar
Description		: initialise Services keynames from SYSTEM\CURRENTCONTROLSET\SERVICES key
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::InitServicesCheck()
{
	CString csSubKey, csData, csData1;
	CStringArray csArrServiceSubKeys;

	if(!m_objReg.EnumSubKeys(SERVICES_MONITOR_KEY, csArrServiceSubKeys, HKEY_LOCAL_MACHINE))
	{
		return (false);
	}

	for(INT_PTR iIndex = 0, iCount = csArrServiceSubKeys.GetCount(); iIndex < iCount; iIndex++)
	{
		csSubKey = CString(SERVICES_MONITOR_KEY) + BACK_SLASH + csArrServiceSubKeys[iIndex];

		csData = BLANKSTRING;
		if(!m_objReg.Get(csSubKey, _T("ImagePath"), csData, HKEY_LOCAL_MACHINE))
		{
			continue;
		}

		if(csData == BLANKSTRING)
		{
			continue;
		}

		csSubKey.MakeLower();
		csData.MakeLower();
		csData = m_objDBPathExpander.ExpandSystemPath(csData, false);
		csData.MakeLower();
		csData1 = csData;
		m_objRegPathExpander.DoesFileExist(csData1);
		csData1 = m_objRegPathExpander.m_csFileFound;
		csData1.MakeLower();

		
		
		if((BLANKSTRING != csSubKey) && (BLANKSTRING != csData1))
		{
			AddFileInList(csData1);
			m_csArrServicesData.Add(csData1);
			m_csArrServicesKeys.Add(csSubKey);
		}
		else
		if((BLANKSTRING != csSubKey) && (BLANKSTRING != csData))
		{
			AddFileInList(csData);
			m_csArrServicesData.Add(csData);
			m_csArrServicesKeys.Add(csSubKey);
		}

		if(BLANKSTRING != csSubKey)
		{
			if(!m_objReg.Get(csSubKey + _T("\\Parameters"), _T("ServiceDll"), csData, HKEY_LOCAL_MACHINE))
			{
				continue;
			}

			if(csData == BLANKSTRING)
			{
				continue;
			}

			csData.MakeLower();
			csData = m_objDBPathExpander.ExpandSystemPath(csData, false);
			csData.MakeLower();
			csData1 = csData;
			m_objRegPathExpander.DoesFileExist(csData1);
			csData1 = m_objRegPathExpander.m_csFileFound;
			csData1.MakeLower();		
			
			
			if(BLANKSTRING != csData1)
			{
				AddFileInList(csData1);
				m_csArrServiceDLLKey.Add(csSubKey);		// using the main key path
				m_csArrServiceDLLData.Add(csData1);		// using the main key path
			}
			else
			if(BLANKSTRING != csData)
			{
				AddFileInList(csData);
				m_csArrServiceDLLKey.Add(csSubKey);		// using the main key path
				m_csArrServiceDLLData.Add(csData);		// using the main key path
			}
		}
	}

	return (true);
}

/*----------------------------------------------------------------------------------
Function		: CheckForServices
In Parameters	: LPCTSTR, LPCTSTR
Out Parameters	: bool
Purpose			: Check infected file name in Services
Author			: Nitin Shekokar
Description		: Check infected file name in Services
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::CheckForServices(LPCTSTR szInfectedFileName, ULONG ulSpyID)
{
	bool bFound = false;
	int iPos = 0;
	CString csServicesSubKeyName = _T("");

	for(INT_PTR iIndex = 0, iCount = m_csArrServicesData.GetCount(); iIndex < iCount; iIndex++)
	{
		if(m_lpfnFileFound)
		{
			m_lpfnFileFound(m_csArrServicesData[iIndex], m_lpThis, m_bStopScan,m_csArrServicesData.GetCount()+m_csArrServiceDLLData.GetCount(),iIndex);
		}
		else
		{
			if(m_csArrServicesData[iIndex] == szInfectedFileName)
			{
				bFound = true;
				m_objRegHlp.EnumKeyNReportToUI(HKEY_LOCAL_MACHINE, m_csArrServicesKeys[iIndex], ulSpyID);

				iPos = m_csArrServicesKeys[iIndex].ReverseFind(_T('\\'));
				if(-1 != iPos)
				{
					csServicesSubKeyName = m_csArrServicesKeys[iIndex].Mid(iPos+1);
					m_objRegHlp.EnumKeyNReportToUI(HKEY_LOCAL_MACHINE,
													SERVICES_LEGACY_KEY + csServicesSubKeyName,
													ulSpyID);
				}
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			break;
		}
	}

	if(!bFound)
	{
		for(INT_PTR iIndex = 0, iCount = m_csArrServiceDLLData.GetCount(); iIndex < iCount; iIndex++)
		{
			if(m_lpfnFileFound)
			{
				m_lpfnFileFound(m_csArrServiceDLLData[iIndex], m_lpThis, m_bStopScan,m_csArrServicesData.GetCount()+m_csArrServiceDLLData.GetCount(),m_csArrServicesData.GetCount()+iIndex);
			}
			else
			{
				if(m_csArrServiceDLLData[iIndex] == szInfectedFileName)
				{
					bFound = true;
					m_objRegHlp.EnumKeyNReportToUI(HKEY_LOCAL_MACHINE, m_csArrServiceDLLKey[iIndex], ulSpyID);

					iPos = m_csArrServiceDLLKey[iIndex].ReverseFind(_T('\\'));
					if(-1 != iPos)
					{
						csServicesSubKeyName = m_csArrServiceDLLKey[iIndex].Mid(iPos+1);
						m_objRegHlp.EnumKeyNReportToUI(HKEY_LOCAL_MACHINE,
														SERVICES_LEGACY_KEY + csServicesSubKeyName,
														ulSpyID);
					}
				}
			}

			if(m_lpfnFileFound && m_bStopScan)
			{
				break;
			}
		}
	}

	return bFound;
}

/*----------------------------------------------------------------------------------
Function		: CheckFileNameInCLSIDByRegKey
In Parameters	: HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath, DWORD dwSpyID
Out Parameters	: bool
Purpose			: Check infected file name in CLSID
Author			: Anand Srivastava
Description		: Check file in clsid in the subkeys of the this main key
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::CheckFileNameInCLSIDByRegKey(HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath,
														DWORD dwSpyID)
{
	bool bFound = false;
	CStringArray csArrSubKeys;
	CString csFileNameToSearch(szFilePath);
	CString csParentKey = _T(""), csData = _T(""), csData1;

	if(!m_objReg.EnumSubKeys(szKey, csArrSubKeys, hHive))
	{
		return false;
	}

	csFileNameToSearch.MakeLower();
	for(INT_PTR i = 0, iTotal = csArrSubKeys.GetCount(); i < iTotal; i++)
	{
		csParentKey = _T("SOFTWARE\\Classes\\CLSID\\");
		if(m_objReg.Get(csParentKey+csArrSubKeys[i]+_T("\\InprocServer32"), _T(""), csData, HKEY_LOCAL_MACHINE))
		{
			if(csData != BLANKSTRING)
			{
				csData1 = csData;

				csData.MakeLower();
				csData = m_objDBPathExpander.ExpandSystemPath(csData, false);

				m_objRegPathExpander.DoesFileExist(csData1);
				csData1 = m_objRegPathExpander.m_csFileFound;
				csData1.MakeLower();

				AddFileInList(csData);
				AddFileInList(csData1);

				if(m_lpfnFileFound)
				{
					m_lpfnFileFound(csData, m_lpThis, m_bStopScan, 0, 0);
					m_lpfnFileFound(csData1, m_lpThis, m_bStopScan, 0, 0);
				}
				else
				{
					if((csData == csFileNameToSearch) || (csData1 == csFileNameToSearch))
					{
						bFound = true;
						m_objRegHlp.GetAllComEntries(csArrSubKeys[i], dwSpyID);
						m_objRegHlp.EnumKeyNReportToUI(hHive, CString(szKey) + BACK_SLASH + csArrSubKeys[i], dwSpyID);
					}
				}
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			break;
		}

#ifdef WIN64
		csParentKey = _T("Software\\Wow6432Node\\Classes\\CLSID\\");
		if(m_objReg.Get(csParentKey+csArrSubKeys[i]+_T("\\InprocServer32"), _T(""), csData, HKEY_LOCAL_MACHINE))
		{
			if(csData != BLANKSTRING)
			{
				csData1 = csData;

				csData.MakeLower();
				csData = m_objDBPathExpander.ExpandSystemPath(csData, false);

				m_objRegPathExpander.DoesFileExist(csData1);
				csData1 = m_objRegPathExpander.m_csFileFound;
				csData1.MakeLower();

				AddFileInList(csData);
				AddFileInList(csData1);

				if(m_lpfnFileFound)
				{
					m_lpfnFileFound(csData, m_lpThis, m_bStopScan, 0, 0);
					m_lpfnFileFound(csData1, m_lpThis, m_bStopScan, 0, 0);
				}
				else
				{
					if((csData == csFileNameToSearch) || (csData1 == csFileNameToSearch))
					{
						bFound = true;
						m_objRegHlp.GetAllComEntries(csArrSubKeys[i], dwSpyID);
						m_objRegHlp.EnumKeyNReportToUI(hHive, CString(szKey) + BACK_SLASH + csArrSubKeys[i], dwSpyID);
					}
				}
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			break;
		}
#endif
	}

	return bFound;
}

/*----------------------------------------------------------------------------------
Function		: CheckFileNameInCLSIDByRegValue
In Parameters	: HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath, DWORD dwSpyID
Out Parameters	: bool
Purpose			: Check infected file name in CLSID
Author			: Anand Srivastava
Description		: check file in clsid in the reg values of the this main key
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::CheckFileNameInCLSIDByRegValue(HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath,
														DWORD dwSpyID)
{
	bool bFound = false;
	CStringArray csArrValues, csArrData;
	CString csFileNameToSearch(szFilePath);
	CString csParentKey = _T(""), csData = _T(""), csData1;

	if(!m_objReg.QueryDataValue(szKey, csArrValues, csArrData, hHive))
	{
		return false;
	}

	csFileNameToSearch.MakeLower();
	for(INT_PTR i = 0, iTotal = csArrValues.GetCount(); i < iTotal; i++)
	{
		csParentKey = _T("SOFTWARE\\Classes\\CLSID\\");
		if(m_objReg.Get(csParentKey+csArrValues[i]+_T("\\InprocServer32"), _T(""), csData, HKEY_LOCAL_MACHINE))
		{
			if(csData != BLANKSTRING)
			{
				csData1 = csData;

				csData.MakeLower();
				csData = m_objDBPathExpander.ExpandSystemPath(csData, false);

				m_objRegPathExpander.DoesFileExist(csData1);
				csData1 = m_objRegPathExpander.m_csFileFound;
				csData1.MakeLower();

				AddFileInList(csData);
				AddFileInList(csData1);

				if(m_lpfnFileFound)
				{
					m_lpfnFileFound(csData, m_lpThis, m_bStopScan, 0, 0);
					m_lpfnFileFound(csData1, m_lpThis, m_bStopScan, 0, 0);
				}
				else
				{
					if((csData == csFileNameToSearch) || (csData1 == csFileNameToSearch))
					{
						bFound = true;
						m_objRegHlp.GetAllComEntries(csArrValues[i], dwSpyID);
						RefSendMessageToUI(RegValue, dwSpyID, hHive, szKey, csArrValues[i], REG_SZ,
											(LPBYTE)(LPCTSTR)csArrData[i], 
											csArrData[i].GetLength()*sizeof(TCHAR));
					}
				}
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			break;
		}

#ifdef WIN64
		csParentKey = _T("Software\\Wow6432Node\\Classes\\CLSID\\");
		if(m_objReg.Get(csParentKey+csArrValues[i]+_T("\\InprocServer32"), _T(""), csData, HKEY_LOCAL_MACHINE))
		{
			if(csData != BLANKSTRING)
			{
				csData1 = csData;

				csData.MakeLower();
				csData = m_objDBPathExpander.ExpandSystemPath(csData, false);

				m_objRegPathExpander.DoesFileExist(csData1);
				csData1 = m_objRegPathExpander.m_csFileFound;
				csData1.MakeLower();

				AddFileInList(csData);
				AddFileInList(csData1);

				if(m_lpfnFileFound)
				{
					m_lpfnFileFound(csData, m_lpThis, m_bStopScan, 0, 0);
					m_lpfnFileFound(csData1, m_lpThis, m_bStopScan, 0, 0);
				}
				else
				{
					if((csData == csFileNameToSearch) || (csData1 == csFileNameToSearch))
					{
						bFound = true;
						m_objRegHlp.GetAllComEntries(csArrValues[i], dwSpyID);
						RefSendMessageToUI(RegValue, dwSpyID, hHive, szKey, csArrValues[i], REG_SZ,
											(LPBYTE)(LPCTSTR)csArrData[i], csArrData[i].GetLength()*sizeof(TCHAR));
					}
				}
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			break;
		}
#endif
	}

	return bFound;
}

/*----------------------------------------------------------------------------------
Function		: CheckFileNameInCLSIDByRegData
In Parameters	: HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath, DWORD dwSpyID
Out Parameters	: bool
Purpose			: Check infected file name in CLSID
Author			: Anand Srivastava
Description		: check file in clsid in the reg data of the this main key
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::CheckFileNameInCLSIDByRegData(HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath,
													   DWORD dwSpyID, bool bReportFullKey)
{
	bool bFound = false;
	CStringArray csArrValues, csArrData;
	CString csFileNameToSearch(szFilePath);
	CString csParentKey = _T(""), csData = _T(""), csData1;

	if(!m_objReg.QueryDataValue(szKey, csArrValues, csArrData, hHive))
	{
		return false;
	}

	csFileNameToSearch.MakeLower();
	for(INT_PTR i = 0, iTotal = csArrData.GetCount(); i < iTotal; i++)
	{
		csParentKey = _T("SOFTWARE\\Classes\\CLSID\\");
		if(m_objReg.Get(csParentKey+csArrData[i]+_T("\\InprocServer32"), _T(""), csData, HKEY_LOCAL_MACHINE))
		{
			if(csData != BLANKSTRING)
			{
				csData1 = csData;

				csData.MakeLower();
				csData = m_objDBPathExpander.ExpandSystemPath(csData, false);

				m_objRegPathExpander.DoesFileExist(csData1);
				csData1 = m_objRegPathExpander.m_csFileFound;
				csData1.MakeLower();

				AddFileInList(csData);
				AddFileInList(csData1);

				if(m_lpfnFileFound)
				{
					m_lpfnFileFound(csData, m_lpThis, m_bStopScan, 0, 0);
					m_lpfnFileFound(csData1, m_lpThis, m_bStopScan, 0, 0);
				}
				else
				{
					if((csData == csFileNameToSearch) || (csData1 == csFileNameToSearch))
					{
						bFound = true;
						m_objRegHlp.GetAllComEntries(csArrData[i], dwSpyID);
						RefSendMessageToUI(RegValue, dwSpyID, hHive, szKey, csArrValues[i], REG_SZ,
											(LPBYTE)(LPCTSTR)csArrData[i], csArrData[i].GetLength()*sizeof(TCHAR));
					}
				}
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			break;
		}

#ifdef WIN64
		csParentKey = _T("Software\\Wow6432Node\\Classes\\CLSID\\");
		if(m_objReg.Get(csParentKey+csArrData[i]+_T("\\InprocServer32"), _T(""), csData, HKEY_LOCAL_MACHINE))
		{
			if(csData != BLANKSTRING)
			{
				csData1 = csData;

				csData.MakeLower();
				csData = m_objDBPathExpander.ExpandSystemPath(csData, false);

				m_objRegPathExpander.DoesFileExist(csData1);
				csData1 = m_objRegPathExpander.m_csFileFound;
				csData1.MakeLower();

				AddFileInList(csData);
				AddFileInList(csData1);

				if(m_lpfnFileFound)
				{
					m_lpfnFileFound(csData, m_lpThis, m_bStopScan, 0, 0);
					m_lpfnFileFound(csData1, m_lpThis, m_bStopScan, 0, 0);
				}
				else
				{
					if((csData == csFileNameToSearch) || (csData1 == csFileNameToSearch))
					{
						bFound = true;
						m_objRegHlp.GetAllComEntries(csArrData[i], dwSpyID);
						RefSendMessageToUI(RegValue, dwSpyID, hHive, szKey, csArrValues[i], REG_SZ,
											(LPBYTE)(LPCTSTR)csArrData[i], csArrData[i].GetLength()*sizeof(TCHAR));
					}
				}
			}
		}

		if(m_lpfnFileFound && m_bStopScan)
		{
			break;
		}
#endif
	}

	if(bFound && bReportFullKey)
	{
		m_objRegHlp.EnumKeyNReportToUI(hHive, szKey, dwSpyID);
	}

	return bFound;
}

/*----------------------------------------------------------------------------------
Function		: CheckFileNameInCLSIDBySubKey
In Parameters	: HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath, DWORD dwSpyID
Out Parameters	: bool
Purpose			: Check infected file name in CLSID
Author			: Anand Srivastava
Description		: check file in clsid in the reg data of the subkeys of main key
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::CheckFileNameInCLSIDBySubKey(HKEY hHive, LPCTSTR szKey, LPCTSTR szFilePath, DWORD dwSpyID)
{
	bool bFound = false;
	CString csFullKey;
	CStringArray csArrSubKeys;

	if(!m_objReg.EnumSubKeys(szKey, csArrSubKeys, hHive))
	{
		return bFound;
	}

	for(INT_PTR i = 0, iTotal = csArrSubKeys.GetCount(); i < iTotal; i++)
	{
		csFullKey = CString(szKey) + BACK_SLASH + csArrSubKeys[i];
		if(CheckFileNameInCLSIDByRegData(hHive, csFullKey, szFilePath, dwSpyID, true))
		{
			bFound = true;
		}
	}

	return bFound;
}

/*----------------------------------------------------------------------------------
Function		: CheckFileForHiddenFolder
In Parameters	: LPCTSTR szFilePath
Out Parameters	: bool
Purpose			: Check for hidden folder
Author			: Anand Srivastava
Description		: check for hidden folder in the same location as file
--------------------------------------------------------------------------------------*/
bool CReferencesScanner::CheckFileForHiddenFolder(LPCTSTR szFilePath)
{
	TCHAR szFolderPath[MAX_PATH] = {0};
	LPCTSTR pDot = 0;
	DWORD dwAttributes = 0;

	pDot = _tcsrchr(szFilePath, _T('.'));
	if(NULL == pDot)
	{
		return false;
	}

	if(pDot - szFilePath >= _countof(szFolderPath))
	{
		return false;
	}

	_tcsncpy_s(szFolderPath, _countof(szFolderPath), szFilePath, pDot - szFilePath);
	for(int i = (int)_tcslen(szFolderPath) - 1; i > -1; i--)
	{
		if(_T(' ') == szFolderPath[i])
		{
			szFolderPath[i] = 0;
		}
		else
		{
			break;
		}
	}

	dwAttributes = GetFileAttributes(szFolderPath);
	if(INVALID_FILE_ATTRIBUTES == dwAttributes)
	{
		return false;
	}

	if((dwAttributes & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY)
	{
		return false;
	}

	if((dwAttributes & FILE_ATTRIBUTE_SYSTEM) == FILE_ATTRIBUTE_SYSTEM)
	{
		dwAttributes ^= FILE_ATTRIBUTE_SYSTEM;
	}

	if((dwAttributes & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN)
	{
		dwAttributes ^= FILE_ATTRIBUTE_HIDDEN;
	}

	SetFileAttributes(szFolderPath, dwAttributes);
	AddLogEntry(L"System and Hidden attributes removed: %s", szFolderPath);
	return true;
}

void CReferencesScanner::AddFileInList(CString csFileName)
{
	if((!m_bDummyCallDone) && (csFileName != BLANKSTRING))
	{
		DWORD dwData = 0;
		m_oFileReferenceList.AppendItem(csFileName, dwData);
	}
}

bool CReferencesScanner::CheckAndReportReferences(LPCTSTR szInfectedFileName, ULONG ulSpyID,
												  DWORD dwReferenceID, SENDMESSAGETOUIMS lpSendMessageToUI)
{
	if(!m_bInitScanners)
	{
		DWORD dwInitStartTime = GetTickCount();
		m_bDummyCallDone = false;
		InitScanners();
		m_bInitScanners = true;
		OldCheckAndReportReferences(_T("dummy"), 0, dwReferenceID, NULL);
		m_bDummyCallDone = true;
		m_dwRefInitTime += (GetTickCount() - dwInitStartTime);
	}

	CString csFileName = szInfectedFileName;
	csFileName.MakeLower();

	// already handled dummy call!
	if(!lpSendMessageToUI) //(csFileName == _T("dummy"))
		return false;

	m_dwNoOfFilesSearched++;
	DWORD dwRefScanStartTime = GetTickCount();

	bool bReturnVal = false;
	DWORD dwData = 0;
	if(m_oFileReferenceList.SearchItem(csFileName, &dwData))
	{
		bReturnVal = OldCheckAndReportReferences(szInfectedFileName, ulSpyID, dwReferenceID, lpSendMessageToUI);
	}
	m_dwRefScanTime += (GetTickCount() - dwRefScanStartTime);
	return bReturnVal;
}