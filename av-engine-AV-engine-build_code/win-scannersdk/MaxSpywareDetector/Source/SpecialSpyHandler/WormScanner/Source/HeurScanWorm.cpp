/*======================================================================================
   FILE				: HeurScanWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining by Heurisctic Method
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 18/09/2010
   NOTE				:
   VERSION HISTORY	:
========================================================================================*/

#include "pch.h"
#include "HeurScanWorm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

SYS_FILE g_SysFiles[] =
{
	{_T("%%windir%%"), _T("explorer.exe")},
	{_T("%%sysdir%%"), _T("svchost.exe")},
	{_T("%%sysdir%%"), _T("smss.exe")},
	{_T("%%sysdir%%"), _T("lsass.exe")},
	{_T("%%sysdir%%"), _T("csrss.exe")},
	{_T("%%sysdir%%"), _T("services.exe")},
	{_T("%%sysdir%%"), _T("lsm.exe")},
	{_T("%%sysdir%%"), _T("spoolsv.exe")},
	{_T("%%sysdir%%"), _T("winlogon.exe")}
#ifdef WIN64
	,
	{_T("%%windir%%\\SysWow64"), _T("svchost.exe")},
	{_T("%%windir%%\\SysWow64"), _T("smss.exe")},
	{_T("%%windir%%\\SysWow64"), _T("lsass.exe")},
	{_T("%%windir%%\\SysWow64"), _T("csrss.exe")},
	{_T("%%windir%%\\SysWow64"), _T("services.exe")},
	{_T("%%windir%%\\SysWow64"), _T("lsm.exe")},
	{_T("%%windir%%\\SysWow64"), _T("spoolsv.exe")},
	{_T("%%windir%%\\SysWow64"), _T("winlogon.exe")}
#endif
};

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: scan by heuristic
	Author			: Anand
	Description		: This function is entry point function for this class
--------------------------------------------------------------------------------------*/
bool CHeurScanWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;
		if(false == bToDelete)
		{
			m_objEnumProc.EnumRunningProcesses((PROCESSHANDLER)HEUR_ProcessHandler, (LPVOID)this);
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		return m_bSplSpyFound;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CHeurScanWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: HEUR_ProcessModuleHandler
	In Parameters	: DWORD , HANDLE , HMODULE , LPCTSTR , LPVOID , bool
	Out Parameters	: bool
	Purpose			: callback function which is called for every module of the given ID
	Author			: Anand
	Description		: checks if file is suspicious
--------------------------------------------------------------------------------------*/
BOOL CALLBACK HEUR_ProcessModuleHandler(DWORD dwProcessID, HANDLE hProcess, HMODULE hModule, LPCTSTR szModulePath, LPVOID pThis, bool &bStopEnum)
{
	try
	{
		CHeurScanWorm * pHeurScanWorm = (CHeurScanWorm*)pThis;

		if(pHeurScanWorm->GetStopStatus())
		{
			return FALSE;
		}

		pHeurScanWorm->ScanThisFile(szModulePath, 0);
		return TRUE;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in HEUR_ProcessModuleHandler, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: HEUR_ProcessHandler
	In Parameters	: LPCTSTR , LPCTSTR , DWORD , HANDLE, LPVOID , bool 
	Out Parameters	: bool
	Purpose			: callback function which is called for every process
	Author			: Anand
	Description		: checks if the process and enumerates its modules
--------------------------------------------------------------------------------------*/
BOOL CALLBACK HEUR_ProcessHandler(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, LPVOID pThis, bool &bStopEnum)
{
	try
	{
		CHeurScanWorm * pHeurScanWorm = (CHeurScanWorm*)pThis;

		if(pHeurScanWorm->GetStopStatus())
		{
			bStopEnum = true;
			return FALSE;
		}

		pHeurScanWorm->ScanThisFile(szExePath, 1);
		//pHeurScanWorm->m_objEnumProc.EnumProcessModuleList(dwProcessID, szExePath, (PROCESSMODULEHANDLER)HEUR_ProcessModuleHandler, pThis);
		return TRUE;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in HEUR_ProcessHandler, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanThisFile
	In Parameters	: LPCTSTR, , SIZE_T
	Out Parameters	: bool
	Purpose			: scan this file
	Author			: Anand
	Description		: scan this file and report
--------------------------------------------------------------------------------------*/
bool CHeurScanWorm::ScanThisFile(LPCTSTR szFilePath, SIZE_T iType)
{
	int iSlash = -1;
	bool bFromDefaultPath = false, bInCheckList = false;
	CString csFullFilePath, csOnlyFileName, csOnlyFilePath;

	csFullFilePath = szFilePath;
	csFullFilePath.MakeLower();
	csFullFilePath = m_oDBPathExpander.ExpandSystemPath(csFullFilePath);

	iSlash = csFullFilePath.ReverseFind(_T('\\'));
	if(-1 == iSlash)
	{
		return false;
	}

	csOnlyFileName = csFullFilePath.Right(csFullFilePath.GetLength() - (iSlash + 1));
	csOnlyFilePath = csFullFilePath.Left(iSlash);

	for(int i = 0; i < _countof(g_SysFiles); i++)
	{
		if(_tcsicmp(csOnlyFileName, g_SysFiles[i].szName))
		{
			continue;
		}

		bInCheckList = true;
		iSlash = csFullFilePath.ReverseFind(_T('\\'));
		if(-1 == iSlash)
		{
			continue;
		}

		csFullFilePath.SetAt(iSlash, 0);
		if(0 == _tcsnicmp(_T("%%windir%%"), g_SysFiles[i].szPath, 8))
		{
			csFullFilePath = g_SysFiles[i].szPath;
			csFullFilePath.Replace(_T("%%windir%%"), m_csWinDir);
		}
		else if(0 == _tcsnicmp(_T("%%sysdir%%"), g_SysFiles[i].szPath, 8))
		{
			csFullFilePath = g_SysFiles[i].szPath;
			csFullFilePath.Replace(_T("%%sysdir%%"), m_csSysDir);
		}
		else
		{
			continue;
		}

		if(0 == csFullFilePath.CompareNoCase(csOnlyFilePath))
		{
			bFromDefaultPath = true;
			break;
		}
	}

	if(bInCheckList && !bFromDefaultPath)
	{
		SendScanStatusToUI(Special_Process, m_ulSpyName, szFilePath);
		if(!_taccess(szFilePath, 0))
		{
			SendScanStatusToUI(Special_File, m_ulSpyName, szFilePath);
		}

		m_bSplSpyFound = true;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetStopStatus
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: check is stop scan signaled
	Author			: Anand
	Description		: check is stop scan signaled
--------------------------------------------------------------------------------------*/
bool CHeurScanWorm::GetStopStatus()
{
	return IsStopScanningSignaled();
}
