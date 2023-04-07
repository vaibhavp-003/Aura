/*======================================================================================
   FILE				: KidoWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Kido Worm
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
   CREATION DATE	: 27/10/2010
   NOTE				:
   VERSION HISTORY	:
========================================================================================*/

#include "pch.h"
#include "KidoWorm.h"
#include "ExecuteProcess.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove Kido
	Author			: Anand Srivastava
	Description		: This is main function for kido worm scan class
--------------------------------------------------------------------------------------*/
bool CKidoWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		if(IsStopScanningSignaled())
		{
			return m_bSplSpyFound;
		}

		if(!bToDelete)
		{
			//KIDO WORM
			
			if(!GetSystemMetrics(SM_CLEANBOOT))
			{
				
			}
			PrepareProcessAndModulesList();
			m_bSplSpyFound = ScanForHiddenServiceKey();
			m_bSplSpyFound = ScanRegistryFixEntries(true) ? true : m_bSplSpyFound;
		}
		else
		{
			ScanRegistryFixEntries(false);
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound;
		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in CKidoWorm::ScanSplSpy, Error : %d"), GetLastError());
		AddLogEntry(csErr, 0, 0);
	}
	
	return false;
}

void CKidoWorm::ExecuteCommandWithWait(CString sExecCmd, CString csParam)
{
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};

	si.cb = sizeof(si);
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW;

	// Start the child process.
	if(!CreateProcess(sExecCmd.GetBuffer(MAX_PATH), csParam.GetBuffer(MAX_PATH), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		sExecCmd.ReleaseBuffer();
		csParam.ReleaseBuffer();
		return ;
	}

	sExecCmd.ReleaseBuffer();
	csParam.ReleaseBuffer();

	// Wait until child process exits.
	for(int i = 0; i < 60 * 100; i++)
	{
		WaitForSingleObject(pi.hProcess, 10);
		if(IsStopScanningSignaled())
		{
			TerminateProcess(pi.hProcess, -1);
			break;
		}
	}

	// Close process and thread handles.
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return ;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanForHiddenServiceKey
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: find hidden key and dll
	Author			: Anand Srivastava
	Description		: Find hidden key in services and dll
--------------------------------------------------------------------------------------*/
bool CKidoWorm::ScanForHiddenServiceKey()
{
	bool bHiddenKeyFound = false;
	CStringArray csArrServiceKeys, csSubKeys;
	CString csFullKey, csData;
	DWORD dwDWord = 0;

	m_objReg.EnumSubKeys(SERVICES_MONITOR_KEY, csArrServiceKeys, HKEY_LOCAL_MACHINE);
	for(int i = 0, iTotal = (int)csArrServiceKeys.GetCount(); i < iTotal; i++)
	{
		dwDWord = 0;
		csData = _T("");
		csFullKey = SERVICES_MAIN_KEY + csArrServiceKeys.GetAt(i);

		// check start value to be 2
		m_objReg.Get(csFullKey, _T("Start"), dwDWord, HKEY_LOCAL_MACHINE);
		if(2 != dwDWord)
		{
			continue;
		}

		// check ErrorControl value to be 0
		m_objReg.Get(csFullKey, _T("ErrorControl"), dwDWord, HKEY_LOCAL_MACHINE);
		if(0 != dwDWord)
		{
			continue;
		}

		// read ImagePath, should have svchost.exe -k
		m_objReg.Get(csFullKey, _T("ImagePath"), csData, HKEY_LOCAL_MACHINE);
		if(_T("") == csData)
		{
			continue;
		}

		csData.MakeLower();
		if(-1 == csData.Find(_T("svchost.exe -k")))
		{
			continue;
		}

		csData = _T("");
		csFullKey = csFullKey + _T("\\Parameters");

		// read ServiceDll from Parameters key, should have dll file path
		m_objReg.Get(csFullKey, _T("ServiceDll"), csData, HKEY_LOCAL_MACHINE);
		if(_T("") == csData)
		{
			continue;
		}

		csData.MakeLower();
		dwDWord = GetFileAttributes(csData);
		if((INVALID_FILE_ATTRIBUTES == dwDWord) || ((dwDWord & FILE_ATTRIBUTE_HIDDEN) != FILE_ATTRIBUTE_HIDDEN))
		{
			continue;
		}

		if(IsFileInfected(csData))
		{
			bHiddenKeyFound = true;
			csFullKey = SERVICES_MAIN_KEY + csArrServiceKeys.GetAt(i);

			SendScanStatusToUI(Special_File, m_ulSpyName, csData);
			CheckReportKeyValueData(m_ulSpyName, csFullKey, HKEY_LOCAL_MACHINE);
		}
	}

	return bHiddenKeyFound;
}


/*-------------------------------------------------------------------------------------
	Function		: IsFileInfected
	In Parameters	: const CString csFilePath
	Out Parameters	: 
	Purpose			: Check if the file is infected
	Author			: Anand Srivastava
	Description		: Check if the file is infected
--------------------------------------------------------------------------------------*/
bool CKidoWorm::IsFileInfected(const CString csFilePath)
{
	bool bInfected = true;

	for(int i = 0, iTotal = (int)m_csArrPrcModList.GetCount(); i < iTotal; i++)
	{
		if(m_csArrPrcModList.GetAt(i) == csFilePath)
		{
			bInfected = false;
			break;
		}
	}

	return bInfected;
}

/*-------------------------------------------------------------------------------------
	Function		: Kido_ModuleHandler
	In Parameters	: DWORD , HANDLE , HMODULE , LPCTSTR , LPVOID , bool
	Out Parameters	: bool
	Purpose			: callback function which is called for every module of the given ID
	Author			: Anand Srivastava
	Description		: adds the module path to class object member variable
--------------------------------------------------------------------------------------*/
BOOL CALLBACK Kido_ModuleHandler(DWORD dwProcessID, HANDLE hProcess, LPCTSTR szProcessPath, HMODULE hModule, LPCTSTR szModulePath, LPVOID pThis, bool &bStopEnum)
{
	try
	{
		CString csFilePath;
		CKidoWorm * pKidoWorm = (CKidoWorm*)pThis;

		if(pKidoWorm->GetStopStatus())
		{
			return FALSE;
		}

		csFilePath = szModulePath;
		csFilePath.MakeLower();
		pKidoWorm->m_csArrPrcModList.Add(csFilePath);
		return TRUE;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CKidoWorm, Kido_ModuleHandler, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: Kido_ProcessHandler
	In Parameters	: LPCTSTR , LPCTSTR , DWORD , HANDLE, LPVOID , bool 
	Out Parameters	: bool
	Purpose			: callback function which is called for every process
	Author			: Anand
	Description		: adds process path to class member object list
--------------------------------------------------------------------------------------*/
BOOL CALLBACK Kido_ProcessHandler(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, LPVOID pThis, bool &bStopEnum)
{
	try
	{
		CString csFilePath;
		CKidoWorm * pKidoWorm = (CKidoWorm*)pThis;

		if(pKidoWorm->GetStopStatus())
		{
			return FALSE;
		}

		csFilePath = szExePath;
		csFilePath.MakeLower();
		pKidoWorm->m_csArrPrcModList.Add(csFilePath);
		pKidoWorm->m_objEnumProcess.EnumProcessModuleList(dwProcessID, szExePath, (PROCESSMODULEHANDLER)Kido_ModuleHandler, pThis);

		return TRUE;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CKidoWorm, SC_ProcessHandler, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: PrepareProcessAndModulesList
	In Parameters	: 
	Out Parameters	: 
	Purpose			: prepare list of process and modules
	Author			: Anand Srivastava
	Description		: prepare list of process and modules
--------------------------------------------------------------------------------------*/
bool CKidoWorm::PrepareProcessAndModulesList()
{
	m_csArrPrcModList.RemoveAll();
	m_objEnumProcess.EnumRunningProcesses((PROCESSHANDLER)Kido_ProcessHandler, (LPVOID)this);
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetStopStatus
	In Parameters	: 
	Out Parameters	: 
	Purpose			: check if stop scanning signaled
	Author			: Anand Srivastava
	Description		: check if stop scanning signaled
--------------------------------------------------------------------------------------*/
bool CKidoWorm::GetStopStatus()
{
	return IsStopScanningSignaled();
}

/*-------------------------------------------------------------------------------------
	Function		: ScanRegistryFixEntries
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check for registry entries to be fixed
	Author			: Anand Srivastava
	Description		: check for registry entries to be fixed
--------------------------------------------------------------------------------------*/
bool CKidoWorm::ScanRegistryFixEntries(bool bScan)
{
	DWORD dwData = 0, dwDefaultValue = 1;
	CString csKey = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL");
	REG_FIX_OPTIONS RegFixOpt = {FIX_TYPE_ALWAYS_FIX, FIX_ACTION_RESTORE};

	if(!bScan)
	{
		return false;
	}

	if(!m_objReg.Get(csKey, _T("CheckedValue"), dwData, HKEY_LOCAL_MACHINE))
	{
		return false;
	}

	if(1 == dwData)
	{
		return false;
	}

	SendScanStatusToUI(RegFix, m_ulSpyName, HKEY_LOCAL_MACHINE, csKey, _T("CheckedValue"), REG_DWORD,
						(LPBYTE)&dwData, 4, &RegFixOpt, (LPBYTE)&dwDefaultValue, 4);
	return true;
}
