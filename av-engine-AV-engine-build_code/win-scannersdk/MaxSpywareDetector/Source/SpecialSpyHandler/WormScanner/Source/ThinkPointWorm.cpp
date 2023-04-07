/*======================================================================================
   FILE				: ThinkPointWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining ThinkPoint Worm
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
#include "ThinkPointWorm.h"
#include "ExecuteProcess.h"
#include "MalwareCatcher.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove ThinkPoint
	Author			: Manjunath, Anand Srivastava
	Description		: This is main function for ThinkPoint worm scan class
--------------------------------------------------------------------------------------*/
bool CThinkPointWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		if(IsStopScanningSignaled())
		{
			return m_bSplSpyFound;
		}

		if(!bToDelete)
		{
			m_bSplSpyFound = ScanForHotfixSpyware()?true:m_bSplSpyFound;
			m_bSplSpyFound = ScanForSystemTool()?true:m_bSplSpyFound;
			m_bSplSpyFound = ScanForSecurityShield()?true:m_bSplSpyFound;
			m_bSplSpyFound = ScanForSystemTool2011()?true:m_bSplSpyFound;
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound;
		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in CThinkPointWorm::ScanSplSpy, Error : %d"), GetLastError());
		AddLogEntry(csErr, 0, 0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanForHotfixSpyware
	In Parameters	: LPTSTR FilePath, LPDWORD FilePathSize, LPTSTR RegKeyPath, LPDWORD RegKeyPathSize
	Out Parameters	: 
	Purpose			: Check and remove ThinkPoint
	Author			: Manjunath, Anand Srivastava
	Description		: This is main function for ThinkPoint worm scan class
--------------------------------------------------------------------------------------*/
bool CThinkPointWorm::ScanForHotfixSpyware(void)
{
	TCHAR tBuffer[MAX_PATH] = {0};
	DWORD tBufferSize = MAX_PATH;
	HKEY hRegKey = NULL;
	CExecuteProcess objExecProc;
	CString csUserSID, csData;
	BYTE bySections[17] = {'U', 'P', 'X', '0', 0, 0, 0, 0, 'U', 'P', 'X', '1', 0, 0, 0, 0};

	csUserSID = objExecProc.GetCurrentUserSid();
	if(BLANKSTRING == csUserSID)
	{
		return false;
	}

	m_objReg.Get(csUserSID + BACK_SLASH + WINLOGON_REG_KEY, _T("Shell"), csData, HKEY_USERS);
	if(_T("") == csData)
	{
		return false;
	}

	if(CheckIfSectionsPresent(csData, bySections, 16))
	{
		if(m_objEnumProcess.IsProcessRunning(csData, false))
		{
			SendScanStatusToUI(Special_Process, m_ulSpyName, csData);
		}

		SendScanStatusToUI(Special_File, m_ulSpyName, csData);
		return true;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanForSystemTool
	In Parameters	: 
	Out Parameters	: 
	Purpose			: scan and remove system tool infection
	Author			: Anand Srivastava
	Description		: scan and remove system tool infection
--------------------------------------------------------------------------------------*/
bool CThinkPointWorm::ScanForSystemTool(void)
{
	TCHAR szPath[MAX_PATH] = {0};
	CString csHoldPath;
	CFileFind objFinder;
	BOOL bMoreFiles = FALSE;
	bool bFound = false;

	SHGetFolderPath(0, CSIDL_COMMON_APPDATA, 0, 0, szPath);
	if(0 == szPath[0])
	{
		return bFound;
	}

	csHoldPath = szPath;
	bMoreFiles = objFinder.FindFile(csHoldPath + _T("\\*"));
	if(FALSE == bMoreFiles)
	{
		return bFound;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDots() || !objFinder.IsDirectory())
		{
			continue;
		}

		csHoldPath = objFinder.GetFilePath() + BACK_SLASH + objFinder.GetFileName();
		if(_taccess_s(csHoldPath, 0))
		{
			continue;
		}

		csHoldPath += _T(".exe");
		if(_taccess_s(csHoldPath, 0))
		{
			continue;
		}

		bFound = true;
		csHoldPath = objFinder.GetFilePath();
		RemoveFolders(csHoldPath, m_ulSpyName, false);
		SendScanStatusToUI(Special_Folder, m_ulSpyName, csHoldPath);
	}

	objFinder.Close();
	return bFound;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanForSecurityShield
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: scan and remove security shiled
	Author			: Anand Srivastava
	Description		: scan and remove security shiled
--------------------------------------------------------------------------------------*/
bool CThinkPointWorm::ScanForSecurityShield()
{
	CString csLnkPath;
	CMalwareCatcherWorm objResSht(0);
	TCHAR szTargetPath[MAX_PATH] = {0};

	if(!GetCurUserStartMenuProgs(csLnkPath))
	{
		return false;
	}

	csLnkPath += _T("\\\\Security Shield.lnk");
	if(_taccess_s(csLnkPath, 0))
	{
		return false;
	}

	objResSht.ResolveShortcut(csLnkPath, szTargetPath, _countof(szTargetPath));
	if(0 == szTargetPath[0])
	{
		return false;
	}

	if(_taccess_s(szTargetPath, 0))
	{
		return false;
	}

	if(m_objEnumProcess.IsProcessRunning(szTargetPath, false))
	{
		SendScanStatusToUI(Special_Process, m_ulSpyName, szTargetPath);
	}

	SendScanStatusToUI(Special_File, m_ulSpyName, csLnkPath);
	SendScanStatusToUI(Special_File, m_ulSpyName, szTargetPath);
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanForSystemTool2011
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: scan and remove SystemTool2011
	Author			: Anand Srivastava
	Description		: scan and remove SystemTool2011
--------------------------------------------------------------------------------------*/
bool CThinkPointWorm::ScanForSystemTool2011()
{
	CString csLnkPath;
	CMalwareCatcherWorm objResSht(0);
	TCHAR szTargetPath[MAX_PATH] = {0};

	if(!GetCurUserStartMenuProgs(csLnkPath))
	{
		return false;
	}

	csLnkPath += _T("\\System Tool\\System Tool 2011.lnk");
	if(_taccess_s(csLnkPath, 0))
	{
		return false;
	}

	objResSht.ResolveShortcut(csLnkPath, szTargetPath, _countof(szTargetPath));
	if(0 == szTargetPath[0])
	{
		return false;
	}

	if(_taccess_s(szTargetPath, 0))
	{
		return false;
	}

	if(m_objEnumProcess.IsProcessRunning(szTargetPath, false))
	{
		SendScanStatusToUI(Special_Process, m_ulSpyName, szTargetPath);
	}

	SendScanStatusToUI(Special_File, m_ulSpyName, szTargetPath);
	int iLastSlash = csLnkPath.ReverseFind(_T('\\'));
	if(-1 != iLastSlash)
	{
		csLnkPath.SetAt(iLastSlash, 0);
		if(!_taccess_s(csLnkPath, 0))
		{
			RemoveFolders(csLnkPath, m_ulSpyName, false);
		}
	}

	return true;
}
