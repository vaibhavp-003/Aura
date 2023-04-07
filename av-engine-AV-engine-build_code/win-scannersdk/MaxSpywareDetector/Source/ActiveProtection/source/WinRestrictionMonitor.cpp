/*======================================================================================
   FILE				: WinRestrictionMonitor.h
   ABSTRACT			: Module for active monitoring of WinRestriction registry value
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
   CREATION DATE	: 05 Feb 2008
   NOTES			: 
   VERSION HISTORY	: 
					Version:19.0.0.066
					Description:Handle same entry condition
					Resource :Sandip
					Date:06/08/2008
=====================================================================================*/

#include "pch.h"
#include "WinRestrictionMonitor.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CWinRestrictionMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: CWinRestrictionMonitor initialization
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CWinRestrictionMonitor::CWinRestrictionMonitor():m_pMsgHandler(NULL), m_pThis(NULL), m_hEvent(NULL)
{
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
}

/*-------------------------------------------------------------------------------------
	Function		: ~CWinRestrictionMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CWinRestrictionMonitor::~CWinRestrictionMonitor()
{
	WaitForSingleObject(m_hEvent, INFINITE); // Wait for the last event to finish its job!
	CloseHandle(m_hEvent);
	m_hEvent = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: StartMonitor
	In Parameters	: -
	Out Parameters	: bool
	Purpose			: Start WinRestriction Value Monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CWinRestrictionMonitor::StartMonitor()
{
	m_bIsMonitoring = true;
	m_objMapStrToStr.RemoveAll();
	LoadAllOldValues(ACTMON_WIN_POL_SYS_KEY,m_objMapStrToStr);
	LoadAllOldValues(ACTMON_WIN_POL_EXP_KEY,m_objMapStrToStr);
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: SetHandler
	In Parameters	: LPVOID pMessageHandler, LPVOID lpThis
	Out Parameters	: -
	Purpose			: Sets the Message handler, required to report entries to the user
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CWinRestrictionMonitor::SetHandler(LPVOID pMessageHandler, LPVOID lpThis)
{
	if(pMessageHandler)
	{
		m_pMsgHandler = (ACTMON_MESSAGEPROCHANDLER)pMessageHandler;
	}

	if(lpThis)
	{
		m_pThis = lpThis;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: HandleExisting
	In Parameters	: -
	Out Parameters	: bool
	Purpose			: Handles exisiting entry of the type of class, called when active
						pritection is started
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CWinRestrictionMonitor::HandleExisting()
{
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: StopMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Stop WinRestriction Value monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CWinRestrictionMonitor::StopMonitor()
{
	m_bIsMonitoring = false;
	CloseAllThreads();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForOldEntry
	In Parameters	: CString csFullPath(Full Path) , CString & csMainPath(onlu path and data) 
					  CString csData(Current data value) , bool & bAddNewEntry(Change Data value)
	Out Parameters	: -
	Purpose			: Check For old data entry
	Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CWinRestrictionMonitor::CheckForOldEntry(CString csFullPath , CString & csMainPath ,
											  CString csData  ,CString csUserSID,
											  CString csValue, bool & bAddNewEntry)
{
	if(!m_bIsMonitoring)
	{
		return false;
	}

	int iPos = csMainPath.Find(ACTMON_DATA_SEPERATOR);
	if(iPos != -1)
	{
		csMainPath = csMainPath.Left(iPos);
	}

	CString csTempData;
	if(m_objMapStrToStr.GetCount() > 0)
	{
		csTempData = csUserSID + _T("-") + csMainPath;
		csTempData.MakeLower();

		if(!m_objMapStrToStr.Lookup(csTempData, csTempData))
		{
			//csData.MakeLower();
			//m_objMapStrToStr.SetAt(csTempData, csData);
			return true;
		}

		if(csTempData.CompareNoCase(csData) == 0)
		{
			return false;
		}
		bAddNewEntry = true;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckRegistryEntry
	In Parameters	: CString : Registry Entry to be checked
					  CString : Process which is accessing the entry!
	Out Parameters	: bool : true if spyware
	Purpose			: Checks the entry is interesting and verifies against our db if
						its a spyware
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CWinRestrictionMonitor::CheckRegistryEntry(CString &csRegistryEntry, CString &csParentProcessName)
{
	const int BREAKOFFLEN1 = 58;
	const int BREAKOFFLEN2 = 60;
	const int BREAKOFFLEN1_X64 = BREAKOFFLEN1 +12;
	const int BREAKOFFLEN2_X64  = BREAKOFFLEN2 +12;

	if(csRegistryEntry.GetLength() <= BREAKOFFLEN1)
	{
		return false;
	}

	CString csValue, csData;
	CString csUserSID;
	if(!GetSoftwarePath(csRegistryEntry, csValue,csUserSID))
	{
		return false;
	}
	CString csFullValue = csValue;
	if(csUserSID.GetLength() == 0)
	{
		csUserSID = L"hklm";
	}

	WaitForSingleObject(m_hEvent, INFINITE); // Check one process at a time
	m_csParentProcessName = csParentProcessName;

	CString csMainPath = csValue;
	if(IsPathInteresting(csValue, BREAKOFFLEN1, ACTMON_WIN_POL_SYS_KEY))
	{
		m_WRMKey = ACTMON_WIN_POL_SYS_KEY;
	}
	else if(IsPathInteresting(csValue, BREAKOFFLEN2, ACTMON_WIN_POL_EXP_KEY))
	{
		m_WRMKey = ACTMON_WIN_POL_EXP_KEY;
	}
	else if(IsPathInteresting(csValue, BREAKOFFLEN1_X64, ACTMON_WIN_POL_SYS_KEY_X64))
	{
		m_WRMKey = ACTMON_WIN_POL_SYS_KEY_X64;
	}
	else if(IsPathInteresting(csValue, BREAKOFFLEN2_X64, ACTMON_WIN_POL_EXP_KEY_X64))
	{
		m_WRMKey = ACTMON_WIN_POL_EXP_KEY_X64;
	}
	else
	{
		SetEvent(m_hEvent);
		return false;
	}

	int iPos = csValue.Find(ACTMON_DATA_SEPERATOR);
	if(iPos == -1)
	{
		return false;
	}
	
	csData = csValue.Mid(iPos + 3);
	csValue = csValue.Left(iPos);

	//Description:Handle same Value Data condition
	//Resource :Sandip	
	bool bAddNewEntry = false;

	if(!CheckForOldEntry(csRegistryEntry, csMainPath, csData, csUserSID, csValue, bAddNewEntry))
	{
		SetEvent(m_hEvent);
		return false;
	}

	DWORD dwAllowed = -1;
	if(m_pMsgHandler && !IsExcludedApplication(m_csParentProcessName, dwAllowed))
	{
		int iReturn = m_pMsgHandler(SETWINRESTRICTIONMONITOR, csValue, csData, csParentProcessName, m_pThis);
		if(iReturn == APPLY_FOR_ALL_YES)
		{
			AddInExcludedApplication(m_csParentProcessName, 1);
		}
		else if(iReturn == APPLY_FOR_ALL_NO)
		{
			AddInExcludedApplication(m_csParentProcessName, 0);
		}

		if(!iReturn || iReturn == APPLY_FOR_ALL_NO)
		{
			AddLogEntry(_T("WinRestriction Monitor: %s\t%s"), csValue, csData, true, LOG_DEBUG);
			time_t ltime=0;
			time(&ltime);
			SPY_ENTRY_INFO oDBObj = {0};
			oDBObj.eTypeOfEntry = RegValue;			
			oDBObj.ul64DateTime = ltime;
			oDBObj.byStatus = eStatus_Detected;
			oDBObj.szKey = (LPTSTR)(LPCTSTR) csFullValue;			
			oDBObj.byData = (LPBYTE)(LPCTSTR) csData;			
			AddEntryInDB(&oDBObj);

			if(m_bDisplayNotification)
			{
				ReportSpywareEntry(RegValue ,csValue, csData, _T("IDS_WIN_RESTRICTION_MONITOR"));
			}
			SetEvent(m_hEvent);
			return true;
		}
		if(bAddNewEntry)
		{
			csUserSID.MakeLower();
			m_objMapStrToStr.SetAt(csUserSID + L"-" + csMainPath.MakeLower(), csData);
		}
	}

	if(!dwAllowed)
	{
		SetEvent(m_hEvent);
		return true;
	}

	SetEvent(m_hEvent);
	return false;
}
