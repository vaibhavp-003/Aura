/*======================================================================================
   FILE				: IERestrictionMonitor.h
   ABSTRACT			: Module for active monitoring of IERestriction registry value
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
=====================================================================================*/

#include "pch.h"
#include "IERestrictionMonitor.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CIERestrictionMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: CIERestrictionMonitor initialization
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CIERestrictionMonitor::CIERestrictionMonitor():m_pMsgHandler(NULL), m_pThis(NULL), m_hEvent(NULL)
{
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
}

/*-------------------------------------------------------------------------------------
	Function		: ~CIERestrictionMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CIERestrictionMonitor::~CIERestrictionMonitor()
{
	WaitForSingleObject(m_hEvent, INFINITE); // Wait for the last event to finish its job!
	CloseHandle(m_hEvent);
	m_hEvent = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: StartMonitor
	In Parameters	: -
	Out Parameters	: bool
	Purpose			: Start IERestriction Value Monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CIERestrictionMonitor::StartMonitor()
{
	m_bIsMonitoring = true;

	//Load old Entries
	m_objMapStrToStr.RemoveAll();
	LoadAllOldValues(ACTMON_IERESTRICT_KEY, m_objMapStrToStr);

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: SetHandler
	In Parameters	: LPVOID pMessageHandler, LPVOID lpThis
	Out Parameters	: -
	Purpose			: Sets the Message handler, required to report entries to the user
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CIERestrictionMonitor::SetHandler(LPVOID pMessageHandler, LPVOID lpThis)
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
bool CIERestrictionMonitor::HandleExisting()
{
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: StopMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Stop IERestriction Value monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CIERestrictionMonitor::StopMonitor()
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
bool CIERestrictionMonitor::CheckForOldEntry(CString csFullPath , CString & csMainPath ,
											CString csData  ,CString csUserSID,CString csValue,
											bool & bAddNewEntry)
{
	int iPos = csMainPath.Find(ACTMON_DATA_SEPERATOR);
	if(iPos != -1)
	{
		csMainPath = csMainPath.Left(iPos);
	}

	CString csTempData;
	if(m_objMapStrToStr.GetCount() > 0)
	{
		csTempData = csUserSID + _T("-")+ csMainPath;
		csTempData.MakeLower();
		CString strValue;
		if(m_objMapStrToStr.Lookup(csTempData, strValue) == NULL)
		{
			//csData.MakeLower();
			//m_objMapStrToStr.SetAt(csTempData,csData);
			return true;
		}

		m_objMapStrToStr.Lookup(csTempData, csTempData);
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
	Purpose			: Checks the entry is interesting and ask the user if he wants to 
						all this registry entry to be changed
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CIERestrictionMonitor::CheckRegistryEntry(CString &csRegistryEntry, CString &csParentProcessName)
{
	const int BREAKOFFLEN = 59;
	const int BREAKOFFLEN_X64 = BREAKOFFLEN+12;

	if(!m_bIsMonitoring)
	{
		return false;
	}

	if(csRegistryEntry.GetLength() <= BREAKOFFLEN)
	{
		return false;
	}

	CString csValue, csData;
	CString csUserSID;
	if(!GetSoftwarePath(csRegistryEntry, csValue, csUserSID))
	{
		return false;
	}
	CString csFullValue = csValue;
	if(csUserSID.GetLength() == 0)
	{
		csUserSID = L"hklm";
	}

	CString csMainPath  = csValue;
	if(!IsPathInteresting(csValue, BREAKOFFLEN, ACTMON_IERESTRICT_KEY))
	{
		if(!IsPathInteresting(csValue, BREAKOFFLEN_X64, ACTMON_IERESTRICT_KEY_X64))
		{
			return false;
		}
	}

	int iPos = csValue.Find(ACTMON_DATA_SEPERATOR);
	if(iPos == -1)
	{
		return false;
	}

	csData = csValue.Mid(iPos + 3);
	csValue = csValue.Left(iPos);

	WaitForSingleObject(m_hEvent, INFINITE); // Check one process at a time
	m_csParentProcessName = csParentProcessName;

	//Description:Handle same Value Data condition
	//Resource :Sandip
	bool  bAddNewEntry = false;
	if(!CheckForOldEntry(csRegistryEntry, csMainPath, csData , csUserSID, csValue , bAddNewEntry))
	{
		SetEvent(m_hEvent);
		return false;
	}

	DWORD dwAllowed = -1;
	if(m_pMsgHandler && !IsExcludedApplication(m_csParentProcessName, dwAllowed))
	{
		int iReturn = m_pMsgHandler(SETIERESTRICTIONMONITOR, csValue, csData, csParentProcessName, m_pThis);
		if(iReturn == APPLY_FOR_ALL_YES)
		{
			AddInExcludedApplication(m_csParentProcessName , 1);
		}
		else if(iReturn == APPLY_FOR_ALL_NO)
		{
			AddInExcludedApplication(m_csParentProcessName,0);
		}

		if(!iReturn || iReturn == APPLY_FOR_ALL_NO)
		{
			AddLogEntry(_T("IERestriction Monitor: %s\t%s"), csValue, csData, true, LOG_DEBUG);
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
				ReportSpywareEntry(RegValue ,csValue, csData, _T("IDS_IERESTRICTION_MONITOR"));
			}
			SetEvent(m_hEvent);
			return true;
		}		
		if(bAddNewEntry)
		{
			csUserSID.MakeLower();
			m_objMapStrToStr.SetAt(csUserSID+L"-"+ csMainPath.MakeLower() , csData);
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
