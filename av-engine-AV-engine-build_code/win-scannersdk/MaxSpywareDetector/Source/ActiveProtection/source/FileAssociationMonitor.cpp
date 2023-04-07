/*======================================================================================
   FILE				: FileAssociationMonitor.h
   ABSTRACT			: Module for active monitoring of File Association registry value(s)
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
   CREATION DATE	: 01 Oct 2009
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/
#include "pch.h"
#include "FileAssociationMonitor.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CFileAssociationMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: CFileAssociationMonitor initialization
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CFileAssociationMonitor::CFileAssociationMonitor(void):m_hEvent(NULL)
{
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
}

/*-------------------------------------------------------------------------------------
	Function		: ~CFileAssociationMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CFileAssociationMonitor::~CFileAssociationMonitor(void)
{
	WaitForSingleObject(m_hEvent, INFINITE); // Wait for the last event to finish its job!
	CloseHandle(m_hEvent);
	m_hEvent = NULL;

	CloseAllThreads();
}

/*-------------------------------------------------------------------------------------
	Function		: StartMonitor
	In Parameters	: -
	Out Parameters	: bool
	Purpose			: Start File Association Monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileAssociationMonitor::StartMonitor()
{	
	m_bIsMonitoring = true;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: SetHandler
	In Parameters	: LPVOID pMessageHandler, LPVOID lpThis
	Out Parameters	: -
	Purpose			: Sets the Message handler, required to report entries to the user
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CFileAssociationMonitor::SetHandler(LPVOID pMessageHandler, LPVOID lpThis)
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
bool CFileAssociationMonitor::HandleExisting()
{
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: StopMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Stop File Association Monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileAssociationMonitor::StopMonitor()
{
	m_bIsMonitoring = false;
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
bool CFileAssociationMonitor::CheckRegistryEntry(CString &csRegistryEntry, CString &csParentProcessName)
{
	const int BREAKOFFLEN1 = 20;
	const int BREAKOFFLEN2 = 21;
	const int BREAKOFFLEN3 = 33;
	const int BREAKOFFLEN4 = 34;

	if(!m_bIsMonitoring)
	{
		return false;
	}

	if(csRegistryEntry.GetLength() <= BREAKOFFLEN1)
	{
		return false;
	}

	CString csOnlyData;
	CString csUserSID;
	if(!GetSoftwarePath(csRegistryEntry, csOnlyData, csUserSID))
	{
		return false;
	}
	int iPos = csOnlyData.Find(ACTMON_DATA_SEPERATOR);
	if(iPos == -1)
	{
		return false;
	}

	CString csData = csOnlyData.Mid(iPos + 3);
	CString csValue = csOnlyData.Left(iPos);

	if(!IsPathInteresting(csOnlyData, BREAKOFFLEN1, ACTMON_FILE_ASSOCIATION_KEY1))
	{
		if(!IsPathInteresting(csOnlyData, BREAKOFFLEN2, ACTMON_FILE_ASSOCIATION_KEY2))
		{
			if(!IsPathInteresting(csOnlyData, BREAKOFFLEN3, ACTMON_FILE_ASSOCIATION_KEY3))
			{
				if(!IsPathInteresting(csOnlyData, BREAKOFFLEN4, ACTMON_FILE_ASSOCIATION_KEY4))
				{
					return false;
				}
			}
		}
	}

	if(csUserSID.GetLength() == 0)
	{
		csUserSID = L"HKLM"; //Its a HKLM entry
	}

	WaitForSingleObject(m_hEvent, INFINITE); // Check one process at a time
	m_csParentProcessName = csParentProcessName;

	CTimeSpan ctSpan = CTime::GetCurrentTime() - m_ctLastCallTime;
	if((ctSpan.GetSeconds() < 5) && (m_csLastEntry == csOnlyData) && (m_csLastParentProcessName == csParentProcessName))
	{
		SetEvent(m_hEvent);
		return m_bLastAction;
	}

	DWORD dwAllowed = -1;
	if(m_pMsgHandler && !IsExcludedApplication(m_csParentProcessName, dwAllowed))
	{	
		int iReturn = m_pMsgHandler(SETFILEASSOCIATION, L"", csOnlyData, csParentProcessName, m_pThis);
		if(iReturn == APPLY_FOR_ALL_YES)
		{
			AddInExcludedApplication(m_csParentProcessName, 1);
		}
		else if (iReturn == APPLY_FOR_ALL_NO)
		{
			AddInExcludedApplication(m_csParentProcessName, 0);
		}
		if(!iReturn || iReturn == APPLY_FOR_ALL_NO)
		{
			AddLogEntry(_T("File Association Monitor: %s, %s"), csOnlyData, m_csParentProcessName);
			time_t ltime=0;
			time(&ltime);
			SPY_ENTRY_INFO oDBObj = {0};
			oDBObj.eTypeOfEntry = RegValue;			
			oDBObj.ul64DateTime = ltime;
			oDBObj.byStatus = eStatus_Detected;
			oDBObj.szKey = (LPTSTR)(LPCTSTR) csValue;			
			oDBObj.szValue = (LPTSTR)(LPCTSTR) csData;			
			AddEntryInDB(&oDBObj);

			if(m_bDisplayNotification)
			{
				ReportSpywareEntry(RegKey,csOnlyData, BLANKSTRING, _T("IDS_FILE_ASSOCIATION_MONITOR")); 
			}
			m_bLastAction = true;
			m_ctLastCallTime = CTime::GetCurrentTime();
			m_csLastEntry = csOnlyData;
			m_csLastParentProcessName = csParentProcessName;
			SetEvent(m_hEvent);
			return true;
		}
	}
	m_bLastAction = false;
	m_ctLastCallTime = CTime::GetCurrentTime();
	m_csLastEntry = csOnlyData;
	m_csLastParentProcessName = csParentProcessName;
	if(!dwAllowed)
	{
		m_bLastAction = true;
		SetEvent(m_hEvent);
		return true;	
	}
	SetEvent(m_hEvent);
	return false;
}
