/*======================================================================================
   FILE				: HomePageMonitor.h
   ABSTRACT			: Module for active monitoring of Toolbar registry value
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
#include "HomePageMonitor.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CHomePageMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: CHomePageMonitor initialization
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CHomePageMonitor::CHomePageMonitor():m_pMsgHandler(NULL), m_pThis(NULL), m_hEvent(NULL)
{
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
}

/*-------------------------------------------------------------------------------------
	Function		: ~CHomePageMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CHomePageMonitor::~CHomePageMonitor()
{
	WaitForSingleObject(m_hEvent, INFINITE); // Wait for the last event to finish its job!
	CloseHandle(m_hEvent);
	m_hEvent = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: StartMonitor
	In Parameters	: -
	Out Parameters	: bool
	Purpose			: Start Home Page Monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CHomePageMonitor::StartMonitor()
{
	m_objOldValues.RemoveAll();

	// Fill the UserSID Map by enumerating the Profile List Key AND Also HKLM && .Default entry manually
	LoadOldValues(L"SOFTWARE\\Microsoft\\Internet Explorer\\Main", L"Search Page", m_objOldValues);
	LoadOldValues(L"SOFTWARE\\Microsoft\\Internet Explorer\\Main", L"Start Page", m_objOldValues);
	LoadOldValues(L"SOFTWARE\\Microsoft\\Internet Explorer\\Main", L"Start Page Redirect Cache", m_objOldValues);
	LoadOldValues(L"SOFTWARE\\Microsoft\\Internet Explorer\\Main", L"Default_Page_URL", m_objOldValues);
	LoadOldValues(L"SOFTWARE\\Microsoft\\Internet Explorer\\Main", L"Default_Search_URL", m_objOldValues);

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
void CHomePageMonitor::SetHandler(LPVOID pMessageHandler, LPVOID lpThis)
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
bool CHomePageMonitor::HandleExisting()
{
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: StopMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Stop Home Page Monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CHomePageMonitor::StopMonitor()
{
	m_bIsMonitoring = false;
	CloseAllThreads();
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
bool CHomePageMonitor::CheckRegistryEntry(CString &csRegistryEntry, CString &csParentProcessName)
{
	const int BREAKOFFLEN1 = 55;
	const int BREAKOFFLEN1_X64 = BREAKOFFLEN1 + 12;
	const int BREAKOFFLEN2 = 56;
	const int BREAKOFFLEN2_X64 = BREAKOFFLEN2 + 12;
	const int BREAKOFFLEN3 = 56;
	const int BREAKOFFLEN3_X64 = BREAKOFFLEN3 + 12;
	const int BREAKOFFLEN4 = 70;
	const int BREAKOFFLEN4_X64 = BREAKOFFLEN4 + 12;
	const int BREAKOFFLEN5 = 61;
	const int BREAKOFFLEN5_X64 = BREAKOFFLEN5 + 12;
	const int BREAKOFFLEN6 = 63;
	const int BREAKOFFLEN6_X64 = BREAKOFFLEN6 + 12;

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

	if(!IsPathInteresting(csOnlyData, BREAKOFFLEN1, ACTMON_STARTPAGE_KEY))
	{
		if(!IsPathInteresting(csOnlyData, BREAKOFFLEN1_X64, ACTMON_STARTPAGE_KEY_X64))
		{
			if(!IsPathInteresting(csOnlyData, BREAKOFFLEN3, ACTMON_SEARCHPAGE_KEY))
			{
				if(!IsPathInteresting(csOnlyData, BREAKOFFLEN3_X64, ACTMON_SEARCHPAGE_KEY_X64))
				{
			if(!IsPathInteresting(csOnlyData, BREAKOFFLEN2, ACTMON_COMPONENT_KEY))
			{
				if(!IsPathInteresting(csOnlyData, BREAKOFFLEN2_X64, ACTMON_COMPONENT_KEY_X64))
				{
							if(!IsPathInteresting(csOnlyData, BREAKOFFLEN4, ACTMON_REDIRECTCACHE_KEY))
							{
								if(!IsPathInteresting(csOnlyData, BREAKOFFLEN4_X64, ACTMON_REDIRECTCACHE_KEY_X64))
								{
									if(!IsPathInteresting(csOnlyData, BREAKOFFLEN5, ACTMON_DEFAULTPAGEURL_KEY))
									{
										if(!IsPathInteresting(csOnlyData, BREAKOFFLEN5_X64, ACTMON_DEFAULTPAGEURL_KEY_X64))
										{
											if(!IsPathInteresting(csOnlyData, BREAKOFFLEN6, ACTMON_DEFAULTSEARCHURL_KEY))
											{
												if(!IsPathInteresting(csOnlyData, BREAKOFFLEN6_X64, ACTMON_DEFAULTSEARCHURL_KEY_X64))
												{
					return false;
												}
											}
										}
									}
								}
							}
						}
					}
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

	//csUserSID look up in the UserSID Map && get its old value
	CString csOldValue;
	m_objOldValues.Lookup(csUserSID, csOldValue);
	if(csOldValue == csOnlyData)
	{
		SetEvent(m_hEvent);
		return false;
	}

	DWORD dwAllowed = -1;
	if(m_pMsgHandler && !IsExcludedApplication(m_csParentProcessName, dwAllowed))
	{
		int iReturn = m_pMsgHandler(SETHOMEPAGE, csOldValue, csOnlyData, csParentProcessName, m_pThis);
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
			AddLogEntry(_T("HomePage Monitor: %s"), csOnlyData, 0, true, LOG_DEBUG);						
			time_t ltime=0;
			time(&ltime);
			SPY_ENTRY_INFO oDBObj = {0};
			oDBObj.eTypeOfEntry = RegValue;			
			oDBObj.ul64DateTime = ltime;
			oDBObj.byStatus = eStatus_Detected;
			oDBObj.szKey = (LPTSTR)(LPCTSTR) csValue;			
			oDBObj.szValue = (LPTSTR)(LPCTSTR) csData;
			oDBObj.byReplaceData = (LPBYTE) (LPCTSTR)csOldValue;
			AddEntryInDB(&oDBObj);
		
			if(m_bDisplayNotification)
			{
				csOnlyData.Replace(L"#@#", L"");	// required incase of active desktop entry!
				ReportSpywareEntry(RegValue, csOnlyData, BLANKSTRING, _T("IDS_HOME_PAGE_PROTECTION"));
			}
			SetEvent(m_hEvent);
			return true;
		}
	}
	m_objOldValues.SetAt(csUserSID,csOnlyData);

	m_csOldValue = csOnlyData;

	if(!dwAllowed)
	{
		SetEvent(m_hEvent);
		return true;
	}
	SetEvent(m_hEvent);
	return false;
}

