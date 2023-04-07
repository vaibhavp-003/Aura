/*======================================================================================
   FILE				: FileSystemMonitor.cpp
   ABSTRACT			: Module for monitoring the file system changes
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
   CREATION DATE	: 25 Sep 2009
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/
#include "pch.h"
#include "FileSystemMonitor.h"
#ifdef USING_FLTMGR
#include <fltuser.h>	
#include "SDActMonConstants.h"
#endif //USING_FLTMGR

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CFileSystemMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: CFileSystemMonitor constructor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CFileSystemMonitor::CFileSystemMonitor(void):m_hEvent(NULL)
{
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
}

/*-------------------------------------------------------------------------------------
	Function		: ~CFileSystemMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CFileSystemMonitor::~CFileSystemMonitor(void)
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
	Purpose			: Start File System monitor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileSystemMonitor::StartMonitor()
{
	m_csSunBeltSetup = _T("sbsetupdrivers.exe");
	m_csWindowsInstaller = _T("msiexec.exe");
	m_csOurMainUI =UI_EXENAME;

	m_bIsMonitoring = true;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: SetHandler
	In Parameters	: LPVOID pMessageHandler: Function pointer for displaying message to user
					  LPVOID lpThis			: Class pointer 
	Out Parameters	: bool
	Purpose			: Start File System monitor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CFileSystemMonitor::SetHandler(LPVOID pMessageHandler, LPVOID lpThis)
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
	Purpose			: Handle existing
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileSystemMonitor::HandleExisting()
{
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: StopMonitor
	In Parameters	: -
	Out Parameters	: bool alway return true
	Purpose			: Stop File system monitoring
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileSystemMonitor::StopMonitor()
{
	m_bIsMonitoring = false;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckFileEntry
	In Parameters	: CString &csFileEntry, CString &csParentProcessName
	Out Parameters	: bool returns true if you want to block access to the file
	Purpose			: Ask the user if they want to allow the monitored file to be modified
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileSystemMonitor::CheckFileEntry(CString &csFileEntry, CString &csParentProcessName, int iTypeOfCall)
{
	if(!m_bIsMonitoring)
	{
		return false;
	}

	bool bSystemFileProtection = false;
	if(csFileEntry.Find(ACTMON_HOST_FILE_XP) == -1)
	{
		if(csFileEntry.Find(ACTMON_HOST_FILE_2K) == -1)
		{
#ifdef USING_FLTMGR
			if((iTypeOfCall == CALL_TYPE_F_NEW_SYS_FILE) || (iTypeOfCall == CALL_TYPE_F_REN_SYS_FILE)
				|| (iTypeOfCall == CALL_TYPE_F_DEL_SYS_FILE) || (iTypeOfCall == CALL_TYPE_F_MOD_SYS_FILE))
			{
				bSystemFileProtection = true;
			}
			else
			{
				return false;
			}
#else
			return false;
#endif
		}
	}

	if((m_csSunBeltSetup == csParentProcessName) 
		|| (m_csWindowsInstaller == csParentProcessName) 
		|| (m_csOurMainUI == csParentProcessName))
	{
		return false;
	}

	WaitForSingleObject(m_hEvent, INFINITE); // Check one process at a time
	m_csParentProcessName = csParentProcessName;

	if(bSystemFileProtection)	// as long as system file monitor is ON, for the system folder we do not allow write access to any process!
	{
#ifdef USING_FLTMGR
		if(iTypeOfCall == CALL_TYPE_F_MOD_SYS_FILE)
		{
			SetEvent(m_hEvent);
			return true;
		}
		else if((iTypeOfCall != CALL_TYPE_F_NEW_SYS_FILE) || (_waccess(csFileEntry, 0) != 0))
		{
			AddLogEntry(_T("FileSystem Monitor: %s, %s"), csFileEntry, csParentProcessName, true, LOG_DEBUG);
			if(m_bDisplayNotification)
			{
				ReportSpywareEntry(File, csFileEntry, BLANKSTRING, L"IDS_SYS_FILE_PROTECTION");
			}
			SetEvent(m_hEvent);
			return true;
		}
#endif
	}
	else
	{
		DWORD dwAllowed = -1;
		if(!IsExcludedApplication(m_csParentProcessName, dwAllowed))
		{
			// blocking access to all system files!
			AddLogEntry(_T("FileSystem Monitor: %s, %s"), csFileEntry, csParentProcessName, true, LOG_DEBUG);
			if(m_bDisplayNotification)
			{
				ReportSpywareEntry(File, csFileEntry, BLANKSTRING, L"IDS_SYS_FILE_PROTECTION");
			}
			SetEvent(m_hEvent);
			return true;
		}
	}
	SetEvent(m_hEvent);
	return false;
}