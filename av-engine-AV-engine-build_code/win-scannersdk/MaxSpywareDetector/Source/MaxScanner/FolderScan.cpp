/*======================================================================================
FILE             : FolderScan.cpp
ABSTRACT         : defines a class to scan folders using a files scanned list
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 4/March/2010 9:57 P
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/

#include "stdafx.h"
#include "FolderScan.h"
#include "SDSystemInfo.h"

/*--------------------------------------------------------------------------------------
Function       : CFolderScan
In Parameters  : 
Out Parameters : 
Description    : constructor
Author		   : Anand Srivastava
--------------------------------------------------------------------------------------*/
CFolderScan::CFolderScan():m_objScannedList(false),m_objFolderDBMap(false)
{
	m_lpSendMessageToUI = NULL;
	m_bScanStarted = false;
}

/*--------------------------------------------------------------------------------------
Function       : CFolderScan
In Parameters  : 
Out Parameters : 
Description    : destructor
Author		   : Anand Srivastava
--------------------------------------------------------------------------------------*/
CFolderScan::~CFolderScan()
{
}

/*--------------------------------------------------------------------------------------
Function       : AddToScannedList
In Parameters  : LPCTSTR szScannedFilePath, DWORD dwSpyID
Out Parameters : bool
Description    : add the folder entry in scanned list
Author		   : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFolderScan::AddToScannedList(LPCTSTR szScannedFilePath, DWORD dwSpyID)
{
	int iSlash = -1;
	CString csFilePath(szScannedFilePath);

	if(m_bScanStarted)
	{
		return true;
	}

	iSlash = csFilePath.ReverseFind(_T('\\'));
	if(-1 == iSlash)
	{
		return false;
	}

	csFilePath.SetAt(iSlash, 0);
	m_objScannedList.AppendItem(csFilePath, dwSpyID);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : EnumerateAndReportFolder
In Parameters  : CString& csPath, DWORD dwSpyID
Out Parameters : bool
Description    : enumerate and report all files and folders
Author		   : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFolderScan::EnumerateAndReportFolder(LPCTSTR szPath, DWORD dwSpyID)
{
	CString csHoldPath(szPath);
	CFileFind objFinder;
	BOOL bMoreFiles = TRUE;

	AddLogEntry(Folder, csHoldPath);
	m_lpSendMessageToUI(Folder, eStatus_Detected, dwSpyID, 0, csHoldPath, 0, 0, 0, 0, 0, 0, 0, 0);

	csHoldPath += _T("\\*");
	bMoreFiles = objFinder.FindFile(csHoldPath);
	if(FALSE == bMoreFiles)
	{
		return false;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDots())
		{
			continue;
		}

		csHoldPath = objFinder.GetFilePath();
		if(objFinder.IsDirectory())
		{
			EnumerateAndReportFolder(csHoldPath, dwSpyID);
		}
		else
		{
			AddLogEntry(File, csHoldPath);
			m_lpSendMessageToUI(File, eStatus_Detected, dwSpyID, 0, csHoldPath, 0, 0, 0, 0, 0, 0, 0, 0);
		}
	}

	objFinder.Close();
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : StartFolderScan
In Parameters  : SENDMESSAGETOUI lpSendMessageToUI
Out Parameters : void 
Description    : scan and report all folders from list which are in SD's FolderDB
Author		   : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFolderScan::StartFolderScan(SENDMESSAGETOUIMS lpSendMessageToUI, const CString &csMaxDBPath)
{
	DWORD dwSpyID = 0;
	LPTSTR szValue = 0;
	LPVOID lpContext = 0;
	CS2U objValueDatabase(true);
	CU2OS2U objValueTypeDatabase(true);

	m_bScanStarted = true;

	SetReporter(lpSendMessageToUI);
	if(NULL == m_lpSendMessageToUI)
	{
		m_bScanStarted = false;
		return false;
	}

	AddLogEntry(Starting_Folder_Scanner, L"Folder Scan");
	m_lpSendMessageToUI(Starting_Folder_Scanner, eStatus_NotApplicable, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

	m_objFolderDBMap.Load(csMaxDBPath + SD_DB_FOLDER);
	if(m_objFolderDBMap.GetFirst() == NULL)
	{
		AddLogEntry(_T("Scanning skip for database : %s"), csMaxDBPath + SD_DB_FOLDER);
		m_objRegistry.Set(CSystemInfo::m_csProductRegKey , _T("AutoDatabasePatch"), 1, HKEY_LOCAL_MACHINE);
		AddLogEntry(Starting_Folder_Scanner, L"Folder Scan", 0, false);
		m_lpSendMessageToUI(Starting_Folder_Scanner, eStatus_NotApplicable, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
		m_bScanStarted = false;
		return false;
	}

	lpContext = m_objScannedList.GetFirst();
	while(lpContext)
	{
		m_objScannedList.GetKey(lpContext, szValue);
		m_objDBPathExpander.SplitPathByValueType(szValue);

		if(m_objFolderDBMap.SearchItem(m_objDBPathExpander.m_lProfileType, objValueTypeDatabase))
		{
			if(objValueTypeDatabase.SearchItem(m_objDBPathExpander.m_lValueTypeID, objValueDatabase))
			{
				if(objValueDatabase.SearchItem(m_objDBPathExpander.m_csValue, &dwSpyID))
				{
					EnumerateAndReportFolder(szValue, dwSpyID);
				}
			}
		}

		lpContext = m_objScannedList.GetNext(lpContext);
	}

	m_objFolderDBMap.RemoveAll();
	m_lpSendMessageToUI(Starting_Folder_Scanner, eStatus_NotApplicable, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	AddLogEntry(Starting_Folder_Scanner, L"Folder Scan", 0, false);
	m_bScanStarted = false;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : SetReporter
In Parameters  : SENDMESSAGETOUI lpSendMessageToUI
Out Parameters : void 
Description    : set message sending function
Author		   : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CFolderScan::SetReporter(SENDMESSAGETOUIMS lpSendMessageToUI)
{
	if(lpSendMessageToUI)
	{
		m_lpSendMessageToUI = lpSendMessageToUI;
	}
}

