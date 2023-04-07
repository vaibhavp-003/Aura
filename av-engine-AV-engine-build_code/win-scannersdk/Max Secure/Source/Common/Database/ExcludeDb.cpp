
/*======================================================================================
FILE             : ExcludeDb.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : 
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 5/15/2009
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "ExcludeDb.h"
#include "SDConstants.h"

//constant defined in AntiRootkitConstants.h
const ULONG Rootkit_SpyNameID_ = 11097;

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CExcludeDb
In Parameters  : void):m_objExcludeByValueDb(false), m_objExcludeByNameDb(false),
m_bNewNodeAdded(false,
Out Parameters :
Description    : C'tor for Initializing By Name and By Value DB
Author         :
--------------------------------------------------------------------------------------*/
CExcludeDb::CExcludeDb(void):m_objExDBByID(false), m_objExDBByName(false),
							 m_objExDBByEntryID(false), m_objExDBByEntryName(false),
							 m_objExDBAutoRtkt(false)
{
	TCHAR *Ptr = 0, strQurantineFolderPath[MAX_PATH] = {0};

	m_bNewNodeAdded = false;
	m_csDatabasePath = _T("");

	GetModuleFileName(NULL, strQurantineFolderPath, MAX_PATH);
	Ptr = _tcsrchr(strQurantineFolderPath, _T('\\'));
	if(Ptr)
	{
		*Ptr = 0;
		m_csDatabasePath = CString(strQurantineFolderPath) + _T("\\Quarantine\\");
	}

	ReLoadExcludeDB();
}

/*--------------------------------------------------------------------------------------
Function       : ~CExcludeDb
In Parameters  : void,
Out Parameters :
Description    : D'tor saves DB
Author         : Anand Srivastva
--------------------------------------------------------------------------------------*/
CExcludeDb::~CExcludeDb(void)
{
	SaveExcludeDB();

	m_objExDBByID.RemoveAll();
	m_objExDBByName.RemoveAll();
	m_objExDBByEntryID.RemoveAll();
	m_objExDBByEntryName.RemoveAll();
	m_objExDBAutoRtkt.RemoveAll();
}

/*--------------------------------------------------------------------------------------
Function       : SaveExcludeDB
In Parameters  :
Out Parameters : bool
Description    : Provision for reloading DB for getting new updates
Author         : Anand Srivastva
--------------------------------------------------------------------------------------*/
void CExcludeDb::SaveExcludeDB()
{
	if(m_bNewNodeAdded)
	{
		m_objExDBByID.Balance();
		m_objExDBByName.Balance();
		m_objExDBByEntryID.Balance();
		m_objExDBByEntryName.Balance();
		m_objExDBAutoRtkt.Balance();

		m_objExDBByID.Save(m_csDatabasePath + EX_DB_BY_ID);
		m_objExDBByName.Save(m_csDatabasePath + EX_DB_BY_NAME);
		m_objExDBByEntryID.Save(m_csDatabasePath + EX_DB_BY_IDENTRY);
		m_objExDBByEntryName.Save(m_csDatabasePath + EX_DB_BY_NAMEENTRY);
		m_objExDBAutoRtkt.Save(m_csDatabasePath + EX_DB_BY_AUTO_RTKT);
	}
}

/*--------------------------------------------------------------------------------------
Function       : ReLoadExcludeDB
In Parameters  :
Out Parameters : bool
Description    : Provision for reloading DB for getting new updates
Author         : Anand Srivastva
--------------------------------------------------------------------------------------*/
bool CExcludeDb::ReLoadExcludeDB()
{
	m_objExDBByID.RemoveAll();
	m_objExDBByName.RemoveAll();
	m_objExDBByEntryID.RemoveAll();
	m_objExDBByEntryName.RemoveAll();
	m_objExDBAutoRtkt.RemoveAll();

	m_objExDBByID.Load(m_csDatabasePath + EX_DB_BY_ID);
	m_objExDBByName.Load(m_csDatabasePath + EX_DB_BY_NAME);
	m_objExDBByEntryID.Load(m_csDatabasePath + EX_DB_BY_IDENTRY);
	m_objExDBByEntryName.Load(m_csDatabasePath + EX_DB_BY_NAMEENTRY);
	m_objExDBAutoRtkt.Load(m_csDatabasePath + EX_DB_BY_AUTO_RTKT);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Exclude
In Parameters  : ULONG &lSpyName, LPCTSTR lpValue, bool bNameDB, bool bRootkitEntry
Out Parameters : bool
Description    : Adding Item to the Exclude DB by Name/By By Value
Author         : Anand Srivastva
--------------------------------------------------------------------------------------*/
bool CExcludeDb::Exclude(ULONG &lSpyName, LPCTSTR strSpyName, LPCTSTR lpValue)
{
	LPVOID lpCon = 0;
	DWORD dwSpyID = 0;
	LPTSTR szEntry = 0, szSpyName = 0;
	CString csTempSpywareName(strSpyName);

	//Rootkit_Entry is sent from threat mgr before rootkit file quarantine
	if(strSpyName && (0 == _tcscmp(strSpyName, _T("Rootkit_Entry"))) && lSpyName == Rootkit_SpyNameID_ && lpValue && *lpValue)
	{
		if(!m_objExDBAutoRtkt.SearchItem(lpValue, &dwSpyID))
		{
			if(m_objExDBAutoRtkt.AppendItem(lpValue, Rootkit_SpyNameID_))
			{
				m_bNewNodeAdded = true;
			}
		}

		return m_bNewNodeAdded;
	}

	if(lSpyName)
	{
		//id has come
		if(lpValue && *lpValue)
		{
			//verify if the id is not already excluded
			if(!m_objExDBByID.SearchItem(lSpyName, &szEntry))
			{
				// add this entry to entry-id tree
				m_objExDBByEntryID.AppendItem(lpValue, lSpyName);
			}
		}
		else
		{
			//add this id to exclude ids tree
			m_objExDBByID.AppendItem(lSpyName, _T(""));

			//remove all entries of this id from id-entry tree
			//because now id is excluded, hence no need to exclude entries

			lpCon = m_objExDBByEntryID.GetFirst();
			while(lpCon)
			{
				m_objExDBByEntryID.GetData(lpCon, dwSpyID);
				if(lSpyName == dwSpyID)
				{
					m_objExDBByEntryID.GetKey(lpCon, szEntry);
					if(szEntry)
					{
						m_objExDBByEntryID.DeleteItem(szEntry);
						lpCon = m_objExDBByEntryID.GetFirst();
						continue;
					}
				}

				lpCon = m_objExDBByEntryID.GetNext(lpCon);
			}
		}

		m_bNewNodeAdded = true;
	}
	else if(csTempSpywareName == L"Userdefined" )
	{
		if(lpValue && *lpValue)
		{
			LPTSTR szData = 0;
			//verify if spyware name is not already excluded
			if(!m_objExDBByEntryName.SearchItem(lpValue, szData))
			{
				// add to entry-name tree
				m_objExDBByEntryName.AppendItem(lpValue, strSpyName);
			}
		}
		m_bNewNodeAdded = true;
	}
	else if(strSpyName && *strSpyName)
	{
		//id did not come, name has come
		if(lpValue && *lpValue)
		{
			//verify if spyware name is not already excluded
			if(!m_objExDBByName.SearchItem(strSpyName, &dwSpyID))
			{
				// add to entry-name tree
				m_objExDBByEntryName.AppendItem(lpValue, strSpyName);
			}
		}
		else
		{
			// add to spyware name tree
			m_objExDBByName.AppendItem(strSpyName, 0);

			//remove all entries of this spyware name from name-entry tree
			//because now name is excluded, hence no need to exclude entries

			lpCon = m_objExDBByEntryName.GetFirst();
			while(lpCon)
			{
				m_objExDBByEntryName.GetData(lpCon, szSpyName);
				if(!_tcsicmp(szSpyName, strSpyName))
				{
					m_objExDBByEntryName.GetKey(lpCon, szEntry);
					if(szEntry)
					{
						m_objExDBByEntryName.DeleteItem(szEntry);
						lpCon = m_objExDBByEntryName.GetFirst();
						continue;
					}
				}

				lpCon = m_objExDBByEntryName.GetNext(lpCon);
			}
		}

		m_bNewNodeAdded = true;
	}

	return m_bNewNodeAdded;
}

/*--------------------------------------------------------------------------------------
Function       : IsExcluded
In Parameters  : ULONG &lSpyName, LPCTSTR lpValue,
Out Parameters : bool
Description    : Checks if the Value/Name is excluded
Author         : Anand Srivastva
--------------------------------------------------------------------------------------*/
bool CExcludeDb::IsExcluded(ULONG &lSpyName, LPCTSTR strSpyName, LPCTSTR lpValue)
{
	DWORD dwSpyID = 0;
	LPTSTR szEntry = 0, szSpyName = 0;

	if(lSpyName)
	{
		if(m_objExDBByID.SearchItem(lSpyName, &szEntry))
		{
			return true;
		}
	}

	if(lSpyName && lpValue && *lpValue)
	{
		if(m_objExDBByEntryID.SearchItem(lpValue, &dwSpyID))
		{
			return dwSpyID == lSpyName;
		}
	}

	if(strSpyName && *strSpyName)
	{
		if(m_objExDBByName.SearchItem(strSpyName, &dwSpyID))
		{
			return true;
		}
	}

	if(strSpyName && *strSpyName && lpValue && *lpValue)
	{
		if(m_objExDBByEntryName.SearchItem(lpValue, szEntry))
		{
			if(szEntry)
			{
				if(!_tcsicmp(szEntry, strSpyName))
				{
					return true;
				}
				else if(!_tcsicmp(szEntry, RESCANNED_ENTRIES))
				{
					return true;
				}
			}
		}
	}

	if(lSpyName == Rootkit_SpyNameID_ && lpValue && *lpValue)
	{
		if(m_objExDBAutoRtkt.SearchItem(lpValue, &dwSpyID))
		{
			return dwSpyID == Rootkit_SpyNameID_;
		}
	}

	return false;
}

/*--------------------------------------------------------------------------------------
Function       : Recover
In Parameters  : ULONG &lSpyName, LPCTSTR lpValue, bool bNameDB,
Out Parameters : bool
Description    : Removing item from DB
Author         : Anand Srivastva
--------------------------------------------------------------------------------------*/
bool CExcludeDb::Recover(ULONG &lSpyName, LPCTSTR strSpyName, LPCTSTR lpValue)
{
	DWORD dwSpyID = 0;
	LPTSTR szEntry = 0, szSpyName = 0;
	CString csTempSpywareName(strSpyName);

	if(lSpyName)
	{
		if(m_objExDBByID.DeleteItem(lSpyName))
		{
			return m_bNewNodeAdded = true;
		}
	}

	if(lSpyName && lpValue && *lpValue)
	{
		if(m_objExDBByEntryID.DeleteItem(lpValue))
		{
			return m_bNewNodeAdded = true;
		}
	}

	if(strSpyName && *strSpyName && csTempSpywareName != L"Userdefined")
	{
		if(m_objExDBByName.DeleteItem(strSpyName))
		{
			return m_bNewNodeAdded = true;
		}
	}

	if(strSpyName && *strSpyName && lpValue && *lpValue)
	{
		if(m_objExDBByEntryName.DeleteItem(lpValue))
		{
			return m_bNewNodeAdded = true;
		}
	}

	return false;
}

/*--------------------------------------------------------------------------------------
Function       : IsFolderExcluded
In Parameters  : LPCTSTR szFolder
Out Parameters : bool
Description    : check if folder excluded
Author         : Anand Srivastva
--------------------------------------------------------------------------------------*/
bool CExcludeDb::IsFolderExcluded(LPCTSTR szFolder)
{
	LPTSTR szData = 0;
	CString csToken(szFolder);
	int iPos = 0;

	if((0 == szFolder) || (0 == *szFolder))
	{
		return false;
	}

	while(csToken.GetLength() > 0)
	{
		if(m_objExDBByEntryName.SearchItem(csToken, szData))
		{
			if(!_tcsicmp(szData, _T("Userdefined")))
			{
				return true;
			}
		}

		iPos = csToken.ReverseFind('\\');
		csToken = csToken.Mid(0,iPos);
	}

	return false;	
}

/*--------------------------------------------------------------------------------------
Function       : SetDatabasePath
In Parameters  : LPCTSTR szPathWithSlash
Out Parameters : void
Description    : set the path to load database from
Author         : Anand Srivastva
--------------------------------------------------------------------------------------*/
void CExcludeDb::SetDatabasePath(LPCTSTR szPathWithSlash)
{
	if(0 == szPathWithSlash || 0 == *szPathWithSlash)
	{
		return;
	}

	m_csDatabasePath = szPathWithSlash;
}

/*--------------------------------------------------------------------------------------
Function       : MergeDB
In Parameters  : CExcludeDb& objNewDB
Out Parameters : bool
Description    : merge the given db object into this
Author         : Anand Srivastva
--------------------------------------------------------------------------------------*/
bool CExcludeDb::MergeDB(CExcludeDb& objNewDB)
{
	bool bSuccess = true;

	bSuccess = m_objExDBByID.AppendObject(objNewDB.m_objExDBByID)? bSuccess: false;
	bSuccess = m_objExDBByName.AppendObject(objNewDB.m_objExDBByName)? bSuccess: false;
	bSuccess = m_objExDBByEntryID.AppendObject(objNewDB.m_objExDBByEntryID)? bSuccess: false;
	bSuccess = m_objExDBByEntryName.AppendObject(objNewDB.m_objExDBByEntryName)? bSuccess: false;
	m_bNewNodeAdded = IsModified()? true: m_bNewNodeAdded;
	return bSuccess;
}
