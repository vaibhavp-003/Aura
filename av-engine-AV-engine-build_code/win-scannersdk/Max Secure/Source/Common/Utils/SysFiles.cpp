/*======================================================================================
FILE             : SysFiles.cpp
ABSTRACT         : defines a class which checks for scanned system files and replaces from fresh
DOCUMENTS	     : 
AUTHOR		     : 
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
				  
CREATION DATE    : 
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "SysFiles.h"
#include "MaxExceptionFilter.h"
#include "CPUInfo.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CSysFiles
In Parameters	: 
Out Parameters	: 
Purpose			: constructor
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
CSysFiles::CSysFiles(void):m_objSysFilesDB(false)
{
	m_bSysWow = false;
	m_bIs64OS = false;
	m_bDrvFile = false;
	m_bDBLoaded = false;
	m_iLoadTries = 0;
}

/*-------------------------------------------------------------------------------------
Function		: ~CSysFiles
In Parameters	: 
Out Parameters	: 
Purpose			: destructor
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
CSysFiles::~CSysFiles(void)
{
	UnloadSysDB();
}

/*-------------------------------------------------------------------------------------
Function		: LoadSysDB
In Parameters	: 
Out Parameters	: 
Purpose			: load database
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CSysFiles::LoadSysDB(const CString &csMaxDBPath)
{
	CString csDBPath = csMaxDBPath + SD_DB_SYSFILES;

	if(m_bDBLoaded)
	{
		return true;
	}

	if(1 == m_iLoadTries)
	{
		AddLogEntry(L"System Database Load Failed: %s", csDBPath);
		return false;
	}

	m_iLoadTries++;
	if(!m_objSysFilesDB.Load(csDBPath))
	{
		AddLogEntry(_T("DB download set, Checking skip by database: %s"), csDBPath);
		m_objRegistry.Set(CSystemInfo::m_csProductRegKey , _T("AutoDatabasePatch"), 1, HKEY_LOCAL_MACHINE);
		return false;
	}
	m_bDBLoaded = true;
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: LoadSysDB
In Parameters	: 
Out Parameters	: 
Purpose			: load database
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CSysFiles::UnloadSysDB()
{
	m_iLoadTries = 0;
	m_bDBLoaded = false;
	return m_objSysFilesDB.RemoveAll();
}

/*-------------------------------------------------------------------------------------
Function		: LoadSysDB
In Parameters	: SD_Message_Info eScannerType, LPCTSTR szFilePath, LPTSTR szReplacePath,
					SIZE_T cchReplacePath
Out Parameters	: bool
Purpose			: check if 'szFilePath' is a system file which we have in our SysDB.
				  if present we search for a fresh copy and replace it with fresh else
				  only report it to the ui and not quarantine it.
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CSysFiles::CheckSystemFile(SD_Message_Info eScnrType, LPCTSTR szFilePath, LPTSTR szReplacePath,
								SIZE_T cchReplacePath)
{
	switch(eScnrType)
	{
	case File:
	case Rootkit_File:
	case KeyLogger_File:
	case ExecPath:
	case MD5:
	case GenPEScan:
	case Special_File:
	case Virus_File:
	case Module:
	case Pattern_File:
		{
			;
		}
		break;
	default:
		{
			return false;
		}
	}

	if(!m_bDBLoaded)
	{
		memset(szReplacePath, 0, cchReplacePath * sizeof(TCHAR));
		return true; // return true if db loading failed, so that we dont delete anything
	}

	if(!IsFilePresentInDB(szFilePath))
	{
		AddLogEntry(L"Not System File  : %s", szFilePath, 0, true, LOG_DEBUG);
		return false;
	}
	else
	{
		AddLogEntry(L"Is System File   : %s", szFilePath, 0, true, LOG_DEBUG);
	}

	memset(szReplacePath, 0, cchReplacePath * sizeof(TCHAR));
	FindFreshCopy(szFilePath, szReplacePath, cchReplacePath);
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: IsFilePresentInDB
In Parameters	: LPCTSTR szFilePath
Out Parameters	: bool
Purpose			: search the file in db
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CSysFiles::IsFilePresentInDB(LPCTSTR szFilePath)
{
	DWORD dwSpyID = 0;
	CS2U objValue(true);
	CU2OS2U objValueType(true);

	if((!szFilePath) || (szFilePath[1] != ':'))
	{
		AddLogEntry(L">>>>> Invalid FileName: %s", szFilePath);
		return false;
	}

	m_ojbDBPathExpander.SplitPathByValueType(szFilePath);
	if(!m_objSysFilesDB.SearchItem(m_ojbDBPathExpander.m_lProfileType, objValueType))
	{
		//AddLogEntry(L"!m_objSysFilesDB.SearchItem: %s", szFilePath, 0, true, LOG_DEBUG);
		return false;
	}

	if(!objValueType.SearchItem(m_ojbDBPathExpander.m_lValueTypeID, objValue))
	{
		//AddLogEntry(L"!objValueType.SearchItem: %s", szFilePath, 0, true, LOG_DEBUG);
		return false;
	}

	if(!objValue.SearchItem(m_ojbDBPathExpander.m_csValue, &dwSpyID))
	{
		//AddLogEntry(L"!objValue.SearchItem: %s, %s", szFilePath, m_ojbDBPathExpander.m_csValue, true, LOG_DEBUG);
		return false;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
Function		: FindFreshCopy
In Parameters	: LPCTSTR szFilePath, LPTSTR szReplacePath, SIZE_T cchReplacePath
Out Parameters	: bool
Purpose			: find a copy in backup locations which has a different md5
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CSysFiles::FindFreshCopy(LPCTSTR szFilePath, LPTSTR szReplacePath, SIZE_T cchReplacePath)
{
	LPCTSTR szLastSlash = 0;
	TCHAR szFileName[MAX_PATH] = {0};
	CString csReplaceFile = _T("");
	CString csFilePath = szFilePath;
	bool bSuccess = false;
	CString csSyswow = CSystemInfo::m_strSysWow64Dir;
	CString csDrvFile = CSystemInfo::m_strSysDir + _T("\\drivers");
	CCPUInfo objCPUInfo;
	CString csWinDir = objCPUInfo.GetWindowsDir();

	m_bIs64OS = m_bSysWow = m_bDrvFile = false;
	csSyswow.MakeLower();
	csDrvFile.MakeLower();
	csFilePath.MakeLower();

	szLastSlash = _tcsrchr(szFilePath, _T('\\'));
	if(!szLastSlash || !(szLastSlash + 1) || !(*(szLastSlash + 1)))
	{
		return false;
	}

	szLastSlash++;
	_tcscpy_s(szFileName, szLastSlash);

	if(csSyswow != _T("") && csFilePath.Find(csSyswow) != -1)
	{
		m_bSysWow = true;
	}

	if(csFilePath.Find(csDrvFile) != -1)
	{
		m_bDrvFile = true;
	}

	AddLogEntry(L">>>>> LOOKUP GetReplaceFileFrom: %s", szFilePath);

	if(CSystemInfo::m_strOS.Find(WXP) != -1)
	{
		if(CSystemInfo::m_strOS == WXP64 && m_bSysWow)
		{
			_stprintf_s(szFileName, _T("w%s"), csFilePath.Mid(csFilePath.ReverseFind(_T('\\')) + 1 ));
		}

		if(GetReplaceFileFrom(CSystemInfo::m_strSysDir + _T("\\dllcache\\"), szFileName, szFileName, szFilePath, szReplacePath, cchReplacePath))
			return true;
		else if(GetReplaceFileFrom(CSystemInfo::m_strWinDir + _T("\\ServicePackFiles"), NULL, szFileName, szFilePath, szReplacePath, cchReplacePath))
			return true;
		else if(GetReplaceFileFrom(CSystemInfo::m_strWinDir, L"\\$*", szFileName, szFilePath, szReplacePath, cchReplacePath))
			return true;
	}
	else if((CSystemInfo::m_strOS.Find(WVISTA) != -1) || (CSystemInfo::m_strOS.Find(WWIN7) != -1 ) || (CSystemInfo::m_strOS.Find(WWIN8) != -1))
	{
		if(CSystemInfo::m_strOS.Find(_T("64")) != -1)
		{
			m_bIs64OS = true;
		}
		if(m_bDrvFile)
		{
			if(GetReplaceFileFrom(CSystemInfo::m_strSysDir + _T("\\driverstore\\filerepository"), NULL, szFileName, szFilePath, szReplacePath, cchReplacePath))
				return true;
		}
		if(csReplaceFile == _T(""))
		{
			m_bDrvFile = false;
			if(GetReplaceFileFrom(csWinDir + _T("\\winsxs"), NULL, szFileName, szFilePath, szReplacePath, cchReplacePath))
				return true;
		}
	}

	AddLogEntry(L"@@@@@ NOTFOUND GetReplaceFileFrom: %s", szFilePath);

	return false;
}

/*-------------------------------------------------------------------------------------
Function		: AreFilesDifferent
In Parameters	: szFilePath, csReplaceFile
Out Parameters	: bool
Purpose			: return true if both files are present and different else false
Author			: Yuvraj
--------------------------------------------------------------------------------------*/
bool CSysFiles::AreFilesDifferent(LPCTSTR szFilePath1, LPCTSTR szFilePath2)
{
	CStringA csFilePath;
	char szSignature1[50] = {0}, szSignature2[50] = {0};

	if(_taccess_s(szFilePath1,0) || _taccess_s(szFilePath2,0))
	{
		return false;
	}

	csFilePath = szFilePath1;
	GetMD5Signature32(csFilePath, szSignature1);
	if(!szSignature1[0])
	{
		return false;
	}

	csFilePath = szFilePath2;
	GetMD5Signature32(csFilePath, szSignature2);
	if(!szSignature2[0])
	{
		return false;
	}
	if(strcmp(szSignature1, szSignature2) != 0)
	{
		return true;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetReplaceFileFrom
	In Parameters	: CString csHoldFileName, LPCTSTR szFilter, LPCTSTR szOriFileName, LPTSTR szReplacePath, SIZE_T cchReplacePath
	Out Parameters	: -
	Purpose			: Search the file in Winsxs folder
	Author			: Yuvraj
	Description		: Search the backup copy of file in winsxs folder for Vista and Win7
--------------------------------------------------------------------------------------*/
bool CSysFiles::GetReplaceFileFrom(CString csHoldFileName, LPCTSTR szFilter, LPCTSTR szOriFileName, LPCTSTR szOrigFullFilePath, LPTSTR szReplacePath, SIZE_T cchReplacePath)
{
	bool bFreshFileFound = false;
	CFileFind objFinder;
	BOOL bMoreFiles = FALSE;
	LPCTSTR szFileName = 0;

	if(szFilter)
	{
		csHoldFileName += szFilter;
	}
	else
	{
		csHoldFileName += _T("\\*");
	}

	bMoreFiles = objFinder.FindFile(csHoldFileName);
	if(!bMoreFiles)
	{
		AddLogEntry(L">>>>> FAILED GetReplaceFileFrom: %s", csHoldFileName);
		return bFreshFileFound;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if (objFinder.IsDots())
			continue;

		csHoldFileName = objFinder.GetFilePath();
		if(!m_bDrvFile)
		{
			if(m_bIs64OS && !m_bSysWow)
			{
				if(csHoldFileName.Find(_T("\\amd64")) == -1)
					continue;
			}
			else if((csHoldFileName.Find(_T("\\x86")) == -1) && (csHoldFileName.Find(_T("\\wow64")) == -1))
			{
				continue;
			}
		}

		if (objFinder.IsDirectory())
		{
			if(GetReplaceFileFrom(csHoldFileName, NULL, szOriFileName, szOrigFullFilePath, szReplacePath, cchReplacePath))
			{
				bFreshFileFound = true;
				break;
			}
		}
		else
		{
			szFileName = _tcsrchr(csHoldFileName, _T('\\'));
			if(!szFileName)
			{
				continue;
			}
			szFileName++;
			if(_tcsicmp(szFileName, szOriFileName) == 0)	// same filename
			{
				if(AreFilesDifferent(szOrigFullFilePath, csHoldFileName))	// different MD5
				{
					csHoldFileName.MakeLower();
					_tcscpy_s(szReplacePath, cchReplacePath, csHoldFileName);
					bFreshFileFound = true;
					AddLogEntry(L"##### SUCCESS GetReplaceFileFrom: %s", csHoldFileName);
					break;
				}
			}
		}
	}
	objFinder.Close();
	return bFreshFileFound;
}


