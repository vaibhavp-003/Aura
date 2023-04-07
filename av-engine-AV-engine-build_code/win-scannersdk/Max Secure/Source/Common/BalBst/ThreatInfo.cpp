
/*======================================================================================
FILE             : ThreatInfo.cpp
ABSTRACT         : defines class to handle database type of threat info(threat name)
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 11/Aug/2010
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "ThreatInfo.h"

BYTE HEADER_THREAT_INFO[24]			= {"MAXDBVERSION00.00.00.10"};
BYTE HEADER_THREAT_INFO_DATA[24]	= {0};

struct _tagNameTableOldToNew
{
	char* szOld;
	char* szNew;
}g_stOldNewTable[] =
{
	{"Undefine", "Auto"},
	{"Sendbox", "Bot"},
	{"UnDefined-Spy-Name", "Agent.usn"},
	{"UnDefined-White-Name", "Agent.uwn"},
	{"Whitelist", "Agent.wl"}
};


CThreatInfo::CThreatInfo(bool bForUpdate):m_objNameDB(false), m_objIDDB(false),
										  m_objCateDB(false, sizeof(DWORD), sizeof(CATE_INFO), sizeof(DWORD))
{
	m_dwHdrSize = sizeof(HEADER_THREAT_INFO) + sizeof(HEADER_THREAT_INFO_DATA);
	m_hFile = INVALID_HANDLE_VALUE;
	m_hMMapFile = 0;
	m_dwCount = m_dwNameID = 0;
	memset(m_szCate, 0, sizeof(m_szCate));
	memset(m_szName, 0, sizeof(m_szName));
	memset(m_szVrnt, 0, sizeof(m_szVrnt));
	memset(m_szCateT, 0, sizeof(m_szCateT));
	memset(m_szNameT, 0, sizeof(m_szNameT));
	memset(m_szVrntT, 0, sizeof(m_szVrntT));
	memset(m_szTempFileName, 0, sizeof(m_szTempFileName));
	memset(m_szTempFilePath, 0, sizeof(m_szTempFilePath));

	m_bForUpdate = bForUpdate;
	m_bModified = false;
	m_bTempFile = false;
}

CThreatInfo::~CThreatInfo()
{
	//AddLogEntry(L"CThreatInfo::~CThreatInfo()");
	RemoveAll();
}

bool CThreatInfo::SetTempPath(LPCTSTR szTempPath)
{
	int iCount = 0;

	if(!szTempPath || !(*szTempPath))
	{
		return false;
	}

	iCount = (int)_tcslen(szTempPath);
	if(iCount >= _countof(m_szTempFilePath))
	{
		return false;
	}

	if(_T('\\') == szTempPath[iCount - 1])
	{
		iCount--;
	}

	memset(m_szTempFilePath, 0, sizeof(m_szTempFilePath));
	_tcsncpy_s(m_szTempFilePath, _countof(m_szTempFilePath), szTempPath, iCount);
	return true;
}

bool CThreatInfo::Balance()
{
	m_objCateDB.Balance();
	m_objIDDB.Balance();
	m_objNameDB.Balance();
	return true;
}

bool CThreatInfo::ConvertU2A(LPSTR szAnsi, SIZE_T cchAnsi, LPCTSTR szUnicode)
{
	SIZE_T iUnicodeLen = _tcslen(szUnicode);

	if(iUnicodeLen >= cchAnsi)
	{
		return false;
	}

	for(SIZE_T i = 0; i < iUnicodeLen; i++)
	{
		szAnsi[i] = (CHAR)szUnicode[i];
	}

	return true;
}

bool CThreatInfo::ConvertU2A_MEM(LPSTR szAnsi, SIZE_T cchAnsi, LPCTSTR szUnicode, SIZE_T cchUnicode)
{
	if(cchUnicode > cchAnsi)
	{
		return false;
	}

	for(SIZE_T i = 0; i < cchUnicode; i++)
	{
		szAnsi[i] = (CHAR)szUnicode[i];
	}

	return true;
}

bool CThreatInfo::ConvertA2U(LPTSTR szUnicode, SIZE_T cchUnicode, LPCSTR szAnsi)
{
	SIZE_T iAnsiLen = strlen(szAnsi);

	if(iAnsiLen >= cchUnicode)
	{
		return false;
	}

	for(SIZE_T i = 0; i < iAnsiLen; i++)
	{
		szUnicode[i] = szAnsi[i];
	}

	return true;
}

bool CThreatInfo::PrepareFileNames(LPCTSTR szFilePath, LPTSTR szCateFileName, DWORD cchCateFileName,
									  LPTSTR szNameFileName, DWORD cchNameFileName, LPTSTR szIDFileName,
									  DWORD cchIDFileName)
{
	LPCTSTR DotPtr = 0;

	DotPtr = _tcsrchr(szFilePath, _T('.'));
	if(!DotPtr)
	{
		return false;
	}

	_tcsncpy_s(szCateFileName, cchCateFileName, szFilePath, DotPtr - szFilePath);
	_tcscat_s(szCateFileName, cchCateFileName, FILE_CAT);
	_tcsncpy_s(szNameFileName, cchNameFileName, szFilePath, DotPtr - szFilePath);
	_tcscat_s(szNameFileName, cchNameFileName, FILE_NAM);
	_tcsncpy_s(szIDFileName, cchIDFileName, szFilePath, DotPtr - szFilePath);
	_tcscat_s(szIDFileName, cchIDFileName, FILE_ID);
	return true;
}

bool CThreatInfo::CleanupTempFiles(LPCTSTR szFolderPath, LPCTSTR szWildCard)
{
	struct _tfinddata_t fileinfo = {0};
	intptr_t iSearch = 0;
	TCHAR szFullPath[MAX_PATH] = {0};

	if(_tcslen(szFolderPath) + _tcslen(szWildCard) + 1 >= _countof(szFullPath))
	{
		return false;
	}

	_stprintf_s(szFullPath, _countof(szFullPath), _T("%s%s"), szFolderPath, szWildCard);
	iSearch = _tfindfirst(szFullPath, &fileinfo);
	if(-1 == iSearch)
	{
		return false;
	}

	do
	{
		if(_tcslen(szFolderPath) + _tcslen(fileinfo.name) + 2 < _countof(szFullPath))
		{
			_stprintf_s(szFullPath, _countof(szFullPath), _T("%s\\%s"), szFolderPath, fileinfo.name);
			_tremove(szFullPath);
		}
	}while(!_tfindnext(iSearch, &fileinfo));

	_findclose(iSearch);
	return true;
}

bool CThreatInfo::GenerateTempFileName()
{
	if(m_szTempFileName[0])
	{
		return true;
	}

	if(!m_szTempFilePath[0])
	{
		memset(m_szTempFilePath, 0, sizeof(m_szTempFilePath));
		GetTempPath(_countof(m_szTempFilePath), m_szTempFilePath);
	}

	CleanupTempFiles(m_szTempFilePath, _T("\\Max*.tmp"));
	if(0 == GetTempFileName(m_szTempFilePath, L"MaxTmp", 0, m_szTempFileName))
	{
		return false;
	}

	m_bTempFile = true;
	return true;
}

HANDLE CThreatInfo::CreateTempFile()
{
	HANDLE hFile = INVALID_HANDLE_VALUE;

	if(!GenerateTempFileName())
	{
		return INVALID_HANDLE_VALUE;
	}

	hFile = CreateFile(m_szTempFileName, GENERIC_READ|GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return INVALID_HANDLE_VALUE;
	}

	return hFile;
}

bool CThreatInfo::SplitThreatName(LPCTSTR szCatName, LPCTSTR szSpyName)
{
	LPCTSTR PtrDot = 0;
	TCHAR szHoldVar[_countof(m_szVrntT) + 1] = {0};

	memset(m_szCate, 0, sizeof(m_szCate));
	memset(m_szName, 0, sizeof(m_szName));
	memset(m_szVrnt, 0, sizeof(m_szVrnt));
	memset(m_szCateT, 0, sizeof(m_szCateT));
	memset(m_szNameT, 0, sizeof(m_szNameT));
	memset(m_szVrntT, 0, sizeof(m_szVrntT));

	PtrDot = _tcsrchr(szSpyName, _T('.'));
	if(PtrDot && (_tcslen(PtrDot + 1) <= _countof(m_szVrntT)))
	{
		if((PtrDot - szSpyName) >= _countof(m_szNameT))
		{
			return false;
		}

		_tcsncpy_s(m_szNameT, _countof(m_szNameT), szSpyName, PtrDot - szSpyName);
		_tcsncpy_s(szHoldVar, _countof(szHoldVar), PtrDot + 1, _countof(m_szVrntT));
		memcpy(m_szVrntT, szHoldVar, _countof(m_szVrntT) * sizeof(TCHAR));
	}
	else
	{
		if(_tcslen(szSpyName) >= _countof(m_szNameT))
		{
			return false;
		}

		_tcscpy_s(m_szNameT, _countof(m_szNameT), szSpyName);
	}

	if(_tcslen(szCatName) >= _countof(m_szCateT))
	{
		return false;
	}

	_tcscpy_s(m_szCateT, _countof(m_szCateT), szCatName);
	if(!ConvertU2A(m_szCate, _countof(m_szCate), m_szCateT))
	{
		return false;
	}

	if(!ConvertU2A(m_szName, _countof(m_szName), m_szNameT))
	{
		return false;
	}

	if(!ConvertU2A_MEM(m_szVrnt, _countof(m_szVrnt), m_szVrntT, _countof(m_szVrntT)))
	{
		return false;
	}

	return true;
}

bool CThreatInfo::PrepareEntry(LPTHREAT_INFO lpEntry, DWORD dwSpyID, DWORD dwCatID, BYTE byTLevel, LPCTSTR szTDesc)
{
	DWORD dwNameID = 0;
	LPVOID lpCateInfo = NULL;

	if(!m_objCateDB.SearchItem(&dwCatID, lpCateInfo))
	{
		CATE_INFO CateInfo = {0};

		strcpy_s(CateInfo.szName, _countof(CateInfo.szName), m_szCate);
		if(!ConvertU2A(CateInfo.szDesc, _countof(CateInfo.szDesc), szTDesc))
		{
			return false;
		}

		if(!m_objCateDB.AppendItem(&dwCatID, &CateInfo))
		{
			return false;
		}
	}

	if(!m_objNameDB.SearchItem(m_szName, &dwNameID))
	{
		dwNameID = m_dwNameID;
		if(!m_objNameDB.AppendItem(m_szName, dwNameID))
		{
			return false;
		}

		if(!m_objIDDB.AppendItem(dwNameID, m_szName))
		{
			return false;
		}

		m_dwNameID++;
	}

	lpEntry->dwThrtID = dwSpyID;
	lpEntry->dwCateID = dwCatID;
	lpEntry->dwNameID = dwNameID;
	lpEntry->byThreatLevel = byTLevel;
	memcpy(lpEntry->szVariant, m_szVrnt, sizeof(lpEntry->szVariant));
	return true;
}

bool CThreatInfo::AddThreatEntry(LPTHREAT_INFO lpThreatInfo)
{
	DWORD dwThreatInfoOffset = 0, dwBytesWritten = 0;

	if(INVALID_HANDLE_VALUE == m_hFile)
	{
		m_hFile = CreateTempFile();
		if(INVALID_HANDLE_VALUE == m_hFile)
		{
			return false;
		}
	}

	if(m_bForUpdate)
	{
		dwThreatInfoOffset = m_dwHdrSize + (m_dwCount * sizeof(THREAT_INFO));
	}
	else
	{
		dwThreatInfoOffset = m_dwHdrSize + (lpThreatInfo->dwThrtID * sizeof(THREAT_INFO));
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(m_hFile, dwThreatInfoOffset, 0, FILE_BEGIN))
	{
		return false;
	}

	if(!WriteFile(m_hFile, lpThreatInfo, sizeof(THREAT_INFO), &dwBytesWritten, 0))
	{
		return false;
	}

	if(sizeof(THREAT_INFO) != dwBytesWritten)
	{
		return false;
	}

	return true;
}

bool CThreatInfo::AppendItem(DWORD dwSpyID, LPCTSTR szSpyName, DWORD dwCatID, LPCTSTR szCatName,
								BYTE byThreatLevel, LPCTSTR szThreatDescription)
{
	THREAT_INFO ThreatInfo = {0};

	if(!SplitThreatName(szCatName, szSpyName))
	{
		return false;
	}

	if(!PrepareEntry(&ThreatInfo, dwSpyID, dwCatID, byThreatLevel, szThreatDescription))
	{
		return false;
	}

	if(!AddThreatEntry(&ThreatInfo))
	{
		return false;
	}

	m_dwCount++;
	m_bModified = true;
	return true;
}

bool CThreatInfo::SearchItem(DWORD dwKey, BYTE& byThreatLevel, LPTSTR szThreatDescription,
							 SIZE_T cchThreatDescription, LPTSTR szThreatName, SIZE_T cchThreatName)
{
	byThreatLevel = 30;
	_stprintf(szThreatName,_T("Trojan.Malware.%d.susgen"),dwKey);
	_tcscpy_s(szThreatDescription, cchThreatDescription, _T("Malicious software designed to infiltrate a computer system without the owner's informed consent."));
	return true;

	
	
	/*
	LPCATE_INFO lpCatInfo = NULL;
	THREAT_INFO ThreatInfo = {0};
	DWORD dwThreatInfoOffset = 0, dwBytesRead = 0;
	CHAR *szThreatNameA = NULL, szFullThreatName[MAX_PATH] = {0}, szVar[MAX_VRNT_NAME + 1] = {0};

	dwThreatInfoOffset = m_dwHdrSize + (dwKey * sizeof(THREAT_INFO));
	if(INVALID_SET_FILE_POINTER == SetFilePointer(m_hFile, dwThreatInfoOffset, 0, FILE_BEGIN))
	{
		AddLogEntry(L"NAMEDB SEARCH: Failed SFP");
		goto ERROR_EXIT;
	}

	if(!ReadFile(m_hFile, &ThreatInfo, sizeof(ThreatInfo), &dwBytesRead, 0))
	{
		AddLogEntry(L"NAMEDB SEARCH: Failed RF1");
		goto ERROR_EXIT;
	}

	if(-1 == ThreatInfo.dwNameID) // change by nilesh on 24th JAN 2012 it does not show 0th item in DBStudyTool
	{
		AddLogEntry(L"NAMEDB SEARCH: ID is -1");
		goto ERROR_EXIT;
	}

	if(!m_objIDDB.SearchItem(ThreatInfo.dwNameID, &szThreatNameA))
	{
		AddLogEntry(L"NAMEDB SEARCH: Failed searching ID");
		goto ERROR_EXIT;
	}

	for(int i = 2; i < _countof(g_stOldNewTable); i++)
	{
		if(!_stricmp(szThreatNameA, g_stOldNewTable[i].szOld))
		{
			szThreatNameA = g_stOldNewTable[i].szNew;
			break;
		}
	}

	if(!m_objCateDB.SearchItem(&ThreatInfo.dwCateID, (LPVOID&)lpCatInfo))
	{
		AddLogEntry(L"NAMEDB SEARCH: Failed searching CT");
		goto ERROR_EXIT;
	}

	for(int i = 0; i < 2; i++)
	{
		if(!_stricmp(lpCatInfo->szName, g_stOldNewTable[i].szOld))
		{
			strcpy_s(lpCatInfo->szName, _countof(lpCatInfo->szName), g_stOldNewTable[i].szNew);
			break;
		}
	}

	memcpy(szVar, ThreatInfo.szVariant, sizeof(ThreatInfo.szVariant));
	strcpy_s(szFullThreatName, _countof(szFullThreatName), lpCatInfo->szName);

	if(0 == szFullThreatName[0])
	{
		AddLogEntry(L"NAMEDB SEARCH: threat name not found");
		goto ERROR_EXIT;
	}

	if(szThreatNameA[0])
	{
		strcat_s(szFullThreatName, _countof(szFullThreatName), ".");
		strcat_s(szFullThreatName, _countof(szFullThreatName), szThreatNameA);
	}

	if(szVar[0])
	{
		strcat_s(szFullThreatName, _countof(szFullThreatName), ".");
		strcat_s(szFullThreatName, _countof(szFullThreatName), szVar);
	}

	if(!ConvertA2U(szThreatName, cchThreatName, szFullThreatName))
	{
		AddLogEntry(L"NAMEDB SEARCH: Failed A2U-1");
		goto ERROR_EXIT;
	}

	if(!ConvertA2U(szThreatDescription, cchThreatDescription, lpCatInfo->szDesc))
	{
		AddLogEntry(L"NAMEDB SEARCH: Failed A2U-2");
		goto ERROR_EXIT;
	}

	byThreatLevel = ThreatInfo.byThreatLevel;
	return true;

ERROR_EXIT:

	{
		TCHAR szLogString[100] = {0};
		_stprintf_s(szLogString, _countof(szLogString), L"%u", dwKey);
		AddLogEntry(L"ID Searched: %s", szLogString);
		_stprintf_s(szLogString, _countof(szLogString), L"%u", cchThreatDescription);
		AddLogEntry(L"size thrt desc: %s", szLogString);
		_stprintf_s(szLogString, _countof(szLogString), L"%u", cchThreatName);
		AddLogEntry(L"size thrt name: %s", szLogString);
	}

	byThreatLevel = 50;
	_tcscpy_s(szThreatName, cchThreatName, _T("Malware.Generic.512"));
	_tcscpy_s(szThreatDescription, cchThreatDescription, _T("Malicious software designed to infiltrate a computer system without the owner's informed consent."));
	return true;
	*/
}

bool CThreatInfo::GetDataByID(LPTHREAT_INFO lpThreatInfo, BYTE& byTL, LPTSTR szCName, DWORD cchCName,
							  LPTSTR szTName, DWORD cchTName, LPTSTR szTDesc, DWORD cchTDesc)
{
	LPCATE_INFO lpCatInfo = NULL;
	CHAR *szThreatNameA = NULL, szVarA[MAX_VRNT_NAME + 1] = {0};

	if(!m_objIDDB.SearchItem(lpThreatInfo->dwNameID, &szThreatNameA))
	{
		return false;
	}

	if(!m_objCateDB.SearchItem(&lpThreatInfo->dwCateID, (LPVOID&)lpCatInfo))
	{
		return false;
	}

	memcpy(szVarA, lpThreatInfo->szVariant, sizeof(lpThreatInfo->szVariant));
	_stprintf_s(szCName, cchCName, _T("%S"), lpCatInfo->szName);
	_stprintf_s(szTName, cchTName, _T("%S.%S"), szThreatNameA, szVarA);
	_stprintf_s(szTDesc, cchTDesc, _T("%S"), lpCatInfo->szDesc);
	byTL = lpThreatInfo->byThreatLevel;
	return true;
}

bool CThreatInfo::GetItemByIndex(DWORD dwIndex, LPTHREAT_INFO lpThreatInfo)
{
	DWORD dwThreatInfoOffset = 0, dwBytesRead = 0;

	dwThreatInfoOffset = m_dwHdrSize + (dwIndex * sizeof(THREAT_INFO));
	if(INVALID_SET_FILE_POINTER == SetFilePointer(m_hFile, dwThreatInfoOffset, 0, FILE_BEGIN))
	{
		return false;
	}

	if(!ReadFile(m_hFile, lpThreatInfo, sizeof(THREAT_INFO), &dwBytesRead, 0))
	{
		return false;
	}

	if(sizeof(THREAT_INFO) != dwBytesRead)
	{
		return false;
	}

	return true;
}

DWORD CThreatInfo::GetCount()
{
	return m_dwCount;
}

bool CThreatInfo::RemoveAll()
{
	if(INVALID_HANDLE_VALUE != m_hFile)
	{
		//AddLogEntry(L"close handle: %s", m_szTempFileName);
		CloseHandle(m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
	}

	//AddLogEntry(L"del: %s", m_szTempFileName);
	DeleteFile(m_szTempFileName);
	memset(m_szTempFileName, 0, sizeof(m_szTempFileName));
	m_objNameDB.RemoveAll();
	m_objCateDB.RemoveAll();
	m_objIDDB.RemoveAll();
	m_dwNameID = 0;
	m_dwCount = 0;
	//AddLogEntry(L"done removeall");
	return true;
}

bool CThreatInfo::IsLoaded()
{
	return INVALID_HANDLE_VALUE != m_hFile;
}

bool CThreatInfo::IsModified()
{
	return m_bModified;
}

bool CThreatInfo::AddDBFile(LPCTSTR szFullFileName)
{
	bool bError = false, bHold = false;
	CThreatInfo objDelta;
	THREAT_INFO TInfo = {0};
	BYTE byTL = 0;
	TCHAR szTDesc[MAX_CATE_DESC] = {0}, szTName[MAX_THRT_NAME] = {0}, szCName[MAX_CATE_NAME] = {0};

	if(!objDelta.Load(szFullFileName))
	{
		return false;
	}

	bHold = m_bForUpdate;
	m_bForUpdate = false;

	for(DWORD dwIndex = 0; dwIndex < objDelta.m_dwCount; dwIndex++)
	{
		if(!objDelta.GetItemByIndex(dwIndex, &TInfo))
		{
			break;
		}

		if(!objDelta.GetDataByID(&TInfo, byTL, szCName, _countof(szCName), szTName, _countof(szTName), szTDesc, _countof(szTDesc)))
		{
			bError = true;
			break;
		}

		if(!AppendItem(TInfo.dwThrtID, szTName, TInfo.dwCateID, szCName, byTL, szTDesc))
		{
			bError = true;
			break;
		}
	}

	m_bForUpdate = bHold;
	return bError;
}

bool CThreatInfo::DelDBFile(LPCTSTR szFullFileName)
{
	return true;
}

bool CThreatInfo::Load(LPCTSTR szFilePath, bool bEncryptContents, bool bCheckVersion, bool bIntegrity)
{
	HANDLE hFile = 0;
	TCHAR szFullFilePath[MAX_PATH] = {0};
	DWORD dwFileSize = 0, dwBytesRead = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_THREAT_INFO)] = {0};
	BYTE byHeaderDataFromFile[sizeof(HEADER_THREAT_INFO_DATA)] ={0};
	TCHAR szCateFileName[MAX_PATH] = {0}, szNameFileName[MAX_PATH] = {0}, szIDFileName[MAX_PATH] = {0};

	if(!MakeFullFilePath(szFilePath, szFullFilePath, _countof(szFullFilePath)))
	{
		return false;
	}

	hFile = CreateFile(szFullFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		//AddLogEntry(L"NAMEDB: Failed loading file: %s", szFullFilePath);
		return false;
	}

	if(!ReadFile(hFile, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE), &dwBytesRead, 0))
	{
		CloseHandle(hFile);
		AddLogEntry(L"NAMEDB: Failed reading1 file: %s", szFullFilePath);
		return false;
	}

	if(bCheckVersion && memcmp(HEADER_THREAT_INFO, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
	{
		CloseHandle(hFile);
		AddLogEntry(L"NAMEDB: Header version mismatch: %s", szFullFilePath);
		return false;
	}

	if(!ReadFile(hFile, byHeaderDataFromFile, sizeof(byHeaderDataFromFile), &dwBytesRead, 0))
	{
		CloseHandle(hFile);
		AddLogEntry(L"NAMEDB: Failed reading2 file: %s", szFullFilePath);
		return false;
	}

	if(!CreateHeaderData(hFile, szFullFilePath, HEADER_THREAT_INFO_DATA, sizeof(HEADER_THREAT_INFO_DATA)))
	{
		CloseHandle(hFile);
		AddLogEntry(L"NAMEDB: Failed CreateHeaderData : %s", szFullFilePath);
		return false;
	}

	if(bIntegrity && memcmp(byHeaderDataFromFile, HEADER_THREAT_INFO_DATA, sizeof(HEADER_THREAT_INFO_DATA)))
	{
		CloseHandle(hFile);
		AddLogEntry(L"NAMEDB: Header mismatch: %s", szFullFilePath);
		return false;
	}

	CloseHandle(hFile);
	if(!GenerateTempFileName())
	{
		AddLogEntry(L"NAMEDB: Generate temp file failed: %s", szFullFilePath);
		return false;
	}

	if(bEncryptContents)
	{
		if(!CopyAndCryptFile(szFullFilePath, m_szTempFileName, 0x00100000, m_dwHdrSize))
		{
			AddLogEntry(L"NAMEDB: Failed CopyAndCryptFile: %s", szFullFilePath);
			return false;
		}
	}
	else
	{
		if(!CopyFile(szFullFilePath, m_szTempFileName, FALSE))
		{
			AddLogEntry(L"NAMEDB: Failed CopyFile: %s", szFullFilePath);
			return false;
		}
	}

	m_hFile = CreateFile(m_szTempFileName, m_bForUpdate ? GENERIC_READ|GENERIC_WRITE : GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == m_hFile)
	{
		AddLogEntry(L"NAMEDB: Failed creating temp file: %s", szFullFilePath);
		return false;
	}

	if(!PrepareFileNames(szFullFilePath, szCateFileName, MAX_PATH, szNameFileName, MAX_PATH, szIDFileName, MAX_PATH))
	{
		CloseHandle(m_hFile);
		AddLogEntry(L"NAMEDB: Failed preparing filenames: %s", szFullFilePath);
		return false;
	}

	m_objIDDB.RemoveAll();
	m_objNameDB.RemoveAll();
	m_objCateDB.RemoveAll();
	if(!m_objNameDB.Load(szNameFileName))
	{
		AddLogEntry(L"NAMEDB: Failed loading nm file: %s", szNameFileName);
		return false;
	}

	if(!m_objIDDB.Load(szIDFileName))
	{
		AddLogEntry(L"NAMEDB: Failed loading id file: %s", szIDFileName);
		return false;
	}

	if(!m_objCateDB.Load(szCateFileName))
	{
		AddLogEntry(L"NAMEDB: Failed loading ct file: %s", szCateFileName);
		return false;
	}

	m_dwNameID = m_objNameDB.GetCount();
	dwFileSize = GetFileSize(m_hFile, 0);
	dwFileSize -= m_dwHdrSize;
	m_dwCount = dwFileSize / sizeof(THREAT_INFO);
	return true;
}

bool CThreatInfo::Save(LPCTSTR szFilePath, bool bEncryptContents)
{
	DWORD dwBytesWritten = 0;
	TCHAR szFullFilePath[MAX_PATH] = {0};
	TCHAR szCateFileName[MAX_PATH] = {0}, szNameFileName[MAX_PATH] = {0}, szIDFileName[MAX_PATH] = {0};

	if(!MakeFullFilePath(szFilePath, szFullFilePath, _countof(szFullFilePath)))
	{
		return false;
	}

	if(INVALID_HANDLE_VALUE == m_hFile)
	{
		return false;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(m_hFile, 0, 0, FILE_BEGIN))
	{
		CloseHandle(m_hFile);
		return false;
	}

	if(!WriteFile(m_hFile, HEADER_THREAT_INFO, sizeof(HEADER_THREAT_INFO), &dwBytesWritten, 0))
	{
		CloseHandle(m_hFile);
		return false;
	}

	if(!CreateHeaderData(m_hFile, szFullFilePath, HEADER_THREAT_INFO_DATA, sizeof(HEADER_THREAT_INFO_DATA)))
	{
		CloseHandle(m_hFile);
		return false;
	}

	if(!WriteFile(m_hFile, HEADER_THREAT_INFO_DATA, sizeof(HEADER_THREAT_INFO_DATA), &dwBytesWritten, 0))
	{
		CloseHandle(m_hFile);
		return false;
	}

	CloseHandle(m_hFile);
	m_hFile = INVALID_HANDLE_VALUE;
	if(bEncryptContents)
	{
		if(!CopyAndCryptFile(m_szTempFileName, szFullFilePath, 0x00100000, m_dwHdrSize))
		{
			return false;
		}
	}
	else
	{
		if(!CopyFile(m_szTempFileName, szFullFilePath, FALSE))
		{
			return false;
		}
	}

	if(!PrepareFileNames(szFullFilePath, szCateFileName, MAX_PATH, szNameFileName, MAX_PATH, szIDFileName, MAX_PATH))
	{
		return false;
	}

	m_objIDDB.Balance();
	m_objNameDB.Balance();
	m_objCateDB.Balance();
	if(!m_objNameDB.Save(szNameFileName, bEncryptContents))
	{
		return false;
	}

	if(!m_objIDDB.Save(szIDFileName, bEncryptContents))
	{
		return false;
	}

	if(!m_objCateDB.Save(szCateFileName, bEncryptContents))
	{
		return false;
	}

	return true;
}

