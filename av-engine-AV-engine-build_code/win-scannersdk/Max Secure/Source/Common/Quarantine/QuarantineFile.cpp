/*======================================================================================
   FILE				: QuarantineFile.cpp
   ABSTRACT			: To Store Quarantine spywares into DB file
   DOCUMENTS		: Refer The Design Folder (SpyEliminator-LLD.Doc)
   AUTHOR			: Dipali Pawar
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 12-12-2007
   NOTE				: 
   VERSION HISTORY	: 
					Date: 15-July-08
					Resource: Dipali
					Description: Changed SDremovedb.db path to apppath

=======================================================================================*/

#include "pch.h"
#include "QuarantineFile.h"
#include "Registry.h"
#include "Shlwapi.h"
#include "SDSystemInfo.h"
#include <winsvc.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CStringArray obj;
//Static objects
CStdioFile CQuarantineFile::objFileDelete;
CStdioFile CQuarantineFile::objFileRemove;
CStringArray CQuarantineFile::m_csRemovedEntryArr;

/*-------------------------------------------------------------------------------------
	Function		: GetFileName
	In Parameters	: CString csFileName
	Out	Parameters	: CString
	Purpose			: Get File Name of remove  Database
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CString CQuarantineFile::GetFileName(CString csFileName)
{
	CString csPath = CSystemInfo::m_strAppPath + _T("\\") + csFileName;
	SetFileAttributes(csPath, FILE_ATTRIBUTE_ARCHIVE);
	return (csPath);
}

/*-------------------------------------------------------------------------------------
	Function		: OpenRemDBFile
	In Parameters	: -
	Out	Parameters	: bool
	Purpose			: Open Remove Database File
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CQuarantineFile::OpenRemDBFile(CString csFileName)
{
	m_csRemovedEntryArr.RemoveAll();
	
	CString strFileName;
	CFileException ex;
	strFileName = GetFileName(csFileName);
	if(!objFileRemove.Open((LPCTSTR)strFileName, CFile::modeCreate | CFile::modeNoTruncate | CFile::modeWrite,&ex))
		return false;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CloseRemDBFile
	In Parameters	: -
	Out	Parameters	: bool
	Purpose			: Close Remove Database File
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CQuarantineFile::CloseRemDBFile()
{
	if(objFileRemove)
	{
		if(objFileRemove.m_hFile)
		{
			CString csToWrite;
			for(int i=0; i< m_csRemovedEntryArr.GetCount(); i++)
			{
				csToWrite = m_csRemovedEntryArr.GetAt(i);
				objFileRemove.SeekToEnd();		
				objFileRemove.WriteString(csToWrite);		
			}
			m_csRemovedEntryArr.RemoveAll();
			objFileRemove.Close();
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenDelDBFile
	In Parameters	: -
	Out	Parameters	: bool
	Purpose			: Open Delete Database File
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CQuarantineFile::OpenDelDBFile()
{
	CString strFileName;
	CFileException ex;
	strFileName = GetFileName(DELETE_SPYDB_FILE_NAME);
	if(!objFileDelete.Open((LPCTSTR)strFileName, CFile::modeCreate | CFile::modeNoTruncate | CFile::modeWrite,&ex))
		return false;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CloseDelDBFile
	In Parameters	: -
	Out	Parameters	: bool
	Purpose			: close Delete Database File
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CQuarantineFile::CloseDelDBFile()
{
	if(objFileDelete)
		if(objFileDelete.m_hFile)
			objFileDelete.Close();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: AddEntryInRemoveDB
	In Parameters	: CString csSpyName, CString csWormType, CString csWorm, CString csNewFileName
	Out	Parameters	: void
	Purpose			: Write Spyware Entry into Remove Database
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CQuarantineFile::AddEntryInRemoveDB(ULONG ulSpyName, CString csWormType, CString csWorm, CString csNewFileName)
{
	csWormType.Trim();
	csWormType.Replace(_T("\n"),_T(""));
	csWorm.Trim();
	csWorm.Replace(_T("\n"),_T(""));
	csNewFileName.Trim();
	csNewFileName.Replace(_T("\n"),_T(""));
	csWorm.MakeLower();
	try
	{
		CString csToWrite = _T("");
		CString csTemp;
		csTemp.Format(_T("%d"), ulSpyName);
		csToWrite = csToWrite + csTemp;
		csToWrite = csToWrite + _T("\n");
		csToWrite = csToWrite + csWormType;
		csToWrite = csToWrite + _T("\n");
		csToWrite = csToWrite + csWorm;
		csToWrite = csToWrite + _T("\n");
		csToWrite = csToWrite + csNewFileName;
		csToWrite = csToWrite + _T("\n");		
		m_csRemovedEntryArr.Add(csToWrite);
		//objFileRemove.SeekToEnd();		
		//objFileRemove.WriteString(csToWrite);		
	}
	catch(...)
	{
		CString cs;
		cs.Format(L"%d",::GetLastError());
		AddLogEntry(_T("Exception caught in CQuarantineFile::AddEntryInRemoveDB %s"),cs);		
	}
}

/*-------------------------------------------------------------------------------------
	Function		: AddEntryInDeleteDB
	In Parameters	: CString csSpyName, CString csWormType, CString csWorm
	Out	Parameters	: void
	Purpose			: Write Spyware Entry into Delete Database
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CQuarantineFile::AddEntryInDeleteDB(CString csSpyName, CString csWormType, CString csWorm)
{
	try
	{
		CString csToWrite = _T("");
		csToWrite = csToWrite + csSpyName;
		csToWrite = csToWrite + _T("\n");
		csToWrite = csToWrite + csWormType;
		csToWrite = csToWrite + _T("\n");
		csToWrite = csToWrite + csWorm;
		csToWrite = csToWrite + _T("\n");
		objFileDelete.SeekToEnd();
		objFileDelete.WriteString(csToWrite);		
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CQuarantineFile::AddEntryInDeleteDB"));
	}
}

/*-------------------------------------------------------------------------------------
	Function		: AddInRestartDeleteList
	In Parameters	: CString csWormInfo, CString csWormType, bool bDeleteWorm
	Out	Parameters	: bool
	Purpose			: Write Spyware Entry into Restart Delete list ini
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CQuarantineFile::AddInRestartDeleteList(CString csWormInfo, CString csWormType, bool bDeleteWorm )			
{
	try
	{
		CString csDeleteINI = CSystemInfo::m_strAppPath + SVCQUARANTINEINI;
		if(!bDeleteWorm)
		{
			if(csWormType == _T("Registry Key")) csWormType = _T("RegistryKey");
			if(csWormType == _T("Registry Value")) csWormType = _T("RegistryValue");
			if(csWormType == _T("Registry Data")) csWormType = _T("RegistryData");
			TCHAR buff[100]={0};
			if(csWormType != _T("Process") )
			{
				int iWormCnt = GetPrivateProfileInt(csWormType, _T("WormCnt"), 0, csDeleteINI);
				swprintf_s(buff,_countof(buff), _T("%d"), iWormCnt);
				WritePrivateProfileString(csWormType, buff, csWormInfo, csDeleteINI);
				iWormCnt++;
				swprintf_s(buff,_countof(buff), _T("%d"), iWormCnt);
				WritePrivateProfileString(csWormType, _T("WormCnt"), buff, csDeleteINI);
			}
		}
		else
		{
			if(csWormType == _T("Registry Key")) csWormType = _T("RegistryKeyDelete");
			else if(csWormType == _T("Registry Value")) csWormType = _T("RegistryValueDelete");
			else if(csWormType == _T("Registry Data")) csWormType = _T("RegistryDataDelete");
			else
				csWormType += _T("Delete");

			TCHAR buff[100]={0};
			if(csWormType != _T("Process") )
			{
				int iWormCnt = GetPrivateProfileInt(csWormType, _T("WormCnt"), 0, csDeleteINI);
				swprintf_s(buff, _countof(buff),_T("%d"), iWormCnt);
				WritePrivateProfileString(csWormType, buff, csWormInfo, csDeleteINI);
				iWormCnt++;
				swprintf_s(buff, _countof(buff),_T("%d"), iWormCnt);
				WritePrivateProfileString(csWormType, _T("WormCnt"), buff, csDeleteINI);
			}
		}
	}
	catch(...)
	{
		CString csInfo = _T("Exception caught in AddInRestartDeleteList: ") + csWormInfo;
		AddLogEntry(csInfo, 0, 0);			
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: AddWormEntry
	In Parameters	: CString csEntry, CString csWormType
	Out	Parameters	: void
	Purpose			: Add Worm Entry into SDHook Ini
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
void CQuarantineFile::AddWormEntry(CString csEntry, CString csWormType)
{
	CString csHookINI = CSystemInfo::m_strAppPath + SDHOOKINI;

	TCHAR buff[100]={0};
	int iWormCnt = GetPrivateProfileInt(csWormType, _T("WormCnt"), 0, csHookINI);
	swprintf_s(buff, _countof(buff),_T("%d"), iWormCnt);
	WritePrivateProfileString(csWormType, buff, csEntry, csHookINI) ;

	iWormCnt++;
	swprintf_s(buff,_countof(buff), _T("%d"), iWormCnt);
	WritePrivateProfileString(csWormType, _T("WormCnt"), buff, csHookINI) ;
}

/*--------------------------------------------------------------------------------------
Function       : CQuarantineFile::AddInRestartDeleteList
In Parameters  : RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID, LPCTSTR szValue,
Out Parameters : BOOL
Description    :
Author         : Vaibhav Desai
--------------------------------------------------------------------------------------*/
bool CQuarantineFile::AddInRestartDeleteIni(RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID,LPCTSTR szValue)
{
	CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
	WCHAR strCount[50] = {0};
	WCHAR strValue[MAX_PATH*4] = {0};

	WCHAR *szSection[8] = {
							L"File_Delete", L"File_Backup",
							L"Folder", L"RegistryKey",
							L"RegistryValue", L"RegistryData",
							L"File_Rename", L"File_Replace" 
						};

	LPTSTR lpszSection = NULL;

	if(eRD_Type == RD_FILE_DELETE)
	{
		lpszSection = szSection[0];
	}
	else if(eRD_Type == RD_FILE_BACKUP)
	{
		lpszSection = szSection[1];
	}
	else if(eRD_Type == RD_FOLDER)
	{
		lpszSection = szSection[2];
	}
	else if(eRD_Type == RD_KEY)
	{
		lpszSection = szSection[3];
	}
	else if(eRD_Type == RD_VALUE)
	{
		lpszSection = szSection[4];
	}
	else if(eRD_Type == RD_DATA)
	{
		lpszSection = szSection[5];
	}
	else if(eRD_Type == RD_FILE_RENAME)
	{
		lpszSection = szSection[6];
	}
	else if(eRD_Type == RD_FILE_REPLACE)
	{
		lpszSection = szSection[7];
	}

	if(lpszSection == NULL)
	{
		return FALSE;
	}

	CreateWormstoDeleteINI(strINIPath);

	UINT ulWormCnt = GetPrivateProfileIntW(lpszSection, L"WormCnt", 0, strINIPath);
	wsprintf(strCount, L"%d", ++ulWormCnt);
	WritePrivateProfileStringW(lpszSection, L"WormCnt", strCount, strINIPath);

	wsprintf(strValue, L"%ld^%s", ulSpyNameID, szValue);
	WritePrivateProfileStringW(lpszSection, strCount, strValue, strINIPath);
	AddLogEntry(L"^^^^^: %s", szValue);
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : CQuarantineFile::CreateWormstoDeleteINI
In Parameters  : CString strINIPath,
Out Parameters : void
Description    :
Author         : Vaibhav Desai
--------------------------------------------------------------------------------------*/
void CQuarantineFile::CreateWormstoDeleteINI(CString strINIPath)
{
	if(_waccess_s(strINIPath, 0) != 0)
	{
		// UTF16-LE BOM(FFFE)
		WORD wBOM = 0xFEFF;
		DWORD NumberOfBytesWritten;
		HANDLE hFile = ::CreateFile(strINIPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		::WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, NULL);
		::CloseHandle(hFile);
		WritePrivateProfileStringW(L"File_Delete", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Backup", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"Folder", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryData", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryValue", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryKey", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Rename", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Replace", L"WormCnt", L"0", strINIPath);
	}
}


