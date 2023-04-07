/*======================================================================================
   FILE			: RegistryHelper.cpp
   ABSTRACT		: This class provides add-on functionality to registry functions
   DOCUMENTS	: 
   AUTHOR		: Anand Srivastava
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
   CREATION DATE: 03/03/2010
   VERSION		: 
   NOTES		: Implements registry enumeration and reporting to UI functions
======================================================================================*/

#include "pch.h"
#include "Constants.h"
#include "MaxConstant.h"
#include "RegistryHelper.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 6386)
#endif

/*-----------------------------------------------------------------------------
Function		: CRegistryHelper
In Parameters	: -
Out Parameters	: -
Purpose			: constructor to initialize the member variables
Author			:
-----------------------------------------------------------------------------*/
CRegistryHelper::CRegistryHelper():m_objAvailableUsers(false)
{
	m_lpSendMessaegToUI = NULL;
	//LoadAvailableUsers(m_objAvailableUsers);
}

/*-----------------------------------------------------------------------------
Function		: CRegistryHelper
In Parameters	: -
Out Parameters	: -
Purpose			: destructor to free the used memory
Author			:
-----------------------------------------------------------------------------*/
CRegistryHelper::~CRegistryHelper()
{
}

/*--------------------------------------------------------------------------------------
Function       : SetReporter
In Parameters  : SENDMESSAGETOUI lpSendMessaegToUI
Out Parameters : void 
Description    : 
Author & Date  : Anand Srivastava & 03/03/2010
--------------------------------------------------------------------------------------*/
void CRegistryHelper::SetReporter(SENDMESSAGETOUIMS lpSendMessaegToUI)
{
	m_lpSendMessaegToUI = lpSendMessaegToUI;
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::SendScanStatusToUI
In Parameters  : SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type,
				 const TCHAR *strKey, const TCHAR *strValue, int Type_Of_Data, LPBYTE lpbData,
				 int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData,
				 int iSizeOfReplaceData
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryHelper::SendScanStatusToUI(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName,
										 HKEY Hive_Type, const TCHAR *strKey, const TCHAR *strValue,
										 int Type_Of_Data, LPBYTE lpbData, int iSizeOfData,
										 REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
										 int iSizeOfReplaceData)
{
	if(m_lpSendMessaegToUI)
	{
		m_lpSendMessaegToUI(eTypeOfScanner, eStatus_Detected, ulSpyName, Hive_Type, strKey, strValue, Type_Of_Data,
							lpbData, iSizeOfData, psReg_Fix_Options, lpbReplaceData, iSizeOfReplaceData,0);
	}

	CString csStringToReport;
	if(RegKey == eTypeOfScanner || RegKey_Report == eTypeOfScanner)
	{
		csStringToReport.Format(_T("Found: %s\\%s"), m_objReg.GetHiveName(Hive_Type), strKey);
	}
	else if(RegValue == eTypeOfScanner || RegValue_Report == eTypeOfScanner)
	{
		if(REG_SZ == Type_Of_Data)
		{
			csStringToReport.Format(_T("Found: %s\\%s - %s - %s"), m_objReg.GetHiveName(Hive_Type), strKey, strValue, (LPCTSTR)lpbData);
		}
		else if(REG_DWORD == Type_Of_Data)
		{
			csStringToReport.Format(_T("Found: %s\\%s - %s - %u"), m_objReg.GetHiveName(Hive_Type), strKey, strValue, *((LPDWORD)lpbData));
		}
		else
		{
			csStringToReport.Format(_T("Found: %s\\%s - %s"), m_objReg.GetHiveName(Hive_Type), strKey, strValue);
		}
	}

	AddLogEntry(csStringToReport);
	return;
}
/*--------------------------------------------------------------------------------------
Function       : GetAlreadyLoadedProfilePath
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Dipali Pawar & 7 Apr, 2010.
--------------------------------------------------------------------------------------*/
void CRegistryHelper::GetAlreadyLoadedProfilePath(CS2S& objLoadedUsers)
{
	HKEY hMainkey = NULL;
	CString csMainKey(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\");
	CStringArray oUserKeyArr;
	CString csProfilePath;
	int iIndex;
	m_objReg.EnumSubKeys(_T(""), oUserKeyArr, HKEY_USERS);

	for(iIndex = 0; iIndex < oUserKeyArr.GetCount(); iIndex++)
	{
		m_objReg.Get(csMainKey + oUserKeyArr.GetAt(iIndex), _T("ProfileImagePath"), csProfilePath, HKEY_LOCAL_MACHINE);
		if(csProfilePath != BLANKSTRING)
		{
			csProfilePath = m_objDBPathExpander.ExpandSystemPath(csProfilePath);
			objLoadedUsers.AppendItem(csProfilePath, BLANKSTRING);
		}
	}
}
/*--------------------------------------------------------------------------------------
Function       : LoadAvailableUsers
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryHelper::LoadAvailableUsers(CS2S& objAvailableUsers)
{
	HKEY hMainkey = NULL;
	CString csMainKey(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");
	CS2S objProfPath(false);
	GetAlreadyLoadedProfilePath(objProfPath);

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, csMainKey, 0, KEY_READ, &hMainkey) != ERROR_SUCCESS)
	{
		return;
	}

	DWORD LengthOfLongestSubkeyName = 0;
	DWORD dwSubKeyCount = 0;			// number of subkeys 

	//To detemine MAX length
	if(RegQueryInfoKey(hMainkey, NULL, NULL, NULL, &dwSubKeyCount, &LengthOfLongestSubkeyName, NULL, NULL,
						NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
	{
		RegCloseKey( hMainkey);
		return;
	}

	DWORD  LengthOfKeyName = LengthOfLongestSubkeyName;
	LPWSTR lpKeyName = NULL;

	lpKeyName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, (LengthOfLongestSubkeyName * sizeof(TCHAR)) + sizeof(TCHAR));
	if ( NULL == lpKeyName )
	{
		RegCloseKey( hMainkey);
		return;
	}

	DWORD idxKey = 0, NTr = 0;

	csMainKey += L"\\";
	for(idxKey = 0; idxKey < dwSubKeyCount ;idxKey++)
	{
		LengthOfKeyName = LengthOfLongestSubkeyName + 1;
		SecureZeroMemory(lpKeyName, (LengthOfLongestSubkeyName * sizeof(TCHAR)) + sizeof(TCHAR));
		NTr = RegEnumKeyEx(hMainkey, idxKey, (LPWSTR)lpKeyName, &LengthOfKeyName, NULL, NULL, NULL, NULL);

		if(NTr == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		// ignore entry which could not be retrieved as the buffer provided was small
		else if(NTr == ERROR_MORE_DATA)
		{
			continue;
		}
		else if(NTr != ERROR_SUCCESS)
		{
			break;
		}
		else if(NTr == ERROR_SUCCESS)
		{
			if(LengthOfKeyName == 0)
			{
				continue;
			}

			CString csProfilePath;

			LPTSTR lpData;
			m_objReg.Get(csMainKey + lpKeyName, _T("ProfileImagePath"), csProfilePath, HKEY_LOCAL_MACHINE);
			if(csProfilePath.GetLength() > 0)
			{
				csProfilePath = m_objDBPathExpander.ExpandSystemPath(csProfilePath);
				objAvailableUsers.AppendItem(lpKeyName, csProfilePath);
				if(objProfPath.SearchItem(csProfilePath, lpData) == false)
				{
					objProfPath.AppendItem(csProfilePath, _T(""));
					HKEY hUserKey = NULL;
					if(RegOpenKeyEx(HKEY_USERS, lpKeyName, 0, KEY_READ, &hUserKey) == ERROR_SUCCESS)
					{
						RegCloseKey(hUserKey);
					}
					else
					{
						//m_objReg.LoadKey(HKEY_USERS, lpKeyName, csProfilePath + L"\\NTUser.dat");
					}
				}
			}
		}
	}
	GlobalFree(lpKeyName);
	RegCloseKey(hMainkey);

	objAvailableUsers.AppendItem(L".default", m_objDBPathExpander.GetDefaultUserPath());
	objAvailableUsers.AppendItem(L"All Users", m_objDBPathExpander.GetAllUsersPath());
	if(m_objDBPathExpander.RunningOnVista() || m_objDBPathExpander.RunningOnWin7())
	{
		objAvailableUsers.AppendItem(L"Public", m_objDBPathExpander.GetPublicUserPath());
	}
}

/*--------------------------------------------------------------------------------------
Function       : GetAllComEntries
In Parameters  : const CString csCLSID, ULONG ulSpyNameID, 
Out Parameters : void 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CRegistryHelper::GetAllComEntries(const CString csCLSID, ULONG ulSpyNameID)
{
	if(csCLSID.GetLength() != 0)
	{
		CString csKey ;

		csKey = CLSID_KEY + csCLSID;
		if(m_objReg.KeyExists(csKey, HKEY_LOCAL_MACHINE))
		{
			EnumKeyNReportToUI(HKEY_LOCAL_MACHINE, csKey, ulSpyNameID);
		}

#ifdef WIN64
		csKey = CLSID_KEY_X64 + csCLSID;
		if(m_objReg.KeyExists(csKey, HKEY_LOCAL_MACHINE))
		{
			EnumKeyNReportToUI(HKEY_LOCAL_MACHINE, csKey, ulSpyNameID);
		}
#endif

		// Main Interface Key
		csKey = INTERFACE_PATH + csCLSID;
		if(m_objReg.KeyExists(csKey, HKEY_LOCAL_MACHINE))
		{
			EnumKeyNReportToUI(HKEY_LOCAL_MACHINE, csKey, ulSpyNameID);
		}

#ifdef WIN64
		csKey = INTERFACE_PATH_X64 + csCLSID;
		if(m_objReg.KeyExists(csKey, HKEY_LOCAL_MACHINE))
		{
			EnumKeyNReportToUI(HKEY_LOCAL_MACHINE, csKey, ulSpyNameID);
		}
#endif

		// Main TypeLib Key
		csKey = TYPELIB_PATH + csCLSID;
		if(m_objReg.KeyExists(csKey, HKEY_LOCAL_MACHINE))
		{
			EnumKeyNReportToUI(HKEY_LOCAL_MACHINE, csKey, ulSpyNameID);	
		}

#ifdef WIN64
		csKey = TYPELIB_PATH_X64 + csCLSID;
		if(m_objReg.KeyExists(csKey, HKEY_LOCAL_MACHINE))
		{
			EnumKeyNReportToUI(HKEY_LOCAL_MACHINE, csKey, ulSpyNameID);	
		}
#endif

		LPVOID posUserName = m_objAvailableUsers.GetFirst();
		while(posUserName)
		{
			LPTSTR strUserSID = NULL;
			m_objAvailableUsers.GetKey(posUserName, strUserSID);

			// Main Stats Key
			csKey = (CString)strUserSID + STATS_PATH + csCLSID;
			if(m_objReg.KeyExists(csKey, HKEY_USERS))
			{
				EnumKeyNReportToUI(HKEY_USERS, csKey, ulSpyNameID);	
			}

#ifdef WIN64
			csKey = (CString)strUserSID + BACK_SLASH + EXT_STATS_PATH_X64 + csCLSID;
			if(m_objReg.KeyExists(csKey, HKEY_USERS))
			{
				EnumKeyNReportToUI(HKEY_USERS, csKey, ulSpyNameID);	
			}
#endif

			posUserName = m_objAvailableUsers.GetNext(posUserName);
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : CScannerBase::EnumKeyNReportToUI
In Parameters  : HKEY hHiveKey, LPCWSTR wcsMainKey, ULONG ulSpyNameID, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CRegistryHelper::EnumKeyNReportToUI(HKEY hHiveKey, LPCWSTR wcsMainKey, ULONG ulSpyNameID)
{
	DWORD LengthOfLongestSubKey = 0;
	DWORD LengthOfLongestValueName = 0;
	DWORD LengthOfLongestValueData = 0;
	DWORD TypeCode = 0;
	DWORD LengthOfFullKey = 0;
	DWORD LengthOfSubKey = 0;
	DWORD LengthOfValueName = 0;
	DWORD LengthOfValueData = 0;
	LPWSTR lpFullKey = NULL;
	LPWSTR lpSubKey = NULL;
	LPWSTR lpValueName = NULL;
	LPBYTE lpValueData = NULL;
	HKEY hSubkey = NULL;

	if(RegOpenKeyEx(hHiveKey, wcsMainKey, 0, KEY_READ, &hSubkey) != ERROR_SUCCESS)
	{
		return;
	}

	SendScanStatusToUI(RegKey, ulSpyNameID, hHiveKey, wcsMainKey, 0, 0, 0, 0, 0, 0, 0);

	if(RegQueryInfoKey(hSubkey, 0, 0, 0, 0, &LengthOfLongestSubKey, 0, 0, &LengthOfLongestValueName,
						&LengthOfLongestValueData, 0, 0) != ERROR_SUCCESS)
	{
		RegCloseKey ( hSubkey ) ;
		return ;
	}

	// just a precaution, as few times RegQueryInfoKey returned lesser lengths
	if(LengthOfLongestValueName < MAX_VALUE_NAME)
	{
		LengthOfLongestValueName = MAX_VALUE_NAME;
	}

	LengthOfLongestValueName += 10;
	LengthOfLongestValueData += 10;

	if(!LengthOfLongestSubKey && !LengthOfLongestValueName && !LengthOfLongestValueData)
	{
		RegCloseKey ( hSubkey ) ;
		return ;
	}

	LengthOfLongestValueName += sizeof(TCHAR);	
	LengthOfLongestValueData ++;

	lpValueName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestValueName * sizeof(TCHAR));
	lpValueData = (LPBYTE)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestValueData);
	if(NULL == lpValueName || NULL == lpValueData)
	{
		if(lpValueName)
		{
			GlobalFree(lpValueName);
		}
		if(lpValueData)
		{
			GlobalFree(lpValueData);
		}
		RegCloseKey(hSubkey);
		return ;
	}

	for(int iValIdx = 0; ; iValIdx++)
	{
		wmemset(lpValueName, 0, LengthOfLongestValueName);
		memset(lpValueData, 0, LengthOfLongestValueData);
		LengthOfValueName	=	LengthOfLongestValueName;
		LengthOfValueData	=	LengthOfLongestValueData;

		DWORD NTr = RegEnumValue(hSubkey, iValIdx, lpValueName, &LengthOfValueName, NULL,
									&TypeCode, lpValueData, &LengthOfValueData);
		if(NTr == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if(NTr != ERROR_SUCCESS)
		{
			break;
		}

		if(LengthOfValueName >= LengthOfLongestValueName)
		{
			//CString csOut;
			//csOut.Format(L"Skipping long value with len: %d, Key: %s, Value: %s", LengthOfValueName, wcsMainKey, lpValueName);
			//AddLogEntry(csOut);
			AddLogEntry(L"Exception CRegistryHelper::EnumKeyNReportToUI, Value name larger than expected");
			continue;
		}

		if(LengthOfValueData >= LengthOfLongestValueData)
		{
			//CString csOut;
			//csOut.Format(L"Skipping long data with len: %d, Key: %s, Value: %s", LengthOfValueData, wcsMainKey, lpValueName);
			//AddLogEntry(csOut);
			AddLogEntry(L"Exception CRegistryHelper::EnumKeyNReportToUI, Data size larger than expected");
			continue;
		}

		SendScanStatusToUI(RegValue, ulSpyNameID, hHiveKey, wcsMainKey, lpValueName, TypeCode,
							lpValueData, LengthOfValueData, 0, 0, 0);
	}

	GlobalFree(lpValueName);
	GlobalFree(lpValueData);

	LengthOfLongestSubKey += 10; // 10 by precaution
	lpSubKey = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestSubKey * sizeof(TCHAR));
	if(NULL == lpSubKey)
	{
		RegCloseKey(hSubkey);
		return ;
	}

	LengthOfFullKey = ((DWORD)wcslen(wcsMainKey)) + LengthOfLongestSubKey + 10; // 10 by precaution
	lpFullKey = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfFullKey * sizeof(TCHAR));
	if(NULL == lpFullKey)
	{
		GlobalFree(lpSubKey);
		RegCloseKey(hSubkey);
		return ;
	}

	for(int iCtr = 0; ; iCtr++)
	{
		wmemset(lpSubKey, 0, LengthOfLongestSubKey);
		LengthOfSubKey = LengthOfLongestSubKey;

		DWORD NTr = RegEnumKey(hSubkey, iCtr, lpSubKey, LengthOfSubKey);
		if(NTr == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if(NTr != ERROR_SUCCESS)
		{
			break;
		}

		if(LengthOfSubKey > LengthOfLongestSubKey)
		{
			//CString csOut;
			//csOut.Format(L"Skipping long SubKey with len: %d, Key: %s, SubKey: %s", LengthOfFullKey, wcsMainKey, lpSubKey);
			//AddLogEntry(csOut);
			AddLogEntry(L"Exception CRegistryHelper::EnumKeyNReportToUI, SubKey name larger than expected");
			continue;
		}

		wcscpy_s(lpFullKey, LengthOfFullKey, wcsMainKey);
		wcscat_s(lpFullKey, LengthOfFullKey, L"\\");
		wcscat_s(lpFullKey, LengthOfFullKey, lpSubKey);

		EnumKeyNReportToUI(hHiveKey, lpFullKey, ulSpyNameID);
	}

	GlobalFree(lpSubKey);
	GlobalFree(lpFullKey);
	RegCloseKey(hSubkey);
}

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning (default:6386)
#endif