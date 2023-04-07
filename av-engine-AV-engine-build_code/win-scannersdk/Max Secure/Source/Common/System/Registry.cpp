/*======================================================================================
   FILE			: Registry.Cpp
   ABSTRACT		: This class provides the functionality to manipulate regstry
   DOCUMENTS	: 
   AUTHOR		: Vikas Jain 
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
   CREATION DATE: 25/12/2003
   VERSION		: 23 Aug 2007, Nupur
				  Unicode Supported.
				  27 Sept. 2007 Avinash B
				  Changed the set and get function for multi-strings used CRegKey class instead of raw
				  registry functions.
				  04 jan 2008 Dipali
				  Removed cpuinfo code from SaveRegKeyPath(). This is not required as
				  we are not supporting 98/ME. Refer: RegSaveKey in MSDN
				  28 Jan 2008
				  In function GetHiveByName make the string in uppercase and then compare	
				  17 March
				  In function QueryDataValue Add Default value
   NOTES		: RestoreRegKeyPath98() removed.
				 Version :19.0.0.63
				 Resource : Sadnip
				 Description:In Get function to retrive DWORD value check for maximum size  upto 20
			
======================================================================================*/
#include "pch.h"
#include <Atlbase.h>
#include "Registry.h"
#include "Constants.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 6386)
#endif

/*-----------------------------------------------------------------------------
Function		: CRegistry
In Parameters	: -
Out Parameters	: -
Purpose			: constructor to initialize the member variables
Author			:
-----------------------------------------------------------------------------*/
CRegistry::CRegistry()
{
	m_bWOW64Key = FALSE;
	m_szp = NULL;
	m_pOrgSecDesc = (PSECURITY_DESCRIPTOR)m_szp;
}

void CRegistry::SetWow64Key(bool bWow64Key)
{
	m_bWOW64Key = bWow64Key;
}

/*-----------------------------------------------------------------------------
Function		: CRegistry
In Parameters	: -
Out Parameters	: -
Purpose			: destructor to free the used memory
Author			:
-----------------------------------------------------------------------------*/
CRegistry::~CRegistry()
{
	if(m_szp)
		delete [] m_szp;
	m_pOrgSecDesc = m_szp = NULL;
}

/*-------------------------------------------------------------------------------------
Function		: Get
In Parameters	:
CString strKeyPath,
CString strValueName,
CString &dwValue,
HKEY HiveRoot
Out Parameters	: TRUE if value found and the data is not empty, ELSE False
Purpose			: Open the given key, query the type of data the value is storing
if the data is of type REG_DWORD, retrieves the data
else will return false
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegistry::Get(CString strKeyPath, CString strValueName, DWORD &dwValue, HKEY HiveRoot)const
{
	DWORD dwSize = MAX_PATH;
	HKEY hKey = NULL;
	DWORD dwType = REG_DWORD;
	try
	{
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}

		dwValue = 0;
		if(::RegOpenKeyEx(HiveRoot, LPCWSTR(strKeyPath), 0, dwAccess, &hKey) != ERROR_SUCCESS)
		{
			return false;
		}

		LONG lReturn = RegQueryValueEx(hKey, LPCWSTR(strValueName), NULL, &dwType, NULL, &dwSize);
		if(lReturn != ERROR_SUCCESS || dwSize > 20)
		{
			::RegCloseKey(hKey);
			return false;
		}

		if((dwType != REG_DWORD) || (dwSize == 0))
		{
			::RegCloseKey(hKey);
			return false;
		}

		lReturn = RegQueryValueEx(hKey, LPCWSTR(strValueName), NULL, &dwType, (LPBYTE)&dwValue, &dwSize);
		if(lReturn != ERROR_SUCCESS)
		{
			::RegCloseKey(hKey);
			return false;
		}
		::RegCloseKey(hKey);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::Get(DWORD): ") + strKeyPath + BACK_SLASH + strValueName);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: Get
In Parameters	:
CString strKeyPath,
CString strValueName,
CString &strValue,
HKEY HiveRoot
Out Parameters	: TRUE if value found and the data is not empty, ELSE False
Purpose			: Open the given key, query the type of data the value is storing
if the data is of type Reg_SZ or REG_EXPAND_SZ, retrieves the data
else will return false
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegistry::Get(CString strKeyPath, CString strValueName, CString &strValue, HKEY HiveRoot, DWORD * dwRegType)const
{
	DWORD dwSize = MAX_PATH;
	HKEY hKey = NULL;
	DWORD dwType = REG_SZ;
	try
	{
		strValue = "";
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}

		if(::RegOpenKeyEx(HiveRoot, LPCWSTR(strKeyPath), 0, dwAccess, &hKey) != ERROR_SUCCESS)
		{
			return false;
		}


		LONG lReturn = RegQueryValueEx(hKey, LPCWSTR(strValueName), NULL, &dwType, NULL, &dwSize);
		if(lReturn != ERROR_SUCCESS)
		{
			::RegCloseKey(hKey);
			return false;
		}

		if(((dwType != REG_SZ) && (dwType != REG_EXPAND_SZ)) || (dwSize == 0))
		{
			::RegCloseKey(hKey);
			return false;
		}
		dwRegType = &dwType;

		LPBYTE pData = new BYTE[dwSize];
		memset(pData, 0, dwSize);
		lReturn = RegQueryValueEx(hKey, LPCWSTR(strValueName), NULL, &dwType, pData, &dwSize);
		if(lReturn != ERROR_SUCCESS)
		{
			::RegCloseKey(hKey);
			return false;
		}
		::RegCloseKey(hKey);

		strValue.Format(_T("%s"), reinterpret_cast<LPTSTR>(pData));

		delete [] pData;
		pData = NULL;

		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::Get(STRING): ") + strKeyPath + BACK_SLASH + strValueName);
	}
	return false;
}


/*-------------------------------------------------------------------------------------
Function		: Get
In Parameters	: CString strKeyPath, CString strValueName, LPBYTE pByte, DWORD &dwSize, HKEY HiveRoot
Out Parameters	: TRUE if value read successfully, ELSE False
Purpose			: Reads the data from the value, The caller must free the memory
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegistry::Get(CString strKeyPath, CString strValueName, DWORD dwType, LPBYTE pValueData, DWORD dwSizeOfBuffer, HKEY HiveRoot)const
{
	HKEY hKey = NULL;
	try
	{
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}
		if(RegOpenKeyEx(HiveRoot, LPCWSTR(strKeyPath), NULL, dwAccess, &hKey) != ERROR_SUCCESS)
		{
			return false;
		}

		DWORD dwMaxValueDataLen = MAX_VALUE_NAME;

		// Get the value and value name buffers.
		if(RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
			&dwMaxValueDataLen, NULL, NULL) != ERROR_SUCCESS)
			return false;

		if(dwMaxValueDataLen == 0)
		{
			dwMaxValueDataLen = 4096;
		}
		else
		{
			dwMaxValueDataLen = (dwMaxValueDataLen * sizeof(TCHAR)) + sizeof(TCHAR);
		}

		DWORD dwReadType = dwType;
		LONG  lRetVal  = 0;
		DWORD dwValueDataLen = dwMaxValueDataLen;
		lRetVal = RegQueryValueEx(hKey, LPCWSTR(strValueName), NULL, &dwReadType, NULL, &dwValueDataLen);

		if(lRetVal != ERROR_SUCCESS)
		{
			::RegCloseKey(hKey);
			return false;
		}
		if((dwReadType != dwType) || (dwValueDataLen == 0))
		{
			::RegCloseKey(hKey);
			return false;
		}

		dwValueDataLen = (dwValueDataLen * sizeof(TCHAR)) + sizeof(TCHAR);
		LPBYTE pByteData = NULL;
		pByteData = (LPBYTE)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, dwValueDataLen);
		if(!pByteData)
		{
			::RegCloseKey(hKey);
			return FALSE;
		}
		lRetVal = RegQueryValueEx(hKey, LPCWSTR(strValueName), NULL, &dwType, pByteData, &dwValueDataLen);
		if(lRetVal != ERROR_SUCCESS)
		{
			::RegCloseKey(hKey);
			return FALSE;
		}
		memcpy_s(pValueData, dwSizeOfBuffer, pByteData, dwValueDataLen);
		GlobalFree(pByteData);
		::RegCloseKey(hKey);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::Get(STRING): ") + strKeyPath + BACK_SLASH+ strValueName);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: Get
In Parameters	: CString strKeyPath, CString strValueName, CStringArray &arrData, HKEY HiveRoot
Out Parameters	: TRUE if value found and the data is not empty, ELSE False
Purpose			: Retrieves strings from a multistring registry entry
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegistry::Get(CString strKeyPath, CString strValueName, CStringArray &arrData, HKEY HiveRoot)const
{
	HKEY hKey = NULL;
	try
	{
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}

		if(::RegOpenKeyEx(HiveRoot, LPCWSTR(strKeyPath), 0, dwAccess, &hKey) != ERROR_SUCCESS)
		{
			return false;
		}

		arrData.RemoveAll();

		DWORD dwType = REG_MULTI_SZ;
		DWORD dwValueDataLen = 0;

		LONG lRetVal = 0;
		lRetVal = RegQueryValueEx(hKey, LPCWSTR(strValueName), NULL, &dwType, NULL, &dwValueDataLen);
		dwValueDataLen = (dwValueDataLen/sizeof(TCHAR));

		if(lRetVal != ERROR_SUCCESS)
		{
			::RegCloseKey(hKey);
			return false;
		}
		else
		{
			::RegCloseKey(hKey);

			TCHAR *pByte = new TCHAR[dwValueDataLen];
			SecureZeroMemory(pByte, dwValueDataLen*sizeof(TCHAR));

			CRegKey objRegKey;
			if(objRegKey.Open(HiveRoot, strKeyPath, KEY_READ) != ERROR_SUCCESS)
				return false;

			lRetVal = objRegKey.QueryMultiStringValue(strValueName, pByte, &dwValueDataLen);

			if(lRetVal != ERROR_SUCCESS || pByte == NULL)
			{
				::RegCloseKey(hKey);
				return false;
			}

			TCHAR *chTemp = new TCHAR[dwValueDataLen];
			SecureZeroMemory(chTemp, dwValueDataLen*sizeof(TCHAR));

			for(unsigned int idx = 0, iPos = 0; idx < dwValueDataLen; idx++)
			{
				if(pByte[idx] != _T('\0'))
				{
					chTemp[iPos] = pByte[idx];
					iPos++;
				}
				else
				{
					if(iPos != 0)
					{
						chTemp[iPos] = _T('\0');
						arrData.Add(chTemp);
						iPos = 0;
						SecureZeroMemory(chTemp, dwValueDataLen*sizeof(TCHAR));
					}
				}
			}
			if(chTemp)
				delete [] chTemp;
			if(pByte)
				delete [] pByte;
		}
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::Get(MULTISTRING): ") + strKeyPath + BACK_SLASH + strValueName);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: Set
In Parameters	: CString strKeyPath, CString strValueName, CString &strValue, HKEY HiveRoot
Out Parameters	: TRUE if value found and the data is not empty, ELSE False
Purpose			: Sets the data of the String type value
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegistry::Set(CString strKeyPath, CString strValueName, CString strValue, HKEY HiveRoot, bool bFulshKey)const
{
	HKEY hKey = NULL;
	try
	{
		if(m_bWOW64Key)
		{
			DWORD dwDisposition = 0;
			if(::RegCreateKeyEx(HiveRoot, LPCWSTR(strKeyPath), 0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS)
			{
				return false;
			}
		}
		else
		{
			if(RegCreateKey(HiveRoot, LPCTSTR(strKeyPath), &hKey) != ERROR_SUCCESS)
				return false;
		}

		if(RegSetValueEx(hKey, LPCWSTR(strValueName), 0, REG_SZ, (LPBYTE)LPCWSTR((strValue)), (sizeof(TCHAR) * (strValue.GetLength() + 1))) != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return false;
		}

		if(bFulshKey)
		{
			RegFlushKey(hKey);
		}

		RegCloseKey(hKey);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::Set(STRING): ") + strKeyPath + BACK_SLASH + strValueName);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: Set
In Parameters	: CString strKeyPath, CString strValueName, DWORD dwValue, HKEY HiveRoot
Out Parameters	: TRUE if value found and the data is not empty, ELSE False
Purpose			: Sets the data of the String type value
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegistry::Set(CString strKeyPath, CString strValueName, DWORD dwValue, HKEY HiveRoot)const
{
	HKEY hKey = NULL;
	try
	{
		if(m_bWOW64Key)
		{
			DWORD dwDisposition = 0;
			if(::RegCreateKeyEx(HiveRoot, LPCWSTR(strKeyPath), 0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS)
			{
				return false;
			}
		}
		else
		{
			if(RegCreateKey(HiveRoot, LPCTSTR(strKeyPath), &hKey) != ERROR_SUCCESS)
				return false;
		}

		if(RegSetValueEx(hKey, LPCWSTR(strValueName), 0, REG_DWORD, (LPBYTE)&dwValue, 4) != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return false;
		}
		RegCloseKey(hKey);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::Set(DWORD): ") + strKeyPath + BACK_SLASH + strValueName);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: Set
In Parameters	: CString strKeyPath, CString strValueName, CStringArray &arrData, HKEY HiveRoot
Out Parameters	: TRUE if value saved and the data is not empty, ELSE False
Purpose			: Save strings to a multistring registry entry
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegistry::Set(CString strKeyPath, CString strValueName, CStringArray &arrData, HKEY HiveRoot)const
{
	try
	{
		DWORD dwDataSizeInBytes = 0;
		INT_PTR iNoOfEntries = arrData.GetCount();
		for(INT_PTR idx = 0; idx < iNoOfEntries; idx++)
		{
			dwDataSizeInBytes += arrData.GetAt(idx).GetLength()* sizeof(TCHAR);
			dwDataSizeInBytes += sizeof(TCHAR);
		}
		dwDataSizeInBytes += sizeof(TCHAR);

		int iPos = 0;
		TCHAR* pValueData = new TCHAR[dwDataSizeInBytes/sizeof(TCHAR)];
		SecureZeroMemory(pValueData, dwDataSizeInBytes);

		for(INT_PTR idx = 0; idx < iNoOfEntries; idx++)
		{
			if(arrData.GetAt(idx).GetLength() != 0)//ignore strings with zero length
			{
				int iStrLenInBytes =  (arrData.GetAt(idx).GetLength()* sizeof(TCHAR)) + sizeof(TCHAR);
				TCHAR* sTemp = new TCHAR[iStrLenInBytes/sizeof(TCHAR)];
				SecureZeroMemory(sTemp, iStrLenInBytes);

				memcpy_s(sTemp, iStrLenInBytes, arrData.GetAt(idx), iStrLenInBytes);
				memcpy_s(pValueData + iPos, dwDataSizeInBytes - iPos, sTemp, iStrLenInBytes);
				iPos += (iStrLenInBytes/sizeof(TCHAR));
				delete [] sTemp;
				sTemp = NULL;
			}
		}

		CRegKey objRegKey;
		if(objRegKey.Open(HiveRoot,strKeyPath) != ERROR_SUCCESS)
			return FALSE;

		LONG lRetVal = objRegKey.SetMultiStringValue(strValueName, pValueData);

		if(pValueData)
			delete [] pValueData;

		if(lRetVal == ERROR_SUCCESS)
			return true;
		else
			return false;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::Set(MULTISTRING): ") + strKeyPath + BACK_SLASH + strValueName);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: Set
In Parameters	: CString strKeyPath, CString strValueName, LPBYTE pByte, DWORD dwSize, DWORD dwType, HKEY HiveRoot
Out Parameters	: TRUE if value found and the data is not empty, ELSE False
Purpose			: Sets the data of the String type value
Author			: Darshan Singh Virdi
Note: For _Unicode, the dwSize => GetLenght()* (sizeof(TCHAR) + sizeof(TCHAR))//Nupur
--------------------------------------------------------------------------------------*/
bool CRegistry::Set(CString strKeyPath, CString strValueName, LPBYTE pByte, DWORD dwSizeOfBuffer, DWORD dwType, HKEY HiveRoot)const
{
	try
	{
		HKEY hKey = NULL;
		if(m_bWOW64Key)
		{
			DWORD dwDisposition = 0;
			if(::RegCreateKeyEx(HiveRoot, LPCWSTR(strKeyPath), 0, NULL, REG_OPTION_NON_VOLATILE,
				KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS)
			{
				return false;
			}
		}
		else
		{
			if(RegCreateKey(HiveRoot, LPCTSTR(strKeyPath), &hKey) != ERROR_SUCCESS)
				return false;
		}

		if(RegSetValueEx(hKey, LPCTSTR(strValueName), 0, dwType, pByte, dwSizeOfBuffer) != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return false;
		}
		RegCloseKey(hKey);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::Set(BYTE): ") + strKeyPath + BACK_SLASH + strValueName);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: DeleteKey
In Parameters	: CString strKeyPath, CString strSubKey, HKEY HiveRoot
Out Parameters	: TRUE if value found and the data is not empty, ELSE False
Purpose			: to delete the key
Author			: Vikas Jain
--------------------------------------------------------------------------------------*/
bool CRegistry::DeleteKey(CString strKeyPath, CString strSubKey, HKEY HiveRoot)
{
	try
	{
		CRegKey registryKey;
		if(strSubKey == "")
		{
			registryKey.m_hKey = HiveRoot;
			if(registryKey.DeleteSubKey(strKeyPath) == ERROR_SUCCESS)
				return true;
			else if(registryKey.RecurseDeleteKey(strKeyPath) == ERROR_SUCCESS)
				return true;
			else
			{
				// Darshan
				// Set all access permission to the key and try again
				CStringArray csSubKeyList;
				EnumSubKeys(strKeyPath, csSubKeyList, HiveRoot);
				INT_PTR nSubkeys = csSubKeyList.GetCount();

				if(nSubkeys > 0)//Setting permissions for the subkeys also.
				{
					for(int idx = 0; idx < nSubkeys; idx++)
					{
						if(!AdjustPermissions(HiveRoot, csSubKeyList[idx]))
							return false;
					}
				}
				else
				{
					if(!AdjustPermissions(HiveRoot, strKeyPath))
						return false;
				}
				if(registryKey.DeleteSubKey(strKeyPath) == ERROR_SUCCESS)
					return true;
				else if(registryKey.RecurseDeleteKey(strKeyPath) == ERROR_SUCCESS)
					return true;
				else
					return false;
			}
		}
		if(registryKey.Open(HiveRoot, strKeyPath) == ERROR_SUCCESS)
		{
			if(registryKey.DeleteSubKey(strSubKey) == ERROR_SUCCESS)
			{
				registryKey.Close();
				return TRUE;
			}
			else if(registryKey.RecurseDeleteKey(strSubKey) == ERROR_SUCCESS)
			{
				registryKey.Close();
				return TRUE;
			}
			registryKey.Close();
		}
		return DeleteRegKey(HiveRoot, strKeyPath + BACK_SLASH + strSubKey);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::DeleteKey: ") + strKeyPath + BACK_SLASH + strSubKey);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: const TCHAR *cEnumKey, const TCHAR *cValue, const TCHAR *cData, HKEY RootKey
In Parameters	: CString strKeyPath, CString strSubKey, HKEY HiveRoot
Out Parameters	: TRUE if value or data delete
Purpose			: to delete the value or data
Author			: sandip Sanap
--------------------------------------------------------------------------------------*/
bool CRegistry::DeleteEnumRegValue(const TCHAR *cEnumKey, const TCHAR *cValue, const TCHAR *cData, HKEY RootKey)
{
	HKEY hKey = NULL;
	TCHAR Data[1024]={0};
	TCHAR ValueName[1024]={0};
	DWORD RetValue = 0, cbData = 0, cbValueName = 0;
	
	DWORD dwAccess = KEY_ALL_ACCESS;
	if(m_bWOW64Key)
	{
		dwAccess |= KEY_WOW64_64KEY;
	}

	RetValue = RegOpenKeyEx(RootKey, cEnumKey, 0, dwAccess, &hKey);
	if(ERROR_SUCCESS != RetValue)
		return (false);

	for(int i = 0;; i++)
	{
		cbData = sizeof(Data);
		cbValueName = _countof(ValueName);
		RetValue = RegEnumValue(hKey, i, ValueName, &cbValueName, 0, 0, (UCHAR*)Data, &cbData);
		if(ERROR_SUCCESS != RetValue)
			break;

		if(cValue && cData)
		{
			if(StrStrI(ValueName, cValue) && StrStrI(Data, cData))
			{
				RegDeleteValue(hKey, ValueName);
			}
		}
		if(cValue)
		{
			if(StrStrI(ValueName, cValue))
			{
				RegDeleteValue(hKey, ValueName);
			}
		}
		if(cData)
		{
			if(StrStrI(Data, cData))
			{
				RegDeleteValue(hKey, ValueName);
			}
		}
		memset(Data, 0, sizeof (Data));
		memset(ValueName, 0, sizeof (ValueName));
	}
	RegCloseKey(hKey);
	return (true);
}


/*-------------------------------------------------------------------------------------
Function		: DeleteValue
In Parameters	: CString strKeyPath, CString strValueName, HKEY HiveRoot
Out Parameters	: TRUE if value deleted, ELSE False
Purpose			: to delete the value
Author			: Vikas Jain
--------------------------------------------------------------------------------------*/
bool CRegistry::DeleteValue(CString strKeyPath, CString strValueName, HKEY HiveRoot)
{
	try
	{
		CRegKey registryKey;
		DWORD dwAccess = KEY_ALL_ACCESS;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}
		if(registryKey.Open(HiveRoot, strKeyPath,dwAccess) == ERROR_SUCCESS)
		{
			if(registryKey.DeleteValue(strValueName) == ERROR_SUCCESS)
			{
				registryKey.Close();
				return true;
			}
			registryKey.Close();
		}
		// Darshan
		// Set all access permission to the key and try again
		if(!AdjustPermissions(HiveRoot, strKeyPath))
			return false;
		if(registryKey.Open(HiveRoot, strKeyPath,dwAccess) == ERROR_SUCCESS)
		{
			if(registryKey.DeleteValue(strValueName) == ERROR_SUCCESS)
			{
				registryKey.Close();
				return true;
			}
			registryKey.Close();
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::DeleteValue: ") + strKeyPath + BACK_SLASH + strValueName);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: KeyExists
In Parameters	: CString strKeyPath, HKEY HiveRoot
Out Parameters	: TRUE if exists, ELSE False
Purpose			: Check existence of the key
Author			: Bhushan Narkhede
--------------------------------------------------------------------------------------*/
bool CRegistry::KeyExists(CString strKeyPath, HKEY HiveRoot)
{
	try
	{
		HKEY hKey;
		DWORD ApiStatus = 0;
		if(m_bWOW64Key)
		{
			ApiStatus =  RegOpenKeyEx(HiveRoot, (LPCWSTR)strKeyPath, 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
		}
		else
		{
			ApiStatus = RegOpenKey(HiveRoot, strKeyPath, &hKey);

		}
		if(ERROR_SUCCESS != ApiStatus)
			return false;
		RegCloseKey(hKey);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::KeyExists: ") + strKeyPath);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: ValueExists
In Parameters	: CString strKeyPath, CString strValueName, HKEY HiveRoot
Out Parameters	: TRUE if exists, ELSE False
Purpose			: Check existence of the value
Author			: Bhushan Narkhede
--------------------------------------------------------------------------------------*/
bool CRegistry::ValueExists(CString strKeyPath, CString strValueName, HKEY HiveRoot)
{
	try
	{
		LONG lResult;
		HKEY hKey;
		if(m_bWOW64Key)
		{
			if(RegOpenKeyEx(HiveRoot, LPCTSTR(strKeyPath), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
				return false;

		}
		else
		{
			if(RegOpenKey(HiveRoot, LPCTSTR(strKeyPath), &hKey) != ERROR_SUCCESS)
				return false;
		}

		lResult = ::RegQueryValueEx(hKey, LPCTSTR(strValueName), NULL, NULL, NULL, NULL);
		::RegCloseKey(hKey);

		if(lResult == ERROR_SUCCESS)
			return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::ValueExists: ") + strKeyPath + BACK_SLASH + strValueName);
	}
	return false;
}
/*-------------------------------------------------------------------------------------
Function		: EnumSubKeys
In Parameters	: CString csMainKey,	CArray<CString,CString> &o_arrEnumSubKeys,	HKEY hHiveKey, bool bReturnOnlySubKey
Out Parameters	: TRUE if exists, ELSE False
Purpose			: to enumerate the key
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry::EnumSubKeys	(CString csMainKey, CMapStringToString &objSubKeyMap, HKEY hHiveKey)
{
	try
	{
		HKEY hMainkey = NULL;
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}
		if(RegOpenKeyEx(hHiveKey, csMainKey, 0, dwAccess, &hMainkey) != ERROR_SUCCESS)
			return false;

		DWORD LengthOfLongestSubkeyName = MAX_BUFFER;
		DWORD dwSubKeyCount;							// number of subkeys

		//To detemine MAX length
		if(RegQueryInfoKey(hMainkey, NULL, NULL, NULL, &dwSubKeyCount, &LengthOfLongestSubkeyName,  NULL,
			NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
		{
			RegCloseKey(hMainkey);
			return false;
		}


		if(LengthOfLongestSubkeyName == 0)
		{
			LengthOfLongestSubkeyName = 4096;
		}
		else
		{
			if(LengthOfLongestSubkeyName < MAX_BUFFER)LengthOfLongestSubkeyName = MAX_BUFFER;
			LengthOfLongestSubkeyName = (LengthOfLongestSubkeyName * sizeof(TCHAR)) + sizeof(TCHAR);
		}

		DWORD  LengthOfKeyName = LengthOfLongestSubkeyName;
		LPWSTR lpKeyName = NULL;

		lpKeyName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestSubkeyName);
		if(!lpKeyName)
		{
			RegCloseKey(hMainkey);
			return false;
		}
		DWORD idxKey = 0, NTr = 0;

		for(idxKey = 0; idxKey < dwSubKeyCount;idxKey++)
		{
			LengthOfKeyName = LengthOfLongestSubkeyName;
			SecureZeroMemory(lpKeyName, LengthOfLongestSubkeyName);
			NTr = RegEnumKeyEx(hMainkey, idxKey, lpKeyName, &LengthOfKeyName, NULL, NULL, NULL, NULL);

			if(NTr == ERROR_NO_MORE_ITEMS)
				break;
			// ignore entry which could not be retrieved as the buffer provided was small
			else if(NTr == ERROR_MORE_DATA)
				continue;
			else if	(NTr != ERROR_SUCCESS)
			{
				break;
			}
			else if	(NTr == ERROR_SUCCESS)
			{
				LengthOfKeyName = (DWORD)wcslen(lpKeyName);
				if(LengthOfKeyName == 0)
					continue;

				objSubKeyMap.SetAt(L"HKEY_LOCAL_MACHINE\\" + csMainKey + BACK_SLASH + lpKeyName,lpKeyName);
			}
		}
		GlobalFree(lpKeyName);
		RegCloseKey(hMainkey);

		if(objSubKeyMap.GetCount() == 0)
			return false;
		else
			return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::EnumSubKeys: %s"), csMainKey);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: EnumSubKeys
In Parameters	: CString csMainKey,	CArray<CString,CString> &o_arrEnumSubKeys,	HKEY hHiveKey, bool bReturnOnlySubKey
Out Parameters	: TRUE if exists, ELSE False
Purpose			: to enumerate the key
Author			: Bhushan Narkhede
--------------------------------------------------------------------------------------*/
bool CRegistry::EnumSubKeys(CString csMainKey,	CArray<CString,CString> &o_arrEnumSubKeys,	HKEY hHiveKey, bool bReturnOnlySubKey)
{
	try
	{
		DWORD    cSubKeys;						// number of subkeys
		DWORD    cbMaxSubKey = MAX_KEY_NAME;    // longest subkey size
		DWORD    cbSecurityDescriptor;			// size of security descriptor
		FILETIME ftLastWriteTime;				// last write time
		HKEY	 hKey;
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}
		//Opening the Key
		if(RegOpenKeyEx(hHiveKey, csMainKey, 0, dwAccess, &hKey) != ERROR_SUCCESS)
			return false;

		// Get the subkey count and max subkey lenght.
		if(RegQueryInfoKey(hKey, NULL, NULL, NULL, &cSubKeys, &cbMaxSubKey, NULL, NULL,
			NULL, NULL, &cbSecurityDescriptor, &ftLastWriteTime) != ERROR_SUCCESS)
		{
			RegCloseKey(hHiveKey);
			return false;
		}

		DWORD  idxKey = 0;
		DWORD  retCode = 0;
		DWORD  dwSubKeySize = MAX_BUFFER;              // longest subkey size


		LPWSTR lpKeyName;

		if(cbMaxSubKey == 0)
		{
			cbMaxSubKey = 4096;
		}
		else
		{
			if(cbMaxSubKey < MAX_BUFFER)cbMaxSubKey = MAX_BUFFER;
			cbMaxSubKey = (cbMaxSubKey * sizeof(TCHAR)) + sizeof(TCHAR);
		}


		lpKeyName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, cbMaxSubKey);
		if(!lpKeyName)
		{
			RegCloseKey(hHiveKey);
			return false;
		}

		for (idxKey = 0, retCode = ERROR_SUCCESS; idxKey < cSubKeys; idxKey++)
		{ 
			SecureZeroMemory(lpKeyName, cbMaxSubKey);
			retCode = RegEnumKeyEx(hKey, idxKey, lpKeyName, &dwSubKeySize, NULL, NULL, NULL, &ftLastWriteTime);

			if(retCode == ERROR_SUCCESS)
			{
				if(bReturnOnlySubKey)
					o_arrEnumSubKeys.Add(lpKeyName);
				else
				{
					o_arrEnumSubKeys.Add(csMainKey + BACK_SLASH + lpKeyName);
					EnumSubKeys(csMainKey + BACK_SLASH + lpKeyName, o_arrEnumSubKeys, hHiveKey, bReturnOnlySubKey);
				}
				dwSubKeySize = MAX_KEY_NAME;
			}
			else if(retCode == ERROR_NO_MORE_ITEMS)
				break;
			// ignore entry which could not be retrieved as the buffer provided was small
			else if(retCode == ERROR_MORE_DATA)
				continue;
			else if(retCode != ERROR_SUCCESS)
			{
				break;
			}
		}
		GlobalFree(lpKeyName);
		::RegCloseKey(hKey);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::EnumSubKeys: ") + csMainKey);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: EnumSubKeys
In Parameters	: CString csMainKey,	CStringArray &objSubKeyArr,	HKEY hHiveKey
Out Parameters	: TRUE if enum was sucessfull, ELSE False
Purpose			: Enumerates the given key and returns all sub keys in the array
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegistry::EnumSubKeys(CString csMainKey,	CStringArray &objSubKeyArr,	HKEY hHiveKey)
{
	try
	{
		HKEY hMainkey = NULL;
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}
		if(RegOpenKeyEx(hHiveKey, csMainKey, 0, dwAccess, &hMainkey) != ERROR_SUCCESS)
			return false;

		DWORD LengthOfLongestSubkeyName = MAX_BUFFER;
		DWORD dwSubKeyCount;							// number of subkeys

		//To detemine MAX length
		if(RegQueryInfoKey(hMainkey, NULL, NULL, NULL, &dwSubKeyCount, &LengthOfLongestSubkeyName,  NULL,
			NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
		{
			RegCloseKey(hMainkey);
			return false;
		}


		if(LengthOfLongestSubkeyName == 0)
		{
			LengthOfLongestSubkeyName = 4096;
		}
		else
		{
			if(LengthOfLongestSubkeyName < MAX_BUFFER)
				LengthOfLongestSubkeyName = MAX_BUFFER;
			LengthOfLongestSubkeyName = (LengthOfLongestSubkeyName * sizeof(TCHAR)) + sizeof(TCHAR);
		}


		DWORD  LengthOfKeyName = LengthOfLongestSubkeyName;
		LPWSTR lpKeyName = NULL;

		lpKeyName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestSubkeyName);

		if(!lpKeyName)
		{
			RegCloseKey(hMainkey);
			return false;
		}

		DWORD idxKey = 0, NTr = 0;

		for(idxKey = 0; idxKey < dwSubKeyCount;idxKey++)
		{
			LengthOfKeyName = LengthOfLongestSubkeyName;
			SecureZeroMemory(lpKeyName, LengthOfLongestSubkeyName);
			NTr = RegEnumKeyEx(hMainkey, idxKey, (LPWSTR)lpKeyName, &LengthOfKeyName, NULL, NULL, NULL, NULL);

			if(NTr == ERROR_NO_MORE_ITEMS)
				break;
			// ignore entry which could not be retrieved as the buffer provided was small
			else if(NTr == ERROR_MORE_DATA)
				continue;
			else if(NTr != ERROR_SUCCESS)
			{
				break;
			}
			else if(NTr == ERROR_SUCCESS)
			{
				LengthOfKeyName = (DWORD)wcslen(lpKeyName);
				if(LengthOfKeyName == 0)
					continue;

				objSubKeyArr.Add(lpKeyName);
			}
		}
		GlobalFree(lpKeyName);
		RegCloseKey(hMainkey);

		if(objSubKeyArr.GetCount() == 0)
			return false;
		else
			return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::EnumSubKeys: %s"), csMainKey);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: FormulatePath
In Parameters	: CString & - key path
HKEY - hkey
Out Parameters	: bool
Purpose			: to formulate the given path
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CRegistry::FormulatePath(CString &strRegPath, HKEY &hKey)
{
	try
	{
		CString strPath = strRegPath;

		int iFind = strPath.Find(_T('\\'));
		if(iFind == -1)
			iFind = strPath.GetLength(); //only includes a root item

		CString strRoot = strPath.Left(iFind);
		if(!StringRoot2key(strRoot, hKey))
			return false;

		strRegPath = strPath.Mid(iFind+1);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::FormulatePath"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: SetPrivilege
In Parameters	: LPCWSTR  - privileg
bool - enable flag
Out Parameters	: bool
Purpose			: to set the privileg
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CRegistry::SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	try
	{
		TOKEN_PRIVILEGES tp;
		LUID luid;
		HANDLE hToken;

		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
		if(!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
			return false;

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;

		if(bEnablePrivilege)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;

		AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

		return ((GetLastError() !=ERROR_SUCCESS)?FALSE:TRUE);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::SetPrivilege"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: SaveRegKeyPath
In Parameters	: HKEY - hive
CString - subkey
CString - outfile
Out Parameters	: bool
Purpose			: to save the registry key path
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CRegistry::SaveRegKeyPath(HKEY HiveRoot, CString &SubKey, CString &csSdbDatFilePath)
{
	bool	bRetVal = true;
	HKEY	hKey = NULL;
	DWORD	dwRetVal = 0;

	try
	{
		SetPrivilege(SE_BACKUP_NAME,TRUE);
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}
		if(RegOpenKeyEx(HiveRoot, SubKey, 0, dwAccess, &hKey) == ERROR_SUCCESS)
		{
			DeleteFile(csSdbDatFilePath);	// make sure this file does not exists!
			dwRetVal = RegSaveKey(hKey, csSdbDatFilePath, NULL);
			if(dwRetVal!=ERROR_SUCCESS)
			{
				/*AddLogEntry(_T("Error caught in CRegistry::SaveRegKeyPath > ") + csSdbDatFilePath);
				CString csErr;
				csErr.Format(L"Error Code : %d", dwRetVal);
				AddLogEntry(csErr);*/
				bRetVal = false;
			}
			//for 98 cannot take long file name
			//so first create temp file and copy to original path

			SetFileAttributes(csSdbDatFilePath, FILE_ATTRIBUTE_ARCHIVE);
			RegCloseKey(hKey);
		}
		else
		{
			bRetVal = false;
		}

		SetPrivilege(SE_BACKUP_NAME,FALSE);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::SaveRegKeyPath"));
	}
	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: RestoreRegKeyPath
In Parameters	: HKEY - hive
CString - subkey
CString - outfile
bool - force flag.If Force = TRUE then we force the restore operation
Out Parameters	: Return TRUE if success, otherwise it returns FALSE
Purpose			: to restore the registry key path
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CRegistry::RestoreRegKeyPath(HKEY HiveRoot, CString &SubKey, CString &InFile, BOOL Force)
{
	bool  bRetVal = true;
	HKEY  hKey = NULL;
	DWORD dwRetVal = 0;

	try
	{
		SetPrivilege(SE_RESTORE_NAME,TRUE);
		SetPrivilege(SE_BACKUP_NAME,TRUE);

		//Need to Create Key for HKEY_ROOT, for Win2K, else RegCreateKeyEx fails
		CreateKey(SubKey, hKey, HiveRoot);

		CloseKey(hKey);
		{
			HKEY  hhKey;
			DWORD dwAccess = KEY_ALL_ACCESS;
			if(m_bWOW64Key)
			{
				dwAccess |= KEY_WOW64_64KEY;
			}	
			DWORD lpDisposition = 0;
			if(RegCreateKeyEx(HiveRoot, SubKey, 0, NULL, REG_OPTION_BACKUP_RESTORE,
				dwAccess, NULL, &hhKey, &lpDisposition) == ERROR_SUCCESS)
			{
				dwRetVal = RegRestoreKey(hhKey, InFile,
					(Force == FALSE)?REG_NO_LAZY_FLUSH:REG_FORCE_RESTORE);
				RegCloseKey(hhKey);
				if(dwRetVal != ERROR_SUCCESS)
				{
					AddLogEntry(_T("Error caught in CRegistry::RestoreRegKeyPath"));
					CString csErr;
					csErr.Format(_T("Error Code : %d"), dwRetVal);
					AddLogEntry(csErr);
					bRetVal = false;
				}
			}
			else
				bRetVal = false;
		}
		SetPrivilege(SE_RESTORE_NAME,FALSE);
		SetPrivilege(SE_BACKUP_NAME,FALSE);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::RestoreRegKeyPath"));
	}
	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: LoadKey
In Parameters	: HKEY - hive
CString - subkey
CString - user file
Out Parameters	: bool
Purpose			: to load the registry key, not valid for HKEY_CLASSES_ROOT and
HKEY_CURRENT_USER hives.
Author			: Dipali
--------------------------------------------------------------------------------------*/
bool CRegistry::LoadKey(HKEY HiveRoot, CString SubKey, CString ntUserFile)
{
	bool bRetVal = false;
	try
	{
		DWORD dwRetVal = 0;
		SetPrivilege(SE_RESTORE_NAME,TRUE);
		SetPrivilege(SE_BACKUP_NAME,TRUE);

		dwRetVal = RegLoadKey(HiveRoot, SubKey, ntUserFile);

		SetPrivilege(SE_RESTORE_NAME, FALSE);
		SetPrivilege(SE_BACKUP_NAME, FALSE);

		if(dwRetVal == ERROR_SUCCESS)
			bRetVal = true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::LoadKey"));
	}
	//return false;
	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: UnLoadKey
In Parameters	: HKEY - hive
CString - subkey
Out Parameters	: bool
Purpose			: to unload the registry key
Author			: Dipali
--------------------------------------------------------------------------------------*/
bool CRegistry::UnLoadKey(HKEY HiveRoot, CString SubKey)
{
	bool bRetVal = false;
	try
	{
		SetPrivilege(SE_RESTORE_NAME,TRUE);
		SetPrivilege(SE_BACKUP_NAME,TRUE);

		long lRetVal = 0;
		lRetVal = RegUnLoadKey(HiveRoot,SubKey);

		SetPrivilege(SE_RESTORE_NAME, FALSE);
		SetPrivilege(SE_BACKUP_NAME, FALSE);

		if(lRetVal == ERROR_SUCCESS)
			bRetVal = true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::UnLoadKey"));
	}
	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: RootKey2String
In Parameters	: HKEY hHive, Handle to the hive
Out Parameters	: Hive name if handle to the Hive is valid, Else Empty string
Purpose			: Returns the String version of the given Hive, Empty string if hive not found
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CString CRegistry::RootKey2String(HKEY hKey)
{
	try
	{
		return GetHiveName(hKey);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::RootKey2String"));
	}
	return _T("");
}
/*-------------------------------------------------------------------------------------
Function		: StringRoot2key
In Parameters	: CString csHive, Name of the Hive
Out Parameters	: Hive handle if valid, Else 0
Purpose			: Returns the Hive by the Name, 0 if hive not found
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry::StringRoot2key(CString strRoot, HKEY &hKey)
{
	try
	{
		hKey = GetHiveByName(strRoot);
		if(hKey)
			return true;
		else
			return false;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::StringRoot2key"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: AdjustPermissions
In Parameters	: HKEY - hive
CString - key
Out Parameters	: bool
Purpose			: to adjust the permission
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry::AdjustPermissions(HKEY hParent, CString csKeyName)
{
	try
	{
		HKEY hKey = 0;
		unsigned char * p = new unsigned char[9000];
		PSECURITY_DESCRIPTOR psecdesc = (PSECURITY_DESCRIPTOR)p;
		DWORD sts = 0;
		bool RetVal = false;

		if(!m_szp)
		{
			m_dwOrgSecDesc = MAX_SIZE * sizeof(TCHAR);
			m_szp = new TCHAR[MAX_SIZE];
			m_pOrgSecDesc = (PSECURITY_DESCRIPTOR)m_szp;
		}
		if(!m_szp)
			return (false);
		if(m_bWOW64Key)
		{
			sts = RegOpenKeyEx(hParent, (LPCWSTR)csKeyName, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey);
		}
		else
		{
			sts = RegOpenKey(hParent, csKeyName, &hKey);
		}
		if(sts != ERROR_SUCCESS)
			goto Cleanup;
		memset(m_pOrgSecDesc, 0, m_dwOrgSecDesc);
		sts = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, m_pOrgSecDesc, &m_dwOrgSecDesc);
		if(sts != ERROR_SUCCESS)
			goto Cleanup;

		sts = InitializeSecurityDescriptor(psecdesc, SECURITY_DESCRIPTOR_REVISION);
		if(sts == FALSE)
			goto Cleanup;

		sts = SetSecurityDescriptorDacl(psecdesc, TRUE, NULL, TRUE);
		if(sts == FALSE)
			goto Cleanup;

		sts = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, psecdesc);
		if(sts != ERROR_SUCCESS)
			goto Cleanup;

		RetVal = true;

Cleanup:
		if(hKey)
			RegCloseKey(hKey);

		if(p)
			delete[] p;

		return RetVal;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::AdjustPermissions"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: DeleteRegKey
In Parameters	: HKEY - hive
CString - key
Out Parameters	: bool
Purpose			: to delete the key
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry::DeleteRegKey(HKEY hParentKey, CString csRegKeyName)
{
	try
	{
		HKEY hKey = 0;

		DWORD dwRetVal = 0, SubKeyCount = 0, i = 0;
		DWORD MaxSubkeyNameLen = MAX_BUFFER;
		
		if(m_bWOW64Key)
		{
			if(RegOpenKeyEx(hParentKey, (LPCWSTR)csRegKeyName, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
				return false;

		}
		else
		{
			if(RegOpenKey(hParentKey, csRegKeyName, &hKey) != ERROR_SUCCESS)
				return false;
		}

		if(RegQueryInfoKey(hKey, NULL, NULL, NULL, &SubKeyCount, &MaxSubkeyNameLen,
			NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return false;
		}


		if(MaxSubkeyNameLen == 0)
		{
			MaxSubkeyNameLen = 4096;
		}
		else
		{
			if(MaxSubkeyNameLen < MAX_BUFFER)MaxSubkeyNameLen = MAX_BUFFER;
			MaxSubkeyNameLen = (MaxSubkeyNameLen * sizeof(TCHAR)) + sizeof(TCHAR);
		}

		LPWSTR lpKeyName = NULL;
		lpKeyName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, MaxSubkeyNameLen);

		if(!lpKeyName)
		{
			RegCloseKey(hKey);
			return false;
		}

		for(i = 0; i < SubKeyCount; i++)
		{
			SecureZeroMemory(lpKeyName, MaxSubkeyNameLen);

			dwRetVal = RegEnumKey(hKey, i, (LPWSTR)lpKeyName, MaxSubkeyNameLen);
			if(ERROR_SUCCESS != dwRetVal)
			{
				if(ERROR_NO_MORE_ITEMS == dwRetVal)
					break;
				// ignore entry which could not be retrieved as the buffer provided was small
				else if(dwRetVal == ERROR_MORE_DATA)
					continue;
				RegCloseKey (hKey);
				return false;
			}

			if(!DeleteRegKey(hKey, lpKeyName))
			{
				RegCloseKey(hKey);
				return false;
			}
			i--;
			SubKeyCount--;
		}
		GlobalFree(lpKeyName);
		RegCloseKey(hKey);

		if(!AdjustPermissions(hParentKey, csRegKeyName))
		{
			return false;
		}
		
		if(m_bWOW64Key)
		{
#ifndef _VS_2005_
			//dwRetVal = RegDeleteKeyEx (hParentKey, csRegKeyName,KEY_ALL_ACCESS | KEY_WOW64_64KEY,0);
			typedef LSTATUS (WINAPI * PFNRegDeleteKeyEx)(HKEY, LPCTSTR, REGSAM, DWORD);
			PFNRegDeleteKeyEx pfnRegDeleteKeyEx = NULL;

			HMODULE hAdvapi32 = GetModuleHandle(_T("Advapi32.dll"));
			if (hAdvapi32 != NULL)
			{
				pfnRegDeleteKeyEx = (PFNRegDeleteKeyEx)GetProcAddress(hAdvapi32, "RegDeleteKeyExW");
			}
			if (pfnRegDeleteKeyEx != NULL)
			{
				dwRetVal = pfnRegDeleteKeyEx(hParentKey, csRegKeyName,KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0);
			}
#endif
		}
		else
		{
			dwRetVal = RegDeleteKey (hParentKey, csRegKeyName);
		}
		if(ERROR_SUCCESS != dwRetVal)
		{
			return false;
		}
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::DeleteRegKey"));
	}
	return false;
}
/*-------------------------------------------------------------------------------------
Function		: AllowAccessToEveryone
In Parameters	: HKEY - hive
CString - key
Out Parameters	: bool
Purpose			: to set permission to allow acces  to everyone
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry ::AllowAccessToEveryone(HKEY hParentKey, CString csRegKeyName)
{
	try
	{
		HKEY hKey = 0;
		DWORD dwRetVal = 0, dwSubKeyCount = 0, i = 0;
		DWORD dwMaxSubKeyLen = MAX_BUFFER;
		if(m_bWOW64Key)
		{
			if(RegOpenKeyEx(hParentKey, (LPCWSTR)csRegKeyName, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
				return false;
		}
		else
		{
			if(RegOpenKey(hParentKey, csRegKeyName, &hKey) != ERROR_SUCCESS)
				return false;
		}

		if(RegQueryInfoKey(hKey, NULL, NULL, NULL, &dwSubKeyCount, &dwMaxSubKeyLen, NULL,
			NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return false;
		}


		if(dwMaxSubKeyLen == 0)
		{
			dwMaxSubKeyLen = 4096;
		}
		else
		{
			if(dwMaxSubKeyLen < MAX_BUFFER)dwMaxSubKeyLen = MAX_BUFFER;
			dwMaxSubKeyLen = (dwMaxSubKeyLen * sizeof(TCHAR)) +  sizeof(TCHAR);
		}

		LPWSTR lpSubKeyName = NULL;
		lpSubKeyName =  (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, dwMaxSubKeyLen);

		if(!lpSubKeyName)
		{
			RegCloseKey(hKey);
			return false;
		}

		for(i = 0; i < dwSubKeyCount; i++)
		{
			dwRetVal = RegEnumKey(hKey, i, (LPWSTR)lpSubKeyName, dwMaxSubKeyLen);

			if(ERROR_SUCCESS != dwRetVal)
			{
				if(ERROR_NO_MORE_ITEMS == dwRetVal)
					break;
				// ignore entry which could not be retrieved as the buffer provided was small
				else if(dwRetVal == ERROR_MORE_DATA)
					continue;
				RegCloseKey(hKey);
				// Darshan
				// 09-Feb-2009
				// Fixed Memory Leak Generated by GlobalAlloc for SubKeyName.
				GlobalFree(lpSubKeyName);
				return false;
			}
			AllowAccessToEveryone(hKey, lpSubKeyName);
		}
		RegCloseKey(hKey);

		// Darshan
		// 09-Feb-2009
		// Fixed Memory Leak Generated by GlobalAlloc for SubKeyName.
		GlobalFree(lpSubKeyName);
		lpSubKeyName = NULL;

		if(!AdjustPermissions(hParentKey, csRegKeyName))
		{
			return false;
		}
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::AllowAccessToEveryone"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: GetHiveName
In Parameters	: HKEY hHive, Handle to the hive
Out Parameters	: Hive name if handle to the Hive is valid, Else Empty string
Purpose			: Returns the String version of the given Hive, Empty string if hive not found
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CString CRegistry::GetHiveName(HKEY hKey)
{
	try
	{
		if(hKey == HKEY_CLASSES_ROOT)			return _T("HKEY_CLASSES_ROOT");
		else if(hKey == HKEY_CURRENT_CONFIG)	return _T("HKEY_CURRENT_CONFIG");
		else if(hKey == HKEY_CURRENT_USER)		return _T("HKEY_CURRENT_USER");
		else if(hKey == HKEY_LOCAL_MACHINE)	return _T("HKEY_LOCAL_MACHINE");
		else if(hKey == HKEY_USERS)			return _T("HKEY_USERS");
		else if(hKey == HKEY_DYN_DATA)			return _T("HKEY_DYN_DATA");
		else if(hKey == HKEY_PERFORMANCE_DATA)	return _T("HKEY_PERFORMANCE_DATA");
		else									return _T("");
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::GetHiveName"));
	}
	return _T("");
}

/*-------------------------------------------------------------------------------------
Function		: GetHiveByName
In Parameters	: CString csHive, Name of the Hive
Out Parameters	: Hive handle if valid, Else 0
Purpose			: Returns the Hive by the Name, 0 if hive not found
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
HKEY CRegistry::GetHiveByName(CString csHive)
{
	csHive.MakeUpper();
	try
	{
		if(csHive == "HKEY_LOCAL_MACHINE")				return HKEY_LOCAL_MACHINE;
		else if(csHive == "HKLM")						return HKEY_LOCAL_MACHINE;
		else if(csHive == "HKEY_CURRENT_USER")			return HKEY_CURRENT_USER;
		else if(csHive == "HKCU")						return HKEY_CURRENT_USER;
		else if(csHive == "HKEY_CLASSES_ROOT")			return HKEY_CLASSES_ROOT;
		else if(csHive == "HKEY_USERS")					return HKEY_USERS;
		else if(csHive == "HKEY_CURRENT_CONFIG")		return HKEY_CURRENT_CONFIG;
		else if(csHive == "HKEY_DYN_DATA")				return HKEY_DYN_DATA;
		else if(csHive == "HKEY_PERFORMANCE_DATA")		return HKEY_PERFORMANCE_DATA;
		else											return 0;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::GetHiveByName"));
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: EnumValues
In Parameters	: CString - main key
CStringArray& - values
HKEY - hive
Out Parameters	:
Purpose			:
Author			:
Created Date	:
--------------------------------------------------------------------------------------*/
bool CRegistry::EnumValues(CString csMainKey, CStringArray &arrValues, HKEY hHive)
{
	try
	{
		HKEY hMainkey = NULL;
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}
		if(RegOpenKeyEx(hHive, (LPCWSTR)csMainKey, 0, dwAccess, &hMainkey) != ERROR_SUCCESS)
			return false;

		DWORD dwMaxValueNameLen  = MAX_BUFFER;
		DWORD dwValueCount = 0;

		//To detemine MAX length
		if(RegQueryInfoKey(hMainkey, NULL, NULL, NULL, NULL, NULL,  NULL, &dwValueCount, &dwMaxValueNameLen,
			NULL, NULL, NULL) != ERROR_SUCCESS)
			return false;


		if(dwMaxValueNameLen == 0)
		{
			dwMaxValueNameLen = 4096;
		}
		else
		{
			if(dwMaxValueNameLen < MAX_BUFFER)dwMaxValueNameLen = MAX_BUFFER;
			dwMaxValueNameLen = (dwMaxValueNameLen * sizeof(TCHAR)) + sizeof(TCHAR);
		}


		DWORD iValIdx = 0;
		DWORD dwRetVal = 0;
		DWORD LengthOfValueName = 0;

		LPWSTR lpValueName = NULL;
		lpValueName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, dwMaxValueNameLen);

		if(!lpValueName)
		{
			RegCloseKey(hHive);
			return false;
		}

		//Get Values
		for(iValIdx = 0; iValIdx < dwValueCount; iValIdx++)
		{
			SecureZeroMemory(lpValueName, dwMaxValueNameLen);

			LengthOfValueName = dwMaxValueNameLen;

			dwRetVal = RegEnumValue(hMainkey, iValIdx, (LPWSTR)lpValueName, &LengthOfValueName, NULL, NULL, NULL, NULL);

			if(dwRetVal == ERROR_NO_MORE_ITEMS)
				break;
			// ignore entry which could not be retrieved as the buffer provided was small
			else if(dwRetVal == ERROR_MORE_DATA)
				continue;
			else if(dwRetVal != ERROR_SUCCESS)
			{
				break;
			}
			else if(dwRetVal == ERROR_SUCCESS)
			{
				LengthOfValueName = (DWORD)wcslen(lpValueName);

				if(LengthOfValueName != 0)
					arrValues.Add(lpValueName);
			}
		}
		GlobalFree(lpValueName);
		RegCloseKey(hMainkey);

		if(arrValues.GetCount() > 0)
			return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::EnumValues(): ") + csMainKey);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: QueryValue
In Parameters	: CString - main key
CArray - values array
HKEY - hive
Out Parameters	: bool
Purpose			: to get the information of key value
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry::QueryValue(CString csMainKey,CArray<CString,CString> &o_arrQueryKeysValues,HKEY hHiveKey)
{
	try
	{
		HKEY hKey = NULL;
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}

		if(RegOpenKeyEx(hHiveKey, csMainKey, 0, dwAccess, &hKey) != ERROR_SUCCESS)
			return false;

		DWORD    dwValueCount = 0;						// number of values for key
		DWORD    dwMaxValueNameLen = MAX_BUFFER;        // longest value name

		// Get the maximum value name length and the value count.
		RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &dwValueCount,
			&dwMaxValueNameLen, NULL, NULL, NULL);


		// Enumerate the Values, until RegEnumValue fails.
		DWORD iValIdx  = 0;
		DWORD dwRetVal = 0;


		if(dwMaxValueNameLen == 0)
		{
			dwMaxValueNameLen = 4096;
		}
		else
		{
			if(dwMaxValueNameLen < MAX_BUFFER)dwMaxValueNameLen = MAX_BUFFER;
			dwMaxValueNameLen = (dwMaxValueNameLen * sizeof(TCHAR)) + sizeof(TCHAR);
		}


		LPWSTR lpValueName = NULL;
		lpValueName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, dwMaxValueNameLen);

		if(!lpValueName)
		{
			RegCloseKey(hHiveKey);
			return false;
		}

		DWORD dwValueNameLen = dwMaxValueNameLen;
		for (iValIdx = 0; iValIdx < dwValueCount; iValIdx++)
		{
			dwValueNameLen = dwMaxValueNameLen;
			SecureZeroMemory(lpValueName, dwMaxValueNameLen);
			dwRetVal = RegEnumValue(hKey, iValIdx, lpValueName, &dwValueNameLen,
				NULL, NULL, NULL, NULL);

			if(dwRetVal == ERROR_SUCCESS)
				o_arrQueryKeysValues.Add(lpValueName);
			else if(dwRetVal == ERROR_NO_MORE_ITEMS)
				break;
			// ignore entry which could not be retrieved as the buffer provided was small
			else if(dwRetVal == ERROR_MORE_DATA)
				continue;
			else if(dwRetVal != ERROR_SUCCESS)
			{
				break;
			}
		}
		GlobalFree(lpValueName);
		::RegCloseKey(hKey);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::QueryValue"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: QueryDataValue
In Parameters	: CString - main key
CArray - values array
HKEY - hive
Out Parameters	: bool
Purpose			: to get the information of key data
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry::QueryDataValue(CString csMainKey, CStringArray &o_arrValues, CStringArray &o_arrData,HKEY hHiveKey )
{
	try
	{
		HKEY hKey = NULL;
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}

		if(RegOpenKeyEx(hHiveKey,csMainKey,0,dwAccess,&hKey) != ERROR_SUCCESS)
			return false;

		DWORD dwMaxValueNameLen = MAX_BUFFER;
		DWORD dwMaxDataLen =  MAX_VALUE_NAME;
		DWORD dwValueCount = 0;

		if(RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &dwValueCount, &dwMaxValueNameLen,
			&dwMaxDataLen, NULL, NULL) != ERROR_SUCCESS)
			return false;


		if(dwMaxValueNameLen == 0)
		{
			dwMaxValueNameLen = 4096;
		}
		else
		{
			if(dwMaxValueNameLen < MAX_BUFFER)
				dwMaxValueNameLen = MAX_BUFFER;
			//dwMaxValueNameLen = (dwMaxValueNameLen * sizeof(TCHAR)) + sizeof(TCHAR);
		}

		dwMaxDataLen	  = dwMaxDataLen + sizeof(TCHAR);

		LPWSTR lpValueName = NULL;
		LPWSTR lpValueData = NULL;
		DWORD dwValueByteLen = (dwMaxValueNameLen * sizeof(TCHAR)) + sizeof(TCHAR);
		lpValueName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, dwValueByteLen);

		if(!lpValueName)
		{
			RegCloseKey(hKey);
			return false;
		}

		lpValueData = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, dwMaxDataLen);

		if(!lpValueData)
		{
			RegCloseKey(hKey);
			return false;
		}

		DWORD dwType;
		DWORD iValIdx = 0, dwRetVal = 0;

		DWORD dwValueNameLen, dwValueDataLen;
		for(iValIdx = 0; iValIdx < dwValueCount; iValIdx++)
		{
			dwValueNameLen = dwMaxValueNameLen;
			dwValueDataLen = dwMaxDataLen;

			SecureZeroMemory(lpValueName, dwValueByteLen);
			SecureZeroMemory(lpValueData, dwMaxDataLen);

			dwRetVal = RegEnumValue(hKey, iValIdx, lpValueName, &dwValueNameLen,
				NULL, &dwType, (LPBYTE)lpValueData, &dwValueDataLen);

			if(dwRetVal == ERROR_NO_MORE_ITEMS)
				break;
			// ignore entry which could not be retrieved as the buffer provided was small
			else if(dwRetVal == ERROR_MORE_DATA)
				continue;
			else if(dwRetVal != ERROR_SUCCESS)
			{
				break;
			}
			else if(dwRetVal == ERROR_SUCCESS)
			{
				CString csValueData;
				if(dwType == REG_DWORD)
				{
					csValueData.Format(_T("%d"), *lpValueData);
				}
				else if(dwType == REG_BINARY)
				{
					csValueData = _T("");
				}
				else
					csValueData = lpValueData;
				CString csValueName;
				csValueName.Format(L"%s",lpValueName);
				if(dwValueNameLen == 0 && csValueData.GetLength() != 0)
				{
					csValueName = L"";
					dwValueNameLen = csValueName.GetLength();
				}

				if(dwValueNameLen > 0)
				{
					o_arrValues.Add(lpValueName);
					o_arrData.Add(csValueData);
				}
			}
		}
		GlobalFree(lpValueName);
		GlobalFree(lpValueData);
		RegCloseKey(hKey);
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::QueryDataValue"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: Open
In Parameters	: CString - key path
HKKEY - hive
Out Parameters	: bool
Purpose			: to open the given key
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry::Open(CString strKeyPath, HKEY &hKey, HKEY HiveRoot, REGSAM regSam)
{
	try
	{
		if(::RegOpenKeyEx(HiveRoot, LPCWSTR(strKeyPath), 0, regSam, &hKey) != ERROR_SUCCESS)
			return false;
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::Open"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: CreateKey
In Parameters	: CString - key path
HKEY & - hive
HKEY - hive root
Out Parameters	: bool
Purpose			: to create the key in given path
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry::CreateKey(CString strKeyPath, HKEY & hkey, HKEY HiveRoot)
{
	try
	{
		DWORD dwDisposition = 0;
		DWORD dwAccess = KEY_ALL_ACCESS;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}	
		if(::RegCreateKeyEx(HiveRoot, LPCWSTR(strKeyPath), 0, NULL, REG_OPTION_NON_VOLATILE,
			dwAccess, NULL, &hkey, &dwDisposition) != ERROR_SUCCESS)
			return false;

		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::CreateKey"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: CloseKey
In Parameters	: HKEY - key
Out Parameters	: bool
Purpose			: to close the given key
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry::CloseKey(HKEY &hKey)
{
	try
	{
		if(hKey == NULL)
			return false;

		if(RegCloseKey(hKey) == ERROR_SUCCESS)
		{
			hKey = NULL;
			return true;
		}
		else
			return false;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::CloseKey"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: CopyKeyRecursive
In Parameters	: CString  - source path
CString  - dest path
HKEY - source hive
HKEY - dest hive
Out Parameters	: bool
Purpose			: to copy the key recursively into another key
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry::CopyKeyRecursive(CString csKeyPathCopyFrom, CString csKeyPathCopyTo, HKEY HiveCopyFrom,	HKEY HiveCopyTo)
{
	try
	{
		CArray<CString,CString> csArrKeys;

		EnumSubKeys(csKeyPathCopyFrom, csArrKeys, HiveCopyFrom);
		if(CopyKeyUsingPreQueryKey(csKeyPathCopyFrom,	csKeyPathCopyTo, HiveCopyFrom,	HiveCopyTo) == FALSE)
			return false;

		for(int iCount = 0; iCount < csArrKeys.GetSize(); iCount++)
		{
			CString csSubKey(csArrKeys.GetAt(iCount));
			csSubKey = csSubKey.Mid(csKeyPathCopyFrom.GetLength() + 1);
			CopyKeyUsingPreQueryKey(csArrKeys.GetAt(iCount), csKeyPathCopyTo + BACK_SLASH + csSubKey,
				HiveCopyFrom, HiveCopyTo);
		}
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::CopyKeyRecursive"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: CopyKeyUsingPreQueryKey
In Parameters	: CString  - source path
CString  - dest path
HKEY - source hive
HKEY - dest hive
Out Parameters	: bool
Purpose			: to copy the key using pre query key
Author			:
--------------------------------------------------------------------------------------*/
bool CRegistry::CopyKeyUsingPreQueryKey(CString csMainKeyCopyFrom,	CString csMainKeyCopyTo,	HKEY hHiveKeyCopyFrom, HKEY hHiveKeyCopyTo)
{
	try
	{
		HKEY	hKey =  NULL;
		DWORD dwAccess = KEY_READ;
		if(m_bWOW64Key)
		{
			dwAccess |= KEY_WOW64_64KEY;
		}

		if(RegOpenKeyEx(hHiveKeyCopyFrom, csMainKeyCopyFrom, 0, dwAccess, &hKey) != ERROR_SUCCESS)
			return false;

		DWORD    dwSubKeyCount  = 0;					  // number of subkeys
		DWORD    dwMaxSubKeyLen = MAX_KEY_NAME;       // longest subkey size
		DWORD    dwValueCount = 0;				      // number of values for key
		DWORD    dwMaxValueNameLen = MAX_BUFFER;	  // longest value name
		DWORD    dwMaxValueDataLen = MAX_VALUE_NAME;  // longest value data


		RegQueryInfoKey(hKey, NULL, NULL, NULL, &dwSubKeyCount, &dwMaxSubKeyLen, NULL,
			&dwValueCount, &dwMaxValueNameLen, &dwMaxValueDataLen, NULL, NULL);

		HKEY	hKeyCreate =  NULL;
		// Added By Nilesh Dorge
		if(dwValueCount == 0)
		{
			if(m_bWOW64Key)
			{
				DWORD dwDisposition = 0;
				RegCreateKeyEx(hHiveKeyCopyTo, csMainKeyCopyTo, 0, NULL, REG_OPTION_NON_VOLATILE,
					KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &hKeyCreate, &dwDisposition);
			}
			else
			{

				RegCreateKey(hHiveKeyCopyTo, csMainKeyCopyTo, &hKeyCreate);
			}
		}

		// Enumerate the child keys and  values.
		DWORD	dwType;
		DWORD   iValIdx = 0, dwRetValue = 0;

		//if(dwMaxValueNameLen == 0)dwMaxValueNameLen = 1;

		if(dwMaxValueNameLen == 0)
		{
			dwMaxValueNameLen = 4096;
		}
		else
		{
			if(dwMaxValueNameLen < MAX_BUFFER)dwMaxValueNameLen = MAX_BUFFER;
			dwMaxValueNameLen = (dwMaxValueNameLen * sizeof(TCHAR)) + sizeof(TCHAR);
		}

		dwMaxValueDataLen = (dwMaxValueDataLen * sizeof(TCHAR)) + sizeof(TCHAR);

		LPWSTR lpValueName, lpValueData;
		lpValueName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, dwMaxValueNameLen);
		lpValueData = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, dwMaxValueDataLen);

		DWORD dwValueNameLen, dwValueDataLen;

		for (iValIdx = 0, dwRetValue = ERROR_SUCCESS; iValIdx < dwValueCount; iValIdx++)
		{
			dwValueNameLen = dwMaxValueNameLen;
			dwValueDataLen = dwMaxValueDataLen;

			dwRetValue = RegEnumValue(hKey, iValIdx, lpValueName, &dwValueNameLen, NULL,
				&dwType, (LPBYTE)lpValueData, &dwValueDataLen);

			if(dwRetValue == ERROR_SUCCESS)
			{
				bool bRet = false;
				if(m_bWOW64Key)
				{
					DWORD dwDisposition = 0;
					if(::RegCreateKeyEx(hHiveKeyCopyTo, csMainKeyCopyTo, 0, NULL, REG_OPTION_NON_VOLATILE,
						KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &hKeyCreate, &dwDisposition) == ERROR_SUCCESS)
					{
						bRet = true;
					}
				}
				else
				{
					if(RegCreateKey(hHiveKeyCopyTo, csMainKeyCopyTo, &hKeyCreate) == ERROR_SUCCESS)
					{
						bRet = true;
					}
				}
				if(bRet)
				{
					RegSetValueEx(hKeyCreate, lpValueName, NULL, dwType, (LPBYTE)lpValueData, dwValueDataLen);				 // length of value data
				}
			}
			else if(dwRetValue == ERROR_NO_MORE_ITEMS)
				break;
			// ignore entry which could not be retrieved as the buffer provided was small
			else if(dwRetValue == ERROR_MORE_DATA)
				continue;
			else if(dwRetValue != ERROR_SUCCESS)
			{
				break;
			}
		}
		GlobalFree(lpValueName);
		GlobalFree(lpValueData);
		if(hKey)
		{
			::RegCloseKey(hKey);
		}
		if(hKeyCreate)
		{
			::RegCloseKey(hKeyCreate);
		}

		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistry::CopyKeyUsingPreQueryKey"));
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : EnumValues
In Parameters  : CString csMainKey, vector<REG_VALUE_DATA> &vecRegValues, HKEY hHiveKey,
Out Parameters : void
Description    : Enumerate Values
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CRegistry::EnumValues(CString csMainKey, vector<REG_VALUE_DATA> &vecRegValues, HKEY hHiveKey)
{
	DWORD LengthOfLongestValueName = 0;
	DWORD LengthOfLongestValueData = 0;
	DWORD TypeCode = 0;
	DWORD LengthOfValueName = 0;
	DWORD LengthOfValueData = 0;
	LPWSTR lpValueName = NULL;
	LPBYTE lpValueData = NULL;

	HKEY hSubkey = NULL;
	DWORD dwAccess = KEY_READ;
	if(m_bWOW64Key)
	{
		dwAccess |= KEY_WOW64_64KEY;
	}

	if(RegOpenKeyEx(hHiveKey, csMainKey, 0, dwAccess, &hSubkey) != ERROR_SUCCESS)
		return;

	if(RegQueryInfoKey(hSubkey, 0, 0, 0, 0, 0, 0, 0, &LengthOfLongestValueName, &LengthOfLongestValueData, 0, 0) != ERROR_SUCCESS)
		return;

	LengthOfLongestValueName += sizeof(TCHAR);
	LengthOfLongestValueData ++;

	lpValueName = (LPWSTR)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestValueName * sizeof(TCHAR));
	lpValueData = (LPBYTE)GlobalAlloc(LMEM_FIXED|LMEM_ZEROINIT, LengthOfLongestValueData);

	for(DWORD iValIdx = 0;; iValIdx++)
	{
		wmemset(lpValueName, 0, LengthOfLongestValueName);
		memset(lpValueData, 0, LengthOfLongestValueData);
		LengthOfValueName	=	LengthOfLongestValueName;
		LengthOfValueData	=	LengthOfLongestValueData;

		DWORD NTr = RegEnumValue(hSubkey, iValIdx, lpValueName, &LengthOfValueName, NULL, &TypeCode, lpValueData, &LengthOfValueData);

		if(NTr == ERROR_NO_MORE_ITEMS)
			break;
		else if(NTr != ERROR_SUCCESS)
			break;

		REG_VALUE_DATA objData = {0};
		objData.Type_Of_Data = TypeCode;
		objData.iSizeOfData = LengthOfValueData;
		wcscpy_s(objData.strValue, lpValueName);
		if(LengthOfValueData <= sizeof(objData.bData))
			memcpy_s(objData.bData, LengthOfValueData, lpValueData, LengthOfValueData);

		vecRegValues.push_back(objData);
	}
	GlobalFree(lpValueName);
	GlobalFree(lpValueData);
	RegCloseKey(hSubkey);
}

bool CRegistry::GetValueType(CString strKeyPath, CString strValueName, DWORD &dwType, HKEY HiveRoot)
{
	bool bRetVal = false;
	HKEY hKey;
	if(RegOpenKey(HiveRoot, strKeyPath, &hKey) == ERROR_SUCCESS)
	{
		if(::RegQueryValueEx(hKey, strValueName, NULL, &dwType, NULL, NULL) == ERROR_SUCCESS)
			bRetVal = true;	

		RegCloseKey(hKey);
	}

	return bRetVal;
}

BOOL CRegistry::IsOS64Bit()
{
	BOOL bIsWow64 = FALSE;
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process = NULL;
	HMODULE hModule = NULL;

	hModule = GetModuleHandle(_T("kernel32"));
	if(hModule)
	{
		fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(hModule, "IsWow64Process");
	}

	if(fnIsWow64Process)
	{
		if(!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		{
			bIsWow64 = FALSE;
		}
	}

	return bIsWow64;
}

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning (default:6386)
#endif