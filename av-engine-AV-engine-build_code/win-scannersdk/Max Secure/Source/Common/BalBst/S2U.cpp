
/*======================================================================================
FILE             : S2U.cpp
ABSTRACT         : tree class to handle databse of type string -> ulong
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
				  
CREATION DATE    : 5/17/2009
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "S2U.h"

BYTE HEADER_S2U[24]			= {"MAXDBVERSION00.00.00.08"};
BYTE HEADER_S2U_DATA[24]	= {0};

/*--------------------------------------------------------------------------------------
Function       : CS2U
In Parameters  : bool bIsEmbedded, 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CS2U::CS2U(bool bIsEmbedded, bool bIgnoreCase): CBalBST(bIsEmbedded)
{
	m_bSaveError = false;
	m_bLoadError = false;
	m_bIgnoreCase = bIgnoreCase;
	m_bCheckFileIntegrity = true;
	memset(m_szVersion, 0, sizeof(m_szVersion));
}

/*--------------------------------------------------------------------------------------
Function       : ~CS2U
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CS2U::~CS2U()
{
	RemoveAll();
}

/*--------------------------------------------------------------------------------------
Function       : Compare
In Parameters  : ULONG64 dwKey1, ULONG64 dwKey2, 
Out Parameters : COMPARE_RESULT 
Description    : compare two key and return small, large or equal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
COMPARE_RESULT CS2U::Compare(ULONG64 dwKey1, ULONG64 dwKey2)
{
	LPTSTR f = (LPTSTR)dwKey1;
	LPTSTR s = (LPTSTR)dwKey2;
	int iResult = 0;

	if(m_bIgnoreCase)
	{
		iResult = _tcsicmp(f, s);
	}
	else
	{
		while(*f && *s && *f == *s)
		{
			f++ ;
			s++;
		}

		iResult = *f - *s;
	}

	if(iResult > 0)
	{
		return (LARGE);
	}
	else if(iResult < 0)
	{
		return (SMALL);
	}
	else
	{
		return (EQUAL);
	}
}

/*--------------------------------------------------------------------------------------
Function       : FreeKey
In Parameters  : ULONG64 dwKey, 
Out Parameters : void 
Description    : release key memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void  CS2U::FreeKey(ULONG64 dwKey)
{
	if(((LPBYTE)dwKey < m_pBuffer) ||((LPBYTE)dwKey >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID &)dwKey);
	}
}

/*--------------------------------------------------------------------------------------
Function       : FreeData
In Parameters  : ULONG64 dwData, 
Out Parameters : void 
Description    : do nothing
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void  CS2U::FreeData(ULONG64 dwData)
{
}

/*--------------------------------------------------------------------------------------
Function       : AppendItemAscOrder
In Parameters  : LPCTSTR szKey, DWORD dwData, 
Out Parameters : bool 
Description    : add node in tree in ascending order in right vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::AppendItemAscOrder(LPCTSTR szKey, DWORD dwData)
{
	TCHAR * newString = 0;

	newString = DuplicateString(szKey);
	if(NULL == newString)
	{
		return (false);
	}

	if(!AddNodeAscOrder((ULONG64)newString, dwData))
	{
		Release((LPVOID &)newString);
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendItem
In Parameters  : LPCTSTR szKey, DWORD dwData, 
Out Parameters : bool 
Description    : add node in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::AppendItem(LPCTSTR szKey, DWORD dwData)
{
	TCHAR * newString = 0;

	newString = DuplicateString(szKey);
	if(NULL == newString)
	{
		return (false);
	}

	if(!AddNode((ULONG64)newString, dwData))
	{
		Release((LPVOID &)newString);
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : DeleteItem
In Parameters  : LPCTSTR szKey, 
Out Parameters : bool 
Description    : delete item from tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::DeleteItem(LPCTSTR szKey)
{
	return (DeleteNode((ULONG64)szKey));
}

/*--------------------------------------------------------------------------------------
Function       : SearchItem
In Parameters  : LPCTSTR szKey, DWORD * pulData, 
Out Parameters : bool 
Description    : search a key in tree and return data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::SearchItem(LPCTSTR szKey, DWORD * pulData)
{
	ULONG64 dwData = 0;

	if(!FindNode((ULONG64)szKey, dwData))
	{
		return (false);
	}

	if(pulData)
	{
		*pulData = (DWORD)dwData;
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : UpdateData
In Parameters  : LPCTSTR szKey, DWORD dwData
Out Parameters : bool 
Description    : update the data of a given key
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::UpdateData(LPCTSTR szKey, DWORD dwData)
{
	if(!m_pLastSearchResult || EQUAL != Compare(m_pLastSearchResult->dwKey, (ULONG64)szKey))
	{
		if(!SearchItem(szKey, NULL))
			return false;

		if(!m_pLastSearchResult || EQUAL != Compare(m_pLastSearchResult->dwKey, (ULONG64)szKey))
			return false;
	}

	m_pLastSearchResult->dwData = dwData;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetKey
In Parameters  : PVOID pVPtr, LPTSTR& pStr, 
Out Parameters : bool 
Description    : get key by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::GetKey(PVOID pVPtr, LPTSTR& pStr)
{
	pStr =(LPTSTR&)(((PNODE)pVPtr) -> dwKey);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetData
In Parameters  : PVOID pVPtr, DWORD& dwData, 
Out Parameters : bool 
Description    : get data by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::GetData(PVOID pVPtr, DWORD& dwData)
{
	dwData =(DWORD)((PNODE)pVPtr) -> dwData;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : CopyContents
In Parameters  : CS2U& objNewCopy
Out Parameters : bool 
Description    : make a new copy of this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::CopyContents(CS2U& objNewCopy)
{
	LPVOID lpContext = NULL;
	LPTSTR lpKey = 0;
	DWORD dwData = 0;

	lpContext = GetFirst();
	while(lpContext)
	{
		GetKey(lpContext, lpKey);
		GetData(lpContext, dwData);

		if(lpKey)
		{
			objNewCopy.AppendItem(lpKey, dwData);
		}

		lpContext = GetNext(lpContext);
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : AppendObject
In Parameters  : (CBalBST& objToAdd
Out Parameters : bool 
Description    : add all the entries of 'objToAdd'
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::AppendObject(CBalBST& objToAdd)
{
	LPVOID lpContext = NULL;
	LPTSTR lpKey = 0;
	DWORD dwData = 0;
	CS2U& objToAddDup = (CS2U&)objToAdd;

	lpContext = objToAddDup.GetFirst();
	while(lpContext)
	{
		objToAddDup.GetKey(lpContext, lpKey);
		objToAddDup.GetData(lpContext, dwData);

		if(lpKey)
		{
			AppendItem(lpKey, dwData);
		}

		lpContext = objToAddDup.GetNext(lpContext);
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : DeleteObject
In Parameters  : CBalBST& objToDel
Out Parameters : bool 
Description    : delete all the entries of 'objToDel'
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::DeleteObject(CBalBST& objToDel)
{
	LPVOID lpContext = NULL;
	LPTSTR lpKey = 0;
	CS2U& objToDelDup = (CS2U&)objToDel;

	lpContext = objToDelDup.GetFirst();
	while(lpContext)
	{
		objToDelDup.GetKey(lpContext, lpKey);

		if(lpKey)
		{
			DeleteItem(lpKey);
		}

		lpContext = objToDelDup.GetNext(lpContext);
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : SearchObject
In Parameters  : CBalBST& objToSearch, bool bAllPresent
Out Parameters : bool 
Description    : load tree object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::SearchObject(CBalBST& objToSearch, bool bAllPresent)
{
	DWORD dwData = 0;
	LPVOID lpContext = NULL;
	LPTSTR szKey = NULL;
	bool bSuccess = true, bFound = false;
	CS2U& _objToSearch = (CS2U&)objToSearch;

	lpContext = _objToSearch.GetFirst();
	while(lpContext)
	{
		_objToSearch.GetKey(lpContext, szKey);
		if(szKey)
		{
			bFound = SearchItem(szKey, &dwData);
			if((bFound && !bAllPresent) || (!bFound && bAllPresent))
			{
				bSuccess = false;
				break;
			}
		}

		lpContext = _objToSearch.GetNext(lpContext);
	}

	return bSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : UpdateItem
In Parameters  : PVOID pVPtr, DWORD dwData
Out Parameters : bool 
Description    : update the data of this item in the tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::UpdateItem(PVOID pVPtr, ULONG64 ulData)
{
	((PNODE)pVPtr)->dwData = ulData;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, 
Out Parameters : bool 
Description    : load tree object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	ULONG64 * pCurrentPtr = 0;
	ULONG64 dwBaseAddress = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwFileSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	TCHAR * pString = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_S2U)] = {0};
	TCHAR szFullFileName[MAX_PATH] = {0};
	BYTE byHeaderDataFromFile[sizeof(HEADER_S2U_DATA)] = {0};
	BYTE byHeaderDataCalculated[sizeof(HEADER_S2U_DATA)] = {0};
	BYTE byVersionToCheck[sizeof(HEADER_S2U)] = {0};

	memcpy(byVersionToCheck, HEADER_S2U, sizeof(HEADER_S2U));

	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return (false);
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return (false);
	}

	if(FALSE == ReadFile(hFile, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(m_szVersion[0])
	{
		memcpy(byVersionToCheck + 5, m_szVersion, sizeof(m_szVersion));
	}

	if(bCheckVersion && memcmp(byVersionToCheck, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
	{
		goto ERROR_EXIT;
	}

	if(FALSE == ReadFile(hFile, byHeaderDataFromFile, sizeof(byHeaderDataFromFile), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFullFileName, byHeaderDataCalculated, sizeof(byHeaderDataCalculated)))
	{
		goto ERROR_EXIT;
	}

	if(m_bCheckFileIntegrity && memcmp(byHeaderDataFromFile, byHeaderDataCalculated, sizeof(byHeaderDataFromFile)))
	{
		goto ERROR_EXIT;
	}

	m_pTemp = m_pRoot = NULL;
	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(HEADER_S2U) + sizeof(HEADER_S2U_DATA))
	{
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(HEADER_S2U) + sizeof(HEADER_S2U_DATA);
	m_pBuffer =(BYTE*)Allocate(dwFileSize);
	if(NULL == m_pBuffer)
	{
		goto ERROR_EXIT;
	}

	if(FALSE == ReadFile(hFile, m_pBuffer, dwFileSize, &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(dwFileSize != dwBytesRead)
	{
		goto ERROR_EXIT;
	}

	CloseHandle(hFile);
	hFile = NULL;
	CryptBuffer(m_pBuffer, dwFileSize);

	dwBaseAddress =(ULONG64)m_pBuffer;
	dwBaseAddress -= sizeof(VERSION_FROM_FILE) + sizeof(HEADER_S2U_DATA);
	pCurrentPtr =(ULONG64*)m_pBuffer;

	m_pRoot =(NODE*)pCurrentPtr;
	while(dwBytesProcessed < dwFileSize)
	{
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		pCurrentPtr++;
		pCurrentPtr++;
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);

		dwBytesProcessed += SIZE_OF_NODE;
		pString = (TCHAR*)pCurrentPtr;
		while(*pString)
		{
			pString++;
			dwBytesProcessed ++;
			dwBytesProcessed ++;
		}

		pString++;
		dwBytesProcessed ++;
		dwBytesProcessed ++;

		pCurrentPtr = (ULONG64*)pString;
	}

	Balance();
	m_nBufferSize = dwFileSize;
	m_bLoadedFromFile = true;
	return (true);

ERROR_EXIT:
	if(hFile != INVALID_HANDLE_VALUE && hFile != NULL)
	{
		CloseHandle(hFile);
	}

	m_pRoot = m_pTemp = NULL;
	if(m_pBuffer)
	{
		Release((LPVOID&)m_pBuffer);
	}

	m_bLoadedFromFile = false;
	m_nBufferSize = 0;
	//DeleteFile(szFullFileName);
	AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
	return (false);
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFullFileName, bool bCheckVersion, bool bCheckFileIntegrity
Out Parameters : bool 
Description    : load tree object from file, enable bypassing version and file integrity checks
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::Load(LPCTSTR szFullFileName, bool bCheckVersion, bool bCheckFileIntegrity)
{
	bool bHoldRetValue = false;

	m_bCheckFileIntegrity = bCheckFileIntegrity;
	bHoldRetValue = Load(szFullFileName, bCheckVersion);
	m_bCheckFileIntegrity = true;
	return bHoldRetValue;
}

/*--------------------------------------------------------------------------------------
Function       : Save
In Parameters  : LPCTSTR szFileName, bool bEncryptContents, 
Out Parameters : bool 
Description    : save tree object to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2U::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	ULONG64	dwCurrentOffset = 0;
	ULONG64 dwLinkOffset = 0;
	ULONG64 dwNodeOffset = 0;
	DWORD dwBytesWritten = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szFullFileName[MAX_PATH] = {0};
	BYTE byVersionToSave[sizeof(HEADER_S2U)] = {0};

	memcpy(byVersionToSave, HEADER_S2U, sizeof(HEADER_S2U));
	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return (false);
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(byVersionToSave) + sizeof(HEADER_S2U_DATA), 0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	m_bSaveError = false;
	m_pTemp = m_pRoot;

	while(m_pTemp)
	{
		dwNodeOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
		dwLinkOffset = dwNodeOffset + sizeof(NODE);
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		if(!WriteFile(hFile, ((BYTE*)m_pTemp) + SIZE_OF_ONE_NODE_ELEMENT, SIZE_OF_ONE_NODE_ELEMENT * 4, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		dwLinkOffset = m_pTemp->pParent ? m_pTemp->pParent->dwHold : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		dwLinkOffset =(_tcslen((TCHAR*)(m_pTemp->dwKey)) + 1)* sizeof(TCHAR);
		if(!WriteFile(hFile, (BYTE*)(m_pTemp->dwKey),(DWORD)dwLinkOffset, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		m_pTemp->dwHold = dwNodeOffset;
		dwLinkOffset = 0;

		if(m_pTemp->pLeft)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 3);
			m_pTemp = m_pTemp->pLeft;
		}
		else if(m_pTemp->pRight)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 4);
			m_pTemp = m_pTemp->pRight;
		}
		else
		{
			while(m_pTemp)
			{
				if(NULL == m_pTemp->pParent)
				{
					m_pTemp = NULL;
				}
				else if(m_pTemp == m_pTemp->pParent->pRight)
				{
					m_pTemp = m_pTemp->pParent;
				}
				else if(m_pTemp->pParent->pRight)
				{
					dwLinkOffset = m_pTemp->pParent->dwHold +(SIZE_OF_ONE_NODE_ELEMENT * 4);
					m_pTemp = m_pTemp->pParent->pRight;
					break;
				}
				else
				{
					m_pTemp = m_pTemp->pParent;
				}
			}
		}

		if(dwLinkOffset)
		{
			dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
			SetFilePointer(hFile,(DWORD)dwLinkOffset, 0, FILE_BEGIN);
			if(!WriteFile(hFile, &dwCurrentOffset, sizeof(dwCurrentOffset), &dwBytesWritten, 0))
			{
				m_bSaveError = true;
				break;
			}

			SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
		}
	}

	if(m_bSaveError)
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		AddLogEntry(L"Error in saving: %s.File Deleted", szFullFileName);
		return (false);
	}

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_S2U) + sizeof(HEADER_S2U_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0, 0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(m_szVersion[0])
	{
		memcpy(byVersionToSave + 5, m_szVersion, sizeof(m_szVersion));
	}

	if(FALSE == WriteFile(hFile, byVersionToSave, sizeof(byVersionToSave), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_S2U_DATA, sizeof(HEADER_S2U_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(FALSE == WriteFile(hFile, HEADER_S2U_DATA, sizeof(HEADER_S2U_DATA), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	CloseHandle(hFile);
	return (true);
}

bool CS2U::LoadByVer(LPCTSTR szFileName, bool bCheckVersion, LPCSTR szVersion)
{
	if(strlen(szVersion) >= sizeof(m_szVersion))
	{
		return false;
	}

	strcpy_s(m_szVersion, _countof(m_szVersion), szVersion);
	return Load(szFileName, bCheckVersion);
}

bool CS2U::SaveByVer(LPCTSTR szFileName, bool bEncryptContents, LPCSTR szVersion)
{
	if(strlen(szVersion) >= sizeof(m_szVersion))
	{
		return false;
	}

	strcpy_s(m_szVersion, _countof(m_szVersion), szVersion);
	return Save(szFileName, bEncryptContents);
}
