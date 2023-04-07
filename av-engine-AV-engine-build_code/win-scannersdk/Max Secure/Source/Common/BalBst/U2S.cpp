
/*======================================================================================
FILE             : U2S.cpp
ABSTRACT         : tree class to handle database type of ulong -> string
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
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "U2S.h"

BYTE HEADER_U2S[24]			= {"MAXDBVERSION00.00.00.08"};
BYTE HEADER_U2S_DATA[24]	= {0};

/*--------------------------------------------------------------------------------------
Function       : CU2S
In Parameters  : bool bIsEmbedded, 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CU2S::CU2S(bool bIsEmbedded): CBalBST(bIsEmbedded)
{
	m_bSaveError = false;
	m_bLoadError = false;
}

/*--------------------------------------------------------------------------------------
Function       : ~CU2S
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CU2S::~CU2S()
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
COMPARE_RESULT CU2S::Compare(ULONG64 dwKey1, ULONG64 dwKey2)
{
	if(dwKey1 < dwKey2)
	{
		return (SMALL);
	}
	else if(dwKey1 > dwKey2)
	{
		return (LARGE);
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
Description    : do nothing
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CU2S::FreeKey(ULONG64 dwKey)
{
	return;
}

/*--------------------------------------------------------------------------------------
Function       : FreeData
In Parameters  : ULONG64 dwData, 
Out Parameters : void 
Description    : release data memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CU2S::FreeData(ULONG64 dwData)
{
	if(((LPBYTE)dwData < m_pBuffer) ||((LPBYTE)dwData >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID &)dwData);
	}

	return;
}

/*--------------------------------------------------------------------------------------
Function       : AppendItemAscOrder
In Parameters  : DWORD dwKey, LPCTSTR szData, 
Out Parameters : bool 
Description    : add node in tree in ascending order in right vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2S::AppendItemAscOrder(DWORD dwKey, LPCTSTR szData)
{
	LPTSTR szHold = 0;

	szHold = DuplicateString(szData);
	if(NULL == szHold)
	{
		return (false);
	}

	if(!AddNodeAscOrder(dwKey,(ULONG64)szHold))
	{
		Release((LPVOID&)szHold);
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendItem
In Parameters  : DWORD dwKey, LPCTSTR szData, 
Out Parameters : bool 
Description    : add node in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2S::AppendItem(DWORD dwKey, LPCTSTR szData)
{
	LPTSTR szHold = 0;

	szHold = DuplicateString(szData);
	if(NULL == szHold)
	{
		return (false);
	}

	if(!AddNode(dwKey,(ULONG64)szHold))
	{
		Release((LPVOID&)szHold);
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : DeleteItem
In Parameters  : DWORD dwKey, 
Out Parameters : bool 
Description    : delete item from tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2S::DeleteItem(DWORD dwKey)
{
	return (DeleteNode(dwKey));
}

/*--------------------------------------------------------------------------------------
Function       : SearchItem
In Parameters  : DWORD dwKey, LPTSTR * ppszData, 
Out Parameters : bool 
Description    : search a key in tree and return data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2S::SearchItem(DWORD dwKey, LPTSTR * ppszData)
{
	ULONG64 dwData = 0;

	if(!FindNode(dwKey, dwData))
	{
		return (false);
	}

	if(ppszData)
	{
		*ppszData = (LPTSTR)dwData;
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetKey
In Parameters  : PVOID pVPtr, DWORD& dwKey, 
Out Parameters : bool 
Description    : get key by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2S::GetKey(PVOID pVPtr, DWORD& dwKey)
{
	dwKey =(DWORD)((PNODE)pVPtr) -> dwKey;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetData
In Parameters  : PVOID pVPtr, LPTSTR& pStr, 
Out Parameters : bool 
Description    : get data by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2S::GetData(PVOID pVPtr, LPTSTR& pStr)
{
	pStr =(LPTSTR&)(((PNODE)pVPtr) -> dwData);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendObject
In Parameters  : CBalBST& objToAdd
Out Parameters : bool 
Description    : add a given object to this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2S::AppendObject(CBalBST& objToAdd)
{
	LPVOID lpContext = NULL;
	LPTSTR szData = 0;
	DWORD dwKey = 0;
	CU2S& objToAddDup = (CU2S&)objToAdd;

	lpContext = objToAddDup.GetFirst();
	while(lpContext)
	{
		objToAddDup.GetKey(lpContext, dwKey);
		objToAddDup.GetData(lpContext, szData);

		if(szData)
		{
			AppendItem(dwKey, szData);
		}

		lpContext = objToAddDup.GetNext(lpContext);
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : DeleteObject
In Parameters  : CBalBST& objToDel
Out Parameters : bool 
Description    : delete a given object from this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2S::DeleteObject(CBalBST& objToDel)
{
	LPVOID lpContext = NULL;
	DWORD dwKey = 0;
	CU2S& objToDelDup = (CU2S&)objToDel;

	lpContext = objToDelDup.GetFirst();
	while(lpContext)
	{
		objToDelDup.GetKey(lpContext, dwKey);
		DeleteItem(dwKey);
		lpContext = objToDelDup.GetNext(lpContext);
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, 
Out Parameters : bool 
Description    : load tree object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2S::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	ULONG64 * pCurrentPtr = 0;
	ULONG64 dwBaseAddress = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwFileSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	TCHAR * pString = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_U2S)] ={0};
	TCHAR szFullFileName[MAX_PATH]={0};
	BYTE byHeaderDataFromFile[sizeof(HEADER_U2S_DATA)] ={0};
	BYTE byHeaderDataCalculated[sizeof(HEADER_U2S_DATA)] ={0};

	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return (false);
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ, FILE_SHARE_READ, 0, 
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return (false);
	}

	if(FALSE == ReadFile(hFile, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(bCheckVersion && memcmp(HEADER_U2S, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
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

	if(memcmp(byHeaderDataFromFile, byHeaderDataCalculated, sizeof(byHeaderDataFromFile)))
	{
		goto ERROR_EXIT;
	}

	m_pTemp = m_pRoot = NULL;
	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(HEADER_U2S) + sizeof(HEADER_U2S_DATA))
	{
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(HEADER_U2S) + sizeof(HEADER_U2S_DATA);
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
	dwBaseAddress -= sizeof(VERSION_FROM_FILE) + sizeof(HEADER_U2S_DATA);
	pCurrentPtr =(ULONG64*)m_pBuffer;
	m_pRoot =(NODE*)m_pBuffer;

	while(dwBytesProcessed < dwFileSize)
	{
		pCurrentPtr++;
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		pCurrentPtr++;
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);

		dwBytesProcessed += SIZE_OF_NODE;
		pString = (TCHAR*)pCurrentPtr;
		while(*pString)
		{
			pString++;
			dwBytesProcessed += sizeof(TCHAR);
		}

		pString++;
		dwBytesProcessed += sizeof(TCHAR);
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
	DeleteFile(szFullFileName);
	AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
	return (false);
}

/*--------------------------------------------------------------------------------------
Function       : Save
In Parameters  : LPCTSTR szFileName, bool bEncryptContents, 
Out Parameters : bool 
Description    : save tree object to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2S::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	ULONG64		dwCurrentOffset = 0;
	ULONG64 dwLinkOffset = 0;
	ULONG64		dwNodeOffset = 0;
	DWORD dwBytesWritten = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szFullFileName[MAX_PATH]={0};

	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return (false);
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(HEADER_U2S) + sizeof(HEADER_U2S_DATA),
													0, FILE_BEGIN))
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
		if(!WriteFile(hFile, m_pTemp, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		if(!WriteFile(hFile, ((BYTE*)m_pTemp) +(SIZE_OF_ONE_NODE_ELEMENT * 2), SIZE_OF_ONE_NODE_ELEMENT * 3, &dwBytesWritten, 0))
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

		dwLinkOffset =(_tcslen((TCHAR*)(m_pTemp->dwData)) + 1)* sizeof(TCHAR);
		if(!WriteFile(hFile, (BYTE*)(m_pTemp->dwData),(DWORD)dwLinkOffset, &dwBytesWritten, 0))
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

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_U2S) + sizeof(HEADER_U2S_DATA)))
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

	if(!WriteFile(hFile, HEADER_U2S, sizeof(HEADER_U2S), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_U2S_DATA, sizeof(HEADER_U2S_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!WriteFile(hFile, HEADER_U2S_DATA, sizeof(HEADER_U2S_DATA), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	CloseHandle(hFile);
	return (true);
}
