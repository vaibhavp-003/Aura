
/*======================================================================================
FILE             : S2S.cpp
ABSTRACT         : tree class to handle databse of type string -> string
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
				  
CREATION DATE    : 6/2/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "S2S.h"

BYTE HEADER_S2S[24]			= {"MAXDBVERSION00.00.00.08"};
BYTE HEADER_S2S_DATA[24]	= {0};

/*--------------------------------------------------------------------------------------
Function       : CS2S
In Parameters  : bool bIsEmbedded, 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CS2S::CS2S(bool bIsEmbedded, bool bIgnoreCase): CBalBST(bIsEmbedded)
{
	m_bLoadError = false;
	m_bSaveError = false;
	m_bIgnoreCase = bIgnoreCase;
	m_dwFileLenH = m_dwFileLenL = -1;
}

/*--------------------------------------------------------------------------------------
Function       : ~CS2S
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CS2S::~CS2S()
{
	m_dwFileLenH = m_dwFileLenL = -1;
	RemoveAll();
}

/*--------------------------------------------------------------------------------------
Function       : GetFileLength
In Parameters  : DWORD * pdwHigh
Out Parameters : DWORD
Description    : returns file length and if in param dword passed returns high byte also
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
DWORD CS2S::GetFileLength(DWORD * pdwHigh)
{
	if(pdwHigh)
	{
		*pdwHigh = m_dwFileLenH;
	}

	return m_dwFileLenL;
}

/*--------------------------------------------------------------------------------------
Function       : Compare
In Parameters  : ULONG64 dwKey1, ULONG64 dwKey2, 
Out Parameters : COMPARE_RESULT 
Description    : compare two key and return small, large or equal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
COMPARE_RESULT CS2S::Compare(ULONG64 dwKey1, ULONG64 dwKey2)
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
			s++ ;
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
void CS2S::FreeKey(ULONG64 dwKey)
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
Description    : release data memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CS2S::FreeData(ULONG64 dwData)
{
	if(((LPBYTE)dwData < m_pBuffer) ||((LPBYTE)dwData >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID &)dwData);
	}
}

/*--------------------------------------------------------------------------------------
Function       : AppendItemAscOrder
In Parameters  : LPCTSTR szKey, LPCTSTR szData, 
Out Parameters : bool 
Description    : add node in tree in ascending order in right vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2S::AppendItemAscOrder(LPCTSTR szKey, LPCTSTR szData)
{
	TCHAR * newKey = 0;
	TCHAR * newData = 0;

	newKey = DuplicateString(szKey);
	newData = DuplicateString(szData);

	if(!newKey || !newData)
	{
		if(newKey)
		{
			Release((LPVOID&)newKey);
		}

		if(newData)
		{
			Release((LPVOID&)newData);
		}

		return (false);
	}

	if(!AddNodeAscOrder((ULONG64)newKey,(ULONG64)newData))
	{
		if(newKey)
		{
			Release((LPVOID&)newKey);
		}

		if(newData)
		{
			Release((LPVOID&)newData);
		}

		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendItem
In Parameters  : LPCTSTR szKey, LPCTSTR szData, 
Out Parameters : bool 
Description    : add node in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2S::AppendItem(LPCTSTR szKey, LPCTSTR szData)
{
	TCHAR * newKey = 0;
	TCHAR * newData = 0;

	newKey = DuplicateString(szKey);
	newData = DuplicateString(szData);

	if(!newKey || !newData)
	{
		if(newKey)
		{
			Release((LPVOID&)newKey);
		}

		if(newData)
		{
			Release((LPVOID&)newData);
		
		}
		return (false);
	}

	if(!AddNode((ULONG64)newKey,(ULONG64)newData))
	{
		if(newKey)
		{
			Release((LPVOID&)newKey);
		}

		if(newData)
		{
			Release((LPVOID&)newData);
		}

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
bool CS2S::DeleteItem(LPCTSTR szKey)
{
	return (DeleteNode((ULONG64)szKey));
}

/*--------------------------------------------------------------------------------------
Function       : SearchItem
In Parameters  : LPCTSTR szKey, LPTSTR& szData, 
Out Parameters : bool 
Description    : search a key in tree and return data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2S::SearchItem(LPCTSTR szKey, LPTSTR& szData)
{
	ULONG64 dwData = 0;

	if(!FindNode((ULONG64)szKey, dwData))
	{
		return (false);
	}

	szData =(LPTSTR&)dwData;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetKey
In Parameters  : PVOID pVPtr, LPTSTR& szKey, 
Out Parameters : bool 
Description    : get key by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2S::GetKey(PVOID pVPtr, LPTSTR& szKey)
{
	szKey =(LPTSTR&)(((PNODE)pVPtr) -> dwKey);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetData
In Parameters  : PVOID pVPtr, LPTSTR& szData, 
Out Parameters : bool 
Description    : get data by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2S::GetData(PVOID pVPtr, LPTSTR& szData)
{
	szData =(LPTSTR&)((PNODE)pVPtr) -> dwData;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendObject
In Parameters  : CBalBST& objToAdd
Out Parameters : bool 
Description    : add all data from objToAdd to object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2S::AppendObject(CBalBST& objToAdd)
{
	CS2S& _objToAdd = (CS2S&)objToAdd;
	LPVOID lpContext = 0;
	LPTSTR szKey = 0, szData = 0;

	lpContext = _objToAdd.GetFirst();
	while(lpContext)
	{
		_objToAdd.GetKey(lpContext, szKey);
		_objToAdd.GetData(lpContext, szData);

		if(szKey && szData)
		{
			AppendItem(szKey, szData);
		}

		lpContext = _objToAdd.GetNext(lpContext);
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : DeleteObject
In Parameters  : CBalBST& objToDel
Out Parameters : bool 
Description    : delete all data in object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2S::DeleteObject(CBalBST& objToDel)
{
	CS2S& _objToDel = (CS2S&)objToDel;
	LPVOID lpContext = 0;
	LPTSTR szKey = 0;

	lpContext = _objToDel.GetFirst();
	while(lpContext)
	{
		_objToDel.GetKey(lpContext, szKey);

		if(szKey)
		{
			DeleteItem(szKey);
		}

		lpContext = _objToDel.GetNext(lpContext);
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
bool CS2S::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	ULONG64 * pCurrentPtr = 0;
	ULONG64 dwBaseAddress = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwFileSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	TCHAR * pString = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_S2S)] ={0};
	BYTE HDRDATA_FROM_FILE[sizeof(HEADER_S2S_DATA)] ={0};
	BYTE byHeaderData[sizeof(HEADER_S2S_DATA)] ={0};
	TCHAR szFullFileName[MAX_PATH]={0};

	m_dwFileLenH = m_dwFileLenL = -1;
	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return (false);
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return (false);
	}

	if(FALSE == ReadFile(hFile, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(bCheckVersion && memcmp(HEADER_S2S, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
	{
		goto ERROR_EXIT;
	}

	m_pTemp = m_pRoot = NULL;
	m_dwFileLenL = GetFileSize(hFile, &m_dwFileLenH);
	dwFileSize = m_dwFileLenL;
	if(dwFileSize <= sizeof(HEADER_S2S) + sizeof(HEADER_S2S_DATA))
	{
		goto ERROR_EXIT;
	}

	if(FALSE == ReadFile(hFile, HDRDATA_FROM_FILE, sizeof(HDRDATA_FROM_FILE), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFullFileName, byHeaderData, sizeof(byHeaderData)))
	{
		goto ERROR_EXIT;
	}

	//if(memcmp(byHeaderData, HDRDATA_FROM_FILE, sizeof(byHeaderData)))
	//{
	//	goto ERROR_EXIT;
	//}

	dwFileSize -= sizeof(HEADER_S2S) + sizeof(HEADER_S2S_DATA);
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
	dwBaseAddress -= sizeof(VERSION_FROM_FILE) + sizeof(HDRDATA_FROM_FILE);
	pCurrentPtr =(ULONG64*)m_pBuffer;

	m_pRoot = m_pTemp =(NODE*)pCurrentPtr;
	while(dwBytesProcessed < dwFileSize)
	{
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		pCurrentPtr++;
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_pBuffer, dwFileSize);

		dwBytesProcessed += SIZE_OF_NODE;

		pString = (TCHAR*)pCurrentPtr;

		if(m_pTemp->dwKey)
		{
			while(*pString)
			{
				pString++;
				dwBytesProcessed += sizeof(TCHAR);
			}

			pString++;
			dwBytesProcessed += sizeof(TCHAR);
		}

		if(m_pTemp->dwData)
		{
			while(*pString)
			{
				pString++;
				dwBytesProcessed += sizeof(TCHAR);
			}

			pString++;
			dwBytesProcessed += sizeof(TCHAR);
		}

		pCurrentPtr = (ULONG64*)pString;
	}

	Balance();
	m_nBufferSize = dwFileSize;
	m_bLoadedFromFile = true;
	return (true);

ERROR_EXIT:
	if(hFile != INVALID_HANDLE_VALUE && hFile != NULL)CloseHandle(hFile);
	m_pRoot = m_pTemp = NULL;
	if(m_pBuffer)Release((LPVOID&)m_pBuffer);
	m_bLoadedFromFile = false;
	m_nBufferSize = 0;
	//DeleteFile(szFullFileName);
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
bool CS2S::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	ULONG64		dwCurrentOffset = 0;
	ULONG64 dwLinkOffset = 0;
	ULONG64		dwNodeOffset = 0;
	DWORD dwBytesWritten = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szFullFileName[MAX_PATH]={0};
	BYTE byHeaderData[sizeof(HEADER_S2S_DATA)] ={0};

	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return (false);
	}

	if(NULL == m_pRoot)
	{
		DeleteFile(szFullFileName);
		return (true);
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(HEADER_S2S) + sizeof(HEADER_S2S_DATA),
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
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		dwLinkOffset = dwNodeOffset + sizeof(NODE) +((_tcslen((LPTSTR)m_pTemp->dwKey) + 1)* sizeof(TCHAR));
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

		dwLinkOffset =(_tcslen((TCHAR*)(m_pTemp->dwKey)) + 1)* sizeof(TCHAR);
		if(!WriteFile(hFile, (BYTE*)(m_pTemp->dwKey),(DWORD)dwLinkOffset, &dwBytesWritten, 0))
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

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_S2S) + sizeof(HEADER_S2S_DATA)))
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

	if(FALSE == WriteFile(hFile, HEADER_S2S, sizeof(HEADER_S2S), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!CreateHeaderData(hFile, szFullFileName, byHeaderData, sizeof(byHeaderData)))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(FALSE == WriteFile(hFile, byHeaderData, sizeof(byHeaderData), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	CloseHandle(hFile);
	return (true);
}
