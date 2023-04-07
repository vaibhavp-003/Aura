
/*======================================================================================
FILE             : S2UA.cpp
ABSTRACT         : tree class to database of type string( ansi ) -> ulong
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
				  
CREATION DATE    : 6/27/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "S2UA.h"

BYTE HEADER_S2UA[24]		= {"MAXDBVERSION00.00.00.08"};
BYTE HEADER_S2UA_DATA[24]	= {0};

/*--------------------------------------------------------------------------------------
Function       : CS2UA
In Parameters  : bool bIsEmbedded, 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CS2UA::CS2UA(bool bIsEmbedded): CBalBST(bIsEmbedded)
{
	m_bSaveError = false;
	m_bLoadError = false;
}

/*--------------------------------------------------------------------------------------
Function       : ~CS2UA
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CS2UA::~CS2UA()
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
COMPARE_RESULT CS2UA::Compare(ULONG64 dwKey1, ULONG64 dwKey2)
{
	LPSTR f = (LPSTR)dwKey1;
	LPSTR s = (LPSTR)dwKey2;
	int iResult = 0;

	while(*f && *s && *f == *s)
	{
		f++ ;
		s++ ;
	}

	iResult = *f - *s;
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
void CS2UA::FreeKey(ULONG64 dwKey)
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
void  CS2UA::FreeData(ULONG64 dwData)
{
}

/*--------------------------------------------------------------------------------------
Function       : AppendItemAscOrder
In Parameters  : LPCSTR szKey, DWORD dwData, 
Out Parameters : bool 
Description    : add node in tree in ascending order in right vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2UA::AppendItemAscOrder(LPCSTR szKey, DWORD dwData)
{
	char * newString = 0;

	newString = DuplicateStringA(szKey);
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
In Parameters  : LPCSTR szKey, DWORD dwData, 
Out Parameters : bool 
Description    : add node in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2UA::AppendItem(LPCSTR szKey, DWORD dwData)
{
	char * newString = 0;

	newString = DuplicateStringA(szKey);
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
In Parameters  : LPCSTR szKey, 
Out Parameters : bool 
Description    : delete item from tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2UA::DeleteItem(LPCSTR szKey)
{
	return (DeleteNode((ULONG64)szKey));
}

/*--------------------------------------------------------------------------------------
Function       : SearchItem
In Parameters  : LPCSTR szKey, DWORD * pdwData, 
Out Parameters : bool 
Description    : search a key in tree and return data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2UA::SearchItem(LPCSTR szKey, DWORD * pdwData)
{
	ULONG64 dwData = 0;

	if(!FindNode((ULONG64)szKey, dwData))
	{
		return (false);
	}

	if(pdwData)*pdwData =(DWORD)dwData;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetKey
In Parameters  : PVOID pVPtr, LPSTR& pStr, 
Out Parameters : bool 
Description    : get key by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2UA::GetKey(PVOID pVPtr, LPSTR& pStr)
{
	pStr =(LPSTR&)(((PNODE)pVPtr) -> dwKey);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetData
In Parameters  : PVOID pVPtr, DWORD& dwData, 
Out Parameters : bool 
Description    : get data by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2UA::GetData(PVOID pVPtr, DWORD& dwData)
{
	dwData =(DWORD)((PNODE)pVPtr) -> dwData;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, 
Out Parameters : bool 
Description    : load tree object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2UA::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	ULONG64 * pCurrentPtr = 0;
	ULONG64 dwBaseAddress = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwFileSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	char * pString = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_S2UA)] ={0};
	TCHAR szFullFileName[MAX_PATH]={0};
	BYTE byHeaderDataFromFile[sizeof(HEADER_S2UA_DATA)] ={0};
	BYTE byHeaderDataCalculated[sizeof(HEADER_S2UA_DATA)] ={0};

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
		CloseHandle(hFile);
		return (false);
	}

	if(bCheckVersion && memcmp(HEADER_S2UA, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
	{
		CloseHandle(hFile);
		return (false);
	}

	if(FALSE == ReadFile(hFile, byHeaderDataFromFile, sizeof(byHeaderDataFromFile), &dwBytesRead, 0))
	{
		CloseHandle(hFile);
		return (false);
	}

	if(!CreateHeaderData(hFile, szFullFileName, byHeaderDataCalculated, sizeof(byHeaderDataCalculated)))
	{
		CloseHandle(hFile);
		return (false);
	}

	if(memcmp(byHeaderDataFromFile, byHeaderDataCalculated, sizeof(byHeaderDataFromFile)))
	{
		CloseHandle(hFile);
		return (false);
	}

	m_pTemp = m_pRoot = NULL;
	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(HEADER_S2UA) + sizeof(HEADER_S2UA_DATA))
	{
		CloseHandle(hFile);
		return (true);
	}

	dwFileSize -= sizeof(HEADER_S2UA) + sizeof(HEADER_S2UA_DATA);
	m_pBuffer =(BYTE*)Allocate(dwFileSize);
	if(NULL == m_pBuffer)
	{
		CloseHandle(hFile);
		return (false);
	}

	if(FALSE == ReadFile(hFile, m_pBuffer, dwFileSize, &dwBytesRead, 0))
	{
		Release((LPVOID &)m_pBuffer);
		CloseHandle(hFile);
		return (false);
	}

	if(dwFileSize != dwBytesRead)
	{
		Release((LPVOID &)m_pBuffer);
		CloseHandle(hFile);
		return (false);
	}

	CloseHandle(hFile);
	CryptBuffer(m_pBuffer, dwFileSize);

	dwBaseAddress =(ULONG64)m_pBuffer;
	dwBaseAddress -= sizeof(VERSION_FROM_FILE) + sizeof(HEADER_S2UA_DATA);
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
		pString = (char*)pCurrentPtr;
		while(*pString)
		{
			pString++;
			dwBytesProcessed ++;
		}

		pString++;
		dwBytesProcessed ++;

		pCurrentPtr = (ULONG64*)pString;
	}

	Balance();
	m_nBufferSize = dwFileSize;
	m_bLoadedFromFile = true;
	return (true);

ERROR_EXIT:
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
Function       : Save
In Parameters  : LPCTSTR szFileName, 
Out Parameters : bool 
Description    : save tree object to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CS2UA::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	ULONG64	dwCurrentOffset = 0;
	ULONG64 dwLinkOffset = 0;
	ULONG64	dwNodeOffset = 0;
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

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(HEADER_S2UA) + sizeof(HEADER_S2UA_DATA), 0, FILE_BEGIN))
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

		dwLinkOffset =(strlen((char*)(m_pTemp->dwKey)) + 1);
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

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_S2UA) + sizeof(HEADER_S2UA_DATA)))
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

	if(!WriteFile(hFile, HEADER_S2UA, sizeof(HEADER_S2UA), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_S2UA_DATA, sizeof(HEADER_S2UA_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!WriteFile(hFile, HEADER_S2UA_DATA, sizeof(HEADER_S2UA_DATA), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	CloseHandle(hFile);
	return (true);
}
