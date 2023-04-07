
/*======================================================================================
FILE             : MD5DB.cpp
ABSTRACT         : tree class to store and load md5
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
				  
CREATION DATE    : 6/26/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "md5db.h"

BYTE HEADER_MD5DB[24]		= {"MAXDBVERSION00.00.00.08"};
BYTE HEADER_MD5DB_DATA[24]	= {0};

/*--------------------------------------------------------------------------------------
Function       : CMD5DB
In Parameters  : 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CMD5DB::CMD5DB(): CBalBST(false)
{
	m_bLoadError = false;
	m_bSaveError = false;
}

/*--------------------------------------------------------------------------------------
Function       : ~CMD5DB
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CMD5DB::~CMD5DB()
{
}

/*--------------------------------------------------------------------------------------
Function       : GetKey
In Parameters  : PVOID pVPtr, LPBYTE& byKey, 
Out Parameters : bool 
Description    : get key by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMD5DB::GetKey(PVOID pVPtr, LPBYTE& byKey)
{
	if(!pVPtr)
	{
		return (false);
	}

	byKey =(LPBYTE)(((PNODE)pVPtr) -> dwKey);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetData
In Parameters  : PVOID pVPtr, DWORD& dwData, 
Out Parameters : bool 
Description    : get data by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMD5DB::GetData(PVOID pVPtr, DWORD& dwData)
{
	if(!pVPtr)
	{
		return (false);
	}

	dwData =(DWORD)(*((LPDWORD)(((PNODE)pVPtr) -> dwData)));
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Compare
In Parameters  : ULONG64 dwKey1, ULONG64 dwKey2, 
Out Parameters : COMPARE_RESULT 
Description    : compare two key and return small, large or equal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
COMPARE_RESULT CMD5DB::Compare(ULONG64 dwKey1, ULONG64 dwKey2)
{
	LPBYTE pbyKey1 =(LPBYTE)dwKey1;
	LPBYTE pbyKey2 =(LPBYTE)dwKey2;

	for(int i = 0; i < MAX_MD5_LEN; i++)
	{
		if(pbyKey1[i]< pbyKey2[i])
		{
			return (SMALL);
		}
		else if(pbyKey1[i]> pbyKey2[i])
		{
			return (LARGE);
		}
	}

	return (EQUAL);
}

/*--------------------------------------------------------------------------------------
Function       : FreeKey
In Parameters  : ULONG64 dwKey, 
Out Parameters : void 
Description    : release key memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CMD5DB::FreeKey(ULONG64 dwKey)
{
	if(!m_pBuffer ||(((LPBYTE)dwKey)< m_pBuffer &&((LPBYTE)dwKey) >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)dwKey);
	}
}

/*--------------------------------------------------------------------------------------
Function       : FreeData
In Parameters  : ULONG64 dwData, 
Out Parameters : void 
Description    : release data memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CMD5DB::FreeData(ULONG64 dwData)
{
	if(!m_pBuffer ||(((LPBYTE)dwData)< m_pBuffer &&((LPBYTE)dwData) >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)dwData);
	}
}

/*--------------------------------------------------------------------------------------
Function       : AppendItemAscOrder
In Parameters  : LPBYTE pbyMD516, DWORD dwSpywareID, 
Out Parameters : bool 
Description    : add node in tree in ascending order in right vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMD5DB::AppendItemAscOrder(LPBYTE pbyMD516, DWORD dwSpywareID)
{
	LPBYTE pbyMD5 = NULL;
	LPBYTE pdwSpywareID = NULL;

	pbyMD5 = DuplicateBuffer(pbyMD516, MAX_MD5_LEN);
	if(NULL == pbyMD5)
	{
		return (false);
	}

	pdwSpywareID = DuplicateBuffer((LPBYTE)&dwSpywareID, sizeof(DWORD));
	if(NULL == pdwSpywareID)
	{
		Release((LPVOID&)pbyMD5);
		return (false);
	}

	if(!AddNodeAscOrder((ULONG64)pbyMD5,(ULONG64)pdwSpywareID))
	{
		Release((LPVOID&)pdwSpywareID);
		Release((LPVOID&)pbyMD5);
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendItem
In Parameters  : LPBYTE pbyMD516, DWORD dwSpywareID, 
Out Parameters : bool 
Description    : add node in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMD5DB::AppendItem(LPBYTE pbyMD516, DWORD dwSpywareID)
{
	LPBYTE pbyMD5 = NULL;
	LPBYTE pdwSpywareID = NULL;

	pbyMD5 = DuplicateBuffer(pbyMD516, MAX_MD5_LEN);
	if(NULL == pbyMD5)
	{
		return (false);
	}

	pdwSpywareID = DuplicateBuffer((LPBYTE)&dwSpywareID, sizeof(DWORD));
	if(NULL == pdwSpywareID)
	{
		Release((LPVOID&)pbyMD5);
		return (false);
	}

	if(!AddNode((ULONG64)pbyMD5,(ULONG64)pdwSpywareID))
	{
		Release((LPVOID&)pdwSpywareID);
		Release((LPVOID&)pbyMD5);
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : DeleteItem
In Parameters  : LPBYTE pbyMD516, 
Out Parameters : bool 
Description    : delete item from tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMD5DB::DeleteItem(LPBYTE pbyMD516)
{
	return (DeleteNode((ULONG64)pbyMD516));
}

/*--------------------------------------------------------------------------------------
Function       : SearchItem
In Parameters  : LPBYTE pbyMD516, DWORD& dwSpywareID, 
Out Parameters : bool 
Description    : search a key in tree and return data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMD5DB::SearchItem(LPBYTE pbyMD516, DWORD& dwSpywareID)
{
	ULONG64 dwData = 0;

	if(!FindNode((ULONG64)pbyMD516, dwData))
	{
		return (false);
	}

	dwSpywareID = *((LPDWORD)dwData);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendObject
In Parameters  : CBalBST& _objToAdd, 
Out Parameters : bool 
Description    : merge an object to this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMD5DB::AppendObject(CBalBST& _objToAdd)
{
	LPBYTE pbyMD5 = NULL;
	DWORD dwSpywareID = 0;
	LPVOID lpContext = NULL;
	CMD5DB &objToAdd = (CMD5DB &)_objToAdd;

	lpContext = objToAdd.GetFirst();
	while(lpContext)
	{
		pbyMD5 = NULL;
		dwSpywareID = 0;

		objToAdd.GetKey(lpContext, pbyMD5);
		if(pbyMD5)
		{
			objToAdd.GetData(lpContext, dwSpywareID);

			AppendItem(pbyMD5, dwSpywareID);
		}
		lpContext = objToAdd.GetNext(lpContext);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : DeleteObject
In Parameters  : CBalBST& _objToDel, 
Out Parameters : bool 
Description    : delete an object from this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMD5DB::DeleteObject(CBalBST& _objToDel)
{
	LPBYTE pbyMD5 = NULL;
	DWORD dwSpywareID = 0;
	LPVOID lpContext = NULL;
	CMD5DB &objToDel = (CMD5DB &)_objToDel;

	lpContext = objToDel.GetFirst();
	while(lpContext)
	{
		pbyMD5 = NULL;
		dwSpywareID = 0;

		objToDel.GetKey(lpContext, pbyMD5);
		if(pbyMD5)
		{
			objToDel.GetData(lpContext, dwSpywareID);

			DeleteItem(pbyMD5);
		}

		lpContext = objToDel.GetNext(lpContext);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, 
Out Parameters : bool 
Description    : load tree object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMD5DB::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	HANDLE hFile = 0;
	LPBYTE pbyDataPtr = NULL;
	PULONG64 pulNodePtr = 0, pulNodePtrFather = 0, pulNodePrevPtr = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_MD5DB)] ={0};
	TCHAR szFullFileName[MAX_PATH]={0};
	DWORD dwOneItemSize = MAX_MD5_LEN + sizeof(DWORD);
	DWORD dwFileSize = 0, dwBytesRead = 0, dwTotalItemsCount = 0;
	BYTE byHeaderDataFromFile[sizeof(HEADER_MD5DB_DATA)] ={0};
	BYTE byHeaderDataCalculated[sizeof(HEADER_MD5DB_DATA)] ={0};

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
		CloseHandle(hFile);
		//DeleteFile(szFullFileName);
		AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
		return (false);
	}

	if(bCheckVersion && memcmp(HEADER_MD5DB, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
	{
		CloseHandle(hFile);
		//DeleteFile(szFullFileName);
		AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
		return (false);
	}

	if(FALSE == ReadFile(hFile, byHeaderDataFromFile, sizeof(byHeaderDataFromFile), &dwBytesRead, 0))
	{
		CloseHandle(hFile);
		//DeleteFile(szFullFileName);
		AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
		return (false);
	}

	if(!CreateHeaderData(hFile, szFullFileName, byHeaderDataCalculated, sizeof(byHeaderDataCalculated)))
	{
		CloseHandle(hFile);
		//DeleteFile(szFullFileName);
		AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
		return (false);
	}

	if(memcmp(byHeaderDataFromFile, byHeaderDataCalculated, sizeof(byHeaderDataFromFile)))
	{
		CloseHandle(hFile);
		//DeleteFile(szFullFileName);
		AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
		return (false);
	}

	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(HEADER_MD5DB) + sizeof(HEADER_MD5DB_DATA))
	{
		CloseHandle(hFile);
		//DeleteFile(szFullFileName);
		AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
		return (false);
	}

	dwFileSize -= sizeof(HEADER_MD5DB) + sizeof(HEADER_MD5DB_DATA);

	if(dwFileSize % dwOneItemSize)
	{
		CloseHandle(hFile);
		//DeleteFile(szFullFileName);
		AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
		return (false);
	}

	dwTotalItemsCount = dwFileSize / dwOneItemSize;
	m_nBufferSize = dwFileSize +(dwTotalItemsCount * SIZE_OF_NODE);

	m_pBuffer =(LPBYTE)Allocate(m_nBufferSize);
	if(NULL == m_pBuffer)
	{
		CloseHandle(hFile);
		//DeleteFile(szFullFileName);
		AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
		return (false);
	}

	if(FALSE == ReadFile(hFile, m_pBuffer, dwFileSize, &dwBytesRead, 0))
	{
		Release((LPVOID &)m_pBuffer);
		CloseHandle(hFile);
		//DeleteFile(szFullFileName);
		AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
		return (false);
	}

	if(dwFileSize != dwBytesRead)
	{
		Release((LPVOID &)m_pBuffer);
		CloseHandle(hFile);
		//DeleteFile(szFullFileName);
		AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
		return (false);
	}

	CloseHandle(hFile);
	hFile = NULL;
	CryptBuffer(m_pBuffer, dwFileSize);

	pbyDataPtr = m_pBuffer;
	pulNodePtr =(PULONG64)(m_pBuffer + dwFileSize);
	m_pRoot =(PNODE)pulNodePtr;

	for(DWORD dwIndex = 0; dwIndex < dwTotalItemsCount; dwIndex++)
	{
		pulNodePrevPtr = pulNodePtr;
		*pulNodePtr =(ULONG64)pbyDataPtr; pulNodePtr++; pbyDataPtr += MAX_MD5_LEN;
		*pulNodePtr =(ULONG64)pbyDataPtr; pulNodePtr++; pbyDataPtr += sizeof(DWORD);
		*pulNodePtr = 0; pulNodePtr++;
		*pulNodePtr = 0; pulNodePtr++;
		*pulNodePtr =(ULONG64)(pulNodePtr + 2); pulNodePtr++;
		*pulNodePtr =(ULONG64)(pulNodePtrFather); pulNodePtr++;
		pulNodePtrFather = pulNodePrevPtr;
	}

	if(dwTotalItemsCount)
	{
		pulNodePtr -= 2;
		*pulNodePtr = 0;
	}

	Balance();
	m_bLoadedFromFile = true;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Save
In Parameters  : LPCTSTR szFileName, bool bEncryptContents, 
Out Parameters : bool 
Description    : save tree object to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMD5DB::Save(LPCTSTR szFileName, bool bEncryptContents)
{
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

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(HEADER_MD5DB) + sizeof(HEADER_MD5DB_DATA),
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
		if(m_pTemp->pLeft)
		{
			m_pTemp = m_pTemp->pLeft;
		}
		else
		{
			WriteFile(hFile,(LPVOID)m_pTemp->dwKey, MAX_MD5_LEN, &dwBytesWritten, 0);
			WriteFile(hFile,(LPVOID)m_pTemp->dwData, 4, &dwBytesWritten, 0);

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
					WriteFile(hFile,(LPVOID)m_pTemp->pParent->dwKey, MAX_MD5_LEN, &dwBytesWritten, 0);
					WriteFile(hFile,(LPVOID)m_pTemp->pParent->dwData, 4, &dwBytesWritten, 0);
					m_pTemp = m_pTemp->pParent->pRight;
					break;
				}
				else
				{
					WriteFile(hFile,(LPVOID)m_pTemp->pParent->dwKey, MAX_MD5_LEN, &dwBytesWritten, 0);
					WriteFile(hFile,(LPVOID)m_pTemp->pParent->dwData, 4, &dwBytesWritten, 0);
					m_pTemp = m_pTemp->pParent;
				}
			}
		}
	}

	if(m_bSaveError)
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		AddLogEntry(L"Error in saving: %s.File Deleted", szFullFileName);
		return (false);
	}

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_MD5DB) + sizeof(HEADER_MD5DB_DATA)))
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

	if(!WriteFile(hFile, HEADER_MD5DB, sizeof(HEADER_MD5DB), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!CreateHeaderData(hFile, szFileName, HEADER_MD5DB_DATA, sizeof(HEADER_MD5DB_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(FALSE == WriteFile(hFile, HEADER_MD5DB_DATA, sizeof(HEADER_MD5DB_DATA), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	CloseHandle(hFile);
	return (true);
}
