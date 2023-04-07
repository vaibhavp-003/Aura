
/*======================================================================================
FILE             : RemoveDB.cpp
ABSTRACT         : defines linklist class for remove database
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
				  
CREATION DATE    : 5/25/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "RemoveDB.h"

BYTE HEADER_REMDB[24]={"MAXDBVERSION00.00.00.07"};
BYTE HEADER_REMDB_DATA[24]={0};

LPTSTR CRemoveDB::m_szGenericName = L"Malware.Generic.512";

/*--------------------------------------------------------------------------------------
Function       : CRemoveDB
In Parameters  :
Out Parameters : CRemoveDB
Description    :
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CRemoveDB::CRemoveDB(): m_pHead(0), m_byBuffer(0), m_nBufferSize(0), m_bTreeModified(false)
{
	m_pCurr = NULL ;
}

/*--------------------------------------------------------------------------------------
Function       : ~CRemoveDB
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CRemoveDB::~CRemoveDB()
{
	__try{
		RemoveAll ();
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
}

/*--------------------------------------------------------------------------------------
Function       : GetNode
In Parameters  : const SYS_OBJ& SystemObject, 
Out Parameters : LPVOID 
Description    : allocate memory and initialize a node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPVOID CRemoveDB::GetNode(const SYS_OBJ& SystemObject)
{
	PSYS_OBJ pNode = NULL;

	pNode =(PSYS_OBJ)Allocate(sizeof(SYS_OBJ));
	if(NULL == pNode)
	{
		return (NULL);
	}

	pNode->szKey					= NULL;
	pNode->szValue				= NULL;
	pNode->byData					= NULL;
	pNode->byReplaceData			= NULL;
	pNode->szBackupFileName		= NULL;
	pNode->iIndex					= SystemObject.iIndex;
	pNode->dwType					= SystemObject.dwType;
	pNode->ulptrHive 				= SystemObject.ulptrHive;
	pNode->dwSpywareID			= SystemObject.dwSpywareID;
	pNode->dwRegDataSize			= SystemObject.dwRegDataSize;
	pNode->dwReplaceRegDataSize	= SystemObject.dwReplaceRegDataSize;
	pNode->wRegDataType			= SystemObject.wRegDataType;
	pNode->bDeleteThis			= FALSE;
	pNode->u64DateTime			= SystemObject.u64DateTime;

	if(NULL != SystemObject.szKey)
	{
		pNode->szKey = DuplicateString(SystemObject.szKey);
		if(NULL == pNode->szKey)
		{
			Release((LPVOID&)pNode);
			return (NULL);
		}
	}

	if(NULL != SystemObject.szValue)
	{
		pNode->szValue = DuplicateString(SystemObject.szValue);
		if(NULL == pNode->szValue)
		{
			Release((LPVOID&)pNode->szKey);
			Release((LPVOID&)pNode);
			return (NULL);
		}
	}

	if(NULL != SystemObject.byData)
	{
		pNode->byData =(LPBYTE)Allocate(SystemObject.dwRegDataSize);
		if(NULL == pNode->byData)
		{
			Release((LPVOID&)pNode->szValue);
			Release((LPVOID&)pNode->szKey);
			Release((LPVOID&)pNode);
			return (NULL);
		}

		memcpy(pNode->byData, SystemObject.byData, SystemObject.dwRegDataSize);
	}

	if(NULL != SystemObject.szBackupFileName)
	{
		pNode->szBackupFileName = DuplicateString(SystemObject.szBackupFileName);
		if(NULL == pNode->szBackupFileName)
		{
			Release((LPVOID&)pNode->byData);
			Release((LPVOID&)pNode->szValue);
			Release((LPVOID&)pNode->szKey);
			Release((LPVOID&)pNode);
			return (NULL);
		}
	}

	if(NULL != SystemObject.byReplaceData)
	{
		pNode->byReplaceData = DuplicateBuffer(SystemObject.byReplaceData, SystemObject.dwReplaceRegDataSize);
		if(NULL == pNode->byReplaceData)
		{
			Release((LPVOID&)pNode->szBackupFileName);
			Release((LPVOID&)pNode->byData);
			Release((LPVOID&)pNode->szValue);
			Release((LPVOID&)pNode->szKey);
			Release((LPVOID&)pNode);
			return (NULL);
		}
	}

	return (pNode);
}

/*--------------------------------------------------------------------------------------
Function       : Add
In Parameters  : SYS_OBJ& SystemObject, 
Out Parameters : bool 
Description    : add a node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRemoveDB::Add(SYS_OBJ& SystemObject)
{
	PSYS_OBJ pNode = NULL;

	SystemObject.iIndex = m_pHead ? m_pHead->iIndex + 1 : 0;
	pNode =(PSYS_OBJ)GetNode(SystemObject);
	if(NULL == pNode)
	{
		return false;
	}

	pNode->pNext = m_pHead;
	m_pHead = pNode;

	m_bTreeModified = true;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : DeleteData
In Parameters  : PSYS_OBJ& pNode, 
Out Parameters : bool 
Description    : release data memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRemoveDB::DeleteData(PSYS_OBJ& pNode)
{
	if(pNode->szKey)
	{
		if((LPBYTE)pNode->szKey < m_byBuffer ||(LPBYTE)pNode->szKey >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->szKey);
		}
	}

	if(pNode->szValue)
	{
		if((LPBYTE)pNode->szValue < m_byBuffer ||(LPBYTE)pNode->szValue >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->szValue);
		}
	}

	if(pNode->byData)
	{
		if(pNode->byData < m_byBuffer || pNode->byData >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->byData);
		}
	}

	if(pNode->byReplaceData)
	{
		if(pNode->byReplaceData < m_byBuffer || pNode->byReplaceData >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->byReplaceData);
		}
	}

	if(pNode->szBackupFileName)
	{
		if((LPBYTE)pNode->szBackupFileName < m_byBuffer ||(LPBYTE)pNode->szBackupFileName >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->szBackupFileName);
		}
	}

	if((LPBYTE)pNode < m_byBuffer ||(LPBYTE)pNode >= m_byBuffer + m_nBufferSize)
	{
		Release((LPVOID&)pNode);
	}

	m_bTreeModified = true;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Delete
In Parameters  : LONG iIndex, 
Out Parameters : bool 
Description    : delete an item by index
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRemoveDB::Delete(LONG iIndex)
{
	PSYS_OBJ pParent = 0, pNode = m_pHead;

	while(pNode)
	{
		if(pNode->iIndex == iIndex)
		{
			if(pNode == m_pHead)
			{
				m_pHead = m_pHead->pNext;
				DeleteData(pNode);
				pNode = m_pHead;
			}
			else
			{
				pParent->pNext = pNode->pNext;
				DeleteData(pNode);
				pNode = pParent->pNext;
			}

			break;
		}
		else
		{
			pParent = pNode;
			pNode = pNode->pNext;
		}
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetFirst
In Parameters  : SYS_OBJ& SystemObject, 
Out Parameters : bool 
Description    : get the first object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRemoveDB::GetFirst(SYS_OBJ& SystemObject)
{
	if(NULL == m_pHead)
	{
		return false;
	}

	m_pCurr = m_pHead;
	SystemObject.bDeleteThis = m_pCurr->bDeleteThis;
	SystemObject.dwType = m_pCurr->dwType;

#ifdef WIN64
	SystemObject.ulptrHive = m_pCurr->ulptrHive | 0xFFFFFFFF00000000;
#else
	SystemObject.ulptrHive = m_pCurr->ulptrHive;
#endif

	SystemObject.dwSpywareID = m_pCurr->dwSpywareID;
	SystemObject.szValue = m_pCurr->szValue;
	if(SystemObject.dwSpywareID == 0)
	{
		SystemObject.szValue = SystemObject.szValue? SystemObject.szValue: m_szGenericName;
	}

	SystemObject.szBackupFileName = m_pCurr->szBackupFileName;
	SystemObject.szKey = m_pCurr->szKey;
	SystemObject.byReplaceData = m_pCurr->byReplaceData;
	SystemObject.dwReplaceRegDataSize = m_pCurr->dwReplaceRegDataSize;
	SystemObject.byData = m_pCurr->byData;
	SystemObject.dwRegDataSize = m_pCurr->dwRegDataSize;
	SystemObject.wRegDataType = m_pCurr->wRegDataType;
	SystemObject.u64DateTime = m_pCurr->u64DateTime;
	SystemObject.iIndex = m_pCurr->iIndex;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetNext
In Parameters  : SYS_OBJ& SystemObject, 
Out Parameters : bool 
Description    : get next object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRemoveDB::GetNext(SYS_OBJ& SystemObject)
{
	if(NULL == m_pCurr->pNext)
	{
		return false;
	}

	m_pCurr = m_pCurr->pNext;
	SystemObject.bDeleteThis = m_pCurr->bDeleteThis;
	SystemObject.dwType = m_pCurr->dwType;

#ifdef WIN64
	SystemObject.ulptrHive = m_pCurr->ulptrHive | 0xFFFFFFFF00000000;
#else
	SystemObject.ulptrHive = m_pCurr->ulptrHive;
#endif

	SystemObject.dwSpywareID = m_pCurr->dwSpywareID;
	SystemObject.szValue = m_pCurr->szValue;
	if(SystemObject.dwSpywareID == 0)
	{
		SystemObject.szValue = SystemObject.szValue? SystemObject.szValue: m_szGenericName;
	}

	SystemObject.szBackupFileName = m_pCurr->szBackupFileName;
	SystemObject.szKey = m_pCurr->szKey;
	SystemObject.byReplaceData = m_pCurr->byReplaceData;
	SystemObject.dwReplaceRegDataSize = m_pCurr->dwReplaceRegDataSize;
	SystemObject.byData = m_pCurr->byData;
	SystemObject.dwRegDataSize = m_pCurr->dwRegDataSize;
	SystemObject.wRegDataType = m_pCurr->wRegDataType;
	SystemObject.u64DateTime = m_pCurr->u64DateTime;
	SystemObject.iIndex = m_pCurr->iIndex;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Search
In Parameters  : SYS_OBJ& SystemObject, 
Out Parameters : bool 
Description    : search and return a object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRemoveDB::Search(SYS_OBJ& SystemObject)
{
	bool bFound = false;

	for(PSYS_OBJ pNode = m_pHead; pNode; pNode = pNode->pNext)
	{
		if(pNode->iIndex == SystemObject.iIndex)
		{
			SystemObject.bDeleteThis = pNode->bDeleteThis;
			SystemObject.dwType = pNode->dwType;
#ifdef WIN64
			SystemObject.ulptrHive = pNode->ulptrHive | 0xFFFFFFFF00000000;
#else
			SystemObject.ulptrHive = pNode->ulptrHive;
#endif

			SystemObject.dwSpywareID = pNode->dwSpywareID;
			SystemObject.szValue = pNode->szValue;
			if(SystemObject.dwSpywareID == 0)
			{
				SystemObject.szValue = SystemObject.szValue? SystemObject.szValue: m_szGenericName;
			}

			SystemObject.szBackupFileName = pNode->szBackupFileName;
			SystemObject.szKey = pNode->szKey;
			SystemObject.byReplaceData = pNode->byReplaceData;
			SystemObject.dwReplaceRegDataSize = pNode->dwReplaceRegDataSize;
			SystemObject.byData = pNode->byData;
			SystemObject.dwRegDataSize = pNode->dwRegDataSize;
			SystemObject.wRegDataType = pNode->wRegDataType;
			SystemObject.u64DateTime = pNode->u64DateTime;
			bFound = true;
			break;
		}
	}

	return (bFound);
}

/*--------------------------------------------------------------------------------------
Function       : 
In Parameters  : 
Out Parameters : UINT GetCount 
Description    : count number of nodes
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
UINT CRemoveDB::GetCount ()
{
	UINT nCount = 0;

	for(PSYS_OBJ pNode = m_pHead; pNode; pNode = pNode->pNext)
	{
		nCount++;
	}

	return (nCount);
}

/*--------------------------------------------------------------------------------------
Function       : SetDeleteFlag
In Parameters  : LONG iIndex, bool bDeleteFlag, 
Out Parameters : bool 
Description    : set a flag to delete the node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRemoveDB::SetDeleteFlag(LONG iIndex, bool bDeleteFlag)
{
	bool bSuccess = false;

	for(PSYS_OBJ pNode = m_pHead; pNode; pNode = pNode->pNext)
	{
		if(iIndex == pNode->iIndex)
		{
			pNode->bDeleteThis = bDeleteFlag;
			bSuccess = true;
			break;
		}
	}

	return (bSuccess);
}

/*--------------------------------------------------------------------------------------
Function       : 
In Parameters  : 
Out Parameters : bool DeleteAllMarkedEntries 
Description    : delete all the entries which have delete flag set
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRemoveDB::DeleteAllMarkedEntries ()
{
	PSYS_OBJ pParent = 0, pNode = m_pHead;

	while(pNode)
	{
		if(TRUE == pNode->bDeleteThis)
		{
			if(pNode == m_pHead)
			{
				m_pHead = m_pHead->pNext;
				DeleteData(pNode);
				pNode = m_pHead;
			}
			else
			{
				pParent->pNext = pNode->pNext;
				DeleteData(pNode);
				pNode = pParent->pNext;
			}
		}
		else
		{
			pParent = pNode;
			pNode = pNode->pNext;
		}
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : 
In Parameters  : 
Out Parameters : bool RemoveAll 
Description    : release memory of all nodes, empty list
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRemoveDB::RemoveAll ()
{
	PSYS_OBJ pNode = 0;

	while(m_pHead)
	{
		pNode = m_pHead->pNext;
		DeleteData(m_pHead);
		m_pHead = pNode;
	}

	if(m_byBuffer)
	{
		Release((LPVOID&)m_byBuffer);
		m_nBufferSize = 0;
	}

	m_pHead = NULL;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, bool bCheckVersion
Out Parameters : bool 
Description    : load list object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRemoveDB::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	ULONG64 * pCurrentPtr = 0;
	ULONG64 dwBaseAddress = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwFileSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	TCHAR * pString = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_REMDB)] ={0};
	PSYS_OBJ pNode = NULL;
	TCHAR szFullFileName[MAX_PATH]={0};
	BYTE byHeaderDataFromFile[sizeof(HEADER_REMDB_DATA)] ={0};
	BYTE byHeaderDataCalculated[sizeof(HEADER_REMDB_DATA)] ={0};

	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return false;
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	if(FALSE == ReadFile(hFile, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(bCheckVersion && memcmp(HEADER_REMDB, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
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

	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(HEADER_REMDB) + sizeof(HEADER_REMDB_DATA))
	{
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(HEADER_REMDB) + sizeof(HEADER_REMDB_DATA);
	m_byBuffer =(LPBYTE)Allocate(dwFileSize);
	if(NULL == m_byBuffer)
	{
		goto ERROR_EXIT;
	}

	if(FALSE == ReadFile(hFile, m_byBuffer, dwFileSize, &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(dwFileSize != dwBytesRead)
	{
		goto ERROR_EXIT;
	}

	CloseHandle(hFile);
	hFile = NULL;
	CryptBuffer(m_byBuffer, dwFileSize);

	dwBaseAddress =(ULONG64)(m_byBuffer -(sizeof(VERSION_FROM_FILE) + sizeof(HEADER_REMDB_DATA)));
	m_pHead = pNode =(PSYS_OBJ)m_byBuffer;
	pCurrentPtr =(ULONG64*)m_pHead;

	while(dwBytesProcessed < dwFileSize)
	{
		pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + SIZE_OF_NON_POINTER_DATA_SYS_OBJ);

		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);

		dwBytesProcessed += sizeof(SYS_OBJ);

		if(pNode->szKey)
		{
			pString =(LPTSTR)pCurrentPtr;
			while(*pString)
			{
				pString++;
				dwBytesProcessed += sizeof(TCHAR);
			}

			pString++;
			dwBytesProcessed += sizeof(TCHAR);
			pCurrentPtr =(ULONG64*)pString;
		}

		if(pNode->szValue)
		{
			pString =(LPTSTR)pCurrentPtr;
			while(*pString)
			{
				pString++;
				dwBytesProcessed += sizeof(TCHAR);
			}

			pString++;
			dwBytesProcessed += sizeof(TCHAR);
			pCurrentPtr =(ULONG64*)pString;
		}

		if(pNode->byData)
		{
			pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + pNode->dwRegDataSize);
			dwBytesProcessed += pNode->dwRegDataSize;
		}

		if(pNode->byReplaceData)
		{
			pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + pNode->dwReplaceRegDataSize);
			dwBytesProcessed += pNode->dwReplaceRegDataSize;
		}

		if(pNode->szBackupFileName)
		{
			pString =(LPTSTR)pCurrentPtr;
			while(*pString)
			{
				pString++;
				dwBytesProcessed += sizeof(TCHAR);
			}

			pString++;
			dwBytesProcessed += sizeof(TCHAR);
			pCurrentPtr =(ULONG64*)pString;
		}

		pNode = pNode->pNext ? pNode->pNext : pNode;
	}

	m_bTreeModified = false;
	m_nBufferSize = dwFileSize;
	return true;

ERROR_EXIT:
	if(hFile != INVALID_HANDLE_VALUE && hFile != NULL)CloseHandle(hFile);
	m_pHead = pNode = NULL;
	if(m_byBuffer)Release((LPVOID&)m_byBuffer);
	m_nBufferSize = dwFileSize = 0;
	//DeleteFile(szFullFileName);
	AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : Save
In Parameters  : LPCTSTR szFileName, 
Out Parameters : bool 
Description    : save list obejct to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRemoveDB::Save(LPCTSTR szFileName)
{
	DWORD dwGlobalIndex = 0;
	DWORD dwKeySize = 0;
	DWORD dwValueSize = 0;
	DWORD dwDataSize = 0;
	DWORD dwReplaceDataSize = 0;
	DWORD dwBackupFileNameSize = 0;
	ULONG64 dwLinkOffset = 0;
	DWORD dwNodeOffset = 0;
	DWORD dwBytesWritten = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szFullFileName[MAX_PATH]={0};
	bool bSaveError = false;

	DeleteAllMarkedEntries();

	if(!m_bTreeModified)
	{
		return true;
	}

	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return false;
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(HEADER_REMDB) + sizeof(HEADER_REMDB_DATA), 0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		DeleteFile(szFileName);
		return false;
	}

	dwGlobalIndex = GetCount();

	for(PSYS_OBJ pNode = m_pHead; pNode; pNode = pNode->pNext)
	{
		pNode->iIndex = --dwGlobalIndex;
		dwKeySize = pNode->szKey ?(DWORD)(_tcslen(pNode->szKey) + 1)* sizeof(TCHAR): 0;
		dwValueSize = pNode->szValue ?(DWORD)(_tcslen(pNode->szValue) + 1)* sizeof(TCHAR): 0;
		dwDataSize = pNode->byData ? pNode->dwRegDataSize : 0;
		dwReplaceDataSize = pNode->byReplaceData ? pNode->dwReplaceRegDataSize : 0;
		dwBackupFileNameSize = pNode->szBackupFileName ?(DWORD)(_tcslen(pNode->szBackupFileName) + 1)* sizeof(TCHAR): 0;

		dwNodeOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
		if(!WriteFile(hFile,((LPBYTE)pNode), SIZE_OF_NON_POINTER_DATA_SYS_OBJ, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->szKey ? dwNodeOffset + sizeof(SYS_OBJ): 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->szValue ? dwNodeOffset + sizeof(SYS_OBJ) + dwKeySize : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->byData ? dwNodeOffset + sizeof(SYS_OBJ) + dwKeySize + dwValueSize : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->byReplaceData ? dwNodeOffset + sizeof(SYS_OBJ) + dwKeySize + dwValueSize + dwDataSize : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->szBackupFileName ? dwNodeOffset + sizeof(SYS_OBJ) + dwKeySize + dwValueSize + dwDataSize + dwReplaceDataSize : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->pNext ? dwNodeOffset + sizeof(SYS_OBJ) + dwKeySize + dwValueSize + dwDataSize + dwReplaceDataSize + dwBackupFileNameSize : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		if(dwKeySize)WriteFile(hFile, pNode->szKey, dwKeySize, &dwBytesWritten, 0);
		if(dwValueSize)WriteFile(hFile, pNode->szValue, dwValueSize, &dwBytesWritten, 0);
		if(dwDataSize)WriteFile(hFile, pNode->byData, dwDataSize, &dwBytesWritten, 0);
		if(dwReplaceDataSize)WriteFile(hFile, pNode->byReplaceData, dwReplaceDataSize, &dwBytesWritten, 0);
		if(dwBackupFileNameSize)WriteFile(hFile, pNode->szBackupFileName, dwBackupFileNameSize, &dwBytesWritten, 0);
	}

	if(bSaveError)
	{
		CloseHandle(hFile);
		DeleteFile(szFileName);
		AddLogEntry(L"Error in saving: %s.File Deleted", szFileName);
		return false;
	}

	if(!CryptFileData(hFile, sizeof(HEADER_REMDB) + sizeof(HEADER_REMDB_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFileName);
		return false;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0, 0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		DeleteFile(szFileName);
		return false;
	}

	if(!WriteFile(hFile, HEADER_REMDB, sizeof(HEADER_REMDB), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFileName);
		return false;
	}

	if(!CreateHeaderData(hFile, szFileName, HEADER_REMDB_DATA, sizeof(HEADER_REMDB_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFileName);
		return false;
	}

	if(FALSE == WriteFile(hFile, HEADER_REMDB_DATA, sizeof(HEADER_REMDB_DATA), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFileName);
		return false;
	}

	CloseHandle(hFile);
	m_bTreeModified = false;
	return true;
}
