
/*======================================================================================
FILE             : RegFix.cpp
ABSTRACT         : link list class for handling registry fix database
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
				  
CREATION DATE    : 5/30/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "RegFix.h"

BYTE HEADER_REGFIX[24]={"MAXDBVERSION00.00.00.08"};
BYTE HEADER_REGFIX_DATA[24]={0};

/*--------------------------------------------------------------------------------------
Function       : CRegFix
In Parameters  : 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CRegFix::CRegFix(): m_pHead(0), m_byBuffer(0), m_nBufferSize(0), m_pCurr(0)
{
}

/*--------------------------------------------------------------------------------------
Function       : ~CRegFix
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CRegFix::~CRegFix()
{
	RemoveAll();
}

/*--------------------------------------------------------------------------------------
Function       : GetNode
In Parameters  : const REGFIX& RegFixData, 
Out Parameters : PREGFIX 
Description    : allocate memory and initialize a node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
PREGFIX CRegFix::GetNode(const REGFIX& RegFixData)
{
	PREGFIX pNode = NULL;

	pNode =(PREGFIX)Allocate(sizeof(REGFIX));
	if(!pNode)
	{
		return (false);
	}

	pNode->dwRegFixEntryID = RegFixData.dwRegFixEntryID;
	pNode->dwSpyNameID = RegFixData.dwSpyNameID;
	pNode->byFixAction = RegFixData.byFixAction;
	pNode->byFixType = RegFixData.byFixType;
	pNode->byCommonForAll = RegFixData.byCommonForAll;
	pNode->dwValueTypeID = RegFixData.dwValueTypeID;
	pNode->byHiveType = RegFixData.byHiveType;
	pNode->dwDataPartSize = RegFixData.dwDataPartSize;
	pNode->dwFixValueSize = RegFixData.dwFixValueSize;
	pNode->dwValueForXPSize = RegFixData.dwValueForXPSize;
	pNode->dwValueForVistaSize = RegFixData.dwValueForVistaSize;
	pNode->dwValueForWindows7Size = RegFixData.dwValueForWindows7Size;

	pNode->pbyDataPart = DuplicateBuffer(RegFixData.pbyDataPart, RegFixData.dwDataPartSize);
	if(NULL != RegFixData.pbyDataPart && NULL == pNode->pbyDataPart)
	{
		Release((LPVOID&)pNode);
		return (false);
	}

	pNode->pbyFixValue = DuplicateBuffer(RegFixData.pbyFixValue, RegFixData.dwFixValueSize);
	if(NULL != RegFixData.pbyFixValue && NULL == pNode->pbyFixValue)
	{
		Release((LPVOID&)pNode->pbyDataPart);
		Release((LPVOID&)pNode);
		return (false);
	}

	pNode->pbyValueForXP = DuplicateBuffer(RegFixData.pbyValueForXP, RegFixData.dwValueForXPSize);
	if(NULL != RegFixData.pbyValueForXP && NULL == pNode->pbyValueForXP)
	{
		Release((LPVOID&)pNode->pbyFixValue);
		Release((LPVOID&)pNode->pbyDataPart);
		Release((LPVOID&)pNode);
		return (false);
	}

	pNode->pbyValueForVista = DuplicateBuffer(RegFixData.pbyValueForVista, RegFixData.dwValueForVistaSize);
	if(NULL != RegFixData.pbyValueForVista && NULL == pNode->pbyValueForVista)
	{
		Release((LPVOID&)pNode->pbyValueForXP);
		Release((LPVOID&)pNode->pbyFixValue);
		Release((LPVOID&)pNode->pbyDataPart);
		Release((LPVOID&)pNode);
		return (false);
	}

	pNode->pbyValueForWindows7 = DuplicateBuffer(RegFixData.pbyValueForWindows7, RegFixData.dwValueForWindows7Size);
	if(NULL != RegFixData.pbyValueForWindows7 && NULL == pNode->pbyValueForWindows7)
	{
		Release((LPVOID&)pNode->pbyValueForVista);
		Release((LPVOID&)pNode->pbyValueForXP);
		Release((LPVOID&)pNode->pbyFixValue);
		Release((LPVOID&)pNode->pbyDataPart);
		Release((LPVOID&)pNode);
		return (false);
	}

	pNode->szKeyPart = DuplicateString(RegFixData.szKeyPart);
	if(NULL != RegFixData.szKeyPart && NULL == pNode->szKeyPart)
	{
		Release((LPVOID&)pNode->pbyValueForWindows7);
		Release((LPVOID&)pNode->pbyValueForVista);
		Release((LPVOID&)pNode->pbyValueForXP);
		Release((LPVOID&)pNode->pbyFixValue);
		Release((LPVOID&)pNode->pbyDataPart);
		Release((LPVOID&)pNode);
		return (false);
	}

	pNode->szValuePart = DuplicateString(RegFixData.szValuePart);
	if(NULL != RegFixData.szValuePart && NULL == pNode->szValuePart)
	{
		Release((LPVOID&)pNode->szKeyPart);
		Release((LPVOID&)pNode->pbyValueForWindows7);
		Release((LPVOID&)pNode->pbyValueForVista);
		Release((LPVOID&)pNode->pbyValueForXP);
		Release((LPVOID&)pNode->pbyFixValue);
		Release((LPVOID&)pNode->pbyDataPart);
		Release((LPVOID&)pNode);
		return (false);
	}

	return (pNode);
}

/*--------------------------------------------------------------------------------------
Function       : Add
In Parameters  : const REGFIX& RegFixData, 
Out Parameters : bool 
Description    : add a node to linklist
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::Add(const REGFIX& RegFixData)
{
	PREGFIX pNode = GetNode(RegFixData);
	if(!pNode)
	{
		return (false);
	}

	pNode->pNext = m_pHead;
	m_pHead = pNode;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : DeleteData
In Parameters  : PREGFIX& pNode, 
Out Parameters : bool 
Description    : release data memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::DeleteData(PREGFIX& pNode)
{
	if(pNode->pbyDataPart)
	{
		if(pNode->pbyDataPart < m_byBuffer || pNode->pbyDataPart >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->pbyDataPart);
		}
	}

	if(pNode->pbyFixValue)
	{
		if(pNode->pbyFixValue < m_byBuffer || pNode->pbyFixValue >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->pbyFixValue);
		}
	}

	if(pNode->pbyValueForXP)
	{
		if(pNode->pbyValueForXP < m_byBuffer || pNode->pbyValueForXP >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->pbyValueForXP);
		}
	}

	if(pNode->pbyValueForVista)
	{
		if(pNode->pbyValueForVista < m_byBuffer || pNode->pbyValueForVista >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->pbyValueForVista);
		}
	}

	if(pNode->pbyValueForWindows7)
	{
		if(pNode->pbyValueForWindows7 < m_byBuffer || pNode->pbyValueForWindows7 >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->pbyValueForWindows7);
		}
	}

	if(pNode->szKeyPart)
	{
		if((LPBYTE)pNode->szKeyPart < m_byBuffer ||(LPBYTE)pNode->szKeyPart >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->szKeyPart);
		}
	}

	if(pNode->szValuePart)
	{
		if((LPBYTE)pNode->szValuePart < m_byBuffer ||(LPBYTE)pNode->szValuePart >= m_byBuffer + m_nBufferSize)
		{
			Release((LPVOID&)pNode->szValuePart);
		}
	}

	if((LPBYTE)pNode < m_byBuffer ||(LPBYTE)pNode >= m_byBuffer + m_nBufferSize)
	{
		Release((LPVOID&)pNode);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Delete
In Parameters  : DWORD dwRegFixEntryID, 
Out Parameters : bool 
Description    : delete a node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::Delete(DWORD dwRegFixEntryID)
{
	PREGFIX pParent = 0, pNode = m_pHead;

	while(pNode)
	{
		if(pNode->dwRegFixEntryID == dwRegFixEntryID)
		{
			if(pNode == m_pHead)
			{
				m_pHead = m_pHead->pNext;
			}
			else
			{
				pParent->pNext = pNode->pNext;
			}

			DeleteData(pNode);
			break;
		}
		else
		{
			pParent = pNode;
			pNode = pNode->pNext;
		}
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Search
In Parameters  : REGFIX& RegFixData, 
Out Parameters : bool 
Description    : search a node and return
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::Search(REGFIX& RegFixData)
{
	bool bSuccess = false;

	for(PREGFIX pNode = m_pHead; pNode; pNode = pNode->pNext)
	{
		if(pNode->dwRegFixEntryID == RegFixData.dwRegFixEntryID)
		{
			RegFixData.dwRegFixEntryID = pNode->dwRegFixEntryID;
			RegFixData.dwSpyNameID = pNode->dwSpyNameID;
			RegFixData.byFixAction = pNode->byFixAction;
			RegFixData.byFixType = pNode->byFixType;
			RegFixData.byCommonForAll = pNode->byCommonForAll;
			RegFixData.dwValueTypeID = pNode->dwValueTypeID;
			RegFixData.byHiveType = pNode->byHiveType;
			RegFixData.dwDataPartSize = pNode->dwDataPartSize;
			RegFixData.dwFixValueSize = pNode->dwFixValueSize;
			RegFixData.dwValueForXPSize = pNode->dwValueForXPSize;
			RegFixData.dwValueForVistaSize = pNode->dwValueForVistaSize;
			RegFixData.dwValueForWindows7Size = pNode->dwValueForWindows7Size;
			RegFixData.pbyDataPart = pNode->pbyDataPart;
			RegFixData.pbyFixValue = pNode->pbyFixValue;
			RegFixData.pbyValueForXP = pNode->pbyValueForXP;
			RegFixData.pbyValueForVista = pNode->pbyValueForVista;
			RegFixData.pbyValueForWindows7 = pNode->pbyValueForWindows7;
			RegFixData.szKeyPart = pNode->szKeyPart;
			RegFixData.szValuePart = pNode->szValuePart;
			bSuccess = true;
			break;
		}
	}

	return (bSuccess);
}

/*--------------------------------------------------------------------------------------
Function       : GetFirst
In Parameters  : REGFIX& RegFixData, 
Out Parameters : bool 
Description    : get first node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::GetFirst(REGFIX& RegFixData)
{
	m_pCurr = m_pHead;

	if(NULL == m_pCurr)
	{
		return (false);
	}

	RegFixData.dwRegFixEntryID = m_pCurr->dwRegFixEntryID;
	RegFixData.dwSpyNameID = m_pCurr->dwSpyNameID;
	RegFixData.byFixAction = m_pCurr->byFixAction;
	RegFixData.byFixType = m_pCurr->byFixType;
	RegFixData.byCommonForAll = m_pCurr->byCommonForAll;
	RegFixData.dwValueTypeID = m_pCurr->dwValueTypeID;
	RegFixData.byHiveType = m_pCurr->byHiveType;
	RegFixData.dwDataPartSize = m_pCurr->dwDataPartSize;
	RegFixData.dwFixValueSize = m_pCurr->dwFixValueSize;
	RegFixData.dwValueForXPSize = m_pCurr->dwValueForXPSize;
	RegFixData.dwValueForVistaSize = m_pCurr->dwValueForVistaSize;
	RegFixData.dwValueForWindows7Size = m_pCurr->dwValueForWindows7Size;
	RegFixData.pbyDataPart = m_pCurr->pbyDataPart;
	RegFixData.pbyFixValue = m_pCurr->pbyFixValue;
	RegFixData.pbyValueForXP = m_pCurr->pbyValueForXP;
	RegFixData.pbyValueForVista = m_pCurr->pbyValueForVista;
	RegFixData.pbyValueForWindows7 = m_pCurr->pbyValueForWindows7;
	RegFixData.szKeyPart = m_pCurr->szKeyPart;
	RegFixData.szValuePart = m_pCurr->szValuePart;
	m_pCurr = m_pCurr->pNext;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetNext
In Parameters  : REGFIX& RegFixData, 
Out Parameters : bool 
Description    : get next node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::GetNext(REGFIX& RegFixData)
{
	if(NULL == m_pCurr)
	{
		return (false);
	}

	RegFixData.dwRegFixEntryID = m_pCurr->dwRegFixEntryID;
	RegFixData.dwSpyNameID = m_pCurr->dwSpyNameID;
	RegFixData.byFixAction = m_pCurr->byFixAction;
	RegFixData.byFixType = m_pCurr->byFixType;
	RegFixData.byCommonForAll = m_pCurr->byCommonForAll;
	RegFixData.dwValueTypeID = m_pCurr->dwValueTypeID;
	RegFixData.byHiveType = m_pCurr->byHiveType;
	RegFixData.dwDataPartSize = m_pCurr->dwDataPartSize;
	RegFixData.dwFixValueSize = m_pCurr->dwFixValueSize;
	RegFixData.dwValueForXPSize = m_pCurr->dwValueForXPSize;
	RegFixData.dwValueForVistaSize = m_pCurr->dwValueForVistaSize;
	RegFixData.dwValueForWindows7Size = m_pCurr->dwValueForWindows7Size;
	RegFixData.pbyDataPart = m_pCurr->pbyDataPart;
	RegFixData.pbyFixValue = m_pCurr->pbyFixValue;
	RegFixData.pbyValueForXP = m_pCurr->pbyValueForXP;
	RegFixData.pbyValueForVista = m_pCurr->pbyValueForVista;
	RegFixData.pbyValueForWindows7 = m_pCurr->pbyValueForWindows7;
	RegFixData.szKeyPart = m_pCurr->szKeyPart;
	RegFixData.szValuePart = m_pCurr->szValuePart;
	m_pCurr = m_pCurr->pNext;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : RemoveAll
In Parameters  : 
Out Parameters : bool 
Description    : remove all nodes
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::RemoveAll()
{
	PREGFIX pNode = NULL;
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
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetCount
In Parameters  : 
Out Parameters : UINT 
Description    : count number of nodes
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
UINT CRegFix::GetCount()
{
	UINT uiCount = 0;

	for(PREGFIX pNode = m_pHead; pNode; pNode = pNode->pNext)
	{
		uiCount++;
	}

	return (uiCount);
}

/*--------------------------------------------------------------------------------------
Function       : AppendObject
In Parameters  : CRegFix& objToAdd
Out Parameters : bool 
Description    : add all entries in the object from a passed object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::AppendObject(CRegFix& objToAdd)
{
	REGFIX RegFix = {0};
	bool bSuccess = true;

	if(!objToAdd.GetFirst(RegFix))
	{
		return true;
	}

	do
	{
		if(!Search(RegFix))
		{
			if(!Add(RegFix))
			{
				bSuccess = false;
			}
		}
	}while(objToAdd.GetNext(RegFix));

	return bSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : DeleteObject
In Parameters  : CRegFix& objToDel
Out Parameters : bool 
Description    : delete all entries in the object of a passed object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::DeleteObject(CRegFix& objToDel)
{
	REGFIX RegFix = {0};
	bool bSuccess = true;

	if(!objToDel.GetFirst(RegFix))
	{
		return true;
	}

	do
	{
		if(Search(RegFix))
		{
			if(!Delete(RegFix.dwRegFixEntryID))
			{
				bSuccess = false;
			}
		}
	}while(objToDel.GetNext(RegFix));

	return bSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : SearchObject
In Parameters  : CRegFix& objToSearch, bool bAllPresent
Out Parameters : bool 
Description    : search all entries when 'bAllPresent' is true for presence and vice-versa
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::SearchObject(CRegFix& objToSearch, bool bAllPresent)
{
	REGFIX RegFix = {0};
	bool bSuccess = true, bFound = false;

	if(!objToSearch.GetFirst(RegFix))
	{
		return true;
	}

	do
	{
		bFound = Search(RegFix);
		if((!bFound && bAllPresent) || (bFound && !bAllPresent))
		{
			bSuccess = false;
			break;
		}
	}while(objToSearch.GetNext(RegFix));

	return bSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, 
Out Parameters : bool 
Description    : load linklist object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	ULONG64 * pCurrentPtr = 0;
	ULONG64 dwBaseAddress = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwFileSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_REGFIX)] ={0};
	PREGFIX pNode = NULL;
	TCHAR szFullFileName[MAX_PATH]={0};
	BYTE byHeaderDataFromFile[sizeof(HEADER_REGFIX_DATA)] ={0};
	BYTE byHeaderDataCalculated[sizeof(HEADER_REGFIX_DATA)] ={0};

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

	if(bCheckVersion && memcmp(HEADER_REGFIX, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
	{
		goto ERROR_EXIT;
	}

	if(FALSE == ReadFile(hFile, byHeaderDataFromFile, sizeof(byHeaderDataFromFile), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFullFileName, byHeaderDataCalculated, sizeof(byHeaderDataFromFile)))
	{
		goto ERROR_EXIT;
	}

	if(memcmp(byHeaderDataFromFile, byHeaderDataCalculated, sizeof(byHeaderDataFromFile)))
	{
		goto ERROR_EXIT;
	}

	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(HEADER_REGFIX) + sizeof(HEADER_REGFIX_DATA))
	{
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(HEADER_REGFIX) + sizeof(HEADER_REGFIX_DATA);
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

	dwBaseAddress =(ULONG64)(m_byBuffer -(sizeof(VERSION_FROM_FILE) + sizeof(HEADER_REGFIX_DATA)));
	m_pHead = pNode =(PREGFIX)m_byBuffer;
	pCurrentPtr =(ULONG64*)m_pHead;

	while(dwBytesProcessed < dwFileSize)
	{
		pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + SIZE_OF_NON_POINTER_DATA_REG_FIX);

		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);
		CHECK_AND_MAKE_POINTER(pCurrentPtr, dwBaseAddress, m_byBuffer, dwFileSize);

		dwBytesProcessed += sizeof(REGFIX);

		if(pNode->pbyDataPart)
		{
			dwBytesProcessed += pNode->dwDataPartSize;
			pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + pNode->dwDataPartSize);
		}

		if(pNode->pbyFixValue)
		{
			dwBytesProcessed += pNode->dwFixValueSize;
			pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + pNode->dwFixValueSize);
		}

		if(pNode->pbyValueForXP)
		{
			dwBytesProcessed += pNode->dwValueForXPSize;
			pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + pNode->dwValueForXPSize);
		}

		if(pNode->pbyValueForVista)
		{
			dwBytesProcessed += pNode->dwValueForVistaSize;
			pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + pNode->dwValueForVistaSize);
		}

		if(pNode->pbyValueForWindows7)
		{
			dwBytesProcessed += pNode->dwValueForWindows7Size;
			pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + pNode->dwValueForWindows7Size);
		}

		if(pNode->szKeyPart)
		{
			dwBytesProcessed +=(DWORD)((_tcslen(pNode->szKeyPart) + 1)* sizeof(TCHAR));
			pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) +((_tcslen(pNode->szKeyPart) + 1)* sizeof(TCHAR)));
		}

		if(pNode->szValuePart)
		{
			dwBytesProcessed +=(DWORD)((_tcslen(pNode->szValuePart) + 1)* sizeof(TCHAR));
			pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) +((_tcslen(pNode->szValuePart) + 1)* sizeof(TCHAR)));
		}

		pNode = pNode->pNext;
	}

	m_nBufferSize = dwFileSize;
	return (true);

ERROR_EXIT:
	if(hFile != INVALID_HANDLE_VALUE && hFile != NULL)CloseHandle(hFile);
	m_pHead = pNode = NULL;
	if(m_byBuffer)Release((LPVOID&)m_byBuffer);
	m_nBufferSize = 0;
	//DeleteFile(szFullFileName);
	AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
	return (false);
}

/*--------------------------------------------------------------------------------------
Function       : Save
In Parameters  : LPCTSTR szFileName, bool bEncryptContents, 
Out Parameters : bool 
Description    : save linklist object to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CRegFix::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	DWORD dwKeyPartSize = 0;
	DWORD dwValuePartSize = 0;
	ULONG64 dwLinkOffset = 0;
	DWORD dwNodeOffset = 0;
	DWORD dwBytesWritten = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szFullFileName[MAX_PATH]={0};
	bool bSaveError = false;

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

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(HEADER_REGFIX) + sizeof(HEADER_REGFIX_DATA),
													0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	for(PREGFIX pNode = m_pHead; pNode; pNode = pNode->pNext)
	{
		dwKeyPartSize = pNode->szKeyPart ?(DWORD)((_tcslen(pNode->szKeyPart) + 1)* sizeof(TCHAR)): 0;
		dwValuePartSize = pNode->szValuePart ?(DWORD)((_tcslen(pNode->szValuePart) + 1)* sizeof(TCHAR)): 0;

		dwNodeOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
		if(!WriteFile(hFile, pNode, SIZE_OF_NON_POINTER_DATA_REG_FIX, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->pbyDataPart ? dwNodeOffset + sizeof(REGFIX): 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->pbyFixValue ? dwNodeOffset + sizeof(REGFIX) + pNode->dwDataPartSize : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->pbyValueForXP ? dwNodeOffset + sizeof(REGFIX) + pNode->dwDataPartSize + pNode->dwFixValueSize : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->pbyValueForVista ? dwNodeOffset + sizeof(REGFIX) + pNode->dwDataPartSize + pNode->dwFixValueSize + pNode->dwValueForXPSize : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->pbyValueForWindows7 ? dwNodeOffset + sizeof(REGFIX) + pNode->dwDataPartSize + pNode->dwFixValueSize + pNode->dwValueForXPSize + pNode->dwValueForVistaSize : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->szKeyPart ? dwNodeOffset + sizeof(REGFIX) + pNode->dwDataPartSize + pNode->dwFixValueSize + pNode->dwValueForXPSize + pNode->dwValueForVistaSize + pNode->dwValueForWindows7Size : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->szValuePart ? dwNodeOffset + sizeof(REGFIX) + pNode->dwDataPartSize + pNode->dwFixValueSize + pNode->dwValueForXPSize + pNode->dwValueForVistaSize + + pNode->dwValueForWindows7Size + dwKeyPartSize : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		dwLinkOffset = pNode->pNext ? dwNodeOffset + sizeof(REGFIX) + pNode->dwDataPartSize + pNode->dwFixValueSize + pNode->dwValueForXPSize + pNode->dwValueForVistaSize + + pNode->dwValueForWindows7Size + dwKeyPartSize + dwValuePartSize : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			bSaveError = true;
			break;
		}

		if(pNode->pbyDataPart)WriteFile(hFile, pNode->pbyDataPart, pNode->dwDataPartSize, &dwBytesWritten, 0);
		if(pNode->pbyFixValue)WriteFile(hFile, pNode->pbyFixValue, pNode->dwFixValueSize, &dwBytesWritten, 0);
		if(pNode->pbyValueForXP)WriteFile(hFile, pNode->pbyValueForXP, pNode->dwValueForXPSize, &dwBytesWritten, 0);
		if(pNode->pbyValueForVista)WriteFile(hFile, pNode->pbyValueForVista, pNode->dwValueForVistaSize, &dwBytesWritten, 0);
		if(pNode->pbyValueForWindows7)WriteFile(hFile, pNode->pbyValueForWindows7, pNode->dwValueForWindows7Size, &dwBytesWritten, 0);
		if(pNode->szKeyPart)WriteFile(hFile, pNode->szKeyPart, dwKeyPartSize, &dwBytesWritten, 0);
		if(pNode->szValuePart)WriteFile(hFile, pNode->szValuePart, dwValuePartSize, &dwBytesWritten, 0);
	}

	if(bSaveError)
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		AddLogEntry(L"Error in saving: %s.File Deleted", szFullFileName);
		return (false);
	}

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_REGFIX) + sizeof(HEADER_REGFIX_DATA)))
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

	if(FALSE == WriteFile(hFile, HEADER_REGFIX, sizeof(HEADER_REGFIX), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!CreateHeaderData(hFile, szFileName, HEADER_REGFIX_DATA, sizeof(HEADER_REGFIX_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(FALSE == WriteFile(hFile, HEADER_REGFIX_DATA, sizeof(HEADER_REGFIX_DATA), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	CloseHandle(hFile);
	return (true);
}
