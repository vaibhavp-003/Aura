
/*======================================================================================
FILE             : U2OS2U.cpp
ABSTRACT         : 2 level tree class for handling database type ulong -> string -> ulong
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
#include "U2OS2U.h"

BYTE HEADER_U2OS2U[24]		= {"MAXDBVERSION00.00.00.08"};
BYTE HEADER_U2OS2U_DATA[24]	= {0};

/*--------------------------------------------------------------------------------------
Function       : CU2OS2U
In Parameters  : bool bIsEmbedded, 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CU2OS2U::CU2OS2U(bool bIsEmbedded): CBalBST(bIsEmbedded)
{
	m_bLoadError = false;
	m_bSaveError = false;
}

/*--------------------------------------------------------------------------------------
Function       : ~CU2OS2U
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CU2OS2U::~CU2OS2U()
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
COMPARE_RESULT CU2OS2U::Compare(ULONG64 dwKey1, ULONG64 dwKey2)
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
void CU2OS2U::FreeKey(ULONG64 dwKey)
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
void CU2OS2U::FreeData(ULONG64 dwData)
{
	CS2U objS2U(false);
	objS2U.SetDataPtr((PNODE)dwData, m_pBuffer, m_nBufferSize);
	objS2U.RemoveAll ();
	return;
}

/*--------------------------------------------------------------------------------------
Function       : AppendItemAscOrder
In Parameters  : DWORD dwKey, CS2U * pObjS2U, 
Out Parameters : bool 
Description    : add node in tree in ascending order in right vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::AppendItemAscOrder(DWORD dwKey, CS2U * pObjS2U)
{
	if(!AddNodeAscOrder(dwKey,(ULONG64)pObjS2U->GetDataPtr()))
	{
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendItem
In Parameters  : DWORD dwKey, CS2U * pObjS2U, 
Out Parameters : bool 
Description    : add node in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::AppendItem(DWORD dwKey, CS2U * pObjS2U)
{
	if(!AddNode(dwKey,(ULONG64)pObjS2U->GetDataPtr()))
	{
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
bool CU2OS2U::DeleteItem(DWORD dwKey)
{
	return (DeleteNode(dwKey));
}

/*--------------------------------------------------------------------------------------
Function       : SearchItem
In Parameters  : DWORD dwKey, CS2U& objS2U, 
Out Parameters : bool 
Description    : search a key in tree and return data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::SearchItem(DWORD dwKey, CS2U& objS2U)
{
	ULONG64 dwData = 0;

	if(!FindNode(dwKey, dwData))
	{
		return (false);
	}

	objS2U.SetDataPtr((PNODE)dwData, m_pBuffer, m_nBufferSize);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : UpdateItem
In Parameters  : DWORD dwKey, CS2U& objS2U, 
Out Parameters : bool 
Description    : overwrite the data of the given key
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::UpdateItem(DWORD dwKey, CS2U& objS2U)
{
	if(!m_pLastSearchResult || m_pLastSearchResult->dwKey !=(ULONG64)dwKey)
	{
		ULONG64 dwData = 0;

		if(!FindNode((ULONG64)dwKey, dwData))
		{
			return (false);
		}

		if(!m_pLastSearchResult || m_pLastSearchResult->dwKey !=(ULONG64)dwKey)
		{
			return (false);
		}
	}

	m_pLastSearchResult->dwData =(ULONG64)objS2U.GetDataPtr();
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetKey
In Parameters  : PVOID pVPtr, DWORD& dwKey, 
Out Parameters : bool 
Description    : get key by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::GetKey(PVOID pVPtr, DWORD& dwKey)
{
	dwKey =(DWORD)((PNODE)pVPtr) -> dwKey;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetData
In Parameters  : PVOID pVPtr, CS2U& objS2U, 
Out Parameters : bool 
Description    : get data by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::GetData(PVOID pVPtr, CS2U& objS2U)
{
	objS2U.SetDataPtr((PNODE)(((PNODE)pVPtr) -> dwData), m_pBuffer, m_nBufferSize);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : CopyContents
In Parameters  : CU2OS2U& objNewCopy
Out Parameters : bool 
Description    : make a new copy of this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::CopyContents(CU2OS2U& objNewCopy)
{
	LPVOID lpContext = NULL;
	DWORD dwKey = 0;
	CS2U objData(true), objNewData(true);

	lpContext = GetFirst();
	while(lpContext)
	{
		dwKey = 0;
		objData.RemoveAll();

		GetKey(lpContext, dwKey);
		GetData(lpContext, objData);

		if(objData.GetFirst())
		{
			objNewData.RemoveAll();
			if(objData.CopyContents(objNewData))
			{
				objNewCopy.AppendItem(dwKey, &objNewData);
			}
		}

		lpContext = GetNext(lpContext);
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Balance
In Parameters  : 
Out Parameters : bool 
Description    : balance all level trees
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::Balance()
{
	LPVOID Position = NULL;

	CBalBST::Balance();

	Position = GetFirst();
	while(Position)
	{
		CS2U objS2U(true);
		GetData(Position, objS2U);
		objS2U.Balance();
		((PNODE)Position) -> dwData =(ULONG64)objS2U.GetDataPtr();
		Position = GetNext(Position);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : ReadS2U
In Parameters  : ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize, 
Out Parameters : bool 
Description    : read s2u node from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::ReadS2U(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize)
{
	DWORD dwBytesProcessed = 0;
	DWORD dwDataSize = 0;
	TCHAR * pString = 0;

	dwDataSize =(DWORD)*pCurrentPtr;
	pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + 4);
	dwBytesProcessed += 4;

	while(dwBytesProcessed < dwDataSize)
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

		pCurrentPtr =(ULONG64*)pString;
	}

	return (true);

ERROR_EXIT:

	m_bLoadError = true;
	return (false);
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, 
Out Parameters : bool 
Description    : load tree object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	ULONG64 * pCurrentPtr = 0;
	ULONG64 dwBaseAddress = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwFileSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	DWORD dwEmbeddedDataSize = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_U2OS2U)] ={0};
	TCHAR szFullFileName[MAX_PATH]={0};
	BYTE byHeaderDataFromFile[sizeof(HEADER_U2OS2U_DATA)] ={0};
	BYTE byHeaderDataCalculated[sizeof(HEADER_U2OS2U_DATA)] ={0};

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

	if(bCheckVersion && memcmp(HEADER_U2OS2U, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
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
	if(dwFileSize <= sizeof(HEADER_U2OS2U) + sizeof(HEADER_U2OS2U_DATA))
	{
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(HEADER_U2OS2U) + sizeof(HEADER_U2OS2U_DATA);
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
	dwBaseAddress -= sizeof(VERSION_FROM_FILE) + sizeof(HEADER_U2OS2U_DATA);
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

		dwEmbeddedDataSize =(DWORD)*pCurrentPtr;

		ReadS2U(pCurrentPtr, dwBaseAddress, dwFileSize);
		if(m_bLoadError)goto ERROR_EXIT;

		dwBytesProcessed += dwEmbeddedDataSize;
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

bool CU2OS2U::Load_NoNameCheck(LPCTSTR szFileName, bool bCheckVersion)
{
	ULONG64 * pCurrentPtr = 0;
	ULONG64 dwBaseAddress = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwFileSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	DWORD dwEmbeddedDataSize = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_U2OS2U)] ={0};
	TCHAR szFullFileName[MAX_PATH]={0};
	BYTE byHeaderDataFromFile[sizeof(HEADER_U2OS2U_DATA)] ={0};
	BYTE byHeaderDataCalculated[sizeof(HEADER_U2OS2U_DATA)] ={0};

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

	if(bCheckVersion && memcmp(HEADER_U2OS2U, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
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

	m_pTemp = m_pRoot = NULL;
	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(HEADER_U2OS2U) + sizeof(HEADER_U2OS2U_DATA))
	{
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(HEADER_U2OS2U) + sizeof(HEADER_U2OS2U_DATA);
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
	dwBaseAddress -= sizeof(VERSION_FROM_FILE) + sizeof(HEADER_U2OS2U_DATA);
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

		dwEmbeddedDataSize =(DWORD)*pCurrentPtr;

		ReadS2U(pCurrentPtr, dwBaseAddress, dwFileSize);
		if(m_bLoadError)goto ERROR_EXIT;

		dwBytesProcessed += dwEmbeddedDataSize;
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
Function       : DumpS2U
In Parameters  : HANDLE hFile, ULONG64 dwData, 
Out Parameters : bool 
Description    : write s2u node to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::DumpS2U(HANDLE hFile, ULONG64 dwData)
{
	ULONG64		dwCurrentOffset = 0;
	ULONG64 dwLinkOffset = 0;
	DWORD dwNodeOffset = 0;
	DWORD dwBytesWritten = 0;
	DWORD dwTotalBytesWritten = 0;
	DWORD dwTotalBytesOffset = 0;
	NODE * pNode =(NODE *)dwData;

	dwTotalBytesOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	WriteFile(hFile, &dwTotalBytesWritten, 4, &dwBytesWritten, 0);
	dwTotalBytesWritten += dwBytesWritten;

	while(pNode)
	{
		dwNodeOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
		dwLinkOffset = dwNodeOffset + sizeof(NODE);
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		if(!WriteFile(hFile, ((BYTE*)pNode) + SIZE_OF_ONE_NODE_ELEMENT, SIZE_OF_ONE_NODE_ELEMENT * 4, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		dwLinkOffset = pNode->pParent ? pNode->pParent->dwHold : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		dwLinkOffset =(_tcslen((TCHAR*)(pNode->dwKey)) + 1)* sizeof(TCHAR);
		if(!WriteFile(hFile, (BYTE*)(pNode->dwKey),(DWORD)dwLinkOffset, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		pNode->dwHold = dwNodeOffset;
		dwLinkOffset = 0;

		if(pNode->pLeft)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 3);
			pNode = pNode->pLeft;
		}
		else if(pNode->pRight)
		{
			dwLinkOffset = dwNodeOffset +(SIZE_OF_ONE_NODE_ELEMENT * 4);
			pNode = pNode->pRight;
		}
		else
		{
			while(pNode)
			{
				if(NULL == pNode->pParent)
				{
					pNode = NULL;
				}
				else if(pNode == pNode->pParent->pRight)
				{
					pNode = pNode->pParent;
				}
				else if(pNode->pParent->pRight)
				{
					dwLinkOffset = pNode->pParent->dwHold +(SIZE_OF_ONE_NODE_ELEMENT * 4);
					pNode = pNode->pParent->pRight;
					break;
				}
				else
				{
					pNode = pNode->pParent;
				}
			}
		}

		if(dwLinkOffset)
		{
			dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
			SetFilePointer(hFile,(DWORD)dwLinkOffset, 0, FILE_BEGIN);
			if(!WriteFile(hFile, &dwCurrentOffset, sizeof(dwCurrentOffset), &dwBytesWritten, 0))
			{
				m_bLoadError = true;
				break;
			}

			SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
		}
	}

	if(m_bLoadError)
	{
		return (false);
	}

	dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	SetFilePointer(hFile, dwTotalBytesOffset, 0, FILE_BEGIN);
	if(!WriteFile(hFile, &dwTotalBytesWritten, sizeof(dwTotalBytesWritten), &dwBytesWritten, 0))
	{
		m_bLoadError = true;
		return (false);
	}

	SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Save
In Parameters  : LPCTSTR szFileName, bool bEncryptContents, 
Out Parameters : bool 
Description    : save tree object to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OS2U::Save(LPCTSTR szFileName, bool bEncryptContents)
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

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(HEADER_U2OS2U) + sizeof(HEADER_U2OS2U_DATA), 0, FILE_BEGIN))
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
		dwLinkOffset = dwNodeOffset + sizeof(NODE) + 4;
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

		DumpS2U(hFile, m_pTemp->dwData);
		if(m_bSaveError)
		{
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

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_U2OS2U) + sizeof(HEADER_U2OS2U_DATA)))
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

	if(FALSE == WriteFile(hFile, HEADER_U2OS2U, sizeof(HEADER_U2OS2U), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_U2OS2U_DATA, sizeof(HEADER_U2OS2U_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(FALSE == WriteFile(hFile, HEADER_U2OS2U_DATA, sizeof(HEADER_U2OS2U_DATA), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	CloseHandle(hFile);
	return (true);
}
