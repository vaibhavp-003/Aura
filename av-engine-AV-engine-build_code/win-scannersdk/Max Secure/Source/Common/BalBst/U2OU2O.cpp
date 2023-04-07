
/*======================================================================================
FILE             : U2OU2O.cpp
ABSTRACT         : 3 level tree class for handling database type ulong -> ulong -> string -> ulong
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
#include "U2OU2O.h"

BYTE HEADER_U2OU2O[24]		= {"MAXDBVERSION00.00.00.08"};
BYTE HEADER_U2OU2O_DATA[24]	= {0};

/*--------------------------------------------------------------------------------------
Function       : CU2OU2O
In Parameters  : bool bIsEmbedded, 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CU2OU2O::CU2OU2O(bool bIsEmbedded): CBalBST(bIsEmbedded)
{
	m_bLoadError = false;
	m_bSaveError = false;
}

/*--------------------------------------------------------------------------------------
Function       : ~CU2OU2O
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CU2OU2O::~CU2OU2O()
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
COMPARE_RESULT CU2OU2O::Compare(ULONG64 dwKey1, ULONG64 dwKey2)
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
void CU2OU2O::FreeKey(ULONG64 dwKey)
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
void CU2OU2O::FreeData(ULONG64 dwData)
{
	CU2OS2U objU2OS2U(false);
	objU2OS2U.SetDataPtr((PNODE)dwData, m_pBuffer, m_nBufferSize);
	objU2OS2U.RemoveAll ();
	return;
}

/*--------------------------------------------------------------------------------------
Function       : AppendItemAscOrder
In Parameters  : DWORD dwKey, CU2OS2U * pObjU2OS2U, 
Out Parameters : bool 
Description    : add node in tree in ascending order in right vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::AppendItemAscOrder(DWORD dwKey, CU2OS2U * pObjU2OS2U)
{
	if(!AddNodeAscOrder(dwKey,(ULONG64)pObjU2OS2U->GetDataPtr()))
	{
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendItem
In Parameters  : DWORD dwKey, CU2OS2U * pObjU2OS2U, 
Out Parameters : bool 
Description    : add node in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::AppendItem(DWORD dwKey, CU2OS2U * pObjU2OS2U)
{
	if(!AddNode(dwKey,(ULONG64)pObjU2OS2U->GetDataPtr()))
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
bool CU2OU2O::DeleteItem(DWORD dwKey)
{
	return (DeleteNode(dwKey));
}

/*--------------------------------------------------------------------------------------
Function       : SearchItem
In Parameters  : DWORD dwKey, CU2OS2U& objU2OS2U, 
Out Parameters : bool 
Description    : search a key in tree and return data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::SearchItem(DWORD dwKey, CU2OS2U& objU2OS2U)
{
	ULONG64 dwData = 0;

	if(!FindNode(dwKey, dwData))
	{
		return (false);
	}

	objU2OS2U.SetDataPtr((NODE*)dwData, m_pBuffer, m_nBufferSize);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : UpdateItem
In Parameters  : DWORD dwKey, CU2OS2U& objU2OS2U, 
Out Parameters : bool 
Description    : overwrite the data of the given key
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::UpdateItem(DWORD dwKey, CU2OS2U& objU2OS2U)
{
	if(!m_pLastSearchResult || m_pLastSearchResult->dwKey !=(ULONG64)dwKey)
	{
		ULONG64 dwData = 0;

		if(!FindNode(dwKey, dwData))
		{
			return (false);
		}

		if(!m_pLastSearchResult || m_pLastSearchResult->dwKey !=(ULONG64)dwKey)
		{
			return (false);
		}
	}

	m_pLastSearchResult->dwData =(ULONG64)objU2OS2U.GetDataPtr();
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetKey
In Parameters  : PVOID pVPtr, DWORD& dwKey, 
Out Parameters : bool 
Description    : get key by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::GetKey(PVOID pVPtr, DWORD& dwKey)
{
	dwKey =(DWORD)((PNODE)pVPtr) -> dwKey;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetData
In Parameters  : PVOID pVPtr, CU2OS2U& objU2OS2U, 
Out Parameters : bool 
Description    : get data by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::GetData(PVOID pVPtr, CU2OS2U& objU2OS2U)
{
	objU2OS2U.SetDataPtr((PNODE)(((PNODE)pVPtr) -> dwData), m_pBuffer, m_nBufferSize);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Balance
In Parameters  : 
Out Parameters : bool 
Description    : balance all level trees
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::Balance()
{
	LPVOID Position = NULL;

	CBalBST::Balance();

	Position = GetFirst();
	while(Position)
	{
		CU2OS2U objU2OS2U(true);
		GetData(Position, objU2OS2U);
		objU2OS2U.Balance();
		((PNODE)Position) -> dwData =(ULONG64)objU2OS2U.GetDataPtr();
		Position = GetNext(Position);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendObject
In Parameters  : CBalBST& objAdd
Out Parameters : bool
Description    : add all the entries in the add object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::AppendObject(CBalBST& objAdd)
{
	LPTSTR lpKey3 = 0;
	DWORD dwKey1 = 0, dwKey2 = 0, dwData = 0;
	CU2OU2O& _objAdd = (CU2OU2O&)objAdd;
	LPVOID lpContext1 = NULL, lpContext2 = NULL, lpContext3 = NULL;
	CU2OS2U _objAdd1(true), objThis1(true);
	CS2U _objAdd2(true), objThis2(true);

	lpContext1 = _objAdd.GetFirst();
	while(lpContext1)
	{
		_objAdd.GetKey(lpContext1, dwKey1);
		_objAdd.GetData(lpContext1, _objAdd1);

		if(SearchItem(dwKey1, objThis1))
		{
			lpContext2 = _objAdd1.GetFirst();
			while(lpContext2)
			{
				_objAdd1.GetKey(lpContext2, dwKey2);
				_objAdd1.GetData(lpContext2, _objAdd2);

				if(objThis1.SearchItem(dwKey2, objThis2))
				{
					lpContext3 = _objAdd2.GetFirst();
					while(lpContext3)
					{
						_objAdd2.GetKey(lpContext3, lpKey3);
						_objAdd2.GetData(lpContext3, dwData);

						if(lpKey3)
						{
							if(objThis2.AppendItem(lpKey3, dwData))
							{
								SetModified();
							}
						}

						lpContext3 = _objAdd2.GetNext(lpContext3);
					}
				}
				else
				{
					if(_objAdd2.GetFirst())
					{
						objThis2.RemoveAll();
						if(_objAdd2.CopyContents(objThis2))
						{
							if(objThis1.AppendItem(dwKey2, &objThis2))
							{
								SetModified();
							}
						}
					}
				}

				lpContext2 = _objAdd1.GetNext(lpContext2);
			}
		}
		else
		{
			if(_objAdd1.GetFirst())
			{
				objThis1.RemoveAll();
				if(_objAdd1.CopyContents(objThis1))
				{
					if(AppendItem(dwKey1, &objThis1))
					{
						SetModified();
					}
				}
			}
		}

		lpContext1 = _objAdd.GetNext(lpContext1);
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : DeleteObject
In Parameters  : CBalBST& objDel
Out Parameters : bool
Description    : delete all the entries in the del object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::DeleteObject(CBalBST& objDel)
{
	LPTSTR lpKey3 = 0;
	DWORD dwKey1 = 0, dwKey2 = 0;
	CU2OU2O& _objDel = (CU2OU2O&)objDel;
	LPVOID lpContext1 = NULL, lpContext2 = NULL, lpContext3 = NULL;
	CU2OS2U _objDel1(true), objThis1(true);
	CS2U _objDel2(true), objThis2(true);

	lpContext1 = _objDel.GetFirst();
	while(lpContext1)
	{
		_objDel.GetKey(lpContext1, dwKey1);
		_objDel.GetData(lpContext1, _objDel1);

		if(SearchItem(dwKey1, objThis1))
		{
			lpContext2 = _objDel1.GetFirst();
			while(lpContext2)
			{
				_objDel1.GetKey(lpContext2, dwKey2);
				_objDel1.GetData(lpContext2, _objDel2);

				if(objThis1.SearchItem(dwKey2, objThis2))
				{
					lpContext3 = _objDel2.GetFirst();
					while(lpContext3)
					{
						_objDel2.GetKey(lpContext3, lpKey3);

						if(lpKey3)
						{
							if(objThis2.DeleteItem(lpKey3))
							{
								SetModified();
							}
						}

						lpContext3 = _objDel2.GetNext(lpContext3);
					}

					objThis1.UpdateItem(dwKey2, objThis2);
					if(!objThis2.GetFirst())
					{
						if(objThis1.DeleteItem(dwKey2))
						{
							SetModified();
						}
					}
				}

				lpContext2 = _objDel1.GetNext(lpContext2);
			}

			UpdateItem(dwKey1, objThis1);
			if(!objThis1.GetFirst())
			{
				if(DeleteItem(dwKey1))
				{
					SetModified();
				}
			}
		}

		lpContext1 = _objDel.GetNext(lpContext1);
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : SearchObject
In Parameters  : CBalBST& objSearch, bool bAllPresent
Out Parameters : bool
Description    : search all the entries in 'objSearch'
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::SearchObject(CBalBST& objSearch, bool bAllPresent)
{
	LPTSTR lpKey3 = 0;
	bool bSuccess = true, bFound = false;
	DWORD dwKey1 = 0, dwKey2 = 0, dwData = 0;
	CU2OU2O& objSearchDup = (CU2OU2O&)objSearch;
	LPVOID lpContext1 = NULL, lpContext2 = NULL, lpContext3 = NULL;
	CU2OS2U objSearch1(true), objThis1(true);
	CS2U objSearch2(true), objThis2(true);

	lpContext1 = objSearchDup.GetFirst();
	while(bSuccess && lpContext1)
	{
		objSearchDup.GetKey(lpContext1, dwKey1);
		objSearchDup.GetData(lpContext1, objSearch1);

		if(SearchItem(dwKey1, objThis1))
		{
			lpContext2 = objSearch1.GetFirst();
			while(bSuccess && lpContext2)
			{
				objSearch1.GetKey(lpContext2, dwKey2);
				objSearch1.GetData(lpContext2, objSearch2);

				if(objThis1.SearchItem(dwKey2, objThis2))
				{
					lpContext3 = objSearch2.GetFirst();
					while(bSuccess && lpContext3)
					{
						objSearch2.GetKey(lpContext3, lpKey3);

						bFound = objThis2.SearchItem(lpKey3, &dwData);
						if((bFound && !bAllPresent) || (!bFound && bAllPresent))
						{
							bSuccess = false;
						}

						lpContext3 = objSearch2.GetNext(lpContext3);
					}
				}
				else
				{
					bSuccess = bAllPresent?false:bSuccess;
				}

				lpContext2 = objSearch1.GetNext(lpContext2);
			}
		}
		else
		{
			bSuccess = bAllPresent?false:bSuccess;
		}

		lpContext1 = objSearchDup.GetNext(lpContext1);
	}

	return bSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : ReadS2U
In Parameters  : ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize
Out Parameters : bool
Description    : read s2u node from file, last level object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::ReadS2U(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize)
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

		pCurrentPtr = (ULONG64*)pString;
	}

	return (true);

ERROR_EXIT:

	m_bLoadError = true;
	return (false);
}

/*--------------------------------------------------------------------------------------
Function       : ReadU2O
In Parameters  : ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize, 
Out Parameters : bool 
Description    : read u2o node from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::ReadU2O(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize)
{
	DWORD dwEmbeddedDataSize = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwDataSize = 0;

	dwDataSize =(DWORD)*pCurrentPtr;
	pCurrentPtr =(ULONG64*)(((LPBYTE)pCurrentPtr) + 4);
	dwBytesProcessed += 4;

	while(dwBytesProcessed < dwDataSize)
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
		if(m_bLoadError)
		{
			goto ERROR_EXIT;
		}

		dwBytesProcessed += dwEmbeddedDataSize;
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
bool CU2OU2O::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	ULONG64 * pCurrentPtr = 0;
	ULONG64 dwBaseAddress = 0;
	DWORD dwBytesProcessed = 0;
	DWORD dwFileSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwBytesRead = 0;
	DWORD dwEmbeddedDataSize = 0;
	BYTE VERSION_FROM_FILE[sizeof(HEADER_U2OU2O)] ={0};
	TCHAR szFullFileName[MAX_PATH]={0};
	BYTE byHeaderDataFromFile[sizeof(HEADER_U2OU2O_DATA)] ={0};
	BYTE byHeaderDataCalculated[sizeof(HEADER_U2OU2O_DATA)] ={0};

	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		AddLogEntry(L"MakeFullFilePath failed in CU2OU2O::Load for: %s", szFileName);
		return false;
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		AddLogEntry(L"CreateFile failed in CU2OU2O::Load for: %s", szFullFileName);
		return false;
	}

	if(FALSE == ReadFile(hFile, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE), &dwBytesRead, 0))
	{
		AddLogEntry(L"ReadFile for version failed in CU2OU2O::Load for: %s", szFullFileName);
		goto ERROR_EXIT;
	}

	if(bCheckVersion && memcmp(HEADER_U2OU2O, VERSION_FROM_FILE, sizeof(VERSION_FROM_FILE)))
	{
		AddLogEntry(L"version mismatch in CU2OU2O::Load for: %s", szFullFileName);
		goto ERROR_EXIT;
	}

	if(FALSE == ReadFile(hFile, byHeaderDataFromFile, sizeof(byHeaderDataFromFile), &dwBytesRead, 0))
	{
		AddLogEntry(L"ReadFile HeaderDataFromFile failed in CU2OU2O::Load for: %s", szFullFileName);
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFullFileName, byHeaderDataCalculated, sizeof(byHeaderDataCalculated)))
	{
		AddLogEntry(L"CreateHeaderData failed in CU2OU2O::Load for: %s", szFullFileName);
		goto ERROR_EXIT;
	}

	if(memcmp(byHeaderDataFromFile, byHeaderDataCalculated, sizeof(byHeaderDataFromFile)))
	{
		AddLogEntry(L"Header mismatch in CU2OU2O::Load for: %s", szFullFileName);
		goto ERROR_EXIT;
	}

	m_pTemp = m_pRoot = NULL;
	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(HEADER_U2OU2O) + sizeof(HEADER_U2OU2O_DATA))
	{
		AddLogEntry(L"FileSize too small in CU2OU2O::Load for: %s", szFullFileName);
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(HEADER_U2OU2O) + sizeof(HEADER_U2OU2O_DATA);
	m_pBuffer = (LPBYTE)Allocate(dwFileSize);
	if(NULL == m_pBuffer)
	{
		TCHAR szStr[100] = {0};

		_stprintf_s(szStr, 100, _T("%u"), dwFileSize);
		AddLogEntry(L"memory allocation failed CU2OU2O::Load for size: %s for: %s", szStr, szFullFileName);
		goto ERROR_EXIT;
	}

	if(FALSE == ReadFile(hFile, m_pBuffer, dwFileSize, &dwBytesRead, 0))
	{
		AddLogEntry(L"ReadFile file for: %s", szFullFileName);
		goto ERROR_EXIT;
	}

	if(dwFileSize != dwBytesRead)
	{
		AddLogEntry(L"not read requested bytes for: %s", szFullFileName);
		goto ERROR_EXIT;
	}

	CloseHandle(hFile);
	hFile = NULL;
	CryptBuffer(m_pBuffer, dwFileSize);

	dwBaseAddress = (ULONG64)m_pBuffer;
	dwBaseAddress -= sizeof(VERSION_FROM_FILE) + sizeof(HEADER_U2OU2O_DATA);
	pCurrentPtr = (ULONG64*)m_pBuffer;
	m_pRoot = (NODE*)m_pBuffer;
	m_bLoadError = false;

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
	return true;

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
bool CU2OU2O::DumpS2U(HANDLE hFile, ULONG64 dwData)
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
			m_bSaveError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		if(!WriteFile(hFile, ((BYTE*)pNode) + SIZE_OF_ONE_NODE_ELEMENT, SIZE_OF_ONE_NODE_ELEMENT * 4, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		dwLinkOffset = pNode->pParent ? pNode->pParent->dwHold : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
			break;
		}

		dwTotalBytesWritten += dwBytesWritten;
		dwLinkOffset =(_tcslen((TCHAR*)(pNode->dwKey)) + 1)* sizeof(TCHAR);
		if(!WriteFile(hFile, (BYTE*)(pNode->dwKey),(DWORD)dwLinkOffset, &dwBytesWritten, 0))
		{
			m_bSaveError = true;
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
				m_bSaveError = true;
				break;
			}

			SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
		}
	}

	if(m_bSaveError)
	{
		return (false);
	}

	dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	SetFilePointer(hFile, dwTotalBytesOffset, 0, FILE_BEGIN);
	if(!WriteFile(hFile, &dwTotalBytesWritten, sizeof(dwTotalBytesWritten), &dwBytesWritten, 0))
	{
		m_bSaveError = true;
		return (false);
	}

	SetFilePointer(hFile, (DWORD)dwCurrentOffset, 0, FILE_BEGIN);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : DumpU2O
In Parameters  : HANDLE hFile, ULONG64 dwData, 
Out Parameters : bool 
Description    : write u2o node to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CU2OU2O::DumpU2O(HANDLE hFile, ULONG64 dwData)
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
		dwLinkOffset = dwNodeOffset + sizeof(NODE) + 4;
		if(!WriteFile(hFile, pNode, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		if(!WriteFile(hFile, ((BYTE*)pNode) +(SIZE_OF_ONE_NODE_ELEMENT * 2), SIZE_OF_ONE_NODE_ELEMENT * 3, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		dwLinkOffset = pNode->pParent ? pNode->pParent->dwHold : 0;
		if(!WriteFile(hFile, &dwLinkOffset, SIZE_OF_ONE_NODE_ELEMENT, &dwBytesWritten, 0))
		{
			m_bLoadError = true;
			break;
		}

		DumpS2U(hFile, pNode->dwData);
		if(m_bLoadError)
		{
			break;
		}

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
bool CU2OU2O::Save(LPCTSTR szFileName, bool bEncryptContents)
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

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(HEADER_U2OU2O) + sizeof(HEADER_U2OU2O_DATA), 0, FILE_BEGIN))
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

		if(!WriteFile(hFile, ((BYTE*)m_pTemp) +(SIZE_OF_ONE_NODE_ELEMENT * 2), 
						SIZE_OF_ONE_NODE_ELEMENT * 3, &dwBytesWritten, 0))
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

		DumpU2O(hFile, m_pTemp->dwData);
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

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_U2OU2O) + sizeof(HEADER_U2OU2O_DATA)))
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

	if(!WriteFile(hFile, HEADER_U2OU2O, sizeof(HEADER_U2OU2O), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_U2OU2O_DATA, sizeof(HEADER_U2OU2O_DATA)))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	if(!WriteFile(hFile, HEADER_U2OU2O_DATA, sizeof(HEADER_U2OU2O_DATA), &dwBytesWritten, 0))
	{
		CloseHandle(hFile);
		DeleteFile(szFullFileName);
		return (false);
	}

	CloseHandle(hFile);
	return (true);
}
