
/*======================================================================================
FILE             : BufferToStructure.cpp
ABSTRACT         : class declaration for 1 level binary tree of buffer -> structure
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
#include "BufferToStructure.h"
										  //00.00	this is sent by client(user of the class)
BYTE HEADER_BUF2ST[24]		= {"MAXDBVERSION00.00.00.10"};
BYTE HEADER_BUF2ST_DATA[24]	= {0};

/*--------------------------------------------------------------------------------------
Function       : CBufferToStructure
In Parameters  :  bool bIsEmbedded, DWORD dwSizeOfKey, DWORD dwSizeOfData,
Out Parameters : CBufferToStructure
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CBufferToStructure::CBufferToStructure(bool bIsEmbedded, DWORD dwSizeOfKey, DWORD dwSizeOfData,int iNumberSize)
									   :CBalBSTOpt(bIsEmbedded)
{
	m_dwSizeOfKey = dwSizeOfKey;
	m_dwSizeOfData = dwSizeOfData;
	m_bLoadError = false;
	m_bSaveError = false;
	m_bCheckName = true;
	m_bByte = sizeof(BYTE) == iNumberSize;
	m_bWord = sizeof(WORD) == iNumberSize;
	m_bDword = sizeof(DWORD) == iNumberSize;
	m_bQword = sizeof(ULONG64) == iNumberSize;
	memset(m_szVersion, 0, sizeof(m_szVersion));
}

/*--------------------------------------------------------------------------------------
Function       : ~CBufferToStructure
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CBufferToStructure::~CBufferToStructure()
{
	RemoveAll();
}

/*--------------------------------------------------------------------------------------
Function       : Compare
In Parameters  : SIZE_T nKey1, SIZE_T nKey2, 
Out Parameters : COMPARE_RESULT 
Description    : compare two key and return small, large or equal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
COMPARE_RESULT CBufferToStructure::Compare(SIZE_T nKey1, SIZE_T nKey2)
{
	if(m_bByte)
	{
		LPBYTE pbyKey1 = (LPBYTE)nKey1;
		LPBYTE pbyKey2 = (LPBYTE)nKey2;

		return *pbyKey1 < *pbyKey2 ? SMALL : *pbyKey1 > *pbyKey2 ? LARGE : EQUAL;
	}
	else if(m_bWord)
	{
		LPWORD pwKey1 = (LPWORD)nKey1;
		LPWORD pwKey2 = (LPWORD)nKey2;

		return *pwKey1 < *pwKey2 ? SMALL : *pwKey1 > *pwKey2 ? LARGE : EQUAL;
	}
	else if(m_bDword)
	{
		LPDWORD pdwKey1 = (LPDWORD)nKey1;
		LPDWORD pdwKey2 = (LPDWORD)nKey2;

		return *pdwKey1 < *pdwKey2 ? SMALL : *pdwKey1 > *pdwKey2 ? LARGE : EQUAL;
	}
	else if(m_bQword)
	{
		PULONG64 pqwKey1 = (PULONG64)nKey1;
		PULONG64 pqwKey2 = (PULONG64)nKey2;

		return *pqwKey1 < *pqwKey2 ? SMALL : *pqwKey1 > *pqwKey2 ? LARGE : EQUAL;
	}
	else
	{
		LPBYTE pbyKey1 =(LPBYTE)nKey1;
		LPBYTE pbyKey2 =(LPBYTE)nKey2;

		for(DWORD i = 0; i < m_dwSizeOfKey; i++)
		{
			if(pbyKey1[i]< pbyKey2[i])
			{
				return SMALL;
			}
			else if(pbyKey1[i]> pbyKey2[i])
			{
				return LARGE;
			}
		}

		return EQUAL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : FreeKey
In Parameters  : SIZE_T nKey
Out Parameters : void 
Description    : release key memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CBufferToStructure::FreeKey(SIZE_T nKey)
{
	if(((LPBYTE)nKey < m_pBuffer) ||((LPBYTE)nKey >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)nKey);
	}
}

/*--------------------------------------------------------------------------------------
Function       : FreeData
In Parameters  : SIZE_T nData
Out Parameters : void 
Description    : release data memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CBufferToStructure::FreeData(SIZE_T nData)
{
	if(((LPBYTE)nData < m_pBuffer) ||((LPBYTE)nData >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)nData);
	}
}

/*--------------------------------------------------------------------------------------
Function       : AppendItemAscOrder
In Parameters  : LPVOID lpvKey, LPVOID lpvData, 
Out Parameters : bool 
Description    : add node in tree in ascending order in right vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::AppendItemAscOrder(LPVOID lpvKey, LPVOID lpvData)
{
	LPBYTE pbyKeyDup = 0;
	LPBYTE pbyDataDup = 0;

	pbyKeyDup = DuplicateBuffer((LPBYTE)lpvKey, m_dwSizeOfKey);
	if(NULL == pbyKeyDup)
	{
		return (false);
	}

	pbyDataDup = DuplicateBuffer((LPBYTE)lpvData, m_dwSizeOfData);
	if(NULL == pbyDataDup)
	{
		Release((LPVOID&)pbyDataDup);
		return (false);
	}

	if(!AddNodeAscOrder((SIZE_T)pbyKeyDup,(SIZE_T)pbyDataDup))
	{
		Release((LPVOID&)pbyKeyDup);
		Release((LPVOID&)pbyDataDup);
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendItem
In Parameters  : LPVOID lpvKey, LPVOID lpvData, 
Out Parameters : bool 
Description    : add node in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::AppendItem(LPVOID lpvKey, LPVOID lpvData)
{
	LPBYTE pbyKeyDup = 0;
	LPBYTE pbyDataDup = 0;

	pbyKeyDup = DuplicateBuffer((LPBYTE)lpvKey, m_dwSizeOfKey);
	if(NULL == pbyKeyDup)
	{
		return (false);
	}

	pbyDataDup = DuplicateBuffer((LPBYTE)lpvData, m_dwSizeOfData);
	if(NULL == pbyDataDup)
	{
		Release((LPVOID&)pbyDataDup);
		return (false);
	}

	if(!AddNode((SIZE_T)pbyKeyDup,(SIZE_T)pbyDataDup))
	{
		Release((LPVOID&)pbyKeyDup);
		Release((LPVOID&)pbyDataDup);
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : DeleteItem
In Parameters  : LPVOID lpvKey, 
Out Parameters : bool 
Description    : delete item from tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::DeleteItem(LPVOID lpvKey)
{
	return (DeleteNode((SIZE_T)lpvKey));
}

/*--------------------------------------------------------------------------------------
Function       : SearchItem
In Parameters  : LPVOID lpvKey, LPVOID& lpvData, 
Out Parameters : bool 
Description    : search a key in tree and return data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::SearchItem(LPVOID lpvKey, LPVOID& lpvData)
{
	SIZE_T nData = 0;

	if(!FindNode((SIZE_T)lpvKey, nData))
	{
		return (false);
	}

	lpvData = (LPVOID)nData;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetKey
In Parameters  : PVOID pVPtr, LPVOID& lpvKey, 
Out Parameters : bool 
Description    : get key by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::GetKey(PVOID pVPtr, LPVOID& lpvKey)
{
	if(!pVPtr)
	{
		return (false);
	}

	lpvKey =(LPVOID&)(((PNODEOPT)pVPtr) -> nKey);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetData
In Parameters  : PVOID pVPtr, LPVOID& lpvData, 
Out Parameters : bool 
Description    : get data by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::GetData(PVOID pVPtr, LPVOID& lpvData)
{
	if(!pVPtr)
	{
		return (false);
	}

	lpvData = (LPVOID&)(((PNODEOPT)pVPtr)->nData);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : UpdateItem
In Parameters  : LPVOID lpvKey, LPVOID lpvData, 
Out Parameters : bool 
Description    : overwrite the data of the given key
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::UpdateItem(LPVOID lpvKey, LPVOID lpvData)
{
	if(!m_pLastSearchResult || memcmp((LPVOID)m_pLastSearchResult->nKey, lpvKey, m_dwSizeOfKey))
	{
		LPVOID lpvTemp = NULL;

		if(!SearchItem(lpvKey, lpvTemp))
		{
			return (false);
		}
	}

	m_bIsModified = true;
	memcpy((LPVOID)(m_pLastSearchResult->nData), lpvData, m_dwSizeOfData);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : CreateObject
In Parameters  : CBufferToStructure& objNewObject, 
Out Parameters : bool 
Description    : make a new copy of this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::CreateObject(CBufferToStructure& objNewObject)
{
	LPBYTE lpKey = NULL;
	LPBYTE lpData = NULL;
	LPVOID lpContext = NULL;

	lpContext = GetFirst();
	while(lpContext)
	{
		lpKey = NULL;
		lpData = NULL;

		GetKey(lpContext,(LPVOID&)lpKey);
		GetData(lpContext,(LPVOID&)lpData);

		if(lpKey && lpData)
		{
			objNewObject.AppendItem(lpKey, lpData);
		}

		lpContext = GetNext(lpContext);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendObject
In Parameters  : CBalBST& objToAdd, 
Out Parameters : bool 
Description    : merge an object to this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::AppendObject(CBalBSTOpt& objToAdd)
{
	LPVOID lpContext = NULL, lpKey = NULL, lpData = NULL;
	CBufferToStructure& _objToAdd = (CBufferToStructure&)objToAdd;

	lpContext = _objToAdd.GetFirst();
	while(lpContext)
	{
		_objToAdd.GetKey(lpContext, lpKey);
		_objToAdd.GetData(lpContext, lpData);

		if(lpKey && lpData)
		{
			if(AppendItem(lpKey, lpData))
			{
				SetModified();
			}
		}

		lpContext = _objToAdd.GetNext(lpContext);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : DeleteObject
In Parameters  : CBalBST& objToDel, 
Out Parameters : bool 
Description    : delete an object from this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::DeleteObject(CBalBSTOpt& objToDel)
{
	LPVOID lpContext = NULL, lpKey = NULL;
	CBufferToStructure& _objToDel = (CBufferToStructure&)objToDel;

	lpContext = _objToDel.GetFirst();
	while(lpContext)
	{
		_objToDel.GetKey(lpContext, lpKey);

		if(lpKey)
		{
			if(DeleteItem(lpKey))
			{
				SetModified();
			}
		}

		lpContext = _objToDel.GetNext(lpContext);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : SearchObject
In Parameters  : CBalBSTOpt& objToSearch, bool bAllPresent
Out Parameters : bool 
Description    : search all the entries from 'objToSearch'
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent)
{
	bool bSuccess = true, bFound = false;
	LPVOID lpContext = NULL;
	LPVOID lpKey = NULL, lpData = NULL;
	CBufferToStructure& objToSearchDup = (CBufferToStructure&)objToSearch;

	lpContext = objToSearchDup.GetFirst();
	while(lpContext)
	{
		objToSearchDup.GetKey(lpContext, (LPVOID&)lpKey);
		if(lpKey)
		{
			bFound = SearchItem(lpKey, lpData);
			if((bFound && !bAllPresent) || (!bFound && bAllPresent))
			{
				bSuccess = false;
				break;
			}
		}

		lpContext = objToSearchDup.GetNext(lpContext);
	}

	return bSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : ReadB2St
In Parameters  : LPBYTE& ptrData, PSIZE_T& ptrNode, DWORD dwKeyLen, DWORD dwDataLen, 
Out Parameters : bool 
Description    : read b2st node from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::ReadB2St(LPBYTE& ptrData, PSIZE_T& ptrNode, LPBYTE byBuffer, DWORD cbBuffer)
{
	PNODEOPT ptrNext = NULL;
	DWORD dwNodesCount = 0;
	BOOL bAllowNull = FALSE;

	VALIDATE_POINTER(ptrData,byBuffer,cbBuffer);
	dwNodesCount = *((LPDWORD)ptrData);
	ptrData += sizeof(dwNodesCount);

	for(DWORD i = 0; i < dwNodesCount; i++)
	{
		if(i + 1 < dwNodesCount)
		{
			ptrNext = (PNODEOPT)(((LPBYTE)ptrNode) + SIZE_OF_NODEOPT);
			bAllowNull = FALSE;
		}
		else
		{
			ptrNext = NULL;
			bAllowNull = TRUE;
		}

		CHECK_AND_MAKE_POINTER2(ptrNode, ptrData, byBuffer, cbBuffer, FALSE);
		ptrData += m_dwSizeOfKey;
		ptrNode++;

		CHECK_AND_MAKE_POINTER2(ptrNode, ptrData, byBuffer, cbBuffer, FALSE);
		ptrData += m_dwSizeOfData;
		ptrNode++;

		CHECK_AND_MAKE_POINTER2(ptrNode, NULL, byBuffer, cbBuffer, TRUE);
		ptrNode++;

		CHECK_AND_MAKE_POINTER2(ptrNode, ptrNext, byBuffer, cbBuffer, bAllowNull);
		ptrNode++;
	}

	return true;

ERROR_EXIT:
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, bool bCheckVersion
Out Parameters : bool 
Description    : load tree object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	HANDLE hFile = 0;
	LPBYTE ptrData = NULL;
	PSIZE_T ptrNode = NULL;
	DWORD dwFileSize = 0, dwBytesRead = 0;
	TCHAR szFullFileName[MAX_PATH]={0};
	ULONG64 ulTotalNodesCount = 0;
	BYTE byHdrBfr[sizeof(HEADER_BUF2ST) + sizeof(HEADER_BUF2ST_DATA)] = {0};
	BYTE byHeader[sizeof(HEADER_BUF2ST)] = {0};

	memcpy(byHeader, HEADER_BUF2ST, sizeof(HEADER_BUF2ST));
	m_pBuffer = NULL;

	if(false == MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return false;
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	if(FALSE == ReadFile(hFile, byHdrBfr, sizeof(byHdrBfr), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(m_szVersion[0])
	{
		memcpy(byHeader + 5, m_szVersion, 18);
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_BUF2ST_DATA, sizeof(HEADER_BUF2ST_DATA)))
	{
		goto ERROR_EXIT;
	}

	if(bCheckVersion && memcmp(byHeader, byHdrBfr, sizeof(byHeader)))
	{
		goto ERROR_EXIT;
	}

	if(m_bCheckName && memcmp(byHdrBfr + sizeof(byHeader), HEADER_BUF2ST_DATA, 8 + 8))
	{
		goto ERROR_EXIT;
	}

	memcpy(&ulTotalNodesCount, byHdrBfr + sizeof(byHeader) + 8 + 8, sizeof(ulTotalNodesCount));

	if(0 == ulTotalNodesCount)
	{
		CloseHandle(hFile); hFile = NULL;
		return true;
	}

	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(byHdrBfr))
	{
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(byHdrBfr);
	m_nBufferSize = dwFileSize + (((DWORD)ulTotalNodesCount)* SIZE_OF_NODEOPT);

	m_pBuffer = (LPBYTE)VAllocate(m_nBufferSize);
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

	CloseHandle(hFile); hFile = NULL;

	if(false == CryptBuffer(m_pBuffer, dwFileSize))
	{
		goto ERROR_EXIT;
	}

	ptrData = m_pBuffer;
	ptrNode = (PSIZE_T)(m_pBuffer + dwFileSize);
	m_pRoot = (PNODEOPT)ptrNode;

	if(false == ReadB2St(ptrData, ptrNode, m_pBuffer, m_nBufferSize))
	{
		goto ERROR_EXIT;
	}

	if(false == Balance())
	{
		goto ERROR_EXIT;
	}

	//VChangeProtection(m_pBuffer, m_nBufferSize, TRUE);
	m_bLoadedFromFile = true;
	return (true);

ERROR_EXIT:

	if(hFile != INVALID_HANDLE_VALUE && hFile != NULL)
	{
		CloseHandle(hFile);
	}

	if(m_pBuffer)
	{
		VRelease(m_pBuffer);
		m_pBuffer = NULL;
	}

	m_pRoot = m_pTemp = NULL;
	m_bLoadedFromFile = false;
	m_nBufferSize = 0;
	//DeleteFile(szFullFileName);
	AddLogEntry(L"Error loading file: %s.File deleted", szFullFileName);
	return (false);
}

/*--------------------------------------------------------------------------------------
Function       : Load_NoNameCheck
In Parameters  : LPCTSTR szFileName, bool bCheckVersion
Out Parameters : bool 
Description    : load tree object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::Load_NoNameCheck(LPCTSTR szFileName, bool bCheckVersion)
{
	m_bCheckName = false;
	return Load(szFileName, bCheckVersion);
}

/*--------------------------------------------------------------------------------------
Function       : DumpB2St
In Parameters  : HANDLE hFile, NODE * pNode, DWORD& dwNodesCount, DWORD dwKeyLen, 
					DWORD dwDataLen, 
Out Parameters : bool 
Description    : write b2st node to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::DumpB2St(HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount, 
								  DWORD dwKeyLen, DWORD dwDataLen)
{
	bool bWriteError = false;
	CPtrStack objPtrStack;
	DWORD dwNodesCountOffset = 0, dwCurrentOffset = 0, dwBytesWritten = 0;

	dwNodesCountOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	if(INVALID_SET_FILE_POINTER == dwNodesCountOffset)
	{
		return (false);
	}

	if(!WriteFile(hFile, &dwNodesCount, sizeof(dwNodesCount), &dwBytesWritten, 0))
	{
		return (false);
	}

	m_pTemp = pNode;
	while(NULL != m_pTemp || !objPtrStack.IsEmpty())
	{
		if(m_pTemp)
		{
			objPtrStack.Push(m_pTemp);
			m_pTemp = m_pTemp->pLeft;
		}
		else
		{
			m_pTemp = (PNODEOPT)objPtrStack.Pop();

			dwNodesCount++;
			if(FALSE == WriteFile(hFile,(LPVOID)m_pTemp->nKey, dwKeyLen, &dwBytesWritten, 0))
			{
				bWriteError = true;
				break;
			}

			if(FALSE == WriteFile(hFile,(LPVOID)m_pTemp->nData, dwDataLen, &dwBytesWritten, 0))
			{
				bWriteError = true;
				break;
			}

			m_pTemp = m_pTemp->pRight;
		}
	}

	if(bWriteError)
	{
		return (false);
	}

	dwCurrentOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	if(INVALID_SET_FILE_POINTER == dwCurrentOffset)
	{
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwNodesCountOffset, 0, FILE_BEGIN))
	{
		return (false);
	}

	if(!WriteFile(hFile, &dwNodesCount, sizeof(dwNodesCount), &dwBytesWritten, 0))
	{
		return (false);
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwCurrentOffset, 0, FILE_BEGIN))
	{
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Save
In Parameters  : LPCTSTR szFileName, bool bEncryptContents, 
Out Parameters : bool 
Description    : save tree object to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBufferToStructure::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	HANDLE hFile = 0;
	ULONG64 ulCount = 0;
	DWORD dwBytesWritten = 0, dwNodesCount = 0;
	BYTE byHdrBfr[sizeof(HEADER_BUF2ST) + sizeof(HEADER_BUF2ST_DATA)] = {0};
	BYTE byHdr[sizeof(HEADER_BUF2ST)] = {0};

	//AddLogEntry(L"CBufferToStructure::Save(Saving file): %s.", szFileName);

	memcpy(byHdr, HEADER_BUF2ST, sizeof(HEADER_BUF2ST));
	hFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		//AddLogEntry(L"CBufferToStructure::Save(INVALID_HANDLE_VALUE == hFile): %s.", szFileName);
		return false;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(byHdrBfr), 0, FILE_BEGIN))
	{
		//AddLogEntry(L"CBufferToStructure::Save(INVALID_SET_FILE_POINTER == SetFilePointer(1)): %s.", szFileName);
		goto ERROR_EXIT;
	}

	if(!DumpB2St(hFile, m_pRoot, dwNodesCount, m_dwSizeOfKey, m_dwSizeOfData))
	{
		//AddLogEntry(L"CBufferToStructure::Save(!DumpB2St): %s.", szFileName);
		goto ERROR_EXIT;
	}

	ulCount = dwNodesCount;
	if(bEncryptContents && !CryptFileData(hFile, sizeof(byHdrBfr)))
	{
		//AddLogEntry(L"CBufferToStructure::Save(bEncryptContents && !CryptFileData): %s.", szFileName);
		goto ERROR_EXIT;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0, 0, FILE_BEGIN))
	{
		//AddLogEntry(L"CBufferToStructure::Save(INVALID_SET_FILE_POINTER == SetFilePointer(2)): %s.", szFileName);
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFileName, HEADER_BUF2ST_DATA, sizeof(HEADER_BUF2ST_DATA), ulCount))
	{
		//AddLogEntry(L"CBufferToStructure::Save(!CreateHeaderData): %s.", szFileName);
		goto ERROR_EXIT;
	}

	if(m_szVersion[0])
	{
		memcpy(byHdr + 5, m_szVersion, 18);
	}

	memcpy(byHdrBfr, byHdr, sizeof(byHdr));
	memcpy(byHdrBfr + sizeof(byHdr), HEADER_BUF2ST_DATA, sizeof(HEADER_BUF2ST_DATA));

	if(!WriteFile(hFile, byHdrBfr, sizeof(byHdrBfr), &dwBytesWritten, 0))
	{
		//AddLogEntry(L"CBufferToStructure::Save(!WriteFile): %s.", szFileName);
		goto ERROR_EXIT;
	}

	CloseHandle(hFile);

	//AddLogEntry(L"CBufferToStructure::Save(DONE): %s.", szFileName);
	return true;

ERROR_EXIT:

	if(INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
	}

	DeleteFile(szFileName);
	AddLogEntry(L"Error saving file: %s.File deleted.", szFileName);
	return false;
}

bool CBufferToStructure::LoadByVer(LPCTSTR szFileName, bool bCheckVersion, LPCSTR szVersion)
{
	if(strlen(szVersion) >= sizeof(m_szVersion))
	{
		return false;
	}

	strcpy_s(m_szVersion, sizeof(m_szVersion), szVersion);
	return Load(szFileName, bCheckVersion);
}

bool CBufferToStructure::SaveByVer(LPCTSTR szFileName, bool bEncryptContents, LPCSTR szVersion)
{
	if(strlen(szVersion) >= sizeof(m_szVersion))
	{
		return false;
	}

	strcpy_s(m_szVersion, sizeof(m_szVersion), szVersion);
	return Save(szFileName, bEncryptContents);
}
