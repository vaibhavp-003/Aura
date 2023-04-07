
/*======================================================================================
FILE             : BBSt.cpp
ABSTRACT         : class declaration for 2 level binary tree of buffer -> buffer -> structure
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
#include "BBSt.h"

BYTE HEADER_BBST[24]			= {"MAXDBVERSION00.00.00.08"};
BYTE HEADER_BBST_DATA[24]		= {0};

/*--------------------------------------------------------------------------------------
Function       : CBBSt
In Parameters  : bool bIsEmbedded, DWORD dwSizeOfKey, DWORD dwSizeOfEmbeddedKey,
					DWORD dwSizeOfEmbeddedData, bool bLoadReadOnly
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CBBSt::CBBSt(bool bIsEmbedded, DWORD dwSizeOfKey, DWORD dwSizeOfEmbeddedKey, DWORD dwSizeOfEmbeddedData, bool bLoadReadOnly):
				CBalBSTOpt(bIsEmbedded)
{
	m_dwSizeOfKey = dwSizeOfKey;
	m_dwSizeOfEmbeddedKey = dwSizeOfEmbeddedKey;
	m_dwSizeOfEmbeddedData = dwSizeOfEmbeddedData;
	m_bLoadError = false;
	m_bSaveError = false;
	m_bLoadReadOnly = bLoadReadOnly;
}

/*--------------------------------------------------------------------------------------
Function       : ~CBBSt
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CBBSt::~CBBSt()
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
COMPARE_RESULT CBBSt::Compare(SIZE_T nKey1, SIZE_T nKey2)
{
	LPBYTE pbyKey1 =(LPBYTE)nKey1;
	LPBYTE pbyKey2 =(LPBYTE)nKey2;

	for(DWORD i = 0; i < m_dwSizeOfKey; i++)
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
In Parameters  : SIZE_T nKey, 
Out Parameters : void 
Description    : release key memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CBBSt::FreeKey(SIZE_T nKey)
{
	if(((LPBYTE)nKey < m_pBuffer) ||((LPBYTE)nKey >= m_pBuffer + m_nBufferSize))
	{
		m_bIsModified = true;
		Release((LPVOID &)nKey);
	}
}

/*--------------------------------------------------------------------------------------
Function       : FreeData
In Parameters  : SIZE_T nData, 
Out Parameters : void 
Description    : release data memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CBBSt::FreeData(SIZE_T nData)
{
	CBufferToStructure objBufToStruct(false, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);
	objBufToStruct.SetDataPtr((PNODEOPT)nData, m_pBuffer, m_nBufferSize);
	objBufToStruct.RemoveAll();
	m_bIsModified = true;
	return;
}

/*--------------------------------------------------------------------------------------
Function       : AppendItemAscOrder
In Parameters  : LPVOID lpvKey, CBufferToStructure& objBufToStruct, 
Out Parameters : bool 
Description    : add node in tree in ascending order in right vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::AppendItemAscOrder(LPVOID lpvKey, CBufferToStructure& objBufToStruct)
{
	LPBYTE pbyKeyDup = 0;

	pbyKeyDup = DuplicateBuffer((LPBYTE)lpvKey, m_dwSizeOfKey);
	if(NULL == pbyKeyDup)
	{
		return (false);
	}

	if(!AddNodeAscOrder((SIZE_T)pbyKeyDup,(SIZE_T)objBufToStruct.GetDataPtr()))
	{
		Release((LPVOID&)pbyKeyDup);
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendItem
In Parameters  : LPVOID lpvKey, CBufferToStructure& objBufToStruct, 
Out Parameters : bool 
Description    : add node in tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::AppendItem(LPVOID lpvKey, CBufferToStructure& objBufToStruct)
{
	LPBYTE pbyKeyDup = 0;

	pbyKeyDup = DuplicateBuffer((LPBYTE)lpvKey, m_dwSizeOfKey);
	if(NULL == pbyKeyDup)
	{
		return (false);
	}

	if(!AddNode((SIZE_T)pbyKeyDup,(SIZE_T)objBufToStruct.GetDataPtr()))
	{
		Release((LPVOID&)pbyKeyDup);
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
bool CBBSt::DeleteItem(LPVOID lpvKey)
{
	return (DeleteNode((SIZE_T)lpvKey));
}

/*--------------------------------------------------------------------------------------
Function       : SearchItem
In Parameters  : LPVOID lpvKey, CBufferToStructure& objBufToStruct, 
Out Parameters : bool 
Description    : search a key in tree and return data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::SearchItem(LPVOID lpvKey, CBufferToStructure& objBufToStruct)
{
	SIZE_T nData = 0;

	if(!FindNode((SIZE_T)lpvKey, nData))
	{
		return (false);
	}

	objBufToStruct.SetDataPtr((PNODEOPT)nData, m_pBuffer, m_nBufferSize);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : GetKey
In Parameters  : PVOID pVPtr, LPVOID& lpvKey, 
Out Parameters : bool 
Description    : get key by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::GetKey(PVOID pVPtr, LPVOID& lpvKey)
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
In Parameters  : PVOID pVPtr, CBufferToStructure& objBufToStruct, 
Out Parameters : bool 
Description    : get data by context pointer, used in traversal
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::GetData(PVOID pVPtr, CBufferToStructure& objBufToStruct)
{
	if(!pVPtr)
	{
		return (false);
	}

	objBufToStruct.SetDataPtr((PNODEOPT)(((PNODEOPT)pVPtr)->nData), m_pBuffer, m_nBufferSize);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : UpdateItem
In Parameters  : LPVOID lpvKey, CBufferToStructure& objBufToStruct, 
Out Parameters : bool 
Description    : overwrite the data of the given key
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::UpdateItem(LPVOID lpvKey, CBufferToStructure& objBufToStruct)
{
	if(!m_pLastSearchResult || EQUAL != Compare(m_pLastSearchResult->nKey,(SIZE_T)lpvKey))
	{
		SIZE_T nData = 0;

		if(!FindNode((SIZE_T)lpvKey, nData))
		{
			return (false);
		}
	}

	m_bIsModified = true;
	m_pLastSearchResult->nData = (SIZE_T)objBufToStruct.GetDataPtr();
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Balance
In Parameters  : 
Out Parameters : bool Balance 
Description    : balance all level trees
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::Balance()
{
	LPVOID Position = NULL;

	CBalBSTOpt::Balance();

	Position = GetFirst();
	while(Position)
	{
		CBufferToStructure objBufToStruct(true, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);
		GetData(Position, objBufToStruct);
		objBufToStruct.Balance();
		((PNODEOPT)Position) -> nData =(SIZE_T)objBufToStruct.GetDataPtr();
		Position = GetNext(Position);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : CreateObject
In Parameters  : CBBSt& objNewCopy, 
Out Parameters : bool 
Description    : make a new copy of this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::CreateObject(CBBSt& objNewCopy)
{
	LPBYTE lpKey = NULL;
	LPVOID lpContext = NULL;
	CBufferToStructure objDstCRC(true, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);
	CBufferToStructure objSrcCRC(true, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);

	lpContext = GetFirst();
	while(lpContext)
	{
		objDstCRC.RemoveAll();
		objSrcCRC.RemoveAll();
		lpKey = NULL;

		GetKey(lpContext,(LPVOID&)lpKey);
		GetData(lpContext, objSrcCRC);

		if(lpKey && objSrcCRC.GetFirst())
		{
			if(objSrcCRC.CreateObject(objDstCRC))
			{
				objNewCopy.AppendItem(lpKey, objDstCRC);
			}
		}

		lpContext = GetNext(lpContext);
	}

	m_bIsModified = true;
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : AppendObject
In Parameters  : CBalBSTOpt& objToAdd, 
Out Parameters : bool 
Description    : merge an object to this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::AppendObject(CBalBSTOpt& objToAdd)
{
	CBBSt& _objToAdd = (CBBSt&)objToAdd;
	LPVOID lpAddObjContext = NULL;
	LPVOID lpEmdAddObjContext = NULL;
	PULONG64 lpAddObjKey = NULL;
	PULONG64 lpEmdAddObjKey = NULL;
	LPDWORD lpEmdAddObjData = NULL;
	CBufferToStructure objAddObjData(true, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);
	CBufferToStructure objTempObjData(true, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);
	CBufferToStructure objThisObjData(true, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);

	lpAddObjContext = _objToAdd.GetFirst();
	while(lpAddObjContext)
	{
		lpAddObjKey = NULL;
		objAddObjData.RemoveAll();

		_objToAdd.GetKey(lpAddObjContext, (LPVOID&)lpAddObjKey);
		_objToAdd.GetData(lpAddObjContext, objAddObjData);

		if(lpAddObjKey)
		{
			objThisObjData.RemoveAll();
			if(SearchItem(lpAddObjKey, objThisObjData))
			{
				lpEmdAddObjContext = objAddObjData.GetFirst();
				while(lpEmdAddObjContext)
				{
					lpEmdAddObjKey = NULL;
					lpEmdAddObjData = NULL;

					objAddObjData.GetKey(lpEmdAddObjContext, (LPVOID&)lpEmdAddObjKey);
					objAddObjData.GetData(lpEmdAddObjContext, (LPVOID&)lpEmdAddObjData);

					if(lpEmdAddObjKey && lpEmdAddObjData)
					{
						if(objThisObjData.AppendItem(lpEmdAddObjKey, lpEmdAddObjData))
						{
							SetModified();
						}
					}

					lpEmdAddObjContext = objAddObjData.GetNext(lpEmdAddObjContext);
				}
			}
			else
			{
				if(objAddObjData.GetFirst())
				{
					objTempObjData.RemoveAll();
					if(objAddObjData.CreateObject(objTempObjData))
					{
						if(AppendItem(lpAddObjKey, objTempObjData))
						{
							SetModified();
						}
					}
				}
			}
		}

		lpAddObjContext = _objToAdd.GetNext(lpAddObjContext);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : DeleteObject
In Parameters  : CBalBSTOpt& objToDel, 
Out Parameters : bool 
Description    : delete all level nodes from this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::DeleteObject(CBalBSTOpt& objToDel)
{
	CBBSt& _objToDel = (CBBSt&)objToDel;
	LPVOID lpDelObjContext = NULL, lpEmdDelObjContext = NULL;
	PULONG64 lpDelObjKey = NULL, lpEmdDelObjKey = NULL;
	CBufferToStructure objDelObjData(true, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);
	CBufferToStructure objThisObjData(true, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);

	lpDelObjContext = _objToDel.GetFirst();
	while(lpDelObjContext)
	{
		lpDelObjKey = NULL;
		objDelObjData.RemoveAll();
		objThisObjData.RemoveAll();

		_objToDel.GetKey(lpDelObjContext, (LPVOID&)lpDelObjKey);
		_objToDel.GetData(lpDelObjContext, objDelObjData);

		if(SearchItem(lpDelObjKey, objThisObjData))
		{
			lpEmdDelObjContext = objDelObjData.GetFirst();
			while(lpEmdDelObjContext)
			{
				lpEmdDelObjKey = NULL;
				objDelObjData.GetKey(lpEmdDelObjContext, (LPVOID&)lpEmdDelObjKey);

				if(lpEmdDelObjKey)
				{
					if(objThisObjData.DeleteItem(lpEmdDelObjKey))
					{
						SetModified();
					}
				}

				lpEmdDelObjContext = objDelObjData.GetNext(lpEmdDelObjContext);
			}
		}

		UpdateItem(lpDelObjKey, objThisObjData);
		if(!objThisObjData.GetFirst())
		{
			if(DeleteItem(lpDelObjKey))
			{
				SetModified();
			}
		}

		lpDelObjContext = _objToDel.GetNext(lpDelObjContext);
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
bool CBBSt::SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent)
{
	bool bSuccess = true, bFound = false;
	LPVOID lpContext1 = NULL, lpContext2 = NULL;
	CBBSt& objToSearchDup = (CBBSt&)objToSearch;
	CBufferToStructure objThis(true, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);
	CBufferToStructure objSearch(true, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);
	LPVOID lpKey1 = NULL, lpKey2 = NULL, lpData = NULL;

	lpContext1 = objToSearchDup.GetFirst();
	while(lpContext1 && bSuccess)
	{
		objToSearchDup.GetKey(lpContext1, lpKey1);
		objToSearchDup.GetData(lpContext1, objSearch);

		if(SearchItem(lpKey1, objThis))
		{
			lpContext2 = objSearch.GetFirst();
			while(lpContext2 && bSuccess)
			{
				objSearch.GetKey(lpContext2, lpKey2);
				if(lpKey2)
				{
					bFound = objThis.SearchItem(lpKey2, (LPVOID&)lpData);
					if((!bFound && bAllPresent) || (bFound && !bAllPresent))
					{
						bSuccess = false;
					}
				}

				lpContext2 = objSearch.GetNext(lpContext2);
			}
		}
		else
		{
			bSuccess = bAllPresent?false:bSuccess;
		}

		lpContext1 = objToSearchDup.GetNext(lpContext1);
	}

	return bSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : ReadBBSt
In Parameters  : LPBYTE& ptrData, PULONG64& ptrNode, LPBYTE byBuffer, DWORD cbBuffer
Out Parameters : bool 
Description    : read bbst object from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::ReadBBSt(LPBYTE& ptrData, PSIZE_T& ptrNode, LPBYTE byBuffer, DWORD cbBuffer)
{
	PSIZE_T ptrNext = NULL;
	BOOL bAllowNull = FALSE;
	DWORD dwNodesCount = 0, dwTotalNodesToSkip = 0;
	CBufferToStructure objB2St(true, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData);

	VALIDATE_POINTER(ptrData,byBuffer,cbBuffer);
	dwNodesCount = *((LPDWORD)ptrData);
	ptrData += sizeof(dwNodesCount);

	for(DWORD i = 0; i < dwNodesCount; i++)
	{
		if(i + 1 < dwNodesCount)
		{
			VALIDATE_POINTER(ptrData + m_dwSizeOfKey,byBuffer,cbBuffer);
			dwTotalNodesToSkip = *((LPDWORD)(ptrData + m_dwSizeOfKey));
			dwTotalNodesToSkip++;
			ptrNext = ptrNode +(dwTotalNodesToSkip * NUMBER_OF_NODEOPT_ELEMENTS);
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

		CHECK_AND_MAKE_POINTER2(ptrNode, ptrNode+3, byBuffer, cbBuffer, FALSE);
		ptrNode++;

		CHECK_AND_MAKE_POINTER2(ptrNode, NULL, byBuffer, cbBuffer, TRUE);
		ptrNode++;

		CHECK_AND_MAKE_POINTER2(ptrNode, ptrNext, byBuffer, cbBuffer, bAllowNull);
		ptrNode++;

		if(!objB2St.ReadB2St(ptrData, ptrNode, byBuffer, cbBuffer))
		{
			return false;
		}
	}

	return true;

ERROR_EXIT:
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, 
Out Parameters : bool 
Description    : load from file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	HANDLE hFile = 0;
	LPBYTE ptrData = NULL;
	DWORD dwFileSize = 0, dwBytesRead = 0;
	TCHAR szFullFileName[MAX_PATH]={0};
	PSIZE_T ptrNode = NULL;
	ULONG64 ulTotalNodesCount = 0;
	BYTE byHdrBfr[sizeof(HEADER_BBST) + sizeof(HEADER_BBST_DATA)] ={0};

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

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_BBST_DATA, sizeof(HEADER_BBST_DATA)))
	{
		goto ERROR_EXIT;
	}

	if(bCheckVersion && memcmp(HEADER_BBST, byHdrBfr, sizeof(HEADER_BBST)))
	{
		goto ERROR_EXIT;
	}

	if(memcmp(byHdrBfr + sizeof(HEADER_BBST), HEADER_BBST_DATA, 8 + 8))
	{
		goto ERROR_EXIT;
	}

	memcpy(&ulTotalNodesCount, byHdrBfr + sizeof(HEADER_BBST) + 8 + 8, sizeof(ulTotalNodesCount));

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
	m_nBufferSize = dwFileSize + (((DWORD)ulTotalNodesCount) * SIZE_OF_NODEOPT);

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

	/*if(false == CryptBuffer(m_pBuffer, dwFileSize))
	{
		goto ERROR_EXIT;
	}*/

	ptrData = m_pBuffer;
	ptrNode =(PSIZE_T)(m_pBuffer + dwFileSize);
	m_pRoot =(PNODEOPT)ptrNode;

	if(false == ReadBBSt(ptrData, ptrNode, m_pBuffer, m_nBufferSize))
	{
		goto ERROR_EXIT;
	}

	if(false == Balance())
	{
		goto ERROR_EXIT;
	}

	if(m_bLoadReadOnly)
	{
		VChangeProtection(m_pBuffer, m_nBufferSize, TRUE);
	}

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
Function       : DumpBBSt
In Parameters  : HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount, DWORD dwKeyLen,
					DWORD dwEmbdKeyLen, DWORD dwEmbdDataLen, 
Out Parameters : bool 
Description    : dump bbst object to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::DumpBBSt(HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount, DWORD dwKeyLen,
					 DWORD dwEmbdKeyLen, DWORD dwEmbdDataLen)
{
	bool bWriteError = false;
	DWORD dwThisNodesCountOffset = 0, dwCurrentOffset = 0, dwBytesWritten = 0;
	DWORD dwThisNodesCount = 0, dwEmdbNodesCount = 0;
	CBufferToStructure objB2St(true, dwEmbdKeyLen, dwEmbdDataLen);
	CPtrStack objPtrStack;

	dwThisNodesCountOffset = SetFilePointer(hFile, 0, 0, FILE_CURRENT);
	if(INVALID_SET_FILE_POINTER == dwThisNodesCountOffset)
	{
		return (false);
	}

	if(FALSE == WriteFile(hFile, &dwThisNodesCount, sizeof(dwThisNodesCount), &dwBytesWritten, 0))
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

			dwEmdbNodesCount = 0;
			dwThisNodesCount++;
			dwNodesCount++;

			if(!WriteFile(hFile,(LPVOID)m_pTemp->nKey, dwKeyLen, &dwBytesWritten, 0))
			{
				bWriteError = true;
				break;
			}

			if(!objB2St.DumpB2St(hFile, (PNODEOPT)m_pTemp->nData, dwEmdbNodesCount, dwEmbdKeyLen, dwEmbdDataLen))
			{
				bWriteError = true;
				break;
			}

			dwNodesCount += dwEmdbNodesCount;
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

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwThisNodesCountOffset, 0, FILE_BEGIN))
	{
		return (false);
	}

	if(!WriteFile(hFile, &dwThisNodesCount, sizeof(dwThisNodesCount), &dwBytesWritten, 0))
	{
		return (false);
	}

	if( INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwCurrentOffset, 0, FILE_BEGIN))
	{
		return (false);
	}

	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Save
In Parameters  : LPCTSTR szFileName, bool bEncryptContents, 
Out Parameters : bool 
Description    : save the object to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CBBSt::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	HANDLE hFile = 0;
	ULONG64 ulCount = 0;
	DWORD dwBytesWritten = 0, dwNodesCount = 0;
	BYTE byHdrBfr[sizeof(HEADER_BBST) + sizeof(HEADER_BBST_DATA)] = {0};

	hFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, sizeof(byHdrBfr), 0, FILE_BEGIN))
	{
		goto ERROR_EXIT;
	}

	if(!DumpBBSt(hFile, m_pRoot, dwNodesCount, m_dwSizeOfKey, m_dwSizeOfEmbeddedKey, m_dwSizeOfEmbeddedData))
	{
		goto ERROR_EXIT;
	}

	ulCount = dwNodesCount;
	/*if(bEncryptContents && !CryptFileData(hFile, sizeof(byHdrBfr)))
	{
		goto ERROR_EXIT;
	}*/

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0, 0, FILE_BEGIN))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFileName, HEADER_BBST_DATA, sizeof(HEADER_BBST_DATA), ulCount))
	{
		goto ERROR_EXIT;
	}

	memcpy(byHdrBfr, HEADER_BBST, sizeof(HEADER_BBST));
	memcpy(byHdrBfr + sizeof(HEADER_BBST), HEADER_BBST_DATA, sizeof(HEADER_BBST_DATA));
	if(!WriteFile(hFile, byHdrBfr, sizeof(byHdrBfr), &dwBytesWritten, 0))
	{
		goto ERROR_EXIT;
	}

	CloseHandle(hFile);
	return (true);

ERROR_EXIT:

	if(INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
	}

	DeleteFile(szFileName);
	AddLogEntry(L"Error saving file: %s.File deleted.", szFileName);
	return (false);
}
