/*======================================================================================
FILE             : FSDB.cpp
ABSTRACT         : file signature database handler class declaration file
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created in 2011 as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura. Hence, it may not be used, copied, 
				  reproduced, transmitted, or stored in any form or by any means, electronic,
				  recording, photocopying, mechanical or otherwise, without the prior written
				  permission of Aura.
				  
CREATION DATE    : 27 May 2011
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "FSDB.h"

/*--------------------------------------------------------------------------------------
Function       : contructor
In Parameters  : int iMemToUseInMB
Out Parameters : 
Description    : 
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CFSDB::CFSDB(int iMemToUseInMB)
{
	DWORD dwDivisor = 0;
	SYSTEM_INFO SysInfo = {0};

	m_byWriteBuffer64KB = NULL;
	m_pPgTbl = NULL;
	m_hMapping = NULL;
	m_bDelEntry = false;
	m_bModified = false;
	m_dwPgTblCurIdx = -1;
	m_bMapReadOnly = false;
	m_hFile = INVALID_HANDLE_VALUE;
	memset(m_szTempFilePath, 0, sizeof(m_szTempFilePath));
	m_dwCurIdxInPage = m_dwMaxPageSize = m_dwFileSize = m_dwPgTblArrCnt = 0;

	GetSystemInfo(&SysInfo);
	dwDivisor = iELEMENT_SIZE * SysInfo.dwAllocationGranularity;

	m_dwMaxPageSize = iMemToUseInMB * 1024 * 1024;
	m_dwMaxPageSize += dwDivisor - (m_dwMaxPageSize % dwDivisor);
}

/*--------------------------------------------------------------------------------------
Function       : destructor
In Parameters  : 
Out Parameters : 
Description    : 
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CFSDB::~CFSDB()
{
	RemoveAll();
}

/*--------------------------------------------------------------------------------------
Function       : SearchSig
In Parameters  : PULONG64 pSig, LPDWORD pSpyID
Out Parameters : bool 
Description    : search a signature in database and return sig and spyid when sig found else false
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::SearchSig(PULONG64 pSig, LPDWORD pSpyID)
{
	bool bFound = false;
	DWORD iPageIdx = -1;
	LPELMNT lpElmnt = NULL;
	int iStart = 0, iEnd = 0, iSearch = 0;

	if(0 == pSig || 0 == *pSig)
	{
		return false;
	}

	for(DWORD i = 0; i < m_dwPgTblArrCnt; i++)
	{
		if(*pSig >= m_pPgTbl[i].ulFrstSig && *pSig <= m_pPgTbl[i].ulLastSig)
		{
			iPageIdx = i;
			break;
		}
	}

	if(-1 == iPageIdx)
	{
		return false;
	}

	if(!MapPageOfTable(iPageIdx))
	{
		return false;
	}

	lpElmnt = (LPELMNT)m_pPgTbl[iPageIdx].lpPagePtr;
	if(!lpElmnt)
	{
		return false;
	}

	iStart = 0;
	iEnd = (int)(m_pPgTbl[iPageIdx].dwUseSigs - 1);

	while(iEnd >= iStart)
	{
		iSearch = (iEnd + iStart) / 2;

		if(lpElmnt[iSearch].ulSig > *pSig)
		{
			iEnd = iSearch - 1;
		}
		else if(lpElmnt[iSearch].ulSig < *pSig)
		{
			iStart = iSearch + 1;
		}
		else
		{
			bFound = true;
			if(pSpyID)
			{
				*pSpyID = lpElmnt[iSearch].dwSpy;
			}

			break;
		}
	}

	return bFound;
}

/*--------------------------------------------------------------------------------------
Function       : Get
In Parameters  : ULONG64* pSig, DWORD* pSpyID
Out Parameters : bool 
Description    : get signature and spyid from current page and current index in page
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::Get(ULONG64* pSig, DWORD* pSpyID)
{
	LPBYTE byPage = 0;

	if(-1 == m_dwPgTblCurIdx || m_dwPgTblCurIdx >= m_dwPgTblArrCnt)
	{
		return false;
	}

	if(m_dwCurIdxInPage >= m_pPgTbl[m_dwPgTblCurIdx].dwUseSigs)
	{
		return false;
	}

	byPage = (LPBYTE)m_pPgTbl[m_dwPgTblCurIdx].lpPagePtr;
	if(pSig)
	{
		*pSig = *((ULONG64*)(byPage + (m_dwCurIdxInPage * iELEMENT_SIZE)));
	}

	if(pSpyID)
	{
		*pSpyID = *((DWORD*)(byPage + (m_dwCurIdxInPage * iELEMENT_SIZE) + sizeof(ULONG64)));
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Set
In Parameters  : ULONG64* pSig, DWORD* pSpyID
Out Parameters : bool 
Description    : sets the signature and spyware id on current page and current index in page
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::Set(ULONG64* pSig, DWORD* pSpyID)
{
	LPBYTE byPage = 0;

	if(-1 == m_dwPgTblCurIdx || m_dwPgTblCurIdx >= m_dwPgTblArrCnt)
	{
		return false;
	}

	if(m_dwCurIdxInPage >= m_pPgTbl[m_dwPgTblCurIdx].dwUseSigs)
	{
		return false;
	}

	byPage = (LPBYTE)m_pPgTbl[m_dwPgTblCurIdx].lpPagePtr;
	if(pSig)
	{
		*((ULONG64*)(byPage + (m_dwCurIdxInPage * iELEMENT_SIZE))) = *pSig;
	}

	if(pSpyID)
	{
		*((DWORD*)(byPage + (m_dwCurIdxInPage * iELEMENT_SIZE) + sizeof(ULONG64))) = *pSpyID;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : AddAtEnd
In Parameters  : PULONG64 pSig, LPDWORD pSpyID
Out Parameters : bool 
Description    : add signature at the end in database
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::AddAtEnd(PULONG64 pSig, LPDWORD pSpyID)
{
	if(!m_pPgTbl)
	{
		return false;
	}

	if(m_pPgTbl[m_dwPgTblCurIdx].dwUseSigs >= m_pPgTbl[m_dwPgTblCurIdx].dwMaxSigs)
	{
		if(m_dwPgTblCurIdx >= m_dwPgTblArrCnt)
		{
			return false;
		}

		if(!MapPageOfTable(m_dwPgTblCurIdx + 1))
		{
			return false;
		}
	}

	m_dwCurIdxInPage = m_pPgTbl[m_dwPgTblCurIdx].dwUseSigs++;
	if(!Set(pSig, pSpyID))
	{
		m_pPgTbl[m_dwPgTblCurIdx].dwUseSigs--;
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetFirst
In Parameters  : PULONG64 pSig, LPDWORD pSpyID
Out Parameters : bool 
Description    : get first signature in database
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::GetFirst(PULONG64 pSig, LPDWORD pSpyID)
{
	if(!m_pPgTbl)
	{
		return false;
	}

	if(0 >= m_dwPgTblArrCnt)
	{
		return false;
	}

	if(!MapPageOfTable(0))
	{
		return false;
	}

	m_dwCurIdxInPage = 0;
	if(!Get(pSig, pSpyID))
	{
		return false;
	}

	m_dwCurIdxInPage++;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetNext
In Parameters  : PULONG64 pSig, LPDWORD pSpyID
Out Parameters : bool 
Description    : get next signature in database
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::GetNext(PULONG64 pSig, LPDWORD pSpyID)
{
	if(!m_pPgTbl)
	{
		return false;
	}

	if(0 >= m_dwPgTblArrCnt)
	{
		return false;
	}

	if(m_dwCurIdxInPage >= m_pPgTbl[m_dwPgTblCurIdx].dwUseSigs)
	{
		if(!MapPageOfTable(m_dwPgTblCurIdx + 1))
		{
			return false;
		}

		m_dwCurIdxInPage = 0;
	}

	if(!Get(pSig, pSpyID))
	{
		return false;
	}

	m_dwCurIdxInPage++;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : RemoveAll
In Parameters  : bool bRemoveTree
Out Parameters : bool 
Description    : cleanup all memory and relinquish any system resources acquired
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::RemoveAll(bool bRemoveTree)
{
	FreePageTable();
	if(bRemoveTree)
	{
		m_objSigTree.RemoveAll();
	}

	if(NULL != m_hMapping)
	{
		CloseHandle(m_hMapping);
		m_hMapping = NULL;
	}

	if(INVALID_HANDLE_VALUE != m_hFile)
	{
		CloseHandle(m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
	}

	if(!m_bMapReadOnly && _tcsrchr(m_szTempFilePath, _T('.')))
	{
		if(!_tcsicmp(_tcsrchr(m_szTempFilePath, _T('.')), _T(".tmp")))
		{
			DeleteFile(m_szTempFilePath);
		}
	}

	if(m_byWriteBuffer64KB)
	{
		Release((LPVOID&)m_byWriteBuffer64KB);
	}

	m_pPgTbl = NULL;
	m_hMapping = NULL;
	m_bModified = false;
	m_dwPgTblCurIdx = -1;
	m_bMapReadOnly = false;
	m_hFile = INVALID_HANDLE_VALUE;
	m_dwCurIdxInPage = m_dwFileSize = m_dwPgTblArrCnt = 0;
	memset(m_szTempFilePath, 0, sizeof(m_szTempFilePath));
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : IsModified
In Parameters  : 
Out Parameters : bool 
Description    : returns true if database is modified since loaded and entries added or deleted
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::IsModified()
{
	return m_bModified;
}

/*--------------------------------------------------------------------------------------
Function       : Balance
In Parameters  : 
Out Parameters : void 
Description    : balance the signature tree object used for live update
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CFSDB::Balance()
{
	m_objSigTree.Balance();
}

/*--------------------------------------------------------------------------------------
Function       : SetTempPath
In Parameters  : LPCTSTR szTempPath
Out Parameters : bool 
Description    : sets the temp path, where a temp file will be created, per object instance
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::SetTempPath(LPCTSTR szTempPath)
{
	if(NULL == szTempPath)
	{
		return false;
	}

	if(_tcslen(szTempPath) >= _countof(m_szTempFilePath))
	{
		return false;
	}

	memset(m_szTempFilePath, 0, sizeof(m_szTempFilePath));
	_tcscpy_s(m_szTempFilePath, _countof(m_szTempFilePath), szTempPath);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : MakeTempFile
In Parameters  : 
Out Parameters : bool 
Description    : make the temp file name
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::MakeTempFile()
{
	TCHAR szFile[MAX_PATH] = {0};

	if(0 == m_szTempFilePath[0])
	{
		memset(m_szTempFilePath, 0, sizeof(m_szTempFilePath));
		if(0 == GetTempPath(_countof(m_szTempFilePath), m_szTempFilePath))
		{
			return false;
		}
	}

	if(0 == GetTempFileName(m_szTempFilePath, _T("Sig"), 0, szFile))
	{
		return false;
	}

	memset(m_szTempFilePath, 0, sizeof(m_szTempFilePath));
	_tcscpy_s(m_szTempFilePath, _countof(m_szTempFilePath), szFile);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : MakeMapFileObj
In Parameters  : 
Out Parameters : bool 
Description    : creates the map file object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::MakeMapFileObj(bool * pbErrorOpenFile)
{
	DWORD dwTemp = 0;

	dwTemp = m_bMapReadOnly? GENERIC_READ: GENERIC_READ|GENERIC_WRITE;
	m_hFile = CreateFile(m_szTempFilePath, dwTemp, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == m_hFile)
	{
		if(pbErrorOpenFile)
		{
			*pbErrorOpenFile = true;
		}

		return false;
	}

	m_dwFileSize = GetFileSize(m_hFile, 0);
	if(0 == m_dwFileSize)
	{
		if(!WriteFile(m_hFile, " ", 1, &dwTemp, 0))
		{
			CloseHandle(m_hFile);
			m_hFile = INVALID_HANDLE_VALUE;
			return false;
		}

		if(INVALID_SET_FILE_POINTER == SetFilePointer(m_hFile, 0, 0, FILE_BEGIN))
		{
			CloseHandle(m_hFile);
			m_hFile = INVALID_HANDLE_VALUE;
			return false;
		}

		m_dwFileSize = iMAX_TEMP_FILE_SIZE;
	}

	dwTemp = m_bMapReadOnly? PAGE_READONLY: PAGE_READWRITE;
	m_hMapping = CreateFileMapping(m_hFile, 0, dwTemp, 0, m_dwFileSize, NULL);
	if(!m_hMapping)
	{
		CloseHandle(m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : MakePageTable
In Parameters  : 
Out Parameters : bool 
Description    : crate page table to access the data in pages and not loading full data in one chunk
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::MakePageTable()
{
	if((0 != m_dwFileSize) && (0 != (m_dwFileSize % iELEMENT_SIZE)))
	{
		AddLogEntry(L"Invalid file size");
		return false;
	}

	m_dwPgTblArrCnt = m_dwFileSize / m_dwMaxPageSize;
	m_dwPgTblArrCnt += m_dwFileSize % m_dwMaxPageSize? 1 : 0;

	m_pPgTbl = (LPSIGPAGE)Allocate(sizeof(SIGPAGE) * m_dwPgTblArrCnt);
	if(!m_pPgTbl)
	{
		return false;
	}

	for(DWORD i = 0; i < m_dwPgTblArrCnt; i++)
	{
		m_pPgTbl[i].dwPageOff = i * m_dwMaxPageSize;

		if(i + 1 >= m_dwPgTblArrCnt)
		{
			m_pPgTbl[i].dwPageLen = m_dwFileSize % m_dwMaxPageSize;
		}
		else
		{
			m_pPgTbl[i].dwPageLen = m_dwMaxPageSize;
		}

		m_pPgTbl[i].dwMaxSigs = m_pPgTbl[i].dwPageLen / iELEMENT_SIZE;
		m_pPgTbl[i].dwUseSigs = m_bMapReadOnly? m_pPgTbl[i].dwMaxSigs: 0;
	}

	if(!MapPageOfTable(0))
	{
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : FreePageTable
In Parameters  : 
Out Parameters : bool 
Description    : unmap the mapped pages and free the page table
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::FreePageTable()
{
	if(m_pPgTbl)
	{
		for(DWORD i = 0; i < m_dwPgTblArrCnt; i++)
		{
			if(m_pPgTbl[i].lpPagePtr)
			{
				UnmapViewOfFile(m_pPgTbl[i].lpPagePtr);
			}
		}

		Release((LPVOID&)m_pPgTbl);
		m_pPgTbl = NULL;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : MapPageOfTable
In Parameters  : DWORD iPage
Out Parameters : bool 
Description    : map the page of given index and unmap other mapped page. only one page is mapped at a time.
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::MapPageOfTable(DWORD iPage)
{
	DWORD dwAccess = m_bMapReadOnly? FILE_MAP_READ: FILE_MAP_READ|FILE_MAP_WRITE;

	if(iPage >= m_dwPgTblArrCnt)
	{
		return false;
	}

	if(iPage == m_dwPgTblCurIdx)
	{
		return true;
	}

	m_pPgTbl[iPage].lpPagePtr = MapViewOfFile(m_hMapping, dwAccess, 0, m_pPgTbl[iPage].dwPageOff, m_pPgTbl[iPage].dwPageLen);
	if(!m_pPgTbl[iPage].lpPagePtr)
	{
		int iError = GetLastError();
		return false;
	}

	if(-1 != m_dwPgTblCurIdx)
	{
		if(!UnmapViewOfFile(m_pPgTbl[m_dwPgTblCurIdx].lpPagePtr))
		{
			return false;
		}

		m_pPgTbl[m_dwPgTblCurIdx].lpPagePtr = NULL;
	}

	m_dwPgTblCurIdx = iPage;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : MakeSigIndex
In Parameters  : 
Out Parameters : bool 
Description    : set the first and last signatures residing on each page in the page table entry
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::MakeSigIndex()
{
	bool bSuccess = true;

	if(!m_bMapReadOnly)
	{
		return false;
	}

	for(DWORD i = 0; i < m_dwPgTblArrCnt; i++)
	{
		if(0 == m_pPgTbl[i].dwUseSigs)
		{
			continue;
		}

		if(!MapPageOfTable(i))
		{
			bSuccess = false;
			break;
		}

		m_dwCurIdxInPage = 0;
		Get(&m_pPgTbl[i].ulFrstSig, 0);

		m_dwCurIdxInPage = m_pPgTbl[i].dwUseSigs - 1;
		Get(&m_pPgTbl[i].ulLastSig, 0);
	}

	return bSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : Init
In Parameters  : 
Out Parameters : bool 
Description    : create a temp file to hold data when creating database
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::Init()
{
	m_bMapReadOnly = false;
	if(!MakeTempFile())
	{
		return false;
	}

	if(!MakeMapFileObj())
	{
		return false;
	}

	if(!MakePageTable())
	{
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : AppendObject
In Parameters  : CFSDB& objToAdd
Out Parameters : bool 
Description    : add all the signatures from this given db to database
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::AppendObject(CFSDB& objToAdd)
{
	return MergeObject(objToAdd, true);
}

/*--------------------------------------------------------------------------------------
Function       : DeleteObject
In Parameters  : CFSDB& objToDel
Out Parameters : bool 
Description    : delete all the signatures from this given db from database
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::DeleteObject(CFSDB& objToDel)
{
	return MergeObject(objToDel, false);
}

/*--------------------------------------------------------------------------------------
Function       : MergeObject
In Parameters  : CFSDB& objFSDB, bool bAdd
Out Parameters : bool 
Description    : merge(add or delete) the entries from given db object into this object
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::MergeObject(CFSDB& objFSDB, bool bAdd)
{
	DWORD dwSpyID = 0;
	ULONG64 ulSig = 0;

	if(!objFSDB.GetFirst(&ulSig, &dwSpyID))
	{
		return false;
	}

	m_bModified = true;

	do
	{
		if(0 == ulSig)
		{
			continue;
		}

		if(bAdd)
		{
			if(m_bDelEntry)
			{
				m_objSigTree.Del(&ulSig);
			}

			m_objSigTree.Add(&ulSig, &dwSpyID);
		}
		else
		{
			m_bDelEntry = true;
			m_objSigTree.Del(&ulSig);
			dwSpyID = MAX_DWORD32;
			m_objSigTree.Add(&ulSig, &dwSpyID);
		}
	}while(objFSDB.GetNext(&ulSig, &dwSpyID));

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetPosition
In Parameters  : LPELMNT lpRecordSet, DWORD dwRecordCnt, ULONG64 ulSig
Out Parameters : DWORD
Description    : find the index where ulSig can fit in the sorted list
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
DWORD CFSDB::GetPosition(LPELMNT lpRecordSet, DWORD dwRecordCnt, ULONG64 ulSig)
{
	DWORD dwPos = 0;

	if(lpRecordSet[0].ulSig > ulSig)
	{
		return MAX_DWORD32;
	}
	else if(lpRecordSet[0].ulSig == ulSig)
	{
		return dwPos;
	}
	else if(lpRecordSet[dwRecordCnt - 1].ulSig < ulSig)
	{
		return dwRecordCnt;
	}
	else if(lpRecordSet[dwRecordCnt - 1].ulSig == ulSig)
	{
		return dwRecordCnt - 1;
	}
	else
	{
		__int64 iStart = 0, iEnd = 0;
		DWORD iSearch = 0, iPos = 0;

		iStart = 0;
		iEnd = dwRecordCnt - 1;

		while(iEnd >= iStart)
		{
			iSearch = ((DWORD)(iEnd + iStart)) / 2;

			if(lpRecordSet[iSearch].ulSig > ulSig)
			{
				iEnd = iSearch - 1;
			}
			else if(lpRecordSet[iSearch].ulSig < ulSig)
			{
				iStart = iSearch + 1;
			}
			else
			{
				break;
			}
		}

		if(lpRecordSet[iSearch].ulSig < ulSig)
		{
			for(iPos = iSearch; iPos < dwRecordCnt; iPos++)
			{
				if(lpRecordSet[iPos].ulSig >= ulSig)
				{
					dwPos = iSearch;
					break;
				}				
			}
		}
		else if(lpRecordSet[iSearch].ulSig > ulSig)
		{
			for(iPos = iSearch; iPos >= 1; iPos--)
			{
				if(lpRecordSet[iPos - 1].ulSig <= ulSig)
				{
					dwPos = iSearch;
					break;
				}
			}
		}
		else
		{
			dwPos = iSearch;
		}
	}

	return dwPos;
}

/*--------------------------------------------------------------------------------------
Function       : WriteDataToFile
In Parameters  : HANDLE hFile, LPVOID lpBuffer, DWORD cbBuffer, bool bUseBuffer
Out Parameters : bool 
Description    : write data to file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::WriteBufferedData(HANDLE hFile, LPVOID lpBuffer, DWORD cbBuffer, bool bUseBuffer)
{
	DWORD dwBytesWritten = 0;

	if(bUseBuffer && !lpBuffer && !cbBuffer)
	{
		if(0 == m_dwWriteBuffer64KBCurBytes)
		{
			return true;
		}

		if(!WriteFile(hFile, m_byWriteBuffer64KB, m_dwWriteBuffer64KBCurBytes, &dwBytesWritten, 0))
		{
			return false;
		}

		if(m_dwWriteBuffer64KBCurBytes != dwBytesWritten)
		{
			return false;
		}

		m_dwWriteBuffer64KBCurBytes = 0;
		memset(m_byWriteBuffer64KB, 0, WRITE_BUF_SIZE);
	}
	else if(bUseBuffer && lpBuffer && cbBuffer)
	{
		if(cbBuffer + m_dwWriteBuffer64KBCurBytes > WRITE_BUF_SIZE)
		{
			if(!WriteBufferedData(hFile, 0, 0, true))
			{
				return false;
			}

			if(cbBuffer > WRITE_BUF_SIZE)
			{
				if(!WriteBufferedData(hFile, lpBuffer, cbBuffer, false))
				{
					return false;
				}
			}
			else
			{
				memcpy(m_byWriteBuffer64KB, lpBuffer, cbBuffer);
				m_dwWriteBuffer64KBCurBytes += cbBuffer;
			}
		}
		else
		{
			memcpy(m_byWriteBuffer64KB + m_dwWriteBuffer64KBCurBytes, lpBuffer, cbBuffer);
			m_dwWriteBuffer64KBCurBytes += cbBuffer;
		}
	}
	else if(!bUseBuffer && lpBuffer && cbBuffer)
	{
		if(!WriteBufferedData(hFile, 0, 0, true))
		{
			return false;
		}

		if(!WriteFile(hFile, lpBuffer, cbBuffer, &dwBytesWritten, 0))
		{
			return false;
		}

		if(cbBuffer != dwBytesWritten)
		{
			return false;
		}
	}
	else
	{
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : CreateMergerdMainFile
In Parameters  : LPCTSTR szFileName
Out Parameters : bool 
Description    : write delta and loaded main file data and create merged final file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::CreateMergerdMainFile(LPCTSTR szFileName)
{
	ULONG64 ulDltSig = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szTempFileName[MAX_PATH] = {0};
	ELMNT * lpRecordSet = NULL, stRec = {0}, stRecPrv = {0};
	bool bWriteDeltaAfterMain = false, bWriteMain = false, bSuccess = true, bWriteDeltaBeforeMain = false;
	DWORD dwRecordCnt = 0, dwDltSpy = 0, dwPosition = 0, dwWriteIndex = 0, dwWriteCount = 0, dwOmittedSignatures = 0;

	if(!m_objSigTree.GetSmallest(&ulDltSig, &dwDltSpy))
	{
		return false;
	}

	if(_tcslen(szFileName) + 10 >= _countof(szTempFileName))
	{
		return false;
	}

	_stprintf_s(szTempFileName, _countof(szTempFileName), _T("%s.%08x"), szFileName, GetTickCount());
	hFile = CreateFile(szTempFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	for(DWORD iPage = 0; iPage < m_dwPgTblArrCnt; iPage++)
	{
		if(!MapPageOfTable(iPage))
		{
			bSuccess = false;
			break;
		}

		lpRecordSet = (LPELMNT)m_pPgTbl[iPage].lpPagePtr;
		dwRecordCnt = m_pPgTbl[iPage].dwUseSigs;

		if(MAX_DWORD64 == ulDltSig)
		{
			if(!WriteBufferedData(hFile, lpRecordSet, dwRecordCnt * sizeof(ELMNT), false))
			{
				bSuccess = false;
				break;
			}
		}
		else
		{
			for(DWORD iSigInPage = 0; iSigInPage < dwRecordCnt;)
			{
				stRec.ulSig = MAX_DWORD64;
				stRec.dwSpy = MAX_DWORD32;

				if(lpRecordSet[iSigInPage].ulSig < ulDltSig)
				{
					stRec.ulSig = lpRecordSet[iSigInPage].ulSig;
					stRec.dwSpy = lpRecordSet[iSigInPage].dwSpy;
					iSigInPage++;
				}
				else
				if(lpRecordSet[iSigInPage].ulSig > ulDltSig)
				{
					stRec.ulSig = ulDltSig;
					stRec.dwSpy = dwDltSpy;

					if(!m_objSigTree.GetLarger(&ulDltSig, &dwDltSpy))
					{
						ulDltSig = MAX_DWORD64;
						dwDltSpy = MAX_DWORD32;
					}
				}
				else
				{
					if(dwDltSpy != MAX_DWORD32)
					{
						stRec.ulSig = lpRecordSet[iSigInPage].ulSig;
						stRec.dwSpy = lpRecordSet[iSigInPage].dwSpy;
					}

					if(!m_objSigTree.GetLarger(&ulDltSig, &dwDltSpy))
					{
						ulDltSig = MAX_DWORD64;
						dwDltSpy = MAX_DWORD32;
					}

					iSigInPage++;
				}

				if(stRec.dwSpy != MAX_DWORD32)
				{
					if(stRecPrv.ulSig >= stRec.ulSig)
					{
						dwOmittedSignatures++;

						TCHAR szLogString[100] = {0};
						_stprintf_s(szLogString, _countof(szLogString), _T("omit sig: %016I64x"), stRec.ulSig);
						AddLogEntry(szLogString);

						if(dwOmittedSignatures >= dwMAX_OMIT_SIG_CNT)
						{
							bSuccess = false;
							break;
						}
					}
					else
					{
						if(!WriteBufferedData(hFile, &stRec, sizeof(ELMNT), true))
						{
							bSuccess = false;
							break;
						}

						stRecPrv.ulSig = stRec.ulSig;
					}
				}
			}

			if(!bSuccess)
			{
				break;
			}
		}
	}

	if(ulDltSig != MAX_DWORD64)
	{
		do
		{
			stRec.ulSig = ulDltSig;
			stRec.dwSpy = dwDltSpy;
			if(!WriteBufferedData(hFile, &stRec, sizeof(ELMNT), true))
			{
				bSuccess = false;
				break;
			}
		}while(m_objSigTree.GetLarger(&ulDltSig, &dwDltSpy));
	}

	if(!WriteBufferedData(hFile, 0, 0, true))
	{
		bSuccess = false;
	}

	CloseHandle(hFile);
	if(!bSuccess)
	{
		DeleteFile(szTempFileName);
		return false;
	}

	RemoveAll();
	if(0 == MoveFileEx(szTempFileName, szFileName, MOVEFILE_REPLACE_EXISTING))
	{
		DeleteFile(szTempFileName);
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Load
In Parameters  : LPCTSTR szFileName, bool bCheckVersion, bool bEncryptData
Out Parameters : bool 
Description    : load database from given db file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::Load(LPCTSTR szFileName, bool bCheckVersion, bool bEncryptData, bool * pbDeleteIfFail)
{
	bool bErrorOpenFile = false;

	m_bDelEntry = false;
	RemoveAll();
	m_bMapReadOnly = true;

	if(!MakeFullFilePath(szFileName, m_szTempFilePath, _countof(m_szTempFilePath)))
	{
		if(pbDeleteIfFail)
		{
			*pbDeleteIfFail = true;
		}

		return false;
	}

	if(!MakeMapFileObj(&bErrorOpenFile))
	{
		goto ERROR_EXIT;
	}

	if(!MakePageTable())
	{
		goto ERROR_EXIT;
	}

	if(!MakeSigIndex())
	{
		goto ERROR_EXIT;
	}

	if(pbDeleteIfFail)
	{
		*pbDeleteIfFail = false;
	}

	return true;

ERROR_EXIT:

	AddLogEntry(L"Error loading file: %s, %s", szFileName, m_szTempFilePath);
	if(pbDeleteIfFail && *pbDeleteIfFail && !bErrorOpenFile)
	{
		*pbDeleteIfFail = true;
		DeleteFile(m_szTempFilePath);
		AddLogEntry(L"Delete file: %s", m_szTempFilePath);
	}

	RemoveAll();
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : Save
In Parameters  : LPCTSTR szFileName, bool bCheckVersion, bool bEncryptData
Out Parameters : bool 
Description    : save database to given db file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFSDB::Save(LPCTSTR szFileName, bool bCheckVersion, bool bEncryptData)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;

	if(m_objSigTree.GetSmallest(0, 0))
	{
		if(!m_byWriteBuffer64KB)
		{
			m_byWriteBuffer64KB = (LPBYTE)Allocate(WRITE_BUF_SIZE);
			if(!m_byWriteBuffer64KB)
			{
				AddLogEntry(_T("error in getting memory for merging"));
				goto ERROR_EXIT;
			}
		}

		m_dwWriteBuffer64KBCurBytes = 0;
		memset(m_byWriteBuffer64KB, 0, WRITE_BUF_SIZE);
		if(!CreateMergerdMainFile(szFileName))
		{
			AddLogEntry(_T("error in delta merging"));
			goto ERROR_EXIT;
		}
	}
	else
	{
		DWORD dwBytesWritten = 0;

		hFile = CreateFile(szFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if(INVALID_HANDLE_VALUE == hFile)
		{
			return false;
		}

		for(DWORD i = 0; i < m_dwPgTblArrCnt; i++)
		{
			if(0 == m_pPgTbl[i].dwUseSigs)
			{
				break;
			}

			if(!MapPageOfTable(i))
			{
				goto ERROR_EXIT;
			}

			if(!WriteFile(hFile, m_pPgTbl[i].lpPagePtr, m_pPgTbl[i].dwUseSigs * iELEMENT_SIZE, &dwBytesWritten, 0))
			{
				goto ERROR_EXIT;
			}
		}

		CloseHandle(hFile);
	}

	return true;

ERROR_EXIT:

	if(INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

	DeleteFile(szFileName);
	AddLogEntry(L"Error saving file, deleted: %s", szFileName);
	return false;
}

//-------------------------------------------------------------------------------------//
//		SigTree Class Implementation. This class is internally used by CFSDB.		   //
//-------------------------------------------------------------------------------------//

/*--------------------------------------------------------------------------------------
Function       : constructor
In Parameters  : 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CSigTree::CSigTree()
{
	m_pRoot = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : destructor
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CSigTree::~CSigTree()
{
	RemoveAll();
}

/*--------------------------------------------------------------------------------------
Function       : Search
In Parameters  : ULONG64* pSig
Out Parameters : bool
Description    : search for a signature and return true if found
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSigTree::Search(ULONG64* pSig)
{
	bool bFound = false;

	m_pTemp = m_pRoot;
	while(!bFound && m_pTemp)
	{
		if(m_pTemp->ulSig > *pSig)
		{
			if(!m_pTemp->pLeft)
			{
				m_ppNewNode = &m_pTemp->pLeft;
			}

			m_pParent = m_pTemp;
			m_pTemp = m_pTemp->pLeft;
		}
		else if(m_pTemp->ulSig < *pSig)
		{
			if(!m_pTemp->pRite)
			{
				m_ppNewNode = &m_pTemp->pRite;
			}

			m_pParent = m_pTemp;
			m_pTemp = m_pTemp->pRite;
		}
		else
		{
			bFound = true;
		}
	}

	return bFound;
}

/*--------------------------------------------------------------------------------------
Function       : Add
In Parameters  : ULONG64* pSig, DWORD* pSpy
Out Parameters : bool
Description    : add one signature and spyid
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSigTree::Add(ULONG64* pSig, DWORD* pSpy)
{
	if(!m_pRoot)
	{
		m_pRoot = GetNode(pSig, pSpy);
		if(!m_pRoot)
		{
			return false;
		}
	}
	else
	{
		m_ppNewNode = NULL;

		if(Search(pSig))
		{
			return true;
		}

		if(!m_ppNewNode)
		{
			return false;
		}

		*m_ppNewNode = GetNode(pSig, pSpy);
		if(!(*m_ppNewNode))
		{
			return false;
		}
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : AddAtEnd
In Parameters  : ULONG64* pSig, DWORD* pSpy
Out Parameters : bool
Description    : add one signature and spyid at the end. used while live update.
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSigTree::AddAtEnd(ULONG64* pSig, DWORD* pSpy)
{
	if(!m_pRoot)
	{
		m_pRoot = GetNode(pSig, pSpy);
		if(!m_pRoot)
		{
			return false;
		}

		m_pTemp = m_pRoot;
	}
	else
	{
		m_pTemp->pRite = GetNode(pSig, pSpy);
		if(!m_pTemp->pRite)
		{
			return false;
		}

		m_pTemp = m_pTemp->pRite;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Del
In Parameters  : ULONG64* pSig
Out Parameters : bool
Description    : delete one signature from tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSigTree::Del(ULONG64* pSig)
{
	STNODE Pseudo_Root = {0};
	LPSTNODE pReplacementNode = NULL, pNextLink = NULL;

	Pseudo_Root.pRite = m_pRoot;
	m_pParent = &Pseudo_Root;
	if(!Search(pSig))
	{
		return true;
	}

	if(m_pTemp->pLeft && m_pTemp->pRite)
	{
		m_pParent = m_pTemp;
		pReplacementNode = m_pTemp->pLeft;
		while(pReplacementNode->pRite)
		{
			m_pParent = pReplacementNode;
			pReplacementNode = pReplacementNode->pRite;
		}

		m_pTemp->ulSig = pReplacementNode->ulSig;
		m_pTemp->dwSpy = pReplacementNode->dwSpy;
		m_pTemp = pReplacementNode;
	}

	pNextLink = m_pTemp->pLeft? m_pTemp->pLeft: m_pTemp->pRite? m_pTemp->pRite: NULL;
	if(m_pParent->pLeft == m_pTemp)
	{
		m_pParent->pLeft = pNextLink;
	}
	else
	{
		m_pParent->pRite = pNextLink;
	}

	m_pRoot = Pseudo_Root.pRite;
	FreeNode(m_pTemp);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetSmallest
In Parameters  : ULONG64* pSig, DWORD* pSpy
Out Parameters : bool
Description    : get the smallest signature and associated spyid
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSigTree::GetSmallest(ULONG64* pSig, DWORD* pSpy)
{
	if(!m_pRoot)
	{
		return false;
	}

	m_objPtrStk.RemoveAll();
	m_pTemp = m_pRoot;
	while(m_pTemp || !m_objPtrStk.IsEmpty())
	{
		if(m_pTemp)
		{
			m_objPtrStk.Push(m_pTemp);
			m_pTemp = m_pTemp->pLeft;
		}
		else
		{
			m_pTemp = (LPSTNODE) m_objPtrStk.Pop();
			break;
		}
	}

	if(pSig) *pSig = m_pTemp->ulSig;
	if(pSpy) *pSpy = m_pTemp->dwSpy;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetLarger
In Parameters  : ULONG64* pSig, DWORD* pSpy
Out Parameters : bool
Description    : get the next larger signature and associated spyid
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CSigTree::GetLarger(ULONG64* pSig, DWORD* pSpy)
{
	m_pTemp = m_pTemp->pRite;
	while(m_pTemp || !m_objPtrStk.IsEmpty())
	{
		if(m_pTemp)
		{
			m_objPtrStk.Push(m_pTemp);
			m_pTemp = m_pTemp->pLeft;
		}
		else
		{
			m_pTemp = (LPSTNODE) m_objPtrStk.Pop();
			break;
		}
	}

	if(!m_pTemp)
	{
		return false;
	}

	if(pSig) *pSig = m_pTemp->ulSig;
	if(pSpy) *pSpy = m_pTemp->dwSpy;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : RemoveAll
In Parameters  : 
Out Parameters : void
Description    : free all memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CSigTree::RemoveAll()
{
	int iCount = 0;

	m_objPtrStk.RemoveAll();
	m_pTemp = m_pRoot;
	while(m_pTemp)
	{
		if(m_pTemp->pLeft)
		{
			m_objPtrStk.Push(m_pTemp);
			m_pTemp = m_pTemp->pLeft;
		}
		else if(m_pTemp->pRite)
		{
			m_objPtrStk.Push(m_pTemp);
			m_pTemp = m_pTemp->pRite;
		}
		else
		{
			LPSTNODE pParent = (LPSTNODE)m_objPtrStk.Pop();

			if(pParent)
			{
				if(pParent->pLeft == m_pTemp)
				{
					pParent->pLeft = NULL;
				}
				else if(pParent->pRite == m_pTemp)
				{
					pParent->pRite = NULL;
				}
			}

			iCount++;
			FreeNode(m_pTemp);
			m_pTemp = pParent;
		}
	}

	m_ppNewNode = NULL;
	m_objPtrStk.RemoveAll();
	m_pRoot = m_pTemp = m_pParent = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : GetNode
In Parameters  : ULONG64* pSig, DWORD* pSpy
Out Parameters : LPSTNODE
Description    : allocate memory for one node and initialize it with given signature and spyid
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPSTNODE CSigTree::GetNode(ULONG64* pSig, DWORD* pSpy)
{
	LPSTNODE pTemp = (LPSTNODE)Allocate(sizeof(STNODE));
	if(pTemp)
	{
		pTemp->ulSig = *pSig;
		pTemp->dwSpy = *pSpy;
		pTemp->pLeft = NULL;
		pTemp->pRite = NULL;
	}

	return pTemp;
}

/*--------------------------------------------------------------------------------------
Function       : FreeNode
In Parameters  : LPSTNODE pNode
Out Parameters : void
Description    : release memory for a given node
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CSigTree::FreeNode(LPSTNODE pNode)
{
	Release((LPVOID&)pNode);
}

/*--------------------------------------------------------------------------------------
Function       : FullSize
In Parameters  : int size
Out Parameters : int
Description    : 
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CSigTree::FullSize(int size)
{
	int Rtn = 1;

	while(Rtn <= size)
	{
		Rtn = Rtn + Rtn + 1;
	}

	return Rtn / 2;
}

/*--------------------------------------------------------------------------------------
Function       : Compress
In Parameters  : LPSTNODE pRoot, int count
Out Parameters : void
Description    : 
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CSigTree::Compress(LPSTNODE pRoot, int count)
{
	LPSTNODE scanner = pRoot;

	for(int j = 0; j < count; j++)
	{
		LPSTNODE child = scanner->pRite;
		scanner->pRite = child->pRite;
		scanner = scanner->pRite;
		child->pRite = scanner->pLeft;
		scanner->pLeft = child;
	}
}

/*--------------------------------------------------------------------------------------
Function       : ConvertVineToTree
In Parameters  : LPSTNODE pRoot, int size
Out Parameters : void
Description    : create tree from a vine
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CSigTree::ConvertVineToTree(LPSTNODE pRoot, int size)
{
	int full_count = FullSize(size);
	Compress(pRoot, size - full_count);
	for(size = full_count; size > 1; size /= 2)
	{
		Compress(pRoot, size / 2);
	}
}

/*--------------------------------------------------------------------------------------
Function       : ConvertTreeToVine
In Parameters  : LPSTNODE pRoot, int &size
Out Parameters : void
Description    : create vine from a tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CSigTree::ConvertTreeToVine(LPSTNODE pRoot, int &size)
{
	LPSTNODE vineTail = 0;
	LPSTNODE remainder = 0;
	LPSTNODE tempPtr = 0;

	vineTail = pRoot;
	remainder = vineTail->pRite;
	size = 0;

	while(remainder != NULL)
	{
		if(remainder->pLeft == NULL)
		{
			vineTail = remainder;
			remainder = remainder->pRite;
			size++;
		}
		else
		{
			tempPtr = remainder->pLeft;
			remainder->pLeft = tempPtr->pRite;
			tempPtr->pRite = remainder;
			remainder = tempPtr;
			vineTail->pRite = tempPtr;
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : Balance
In Parameters  : 
Out Parameters : void
Description    : balance the tree
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CSigTree::Balance()
{
	int iCount = 0;
	STNODE Pseudo_Root = {0};

	Pseudo_Root.pRite = m_pRoot;
	ConvertTreeToVine(&Pseudo_Root, iCount);
	ConvertVineToTree(&Pseudo_Root, iCount);
	m_pRoot = Pseudo_Root.pRite;
}
