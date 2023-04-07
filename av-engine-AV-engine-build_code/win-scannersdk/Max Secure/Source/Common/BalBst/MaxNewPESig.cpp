#include "pch.h"
#include "MaxNewPESig.h"

CMaxNewPESig::CMaxNewPESig(int iMemToUseInMB)
{
	DWORD		dwDivisor = 0;
	SYSTEM_INFO SysInfo = {0};

	_tcscpy_s(m_szTempFilePath,MAX_PATH,L"");
	m_bMapReadOnly = false;
	m_hMapping = nullptr;
	m_hFile = INVALID_HANDLE_VALUE;
	m_bModified = false; 
	m_bDelEntry = false;
	m_dwPgTblArrCnt = 0;
	m_dwMaxPageSize = 0;
	m_dwPgTblCurIdx = 0;
	m_dwCurIdxInPage = 0x00;
	m_hHeapHadle = nullptr;
	m_dwCurDBIndex = 0x00;
	m_dwCurReadPos = 0x00;

	m_pPgTbl = nullptr;

	m_pHeapBuffer = nullptr;

	GetSystemInfo(&SysInfo);
	dwDivisor = iSMALLELEMENT_SIZE * SysInfo.dwAllocationGranularity;

	m_dwMaxPageSize = iMemToUseInMB * 1024 * 1024;
	m_dwMaxPageSize += dwDivisor - (m_dwMaxPageSize % dwDivisor);

	
}

CMaxNewPESig::~CMaxNewPESig(void)
{
	RemoveAll();
}

bool CMaxNewPESig::Load(LPCTSTR szFileName, bool bCheckVersion, bool bEncryptData, bool *pbDeleteIfFail)
{
	bool	bErrorOpenFile = false;

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

bool CMaxNewPESig::MakeMapFileObj(bool *pbErrorOpenFile)
{
	DWORD			dwTemp = 0x00;

	dwTemp = m_bMapReadOnly? GENERIC_READ: GENERIC_READ|GENERIC_WRITE;

	m_hFile = INVALID_HANDLE_VALUE;
	m_hFile = CreateFile(m_szTempFilePath, dwTemp, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == m_hFile)
	{
		if(pbErrorOpenFile)
		{
			*pbErrorOpenFile = true;
		}

		return false;
	}

	m_dwFileSize = 0x00;
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

		m_dwFileSize = iNEW_MAX_TEMP_FILE_SIZE;
	}

	dwTemp = m_bMapReadOnly? PAGE_READONLY: PAGE_READWRITE;
	m_hMapping = NULL;
	m_hMapping = CreateFileMapping(m_hFile, 0, dwTemp, 0, m_dwFileSize, NULL);
	if(!m_hMapping)
	{
		CloseHandle(m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
		return false;
	}

	return true;

}

bool CMaxNewPESig::MakePageTable()
{
	if((0 != m_dwFileSize) && (0 != (m_dwFileSize % iSMALLELEMENT_SIZE)))
	{
		AddLogEntry(L"Invalid file size");
		//TCHAR szLogLine[MAX_PATH] = {0x00};
		//_stprintf_s(szLogLine,MAX_PATH,_T("MakePageTable : File Size (%s) => %d"),m_szTempFilePath,m_dwFileSize);
		//AddLogEntry(szLogLine);
		return false;
	}

	m_dwPgTblArrCnt = m_dwFileSize / m_dwMaxPageSize;
	m_dwPgTblArrCnt += m_dwFileSize % m_dwMaxPageSize? 1 : 0;

	m_pPgTbl = (LPSMALLSIGPAGE)Allocate(sizeof(SMALLSIGPAGE) * m_dwPgTblArrCnt);
	if(NULL == m_pPgTbl)
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

		m_pPgTbl[i].dwMaxSigs = m_pPgTbl[i].dwPageLen / iSMALLELEMENT_SIZE;
		m_pPgTbl[i].dwUseSigs = m_bMapReadOnly? m_pPgTbl[i].dwMaxSigs: 0;
	}

	if(!MapPageOfTable(0))
	{
		return false;
	}

	return true;
}

bool CMaxNewPESig::MapPageOfTable(DWORD iPage)
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

bool CMaxNewPESig::MakeSigIndex()
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

bool CMaxNewPESig::Get(ULONG64* pSig, DWORD* pSpyID)
{
	LPBYTE			byPage = 0;
	unsigned char	szSigData[0x06] = {0x00};
	ULONG64			ulDummySig = 0x00;

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
		memcpy(&szSigData[0x00],(byPage + (m_dwCurIdxInPage * iSMALLELEMENT_SIZE)),iNEW_SIG_SIZE);
		//*pSig = *((ULONG64*)(&szSigData[0x00]));
		CMaxSmallPESig	objSmallSig;
		objSmallSig.GetUlongFromSz(&szSigData[0x00],&ulDummySig);

		*pSig = ulDummySig;
	}

	if(pSpyID)
	{
		*pSpyID = *((DWORD*)(byPage + (m_dwCurIdxInPage * iSMALLELEMENT_SIZE) + iNEW_SIG_SIZE));
	}

	return true;
}

int	CMaxNewPESig::GetPageIndex(ULONG64 pSig)
{
	int		iPageIdx = 0;
	DWORD	i = 0x00;

	if (m_dwPgTblArrCnt == 0x01)
	{
		//if(m_pPgTbl[i].ulFrstSig == m_pPgTbl[i].ulLastSig)
		if(m_pPgTbl[0].dwUseSigs == 0x01)
		{
			iPageIdx = 0;
			return iPageIdx;
		}
	}

	for(i = 0; i < m_dwPgTblArrCnt; i++)
	{
		if(pSig >= m_pPgTbl[i].ulFrstSig && pSig <= m_pPgTbl[i].ulLastSig)
		{
			iPageIdx = i;
			break;
		}
		if ((i+1) == m_dwPgTblArrCnt && pSig > m_pPgTbl[i].ulLastSig)
		{
			iPageIdx = i;
			break;
		}
		if (i < (m_dwPgTblArrCnt - 1))
		{
			if(pSig > m_pPgTbl[i].ulLastSig && pSig < m_pPgTbl[i+1].ulFrstSig)
			{
				iPageIdx = i;
				break;
			}
		}
		if (i == 0x00)
		{
			if(pSig < m_pPgTbl[i].ulFrstSig)
			{
				iPageIdx = i;
				break;
			}
		}
	}
	return iPageIdx; 
}

/*
bool CMaxNewPESig::SearchSig(PULONG64 pSig, LPDWORD pSpyID)
{
	bool			bFound = false;
	DWORD			iPageIdx = -1;
	LPSMALLELMNT	lpElmnt = NULL;
	int				iStart = 0, iEnd = 0, iSearch = 0;
	ULONG64			ulSig2Search = 0x00, ulSmallSig = 0x00, ulDummy = 0x00;
	unsigned char	szNewSig[0x06] = {0x00};
	CMaxSmallPESig	objNewSig;
	TCHAR			szLogLine[MAX_PATH] = {0x00};	
	bool			bLog = false;


	if(0 == pSig || 0 == *pSig)
	{
		return false;
	}

	ulSig2Search = *pSig;
	objNewSig.GetNewPESig(ulSig2Search,&szNewSig[0x00]);
	objNewSig.GetUlongFromSz(&szNewSig[0x00],&ulSmallSig);

	if(ulSmallSig == 0x00)
	{
		return false;
	}

	for(DWORD i = 0; i < m_dwPgTblArrCnt; i++)
	{

		if(ulSmallSig >= m_pPgTbl[i].ulFrstSig && ulSmallSig <= m_pPgTbl[i].ulLastSig)
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
	
	lpElmnt = (LPSMALLELMNT)m_pPgTbl[iPageIdx].lpPagePtr;
	if(!lpElmnt)
	{
		return false;
	}

	iStart = 0;
	iEnd = (int)(m_pPgTbl[iPageIdx].dwUseSigs - 1);
	
	while(iEnd >= iStart)
	{
		iSearch = (iEnd + iStart) / 2;

		if (lpElmnt[iSearch] != NULL)
		{
			objNewSig.GetUlongFromSz(&lpElmnt[iSearch].szPESig[0x00],&ulDummy); 
		}

		if(ulDummy > ulSmallSig)
		{
			iEnd = iSearch - 1;
		}
		else if(ulDummy < ulSmallSig)
		{
			iStart = iSearch + 1;
		}
		else
		{
			if (lpElmnt[iSearch].dwSpyID > 0x00)
			{
				bFound = true;
				if(pSpyID)
				{
					*pSpyID = lpElmnt[iSearch].dwSpyID;
				}
			}
			break;
		}
	}
	return bFound;
}
*/
bool CMaxNewPESig::SearchSig(PULONG64 pSig, LPDWORD pSpyID)
{
	bool			bFound = false;
	DWORD			iPageIdx = -1;
	LPSMALLELMNT	lpElmnt = NULL;
	int				iStart = 0, iEnd = 0, iSearch = 0;
	ULONG64			ulDummy = 0x00;
	CMaxSmallPESig	objNewSig;
	bool			bLog = false;
	ULONG64			ulSmallSig = *pSig;

	/*
	if(NULL == pszSig)
	{
		return false;
	}
	*/

	//objNewSig.GetUlongFromSz(pszSig,&ulSmallSig);

	if(ulSmallSig == 0x00)
	{
		return false;
	}

	for(DWORD i = 0; i < m_dwPgTblArrCnt; i++)
	{

		if(ulSmallSig >= m_pPgTbl[i].ulFrstSig && ulSmallSig <= m_pPgTbl[i].ulLastSig)
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
	
	lpElmnt = (LPSMALLELMNT)m_pPgTbl[iPageIdx].lpPagePtr;
	if(!lpElmnt)
	{
		return false;
	}

	iStart = 0;
	iEnd = (int)(m_pPgTbl[iPageIdx].dwUseSigs - 1);
	
	while(iEnd >= iStart)
	{
		iSearch = (iEnd + iStart) / 2;

		objNewSig.GetUlongFromSz(&lpElmnt[iSearch].szPESig[0x00],&ulDummy); 

		if(ulDummy > ulSmallSig)
		{
			iEnd = iSearch - 1;
		}
		else if(ulDummy < ulSmallSig)
		{
			iStart = iSearch + 1;
		}
		else
		{
			if (lpElmnt[iSearch].dwSpyID > 0x00)
			{
				bFound = true;
				if(pSpyID)
				{
					*pSpyID = lpElmnt[iSearch].dwSpyID;
				}
			}
			break;
		}
	}
	return bFound;
}
bool CMaxNewPESig::SearchSigEx(PULONG64 pSig, LPDWORD pSpyID)
{
	bool			bFound = false;
	DWORD			iPageIdx = -1;
	LPSMALLELMNT	lpElmnt = NULL;
	int				iStart = 0, iEnd = 0, iSearch = 0;
	ULONG64			ulDummy = 0x00;
	CMaxSmallPESig	objNewSig;
	bool			bLog = false;
	ULONG64			ulSmallSig = *pSig;

	/*
	if(NULL == pszSig)
	{
		return false;
	}
	*/

	//objNewSig.GetUlongFromSz(pszSig,&ulSmallSig);

	if(ulSmallSig == 0x00)
	{
		return false;
	}

	for(DWORD i = 0; i < m_dwPgTblArrCnt; i++)
	{

		if(ulSmallSig >= m_pPgTbl[i].ulFrstSig && ulSmallSig <= m_pPgTbl[i].ulLastSig)
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
	
	lpElmnt = (LPSMALLELMNT)m_pPgTbl[iPageIdx].lpPagePtr;
	if(!lpElmnt)
	{
		return false;
	}

	iStart = 0;
	iEnd = (int)(m_pPgTbl[iPageIdx].dwUseSigs - 1);
	
	while(iEnd >= iStart)
	{
		iSearch = (iEnd + iStart) / 2;

		objNewSig.GetUlongFromSz(&lpElmnt[iSearch].szPESig[0x00],&ulDummy); 

		if(ulDummy > ulSmallSig)
		{
			iEnd = iSearch - 1;
		}
		else if(ulDummy < ulSmallSig)
		{
			iStart = iSearch + 1;
		}
		else
		{
				bFound = true;
				if(pSpyID)
				{
					*pSpyID = lpElmnt[iSearch].dwSpyID;
				}
			break;
		}
	}
	return bFound;
}

bool CMaxNewPESig::SetTempPath(LPCTSTR szTempPath)
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

bool CMaxNewPESig::Save(LPCTSTR szFileName, bool bCheckVersion, bool bEncryptData)
{
	HANDLE	hFile = INVALID_HANDLE_VALUE;
	DWORD	dwBytesWritten = 0;
	DWORD	dwNewSize = 0x00;	
	int		iRetValue = 0x00;
	TCHAR	szTempFileName[MAX_PATH] = {0};
	bool	bSuccess = false;
	TCHAR	szLogLine[MAX_PATH] = {0x00};

	_stprintf_s(szTempFileName, _countof(szTempFileName), _T("%s.%08x"), szFileName, GetTickCount());
	hFile = CreateFile(szTempFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		_stprintf_s(szLogLine,MAX_PATH,_T("(Save) Create Failed : %s"),m_szTempFilePath);
		AddLogEntry(szLogLine);
		return false;
	}

	//Need to modify
	for(DWORD i = 0; i < m_dwPgTblArrCnt; i++)
	{
		if(0 == m_pPgTbl[i].dwUseSigs)
		{
			bSuccess = false;
			goto ERROR_EXIT;
		}

		if(!MapPageOfTable(i))
		{
			bSuccess = false;
			goto ERROR_EXIT;
		}


		dwNewSize = 0x00;

		iRetValue = BalancePageMemory(i,&dwNewSize);
		
		if (iRetValue == 0x00)
		{
			bSuccess = false;
			goto ERROR_EXIT;
		}

		if (iRetValue == 0x01)
		{
			if(!WriteFile(hFile, m_pPgTbl[i].lpPagePtr, m_pPgTbl[i].dwUseSigs * iSMALLELEMENT_SIZE, &dwBytesWritten, 0))
			{
				bSuccess = false;
				goto ERROR_EXIT;
			}
		}
		else
		{
			if(!WriteFile(hFile, m_pHeapBuffer, dwNewSize, &dwBytesWritten, 0))
			{
				bSuccess = false;
				goto ERROR_EXIT;
			}
			//Need to Free Heap Memory
		}
	}

	CloseHandle(hFile);
	hFile = INVALID_HANDLE_VALUE;

	RemoveAll();
	if(0 == MoveFileEx(szTempFileName, szFileName, MOVEFILE_REPLACE_EXISTING))
	{
		DeleteFile(szTempFileName);
		return false;
	}

	return true;

ERROR_EXIT:

	if(!bSuccess)
	{
		DeleteFile(szTempFileName);
		return false;
	}

	if(INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

	DeleteFile(szTempFileName);
	AddLogEntry(L"Error saving file, deleted: %s", szFileName);
	return false;
}

bool CMaxNewPESig::RemoveAll(bool bRemoveTree)
{

	FreePageTable();

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

	if (NULL != m_pHeapBuffer)
	{
		HeapFree(m_hHeapHadle,0x00,(LPVOID)m_pHeapBuffer);
		m_pHeapBuffer = NULL;
	}
	if (m_hHeapHadle != NULL)
	{
		HeapDestroy(m_hHeapHadle); 
		m_hHeapHadle = NULL;
	}

	m_pPgTbl = NULL;
	m_hMapping = NULL;
	m_bModified = false;
	m_dwPgTblCurIdx = -1;
	m_bMapReadOnly = false;
	m_hFile = INVALID_HANDLE_VALUE;
	m_dwCurIdxInPage = m_dwFileSize = m_dwPgTblArrCnt = 0;
	memset(m_szTempFilePath, 0, sizeof(m_szTempFilePath));

	m_dwCurReadPos = 0x00;

	return true;
}

bool CMaxNewPESig::FreePageTable()
{
	if(NULL != m_pPgTbl)
	{
		for(DWORD i = 0; i < m_dwPgTblArrCnt; i++)
		{
			if(NULL != m_pPgTbl[i].lpPagePtr)
			{
				UnmapViewOfFile(m_pPgTbl[i].lpPagePtr);
			}
		}

		Release((LPVOID&)m_pPgTbl);
		m_pPgTbl = NULL;
	}

	return true;
}

bool CMaxNewPESig::IsModified()
{
	return m_bModified;
}

int	CMaxNewPESig::GetNewMemoryPage()
{
	int		iReturn = 0x00;

	if (NULL == m_hHeapHadle)
	{
		m_hHeapHadle = HeapCreate(0x00, 6 * 1024 * 1024, 0x00);
		if (m_hHeapHadle == NULL)
		{
			return iReturn;
		}
		int		iHEAP_LFH = 0x02;
		if (!HeapSetInformation(m_hHeapHadle,HeapCompatibilityInformation,&iHEAP_LFH,sizeof(iHEAP_LFH)))
		{
			return iReturn;
		}
	}

	if (m_pHeapBuffer == NULL)
	{
		m_pHeapBuffer = (unsigned char *)HeapAlloc(m_hHeapHadle,HEAP_ZERO_MEMORY,(5 * 1024 * 1024));
		if (NULL == m_pHeapBuffer)
		{
			return iReturn;
		}
		iReturn = 0x01;
	}
	else
	{
		iReturn = 0x01;
	}

	return iReturn;
}

int	CMaxNewPESig::MergeInCurPage(DWORD dwPageIndex, DWORD *dwNewSize)
{
	/*
	int				iReturn = 0x00, iPageIndex = -1;
	bool			bFound = false, bIgnore = false, bAdd = false;
	DWORD			dwCurPageSize = 0x00, dwNewPageSize = 0x00, dwDestPtr = 0x00;
	DWORD			dwIncCnt = 0x00, dwSpyID = 0x00;
	int				dwReqPageID = 0x00;
	ULONG64			ulSig1 = 0x00, ulSig2 = 0x00, ulCurSig = 0x00;
	SMALLELMNT		objSigElement[0x02] = {0x00}, objCurSigElement = {0x00};
	unsigned char	*lpSrc = NULL, *lpDest = NULL, szNewSig[0x06] = {0x00};
	CMaxSmallPESig	objSmallSig;

	
	dwCurPageSize = m_pPgTbl[dwPageIndex].dwUseSigs * iSMALLELEMENT_SIZE;

	if (!GetItem(&szNewSig[0x00],&dwSpyID,&bAdd,&iPageIndex))
	{
		return 0x01;
	}
	objSmallSig.GetUlongFromSz(&szNewSig[0x00],&ulCurSig);

	lpSrc = (unsigned char *)m_pPgTbl[dwPageIndex].lpPagePtr;
	if (lpSrc == NULL)
	{
		return 0x00;
	}

	lpDest = m_pHeapBuffer;
	if (lpDest == NULL)
	{
		return 0x00;
	}

	while(1)
	{
		if (dwIncCnt >= dwCurPageSize || dwDestPtr >= dwCurPageSize)
		{
			break;
		}

		memset(&objSigElement,0x00,sizeof(SMALLELMNT) * 2);
		//lpSrc = (unsigned char *)m_pPgTbl[dwPageIndex].lpPagePtr;
		//lpSrc += dwIncCnt;

		if (bFound == true)
		{
			dwReqPageID = 0x00;
			dwReqPageID = GetNextInsertionIndex();
			if (dwReqPageID != dwPageIndex || dwReqPageID == -1)
			{
				bIgnore = true;
			}
			else
			{
				if (!GetItem(&szNewSig[0x00],&dwSpyID,&bAdd,&iPageIndex))
				{
					break;
				}
				objSmallSig.GetUlongFromSz(&szNewSig[0x00],&ulCurSig);
			}
			bFound = false;
		}

		memcpy(&objSigElement,&lpSrc[dwIncCnt],sizeof(SMALLELMNT) * 2);
		dwIncCnt+=(sizeof(SMALLELMNT) * 2);

		if (bIgnore == false)
		{
			objSmallSig.GetUlongFromSz(objSigElement[0x01].szPESig,&ulSig2);
			objSmallSig.GetUlongFromSz(objSigElement[0x00].szPESig,&ulSig1);
			if (ulSig2 > ulCurSig && ulSig1 < ulCurSig && bAdd == true)
			{
				memcpy(objCurSigElement.szPESig,&szNewSig[0x00],0x06);
				objCurSigElement.dwSpyID = dwSpyID;

				memcpy((LPVOID)(&lpDest[dwDestPtr]),&objSigElement[0x00],sizeof(SMALLELMNT));
				dwDestPtr+=sizeof(SMALLELMNT);
			
				memcpy((LPVOID)(&lpDest[dwDestPtr]),&objCurSigElement,sizeof(SMALLELMNT));
				dwDestPtr+=sizeof(SMALLELMNT);

				memcpy((LPVOID)(&lpDest[dwDestPtr]),&objSigElement[0x01],sizeof(SMALLELMNT));
				dwDestPtr+=sizeof(SMALLELMNT);

				bFound = true;
				continue;
			}
			else if(ulCurSig < ulSig1 && bAdd == true)
			{
				memcpy(objCurSigElement.szPESig,&szNewSig[0x00],0x06);
				objCurSigElement.dwSpyID = dwSpyID;

				memcpy((LPVOID)(&lpDest[dwDestPtr]),&objCurSigElement,sizeof(SMALLELMNT));
				dwDestPtr+=sizeof(SMALLELMNT);

				dwIncCnt-=(sizeof(SMALLELMNT) * 2);

				bFound = true;
				continue;
			}
			else if (bAdd == false)
			{
				if (ulCurSig == ulSig1)
				{
					objSigElement[0x00].dwSpyID = 0x00;
					bFound = true;
				}
				else if(ulCurSig == ulSig2)
				{
					objSigElement[0x01].dwSpyID = 0x00;
					bFound = true;
				}
			}
		}
		memcpy((LPVOID)(&lpDest[dwDestPtr]),&objSigElement,(sizeof(SMALLELMNT) * 2));
		dwDestPtr += (sizeof(SMALLELMNT) * 2);
	}

	*dwNewSize = dwDestPtr;
	*/
	return	0x02;
}

int	CMaxNewPESig::AppendInCurPage(DWORD dwPageIndex, DWORD *dwNewSize)
{
	/*
	int				iReturn = 0x00, iPageIndex = 0x00;
	unsigned char	*lpSrc = NULL, szNewSig[0x06] = {0x00}, *lpDest = NULL;
	bool			bAdd = false;
	DWORD			dwSpyID = 0x00, dwIncCnt = 0x00, dwDestPtr = 0x00;
	SMALLELMNT		objSigElement = {0x00}, objCurSigElement = {0x00};

	if (!m_objNewDeltaItems.GetItem(&szNewSig[0x00],&dwSpyID,&bAdd,&iPageIndex))
	{
		return iReturn;
	}

	lpSrc = (unsigned char *)m_pPgTbl[dwPageIndex].lpPagePtr;
	if (lpSrc == NULL)
	{
		return iReturn;
	}
	lpSrc += dwIncCnt;

	memcpy(&objSigElement,lpSrc,sizeof(SMALLELMNT));
	dwIncCnt+=sizeof(SMALLELMNT);

	
	lpDest = m_pHeapBuffer;
	memcpy((LPVOID)(lpDest),&objSigElement,sizeof(SMALLELMNT));
	//lpDest+=sizeof(SMALLELMNT);
	dwDestPtr+=sizeof(SMALLELMNT);

	if (lpDest == NULL)
	{
		return iReturn;
	}

	while(1)
	{
		memcpy(&objCurSigElement.szPESig[0x00],&szNewSig[0x00],0x06);
		objCurSigElement.dwSpyID = dwSpyID;

		
		memcpy((LPVOID)(&lpDest[dwDestPtr]),(LPVOID)&objCurSigElement,sizeof(SMALLELMNT));
		//lpDest+=sizeof(SMALLELMNT);
		dwDestPtr+=sizeof(SMALLELMNT);

		if (lpDest == NULL)
		{
			return iReturn;
		}

		iPageIndex = m_objNewDeltaItems.GetNextInsertionIndex();
		if (iPageIndex == -1 || iPageIndex != dwPageIndex)
		{
			break;
		}
		memset(&szNewSig[0x00],0x00,0x06);
		dwSpyID = 0x00;
		if (!m_objNewDeltaItems.GetItem(&szNewSig[0x00],&dwSpyID,&bAdd,&iPageIndex))
		{
			break;
		}
	}

	*dwNewSize = dwDestPtr;

	*/

	return 0x02; 
}

int	CMaxNewPESig::BalancePageMemory(DWORD dwPageIndex, DWORD *dwNewSize)
{
	int				iReturn = 0x00;
	int				dwReqPageID = 0x00;

	dwReqPageID = GetNextInsertionIndex();
	if (dwReqPageID != dwPageIndex)
	{
		return 0x01;
	}

	if (!GetNewMemoryPage())
	{
		return iReturn;
	}

	iReturn = CreateNewMergePage(dwPageIndex,dwNewSize);

	return iReturn;
}

int	CMaxNewPESig::CreateNewMergePage(DWORD dwPageIndex, DWORD *dwNewSize)
{
	DWORD			dwCurPageSize = 0x00, dwIncCnt = 0x00, dwDestPtr = 0x00,dwSpyID = 0x00;
	unsigned char	*lpSrc = NULL, *lpDest = NULL, szNewSig[0x06] = {0x00};
	SMALLELMNT		objSigElement = {0x00};
	CMaxQSort		objSigQueue(3);
	int				iPageIndex = -1, iReturn = 0x00;
	DWORD			dwSigCount = 0x00;
	bool			bAdd = false;
	bool			bFirstSigWritten = false;
	TCHAR			szLogLine[1024] = {0x00};


	dwCurPageSize = m_pPgTbl[dwPageIndex].dwUseSigs * iSMALLELEMENT_SIZE;

	if (dwCurPageSize == 0x00)
	{
		return iReturn;
	}

	lpSrc = (unsigned char *)m_pPgTbl[dwPageIndex].lpPagePtr;
	if (lpSrc == NULL)
	{
		return iReturn;
	}
	
	while(1)
	{
		if (dwIncCnt >= dwCurPageSize)
		{
			break;
		}
		memcpy(&objSigElement,&lpSrc[dwIncCnt],sizeof(SMALLELMNT));
		dwIncCnt+=(sizeof(SMALLELMNT));

		dwSigCount++;
		if (dwSigCount > 0x500)
		{
			dwSigCount = 0x00;
			Sleep(10);
		}

		if (!objSigQueue.InsertItem(objSigElement.szPESig,objSigElement.dwSpyID,true,0))
		{
			break;
		}
	}

	/*
	/*try
	{*/
		while(1)
		{
			iPageIndex = GetNextInsertionIndex();
			if (iPageIndex == -1)
			{
				break;
			}

			if (iPageIndex != dwPageIndex)
			{
				break;
			}

			if (!GetItem(&szNewSig[0x00],&dwSpyID,&bAdd,&iPageIndex))
			{
				break;
			}

			if (!objSigQueue.InsertItem(&szNewSig[0x00],dwSpyID,bAdd,iPageIndex))
			{
				break;
			}
			objSigQueue.m_bLog = false;
			dwSigCount++;
		}
	/*}
	catch(...)
	{
		_stprintf_s(szLogLine,MAX_PATH,_T("CMaxNewPESig : Signature Returned From QUEUE CATCH = %d"), dwSigCount);
		AddLogEntry(szLogLine);
		return 0x00;
	}*/


	Sleep(25);

	lpDest = m_pHeapBuffer;
	if (NULL == lpDest)
	{
		return 0x01;
	}

	dwSigCount = 0x00;	

	while(1)
	{
		if (dwDestPtr >= (5 * 1024 * 1024))
		{
			break;
		}

		if (!objSigQueue.GetItem(&objSigElement.szPESig[0x00],&objSigElement.dwSpyID,&bAdd,&iPageIndex))
		{
			break;
		}

		if (objSigElement.dwSpyID == 0x00 && bFirstSigWritten != false)
		{
			continue;
		}
		bFirstSigWritten = true;
		memcpy((LPVOID)(&lpDest[dwDestPtr]),&objSigElement,sizeof(SMALLELMNT));
		dwDestPtr+=sizeof(SMALLELMNT);

		dwSigCount++;
	}

	*dwNewSize = dwDestPtr;

	return 0x02; 
}

bool CMaxNewPESig::InsertItem(unsigned char *pszSig, DWORD dwSpyID, bool bAdd, int iPageIndex)
{
	bool	bRet = false;
	int		iIndex = 0x00;
	
	if (NULL == pszSig)
	{
		return bRet;
	}
	
	iIndex = pszSig[0x00] % 0x10;

	bRet = m_NewSigs[iIndex].InsertItem(pszSig,dwSpyID,bAdd,iPageIndex);
	m_NewSigs[iIndex].m_bLog = false;

	return bRet;
}

bool CMaxNewPESig::GetItem(unsigned char *pszSig, DWORD *pdwSpyID, bool *pbAdd, int *piPageIndex)
{
	bool	bRet = false;

	while(1)
	{
		if (m_NewSigs[m_dwCurDBIndex].GetNextInsertionIndex() == -1)
		{
			m_dwCurDBIndex++;
			if (m_dwCurDBIndex >= 0x10)
			{
				return bRet;
			}
		}
		else
		{
			break;
		}
	}
	bRet = m_NewSigs[m_dwCurDBIndex].GetItem(pszSig,pdwSpyID,pbAdd,piPageIndex);

	return bRet;
}

int	 CMaxNewPESig::GetNextInsertionIndex()
{
	int		iRet = -1;
	while(1)
	{
		iRet = m_NewSigs[m_dwCurDBIndex].GetNextInsertionIndex();
		if (iRet == -1)
		{
			m_dwCurDBIndex++;
			if (m_dwCurDBIndex >= 0x10)
			{
				return iRet;
			}
		}
		else
		{
			break;
		}
	}
	
	return iRet;
}

DWORD CMaxNewPESig::GetSigBuff4Insertion(unsigned char *pszBuff,DWORD	dwBuffSize)
{
	DWORD	dwReturn = 0x00;
	TCHAR	szLogLine[MAX_PATH] = {0x00}; 
	DWORD	dwBytes2Read = false;

	if (NULL == pszBuff || dwBuffSize == 0x00)
	{
		return dwReturn;
	}
	
	if (m_dwFileSize == 0x00)
	{
		return dwReturn;
	}
	if ((m_dwFileSize % iSMALLELEMENT_SIZE) != 0x00)
	{
		return dwReturn;
	}

	if (m_dwCurReadPos > m_dwFileSize)
	{
		return dwReturn;
	}

	dwBytes2Read = m_dwFileSize - m_dwCurReadPos;
	if (dwBytes2Read > dwBuffSize)
	{
		dwBytes2Read = dwBuffSize;
	}

	ReadFile(m_hFile,pszBuff,dwBytes2Read,&dwReturn,NULL);
	m_dwCurReadPos+=dwReturn;

	return dwReturn;
}
bool CMaxNewPESig::GetFirst(PULONG64 pSig, LPDWORD pSpyID)
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
bool CMaxNewPESig::GetNext(PULONG64 pSig, LPDWORD pSpyID)
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