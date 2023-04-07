#include "pch.h"
#include "BSArray.h"

BYTE HEADER_BSARRAY[24]			= {"MAXDBVERSION00.00.00.10"};
BYTE HEADER_BSARRAY_DATA[24]	= {0};

CBSArray::CBSArray(DWORD dwKeySize, DWORD dwDataSize, int iNumberSize)
{
	SYSTEM_INFO SysInfo = {0};
	DWORD dwMod = 0, dwMultiple = 0;

	m_bByte = sizeof(BYTE) == iNumberSize;
	m_bWord = sizeof(WORD) == iNumberSize;
	m_bDWord = sizeof(DWORD) == iNumberSize;
	m_bQWord = sizeof(ULONG64) == iNumberSize;
	m_bModified = false;
	m_bObjectMerging = false;

	m_dwKeySize = dwKeySize;
	m_dwDataSize = dwDataSize;
	m_dwItemSize = m_dwKeySize + m_dwDataSize;

	m_lpArray = NULL;
	m_dwArrayMaxSize = 0;
	m_dwArrayUseSize = 0;

	m_dwMaxMemory = 100 * 1024 * 1024;
	m_dwPageSize = 10 * 1024 * 1024;
	m_dwPageCount = 0;

	GetSystemInfo(&SysInfo);

	dwMultiple = SysInfo.dwPageSize * m_dwItemSize;
	dwMod = m_dwMaxMemory % dwMultiple;
	if(dwMod)
	{
		m_dwMaxMemory += dwMultiple - dwMod;
	}

	dwMod = m_dwPageSize % dwMultiple;
	if(dwMod)
	{
		m_dwPageSize += dwMultiple - dwMod;
	}
}

CBSArray::~CBSArray()
{
	RemoveAll();
}

bool CBSArray::AddMemPage()
{
	LPVOID lpMemory = 0;

	if(!m_lpArray)
	{
		m_lpArray = (LPBYTE) VirtualAlloc(0, m_dwMaxMemory, MEM_RESERVE, PAGE_READWRITE);
		if(!m_lpArray)
		{
			return false;
		}
	}

	if((m_dwPageSize * (m_dwPageCount + 1)) > m_dwMaxMemory)
	{
		return false;
	}

	lpMemory = VirtualAlloc(m_lpArray + (m_dwPageSize * m_dwPageCount), m_dwPageSize, MEM_COMMIT, PAGE_READWRITE);
	if(!lpMemory)
	{
		return false;
	}

	m_dwPageCount++;
	m_dwArrayMaxSize += m_dwPageSize / m_dwItemSize;
	m_objPages.Push(lpMemory);
	return true;
}

bool CBSArray::AddRequiredMemPages(DWORD dwMemSize)
{
	bool bSuccess = true;

	for(DWORD i = 0, iTotal = (dwMemSize / m_dwPageSize) + 1; i < iTotal; i++)
	{
		if(!AddMemPage())
		{
			bSuccess = false;
			break;
		}
	}

	return bSuccess;
}

LPBYTE CBSArray::GetAt(DWORD dwIndex)
{
	LPBYTE lpItem = NULL;

	if(m_lpArray && m_dwArrayUseSize && (dwIndex < m_dwArrayUseSize))
	{
		lpItem = m_lpArray + (m_dwItemSize * dwIndex);
	}

	return lpItem;
}

bool CBSArray::SetAt(DWORD dwIndex, LPVOID lpKey, LPVOID lpData)
{
	bool bSet = false;

	if(m_lpArray && m_dwArrayUseSize && (dwIndex < m_dwArrayUseSize))
	{
		bSet = true;
		memcpy(m_lpArray + (m_dwItemSize * dwIndex), lpKey, m_dwKeySize);
		memcpy(m_lpArray + (m_dwItemSize * dwIndex) + m_dwKeySize, lpData, m_dwDataSize);
	}

	return bSet;
}

bool CBSArray::InsertAt(DWORD dwIndex, LPVOID lpKey, LPVOID lpData)
{
	LPBYTE lpSource = 0, lpDest = 0;
	DWORD dwSize = 0;

	if(!AppendItemAscOrder(lpKey, lpData))
	{
		return false;
	}

	if(!m_lpArray || !m_dwArrayUseSize || ((dwIndex + 1) >= m_dwArrayUseSize))
	{
		return false;
	}

	lpSource = m_lpArray + (m_dwItemSize * dwIndex);
	lpDest = lpSource + m_dwItemSize;
	dwSize = (m_dwArrayUseSize - dwIndex - 1) * m_dwItemSize;
	memmove(lpDest, lpSource, dwSize);
	memcpy(m_lpArray + (m_dwItemSize * dwIndex), lpKey, m_dwKeySize);
	memcpy(m_lpArray + (m_dwItemSize * dwIndex) + m_dwKeySize, lpData, m_dwDataSize);
	return true;
}

DWORD CBSArray::LocateInsertPosition(LPVOID lpKey, DWORD dwStart, DWORD dwEnd, DWORD dwHop)
{
	bool bFoundLarge = false;
	LPBYTE lpItem = 0;
	DWORD dwIndex = 0, dwPrev = 0;

	for(dwIndex = dwStart, dwPrev = dwStart; dwIndex <= dwEnd; dwIndex += dwHop)
	{
		lpItem = GetAt(dwIndex);
		if(!lpItem)
		{
			break;
		}

		if(LARGE == Compare(lpItem, lpKey))
		{
			bFoundLarge = true;
			break;
		}

		dwPrev = dwIndex;
	}

	if(!lpItem)
	{
		return MAXDWORD;
	}

	if(1 == dwHop)
	{
		return dwIndex;
	}
	else
	{
		if((dwEnd - dwPrev) >= dwHop)
		{
			dwIndex = dwPrev + (dwHop -1);
		}
		else
		{
			dwIndex = dwPrev + (dwEnd - dwPrev);
		}

		return LocateInsertPosition(lpKey, dwPrev, dwIndex, dwHop / 10);
	}
}

COMPARE_RESULT CBSArray::Compare(LPVOID lpKey1, LPVOID lpKey2)
{
	COMPARE_RESULT Result = EQUAL;

	if(m_bByte)
	{
		BYTE by1 = *((LPBYTE)lpKey1);
		BYTE by2 = *((LPBYTE)lpKey2);
		Result = by1 > by2 ? LARGE : by1 < by2 ? SMALL : EQUAL;
	}
	else if(m_bWord)
	{
		WORD w1 = *((LPWORD)lpKey1);
		WORD w2 = *((LPWORD)lpKey2);
		Result = w1 > w2 ? LARGE : w1 < w2 ? SMALL : EQUAL;
	}
	else if(m_bDWord)
	{
		DWORD dw1 = *((LPDWORD)lpKey1);
		DWORD dw2 = *((LPDWORD)lpKey2);
		Result = dw1 > dw2 ? LARGE : dw1 < dw2 ? SMALL : EQUAL;
	}
	else if(m_bQWord)
	{
		ULONG64 ul1 = *((PULONG64)lpKey1);
		ULONG64 ul2 = *((PULONG64)lpKey2);
		Result = ul1 > ul2 ? LARGE : ul1 < ul2 ? SMALL : EQUAL;
	}
	else
	{
		LPBYTE pbyKey1 = (LPBYTE)lpKey1;
		LPBYTE pbyKey2 = (LPBYTE)lpKey2;

		Result = EQUAL;
		for(DWORD i = 0; i < m_dwKeySize; i++)
		{
			if(pbyKey1[i]< pbyKey2[i])
			{
				Result = SMALL;
				break;
			}
			else if(pbyKey1[i]> pbyKey2[i])
			{
				Result = LARGE;
				break;
			}
		}
	}

	return Result;
}

bool CBSArray::SearchItem(LPVOID lpKey, LPVOID& lpData)
{
	bool bFound = false;
	__int64 dwStartIndex = 0, dwEndIndex = 0;
	COMPARE_RESULT Result = EQUAL;

	m_dwLastSearchIndex = 0;
	if(0 >= m_dwArrayUseSize)
	{
		return false;
	}

	if(!m_bObjectMerging)
	{
		if(sizeof(ULONG64) == m_dwKeySize)
		{
			ULONG64* lpUlong64 = (ULONG64*)lpKey;
			*lpUlong64 = REV_BYT_ODR_QWORD(*lpUlong64);
		}
	}

	dwStartIndex = 0;
	dwEndIndex = m_dwArrayUseSize - 1;

	while(!bFound && (dwEndIndex >= dwStartIndex))
	{
		m_dwLastSearchIndex = (DWORD)((dwEndIndex + dwStartIndex) / 2);

		Result = Compare(m_lpArray + (m_dwItemSize * m_dwLastSearchIndex), lpKey);
		if(LARGE == Result)
		{
			dwEndIndex = ((__int64)m_dwLastSearchIndex) - 1;
		}
		else if(SMALL == Result)
		{
			dwStartIndex = ((__int64)m_dwLastSearchIndex) + 1;
		}
		else
		{
			lpData = m_lpArray + (m_dwItemSize * m_dwLastSearchIndex) + m_dwKeySize;
			bFound = true;
		}
	}

	return bFound;
}

bool CBSArray::AppendItemAscOrder(LPVOID lpKey, LPVOID lpData)
{
	if(m_dwArrayUseSize >= m_dwArrayMaxSize)
	{
		AddMemPage();
	}

	if(m_dwArrayUseSize >= m_dwArrayMaxSize)
	{
		return false;
	}

	memcpy(m_lpArray + (m_dwArrayUseSize * m_dwItemSize), lpKey, m_dwKeySize);
	memcpy(m_lpArray + (m_dwArrayUseSize * m_dwItemSize) + m_dwKeySize, lpData, m_dwDataSize);
	m_dwArrayUseSize++;
	m_bModified = true;
	return true;
}

bool CBSArray::AppendItem(LPVOID lpKey, LPVOID lpData)
{
	DWORD dwIndex = 0;
	LPVOID lpSearchData = NULL;

	if(SearchItem(lpKey, lpSearchData))
	{
		return false;
	}

	dwIndex = LocateInsertPosition(lpKey, 0, m_dwArrayUseSize - 1, 100000);
	if(MAXDWORD == dwIndex)
	{
		return false;
	}

	if(dwIndex >= m_dwArrayUseSize)
	{
		if(!AppendItemAscOrder(lpKey, lpData))
		{
			return false;
		}
	}
	else
	{
		if(!InsertAt(dwIndex, lpKey, lpData))
		{
			return false;
		}
	}

	m_bModified = true;
	return true;
}

bool CBSArray::UpdateItem(LPVOID lpKey, LPVOID lpData)
{
	if(!m_lpLastSearchResult || (EQUAL != Compare(m_lpLastSearchResult, lpKey)))
	{
		LPVOID lpData = NULL;

		if(!SearchItem(lpKey, lpData))
		{
			return false;
		}
	}

	if(!m_lpLastSearchResult || (EQUAL != Compare(m_lpLastSearchResult, lpKey)))
	{
		return false;
	}

	m_bModified = true;
	memcpy(m_lpLastSearchResult + m_dwKeySize, lpData, m_dwDataSize);
	return true;
}

bool CBSArray::DeleteItem(LPVOID lpKey)
{
	LPBYTE lpSearchData = NULL;
	LPBYTE lpSrc = 0, lpDest = 0;
	DWORD dwSize = 0;

	if(!SearchItem(lpKey, (LPVOID&)lpSearchData))
	{
		return false;
	}

	lpSearchData = GetAt(m_dwLastSearchIndex);
	if(!lpSearchData)
	{
		return false;
	}

	if(EQUAL != Compare(lpSearchData, lpKey))
	{
		return false;
	}

	if(!m_lpArray || !m_dwArrayUseSize || (m_dwLastSearchIndex >= m_dwArrayUseSize))
	{
		return false;
	}

	lpSrc = m_lpArray + (m_dwItemSize * (m_dwLastSearchIndex + 1));
	lpDest = m_lpArray + (m_dwItemSize * m_dwLastSearchIndex);
	dwSize = m_dwItemSize * (m_dwArrayUseSize - m_dwLastSearchIndex -1);
	memmove(lpDest, lpSrc, dwSize);
	m_dwArrayUseSize--;
	m_bModified = true;
	return true;
}

DWORD CBSArray::GetCount()
{
	return m_dwArrayUseSize;
}

LPVOID CBSArray::GetFirst()
{
	return m_lpArray;
}

LPVOID CBSArray::GetNext(LPVOID lpContext)
{
	DWORD dwCurrentIndex = 0;
	LPBYTE byCurrent = (LPBYTE)lpContext;
	SIZE_T ulDifference = 0;
	LPVOID lpNext = 0;

	if(!lpContext)
	{
		return NULL;
	}

	ulDifference = byCurrent - m_lpArray;
	dwCurrentIndex = ((DWORD)ulDifference)  / m_dwItemSize;
	dwCurrentIndex++;

	if(dwCurrentIndex >= m_dwArrayUseSize)
	{
		return NULL;
	}

	lpNext = m_lpArray + (m_dwItemSize * dwCurrentIndex);
	return lpNext;
}

bool CBSArray::GetKey(LPVOID lpContext, LPVOID& lpKey)
{
	if(!lpContext)
	{
		return false;
	}

	lpKey = lpContext;
	return true;
}

bool CBSArray::GetData(LPVOID lpContext, LPVOID& lpData)
{
	if(!lpContext)
	{
		return false;
	}

	lpData = ((LPBYTE)lpContext) + m_dwKeySize;
	return true;
}

bool CBSArray::RemoveAll()
{
	while(!m_objPages.IsEmpty())
	{
		LPVOID lpMemory = m_objPages.Pop();
		if(lpMemory)
		{
			VirtualFree(lpMemory, m_dwPageSize, MEM_DECOMMIT);
		}
	}

	if(m_lpArray)
	{
		VirtualFree(m_lpArray, 0, MEM_RELEASE);
	}

	m_lpArray = NULL;
	m_dwArrayMaxSize = 0;
	m_dwArrayUseSize = 0;
	m_dwPageCount = 0;
	return true;
}

void CBSArray::Balance()
{
}

bool CBSArray::IsModified()
{
	return m_bModified;
}

bool CBSArray::AppendObject(CBSArray& objToAdd)
{
	LPVOID lpContext = NULL;
	LPBYTE lpKey = 0, lpData = 0;

	m_bObjectMerging = true;

	lpContext = objToAdd.GetFirst();
	while(lpContext)
	{
		objToAdd.GetKey(lpContext, (LPVOID&)lpKey);
		objToAdd.GetData(lpContext, (LPVOID&)lpData);

		if(lpKey && lpData)
		{
			AppendItem(lpKey, lpData);
		}

		lpContext = objToAdd.GetNext(lpContext);
	}

	m_bObjectMerging = false;
	return true;
}

bool CBSArray::DeleteObject(CBSArray& objToDel)
{
	LPVOID lpContext = NULL;
	LPBYTE lpKey = 0, lpData = 0;

	m_bObjectMerging = true;

	lpContext = objToDel.GetFirst();
	while(lpContext)
	{
		objToDel.GetKey(lpContext, (LPVOID&)lpKey);
		objToDel.GetData(lpContext, (LPVOID&)lpData);

		if(lpKey && lpData)
		{
			DeleteItem(lpKey);
		}

		lpContext = objToDel.GetNext(lpContext);
	}

	m_bObjectMerging = false;
	return true;
}

bool CBSArray::SetModified(bool bModified)
{
	m_bModified = bModified;
	return true;
}

bool CBSArray::SearchObject(CBSArray& objToSearch, bool bAllPresent)
{
	return true;
}

bool CBSArray::Load(LPCTSTR szFileName, bool bCheckVersion, bool bEncryptData)
{
	HANDLE hFile = NULL;
	DWORD dwFileSize = 0, dwBytesRead = 0;
	TCHAR szFullFileName[MAX_PATH]={0};
	ULONG64 ulCount = 0;
	BYTE byHdrBfr[sizeof(HEADER_BSARRAY) + sizeof(HEADER_BSARRAY_DATA)] ={0};

	RemoveAll();

	if(!MakeFullFilePath(szFileName, szFullFileName, _countof(szFullFileName)))
	{
		return false;
	}

	hFile = CreateFile(szFullFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	if(!ReadFile(hFile, byHdrBfr, sizeof(byHdrBfr), &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_BSARRAY_DATA, sizeof(HEADER_BSARRAY_DATA)))
	{
		goto ERROR_EXIT;
	}

	if(bCheckVersion && memcmp(HEADER_BSARRAY, byHdrBfr, sizeof(HEADER_BSARRAY)))
	{
		goto ERROR_EXIT;
	}

	if(memcmp(byHdrBfr + sizeof(HEADER_BSARRAY), HEADER_BSARRAY_DATA, 8 + 8))
	{
		goto ERROR_EXIT;
	}

	memcpy(&ulCount, byHdrBfr + sizeof(HEADER_BSARRAY) + 8 + 8, sizeof(ulCount));
	if(0 == ulCount)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
		return true;
	}

	m_dwArrayUseSize = (DWORD)ulCount;

	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(byHdrBfr))
	{
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(byHdrBfr);
	if(dwFileSize != (m_dwArrayUseSize * m_dwItemSize))
	{
		goto ERROR_EXIT;
	}

	dwFileSize = m_dwArrayUseSize * m_dwItemSize;
	if(!AddRequiredMemPages(dwFileSize))
	{
		goto ERROR_EXIT;
	}

	if(NULL == m_lpArray)
	{
		goto ERROR_EXIT;
	}

	if(!ReadFile(hFile, m_lpArray, dwFileSize, &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(dwFileSize != dwBytesRead)
	{
		goto ERROR_EXIT;
	}

	CloseHandle(hFile);
	hFile = INVALID_HANDLE_VALUE;

	if(bEncryptData && !CryptBuffer(m_lpArray, dwFileSize))
	{
		goto ERROR_EXIT;
	}

	return true;

ERROR_EXIT:

	if(hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}

	RemoveAll();
	AddLogEntry(L"Error loading file: %s", szFullFileName);
	return false;
}

bool CBSArray::Save(LPCTSTR szFileName, bool bCheckVersion, bool bEncryptData)
{
	HANDLE hFile = 0;
	DWORD dwBytesWritten = 0;
	BYTE byHdrBfr[sizeof(HEADER_BSARRAY) + sizeof(HEADER_BSARRAY_DATA)] = {0};

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

	if(!WriteFile(hFile, m_lpArray, (m_dwKeySize + m_dwDataSize) * m_dwArrayUseSize, &dwBytesWritten, 0))
	{
		goto ERROR_EXIT;
	}

	if(bEncryptData && !CryptFileData(hFile, sizeof(byHdrBfr)))
	{
		goto ERROR_EXIT;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0, 0, FILE_BEGIN))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFileName, HEADER_BSARRAY_DATA, sizeof(HEADER_BSARRAY_DATA), m_dwArrayUseSize))
	{
		goto ERROR_EXIT;
	}

	memcpy(byHdrBfr, HEADER_BSARRAY, sizeof(HEADER_BSARRAY));
	memcpy(byHdrBfr + sizeof(HEADER_BSARRAY), HEADER_BSARRAY_DATA, sizeof(HEADER_BSARRAY_DATA));

	if(!WriteFile(hFile, byHdrBfr, sizeof(byHdrBfr), &dwBytesWritten, 0))
	{
		goto ERROR_EXIT;
	}

	CloseHandle(hFile);
	return true;

ERROR_EXIT:

	if(INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
	}

	DeleteFile(szFileName);
	AddLogEntry(L"Error saving file, deleted: %s", szFileName);
	return false;
}
