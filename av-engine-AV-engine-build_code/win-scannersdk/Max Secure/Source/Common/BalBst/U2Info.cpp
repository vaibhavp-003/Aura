#include "pch.h"
#include "U2Info.h"

BYTE HEADER_U2INFO[24]		= {"MAXDBVERSION00.00.00.09"};
BYTE HEADER_U2INFO_DATA[24]	= {0};

CU2Info::CU2Info(bool bIsEmbedded):CBalBSTOpt(bIsEmbedded)
{
}

CU2Info::~CU2Info(void)
{
	RemoveAll();
}

COMPARE_RESULT CU2Info::Compare(SIZE_T nKey1, SIZE_T nKey2)
{
	if(nKey1 < nKey2)
	{
		return SMALL;
	}
	else if(nKey1 > nKey2)
	{
		return LARGE;
	}
	else
	{
		return EQUAL;
	}
}

void CU2Info::FreeKey(SIZE_T nKey)
{
}

void CU2Info::FreeData(SIZE_T nData)
{
	SIZE_T nTemp = 0;
	LPSPY_ENTRY_INFO lpSpyInfo = (LPSPY_ENTRY_INFO)nData;

	nTemp = (SIZE_T)lpSpyInfo->szSpyName;
	if(((LPBYTE)nTemp < m_pBuffer) ||((LPBYTE)nTemp >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)nTemp);
	}

	nTemp = (SIZE_T)lpSpyInfo->szKey;
	if(((LPBYTE)nTemp < m_pBuffer) ||((LPBYTE)nTemp >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)nTemp);
	}

	nTemp = (SIZE_T)lpSpyInfo->szValue;
	if(((LPBYTE)nTemp < m_pBuffer) ||((LPBYTE)nTemp >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)nTemp);
	}

	nTemp = (SIZE_T)lpSpyInfo->szBackupFileName;
	if(((LPBYTE)nTemp < m_pBuffer) ||((LPBYTE)nTemp >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)nTemp);
	}

	nTemp = (SIZE_T)lpSpyInfo->byData;
	if(((LPBYTE)nTemp < m_pBuffer) ||((LPBYTE)nTemp >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)nTemp);
	}

	nTemp = (SIZE_T)lpSpyInfo->byReplaceData;
	if(((LPBYTE)nTemp < m_pBuffer) ||((LPBYTE)nTemp >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)nTemp);
	}

	if(((LPBYTE)nData < m_pBuffer) ||((LPBYTE)nData >= m_pBuffer + m_nBufferSize))
	{
		Release((LPVOID&)nData);
	}
}

bool CU2Info::GetKey(PVOID lpContext, DWORD& dwKey)
{
	if(!lpContext)
	{
		return false;
	}

	dwKey = (DWORD)(((PNODEOPT)lpContext)->nKey);
	return true;
}

bool CU2Info::GetData(PVOID lpContext, LPSPY_ENTRY_INFO& lpSpyInfo)
{
	if(!lpContext)
	{
		return false;
	}

	lpSpyInfo = (LPSPY_ENTRY_INFO&)(((PNODEOPT)lpContext)->nData);
	return true;
}

LPSPY_ENTRY_INFO CU2Info::DuplicateSpyInfo(LPSPY_ENTRY_INFO lpSpyInfo)
{
	LPSPY_ENTRY_INFO lpSpyInfoDup = 0;

	if(!lpSpyInfo)
	{
		return lpSpyInfoDup;
	}

	lpSpyInfoDup = (LPSPY_ENTRY_INFO)Allocate(sizeof(SPY_ENTRY_INFO));
	if(!lpSpyInfoDup)
	{
		return lpSpyInfoDup;
	}

	memcpy(lpSpyInfoDup, lpSpyInfo, SIZE_OF_STATIC_DATA);
	lpSpyInfoDup->szSpyName = DuplicateString(lpSpyInfo->szSpyName);
	lpSpyInfoDup->szKey = DuplicateString(lpSpyInfo->szKey);
	lpSpyInfoDup->szValue = DuplicateString(lpSpyInfo->szValue);
	lpSpyInfoDup->szBackupFileName = DuplicateString(lpSpyInfo->szBackupFileName);
	lpSpyInfoDup->byData = DuplicateBuffer(lpSpyInfo->byData, lpSpyInfo->dwRegDataSize);
	lpSpyInfoDup->byReplaceData = DuplicateBuffer(lpSpyInfo->byReplaceData, lpSpyInfo->dwReplaceRegDataSize);

	if(!lpSpyInfoDup->szSpyName && lpSpyInfo->szSpyName) goto ERROR_EXIT;
	if(!lpSpyInfoDup->szKey && lpSpyInfo->szKey) goto ERROR_EXIT;
	if(!lpSpyInfoDup->szValue && lpSpyInfo->szValue) goto ERROR_EXIT;
	if(!lpSpyInfoDup->szBackupFileName && lpSpyInfo->szBackupFileName) goto ERROR_EXIT;
	if(!lpSpyInfoDup->byData && lpSpyInfo->byData) goto ERROR_EXIT;
	if(!lpSpyInfoDup->byReplaceData && lpSpyInfo->byReplaceData) goto ERROR_EXIT;

	return lpSpyInfoDup;

ERROR_EXIT:

	if(lpSpyInfoDup)
	{
		if(lpSpyInfoDup->szSpyName) Release((LPVOID&)lpSpyInfoDup->szSpyName);
		if(lpSpyInfoDup->szKey) Release((LPVOID&)lpSpyInfoDup->szKey);
		if(lpSpyInfoDup->szValue) Release((LPVOID&)lpSpyInfoDup->szValue);
		if(lpSpyInfoDup->szBackupFileName) Release((LPVOID&)lpSpyInfoDup->szBackupFileName);
		if(lpSpyInfoDup->byData) Release((LPVOID&)lpSpyInfoDup->byData);
		if(lpSpyInfoDup->byReplaceData) Release((LPVOID&)lpSpyInfoDup->byReplaceData);
		Release((LPVOID&)lpSpyInfoDup); lpSpyInfoDup = NULL;
	}

	return lpSpyInfoDup;
}

bool CU2Info::AppendItemAscOrder(DWORD dwKey, LPSPY_ENTRY_INFO lpSpyInfo)
{
	LPSPY_ENTRY_INFO lpSpyInfoDup = 0;

	lpSpyInfoDup = DuplicateSpyInfo(lpSpyInfo);
	if(NULL == lpSpyInfoDup)
	{
		return false;
	}

	if(!AddNodeAscOrder(dwKey,(SIZE_T)lpSpyInfoDup))
	{
		if(lpSpyInfoDup->szSpyName) Release((LPVOID&)lpSpyInfoDup->szSpyName);
		if(lpSpyInfoDup->szKey) Release((LPVOID&)lpSpyInfoDup->szKey);
		if(lpSpyInfoDup->szValue) Release((LPVOID&)lpSpyInfoDup->szValue);
		if(lpSpyInfoDup->szBackupFileName) Release((LPVOID&)lpSpyInfoDup->szBackupFileName);
		if(lpSpyInfoDup->byData) Release((LPVOID&)lpSpyInfoDup->byData);
		if(lpSpyInfoDup->byReplaceData) Release((LPVOID&)lpSpyInfoDup->byReplaceData);
		Release((LPVOID&)lpSpyInfoDup);
		return false;
	}

	return true;
}

bool CU2Info::AppendItem(DWORD dwKey, LPSPY_ENTRY_INFO lpSpyInfo)
{
	LPSPY_ENTRY_INFO lpSpyInfoDup = 0;

	lpSpyInfoDup = DuplicateSpyInfo(lpSpyInfo);
	if(NULL == lpSpyInfoDup)
	{
		return false;
	}

	if(!AddNode(dwKey,(SIZE_T)lpSpyInfoDup))
	{
		if(lpSpyInfoDup->szSpyName) Release((LPVOID&)lpSpyInfoDup->szSpyName);
		if(lpSpyInfoDup->szKey) Release((LPVOID&)lpSpyInfoDup->szKey);
		if(lpSpyInfoDup->szValue) Release((LPVOID&)lpSpyInfoDup->szValue);
		if(lpSpyInfoDup->szBackupFileName) Release((LPVOID&)lpSpyInfoDup->szBackupFileName);
		if(lpSpyInfoDup->byData) Release((LPVOID&)lpSpyInfoDup->byData);
		if(lpSpyInfoDup->byReplaceData) Release((LPVOID&)lpSpyInfoDup->byReplaceData);
		Release((LPVOID&)lpSpyInfoDup);
		return false;
	}

	return true;
}

bool CU2Info::DeleteItem(DWORD dwKey)
{
	return DeleteNode((SIZE_T)dwKey);
}

bool CU2Info::SearchItem(DWORD dwKey, LPSPY_ENTRY_INFO& lpSpyInfo)
{
	SIZE_T nData = 0;

	if(!FindNode((SIZE_T)dwKey, nData))
	{
		return false;
	}

	lpSpyInfo = (LPSPY_ENTRY_INFO)nData;
	return true;
}

bool CU2Info::UpdateItem(DWORD dwKey, LPSPY_ENTRY_INFO lpSpyInfo)
{
	m_bIsModified = true;
	if(!m_pLastSearchResult || m_pLastSearchResult->nKey != dwKey)
	{
		SIZE_T nData = 0;

		if(!FindNode(dwKey, nData))
		{
			return false;
		}

		if(!m_pLastSearchResult || m_pLastSearchResult->nKey != dwKey)
		{
			return false;
		}
	}

	m_pLastSearchResult->nData = (SIZE_T)lpSpyInfo;
	return true;
}

bool CU2Info::AppendObject(CBalBSTOpt& objToAdd)
{
	DWORD dwKey = 0;
	LPVOID lpContext = 0;
	LPSPY_ENTRY_INFO lpSpyInfo = 0;
	CU2Info _objToAdd = (CU2Info&)objToAdd;

	lpContext = _objToAdd.GetLowest();
	while(lpContext)
	{
		_objToAdd.GetKey(lpContext, dwKey);
		_objToAdd.GetData(lpContext, lpSpyInfo);

		if(lpSpyInfo)
		{
			if(AppendItemAscOrder(dwKey, lpSpyInfo))
			{
				SetModified();
			}
		}

		lpContext = _objToAdd.GetLowestNext(lpContext);
	}

	return true;
}

bool CU2Info::DeleteObject(CBalBSTOpt& objToDel)
{
	DWORD dwKey = 0;
	LPVOID lpContext = 0;
	LPSPY_ENTRY_INFO lpSpyInfo = 0;
	CU2Info _objToDel = (CU2Info&)objToDel;

	lpContext = _objToDel.GetFirst();
	while(lpContext)
	{
		lpSpyInfo = 0;
		_objToDel.GetKey(lpContext, dwKey);
		_objToDel.GetData(lpContext, lpSpyInfo);

		if(lpSpyInfo)
		{
			if(DeleteItem(dwKey))
			{
				SetModified();
			}
		}

		lpContext = _objToDel.GetNext(lpContext);
	}

	return true;
}

bool CU2Info::CreateObject(CU2Info& objNewObject)
{
	DWORD dwKey = 0;
	LPSPY_ENTRY_INFO lpSpyInfo = 0;
	LPVOID lpContext = NULL;

	lpContext = GetLowest();
	while(lpContext)
	{
		lpSpyInfo = 0;
		GetKey(lpContext, dwKey);
		GetData(lpContext, lpSpyInfo);

		if(lpSpyInfo)
		{
			objNewObject.AppendItemAscOrder(dwKey, lpSpyInfo);
		}

		lpContext = GetLowestNext(lpContext);
	}

	return true;
}

bool CU2Info::SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent)
{
	bool bSuccess = true, bFound = false;
	LPVOID lpContext = NULL;
	DWORD dwKey = 0;
	LPSPY_ENTRY_INFO lpSpyInfo = 0;
	CU2Info& objToSearchDup = (CU2Info&)objToSearch;

	lpContext = objToSearchDup.GetFirst();
	while(lpContext)
	{
		objToSearchDup.GetKey(lpContext, dwKey);
		bFound = SearchItem(dwKey, lpSpyInfo);
		if((bFound && !bAllPresent) || (!bFound && bAllPresent))
		{
			bSuccess = false;
			break;
		}

		lpContext = objToSearchDup.GetNext(lpContext);
	}

	return bSuccess;
}

bool CU2Info::ReadU2In(SIZE_T nBaseAddress, LPBYTE& pData, PSIZE_T& pNode, DWORD& dwNodesMade)
{
	SIZE_T pLink = 0;
	LPTSTR lpStr = 0;
	PULONG64 pDataDup = 0;
	DWORD dwNodesCount = 0;
	LPSPY_ENTRY_INFO lpSpyEntry = 0;

	dwNodesCount = *((LPDWORD)pData);
	pData += sizeof(DWORD);

	for(DWORD dwIndex = 0; dwIndex < dwNodesCount; dwIndex++)
	{
		pLink = dwIndex + 1 >= dwNodesCount ? 0 : (SIZE_T)(pNode + NUMBER_OF_NODEOPT_ELEMENTS);

		*pNode = *((LPDWORD)pData); pNode++; pData += sizeof(DWORD);
		*pNode = (SIZE_T)pData; pNode++;
		*pNode = NULL; pNode++;
		*pNode = pLink; pNode++;

		lpSpyEntry = (LPSPY_ENTRY_INFO)pData;
		pData += SIZE_OF_STATIC_DATA;
		pDataDup = (PULONG64)pData;
		*pDataDup = *pDataDup ? *pDataDup + nBaseAddress : *pDataDup; pDataDup++;
		*pDataDup = *pDataDup ? *pDataDup + nBaseAddress : *pDataDup; pDataDup++;
		*pDataDup = *pDataDup ? *pDataDup + nBaseAddress : *pDataDup; pDataDup++;
		*pDataDup = *pDataDup ? *pDataDup + nBaseAddress : *pDataDup; pDataDup++;
		*pDataDup = *pDataDup ? *pDataDup + nBaseAddress : *pDataDup; pDataDup++;
		*pDataDup = *pDataDup ? *pDataDup + nBaseAddress : *pDataDup; pDataDup++;

		if(lpSpyEntry->szSpyName)
		{
			lpStr = (LPTSTR)pDataDup;
			while(*lpStr++);
			pDataDup = (PULONG64)lpStr;
		}

		if(lpSpyEntry->szKey)
		{
			lpStr = (LPTSTR)pDataDup;
			while(*lpStr++);
			pDataDup = (PULONG64)lpStr;
		}

		if(lpSpyEntry->szValue)
		{
			lpStr = (LPTSTR)pDataDup;
			while(*lpStr++);
			pDataDup = (PULONG64)lpStr;
		}

		if(lpSpyEntry->szBackupFileName)
		{
			lpStr = (LPTSTR)pDataDup;
			while(*lpStr++);
			pDataDup = (PULONG64)lpStr;
		}

		if(lpSpyEntry->byData)
		{
			pDataDup = (PULONG64)(((LPBYTE)pDataDup) + lpSpyEntry->dwRegDataSize);
		}

		if(lpSpyEntry->byReplaceData)
		{
			pDataDup = (PULONG64)(((LPBYTE)pDataDup) + lpSpyEntry->dwReplaceRegDataSize);
		}

		pData = (LPBYTE)pDataDup;
	}

	dwNodesMade = dwNodesCount;
	return true;

//ERROR_EXIT:
//	return false;
}

bool CU2Info::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	LPBYTE lpTempData = 0;
	SIZE_T nBaseAddress = 0, *lpTempNode = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szFullFileName[MAX_PATH] = {0};
	DWORD dwFileSize = 0, dwBytesRead = 0, dwNodesCount = 0, dwNodesMade = 0;
	BYTE byHdrBfr[sizeof(HEADER_U2INFO) + sizeof(HEADER_U2INFO_DATA)] = {0};

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

	if(bCheckVersion && memcmp(HEADER_U2INFO, byHdrBfr, sizeof(HEADER_U2INFO)))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_U2INFO_DATA, sizeof(HEADER_U2INFO_DATA)))
	{
		goto ERROR_EXIT;
	}

	if(memcmp(byHdrBfr + sizeof(HEADER_U2INFO), HEADER_U2INFO_DATA, sizeof(HEADER_U2INFO_DATA) - sizeof(ULONG64)))
	{
		goto ERROR_EXIT;
	}

	memcpy(&dwNodesCount, byHdrBfr + sizeof(HEADER_U2INFO) + sizeof(HEADER_U2INFO_DATA) - sizeof(ULONG64), sizeof(dwNodesCount));

	m_pTemp = m_pRoot = NULL;
	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(byHdrBfr))
	{
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(byHdrBfr);
	m_nBufferSize = dwFileSize + (SIZE_OF_NODEOPT * dwNodesCount);
	m_pBuffer = (LPBYTE) VAllocate(m_nBufferSize);
	if(NULL == m_pBuffer)
	{
		goto ERROR_EXIT;
	}

	if(!ReadFile(hFile, m_pBuffer, dwFileSize, &dwBytesRead, 0))
	{
		goto ERROR_EXIT;
	}

	if(dwFileSize != dwBytesRead)
	{
		goto ERROR_EXIT;
	}

	CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;
	CryptBuffer(m_pBuffer, dwFileSize);
	nBaseAddress = ((SIZE_T)m_pBuffer) - ((SIZE_T)sizeof(byHdrBfr));
	m_pRoot = (PNODEOPT)(m_pBuffer + dwFileSize);
	lpTempData = m_pBuffer;
	lpTempNode = (PSIZE_T)m_pRoot;

	if(!ReadU2In(nBaseAddress, lpTempData, lpTempNode, dwNodesMade))
	{
		goto ERROR_EXIT;
	}

	Balance();
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
		VRelease((LPVOID)m_pBuffer);
	}

	m_bLoadedFromFile = false;
	m_nBufferSize = 0;
	//DeleteFile(szFullFileName);
	AddLogEntry(L"Error in loading: %s.File Deleted.", szFullFileName);
	return false;
}

bool CU2Info::DumpU2In(HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount)
{
	DWORD nWriteKey = 0;
	ULONG64 nWriteData = 0;
	LPSPY_ENTRY_INFO lpSpyInfo = 0;
	DWORD dwNodeOffset = 0, dwBytesWritten = 0, dwCountOffset = 0, dwCurOff = 0;
	DWORD cbSpyName = 0, cbKey = 0, cbValue = 0, cbBkpFile = 0, cbData = 0, cbRData = 0;

	dwNodesCount = 0;
	SFPTR(hFile, 0, 0, FILE_CURRENT, dwCountOffset);
	WFILE(hFile, &dwNodesCount, sizeof(dwNodesCount), &dwBytesWritten, 0);

	while(pNode || !m_objStack.IsEmpty())
	{
		m_pTemp = NULL;

		if(pNode)
		{
			m_objStack.Push(pNode);
			pNode = pNode->pLeft;
		}
		else
		{
			m_pTemp = (PNODEOPT)m_objStack.Pop();
			pNode = m_pTemp->pRight;
		}

		if(!m_pTemp)
		{
			continue;
		}

		lpSpyInfo = (LPSPY_ENTRY_INFO)m_pTemp->nData;
		if(!lpSpyInfo)
		{
			goto ERROR_EXIT;
		}

		cbSpyName = lpSpyInfo->szSpyName?((DWORD)_tcslen(lpSpyInfo->szSpyName)+1)*sizeof(TCHAR):0;
		cbKey = lpSpyInfo->szKey?((DWORD)_tcslen(lpSpyInfo->szKey)+1)*sizeof(TCHAR):0;
		cbValue = lpSpyInfo->szValue?((DWORD)_tcslen(lpSpyInfo->szValue)+1)*sizeof(TCHAR):0;
		cbBkpFile = lpSpyInfo->szBackupFileName?((DWORD)_tcslen(lpSpyInfo->szBackupFileName)+1)*sizeof(TCHAR):0;
		cbData = lpSpyInfo->byData?lpSpyInfo->dwRegDataSize:0;
		cbRData = lpSpyInfo->byReplaceData?lpSpyInfo->dwReplaceRegDataSize:0;

		nWriteKey = (DWORD)m_pTemp->nKey;
		WFILE(hFile, &nWriteKey, sizeof(nWriteKey), &dwBytesWritten, 0);

		SFPTR(hFile, 0, 0, FILE_CURRENT, dwNodeOffset);
		WFILE(hFile, (LPVOID)m_pTemp->nData, SIZE_OF_STATIC_DATA, &dwBytesWritten, 0);

		nWriteData = cbSpyName ? dwNodeOffset + sizeof(SPY_ENTRY_INFO) : 0;
		WFILE(hFile, (LPVOID)&nWriteData, sizeof(nWriteData), &dwBytesWritten, 0);

		nWriteData = cbKey ? dwNodeOffset + sizeof(SPY_ENTRY_INFO) + cbSpyName: 0;
		WFILE(hFile, (LPVOID)&nWriteData, sizeof(nWriteData), &dwBytesWritten, 0);

		nWriteData = cbValue ? dwNodeOffset + sizeof(SPY_ENTRY_INFO) + cbSpyName + cbKey: 0;
		WFILE(hFile, (LPVOID)&nWriteData, sizeof(nWriteData), &dwBytesWritten, 0);

		nWriteData = cbBkpFile ? dwNodeOffset + sizeof(SPY_ENTRY_INFO) + cbSpyName + cbKey + cbValue: 0;
		WFILE(hFile, (LPVOID)&nWriteData, sizeof(nWriteData), &dwBytesWritten, 0);

		nWriteData = cbData ? dwNodeOffset + sizeof(SPY_ENTRY_INFO) + cbSpyName + cbKey + cbValue + cbBkpFile: 0;
		WFILE(hFile, (LPVOID)&nWriteData, sizeof(nWriteData), &dwBytesWritten, 0);

		nWriteData = cbRData ? dwNodeOffset + sizeof(SPY_ENTRY_INFO) + cbSpyName + cbKey + cbValue + cbBkpFile + cbData: 0;
		WFILE(hFile, (LPVOID)&nWriteData, sizeof(nWriteData), &dwBytesWritten, 0);

		if(cbSpyName)
		{
			WFILE(hFile, (LPVOID)lpSpyInfo->szSpyName, cbSpyName, &dwBytesWritten, 0);
		}

		if(cbKey)
		{
			WFILE(hFile, (LPVOID)lpSpyInfo->szKey, cbKey, &dwBytesWritten, 0);
		}

		if(cbValue)
		{
			WFILE(hFile, (LPVOID)lpSpyInfo->szValue, cbValue, &dwBytesWritten, 0);
		}

		if(cbBkpFile)
		{
			WFILE(hFile, (LPVOID)lpSpyInfo->szBackupFileName, cbBkpFile, &dwBytesWritten, 0);
		}

		if(cbData)
		{
			WFILE(hFile, (LPVOID)lpSpyInfo->byData, cbData, &dwBytesWritten, 0);
		}

		if(cbRData)
		{
			WFILE(hFile, (LPVOID)lpSpyInfo->byReplaceData, cbRData, &dwBytesWritten, 0);
		}

		dwNodesCount++;
	}

	SFPTR(hFile, 0, 0, FILE_CURRENT, dwCurOff);
	SFPTR(hFile, dwCountOffset, 0, FILE_BEGIN, dwCountOffset);
	WFILE(hFile, &dwNodesCount, sizeof(dwNodesCount), &dwBytesWritten, 0);
	SFPTR(hFile, dwCurOff, 0, FILE_BEGIN, dwCurOff);
	return true;

ERROR_EXIT:
	m_objStack.RemoveAll();
	return false;
}

bool CU2Info::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	HANDLE hFile = 0;
	DWORD dwBytesWritten = 0, dwNodesCount = 0, dwTemp = 0;

	hFile = CreateFile(szFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	SFPTR(hFile, sizeof(HEADER_U2INFO) + sizeof(HEADER_U2INFO_DATA), 0, FILE_BEGIN, dwTemp);

	if(!DumpU2In(hFile, m_pRoot, dwNodesCount))
	{
		goto ERROR_EXIT;
	}

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_U2INFO) + sizeof(HEADER_U2INFO_DATA)))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFileName, HEADER_U2INFO_DATA, sizeof(HEADER_U2INFO_DATA), dwNodesCount))
	{
		goto ERROR_EXIT;
	}

	SFPTR(hFile, 0, 0, FILE_BEGIN, dwTemp);
	WFILE(hFile, HEADER_U2INFO, sizeof(HEADER_U2INFO), &dwBytesWritten, 0);
	WFILE(hFile, HEADER_U2INFO_DATA, sizeof(HEADER_U2INFO_DATA), &dwBytesWritten, 0);
	CloseHandle(hFile);
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

bool DateTimeForDB(ULONG64 ulDateTime64, ULONG64& ulDate, DWORD& dwTime)
{
	struct tm timeinfo = {0};
	localtime_s(&timeinfo, (time_t*)&ulDateTime64);
	dwTime = (timeinfo.tm_hour * 60 * 60) + (timeinfo.tm_min * 60) + timeinfo.tm_sec;
	ulDate = ulDateTime64 - dwTime;
	return true;
}

bool DateTimeForUI(ULONG64 ulDate, DWORD dwTime, LPTSTR szDateTime, SIZE_T cchDateTime)
{
	struct tm timeinfo = {0};
	ulDate += dwTime;
	localtime_s(&timeinfo, (time_t*)&ulDate);
	memset(szDateTime, 0, cchDateTime * sizeof(TCHAR));
	return !!wcsftime(szDateTime, cchDateTime, _T("%d %b, %Y [%H:%M:%S]"), &timeinfo);
}

bool DateTimeForUI(ULONG64 ulDateTime64, LPTSTR szDateTime, SIZE_T cchDateTime)
{
	struct tm timeinfo = {0};
	localtime_s(&timeinfo, (time_t*)&ulDateTime64);
	memset(szDateTime, 0, cchDateTime * sizeof(TCHAR));
	return !!wcsftime(szDateTime, cchDateTime, _T("%d %b, %Y [%H:%M:%S]"), &timeinfo);
}

bool ReduceNoOfDays(ULONG64 &ulDate, ULONG64 ulDays)
{
	ulDays = ulDays * 24 * 60 * 60;
	if(ulDays > ulDate)
	{
		return false;
	}
	else
	{
		ulDate -= ulDays;
		return true;
	}
}