#include "pch.h"
#include "UU2Info.h"

BYTE HEADER_UU2INFO[24]			= {"MAXDBVERSION00.00.00.09"};
BYTE HEADER_UU2INFO_DATA[24]	= {0};

CUU2Info::CUU2Info(bool bIsEmbedded):CBalBSTOpt(bIsEmbedded)
{
}

CUU2Info::~CUU2Info()
{
	RemoveAll();
}

COMPARE_RESULT CUU2Info::Compare(SIZE_T nKey1, SIZE_T nKey2)
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

void CUU2Info::FreeKey(SIZE_T nKey)
{
}

void CUU2Info::FreeData(SIZE_T nData)
{
	CU2Info objU2Info(false);
	objU2Info.SetDataPtr((PNODEOPT)nData, m_pBuffer, m_nBufferSize);
	objU2Info.RemoveAll();
	return;
}

bool CUU2Info::AppendItemAscOrder(DWORD dwKey, CU2Info& objU2Info)
{
	return AddNodeAscOrder(dwKey, (SIZE_T)objU2Info.GetDataPtr());
}

bool CUU2Info::AppendItem(DWORD dwKey, CU2Info& objU2Info)
{
	return AddNode(dwKey, (SIZE_T)objU2Info.GetDataPtr());
}

bool CUU2Info::DeleteItem(DWORD dwKey)
{
	return DeleteNode(dwKey);
}

bool CUU2Info::SearchItem(DWORD dwKey, CU2Info& objU2Info)
{
	SIZE_T nData = 0;

	if(!FindNode(dwKey, nData))
	{
		return false;
	}

	objU2Info.SetDataPtr((PNODEOPT)nData, m_pBuffer, m_nBufferSize);
	return true;
}

bool CUU2Info::UpdateItem(DWORD dwKey, CU2Info& objU2Info)
{
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

	m_pLastSearchResult->nData = (SIZE_T)objU2Info.GetDataPtr();
	return true;
}

bool CUU2Info::Balance()
{
	CU2Info objU2Info(true);
	LPVOID lpContext = NULL;

	CBalBSTOpt::Balance();
	lpContext = GetFirst();
	while(lpContext)
	{
		GetData(lpContext, objU2Info);
		objU2Info.Balance();
		((PNODEOPT)lpContext)->nData = (SIZE_T)objU2Info.GetDataPtr();
		lpContext = GetNext(lpContext);
	}

	return true;
}

bool CUU2Info::GetKey(PVOID lpContext, DWORD& dwKey)
{
	if(!lpContext)
	{
		return false;
	}

	dwKey = (DWORD)(((PNODEOPT)lpContext)->nKey);
	return true;
}

bool CUU2Info::GetData(PVOID lpContext, CU2Info& objU2Info)
{
	if(!lpContext)
	{
		return false;
	}

	objU2Info.SetDataPtr((PNODEOPT)(((PNODEOPT)lpContext)->nData), m_pBuffer, m_nBufferSize);
	return true;
}

bool CUU2Info::AppendObject(CBalBSTOpt& objToAdd)
{
	DWORD dwKey1 = 0, dwKey2 = 0;
	LPVOID lpCon1 = 0, lpCon2 = 0;
	CUU2Info objAddL1 = (CUU2Info&)objToAdd;
	CU2Info objAddL2(true), objThisL2(true);
	LPSPY_ENTRY_INFO lpSpyInfo = 0;

	lpCon1 = objAddL1.GetFirst();
	while(lpCon1)
	{
		objAddL1.GetKey(lpCon1, dwKey1);
		objAddL1.GetData(lpCon1, objAddL2);

		if(SearchItem(dwKey1, objThisL2))
		{
			lpCon2 = objAddL2.GetFirst();
			while(lpCon2)
			{
				objAddL2.GetKey(lpCon2, dwKey2);
				objAddL2.GetData(lpCon2, lpSpyInfo);

				if(lpSpyInfo)
				{
					if(objThisL2.AppendItem(dwKey2, lpSpyInfo))
					{
						SetModified();
					}
				}

				lpCon2 = objAddL2.GetNext(lpCon2);
			}
		}
		else
		{
			if(objAddL2.GetFirst())
			{
				objThisL2.RemoveAll();
				objAddL2.CreateObject(objThisL2);
				if(objThisL2.GetFirst())
				{
					if(AppendItem(dwKey1, objThisL2))
					{
						SetModified();
					}

					objThisL2.RemoveAll();
				}
			}
		}

		lpCon1 = objAddL1.GetNext(lpCon1);
	}

	return true;
}

bool CUU2Info::DeleteObject(CBalBSTOpt& objToDel)
{
	DWORD dwKey1 = 0, dwKey2 = 0;
	LPVOID lpCon1 = 0, lpCon2 = 0;
	CUU2Info objDelL1 = (CUU2Info&)objToDel;
	CU2Info objThisL2(true), objDelL2(true);

	lpCon1 = objDelL1.GetFirst();
	while(lpCon1)
	{
		objDelL1.GetKey(lpCon1, dwKey1);
		objDelL1.GetData(lpCon1, objDelL2);

		if(SearchItem(dwKey1, objThisL2))
		{
			lpCon2 = objThisL2.GetFirst();
			while(lpCon2)
			{
				objThisL2.GetKey(lpCon2, dwKey2);
				if(objThisL2.DeleteItem(dwKey2))
				{
					SetModified();
				}

				lpCon2 = objThisL2.GetNext(lpCon2);
			}

			UpdateItem(dwKey1, objThisL2);
			if(!objThisL2.GetFirst())
			{
				if(DeleteItem(dwKey1))
				{
					SetModified();
				}
			}
		}

		lpCon1 = objDelL1.GetNext(lpCon1);
	}

	return true;
}

bool CUU2Info::CreateObject(CUU2Info& objNewObject)
{
	DWORD dwKey = 0;
	LPVOID lpContext = 0;
	CU2Info objU2Info(true), objU2InfoNew(true);

	lpContext = GetLowest();
	while(lpContext)
	{
		GetKey(lpContext, dwKey);
		GetData(lpContext, objU2Info);

		if(objU2Info.GetFirst())
		{
			objU2InfoNew.RemoveAll();
			objU2Info.CreateObject(objU2InfoNew);
			if(objU2InfoNew.GetFirst())
			{
				objNewObject.AppendItemAscOrder(dwKey, objU2InfoNew);
			}
		}

		lpContext = GetLowestNext(lpContext);
	}

	return true;
}

bool CUU2Info::SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent)
{
	bool bSuccess = true, bFound = false;
	DWORD dwKey1 = 0, dwKey2 = 0;
	LPVOID lpCon1 = 0, lpCon2 = 0;
	CU2Info objSearchL2(true), objThisL2(true);
	CUU2Info& objSearchL1 = (CUU2Info&)objToSearch;
	LPSPY_ENTRY_INFO lpSpyInfo = 0;

	lpCon1 = objSearchL1.GetFirst();
	while(lpCon1 && bSuccess)
	{
		objSearchL1.GetKey(lpCon1, dwKey1);
		objSearchL1.GetData(lpCon1, objSearchL2);

		if(SearchItem(dwKey1, objThisL2))
		{
			lpCon2 = objSearchL2.GetFirst();
			while(lpCon2 && bSuccess)
			{
				objSearchL2.GetKey(lpCon2, dwKey2);

				bFound = objThisL2.SearchItem(dwKey2, lpSpyInfo);
				if((bFound && !bAllPresent) || (!bFound && bAllPresent))
				{
					bSuccess = false;
				}

				lpCon2 = objSearchL2.GetNext(lpCon2);
			}
		}
		else
		{
			bSuccess = false;
		}

		lpCon1 = objSearchL1.GetNext(lpCon1);
	}

	return bSuccess;
}

bool CUU2Info::ReadUU2In(SIZE_T nBaseAddr, LPBYTE& pData, PSIZE_T& pNode, DWORD& dwNodesMade)
{
	PSIZE_T pLink = 0;
	CU2Info objU2Info(true);
	DWORD dwThisCount = 0, dwChildNodes = 0;

	dwThisCount = *((LPDWORD)pData);
	pData += sizeof(DWORD);

	for(DWORD dwIndex = 0; dwIndex < dwThisCount; dwIndex++)
	{
		*pNode = *((LPDWORD)pData); pNode++; pData += sizeof(DWORD);
		*pNode = (SIZE_T)(pNode + 3); pNode++;
		*pNode = NULL; pNode++;
		pLink = pNode; pNode++;

		dwChildNodes = 0;
		if(!objU2Info.ReadU2In(nBaseAddr, pData, pNode, dwChildNodes))
		{
			goto ERROR_EXIT;
		}

		if(dwIndex + 1 < dwThisCount)
		{
			*pLink = (SIZE_T)(pLink + ((dwChildNodes * NUMBER_OF_NODEOPT_ELEMENTS) + 1));
		}
		else
		{
			*pLink = 0;
		}

		dwNodesMade += dwChildNodes;
	}

	dwNodesMade += dwThisCount;
	return true;

ERROR_EXIT:
	return false;
}

bool CUU2Info::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	LPBYTE lpTempData = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szFullFileName[MAX_PATH] = {0};
	SIZE_T nBaseAddress = 0, *lpTempNode = 0;
	DWORD dwFileSize = 0, dwBytesRead = 0, dwNodesCount = 0, dwNodesMade = 0;
	BYTE byHdrBfr[sizeof(HEADER_UU2INFO) + sizeof(HEADER_UU2INFO_DATA)] = {0};

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

	if(bCheckVersion && memcmp(HEADER_UU2INFO, byHdrBfr, sizeof(HEADER_UU2INFO)))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_UU2INFO_DATA, sizeof(HEADER_UU2INFO_DATA)))
	{
		goto ERROR_EXIT;
	}

	if(memcmp(byHdrBfr + sizeof(HEADER_UU2INFO), HEADER_UU2INFO_DATA, sizeof(HEADER_UU2INFO_DATA) - sizeof(ULONG64)))
	{
		goto ERROR_EXIT;
	}

	memcpy(&dwNodesCount, byHdrBfr + sizeof(HEADER_UU2INFO) + sizeof(HEADER_UU2INFO_DATA) - sizeof(ULONG64), sizeof(dwNodesCount));

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

	if(!ReadUU2In(nBaseAddress, lpTempData, lpTempNode, dwNodesMade))
	{
		goto ERROR_EXIT;
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
		VRelease((LPVOID)m_pBuffer);
	}

	m_bLoadedFromFile = false;
	m_nBufferSize = 0;
	//DeleteFile(szFullFileName);
	AddLogEntry(L"Error in loading: %s.File Deleted", szFullFileName);
	return false;
}

bool CUU2Info::DumpUU2In(HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount)
{
	DWORD nWriteKey = 0;
	CU2Info objU2Info(true);
	DWORD dwEmbdNodesCount = 0, dwThisCount = 0, dwBytesWritten = 0, dwCurOff = 0, dwCountOffset = 0;

	dwNodesCount = 0;
	SFPTR(hFile, 0, 0, FILE_CURRENT, dwCountOffset);
	WFILE(hFile, &dwThisCount, sizeof(dwThisCount), &dwBytesWritten, 0);

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

		nWriteKey = (DWORD)m_pTemp->nKey;
		WFILE(hFile, &nWriteKey, sizeof(nWriteKey), &dwBytesWritten, 0);

		dwEmbdNodesCount = 0;
		if(!objU2Info.DumpU2In(hFile, (PNODEOPT)m_pTemp->nData, dwEmbdNodesCount))
		{
			goto ERROR_EXIT;
		}

		dwThisCount++;
		dwNodesCount += dwEmbdNodesCount;
	}

	dwNodesCount = dwNodesCount + dwThisCount;
	SFPTR(hFile, 0, 0, FILE_CURRENT, dwCurOff);
	SFPTR(hFile, dwCountOffset, 0, FILE_BEGIN, dwCountOffset);
	WFILE(hFile, &dwThisCount, sizeof(dwThisCount), &dwBytesWritten, 0);
	SFPTR(hFile, dwCurOff, 0, FILE_BEGIN, dwCurOff);
	return true;

ERROR_EXIT:
	m_objStack.RemoveAll();
	return false;
}

bool CUU2Info::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	HANDLE hFile = 0;
	DWORD dwBytesWritten = 0, dwNodesCount = 0, dwTemp = 0;

	hFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	SFPTR(hFile, sizeof(HEADER_UU2INFO) + sizeof(HEADER_UU2INFO_DATA), 0, FILE_BEGIN, dwTemp);

	if(!DumpUU2In(hFile, m_pRoot, dwNodesCount))
	{
		goto ERROR_EXIT;
	}

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_UU2INFO) + sizeof(HEADER_UU2INFO_DATA)))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFileName, HEADER_UU2INFO_DATA, sizeof(HEADER_UU2INFO_DATA), dwNodesCount))
	{
		goto ERROR_EXIT;
	}

	SFPTR(hFile, 0, 0, FILE_BEGIN, dwTemp);
	WFILE(hFile, HEADER_UU2INFO, sizeof(HEADER_UU2INFO), &dwBytesWritten, 0);
	WFILE(hFile, HEADER_UU2INFO_DATA, sizeof(HEADER_UU2INFO_DATA), &dwBytesWritten, 0);
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
