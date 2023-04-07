#include "pch.h"
#include "UUU2Info.h"

BYTE HEADER_UUU2INFO[24]		= {"MAXDBVERSION00.00.00.09"};
BYTE HEADER_UUU2INFO_DATA[24]	= {0};

CUUU2Info::CUUU2Info(bool bIsEmbedded):CBalBSTOpt(bIsEmbedded)
{
}

CUUU2Info::~CUUU2Info()
{
	RemoveAll();
}

COMPARE_RESULT CUUU2Info::Compare(SIZE_T nKey1, SIZE_T nKey2)
{
	ULONG64 nVal1 = *((PULONG64)nKey1);
	ULONG64 nVal2 = *((PULONG64)nKey2);

	if(nVal1 < nVal2)
	{
		return SMALL;
	}
	else if(nVal1 > nVal2)
	{
		return LARGE;
	}
	else
	{
		return EQUAL;
	}
}

void CUUU2Info::FreeKey(SIZE_T nKey)
{
	if ( (((LPBYTE)nKey) < m_pBuffer) || (((LPBYTE)nKey) >= (m_pBuffer + m_nBufferSize)) )
	{
		Release((LPVOID&)nKey);
	}
}

void CUUU2Info::FreeData(SIZE_T nData)
{
	CUU2Info objUU2Info(false);
	objUU2Info.SetDataPtr((PNODEOPT)nData, m_pBuffer, m_nBufferSize);
	objUU2Info.RemoveAll();
	return;
}

bool CUUU2Info::AppendItemAscOrder(ULONG64 ulKey, CUU2Info& objUU2Info)
{
	PULONG64 pulKeyDup = 0;
	
	pulKeyDup = (PULONG64)DuplicateBuffer((LPBYTE)&ulKey, sizeof(ulKey));
	if(!pulKeyDup)
	{
		return false;
	}

	if(!AddNodeAscOrder((SIZE_T)pulKeyDup, (SIZE_T)objUU2Info.GetDataPtr()))
	{
		Release((LPVOID&)pulKeyDup);
		return false;
	}

	return true;
}

bool CUUU2Info::AppendItem(ULONG64 ulKey, CUU2Info& objUU2Info)
{
	PULONG64 pulKeyDup = 0;

	pulKeyDup = (PULONG64)DuplicateBuffer((LPBYTE)&ulKey, sizeof(ulKey));
	if(!pulKeyDup)
	{
		return false;
	}

	if(!AddNode((SIZE_T)pulKeyDup, (SIZE_T)objUU2Info.GetDataPtr()))
	{
		Release((LPVOID&)pulKeyDup);
		return false;
	}

	return true;
}

bool CUUU2Info::DeleteItem(ULONG64 ulKey)
{
	return DeleteNode((SIZE_T)&ulKey);
}

bool CUUU2Info::SearchItem(ULONG64 ulKey, CUU2Info& objUU2Info)
{
	SIZE_T nData = 0;

	if(!FindNode((SIZE_T)&ulKey, nData))
	{
		return false;
	}

	objUU2Info.SetDataPtr((PNODEOPT)nData, m_pBuffer, m_nBufferSize);
	return true;
}

bool CUUU2Info::UpdateItem(ULONG64 ulKey, CUU2Info& objUU2Info)
{
	if(!m_pLastSearchResult || (EQUAL != Compare(m_pLastSearchResult->nKey, (SIZE_T)&ulKey)))
	{
		SIZE_T nData = 0;

		if(!FindNode((SIZE_T)&ulKey, nData))
		{
			return false;
		}

		if(!m_pLastSearchResult || (EQUAL != Compare(m_pLastSearchResult->nKey, (SIZE_T)&ulKey)))
		{
			return false;
		}
	}

	m_pLastSearchResult->nData = (SIZE_T)objUU2Info.GetDataPtr();
	return true;
}

bool CUUU2Info::Balance()
{
	CUU2Info objUU2Info(true);
	LPVOID lpContext = NULL;

	CBalBSTOpt::Balance();
	lpContext = GetFirst();
	while(lpContext)
	{
		GetData(lpContext, objUU2Info);
		objUU2Info.Balance();
		((PNODEOPT)lpContext)->nData = (SIZE_T)objUU2Info.GetDataPtr();
		lpContext = GetNext(lpContext);
	}

	return true;
}

bool CUUU2Info::GetKey(PVOID lpContext, ULONG64& ulKey)
{
	if(!lpContext)
	{
		return false;
	}

	ulKey = *((ULONG64*)(((PNODEOPT)lpContext)->nKey));
	return true;
}

bool CUUU2Info::GetData(PVOID lpContext, CUU2Info& objUU2Info)
{
	if(!lpContext)
	{
		return false;
	}

	objUU2Info.SetDataPtr((PNODEOPT)(((PNODEOPT)lpContext)->nData), m_pBuffer, m_nBufferSize);
	return true;
}

bool CUUU2Info::AppendObject(CBalBSTOpt& objToAdd)
{
	ULONG64 ulKey1 = 0;
	DWORD dwKey2 = 0, dwKey3 = 0;
	LPVOID lpCon1 = 0, lpCon2 = 0, lpCon3 = 0;
	CUUU2Info& objAddL1 = (CUUU2Info&)objToAdd;
	CUU2Info objAddL2(true), objThisL2(true);
	CU2Info objAddL3(true), objThisL3(true);
	LPSPY_ENTRY_INFO lpSpyInfo = 0;

	lpCon1 = objAddL1.GetFirst();
	while(lpCon1)
	{
		objAddL1.GetKey(lpCon1, ulKey1);
		objAddL1.GetData(lpCon1, objAddL2);

		if(SearchItem(ulKey1, objThisL2))
		{
			lpCon2 = objAddL2.GetFirst();
			while(lpCon2)
			{
				objAddL2.GetKey(lpCon2, dwKey2);
				objAddL2.GetData(lpCon2, objAddL3);

				if(objThisL2.SearchItem(dwKey2, objThisL3))
				{
					lpCon3 = objAddL3.GetFirst();
					while(lpCon3)
					{
						objAddL3.GetKey(lpCon3, dwKey3);
						objAddL3.GetData(lpCon3, lpSpyInfo);

						if(lpSpyInfo)
						{
							if(objThisL3.AppendItem(dwKey3, lpSpyInfo))
							{
								SetModified();
							}
						}

						lpCon3 = objAddL3.GetNext(lpCon3);
					}
				}
				else
				{
					if(objAddL3.GetFirst())
					{
						objThisL3.RemoveAll();
						objAddL3.CreateObject(objThisL3);
						if(objThisL3.GetFirst())
						{
							if(objThisL2.AppendItem(dwKey2, objThisL3))
							{
								SetModified();
							}
						}
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
					if(AppendItem(ulKey1, objThisL2))
					{
						SetModified();
					}
				}
			}
		}

		lpCon1 = objAddL1.GetNext(lpCon1);
	}

	return true;
}

bool CUUU2Info::DeleteObject(CBalBSTOpt& objToDel)
{
	ULONG64 ulKey1 = 0;
	DWORD dwKey2 = 0, dwKey3 = 0;
	LPVOID lpCon1 = 0, lpCon2 = 0, lpCon3 = 0;
	CUUU2Info& objDelL1 = (CUUU2Info&)objToDel;
	CUU2Info objDelL2(true), objThisL2(true);
	CU2Info objDelL3(true), objThisL3(true);

	lpCon1 = objDelL1.GetFirst();
	while(lpCon1)
	{
		objDelL1.GetKey(lpCon1, ulKey1);
		objDelL1.GetData(lpCon1, objDelL2);

		if(SearchItem(ulKey1, objThisL2))
		{
			lpCon2 = objDelL2.GetFirst();
			while(lpCon2)
			{
				objDelL2.GetKey(lpCon2, dwKey2);
				objDelL2.GetData(lpCon2, objDelL3);

				if(objThisL2.SearchItem(dwKey2, objThisL3))
				{
					lpCon3 = objDelL3.GetFirst();
					while(lpCon3)
					{
						objDelL3.GetKey(lpCon3, dwKey3);
						if(objThisL3.DeleteItem(dwKey3))
						{
							SetModified();
						}

						lpCon3 = objDelL3.GetNext(lpCon3);
					}

					objThisL2.UpdateItem(dwKey2, objThisL3);
					if(!objThisL3.GetFirst())
					{
						if(objThisL2.DeleteItem(dwKey2))
						{
							SetModified();
						}
					}
				}

				lpCon2 = objDelL2.GetNext(lpCon2);
			}

			UpdateItem(ulKey1, objThisL2);
			if(!objThisL2.GetFirst())
			{
				if(DeleteItem(ulKey1))
				{
					SetModified();
				}
			}
		}

		lpCon1 = objDelL1.GetNext(lpCon1);
	}

	return true;
}

bool CUUU2Info::CreateObject(CUUU2Info& objNewObject)
{
	ULONG64 ulKey = 0;
	LPVOID lpContext = 0;
	CUU2Info objUU2Info(true), objUU2InfoNew(true);

	lpContext = GetLowest();
	while(lpContext)
	{
		GetKey(lpContext, ulKey);
		GetData(lpContext, objUU2Info);

		if(objUU2Info.GetFirst())
		{
			objUU2InfoNew.RemoveAll();
			objUU2Info.CreateObject(objUU2InfoNew);
			if(objUU2InfoNew.GetFirst())
			{
				objNewObject.AppendItemAscOrder(ulKey, objUU2InfoNew);
			}
		}

		lpContext = GetLowestNext(lpContext);
	}

	return true;
}

bool CUUU2Info::SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent)
{
	ULONG64 ulKey1 = 0;
	DWORD dwKey2 = 0, dwKey3 = 0;
	bool bSuccess = true, bFound = false;
	LPVOID lpCon1 = 0, lpCon2 = 0, lpCon3 = 0;
	CUUU2Info& objSearchL1 = (CUUU2Info&)objToSearch;
	CUU2Info objSearchL2(true), objThisL2(true);
	CU2Info objSearchL3(true), objThisL3(true);
	LPSPY_ENTRY_INFO lpSpyInfo = 0;

	lpCon1 = objSearchL1.GetFirst();
	while(lpCon1 && bSuccess)
	{
		objSearchL1.GetKey(lpCon1, ulKey1);
		objSearchL1.GetData(lpCon1, objSearchL2);

		if(SearchItem(ulKey1, objThisL2))
		{
			lpCon2 = objSearchL2.GetFirst();
			while(lpCon2 && bSuccess)
			{
				objSearchL2.GetKey(lpCon2, dwKey2);
				objSearchL2.GetData(lpCon2, objSearchL3);

				if(objThisL2.SearchItem(dwKey2, objThisL3))
				{
					lpCon3 = objSearchL3.GetFirst();
					while(lpCon3 && bSuccess)
					{
						objSearchL3.GetKey(lpCon3, dwKey3);

						bFound = objThisL3.SearchItem(dwKey3, lpSpyInfo);
						if((bFound && !bAllPresent) || (!bFound && bAllPresent))
						{
							bSuccess = false;
						}

						lpCon3 = objSearchL3.GetNext(lpCon3);
					}
				}
				else
				{
					if(bAllPresent)
					{
						bSuccess = false;
					}
				}

				lpCon2 = objSearchL2.GetNext(lpCon2);
			}
		}
		else
		{
			if(bAllPresent)
			{
				bSuccess = false;
			}
		}

		lpCon1 = objSearchL1.GetNext(lpCon1);
	}

	return bSuccess;
}

bool CUUU2Info::ReadUUU2In(SIZE_T nBaseAddr, LPBYTE& pData, PSIZE_T& pNode, DWORD& dwNodesMade)
{
	PSIZE_T pLink = 0;
	DWORD dwThisCount = 0, dwChildNodes = 0;
	CUU2Info objUU2Info(true);

	dwThisCount = *((LPDWORD)pData);
	pData += sizeof(DWORD);

	for(DWORD dwIndex = 0; dwIndex < dwThisCount; dwIndex++)
	{
		*pNode = (SIZE_T)pData; pNode++; pData += sizeof(ULONG64);
		*pNode = (SIZE_T)(pNode + 3); pNode++;
		*pNode = NULL; pNode++;
		pLink = pNode; pNode++;

		dwChildNodes = 0;
		if(!objUU2Info.ReadUU2In(nBaseAddr, pData, pNode, dwChildNodes))
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

bool CUUU2Info::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	LPBYTE lpTempData = 0;
	DWORD dwFileSize = 0, dwBytesRead = 0, dwNodesCount = 0, dwNodesMade = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szFullFileName[MAX_PATH] = {0};
	SIZE_T nBaseAddress = 0, *lpTempNode = 0;
	BYTE byHdrBfr[sizeof(HEADER_UUU2INFO) + sizeof(HEADER_UUU2INFO_DATA)] = {0};

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

	if(bCheckVersion && memcmp(HEADER_UUU2INFO, byHdrBfr, sizeof(HEADER_UUU2INFO)))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_UUU2INFO_DATA, sizeof(HEADER_UUU2INFO_DATA)))
	{
		goto ERROR_EXIT;
	}

	if(memcmp(byHdrBfr + sizeof(HEADER_UUU2INFO), HEADER_UUU2INFO_DATA, sizeof(HEADER_UUU2INFO_DATA) - sizeof(ULONG64)))
	{
		goto ERROR_EXIT;
	}

	memcpy(&dwNodesCount, byHdrBfr + sizeof(HEADER_UUU2INFO)+ sizeof(HEADER_UUU2INFO_DATA) - sizeof(ULONG64), sizeof(dwNodesCount));

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
	lpTempData = (LPBYTE)m_pBuffer;
	lpTempNode = (PSIZE_T)m_pRoot;

	if(!ReadUUU2In(nBaseAddress, lpTempData, lpTempNode, dwNodesMade))
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

bool CUUU2Info::DumpUUU2In(HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount)
{
	CUU2Info objUU2Info(true);
	DWORD dwCountOffset = 0, dwBytesWritten = 0, dwThisCount = 0, dwCurOff = 0, dwEmbdNodesCount = 0;

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

		WFILE(hFile, (LPVOID)m_pTemp->nKey, sizeof(ULONG64), &dwBytesWritten, 0);

		dwEmbdNodesCount = 0;
		if(!objUU2Info.DumpUU2In(hFile, (PNODEOPT)m_pTemp->nData, dwEmbdNodesCount))
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

bool CUUU2Info::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	HANDLE hFile = 0;
	DWORD dwBytesWritten = 0, dwNodesCount = 0, dwTemp = 0;

	hFile = CreateFile(szFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	SFPTR(hFile, sizeof(HEADER_UUU2INFO) + sizeof(HEADER_UUU2INFO_DATA), 0, FILE_BEGIN, dwTemp);

	if(!DumpUUU2In(hFile, m_pRoot, dwNodesCount))
	{
		goto ERROR_EXIT;
	}

	if(bEncryptContents && !CryptFileData(hFile, sizeof(HEADER_UUU2INFO) + sizeof(HEADER_UUU2INFO_DATA)))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFileName, HEADER_UUU2INFO_DATA, sizeof(HEADER_UUU2INFO_DATA), dwNodesCount))
	{
		goto ERROR_EXIT;
	}

	SFPTR(hFile, 0, 0, FILE_BEGIN, dwTemp);
	WFILE(hFile, HEADER_UUU2INFO, sizeof(HEADER_UUU2INFO), &dwBytesWritten, 0);
	WFILE(hFile, HEADER_UUU2INFO_DATA, sizeof(HEADER_UUU2INFO_DATA), &dwBytesWritten, 0);
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
