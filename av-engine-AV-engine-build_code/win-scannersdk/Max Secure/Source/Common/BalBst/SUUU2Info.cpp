#include "pch.h"
#include "SUUU2Info.h"

BYTE HEADER_SUUU2INFO[24]		= {"MAXDBVERSION00.00.00.09"};
BYTE HEADER_SUUU2INFO_DATA[24]	= {0};

CSUUU2Info::CSUUU2Info(bool bIsEmbedded):CBalBSTOpt(bIsEmbedded)
{
}

CSUUU2Info::~CSUUU2Info()
{
	RemoveAll();
}

COMPARE_RESULT CSUUU2Info::Compare(SIZE_T nKey1, SIZE_T nKey2)
{
	LPTSTR f = (LPTSTR)nKey1 ;
	LPTSTR s = (LPTSTR)nKey2 ;
	int iResult = 0 ;

	while ( *f && *s && *f == *s ) f++ , s++ ;
	iResult = *f - *s ;

	if(iResult > 0)
	{
		return LARGE;
	}
	else if(iResult < 0)
	{
		return SMALL;
	}
	else
	{
		return EQUAL;
	}
}

void CSUUU2Info::FreeKey(SIZE_T nKey)
{
	if ( (((LPBYTE)nKey) < m_pBuffer) || (((LPBYTE)nKey) >= (m_pBuffer + m_nBufferSize)) )
	{
		Release((LPVOID&)nKey);
	}
}

void CSUUU2Info::FreeData(SIZE_T nData)
{
	CUUU2Info objUUU2Info(false);
	objUUU2Info.SetDataPtr((PNODEOPT)nData, m_pBuffer, m_nBufferSize);
	objUUU2Info.RemoveAll();
	return;
}

bool CSUUU2Info::AppendItemAscOrder(LPCTSTR szKey, CUUU2Info& objUUU2Info)
{
	LPTSTR szKeyDup = 0;
	
	szKeyDup = (LPTSTR)DuplicateString(szKey);
	if(!szKeyDup)
	{
		return false;
	}

	if(!AddNodeAscOrder((SIZE_T)szKeyDup, (SIZE_T)objUUU2Info.GetDataPtr()))
	{
		Release((LPVOID&)szKeyDup);
		return false;
	}

	return true;
}

bool CSUUU2Info::AppendItem(LPCTSTR szKey, CUUU2Info& objUUU2Info)
{
	LPTSTR szKeyDup = 0;
	
	szKeyDup = (LPTSTR)DuplicateString(szKey);
	if(!szKeyDup)
	{
		return false;
	}

	if(!AddNode((SIZE_T)szKeyDup, (SIZE_T)objUUU2Info.GetDataPtr()))
	{
		Release((LPVOID&)szKeyDup);
		return false;
	}

	return true;
}

bool CSUUU2Info::DeleteItem(LPCTSTR szKey)
{
	return DeleteNode((SIZE_T)szKey);
}

bool CSUUU2Info::SearchItem(LPCTSTR szKey, CUUU2Info& objUUU2Info)
{
	SIZE_T nData = 0;

	if(!FindNode((SIZE_T)szKey, nData))
	{
		return false;
	}

	objUUU2Info.SetDataPtr((PNODEOPT)nData, m_pBuffer, m_nBufferSize);
	return true;
}

bool CSUUU2Info::UpdateItem(LPCTSTR szKey, CUUU2Info& objUUU2Info)
{
	if(!m_pLastSearchResult || (EQUAL != Compare(m_pLastSearchResult->nKey, (SIZE_T)szKey)))
	{
		SIZE_T nData = 0;

		if(!FindNode((SIZE_T)szKey, nData))
		{
			return false;
		}

		if(!m_pLastSearchResult || (EQUAL != Compare(m_pLastSearchResult->nKey, (SIZE_T)szKey)))
		{
			return false;
		}
	}

	m_pLastSearchResult->nData = (SIZE_T)objUUU2Info.GetDataPtr();
	return true;
}

bool CSUUU2Info::Balance()
{
	CUUU2Info objUUU2Info(true);
	LPVOID lpContext = NULL;

	CBalBSTOpt::Balance();
	lpContext = GetFirst();
	while(lpContext)
	{
		GetData(lpContext, objUUU2Info);
		objUUU2Info.Balance();
		((PNODEOPT)lpContext)->nData = (SIZE_T)objUUU2Info.GetDataPtr();
		lpContext = GetNext(lpContext);
	}

	return true;
}

bool CSUUU2Info::GetKey(PVOID lpContext, LPTSTR& szKey)
{
	if(!lpContext)
	{
		return false;
	}

	szKey = (LPTSTR)(((PNODEOPT)lpContext)->nKey);
	return true;
}

bool CSUUU2Info::GetData(PVOID lpContext, CUUU2Info& objUUU2Info)
{
	if(!lpContext)
	{
		return false;
	}

	objUUU2Info.SetDataPtr((PNODEOPT)(((PNODEOPT)lpContext)->nData), m_pBuffer, m_nBufferSize);
	return true;
}

bool CSUUU2Info::AppendObject(CBalBSTOpt& objToAdd)
{
	LPTSTR szKey1 = 0;
	ULONG64 ulKey2 = 0;
	DWORD dwKey3 = 0, dwKey4 = 0;
	LPSPY_ENTRY_INFO lpSpyInfo = 0;
	LPVOID lpCon1 = 0, lpCon2 = 0, lpCon3 = 0, lpCon4 = 0;
	CU2Info objAddL4(true), objThisL4(true);
	CUU2Info objAddL3(true), objThisL3(true);
	CUUU2Info objAddL2(true), objThisL2(true);
	CSUUU2Info& objAddL1 = (CSUUU2Info&)objToAdd;

	lpCon1 = objAddL1.GetFirst();
	while(lpCon1)
	{
		objAddL1.GetKey(lpCon1, szKey1);
		objAddL1.GetData(lpCon1, objAddL2);

		if(SearchItem(szKey1, objThisL2))
		{
			lpCon2 = objAddL2.GetFirst();
			while(lpCon2)
			{
				objAddL2.GetKey(lpCon2, ulKey2);
				objAddL2.GetData(lpCon2, objAddL3);

				if(objThisL2.SearchItem(ulKey2, objThisL3))
				{
					lpCon3 = objAddL3.GetFirst();
					while(lpCon3)
					{
						objAddL3.GetKey(lpCon3, dwKey3);
						objAddL3.GetData(lpCon3, objAddL4);

						if(objThisL3.SearchItem(dwKey3, objThisL4))
						{
							lpCon4 = objAddL4.GetFirst();
							while(lpCon4)
							{
								objAddL4.GetKey(lpCon4, dwKey4);
								objAddL4.GetData(lpCon4, lpSpyInfo);

								if(lpSpyInfo)
								{
									if(objThisL4.AppendItem(dwKey4, lpSpyInfo))
									{
										SetModified();
									}
								}

								lpCon4 = objAddL4.GetNext(lpCon4);
							}
						}
						else
						{
							if(objAddL4.GetFirst())
							{
								objThisL4.RemoveAll();
								objAddL4.CreateObject(objThisL4);
								if(objThisL4.GetFirst())
								{
									if(objThisL3.AppendItem(dwKey3, objThisL4))
									{
										SetModified();
									}
								}
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
							if(objThisL2.AppendItem(ulKey2, objThisL3))
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
					if(AppendItem(szKey1, objThisL2))
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


bool CSUUU2Info::DeleteObject(CBalBSTOpt& objToDel)
{
	LPTSTR szKey1 = 0;
	ULONG64 ulKey2 = 0;
	DWORD dwKey3 = 0, dwKey4 = 0;
	CU2Info objDelL4(true), objThisL4(true);
	CUU2Info objDelL3(true), objThisL3(true);
	CUUU2Info objDelL2(true), objThisL2(true);
	CSUUU2Info& objDelL1 = (CSUUU2Info&)objToDel;
	LPVOID lpCon1 = 0, lpCon2 = 0, lpCon3 = 0, lpCon4 = 0;

	lpCon1 = objDelL1.GetFirst();
	while(lpCon1)
	{
		objDelL1.GetKey(lpCon1, szKey1);
		objDelL1.GetData(lpCon1, objDelL2);

		if(SearchItem(szKey1, objThisL2))
		{
			lpCon2 = objDelL2.GetFirst();
			while(lpCon2)
			{
				objDelL2.GetKey(lpCon2, ulKey2);
				objDelL2.GetData(lpCon2, objDelL3);

				if(objThisL2.SearchItem(ulKey2, objThisL3))
				{
					lpCon3 = objDelL3.GetFirst();
					while(lpCon3)
					{
						objDelL3.GetKey(lpCon3, dwKey3);
						objDelL3.GetData(lpCon3, objDelL4);

						if(objThisL3.SearchItem(dwKey3, objThisL4))
						{
							lpCon4 = objDelL4.GetFirst();
							while(lpCon4)
							{
								objDelL4.GetKey(lpCon4, dwKey4);
								if(objThisL4.DeleteItem(dwKey4))
								{
									SetModified();
								}

								lpCon4 = objDelL4.GetNext(lpCon4);
							}

							objThisL3.UpdateItem(dwKey3, objThisL4);
							if(!objThisL4.GetFirst())
							{
								if(objThisL3.DeleteItem(dwKey3))
								{
									SetModified();
								}
							}
						}

						lpCon3 = objDelL3.GetNext(lpCon3);
					}

					objThisL2.UpdateItem(ulKey2, objThisL3);
					if(!objThisL3.GetFirst())
					{
						if(objThisL2.DeleteItem(ulKey2))
						{
							SetModified();
						}
					}
				}

				lpCon2 = objDelL2.GetNext(lpCon2);
			}

			UpdateItem(szKey1, objThisL2);
			if(!objThisL2.GetFirst())
			{
				if(DeleteItem(szKey1))
				{
					SetModified();
				}
			}
		}

		lpCon1 = objDelL1.GetNext(lpCon1);
	}

	return true;
}

bool CSUUU2Info::CreateObject(CSUUU2Info& objNewObject)
{
	LPVOID lpContext = 0;
	LPTSTR szKey = 0;
	CUUU2Info objUUU2Info(true), objUUU2InfoNew(true);

	lpContext = GetLowest();
	while(lpContext)
	{
		GetKey(lpContext, szKey);
		GetData(lpContext, objUUU2Info);

		if(szKey && objUUU2Info.GetFirst())
		{
			objUUU2InfoNew.RemoveAll();
			objUUU2Info.CreateObject(objUUU2InfoNew);
			if(objUUU2InfoNew.GetFirst())
			{
				objNewObject.AppendItemAscOrder(szKey, objUUU2InfoNew);
			}
		}

		lpContext = GetLowestNext(lpContext);
	}

	return true;
}

bool CSUUU2Info::SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent)
{
	LPTSTR szKey1 = 0;
	ULONG64 ulKey2 = 0;
	DWORD dwKey3 = 0, dwKey4 = 0;
	LPSPY_ENTRY_INFO lpSpyInfo = 0;
	bool bSuccess = true;
	CU2Info objSearchL4(true), objThisL4(true);
	CUU2Info objSearchL3(true), objThisL3(true);
	CUUU2Info objSearchL2(true), objThisL2(true);
	CSUUU2Info& objSearchL1 = (CSUUU2Info&)objToSearch;
	LPVOID lpCon1 = 0, lpCon2 = 0, lpCon3 = 0, lpCon4 = 0;

	lpCon1 = objSearchL1.GetFirst();
	while(lpCon1 && bSuccess)
	{
		objSearchL1.GetKey(lpCon1, szKey1);
		objSearchL1.GetData(lpCon1, objSearchL2);

		if(SearchItem(szKey1, objThisL2))
		{
			lpCon2 = objSearchL2.GetFirst();
			while(lpCon2 && bSuccess)
			{
				objSearchL2.GetKey(lpCon2, ulKey2);
				objSearchL2.GetData(lpCon2, objSearchL3);

				if(objThisL2.SearchItem(ulKey2, objThisL3))
				{
					lpCon3 = objSearchL3.GetFirst();
					while(lpCon3 && bSuccess)
					{
						objSearchL3.GetKey(lpCon3, dwKey3);
						objSearchL3.GetData(lpCon3, objSearchL4);

						if(objThisL3.SearchItem(dwKey3, objThisL4))
						{
							lpCon4 = objSearchL4.GetFirst();
							while(lpCon4 && bSuccess)
							{
								objSearchL4.GetKey(lpCon4, dwKey4);
								if(objThisL4.SearchItem(dwKey4, lpSpyInfo))
								{
									bSuccess = !bAllPresent?false:bSuccess;
								}
								else
								{
									bSuccess = bAllPresent?false:bSuccess;
								}

								lpCon4 = objSearchL4.GetNext(lpCon4);
							}
						}
						else
						{
							bSuccess = bAllPresent?false:bSuccess;
						}

						lpCon3 = objSearchL3.GetNext(lpCon3);
					}
				}
				else
				{
					bSuccess = bAllPresent?false:bSuccess;
				}

				lpCon2 = objSearchL2.GetNext(lpCon2);
			}
		}
		else
		{
			bSuccess = bAllPresent?false:bSuccess;
		}

		lpCon1 = objSearchL1.GetNext(lpCon1);
	}

	return bSuccess;
}

bool CSUUU2Info::ReadSUUU2In(SIZE_T nBaseAddr, LPBYTE& pData, PSIZE_T& pNode, DWORD& dwNodesMade)
{
	PSIZE_T pLink = 0;
	DWORD dwThisCount = 0, dwChildNodes = 0;
	CUUU2Info objUUU2Info(true);
	LPTSTR lpStr = 0;

	dwThisCount = *((LPDWORD)pData);
	pData += sizeof(DWORD);

	for(DWORD dwIndex = 0; dwIndex < dwThisCount; dwIndex++)
	{
		*pNode = (SIZE_T)pData; pNode++;
		lpStr = (LPTSTR)pData;
		while(*lpStr++);
		pData = (LPBYTE)lpStr;

		*pNode = (SIZE_T)(pNode + 3); pNode++;
		*pNode = NULL; pNode++;
		pLink = pNode; pNode++;

		dwChildNodes = 0;
		if(!objUUU2Info.ReadUUU2In(nBaseAddr, pData, pNode, dwChildNodes))
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

bool CSUUU2Info::Load(LPCTSTR szFileName, bool bCheckVersion)
{
	LPBYTE lpTempData = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szFullFileName[MAX_PATH] = {0};
	SIZE_T nBaseAddress = 0, *lpTempNode = 0;
	DWORD dwFileSize = 0, dwBytesRead = 0, dwNodesCount = 0, dwNodesMade = 0;
	BYTE byHdrBfr[sizeof(HEADER_SUUU2INFO) + sizeof(HEADER_SUUU2INFO_DATA)] = {0};

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

	if(bCheckVersion && memcmp(HEADER_SUUU2INFO, byHdrBfr, sizeof(HEADER_SUUU2INFO)))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFullFileName, HEADER_SUUU2INFO_DATA, sizeof(HEADER_SUUU2INFO_DATA)))
	{
		goto ERROR_EXIT;
	}

	if(memcmp(byHdrBfr + sizeof(HEADER_SUUU2INFO), HEADER_SUUU2INFO_DATA, sizeof(HEADER_SUUU2INFO_DATA) - sizeof(ULONG64)))
	{
		goto ERROR_EXIT;
	}

	memcpy(&dwNodesCount, byHdrBfr + sizeof(HEADER_SUUU2INFO) + sizeof(HEADER_SUUU2INFO_DATA) - sizeof(ULONG64), sizeof(dwNodesCount));

	m_pTemp = m_pRoot = NULL;
	dwFileSize = GetFileSize(hFile, 0);
	if(dwFileSize <= sizeof(byHdrBfr))
	{
		goto ERROR_EXIT;
	}

	dwFileSize -= sizeof(byHdrBfr);
	m_nBufferSize = dwFileSize + (SIZE_OF_NODEOPT * dwNodesCount);
	m_pBuffer = (LPBYTE)VAllocate(m_nBufferSize);
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

	if(!ReadSUUU2In(nBaseAddress, lpTempData, lpTempNode, dwNodesMade))
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

	TCHAR szNewFileName[MAX_PATH] = {0};
	_tcscpy_s(szNewFileName, _countof(szNewFileName), szFullFileName);
	_tcscat_s(szNewFileName, _countof(szNewFileName), _T(".bkp.wr"));
	MoveFile(szFullFileName, szNewFileName);
	AddLogEntry(L"Error in loading: %s.File Renamed", szFullFileName);
	return false;
}

bool CSUUU2Info::DumpSUUU2In(HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount)
{
	CUUU2Info objUUU2Info(true);
	DWORD dwCountOffset = 0, dwBytesWritten = 0, dwThisCount = 0, dwCurOff = 0, dwEmbdNodesCount = 0, dwKeySize = 0;

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

		dwKeySize = ((DWORD)_tcslen((LPTSTR)m_pTemp->nKey) + 1) * sizeof(TCHAR);
		WFILE(hFile, (LPVOID)m_pTemp->nKey, dwKeySize, &dwBytesWritten, 0);

		dwEmbdNodesCount = 0;
		if(!objUUU2Info.DumpUUU2In(hFile, (PNODEOPT)m_pTemp->nData, dwEmbdNodesCount))
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

bool CSUUU2Info::Save(LPCTSTR szFileName, bool bEncryptContents)
{
	HANDLE hFile = 0;
	DWORD dwBytesWritten = 0, dwNodesCount = 0, dwTemp = 0;
	BYTE byHdrBfr[sizeof(HEADER_SUUU2INFO) + sizeof(HEADER_SUUU2INFO_DATA)] = {0};

	hFile = CreateFile(szFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return false;
	}

	SFPTR(hFile, sizeof(byHdrBfr), 0, FILE_BEGIN, dwTemp);

	if(!DumpSUUU2In(hFile, m_pRoot, dwNodesCount))
	{
		goto ERROR_EXIT;
	}

	if(bEncryptContents && !CryptFileData(hFile, sizeof(byHdrBfr)))
	{
		goto ERROR_EXIT;
	}

	if(!CreateHeaderData(hFile, szFileName, HEADER_SUUU2INFO_DATA, sizeof(HEADER_SUUU2INFO_DATA), dwNodesCount))
	{
		goto ERROR_EXIT;
	}

	SFPTR(hFile, 0, 0, FILE_BEGIN, dwTemp);
	WFILE(hFile, HEADER_SUUU2INFO, sizeof(HEADER_SUUU2INFO), &dwBytesWritten, 0);
	WFILE(hFile, HEADER_SUUU2INFO_DATA, sizeof(HEADER_SUUU2INFO_DATA), &dwBytesWritten, 0);
	CloseHandle(hFile);
	return true;

ERROR_EXIT:

	if(INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
	}

	TCHAR szNewFileName[MAX_PATH] = {0};
	_tcscpy_s(szNewFileName, _countof(szNewFileName), szFileName);
	_tcscat_s(szNewFileName, _countof(szNewFileName), _T(".bkp.rd"));
	MoveFile(szFileName, szNewFileName);
	AddLogEntry(L"Error saving file: %s.File renamed.", szFileName);
	return false;
}
