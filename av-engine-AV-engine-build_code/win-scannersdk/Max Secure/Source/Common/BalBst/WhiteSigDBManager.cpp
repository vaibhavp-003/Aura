#include "pch.h"
#include "WhiteSigDBManager.h"
#include <TCHAR.h>

CWhiteSigDBManager::CWhiteSigDBManager()
{
	m_dwSmallDBCnt = 0x00;
	m_dwDeleteDBCnt = 0x00;
	m_pDbArray = NULL;
	m_pDeleteDBArray  = NULL;
	m_dwFirstSmallDBVer = 0x00;
	m_dwFirstDeleteDBVer = 0x00;
}

CWhiteSigDBManager::~CWhiteSigDBManager()
{
	RemoveSmallDBs();
}

DWORD	CWhiteSigDBManager::GetSD44Ver(LPCTSTR pszFileName)
{
	DWORD		dwRetVal = 0x00;
	CString		csFileName;

	if (pszFileName == NULL)
	{
		return dwRetVal;
	}

	csFileName.Format(L"%s",pszFileName);
	csFileName.MakeUpper();

	csFileName.Replace(L"SD44_",L"");
	csFileName.Replace(L"SD44D_",L"");

	dwRetVal = _tstol(csFileName);

	return dwRetVal;
}

DWORD	CWhiteSigDBManager::GetHeighestVersion()
{
	DWORD	dwRetValue = 440000000;

	if (m_dwSmallDBCnt <= 0x00)
	{
		return dwRetValue;
	}

	dwRetValue = m_pDbArray[m_dwSmallDBCnt - 0x01]->dwVersion;

	return dwRetValue;
}

DWORD	CWhiteSigDBManager::LoadSmallDBs(LPCTSTR pszDBFolderName, bool bCheckVersion, bool bEncryptData, bool * pbDeleteIfFail)
{
	DWORD		dwDBIndex = 0x00;
	TCHAR		szDBFolPath[MAX_PATH] = {0x00};
	TCHAR		szDBPath[MAX_PATH] = {0x00};
	BOOL		bFind = FALSE;
	bool		bLoadStatus = false;

	if (_taccess_s(pszDBFolderName,0) != 0)
	{
		return dwDBIndex; 
	}
	
	_stprintf(szDBFolPath,L"%sSD44_44*.db",pszDBFolderName);


	CFileFind	objDbFinder;
	bFind = objDbFinder.FindFile(szDBFolPath);
	while(bFind)
	{
		_tcscpy_s(szDBPath,MAX_PATH,L"");

		bFind = objDbFinder.FindNextFileW();

		if (objDbFinder.IsDirectory() == FALSE && objDbFinder.IsDots() == FALSE)
		{
			if (dwDBIndex  > m_dwSmallDBCnt)
			{
				break;
			}
			_tcscpy_s(szDBPath,MAX_PATH,objDbFinder.GetFilePath());

			bLoadStatus = m_pDbArray[dwDBIndex]->objMaxPESig.Load(szDBPath,bCheckVersion,bEncryptData,pbDeleteIfFail);
			m_pDbArray[dwDBIndex]->dwVersion = GetSD44Ver(objDbFinder.GetFileName());


			if (bLoadStatus == false)
			{
				break;
			}

			dwDBIndex++;
		}
	}
	objDbFinder.Close();
	

	return dwDBIndex; 
}


DWORD	CWhiteSigDBManager::GetSmallDBCount(LPCTSTR pszDBFolderName)
{
	DWORD		dwDBFileCnt = 0x00;
	TCHAR		szDBFolPath[MAX_PATH] = {0x00};
	BOOL		bFind = FALSE;

	
	if (_taccess(pszDBFolderName,0) != 0)
	{
		return dwDBFileCnt; 
	}
	
	_stprintf_s(szDBFolPath,MAX_PATH,L"%sSD44_44*.db",pszDBFolderName);


	CFileFind	objDbFinder;
	bFind = objDbFinder.FindFile(szDBFolPath);
	while(bFind)
	{
		bFind = objDbFinder.FindNextFileW();
		if (objDbFinder.IsDirectory() == FALSE && objDbFinder.IsDots() == FALSE)
		{
			dwDBFileCnt++;
		}
	}
	objDbFinder.Close();
	
	return dwDBFileCnt; 
}

bool CWhiteSigDBManager::CreateSmallDBArray()
{
	bool	bArrayCreated = false;

	if (m_dwSmallDBCnt <= 0x00)
	{
		return	bArrayCreated;
	}

	//Reminder for Ravi : Need to Add Error Handling
	m_pDbArray = (WHITESIGDBARRAY **)calloc(m_dwSmallDBCnt,sizeof(WHITESIGDBARRAY *));

	
	if (m_pDbArray == NULL)
	{
		return bArrayCreated;
	}

	bArrayCreated = true;

	for(DWORD i = 0x00; i < m_dwSmallDBCnt; i++)
	{
		m_pDbArray[i] = new WHITESIGDBARRAY;

		if (m_pDbArray[i] == NULL)
		{
			bArrayCreated = false;
			break;
		}
	}

	return	bArrayCreated;
}

bool CWhiteSigDBManager::Load(LPCTSTR szFolderName, bool bCheckVersion, bool bEncryptData, bool * pbDeleteIfFail)
{
	TCHAR	szLargeDbFileName[MAX_PATH];
	bool	bStatus = false;
	DWORD	dwDBLoadedCnt = 0x00;
	
	_stprintf(szLargeDbFileName,L"%s%s",szFolderName , SD_DB_FS_WHT);
	bStatus = m_WhiteFilePESig.Load(szLargeDbFileName,bCheckVersion,bEncryptData,pbDeleteIfFail);
	if (bStatus == false)
	{
		return bStatus;
	}

	m_dwSmallDBCnt = GetSmallDBCount(szFolderName);
	if (m_dwSmallDBCnt > 0x00)
	{
		if (CreateSmallDBArray())
		{
			dwDBLoadedCnt = LoadSmallDBs(szFolderName,bCheckVersion, bEncryptData, pbDeleteIfFail);
			if (dwDBLoadedCnt != m_dwSmallDBCnt)
			{
				bStatus = false;
			}
			if (dwDBLoadedCnt > 0x00)
			{
				m_dwFirstSmallDBVer = m_pDbArray[0x00]->dwVersion;
			}
		}
		else
		{
			bStatus = false;
		}
	}

	//Delete Db Loading
	m_dwDeleteDBCnt = GetDeleteDBCount(szFolderName);
	if (m_dwDeleteDBCnt > 0x00)
	{
		if (CreateDeleteDBArray())
		{
			dwDBLoadedCnt = LoadDeleteDBs(szFolderName,bCheckVersion, bEncryptData, pbDeleteIfFail);
			if (dwDBLoadedCnt != m_dwDeleteDBCnt)
			{
				bStatus = false;
			}
			if (dwDBLoadedCnt > 0x00)
			{
				m_dwFirstDeleteDBVer = m_pDeleteDBArray[0x00]->dwVersion;
			}
		}
		else
		{
			bStatus = false;
		}
	}
	
	return bStatus;
}

bool CWhiteSigDBManager::SearchSigInSmallDs(PULONG64 pSig2Search, LPDWORD pSpyID, DWORD dwLocalVer, bool *pbFoundInDelete)
{
	bool	bResult = false;
	DWORD	dwSigMatchVer = 0x00;
	bool	bDeleteResult = false;

	if (m_dwSmallDBCnt <= 0x00)
	{
		return bResult;
	}
	if (m_pDbArray == NULL)
	{
		return bResult;
	}
	for (int i = (m_dwSmallDBCnt - 0x01); i >= 0x00; i--)
	{
		if (m_pDbArray[i] != NULL)
		{
			if (m_pDbArray[i]->dwVersion > dwLocalVer)
			{
				bResult = false;
				bResult = m_pDbArray[i]->objMaxPESig.SearchSig(pSig2Search,pSpyID);
				if (bResult)
				{
					dwSigMatchVer = m_pDbArray[i]->dwVersion;
					break;
				}
			}
		}
	}

	if(bResult == true)
	{
		//Searching In Delete DB
		bDeleteResult = SearchSigInDeleteDbs(pSig2Search,pSpyID,dwSigMatchVer);
		if (bDeleteResult)
		{
			if (pbFoundInDelete != NULL)
			{
				*pbFoundInDelete = true;
			}
			bResult = false;
		}
	}

	return bResult;
}

bool CWhiteSigDBManager::SearchSig(PULONG64 pSig, LPDWORD pSpyID, DWORD dwLocalVer)
{
	DWORD			dwIndex = 0x00;
	bool			bResult = false;
	bool			bDeleteResult = false;
	bool			bFoundInDelete = false;

	if (pSig == NULL || *pSig == 0x00)
	{
		return bResult;
	}

	bResult = SearchSigInSmallDs(pSig, pSpyID, dwLocalVer,&bFoundInDelete);
	
	if (bResult == false && bFoundInDelete == false)
	{
		if (m_dwFirstSmallDBVer >= dwLocalVer)
		{
			bResult = m_WhiteFilePESig.SearchSig(pSig, pSpyID);
			if (bResult)
			{
				bDeleteResult = SearchSigInDeleteDbs(pSig, pSpyID);
				if (bDeleteResult == true)
				{
					return false;
				}
			}
		}
	}
	
	return bResult;
}

bool CWhiteSigDBManager::RemoveAll(bool bRemoveTree)
{
	m_WhiteFilePESig.RemoveAll(bRemoveTree);
	RemoveSmallDBs();
	return true;
}

DWORD	CWhiteSigDBManager::GetDeleteDBCount(LPCTSTR pszDBFolderName)
{
	DWORD		dwDBFileCnt = 0x00;
	TCHAR		szDBFolPath[MAX_PATH] = {0x00};
	BOOL		bFind = FALSE;

	if (_taccess(pszDBFolderName,0) != 0)
	{
		return dwDBFileCnt; 
	}
	
	_stprintf(szDBFolPath,L"%sSD44D_44*.db",pszDBFolderName);

	CFileFind	objDbFinder;
	bFind = objDbFinder.FindFile(szDBFolPath);
	while(bFind)
	{
		bFind = objDbFinder.FindNextFileW();
		if (objDbFinder.IsDirectory() == FALSE && objDbFinder.IsDots() == FALSE)
		{
			dwDBFileCnt++;
		}
	}
	objDbFinder.Close();
	
	return dwDBFileCnt; 
}

DWORD	CWhiteSigDBManager::LoadDeleteDBs(LPCTSTR pszDBFolderName, bool bCheckVersion, bool bEncryptData, bool * pbDeleteIfFail)
{
	DWORD		dwDBIndex = 0x00;
	TCHAR		szDBFolPath[MAX_PATH] = {0x00};
	TCHAR		szDBPath[MAX_PATH] = {0x00};
	BOOL		bFind = FALSE;
	bool		bLoadStatus = false;


	if (_taccess_s(pszDBFolderName,0) != 0)
	{
		return dwDBIndex; 
	}
	
	_stprintf(szDBFolPath,L"%sSD44D_44*.db",pszDBFolderName);


	CFileFind	objDbFinder;
	bFind = objDbFinder.FindFile(szDBFolPath);
	while(bFind)
	{
		_tcscpy_s(szDBPath,MAX_PATH,L"");

		bFind = objDbFinder.FindNextFileW();

		if (objDbFinder.IsDirectory() == FALSE && objDbFinder.IsDots() == FALSE)
		{
			if (dwDBIndex  > m_dwDeleteDBCnt)
			{
				break;
			}
			_tcscpy_s(szDBPath,MAX_PATH,objDbFinder.GetFilePath());


			bLoadStatus = m_pDeleteDBArray[dwDBIndex]->objMaxPESig.Load(szDBPath,bCheckVersion,bEncryptData,pbDeleteIfFail);
			m_pDeleteDBArray[dwDBIndex]->dwVersion = GetSD44Ver(objDbFinder.GetFileName());

			if (bLoadStatus == false)
			{
				break;
			}

			dwDBIndex++;
		}
	}
	objDbFinder.Close();
	

	return dwDBIndex; 
}

bool CWhiteSigDBManager::CreateDeleteDBArray()
{
	bool	bArrayCreated = false;

	if (m_dwDeleteDBCnt <= 0x00)
	{
		return	bArrayCreated;
	}

	//Reminder for Ravi : Need to Add Error Handling
	m_pDeleteDBArray = (WHITESIGDBARRAY **)calloc(m_dwDeleteDBCnt,sizeof(WHITESIGDBARRAY *));

	if (m_pDeleteDBArray == NULL)
	{
		return bArrayCreated;
	}

	bArrayCreated = true;

	for(DWORD i = 0x00; i < m_dwDeleteDBCnt; i++)
	{
		m_pDeleteDBArray[i] = new WHITESIGDBARRAY;

		if (m_pDeleteDBArray[i] == NULL)
		{
			bArrayCreated = false;
			break;
		}
	}
	return	bArrayCreated;
}

bool CWhiteSigDBManager::SearchSigInDeleteDbs(PULONG64 pSig2Search, LPDWORD pSpyID, DWORD dwSigMatchVer)
{
	bool	bResult = false;

	if (m_dwDeleteDBCnt <= 0x00)
	{
		return bResult;
	}
	if (m_pDeleteDBArray == NULL)
	{
		return bResult;
	}
	//for (int i = 0x00; i < m_dwSmallDBCnt; i++)
	for (int i = (m_dwDeleteDBCnt - 0x01); i >= 0x00; i--)
	{
		if (m_pDeleteDBArray[i] != NULL)
		{
			if (m_pDeleteDBArray[i]->dwVersion > dwSigMatchVer)
			{
				bResult = false;
				bResult = m_pDeleteDBArray[i]->objMaxPESig.SearchSig(pSig2Search,pSpyID);
				if (bResult)
				{
					if (pSpyID != NULL)
					{
						*pSpyID = 0x00;
					}
					return bResult;
				}
			}
		}
	}


	return bResult;
}
void CWhiteSigDBManager::RemoveSmallDBs()
{
	if (m_pDbArray != NULL && m_dwSmallDBCnt > 0x00)
	{
		for (DWORD i = 0x00; i< m_dwSmallDBCnt; i++)
		{
			if (m_pDbArray[i] != NULL)
			{
				m_pDbArray[i]->objMaxPESig.RemoveAll();
				free(m_pDbArray[i]);
				m_pDbArray[i] = NULL;
			}
		}
		free(m_pDbArray);
	}
	m_pDbArray = NULL;

	if (m_pDeleteDBArray != NULL && m_dwDeleteDBCnt > 0x00)
	{
		for (DWORD i = 0x00; i< m_dwDeleteDBCnt; i++)
		{
			if (m_pDeleteDBArray[i] != NULL)
			{
				m_pDeleteDBArray[i]->objMaxPESig.RemoveAll();
				free(m_pDeleteDBArray[i]);
				m_pDeleteDBArray[i] = NULL;
			}
		}
		free(m_pDeleteDBArray);
	}
	m_pDeleteDBArray = NULL;

	m_dwDeleteDBCnt = 0x00;
	m_dwSmallDBCnt = 0x00;
}