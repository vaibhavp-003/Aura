#include "pch.h"
#include "BlackDBManager.h"
#include <TCHAR.h>

CBlackDBManager::CBlackDBManager()
{
	m_dwSmallDBCnt = 0x00;
	m_dwDeleteDBCnt = 0x00;

	m_pDbArray = NULL;
	m_pDeleteDBArray = NULL;

	m_dwFirstSmallDBVer = 0x00;
	m_dwFirstDeleteDBVer  = 0x00;
}

CBlackDBManager::~CBlackDBManager()
{
	RemoveSmallDBs();
}

DWORD	CBlackDBManager::GetSD43Ver(LPCTSTR pszFileName)
{
	DWORD		dwRetVal = 0x00;
	CString		csFileName;

	if (pszFileName == NULL)
	{
		return dwRetVal;
	}

	csFileName.Format(L"%s",pszFileName);
	csFileName.MakeUpper();

	csFileName.Replace(L"SD43_",L"");
	csFileName.Replace(L"SD43D_",L"");

	dwRetVal = _tstol(csFileName);

	return dwRetVal;
}

DWORD	CBlackDBManager::GetHeighestVersion()
{
	DWORD	dwRetValue = 430000000;

	if (m_dwSmallDBCnt <= 0x00)
	{
		return dwRetValue;
	}

	dwRetValue = m_pDbArray[m_dwSmallDBCnt - 0x01]->dwVersion;

	return dwRetValue;
}

DWORD	CBlackDBManager::LoadDeleteDBs(LPCTSTR pszDBFolderName, bool bCheckVersion, bool bEncryptData, bool * pbDeleteIfFail)
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
	
	_stprintf(szDBFolPath,L"%sSD43D_43*.db",pszDBFolderName);

	CFileFind	objDbFinder;
	bFind = objDbFinder.FindFile(szDBFolPath);
	while(bFind)
	{
		_tcscpy_s(szDBPath, MAX_PATH,L"");

		bFind = objDbFinder.FindNextFileW();

		if (objDbFinder.IsDirectory() == FALSE && objDbFinder.IsDots() == FALSE)
		{
			if (dwDBIndex  > m_dwDeleteDBCnt)
			{
				break;
			}
			_tcscpy_s(szDBPath,MAX_PATH,objDbFinder.GetFilePath());


			bLoadStatus = m_pDeleteDBArray[dwDBIndex]->objMaxPESig.Load(szDBPath,bCheckVersion,bEncryptData,pbDeleteIfFail);
			m_pDeleteDBArray[dwDBIndex]->dwVersion = GetSD43Ver(objDbFinder.GetFileName());

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

DWORD	CBlackDBManager::LoadSmallDBs(LPCTSTR pszDBFolderName, bool bCheckVersion, bool bEncryptData, bool * pbDeleteIfFail)
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
	
	_stprintf(szDBFolPath,L"%sSD43_43*.db",pszDBFolderName);


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
			_tcscpy_s(szDBPath, MAX_PATH,objDbFinder.GetFilePath());


			bLoadStatus = m_pDbArray[dwDBIndex]->objMaxPESig.Load(szDBPath,bCheckVersion,bEncryptData,pbDeleteIfFail);
			m_pDbArray[dwDBIndex]->dwVersion = GetSD43Ver(objDbFinder.GetFileName());


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

DWORD	CBlackDBManager::GetDeleteDBCount(LPCTSTR pszDBFolderName)
{
	DWORD		dwDBFileCnt = 0x00;
	TCHAR		szDBFolPath[MAX_PATH] = {0x00};
	BOOL		bFind = FALSE;

	if (_taccess(pszDBFolderName,0) != 0)
	{
		return dwDBFileCnt; 
	}
	
	_stprintf(szDBFolPath,L"%sSD43D_43*.db",pszDBFolderName);

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

DWORD	CBlackDBManager::GetSmallDBCount(LPCTSTR pszDBFolderName)
{
	DWORD		dwDBFileCnt = 0x00;
	TCHAR		szDBFolPath[MAX_PATH] = {0x00};
	BOOL		bFind = FALSE;


	if (_taccess(pszDBFolderName,0) != 0)
	{
		return dwDBFileCnt; 
	}
	
	_stprintf(szDBFolPath,L"%sSD43_43*.db",pszDBFolderName);


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

bool CBlackDBManager::CreateDeleteDBArray()
{
	bool	bArrayCreated = false;

	if (m_dwDeleteDBCnt <= 0x00)
	{
		return	bArrayCreated;
	}


	//Reminder for Ravi : Need to Add Error Handling
	m_pDeleteDBArray = (DBARRAY **)calloc(m_dwDeleteDBCnt,sizeof(DBARRAY *));

	if (m_pDeleteDBArray == NULL)
	{
		return bArrayCreated;
	}

	bArrayCreated = true;

	for(DWORD i = 0x00; i < m_dwDeleteDBCnt; i++)
	{
		m_pDeleteDBArray[i] = new DBARRAY;

		if (m_pDeleteDBArray[i] == NULL)
		{
			bArrayCreated = false;
			break;
		}
	}
	return	bArrayCreated;
}

bool CBlackDBManager::CreateSmallDBArray()
{
	bool	bArrayCreated = false;

	if (m_dwSmallDBCnt <= 0x00)
	{
		return	bArrayCreated;
	}


	//Reminder for Ravi : Need to Add Error Handling
	m_pDbArray = (DBARRAY **)calloc(m_dwSmallDBCnt,sizeof(DBARRAY *));
	
	if (m_pDbArray == NULL)
	{
		return bArrayCreated;
	}

	bArrayCreated = true;

	for(DWORD i = 0x00; i < m_dwSmallDBCnt; i++)
	{
		m_pDbArray[i] = new DBARRAY;

		if (m_pDbArray[i] == NULL)
		{
			bArrayCreated = false;
			break;
		}
	}

	

	return	bArrayCreated;
}

bool CBlackDBManager::Load(LPCTSTR szFolderName, bool bCheckVersion, bool bEncryptData, bool * pbDeleteIfFail)
{
	TCHAR	szFileName[MAX_PATH];
	bool	bStatus = false;
	DWORD	dwDBLoadedCnt = 0x00;
	
	for(int iIndex = 0x00; iIndex <= 0x0F; iIndex++)
	{
		_stprintf_s(szFileName, MAX_PATH, _T("%sSD43_%0.1X.db"), szFolderName, iIndex);
		bStatus =  m_arrStaticBlackDB[iIndex].Load(szFileName, bCheckVersion, bEncryptData, pbDeleteIfFail);
		if(!bStatus)
			break;

		_stprintf_s(szFileName, MAX_PATH, _T("%sSD43_%0.1XT.db"), szFolderName, iIndex);
		bStatus =  m_arrNewBlackDB[iIndex].Load(szFileName, bCheckVersion, bEncryptData, pbDeleteIfFail);
		if(!bStatus)
			break;
	}	

	if (bStatus)
	{
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

bool CBlackDBManager::RemoveAll(bool bRemoveTree)
{
	for(int iIndex = 0x00 ; iIndex <= 0x0F; iIndex++)
	{
		m_arrStaticBlackDB[iIndex].RemoveAll(bRemoveTree);
	}
	for(int iIndex = 0x00 ; iIndex <= 0x0F; iIndex++)
	{
		m_arrNewBlackDB[iIndex].RemoveAll(bRemoveTree);
	}
	RemoveSmallDBs();
	return true;
}

bool CBlackDBManager::SearchSigInDeleteDbs(PULONG64 pSig2Search, LPDWORD pSpyID, DWORD dwSigMatchVer)
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
				bResult = m_pDeleteDBArray[i]->objMaxPESig.SearchSigEx(pSig2Search,pSpyID);
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

bool CBlackDBManager::SearchSigInSmallDs(PULONG64 pSig2Search, LPDWORD pSpyID, DWORD dwLocalVer, bool *pbFoundInDelete)
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
	for (int i = (m_dwSmallDBCnt - 0x01); i >= 0x00 ; i--)
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

bool CBlackDBManager::SearchSig(PULONG64 pSig, LPDWORD pSpyID, DWORD dwLocalVer)
{
	DWORD			dwIndex = 0x00;
	bool			bResult = false;
	bool			bDeleteResult = false;
	bool			bFoundInDelete = false;
	unsigned char	szNewPESig[0x06] = {0x00};
	CMaxSmallPESig	objNewPESig;
	ULONG64			ulSmallSig = 0x00;

	if (pSig == NULL || *pSig == 0x00)
	{
		return bResult;
	}
	ULONG64	ulSig = *pSig;
	objNewPESig.GetNewPESig(ulSig,&szNewPESig[0x00],&ulSmallSig);

	if (ulSmallSig == 0x00)
	{
		return bResult;
	}

	//dwIndex = GetSignatureIndex(&szNewPESig[0x00]);
	dwIndex = szNewPESig[0x00] / 0x10;

	//Reminder for Ravi : No need for this array : m_arrNewBlackDB.

	bResult = SearchSigInSmallDs(&ulSmallSig, pSpyID, dwLocalVer,&bFoundInDelete);
	
	if(bResult == false && bFoundInDelete == false)
	{
		if (m_dwFirstSmallDBVer >= dwLocalVer)
		{
			bResult = m_arrNewBlackDB[dwIndex].SearchSig(&ulSmallSig, pSpyID);
			if(bResult == false)
			{
				bResult = m_arrStaticBlackDB[dwIndex].SearchSig(&ulSmallSig, pSpyID);
			}
			if (bResult)
			{
				bDeleteResult = SearchSigInDeleteDbs(&ulSmallSig, pSpyID);
				if (bDeleteResult == true)
				{
					return false;
				}
			}
		}
	}

	return bResult;
}

/*
int CBlackDBManager::GetSignatureIndex(PULONG64 pSig)
{
	ULONG64 ulLocalSig = *pSig;
	ulLocalSig = ulLocalSig >> 32;
	ulLocalSig = ulLocalSig >> 28;
	ulLocalSig = ulLocalSig % 0x10;
	return (int)ulLocalSig;
}
*/

DWORD CBlackDBManager::GetSignatureIndex(unsigned char *pszSig)
{
	DWORD	dwIndex = 0x00;

	dwIndex = pszSig[0x00] / 0x10;

	return dwIndex;
}

bool CBlackDBManager::AppendObject(CMaxNewPESig& objToAdd)
{
	return MergeObject(objToAdd, true);
}

bool CBlackDBManager::DeleteObject(CMaxNewPESig& objToDel)
{
	return MergeObject(objToDel, false);
}

bool CBlackDBManager::AppendObject(CFSDB& objToAdd)
{
	return MergeObject(objToAdd, true);
}

bool CBlackDBManager::DeleteObject(CFSDB& objToDel)
{
	return MergeObject(objToDel, false);
}

bool CBlackDBManager::MergeObject(CMaxNewPESig& objToAdd, bool bAdd)
{
	bool			bRetValue = false;
	unsigned char	*pszSigBuff = NULL;
	DWORD			dwBuffSize = 0x2800;
	DWORD			dwRet = 0x00;
	LPSMALLELMNT	lpElmnt = NULL;
	DWORD			dwSpyID = 0x00;
	ULONG64			ulSmallSig = 0x00;
	unsigned char	szNewPESig[0x06] = {0x00};
	int				iPageIndex = -1;
	CMaxSmallPESig	objSigConvertor;
	DWORD			dwArrayIndex = 0x00;	
	TCHAR			szLogLine[MAX_PATH] = {0x00}; 
	DWORD			dwBuffRead = 0x00;

	pszSigBuff = (unsigned char *)calloc(dwBuffSize,sizeof(unsigned char));
	if (pszSigBuff == NULL)
	{
		return false;
	}

	while(1)
	{
		memset(pszSigBuff,0x00,sizeof(dwBuffSize));
		dwRet = objToAdd.GetSigBuff4Insertion(pszSigBuff,dwBuffSize);
		if (dwRet == 0x00)
		{
			break;
		}
		else
		{
			bRetValue = true;
		}

		lpElmnt = (LPSMALLELMNT)pszSigBuff;
		if(!lpElmnt)
		{
			bRetValue = false;
			break;
		}

		dwBuffRead = dwRet;
		dwRet = dwRet / iSMALLELEMENT_SIZE;


		for(DWORD iIndex = 0x00; iIndex < dwRet; iIndex++)
		{
			dwSpyID = 0x00;
			memset(&szNewPESig[0x00],0x00,0x06);
			memcpy(&szNewPESig[0x00],&lpElmnt[iIndex].szPESig[0x00],0x06);
			dwSpyID = lpElmnt[iIndex].dwSpyID;

			objSigConvertor.GetUlongFromSz(&szNewPESig[0x00],&ulSmallSig);
			if(0 == ulSmallSig)
			{
				continue;
			}

			dwArrayIndex = szNewPESig[0x00] / 0x10;

			iPageIndex = m_arrNewBlackDB[dwArrayIndex].GetPageIndex(ulSmallSig);
			if (iPageIndex < 0)
			{
				continue;
			}

			m_arrNewBlackDB[dwArrayIndex].m_bModified = true;


			if (bAdd)
			{
				m_arrNewBlackDB[dwArrayIndex].InsertItem(&szNewPESig[0x00],dwSpyID,bAdd,iPageIndex);
			}
			else
			{
				//dwSpyID = 0x00;
					
				m_arrNewBlackDB[dwArrayIndex].m_bDelEntry = true;
				m_arrNewBlackDB[dwArrayIndex].InsertItem(&szNewPESig[0x00],dwSpyID,bAdd,iPageIndex);
			}

		}

		Sleep(20);
			

		if (dwBuffRead < dwBuffSize)
		{
			bRetValue = true;
			break;
		}
	}
	if (NULL != pszSigBuff)
	{
		free(pszSigBuff);
		pszSigBuff = NULL;
	}

	return bRetValue;
}

bool CBlackDBManager::MergeObject(CFSDB& objFSDB, bool bAdd)
{
	DWORD			dwSpyID = 0;
	int				iPageIndex = -1;
	ULONG64			ulSig = 0, ulSmallSig = 0x00;
	DWORD			dwIndex = 0;
	CMaxSmallPESig	objSigConvertor;
	unsigned char	szNewPESig[0x06] = {0x00};
	DWORD			dwSigCnt = 0x00;

	if(!objFSDB.GetFirst(&ulSig, &dwSpyID))
	{
		return false;
	}

	do
	{
		if(0 == ulSig)
		{
			continue;
		}

		dwSigCnt++;
		if (dwSigCnt >= 0x800)
		{
			dwSigCnt = 0x00;
			Sleep(20);
		}
		
		memset(&szNewPESig[0x00],0x00,0x06);

		objSigConvertor.GetNewPESig(ulSig,&szNewPESig[0x00],&ulSmallSig);
		//dwIndex = GetSignatureIndex(&szNewPESig[0x00]);
		if(0 == ulSmallSig)
		{
			continue;
		}

		dwIndex = szNewPESig[0x00] / 0x10;

		iPageIndex = m_arrNewBlackDB[dwIndex].GetPageIndex(ulSmallSig);
		if (iPageIndex < 0)
		{
			continue;
		}

		m_arrNewBlackDB[dwIndex].m_bModified = true;


		if (bAdd)
		{
			m_arrNewBlackDB[dwIndex].InsertItem(&szNewPESig[0x00],dwSpyID,bAdd,iPageIndex);
		}
		else
		{
			//dwSpyID = 0x00;
				
			m_arrNewBlackDB[dwIndex].m_bDelEntry = true;
			m_arrNewBlackDB[dwIndex].InsertItem(&szNewPESig[0x00],dwSpyID,bAdd,iPageIndex);

			//m_arrStaticBlackDB[dwIndex].m_bDelEntry = true;
			//m_arrStaticBlackDB[dwIndex].InsertItem(&szNewPESig[0x00],dwSpyID,bAdd,iPageIndex);
		}
		
	}while(objFSDB.GetNext(&ulSig, &dwSpyID));



	return true;
}

bool CBlackDBManager::IsModified()
{
	for(int iIndex = 0x00 ; iIndex <= 0x0F; iIndex++)
	{
		if(m_arrNewBlackDB[iIndex].IsModified())
			return true;
	}
	return false;
}

void CBlackDBManager::Balance()
{
	/*
	for(int iIndex = 0x00 ; iIndex <= 0x0F; iIndex++)
	{
		if(m_arrNewBlackDB[iIndex].IsModified())
			m_arrNewBlackDB[iIndex].Balance();
	}
	*/
	return;
}

bool CBlackDBManager::Save(LPCTSTR szFolderName, bool bCheckVersion, bool bEncryptData)
{
	TCHAR	szFileName[MAX_PATH];
	bool	bStatus = false;

	for(int iIndex = 0x00; iIndex <= 0x0F; iIndex++)
	{
		//Tushar : Check
		//if(m_arrNewBlackDB[iIndex].IsModified())
		//{
			_stprintf_s(szFileName, MAX_PATH, _T("%sSD43_%0.1XT.db"), szFolderName, iIndex);
			//AddLogEntry(L"CBlackDBManager:: Before Save ===== ");
			//AddLogEntry(szFileName);
			bStatus =  m_arrNewBlackDB[iIndex].Save(szFileName, bCheckVersion, bEncryptData);
			if(!bStatus)
			{
				AddLogEntry(L"CBlackDBManager::Save Failed");
				AddLogEntry(szFileName);
				break;
			}
		//}
	}	
	return bStatus;
}
void CBlackDBManager::RemoveSmallDBs()
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

	m_dwSmallDBCnt = 0x00;
	m_dwDeleteDBCnt = 0x00;
}