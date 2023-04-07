#include "StdAfx.h"
#include "MaxSqliteMgr.h"


CMaxSqliteMgr::CMaxSqliteMgr(LPCTSTR pszDBPath):CMaxSqLiteBase(pszDBPath)
{
	memset(&m_MaxScanData,0x00,sizeof(UNSAFE_FILE_FULL_INFO) * 15); 

}

CMaxSqliteMgr::~CMaxSqliteMgr(void)
{

}

bool CMaxSqliteMgr::GetLocalFileInfo(LPCTSTR pszFileMD5,LPUNSAFE_FILE_INFO pszResults)
{
	bool			bFound = false;
	TCHAR			szQuery[2048] = {0x00};
	TCHAR			szKeyName[1024] = {0x00};
	char			szData[1024] = {0x00};

	if (m_bDBLoaded == FALSE)
	{ 
		return bFound;
	}

	if (!pszResults)
	{
		return bFound;
	}
	
	_stprintf(szQuery,L"SELECT * FROM ThreatIntelligence WHERE File_MD5 = '%s' LIMIT 1",pszFileMD5);
	bFound = ExecuteQuery(szQuery,TRUE);
	if (bFound)
	{
		bFound = false;
		m_bEnumStarted = TRUE;
		int iRetval = sqlite3_step(m_pstmGetAll);
		if (iRetval == SQLITE_ROW)
		{
			bFound = true;
			GetScanRecord(pszResults);
		}
		sqlite3_finalize(m_pstmGetAll);
		m_bEnumStarted = FALSE;
	}

	return bFound;
}