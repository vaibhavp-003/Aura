#include "pch.h"
#include "MaxSqliteMgr.h"


CMaxSqliteMgr::CMaxSqliteMgr(LPCTSTR pszDBPath):CMaxSqLiteBase(pszDBPath)
{
	memset(&m_MaxScanData,0x00,sizeof(UNSAFE_FILE_FULL_INFO) * 15); 

}

CMaxSqliteMgr::~CMaxSqliteMgr(void)
{

}

bool CMaxSqliteMgr::InsertUnsafeFileInfo(LPUNSAFE_FILE_INFO pFileInfo)
{
	bool	bStatus = false;
	TCHAR	szQuery[2048] = {0x00};

/*
	_stprintf(szQuery,L"INSERT  INTO ClientInfo (ActivationKey, ActivationStatus, DeviceID, CompanyID, ValidationCnt,UseCloudScan,ServerURL,LastVisit) \
					   VALUES ('%s',%d,%d,%d,%d,%d,'%s','%s')",pDevInfo->szActKey,pDevInfo->iActStatus,pDevInfo->iDeviceID,
					   pDevInfo->iCompanyID,pDevInfo->iNoofDays,pDevInfo->iUseCloudScan,pDevInfo->szServerURL,pDevInfo->szLastVisit); 

		*/

	//_stprintf(szQuery,L"INSERT INTO ThreatIntelligence (File_Path,File_MD5 ,File_SHA256, File_PESign, File_Size,Probability, Scan_Time) VALUES ('%s','%s','%s','%s','%s','%s','%s')",pFileInfo->szFilePath,pFileInfo->szMD5,pFileInfo->szSHA256,pFileInfo->szPESig,pFileInfo->szFileSize,pFileInfo->szProbability,pFileInfo->szScanTime); 

	//CString csTest;


	/*
	CString csFilePath(pFileInfo->szFilePath);
	CString csMD5(pFileInfo->szMD5);
	CString csSHA256(pFileInfo->szSHA256);
	CString csPESign(pFileInfo->szPESig);
	CString csProbability(pFileInfo->szProbability);
	CString csScanTime(pFileInfo->szScanTime);
	*/

	//CString csValues = L"'"+csFilePath+L"'"
	
	_stprintf(szQuery,L"INSERT INTO ThreatIntelligence (File_Path,File_MD5 ,File_SHA256, File_PESign, File_Size,Probability, Scan_Time) VALUES ('%s','%s','%s','%s','%s','%s','%s')",pFileInfo->szFilePath,pFileInfo->szMD5,pFileInfo->szSHA256,L"",L"",pFileInfo->szProbability,L""); 
	
	//_stprintf(szQuery,L"INSERT INTO ThreatIntelligence (File_Path,File_MD5 ,File_SHA256, File_PESign, File_Size,Probability, Scan_Time) VALUES ('%s','%s','%s','%s','%s','%s','%s')",csFilePath,csMD5,csSHA256,csPESign,L"",csProbability,csScanTime);

	//_stprintf(szQuery,L"INSERT INTO ThreatIntelligence (File_Path,File_MD5 ,File_SHA256, File_PESign, File_Size,Probability, Scan_Time) VALUES ('%s','%s','%s','%s','%s','%s','%s')",L"",L"",L"",L"",L"",L"",L"");
	AddLogEntry(szQuery);
	
	bStatus = ExecuteQuery(szQuery);

	return bStatus;
}



bool CMaxSqliteMgr::InsertUnsafeFileInfoEx(LPCTSTR pszFilePath,CString csMD5,LPCTSTR pszFileSHA256,LPCTSTR pszProbability)
{
	bool	bStatus = false;
	TCHAR	szQuery[5120] = {0x00};

	_stprintf(szQuery,L"INSERT INTO ThreatIntelligence (File_Path,File_MD5,File_SHA256,Probability) VALUES ('%s','%s','%s','%s')",pszFilePath,csMD5,pszFileSHA256,pszProbability);
	AddLogEntry(szQuery);
	
	bStatus = ExecuteQuery(szQuery);

	return bStatus;
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
	AddLogEntry(szQuery);
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

int	CMaxSqliteMgr::GetdBatchForTIScanning(DWORD dwScannerID)
{
	int		iIndex = -1;
	TCHAR	szQuery[2048] = {0x00};
	bool	bFound;

	if (m_bDBLoaded == FALSE)
	{
		return bFound;
	}

	
	_stprintf(szQuery,L"SELECT * FROM ThreatIntelligence WHERE Detection_Status = 0 and Scan_Done = 0 and ScannerID = %d LIMIT 15",dwScannerID);
	
	bFound = ExecuteQuery(szQuery,TRUE);
	
	if (bFound)
	{
		m_bEnumStarted = TRUE;
		while(1)
		{
			iIndex++;
			if (iIndex >= 15)
			{
				break;
			}
			int iRetval = sqlite3_step(m_pstmGetAll);
			if (iRetval != SQLITE_ROW)
			{
				break;
			}
			else
			{
				GetScanRecordEx(&m_MaxScanData[iIndex]);
			}
		}
		sqlite3_finalize(m_pstmGetAll);
		m_bEnumStarted = FALSE;
	}

	return iIndex;
}

int	CMaxSqliteMgr::GetRescanBatchForTIScanning(DWORD dwScannerID)
{
	int		iIndex = -1;
	TCHAR	szQuery[2048] = {0x00};
	bool	bFound;

	if (m_bDBLoaded == FALSE)
	{
		return bFound;
	}

	
	_stprintf(szQuery,L"SELECT * FROM ThreatIntelligence WHERE Detection_Status = 0 and Scan_Done = 1 and ReScan = 1 and ScannerID = %d LIMIT 15",dwScannerID);
	
	bFound = ExecuteQuery(szQuery,TRUE);
	
	if (bFound)
	{
		m_bEnumStarted = TRUE;
		while(1)
		{
			iIndex++;
			if (iIndex >= 15)
			{
				break;
			}
			int iRetval = sqlite3_step(m_pstmGetAll);
			if (iRetval != SQLITE_ROW)
			{
				break;
			}
			else
			{
				GetScanRecordEx(&m_MaxScanData[iIndex]);
			}
		}
		sqlite3_finalize(m_pstmGetAll);
		m_bEnumStarted = FALSE;
	}

	return iIndex;
}

int	CMaxSqliteMgr::GetdBatchForSandBoxing(DWORD dwScannerID,LPCTSTR pszThreshold)
{
	int		iIndex = -1;
	TCHAR	szQuery[2048] = {0x00};
	bool	bFound;

	if (m_bDBLoaded == FALSE)
	{
		return bFound;
	}

	
	_stprintf(szQuery,L"SELECT * FROM ThreatIntelligence WHERE Detection_Status = 0 and Scan_Done = 1 and IsFileUploaded = 0 and Pre_Send = 1 and ScannerID = %d LIMIT 15",dwScannerID);
	
	AddLogEntry(szQuery);
	bFound = ExecuteQuery(szQuery,TRUE);
	
	if (bFound)
	{
		m_bEnumStarted = TRUE;
		while(1)
		{
			iIndex++;
			if (iIndex >= 15)
			{
				break;
			}
			int iRetval = sqlite3_step(m_pstmGetAll);
			if (iRetval != SQLITE_ROW)
			{
				break;
			}
			else
			{
				GetScanRecordEx(&m_MaxScanData[iIndex]);
			}
		}
		sqlite3_finalize(m_pstmGetAll);
		m_bEnumStarted = FALSE;
	}

	return iIndex;
}

int	CMaxSqliteMgr::GetdBatchForSandBoxingScanning(DWORD dwScannerID)
{
	int		iIndex = -1;
	TCHAR	szQuery[2048] = {0x00};
	bool	bFound;

	if (m_bDBLoaded == FALSE)
	{
		return bFound;
	}

	
	_stprintf(szQuery,L"SELECT * FROM ThreatIntelligence WHERE Detection_Status = 0 and Scan_Done = 1 and IsFileUploaded = 1 and ScannerID = %d LIMIT 15",dwScannerID);
	
	AddLogEntry(szQuery);
	bFound = ExecuteQuery(szQuery,TRUE);
	
	if (bFound)
	{
		m_bEnumStarted = TRUE;
		while(1)
		{
			iIndex++;
			if (iIndex >= 15)
			{
				break;
			}
			int iRetval = sqlite3_step(m_pstmGetAll);
			if (iRetval != SQLITE_ROW)
			{
				break;
			}
			else
			{
				GetScanRecordEx(&m_MaxScanData[iIndex]);
			}
		}
		sqlite3_finalize(m_pstmGetAll);
		m_bEnumStarted = FALSE;
	}

	return iIndex;
}


bool CMaxSqliteMgr::UpdateScanDoneFlag(LPCTSTR pszMD5)
{
	bool	bStatus = false;
	TCHAR	szQuery[5120] = {0x00};


	_stprintf(szQuery,L"UPDATE ThreatIntelligence SET Scan_Done = 1 WHERE File_MD5 = '%s'",pszMD5);
	
	
	AddLogEntry(szQuery);
	
	bStatus = ExecuteQuery(szQuery);

	return bStatus;
}

bool CMaxSqliteMgr::UpdateReScanDoneFlag(LPCTSTR pszMD5)
{
	bool	bStatus = false;
	TCHAR	szQuery[5120] = {0x00};


	_stprintf(szQuery,L"UPDATE ThreatIntelligence SET Scan_Done = 1, ReScan = 3 WHERE File_MD5 = '%s'",pszMD5);
	
	
	AddLogEntry(szQuery);
	
	bStatus = ExecuteQuery(szQuery);

	return bStatus;
}

bool CMaxSqliteMgr::UpdatePreSendFlag(LPCTSTR pszMD5)
{
	bool	bStatus = false;
	TCHAR	szQuery[5120] = {0x00};

	_stprintf(szQuery,L"UPDATE ThreatIntelligence SET Pre_Send = 1 WHERE File_MD5 = '%s'",pszMD5);
	AddLogEntry(szQuery);
	
	bStatus = ExecuteQuery(szQuery);

	return bStatus;
}

bool CMaxSqliteMgr::DeleteUnwantedEntries()
{
	bool	bStatus = false;
	TCHAR	szQuery[5120] = {0x00};

	_stprintf(szQuery,L"DELETE FROM ThreatIntelligence WHERE Pre_Send = 0");
	AddLogEntry(szQuery);
	
	bStatus = ExecuteQuery(szQuery);

	return bStatus;
}

bool CMaxSqliteMgr::UpdateFileUploadFlag(LPCTSTR pszMD5, int iTaskID)
{
	bool	bStatus = false;
	TCHAR	szQuery[5120] = {0x00};

	_stprintf(szQuery,L"UPDATE ThreatIntelligence SET IsFileUploaded = 1,ReScan = 1,TaskID = %d WHERE File_MD5 = '%s'",iTaskID,pszMD5);
	AddLogEntry(szQuery);
	
	bStatus = ExecuteQuery(szQuery);

	return bStatus;
}

bool CMaxSqliteMgr::UpdateDetectionStatusFlag(LPCTSTR pszMD5,int iDetection)
{
	bool	bStatus = false;
	TCHAR	szQuery[5120] = {0x00};

	if(iDetection == 1)
	{
		_stprintf(szQuery,L"UPDATE ThreatIntelligence SET Scan_Done = 1, Detection_Status =1, Spyware_Name = 'Trojan.Susgen.MISP', Spyware_Id = 10008 WHERE File_MD5 = '%s'",pszMD5);
	}
	else if(iDetection == 2)
	{
		_stprintf(szQuery,L"UPDATE ThreatIntelligence SET Scan_Done = 1 WHERE File_MD5 = '%s'",pszMD5);
		//_stprintf(szQuery,L"UPDATE ThreatIntelligence SET Scan_Done = 1, Detection_Status =1, Spyware_Name = 'Trojan.Susgen.CUC', Spyware_Id = 10009 WHERE File_MD5 = '%s'",pszMD5);
		//_stprintf(szQuery,L"UPDATE ThreatIntelligence SET Scan_Done = 1, Detection_Status =1, Spyware_Name = 'Trojan.Susgen.MISP', Spyware_Id = 10008 WHERE File_MD5 = '%s'",pszMD5);
	}
	AddLogEntry(szQuery);
	
	bStatus = ExecuteQuery(szQuery);

	return bStatus;
}


bool CMaxSqliteMgr::UpdateSandBoxScanningFlag(LPCTSTR pszMD5)
{
	bool	bStatus = false;
	TCHAR	szQuery[5120] = {0x00};


	_stprintf(szQuery,L"UPDATE ThreatIntelligence SET SandBoxScanning = 1 WHERE File_MD5 = '%s'",pszMD5);
		
	AddLogEntry(szQuery);
	
	bStatus = ExecuteQuery(szQuery);

	return bStatus;

}

bool CMaxSqliteMgr::IsAlreadyScan(LPCTSTR pszFileMD5)
{
	bool bFound = false;
	TCHAR	szQuery[1024] = {0x00};
	_stprintf(szQuery,L"SELECT File_MD5 FROM ThreatIntelligence  WHERE File_MD5 = '%s' AND Scan_Done = 1 LIMIT 1",pszFileMD5);
	bFound = ExecuteQuery(szQuery);
	return bFound;
}