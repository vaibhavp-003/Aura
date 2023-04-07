#include "StdAfx.h"
#include "MaxSqLiteBase.h"

CMaxSqLiteBase::CMaxSqLiteBase(LPCTSTR	pszDBPath)
{
	m_pSQliteDB = NULL;
	m_bDBLoaded = FALSE;
	m_bEnumStarted = FALSE;
	m_bISDBLOADED = FALSE;
	m_bISDBLOADED = OpenDatabase(pszDBPath); 
}

CMaxSqLiteBase::~CMaxSqLiteBase(void)
{
	CloseDatabase();
}

BOOL CMaxSqLiteBase::OpenDatabase(LPCTSTR	pszDBPath)
{
	if (m_bDBLoaded == TRUE)
	{
		return TRUE;
	}

	TCHAR	szLogLine[1024] = {0x00};

	strcpy(m_szDDBPath,"");
	if (pszDBPath != NULL)
	{
		strcpy(m_szDDBPath,CT2A(pszDBPath));
	}

	if (strlen(m_szDDBPath) != 0x00)
	{
		int iRet = 0x00;
		iRet = sqlite3_open(m_szDDBPath, &m_pSQliteDB);

		sqlite3_exec(m_pSQliteDB, "PRAGMA journal_mode = OFF;", NULL, 0, 0);
		sqlite3_exec(m_pSQliteDB, "PRAGMA SYNCHRONOUS = OFF;", NULL, 0, 0);
		sqlite3_exec(m_pSQliteDB, "PRAGMA TEMP_STORE = MEMORY;", NULL, 0, 0);
		sqlite3_busy_timeout(m_pSQliteDB,1500);

		if(iRet == SQLITE_OK)
		{
			m_bDBLoaded = TRUE;
		}
		else
		{
			m_pSQliteDB = NULL;
			m_bDBLoaded = FALSE;
		}
	}

	return m_bDBLoaded;

}

BOOL CMaxSqLiteBase::CloseDatabase()
{
	if (m_pSQliteDB != NULL)
	{
		sqlite3_close(m_pSQliteDB);
		m_pSQliteDB = NULL;
	}
	m_bEnumStarted = FALSE;
	return TRUE;
}


BOOL CMaxSqLiteBase::ExecuteQuery(LPCTSTR pszQuey,BOOL bGlobalEnum, BOOL bInsertStm,int *piErrCode)
{
	BOOL	bRetValue = FALSE;

	if (NULL == pszQuey || m_bDBLoaded == FALSE)
	{
		return bRetValue;
	}

	if (_tcslen(pszQuey) == 0x00)
	{
		return bRetValue;
	}
	
	int				iIsFolder = 0x00;
	char			szQuery[2048] = {0x00};
	int				iRetval = 0x00;

	DWORD			dwUnLength = 0x00;
	DWORD			dwAnsLength = 0x00;

	dwUnLength = _tcslen(pszQuey);
	strcpy(szQuery,CT2A(pszQuey));
	dwAnsLength = strlen(szQuery);

	if (dwUnLength != dwAnsLength)
	{
		strcpy(szQuery,"");
		GetAnsiString(pszQuey,szQuery); 
	}

	try
	{

		if (bGlobalEnum == FALSE)
		{
			sqlite3_stmt	*stmInsert;
			iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
			if (!iRetval)
			{
				do
				{
					iRetval = 0x00;
					iRetval = sqlite3_step(stmInsert);
				}
				while(iRetval == SQLITE_BUSY);

				
				
				if (iRetval == SQLITE_ROW)
				{
					bRetValue = TRUE;
				}
				//if(bInsertStm == TRUE || bUpdateQuery == TRUE)
				//{
					if (iRetval == SQLITE_DONE)
					{
						bRetValue = TRUE;
					}
					else
					{
						bRetValue = FALSE;
					}
				//}
				sqlite3_finalize(stmInsert);
				Sleep(2);
			}
		}
		else
		{
			iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &m_pstmGetAll, NULL);
			if (!iRetval)
			{
				bRetValue = TRUE;
			}
		}
	}
	catch(...)
	{
		
	}

	if (piErrCode)
	{
		*piErrCode = iRetval;
	}

	return bRetValue;
}

BOOL CMaxSqLiteBase::GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT)
{
	BOOL		bRetValue = FALSE;
	char		szOut[MAX_PATH] = {0x00};		

	if (pszUnicodeIN == NULL || pszAnsiOUT == NULL)
	{
		return bRetValue;
	}

	int iRetLen =  WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK,pszUnicodeIN,_tcslen(pszUnicodeIN),szOut,MAX_PATH,NULL,NULL);

	if (iRetLen > 0x00)
	{
		strcpy(pszAnsiOUT,szOut);
	}

	return bRetValue;
}

bool CMaxSqLiteBase::GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT)
{
	bool		bRetValue = FALSE;
	TCHAR		szOut[MAX_PATH] = {0x00};
	
	if (pszAnsiIN == NULL || pszUnicodeOUT == NULL)
	{
		return bRetValue;
	}
	int iLen = strlen(pszAnsiIN);
	if( iLen == 0)
	{
		_tcscpy(pszUnicodeOUT,szOut);
		return bRetValue;
	}
	
	int iRetLen =  MultiByteToWideChar(CP_ACP,0,pszAnsiIN,strlen(pszAnsiIN),szOut,MAX_PATH);

	if (iRetLen > 0x00)
	{
		_tcscpy(pszUnicodeOUT,szOut);
	}

	return bRetValue;
}


bool CMaxSqLiteBase::GetScanRecord(LPUNSAFE_FILE_INFO pResults)
{
	bool	bSuccess = false; 
	char	szData[1024] = {0x00};
	TCHAR	szKeyName[1024] = {0x00};

	//File Path 
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll, 1));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szFilePath,szKeyName);
	//File Extension
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 2));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szHuerFilePath,szKeyName);
	//File MD5
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll, 3));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szMD5,szKeyName);
	//SHA256
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 4));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szSHA256,szKeyName);
	//Pe Sig
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll, 5));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szPESig,szKeyName);
	//Size
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 6));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szFileSize,szKeyName);
	//Probability
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll, 7));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szProbability,szKeyName);
	//ScanTime
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll, 8));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szScanTime,szKeyName);
	return true;
}

bool CMaxSqLiteBase::GetScanRecordEx(LPUNSAFE_FILE_FULL_INFO pResults)
{
	bool	bSuccess = false; 
	char	szData[1024] = {0x00};
	TCHAR	szKeyName[1024] = {0x00};

	//File Path 
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll, 1));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szFilePath,szKeyName);
	//File Extension
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 2));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szHuerFilePath,szKeyName);
	//File MD5
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll, 3));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szMD5,szKeyName);
	//SHA256
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 4));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szSHA256,szKeyName);
	//Pe Sig
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll, 5));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szPESig,szKeyName);
	//Size
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 6));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szFileSize,szKeyName);
	//Probability
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll, 7));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szProbability,szKeyName);
	//ScanTime
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll, 8));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szScanTime,szKeyName);
	//Detection Status
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 9));
	GetUnicodeString(szData,szKeyName);
	pResults->iDetectionStatus = _wtoi(szKeyName);
	//SpywareName
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll, 10));
	GetUnicodeString(szData,szKeyName);
	_tcscpy(pResults->szSpyName,szKeyName);
	//Spy ID
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 11));
	GetUnicodeString(szData,szKeyName);
	pResults->iSpyID = _wtoi(szKeyName);
	//Scanner Name
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 12));
	GetUnicodeString(szData,szKeyName);
	pResults->iScannerName = _wtoi(szKeyName);
	//Action
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 13));
	GetUnicodeString(szData,szKeyName);
	pResults->iAction = _wtoi(szKeyName);
	//Action Status
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 14));
	GetUnicodeString(szData,szKeyName);
	pResults->iActionStatus = _wtoi(szKeyName);
	//FileType
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 15));
	GetUnicodeString(szData,szKeyName);
	pResults->iFileType = _wtoi(szKeyName);
	//Info Uploaded
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 16));
	GetUnicodeString(szData,szKeyName);
	pResults->iInfoUpload = _wtoi(szKeyName);
	//File Uploaded
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 17));
	GetUnicodeString(szData,szKeyName);
	pResults->iISFileUploaded = _wtoi(szKeyName);
	//ThreatID
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 18));
	GetUnicodeString(szData,szKeyName);
	pResults->iThreatID = _wtoi(szKeyName);
	//iScanDone
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 19));
	GetUnicodeString(szData,szKeyName);
	pResults->iScanDone = _wtoi(szKeyName);
	//ScannerID
	strcpy(szData,(char *)sqlite3_column_text(m_pstmGetAll , 20));
	GetUnicodeString(szData,szKeyName);
	pResults->dwScannerID = _wtoi(szKeyName);
	return true;
}