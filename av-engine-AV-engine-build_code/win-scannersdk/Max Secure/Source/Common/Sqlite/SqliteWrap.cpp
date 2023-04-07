#include "StdAfx.h"
#include "SqliteWrap.h"


CSqliteWrap::CSqliteWrap(LPCSTR pszDBPath)
{
	m_pSQliteDB = NULL;
	strcpy(m_szDDBPath,"");
	if (pszDBPath != NULL)
	{
		strcpy(m_szDDBPath,pszDBPath);
	}

	if (strlen(m_szDDBPath) != 0x00)
	{
		int iRet = 0x00;
		iRet = sqlite3_open(m_szDDBPath, &m_pSQliteDB);
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

	m_pstmGetAll = NULL;
	m_bEnumStarted = FALSE;
}

CSqliteWrap::~CSqliteWrap(void)
{
	if (m_pSQliteDB != NULL)
	{
		sqlite3_close(m_pSQliteDB);
		m_pSQliteDB = NULL;
	}
	m_bEnumStarted = FALSE;
}

BOOL CSqliteWrap::OpenDatabase(LPCSTR	pszDBPath)
{
	if (m_bDBLoaded == TRUE)
	{
		return TRUE;
	}

	strcpy(m_szDDBPath,"");
	if (pszDBPath != NULL)
	{
		strcpy(m_szDDBPath,pszDBPath);
	}

	if (strlen(m_szDDBPath) != 0x00)
	{
		int iRet = 0x00;
		iRet = sqlite3_open(m_szDDBPath, &m_pSQliteDB);
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

BOOL CSqliteWrap::CloseDatabase()
{
	if (m_pSQliteDB != NULL)
	{
		sqlite3_close(m_pSQliteDB);
		m_pSQliteDB = NULL;
	}
	return TRUE;
}

BOOL CSqliteWrap::DeleteFilter(LPCTSTR pszTable,LPCTSTR pszValue)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszValue == NULL)
	{
		return bRetValue;
	}

	if (_tcslen(pszTable) == 0x00)
	{
		return bRetValue;
	}

	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szTableName[50] =  {0x00};
	char			szKeyData[MAX_PATH] =  {0x00};

	
	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);
	
	strcpy(szKeyData,CT2A(pszValue));
	strlwr(szKeyData);
	
	//sprintf(szQuery,"SELECT szFilePath FROM EncryptList WHERE szFilePath = '%s'",szPath2Check);
	sprintf(szQuery,"DELETE FROM %s WHERE FilterString = '%s'",szTableName, szKeyData);
	int iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			bRetValue = TRUE;
		}
		else
		{
			
			bRetValue = FALSE;
		}
		sqlite3_finalize(stmInsert);
	}
	
	return bRetValue;
}


BOOL CSqliteWrap::DeleteFilter(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszKey == NULL || pszValue == NULL)
	{
		return bRetValue;
	}

	if (_tcslen(pszTable) == 0x00 || _tcslen(pszKey) == 0x00)
	{
		return bRetValue;
	}

	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szTableName[50] =  {0x00};
	char			szKeyName[50] =  {0x00};
	char			szKeyData[MAX_PATH] =  {0x00};

	
	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);

	strcpy(szKeyName,CT2A(pszKey));
	strlwr(szKeyName);

	strcpy(szKeyData,CT2A(pszValue));
	strlwr(szKeyData);
	
	//sprintf(szQuery,"SELECT szFilePath FROM EncryptList WHERE szFilePath = '%s'",szPath2Check);
	sprintf(szQuery,"DELETE FROM %s WHERE FilterString = '%s' AND FilterType = '%s'",szTableName, szKeyData,szKeyName);
	int iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			bRetValue = TRUE;
		}
		else
		{
			
			bRetValue = FALSE;
		}
		sqlite3_finalize(stmInsert);
	}
	
	return bRetValue;
}

BOOL CSqliteWrap::IsDuplicateValue(LPCTSTR pszTable,LPCTSTR pszKey2Check)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszKey2Check ==  NULL)
	{
		return bRetValue;
	}

	if (_tcslen(pszTable) == 0x00 || _tcslen(pszKey2Check) == 0x00)
	{
		return bRetValue;
	}

	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szTableName[50] =  {0x00};
	char			szKeyData[MAX_PATH] =  {0x00};

	
	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);

	strcpy(szKeyData,CT2A(pszKey2Check));
	strlwr(szKeyData);
	
	//sprintf(szQuery,"SELECT szFilePath FROM EncryptList WHERE szFilePath = '%s'",szPath2Check);
	sprintf(szQuery,"SELECT FilterString FROM %s WHERE FilterString = '%s'",szTableName, szKeyData);
	int iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			bRetValue = TRUE;
		}
		else
		{
			
			bRetValue = FALSE;
		}
		sqlite3_finalize(stmInsert);
	}
	
	return bRetValue;
}

BOOL CSqliteWrap::IsDuplicateValue(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszKey == NULL || pszValue == NULL)
	{
		return bRetValue;
	}

	if (_tcslen(pszTable) == 0x00 || _tcslen(pszKey) == 0x00)
	{
		return bRetValue;
	}

	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szTableName[50] =  {0x00};
	char			szKeyName[50] =  {0x00};
	char			szKeyData[MAX_PATH] =  {0x00};

	
	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);

	strcpy(szKeyName,CT2A(pszKey));
	strlwr(szKeyName);

	strcpy(szKeyData,CT2A(pszValue));
	strlwr(szKeyData);
	
	//sprintf(szQuery,"SELECT szFilePath FROM EncryptList WHERE szFilePath = '%s'",szPath2Check);
	sprintf(szQuery,"SELECT FilterType FROM %s WHERE FilterString = '%s' AND FilterType = '%s'",szTableName, szKeyData,szKeyName);
	int iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			bRetValue = TRUE;
		}
		else
		{
			
			bRetValue = FALSE;
		}
		sqlite3_finalize(stmInsert);
	}
	
	return bRetValue;
}

BOOL CSqliteWrap::IsKeyExists(LPCTSTR pszTable,LPCTSTR pszKey)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszKey == NULL)
	{
		return bRetValue;
	}

	if (_tcslen(pszTable) == 0x00 || _tcslen(pszKey) == 0x00)
	{
		return bRetValue;
	}

	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szTableName[50] =  {0x00};
	char			szKeyName[50] =  {0x00};

	
	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);

	strcpy(szKeyName,CT2A(pszKey));
	strlwr(szKeyName);

	
	//sprintf(szQuery,"SELECT szFilePath FROM EncryptList WHERE szFilePath = '%s'",szPath2Check);
	sprintf(szQuery,"SELECT FilterType FROM %s WHERE FilterType = '%s'",szTableName, szKeyName);
	int iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			bRetValue = TRUE;
		}
		else
		{
			
			bRetValue = FALSE;
		}
		sqlite3_finalize(stmInsert);	
	}
	
	return bRetValue;
}

BOOL CSqliteWrap::GetValue(LPCTSTR pszTable,LPCTSTR pszKey,LPTSTR pszValueOut,LPSTR pszValueOutANSI)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszKey == NULL)
	{
		return bRetValue;
	}

	if (_tcslen(pszTable) == 0x00 || _tcslen(pszKey) == 0x00)
	{
		return bRetValue;
	}

	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szTableName[50] =  {0x00};
	char			szKeyName[50] =  {0x00};
	char			szKeyData[MAX_PATH] =  {0x00};

	
	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);

	strcpy(szKeyName,CT2A(pszKey));
	strlwr(szKeyName);

	sprintf(szQuery,"SELECT FilterString FROM %s WHERE FilterType = '%s'",szTableName, szKeyName);
	int iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(szKeyData,(char *)sqlite3_column_text(stmInsert, 0));
			if (pszValueOut != NULL)
			{
				_stprintf(pszValueOut,_T("%S"),(LPCTSTR)szKeyData);
			}
			if (pszValueOutANSI != NULL)
			{
				strcpy(pszValueOutANSI,szKeyData);
			}
		}

		sqlite3_finalize(stmInsert);
		return TRUE;
	}
	
	
	return bRetValue;
}

BOOL CSqliteWrap::InsertRecord(LPCTSTR pszTable,LPCTSTR pszData)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszData == NULL)
	{
		return bRetValue;
	}

	if (_tcslen(pszTable) == 0x00 || _tcslen(pszData) == 0x00)
	{
		return bRetValue;
	}

	if (IsDuplicateValue(pszTable,pszData) == TRUE)
	{
		return TRUE;
	}


	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szTableName[50] =  {0x00};
	char			szKeyData[MAX_PATH] =  {0x00};

	
	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);

	strcpy(szKeyData,CT2A(pszData));
	strlwr(szKeyData);
	
	sprintf(szQuery,"INSERT INTO %s (FilterString) VALUES ('%s')",szTableName, szKeyData);
	int iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);

		sqlite3_finalize(stmInsert);
		return TRUE;
	}
	
	
	return bRetValue;
}

BOOL CSqliteWrap::InsertRecord(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszKey == NULL || pszValue == NULL)
	{
		return bRetValue;
	}

	if (_tcslen(pszTable) == 0x00 || _tcslen(pszKey) == 0x00)
	{
		return bRetValue;
	}

	if (IsDuplicateValue(pszTable,pszKey,pszValue) == TRUE)
	{
		return TRUE;
	}


	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szTableName[50] =  {0x00};
	char			szKeyName[50] =  {0x00};
	char			szKeyData[MAX_PATH] =  {0x00};

	
	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);

	strcpy(szKeyName,CT2A(pszKey));
	strlwr(szKeyName);

	strcpy(szKeyData,CT2A(pszValue));
	strlwr(szKeyData);
	
	sprintf(szQuery,"INSERT INTO %s (FilterType,FilterString) VALUES ('%s','%s')",szTableName, szKeyName,szKeyData);
	int iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);

		sqlite3_finalize(stmInsert);
		return TRUE;
	}
	
	
	return bRetValue;
}

BOOL CSqliteWrap::UpdateRecord(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszKey == NULL || pszValue == NULL)
	{
		return bRetValue;
	}

	if (_tcslen(pszTable) == 0x00 || _tcslen(pszKey) == 0x00)
	{
		return bRetValue;
	}

	if (IsDuplicateValue(pszTable,pszKey,pszValue) == TRUE)
	{
		return TRUE;
	}


	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szTableName[50] =  {0x00};
	char			szKeyName[50] =  {0x00};
	char			szKeyData[MAX_PATH] =  {0x00};

	
	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);

	strcpy(szKeyName,CT2A(pszKey));
	strlwr(szKeyName);

	strcpy(szKeyData,CT2A(pszValue));
	strlwr(szKeyData);
	
	sprintf(szQuery,"UPDATE %s SET FilterString='%s' WHERE FilterType = '%s'",szTableName, szKeyData,szKeyName);
	int iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);

		sqlite3_finalize(stmInsert);
		return TRUE;
	}
	
	
	return bRetValue;
}


//Need To Optimize : Replace SELECT Query With GetValue Function
BOOL  CSqliteWrap::IsInternetBlockingON(bool &bWeekDays,bool &bWeekEnds,LPSTR	pszWeekDays,LPSTR	pszWeekEnds)
{
	BOOL	bRetValue = FALSE;

	bWeekDays = false;
	bWeekEnds = false;

	if (pszWeekDays != NULL)
	{
		strcpy(pszWeekDays,"");
	}
	if (pszWeekEnds != NULL)
	{
		strcpy(pszWeekEnds,"");
	}

	sqlite3_stmt	*stmInsert;
	char			szQuery[512] = {0x00};
	char			szData[MAX_PATH] = {0x00};
	int				iRetval = 0x00;

	//1 : Checking for INetUsageBlocking value
	sprintf(szQuery,"SELECT FilterString FROM UserRules WHERE FilterType = 'inetusageblocking'");
	iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
			if (strstr(szData,"1") != NULL)
			{
				bRetValue = TRUE;
			}
			else
			{
				bRetValue = FALSE;
			}
			
		}
		else
		{
			bRetValue = FALSE;
		}
		sqlite3_finalize(stmInsert);
	}

	if (bRetValue == FALSE)
	{
		return bRetValue;
	}

	//2 : Checking for INetUsageBlocking value
	sprintf(szQuery,"SELECT FilterString FROM UserRules WHERE FilterType = 'inetblockingweekdays'");
	iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
			if (strstr(szData,"1") != NULL)
			{
				bWeekDays = true;
			}
			else
			{
				bWeekDays = false;
			}
			
		}
		else
		{
			bWeekDays = false;
		}
		sqlite3_finalize(stmInsert);
	}
	if (bWeekDays == true)
	{
		//3 : Checking for INetUsageBlocking value
		sprintf(szQuery,"SELECT FilterString FROM UserRules WHERE FilterType = 'inetblockweekdays'");
		iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
		if (!iRetval)
		{
			iRetval = sqlite3_step(stmInsert);
			if (iRetval == SQLITE_ROW)
			{
				strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
				if (strlen(szData) != 0x00)
				{
					strcpy(pszWeekDays,szData);
				}
			}
			sqlite3_finalize(stmInsert);
		}
	}

	//4 : Checking for INetBlockingWeekEnds value
	sprintf(szQuery,"SELECT FilterString FROM UserRules WHERE FilterType = 'inetblockingweekends'");
	iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
			if (strstr(szData,"1") != NULL)
			{
				bWeekEnds = true;
			}
			else
			{
				bWeekEnds = false;
			}
			
		}
		else
		{
			bWeekEnds = false;
		}
		sqlite3_finalize(stmInsert);
	}
	if (bWeekEnds == true)
	{
		//5 : Checking for INetBlockWeekends value
		sprintf(szQuery,"SELECT FilterString FROM UserRules WHERE FilterType = 'inetblockweekends'");
		iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
		if (!iRetval)
		{
			iRetval = sqlite3_step(stmInsert);
			if (iRetval == SQLITE_ROW)
			{
				strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
				if (strlen(szData) != 0x00)
				{
					strcpy(pszWeekEnds,szData);
				}
			}
			sqlite3_finalize(stmInsert);
		}
	}

	return bRetValue;
}

BOOL  CSqliteWrap::IsCompBlockingON(bool &bWeekDays,bool &bWeekEnds,LPSTR	pszWeekDays,LPSTR	pszWeekEnds)
{
	BOOL	bRetValue = FALSE;

	bWeekDays = false;
	bWeekEnds = false;

	if (pszWeekDays != NULL)
	{
		strcpy(pszWeekDays,"");
	}
	if (pszWeekEnds != NULL)
	{
		strcpy(pszWeekEnds,"");
	}

	sqlite3_stmt	*stmInsert;
	char			szQuery[512] = {0x00};
	char			szData[MAX_PATH] = {0x00};
	int				iRetval = 0x00;

	//1 : Checking for INetUsageBlocking value
	sprintf(szQuery,"SELECT FilterString FROM UserRules WHERE FilterType = 'compusageusageblocking'");
	iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
			if (strstr(szData,"1") != NULL)
			{
				bRetValue = TRUE;
			}
			else
			{
				bRetValue = FALSE;
			}
			
		}
		else
		{
			bRetValue = FALSE;
		}
		sqlite3_finalize(stmInsert);
	}

	if (bRetValue == FALSE)
	{
		return bRetValue;
	}

	//2 : Checking for INetUsageBlocking value
	sprintf(szQuery,"SELECT FilterString FROM UserRules WHERE FilterType = 'compusageblockingweekdays'");
	iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
			if (strstr(szData,"1") != NULL)
			{
				bWeekDays = true;
			}
			else
			{
				bWeekDays = false;
			}
			
		}
		else
		{
			bWeekDays = false;
		}
		sqlite3_finalize(stmInsert);
	}
	if (bWeekDays == true)
	{
		//3 : Checking for INetUsageBlocking value
		sprintf(szQuery,"SELECT FilterString FROM UserRules WHERE FilterType = 'compusageblockweekdays'");
		iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
		if (!iRetval)
		{
			iRetval = sqlite3_step(stmInsert);
			if (iRetval == SQLITE_ROW)
			{
				strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
				if (strlen(szData) != 0x00)
				{
					strcpy(pszWeekDays,szData);
				}
			}
			sqlite3_finalize(stmInsert);
		}
	}

	//4 : Checking for INetBlockingWeekEnds value
	sprintf(szQuery,"SELECT FilterString FROM UserRules WHERE FilterType = 'compusageblockingweekends'");
	iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
			if (strstr(szData,"1") != NULL)
			{
				bWeekEnds = true;
			}
			else
			{
				bWeekEnds = false;
			}
			
		}
		else
		{
			bWeekEnds = false;
		}
		sqlite3_finalize(stmInsert);
	}
	if (bWeekEnds == true)
	{
		//5 : Checking for INetBlockWeekends value
		sprintf(szQuery,"SELECT FilterString FROM UserRules WHERE FilterType = 'compusageblockweekends'");
		iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
		if (!iRetval)
		{
			iRetval = sqlite3_step(stmInsert);
			if (iRetval == SQLITE_ROW)
			{
				strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
				if (strlen(szData) != 0x00)
				{
					strcpy(pszWeekEnds,szData);
				}
			}
			sqlite3_finalize(stmInsert);
		}
	}

	return bRetValue;
}

//0 : Turn OFF
//1 : Turn ON
//2 : Ignore (Do Not Set)
//If String Values are NULL (pszWeekEnds,pszWeekDays) then do not set
BOOL CSqliteWrap::SetInternetBloking(int iBlockingON, int iWeekDays, int iWeekEnds,LPCTSTR	pszWeekDays,LPCTSTR	pszWeekEnds)
{
	BOOL	bRetValue = FALSE;
	TCHAR	szData[0x10] = {0x00};

	if (iBlockingON != 2)
	{
		iBlockingON==1?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
		if (IsKeyExists(_T("UserRules"),_T("INetUsageBlocking")))
		{
			UpdateRecord(_T("UserRules"),_T("INetUsageBlocking"),szData);
		}
		else
		{
			InsertRecord(_T("UserRules"),_T("INetUsageBlocking"),szData);
		}
	}

	if (iWeekDays != 2)
	{
		iWeekDays==1?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
		if (IsKeyExists(_T("UserRules"),_T("INetBlockingWeekDays")))
		{
			UpdateRecord(_T("UserRules"),_T("INetBlockingWeekDays"),szData);
		}
		else
		{
			InsertRecord(_T("UserRules"),_T("INetBlockingWeekDays"),szData);
		}
	}

	if (iWeekEnds != 2)
	{
		iWeekEnds==1?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
		if (IsKeyExists(_T("UserRules"),_T("INetBlockingWeekEnds")))
		{
			UpdateRecord(_T("UserRules"),_T("INetBlockingWeekEnds"),szData);
		}
		else
		{
			InsertRecord(_T("UserRules"),_T("INetBlockingWeekEnds"),szData);
		}
	}


	if (pszWeekDays != NULL)
	{
		if (IsKeyExists(_T("UserRules"),_T("INetBlockWeekdays")))
		{
			UpdateRecord(_T("UserRules"),_T("INetBlockWeekdays"),pszWeekDays);
		}
		else
		{
			InsertRecord(_T("UserRules"),_T("INetBlockWeekdays"),pszWeekDays);
		}
	}

	if (pszWeekEnds != NULL)
	{
		if (IsKeyExists(_T("UserRules"),_T("INetBlockWeekends")))
		{
			UpdateRecord(_T("UserRules"),_T("INetBlockWeekends"),pszWeekEnds);
		}
		else
		{
			InsertRecord(_T("UserRules"),_T("INetBlockWeekends"),pszWeekEnds);
		}
	}

	return bRetValue;
}

//0 : Turn OFF
//1 : Turn ON
//2 : Ignore (Do Not Set)
//If String Values are NULL (pszWeekEnds,pszWeekDays) then do not set
BOOL CSqliteWrap::SetComputerBloking(int iBlockingON, int iWeekDays, int iWeekEnds,LPCTSTR	pszWeekDays,LPCTSTR	pszWeekEnds)
{
	BOOL	bRetValue = FALSE;
	TCHAR	szData[0x10] = {0x00};

	if (iBlockingON != 2)
	{
		iBlockingON==1?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
		if (IsKeyExists(_T("UserRules"),_T("CompUsageUsageBlocking")))
		{
			UpdateRecord(_T("UserRules"),_T("CompUsageUsageBlocking"),szData);
		}
		else
		{
			InsertRecord(_T("UserRules"),_T("CompUsageUsageBlocking"),szData);
		}
	}

	if (iWeekDays != 2)
	{
		iWeekDays==1?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
		if (IsKeyExists(_T("UserRules"),_T("CompUsageBlockingWeekDays")))
		{
			UpdateRecord(_T("UserRules"),_T("CompUsageBlockingWeekDays"),szData);
		}
		else
		{
			InsertRecord(_T("UserRules"),_T("CompUsageBlockingWeekDays"),szData);
		}
	}

	if (iWeekEnds != 2)
	{
		iWeekEnds==1?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
		if (IsKeyExists(_T("UserRules"),_T("CompUsageBlockingWeekEnds")))
		{
			UpdateRecord(_T("UserRules"),_T("CompUsageBlockingWeekEnds"),szData);
		}
		else
		{
			InsertRecord(_T("UserRules"),_T("CompUsageBlockingWeekEnds"),szData);
		}
	}


	if (pszWeekDays != NULL)
	{
		if (IsKeyExists(_T("UserRules"),_T("CompUsageBlockWeekdays")))
		{
			UpdateRecord(_T("UserRules"),_T("CompUsageBlockWeekdays"),pszWeekDays);
		}
		else
		{
			InsertRecord(_T("UserRules"),_T("CompUsageBlockWeekdays"),pszWeekDays);
		}
	}

	if (pszWeekEnds != NULL)
	{
		if (IsKeyExists(_T("UserRules"),_T("CompUsageBlockWeekends")))
		{
			UpdateRecord(_T("UserRules"),_T("CompUsageBlockWeekends"),pszWeekEnds);
		}
		else
		{
			InsertRecord(_T("UserRules"),_T("CompUsageBlockWeekends"),pszWeekEnds);
		}
	}

	return bRetValue;
}

BOOL CSqliteWrap::GetCommonRules(LPFW_COMMON_RULES pRulesStruct)
{
	BOOL		bRetValue = FALSE;
	char		szData[0x10] = {0x00};

	if (pRulesStruct == NULL)
	{
		return bRetValue;
	}

	memset(pRulesStruct,0x00,sizeof(FW_COMMON_RULES));

	if (GetValue(_T("CommonRules"),_T("networkfilter"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bNetworkFilter = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("blockwebsites"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bBlockWebSites = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("applicationrule"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bApplicationRule = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("antibanner"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bAntiBanner = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("antiphishing"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bAntiPhishing = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("networkmonitor"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bNetworkMonitor = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("whitefiltering"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bWhiteFiltering = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("blockall"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bBlockAll = true;
			bRetValue = TRUE;
		}
	}

	//Network Filter 
	
	if (GetValue(_T("CommonRules"),_T("dhcp"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bDHCP = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("dns"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bDNS = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("netbios"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bNetBios = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("ldap"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bLDAP = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("kerbores"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bKerbores = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("vpn"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bVPN = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("igmp"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bIGMP = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("othericmp"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bICMP = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("ftp"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bFTP = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("contentsearch"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bContentSearch = true;
			bRetValue = TRUE;
		}
	}

	if (GetValue(_T("CommonRules"),_T("idsip"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pRulesStruct->bIDSRules = true;
			bRetValue = TRUE;
		}
	}
	return bRetValue;

}

BOOL CSqliteWrap::GetUserCategories(LPPC_CATEGORIES pCatStruct)
{
	BOOL		bRetValue = FALSE;
	char		szData[0x10] = {0x00};

	if (pCatStruct == NULL)
	{
		return bRetValue;
	}

	memset(pCatStruct,0x00,sizeof(PC_CATEGORIES));

	if (GetValue(_T("UserRules"),_T("CategoryBlocking"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bCategoryBlocking=true;
			bRetValue = TRUE;
		}
	}

	//SocialSites
	if (GetValue(_T("UserRules"),_T("SocialSites"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bSocialSites =true;
		}
	}

	//PornSites
	if (GetValue(_T("UserRules"),_T("PornSites"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bPornSites =true;
		}
	}

	//Gambling
	if (GetValue(_T("UserRules"),_T("Gambling"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bGambling =true;
		}
	}

	//OnlineGames
	if (GetValue(_T("UserRules"),_T("OnlineGames"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bOnlineGames =true;
		}
	}

	//Webmails
	if (GetValue(_T("UserRules"),_T("Webmails"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bWebmails =true;
		}
	}

	//Weapons
	if (GetValue(_T("UserRules"),_T("Weapon"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bWeapons =true;
		}
	}

	//Violence
	if (GetValue(_T("UserRules"),_T("Violence"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bViolence =true;
		}
	}

	//OnlinePayments
	if (GetValue(_T("UserRules"),_T("OnlinePayments"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bOnlinePaymenst =true;
		}
	}

	//ChatForums
	if (GetValue(_T("UserRules"),_T("ChatForums"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bChatForums =true;
		}
	}

	//IllegalSoft
	if (GetValue(_T("UserRules"),_T("IllegalSoft"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bIllegalSoft =true;
		}
	}

	//Drugs
	if (GetValue(_T("UserRules"),_T("Drugs"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bDrugs =true;
		}
	}

	//OnlineStores
	if (GetValue(_T("UserRules"),_T("OnlineStores"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bOnlineStores =true;
		}
	}

	//ExplicitLang
	if (GetValue(_T("UserRules"),_T("ExplicitLang"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bExplicitLang =true;
		}
	}

	//ProxyServ
	if (GetValue(_T("UserRules"),_T("ProxyServ"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bProxyServ =true;
		}
	}

	//BlockWebSites
	if (GetValue(_T("UserRules"),_T("BlockWebSites"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bBlockWebSites =true;
		}
	}

	//PrentalControl
	if (GetValue(_T("UserRules"),_T("ParentalControl"),NULL,&szData[0x00]))
	{
		if (strstr(szData,"1") != NULL)
		{
			pCatStruct->bParentalControl =true;
		}
	}

	return bRetValue;
}

BOOL CSqliteWrap::SetValue(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszKey == NULL || pszValue == NULL)
	{
		return bRetValue;
	}

	if (IsKeyExists(pszTable,pszKey))
	{
		bRetValue = UpdateRecord(pszTable,pszKey,pszValue);
	}
	else
	{
		bRetValue = InsertRecord(pszTable,pszKey,pszValue);
	}	

	return bRetValue;
}

/*
//IMP == User This in case of FilterValue like dns_name etc
BOOL CSqliteWrap::SetFilterValue(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszKey == NULL || pszValue == NULL)
	{
		return bRetValue;
	}

	bRetValue = InsertRecord(pszTable,pszKey,pszValue);
		

	return bRetValue;
}
*/

BOOL CSqliteWrap::SetFilterValue(LPCTSTR pszTable, LPCTSTR pszData)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszData == NULL)
	{
		return bRetValue;
	}

	bRetValue = InsertRecord(pszTable,pszData);
		

	return bRetValue;
}

BOOL CSqliteWrap::UpdateFilterValue(LPCTSTR pszTable,LPCTSTR pszOldValue,LPCTSTR pszNewValue)
{
	BOOL	bRetValue = FALSE;
	if (pszTable == NULL || pszNewValue == NULL || pszOldValue == NULL)
	{
		return bRetValue;
	}

	DeleteFilter(pszTable,pszOldValue);
	bRetValue = InsertRecord(pszTable,pszNewValue);
	
	return bRetValue;
}

BOOL CSqliteWrap::UpdateFilterValue(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszOldValue,LPCTSTR pszNewValue)
{
	BOOL	bRetValue = FALSE;
	if (pszTable == NULL || pszKey == NULL || pszNewValue == NULL || pszOldValue == NULL)
	{
		return bRetValue;
	}

	DeleteFilter(pszTable,pszKey,pszOldValue);
	bRetValue = InsertRecord(pszTable,pszKey,pszNewValue);
	
	return bRetValue;
}

BOOL CSqliteWrap::DeleteFilterValue(LPCTSTR pszTable,LPCTSTR pszValue)
{
	BOOL	bRetValue = FALSE;
	if (pszTable == NULL || pszValue == NULL)
	{
		return bRetValue;
	}

	bRetValue = DeleteFilter(pszTable,pszValue);
	
	return bRetValue;
}

BOOL CSqliteWrap::DeleteFilterValue(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue)
{
	BOOL	bRetValue = FALSE;
	if (pszTable == NULL || pszKey == NULL || pszValue == NULL)
	{
		return bRetValue;
	}

	bRetValue = DeleteFilter(pszTable,pszKey,pszValue);
	
	return bRetValue;
}

BOOL CSqliteWrap::DeleteTableValue(LPCTSTR pszTable)
{
	BOOL	bRetValue = FALSE;
	if (pszTable == NULL)
	{
		return bRetValue;
	}

	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szTableName[50] =  {0x00};
	char			szKeyName[50] =  {0x00};
	char			szKeyData[MAX_PATH] =  {0x00};

	
	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);

	//sprintf(szQuery,"SELECT szFilePath FROM EncryptList WHERE szFilePath = '%s'",szPath2Check);
	sprintf(szQuery,"DELETE FROM %s",szTableName);
	int iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			bRetValue = TRUE;
		}
		else
		{
			
			bRetValue = FALSE;
		}
		sqlite3_finalize(stmInsert);
	}
	
	return bRetValue;
}

BOOL CSqliteWrap::SetUserCategories(LPPC_CATEGORIES pCatStruct)
{
	BOOL	bRetValue = FALSE;
	TCHAR	szData[0x10] = {0x00};

	if (pCatStruct == NULL)
	{
		return bRetValue;
	}

	pCatStruct->bCategoryBlocking==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("CategoryBlocking"),&szData[0x00]);
		
	pCatStruct->bSocialSites==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("SocialSites"),&szData[0x00]);

	pCatStruct->bPornSites==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("PornSites"),&szData[0x00]);

	pCatStruct->bGambling==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("Gambling"),&szData[0x00]);

	pCatStruct->bOnlineGames==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("OnlineGames"),&szData[0x00]);
		
	pCatStruct->bWebmails ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("Webmails"),&szData[0x00]);

	pCatStruct->bWeapons ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("Weapon"),&szData[0x00]);

	pCatStruct->bViolence == true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("Violence"),&szData[0x00]);

	pCatStruct->bOnlinePaymenst==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("OnlinePayments"),&szData[0x00]);

	pCatStruct->bChatForums ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("ChatForums"),&szData[0x00]);
		
	pCatStruct->bIllegalSoft ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("IllegalSoft"),&szData[0x00]);

	pCatStruct->bDrugs ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("Drugs"),&szData[0x00]);

	pCatStruct->bOnlineStores == true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("OnlineStores"),&szData[0x00]);

	pCatStruct->bProxyServ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("ProxyServ"),&szData[0x00]);

	pCatStruct->bExplicitLang==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("ExplicitLang"),&szData[0x00]);

	pCatStruct->bBlockWebSites==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("BlockWebSites"),&szData[0x00]);

	pCatStruct->bParentalControl==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("UserRules"),_T("ParentalControl"),&szData[0x00]);
		

	return bRetValue;
}

BOOL CSqliteWrap::SetCommonRules(LPFW_COMMON_RULES pRulesStruct)
{
	BOOL	bRetValue = FALSE;
	TCHAR	szData[0x10] = {0x00};

	if (pRulesStruct == NULL)
	{
		return bRetValue;
	}

	pRulesStruct->bNetworkFilter==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("NetworkFilter"),&szData[0x00]);
		
	pRulesStruct->bBlockWebSites ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("BlockWebSites"),&szData[0x00]);

	pRulesStruct->bApplicationRule==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("ApplicationRule"),&szData[0x00]);

	pRulesStruct->bAntiBanner==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("AntiBanner"),&szData[0x00]);

	pRulesStruct->bAntiPhishing==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("AntiPhishing"),&szData[0x00]);
		
	pRulesStruct->bNetworkMonitor ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("NetworkMonitor"),&szData[0x00]);

	pRulesStruct->bWhiteFiltering ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("whitefiltering"),&szData[0x00]);

	pRulesStruct->bBlockAll ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("blockall"),&szData[0x00]);

	pRulesStruct->bDHCP  ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("DHCP"),&szData[0x00]);

	pRulesStruct->bDNS  ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("DNS"),&szData[0x00]);

	pRulesStruct->bNetBios  ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("netbios"),&szData[0x00]);
	
	pRulesStruct->bLDAP  ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("ldap"),&szData[0x00]);

	pRulesStruct->bKerbores  ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("kerbores"),&szData[0x00]);
	
	pRulesStruct->bVPN  ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("VPN"),&szData[0x00]);
	
	pRulesStruct->bIGMP  ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("IGMP"),&szData[0x00]);
	
	pRulesStruct->bICMP  ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("OtherIcmp"),&szData[0x00]);
	
	pRulesStruct->bFTP  ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("FTP"),&szData[0x00]);

	pRulesStruct->bContentSearch  ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("contentsearch"),&szData[0x00]);

	pRulesStruct->bIDSRules  ==true?_tcscpy(szData,_T("1")):_tcscpy(szData,_T("0"));
	bRetValue = SetValue(_T("CommonRules"),_T("idsip"),&szData[0x00]);
	
	return bRetValue;
}

BOOL CSqliteWrap::IsUserDBPresent(LPTSTR pszUserName, LPTSTR pszDBFolderPath)
{
	BOOL	bRetValue = FALSE;
	TCHAR	szUserDBPath[MAX_PATH] = {0x00};

	if (pszUserName == NULL || pszDBFolderPath == NULL)
	{
		return bRetValue; 
	}

	_stprintf(&szUserDBPath[0x00],_T("%s\\PnPFW%s.DB"),pszDBFolderPath,_tcslwr(pszUserName));
	if (PathFileExists(szUserDBPath))
	{
		bRetValue = TRUE;
	}
	return bRetValue;
}

BOOL CSqliteWrap::DeleteUserDB(LPTSTR pszUserName, LPTSTR pszDBFolderPath)
{
	BOOL	bRetValue = FALSE;
	TCHAR	szUserDBPath[MAX_PATH] = {0x00};

	if (pszUserName == NULL || pszDBFolderPath == NULL)
	{
		return bRetValue; 
	}

	_stprintf(&szUserDBPath[0x00],_T("%s\\PnPFW%s.DB"),pszDBFolderPath,_tcslwr(pszUserName));
	
	bRetValue = DeleteFile(szUserDBPath);
	
	return bRetValue;
}

BOOL CSqliteWrap::CreateUserDB(LPTSTR pszUserName, LPTSTR pszDBFolderPath,LPTSTR pszUserDBPath)
{
	BOOL	bRetValue = FALSE;
	TCHAR	szUserDBPath[MAX_PATH] = {0x00};
	TCHAR	szBlankUserDB[MAX_PATH] = {0x00};

	_stprintf(szUserDBPath,_T("%s\\PnPFW%s.DB"),pszDBFolderPath,_tcslwr(pszUserName));
	_stprintf(szBlankUserDB,_T("%s\\PnpUserDB.DB"),pszDBFolderPath);

	//PnpUserDB.DB
	if (IsUserDBPresent(pszUserName,pszDBFolderPath))
	{
		if (pszUserDBPath != NULL)
		{
			_tcscpy(pszUserDBPath,szUserDBPath);
		}
		return TRUE;
	}

	CopyFile(szBlankUserDB,szUserDBPath,TRUE);
	Sleep(100);
	if (IsUserDBPresent(pszUserName,pszDBFolderPath))
	{
		if (pszUserDBPath != NULL)
		{
			_tcscpy(pszUserDBPath,szUserDBPath);
		}
		return TRUE;
	}

	return bRetValue;
}

/*
OLD
BOOL CSqliteWrap::GetAllTableEntries(LPCTSTR pszTable,LPTSTR pszKeyOut,LPSTR pszKeyOutANSI,LPTSTR pszValueOut,LPSTR pszValueOutANSI)
{
	BOOL	bRetValue = FALSE;
	char	szQuery[512] = {0x00};
	char	szKeyName[MAX_PATH] = {0x00};
	char	szKeyValue[MAX_PATH] = {0x00};
	char	szTableName[MAX_PATH] = {0x00};
	int		iRetval = 0x00;

	if (m_bEnumStarted == FALSE)
	{
		strcpy(szTableName,CT2A(pszTable));
		strlwr(szTableName);

		sprintf(szQuery,"SELECT FilterType,FilterString FROM %s",szTableName);
		iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &m_pstmGetAll, NULL);
		if (!iRetval)
		{
			m_bEnumStarted = TRUE;
			iRetval = sqlite3_step(m_pstmGetAll);
			if (iRetval == SQLITE_ROW)
			{
				strcpy(szKeyName,(char *)sqlite3_column_text(m_pstmGetAll , 0));
				strcpy(szKeyValue,(char *)sqlite3_column_text(m_pstmGetAll, 1));

				if (pszKeyOut != NULL)
				{
					_stprintf(pszKeyOut,_T("%S"),(LPCTSTR)szKeyName);
				}
				if (pszKeyOutANSI != NULL)
				{
					strcpy(pszKeyOutANSI,szKeyName);
				}

				if (pszValueOut != NULL)
				{
					_stprintf(pszValueOut,_T("%S"),(LPCTSTR)szKeyValue);
				}
				if (pszValueOutANSI != NULL)
				{
					strcpy(pszValueOutANSI,szKeyValue);
				}

				return TRUE;
			}
			else
			{
				m_bEnumStarted = FALSE;
				sqlite3_finalize(m_pstmGetAll);
				return FALSE;
			}
		}
	}
	else
	{
		iRetval = sqlite3_step(m_pstmGetAll);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(szKeyName,(char *)sqlite3_column_text(m_pstmGetAll, 0));
			strcpy(szKeyValue,(char *)sqlite3_column_text(m_pstmGetAll, 1));

			if (pszKeyOut != NULL)
			{
				_stprintf(pszKeyOut,_T("%S"),(LPCTSTR)szKeyName);
			}
			if (pszKeyOutANSI != NULL)
			{
				strcpy(pszKeyOutANSI,szKeyName);
			}

			if (pszValueOut != NULL)
			{
				_stprintf(pszValueOut,_T("%S"),(LPCTSTR)szKeyValue);
			}
			if (pszValueOutANSI != NULL)
			{
				strcpy(pszValueOutANSI,szKeyValue);
			}

			return TRUE;
		}
		else
		{
			m_bEnumStarted = FALSE;
			sqlite3_finalize(m_pstmGetAll);
			return FALSE;
		}
	}

	return bRetValue;
}
*/

int	CSqliteWrap::GetCountTableEntries(LPCSTR pszTable,int &pUrlCnt)
{
	int				iRetCnt = 0x00;
	sqlite3_stmt	*stmInsert;
	char			szQuery[512] = {0x00};
	char			szData[MAX_PATH] = {0x00};
	int				iRetval = 0x00;

	pUrlCnt = 0x00;
	sprintf(szQuery,"select count(filterString) from %s",pszTable);
	iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
			iRetCnt = strtol(szData,NULL,10);
		}
		sqlite3_finalize(stmInsert);
	}

	sprintf(szQuery,"select count(filterString) from %s where filterString like '%%.%%'",pszTable);
	iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(szData,(char *)sqlite3_column_text(stmInsert, 0));
			pUrlCnt = strtol(szData,NULL,10);
		}
		sqlite3_finalize(stmInsert);
	}

	return iRetCnt;
}

BOOL CSqliteWrap::GetAllTableEntries(LPCSTR pszTable,LPSTR pszValueOutANS)
{
	BOOL	bRetValue = FALSE;
	char	szQuery[512] = {0x00};
	char	szKeyName[MAX_PATH] = {0x00};
	//char	szKeyValue[MAX_PATH] = {0x00};
	char	szTableName[MAX_PATH] = {0x00};
	int		iRetval = 0x00;

	if (m_bEnumStarted == FALSE)
	{
		//strcpy(szTableName,CT2A(pszTable));
		strcpy(szTableName,pszTable);
		strlwr(szTableName);

		sprintf(szQuery,"SELECT filterString FROM %s ORDER BY filterString ASC",szTableName);
		iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &m_pstmGetAll, NULL);
		if (!iRetval)
		{
			m_bEnumStarted = TRUE;
			iRetval = sqlite3_step(m_pstmGetAll);
			if (iRetval == SQLITE_ROW)
			{
				strcpy(szKeyName,(char *)sqlite3_column_text(m_pstmGetAll , 0));
				
				if (pszValueOutANS != NULL)
				{
					strcpy(pszValueOutANS,szKeyName);
				}

				
				return TRUE;
			}
			else
			{
				m_bEnumStarted = FALSE;
				sqlite3_finalize(m_pstmGetAll);
				return FALSE;
			}
		}
	}
	else
	{
		iRetval = sqlite3_step(m_pstmGetAll);
		if (iRetval == SQLITE_ROW)
		{
			strcpy(szKeyName,(char *)sqlite3_column_text(m_pstmGetAll, 0));

			if (pszValueOutANS != NULL)
			{
				strcpy(pszValueOutANS,szKeyName);
			}

			return TRUE;
		}
		else
		{
			m_bEnumStarted = FALSE;
			sqlite3_finalize(m_pstmGetAll);
			return FALSE;
		}
	}

	return bRetValue;
}

BOOL CSqliteWrap::GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT)
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

BOOL CSqliteWrap:: CreateNewTable(LPCTSTR pszTable, LPCTSTR pszColumnName)
{
	BOOL	bRetValue = FALSE;
	char	szQuery[512] = {0x00};
	char	szTableName[MAX_PATH]	= {0x00};
	char    szColumnName[MAX_PATH]	= {0x00};
	int 	iRetval = 0x00;
	sqlite3_stmt	*stmInsert;

	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);
	strcpy(szColumnName,CT2A(pszColumnName));
	sprintf(szQuery,"CREATE TABLE %s (%s TEXT);", szTableName ,szColumnName);
	//sprintf(szQuery,"CREATE TABLE %s (ID int NOT NULL, %s TEXT);", szTableName, szColumnName);


	iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW ||iRetval == SQLITE_DONE)
		{
			bRetValue = TRUE;
		}
		else
		{  
			bRetValue = FALSE;
		}
		sqlite3_finalize(stmInsert);
	}

	return bRetValue;
}

BOOL CSqliteWrap::IsKeyExistsForIDS(LPCTSTR pszTable,LPCTSTR pszKey)
{
	BOOL	bRetValue = FALSE;

	if (pszTable == NULL || pszKey == NULL)
	{
		return bRetValue;
	}

	if (_tcslen(pszTable) == 0x00 || _tcslen(pszKey) == 0x00)
	{
		return bRetValue;
	}

	sqlite3_stmt	*stmInsert;
	int				iIsFolder = 0x00;
	char			szQuery[512] = {0x00};
	char			szTableName[50] =  {0x00};
	char			szKeyName[50] =  {0x00};

	
	strcpy(szTableName,CT2A(pszTable));
	strlwr(szTableName);

	strcpy(szKeyName,CT2A(pszKey));
	strlwr(szKeyName);

	
	//sprintf(szQuery,"SELECT szFilePath FROM EncryptList WHERE szFilePath = '%s'",szPath2Check);
	//sprintf(szQuery,"SELECT FilterType FROM %s WHERE FilterType = '%s'",szTableName, szKeyName);
	sprintf(szQuery,"SELECT %s FROM %s",szKeyName, szTableName);
	int iRetval = sqlite3_prepare(m_pSQliteDB, szQuery, -1, &stmInsert, NULL);
	if (!iRetval)
	{
		iRetval = sqlite3_step(stmInsert);
		if (iRetval == SQLITE_ROW)
		{
			bRetValue = TRUE;
		}
		else
		{
			
			bRetValue = FALSE;
		}
		sqlite3_finalize(stmInsert);	
	}
	
	return bRetValue;
}