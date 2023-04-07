#pragma once
#include "sqlite3.h"
#include <atlbase.h>
#include <atlconv.h>


class CMaxSqLiteBase
{
public:
	CMaxSqLiteBase(LPCTSTR	pszDBPath);
	~CMaxSqLiteBase(void);

	sqlite3			*m_pSQliteDB;
	sqlite3_stmt	*m_pstmGetAll;
	char			m_szDDBPath[1024];
	BOOL			m_bDBLoaded;
	BOOL			m_bEnumStarted;
	
	BOOL			OpenDatabase(LPCTSTR	pszDBPath);
	BOOL			CloseDatabase();
	BOOL			ExecuteQuery(LPCTSTR pszQuey,BOOL bGlobalEnum = FALSE,BOOL bInsertStm = FALSE,int *piErrCode = NULL);
	//BOOL			ExecuteQuery(LPCTSTR pszQuey,BOOL bGlobalEnum = FALSE,BOOL bInsertStm = FALSE,int *piErrCode = NULL);
	//BOOL			ExecuteQueryEx(LPCTSTR pszQuey,BOOL bGlobalEnum = FALSE,BOOL bInsertStm = FALSE,int *piErrCode = NULL);

	BOOL			GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT);
	bool			GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT);

	bool			GetScanRecord(LPUNSAFE_FILE_INFO pResults);

	bool			GetScanRecordEx(LPUNSAFE_FILE_FULL_INFO pResults);


	BOOL			m_bISDBLOADED;
};
