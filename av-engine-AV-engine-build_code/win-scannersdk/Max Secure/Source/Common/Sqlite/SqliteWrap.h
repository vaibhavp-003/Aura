#pragma once
#include "sqlite3.h"

#include "MaxFWStructures.h"

class CSqliteWrap
{
	char			m_szDDBPath[MAX_PATH];
	sqlite3			*m_pSQliteDB;
	
	BOOL			IsDuplicateValue(LPCTSTR pszTable,LPCTSTR pszKey2Check);
	BOOL			IsDuplicateValue(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue);
	BOOL			IsKeyExists(LPCTSTR pszTable,LPCTSTR pszKey);

	BOOL			InsertRecord(LPCTSTR pszTable,LPCTSTR pszData);
	BOOL			InsertRecord(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue);
	
	BOOL			UpdateRecord(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue);
	//BOOL			UpdateRecord(LPCTSTR pszTable,LPCTSTR pszValue);

	BOOL			DeleteFilter(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue);
	BOOL			DeleteFilter(LPCTSTR pszTable,LPCTSTR pszValue);

	sqlite3_stmt	*m_pstmGetAll;
	BOOL			m_bEnumStarted;

public:
	CSqliteWrap(LPCSTR	pszDBPath);
	~CSqliteWrap(void);
	
	BOOL		m_bDBLoaded;
	
	BOOL		OpenDatabase(LPCSTR	pszDBPath);
	BOOL		CloseDatabase();
	
	BOOL		GetValue(LPCTSTR pszTable,LPCTSTR pszKey,LPTSTR pszValueOut,LPSTR pszValueOutANSI);
	BOOL		SetValue(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue);
	//BOOL		SetFilterValue(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue);
	BOOL		SetFilterValue(LPCTSTR pszTable, LPCTSTR pszData);

	BOOL		UpdateFilterValue(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszOldValue,LPCTSTR pszNewValue);
	BOOL		UpdateFilterValue(LPCTSTR pszTable,LPCTSTR pszOldValue,LPCTSTR pszNewValue);

	BOOL		DeleteFilterValue(LPCTSTR pszTable,LPCTSTR pszKey,LPCTSTR pszValue);
	BOOL		DeleteFilterValue(LPCTSTR pszTable,LPCTSTR pszValue);

	BOOL		DeleteTableValue(LPCTSTR pszTable);

	BOOL		IsInternetBlockingON(bool &bWeekDays,bool &bWeekEnds,LPSTR	pszWeekDays,LPSTR	pszWeekEnds);
	BOOL		IsCompBlockingON(bool &bWeekDays,bool &bWeekEnds,LPSTR	pszWeekDays,LPSTR	pszWeekEnds);
	
	BOOL		SetInternetBloking(int iBlockingON, int iWeekDays, int iWeekEnds,LPCTSTR	pszWeekDays,LPCTSTR	pszWeekEnds);
	BOOL		SetComputerBloking(int iBlockingON, int iWeekDays, int iWeekEnds,LPCTSTR	pszWeekDays,LPCTSTR	pszWeekEnds);

	BOOL		GetUserCategories(LPPC_CATEGORIES pCatStruct);
	BOOL		SetUserCategories(LPPC_CATEGORIES pCatStruct);

	BOOL		GetCommonRules(LPFW_COMMON_RULES pRulesStruct);
	BOOL		SetCommonRules(LPFW_COMMON_RULES pRulesStruct);

	BOOL		IsUserDBPresent(LPTSTR pszUserName, LPTSTR pszDBFolderPath);
	BOOL		CreateUserDB(LPTSTR pszUserName, LPTSTR pszDBFolderPath,LPTSTR pszUserDBPath);
	BOOL		DeleteUserDB(LPTSTR pszUserName, LPTSTR pszDBFolderPath);

	int			GetCountTableEntries(LPCSTR pszTable,int &pUrlCnt);
	BOOL		GetAllTableEntries(LPCTSTR pszTable,LPTSTR pszKeyOut,LPSTR pszKeyOutANSI,LPTSTR pszValueOut,LPSTR pszValueOutANSI);
	BOOL		GetAllTableEntries(LPCSTR pszTable,LPSTR pszValueOutANS);

	BOOL		GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT);

	BOOL		CreateNewTable(LPCTSTR pszTable, LPCTSTR pszColumnName); 
	BOOL		IsKeyExistsForIDS(LPCTSTR pszTable,LPCTSTR pszKey);
};
