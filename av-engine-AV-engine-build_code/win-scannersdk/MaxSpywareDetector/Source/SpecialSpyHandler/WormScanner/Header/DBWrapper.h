#pragma once
#include "sqlite3.h"
class CDBWrapper
{
private:
	sqlite3			*m_pPCSafeDB;
	sqlite3_stmt	*m_pstmGetList;
	bool			m_bEnumStarted;
	bool			IsAlreadyExists(const char *pszFile2Check);
public:
	CDBWrapper(void);
	~CDBWrapper(void);
	bool OpenDB(const char * pszDBPath );
	bool Insert(const char * pszFilePath );
	bool InsertDefaultGoogle(const char *pszFilePath);
	bool InsertDefaultYahoo(const char *pszFilePath);
	bool InsertDefaultBing(const char *pszFilePath);
	bool Delete(const char * pszFilePath );
	bool DeleteQuery(const char *pszFilePath);
	bool GetFullList(char *pszFilePath);
	
};
