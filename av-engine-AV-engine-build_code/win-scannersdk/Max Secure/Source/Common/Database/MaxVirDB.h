// LoadMMF.cpp : Defines the entry point for the console application.
//

using namespace std;
#include <atlbase.h>
#include <string>
#include <vector>
#include <map>
using namespace std;


const int MAX_EXPRESSION_SIZE = 96;
const TCHAR REPAIR_DB_NAME[] = _T("SDVR50.DB");
const TCHAR SCAN_DB_NAME[] = _T("SDVS50.DB");

typedef map<string,string> SCANDBMAP;

#pragma pack (1)
typedef struct tag_REPAIRDB
{
	DWORD dwID;
	char sbExpr[MAX_EXPRESSION_SIZE];
}REPAIRDB,*LPREPAIRDB;
#pragma pack ()
const int SIZE_OF_REPAIR_DB = sizeof(REPAIRDB);

enum VIRDBTYPE{
	eVirRepairDB,
	eVirScannerDB
};

typedef std::vector<REPAIRDB> APPENDLIST;

class CMaxVirDB{
public:
	CMaxVirDB(int nStructSize,VIRDBTYPE eDBType);
	~CMaxVirDB();
	bool GetInstallPath(LPTSTR szInstall);
	bool GetRepairExpression(DWORD &dwRepairID,LPTSTR szRepairAction);
	void CloseFile();
	bool CreateRepairDB(LPCTSTR lpIniFileName, LPCTSTR lpFileName);
	bool MergeRepairDB(LPCTSTR lpIniFileName,LPCTSTR lpFileName);
	bool UpdateScanDB(LPCTSTR lpIniFileName,LPCTSTR lpFileName);
	bool IsRepairDBLoaded();
	bool LoadMMFDB(LPCTSTR lpFileName,bool bReadOnly = true);

private:
	VIRDBTYPE m_eDBType;
	int m_nStructSize;
	HANDLE	m_hFile;
	HANDLE	m_hFileMapp;
	void *	m_pFileBase;
	void *  m_pCurrPos;
	DWORD m_dwFileSize;
	BOOL ProcessBuffer(HANDLE hFile, string &strLine);
	bool MergeBuffer(string &strLine);
	bool m_bSaveMode;
	DWORD m_dwLastIDIndex;
	APPENDLIST m_objAppendList;
	bool m_bAppendFile;
	TCHAR m_szMainDBFile[MAX_PATH];
	bool LoadScanDB(LPCTSTR lpIniFileName,SCANDBMAP& objScanDBMap);
	bool ProcesScanBuffer(string &strLine,SCANDBMAP& objScanDBMap);
};