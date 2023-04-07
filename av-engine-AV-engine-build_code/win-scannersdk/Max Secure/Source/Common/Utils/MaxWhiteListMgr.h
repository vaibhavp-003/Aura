#pragma once
#include "S2S.h"
#define MAX_WHITELIST_NOTFOUND		0
#define MAX_WHITELIST_BLOCK			1
#define MAX_WHITELIST_ALLOW			2
#define MAX_WHITELIST_NEWBLOCK		3
#define MAX_WHITELIST_NEWALLOW		4

typedef struct _WhiteListedApps
{
	wchar_t szWhiteApplicationPath[MAX_PATH];
} WhiteListedApps;

typedef struct _BlackListedApps
{
	wchar_t szBlackApplicationPath[MAX_PATH];
} BlackListedApps;

typedef struct _CrptExtList
{
	wchar_t szCryptMonExt[20];
} CrptExtList;

class CMaxWhiteListMgr
{
public:
	CMaxWhiteListMgr(void);
	~CMaxWhiteListMgr(void);
	CS2S			m_objDBWhiteList;
	CS2S			m_objDBAppBlockList;
	CS2S			m_objDBAppExtList;
	CStringArray	m_csArrWhiteListEntries;
	CStringArray	m_csArrAppBlockListEntries;
	CStringArray	m_csArrAppExtListEntries;
	DWORD			m_dwWhiteListEnable;
	
	void LoadDB();
	void SaveDB();
	void LoadExtDB();
	void LoadExtDBEx();
	void SaveExtDB();
	int CheckWhiteList();
	int SearchDB(LPCTSTR pszPathSearch);
	int SearchDBForWhite(LPCTSTR pszPathSearch);
	int SearchDBExt(LPCTSTR pszExtSearch);
	bool CheckIgnorePath(LPCTSTR pszPathSearch);
	bool IgnorePath(LPCTSTR pszPathSearch, BOOL bFSMonCall =  FALSE);
	int SearchINBlackDB(LPCTSTR pszPathSearch,bool bSearchOnly = false);
	bool CheckAccessedFile(LPCTSTR pszFileAccessed,LPCTSTR pszProcName = NULL);
	int ManageShortPath(CString &csProcessPath,CString &csFilePath);
	int GetWhiteListedAppsCnt();
	int GetBlackListedAppsCnt();
	int GetCryptExtCnt();
	void GetListedData(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize);
	void SetListedData(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize);
	void SetCryptMonDataIntoDB(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize, CrptExtList* pCryptMonExt, int iCryptMonExtSize);
	bool PostMessageToService();
	bool PostMessageToServiceCrypt();
	bool PostMessageToProtection(UINT WM_Message, UINT ActMon_Message, UINT uStatus);

	void GetExtListForCryptMon(CrptExtList* pCryptMonExt, int iCryptMonExtSize);
private:
	bool	m_bAlreadyLoaded;
	
};
