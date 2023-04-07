#pragma once

#include "MaxFWStructures.h"

#include "SqliteWrap.h"
#include "ProcessRuleMgr.h"
#include "wininet.h"

typedef struct _MAX_ANTI_PHISH_STATUS
{
	char	strUrl[512];
	BOOL	bStatus; //FALSE = Not Phishing
}MAX_ANTI_PHISH_STATUS,*lpMAX_ANTI_PHISH_STATUS;

typedef struct _MAX_CONNECTION_LIST
{
	TCHAR	szIPAdr[40];
	DWORD	dwConID;
	BOOL	bBlock;
}MAX_CONNECTION_LIST,*lpMAX_CONNECTION_LIST;


class MaxFWDBMgr
{
private:
	CSqliteWrap		*m_pSqliteWrap;
	CSqliteWrap		*m_pUserSqliteWrap;
	CProcessRuleMgr	*m_pProcRuleMgr;

	char			m_szFwDBPath[MAX_PATH];
	char			m_szUserDBPath[MAX_PATH];

	BOOL			GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT);
	BOOL			GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT);
	BOOL			UnloadMemDB(LPFIREWALL_DB_DATA pDBinMemory);
	BOOL			AllocMemory2DB(LPFIREWALL_DB_DATA *pDBinMemory);
	int				SearchInMemDB(LPFIREWALL_DB_DATA pDBinMemory, LPCSTR pszBuff2Search, BOOL bIsURL, BOOL bCheckSubDomain = FALSE);
	 

	BOOL			LoadHrsArray(LPINT_COMP_USAGE_BLOCK pUsageStruct);
	HINTERNET		m_hInternetSession;
	HINTERNET		m_hHttpConnection;

public:
	MaxFWDBMgr(void);
	~MaxFWDBMgr(void);

	FW_COMMON_RULES				m_FWCommonRules;
	PC_CATEGORIES				m_ParentalCntrlRules;
	NETWORK_FILTER_SETTINGS		m_NetworkSettings;
	INT_COMP_USAGE_BLOCK		m_InterNetUsageBlock;
	INT_COMP_USAGE_BLOCK		m_ComputerUsageBlock;


	LPFIREWALL_DB_DATA	m_pBlackList;
	LPFIREWALL_DB_DATA	m_pWhiteList;
	LPFIREWALL_DB_DATA	m_pUserBlackList;
	LPFIREWALL_DB_DATA	m_pApplicationList;
	LPFIREWALL_DB_DATA	m_pNetworkMonitor;
	LPFIREWALL_DB_DATA	m_pIDSRules; //Added by Tushar on 16 Nov 2018

	LPFIREWALL_DB_DATA	m_pPornSites;
	LPFIREWALL_DB_DATA	m_pSocialNetwork;
	LPFIREWALL_DB_DATA	m_pPaymentGateways;
	LPFIREWALL_DB_DATA	m_pOnlienStores;
	LPFIREWALL_DB_DATA	m_pWebMail;
	LPFIREWALL_DB_DATA	m_pDrugs;
	LPFIREWALL_DB_DATA	m_pWeapons;
	LPFIREWALL_DB_DATA	m_pViolence;
	LPFIREWALL_DB_DATA	m_pIllegalSoft;
	LPFIREWALL_DB_DATA	m_pOnlineGaming;
	LPFIREWALL_DB_DATA	m_pProxy;
	LPFIREWALL_DB_DATA	m_pExpliciteLang;
	LPFIREWALL_DB_DATA	m_pGambling;
	LPFIREWALL_DB_DATA	m_pChatForums;    

	BOOL	LoadDatabase(LPCTSTR pszDBPath,LPCTSTR pszUserDBPath);
	BOOL	UnloadDatabase();
	int		LoadDBInMemory(CSqliteWrap *pSqlAgent, LPCSTR pszTableName, LPFIREWALL_DB_DATA pDBinMemory);

	int		Search4MaxDownloadSite(LPCSTR pszInBuff);
	int		Search4Rules(LPCSTR pszInBuff, BOOL bDoContainSearch = TRUE);
	BOOL	CheckProcInAppRule(DWORD dwProcID);
	BOOL	CheckIPAddress(LPCTSTR pszIPAdrswithPort); 
	int		GetWhiteListCount();
	int		GetBlackListCount();
	BOOL	GetNetworkSettings(LPNETWORK_FILTER_SETTINGS pNetworkSettings);

	BOOL	CheckIDSIPAddress(LPCTSTR pszIPAdrs);

	BOOL		GetUserCategories(LPPC_CATEGORIES pCatStruct);
	BOOL		SetUserCategories(LPPC_CATEGORIES pCatStruct);
	BOOL		GetCommonRules(LPFW_COMMON_RULES pRulesStruct);
	BOOL		SetCommonRules(LPFW_COMMON_RULES pRulesStruct);

	BOOL		GetUserCategories();
	BOOL		SetUserCategories();
	BOOL		GetCommonRules();
	BOOL		SetCommonRules();

	BOOL		IsInternetBlockingON(bool &bWeekDays,bool &bWeekEnds,LPSTR	pszWeekDays,LPSTR	pszWeekEnds);
	BOOL		IsCompBlockingON(bool &bWeekDays,bool &bWeekEnds,LPSTR	pszWeekDays,LPSTR	pszWeekEnds);
	BOOL		IsInternetBlockingON(bool &bWeekDays,bool &bWeekEnds,LPTSTR	pszWeekDays,LPTSTR	pszWeekEnds);
	BOOL		IsCompBlockingON(bool &bWeekDays,bool &bWeekEnds,LPTSTR	pszWeekDays,LPTSTR	pszWeekEnds);

	BOOL		IsCompBlockingON(LPINT_COMP_USAGE_BLOCK pCompUsage);
	BOOL		IsInternetBlockingON(LPINT_COMP_USAGE_BLOCK pInternetUsage);

	BOOL		IsCompBlockingON();
	BOOL		IsInternetBlockingON();

	BOOL		SetInternetBloking();
	BOOL		SetComputerBloking();

	BOOL		SetInternetBloking(int iBlockingON, int iWeekDays, int iWeekEnds,LPCTSTR	pszWeekDays,LPCTSTR	pszWeekEnds);
	BOOL		SetComputerBloking(int iBlockingON, int iWeekDays, int iWeekEnds,LPCTSTR	pszWeekDays,LPCTSTR	pszWeekEnds);

	BOOL		IsUserDBPresent(LPTSTR pszUserName, LPTSTR pszDBFolderPath);
	BOOL		CreateUserDB(LPTSTR pszUserName, LPTSTR pszDBFolderPath,LPTSTR pszUserDBPath);
	BOOL		DeleteUserDB(LPTSTR pszUserName, LPTSTR pszDBFolderPath);

	BOOL		SetFilterValue(LPCTSTR pszTable,LPCTSTR pszData,BOOL bUserDBValue = FALSE);
	BOOL		DeleteFilterValue(LPCTSTR pszTable,LPCTSTR pszData,BOOL bUserDBValue = FALSE);
	BOOL		UpdateFilterValue(LPCTSTR pszTable,LPCTSTR pszOldData,LPCTSTR pszNewData,BOOL bUserDBValue = FALSE);
	BOOL		GetAllEntries(LPCTSTR pszTable,LPFIREWALL_DB_DATA pDBinMem);

	int			ImportBulkDatafromFile(LPCTSTR pszTable,LPCTSTR pszFilePath, BOOL bUserData = FALSE);
	BOOL		GetReplyFromURL(char *pczURL);
	BOOL		GetReplyFromURLEx(char *pczURL); //For Antiphishing API
	

	BOOL		CreateNewTable(LPCTSTR pszTable, LPCTSTR pszColumnName);
	BOOL		IsKeyExists(LPCTSTR pszTable,LPCTSTR pszKey);
	int			Check4WhiteUrl(char *pczURL);
	int			GetURLAntiPhishStatus(char *pczURL);
	int			AddURLAntiPhishStatus(char *pczURL, BOOL bStatus);
	//MAX_ANTI_PHISH_STATUS	m_AntiPhishingLst[0x01];
	MAX_ANTI_PHISH_STATUS	*pm_AntiPhishingLst;
	DWORD					m_dwAntiPhishingLstCnr;
	
	//MAX_CONNECTION_LIST		m_ConnectionList[0x01];
	MAX_CONNECTION_LIST		*pm_ConnectionList;
	DWORD					m_dwConnectionLstCnt;
	int						AddNewConnection(DWORD dwConId, LPCTSTR pszRemoteIP, BOOL bBlock = FALSE);
	int						GetIPofConnection(DWORD dwConId, LPTSTR pszRemoteIP);
	int						IsSusConnectionID(DWORD dwConId, LPTSTR pszRemoteIP);
};
