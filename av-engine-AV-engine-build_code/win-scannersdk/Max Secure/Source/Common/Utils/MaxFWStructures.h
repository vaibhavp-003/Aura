#pragma once

typedef struct _FIREWALL_DB_DATA
{
	DWORD	dwRuleCnt;
	char	**pRuleList;

	DWORD	dwKeyWordCnt;
	char	**pKeyWordList;

	int		iChrIndex[0x1A];

}FIREWALL_DB_DATA,*LPFIREWALL_DB_DATA;

typedef struct _NETWORK_FILTER_SETTINGS
{
	bool	bNetworkMonitor; //For IP Base
	bool	bNetworkFilter; //For Protocols
	bool	bDHCP;
	bool	bDNS;
	bool	bIGMP;
	bool	bKerbores;
	bool	bLDAP;
	bool	bNetBios;
	bool	bICMP;
	bool	bVPN;
	bool	bFTP;  
}NETWORK_FILTER_SETTINGS, *LPNETWORK_FILTER_SETTINGS;

typedef struct _PROCESS_CACHE_LIST
{
	DWORD	dwProcID;
	char	szProcName[512];
	bool	bBlock;
	
}PROCESS_CACHE_LIST,*LPPROCESS_CACHE_LIST;

typedef struct _FW_COMMON_RULES
{
	bool	bBlockAll;
	bool	bWhiteFiltering;
	
	bool	bNetworkFilter;
	bool	bBlockWebSites;
	bool	bNetworkMonitor;
	bool	bApplicationRule;
	bool	bAntiBanner;
	bool	bAntiPhishing;
	bool	bContentSearch;

	bool	bDHCP;
	bool	bDNS;
	bool	bIGMP;
	bool	bKerbores;
	bool	bLDAP;
	bool	bNetBios;
	bool	bICMP;
	bool	bVPN;
	bool	bFTP;    

	bool	bIDSRules;
	bool	bAllowSubDomain;
	
}FW_COMMON_RULES,*LPFW_COMMON_RULES;

typedef struct _PC_CATEGORIES
{
	bool	bCategoryBlocking;
	bool	bSocialSites;
	bool	bPornSites;
	bool	bGambling;
	bool	bOnlineGames;
	bool	bWebmails;
	bool	bWeapons;
	bool	bViolence;
	bool	bOnlinePaymenst;
	bool	bChatForums;
	bool	bIllegalSoft;
	bool	bDrugs;
	bool	bOnlineStores;
	bool	bProxyServ;
	bool	bExplicitLang;
	bool	bBlockWebSites;
	bool	bParentalControl;
}PC_CATEGORIES,*LPPC_CATEGORIES;

typedef struct _INT_COMP_USAGE_BLOCK
{
	bool	bIsBlockingON;
	bool	bWeekDays;
	bool	bWeekEnds;
	TCHAR	szWeekDays[60];
	TCHAR	szWeekEnds[60];
	int		intWeekDays[24];
	int		intWeekEnds[24];
}INT_COMP_USAGE_BLOCK,*LPINT_COMP_USAGE_BLOCK;