#include "pch.h"
#include "MaxFWDBMgr.h"
#include <afxinet.h>
MaxFWDBMgr::MaxFWDBMgr(void)
{
	m_pSqliteWrap = NULL;
	m_pUserSqliteWrap = NULL;
	m_pProcRuleMgr = NULL;
	
	m_pBlackList = NULL;
	m_pWhiteList = NULL;
	m_pUserBlackList = NULL; 

	//Category DB
	m_pPornSites = NULL;
	m_pSocialNetwork = NULL;
	m_pPaymentGateways = NULL;
	m_pOnlienStores = NULL;
	m_pWebMail = NULL;
	m_pDrugs = NULL;
	m_pWeapons = NULL;
	m_pViolence = NULL;
	m_pIllegalSoft = NULL;
	m_pOnlineGaming = NULL;
	m_pProxy = NULL;
	m_pExpliciteLang = NULL;
	m_pGambling = NULL;
	m_pChatForums = NULL;

	m_pApplicationList = NULL;
	m_pNetworkMonitor = NULL;
	m_pIDSRules = NULL;

	memset(&m_FWCommonRules,0x00,sizeof(FW_COMMON_RULES));
	memset(&m_ParentalCntrlRules,0x00,sizeof(PC_CATEGORIES));
	memset(&m_InterNetUsageBlock,0x00,sizeof(INT_COMP_USAGE_BLOCK)); 
	memset(&m_ComputerUsageBlock,0x00,sizeof(INT_COMP_USAGE_BLOCK)); 
	
	
	strcpy(m_szFwDBPath,"");
	m_hInternetSession = NULL;
	m_hHttpConnection = NULL;

	m_dwAntiPhishingLstCnr = 0x00;
	pm_AntiPhishingLst = NULL;

	pm_ConnectionList = NULL;
	m_dwConnectionLstCnt = 0x00;
}

MaxFWDBMgr::~MaxFWDBMgr(void)
{
	strcpy(m_szFwDBPath,"");
	UnloadDatabase();
	if (m_pSqliteWrap)
	{
		delete m_pSqliteWrap;
		m_pSqliteWrap = NULL;
	}
	if (m_pUserSqliteWrap)
	{
		delete m_pUserSqliteWrap;
		m_pUserSqliteWrap = NULL;
	}
	if (m_pProcRuleMgr)
	{
		delete m_pProcRuleMgr;
		m_pProcRuleMgr = NULL;
	}
	if(m_hInternetSession)
	{
		InternetCloseHandle(m_hInternetSession);
		m_hInternetSession = NULL;
	}
	if(m_hHttpConnection)
	{
		InternetCloseHandle(m_hHttpConnection);
		m_hHttpConnection = NULL;
	}	

	if (pm_ConnectionList != NULL)
	{
		delete []pm_ConnectionList;
	}
	if (pm_AntiPhishingLst != NULL)
	{
		delete []pm_AntiPhishingLst;
	}
	
}

BOOL MaxFWDBMgr::GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT)
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

BOOL MaxFWDBMgr::GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT)
{
	BOOL		bRetValue = FALSE;
	TCHAR		szOut[MAX_PATH] = {0x00};		

	if (pszAnsiIN == NULL || pszUnicodeOUT == NULL)
	{
		return bRetValue;
	}

	//int iRetLen =  MultiByteToWideChar(CP_ACP,WC_COMPOSITECHECK,pszUnicodeIN,_tcslen(pszUnicodeIN),szOut,MAX_PATH,NULL,NULL);
	int iRetLen =  MultiByteToWideChar(CP_ACP,0,pszAnsiIN,strlen(pszAnsiIN),szOut,MAX_PATH);

	if (iRetLen > 0x00)
	{
		_tcscpy(pszUnicodeOUT,szOut);
	}

	return bRetValue;
}

BOOL MaxFWDBMgr::AllocMemory2DB(LPFIREWALL_DB_DATA *pDBinMemory)
{
	*pDBinMemory = new FIREWALL_DB_DATA;
	memset(*pDBinMemory,0x00,sizeof(FIREWALL_DB_DATA));

	return TRUE;
}

BOOL MaxFWDBMgr::LoadDatabase(LPCTSTR pszDBPath, LPCTSTR pszUserDBPath)
{
	strcpy(m_szFwDBPath,"");
	GetAnsiString(pszDBPath,&m_szFwDBPath[0x00]);

	if (strlen(m_szFwDBPath) <= 0x00)
	{
		return FALSE;
	}
	
	if (pszUserDBPath != NULL)
	{
		strcpy(m_szUserDBPath,"");
		GetAnsiString(pszUserDBPath,&m_szUserDBPath[0x00]);
		if (strlen(m_szUserDBPath) <= 0x00)
		{
			return FALSE;
		}
		m_pUserSqliteWrap = new CSqliteWrap(m_szUserDBPath);
		m_pUserSqliteWrap->OpenDatabase(m_szUserDBPath);
	}

	m_pSqliteWrap = new CSqliteWrap(m_szFwDBPath);

	m_pSqliteWrap->OpenDatabase(m_szFwDBPath);

	/*
	FIREWALL_DB_DATA	objPornSites = {0x00};
	LoadDBInMemory("pornSites",&objPornSites);
	*/


	AllocMemory2DB(&m_pBlackList);
	AllocMemory2DB(&m_pWhiteList);
	AllocMemory2DB(&m_pUserBlackList);
	AllocMemory2DB(&m_pApplicationList);
	AllocMemory2DB(&m_pNetworkMonitor);
	AllocMemory2DB(&m_pIDSRules);

	AllocMemory2DB(&m_pPornSites);
	AllocMemory2DB(&m_pSocialNetwork);
	AllocMemory2DB(&m_pPaymentGateways);
	AllocMemory2DB(&m_pOnlienStores);
	AllocMemory2DB(&m_pWebMail);
	AllocMemory2DB(&m_pDrugs);
	AllocMemory2DB(&m_pWeapons);
	AllocMemory2DB(&m_pViolence);
	AllocMemory2DB(&m_pIllegalSoft);
	AllocMemory2DB(&m_pOnlineGaming);
	AllocMemory2DB(&m_pProxy);
	AllocMemory2DB(&m_pExpliciteLang);
	AllocMemory2DB(&m_pGambling);
	AllocMemory2DB(&m_pChatForums);

	m_pProcRuleMgr  = new CProcessRuleMgr(m_pApplicationList);
	
	//LoadDBInMemory(m_pSqliteWrap, "PornSites",m_pPornSites);

	
	LoadDBInMemory(m_pUserSqliteWrap, "BlockWebSites",m_pUserBlackList);

	LoadDBInMemory(m_pSqliteWrap, "BlockWebsites",m_pBlackList);
	LoadDBInMemory(m_pSqliteWrap, "WhiteList",m_pWhiteList);
	LoadDBInMemory(m_pSqliteWrap, "ApplicationRule",m_pApplicationList);
	LoadDBInMemory(m_pSqliteWrap, "NetworkMonitor",m_pNetworkMonitor);
	LoadDBInMemory(m_pSqliteWrap, "idsip",m_pIDSRules);
	
	LoadDBInMemory(m_pSqliteWrap, "PornSites",m_pPornSites);
	LoadDBInMemory(m_pSqliteWrap, "SocialSites",m_pSocialNetwork);
	LoadDBInMemory(m_pSqliteWrap, "PaymentGateways",m_pPaymentGateways);
	LoadDBInMemory(m_pSqliteWrap, "OnlineStores",m_pOnlienStores);
	LoadDBInMemory(m_pSqliteWrap, "WebMails",m_pWebMail);
	LoadDBInMemory(m_pSqliteWrap, "Drugs",m_pDrugs);
	LoadDBInMemory(m_pSqliteWrap, "Weapons",m_pWeapons);
	LoadDBInMemory(m_pSqliteWrap, "Violence",m_pViolence);
	LoadDBInMemory(m_pSqliteWrap, "IllegalSoft",m_pIllegalSoft);
	LoadDBInMemory(m_pSqliteWrap, "OnlineGames",m_pOnlineGaming);
	LoadDBInMemory(m_pSqliteWrap, "ProxyServ",m_pProxy);
	LoadDBInMemory(m_pSqliteWrap, "ExpliciteLang",m_pExpliciteLang);
	LoadDBInMemory(m_pSqliteWrap, "Gambling",m_pGambling);
	LoadDBInMemory(m_pSqliteWrap, "ChatForums",m_pChatForums);
	
	m_pSqliteWrap->GetCommonRules(&m_FWCommonRules);
	if (m_pUserSqliteWrap != NULL)
	{
		m_pUserSqliteWrap->GetUserCategories(&m_ParentalCntrlRules);
		IsCompBlockingON();
		IsInternetBlockingON();
	}

	GetNetworkSettings(&m_NetworkSettings);
		
	return TRUE;
}

BOOL MaxFWDBMgr::UnloadMemDB(LPFIREWALL_DB_DATA pDBinMemory)
{
	if (pDBinMemory != NULL)
	{
		int	i = 0x00;
		if (pDBinMemory->dwRuleCnt > 0x00 && pDBinMemory->pRuleList != NULL)
		{
			for( i = 0x00; i < pDBinMemory->dwRuleCnt; i++)
			{
				free((void *)pDBinMemory->pRuleList[i]);
				pDBinMemory->pRuleList[i] = NULL;
			}
			free((void *)pDBinMemory->pRuleList);
			pDBinMemory->pRuleList = NULL;
		}

		if (pDBinMemory->dwKeyWordCnt > 0x00 && pDBinMemory->pKeyWordList != NULL)
		{
			for( i = 0x00; i < pDBinMemory->dwKeyWordCnt; i++)
			{
				free((void *)pDBinMemory->pKeyWordList[i]);
				pDBinMemory->pKeyWordList[i] = NULL;
			}
			free((void *)pDBinMemory->pKeyWordList);
			pDBinMemory->pKeyWordList = NULL;
		}
	}
	free(pDBinMemory);
	pDBinMemory = NULL;

	return TRUE;
}

BOOL MaxFWDBMgr::UnloadDatabase()
{
	BOOL	bRetValue = FALSE;
	if (m_pSqliteWrap)
	{
		bRetValue = m_pSqliteWrap->CloseDatabase();
		delete m_pSqliteWrap;
		m_pSqliteWrap = NULL;

		bRetValue = TRUE;
	}

	if (m_pUserSqliteWrap)
	{
		bRetValue = m_pUserSqliteWrap->CloseDatabase();
		delete m_pUserSqliteWrap;
		m_pUserSqliteWrap = NULL;

		bRetValue = TRUE;
	}

	UnloadMemDB(m_pBlackList);
	UnloadMemDB(m_pWhiteList);
	UnloadMemDB(m_pUserBlackList); 
	UnloadMemDB(m_pApplicationList);
	UnloadMemDB(m_pNetworkMonitor);
	UnloadMemDB(m_pIDSRules);

	UnloadMemDB(m_pPornSites);
	UnloadMemDB(m_pSocialNetwork);
	UnloadMemDB(m_pPaymentGateways);
	UnloadMemDB(m_pOnlienStores);
	UnloadMemDB(m_pWebMail);
	UnloadMemDB(m_pDrugs);
	UnloadMemDB(m_pWeapons);
	UnloadMemDB(m_pViolence);
	UnloadMemDB(m_pIllegalSoft);
	UnloadMemDB(m_pOnlineGaming);
	UnloadMemDB(m_pProxy);
	UnloadMemDB(m_pExpliciteLang);
	UnloadMemDB(m_pGambling);
	UnloadMemDB(m_pChatForums);

	memset(&m_FWCommonRules,0x00,sizeof(FW_COMMON_RULES));
	memset(&m_ParentalCntrlRules,0x00,sizeof(PC_CATEGORIES));
	memset(&m_InterNetUsageBlock,0x00,sizeof(INT_COMP_USAGE_BLOCK)); 
	memset(&m_ComputerUsageBlock,0x00,sizeof(INT_COMP_USAGE_BLOCK)); 

	return bRetValue;
}

int	MaxFWDBMgr::LoadDBInMemory(CSqliteWrap *pSqlAgent, LPCSTR pszTableName, LPFIREWALL_DB_DATA pDBinMemory)
{
	int		iRetValue = 0x00;
	BOOL	bStatus = FALSE;
	char	szDBEntry[MAX_PATH] = {0x00};

	if (pSqlAgent == NULL || pszTableName == NULL || pDBinMemory == NULL)
	{
		return iRetValue; 
	}

	if (pSqlAgent->m_bDBLoaded == FALSE)
	{
		return iRetValue;
	}

	int	iUrlCnt = 0x00, iKeyWordCnt = 0x00;
	int	iRuleCount = pSqlAgent->GetCountTableEntries(pszTableName,iUrlCnt);
	iKeyWordCnt = iRuleCount - iUrlCnt;

	if (iRuleCount <= 0x00 || iKeyWordCnt < 0x00)
	{
		return iRetValue;
	}

	pDBinMemory->pRuleList = (char **)calloc(iUrlCnt,sizeof(char *));
	if (iKeyWordCnt > 0x00)
	{
		pDBinMemory->pKeyWordList = (char **)calloc(iKeyWordCnt,sizeof(char *));
	}

	memset(&pDBinMemory->iChrIndex[0x00],-1,sizeof(int) * 26);

	bStatus = pSqlAgent->GetAllTableEntries(pszTableName,&szDBEntry[0x00]);
	while(bStatus)
	{
		strlwr(szDBEntry);
		
		if (strstr(szDBEntry,".") != NULL)
		{
			if (szDBEntry[0x00] >= 'a' && szDBEntry[0x00] <= 'z')
			{
				if (pDBinMemory->iChrIndex[szDBEntry[0x00] - 'a'] < 0)
				{
					pDBinMemory->iChrIndex[szDBEntry[0x00] - 'a'] = pDBinMemory->dwRuleCnt;
				}
			}
			pDBinMemory->pRuleList[pDBinMemory->dwRuleCnt] = (char *)calloc(strlen(szDBEntry) + 0x01,sizeof(char));
			strcpy(pDBinMemory->pRuleList[pDBinMemory->dwRuleCnt],szDBEntry);
			pDBinMemory->dwRuleCnt++;
		}
		else
		{
			pDBinMemory->pKeyWordList[pDBinMemory->dwKeyWordCnt] = (char *)calloc(strlen(szDBEntry) + 0x01,sizeof(char));
			strcpy(pDBinMemory->pKeyWordList[pDBinMemory->dwKeyWordCnt],szDBEntry);
			pDBinMemory->dwKeyWordCnt++;
		}
		
		iRetValue++;

		strcpy(&szDBEntry[0x00],"");
		bStatus = pSqlAgent->GetAllTableEntries(pszTableName,&szDBEntry[0x00]);
	}

	return iRetValue;
}


int	MaxFWDBMgr::SearchInMemDB(LPFIREWALL_DB_DATA pDBinMemory, LPCSTR pszBuff2Search, BOOL bDoContainSearch, BOOL bCheckSubDomain)
{
	int		iStart = 0x00, iEnd = 0x00;
	int		iFoundinDB = 0x00;
	char	szAnsiLogLine[1024] = {0x00};
	TCHAR	szLogLine[1024] = {0x00};

	if (pDBinMemory == NULL)
	{
		return 0x00;
	}
	if (pDBinMemory->dwRuleCnt == 0x00 && pDBinMemory->dwKeyWordCnt == 0x00)
	{
		return 0x00;
	}

	//if (bDoContainSearch == TRUE)
	{
		//AddLogEntry(L"FIREWALL >>>> CONTENT SEARCH ON");
		if (pDBinMemory->dwKeyWordCnt > 0x00)
		{
			for (int i = 0x00 ; i < pDBinMemory->dwKeyWordCnt; i++)
			{
				//if (strlen(pszBuff2Search) < strlen(pDBinMemory->pKeyWordList[i]))
				{
					if (strstr(pszBuff2Search,pDBinMemory->pKeyWordList[i]) != NULL)
					{
						iFoundinDB = i + 0x01;
						sprintf(szAnsiLogLine,"FIREWALL >>>> CONTENT MATCHED [%d] : %s",iFoundinDB,pDBinMemory->pKeyWordList[i]);
						GetUnicodeString(szAnsiLogLine,szLogLine);
						return iFoundinDB;
					}
				}
			}	
		}
	}

	if (bCheckSubDomain == FALSE)
	{
		char	*pFirstChar = NULL;
		
		pFirstChar = (char *)pszBuff2Search;
		if (pFirstChar[0x00] < 'a')
		{
			iStart = 0x00;
			iEnd = pDBinMemory->iChrIndex[0x00]; //'a' Index;
		}
		else if (pFirstChar[0x00] >= 'z')
		{
			iStart = pDBinMemory->iChrIndex[0x19];
			iEnd = pDBinMemory->dwRuleCnt; //'a' Index;
		}
		else
		{
			iStart = pDBinMemory->iChrIndex[pFirstChar[0x00] - 'a'];
			iEnd = pDBinMemory->iChrIndex[(pFirstChar[0x00] - 'a') + 0x01]; //'a' Index;
		}
		
	}
	if (iStart < 0x00)
	{
		iStart = 0x00;
	}
	if (iEnd <= 0x00)
	{
		iEnd = pDBinMemory->dwRuleCnt;
	}

	for (int i = iStart ; i < iEnd; i++)
	{
		//if (strlen(pszBuff2Search) < strlen(pDBinMemory->pKeyWordList[i]))
		{
			if (strstr(pszBuff2Search,pDBinMemory->pRuleList[i]) != NULL)
			{
				iFoundinDB = i + 0x01;
				sprintf(szAnsiLogLine,"FIREWALL >>>> URL MATCHED [%d] : %s",iFoundinDB,pDBinMemory->pRuleList[i]);
				GetUnicodeString(szAnsiLogLine,szLogLine);
				return iFoundinDB;
			}
		}
	}
	
	return iFoundinDB;
}

int	MaxFWDBMgr::Search4MaxDownloadSite(LPCSTR pszInBuff)
{
	int	iRetValue = 0x00;

	if (pszInBuff == NULL)
	{
		return iRetValue;
	}

	if (strlen(pszInBuff) <= 0x00)
	{
		return iRetValue;
	}

	if( strstr(pszInBuff, "updateultraav.s3.amazonaws.com") != NULL || 
		strstr(pszInBuff, "132.148.148.183:82") != NULL || 
		strstr(pszInBuff, "192.") != NULL ||
		strstr(pszInBuff, "10.") != NULL ||
		strstr(pszInBuff, "172.") != NULL)
	{
		return 0x01;
	}

	return iRetValue;
}

int	MaxFWDBMgr::Search4Rules(LPCSTR pszInBuff, BOOL bDoContainSearch)
{
	int			iRetValue = 0x00;
	TCHAR		szLogLine[MAX_PATH] = {0x00};
	BOOL		bUrlSearch = bDoContainSearch;
	

	if (pszInBuff == NULL)
	{
		return iRetValue;
	}


	char		*pszBuff2Search = NULL;	
	CStringA	csBuffer(pszInBuff);

	//AddLogEntry(CA2T(pszInBuff));

	if (csBuffer.Find("http://",0) == 0x00)
	{
		csBuffer.Replace("http://","");
	}
	if (csBuffer.Find("https://",0) == 0x00)
	{
		csBuffer.Replace("https://","");
	}
	if (csBuffer.Find("www.",0) == 0x00)
	{
		csBuffer.Replace("www.","");
	}

	if (csBuffer.GetLength() <= 0x00)
	{
		return iRetValue;
	}

	pszBuff2Search = (char *)csBuffer.GetBuffer();
	csBuffer.ReleaseBuffer();
	
	if (bDoContainSearch)
	{
		if (Search4MaxDownloadSite(pszBuff2Search) > 0x00)
		{
			return 0x100;
		}
	}
	bDoContainSearch =  m_FWCommonRules.bContentSearch;

	if (m_FWCommonRules.bBlockAll == true)
	{


		/*
		if (Search4MaxDownloadSite(pszBuff2Search) > 0x00)
		{
			return 0x01;
		}
		*/
		if (m_FWCommonRules.bWhiteFiltering == true)
		{
			BOOL	bSubDomain = FALSE;
			if (m_FWCommonRules.bAllowSubDomain == true)
			{
				bSubDomain = TRUE;
			}
			iRetValue = SearchInMemDB(m_pWhiteList,pszBuff2Search,bDoContainSearch,bSubDomain);	
			if (iRetValue > 0x00)
			{
				return 0x01;
			}
			else
			{
				return 0x00;
			}
		}
		else
		{
			return 0x00;
		}
	}
	if (m_FWCommonRules.bBlockWebSites == true)
	{
		iRetValue = SearchInMemDB(m_pBlackList,pszBuff2Search,bDoContainSearch);
		if (iRetValue > 0x00)
		{
			return iRetValue;
		}
	}

	if(m_FWCommonRules.bAntiPhishing == true && bUrlSearch == TRUE)
	{
		char		*pszSite2Search = NULL;	
		int iPos = csBuffer.Find('/');
		if(iPos != -1)
		{
			csBuffer = csBuffer.Left(iPos);
		}
		pszSite2Search = (char *)csBuffer.GetBuffer();
		csBuffer.ReleaseBuffer();
		if (Check4WhiteUrl(pszSite2Search) == 0x00)
		{
			BOOL bRetVal =  GetReplyFromURL(pszSite2Search);
			AddURLAntiPhishStatus(pszSite2Search,bRetVal);
			if(bRetVal == TRUE)
			{
				iRetValue = 0x01;
				return iRetValue;
			}
		}
	}

	//NetworkMonitoring
	//NetworkMonitoring
	
	//Always Keep it Last
	if (m_ParentalCntrlRules.bParentalControl == false)
	{
		return iRetValue;
	}
	if (m_ParentalCntrlRules.bBlockWebSites == true)
	{
		iRetValue = SearchInMemDB(m_pUserBlackList,pszBuff2Search,bDoContainSearch);
		if (iRetValue > 0x00)
		{
			return iRetValue;
		}
	}

	if (m_ParentalCntrlRules.bCategoryBlocking == true)
	{
		if (m_ParentalCntrlRules.bWeapons == true)
		{
			iRetValue = SearchInMemDB(m_pWeapons,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
		if (m_ParentalCntrlRules.bViolence == true)
		{
			iRetValue = SearchInMemDB(m_pViolence,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}

		}
		if (m_ParentalCntrlRules.bIllegalSoft == true)
		{
			iRetValue = SearchInMemDB(m_pIllegalSoft,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}

		}
		if (m_ParentalCntrlRules.bExplicitLang == true)
		{
			iRetValue = SearchInMemDB(m_pExpliciteLang,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
		if (m_ParentalCntrlRules.bDrugs == true)
		{
			iRetValue = SearchInMemDB(m_pDrugs,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
		if (m_ParentalCntrlRules.bProxyServ == true)
		{
			iRetValue = SearchInMemDB(m_pProxy,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
		if (m_ParentalCntrlRules.bWebmails == true)
		{
			iRetValue = SearchInMemDB(m_pWebMail,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
		if (m_ParentalCntrlRules.bChatForums == true)
		{
			iRetValue = SearchInMemDB(m_pChatForums,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
		if (m_ParentalCntrlRules.bOnlineStores == true)
		{
			iRetValue = SearchInMemDB(m_pOnlienStores,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
		if (m_ParentalCntrlRules.bOnlineGames == true)
		{
			iRetValue = SearchInMemDB(m_pOnlineGaming,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
		if (m_ParentalCntrlRules.bOnlinePaymenst == true)
		{
			iRetValue = SearchInMemDB(m_pPaymentGateways,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
		if (m_ParentalCntrlRules.bSocialSites == true)
		{
			iRetValue = SearchInMemDB(m_pSocialNetwork,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
		if (m_ParentalCntrlRules.bGambling == true)
		{
			iRetValue = SearchInMemDB(m_pGambling,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
		if (m_ParentalCntrlRules.bPornSites == true)
		{
			iRetValue = SearchInMemDB(m_pPornSites,pszBuff2Search,bDoContainSearch);
			if (iRetValue > 0x00)
			{
				return iRetValue;
			}
		}
	}
	
	return iRetValue;
}

int	MaxFWDBMgr::GetWhiteListCount()
{
	int		iRetCnt = 0x00;
	if (m_pWhiteList != NULL)
	{
		iRetCnt = m_pWhiteList->dwRuleCnt + m_pWhiteList->dwKeyWordCnt;
	}

	return iRetCnt;
}

int	MaxFWDBMgr::GetBlackListCount()
{
	int		iRetCnt = 0x00;
	if (m_pBlackList != NULL)
	{
		iRetCnt = m_pBlackList->dwRuleCnt + m_pBlackList->dwKeyWordCnt;
	}

	return iRetCnt;
}

BOOL MaxFWDBMgr::GetNetworkSettings(LPNETWORK_FILTER_SETTINGS pNetworkSettings)
{
	if (pNetworkSettings == NULL)
	{
		return FALSE;
	}
	pNetworkSettings->bNetworkMonitor = m_FWCommonRules.bNetworkMonitor;
	pNetworkSettings->bNetworkFilter = m_FWCommonRules.bNetworkFilter;
	pNetworkSettings->bDHCP = m_FWCommonRules.bDHCP;
	pNetworkSettings->bDNS = m_FWCommonRules.bDNS;
	pNetworkSettings->bFTP = m_FWCommonRules.bFTP;
	pNetworkSettings->bICMP = m_FWCommonRules.bICMP;
	pNetworkSettings->bIGMP = m_FWCommonRules.bIGMP;
	pNetworkSettings->bKerbores = m_FWCommonRules.bKerbores;
	pNetworkSettings->bLDAP = m_FWCommonRules.bLDAP;
	pNetworkSettings->bNetBios = m_FWCommonRules.bNetBios;
	pNetworkSettings->bVPN = m_FWCommonRules.bVPN;

}

BOOL MaxFWDBMgr::CheckProcInAppRule(DWORD dwProcID)
{
	BOOL	bFound = FALSE;

	if (m_FWCommonRules.bApplicationRule == true)
	{
		bFound = m_pProcRuleMgr->CheckProcessInBlockList(dwProcID);
	}

	return bFound;
}
/*
BOOL MaxFWDBMgr::CheckProcSuricata(DWORD dwProcID)
{
	BOOL	bFound = FALSE;

	if (m_pProcRuleMgr->m_dwSuricataProcID == dwProcID)
	{
		return TRUE;
	}
	if (m_pProcRuleMgr->m_dwSuricataProcID == 0)
	{
		bFound = m_pProcRuleMgr->Check4SuricataProc(dwProcID);
	}
	
	return bFound;
}
*/
BOOL MaxFWDBMgr::CheckIDSIPAddress(LPCTSTR pszIPAdrs)
{
	BOOL	bFound = FALSE;
	char	szIPAddress[MAX_PATH] = {0x00};
	TCHAR	szLogLine[MAX_PATH] = {0x00};	

	if (pszIPAdrs == NULL)
	{
		return bFound;
	}

	if (m_FWCommonRules.bIDSRules == false)
	{
		return bFound;
	}

	if (m_pIDSRules == NULL)
	{
		return bFound;
	}
	
	if (m_pIDSRules->dwRuleCnt == 0x00)
	{
		return bFound;
	}

	GetAnsiString(pszIPAdrs,&szIPAddress[0x00]);

	if (strlen(szIPAddress) == 0x00)
	{
		return bFound;
	}

	for (int i = 0x00;  i < m_pIDSRules->dwRuleCnt; i++)
	{
		if (strstr(szIPAddress,m_pIDSRules->pRuleList[i]) != NULL)
		{
			return TRUE;
		}
	}

	return bFound;
}

BOOL MaxFWDBMgr::CheckIPAddress(LPCTSTR pszIPAdrswithPort)
{
	BOOL	bFound = FALSE;
	char	szIPAddress[MAX_PATH] = {0x00};
	TCHAR	szLogLine[MAX_PATH] = {0x00};	

	if (pszIPAdrswithPort == NULL)
	{
		return bFound;
	}

	if (m_FWCommonRules.bNetworkMonitor == false)
	{
		return bFound;
	}
	
	if (m_pNetworkMonitor == NULL)
	{
		return bFound;
	}
	
	if (m_pNetworkMonitor->dwRuleCnt == 0x00)
	{
		return bFound;
	}

	char	szFullBlock[20] = {0x00};
	char	szCurrentSet[20] = {0x00};

	GetAnsiString(pszIPAdrswithPort,&szIPAddress[0x00]);

	if (strlen(szIPAddress) == 0x00)
	{
		return bFound;
	}


	sprintf(szCurrentSet,"%s",szIPAddress);
	char	*pszColn = NULL;

	pszColn = strrchr(szIPAddress,':');
	if (pszColn != NULL)
	{
		*pszColn = '\0';
		pszColn = NULL;
	}
	sprintf(szFullBlock,"%s:0",szIPAddress);

	for (int i = 0x00;  i < m_pNetworkMonitor->dwRuleCnt; i++)
	{
		if (strstr(szFullBlock,m_pNetworkMonitor->pRuleList[i]) != NULL)
		{
			return TRUE;
		}
		if (strstr(szCurrentSet,m_pNetworkMonitor->pRuleList[i]) != NULL)
		{
			return TRUE;
		}
	}

	return bFound;
}

BOOL MaxFWDBMgr::GetUserCategories()
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	return m_pUserSqliteWrap->GetUserCategories(&m_ParentalCntrlRules);
}

BOOL MaxFWDBMgr::GetUserCategories(LPPC_CATEGORIES pCatStruct)
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	return m_pUserSqliteWrap->GetUserCategories(pCatStruct);
}

BOOL MaxFWDBMgr::SetUserCategories()
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	return m_pUserSqliteWrap->SetUserCategories(&m_ParentalCntrlRules);
}

BOOL MaxFWDBMgr::SetUserCategories(LPPC_CATEGORIES pCatStruct)
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	return m_pUserSqliteWrap->SetUserCategories(pCatStruct);
}

BOOL MaxFWDBMgr::GetCommonRules()
{
	if (m_pSqliteWrap == NULL)
	{
		return FALSE;
	}
	return m_pSqliteWrap->GetCommonRules(&m_FWCommonRules);
}

BOOL MaxFWDBMgr::GetCommonRules(LPFW_COMMON_RULES pRulesStruct)
{
	if (m_pSqliteWrap == NULL)
	{
		return FALSE;
	}
	return m_pSqliteWrap->GetCommonRules(pRulesStruct);
}

BOOL MaxFWDBMgr::SetCommonRules()
{
	if (m_pSqliteWrap == NULL)
	{
		return FALSE;
	}
	return m_pSqliteWrap->SetCommonRules(&m_FWCommonRules);
}

BOOL MaxFWDBMgr::SetCommonRules(LPFW_COMMON_RULES pRulesStruct)
{
	if (m_pSqliteWrap == NULL)
	{
		return FALSE;
	}
	return m_pSqliteWrap->SetCommonRules(pRulesStruct);
}

BOOL  MaxFWDBMgr::IsInternetBlockingON(bool &bWeekDays,bool &bWeekEnds,LPSTR	pszWeekDays,LPSTR	pszWeekEnds)
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	return m_pUserSqliteWrap->IsInternetBlockingON(bWeekDays, bWeekEnds, pszWeekDays, pszWeekEnds);
}
BOOL  MaxFWDBMgr::IsCompBlockingON(bool &bWeekDays,bool &bWeekEnds,LPSTR	pszWeekDays,LPSTR	pszWeekEnds)
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}

	return m_pUserSqliteWrap->IsCompBlockingON(bWeekDays, bWeekEnds, pszWeekDays, pszWeekEnds);
}

BOOL  MaxFWDBMgr::IsInternetBlockingON(bool &bWeekDays,bool &bWeekEnds,LPTSTR	pszWeekDays,LPTSTR	pszWeekEnds)
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	char	szWeekDays[MAX_PATH] = {0x00};
	char	szWeekEnds[MAX_PATH] = {0x00};
	BOOL	bRet = FALSE;
	bRet = m_pUserSqliteWrap->IsInternetBlockingON(bWeekDays, bWeekEnds, szWeekDays, szWeekEnds);

	if (pszWeekDays)
	{
		GetUnicodeString(szWeekDays,pszWeekDays);
	}
	if (pszWeekDays)
	{
		GetUnicodeString(szWeekEnds,pszWeekEnds);
	}

	return bRet;
}



BOOL  MaxFWDBMgr::LoadHrsArray(LPINT_COMP_USAGE_BLOCK pUsageStruct)
{
	TCHAR	szDummy[MAX_PATH] = {0x00};
	TCHAR	*pCommaPos = NULL;
	int		iIndex = 23;

	_tcscpy(szDummy,pUsageStruct->szWeekDays);
	
	pCommaPos = _tcsrchr(szDummy,L';');
	while(pCommaPos)
	{
		if (_tcsstr(pCommaPos,L"1") != NULL)
		{
			pUsageStruct->intWeekDays[iIndex--] = 1;
		}
		else
		{
			pUsageStruct->intWeekDays[iIndex--] = 0;
		}

		*pCommaPos = L'\0';
		pCommaPos = NULL;	
		pCommaPos = _tcsrchr(szDummy,L';');
	}
	if (iIndex == 0x00)
	{
		if (_tcsstr(szDummy,L"1") != NULL)
		{
			pUsageStruct->intWeekDays[iIndex--] = 1;
		}
		else
		{
			pUsageStruct->intWeekDays[iIndex--] = 0;
		}
	}

	iIndex = 23;
	_tcscpy(szDummy,pUsageStruct->szWeekEnds);
	
	pCommaPos = _tcsrchr(szDummy,L';');
	while(pCommaPos)
	{
		if (_tcsstr(pCommaPos,L"1") != NULL)
		{
			pUsageStruct->intWeekEnds[iIndex--] = 1;
		}
		else
		{
			pUsageStruct->intWeekEnds[iIndex--] = 0;
		}

		*pCommaPos = L'\0';
		pCommaPos = NULL;	
		pCommaPos = _tcsrchr(szDummy,L';');
	}
	if (iIndex == 0x00)
	{
		if (_tcsstr(szDummy,L"1") != NULL)
		{
			pUsageStruct->intWeekDays[iIndex--] = 1;
		}
		else
		{
			pUsageStruct->intWeekDays[iIndex--] = 0;
		}
	}

	return TRUE;
}

BOOL  MaxFWDBMgr::IsCompBlockingON()
{	
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	char	szWeekDays[MAX_PATH] = {0x00};
	char	szWeekEnds[MAX_PATH] = {0x00};
	BOOL	bRet = FALSE;

	bRet = m_pUserSqliteWrap->IsCompBlockingON(m_ComputerUsageBlock.bWeekDays, m_ComputerUsageBlock.bWeekEnds, szWeekDays, szWeekEnds);

	GetUnicodeString(szWeekDays,m_ComputerUsageBlock.szWeekDays);
	GetUnicodeString(szWeekEnds,m_ComputerUsageBlock.szWeekEnds);
	m_ComputerUsageBlock.bIsBlockingON = bRet;

	LoadHrsArray(&m_ComputerUsageBlock);

	return bRet;
}
BOOL  MaxFWDBMgr::IsInternetBlockingON()
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	char	szWeekDays[MAX_PATH] = {0x00};
	char	szWeekEnds[MAX_PATH] = {0x00};
	BOOL	bRet = FALSE;

	bRet = m_pUserSqliteWrap->IsInternetBlockingON(m_InterNetUsageBlock.bWeekDays, m_InterNetUsageBlock.bWeekEnds, szWeekDays, szWeekEnds);

	GetUnicodeString(szWeekDays,m_InterNetUsageBlock.szWeekDays);
	GetUnicodeString(szWeekEnds,m_InterNetUsageBlock.szWeekEnds);
	m_InterNetUsageBlock.bIsBlockingON = bRet;

	LoadHrsArray(&m_InterNetUsageBlock);

	return bRet;
}

BOOL  MaxFWDBMgr::IsCompBlockingON(LPINT_COMP_USAGE_BLOCK pCompUsage)
{	
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	char	szWeekDays[MAX_PATH] = {0x00};
	char	szWeekEnds[MAX_PATH] = {0x00};
	BOOL	bRet = FALSE;

	bRet = m_pUserSqliteWrap->IsCompBlockingON(pCompUsage->bWeekDays, pCompUsage->bWeekEnds, szWeekDays, szWeekEnds);

	GetUnicodeString(szWeekDays,pCompUsage->szWeekDays);
	GetUnicodeString(szWeekEnds,pCompUsage->szWeekEnds);
	pCompUsage->bIsBlockingON = bRet;

	LoadHrsArray(pCompUsage);

	return bRet;
}
BOOL  MaxFWDBMgr::IsInternetBlockingON(LPINT_COMP_USAGE_BLOCK pInternetUsage)
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	char	szWeekDays[MAX_PATH] = {0x00};
	char	szWeekEnds[MAX_PATH] = {0x00};
	BOOL	bRet = FALSE;

	bRet = m_pUserSqliteWrap->IsInternetBlockingON(pInternetUsage->bWeekDays, pInternetUsage->bWeekEnds, szWeekDays, szWeekEnds);

	GetUnicodeString(szWeekDays,pInternetUsage->szWeekDays);
	GetUnicodeString(szWeekEnds,pInternetUsage->szWeekEnds);
	pInternetUsage->bIsBlockingON = bRet;

	LoadHrsArray(pInternetUsage);

	return bRet;
}

BOOL  MaxFWDBMgr::IsCompBlockingON(bool &bWeekDays,bool &bWeekEnds,LPTSTR	pszWeekDays,LPTSTR	pszWeekEnds)
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	char	szWeekDays[MAX_PATH] = {0x00};
	char	szWeekEnds[MAX_PATH] = {0x00};
	BOOL	bRet = FALSE;

	bRet = m_pUserSqliteWrap->IsCompBlockingON(bWeekDays, bWeekEnds, szWeekDays, szWeekEnds);

	if (pszWeekDays)
	{
		GetUnicodeString(szWeekDays,pszWeekDays);
	}
	if (pszWeekDays)
	{
		GetUnicodeString(szWeekEnds,pszWeekEnds);
	}
	return bRet;
}

BOOL  MaxFWDBMgr::SetInternetBloking()
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}

	int iBlockingON = 0x00, iWeekDays = 0x00, iWeekEnds = 0x00;

	iBlockingON = m_InterNetUsageBlock.bIsBlockingON?1:0;
	iWeekDays = m_InterNetUsageBlock.bWeekDays?1:0;
	iWeekEnds = m_InterNetUsageBlock.bWeekEnds?1:0;

	return m_pUserSqliteWrap->SetInternetBloking(iBlockingON, iWeekDays, iWeekEnds, m_InterNetUsageBlock.szWeekDays, m_InterNetUsageBlock.szWeekEnds);
}


BOOL  MaxFWDBMgr::SetInternetBloking(int iBlockingON, int iWeekDays, int iWeekEnds,LPCTSTR	pszWeekDays,LPCTSTR	pszWeekEnds)
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	return m_pUserSqliteWrap->SetInternetBloking(iBlockingON, iWeekDays, iWeekEnds, pszWeekDays, pszWeekEnds);
}

BOOL  MaxFWDBMgr::SetComputerBloking(int iBlockingON, int iWeekDays, int iWeekEnds,LPCTSTR	pszWeekDays,LPCTSTR	pszWeekEnds)
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}
	return m_pUserSqliteWrap->SetComputerBloking(iBlockingON, iWeekDays, iWeekEnds, pszWeekDays, pszWeekEnds);
}

BOOL  MaxFWDBMgr::SetComputerBloking()
{
	if (m_pUserSqliteWrap == NULL)
	{
		return FALSE;
	}

	int iBlockingON = 0x00, iWeekDays = 0x00, iWeekEnds = 0x00;

	iBlockingON = m_ComputerUsageBlock.bIsBlockingON?1:0;
	iWeekDays = m_ComputerUsageBlock.bWeekDays?1:0;
	iWeekEnds = m_ComputerUsageBlock.bWeekEnds?1:0;

	return m_pUserSqliteWrap->SetComputerBloking(iBlockingON, iWeekDays, iWeekEnds, m_ComputerUsageBlock.szWeekDays, m_ComputerUsageBlock.szWeekEnds);
}

BOOL  MaxFWDBMgr::IsUserDBPresent(LPTSTR pszUserName, LPTSTR pszDBFolderPath)
{
	return m_pSqliteWrap->IsUserDBPresent(pszUserName, pszDBFolderPath);
}

BOOL  MaxFWDBMgr::CreateUserDB(LPTSTR pszUserName, LPTSTR pszDBFolderPath,LPTSTR pszUserDBPath)
{
	return m_pSqliteWrap->CreateUserDB(pszUserName, pszDBFolderPath, pszUserDBPath);
}

BOOL  MaxFWDBMgr::DeleteUserDB(LPTSTR pszUserName, LPTSTR pszDBFolderPath)
{
	return m_pSqliteWrap->DeleteUserDB(pszUserName, pszDBFolderPath);
}

BOOL MaxFWDBMgr::UpdateFilterValue(LPCTSTR pszTable,LPCTSTR pszOldData,LPCTSTR pszNewData,BOOL bUserDBValue)
{
	if (bUserDBValue == TRUE)
	{
		return m_pUserSqliteWrap->UpdateFilterValue(pszTable, pszOldData, pszNewData);
	}
	else
	{
		return m_pSqliteWrap->UpdateFilterValue(pszTable, pszOldData, pszNewData);
	}
}

BOOL MaxFWDBMgr::DeleteFilterValue(LPCTSTR pszTable,LPCTSTR pszData,BOOL bUserDBValue)
{
	if (bUserDBValue == TRUE)
	{
		return m_pUserSqliteWrap->DeleteFilterValue(pszTable, pszData);
	}
	else
	{
		return m_pSqliteWrap->DeleteFilterValue(pszTable, pszData);
	}
}

BOOL MaxFWDBMgr::SetFilterValue(LPCTSTR pszTable,LPCTSTR pszData,BOOL bUserDBValue)
{
	if (bUserDBValue == TRUE)
	{
		return m_pUserSqliteWrap->SetFilterValue(pszTable, pszData);
	}
	else
	{
		return m_pSqliteWrap->SetFilterValue(pszTable, pszData);
	}
}

BOOL MaxFWDBMgr::GetAllEntries(LPCTSTR pszTable,LPFIREWALL_DB_DATA pDBinMem)
{
	TCHAR	szTableName[MAX_PATH] = {0x00};
	
	if (pszTable == NULL)
	{
		return FALSE;
	}

	_tcscpy(szTableName,pszTable);
	_tcslwr(szTableName);

	if (_tcsstr(pszTable,L"blockwebsites_user") != NULL)
	{
		pDBinMem = m_pUserBlackList;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"blockwebsites") != NULL)
	{
		pDBinMem = m_pBlackList;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"whitelist") != NULL)
	{
		pDBinMem = m_pWhiteList;
		return TRUE;	
	}
	if (_tcsstr(pszTable,L"applicationrule") != NULL)
	{
		pDBinMem = m_pApplicationList;
		return TRUE;		
	}
	if (_tcsstr(pszTable,L"networkmonitor") != NULL)
	{
		pDBinMem = m_pNetworkMonitor;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"pornsites") != NULL)
	{
		pDBinMem = m_pPornSites;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"socialsites") != NULL)
	{
		pDBinMem = m_pSocialNetwork;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"paymentgateways") != NULL)
	{
		pDBinMem = m_pPaymentGateways;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"onlinestores") != NULL)
	{
		pDBinMem = m_pOnlienStores;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"webmails") != NULL)
	{
		pDBinMem = m_pWebMail;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"drugs") != NULL)
	{
		pDBinMem = m_pDrugs;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"weapons") != NULL)
	{
		pDBinMem = m_pWeapons;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"violence") != NULL)
	{
		pDBinMem = m_pViolence;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"illegalsoft") != NULL)
	{
		pDBinMem = m_pIllegalSoft;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"onlinegames") != NULL)
	{
		pDBinMem = m_pOnlineGaming;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"proxyserv") != NULL)
	{
		pDBinMem = m_pProxy;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"explicitelang") != NULL)
	{
		pDBinMem = m_pExpliciteLang;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"gambling") != NULL)
	{
		pDBinMem = m_pGambling;
		return TRUE;
	}
	if (_tcsstr(pszTable,L"chatforums") != NULL)
	{
		pDBinMem = m_pChatForums;
		return TRUE;
	}

	return FALSE;
}

int	MaxFWDBMgr::ImportBulkDatafromFile(LPCTSTR pszTable,LPCTSTR pszFilePath, BOOL bUserData)
{
	int		iInsertCnt = 0x00;
	TCHAR	szLine[MAX_PATH] = {0x00};
	bool	bOnlyURLs = false; //Added to Handle No Key words for WhiteList Table

	if (pszTable == NULL || pszFilePath == NULL)
	{
		return iInsertCnt;
	}

	FILE	*fpInDB = NULL;
	TCHAR	*pFirstDot = NULL;
	
	fpInDB = _wfopen(pszFilePath,L"rt");
	if (NULL == fpInDB)
	{
		return iInsertCnt;
	}

	if (_tcsstr(pszTable,_T("WhiteList")) != NULL)
	{
		bOnlyURLs  = true;
	}

	while(!feof(fpInDB))
	{
		_tcscpy(szLine,L"");
		fgetws(szLine,MAX_PATH,fpInDB);
		int iLen = _tcslen(szLine);

		if (iLen > 0x00)
		{
			if (szLine[iLen - 0x01] == 0x0A)
			{
				szLine[iLen - 0x01] = '\0';
			}

		}
		if (_tcslen(szLine) > 0x00)
		{
			_tcslwr(szLine);

			if (bOnlyURLs == true)
			{
				if (_tcsstr(szLine,_T("www.")) == NULL && _tcsstr(szLine,_T(".")) == NULL)
				{
					continue;
				}
			}
			
			pFirstDot = NULL;
			pFirstDot = _tcsstr(szLine,L"www.");
			if (pFirstDot != NULL)
			{
				if (_tcslen(szLine) >= 0x04)
				{
					pFirstDot+=0x4;
					if (pFirstDot != NULL && _tcslen(pFirstDot) > 0x00)
					{
						if (SetFilterValue(pszTable,pFirstDot,bUserData))
						{
							iInsertCnt++;
						}
					}
				}
			}
			else
			{
				if (SetFilterValue(pszTable,szLine,bUserData))
				{
					iInsertCnt++;
				}
			}
		}
		else
		{
			break;
		}
	}
	fclose(fpInDB);
	fpInDB = NULL;

	return iInsertCnt;
}

BOOL MaxFWDBMgr::GetReplyFromURLEx(char *pczURL)
{
	m_hInternetSession = NULL;
	m_hHttpConnection = NULL;

	CString csCheckURL(pczURL);
	CString csAPI = L"";					//Check at the time of Firewall
	CString csURL = csAPI+csCheckURL;
	CString       csServer, csObject;
	DWORD         dwServiceType = 0;
	HINTERNET     hHttpFile = NULL;
	INTERNET_PORT nPort  = 0;
	DWORD dwSize;
	TCHAR szBuffer[MAX_PATH] = {0};
	BOOL bReturn = FALSE;
	
	try
	{
		if(!AfxParseURL(csURL, dwServiceType, csServer, csObject, nPort))
		{
			return bReturn;
		}

		if(!m_hInternetSession)
		{
			m_hInternetSession = ::InternetOpen(_T("Check"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);   
		}
		
		if(!m_hInternetSession)
		{
			return bReturn;
		}

		if(!m_hHttpConnection)
		{
			m_hHttpConnection = ::InternetConnect(m_hInternetSession, csServer, nPort, NULL,  NULL, INTERNET_SERVICE_HTTP, 0, NULL);
		}

		if(!m_hHttpConnection)
		{
			return bReturn;
		}

		LPCTSTR ppszAcceptTypes[2] = {0};

		DWORD dwFlags = INTERNET_NO_CALLBACK | INTERNET_FLAG_FORMS_SUBMIT | INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_PRAGMA_NOCACHE;

		if(dwServiceType == AFX_INET_SERVICE_HTTPS)
		{
			dwFlags	|= (INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID);
		}
		
		hHttpFile = ::HttpOpenRequest(m_hHttpConnection, NULL, csObject, NULL, NULL, ppszAcceptTypes, dwFlags, NULL);
		if(!hHttpFile)
		{
			return bReturn;
		}
		
		if(!::HttpSendRequest(hHttpFile, NULL, 0, NULL, 0))
		{
			DWORD dwError = ::GetLastError();

			InternetCloseHandle(hHttpFile);
			hHttpFile = NULL;

			return FALSE;
		}


		DWORD dwStatusCode = 0;
		dwSize = sizeof(DWORD);

		if(!::HttpQueryInfo(hHttpFile, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwSize, NULL))
		{
			InternetCloseHandle(hHttpFile);
			hHttpFile = NULL;

			return FALSE;
		}

		if(dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ || dwStatusCode == HTTP_STATUS_DENIED)
		{
			char szData[MAX_PATH] = {0};
			dwSize = 0;
			do 
			{
				::InternetReadFile(hHttpFile, szData, sizeof(szData), &dwSize);
			}while(dwSize != 0);
		}
		if(dwStatusCode == HTTP_STATUS_OK)
		{
			char szData[MAX_PATH] = {0};
			dwSize = 0;
			CString csReturnedData = _T("");
			if(!::InternetReadFile(hHttpFile, szData, sizeof(szData), &dwSize))
			{
				InternetCloseHandle(hHttpFile);
				hHttpFile = NULL;
				return bReturn;
			}
			if(dwSize != 0)
			{
				csReturnedData += CString(CStringA(szData));
				ZeroMemory(szData, MAX_PATH);
				csReturnedData.MakeLower();
				csReturnedData.Replace(L"\"",L"");
				csReturnedData.Replace(L"{",L"");
				csReturnedData.Replace(L"}",L"");
				csReturnedData.Replace(L"prediction:",L"");
				csReturnedData.Replace(L",url:",L"");
				csReturnedData.Replace(csCheckURL,L"");

				if(csReturnedData.Find(L"bad") != -1)
				{
						InternetCloseHandle(hHttpFile);
						hHttpFile = NULL;
						OutputDebugString(L"phishing detected");
						return TRUE;
				}
			}
			InternetCloseHandle(hHttpFile);
			hHttpFile = NULL;
			return bReturn;
		}
		InternetCloseHandle(hHttpFile);
		hHttpFile = NULL;
		return bReturn;
	}
	catch(...)
	{
		//AddLogEntry(CString(_T("Internet connection failed")));
	}

	if(hHttpFile)
	{
		InternetCloseHandle(hHttpFile);
	}
	hHttpFile = NULL;

	return bReturn;
}

BOOL MaxFWDBMgr::GetReplyFromURL(char *pczURL)
{
	//csURLPath = EncodeToUTF8(csURLPath);
	CString csURL = L"";				//Check at the time of Firewall
	CString       csServer, csObject;
	DWORD         dwServiceType = 0;
	HINTERNET     hHttpFile = NULL;
	INTERNET_PORT nPort  = 0;
	DWORD dwSize;
	TCHAR szBuffer[MAX_PATH] = {0};
	BOOL bReturn = FALSE;
	
	try
	{
		if(!AfxParseURL(csURL, dwServiceType, csServer, csObject, nPort))
		{
			return bReturn;
		}

		if(!m_hInternetSession)
		{
			m_hInternetSession = ::InternetOpen(_T("Check"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);   
		}
		
		if(!m_hInternetSession)
		{
			return bReturn;
		}

		if(!m_hHttpConnection)
		{
			m_hHttpConnection = ::InternetConnect(m_hInternetSession, csServer, nPort, NULL,  NULL, INTERNET_SERVICE_HTTP, 0, NULL);
		}

		if(!m_hHttpConnection)
		{
			return bReturn;
		}

		LPCTSTR ppszAcceptTypes[] = {_T("application/json"), NULL};  

		DWORD dwFlags = INTERNET_NO_CALLBACK | INTERNET_FLAG_FORMS_SUBMIT | INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_PRAGMA_NOCACHE;

		if(dwServiceType == AFX_INET_SERVICE_HTTPS)
		{
			dwFlags	|= (INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID);
		}
		
		hHttpFile = ::HttpOpenRequest(m_hHttpConnection, L"POST", csObject, NULL, NULL, ppszAcceptTypes, dwFlags, NULL);
		if(!hHttpFile)
		{
			return bReturn;
		}
		char szPath[1024]={0};
		sprintf(szPath,"{" 
			"    \"client\": {" 
			"      \"clientId\":      \"AURA\"," 
			"      \"clientVersion\": \"1.0.9\"" 
			"    }," 
			"    \"threatInfo\": {" 
			"      \"threatTypes\":      [\"MALWARE\", \"SOCIAL_ENGINEERING\"]," 
			"      \"platformTypes\":    [\"WINDOWS\"]," 
			"      \"threatEntryTypes\": [\"URL\"]," 
			"      \"threatEntries\": [" 
			"        {\"url\": \"%s\"}," 
			"      ]" 
			"    }" 
			"  }",pczURL);
		//Issue the request
		HttpAddRequestHeaders(hHttpFile, _T("Content-Type: application/json\r\n"), -1, HTTP_ADDREQ_FLAG_ADD);
		int iLen = strlen(szPath);
		if(!::HttpSendRequest(hHttpFile, NULL, 0, szPath, iLen))
		{
			InternetCloseHandle(hHttpFile);
			hHttpFile = NULL;
			return bReturn;
		}

		//Handle the status code in the response
		DWORD dwStatusCode = 0;
		dwSize = sizeof(DWORD);

		if(!::HttpQueryInfo(hHttpFile, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwSize, NULL))
		{
			InternetCloseHandle(hHttpFile);
			hHttpFile = NULL;
			return bReturn;
		}
		if(dwStatusCode == HTTP_STATUS_OK)
		{
			char szData[MAX_PATH] = {0};
			dwSize = 0;
			CString csReturnedData = _T("");
			if(!::InternetReadFile(hHttpFile, szData, sizeof(szData), &dwSize))
			{
				InternetCloseHandle(hHttpFile);
				hHttpFile = NULL;
				return bReturn;
			}
			if(dwSize != 0)
			{
				csReturnedData += CString(CStringA(szData));
				ZeroMemory(szData, MAX_PATH);
				csReturnedData.MakeLower();
				if(csReturnedData.Find(L"matches") != -1)
				{
						InternetCloseHandle(hHttpFile);
						hHttpFile = NULL;
						OutputDebugString(L"phishing detected");
						return TRUE;
				}
			}
			InternetCloseHandle(hHttpFile);
			hHttpFile = NULL;
			return bReturn;
		}
		InternetCloseHandle(hHttpFile);
		hHttpFile = NULL;
		return bReturn;
	}
	catch(...)
	{
	}

	if(hHttpFile)
	{
		InternetCloseHandle(hHttpFile);
	}
	hHttpFile = NULL;

	return bReturn;
}
BOOL MaxFWDBMgr::CreateNewTable(LPCTSTR pszTable, LPCTSTR pszColumnName)
{
	BOOL bRetVal = FALSE;

	if(m_pSqliteWrap->CreateNewTable(pszTable, pszColumnName))
	{
		bRetVal = TRUE;
	}

	return bRetVal;
}

BOOL MaxFWDBMgr::IsKeyExists(LPCTSTR pszTable, LPCTSTR pszColumnName)
{
	BOOL bRetVal = FALSE;

	if(m_pSqliteWrap->IsKeyExistsForIDS(pszTable, pszColumnName))
	{
		bRetVal = TRUE;
	}

	return bRetVal;
}
//0 : Not Found
//1 : Found : WHITE
//2 : Found : Phishing Site
int MaxFWDBMgr::Check4WhiteUrl(char *pczURL)
{
	BOOL	iReturn = 0x00;

	if (pczURL == NULL)
	{
		return iReturn;
	}

	if (strstr(pczURL,"safebrowsing.googleapis.com") != NULL || 
		strstr(pczURL,"accounts.google.com") != NULL || strstr(pczURL,".googleapis.com") != NULL || 
		strstr(pczURL,".windowsupdate.com") != NULL || strstr(pczURL,"google.com") != NULL ||
		strstr(pczURL,".googleusercontent.com") != NULL || strstr(pczURL,"googlesyndication.com") != NULL ||
		strstr(pczURL,".yooutube.com") != NULL || strstr(pczURL,"microsoft.com") != NULL ||
		strstr(pczURL,"mns.com") != NULL || strstr(pczURL,"bing.com") != NULL || strstr(pczURL,"/search?") != NULL ||
		(strstr(pczURL,"[") != NULL && strstr(pczURL,"::") != NULL))
	{
		iReturn = 0x01;
		return iReturn;
	}

	iReturn = GetURLAntiPhishStatus(pczURL);

	return iReturn;
}

//0 : Not Found in List
//1 : Found in List = WHITE
//2 : Found in List = BLACK
int	MaxFWDBMgr::GetURLAntiPhishStatus(char *pczURL)
{
	int		iReturn = 0x00;
	TCHAR	szLogLine[1024] = {0x00};

	if (m_dwAntiPhishingLstCnr == 0x00 || pczURL == NULL)
	{
		return iReturn;
	}

	for (int i = 0x00; i < m_dwAntiPhishingLstCnr; i++)
	{
		if (strstr(pczURL,pm_AntiPhishingLst[i].strUrl) != NULL)
		{
			_stprintf(szLogLine,L"FIREWALL : >>>> FOUND URL in List : %S",pczURL);

			if (pm_AntiPhishingLst[i].bStatus == FALSE)
			{
				iReturn = 0x01;
			}
			else
			{
				iReturn = 0x02;
			}
			break;
		}
	}

	

	return iReturn;
}

int	MaxFWDBMgr::AddURLAntiPhishStatus(char *pczURL, BOOL bStatus)
{
	int		iReturn = 0x00;
	TCHAR	szLogLine[1024] = {0x00};

	if (pczURL == NULL)
	{
		return iReturn;
	}

	if (m_dwAntiPhishingLstCnr >= 1024)
	{
		return iReturn;
	}

	if (m_dwAntiPhishingLstCnr == 0x00)
	{
		if (pm_AntiPhishingLst == NULL)
		{
			pm_AntiPhishingLst = new MAX_ANTI_PHISH_STATUS[1024];
		}
	}

	strcpy(pm_AntiPhishingLst[m_dwAntiPhishingLstCnr].strUrl,pczURL);
	pm_AntiPhishingLst[m_dwAntiPhishingLstCnr].bStatus = bStatus;

	m_dwAntiPhishingLstCnr++;

	return m_dwAntiPhishingLstCnr;
}

int	MaxFWDBMgr::AddNewConnection(DWORD dwConId, LPCTSTR pszRemoteIP, BOOL bBlock)
{
	int		iReturn = 0x00;
	TCHAR	szLogLine[1024] = {0x00};

	if (pszRemoteIP == NULL)
	{
		return iReturn;
	}

	if (m_dwConnectionLstCnt == 0x00)
	{
		if (pm_ConnectionList == NULL)
		{
			pm_ConnectionList = new MAX_CONNECTION_LIST[2048];
		}
	}

	if (m_dwConnectionLstCnt >= 2048)
	{
		m_dwConnectionLstCnt = 0x00;
	}
	if (m_dwConnectionLstCnt == 0x00)
	{
		_tcscpy(pm_ConnectionList[m_dwConnectionLstCnt].szIPAdr,pszRemoteIP);
		pm_ConnectionList[m_dwConnectionLstCnt].dwConID = dwConId;
		pm_ConnectionList[m_dwConnectionLstCnt].bBlock = bBlock;
		m_dwConnectionLstCnt++;
		return 0x01;
	}

	for (int i = 0x00; i <  m_dwConnectionLstCnt; i++)
	{
		if (pm_ConnectionList[i].dwConID == dwConId)
		{
			return 0x02; // Already Present
		}
	}

	_tcscpy(pm_ConnectionList[m_dwConnectionLstCnt].szIPAdr,pszRemoteIP);
	pm_ConnectionList[m_dwConnectionLstCnt].dwConID = dwConId;
	pm_ConnectionList[m_dwConnectionLstCnt].bBlock = bBlock;
	m_dwConnectionLstCnt++;

	TCHAR	szTemp[MAX_PATH] = {0x00},*pTemp = NULL;

	_tcscpy(szTemp,pszRemoteIP);

	pTemp = _tcsrchr(szTemp,L':');
	if (pTemp != NULL)
	{
		*pTemp = L'\0';
	}

	for (int i = 0x00; i <  m_dwConnectionLstCnt; i++)
	{
		if (_tcsstr(pm_ConnectionList[i].szIPAdr,szTemp) != NULL && pm_ConnectionList[i].bBlock == TRUE)
		{
			pm_ConnectionList[m_dwConnectionLstCnt].bBlock = TRUE;
			break;
		}
	}

	return 0x01;
}

int	MaxFWDBMgr::GetIPofConnection(DWORD dwConId, LPTSTR pszRemoteIP)
{
	int		iReturn = 0x00;
	TCHAR	szLogLine[1024] = {0x00};

	if (pszRemoteIP == NULL)
	{
		return iReturn;
	}
	
	for (int i = 0x00; i <  m_dwConnectionLstCnt; i++)
	{
		if (pm_ConnectionList[i].dwConID == dwConId)
		{
			pm_ConnectionList[i].bBlock = TRUE;
			_tcscpy(pszRemoteIP,pm_ConnectionList[i].szIPAdr);
		
			return 0x01;
		}
	}
	
	return iReturn;
}

int	MaxFWDBMgr::IsSusConnectionID(DWORD dwConId, LPTSTR pszRemoteIP)
{
	int		iReturn = 0x00;
	
	for (int i = 0x00; i <  m_dwConnectionLstCnt; i++)
	{
		if (pm_ConnectionList[i].dwConID == dwConId && pm_ConnectionList[i].bBlock == TRUE)
		{
			if (pszRemoteIP != NULL)
			{
				_tcscpy(pszRemoteIP,pm_ConnectionList[i].szIPAdr);
			}

			return 0x01;
		}
	}
	
	return iReturn;
}