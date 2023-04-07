#include "pch.h"
#include "ProcessRuleMgr.h"
#include <Psapi.h>

CProcessRuleMgr::CProcessRuleMgr(LPFIREWALL_DB_DATA	pAppRuleDB)
{
	m_dwProcListCnt = 0x00;
	m_dwRecursionCnt = 0x00;
	m_pApplicationRule = NULL;
	m_pApplicationRule = pAppRuleDB;

	memset(&m_ProcCacheList,0x00,(sizeof(PROCESS_CACHE_LIST) * 0x64));
	memset(&m_LastProcChecked,0x00,sizeof(PROCESS_CACHE_LIST));
	
}

CProcessRuleMgr::~CProcessRuleMgr(void)
{
	m_dwProcListCnt = 0x00;
	memset(&m_ProcCacheList,0x00,(sizeof(PROCESS_CACHE_LIST) * 0x64));
	memset(&m_LastProcChecked,0x00,sizeof(PROCESS_CACHE_LIST));
	m_pApplicationRule = NULL;
}

BOOL CProcessRuleMgr::GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT)
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

BOOL CProcessRuleMgr::CheckProcessInBlockList(DWORD dwProcID)
{
	BOOL	bFound = FALSE;
	char	szProcNameANS[512] = {0x00};

	if (dwProcID <= 0x08)
	{
		return bFound;
	}

	if (m_LastProcChecked.dwProcID == dwProcID)
	{
		return m_LastProcChecked.bBlock;
	}

	if (m_dwProcListCnt > 0x00)
	{
		for (int i = 0x00; i < m_dwProcListCnt; i++)
		{
			if (m_ProcCacheList[i].dwProcID == dwProcID)
			{
				m_LastProcChecked.dwProcID = m_ProcCacheList[i].dwProcID;
				strcpy(m_LastProcChecked.szProcName,"");
				strcpy(m_LastProcChecked.szProcName,m_ProcCacheList[i].szProcName);
				m_LastProcChecked.bBlock = m_ProcCacheList[i].bBlock;
				return m_ProcCacheList[i].bBlock;
			}
		}
	}

	if (m_pApplicationRule == NULL)
	{
		return bFound;
	}
	if (m_pApplicationRule->dwRuleCnt == 0x00)
	{
		return bFound;
	}

	HANDLE	hCurProc = NULL;

	hCurProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE, dwProcID);
	if (NULL != hCurProc)
	{
		TCHAR	szProcName[512] = {0x00};
		DWORD	dwLen = 512;
		

		DWORD dwRet = GetModuleFileNameEx(hCurProc,NULL,szProcName,dwLen);
		int	iError = GetLastError();
		if (_tcslen(szProcName) != 0x00)
		{
			GetAnsiString(&szProcName[0x00],&szProcNameANS[0x00]);
		}
	}
	if (strlen(szProcNameANS) == 0x00)
	{
		return bFound;
	}

	strlwr(szProcNameANS);

	char *pFileNameOnly = NULL;

	pFileNameOnly = strrchr(szProcNameANS,'\\');
	if (pFileNameOnly == NULL)
	{
		return bFound;
	}

	for (int i = 0x00; i < m_pApplicationRule->dwRuleCnt; i++)
	{
		if (strstr(pFileNameOnly,m_pApplicationRule->pRuleList[i]) != NULL)
		{
			bFound = true;
			break;
		}
	}

	m_LastProcChecked.dwProcID = dwProcID;
	strcpy(m_LastProcChecked.szProcName,szProcNameANS);
	m_LastProcChecked.bBlock = bFound;

	DWORD	dwInsertPos = 0x00;
	if (m_dwProcListCnt == 0x64)
	{
		if (m_dwRecursionCnt >= 0x64)
		{
			m_dwRecursionCnt = 0x00;
			dwInsertPos = 0x00;
		}
		dwInsertPos = m_dwRecursionCnt;
		m_dwRecursionCnt++;
	}
	else
	{
		dwInsertPos = m_dwProcListCnt;
		m_dwProcListCnt++;
	}

	m_ProcCacheList[dwInsertPos].dwProcID = dwProcID;
	strcpy(m_ProcCacheList[dwInsertPos].szProcName,szProcNameANS);
	m_ProcCacheList[dwInsertPos].bBlock = bFound;

	return bFound;
}