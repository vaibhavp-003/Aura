#pragma once

class CProcessRuleMgr
{
	PROCESS_CACHE_LIST		m_ProcCacheList[0x64];
	PROCESS_CACHE_LIST		m_LastProcChecked;
	DWORD					m_dwProcListCnt;
	DWORD					m_dwRecursionCnt;
	LPFIREWALL_DB_DATA		m_pApplicationRule;

	BOOL					GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT);

public:
	CProcessRuleMgr(LPFIREWALL_DB_DATA	pAppRuleDB = NULL);
	~CProcessRuleMgr(void);

	BOOL	CheckProcessInBlockList(DWORD dwProcID);
};
