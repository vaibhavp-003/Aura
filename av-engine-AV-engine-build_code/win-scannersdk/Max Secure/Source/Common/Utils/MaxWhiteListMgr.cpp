#include "pch.h"
#include "MaxWhiteListMgr.h"
#include "SDSystemInfo.h"
#include "Registry.h"
#include "MaxCommunicator.h"
#include "MaxPipes.h"


CMaxWhiteListMgr::CMaxWhiteListMgr(void)
	:m_objDBWhiteList(false), m_objDBAppBlockList(false),m_objDBAppExtList(false)
{
	m_objDBWhiteList.RemoveAll();
	m_objDBAppBlockList.RemoveAll();
	m_objDBAppExtList.RemoveAll();
	m_dwWhiteListEnable = 0;
	m_bAlreadyLoaded = false;
	m_csArrWhiteListEntries.RemoveAll();
	m_csArrAppBlockListEntries.RemoveAll();
	m_csArrAppExtListEntries.RemoveAll();
}

CMaxWhiteListMgr::~CMaxWhiteListMgr(void)
{
	m_bAlreadyLoaded = false;
	m_objDBWhiteList.RemoveAll();
	m_objDBAppBlockList.RemoveAll();
	m_objDBAppExtList.RemoveAll();
	m_csArrWhiteListEntries.RemoveAll();
	m_csArrAppBlockListEntries.RemoveAll();
	m_csArrAppExtListEntries.RemoveAll();
}
int CMaxWhiteListMgr::CheckWhiteList()
{
	CRegistry objReg;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("WhiteListEnable"), m_dwWhiteListEnable, HKEY_LOCAL_MACHINE);
	return m_dwWhiteListEnable;
}
void CMaxWhiteListMgr::LoadDB()
{
	m_objDBWhiteList.RemoveAll();
	m_objDBAppBlockList.RemoveAll();
	m_csArrWhiteListEntries.RemoveAll();
	m_csArrAppBlockListEntries.RemoveAll();
	
	CString csAppPath =  CSystemInfo::m_strAppPath;
	CString csApplicationPath = csAppPath +_T("Tools\\");
	if (m_objDBWhiteList.Load(csApplicationPath + WHITELIST_MGR_DB) == true)
	{
		LPVOID lpVoid = m_objDBWhiteList.GetFirst();
		while(lpVoid)
		{
			CString csPath;
			LPTSTR strKey = NULL;
			m_objDBWhiteList.GetKey(lpVoid, strKey);
			csPath = strKey; //GetSpyName(ulSpyName);
			m_csArrWhiteListEntries.Add(csPath);
			lpVoid = m_objDBWhiteList.GetNext(lpVoid);
		}		
	}
	if (m_objDBAppBlockList.Load(csApplicationPath + APPBLOCKLIST_MGR_DB) == true)
	{
		LPVOID lpVoid = m_objDBAppBlockList.GetFirst();
		while(lpVoid)
		{
			CString csPath;
			LPTSTR strKey = NULL;
			m_objDBAppBlockList.GetKey(lpVoid, strKey);
			csPath = strKey; //GetSpyName(ulSpyName);
			m_csArrAppBlockListEntries.Add(csPath);
			lpVoid = m_objDBAppBlockList.GetNext(lpVoid);
		}

	}
	
}
void CMaxWhiteListMgr::LoadExtDB()
{
	m_objDBWhiteList.RemoveAll();
	m_objDBAppExtList.RemoveAll();
	m_objDBAppBlockList.RemoveAll();
	m_csArrWhiteListEntries.RemoveAll();
	m_csArrAppExtListEntries.RemoveAll();
	m_csArrAppBlockListEntries.RemoveAll();
	CString csAppPath =  CSystemInfo::m_strAppPath;
	CString csApplicationPath = csAppPath +_T("Tools\\");
	if (m_objDBWhiteList.Load(csApplicationPath + WHITELIST_MGR_DB) == true)
	{
		LPVOID lpVoid = m_objDBWhiteList.GetFirst();
		while(lpVoid)
		{
			CString csPath;
			LPTSTR strKey = NULL;
			m_objDBWhiteList.GetKey(lpVoid, strKey);
			csPath = strKey; //GetSpyName(ulSpyName);
			m_csArrWhiteListEntries.Add(csPath);
			lpVoid = m_objDBWhiteList.GetNext(lpVoid);
		}		
	}
	if (m_objDBAppExtList.Load(csApplicationPath + APPEXTLIST_MGR_DB) == true)
	{
		LPVOID lpVoid = m_objDBAppExtList.GetFirst();
		while(lpVoid)
		{
			CString csPath;
			LPTSTR strKey = NULL;
			m_objDBAppExtList.GetKey(lpVoid, strKey);
			csPath = strKey; //GetSpyName(ulSpyName);
			m_csArrAppExtListEntries.Add(csPath);
			lpVoid = m_objDBAppExtList.GetNext(lpVoid);
		}

	}
	if (m_objDBAppBlockList.Load(csApplicationPath + APPBLOCKLIST_MGR_DB) == true)
	{
		LPVOID lpVoid = m_objDBAppBlockList.GetFirst();
		while(lpVoid)
		{
			CString csPath;
			LPTSTR strKey = NULL;
			m_objDBAppBlockList.GetKey(lpVoid, strKey);
			csPath = strKey; //GetSpyName(ulSpyName);
			m_csArrAppBlockListEntries.Add(csPath);
			lpVoid = m_objDBAppBlockList.GetNext(lpVoid);
		}

	}
	
}

void CMaxWhiteListMgr::LoadExtDBEx()
{
	m_objDBAppExtList.RemoveAll();
	m_csArrAppExtListEntries.RemoveAll();
	CString csAppPath = CSystemInfo::m_strAppPath;
	CString csApplicationPath = csAppPath + _T("Tools\\");
	if (m_objDBAppExtList.Load(csApplicationPath + APPEXTLIST_MGR_DB) == true)
	{
		LPVOID lpVoid = m_objDBAppExtList.GetFirst();
		while (lpVoid)
		{
			CString csPath;
			LPTSTR strKey = NULL;
			m_objDBAppExtList.GetKey(lpVoid, strKey);
			csPath = strKey; //GetSpyName(ulSpyName);
			m_csArrAppExtListEntries.Add(csPath);
			lpVoid = m_objDBAppExtList.GetNext(lpVoid);
		}

	}

}
void CMaxWhiteListMgr::SaveDB()
{
	CString csAppPath =  CSystemInfo::m_strAppPath;
	CString csWhiteListPath = csAppPath + _T("Tools\\") + WHITELIST_MGR_DB;
	CString csAppBlockListPath = csAppPath + _T("Tools\\") + APPBLOCKLIST_MGR_DB;
	DeleteFile(csWhiteListPath);
	DeleteFile(csAppBlockListPath);
	if(m_objDBWhiteList.GetFirst())
	{
		m_objDBWhiteList.Balance();
		m_objDBWhiteList.Save(csWhiteListPath);
	}
	if(m_objDBAppBlockList.GetFirst())
	{
		m_objDBAppBlockList.Balance();
		m_objDBAppBlockList.Save(csAppBlockListPath);
	}
}
void CMaxWhiteListMgr::SaveExtDB()
{
	CString csAppPath =  CSystemInfo::m_strAppPath;
	CString csWhiteListPath = csAppPath + _T("Tools\\") + WHITELIST_MGR_DB;
	CString csExtListPath = csAppPath + _T("Tools\\") + APPEXTLIST_MGR_DB;
	CString csAppBlockListPath = csAppPath + _T("Tools\\") + APPBLOCKLIST_MGR_DB;
	DeleteFile(csWhiteListPath);
	DeleteFile(csExtListPath);
	DeleteFile(csAppBlockListPath);
	if(m_objDBWhiteList.GetFirst())
	{
		m_objDBWhiteList.Balance();
		m_objDBWhiteList.Save(csWhiteListPath);
	}
	if(m_objDBAppExtList.GetFirst())
	{
		m_objDBAppExtList.Balance();
		m_objDBAppExtList.Save(csExtListPath);
	}
	if(m_objDBAppBlockList.GetFirst())
	{
		m_objDBAppBlockList.Balance();
		m_objDBAppBlockList.Save(csAppBlockListPath);
	}
}
int CMaxWhiteListMgr::SearchDB(LPCTSTR pszPathSearch)
{
	if(!m_dwWhiteListEnable)
	{
		return MAX_WHITELIST_ALLOW;
	}
	//LPTSTR pszRetVal = NULL;
	/*if(m_objDBWhiteList.SearchItem(pszPathSearch,pszRetVal))
	{
		return MAX_WHITELIST_ALLOW;
	}
	if(m_objDBAppBlockList.SearchItem(pszPathSearch,pszRetVal))
	{
		return MAX_WHITELIST_BLOCK;
	}
	if(CheckIgnorePath(pszPathSearch))
	{
		return MAX_WHITELIST_ALLOW;
	}*/
	CString csSearchPath(pszPathSearch);
	if(IgnorePath(pszPathSearch))
	{
		return MAX_WHITELIST_ALLOW;
	}
	bool bFlag = false;
	for(int iPos = 0; iPos < m_csArrWhiteListEntries.GetCount(); iPos++)
	{
		if(csSearchPath.Find(m_csArrWhiteListEntries.GetAt(iPos)) != -1)
		{
			bFlag = true;
			break;
		}
	}
	if(bFlag)
	{
		return MAX_WHITELIST_ALLOW;
	}
	bFlag = false;
	for(int iPos = 0; iPos < m_csArrAppBlockListEntries.GetCount(); iPos++)
	{
		if(csSearchPath.Find(m_csArrAppBlockListEntries.GetAt(iPos)) != -1)
		{
			bFlag = true;
			break;
		}
	}
	if(bFlag)
	{
		return MAX_WHITELIST_BLOCK;
	}
	if(CheckIgnorePath(pszPathSearch))
	{
		return MAX_WHITELIST_ALLOW;
	}
	m_csArrAppBlockListEntries.Add(csSearchPath);
	m_objDBAppBlockList.AppendItem(pszPathSearch,_T("black"));
	SaveDB();
	return MAX_WHITELIST_BLOCK;
	
}
int CMaxWhiteListMgr::SearchDBForWhite(LPCTSTR pszPathSearch)
{
	/*if(!m_dwWhiteListEnable)
	{
		return MAX_WHITELIST_ALLOW;
	}*/

	CString csSearchPath(pszPathSearch);
	
	if(IgnorePath(pszPathSearch))
	{
		return MAX_WHITELIST_ALLOW;
	}
	bool bFlag = false;
	for(int iPos = 0; iPos < m_csArrWhiteListEntries.GetCount(); iPos++)
	{
		if(csSearchPath.Find(m_csArrWhiteListEntries.GetAt(iPos)) != -1)
		{
			bFlag = true;
			break;
		}
	}
	if(bFlag)
	{
		return MAX_WHITELIST_ALLOW;
	}
	if(csSearchPath.Find(_T("\\teamviewer\\")) != -1)
	{
		return MAX_WHITELIST_ALLOW;
	}

	
	return MAX_WHITELIST_BLOCK;
	
}
int CMaxWhiteListMgr::SearchDBExt(LPCTSTR pszExtSearch)
{
	//return MAX_WHITELIST_BLOCK;

	CString csExtPath(pszExtSearch);
	bool bFlag = false;
	for(int iPos = 0; iPos < m_csArrAppExtListEntries.GetCount(); iPos++)
	{
		if(csExtPath.Compare(m_csArrAppExtListEntries.GetAt(iPos)) == 0)
		{
			bFlag = true;
			break;
		}
	}
	if(bFlag)
	{
		return MAX_WHITELIST_BLOCK;
	}
	
	return MAX_WHITELIST_ALLOW;
	
}
bool CMaxWhiteListMgr::CheckIgnorePath(LPCTSTR pszPathSearch)
{
	CString csPathSearch(pszPathSearch);
	DWORD dwAttributes = GetFileAttributes(csPathSearch);
	if((dwAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
	{
		return true;
	}

	/*
	int iPos = csPathSearch.Find(_T("~"));
	if(iPos != -1)
	{
		TCHAR tcFilePath[1024] = {0};
		GetLongPathName(csPathSearch, tcFilePath, 1024);
		csPathSearch.Format(_T("%s"),tcFilePath);
		csPathSearch.MakeLower();
	}
	*/
	int iPos = 0x00;
	iPos = csPathSearch.ReverseFind('.');
	if(iPos != -1)
	{
		CString csTemp = csPathSearch.Mid(iPos);
		if(csTemp.Compare(_T(".manifest")) == 0)
		{
			return true;
		}
		else if(csTemp.Compare(_T(".config")) == 0)
		{
			return true;
		}
		else if(csTemp.Compare(_T(".dll")) == 0)
		{
			return true;
		}
	}
	
	CString csOwnFolder, csOwnFolderx86;
	csOwnFolder.Format(_T(":\\program files\\%s"),CSystemInfo::m_csInstallProdName);
	csOwnFolder.MakeLower();
	csOwnFolderx86.Format(_T(":\\program files (x86)\\%s"), CSystemInfo::m_csInstallProdName);
	csOwnFolderx86.MakeLower();
	if(csPathSearch.Find(_T(":\\windows\\")) != -1)
	{
		return true;
	}
	else if((csPathSearch.Find(csOwnFolder) != -1) || (csPathSearch.Find(csOwnFolderx86) != -1))
	{
		return true;
	}
	else if((csPathSearch.Find(_T(":\\program files\\internet explorer\\ieproxy.dll")) != -1)
		|| (csPathSearch.Find(_T(":\\program files (x86)\\internet explorer\\ieproxy.dll")) != -1))
	{
		return true;
	}
	else if((csPathSearch.Find(_T(":\\program files\\common files\\microsoft shared")) !=-1)
		|| (csPathSearch.Find(_T(":\\program files (x86)\\common files\\microsoft shared")) !=-1))
	{
		return true;
	}

	return false;
}
bool CMaxWhiteListMgr::IgnorePath(LPCTSTR pszPathSearch, BOOL bFSMonCall)
{
	CString csPathSearch(pszPathSearch);
	
	int iPos = csPathSearch.Find(_T("~"));
	if(iPos != -1)
	{
		TCHAR tcFilePath[1024] = {0};
		GetLongPathName(csPathSearch, tcFilePath, 1024);
		csPathSearch.Format(_T("%s"),tcFilePath);
		csPathSearch.MakeLower();
	}

	CString csOwnFolder, csOwnFolderx86;
	csOwnFolder.Format(_T(":\\program files\\%s"), CSystemInfo::m_csInstallProdName);
	csOwnFolder.MakeLower();
	csOwnFolderx86.Format(_T(":\\program files (x86)\\%s"), CSystemInfo::m_csInstallProdName);
	csOwnFolderx86.MakeLower();

	if((csPathSearch.Find(csOwnFolder) != -1) || (csPathSearch.Find(csOwnFolderx86) != -1))
	{
		return true;
	}
	else if((csPathSearch.Find(_T("\\teamviewer\\")) !=-1))
	{
		return true;
	}
	if (bFSMonCall == TRUE)
	{
		if((csPathSearch.Find(_T(":\\program files")) !=-1))
		{
			return true;
		}
	}
	return false;
}

bool CMaxWhiteListMgr::CheckAccessedFile(LPCTSTR pszFileAccessed,LPCTSTR pszProcName)
{
	bool	bRetValue = false;
	TCHAR	pszDummyProcName[1024] = {0x00},*pTemp = NULL;

	if (pszProcName != NULL)
	{
		_tcscpy(pszDummyProcName,pszProcName);
		pTemp = _tcsrchr(pszDummyProcName,L'\\');
		if (pTemp != NULL)
		{
			*pTemp = '\0';
			pTemp = NULL;
			if (_tcslen(pszDummyProcName) > 0x00)
			{
				pTemp = _tcsstr(pszDummyProcName,L":\\");
				if (pTemp)
				{
					pTemp++;
					if (_tcsstr(pszFileAccessed,pTemp) != NULL)
					{
						return true;
					}
				}
			}
		}
	}
	if(_tcsstr(pszFileAccessed,L"\\temp\\") != NULL /*||  _tcsstr(pszFileAccessed,L"\\appdata\\") != NULL*/)
	{
		//if (_tcsstr(pszFileAccessed,L"\\desktop\\") == NULL)
		{
			return true;
		}
	}
	
	return bRetValue;
}

int CMaxWhiteListMgr::SearchINBlackDB(LPCTSTR pszPathSearch,bool bSearchOnly)
{
	CString csSearchPath(pszPathSearch);
	bool bFlag = false;

	
	for(int iPos = 0; iPos < m_csArrAppBlockListEntries.GetCount(); iPos++)
	{
		if(csSearchPath.Find(m_csArrAppBlockListEntries.GetAt(iPos)) != -1)
		{
			bFlag = true;
			break;
		}
	}
	if(bFlag)
	{
		return MAX_WHITELIST_BLOCK;
	}
	if(!bSearchOnly)
	{
		m_csArrAppBlockListEntries.Add(csSearchPath);
		m_objDBAppBlockList.AppendItem(pszPathSearch,_T("black"));
		SaveDB();
		return MAX_WHITELIST_NEWBLOCK;
	}
	else
	{
		return MAX_WHITELIST_ALLOW;
	}
	return MAX_WHITELIST_NOTFOUND;
}

int CMaxWhiteListMgr::ManageShortPath(CString &csProcessPath,CString &csFilePath)
{
	int		iRevValue = 0x00;
	
	int iPos = csProcessPath.Find(_T("~"));
	if(iPos != -1)
	{
		TCHAR tcFilePath[1024] = {0};
		GetLongPathName(csProcessPath, tcFilePath, 1024);
		csProcessPath.Format(_T("%s"),tcFilePath);
		csProcessPath.MakeLower();
	}

	iPos = csFilePath.Find(_T("~"));
	if(iPos != -1)
	{
		TCHAR tcFilePath[1024] = {0};
		GetLongPathName(csFilePath, tcFilePath, 1024);
		if (_tcslen(tcFilePath) > 0x00)
		{
			csFilePath.Format(_T("%s"),tcFilePath);
		}
		csFilePath.MakeLower();
	}

	return iRevValue;
}

int CMaxWhiteListMgr::GetWhiteListedAppsCnt()
{
	int iWhtCnt = 0;
	iWhtCnt = m_objDBWhiteList.GetCount();
	return iWhtCnt;
}


int CMaxWhiteListMgr::GetBlackListedAppsCnt()
{
	int iBlkCnt = 0;
	iBlkCnt = m_objDBAppBlockList.GetCount();
	return iBlkCnt;
}

int CMaxWhiteListMgr::GetCryptExtCnt()
{
	int iExtCnt = 0;
	iExtCnt = m_objDBAppExtList.GetCount();
	return iExtCnt;
}


void CMaxWhiteListMgr::SetListedData(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize)
{

	m_objDBWhiteList.RemoveAll();
	for (int i = 0; i < iWhiteListedAppDataSize; i++)
	{
		CString csWApplicationPath = pWhiteListedAppData[i].szWhiteApplicationPath;
		csWApplicationPath.MakeLower();
		m_objDBWhiteList.AppendItem(csWApplicationPath, _T("white"));
		//m_objDBWhiteList.AppendItem(pWhiteListedAppData[i].szWhiteApplicationPath, _T("white"));
	}

	m_objDBAppBlockList.RemoveAll();
	for (int i = 0; i < iBlackListedAppDataSize; i++)
	{
		CString csBApplicationPath = pBlackListedAppData[i].szBlackApplicationPath;
		csBApplicationPath.MakeLower();
		//m_objDBAppBlockList.AppendItem(pBlackListedAppData[i].szBlackApplicationPath, _T("black"));
		m_objDBAppBlockList.AppendItem(csBApplicationPath, _T("black"));
	}

	SaveDB();

	PostMessageToService();

	PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RESTARTPROTECTION, ON);

}
void CMaxWhiteListMgr::GetListedData(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize)
{
	m_objDBWhiteList.RemoveAll();
	m_objDBAppBlockList.RemoveAll();
	m_csArrWhiteListEntries.RemoveAll();
	m_csArrAppBlockListEntries.RemoveAll();
	int iCnt = 0;
	CString csAppPath = CSystemInfo::m_strAppPath;
	CString csApplicationPath = csAppPath + _T("Tools\\");
	if (m_objDBWhiteList.Load(csApplicationPath + WHITELIST_MGR_DB) == true)
	{
		LPVOID lpVoid = m_objDBWhiteList.GetFirst();
		iCnt = 0;
		while (lpVoid)
		{
			CString csPath;
			LPTSTR strKey = NULL;
			m_objDBWhiteList.GetKey(lpVoid, strKey);
			csPath = strKey; //GetSpyName(ulSpyName);
			m_csArrWhiteListEntries.Add(csPath);
			lpVoid = m_objDBWhiteList.GetNext(lpVoid);
			wcscpy_s(pWhiteListedAppData[iCnt].szWhiteApplicationPath, csPath);
			iCnt++;
		}
	}
	if (m_objDBAppBlockList.Load(csApplicationPath + APPBLOCKLIST_MGR_DB) == true)
	{
		LPVOID lpVoid = m_objDBAppBlockList.GetFirst();
		iCnt = 0;
		while (lpVoid)
		{
			CString csPath;
			LPTSTR strKey = NULL;
			m_objDBAppBlockList.GetKey(lpVoid, strKey);
			csPath = strKey; //GetSpyName(ulSpyName);
			m_csArrAppBlockListEntries.Add(csPath);
			lpVoid = m_objDBAppBlockList.GetNext(lpVoid);
			wcscpy_s(pBlackListedAppData[iCnt].szBlackApplicationPath, csPath);
			iCnt++;
		}

	}
	
}

bool CMaxWhiteListMgr::PostMessageToServiceCrypt()
{
	CRegistry oReg;
	DWORD dwVal = 0;
	bool bResult = false;

	oReg.Get(CSystemInfo::m_csProductRegKey, FSMON_KEY, dwVal, HKEY_LOCAL_MACHINE);

	if (dwVal == 1)
	{

		SHARED_ACTMON_SWITCH_DATA sRequest = { 0 };
		sRequest.eProcType = FSMonitorRestart;
		sRequest.dwMonitorType = RESTARTPROTECTION;
		sRequest.bStatus = true;
		//CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_FSMONSERVICE, false);
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_TRAY_TO_ACTMON, false);		//cryptmon merged in actmon
		if (objMaxCommunicator.SendData(&sRequest, sizeof(SHARED_ACTMON_SWITCH_DATA)))
		{
			if (!objMaxCommunicator.ReadData((LPVOID)&sRequest, sizeof(SHARED_ACTMON_SWITCH_DATA)))
			{
				return bResult;
			}
			//wait broken so read the result.
			bResult = sRequest.bStatus;
		}
	}
	else
	{
		SHARED_ACTMON_SWITCH_DATA sRequest = { 0 };
		sRequest.eProcType = FSMonitorRestart;
		sRequest.dwMonitorType = PAUSEPROTECTION;
		sRequest.bStatus = false;
		////wcscpy_s(sRequest.strValue, szCommandLine);
		//CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_FSMONSERVICE, true);
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_TRAY_TO_ACTMON, true);		//cryptmon merged in actmon
		if (objMaxCommunicator.SendData(&sRequest, sizeof(SHARED_ACTMON_SWITCH_DATA)))
		{
			if (!objMaxCommunicator.ReadData((LPVOID)&sRequest, sizeof(SHARED_ACTMON_SWITCH_DATA)))
			{
				return bResult;
			}
			//wait broken so read the result.
			bResult = sRequest.bStatus;
		}
	}
	return bResult;
}
bool CMaxWhiteListMgr::PostMessageToService()
{
	CRegistry oReg;
	DWORD dwCryptMonitor = 0;
	oReg.Get(CSystemInfo::m_csProductRegKey, FSMON_KEY, dwCryptMonitor, HKEY_LOCAL_MACHINE);
	bool bResult = false;

	if (dwCryptMonitor == 1)
	{
		SHARED_ACTMON_SWITCH_DATA sRequest = { 0 };
		sRequest.eProcType = FSMonitorRestart;
		sRequest.dwMonitorType = RESTARTPROTECTION;
		sRequest.bStatus = true;
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_FSMONSERVICE, false);
		if (objMaxCommunicator.SendData(&sRequest, sizeof(SHARED_ACTMON_SWITCH_DATA)))
		{
			if (!objMaxCommunicator.ReadData((LPVOID)&sRequest, sizeof(SHARED_ACTMON_SWITCH_DATA)))
			{
				return bResult;
			}
			//wait broken so read the result.
			bResult = sRequest.bStatus;
		}
	}
	else
	{
		SHARED_ACTMON_SWITCH_DATA sRequest = { 0 };
		sRequest.eProcType = FSMonitorRestart;
		sRequest.dwMonitorType = PAUSEPROTECTION;
		sRequest.bStatus = false;
		////wcscpy_s(sRequest.strValue, szCommandLine);
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_FSMONSERVICE, false);
		if (objMaxCommunicator.SendData(&sRequest, sizeof(SHARED_ACTMON_SWITCH_DATA)))
		{
			if (!objMaxCommunicator.ReadData((LPVOID)&sRequest, sizeof(SHARED_ACTMON_SWITCH_DATA)))
			{
				return bResult;
			}
			//wait broken so read the result.
			bResult = sRequest.bStatus;
		}
	}
	return bResult;
}

bool CMaxWhiteListMgr::PostMessageToProtection(UINT WM_Message, UINT ActMon_Message, UINT uStatus)
{
	bool bReply = true;
	AM_MESSAGE_DATA amMsgData = { 0 };
	amMsgData.dwMsgType = WM_Message;
	amMsgData.dwProtectionType = ActMon_Message;
	amMsgData.bProtectionStatus = (BYTE)uStatus;
	CMaxCommunicator objComm(_NAMED_PIPE_ACTMON_TO_TRAY);
	if (objComm.SendData(&amMsgData, sizeof(AM_MESSAGE_DATA)))
	{
		if (!objComm.ReadData((LPVOID)&amMsgData, sizeof(AM_MESSAGE_DATA)))
		{
			return false;
		}
		//wait broken so read the result.
		bReply = (amMsgData.dwMsgType ? true : false);
	}
	return bReply;
}


void CMaxWhiteListMgr::GetExtListForCryptMon(CrptExtList* pCryptMonExt, int iCryptMonExtSize)
{
	int iCount = 0;
	LPVOID lpVoid = m_objDBAppExtList.GetFirst();
	while (lpVoid)
	{
		CString csPath;
		LPTSTR strKey = NULL;
		m_objDBAppExtList.GetKey(lpVoid, strKey);
		csPath = strKey; //GetSpyName(ulSpyName);
		lpVoid = m_objDBAppExtList.GetNext(lpVoid);
		wcscpy_s(pCryptMonExt[iCount].szCryptMonExt, csPath);
		iCount++;
	}
}


void CMaxWhiteListMgr::SetCryptMonDataIntoDB(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize, CrptExtList* pCryptMonExt, int iCryptMonExtSize)
{
	m_objDBWhiteList.RemoveAll();
	for (int i = 0; i < iWhiteListedAppDataSize; i++)
	{
		m_objDBWhiteList.AppendItem(pWhiteListedAppData[i].szWhiteApplicationPath, _T("white"));
	}

	m_objDBAppBlockList.RemoveAll();
	for (int i = 0; i < iBlackListedAppDataSize; i++)
	{
		m_objDBAppBlockList.AppendItem(pBlackListedAppData[i].szBlackApplicationPath, _T("black"));
	}

	m_objDBAppExtList.RemoveAll();
	for (int i = 0; i < iCryptMonExtSize; i++)
	{
		m_objDBAppExtList.AppendItem(pCryptMonExt[i].szCryptMonExt, _T("ext"));
	}

	SaveDB();

	PostMessageToServiceCrypt();

	PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RESTARTPROTECTION, ON);
}