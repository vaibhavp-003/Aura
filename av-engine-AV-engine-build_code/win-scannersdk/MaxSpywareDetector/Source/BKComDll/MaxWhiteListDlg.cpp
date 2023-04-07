#include "pch.h"
#include "MaxWhiteListDlg.h"
#include "MaxCommunicator.h"
#include "SDSystemInfo.h"
CMaxWhiteListDlg::CMaxWhiteListDlg()
{
	
}


CMaxWhiteListDlg::~CMaxWhiteListDlg()
{

}

int CMaxWhiteListDlg::GetWhiteListStatus()
{
	int iRetStatus = 0;

	iRetStatus = m_objMaxWhiteListMgr.CheckWhiteList();

	return iRetStatus;

}

void CMaxWhiteListDlg::SetWhiteListStatusEx(int iValue)
{
	CRegistry objReg;
	objReg.Set(CSystemInfo::m_csProductRegKey, _T("WhiteListEnable"), iValue, HKEY_LOCAL_MACHINE);

	/*
	m_objMaxWhiteListMgr.PostMessageToService();

	m_objMaxWhiteListMgr.PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RESTARTPROTECTION, ON);
	*/
	/*
	bool m_bWhiteList = m_objMaxWhiteListMgr.CheckWhiteList();

	if (!m_bWhiteList)
	{
		if (!objReg.ValueExists(CSystemInfo::m_csProductRegKey, _T("ShowWhiteListMsgEnable"), HKEY_LOCAL_MACHINE))
		{
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("ShowWhiteListMsgEnable"), 0x00, HKEY_LOCAL_MACHINE);
		}
		else
		{
			DWORD dwShowMsg;
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("ShowWhiteListMsgEnable"), dwShowMsg, HKEY_LOCAL_MACHINE);
			if (dwShowMsg == 0x00)
			{

			}

		}
	}
	*/
	
}

void CMaxWhiteListDlg::GetListedAppsCnt(int* ptrListedAppArrayCountArray)
{
	m_objMaxWhiteListMgr.LoadDB();
	int iWhiteListedCnt = m_objMaxWhiteListMgr.GetWhiteListedAppsCnt();
	int iBlackListedCnt = m_objMaxWhiteListMgr.GetBlackListedAppsCnt();

	ptrListedAppArrayCountArray[0] = iWhiteListedCnt;
	ptrListedAppArrayCountArray[1] = iBlackListedCnt;
}

void CMaxWhiteListDlg::FillListedApps(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize)
{
	m_objMaxWhiteListMgr.GetListedData(pWhiteListedAppData, iWhiteListedAppDataSize, pBlackListedAppData, iBlackListedAppDataSize);
}

void CMaxWhiteListDlg::SetListedAppsIntoDB(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize)
{
	m_objMaxWhiteListMgr.SetListedData(pWhiteListedAppData, iWhiteListedAppDataSize, pBlackListedAppData, iBlackListedAppDataSize);
}

int CMaxWhiteListDlg::GetCryptMonExtCnt()
{
	int iRetStatus; 0;
	m_objMaxWhiteListMgr.LoadExtDBEx();
	iRetStatus = m_objMaxWhiteListMgr.GetCryptExtCnt();
	return iRetStatus;
}

void CMaxWhiteListDlg::FillExtForCrypt(CrptExtList * pCryptMonExt, int iCryptMonExtSize)
{
	m_objMaxWhiteListMgr.GetExtListForCryptMon(pCryptMonExt, iCryptMonExtSize);
}


void CMaxWhiteListDlg::SetCryptMonDataIntoDB(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize, CrptExtList* pCryptMonExt, int iCryptMonExtSize)
{
	m_objMaxWhiteListMgr.SetCryptMonDataIntoDB(pWhiteListedAppData, iWhiteListedAppDataSize, pBlackListedAppData, iBlackListedAppDataSize, pCryptMonExt, iCryptMonExtSize);
}

int CMaxWhiteListDlg::GetCryptMonStatus()
{
	DWORD dwRetStatus = 0;
	CRegistry objReg;
	objReg.Get(CSystemInfo::m_csProductRegKey, FSMON_KEY, dwRetStatus, HKEY_LOCAL_MACHINE);
	return dwRetStatus;

}

void CMaxWhiteListDlg::SetCryptMonStatus(int iValue)
{
	CRegistry objReg;
	objReg.Set(CSystemInfo::m_csProductRegKey, FSMON_KEY, iValue, HKEY_LOCAL_MACHINE);
	/*
	m_objMaxWhiteListMgr.PostMessageToServiceCrypt();

	m_objMaxWhiteListMgr.PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, RESTARTPROTECTION, ON);
	*/
}
