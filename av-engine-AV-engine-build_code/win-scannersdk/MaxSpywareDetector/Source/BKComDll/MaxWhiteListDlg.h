#pragma once
#include "pch.h"
#include "MaxWhiteListMgr.h"

//typedef struct _WhiteListedApps
//{
//	wchar_t szWhiteApplicationPath[MAX_PATH];
//} WhiteListedApps;
//
//typedef struct _BlackListedApps
//{
//	wchar_t szBlackApplicationPath[MAX_PATH];
//} BlackListedApps;


class CMaxWhiteListDlg 
{
public:
	CMaxWhiteListDlg();
	~CMaxWhiteListDlg();

public:
	CMaxWhiteListMgr m_objMaxWhiteListMgr;
	int GetWhiteListStatus();
	int GetCryptMonStatus();
	void SetWhiteListStatusEx(int iValue);
	void SetCryptMonStatus(int iValue);
	void GetListedAppsCnt(int* ptrListedAppArrayCountArray);
	void FillListedApps(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize);
	void SetListedAppsIntoDB(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize);
	int  GetCryptMonExtCnt();
	void FillExtForCrypt(CrptExtList* pCryptMonExt, int iCryptMonExtSize);
	void SetCryptMonDataIntoDB(WhiteListedApps* pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps* pBlackListedAppData, int iBlackListedAppDataSize, CrptExtList* pCryptMonExt, int iCryptMonExtSize);
	
};
