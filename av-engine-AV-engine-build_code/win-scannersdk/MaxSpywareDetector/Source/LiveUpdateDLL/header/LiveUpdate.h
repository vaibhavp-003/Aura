#pragma once
#include "pch.h"
#include "DownloadManagerSDK.h"
#include "SDSystemInfo.h"
#include "DownloadManagerEx.h"
//#include "ResourceManager.h"
//#include "colorstatic.h"

class CLiveUpdate
{

	DownloadManagerSDK *m_pDownloadMgr;	

public:
	CLiveUpdate(void);
	~CLiveUpdate(void);
//	bool Update(LPVOID *pParam);
	//bool Update(SENDSDKLVMESSAGEUI pSendMessageToUI, LPVOID *pParam);
	HANDLE	m_hUpdateStatusMutex;
	int Update(SENDSDKLVMESSAGEUI pSendMessageToUI, int iUpdateOption);
	bool UpdateNow();
	bool StopLiveUpdate();
	bool ExecutePatch(const CString &csPatchFileName,CString csOrgFileName, bool bWaitForUIToClose);
	bool IsReadyToInstall();
	void ExecuteDeltaRollBack();

	bool m_bLiveUpdateThread;
	int m_cUpdateCheckVerifyFlag;

	UPDATE_OPTIONS m_objUpdateInfo;
	CStatic m_Status, m_TotalTimeRemaining, m_TotalPercentage;
	SENDSDKLVMESSAGEUI m_pSendSDKMessageToUI;

	bool	m_bExitApplication;
	bool m_bUpdateCheck;
	bool m_bNewDBFileDownloaded;
	bool CheckServerVersion();

	//CDownloadManagerEx m_objLiveUpdateEx;
private:
	
	CWinThread *m_pThreadUpdateNow/*, *m_pAllLogThread*/;
	TCHAR* GetModuleFilePath();
	bool Check4ValidDataBackUP(LPCTSTR	pszBackUPFolPath);
	bool PostMessageToProtection(UINT WM_Message, UINT ActMon_Message, UINT uStatus);
	
};

//extern CLiveUpdate theApp;


