#pragma once
#include "pch.h"

typedef struct _RefreshToken
{
	wchar_t szToken[MAX_PATH];
	
} RefreshToken;


class CRegAuth
{
public:
	CRegAuth();
	~CRegAuth();

public:
	void GetRefreshTokenFromReg(RefreshToken* pRefreshToken);
	int SetLoginInfo(CString csRefresh_token, CString csRegInfo, CString csExpInfo);
	int GetSubscriptionStatus(CString csSubInfo);
	//int GetAVDevicesEx(CString csRegInfo);
	//int GetAVDevices(CString csRegInfo);
	int GetAVDevices(CString csRegInfo, int& iStatus);
	void SetRegTokens(TCHAR* szRefresh_token);
	int IsProductionMode();
	int IsLogin();
	void GetTokenExpiryDate(CString csRegInfo);
	CString m_csTokenIssueDate;
	CString m_csTokenExpiryDate;

	void SetQuarantineFlag(int iRegistered, bool bRestartProtection = true);
	bool CheckForFullProtectionEx();
	void CheckForFullProtection(int iRegistered);

	bool m_bActiveMonitor;
	bool m_bActiveProtection;
	bool m_bAutoQuarOn;
	bool m_bRegisteredVersion;
	bool m_bLiveUpdateDone;
	bool m_bSecurityUpdates;
	bool m_bFullyProtected;
	bool m_bCheckForVulnerability;

	void PostMessageToProtection(UINT message, WPARAM wParam, LPARAM lParam);
	void SetActiveMonitorOn();
	void UpdateToken(CString csRefresh_token, CString csRegInfo, CString csExpInfo);
	void LogOff();
};