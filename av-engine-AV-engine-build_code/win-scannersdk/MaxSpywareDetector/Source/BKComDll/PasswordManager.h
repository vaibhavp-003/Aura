#pragma once
#include "pch.h"

typedef struct _PasswordDetails
{
	wchar_t szPassword[20];
	wchar_t szRePassword[20];
	wchar_t szHintQuestationNo[MAX_PATH];
	wchar_t szHint[MAX_PATH];	
} PasswordDetails;

typedef struct _UserInfo
{
	TCHAR szPassword[50];
	bool  bActivated;
}USER_INFO, * LPUSER_INFO;

typedef struct _UserHintInfo
{
	TCHAR szHint[50];
	TCHAR szHintNumber[10];
}USERHINT_INFO, * LPUSERHINT_INFO;

class CPasswordManager
{
public:
	CPasswordManager();
	~CPasswordManager();

public:
	void GetPassStatusFromReg(int PassMgrDataLen, int* PassMgrData);
	void SetPassSettingToReg(int iPassSetting, int iValue);
	void StorePassword(PasswordDetails * sPasswordDetails);
	void ShowPassword(PasswordDetails* sPasswordDetails);
	bool RemovePassword();
	bool VerifyPassword(CString csPassword);
//public:
//	bool					m_bUsbON;
//	bool					m_bWhiteListON;
//	bool					m_bParentalON;
//	bool					m_bUnInstallON;
};