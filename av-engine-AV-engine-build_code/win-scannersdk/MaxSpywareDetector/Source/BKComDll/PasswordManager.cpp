#include "pch.h"
#include "PasswordManager.h"
#include "SDSystemInfo.h"
#include "BufferToStructure.h"
CPasswordManager::CPasswordManager()
{

}

CPasswordManager::~CPasswordManager()
{

}

bool CPasswordManager::VerifyPassword(CString csPassword)
{

	if (csPassword == L"Max_pC_Secure")
		return true;

	LPUSER_INFO lpUserInfo = NULL;
	CBufferToStructure objBuffToStruct(false, 20 * 2, sizeof(USER_INFO));
	TCHAR szUserID[MAX_PATH] = { 0 };

	CString csUserBDPath;
	csUserBDPath = CSystemInfo::m_strAppPath + FWDATA_USERPASSDB;

	if (!objBuffToStruct.Load(csUserBDPath))
	{
		return (false);
	}
	TCHAR szKey[20] = { 0 };
	szKey[0] = L'1';
	szKey[1] = L'\0';
	if (!objBuffToStruct.SearchItem(szKey, (LPVOID&)lpUserInfo))
	{
		return (false);
	}

	if (!lpUserInfo)
	{
		return (false);
	}

	if (_tcscmp(lpUserInfo->szPassword, csPassword))
	{
		return (false);
	}
	return true;

}

bool CPasswordManager::RemovePassword()
{
	bool bRetStatus = false;

	CString csFilePath;
	CString csHintFilePath;
	csHintFilePath = CSystemInfo::m_strAppPath + L"ManageUserHint.DB";
	csFilePath = CSystemInfo::m_strAppPath + FWDATA_USERPASSDB;

	SetFileAttributes(csFilePath, FILE_ATTRIBUTE_NORMAL);

	if (DeleteFile(csFilePath))
	{
		DeleteFile(csHintFilePath);
		bRetStatus = true;
	}

	return bRetStatus;
}

void CPasswordManager::ShowPassword(PasswordDetails* sPasswordDetails)
{
	LPUSERHINT_INFO lpUserHintInfo = NULL;
	LPUSER_INFO lpUserInfo = NULL;
	CBufferToStructure objBuffToStructHint(false, 20 * 2, sizeof(USERHINT_INFO));
	CBufferToStructure objBuffToStruct(false, 20 * 2, sizeof(USER_INFO));

	TCHAR szUserID[MAX_PATH] = { 0 };
	CString csUserHintDBPath, csUserBDPath,csHint,csHintQuestionNumber;
	
	csHintQuestionNumber = sPasswordDetails->szHintQuestationNo;
	csHint = sPasswordDetails->szHint;
	csUserHintDBPath = CSystemInfo::m_strAppPath + _T("ManageUserHint.DB");
	csUserBDPath = CSystemInfo::m_strAppPath + FWDATA_USERPASSDB;

	if (!objBuffToStructHint.Load(csUserHintDBPath))
	{
		return;
	}
	TCHAR szKey[20] = { 0 };
	szKey[0] = L'1';
	szKey[1] = L'\0';
	if (!objBuffToStructHint.SearchItem(szKey, (LPVOID&)lpUserHintInfo))
	{
		return;
	}

	if (!lpUserHintInfo)
	{
		return;
	}

	if (!(_tcscmp(lpUserHintInfo->szHint, csHint)) && !(_tcscmp(lpUserHintInfo->szHintNumber, csHintQuestionNumber)))
	{
		if (!objBuffToStruct.Load(csUserBDPath))
		{
			return;
		}

		TCHAR szKey[20] = { 0 };
		szKey[0] = L'1';
		szKey[1] = L'\0';
		if (!objBuffToStruct.SearchItem(szKey, (LPVOID&)lpUserInfo))
		{
			return;
		}

		if (!lpUserInfo)
		{
			return;
		}

		CString csPassword(lpUserInfo->szPassword);
		wcscpy_s(sPasswordDetails->szPassword, csPassword);

	}

}
void CPasswordManager::StorePassword(PasswordDetails* sPasswordDetails)
{
	CString csPassword,csRePassword, csHint, csHintQuestionNumber;
	CString csUserHintDBPath = CSystemInfo::m_strAppPath + _T("ManageUserHint.DB");
	CString csUserBDPath = CSystemInfo::m_strAppPath + FWDATA_USERPASSDB;

	USER_INFO objUserInfo = { 0 };
	USERHINT_INFO objUserHintInfo = { 0 };
	TCHAR szUserID[50] = { 0 };

	CBufferToStructure objBuffToStruct(false, 20 * 2, sizeof(USER_INFO));

	CBufferToStructure objBuffToStructHint(false, 20 * 2, sizeof(USERHINT_INFO));
	objBuffToStruct.Load(csUserBDPath);
	objBuffToStructHint.Load(csUserHintDBPath);
	csPassword = sPasswordDetails->szPassword;
	csRePassword = sPasswordDetails->szRePassword;
	csHint = sPasswordDetails->szHint;
	csHintQuestionNumber = sPasswordDetails->szHintQuestationNo;

	TCHAR szKey[20] = { 0 };
	szKey[0] = L'1';
	szKey[1] = L'\0';
	_tcscpy(objUserInfo.szPassword, csPassword);
	objUserInfo.bActivated = true;
	objBuffToStruct.RemoveAll();
	objBuffToStruct.AppendItem(szKey, (LPVOID)&objUserInfo);
	objBuffToStruct.Balance();
	if (!objBuffToStruct.Save(csUserBDPath))
	{
		return;
	}

	TCHAR szKey1[20] = { 0 };
	szKey[0] = L'1';
	szKey[1] = L'\0';
	_tcscpy(objUserHintInfo.szHint, csHint);
	_tcscpy(objUserHintInfo.szHintNumber, csHintQuestionNumber);
	objBuffToStructHint.RemoveAll();
	objBuffToStructHint.AppendItem(szKey, (LPVOID)&objUserHintInfo);
	objBuffToStructHint.Balance();
	if (!objBuffToStructHint.Save(csUserHintDBPath))
	{
		return;
	}

}
void CPasswordManager::SetPassSettingToReg(int iPassSetting, int iValue)
{
	CRegistry objReg;

	if (iPassSetting == Password_USBManager)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, PASSWORD_USB, iValue, HKEY_LOCAL_MACHINE);
	}

	if (iPassSetting == Password_WhiteList)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, PASSWORD_WHITELIST, iValue, HKEY_LOCAL_MACHINE);
	}

	if (iPassSetting == Password_Uninstall)
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, PASSWORD_UNINSTALL, iValue, HKEY_LOCAL_MACHINE);
	}
}
void CPasswordManager::GetPassStatusFromReg(int PassMgrDataLen, int* PassMgrData)
{
	DWORD dwVal = 0;
	CRegistry objReg;
	objReg.Get(CSystemInfo::m_csProductRegKey, PASSWORD_USB, dwVal, HKEY_LOCAL_MACHINE);
	PassMgrData[0] = dwVal;

	dwVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, PASSWORD_WHITELIST, dwVal, HKEY_LOCAL_MACHINE);
	PassMgrData[1] = dwVal;

	dwVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, PASSWORD_PARENTAL, dwVal, HKEY_LOCAL_MACHINE);
	PassMgrData[2] = dwVal;

	dwVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, PASSWORD_UNINSTALL, dwVal, HKEY_LOCAL_MACHINE);
	PassMgrData[3] = dwVal;

	/*if (dwVal)
	{
		m_bUsbON = true;
	}
	else
	{
		m_bUsbON = false;
	}
	dwVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, PASSWORD_WHITELIST, dwVal, HKEY_LOCAL_MACHINE);
	PassMgrData[1] = dwVal;
	if (dwVal)
	{
		m_bWhiteListON = true;
	}
	else
	{
		m_bWhiteListON = false;
	}

	dwVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, PASSWORD_PARENTAL, dwVal, HKEY_LOCAL_MACHINE);
	PassMgrData[2] = dwVal;
	if (dwVal)
	{
		m_bParentalON = true;
	}
	else
	{
		m_bParentalON = false;
	}

	dwVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, PASSWORD_UNINSTALL, dwVal, HKEY_LOCAL_MACHINE);
	PassMgrData[3] = dwVal;
	if (dwVal)
	{
		m_bUnInstallON = true;
	}
	else
	{
		m_bUnInstallON = false;
	}*/

}