#include "pch.h"
#include "RegAuth.h"
#include "SDSystemInfo.h"

CRegAuth::CRegAuth()
{

}

CRegAuth::~CRegAuth()
{

}
int CRegAuth::IsLogin()
{
	CRegistry objReg;
	DWORD dwIsLogin = 0x00;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("IsLogin"), dwIsLogin, HKEY_LOCAL_MACHINE);

	return dwIsLogin;
}
int CRegAuth::IsProductionMode()
{
	CRegistry objReg;
	DWORD dwResult = 0x00;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("TModeType"), dwResult, HKEY_LOCAL_MACHINE);
	return dwResult;
}
/*
int CRegAuth::GetAVDevices(CString csRegInfo)
{
	CString csAVDeviceLimit;
	CString		csTokanized = csRegInfo;
	int iDevLimit = 0;
	if (csTokanized.GetLength() == 0x00)
	{
		return iDevLimit;
	}
	csTokanized.Replace(L"\"", L"");
	csTokanized.Replace(L"{", L"");
	csTokanized.Replace(L"}", L"");
	csTokanized.Replace(L"]", L"");
	csTokanized.Replace(L"[", L"");
	csTokanized.Replace(L" ", L"");
	csTokanized.Replace(L"aurasvc:entitlements:", L"");

	int iPos = 0;
	CString csToken = csTokanized.Tokenize(L",", iPos);
	while (!csToken.IsEmpty())
	{
		if (csToken.Find(L"av:device_limit:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":") + 1);
			csAVDeviceLimit = csToken;
			csAVDeviceLimit.Replace(L"device_limit:",L"");
			iDevLimit = _wtoi(csAVDeviceLimit);
			break;
		}
		csToken = csTokanized.Tokenize(L",", iPos);
	}


	return iDevLimit;
}
*/

int CRegAuth::GetAVDevices(CString csRegInfo, int& iStatus)
{
	CString csAVDeviceLimit;
	CString		csTokanized = csRegInfo;
	int iDevLimit = 0;
	if (csTokanized.GetLength() == 0x00)
	{
		return iDevLimit;
	}
	csTokanized.Replace(L"\"", L"");
	csTokanized.Replace(L"{", L"");
	csTokanized.Replace(L"}", L"");
	csTokanized.Replace(L"]", L"");
	csTokanized.Replace(L"[", L"");
	csTokanized.Replace(L" ", L"");
	csTokanized.Replace(L"aurasvc:entitlements:", L"");
	if (csTokanized.GetLength() <= 0)
	{
		iStatus = STATUS_UNREGISTERED_COPY;
	}

	int iPos = 0;
	CString csToken = csTokanized.Tokenize(L",", iPos);
	while (!csToken.IsEmpty())
	{
		if (csToken.Find(L"av:device_limit:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":") + 1);
			csAVDeviceLimit = csToken;
			csAVDeviceLimit.Replace(L"device_limit:", L"");
			iDevLimit = _wtoi(csAVDeviceLimit);
			if (iDevLimit > 0)
			{
				iStatus = STATUS_REGISTERED_COPY;
			}
			else
			{
				iStatus = STATUS_SUBSCRIPTION_EXPIRED;
			}
			break;
		}
		csToken = csTokanized.Tokenize(L",", iPos);
	}


	return iDevLimit;
}

void CRegAuth::GetTokenExpiryDate(CString csExpInfo)
{
	CString		csTokanized = csExpInfo;

	if (csTokanized.GetLength() == 0x00)
	{
		return;
	}
	csTokanized.Replace(L"\"", L"");
	csTokanized.Replace(L"{", L"");
	csTokanized.Replace(L"}", L"");
	csTokanized.Replace(L"]", L"");
	csTokanized.Replace(L"[", L"");
	csTokanized.Replace(L"default.", L"default,");

	int iPos = 0;
	CString csToken = csTokanized.Tokenize(L",", iPos);
	while (!csToken.IsEmpty())
	{
		if (csToken.Find(L"exp:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":") + 1);
			m_csTokenExpiryDate = csToken;
		}
		else if (csToken.Find(L"iat:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":") + 1);
			m_csTokenIssueDate = csToken;
		}

		csToken = csTokanized.Tokenize(L",", iPos);
	}

}
void CRegAuth::SetRegTokens(TCHAR* szRefresh_token)
{
	CRegistry	objReg;
	objReg.Set(CSystemInfo::m_csProductRegKey, _T("Refresh_Token"), szRefresh_token, HKEY_LOCAL_MACHINE);

}


 int CRegAuth::SetLoginInfo(CString csRefresh_token, CString csRegInfo, CString csExpInfo)
 {
	 int iStatus = STATUS_UNREGISTERED_COPY;
	 //int iAVDevices = GetAVDevices(csRegInfo);
	 int iAVDevices = GetAVDevices(csRegInfo, iStatus);
	 int iAVRegistered = 0;
	 
	 GetTokenExpiryDate(csExpInfo);
	 CRegistry	objReg;
	 objReg.Set(CSystemInfo::m_csProductRegKey, _T("Refresh_Token"), csRefresh_token, HKEY_LOCAL_MACHINE);
	 //objReg.Set(CSystemInfo::m_csProductRegKey, _T("AV_Devices"), iAVDevices, HKEY_LOCAL_MACHINE);


	 CString csExpiryTime = m_csTokenExpiryDate;
	 __time64_t Extime = _wtoi64(csExpiryTime);
	 CTime cExTimeO(Extime);
	 CString csExpiryDate;
	 csExpiryDate.Format(_T("%d-%d-%d %d:%d:%d"), cExTimeO.GetDay(), cExTimeO.GetMonth(), cExTimeO.GetYear(), cExTimeO.GetHour(), cExTimeO.GetMinute(), cExTimeO.GetSecond());

	 objReg.Set(CSystemInfo::m_csProductRegKey, _T("Token_Expiry_Stamp"), m_csTokenExpiryDate, HKEY_LOCAL_MACHINE);

	 objReg.Set(CSystemInfo::m_csProductRegKey, _T("Token_Expiry"), csExpiryDate, HKEY_LOCAL_MACHINE);
	 objReg.Set(CSystemInfo::m_csProductRegKey, _T("IsLogin"), 1, HKEY_LOCAL_MACHINE);
	
	 if (iAVDevices > 0)
	 {
		 iAVRegistered = 1;
		 SetQuarantineFlag(iAVRegistered);
	 }
	 else
	 {
		 objReg.Set(CSystemInfo::m_csProductRegKey, _T("IsLogin"), 0, HKEY_LOCAL_MACHINE);

		 DWORD dw = 1;
		 objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
		 objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), 0, HKEY_LOCAL_MACHINE);
		 //PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, STOPPROTECTION, ON);
	 }
	 return iStatus;
	 //CheckForFullProtection(iAVDevices);
		
	
 }

/*
void CRegAuth::SetLoginInfo(CString csRefresh_token, CString csRegInfo, CString csExpInfo, CString csSubInfo)
{
	//OutputDebugString(L"Inside SetLoginInfo");
	//OutputDebugString(csSubInfo);
	int iSubStatus = GetSubscriptionStatus(csSubInfo); 
	int iAVDevices = GetAVDevicesEx(csSubInfo);
	int iAVRegistered = 0;
	if (iSubStatus == 1 || iAVDevices > 0)
	{
		OutputDebugString(L"Registered !!!");
		iAVRegistered = 1;
	}
	GetTokenExpiryDate(csExpInfo);
	CRegistry	objReg;
	objReg.Set(CSystemInfo::m_csProductRegKey, _T("Refresh_Token"), csRefresh_token, HKEY_LOCAL_MACHINE);

	CString csExpiryTime = m_csTokenExpiryDate;
	__time64_t Extime = _wtoi64(csExpiryTime);
	CTime cExTimeO(Extime);
	CString csExpiryDate;
	csExpiryDate.Format(_T("%d-%d-%d %d:%d:%d"), cExTimeO.GetDay(), cExTimeO.GetMonth(), cExTimeO.GetYear(), cExTimeO.GetHour(), cExTimeO.GetMinute(), cExTimeO.GetSecond());

	objReg.Set(CSystemInfo::m_csProductRegKey, _T("Token_Expiry_Stamp"), m_csTokenExpiryDate, HKEY_LOCAL_MACHINE);
	objReg.Set(CSystemInfo::m_csProductRegKey, _T("Token_Expiry"), csExpiryDate, HKEY_LOCAL_MACHINE);
	objReg.Set(CSystemInfo::m_csProductRegKey, _T("IsLogin"), 1, HKEY_LOCAL_MACHINE);
	
	SetQuarantineFlag(iAVRegistered);		
}
*/

void CRegAuth::GetRefreshTokenFromReg(RefreshToken* pRefreshToken)
{
	CRegistry	objReg;
	CString		csToken(L"");
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("Refresh_Token"), csToken, HKEY_LOCAL_MACHINE);
	wcscpy_s(pRefreshToken->szToken, csToken);
}

/*
void CRegAuth::SetQuarantineFlag(int iRegistered)
{
	CRegistry objReg;
	DWORD dw = 0;
	SetActiveMonitorOn();
	if (iRegistered <= 0) //Unregistered
	{
		dw = 1;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), 0, HKEY_LOCAL_MACHINE);
	}
	if (iRegistered > 0) //Registered
	{
		dw = 0;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), 1, HKEY_LOCAL_MACHINE);
	}

	if (CSystemInfo::m_iVirusScanFlag)
	{
		if (iRegistered > 0) //Registered
		{
			dw = 0;
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), 1, HKEY_LOCAL_MACHINE);
		}

	}
	PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, STARTPROTECTION, ON);
}
*/

void CRegAuth::SetQuarantineFlag(int iRegistered, bool bRestartProtection)
{
	CRegistry objReg;
	DWORD dw = 0;
	SetActiveMonitorOn();
	if (iRegistered == 0) //Unregistered
	{
		dw = 1;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), 0, HKEY_LOCAL_MACHINE);
	}
	if (iRegistered == 1) //Registered
	{
		dw = 0;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), 1, HKEY_LOCAL_MACHINE);
	}

	if (CSystemInfo::m_iVirusScanFlag)
	{
		if (iRegistered == 1) //Registered
		{
			dw = 0;
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), 1, HKEY_LOCAL_MACHINE);
		}

	}
	if (bRestartProtection)
	{
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, STARTPROTECTION, ON);
	}
}

void CRegAuth::CheckForFullProtection(int iRegistered)
{

	m_bActiveMonitor = false;
	m_bActiveProtection = false;
	m_bAutoQuarOn = false;
	m_bRegisteredVersion = false;
	m_bLiveUpdateDone = false;

	CRegistry objReg;
	DWORD dwStatus;
	objReg.Get(CSystemInfo::m_csActMonRegKey, _T("ProcessMonitor"), dwStatus, HKEY_LOCAL_MACHINE);
	m_bActiveMonitor = (dwStatus ? true : false);

	m_bActiveProtection = CheckForFullProtectionEx();

	objReg.Get(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), dwStatus, HKEY_LOCAL_MACHINE);
	m_bAutoQuarOn = (dwStatus ? true : false);

	objReg.Get(CSystemInfo::m_csProductRegKey, _T("VulnerabilityNotification"), dwStatus, HKEY_LOCAL_MACHINE);
	m_bCheckForVulnerability = (dwStatus ? true : false);

	if (iRegistered > 0) //Registered
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), 1, HKEY_LOCAL_MACHINE);
		m_bRegisteredVersion = true;
	}
	else//Unregistered
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), 0, HKEY_LOCAL_MACHINE);
		m_bRegisteredVersion = false;
	}

	DWORD chkPCStatus;
	if (m_bActiveProtection && m_bActiveMonitor && m_bAutoQuarOn && m_bRegisteredVersion)
	{
		chkPCStatus = 1;
	}
	else
	{
		chkPCStatus = 0;
	}
	CRegistry	updStatusReg;
	updStatusReg.SetWow64Key(updStatusReg.IsOS64Bit());
	updStatusReg.Set(CSystemInfo::m_csProductRegKey, L"CheckProtection", chkPCStatus, HKEY_LOCAL_MACHINE);
}

bool CRegAuth::CheckForFullProtectionEx()
{
	m_bFullyProtected = false;
	bool bRet = false;
	DWORD dwActMonCheck = 1;
	CRegistry objRegistry;
	objRegistry.Get(CSystemInfo::m_csProductRegKey, L"bActiveProtection", dwActMonCheck, HKEY_LOCAL_MACHINE);
	if (dwActMonCheck == 0)
	{
		m_bFullyProtected = true;
		bRet = true;
	}
	return bRet;
}

void CRegAuth::PostMessageToProtection(UINT message, WPARAM wParam, LPARAM lParam)
{
	HWND hwnd = ::FindWindowEx(NULL, NULL, _T("#32770"), AUACTIVEPROTECTION);
	if (hwnd)
	{
		::PostMessage(hwnd, message, wParam, lParam);
	}
}

void CRegAuth::SetActiveMonitorOn()
{
	DWORD dwValue = 1;
	CRegistry objRegistry;
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ActivexMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"BhoMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ExtensionMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"HomePage", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"HostMonitor", 0, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ProcessMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"RegistryMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"NetworkMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ServiceMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ShowKillPopup", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"StartupMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"ToolbarMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"TrackingCookie", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"FileAssocMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"WinRestrictionMonitor", dwValue, HKEY_LOCAL_MACHINE);
	objRegistry.Set(CSystemInfo::m_csActMonRegKey, L"IERestrictionMonitor", dwValue, HKEY_LOCAL_MACHINE);
}

int CRegAuth::GetSubscriptionStatus(CString csSubInfo)
{
	CString		csTokanized = csSubInfo;
	int			iSubStatus = 0;
	int			iDevLimit = 0;
	CString		csSubStatus, csAVDeviceLimit;
	if (csTokanized.GetLength() == 0x00)
	{
		return iDevLimit;
	}
	csTokanized.Replace(L"\"", L"");
	csTokanized.Replace(L"{", L"");
	csTokanized.Replace(L"}", L"");
	csTokanized.Replace(L"]", L"");
	csTokanized.Replace(L"[", L"");

	int iPos = 0;
	CString csToken = csTokanized.Tokenize(L",", iPos);
	while (!csToken.IsEmpty())
	{
		if (csToken.Find(L"status:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":") + 1);
			//csAVDeviceLimit = csToken;
			//csAVDeviceLimit.Replace(L"device_limit:", L"");
			//iDevLimit = _wtoi(csAVDeviceLimit);
			csSubStatus = csToken;
			csSubStatus.Replace(L"status:", L"");
			if (csSubStatus.Compare(L"ACTIVE") == 0)
			{
				iSubStatus = 1;
				break;
			}
			if (csSubStatus.Compare(L"CLOSED") == 0)
			{
				iSubStatus = 2;
				break;
			}
			if (csSubStatus.Compare(L"EXPIRED") == 0)
			{
				iSubStatus = 3;
				break;
			}
			if (csSubStatus.Compare(L"SUSPENDED") == 0)
			{
				iSubStatus = 4;
				break;
			}
			if (csSubStatus.Compare(L"FAILED") == 0)
			{
				iSubStatus = 5;
				break;
			}
			
		}
		csToken = csTokanized.Tokenize(L",", iPos);
	}
	return iSubStatus;
}
/*
int CRegAuth::GetAVDevicesEx(CString csRegInfo)
{
	CString csAVDeviceLimit;
	CString		csTokanized = csRegInfo;
	int iDevLimit = 0;
	if (csTokanized.GetLength() == 0x00)
	{
		return iDevLimit;
	}
	csTokanized.Replace(L"\"", L"");
	csTokanized.Replace(L"{", L"");
	csTokanized.Replace(L"}", L"");
	csTokanized.Replace(L"]", L"");
	csTokanized.Replace(L"[", L"");

	int iPos = 0;
	CString csToken = csTokanized.Tokenize(L",", iPos);
	while (!csToken.IsEmpty())
	{
		if (csToken.Find(L"av:device_limit:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":") + 1);
			csAVDeviceLimit = csToken;
			csAVDeviceLimit.Replace(L"device_limit:", L"");
			iDevLimit = _wtoi(csAVDeviceLimit);
			break;
		}
		csToken = csTokanized.Tokenize(L",", iPos);
	}


	return iDevLimit;
}
*/
void CRegAuth::UpdateToken(CString csRefresh_token, CString csRegInfo, CString csExpInfo)
{

	CRegistry	objReg;
	DWORD		dwIsLoginReg = 0x00;
	DWORD		dwIsQrtnCntReg = 0x00;
	bool		bRestartProtection = true;

	objReg.Get(CSystemInfo::m_csProductRegKey, _T("IsLogin"), dwIsLoginReg, HKEY_LOCAL_MACHINE);
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dwIsQrtnCntReg, HKEY_LOCAL_MACHINE);

	if (dwIsLoginReg == 1 && dwIsQrtnCntReg == 0)
	{
		bRestartProtection = false;
	}
	int iStatus = STATUS_UNREGISTERED_COPY;
	//int iAVDevices = GetAVDevices(csRegInfo);
	int iAVDevices = GetAVDevices(csRegInfo, iStatus);
	int iAVRegistered = 0;
	if (iAVDevices > 0)
	{
		OutputDebugString(L"Registered");
		iAVRegistered = 1;
		
		GetTokenExpiryDate(csExpInfo);
		
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("Refresh_Token"), csRefresh_token, HKEY_LOCAL_MACHINE);

		CString csExpiryTime = m_csTokenExpiryDate;
		__time64_t Extime = _wtoi64(csExpiryTime);
		CTime cExTimeO(Extime);
		CString csExpiryDate;
		csExpiryDate.Format(_T("%d-%d-%d %d:%d:%d"), cExTimeO.GetDay(), cExTimeO.GetMonth(), cExTimeO.GetYear(), cExTimeO.GetHour(), cExTimeO.GetMinute(), cExTimeO.GetSecond());

		objReg.Set(CSystemInfo::m_csProductRegKey, _T("Token_Expiry_Stamp"), m_csTokenExpiryDate, HKEY_LOCAL_MACHINE);
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("Token_Expiry"), csExpiryDate, HKEY_LOCAL_MACHINE);
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("IsLogin"), 1, HKEY_LOCAL_MACHINE);
		SetQuarantineFlag(iAVRegistered, bRestartProtection);
	}
	else
	{
		iAVRegistered = 0;
		DWORD dw = 1;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("IsLogin"), 0, HKEY_LOCAL_MACHINE);
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), 0, HKEY_LOCAL_MACHINE);
		PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, STOPPROTECTION, ON);
	}

}

void CRegAuth::LogOff() 
{
	//AfxMessageBox(L"Inside LogOff");
	CRegistry	objReg;
	objReg.Set(CSystemInfo::m_csProductRegKey, _T("IsLogin"), 0, HKEY_LOCAL_MACHINE);

	DWORD dw = 1;
	objReg.Set(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dw, HKEY_LOCAL_MACHINE);
	objReg.Set(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), 0, HKEY_LOCAL_MACHINE);
	PostMessageToProtection(WM_USER_RESTART_MON_SWITCH, STOPPROTECTION, ON);
}