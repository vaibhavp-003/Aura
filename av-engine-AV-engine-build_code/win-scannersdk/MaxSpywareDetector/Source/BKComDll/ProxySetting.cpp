#include "pch.h"
#include "ProxySetting.h"
#include "CPUInfo.h"
#include "SDSystemInfo.h"
#include "MaxPipes.h"
#include "MaxDSrvWrapper.h"

/*-------------------------------------------------------------------------------------
Function		: CProxySetting
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor for class CProxySetting
--------------------------------------------------------------------------------------*/
CProxySetting::CProxySetting()
{

}

/*-------------------------------------------------------------------------------------
Function		: CProxySetting
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor for class CProxySetting
--------------------------------------------------------------------------------------*/
CProxySetting::~CProxySetting()
{

}
/*-------------------------------------------------------------------------------------
Function		: GetProxySetting
In Parameters	: ProxySetting* pProxySettingArray
Out Parameters	: void
Purpose			: This function is for to get proxy setting from ProxySetting.ini
--------------------------------------------------------------------------------------*/
void CProxySetting::GetProxySetting(ProxySetting* pProxySettingArray)
{
	CCPUInfo objSystem;
	CString csProxyINI = objSystem.GetSystemDir() + PROXYSETTINGS_INI;
	CString m_csServerIP, m_csPort, m_csProxyUserName, m_csProxyPassword;
	 
	GetPrivateProfileString(L"Settings", L"ProxyUserName", L"", m_csProxyUserName.GetBuffer(20), 20, csProxyINI);
	m_csProxyUserName.ReleaseBuffer(20);

	GetPrivateProfileString(L"Settings", L"ProxyPassword", L"", m_csProxyPassword.GetBuffer(20), 20, csProxyINI);
	m_csProxyPassword.ReleaseBuffer(20);

	CString csServer;
	GetPrivateProfileString(L"Settings", L"ProxyServer", L"", csServer.GetBuffer(20), 20, csProxyINI);
	csServer.ReleaseBuffer(20);
	int iPos = csServer.Find(L":");
	if (iPos > 0)
	{
		m_csServerIP = csServer.Left(iPos);
		m_csPort = csServer.Mid(iPos + 1);
	}
	else
	{
		m_csServerIP = L"";
		m_csPort = L"";
	}

	CString csConn;
	GetPrivateProfileString(L"Settings", L"Connection", L"", csConn.GetBuffer(20), 20, csProxyINI);
	csConn.ReleaseBuffer(20);

	wcscpy_s(pProxySettingArray->szProxyUserName, m_csProxyUserName);
	wcscpy_s(pProxySettingArray->szProxyPassword, m_csProxyPassword);
	wcscpy_s(pProxySettingArray->szProxyServer, m_csServerIP);
	wcscpy_s(pProxySettingArray->szProxyPort, m_csPort);
}

/*-------------------------------------------------------------------------------------
Function		: SetProxySettings
In Parameters	: ProxySetting* pProxySettingArray
Out Parameters	: void
Purpose			: This function is for to set proxy setting to ProxySetting.ini
--------------------------------------------------------------------------------------*/
void CProxySetting::SetProxySettings(ProxySetting* pProxySettingArray)
{
	CString csProxyINI = CSystemInfo::m_strAppPath + SETTING_FOLDER + PROXYSETTINGS_INI;
	CString csProxyServer = pProxySettingArray->szProxyServer;
	CString csProxyPort = pProxySettingArray->szProxyPort;
	WritePrivateProfileString(L"Settings", L"HTTPUserName", L"", csProxyINI);
	WritePrivateProfileString(L"Settings", L"HTTPPassword", L"", csProxyINI);
	
	WritePrivateProfileString(L"Settings", L"ProxyUserName", pProxySettingArray->szProxyUserName, csProxyINI);
	WritePrivateProfileString(L"Settings", L"ProxyPassword", pProxySettingArray->szProxyPassword, csProxyINI);
	WritePrivateProfileString(L"Settings", L"ProxyServer", csProxyServer + L":" + csProxyPort, csProxyINI);

	CString csConn;
	csConn.Format(L"0");
	WritePrivateProfileString(L"Settings", L"Connection", csConn, csProxyINI);

	MAX_PIPE_DATA_REG oPipeData = { 0 };
	oPipeData.eMessageInfo = SetProxySetting;
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
	objMaxCommunicator.SendData(&oPipeData, sizeof(MAX_PIPE_DATA_REG));
}