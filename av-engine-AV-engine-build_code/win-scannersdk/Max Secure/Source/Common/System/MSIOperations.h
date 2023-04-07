#pragma once
#include "pch.h"

class CMSIOperations
{
public:
	CMSIOperations();
	~CMSIOperations();

	void CleanUpMSIComponents();
	void ReInstallFirewallMSI(CString csAppPath);
	void InstallFirewallMSI(CString csAppPath);
	void ExecuteFirewallSetup(CString csFirewallSetupPath);
	void CreateAntiSpamSettingINIFile(CString strINIPath);
	void UninstallFirewall(LPCTSTR szAppPath);
	void UninstallFirewallSetup(LPCTSTR szAppPath);
	void UninstallFirewall(LPCTSTR szAppPath,bool is64BitOs);
	void UninstallNodeJSServer(LPCTSTR szAppPath);

private:
	void UninstallFirewallUsingParam(CString csAppPath, bool bUsingGUID);
	void UninstallFirewallUsingParam(CString csAppPath, bool bUsingGUID,bool is64BitOs);
	void UninstallFirewallFromSetup(CString csAppPath, bool bUsingGUID);
	void ShellExecuteApp(CString csAppPath);
	void UninstallNodeJSServerUsingParam(CString csAppPath, bool bUsingGUID);
};