/*======================================================================================
FILE             : CommonFunctions.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Sandip Sanap
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.				  
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	

CREATION DATE    : 05/18/2009 11:18:03 AM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include <afxwin.h>
#include <winsvc.h>
#include "MaxWarnings.h"
#include "atlbase.h"
#include "YesNoMsgBoxDlg.h"
#include "CPUInfo.h"
#include "ProductInfo.h"
#include "RemoteService.h"
#include "Registry.h"
#include "MessageBox.h"
#include "MessageBoxNormal.h"
#include "EnumProcess.h"

class CCommonFunctions
{

public:
	CCommonFunctions(void);
	virtual ~CCommonFunctions(void);

	static bool m_bRestartRequired;
	static bool RestartRequired();

	BOOL CheckDLLFunction(UINT uType, CString chDownLoadLink, 
		BOOL bIs64Setup, CString csProdRegKey = PRODUCT_REG);
	BOOL ProductCompatibiltiy(UINT uType, CString chDownLoadLink, 
		BOOL bIs64Setup, CString csProdRegKey = PRODUCT_REG);
	
	BOOL EncryptFileDB(TCHAR csFileNames[200], short iHeaderSize = 48);
	BOOL CheckDLLCloseFunction(HWND hWnd, UINT uType, int iExeCheck,CString csProdName = PRODUCTNAME);
	BOOL StopSDService(int iService, TCHAR csFileNames[MAX_PATH]);
	bool Is64bitOS(CString csDownLoadLink, BOOL bIs64Setup, CString csProductName);
	bool UpdateFileIntegrityDB(CString csAppPath);
	bool VerifyPatchUpdate(LPCTSTR szDBPath,CString csAppPath);	
	bool CopyAndCryptFileDatabase(LPCTSTR szOrgFile, LPCTSTR szNewFile, DWORD dwMaxMemLimit, DWORD dwStartOffset);
	bool PauseMaxProtectorDriver(bool bDeleteService = false);
	void PostMessageToProtection(UINT message, WPARAM wParam, LPARAM lParam);
	BOOL CheckForBartPE();
	int LaunchNotificationsInUserContext(int iType, TCHAR* pszAppName, TCHAR* pszParam);
	void CheckAndEnableFirewallSetting();
	BOOL CheckForDBVersion(CString csNewVer);
	void CleanUp(CString csFirewallPath, CString csAppPath, bool bReinstall, bool bMigrate);
	void ConfigureFirewallInstallation(CString csAppPath, int iType);
	BOOL ParseInfo(CString csSetupFilePath);
	BOOL EnableAutoScnAndSchedular();
	BOOL PauseForDataBasePatch();
	BOOL CheckForDataBaseVersion(CString csNewVer);
	BOOL CheckForValidProductToProceed();	
	void RemoveServiceKeys(LPCTSTR szName);
	BOOL CheckCleanLocalDB();
	bool CCommonFunctions::Is64bitOSEx(CString csDownLoadLink, BOOL bIs64Setup, CString csProductName,BOOL bShowMsgBox);
	BOOL NetFilterFirewall(CString csAppPath);
	BOOL WinDefendSrvStop(int iOldVer, int iDefendServ);
	bool ChangeServiceStartType(LPCTSTR sDriverName, LPCTSTR sDriverPath, DWORD dwStartType);
	BOOL WinELamDriver();
	bool IsWin10();
	bool CreateRansomBackupFolder(CString csAppPath);
	bool SetIniRegistries();
	bool CreateRansomBackupFolderEx();
	void LaunchUltraAV();
	void DllRegisterComponentsEx(CString cszDllPath);
	bool RegistryGrantAll();
	void EnableProtectection();

	void StartInstallation();
	void EndInstallation();

private:
	BOOL CheckHardDiskSpaceAvailable(double dwDiskFreeSize);
	bool CheckInstallation(CString csProdReg = PRODUCT_REG);
	void StopWDService();
	BOOL HandlingFor64bit();
	BOOL AddProcessList(CStringArray & arrProcesses, int iExeCheck);
	void KillProcesses(CStringArray& arrProcesses);
	void ExecuteApplicationAndWaitOnChilds(char * pszAppName, char * pszParam);
	void UnregisterComponents(CString csFilePath);
	void HandlingForVirusPatch();
	bool ShellExecuteApp(CString csAppPath,UINT uType);
	void GetOSVersion(LPTSTR pszOS);
	bool CleanUpService(LPCTSTR szName);
};
