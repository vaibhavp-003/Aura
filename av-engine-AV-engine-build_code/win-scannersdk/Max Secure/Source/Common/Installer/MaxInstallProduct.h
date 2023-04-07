#pragma once
#include "RemoteService.h"
#include "Registry.h"
#include "ExecuteProcess.h"
#include "DirectoryManager.h"
#include <shlwapi.h>
#include "MSIOperations.h"

class CMaxInstallProduct
{
public:
	CMaxInstallProduct(void);
	~CMaxInstallProduct(void);

	CRegistry				m_oReg;
private:	
	CRemoteService			m_oRemoteService;
	CExecuteProcess 		m_oExecProc;
	CDirectoryManager		m_oDirectoryManager;
	CMSIOperations			m_oMSIOperations;
	
	typedef void (*LPDLLREGISTER)(void);
	LPDLLREGISTER				 m_lpDllRegisterServer;

public:
	void CleanUpPFFolder(LPCTSTR szProductName, LPCTSTR szRemovePath, LPCTSTR szIgnorePath, bool bAddRestartDelete, bool bRecursive);
	void CleanUpStartMenu(LPCTSTR szProductName);
	void CleanUpProdRegKey(LPCTSTR szProductName, LPCTSTR szProductRegKey);
	void CleanUpService(LPCTSTR szServiceName);
	void CleanUpShortCut(LPCTSTR szProductName, LPCTSTR szProductRegKey);
	void KillProcesses(CStringArray& arrProcesses);
	void DllUnRegisterComponents(LPCTSTR szAppPath);
	void UninstallFirewall(LPCTSTR szAppPath);
	void CompleteUninst(CString csProductPath, CString csFolderInAppPath);
	bool CreateRansomBackupFolder();
	bool DeleteFilesFolders(CString csAppPath, CString csProdName);
};
