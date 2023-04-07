// ToolBarCleanerDlg.h : header file
//

#pragma once

#include "Registry.h"
#include "DirectoryManager.h"


// CToolBarCleanerDlg dialog
class CToolBarCleaner
{
// Construction
public:
	
	bool StartToolbarScanning();
	void ExcludeCachePaths(); 
	protected:
	CRegistry				m_oReg;
	bool					bIS64Bit;
	CDirectoryManager		m_oDirectoryManager;
	CString m_csRegistry[MAX_PATH];
	int m_nRegistryCount;
	CString m_csSysPath;
	CStringArray objSubKeyArr;

	//Added By Tushar on 13 Feb 2015 for Excluding Cache paths of all browserd
	
	
	
	
private:
	void DeleteRegistryKey(CString szRemovePath);
	void CheckRegistryValue(CString szRemovePath);
	void CheckRegistryValueData(CString szRemovePath);
	void RegValueDataFromDefaultFileDelete(CString szRemovePath);
	void UnRegistryDll(CString szRemovePath);
	void UninstallerFile(CString szRemovePath);
	void DeleteFolder(LPCTSTR szRemovePath, bool bFolderDelete);
	void FilterINI();
	bool ExecuteProcess(LPCTSTR szCommand, LPCTSTR szArguments, DWORD dwWaitSeconds = MAXDWORD);
	int FindHIVE(CString &csKey);
	void CleanMozilla(CString szRemovePath);
	int ReplaceTags(CString csKey, bool bDelete);
};
