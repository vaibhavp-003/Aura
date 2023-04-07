#pragma once
#include "SDSystemInfo.h"
#include "S2U.h"
#include "Registry.h"
#include "CommonFunctions.h"
#include "ExecuteProcess.h"
#include "UpdateManager.h"
#include "EnumProcess.h"
#include <afxmt.h>
#include "DirectoryManager.h"

typedef enum _updateType
{
	ENUM_PRODUCT = 0,
	ENUM_VIRUS,
	ENUM_DELTAS,
	ENUM_DATABASE,
	ENUM_UPDATE
}ENUM_UPDATE_TYPE;

class CMaxProductMerger
{
public:
	CMaxProductMerger(void);
	virtual ~CMaxProductMerger(void);

	void StartMonitoringThread();
	void StopMonitoringThread();

	void StartMonitoring();
	void StartEnumerating();

	void GenerateFileEvent(LPCTSTR szFileName);
	bool CheckAndFixDB();
	void StartBlkDBMerging();
	void CopyDelta();
	void CleanUnwantedDelta(CString csSource, CString csSDFile);

private:

	bool m_bShowAutoUpdateSuccessMsg;
	bool m_bReceivedNewEvent;
	bool m_bReceivedQuitEvent;
	CEvent m_QuitEvent;
	CEvent m_EnumerateEvent;
	bool m_bCopySuccess;
	void EnumFolderAndPerformUpdate();

	CString			m_csFolderToMonitor;
	CString			m_csServerVersionTXT;
	CString			m_csLockFileName;
	CString			m_csLocalBackupFolder;
	CRegistry		m_objRegistry;
	CSystemInfo		m_objSystemInfo;
	CEnumProcess	m_objEnumProcess;
	CDirectoryManager m_oDirectoryManager;
	bool			m_bCheckAndFixDB;
	

	void StartUpdating();
	bool ReadAllSectionNameFromIni();

	bool m_bPartialDatabaseMerged;
	bool m_bMaxDBMergeSuccess;
	void MergeMaxDeltas();
	void MergeMaxDeltasEx();
	void CopyDBFilesToData(CString csDbPath, CString csMergePath);
	bool CheckAndCompareFileVersion(CString csName, CString csIniName);
	
	CStringArray m_csDBFileNames;
	CString m_csMaxDBVersionNo;
	CString m_csDeltaDetails;					//(_T("DELTADETAILS"));

	bool m_bDatabaseFullPatch;
	CString m_csDatabaseFileName;
	CString m_csDatabaseDetails;				//(_T("DATABASEKEY"));

	bool m_bMergingLatestBase;

	CUpdateManager		*m_pUpdateManager;
	CCommonFunctions	m_objCommonFunctions;
	CExecuteProcess		m_objExecutor;

	CString GetDBFolderName();
	void BackupPatch(const CString &csPatchFileName);
	void BackupPatch(const CStringArray& csArrFileNames);
	bool ExecutePatch(const CString &csPatchFileName, bool bWaitForUIToClose);
	bool ExecutePatch(const CStringArray &csPatchFileNames, bool bWaitForUIToClose);
	bool IsReadyToInstall();
	bool IsReadyToMerge();

	bool m_bFullUpdatePatch;
	CString m_csFullUpdateFileName;
	CString m_csFullUpdateDetails;				//(_T("SDUPDATEKEY"));

	bool m_bProductPatch;
	CString m_csProductFileName;
	CString m_csProductDetails;					//(_T("PRODUCTKEY"));

	bool m_bVirusPatch;
	CString m_csVirusFileName;
	CString m_csVirusDetails;					//(_T("VIRUSKEY"));

	bool m_bFirewallPatch;
	CString m_csFirewallFileName;
	CString m_csFirewallDetails;					//(_T("VIRUSKEY"));

	bool m_bFirstPriorityPatch;
	CString m_csFirstPriorityFileName;
	CString m_csFirstPriorityDetails;				//(_T("FIRSTPRIORITYDETAILS"));

	bool m_bSDDatabaseMiniPatch;
	CString m_csSDDatabaseMiniFileName;
	CString m_csSDDatabaseMiniDetails;				//(_T("SDDATABASEMINIDETAILS"));

	bool m_bRemoveSpyPatch;
	CString m_csRemoveSpyFileName;
	CString m_csRemoveSpyDetails;				//(_T("REMOVESPYKEY"));

	bool m_bKeyLoggerPatch;
	CString m_csKeyLoggerFileName;
	CString m_csKeyloggerDetails;				//(_T("KEYLOGGERSPYKEY"));

	bool m_bRootKitPatch;
	CString m_csRootkitDetails;					//(_T("ROOTKITSPYKEY"));
	CString m_csRootKitFileName;
	
	bool m_bUpdateVersionPartial;
	bool m_bUpdateVersionPatch;
	CString m_csUpdateVersionDetails;					//(_T("UPDATEVERSION"));
	CStringArray m_csArrUpdtVerFileName;

	bool m_bDownloaded;

	BOOL CheckVersionNumber(const CString &csSectionName);

	BOOL IsOS64bit();
	BOOL m_bIsWow64;
	PVOID m_pOldValue;
	typedef BOOL (WINAPI *LPFN_DISABLEWOW64REDIRECTION)(PVOID *OldValue);
	typedef BOOL (WINAPI *LPFN_REVERTWOW64REDIRECTION)(PVOID OlValue);
	LPFN_DISABLEWOW64REDIRECTION m_lpfnDisableWow64BitRedirection;
	LPFN_REVERTWOW64REDIRECTION m_lpfnRevert64BitRedirection;

	bool GetMD5Signature(const CString &csFileName, CString &csMD5);
	int CheckExistance(const CString &csSectionName, LPCTSTR szKeyName, const CString &csFileName, int iType);
	void ShowAutoUpdateSuccessDlg();
	void ProcessCleanups();
	bool PostMessageToProtection(UINT WM_Message, UINT ActMon_Message, UINT uStatus);
	bool CheckAndFixDBRequirements(const CString& csSource, const CString& csDestination, bool bSkipBlackDB);
	void LowerProcessPriorityIfUniProcessorCPU();
	bool IsFileValidForThisProduct(const CString& csSectionName);
	bool ShutDownMailScannerIfRunning();
};
