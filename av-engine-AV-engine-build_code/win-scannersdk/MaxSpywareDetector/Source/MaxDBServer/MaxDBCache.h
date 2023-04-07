// MaxDBCache.h : Declaration of the CMaxDBCache

#pragma once
#include "resource.h"       // main symbols
#include "MaxConstant.h"
#include "PEConstants.h"
#include "ExcludeDb.h"
#include "RemoveDB.h"
#include "ThreatInfo.h"

typedef BOOL (WINAPI *LPFN_DISABLEWOW64REDIRECTION)(PVOID *OldValue);
typedef BOOL (WINAPI *LPFN_REVERTWOW64REDIRECTION)(PVOID OlValue);

class CMaxDBCache
{
	CExcludeDb		m_objExcludeDB;
	CRemoveDB		m_objRemoveDB;
	CRemoveDB		m_objMailRemoveDB;
	CS2S			m_objRescanDB;
	CS2U			m_objFileScanStatus;
	CThreatInfo		m_objThreatInfo;
	HANDLE			m_hEvent;
	LONG			m_lInstanceCount;
	CStringA		m_csLocalDBVersion;
	TCHAR			m_szAppPath[MAX_PATH];
	CString			m_strProductKey;
	CString			m_strInstallPath;
	CString			m_csCurrentSettingIniPath;
	CString			m_csRemoveDB;
	CString			m_csRescannedDB;
	CString			m_csFileScanStatus;
	CString			m_csMailRemoveDB;

	bool SetFullLiveUpdate();
	bool SetInstallPath();
	bool SetProductRegKey();
	bool LoadAllDB();
	bool ClearAllDB();
	void GetCurrentDBVersion();

public:
	CMaxDBCache();
	~CMaxDBCache();

	static void OnDataReceivedCallBack(LPVOID pMaxPipeDataReg);

	bool FinalConstruct();
	void FinalRelease();
	bool ReloadAllDB();
	bool IsExcluded(bool * bIsExcluded, ULONG ulThreatID, LPCTSTR pThreatName, LPCTSTR pPath);
	bool Exclude(ULONG ulThreatID, LPCTSTR pThreatName, LPCTSTR pPath);
	bool Recover(ULONG ulThreatID, LPCTSTR pThreatName, LPCTSTR pPath);
	bool GetThreatInfo(ULONG ulThreatID, BYTE* byThreatLevel, LPTSTR szThreatInfo, DWORD cchThreatInfo, LPTSTR szThreatName, DWORD cchThreatName, LPTSTR szKeyValue, int iTypeId);
	bool GetRemoveDBData(ULONG ulSpyID, MAX_PIPE_DATA_REG * pMaxPipeDataReg);
	bool AddToRemoveDB(PSYS_OBJ_FIXEDSIZE pSysObjFixed);
	bool AddFileToRescannedDB(LPCTSTR szFilePath, LPCTSTR szSpyName);
	bool SetGamingMode(ULONG ulGamingMode);
	bool GetScanStatus(LPCTSTR szFileName, ULONG* ulStatus);
	bool SetScanStatus(LPCTSTR szFileName, ULONG ulStatus);
	bool ReloadRemoveDB();
	bool AddMailToRemoveDB(PSYS_OBJ_FIXEDSIZE pSysObjFixed);
	bool GetMailRemoveDBData(ULONG ulSpyID, MAX_PIPE_DATA_REG * pMaxPipeDataReg);
	bool ReloadMailRemoveDB();
	void InitialSettings();
};
