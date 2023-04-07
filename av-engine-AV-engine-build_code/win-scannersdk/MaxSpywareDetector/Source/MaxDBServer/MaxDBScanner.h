// MaxDBCache.h : Declaration of the CMaxDBCache

#pragma once
#include "resource.h"       // main symbols
#include "MaxConstant.h"
#include "MaxScanner.h"

class CMaxDBScanner
{
	HANDLE	m_hEvent;
	LONG	m_lInstanceCount;
	CString	m_strProductKey;
	CString	m_strInstallPath;
	CString	m_csCurrentSettingIniPath;

	bool m_bScannerReady;
	LONG m_lScanFileCount;
	CMaxScanner *m_pMaxScanner;

	bool SetInstallPath();
	bool SetProductRegKey();

	bool LoadScanner();
	bool UnloadScanner();
	void WaitForScanToFinish();

public:
	CMaxDBScanner();
	~CMaxDBScanner();

	static void OnDataReceivedCallBack(LPVOID pMaxPipeDataReg);

	bool FinalConstruct();
	void FinalRelease();
	bool ReloadScanner();
	void UnloadMainScanner();
	bool ScanFile(PMAX_SCANNER_INFO pScanInfo);
	bool ScanAlternateDataStream(PMAX_SCANNER_INFO pScanInfo);
	void InitialSettings();
	bool SetAutomationLabStatus();
	bool ReloadInstantINI();
	bool ReloadMailScannerDB();
};
