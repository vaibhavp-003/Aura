#pragma once

#include "MaxConstant.h"
#include "MaxCommunicator.h"
#include "MaxPipes.h"
#include "FileSignatureDb.h"
#include "MaxProcessScanner.h"
#include "MaxDSrvWrapper.h"

class CMaxScannerWrapper
{
public:
	CFileSignatureDb	m_oLocalSignature;
	CMaxProcessScanner	m_oMaxProcessScanner;

	CMaxScannerWrapper();
	virtual ~CMaxScannerWrapper();

	bool InitializeScanner();
	void DeInitializeScanner();

	bool ScanFile(PMAX_SCANNER_INFO pScanInfo);
	bool ScanAlternateDataStream(PMAX_SCANNER_INFO pScanInfo);
	bool IsExcluded(ULONG ulThreatID, LPCTSTR szThreatName, LPCTSTR szPath);
	bool SetAutomationLabStatus(bool bAutomationLab);
	bool GetThreatName(ULONG ulThreatID, TCHAR *szThreatName);
	bool ReloadInstantINI();
	bool ReloadMailScannerDB();

private:

	CMaxDSrvWrapper		*m_pMaxDSrvWrapper;
	CMaxCommunicator	*m_pCommClient;
	MAX_SCANNER_INFO	m_stScannerInfo;

	LONG	m_lScanFileCount;
	bool	m_bScannerReady;
	bool	m_bScannerInit;
	HANDLE	m_hEvent;
	void WaitForScanToFinish();

	CString GetInstallPath();
	bool ConnectServerNew();
	bool ConnectServer();
	bool DisConnectServer();
};