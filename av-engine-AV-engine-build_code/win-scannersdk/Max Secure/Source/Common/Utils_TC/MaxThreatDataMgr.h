#pragma once
#include "stdafx.h"
#include <afxinet.h>
#include "MaxSqliteMgr.h"


#define _MAX_SERVER_URL								_T("http://106.201.237.96:9003");
#define _MAX_URL_CHECK_SERVER_STATUS				_T("/api/check");
#define _MAX_URL_CHECK_SUSPECIOUS					_T("/api/submithash/");
#define _MAX_URL_UPLOAD_FILE_SANDBOX				_T("/api/submitsample/2");
//#define _MAX_URL_UPLOAD_FILE_SANDBOX				_T("/api/submittask/");
#define _MAX_URL_SANDBOX_FILE_SCANNING				_T("/api/getreport/");
#define _MAX_URL_CHECK_PROGRESS						_T("/api/task/");
#define _MAX_URL_CHECK_INSERT_THREATINTELLIGENCE	_T("/ThreatCommunityService.asmx/Insert_MD5_SHA256_Threat_Inteligence_Information?");
#define _MAX_URL_PRE_MISP_CHECK						_T("/ThreatCommunityService.asmx/Check_MD5_Present_InThreat_Inteligence?");


#ifndef _ConnectionType_
#define _ConnectionType_
	enum ConnectionType
	{
		UsePreConfig,  
		DirectToInternet,
		UseProxy,
	};
#endif

class CMaxThreatDataMgr
{
	HINTERNET				m_hInternetSession;
	HINTERNET				m_hHttpConnection;

public:
	CMaxThreatDataMgr(void);
	~CMaxThreatDataMgr(void);

	CMaxSqliteMgr			*m_pSQLiteMgr;

	CString	UploadDatatoPortal(CString cszData2Send, int iDataSize = 1);

	CString CreateTIInformationJSON(CString csMD5,CString csSHA256, CString csPESign, CString csProbability ,int iDetectionStatus);
	CString CreateMISPScanJSON(CString csMD5);

	bool	IsServerOn();

	int		SendFilesForTIScanner();
	int		RescanFilesForTIScanner();
	int		SendFilesForScanBoxScanner();

	int	SendHashForScanning(CString csMD5, CString csSHA256);

	int	UploadFileForAnalysis(CString csFilePath);
	int	UploadFileForAnalysisEX(CString csLocation,CString csFilePath);
	int	SendFileForScanningBytaskID(int iTaskID);

	int	ScanFileThroughSandBox();
	int CheckProgress(int iTaskID);
	int	InsertORCheckIntoTIServer(CString csMD5,CString csSHA256, CString csPESign, CString csProbability ,int iDetectionStatus);
	void UpdateReport();
	bool PreMISPCheck(LPCTSTR pszFileMD5);

	TCHAR			m_szScanSQLDB[MAX_PATH];

};

