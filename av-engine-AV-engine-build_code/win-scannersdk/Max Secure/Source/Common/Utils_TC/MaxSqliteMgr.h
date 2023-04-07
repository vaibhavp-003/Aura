#pragma once
#include "sqlite3.h"
#include "MaxSqLiteBase.h"
#include "atlstr.h"


class CMaxSqliteMgr : public CMaxSqLiteBase
{
public:
	CMaxSqliteMgr(LPCTSTR pszDBPath);
	~CMaxSqliteMgr(void);

	UNSAFE_FILE_FULL_INFO m_MaxScanData[15];

	bool	InsertUnsafeFileInfo(LPUNSAFE_FILE_INFO pFileInfo);
	bool	InsertUnsafeFileInfoEx(LPCTSTR pszFileMD5,CString csMD5,LPCTSTR pszFileSHA256,LPCTSTR pszProbability);
	bool	GetLocalFileInfo(LPCTSTR pszFileMD5,LPUNSAFE_FILE_INFO pszResults);
	int		GetdBatchForTIScanning(DWORD dwScannerID);
	int		GetdBatchForSandBoxing(DWORD dwScannerID,LPCTSTR pszThreshold);
	int		GetdBatchForSandBoxingScanning(DWORD dwScannerID);
	int		GetRescanBatchForTIScanning(DWORD dwScannerID);
	bool	UpdateScanDoneFlag(LPCTSTR pszMD5);
	bool	UpdateReScanDoneFlag(LPCTSTR pszMD5);
	bool	UpdateFileUploadFlag(LPCTSTR pszMD5, int iTaskID);
	bool	UpdateDetectionStatusFlag(LPCTSTR pszMD5,int iDetection);
	bool	UpdateSandBoxScanningFlag(LPCTSTR pszMD5);
	bool	UpdatePreSendFlag(LPCTSTR pszMD5);
	bool	DeleteUnwantedEntries();
	bool	IsAlreadyScan(LPCTSTR pszFileMD5);
	bool	UpdateReportInfo(LPCTSTR pszStartTime,int iDetectedFiles,bool bStartScan);
	int		GetTotalFilesScanned();
	int		GetDetectedFiles();
	int		GetTotalFiles();
	bool	DeleteDetectedEntries();
	bool	UpdateTotalFilesScanned(int iTotalFiles);
	bool	SetExcludeFlag(LPCTSTR pszFilePath);
	bool	UpdateReportInfoEx(LPCTSTR pszStartTime,int iTotalFiles,int iDetectedFiles,bool bStartScan);
	int		GetThreatCommunityStatus();

};
