/*======================================================================================
FILE             : FileSystemBase.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshan Singh Virdi
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 8/1/2009 6:52:47 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "ScannerBase.h"
#include "U2OU2O.h"
#include "U2OS2U.h"
#include "S2U.h"

enum ENUM_MESSAGEINFO
{
	eMsg_ActualCount = 1,
	eMsg_StartScanning,
	eMsg_FinishedScanning,
	eMsg_CurrentProgress
};

UINT _cdecl TotalQuickScanningSizeThread(LPVOID pParam);
UINT _cdecl TotalDriveScanningSizeThread(LPVOID pParam);
UINT _cdecl ScanningStatusThread(LPVOID pParam);

class CFileSystemBase : public CScannerBase
{
public:
	void GetTotalScanningSize();
	void ShowScanningStatus();
	double GetCurrentPercentage(ENUM_MESSAGEINFO eMessageInfo);

	CFileSystemBase(void);
	virtual ~CFileSystemBase(void);

protected:
	bool m_bCustomScan;
	HANDLE m_bStatusVariableLock;
	bool m_bSendStatusToUI;
	CString m_csCurrentFileName;
	CString m_csIgnoreFolder;
	bool m_bActualValueReady;
	DWORD m_dwTotalNoOfFilesToScan;
	ULONG m_ulFileCount;
	DWORD m_dwStartTickCount;
	CString m_csNonRemovableDrives;
	CString m_csUSBDrives;
	bool m_bIsUSBFolder;

	void StartCookieScan(const TCHAR *strDrivesToScan);
	void StartFolderScan(const TCHAR *strDrivesToScan);
	void StartFileScan(const TCHAR *strDrivesToScan);

	void PerformQuickSignatureScan();
	void ScanSystemWithSignature(const TCHAR *strDriveToScan);

	void EnumFolder(const TCHAR *cFolderPath, bool bCheckCookies, bool bEnumSubFolders = true, DWORD *pdwTotalNoOfFilesToScan = NULL, bool bSkipFolder = true);

	void EnunUSBFolder(const TCHAR *cFolderPath);

	bool m_bVirusScan;
	void UnloadAllDatabase();
	BOOL GetLastScanStatus(TCHAR *szDrive = NULL);
	BOOL GetLastStage(LPTSTR pszFileScan);
	BOOL SaveCurStage(LPCTSTR pszFileScan, int iStatus= 1);
	BOOL GetIniPathScanStatus();

private:

	CS2U	m_objCookieDBMap;
	CU2OU2O m_objFolderDBMap;
	CU2OU2O m_objFileDBMap;

	void ScanFolder(CS2U &oValueNSpyID, LPCTSTR strValuePath, bool bReportFolder);
	void ScanProfilePath(CU2OS2U &oValueType, bool bReportFolder, TCHAR cDriveToScan);
	void ScanNonProfilePath(CU2OS2U &oValueType, bool bReportFolder, TCHAR cDriveToScan);
	void ScanUsingDBByValueType(TCHAR cDriveToScan, CU2OU2O &objDBMap, bool bReportFolder);
	void ScanUsingFilesList(TCHAR cDriveToScan, CU2OU2O &objDBMap, bool bReportFolder, CS2U& objFilesList);

	bool CheckCookie(const TCHAR *cFileName, TCHAR *cFullPath);
	bool ScanCookieContent(const TCHAR *cFileName, TCHAR *cFullPath);
	void NormalizeBuffer(BYTE *pbReadBuffer, DWORD dwBytesRead);
	void EnumFolderNReportToUI(const TCHAR *cFolderPath, const ULONG lSpyNameID, bool& bMatchFound, bool bCheckScanList = false, LPDWORD lpdwFilesCount = 0);
	bool IsFolderPathInScannedList(LPCTSTR szFolderPath);

	//Krishna::Check FireFox Bug::13.05.2015
	void initilizeFirefoxPath();
	void initilizeChromePath();
	CStringArray m_csChromePath;
	CString m_sTempPath;
	CStringArray m_csFireFoxPath;
	bool CheckFirefoxBug(CString cFileName,CString cFolderName,CString &outFilePath);
	bool CheckChromeBug(CString czFolderName,CString &outFilePath);
	

private:	// percentage & remaining time calculation
	DWORD dwActualFileCountPending;
	DWORD dwActualFileCountInIncrements;
	BOOLEAN bDummyCount;
	DWORD Forty5MinuteIn;
	DWORD TwentyMinuteIn;
	DWORD FifteenMinuteIn;
	BOOLEAN bInitialCount;
	BOOLEAN bArrSampleZero;
	BOOLEAN bMedianCalculate;
	long double ldwProgress_In_Percent;
	long double ldwPreviousTime;
	long double ldwCurrentTotalFileSize;
	long double ldwtemp;
	long double ldwPrevious_Progress;
	long double Arr_CollectSamplingFiles[100];
	long double ldwOriginalSampleValue;
	int iCounter;
	long double ldwTotalRemTime;
	long double ldwActualRemTime;
	long double ldwGetDiffTime;
	DWORD dwPrevious_count;
	DWORD dwPreviousTotalFileCount;
	TCHAR	m_szDrive[0x5];
	TCHAR	m_szFilePath[1024];
	BOOL	m_bLastScanInfoFound;
	CString	m_csScanStatusIni;
	void  ConfigForNetworkScan(CString csScanDrive);
};
