/*=============================================================================
   FILE		           : DownloadManager.h 
   ABSTRACT		       : DownloadManager class will check for the updates available on the 
						 server. It will compare local version present on client with latest 
						 version available. If client don’t have the latest version it will 
						 check if client require full patch (That is if client is having 
						 low version than base version) or incremental updates files 
						 (delta files present on server). 
   DOCUMENTS	       : Refer The Live Update Design.doc, Live Update Requirement Document.doc
   AUTHOR		       :
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C) Aura
						 Created as an unpublished copyright work.  All rights reserved.
						 This document and the information it contains is confidential and
						 proprietary to Aura.  Hence, it may not be 
						 used, copied, reproduced, transmitted, or stored in any form or by any 
						 means, electronic, recording, photocopying, mechanical or otherwise, 
						 without the prior written permission of Aura.	
   CREATION DATE      : 
   NOTES		      : 
   VERSION HISTORY    : 
=============================================================================*/



#include "XListCtrl.h"
#include "SDSystemInfo.h"
#include "CommonFunctions.h"
#include "U2U.h"
#include "Logger.h"

#pragma once

//const int RETRY_COUNT = 12;
//const int ONE_RETRY_TIMEOUT = 5000;//ms

class CDownloadManager//:public ILogger
{
	CWinThread *m_pAnimationThread, *m_pStatusThread;

public:
	CDownloadManager();
	~CDownloadManager();

	int m_iFilecount;
	CString m_csVersionINI;
	CString m_csDeltaVersionINI;

	

	CXListCtrl *m_pStatusListCtrl;
	bool m_bUpdateVersion;
	bool m_bUpdateVersionX64;
	bool m_bDataBasePatch;
	bool m_bDataBasePatchX64;
	bool m_bMiniDataBasePatch;
	bool m_bDataBasePatchMonthly;
	bool m_bDataBasePatchWeekly;
	bool m_bDataBase;
	bool m_bProduct;
	bool m_bProductX64;
	bool m_bHelp;
	bool m_bHelpX64;
	bool m_bRemoveSpy;
	bool m_bRemoveSpyX64;
	bool m_bDownLoadFullPatch;
	bool m_bKeyLogger;
	bool m_bKeyLoggerX64;
	bool m_bRootKit;
	bool m_bRootKitX64;
	bool m_bAdvScan;
	bool m_bAdvScanX64;
	bool m_bVirus;
	bool m_bVirusX64;
	bool m_bFirewall;
	bool m_bFirewallX64;
	bool m_bMerger;
	bool m_bMergerX64;
	bool m_bMisc;
	BOOL m_bPassive;
	bool m_bPEndingEPMD5;
	bool m_bAdvDB;
	bool m_bDownloadingLatestBase;

	CStringArray m_csUpdtVerFileNames;
	CStringArray m_csUpdtVerFileNamesX64;
	CStringArray m_csDBFileNames;
	CStringArray m_csArrMiscDownloadFiles;
	CStringArray m_csArrMiscMD5Files;
	CStringArray m_csArrMiscDestPath;
	CStringArray m_csArrMiscVersions;
	CStringArray m_csArrMiscRegValueName;
	CStringArray fileNameArray;
	CStringArray deltaFileNameArray;

	CDWordArray m_dwArrMiscEncrypt;
	DWORD m_dwArrMiscFileSize[MAX_PATH];
	//Mrudula
	CString csStringToDisPlay;
	CU2U m_objIndexOfDownload;
	int m_iAnimateItemCount;
	bool m_bAnimation;
	void SetListCtrlItems (CXListCtrl *pList, CStatic  *pStatus, CProgressCtrl *pProgress, 
			CStatic *pTotalTimeRemaining, CStatic *pTotalPercentage);
	bool DownLoad(bool &  bExitApplication);
	bool DownLoadfromLocalIP(bool &  bExitApplication);
	void DisplayError(bool bInternetError=false, bool bEPMD5Update = false);
	bool GetProxyDetails(CString &csProxyServer, CString &csProxyUserName, CString &csProxyPassword);
	CString GetDeltaVersion(const CString & csFileName);
	void UpdateStatus();
	BOOL IsFileAlreadyDownloaded(CString csSectionName, CString szKeyName, CString csFileName, CString * pcsFilePath = NULL);
	BOOL IsFirewallEnabled();
	bool CheckForSplittedDBs(CString &csDestPath);

	//new code added for SDK
	bool m_bSDK;
	void SetCtrlItemsSDK(CStatic *pStatus, CStatic *pTotalTimeRemaining, CStatic *pTotalPercentage, bool bSDK = false);

private:
	int m_iMaxNoOfDeltaToDownload;
	int m_iPercent;
	DWORD m_dwRemainingTime;
	CTime m_objDownloadStartTime;
	CStatic *m_pStatus, *m_pTotalTimeRemaining, *m_pTotalPercentage;
	CProgressCtrl *m_pProgLiveUpdate;
	CCommonFunctions m_objCommonFunctions;
	//CSystemInfo objSys;
	CString m_csDBPatchFileName;
	CString m_csDBPatchFileNameX64;
	CString m_csMiniDBPatchFileName1;
	CString m_csMiniDBPatchFileName2;
	CString m_csDBPatchFileNameMonthly;
	CString m_csDBPatchFileNameWeekly;
	CString m_csProductFileName;
	CString m_csProductFileName1;
	CString m_csProductFileName2;
	CString m_csProductFileNameX64;
	
	CString m_csInfoFileName1;
	CString m_csInfoFileName2;
	CString m_csRemoveSpyFileName1;
	CString m_csRemoveSpyFileName2;
	CString m_csKeyLoggerFileName1;
	CString m_csKeyLoggerFileName2;
	CString m_csRootKitFileName1;
	CString m_csRootKitFileName2;
	CString m_csAdvancedScanFileName1;
	CString m_csAdvancedScanFileName2;
	CString m_csVirusFileName1;
	CString m_csVirusFileName2;
	CString m_csFirewallFileName1;
	CString m_csFirewallFileName2;
	CString m_csMergerFileName1;
	CString m_csMergerFileName2;
	DWORD m_dwTotalDownloadSize, m_dwTotalDownloadedSize;
	BOOL m_bUpdateStatus;
	bool m_bDownloadUsingProxy;

	CString m_csLiveUpdatePath1;
	CString m_csLiveUpdatePath2;

	bool IsFileValidForThisProduct(const CString& csSectionName);
	bool CheckForUpdate(BOOL& bIsSVDownloaded);
	bool CheckForLocalUpdate(BOOL& bIsSVDownloaded);
	BOOL CheckVersionNumber(CString sSectionName);
	bool DownloadRemoteFile(CString csSource, CString csSource2, CString csLocalFileName, DWORD dwTotalSize, int iType, 
							CString csMD5 = _T(""), CString csHeader = _T(""));
	void SetInitialStatusText(int & iType, CStringArray & csFileNameArray, CString & csSectionName);
	void SetDownloadedSuccessStatusText(const int & iType);
	void SetDownloadedErrorStatusText(const int & iType);
	bool GetMiscDownloadList(void);
	void updateBackupPatchOnCheck(const CString &csPatchFileName);
	//void updateBackupPatchOnCheck(const CStringArray& csArrFileNames);
	bool DownloadHTTPFiles();
	BOOL CheckFirstPriorityPatchPresent();
	BOOL CheckFirstPriorityPatchPresentForX64();
	DWORD UpdateDownloadSize(CString csSectionName);
	bool GetDBFilesFromBackupIfAvailable();
	bool CheckDBsWhichAreNotAPartOfMerging(const CString &csBackupPath, const CString &csProductPath);
	
};