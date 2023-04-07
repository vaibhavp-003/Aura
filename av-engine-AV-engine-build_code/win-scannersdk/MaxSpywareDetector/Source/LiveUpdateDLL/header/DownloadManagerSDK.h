/*=============================================================================
   FILE		           : DownloadManagerSDK.h 
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

#include "SDSystemInfo.h"
#include "CommonFunctions.h"
#include "U2U.h"
#include "Logger.h"


enum UpdateMessages
{
	None1,
	FILECNT,//Deltas
	FILECNT_UPDATE,//For Update Patch
	UPTODATE,//Ultra AV is up to date!
	DWONLOAD_ERR,//Error occurred while downloading updates! Please try to update one more time by clicking on the Live Update button on the main interface.
	DISKSIZE_ERR,//There is not enough free disk space.
	DB_DOWNLOADING, //Downloading Threat Definitions...
	VP_DOWNLOADING,//Downloading Virus Scan Engine...
	UPDT_VER_DOWNLOADING,//Downloading product version updates...
	PRODUCT_DOWNLOADING,//Downloading Core Scan Engine...
	DB_PART_DOWNLOADED,//Threat Definition downloaded :
	UPDT_VER_PART_DOWNLOADED,//Product version update downloaded :
	DB_DOWNLOADED, //Threat Definitions are downloaded!
	UPDT_VER_DOWNLOADED,//Product version update are downloaded!
	FAILED_TO_UPDATE,//Failed to update.
	DOWNLOAD_SUCCESS,//Updates downloaded.
	DB_DOWNLOADED_ERROR,//Error occurred while downloading Threat Definitions!
	PRODUCT_DOWNLOADED_ERROR,//Error occurred while downloading Core Scan Engine!
	VIRUS_DOWNLOADED_ERROR,//Error occurred while downloading Virus Scan Engine!
	PRODUCT_DOWNLOADED,//Core Scan Engine is downloaded!
	VIRUS_DOWNLOADED,//Virus Scan Engine is downloaded!
	FINISH_UPDATE,
	Reserv
};

#pragma once

const int RETRY_COUNT = 12;
const int ONE_RETRY_TIMEOUT = 5000;//ms

class DownloadManagerSDK
{
	CWinThread  *m_pStatusThread;
public:
	DownloadManagerSDK(void);
	~DownloadManagerSDK(void);

	CStatic *m_pStatus, *m_pTotalTimeRemaining, *m_pTotalPercentage;
	CU2U m_objIndexOfDownload;

	SENDSDKLVMESSAGEUI m_pSendSDKMessageToUI;
	
	CStringArray m_csUpdtVerFileNames;
	CStringArray m_csUpdtVerFileNamesX64;
	CStringArray m_csDBFileNames;
	CStringArray fileNameArray;
	CStringArray deltaFileNameArray;

	CString m_csSDKFileName1;
	CString m_csSDKFileName2;

	CString m_csDownloadedFiles;

	int m_iEnumLabelStatus;

	bool m_bDownLoadFullPatch;
	bool m_bDataBase;
	
	bool m_bUpdateVersion;
	bool m_bUpdateVersionX64;
	bool m_bDataBasePatch;
	bool m_bDataBasePatchCL;
	bool m_bDataBasePatchX64;
	bool m_bProduct;
	bool m_bProductX64;
	bool m_bVirus;
	bool m_bVirusX64;
	bool m_bMergerX64;
	bool m_bMerger;

	bool m_bSDK;
	bool m_bSDKX64;

	bool m_bCloudSrv;
	bool m_bCloudControlSrv;

	CString m_csDownLoadPath;
	CString m_csSettingIniPath;
	
	//CString m_csExtractFolderPath;

	/*DWORD	m_dwTotalDownloadSize, m_dwTotalDownloadedSize;
	BOOL	m_bUpdateStatus;
	int		m_iPercent;
	DWORD	m_dwRemainingTime;
	CTime	m_objDownloadStartTime;*/
	

	void SetCtrlItemsSDK(CStatic *pStatus, CStatic *pTotalTimeRemaining, CStatic *pTotalPercentage);
	bool DownLoad(bool &  bExitApplication);
	void UpdateStatus();
	void UpdateStatusEx();

	void SetSDKParams(SENDSDKLVMESSAGEUI pSendSDKMessageToUI);
	//void SetSDKParams();
	bool ExtractAndUpdateDownloads();

private:
	int m_iFilecount;
	CString m_csVersionINI;
	CString m_csDeltaVersionINI;

	int m_iMaxNoOfDeltaToDownload;
	int m_iPercent;
	DWORD m_dwRemainingTime;
	CTime m_objDownloadStartTime;
	CCommonFunctions m_objCommonFunctions;
	

	CString m_csLiveUpdatePath1;
	CString m_csLiveUpdatePath2;
	CString m_csMergerFileName1;
	CString m_csMergerFileName2;

	CString m_csProductFileName;
	CString m_csProductFileName1;
	CString m_csProductFileName2;
	CString m_csProductFileNameX64;
	CString m_csDBPatchFileName;
	CString m_csDBPatchFileNameCL;
	CString m_csDBPatchFileNameX64;
	CString m_csVirusFileName1;
	CString m_csVirusFileName2;
	CString m_csDeltaFileName;
	CString m_csCloudSrvFileName;
	CString m_csCloudContSrvFileName;

	BOOL m_bUpdateStatus;

	DWORD m_dwTotalDownloadSize, m_dwTotalDownloadedSize;

	bool m_bMaxDBMergeSuccess;

	TCHAR* GetModuleFilePath();
	bool CheckForUpdate(BOOL& bIsSVDownloaded);
	BOOL CheckVersionNumber(CString sSectionName);
	DWORD UpdateDownloadSize(CString csSectionName);
	BOOL IsFileAlreadyDownloaded(CString csSectionName, CString szKeyName, CString csFileName, CString * pcsFilePath = NULL);
	CString GetDeltaVersion(const CString & csFileName);
	bool CheckForSplittedDBs(CString &csDestPath);
	bool DownloadHTTPFiles();
	void SetInitialStatusText(int & iType, CStringArray & csFileNameArray, CString & csSectionName);
	bool DownloadRemoteFile(CString csSource, CString csSource2, CString csLocalFileName, DWORD dwTotalSize, int iType, 
							CString csMD5 = _T(""), CString csHeader = _T(""));

	bool CreateDownloadFolders();
	bool GetDBFilesFromBackupIfAvailable();
	void SetDownloadedSuccessStatusText(const int & iType);
	void SetDownloadedErrorStatusText(const int & iType);
	void FinishUpdateStatus(int iSuccessErr);

};
