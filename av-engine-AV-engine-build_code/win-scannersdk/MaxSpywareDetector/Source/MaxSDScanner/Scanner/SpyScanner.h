/*======================================================================================
FILE             : SpyScanner.h
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
				  
CREATION DATE    : 8/1/2009 7:51:18 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "FileSystemScanner.h"
#include "RegistryScanner.h"
#include "ProcessScanner.h"
#include "NetworkScanner.h"
#include "MaxScanner.h"
#include "StartupScanner.h"

class CSpyScanner
{
public:
	CSpyScanner(SENDMESSAGETOUIMS lpSendMessaegToUI, CMaxScanner *pMaxScanner);
	virtual ~CSpyScanner();

	bool m_bDatabaseScan;
	bool m_bSignatureScan;
	bool m_bVirusScan;
	bool m_bDeepScan;
	bool m_bRegFixScan;
	bool m_bRegFixForOptionTab;
	bool m_bScan;
	bool m_bScanReferences;
	bool m_bAutoQuarantine;
	bool m_bUSBScan;
	bool m_bMachineLearning;
	bool m_bMachineLearningQ;
	CS2U* m_pobjFilesList;
	CS2U* m_pobjFoldersList;
	CString m_csFolderPath;

	void StartScanning(const TCHAR *strDrivesToScan);
	void StartStartUPScan();
	void UpdateUIStatus();
	void StopScanning();
	BOOL DeleteTempFilesSEH(LPCTSTR lpDirectoryName, BOOL bSubDir);
	bool ScanFile(LPMAX_PIPE_DATA_REG lpPipeData);

private:
	CStartupScanner		*m_pStartupScanner;
	CProcessScanner		*m_pProcessScanner;
	CFileSystemScanner	*m_pFileSystemScanner;
	CRegistryScanner	*m_pRegistryScanner;
	CNetworkScanner		*m_pNetworkScanner;
	CMaxScanner			*m_pMaxScanner;

	LPVOID m_pScanner;
	SENDMESSAGETOUIMS m_lpSendMessaegToUI;
	bool m_bStopScanning;
	BOOL DeleteTempFiles(LPCTSTR lpDirectoryName, BOOL bSubDir);
	void CleanSysVolumeInfoFolder();
	void CleanSysVolumeInfoFolderWithSEH();	
	void EnumFolder(CString csFolderPath);	
	BOOL DeleteTempInternetFilesSEH();
	BOOL DeleteTempInternetFiles();
	void ReportAutoRunInfFiles();
	BOOL AddInRestartDeleteList(RESTART_DELETE_TYPE eMessageInfo, ULONG ulSpyNameID, LPCTSTR szValue);
	void CreateWormstoDeleteINI(CString strINIPath);
	bool StartUpdateCount(CString csKey,DWORD dwCount=0);
	DWORD m_dwTempCount;
	CString m_csScanDetectedIni;
};