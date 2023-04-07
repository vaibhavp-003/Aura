/*======================================================================================
FILE             : ThreatManager.h
ABSTRACT         :
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE): 
                   (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be 
                   used, copied, reproduced, transmitted, or stored in any form or by any 
                   means, electronic, recording, photocopying, mechanical or otherwise, 
                   without the prior written permission of Aura.	
CREATION DATE    : 8/1/2009 6:51:30 PM
NOTES            : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once

#include "SDConstants.h"
#include "MaxConstant.h"
#include "RemoveDB.h"
#include "DBPathExpander.h"
#include "ZipArchive.h"
#include "S2S.h"
#include "SysFiles.h"
#include "MaxDSrvWrapper.h"

class CThreatManager
{
public:
	CThreatManager(SENDMESSAGETOUI lpSendMessaegToUI);
	~CThreatManager();

	//Quarantine related public functions!
	bool PerformDBAction(LPMAX_PIPE_DATA lpPipeData);
	bool PerformRegAction(LPMAX_PIPE_DATA_REG lpMaxregdata);

	//Recover related public functions!
	bool PerformRecoverAction(LPMAX_PIPE_DATA lpPipeData, bool bUpdateDB = false);
	void PerformQuarantine(bool bCallFromRestart = true);
	BOOL m_bIs64Bit;
	BOOL m_bIsFromFWUI;
	bool m_bThreatCommEnable;
	bool m_bThreatCommDataFound;
	bool m_bAutomationLab;

	bool QuarantineFile(PMAX_SCANNER_INFO pScanInfo);
	bool BackupFile(PMAX_SCANNER_INFO pScanInfo);
	bool RestoreFile(PMAX_SCANNER_INFO pScanInfo);

	bool GetRepairFileName(const TCHAR *sOriginalFileName, TCHAR *sDummyFileName);
	void MakeRestartReplaceEntry(const TCHAR *sOriginalFileName, TCHAR *sDummyFileName);
	BOOL AddInRestartDeleteList(RESTART_DELETE_TYPE eMessageInfo, ULONG ulSpyNameID, LPCTSTR szValue);

	void AddFileToRescannedDB(LPCTSTR szFilePath, LPCTSTR szSpyName);

private:
	CMaxDSrvWrapper		*m_pMaxDSrvWrapper;
	static ULONG m_lFreeDiskSpace;
	SENDMESSAGETOUI m_lpSendMessaegToUI;
	CDBPathExpander oDBPathExpander;
	bool m_bRestartQuarantine;
	RESTART_DELETE_TYPE m_CurrRDType;
	void ProcessBuffer(PWCHAR pBuffer, ULONG ulSizeOfBuffer);
	void ProcessLine(PWCHAR wsLineRead);

	bool CheckForDiskSpace(bool bBoth, DWORD & dwFileSize, CString csFilePath = _T(""));
	void GetBackupFileName(LPTSTR szBackupFilename);
	void CreateWormstoDeleteINI(CString strINIPath);

	// repair using dummy file handling
	BOOL MaxCopyFile(LPCTSTR lpFileName, TCHAR *lpNewFileName);
	BOOL MaxTempFileName(TCHAR *szTempFilename);

	bool m_bRestartRequired;
	bool m_bRootkitFound;
	ULONG GetHardDiskSpaceAvailable();

	CSysFiles m_objSysFiles;

	CString m_csDesktopPath;

	//Quarantine related private functions!
	// File System Functions
	bool SafeToTerminiate(CString csFileName);
	bool HandleProcesses(LPCTSTR strValue);
	bool QuarantineFile(LPMAX_PIPE_DATA pMaxPipeData);
	bool AddFiletoRemoveDB(LPMAX_PIPE_DATA pMaxPipeData);
	bool AddMailEntrytoRemoveDB(LPMAX_PIPE_DATA_REG pMaxPipeDataReg);
	bool QuarantineFolder(LPMAX_PIPE_DATA pMaxPipeData);
	bool BackupFile(LPMAX_PIPE_DATA pMaxPipeData);
	bool RecursiveDeleteFolder(LPCTSTR strValue);

	// Registry Functions
	bool AddRegistrytoRemoveDB(LPMAX_PIPE_DATA_REG pMaxPipeDataReg);
	bool DeleteRegKey(LPMAX_PIPE_DATA_REG pMaxPipeDataReg);
	bool DeleteRegValue(LPMAX_PIPE_DATA_REG pMaxPipeDataReg);
	bool FixRegData(LPMAX_PIPE_DATA_REG pMaxPipeDataReg);
	bool FixAppInitData(LPMAX_PIPE_DATA_REG pMaxPipeDataReg);

	//Recover related private functions!
	bool RecoverFiles(MAX_PIPE_DATA_REG &sMaxPipeDataReg);
	bool Is64BitKey(CString strValue);

	//send rescan data to threat community
	CString m_csRescanFilePath;
	CZipArchive	m_objRescanArc;
	void CheckForRescanZipFilesCount();
	void AddAllLogFilesToZip();
	bool IsFileLargerThanSize(LPCTSTR szFilePath, DWORD dwMaxSize);
	bool CheckFileForHiddenFolder(LPCTSTR szFilePath);
	bool DelFileUsingDriver(CString csPath2Del);
	void  ConfigForNetworkScan(CString csScanDrive);
	bool m_bValidated;
};

