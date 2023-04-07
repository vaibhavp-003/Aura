
/*======================================================================================
FILE             : DownloadController.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Sandip Sanap
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
CREATION DATE    : 12/28/2009
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "DownloadContext.h"
#include "MaxThreadPool.h"
#include "IController.h"
#include "DownloadConst.h"
#include "MessageQueue.h"
#include "Logger.h"
#include "ThreadSync.h"

class CDownloadController :
	public IController
{

public:
	static DWORD m_nPoolSize;
	CDownloadController(void);
	~CDownloadController(void);
#ifdef DOWNLOAD_BOT
	STRUCT_DOWNLOAD_INFO m_sDownloadInfo;
#endif
	void SetThreadPoolStatus(bool bPause);
	bool InitController(LPVOID lParam);
	bool StartController(LPVOID lParam);
	bool StopController();
	void DeleteController();
	bool JoinDownloadFiles();
	bool VerifyDownloader();
	void CheckDownloadStatus(DWORD nPassedSeconds);
	static DWORD WINAPI ControllerThreadProc(LPVOID lpParameter);
	bool AssignScanUrl(LPCTSTR szItem, int iItemType);
	bool NotifyAllContex();
	TCHAR m_szDownloadLocalPath[MAX_PATH];
	TCHAR m_szLocalTempDownloadPath[MAX_PATH];
	TCHAR m_szOrgFileName[MAX_PATH];
	TCHAR m_szFileMD5[MAX_PATH];
	bool ResumeDownload();
	bool DeleteFolderTree(CString csFilePath);
	void ResetInitData();
	CMessageQueue m_objDownloadQueue;
	CMessageQueue m_objDownloadPriorityQueue;
	CMessageQueueItem m_objCurrQueueItem;
	void ProcessQueueItem();
	LPSTRUCT_DOWNLOAD_INFO m_lpDownloadInfo;
	void SetGUIInterface(IGUIInterface *pIGUI);
	void CancelDownload();
	void StartDownload();
	bool CheckForInternetConnection();
private:
	TCHAR m_szINIPath[MAX_PATH];
	TCHAR m_szUrlPAth[URL_SIZE];
	TCHAR m_szSectionHeader[MAX_PATH];
	DWORD m_dwCurrContentLength;
	DWORD m_nTaskItems;
	DWORD m_nContextIndex;
	CMaxThreadPool m_DownloaderThreadPool;
	CDownloadContext *m_pIExecCurrentContext;
	DWORD m_dwStartTime;
	DWORD m_dwEndTime;
	STRUCT_HEADER_INFO m_sHeaderInfo;
	DWORD GetFileSizeEx(TCHAR *szFilePath);
	bool VerifyResumeDownloadFiles(DWORD dwFileSize);
	CLogger m_objDownloadStatusLog;
	DWORD m_dwCurrentDownloadStatus;
	DWORD m_dwCurrentFileSize;
	IGUIInterface *m_pIGuiInterface; 
	DWORD m_dwCurrDownloadedBytes;
	bool m_bResumeDownload;
	HANDLE m_hCtrlThread;
	bool m_bStartController;
	bool CheckMD5();
};
