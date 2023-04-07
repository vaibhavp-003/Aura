
/*======================================================================================
FILE             : WinHttpManager.h
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
#include "pch.h"
#include "ThreadSync.h"
#include <winhttp.h>
#include "Downloadconst.h"


const int MAX_RESPONSE_DRAIN_SIZE = 20*1024*1024;
class CWinHttpManager
{
public:
	CWinHttpManager(void);
	~CWinHttpManager(void);

	TCHAR m_szHostName[MAX_PATH];
	TCHAR m_szMainUrl[URL_SIZE];
	DWORD m_dwCompletedDownloadBytes;
	HINTERNET  m_hSession;
	HINTERNET  m_hConnect;
	HINTERNET  m_hRequest;

	bool Initialize(LPCTSTR szHost,bool bCrackURL = true);
	bool GetHeaderInfo(int iQueryType, LPTSTR szHeaderInfo, DWORD &dwQueryBufLen);
	void GetDownloadStatus(DWORD & dwDownloaded);
	void SetDownloadStatus(DWORD  dwDownloaded);
	void PerformCleanup(ConnectionHandle enumConnHandle);
	bool Download(TCHAR * szLocalFileName, DWORD dwByteRangeStart, DWORD dwByteRangeStop);
	bool GetWebPage(LPBYTE lpBuffer, DWORD dwContentLength,DWORD &dwDownloadedLen);
	bool CreateRequestHandle(LPTSTR szURLPath = NULL);
	bool OpenRequestHandle();
	bool m_bSharedSession;
	static long m_lStopDownload;
	static void StopDownload();
	static void StartDownload();
	static bool CheckInternetConnection();

private:
	CThreadSync m_objThreadSync;
	bool CrackURL(LPCTSTR szFullUrl);
	BOOL SetByteRange(DWORD dwByteRangeStart, DWORD dwByteRangeStop);
	void ReadWriteFile(HANDLE hFile);
	bool CheckProxySettings();

};
