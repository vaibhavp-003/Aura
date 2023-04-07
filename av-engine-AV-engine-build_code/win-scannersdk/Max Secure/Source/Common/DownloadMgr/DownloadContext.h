
/*======================================================================================
FILE             : DownloadContext.h
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
#include "iexeccontext.h"
#include "MessageQueue.h"
#include "WinHttpManager.h"


const int MAX_READBUFF_SIZE = 65536;
class CDownloadContext : public IExecContext
{
public:
	CDownloadContext(void);
	~CDownloadContext(void);

	CMessageQueue m_objMsgQueue;
	DWORD m_dwFileSize;
	DWORD m_dwFailedHeaderCnt;
	DWORD m_dwByteRangeStart;
	DWORD m_dwByteRangeEnd;
	DWORD m_dwTotalParts;
	DWORD m_dwPartNo;
	DWORD m_dwDownloadedSize;
	TCHAR m_szLocalFilePath[MAX_PATH];
	TCHAR m_szAppPath[MAX_PATH];
	TCHAR m_strLocalFileName[MAX_PATH];
	HINTERNET m_hConnect;
	bool m_bResumDownload;

	void DumpStatistics();
	void DeleteContext();
	void GetDownloadStatus(DWORD & dwDownloaded);
	void GetHeaderInfo(TCHAR * szSourceUrl,STRUCT_HEADER_INFO &sHeaderInfo );
	bool SetHeaderInfo(STRUCT_HEADER_INFO &sHeaderInfo);
	bool Initialize(HANDLE hQueueEvent);
	bool Run(bool bLastOperation = false);
	void NotifyQueueEvent();
	bool m_bPartComplete;
private:
	CMessageQueueItem m_objCurrQueueItem;
	DWORD m_dwCurrFileSize;
	DWORD m_dwCurrReadBytes;
	DWORD m_dwCurrTotalBytes;
	DWORD m_dwTotalQueueCnt;
	CWinHttpManager m_objwinHttpManager;

	bool EnumFolder(LPCTSTR szFolderPath);
	LPVOID Allocate (DWORD dwSize);
	void Release(LPVOID& pVPtr);
};
