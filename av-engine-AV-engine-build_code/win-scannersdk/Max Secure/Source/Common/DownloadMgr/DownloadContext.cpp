
/*======================================================================================
FILE             : DownloadContext.cpp
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

#include "pch.h"
#include "WinHttpManager.h"
#include "DownloadContext.h"
#include "Logger.h"
#include "WinHttpManager.h"
#ifdef DOWNLOAD_BOT
#include "WebParser.h"
#endif
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE

static char THIS_FILE[] = __FILE__;

#endif


/*--------------------------------------------------------------------------------------
Function       : CDownloadContext
In Parameters  : void, 
Out Parameters :
Description    :constructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CDownloadContext::CDownloadContext(void)
{
	m_dwFileSize = 0;
	m_dwFailedHeaderCnt = 0;
	m_dwCurrFileSize = 0;
	m_dwCurrReadBytes = 1;
	m_dwCurrTotalBytes =0;
	m_dwTotalQueueCnt = 0;
	m_dwByteRangeStart = 0;
	m_dwByteRangeEnd = 0;
	m_dwDownloadedSize = 0;
	m_hConnect = NULL;
	m_bResumDownload = false;
	m_dwPartNo = 0;
	::ZeroMemory(m_szLocalFilePath,sizeof(m_szLocalFilePath));
	::ZeroMemory(m_szAppPath,sizeof(m_szLocalFilePath));
	::ZeroMemory(m_strLocalFileName,sizeof(m_szLocalFilePath));
	m_bPartComplete = false;
}

/*--------------------------------------------------------------------------------------
Function       : ~CDownloadContext
In Parameters  : void, 
Out Parameters :
Description    : destructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CDownloadContext::~CDownloadContext(void)
{

}

/*--------------------------------------------------------------------------------------
Function       : GetHeaderInfo
In Parameters  : TCHAR * szSourceUrl, 
Out Parameters : STRUCT_HEADER_INFO
Description    : retrive header info
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CDownloadContext::GetHeaderInfo(TCHAR * szSourceUrl, STRUCT_HEADER_INFO &sHeaderInfo)
{
	if(CWinHttpManager::m_lStopDownload)
	{
		return;
	}
	TCHAR szInfo[MAX_PATH] = {0};
	TCHAR szETAG[MAX_PATH] = {0};
	DWORD dwBufLen = MAX_PATH*sizeof(TCHAR);
	if(m_objwinHttpManager.Initialize(szSourceUrl))
	{
		if(m_dwPartNo == 0)
		{
			m_objwinHttpManager.GetHeaderInfo(WINHTTP_QUERY_CONTENT_LENGTH, szInfo,dwBufLen);
			dwBufLen = MAX_PATH*sizeof(TCHAR);
			m_objwinHttpManager.GetHeaderInfo(WINHTTP_QUERY_ETAG, szETAG,dwBufLen);
			
#ifdef DOWNLOAD_BOT
			TCHAR szContentInfo[MAX_PATH] = {0};
			DWORD dwContentBufLen = MAX_PATH*sizeof(TCHAR);
			m_objwinHttpManager.GetHeaderInfo(WINHTTP_QUERY_CONTENT_DISPOSITION, szContentInfo,dwContentBufLen);
			if(_tcslen(szContentInfo) > 0)
			{
				tstring strBinaryName;
				CWebParser::GetBinaryName(tstring(szContentInfo),strBinaryName);
				_tcscpy_s(sHeaderInfo.szBinaryName, strBinaryName.c_str());
			}
			else
			{
				::ZeroMemory(szContentInfo,sizeof(szContentInfo));
				dwContentBufLen = MAX_PATH*sizeof(TCHAR);;
				m_objwinHttpManager.GetHeaderInfo(WINHTTP_QUERY_CONTENT_LOCATION,szContentInfo,dwContentBufLen);
				if(_tcslen(szContentInfo) > 0)
				{
					tstring strBinaryName;
					CWebParser::GetBinaryName(tstring(szContentInfo),strBinaryName);
					_tcscpy_s(sHeaderInfo.szBinaryName, strBinaryName.c_str());
				}
			}
#endif
		}
		sHeaderInfo.dwFileSize =  _wtol(szInfo);
		sHeaderInfo.hSession  = m_objwinHttpManager.m_hSession;
		sHeaderInfo.hConnect = m_objwinHttpManager.m_hConnect;
		sHeaderInfo.hRequest = m_objwinHttpManager.m_hRequest;
		if(_tcslen(szETAG) > 0)
		{
			_tcscpy_s(sHeaderInfo.szETag,szETAG);
		}
		_tcscpy_s(sHeaderInfo.szHostName, m_objwinHttpManager.m_szHostName);
		_tcscpy_s(sHeaderInfo.szMainUrl, m_objwinHttpManager.m_szMainUrl);
	}
}

/*--------------------------------------------------------------------------------------
Function       : SetHeaderInfo
In Parameters  : STRUCT_HEADER_INFO sHeaderInfo, 
Out Parameters : bool
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadContext::SetHeaderInfo(STRUCT_HEADER_INFO &sHeaderInfo)
{
	m_objwinHttpManager.m_hSession = sHeaderInfo.hSession;
	m_objwinHttpManager.m_hConnect = sHeaderInfo.hConnect;
	//wcscpy_s(m_objwinHttpManager.m_szHostName, sHeaderInfo.szHostName);
	//wcscpy_s(m_objwinHttpManager.m_szMainUrl, sHeaderInfo.szMainUrl);
	m_objwinHttpManager.m_bSharedSession = true;	
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : DeleteContext
In Parameters  :
Out Parameters : void
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CDownloadContext::DeleteContext()
{
	g_objLogApp.AddLog1(_T("%d:DeleteContext()....\r\n"), GetCurrentThreadId());
	delete this;
}

/*--------------------------------------------------------------------------------------
Function       : Initialize
In Parameters  : HANDLE hQueueEvent, 
Out Parameters : bool
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadContext::Initialize(HANDLE hQueueEvent)
{
	//Do not close this handle
	m_objMsgQueue.m_hQueueEvent = hQueueEvent;
	return true;
}
bool CDownloadContext::Run(bool bLastOperation)
{
    if(!bLastOperation)
	{
		m_dwTotalQueueCnt = (DWORD)m_objMsgQueue.m_MsgQueue.size();
	}
	
	while(m_objMsgQueue.FetchQueueItem(m_objCurrQueueItem))
	{
		if(CWinHttpManager::m_lStopDownload)
		{
			return false;
		}
		CString csTemp;
		csTemp.Format(_T("%s%s_%d_%d.tmp"), m_szAppPath, m_strLocalFileName, m_dwTotalParts,
			m_dwPartNo);
		wcscpy_s(m_szLocalFilePath, _countof(m_szLocalFilePath), csTemp);
		if(m_bResumDownload == false)
		{
			DeleteFile(m_szLocalFilePath);
		}
		m_objwinHttpManager.SetDownloadStatus(m_dwDownloadedSize);
		if(m_bPartComplete)
		{
			continue;
		}
		m_objwinHttpManager.Download(m_szLocalFilePath, m_dwByteRangeStart, m_dwByteRangeEnd);
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       :
In Parameters  : DWORD dwSize, 
Out Parameters : LPVOID Allocate
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
LPVOID CDownloadContext::Allocate (DWORD dwSize)
{
	return (HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize));
}

/*--------------------------------------------------------------------------------------
Function       :
In Parameters  : LPVOID& pVPtr, 
Out Parameters : void Release
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CDownloadContext::Release(LPVOID& pVPtr)
{
	HeapFree(GetProcessHeap(), 0, pVPtr);
	pVPtr = NULL;
}


/*--------------------------------------------------------------------------------------
Function       : NotifyQueueEvent
In Parameters  :
Out Parameters : void
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CDownloadContext::NotifyQueueEvent()
{
	if(m_objMsgQueue.m_hQueueEvent)
	{
		::SetEvent(m_objMsgQueue.m_hQueueEvent);
	}

}

/*--------------------------------------------------------------------------------------
Function       : DumpStatistics
In Parameters  :
Out Parameters : void
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CDownloadContext::DumpStatistics()
{
}

/*--------------------------------------------------------------------------------------
Function       : GetDownloadStatus
In Parameters  : DWORD & dwDownloaded, 
Out Parameters : void
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CDownloadContext::GetDownloadStatus(DWORD & dwDownloaded)
{
	m_objwinHttpManager.GetDownloadStatus(dwDownloaded);
}