
/*======================================================================================
FILE             : DownloadController.cpp
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
#include "DownloadController.h"
#include "DownloadConst.h"
#ifdef DOWNLOAD_BOT
#include "CMaxBotApp.h"
#include "WebParser.h"
#include "DownloadMgrController.h"
#endif

#ifdef LIVE_UPDATE
#include "CommonFileIntegrityCheck.h"
#endif

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

DWORD CDownloadController::m_nPoolSize = 1;

/*--------------------------------------------------------------------------------------
Function       : CDownloadController
In Parameters  : void, 
Out Parameters :
Description    : constructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CDownloadController::CDownloadController(void)
{
	m_objDownloadQueue.m_hQueueEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
#ifdef DOWNLOAD_BOT
	::SecureZeroMemory(&m_sDownloadInfo, sizeof(STRUCT_DOWNLOAD_INFO));
	m_objDownloadStatusLog.Initialize(DOWNLOAD_STATUS_LOG,false,0,true);
#endif
	m_pIGuiInterface = NULL;
	m_hCtrlThread = NULL;

	ResetInitData();
}

void CDownloadController::ResetInitData()
{
	m_bStartController = false;
	m_bResumeDownload = false;
	m_lpDownloadInfo  = NULL;
	m_dwCurrentDownloadStatus = 0;
	m_dwCurrentFileSize = 0;
	m_nContextIndex = 0;
	m_pIExecCurrentContext = NULL;
	m_nTaskItems =   0;
	m_dwCurrDownloadedBytes = 0;
	::ZeroMemory(&m_sHeaderInfo,sizeof(STRUCT_HEADER_INFO));
	::ZeroMemory(m_szDownloadLocalPath,sizeof(m_szDownloadLocalPath));
	::ZeroMemory(m_szLocalTempDownloadPath,sizeof(m_szLocalTempDownloadPath));
	::ZeroMemory(m_szOrgFileName,sizeof(m_szOrgFileName));
	::ZeroMemory(m_szUrlPAth,sizeof(m_szUrlPAth));
	::ZeroMemory(m_szSectionHeader,sizeof(m_szSectionHeader));
	::ZeroMemory(m_szINIPath,sizeof(m_szINIPath));
	::ZeroMemory(m_szFileMD5,sizeof(m_szFileMD5));
#ifdef DOWNLOAD_BOT
	::ZeroMemory(m_sDownloadInfo.szMainUrl,sizeof(m_sDownloadInfo.szMainUrl));
	::ZeroMemory(m_sDownloadInfo.szSectionName,sizeof(m_sDownloadInfo.szSectionName));
	::ZeroMemory(m_sDownloadInfo.szExeName,sizeof(m_sDownloadInfo.szExeName));
#endif
	m_DownloaderThreadPool.ClearExecutionContext();
	m_dwCurrContentLength = 0;
	if(m_hCtrlThread)
	{
		::CloseHandle(m_hCtrlThread);
		m_hCtrlThread = NULL;
	}

}
/*--------------------------------------------------------------------------------------
Function       : ~CDownloadController
In Parameters  : void, 
Out Parameters :
Description    : destructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CDownloadController::~CDownloadController(void)
{
	if(m_objDownloadQueue.m_hQueueEvent)
	{
		::CloseHandle(m_objDownloadQueue.m_hQueueEvent);
		m_objDownloadQueue.m_hQueueEvent = NULL; 
	}
}

/*--------------------------------------------------------------------------------------
Function       : GetFileSizeEx
In Parameters  : TCHAR *szFilePath, 
Out Parameters : DWORD
Description    : retrive file size
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
DWORD CDownloadController::GetFileSizeEx(TCHAR *szFilePath)
{
	HANDLE hFile = NULL;
	SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, FALSE};
	if((hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
	{
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		if(hFile)
		{
			FlushFileBuffers(hFile);
			CloseHandle(hFile);
			hFile = NULL;
		}
		return dwFileSize;
	}
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : VerifyResumeDownloadFiles
In Parameters  : DWORD dwFileSize
Out Parameters : bool
Description    : verify resume download files
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadController::VerifyResumeDownloadFiles(DWORD dwFileSize)
{
	bool bResumeCancel = true;
	for(DWORD i = 0;i < m_nPoolSize;i++)
	{
		TCHAR szSection[MAX_PATH] = {0};
		wsprintf(szSection, _T("PARTS_%ld_%ld_DOWNLOADEDSIZE"), m_nPoolSize, i);
		DWORD dwDownloadedSize = GetPrivateProfileInt(m_szSectionHeader, szSection,
								0, m_szINIPath);
		CString csTemp;
		csTemp.Format(_T("%s%s_%d_%d.tmp"), m_szLocalTempDownloadPath, m_szOrgFileName,
					 m_nPoolSize, i);
		DWORD dwTempFileSize = GetFileSizeEx((TCHAR *)(LPCTSTR)csTemp);
		//if(!dwTempFileSize || !dwDownloadedSize || dwTempFileSize < dwDownloadedSize)
		if(dwTempFileSize < dwDownloadedSize)
		{
			bResumeCancel = false;
			break;
		}

		wsprintf(szSection, _T("PARTS_%ld_%ld_ASSIGNEDSIZE"), m_nPoolSize, i);
		DWORD dwAssignedSize = GetPrivateProfileInt(m_szSectionHeader,
														szSection, 0, m_szINIPath);
		if(dwAssignedSize)
		{
			DWORD dwPartSize = dwFileSize / m_nPoolSize;
			if(m_nPoolSize == 1)
			{
				if(dwAssignedSize != dwPartSize)
				{
					bResumeCancel = false;
					break;
				}
			}
			else
			{
				if(i == 0)
				{
					if(dwAssignedSize != dwPartSize)
					{
						bResumeCancel = false;
						break;	
					}
				}
				else if(i == m_nPoolSize-1)
				{
					DWORD dwByteRangeStart = ((dwFileSize/m_nPoolSize)*(i));
					dwPartSize= dwFileSize - dwByteRangeStart;
					if(dwAssignedSize != dwPartSize)
					{
						bResumeCancel = false;
						break;
					}
				}
				else
				{
					DWORD dwByteRangeStart = ((dwFileSize/m_nPoolSize)*(i));
					DWORD dwByteRangeEnd = ((dwFileSize/m_nPoolSize)*(i+1))-1;
					dwPartSize = dwByteRangeEnd - dwByteRangeStart+1;
					if(dwAssignedSize != dwPartSize)
					{
						bResumeCancel = false;
						break;
					}
				}
			}
		}
		else
		{
			bResumeCancel = false;
			break;
		}
	}
	return bResumeCancel;
}

/*--------------------------------------------------------------------------------------
Function       : ResumeDownload
In Parameters  :
Out Parameters : bool
Description    : resume download starts
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadController::ResumeDownload()
{
	TCHAR szSouceUrl[URL_SIZE] = {0};
	GetPrivateProfileString(m_szSectionHeader, _T("SourceUrl"), _T(""), szSouceUrl,
							URL_SIZE, m_szINIPath);
	m_dwCurrentFileSize = GetPrivateProfileInt(m_szSectionHeader, _T("FullFileSize"), 0,m_szINIPath);

	if(m_dwCurrentFileSize == 0)
	{
		return false;
	}

	CDownloadContext *pIExecCurrentContextFirst = new CDownloadContext();
	pIExecCurrentContextFirst->GetHeaderInfo(szSouceUrl, m_sHeaderInfo);
	if(m_sHeaderInfo.dwFileSize == 0)
	{
		return false;
	}
	if(m_dwCurrentFileSize != m_sHeaderInfo.dwFileSize)
	{
		return false;
	}
	bool bETAGMatch = true;
#ifdef DOWNLOAD_BOT
	if(_tcslen(m_sHeaderInfo.szBinaryName) > 0)
	{
		_tcscat_s(m_szDownloadLocalPath,m_sHeaderInfo.szBinaryName);
	}
	else
	{
		tstring strBinaryName;
		CWebParser::GetBinaryName(tstring(m_szUrlPAth),strBinaryName);
		_tcscat_s(m_szDownloadLocalPath,strBinaryName.c_str());
	}
#else
	CDownloadController::m_nPoolSize = GetPrivateProfileInt(m_szSectionHeader,
											_T("NOOFPARTS"), 0, m_szINIPath);
	TCHAR szETAG[MAX_PATH] = {0};
	GetPrivateProfileString(m_szSectionHeader, _T("ETAG"), _T(""), szETAG,
							MAX_PATH, m_szINIPath);
	if((_tcslen(szETAG) > 0) && (_tcslen(m_sHeaderInfo.szETag) > 0) )
	{
		if(_tcsstr(m_sHeaderInfo.szETag,szETAG) == NULL)
		{
			bETAGMatch = false;
		}
	}
	

#endif
	if((!bETAGMatch) || (m_dwCurrentFileSize != m_sHeaderInfo.dwFileSize) || (!VerifyResumeDownloadFiles(m_dwCurrentFileSize)))
	{
		if(pIExecCurrentContextFirst)
		{
			delete pIExecCurrentContextFirst;
			pIExecCurrentContextFirst = NULL;
		}
		return false;
	}
	m_DownloaderThreadPool.CreateThreadPool(CDownloadController::m_nPoolSize);
	for(DWORD i = 0;i < m_nPoolSize;i++)
	{

		CDownloadContext *pIExecCurrentContext = NULL;
		if(i != 0)
		{
			pIExecCurrentContext = new CDownloadContext();
			if(pIExecCurrentContext)
			{
				STRUCT_HEADER_INFO sHeaderInfo = {0};
				pIExecCurrentContext->GetHeaderInfo(szSouceUrl, sHeaderInfo);
			}
		}
		else
		{
			pIExecCurrentContext = pIExecCurrentContextFirst;
		}

		TCHAR szSection[MAX_PATH] = {0};

		pIExecCurrentContext->m_dwPartNo = i;
		pIExecCurrentContext->m_dwTotalParts = m_nPoolSize;

		wcscpy_s(pIExecCurrentContext->m_strLocalFileName, m_szOrgFileName);
		wcscpy_s(pIExecCurrentContext->m_szAppPath, m_szLocalTempDownloadPath);
		
		wsprintf(szSection, _T("PARTS_%ld_%ld_DOWNLOADEDSIZE"), m_nPoolSize, i);
		DWORD dwDownloadedSize = GetPrivateProfileInt(m_szSectionHeader, szSection, 0, m_szINIPath);
		pIExecCurrentContext->m_dwDownloadedSize = dwDownloadedSize;
		
		wsprintf(szSection, _T("PARTS_%ld_%ld_ASSIGNEDSIZE"), m_nPoolSize, i);
		pIExecCurrentContext->m_dwFileSize = GetPrivateProfileInt(m_szSectionHeader,
														szSection, 0, m_szINIPath);

		wsprintf(szSection, _T("PARTS_%ld_%ld_BYTERANGESTART"), m_nPoolSize, i);
		pIExecCurrentContext->m_dwByteRangeStart = GetPrivateProfileInt(m_szSectionHeader,
																		szSection, 0, m_szINIPath);
		wsprintf(szSection, _T("PARTS_%ld_%ld_BYTERANGEEND"), m_nPoolSize, i);
		pIExecCurrentContext->m_dwByteRangeEnd = GetPrivateProfileInt(m_szSectionHeader,
																	szSection, 0, m_szINIPath);

		if(pIExecCurrentContext->m_dwFileSize == dwDownloadedSize)
		{
			pIExecCurrentContext->m_bPartComplete = true;
			pIExecCurrentContext->m_dwByteRangeStart = -1L;
			pIExecCurrentContext->m_dwByteRangeEnd = -1L;
		}
		else
		{
			pIExecCurrentContext->m_bPartComplete = false;
			pIExecCurrentContext->m_dwByteRangeStart +=dwDownloadedSize;// + (dwDownloadedSize?1:0));
		}
		
		pIExecCurrentContext->m_objMsgQueue.m_dwTaskItems = DEFAULT_QUEUE_ITEMS;
		m_DownloaderThreadPool.AssignContext(pIExecCurrentContext);
		pIExecCurrentContext->m_bResumDownload = true;
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : InitController
In Parameters  :
Out Parameters : bool
Description    : Based on COntext Object.It an also be a registry object
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadController::InitController(LPVOID lParam)
{
	LPSTRUCT_DOWNLOAD_INFO pDownloadInfo = (LPSTRUCT_DOWNLOAD_INFO)lParam;

	wcscpy_s(m_szINIPath, m_szLocalTempDownloadPath);
	_tcscpy_s(m_szOrgFileName, pDownloadInfo->szExeName);
	wcscat_s(m_szINIPath, MAX_PATH, pDownloadInfo->szExeName);
	wcscat_s(m_szINIPath, MAX_PATH, _T(".ini"));

#ifdef DOWNLOAD_BOT
	_stprintf_s(m_szDownloadLocalPath,_T("%s%s_"),m_szDownloadLocalPath,pDownloadInfo->szExeName);
#else
#ifndef LIVE_UPDATE
	_stprintf_s(m_szDownloadLocalPath,_T("%s%s"),m_szDownloadLocalPath,pDownloadInfo->szExeName);
#endif
#endif

	//DeleteFolderTree(m_szLocalTempDownloadPath);
	//Get The File Properties
	if(PathFileExists(m_szINIPath))
	{
		if(ResumeDownload())
		{
			g_objLogApp.AddLog1(_T("Start resume download for file %s") ,m_szOrgFileName);
			m_DownloaderThreadPool.RunThreadPool();
			m_bResumeDownload = true;
			return true;
		}
		else
		{
			if(m_sHeaderInfo.dwFileSize == 0)
			{
				g_objLogApp.AddLog1(_T("ResumeDownload cancelled as internet not availble!"));
				return false;
			}
			g_objLogApp.AddLog1(_T("ResumeDownload cancelled for file %s due to server file version mismatch!"), m_szOrgFileName);
			DeleteFolderTree(m_szLocalTempDownloadPath);
		}
	}

	CDownloadContext *pIExecCurrentContext = new CDownloadContext();
	pIExecCurrentContext->GetHeaderInfo(m_szUrlPAth, m_sHeaderInfo);
	if(m_sHeaderInfo.dwFileSize == 0)
	{
		return false;
	}
	if(m_dwCurrentFileSize != m_sHeaderInfo.dwFileSize)
	{
		m_dwCurrentFileSize = m_sHeaderInfo.dwFileSize;
	}
#ifdef DOWNLOAD_BOT
	if(_tcslen(m_sHeaderInfo.szBinaryName) > 0)
	{
		_tcscat_s(m_szDownloadLocalPath,m_sHeaderInfo.szBinaryName);
	}
	else
	{
		tstring strBinaryName;
		CWebParser::GetBinaryName(tstring(m_szUrlPAth),strBinaryName);
		_tcscat_s(m_szDownloadLocalPath,strBinaryName.c_str());
	}
#endif

	DWORD dwFileSize  = m_sHeaderInfo.dwFileSize;
	if(m_dwCurrentFileSize != 0)
	{
		if(m_dwCurrentFileSize != dwFileSize)
		{
			if(dwFileSize)
			{
				g_objLogApp.AddLog1(_T("Serverversion size and actual file size mismatch!"));
			}
			if(pIExecCurrentContext)
			{
				delete pIExecCurrentContext;
				pIExecCurrentContext = NULL;
			}
			return false;
		}
	}
	WritePrivateProfileStringW(m_szSectionHeader, _T("SourceUrl"), m_szUrlPAth,
		m_szINIPath);

	TCHAR szValue[MAX_PATH] = {0};
	wsprintf(szValue, _T("%d"), dwFileSize);
	WritePrivateProfileStringW(m_szSectionHeader, _T("FullFileSize"), szValue, m_szINIPath);
	wsprintf(szValue, _T("%d"), m_nPoolSize);
	WritePrivateProfileStringW(m_szSectionHeader, _T("NOOFPARTS"), szValue, m_szINIPath);
	WritePrivateProfileStringW(m_szSectionHeader, _T("ETAG"), m_sHeaderInfo.szETag, m_szINIPath);
	m_DownloaderThreadPool.CreateThreadPool(CDownloadController::m_nPoolSize);
	for(DWORD i = 0;i < m_nPoolSize;i++)
	{
		TCHAR szSection[URL_SIZE] = {0};
		if(i == 0)
		{
			wcscpy_s(pIExecCurrentContext->m_strLocalFileName, m_szOrgFileName);
			wcscpy_s(pIExecCurrentContext->m_szAppPath, m_szLocalTempDownloadPath);
			pIExecCurrentContext->m_dwPartNo = i;
			pIExecCurrentContext->m_dwTotalParts = m_nPoolSize;
			pIExecCurrentContext->m_dwByteRangeStart = 0;
			pIExecCurrentContext->m_dwByteRangeEnd = (dwFileSize / m_nPoolSize)-1;
			if(m_nPoolSize == 1)
			{
				pIExecCurrentContext->m_dwFileSize = pIExecCurrentContext->m_dwByteRangeEnd+1;
			}
			else
			{
				pIExecCurrentContext->m_dwFileSize = pIExecCurrentContext->m_dwByteRangeEnd+1;
			}
			pIExecCurrentContext->m_objMsgQueue.m_dwTaskItems = DEFAULT_QUEUE_ITEMS;
			m_DownloaderThreadPool.AssignContext(pIExecCurrentContext);
			wsprintf(szValue, _T("%d"), pIExecCurrentContext->m_dwFileSize);
			wsprintf(szSection, _T("PARTS_%ld_%ld_ASSIGNEDSIZE"), m_nPoolSize, i);
			WritePrivateProfileStringW(m_szSectionHeader, szSection, szValue, m_szINIPath);

			wsprintf(szValue, _T("%d"), pIExecCurrentContext->m_dwByteRangeStart);
			wsprintf(szSection, _T("PARTS_%ld_%ld_BYTERANGESTART"), m_nPoolSize, i);
			WritePrivateProfileStringW(m_szSectionHeader, szSection, szValue, m_szINIPath);

			wsprintf(szValue, _T("%d"), pIExecCurrentContext->m_dwByteRangeEnd);
			wsprintf(szSection, _T("PARTS_%ld_%ld_BYTERANGEEND"), m_nPoolSize, i);
			WritePrivateProfileStringW(m_szSectionHeader, szSection, szValue, m_szINIPath);
		}
		else
		{
			CDownloadContext *pIExecCurrentContext = new CDownloadContext();
			pIExecCurrentContext->SetHeaderInfo(m_sHeaderInfo);
			pIExecCurrentContext->m_dwPartNo = i;
			pIExecCurrentContext->m_dwTotalParts = m_nPoolSize;
			pIExecCurrentContext->m_objMsgQueue.m_dwTaskItems = DEFAULT_QUEUE_ITEMS;
			if(i == m_nPoolSize-1)
			{
				pIExecCurrentContext->m_dwByteRangeStart = ((dwFileSize/m_nPoolSize)*(i));
				pIExecCurrentContext->m_dwByteRangeEnd = dwFileSize-1;
				pIExecCurrentContext->m_dwFileSize = (pIExecCurrentContext->m_dwByteRangeEnd 
					- pIExecCurrentContext->m_dwByteRangeStart) + 1;
			}
			else
			{
				pIExecCurrentContext->m_dwByteRangeStart = ((dwFileSize/m_nPoolSize)*(i));
				pIExecCurrentContext->m_dwByteRangeEnd = ((dwFileSize/m_nPoolSize)*(i+1))-1;
				pIExecCurrentContext->m_dwFileSize = pIExecCurrentContext->m_dwByteRangeEnd 
					- pIExecCurrentContext->m_dwByteRangeStart+1;
			}

			wcscpy_s(pIExecCurrentContext->m_strLocalFileName, m_szOrgFileName);
			wcscpy_s(pIExecCurrentContext->m_szAppPath, m_szLocalTempDownloadPath);
			STRUCT_HEADER_INFO sHeaderInfo = {0};
			pIExecCurrentContext->GetHeaderInfo(m_szUrlPAth,sHeaderInfo );
			m_DownloaderThreadPool.AssignContext(pIExecCurrentContext);
			wsprintf(szValue, _T("%d"), pIExecCurrentContext->m_dwFileSize);
			wsprintf(szSection, _T("PARTS_%ld_%ld_ASSIGNEDSIZE"), m_nPoolSize, i);
			WritePrivateProfileStringW(m_szSectionHeader, szSection, szValue, m_szINIPath);

			wsprintf(szValue, _T("%d"), pIExecCurrentContext->m_dwByteRangeStart);
			wsprintf(szSection, _T("PARTS_%ld_%ld_BYTERANGESTART"), m_nPoolSize, i);
			WritePrivateProfileStringW(m_szSectionHeader, szSection, szValue, m_szINIPath);

			wsprintf(szValue, _T("%d"), pIExecCurrentContext->m_dwByteRangeEnd);
			wsprintf(szSection, _T("PARTS_%ld_%ld_BYTERANGEEND"), m_nPoolSize, i);
			WritePrivateProfileStringW(m_szSectionHeader, szSection, szValue, m_szINIPath);
		}

	}
	m_DownloaderThreadPool.RunThreadPool();
	return true;
}


/*--------------------------------------------------------------------------------------
Function       : ControllerThreadProc
In Parameters  : LPVOID lpParameter, 
Out Parameters : DWORD
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
DWORD WINAPI CDownloadController::ControllerThreadProc(LPVOID lpParameter)
{
	__try{
		CDownloadController *pDownloadController = (CDownloadController *)lpParameter;
		pDownloadController->m_dwStartTime = ::GetTickCount();
		for(DWORD i = 0;i<m_nPoolSize;i++)
		{
			pDownloadController->AssignScanUrl(pDownloadController->m_szUrlPAth, 0);
		}
		pDownloadController->NotifyAllContex();
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : NotifyAllContex
In Parameters  :
Out Parameters : bool
Description    : notify all context
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadController::NotifyAllContex()
{
	m_DownloaderThreadPool.WaitForLastOperation();
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : AssignScanUrl
In Parameters  : LPCTSTR szItem, int iItemType, 
Out Parameters : bool
Description    : assign download url
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadController::AssignScanUrl(LPCTSTR szItem, int iItemType)
{
	if(m_nTaskItems >= DEFAULT_QUEUE_ITEMS)
	{
		m_nTaskItems = 0;
		m_nContextIndex++;
		m_pIExecCurrentContext = NULL;
	}

	if(m_nContextIndex >= m_nPoolSize)
	{
		m_nContextIndex = 0;
		m_nTaskItems = 0;
	}
	if(m_pIExecCurrentContext == NULL)
	{
		m_pIExecCurrentContext = (CDownloadContext *)m_DownloaderThreadPool.GetContext(m_nContextIndex);
	}
	if(m_pIExecCurrentContext)
	{
		m_pIExecCurrentContext->m_objMsgQueue.AddQueueItem(szItem, iItemType);
		m_nTaskItems++;
		return true;
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : StartController
In Parameters  : LPVOID pThis, 
Out Parameters : bool
Description    : start controller
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadController::StartController(LPVOID lParam)
{
	m_bStartController = true;
	bool bReturn = false;
	m_lpDownloadInfo = (LPSTRUCT_DOWNLOAD_INFO)lParam;
	if(m_lpDownloadInfo)
	{
		_tcscpy_s(m_szUrlPAth, m_lpDownloadInfo->szMainUrl);
		_tcscpy_s(m_szDownloadLocalPath, m_lpDownloadInfo->szLocalPath);
		_tcscpy_s(m_szLocalTempDownloadPath, m_lpDownloadInfo->szLocalTempDownloadPath);
#ifndef DOWNLOAD_BOT
		TCHAR szLog[MAX_PATH_LENGTH] = {0};
		_tcscpy_s(szLog, m_lpDownloadInfo->szLocalTempDownloadPath);
		_tcscat_s(szLog,DOWNLOAD_STATUS_LOG);
		m_objDownloadStatusLog.Initialize(szLog,true,0,true);
		g_objLogApp.Initialize(szLog,true,0,true);
#endif
		wcscpy_s(m_szSectionHeader, m_lpDownloadInfo->szSectionName);
		m_dwCurrContentLength = m_lpDownloadInfo->dwFileSize;
		if(m_lpDownloadInfo->bCheckMD5)
		{
			if((_tcslen(m_lpDownloadInfo->szFileMD5) > 0) && (_tcsicmp(m_lpDownloadInfo->szFileMD5,_T("NA")) != 0))
			{
				wcscpy_s(m_szFileMD5, m_lpDownloadInfo->szFileMD5);
			}
		}
		m_nPoolSize = m_lpDownloadInfo->dwDownloadThreadCount;
		m_dwCurrentFileSize = m_lpDownloadInfo->dwFileSize;
		m_dwCurrentDownloadStatus = 0;
		if(InitController(lParam))
		{
			DWORD dwThreadId = 0;
			m_hCtrlThread = CreateThread(NULL, 0, ControllerThreadProc, this, 0, &dwThreadId);
			DWORD dwReturn = 0;
			m_objDownloadStatusLog.AddLog1(_T("\r\n%ld:Downloading...:%s\r\n"),::GetCurrentThreadId(), m_szUrlPAth);
			if(m_pIGuiInterface)
			{
				m_pIGuiInterface->SetPercentDownload(2);
			}
			DWORD dwTimeout = 1;
			do{
				dwReturn = WaitForSingleObject(m_hCtrlThread, dwTimeout*1000);
				if(CWinHttpManager::m_lStopDownload)
				{
					return false;
				}
				if(dwReturn == WAIT_TIMEOUT)
				{
					CheckDownloadStatus(dwTimeout);
					if(dwTimeout == 1)
					{
						dwTimeout = STATUS_INTERVAL;
					}
				}
				else
				{
					break;
				}

			}while(dwReturn == WAIT_TIMEOUT);
			m_dwEndTime = ::GetTickCount();
			CheckDownloadStatus(dwTimeout);

			if(m_dwCurrentDownloadStatus >= 100)
			{
				bReturn = JoinDownloadFiles();
#ifdef DOWNLOAD_BOT
				if(bReturn)
				{
					TCHAR szRemotePath[MAX_PATH] = {0};
//					if(m_lpDownloadInfo->wPriority)
//					{
//						_tcscpy_s(szRemotePath, BOT_PRIORITY_FOLDER_PATH);
//					}
//					else
//					{
						_tcscpy_s(szRemotePath, BOT_INPUT_FOLDER_PATH);
//					}

					if(CDownloadMgrController::SendFileToBDB(m_szDownloadLocalPath,szRemotePath,eGEN_FILES))
					{
						//::DeleteFile(m_szDownloadLocalPath);
						tstring strDownloadPath = m_szDownloadLocalPath;
						size_t found = strDownloadPath.rfind(L"\\");
						tstring strBinaryName;
						if(found!=string::npos)
						{
							strBinaryName = strDownloadPath.substr(found+1);
						}
						TCHAR szBackupPath[MAX_PATH] = {0};
						_tcscpy_s(szBackupPath,m_lpDownloadInfo->szBackUpPath);
						_tcscat_s(szBackupPath,strBinaryName.c_str());
						::MoveFile(m_szDownloadLocalPath,szBackupPath);
					}
				}
#endif
			}
			else
			{
				m_objDownloadStatusLog.AddLog1(_T("\r\n%ld:Unable to perform Complete Download at this time...:%s\r\n"),::GetCurrentThreadId(), m_szUrlPAth);
				bReturn = false;
			}
		}
	}
	return bReturn;
}

/*--------------------------------------------------------------------------------------
Function       : StopController
In Parameters  :
Out Parameters : bool
Description    : stop the controller and clean up context
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadController::StopController()
{
	if(!m_bStartController)
	{
		return true;
	}
	__try{

#ifndef DOWNLOAD_BOT 
		CancelDownload();
		m_DownloaderThreadPool.StopThreadPool();
#endif
		if(m_hCtrlThread)
		{
			DWORD dwErr = ::WaitForSingleObject(m_hCtrlThread,3000);
			if(dwErr == WAIT_TIMEOUT)
			{
				::TerminateThread(m_hCtrlThread,0);
			}
			::CloseHandle(m_hCtrlThread);
			m_hCtrlThread = NULL;
		}

		for(DWORD i = 0;i<m_nPoolSize;i++)
		{
			CDownloadContext *pIExecContext = (CDownloadContext *)m_DownloaderThreadPool.GetContext(i);
			if(pIExecContext)
			{
				delete pIExecContext;
				pIExecContext = NULL;
			}
		}
		ResetInitData();
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : CheckDownloadStatus
In Parameters  :
Out Parameters : void
Description    : check download status
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CDownloadController::CheckDownloadStatus(DWORD nPassedSeconds)
{
	TCHAR szSection[URL_SIZE] = {0};
	TCHAR szValue[MAX_PATH] = {0};
	DWORD dwTotalPerc = 0;
	DWORD dwTotalBytes = 0;
	for(DWORD i = 0; i < m_nPoolSize; i++)
	{
		if(CWinHttpManager::m_lStopDownload)
		{
			return;
		}
		CDownloadContext *pIExecContext = (CDownloadContext *)m_DownloaderThreadPool.GetContext(i);
		if(pIExecContext)
		{
			DWORD  dwDownloaded = 0;
			pIExecContext->GetDownloadStatus(dwDownloaded);
			if(dwDownloaded)
			{
				wsprintf(szSection, _T("PARTS_%ld_%ld_DOWNLOADEDSIZE"), pIExecContext->m_dwTotalParts,
					pIExecContext ->m_dwPartNo);
				wsprintf(szValue, _T("%ld"), dwDownloaded);
				dwTotalBytes += dwDownloaded;
				WritePrivateProfileStringW(m_szSectionHeader, szSection, szValue, m_szINIPath);
				if(dwDownloaded)
				{
					DWORD dwPercent = 0;
					if(pIExecContext->m_dwFileSize != 0)
					{
						dwPercent = static_cast<DWORD>(((static_cast<double>(dwDownloaded))/ pIExecContext->m_dwFileSize)*100);
					}
					dwTotalPerc +=dwPercent;
				}
			}
		}
	}
	float dTransferRateKB = 0;
	if(m_dwCurrDownloadedBytes == 0)
	{
		m_dwCurrDownloadedBytes += dwTotalBytes;
	}
	else
	{
		DWORD dwDiff = dwTotalBytes - m_dwCurrDownloadedBytes;
		dTransferRateKB = static_cast<float>(dwDiff)/(nPassedSeconds*1024);
		m_dwCurrDownloadedBytes += dwDiff;
	}
	
	if(m_dwCurrentDownloadStatus < 100)
	{
		m_dwCurrentDownloadStatus = dwTotalPerc/m_nPoolSize;

		if(dTransferRateKB > 0.0f)
		{
			if(m_pIGuiInterface)
			{
				if(m_dwCurrDownloadedBytes != 0)
				{
					m_pIGuiInterface->SetDownloadedBytes(m_dwCurrentFileSize, dwTotalBytes,dTransferRateKB);
					m_pIGuiInterface->SetPercentDownload(dwTotalPerc/m_nPoolSize);
				}
				else
				{
					m_dwCurrDownloadedBytes = dwTotalBytes;
				}
			}
				m_objDownloadStatusLog.AddLog1(_T("%s-> %ld%s:  %0.2f KB/sec\r\n"),m_szOrgFileName, dwTotalPerc/m_nPoolSize,_T("%"),dTransferRateKB);
		}
	}
#ifdef LIVE_UPDATE
	wsprintf(szValue, _T("Total Bytes Download : %ld\n"), dwTotalBytes);
	g_objLogApp.LogCallback(szValue);

	wsprintf(szValue, _T("Total : %ld\n"), dwTotalPerc/m_nPoolSize);
	g_objLogApp.LogCallback(szValue);
#endif
}

/*--------------------------------------------------------------------------------------
Function       : VerifyDownloader
In Parameters  :
Out Parameters : bool
Description    : verify that given download file downloaded successful or not
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadController::VerifyDownloader()
{
	bool bSuccess = true;
	SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, FALSE};
	HANDLE hFile = NULL;
	DWORD dwTotalFileSize = 0;
	for(DWORD i = 0; i < m_nPoolSize; i++)
	{
		CDownloadContext *pIExecContext = (CDownloadContext *)m_DownloaderThreadPool.GetContext(i);
		if(pIExecContext)
		{
			DWORD dwFileSize = GetFileSizeEx(pIExecContext->m_szLocalFilePath);
			dwTotalFileSize += dwFileSize;
			DWORD dwDownloadFileSize = pIExecContext->m_dwFileSize;
			if(dwFileSize !=  dwDownloadFileSize)
			{
				bSuccess = false;
			}
			if(bSuccess == false)
			{
				break;
			}
		}
	}
	if(dwTotalFileSize != m_dwCurrentFileSize)
	{
		bSuccess = false;
	}
	return bSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : JoinDownloadFiles
In Parameters  :
Out Parameters : void
Description    : join the multi part file into one
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadController::JoinDownloadFiles()
{
	if(VerifyDownloader() == false)
	{
		g_objLogApp.AddLog1(_T("VerifyDownloader returns fails. Not match size for all temp download parts!"));
		return false;
	}
	bool bReturn = false;
	TCHAR szBuffer[4096] = {0};
	HANDLE hMainFile = NULL;
	HANDLE hFile = NULL;
	SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, FALSE};
	if((hMainFile = CreateFile(m_szDownloadLocalPath, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
							FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
	{
		bool bSuccess = false;
		for(DWORD i = 0; i < m_nPoolSize; i++)
		{
			bSuccess = false;
			CDownloadContext *pIExecContext = (CDownloadContext *)m_DownloaderThreadPool.GetContext(i);
			if(pIExecContext)
			{
				if((hFile = CreateFile(pIExecContext->m_szLocalFilePath, GENERIC_READ,
					FILE_SHARE_READ, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL))
					!= INVALID_HANDLE_VALUE)
				{
					DWORD dwFileSize = GetFileSize(hFile, NULL);
					DWORD dwDonloadFileSize = pIExecContext->m_dwFileSize;
					if(dwFileSize == dwDonloadFileSize)
					{
						DWORD dwRead = 0;
						do
						{
							if(ReadFile(hFile, szBuffer, 4096, &dwRead, 0))
							{
								if(dwRead)
								{
									DWORD dwSize = 0;
									WriteFile(hMainFile, szBuffer, dwRead, &dwSize, NULL);
								}
							}
						}while(dwRead != 0);
						if(hFile)
						{
							FlushFileBuffers(hFile);
							CloseHandle(hFile);
							hFile = NULL;
						}
						//DeleteFile(pIExecContext->m_szLocalFilePath);
						bSuccess = true;
					}
				}
			}
			if(!bSuccess)
			{
				bReturn = false;
				break;
			}
		}
		DWORD dwMainFileSize = 0;
		if(hMainFile)
		{
			FlushFileBuffers(hMainFile);
			dwMainFileSize = ::GetFileSize(hMainFile,NULL);
			CloseHandle(hMainFile);
			hMainFile = NULL;
		}

		if(bSuccess)
		{
			if((dwMainFileSize != m_dwCurrentFileSize) || (!CheckMD5()))
			{
				DeleteFile(m_szDownloadLocalPath);
				DeleteFile(m_szINIPath);
				g_objLogApp.AddLog1(_T("*** File Size not Matching/MD5 Failed:%d:%d"),dwMainFileSize,m_dwCurrentFileSize);
				bReturn = false;
			}
			else
			{
				//DeleteFile(m_szINIPath);
				bReturn = true;
			}
		}
	}
	return bReturn;
}

/*--------------------------------------------------------------------------------------
Function       : DeleteFolderTree
In Parameters  : CString csFilePath, 
Out Parameters : bool
Description    :
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CDownloadController::DeleteFolderTree(CString csFilePath)
{
#ifndef DOWNLOAD_BOT 
	CFileFind findfile;
	CString csOldFilePath;

	csFilePath += _T("\\*.*");
	//To Check Whether The File Is Exist Or Not
	BOOL bCheck = findfile.FindFile(csFilePath);
	if(!bCheck)
	{
		return false;
	}
	while(bCheck)
	{
		//To Find Next File In Same Directory
		bCheck = findfile.FindNextFile();
		if(findfile.IsDots())
		{
			continue;
		}

		//To get file path
		csFilePath = findfile.GetFilePath();
		csOldFilePath = csFilePath;
		{
			//To set the file attribute to archive
			DWORD dwAttrs = GetFileAttributes(csFilePath);
			if(dwAttrs != INVALID_FILE_ATTRIBUTES && dwAttrs & FILE_ATTRIBUTE_READONLY)
			{
				SetFileAttributes(csFilePath, dwAttrs ^ FILE_ATTRIBUTE_READONLY);
			}
			::DeleteFile(csFilePath);
		}
	}
	//to close handle
	findfile.Close();
#endif
	return true;
}

void CDownloadController::DeleteController()
{
	delete this;
}

void CDownloadController::ProcessQueueItem()
{
#ifdef DOWNLOAD_BOT
	CMaxBotApp* pBotApp = CMaxBotApp::GetInstance();
	CBotContext *pBotContext = &pBotApp->m_ctTopLevelCntxt;
	CAutoThreadSync objAutoThreadSync(_T("AutoThreadSync"));
	while((m_objDownloadPriorityQueue.FetchQueueItem(m_objCurrQueueItem)) || (m_objDownloadQueue.FetchQueueItem(m_objCurrQueueItem)))
	{
		//TODO: If same domain let avoid calling stop controller
		m_sDownloadInfo.dwFileSize = m_objCurrQueueItem.m_dwContentLength;
		m_sDownloadInfo.dwDownloadThreadCount = pBotContext->m_nThreadDomain;
		_tcscpy_s(m_sDownloadInfo.szFileMD5,m_objCurrQueueItem.m_szETAG);
		_tcscpy_s(m_sDownloadInfo.szMainUrl, URL_SIZE, m_objCurrQueueItem.m_strQueueItem.c_str());
		_stprintf_s(m_sDownloadInfo.szSectionName,_T("%d"),m_objCurrQueueItem.m_dwDownloadID);
		_tcscpy_s(m_sDownloadInfo.szExeName, MAX_BINARY_SIZE, m_sDownloadInfo.szSectionName);
		MA_CONTROL_REQUEST oUrlInfo = {0};
		oUrlInfo.DOWNLOAD_TASK_INFORMATION.sMA_Download_Task.dwDownloadID = m_objCurrQueueItem.m_dwDownloadID;
		pBotContext->UpdateDownloadStatus(oUrlInfo, e_URL_Download_Start);
		bool bReturn = StartController((LPVOID)&m_sDownloadInfo);
		if(bReturn)
		{
			pBotContext->UpdateDownloadStatus(oUrlInfo, e_URL_Download_Done);
		}
		else
		{
			pBotContext->UpdateDownloadStatus(oUrlInfo, e_URL_Download_Failed);			
		}
		StopController();
	}
#endif	
}

void CDownloadController::SetGUIInterface(IGUIInterface *pIGUI)
{
	m_pIGuiInterface = pIGUI;	
}

void CDownloadController::CancelDownload()
{
	CWinHttpManager::StopDownload();
}

void CDownloadController::StartDownload()
{
	CWinHttpManager::StartDownload();
}

void CDownloadController::SetThreadPoolStatus(bool bPause)
{
	if(bPause)
	{
		m_DownloaderThreadPool.PauseThreadPool();	
	}
	else
	{
		m_DownloaderThreadPool.ResumeThreadPool();	
	}
}

bool CDownloadController::CheckMD5()
{
	bool bRet = false;
#ifdef LIVE_UPDATE
	if(m_lpDownloadInfo->bCheckMD5)
	{
		TCHAR szMD5[MAX_PATH]={0};
		CCommonFileIntegrityCheck objCreateSignature(_T(""));
		objCreateSignature.GetSignature(m_szDownloadLocalPath, szMD5);
		if(_tcsicmp(m_szFileMD5,szMD5) != 0)
		{
			AddLogEntry(_T("MD5 not match so delete downloaded file! Original MD5 %s and local file MD5 %s"),m_szFileMD5, szMD5);
			bRet = false;
		}
		else
		{
			bRet = true;
		}
	}
#else
	return true;
#endif
	return bRet;
}

bool CDownloadController::CheckForInternetConnection()
{
	return CWinHttpManager::CheckInternetConnection();
}
