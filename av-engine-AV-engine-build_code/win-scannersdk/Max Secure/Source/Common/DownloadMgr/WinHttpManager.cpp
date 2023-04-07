
/*======================================================================================
FILE             : WinHttpManager.cpp
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
#include "Logger.h"
#include <atlbase.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

const TCHAR BROWSER_INFO[] = _T("Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; .NET CLR 1.0.3705; .NET CLR 1.1.4322; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729");
const WCHAR *HTTP_TYPES[]  = {L"Accept: image/gif", L"image/x-xbitmap", L"image/jpeg", L"image/pjpeg", L"application/x-shockwave-flash", L"application/x-ms-application", L"application/x-ms-xbap", L"application/vnd.ms-xpsdocument", L"application/xaml+xml", L"application/msword", L"application/vnd.ms-excel", L"application/x-cabinet-win32-x86",L"application/x-pe-win32-x86",L"application/octet-stream",L"application/x-setupscript", L"*/*", NULL};
long CWinHttpManager::m_lStopDownload = 0;
/*--------------------------------------------------------------------------------------
Function       : CWinHttpManager
In Parameters  : void, 
Out Parameters : 
Description    : Constructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CWinHttpManager::CWinHttpManager(void)
{
	m_hSession = NULL;
	m_hConnect = NULL;
	m_hRequest = NULL;
	m_dwCompletedDownloadBytes = 0;
	m_bSharedSession = false;
	m_lStopDownload = 0;
}

/*--------------------------------------------------------------------------------------
Function       : ~CWinHttpManager
In Parameters  : void, 
Out Parameters : 
Description    : destructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CWinHttpManager::~CWinHttpManager(void)
{
	PerformCleanup(eSessionHandle);
}

/*--------------------------------------------------------------------------------------
Function       : CrackURL
In Parameters  : TCHAR * szFullUrl, 
Out Parameters : bool 
Description    : Crack given url
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CWinHttpManager::CrackURL(LPCTSTR szFullUrl)
{
	URL_COMPONENTS urlComp;
	size_t nURLLen = 0;

	wmemset(m_szMainUrl, 0, URL_SIZE);
	wmemset(m_szHostName, 0, MAX_PATH);

	// Initialize the URL_COMPONENTS structure.
	ZeroMemory(&urlComp, sizeof(urlComp));
	urlComp.dwStructSize = sizeof(urlComp);

	// Set required component lengths to non-zero so that they are cracked.
	urlComp.dwSchemeLength    = -1;
	urlComp.dwHostNameLength  = -1;
	urlComp.dwUrlPathLength   = -1;
	urlComp.dwExtraInfoLength = -1;

	// Crack the URL.
	if(WinHttpCrackUrl(szFullUrl, (DWORD)_tcslen(szFullUrl), 0, &urlComp))
	{
		_tcscpy_s(m_szMainUrl, URL_SIZE, urlComp.lpszUrlPath);
		nURLLen = _tcslen(urlComp.lpszUrlPath);
		size_t nHostLen = _tcslen(urlComp.lpszHostName) - nURLLen;
		_tcsncpy_s(m_szHostName, MAX_PATH, urlComp.lpszHostName, nHostLen);
		return true;
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : PerformCleanup
In Parameters  : ConnectionHandle enumConnHandle, 
Out Parameters : void 
Description    : cleanup handles
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CWinHttpManager::PerformCleanup(ConnectionHandle enumConnHandle)
{
	if(enumConnHandle == eRequestHandle || enumConnHandle == eConnectHandle
		|| enumConnHandle == eSessionHandle)
	{
		if(m_hRequest)
		{
			WinHttpCloseHandle(m_hRequest);
			m_hRequest = NULL;
		}
	}
	if(enumConnHandle != eRequestHandle)
	{
		if(!m_bSharedSession)
		{
			if(m_hSession)
			{
				WinHttpCloseHandle(m_hSession);
				m_hSession = NULL;
			}
			if(m_hConnect)
			{
				WinHttpCloseHandle(m_hConnect);
				m_hConnect = NULL;
			}
		}
		else
		{
			m_hSession = NULL;
			m_hConnect = NULL;
			m_bSharedSession = false;
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : Initialize
In Parameters  : LPCTSTR szHost, 
Out Parameters : bool 
Description    : Initialize internet
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CWinHttpManager::Initialize(LPCTSTR szHost, bool bCrackURL)
{
	if(bCrackURL)
	{
		if(CrackURL(szHost) == false)
		{
			g_objLogApp.AddLog1(_T("***CWinHttpManager::Initialize CrackURL connection failed for URL %s"), szHost);
			return false;
		}
	}
	else
	{
		_tcscpy_s(m_szHostName,szHost);
	}
	// Use WinHttpOpen to obtain a session handle.
	if(m_hSession == NULL)
	{
		if(!CheckProxySettings())
		{
			m_hSession = WinHttpOpen(BROWSER_INFO, 
				WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
				WINHTTP_NO_PROXY_NAME, 
				WINHTTP_NO_PROXY_BYPASS, 0);
		}

		// Specify an HTTP server.
		if(m_hSession)
		{
			m_hConnect = WinHttpConnect(m_hSession, m_szHostName, 
				INTERNET_DEFAULT_HTTP_PORT, 0);
			return true;
		}
	}
	else
	{
		return true;
	}
	g_objLogApp.AddLog1(_T("***CWinHttpManager::Initialize connection failed for URL %s"), szHost);
	return false;
}

bool CWinHttpManager::CheckProxySettings()
{
	CRegKey oRegKey;
	if(oRegKey.Open(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", KEY_READ) != ERROR_SUCCESS)
	{
		return false;
	}

	DWORD dwProxyEnabled = 0;
	if(oRegKey.QueryDWORDValue(L"ProxyEnable", dwProxyEnabled) != ERROR_SUCCESS)
	{
		oRegKey.Close();
		return false;
	}
	if(dwProxyEnabled == 0)
	{
		oRegKey.Close();
		return false;
	}

	g_objLogApp.AddLog1(_T("##### Machine has Proxy Settings!"));

	WCHAR szProxyServer[MAX_PATH] = {0};
	ULONG ulBytes = MAX_PATH;
	if(oRegKey.QueryStringValue(L"ProxyServer", szProxyServer, &ulBytes) != ERROR_SUCCESS)
	{
		oRegKey.Close();
		return false;
	}

	oRegKey.Close();

	g_objLogApp.AddLog1(_T("##### Using Proxy Server: %s"), szProxyServer);

	m_hSession = WinHttpOpen(BROWSER_INFO, WINHTTP_ACCESS_TYPE_NAMED_PROXY, szProxyServer, L"<local>", 0);

	if(m_hSession == NULL)
	{
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetHeaderInfo
In Parameters  : int iQueryType, TCHAR * szResults, 
Out Parameters : bool 
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CWinHttpManager::GetHeaderInfo(int iQueryType, LPTSTR szHeaderInfo, DWORD &dwQueryBufLen)
{
	if(m_hConnect == NULL)
	{
		return false;
	}
	if(!m_hRequest)
	{
		if(!CreateRequestHandle(m_szMainUrl))
		{
			g_objLogApp.AddLog1(_T("***URL Doest not exits: %s "),m_szMainUrl);
			return false;
		}
	}

	if(m_hRequest)
	{
		WinHttpQueryHeaders(m_hRequest, iQueryType, WINHTTP_HEADER_NAME_BY_INDEX, 
			szHeaderInfo, &dwQueryBufLen, WINHTTP_NO_HEADER_INDEX);
		return true;
		
	}
	
	g_objLogApp.AddLog1(_T("***WinHttpReceiveResponse failed to connect to host  : %s "),m_szHostName);
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : GetDownloadStatus
In Parameters  : DWORD & dwDownloaded, 
Out Parameters : void 
Description    : retrive download status
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CWinHttpManager::GetDownloadStatus(DWORD & dwDownloaded)
{
	m_objThreadSync.Acquire();
	dwDownloaded = m_dwCompletedDownloadBytes;
	m_objThreadSync.Release();
}

/*--------------------------------------------------------------------------------------
Function       : SetDownloadStatus
In Parameters  : DWORD  dwDownloaded, 
Out Parameters : void 
Description    : set download status
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CWinHttpManager::SetDownloadStatus(DWORD  dwDownloaded)
{
	m_objThreadSync.Acquire();
	m_dwCompletedDownloadBytes = dwDownloaded;
	m_objThreadSync.Release();
}

/*--------------------------------------------------------------------------------------
Function       : CreateRequestHandle
In Parameters  : 
Out Parameters : bool 
Description    : create the internet request handle
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CWinHttpManager::CreateRequestHandle(LPTSTR szURLPath)
{
	if(CWinHttpManager::m_lStopDownload)
	{
		return false;
	}
	// Create an HTTP request handle.
	BOOL bResults = FALSE;
	if(m_hRequest)
	{
		return true;
	}
	if(szURLPath)
	{
		_tcscpy_s(m_szMainUrl,szURLPath);
	}
	
	if(m_hConnect)	
	{
		m_hRequest = WinHttpOpenRequest(m_hConnect, L"GET", m_szMainUrl, NULL, WINHTTP_NO_REFERER, HTTP_TYPES, 0);
	}
	if(m_hRequest)
	{
		//DWORD dwDrainSize = MAX_RESPONSE_DRAIN_SIZE;
		//WinHttpSetOption(m_hRequest,WINHTTP_OPTION_MAX_RESPONSE_DRAIN_SIZE,(LPVOID)&dwDrainSize,sizeof(dwDrainSize));
		// Send a request.
        bResults = WinHttpSendRequest( m_hRequest,
                                       WINHTTP_NO_ADDITIONAL_HEADERS,
                                       0, WINHTTP_NO_REQUEST_DATA, 0, 
                                       0, 0);
		    // End the request.
		if (bResults)
			bResults = WinHttpReceiveResponse( m_hRequest, NULL);
		
		if(bResults)
		{
			DWORD dwStatusCode = 0;
			DWORD dwTemp     = sizeof(dwStatusCode); 
			WinHttpQueryHeaders( m_hRequest, WINHTTP_QUERY_STATUS_CODE| WINHTTP_QUERY_FLAG_NUMBER,NULL, &dwStatusCode, &dwTemp, NULL ); 
			if((dwStatusCode >= HTTP_STATUS_CONTINUE) && (dwStatusCode < HTTP_STATUS_BAD_REQUEST))
			{
				return true;
			}
		}
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : SetByteRange
In Parameters  : DWORD dwByteRangeStart, DWORD dwByteRangeStop, 
Out Parameters : BOOL 
Description    : Set the byte range
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
BOOL CWinHttpManager::SetByteRange(DWORD dwByteRangeStart, DWORD dwByteRangeStop)
{
	if(CWinHttpManager::m_lStopDownload)
	{
		return FALSE;
	}
	BOOL bResults = FALSE;
	TCHAR szByteRange[MAX_PATH]= {0};
	_stprintf_s(szByteRange, MAX_PATH, _T("Range: bytes=%ld-%ld"), dwByteRangeStart, dwByteRangeStop);
	if(m_hRequest)
	{
		bResults = WinHttpAddRequestHeaders(m_hRequest, szByteRange, -1, WINHTTP_ADDREQ_FLAG_ADD);
	}

	// Send a request.
	if(m_hRequest)
	{
		bResults = WinHttpSendRequest(m_hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	}

	if(!bResults)
	{
		g_objLogApp.AddLog1(_T("***SetByteRange Handle failed for: %s:%s "),m_szHostName, m_szMainUrl);
		return bResults;
	}

	// End the request.
	bResults = WinHttpReceiveResponse(m_hRequest, NULL);
	return bResults;
}

/*--------------------------------------------------------------------------------------
Function       : ReadWriteFile
In Parameters  : HANDLE hFile, 
Out Parameters : bool 
Description    : Read Write file from internet
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
void CWinHttpManager::ReadWriteFile(HANDLE hFile)
{
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer = NULL;
	do
	{
		if(CWinHttpManager::m_lStopDownload)
		{
			return;
		}
		dwSize = 0;
		if(!WinHttpQueryDataAvailable(m_hRequest, &dwSize))
		{
			g_objLogApp.AddLog1(_T("Problem with the Host Connection! %s:%s:Error Code:%d"),m_szHostName,m_szMainUrl,::GetLastError());
			return ;
		}
		if(dwSize == 0)
		{
			return ;
		}
		pszOutBuffer = new char[dwSize+1];				// Allocate space for the buffer.
		ZeroMemory(pszOutBuffer, dwSize+1);				// Read the Data.

		if(!WinHttpReadData(m_hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
		{
			CString csLAstError;
			csLAstError.Format(_T("%d"),::GetLastError());
			g_objLogApp.AddLog1(_T("WinHttpReadData Unable to read from Host:%s:%s"), m_szHostName,m_szMainUrl);
			if(pszOutBuffer)
			{
				delete [] pszOutBuffer;
				pszOutBuffer = NULL;
			}
			return ;
		}
		DWORD dwBytesWritten = 0;
		if(FALSE == WriteFile(hFile, pszOutBuffer, dwDownloaded, &dwBytesWritten, NULL))
		{
			if(pszOutBuffer)
			{
				delete [] pszOutBuffer;
				pszOutBuffer = NULL;
			}
			return ;
		}
		FlushFileBuffers(hFile);
		if(pszOutBuffer)
		{
			delete [] pszOutBuffer;
			pszOutBuffer = NULL;
		}
		m_objThreadSync.Acquire();
		m_dwCompletedDownloadBytes += dwBytesWritten;
		m_objThreadSync.Release();

	} while ((dwSize>0) && (!m_lStopDownload));

	return ;
}
bool CWinHttpManager::OpenRequestHandle()
{
	if(m_hRequest)
	{
		WinHttpCloseHandle(m_hRequest);
		m_hRequest = NULL;
	}

	if(m_hConnect)
	{
		m_hRequest = WinHttpOpenRequest(m_hConnect, L"GET", m_szMainUrl, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
	}

	if(!m_hRequest)
	{
		return false;
	}
	return true;
}
/*--------------------------------------------------------------------------------------
Function       : Download
In Parameters  : TCHAR * szLocalFileName, DWORD dwByteRangeStart, 
				DWORD dwByteRangeStop, 
Out Parameters : bool 
Description    : Start download files
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CWinHttpManager::Download(TCHAR * szLocalFileName, DWORD dwByteRangeStart, 
							DWORD dwByteRangeStop)
{
	bool bReturn = false;
	if(OpenRequestHandle() == false)
	{
		return bReturn;
	}

	if(SetByteRange(dwByteRangeStart, dwByteRangeStop) == FALSE)
	{

		return bReturn;
	}

	HANDLE hFile = NULL;
	if(PathFileExists(szLocalFileName))
	{
		hFile = CreateFile(szLocalFileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		SetFilePointer(hFile, m_dwCompletedDownloadBytes, NULL, FILE_BEGIN);
	}
	else
	{
		hFile = CreateFile(szLocalFileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	}

	if(hFile)
	{
		ReadWriteFile(hFile);
		CloseHandle(hFile);
		hFile = NULL;
	}
	return bReturn;
}

bool CWinHttpManager::GetWebPage(LPBYTE lpBuffer, DWORD dwContentLength, DWORD &dwDownloadedLen)
{
	bool bRet = false;
	LPBYTE lpHeadBuf = lpBuffer;
	if(!m_hRequest)
	{
		return false;
	}
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	DWORD dwTotalBytesReceived = 0;
	do
	{
		dwSize = 0;
		if(!WinHttpQueryDataAvailable(m_hRequest, &dwSize))
		{
			g_objLogApp.AddLog1(_T("WinHttpQueryDataAvailable fails due to internet problem! Last error Code: %d"), ::GetLastError());
			goto Quit;
		}
		if(dwSize == 0)
		{
			goto Quit;
		}

		if(!WinHttpReadData(m_hRequest, (LPVOID)lpBuffer, dwSize, &dwDownloaded))
		{
			g_objLogApp.AddLog1(_T("WinHttpReadData fails due to internet problem! Last error Code: %d"), ::GetLastError());
			goto Quit;
		}
		dwTotalBytesReceived += dwDownloaded;
		if(dwTotalBytesReceived >= dwContentLength)
		{
			goto Quit;
		}
		lpBuffer += dwDownloaded;
		
	} while ((dwSize>0) && (!m_lStopDownload));
Quit:
	lpBuffer = lpHeadBuf; 
	if(dwTotalBytesReceived > 0)
	{
		bRet = true;
	}
	dwDownloadedLen = dwTotalBytesReceived;
	return bRet;
}

void CWinHttpManager::StopDownload()
{
	::InterlockedIncrement(&CWinHttpManager::m_lStopDownload);
}

void CWinHttpManager::StartDownload()
{
	::InterlockedExchange(&CWinHttpManager::m_lStopDownload,0);
}

bool CWinHttpManager::CheckInternetConnection()
{
	bool bRet = false;
	CWinHttpManager objTempMgr;
	TCHAR szURL1[MAX_PATH] = MAX_CHECK_INTERNET_CONNECTION_1;
	TCHAR szURL2[MAX_PATH] = MAX_CHECK_INTERNET_CONNECTION_2;

	if(objTempMgr.Initialize(szURL1,true))
	{
		if(objTempMgr.CreateRequestHandle(NULL))
		{
			bRet = true;
		}
	}
	if(!bRet)
	{
		if(objTempMgr.Initialize(szURL2,true))
		{
			if(objTempMgr.CreateRequestHandle(NULL))
			{
				bRet = true;
			}
		}
	}
	return bRet;
}