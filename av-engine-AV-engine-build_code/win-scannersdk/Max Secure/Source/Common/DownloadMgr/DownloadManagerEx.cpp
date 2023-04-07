#include "pch.h"
#include <afxinet.h>
#include <Wininet.h>
#include "SDSystemInfo.h"
#include "CPUInfo.h"
//#include "VchReg.h"
#include "CommonFileIntegrityCheck.h"
#include "DownloadManagerEx.h"		
//#include "ResourceManager.h"
#include "LiveUpdate.h"
#include "LiveUpdateDLL.h"


#define HTTPBUFFLEN    1024 // Size of HTTP Buffer...
const INTERNET_PORT  FTP_PORT=21;

double CDownloadManagerEx::m_dDownloadedFileSize, CDownloadManagerEx::m_dTotalFileSize;

UINT DownloadURLUsingHTTPInThread(LPVOID lpVoid);

int CDownloadManagerEx::m_iAccessType = -1;
CDownloadManagerEx::CDownloadManagerEx(int iThreadCount)
{
	CCPUInfo objCPUInfo;
	//This will work if default browser have the Internet settings configured
	if(m_iAccessType < 0)
		m_iAccessType = CheckInternet(INTERNET_OPEN_TYPE_PRECONFIG);

	//This will work if Internet doesn't need any proxy
	if(m_iAccessType < 0)
		m_iAccessType = CheckInternet(INTERNET_OPEN_TYPE_DIRECT);

	//Ask user for Proxy
	if(m_iAccessType < 0)
		m_iAccessType = CheckInternet(INTERNET_OPEN_TYPE_PROXY);

	m_iThreadCount = iThreadCount;
	m_pdwFileDownloadedSize = new DWORD[m_iThreadCount];
	m_piIsThreadRunning = new int[m_iThreadCount];
}

CDownloadManagerEx::~CDownloadManagerEx()
{
	if(m_pdwFileDownloadedSize)
		delete [] m_pdwFileDownloadedSize;

	if(m_piIsThreadRunning)
		delete [] m_piIsThreadRunning;
}

DWORD CDownloadManagerEx::CheckInternet(DWORD dwAccessType)
{
	BOOL bInternetFound = FALSE;

	CStringArray csarrPingSites;
	
	{
		if(!theApp.m_bLocalServerUpdate)
		{
				AddLogEntry(L">>>>> CHECK_INTERNET: ",0 , 0, true,LOG_DEBUG);
				csarrPingSites.Add(MAX_CHECK_INTERNET_CONNECTION_1);
				csarrPingSites.Add(MAX_CHECK_INTERNET_CONNECTION_2);
		}
		else
		{
			CString csIPaddress;
			CRegistry objReg;
			objReg.Get(CSystemInfo::m_csProductRegKey, L"LocalIPPath", csIPaddress, HKEY_LOCAL_MACHINE);
			CString csLocalServerVersionFile;
			csLocalServerVersionFile.Format(L"http://%s:3000/ServerVersionEx.txt",csIPaddress);
			csarrPingSites.Add(csLocalServerVersionFile);
		}
	}

	CString csStr;
	for(int iCount = 0; (iCount<csarrPingSites.GetCount()) && (!bInternetFound); iCount++)
	{
//		CInternetSession* pInternetSession = NULL;
//		try
//		{
//			if(dwAccessType == INTERNET_OPEN_TYPE_PROXY)
//			{
//				CString csServer, csPort, csUserName, csPassword;
////				GetProxyDetails(csServer, csUserName, csPassword);	//Commented since if proxy is not set then it asks for proxy each time
//				CString csProxyINI = CSystemInfo::m_strSysDir + PROXYSETTINGS_INI;
//				GetPrivateProfileString(L"Settings", L"ProxyServer", L"", csServer.GetBuffer(100), 100, csProxyINI);
//				csServer.ReleaseBuffer();
//				pInternetSession = new CInternetSession(L"LiveUpdate Session", 1, dwAccessType, csServer);
//			}
//			else
//				pInternetSession = new CInternetSession(L"LiveUpdate Session", 1, dwAccessType);
//
//			char szBuff[1024] = {0};
//			CStdioFile* pFile = pInternetSession->OpenURL(csarrPingSites[iCount]);
//			if(pFile)
//			{
//				if(pFile->Read(szBuff, 1024) > 0)
//				{
//					bInternetFound = TRUE;
//					break;
//				}
//				delete pFile;
//			}
//		}
//		catch(CInternetException* pEx)
//		{
//			pEx->Delete();
//		}
//
//		if(pInternetSession)
//		{
//			pInternetSession->Close();
//			delete pInternetSession;
//			pInternetSession = NULL;
//		}
		CString csResult = L"";
		bInternetFound = CheckInternetPresent(csarrPingSites[iCount],dwAccessType, csResult);
		if(bInternetFound)
		{
			//AddLogEntry(L"OpenURL success");
			break;
		}
	}

	if(bInternetFound)
		return dwAccessType;

	return -1;
}

BOOL CDownloadManagerEx::DownloadURL(CString csSourceURL1, CString csSourceURL2, CString csDestFile, DWORD dwTotalSize, CString csMD5)
{
	BOOL bRetVal = FALSE;

	BOOL bDownload = FALSE;
	if(!bDownload && !csSourceURL1.IsEmpty())
	{
		AddLogEntry(_T("LiveUpdatePath1"));
		bDownload = DownloadURLUsingHTTP(csSourceURL1, csDestFile, dwTotalSize);
	}
	if(!bDownload && !csSourceURL2.IsEmpty())
	{
		AddLogEntry(_T("LiveUpdatePath2"));
		bDownload = DownloadURLUsingHTTP(csSourceURL2, csDestFile, dwTotalSize);
	}
	//Commented Since HTTP is multi threaded and Resume support while FTP is not yet
//	if(!bDownload && !csSourceURL1.IsEmpty())
//		bDownload = DownloadURLUsingFTP(csSourceURL1, csDestFile, dwTotalSize);
//	if(!bDownload && !csSourceURL2.IsEmpty())
//		bDownload = DownloadURLUsingFTP(csSourceURL2, csDestFile, dwTotalSize);

	if(bDownload)
	{
		if(dwTotalSize<=0 || csMD5.IsEmpty())
		{
			bRetVal = TRUE;
		}
		else
		{
			HANDLE hFile = CreateFile(csDestFile, 0, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			DWORD dwLocalFileSize = GetFileSize(hFile, NULL);
			CloseHandle(hFile);
			if(dwTotalSize == dwLocalFileSize)
			{
				TCHAR szMD5[MAX_PATH]={0};
				CCommonFileIntegrityCheck objCreateSignature(_T(""));
				objCreateSignature.GetSignature(csDestFile.GetBuffer(1000), szMD5);
				csDestFile.ReleaseBuffer();
				if(!csMD5.CompareNoCase(szMD5))
				{
					bRetVal = TRUE;
				}
				else
				{
					CString csLog;
					csLog.Format(L"MD5 mismatched. Origional MD5:%s  Downloaded MD5:%s", csMD5, szMD5);
					AddLogEntry(csLog);
				}
			}
			else
			{
				CString csLog;
				csLog.Format(L"File Size mismatched. Origional Size:%d  Downloaded Size:%d", dwTotalSize, dwLocalFileSize);
				AddLogEntry(csLog);
			}
		}
	}

	return bRetVal;
}

CString CDownloadManagerEx::DownloadURLContent(CString csSourceURL)
{
	CString csRetVal = L"";
	/*CInternetSession* pInternetSession = NULL;
	try
	{
		if(m_iAccessType == INTERNET_OPEN_TYPE_PROXY)
		{
			CString csServer, csPort, csUserName, csPassword;
			GetProxyDetails(csServer, csUserName, csPassword);
			pInternetSession = new CInternetSession(L"LiveUpdate Session", 1, m_iAccessType, csServer);
		}
		else
			pInternetSession = new CInternetSession(L"LiveUpdate Session", 1, m_iAccessType);

		char szBuff[1024] = {0};
		CStdioFile* pFile = pInternetSession->OpenURL(csSourceURL);
		while(pFile->Read(szBuff, 1024) > 0)
		{
			csRetVal += szBuff;
			ZeroMemory(szBuff, sizeof(char)*1024);
		}

		delete pFile;
	}
	catch(CInternetException* pEx)
	{
		pEx->Delete();
		csRetVal = L"";
	}

	if(pInternetSession)
	{
		pInternetSession->Close();
		delete pInternetSession;
		pInternetSession = NULL;
	}*/
	CString csResult = L"";
	CheckInternetPresent(csSourceURL,m_iAccessType, csRetVal);
	
	return csRetVal;
}

BOOL CDownloadManagerEx::DownloadURLUsingHTTP(CString csSourceURL, CString csDestFile, DWORD dwTotalSize)
{
	BOOL bRetVal = FALSE;

	//AddLogEntry(L">>>>> DOWNLOADING: " + csSourceURL,LOG_DEBUG);

	//If download size is not known then download complete file in 1 thread only
	int iTotalNoofThreads = m_iThreadCount;
	if(dwTotalSize <= 0)
		iTotalNoofThreads = 1;

	DWORD dwPerThreadSize = dwTotalSize / iTotalNoofThreads;
	int iCount = 0;

	int iStartPos = csDestFile.ReverseFind('\\');
	int iEndPos = csDestFile.ReverseFind('.');
	CString csFileName = csDestFile.Mid(iStartPos+1, iEndPos-iStartPos-1);

	for(iCount=0 ; iCount<iTotalNoofThreads ; iCount++)
	{
		DownloadInfo* pDownloadInfo = new DownloadInfo;
		pDownloadInfo->iThreadID = iCount;
		pDownloadInfo->csSourceURL = csSourceURL;
		pDownloadInfo->csDestFile.Format(L"%s\\DownloadTempFiles\\%s_%d.tmp", CSystemInfo::m_strTempLiveupdate, csFileName, iCount);
		pDownloadInfo->dwStartPos = iCount * dwPerThreadSize;
		if(dwTotalSize)
		{
			if(iCount == iTotalNoofThreads-1)
				pDownloadInfo->dwEndPos = dwTotalSize - 1;
			else
				pDownloadInfo->dwEndPos = pDownloadInfo->dwStartPos + dwPerThreadSize - 1;
		}
		else
			pDownloadInfo->dwEndPos = dwTotalSize;
		pDownloadInfo->pDownloadManagerEx = this;

		m_piIsThreadRunning[iCount] = 1;
		m_pdwFileDownloadedSize[iCount] = 0;

		AfxBeginThread(DownloadURLUsingHTTPInThread, pDownloadInfo);
	}

	BOOL bRunWhile = TRUE;
	while(bRunWhile)
	{
		for(iCount=0 ; iCount<iTotalNoofThreads ; iCount++)
		{
			if(m_piIsThreadRunning[iCount] == 1)
				break;
			else if(m_piIsThreadRunning[iCount] < 0)
			{
				bRunWhile = FALSE;
				break;
			}
		}

		UpdateStatus(dwTotalSize);

		if(iCount == iTotalNoofThreads)
		{
			bRunWhile = FALSE;

			CFile objDestFile;
			objDestFile.Open(csDestFile, CFile::modeCreate | CFile::modeWrite | CFile::shareDenyNone);

			for(int iCount=0 ; iCount<iTotalNoofThreads ; iCount++)
			{
				CString csFile;
				csFile.Format(L"%s\\DownloadTempFiles\\%s_%d.tmp", CSystemInfo::m_strTempLiveupdate, csFileName, iCount);

				CFile objSourceFile;
				objSourceFile.Open(csFile, CFile::modeRead);

				do
				{
					TCHAR szData[1000] = {0};
					UINT uiBytesRead = objSourceFile.Read(szData, 1000);
					if(uiBytesRead)
					{
						objDestFile.Write(szData, uiBytesRead);
					}
					else
						break;
				}while(1);
				objSourceFile.Close();
				DeleteFile(csFile);
			}

			objDestFile.Close();
			bRetVal = TRUE;
		}
		else
			Sleep(500);
	}

	if(bRetVal)
		AddLogEntry(L">>>>> SUCCESS :");
	else
		AddLogEntry(L">>>>> FAILED  :");

	return bRetVal;
}

UINT DownloadURLUsingHTTPInThread(LPVOID lpVoid)
{
	DownloadInfo* pDownloadInfo = (DownloadInfo*)lpVoid;
	if(pDownloadInfo && pDownloadInfo->pDownloadManagerEx)
	{
		if(pDownloadInfo->pDownloadManagerEx->DownloadURLUsingHTTPInThreads(pDownloadInfo->iThreadID,
			pDownloadInfo->csSourceURL, pDownloadInfo->csDestFile, pDownloadInfo->dwStartPos,
			pDownloadInfo->dwEndPos))
		{
			if (theApp.m_bExitThread == false)
			{
				pDownloadInfo->pDownloadManagerEx->m_piIsThreadRunning[pDownloadInfo->iThreadID] = 0;
			}
		}
		else
		{
			if (theApp.m_bExitThread == false)
			{
				pDownloadInfo->pDownloadManagerEx->m_piIsThreadRunning[pDownloadInfo->iThreadID] = -1;
			}
		}
		pDownloadInfo->pDownloadManagerEx = NULL;

		delete pDownloadInfo;
	}
	return 0;
}

BOOL CDownloadManagerEx::DownloadURLUsingHTTPInThreads(int iThreadID, CString csSourceURL, CString csDestFile, DWORD dwStartPos, DWORD dwEndPos)
{
	BOOL bRetVal = FALSE;
	CString csError;
	CString csProxyINI = CSystemInfo::m_strSysDir + PROXYSETTINGS_INI;

	CString csHTTPUserName;
	GetPrivateProfileString(L"Settings", L"HTTPUserName", L"", csHTTPUserName.GetBuffer(100), 100, csProxyINI);
	csHTTPUserName.ReleaseBuffer();

	CString csHTTPPassword;
	GetPrivateProfileString(L"Settings", L"HTTPPassword", L"", csHTTPPassword.GetBuffer(100), 100, csProxyINI);
	csHTTPPassword.ReleaseBuffer();

	CString csProxyUserName;
	GetPrivateProfileString(L"Settings", L"ProxyUserName", L"", csProxyUserName.GetBuffer(100), 100, csProxyINI);
	csProxyUserName.ReleaseBuffer();

	CString csProxyPassword;
	GetPrivateProfileString(L"Settings", L"ProxyPassword", L"", csProxyPassword.GetBuffer(100), 100, csProxyINI);
	csProxyPassword.ReleaseBuffer();

	CString csProxyServer;
	GetPrivateProfileString(L"Settings", L"ProxyServer", L"", csProxyServer.GetBuffer(100), 100, csProxyINI);
	csProxyServer.ReleaseBuffer();

	try
	{
		DWORD dwOffset = 0;
		CFile objFile;
		if(GetFileAttributes(csDestFile) == 0xFFFFFFFF)
		{
			objFile.Open(csDestFile, CFile::modeCreate | CFile::modeWrite | CFile::shareDenyNone);
		}
		else
		{
			if(objFile.Open(csDestFile, CFile::modeReadWrite))
			{
				dwOffset = (DWORD)objFile.SeekToEnd();
				if(dwOffset>0 && ( (dwStartPos + dwOffset) > dwEndPos) )
				{
					objFile.Close();
					DeleteFile(csDestFile);
					objFile.Open(csDestFile, CFile::modeCreate | CFile::modeWrite);

					dwOffset = 0;
				}
				else
				{
					
					if (theApp.m_bExitThread == false)
					{
						m_pdwFileDownloadedSize[iThreadID] = dwOffset;
					}
					
					//m_pdwFileDownloadedSize[iThreadID] = dwOffset;
				}
			}
		}

		if (theApp.m_bExitThread == true)
		{
			return bRetVal;
		}

		DWORD dwServiceType = 0;
		CString csServer, csObject;
		INTERNET_PORT nPort = 0;
		if(!AfxParseURL(csSourceURL, dwServiceType, csServer, csObject, nPort))
		{
			AddLogEntry(L"Failed to parse the URL:  ");
			return bRetVal;
		}

		HINTERNET hInternetSession = NULL;
		if(m_iAccessType == INTERNET_OPEN_TYPE_PROXY)
		{
			CString csServer, csUserName, csPassword;
			GetProxyDetails(csServer, csUserName, csPassword);
			hInternetSession = ::InternetOpen(AfxGetAppName(), m_iAccessType, csServer, NULL, 0);
		}
		else
			hInternetSession = ::InternetOpen(AfxGetAppName(), m_iAccessType, NULL, NULL, 0);

		if(hInternetSession == NULL)
		{
			csError.Format(L"Failed in call to InternetOpen, Error:%d", ::GetLastError());
			AddLogEntry(csError);
		}

		//Make the connection to the HTTP server
		HINTERNET hHttpConnection = NULL;
		if(csHTTPUserName.GetLength())
			hHttpConnection = ::InternetConnect(hInternetSession, csServer, nPort, csHTTPUserName, csHTTPPassword, INTERNET_SERVICE_HTTP, 0, (DWORD)this);
		else
			hHttpConnection = ::InternetConnect(hInternetSession, csServer, nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD)this);

		if(hHttpConnection == NULL)
		{
			csError.Format(L"Failed in call to InternetConnect, Error:%d", ::GetLastError());
			AddLogEntry(csError);
			
			if(hInternetSession)
			{
				InternetCloseHandle(hInternetSession);
			}
			hInternetSession = NULL;

			return bRetVal;
		}

		DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE |INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION;
		if(dwServiceType == AFX_INET_SERVICE_HTTPS)
			dwFlags	|= (INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |INTERNET_FLAG_IGNORE_CERT_DATE_INVALID);

		HINTERNET hHttpFile = NULL;
		LPCTSTR pszAcceptTypes[2] = {0};
		hHttpFile = HttpOpenRequest(hHttpConnection, NULL, csObject, NULL, NULL, pszAcceptTypes, dwFlags, (DWORD)this);
		if(hHttpFile == NULL)
		{
			csError.Format (L"Failed in call to HttpOpenRequest, Error:%d", ::GetLastError());
			AddLogEntry(csError);
			
			if(hHttpConnection)
			{
				InternetCloseHandle(hHttpConnection);
			}
			hHttpConnection = NULL;
			if(hInternetSession)
			{
				InternetCloseHandle(hInternetSession);
			}
			hInternetSession = NULL;
			return bRetVal;
		}

		if(dwEndPos > 0)
		{
			CString csHeader;
			csHeader.Format(L"Range: bytes=%ld-%ld", dwStartPos+dwOffset, dwEndPos);
			BOOL bVal = HttpAddRequestHeaders(hHttpFile, csHeader, csHeader.GetLength(), HTTP_ADDREQ_FLAG_ADD_IF_NEW);
		}
resend:
		//Issue the request
		if(!HttpSendRequest(hHttpFile, NULL, 0, NULL, 0))
		{
			//DWORD dwError = ::GetLastError();
			bool bError = true;
			CString csLog;
			if(dwServiceType == AFX_INET_SERVICE_HTTPS)
			{
				DWORD dwError = GetLastError();

				if (dwError == ERROR_INTERNET_INVALID_CA || dwError == ERROR_INTERNET_SEC_CERT_REV_FAILED) 
				{
					DWORD dwFlags;
					DWORD dwBuffLen = sizeof(dwFlags);
					InternetQueryOption(hHttpFile, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwFlags, &dwBuffLen);

					dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
					dwFlags |= SECURITY_FLAG_IGNORE_REVOCATION;

					InternetSetOption (hHttpFile, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof (dwFlags));
					if(::HttpSendRequest(hHttpFile, NULL, 0, NULL, 0))
					{
						bError = false;
					}
				}
			}
			if(bError)
			{
				if(hHttpFile)
				{
					InternetCloseHandle(hHttpFile);
				}
				hHttpFile = NULL;
				if(hHttpConnection)
				{
					InternetCloseHandle(hHttpConnection);
				}
				hHttpConnection = NULL;
				if(hInternetSession)
				{
					InternetCloseHandle(hInternetSession);
				}
				hInternetSession = NULL;
				csError.Format (L"Failed in call to HttpSendRequest, Error:%d", ::GetLastError());
				AddLogEntry(csError);
				return bRetVal;
			}
		}

		//Handle the status code in the response
		DWORD dwStatusCode = 0;
		DWORD dwSize = sizeof(DWORD);
		if(!::HttpQueryInfo(hHttpFile, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwSize, NULL))
		{
			csError.Format (L"Failed in call to HttpQueryInfo for HTTP query status code, Error:%d", GetLastError());
			AddLogEntry(csError);

			if(hHttpFile)
			{
				InternetCloseHandle(hHttpFile);
			}
			hHttpFile = NULL;
			if(hHttpConnection)
			{
				InternetCloseHandle(hHttpConnection);
			}
			hHttpConnection = NULL;
			if(hInternetSession)
			{
				InternetCloseHandle(hInternetSession);
			}
			hInternetSession = NULL;
			return bRetVal;
		}
		//discard any outstanding data if required
		if(dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ || dwStatusCode  == HTTP_STATUS_DENIED)
		{
			char szData[1024];
			dwSize = 0;
			do
			{
				::InternetReadFile(hHttpFile, szData, sizeof(szData), &dwSize);
			}while(dwSize != 0);
		}

		if(dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ)//Proxy authentication required
		{
			int nProxyUserLength = csProxyUserName.GetLength();
			if(nProxyUserLength == 0)
				GetProxyDetails(csProxyServer, csProxyUserName, csProxyPassword);

			nProxyUserLength = csProxyUserName.GetLength();
			if(nProxyUserLength)
			{
				InternetSetOption(hHttpFile, INTERNET_OPTION_PROXY_USERNAME, (LPVOID)(LPCTSTR)csProxyUserName, (nProxyUserLength+1)* sizeof(TCHAR));
				InternetSetOption(hHttpFile, INTERNET_OPTION_PROXY_PASSWORD, (LPVOID)(LPCTSTR)csProxyPassword, (csProxyPassword.GetLength() +1)* sizeof(TCHAR));
				goto resend;
			}
			else
			{
				csError.Format (L"Failed in call to HttpQueryInfo for HTTP query status code, %d", dwStatusCode);
				AddLogEntry(csError);
				if(hHttpFile)
				{
					InternetCloseHandle(hHttpFile);
				}
				hHttpFile = NULL;
				if(hHttpConnection)
				{
					InternetCloseHandle(hHttpConnection);
				}
				hHttpConnection = NULL;
				if(hInternetSession)
				{
					InternetCloseHandle(hInternetSession);
				}
				hInternetSession = NULL;
				return bRetVal;
			}
		}
		else if(dwStatusCode == HTTP_STATUS_DENIED)//Http authentication
		{
			int nHTTPUserLength = csHTTPUserName.GetLength();
			if(nHTTPUserLength)
			{
				InternetSetOption(hHttpFile, INTERNET_OPTION_USERNAME, (LPVOID)(LPCTSTR)csHTTPUserName, (nHTTPUserLength+1)* sizeof(TCHAR));
				InternetSetOption(hHttpFile, INTERNET_OPTION_PASSWORD, (LPVOID)(LPCTSTR)csHTTPPassword, (csHTTPPassword.GetLength() +1)* sizeof(TCHAR));
				goto resend;
			}
			else
			{
				csError.Format (L"Failed in call to HttpQueryInfo for HTTP query status code, %d", dwStatusCode);
				AddLogEntry(csError);
				if(hHttpFile)
				{
					InternetCloseHandle(hHttpFile);
				}
				hHttpFile = NULL;
				if(hHttpConnection)
				{
					InternetCloseHandle(hHttpConnection);
				}
				hHttpConnection = NULL;
				if(hInternetSession)
				{
					InternetCloseHandle(hInternetSession);
				}
				hInternetSession = NULL;
				return bRetVal;
			}
		}
		else if(dwStatusCode != HTTP_STATUS_OK && dwStatusCode !=HTTP_STATUS_PARTIAL_CONTENT)
		{
			TRACE(L"Failed to retrieve a HTTP OK or partial content status, Status Code:%d\n", dwStatusCode);
			if(hHttpFile)
			{
				InternetCloseHandle(hHttpFile);
			}
			hHttpFile = NULL;
			if(hHttpConnection)
			{
				InternetCloseHandle(hHttpConnection);
			}
			hHttpConnection = NULL;
			if(hInternetSession)
			{
				InternetCloseHandle(hInternetSession);
			}
			hInternetSession = NULL;
			return bRetVal;
		}

		//read File
		int numBytes = 0;
		char szHttpBuff[HTTPBUFFLEN];
		ZeroMemory(szHttpBuff, HTTPBUFFLEN);

		DWORD dwFileDownloadedSize = 0;

		int iPercentage = 0;
		while(InternetReadFile(hHttpFile, szHttpBuff, 1024, (LPDWORD)&numBytes))
		{
			if(numBytes == 0)
				break;

			objFile.Write(szHttpBuff, numBytes);
			if (theApp.m_bExitThread == true)
			{
				break;
			}
			/*if (IsThreadRunningTest == true)
			{
				break;
			}*/
			m_pdwFileDownloadedSize[iThreadID] += numBytes;
		}

		objFile.Close();
		if (theApp.m_bExitThread == false)
		{
			if (dwEndPos)
			{
				if (dwEndPos == dwStartPos + m_pdwFileDownloadedSize[iThreadID] - 1)
					bRetVal = TRUE;
			}
			else
				bRetVal = TRUE;
		}
		

		if(hHttpFile)
		{
			InternetCloseHandle(hHttpFile);
		}
		hHttpFile = NULL;
		if(hHttpConnection)
		{
			InternetCloseHandle(hHttpConnection);
		}
		hHttpConnection = NULL;
		if(hInternetSession)
		{
			InternetCloseHandle(hInternetSession);
		}
		hInternetSession = NULL;
	}
	catch(CInternetException* pEx)
	{
		AddLogEntry(L"Internet Exception occured in DownloadURLUsingHTTPInThreads");
		TCHAR sz[1024];
		pEx->GetErrorMessage(sz, 1024);
		if(pEx->m_dwError == 12007)
		{
			AddLogEntry(sz);
		}

		pEx->Delete();
	}
	catch(...)
	{
		AddLogEntry(L"Exception occured in DownloadURLUsingHTTPInThreads");
	}

	return bRetVal;
}

BOOL CDownloadManagerEx::GetProxyDetails(CString &csProxyServer, CString &csProxyUserName, CString &csProxyPassword)
{
	CSystemInfo objSystem;
	CString csProxyINI = CSystemInfo::m_strSysDir + PROXYSETTINGS_INI;
	BOOL bLoadedFromINI = false;

	csProxyUserName = csProxyPassword = csProxyServer = L"";

	GetPrivateProfileString(L"Settings", L"ProxyServer", L"", csProxyServer.GetBuffer(100), 100, csProxyINI);
	csProxyServer.ReleaseBuffer();

	GetPrivateProfileString(L"Settings", L"ProxyUserName", L"", csProxyUserName.GetBuffer(100), 100, csProxyINI);
	csProxyUserName.ReleaseBuffer();

	GetPrivateProfileString(L"Settings", L"ProxyPassword", L"", csProxyPassword.GetBuffer(100), 100, csProxyINI);
	csProxyPassword.ReleaseBuffer();

	/*
	CVchReg *pVoucherReg = NULL;
	if(csProxyServer.GetLength() == 0)
	{
		pVoucherReg = new CVchReg();
		if(pVoucherReg->LoadedSuccssfully())
		{
			if(pVoucherReg->DoProxySettings())
			{
				GetPrivateProfileString(L"Settings", L"ProxyServer", L"", csProxyServer.GetBuffer(100), 100, csProxyINI);
				csProxyServer.ReleaseBuffer();

				GetPrivateProfileString(L"Settings", L"ProxyUserName", L"", csProxyUserName.GetBuffer(100), 100, csProxyINI);
				csProxyUserName.ReleaseBuffer();

				GetPrivateProfileString(L"Settings", L"ProxyPassword", L"", csProxyPassword.GetBuffer(100), 100, csProxyINI);
				csProxyPassword.ReleaseBuffer();
			}
		}
		delete pVoucherReg;
		pVoucherReg = NULL;
	}
	*/

	return csProxyServer.GetLength();
}

BOOL CDownloadManagerEx::DownloadURLUsingFTP(CString csSourceURL, CString csDestFile, DWORD dwTotalSize)
{
	BOOL bRetVal = FALSE;
	CString csServerName, csObject;
	DWORD dwServiceType;
	INTERNET_PORT nPort;
	if(!AfxParseURL(csSourceURL, dwServiceType, csServerName, csObject, nPort))
	{
		CString csLAstError;
		csLAstError.Format(_T("%d"),::GetLastError());
		AddLogEntry(_T("Failed to parse the URL: Last Error Code:%s "),csLAstError);
		return FALSE;
	}

	CInternetSession* pInternetSession = NULL;
	try
	{
		if(m_iAccessType == INTERNET_OPEN_TYPE_PROXY)
		{
			CString csServer, csPort, csUserName, csPassword;
			GetProxyDetails(csServer, csUserName, csPassword);
			pInternetSession = new CInternetSession(L"LiveUpdate Session", 1, m_iAccessType, csServer);
		}
		else
			pInternetSession = new CInternetSession(L"LiveUpdate Session", 1, m_iAccessType);

		int nConnectionTimeout = 60000;
		pInternetSession->SetOption(INTERNET_OPTION_CONNECT_TIMEOUT, nConnectionTimeout);
		pInternetSession->SetOption(INTERNET_OPTION_RECEIVE_TIMEOUT, nConnectionTimeout);
		pInternetSession->SetOption(INTERNET_OPTION_SEND_TIMEOUT, nConnectionTimeout);
		CString csProxyINI(CSystemInfo::m_strSysDir);
		csProxyINI+="\\Proxysettings.ini";

		CString csProxyServer, csProxyUserName, csProxyPassword;
		GetPrivateProfileString(_T("Settings"), _T("ProxyUserName"), _T(""), csProxyUserName.GetBuffer(100), 100, csProxyINI);
		csProxyUserName.ReleaseBuffer();
		GetPrivateProfileString(_T("Settings"), _T("ProxyPassword"), _T(""), csProxyPassword.GetBuffer(100), 100, csProxyINI);
		csProxyPassword.ReleaseBuffer();
		GetPrivateProfileString(_T("Settings"), _T("ProxyServer"), _T(""), csProxyServer.GetBuffer(100), 100, csProxyINI);
		csProxyServer.ReleaseBuffer();

		if(csProxyUserName != "")
		{
			pInternetSession->SetOption(INTERNET_OPTION_PROXY_USERNAME, (LPVOID)csProxyUserName.operator LPCTSTR(),
								(csProxyUserName.GetLength()+1)* sizeof(TCHAR));
		}
		if(csProxyPassword != "")
		{
			pInternetSession->SetOption(INTERNET_OPTION_PROXY_PASSWORD, (LPVOID)csProxyPassword.operator LPCTSTR(),
								(csProxyPassword.GetLength() +1)* sizeof(TCHAR));
		}

		BOOL m_bPassive = TRUE;
TryPassive:
		CFtpConnection* pConn = NULL;
		int x=0;
		do
		{
			pConn = pInternetSession->GetFtpConnection(csServerName, FTP_USER_NAME, FTP_PASSWORD, FTP_PORT, m_bPassive);
			x++;
		}
		while(pConn == NULL && x<2); //Reatempt to connect
		if(!pConn)
		{
			AddLogEntry(_T("Failed to make FTP connection: "));
			return FALSE;
		}

		CString csCurrentDirectory = FTP_DIR_NAME;
		int nPos = csObject.ReverseFind('/');
		if(nPos != -1)
			csCurrentDirectory = csObject.Left(nPos+1);
		pConn->SetCurrentDirectory(csCurrentDirectory);

		CString csFileName = csSourceURL.Mid(csSourceURL.ReverseFind('/') + 1);
		if(pConn->GetFile(csFileName, csDestFile, false) == FALSE)
		{
			DWORD dwError = GetLastError();
			CString csStr;
			csStr.Format(L"Failed to downloaded, Error %d", dwError);
			AddLogEntry(csStr);

			//Error 12002 set passive flag to false
			//try download
			if(m_bPassive)
			{
				//AddLogEntry(L"Try with m_bPassive = FALSE");
				if(pConn != NULL)
				{
					pConn->Close();
					delete pConn;
				}
				pConn = NULL;
				m_bPassive = FALSE;
				goto TryPassive;
			}

			pInternetSession->Close();
			if(pConn != NULL)
				pConn->Close();
			delete pConn;
			pConn = NULL;
			return FALSE;
		}
		pInternetSession->Close();
		if(pConn  != NULL)
		{
			pConn ->Close();
		}
		delete pConn;
		pConn = NULL;

		bRetVal = TRUE;
	}
	catch (CInternetException* pEx)
	{
		TCHAR szStatus[MAX_PATH];
		pEx->GetErrorMessage(szStatus, _countof(szStatus));
		pEx->Delete();
		AddLogEntry(szStatus);
	}

	if(pInternetSession)
	{
		pInternetSession->Close();
		delete pInternetSession;
		pInternetSession = NULL;
	}

	return bRetVal;
}

void CDownloadManagerEx::UpdateStatus(DWORD dwTotalSize)
{
	if(dwTotalSize)
	{
		double dFileDownloadedSize = 0;
		for(int iCount=0 ; iCount<m_iThreadCount ; iCount++)
		{
			double dVal = m_pdwFileDownloadedSize[iCount];
			//Indicating all threads are not started yet...
			//If net connection breaks...the for resuming again it may toggle between actual & some values.
			//So wait untill all threads starts
			if(dVal == 0)
				return;
			dFileDownloadedSize += dVal;
		}

		m_dDownloadedFileSize = dFileDownloadedSize;
		m_dTotalFileSize = dwTotalSize;
	}
}
BOOL CDownloadManagerEx::CheckInternetPresent(CString csSourceURL, int iAccessType, CString &csResult)
{
	BOOL bRetVal = FALSE;
	CString csError;
	CString csProxyINI = CSystemInfo::m_strSysDir + PROXYSETTINGS_INI;

	CString csHTTPUserName;
	GetPrivateProfileString(L"Settings", L"HTTPUserName", L"", csHTTPUserName.GetBuffer(100), 100, csProxyINI);
	csHTTPUserName.ReleaseBuffer();

	CString csHTTPPassword;
	GetPrivateProfileString(L"Settings", L"HTTPPassword", L"", csHTTPPassword.GetBuffer(100), 100, csProxyINI);
	csHTTPPassword.ReleaseBuffer();

	CString csProxyUserName;
	GetPrivateProfileString(L"Settings", L"ProxyUserName", L"", csProxyUserName.GetBuffer(100), 100, csProxyINI);
	csProxyUserName.ReleaseBuffer();

	CString csProxyPassword;
	GetPrivateProfileString(L"Settings", L"ProxyPassword", L"", csProxyPassword.GetBuffer(100), 100, csProxyINI);
	csProxyPassword.ReleaseBuffer();

	CString csProxyServer;
	GetPrivateProfileString(L"Settings", L"ProxyServer", L"", csProxyServer.GetBuffer(100), 100, csProxyINI);
	csProxyServer.ReleaseBuffer();

	try
	{
		DWORD dwServiceType = 0;
		CString csServer, csObject;
		INTERNET_PORT nPort = 0;
		if(!AfxParseURL(csSourceURL, dwServiceType, csServer, csObject, nPort))
		{
			AddLogEntry(L"Failed to parse the URL:  ");
			return bRetVal;
		}

		HINTERNET hInternetSession = NULL;
		if(m_iAccessType == INTERNET_OPEN_TYPE_PROXY)
		{
			CString csServer, csUserName, csPassword;
			GetProxyDetails(csServer, csUserName, csPassword);
			hInternetSession = ::InternetOpen(AfxGetAppName(), iAccessType, csServer, NULL, 0);
		}
		else
		{
			CString csLog;
			hInternetSession = ::InternetOpen(/*AfxGetAppName()*/_T("LiveUpdateDLL"), iAccessType, NULL, NULL, 0);
			csLog.Format(L"InternetOpen: %d",iAccessType);
			AddLogEntry(csLog);
		}

		if(hInternetSession == NULL)
		{
			csError.Format(L"Failed in call to InternetOpen, Error:%d", ::GetLastError());
			AddLogEntry(csError);
		}

		//Make the connection to the HTTP server
		HINTERNET hHttpConnection = NULL;
		if(csHTTPUserName.GetLength())
			hHttpConnection = ::InternetConnect(hInternetSession, csServer, nPort, csHTTPUserName, csHTTPPassword, INTERNET_SERVICE_HTTP, 0, NULL);
		else
			hHttpConnection = ::InternetConnect(hInternetSession, csServer, nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, NULL);

		if(hHttpConnection == NULL)
		{
			csError.Format(L"Failed in call to InternetConnect, Error:%d", ::GetLastError());
			AddLogEntry(csError);
			
			if(hInternetSession)
			{
				InternetCloseHandle(hInternetSession);
			}
			hInternetSession = NULL;

			return bRetVal;
		}

		
		DWORD dwFlags = INTERNET_NO_CALLBACK | INTERNET_FLAG_FORMS_SUBMIT | INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_PRAGMA_NOCACHE;

		if(dwServiceType == AFX_INET_SERVICE_HTTPS)
		{
			dwFlags	|= (INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID);
		}

		HINTERNET hHttpFile = NULL;
		LPCTSTR pszAcceptTypes[2] = {0};
		hHttpFile = HttpOpenRequest(hHttpConnection, NULL, csObject, NULL, NULL, pszAcceptTypes, dwFlags, NULL);
		if(hHttpFile == NULL)
		{
			csError.Format (L"Failed in call to HttpOpenRequest, Error:%d", ::GetLastError());
			AddLogEntry(csError);
			
			if(hHttpConnection)
			{
				InternetCloseHandle(hHttpConnection);
			}
			hHttpConnection = NULL;
			if(hInternetSession)
			{
				InternetCloseHandle(hInternetSession);
			}
			hInternetSession = NULL;
			return bRetVal;
		}
		
resend:
		//Issue the request
		if(!HttpSendRequest(hHttpFile, NULL, 0, NULL, 0))
		{
		//	DWORD dwError = ::GetLastError();
			bool bError = true;
			CString csLog;
			if(dwServiceType == AFX_INET_SERVICE_HTTPS)
			{
				DWORD dwError = GetLastError();
				if (dwError == ERROR_INTERNET_INVALID_CA || dwError == ERROR_INTERNET_SEC_CERT_REV_FAILED) 
				{
					DWORD dwFlags;
					DWORD dwBuffLen = sizeof(dwFlags);
					InternetQueryOption(hHttpFile, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwFlags, &dwBuffLen);

					dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
					dwFlags |= SECURITY_FLAG_IGNORE_REVOCATION;

					InternetSetOption (hHttpFile, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof (dwFlags));
					if(::HttpSendRequest(hHttpFile, NULL, 0, NULL, 0))
					{
						bError = false;
					}
				}
			}
			if(bError)
			{
				if(hHttpFile)
				{
					InternetCloseHandle(hHttpFile);
				}
				hHttpFile = NULL;
				if(hHttpConnection)
				{
					InternetCloseHandle(hHttpConnection);
				}
				hHttpConnection = NULL;
				if(hInternetSession)
				{
					InternetCloseHandle(hInternetSession);
				}
				hInternetSession = NULL;
				csError.Format (L"Failed in call to HttpSendRequest, Error:%d", ::GetLastError());
				AddLogEntry(csError);
				return bRetVal;
			}
		}

		//Handle the status code in the response
		DWORD dwStatusCode = 0;
		DWORD dwSize = sizeof(DWORD);
		if(!::HttpQueryInfo(hHttpFile, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwSize, NULL))
		{
			csError.Format (L"Failed in call to HttpQueryInfo for HTTP query status code, Error:%d", GetLastError());
			AddLogEntry(csError);

			if(hHttpFile)
			{
				InternetCloseHandle(hHttpFile);
			}
			hHttpFile = NULL;
			if(hHttpConnection)
			{
				InternetCloseHandle(hHttpConnection);
			}
			hHttpConnection = NULL;
			if(hInternetSession)
			{
				InternetCloseHandle(hInternetSession);
			}
			hInternetSession = NULL;
			return bRetVal;
		}
		//discard any outstanding data if required
		if(dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ || dwStatusCode  == HTTP_STATUS_DENIED)
		{
			char szData[1024];
			dwSize = 0;
			do
			{
				::InternetReadFile(hHttpFile, szData, sizeof(szData), &dwSize);
			}while(dwSize != 0);
		}

		if(dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ)//Proxy authentication required
		{
			int nProxyUserLength = csProxyUserName.GetLength();
			if(nProxyUserLength == 0)
				GetProxyDetails(csProxyServer, csProxyUserName, csProxyPassword);

			nProxyUserLength = csProxyUserName.GetLength();
			if(nProxyUserLength)
			{
				InternetSetOption(hHttpFile, INTERNET_OPTION_PROXY_USERNAME, (LPVOID)(LPCTSTR)csProxyUserName, (nProxyUserLength+1)* sizeof(TCHAR));
				InternetSetOption(hHttpFile, INTERNET_OPTION_PROXY_PASSWORD, (LPVOID)(LPCTSTR)csProxyPassword, (csProxyPassword.GetLength() +1)* sizeof(TCHAR));
				goto resend;
			}
			else
			{
				csError.Format (L"Failed in call to HttpQueryInfo for HTTP query status code, %d", dwStatusCode);
				AddLogEntry(csError);
				if(hHttpFile)
				{
					InternetCloseHandle(hHttpFile);
				}
				hHttpFile = NULL;
				if(hHttpConnection)
				{
					InternetCloseHandle(hHttpConnection);
				}
				hHttpConnection = NULL;
				if(hInternetSession)
				{
					InternetCloseHandle(hInternetSession);
				}
				hInternetSession = NULL;
				return bRetVal;
			}
		}
		else if(dwStatusCode == HTTP_STATUS_DENIED)//Http authentication
		{
			int nHTTPUserLength = csHTTPUserName.GetLength();
			if(nHTTPUserLength)
			{
				InternetSetOption(hHttpFile, INTERNET_OPTION_USERNAME, (LPVOID)(LPCTSTR)csHTTPUserName, (nHTTPUserLength+1)* sizeof(TCHAR));
				InternetSetOption(hHttpFile, INTERNET_OPTION_PASSWORD, (LPVOID)(LPCTSTR)csHTTPPassword, (csHTTPPassword.GetLength() +1)* sizeof(TCHAR));
				goto resend;
			}
			else
			{
				csError.Format (L"Failed in call to HttpQueryInfo for HTTP query status code, %d", dwStatusCode);
				AddLogEntry(csError);
				if(hHttpFile)
				{
					InternetCloseHandle(hHttpFile);
				}
				hHttpFile = NULL;
				if(hHttpConnection)
				{
					InternetCloseHandle(hHttpConnection);
				}
				hHttpConnection = NULL;
				if(hInternetSession)
				{
					InternetCloseHandle(hInternetSession);
				}
				hInternetSession = NULL;
				return bRetVal;
			}
		}
		else if(dwStatusCode != HTTP_STATUS_OK && dwStatusCode !=HTTP_STATUS_PARTIAL_CONTENT)
		{
			TRACE(L"Failed to retrieve a HTTP OK or partial content status, Status Code:%d\n", dwStatusCode);
			if(hHttpFile)
			{
				InternetCloseHandle(hHttpFile);
			}
			hHttpFile = NULL;
			if(hHttpConnection)
			{
				InternetCloseHandle(hHttpConnection);
			}
			hHttpConnection = NULL;
			if(hInternetSession)
			{
				InternetCloseHandle(hInternetSession);
			}
			hInternetSession = NULL;
			return bRetVal;
		}

		const int iMaxSize = 3072;//MAX_PATH * iDataSize;
		char szData[iMaxSize] = {0};
		dwSize = 0;
		CString csReturnedData = _T("");
		while(InternetReadFile(hHttpFile, szData, sizeof(szData), &dwSize))
		{
			if(dwSize != 0)
			{
				csReturnedData += CString(CStringA(szData));
				ZeroMemory(szData, iMaxSize);
				bRetVal = TRUE;
			}
			else
			{
				break;
			}
		}
		
		csResult = csReturnedData;
		if(hHttpFile)
		{
			InternetCloseHandle(hHttpFile);
		}
		hHttpFile = NULL;
		if(hHttpConnection)
		{
			InternetCloseHandle(hHttpConnection);
		}
		hHttpConnection = NULL;
		if(hInternetSession)
		{
			InternetCloseHandle(hInternetSession);
		}
		hInternetSession = NULL;
	}
	catch(CInternetException* pEx)
	{
		AddLogEntry(L"Internet Exception occured in DownloadURLUsingHTTPInThreads");
		TCHAR sz[1024];
		pEx->GetErrorMessage(sz, 1024);
		if(pEx->m_dwError == 12007)
		{
			AddLogEntry(sz);
		}

		pEx->Delete();
	}
	catch(...)
	{
		AddLogEntry(L"Exception occured in DownloadURLUsingHTTPInThreads");
	}

	return bRetVal;
}