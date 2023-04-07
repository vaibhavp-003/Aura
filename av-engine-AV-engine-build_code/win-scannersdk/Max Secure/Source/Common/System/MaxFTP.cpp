#include "stdafx.h"
#include "maxftp.h"
#include "SDSystemInfo.h"

CMaxFTP::CMaxFTP()
{
	memset(m_szSysDir, 0, sizeof(m_szSysDir));
	memset(m_szServerName, 0, sizeof(m_szServerName));
	memset(m_szUserName, 0, sizeof(m_szUserName));
	memset(m_szPassword, 0, sizeof(m_szPassword));
	memset(m_szServerUploadPath, 0, sizeof(m_szServerUploadPath));

	//_tcscpy_s(m_szServerName, _countof(m_szServerName), FTP_SERVER_NAME);
	_tcscpy_s(m_szUserName, _countof(m_szUserName), FTP_USER_NAME);
	_tcscpy_s(m_szPassword, _countof(m_szPassword), FTP_PASSWORD);
	_tcscpy_s(m_szServerUploadPath, _countof(m_szServerUploadPath), FTP_SUBMIT_SAMPLES);

	m_pFTPCon = NULL;
	m_bConnected = false;
	m_byBuffer = NULL;
	m_hProcHeap = NULL;

	m_lpfnReporter = NULL;
	m_lpReporterData = NULL;

	m_hProcHeap = GetProcessHeap();
	if(m_hProcHeap)
	{
		m_byBuffer = (LPBYTE)HeapAlloc(m_hProcHeap, HEAP_ZERO_MEMORY, FTP_MAX_READ_BUFFER);
	}

	GetSystemDirectory(m_szSysDir, _countof(m_szSysDir));
}

CMaxFTP::~CMaxFTP()
{
	DisConnect();

	if(m_hProcHeap && m_byBuffer)
	{
		HeapFree(m_hProcHeap, 0, m_byBuffer);
	}

	m_byBuffer = NULL;
	m_hProcHeap = NULL;
}

bool CMaxFTP::Connect()
{
	try
	{
		if(m_bConnected)
		{
			return m_bConnected;
		}

		GetConfigurationDynamically();

		INTERNET_PORT iPort = 21;

		if(!m_objNetSession.SetOption(INTERNET_OPTION_CONNECT_TIMEOUT, 1000 * 60))
		{
			AddLogEntry(_T("Timeout set failure\r\n"));
		}

		m_pFTPCon = m_objNetSession.GetFtpConnection(m_szServerName, m_szUserName, m_szPassword, iPort, true);
		if(m_pFTPCon)
		{
			m_bConnected = true;
			return m_bConnected;
		}

		//if(!Configure(FTP_SERVER_NAME_ATV, FTP_USER_NAME_ATV, FTP_PASSWORD_ATV, FTP_SUBMIT_SAMPLES))
		//{
		//	return m_bConnected;
		//}

		//m_pFTPCon = m_objNetSession.GetFtpConnection(m_szServerName, m_szUserName, m_szPassword, iPort, true);
		//if(m_pFTPCon)
		//{
		//	m_bConnected = true;
		//	return m_bConnected;
		//}

		return m_bConnected;
	}

	catch(CInternetException *pEx)
	{
		TCHAR szErrorText[1024] = {0};

		pEx->GetErrorMessage(szErrorText, _countof(szErrorText));
		AddLogEntry(_T("\r\nError: "), szErrorText, _T("\r\n"));
		m_pFTPCon = NULL;
		pEx->Delete();
	}

	m_bConnected = false;
	return m_bConnected;
}

bool CMaxFTP::DisConnect()
{
	if(m_bConnected && m_pFTPCon)
	{
		m_pFTPCon->Close();
		delete m_pFTPCon;
	}

	m_pFTPCon = NULL;
	m_bConnected = false;
	return true;
}

bool CMaxFTP::UploadFileByDate(LPCTSTR szFilePath)
{
	return true;
}

bool CMaxFTP::UploadFile(LPCTSTR szFilePath)
{
	LPCTSTR szServerFileName = NULL;

	if(!szFilePath)
	{
		return false;
	}

	szServerFileName = _tcsrchr(szFilePath, _T('\\'));
	if(szServerFileName)
	{
		if(0 == (*(szServerFileName + 1)))
		{
			return false;
		}

		szServerFileName++;
	}
	else
	{
		szServerFileName = szFilePath;
	}
	//AddMLHeurLogEntry(szServerFileName);
	//AddMLHeurLogEntry(szFilePath);

	return UploadFileByName(szFilePath, szServerFileName);
}

bool CMaxFTP::UploadFileByName(LPCTSTR szFilePath, LPCTSTR szServerFileName)
{
	bool bUploadSuccess = false;
	int iMaxRetries = 5;
	LPCTSTR lpLastSlash = NULL;
	TCHAR szServerFilePath[MAX_PATH] = {0}, *pSlash = 0;

	try
	{
		if(!szFilePath || !m_szServerUploadPath[0])
		{
			return false;
		}

		if(_tcslen(m_szServerUploadPath) >= _countof(szServerFilePath))
		{
			return false;
		}

		Connect();
		if(!m_bConnected)
		{
			return false;
		}

		_tcscpy_s(szServerFilePath, _countof(szServerFilePath), m_szServerUploadPath);
		pSlash = szServerFilePath;
		while(pSlash)
		{
			pSlash = _tcschr(pSlash, _T('/'));
			if(pSlash)
			{
				*pSlash = _T('\0');
			}

			m_pFTPCon->CreateDirectory(szServerFilePath);
			if(pSlash)
			{
				*pSlash = _T('/');
				pSlash++;
			}
		}

		if(_tcslen(m_szServerUploadPath) + _tcslen(szServerFileName) + 1 >= _countof(szServerFilePath))
		{
			return false;
		}

		_tcscpy_s(szServerFilePath, _countof(szServerFilePath), m_szServerUploadPath);
		_tcscat_s(szServerFilePath, _countof(szServerFilePath), _T("/"));
		_tcscat_s(szServerFilePath, _countof(szServerFilePath), szServerFileName);

		for(int i = 0; !bUploadSuccess && i < iMaxRetries; i++)
		{
			bUploadSuccess = UploadFileByNameAndPath(szFilePath, szServerFilePath);
		}

		return bUploadSuccess;
	}

	catch(CException* error)
	{
		TCHAR szCause[MAX_PATH] = {0};

		error->GetErrorMessage(szCause, _countof(szCause), NULL);
		AddLogEntry(_T("FTP::UploadFileByName Upload error: %s"), szCause);
	}

	return false;
}

bool CMaxFTP::UploadFileByNameAndPath(LPCTSTR szFilePath, LPCTSTR szServerFilePath)
{
	BOOL bError = FALSE;
	BYTE * byBuffer = NULL;
	HANDLE hClientFile = NULL;
	CInternetFile* pServerFile = NULL;
	DWORD dwTotalBytesRead = 0, dwFileSize = 0, dwBufferSize = 0, dwBytesToRead = 0, dwBytesRead = 0;
	int iBlocks = 0;
	TCHAR szCause[255] = {0};

	try
	{
		if(!szFilePath || !szServerFilePath || !m_byBuffer)
		{
			return false;
		}

		Connect();
		if(!m_bConnected)
		{
			AddLogEntry(_T("Connection fail: "), m_szServerName);
			return false;
		}

		hClientFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if(INVALID_HANDLE_VALUE == hClientFile)
		{
			return false;
		}

		m_pFTPCon->Remove(szServerFilePath);
		pServerFile = m_pFTPCon->OpenFile(szServerFilePath, GENERIC_WRITE);
		if(!pServerFile)
		{
			CloseHandle(hClientFile);
			return false;
		}

		dwFileSize = GetFileSize(hClientFile, 0);

		if(m_lpfnReporter)
		{
			iBlocks = dwFileSize > FTP_MAX_READ_BUFFER ? (dwFileSize / FTP_MAX_READ_BUFFER) + 1: 1;
			m_lpReporterData->iStatus = 0;
			m_lpReporterData->iTotalBlocks = iBlocks;
			m_lpfnReporter(m_lpReporterData);
		}

		while(dwTotalBytesRead < dwFileSize)
		{
			dwBytesToRead = dwFileSize - dwTotalBytesRead;
			dwBytesToRead = dwBytesToRead > FTP_MAX_READ_BUFFER ? FTP_MAX_READ_BUFFER : dwBytesToRead;

			if(!ReadFile(hClientFile, m_byBuffer, dwBytesToRead, &dwBytesRead, 0))
			{
				bError = TRUE;
				break;
			}

			if(dwBytesRead != dwBytesToRead)
			{
				bError = TRUE;
				break;
			}

			if(m_lpfnReporter)
			{
				m_lpReporterData->iStatus = 1;
				m_lpfnReporter(m_lpReporterData);
			}

			pServerFile->Write(m_byBuffer, dwBytesRead);
			dwTotalBytesRead += dwBytesRead;

			if(m_lpfnReporter)
			{
				m_lpReporterData->iStatus = 1;
				m_lpfnReporter(m_lpReporterData);
			}
		}

		if(bError)
		{
			goto ERROR_EXIT;
		}

		pServerFile->Close();
		delete pServerFile;
		CloseHandle(hClientFile);

		if(m_lpfnReporter)
		{
			m_lpReporterData->iStatus = 2;
			m_lpfnReporter(m_lpReporterData);
		}

		return true;
	}

	catch(CException* error)
	{
		error->GetErrorMessage(szCause, _countof(szCause), NULL);
		AddLogEntry(_T("FTP::UploadFileByNameAndPath Upload error: %s"), szCause);
	}

ERROR_EXIT:
	if(pServerFile)
	{
		pServerFile->Close();
		delete pServerFile;
		pServerFile = NULL;
	}

	if(INVALID_HANDLE_VALUE != hClientFile)
	{
		CloseHandle(hClientFile);
		hClientFile = INVALID_HANDLE_VALUE;
	}

	m_pFTPCon->Remove(szServerFilePath);
	DisConnect();

	AddLogEntry(_T("UploadFileByNameAndPath() error: "), szCause);
	return false;
}

bool CMaxFTP::Configure(LPCTSTR szServerName, LPCTSTR szUserName, LPCTSTR szPassword, LPCTSTR szServerUploadPath)
{
	bool bSuccess = true;

	if(szServerName)
	{
		if(_tcslen(szServerName) >= _countof(m_szServerName))
		{
			bSuccess = false;
		}
		else
		{
			_tcscpy_s(m_szServerName, _countof(m_szServerName), szServerName);
		}
	}

	if(szUserName)
	{
		if(_tcslen(szUserName) >= _countof(m_szUserName))
		{
			bSuccess = false;
		}
		else
		{
			_tcscpy_s(m_szUserName, _countof(m_szUserName), szUserName);
		}
	}
	
	if(szPassword)
	{
		if(_tcslen(szPassword) >= _countof(m_szPassword))
		{
			bSuccess = false;
		}
		else
		{
			_tcscpy_s(m_szPassword, _countof(m_szPassword), szPassword);
		}
	}
	
	if(szServerUploadPath)
	{
		if(_tcslen(szServerUploadPath) >= _countof(m_szServerUploadPath))
		{
			bSuccess = false;
		}
		else
		{
			_tcscpy_s(m_szServerUploadPath, _countof(m_szServerUploadPath), szServerUploadPath);
		}
	}

	return bSuccess;
}

CString CMaxFTP::GetExternalIPAddress()
{
	CString csRetStatus = L"";
	HINTERNET net = InternetOpen(L"IP retriever",INTERNET_OPEN_TYPE_PRECONFIG,NULL,NULL,0);
	if(!net)
	{
		//AddHeurLogEntry(L"Faild NET!!!");
		return csRetStatus;
	}
	//HINTERNET conn = InternetOpenUrl(net, L"https://myexternalip.com/raw", NULL, 0, INTERNET_FLAG_HYPERLINK, 0);
	HINTERNET conn = InternetOpenUrlA(net, "http://checkip.dyndns.org/", NULL, 0, INTERNET_FLAG_RELOAD, 0);
	if(!conn)
	{
//		AddHeurLogEntry(L"Faild conn!!!");
		return csRetStatus;
	}
	char buffer[100];
	DWORD read;
	if(!InternetReadFile(conn, buffer, sizeof(buffer)/sizeof(buffer[0]), &read))
	{
//		AddHeurLogEntry(L"Faild InternetReadFile!!!");
		return csRetStatus;
	}
	InternetCloseHandle(net);
	return CString(buffer, read);	
}


bool CMaxFTP::SetReporter(LPFN_REPORTER lpfnReporter, LPREPORTER_DATA lpReporterData)
{
	m_lpfnReporter = lpfnReporter;
	m_lpReporterData = lpReporterData;
	return true;
}

bool CMaxFTP::CheckInternet(bool bDisplayError)
{
	CStringArray csPingSiteArr;
	csPingSiteArr.Add(MAX_CHECK_INTERNET_CONNECTION_1);
	csPingSiteArr.Add(MAX_CHECK_INTERNET_CONNECTION_2);
	
	for(int i = 0; i < csPingSiteArr.GetCount(); i++)
	{
		if(InternetCheckConnection(csPingSiteArr.GetAt(i), FLAG_ICC_FORCE_CONNECTION, 0))
		{
			return TRUE;
		}
	}
	return FALSE;
}

bool CMaxFTP::GetProxyDetails(CString &csProxyServer, CString &csProxyUserName, CString &csProxyPassword)
{
	CString		csProxyINI(m_szSysDir);
	csProxyINI += "\\Proxysettings.ini";
	bool bLoadedFromINI = false;
	TCHAR buff[1024];

//LoadFromINI:

	csProxyUserName="";
	csProxyPassword="";
	csProxyServer="";
	GetPrivateProfileString(_T("Settings"), _T("ProxyServer"), _T(""), buff, 100, csProxyINI);
	csProxyServer = buff;
	GetPrivateProfileString(_T("Settings"), _T("ProxyUserName"), _T(""), buff, 100, csProxyINI);
	csProxyUserName = buff;
	GetPrivateProfileString(_T("Settings"), _T("ProxyPassword"), _T(""), buff, 100, csProxyINI);
	csProxyPassword = buff;

	//CVchReg *pVoucherReg = NULL;
	//if((csProxyServer.GetLength() == 0) && !bLoadedFromINI)
	//{
	//	pVoucherReg = new CVchReg();
	//	if(pVoucherReg->LoadedSuccssfully())
	//	{
	//		if(pVoucherReg->DoProxySettings())
	//		{
	//			bLoadedFromINI = true;
	//			goto LoadFromINI;
	//		}
	//	}
	//}
	//if(pVoucherReg)
	//{
	//	delete pVoucherReg;
	//	pVoucherReg = NULL;
	//}
	return (csProxyServer.GetLength() == 0 ? false : true);
}

CString CMaxFTP::GetResponseFromASPPage(CString& csASPPage)
{
#define HTTPBUFLEN    512 // Size of HTTP Buffer...
	char httpbuff[HTTPBUFLEN];
	CString Cause;
	CString strRet = _T("NO");//DEFAULT_SERVERPATH;
	CString csCause;

	if(!CheckInternet())
	{
		return false;
	}

	CString       csError;
	CString       csServer;
	DWORD         dwServiceType=0;
	CString       csObject;
	INTERNET_PORT nPort=0;
	HINTERNET     hInternetSession=NULL;
	HINTERNET     hHttpConnection=NULL;
	HINTERNET     hHttpFile=NULL;

	CString        csProxyServer;
	CString        csProxyUserName;
	CString        csProxyPassword;
	CString        csHTTPUserName;
	CString        csHTTPPassword;
	CString        csUserAgent;


	CString csProxyINI(m_szSysDir);
	csProxyINI+="\\Proxysettings.ini";

	TCHAR buff[1024];
	GetPrivateProfileString(_T("Settings"), _T("HTTPUserName"), _T(""), buff, 100, csProxyINI);

	csHTTPUserName=buff;

	GetPrivateProfileString(_T("Settings"), _T("HTTPPassword"), _T(""), buff, 100, csProxyINI);
	csHTTPPassword=buff;
	GetPrivateProfileString(_T("Settings"), _T("ProxyUserName"), _T(""), buff, 100, csProxyINI);
	csProxyUserName=buff;
	GetPrivateProfileString(_T("Settings"), _T("ProxyPassword"), _T(""), buff, 100, csProxyINI);
	csProxyPassword=buff;
	GetPrivateProfileString(_T("Settings"), _T("ProxyServer"), _T(""), buff, 100, csProxyINI);
	csProxyServer=buff;
	GetPrivateProfileString(_T("Settings"), _T("Connection"), _T(""), buff, 100, csProxyINI);

	try
	{
		if(!AfxParseURL(csASPPage, dwServiceType, csServer, csObject, nPort))
		{
			AddLogEntry(_T("Failed to parse the URL:  ") + csASPPage);
			return strRet;
		}

		hInternetSession = ::InternetOpen(csUserAgent.GetLength()? csUserAgent : AfxGetAppName(), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if(hInternetSession == NULL)
		{
			csError.Format (_T("Failed in call to InternetOpen, Error:%d"), ::GetLastError());
			AddLogEntry(csError);
		}

		//Make the connection to the HTTP server
		ASSERT(hHttpConnection == NULL);
		if(csHTTPUserName.GetLength())
		{
			hHttpConnection = ::InternetConnect(hInternetSession, csServer, nPort, csHTTPUserName, csHTTPPassword, INTERNET_SERVICE_HTTP, 0, (DWORD)this);
		}
		else
		{
			hHttpConnection = ::InternetConnect(hInternetSession, csServer, nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD)this);
		}

		if(hHttpConnection == NULL)
		{
			csError.Format (_T("Failed in call to InternetConnect, Error:%d"), ::GetLastError());
			AddLogEntry(csError);
			return strRet;
		}

		LPCTSTR ppszAcceptTypes[2]={0};
		ASSERT(hHttpFile == NULL);
		DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE |INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION;
		if(dwServiceType == AFX_INET_SERVICE_HTTPS)
		{
			dwFlags	|= (INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |INTERNET_FLAG_IGNORE_CERT_DATE_INVALID);
		}

		hHttpFile = HttpOpenRequest(hHttpConnection, NULL, csObject, _T("HTTP/1.1"), NULL, ppszAcceptTypes, dwFlags, (DWORD)this);
		if(hHttpFile == NULL)
		{
			csError.Format (_T("Failed in call to HttpOpenRequest, Error:%d"), ::GetLastError());
			AddLogEntry(csError);
			return strRet;
		}

resend:
		//Issue the request
		BOOL bSend;
		bSend = ::HttpSendRequest(hHttpFile, NULL, 0, NULL, 0);
		if(!bSend)
		{
			DWORD dwError = ::GetLastError();
			bool bError = true;
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
				csError.Format (_T("Failed in call to HttpSendRequest, Error:%d"), ::GetLastError());
				AddLogEntry(csError);
			}
			return strRet;
		}

		//Handle the status code in the response
		DWORD dwStatusCode = 0;
		DWORD dwSize;
		dwSize = sizeof (DWORD);
		if(!::HttpQueryInfo (hHttpFile, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwSize, NULL))
		{
			DWORD dwError = ::GetLastError();
			csError.Format (_T("Failed in call to HttpQueryInfo for HTTP query status code, Error:%d"), dwError);
			AddLogEntry(csError);
			return strRet;
		}
		//discard any outstanding data if required
		if(dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ || dwStatusCode  == HTTP_STATUS_DENIED)
		{
			char szData[1024];
			dwSize = 0;
			do
			{
				::InternetReadFile(hHttpFile, szData, sizeof(szData), &dwSize);
			}
			while (dwSize != 0);
		}

		if(dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ)//Proxy authentication required
		{
			int nProxyUserLength = csProxyUserName.GetLength();
			if(nProxyUserLength == 0)
			{
				GetProxyDetails(csProxyServer, csProxyUserName, csProxyPassword);
			}
			nProxyUserLength = csProxyUserName.GetLength();
			if(nProxyUserLength)
			{
				InternetSetOption(hHttpFile, INTERNET_OPTION_PROXY_USERNAME, 
							(LPVOID)csProxyUserName.operator LPCTSTR(),
							(nProxyUserLength+1)* sizeof(TCHAR));
				InternetSetOption(hHttpFile, INTERNET_OPTION_PROXY_PASSWORD, 
							(LPVOID)csProxyPassword.operator LPCTSTR(), 
							(csProxyPassword.GetLength() +1)* sizeof(TCHAR));
				goto resend;
			}
			else
			{
				csError.Format (_T("Failed in call to HttpQueryInfo for HTTP query status code, %d"), dwStatusCode);
				AddLogEntry(csError);
				return strRet;
			}
		}
		else if(dwStatusCode == HTTP_STATUS_DENIED)//Http authentication
		{
			int nHTTPUserLength = csHTTPUserName.GetLength();
			if(nHTTPUserLength)
			{
				InternetSetOption(hHttpFile, INTERNET_OPTION_USERNAME, 
								(LPVOID)csHTTPUserName.operator LPCTSTR(), 
								(nHTTPUserLength+1)* sizeof(TCHAR));
				InternetSetOption(hHttpFile, INTERNET_OPTION_PASSWORD, 
								(LPVOID)csHTTPPassword.operator LPCTSTR(), 
								(csHTTPPassword.GetLength() +1)* sizeof(TCHAR));
				goto resend;
			}
			else
			{
				csError.Format (_T("Failed in call to HttpQueryInfo for HTTP query status code, %d"), dwStatusCode);
				AddLogEntry(csError);
				return strRet;
			}
		}
		else if(dwStatusCode != HTTP_STATUS_OK && dwStatusCode !=HTTP_STATUS_PARTIAL_CONTENT)
		{
			TRACE(_T("Failed to retrieve a HTTP OK or partial content status, Status Code:%d\n"), dwStatusCode);
			return strRet;
		}

		//read File
		int numBytes;
		ZeroMemory(httpbuff, 512);
		while(InternetReadFile(hHttpFile, httpbuff, HTTPBUFLEN, (LPDWORD)&numBytes))
		{
			if(numBytes == 0)
			{
				break;
			}
			csCause.Format(_T("%S"), httpbuff);
			if(Cause.Find(_T("ERROR")) != -1 || Cause.Find(_T("following")) != -1 ||
				Cause.Find(_T("encountered")) != -1 || Cause.Find(_T("Error")) != -1 ||
				csCause.Find(_T("Socket Error")) != -1)
			{
				csCause.Format(_T("NO"));
			}
			strRet = httpbuff;
			strRet.Trim();
			int iFind = strRet.Find(_T("Uploadstandalone/"));
			if(iFind != -1)
			{
				strRet = strRet.Mid(0, iFind + 17);
			}
		}
		InternetCloseHandle(hHttpFile);
		int iFind = strRet.ReverseFind('/');
		if(iFind != -1)
		{
			strRet = strRet.Mid(0, iFind+1);
		}
		return strRet;
	}
	catch(CInternetException* pEx)
	{
		csCause = _T("NO");
		TCHAR sz[1024];
		pEx->GetErrorMessage(sz, 1024);
		if(pEx->m_dwError == 12007)
		{
			AddLogEntry(sz); //DisplayError(true);
		}
		pEx->Delete();
		return strRet;
	}
}

CString CMaxFTP::GetResponseFromASPPage(CString& csASPPage, CString csDest)
{
#define HTTPBUFLEN    1024 // Size of HTTP Buffer...
	char httpbuff[HTTPBUFLEN];
	CString Cause;
	CString strRet = _T("NO");//DEFAULT_SERVERPATH;
	CString csCause;

	if(!CheckInternet())
	{
		return false;
	}

	CString       csError;
	CString       csServer;
	DWORD         dwServiceType=0;
	CString       csObject;
	INTERNET_PORT nPort=0;
	HINTERNET     hInternetSession=NULL;
	HINTERNET     hHttpConnection=NULL;
	HINTERNET     hHttpFile=NULL;

	CString        csProxyServer = _T("");
	CString        csProxyUserName = _T("");
	CString        csProxyPassword = _T("");
	CString        csHTTPUserName = _T("");
	CString        csHTTPPassword = _T("");
	CString        csUserAgent = _T("");
	CFile m_File;

	try
	{
		if(!AfxParseURL(csASPPage, dwServiceType, csServer, csObject, nPort))
		{
			AddLogEntry(_T("Failed to parse the URL:  ") + csASPPage);
			return strRet;
		}

		hInternetSession = ::InternetOpen(csUserAgent.GetLength()? csUserAgent : AfxGetAppName(), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if(hInternetSession == NULL)
		{
			csError.Format (_T("Failed in call to InternetOpen, Error:%d"), ::GetLastError());
			AddLogEntry(csError);
		}

		//Make the connection to the HTTP server
		ASSERT(hHttpConnection == NULL);
		hHttpConnection = ::InternetConnect(hInternetSession, csServer, nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD)this);
		
		if(hHttpConnection == NULL)
		{
			csError.Format (_T("Failed in call to InternetConnect, Error:%d"), ::GetLastError());
			AddLogEntry(csError);
			return strRet;
		}

		LPCTSTR ppszAcceptTypes[2]={0};
		ASSERT(hHttpFile == NULL);
		DWORD dwFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE |INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION;
		if(dwServiceType == AFX_INET_SERVICE_HTTPS)
		{
			dwFlags	|= (INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |INTERNET_FLAG_IGNORE_CERT_DATE_INVALID);
		}

		hHttpFile = HttpOpenRequest(hHttpConnection, NULL, csObject, _T("HTTP/1.1"), NULL, ppszAcceptTypes, dwFlags, (DWORD)this);
		if(hHttpFile == NULL)
		{
			csError.Format (_T("Failed in call to HttpOpenRequest, Error:%d"), ::GetLastError());
			AddLogEntry(csError);
			return strRet;
		}

resend:
		//Issue the request
		BOOL bSend;
		bSend = ::HttpSendRequest(hHttpFile, NULL, 0, NULL, 0);
		if(!bSend)
		{
			DWORD dwError = ::GetLastError();
			bool bError = true;
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
				csError.Format (_T("Failed in call to HttpSendRequest, Error:%d"), ::GetLastError());
				AddLogEntry(csError);
				return strRet;
			}
		}

		//Handle the status code in the response
		DWORD dwStatusCode = 0;
		DWORD dwSize;
		dwSize = sizeof (DWORD);
		if(!::HttpQueryInfo (hHttpFile, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwSize, NULL))
		{
			DWORD dwError = ::GetLastError();
			csError.Format (_T("Failed in call to HttpQueryInfo for HTTP query status code, Error:%d"), dwError);
			AddLogEntry(csError);
			return strRet;
		}
		//discard any outstanding data if required
		if(dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ || dwStatusCode  == HTTP_STATUS_DENIED)
		{
			char szData[1024];
			dwSize = 0;
			do
			{
				::InternetReadFile(hHttpFile, szData, sizeof(szData), &dwSize);
			}
			while (dwSize != 0);
		}

		if(dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ)//Proxy authentication required
		{
			int nProxyUserLength = csProxyUserName.GetLength();
			if(nProxyUserLength == 0)
			{
				GetProxyDetails(csProxyServer, csProxyUserName, csProxyPassword);
			}
			nProxyUserLength = csProxyUserName.GetLength();
			if(nProxyUserLength)
			{
				InternetSetOption(hHttpFile, INTERNET_OPTION_PROXY_USERNAME, 
							(LPVOID)csProxyUserName.operator LPCTSTR(),
							(nProxyUserLength+1)* sizeof(TCHAR));
				InternetSetOption(hHttpFile, INTERNET_OPTION_PROXY_PASSWORD, 
							(LPVOID)csProxyPassword.operator LPCTSTR(), 
							(csProxyPassword.GetLength() +1)* sizeof(TCHAR));
				goto resend;
			}
			else
			{
				csError.Format (_T("Failed in call to HttpQueryInfo for HTTP query status code, %d"), dwStatusCode);
				AddLogEntry(csError);
				return strRet;
			}
		}
		else if(dwStatusCode == HTTP_STATUS_DENIED)//Http authentication
		{
			int nHTTPUserLength = csHTTPUserName.GetLength();
			if(nHTTPUserLength)
			{
				InternetSetOption(hHttpFile, INTERNET_OPTION_USERNAME, 
								(LPVOID)csHTTPUserName.operator LPCTSTR(), 
								(nHTTPUserLength+1)* sizeof(TCHAR));
				InternetSetOption(hHttpFile, INTERNET_OPTION_PASSWORD, 
								(LPVOID)csHTTPPassword.operator LPCTSTR(), 
								(csHTTPPassword.GetLength() +1)* sizeof(TCHAR));
				goto resend;
			}
			else
			{
				csError.Format (_T("Failed in call to HttpQueryInfo for HTTP query status code, %d"), dwStatusCode);
				AddLogEntry(csError);
				return strRet;
			}
		}
		else if(dwStatusCode != HTTP_STATUS_OK && dwStatusCode !=HTTP_STATUS_PARTIAL_CONTENT)
		{
			TRACE(_T("Failed to retrieve a HTTP OK or partial content status, Status Code:%d\n"), dwStatusCode);
			return strRet;
		}
		unsigned int nTotalRead = 0;
		if(m_File.Open(csDest, CFile::modeCreate | CFile::modeWrite, NULL) == FALSE)
		{
			return strRet;
		}

		//read File
		int numBytes = 0;;
		ZeroMemory(httpbuff, HTTPBUFLEN);
		int total = 0;
		while(InternetReadFile(hHttpFile, httpbuff, HTTPBUFLEN, (LPDWORD)&numBytes))
		{
			if(numBytes == 0)
			{
				break;
			}
			m_File.Write(httpbuff, numBytes);
			nTotalRead += numBytes;
			total++;
		}
		m_File.Close();
		InternetCloseHandle(hHttpFile);
		int iFind = strRet.ReverseFind('/');
		if(iFind != -1)
		{
			strRet = strRet.Mid(0, iFind+1);
		}
		return strRet;
	}
	catch(CInternetException* pEx)
	{
		csCause = _T("NO");
		TCHAR sz[1024];
		pEx->GetErrorMessage(sz, 1024);
		if(pEx->m_dwError == 12007)
		{
			AddLogEntry(sz); //DisplayError(true);
		}
		pEx->Delete();
		return strRet;
	}
}

bool CMaxFTP::GetConfigurationDynamically(CString csURL)
{
	CString csResponse;

	if(m_szServerName[0])
	{
		return true;
	}

	csResponse = GetResponseFromASPPage(csURL);
	if(_T("") == csResponse)
	{
		return false;
	}

	if(_tcslen(csResponse) >= _countof(m_szServerName))
	{
		return false;
	}

	_tcscpy_s(m_szServerName, _countof(m_szServerName), csResponse);
	return true;
}

bool CMaxFTP::GetServerDateTime(LPCTSTR szUniqueStr, CString& csDate, CString& csTime)
{
	CString csServerTempFile, csCommand, csCmdResponse;;
	SYSTEMTIME stFileTime = {0};
	FILETIME ftFileTime = {0};
	CInternetFile * pInternetFile = 0;

	try
	{
		if(!m_bConnected && !Connect())
		{
			return false;
		}

		//GetLocalTime(&stFileTime);
		//SystemTimeToFileTime(&stFileTime, &ftFileTime);
		//csServerTempFile.Format(_T("%s/%s-%08x-%08X%08X.TXT"), m_szServerUploadPath, szUniqueStr,
		//						GetTickCount(), ftFileTime.dwHighDateTime, ftFileTime.dwLowDateTime);
		csServerTempFile.Format(_T("%s/%s.txt"), m_szServerUploadPath, szUniqueStr);

		pInternetFile = m_pFTPCon->OpenFile(csServerTempFile, GENERIC_WRITE, FTP_TRANSFER_TYPE_BINARY);
		if(NULL == pInternetFile)
		{
			return false;
		}

		pInternetFile->Close();
		pInternetFile = NULL;

		//csCommand.Format(_T("MDTM %s\r\n"), csServerTempFile);
		csCommand.Format(_T("CWD /NewThreat\r\n"), csServerTempFile);
		pInternetFile = m_pFTPCon->Command(csCommand, CFtpConnection::CmdRespRead);
		ULONGLONG iReadTillNow = 0, iResponseLength = pInternetFile->GetLength();
		while(iReadTillNow < iResponseLength)
		{
			pInternetFile->ReadString(csCmdResponse);
			iReadTillNow = csCmdResponse.GetLength();
		}

		CFtpFileFind finderRemote(m_pFTPCon);
		if(!finderRemote.FindFile(csServerTempFile))
		{
			m_pFTPCon->Remove(csServerTempFile);
			return false;
		}

		finderRemote.FindNextFile();
		if(!finderRemote.GetLastWriteTime(&ftFileTime))
		{
			finderRemote.Close();
			m_pFTPCon->Remove(csServerTempFile);
			return false;
		}

		finderRemote.Close();
		//m_pFTPCon->Remove(csServerTempFile);

		FileTimeToSystemTime(&ftFileTime, &stFileTime);
		csDate.Format(_T("%04i-%02i-%02i"), stFileTime.wYear, stFileTime.wMonth, stFileTime.wDay);
		csTime.Format(_T("%02i-%02i-%02i"), stFileTime.wHour, stFileTime.wMinute, stFileTime.wSecond);
		return true;
	}

	catch(CException* error)
	{
		TCHAR szCause[MAX_PATH] = {0};
		error->GetErrorMessage(szCause, _countof(szCause), NULL);
		AddLogEntry(_T("FTP::GetServerDateTime failed: %s"), szCause);
	}

	if(pInternetFile)
	{
		pInternetFile->Close();
		pInternetFile = NULL;
	}

	return false;
}

bool CMaxFTP::UploadExportLogFile(LPCTSTR szFilePath, CString csMachineID)
{
	LPCTSTR szServerFileName = NULL;
	TCHAR szFullServerFileName[MAX_PATH] = {0};
	TCHAR *szMachineID = new TCHAR[csMachineID.GetLength() + 1];
	_tcscpy(szMachineID, csMachineID);

	__int64 iCurTimeStamp = (__int64)_time64(NULL);
	CString csTimeStamp;
	csTimeStamp.Format(L"%d", iCurTimeStamp);
	TCHAR *szTimeSTAMP = new TCHAR[csTimeStamp.GetLength() + 1];
	_tcscpy(szTimeSTAMP, csTimeStamp);
	

	if(!szFilePath)
	{
		return false;
	}

	szServerFileName = _tcsrchr(szFilePath, _T('\\'));
	if(szServerFileName)
	{
		if(0 == (*(szServerFileName + 1)))
		{
			return false;
		}

		szServerFileName++;
	}
	else
	{
		szServerFileName = szFilePath;
	}

	_tcscpy_s(szFullServerFileName, _countof(szFullServerFileName), szMachineID);
	_tcscat_s(szFullServerFileName, _countof(szFullServerFileName), _T("_"));
	_tcscat_s(szFullServerFileName, _countof(szFullServerFileName), szTimeSTAMP);
	_tcscat_s(szFullServerFileName, _countof(szFullServerFileName), _T("_"));
	_tcscat_s(szFullServerFileName, _countof(szFullServerFileName), szServerFileName);

	delete[] szMachineID;
	delete[] szTimeSTAMP;

	return UploadFileByName(szFilePath, szFullServerFileName);
}

bool CMaxFTP::UploadFileEx(LPCTSTR szFilePath,LPCTSTR szServerFileName)
{
	if(!szFilePath)
	{
		return false;
	}

	return UploadFileByName(szFilePath, szServerFileName);
}