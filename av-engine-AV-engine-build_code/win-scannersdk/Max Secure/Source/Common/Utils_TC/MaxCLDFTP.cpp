#include "stdafx.h"
#include "MaxCLDFTP.h"

CMaxCLDFTP::CMaxCLDFTP()
{
	memset(m_szSysDir, 0, sizeof(m_szSysDir));
	memset(m_szServerName, 0, sizeof(m_szServerName));
	memset(m_szUserName, 0, sizeof(m_szUserName));
	memset(m_szPassword, 0, sizeof(m_szPassword));
	memset(m_szServerUploadPath, 0, sizeof(m_szServerUploadPath));

	_tcscpy_s(m_szServerName, _countof(m_szServerName), FTP_SERVER_NAME);
	_tcscpy_s(m_szUserName, _countof(m_szUserName), FTP_USER_NAME);
	_tcscpy_s(m_szPassword, _countof(m_szPassword), FTP_PASSWORD);
	_tcscpy_s(m_szServerUploadPath, _countof(m_szServerUploadPath), FTP_SHARED_FILES);

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

CMaxCLDFTP::~CMaxCLDFTP()
{
	DisConnect();

	if(m_hProcHeap && m_byBuffer)
	{
		HeapFree(m_hProcHeap, 0, m_byBuffer);
	}

	m_byBuffer = NULL;
	m_hProcHeap = NULL;
}

bool CMaxCLDFTP::Connect()
{
	try
	{
		if(m_bConnected)
		{
			return m_bConnected;
		}
		/*

		GetConfigurationDynamically();

		

		if(!m_objNetSession.SetOption(INTERNET_OPTION_CONNECT_TIMEOUT, 1000 * 60))
		{
			//AddLogEntry(_T("Timeout set failure\r\n"));
		}

		m_pFTPCon = m_objNetSession.GetFtpConnection(m_szServerName, m_szUserName, m_szPassword, iPort, true);
		if(m_pFTPCon)
		{
			m_bConnected = true;
			return m_bConnected;
		}
		*/

		if(!m_objNetSession.SetOption(INTERNET_OPTION_CONNECT_TIMEOUT, 1000 * 60))
		{
			//AddLogEntry(_T("Timeout set failure\r\n"));
		}

		INTERNET_PORT iPort = 21;
		if(!Configure(FTP_SERVER_NAME, FTP_USER_NAME, FTP_PASSWORD, FTP_SHARED_FILES))
		{
			return m_bConnected;
		}

		m_pFTPCon = m_objNetSession.GetFtpConnection(m_szServerName, m_szUserName, m_szPassword, iPort, true);
		if(m_pFTPCon)
		{
			m_bConnected = true;
			return m_bConnected;
		}

		return m_bConnected;
	}

	catch(CInternetException *pEx)
	{
		TCHAR szErrorText[1024] = {0};

		pEx->GetErrorMessage(szErrorText, _countof(szErrorText));
		//AddLogEntry(_T("\r\nError: "), szErrorText, _T("\r\n"));
		m_pFTPCon = NULL;
		pEx->Delete();
	}

	m_bConnected = false;
	return m_bConnected;
}

bool CMaxCLDFTP::DisConnect()
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

bool CMaxCLDFTP::UploadFile(LPCTSTR szFilePath,LPCTSTR szServerFileName)
{
//	LPCTSTR szServerFileName = NULL;

	if(!szFilePath)
	{
		return false;
	}
	/*
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
	*/
	return UploadFileByName(szFilePath, szServerFileName);
}

bool CMaxCLDFTP::UploadFileByName(LPCTSTR szFilePath, LPCTSTR szServerFileName)
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
		
	}

	return false;
}

bool CMaxCLDFTP::UploadFileByNameAndPath(LPCTSTR szFilePath, LPCTSTR szServerFilePath)
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
			//AddLogEntry(_T("Connection fail: "), m_szServerName);
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

	return false;
}

bool CMaxCLDFTP::Configure(LPCTSTR szServerName, LPCTSTR szUserName, LPCTSTR szPassword, LPCTSTR szServerUploadPath)
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

bool CMaxCLDFTP::CheckInternet(bool bDisplayError)
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
