#include "MaxThreatDataMgr.h"
#include "CPUInfo.h"
#include "MaxCLDFTP.h"
#include "SDKSettings.h"


CMaxThreatDataMgr::CMaxThreatDataMgr(void)
{
	m_hInternetSession = NULL;
	m_hHttpConnection = NULL;

	CSDKSettings objSDKSettings;
	CString csAppPath = objSDKSettings.GetProductAppPath();
	csAppPath +=_MAX_THREAT_INTELLIGENCE_DB;	
	_tcscpy(m_szScanSQLDB,csAppPath);
	m_pSQLiteMgr=NULL;
	m_pSQLiteMgr= new CMaxSqliteMgr(m_szScanSQLDB);
}

CMaxThreatDataMgr::~CMaxThreatDataMgr(void)
{
	
	if(m_pSQLiteMgr)
	{
		delete m_pSQLiteMgr;
		m_pSQLiteMgr=NULL;
	}
	
}


CString	CMaxThreatDataMgr::UploadDatatoPortal(CString cszData2Send, int iDataSize)
{
	CString       csServer, csObject;
	DWORD         dwServiceType = 0;
	HINTERNET     hHttpFile = NULL;
	INTERNET_PORT nPort  = 0;
	DWORD dwSize;
	TCHAR szBuffer[MAX_PATH] = {0};

	m_hInternetSession = NULL;
	m_hHttpConnection = NULL;

	CCPUInfo objCPUInfo;
	CString csProxyINI = objCPUInfo.GetSystemDir() + PROXYSETTINGS_INI;
	ConnectionType  nConnectionType;
	CString csProxyServer, csProxyUserName, csProxyPassword, csHTTPUserName, csHTTPPassword;

	GetPrivateProfileString(_T("Settings"), _T("HTTPUserName"), BLANKSTRING, szBuffer, MAX_PATH, csProxyINI);
	csHTTPUserName = szBuffer;
	
	GetPrivateProfileString(_T("Settings"), _T("HTTPPassword"), BLANKSTRING, szBuffer, MAX_PATH, csProxyINI);
	csHTTPPassword = szBuffer;
	
	GetPrivateProfileString(_T("Settings"), _T("ProxyUserName"), BLANKSTRING, szBuffer, MAX_PATH, csProxyINI);
	csProxyUserName = szBuffer;
	
	GetPrivateProfileString(_T("Settings"), _T("ProxyPassword"), BLANKSTRING, szBuffer, MAX_PATH, csProxyINI);
	csProxyPassword = szBuffer;
	
	GetPrivateProfileString(_T("Settings"), _T("ProxyServer"), BLANKSTRING, szBuffer, MAX_PATH, csProxyINI);
	csProxyServer = szBuffer;
	
	GetPrivateProfileString(_T("Settings"), _T("Connection"), _T("0"), szBuffer, MAX_PATH, csProxyINI);
	nConnectionType = (ConnectionType)_wtoi(szBuffer);
	
	try
	{
		if(!AfxParseURL(cszData2Send, dwServiceType, csServer, csObject, nPort))
			return BLANKSTRING;

		OutputDebugString(_T("Parse URL: ") + cszData2Send + _T(" - ") + csServer + _T(" - ") + csObject);

		if(!m_hInternetSession)
		{
			switch (nConnectionType)
			{
			case UsePreConfig:
				{
					//OutputDebugString(_T("nConnectionType -> UsePreConfig"));
					m_hInternetSession = ::InternetOpen(_T("VchReg"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
					break;
				}
			case DirectToInternet:
				{
					//OutputDebugString(_T("nConnectionType -> DirectToInternet"));
					m_hInternetSession = ::InternetOpen(_T("VchReg"), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);    
					break;
				}
			case UseProxy:
				{
					//OutputDebugString(_T("nConnectionType -> UseProxy"));
					m_hInternetSession = ::InternetOpen(_T("VchReg"), INTERNET_OPEN_TYPE_PROXY, csProxyServer, NULL, 0);
					break;
				}
			default:  
				{
					//OutputDebugString(_T("nConnectionType -> default"));
					return BLANKSTRING;
				}
			}
		}
		
		if(!m_hInternetSession)
			return BLANKSTRING;

		if(!m_hHttpConnection)
		{
			//OutputDebugString(_T("csHTTPUserName: ") + csHTTPUserName);
			if(csHTTPUserName.GetLength())
			{
				m_hHttpConnection = ::InternetConnect(m_hInternetSession, csServer, nPort, csHTTPUserName, csHTTPPassword, INTERNET_SERVICE_HTTP, 0, NULL);
			}
			else
			{
				m_hHttpConnection = ::InternetConnect(m_hInternetSession, csServer, nPort, NULL,  NULL, INTERNET_SERVICE_HTTP, 0, NULL);
			}
		}

		if(!m_hHttpConnection)
		{
			DWORD dwError = ::GetLastError();
			return BLANKSTRING;
		}

		LPCTSTR ppszAcceptTypes[2] = {0};  

		DWORD dwFlags = INTERNET_NO_CALLBACK | INTERNET_FLAG_FORMS_SUBMIT | INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_PRAGMA_NOCACHE;

		if(dwServiceType == AFX_INET_SERVICE_HTTPS)
		{
			dwFlags	|= (INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID);
		}
		
		//OutputDebugString(_T("HttpOpenRequest: "));
		hHttpFile = ::HttpOpenRequest(m_hHttpConnection, NULL, csObject, NULL, NULL, ppszAcceptTypes, dwFlags, NULL);
		if(!hHttpFile)
		{
			return BLANKSTRING;
		}

resend:
		//OutputDebugString(_T("HttpSendRequest: "));
		//Issue the request
		if(!::HttpSendRequest(hHttpFile, NULL, 0, NULL, 0))
		{
			DWORD dwError = ::GetLastError();

			InternetCloseHandle(hHttpFile);
			hHttpFile = NULL;

			//OutputDebugString(_T("HttpSendRequest Failed!"));

			return BLANKSTRING;
		}

		//OutputDebugString(_T("HttpSendRequest Success!"));
		//Handle the status code in the response
		DWORD dwStatusCode = 0;
		dwSize = sizeof(DWORD);

		//OutputDebugString(_T("HttpQueryInfo Success!"));
		if(!::HttpQueryInfo(hHttpFile, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwSize, NULL))
		{
			InternetCloseHandle(hHttpFile);
			hHttpFile = NULL;

			//OutputDebugString(_T("HttpQueryInfo Failed!"));
			return BLANKSTRING;
		}
		//OutputDebugString(_T("HttpQueryInfo Success!"));

		if(dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ || dwStatusCode == HTTP_STATUS_DENIED)
		{
			char szData[MAX_PATH] = {0};
			dwSize = 0;
			do 
			{
				::InternetReadFile(hHttpFile, szData, sizeof(szData), &dwSize);
			}while(dwSize != 0);
		}

		if(dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ) //Proxy authentication required
		{
			//OutputDebugString(_T("dwStatusCode == HTTP_STATUS_PROXY_AUTH_REQ!"));
			csProxyUserName = L"";
			csProxyPassword = L"";
			csProxyServer = L"";

			int nProxyUserLength = csProxyUserName.GetLength();
			if(nProxyUserLength > 0)
			{
				//OutputDebugString(_T("Resend!"));
				InternetSetOption(hHttpFile, INTERNET_OPTION_PROXY_USERNAME, (LPVOID)csProxyUserName.operator LPCTSTR(), (nProxyUserLength+1) * sizeof(TCHAR));
				InternetSetOption(hHttpFile, INTERNET_OPTION_PROXY_PASSWORD, (LPVOID)csProxyPassword.operator LPCTSTR(), (csProxyPassword.GetLength()+1) * sizeof(TCHAR));
				goto resend;
			}
			else
			{
				//OutputDebugString(_T("Return!"));
				InternetCloseHandle(hHttpFile);
				hHttpFile = NULL;
				return BLANKSTRING;
			}
		}
		else if(dwStatusCode == HTTP_STATUS_DENIED) //Http authentication
		{
			//OutputDebugString(_T("dwStatusCode == HTTP_STATUS_DENIED!"));
			int nHTTPUserLength = csHTTPUserName.GetLength();
			if (nHTTPUserLength)
			{
				InternetSetOption(hHttpFile, INTERNET_OPTION_USERNAME, (LPVOID)csHTTPUserName.operator LPCTSTR(), (nHTTPUserLength+1) * sizeof(TCHAR));
				InternetSetOption(hHttpFile, INTERNET_OPTION_PASSWORD, (LPVOID)csHTTPPassword.operator LPCTSTR(), (csHTTPPassword.GetLength()+1) * sizeof(TCHAR));
				goto resend;
			}
			else
			{
				InternetCloseHandle(hHttpFile);
				hHttpFile = NULL;
				return BLANKSTRING;
			}
		}
		else if (dwStatusCode != HTTP_STATUS_OK && dwStatusCode != HTTP_STATUS_PARTIAL_CONTENT)
		{
			//OutputDebugString(_T("dwStatusCode != HTTP_STATUS_OK!"));
			InternetCloseHandle(hHttpFile);
			hHttpFile = NULL;
			return BLANKSTRING;
		}

		//OutputDebugString(_T("InternetReadFile"));
		int iSize = MAX_PATH;
		if(iDataSize == 0)
		{
		}
		else
		{
		}
		const int iMaxSize = 3072;//MAX_PATH * iDataSize;
		char szData[iMaxSize] = {0};
		dwSize = 0;
		CString csReturnedData = _T("");
		do
		{
			if(!::InternetReadFile(hHttpFile, szData, sizeof(szData), &dwSize))
			{
				InternetCloseHandle(hHttpFile);
				hHttpFile = NULL;
				return BLANKSTRING;
			}
			if(dwSize != 0)
			{
				csReturnedData += CString(CStringA(szData));
				ZeroMemory(szData, iMaxSize);
			}
		}while(dwSize != 0);

		InternetCloseHandle(hHttpFile);
		hHttpFile = NULL;

		OutputDebugString(_T("csReturnedData: ") + csReturnedData);

		return csReturnedData;
	}
	catch(...)
	{
		//OutputDebugString(CString(_T("Internet connection failed")));
	}

	if(hHttpFile)
	{
		InternetCloseHandle(hHttpFile);
	}
	hHttpFile = NULL;

	//OutputDebugString(_T("Out CRegistration::GetReplyFromURL"));

	return BLANKSTRING;
}

bool CMaxThreatDataMgr::IsServerOn()
{
	bool bRetStaus = false;

	CString	csFinalURL(L""),csResult(L"");

	csFinalURL = _MAX_SERVER_URL;
	csFinalURL = csFinalURL + _MAX_URL_CHECK_SERVER_STATUS;
	
	csResult = UploadDatatoPortal(csFinalURL);
	if (csResult.Find(L"true") == -1)
	{
		return bRetStaus;
	}
	return true;
}

int	CMaxThreatDataMgr::SendFilesForTIScanner()
{
	OutputDebugString(L"Threat Community Scanner ##### SendFilesForTIScanner()s");
	if (m_pSQLiteMgr->m_bDBLoaded == FALSE)
	{
		return 0x00;
	}

	if(IsServerOn() == true)
	{
		AddLogEntry(L"MISP CUCKOO SERVER IS ON");
	}
	else
	{
		AddLogEntry(L"MISP CUCKOO SERVER IS OFF");
		return 0;
	}
	
	int iRetry =0;
	int iRecordCnt = 0;
	while(1)
	{
		iRecordCnt =	m_pSQLiteMgr->GetdBatchForTIScanning(2);
		if(iRecordCnt > 0)
		{
			for (int iIndex = 0x00; iIndex < iRecordCnt; iIndex++)
			{
				if(!PreMISPCheck(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5))
				{
					int iDetStatus = 0;

					iDetStatus = SendHashForScanning(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5,m_pSQLiteMgr->m_MaxScanData[iIndex].szSHA256);
					if(iDetStatus == 1) //MISP Detected
					{
						m_pSQLiteMgr->UpdateDetectionStatusFlag(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5,iDetStatus);
						InsertORCheckIntoTIServer(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5,L"0",m_pSQLiteMgr->m_MaxScanData[iIndex].szPESig,m_pSQLiteMgr->m_MaxScanData[iIndex].szProbability,1);
					}
					else if(iDetStatus == 2) //Cuckoo Uploaded
					{
						m_pSQLiteMgr->UpdateDetectionStatusFlag(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5,iDetStatus);
					}
					else
					{
						m_pSQLiteMgr->UpdateScanDoneFlag(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5);
					}	
				}
				else
				{
					m_pSQLiteMgr->UpdateDetectionStatusFlag(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5,1);
				}

				
			}


		}
		if(iRecordCnt == 0)
		{
			break;
		}
	}
	if(iRecordCnt > 0)
	{
		RescanFilesForTIScanner();
		return iRecordCnt;
	}

	RescanFilesForTIScanner();
	return 0;
}

int	CMaxThreatDataMgr::RescanFilesForTIScanner()
{
	if (m_pSQLiteMgr->m_bDBLoaded == FALSE)
	{
		return 0x00;
	}

	int iRetry =0;
	int iRecordCnt = 0;
	while(1)
	{
		iRecordCnt =	m_pSQLiteMgr->GetRescanBatchForTIScanning(2);
		if(iRecordCnt > 0)
		{
			for (int iIndex = 0x00; iIndex < iRecordCnt; iIndex++)
			{
				int iDetStatus = 0;
				iDetStatus = SendHashForScanning(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5,m_pSQLiteMgr->m_MaxScanData[iIndex].szSHA256);
				if(iDetStatus == 1) //MISP Detected
				{
					m_pSQLiteMgr->UpdateDetectionStatusFlag(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5,iDetStatus);
				}
				else
				{
					m_pSQLiteMgr->UpdateReScanDoneFlag(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5);
				}
			}


		}
		if(iRecordCnt == 0)
		{
			break;
		}
	}
	if(iRecordCnt > 0)
	{
		return iRecordCnt;
	}

	return 0;
}

int	CMaxThreatDataMgr::SendFilesForScanBoxScanner()
{

	if (m_pSQLiteMgr->m_bDBLoaded == FALSE)
	{
		return 0x00;
	}
	
	//CMaxCLDFTP objMaxCldFtp;
	
	CSDKSettings objSDKSettings;
	CString csAppPath = objSDKSettings.GetProductAppPath();

	CString csIniPath =  csAppPath;
	csIniPath = csIniPath + L"Setting\\TISettings.ini";

	TCHAR szCuckooThreshold[MAX_PATH] = {0};
	TCHAR szSendFileLocation[MAX_PATH] = {0};
	GetPrivateProfileString(_T("ThreatIntelligenceSetting"), _T("CuckooThreshold"), _T("0"), szCuckooThreshold, MAX_PATH, csIniPath);
	GetPrivateProfileString(_T("ThreatIntelligenceSetting"), _T("Location"), _T(""), szSendFileLocation, MAX_PATH, csIniPath);

	CString csLocation(szSendFileLocation);
	csLocation = csLocation + L"/";

	int iRecordCnt = 0;
	while(1)
	{
		iRecordCnt =	m_pSQLiteMgr->GetdBatchForSandBoxing(2,szCuckooThreshold);
		if(iRecordCnt > 0)
		{
			for (int iIndex = 0x00; iIndex < iRecordCnt; iIndex++)
			{
				CString csHuerFileName(m_pSQLiteMgr->m_MaxScanData[iIndex].szHuerFilePath);
				int iTaskid = 0;
				iTaskid = UploadFileForAnalysisEX(csLocation,m_pSQLiteMgr->m_MaxScanData[iIndex].szHuerFilePath);
				if(iTaskid !=0)
				{
					m_pSQLiteMgr->UpdateFileUploadFlag(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5,iTaskid);
				}
				else
				{
					m_pSQLiteMgr->UpdateFileUploadFlag(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5,0);
				}
			}
		}
		if(iRecordCnt == 0)
		{
			break;
		}

	}
	if(iRecordCnt > 0)
	{
		return iRecordCnt;
	}

	return 0;
}

int CMaxThreatDataMgr::SendHashForScanning(CString csMD5, CString csSHA256)
{
	CString	csFinalURL(L""),csResult(L"");

	csFinalURL = _MAX_SERVER_URL;
	csFinalURL = csFinalURL + _MAX_URL_CHECK_SUSPECIOUS;
	csFinalURL = csFinalURL + csMD5;
	csFinalURL = csFinalURL +L"/";
	csFinalURL = csFinalURL + csSHA256;

	csResult = UploadDatatoPortal(csFinalURL);

	CString		csTokanized(csResult);
	csTokanized.MakeLower();
	csTokanized.Replace(L"\"",L"");
	csTokanized.Replace(L"{",L"");
	csTokanized.Replace(L"}",L"");
	csTokanized.Replace(L"success:true",L"");

	int			iDetection = 0 ,iProcessing = 0,iTaskId = 0 ,iPos =0;
	CString csToken = csTokanized.Tokenize(L",",iPos);
	while(!csToken.IsEmpty())
	{
		if (csToken.Find(L"s:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":")+1);
			iDetection = _wtoi(csToken);
		}
		else if (csToken.Find(L"processing:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":")+1);
			iProcessing = _wtoi(csToken);
		}
		else if (csToken.Find(L"task_id:") != -1)
		{
			
			csToken = csToken.Mid(csToken.Find(L":")+1);
			iTaskId = _wtoi(csToken);
		}
		csToken = csTokanized.Tokenize(L",",iPos);
	}
 	
	if(iDetection == 1)
	{
		return 1;
	
	}
	else if(iDetection == 2 && iProcessing == 0)
	{
		return 2;
	}
	else if(iDetection == 2 && iProcessing == 1)
	{
		return 3;
	}	
	return iDetection;
}

int	CMaxThreatDataMgr::UploadFileForAnalysis(CString csFileName)
{
	CString	csFinalURL(L""),csResult(L"");

	csFinalURL = _MAX_SERVER_URL;
	csFinalURL = csFinalURL + _MAX_URL_UPLOAD_FILE_SANDBOX;
	csFinalURL = csFinalURL + csFileName;
	csFinalURL = csFinalURL + L"\\";
	

	csResult = UploadDatatoPortal(csFinalURL);
	CString		csTokanized(csResult);
	csTokanized.MakeLower();
	csTokanized.Replace(L"\"",L"");
	csTokanized.Replace(L"{",L"");
	csTokanized.Replace(L"}",L"");
	csTokanized.Replace(L"success:true",L"");

	int			iTaskID = 0 ,iPos =0;
	CString csToken = csTokanized.Tokenize(L",",iPos);
	while(!csToken.IsEmpty())
	{
		if (csToken.Find(L"task_id:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":")+1);
			iTaskID = _wtoi(csToken);
		}	
		csToken = csTokanized.Tokenize(L",",iPos);
	}

	return iTaskID;

}

int	CMaxThreatDataMgr::UploadFileForAnalysisEX(CString csLocation,CString csFileName)
{
	CString	csFinalURL(L""),csResult(L"");

	csFinalURL = _MAX_SERVER_URL;
	csFinalURL = csFinalURL + _MAX_URL_UPLOAD_FILE_SANDBOX;
	csFinalURL = csFinalURL + csLocation;
	csFinalURL = csFinalURL + csFileName;
	csFinalURL = csFinalURL + L"/";

	csResult = UploadDatatoPortal(csFinalURL);
	CString		csTokanized(csResult);
	csTokanized.MakeLower();
	csTokanized.Replace(L"\"",L"");
	csTokanized.Replace(L"{",L"");
	csTokanized.Replace(L"}",L"");
	csTokanized.Replace(L"success:true",L"");

	int			iTaskID = 0 ,iPos =0;
	CString csToken = csTokanized.Tokenize(L",",iPos);
	while(!csToken.IsEmpty())
	{
		if (csToken.Find(L"task_id:") != -1)
		{
			
			csToken = csToken.Mid(csToken.Find(L":")+1);
			iTaskID = _wtoi(csToken);
		}	
		csToken = csTokanized.Tokenize(L",",iPos);
	}

	return iTaskID;

}

int	CMaxThreatDataMgr::SendFileForScanningBytaskID(int iTaskID)
{
	CString	csFinalURL(L""),csResult(L"");
	CString csTaskID;
	csTaskID.Format(L"%d",iTaskID);

	csFinalURL = _MAX_SERVER_URL;
	csFinalURL = csFinalURL + _MAX_URL_SANDBOX_FILE_SCANNING;
	csFinalURL = csFinalURL + csTaskID;
	

	csResult = UploadDatatoPortal(csFinalURL);
	CString		csTokanized(csResult);
	csTokanized.MakeLower();
	csTokanized.Replace(L"\"",L"");
	csTokanized.Replace(L"{",L"");
	csTokanized.Replace(L"}",L"");
	csTokanized.Replace(L"success:true",L"");

	int			iDetected = 0 ,iPos =0;
	CString csToken = csTokanized.Tokenize(L",",iPos);
	while(!csToken.IsEmpty())
	{
		if (csToken.Find(L"sus:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":")+1);
			iDetected = _wtoi(csToken);
		}	
		csToken = csTokanized.Tokenize(L",",iPos);
	}

	return iDetected;

}

int	CMaxThreatDataMgr::ScanFileThroughSandBox()
{
	if (m_pSQLiteMgr->m_bDBLoaded == FALSE)
	{
		return 0x00;
	}
//	CMaxCLDFTP objMaxCldFtp;

	int iRecordCnt = 0;
	while(1)
	{
		iRecordCnt =	m_pSQLiteMgr->GetdBatchForSandBoxingScanning(100);
		if(iRecordCnt > 0)
		{
			for (int iIndex = 0x00; iIndex < iRecordCnt; iIndex++)
			{
				int iCuckooStatus = CheckProgress(m_pSQLiteMgr->m_MaxScanData[iIndex].iThreatID);
				if(iCuckooStatus == 1)
				{
					int iDetStatus = SendFileForScanningBytaskID(m_pSQLiteMgr->m_MaxScanData[iIndex].iThreatID);
					if(iDetStatus == 1)
					{
						m_pSQLiteMgr->UpdateDetectionStatusFlag(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5,iDetStatus);
					}
					m_pSQLiteMgr->UpdateSandBoxScanningFlag(m_pSQLiteMgr->m_MaxScanData[iIndex].szMD5);
				}
			}
		}
		if(iRecordCnt == 0)
		{
			break;
		}

	}
	if(iRecordCnt > 0)
	{
		return iRecordCnt;
	}

	return 0;
}

int	CMaxThreatDataMgr::CheckProgress(int iTaskID)
{
	CString	csFinalURL(L""),csResult(L"");
	CString csTaskID;
	csTaskID.Format(L"%d",iTaskID);

	csFinalURL = _MAX_SERVER_URL;
	csFinalURL = csFinalURL + _MAX_URL_SANDBOX_FILE_SCANNING;
	csFinalURL = csFinalURL + csTaskID;
	

	csResult = UploadDatatoPortal(csFinalURL);
	CString		csTokanized(csResult);
	csTokanized.MakeLower();
	csTokanized.Replace(L"\"",L"");
	csTokanized.Replace(L"{",L"");
	csTokanized.Replace(L"}",L"");
	csTokanized.Replace(L"success:true",L"");

	CString csStatus;
	int			iStatus = 0 ,iPos =0;
	CString csToken = csTokanized.Tokenize(L",",iPos);
	while(!csToken.IsEmpty())
	{
		if (csToken.Find(L"status:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":")+1);
			csStatus = csToken;
		}	
		csToken = csTokanized.Tokenize(L",",iPos);
	}

	if(csStatus.Compare(L"finished") == 0)
	{
		return 1;
	
	}
	else if(csStatus.Compare(L"process") == 0)
	{
		return 2;
	
	}
	else
	{
		return iStatus;
	}

	return iStatus;

}

CString CMaxThreatDataMgr::CreateTIInformationJSON(CString csMD5,CString csSHA256, CString csPESign, CString csProbability ,int iDetectionStatus)
{
	CString		cszScanStatus;
	CString		cszJSONData;
	CString		cszScanStatusData;
	CString		csData;

	CString		csDetectionStatus;
	csDetectionStatus.Format(L"%d",iDetectionStatus);

	CString cszServerURL = L"https://tc.thespywaredetector.com";
	
	/******************* Header *******************/
	cszJSONData = cszJSONData + _T("Md5="); //MD5
	cszJSONData = cszJSONData + csMD5;
	cszJSONData = cszJSONData + _T("&");
	cszJSONData = cszJSONData + _T("SHA256="); //FileName
	cszJSONData = cszJSONData + csSHA256;
	cszJSONData = cszJSONData + _T("&");
	cszJSONData = cszJSONData + _T("PE_Signature=");//machine_id
	cszJSONData = cszJSONData + csPESign;
	cszJSONData = cszJSONData + _T("&");
	cszJSONData = cszJSONData + _T("Probability_score=");//IpAddress
	cszJSONData = cszJSONData + csProbability;
	cszJSONData = cszJSONData + _T("&");
	cszJSONData = cszJSONData + _T("Detection_status=");//result
	cszJSONData = cszJSONData + csDetectionStatus;


	cszScanStatus = cszServerURL + _MAX_URL_CHECK_INSERT_THREATINTELLIGENCE;
	cszScanStatus = cszScanStatus + cszJSONData;
	OutputDebugString(cszScanStatus);
 	//cszScanStatus = cszServerURL + _MAX_URL_VULNERABILITYINST;
	return cszScanStatus;

}

int	CMaxThreatDataMgr::InsertORCheckIntoTIServer(CString csMD5,CString csSHA256, CString csPESign, CString csProbability ,int iDetectionStatus)
{
	CString	csFinalURL(L""),csResult(L"");
	

	csFinalURL = CreateTIInformationJSON(csMD5,csSHA256,csPESign,csProbability,iDetectionStatus);

	csResult = UploadDatatoPortal(csFinalURL);
	CString		csTokanized(csResult);

	csTokanized.MakeLower();
	csTokanized.Replace(L"\"",L"");
	csTokanized.Replace(L"{",L"");
	csTokanized.Replace(L"}",L"");
	csTokanized.Replace(L"response:true",L"");

	int			iStatus = 0 ,iPos =0;
	CString csToken = csTokanized.Tokenize(L",",iPos);
	while(!csToken.IsEmpty())
	{
		if (csToken.Find(L"RetVal:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":")+1);
			iStatus = _wtoi(csToken);
		}	
		csToken = csTokanized.Tokenize(L",",iPos);
	}

	return iStatus;

}

void CMaxThreatDataMgr::UpdateReport()
{
	CSDKSettings objSDKSettings;
	CString csDBPath = objSDKSettings.GetProductAppPath();
	csDBPath +=_MAx_SCAN_DETAILS_DB;

	CMaxSqliteMgr objMaxSQLiteMgr(csDBPath);
	int iDetectedFiles = m_pSQLiteMgr->GetDetectedFiles();
	
	objMaxSQLiteMgr.UpdateReportInfo(0,iDetectedFiles,false);
}

bool CMaxThreatDataMgr::PreMISPCheck(LPCTSTR pszFileMD5)
{
	bool bRetStatus = false;

	CString	csFinalURL(L""),csResult(L"");
	

	csFinalURL = CreateMISPScanJSON(pszFileMD5);

	csResult = UploadDatatoPortal(csFinalURL);

	CString		csTokanized(csResult);
	csTokanized.MakeLower();
	csTokanized.Replace(L"\"",L"");
	csTokanized.Replace(L"{",L"");
	csTokanized.Replace(L"}",L"");
	csTokanized.Replace(L"response:true",L"");

	int			iStatus = 0 ,iPos =0;
	CString csToken = csTokanized.Tokenize(L",",iPos);
	while(!csToken.IsEmpty())
	{
		if (csToken.Find(L"retval:") != -1)
		{
			csToken = csToken.Mid(csToken.Find(L":")+1);
			iStatus = _wtoi(csToken);
		}	
		csToken = csTokanized.Tokenize(L",",iPos);
	}

	if(iStatus == 2)
	{
		return true;
	}

	return bRetStatus;


}

CString CMaxThreatDataMgr::CreateMISPScanJSON(CString csMD5)
{
	CString		cszScanStatus;
	CString		cszJSONData;
	CString		cszScanStatusData;
	CString		csData;

	CString cszServerURL = L"https://tc.thespywaredetector.com";
	
	/******************* Header *******************/
	cszJSONData = cszJSONData + _T("Md5="); //MD5
	cszJSONData = cszJSONData + csMD5;

	cszScanStatus = cszServerURL + _MAX_URL_PRE_MISP_CHECK;
	cszScanStatus = cszScanStatus + cszJSONData;
	OutputDebugString(cszScanStatus);
 	//cszScanStatus = cszServerURL + _MAX_URL_VULNERABILITYINST;
	return cszScanStatus;

}
