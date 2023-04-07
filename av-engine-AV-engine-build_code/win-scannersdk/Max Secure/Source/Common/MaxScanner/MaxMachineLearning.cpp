#include "pch.h"
#include "MaxMachineLearning.h"
#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

CMaxMachineLearning::CMaxMachineLearning(void)
{
	//pMaxMacLrnLib = NULL;							//For Python Scanner
	//pMaxMacLrnModule = NULL;
	//pImportDict = NULL;

	////Py_SetPath(L"c:\\zv\\python35");
	//Py_Initialize();

	//m_bMaxMacLearnLoaded = false;
	//
	
	//pMaxMacLrnLib = PyString_FromString("MacLearning");
	////pMaxMacLrnLib = PyUnicode_FromString("MacLearning");

	
	//pMaxMacLrnModule = PyImport_Import(pMaxMacLrnLib);

	//pImportDict = PyModule_GetDict(pMaxMacLrnModule);

	///*
	//if (pImportDict == Py_None)
	//{
	//}
	//*/
	m_hMLHeurScanDLL = NULL;
	m_bMaxMacLearnLoaded = false;
	m_csCompanySafeList.RemoveAll();
	m_csCopyrightSafeList.RemoveAll();
}

CMaxMachineLearning::~CMaxMachineLearning(void)
{
	m_csCompanySafeList.RemoveAll();
	m_csCopyrightSafeList.RemoveAll();
	m_bMaxMacLearnLoaded = false;
	/*
	if(m_pUnloadMLScanner != NULL)
	{
		m_pUnloadMLScanner();
	}
	*/
	//Py_Finalize();			//For Python Scanner
	DeInitializeScanner();
}

bool CMaxMachineLearning::DeInitializeScanner()
{
	if (m_pUnloadMLScanner != NULL)
	{
		m_pUnloadMLScanner();
	}
	if (m_hMLHeurScanDLL)
	{
		FreeLibrary(m_hMLHeurScanDLL);
		m_hMLHeurScanDLL = NULL;
	}
	
	m_pMLScanFile = NULL;
	m_pMLScanFileEx = NULL;
	m_pLoadMLScanner = NULL;
	m_pUnloadMLScanner = NULL;

	m_bMaxMacLearnLoaded = false;
	return true;
}

//bool CMaxMachineLearning::InitializeScanner(LPCTSTR pszClassifierPath,LPCTSTR pszFeaturesPath)
bool CMaxMachineLearning::InitializeScanner(LPCTSTR pszDBPath,bool bMLScanner)
{
	bool	bResult = false;
	//char	strClassifierPath[MAX_PATH] = {0x00};						//For Python Scanner
	//char	strFeaturesPath[MAX_PATH] = {0x00};

	//if (pszClassifierPath == NULL || pszFeaturesPath == NULL)
	//{
	//	return bResult; 
	//}

	//if (_tcslen(pszClassifierPath) == 0x00 || _tcslen(pszFeaturesPath) == 0x00)
	//{
	//	return bResult;
	//}

	//GetAnsiString(pszClassifierPath,strClassifierPath);
	//GetAnsiString(pszFeaturesPath,strFeaturesPath);

	
	////Call for Python Code
	//PyObject *pInitScannerFunc = NULL, *pInArgs = NULL, *pValue = NULL;
	//pInitScannerFunc = PyDict_GetItemString(pImportDict, "Init_Classifiers");

	//pInArgs = PyTuple_New(2);
	//
	//
	//pValue = PyString_FromString(strClassifierPath);
	//PyTuple_SetItem(pInArgs, 0, pValue);

	//pValue = PyString_FromString(strFeaturesPath);
	//PyTuple_SetItem(pInArgs, 1, pValue);

	//PyObject_CallObject(pInitScannerFunc, pInArgs);
	
	///*
	//pValue = PyUnicode_FromString(strClassifierPath);
	//PyTuple_SetItem(pInArgs, 0, pValue);
	//pValue = PyUnicode_FromString(strFeaturesPath);
	//PyTuple_SetItem(pInArgs, 1, pValue);
	//PyObject_CallObject(pInitScannerFunc, pInArgs);
	//*/
	m_bMaxMacLearnLoaded = false;
	///MachineLearning 14-June-2018
	//m_hMLHeurScanDLL = LoadLibrary(L"AuMLHeurScan.dll");
	/*
	TCHAR	szDllFolPath[MAX_PATH] = {0x00};
	TCHAR	szDllFolShortPath[MAX_PATH] = {0x00};
	_stprintf(szDllFolPath,L"%sAuMLHeurScan.dll",pszDBPath);

	DWORD dwRet = GetShortPathName(szDllFolPath,szDllFolShortPath,MAX_PATH);
	if (dwRet == 0x00)
	{
		_tcscpy(szDllFolShortPath,szDllFolPath);
	}
	*/
	m_hMLHeurScanDLL = LoadLibrary(L"AuMLHeurScan.dll");
	if(m_hMLHeurScanDLL != NULL)
	{
		m_pLoadMLScanner = (LOADDB)GetProcAddress(m_hMLHeurScanDLL,"LoadMLDB");
		m_pUnloadMLScanner = (UNLOADDB)GetProcAddress(m_hMLHeurScanDLL,"UnLoadMLDB");
		m_pMLScanFile = (SCANFILE)GetProcAddress(m_hMLHeurScanDLL,"ScanFile");
		m_pMLScanFileEx = NULL;
		m_pMLScanFileEx = (SCANFILEEX)GetProcAddress(m_hMLHeurScanDLL,"ScanFileEX");
		if(m_pLoadMLScanner != NULL &&  m_pUnloadMLScanner!= NULL && m_pMLScanFile != NULL && m_pMLScanFileEx != NULL)
		{	
			DWORD dwRetVal = m_pLoadMLScanner(pszDBPath,bMLScanner);
			if(dwRetVal == 1)
			{
				m_bMaxMacLearnLoaded = true;
			}
		}
		
	}
	LoadCompanyNameList();

	return true;
}

//True = Clean File 
//Flase = Virus
bool CMaxMachineLearning::ScanFile(LPCTSTR pszFile2Scan)
{
	bool	bResult = true;
	char	strFile2Scan[MAX_PATH] = {0x00};

	if(!m_bMaxMacLearnLoaded)
	{
		return bResult;
	}
	if (pszFile2Scan == NULL)
	{
		return bResult; 
	}

	if (_tcslen(pszFile2Scan) == 0x00)
	{
		return bResult;
	}

	if (IsValidFile2Scan(pszFile2Scan) == false)
	{
		return bResult;
	}
	//AddLogEntry(pszFile2Scan);
	//GetAnsiString(pszFile2Scan,strFile2Scan);				//For Python Scanner

	//PyObject	*pScanFileFunc = NULL, *pInArgs = NULL, *pValue = NULL, *pResult = NULL;
	//int			iResult = 0x01;

	//pScanFileFunc = PyDict_GetItemString(pImportDict, "Scan_File");

	//pInArgs = PyTuple_New(1);
	//
	//pValue = PyString_FromString(strFile2Scan);
	////pValue = PyUnicode_FromString(strFile2Scan);
	//PyTuple_SetItem(pInArgs, 0, pValue);
	//
	//pResult = PyObject_CallObject(pScanFileFunc, pInArgs);
	//
	////iResult = PyLong_AsLong(pResult);
	//iResult = PyInt_AsLong(pResult);
	int			iResult = 0x00;
	iResult = m_pMLScanFile(pszFile2Scan);
	if (iResult == 0x01)
	{
		//File Is Malicious
		bResult = false;
	}

	return bResult;
}

bool CMaxMachineLearning::ScanFileEX(CMaxPEFile *pMaxPEFile)
{
	bool	bResult = true;
	char	strFile2Scan[MAX_PATH] = {0x00};

	if(!m_bMaxMacLearnLoaded)
	{
		return bResult;
	}
	if (pMaxPEFile == NULL)
	{
		return bResult; 
	}

	if (_tcslen(pMaxPEFile->m_szFilePath) == 0x00)
	{
		return bResult;
	}

	if (IsValidFile2Scan(pMaxPEFile->m_szFilePath) == false)
	{
		return bResult;
	}
	
	int			iResult = 0x00;
	iResult = m_pMLScanFileEx(pMaxPEFile);
	if (iResult == 0x01)
	{
		//File Is Malicious
		bResult = false;
	}

	return bResult;
}

bool CMaxMachineLearning::GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT)
{
	bool		bRetValue = FALSE;
	char		szOut[MAX_PATH] = {0x00};		

	if (pszUnicodeIN == NULL || pszAnsiOUT == NULL)
	{
		return bRetValue;
	}

	int iRetLen =  WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK,pszUnicodeIN,_tcslen(pszUnicodeIN),szOut,MAX_PATH,NULL,NULL);

	if (iRetLen > 0x00)
	{
		strcpy(pszAnsiOUT,szOut);
	}

	return bRetValue;
}


bool CMaxMachineLearning::GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT)
{
	bool		bRetValue = FALSE;
	TCHAR		szOut[MAX_PATH] = {0x00};		

	if (pszAnsiIN == nullptr || pszUnicodeOUT == nullptr)
	{
		return bRetValue;
	}

	int iRetLen =  MultiByteToWideChar(CP_ACP,0,pszAnsiIN,strlen(pszAnsiIN),szOut,MAX_PATH);

	if (iRetLen > 0x00)
	{
		_tcscpy_s(pszUnicodeOUT,_tcslen(pszUnicodeOUT),szOut);
	}

	return bRetValue;
}

bool CMaxMachineLearning::IsValidFile2Scan(LPCTSTR pszFile2Check)
{
	bool		bRetValue = false;
	
	if (pszFile2Check == nullptr)
	{
		return	bRetValue;
	}
	
	{
		if(DetectWhiteCertificate(pszFile2Check))
		{
			return false;
		
		}

		CFileVersionInfo	objVerInfo;
		bool				bSafeCompFound = false;
		bool				bSafeCopyrightFound = false;

		TCHAR	szCompName[MAX_PATH] = {0x00};
		TCHAR	szLegCopyright[MAX_PATH] = {0x00};
		objVerInfo.GetCompanyName(pszFile2Check,&szCompName[0x00]);
		objVerInfo.GetLegalCopyright(pszFile2Check,&szLegCopyright[0x00]);
		_tcslwr(szCompName);
		_tcslwr(szLegCopyright);
		bSafeCompFound = IsKnowCompanyName(szCompName);
		bSafeCopyrightFound = IsKnowCopyrights(szLegCopyright);
		
		if (bSafeCompFound == true && bSafeCopyrightFound == true)
		{
			bRetValue = false;
		}
		else
		{
			bRetValue = true;
		}
		
	}

	return	bRetValue;
}


bool CMaxMachineLearning::IsKnowCompanyName(LPCTSTR pszComName2Check)
{
	bool	bRetValue = false;
	int		iListCnt = 0x00;
	CString csCompanyName(pszComName2Check);
	csCompanyName.Trim();
	if (csCompanyName.IsEmpty())
	{
		return bRetValue;
	}

	if (_tcslen(csCompanyName) <= 0x05)
	{
		return bRetValue;
	}
	iListCnt = m_csCompanySafeList.GetCount();
	for (int i = 0x00; i < iListCnt; i++)
	{
		CString	csData = m_csCompanySafeList.GetAt(i);
		csData.Trim();
		if (csData.Find(csCompanyName) != -1 || csCompanyName.Find(csData) != -1)
		{
			return true;
		}
	}
	
	return bRetValue;
}

bool CMaxMachineLearning::IsKnowCopyrights(LPCTSTR pszCopyright2Check)//pszComName2Check
{
	bool	bRetValue = false;
	int		iListCnt = 0x00;
	CString csCopyright(pszCopyright2Check);
	csCopyright.Trim();
	if (csCopyright.IsEmpty())
	{
		return bRetValue;
	}

	if (_tcslen(csCopyright) <= 0x05)
	{
		return bRetValue;
	}
	iListCnt = m_csCopyrightSafeList.GetCount();
	
	for (int i = 0x00; i < iListCnt; i++)
	{
		CString	csData = m_csCopyrightSafeList.GetAt(i);
		csData.Trim();
		if(csData.CompareNoCase(csCopyright) == 0)
		{
			return true;
		
		}
	}
	
	return bRetValue;
}

bool CMaxMachineLearning::DetectWhiteCertificate(LPCTSTR pszFile2Check) // Sign from Certificate only
{
	TCHAR				szFileName[MAX_PATH] = {0};
	int					iListCnt = 0x00;

	HCERTSTORE			hStore = nullptr;
	HCRYPTMSG			hMsg = nullptr;
	PCCERT_CONTEXT		pCertContext = nullptr;
	PCMSG_SIGNER_INFO	pSignerInfo = nullptr;
	BOOL				fResult = FALSE;   
	DWORD				dwEncoding = 0x00, dwContentType = 0x00, dwFormatType = 0x00;

	DWORD dwSignerInfo = 0x00;
	CERT_INFO CertInfo; 
	LPTSTR szName = nullptr;
	DWORD dwData;

	_tcscpy_s(szFileName, MAX_PATH, pszFile2Check);

	if (pSignerInfo != NULL) LocalFree(pSignerInfo);
	if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
	if (hStore != NULL) CertCloseStore(hStore, 0);
	if (hMsg != NULL) CryptMsgClose(hMsg);

	fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
		szFileName,
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&dwEncoding,
		&dwContentType,
		&dwFormatType,
		&hStore,
		&hMsg,
		NULL);
	if (!fResult)
	{
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return 0;
	}

	fResult = CryptMsgGetParam(hMsg, 
		CMSG_SIGNER_INFO_PARAM, 
		0, 
		NULL, 
		&dwSignerInfo);
	if (!fResult)
	{
		if (pSignerInfo != NULL) LocalFree(pSignerInfo);
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return 0;
	}

	pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
	if (!pSignerInfo)
	{
		if (pSignerInfo != NULL) LocalFree(pSignerInfo);
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return 0;
	}
	fResult = CryptMsgGetParam(hMsg, 
		CMSG_SIGNER_INFO_PARAM, 
		0, 
		(PVOID)pSignerInfo, 
		&dwSignerInfo);
	if (!fResult)
	{
		if (pSignerInfo != NULL) LocalFree(pSignerInfo);
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return 0;
	}

	CertInfo.Issuer = pSignerInfo->Issuer;
	CertInfo.SerialNumber = pSignerInfo->SerialNumber;

	pCertContext = CertFindCertificateInStore(hStore,
		ENCODING,
		0,
		CERT_FIND_SUBJECT_CERT,
		(PVOID)&CertInfo,
		NULL);
	if (!pCertContext)
	{
		if (pSignerInfo != NULL) LocalFree(pSignerInfo);
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return 0;
	}
	dwData = pCertContext->pCertInfo->SerialNumber.cbData;

	if (!(dwData = CertGetNameString(pCertContext, 
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		CERT_NAME_ISSUER_FLAG,
		NULL,
		NULL,
		0)))
	{
		if (pSignerInfo != NULL) LocalFree(pSignerInfo);
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return 0;
	}
	szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
	if (!szName)
	{
		if (pSignerInfo != NULL) LocalFree(pSignerInfo);
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return 0;
	}
	if (!(CertGetNameString(pCertContext, 
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		NULL,
		szName,
		dwData)))
	{
		if (szName != NULL) LocalFree(szName);
		if (pSignerInfo != NULL) LocalFree(pSignerInfo);
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return 0;
	}
	/*
	TCHAR szDummy[MAX_PATH] = {0};

	_tcscpy(szDummy,szName);
	_tcslwr(szDummy);
	*/
	CString csFileCompanyName(szName);
	if (pSignerInfo != NULL) LocalFree(pSignerInfo);
	if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
	if (hStore != NULL) CertCloseStore(hStore, 0);
	if (hMsg != NULL) CryptMsgClose(hMsg);

	iListCnt = m_csCompanySafeList.GetCount();
	for (int i = 0x00; i < iListCnt; i++)
	{
		CString	csData = m_csCompanySafeList.GetAt(i);
		csData.Trim();
		if(csData.CompareNoCase(csFileCompanyName) == 0)
		{
			return true;
		}
	}
	return false;
}
int CMaxMachineLearning::LoadCompanyNameList()
{
	int		iRetValue = 0x00;
	TCHAR	szFilePath[MAX_PATH] = {0x00};
	TCHAR	*pTemp = nullptr;

	GetModuleFileName(NULL,szFilePath,MAX_PATH);
	if (_tcslen(szFilePath) <= 0x00)
	{
		return iRetValue;
	}
	
	pTemp = _tcsrchr(szFilePath,L'\\');
	if (pTemp == nullptr)
	{
		return iRetValue;
	}

	*pTemp = '\0';
	pTemp = nullptr;

	_tcslwr(szFilePath);
	_tcscat(szFilePath,L"\\Setting\\CompSafeList.ini");

	if (PathFileExists(szFilePath) == FALSE)
	{
		return iRetValue;
	}

	TCHAR	szOutPut[MAX_PATH] = {0x00};
	TCHAR	szKeyName[MAX_PATH] = {0x00};
	int		iCount = 0x00;
	int		iCopyrightCount = 0x00;

	GetPrivateProfileString(L"Company Names",L"Count",L"0",szOutPut,MAX_PATH,szFilePath);
	iCount = _wtoi(szOutPut);
	GetPrivateProfileString(L"Legal Copyright",L"Count",L"0",szOutPut,MAX_PATH,szFilePath);
	iCopyrightCount  =  _wtoi(szOutPut);
	if (iCount <= 0x00)
	{
		iCount = 0; 
	}
	if (iCopyrightCount <= 0x00)
	{
		iCopyrightCount = 0; 
	}

	for(int i = 0x00; i < iCount; i++)
	{
		_tcscpy_s(szOutPut,MAX_PATH,L"");
		_tcscpy_s(szKeyName, MAX_PATH,L"");
		_itow(i,szKeyName,10);
		GetPrivateProfileString(L"Company Names",szKeyName,L"0",szOutPut,MAX_PATH,szFilePath);
		_tcslwr(szOutPut);
		if (_tcslen(szOutPut) > 0x05)
		{
			m_csCompanySafeList.Add(szOutPut);
		}
	}

	for(int i = 0x00; i < iCopyrightCount; i++)
	{
		_tcscpy_s(szOutPut,MAX_PATH,L"");
		_tcscpy_s(szKeyName, MAX_PATH,L"");
		_itow(i,szKeyName,10);
		GetPrivateProfileString(L"Legal Copyright",szKeyName,L"0",szOutPut,MAX_PATH,szFilePath);
		_tcslwr(szOutPut);
		
		if (_tcslen(szOutPut) > 0x05)
		{
			CString csOutput(szOutPut);
			csOutput.Replace(L"Â",L"");
			m_csCopyrightSafeList.Add(csOutput);
		}
	}

	return iCount + iCopyrightCount;
}