#include "pch.h"
#include "MaxRandomPattern.h"
#include "VerInfo.h"
#include <shlobj.h>
#include "ProductInfo.h"
#include "Registry.h"
#include "MaxDigitalSigCheck.h"
#include "MaxExceptionFilter.h"

#define MAX_FILE_PATH			MAX_PATH 
CMaxRandomPattern::CMaxRandomPattern(void)
{
	
	
}
bool CMaxRandomPattern::UnloadDB()
{
	if(m_bRandPatternLoaded)
	{	
		m_bRandPatternLoaded = false;
		m_csCompanySafeList.RemoveAll();
		Py_Finalize();			//For Python Scanner
		m_pMaxRandLrnLib = NULL;	
		m_pMaxRandLrnModule = NULL;
		m_pImportDict = NULL;
		m_pMaxFileLessLib = NULL;
		m_pMaxRandLrnModule = NULL;
		m_pImportFileLessDict = NULL;
	}
	return true;
}
CMaxRandomPattern::~CMaxRandomPattern(void)
{
	//UnloadDB();
}
bool CMaxRandomPattern::CheckInitializeScan(LPCTSTR pszDBPath,bool bMLScanner)
{
	bool bReturn = false;
	__try
	{
		bReturn =  InitializeScanner(pszDBPath,bMLScanner);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught in CMaxRandomPattern::CheckInitializeScan")))
	{
		return false;
	}
	return bReturn;
}
bool CMaxRandomPattern::CheckScanPattern(LPCTSTR pszFile2Scan)
{
	bool bReturn = false;
	__try
	{
		bReturn =  ScanPattern(pszFile2Scan);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught in CMaxRandomPattern::CheckScanPattern")))
	{
		return false;
	}
	return bReturn;
}

bool CMaxRandomPattern::InitializeScanner(LPCTSTR pszDBPath,bool bMLScanner)
{
	bool	bResult = false;
	char	strDBPath[MAX_PATH] = {0x00};						//For Python Scanner
	if (pszDBPath == NULL)
	{
		return bResult; 
	}

	if (_tcslen(pszDBPath) == 0x00)
	{
		return bResult;
	}
	m_pMaxRandLrnLib = NULL;							//For Python Scanner
	m_pMaxRandLrnModule = NULL;
	m_pImportDict = NULL;
	m_pMaxFileLessLib = NULL;
	m_pMaxFileLessModule = NULL;
	m_pImportFileLessDict = NULL;

	m_bRandPatternLoaded = false;

	Py_Initialize();

	m_pMaxRandLrnLib = PyString_FromString("RandPattern");
	//m_pMaxRandLrnLib = PyString_FromString("Sample");
	m_pMaxRandLrnModule = PyImport_Import(m_pMaxRandLrnLib);
	m_pImportDict = PyModule_GetDict(m_pMaxRandLrnModule);

	m_pMaxFileLessLib = PyString_FromString("FileLessScanner");
	m_pMaxFileLessModule = PyImport_Import(m_pMaxFileLessLib);
	m_pImportFileLessDict = PyModule_GetDict(m_pMaxFileLessModule);

	GetAnsiString(pszDBPath,strDBPath);	
	
	//Call for Python Code
	PyObject *pInitScannerFunc = NULL, *pInArgs = NULL, *pValue = NULL;
	pInitScannerFunc = PyDict_GetItemString(m_pImportDict, "Init_Classifiers");

	pInArgs = PyTuple_New(1);	
	
	pValue = PyString_FromString(strDBPath);
	PyTuple_SetItem(pInArgs, 0, pValue);

	PyObject_CallObject(pInitScannerFunc, pInArgs);

	m_bRandPatternLoaded = true;
	m_csCompanySafeList.RemoveAll();
	LoadCompanyNameList();
	m_csAppDataPath = m_csProgData = m_csProgFiles = m_csProgFilesx86 = _T("");
	CProductInfo objProdInfo;
	CRegistry objReg;
	CString csRegPath = objProdInfo.GetProductRegKey();
	
	objReg.Get(csRegPath,_T("APPDATA"),m_csAppDataPath,HKEY_LOCAL_MACHINE);
	//objReg.Get(csRegPath,_T("APPDATA_LOCAL"),m_csAppDataTempPath,HKEY_LOCAL_MACHINE);
	
	//m_csAppDataPath = GetAPPDataPath();
	/*if(!m_csAppDataTempPath.IsEmpty())
	{
		m_csAppDataTempPath = m_csAppDataTempPath +_T("\\Temp");
	}*/
	int iPos = m_csAppDataPath.ReverseFind('\\');
	if(iPos != -1)
	{
		m_csAppDataPath = m_csAppDataPath.Left(iPos);
	}
	m_csProgData = GetAllUserAppDataPath();
	
	m_csProgFiles = GetProgramFilesDir();
	
	#ifdef WIN64
	m_csProgFilesx86 = GetProgramFilesDirX64();
	m_csProgFilesx86.Trim();
	m_csProgFilesx86.MakeLower();
	
	#endif
	m_csAppDataTempPath.Trim();
	m_csAppDataPath.Trim();
	m_csProgData.Trim();
	m_csProgFiles.Trim();
	m_csAppDataTempPath.MakeLower();
	m_csAppDataPath.MakeLower();
	m_csProgData.MakeLower();
	m_csProgFiles.MakeLower();
	return true;
}

//True = Clean File 
//Flase = Virus
bool CMaxRandomPattern::ScanPattern(LPCTSTR pszFile2Scan)
{
	bool	bResult = false;
	
	if(!m_bRandPatternLoaded)
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
	CString csFilePath(pszFile2Scan);
	
	bResult =	IsFileLessMalware(pszFile2Scan);

	if(bResult)
	{
		return bResult;
	}


	bool bFile2Scan = false;
	/*if(csFilePath.Find(m_csAppDataTempPath)!= -1)
	{
		bFile2Scan = false;
	}*/
	if((csFilePath.Find(m_csProgData) != -1) || (csFilePath.Find(m_csProgFiles) != -1) || (csFilePath.Find(m_csAppDataPath) != -1))
	{
		bFile2Scan = true;
	}
	#ifdef WIN64
	if(!bFile2Scan && (csFilePath.Find(m_csProgFilesx86) != -1))
	{
		bFile2Scan = true;
	}
	#endif
	if(!bFile2Scan)
	{
		return bResult;
	}
	if (IsValidFile2Scan(pszFile2Scan) == false)
	{
		return bResult;
	}
	
	CString csFolderName = L"";
	CString csFileName = L"";
	int iPos = 0;
	iPos = csFilePath.ReverseFind('\\');
	if(iPos != -1)
	{
		csFolderName = csFilePath.Left(iPos);
		csFileName = csFilePath.Mid(iPos+1);
		iPos =  csFolderName.ReverseFind('\\');
		if(iPos > 3)
		{
			csFolderName = csFolderName.Mid(iPos+1);
			iPos = csFolderName.Find('.');
			if(iPos != -1)
			{
				csFolderName = csFolderName.Left(iPos);
			}
		}
		else
		{
			csFolderName = _T("");
		}
		
		/*iPos = csFileName.ReverseFind('.');
		if(iPos != -1)
		{
			csFileName = csFileName.Left(iPos);
		}*/
		iPos = csFileName.Find('.');
		if(iPos != -1)
		{
			csFileName = csFileName.Left(iPos);
		}
	}
	int iFolderLen = 0;
	int iFileLen = 0;
	if(!csFolderName.IsEmpty())
	{
		iFolderLen = csFolderName.GetLength();
	}
	if(!csFileName.IsEmpty())
	{
		iFileLen = csFileName.GetLength();
	}
	TCHAR szPatternName[MAX_PATH] = {0};
	//_tcscpy(szPatternName,csFolderName);
	
	/*if(iFolderLen > 6 && iFolderLen < 22)
	{
		bResult =	IsPatternPresent(szPatternName);
	}*/
	//if(!bResult)
	//{
	//bResult = false;
	if(iFileLen > 6 && iFileLen < 22)
	{
		_tcscpy(szPatternName,csFileName);
		bResult =	IsPatternPresent(szPatternName);
	}
	//}
	return bResult;
}
bool CMaxRandomPattern::ScanFLessMal(LPCTSTR szFileName)
{
	bool	bResult = false;
	bResult =	IsFileLessMalware(szFileName);

	if(bResult)
	{
		return bResult;
	}
	return bResult;
}
bool CMaxRandomPattern::IsPatternPresent(LPCTSTR pszPattern2Scan)
{
	char	strPattern2Scan[MAX_PATH] = {0x00};

	GetAnsiString(pszPattern2Scan,strPattern2Scan);				//For Python Scanner

	PyObject	*pScanFileFunc = NULL, *pInArgs = NULL, *pValue = NULL, *pResult = NULL;
	long		iResult = 0x01;
	bool		bResult = false;

	pScanFileFunc = PyDict_GetItemString(m_pImportDict, "RandomNamePtrn");

	pInArgs = PyTuple_New(1);
	pValue = PyString_FromString(strPattern2Scan);
	PyTuple_SetItem(pInArgs, 0, pValue);

	pResult = PyObject_CallObject(pScanFileFunc, pInArgs);
	iResult = PyInt_AsLong(pResult);
	if (iResult == 0x00)
	{
		bResult = true;
	}
	return bResult;
}

bool CMaxRandomPattern::IsFileLessMalware(LPCTSTR szFilePath)
{
	PyObject	*pScanFileFunc = NULL, *pInArgs = NULL, *pValue = NULL, *pResult = NULL;
	long		iResult = 0x00;
	bool		bResult = false;
	CStringA cstrText(szFilePath);
	pScanFileFunc = PyDict_GetItemString(m_pImportFileLessDict, "ScanFFile");

	pInArgs = PyTuple_New(1);
	pValue = PyString_FromString(cstrText);
	PyTuple_SetItem(pInArgs, 0, pValue);

	pResult = PyObject_CallObject(pScanFileFunc, pInArgs);
	iResult = PyInt_AsLong(pResult);
	if (iResult == 0x1)
	{
		bResult = true;
	}
	return bResult;
}

bool CMaxRandomPattern::GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT)
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


bool CMaxRandomPattern::GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT)
{
	bool		bRetValue = FALSE;
	TCHAR		szOut[MAX_PATH] = {0x00};		

	if (pszAnsiIN == NULL || pszUnicodeOUT == NULL)
	{
		return bRetValue;
	}

	//int iRetLen =  MultiByteToWideChar(CP_ACP,WC_COMPOSITECHECK,pszUnicodeIN,_tcslen(pszUnicodeIN),szOut,MAX_PATH,NULL,NULL);
	int iRetLen =  MultiByteToWideChar(CP_ACP,0,pszAnsiIN,strlen(pszAnsiIN),szOut,MAX_PATH);

	if (iRetLen > 0x00)
	{
		_tcscpy(pszUnicodeOUT,szOut);
	}

	return bRetValue;
}
bool CMaxRandomPattern::IsValidFile2Scan(LPCTSTR pszFile2Scan)
{
	bool bReturn = false;
	__try
	{
		bReturn =  CheckScanPatternDigi(pszFile2Scan);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught in CMaxRandomPattern::CheckScanPattern")))
	{
		return false;
	}
	return bReturn;
}
bool CMaxRandomPattern::CheckScanPatternDigi(LPCTSTR pszFile2Check)
{
	bool		bRetValue = false;
	
	if (pszFile2Check == NULL)
	{
		return	bRetValue;
	}
	
	TCHAR	*pTemp = NULL;

	pTemp = (TCHAR *)_tcsrchr(pszFile2Check,L'.');
	if (pTemp)
	{
		if (_tcslen(pTemp) > 4)
		{
			return bRetValue;
		}
		TCHAR	szExt[0x10] = {0x00};
		_tcscpy(szExt,pTemp);
		_tcslwr(szExt);

		//if (_tcsstr(szExt,L".dll") != NULL || _tcsstr(szExt,L".exe") != NULL || _tcsstr(szExt,L".tmp") != NULL)   //.config
		if (_tcsstr(szExt,L".exe") != NULL)
		{
			bRetValue = true;
		}
	}
	

	if (bRetValue == true)
	{
		CFileVersionInfo	objVerInfo;
		bool				bFound = false;

		TCHAR	szCompName[MAX_PATH] = {0x00};
		objVerInfo.GetCompanyName(pszFile2Check,&szCompName[0x00]);
		_tcslwr(szCompName);
		bFound = IsKnowCompanyName(szCompName);
		if (bFound == true)
		{
			bRetValue = false;
		}
		else
		{
			CMaxDigitalSigCheck objMaxDigiSign;
			bFound = objMaxDigiSign.CheckDigitalSign(pszFile2Check);
			if (bFound == true)
			{
				bRetValue = false;
			}
		}
	}

	return	bRetValue;
}

bool CMaxRandomPattern::IsKnowCompanyName(LPCTSTR pszComName2Check)
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

int CMaxRandomPattern::LoadCompanyNameList()
{
	int		iRetValue = 0x00;
	TCHAR	szFilePath[MAX_PATH] = {0x00};
	TCHAR	*pTemp = NULL;
	
	GetModuleFileName(NULL,szFilePath,MAX_PATH);
	
	if (_tcslen(szFilePath) <= 0x00)
	{
		return iRetValue;
	}
	
	pTemp = _tcsrchr(szFilePath,L'\\');
	if (pTemp == NULL)
	{
		return iRetValue;
	}

	*pTemp = '\0';
	pTemp = NULL;

	_tcslwr(szFilePath);
	_tcscat(szFilePath,L"\\Setting\\CompSafeList.ini");
	
	if (PathFileExists(szFilePath) == FALSE)
	{
		return iRetValue;
	}

	TCHAR	szOutPut[MAX_PATH] = {0x00};
	TCHAR	szKeyName[MAX_PATH] = {0x00};
	int		iCount = 0x00;
	
	GetPrivateProfileString(L"Company Names",L"Count",L"0",szOutPut,MAX_PATH,szFilePath);
	iCount = _wtoi(szOutPut);
	
	if (iCount <= 0x00)
	{
		return iRetValue; 
	}

	for(int i = 0x00; i < iCount; i++)
	{
		_tcscpy(szOutPut,L"");
		_tcscpy(szKeyName,L"");
		_itow(i,szKeyName,10);
		
		GetPrivateProfileString(L"Company Names",szKeyName,L"0",szOutPut,MAX_PATH,szFilePath);
		_tcslwr(szOutPut);
		
		if (_tcslen(szOutPut) > 0x05)
		{
			m_csCompanySafeList.Add(szOutPut);
		}
	}

	return iCount;
}
CString CMaxRandomPattern::GetAllUserAppDataPath(void)
{
	CString csReturn;

	try
	{
		HRESULT hResult	= 0;
		LPITEMIDLIST pidlRoot = NULL;
		TCHAR *lpszPath = NULL;

		lpszPath = new TCHAR[MAX_FILE_PATH];

		if(lpszPath)
		{
			SecureZeroMemory(lpszPath, MAX_FILE_PATH*sizeof(TCHAR));

			hResult	= SHGetSpecialFolderLocation(NULL, CSIDL_COMMON_APPDATA, &pidlRoot);

			if(NOERROR == hResult)
			{
				SHGetPathFromIDList(pidlRoot, lpszPath);
				csReturn.Format(_T("%s"), lpszPath);
			}
			delete [] lpszPath;
			lpszPath = NULL;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in GetAllUserAppDataPath"));
	}

	return csReturn;
}
CString CMaxRandomPattern::GetAPPDataPath(void)
{
	CString csReturn;
	try
	{
		HRESULT hResult	= 0;
		LPITEMIDLIST pidlRoot = NULL;

		TCHAR* lpszPath = NULL;
		lpszPath = new TCHAR[MAX_FILE_PATH];

		if(lpszPath)
		{
			SecureZeroMemory(lpszPath, MAX_FILE_PATH*sizeof(TCHAR));

			hResult	= SHGetSpecialFolderLocation(NULL, CSIDL_APPDATA, &pidlRoot);
			if(NOERROR == hResult)
			{
				SHGetPathFromIDList(pidlRoot, lpszPath);
				csReturn.Format(_T("%s"), lpszPath);
			}

			delete[] lpszPath;
			lpszPath = NULL;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in GetAPPDataPath"));
	}
	return csReturn;
}
CString CMaxRandomPattern::GetProgramFilesDir()
{
	try
	{
		TCHAR lpszPath[MAX_PATH]={0};

		SHGetFolderPath(NULL,CSIDL_PROGRAM_FILES, NULL, 0, lpszPath);
		return lpszPath;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in GetProgramFilesDir"));
	}
	return CString(_T(""));
}
CString	CMaxRandomPattern::GetProgramFilesDirX64()
{
	try
	{
		TCHAR lpszPath[MAX_PATH]={0};

		SHGetFolderPath(NULL,CSIDL_PROGRAM_FILESX86, NULL, 0, lpszPath);
		return lpszPath;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in GetProgramFilesDir"));
	}
	return CString(_T(""));
}