#pragma once
//#include "Python.h"			//For Python Scanner
#include "MaxPEFile.h"
#include "VerInfo.h"
#include "wincrypt.h"
#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)


class CMaxMachineLearning
{
	bool		GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT);
	bool		GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT);
	bool		IsValidFile2Scan(LPCTSTR pszFile2Check);
	bool		IsKnowCompanyName(LPCTSTR pszComName2Check);
	bool		IsKnowCopyrights(LPCTSTR pszCopyright2Check);
	int			LoadCompanyNameList();

	bool		m_bMaxMacLearnLoaded;
//	PyObject	*pMaxMacLrnLib, *pMaxMacLrnModule, *pImportDict;
	TCHAR		szLogLine[1024];

	CStringArray	m_csCompanySafeList;
	CStringArray	m_csCopyrightSafeList;

public:
	CMaxMachineLearning(void);
	~CMaxMachineLearning(void);
	
	//bool	InitializeScanner(LPCTSTR pszClassifierPath,LPCTSTR pszFeaturesPath);
	bool	InitializeScanner(LPCTSTR pszDBPath,bool bMLScanner);
	bool	DeInitializeScanner();
	bool	ScanFile(LPCTSTR pszFile2Scan);
	bool	ScanFileEX(CMaxPEFile *pMaxPEFile);
	bool	DetectWhiteCertificate(LPCTSTR pszFile2Check);
	typedef DWORD (*SCANFILE) (LPCTSTR);
	typedef DWORD (*LOADDB) (LPCTSTR, bool);
	typedef DWORD (*UNLOADDB) ();
	typedef DWORD (*SCANFILEEX)(CMaxPEFile *pMaxPEFile);

	HMODULE m_hMLHeurScanDLL = NULL;
	SCANFILE m_pMLScanFile = NULL;
	SCANFILEEX m_pMLScanFileEx = NULL;
	LOADDB m_pLoadMLScanner = NULL;
	UNLOADDB m_pUnloadMLScanner = NULL;
};
