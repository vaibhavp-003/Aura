/*======================================================================================
FILE				: PolyHeuristics.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 23rd Feb 2017
NOTES				: This is detection module for malware depending on Heuristic rules from binary data.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
					Heuristic Detection of Trojan depending on Static Analysis and following Rules
					Rule 1 : Files with very HIGH File Version Nos. and NO (empty) company name / product name.
						e.g. 1.0.1680.45680 (etc). High chances of creation through build tools. 
					Rule 2 : File with Digital Signatures but NO (empty) company name / product name.
					Rule 3 : Files with only Integer value in Product name and Company Name.
=====================================================================================*/
#include "PolyHeuristics.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyHeuristics
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyHeuristics::CPolyHeuristics(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_lpbyVIB = NULL;
	m_bHasVerionTable = FALSE;
	m_bHasCertificateTable = FALSE;
	Close();
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyHeuristics
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detructor for this class
--------------------------------------------------------------------------------------*/
CPolyHeuristics::~CPolyHeuristics(void)
{
	Close();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
Structure      : s_ppszStr
-------------------------------------------------------------------------------------*/
LPCTSTR CPolyHeuristics::s_ppszStr[] = {	_T("Comments"), _T("CompanyName"),
											_T("FileDescription"), _T("FileVersion"),
											_T("InternalName"), _T("LegalCopyright"),
											_T("LegalTrademarks"), _T("OriginalFilename"),
											_T("PrivateBuild"), _T("ProductName"),
											_T("ProductVersion"), _T("SpecialBuild"),
											_T("OLESelfRegister")};


/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of malware using heuristic rules
--------------------------------------------------------------------------------------*/
int	CPolyHeuristics::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	m_bHasVerionTable = FALSE;
	m_bHasCertificateTable = FALSE;
	Close();

	_tcscpy(m_szCompanyName,L"");
	_tcscpy(m_szProductName,L"");
	_tcscpy(m_szProductVersion,L"");
	_tcscpy(m_szFileInternalName,L"");
	_tcscpy(m_szFileDescription,L"");
	_tcscpy(m_szFileVersion,L"");
	_tcscpy(m_szProductComment,L"");
	_tcscpy(m_szCopyRight,L"");

	m_bHasVerionTable = HasVersionTab(m_pMaxPEFile->m_szFilePath); 

	if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].Size > 0x00 && m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].Size <= m_pMaxPEFile->m_dwFileSize)
	{
		m_bHasCertificateTable = TRUE;
	}

	if (TRUE == m_bHasVerionTable)
	{
		GetCompanyName(m_pMaxPEFile->m_szFilePath,m_szCompanyName);
		GetProductName(m_pMaxPEFile->m_szFilePath,m_szProductName);
		GetProductVersion(m_pMaxPEFile->m_szFilePath,m_szProductVersion);
		GetFileVersion(m_pMaxPEFile->m_szFilePath,m_szFileVersion);
		GetFileInternalName(m_pMaxPEFile->m_szFilePath,m_szFileInternalName);
		GetFileDescription(m_pMaxPEFile->m_szFilePath,m_szFileDescription);
		GetProductComments(m_pMaxPEFile->m_szFilePath,m_szProductComment);
		GetCopyRightInfo(m_pMaxPEFile->m_szFilePath,m_szCopyRight);
	}

	//Scanning For Different Heuristic Rules
	typedef int (CPolyHeuristics::*LPFNDetectVirus)();	
	LPFNDetectVirus pVirusList[] = 
	{	
		//&CPolyHeuristics::CheckForFileVersion,
		//&CPolyHeuristics::CheckForFakeCerWithNoVerTable,
		&CPolyHeuristics::CheckForSuspProductName
	};

	for(int i = 0; i < _countof(pVirusList); i++)
	{
		iRetStatus = (this->*(pVirusList[i]))();
		if(iRetStatus)
		{					
			return iRetStatus;
		}
	}	
	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: HasVersionTab
	In Parameters	: LPCTSTR lpszFileName
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Anand Shrivastva + Virus Analysis Team
	Description		: Check version table from file
--------------------------------------------------------------------------------------*/
bool CPolyHeuristics::HasVersionTab(LPCTSTR lpszFileName)
{
	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: IN LPCTSTR lpszFileName
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Anand Shrivastva + Virus Analysis Team
	Description		: Get version table from file
--------------------------------------------------------------------------------------*/
BOOL CPolyHeuristics::GetVersionInfo(IN LPCTSTR lpszFileName)
{
	// Version: 1.0.0.1
	/*if(false == Is3264BitApp(lpszFileName))
	{
		return (FALSE);
	}*/

	m_bValid = FALSE;
	DWORD dwDummy = 0;
	DWORD dwSize  = ::GetFileVersionInfoSize(const_cast< LPTSTR >(lpszFileName),
											&dwDummy // Set to 0
											);

	if(dwSize > 0)
	{
		m_lpbyVIB = (LPBYTE)malloc(dwSize);
		if(m_lpbyVIB != NULL &&
			::GetFileVersionInfo(const_cast< LPTSTR >(lpszFileName),
			0, dwSize, m_lpbyVIB))
		{
			UINT   uLen    = 0;
			LPVOID lpVSFFI = NULL;
			if(::VerQueryValue(m_lpbyVIB, _T("\\"), (LPVOID*)&lpVSFFI, &uLen))
			{
				::CopyMemory(&m_vsffi, lpVSFFI, sizeof(VS_FIXEDFILEINFO));
				m_bValid =(m_vsffi.dwSignature == VS_FFI_SIGNATURE);
			}
		}
	}
	return m_bValid;
}

/*-------------------------------------------------------------------------------------
	Function		: QueryStringValue
	In Parameters	: IN INT nIndex, OUT LPTSTR lpszValue, IN INT nBuf
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Anand Shrivastva + Virus Analysis Team
	Description		: Supportive function to Get version table from file
--------------------------------------------------------------------------------------*/
BOOL CPolyHeuristics::QueryStringValue(IN INT nIndex, OUT LPTSTR lpszValue, IN INT nBuf) const
{
	if(nIndex < VI_STR_COMMENTS || nIndex > VI_STR_OLESELFREGISTER)
	{
		return FALSE;
	}
	
	return QueryStringValue(s_ppszStr[nIndex], lpszValue, nBuf);
}

/*-------------------------------------------------------------------------------------
	Function		: FindTrans
	In Parameters	: IN LANGID wLID, IN WORD   wCP
	Out Parameters	: -1 for failure else >= 0 
	Purpose			: 
	Author			: Anand Shrivastva + Virus Analysis Team
	Description		: Finds the translation (the Language Identifier and Code Page)in the the version
				information data, if any.
--------------------------------------------------------------------------------------*/
INT CPolyHeuristics::FindTrans(IN LANGID wLID,
								IN WORD   wCP)const
{
	if(m_bValid == FALSE)
	{
		return -1;
	}

	for(UINT n = 0; n < m_nTransCnt; n++)
	{
		if(LOWORD(m_lpdwTrans[ n])== wLID && HIWORD(m_lpdwTrans[ n])== wCP )
		{
			return n;
		}
	}
	return -1;
}

/*-------------------------------------------------------------------------------------
	Function		: SetTrans
	In Parameters	: IN LANGID wLID , IN WORD  wCP
	Out Parameters	: TRUE if success else FALSE 
	Purpose			: 
	Author			: Anand Shrivastva + Virus Analysis Team
	Description		: Sets the Language Identifier and Code Page to use in the version 
					information data (if any).
--------------------------------------------------------------------------------------*/
BOOL CPolyHeuristics::SetTrans(IN LANGID wLID /*LANG_NEUTRAL*/, IN WORD  wCP  /*WSLVI_CP_UNICODE*/)
{
	if(m_bValid == FALSE)
	{
		return FALSE;
	}

	if(GetCurLID()== wLID && GetCurCP()== wCP)
	{
		return TRUE;
	}

	INT nPos = FindTrans(wLID, wCP);
	if(nPos != -1)
	{
		m_nTransCur = nPos;
	}

	return (m_nTransCur == (UINT)nPos);
}

/*-------------------------------------------------------------------------------------
	Function		: SetTransIndex
	In Parameters	: IN UINT nIndex
	Out Parameters	: TRUE if success else FALSE 
	Purpose			: 
	Author			: Anand Shrivastva + Virus Analysis Team
	Description		: Sets the translation to use in the version information data by index (if any).
--------------------------------------------------------------------------------------*/
BOOL CPolyHeuristics::SetTransIndex(IN UINT nIndex /*0*/)
{
	if(m_bValid == FALSE)
	{
		return FALSE;
	}

	if(m_nTransCur == nIndex)
	{
		return TRUE;
	}

	if(nIndex >= 0 && nIndex <= m_nTransCnt)
	{
		m_nTransCur = nIndex;
	}

	return (m_nTransCur == nIndex);
}


/*-------------------------------------------------------------------------------------
	Function		: GetTransByIndex
	In Parameters	: IN UINT nIndex
	Out Parameters	: 0 for Failure else > 0
	Purpose			: 
	Author			: Anand Shrivastva + Virus Analysis Team
	Description		: Extracts the translation (the Language Identifier and Code Page) at
				      the specified index in the translation array (if any).
--------------------------------------------------------------------------------------*/
DWORD CPolyHeuristics::GetTransByIndex(IN UINT nIndex)const
{
	if(m_bValid == FALSE || nIndex < 0 || nIndex > m_nTransCnt)
	{
		return 0;
	}
	return m_lpdwTrans[ nIndex];
}

/*-------------------------------------------------------------------------------------
	Function		: QueryStringValue
	In Parameters	: IN  LPCTSTR lpszItem, OUT LPTSTR  lpszValue, IN  INT    nBuf
	Out Parameters	: TRUE is success else FALSE
	Purpose			: 
	Author			: Anand Shrivastva + Virus Analysis Team
	Description		: 
--------------------------------------------------------------------------------------*/
BOOL CPolyHeuristics::QueryStringValue(IN  LPCTSTR lpszItem, OUT LPTSTR  lpszValue, IN  INT    nBuf) const
{
	//strcpy(lpszItem,"CompanyName");

	
	if(m_bValid  == FALSE || lpszItem == NULL)
	{
		return FALSE;
	}

	if(lpszValue != NULL && nBuf <= 0)
	{
		return FALSE;
	}

	::ZeroMemory(lpszValue, nBuf * sizeof(TCHAR));

	TCHAR	szSFI[ MAX_PATH]={0 };

	swprintf_s(szSFI, _countof(szSFI), _T("\\StringFileInfo\\%04X%04X\\%s"),GetCurLID(), GetCurCP(), lpszItem);
	
	BOOL	bRes    = FALSE;
	UINT	uLen    = 0;
	LPTSTR	lpszBuf = NULL;

	if(::VerQueryValue(m_lpbyVIB, (LPTSTR)szSFI, (LPVOID*)&lpszBuf, &uLen))
	{
		if(lpszValue != NULL && nBuf > 0)
		{
			bRes = (BOOL)(::lstrcpyn(lpszValue, lpszBuf, nBuf) != NULL);
		}
		else
		{
			bRes = TRUE;
		}
	}
	return (bRes);
}

/*-------------------------------------------------------------------------------------
	Function		: GetCompanyName
	In Parameters	: LPCTSTR lpszFileName, LPTSTR lpszCompanyName
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: this function gets company name from File version table
--------------------------------------------------------------------------------------*/
bool CPolyHeuristics::GetCompanyName(LPCTSTR lpszFileName, LPTSTR lpszCompanyName)
{
	if(!lpszCompanyName)
	{
		return false;
	}

	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}

	return (QueryStringValue(1, lpszCompanyName, MAX_PATH) ? true : false);
}

/*-------------------------------------------------------------------------------------
	Function		: GetFileVersion
	In Parameters	: LPCTSTR lpszFileName, LPTSTR lpszFileDescription
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: this function gets file version from version table
--------------------------------------------------------------------------------------*/
bool CPolyHeuristics::GetFileVersion(LPCTSTR lpszFileName, LPTSTR lpszFileDescription)
{
	if(!lpszFileDescription)
	{
		return false;
	}

	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}

	return (QueryStringValue(3, lpszFileDescription, MAX_PATH)?true:false);
}


/*-------------------------------------------------------------------------------------
	Function		: GetFileInternalName
	In Parameters	: LPCTSTR lpszFileName, LPTSTR lpszFileDescription
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get the Orginal name of file
--------------------------------------------------------------------------------------*/
bool CPolyHeuristics::GetFileInternalName(LPCTSTR lpszFileName, LPTSTR lpszFileDescription)
{
	if(!lpszFileDescription)
	{
		return false;
	}

	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}

	return (QueryStringValue(7, lpszFileDescription, MAX_PATH)?true:false);
}


/*-------------------------------------------------------------------------------------
	Function		: GetFileDescription
	In Parameters	: LPCTSTR lpszFileName, LPTSTR lpszFileDescription
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get File description info
--------------------------------------------------------------------------------------*/
bool CPolyHeuristics::GetFileDescription(LPCTSTR lpszFileName, LPTSTR lpszFileDescription)
{
	if(!lpszFileDescription)
	{
		return false;
	}

	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}

	return (QueryStringValue(2, lpszFileDescription, MAX_PATH)?true:false);
}


/*-------------------------------------------------------------------------------------
	Function		: GetInternalNameofFile
	In Parameters	: LPCTSTR lpszFileName, LPTSTR lpszFileDescription
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get the internal name of file
--------------------------------------------------------------------------------------*/
bool CPolyHeuristics::GetInternalNameofFile(LPCTSTR lpszFileName, LPTSTR lpszFileDescription)
{
	if(!lpszFileDescription)
	{
		return false;
	}

	if(Open(lpszFileName)== FALSE)
	{
		return false;
	}

	return (QueryStringValue(4, lpszFileDescription, MAX_PATH) ? true : false);
}


/*-------------------------------------------------------------------------------------
	Function		: GetCopyRightInfo
	In Parameters	: LPCTSTR lpszFileName, LPTSTR lpszCopyWriteInfo
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get copyright information of file
--------------------------------------------------------------------------------------*/
bool CPolyHeuristics::GetCopyRightInfo(LPCTSTR lpszFileName, LPTSTR lpszCopyWriteInfo)
{
	if(!lpszCopyWriteInfo)
	{
		return false;
	}

	if(Open(lpszFileName) == FALSE)
	{
		return false;
	}

	return (QueryStringValue(5, lpszCopyWriteInfo, MAX_PATH)?true:false);
}

/*-------------------------------------------------------------------------------------
	Function		: GetProductVersion
	In Parameters	: LPCTSTR lpszFileName, LPTSTR lpszFileDescription
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get product version of file
--------------------------------------------------------------------------------------*/
bool CPolyHeuristics::GetProductVersion(LPCTSTR lpszFileName, LPTSTR lpszFileDescription)
{
	if(!lpszFileDescription)
	{
		return false;
	}

	if(Open(lpszFileName) == FALSE)
	{
		return false;
	}

	return (QueryStringValue(10, lpszFileDescription, MAX_PATH)?true:false);
}


/*-------------------------------------------------------------------------------------
	Function		: GetProductComments
	In Parameters	: LPCTSTR lpszFileName, LPTSTR lpszProductName
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get product's internal comment of file
--------------------------------------------------------------------------------------*/
bool CPolyHeuristics::GetProductComments(LPCTSTR lpszFileName, LPTSTR lpszProductName)
{
	if(!lpszProductName)
		return false;

	if(Open( lpszFileName ) == FALSE)
		return false;

	return (QueryStringValue(0, lpszProductName, MAX_PATH)?true:false);
}

/*-------------------------------------------------------------------------------------
	Function		: GetProductName
	In Parameters	: LPCTSTR lpszFileName, LPTSTR lpszProductName
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get product's name of file
--------------------------------------------------------------------------------------*/
bool CPolyHeuristics::GetProductName(LPCTSTR lpszFileName, LPTSTR lpszProductName)
{
	if(!lpszProductName)
		return false;

	if(Open( lpszFileName ) == FALSE)
		return false;

	return (QueryStringValue(9, lpszProductName, MAX_PATH)?true:false);
}

/*-------------------------------------------------------------------------------------
	Function		: Open
	In Parameters	: IN LPCTSTR lpszFileName
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Anand Shrivastava + Virus Analysis Team
	Description		: This function opens file for retrieving version info
--------------------------------------------------------------------------------------*/
BOOL CPolyHeuristics::Open(IN LPCTSTR lpszFileName)
{
	if(lpszFileName == NULL)
	{
		return FALSE;
	}

	Close();
	if(!GetVersionInfo(lpszFileName) || !QueryVersionTrans())
	{
		Close();
	}

	return m_bValid;
};

/*-------------------------------------------------------------------------------------
	Function		: Close
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Anand Shrivastava + Virus Analysis Team
	Description		: This function close file
--------------------------------------------------------------------------------------*/
void CPolyHeuristics::Close(void)
{
	m_nTransCnt  = 0;
	m_nTransCur  = 0;
	m_bValid	 = FALSE;
	m_lpdwTrans  = NULL;

	::ZeroMemory(&m_vsffi, sizeof(VS_FIXEDFILEINFO));
	if(m_lpbyVIB)
	{
		free(m_lpbyVIB);
		m_lpbyVIB = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: QueryVersionTrans
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Anand Shrivastava + Virus Analysis Team
	Description		: This function close file
--------------------------------------------------------------------------------------*/
BOOL CPolyHeuristics::QueryVersionTrans(void)
{
	if(m_bValid == FALSE)
	{
		return FALSE;
	}

	UINT   uLen  = 0;
	LPVOID lpBuf = NULL;

	if(::VerQueryValue(m_lpbyVIB, _T("\\VarFileInfo\\Translation"), (LPVOID*)&lpBuf, &uLen))
	{
		m_lpdwTrans = (LPDWORD)lpBuf;
		m_nTransCnt =(uLen / sizeof(DWORD));
	}
	return (BOOL)(m_lpdwTrans != NULL);
}

//Rule : 1
/*-------------------------------------------------------------------------------------
	Function		: CheckForFileVersion
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection using Rule 1
--------------------------------------------------------------------------------------*/
int	CPolyHeuristics::CheckForFileVersion()
{
	int		iRetStatus = VIRUS_NOT_FOUND;

	TCHAR	szProdVersion[MAX_PATH] = {0x00};
	TCHAR	szProdName[MAX_PATH] = {0x00};
	TCHAR	szCompName[MAX_PATH] = {0x00};
	TCHAR	szFileInName[MAX_PATH] = {0x00};
	TCHAR	szFileDescription[MAX_PATH] = {0x00};
	DWORD	dwMajVersion = 0x00, dwMinVersion = 0x00, dwThirdVersion = 0x00;
	TCHAR	*pTemp = NULL;

	_tcscpy(szProdName,m_szProductName);
	_tcscpy(szCompName,m_szCompanyName);
	_tcscpy(szProdVersion,m_szProductVersion);
	_tcscpy(szFileInName,m_szFileInternalName);
	_tcscpy(szFileDescription,m_szFileDescription);

	/*
	//Original Working
	if (_tcslen(szProdVersion) == 0x00 || _tcslen(szProdName) > 0x00 || _tcslen(szCompName) > 0x00 || _tcslen(szFileInName) > 0x00 || _tcslen(szFileDescription) > 0x00)
	{
		return iRetStatus;
	}
	*/

	if (_tcslen(szProdVersion) == 0x00 || _tcslen(szProdName) > 0x00 || _tcslen(szCompName) > 0x00)
	{
		return iRetStatus;
	}

	if (_tcslen(szFileInName) > 0x00 && _tcslen(szFileDescription) > 0x02 && _tcslen(m_szCopyRight) > 0x02)
	{
		return iRetStatus;
	}

	_tcslwr(szProdVersion);
	if (_tcslen(szProdVersion) < 12)
	{
		return iRetStatus;
	}

	pTemp = NULL;
	pTemp = _tcsrchr(szProdVersion,_T('.'));
	if (pTemp == NULL)
	{
		return iRetStatus;
	}

	pTemp++;
	if (pTemp == NULL)
	{
		return iRetStatus;
	}

	dwMinVersion = _tcstod(pTemp,NULL);
	pTemp--;
	*pTemp = 0;

	pTemp = NULL;
	pTemp = _tcsrchr(szProdVersion,_T('.'));
	if (pTemp == NULL)
	{
		return iRetStatus;
	}

	pTemp++;
	if (pTemp == NULL)
	{
		return iRetStatus;
	}

	dwMajVersion = _tcstod(pTemp,NULL);

	pTemp--;
	*pTemp = 0;

	pTemp = NULL;
	pTemp = _tcsrchr(szProdVersion,_T('.'));
	if (pTemp != NULL)
	{
		pTemp++;
		dwThirdVersion = _tcstod(pTemp,NULL);
	}

	DWORD	dwHitScore = 0x00;	

	if (dwMajVersion >= 5000)
	{
		dwHitScore++;
	}

	if (dwMinVersion >= 1000)
	{
		dwHitScore++;
	}

	if (dwThirdVersion >= 2000)
	{
		dwHitScore++;
	}

	//if (dwMajVersion >= 5000 && dwMinVersion >= 1000)
	if (dwHitScore >= 0x02)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, L"not-a-virus:Trojan.SuspHeur.Gen");
		iRetStatus = VIRUS_FILE_DELETE;
	}
	

	return iRetStatus;
}

//Rule : 2
/*-------------------------------------------------------------------------------------
	Function		: CheckForFakeCerWithNoVerTable
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection using Rule 2
--------------------------------------------------------------------------------------*/
int	CPolyHeuristics::CheckForFakeCerWithNoVerTable()
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	TCHAR	szFilePath[1024]  = {0x00};

	if (m_bHasCertificateTable == FALSE)
	{
		return iRetStatus;
	}

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}

	_tcscpy(szFilePath,m_pMaxPEFile->m_szFilePath);
	_tcslwr(szFilePath);

	if (_tcslen(szFilePath) <= 0x08)
	{
		return iRetStatus; 
	}

	if (_tcsstr(szFilePath,L"\\program files") != NULL || _tcsstr(szFilePath,L"\\windows\\") != NULL || _tcsstr(szFilePath,L"\\winddk\\") != NULL)
	{
		return iRetStatus; 
	}

	if (_tcslen(m_szCompanyName) == 0x00 && _tcslen(m_szProductName) == 0x00 && _tcslen(m_szFileInternalName) == 0x00 
		&& _tcslen(m_szFileDescription) == 0x00 && _tcslen(m_szFileVersion) == 0x00 && _tcslen(m_szProductVersion) == 0x00)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, L"not-a-virus:Trojan.SuspHeur2.Gen");
		iRetStatus = VIRUS_FILE_DELETE;
	}

	return iRetStatus;
}

//Rule : 3
/*-------------------------------------------------------------------------------------
	Function		: CheckForSuspProductName
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection using Rule 3
--------------------------------------------------------------------------------------*/
int	CPolyHeuristics::CheckForSuspProductName()
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	TCHAR	szProductName[MAX_PATH] = {0x00};
	BOOL	bNonNumericCharFound = FALSE;


	if (m_bHasVerionTable == FALSE)
	{
		return iRetStatus;
	}

	_tcscpy(szProductName,m_szProductName);
	_tcslwr(szProductName); 

	DWORD	dwLen = _tcslen(szProductName);
	if (dwLen <= 0x08)
	{
		return iRetStatus;
	}

	for(int i = 0x00; i < dwLen; i++)
	{
		if (!(szProductName[i] >= '0' && szProductName[i] <= '9'))
		{
			bNonNumericCharFound = TRUE;
			break;
		}
	}

	if (bNonNumericCharFound == FALSE)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, L"not-a-virus:Trojan.SuspHeur3.Gen");
		iRetStatus = VIRUS_FILE_DELETE;
	}

	return iRetStatus;
}