/*======================================================================================
FILE             : FileSignatureDb.h
ABSTRACT         : Class for handling operation realted to local sugnature db
DOCUMENTS        : 
AUTHOR           : Dipali Pawar
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 01-Sep-2007
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : Version: 19.0.0.053, Dipali : Solved no disk space problem.
======================================================================================*/
#include "pch.h"
#include "FileSignatureDb.h"
#include "MaxConstant.h"
#include <atlbase.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

const LPCSTR szLocalDBVersionNo = "MAXDBVERSION000001";

bool GetMD5Signature16(const char *filepath, unsigned char bMD5Signature[16]);

/*--------------------------------------------------------------------------------------
Function       : CFileSignatureDb
In Parameters  : void, 
Out Parameters : 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CFileSignatureDb::CFileSignatureDb(void):
					m_objPEFileSigLocalDB(false, 8, sizeof(PESIGCRCLOCALDB)),
					m_objVirusLocalDB(false, 8, sizeof(VIRUSLOCALDB))
{
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
	SetInstallPath();
	SetProductRegKey();
}

/*--------------------------------------------------------------------------------------
Function       : ~CFileSignatureDb
In Parameters  : void, 
Out Parameters : 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CFileSignatureDb::~CFileSignatureDb(void)
{
	if(m_hEvent)
	{
		CloseHandle(m_hEvent);
		m_hEvent = NULL;
	}
}

/*-------------------------------------------------------------------------------------
Function		: SaveAllDB
In Parameters	: none
Out Parameters	: void
Purpose			: Save the local DB
Author			: Dipali
--------------------------------------------------------------------------------------*/
void CFileSignatureDb::SaveAllDB()
{
	m_objPEFileSigLocalDB.Balance();
	m_objPEFileSigLocalDB.SaveByVer(m_csPESigFileName, true, szLocalDBVersionNo);
	m_objPEFileSigLocalDB.RemoveAll();

	m_objVirusLocalDB.Balance();
	m_objVirusLocalDB.SaveByVer(m_csVirusDBFileName, true, m_csLocalDBVersion);
	m_objVirusLocalDB.RemoveAll();
}

/*-------------------------------------------------------------------------------------
Function		: LoadAllDB
In Parameters	: none
Out Parameters	: void
Purpose			: Read the local DB
Author			: Dipali
--------------------------------------------------------------------------------------*/
bool CFileSignatureDb::LoadAllDB()
{
	m_objPEFileSigLocalDB.LoadByVer(m_csPESigFileName, true, szLocalDBVersionNo);
	m_objVirusLocalDB.LoadByVer(m_csVirusDBFileName, true, m_csLocalDBVersion);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetMD5Signature
In Parameters  : const TCHAR *cFileName, BYTE bMD5Signature[iMAX_MD5_SIG_LEN], 
Out Parameters : bool true if successfull else false
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileSignatureDb::GetMD5Signature(const TCHAR *cFileName, BYTE bMD5Signature[iMAX_MD5_SIG_LEN])
{
	return GetMD5Signature16(CStringA(cFileName), bMD5Signature);
}

/*--------------------------------------------------------------------------------------
Function       : GetFileSignature
In Parameters  : const TCHAR *cFileName, PESIGCRCLOCALDB &PESigLocal, VIRUSLOCALDB &VirusLocalDB
Out Parameters : true if successfull, else false
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileSignatureDb::GetFileSignature(const TCHAR *cFileName, PESIGCRCLOCALDB &PESigLocal, 
																VIRUSLOCALDB &VirusLocalDB)
{
	WIN32_FIND_DATA oFindFileData = {0};
	HANDLE hFindFile = INVALID_HANDLE_VALUE;
	hFindFile = FindFirstFile(cFileName, &oFindFileData);
	if(INVALID_HANDLE_VALUE == hFindFile)
	{
		return false;
	}

	ULONG64 ulFileNameCRC = 0;
	if(!CreateCRC64(cFileName, ulFileNameCRC))
	{
		FindClose(hFindFile);
		return false;
	}

	bool bReturnVal = false;
	LPPESIGCRCLOCALDB lpLocalDBEntry = 0;
	WaitForSingleObject(m_hEvent, INFINITE);
	if(m_objPEFileSigLocalDB.SearchItem(&ulFileNameCRC, (LPVOID&)lpLocalDBEntry))
	{
		SetEvent(m_hEvent);
		if(lpLocalDBEntry)
		{
			if((lpLocalDBEntry->dwModifiedTimeHigh == oFindFileData.ftLastWriteTime.dwHighDateTime)
				&& (lpLocalDBEntry->dwModifiedTimeLow == oFindFileData.ftLastWriteTime.dwLowDateTime)
				&& (lpLocalDBEntry->dwFileSizeHigh == oFindFileData.nFileSizeHigh)
				&& (lpLocalDBEntry->dwFileSizeLow == oFindFileData.nFileSizeLow))
				//&& (lpLocalDBEntry->ulSignature != 0))
			{
				memcpy_s(&PESigLocal, sizeof(PESIGCRCLOCALDB), lpLocalDBEntry, sizeof(PESIGCRCLOCALDB));
				bReturnVal = true;
			}
		}
	}
	else
	{
		SetEvent(m_hEvent);
	}

	if(bReturnVal)		// If found PE Signture in Local DB, Look up Virus Local Signature too
	{
		LPVIRUSLOCALDB lpLocalDBEntry = 0;
		WaitForSingleObject(m_hEvent, INFINITE);
		if(m_objVirusLocalDB.SearchItem(&ulFileNameCRC, (LPVOID&)lpLocalDBEntry))
		{
			SetEvent(m_hEvent);
			memcpy_s(&VirusLocalDB, sizeof(VIRUSLOCALDB), lpLocalDBEntry, sizeof(VIRUSLOCALDB));
		}
		else
		{
			SetEvent(m_hEvent);
		}
	}

	WCHAR *wcsTemp = new WCHAR[MAX_PATH*2];
	wmemset(wcsTemp, 0, MAX_PATH*2);
	swprintf_s(wcsTemp, MAX_PATH*2, _T(">>>>> GET-LOCAL  : %s : %i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i"), cFileName,
								PESigLocal.btVirusPolyScanStatus[0], PESigLocal.btVirusPolyScanStatus[1],
								PESigLocal.btVirusPolyScanStatus[2], PESigLocal.btVirusPolyScanStatus[3],
								PESigLocal.btVirusPolyScanStatus[4], PESigLocal.btVirusPolyScanStatus[5],
								PESigLocal.btVirusPolyScanStatus[6], PESigLocal.btVirusPolyScanStatus[7],
								PESigLocal.btVirusPolyScanStatus[8], PESigLocal.btVirusPolyScanStatus[9],
								PESigLocal.btVirusPolyScanStatus[10], PESigLocal.btVirusPolyScanStatus[11],
								PESigLocal.btVirusPolyScanStatus[12], PESigLocal.btVirusPolyScanStatus[13],
								PESigLocal.btVirusPolyScanStatus[14], PESigLocal.btVirusPolyScanStatus[15]);
	AddLogEntry(wcsTemp, 0, 0, true, LOG_DEBUG);
	delete [] wcsTemp;
	wcsTemp = NULL;

	FindClose(hFindFile);
	return bReturnVal;
}

/*--------------------------------------------------------------------------------------
Function       : SetFileSignature
In Parameters  : const TCHAR *cFileName, PESIGCRCLOCALDB &PESigLocal, VIRUSLOCALDB &VirusLocalDB
Out Parameters : bool true is successfull, else false 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileSignatureDb::SetFileSignature(const TCHAR *cFileName, PESIGCRCLOCALDB &PESigLocal, 
																VIRUSLOCALDB &VirusLocalDB)
{
	//if(PESigLocal.ulSignature == 0)
	//{
	//	return false;
	//}
	WCHAR *wcsTemp = new WCHAR[MAX_PATH*2];
	wmemset(wcsTemp, 0, MAX_PATH*2);
	swprintf_s(wcsTemp, MAX_PATH*2, _T(">>>>> SET-LOCAL  : %s : %i%i%i%i%i%i%i%i%i%i%i%i%i%i%i%i"), cFileName,
								PESigLocal.btVirusPolyScanStatus[0], PESigLocal.btVirusPolyScanStatus[1],
								PESigLocal.btVirusPolyScanStatus[2], PESigLocal.btVirusPolyScanStatus[3],
								PESigLocal.btVirusPolyScanStatus[4], PESigLocal.btVirusPolyScanStatus[5],
								PESigLocal.btVirusPolyScanStatus[6], PESigLocal.btVirusPolyScanStatus[7],
								PESigLocal.btVirusPolyScanStatus[8], PESigLocal.btVirusPolyScanStatus[9],
								PESigLocal.btVirusPolyScanStatus[10], PESigLocal.btVirusPolyScanStatus[11],
								PESigLocal.btVirusPolyScanStatus[12], PESigLocal.btVirusPolyScanStatus[13],
								PESigLocal.btVirusPolyScanStatus[14], PESigLocal.btVirusPolyScanStatus[15]);
	AddLogEntry(wcsTemp, 0, 0, true, LOG_DEBUG);
	delete [] wcsTemp;
	wcsTemp = NULL;

	WIN32_FIND_DATA oFindFileData = {0};
	HANDLE hFindFile = INVALID_HANDLE_VALUE;
	hFindFile = FindFirstFile(cFileName, &oFindFileData);
	if(INVALID_HANDLE_VALUE == hFindFile)
	{
		return false;
	}

	ULONG64 ulFileNameCRC = 0;
	if(!CreateCRC64(cFileName, ulFileNameCRC))
	{
		FindClose(hFindFile);
		return false;
	}

	PESigLocal.dwModifiedTimeHigh = oFindFileData.ftLastWriteTime.dwHighDateTime;
	PESigLocal.dwModifiedTimeLow = oFindFileData.ftLastWriteTime.dwLowDateTime;
	PESigLocal.dwFileSizeHigh = oFindFileData.nFileSizeHigh;
	PESigLocal.dwFileSizeLow = oFindFileData.nFileSizeLow;

	WaitForSingleObject(m_hEvent, INFINITE);
	//Save PE, Virus Poly Signature in local DB
	if(!m_objPEFileSigLocalDB.AppendItem(&ulFileNameCRC, &PESigLocal))
	{
		m_objPEFileSigLocalDB.DeleteItem(&ulFileNameCRC);
		m_objPEFileSigLocalDB.AppendItem(&ulFileNameCRC, &PESigLocal);
	}

	//Save Virus DB Scan Status in local DB
	if(!m_objVirusLocalDB.AppendItem(&ulFileNameCRC, &VirusLocalDB))
	{
		m_objVirusLocalDB.DeleteItem(&ulFileNameCRC);
		m_objVirusLocalDB.AppendItem(&ulFileNameCRC, &VirusLocalDB);
	}
	SetEvent(m_hEvent);

	FindClose(hFindFile);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetStringDataFromIni
In Parameters  : TCHAR *csVal
Out Parameters : CString Value from Ini
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CString CFileSignatureDb::GetStringDataFromIni(TCHAR *csVal)
{
	TCHAR szData[MAX_PATH] = {0};
	GetPrivateProfileString(SETTING_VAL_INI, csVal, _T(""), szData, MAX_PATH, m_csCurrentSettingIniPath);
	return CString(szData);
}

/*--------------------------------------------------------------------------------------
Function       : SetInstallPath
In Parameters  : none
Out Parameters : void
Description    : Initializes the application install path
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CFileSignatureDb::SetInstallPath()
{
	TCHAR sExeFileName[MAX_FILE_PATH]={0};
	GetModuleFileName((HINSTANCE)&__ImageBase, sExeFileName, MAX_FILE_PATH);

	CString csInstallPath;
	csInstallPath = sExeFileName;

	int iPos = 0;
	iPos = csInstallPath.ReverseFind('\\');
	if(iPos == -1)
	{
		m_strInstallPath = csInstallPath + BACK_SLASH;
	}
	else
	{
		csInstallPath = csInstallPath.Mid(0, iPos);
		m_strInstallPath = (csInstallPath + BACK_SLASH);
	}
}

/*--------------------------------------------------------------------------------------
Function       : SetProductRegKey
In Parameters  : none
Out Parameters : void
Description    : Initializes the Product key to use, which is used by virus local db
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CFileSignatureDb::SetProductRegKey()
{
	m_csCurrentSettingIniPath = m_strInstallPath + SETTING_FOLDER + CURRENT_SETTINGS_INI;
	TCHAR szData[MAX_PATH] = {0};
	GetPrivateProfileString(SETTING_VAL_INI, _T("PRODUCT_REG"), _T(""), szData, MAX_PATH, m_csCurrentSettingIniPath);
	m_strProductKey = szData;

	m_csLocalDBVersion = "000005000005000005";

	CRegKey objRegKey;
	if(objRegKey.Open(HKEY_LOCAL_MACHINE, m_strProductKey) == ERROR_SUCCESS)
	{
		CString csDatabase = _T("000000");

		wmemset(szData, 0, MAX_PATH);
		ULONG ulLen = MAX_PATH;
		objRegKey.QueryStringValue(L"VirusVersionNo", szData, &ulLen);
		CString csVirusPatch = CString(szData);

		wmemset(szData, 0, MAX_PATH);
		ulLen = MAX_PATH;
		objRegKey.QueryStringValue(VIRUSDBUPDATECOUNT, szData, &ulLen);
		CString csVirusDBUpdateCount = CString(szData);

		csDatabase.Remove('.');
		csVirusPatch.Remove('.');
		csVirusDBUpdateCount.Remove('.');
		csDatabase = csDatabase.Right(6);
		csVirusPatch = csVirusPatch.Right(6);
		csVirusDBUpdateCount = csVirusDBUpdateCount.Right(6);
		m_csLocalDBVersion.Format("%06S%06S%06S", csDatabase, csVirusPatch, csVirusDBUpdateCount);
		if(m_csLocalDBVersion.Trim().GetLength() < 18)
		{
			m_csLocalDBVersion = "000005000005000005";
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : GetAllUserAppDataPath
In Parameters  : none
Out Parameters : CString
Description    : returns the Local DB Path to use
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CString CFileSignatureDb::GetAllUserAppDataPath(void)
{
	CString csReturn;
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
	return csReturn;
}

/*--------------------------------------------------------------------------------------
Function       : PrepareLocalDBPath
In Parameters  : const TCHAR *cDriveLetter, int nScannerType
Out Parameters : void
Description    : prepares the file name to use for local db according to the current scanner
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CFileSignatureDb::PrepareLocalDBPath(const TCHAR *cDriveLetter, int nScannerType)
{
	CString csLocalDBPath = GetAllUserAppDataPath();
	CString csTemp(csLocalDBPath);
	CString csProductNo =  GetStringDataFromIni(_T("PRODUCTNUM"));
	CString csParentName = GetStringDataFromIni(_T("APP_PATH_PROD_PARENT"));

	csTemp += _T("\\") + csParentName;

	if(PathFileExists(csTemp) == FALSE)
	{
		CreateDirectoryW(csTemp,NULL);
	}

	csLocalDBPath += GetStringDataFromIni(_T("SD_PRODUCT_APP_PATH"));
	if(PathFileExists(csLocalDBPath) == FALSE)
	{
		CreateDirectoryW(csLocalDBPath,NULL);
	}

	CString csPEFileName, csVirusDBFileName;
	if(nScannerType == Scanner_Type_Max_SignatureScan)
	{
		csPEFileName.Format(_T("\\%c_F_PE_%s"), cDriveLetter[0], SD_DB_LOCAL_SIGNATURE);
		csVirusDBFileName.Format(_T("\\%c_F_VD_%s"), cDriveLetter[0], SD_DB_LOCAL_SIGNATURE);
	}
	else if(nScannerType == Scanner_Type_Max_Startup)
	{
		csPEFileName.Format(_T("\\%c_S_PE_%s"), cDriveLetter[0], SD_DB_LOCAL_SIGNATURE);
		csVirusDBFileName.Format(_T("\\%c_S_VD_%s"), cDriveLetter[0], SD_DB_LOCAL_SIGNATURE);
	}
	else if(nScannerType == Scanner_Type_Max_Email_Scan)
	{
		csPEFileName.Format(_T("\\%c_E_PE_%s"), cDriveLetter[0], SD_DB_LOCAL_SIGNATURE);
		csVirusDBFileName.Format(_T("\\%c_E_VD_%s"), cDriveLetter[0], SD_DB_LOCAL_SIGNATURE);
	}
	else
	{
		csPEFileName.Format(_T("\\%c_A_PE_%s"), cDriveLetter[0], SD_DB_LOCAL_SIGNATURE);
		csVirusDBFileName.Format(_T("\\%c_A_VD_%s"), cDriveLetter[0], SD_DB_LOCAL_SIGNATURE);
	}

	m_csPESigFileName = csLocalDBPath + csPEFileName;
	m_csVirusDBFileName = csLocalDBPath + csVirusDBFileName;
}

/*--------------------------------------------------------------------------------------
Function       : LoadLocalDatabase
In Parameters  : const TCHAR *cDriveLetter, int nScannerType
Out Parameters : true if successfull, else false
Description    : loads the pe, poly and virus db local database
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CFileSignatureDb::LoadLocalDatabase(const TCHAR *cDriveLetter, int nScannerType)
{
	bool bRet = false;

	// Prepare Database path according to the current scanner type
	PrepareLocalDBPath(cDriveLetter, nScannerType);

	// Load Selected Local Databases
	bRet = LoadAllDB();
	
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : UnLoadLocalDatabase
In Parameters  : none
Out Parameters : void
Description    : save the pe, poly and virus db local database
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CFileSignatureDb::UnLoadLocalDatabase()
{
	SaveAllDB();
	return;
}