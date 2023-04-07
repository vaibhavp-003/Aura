/*======================================================================================
FILE             : FileSystemBase.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshan Singh Virdi
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
(C) Aura
Created as an unpublished copyright work.  All rights reserved.
This document and the information it contains is confidential and
This document and the information it contains is confidential and
proprietary to Aura.  Hence, it may not be 
used, copied, reproduced, transmitted, or stored in any form or by any 
means, electronic, recording, photocopying, mechanical or otherwise, 
without the prior written permission of Aura.	

CREATION DATE    : 8/1/2009 6:53:00 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "..\SDScanner.h"
#include "FileSystemBase.h"
#include "MaxExceptionFilter.h"
#include <shlwapi.h>
#include <comdef.h>
#include "BufferToStructure.h"
#include "NetWorkUserValidation.h"
#include "S2S.h"
#include "SDSystemInfo.h"
#include "Registry.h"
#include <Lmcons.h>
#include <lm.h>
#pragma comment(lib, "netapi32.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

int  START_SCAN_PERCENT = 3;
int END_SCAN_PERCENT = 90;
int DUMMY_MAX_SCAN_PERCENT = 10;

const int EXTENSION_FOR_QUICK_SCAN = 14;
const DWORD MAX_FULLPATH_SIZE = (MAX_PATH * 2)+10 ;
WCHAR ValidExtension[EXTENSION_FOR_QUICK_SCAN][5] =
{
	{L".EXE"}, {L".TMP"}, {L".DLL"}, {L".OCX"}, {L".SYS"}, 
	{L".COM"}, {L".DOC"}, {L".XLS"}, {L".XLT"}, {L".PPT"}, 
	{L".LNK"}, {L".WMA"}, {L".CPL"}, {L".SCR"}
};

/*--------------------------------------------------------------------------------------
Function       : IsValidExtension
In Parameters  : WCHAR *cFileName, 
Out Parameters : int nt 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
int IsValidExtension(WCHAR *cFileName)
{
	WCHAR *ExtPtr;
	INT i;

	ExtPtr = wcsrchr(cFileName, '.');
	if(ExtPtr != NULL)
	{
		for(i = 0; i < EXTENSION_FOR_QUICK_SCAN; i++)
		{
			if(_wcsicmp(ExtPtr, ValidExtension[i])== 0)
				return i;
		}
	}
	return -1;
}

/*--------------------------------------------------------------------------------------
Function       : AppendString
In Parameters  : LPTSTR szFinal, DWORD cchFinal, LPCTSTR szAppend
Out Parameters : bool
Description    : concatenate strings but return false if dest smaller
Author & Date  : Anand Srivastava & 22 July, 2011.
--------------------------------------------------------------------------------------*/
bool AppendString(LPTSTR szFinal, DWORD cchFinal, LPCTSTR szAppend)
{
	if(_tcslen(szFinal) + _tcslen(szAppend) >= cchFinal)
	{
		return false;
	}

	_tcscat_s(szFinal, cchFinal, szAppend);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : JoinStrings
In Parameters  : LPTSTR szFinal, DWORD cchFinal, LPCTSTR szFormat, ...
Out Parameters : bool
Description    : join strings but return false if dest smaller
Author & Date  : Anand Srivastava & 22 July, 2011.
--------------------------------------------------------------------------------------*/
bool JoinStrings(LPTSTR szFinal, DWORD cchFinal, LPCTSTR szFormat, ...)
{
	va_list Arguments_List;
	DWORD dwReqLen = 0;

	va_start(Arguments_List, szFormat);
	dwReqLen = _vsctprintf(szFormat, Arguments_List);
	if(dwReqLen >= cchFinal)
	{
		return false;
	}

	memset(szFinal, 0, cchFinal * sizeof(TCHAR));
	_vstprintf_s(szFinal, cchFinal, szFormat, Arguments_List);
	va_end(Arguments_List);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::CFileSystemBase
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CFileSystemBase::CFileSystemBase(void):m_objFolderDBMap(false), m_objFileDBMap(false), 
										m_objCookieDBMap(false), m_bVirusScan(false)
{
	ldwtemp = 0;
	iCounter = 0;
	bDummyCount = true;
	bArrSampleZero = false;
	bInitialCount = false;
	bMedianCalculate = false;
	ldwProgress_In_Percent = 0;
	ldwPrevious_Progress = 0;
	ldwPreviousTime = 0;
	ldwGetDiffTime = 0;
	dwPrevious_count = 0;
	Forty5MinuteIn = 0;
	TwentyMinuteIn = 1;
	FifteenMinuteIn = 0;
	ldwTotalRemTime = 0;
	ldwActualRemTime = 0;
	ldwOriginalSampleValue = 0;
	dwPreviousTotalFileCount = 0;
	dwActualFileCountPending = 0x0;
	dwActualFileCountInIncrements = 0;
	memset(Arr_CollectSamplingFiles, 0, sizeof(Arr_CollectSamplingFiles));

	m_bCustomScan = false;

	m_bActualValueReady = false;
	m_dwTotalNoOfFilesToScan = 0;
	m_ulFileCount = 0;
	m_bStatusVariableLock = CreateEvent(NULL, FALSE, TRUE, NULL);
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::~CFileSystemBase
In Parameters  : void,
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CFileSystemBase::~CFileSystemBase(void)
{
	UnloadAllDatabase();
	CloseHandle(m_bStatusVariableLock);
	m_bStatusVariableLock = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::UnloadAllDatabase
In Parameters  :
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::UnloadAllDatabase()
{
	m_objFolderDBMap.RemoveAll();
	m_objFileDBMap.RemoveAll();
	m_objCookieDBMap.RemoveAll();
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::StartCookieScan
In Parameters  : const TCHAR *strDrivesToScan,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::StartCookieScan(const TCHAR *strDrivesToScan)
{
	TCHAR	cDriveToScan = m_oDBPathExpander.m_cs543[0];
	DWORD	dwIsCookiesScanningON = 0x00;

	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, _T("CookiesScan"), dwIsCookiesScanningON, HKEY_LOCAL_MACHINE);
	
	if (dwIsCookiesScanningON == 0x01)
	{
		if((wcscmp(strDrivesToScan, L"")== 0) || (wcschr(strDrivesToScan, cDriveToScan) != NULL))
		{
			CString csMaxDBPath;
			m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
			if(m_objCookieDBMap.GetFirst()== NULL)
			{
				m_objCookieDBMap.Load(csMaxDBPath + SD_DB_COOKIES);
			}

			if(m_objCookieDBMap.GetFirst() != NULL)
			{
				LPVOID posUserName = m_objAvailableUsers.GetFirst();
				while((!m_bStopScanning) && (posUserName))
				{
					LPTSTR strUserName = NULL;
					m_objAvailableUsers.GetData(posUserName, strUserName);
					CString csCookiePath(m_oDBPathExpander.m_cs511);
					csCookiePath.Replace(L"<user>", strUserName);
					EnumFolder(csCookiePath, true);
					posUserName = m_objAvailableUsers.GetNext(posUserName);
				}
			}
			else
			{
				SetFullLiveUpdateReg(csMaxDBPath + SD_DB_COOKIES);
			}
		}
	}
	CString csPercentage;
	//csPercentage.Format(L"%d", 10);
	csPercentage.Format(L"%d", 1);
	SendScanStatusToUI(Status_Bar_File_Report, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0);

}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::StartFolderScan
In Parameters  : const TCHAR *strDrivesToScan,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::StartFolderScan(const TCHAR *strDrivesToScan)
{
	TCHAR cDriveToScan = m_oDBPathExpander.m_cs543[0];
	if((wcscmp(strDrivesToScan, L"")== 0) || (wcschr(strDrivesToScan, cDriveToScan) != NULL))
	{
		CString csMaxDBPath;
		m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
		if(m_objFolderDBMap.GetFirst() ==  NULL)
		{
			m_objFolderDBMap.Load(csMaxDBPath + SD_DB_FOLDER);
		}

		if(m_objFolderDBMap.GetFirst() != NULL)
		{
			initilizeFirefoxPath();
			m_sTempPath=_T("");
			initilizeChromePath();
			ScanUsingDBByValueType(cDriveToScan, m_objFolderDBMap, true);
		}
		else
		{
			SetFullLiveUpdateReg(csMaxDBPath + SD_DB_FOLDER);
		}
	}
	CString csPercentage;
	csPercentage.Format(L"%d", 97);
	SendScanStatusToUI(Status_Bar_File_Report, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0);
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::StartFileScan
In Parameters  : const TCHAR *strDrivesToScan,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::StartFileScan(const TCHAR *strDrivesToScan)
{
	TCHAR cDriveToScan = m_oDBPathExpander.m_cs543[0];
	if((wcscmp(strDrivesToScan, L"")== 0) || (wcschr(strDrivesToScan, cDriveToScan) != NULL))
	{
		CString csMaxDBPath;
		m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
		if(m_objFileDBMap.GetFirst()== NULL)
		{
			m_objFileDBMap.Load(csMaxDBPath + SD_DB_FILE);
		}

		if(m_objFileDBMap.GetFirst() != NULL)
		{
			ScanUsingDBByValueType(cDriveToScan, m_objFileDBMap, false);
		}
		else
		{
			SetFullLiveUpdateReg(csMaxDBPath + SD_DB_FILE);
		}
	}
	CString csPercentage;
	//csPercentage.Format(L"%d", 12);
	csPercentage.Format(L"%d", 2);
	SendScanStatusToUI(Status_Bar_File_Report, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0);
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::ScanUsingDBByValueType
In Parameters  : TCHAR cDriveToScan, CU2OU2O &objDBMap, bool bReportFolder,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::ScanUsingDBByValueType(TCHAR cDriveToScan, CU2OU2O &objDBMap, bool bReportFolder)
{
	TCHAR strCurrDir[MAX_PATH] = {0};
	_wgetcwd(strCurrDir, MAX_PATH);

	LPVOID posProfType = objDBMap.GetFirst();
	while((!m_bStopScanning) && (posProfType))
	{
		ULONG lProfType = 0;
		objDBMap.GetKey(posProfType, lProfType);
		CU2OS2U oValueType(true);
		objDBMap.GetData(posProfType, oValueType);
		if(lProfType == 0)
		{
			ScanNonProfilePath(oValueType, bReportFolder, cDriveToScan);
		}
		else
		{
			ScanProfilePath(oValueType, bReportFolder, cDriveToScan);
		}
		posProfType = objDBMap.GetNext(posProfType);
	}
	_wchdir(strCurrDir);
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::ScanUsingFilesList
In Parameters  : TCHAR cDriveToScan, CU2OU2O &objDBMap, bool bReportFolder, const CS2U& objFilesList
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::ScanUsingFilesList(TCHAR cDriveToScan, CU2OU2O &objDBMap, bool bReportFolder,
										 CS2U& objFilesList)
{
	int iSlash = 0;
	CString csValue;
	DWORD dwSpyID = 0;
	LPTSTR szValue = 0;
	LPVOID lpContext = 0;
	CS2U objValueDatabase(true);
	CU2OS2U objValueTypeDatabase(true);
	CString csValuePath, csCurrentUser = m_oDBPathExpander.GetCurrentUserPath();

	lpContext = objFilesList.GetFirst();
	while(lpContext)
	{
		if(m_bStopScanning)
		{
			break;
		}

		objFilesList.GetKey(lpContext, szValue);

		//remove filename from full filepath
		csValue = szValue;
		csValue.MakeLower();
		iSlash = csValue.ReverseFind(_T('\\'));
		if(-1 != iSlash)
		{
			csValue.SetAt(iSlash, 0);
		}

		m_oDBPathExpander.SplitPathByValueType(csValue);
		if(m_objFolderDBMap.SearchItem(m_oDBPathExpander.m_lProfileType, objValueTypeDatabase))
		{
			if(objValueTypeDatabase.SearchItem(m_oDBPathExpander.m_lValueTypeID, objValueDatabase))
			{
				if(objValueDatabase.SearchItem(m_oDBPathExpander.m_csValue, &dwSpyID))
				{
					csValuePath = m_oDBPathExpander.ExpandPath(m_oDBPathExpander.m_csValueTAG, csCurrentUser);
					ScanFolder(objValueDatabase, csValuePath, true);
				}
			}
		}

		lpContext = objFilesList.GetNext(lpContext);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::ScanNonProfilePath
In Parameters  : CU2OS2U &oValueType, bool bReportFolder, TCHAR cDriveToScan,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::ScanNonProfilePath(CU2OS2U &oValueType, bool bReportFolder, TCHAR cDriveToScan)
{
	LPVOID posValueType = oValueType.GetFirst();
	while((!m_bStopScanning) && (posValueType))
	{
		ULONG lValueTypeID = 0;
		oValueType.GetKey(posValueType, lValueTypeID);
		CS2U oValueNSpyID(true);
		oValueType.GetData(posValueType, oValueNSpyID);
		LPTSTR strValuePath = NULL;
		if(m_objFileValueType.SearchItem(lValueTypeID, &strValuePath))
		{
			if(wcslen(strValuePath) > 0)
			{
				strValuePath[0] = cDriveToScan;
				ScanFolder(oValueNSpyID, strValuePath, bReportFolder);
#ifdef WIN64
				if(lValueTypeID == 528)
				{
					CString csx64Path = strValuePath;
					csx64Path = csx64Path.Left(csx64Path.GetLength() -1);
					csx64Path += L" (x86)\\";
					ScanFolder(oValueNSpyID, csx64Path, bReportFolder);
				}
				else if(lValueTypeID == 531)
				{
					CString csx64Path = strValuePath;
					csx64Path.Replace(L"\\system32\\", L"\\syswow64\\");
					ScanFolder(oValueNSpyID, csx64Path, bReportFolder);
				}
#endif
			}
		}
		posValueType = oValueType.GetNext(posValueType);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::ScanProfilePath
In Parameters  : CU2OS2U &oValueType, bool bReportFolder, TCHAR cDriveToScan,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::ScanProfilePath(CU2OS2U &oValueType, bool bReportFolder, TCHAR cDriveToScan)
{
	LPVOID posValueType = oValueType.GetFirst();
	while((!m_bStopScanning) && (posValueType))
	{
		ULONG lValueTypeID = 0;
		oValueType.GetKey(posValueType, lValueTypeID);
		CS2U oValueNSpyID(true);
		oValueType.GetData(posValueType, oValueNSpyID);
		LPVOID posUserName = m_objAvailableUsers.GetFirst();
		while((!m_bStopScanning) && (posUserName))
		{
			LPTSTR strValuePath = NULL;
			if(m_objFileValueType.SearchItem(lValueTypeID, &strValuePath))
			{
				CString csValuePath(strValuePath);
				LPTSTR strUserName = NULL;
				m_objAvailableUsers.GetData(posUserName, strUserName);
				if(csValuePath.GetLength() > 0)
				{
					csValuePath.Replace(L"<user>", strUserName);
					csValuePath.SetAt(0, cDriveToScan);
					ScanFolder(oValueNSpyID, csValuePath, bReportFolder);
					if(m_oDBPathExpander.RunningOnVista())
					{
						ULONG lValueTypeID2 = GetOtherValueTypeID(lValueTypeID);
						if(lValueTypeID2 != 0)
						{
							strValuePath = NULL;
							if(m_objFileValueType.SearchItem(lValueTypeID2, &strValuePath))
							{
								CString csValuePath(strValuePath);
								strUserName = NULL;
								m_objAvailableUsers.GetData(posUserName, strUserName);
								csValuePath.Replace(L"<user>", strUserName);
								csValuePath.SetAt(0, cDriveToScan);
								ScanFolder(oValueNSpyID, csValuePath, bReportFolder);
							}
						}
					}
				}
			}
			posUserName = m_objAvailableUsers.GetNext(posUserName);
		}
		posValueType = oValueType.GetNext(posValueType);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::ScanFolder
In Parameters  : CS2U &oValueNSpyID, LPCTSTR strValuePath, bool bReportFolder,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::ScanFolder(CS2U &oValueNSpyID, LPCTSTR strValuePath, bool bReportFolder)
{
	if(_wchdir(strValuePath)== 0)
	{
		LPVOID posValueNSpyID = oValueNSpyID.GetFirst();
		while((!m_bStopScanning) && (posValueNSpyID))
		{
			LPTSTR strValue = NULL;
			oValueNSpyID.GetKey(posValueNSpyID, strValue);
			TCHAR strTemp[MAX_PATH] = {0};
				swprintf_s(strTemp, MAX_PATH, L"%s", strValue);
			if(bReportFolder)
			{
				HANDLE hFindFile;
				CString s_actualPath,s_sd1Path;
				WIN32_FIND_DATA info;
				TCHAR strTemp[MAX_PATH] = {0};
				ULONG lSpyNameID = 0;
				CString szFilePath;
				swprintf_s(strTemp, MAX_PATH, L"%s%s", strValuePath, strValue);
				int pos = 0;
				s_actualPath.Format(_T("%s"),strValuePath);
				s_sd1Path.Format(_T("%s"),strValue);
				s_sd1Path.MakeLower();
		

				if(s_sd1Path.Find(_T("mozilla")) != -1 && s_sd1Path.Find(_T("firefox")) != -1 && s_sd1Path.Find(_T("profiles")) != -1 && s_sd1Path.Find(_T(".default")) != -1)
				{
					for(int i=0;i<m_csFireFoxPath.GetCount();i++)
					{
						bool bFirefoxBug= CheckFirefoxBug(s_sd1Path,m_csFireFoxPath.GetAt(i), szFilePath);
						if(bFirefoxBug)
						{
							oValueNSpyID.GetData(posValueNSpyID, lSpyNameID);
							SendScanStatusToUI(Folder, lSpyNameID, szFilePath, 0);
						}
					}
					
				}
				
				if(s_sd1Path.Find(_T("google"))!=-1 && s_sd1Path.Find(_T("chrome")) != -1  && s_sd1Path.Find(_T("user data")) != -1 && s_sd1Path.Find(_T("default")) != -1 && s_sd1Path.Find(_T("extensions")) != -1)
				{
					CString outChromeBug;
					for(int i=0;i<m_csChromePath.GetCount();i++)
					{
						CString czTempFileName;
						czTempFileName=m_csChromePath.GetAt(i);
						int iPos=czTempFileName.ReverseFind('\\');
						czTempFileName=czTempFileName.Mid(iPos);
						if(s_sd1Path.Find(czTempFileName)!=-1)
						{
							bool bChromeBug=CheckChromeBug(m_csChromePath.GetAt(i),outChromeBug);
							if(bChromeBug)
							{
								oValueNSpyID.GetData(posValueNSpyID, lSpyNameID);
								SendScanStatusToUI(Folder, lSpyNameID, outChromeBug, 0);
							}
						}
					}

				}

			
				hFindFile = FindFirstFile(strTemp, &info);
				if(INVALID_HANDLE_VALUE != hFindFile)
				{
					BOOL bWorking = PathIsDirectoryEmpty(strTemp);
					if(bWorking)
					{
						oValueNSpyID.GetData(posValueNSpyID, lSpyNameID);
						SendScanStatusToUI(Folder, lSpyNameID, strTemp, 0);
						//RemoveDirectory(strTemp);
					}
				}
			}
			if((strValue) && (_waccess((LPCTSTR)strValue, 0)) != -1)
			{
				ULONG lSpyNameID = 0;
				oValueNSpyID.GetData(posValueNSpyID, lSpyNameID);
				bool bItsAFolder = (_wchdir((LPCTSTR)strValue)== 0);
				if(bItsAFolder)
				{
					_wchdir(strValuePath);
				}

				if(bReportFolder && bItsAFolder) // Report as Folder
				{
					bool bMatchFound = false;
					DWORD dwFilesCount = 0;
					TCHAR strTemp[MAX_PATH] = {0};
					swprintf_s(strTemp, MAX_PATH, L"%s%s", strValuePath, strValue);

					EnumFolderNReportToUI(strTemp, lSpyNameID, bMatchFound, true, &dwFilesCount);
					if(bMatchFound)
					{
						SendScanStatusToUI(Folder, lSpyNameID, strTemp, 0);
						EnumFolderNReportToUI(strTemp, lSpyNameID, bMatchFound);
						_wchdir(strValuePath);
					}
				}
				else if(!bReportFolder && !bItsAFolder)// Report as File
				{
					TCHAR strTemp[MAX_PATH] = {0};
					swprintf_s(strTemp, MAX_PATH, L"%s%s", strValuePath, strValue);
					SendScanStatusToUI(File, lSpyNameID, strTemp, 0);
					_wchdir(strValuePath);
				}
			}
			posValueNSpyID = oValueNSpyID.GetNext(posValueNSpyID);
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::PerformQuickSignatureScan
In Parameters  : none
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 24 Jan, 2010.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::PerformQuickSignatureScan()
{
	m_bSendStatusToUI = true;
	m_csIgnoreFolder = CSystemInfo::m_strAppPath + QUARANTINEFOLDER;
	m_csIgnoreFolder.MakeLower();

	CWinThread *pCountThread = AfxBeginThread(TotalQuickScanningSizeThread, this, THREAD_PRIORITY_HIGHEST, NULL, CREATE_SUSPENDED, NULL);
	CWinThread *pStatusThread = AfxBeginThread(ScanningStatusThread, this, THREAD_PRIORITY_HIGHEST, NULL, CREATE_SUSPENDED, NULL);
	if(pCountThread)
	{
		pCountThread->m_bAutoDelete = FALSE;
		pCountThread->ResumeThread();
	}
	if(pStatusThread)
	{
		pStatusThread->m_bAutoDelete = FALSE;
		pStatusThread->ResumeThread();
	}
	
	TCHAR chDriveToScan[3] = {0};
	chDriveToScan[0] = m_oDBPathExpander.GetOSDriveLetter();
	chDriveToScan[1] = ':';

	m_pMaxScanner->m_oLocalSignature.LoadLocalDatabase(chDriveToScan, Scanner_Type_Max_SignatureScan);

	LPVOID posUserName = m_objAvailableUsers.GetFirst();
	while((!m_bStopScanning) && (posUserName))
	{
		CString csPathToScan;
		LPTSTR strUserName = NULL;
		m_objAvailableUsers.GetData(posUserName, strUserName);

		csPathToScan = m_oDBPathExpander.m_cs512;			//Desktop Recursive Scan
		csPathToScan.Replace(L"<user>", strUserName);
		EnumFolder(csPathToScan, false, true);

		csPathToScan = m_oDBPathExpander.m_cs503;			//AppData Main Folder Scan
		csPathToScan.Replace(L"<user>", strUserName);
		EnumFolder(csPathToScan, false, false);

		csPathToScan = m_oDBPathExpander.m_cs509;			//Common AppData Main Folder Scan
		csPathToScan.Replace(L"<user>", strUserName);
		EnumFolder(csPathToScan, false, false);
		posUserName = m_objAvailableUsers.GetNext(posUserName);
	}

	if(!m_bStopScanning)
	{
		EnumFolder(m_oDBPathExpander.m_cs543, false, false);	// Root Drive
		EnumFolder(m_oDBPathExpander.m_cs542, false, false);	// Windows
		EnumFolder(m_oDBPathExpander.m_cs531, false, false);	// System32
		EnumFolder(m_oDBPathExpander.m_cs529, false, false);	// Drivers
		EnumFolder(m_oDBPathExpander.m_cs528, false, false);	// Program Files
	}

	m_pMaxScanner->m_oLocalSignature.UnLoadLocalDatabase();

	m_bSendStatusToUI = false;
	if(pCountThread)
	{
		WaitForSingleObject(pCountThread->m_hThread, INFINITE);
		delete pCountThread;
		pCountThread = NULL;
	}
	if(pStatusThread)
	{
		WaitForSingleObject(pStatusThread->m_hThread, INFINITE);
		delete pStatusThread;
		pStatusThread = NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::ScanSystemWithSignature
In Parameters  : const TCHAR *strDriveToScan,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::ScanSystemWithSignature(const TCHAR *strDriveToScan)
{
	__try
	{
		m_pMaxScanner->m_oLocalSignature.LoadLocalDatabase(strDriveToScan, Scanner_Type_Max_SignatureScan);
		EnumFolder(strDriveToScan, false);
		
		m_pMaxScanner->m_oLocalSignature.UnLoadLocalDatabase();
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught CFileSystemBase::ScanSystemWithSignature")))
	{
	}
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::EnumFolder
In Parameters  : const TCHAR *cFolderPath, bool bCheckCookies,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::EnumFolder(const TCHAR *cFolderPath, bool bCheckCookies, bool bEnumSubFolders, DWORD *pdwTotalNoOfFilesToScan, bool bSkipFolder)
{
	if(cFolderPath[0]==L'\\')
	{
		ConfigForNetworkScan(cFolderPath);
	}
	//AddLogEntry(L"#### Main Folder: %s", cFolderPath);
	bool bFile = false;
	bool bSkipFile = bSkipFolder? false : true;
	CString csSkipFolder;
	csSkipFolder.Format(L"%d", bSkipFolder);
	HANDLE hFindFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA FindFileData = {0};
	TCHAR *cFullPath = NULL;
	m_bIsUSBFolder = false;
	CString csFullPath(cFolderPath);


	if(theApp.m_pMaxScanner)
	{
		if(theApp.m_pMaxScanner->IsExcluded(0, 0, cFolderPath))
		{
			AddLogEntry(L"Exl folder: %s", cFolderPath);
			return;
		}
	}

	cFullPath = new TCHAR[MAX_PATH];
	if(!cFullPath)
	{
		return;
	}

	if(!JoinStrings(cFullPath, MAX_PATH, _T("%s"), cFolderPath, NULL))
	{
		AddLogEntry(L"Skipping long folder: %s", cFolderPath);
		delete [] cFullPath;
		return;
	}

	if(cFullPath[wcslen(cFullPath) - 1] == '\\') // remove \\ 
	{
		cFullPath[wcslen(cFullPath) - 1] = 0;
	}

	TCHAR szDummy[1024] = {0x00};
	_tcscpy(szDummy, cFolderPath);
	szDummy[3] = '\0';
	_tcsupr(szDummy);
	bool bSkipUnhideUsb = false;
	csFullPath.MakeUpper();
	if(csFullPath.Find(L"\\SYSTEM VOLUME INFORMATION") == 2 || csFullPath.Find(L"\\RECYCLER") == 2)
	{
		//AddLogEntry(L"recycler path : %s", csFullPath,0,true,LOG_DEBUG);
		bSkipUnhideUsb = true;
	}
	if (m_csNonRemovableDrives.Find(szDummy) == -1)
	{
		if (m_csUSBDrives.Find(szDummy) == -1)
		{
			
			if(GetDriveType(szDummy) == DRIVE_REMOVABLE)
			{
				
				m_csUSBDrives = m_csUSBDrives + szDummy;
				m_csUSBDrives = m_csUSBDrives + L"|";
				m_bIsUSBFolder = true;
			}
			else
			{
				m_csNonRemovableDrives = m_csNonRemovableDrives + szDummy;
				m_csNonRemovableDrives = m_csNonRemovableDrives + L"|";
				m_bIsUSBFolder = false;
			}
		}
		else
		{
			
			m_bIsUSBFolder = true;
		}
	}
	if(m_bIsUSBFolder == true)
	{
		DWORD		dwAttributes = 0x00;
	
		try
		{
			if(bSkipUnhideUsb == false)
			{
				dwAttributes = GetFileAttributes(cFolderPath);
				if (_tcslen(cFolderPath) > 0x03)
				{
					if((dwAttributes & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN)
					{
						AddLogEntry(L"unhide following path 1: %s", cFolderPath,0,true,LOG_DEBUG);
						dwAttributes ^= FILE_ATTRIBUTE_HIDDEN;
						if((dwAttributes & FILE_ATTRIBUTE_SYSTEM) == FILE_ATTRIBUTE_SYSTEM)
						{
							dwAttributes ^= FILE_ATTRIBUTE_SYSTEM;
						}
						bool m_bSetFileAttributes = SetFileAttributes(cFolderPath, dwAttributes);
					}
				}
			}
		}
		catch(...)
		{
			AddLogEntry(L"Files To Remove HIDDEN Attribes : %s", cFolderPath,0,true,LOG_DEBUG);
		}
	}
	hFindFile = FindFirstFile(cFullPath, &FindFileData);
	CString csFirstFile(FindFileData.cFileName);
	if(INVALID_HANDLE_VALUE != hFindFile)
	{
		if((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)!= FILE_ATTRIBUTE_DIRECTORY)
		{
			bFile = true;
		}

		FindClose(hFindFile);
	}

	if(bFile == false)
	{
		if(!pdwTotalNoOfFilesToScan && m_pMaxScanner->m_bADSScan)
		{
			MAX_SCANNER_INFO oScannerInfo = {0};
			oScannerInfo.eScannerType = Scanner_Type_Max_SignatureScan;
			_tcscpy_s(oScannerInfo.szFileToScan, cFullPath);
			m_pMaxScanner->ScanAlternateDataStream(&oScannerInfo);
			if((oScannerInfo.ThreatDetected == 1) || (oScannerInfo.ThreatSuspicious == 1))
			{
				SendScanStatusToUI(&oScannerInfo);
			}
		}
		if(!AppendString(cFullPath, MAX_PATH, L"\\*.*"))
		{
			delete [] cFullPath;
			return;
		}
	}

	hFindFile = FindFirstFile(cFullPath, &FindFileData);
	if(INVALID_HANDLE_VALUE != hFindFile)
	{
		do
		{
			if((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)== FILE_ATTRIBUTE_REPARSE_POINT)
			{
				continue;
			}

			if(bFile == false)
			{
				if(!JoinStrings(cFullPath, MAX_PATH, _T("%s%s"), cFolderPath, FindFileData.cFileName, NULL))
				{
					AddLogEntry(L"Skipping long file: %s", FindFileData.cFileName);
					AddLogEntry(L"In this folder: %s", cFolderPath);
					continue;
				}
			}

			_wcslwr_s(cFullPath, MAX_PATH);
			if((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)== FILE_ATTRIBUTE_DIRECTORY && !bSkipFolder)
			{
				bool bScanFolder = false;
				if(theApp.m_bBGScanner && m_bLastScanInfoFound == TRUE)
				{
					CString csTempFolderPath(FindFileData.cFileName);
					csTempFolderPath.MakeLower();
					TCHAR		szNewPath[1024] = {0};
					_stprintf(szNewPath,_T("%s"),csTempFolderPath);
					if (_tcsstr(m_szFilePath,szNewPath) != NULL)
					{
						bScanFolder = true;
					}
				}
				else
				{
					bScanFolder = true;
				}
				if(bEnumSubFolders && bScanFolder)
				{
					if(wcscmp(FindFileData.cFileName, L"") == 0)
					{
						AddLogEntry (L"Blank Folder For Scanning So Break");
						break;
					}

					if((wcscmp(FindFileData.cFileName, L".") != 0) && (wcscmp(FindFileData.cFileName, L"..") != 0) &&
					   (_wcsicmp(FindFileData.cFileName, L"System Volume Information") != 0))
					{
						if(AppendString(cFullPath, MAX_PATH, L"\\"))
						{
							bool bIgnoreFolder = false;
							if(!pdwTotalNoOfFilesToScan)
							{
								WaitForSingleObject(m_bStatusVariableLock, INFINITE);
								m_csCurrentFileName = cFullPath;
								m_csCurrentFileName.MakeLower();
								if(m_csCurrentFileName.Left(m_csIgnoreFolder.GetLength()) == m_csIgnoreFolder)
									bIgnoreFolder = true;
								SetEvent(m_bStatusVariableLock);
							}
							if(bIgnoreFolder)
							{
								//AddLogEntry(L"Ignored Folder from scan: %s, %s", m_csCurrentFileName, m_csIgnoreFolder);
							}
							else
							{
								if(m_bUSBScan)
								{
									TCHAR *ptr = NULL;
									ptr = _tcsstr(cFullPath, L"autorun.inf");
									if(ptr == NULL)
									{
										if(bSkipUnhideUsb == false)
										{
											CString csTempPath(FindFileData.cFileName);
											csTempPath.MakeUpper();
											if(csTempPath.Find(L"SYSTEM VOLUME INFORMATION") != -1 || csTempPath.Find(L"RECYCLER") != -1)
											{
												//AddLogEntry(L"recycler folderpath : %s", csTempPath,0,true,LOG_DEBUG);
												//bSkipUnhideUsb = true;
											}
											else
											{
												//AddLogEntry(L"recycler folderpath else : %s", csTempPath,0,true,LOG_DEBUG);
												DWORD dwAttributes = 0;
												dwAttributes = ::GetFileAttributes(cFullPath);
												if((dwAttributes & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN)
												{
													dwAttributes ^= FILE_ATTRIBUTE_HIDDEN;
													::SetFileAttributes(cFullPath, dwAttributes);
												}
											}
										}
									}
								}
								//AddLogEntry(L"$$$$$$ SUB Folder: %s", cFullPath);
								EnumFolder(cFullPath, bCheckCookies, bEnumSubFolders, pdwTotalNoOfFilesToScan, true);
							}
						}
					}
				}
			}
			else
			{
				CString csFile(FindFileData.cFileName);
				
				if(theApp.m_bSkipFolder)
				{
					theApp.m_bSkipFolder = false;
					return;
				}
				
				if(m_bIsUSBFolder == true)
				{
					
					DWORD		dwAttributes = 0x00;



					try
					{
						if(wcscmp(FindFileData.cFileName,L"Thumbs.db") != 0)
						{
							dwAttributes = GetFileAttributes(cFullPath);
							if(bSkipUnhideUsb == false)
							{
								if (_tcslen(cFolderPath) > 0x03)
								{
									if((dwAttributes & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN)
									{
										AddLogEntry(L"unhide following path 2: %s", cFolderPath,0,true,LOG_DEBUG);
										dwAttributes ^= FILE_ATTRIBUTE_HIDDEN;
										if((dwAttributes & FILE_ATTRIBUTE_SYSTEM) == FILE_ATTRIBUTE_SYSTEM)
										{
											dwAttributes ^= FILE_ATTRIBUTE_SYSTEM;
										}
										SetFileAttributes(cFullPath, dwAttributes);
									}
								}
							}
						}
					}
					catch(...)
					{
						AddLogEntry(L"Files To Remove HIDDEN Attribes : %s", cFullPath,0,true,LOG_DEBUG);
					}
					
				}

				if(bCheckCookies)
				{
					CheckCookie(FindFileData.cFileName, cFullPath);
				}
				else if(!bSkipFile)
				{
					ULONGLONG ulFileSize = (FindFileData.nFileSizeHigh * (((ULONGLONG)MAXDWORD) +1)) + FindFileData.nFileSizeLow;
					if(ulFileSize != 0)
					{
						if(pdwTotalNoOfFilesToScan)
						{
							int iExecutableType = IsValidExtension(FindFileData.cFileName);
							if((m_bDeepScan) || ((iExecutableType != -1) && (iExecutableType >= 0)))
							{
								(*pdwTotalNoOfFilesToScan)++;
							}
						}
						else
						{
							WaitForSingleObject(m_bStatusVariableLock, INFINITE);
							m_csCurrentFileName = cFullPath;
							m_csCurrentFileName.MakeLower();
							SetEvent(m_bStatusVariableLock);
							int iExecutableType = IsValidExtension(FindFileData.cFileName);
							if((m_bDeepScan) || ((iExecutableType != -1) && (iExecutableType >= 0)))
							{
								MAX_SCANNER_INFO oScannerInfo = {0};
								oScannerInfo.eMessageInfo = File;
								oScannerInfo.eScannerType = Scanner_Type_Max_SignatureScan;
								if(JoinStrings(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), L"%s", cFullPath, NULL))
								{
									//AddLogEntry(L"******** File For Scan: %s", cFullPath);
									////// add scanner check here......
									bool bSkipScan = false;
									if(theApp.m_bBGScanner)
									{
										if (m_bLastScanInfoFound == TRUE)
										{
											if (_tcsstr(m_szFilePath,oScannerInfo.szFileToScan) != NULL)
											{
												m_bLastScanInfoFound = FALSE;
												SaveCurStage(cFullPath);
											}
											else
											{
												bSkipScan = true;
											}
										}
									}
									if(!bSkipScan)
									{
										m_pMaxScanner->ScanFile(&oScannerInfo);
										if(theApp.m_bBGScanner)
										{
											SaveCurStage(oScannerInfo.szFileToScan);
										}
									}
								}
								else
								{
									AddLogEntry(L"Skipped file from scan: %s", cFullPath);
								}

								m_ulFileCount++;
								if((oScannerInfo.ThreatDetected == 1) || (oScannerInfo.ThreatSuspicious == 1))
								{
									SendScanStatusToUI(&oScannerInfo);
								}
							}
						}
					}
				}
			}
		}while((!m_bStopScanning) && (FindNextFile(hFindFile, &FindFileData)));
		FindClose(hFindFile);
	}

	delete [] cFullPath;
	if(bSkipFolder)
	{
		EnumFolder(cFolderPath, bCheckCookies, bEnumSubFolders, pdwTotalNoOfFilesToScan, false);
	}

	return;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::GetLastScanStatus
In Parameters  : TCHAR *
Out Parameters : BOOL
Description    :
Author & Date  : Ravi
--------------------------------------------------------------------------------------*/
BOOL CFileSystemBase::GetLastScanStatus(TCHAR *szDrive)
{
	BOOL	bRetValue = FALSE;
	m_bLastScanInfoFound = FALSE;
	TCHAR	szLastScanedFile[1024] = {0x00};
	GetIniPathScanStatus();
	bRetValue = GetLastStage(szLastScanedFile);
	if (_tcslen(szLastScanedFile) <= 0x03)
	{
		return bRetValue;
	}

	m_szDrive[0x00] = szLastScanedFile[0x00];
	m_szDrive[0x01] = szLastScanedFile[0x01];
	m_szDrive[0x02] = szLastScanedFile[0x02];
	m_szDrive[0x03] = '\0';
	if(szDrive != NULL)
	{
		_tcscpy(szDrive,m_szDrive);
	}

	_tcscpy(m_szFilePath,szLastScanedFile);

	if (PathFileExists(m_szFilePath) == FALSE)
	{
		m_bLastScanInfoFound = FALSE;
	}
	else
	{
		m_bLastScanInfoFound = TRUE;
	}
	bRetValue = TRUE;

	return bRetValue;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::GetLastStage
In Parameters  : LPTSTR
Out Parameters : BOOL
Description    :
Author & Date  : Tushar
--------------------------------------------------------------------------------------*/
BOOL CFileSystemBase::GetLastStage(LPTSTR pszFileScan)
{
	BOOL	bRetValue = FALSE;

	_tcscpy(&m_szDrive[0x00],L"");
	_tcscpy(&m_szFilePath[0x00],L"");
	m_bLastScanInfoFound = FALSE;

	if (pszFileScan == NULL)
	{
		return bRetValue;
	}

	//bRetValue = GetProfileString(L"MAX_SCAN_STATUS",L"CURRENTFILE",L"",pszFileScan,1024);
	int iStatus = 0;
	iStatus = GetPrivateProfileIntW(L"MAX_SCAN_STATUS", L"SCAN_STATUS",0, m_csScanStatusIni);
	if(iStatus == 0)
	{
		return bRetValue;
	}
	GetPrivateProfileStringW(L"MAX_SCAN_STATUS", L"CURRENTFILE", _T(""), pszFileScan, MAX_PATH, m_csScanStatusIni);
	bRetValue = TRUE;
	return bRetValue;
}
/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::SaveCurStage
In Parameters  : LPTSTR, int
Out Parameters : BOOL
Description    :
Author & Date  : Ravi
--------------------------------------------------------------------------------------*/
BOOL CFileSystemBase::SaveCurStage(LPCTSTR pszFileScan, int iStatus)
{
	BOOL	bRetValue = FALSE;

	if (pszFileScan == NULL)
	{
		return bRetValue;
	}

	//bRetValue = WriteProfileStringW(L"MAX_SCAN_STATUS",L"CURRENTFILE",pszFileScan);
	if(iStatus == 0)
	{
		WritePrivateProfileStringW(L"MAX_SCAN_STATUS", L"SCAN_STATUS", L"0", m_csScanStatusIni);
	}
	else
	{
		WritePrivateProfileStringW(L"MAX_SCAN_STATUS", L"SCAN_STATUS", L"1", m_csScanStatusIni);
	}
	WritePrivateProfileStringW(L"MAX_SCAN_STATUS", L"CURRENTFILE", pszFileScan, m_csScanStatusIni);
	bRetValue = TRUE;
	return bRetValue;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::SaveCurStage
In Parameters  : CString
Out Parameters : BOOL
Description    :
Author & Date  : Ravi
--------------------------------------------------------------------------------------*/
BOOL CFileSystemBase::GetIniPathScanStatus()
{
	BOOL	bRetValue = FALSE;
	CRegistry objRegistry;
	objRegistry.Get(CSystemInfo::m_csProductRegKey,_T("AppFolder"),m_csScanStatusIni,HKEY_LOCAL_MACHINE);
	if(!m_csScanStatusIni.IsEmpty())
	{
		m_csScanStatusIni.Format(_T("%sSetting\\ScanStatusLastScan.ini"),m_csScanStatusIni);
		bRetValue = TRUE;
	}
	return bRetValue;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::CheckCookie
In Parameters  : const TCHAR *cFileName, TCHAR *cFullPath,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CFileSystemBase::CheckCookie(const TCHAR *cFileName, TCHAR *cFullPath)
{
	__try
	{
		if(_tcscmp(cFileName, L"index.dat"))
		{
			if(ScanCookieContent(cFileName, cFullPath))
			{
				return true;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::EnumFolderNReportToUI
In Parameters  : const TCHAR *cFolderPath, const ULONG lSpyNameID, bool& bMatchFound,
bool bCheckScanList, LPDWORD lpdwFilesCount
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::EnumFolderNReportToUI(const TCHAR *cFolderPath, const ULONG lSpyNameID,
											bool& bMatchFound, bool bCheckScanList,
											LPDWORD lpdwFilesCount)
{
	HANDLE hFindFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA FindFileData = {0};
	DWORD dwTemp = 0;
	LPTSTR szHoldPath = 0;

	if(bCheckScanList)
	{
		bMatchFound = IsFolderPathInScannedList(cFolderPath);
		return;
	}

	szHoldPath = new TCHAR[MAX_PATH*2];
	if(!szHoldPath)
	{
		return;
	}

	_tcscpy_s(szHoldPath, MAX_PATH*2, cFolderPath);
	_tcscat_s(szHoldPath, MAX_PATH*2, L"\\*.*");

	hFindFile = FindFirstFile(szHoldPath, &FindFileData);
	if(INVALID_HANDLE_VALUE != hFindFile)
	{
		do
		{
			if((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)== FILE_ATTRIBUTE_REPARSE_POINT)
			{
				continue;
			}

			_tcscpy_s(szHoldPath, MAX_PATH*2, cFolderPath);
			_tcscat_s(szHoldPath, MAX_PATH*2, L"\\");
			_tcscat_s(szHoldPath, MAX_PATH*2, FindFileData.cFileName);

			if((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)== FILE_ATTRIBUTE_DIRECTORY)
			{
				if((wcscmp(FindFileData.cFileName, L".") != 0) && (wcscmp(FindFileData.cFileName, L"..") != 0))
				{
					if(!bCheckScanList)
					{
						SendScanStatusToUI(Folder, lSpyNameID, szHoldPath, 0);
					}

					EnumFolderNReportToUI(szHoldPath, lSpyNameID, bMatchFound, bCheckScanList, lpdwFilesCount);
				}
			}
			else
			{
				if(lpdwFilesCount)
				{
					(*lpdwFilesCount)++;
				}

				if(bCheckScanList)
				{
					_tcslwr_s(szHoldPath, MAX_PATH*2);
					if(m_pobjFilesList)
					{
						bMatchFound = m_pobjFilesList->SearchItem(szHoldPath,&dwTemp)?true:bMatchFound;
					}
				}
				else
				{
					SendScanStatusToUI(File, lSpyNameID, szHoldPath, 0);
				}
			}

			if(bCheckScanList && bMatchFound)
			{
				break;
			}

		}while((!m_bStopScanning) && (FindNextFile(hFindFile, &FindFileData)));
		FindClose(hFindFile);
	}

	delete []szHoldPath;
	return;
}

bool CFileSystemBase::IsFolderPathInScannedList(LPCTSTR szFolderPath)
{
	bool bFound = false;
	int iFolderPathLen = 0;
	LPVOID lpContext = NULL;
	LPTSTR szFileName = NULL;

	if(!m_pobjFilesList)
	{
		return bFound;
	}

	iFolderPathLen = (int)_tcslen(szFolderPath);
	lpContext = m_pobjFilesList->GetFirst();
	while(lpContext && !bFound)
	{
		m_pobjFilesList->GetKey(lpContext, szFileName);
		bFound = szFileName && !_tcsnicmp(szFileName, szFolderPath, iFolderPathLen);
		lpContext = m_pobjFilesList->GetNext(lpContext);
	}

	return bFound;
}

UINT _cdecl TotalQuickScanningSizeThread(LPVOID pParam)
{
	CFileSystemBase* pFileSystemBase = (CFileSystemBase*)pParam;
	pFileSystemBase->GetTotalScanningSize();
	return 0;
}

UINT _cdecl ScanningStatusThread(LPVOID pParam)
{
	CFileSystemBase* pFileSystemBase = (CFileSystemBase*)pParam;
	pFileSystemBase->ShowScanningStatus();
	return 0;
}


void CFileSystemBase::GetTotalScanningSize()
{
	m_dwTotalNoOfFilesToScan = 0;

	LPVOID posUserName = m_objAvailableUsers.GetFirst();
	CString csTemp;
	while((!m_bStopScanning) && (posUserName))
	{
		CString csPathToScan;
		LPTSTR strUserName = NULL;
		m_objAvailableUsers.GetData(posUserName, strUserName);

		csPathToScan = m_oDBPathExpander.m_cs512;			//Desktop Recursive Scan
		csPathToScan.Replace(L"<user>", strUserName);
		EnumFolder(csPathToScan, false, true, &m_dwTotalNoOfFilesToScan);

		csPathToScan = m_oDBPathExpander.m_cs503;			//AppData Main Folder Scan
		csPathToScan.Replace(L"<user>", strUserName);
		EnumFolder(csPathToScan, false, false, &m_dwTotalNoOfFilesToScan);

		csPathToScan = m_oDBPathExpander.m_cs509;			//Common AppData Main Folder Scan
		csPathToScan.Replace(L"<user>", strUserName);
		EnumFolder(csPathToScan, false, false, &m_dwTotalNoOfFilesToScan);

		posUserName = m_objAvailableUsers.GetNext(posUserName);
	}

	if(!m_bStopScanning)
	{
		EnumFolder(m_oDBPathExpander.m_cs543, false, false, &m_dwTotalNoOfFilesToScan);	// Root Drive
		EnumFolder(m_oDBPathExpander.m_cs542, false, false, &m_dwTotalNoOfFilesToScan);	// Windows
		EnumFolder(m_oDBPathExpander.m_cs531, false, false, &m_dwTotalNoOfFilesToScan);	// System32
		EnumFolder(m_oDBPathExpander.m_cs529, false, false, &m_dwTotalNoOfFilesToScan);	// Drivers
		EnumFolder(m_oDBPathExpander.m_cs528, false, false, &m_dwTotalNoOfFilesToScan);	// Program Files
		if(theApp.IsAutoCleanActive())
		{
			EnumFolder(m_oDBPathExpander.m_cs543 + L"system volume information\\", false, false, &m_dwTotalNoOfFilesToScan);	// System Volume Information
		}
	}

	m_bActualValueReady = true;

	csTemp.Format(L"Actual Total No of Files To Scan: %d", m_dwTotalNoOfFilesToScan);
	AddLogEntry(csTemp);
}

void CFileSystemBase::ShowScanningStatus()
{
	CString csPercentage, csFileName, csTemp;

	/*if(m_bCustomScan)
		AddLogEntry(L"Start Custom Scan!");
	else
		AddLogEntry(L"Start Quick/Full Scan!");*/

	m_dwStartTickCount = GetTickCount();
	double dPercentage = GetCurrentPercentage(eMsg_StartScanning);

	csPercentage.Format(L"%d", (int)dPercentage);
	//csTemp.Format(L"Start Scanning: No Of Files: %d, Current Count: %d, %lf%%, %s", m_dwTotalNoOfFilesToScan, m_ulFileCount, dPercentage, csPercentage);
	//AddLogEntry(csTemp);

	bool bActualCountSent = false;
	while(m_bSendStatusToUI && !m_bStopScanning)
	{
		if(m_bActualValueReady && !bActualCountSent)
		{
			dPercentage = GetCurrentPercentage(eMsg_ActualCount);
			bActualCountSent = true;
			csPercentage.Format(L"%d", (int)dPercentage);
			//csTemp.Format(L"Actual Count: %d, Current Count: %d, %lf%%, %s", m_dwTotalNoOfFilesToScan, m_ulFileCount, dPercentage, csPercentage);
			//AddLogEntry(csTemp);
		}
		else
		{
			dPercentage = GetCurrentPercentage(eMsg_CurrentProgress);
			csPercentage.Format(L"%d", (int)dPercentage);
			//csTemp.Format(L"Current Status: %d, Current Count: %d, %lf%%, %s", m_dwTotalNoOfFilesToScan, m_ulFileCount, dPercentage, csPercentage);
			//AddLogEntry(csTemp);
		}

		WaitForSingleObject(m_bStatusVariableLock, INFINITE);
		csFileName = m_csCurrentFileName;
		SetEvent(m_bStatusVariableLock);
		SendScanStatusToUI(Status_Bar_File_Report, m_ulFileCount, 0, csFileName, csPercentage, 0, 0, 0, 0, 0, 0);
		Sleep(5);
	}

	// Once the loop has broken we must send the latest total file scanned count to the UI!
	if(!m_bStopScanning)
	{
		dPercentage = GetCurrentPercentage(eMsg_FinishedScanning);
	}
	csPercentage.Format(L"%d", (int)dPercentage);
	//csTemp.Format(L"Finished Scan: No Of Files: %d, Current Count: %d, %lf%%, %s", m_dwTotalNoOfFilesToScan, m_ulFileCount, dPercentage, csPercentage);
	//AddLogEntry(csTemp);

	WaitForSingleObject(m_bStatusVariableLock, INFINITE);
	csFileName = m_csCurrentFileName;
	SetEvent(m_bStatusVariableLock);
	SendScanStatusToUI(Status_Bar_File_Report, m_ulFileCount, 0, csFileName, csPercentage, 0, 0, 0, 0, 0, 0);
}

double CFileSystemBase::GetCurrentPercentage(ENUM_MESSAGEINFO eMessageInfo)
{
	switch(eMessageInfo)
	{
	case eMsg_ActualCount:
		{
			bDummyCount=false;
			dwActualFileCountPending = m_dwTotalNoOfFilesToScan - m_ulFileCount;
			ldwPrevious_Progress =ldwProgress_In_Percent;

			CTimeSpan ctTotalScanTime = ((GetTickCount() - m_dwStartTickCount)/1000);

			if(!bMedianCalculate)
			{
				BYTE byflag=0x01;
				while(byflag)
				{
					byflag=0x00;
					for(int i=1; i<=iCounter-0x01; i++)
					{
						if(Arr_CollectSamplingFiles[i-0x01] > Arr_CollectSamplingFiles[i])
						{
							Arr_CollectSamplingFiles[i-0x01]+=Arr_CollectSamplingFiles[i];
							Arr_CollectSamplingFiles[i]=Arr_CollectSamplingFiles[i-0x01]-Arr_CollectSamplingFiles[i];
							Arr_CollectSamplingFiles[i-0x01]-=Arr_CollectSamplingFiles[i];
							byflag=0x01;
						}
					}
				}
				int i=0;
				if(iCounter>0)
				{
					while(Arr_CollectSamplingFiles[i]==0)
					{i++;}
				}

				if(iCounter==0 && ctTotalScanTime.GetTimeSpan()>5)
				{
					Arr_CollectSamplingFiles[0]=200;
				}
				else if((iCounter-i)%2==1)
				{
					Arr_CollectSamplingFiles[0]=Arr_CollectSamplingFiles[i+(iCounter-i)/2];
				}
				else if(iCounter>0)
				{ 
					Arr_CollectSamplingFiles[0]=(Arr_CollectSamplingFiles[i+(iCounter-i)/2]+Arr_CollectSamplingFiles[i+((iCounter-i)/2)+1])/2;
				}
				bMedianCalculate=true;
			}

			if(Forty5MinuteIn==0)
			{
				if(Arr_CollectSamplingFiles[0]>0)
				{
					ldwTotalRemTime=dwActualFileCountPending*(1/(Arr_CollectSamplingFiles[0]));
				}
			}
			else
			{
				ldwTotalRemTime=dwActualFileCountPending*(1/(ldwOriginalSampleValue));
			}

			if(Arr_CollectSamplingFiles[0]==0 && ctTotalScanTime.GetTimeSpan()<5)
			{
				bArrSampleZero=true;
			}

			if(!bArrSampleZero)
			{
				ldwActualRemTime=ldwTotalRemTime;
			}

			/*
			CString csTemp;
			// do your calculation here
			// m_dwTotalNoOfFilesToScan would be the actual no of files on all drives
			csTemp.Format(L"%d", m_dwTotalNoOfFilesToScan);
			((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlNoOfFilesAvailable.SetWindowText(csTemp);

			csTemp.Format(L"%02d:%02d:%02d", (DWORD)ctTotalScanTime.GetHours(), (DWORD)ctTotalScanTime.GetMinutes(), (DWORD)ctTotalScanTime.GetSeconds());
			((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlReceivedActualCount.SetWindowText(csTemp);
			*/
		}
		break;
	case eMsg_StartScanning:
		{
			if(m_bCustomScan)
			{
				START_SCAN_PERCENT = 0;
				END_SCAN_PERCENT = 100;
			}
			else
			{
				DUMMY_MAX_SCAN_PERCENT = 20;
			}

			CString csTemp;
			// progress should be 0%
			// calculate with dummy count
			// m_dwTotalNoOfFilesToScan would be 80000
			dwActualFileCountPending = 0x0;
			bDummyCount = true;
			bInitialCount=false;
			bMedianCalculate = false;
			bArrSampleZero = false;
			ldwProgress_In_Percent = START_SCAN_PERCENT;
			ldwGetDiffTime=0;
			ldwPrevious_Progress = 0;
			dwPrevious_count = 0;
			dwActualFileCountInIncrements=0;
			ldwtemp=0;
			Forty5MinuteIn=0;
			TwentyMinuteIn=1;
			ldwTotalRemTime=0;
			ldwActualRemTime=0;
			dwPreviousTotalFileCount=0;
			ldwOriginalSampleValue=0;
			iCounter=0;
			memset(&Arr_CollectSamplingFiles,0,sizeof(Arr_CollectSamplingFiles));

			csTemp.Format(L"%d", START_SCAN_PERCENT);
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlProgressInPercentage.SetWindowText(csTemp);

			//csTemp.Format(L"%d", m_dwTotalNoOfFilesToScan);
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlNoOfFilesAvailable.SetWindowText(csTemp);

			//CTimeSpan ctTotalScanTime = ((GetTickCount() - ((CSample2008Dlg*)(theApp.m_pMainWnd))->m_dwStartTickCount)/1000);
			//csTemp.Format(L"%02d:%02d:%02d", (DWORD)ctTotalScanTime.GetHours(), (DWORD)ctTotalScanTime.GetMinutes(), (DWORD)ctTotalScanTime.GetSeconds());
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlElapsedTime.SetWindowText(csTemp);
		}
		break;
	case eMsg_FinishedScanning:
		{
			ldwProgress_In_Percent = END_SCAN_PERCENT;
			//CString csTemp;
			//// progress should be 100%
			//if(m_dwTotalNoOfFilesToScan>=5)
			//{
			//	if((m_ulFileCount <= m_dwTotalNoOfFilesToScan + 0x05) && (m_ulFileCount >= m_dwTotalNoOfFilesToScan - 0x05))
			//	{
			//		csTemp.Format(L"%d", END_SCAN_PERCENT);
			//		//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlProgressInPercentage.SetWindowText(csTemp);
			//		//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlProgressBar.SetPos(100);
			//	}
			//}
			//else if(m_dwTotalNoOfFilesToScan<5)
			//{
			//	csTemp.Format(L"%d", END_SCAN_PERCENT);
			//	//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlProgressInPercentage.SetWindowText(csTemp);
			//	//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlProgressBar.SetPos(100);
			//}

			//csTemp.Format(L"%d", m_ulFileCount);
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrl_NoOfFilesScanned.SetWindowText(csTemp);

			//CTimeSpan ctTotalScanTime = ((GetTickCount() - ((CSample2008Dlg*)(theApp.m_pMainWnd))->m_dwStartTickCount)/1000);
			//csTemp.Format(L"%02d:%02d:%02d", (DWORD)ctTotalScanTime.GetHours(), (DWORD)ctTotalScanTime.GetMinutes(), (DWORD)ctTotalScanTime.GetSeconds());
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlElapsedTime.SetWindowText(csTemp);

			//csTemp.Format(L"%02d:%02d:%02d", 0,0,0);
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlEstimatedFinishTime.SetWindowText(csTemp);

			//csTemp.Format(L"Finished Scanning: Total: %d, Scanned: %d, Detected: %d", m_dwTotalNoOfFilesToScan, m_ulFileCount, dwNoOfVirusFound);
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlStatusBar.SetWindowText(csTemp);

			//CTime ctFinishedTime = CTime::GetCurrentTime();
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlFinishedTime.SetWindowText(ctFinishedTime.Format(L"%H:%M:%S"));
		}
		break;
	case eMsg_CurrentProgress:
		{
			CString csTemp;
			// increment progressbar here using m_ulFileCount!

			if(bDummyCount && m_dwTotalNoOfFilesToScan!=0)
			{  
				CTimeSpan ctTotalScanTime =((GetTickCount() - m_dwStartTickCount)/1000);
				if(m_ulFileCount < m_dwTotalNoOfFilesToScan && m_dwTotalNoOfFilesToScan != 0x00)
				{					
					if((ctTotalScanTime.GetTimeSpan() >= 2 && ctTotalScanTime.GetTimeSpan() <= 60) )
					{
						if(m_dwTotalNoOfFilesToScan - m_ulFileCount >= 1000)
						{
							if(ldwProgress_In_Percent < (1 + START_SCAN_PERCENT) && ctTotalScanTime.GetTimeSpan()<16 && ctTotalScanTime.GetTimeSpan()/15==1)
							{
								ldwProgress_In_Percent+=1;
							}
							else if(m_dwTotalNoOfFilesToScan - m_ulFileCount>7000 && ldwProgress_In_Percent<(0.4+START_SCAN_PERCENT))
							{
								ldwProgress_In_Percent+=1;
							}					
							if(!bInitialCount)
							{
								DUMMY_MAX_SCAN_PERCENT = 30+START_SCAN_PERCENT;
								bInitialCount = true;
							}
						}
					}

					if(!bInitialCount && ctTotalScanTime.GetTimeSpan() > 20 && (ctTotalScanTime.GetTimeSpan()/20) >= (TwentyMinuteIn+1) && (m_dwTotalNoOfFilesToScan-m_ulFileCount)<500)
					{
						if(DUMMY_MAX_SCAN_PERCENT<=(END_SCAN_PERCENT-10))
						{
							DUMMY_MAX_SCAN_PERCENT+=10;
						}
					}

					TwentyMinuteIn=DWORD(ctTotalScanTime.GetTimeSpan()/20);

					ldwtemp=(((long double((DUMMY_MAX_SCAN_PERCENT-ldwProgress_In_Percent)/(long double(m_dwTotalNoOfFilesToScan-m_ulFileCount))))*(m_ulFileCount-dwPrevious_count)));

					if((m_ulFileCount-dwPrevious_count)  > (m_dwTotalNoOfFilesToScan-m_ulFileCount) && (ctTotalScanTime.GetTimeSpan()>2 && ctTotalScanTime.GetTimeSpan()<5) && ldwProgress_In_Percent+0.1<DUMMY_MAX_SCAN_PERCENT)
					{
						ldwProgress_In_Percent+=0.1;
					}
					else if((m_ulFileCount-dwPrevious_count)  > (m_dwTotalNoOfFilesToScan-m_ulFileCount) && (ctTotalScanTime.GetTimeSpan()>5) && ldwProgress_In_Percent+1<DUMMY_MAX_SCAN_PERCENT)
					{
						if(ldwProgress_In_Percent<=(END_SCAN_PERCENT-1))
						{
							ldwProgress_In_Percent+=1;
						}
					}
					else if(ldwtemp>1 && ctTotalScanTime.GetTimeSpan()<8 && (m_ulFileCount-dwPrevious_count)  < (m_dwTotalNoOfFilesToScan-m_ulFileCount)&& ldwProgress_In_Percent+0.1<DUMMY_MAX_SCAN_PERCENT)
					{
						ldwProgress_In_Percent+=0.1;
					}
					else if(ldwtemp>0.5 && ctTotalScanTime.GetTimeSpan()<20 && (m_ulFileCount-dwPrevious_count)  < (m_dwTotalNoOfFilesToScan-m_ulFileCount)&& ldwProgress_In_Percent+0.135<DUMMY_MAX_SCAN_PERCENT)
					{
						ldwProgress_In_Percent+=0.135;
					}
					else if((m_ulFileCount-dwPrevious_count)  < (m_dwTotalNoOfFilesToScan-m_ulFileCount))
					{
						ldwProgress_In_Percent+=ldwtemp;
					}
				}
				else if(m_ulFileCount>=m_dwTotalNoOfFilesToScan)
				{
					if(ctTotalScanTime.GetTimeSpan()>20 && (ctTotalScanTime.GetTimeSpan()%30)==00 && (m_ulFileCount-m_dwTotalNoOfFilesToScan)<500)
					{
						if(DUMMY_MAX_SCAN_PERCENT<=25 && ctTotalScanTime.GetTimeSpan()<150)
						{
							DUMMY_MAX_SCAN_PERCENT+=5;
							ldwProgress_In_Percent+=1;
						}
						else if(DUMMY_MAX_SCAN_PERCENT<=70 && ctTotalScanTime.GetTimeSpan()<1500)
						{
							DUMMY_MAX_SCAN_PERCENT+=1;
							ldwProgress_In_Percent+=0.25;
						}
						else
							ldwProgress_In_Percent+=0.0020;
					}
				}
			}
			else if(m_dwTotalNoOfFilesToScan!=0)
			{
				if(dwActualFileCountInIncrements+(m_ulFileCount-dwPrevious_count)<dwActualFileCountPending)
				{
					dwActualFileCountInIncrements+=(m_ulFileCount-dwPrevious_count);
				}
				if(dwActualFileCountPending!=0x00)
				{
				 ldwProgress_In_Percent=ldwPrevious_Progress+(((END_SCAN_PERCENT-ldwPrevious_Progress)/dwActualFileCountPending)*(dwActualFileCountInIncrements));
				}
			}

			csTemp.Format(L"%d", (int)ldwProgress_In_Percent);
			if((int)ldwProgress_In_Percent < 0)
			{
				CString csMsg;
				csMsg.Format(L"ldwPrevious_Progress = %u, dwActualFileCountPending = %u, m_ulFileCount = %u, bDummyCount = %u, m_dwTotalNoOfFilesToScan = %u, dwActualFileCountInIncrements = %u",
					ldwPrevious_Progress, dwActualFileCountPending, m_ulFileCount, bDummyCount, m_dwTotalNoOfFilesToScan, dwActualFileCountInIncrements);
				AddLogEntry(csMsg);				
			}

			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlProgressInPercentage.SetWindowText(csTemp);
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlProgressBar.SetPos((int)ldwProgress_In_Percent);

			//csTemp.Format(L"%d", m_dwTotalNoOfFilesToScan);
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlNoOfFilesAvailable.SetWindowText(csTemp);

			//csTemp.Format(L"%d", m_ulFileCount);
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrl_NoOfFilesScanned.SetWindowText(csTemp);

			CTimeSpan ctTotalScanTime = ((GetTickCount() - m_dwStartTickCount)/1000);
			//csTemp.Format(L"%02d:%02d:%02d", (DWORD)ctTotalScanTime.GetHours(), (DWORD)ctTotalScanTime.GetMinutes(), (DWORD)ctTotalScanTime.GetSeconds());
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlElapsedTime.SetWindowText(csTemp);

			if(bDummyCount)
			{
				if(ctTotalScanTime.GetTimeSpan()<2)
				{
					ldwTotalRemTime+=4;
				}
				else if(ctTotalScanTime.GetTimeSpan()<=8)
				{
					if(m_dwTotalNoOfFilesToScan-m_ulFileCount>15000)
					{
						ldwTotalRemTime+=75;
					}
					else if(m_dwTotalNoOfFilesToScan-m_ulFileCount>8000)
					{
						ldwTotalRemTime+=55;
					}
					else if(m_dwTotalNoOfFilesToScan-m_ulFileCount>4000)
					{ 
						ldwTotalRemTime+=30;
					}
					else if(m_dwTotalNoOfFilesToScan-m_ulFileCount>750)
					{
						ldwTotalRemTime+=17;
					}
					else if(m_dwTotalNoOfFilesToScan-m_ulFileCount>0)
					{
						ldwTotalRemTime+=10;
					}
					else
					{
						ldwTotalRemTime+=5;
					}
				}

				if(ctTotalScanTime.GetTimeSpan()>0 && ctTotalScanTime.GetTimeSpan()<=8 && iCounter<100)
				{
					ldwGetDiffTime=((GetTickCount() - ldwPreviousTime)/1000);
					Arr_CollectSamplingFiles[iCounter++]=(m_ulFileCount-dwPrevious_count)/ldwGetDiffTime;
				}

				if(ctTotalScanTime.GetTimeSpan()>8)
				{
					if(!bMedianCalculate)
					{
						BYTE byflag=0x01;
						while(byflag)
						{
							byflag=0x00;
							for(int i=1; i<=iCounter-0x01; i++)
							{
								if(Arr_CollectSamplingFiles[i-0x01] > Arr_CollectSamplingFiles[i])
								{
									Arr_CollectSamplingFiles[i-0x01]+=Arr_CollectSamplingFiles[i];
									Arr_CollectSamplingFiles[i]=Arr_CollectSamplingFiles[i-0x01]-Arr_CollectSamplingFiles[i];
									Arr_CollectSamplingFiles[i-0x01]-=Arr_CollectSamplingFiles[i];
									byflag=0x01;
								}
							}
						}

						int i=0;
						if(iCounter>0)
						{
							while(Arr_CollectSamplingFiles[i]==0)
							{i++;}
						}
						if(iCounter==0)
						{
							Arr_CollectSamplingFiles[0]=200;
						}
						else if((iCounter-i)%2==1)
						{
							Arr_CollectSamplingFiles[0]=Arr_CollectSamplingFiles[i+(iCounter-i)/2];
						}
						else if(iCounter>0)
						{ 
							Arr_CollectSamplingFiles[0]=(Arr_CollectSamplingFiles[i+(iCounter-i)/2]+Arr_CollectSamplingFiles[i+((iCounter-i)/2)+1])/2;
						}
						bMedianCalculate=true;
					}

					if(ldwTotalRemTime>0 && (DWORD)((ldwTotalRemTime/60))/45>=(Forty5MinuteIn+1))
					{   
						if(Forty5MinuteIn==0)
						{
							ldwOriginalSampleValue=Arr_CollectSamplingFiles[0];
						}
						Forty5MinuteIn++;
						Arr_CollectSamplingFiles[0]*=4;
					}

					if(bMedianCalculate)
					{
						if((m_dwTotalNoOfFilesToScan+dwPrevious_count)>(dwPreviousTotalFileCount+m_ulFileCount))
						{
							ldwTotalRemTime+=(m_dwTotalNoOfFilesToScan-dwPreviousTotalFileCount-m_ulFileCount+dwPrevious_count)*(1/Arr_CollectSamplingFiles[0]);
						}
					}
				}
			}
			else
			{
				if(dwActualFileCountPending>0 && !bArrSampleZero)
				{
					ldwTotalRemTime=((ldwActualRemTime/dwActualFileCountPending)*(dwActualFileCountPending-dwActualFileCountInIncrements));
				}
				else if(bArrSampleZero && (dwActualFileCountPending-dwActualFileCountInIncrements)<1200)
				{
					ldwActualRemTime=10;
					bArrSampleZero=false;
				}
				else if(bArrSampleZero && (dwActualFileCountPending-dwActualFileCountInIncrements)<3000)
				{ 
					ldwActualRemTime=25;
					bArrSampleZero=false;
				}
				else if(bArrSampleZero && (dwActualFileCountPending-dwActualFileCountInIncrements)<15000)
				{
					ldwTotalRemTime+=28;
				}
				else if(bArrSampleZero)
				{
					ldwTotalRemTime+=75;
				}

				if(bArrSampleZero && ctTotalScanTime.GetTimeSpan()>0 && ctTotalScanTime.GetTimeSpan()<=4 && iCounter<100)
				{
					ldwGetDiffTime=((GetTickCount() - ldwPreviousTime)/1000);
					Arr_CollectSamplingFiles[iCounter++]=(m_ulFileCount-dwPrevious_count)/ldwGetDiffTime;

				}
				else if(bArrSampleZero && ctTotalScanTime.GetTimeSpan()>4)
				{
					BYTE byflag=0x01;
					while(byflag)
					{
						byflag=0x00;
						for(int i=1; i<=iCounter-0x01; i++)
						{
							if(Arr_CollectSamplingFiles[i-0x01] > Arr_CollectSamplingFiles[i])
							{
								Arr_CollectSamplingFiles[i-0x01]+=Arr_CollectSamplingFiles[i];
								Arr_CollectSamplingFiles[i]=Arr_CollectSamplingFiles[i-0x01]-Arr_CollectSamplingFiles[i];
								Arr_CollectSamplingFiles[i-0x01]-=Arr_CollectSamplingFiles[i];
								byflag=0x01;
							}
						}
					}
					int i=0;
					if(iCounter>0)
					{
						while(Arr_CollectSamplingFiles[i]==0)
						{i++;}
					}
					if(iCounter==0)
					{
						Arr_CollectSamplingFiles[0]=200;
					}
					else if((iCounter-i)%2==1)
					{
						Arr_CollectSamplingFiles[0]=Arr_CollectSamplingFiles[i+(iCounter-i)/2];
					}
					else if(iCounter>0)
					{ 
						Arr_CollectSamplingFiles[0]=Arr_CollectSamplingFiles[i+(iCounter-i)/2]+Arr_CollectSamplingFiles[i+((iCounter-i)/2)+1];
					}
					bArrSampleZero=false;
					ldwActualRemTime=(m_dwTotalNoOfFilesToScan-m_ulFileCount)*(1/(Arr_CollectSamplingFiles[0]));
				}
			}

			if(((DWORD)ldwTotalRemTime%60)==0 && (((DWORD)ldwTotalRemTime/3600)%24==0) &&  ((((DWORD)ldwTotalRemTime/60)%60)==0) && (int)ldwProgress_In_Percent<100 )
			{
				ldwTotalRemTime=1;
			}
			if((ldwTotalRemTime/3600)==24)//Time==24hrs and xy minutes and xy seconds
				csTemp.Format(L"1 Day %02d:%02d:%02d", ((DWORD)ldwTotalRemTime/3600)%24, (((DWORD)ldwTotalRemTime/60)%60), ((DWORD)ldwTotalRemTime%60));
			else if(((ldwTotalRemTime/3600)>24))//Time>24hrs and xy minutes and xy seconds
				csTemp.Format(L"%02d Days %02d:%02d:%02d",((DWORD)ldwTotalRemTime/(3600*24)), ((DWORD)ldwTotalRemTime/3600)%24, (((DWORD)ldwTotalRemTime/60)%60), ((DWORD)ldwTotalRemTime%60));
			else//Time<24hrs and xy minutes and xy seconds
				csTemp.Format(L"%02d:%02d:%02d", ((DWORD)ldwTotalRemTime/3600)%24,(((DWORD)ldwTotalRemTime/60)%60), ((DWORD)ldwTotalRemTime%60));
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlEstimatedFinishTime.SetWindowText(csTemp);

			//csTemp.Format(L"CurrentFile: %s", lpszTextToDisplay);
			//((CSample2008Dlg*)(theApp.m_pMainWnd))->m_ctrlStatusBar.SetWindowText(csTemp);

			dwPrevious_count=m_ulFileCount;
			dwPreviousTotalFileCount=m_dwTotalNoOfFilesToScan;
			ldwPreviousTime=GetTickCount();
		}
		break;
	default:
		{
		}
	}

	return ldwProgress_In_Percent;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::ScanCookieContent
In Parameters  : const TCHAR *cFileName, TCHAR *cFullPath,
Out Parameters : bool, returns true and reports the file to the UI if domain found in DB
Description    : IE 7.0 onwards the file name does not contain the cookie domain name
				 we need to read the file content to check for domain name.
Author & Date  : Darshan Singh Virdi & 22 Jul, 2013.
--------------------------------------------------------------------------------------*/
bool CFileSystemBase::ScanCookieContent(const TCHAR *cFileName, TCHAR *cFullPath)
{
	DWORD dwFileSize = 0x00;
	DWORD dwBytesReadA = 0x00;
	BYTE *pbReadBufferA = NULL;

	try
	{
		
		HANDLE hFileHandle = CreateFile(cFullPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if(INVALID_HANDLE_VALUE == hFileHandle)
		{
			return false;
		}

		dwFileSize = GetFileSize(hFileHandle, 0);

		if(dwFileSize == 0)
		{
			return false;
		}

		dwFileSize++;	// for null terminator!

		::SetFilePointer(hFileHandle, 0, 0, FILE_BEGIN);

		pbReadBufferA = new BYTE[dwFileSize];
		memset(pbReadBufferA, 0, dwFileSize);
		if(!ReadFile(hFileHandle, pbReadBufferA, dwFileSize, &dwBytesReadA, NULL))
		{
			CloseHandle(hFileHandle);
			delete [] pbReadBufferA;
			return false;
		}

		CloseHandle(hFileHandle);
		hFileHandle = NULL;

		if(dwBytesReadA == 0)
		{
			delete [] pbReadBufferA;
			return false;
		}

		NormalizeBuffer(pbReadBufferA, dwBytesReadA);

		DWORD dwBytesReadW = dwFileSize * sizeof(WCHAR);
		BYTE *pbReadBufferW = new BYTE[dwBytesReadW];
		memset(pbReadBufferW, 0, dwBytesReadW);
		
		// cookie file are only in ANSI format. As our database is in UNICODE, we need to convert this buffer to wide char!
		if(MultiByteToWideChar(CP_ACP, 0, (char*)pbReadBufferA, dwBytesReadA, (wchar_t*)pbReadBufferW, dwBytesReadW) == 0)
		{
			delete [] pbReadBufferA;
			delete [] pbReadBufferW;
			return false;
		}

		delete [] pbReadBufferA;

		LPVOID lpPos = m_objCookieDBMap.GetFirst();
		while(lpPos)
		{
			LPTSTR lpszKey = NULL;
			if(m_objCookieDBMap.GetKey(lpPos, lpszKey))
			{
				lpszKey++;
				if(_tcsstr((const wchar_t *)pbReadBufferW, lpszKey))
				{
					ULONG lSpyNameID = 0;
					m_objCookieDBMap.GetData(lpPos, lSpyNameID);
					
					SendScanStatusToUI(/*Cookie*/ Cookie_New, lSpyNameID, 0, cFullPath, lpszKey, 0,0,0,0,0,0);

					delete [] pbReadBufferW;
					return true;
				}
			}

			lpPos = m_objCookieDBMap.GetNext(lpPos);
		}

		delete [] pbReadBufferW;
	}
	catch(...)
	{

	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::NormalizeBuffer
In Parameters  : BYTE *pbReadBuffer, DWORD dwBytesRead
Out Parameters : none
Description    : Converts unknown chars in the buffer to a space.
				 Also converts upper case to lower case.
Author & Date  : Darshan Singh Virdi & 22 Jul, 2013.
--------------------------------------------------------------------------------------*/
void CFileSystemBase::NormalizeBuffer(BYTE *pbReadBuffer, DWORD dwBytesRead)
{
	for(DWORD dwPos = 0; dwPos < (dwBytesRead - 1); dwPos++)
	{
		// other than these chars convert all other chars to a space
		if(((pbReadBuffer[dwPos] > 47) && (pbReadBuffer[dwPos] < 58)) ||		// char 0 - 9
			((pbReadBuffer[dwPos] > 64) && (pbReadBuffer[dwPos] < 91)) ||		// char A - Z
			((pbReadBuffer[dwPos] > 96) && (pbReadBuffer[dwPos] < 123)) ||		// char a - z
			(pbReadBuffer[dwPos] == 45) || (pbReadBuffer[dwPos] == 46) ||		// char - & .
			(pbReadBuffer[dwPos] == 47) || (pbReadBuffer[dwPos] == 37) ||		// char / & %
			(pbReadBuffer[dwPos] == 64))										// char @
		{
			// convert upper case to lower case
			if((pbReadBuffer[dwPos] > 64) && (pbReadBuffer[dwPos] < 91))
			{
				pbReadBuffer[dwPos] = pbReadBuffer[dwPos] + 32;
			}
		}
		else
		{
			pbReadBuffer[dwPos] = ' ';
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::CheckFirefoxBug
In Parameters  : TCHAR *cFileName
Out Parameters : none
Description    : Check Firefox bug.
Author & Date  : Krishna thapa (13.05.2015).
--------------------------------------------------------------------------------------*/

void CFileSystemBase::initilizeFirefoxPath()
{
	CRegistry objRegistry;
	CString strPathTemp;
	
	objRegistry.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA_LOCAL"),strPathTemp,HKEY_LOCAL_MACHINE);
	strPathTemp+="\\Mozilla\\Firefox\\Profiles";
	CFileFind finder;
	strPathTemp+="\\*.*";
	BOOL bWorking = finder.FindFile(strPathTemp);
	while (bWorking)
	{
		
		bWorking = finder.FindNextFile();
		if (finder.IsDots())
			continue;

		if(finder.IsDirectory())
		{
			m_csFireFoxPath.Add(finder.GetFilePath());
		}
		
	}
}


/*--------------------------------------------------------------------------------------
Function       : CFileSystemBase::CheckFirefoxBug
In Parameters  : TCHAR *cFileName
Out Parameters : none
Description    : Check Firefox bug.
Author & Date  : Krishna thapa (13.05.2015).
--------------------------------------------------------------------------------------*/

bool CFileSystemBase::CheckFirefoxBug(CString cFileName,CString cFolderName,CString &szFilePath)
{
	CString szName;
	HANDLE hFindFile;
	WIN32_FIND_DATA info;
	int fullLength=cFileName.GetLength();
	int pos=cFileName.Find(_T(".default"));
	int diffLength=fullLength-pos;
	CString l_sFireFoxPath=_T(" ");
	l_sFireFoxPath=cFolderName;
	if(pos!=-1)
	{
		szName=cFileName.Mid(pos+9,diffLength);
		l_sFireFoxPath+=_T("\\");
		l_sFireFoxPath+=szName;
		hFindFile = FindFirstFile(l_sFireFoxPath, &info);
		if(INVALID_HANDLE_VALUE != hFindFile)
		{
			szFilePath=l_sFireFoxPath;
			return true;
		}
	}
	return false;
}



void CFileSystemBase::initilizeChromePath()
{
	CRegistry objRegistry;
	CString strPathTemp;
	
	objRegistry.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA_LOCAL"),strPathTemp,HKEY_LOCAL_MACHINE);
	//m_sChromePath=strPathTemp;
	strPathTemp+=_T("\\Google\\Chrome\\User Data\\Default\\Extensions");
	CFileFind finder;
	strPathTemp+="\\*.*";
	BOOL bWorking = finder.FindFile(strPathTemp);
	while (bWorking)
	{
		
		bWorking = finder.FindNextFile();
		if (finder.IsDots())
			continue;

		if(finder.IsDirectory())
		{
			m_csChromePath.Add(finder.GetFilePath());
		}
		
	}
}


bool CFileSystemBase::CheckChromeBug(CString cFolderName,CString &outFilePath)
{
	HANDLE hFindFile;
	WIN32_FIND_DATA info;
	hFindFile = FindFirstFile(cFolderName, &info);
	if(INVALID_HANDLE_VALUE != hFindFile)
	{
		outFilePath=cFolderName;
		return true;
	}
	return false;


}
void  CFileSystemBase::ConfigForNetworkScan(CString csScanDrive)
{

	if(!theApp.m_bValidated)
	{
		CString csAppPath =  CSystemInfo::m_strAppPath;
		CString csApplicationPath = csAppPath +_T("Tools\\");
		TCHAR szHostname[MAX_PATH]={0};
				DWORD dwSize = UNLEN + 1;
		CString csMachineName = csScanDrive.Left(csScanDrive.Find(L"\\",csScanDrive.Find(L"\\")+3));
				csMachineName = csMachineName.Mid(2);
				csMachineName.Trim();
				GetComputerName(szHostname,&dwSize);
				CString csHostname(szHostname);
				csHostname.Trim();
				if(csMachineName.CompareNoCase(csHostname) == 0 ) 
				{
					return;
				}			
		if(csScanDrive.GetAt(0)==L'\\')
		{		
			CRegistry objReg;				
			TCHAR  szUsername[MAX_PATH]= {0};
			CString csUsername;
			CString csProductKey = CSystemInfo::m_csProductRegKey;	           
			objReg.Get(csProductKey,L"CurrUser", csUsername,HKEY_LOCAL_MACHINE);
			_tcscpy_s(szUsername,MAX_PATH,csUsername);
			  
			CS2S objUseraccounts(false);
			objUseraccounts.Load(csApplicationPath + CURR_USER_CRED);
			TCHAR *szPassword=NULL;
			objUseraccounts.SearchItem(szUsername,szPassword);
			
			CNetWorkUserValidation objNetValid;
			objNetValid.ImpersonateLocalUser(szUsername,szPassword);

			CString csMachineName;
			size_t iLen = csScanDrive.GetLength();
			if(iLen > 0)
			{
				CString csTemp(csScanDrive);			
				if(csTemp.Right(1) == L"\\")
					{
						csTemp = csTemp.Left((int)iLen -1);
					}
					if(csTemp.GetAt(0)==L'\\')
					{
						csMachineName = csTemp.Left(csTemp.Find(L"\\",csTemp.Find(L"\\")+3));
						csMachineName = csMachineName.Mid(2);			
					}
				}		
				TCHAR szMachineName[MAX_PATH]={0};
				_tcscpy_s(szMachineName,MAX_PATH,csMachineName);


				CBufferToStructure objNetworkCredentials(false, sizeof(TCHAR)*MAX_PATH, sizeof(NETCREDDATA));
				LPNETCREDDATA lpNetCredentials = NULL;				
				
				RevertToSelf();
				objNetworkCredentials.Load(csApplicationPath + NETWORK_SCAN_CRED);

				_tcslwr(szMachineName);
				if(objNetworkCredentials.SearchItem(szMachineName,(LPVOID&)lpNetCredentials))
				{
					OutputDebugString(L"Successfully Got the Machine Name");
					objNetValid.ImpersonateLocalUser(szUsername,szPassword);
					objNetValid.NetworkValidation(szMachineName,lpNetCredentials->szUsername,lpNetCredentials->szPassword);					   
					theApp.m_bValidated = true;
				}

		}
		else
		{
			return;
		}
	}
}