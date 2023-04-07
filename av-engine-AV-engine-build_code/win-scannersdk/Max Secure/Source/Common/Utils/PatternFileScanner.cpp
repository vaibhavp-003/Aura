/*======================================================================================
FILE             : PatternFileScanner.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Tushar Kadam
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

CREATION DATE    : 07/2/2011 6:53:00 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include <shlobj.h>
#include "PatternFileScanner.h"
#include "Constants.h"
#include "MaxConstant.h"
#include "Shellapi.h"
#include "AdwarePatternScan.h"


#ifndef ACTIVEPROT2K
#include "TaskHostScan.h"
#endif 

#ifndef MAXAVDBSCAN_EXPORTS
	#include "SDSystemInfo.h"
#endif

bool	bScanTaskHostDone = false;
void	ScanTaskHostThread(void *lpVoid);
void	ScanTaskHostThread(void *lpVoid)
{
	#ifndef ACTIVEPROT2K
	CTaskHostScan	*pTaskHost;
	
	pTaskHost = new CTaskHostScan;
	
	pTaskHost->ScanTaskSVCHost();
	#endif 
	
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: CPatternFileScanner
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CPatternFileScanner::CPatternFileScanner():m_objBlackFileNames(false), m_objFileFolderSameLevel(false),
						m_objFileInsideFolder(false), m_objExcludePath(false)
{
	TCHAR szPath[MAX_PATH] = {0};
	CString csInstallPath;

	m_hDBScan = NULL;
	m_chDrive = 0;
	m_bExcludeDBReady = false;
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
	m_csUSBDrives = "";
	m_csNonRemovableDrives ="";

#ifdef MAXAVDBSCAN_EXPORTS
	csInstallPath = GetInstallPath();
#else

	m_lpfnScanFileByPattern = NULL;
	m_lpfnGetPatterScanVersion = NULL;
	csInstallPath = CSystemInfo::m_strAppPath;
	m_hDBScan = LoadLibrary(_T("AuAVDBScan.dll"));
	if(m_hDBScan)
	{
		m_lpfnScanFileByPattern = (LPFN_ScanFileByPattern)GetProcAddress(m_hDBScan, "ScanFileByPattern");
		m_lpfnGetPatterScanVersion = (LPFN_GetPatterScanVersion)GetProcAddress(m_hDBScan, "GetPatterScanVersion");
		
	}

	if(!m_lpfnScanFileByPattern)
	{
		FreeLibrary(m_hDBScan);
		m_hDBScan = nullptr;
		AddLogEntry(L"Failed getting ScanFileByPattern from DB Scan Dll");
	}
	if(!m_lpfnGetPatterScanVersion)
	{
		AddLogEntry(L"Failed To Get Current Pattern Scan Version");
	}
#endif

	m_hRandomNamePatternScn = NULL;
	m_lpfnRandomNameScan = NULL;
	m_lpfnRandomNameLoadDB = NULL;
	m_bRandomDllLoaded = false;
	m_csInstScanIni = csInstallPath + _T("Setting\\InstantScan.ini");
	m_csPattScanIni = csInstallPath + _T("Setting\\PatternScan.ini");
	m_csLnkScanIni = csInstallPath + _T("Setting\\LnkScan.ini");
	_stprintf(m_szRandPatDBPath,_T("%sNamePtrn.pki"),csInstallPath);
	InitExcludeIni();

	m_csWinPath = m_csRootPath = m_csPFDirPath = _T("");
	if(0 != GetWindowsDirectory(szPath, MAX_PATH))
	{
		if(szPath[0])
		{
			TCHAR szDrive[5] = _T("C:\\");

			szDrive[0] = szPath[0];
			m_csRootPath.Format(_T("%s"), szDrive);
			m_csPFDirPath.Format(_T("%sProgram Files\\"), szDrive);
			if(szPath[_tcslen(szPath) - 1] != _T('\\'))
			{
				m_csWinPath.Format(_T("%s\\"), szPath);
			}
			else
			{
				m_csWinPath.Format(_T("%s"), szPath);
			}
		}
	}

	m_iDocAndSetPathLen = 0;
	memset(m_szDocAndSet, 0, sizeof(m_szDocAndSet));
	if(!GetDocAndSet(m_szDocAndSet, _countof(m_szDocAndSet)))
	{
		m_szDocAndSet[0] = 0;
		m_iDocAndSetPathLen = 0;
	}
	else
	{
		LPTSTR szLastSlash = _tcsrchr(m_szDocAndSet, _T('\\'));
		if(szLastSlash)
		{
			*szLastSlash = 0;
			szLastSlash = _tcsrchr(m_szDocAndSet, _T('\\'));
			if(szLastSlash)
			{
				*(szLastSlash + 1) = 0;
				m_iDocAndSetPathLen = _tcslen(m_szDocAndSet);
			}
			else
			{
				m_szDocAndSet[0] = 0;
				m_iDocAndSetPathLen = 0;
			}
		}
		else
		{
			m_szDocAndSet[0] = 0;
			m_iDocAndSetPathLen = 0;
		}
	}

	TCHAR		szDummy[1024] = {0x00};
	m_csRansExtList = L"";
	CString		csRanExtIni = csInstallPath + _T("Setting\\RansExtLst.ini");
	GetPrivateProfileStringW(L"RANS_EXT",L"EXT",L"",szDummy,1024,csRanExtIni);
	if (_tcslen(szDummy) > 0x00)
	{
		m_csRansExtList.Format(L"%s",szDummy);
		m_csRansExtList.Trim();
		m_csRansExtList.MakeLower();
	}
} 

/*-------------------------------------------------------------------------------------
	Function		: ~CPatternFileScanner
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CPatternFileScanner::~CPatternFileScanner()
{
	AddSignatureToInstantScanner(m_objBlackFileNames, MAX_BLACK_FILE_NAMES_COUNT, true);
	AddSignatureToInstantScanner(m_objFileInsideFolder, MAX_FILE_INSIDE_FOLDER_COUNT, true);
	AddSignatureToInstantScanner(m_objFileFolderSameLevel, MAX_FIL_FOLDER_SAME_LEVEL_COUNT, true);

	if(m_hDBScan)
	{
		FreeLibrary(m_hDBScan);
		m_hDBScan = NULL;
	}
	RandomNamePatternUnLoad();

	if(m_hEvent)
	{
		CloseHandle(m_hEvent);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: GetCurrentPatVersion
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Reruns the current Pattern Version for Local Db scanning
--------------------------------------------------------------------------------------*/
DWORD CPatternFileScanner::GetCurrentPatVersion()
{
	#ifdef MAXAVDBSCAN_EXPORTS
		return MAX_PATTERN_SCAN_VERSION;
	#else
		if(m_lpfnGetPatterScanVersion)
		{
			return m_lpfnGetPatterScanVersion();
		}
	#endif
	
	return MAX_PATTERN_SCAN_VERSION;
}

/*-------------------------------------------------------------------------------------
	Function		: GetCurrentVersion
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Reruns the current Pattern Version for Local Db scanning
--------------------------------------------------------------------------------------*/
DWORD CPatternFileScanner::GetCurrentVersion()
{
	return MAX_PATTERN_SCAN_VERSION;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDocAndSet
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Supportive Function
	Author			: Tushar Kadam
	Description		: Retrieves "Common Desktop" Path for Internal use
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::GetDocAndSet(LPTSTR szDocAndSetPath, DWORD cchDocAndSetPath)
{
	HKEY hKey = 0;
	DWORD dwRetVal = 0, dwSize = 0;

	dwRetVal = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_SHELL_FOLDER, 0, KEY_READ, &hKey);
	if(ERROR_SUCCESS != dwRetVal || NULL == hKey)
	{
		AddLogEntry(_T("Open key failed: %s"), REG_SHELL_FOLDER, 0, true, LOG_DEBUG);

		if(hKey)
		{
			RegCloseKey(hKey);
			hKey = NULL;
		}

		return false;
	}

	dwSize = sizeof(m_szDocAndSet);
	dwRetVal = RegQueryValueEx(hKey, _T("Common Desktop"), 0, 0, (LPBYTE)m_szDocAndSet, &dwSize);
	RegCloseKey(hKey);

	if(ERROR_SUCCESS != dwRetVal)
	{
		AddLogEntry(_T("Read value failed: %s-%s"), REG_SHELL_FOLDER, _T("Common Desktop"), true, LOG_DEBUG);
		return false;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: InitExcludeIni
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Supportive Function
	Author			: Tushar Kadam
	Description		: Loads Exclude INI
--------------------------------------------------------------------------------------*/
void CPatternFileScanner::InitExcludeIni()
{
	int iCount = 0;
	CString csKey;
	TCHAR szPath[MAX_PATH] = {0};

	m_bExcludeDBReady = false;
	m_objExcludePath.RemoveAll();
	if(_taccess_s(m_csPattScanIni, 0))
	{
		AddLogEntry(L"Not found: %s", m_csPattScanIni, 0, true, LOG_DEBUG);
		return;
	}

	iCount = GetPrivateProfileInt(L"Path", L"Count", 0, m_csPattScanIni);
	if(iCount)
	{
		AddLogEntry(L"Exl path count not zero", 0, 0, true, LOG_DEBUG);
		for(int i = 0; i < iCount; i++)
		{
			csKey.Format(_T("%i"), i);
			AddLogEntry(L"Count: %s", csKey, 0, true, LOG_DEBUG);

			memset(szPath, 0, sizeof(szPath));
			GetPrivateProfileString(L"Path", csKey, _T(""), szPath, _countof(szPath), m_csPattScanIni);
			AddLogEntry(L"Path: %s", szPath, 0, true, LOG_DEBUG);
			if(szPath[0])
			{
				_tcslwr_s(szPath, _countof(szPath));
				m_objExcludePath.AppendItem(szPath + 1, 10);
				AddLogEntry(L"Exl Path: %s", szPath + 1, 0, true, LOG_DEBUG);
				m_bExcludeDBReady = true;
			}
		}
	}
	else
	{
		AddLogEntry(L"No exl path found", 0, 0, true, LOG_DEBUG);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: IsExcluded
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if present in exclude list else false
	Purpose			: Supportive Function
	Author			: Tushar Kadam
	Description		: Checks File in exclude list
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::IsExcluded(LPCTSTR szFilePath)
{
	TCHAR szDupName[MAX_PATH] = {0};
	LPVOID lpContext = NULL;
	bool bFound = false;
	LPTSTR szNameFromDB = NULL;

	if(!szFilePath || _tcslen(szFilePath) >= _countof(szDupName))
	{
		AddLogEntry(L"Excluding too long path: %s", szFilePath, 0, true, LOG_DEBUG);
		return true;
	}

	_tcscpy_s(szDupName, _countof(szDupName), szFilePath);
	_tcslwr_s(szDupName, _countof(szDupName));

	CS2U objTempExcludeDB(true);
	objTempExcludeDB.SetDataPtr(m_objExcludePath.GetDataPtr(), 0, 0);

	lpContext = objTempExcludeDB.GetFirst();
	while(lpContext)
	{
		objTempExcludeDB.GetKey(lpContext, szNameFromDB);
		if(szNameFromDB)
		{
			if(_tcsstr(szDupName, szNameFromDB))
			{
				bFound = true;
				AddLogEntry(L"Excluded Path: %s, %s", szDupName, szNameFromDB, true, LOG_DEBUG);
				break;
			}
		}
		lpContext = objTempExcludeDB.GetNext(lpContext);
	}

	return bFound;
}

/*-------------------------------------------------------------------------------------
	Function		: TrimString
	In Parameters	: LPTSTR szString
	Out Parameters	: 
	Purpose			: Supportive Function
	Author			: Tushar Kadam
	Description		: 
--------------------------------------------------------------------------------------*/
void CPatternFileScanner::TrimString(LPTSTR szString)
{
	int i = 0, iLen = 0;
	LPTSTR pBegin = 0, pFinish = 0;

	iLen = _tcslen(szString);
	for(i = 0; i < iLen; i++)
	{
		if(0 != _istprint(szString[i]) && szString[i] != 32 && szString[i] != 160)
		{
			pBegin = szString + i;
			break;
		}
	}

	if(!pBegin)
	{
		*szString = 0;
		return;
	}

	for(i = iLen; i >= 0; i--)
	{
		if(0 != _istprint(szString[i]) && szString[i] != 32 && szString[i] != 160)
		{
			pFinish = szString + i;
			break;
		}
	}

	if(pBegin >= pFinish)
	{
		return;
	}

	while(pBegin <= pFinish)
	{
		*szString++ = *pBegin++;
	}

	*szString = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: HasValidVersionTab
	In Parameters	: LPCTSTR szFilePath, BYTE& byVerTabInfo
	Out Parameters	: true if version table present else false
	Purpose			: Supportive Function
	Author			: Tushar Kadam
	Description		: Checks File for its version info
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::HasValidVersionTab(LPCTSTR szFilePath, BYTE& byVerTabInfo)
{
	TCHAR szCompanyName[MAX_PATH] = {0};

	if(1 == byVerTabInfo)
	{
		return true;
	}
	else if(2 == byVerTabInfo)
	{
		return false;
	}

	CFileVersionInfo objVerInfo;
	if(!objVerInfo.GetCompanyName(szFilePath, szCompanyName))
	{
		byVerTabInfo = 2;
		return false;
	}

	_tcslwr_s(szCompanyName, _countof(szCompanyName));
	if(!_tcsstr(szCompanyName, _T("microsoft")))
	{
		byVerTabInfo = 2;
		return false;
	}

	byVerTabInfo = 1;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanFile
	In Parameters	: LPCTSTR szFilePath, bool bSigCreated, ULONG64 ulSignature, BYTE& byVerTabInfo, DWORD dwLocalDBVer
	Out Parameters	: true if Pattern Match else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file for differnt pattern rules
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::ScanFile(LPCTSTR szFilePath, bool bSigCreated, ULONG64 ulSignature, BYTE& byVerTabInfo, DWORD dwLocalDBVer)
{
#ifdef MAXAVDBSCAN_EXPORTS
	return ScanFileByPattern(szFilePath, bSigCreated, ulSignature, byVerTabInfo,dwLocalDBVer);
#else
	if(m_lpfnScanFileByPattern)
	{
		return m_lpfnScanFileByPattern(szFilePath, bSigCreated, ulSignature, byVerTabInfo,dwLocalDBVer);
	}
#endif
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanFileByPattern
	In Parameters	: LPCTSTR szFilePath, bool bSigCreated, ULONG64 ulSignature, BYTE& byVerTabInfo, DWORD dwLocalDBVer
	Out Parameters	: true if Pattern Match else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file for differnt pattern rules
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::ScanFileByPattern(LPCTSTR szFilePath, bool bSigCreated, ULONG64 ulSignature, BYTE& byVerTabInfo, DWORD dwLocalDBVer)
{
	bool bInfected = false;

	if (dwLocalDBVer >= MAX_PATTERN_SCAN_VERSION)
	{
		AddLogEntry(L"SKIP LOCAL : %s", szFilePath, 0, true, LOG_DEBUG);
		return bInfected;
	}

	m_bIsUSBFile = false;
	if(m_bExcludeDBReady && IsExcluded(szFilePath))
	{
		AddLogEntry(L"Excluded by Path in Pattern Scan Ini: %s", szFilePath, nullptr, true, LOG_DEBUG);
		return bInfected;
	}

	TCHAR szDummy[1024] = {0x00};
	_tcscpy_s(szDummy,1024, szFilePath);
	szDummy[3] = '\0';
	_tcsupr(szDummy);

	if (m_csNonRemovableDrives.Find(szDummy) == -1)
	{
		if (m_csUSBDrives.Find(szDummy) == -1)
		{
			if(GetDriveType(szDummy) == DRIVE_REMOVABLE)
			{
				m_csUSBDrives = m_csUSBDrives + szDummy;
				m_csUSBDrives = m_csUSBDrives + L"|";
				m_bIsUSBFile = true;
			}
			else
			{
				m_csNonRemovableDrives = m_csNonRemovableDrives + szDummy;
				m_csNonRemovableDrives = m_csNonRemovableDrives + L"|";
				m_bIsUSBFile = false;
			}
		}
		else
		{
			m_bIsUSBFile = true;
		}
	}

	
	if(bScanTaskHostDone  == false)
	{
		//if (m_bIsUSBFile == true)
		//{
			//CWinThread	*pScanTaskHostThread = NULL;
			//pScanTaskHostThread = AfxBeginThread((AFX_THREADPROC)ScanTaskHostThread,(void *)this,THREAD_PRIORITY_NORMAL,0,0,NULL);
			if (CreateThread(nullptr,0x00,(LPTHREAD_START_ROUTINE)ScanTaskHostThread,nullptr,0, nullptr) != nullptr)
			{
				bScanTaskHostDone  = true;
			}
		//}
	}

	TCHAR	szDummyFileNm[1024] = {0x0};

	_tcscpy_s(szDummyFileNm,1024,szFilePath);
	_tcslwr(szDummyFileNm);

	if ((_tcsstr(szDummyFileNm,L" files\\max ") != nullptr) && (_tcsstr(szDummyFileNm,L"\\tempfolder\\") != nullptr))
	{
		return bInfected;
	}

	CAdwarePatternScan objAdwarePatternScan ;

	if(objAdwarePatternScan.ScanAdwarePattern(szFilePath))
	{
		bInfected = true;
	}
	if(!bInfected && ScanPluginContainer(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKPLUGINCONTDIRLOC: %s", szFilePath);
	}

	if(!bInfected && DetectBadGuid(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKBADGUID: %s", szFilePath);
	}

	if(!bInfected && ScanBestAddBlocker(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####BLKBSTADDBLKDIRLOC: %s", szFilePath);
	}

	if(!bInfected && ScanLinkFile(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####SCNLNKPTH: %s", szFilePath);
	}
	
	if(!bInfected && CheckForLNKFile(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####SCNLNKPTH: %s", szFilePath);
	}

	if(!bInfected && CheckForPDVDBVirus(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####SCNLNKVBSPTH: %s", szFilePath);
	}

	if(!bInfected && BlackPtnByFileName(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####SCNPTHNME : %s", szFilePath);
	}

	if(!bInfected && KnownBlackPattern1(szFilePath, bSigCreated, ulSignature, byVerTabInfo))
	{
		bInfected = true;
		AddLogEntry(L"####BLACKPATTERN1: %s", szFilePath);
	}

	if(!bInfected && IsInvalidLink(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####SCNINVLNK: %s", szFilePath);
	}

	if(!bInfected && KnownBlackName(szFilePath, ulSignature))
	{
		bInfected = true;
		AddLogEntry(L"####KNWNBLKNM: %s", szFilePath);
	}

	if(!bInfected && ScanByDirLocation(szFilePath, ulSignature, byVerTabInfo))
	{
		bInfected = true;
		AddLogEntry(L"####BLACKDIRLOCATION: %s", szFilePath);
	}

	if(!bInfected && ScanByLocation(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####INVLOCATION: %s", szFilePath);
	}

	if(!bInfected && IsSuspeciousLink(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####INVLDLNK2: %s", szFilePath);
	}

	if (!bInfected && Scan_G_FilePattern(szFilePath,ulSignature))
	{
		bInfected = true;
		AddLogEntry(L"####GFILEPATRN: %s", szFilePath);
	}

	if(!bInfected && RandomNamePatternScanner(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####RFOLDERNAMEPATT: %s", szFilePath);
	}
	if(!bInfected && RansomwareCleanUP(szFilePath))
	{
		bInfected = true;
		AddLogEntry(L"####RANSCLNPATT: %s", szFilePath);
	}

	if (bInfected == false && m_bIsUSBFile == true)
	{
		DWORD		dwAttributes = 0x00;

		try
		{
			dwAttributes = GetFileAttributes(szFilePath);

			if((dwAttributes & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN)
			{
				dwAttributes ^= FILE_ATTRIBUTE_SYSTEM;
				dwAttributes ^= FILE_ATTRIBUTE_HIDDEN;
				SetFileAttributes(szFilePath, dwAttributes);
			}
		}
		catch(...)
		{
			AddLogEntry(L"Files To Remove HIDDEN Attribes : %s", szFilePath,0,true,LOG_DEBUG);
		}
	}

	return bInfected;
}

/*-------------------------------------------------------------------------------------
	Function		: BlackPtnByFileName
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if Pattern Match else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file rule : Suspicious File Name
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::BlackPtnByFileName(LPCTSTR szFilePath)
{
	CString csFullFilePath(szFilePath);
	if((csFullFilePath.Find(L".exe") != -1) || (csFullFilePath.Find(L".scr") != -1))
	{
		if(csFullFilePath.Find(L"                    ") != -1)		//20 space
			return true;

		else if(csFullFilePath.Find(L"____________________") != -1)	//20 '_'
			return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForVBSFile
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if Pattern Match else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file rule : Suspicious VBS File
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::CheckForVBSFile(LPCTSTR szFilePath)
{
	CString csFullFilePath(szFilePath);
	csFullFilePath.MakeLower();
	bool bIsVBS = false;
	if(csFullFilePath.Right(4) == _T(".vbs"))
	{
		AddLogEntry(L"VBS File Found: %s", szFilePath, 0, true, LOG_DEBUG);
		bIsVBS = true;
	}
	
	if(bIsVBS)
	{
		if (m_bIsUSBFile)
		{
			AddLogEntry(L"Got Removable drive: %s", szFilePath, 0, true, LOG_DEBUG);
			if(csFullFilePath.Find(_T("\\"),4) != -1)
			{
				return false;
			}
			else
			{
				AddLogEntry(L"Suspicious VB: %s", szFilePath, 0, true, LOG_DEBUG);
				return true;
			}
		}
		else
		{
			AddLogEntry(L"more than 100h byte: %s", szFilePath, 0, true, LOG_DEBUG);
			DWORD dwBytesRead = 0;
			m_PEFile.OpenFile(szFilePath, false);
			
			if(m_PEFile.m_dwFileSize < 0x78)
			{
				m_PEFile.CloseFile();
				AddLogEntry(L"Less than 78h: %s", szFilePath,0, true, LOG_DEBUG);
				return false;
			}

			BYTE byBuffer[0x100];

			if(m_PEFile.ReadBuffer(byBuffer, 0, 0x100, 0x78, &dwBytesRead))
			{
				m_PEFile.CloseFile();
				int iFirstLineLen = 0;
				int iSpacCnt = 0x00;
				bool bIsSuspicious = false;
				for(DWORD i = 0; i < dwBytesRead; i++)
				{
					if(byBuffer[i] == 0x0D && byBuffer[i + 1] == 0x0A)
					{
						if(i < 2)
						{
							iFirstLineLen = 0;
							continue;
						}
						if(iFirstLineLen > 0x78)
							bIsSuspicious = true;
						
						break;
					}
					else if(byBuffer[i] == 0x27)
					{
						break;
					}
					else if(byBuffer[i] == 0x20)
					{
						iSpacCnt++;
						if(iSpacCnt > 0x09)
							break;
					}
					else if(iFirstLineLen == (dwBytesRead - 0x3) || iFirstLineLen == (dwBytesRead - 0x1))
					{
						bIsSuspicious = true;
						break;
					}
					iFirstLineLen++;
				}
				if(bIsSuspicious)
				{
					AddLogEntry(L"Suspiciou VBS by size: %s", szFilePath,0, true, LOG_DEBUG);
					return true;
				}
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IncrementSigCount
	In Parameters	: CQ2S& objSigDB, ULONG64 ulSignature, int iMaxCount
	Out Parameters	: true if sucess else false
	Purpose			: Internal function
	Author			: Tushar Kadam
	Description		: Add PE sig in array if match count greater than allowed limit
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::IncrementSigCount(CQ2S& objSigDB, ULONG64 ulSignature, int iMaxCount)
{
	LPTSTR szCount = ((LPTSTR)1);

	if(0 == ulSignature)
	{
		return false;
	}

	WaitForSingleObject(m_hEvent, INFINITE);

	if(objSigDB.SearchItem(ulSignature, szCount))
	{
		if(szCount)
		{
			TCHAR szNumber[50] = {0};
			int iCount = 0;

			iCount = _tcstol(szCount, 0, 10);
			iCount++;
			_stprintf_s(szNumber, _T("%i"), iCount);
			objSigDB.DeleteItem(ulSignature);
			objSigDB.AppendItem(ulSignature, szNumber);

			if(iCount >= iMaxCount)
			{
				SetEvent(m_hEvent);
				return true;
			}
		}
	}
	else
	{
		objSigDB.AppendItem(ulSignature, _T("1"));
	}

	SetEvent(m_hEvent);
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: AddSignatureToInstantScanner
	In Parameters	: CQ2S& objSigDB, ULONG64 ulSignature, int iMaxCount
	Out Parameters	: true if sucess else false
	Purpose			: Internal function
	Author			: Tushar Kadam
	Description		: Add PE sig in instancescan.ini if match count greater than allowed limit
--------------------------------------------------------------------------------------*/
void CPatternFileScanner::AddSignatureToInstantScanner(CQ2S& objDB, int iMaxCount, bool bCleanupDB)
{
	LPVOID lpContext = 0;
	ULONG64 ulSig = 0;
	LPTSTR szCount = 0;
	int iCount = 0;

	WaitForSingleObject(m_hEvent, INFINITE);

	lpContext = objDB.GetFirst();
	while(lpContext)
	{
		ulSig = 0;
		szCount = _T("");

		objDB.GetData(lpContext, szCount);
		if(szCount)
		{
			iCount = _tcstol_l(szCount, 0, 10, 0);
			if(iCount >= iMaxCount)
			{
				objDB.GetKey(lpContext, ulSig);
				WriteSignatureToIni(ulSig);
			}
			else
			{
				CString csLogStr;
				csLogStr.Format(_T("Sig Found: %i, Required: %i\n"), iCount, iMaxCount);
				AddLogEntry(csLogStr, 0, 0, true, LOG_DEBUG);
			}
		}

		lpContext = objDB.GetNext(lpContext);
	}

	if(bCleanupDB)
	{
		objDB.RemoveAll();
	}

	SetEvent(m_hEvent);
}

/*-------------------------------------------------------------------------------------
	Function		: WriteSignatureToIni
	In Parameters	: ULONG64 ulSignature
	Out Parameters	: true if sucess else false
	Purpose			: Internal function
	Author			: Tushar Kadam
	Description		: Write PE sig in instancescan.ini if match count greater than allowed limit
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::WriteSignatureToIni(ULONG64 ulSignature)
{
	bool bAlreadyPresent = false;
	TCHAR szCount[50] = {0}, szSignature[100] = {0}, szExistingSig[100] = {0};
	int iCount = 0;

	GetPrivateProfileString(_T("Signature"), _T("Count"), _T("0"), szCount, _countof(szCount), m_csInstScanIni);
	iCount = _tcstol(szCount, 0, 10);
	_stprintf_s(szSignature, _countof(szSignature), _T("%016I64X*NoFileName"), ulSignature);

	for(int i = 0; i < iCount; i++)
	{
		memset(szExistingSig, 0, sizeof(szExistingSig));
		_stprintf_s(szCount, _countof(szCount), _T("%i"), i);
		GetPrivateProfileString(_T("Signature"), szCount, _T(""), szExistingSig, _countof(szExistingSig), m_csInstScanIni);
		if(szExistingSig[0] && 0 == _tcsnicmp(szExistingSig, szSignature, 16))
		{
			bAlreadyPresent = true;
			break;
		}
	}

	if(!bAlreadyPresent)
	{
		iCount++;
		_stprintf_s(szCount, _countof(szCount), _T("%i"), iCount);
		WritePrivateProfileString(_T("Signature"), _T("Count"), szCount, m_csInstScanIni);
		WritePrivateProfileString(_T("Signature"), szCount, szSignature, m_csInstScanIni);
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ResolveVariablesAndDoubleQuotes
	In Parameters	: LPTSTR szFilePath, DWORD cchFilePathe
	Out Parameters	: true if sucess else false
	Purpose			: Internal function
	Author			: Tushar Kadam
	Description		: Normalize file path to physical path
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::ResolveVariablesAndDoubleQuotes(LPTSTR szFilePath, DWORD cchFilePath)
{
	CString csFilePath(szFilePath);

	csFilePath.MakeLower();
	if(m_csWinPath != _T(""))
	{
		csFilePath.Replace(L"%systemroot%\\", m_csWinPath);
		csFilePath.Replace(L"\\systemroot\\", m_csWinPath);
	}

	csFilePath.Replace(L"\\??\\", L"");
	if(m_csRootPath != _T(""))
	{
		csFilePath.Replace(L"%systemdrive%\\", m_csRootPath);
	}

	if(m_csPFDirPath != _T(""))
	{
		csFilePath.Replace(L"%programfiles%\\", m_csPFDirPath);
	}

	csFilePath.Trim(_T("\" "));
	if(_tcslen(csFilePath) >= cchFilePath)
	{
		return false;
	}

	_tcscpy_s(szFilePath, cchFilePath, csFilePath);
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ResolveBrowserShortcut
	In Parameters	: LPTSTR szFilePath, DWORD cchFilePathe
	Out Parameters	: true if sucess else false
	Purpose			: Internal function
	Author			: Tushar Kadam
	Description		: Retrives the file path information from broswer shortcut files (.LNK)
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::ResolveBrowserShortcut(LPCTSTR szShortcutFileName)
{
    HRESULT					hRes = E_FAIL;
    CComPtr<IShellLink>		ipShellLink = NULL ;
    TCHAR					szPath [ MAX_PATH ] = { 0 } ;
    TCHAR					szDesc [ MAX_PATH ] = { 0 } ;
    WIN32_FIND_DATA			wfd = { 0 } ;
    WCHAR					wszTemp [ MAX_PATH ] = { 0 } ;
	bool					bDirtyLnk = false;

	hRes = CoInitialize ( NULL ) ;

	// Get a pointer to the IShellLink interface
	hRes = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&ipShellLink);
	COCREATE_OUTPUTDEBUGSTRING(hRes);
	if ( FAILED ( hRes ) )
	{
		CoUninitialize() ;
		return ( false ) ;
	}

    // Get a pointer to the IPersistFile interface
    CComQIPtr<IPersistFile> ipPersistFile ( ipShellLink ) ;

    // IMP: IPersistFile is using LPCOLESTR, so make sure that the string is Unicode
    // Open the shortcut file and initialize it from its contents
    hRes = ipPersistFile -> Load ( szShortcutFileName , STGM_READ ) ;
    if ( FAILED ( hRes ) )
    {
        CoUninitialize() ;
        return ( false ) ;
    }

   	// Get the path to the shortcut target
	TCHAR		szArguments[MAX_PATH] = {0x00};
	int			cbArguments = MAX_PATH;
	
	hRes = ipShellLink->GetArguments(szArguments, cbArguments);
	
	HRESULT		hResTmp = E_FAIL;
	TCHAR		szExePath[MAX_PATH] = {0x00};
	int			cbPathLen = MAX_PATH;

	hResTmp = ipShellLink->GetPath(szExePath, cbPathLen, &wfd, SLGP_RAWPATH);
	_tcslwr(szExePath);
	if (_tcsstr(szExePath,_T("\\firefox.exe")) != NULL || _tcsstr(szExePath,_T("\\chrome.exe")) != NULL || _tcsstr(szExePath,_T("\\opera.exe")) != NULL || _tcsstr(szExePath,_T("\\iexplore.exe")) != NULL)		
	{
		if (_tcslen(szArguments) > 0x00)
		{
			bDirtyLnk = true;
			AddLnk2SpclCleanerList(szShortcutFileName);
		}
	}
	
	CoUninitialize() ;
	return bDirtyLnk;
}

/*-------------------------------------------------------------------------------------
	Function		: ResolveShortcut
	In Parameters	: LPCTSTR szShortcutFileName, LPTSTR szArguments, DWORD cbArguments, bool bGetArgs
	Out Parameters	: true if sucess else false
	Purpose			: Internal function
	Author			: Tushar Kadam
	Description		: Retrives the file path information from shortcut files (.LNK)
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::ResolveShortcut(LPCTSTR szShortcutFileName, LPTSTR szArguments, DWORD cbArguments, bool bGetArgs)
{
    HRESULT hRes = E_FAIL;
    CComPtr<IShellLink> ipShellLink = NULL ;
    TCHAR szPath [ MAX_PATH ] = { 0 } ;
    TCHAR szDesc [ MAX_PATH ] = { 0 } ;
    WIN32_FIND_DATA wfd = { 0 } ;
    WCHAR wszTemp [ MAX_PATH ] = { 0 } ;

	// Removed Coinit as this is already done in AuScanner
	hRes = CoInitialize ( NULL ) ;
	if (FAILED(hRes))
	{
		//AddLogEntry(L"RESPATH FAILED: %s", szShortcutFileName);
		return (false);
	}
	//COINITIALIZE_OUTPUTDEBUGSTRING(hRes);

	// Get a pointer to the IShellLink interface
	hRes = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&ipShellLink);
	COCREATE_OUTPUTDEBUGSTRING(hRes);
	if ( FAILED ( hRes ) )
	{
		//AddLogEntry(L"RESPATH FAILED: %s", szShortcutFileName);
		CoUninitialize() ;
		return ( false ) ;
	}

    // Get a pointer to the IPersistFile interface
    CComQIPtr<IPersistFile> ipPersistFile ( ipShellLink ) ;

    // IMP: IPersistFile is using LPCOLESTR, so make sure that the string is Unicode
    // Open the shortcut file and initialize it from its contents
    hRes = ipPersistFile -> Load ( szShortcutFileName , STGM_READ ) ;
    if ( FAILED ( hRes ) )
    {
	    CoUninitialize() ;
        return ( false ) ;
    }

    /*
    INFO: This was commented because if the file was moved or renamed a mesage window appears
          which needs a user response. This mesage windows hangs the special spyware scanning
          as the message box has come from service and is not viewable to the user.
    // Try to find the target of a shortcut, even if it has been moved or renamed
    hRes = ipShellLink -> Resolve ( NULL , SLR_UPDATE ) ;
    if ( FAILED ( hRes ) ) 
    {
        CoUninitialize() ;
        return ( false ) ;
    }
    */

	// Get the path to the shortcut target
	if(bGetArgs)
	{
		hRes = ipShellLink->GetArguments(szArguments, cbArguments);
	}
	else
	{
		hRes = ipShellLink->GetPath(szArguments, cbArguments, &wfd, SLGP_RAWPATH);

		ResolveVariablesAndDoubleQuotes(szArguments, cbArguments);
	
		_tcslwr_s(szArguments, cbArguments);
		if(_tcsstr(szArguments, _T("windows\\system32\\config\\systemprofile")))
		{
			CoUninitialize() ;
			return false;
		}

	}

	if ( FAILED ( hRes ) )
	{
		CoUninitialize() ;
		return ( false ) ;
	}

	CoUninitialize() ;
	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanLinkFile
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan shortcut files (.LNK)
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::ScanLinkFile(LPCTSTR szFilePath)
{
	CString csFullFilePath(szFilePath);
	CString csFileName;
	CString csArguments;
	TCHAR szFullCommandLine [ 512 ] = { 0x00 } ;
	bool bRet = false;

	csFullFilePath.MakeLower();
	if(csFullFilePath.Right(4) == _T(".lnk"))
	{
		csFullFilePath.Replace(_T(".lnk"),_T(""));
		int iPos = csFullFilePath.ReverseFind(_T('\\'));
		csFileName = csFullFilePath.Mid (iPos + 1);
		if(_waccess(csFullFilePath,0) != -1)
		{
			if(ResolveShortcut(szFilePath, szFullCommandLine, _countof(szFullCommandLine)))
			{
				if (_tcslen(szFullCommandLine) > 0x00)
				{
					csArguments = (CString)szFullCommandLine;
					csArguments.MakeLower();
					if (csArguments.Find(csFileName) != -1)
					{
						bRet = true;
					}
				}
			}
		}
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: KnownBlackPattern1
	In Parameters	: LPCTSTR szFilePath, bool bSigCreated, ULONG64 ulSignature, BYTE& byVerTabInfo
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan File for Pattern : Folder and File has same name
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::KnownBlackPattern1(LPCTSTR szFilePath, bool bSigCreated, ULONG64 ulSignature, BYTE& byVerTabInfo)
{
	DWORD dwAttributes = 0;
	bool bPickSig = false;
	TCHAR szFName[MAX_PATH] = {0}, szFolderPath[MAX_PATH] = {0};
	LPCTSTR szExtension = 0;
	LPTSTR szSlash = 0;

	szExtension = _tcsrchr(szFilePath, _T('.'));
	if(!szExtension)
	{
		return false;
	}

	if(!_tcsicmp(szExtension, _T(".exe")))
	{
		bPickSig = true;
	}
	else if(!_tcsicmp(szExtension, _T(".scr")))
	{
		bPickSig = true;
	}
	else if(!_tcsicmp(szExtension, _T(".lnk")))
	{
		bPickSig = false;
	}
	else
	{
		return false;
	}

	if(_tcslen(szFilePath) >= _countof(szFolderPath))
	{
		return false;
	}

	_tcscpy_s(szFolderPath, _countof(szFolderPath), szFilePath);
	szSlash = _tcsrchr(szFolderPath, _T('\\'));
	if(!szSlash)
	{
		return false;
	}

	*szSlash = 0;
	if(_tsplitpath_s(szFilePath, 0, 0, 0, 0, szFName, _countof(szFName), 0, 0))
	{
		return false;
	}

	if(0 == szFName[0])
	{
		return false;
	}

	TrimString(szFName);
	if(_tcslen(szFolderPath) + _tcslen(szFName) + 1 >= _countof(szFolderPath))
	{
		return false;
	}

	_tcscat_s(szFolderPath, _countof(szFolderPath), _T("\\"));
	_tcscat_s(szFolderPath, _countof(szFolderPath), szFName);

	dwAttributes = GetFileAttributes(szFolderPath);
	if(INVALID_FILE_ATTRIBUTES == dwAttributes)
	{
		return false;
	}

	if((dwAttributes & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY)
	{
		return false;
	}

	if(bPickSig && bSigCreated)
	{
		if(HasValidVersionTab(szFilePath, byVerTabInfo))
		{
			return false;
		}
		else
		{
			if(IncrementSigCount(m_objFileFolderSameLevel, ulSignature, MAX_FIL_FOLDER_SAME_LEVEL_COUNT))
			{
				return true;
			}
		}
	}

	if((dwAttributes & FILE_ATTRIBUTE_HIDDEN) != FILE_ATTRIBUTE_HIDDEN)
	{
		return false;
	}

	if(HasValidVersionTab(szFilePath, byVerTabInfo))
	{
		return false;
	}

	dwAttributes ^= FILE_ATTRIBUTE_SYSTEM;
	dwAttributes ^= FILE_ATTRIBUTE_HIDDEN;
	SetFileAttributes(szFolderPath, dwAttributes);
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: IsInvalidLink
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Validates file type shortcut (.LNK)
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::IsInvalidLink(LPCTSTR szFilePath)
{
	LPCTSTR szLastDot = NULL, szSlash = NULL;
	TCHAR szTragetFilePath[MAX_PATH] = {0};
	LPCTSTR szValidExtList[] = 
	{
		_T(".exe"),
		_T(".pif"),
		_T(".scr"),
		_T(".com")
	};

	szLastDot = _tcsrchr(szFilePath, _T('.'));
	if(!szLastDot)
	{
		return false;
	}

	if(_tcsicmp(szLastDot, _T(".lnk")))
	{
		return false;
	}

	szSlash = _tcschr(szFilePath, _T('\\'));
	if(!szSlash)
	{
		return false;
	}

	szSlash++;
	szSlash = _tcschr(szSlash, _T('\\'));
	if(szSlash)
	{
		return false;
	}

	if(!ResolveShortcut(szFilePath, szTragetFilePath, _countof(szTragetFilePath), false))
	{
		return false;
	}

	if(0 == szTragetFilePath[0])
	{
		LPCTSTR szFileName = _tcsrchr(szFilePath, _T('\\'));
		if(szFileName)
		{
			szFileName++;
			if(_T('z') == *szFileName)
			{
				szFileName += 3;
				if(!_tcsicmp(szFileName, _T(".lnk")))
				{
					return true;
				}
			}
			else if(!_tcsnicmp(szFileName, _T("Copy of Shortcut to ("), 21))
			{
				return true;
			}
		}

		return false;
	}

	if(_T(':') != szTragetFilePath[1])
	{
		return false;
	}

	szLastDot = _tcsrchr(szTragetFilePath, _T('.'));
	if(!szLastDot)
	{
		return false;
	}

	for(int i = 0; ; i++)
	{
		if(i >= _countof(szValidExtList))
		{
			return false;
		}
		else if(0 == _tcsicmp(szLastDot, szValidExtList[i]))
		{
			break;
		}
	}

	if(!_taccess_s(szTragetFilePath, 0))
	{
		memset(szTragetFilePath, 0, sizeof(szTragetFilePath));
		if(!ResolveShortcut(szFilePath, szTragetFilePath, _countof(szTragetFilePath), true))
		{
			return false;
		}

		if(0 == szTragetFilePath[0])
		{
			return false;
		}

		if(_T(':') == szTragetFilePath[1] && _T('\\') != szTragetFilePath[2])
		{
			AddLogEntry(L"ARGNOSLASH: %s", szTragetFilePath, 0, true, LOG_DEBUG);
			return true;
		}

		return false;
	}

	AddLogEntry(L"INVTARGET: %s", szTragetFilePath, 0, true, LOG_DEBUG);
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: IsSuspeciousLink
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: check for Suspicious shortcut (.LNK) file
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::IsSuspeciousLink(LPCTSTR szFilePath)
{
    HRESULT					hRes = E_FAIL;
    CComPtr<IShellLink>		ipShellLink = NULL ;
    TCHAR					szPath [ MAX_PATH ] = { 0 } ;
    TCHAR					szDesc [ MAX_PATH ] = { 0 } ;
    WIN32_FIND_DATA			wfd = { 0 } ;
    WCHAR					wszTemp [ MAX_PATH ] = { 0 } ;
	bool					bDirtyLnk = false;
	LPCTSTR					pszLastDot = NULL;

	pszLastDot = _tcsrchr(szFilePath, _T('.'));
	if(!pszLastDot)
	{
		return false;
	}

	if(_tcsicmp(pszLastDot, _T(".lnk")))
	{
		return false;
	}

	hRes = CoInitialize ( NULL ) ;

	//AddLogEntry(L"RAVI : INSIDE %s", szFilePath);

	// Get a pointer to the IShellLink interface
	hRes = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&ipShellLink);
	COCREATE_OUTPUTDEBUGSTRING(hRes);
	if ( FAILED ( hRes ) )
	{
		//AddLogEntry(L"RAVI : FAILED %s", szFilePath);
		CoUninitialize() ;
		return ( false ) ;
	}

    // Get a pointer to the IPersistFile interface
    CComQIPtr<IPersistFile> ipPersistFile ( ipShellLink ) ;

    // IMP: IPersistFile is using LPCOLESTR, so make sure that the string is Unicode
    // Open the shortcut file and initialize it from its contents
    hRes = ipPersistFile -> Load ( szFilePath , STGM_READ ) ;
    if ( FAILED ( hRes ) )
    {
		//AddLogEntry(L"RAVI : FAILED LOAD %s", szFilePath);
        CoUninitialize() ;
        return ( false ) ;
    }

   	// Get the path to the shortcut target
	TCHAR		szArguments[MAX_PATH] = {0x00};
	int			cbArguments = MAX_PATH;
	
	hRes = ipShellLink->GetArguments(szArguments, cbArguments);
	
	HRESULT		hResTmp = E_FAIL;
	TCHAR		szExePath[MAX_PATH] = {0x00};
	int			cbPathLen = MAX_PATH;

	hResTmp = ipShellLink->GetPath(szExePath, cbPathLen, &wfd, SLGP_RAWPATH);
	_tcslwr(szExePath);
	

	//AddLogEntry(L"RAVI : INFO %s [%s]", szExePath,szArguments);

	if (_tcslen(szArguments) >= 0x10 && _tcslen(szExePath) >= 0x05)
	{
		_tcslwr(szArguments);
		if (_tcsstr(szExePath,_T("\\cmd.exe")) != NULL)
		{
			if (_tcsstr(szArguments,_T(".bat")) != NULL && _tcsstr(szArguments,_T("explore")) != NULL && _tcsstr(szArguments,_T("\\program files")) == NULL)
			{
				bDirtyLnk = true;
			}
		}
	}
	
	CoUninitialize() ;
	return bDirtyLnk;
}

/*-------------------------------------------------------------------------------------
	Function		: KnownBlackName
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file with Rule : Suspicious file names
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::KnownBlackName(LPCTSTR szFilePath, ULONG64 ulSignature)
{
	CString csFullFilePath(szFilePath); //Added

	bool bNameMatched = false;
	CString csFilename, csExtension;
	TCHAR szFileName[MAX_PATH] = {0}, szExtension[MAX_PATH] = {0};
	bool	bAdd2InstanceScn = false;
	struct
	{
		LPCTSTR szFileName;
		LPCTSTR szExtension;
	}stBlackFileNames[] = 
	{
		{_T("System3_"), _T(".exe")},
		{_T("regsvr"), _T(".exe")},
		{_T("regsvr"), _T(".scr")},
		{_T("My Music"), _T(".lnk")},
		{_T("gphone"), _T(".exe")},				//added virus signature of gphone.exe
		{_T("khatra"), _T(".exe")},
		{_T("photo"), _T(".scr")},	
		{_T("photo"), _T(".exe")},
		{_T("WdsManPro"), _T(".exe")},
		{_T("0photo"), _T(".exe")},
		{_T("Images"), _T(".exe")},
		{_T("Images"), _T(".scr")},
		{_T("Key"), _T(".exe")},
		{_T("MsUpdate"), _T(".exe")},
		{_T(" ADMI"), _T(".exe")},
		{_T("1010"), _T(".exe")},
		{_T("505040"), _T(".exe")},
		{_T("505050"), _T(".exe")},
		{_T("252525"), _T(".exe")},
		{_T("NewFolder"), _T(".exe")},
		{_T("HealthAlert"), _T(".exe")},
		{_T("HealthAlert"), _T(".dll")},
		{_T("My Folder"), _T(".exe")},
		{_T("Svcchost"), _T(".exe")},
		{_T("tasksche"), _T(".exe")},
		{_T("tor"), _T(".exe")},
		{_T("New Folder"), _T(".exe")},
		{_T("photosa"), _T(".exe")},
		{_T("movies."), _T(".exe")},
		{_T("movies"), _T(".exe")},
		{_T("Temp"), _T(".exe")},
		{_T("xelag"), _T(".exe")},
		{_T("windefender"), _T(".exe")},
		{_T("download_manager"), _T(".exe")},
		{_T("Schosts"), _T(".exe")},
		{_T("thumb"), _T(".db")},
		{_T("database"), _T(".mdb")}
	};

	_tsplitpath_s(szFilePath, 0, 0, 0, 0, szFileName, _countof(szFileName), szExtension, _countof(szExtension));
	csFilename.Format(_T("%s"), szFileName);
	csFilename.TrimRight(_T(' '));
	csExtension.Format(_T("%s"), szExtension);
	csExtension.TrimRight(_T(' '));

	int		iNameLen = _tcslen(szFileName);
	TCHAR	szDummyName[MAX_PATH] = {0x00};

	_tcscpy_s(szDummyName,MAX_PATH,szFileName);
	_tcsupr(szDummyName);
	
	//For Handling //IMG001
	if((_T("") != csExtension) && (0 == _tcsicmp(csExtension, _T(".exe"))))
	{
		if (iNameLen == 0x06)
		{
			if (szDummyName[0x00] == 'I' && szDummyName[0x01] == 'M' && szDummyName[0x02] == 'G' && 
				(szDummyName[0x03] >= '0' && szDummyName[0x03] <= '9') && (szDummyName[0x04] >= '0' && szDummyName[0x04] <= '9') && (szDummyName[0x05] >= '0' && szDummyName[0x05] <= '9'))
			{
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);

				csFullFilePath.MakeUpper();
				csFullFilePath.Replace(szDummyName,L"");
				csFullFilePath.Replace(L".EXE",L"");

				DeleteFile(csFullFilePath + L"NsCpuCNMiner64.exe");
				DeleteFile(csFullFilePath + L"NsCpuCNMiner32.exe");
				DeleteFile(csFullFilePath+L"pools.txt");

				return true;
			}
			if (szDummyName[0x00] == 'V' && szDummyName[0x01] == 'I' && szDummyName[0x02] == 'D' && 
				(szDummyName[0x03] >= '0' && szDummyName[0x03] <= '9') && (szDummyName[0x04] >= '0' && szDummyName[0x04] <= '9') && (szDummyName[0x05] >= '0' && szDummyName[0x05] <= '9'))
			{
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);

				csFullFilePath.MakeUpper();
				csFullFilePath.Replace(szDummyName,L"");
				csFullFilePath.Replace(L".EXE",L"");

				DeleteFile(csFullFilePath + L"uihost64.exe");
				DeleteFile(csFullFilePath + L"uihost32.exe");
				DeleteFile(csFullFilePath+L"pools.txt");

				return true;
			}
		}

		//For Handling //SIMG001
		if (iNameLen == 0x07)
		{
			if (szDummyName[0x00] == 'S' && szDummyName[0x01] == 'I' && szDummyName[0x02] == 'M' && szDummyName[0x03] == 'G' && 
				(szDummyName[0x04] >= '0' && szDummyName[0x04] <= '9') && (szDummyName[0x05] >= '0' && szDummyName[0x05] <= '9') && (szDummyName[0x06] >= '0' && szDummyName[0x06] <= '9'))
			{
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);

				return true;
			}
			if (szDummyName[0x00] == 'I' && szDummyName[0x01] == 'M' && szDummyName[0x02] == 'G' && szDummyName[0x03] == '_' && 
				(szDummyName[0x04] >= '0' && szDummyName[0x04] <= '9') && (szDummyName[0x05] >= '0' && szDummyName[0x05] <= '9') && (szDummyName[0x06] >= '0' && szDummyName[0x06] <= '9'))
			{
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);

				return true;
			}
		}
	}

	int iBlackFileCount = _countof(stBlackFileNames);

	for(int i = 0; i < iBlackFileCount; i++)
	{
		if((_T("") != csFilename) && (0 == _tcsicmp(csFilename, stBlackFileNames[i].szFileName)))
		{
			if((_T("") != csExtension) && (0 == _tcsicmp(csExtension, stBlackFileNames[i].szExtension)))
			{
				//if (i == (iBlackFileCount - 0x03))
				if ( i>= 0x04)
				{
					bAdd2InstanceScn = true;
				}
				bNameMatched = true;
				break;
			}
		}
	}

	if(!bNameMatched)
	{
		return false;
	}
	if(0 != ulSignature)
	{
		if (bAdd2InstanceScn == true)
		{
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
		}
		else
		{
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
		}
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: KnownBlackPattern2
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file with Rule : Shortcut with same name (as file name) is present in same folder
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::KnownBlackPattern2(LPCTSTR szFilePath, ULONG64 ulSignature, BYTE& byVerTabInfo)
{
	CString csFilename, csFolder;
	LPCTSTR szExtension = 0;
	LPTSTR	szFolder = 0, szFileName = 0;
	int		iFolderLen = 0, iFileNameLen = 0;
	TCHAR	szDupFilePath[MAX_PATH] = {0};
	bool	bValidExtension = false;
	bool	bValidLnk = false;

	LPCTSTR szValidExtList[] = 
	{
		_T(".exe"),
		_T(".pif"),
		_T(".scr"),
		_T(".lnk"),
		_T(".com")
	};

	if(0 == ulSignature)
	{
		return false;
	}

	szExtension = _tcsrchr(szFilePath, _T('.'));
	if(!szExtension)
	{
		return false;
	}

	for(int i = 0; i < _countof(szValidExtList); i++)
	{
		if(!_tcsicmp(szExtension, szValidExtList[i]))
		{
			bValidExtension = true;
			break;
		}
	}

	if(!bValidExtension)
	{
		return false;
	}

	if(_tcslen(szFilePath) >= _countof(szDupFilePath))
	{
		return false;
	}

	_tcscpy_s(szDupFilePath, _countof(szDupFilePath), szFilePath);
	_tcslwr(szDupFilePath);

	if (_tcsstr(szDupFilePath,_T("\\tempfolder\\")) != NULL || _tcsstr(szDupFilePath,_T("\\temp\\")) != NULL)
	{
		return false;
	}

	if (_tcsstr(szDupFilePath,_T("\\start menu\\")) == NULL)
	{
		bValidLnk = true;
	}
	
	szFileName = _tcsrchr(szDupFilePath, _T('\\'));
	if(!szFileName)
	{
		return false;
	}

	*szFileName++ = _T('\0');
	szFolder = _tcsrchr(szFileName, _T('.'));
	if(!szFolder)
	{
		return false;
	}

	*szFolder = _T('\0');
	szFolder = _tcsrchr(szDupFilePath, _T('\\'));
	if(!szFolder)
	{
		return false;
	}

	szFolder++;
	csFolder.Format(_T("%s"), szFolder);
	csFilename.Format(_T("%s"), szFileName);
	csFolder.Trim(_T(' '));
	csFilename.Trim(_T(' '));

	if(_tcsicmp(csFolder, csFilename))
	{
		return false;
	}
	
	if(!_tcsicmp(szExtension, _T(".lnk")) && bValidLnk == true)
	{
		return true;
	}

	if(HasValidVersionTab(szFilePath, byVerTabInfo))
	{
		return false;
	}

	return IncrementSigCount(m_objFileInsideFolder, ulSignature, MAX_FILE_INSIDE_FOLDER_COUNT);
}

/*-------------------------------------------------------------------------------------
	Function		: ScanByLocation
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file with Rule : Suspicious Location 
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::ScanByLocation(LPCTSTR szFilePath)
{
	bool bValidExtension = false;
	int iSlashCount = 0;
	LPCTSTR szExtension = NULL, szPtr = NULL;
	LPCTSTR szValidExtList[] = 
	{
		_T(".exe"),
		_T(".pif"),
		_T(".scr"),
		_T(".com"),
		_T(".dll"),
		_T(".lnk")
	};

	if(0 == m_iDocAndSetPathLen)
	{
		return false;
	}

	if(_tcsnicmp(m_szDocAndSet, szFilePath, m_iDocAndSetPathLen))
	{
		return false;
	}

	szExtension = _tcsrchr(szFilePath, _T('.'));
	if(!szExtension)
	{
		return false;
	}

	for(int i = 0; i < _countof(szValidExtList); i++)
	{
		if(!_tcsicmp(szExtension, szValidExtList[i]))
		{
			bValidExtension = true;
			break;
		}
	}

	if(!bValidExtension)
	{
		return false;
	}

	for(szPtr = szFilePath + m_iDocAndSetPathLen; szPtr && *szPtr; szPtr++)
	{
		if(_T('\\') == *szPtr)
		{
			iSlashCount++;
		}
	}

	if(iSlashCount < 1)
	{
		return true;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForPDVDBVirus
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: 
	Description		: 
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::CheckForPDVDBVirus(LPCTSTR szFilePath)
{
	CString csFullFilePath(szFilePath);
	csFullFilePath.MakeLower();
	TCHAR szDummy[1024] = {0x00};


	_tcscpy_s(szDummy,1024, szFilePath);
	szDummy[3] = '\0';
	if(GetDriveType(szDummy) == 2)
	{
		if(csFullFilePath.Right(4) == _T(".vbs"))
		{
			if(csFullFilePath.Find(_T("\\"), 3) != -1)
			{
				return false;
			}
			else
			{
				CString csOnlyFileName= csFullFilePath.Mid(csFullFilePath.ReverseFind('\\')+1);
				if(csOnlyFileName == L"deviceconfigmanager.vbs")
				{
					return true;
				}
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForLNKFile
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file with Rule : LNK Rules
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::CheckForLNKFile(LPCTSTR szFilePath)
{
	CString csFullFilePath(szFilePath);
	csFullFilePath.MakeLower();
	TCHAR szDummy[1024] = {0x00};

	_tcscpy_s(szDummy,1024, szFilePath);
	szDummy[3] = '\0';
	if(GetDriveType(szDummy) == 2)
	{
		if(csFullFilePath.Right(4) == _T(".lnk"))
		{
			AddLogEntry(L"Got Removable drive: %s", szFilePath, 0, true, LOG_DEBUG);
			if(csFullFilePath.Find(_T("\\"), 3) != -1)
			{
				return false;
			}
			else
			{
				return true;
			}
		}
	}
	if(csFullFilePath.Find(_T("\\recycler\\")) == 2)
	{
		if(csFullFilePath.Right(4) == _T(".lnk"))
		{
			AddLogEntry(L"Got recycler path: %s", szFilePath, 0, true, LOG_DEBUG);
			if(csFullFilePath.Find(_T("\\"), 0x0C) != -1)
				return false;
			else
				return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: KnownBlackPattern3
	In Parameters	: LPCTSTR szFilePath, ULONG64 ulSignature, BYTE& byVerTabInfo
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file with Rule : 
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::KnownBlackPattern3(LPCTSTR szFilePath, ULONG64 ulSignature, BYTE& byVerTabInfo)
{
	TCHAR			*pszExtension = NULL;
	TCHAR			szDummyFilePath[512] = {0x00};
	bool			bValidExtension = false;
	
	LPCTSTR szValidExtList[] = 
	{
		_T(".exe"),
		_T(".pif"),
		_T(".scr"),
		_T(".com")
	};

	if(0 == ulSignature)
	{
		return false;
	}

	_tcscpy_s(szDummyFilePath,512,szFilePath);

	pszExtension = _tcsrchr(szDummyFilePath, _T('.'));
	if(!pszExtension)
	{
		return false;
	}

	for(int i = 0; i < _countof(szValidExtList); i++)
	{
		if(!_tcsicmp(pszExtension, szValidExtList[i]))
		{
			bValidExtension = true;
			break;
		}
	}

	if(!bValidExtension)
	{
		return false;
	}

	*pszExtension = '\0';
	pszExtension = NULL;

	pszExtension = _tcsrchr(szDummyFilePath, _T('.'));
	if (pszExtension == NULL)
	{
		return false;
	}

	if (PathFileExists(szDummyFilePath) == false)
	{
		return false;
	}

	DWORD dwAttributes = GetFileAttributes(szDummyFilePath);
	if((dwAttributes & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY)
	{
		return false;
	}
	
	bool	bIncreamented = IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
	if(HasValidVersionTab(szFilePath, byVerTabInfo))
	{
		return bIncreamented;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanByDirLocation
	In Parameters	: LPCTSTR szFilePath, ULONG64 ulSignature, BYTE& byVerTabInfo
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan file with Rule : Adware directory location
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::ScanByDirLocation(LPCTSTR szFilePath, ULONG64 ulSignature, BYTE& byVerTabInfo)
{
	TCHAR			*pszExtension = nullptr;
	TCHAR			szDummyFilePath[512] = {0x00};
	TCHAR			szFileNameOnly[512] = {0x00};	
	bool			bValidExtension = false;
	
	LPCTSTR szValidExtList[] = 
	{
		_T(".exe"),
		_T(".pif"),
		_T(".scr"),
		_T(".dmp"),
		_T(".com")
	};

	if(0 == ulSignature)
	{
		return false;
	}

	_tcscpy_s(szDummyFilePath,512,szFilePath);
	_tcslwr(szDummyFilePath);

	pszExtension = _tcsrchr(szDummyFilePath, _T('.'));
	if(!pszExtension)
	{
		return false;
	}

	for(int i = 0; i < _countof(szValidExtList); i++)
	{
		if(!_tcsicmp(pszExtension, szValidExtList[i]))
		{
			bValidExtension = true;
			break;
		}
	}

	if(!bValidExtension)
	{
		return false;
	}
	TCHAR			*pszFolderPath = nullptr;
	pszFolderPath = _tcsrchr(szDummyFilePath, _T('\\'));
	if(pszFolderPath == nullptr)
	{
		return false;
	}
	_tcscpy_s(szFileNameOnly,512,pszFolderPath);
	*pszFolderPath = '\0';
	
	pszFolderPath = nullptr;
	pszFolderPath = _tcsrchr(szDummyFilePath, _T('\\'));
	
	if(pszFolderPath == nullptr)
	{
		return false;
	}

	if (_tcsstr(pszFolderPath,_T("\\windowsupdate")) != nullptr)// || _tcsstr(pszFolderPath,_T("\\windows live")) != NULL) //Commeneted By Tushar to remove (+)ve
	{
		for(int iCount = 0x00; iCount < 0x05; iCount++)
		{
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
		}
		return true;
	}
	if (_tcsstr(pszFolderPath,_T("\\programdata")) != nullptr)// || _tcsstr(pszFolderPath,_T("\\windows live")) != NULL) //Commeneted By Tushar to remove (+)ve
	{
		if (_tcsstr(szFileNameOnly,_T("\\m")) != nullptr)
		{
			for(int iCount = 0x00; iCount < 0x05; iCount++)
			{
				IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			}
			return true;
		}
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: AddLnk2SpclCleanerList
	In Parameters	: LPCTSTR szFileLnkPath
	Out Parameters	: true if success else false
	Purpose			: Supportive functions
	Author			: Tushar Kadam
	Description		: List the repairable lnk file in INI file for SpecialSpywareScanner
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::AddLnk2SpclCleanerList(LPCTSTR szFileLnkPath)
{
	TCHAR		szOutPut[MAX_PATH] = {0x00};
	int			iLnkCount = 0x00;

	if(_tcslen(szFileLnkPath) == 0x00)
	{
		return false;
	}

	GetPrivateProfileString(_T("LNK2CLEAN"),_T("Count"),_T("0"),&szOutPut[0x00],MAX_PATH,m_csLnkScanIni);
	iLnkCount =  _tcstol(szOutPut, 0, 10);

	iLnkCount++;
	_stprintf(szOutPut,_T("%d"),iLnkCount);
	WritePrivateProfileString(_T("LNK2CLEAN"),_T("Count"),szOutPut,m_csLnkScanIni);
	WritePrivateProfileString(_T("LNK2CLEAN"),szOutPut,szFileLnkPath,m_csLnkScanIni);

	return true;
}

/*--------------------------------------------------------------------------------------------------
Function	:	ScanPriceLess
Author		:	Ramandeep (Virus Team)
Desription	:	Fnction handles the Throjan which on installation creates folders in <%PROGDIR%>
				with random names with following pattern
				1 : PRiceeLesse		2 : Priceless		3 : PriiceLess
				4 : CitThoePrice	5 :  bestadblocker   6 : Cinema_Plus.v2.1V11.07
--------------------------------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------------------------
Function	:	ScanPriceLess
Author		:	Ramandeep (Virus Team)
Desription	:	Fnction handles the Throjan which on installation creates folders in <%PROGDIR%>
				with random names with following pattern
				1 : PRiceeLesse		2 : Priceless		3 : PriiceLess
				4 : CitThoePrice	
Commented because code is moved to AdwarePatternScan file
--------------------------------------------------------------------------------------------------*/
//bool CPatternFileScanner::ScanPriceLess(LPCTSTR szFilePath)
//{
//	TCHAR	szFilePathTemp[MAX_PATH] = {0};
//	TCHAR	szParentFolderName[MAX_PATH] = {0};
//
//	TCHAR	*pTemp = NULL;
//
//	TCHAR	szBlackList[][40] = {
//		_T("\\dsrchlnk"),
//		_T("\\cthprc"), 
//		_T("\\prcls"),
//		_T("\\cnmplscv"), 
//		_T("\\grtsvu"), 
//		_T("\\nyprtctx"),
//		_T("\\hpysv"), 
//		_T("\\gmsdjp"), 
//		_T("\\grtsv"), 
//		_T("\\mnmprc"), 
//		_T("\\nzbrws"), 
//		_T("\\pgptp"), 
//		_T("\\slpls"), 
//		_T("\\svlt"), 
//		_T("\\svrxtnsn"),
//		_T("\\gmsdn"), 
//		_T("\\ctvdlscpntm"), 
//		_T("\\gmrsdsktp"),
//		_T("\\jncpn"),
//		_T("\\cnmplsvbrwsrxtnsnstl"),
//		_T("\\nrmsls"),
//		_T("\\syscpn"),
//		_T("\\bstdblckr"),
//		_T("\\cplsvbrwsrxtns"),
//		_T("\\ldysl"),		
//		_T("\\cnmpls"),
//		_T("\\hlthlrt"),
//		_T("wdsmnpr"),
//		_T("\\dblckr"),
//		_T("\\brkngnwslrt"),
//		_T("\\brwsrdfndr"),
//		_T("\\hlthlrt"),
//		_T("\\hprtctpdt"),
//		_T("\\lhpmpfcjpfjhjcdkpcmpflmpn"),
//		_T("\\gmsdsktp"),
//		_T("\\rgclnpr"),
//		_T("\\spdbtvdwnldr"),
//		_T("\\wntrntn"),
//		_T("\\mysrch"),
//		_T("\\ntngn"),
//		_T("\\spdbt"),
//		_T("\\trmnstlr"),
//		_T("\\txmpc"),
//		_T("\\wndwsmngrprtct"),
//		_T("\\wndwsprtctmngr"),
//		_T("\\ylwdblckr"),
//		_T("\\ytdvdwnldr"),
//		_T("\\btsvr"),
//		_T("\\spcsndpr"),
//		_T("\\spcsndprv"),
//		_T("\\plshdpv"),
//		_T("\\plshd"),
//		_T("\\hpysv"),
//		_T("\\cpxtnsn"),
//		_T("\\rlrcstrprk"),
//		_T("\\svps"),
//		_T("\\svsns"),
//		_T("\\dgcpn"),
//		_T("\\dscvrtrsr"),
//		_T("\\dnsnlckr"),
//		_T("\\lxtch"),
//		_T("\\fdntfr"),
//		_T("\\glblpdt"),
//		_T("\\skprtnrntwrk"),
//		_T("\\vgsfgrdtlbr"),
//		_T("\\vgscrsrch"),
//		_T("\\grntrplctns"),
//		_T("\\gplyr"),
//		_T("\\jgtmp"),
//		_T("\\mgclfnd"),
//		_T("\\mtcrwlr"),
//		_T("\\mnmmprc"),
//		_T("\\myscrpnk"),
//		_T("\\pybyds"),
//		_T("\\rydld"),
//		_T("\\srchprdct"),
//		_T("\\shpndsvp"),
//		_T("\\shprpr"),
//		_T("\\shprz"),
//		_T("\\snctrn"),
//		_T("\\spdbtvdwnldr"),
//		_T("\\thmsngjsnnspctr"),
//		_T("\\wntrntn"),
//		_T("\\wndwssrchqtlbr"),
//		_T("\\brkngnwslrt"),
//		_T("\\lpkhkcgmgkdglfnfnfhflk"),
//		_T("\\hlthlrt"),
//		_T("\\mlwrprtctnlv"),
//		_T("\\spdbrwsr"),
//		_T("\\mtcrwlr"),
//		_T("\\prcgng"),
//		_T("\\smrtwb"),
//		_T("\\spdbt"),
//		_T("\\wbprtctr"),
//		_T("\\nyprtctx"),
//		_T("\\lxtch"),
//		_T("\\mtcrwlr"),
//		_T("\\mystrtsrch"),
//		_T("\\pncndy"),
//		_T("\\rsrfng"),
//		_T("\\pcxvwr"),
//		_T("\\shrtctstr"),
//		_T("\\systwk"),
//		_T("\\wbxtnd"),
//		_T("\\wbsrchs"),
//		_T("\\pncndy"),
//		_T("\\skprtnrntwrk"),
//		_T("\\srchprtct"),
//		_T("\\smplfls"),
//		_T("\\shprpr"),
//		_T("\\spdbt"),
//		_T("\\bnsrchltd"),
//		_T("\\nyprtctx"),
//		_T("\\jgtmp"),
//		_T("\\prcmtér"),
//		_T("\\svsns"),
//		_T("\\spcsndpr"),
//		_T("\\vpckg"),
//		_T("\\mystrtsrch"),
//		_T("\\pncndy"),
//		_T("\\slvsft"),
//		_T("\\vpckg"),
//		_T("\\brwsrhlpr"),
//		_T("\\smrtwb"),
//		_T("\\systbyhtwhl"),
//		_T("\\smrtwb"),
//		_T("\\qyvd"),
//		_T("\\jgtmp"),
//		_T("\\mystrtsrch"),
//		_T("\\trvlchp"),
//		_T("\\rvlchp")
//					};
//	
//	_tcscpy_s(szFilePathTemp, MAX_PATH,szFilePath);
//	_tcslwr(szFilePathTemp);
//
//	//if((_tcsstr(szFilePathTemp,_T(":\\program files")) == NULL) && ( _tcsstr(szFilePathTemp,_T("\\appdata\\local")) == NULL)&&(_tcsstr(szFilePathTemp,_T(":\\programdata")) == NULL) && ( _tcsstr(szFilePathTemp,_T("\\application data")) == NULL))
//	if((_tcsstr(szFilePathTemp,_T(":\\program files")) == NULL) && ( _tcsstr(szFilePathTemp,_T("\\appdata\\local")) == NULL)&&(_tcsstr(szFilePathTemp,_T(":\\programdata")) == NULL) && ( _tcsstr(szFilePathTemp,_T("\\application data")) == NULL) && ( _tcsstr(szFilePathTemp,_T(":\\documents and settings\\all users\\application data")) == NULL)&& (_tcsstr(szFilePathTemp,_T("\\appdata\\roaming\\")) == NULL))
//	{
//				return false;
//	}
//
//	pTemp = _tcsrchr(szFilePathTemp, _T('\\'));
//	if (pTemp == NULL)
//	{
//		return false;
//	}
//
//	*pTemp = '\0';
//	pTemp = NULL;
//	
//	
//	pTemp = _tcsrchr(szFilePathTemp, _T('\\'));
//	if (pTemp == NULL)
//	{
//		return false;
//	}
//	
//	_tcscpy(szParentFolderName,pTemp);
//	//if (_tcsstr(szParentFolderName,_T("\\c")) == NULL && _tcsstr(szParentFolderName,_T("\\p")) == NULL)
//	//{
//	//	return false;
//	//}
//
//	TCHAR	szVowelList[MAX_PATH] = {0x00};
//	TCHAR	szNormalisedNm[MAX_PATH] = {0x00};
//	int		iLen = 0x00, kCnt = 0x00;
//	
//
//	pTemp = NULL;
//	_tcscpy(szVowelList,_T("aeiou"));
//	iLen = _tcslen(szParentFolderName);
//
//	for (int i = 0x00;  i < iLen; i++)
//	{
//		if(!((szParentFolderName[i] >= 0x61 && szParentFolderName[i] < 0x7B) || szParentFolderName[i] == 0x5C))
//		{
//			continue;
//		}
//		pTemp = _tcsrchr(szVowelList,szParentFolderName[i]);
//		if (pTemp != NULL)
//		{
//			pTemp = NULL;
//			continue;
//		}
//		if(kCnt > 0x00)
//		{
//			if (szNormalisedNm[kCnt - 0x01] == szParentFolderName[i])
//			{
//				continue;
//			}
//		}
//		szNormalisedNm[kCnt] = szParentFolderName[i];
//		kCnt++;
//	}
//	
//	//AddLogEntry(L"Parent Folder After Normalization : %s", szNormalisedNm);
//
//	if (szNormalisedNm[0x00] == 0x00)
//	{
//		return false;
//	}
//
//	int iLent=0x00;
//	iLent = _countof(szBlackList);
//	for(int j = 0x00; j < iLent; j++)
//	{
//		if (_tcsstr( szNormalisedNm,szBlackList[j]) != NULL)
//		{
//		return true;
//		}
//	}
//
//	return false;
//
//}

/*-------------------------------------------------------------------------------------
	Function		: ScanBestAddBlocker
	In Parameters	: LPCTSTR szFileLnkPath
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Scan File with Rule : "Best Add" Adware
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::ScanBestAddBlocker(LPCTSTR szFilePath)
{
	TCHAR	szFilePathTemp[MAX_PATH] = {0};
	TCHAR	szParentFolderName[MAX_PATH] = {0};
	TCHAR	*pTemp = NULL;
	
	_tcscpy_s(szFilePathTemp, MAX_PATH,szFilePath);
	_tcslwr(szFilePathTemp);

	if(_tcsstr(szFilePathTemp,_T(":\\program files")) == NULL)
	{
		return false;
	}

	pTemp = _tcsrchr(szFilePathTemp, _T('\\'));
	if (pTemp == NULL)
	{
		return false;
	}

	pTemp++;
	*pTemp = '\0';
	pTemp = NULL;
	
	if (_tcsstr(szFilePathTemp,_T("\\bestadblocker\\")) != NULL)
	{
		return true;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: Scan_G_FilePattern
	In Parameters	: LPCTSTR szFilePath, ULONG64 ulSignature
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: G File Pattern
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::Scan_G_FilePattern(LPCTSTR szFilePath, ULONG64 ulSignature)
{
	TCHAR	szFilePathTemp[MAX_PATH] = {0};
	TCHAR	*pszFileExt = NULL;

	_tcscpy_s(szFilePathTemp, MAX_PATH,szFilePath);
	_tcslwr(szFilePathTemp);

	pszFileExt = _tcsrchr(szFilePathTemp,'\\');
	if (pszFileExt != NULL)
	{
		if (_tcsstr(pszFileExt,L"\\g") != NULL && _tcsstr(pszFileExt,L".tmp.exe") != NULL && _tcslen(szFilePathTemp) == 0x0E)
		{
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			return true;
		}
	}
	return false;
}

/*--------------------------------------------------------------------------------------------------
Function	:	ScanPluginContainer
Author		:	Ramandeep (Virus Team)
Description	:	Function handles the Trojan which on installation creates random named
                        folders in ProgramData folder contaning folder and exe's  named PluginContainer + Plugins.
Note            :       
--------------------------------------------------------------------------------------------------*/
bool CPatternFileScanner::ScanPluginContainer(LPCTSTR szFilePath)
{
	TCHAR	szFilePathTemp[MAX_PATH] = {0};
	TCHAR	szParentFolderName[MAX_PATH] = {0};
	TCHAR   szDeleteFolderName[MAX_PATH] = {0};
	TCHAR	*pTemp = NULL;
	TCHAR	*pTemp1 = NULL;

	_tcscpy_s(szFilePathTemp, MAX_PATH,szFilePath);
	_tcslwr(szFilePathTemp);

	if((_tcsstr(szFilePathTemp,_T(":\\programdata")) == NULL) && ( _tcsstr(szFilePathTemp,_T(":\\documents and settings\\all users\\application data")) == NULL) )
	{
		return false;
	}


	_tcscpy_s(szParentFolderName, MAX_PATH,szFilePathTemp);

	for(int i=0;i<=1;i++)
	{
		if(i==1)
		{
			*pTemp1 = '\0';

		}

		pTemp1 = _tcsrchr(szParentFolderName, _T('\\'));
		if (pTemp1 == NULL)
		{
			return false;
		}
	}


	pTemp = _tcsrchr(szFilePathTemp, _T('\\'));
	if (pTemp == NULL)
	{
		return false;
	}


	if((_tcsstr(pTemp,_T("\\plugincontainer.")) != NULL) && (_tcsstr(pTemp1,_T("\\plugincontainer")) == NULL) )
	{
		return true;
	}
	*pTemp = '\0';
	pTemp = NULL;	

	pTemp = _tcsrchr(szFilePathTemp, _T('\\'));
	if (pTemp == NULL)
	{
		return false;
	}
	if((_tcsstr(pTemp,_T("\\plugincontainer")) != NULL)&&(_tcsstr(pTemp1,_T("\\plugincontainer")) != NULL))
	{

		////////////////////////code for removing Plugins folder that accompanies PluginContainer folder////////////////////////////////
		*pTemp = '\0';
		pTemp = NULL;
		memset ( (void *)&szParentFolderName, '\0', sizeof(TCHAR) * MAX_PATH);
		_tcscpy_s(szParentFolderName, MAX_PATH,szFilePathTemp);
		wcscat_s(szFilePathTemp, MAX_PATH,_T("\\plugins\\"));
		wcscat_s(szParentFolderName, MAX_PATH,_T("\\plugins\\*"));
		_tcscpy_s(szDeleteFolderName, MAX_PATH,szParentFolderName);

		memcpy(szDeleteFolderName + _tcslen(szDeleteFolderName), "\0\0\0\0", 4);

		if(PathFileExists(szFilePathTemp))
		{	
			SHFILEOPSTRUCT file_op = {
				NULL,
				FO_DELETE,
				szDeleteFolderName,
				NULL,
				FOF_NOCONFIRMATION |FOF_NOERRORUI |FOF_SILENT,
				false,
				NULL,
				NULL
			};
			int ret = SHFileOperation(&file_op);

		}

		/////////////////end of plugin removal//////////////////////////////////////

		return true;  //remove plugin container exe after removal of plugins folder
	}
	return false;	

}

/*--------------------------------------------------------------------------------------------------
Function	:	DetectValidGUID
Author		:	Ramandeep (Virus Team)
Description	:	Remove GUID from Program Data			
--------------------------------------------------------------------------------------------------*/
bool CPatternFileScanner::DetectBadGuid(LPCTSTR szFilePath)
{
	TCHAR	szFilePathTemp[MAX_PATH] = {0};
	TCHAR	szParentFolderName[MAX_PATH] = {0};
	TCHAR   szDeleteFolderName[MAX_PATH] = {0};
	TCHAR	*pTemp = nullptr;
	TCHAR	*pTemp1 = nullptr;


	_tcscpy_s(szFilePathTemp, MAX_PATH, szFilePath);
	_tcslwr(szFilePathTemp);


	if((_tcsstr(szFilePathTemp,_T(":\\programdata")) == nullptr)&& (_tcsstr(szFilePathTemp,_T(":\\program files")) == nullptr))
	{
		return false;
	}

	_tcscpy_s(szParentFolderName, MAX_PATH,szFilePathTemp);

	for(int i=0;i<=1;i++)
	{
		if(i==0)
		{
			pTemp1 = _tcschr(szParentFolderName, _T('\\'));
			*pTemp1++;
		}
		else
		{
			pTemp1 = _tcschr(pTemp1, _T('\\'));
		}
		if (pTemp1 == nullptr)
		{
			return false;
		}

	}
	*pTemp1++;
	pTemp1 = _tcschr(pTemp1, _T('\\'));
	if (pTemp1 == nullptr)
	{
		return false;
	}
	*pTemp1 = 0;

	pTemp1 = _tcsrchr(szParentFolderName, _T('\\'));
	if (pTemp1 == nullptr)
	{
		return false;
	}
	*pTemp1++;

	_tcscpy_s(szParentFolderName, MAX_PATH,  pTemp1);


	TCHAR	szExclusionList[MAX_PATH] = {0x00};
	TCHAR	szNormalisedNm[MAX_PATH] = {0x00};
	int		iLen = 0x00, kCnt = 0x00;


	pTemp = NULL;
	_tcscpy_s(szExclusionList,MAX_PATH,_T("{-}"));
	iLen = _tcslen(szParentFolderName);

	for (int i = 0x00;  i < iLen; i++)
	{

		pTemp = _tcsrchr(szExclusionList,szParentFolderName[i]);
		if (pTemp != nullptr)
		{
			pTemp = nullptr;
			continue;
		}
		szNormalisedNm[kCnt] = szParentFolderName[i];
		kCnt++;
	}

	if (szNormalisedNm[0x00] == 0x00)
	{
		return false;
	}
	iLen=_tcslen(szNormalisedNm);

	if ( iLen!= 32 && iLen!= 38)
	{
		return false;//The length doesn't match after removing - and braces should be 32.
	}
	for(int i=0;i<=iLen-1;i++)
	{

		if (isxdigit(szNormalisedNm[i]) == false)
		{
			return false;
		}
	}	
	return true;	

}


/*--------------------------------------------------------------------------------------------------
Function	:	DeleteBadFolder
Author		:	Ramandeep (Virus Team)
Desription	:	Delete the folder which is malicious.
--------------------------------------------------------------------------------------------------*/
int CPatternFileScanner::DeleteBadFolder(LPCTSTR szParentFolderName)
{
	TCHAR   szDeleteFolderName[MAX_PATH] = {0};
	_tcscpy_s(szDeleteFolderName, MAX_PATH,szParentFolderName);
	memcpy(szDeleteFolderName + _tcslen(szDeleteFolderName), "\0\0\0\0", 4);
	if(PathFileExists(szParentFolderName))
	{	
		SHFILEOPSTRUCT file_op = {
			NULL,
			FO_DELETE,
			szDeleteFolderName,
			NULL,
			FOF_NOCONFIRMATION |FOF_NOERRORUI |FOF_SILENT,
			false,
			NULL,
			NULL
		};
		int ret = SHFileOperation(&file_op);
		return ret;

	}
	return 0;
}

/*--------------------------------------------------------------------------------------------------
Function	:	CheckForWrongExecutionLocation
Author		:	Tushar (Virus Team)
Desription	:	Checks for wrong path of system files. 
				E.g. : If Winlogon.exe is present in appdata folder then its Trojan.
				(Found case with Folder Icon Trojans).
--------------------------------------------------------------------------------------------------*/
bool CPatternFileScanner::CheckForWrongExecutionLocation(LPCTSTR pszPath2Check, ULONG64 ulSignature)
{
	BOOL	bRet = FALSE;

	if (_tcslen(pszPath2Check) == 0x00)
	{
		return bRet;
	}
		
	TCHAR		szFileNameOnly[MAX_PATH] = {0};
	TCHAR		szFolderPath[MAX_PATH] = {0};
	TCHAR		*ptrW =  NULL;

	_stprintf(szFolderPath,L"%s",pszPath2Check);
	_tcslwr(szFolderPath);

	if (_tcsstr(szFolderPath,L":\\windows\\"))
	{
		return bRet;
	}

	ptrW = _tcsrchr(szFolderPath,'\\');

	if (ptrW == NULL)
	{
		return bRet;
	}

	_stprintf_s(szFileNameOnly,MAX_PATH,L"%s",ptrW);
	*ptrW = '\0';

	//if (_tcsstr(L"\\lsass.exe;\\smss.exe;\\winlogon.exe;\\services.exe;\\svchost.exe;\\csrss.exe",szFileNameOnly))
	if (_tcsstr(L"\\winlogon.exe;",szFileNameOnly))
	{
		if (_tcsstr(szFolderPath,L"\\windows\\") || _tcsstr(szFolderPath,L"\\system32\\"))
		{
			return bRet;
		}
		else
		{
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			IncrementSigCount(m_objBlackFileNames, ulSignature, MAX_BLACK_FILE_NAMES_COUNT);
			return TRUE;
		}
	}

	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: RandomNamePatternLoad
	In Parameters	: LPCTSTR szDBPath
	Out Parameters	: true if Load else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Load Dll for detecting Random Name Patterns
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::RandomNamePatternLoad(LPCTSTR szDBPath)
{
	bool bRetValue = false;

	if(m_bRandomDllLoaded)
	{
		bRetValue = true;
	}
	else
	{
		//m_bRandomDllLoaded = m_objMaxRandomPattern.InitializeScanner(m_csRandPatDBPath, true);
		
		m_hRandomNamePatternScn = LoadLibrary(L"AuRandPattern.dll");
		if(m_hRandomNamePatternScn)
		{
			m_lpfnRandomNameScan = (LPFN_NameScanPattern)GetProcAddress(m_hRandomNamePatternScn,"ScanPattern");
			m_lpfnScanFileLess = (LPFN_ScanFileLess)GetProcAddress(m_hRandomNamePatternScn,"ScanFileLessMalware");
			m_lpfnRandomNameLoadDB = (LPFN_NameLoadDB)GetProcAddress(m_hRandomNamePatternScn,"LoadDB");
			m_lpfnRandomNameUnLoadDB = (LPFN_UnLoadDB)GetProcAddress(m_hRandomNamePatternScn,"UnLoadDB");
			if(m_lpfnRandomNameScan == NULL || m_lpfnRandomNameLoadDB == NULL || m_lpfnRandomNameUnLoadDB == NULL || m_lpfnScanFileLess == NULL)
			{
				bRetValue = false;
			}
			else
			{
				bRetValue = true;
				//m_bRandomDllLoaded = m_objMaxRandomPattern.InitializeScanner(m_csRandPatDBPath, true);
				m_bRandomDllLoaded = m_lpfnRandomNameLoadDB(m_szRandPatDBPath);
			}
		}
	}
	return bRetValue;
}
bool CPatternFileScanner::FileLessMalScanner(LPCTSTR szFilePath)
{
	bool	bRetStatus = false;
	if(!m_bRandomDllLoaded)
	{
		return bRetStatus;
	}
	bool bResult =	m_lpfnScanFileLess(szFilePath);
	if(bResult)
	{
		bRetStatus = true;
	}
	return bRetStatus;

}
/*-------------------------------------------------------------------------------------
	Function		: RandomNamePatternScanner
	In Parameters	: LPTSTR szFilePath
	Out Parameters	: true Random Folder pattern match if Load else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detecting Random Name Patterns for folder and files
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::RansomwareCleanUP(LPCTSTR szFilePath)
{
	bool	bRetStatus = false;
	TCHAR	szFileExtenssion[MAX_PATH] = {0x00};
	TCHAR	*pszTemp = NULL;
	//CString	csLog;

	//.adame.adobe.armage.banta.barak.blackrouter.boom.bora.bot.buran.coot.crypt.derp.dharma.djvu.dqb.dridex.ency.emoted.encrypted.jmed.karl.katusha.kraken.leto.litar.lokf.lotej.mabuxhsa (strange_antefrigus).masodas.maze.meka.mockba.money.mosok.mosk.nakw.nemty.nesa.newrar.nols.nvram.phoenix.pkxlpk (strange_antefrigus).plauge17.rayuk.righ.tfflowre.toec.tro.viro.wallet.whycry.wiki.windows.yarraq.yyto.zero.zobm.roger

	pszTemp = _tcsrchr((LPTSTR)szFilePath,L'.');
	if (pszTemp == NULL)
	{
		return bRetStatus;
	}

	if (_tcslen(pszTemp) > MAX_PATH)
	{
		return bRetStatus;	
	}

	_tcscpy(szFileExtenssion,pszTemp);
	_tcslwr(szFileExtenssion);

	CString csFileExt(szFileExtenssion);
	csFileExt = csFileExt+ L".";

	if (m_csRansExtList.Find(csFileExt) != -1)
	 {
		bRetStatus = true;
	 }

	return bRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: RandomNamePatternScanner
	In Parameters	: LPTSTR szFilePath
	Out Parameters	: true Random Folder pattern match if Load else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detecting Random Name Patterns for folder and files
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::RandomNamePatternScanner(LPCTSTR szFilePath)
{
	bool	bRetStatus = false;
	if(!m_bRandomDllLoaded)
	{
		return bRetStatus;
	}
	if(m_lpfnRandomNameScan == NULL)
	{
		return bRetStatus;
	}
	//CString csFilePath(szFilePath);
	
	bool bResult =	m_lpfnRandomNameScan((TCHAR *)szFilePath);
	if(bResult)
	{
		bRetStatus = true;
	}
	else
	{
		bRetStatus = false;
	}

	return bRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: RandomNamePatternUnLoad
	In Parameters	: Void
	Out Parameters	: true if Load else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: UnLoad Dll for detecting Random Name Patterns
--------------------------------------------------------------------------------------*/
bool CPatternFileScanner::RandomNamePatternUnLoad()
{
	if(m_bRandomDllLoaded && m_hRandomNamePatternScn != NULL)
	{
		if(m_lpfnRandomNameUnLoadDB != NULL)
		{
			m_lpfnRandomNameUnLoadDB();
		}
		FreeLibrary(m_hRandomNamePatternScn);
		m_hRandomNamePatternScn = NULL;
		m_lpfnRandomNameScan = NULL;
		m_lpfnScanFileLess = NULL;
		m_lpfnRandomNameLoadDB = NULL;
		m_lpfnRandomNameUnLoadDB = NULL;
	}
	m_bRandomDllLoaded = false;
	return true;
}