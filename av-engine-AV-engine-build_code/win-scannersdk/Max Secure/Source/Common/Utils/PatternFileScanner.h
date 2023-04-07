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

#pragma once
#include "Q2S.h"
#include "S2U.h"
#include "VerInfo.h"
#include "MaxPEFile.h"

#define MAX_BLACK_FILE_NAMES_COUNT			5
#define MAX_FIL_FOLDER_SAME_LEVEL_COUNT		5
#define MAX_FILE_INSIDE_FOLDER_COUNT		5

/*=====================================================================================
IMPORTANT NOTE
1 : IF THERE ARE ANY CHANGES IN PATTERN SCANNER, MAKE SURE THAT VERSION IS INCREAMENTED
2 : VERSION BASE SHOULD BE 300000000
3 : IF VERSION IS NOT INCREAMENTED AND LOCAL DB IS PRESENT THEN PATTERN SCAN WILL GET SKIPED 
======================================================================================*/
#define MAX_PATTERN_SCAN_VERSION			300000016 
/*=====================================================================================
VERSION NOTE
300000001 : Date 20 May 2016 : Base Version for New Local DB Structure
300000002 : Date 23 Jun 2016 : 1 : Added New Pattern "CheckForWrongExecutionLocation" 
							   2 : Removed Entry of Black Folder Name "\\Delta"	
300000003 : Date 05 Jan 2017 : 1 : Added New Pattern in "ScanByDirLocation" function 
									to Handle big size \\programdata trojan
300000004 : Date 24 Mar 2017 : 1 : 
300000005 : Date 25 Apr 2017 : 1 : Changes for Movies..exe
300000006 : Date 10 May 2017 : 1 : Added new pattern multiplug adware
300000008 : Date 27 Jul 2017 : 08 : Added new pattern adware (Alisha)
300000009 : Date 06 Sept2017 : 09 : Changes in Scan4ExeConfigPattern (Tushar)
300000010 : Date 11 Nov 2017 : 10 : Changes in TaskHost Scanner (Alisha)
300000011 : Date 27 Nov 2017 : 11 : Changes in TaskHost Scanner (Alisha) For x64 OS
300000012 : Date 08 Feb 2018 : 12 : Added new Pattern : g******.tmp.exe
300000013 : Date 28 Feb 2018 : 13 : Changes Handling of Taskhost
300000013 : Date 04 Apr 2018 : 14 : New Adware Patterns (1.0.2.87)
300000013 : Date 26 Apr 2018 : 15 : Changes Handling of Taskhost + Handling of Adware Pattern (1.0.2.88)
300000015 : Date 18 Jan 2018 : 15 : Pattern detection by Jay Prakash (1.0.3.07)
======================================================================================*/

typedef bool (*LPFN_ScanFileByPattern)(LPCTSTR szFilePath, bool bSigCreated, ULONG64 ulSignature, BYTE& byVerTabInfo, DWORD dwLocalDBVer);
typedef DWORD (*LPFN_GetPatterScanVersion)();
typedef bool (* LPFN_NameScanPattern) (TCHAR*);	
typedef bool (* LPFN_NameLoadDB) (TCHAR*);	
typedef bool (* LPFN_UnLoadDB)();
typedef int (*LPFN_ScanFileLess)(LPCTSTR szFilePath);

class CPatternFileScanner
{
public:

	CPatternFileScanner();
	~CPatternFileScanner();
	bool	ScanFile(LPCTSTR szFilePath, bool bSigCreated, ULONG64 ulSignature, BYTE& byVerTabInfo, DWORD dwLocalDBVer = 0x00);
	bool	ScanFileByPattern(LPCTSTR szFilePath, bool bSigCreated, ULONG64 ulSignature, BYTE& byVerTabInfo, DWORD dwLocalDBVer = 0x00);
	DWORD	GetCurrentVersion();
	DWORD	GetCurrentPatVersion();
	bool	RandomNamePatternLoad(LPCTSTR szDBPath);
	bool	FileLessMalScanner(LPCTSTR szFilePath);
	bool	RandomNamePatternScanner(LPCTSTR szFilePath);
	bool	RansomwareCleanUP(LPCTSTR szFilePath);
	bool	RandomNamePatternUnLoad();

	CString		m_csRansExtList; 
private:
	CQ2S		m_objBlackFileNames;
	CQ2S		m_objFileFolderSameLevel;
	CQ2S		m_objFileInsideFolder;
	CS2U		m_objExcludePath;
	TCHAR		m_chDrive;
	CString		m_csInstScanIni;
	CString		m_csPattScanIni;
	bool		m_bExcludeDBReady;
	CString		m_csWinPath;
	CString		m_csRootPath;
	CString		m_csPFDirPath;
	CFileVersionInfo	m_objVerInfo;
	HMODULE		m_hDBScan;
	LPFN_ScanFileByPattern		m_lpfnScanFileByPattern;
	LPFN_GetPatterScanVersion	m_lpfnGetPatterScanVersion;
	TCHAR		m_szDocAndSet[MAX_PATH];
	int			m_iDocAndSetPathLen;
	HANDLE		m_hEvent;
	CMaxPEFile	m_PEFile;
	CString		m_csUSBDrives;
	CString		m_csNonRemovableDrives;
	bool		m_bIsUSBFile;
	CString		m_csLnkScanIni;
	TCHAR		m_szRandPatDBPath[MAX_PATH];

	// scanner logic functions
	bool ScanLinkFile(LPCTSTR szFilePath);
	bool KnownBlackPattern1(LPCTSTR szFilePath, bool bSigCreated, ULONG64 ulSignature, BYTE& byVerTabInfo);
	bool IsInvalidLink(LPCTSTR szFilePath);
	bool IsSuspeciousLink(LPCTSTR szFilePath); //Tushar : 17 Jan 2017 for handling sus shortcuts
	bool KnownBlackName(LPCTSTR szFilePath, ULONG64 ulSignature);
	bool KnownBlackPattern2(LPCTSTR szFilePath, ULONG64 ulSignature, BYTE& byVerTabInfo);
	bool ScanByLocation(LPCTSTR szFilePath);
	bool ScanByDirLocation(LPCTSTR szFilePath, ULONG64 ulSignature, BYTE& byVerTabInfo);
	bool ScanPriceLess(LPCTSTR szFilePath); //Ramandeep : 15 Jul 2015
	bool ScanBestAddBlocker(LPCTSTR szFilePath); //Tushar : 15 Jul 2015
	bool ScanPluginContainer(LPCTSTR szFilePath);//Ramandeep : 15 Sept2015
	bool Scan_G_FilePattern(LPCTSTR szFilePath, ULONG64 ulSignature);//Sneha + Swapnil : 08 Feb 2018

	void InitExcludeIni();
	void TrimString(LPTSTR szString);
	bool IsExcluded(LPCTSTR szFilePath);
	bool HasValidVersionTab(LPCTSTR szFilePath, BYTE& byVerTabInfo);
	bool WriteSignatureToIni(ULONG64 ulSignature);
	bool GetDocAndSet(LPTSTR szDocAndSetPath, DWORD cchDocAndSetPath);
	void AddSignatureToInstantScanner(CQ2S& objDB, int iMaxCount, bool bCleanupDB);
	bool IncrementSigCount(CQ2S& objSigDB, ULONG64 ulSignature, int iMaxCount);
	bool ResolveShortcut(LPCTSTR szShortcutFileName, LPTSTR szArguments, DWORD cbArguments, bool bGetArgs = true);
	bool ResolveVariablesAndDoubleQuotes(LPTSTR szFilePath, DWORD cchFilePath);
	bool CheckForVBSFile(LPCTSTR szFilePath);
	bool BlackPtnByFileName(LPCTSTR szFilePath);
	bool CheckForLNKFile(LPCTSTR szFilePath);
	bool CheckForPDVDBVirus(LPCTSTR szFilePath);
	bool KnownBlackPattern3(LPCTSTR szFilePath, ULONG64 ulSignature, BYTE& byVerTabInfo);

	bool AddLnk2SpclCleanerList(LPCTSTR szFileLnkPath);
	bool ResolveBrowserShortcut(LPCTSTR szShortcutFileName);
	bool DetectBadGuid(LPCTSTR szFilePath);
	int DeleteBadFolder(LPCTSTR szParentFolderName);
	bool ScanHardcodedPathAndFolderName(LPCTSTR szFilePath);
	//bool ScanForInvalidFileVersion(LPCTSTR szFilePath);			// Moved to poly virus

	bool CheckForWrongExecutionLocation(LPCTSTR pszPath2Check, ULONG64 ulSignature);

	HMODULE m_hRandomNamePatternScn;
	LPFN_ScanFileLess m_lpfnScanFileLess;//FILELESSSCN
	LPFN_NameScanPattern m_lpfnRandomNameScan;
	LPFN_NameLoadDB m_lpfnRandomNameLoadDB;
	LPFN_UnLoadDB m_lpfnRandomNameUnLoadDB;
	bool m_bRandomDllLoaded;
	//CMaxRandomPattern m_objMaxRandomPattern;

	
};
