/*======================================================================================
   FILE				: BaiduWorm.Cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware BaiduWorm
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Prashant Mandhare
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	:15/2/2010 
   NOTE				:
   VERSION HISTORY	:

========================================================================================*/

#include "pch.h"
#include "BaiduWorm.h"
#include "io.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and remove BaiduWorm Search Assistant
	Author			: 
	Description		: remove BaiduWorm entries from system32 and windows folders
--------------------------------------------------------------------------------------*/
bool CBaiduWorm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		ScanBaiduFiles(bToDelete);
		ScanDesktopLinks(bToDelete);
		ScanRegistryRandomKeys(bToDelete);
		ScanCommonLocations(bToDelete);

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		return m_bSplSpyFound ;
	}

	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in CBaiduWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanBaiduFiles
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: Checks and remove Baidu Worm
	Author			: Anand Srivastava
	Description		: scan for a list of files and folders
--------------------------------------------------------------------------------------*/
bool CBaiduWorm::ScanBaiduFiles(bool bToDelete)
{
	TCHAR szWinPath[MAX_PATH] = {0};
	CStringArray csFilesList;

	if(IsStopScanningSignaled())
	{
		return false;
	}

	csFilesList.Add(_T("X:\\WINDOWS\\ALI.EXE"));
	csFilesList.Add(_T("X:\\WINDOWS\\system32\\drivers\\BDGuard.SYS"));
	csFilesList.Add(_T("X:\\WINDOWS\\system32\\BDGuard.DAT"));
	csFilesList.Add(_T("X:\\WINDOWS\\system32\\BDGuardS.DAT"));
	csFilesList.Add(_T("X:\\Program Files\\baidu\\bar\\baidubar.dat"));
	csFilesList.Add(_T("X:\\Program Files\\baidu\\bar\\bdgdins.dll"));
	csFilesList.Add(_T("X:\\Program Files\\baidu\\bar\\BaiduBar.dll"));
	csFilesList.Add(_T("X:\\Program Files\\baidu\\bar\\img\\imglist.bmp"));
	csFilesList.Add(_T("X:\\Program Files\\baidu\\bar\\img\\logo.bmp"));
	csFilesList.Add(_T("X:\\Program Files\\baidu"));

	GetWindowsDirectory(szWinPath, _countof(szWinPath));
	if(0 == szWinPath[0])
	{
		return false;
	}

	for(INT_PTR i = 0, iTotal = csFilesList.GetCount(); i < iTotal ; i++)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		csFilesList[i].SetAt(0, szWinPath[0]);
		if(!_taccess(csFilesList[i],0))
		{
			m_bSplSpyFound = true;
			
			if(bToDelete)
			{
				if(i != iTotal - 1)
					AddInRestartDeleteList(RD_FILE_BACKUP, m_ulSpyName, csFilesList[i]);
				else
					AddInRestartDeleteList(RD_FOLDER, m_ulSpyName, csFilesList[i]);
			}
			else
			{
				if(i != iTotal - 1)
				{
					SendScanStatusToUI(Special_File, m_ulSpyName, csFilesList[i]);
				}
				else
				{
					SendScanStatusToUI(Special_Folder, m_ulSpyName, csFilesList[i]);
				}
			}
		}
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanDesktopLinks
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: scan for new chinese infection, desktop icons
	Author			: Anand Srivastava
	Description		: scan for new chinese infection, desktop icons
--------------------------------------------------------------------------------------*/
bool CBaiduWorm::ScanDesktopLinks(bool bToDelete)
{
	CString csAllUserDesktop, csCurUserDesktop;
	CFileFind objFinder;
	BOOL bMoreFiles = FALSE;
	bool bInfectionFound = false;
	CS2S objExtList(false);

	if(bToDelete)
	{
		return bInfectionFound;
	}

	m_objReg.Get(REG_SHELL_FOLDER, _T("Common Desktop"), csAllUserDesktop, HKEY_LOCAL_MACHINE);
	if(BLANKSTRING == csAllUserDesktop)
	{
		return bInfectionFound;
	}

	bMoreFiles = objFinder.FindFile(csAllUserDesktop + _T("\\*"));
	if(FALSE == bMoreFiles)
	{
		return bInfectionFound;
	}

	while(bMoreFiles)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDirectory())
		{
			continue;
		}

		if(CheckFileAssoc(objFinder.GetFilePath(), objExtList))
		{
			bInfectionFound = true;
		}
	}

	objFinder.Close();

	GetCurUserDesktopPath(csCurUserDesktop);
	bMoreFiles = objFinder.FindFile(csCurUserDesktop + _T("\\*"));
	if(FALSE == bMoreFiles)
	{
		return bInfectionFound;
	}

	while(bMoreFiles)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDirectory())
		{
			continue;
		}

		if(CheckFileAssoc(objFinder.GetFilePath(), objExtList))
		{
			bInfectionFound = true;
		}
	}

	objFinder.Close();
	return bInfectionFound;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckFileAssoc
	In Parameters	: const CString& csFilePath, CS2S& objExtList
	Out Parameters	: bool
	Purpose			: check file extension and file association
	Author			: Anand Srivastava
	Description		: check file extension and file association
--------------------------------------------------------------------------------------*/
bool CBaiduWorm::CheckFileAssoc(const CString& csFilePath, CS2S& objExtList)
{
	LPCTSTR szExt = 0, Ptr = 0;
	CString csRegPath, csData, csExt;
	LPTSTR szTemp = 0;

	szExt = _tcsrchr(csFilePath, _T('.'));
	if(NULL == szExt)
	{
		return false;
	}

	szExt++;
	if(0 == *szExt)
	{
		return false;
	}

	csExt = szExt;
	csExt.MakeLower();
	if(objExtList.SearchItem(csExt, szTemp))
	{
		SendScanStatusToUI(Special_File, m_ulSpyName, csFilePath);
	}

	csRegPath = _T("SOFTWARE\\Classes\\%EXT_PLACE_HOLDER%\\shell\\open\\command");
	csRegPath.Replace(_T("%EXT_PLACE_HOLDER%"), szExt);

	m_objReg.Get(csRegPath, BLANKSTRING, csData, HKEY_LOCAL_MACHINE);
	if(BLANKSTRING == csData)
	{
		return false;
	}

	csData.MakeLower();
	Ptr = _tcsstr(csData, _T("iexplore"));
	if(NULL == Ptr)
	{
		return false;
	}

	Ptr += _tcslen(_T("iexplore"));
	if(0 == *Ptr)
	{
		return false;
	}

	Ptr = _tcsstr(Ptr, _T("http://"));
	if(NULL == Ptr)
	{
		return false;
	}

	SendScanStatusToUI(Special_File, m_ulSpyName, csFilePath);
	EnumAndReportCOMKeys(m_ulSpyName, CString(_T("SOFTWARE\\Classes\\")) + szExt, HKEY_LOCAL_MACHINE, false);
	objExtList.AppendItem(csExt, _T("dummy"));
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanRegistryRandomKeys
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: remove random keys in software which look service keys
	Author			: Anand Srivastava
	Description		: remove random keys in software which look service keys
--------------------------------------------------------------------------------------*/
bool CBaiduWorm::ScanRegistryRandomKeys(bool bToDelete)
{
	bool bFound = false, bHold = true;
	CArray<CString, CString> csArrSubKeys;
	CString csKey, csHoldKey = _T("Software\\"), csData;
	CStringArray csValueList;

	if(bToDelete)
	{
		return false;
	}

	csValueList.Add(_T("Type"));
	csValueList.Add(_T("Start"));
	csValueList.Add(_T("ErrorControl"));
	csValueList.Add(_T("ImagePath"));
	csValueList.Add(_T("DisplayName"));
	csValueList.Add(_T("ObjectName"));
	csValueList.Add(_T("Description"));
	csValueList.Add(_T("FailureActions"));

	m_objReg.EnumSubKeys(_T("Software"), csArrSubKeys, HKEY_LOCAL_MACHINE, true);
	for(INT_PTR i = 0, iTotal = csArrSubKeys.GetCount(); i < iTotal; i++)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		bHold = true;
		csKey = csHoldKey + csArrSubKeys.GetAt(i);

		for(int j = 0, jTotal = (int)csValueList.GetCount(); j < jTotal; j++)
		{
			if(!m_objReg.ValueExists(csKey, csValueList.GetAt(j), HKEY_LOCAL_MACHINE))
			{
				bHold = false;
				break;
			}
		}

		if(!m_objReg.ValueExists(csKey + _T("\\Parameters"), _T("ServiceDll"), HKEY_LOCAL_MACHINE))
		{
			bHold = false;
		}

		if(bHold)
		{
			bFound = true;
			EnumAndReportCOMKeys(m_ulSpyName, csKey, HKEY_LOCAL_MACHINE, false);
		}
	}

	return bFound;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanCommonLocations
	In Parameters	: bool bToDelete
	Out Parameters	: bool
	Purpose			: scan PFDIR, SYS32, STARTUP for random files of baidu
	Author			: Anand Srivastava
	Description		: scan PFDIR, SYS32, STARTUP for random files of baidu
--------------------------------------------------------------------------------------*/
bool CBaiduWorm::ScanCommonLocations(bool bToDelete)
{
	bool bInfected = false;

	if(bToDelete)
	{
		return false;
	}

	bInfected = ScanPFDIR()?true:bInfected;
	bInfected = ScanStartUpDIR()?true:bInfected;
	bInfected = ScanSystem32()?true:bInfected;
	//ScanRoot();
	return bInfected;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanPFDIR
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: scan PFDIR for random files of baidu
	Author			: Anand Srivastava
	Description		: scan PFDIR for random files of baidu
--------------------------------------------------------------------------------------*/
bool CBaiduWorm::ScanPFDIR()
{
	bool bInfectionFound = false;
	BOOL bMoreFiles = FALSE;
	CString csPath;
	CFileFind objFinder;
	ULONG64 ulFileSize = 0;
	CStringArray objList1;
	CArray<CStringA, CStringA> objList2;
	CFileVersionInfo objVerInfo;

	objList1.Add(_T("www.qq.com"));
	objList2.Add("360tray.exe");

	csPath = CSystemInfo::m_strProgramFilesDir + _T("\\*.exe");
	bMoreFiles = objFinder.FindFile(csPath);
	if(FALSE == bMoreFiles)
	{
		return false;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDots() || objFinder.IsDirectory())
		{
			continue;
		}

		csPath = objFinder.GetFilePath();
		csPath.MakeLower();

		ulFileSize = objFinder.GetLength();
		if(ulFileSize < 100 || SearchStringsInFileU(csPath, objList1) ||
			SearchStringsInFile(csPath, objList2) || objVerInfo.DoTheVersionJob(csPath, false) ||
			CheckCompanyName(csPath, _T("funshion")))
		{
			if(m_objEnumProcess.IsProcessRunning(csPath, false))
			{
				SendScanStatusToUI(Special_Process, m_ulSpyName, csPath);
			}

			SendScanStatusToUI(Special_File, m_ulSpyName, csPath);
			bInfectionFound = true;
		}
	}

	objFinder.Close();
	return bInfectionFound;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanStartUpDIR
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: scan StartUp for random files of baidu
	Author			: Anand Srivastava
	Description		: scan StartUp for random files of baidu
--------------------------------------------------------------------------------------*/
bool CBaiduWorm::ScanStartUpDIR()
{
	bool bInfectionFound = true;
	CString csPath;
	BOOL bMoreFiles = FALSE;
	CFileFind objFinder;
	CStringArray csArrList;

	csArrList.Add(_T("\\Realtek\\EditorsUI.dll"));

	if(!GetCurUserStartupPath(csPath, true))
	{
		return false;
	}

	csPath = csPath + _T("\\*");
	bMoreFiles = objFinder.FindFile(csPath);
	if(FALSE == bMoreFiles)
	{
		return false;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDots() || objFinder.IsDirectory())
		{
			continue;
		}

		csPath = objFinder.GetFilePath();
		if(SearchStringsInFileU(csPath, csArrList))
		{
			if(m_objEnumProcess.IsProcessRunning(csPath, false))
			{
				SendScanStatusToUI(Special_Process, m_ulSpyName, csPath);
			}

			SendScanStatusToUI(Special_File, m_ulSpyName, csPath);
			bInfectionFound = true;
		}
	}

	objFinder.Close();
	return bInfectionFound;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanSystem32
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: scan System32 for random files of baidu
	Author			: Anand Srivastava
	Description		: scan System32 for random files of baidu
--------------------------------------------------------------------------------------*/
bool CBaiduWorm::ScanSystem32()
{
	bool bInfectionFound = true, bSkip = true;
	CString csPath, csFileName;
	BOOL bMoreFiles = FALSE, bMoreFiles2 = FALSE;
	CFileFind objFinder, objFinder2;
	CArray<CStringA, CStringA> csArrList;
	CStringArray csSkipFolders;

	csSkipFolders.Add(_T("1025"));
	csSkipFolders.Add(_T("1028"));
	csSkipFolders.Add(_T("1031"));
	csSkipFolders.Add(_T("1033"));
	csSkipFolders.Add(_T("1037"));
	csSkipFolders.Add(_T("1041"));
	csSkipFolders.Add(_T("1042"));
	csSkipFolders.Add(_T("1054"));
	csSkipFolders.Add(_T("2052"));
	csSkipFolders.Add(_T("3076"));
	csSkipFolders.Add(_T("3com_dmi"));
	csSkipFolders.Add(_T("cache"));
	csSkipFolders.Add(_T("catroot"));
	csSkipFolders.Add(_T("catroot2"));
	csSkipFolders.Add(_T("com"));
	csSkipFolders.Add(_T("config"));
	csSkipFolders.Add(_T("dhcp"));
	csSkipFolders.Add(_T("directx"));
	csSkipFolders.Add(_T("dllcache"));
	csSkipFolders.Add(_T("drivers"));
	csSkipFolders.Add(_T("drvstore"));
	csSkipFolders.Add(_T("en-us"));
	csSkipFolders.Add(_T("export"));
	csSkipFolders.Add(_T("grouppolicy"));
	csSkipFolders.Add(_T("ias"));
	csSkipFolders.Add(_T("icsxml"));
	csSkipFolders.Add(_T("ime"));
	csSkipFolders.Add(_T("inetsrv"));
	csSkipFolders.Add(_T("lang"));
	csSkipFolders.Add(_T("logfiles"));
	csSkipFolders.Add(_T("macromed"));
	csSkipFolders.Add(_T("microsoft"));
	csSkipFolders.Add(_T("msdtc"));
	csSkipFolders.Add(_T("mui"));
	csSkipFolders.Add(_T("npp"));
	csSkipFolders.Add(_T("oobe"));
	csSkipFolders.Add(_T("ras"));
	csSkipFolders.Add(_T("reinstallbackups"));
	csSkipFolders.Add(_T("restore"));
	csSkipFolders.Add(_T("rtcom"));
	csSkipFolders.Add(_T("setup"));
	csSkipFolders.Add(_T("shellext"));
	csSkipFolders.Add(_T("spool"));
	csSkipFolders.Add(_T("urttemp"));
	csSkipFolders.Add(_T("usmt"));
	csSkipFolders.Add(_T("wbem"));
	csSkipFolders.Add(_T("wins"));
	csSkipFolders.Add(_T("xircom"));
	csSkipFolders.Add(_T("xpsviewer"));

	csArrList.Add("tedun001.3322.org");

	csPath = CSystemInfo::m_strSysDir + _T("\\*");
	bMoreFiles = objFinder.FindFile(csPath);
	if(FALSE == bMoreFiles)
	{
		return false;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDots() || (!objFinder.IsDirectory()))
		{
			continue;
		}

		csPath = objFinder.GetFileName();
		csPath.MakeLower();
		bSkip = false;
		for(int i = 0, iTotal = (int)csSkipFolders.GetCount(); i < iTotal; i++)
		{
			if(csPath == csSkipFolders.GetAt(i))
			{
				bSkip = true;
				break;
			}
		}

		if(bSkip)
		{
			continue;
		}

		csPath = objFinder.GetFilePath();
		bMoreFiles2 = objFinder2.FindFile(csPath + _T("\\*.exe"));
		if(bMoreFiles2)
		{
			while(bMoreFiles2)
			{
				bMoreFiles2 = objFinder2.FindNextFile();
				if(objFinder2.IsDots() || objFinder2.IsDirectory())
				{
					continue;
				}

				csFileName = objFinder2.GetFileName();
				csPath = objFinder2.GetFilePath();
				csFileName.MakeLower();

				//if(SearchStringsInFile(csPath, csArrList) || CheckNamePattern(csFileName))
				if(CheckNamePattern(csFileName))
				{
					if(m_objEnumProcess.IsProcessRunning(csPath, false))
					{
						SendScanStatusToUI(Special_Process, m_ulSpyName, csPath);
					}

					SendScanStatusToUI(Special_File, m_ulSpyName, csPath);
				}
			}

			objFinder2.Close();
		}
	}

	objFinder.Close();
	return bInfectionFound;
}


/*-------------------------------------------------------------------------------------
	Function		: CheckNamePattern
	In Parameters	: const CString& csFileName
	Out Parameters	: bool
	Purpose			: check name pattern for sys32 files
	Author			: Anand Srivastava
	Description		: check name pattern for sys32 files. e.g. A16.exe, e001.exe
--------------------------------------------------------------------------------------*/
bool CBaiduWorm::CheckNamePattern(const CString& csFileName)
{
	bool bDotFound = false;
	TCHAR chLetter = csFileName.GetAt(0);

	if(csFileName == _T("jayz.exe"))
	{
		return true;
	}

	if(7 != csFileName.GetLength() && 8 != csFileName.GetLength())
	{
		return false;
	}

	if(chLetter < _T('a') || chLetter > _T('z'))
	{
		return false;
	}

	chLetter = csFileName.GetAt(1);
	if(chLetter < _T('0') || chLetter > _T('9'))
	{
		return false;
	}

	chLetter = csFileName.GetAt(2);
	if(chLetter < _T('0') || chLetter > _T('9'))
	{
		return false;
	}

	chLetter = csFileName.GetAt(3);
	if(chLetter == _T('.'))
	{
		return true;
	}

	if(chLetter < _T('0') || chLetter > _T('9'))
	{
		return false;
	}

	chLetter = csFileName.GetAt(4);
	if(chLetter == _T('.'))
	{
		return true;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanRoot
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: scan root for random files of baidu
	Author			: Anand Srivastava
	Description		: scan root for random files of baidu
--------------------------------------------------------------------------------------*/
/*bool CBaiduWorm::ScanRoot()
{
	bool bInfectionFound = false;
	CString csPath;
	BOOL bMoreFiles = FALSE;
	CFileFind objFinder;
	CStringArray csArrList;

	csPath = CSystemInfo::m_strRoot + _T("\\*.exe");
	bMoreFiles = objFinder.FindFile(csPath);
	if(FALSE == bMoreFiles)
	{
		return false;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDots() || objFinder.IsDirectory())
		{
			continue;
		}

		csPath = objFinder.GetFilePath();
		if(SearchStringsInFileU(csPath, csArrList))
		{
			SendScanStatusToUI(Special_File, m_ulSpyName, csPath);
			bInfectionFound = true;
		}
	}

	objFinder.Close();
	return bInfectionFound;
}*/
