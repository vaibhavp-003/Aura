/*=============================================================================
   FILE				: TrojanAgentWorm.Cpp
   ABSTRACT			: Implementation of Special Spyware TrojanAgentWorm Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Shweta
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 29/10/2007
   NOTES			:
   VERSION HISTORY	: 
					version: 2.5.0.19
					resource: Shweta
					Description: added fix for Trojan.Agent 

					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability

					version: 2.5.0.23
					resource: Shweta
					Description: Removed the String Scan as the String Change.
							     Implemented Check of BHO in File.

				 	version: 2.5.0.24
					resource: Shweta
					Description: Implemented new function for the MSVPS files.
								 Removed the old check from ScanSplSpy.

					version: 2.5.0.25
					resource: Shweta
					Description: Implemented Generic BHO for random BHO detection
					
					version: 2.5.0.31
					resource: Shweta
					Description: Implemented infected explorer.exe	

					version: 2.5.0.33
					resource: Sandip
					Description: Compile CheckForExplorerExe function only for 32 bit dll

					version: 2.5.0.41
					resource: Anand Srivastava
					Description: modified code for fixing infected explorer.exe

					version: 2.5.0.56
					resource: Shweta Mulay
					Description: solved the exception in scanning
=============================================================================*/
#include "pch.h"
#include "TrojanAgentWorm.h"
//#include "FileHeaderInfo.h"
#include "SDRestriction.h"
#include "DirectoryManager.h"
#include "ToolBarCleaner.h"
#include "ChromePreference.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool ,CFileSignatureDb
	Out Parameters	: bool
	Purpose			: Checks and remove CtrojanAgent
    Author			: Shweta
	Description		: Finds and Displays Trojan Agent dll BHO and CLSID 
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		//CStringArray csBHoKeys;
		//bool bInfectedFile = false;
		//CStringArray csRegLocations;

		if(IsStopScanningSignaled())
			return false;

//#ifndef WIN64
//		CheckForExplorerExe ( bToDelete ) ; // 2.5.0.31
//#endif
		if(bToDelete)
		{
			return false;
		}
		CToolBarCleaner obj;
		//obj.StartToolbarScanning();
		obj.ExcludeCachePaths();
		ResetImportantFolderAttributes();

		// Removing homepages from mozilla and chrome 
		DWORD dw = 0;
		CRegistry objReg;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("CleanBrowsers"), dw, HKEY_LOCAL_MACHINE);
		if(dw)
		{
			CChromePreference objChromePref ;
			objChromePref.CleanBrowsers();
		}



		m_bSplSpyFound = CheckForHiddenRandomAutorunGenerator() ? true : m_bSplSpyFound;
		m_bSplSpyFound = CheckForShortcutTrojan() ? true : m_bSplSpyFound;
		m_bSplSpyFound = CheckForCommonInfectionKeys() ? true : m_bSplSpyFound;
		m_bSplSpyFound = CheckForDoubleSpacePFDIR() ? true : m_bSplSpyFound;
		m_bSplSpyFound = FixDesktopShortcutPaths() ? true : m_bSplSpyFound;

		//csRegLocations . Add ( BHO_REGISTRY_PATH ) ;
		//if ( m_bScanOtherLocations )
		//	csRegLocations . Add ( BHO_REGISTRY_PATH_X64 ) ;

		//for (int iBHOLoc = 0 ; iBHOLoc < csRegLocations.GetCount(); iBHOLoc++ )
		//{
		//	if(IsStopScanningSignaled())
		//		break ;

		//	//Enumerate BHO and find the files related to it
		//	if ( !m_objReg.EnumSubKeys ( csRegLocations.GetAt(iBHOLoc) , csBHoKeys , HKEY_LOCAL_MACHINE ) )
		//		continue;
		//	
		//	for ( int i = 0 ; i < csBHoKeys.GetCount() ; i++ )
		//	{
		//		CString csData , csFileName , csFullKey;
		//		DWORD dwsize ;
		//		CStringArray csArrCLSID;

		//		if(IsStopScanningSignaled())
		//			break ;
		//		//2.5.0.20
		//		csArrCLSID.Add ( CLSID_KEY );
		//		if ( m_bScanOtherLocations )
		//		{
		//			csArrCLSID.Add( CString(WOW6432NODE_REG_PATH) + CString(_T("classes\\clsid\\")) ) ;
		//		}
		//		
		//		for (int iCLSIDCnt = 0 ; iCLSIDCnt < csArrCLSID.GetCount() ; iCLSIDCnt++ ) 
		//		{
		//			if(IsStopScanningSignaled())
		//				break ;

		//			bInfectedFile = false ;

		//			csFullKey = csArrCLSID.GetAt ( iCLSIDCnt ) + csBHoKeys.GetAt(i) + _T("\\InprocServer32") ;
		//			dwsize = MAX_PATH ;
		//			m_objReg .Get ( csFullKey , _T("") , csData ,HKEY_LOCAL_MACHINE ) ;
		//			csFileName = csData ;

		//			//2.5.0.25
		//			if ( GenericBHOScanner ( csFileName ) )
		//			{
		//				bInfectedFile = true;
		//			}
		//			else
		//			{
		//				//2.5.0.20
		//				if ( NULL != StrStrI ( csFileName , m_objSysInfo . m_strProgramFilesDir ) )
		//				{
		//					if ( CheckPFDirDll ( csFileName ) )
		//						bInfectedFile = true ;
		//				}
		//				else 
		//				{ //2.5.0.24
		//					if ( StrStrI ( csFileName , m_objSysInfo . m_strSysDir ) ||
		//						StrStrI ( csFileName , m_objSysInfo . m_strWinDir ) )
		//					{
		//						if ( IsFileInfected ( csFileName ) )//|| IsRandomBHOFile ( csFileName , csBHoKeys [ i ] ) ) scans for UrlFilter.dll
		//						{
		//							bInfectedFile = true ;
		//						}
		//					}
		//				}
		//			}

		//			if ( bInfectedFile )
		//			{
		//				m_bSplSpyFound = true ;
		//				SendScanStatusToUI ( Special_File , m_ulSpyName , csFileName ) ;
		//				EnumKeynSubKey ( _T("HKEY_LOCAL_MACHINE\\") + csRegLocations.GetAt(iBHOLoc) + _T("\\") + csBHoKeys.GetAt(i) , m_ulSpyName );
		//				EnumKeynSubKey ( CString(_T("HKEY_LOCAL_MACHINE\\")) + CString(CLSID_KEY) 
		//					+ csBHoKeys.GetAt(i) ,m_ulSpyName );
		//			}
		//		}
		//	}
		//}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}
	
	catch(...)
	{
		AddLogEntry ( _T("Exception caught in CTrojanAgentWorm"), 0, 0 ) ;
	}
	
	return ( false );
}

/*-------------------------------------------------------------------------------------
	Function		: CheckPFDirDll
	In Parameters	: CString
	Out Parameters	: bool
	Purpose			: Checks and remove CtrojanAgent
    Author			: Shweta
	Description		: Finds and Displays random Trojan Agent dll BHO and CLSID 
					  from Program files directory. 2.5.0.20
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::CheckPFDirDll(const CString& csFilenm)
{
	//check if it is the only entry in PFDIR folder.
	//Version tab must be absent.
	//Should contain string "out.dll"
	try
	{
		CString csPFDirDirectory;
		int icnt = 0;
		BOOL bFound = false;
		CFileFind objFilFin;

		if(IsStopScanningSignaled())
			return ( false ) ;

		csPFDirDirectory = csFilenm.Left( csFilenm.ReverseFind('\\'));
		bFound = objFilFin . FindFile ( csPFDirDirectory + L"\\*.*" ) ;
		if ( !bFound )
			return ( false ) ;

		// break if there are more than one file or
		// also if any folder ( also return false )
		while ( bFound && ( icnt <= 1 ) )
		{
			bFound = objFilFin.FindNextFile();
			if ( objFilFin.IsDots() )
				continue;

			if (objFilFin.IsDirectory())
				return false;

			icnt++;
		}

		objFilFin.Close() ;
		if ( icnt != 1 )
			return ( false ) ;

		CFileVersionInfo objFileVer;
		CArray<CStringA,CStringA>  csPFDirArr;
		csPFDirArr.Add ( "out.dll" ) ;

		// return if version tab present
		if ( !objFileVer.DoTheVersionJob ( csFilenm , false ) )
			return ( false ) ;

		// return false if the string is not found
		if ( !SearchStringsInFile ( csFilenm , csPFDirArr ) )
			return ( false ) ;

		return ( true ) ;
	}

	catch(...)
	{
		AddLogEntry(L"Exception Caught in CheckPFDirDll",0,0);
	}

	return ( false ) ;
}
/*-------------------------------------------------------------------------------------
	Function		: IsFileInfected
	In Parameters	: CString
	Out Parameters	: bool
	Purpose			: Checks and remove CtrojanAgent
    Author			: Shweta
	Description		: Finds and Displays random Trojan Agent dll BHO and CLSID 
					  from system32 directory. 2.5.0.20
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::IsFileInfected ( const CString& csFileNm )
{
	try
	{
		if(IsStopScanningSignaled())
			return ( false ) ;

		//Version tab must be present
		//must contain company Name as "3gp.org" or "kodack"
		//and description "3GP Video Driver" or "Video Driver"
		//Check for the String "Media Codec" in the file -- removed

		TCHAR szCompanyName [ MAX_PATH ] = { 0 } ;
		TCHAR szDescription [ MAX_PATH ] = { 0 } ;
		CStringArray csArr , csCmpyArr , csDescArr ;
		bool bInfectedFileFound = false;
		
		//Initialize all Array. it has to be in pairs of (Company Name and Description)
		csArr.Add ( L"Media Codec" ) ;

		csCmpyArr.Add ( L"kodack" ) ;
		csDescArr.Add ( L"video driver" ) ;

		csCmpyArr.Add ( L"3gp.org" ) ;
		csDescArr.Add ( L"3gp video driver" ) ;

		if ( _taccess_s ( csFileNm , 0 ) == -1 )
			return ( false ) ;
		
		CFileVersionInfo objFileVer ;
		if ( objFileVer . DoTheVersionJob ( csFileNm , false ) )
			return ( false ) ;

		objFileVer.GetCompanyName ( csFileNm , szCompanyName ) ;
		objFileVer.GetFileDescription ( csFileNm , szDescription ) ;
		
		for ( int icmpycnt = 0 ; icmpycnt < csCmpyArr . GetCount() ; icmpycnt++ )
		{
			if ( 0 == csCmpyArr [ icmpycnt ] . CompareNoCase ( szCompanyName ) &&
				 0 == csDescArr [ icmpycnt ] . CompareNoCase ( szDescription ) )
			{
				bInfectedFileFound = true ;
				break ;
			}
		}
		return ( bInfectedFileFound ) ;
	}

	catch(...)
	{
		AddLogEntry(L"Exception caught in CTrojanAgentWorm::IsFileInfected",0,0);
	}

	return ( false ) ;
}
/*-------------------------------------------------------------------------------------
	Function		: IsRandomBHOFile
	In Parameters	: CString ,CString
	Out Parameters	: bool
	Purpose			: Checks and remove CtrojanAgent
    Author			: Shweta
	Description		: Finds and Displays Trojan Agent dll BHO and CLSID 
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::IsRandomBHOFile( CString csFilenm, CString csBHO )
{
	CArray<CStringA,CStringA> csArrStr; 
	CStringA csBHOA;
	csBHOA.Format ( "%S" , static_cast<LPCTSTR>(csBHO) );

	if(IsStopScanningSignaled())
		return ( false );
	try
	{
		csArrStr.Add ( "Explorer" ) ;
		csArrStr.Add ( "CurrentVersion" ) ;
		csArrStr.Add ( "Windows" ) ;
		csArrStr.Add ( "Microsoft" ) ;
		csArrStr.Add ( csBHOA );

		return ( SearchStringsInFile ( csFilenm , csArrStr ) ) ;
	}
	catch(...)
	{
		AddLogEntry ( L"Exception caught in CTrojanAgentWorm::IsRandomBHOFile" ) ;
	}
	return ( false );
}
/*-------------------------------------------------------------------------------------
	Function		: GenericBHO
	In Parameters	: const CString
	Out Parameters	: bool
	Purpose			: Scans for Spyware BHO		
    Author			: Shweta
	Description		: Checks for random BHO 
	Version			: 2.5.0.25
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::GenericBHOScanner ( const CString csFilenm )
{
	try
	{
		CFileVersionInfo oFileVersionInfo;
		TCHAR* szWhiteList[]=
		{
			_T("twctoolbarbho.dll")
		};

		if(IsStopScanningSignaled())
			return ( false ) ;

		if ( _taccess_s ( csFilenm , 0 ) )
			return false;

		for(INT_PTR i = 0; i < _countof(szWhiteList); i++)
		{
			if(StrStrI(csFilenm, szWhiteList[i]))
			{
				return false;
			}
		}

		if ( StrStrI ( csFilenm , m_objSysInfo . m_strSysDir ) ||
						StrStrI ( csFilenm , m_objSysInfo . m_strWinDir ) ||
						StrStrI ( csFilenm , m_objSysInfo . m_strSysWow64Dir ))
		{
			if ( oFileVersionInfo.DoTheVersionJob ( csFilenm , false ) )
			{
				return ( true );
			}
			else
			{
				TCHAR csCmpy[MAX_PATH] = { 0 } ;
				if ( oFileVersionInfo.GetCompanyName ( csFilenm , csCmpy ) )
				{
					if ( _tcscmp ( csCmpy , L"" ) == 0 )
					{
						return ( true );
					}
				}
				return ( false ) ;
			}
		}
		return false;
	}
	
	catch(...)
	{
		AddLogEntry ( L"Exception caught in CTrojanAgentWorm::GenericBHOScanner" );
	}
	
	return ( false );
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForExplorerExe
	In Parameters	: bool
	Out Parameters	: void
	Purpose			: Scans for Spyware infected explorer.exe
    Author			: Shweta
	Description		: Checks for infected explorer.exe
	Version			: 2.5.0.41
--------------------------------------------------------------------------------------*/
void CTrojanAgentWorm :: CheckForExplorerExe ( bool bToDelete )
{
	try
	{
		//CFileHeaderInfo objFileHeader;
		//CString csFileName , csOrigFilePath;
		//CArray<CStringA,CStringA> csArrPath ;
		//CArray<CStringA,CStringA> csArrWidth ;
		//CArray<CStringA,CStringA> csArrCRC ;
		//CStringA csWidthCRC , csPathCRC , csSectionCRC ;
		//bool bflag = false;

		//csOrigFilePath = m_objSysInfo . m_strSysDir + _T ( "\\dllcache\\explorer.exe" ) ;
		//csFileName = m_objSysInfo . m_strWinDir + _T ( "\\explorer.exe" ) ;

		//if ( bToDelete )
		//{
		//	//Check if Entry Present in dllcache
		//	if ( _taccess_s ( csOrigFilePath , 0 ) )
		//		return ;

		//	CopyFile ( csOrigFilePath , csFileName , FALSE ) ;
		//}
		//else
		//{
		//	csArrPath.Add ( "c6709759e1d6c050" ); csArrWidth.Add ( "279cc7e42edb65e0" ); csArrCRC.Add ( "69d2c245f1e1532e" );
		//	csArrPath.Add ( "5f9f9ac29a816ee5" ); csArrWidth.Add ( "a3f69f82267a137d" ); csArrCRC.Add ( "0e8f8352bc19aede" );
		//	csArrPath.Add ( "ae988698d707eb73" ); csArrWidth.Add ( "731f8cbc08a0cb74" ); csArrCRC.Add ( "1afd1620d7ff87ff" );
		//	csArrPath.Add ( "122222926be664d2" ); csArrWidth.Add ( "3b0316adf006a96a" ); csArrCRC.Add ( "60956c4a02d9816e" );
		//	csArrPath.Add ( "38406e5e6de127c5" ); csArrWidth.Add ( "7dca4d27557cd6d9" ); csArrCRC.Add ( "2372ad372f38830c" );
		//	csArrPath.Add ( "adf75032ced9cb6a" ); csArrWidth.Add ( "443a302e31769572" ); csArrCRC.Add ( "fd8128858dea4931" );

		//	if ( _taccess_s ( csFileName , 0 ) )
		//		return ;

		//	if ( !objFileHeader.IsInitialized() )
		//	{
		//		return;
		//	}

		//	if ( !objFileHeader.GetFileHeaderInfo( csFileName , true , 0) )
		//	{
		//		bflag = true;
		//	}
		//	else
		//	{
  //              //TODO: convert to new type of exec signature
		//		/*csPathCRC = objFileHeader.GetExecPathCRC();
		//		csWidthCRC = objFileHeader.GetExecWidthCRC();
		//		csSectionCRC = objFileHeader.GetSectionSignature(7, 512);

		//		for ( int icrccnt = 0 ; icrccnt < csArrCRC.GetCount() ; icrccnt++ )
		//		{
		//			if ( csSectionCRC == csArrCRC.GetAt ( icrccnt ) && csWidthCRC == csArrWidth.GetAt ( icrccnt ) &&
		//				 csPathCRC == csArrPath.GetAt  ( icrccnt ) )
		//			{
		//				bflag = true ;
		//				break ;
		//			}
		//		}*/
		//	}

		//	if ( bflag )
		//	{
		//		if ( _taccess_s ( csOrigFilePath , 0 ) )
		//			return ;

		//		m_bSplSpyFound = true ;
		//		SendScanStatusToUI ( Special_File , m_ulSpyName , csFileName  ) ;
		//	}
		//}
	}

	catch(...)
	{
		AddLogEntry ( L"Exception caught in CTrojanAgentWorm::CheckForExplorerexe" );		
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForCommonInfectionKeys
	In Parameters	: bool
	Out Parameters	: void
	Purpose			: check and remove all common infection keys
    Author			: Anand Srivastava
	Description		: Checks for common keys
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::CheckForCommonInfectionKeys()
{
	bool bFound = false;
	DWORD dwValue = 0;
	CString csKey;
	CStringArray csArrUsersList;
	REG_FIX_OPTIONS RegFixOpt = {FIX_TYPE_ALWAYS_FIX, FIX_ACTION_RESTORE};
	struct
	{
		DWORD	dwLoc;			// 0 - dont check, 1 - hklm, 2 - hku, 3 - check all
		LPCTSTR szKey;
		LPCTSTR szValue;
		DWORD	dwBlack;
		DWORD	dwWhite;
	} Keys_List[]=
	{
		{3, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_TASKMGR, 1, 0},
		{3, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_REGISTRY, 1, 0},
		{3, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_SEARCH, 1, 0},
		{3, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_SHUTDOWN, 1, 0},
		{3, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_TASKBAR_CLICK, 1, 0},
		{3, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_RUN, 1, 0},
		{3, WIN_RESTRICTION_EXPLORER_KEY, DISABLE_CONTROL_PANEL, 1, 0},
		{3, WIN_RESTRICTION_EXPLORER_KEY, _T("NofolderOptions"), 1, 0},
		{3, WIN_RESTRICTION_EXPLORER_KEY, _T("NoViewContextMenu"), 1, 0},
		{3, WIN_RESTRICTION_SYSTEM_KEY, DISABLE_REGISTRY, 1, 0},
		{3, WIN_RESTRICTION_SYSTEM_KEY, DISABLE_TASKMGR, 1, 0},
		{3, WIN_RESTRICTION_SYSTEM_KEY, DISABLE_PROPERTY, 1, 0},
		{3, WIN_RESTRICTION_SYSTEM_KEY, DISABLE_PASSWORD, 1, 0},
		{3, WIN_RESTRICTION_SYSTEM_KEY, DISABLE_LOCK_COMPUTER, 1, 0},
		{3, WIN_RESTRICTION_POLICIES_KEY, DISABLE_CMD, 1, 0}
		//{3, WIN_RESTRICTION_EXPLORER_KEY, _T("NoDesktop"), 1, 0}		Removed on 9-3-2021, Reason: Admin not able to apply Desktop block policy
	};

	m_objReg.EnumSubKeys(PROFILELIST_PATH, csArrUsersList, HKEY_LOCAL_MACHINE);

	for(int i = 0; i < _countof(Keys_List); i++)
	{
		if(3 == Keys_List[i].dwLoc || 1 == Keys_List[i].dwLoc)
		{
			if(m_objReg.Get(Keys_List[i].szKey, Keys_List[i].szValue, dwValue, HKEY_LOCAL_MACHINE))
			{
				if(dwValue == Keys_List[i].dwBlack)
				{
					bFound = true;
					SendScanStatusToUI(RegFix, m_ulSpyName, HKEY_LOCAL_MACHINE, Keys_List[i].szKey,
										Keys_List[i].szValue, REG_DWORD, (LPBYTE)&dwValue,
										4, &RegFixOpt, (LPBYTE)&Keys_List[i].dwWhite, 4);
				}
			}
		}

		if(3 == Keys_List[i].dwLoc || 2 == Keys_List[i].dwLoc)
		{
			for(int j = 0, jTotal = (int)csArrUsersList.GetCount(); j < jTotal; j++)
			{
				csKey = csArrUsersList[j] + BACK_SLASH + Keys_List[i].szKey;
				if(m_objReg.Get(csKey, Keys_List[i].szValue, dwValue, HKEY_USERS))
				{
					if(dwValue == Keys_List[i].dwBlack)
					{
						bFound = true;
						SendScanStatusToUI(RegFix, m_ulSpyName, HKEY_USERS, csKey,
											Keys_List[i].szValue, REG_DWORD, (LPBYTE)&dwValue,
											4, &RegFixOpt, (LPBYTE)&Keys_List[i].dwWhite, 4);
					}
				}
			}
		}
	}

	CString csData;
	CStringArray csArrKeysList;
	m_objReg.EnumSubKeys(IMG_FILE_EXE_OPTS_PATH, csArrKeysList, HKEY_LOCAL_MACHINE);
	for(INT_PTR i = 0, iTotal = csArrKeysList.GetCount(); i < iTotal; i++)
	{
		csData.Empty();
		csKey = CString(IMG_FILE_EXE_OPTS_PATH) + BACK_SLASH + csArrKeysList.GetAt(i);
		m_objReg.Get(csKey, _T("debugger"), csData, HKEY_LOCAL_MACHINE);

		if(csData.IsEmpty() || -1 == csData.Find(_T('\\')))
		{
			continue;
		}

		if(!_taccess_s(csData, 0))
		{
			continue;
		}

		bFound = true;
		EnumAndReportCOMKeys(m_ulSpyName, csKey, HKEY_LOCAL_MACHINE);
	}

	csData = BLANKSTRING;
	csKey = _T("SOFTWARE\\Classes\\Drive\\shell");
	m_objReg.Get(csKey, BLANKSTRING, csData, HKEY_LOCAL_MACHINE);
	if(csData.CompareNoCase(_T("none")))
	{
		DWORD dwCurDataSize = 0, dwRepDataSize = 0;

		bFound = true;
		dwCurDataSize = (_tcslen(csData) + 1) * sizeof(TCHAR);
		dwRepDataSize = (_tcslen(_T("none")) + 1) * sizeof(TCHAR);
		SendScanStatusToUI(RegFix, m_ulSpyName, HKEY_LOCAL_MACHINE, csKey, BLANKSTRING, REG_EXPAND_SZ,
							(LPBYTE)(LPCTSTR)csData, dwCurDataSize, &RegFixOpt, (LPBYTE)_T("none"), dwRepDataSize);
	}

	csData = BLANKSTRING;
	csKey = _T("SOFTWARE\\Classes\\Drive\\shell\\find\\command");
	m_objReg.Get(csKey, BLANKSTRING, csData, HKEY_LOCAL_MACHINE);
	if(csData.CompareNoCase(_T("%SystemRoot%\\Explorer.exe")))
	{
		DWORD dwCurDataSize = 0, dwRepDataSize = 0;

		bFound = true;
		dwCurDataSize = (_tcslen(csData) + 1) * sizeof(TCHAR);
		dwRepDataSize = (_tcslen(_T("%SystemRoot%\\Explorer.exe")) + 1) * sizeof(TCHAR);
		SendScanStatusToUI(RegFix, m_ulSpyName, HKEY_LOCAL_MACHINE, csKey, BLANKSTRING, REG_EXPAND_SZ,
							(LPBYTE)(LPCTSTR)csData, dwCurDataSize, &RegFixOpt,
							(LPBYTE)_T("%SystemRoot%\\Explorer.exe"), dwRepDataSize);
	}

	return bFound;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForShortcutTrojan
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: check and remove shortcut creating trojans
    Author			: Anand Srivastava
	Description		: check and remove shortcut creating trojans on pendrive
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::CheckForShortcutTrojan()
{
	TCHAR szPath[4] = {_T('A'), _T(':'), _T('\\')};
	CFileFind objFinder;
	CString csTemp;
	BOOL bMoreFiles = FALSE;
	TCHAR szTarget[MAX_PATH] = {0};
	bool bFound = false;
	CStringArray csArrList;

	csArrList.Add(_T("RECYCLER\\"));

	for(; szPath[0] <= _T('Z'); szPath[0]++)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		if(_taccess_s(szPath, 0))
		{
			continue;
		}

		if(DRIVE_REMOVABLE != GetDriveType(szPath))
		{
			continue;
		}

		CheckSuspiciousFilesRunningFromAutorun(szPath[0]);

		csTemp = szPath;
		bMoreFiles = objFinder.FindFile(csTemp + _T("*.lnk"));
		if(!bMoreFiles)
		{
			continue;
		}

		while(bMoreFiles)
		{
			bMoreFiles = objFinder.FindNextFile();
			csTemp = objFinder.GetFilePath();

			if(!SearchStringsInFileU(csTemp, csArrList))
			{
				continue;
			}

			SendScanStatusToUI(Special_File, m_ulSpyName, csTemp);
			bFound = true;
		}

		objFinder.Close();
	}

	return bFound;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForHiddenRandomAutorunGenerator
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: check and remove shortcut creating trojans
    Author			: Anand Srivastava
	Description		: scan for trojan, file in userinit, present in startup
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::CheckForHiddenRandomAutorunGenerator()
{
	bool bInitPFDirsList = false;
	int iContext = 0;
	CString csUserinitData, csUIToken;
	CStringArray csArrPFFolders;
	CFileFind objFinder;
	BOOL bMoreFiles = FALSE;

	bMoreFiles = objFinder.FindFile(CSystemInfo::m_strProgramFilesDir + _T("\\*"));
	if(!bMoreFiles)
	{
		return false;
	}

	while(bMoreFiles)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDots() || (!objFinder.IsDirectory()))
		{
			continue;
		}

		csArrPFFolders.Add(objFinder.GetFilePath());
	}

	objFinder.Close();
	m_objReg.Get(WINLOGON_REG_KEY, _T("Userinit"), csUserinitData, HKEY_LOCAL_MACHINE);

	csUIToken = csUserinitData.Tokenize(_T(","), iContext);
	csUIToken.MakeLower();

	while(-1 != iContext)
	{
		if(-1 == csUIToken.Find(_T("\\userinit.exe")))
		{
			CheckPattern(csUIToken, csArrPFFolders);
		}

		csUIToken = csUserinitData.Tokenize(_T(","), iContext);
		csUIToken.MakeLower();
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckPattern
	In Parameters	: const CString& csFilePath, const CStringArray& csArrPFFolders
	Out Parameters	: bool
	Purpose			: check and remove shortcut creating trojans
    Author			: Anand Srivastava
	Description		: pattern is-> these 3 things present
						c:\Documents and Settings\admin\Start Menu\Programs\Startup\filename, file
						c:\Program Files\tfQEdIFO%2filename.exe, folder
						filepath is present
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::CheckPattern(const CString& csFilePath, const CStringArray& csArrPFFolders)
{
	int iLastSlash = -1;
	TCHAR szPath[MAX_PATH] = {0};
	CString csFileName, csStartupFile, csPFFolderPath;
	CString csRevDir, csRevFile;

	if(_taccess_s(csFilePath, 0))
	{
		return false;
	}

	iLastSlash = csFilePath.ReverseFind(_T('\\'));
	csFileName = csFilePath.Mid(iLastSlash);
	csFileName.Replace(_T("\\"), _T(""));

	if(!GetCurUserStartupPath(csStartupFile))
	{
		return false;
	}

	csStartupFile = csStartupFile + BACK_SLASH + csFileName;
	if(_taccess_s(csStartupFile, 0))
	{
		return false;
	}

	csRevFile = csFileName;
	csRevFile.MakeLower();
	csRevFile.MakeReverse();
	for(int i = 0, iLen = csRevFile.GetLength(), iTotal = (int)csArrPFFolders.GetCount(); i < iTotal; i++)
	{
		csRevDir = csArrPFFolders[i];
		csRevDir.MakeLower();
		csRevDir.MakeReverse();

		if(0 == _tcsncmp(csRevDir, csRevFile, iLen))
		{
			csRevDir.MakeReverse();
			break;
		}

		csRevDir = _T("");
	}

	if(BLANKSTRING == csRevDir)
	{
		return false;
	}

	csFileName = csRevDir + BACK_SLASH + csFileName;
	if(!_taccess(csFileName, 0))
	{
		SendScanStatusToUI(Special_File, m_ulSpyName, csFileName);
	}

	SendScanStatusToUI(Special_File, m_ulSpyName, csFilePath);
	SendScanStatusToUI(Special_File, m_ulSpyName, csStartupFile);
	RemoveFolders(csRevDir, m_ulSpyName, false);
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ResetImportantFolderAttributes
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: check and reset
    Author			: Anand Srivastava
	Description		: remove hidden and system attributes from OS Drive root folders, win, sys32
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::ResetImportantFolderAttributes()
{
	/*BOOL bMoreFiles = FALSE;
	CString csPath, csName;
	CFileFind objFinder;
	DWORD dwAttributes = 0;
	CStringArray csArrExcludeList;
	bool bFoundInExcludeList = false;

	csArrExcludeList.Add(_T("MSOCache"));
	csArrExcludeList.Add(_T("RECYCLER"));
	csArrExcludeList.Add(_T("System Volume Information"));
	csArrExcludeList.Add(_T("$RECYCLE.BIN"));
	csArrExcludeList.Add(_T("Documents and Settings"));

	bMoreFiles = objFinder.FindFile(CSystemInfo::m_strRoot + _T("\\*"));
	if(bMoreFiles)
	{
		while(bMoreFiles)
		{
			bMoreFiles = objFinder.FindNextFile();
			if(objFinder.IsDots() || (!objFinder.IsDirectory()))
			{
				continue;
			}

			csPath = objFinder.GetFilePath();
			csName = objFinder.GetFileName();

			bFoundInExcludeList = false;
			for(int i = 0, iTotal = csArrExcludeList.GetCount(); i < iTotal; i++)
			{
				if(0 == _tcsicmp(csName, csArrExcludeList[i]))
				{
					bFoundInExcludeList = true;
					break;
				}
			}

			if(!bFoundInExcludeList)
			{
				RemoveSystemAndHidden(csPath);
			}
		}

		objFinder.Close();
	}*/

	TCHAR *szSlash = NULL, szDocAndSet[MAX_PATH] = {0};

	SHGetFolderPath(0, CSIDL_PROFILE, 0, 0, szDocAndSet);
	szSlash = _tcschr(szDocAndSet, _T('\\'));
	if(szSlash)
	{
		szSlash = _tcschr(szSlash + 1, _T('\\'));
		if(szSlash)
		{
			*szSlash = _T('\0');
			RemoveSystemAndHidden(szDocAndSet);
		}
	}

	RemoveSystemAndHidden(CSystemInfo::m_strWinDir);
	RemoveSystemAndHidden(CSystemInfo::m_strSysDir);
	RemoveSystemAndHidden(CSystemInfo::m_strProgramFilesDir);
	RemoveSystemAndHidden(CSystemInfo::m_strProgramFilesDirX64);
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: RemoveSystemAndHidden
	In Parameters	: LPCTSTR szObject
	Out Parameters	: bool
	Purpose			: check and reset system and hidden attributes
    Author			: Anand Srivastava
	Description		: check and reset system and hidden attributes
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::RemoveSystemAndHidden(LPCTSTR szObject)
{
	DWORD dwAttributes = 0;
	bool bRequiredResetting = false;

	dwAttributes = GetFileAttributes(szObject);
	if(INVALID_FILE_ATTRIBUTES == dwAttributes)
	{
		return false;
	}

	if((dwAttributes & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN)
	{
		dwAttributes ^= FILE_ATTRIBUTE_HIDDEN;
		bRequiredResetting = true;
	}

	if((dwAttributes & FILE_ATTRIBUTE_SYSTEM) == FILE_ATTRIBUTE_SYSTEM)
	{
		dwAttributes ^= FILE_ATTRIBUTE_SYSTEM;
		bRequiredResetting = true;
	}

	if(bRequiredResetting)
	{
		SetFileAttributes(szObject, dwAttributes);
		AddLogEntry(_T("Removing sys and hid from: %s"), szObject);
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSuspiciousFilesRunningFromAutorun
	In Parameters	: TCHAR chDriveLetter
	Out Parameters	: bool
	Purpose			: check and scan any files being run from suspicious folder
    Author			: Anand Srivastava
	Description		: check and scan any files being run from suspicious folder
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::CheckSuspiciousFilesRunningFromAutorun(TCHAR chDriveLetter)
{
	bool bFound = false;
	CString csPath, csAutorunFile = _T("A:\\Autorun.inf");
	CStringArray csArrValues;
	TCHAR szData[512] = {0}, *szStart = 0, *szEnd = 0;
	LPTSTR szArrCommand[]=
	{
		_T("shellexecute"),
		_T("shell\\open\\Command"),
		_T("shell\\explore\\Command")
	};

	csAutorunFile.SetAt(0, chDriveLetter);
	if(_taccess_s(csAutorunFile, 0))
	{
		return false;
	}

	for(int i = 0; i < _countof(szArrCommand); i++)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		memset(szData, 0, sizeof(szData));
		GetPrivateProfileString(_T("Autorun"), szArrCommand[i], _T(""), szData, _countof(szData), csAutorunFile);
		if(0 == szData[0])
		{
			continue;
		}

		_tcslwr_s(szData, _countof(szData));
		szStart = _tcsstr(szData, _T("recycle"));
		if(NULL == szStart)
		{
			continue;
		}

		szEnd = _tcschr(szStart, _T('\\'));
		if(szEnd)
		{
			*szEnd = 0;
		}

		csPath = _T("");
		csPath.Format(_T("%C:\\%s"), chDriveLetter, szStart);

		if(!_taccess_s(csPath, 0))
		{
			RemoveFolders(csPath, 1401146, false);
			bFound = true;
		}
	}

	if(bFound)
	{
		SendScanStatusToUI(Special_File, m_ulSpyName, csAutorunFile);
	}

	return bFound;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForDoubleSpacePFDIR
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: check for 3 files in 'Program  Files' and 4 in RECYCLER
    Author			: Anand Srivastava
	Description		: check for 3 files in 'Program  Files' and 4 in RECYCLER
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::CheckForDoubleSpacePFDIR()
{
	LPCTSTR szArrMalFolderList[] =
	{
		_T(":\\RECYCLER\\X-1-5-21-1960408961-725345543-839522115-1003"),
		_T(":\\Program  Files")
	};

	bool bInfectionFound = false;
	CString csFolderPath;

	for(int i = 0; i < _countof(szArrMalFolderList); i++)
	{
		csFolderPath.Format(_T("%c%s"), m_csWinDir.GetAt(0), szArrMalFolderList[i]);
		if(_taccess_s(csFolderPath, 0))
		{
			continue;
		}

		bInfectionFound = true;
		RemoveFolders(csFolderPath, m_ulSpyName, false, true);
	}

	return bInfectionFound;
}

/*-------------------------------------------------------------------------------------
	Function		: FixDesktopShortcutPaths
	In Parameters	: 
	Out Parameters	: bool
	Purpose			: check for removed desktop trojan shortcuts
    Author			: Anand Srivastava
	Description		: check for removed desktop trojan shortcuts
--------------------------------------------------------------------------------------*/
bool CTrojanAgentWorm::FixDesktopShortcutPaths()
{
	bool bFoundShortcut = false;
	CString csTempPath, csStartMenu, csDesktop, csUserProfile, csAppData;
	TCHAR szStartMenu[MAX_PATH] = {0}, szDesktop[MAX_PATH] = {0};
	CDirectoryManager objDirMgr;

	if(!m_objReg.Get(CSystemInfo::m_csProductRegKey, _T("TempFolderPath"), csTempPath, HKEY_LOCAL_MACHINE))
	{
		AddLogEntry(L"not found temp folder path");
		return bFoundShortcut;
	}

	if(csTempPath == BLANKSTRING)
	{
		AddLogEntry(L"found temp folder path, but blank");
		return bFoundShortcut;
	}

	if(_taccess_s(csTempPath + _T("smtmp"), 0))
	{
		return bFoundShortcut;
	}

	if(0 == _taccess_s(csTempPath + _T("smtmp\\1"), 0))
	{
		SHGetFolderPath(0, CSIDL_COMMON_STARTMENU, 0, 0, szStartMenu);
		csStartMenu = szStartMenu[0]? szStartMenu: BLANKSTRING;
		if(BLANKSTRING != csStartMenu)
		{
			bFoundShortcut = true;
			objDirMgr.MaxCopyDirectory(szStartMenu, csTempPath + _T("smtmp\\1"), true, true, NULL, NULL, true);
		}
	}

	if(0 == _taccess_s(csTempPath + _T("smtmp\\2"), 0))
	{
		if(m_objReg.Get(CSystemInfo::m_csProductRegKey, _T("USERPROFILE"), csUserProfile, HKEY_LOCAL_MACHINE))
		{
			if(csUserProfile != BLANKSTRING)
			{
				bFoundShortcut = true;
				objDirMgr.MaxCopyDirectory(csUserProfile + _T("\\Application Data\\Microsoft\\Internet Explorer\\Quick Launch"),
											csTempPath + _T("smtmp\\2"), true, true, NULL, NULL, true);
			}
		}
	}

	if(0 == _taccess_s(csTempPath + _T("smtmp\\3"), 0))
	{
		if(m_objReg.Get(CSystemInfo::m_csProductRegKey, _T("APPDATA"), csAppData, HKEY_LOCAL_MACHINE))
		{
			if(csAppData != BLANKSTRING)
			{
				bFoundShortcut = true;
				objDirMgr.MaxCopyDirectory(csAppData + _T("\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar"),
											csTempPath + _T("smtmp\\3"), true, true, NULL, NULL, true);
			}
		}
	}

	if(0 == _taccess_s(csTempPath + _T("smtmp\\4"), 0))
	{
		SHGetFolderPath(0, CSIDL_COMMON_DESKTOPDIRECTORY, 0, 0, szDesktop);
		csDesktop = szDesktop[0]? szDesktop: BLANKSTRING;
		if(BLANKSTRING != csDesktop)
		{
			bFoundShortcut = true;
			objDirMgr.MaxCopyDirectory(szDesktop, csTempPath + _T("smtmp\\4"), true, true, NULL, NULL, true);
		}

	}

	objDirMgr.MaxDeleteDirectory(csTempPath + _T("smtmp"), _T(""), true, true);
	return bFoundShortcut;
}
