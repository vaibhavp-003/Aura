/*====================================================================================
   FILE				: RandomInfectedFiles.cpp
   ABSTRACT			: This class is used for scanning and qurantining random and multiple spyware
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Shweta Mulay
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 25/12/2003
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
					version: 2.5.0.49
					Resource : Shweta Mulay
					Description: Added code to exclude scshost.exe on Server2003
					version: 2.5.0.59
					Description: Added code for fixing karna.dat

========================================================================================*/

#include "pch.h"
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "RandomInfectedFiles.h"
#include "StringFunctions.h"
#include "SpecialSpyHandler.h"
#include "MaxDSrvWrapper.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForRandomFiles
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and remove random files
	Author			: 
	Description		: Searches for files with wildcard in folder
--------------------------------------------------------------------------------------*/

bool CRandomInfectedFiles::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		CMaxDSrvWrapper objMaxDSrvWrapper;
		objMaxDSrvWrapper.InitializeDatabase();
		if(bToDelete || !objMaxDSrvWrapper.IsExcluded(m_ulSpyName, L"", L""))
		{
			if(CheckReportDeleteRegKey( HKEY_LOCAL_MACHINE, SOFTWARE , _T("ShudderLTD"), 7586, bToDelete ))
				m_bSplSpyFound = true;

		}

		if ( m_bScanOtherLocations )
		{

			if(bToDelete || !objMaxDSrvWrapper.IsExcluded(m_ulSpyName, L"", L""))
			{	
				if( CheckReportDeleteRegKey( HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node" , _T("ShudderLTD"), 7586, bToDelete ))
					m_bSplSpyFound = true;
			}
		}

		CString csRoot;
		csRoot = CSystemInfo :: m_strRoot ;
		//ToDo : EHere
		//if(bToDelete || !CheckInExcludeDB(*m_pHoldExcludeDBList,3760))
		if(bToDelete)
		{
			if(FindExeAndRemove(3760, CSystemInfo::m_strSysDir, _T("ld????.tmp"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strSysDir, _T("hp???.tmp"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strSysDir, _T("tool?.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strSysDir, _T("mdms.exe"), bToDelete))
				m_bSplSpyFound = true;
			

			if ( m_bScanOtherLocations )
			{
				if(FindExeAndRemove(3760, m_csOtherSysDir , _T("ld????.tmp"), bToDelete))
					m_bSplSpyFound = true;

				if(FindExeAndRemove(3760, m_csOtherSysDir , _T("hp???.tmp"), bToDelete))
					m_bSplSpyFound = true;

				if(FindExeAndRemove(3760, m_csOtherSysDir , _T("tool?.exe"), bToDelete))
					m_bSplSpyFound = true;

				if(FindExeAndRemove(3760, m_csOtherSysDir , _T("mdms.exe"), bToDelete))
					m_bSplSpyFound = true;
			}
		
			CStringArray csArrIgnorelist; // 2.5.0.49
			CString csPath;
			csPath.Format(_T("%s\\Common Files\\Microsoft Shared\\Web Folders"), static_cast<LPCTSTR>(CSystemInfo::m_strProgramFilesDir));
			if(FindExeAndRemove(3760, csPath, _T("ibm*.*"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, csPath, _T("?ibm*.*"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strWinDir, _T("s??host?.exe"), bToDelete))
				m_bSplSpyFound = true;

			// 2.5.0.49
			csArrIgnorelist.Add ( _T( "\\svchost.exe" ) ) ;
			csArrIgnorelist.Add ( _T( "\\scshost.exe" ) ) ;

			if(FindExeAndRemove(3760, CSystemInfo::m_strSysDir , _T("s??host?.exe"), bToDelete, csArrIgnorelist))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strSysDir , _T("vxgame*.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strSysDir , _T("vxh*.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strSysDir , _T("?vxgame*.exe"), bToDelete))
				m_bSplSpyFound = true;

			if ( m_bScanOtherLocations )
			{
				if(FindExeAndRemove(3760, m_csOtherSysDir , _T("s??host?.exe"), bToDelete, csArrIgnorelist ))// 2.5.0.49
					m_bSplSpyFound = true;

				if(FindExeAndRemove(3760, m_csOtherSysDir , _T("vxgame*.exe"), bToDelete))
					m_bSplSpyFound = true;

				if(FindExeAndRemove(3760, m_csOtherSysDir , _T("vxh*.exe"), bToDelete))
					m_bSplSpyFound = true;

				if(FindExeAndRemove(3760, m_csOtherSysDir , _T("?vxgame*.exe"), bToDelete))
					m_bSplSpyFound = true;
			}

			if(FindExeAndRemove(3760, csRoot, _T("lo*.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strWinDir, _T("mousepad*.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strWinDir, _T("keyboard*.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, csRoot, _T("mousepad*.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, csRoot, _T("keyboard*.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, csRoot, _T("gimmysmile*.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strSysDir , _T("bum???.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strSysDir , _T("tio???.dll"), bToDelete))
				m_bSplSpyFound = true;

			if ( m_bScanOtherLocations )
			{
				if(FindExeAndRemove(3760, m_csOtherSysDir , _T("bum???.exe"), bToDelete))
					m_bSplSpyFound = true;

				if(FindExeAndRemove(3760, m_csOtherSysDir , _T("tio???.dll"), bToDelete))
					m_bSplSpyFound = true;
			}

			if(FindInetDir(3760, CSystemInfo::m_strWinDir, _T("\\inet20"), bToDelete))
				m_bSplSpyFound = true;

			if(CheckForInvalidDesktop(bToDelete))
				m_bSplSpyFound = true;

			if ( FindExeAndRemove ( 3760 , CSystemInfo::m_strSysDir , _T("tetriz?.exe") , bToDelete ) )
				m_bSplSpyFound = true;

			if ( FindExeAndRemove ( 3760 , CSystemInfo::m_strSysDir , _T("newname?.exe") , bToDelete ) )
				m_bSplSpyFound = true;

			if ( m_bScanOtherLocations )
			{
				if ( FindExeAndRemove ( 3760 , m_csOtherSysDir , _T("tetriz?.exe") , bToDelete ) )
					m_bSplSpyFound = true;

				if ( FindExeAndRemove ( 3760 , m_csOtherSysDir , _T("newname?.exe") , bToDelete ) )
					m_bSplSpyFound = true;
			}

			if(FindExeAndRemove(3760, CSystemInfo::m_strWinDir, _T("newname?.exe"), bToDelete))
				m_bSplSpyFound = true;
			
			if(FindExeAndRemove(3760, CSystemInfo::m_strWinDir, _T("sys*2006.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strWinDir, _T("win*2006.exe"), bToDelete))
				m_bSplSpyFound = true;

			if(FindExeAndRemove(3760, CSystemInfo::m_strWinDir, _T("ms*2006.exe"), bToDelete))
				m_bSplSpyFound = true;	
		}
					
		
		if(IsStopScanningSignaled())
		{
			objMaxDSrvWrapper.DeInitializeDatabase();
			return m_bSplSpyFound;
		}

		if(bToDelete || !objMaxDSrvWrapper.IsExcluded(m_ulSpyName, L"", L""))
		{

			if ( CheckAndRemoveDriver ( 1497 , _T("directprt") , m_objSysInfo . m_strSysDir + _T("\\directprt.SYS"), m_csArrCrackzTrojan , bToDelete ) )
				m_bSplSpyFound = true;

			if ( m_bScanOtherLocations )
			{
				if ( CheckAndRemoveDriver ( 1497 , _T("directprt") , m_csOtherSysDir + _T("\\directprt.SYS"), m_csArrCrackzTrojan , bToDelete ) )
					m_bSplSpyFound = true;
			}
		}

		//version 2.5.0.59
		if ( !_taccess ( m_objSysInfo.m_strWinDir + _T("\\karna.dat") , 0 ))
		{
			if ( bToDelete )
			{
				AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, CSystemInfo::m_strWinDir + _T("\\karna.dat"));
			}
			else
			{
				m_bSplSpyFound = true;
				SendScanStatusToUI  ( Special_File , 295,  m_objSysInfo.m_strWinDir + _T("\\karna.dat")  ) ;
			}
		}

		if(!objMaxDSrvWrapper.IsExcluded(m_ulSpyName, L"", L""))
		{
			if ( !_taccess ( m_objSysInfo.m_strSysDir + _T("\\olemdb32.dll") , 0 ) )
			{
				if ( bToDelete )
				{
					AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, m_objSysInfo.m_strSysDir + _T("\\olemdb32.dll"));
					//CQuarantineFile::AddInRestartDeleteList(_T("Trojan.Agent^") + m_objSysInfo.m_strSysDir + _T("\\olemdb32.dll"), _T("File"));
				}
				else
				{
					m_bSplSpyFound = true;
					SendScanStatusToUI (Special_File ,  295,  m_objSysInfo.m_strSysDir + _T("\\olemdb32.dll") ) ;
				}
			}

			if ( !_taccess ( m_objSysInfo . m_strRoot + _T ( "\\pooh.vbs" ) , 0 ) )
			{
				if ( bToDelete )
				{
					AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, m_objSysInfo . m_strRoot + _T ( "\\pooh.vbs" ));
				}
				else
				{
					m_bSplSpyFound = true;
					SendScanStatusToUI ( Special_File , 295,  m_objSysInfo . m_strRoot + _T ( "\\pooh.vbs" ) ) ;
				}
			}
		}

		if(bToDelete)
		{
			// Dont show this entries in the ListView. We dont want to delete them while quarantine, but only on restart!
			if(m_objReg.KeyExists ( CString(SERVICES_MAIN_KEY) + CString(_T("sysbus32")), HKEY_LOCAL_MACHINE))
			{
				AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, CSystemInfo::m_strSysDir + _T("\\drivers\\sysbus32.sys"));
				if ( m_bScanOtherLocations )
					AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, m_csOtherSysDir + _T("\\drivers\\sysbus32.sys"));
			}

			// Dont show this entries in the ListView
			// We dont want to delete them while quarantine, but only on restart!
			if(m_objReg.KeyExists ( CString(SERVICES_MAIN_KEY) + CString(_T("AlfaCleaner")), HKEY_LOCAL_MACHINE))
			{
				AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, CSystemInfo::m_strSysDir + _T("\\drivers\\hesvc.sys"));
				if ( m_bScanOtherLocations )
					AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, m_csOtherSysDir + _T("\\drivers\\hesvc.sys"));
			}

			CString sPath(CSystemInfo::m_strSysDir);
			sPath += _T("\\Win.ini");
			FixINIFile(sPath, _T("Windows"), _T("Run"), _T("inet20"));
			FixINIFile(sPath, _T("Windows"), _T("Load"), _T("inet20"));

			sPath = CSystemInfo::m_strSysDir;
			sPath += _T("\\System.ini");
			FixINIFile(sPath, _T("Windows"), _T("Run"), _T("inet20"));
			FixINIFile(sPath, _T("Windows"), _T("Load"), _T("inet20"));
		}
		
		objMaxDSrvWrapper.DeInitializeDatabase();

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CRandomInfectedFiles::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForInvalidDesktop
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks if the file is a hotbar file
	Author			: Anand
	Description		: check in registry for infected desktop entry
--------------------------------------------------------------------------------------*/
bool CRandomInfectedFiles::CheckForInvalidDesktop ( bool bFixInfection )
{
	try
	{
		CString csRegKey , csRegCommonKey ;
		CString csData ;
		bool bInfectionFound = false ;

		if ( StrStrI ( m_objSysInfo . m_strOS , W95 ) ||
			StrStrI ( m_objSysInfo . m_strOS , W98 ) ||
			StrStrI ( m_objSysInfo . m_strOS , WME ) ||
			StrStrI ( m_objSysInfo . m_strOS , WNT4 )||
			StrStrI ( m_objSysInfo . m_strOS , W2K ) )
		{
			csRegKey = _T("Software\\Microsoft\\Internet Explorer\\Desktop\\General") ;
		}
		else if ( StrStrI ( m_objSysInfo . m_strOS , WXP ) )
		{
			csRegKey = _T("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\LastTheme") ;
		}
		else
		{
			return ( false ) ;
		}

		// this is common for all OS
		csRegCommonKey = _T("Software\\Microsoft\\Internet Explorer\\Desktop\\General") ;

		if ( bFixInfection )
		{
			// Darshan
			// 25-June-2007
			// Added code to loop thru all users under HKEY_USERS
			for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
			{
				if(IsStopScanningSignaled())
					break;
				CString csUserKey = m_arrAllUsers.GetAt(iCnt);
				m_objReg . Get ( csUserKey + _T("\\") + csRegKey , _T("Wallpaper") , csData , HKEY_USERS) ;
				if ( -1 != csData . MakeLower () . Find ( _T("security.htm") ) )
				{
					csData = _T("") ;
					m_objReg . Set ( csUserKey + _T("\\") + csRegKey , _T("Wallpaper") , csData , HKEY_USERS ) ;
				}

				m_objReg . Get ( csUserKey + _T("\\") + csRegCommonKey , _T("Wallpaper") , csData , HKEY_USERS ) ;
				if ( -1 != csData . MakeLower () . Find ( _T("security.htm") ) )
				{
					csData = _T("") ;
					m_objReg . Set ( csUserKey + _T("\\") + csRegCommonKey , _T("Wallpaper") , csData , HKEY_USERS ) ;
				}

				if ( IsWallpaperPresent ( csData ) )
				{
					SetFileAttributes ( csData , FILE_ATTRIBUTE_NORMAL ) ;
					if ( !DeleteFile ( csData ) )
					{
						AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, csData);
					}
				}
			}

			IsDesktopUninstallKeyPresent ( bFixInfection ) ;
		}
		else
		{
			// Darshan
			// 25-June-2007
			// Added code to loop thru all users under HKEY_USERS
			for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
			{
				if(IsStopScanningSignaled())
					break;
				CString csUserKey = m_arrAllUsers.GetAt(iCnt);
                DWORD dwRegType =0;
				m_objReg . Get ( csUserKey + _T("\\") + csRegKey , _T("Wallpaper") , csData , HKEY_USERS , &dwRegType) ;
				if ( -1 != csData . MakeLower () . Find ( _T("security.htm") ) )
				{
					bInfectionFound = true ;
                    SendScanStatusToUI ( Special_RegVal , 6161 , HKEY_USERS ,  csUserKey + _T("\\") + csRegKey ,  _T("Wallpaper")  ,  dwRegType, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR));
				}

                dwRegType =0;
				m_objReg . Get ( csUserKey + _T("\\") + csRegCommonKey , _T("Wallpaper") , csData , HKEY_USERS, &dwRegType);
				if ( -1 != csData . MakeLower () . Find ( _T("security.htm") ) )
				{
					bInfectionFound = true ;					
                    SendScanStatusToUI ( Special_RegVal , 6161 , HKEY_USERS ,  csUserKey + _T("\\") + csRegKey ,  _T("Wallpaper")  , dwRegType, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR));
				}

				if ( IsWallpaperPresent ( csData ) )
				{
					bInfectionFound = true ;
					SendScanStatusToUI ( Special_File , 6161 , csData ) ;
				}
			}

			IsDesktopUninstallKeyPresent ( bFixInfection ) ;
		}
		return ( bInfectionFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CheckForInvalidDesktop, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}


/*-------------------------------------------------------------------------------------
	Function		: IsWallpaperPresent 
	In Parameters	: 
	Out Parameters	: CString &
	Purpose			: check if infected wallpaper present
	Author			: Anand
	Description		: check in sysDir and look for keywords
--------------------------------------------------------------------------------------*/
bool CRandomInfectedFiles::IsWallpaperPresent ( CString & csWallFilename )
{
	try
	{
		bool bFound = false ;
		char * string = "http://www.topadwarereviews.com" ;

		csWallFilename = CSystemInfo::m_strWinDir + _T("\\security.html") ;
		if ( !_taccess_s ( csWallFilename , 0 ) )
		{
			int hFile = -1 ;

			_tsopen_s ( &hFile , csWallFilename , _O_RDONLY | _O_BINARY , _SH_DENYNO , _S_IREAD | _S_IWRITE ) ;
			if ( hFile == -1 )
			{
				csWallFilename = _T("") ;
				return ( bFound ) ;
			}

			SearchString ( hFile , string , &bFound ) ;
			_close ( hFile ) ;
			return ( bFound ) ;
		}

		csWallFilename = _T("") ;
		return ( bFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in IsWallpaperPresent, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false ;
}//End Of Function is wall paper present


/*-------------------------------------------------------------------------------------
	Function		: IsDesktopUninstallKeyPresent
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks if the file is a hotbar file
	Author			: Anand
	Description		: check for desktop uninstall key present
--------------------------------------------------------------------------------------*/
bool CRandomInfectedFiles::IsDesktopUninstallKeyPresent ( bool bToDelete )
{
	try
	{
		CString csRegKey = _T("Software\\Microsoft\\Internet Explorer\\Desktop\\Components") ;
		CStringArray csArrSubKeys ;
		CString csFullKey , csData ;
		int i = 0 ;

		// Darshan
		// 25-June-2007
		// Added code to loop thru all users under HKEY_USERS
		for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
		{
			if(IsStopScanningSignaled())
				break;
			CString csUserKey = m_arrAllUsers.GetAt(iCnt);
			m_objReg.EnumSubKeys(csUserKey + _T("\\") + csRegKey , csArrSubKeys , HKEY_USERS) ;
			for ( i = 0 ; i < csArrSubKeys . GetCount() ; i++ )
			{
				if(IsStopScanningSignaled())
					break;

				csFullKey = csUserKey + BACK_SLASH + csRegKey + BACK_SLASH + csArrSubKeys [ i ] ;
				m_objReg.Get( csFullKey , _T("FriendlyName") , csData , HKEY_USERS) ;
				if ( -1 != csData.MakeLower().Find( _T("desktop uninstall") ) )
				{
					if ( !bToDelete )
					{
						SendScanStatusToUI (Special_RegKey ,  7586 , HKEY_USERS ,  
							csUserKey + CString(BACK_SLASH) + csRegKey + CString(BACK_SLASH) + csArrSubKeys [ i ] , 0,0,0,0 ) ;
					}
				}
			}
		}
	
		return true ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in IsDesktopUninstallKeyPresent, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;	
}

/*-------------------------------------------------------------------------------------
	Function		: FindInetDir
	In Parameters	: CString , CString , CString , bool 
	Out Parameters	: 
	Purpose			: Checks and removes folder with given name
	Author			: 
	Description		: Checks and removes folder with given name
--------------------------------------------------------------------------------------*/
bool CRandomInfectedFiles::FindInetDir(ULONG ulSpyName, CString csPath, CString sLookUp, bool bRemoveIt)
{
	try
	{
		CFileFind  objFile;
		bool bRetVal = false;

		if(IsStopScanningSignaled())
			return false;

		csPath += _T("\\*.*");
		BOOL bFound = objFile.FindFile(csPath);

		while(bFound)
		{  
			bFound = objFile.FindNextFile();
			if (objFile.IsDots())
				continue;

			if (!objFile.IsDirectory())// we are only interested in directories, ignore all files
				continue;
		
			CString csDirPath = objFile.GetFilePath();
			if(csDirPath.Find(sLookUp) != -1)
			{
				bRetVal = true;
				if(!bRemoveIt)
					SendScanStatusToUI(Special_Folder, ulSpyName, csDirPath);
				//Enum this folder and all sub folders and send all files to ui!
				RemoveFolders(csDirPath, ulSpyName, bRemoveIt);
				break;
			}
		}
		objFile.Close();
		return bRetVal;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in IsDesktopUninstallKeyPresent, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

