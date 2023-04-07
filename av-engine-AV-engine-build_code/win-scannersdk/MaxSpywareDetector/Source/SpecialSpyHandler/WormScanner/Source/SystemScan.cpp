/*====================================================================================
   FILE				: SystemScan.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware which are in sys and win dir
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
					Version: 2.5.0.7
					Resource : Vikram
					Description: Fixed the random dlls of Trojan Delf

					Version: 2.5.0.8
					Resource : Avinash B
					Description: Added code for detecting msdebug.dll files and other appinit dlls

					Version: 2.5.0.14
					Resource : Shweta
					Description: Added code for newly added delf files.
					
					Version: 2.5.0.16
					Resource : Shweta
					Description: Added code for About blank files(CheckforAboutBlank).

					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability

					version: 2.5.0.78
					Resource : Shweta Mulay
					Description: Added code for Winblue soft Spyware random entries
                    
                    version:  2.5.0.00
					Resource : vaibhav desai
					Description: Added code for detecting random infection of monder 

					version:  2.5.1.07
					Resource : vaibhav desai
					Description: Added code for detecting infection of Dreamy worm
                            
====================================================================================*/

#include "pch.h"
#include "SystemScan.h"
#include "StringFunctions.h"
#include "SpecialSpyHandler.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: searches full windows and system32 folders
	Author			: 
	Description		: scans complete windows and system32 folders
--------------------------------------------------------------------------------------*/
bool CSystemScan::ScanSplSpy( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		if ( bToDelete )
		{
			for ( int i = 0 ; i < m_csArrCommonInfectedFiles . GetSize() ; i++ )
				MoveFileEx ( m_csArrCommonInfectedFiles [ i ] , NULL , MOVEFILE_DELAY_UNTIL_REBOOT ) ;
		}
		else
		{
			m_csArrCommonInfectedFiles . RemoveAll() ;
			m_pFileSigMan = pFileSigMan;
			if(IsStopScanningSignaled())
				return false ;

			SEARCH_FOLDER_LIST SearchFoldersList[4] =
			{
				{ m_objSysInfo.m_strSysDir	, _T("*")} ,
				{ m_objSysInfo.m_strWinDir	, _T("*")} ,
				{ m_objSysInfo.m_strRoot	, _T("*")}
			} ;
			
			int nCount = sizeof SearchFoldersList / sizeof SearchFoldersList[0];

			if ( m_bScanOtherLocations )
			{
				SearchFoldersList [ nCount - 1] . csPath = m_csOtherSysDir ;
				SearchFoldersList [ nCount - 1] . csWildCard = _T("*") ;
			}

			m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
			m_pMaxDSrvWrapper->InitializeDatabase();

			for ( int idx = 0; idx < nCount ; idx++ )
			{
				if(IsStopScanningSignaled())
					return false ;

				if(_T("") != SearchFoldersList [ idx ] . csPath )
				{
					EnumerateFiles ( SearchFoldersList [ idx ] , pFileSigMan) ;
				}
			}

			m_pMaxDSrvWrapper->DeInitializeDatabase();
			delete m_pMaxDSrvWrapper;
			m_pMaxDSrvWrapper = NULL;
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::ScanSplSpy"), 0, 0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: EnumerateFiles
	In Parameters	: SEARCH_FOLDER_LIST
	Out Parameters	: 
	Purpose			: search files in folder
	Author			: Shweta M
	Description		: scan every file in the folder and send to UI
--------------------------------------------------------------------------------------*/
bool CSystemScan::EnumerateFiles ( SEARCH_FOLDER_LIST SFLVariable ,CFileSignatureDb *pFileSigMan )
{
	try
	{
		if(IsStopScanningSignaled())
			return false ;

		BOOL bReadFile		=	FALSE;
		BOOL bFileFlag		=	FALSE ;
		bool bIgnoreFile	=	false;

		CString csfilesz;
		DWORD  minsize = 750 * 1024 ;
		DWORD  maxsize = 800 * 1024 ;

		HANDLE hFile = NULL ;
		DWORD dwBytesRead = 0 ;
		CString csFullFileName, csSearchPath;
		FILETIME stLastModTime = {0};

		if(NULL == m_cFileBuff)
			return false;

		csSearchPath = SFLVariable.csPath + BACK_SLASH + SFLVariable.csWildCard;
		bFileFlag = m_objFile.FindFile( csSearchPath);
		if(!bFileFlag)
		{
			return true;
		}
		
		while(bFileFlag)
		{
			if(IsStopScanningSignaled())
			{
				break;
			}

			bFileFlag = m_objFile.FindNextFile();
			if(m_objFile.IsDots() || m_objFile.IsDirectory())
			{
				continue;
			}

			csFullFileName = m_objFile.GetFilePath();

			//ndisvvan, 13/May/2011, anand srivastava
			if(!m_pMaxDSrvWrapper->IsExcluded(iSPYID_WormKolab, L"", L""))
			{
				if(m_objFile.GetLastWriteTime(&stLastModTime))
				{
					if(CheckForWormKolab(csFullFileName, &stLastModTime, SFLVariable.csPath))
					{
						continue ;
					}
				}
			}

			//Version : 19.0.0.039
			//Resource: Shweta
			if(m_objFile.GetLength() < maxsize && m_objFile.GetLength() > minsize)
			{
				CheckForAdmokeFiles(csFullFileName);
				continue;
			}

			if(MAXIMUM_FILE_SIZE < m_objFile.GetLength())
			{
				continue;
			}

			bIgnoreFile = CheckExtension( m_objFile.GetFileName());
			if(bIgnoreFile)
				continue;

			csFullFileName = SFLVariable.csPath + _T("\\") + m_objFile.GetFileName() ;
			hFile = CreateFile( csFullFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE , 0 , OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if ( INVALID_HANDLE_VALUE == hFile)
				continue;
					
			csFullFileName.MakeLower();

			SetFilePointer ( hFile , 0 , 0 , FILE_BEGIN );
			bReadFile = ReadFile ( hFile , m_cFileBuff , (DWORD)m_objFile.GetLength() , &dwBytesRead , 0 ) ;
			
			if ( m_objFile.GetLength() != dwBytesRead )
			{
				CloseHandle ( hFile ) ;
				continue;
			}

			//version : 2.5.0.78
			//resopurce : Shweta Mulay
			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( CheckWinBlueSoft ( csFullFileName , m_cFileBuff , dwBytesRead ) )
				{
					CloseHandle ( hFile );
					continue;
				}

			}

			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( Check180FileCompany( csFullFileName))
				{
					CloseHandle ( hFile ) ;
					continue ;
				}
			}

			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( IsApherFile( csFullFileName, m_cFileBuff, dwBytesRead))
				{
					CloseHandle ( hFile ) ;
					continue ;
				}
			}

			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if( CheckIfHSAFile ( csFullFileName, m_cFileBuff, dwBytesRead))
				{
					CloseHandle ( hFile ) ;
					continue ;
				}
			}
			
			if ( CheckIfRandomSpyware( csFullFileName, m_cFileBuff, dwBytesRead))
			{
				CloseHandle ( hFile ) ;
				continue ;
			}

			//version : 19.0.0.12
			//resource: Anand
			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( CheckIfVSToolbarFile( csFullFileName, m_cFileBuff, dwBytesRead ))
				{
					CloseHandle( hFile);
					continue ;
				}
			}

			//version : 19.0.0.14
			//resource: Anand
			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( CheckIfISearchFile( csFullFileName, m_cFileBuff, dwBytesRead))
				{
					CloseHandle ( hFile ) ;
					continue ;
				}
			}

			//version : 19.0.0.39
			//resource: Anand
			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( CheckIfSpyLockedFile ( csFullFileName, m_cFileBuff, dwBytesRead, m_objFile.GetLength()))
				{
					CloseHandle ( hFile ) ;
					continue ;
				}
			}

			//version : 2.5.0.7
			//resource: Vikram
			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( CheckIfTrojanDelfFile ( csFullFileName, m_cFileBuff, dwBytesRead, m_objFile.GetLength()))
				{
					CloseHandle ( hFile ) ;
					continue ;
				}
			}
			
			//version : 2.5.0.16
			//resource: Shweta
			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( CheckforAboutBlank ( csFullFileName, m_cFileBuff, dwBytesRead, m_objFile.GetLength()))
				{
					CloseHandle ( hFile ) ;
					continue ;
				}
			}

			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( CheckforMonder(csFullFileName, m_cFileBuff, m_objFile.GetFileName(), m_objFile.GetLength()))
				{
					CloseHandle ( hFile ) ;
					continue ;
				}
			}

			//vaibhav
			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( CheckForDreamy( m_objFile.GetFilePath() , m_objFile.GetLength() ) )
				{
					CloseHandle ( hFile ) ;
					continue ;
				}
			}

            //Shweta mulay
			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( CheckforMalwareAgent ( csFullFileName, m_objFile.GetFileName(), pFileSigMan ,  m_objFile.GetLength()))
				{
					CloseHandle ( hFile ) ;
					continue ;
				}
			}

			//vaibhav
			if(!m_pMaxDSrvWrapper->IsExcluded(m_ulSpyName, L"", L""))
			{
				if ( CheckForStuh( csFullFileName , m_objFile.GetLength() ) )
				{
					CloseHandle ( hFile ) ;
					continue ;
				}
			}

			CloseHandle ( hFile ) ;
		}
		
		m_objFile.Close() ;
		return true ;
	}
	
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::EnumerateFiles"), 0, 0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: CheckForAdmokeFiles
In Parameters	: bool
Out Parameters	: 
Purpose			: check for admoke Files
Author			: Shweta
Description		: checks Admoke files
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckForAdmokeFiles ( const CString& csFileName )
{
	try
	{
		HANDLE hFile ;
		BYTE * cFileBuff = NULL ;
		DWORD dwBytesRead ;

		// check for extension
		CString csExt = csFileName.Right(4);
		csExt.MakeLower();
		if (csExt != _T(".exe"))
			return false;

		// checking if the location is sysdir
		if ( _tcsnicmp ( csFileName , CSystemInfo::m_strSysDir , _tcslen ( CSystemInfo::m_strSysDir ) ) )
		{
			// checking if the other location is to be checked
			if ( m_bScanOtherLocations )
			{
				// checking if the other location is sysdir
				if ( _tcsnicmp ( csFileName , m_csOtherSysDir , _tcslen ( m_csOtherSysDir ) ) )
					return ( false ) ;
			}
			else
			{
				return ( false ) ;
			}
		}

		hFile = CreateFile ( csFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if ( INVALID_HANDLE_VALUE == hFile )
			return (false) ;

		cFileBuff = new BYTE [ 1024 * 800 ] ;
		if ( !cFileBuff )
		{
			CloseHandle ( hFile ) ;
			return ( false ) ;
		}

		if ( FALSE == ReadFile( hFile, cFileBuff, (DWORD)m_objFile.GetLength(), &dwBytesRead, 0) )
		{
			CloseHandle ( hFile ) ;
			delete [] cFileBuff ;

			return ( false );
		}

		if ( m_objFile.GetLength() != dwBytesRead )
		{
			CloseHandle ( hFile ) ;
			delete [] cFileBuff ;
			
			return false;
		}	

		CloseHandle(hFile);
		if ( !CheckStringsinAdmokeFiles ( csFileName, cFileBuff, dwBytesRead))
		{
			delete [] cFileBuff ;
			return ( false ) ;
		}	

		if ( !FindServiceName( cFileBuff, dwBytesRead))
		{
			delete [] cFileBuff ;
			return ( false ) ;
		}

		delete [] cFileBuff ;

		if (! ChecknDelforAdmokeBHO())
			return false;

		m_bSplSpyFound = true ;
		
		SendScanStatusToUI (Special_File , 7545, csFileName);
			
		if ( m_objEnumProcess.IsProcessRunning(csFileName, false))
			SendScanStatusToUI ( Special_Process , 7545, csFileName);  

		CStringArray csArrAdMoke;
		CheckAndRemoveDriver( 7545 , m_csAdmokeServiceName , csFileName , csArrAdMoke , false );
		
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::CheckForAdmokeFiles "), 0, 0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckStringsinAdmokeFiles
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check for Strings in Admoke Files
	Author			: shweta
	Description		: checks the Strings in Admoke files
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckStringsinAdmokeFiles(CString csFileName , UCHAR * cFileBuff , DWORD dwBytes)
{
	try
	{
		char * Strings [] =
		{
			"mokead.com",
			"w1.okads.cn",
			"do.okads.cn",
			"trojan.clicker.adclick.b",
			"www.chaoym.com",
			"www.bagayalu.cn",
			"www.yymax.com",
			"www.akmov.com",
			"www.gotourl.cn",
			"www.jjmmgg.cn",
			"www.4ga.cn",
			"www.5ibmw.cn",
			"www.999ss.cn",
			"www.hzhyly.com",
			"www.yuheyoga",
			"www.seita.cn",
			"www.mokead.com/NewSetup.exe",
			NULL
		} ;

		for ( int i = 0 ; Strings [ i ] ; i++ )
		{
			if (!StrNIStr ( cFileBuff , dwBytes , (UCHAR*) Strings [ i ] , strlen ( Strings [ i ] ) ) )
				return ( false ) ;
		}

		return ( true ) ;
	}
	
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::CheckStringsinAdmokeFiles"), 0, 0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: FindServiceName
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Finds the Service name
	Author			: shweta
	Description		: Finds the Service Name for the file having the Strings
--------------------------------------------------------------------------------------*/
bool CSystemScan::FindServiceName ( UCHAR * cFileBuff , DWORD dwBytesRead )
{
	try
	{
		bool bServiceNameFound = false ;
		UCHAR * ptr = NULL ;
		UCHAR * ptrEndLocation = NULL ;

		// this is a precondition for the file to spyware file
		if ( !cFileBuff || dwBytesRead < 1024 )
			return ( false ) ;

		ptr = cFileBuff + ( dwBytesRead - 1024 ) ;
		ptr = StrNIStr ( ptr, 1024, (UCHAR*)"DisplayName", 11);
		if ( !ptr )
			return ( false ) ;

		// shift ptr by length of DisplayName, two bytes and SYS
		ptr += 11 + 2 + 3 ;

		// store the end location pointer
		ptrEndLocation = cFileBuff + dwBytesRead ;

		for ( int i = 0 ; ptr < ptrEndLocation ; i++ )
		{
			if ( !isalnum ( ptr[i]))
			{
				UCHAR hold = ptr[i];
				ptr[i] = 0 ;
				
				m_csAdmokeServiceName = ptr ;
				ptr [ i ] = hold ;
				bServiceNameFound = true ;
				break ;
			}
		}
		return bServiceNameFound;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::FindServiceName"), 0, 0);
	}
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: ChecknDelforAdmokeBHO 
	In Parameters	: void
	Out Parameters	: 
	Purpose			: Checks for BHO entry
	Author			: shweta
	Description		: Checks and sends the BHO entry to UI
--------------------------------------------------------------------------------------*/
bool CSystemScan::ChecknDelforAdmokeBHO( void )
{
	try
	{
		CString			csFileName;
		CStringArray	csArrBHO;
		CArray<CStringA,CStringA>	csArrStrings ;
		CStringArray	csArrBHOLocations ;

		csArrBHOLocations . Add ( BHO_REGISTRY_PATH ) ;
		if ( m_bScanOtherLocations )
			csArrBHOLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_BHO_REGISTRY_PATH) ) ;

		csArrStrings .Add("www.modadcom");
		csArrStrings .Add("mokead.com");
		csArrStrings .Add("www.baidu.com");
		csArrStrings .Add("www.sina.com.cn");
		csArrStrings .Add("www.sohu.com");
		csArrStrings .Add("www.sogua.com");
		csArrStrings .Add("www.mop.com");
		csArrStrings .Add("www.beareyes.com.cn");
		csArrStrings .Add("www.xxsy.net");
		csArrStrings .Add("www.mokead.com/NewSetup.exe");

		for ( int j = 0 ; j < csArrBHOLocations . GetCount() ; j++ )
		{
			m_objReg.EnumSubKeys( csArrBHOLocations [ j ] , csArrBHO, HKEY_LOCAL_MACHINE);
			int iBHOCount = (int)csArrBHO.GetCount();
			for ( int i = 0 ; i < iBHOCount; i++)
			{
				CString csBHO;
				csBHO = csArrBHO.GetAt(i);
				
				CStringArray	csArrCLSIDLocations ;

				csArrCLSIDLocations . Add ( CLSID_KEY ) ;
				if ( m_bScanOtherLocations )
					csArrCLSIDLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_REG_NOTIFY_ENTRY) ) ;

				for ( int k = 0 ; k < csArrCLSIDLocations . GetCount() ; k++ )
				{
					if ( m_objReg.KeyExists ( csArrCLSIDLocations [ k ] + csBHO + BACK_SLASH + INPROCSERVER32 , HKEY_LOCAL_MACHINE ) )
					{
						CString csCLSID = csArrCLSIDLocations [ k ] + csBHO;
						m_objReg.Get ( csCLSID + BACK_SLASH + INPROCSERVER32 , BLANKSTRING , csFileName, HKEY_LOCAL_MACHINE );
						if ( SearchStringsInFile (csFileName, csArrStrings))
						{
							SendScanStatusToUI ( Special_File , 7545 , csFileName ) ;
                            SendScanStatusToUI ( Special_RegKey , 7545 , HKEY_LOCAL_MACHINE, 
								+ csArrBHOLocations [ j ] + CString(BACK_SLASH) + csBHO ,0,0,0,0 );
							SendScanStatusToUI ( Special_RegKey , 7545 , HKEY_LOCAL_MACHINE, 
								 csArrCLSIDLocations [ k ] , 0,0,0,0 );
						}
					}
				}
			}
		}

		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::ChecknDelforAdmokeBHO"), 0, 0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckExtension
	In Parameters	: CString
	Out Parameters	: 
	Purpose			: Checks extension
	Author			: 
	Description		: checks against a list of extensions
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckExtension( CString csFileName )
{
	try
	{
		//version : 19.0.0.013
		//Resource : dipali
		//change in code - it was creating list for each file then compairing
		CStringArray	csAExtList ;
		CString			csExtension, csRet;

		csExtension  =	csFileName.Right(4);
		csExtension.MakeLower();

		if ( m_objAExtMap.Lookup(csExtension,csRet))
			return false;

		return true ;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::CheckExtension"), 0, 0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: Check180FileCompany
	In Parameters	: CString 
	Out Parameters	: 
	Purpose			: Check for 180 file
	Author			: Shweta M
	Description		: Check company name in the version tab
--------------------------------------------------------------------------------------*/
bool CSystemScan::Check180FileCompany ( CString csFullFileName ) 
{
	CString		csExt, csExeName;
	csExt = csFullFileName.Right(3);
	csExt.MakeLower();

	if ( csExt == _T("dll") || csExt == _T("dat") || csExt == _T("exe") )
	{
		if ( CheckCompanyName( csFullFileName, _T("180solutions") ))
		{
			m_bSplSpyFound = true;
			if (csFullFileName.Right(3) == _T("exe"))
				csExeName = csFullFileName;
			
			SendScanStatusToUI ( Special_File , 16 , csFullFileName  ) ;
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsApherFile
	In Parameters	: CString , UCHAR * , DWORD 
	Out Parameters	: bool * 
	Purpose			: determine if a Apher file
	Author			: Anand
	Description		: check name or keywords to determine
--------------------------------------------------------------------------------------*/
bool CSystemScan::IsApherFile( CString csFileName, UCHAR * FileBuffer, DWORD cbFileBuffer)
{
	try
	{
		char*  szApherString	=	"http://1800-search.com/all.exe" ;
		CString		csFilePath;
		CString		csFileExt;
		CString		csSearchPath;

		// check if the extension is exe and path is sysdir, only then process, or return
		csFileExt		=	csFileName.Right(3);
		csFilePath		=	csFileName.Left( csFileName.ReverseFind('\\'));
		csSearchPath	=	m_objSysInfo.m_strSysDir ;

		csFileExt.MakeLower();
		csFilePath.MakeLower();
		csSearchPath.MakeLower();

		if ( csFileExt == _T("exe")  && csFilePath == csSearchPath )
		{
			if ( StrNIStr ( FileBuffer, cbFileBuffer, (UCHAR*) szApherString, strlen(szApherString)))
			{	
				SendScanStatusToUI ( Special_File , 515 , csFileName  ) ;
				return true;
			}
		}
		else
		{
			CString csInfectedFile = m_objSysInfo.m_strWinDir + BACK_SLASH + _T("sys00.exe") ;

			if ( !_tcsicmp ( csInfectedFile, csFileName ) )
			{
				SendScanStatusToUI( Special_File , 515 , csFileName  ) ;
				return true;
			}
		}
		return false;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::IsApherFile"), 0, 0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfHSAFile
	In Parameters	: CString , UCHAR * , DWORD 
	Out Parameters	: 
	Purpose			: determine if HSA File
	Author			: 
	Description		: Searches for all the keyword list and returns true 
					  and adds them to UI
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckIfHSAFile( CString csFileName,UCHAR * FileBuffer, DWORD cbFileBuffer)
{
	char * Strings [] =
	{
		"WIN0",
		"WIN1",
		"WIN2",
		"NIWU",
		"UWIN",
		 NULL
	} ;

	DWORD i = 0 ;
	CString csExt ;

	csExt = csFileName.Right(3);
	csExt.MakeLower();
	if( csExt != _T("dll") && csExt != _T("dat") && csExt != _T("txt") && csExt != _T("log") &&	csExt != _T("exe") )
	{
		return false;
	}

	for ( i = 0; Strings[i]; i++)
	{
		if (!StrNIStr( FileBuffer, cbFileBuffer, (UCHAR*) Strings[i], strlen( Strings[i])))
			return false;
	}

	if ( ( csExt == _T("exe") ) && m_objEnumProcess.IsProcessRunning( csFileName, false))
		SendScanStatusToUI(Special_Process ,  2935, csFileName );  

    if ( ( csExt == _T("dll") ) )
	{
        CString ClassID = BLANKSTRING ;
		if(ClassID.GetLength() != 0)
		{
			SendScanStatusToUI( Special_RegKey , 2935 ,HKEY_LOCAL_MACHINE 
				, CString(CLSID_KEY) + ClassID , 0,0,0,0 );
			EnumKeysForHSA ( CLSID_KEY , HKEY_LOCAL_MACHINE , false , csFileName , ClassID );
			if ( m_bScanOtherLocations )
				EnumKeysForHSA ( CString(WOW6432NODE_REG_PATH) + CString(_T("classes\\clsid")) , HKEY_LOCAL_MACHINE , false , csFileName , ClassID ) ;
		}
	}//End Of if to check for dll to send value in ui of reg key
    
    SendScanStatusToUI ( Special_File , 2935 , csFileName  ) ;
	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: EnumKeysForHSA
	In Parameters	: CString , HKEY , bool 
	Out Parameters	: CString& 
	Purpose			: Checks all SubKeys under given key
	Author			: 
	Description		: stops sevice and removes registry keys and sends them to UI
--------------------------------------------------------------------------------------*/
bool CSystemScan::EnumKeysForHSA ( CString csMainKey , HKEY hHiveKey , bool bRemove , CString csExePath , CString& csDllClassID )
 {
	try
	{
		long lVal = 0;
		CStringArray	spyExes, csSubKeyArr ;
		CString			csSubKey;		
		CString			strSubKey;
		HKEY			hSubKey;
		CStringArray csRunEntries;

		m_objReg.EnumSubKeys( csMainKey, csSubKeyArr, hHiveKey);

		for ( long i = 0; i < csSubKeyArr.GetCount(); i++)
		{
			csSubKey = csMainKey + BACK_SLASH + csSubKeyArr .GetAt ( i );
			csSubKey.MakeLower();
			strSubKey = _T("");
			
			if( ( CheckRegKey ( csSubKey , _T("localserver"),   hHiveKey, strSubKey ) )	|| 
				  CheckRegKey ( csSubKey , _T("localserver32"), hHiveKey, strSubKey ) || 
				  CheckRegKey ( csSubKey , _T("InprocServer32"), hHiveKey, strSubKey )  )
			{				
				csSubKey = csSubKey + BACK_SLASH + strSubKey ;				
				lVal = RegOpenKeyEx ( hHiveKey , csSubKey , 0 , KEY_READ | KEY_QUERY_VALUE , &hSubKey );
				if ( lVal != ERROR_SUCCESS )
				{
					RegCloseKey ( hSubKey );
					continue ;
				}

				CString csData;
				m_objReg.Get( csSubKey , BLANKSTRING , csData , hHiveKey );

				if( csData == BLANKSTRING )
				{
					RegCloseKey ( hSubKey );
					continue ;
				}
                if ( ( csData.Find(_T(".dll")) != -1 ) )
				{
					if ( csData . MakeLower() == csExePath . MakeLower () ) 
					{
						csDllClassID = csSubKeyArr .GetAt ( i ) ;
						RegCloseKey ( hSubKey );
						return true;
					}
				}

				bool bFound = false;				
				CString sTemp;
				for ( int k = 0 ; k < csRunEntries.GetCount () ; k ++ )
				{
					sTemp = csRunEntries.GetAt ( k ) ;
					if ( csData . MakeLower () == sTemp . MakeLower () )
					{
						bFound = true ; 
						spyExes . Add ( csData ) ;						
					}//End Of If To Make The ExePath LowerCase
				}//End Of For Loop To Check With Entries Caught And Add The ExePath To Remove it
				
				if( csData . MakeLower() == csExePath . MakeLower () )
					bFound = true;
                
				//Delete key in CLSID
				if( bFound )
				{
					csData = csSubKeyArr .GetAt ( i ) ;
					SendScanStatusToUI ( Special_RegKey , 2935 , hHiveKey , csMainKey + CString(BACK_SLASH) + csData , 0,0,0,0 );
				}//End of if to check wether Required Key found
				RegCloseKey ( hSubKey ) ;
			}//End of if to Check csSubKey is LocalServer Or LocalServer32
		}//End Of For to traverse the clsid and find the exe
		
		//Now Kill all spy exes and delete run entries
		for ( int j=0 ; j < spyExes . GetCount ( ) ; j ++ )
		{
            strSubKey = spyExes . GetAt ( j );		
			//Remove spyware exe
			if ( m_objEnumProcess . IsProcessRunning ( strSubKey , false ) )
				SendScanStatusToUI ( Special_Process , 2935 , strSubKey  );  

			if ( strSubKey .GetLength () > 4 )
			SendScanStatusToUI ( Special_File , 2935 , strSubKey  );

			csSubKey = strSubKey . Mid ( strSubKey . ReverseFind ( '\\' ) + 1 , strSubKey . GetLength () );			
			SendScanStatusToUI ( Special_RegVal , 2935 , HKEY_LOCAL_MACHINE , CString(RUN_REG_PATH) ,
                csSubKey , REG_SZ , (LPBYTE)(LPCTSTR)strSubKey , strSubKey.GetLength());
            //CString(RUN_REG_PATH) , csSubKey , REG_SZ, (LPBYTE)strSubKey.GetBuffer(MAX_PATH) , strSubKey.GetLength());
            //strSubKey.ReleaseBuffer();
		}//End of For Loop To Kill All Spy Exe
	}
	catch (...)	
	{ 
		AddLogEntry(_T("Exception caught in  CSystemScan::EnumKeysForHSA"), 0, 0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfRandomSpyware
	In Parameters	: CString , BYTE * , DWORD 
	Out Parameters	: 
	Purpose			: check and find random files
	Author			: Anand
	Description		: checks for random spywares in system32 folder and matches with signatures
					  makes entry in unknown temp file
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckIfRandomSpyware ( CString csFullFileName, BYTE* cFileBuff, DWORD cbFileBuff )
{
	bool bInfectedFile = false ;
	
	CStringArray csArrSignatures ;
	
	// check if the extension is exe and path is sysdir, only then process, or return
	CString	 csExt	=	csFullFileName.Right(3);
	CString  csPath =	csFullFileName.Left( csFullFileName.ReverseFind('\\'));
	CString  csSysDir = m_objSysInfo.m_strSysDir;
	csExt.MakeLower();
	csPath.MakeLower();
	csSysDir.MakeLower();
	
	if( csExt != _T("exe")  || csPath != csSysDir )
		return ( bInfectedFile ) ;

/*	// all the signature added should be in upper case
	csArrSignatures.Add ( _T("AF42B8B2B65CBC7F8DC1E59E856FE124") ) ;
	csArrSignatures.Add ( _T("EA47A964389E558AAA929737CFDC5D72") ) ;

	CString Signature ;
	Signature = m_pFileSigMan->GetSignature(csFullFileName);
	Signature.MakeUpper() ;

	// check in the array
	for ( int i = 0 ; i < csArrSignatures.GetCount() && !bInfectedFile ; i++ )
		bInfectedFile = Signature == csArrSignatures [ i ] ;
*/
	BYTE bMD5Signature[16] = {0};
	const BYTE MD5_RANDOMSPYWARE_1[16] = {0xAF,0x42,0xB8,0xB2,0xB6,0x5C,0xBC,0x7F,0x8D,0xC1,0xE5,0x9E,0x85,0x6F,0xE1,0x24};
	const BYTE MD5_RANDOMSPYWARE_2[16] = {0xEA,0x47,0xA9,0x64,0x38,0x9E,0x55,0x8A,0xAA,0x92,0x97,0x37,0xCF,0xDC,0x5D,0x72};
	if(m_pFileSigMan->GetMD5Signature(csFullFileName, bMD5Signature))
	{
		if((!memcmp(bMD5Signature, MD5_RANDOMSPYWARE_1, 16)) || (!memcmp(bMD5Signature, MD5_RANDOMSPYWARE_2, 16)))
			bInfectedFile = true;
	}

	// if the flag is true add them to file
	if ( bInfectedFile )
	{
		FILE *fp = NULL ;
		_tfopen_s ( &fp , m_objSysInfo.m_strAppPath + _T("unkwn.tmp") , _T("a") );
		if ( fp )
		{
			_fputts ( csFullFileName , fp ) ;
			_fputts ( _T("\r\n") , fp ) ;
			fclose ( fp ) ;
		}
	}
	return bInfectedFile;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfVSToolbarFile
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: check for random entries of VSToolbar
	Author			: Anand
	Description		: checks the exe file in sysdir folder and search for VS.VsToolbar
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckIfVSToolbarFile( CString csFileName, BYTE *cFileBuff, DWORD cbFileBuff )
{
	try
	{
		// check if the extension is dll and path is sysdir, only then process, or else just return
		CString csExt	 =	csFileName.Right(3);
		CString csPath	 =	csFileName.Left(csFileName.ReverseFind('\\'));
		CString csSysDir =	m_objSysInfo.m_strSysDir;

		csExt.MakeLower();
		csPath.MakeLower();
		csSysDir.MakeLower();
		if ( csExt != _T("exe") || csPath != csSysDir )
			return ( false ) ;
		
		CFileVersionInfo	oFileVersionInfo;

		if ( !oFileVersionInfo.DoTheVersionJob( csFileName, false))
			return ( false ) ;

		if ( !StrNIStr( cFileBuff, cbFileBuff, (BYTE*) "Adware.VSToolbar", 12))
			return ( false ) ;

		SendScanStatusToUI ( Special_File , 7020 , csFileName ) ;
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::CheckIfVSToolbarFile"),0, 0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfISearchFile
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: check random isearch file in windows folder
	Author			: Anand
	Description		: checks an array of keywords for files in windows folder
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckIfISearchFile ( CString csFullFileName, BYTE *cFileBuff, DWORD dwBytesRead )
{
	try
	{
		CArray<CStringA,CStringA> csArrKeywords ;

		// Check if the extension is exe and path is windir, only then process, else return
		CString csExt	=	csFullFileName.Right(3);
		CString csPath	=	csFullFileName.Left(csFullFileName.ReverseFind('\\'));
		CString csWinDir =	m_objSysInfo.m_strWinDir ;

		// make lower case to all file names
		csExt.MakeLower();
		csPath.MakeLower();
		csWinDir.MakeLower();

		// if extension is not _T("exe") or path is not windows, just return false
		if ( csExt != _T("exe")  || csPath != csWinDir )
			return false;

		// make keywords array to scan the files
		csArrKeywords.Add ( "iSearch.com" ) ;
		csArrKeywords.Add ( "iSearch Toolbar" ) ;

		// search for entire array of keywords, and return false if the array is not found
		if ( !SearchStringsInFile ( csFullFileName , csArrKeywords ) )
			return ( false ) ;

		// now look for a dat file in same path and same name, so get filename without extension
		csPath = csFullFileName.Left(csFullFileName.GetLength() - 3 );
		if ( _taccess ( csPath + _T("dat") , 0 ) )
			return false;

		// free the keywords list and remake the new one
		csArrKeywords.RemoveAll();
		csArrKeywords.Add( "iSearch Toolbar" ) ;

		// search for entire array of keywords, and return false if the array is not found
		if ( !SearchStringsInFile ( csPath + _T("dat") , csArrKeywords ) )
			return false ;

		// send entries fonud to UI
		SendScanStatusToUI ( Special_File , 3260 , csFullFileName  ) ;
		SendScanStatusToUI ( Special_File , 3260 , csPath + _T("dat") ) ;
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::CheckIfISearchFile"), 0, 0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfSpyLockedFile
	In Parameters	: const CString&, UCHAR*, DWORD, int
	Out Parameters	: bool
	Purpose			: check file to be spylock
	Author			: Anand
	Description		: checks the path, ext, version tab, size and strings to determine spylock file
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckIfSpyLockedFile( const CString& csFullFileName , UCHAR * cFileBuff ,
										 DWORD dwBytesRead , ULONGLONG iFileLength )
{
	try
	{
		if(IsStopScanningSignaled())
			return false ;

		int iLocation = 0 ;
		bool bStringsFound = true ;

		// check the size, it must be between 6 and 8 KB
		if ( ( iFileLength > 1024 * 8 ) || ( iFileLength < 1024 * 6 ) )
			return ( false ) ;

		// check the extension to be dll
		iLocation = csFullFileName.ReverseFind('.');
		if ( -1 == iLocation )
			return false;

		CString csPart  =  csFullFileName.Right( csFullFileName.GetLength() - iLocation - 1);
		if ( csPart.IsEmpty())
			return false ;

		if ( 0 != csPart.CompareNoCase( _T("dll") ))
			return false;

		// check the path to be sysdir
		iLocation = csFullFileName.ReverseFind('\\');
		if ( -1 == iLocation )
			return false ;

		csPart = csFullFileName.Left( iLocation);
		if ( csPart.IsEmpty())
			return  false ;

		if ( 0 != csPart.CompareNoCase( m_objSysInfo.m_strSysDir ))
		{
			if ( m_bScanOtherLocations )
			{
				if ( 0 != csPart . CompareNoCase ( m_csOtherSysDir ) )
					return ( false ) ;
			}
			else
			{
				return ( false ) ;
			}
		}

		// check the version tab
		CFileVersionInfo	oFileVersionInfo;
		if ( !oFileVersionInfo.DoTheVersionJob ( csFullFileName , false ) )
			return  false;

		// now check for the strings
		CHAR * uStringArray1 [] = {
										"UPX0" ,
										"UPX1" ,
										" System Al" ,
										" detecd a numb" ,
										"ive spywa" ,
										"peica" ,
										"may imp" ,
										"o gt rid"
									};

		// now check for the strings
		CHAR * uStringArray2 [] = {
									"UPX0" ,
									"UPX1" ,
									"334.dll"		//Version: 19.0.0.041, Resource: Anand
								  };

		// check that all the strings are present in the file buffer
		for ( int i = 0; bStringsFound && i < ( sizeof(uStringArray1)/ sizeof(uStringArray1[0])); i++ )
			bStringsFound = !!StrNIStr ( cFileBuff , dwBytesRead , (UCHAR*)uStringArray1[i], strlen( uStringArray1[i]));

		if ( !bStringsFound )
		{
			bStringsFound = true ;
			
			// check that all the strings are present in the file buffer
			for ( int i = 0 ; bStringsFound && i < ( sizeof ( uStringArray2 ) / sizeof ( uStringArray2 [ 0 ] ) ) ; i++ )
				bStringsFound = !!StrNIStr ( cFileBuff , dwBytesRead , (UCHAR*)uStringArray2 [ i ] , strlen ( uStringArray2 [ i ] ) ) ;
		}

		// only if any of the above keywords list was found
		// check the dll entry is present in SharedTaskScheduler
		if ( bStringsFound && !IsFilePresentInSharedTaskKey ( csFullFileName ) )
			return false;

		return true;
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in  CSystemScan::CheckIfSpyLockedFile "), 0, 0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsFilePresentInSharedTaskKey
	In Parameters	: const CString&
	Out Parameters	: bool
	Purpose			: check file to be persent in share task scheduler
	Author			: Anand
	Description		: checks the STS entry for the file
--------------------------------------------------------------------------------------*/
bool CSystemScan::IsFilePresentInSharedTaskKey ( const CString& csFullFileName )
{
	try
	{
		bool bEntryFound = false ;
		CString csFullKeyName, csData ;		
		CStringArray csArrSTSLocations ;

		csArrSTSLocations . Add ( STS_PATH ) ;
		if ( m_bScanOtherLocations )
			csArrSTSLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_STS_PATH) ) ;

		for ( int j = 0 ; j < csArrSTSLocations . GetCount() ; j++ )
		{   
            vector<REG_VALUE_DATA> vecRegValues;
	        m_objReg.EnumValues(csArrSTSLocations [ j ], vecRegValues, HKEY_LOCAL_MACHINE);

            for ( size_t i = 0 ; i < vecRegValues.size(); i++ )
			{
				csFullKeyName.Format( _T("CLSID\\%s\\InprocServer32"), static_cast<LPCTSTR>(vecRegValues [ i ].strValue));
				m_objReg.Get( csFullKeyName, _T(""), csData, HKEY_CLASSES_ROOT);

				if ( !csData.IsEmpty() && ( 0 == csData.CompareNoCase( csFullFileName)))
				{
                    EnumAndReportCOMKeys ( 6182 , (CString)CLSID_KEY +  (CString)vecRegValues[i].strValue , HKEY_CLASSES_ROOT ) ;

					SendScanStatusToUI( Special_RegVal ,  6182 , HKEY_LOCAL_MACHINE , 
                        csArrSTSLocations [ j ] ,  vecRegValues [ i ].strValue, vecRegValues [ i ].Type_Of_Data, vecRegValues [ i ].bData, vecRegValues [ i ].iSizeOfData) ;
					bEntryFound = true ;
				}

				csData.Empty() ;
				csFullKeyName.Empty() ;
			}
		}

		return bEntryFound;
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::IsFilePresentInSharedTaskKey"), 0, 0);
	}
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: GetiniFileName
	In Parameters	: CString, UCHAR*, DWORD, ULONGLONG
	Out Parameters	: bool
	Purpose			: Check file to be of Trojan.Delf
	Author			: Shweta
	Description		: Gets the File name from Already existing File and then checks for file existance.
--------------------------------------------------------------------------------------*/
bool CSystemScan::GetiniFileName ( CString csFullFileName , UCHAR * cFileBuff , DWORD dwBytesRead )
{
	char cDelfFile [ MAX_PATH ] = { 0 } ;
	UCHAR * ptr = NULL ;
	TCHAR ch = 0 ;
	CString csFlnm ;
	CStringArray csArr ;

	try
	{
		//Get the filename only not exclude the complete path
		csFlnm = csFullFileName.Right ( csFullFileName.GetLength() - csFullFileName.ReverseFind('\\') -1 );
		
		//strcpy_s ( cDelfFile , sizeof ( cDelfFile ) , csFlnm ) ;
        if (csFlnm.GetLength() >= sizeof ( cDelfFile ) )
			return ( false ) ;
		sprintf_s ( cDelfFile , sizeof ( cDelfFile ) , "%S" , static_cast<LPCTSTR>(csFlnm) ) ;

		if ( IsStopScanningSignaled() )
			return ( false ) ;

		//check if file has the File name in th file 
		ptr = StrNIStr ( cFileBuff , dwBytesRead , (UCHAR*) cDelfFile , strlen ( cDelfFile ) ) ;
		if ( !ptr )
			return ( false ) ;

		ptr = ptr + strlen ( cDelfFile ) ;
		csFlnm . Empty() ;

		while ( (DWORD)( ptr - cFileBuff ) >= dwBytesRead )
		{
			ch = *ptr ;
			if ( ch == _T('{') )
				break ;

			if ( ch == _T('\0') )
			{
				if ( csFlnm == _T("") )
				{
					ptr++;
					continue;
				}

				csArr.Add ( csFlnm ) ;
				ptr++;
				csFlnm = _T("");
				continue;
			}

			csFlnm += ch ;
			ptr++ ;
		}

		for ( int i = 0 ; i < csArr.GetCount(); i++ )
		{
			CString csnewFileName;
			csnewFileName = csArr.GetAt(i);
			
			if ( csnewFileName.Find ( _T(".dll") ) == -1 )
				continue ;

			CStringArray csArrSYSLocations ;

			csArrSYSLocations . Add ( CSystemInfo::m_strSysDir ) ;
			if ( m_bScanOtherLocations )
				csArrSYSLocations . Add ( m_csOtherSysDir ) ;

			for ( int k = 0 ; k < csArrSYSLocations . GetCount(); k++ )
			{
				csnewFileName = csArrSYSLocations [ k ] + BACK_SLASH + csnewFileName ;
				if ( _taccess_s ( csnewFileName , 0 ) == 0)
				{
					m_csArrCommonInfectedFiles.Add ( csnewFileName );
					SendScanStatusToUI ( Special_File , 7528 , csnewFileName  ) ;
				}
			}
		}

		return ( true ) ;
	}

	catch(...)
	{
		AddLogEntry ( _T("Exception caught in CSystemScan::GetiniFileName") , 0 , 0 );
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckDelfExe
	In Parameters	: const CString&, UCHAR*, DWORD, int
	Out Parameters	: bool
	Purpose			: Check file to be of Trojan.Delf
	Author			: Shweta
	Description		: Checks the size , ext , path , version tab and strings to determine Trojan.Delf file
--------------------------------------------------------------------------------------*/
bool CSystemScan :: CheckDelfExe ( const CString& csFullFileName , UCHAR * cFileBuff , DWORD dwBytesRead )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return false ;

		char * arrOfSymbols [] = 
		{
			"UpackByDwing" ,
			".Upack"
		};

		for ( int i = 0 ; i < sizeof ( arrOfSymbols )  / sizeof ( arrOfSymbols [ 0 ] ) ;i++ )
		{
			if ( !StrNIStr ( cFileBuff , dwBytesRead , (UCHAR*)arrOfSymbols [ i ]  , strlen ( arrOfSymbols [ i ] ) ) )
				return ( false ) ;			
		}
		SendScanStatusToUI ( Special_File , 7528 , csFullFileName ) ;
		return ( true ) ;
	}

	catch(...)
	{
		AddLogEntry ( _T("Exception caught in CheckDelfExe") , 0 , 0 ) ;
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfTrojanDelfFile
	In Parameters	: const CString&, UCHAR*, DWORD, int
	Out Parameters	: bool
	Purpose			: Check file to be of Trojan.Delf
	Author			: Anand
	Description		: Checks the size , ext , path , version tab and strings to determine Trojan.Delf file
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckIfTrojanDelfFile( const CString& csFullFileName , UCHAR * cFileBuff ,
										 DWORD dwBytesRead , ULONGLONG iFileLength )
{
	try
	{
		if(IsStopScanningSignaled())
			return false ;

		if ( !csFullFileName . CompareNoCase ( m_objSysInfo . m_strSysDir + _T("\\msdebug.dll" ) ) ||
			 ( m_bScanOtherLocations && !csFullFileName . CompareNoCase ( m_csOtherSysDir + _T("\\msdebug.dll" ) ) ) )
		{
			SendScanStatusToUI ( Special_File , 7528 , csFullFileName ) ;
			m_csArrCommonInfectedFiles . Add ( csFullFileName ) ;
			m_bSplSpyFound = true ;
			return ( true ) ;
		}

		CString csPart;
		int iLocation = 0 ;
		bool bStringsFound = true ;
		bool bFileTypeLarge = false ;
		bool bFileTypeSmall = false ;

		// check the path to be sysdir
		iLocation = csFullFileName.ReverseFind(_T('\\'));
		if ( -1 == iLocation )
			return false;

		csPart = csFullFileName.Left( iLocation );
		if ( csPart.IsEmpty())
			return false;

		if ( 0 != csPart.CompareNoCase ( m_objSysInfo.m_strSysDir ) )
		{
			if ( m_bScanOtherLocations )
			{
				if ( 0 != csPart.CompareNoCase ( m_csOtherSysDir ) )
					return ( false ) ;
			}
			else
			{
				return ( false ) ;
			}
		}

		// check the size, it must be between 38 and 45 KB or 10 to 25 KB
		bFileTypeLarge = ( iFileLength > 1024 * 38 ) && ( iFileLength < 1024 * 45 ) ;
		bFileTypeSmall = ( iFileLength > 1024 * 10 ) && ( iFileLength < 1024 * 25 ) ;
		if ( !bFileTypeSmall && !bFileTypeLarge )
			return ( false ) ;

		// check the version tab
		CFileVersionInfo	oFileVersionInfo;
		if ( !oFileVersionInfo.DoTheVersionJob ( csFullFileName , false ) )
			return false;

		// check the extension to be dll or exe
		iLocation = csFullFileName.ReverseFind('.');
		if ( -1 == iLocation )
			return false;

		csPart = csFullFileName.Right( csFullFileName.GetLength() - iLocation - 1);
		if ( csPart.IsEmpty())
			return false;

		// Resource: Shweta
		// Version: 2.5.0.14
		// Check if Any Delf exe exist
		if ( 0 == csPart . CompareNoCase ( _T("exe") ) )
		{
			if ( CheckDelfExe ( csFullFileName , cFileBuff , dwBytesRead ) )
			{
				m_bSplSpyFound = true ;
				return ( true ) ;
			}

			return ( false ) ;
		}

		if ( 0 != csPart . CompareNoCase ( _T("dll") ) )
			return ( false ) ;

		//Resource: Avinash B
		//Version: 2.5.0.9
		//preparing the array of strings to be searched in dlls
		char * arrOfSymbols [] = 
		{
			"Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\ShellExecuteHooks" ,
			"AppInit_DLLs" ,
			"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" ,
			"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" ,
			"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile"
		};

		if ( bFileTypeLarge )
		{
			if ( !StrNIStr ( cFileBuff , dwBytesRead , (UCHAR*) "puma.dll" , strlen ( "puma.dll" ) ) )
				return false;
		}
		else if(bFileTypeSmall)
		{
			for(int i = 0 ; i < sizeof ( arrOfSymbols )  / sizeof ( arrOfSymbols [ 0 ] ) ;i++ )
			{
				if ( !StrNIStr ( cFileBuff , dwBytesRead , (UCHAR*)arrOfSymbols [ i ]  , strlen ( arrOfSymbols [ i ] ) ) )
					return ( false ) ;
			}

			//Resource: Shweta
			//Version: 2.5.0.14
			//Description: Get the ini filename
			GetiniFileName ( csFullFileName , cFileBuff , dwBytesRead ) ;
		}
		else
		{
			return ( false ) ;
		}

		SendScanStatusToUI ( Special_File , 7528 , csFullFileName  ) ;
		m_csArrCommonInfectedFiles . Add ( csFullFileName ) ;
		m_bSplSpyFound = true ;
		return ( true ) ;
	}

	catch (...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::CheckIfTrojanDelfFile"), 0, 0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckforAboutBlank
	In Parameters	: const CString&, UCHAR*, DWORD, int
	Out Parameters	: bool
	Purpose			: Check file to be of About Blank
	Author			: Shweta
	Description		: Checks the size , ext , path , version tab and strings to determine AboutBlank file
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckforAboutBlank  ( const CString& csFullFileName , UCHAR * cFileBuff ,
										 DWORD dwBytesRead , ULONGLONG iFileLength )
{
	try
	{
		// checking if the location is sysdir
		if ( _tcsnicmp ( csFullFileName , CSystemInfo::m_strSysDir , _tcslen ( CSystemInfo::m_strSysDir ) ) )
		{
			// checking if the other location is to be checked
			if ( m_bScanOtherLocations )
			{
				// checking if the other location is sysdir
				if ( _tcsnicmp ( csFullFileName , m_csOtherSysDir , _tcslen ( m_csOtherSysDir ) ) )
					return ( false ) ;
			}
			else
			{
				return ( false ) ;
			}
		}

		// check for extension
		CString csExt = csFullFileName.Right(4);
		csExt.MakeLower();
		if (csExt != _T(".exe"))
			return false;

		// check the size, it must be between 80 and 120 KB 
		bool bFileSize = ( iFileLength > 1024 * 80 ) && ( iFileLength < 1024 * 120 ) ;
        if ( !bFileSize )
			return ( false ) ;

		//Check for Version information
		CFileVersionInfo	oFileVersionInfo;
		CString csInternalCheck;
		char chfilename[MAX_PATH] ;
		TCHAR cInteralname[MAX_PATH] = { 0 } ;

		if ( _tcslen ( csFullFileName ) >= sizeof ( chfilename ) )
			return ( false ) ;

		sprintf_s ( chfilename , sizeof ( chfilename ) , "%S" , static_cast<LPCTSTR>(csFullFileName) ) ;

		oFileVersionInfo.GetFileInternalName ( csFullFileName , cInteralname ); 
		csInternalCheck = cInteralname ;
		csInternalCheck.MakeLower();
		if ( csInternalCheck . Find ( _T("dfort_5_2") , 0 ) == -1 )
		{
			return ( false );
		}
	
		//Check the Strings 
		char * carrOfStr [] = 
		{
			".aspack" ,
			".adata" 
		};

		for ( int i = 0 ; i < sizeof ( carrOfStr )  / sizeof ( carrOfStr [ 0 ] ) ; i++ )
		{
			if ( !StrNIStr ( cFileBuff , dwBytesRead , (UCHAR*)carrOfStr [ i ]  , strlen ( carrOfStr [ i ] ) ) )
			{
				return ( false ) ;
			}
		}

		SendScanStatusToUI ( Special_File , 71,csFullFileName  );		
		return true;
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::CheckForAboutBlank "), 0, 0);
	}

	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckWinBlueSoft
	In Parameters	: const CString&, UCHAR*, DWORD
	Out Parameters	: bool
	Purpose			: Check file to be of Winbluesoft
	Author			: Shweta
	Description		: Checks the size , ext , path , and strings to determine WinblueSoftw file
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckWinBlueSoft ( const CString& csFullFileName , BYTE * Buff , DWORD dwFileSize )
{
	if(IsStopScanningSignaled())
		return ( false ) ;

	CString csFullFileName_ = csFullFileName;
	csFullFileName_.MakeLower();
	if(_tcsstr(csFullFileName_, _T("\\cbid32.dll")))
	{
		return false;
	}

	//Check System32 or windows
	if ( _tcsnicmp ( csFullFileName , CSystemInfo::m_strSysDir , _tcslen ( CSystemInfo::m_strSysDir ) ) )
	{
		if ( _tcsnicmp ( csFullFileName , CSystemInfo::m_strWinDir , _tcslen ( CSystemInfo::m_strWinDir ) ) )
			return false ;
	}

	//Chk Size
	if ( dwFileSize > 0x18413 )
		return ( false ) ;

	//Chk extension
	CString		csExt, csExeName;
	csExt = csFullFileName.Right(3);
	csExt.MakeLower();

	if ( csExt == _T("dll") || csExt == _T("exe") || csExt == _T("cpl") || csExt == _T("bin") || csExt == _T("ocx"))
	{
		if ( Buff [ 0 ] == 'M' && Buff [ 1 ] == 'Z' )
			return ( false ) ;

		if ( Buff [ 0 ] != '8' && Buff [ 2 ] != 'K' && Buff [ 3 ] != '!' )
		{
			if ( Buff [ 4 ] != '8' && Buff [ 6 ] != 'K' && Buff [ 7 ] != '!' )
			{
				if ( Buff [ 8 ] != '8' && Buff [ 10 ] != 'K' && Buff [ 11 ] != '!' )
				{
					if ( Buff [ 12 ] != '8' && Buff [ 14 ] != 'K' && Buff [ 15 ] != '!' )
					{
							return ( false ) ;
					}
				}

			}
		}

		SendScanStatusToUI ( Special_File , 16 , csFullFileName ) ;
	}
	else
	{
		return false ;
	}

	return ( true ) ;
}
/*-------------------------------------------------------------------------------------
	Function		: CheckforMonder
	In Parameters	: const CString&, BYTE *, CString
	Out Parameters	: bool
	Purpose			: Check file to be of monder
	Author			: vaibhav Desai
	Description		: Checks the version tab , ext, starting two charachers of file name and path to determine Monder file
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckforMonder ( const CString& csFullFileName , BYTE * Buff, CString csFileName, ULONGLONG iFileLength )
{
    try
	{
		if(IsStopScanningSignaled())
			return ( false ) ;

        //Check System32 
	    if ( _tcsnicmp ( csFullFileName , CSystemInfo::m_strSysDir , _tcslen ( CSystemInfo::m_strSysDir ) ) )
	    {
             return false;
        }
     
        //Check extention
        CString		csExt;
	    csExt = csFullFileName.Right(4);

	    csExt.MakeLower();
        if( csExt != _T(".exe" ) )
        {
            return false;
        }
       
        //check file size
        if(( iFileLength < 1024 * 50 ) || ( iFileLength > 1024 * 60 ))
        {
            return false;
        }
            
        //check file Name
        csFileName.MakeLower();
        if( csFileName.Left( 2 ) != _T("dm" ))
        {
            return false;
        }
       
        //check version tab
        CFileVersionInfo	oFileVersionInfo;
	    if ( !oFileVersionInfo.DoTheVersionJob ( csFullFileName , false ) )
		    return false;
        
        //check run entry
        CheckRegEntryForRun( csFullFileName, csFileName);
        
        if( m_objEnumProcess.IsProcessRunning( csFullFileName, false ))
        {
            SendScanStatusToUI ( Special_Process , 4053 , csFullFileName ) ;
        }
        SendScanStatusToUI ( Special_File , 4053 , csFullFileName ) ;
	    return true;
    }
    catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::CheckforMonder "), 0, 0);
	}
    return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckRegEntryForRun
	In Parameters	: cCString, CString
	Out Parameters	: bool
	Purpose			: Check Run entry 
	Author			: vaibhav Desai
	Description		: Checks file name in value and data part in RUN Key
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckRegEntryForRun(const CString& csFullFilePath, const CString& csFileName)
{

     try
	{		    
         CString csData;

         if( !(m_objReg.Get(RUN_REG_PATH, csFileName, csData, HKEY_LOCAL_MACHINE)))
                return false;
                          
        if ( -1 == csData.Find ( csFileName ) )
            return false;
           
        SendScanStatusToUI ( Special_RegVal , 4053 , HKEY_LOCAL_MACHINE , CString(RUN_REG_PATH) ,
                                         csFileName , REG_SZ , (LPBYTE)(LPCTSTR)csData, (csData.GetLength())* 2);
                       
         return true ;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::CheckRegEntryForRun "), 0, 0);
	}
    return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForDreamy
	In Parameters	: const CString&,const CString&, ULONGLONG
	Out Parameters	: bool
	Purpose			: Check file to be of Dreamy
	Author			: vaibhav Desai
	Description		: Checks the Extention , path and MD5 to determine Dreamy file
--------------------------------------------------------------------------------------*/

bool CSystemScan :: CheckForDreamy ( const CString& csFilePath, ULONGLONG iFileLength )
{
	CString csFullFilePath ;
	CString csExt ;

	if ( iFileLength != 4672 )
		return ( false ) ;

	csFullFilePath = csFilePath ;
	csFullFilePath.MakeLower();
	csExt = csFullFilePath.Right ( 4 ) ;
	if( csExt != _T(".syz") )
	{
		return ( false ) ;
	}

	if ( _tcsnicmp ( csFullFilePath , CSystemInfo::m_strSysDir , _tcslen ( CSystemInfo::m_strSysDir ) ) )
    {
         return false;
    }

	if ( ! CheckSignatureOfDreamyFile ( csFullFilePath ) )
	{
		return ( false ) ;
	}

	SendScanStatusToUI ( Special_File , 8565 , csFullFilePath ) ;
	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSignatureOfDreamyFile
	In Parameters	: const CString&
	Out Parameters	: bool
	Purpose			: Check file to be of Dreamy
	Author			: vaibhav Desai
	Description		: Checks the PE signature
--------------------------------------------------------------------------------------*/
bool CSystemScan :: CheckSignatureOfDreamyFile ( const CString csFilePath )
{
	DWORD dwBytesRead = 0 ;
	HANDLE hFile = NULL ;
	IMAGE_NT_HEADERS NTFileHeader = { 0 } ;
	IMAGE_DOS_HEADER DosHeader = { 0 } ;
	IMAGE_SECTION_HEADER SectionHeader [ 5 ] = { 0 } ;
	BYTE ReadBuffer[ 48 ] = { 0 };
	BYTE bySig[ 48 ] ={ 0x08, 0x58, 0xC7, 0x40, 0x34, 0xF3, 0x0B, 0x01, 0x00, 0x6A, 0x00, 0x58, 0x5B, 0x5F, 0x5E, 0xC9,
						0xC2, 0x08, 0x00, 0x55, 0x8B, 0xEC, 0x83, 0xC4, 0xFC, 0xFA, 0x0F, 0x20, 0xC0, 0x89, 0x45, 0xFC,
						0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F, 0x22, 0xC0, 0xFF, 0x35, 0x34, 0x0E, 0x01, 0x00, 0xFF, 0x35 };

		

	hFile = CreateFile ( csFilePath , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if ( INVALID_HANDLE_VALUE == hFile )
		return ( false ) ;

	if ( ! ReadFile ( hFile , &DosHeader , sizeof ( DosHeader ) , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( sizeof ( DosHeader ) != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( 0x5A4D != DosHeader . e_magic  )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}
	
	SetFilePointer ( hFile , DosHeader . e_lfanew , 0 , FILE_BEGIN ) ;
	
	if (!ReadFile ( hFile , &NTFileHeader , sizeof ( NTFileHeader ) , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if ( sizeof ( NTFileHeader ) != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( 0x00004550 != NTFileHeader.Signature  )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( NTFileHeader.FileHeader.NumberOfSections != 0x5 )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( NTFileHeader.OptionalHeader.AddressOfEntryPoint != 0xBBC )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( !ReadFile ( hFile , &SectionHeader , sizeof ( SectionHeader [ 0 ] ) * NTFileHeader . FileHeader . NumberOfSections , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( sizeof ( SectionHeader [ 0 ] ) * NTFileHeader . FileHeader . NumberOfSections != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( SectionHeader [ 0 ] . PointerToRawData != 0x2A0 )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	SetFilePointer ( hFile , NTFileHeader . OptionalHeader . AddressOfEntryPoint + 36, 0 , FILE_BEGIN ) ;

	if (!ReadFile ( hFile , ReadBuffer , 48 , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( dwBytesRead != 48 )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;

	if ( memcmp ( bySig , ReadBuffer , 48 ) )
		return ( false ) ;

	return true;

}

/*-------------------------------------------------------------------------------------
	Function		: CheckforMalwareAgent
	In Parameters	: const CString& csFullFileName , CString& csFileName ,
					  CFileSignatureDb *pFileSigMan , ULONGLONG iFileLength
	Out Parameters	: bool
	Purpose			: Check file to be of MalwareAgent
	Author			: Shweta Mulay
	Description		: Checks the files by size and md5
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckforMalwareAgent ( const CString& csFullFileName , CString& csFileName ,CFileSignatureDb *pFileSigMan , ULONGLONG iFileLength)
{
    try
	{
		if(IsStopScanningSignaled())
			return ( false ) ;

		BYTE bMD5Signature[16] = { 0 };
		DWORD dwSizeArr[5] = { 0 } ;
		bool bFound = false ;

		dwSizeArr[0] = 11776;
		dwSizeArr[1] = 226400 ;
		
		for ( DWORD i = 0 ; i < _countof ( dwSizeArr ) ; i++ )
		{
			if ( iFileLength == dwSizeArr [ i ] )
				bFound = true ;
		}
		if ( !bFound ) 
			return ( false ) ;

        //Check System32 
	    if ( _tcsnicmp ( csFullFileName , CSystemInfo::m_strSysDir , _tcslen ( CSystemInfo::m_strSysDir ) ) )
             return false;
     
        //Check extention
        CString		csExt;
	    csExt = csFullFileName.Right(4);

	    csExt.MakeLower();
        if( csExt != _T(".dll" ) )
        {
            return false;
        }

		pFileSigMan->GetMD5Signature(csFullFileName , bMD5Signature ) ;
		const BYTE MD5_MALWARE[16] = {0xCD, 0x0E, 0xC7, 0x19, 0x60, 0x9A, 0xDE, 0x3D, 0x39, 0x99, 0x55, 0x5D, 0x50, 0xC9, 0x4B, 0x6D } ;
		const BYTE MD5_MALWARE_1[16] = {0x6A, 0x52, 0xD7, 0x5E, 0xE7, 0x17, 0xB6, 0x39, 0x8D, 0xD7, 0x40, 0x91, 0x6E, 0x76, 0xAD, 0xAD } ;
		
		csFileName.MakeLower();
		if ( ( ! memcmp ( bMD5Signature, MD5_MALWARE , 16 ) || ! memcmp ( bMD5Signature, MD5_MALWARE_1, 16 ) ) &&
			 ( csFileName != _T( "comres.dll" ) ) )
		{
			SendScanStatusToUI ( Special_File , 4053 , csFullFileName ) ;
		}

	    return true ;
    }
    catch(...)
	{
		AddLogEntry(_T("Exception caught in CSystemScan::CheckforMonder "), 0, 0);
	}
    return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForStuh
	In Parameters	: const CString& , ULONGLONG
	Out Parameters	: bool
	Purpose			: Check file to be of Stuh worm
	Author			: vaibhav Desai
	Description		: Checks the Extention , path , version tab, size and pe header checks to determine Dreamy file
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckForStuh ( const CString& csFullFileName , ULONGLONG iFileLength )
{
	try
	{
		if(IsStopScanningSignaled())
			return ( false ) ;
		
		CString	 csExt ;
		CString  csData ;
		size_t icnt = 0 ;

		//Check System32 
		if ( _tcsnicmp ( csFullFileName , CSystemInfo::m_strSysDir , _tcslen ( CSystemInfo::m_strSysDir ) ) )
		{
			 return ( false ) ;
		}

		//Check extention
	    
		csExt = csFullFileName . Right( 4 ) ;
		csExt . MakeLower() ;
		if( csExt != _T( ".dll" ) )
		{
			return ( false ) ;
		}

		//check file size
		if( ( iFileLength < 1024 * 78 ) || ( iFileLength > 1024 * 88 ) )
		{
			return false;
		}
		
		CFileVersionInfo	oFileVersionInfo;
		if ( ! oFileVersionInfo.DoTheVersionJob ( csFullFileName , false ) )
		{
			return ( false ) ;
		}

		

		if ( CheckFirstStuhSig ( csFullFileName ) )
		{
			SendScanStatusToUI ( Special_File , 9993 , csFullFileName ) ;
		}
		else if ( checkSecondStuhSig ( csFullFileName ) )
		{
			SendScanStatusToUI ( Special_File , 9993 , csFullFileName ) ;
		}
		else
		{
			return ( false );
		}

		vector<REG_VALUE_DATA> vecRegValues ;            
	    m_objReg . EnumValues ( RUN_REG_PATH , vecRegValues , HKEY_LOCAL_MACHINE ) ;        

        for ( size_t icnt = 0 ; icnt < vecRegValues.size() ; icnt++ )
		{
            csData . Format ( _T("%s") , ( TCHAR * ) vecRegValues [ icnt ] . bData ) ;
			csData . MakeLower() ;
			if ( ( csData . Find ( _T("rundll32.exe") ) != -1 ) && ( csData . Find ( csFullFileName ) != -1 ) )
			{				
				SendScanStatusToUI ( Special_RegVal , 9993 , HKEY_LOCAL_MACHINE , CString(RUN_REG_PATH) ,
								 vecRegValues [ icnt ] .strValue , REG_SZ , (LPBYTE)(LPCTSTR)csData, ( csData.GetLength() ) * sizeof ( TCHAR ) ) ;
				break ;
			}
		}		
	
		return ( true ) ;
	}
    catch(...)
	{
		AddLogEntry( _T("Exception caught in CSystemScan::CheckForStuh") , 0 , 0 ) ;
	}
    return ( false ) ;

}

/*-------------------------------------------------------------------------------------
	Function		: CheckFirstStuhSig
	In Parameters	: const CString&
	Out Parameters	: bool
	Purpose			: Check file to be of stuh worm
	Author			: vaibhav Desai
	Description		: Checks the PE signature
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckFirstStuhSig ( const CString& csFilePath )
{
	DWORD dwBytesRead = 0 ;
	HANDLE hFile = NULL ;
	IMAGE_NT_HEADERS NTFileHeader = { 0 } ;
	IMAGE_DOS_HEADER DosHeader = { 0 } ;
	IMAGE_SECTION_HEADER SectionHeader [ 3 ] = { 0 } ;
	 __int64 SecName = 0x0000000000000000 ;
	
	hFile = CreateFile ( csFilePath , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if ( INVALID_HANDLE_VALUE == hFile )
		return ( false ) ;

	if ( ! ReadFile ( hFile , &DosHeader , sizeof ( DosHeader ) , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( sizeof ( DosHeader ) != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( 0x5A4D != DosHeader . e_magic  )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}
	
	SetFilePointer ( hFile , DosHeader . e_lfanew , 0 , FILE_BEGIN ) ;
	
	if (!ReadFile ( hFile , &NTFileHeader , sizeof ( NTFileHeader ) , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if ( sizeof ( NTFileHeader ) != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( 0x00004550 != NTFileHeader.Signature  )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( NTFileHeader.FileHeader.NumberOfSections != 0x3 )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( NTFileHeader.OptionalHeader.AddressOfEntryPoint < 0x24000 )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( !ReadFile ( hFile , &SectionHeader , sizeof ( SectionHeader [ 0 ] ) * NTFileHeader . FileHeader . NumberOfSections , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( sizeof ( SectionHeader [ 0 ] ) * NTFileHeader . FileHeader . NumberOfSections != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( SecName != *( (UINT64 * ) & ( SectionHeader [ 2 ]. Name ) )  )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: checkSecondStuhSig
	In Parameters	: const CString&
	Out Parameters	: bool
	Purpose			: Check file to be of stuh worm
	Author			: vaibhav Desai
	Description		: Checks the PE signature
--------------------------------------------------------------------------------------*/
bool CSystemScan::checkSecondStuhSig ( const CString& csFilePath )
{

	DWORD dwBytesRead = 0 ;
	HANDLE hFile = NULL ;
	IMAGE_NT_HEADERS NTFileHeader = { 0 } ;
	IMAGE_DOS_HEADER DosHeader = { 0 } ;
	IMAGE_SECTION_HEADER SectionHeader [ 4 ] = { 0 } ;
	__int64 SecName = 0x00000065646F632E ;
	
	hFile = CreateFile ( csFilePath , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , 0 ) ;
	if ( INVALID_HANDLE_VALUE == hFile )
		return ( false ) ;

	if ( ! ReadFile ( hFile , &DosHeader , sizeof ( DosHeader ) , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( sizeof ( DosHeader ) != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( 0x5A4D != DosHeader . e_magic  )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}
	
	SetFilePointer ( hFile , DosHeader . e_lfanew , 0 , FILE_BEGIN ) ;
	
	if (!ReadFile ( hFile , &NTFileHeader , sizeof ( NTFileHeader ) , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile ) ;
		return ( false ) ;
	}

	if ( sizeof ( NTFileHeader ) != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( 0x00004550 != NTFileHeader.Signature  )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( NTFileHeader.FileHeader.NumberOfSections != 0x4 )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( NTFileHeader.OptionalHeader.AddressOfEntryPoint < 0x25000 )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( !ReadFile ( hFile , &SectionHeader , sizeof ( SectionHeader [ 0 ] ) * NTFileHeader . FileHeader . NumberOfSections , &dwBytesRead , 0 ) )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( sizeof ( SectionHeader [ 0 ] ) * NTFileHeader . FileHeader . NumberOfSections != dwBytesRead )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	if ( SecName !=  *( (UINT64 * ) & ( SectionHeader [ 3 ]. Name ) ) )
	{
		CloseHandle ( hFile );
		return ( false ) ;
	}

	CloseHandle ( hFile ) ;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForWormKolab
	In Parameters	: const CString& csFilePath, FILETIME* stLastModTime, const CString& csFileLoc
	Out Parameters	: bool
	Purpose			: Check file to be of kolab worm
	Author			: anand srivastava
	Description		: checks patterns
--------------------------------------------------------------------------------------*/
bool CSystemScan::CheckForWormKolab(const CString& csFilePath, FILETIME* stLastModTime, const CString& csFileLoc)
{
	bool bInfected = false;
	static bool bCheckOnce = false;

	if(!bCheckOnce)
	{
		CString csSandbox, csNotepad;
		WIN32_FILE_ATTRIBUTE_DATA stAttrSandbox = {0}, stAttrNotepad = {0};

		bCheckOnce = true;
		csSandbox.Format(_T("%s\\cwsandbox\\cwsandbox.exe"), m_objSysInfo.m_strRoot);
		csNotepad.Format(_T("%s\\notepad.exe"), m_objSysInfo.m_strSysDir);

		if(GetFileAttributesEx(csSandbox, GetFileExInfoStandard, &stAttrSandbox))
		{
			if(GetFileAttributesEx(csNotepad, GetFileExInfoStandard, &stAttrNotepad))
			{
				if(stAttrSandbox.nFileSizeHigh == stAttrNotepad.nFileSizeHigh && stAttrSandbox.nFileSizeLow == stAttrNotepad.nFileSizeLow)
				{
					SendScanStatusToUI(Special_File, iSPYID_WormKolab, csSandbox);
				}
			}
		}

		bool bMatched = false;
		DWORD dwCount = 0;
		CStringArray csSubKeysList;
		BYTE bySections[] = {0x2E,0x62,0x73,0x73,0x00,0x00,0x00,0x00};
		IMAGE_SECTION_HEADER_MSS SectionHeader[10] = {0};
		CString csImagePath;
		CString csSubKey, csData, csValue = _T("Ime File"), csKey = _T("SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts");

		m_objReg.EnumSubKeys(csKey, csSubKeysList, HKEY_LOCAL_MACHINE);
		for(INT_PTR i = 0, iTotal = csSubKeysList.GetCount(); i < iTotal; i++)
		{
			bMatched = false;
			csSubKey = csKey + BACK_SLASH + csSubKeysList.GetAt(i);
			if(!m_objReg.Get(csSubKey, csValue, csData, HKEY_LOCAL_MACHINE))
			{
				continue;
			}

			if(_tcschr(csData, _T('\\')))
			{
				continue;
			}

			csImagePath.Format(_T("%s\\%s"), m_objSysInfo.m_strSysDir, csData);
			if(_taccess_s(csImagePath, 0))
			{
				continue;
			}

			memset(SectionHeader, 0, sizeof(SectionHeader));
			dwCount = _countof(SectionHeader);
			if(!CheckIfSectionsPresent(csImagePath, bySections, sizeof(bySections), 0, 0, SectionHeader, &dwCount))
			{
				continue;
			}

			for(DWORD i = 0; i < dwCount; i++)
			{
				if(!memcmp(SectionHeader[i].Name, ".bss\0\0\0\0", sizeof(SectionHeader[i].Name)))
				{
					if(0 == SectionHeader[i].SizeOfRawData)
					{
						bMatched = true;
						break;
					}
				}
			}

			if(bMatched)
			{
				EnumAndReportCOMKeys(m_ulSpyName, csSubKey, HKEY_LOCAL_MACHINE);
				SendScanStatusToUI(Special_File, m_ulSpyName, csImagePath);
			}
		}
	}

	if(!csFileLoc.CompareNoCase(m_objSysInfo.m_strSysDir))
	{
		if(IsRecentlyModified(csFilePath, stLastModTime, 30))
		{
			BYTE bySections1[] = {0x2E,0x76,0x6d,0x70,0x30,0x00,0x00,0x00,0x2E,0x76,0x6d,0x70,0x31,0x00,0x00,0x00};
			BYTE bySections2[] = {0x2E,0x62,0x73,0x73,0x00,0x00,0x00,0x00, 0x2E,0x64,0x61,0x74,0x61,0x00,0x00,0x00,
								  0x2E,0x43,0x52,0x54,0x00,0x00,0x00,0x00, 0x2E,0x72,0x65,0x6c,0x6f,0x63,0x00,0x00};
			IMAGE_SECTION_HEADER_MSS SectionHeader[10] = {0};
			DWORD dwCount = _countof(SectionHeader);

			if(CheckIfSectionsPresent(csFilePath, bySections1, sizeof(bySections1)))
			{
				bInfected = true;
			}
			else if(CheckIfSectionsPresent(csFilePath, bySections2, sizeof(bySections2), 0, 0, SectionHeader, &dwCount))
			{
				for(DWORD i = 0; i < dwCount; i++)
				{
					if(memcmp(SectionHeader[i].Name, ".bss\0\0\0\0", sizeof(SectionHeader[i].Name)))
					{
						bInfected = true;
						break;
					}
				}
			}
		}
		else
		{
			LPCTSTR szLastSlash = NULL, szExtension = NULL;

			szExtension = _tcsrchr(csFilePath, _T('.'));
			if(szExtension)											// filepath has dot
			{
				if(!_tcsicmp(szExtension, _T(".bak")))				// extension is .bak
				{
					CString csDllCache;

					szLastSlash = _tcsrchr(csFilePath, _T('\\'));	// take out only filename
					if(szLastSlash)
					{
						csDllCache.Format(_T("%s\\dllcache%s"), csFileLoc, szLastSlash); // prepare same name file in dllcache
						if(!_taccess_s(csDllCache, 0))				// check if there is a same name file in dllcache
						{
							WIN32_FILE_ATTRIBUTE_DATA Sys32FI = {0}, DllCahFI = {0};
							ULONG64 ulSys32FS = 0, ulDllCahFS = 0;

							if(GetFileAttributesEx(csFilePath, GetFileExInfoStandard, &Sys32FI))		// get sys32 file info
							{
								if(GetFileAttributesEx(csDllCache, GetFileExInfoStandard, &DllCahFI))	// get dll cache file info
								{
									ulSys32FS = MKQWORD(Sys32FI.nFileSizeHigh, Sys32FI.nFileSizeLow);
									ulDllCahFS = MKQWORD(DllCahFI.nFileSizeHigh, DllCahFI.nFileSizeLow);

									if(ulDllCahFS < ulSys32FS)		// dll cache file size should be less than sys32
									{
										BYTE bySections[] = {0x2E,0x75,0x70,0x78,0x5F,0x00,0x00,0x00}; // .upx_

										if(CheckIfSectionsPresent(csFilePath, bySections, sizeof(bySections))) // file should have section by name .upx_
										{
											bInfected = true;
										}
									}
								}
							}
						}
					}
				}
			}

			if(bInfected)
			{
				CString csMaxFormat;
				TCHAR szOnyFileName[MAX_PATH] = {0};

				_tsplitpath_s(csFilePath, 0, 0, 0, 0, szOnyFileName, _countof(szOnyFileName), 0, 0);

				csMaxFormat.Format(_T("%s\\dllcache\\%s.bak%s%s\\%s"), csFileLoc, szOnyFileName, RENAME_FILE_SEPARATOR, csFileLoc, szOnyFileName);
				AddInRestartDeleteList(RD_FILE_REPLACE, m_ulSpyName, csMaxFormat);
				SendScanStatusToUI(Special_File_Report, m_ulSpyName, csFilePath);

				csMaxFormat.Format(_T("%s\\%s"), csFileLoc, szOnyFileName);
				if(!_taccess_s(csMaxFormat, 0))
				{
					SendScanStatusToUI(Special_File_Report, m_ulSpyName, csMaxFormat);
					AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, csMaxFormat);
				}

				csMaxFormat += _T(".ocx");
				if(!_taccess_s(csMaxFormat, 0))
				{
					SendScanStatusToUI(Special_File_Report, m_ulSpyName, csMaxFormat);
					AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, csMaxFormat);
				}
			}
		}
	}
	else if(!csFileLoc.CompareNoCase(m_objSysInfo.m_strWinDir))
	{
		if(IsRecentlyModified(csFilePath, stLastModTime, 30))
		{
			BYTE bySections[] = {0x20,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x20,0x00,0x00,0x00,0x00,0x00,0x00};
			IMAGE_SECTION_HEADER_MSS SectionHeader[10] = {0};
			DWORD dwCount = 0;

			dwCount = _countof(SectionHeader);
			if(CheckIfSectionsPresent(csFilePath, bySections, sizeof(bySections), 0, 0, SectionHeader, &dwCount))
			{
				for(DWORD i = 0; i < dwCount; i++)
				{
					if(0 == SectionHeader[i].SizeOfRawData)
					{
						bInfected = true;
						break;
					}
				}
			}
		}
	}
	else if(!csFileLoc.CompareNoCase(m_objSysInfo.m_strRoot))
	{
		IMAGE_NT_HEADERS_MSS NtHeader = {0};
		BYTE bySections[] = {0x2E,0x55,0x50,0x58,0x30,0x00,0x00,0x00,0x2E,0x55,0x50,0x58,0x31,0x00,0x00,0x00,
							 0x2E,0x61,0x73,0x70,0x61,0x63,0x6B,0x00};

		if(CheckIfSectionsPresent(csFilePath, 0, 0, 0, &NtHeader))
		{
			if(NtHeader.Signature == IMAGE_NT_SIGNATURE)
			{
				if(0 == NtHeader.OptionalHeader.AddressOfEntryPoint)
				{
					bInfected = true;
				}
			}
		}
		else if(CheckIfSectionsPresent(csFilePath, bySections, sizeof(bySections)))
		{
			bInfected = true;
		}
	}
	else
	{
		return false;
	}

	if(bInfected)
	{
		SendScanStatusToUI(Special_File, iSPYID_WormKolab, csFilePath);
	}

	return bInfected;
}

/*-------------------------------------------------------------------------------------
	Function		: IsRecentlyModified
	In Parameters	: const CString& csFilePath, FILETIME* stLastModTime, DWORD dwModWithinDays
	Out Parameters	: bool
	Purpose			: Check if the file is modified within given days
	Author			: anand srivastava
--------------------------------------------------------------------------------------*/
bool CSystemScan::IsRecentlyModified(const CString& csFilePath, FILETIME* stLastModTime, DWORD dwModWithinDays)
{
	DWORD dwTemp = 0;
	FILETIME TodaysTime = {0};
	SYSTEMTIME SysTime = {0};

	GetLocalTime(&SysTime);
	if(!SystemTimeToFileTime(&SysTime, &TodaysTime))
	{
		return false;
	}

	COleDateTime ot1(TodaysTime);
	COleDateTime ot2(*stLastModTime);
	COleDateTimeSpan otdiff = ot1 - ot2;
	return dwModWithinDays >= otdiff.GetTotalDays();
}
