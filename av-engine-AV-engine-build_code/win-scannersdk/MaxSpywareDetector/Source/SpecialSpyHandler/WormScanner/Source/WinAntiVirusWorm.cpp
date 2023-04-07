/*======================================================================================
   FILE				: WinAntiVirusWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware WinAntiVirus
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
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
					version: 2.5.0.33
					Resource : Sandip
					Description: Add CheckRandomEntries function to find Random entry in registry
					version: 2.5.0.33
					Resource : Sandip
					Description: Add valuexists condition in CheckRandomEntries function 
========================================================================================*/
#include "pch.h"
#include "winantivirusworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckforWinAntiVirus
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and remove WinAntiVirus
	Author			: Anand
	Description		: runs unistaller WinAntiVirus
--------------------------------------------------------------------------------------*/
bool CWinAntiVirusWorm::ScanSplSpy( bool bToDelete, CFileSignatureDb *pFileSigMan )
{
	try
	{
		m_pFileSigMan = pFileSigMan;
        
		if(IsStopScanningSignaled())
			return ( false ) ;

 		if( CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinAntiVirus 2005 Pro Trial"), _T("unins000.exe") ,
												   _T("/VERYSILENT /NORESTART"), bToDelete, m_ulSpyName ) )
		{
			m_bSplSpyFound = true;
			if ( bToDelete )
				HandleUninstaller ( m_ulSpyName ) ;
		}

		if( CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinAntiVirus 2005 Trial"), _T("unins000.exe") ,
											  _T("/VERYSILENT /NORESTART"), bToDelete, m_ulSpyName ) )
		{

			m_bSplSpyFound = true;
			if ( bToDelete )
				AddLogEntry(_T("WinAntiVirus variant handled"),0, 0); // no handling required
		}
		
		if( CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinAntiVirus 2005 Pro"), _T("unins000.exe") ,
											 _T("/VERYSILENT /NORESTART"), bToDelete, m_ulSpyName ) )
		{
			m_bSplSpyFound = true;
			if ( bToDelete )
				HandleUninstaller ( m_ulSpyName ) ;
		}
		
		if( CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinAntiVirus Pro 2006"), _T("unins000.exe"), _T("/VERYSILENT /NORESTART") ,
											  bToDelete, m_ulSpyName ) )
		{
			m_bSplSpyFound = true;
			if ( bToDelete )
				AddLogEntry(_T("WinAntiVirus variant handled"),0, 0);

		}
	
		//Version: 19.0.0.24
		//Resource: Prajata
		if( CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinAntiVirus Pro 2007"), _T("unins000.exe") ,
											  _T("/VERYSILENT /NORESTART"), bToDelete , m_ulSpyName ) )
		{
			m_bSplSpyFound = true;
			if ( bToDelete )
				AddLogEntry(_T("WinAntiVirus variant handled"),0, 0);

		}
		
		if ( !bToDelete )
		{
			//Version: 19.0.0.34
			//Resource: Sandip
			CheckRandomEntries ( SOFTWARE ) ;
		}

		if ( m_bScanOtherLocations )
		{
 			if( CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinAntiVirus 2005 Pro Trial"), _T("unins000.exe") ,
												  _T("/VERYSILENT /NORESTART"), bToDelete, m_ulSpyName ) )
			{
				m_bSplSpyFound = true;
				if ( bToDelete )
					HandleUninstaller ( m_ulSpyName ) ;
			}

			if( CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinAntiVirus 2005 Trial"), _T("unins000.exe") ,
												  _T("/VERYSILENT /NORESTART"), bToDelete, m_ulSpyName ) )
			{

				m_bSplSpyFound = true;
			}
			
			if( CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinAntiVirus 2005 Pro"), _T("unins000.exe") ,
												 _T("/VERYSILENT /NORESTART"), bToDelete, m_ulSpyName ) )
			{
				m_bSplSpyFound = true;
				if ( bToDelete )
					HandleUninstaller ( m_ulSpyName ) ;
			}
			
			if( CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinAntiVirus Pro 2006"), _T("unins000.exe"), _T("/VERYSILENT /NORESTART") ,
												  bToDelete, m_ulSpyName ) )
			{
				m_bSplSpyFound = true;

			}
		
			//Version: 19.0.0.24
			//Resource: Prajata
			if( CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinAntiVirus Pro 2007"), _T("unins000.exe") ,
												  _T("/VERYSILENT /NORESTART"), bToDelete , m_ulSpyName ) )
			{
				m_bSplSpyFound = true;
			}

			if ( !bToDelete )
			{
				//Version: 19.0.0.34
				//Resource: Sandip			
				CheckRandomEntries ( WOW6432NODE_REG_PATH ) ;
			}
		}
	
		// Clean registry entry incase if WinAntiSpyware 2006 was found
		if ( bToDelete && m_bSplSpyFound )
		{
			_RemoveInstallerEntry(HKEY_LOCAL_MACHINE, BLANKSTRING, HKLM );

			// Darshan
			// 25-June-2007
			// Added code to loop thru all users under HKEY_USERS
			for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
			{
				if(IsStopScanningSignaled())
					break;
				CString csUserKey = m_arrAllUsers.GetAt(iCnt);
				_RemoveInstallerEntry(HKEY_USERS, csUserKey + BACK_SLASH, CString(HKU) + CString(BACK_SLASH) 
					+ csUserKey);
			}
		}

		//Resource: Anand
		//Version:  19.0.0.9
		if ( !bToDelete )
		{
			if( _CheckIfDownloaderPresent())
				m_bSplSpyFound = true ;
		}

		//Resource: Anand
		//Version:  19.0.0.14
		if ( _taccess_s ( CSystemInfo::m_strProgramFilesDir + _T("\\WinAntiVirus 2005 Trial\\MailScan.dll") , 0 ) == 0)
		{
			m_bSplSpyFound = true ;
			if ( !bToDelete )
			{
				SendScanStatusToUI (Special_File ,  m_ulSpyName , CSystemInfo:: m_strProgramFilesDir + _T("\\WinAntiVirus 2005 Trial\\MailScan.dll") ) ;
			}
		}

		if ( m_bScanOtherLocations )
		{
			if ( _taccess_s ( m_csOtherPFDir + _T("\\WinAntiVirus 2005 Trial\\MailScan.dll") , 0 ) == 0)
			{
				m_bSplSpyFound = true ;
				if ( !bToDelete )
				{
					SendScanStatusToUI (Special_File ,  m_ulSpyName , m_csOtherPFDir + _T("\\WinAntiVirus 2005 Trial\\MailScan.dll")) ;
				}
			}
		}

		//version: 16.3
		//resource: Anand
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWinAntiVirusWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckRandomEntries
	In Parameters	: const CString csKeyPath 
	Out Parameters	: void
	Purpose			: checks the random software entry
	Author			: sandip sanap
	Description		: searches  WinAntiVirus entry from registry software
--------------------------------------------------------------------------------------*/
void CWinAntiVirusWorm :: CheckRandomEntries ( const CString &csKeyPath )
{
	CRegistry objRegistry;
	CStringArray csSubArray;		
	try
	{
		objRegistry.EnumSubKeys(csKeyPath,csSubArray,HKEY_LOCAL_MACHINE);
		BYTE szValue[1024] = {0};	
		CString csData;
		for(int i=0; i<csSubArray.GetCount(); i++)
		{				
			if(!objRegistry.ValueExists(csKeyPath + L"\\" + csSubArray[i] , L"1" , HKEY_LOCAL_MACHINE))
				continue;

			objRegistry.Get(csKeyPath + L"\\" + csSubArray[i], L"1", REG_BINARY, szValue, sizeof(szValue), HKEY_LOCAL_MACHINE);
			csData  =  ( const char * )szValue;
			csData.MakeLower();

			if(csData.Find(L"winantivirus.com") != -1)
			{
				EnumAndReportCOMKeys(m_ulSpyName, csKeyPath + BACK_SLASH + csSubArray[i], HKEY_LOCAL_MACHINE , false);
				m_bSplSpyFound = true;				
				break;		
			}
		}
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWinAntiVirusWorm::CheckRandomEntries, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}	
}

/*-------------------------------------------------------------------------------------
	Function		: RemoveInstallerEntry
	In Parameters	: HKEY
	Out Parameters	: 
	Purpose			: checks the installer entry
	Author			: 
	Description		: searches and removes WinAntiVirus entry from registry
--------------------------------------------------------------------------------------*/
void CWinAntiVirusWorm::_RemoveInstallerEntry(HKEY hHive, CString csMainKey, CString csHive)
{
	try
	{
		CString		csWinAVFolderName	=	_T("winantivirus") ;
		CStringArray csArrVal , csArrData ;
		CStringArray csArrLocations ;

		csArrLocations . Add ( RUNONCE_REG_PATH ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUNONCE_REG_PATH) ) ;

		for ( int i = 0 ; i < csArrLocations.GetCount() ; i++ )
		{
			m_objReg.QueryDataValue(csMainKey + csArrLocations [ i ] , csArrVal, csArrData, hHive);
			int nRunOnceVal = (int)csArrVal.GetCount();

			for ( i = 0; i < nRunOnceVal; i++)
			{
				csArrData[i].MakeLower() ;
				if (csArrData[i].Find(csWinAVFolderName)  != -1)
				{
					m_objReg.DeleteValue(csMainKey + csArrLocations [ i ], csArrVal[i], hHive) ;
				}
			}
		}
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWinAntiVirusWorm::_RemoveInstallerEntry, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfDownloaderPresent
	In Parameters	: HKEY
	Out Parameters	: 
	Purpose			: checks the run reg key for downloader entry
	Author			: 
	Description		: searches and removes WinAntiVirus and WinAntiSpyware downloader page entry from registry
--------------------------------------------------------------------------------------*/
bool CWinAntiVirusWorm::_CheckIfDownloaderPresent ( void )
{
	try
	{
		CString csData ;
		const TCHAR *End = NULL, *Ptr = NULL;
		TCHAR szFileName[MAX_PATH] = { 0 } ;
        DWORD dwDataType = 0;
		m_objReg.Get(RUN_REG_PATH, _T("CTDrive"), csData, HKEY_LOCAL_MACHINE,&dwDataType);

		if ( csData.IsEmpty() )
			return false;

		// see if rundll is present in entry
		Ptr = StrStrI ( csData , _T("rundll32") ) ;
		if ( !Ptr )
			return false;

		// now make the pointer point to dll filename
		Ptr = _tcschr ( csData , _T(' ') ) ;
		if ( !Ptr )
			return false;

		Ptr++ ;
		if ( !Ptr || !*Ptr )
			return false;
	    
		End = _tcschr ( Ptr , _T(',') ) ;
		if ( !End )
			return false;

		if ( End - Ptr >= _countof ( szFileName ) )
			return false;

		// copy the filename
		_tcsncpy_s ( szFileName , _countof ( szFileName ) , Ptr , End - Ptr ) ;

		// check if the file is persent
		if ( _taccess_s ( szFileName , 0 ) )
			return false;

		Ptr = _tcsrchr ( szFileName , _T('\\') ) ;
		if ( !Ptr )
			return false;

		Ptr++ ;
		if ( !Ptr || !*Ptr )
			return false;

		// check if the first three letters are drv of the filename
		if ( _tcsnicmp ( Ptr , _T("drv") , 3 ) )
			return false ;

		SendScanStatusToUI ( Special_File , m_ulSpyName , szFileName  ) ;		
		SendScanStatusToUI ( Special_RegVal , m_ulSpyName , HKEY_LOCAL_MACHINE ,  CString(RUN_REG_PATH) 
            , CString(_T("CTDrive"))  ,dwDataType, (LPBYTE)(LPCTSTR)csData, csData.GetLength()+sizeof(TCHAR));
		return ( true ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWinAntiVirusWorm::_CheckIfDownloaderPresent, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}
