/*======================================================================================
   FILE				: SmokingGunWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware 180Solutions
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

					version: 2.5.0.31
					Resource : Shweta
					Description: Added Code to scan random registry entries and ini file.
					Added call for RandomVersion and CheckForUninstallKey.
========================================================================================*/

#include "pch.h"
#include "smokinggunworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and fix SmokingGun spyware
	Author			: Anand
	Description		: checks and removes SmokingGun random folder in pfdir
--------------------------------------------------------------------------------------*/
bool CSmokingGunWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;

		CFileFind objFind;
		BOOL bMoreFiles = FALSE ;
		CStringArray csArrLocations ;
		CString csRandomVersion = _T("") , csSubFolderName = _T("") ;

		csArrLocations . Add ( CSystemInfo::m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( m_csOtherPFDir ) ;

		for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
		{
			bMoreFiles = objFind.FindFile( csArrLocations [ i ] + _T("\\*.*") );
			while ( bMoreFiles )
			{
				bMoreFiles = objFind.FindNextFile();
				if ( objFind.IsDots() || !objFind.IsDirectory() )
					continue ;

				if ( IsRandomSpywareFolder ( objFind.GetFilePath(), _T("smokinggun"), m_ulSpyName ))
				{
					m_bSplSpyFound =  true ;
					RemoveFolders ( objFind.GetFilePath(), m_ulSpyName , false ) ;

					//2.5.0.31		
					//Change Made for Scan Random .INI Files & RegistryKey 
					CString csRandomNumber , csFolderName , csRandomVersionWithDot ;
					csRandomNumber = "" ;
					csFolderName = objFind .GetFilePath() ;
					int iDashIndex = 0 ;

					iDashIndex = csFolderName . Find ( L"-" , 0 ) ;
					if ( iDashIndex != -1 )
					{
						csRandomNumber = csFolderName . Right ( csFolderName . GetLength() - ( iDashIndex + 1 ) ) ;

						//Scan random regidtry key & report to UI
						CheckForKeyLoggerKeys ( csRandomNumber , L"PCSmokingGun" , m_ulSpyName , L"SmokingGun" ) ;

					}

					if ( RandomVersion (csFolderName , csRandomVersion , csSubFolderName, csRandomVersionWithDot  , L"SmokingGun.Net") )
					{
						CheckForUninstallKey ( csRandomVersionWithDot , m_ulSpyName , L"SmokingGun.Net");
						CheckForKeyLoggerFiles ( csRandomNumber , m_ulSpyName ,  csSubFolderName ,csRandomVersion  , L"SmokingGun.Net") ;
					}
				}
			}
			objFind.Close();
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;

	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSmokingGunWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

