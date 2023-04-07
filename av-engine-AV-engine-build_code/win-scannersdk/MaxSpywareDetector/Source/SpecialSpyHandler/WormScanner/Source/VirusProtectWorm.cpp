/*=============================================================================
   FILE				: VirusProtectWorm.Cpp
   ABSTRACT			: Implementation of Special Spyware VirusProtect Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 31/08/2007
   NOTES			:
   VERSION HISTORY	: 
						version: 2.5.0.13
						resource: Anand
						Description: added fix for VirusProtect variant spyware

						version: 2.5.0.23
						Resource : Anand
						Description: Ported to VS2005 with Unicode and X64 bit Compatability
=============================================================================*/

#include "pch.h"
#include "VirusProtectWorm.h"
#include "StringFunctions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool , CFileSignatureListManager*
	Out Parameters	: bool
	Purpose			: Checks and removes VirusProtect
	Author			: Anand Srivastava
	Description		: scans for worm VirusProtect in pfdir
--------------------------------------------------------------------------------------*/
bool CVirusProtectWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan )
{
	try
	{
		CString csPath = m_objSysInfo . m_strProgramFilesDir + _T("\\VirusProtect") ;
		CFileFind objFinder ;
		BOOL bFind = FALSE ;

		CStringArray csArrLocations ;

		csArrLocations . Add ( CSystemInfo::m_strProgramFilesDir + _T("\\VirusProtect") ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( m_csOtherPFDir + _T("\\VirusProtect") ) ;

		for ( int i = 0 ; i < csArrLocations.GetCount() ; i++ )
		{
			bFind = objFinder . FindFile ( csArrLocations [ i ] ) ;
			if ( !bFind )
				continue ;

			while ( bFind )
			{
				bFind = objFinder . FindNextFile() ;
				if ( objFinder . IsDots() || !objFinder . IsDirectory() )
					continue ;

				if ( IsSpywareFolder ( objFinder . GetFilePath() , objFinder . GetFileName() ) )
				{
					m_bSplSpyFound = true ;
					RemoveFolders ( objFinder . GetFilePath() , m_ulSpyName , false ) ;
				}
			}

			objFinder . Close() ;
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch (...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in VirusProtect::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: IsSpywareFolder
	In Parameters	: const CString& 
	Out Parameters	: bool
	Purpose			: Determines whether a VirusProtect folder
	Author			: Anand Srivastava
	Description		: determines whether a given folder is a VirusProtect folder
--------------------------------------------------------------------------------------*/
bool CVirusProtectWorm :: IsSpywareFolder ( const CString& csPath , const CString& csName )
{
	CString csFullFilename ;
	CFileVersionInfo objFileVersionInfo ;
	TCHAR szCompanyName [ MAX_PATH ] = { 0 } ;

	// make full filename
	csFullFilename = csPath + BACK_SLASH + csName + _T(".exe") ;

	// must have an exe file in the path with same name
	if ( _taccess_s ( csFullFilename , 0 ) )
		return ( false ) ;

	// check and return false if doesnt have a version tab
	if ( objFileVersionInfo . DoTheVersionJob ( csFullFilename , false ) )
		return ( false ) ;

	// get the company name
	if ( objFileVersionInfo . GetCompanyName ( csFullFilename , szCompanyName ) )
		return ( false ) ;

	// company name must contain VirusProtect
	if ( !StrNIStr ( (UCHAR*) szCompanyName , _tcslen ( szCompanyName ) , (UCHAR*) _T("VirusProtect") , 12 ) )
		return ( false ) ;

	return ( true ) ;
}
