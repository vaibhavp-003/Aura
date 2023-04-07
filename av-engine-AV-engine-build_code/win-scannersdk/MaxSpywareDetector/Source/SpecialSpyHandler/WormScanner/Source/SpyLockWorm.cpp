/*====================================================================================
   FILE				: SpyLockWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware SpyLock
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
========================================================================================*/

#include "pch.h"
#include "SpyLockWorm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool , CFileSignatureListManager*
	Out Parameters	: bool
	Purpose			: Checks and removes spylocked folder from program files
	Author			: Anand
	Description		: Checks for folder of SpyLocked in PFDIR
--------------------------------------------------------------------------------------*/
bool CSpylockWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		BOOL			bMoreFiles = FALSE ;
		CFileFind		objFile ;
		CStringArray	csArrLocations ;

		csArrLocations . Add ( CSystemInfo::m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( m_csOtherPFDir ) ;

		for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
		{
			bMoreFiles = objFile.FindFile( csArrLocations [ i ] + _T("\\Spy*") ) ;
			while ( bMoreFiles )
			{
				if ( IsStopScanningSignaled() )
				{
					objFile.Close();
					return ( false );
				}

				bMoreFiles = objFile.FindNextFile() ;
				if ( !objFile.IsDirectory() )
					continue ;

				if ( CheckIfSpylockFolder ( objFile.GetFilePath() , objFile.GetFileName() ) )
				{
					m_bSplSpyFound = true;
					RemoveFolders ( objFile.GetFilePath() , m_ulSpyName , false ) ;
				}
			}

			objFile.Close();
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound;
	}

	catch ( ... )
	{
		CString csErr;
		csErr.Format( _T("Exception caught in  Spylock::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfSpylockFolder
	In Parameters	: const CString&
	Out Parameters	: bool
	Purpose			: determines that the given path is spylock folder
	Author			: Anand
	Description		: checks for files and data inside them to decide if this folder
--------------------------------------------------------------------------------------*/
bool CSpylockWorm :: CheckIfSpylockFolder ( const CString& csFolderPath , const CString& csFolderName )
{
	CString csFilename ;
	CArray<CStringA,CStringA> csArrKeywords ;

	csFilename = csFolderPath + BACK_SLASH + csFolderName + _T(".url") ;
	if ( _taccess_s ( csFilename , 0 ) )
		return ( false ) ;

	csArrKeywords . Add ( "spylocked.com" ) ;
	if ( !SearchStringsInFile ( csFilename , csArrKeywords ) )
		return ( false ) ;

	csFilename = csFolderPath + _T("\\blacklist.txt") ;
	if ( _taccess_s ( csFilename , 0 ) )
		return ( false ) ;

	return ( true ) ;
}
