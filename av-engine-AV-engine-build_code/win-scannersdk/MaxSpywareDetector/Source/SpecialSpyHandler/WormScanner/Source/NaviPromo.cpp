/*======================================================================================
   FILE				: NaviPromoWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware NaviPromo
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created in 2009 as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 09/04/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.75
					Resource : Anand
					Description: created this class
========================================================================================*/

#include "pch.h"
#include "NaviPromo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool , CFileSignatureDb*
	Out Parameters	: bool
	Purpose			: Check and remove NaviPromo
	Author			: Anand Srivastava
	Description		: This function checks for random files in sysdir
--------------------------------------------------------------------------------------*/
bool CNaviPromoWorm :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		if ( false == bToDelete )
		{
			CFileFind objFinder ;
			CStringArray csLocations ;
			BOOL bMoreFiles = FALSE ;

			csLocations . Add ( CSystemInfo :: m_strSysDir ) ;
			if ( m_bScanOtherLocations ) csLocations . Add ( m_csOtherSysDir ) ;

			// loop for both sysdir and 32bit sys dir if on 64 bit machine
			for ( INT_PTR i = 0 , iTotal = csLocations . GetCount() ; i < iTotal ; i++ )
			{
				// search for .dat files
				bMoreFiles = objFinder . FindFile ( csLocations [ i ] + _T("\\*.dat") ) ;
				if ( FALSE == bMoreFiles )
					continue ;

				while ( bMoreFiles )
				{
					bMoreFiles = objFinder . FindNextFile() ;
					if ( objFinder . IsDirectory() )
						continue ;

					// check if this .dat file is spyware
					if ( IsSpywareFile ( objFinder . GetFilePath() ) )
					{
						// report all the entries related with this .dat file
						ReportAllEntries ( objFinder . GetFilePath() ) ;
						m_bSplSpyFound = true ;
					}
				}

				objFinder . Close() ;
			}
		}


		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) AddLogEntry ( _T("Spyware Found : %s") , m_csSpywareName ) ;
		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CXPProWorm::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckValuetobeDigit
	In Parameters	: CString
	Out Parameters	: bool
	Purpose			: check if the file is spyware
	Author			: Anand
	Description		: check for a pattern and determine if the file is infected
--------------------------------------------------------------------------------------*/
bool CNaviPromoWorm :: IsSpywareFile ( LPCTSTR szFileName )
{
	TCHAR szFileNameOnly [ MAX_PATH ] = { 0 } ;

	// get only file name from full filepath, without extension
	if ( 0 != _tsplitpath_s ( szFileName , 0 , 0 , 0 , 0 , szFileNameOnly , _countof ( szFileNameOnly ) , 0 , 0 ) )
		return ( false ) ;

	// if this file is not present return false
	if ( _taccess ( CSystemInfo::m_strSysDir + BACK_SLASH + szFileNameOnly + _T(".exe") , 0 ) )
		return ( false ) ;

	// if this file is not present return false
	if ( _taccess ( CSystemInfo::m_strSysDir + BACK_SLASH + szFileNameOnly + _T("_nav.dat") , 0 ) )
		return ( false ) ;

	// if this file is not present return false
	if ( _taccess ( CSystemInfo::m_strSysDir + BACK_SLASH + szFileNameOnly + _T("_navps.dat") , 0 ) )
		return ( false ) ;

	// when all the files are found present, return true
	return ( true ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ReportAllEntries
	In Parameters	: LPCTSTR
	Out Parameters	: bool
	Purpose			: report all the entries
	Author			: Anand
	Description		: report all entries in sys32 and reg run path
--------------------------------------------------------------------------------------*/
bool CNaviPromoWorm :: ReportAllEntries ( LPCTSTR szFileName )
{
	CString csInfectedFileName ;
	TCHAR szFileNameOnly [ MAX_PATH ] = { 0 } ;
	TCHAR* szFilesList [] =
	{
		_T(".exe") ,
		_T(".dat") ,
		_T("_nav.dat") ,
		_T("_navps.dat") ,
		_T("_navup.dat") ,
		_T("_navtmp.dat") ,
		_T("_m2s.xml") ,
		_T("_m2s.zl")
	};

	// get only file name from full filepath, without extension
	if ( 0 != _tsplitpath_s ( szFileName , 0 , 0 , 0 , 0 , szFileNameOnly , _countof ( szFileNameOnly ) , 0 , 0 ) )
		return ( false ) ;

	// this called before calling KeyExists() becuase if there are no rights exits fails
	m_objReg . AdjustPermissions ( HKEY_LOCAL_MACHINE , (CString)UNINSTALL_PATH + (CString)BACK_SLASH + szFileNameOnly ) ;
	if ( m_objReg . KeyExists ( HKLM + (CString)BACK_SLASH + (CString)UNINSTALL_PATH + (CString)BACK_SLASH + szFileNameOnly , HKEY_LOCAL_MACHINE ) )
		EnumKeynSubKey ( (CString)UNINSTALL_PATH + (CString)BACK_SLASH + szFileNameOnly , m_ulSpyName , false ) ;
	
	for ( int i = 0 ; i < _countof ( szFilesList ) ; i++ )
	{
		csInfectedFileName = CSystemInfo :: m_strSysDir + BACK_SLASH + szFileNameOnly + szFilesList [ i ] ;

		if ( 0 == _taccess ( csInfectedFileName , 0 ) )
			SendScanStatusToUI ( Special_File , m_ulSpyName , csInfectedFileName );

		if ( 0 == i )
			SearchStringInRunKeyData ( m_ulSpyName , csInfectedFileName , CString ( BLANKSTRING ) , CString ( BLANKSTRING ) , HKEY_USERS ) ;
	}

	return ( true ) ;
}