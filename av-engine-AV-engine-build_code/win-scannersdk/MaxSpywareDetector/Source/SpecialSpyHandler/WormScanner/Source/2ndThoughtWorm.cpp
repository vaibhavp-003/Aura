 /*====================================================================================
   FILE				: 2ndThoughtWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware 2ndThought
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
========================================================================================*/

#include "pch.h"
#include "io.h"
#include "2ndthoughtworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: Check2ndThought
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and removes 2ndThought
	Author			: 
	Description		: makes a list of all keys under HKLM\software and checks for a pattern
					  in program files folder
--------------------------------------------------------------------------------------*/
bool C2ndThoughtWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
		{
			return m_bSplSpyFound ;
		}

		CStringArray csArrSubKeys ;
		if ( !m_objReg . EnumSubKeys ( SOFTWARE , csArrSubKeys , HKEY_LOCAL_MACHINE) )
		{
			return ( false ) ;
		}

		if ( m_bScanOtherLocations )
		{
			if ( !m_objReg . EnumSubKeys ( WOW6432NODE_REG_PATH , csArrSubKeys , HKEY_LOCAL_MACHINE) )
			{
				return ( false ) ;
			}
		}

		for ( int index = 0 ; index < csArrSubKeys . GetCount() ; index++ )
		{
			ArePatternFoldersPresent ( csArrSubKeys [ index ] , bToDelete ) ;
		}

		//version: 16.3
		//resource: Anand
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in C2ndThoughtWorm::ScanSplSpy(), Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ArePatternFoldersPresent
	In Parameters	: char *
	Out Parameters	: bool * 
	Purpose			: Checks and makes entry in UI
	Author			: 
	Description		: Checks for folder in list and sends to UI
--------------------------------------------------------------------------------------*/
bool C2ndThoughtWorm :: ArePatternFoldersPresent ( const CString& csRegKeyName, bool bDeleteEntries )
{
	try
	{
		CStringArray csArrPFDirLocations ;

		if(IsStopScanningSignaled())
			return false;

		csArrPFDirLocations . Add ( CSystemInfo::m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations )
		{
			csArrPFDirLocations . Add ( m_csOtherPFDir ) ;
		}

		for ( int i = 0 ; i < csArrPFDirLocations . GetCount() ; i++ )
		{
			CString csName = csArrPFDirLocations [ i ] + BACK_SLASH + csRegKeyName ;
			if ( 0 != _taccess ( csName , 0 ) )
				return ( false ) ;

			csName = csArrPFDirLocations [ i ] + BACK_SLASH + csRegKeyName + BACK_SLASH + csRegKeyName + _T("1") ;
			if ( 0 != _taccess ( csName , 0 ) )
				return ( false ) ;

			m_bSplSpyFound = true ;
			csName = csArrPFDirLocations [ i ] + BACK_SLASH + csRegKeyName ;
			RemoveFolders( csName , m_ulSpyName , bDeleteEntries ) ;

			csName = CString(SOFTWARE) + CString(BACK_SLASH) + csRegKeyName ;
			if ( FindReportRegKey ( csName , m_ulSpyName , HKEY_LOCAL_MACHINE, false))
				m_bSplSpyFound = true ;

			if ( m_bScanOtherLocations )
			{
				csName = CString(WOW6432NODE_REG_PATH) + CString(BACK_SLASH) + csRegKeyName ;
				if ( FindReportRegKey ( csName , m_ulSpyName , HKEY_LOCAL_MACHINE, false))
					m_bSplSpyFound = true ;
			}

			csName = CString(SOFTWARE) + CString(BACK_SLASH) + csRegKeyName + CString ( _T("1") ) ;
			if( FindReportRegKey ( csName , m_ulSpyName , HKEY_LOCAL_MACHINE, false))
				m_bSplSpyFound = true ;

			if ( m_bScanOtherLocations )
			{
				csName = CString(WOW6432NODE_REG_PATH) + CString(BACK_SLASH) + csRegKeyName + CString ( _T("1") ) ;
				if( FindReportRegKey ( csName , m_ulSpyName , HKEY_LOCAL_MACHINE, false))
					m_bSplSpyFound = true ;
			}
		}

		return ( m_bSplSpyFound ) ;
	}
	
	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in C2ndThoughtWorm::ArePatternFoldersPresent, Error : %d") ,GetLastError());
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}
