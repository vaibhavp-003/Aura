/*====================================================================================
   FILE				: PSGuardWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware PSGuard
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

					version: 2.5.0.34
					Resource : Anand
					Description: Fixed ShudderLTD registry entry
========================================================================================*/

#include "pch.h"
#include "psguardworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckforPsGuard
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and cleans PsGuard
	Author			: 
	Description		: removes key _T("SOFTWARE\\PSGuard.com") under HKLM
					  and runs uninstaller
--------------------------------------------------------------------------------------*/
bool CPSGuardWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

        if(IsStopScanningSignaled())
			return false;

		if ( !bToDelete )
		{
			m_csArrInfectedKeys.RemoveAll();
		}
		else
		{
			for ( int i = 0 ; i < m_csArrInfectedKeys . GetCount() ; i++ )
				DeleteAllTheValues ( HKEY_LOCAL_MACHINE , m_csArrInfectedKeys [ i ] ) ;
		}

		if( CheckUnInstaller(5074, _T("P.S.Guard"), _T("uninstall.exe"), bToDelete) || 
		    CheckUnInstaller(5074, _T("PSGuard"), _T("uninstall.exe"), bToDelete))
			m_bSplSpyFound = true;

		if( CheckReportDeleteRegKey ( HKEY_LOCAL_MACHINE, SOFTWARE, _T("PSGuard.com"), m_ulSpyName, bToDelete ))
		{
			m_bSplSpyFound = true;
			if ( !bToDelete ) m_csArrInfectedKeys . Add ( CString(SOFTWARE) + CString(_T("\\PSGuard.com")) ) ;
		}

		if( CheckReportDeleteRegKey ( HKEY_LOCAL_MACHINE, SOFTWARE, _T("ShudderLTD"), m_ulSpyName, bToDelete ))
		{
			m_bSplSpyFound = true;
			if ( !bToDelete ) m_csArrInfectedKeys . Add ( CString(SOFTWARE) + CString(_T("\\ShudderLTD")) ) ;
		}

		if ( m_bScanOtherLocations )
		{
			if( CheckReportDeleteRegKey( HKEY_LOCAL_MACHINE, WOW6432NODE_REG_PATH, _T("PSGuard.com"), m_ulSpyName, bToDelete ))
			{
				m_bSplSpyFound = true;
				if ( !bToDelete ) m_csArrInfectedKeys . Add ( CString(WOW6432NODE_REG_PATH) + 
					CString(_T("\\PSGuard.com")) ) ;
			}

			if( CheckReportDeleteRegKey ( HKEY_LOCAL_MACHINE, WOW6432NODE_REG_PATH, _T("ShudderLTD"), m_ulSpyName, bToDelete ))
			{
				m_bSplSpyFound = true;
				if ( !bToDelete ) m_csArrInfectedKeys . Add ( CString(WOW6432NODE_REG_PATH) + CString(_T("\\ShudderLTD")) ) ;
			}
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound;	
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CPSGuardWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
