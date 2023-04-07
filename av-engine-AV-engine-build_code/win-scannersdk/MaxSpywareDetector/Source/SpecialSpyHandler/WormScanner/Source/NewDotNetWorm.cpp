/*=======================================================================================
   FILE				: NewDotNetWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware NewDotNet
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
#include "newdotnetworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForNewDotNet
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and remove NewDotNet
	Author			: 
	Description		: remove registry entry , BHO and fix LSP
--------------------------------------------------------------------------------------*/
bool CNewDotNetWorm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;
		
		if(IsStopScanningSignaled())
				return false;

		// terminate rundll32.exe, which has run newdotnet7_22.dll
		CString csRunDll32 ;
		csRunDll32 = CSystemInfo::m_strSysDir + _T("\\rundll32.exe") ;

		m_objEnumProcess.IsProcessRunning ( csRunDll32 , bToDelete ) ;
		if ( m_bScanOtherLocations )
		{
			m_objEnumProcess.IsProcessRunning ( m_csOtherSysDir + _T("\\rundll32.exe") , bToDelete ) ;
		}

		if( FindReportRegValue(RUN_REG_PATH, _T("New.net Startup"), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete, true))
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			if( FindReportRegValue ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) , _T("New.net Startup"), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete, true))
				m_bSplSpyFound = true;
		}

		if( FindReportRegKey(_T("SOFTWARE\\New.net"), m_ulSpyName , HKEY_LOCAL_MACHINE, bToDelete))
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			if( FindReportRegKey( CString(WOW6432NODE_REG_PATH) + CString(_T("\\New.net")), m_ulSpyName , HKEY_LOCAL_MACHINE, bToDelete))
				m_bSplSpyFound = true;
		}
		
		if ( !bToDelete )
		{
			if(RemoveBHOWithKey(_T("{4A2AACF3-ADF6-11D5-98A9-00E018981B9E}"), bToDelete, m_ulSpyName))
				m_bSplSpyFound = true ;
		}

		// do fixlsp and removing folder only if delete flag has come true
		// delete flag comes true only when spyware was found and has now come for fix
		if ( bToDelete )
		{
			// run appropriate .reg file to overwrite the deault LSP registry entries
			FixLSP() ;
		}
		else
		{
			// Clean up the NewDotNet folder made in Prog Files
			CString csNewDotNetProgFolder ;
			csNewDotNetProgFolder = CSystemInfo::m_strProgramFilesDir + _T("\\NewDotNet") ;
			RemoveFolders ( csNewDotNetProgFolder , m_ulSpyName , bToDelete ) ;

			if ( m_bScanOtherLocations )
			{
				csNewDotNetProgFolder = m_csOtherPFDir + _T("\\NewDotNet") ;
				RemoveFolders ( csNewDotNetProgFolder , m_ulSpyName , bToDelete ) ;
			}
		}
		
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CNewDotNetWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
