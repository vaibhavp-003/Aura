/*======================================================================================
   FILE				: WebSerToolbarWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware WebSerToolbar
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
#include "WebSerToolbarWorm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckWebSearchToolBar
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks if the file is a hotbar file
	Author			: 
	Description		: Removes file in Prog files in \\WebSearch Toolbar\\TBPSSvc.exe
					  and \\WebSearch Toolbar\\TBPSSvc.exe
					  and removes rnu entries and BHO
--------------------------------------------------------------------------------------*/
bool CWebSerToolbarWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		CStringArray csArrLocations ;

		csArrLocations . Add ( CSystemInfo::m_strProgramFilesDir ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( m_csOtherPFDir ) ;

		for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
		{
			if ( PathIsDirectory ( csArrLocations [ i ] + BACK_SLASH + _T("WebSearch Toolbar") ) )
			{
				m_bSplSpyFound = true;
				RemoveFolders ( csArrLocations [ i ] + _T("\\WebSearch Toolbar") , m_ulSpyName , bToDelete );
			}

			if( FindKillReportProcess(csArrLocations [ i ] + _T("\\WebSearch Toolbar\\TBPSSvc.exe"), m_ulSpyName, bToDelete))
				m_bSplSpyFound = true;

			if( FindKillReportProcess(csArrLocations [ i ] + _T("\\WebSearch Toolbar\\PIB.exe"), m_ulSpyName, bToDelete))
				m_bSplSpyFound = true;

			if( FindKillReportProcess(csArrLocations [ i ] +_T("\\WebSearch Toolbar\\TBPS.exe"), m_ulSpyName, bToDelete))
				m_bSplSpyFound = true;

			if( FindKillReportProcess(csArrLocations [ i ] + _T("\\WebSearch Toolbar\\TBPSSvc.exe"), m_ulSpyName, bToDelete))
				m_bSplSpyFound = true;
		}
		
		if(IsStopScanningSignaled())
			return false;
		
		// Darshan
		// 25-June-2007
		// Added code to loop thru all users under HKEY_USERS
		for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
		{
			if(IsStopScanningSignaled())
				break;
			CString csUserKey = m_arrAllUsers.GetAt(iCnt);
			if(FindReportRegValue(csUserKey + BACK_SLASH + RUN_REG_PATH, _T("TBPS"), m_ulSpyName , HKEY_USERS, bToDelete))
				m_bSplSpyFound = true;
		}

		if ( FindReportRegValue ( RUN_REG_PATH , _T("TBPS"), m_ulSpyName,HKEY_LOCAL_MACHINE, bToDelete ) )
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			if ( FindReportRegValue ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_RUN_REG_PATH) , _T("TBPS"), m_ulSpyName,HKEY_LOCAL_MACHINE, bToDelete ) )
				m_bSplSpyFound = true;
		}
	
		if ( RemoveBHOWithKey ( _T("{8952A998-1E7E-4716-B23D-3DBE03910972}") , bToDelete , m_ulSpyName ) )
			m_bSplSpyFound = true;

		CString csFolderPath;

		csFolderPath.Format(_T("%s\\MyWebSearch"), CSystemInfo::m_strProgramFilesDir);
		if(!_taccess(csFolderPath, 0))
		{
			RemoveFolders(csFolderPath, m_ulSpyName, false);
		}

		csFolderPath.Format(_T("%s\\FunWebProducts"), CSystemInfo::m_strProgramFilesDir);
		if(!_taccess(csFolderPath, 0))
		{
			RemoveFolders(csFolderPath, m_ulSpyName, false);
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;

	}//End Of Try Block

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWebSerToolbarWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return false;
}
