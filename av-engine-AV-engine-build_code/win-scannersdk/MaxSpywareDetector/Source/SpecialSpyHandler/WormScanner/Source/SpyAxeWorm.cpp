/*====================================================================================
   FILE				: SpyAxeWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware SpyAxe
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
#include "spyaxeworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckforSpyAxe
	In Parameters	: CString , bool 
	Out Parameters	: 
	Purpose			: Checks and fixes SpyAxe
	Author			: 
	Description		: runs uninstaller to clean SpyAxe
--------------------------------------------------------------------------------------*/
bool CSpyAxeWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		CString csSpyAxe = CSystemInfo::m_strProgramFilesDir + BACK_SLASH + m_csSpywareName + BACK_SLASH + m_csSpywareName + _T(".exe");
		if( FindKillReportProcess(csSpyAxe, m_ulSpyName ,  bToDelete))
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			csSpyAxe = m_csOtherPFDir + BACK_SLASH + m_csSpywareName + BACK_SLASH + m_csSpywareName + _T(".exe");
			if( FindKillReportProcess(csSpyAxe, m_ulSpyName ,  bToDelete))
				m_bSplSpyFound = true;
		}
	
		if(CheckUnInstaller ( m_ulSpyName, m_csSpywareName, _T("uninst.exe"), bToDelete))
			m_bSplSpyFound = true;
		
		if( CheckReportDeleteRegKey( HKEY_LOCAL_MACHINE, CString(SOFTWARE) + CString(BACK_SLASH) 
			+ m_csSpywareName , BLANKSTRING , m_ulSpyName , bToDelete))
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			if( CheckReportDeleteRegKey( HKEY_LOCAL_MACHINE, CString(WOW6432NODE_REG_PATH) + CString(BACK_SLASH) + m_csSpywareName , BLANKSTRING , m_ulSpyName , bToDelete))
				m_bSplSpyFound = true;
		}
		
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSpyAxeWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return false;
}
