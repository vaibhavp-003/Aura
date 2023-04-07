/*======================================================================================
   FILE				: WinFoundWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware WinFoundWorm
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
#include "winfoundworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckforWinHound
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and cleasn WinHound
	Author			: Anand
	Description		: removes unreabable key _T("SOFTWARE\\WinHound.com") in HKLM
					  and runs uninstaller of WinHound software
--------------------------------------------------------------------------------------*/
bool CWinFoundWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		if( CheckUnInstaller(7192,_T("WinHound"), _T("uninstall.exe"), bToDelete))
			m_bSplSpyFound = true;		
		
		if( CheckReportDeleteRegKey(HKEY_LOCAL_MACHINE, _T("SOFTWARE"), _T("WinHound.com"), m_ulSpyName, bToDelete))
			m_bSplSpyFound = true;

		if( m_bScanOtherLocations )
		{
			if( CheckReportDeleteRegKey(HKEY_LOCAL_MACHINE, WOW6432NODE_REG_PATH , _T("WinHound.com"), 
																m_ulSpyName, bToDelete))
				m_bSplSpyFound = true;
		}
		
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWinFoundWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

