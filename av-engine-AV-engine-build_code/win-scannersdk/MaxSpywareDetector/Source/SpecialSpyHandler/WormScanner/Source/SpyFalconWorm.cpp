/*====================================================================================
   FILE				: SpyFalconWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware SpyFalcon
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
#include "spyfalconworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckforSpyFalcon
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and cleans SpyFalcon
	Author			: Anand
	Description		: Runs uninstaller to remove SpyFalcon
--------------------------------------------------------------------------------------*/
bool CSpyFalconWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;

		m_bSplSpyFound = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("SpyFalcon") , _T("uninst.exe") , _T("/S") , bToDelete ,
														   m_ulSpyName ) ;
		if ( m_bSplSpyFound && bToDelete )
		{
			KillProcess ( _T("SpyFalcon") , _T("SpyFalcon.exe") ) ;
			HandleUninstaller ( m_ulSpyName ) ;
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;

		if ( m_bScanOtherLocations )
		{
			m_bSplSpyFound = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("SpyFalcon") , _T("uninst.exe") , _T("/S") , bToDelete ,
															   m_ulSpyName ) ;
			if ( m_bSplSpyFound && bToDelete )
			{
				KillProcess ( _T("SpyFalcon") , _T("SpyFalcon.exe") ) ;
				HandleUninstaller ( m_ulSpyName ) ;
			}

			m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
			//if ( m_bSplSpyFound ) 
			//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		}
		return ( m_bSplSpyFound ) ;

	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CSpyFalconWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}
