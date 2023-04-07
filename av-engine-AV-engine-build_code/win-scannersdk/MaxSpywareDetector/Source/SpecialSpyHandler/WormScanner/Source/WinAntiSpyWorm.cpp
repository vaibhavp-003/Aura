/*======================================================================================
   FILE				: WinAntiSpyWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware WinAntiSpy
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
#include "winantispyworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckforWinAntiSpyware
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and remove win Anti spyware
	Author			: Anand
	Description		: runs uninstaller for win anti spyware
--------------------------------------------------------------------------------------*/
bool CWinAntiSpyWorm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;

		if( CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinAntiSpyware 2005"), _T("unins000.exe"), _T("/VERYSILENT /NORESTART") ,
											  bToDelete, m_ulSpyName ) )
		{
			m_bSplSpyFound = true;
			if(bToDelete)
				HandleUninstaller ( m_ulSpyName ) ;
		}
		
		if( CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinAntiSpyware 2006 Scanner"), _T("unins000.exe") ,
											_T("/VERYSILENT /NORESTART"), bToDelete, m_ulSpyName ) )
		{
			m_bSplSpyFound = true;
			if(bToDelete)
				HandleUninstaller ( m_ulSpyName ) ;
		}
		
		if( CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinAntiSpyware 2006 Free"), _T("unins000.exe"), _T("/VERYSILENT /NORESTART") ,
												   bToDelete, m_ulSpyName ) )
		{
			m_bSplSpyFound = true;
			if(bToDelete)
				HandleUninstaller ( m_ulSpyName ) ;
		}
	
		//version:19.0.0.24
		//Resource: Prajata
		if( CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("WinAntiSpyware 2007 Free"), _T("unins000.exe"), 
											  _T("/VERYSILENT /NORESTART"), bToDelete, m_ulSpyName ) )
		{
			m_bSplSpyFound = true;
			if(bToDelete)
			{
				SearchStringInRunKeyData( m_ulSpyName , _T("WinAntiSpyware") ) ;
				HandleUninstaller ( m_ulSpyName ) ;
			}
		}

		if ( m_bScanOtherLocations )
		{
			if( CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinAntiSpyware 2005"), _T("unins000.exe"), _T("/VERYSILENT /NORESTART") ,
												  bToDelete, m_ulSpyName ) )
			{
				m_bSplSpyFound = true;
				if(bToDelete)
					HandleUninstaller ( m_ulSpyName ) ;
			}
			
			if( CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinAntiSpyware 2006 Scanner"), _T("unins000.exe") ,
												_T("/VERYSILENT /NORESTART"), bToDelete, m_ulSpyName ) )
			{
				m_bSplSpyFound = true;
				if(bToDelete)
					HandleUninstaller ( m_ulSpyName ) ;
			}
			
			if( CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinAntiSpyware 2006 Free"), _T("unins000.exe"), _T("/VERYSILENT /NORESTART") ,
													   bToDelete, m_ulSpyName ) )
			{
				m_bSplSpyFound = true;
				if(bToDelete)
					HandleUninstaller ( m_ulSpyName ) ;
			}
		
			//version:19.0.0.24
			//Resource: Prajata
			if( CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("WinAntiSpyware 2007 Free"), _T("unins000.exe"), 
												  _T("/VERYSILENT /NORESTART"), bToDelete, m_ulSpyName ) )
			{
				m_bSplSpyFound = true;
				if(bToDelete)
				{
					SearchStringInRunKeyData( m_ulSpyName , _T("WinAntiSpyware") ) ;
					HandleUninstaller ( m_ulSpyName ) ;
				}
			}
		}

		//version: 16.3
		//resource: Anand
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWinAntiSpyWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}

