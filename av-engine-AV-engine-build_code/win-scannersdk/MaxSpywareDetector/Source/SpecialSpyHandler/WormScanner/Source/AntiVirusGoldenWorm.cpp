/*=====================================================================================
   FILE				: AntiVirusGoldenWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware AntiVirusGolden
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
#include "antivirusgoldenworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForAntiVirusGolden
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and cleans AntiVirusGolden
	Author			: Anand
	Description		: Runs uninstaller to remove AntiVirusGolden
	Version			: 18.3
--------------------------------------------------------------------------------------*/
bool CAntiVirusGoldenWorm::ScanSplSpy( bool bToDelete, CFileSignatureDb *pFileSigMan )
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;

		bool bAVGFound = false ;
		bool bAV_GFound = false ;
		bool bAVGProFound = false ;

		bAVGFound = CheckAndRunUnInstallerWithParam( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("AntiVirusGolden") , _T("uninst.exe") , _T("/S") , bToDelete ,
													 m_ulSpyName ) ;
		if ( bAVGFound && bToDelete )
		{
			KillProcess( _T("AntiVirusGolden") , _T("AntiVirusGolden.exe") ) ;
			HandleUninstaller( 477 ) ;
		}

		if ( m_bScanOtherLocations )
		{
			bAVGFound = CheckAndRunUnInstallerWithParam( m_csOtherPFDir + BACK_SLASH + _T("AntiVirusGolden") , _T("uninst.exe") , _T("/S") , bToDelete ,
														 m_ulSpyName ) ;
			if ( bAVGFound && bToDelete )
			{
				KillProcess( _T("AntiVirusGolden") , _T("AntiVirusGolden.exe") ) ;
				HandleUninstaller( 477 ) ;
			}
		}

		bAV_GFound = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("AntiVirus-Golden") , _T("uninst.exe") , _T("/S") , bToDelete ,
													   m_ulSpyName ) ;
		if ( bAV_GFound && bToDelete )
		{
			KillProcess ( _T("AntiVirus-Golden") , _T("AntiVirus-Golden.exe") ) ;
			HandleUninstaller ( 477 ) ;
		}

		m_bSplSpyFound = bToDelete ? false : bAVGFound || bAV_GFound ;

		if ( m_bScanOtherLocations )
		{
			bAV_GFound = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("AntiVirus-Golden") , _T("uninst.exe") , _T("/S") , bToDelete ,
														   m_ulSpyName ) ;
			if ( bAV_GFound && bToDelete )
			{
				KillProcess ( _T("AntiVirus-Golden") , _T("AntiVirus-Golden.exe") ) ;
				HandleUninstaller ( 477 ) ;
			}
		}
		
		m_bSplSpyFound = bToDelete ? false : bAVGFound || bAV_GFound ;

		//Version : 19.0.0.24
		//Resource : Prajakta
		bAVGProFound = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("AntiVirusGoldenPro") , _T("uninst.exe") , _T("/S") , bToDelete ,
														 m_ulSpyName ) ;
		if ( bAVGProFound && bToDelete )
		{
			KillProcess ( _T("AntiVirusGoldenPro") , _T("AntiVirusGoldenPro.exe") ) ;
			HandleUninstaller ( 477 ) ;
		}

		if ( m_bScanOtherLocations )
		{
			//Version : 19.0.0.24
			//Resource : Prajakta
			bAVGProFound = CheckAndRunUnInstallerWithParam ( m_csOtherPFDir + BACK_SLASH + _T("AntiVirusGoldenPro") , _T("uninst.exe") , _T("/S") , bToDelete ,
															 m_ulSpyName ) ;
			if ( bAVGProFound && bToDelete )
			{
				KillProcess ( _T("AntiVirusGoldenPro") , _T("AntiVirusGoldenPro.exe") ) ;
				HandleUninstaller ( 477 ) ;
			}
		}

		if ( bAVGProFound && !bToDelete )
		{
			SendScanStatusToUI ( Special_Folder , m_ulSpyName , CSystemInfo::m_strProgramFilesDir + _T("\\AntiVirusGoldenPro")  ) ;
		}
		
		m_bSplSpyFound = bToDelete ? false : bAVGFound || bAV_GFound || bAVGProFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CAntiVirusGoldenWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
