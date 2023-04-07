/*====================================================================================
   FILE				: AntiSoldierWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware AntiSoldier
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
#include "antisoldierworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForAntiSpywareSoldier
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and remove AntiSpywareSoldier
	Author			: Anand
	Description		: runs uninstaller for AntiSpywareSoldier
	Version			: 18.3
--------------------------------------------------------------------------------------*/
bool CAntiSoldierWorm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;

		// kill the main window process of antispyware soldier
		if ( bToDelete )
			KillProcess ( _T("AntiSpyware Soldier") , _T("AntiSpySoldier.exe") ) ;

		m_bSplSpyFound = CheckAndRunUnInstallerWithParam ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("AntiSpyware Soldier"), _T("unins000.exe") ,
														   _T("/VERYSILENT /NORESTART") , bToDelete, m_ulSpyName );
		// wait for the Uninstaller to complete its processing
		Sleep ( 500 ) ;

		if ( m_bScanOtherLocations )
		{
			m_bSplSpyFound = CheckAndRunUnInstallerWithParam (
				m_csOtherPFDir + BACK_SLASH + _T("AntiSpyware Soldier"),
				_T("unins000.exe") ,_T("/VERYSILENT /NORESTART") ,
				bToDelete, m_ulSpyName );

			// wait for the Uninstaller to complete its processing
			Sleep ( 500 ) ;
		}

		
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;

	}

	catch(...)
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CAntiSoldierWorm::ScanSplSpy, Error : %d") , GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}

	return ( false ) ;
}
