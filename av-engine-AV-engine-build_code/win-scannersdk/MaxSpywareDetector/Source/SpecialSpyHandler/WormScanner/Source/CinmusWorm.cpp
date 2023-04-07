/*====================================================================================
   FILE				: CinmusWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware Cinmus
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
#include "cinmusworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//Version : 19.0.0.039
/*-------------------------------------------------------------------------------------
Function		: CheckForCinmus
In Parameters	: bool
Out Parameters	: bool
Purpose			: Driver Entry,ntmcsvc.dll couldnt be deleted
Author			: Shweta
Description		: Check and remove Driver Entry , ntmcsvc.dll and  ~.exe 
--------------------------------------------------------------------------------------*/
bool CCinmusWorm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		CStringArray csArrLocations ;
		
		csArrLocations.Add ( CSystemInfo::m_strSysDir ) ;
		if ( m_bScanOtherLocations )
			csArrLocations.Add ( m_csOtherSysDir ) ;

		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;

		if ( !bToDelete )
			m_cArrAdwrCinmus.RemoveAll();

		for ( int i = 0 ; i < csArrLocations.GetCount() ; i++ )
		{
			if ( CheckAndRemoveDriver ( m_ulSpyName , _T("acpidisk") , csArrLocations [ i ] + _T("\\Drivers\\acpidisk.sys"), m_cArrAdwrCinmus, bToDelete ) )
				m_bSplSpyFound = true;
			
			if( FindReportKillOnRestart( csArrLocations [ i ] + _T("\\ntmcsvc.dll"), m_ulSpyName , false, false))
				m_bSplSpyFound = true;

			if( m_bSplSpyFound && bToDelete)
				MoveFileEx( csArrLocations [ i ] + _T("\\ntmcsvc.dll"), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
			
			if( FindKillReportProcess( csArrLocations [ i ] + _T("\\~.exe"), m_ulSpyName , bToDelete, true))
				m_bSplSpyFound = true;
		}
	
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CCinmusWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}	
	
	return ( false ) ;
}
