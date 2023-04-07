/*====================================================================================
   FILE				: ProAgentWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware ProAgent
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
#include "proagentworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForProAgent
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: check for Pro Agent
	Author			: Anand
	Description		: remove the proagent driver
--------------------------------------------------------------------------------------*/
bool CProAgentWorm::ScanSplSpy( bool bToDelete, CFileSignatureDb *pFileSigMan )
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
				return false;

		CString csFullFileName = BLANKSTRING ;
		BOOL bMoreFiles = FALSE ;
		CStringArray csArrLocations ;

		csArrLocations . Add ( CSystemInfo :: m_strSysDir ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( m_csOtherSysDir ) ;

		for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
		{
			if ( CheckAndRemoveDriver ( m_ulSpyName , _T("KeenSense") , csArrLocations [ i ] + _T("\\Drivers\\keensense.sys"), m_csArrPGKS , bToDelete ) )
				m_bSplSpyFound = true;

			if ( CheckAndRemoveDriver ( m_ulSpyName , _T("KSDevice") , csArrLocations [ i ] + _T("\\Drivers\\ksdevice.sys"), m_csArrPAKSD , bToDelete ) )
				m_bSplSpyFound = true;
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;

	}
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CProAgentWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
