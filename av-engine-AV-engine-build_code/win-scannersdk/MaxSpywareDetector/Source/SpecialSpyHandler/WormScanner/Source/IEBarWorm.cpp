/*====================================================================================
   FILE				: IEBarWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware IEBar
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
#include "iebarworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForIEBar
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: check for iebar
	Author			: Anand
	Description		: remove the driver for IEBar, the driver monitors its files in pfdir\commonfiles\ie-bar
--------------------------------------------------------------------------------------*/
bool CIEBarWorm::ScanSplSpy( bool bToDelete, CFileSignatureDb *pFileSigMan )
{
	try
	{
		m_pFileSigMan = pFileSigMan;
	
		if(IsStopScanningSignaled())
			return false;
	
		if ( CheckAndRemoveDriver ( m_ulSpyName , _T("fsprot") , m_objSysInfo.m_strSysDir + _T("\\Drivers\\fsprot.SYS"), m_csArrDriver, bToDelete))
			m_bSplSpyFound = true ;

		if ( m_bScanOtherLocations )
		{
			if ( CheckAndRemoveDriver ( m_ulSpyName , _T("fsprot") , m_csOtherSysDir + _T("\\Drivers\\fsprot.SYS"), m_csArrDriver, bToDelete))
				m_bSplSpyFound = true ;
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CIEBarWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return ( false ) ;
}
