/*======================================================================================
   FILE				: XPCSpyWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware XPCSpy
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
#include "xpcspyworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForXPCSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove XPC Spy
	Author			: Sudeep
	Description		: This function checks for any checks for the driver entries of XPCspy
--------------------------------------------------------------------------------------*/
bool CXPCSpyWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;

		CString csRegKey;

		m_cArrXPCSpyInfectedKeys.RemoveAll( );
		if ( CheckAndRemoveDriver ( m_ulSpyName , _T("systemin"), CSystemInfo::m_strSysDir + _T("\\drivers\\systemin.sys"), m_cArrXPCSpyInfectedKeys, bToDelete ) )
			m_bSplSpyFound = true ;

		if ( m_bScanOtherLocations )
		{
			if ( CheckAndRemoveDriver ( m_ulSpyName , _T("systemin"), m_csOtherSysDir + _T("\\drivers\\systemin.sys"), m_cArrXPCSpyInfectedKeys, bToDelete ) )
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
		csErr.Format( _T("Exception caught in CXPCSpyWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}//End of function to check for MSDirect
