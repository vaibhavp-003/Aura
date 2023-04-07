/*====================================================================================
   FILE				: DialerPhoneAccess.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware 180Solutions
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
#include "DialerPhoneAccess.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CheckDialerPhoneAccess
In Parameters	: bool
Out Parameters	: bool
Purpose			: check for CheckDialerPhoneAccess driver
Author			: Shweta
Description		: remove the Dialer.PhoneAccess driver
--------------------------------------------------------------------------------------*/
bool CDialerPhoneAccess::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;

		if ( !bToDelete )
			m_cArrDialer.RemoveAll();

		if ( CheckAndRemoveDriver ( m_ulSpyName , _T("mspcidrv") , m_objSysInfo . m_strSysDir + _T("\\Drivers\\mspcidrv.sys"), m_cArrDialer, bToDelete ) )
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			if ( CheckAndRemoveDriver ( m_ulSpyName , _T("mspcidrv") , m_csOtherSysDir + _T("\\Drivers\\mspcidrv.sys"), m_cArrDialer, bToDelete ) )
				m_bSplSpyFound = true;
		}

		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;
		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CDialerPhoneAccess::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
