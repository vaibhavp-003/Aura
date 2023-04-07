 /*====================================================================================
   FILE				: AddGunWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware Add Gun
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
#include "addgunworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForGoldun
	In Parameters	: bool
	Out Parameters	: bool
	Purpose			: check for Trojan Goldun
	Author			: Anand
	Description		: remove the Goldun driver
--------------------------------------------------------------------------------------*/
bool CAddGunWorm ::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;
		
		if(IsStopScanningSignaled())
			return ( false ) ;

		if ( !bToDelete )
			m_csArrGoldunDriver.RemoveAll();

		if( CheckAndRemoveDriver ( 2693, _T("GDIW2K"), m_objSysInfo.m_strSysDir + _T("\\gdiw2k.sys"),
									m_csArrGoldunDriver, bToDelete))
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			if( CheckAndRemoveDriver ( 2693, _T("GDIW2K"),
				m_csOtherSysDir + _T("\\gdiw2k.sys"), m_csArrGoldunDriver, bToDelete))
			{
					m_bSplSpyFound = true;
			}
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;

	}
	
	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in CAddGunWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
