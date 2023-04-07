/*====================================================================================
   FILE				: EliteKeyLogWorm.cpp
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
#include "elitekeylogworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CheckEliteKeylogger
In Parameters	: bool
Out Parameters	: bool
Purpose			: check for EliteKeylogger
Author			: Shweta
Description		: remove the Elite Keylogger driver
--------------------------------------------------------------------------------------*/
bool CEliteKeyLogWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;
	
		if(IsStopScanningSignaled())
			return ( false ) ;

		if ( !bToDelete )
		{
			m_cArrEliteus. RemoveAll () ;
			m_cArrElitetd. RemoveAll ();
			m_cArrEliteex. RemoveAll ();
			m_cArrElitems. RemoveAll ();
		}

		CStringArray csArrLocations ;

		csArrLocations . Add ( CSystemInfo::m_strSysDir ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( m_csOtherSysDir ) ;

		for ( int i = 0 ; i < csArrLocations .GetCount() ; i++ )
		{
			if ( CheckAndRemoveDriver ( m_ulSpyName , _T("usbkbd") , csArrLocations [ i ] + _T("\\Drivers\\usbkbd.sys"), m_cArrEliteus, bToDelete ) )
				m_bSplSpyFound = true;

			if ( CheckAndRemoveDriver ( m_ulSpyName , _T("tdiip") , csArrLocations [ i ] + _T("\\Drivers\\tdiip.sys"), m_cArrElitetd, bToDelete ) )
				m_bSplSpyFound = true;

			if ( CheckAndRemoveDriver ( m_ulSpyName , _T("extfs") , csArrLocations [ i ] + _T("\\Drivers\\extfs.sys"), m_cArrEliteex, bToDelete ) )
				m_bSplSpyFound = true;

			if ( CheckAndRemoveDriver ( m_ulSpyName , _T("mscache") , csArrLocations [ i ] + _T("\\mscache.sys"), m_cArrElitems, bToDelete ) )
				m_bSplSpyFound = true;
		}

		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format ( _T("Exception caught in CEliteKeyLogWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}