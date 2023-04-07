/*====================================================================================
   FILE				: RunEntryWorm.cpp
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
#include "runentryworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool, CFileSignatureDb*
	Out Parameters	: 
	Purpose			: check and remove Run entry worm
	Author			: Anand
	Description		: this function checks reg key and removes
--------------------------------------------------------------------------------------*/
bool CRunEntryWorm::ScanSplSpy(bool bRemoveThem, CFileSignatureDb *pFileSigMan)
{
	try
	{
		bool bReturnVal = false;
		
		m_pFileSigMan = pFileSigMan;
		
		if(ScanEveryKey(bRemoveThem, HKEY_LOCAL_MACHINE, BLANKSTRING , HKLM ) )
			bReturnVal = true;

		// Darshan
		// 25-June-2007
		// Added code to loop thru all users under HKEY_USERS
		for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
		{
			if(IsStopScanningSignaled())
				break;

			CString csUserKey = m_arrAllUsers.GetAt(iCnt);
			if(ScanEveryKey(bRemoveThem, HKEY_USERS, csUserKey + CString(BACK_SLASH) , 
				CString(HKU) + CString(BACK_SLASH) + csUserKey))
				bReturnVal = true;
		}

		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;
		return ( bReturnVal ) ;
	}

	catch ( ... )
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CRunEntryWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanEveryKey
	In Parameters	: bool , HKEY , CString , CString 
	Out Parameters	: 
	Purpose			: check and remove key worm
	Author			: Anand
	Description		: this function checks for a key infection
--------------------------------------------------------------------------------------*/
bool CRunEntryWorm::ScanEveryKey(bool bRemoveThem, HKEY hHive, CString csMainKey, CString csHkey)
{
	try
	{
		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;

		if(FindReportRegValue(csMainKey + RUN_REG_PATH, _T("Microsoft Office"), m_ulSpyName, hHive, bRemoveThem, true))
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			if(FindReportRegValue(csMainKey + WOW6432NODE_REG_PATH + UNDERWOW_RUN_REG_PATH , _T("Microsoft Office"), m_ulSpyName, hHive, bRemoveThem, true))
				m_bSplSpyFound = true;
		}
		
		CString csStrData;
		if(m_objReg.Get(csMainKey + RUN_REG_PATH, _T("Microsoft Office"), csStrData, hHive))
		{
			if(!csStrData.IsEmpty())
			{
				if(FindKillReportProcess(csStrData, m_ulSpyName, bRemoveThem))
					m_bSplSpyFound = true;
			}
		}
		
		if(bRemoveThem)
		{
			AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, csStrData);
			AddInRestartDeleteList(RD_VALUE, m_ulSpyName, csHkey + RUN_REG_PATH + _T("\\Microsoft Office"));
		}
		
		m_bSplSpyFound = bRemoveThem ? false : m_bSplSpyFound ;
		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CRunEntryWorm::ScanEveryKey, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}
