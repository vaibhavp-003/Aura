/*====================================================================================
   FILE				: KeyKeyWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware KeyKey
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
#include "keykeyworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForKeyKey
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and remove keykey
	Author			: 
	Description		: remove driver and registry entries
--------------------------------------------------------------------------------------*/
bool CKeyKeyWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;

		if( FindReportKillOnRestart(m_objSysInfo.m_strSysDir + _T("\\drivers\\keykey.sys"), m_ulSpyName , false))
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			if( FindReportKillOnRestart(m_csOtherSysDir + _T("\\drivers\\keykey.sys"), m_ulSpyName , false))
				m_bSplSpyFound = true;
		}
		
		if( FindReportRegKey( CString(SERVICES_MAIN_KEY) + CString(_T("KeyKey")), m_ulSpyName , HKEY_LOCAL_MACHINE, bToDelete))
			m_bSplSpyFound = true;

		CStringArray arrValue, arrData;
		if(m_objReg.QueryDataValue( CString(SERVICES_MAIN_KEY) + CString(_T("Kbdclass\\Enum")), arrValue, arrData, HKEY_LOCAL_MACHINE))
		{
			int nVals = (int)arrData.GetCount();
			for(int i = 0; i < nVals; i++)
			{
				if( m_objReg.KeyExists ( SERVICES_ENUM_KEY + arrData.GetAt(i), HKEY_LOCAL_MACHINE))
				{
					m_objReg.AllowAccessToEveryone(HKEY_LOCAL_MACHINE, SERVICES_ENUM_KEY + arrData.GetAt(i));
					CString csKey = SERVICES_ENUM_KEY + arrData.GetAt(i);
					
					if(IsEntryInMultiStringReg(HKEY_LOCAL_MACHINE, csKey, _T("UpperFilters"), _T("KeyKey"), bToDelete))
					{
						m_bSplSpyFound = true;
					}

					CString csData;
					m_objReg.Get( csKey + _T("\\Control"), _T("ActiveService"), csData, HKEY_LOCAL_MACHINE);
					if((csData.MakeLower()) == _T("keykey"))
					{
						m_bSplSpyFound = true;
						if(bToDelete)
						{
							CString sValue(_T("Kbdclass"));
							m_objReg.Set(csKey + _T("\\Control"), _T("ActiveService"), csData, HKEY_LOCAL_MACHINE);
						}
						break;
					}
				}
			}
		}
		m_objReg.AllowAccessToEveryone( HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E96B-E325-11CE-BFC1-08002BE10318}"));
		
		if(IsEntryInMultiStringReg( HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E96B-E325-11CE-BFC1-08002BE10318}"), 
								    _T("UpperFilters"), _T("KeyKey"), bToDelete))
		{
			if ( !bToDelete ) 
                SendScanStatusToUI ( Special_RegVal_Report ,  m_ulSpyName , HKEY_LOCAL_MACHINE,  CString(_T ( "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E96B-E325-11CE-BFC1-08002BE10318}")) 
                , CString(_T("UpperFilters")) , REG_MULTI_SZ , LPBYTE(_T("KeyKey")), 14 ) ;
			m_bSplSpyFound = true;
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CKeyKeyWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}
