/*====================================================================================
   FILE				: MSDirectDriver.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware MSDirect
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
#include "msdirectdriver.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForMSDirect
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check legacy driver
	Author			: Sudeep
	Description		: This function checks for any legacy entry of driver are present or not
					  and adds the driver to the restart delete list
--------------------------------------------------------------------------------------*/
bool CMSDirectDriver::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;	

		CStringArray	csArrLocations ;
		csArrLocations . Add ( CSystemInfo::m_strSysDir + _T("\\msdirect.sys") ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( m_csOtherSysDir + _T("\\msdirect.sys") ) ;

		CString csDriver = m_objSysInfo.m_strSysDir + _T("\\msdirect.sys") ;
		
		if ( !bToDelete )
		{
			m_csArrMSDirectInfectedKeys.RemoveAll() ;
			
			CStringArray csSystemSubKeys;
			m_objReg.EnumSubKeys(_T("SYSTEM"), csSystemSubKeys, HKEY_LOCAL_MACHINE);
            int nSubKeys = (int)csSystemSubKeys.GetCount();

            for ( int i = 0; i < nSubKeys; i ++ )  
			{
				int iPos = 0;

				(csSystemSubKeys.GetAt(i)).Find(_T("ControlSet0"), iPos); //Check for ControlSet001 , 002, 003...
				if(iPos != -1)
				{
					CString csKey = _T("SYSTEM\\") + csSystemSubKeys.GetAt(i) + _T("\\Enum\\Root\\LEGACY_MSDIRECT");

					if( FindReportRegKey(csKey, m_ulSpyName , HKEY_LOCAL_MACHINE, bToDelete, true))
					{
						m_bSplSpyFound = true;
						m_csArrMSDirectInfectedKeys.Add( csKey );
					}
				}
			}
		
			for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
			{
				if ( !_taccess_s ( csArrLocations [ i ] , 0 ) )
				{
					m_bSplSpyFound = true ;
					SendScanStatusToUI ( Special_File , m_ulSpyName , csArrLocations [ i ] ) ;
				}
			}
		}
		else
		{
			if ( EnablePrivilegesToHandleReg() )
			{
				int nInfectedKeys =  (int)m_csArrMSDirectInfectedKeys.GetCount();
				for ( int i = 0 ; i < nInfectedKeys; i++ )
				{
					if ( DeleteAllTheValues ( HKEY_LOCAL_MACHINE , m_csArrMSDirectInfectedKeys.GetAt( i )))
					{
						CString csKeyToDelete ( CString(_T("Generic^")) + CString(HKLM) + CString(BACK_SLASH) ) ;
						csKeyToDelete = csKeyToDelete + m_csArrMSDirectInfectedKeys.GetAt(i) + _T("Dummy");
				
						AddInRestartDeleteList(RD_KEY, m_ulSpyName, csKeyToDelete);
						RemoveRegistryKey ( m_csArrMSDirectInfectedKeys.GetAt(i), HKEY_LOCAL_MACHINE, m_ulSpyName );
					}				
				}

				for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
				{
					if ( _taccess_s ( csArrLocations [ i ] , 0 ) == 0)
					{
						AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, csArrLocations [ i ]);
					}
				}
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
		csErr.Format( _T("Exception caught in CMSDirectDriver::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}	

	return false;
}//End of function to check for MSDirect
