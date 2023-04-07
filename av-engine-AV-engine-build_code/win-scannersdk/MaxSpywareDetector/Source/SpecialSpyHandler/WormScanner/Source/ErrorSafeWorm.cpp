/*====================================================================================
   FILE				: ErrorSafeWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware ErrorSafe
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Sudeep Shelke
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
#include "errorsafeworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForErrorSafe
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and clean error safe
	Author			: Sudeep
	Description		: This function checks the Registry entries for erssdd.sys in HKLM\ControlSet001 ... 00n
					  Searches for three types of entries Safeboot , LEGACY_ERSSDD , Services
					  deletes these entries at qurantine and deletes the driver at restart
--------------------------------------------------------------------------------------*/
bool CErrorSafeWorm :: ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( m_bSplSpyFound ) ;	

		CStringArray csLocations ;
		
		csLocations.Add ( CSystemInfo::m_strSysDir + _T("\\Drivers\\erssdd.sys") ) ;
		if ( m_bScanOtherLocations )
			csLocations . Add ( m_csOtherSysDir + _T("\\Drivers\\erssdd.sys") ) ;

		if ( !bToDelete )
		{
			m_csArrErrorSafeInfectedKeys.RemoveAll() ;
			
			CStringArray csSystemSubKeys;
			m_objReg.EnumSubKeys(_T("SYSTEM"), csSystemSubKeys, HKEY_LOCAL_MACHINE);
            int nSubKeys = (int)csSystemSubKeys.GetCount();

            for ( int i = 0; i < nSubKeys ; i++ )  
			{
				int iPos = 0;
				(csSystemSubKeys.GetAt(i)).Find(_T("ControlSet0"), iPos); //Check for ControlSet001 , 002, 003...
				if(iPos != -1)
				{
					if( CheckSubKeysForErrorSafeInfection ( _T("SYSTEM\\") + csSystemSubKeys.GetAt(i) ))
						m_bSplSpyFound = true;
				}
			}
			
			for ( int i = 0 ; i < csLocations . GetCount() ; i++ )
			{
				if ( _taccess_s ( csLocations [ i ] , 0) == 0) //Check for the driver file            
				{
					if ( m_bSplSpyFound )
						SendScanStatusToUI ( Special_File ,  m_ulSpyName , csLocations [ i ] ) ;
					else
						SendScanStatusToUI ( Special_File ,  m_ulSpyName , csLocations [ i ]  ) ;
				}
			}
		}
		else
		{
			if ( EnablePrivilegesToHandleReg() )
			{
				int nInfectedFiles = (int)m_csArrErrorSafeInfectedKeys.GetCount();
				for ( int i = 0; i < nInfectedFiles; i++)
				{
					// delete all the values in this key, so that driver is not loaded next time
					if ( DeleteAllTheValues ( HKEY_LOCAL_MACHINE , m_csArrErrorSafeInfectedKeys.GetAt( i )))
					{
						CString csKeyToDelete  = _T("Generic^HKEY_LOCAL_MACHINE\\") ;
						csKeyToDelete =  csKeyToDelete + m_csArrErrorSafeInfectedKeys.GetAt(i) + _T("Dummy");
						
						AddInRestartDeleteList(RD_KEY, m_ulSpyName, csKeyToDelete);
						//CQuarantineFile::AddInRestartDeleteList( csKeyToDelete , _T("RegistryKey") ) ;
						RemoveRegistryKey( m_csArrErrorSafeInfectedKeys.GetAt(i), HKEY_LOCAL_MACHINE, m_ulSpyName);
					}
				}		
			}
			
			for ( int i = 0 ; i < csLocations . GetCount() ; i++ )
			{
				if ( _taccess_s ( csLocations [ i ] , 0 ) == 0 )
				{
					AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, csLocations [ i ]);
					//CQuarantineFile::AddInRestartDeleteList( m_ulSpyName + _T("^") + csLocations [ i ] , _T("File"));
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
		csErr.Format( _T("Exception caught in CErrorSafeWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSubKeysForErrorSafeInfection
	In Parameters	: CString 
	Out Parameters	: 
	Purpose			: check subkeys ControlSet001 etc.
	Author			: Sudeep
	Description		: This function enumerates the registry keys ControlSet001 , ControlSet002 ... 
					  ControlSet00N , CurrentControleSet
--------------------------------------------------------------------------------------*/
bool CErrorSafeWorm :: CheckSubKeysForErrorSafeInfection ( CString csRegKey )
{
	bool bDriverFound = false;

	if( FindReportRegKey( csRegKey + _T("\\Control\\SafeBoot\\Network\\erssdd.sys"), 
						  m_ulSpyName , HKEY_LOCAL_MACHINE, false, true))
	{
		bDriverFound = true;
		m_csArrErrorSafeInfectedKeys.Add ( csRegKey + _T("\\Control\\SafeBoot\\Network\\erssdd.sys") );
	}
	
	if( FindReportRegKey( csRegKey + _T("\\Enum\\Root\\LEGACY_ERSSDD"), m_ulSpyName , 
						  HKEY_LOCAL_MACHINE, false, true))
	{
		bDriverFound = true;
		m_csArrErrorSafeInfectedKeys.Add ( csRegKey + _T("\\Enum\\Root\\LEGACY_ERSSDD") );
	}
	
	if( FindReportRegKey( csRegKey + _T("\\Services\\ERSSDD"), m_ulSpyName , 
						  HKEY_LOCAL_MACHINE, false, true))
	{
		bDriverFound = true;
		m_csArrErrorSafeInfectedKeys.Add ( csRegKey + _T("\\Services\\ERSSDD") );
	}
	
	return bDriverFound ;
}//End of function to check for ErrorSafe Driver Registry Keys
