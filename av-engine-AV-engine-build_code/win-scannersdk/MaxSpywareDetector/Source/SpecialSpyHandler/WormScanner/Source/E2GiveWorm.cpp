/*====================================================================================
   FILE				: E2GiveWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware 180Solutions
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Darshan
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
#include "e2giveworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForE2Give
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check and remove E2give
	Author			: Darshan
	Description		: remove iniwin32.dll from System32 Folder
--------------------------------------------------------------------------------------*/
bool CE2GiveWorm ::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return false;	

		CStringArray csArrLocations ;

		csArrLocations . Add ( WNT_WINDOWS_PATH ) ;
		if ( m_bScanOtherLocations )
			csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_WINLOGON_REG_KEY) ) ;
	
		if(!bToDelete)
		{
			CString csData;

			for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
			{
				if ( m_objReg . Get ( csArrLocations [ i ] , APPINIT , csData , HKEY_LOCAL_MACHINE ) )
				{
					(csData.Trim()).MakeLower();
					if(csData.Find( _T("iniwin32.dll")) != -1 )
					{
						CString csnewData = csData ;
						csnewData.Replace ( _T("iniwin32.dll") , _T("") );
						CString sEntry = CString(HKLM) + CString(BACK_SLASH) + csArrLocations [ i ] + CString(BACK_SLASH) 
							+ CString(APPINIT) + CString(BACK_SLASH) + CString(_T("\"")) + csData  + 
							CString(_T("\"|")) + csnewData;
						
                        //TODO:Reg Fix Scanner
						//SendMessageToUI ( m_ulSpyName, sEntry , Special_RegDataFix_Scanner );
						m_bSplSpyFound = true;

					}
				}
			}
		}
		else
		{
			//Version: 17.2
			//Resource: Anand
			// earlier the function name was MakeRestartDeleteEntry()
			//ReplaceFileOnRestart(CSystemInfo::m_strSysDir + _T("\\iniwin32.dll") , NULL);
			//AddInHookList(CSystemInfo::m_strSysDir + _T("\\iniwin32.dll"), FILEWORM);
			//for ( int i = 0 ; i < csArrLocations .GetCount() ; i++ )
			{
				//CQuarantineFile::AddInRestartDeleteList(m_ulSpyName + _T("^") + csArrLocations [ i ] + _T("\\iniwin32.dll"), FILEWORM, true); 
			}
		}//End Of else to check for delete flag value is true
		
		//version: 16.3
		//resource: Anand
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}//End Of try block
	
	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CE2GiveWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return ( false ) ;
}
