/*======================================================================================
   FILE				: TrojanQQPassWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware TrojanQQPass
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
#include "trojanqqpassworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CheckForTrojanQQPass
In Parameters	: bool
Out Parameters	: bool
Purpose			: Checks for ShellExtensionHook
Author			: anand
Description		: Checks and removes the dll entry on restart
--------------------------------------------------------------------------------------*/
bool CTrojanQQPassWorm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;
		
		if ( !bToDelete )
		{
			CArray<CStringA,CStringA> csArrKeywords ;
			CStringArray	csArrValues,  csArrData;
			CString			csFullKeyName,  csData;
		
			m_csFilename . Empty() ;
			csArrKeywords .Add ( "Insert.dll" ) ;
			csArrKeywords .Add ( "JumpHookOff" ) ;
			csArrKeywords .Add ( "JumpHookOn" ) ;
			csArrKeywords .Add ( "Baidu.com" ) ;
			csArrKeywords .Add ( "software\\microsoft\\windows\\currentversion\\explorer\\browser helper objects" ) ;
			csArrKeywords .Add ( "kaspersky" ) ;
			csArrKeywords .Add ( "Norton" ) ;
			csArrKeywords .Add ( "Symantec" ) ;

			CStringArray csArrLocations ;

			csArrLocations . Add ( SHELL_EXEC_HOOKS ) ;
			if ( m_bScanOtherLocations )
				csArrLocations . Add ( CString(WOW6432NODE_REG_PATH) + CString(UNDERWOW_SHELL_EXEC_HOOKS) ) ;

			for ( int i = 0 ; i < csArrLocations . GetCount() ; i++ )
			{
				m_objReg.QueryDataValue( csArrLocations [ i ] , csArrValues, csArrData, HKEY_LOCAL_MACHINE) ;
				for ( int j = 0 ; j < static_cast<int>(csArrValues.GetCount()) ; j++ )
				{
					if ( csArrValues[j].GetLength() <= 0 )
						continue ;

					csFullKeyName.Format( _T("CLSID\\%s\\InprocServer32") , static_cast<LPCTSTR>(csArrValues[j]));
					m_objReg.Get( csFullKeyName , _T(""), csData, HKEY_CLASSES_ROOT);

					if ( SearchStringsInFile( csData, csArrKeywords))
					{
						m_bSplSpyFound = true ;
						m_csFilename = csData ;
						SendScanStatusToUI ( Special_File , m_ulSpyName , m_csFilename  ) ;
					}
				}
			}
		}
	}

	catch ( ... )
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CTrojanQQPassWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
	//if ( m_bSplSpyFound ) 
	//		AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

	return ( m_bSplSpyFound ) ;
}
