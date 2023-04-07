/*=============================================================================
   FILE				: TheLastDefender.Cpp
   ABSTRACT			: Implementation of Special Spyware CLastDefenderWorm Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Shweta
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 03/04/2008
   NOTES			:
   VERSION HISTORY	: 2.5.0.31
					  Code to handle random Key															
=============================================================================*/

#include "pch.h"
#include "TheLastDefender.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool ,CFileSignatureDb
	Out Parameters	: bool
	Purpose			: Checks and remove The Last defender
    Author			: Shweta
	Description		: Finds and Displays Last Defendr random Key Entry
--------------------------------------------------------------------------------------*/
bool CTheLastDefender ::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{ 
	try
	{
		CStringArray csProductKeys ;
		CString csInstallLocation , csDisplayName , csFullKey ;
		CStringArray csArrPath ;
		csArrPath .Add ( CSystemInfo::m_strProgramFilesDir );

		if ( m_bScanOtherLocations )
		{
			csArrPath.Add ( CSystemInfo::m_strProgramFilesDirX64 );
		}

		for (int iPathCnt = 0; iPathCnt < csArrPath.GetCount() ; iPathCnt++ )
		{
			CString	csFilePath = csArrPath.GetAt ( iPathCnt ) + _T("\\The Last Defender") ;

			if ( _taccess_s ( csFilePath , 0 ) )
				return ( false ) ;

			if ( ! m_objReg.EnumSubKeys ( csArrPath.GetAt(iPathCnt) , csProductKeys , HKEY_LOCAL_MACHINE ) )
				return ( false ) ;

			for ( int i = 0 ; i < csProductKeys.GetCount() ; i++ )
			{
				csInstallLocation = csDisplayName = csFullKey = BLANKSTRING ;

				csFullKey = CString(PRODUCTS_PATH) + CString(BACK_SLASH) 
					+ csProductKeys.GetAt(i) + CString(_T("\\InstallProperties")) ;
				m_objReg . Get ( csFullKey , _T("InstallLocation") , csInstallLocation ,HKEY_LOCAL_MACHINE ) ;
				m_objReg . Get ( csFullKey , _T("DisplayName") , csDisplayName ,HKEY_LOCAL_MACHINE ) ;

				if ( ( csInstallLocation.Find(_T("The Last Defender")) != -1 ) && (csDisplayName.Find(_T("The Last Defender")) != -1 ))
				{
					m_bSplSpyFound = true ;
					EnumKeynSubKey ( CString(HKLM) + CString(BACK_SLASH) 
						+ csArrPath.GetAt(iPathCnt) + CString(BACK_SLASH) + csProductKeys.GetAt(i) , m_ulSpyName ) ;
				}
			}
		}
   
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in CLastDefenderWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}

