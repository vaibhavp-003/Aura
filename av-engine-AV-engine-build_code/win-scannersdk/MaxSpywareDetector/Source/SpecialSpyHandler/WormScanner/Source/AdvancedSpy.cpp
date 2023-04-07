/*=============================================================================
   FILE				: TheAdvancedSpy.Cpp
   ABSTRACT			: Implementation of Special Spyware CAdvancedSpy Class
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
					  Code to handle Random Folder
=============================================================================*/

#include "pch.h"
#include "AdvancedSpy.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool ,CFileSignatureDb
	Out Parameters	: bool
	Purpose			: Checks and remove CAdvancedSpy
    Author			: Shweta
	Description		: Finds and Displays random folder of CAdvancedSpy Keylogger
--------------------------------------------------------------------------------------*/
bool CAdvancedSpy ::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{ 
	try
	{
		CString csUninstallKey ,csFilePath , csDisplayPath;
		CStringArray csArrLoc ;

		csArrLoc.Add ( UNINSTALL_PATH );
		if ( m_bScanOtherLocations )
		{
			csArrLoc . Add ( UNINSTALL_PATH_X64 );
		}

		for ( int iLocCnt = 0 ; iLocCnt < csArrLoc.GetCount() ; iLocCnt++ ) 
		{
			csUninstallKey = csArrLoc.GetAt(iLocCnt) + _T("\\Advanced Spy") ;
			if ( !m_objReg.KeyExists ( csUninstallKey , HKEY_LOCAL_MACHINE ) )
				continue;

			m_objReg.Get( csUninstallKey , _T("InstallLocation") , csFilePath , HKEY_LOCAL_MACHINE ); 
			m_objReg.Get( csUninstallKey , _T("DisplayName") ,  csDisplayPath , HKEY_LOCAL_MACHINE ); 

			csDisplayPath.MakeLower();
			if ( csDisplayPath.Find ( _T("advanced spy" ) ) == -1 )
			{
				continue;
			}
			RemoveFolders ( csFilePath , m_ulSpyName , bToDelete );
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in CAdvancedSpy::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}