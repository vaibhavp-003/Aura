/*=============================================================================
   FILE				: FraudTool.Cpp
   ABSTRACT			: Implementation of Special Spyware CFraudTool Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Ritesh
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 04/06/2008
   NOTES			:
   VERSION HISTORY	: 
						version: 2.5.0.34
						resource: Ritesh
						Description: added fix for FraudTool

=============================================================================*/

#include "pch.h"
#include "FraudTool.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool ,CFileSignatureDb
	Out Parameters	: bool
	Purpose			: Checks and remove Downloader FraudTool
    Author			: Ritesh
	Description		: Finds and Displays Downloader FraudTool
--------------------------------------------------------------------------------------*/
bool CFraudTool::ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{ 
	try
	{
		CStringArray csArrLoc;

		csArrLoc .Add ( CSystemInfo::m_strSysDir );
		if (m_bScanOtherLocations)
			csArrLoc.Add ( CSystemInfo::m_strSysWow64Dir );
		
		for ( int iloc = 0 ; iloc < csArrLoc.GetCount() ; iloc++ )
		{
			CString csCRU629 = csArrLoc.GetAt (iloc) + _T ( "\\cru629.dat" ) ;
			CString csBEEP = csArrLoc.GetAt (iloc) + _T ( "\\drivers\\beep.sys.RenamedSD" ) ;

			if ( bToDelete )
			{
				AddInRestartDeleteList(RD_FILE_DELETE, m_ulSpyName, csCRU629);
			}
			else
			{
				if ( _taccess ( csBEEP , 0 ) || _taccess ( csCRU629 , 0 ) )
					return ( m_bSplSpyFound ) ;

				m_bSplSpyFound = true ;
				SendScanStatusToUI ( Special_File , m_ulSpyName , csBEEP  ) ;
				SendScanStatusToUI ( Special_File ,  m_ulSpyName , csCRU629  ) ;
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
		csErr.Format( _T("Exception caught in CFraudTool::ScanSplSpy, Error : %d") , GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}

	return ( false ) ;
}