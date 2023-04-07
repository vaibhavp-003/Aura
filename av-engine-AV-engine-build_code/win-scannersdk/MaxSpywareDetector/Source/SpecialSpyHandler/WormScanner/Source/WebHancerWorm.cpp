/*=============================================================================
   FILE				: webhancerworm.Cpp
   ABSTRACT			: Implementation of Special Spyware WebHancer Worm Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 31/08/2007
   NOTES			:
   VERSION HISTORY	: 
=============================================================================*/

#include "pch.h"
#include "webhancerworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckForWebHancer
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and removes WebHancer
	Author			: 
	Description		: remove "\\webHancer\\Programs\\webhdll.dll" frmo program files and
					  fixes registry lsp entries
--------------------------------------------------------------------------------------*/
bool CWebHancerWorm::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
			return ( false ) ;

		if ( !bToDelete )
		{
			CString csWebHancerPath;
			csWebHancerPath = _T("\\webHancer\\Programs\\webhdll.dll") ;
			if( FindReportKillOnRestart( CSystemInfo::m_strProgramFilesDir + csWebHancerPath, m_ulSpyName , false))
				m_bSplSpyFound = true;

			if ( m_bScanOtherLocations )
			{
				if( FindReportKillOnRestart( m_csOtherPFDir + csWebHancerPath, m_ulSpyName , false))
					m_bSplSpyFound = true;
			}
			
			if( FindReportKillOnRestart( CSystemInfo::m_strWinDir + _T("\\webhdll.dll"), m_ulSpyName, false))
				m_bSplSpyFound = true;
		}		
		else
			FixLSP() ;

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CWebHancerWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}
	
	return false;
}
