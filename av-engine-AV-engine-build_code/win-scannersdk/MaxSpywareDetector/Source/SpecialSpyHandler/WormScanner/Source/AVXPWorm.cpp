/*======================================================================================
   FILE				: AVXPWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware AntiVirusXP 2008
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 02/07/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.36
					Resource : Anand
					Description: created this class to fix AntiVirusXP 2008
========================================================================================*/

#include "pch.h"
#include "AVXPWorm.h"
#include <io.h>
#include "ExecuteProcess.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and remove AntiVirusXP 2008
	Author			: Anand Srivastava
	Description		: This function checks for random folder in PFDIR of AntiVirusXP 2008
--------------------------------------------------------------------------------------*/
bool CAVXPWorm :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		if ( !bToDelete )
		{
			CSplSpyScan * pMalwarePrtector = new CMalwarePrtector ( this -> m_pSplSpyWrapper ) ;
			if ( ((CMalwarePrtector*)pMalwarePrtector)->ScanForInfection ( m_ulSpyName , _T("antivir") , true) )
				m_bSplSpyFound = true ;

			delete pMalwarePrtector ;
		}

		CExecuteProcess objExeProcess;
		CString csSid ;
		csSid = objExeProcess.GetCurrentUserSid();

		RegfixData ( HKEY_USERS , csSid + BACK_SLASH + _T("Control Panel\\International") , _T("sTimeFormat"),_T("HH:mm: VIRUS ALERT!"),_T("h:mm:ss tt"),m_ulSpyName);

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;
		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CAVXPWorm::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}