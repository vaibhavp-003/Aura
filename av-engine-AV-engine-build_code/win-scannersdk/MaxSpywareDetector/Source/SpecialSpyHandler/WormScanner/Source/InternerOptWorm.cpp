/*====================================================================================
   FILE				: InternerOptWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware Internet Optimizer
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
#include "interneroptworm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: CheckforInternetOptimizer
	In Parameters	: bool 
	Out Parameters	: bool
	Purpose			: Check for internet Optimizer
	Author			: Dipali Pawar
	Description:
					Internet Optimizer creates avenue media entry in software with unicode
					We cannot keep backup of it.so need to Delete it directly.
					Also it has 3 random DLL
					1.iopti???.dll
					2.nem???.dll
					3.wsem???.dll
--------------------------------------------------------------------------------------*/
bool CInternerOptWorm::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
				return false;
	
		if( FindReportRegKey(_T("SOFTWARE\\avenue media"), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete))
			m_bSplSpyFound = true;

		if ( m_bScanOtherLocations )
		{
			if( FindReportRegKey ( CString(WOW6432NODE_REG_PATH) + CString(_T("avenue media")), m_ulSpyName, HKEY_LOCAL_MACHINE, bToDelete))
				m_bSplSpyFound = true;
		}

		// Darshan
		// 25-June-2007
		// Added code to loop thru all users under HKEY_USERS
		for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
		{
			if(IsStopScanningSignaled())
				break;
			CString csUserKey = m_arrAllUsers.GetAt(iCnt);
			if(FindReportRegKey(csUserKey + BACK_SLASH + _T("SOFTWARE\\avenue media"), m_ulSpyName , HKEY_USERS, bToDelete))
				m_bSplSpyFound = true;
		}
		
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return m_bSplSpyFound ;
	}

	catch(...)
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CInternerOptWorm::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr,0,0);
	}

	return ( false ) ;
}