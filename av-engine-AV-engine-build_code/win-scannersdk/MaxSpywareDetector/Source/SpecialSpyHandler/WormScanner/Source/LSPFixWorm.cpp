/*======================================================================================
   FILE				: LSPFixWorm.cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware XP protector 2009
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
   CREATION DATE	: 29/07/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.1.01
					Resource : Shweta
					Description: created this class to LSP fix . Will fix all the spyware files creating lSP fix issue
========================================================================================*/

#include "pch.h"
#include "LSPFixWorm.h"
#include <io.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Check and fix LSP dll 
	Author			: Shweta M
	Description		: This function checks for spyware files in Winsock and fix them
--------------------------------------------------------------------------------------*/
bool CLSPFixWorm :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		if ( bToDelete )
		{
			FixLSP();
		}
		else
		{
			CStringArray csFileName ;
			csFileName.Add ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("contraviro\\siglsp.dll" ) ) ;
			csFileName.Add ( m_objSysInfo.m_strProgramFilesDir + BACK_SLASH + _T("UnVirex\\siglsp.dll" ) ) ;

			for ( INT_PTR i = 0 , iTotal = csFileName . GetCount() ; i < iTotal ; i++  )
			{
				if ( _taccess ( csFileName . GetAt ( i ) , 0 ) )
					continue ;

				SendScanStatusToUI ( Special_File , m_ulSpyName , csFileName . GetAt ( i ) ) ;
				m_bSplSpyFound = true ;
			}
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CLSPFixWorm :: ScanSplSpy , Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}