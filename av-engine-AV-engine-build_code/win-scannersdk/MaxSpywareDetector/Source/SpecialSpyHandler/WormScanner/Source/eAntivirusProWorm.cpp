/*======================================================================================
   FILE				: eAntivirusProWorm.cpp
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
   CREATION DATE	: 19/09/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.53
					Resource : Shweta
					Description: created this class to fix eAntivirusPro Worm
========================================================================================*/

#include "pch.h"
#include "eAntivirusProWorm.h"
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
	Purpose			: Check and remove eAntivirusPro
	Author			: Shweta M
	Description		: This function checks for random folder in PFDIR for eAntivirusPro
--------------------------------------------------------------------------------------*/
bool CeAntivirusProWorm  :: ScanSplSpy ( bool bToDelete , CFileSignatureDb *pFileSigMan )
{
	try
	{
		if ( IsStopScanningSignaled() )
			return ( m_bSplSpyFound ) ;

		if ( !bToDelete )
		{
			CSplSpyScan * pMalwarePrtector = new CMalwarePrtector ( this -> m_pSplSpyWrapper ) ;
			if ( ((CMalwarePrtector*)pMalwarePrtector)->ScanForInfection ( m_ulSpyName , _T("eAntivirusPro") , true ) )
				m_bSplSpyFound = true ;

			delete pMalwarePrtector ;
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound ;
		//if ( m_bSplSpyFound ) 
		//	AddLogEntry ( _T("Spyware Found : %s") , m_ulSpyName ) ;

		return ( m_bSplSpyFound ) ;
	}

	catch ( ... )
	{
		CString csErr ;
		csErr . Format ( _T("Exception caught in CeAntivirusProWorm::ScanSplSpy, Error : %d") ,GetLastError() ) ;
		AddLogEntry ( csErr , 0 , 0 ) ;
	}
	
	return ( false ) ;
}