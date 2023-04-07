/*=============================================================================
   FILE				: VirusProtectWorm.h
   ABSTRACT			: Declaration of Special Spyware VirusProtect Class
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
   VERSION HISTORY	: added the class
								
=============================================================================*/

#pragma once
#include "splspyscan.h"

class CVirusProtectWorm : public CSplSpyScan
{
	
	bool m_bSplSpyFound ;
	bool IsSpywareFolder ( const CString& csPath , const CString& csName ) ;

public:

	CVirusProtectWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,6976)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CVirusProtectWorm ( void )
	{
	}

	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL) ;
	
};