/*=============================================================================
   FILE				: Cnsmin.h
   ABSTRACT			: Declaration of Special Spyware Zhelatin Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Shweta Mulay		
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 7/03/2008
   NOTES			: 
   VERSION HISTORY	: added the class type 2.5.0.30 
								
=============================================================================*/

#pragma once
#include "splspyscan.h"
#define MAX_DRIVES_NUM	26

class CCnsmin : public CSplSpyScan
{
	CStringArray		 m_csArrInfectedFiles ;

public:
	
	CCnsmin ( CSplSpyWrapper *pSplSpyWrapper ) : CSplSpyScan ( pSplSpyWrapper , 1364 )
	{
		m_bSplSpyFound = false;
	}

	virtual ~CCnsmin ( void )
	{
	}

	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL) ;

};