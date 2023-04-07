/*=====================================================================================
   FILE				: SpywareGuard.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware Guard
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
   CREATION DATE	: 12/31/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.64
					Resource : Shweta
					Description: created the class
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CSpywareGuardWorm : public CSplSpyScan
{
public:
	CSpywareGuardWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,9182)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CSpywareGuardWorm (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	

};
