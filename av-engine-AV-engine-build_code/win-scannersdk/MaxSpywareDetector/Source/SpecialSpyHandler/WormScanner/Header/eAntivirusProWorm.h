/*=====================================================================================
   FILE				: eAntivirusProWorm.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware eAntivirusPro
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
					Description: created the class
========================================================================================*/

#pragma once
#include "splspyscan.h"
#include "MalwareProtector.h"

class CeAntivirusProWorm : public CSplSpyScan
{
public:
	CeAntivirusProWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,8573)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CeAntivirusProWorm (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
};
