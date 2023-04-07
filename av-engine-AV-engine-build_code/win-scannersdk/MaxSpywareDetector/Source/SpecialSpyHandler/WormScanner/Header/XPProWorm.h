/*=====================================================================================
   FILE				: XPProWorm.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware XP Protector 2009
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
   CREATION DATE	: 11/09/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.50
					Resource : Shweta
					Description: created the class
========================================================================================*/

#pragma once
#include "splspyscan.h"
#include "MalwareProtector.h"

class CXPProWorm : public CSplSpyScan
{
public:
	CXPProWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,8418)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CXPProWorm (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
};
