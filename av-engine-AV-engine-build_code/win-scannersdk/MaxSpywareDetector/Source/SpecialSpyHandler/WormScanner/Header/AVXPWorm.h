/*=====================================================================================
   FILE				: AVXPWorm.h
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
					Description: created the class
========================================================================================*/

#pragma once
#include "splspyscan.h"
#include "MalwareProtector.h"

class CAVXPWorm : public CSplSpyScan
{
public:
	CAVXPWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,484)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CAVXPWorm(void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
};
