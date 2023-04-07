
/*=====================================================================================
   FILE				: Poison.h
   ABSTRACT			: This class is used for scanning Backdoor Poison worm
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Vaibhav Desai
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 13/08/2009
   NOTE				:
   VERSION HISTORY	:	
					version  : 2.5.1.02	
					Resource : vaibhav 
					Description: created the class
========================================================================================*/
#pragma once
#include "splspyscan.h"

class CPoisonWorm :	public CSplSpyScan
{
public:
	CPoisonWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,7567)
	{
		m_bSplSpyFound = false; 
	}
	virtual ~CPoisonWorm(void)
	{}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
	
};