/*====================================================================================
   FILE				: InternerOptWorm.h
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

#pragma once
#include "splspyscan.h"

class CInternerOptWorm :	public CSplSpyScan
{

public:
	CInternerOptWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,3200)
	{
		m_bSplSpyFound  = false;
	}
	virtual ~CInternerOptWorm(void)
	{}
	bool ScanSplSpy (bool bToDelete, CFileSignatureDb *pFileSigMan = NULL);
};
