/*====================================================================================
   FILE				: RandomDrivers.h
   ABSTRACT			: This class is used for scanning Random Drivers
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
   CREATION DATE	: 04/06/2008
   NOTE				:
   VERSION HISTORY	:					
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CRandomDriversWorm :	public CSplSpyScan
{
public:
	CRandomDriversWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,5239)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CRandomDriversWorm (void)
	{}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
	
};
