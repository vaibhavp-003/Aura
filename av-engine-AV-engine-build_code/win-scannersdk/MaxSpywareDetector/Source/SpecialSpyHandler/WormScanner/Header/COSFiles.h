 /*====================================================================================
   FILE				: COSFiles.h
   ABSTRACT			: This class is used for Scanning SYstem Files
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
   CREATION DATE	: 03/04/2009
   NOTE				:
   VERSION HISTORY	:					
					
========================================================================================*/

#pragma once
#include "splspyscan.h"

class COSFiles :public CSplSpyScan
{
public:
	COSFiles(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper, 16 )
	{
		m_bSplSpyFound = false;
	}

	virtual ~COSFiles(void)
	{
	}
	
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
};
