/*=====================================================================================
   FILE				: LSPFixWorm.h
   ABSTRACT			: This class is used for scanning and qurantining LSP issue
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
   CREATION DATE	: 29/07/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.1.01
					Resource : Shweta
					Description: created this class to LSP fix . Will fix all the spyware files creating lSP fix issue
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CLSPFixWorm : public CSplSpyScan
{
public:
	CLSPFixWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,11380)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CLSPFixWorm (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
};
