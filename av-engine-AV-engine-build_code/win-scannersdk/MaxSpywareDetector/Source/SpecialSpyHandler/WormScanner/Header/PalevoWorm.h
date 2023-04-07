/*=====================================================================================
   FILE				: PalevoWorm.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware Guard
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			:  
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 
   NOTE				:
   VERSION HISTORY	:
					
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CPalevoWorm : public CSplSpyScan
{
public:
	CPalevoWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,9681)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CPalevoWorm (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
	void ScanPathForExes(CString csPath);
	bool ScanFile(CString csFullFileName);

};
