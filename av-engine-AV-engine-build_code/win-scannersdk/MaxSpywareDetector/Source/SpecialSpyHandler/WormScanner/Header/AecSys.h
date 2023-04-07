/*=====================================================================================
   FILE				: CAecSys.h
   ABSTRACT			: This class is used for scanning and qurantining Aec Sys
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

class CAecSys : public CSplSpyScan
{
public:
	CAecSys (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,3277)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CAecSys (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	

};
