/*=============================================================================
   FILE				: WebHancerWorm.h
   ABSTRACT			: Declaration of Special Spyware WebHancerWorm Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 31/08/2007
   NOTES			:
   VERSION HISTORY	: added the class
=============================================================================*/

#pragma once
#include "splspyscan.h"

class CWebHancerWorm :	public CSplSpyScan
{
	
public:
	CWebHancerWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,8142)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CWebHancerWorm(void){}
	bool ScanSplSpy (bool bToDelete, CFileSignatureDb *pFileSigMan = NULL);
	
};
