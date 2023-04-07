/*=============================================================================
   FILE				: TheLastDefender.h
   ABSTRACT			: Declaration of Special Spyware CLastDefenderWorm Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Shweta
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 03/04/2008
   NOTES			:
   VERSION HISTORY	: 2.5.0.31 added the class type
								
=============================================================================*/
#pragma once
#include "splspyscan.h"

class CTheLastDefender :public CSplSpyScan
{
	
public:

	CTheLastDefender (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,6603)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CTheLastDefender (void)
	{
	}

	bool ScanSplSpy ( bool bIsDelete = false , CFileSignatureDb *pFileSigMan = NULL );	
};