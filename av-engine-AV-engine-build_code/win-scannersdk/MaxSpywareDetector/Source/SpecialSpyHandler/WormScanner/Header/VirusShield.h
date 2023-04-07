/*=====================================================================================
   FILE				: VirusShield.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware virus Shield
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
   CREATION DATE	: 24/16/2009
   NOTE				:
   VERSION HISTORY	: 2.5.0.81				
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CVirusShield : public CSplSpyScan
{
public:
	CVirusShield (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,11389)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CVirusShield (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
};
