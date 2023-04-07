/*=====================================================================================
   FILE				: GenActiveSetup.h
   ABSTRACT			: This class is used for scanning and qurantining Random infection of Active setup install components
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
   CREATION DATE	: 19/11/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.1.13
					Resource : Shweta
					Description: created the class
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CGenActiveSetupICWorm : public CSplSpyScan
{

public:
	CGenActiveSetupICWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,4727)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CGenActiveSetupICWorm (void)
	{}

	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
	bool CheckforActiveSetupEntries(const CString & csKeyToenum , bool bToDelete);
	bool CheckforMicrosoftKey (bool bToDelete);
};
