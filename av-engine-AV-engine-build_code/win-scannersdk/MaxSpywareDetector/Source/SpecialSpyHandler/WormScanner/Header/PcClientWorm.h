/*=====================================================================================
   FILE				: PcClientWorm.h
   ABSTRACT			: This class is used for scanning and qurantining Backdoor PcClientWorm
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
   CREATION DATE	: 17/09/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.52
					Resource : Shweta
					Description: created the class
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CPcClientWorm : public CSplSpyScan
{
	void ScanRegEntryAndFiles ( bool ) ;
	void ScanRegEntryBySysFiles ( bool ) ;
	bool CheckSignature ( const CString csFilePath ) ;

public:
	CPcClientWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,4727)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CPcClientWorm (void)
	{}

	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
};
