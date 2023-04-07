/*=====================================================================================
   FILE				: CSdra64.h
   ABSTRACT			: This class is used for scanning and qurantining Sdra64 rootkit
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

class CSdra64 : public CSplSpyScan
{
public:
	CSdra64 (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,858481)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CSdra64 (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
	bool AddEntryInMaxManagerIni(bool bToDelete);
	void CreateWormstoDeleteINI(const CString& strINIPath);
};
