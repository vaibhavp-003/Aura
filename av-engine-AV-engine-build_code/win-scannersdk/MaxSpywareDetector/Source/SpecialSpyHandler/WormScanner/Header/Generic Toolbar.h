/*=============================================================================
   FILE				: GenericToolbar.h
   ABSTRACT			: Declaration of Special Spyware GenericToolbar Class
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
   CREATION DATE	: 18/02/2008	
   NOTES			:
   VERSION HISTORY	: 2.5.0.28								
=============================================================================*/
#pragma once
#include "splspyscan.h"

class CGenericToolbar :	public CSplSpyScan
{
	
public:
	CGenericToolbar(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,295)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CGenericToolbar(void)
	{
	}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
	bool GenericToolbarScanner ( const CString csFilenm);
};
