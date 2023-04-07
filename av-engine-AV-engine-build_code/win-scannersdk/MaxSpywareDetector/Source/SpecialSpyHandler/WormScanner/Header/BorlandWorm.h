/*=============================================================================
   FILE				: BorlandWorm.h
   ABSTRACT			: Declaration of class BorlandWorm
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			:
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: DD/Month/YYYY
   NOTES			:
   VERSION HISTORY	: 
			Date	: 18 June 2007
			Version : 2.5.0.2	
			Resource: Shweta
			Description: Added functions CheckforPFDirRandomEntry ,CheckIfSpywareFolder. 
				
=============================================================================*/

#pragma once
#include "splspyscan.h"

class CBorlandWorm :	public CSplSpyScan
{
	CStringArray m_csArrDelKeys;
	//Version :2.5.0.2
	CStringArray m_csArrFiles2Delete;
	bool CheckforPFDirRandomEntry();
	bool CheckIfSpywareFolder(const CString& csFolderPath);

public:
	CBorlandWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,995)
	{
		m_bSplSpyFound  = false;
	}
	virtual ~CBorlandWorm(void)
	{}

	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
	
};
