/*======================================================================================
   FILE				: BustedWorm.Cpp
   ABSTRACT			: Scans for PCBusted.Net spyware
   DOCUMENTS		: Refer The Design Folder (SpecialSpyHandler_DesignDoc.doc)
   AUTHOR			: Avinash B
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 30/07/2007
   NOTES			:
   Version History	:
				version: 2.5.0.23
				Resource : Anand
				Description: Ported to VS2005 with Unicode and X64 bit Compatability					
======================================================================================*/

#pragma once
#include "splspyscan.h"

class CBustedWorm :	public CSplSpyScan
{
	void CheckForRegKeys(CString& csFolderName);

public:

	CBustedWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,1103)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CBustedWorm(void){}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
	
};
