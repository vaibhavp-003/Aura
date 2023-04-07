 /*====================================================================================
   FILE				: BaiduWorm.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware BaiduWorm
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Prashant Mandhare
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 15/2/2010
   NOTE				:
   VERSION HISTORY	:
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CBaiduWorm :public CSplSpyScan
{
	
public:
	CBaiduWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,696)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CBaiduWorm(void)
	{
	}
	
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);

private:

	bool ScanBaiduFiles(bool bToDelete);
	bool ScanDesktopLinks(bool bToDelete);
	bool CheckFileAssoc(const CString& csFilePath, CS2S& objExtList);
	bool ScanRegistryRandomKeys(bool bToDelete);
	bool ScanCommonLocations(bool bToDelete);
	bool ScanPFDIR();
	bool ScanStartUpDIR();
	bool ScanSystem32();
	//bool ScanRoot();
	bool CheckNamePattern(const CString& csFileName);
};
