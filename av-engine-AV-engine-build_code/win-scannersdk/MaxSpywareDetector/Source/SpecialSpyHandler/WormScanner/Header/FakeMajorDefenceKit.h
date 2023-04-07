 /*====================================================================================
   FILE				: FakeMajorDefenceKit.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware Fake Major Defence Kit
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 31/08/2010
   NOTE				:
   VERSION HISTORY	:
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CFakeMajorDefenceKit : public CSplSpyScan
{
public:
	CFakeMajorDefenceKit(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper, 1421381)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CFakeMajorDefenceKit(void)
	{
	}
	
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);

private:
	CStringArray		m_csArrSpyLocation;
	CStringArray		m_csArrFixKey;
	CStringArray		m_csArrFixValue;

	bool FixInfection();
	bool SearchInfection();
	bool PreparePathsToSearch();
	bool IsFileInfected(const CString& csFilePath);
	void CheckAndReportInfection(const CString& csFilePath);
};
