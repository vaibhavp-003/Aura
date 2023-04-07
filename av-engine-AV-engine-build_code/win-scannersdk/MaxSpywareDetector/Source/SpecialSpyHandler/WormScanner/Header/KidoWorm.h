/*======================================================================================
   FILE				: KidoWorm.h
   ABSTRACT			: This class is used for scanning and qurantining Kido Worm
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
   CREATION DATE	: 27/10/2010
   NOTE				:
   VERSION HISTORY	:
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CKidoWorm : public CSplSpyScan
{
public:
	CKidoWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper, 9310)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CKidoWorm (void)
	{}

	CStringArray m_csArrPrcModList;
	bool GetStopStatus();
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;

private:

	void ExecuteCommandWithWait(CString sExecCmd, CString csParam);
	bool PrepareProcessAndModulesList();
	bool ScanForHiddenServiceKey();
	bool IsFileInfected(const CString csFilePath);
	bool ScanRegistryFixEntries(bool bScan);
};
