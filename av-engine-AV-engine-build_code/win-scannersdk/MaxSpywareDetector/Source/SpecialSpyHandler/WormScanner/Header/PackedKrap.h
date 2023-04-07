/*=====================================================================================
   FILE				: PackedKrap.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware Packed Krap
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Yuvraj
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 13-4-2010
   NOTE				:
   VERSION HISTORY	:
					
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CPackedKrap : public CSplSpyScan
{
public:
	CPackedKrap(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper, 923818)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CPackedKrap (void)
	{}
	bool ScanSplSpy(bool bToDelete = false, CFileSignatureDb *pFileSigMan = NULL);	
	bool ScanEnrtyInRun(HKEY hHive, CString csLocation);
	bool CheckFileIsSpyware(CString csData);
	bool ScanFile(const CString csFullFileName);

	CStringArray m_csInfecFiles;
};