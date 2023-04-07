 /*====================================================================================
   FILE				: GenAutorunInf.h
   ABSTRACT			: This class is used for scanning and qurantining generic autorun.inf entries
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created in 2009 as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 30/04/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.76
					Resource : Anand
					Description: created the class
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CGenAutorunInfWorm : public CSplSpyScan
{
public:
	CGenAutorunInfWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,295)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CGenAutorunInfWorm(void)
	{
	}
	
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);

private:

	bool GetTargetFileNames ( LPCTSTR csAutorunFilename , CStringArray& csArrTargetFilesList ) ;
	void EnumerateFolder(const CString csFolderPath);
	bool CheckForGenericAutorun();
	bool InSafeList(CString csFileSearch);
	CStringArray m_csFolderNames;
	CStringArray m_csFileNames;
	CStringArray m_csSafeList;
};