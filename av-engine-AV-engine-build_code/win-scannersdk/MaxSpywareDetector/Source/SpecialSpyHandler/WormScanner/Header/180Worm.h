 /*====================================================================================
   FILE				: 180Worm.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware 180Solutions
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
   CREATION DATE	: 25/12/2003
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
========================================================================================*/

#pragma once
#include "splspyscan.h"

class C180Worm :public CSplSpyScan
{
	int					m_depth180 ;
	CString				m_csExeName ;
	CStringArray		m_csArrInfectedFiles ;

	bool CheckIf180File ( CString csFileName);
	bool Determine180File ( CString csSearchFolder, CString csExt, CString csCompanyName, int iSubFolderDepth );

public:
	//C180Worm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,_T("Adware.180 Search Assistant"))
	//180Solutions
	C180Worm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,16)
	{
		m_bSplSpyFound = false;
	}

	virtual ~C180Worm(void)
	{
	}
	
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
};
