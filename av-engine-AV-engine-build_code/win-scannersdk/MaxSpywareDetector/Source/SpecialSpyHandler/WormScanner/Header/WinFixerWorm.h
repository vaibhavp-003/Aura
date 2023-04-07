/*====================================================================================
   FILE				: WinFixerWorm.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware WinFixer
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
   CREATION DATE	: 25/12/2005
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CWinFixerWorm :	public CSplSpyScan
{
	
	CStringArray m_csArrWinFixerFOPN ;
	CStringArray m_csArrWinFixerWff ;
	CStringArray m_csArrWinFixerDf_kmd ;
	CStringArray m_csArrWinFixerSSODLRegEntries ;
	CStringArray m_csArrWinFixerSSODLFileEntries ;

	bool _CheckAndRunWinFixerUninstaller(bool bToDelete);
	void _ProcessRunEntry(HKEY hKeyHive, CString csMainKey);
	void _HandleUninstaller( ULONG ulSpywareName );

public:

	CWinFixerWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,7186)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CWinFixerWorm(void){}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
	
};
