/*====================================================================================
   FILE				: FakeSecurityAlert.h
   ABSTRACT			: This class is used for scanning Fake Security Alerts 
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
   CREATION DATE	: 25/08/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.49
					Resource : Shweta
					Description: FakeSecurityAlert 
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CFakeSecurityAlertWorm :	public CSplSpyScan
{
public:
	CStringArray 	m_csArrRunEntries ;
	CEnumProcess m_objEnumProc;

	CFakeSecurityAlertWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,2246)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CFakeSecurityAlertWorm(void)
	{}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
	bool GetStopStatus() ;
	bool CollectRunEntries() ;
	bool CheckMemDetails ( const CString& csFilename , HANDLE hProcess , HMODULE hModule ) ;
	bool GetSizeOfImage ( LPCTSTR szImageFilename , DWORD& dwSizeOfImage ) ;
	bool IsVersionTabPresent ( const CString& csFileName ) ;
	
};
