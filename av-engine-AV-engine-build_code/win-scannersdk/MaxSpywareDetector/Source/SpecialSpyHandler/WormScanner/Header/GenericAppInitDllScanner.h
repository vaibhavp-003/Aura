/*======================================================================================
   FILE				: InitDllWormList.h 
   ABSTRACT			: Adds scanned AppInit_Dlls registry entries.
   DOCUMENTS		: Refer the document Folder (SpyEliminator-LLD.Doc)
   AUTHOR			: Dipali Pawar
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: 
				  (C) Aura
  				  Created as an unpublished copyright work.  All rights reserved.
 				  This document and the information it contains is confidential and
  				  proprietary to Aura.  Hence, it may not be 
  				  used, copied, reproduced, transmitted, or stored in any form or by any 
  				  means, electronic, recording, photocopying, mechanical or otherwise, 
  				  without the prior written permission of Aura
   CREATION DATE	: 28/10/2006
   NOTES			:
    VERSION HISTORY :
======================================================================================*/
#pragma once
#include "splspyscan.h"

class CGenericAppInitDllScanner :public CSplSpyScan
{
public:
	CGenericAppInitDllScanner(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,2693)
	{
		m_bSplSpyFound = false ;
	}
	virtual ~CGenericAppInitDllScanner(void){}

	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
	void ScanAppInitDataPart(CS2U &objDBMap,LPCWSTR lstrRegistryPath);
	bool CheckVersionTab(CString csFilePath);
};
