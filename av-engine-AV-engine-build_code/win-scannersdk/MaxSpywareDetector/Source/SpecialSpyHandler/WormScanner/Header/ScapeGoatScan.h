/*=====================================================================================
   FILE				: CScapeGoatScan.h
   ABSTRACT			: This class is used for scanning ScapeGoat Files 
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			:  
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 
   NOTE				:
   VERSION HISTORY	:
					
========================================================================================*/

#pragma once
#include "splspyscan.h"
#include "C7zDLL.h"
#define INI_FILE_DATA_NAME	_T("\\FileData.ini")

class CScapeGoatScan : public CSplSpyScan
{
private:
	void EnumerateFolder(const CString csFolderPath);
	bool CheckMD5MisMatch(const CString csFilePath);
	C7zDLL	m_obj7zDLL;

	CString m_csFDPath; 
public:
	CScapeGoatScan (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper, 13277)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CScapeGoatScan (void)
	{}
	
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
};
