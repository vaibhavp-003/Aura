/*====================================================================================
   FILE				: GenHostScanner.h
   ABSTRACT			: This class is used for scanning and qurantining generic entries in host file
   DOCUMENTS		: No documentation, as its a temporary scanner, has to be removed
   AUTHOR			: Anand Srivastava
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

class CGenHostScanner :	public CSplSpyScan
{

private:

	CStringArray	m_csArrLinesToRemove ;

	bool CheckHostFile ( bool bToDelete ) ;
	bool GetDomainName ( TCHAR * szLineFromFile , TCHAR * szDomainName , DWORD dwDomainNameSize ) ;

public:

	CGenHostScanner(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,2947)
	{
		m_bSplSpyFound =  false;
	}

	virtual ~CGenHostScanner(void){}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
};
