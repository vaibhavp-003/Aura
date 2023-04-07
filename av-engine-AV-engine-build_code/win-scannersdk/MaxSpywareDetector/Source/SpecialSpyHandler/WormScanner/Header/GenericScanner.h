/*====================================================================================
   FILE				: ShellExecHookList.h
   ABSTRACT			: This class is used for scanning and qurantining Keylogger Beyond
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Siddharam Pujari
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
========================================================================================*/


#pragma once
#include "splspyscan.h"
//#include "GenericFileScanner.h"
//#include "Registry.h"

class CGenericScanner :public CSplSpyScan
{
	CStringArray m_csArrSpyLocation ;

public:
	CGenericScanner(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,2693)
	{
		m_bSplSpyFound  = false;
	}
	virtual ~CGenericScanner(void)
	{}
	bool ScanSplSpy(bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
	bool CheckSharedTask( CString csSTS,bool bWow6432Node = false); 
	bool CheckSSODL();
	bool CheckMenuExtension(const CString& csRegKey , HKEY hHive , const CString& csHiveName, bool bX64Check = false );
	bool CheckBHO();
	bool CheckToolBar(const CString& csRegKey , HKEY hHive , const CString& csHiveName, bool bX64Check = false );
	bool CheckShellExecHook();
	void MakeListofLocations() ;
};
