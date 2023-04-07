/*====================================================================================
   FILE				: HeurScanWorm.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware by Heurisctic Method
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
   CREATION DATE	: 18/09/2010
   NOTE				:
   VERSION HISTORY	:
========================================================================================*/

#pragma once
#include "splspyscan.h"

BOOL CALLBACK HEUR_ProcessModuleHandler(DWORD dwProcessID, HANDLE hProcess, HMODULE hModule, LPCTSTR szModulePath, LPVOID pThis, bool &bStopEnum);
BOOL CALLBACK HEUR_ProcessHandler(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, LPVOID pThis, bool &bStopEnum);

typedef struct _tagSysFile
{
	LPCTSTR		szPath;
	LPCTSTR		szName;
}SYS_FILE, *PSYS_FILE, *LPSYS_FILE;

class CHeurScanWorm : public CSplSpyScan
{
public:

	CHeurScanWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper, 1443293)
	{
		m_bSplSpyFound = false;
	}

	~CHeurScanWorm()
	{
	}

	bool ScanSplSpy(bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);

	CEnumProcess m_objEnumProc;
	bool GetStopStatus();
	bool ScanThisFile(LPCTSTR szFilePath, SIZE_T iType);
};
