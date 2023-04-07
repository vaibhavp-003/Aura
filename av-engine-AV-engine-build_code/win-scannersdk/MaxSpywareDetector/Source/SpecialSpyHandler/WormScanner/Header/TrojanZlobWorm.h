/*====================================================================================
   FILE				: TrojanZlob.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware TrojanZlob
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Shweta
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 17/04/2008
   NOTE				:
   VERSION HISTORY	:
					
					
========================================================================================*/

#pragma once
#include "splspyscan.h"

typedef BOOL ( WINAPI * LPFN_EnumProcesses ) ( DWORD * lpidProcess, DWORD   cb, DWORD * cbNeeded ) ;
typedef BOOL ( WINAPI * LPFN_EnumProcessModules )( HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded ) ;
typedef DWORD (WINAPI * LPFN_GetModuleFileNameEx)(HANDLE hProcess, HMODULE hModule, LPTSTR lpFilename, DWORD nSize);

class CTrojanZlobWorm :	public CSplSpyScan
{
private:
	CEnumProcess m_objEnumProc;
	CStringArray m_csArrRunEntries ;

	LPFN_EnumProcesses m_lpfnEnumProcesses ;
	LPFN_EnumProcessModules m_lpfnEnumProcessModules ;
	LPFN_GetModuleFileNameEx m_lpfnGetModuleFileNameEx;

	bool CheckMemDetails ( const CString& csFilename , HANDLE hProcess , HMODULE hModule , int iRunCnt);
	bool GetSizeOfImage ( LPCTSTR szImageFilename , DWORD& dwSizeOfImage );
	bool CollectRunEntries();
	void CheckAppDataFile();
	bool EnumProcessAndModules();		

public:
	CTrojanZlobWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,7485)
	{
		m_bSplSpyFound = false;
		m_lpfnEnumProcesses = NULL ;
		m_lpfnEnumProcessModules = NULL ;
		m_lpfnGetModuleFileNameEx = NULL ;
	}

	virtual ~CTrojanZlobWorm(void)
	{}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
	
};
