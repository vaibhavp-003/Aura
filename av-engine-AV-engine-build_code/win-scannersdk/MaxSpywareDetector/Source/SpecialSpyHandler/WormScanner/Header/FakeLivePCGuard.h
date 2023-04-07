/*=====================================================================================
   FILE				: FakeLivePCGuard.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware Guard
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
#include "PathExpander.h"
#include "string.h"
#include "FileSig.h"

using namespace std;
class CFakeAvData
{
public:
	CString m_RegKey;
	CString m_RegLocation;
	CString m_FilePath;
	HKEY hHive;
};

class CFakeLivePCGuard : public CSplSpyScan
{
public:
	CFakeLivePCGuard (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,39234)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CFakeLivePCGuard (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
	bool ScanEnrtyInRun(HKEY, CString );
	bool IsRootFolder(CString& csData);
	bool IsSameFolderFileName(CString& csData);
	void InitFolderData();
	bool ScanLinkFile(LPCTSTR szFilePath);
	bool ResolveShortcut(LPCTSTR szShortcutFileName, LPTSTR szArguments, DWORD cbArguments, LPTSTR strworkdir ,bool bGetArgs = true);
	void EnumerateFolder(std::wstring& wsData);
	HRESULT ResolveShortcutEx(LPCTSTR lpszShortcutPath,LPTSTR lpszFilePath);
	bool IsSameSize(std::wstring& wStr1, std::wstring& wStr2);
	void ParseWinlogonUserInit();
	void ShellServiceObjectDelayLoad();
	void ParseWindowsLoad();
	void ParseWinlogonShell(HKEY hHive);
	void WriteSignatureToIni(CString csOriginalFilePath);
	bool FindInfectionAtDepth(CString& csData, int iDepth);

private:
	CString m_UsrPath;
	CString m_LocalPath;
	CString m_wsPath;
	CFileSig* m_pFileSig;

	CString m_ShortCutPath1;
	CString m_ShortCutPath2;
	CString m_ShortCutPath3;
	CString m_csINIFileName;
};
