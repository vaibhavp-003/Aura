/*=============================================================================
   FILE				: TrojanAgentWorm.h
   ABSTRACT			: Declaration of Special Spyware TrojanAgentWorm Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Shweta
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 29/06/2007
   NOTES			:
   VERSION HISTORY	: added the class type
								
=============================================================================*/
#pragma once
#include "splspyscan.h"

class CTrojanAgentWorm :	public CSplSpyScan
{
	
public:

	CTrojanAgentWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,295)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CTrojanAgentWorm(void)
	{
	}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
	bool CheckPFDirDll ( const CString& csFilem);
	bool IsFileInfected ( const CString& csFilem);
	bool IsRandomBHOFile( CString csFilenm, CString csBHO );
	bool GenericBHOScanner( const CString csFilenm);
	void CheckForExplorerExe(bool bToDelete);

private:
	bool CheckPattern(const CString& csFilePath, const CStringArray& csArrPFFolders);
	bool CheckForCommonInfectionKeys();
	bool CheckForShortcutTrojan();
	bool CheckForHiddenRandomAutorunGenerator();
	bool ResetImportantFolderAttributes();
	bool RemoveSystemAndHidden(LPCTSTR szObject);
	bool CheckSuspiciousFilesRunningFromAutorun(TCHAR chDriveLetter);
	bool CheckForDoubleSpacePFDIR();
	bool FixDesktopShortcutPaths();
};
