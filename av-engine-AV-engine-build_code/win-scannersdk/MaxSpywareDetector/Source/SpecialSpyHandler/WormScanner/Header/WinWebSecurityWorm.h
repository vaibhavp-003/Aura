/*=====================================================================================
   FILE				: WinWebSecurityWorm.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware WinWeb Security
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
   CREATION DATE	: 12/15/2008
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.61
					Resource : Shweta
					Description: created the class
					
					version: 2.5.1.08
					Resource : Shweta
					Description: Added function for Smart virus eliminator.
========================================================================================*/

#pragma once
#include "splspyscan.h"
#include "ExecuteProcess.h"

class CWinWebSecurityWorm : public CSplSpyScan
{
public:
	CWinWebSecurityWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,9096)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CWinWebSecurityWorm (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
	bool CheckValueToBeDigit ( const CString & csVal , bool bAllDigits = true ) ;
	bool CheckIfSpywarePath ( CString csPath , bool bToDelete);
	void CheckAppFolder ( void ) ;
	void CheckForRunEntry(CString csFileName,CString csCheckPath);
	bool CheckOtherFakeInfection ( const CString& csFolderName , const CString& csFullFolderPath);
	bool CheckForEnterpriseSuit ( const CString& csFolderName , const CString& csFullFolderPath);
	bool CheckForSysguardinfection ( const CString& csFolderName , const CString& csFullFolderPath);
	bool CheckSpyFolder ( const CString csFilePath , const CString csAppPath , const CString csFolderName , bool bToDelete ) ;

private:

	CStringArray m_csArrSpyLocation;
	CStringArray m_csArrRegistryKeys;

    bool CheckByStartProgramsLink() ;
    bool ResolveShortcut ( LPCTSTR szShortcutFileName , LPTSTR szTargetFileName , DWORD cbTargetFileName ) ;
    bool CheckFolderForPattern ( LPCTSTR szPath , LPCTSTR szPattern ) ;
	bool CheckVersionTab ( CString csData , bool bFolder = true ) ; //2.5.0.78
	bool CheckForXPHomeSecurity();
	void MakeListofLocations();
};
