/*=============================================================================
   FILE				: SpyCrushWorm.h
   ABSTRACT			: declaration of Special Spyware SpyCrush Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 20/06/2007
   NOTES			:
   VERSION HISTORY	: 
					Version: 2.5.0.2
					Resource: Anand
					Description: file creation

					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
=============================================================================*/

#pragma once
#include "splspyscan.h"

class CSpyCrushWorm : public CSplSpyScan
{
public:
	CEnumProcess m_objEnumProc;
	CStringArray m_csArrSTSEntries ;
	CStringArray m_csArrInfectedFiles ;

	CSpyCrushWorm(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,6147)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CSpyCrushWorm ( void )
	{
	}

	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL) ;
	bool GetStopStatus() ;
	bool CollectSTSEntries() ;
	bool CheckMemDetails ( const CString& csFilename , HANDLE hProcess , HMODULE hModule ) ;
	bool GetSizeOfImage ( LPCTSTR szImageFilename , DWORD& dwSizeOfImage ) ;
	bool IsVersionTabPresent ( const CString& csFileName ) ;
	
};
