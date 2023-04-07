/*=============================================================================
   FILE				: Looktome.h
   ABSTRACT			: Declaration of Special Spyware Looktome Class
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
   CREATION DATE	: 
   NOTES			:
   VERSION HISTORY	: 
					Version: 2.5.0.8
					Resource: Shweta
					Description: added function for BHO

					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
=============================================================================*/
#pragma once
#include "splspyscan.h"

class CLookToMe :	public CSplSpyScan
{
	
	CStringArray csArrL2MFiles ;
	CStringArray csArrKeyToDelete ;

	bool CheckCLSIDforData (bool bToDelete );
	bool CheckforBHOEntry();//2.5.0.8
	bool CheckRegistryforLook2Me ( bool bDelete );
	bool CheckNotifyKeys (bool bToDelete);
	bool CheckIfLook2MeFile ( CString csFileName , UCHAR * FileBuffer , DWORD cbFileBuffer );
	
public:
	CLookToMe(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,3669)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CLookToMe(void)
	{}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
};
