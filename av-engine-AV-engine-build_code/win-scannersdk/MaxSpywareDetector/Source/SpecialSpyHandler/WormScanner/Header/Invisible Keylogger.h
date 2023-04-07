/*=============================================================================
   FILE				: Invisible Keylogger.h
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
   CREATION DATE	: 26/02/2008
   NOTES			:
   VERSION HISTORY	: version: 2.5.0.41
					Resource : shweta
					Description: Added CStringArray object and function declaration. 
					 
								
=============================================================================*/
#pragma once
#include "splspyscan.h"

class CInvisibleKeylogger :	public CSplSpyScan
{
private:
	 CStringArray m_csArrModifiedData ;
	 bool SetNonIKSData ();

public:
	CInvisibleKeylogger(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,3217)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CInvisibleKeylogger(void)
	{
	}
	bool ScanSplSpy ( bool bIsDelete = false, CFileSignatureDb *pFileSigMan = NULL);
};
