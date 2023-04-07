/*=============================================================================
   FILE				: FraudTool.h
   ABSTRACT			: Declaration of Special Spyware CFraudTool Class
   DOCUMENTS		: SpeacialSpyhandler_DesignDoc.doc
   AUTHOR			: Ritesh
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 04/06/2008
   NOTES			:
   VERSION HISTORY	: added the class type

=============================================================================*/
#pragma once
#include "splspyscan.h"

class CFraudTool : public CSplSpyScan
{
	
public :

	CFraudTool ( CSplSpyWrapper *pSplSpyWrapper ): CSplSpyScan ( pSplSpyWrapper , 2436 )
	{
		m_bSplSpyFound = false;
	}

	virtual ~CFraudTool ( void )
	{
	}

	bool ScanSplSpy ( bool bIsDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
} ;