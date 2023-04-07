/*=====================================================================================
   FILE				: Antivirus2009.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware Antivirus2009
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
   CREATION DATE	: 01/03/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.65
					Resource : Shweta
					Description: created the class
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CAntivirus2009 : public CSplSpyScan
{
public:
	CAntivirus2009 (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,474)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CAntivirus2009 (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
	bool CheckIfRandomEntry ( const CString & csVal , CString csData , const CString & csSid ) ;
	void CheckIfSpywareDesktop ( const CString &csSid );
};
