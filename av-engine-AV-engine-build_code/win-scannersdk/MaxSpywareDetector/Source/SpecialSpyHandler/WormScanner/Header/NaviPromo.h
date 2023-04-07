/*=====================================================================================
   FILE				: NaviPromo.h
   ABSTRACT			: This class is used for scanning and qurantining Spyware NaviPromo
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created in 2009 as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 09/04/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.75
					Resource : Anand
					Description: created the class
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CNaviPromoWorm : public CSplSpyScan
{
public:
	CNaviPromoWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,4272)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CNaviPromoWorm()
	{
	}

	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;

private:
	bool IsSpywareFile ( LPCTSTR szFileName ) ;
	bool ReportAllEntries ( LPCTSTR szFileName ) ;
};
