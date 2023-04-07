/*=====================================================================================
   FILE				: VirusDoctor.h
   ABSTRACT			: This class is used for scanning Spyware Virus Doctor
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
   CREATION DATE	: 10/02/2009
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.50
					Resource : Shweta
					Description: created the class
========================================================================================*/

#pragma once
#include "splspyscan.h"

class CVirusDoctorWorm : public CSplSpyScan
{
public:
	CVirusDoctorWorm (CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,9620)
	{
		m_bSplSpyFound = false;
	}
	virtual ~CVirusDoctorWorm (void)
	{}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;	
};
