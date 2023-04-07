/*=============================================================================
   FILE				: GenericFileScanner.h
   ABSTRACT			: class for generic scanning of files based on heuristic factors
   DOCUMENTS		: 
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created in 2008 as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				without the prior written permission of Aura
   CREATION DATE	: 23/04/2008
   NOTES			:
   VERSION HISTORY	: 
					Version: 19.0.0.062
					Resource: Anand Srivastava
					Description: Added generic scanner for files
=============================================================================*/
class CGenericFileScanner
{
public:
	CGenericFileScanner()
	{}
	virtual ~CGenericFileScanner(void)
	{}

	bool CheckIfFileSuspicious(const CString& csFullFilename, const CStringArray&  csArrSpyLocation, bool bX64 = false);
	bool CheckFileInCLSID(const CString& csCLSID, CString& csData, const CStringArray& csArrSpyLocation, bool bX64 = false);
};
