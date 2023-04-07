/*======================================================================================
   FILE				: IPInfo.h
   ABSTRACT			: Information of spyware IP entry.
   DOCUMENTS		: Network Connection scanner-Design Document.doc
   AUTHOR			: Dipali
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 10/june/2008
   NOTES			: 
   VERSION HISTORY	: 	
======================================================================================*/
#pragma once
#include <Afxtempl.h>
class CIPInfo : public CObject
{
public:
	DECLARE_SERIAL(CIPInfo)

	//functions
	inline CIPInfo(void){};
	inline ~CIPInfo(void){};
	void Serialize(CArchive &archive);

	//data
	CString csSpywareID;
	CString csSpywareName;
};
