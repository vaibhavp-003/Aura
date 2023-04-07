/*======================================================================================
   FILE				: ExcludeDb.Cpp
   ABSTRACT			: List Of Spywares, Which User Doesn’t Want To Get Searched Or Removed 
					  While Searching The Spywares. Recovery Of The Exlcudeded Spywares
   DOCUMENTS		: OptionDll Design.doc
   AUTHOR			: Dipali
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 5/May/2008
   NOTES			: 
   VERSION HISTORY	: 	
======================================================================================*/
#pragma once
#include "tbtremfc.h"
class COldExcludeDb
{
public:
	COldExcludeDb(void);
	~COldExcludeDb(void);

	bool IsExcluded(CString csName, CString &csSpyware, bool bParent = true);
	bool Read();
	bool Save();
	void Exclude(CString &csName, CString &csSpyware, bool bParent = true);
	void Recover(CString &csName, CString &csSpyware, bool bParent = true);
	CString GetFileName()const;

	CtStringToCObject m_objExcludeDb;
};
