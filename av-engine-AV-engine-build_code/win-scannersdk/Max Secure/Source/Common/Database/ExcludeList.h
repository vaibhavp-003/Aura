/*======================================================================================
   FILE				: ExcludeList.h
   ABSTRACT			: List Of Spywares, Which User Doesn’t Want To Get Searched Or Removed 
					  While Searching The Spywares. Recovery Of The Exlcudeded Spywares
   DOCUMENTS		: SpyEliminator-LLD.Doc
   AUTHOR			: Nilesh Dorge
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 25/12/2003
   NOTES			: 
   VERSION HISTORY	: 	
======================================================================================*/
#pragma once
//#include "spy.h"

class CExcludeList :  public CStringArray
{
public:
	CExcludeList(bool bReadOnly = false);
	virtual ~CExcludeList();
	void Remove(const CString& spyName);

private:
	void Read(void);
	void Save(void);
	CString GetFileName(void)const;

	bool m_bReadOnly;
};


