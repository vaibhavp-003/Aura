
/*======================================================================================
FILE             : Q2S.h
ABSTRACT         : tree class to handle database type of quad word(u64) -> string
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 2/3/2011
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "BalBSTOpt.h"

typedef ULONG64	QWORD;

class CQ2S : public CBalBSTOpt
{
public:

	CQ2S(bool bIsEmbedded);
	virtual ~CQ2S();

	bool AppendItemAscOrder(QWORD ulKey, LPCTSTR szData);
	bool AppendItem(QWORD ulKey, LPCTSTR szData);
	bool DeleteItem(QWORD ulKey);
	bool SearchItem(QWORD ulKey, LPTSTR& szData);
	bool Load(LPCTSTR szFullFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFullFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, QWORD& ulKey);
	bool GetData(PVOID pVPtr, LPTSTR& szData);
	bool AppendObject(CBalBSTOpt& objAdd)
	{
		return true;
	}

	bool DeleteObject(CBalBSTOpt& objDel)
	{
		return true;
	}

private:

	virtual COMPARE_RESULT Compare(SIZE_T nKey1, SIZE_T nKey2);
	virtual void FreeKey(SIZE_T nKey);
	virtual void FreeData(SIZE_T nData);
};

