
/*======================================================================================
FILE             : U2S.h
ABSTRACT         : tree class to handle database type of ulong -> string
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
				  
CREATION DATE    : 5/17/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "BalBST.h"

class CU2S : public CBalBST
{
public:

	CU2S(bool bIsEmbedded);
	virtual ~CU2S();

	bool AppendItemAscOrder(DWORD dwKey, LPCTSTR szData);
	bool AppendItem(DWORD dwKey, LPCTSTR szData);
	bool DeleteItem(DWORD dwKey);
	bool SearchItem(DWORD dwKey, LPTSTR * ppszData);
	bool Load(LPCTSTR szFullFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFullFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, DWORD& dwKey);
	bool GetData(PVOID pVPtr, LPTSTR& pStr);
	bool AppendObject(CBalBST& objToAdd);
	bool DeleteObject(CBalBST& objToDel);

private:

	virtual COMPARE_RESULT Compare(ULONG64 dwKey1, ULONG64 dwKey2);
	virtual void FreeKey(ULONG64 dwKey);
	virtual void FreeData(ULONG64 dwData);
};
