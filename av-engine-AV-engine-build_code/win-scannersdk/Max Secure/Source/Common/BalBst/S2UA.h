
/*======================================================================================
FILE             : S2UA.h
ABSTRACT         : tree class to database of type string( ansi ) -> ulong
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
				  
CREATION DATE    : 6/27/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "BalBST.h"

class CS2UA : public CBalBST
{
public:

	CS2UA(bool bIsEmbedded);
	virtual ~CS2UA();

	bool AppendItemAscOrder(LPCSTR szKey, DWORD dwData);
	bool AppendItem(LPCSTR szKey, DWORD dwData);
	bool DeleteItem(LPCSTR szKey);
	bool SearchItem(LPCSTR szKey, unsigned long * pulData);
	bool Load(LPCTSTR szFullFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFullFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, LPSTR& pStr);
	bool GetData(PVOID pVPtr, DWORD& dwData);
	bool AppendObject(CBalBST& objToAdd)
	{
		return true;
	}

	bool DeleteObject(CBalBST& objToDel)
	{
		return true;
	}

private:

	virtual COMPARE_RESULT Compare(ULONG64 dwKey1, ULONG64 dwKey2);
	virtual void FreeKey(ULONG64 dwKey);
	virtual void FreeData(ULONG64 dwData);
};
