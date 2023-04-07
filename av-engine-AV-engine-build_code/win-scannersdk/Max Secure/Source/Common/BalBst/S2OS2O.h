
/*======================================================================================
FILE             : S2OS2O.h
ABSTRACT         : 3 level tree class to handle database of type string -> string -> string -> ulong
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
				  
CREATION DATE    : 5/18/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "BalBST.h"
#include "S2OS2U.h"

class CS2OS2O : public CBalBST
{
public:

	CS2OS2O(bool bIsEmbedded);
	virtual ~CS2OS2O();

	bool AppendItemAscOrder(LPCTSTR szKey, CS2OS2U * pObjS2OS2U);
	bool AppendItem(LPCTSTR szKey, CS2OS2U * pObjS2OS2U);
	bool DeleteItem(LPCTSTR szKey);
	bool SearchItem(LPCTSTR szKey, CS2OS2U& objS2OS2U);
	bool UpdateItem(LPCTSTR szKey, CS2OS2U& objS2OS2U);
	bool Load(LPCTSTR szFullFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFullFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, LPCTSTR& szKey);
	bool GetData(PVOID pVPtr, CS2OS2U& objS2OS2U);
	bool Balance ();

	bool AppendObject(CBalBST& objBBBSt)
	{
		return true;
	}
	bool DeleteObject(CBalBST& objBBBSt)
	{
		return true;
	}

private:

	virtual COMPARE_RESULT Compare(ULONG64 dwKey1, ULONG64 dwKey2);
	virtual void FreeKey(ULONG64 dwKey);
	virtual void FreeData(ULONG64 dwData);

	DWORD DumpS2O(HANDLE hFile, ULONG64 dwData);
	DWORD DumpS2U(HANDLE hFile, ULONG64 dwData);
	DWORD ReadS2O(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize);
	DWORD ReadS2U(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize);
};
