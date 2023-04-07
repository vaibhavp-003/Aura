
/*======================================================================================
FILE             : U2OS2O.h
ABSTRACT         : 3 level tree class for handling database type ulong -> string -> string -> ulong
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
				  
CREATION DATE    : 6/10/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "BalBST.h"
#include "S2OS2U.h"

class CU2OS2O : public CBalBST
{
public:
	CU2OS2O(bool bIsEmbedded);
	virtual ~CU2OS2O();

	bool AppendItemAscOrder(DWORD dwKey, CS2OS2U * pS2OS2U);
	bool AppendItem(DWORD dwKey, CS2OS2U * pS2OS2U);
	bool DeleteItem(DWORD dwKey);
	bool SearchItem(DWORD dwKey, CS2OS2U& objS2OS2U);
	bool UpdateItem(DWORD dwKey, CS2OS2U& objS2OS2U);
	bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, DWORD& dwKey);
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
