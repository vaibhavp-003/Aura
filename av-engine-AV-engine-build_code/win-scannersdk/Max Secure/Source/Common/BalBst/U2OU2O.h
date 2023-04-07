
/*======================================================================================
FILE             : U2OU2O.h
ABSTRACT         : 3 level tree class for handling database type ulong -> ulong -> string -> ulong
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
#include "U2OS2U.h"

class CU2OU2O : public CBalBST
{
public:

	CU2OU2O(bool bIsEmbedded);
	virtual ~CU2OU2O();

	bool AppendItemAscOrder(DWORD dwKey, CU2OS2U * pObjU2OS2U);
	bool AppendItem(DWORD dwKey, CU2OS2U * pObjU2OS2U);
	bool DeleteItem(DWORD dwKey);
	bool SearchItem(DWORD dwKey, CU2OS2U& objU2OS2U);
	bool UpdateItem(DWORD dwKey, CU2OS2U& objU2OS2U);
	bool Load(LPCTSTR szFullFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFullFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, DWORD& dwKey);
	bool GetData(PVOID pVPtr, CU2OS2U& objU2OS2U);
	bool Balance();
	bool AppendObject(CBalBST& objAdd);
	bool DeleteObject(CBalBST& objDel);
	bool SearchObject(CBalBST& objSearch, bool bAllPresent = true);

private:

	virtual COMPARE_RESULT Compare(ULONG64 dwKey1, ULONG64 dwKey2);
	virtual void FreeKey(ULONG64 dwKey);
	virtual void FreeData(ULONG64 dwData);

	bool DumpU2O(HANDLE hFile, ULONG64 dwData);
	bool DumpS2U(HANDLE hFile, ULONG64 dwData);
	bool ReadU2O(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize);
	bool ReadS2U(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize);
};
