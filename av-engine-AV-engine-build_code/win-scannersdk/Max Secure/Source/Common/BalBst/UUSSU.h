
/*======================================================================================
FILE             : UUSSU.h
ABSTRACT         : 4 level tree class to handle database type of ulong -> ulong -> string -> string -> ulong
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
#include "balbst.h"
#include "U2OS2O.h"

class CUUSSU : public CBalBST
{
public:

	CUUSSU(bool bIsEmbedded);
	virtual ~CUUSSU();

	bool AppendItemAscOrder(DWORD dwKey, CU2OS2O * pU2OS2O);
	bool AppendItem(DWORD dwKey, CU2OS2O * pU2OS2O);
	bool DeleteItem(DWORD dwKey);
	bool SearchItem(DWORD dwKey, CU2OS2O& objU2OS2O);
	bool UpdateItem(DWORD dwKey, CU2OS2O& objU2OS2O);
	bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, DWORD& dwKey);
	bool GetData(PVOID pVPtr, CU2OS2O& objU2OS2O);
	bool Balance();
	bool AppendObject(CBalBST& objToAdd);
	bool DeleteObject(CBalBST& objToDel);
	bool SearchObject(CBalBST& objToSearch, bool bAllPresent = true);

private:

	virtual COMPARE_RESULT Compare(ULONG64 dwKey1, ULONG64 dwKey2);
	virtual void FreeKey(ULONG64 dwKey);
	virtual void FreeData(ULONG64 dwData);

	bool MakeDuplicate(CS2U& objS2UDst, CS2U& objS2USrc);
	bool MakeDuplicate(CS2OS2U& objS2OS2UDst, CS2OS2U& objS2OS2USrc);
	bool MakeDuplicate(CU2OS2O& objU2OS2ODst, CU2OS2O& objU2OS2OSrc);

	DWORD DumpU2O(HANDLE hFile, ULONG64 dwData);
	DWORD DumpS2O(HANDLE hFile, ULONG64 dwData);
	DWORD DumpS2U(HANDLE hFile, ULONG64 dwData);
	DWORD ReadU2O(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize);
	DWORD ReadS2O(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize);
	DWORD ReadS2U(ULONG64*& pCurrentPtr, ULONG64 dwBaseAddress, DWORD dwFileSize);
};
