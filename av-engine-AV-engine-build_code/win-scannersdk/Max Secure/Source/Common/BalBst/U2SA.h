
/*======================================================================================
FILE             : U2SA.h
ABSTRACT         : tree class to handle database type of ulong -> string(ansi)
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
				  
CREATION DATE    : 12/08/2010
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "BalBSTOpt.h"

class CU2SA : public CBalBST
{
public:

	CU2SA(bool bIsEmbedded);
	virtual ~CU2SA();

	bool AppendItemAscOrder(DWORD dwKey, LPCSTR szData);
	bool AppendItem(DWORD dwKey, LPCSTR szData);
	bool DeleteItem(DWORD dwKey);
	bool SearchItem(DWORD dwKey, LPSTR * ppszData);
	bool Load(LPCTSTR szFullFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFullFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, DWORD& dwKey);
	bool GetData(PVOID pVPtr, LPSTR& pStr);
	bool AppendObject(CBalBST& objBBBSt);
	bool DeleteObject(CBalBST& objBBBSt);

private:

	virtual COMPARE_RESULT Compare(ULONG64 dwKey1, ULONG64 dwKey2);
	virtual void FreeKey(ULONG64 dwKey);
	virtual void FreeData(ULONG64 dwData);
};
