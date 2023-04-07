
/*======================================================================================
FILE             : U2U.h
ABSTRACT         : tree class to handle database of type ulong -> ulong
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
				  
CREATION DATE    : 6/2/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "balbst.h"

class CU2U : public CBalBST
{
public:

	CU2U(bool bIsEmbedded);
	virtual ~CU2U();
	bool AppendItemAscOrder(DWORD dwKey, DWORD dwData);
	bool AppendItem(DWORD dwKey, DWORD dwData);
	bool DeleteItem(DWORD dwKey);
	bool SearchItem(DWORD dwKey, DWORD& dwData);
	bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, DWORD& dwKey);
	bool GetData(PVOID pVPtr, DWORD& dwData);
	bool UpdateData(DWORD dwKey, DWORD dwData);
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
};
