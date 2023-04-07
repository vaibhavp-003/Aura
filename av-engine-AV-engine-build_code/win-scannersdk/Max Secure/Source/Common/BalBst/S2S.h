
/*======================================================================================
FILE             : S2S.h
ABSTRACT         : tree class to handle databse of type string -> string
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

class CS2S : public CBalBST
{

public:

	CS2S(bool bIsEmbedded, bool bIgnoreCase = false);
	virtual ~CS2S();
	bool AppendItemAscOrder(LPCTSTR szKey, LPCTSTR szData);
	bool AppendItem(LPCTSTR szKey, LPCTSTR szData);
	bool DeleteItem(LPCTSTR szKey);
	bool SearchItem(LPCTSTR szKey, LPTSTR& szData);
	DWORD GetFileLength(DWORD * pdwHigh);
	bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, LPTSTR& pStr);
	bool GetData(PVOID pVPtr, LPTSTR& szData);
	bool AppendObject(CBalBST& objToAdd);
	bool DeleteObject(CBalBST& objToDel);

private:

	bool m_bIgnoreCase;
	DWORD m_dwFileLenH, m_dwFileLenL;

	virtual COMPARE_RESULT Compare(ULONG64 dwKey1, ULONG64 dwKey2);
	virtual void FreeKey(ULONG64 dwKey);
	virtual void FreeData(ULONG64 dwData);
};
