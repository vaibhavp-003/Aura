/*======================================================================================
FILE             : S2U.h
ABSTRACT         : tree class to handle databse of type string -> ulong
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

class CS2U : public CBalBST
{
public:

	CS2U(bool bIsEmbedded, bool bIgnoreCase = false);
	virtual ~CS2U();

	bool AppendItemAscOrder(LPCTSTR szKey, DWORD dwData);
	bool AppendItem(LPCTSTR szKey, DWORD dwData);
	bool DeleteItem(LPCTSTR szKey);
	bool SearchItem(LPCTSTR szKey, DWORD * pulData);
	bool Load(LPCTSTR szFullFileName, bool bCheckVersion = true);
	bool Load(LPCTSTR szFullFileName, bool bCheckVersion, bool bCheckFileIntegrity);
	bool Save(LPCTSTR szFullFileName, bool bEncryptContents = true);
	bool GetKey(PVOID pVPtr, LPTSTR& pStr);
	bool GetData(PVOID pVPtr, DWORD& dwData);
	bool CopyContents(CS2U& objNewCopy);
	bool AppendObject(CBalBST& objToAdd);
	bool DeleteObject(CBalBST& objToDel);
	bool SearchObject(CBalBST& objToSearch, bool bAllPresent = true);
	bool UpdateItem(PVOID pVPtr, ULONG64 ulData);
	bool UpdateData(LPCTSTR szKey, DWORD dwData);
	bool LoadByVer(LPCTSTR szFileName, bool bCheckVersion = true, LPCSTR szVersion = "123456abcdef123456");
	bool SaveByVer(LPCTSTR szFileName, bool bEncryptContents = true, LPCSTR szVersion = "123456abcdef123456");

private:

	CHAR	m_szVersion[19];
	bool	m_bCheckFileIntegrity;
	bool	m_bIgnoreCase;

	virtual COMPARE_RESULT Compare(ULONG64 dwKey1, ULONG64 dwKey2);
	virtual void FreeKey(ULONG64 dwKey);
	virtual void FreeData(ULONG64 dwData);
};
