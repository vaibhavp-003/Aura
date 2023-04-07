
/*======================================================================================
FILE             : BufferToStructure.h
ABSTRACT         : class declaration for 1 level binary tree of buffer -> structure
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
				  
CREATION DATE    : 6/26/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "balbstopt.h"

class CBufferToStructure : public CBalBSTOpt
{

public:

	CBufferToStructure(bool bIsEmbedded, DWORD dwSizeOfKey, DWORD dwSizeOfData, int iNumberSize = 0);
	virtual ~CBufferToStructure();

	bool AppendItemAscOrder(LPVOID lpvKey, LPVOID lpvData);
	bool AppendItem(LPVOID lpvKey, LPVOID lpvData);
	bool DeleteItem(LPVOID lpvKey);
	bool SearchItem(LPVOID lpvKey, LPVOID& lpvData);
	bool UpdateItem(LPVOID lpvKey, LPVOID lpvData);

	bool GetKey(PVOID pVPtr, LPVOID& lpvKey);
	bool GetData(PVOID pVPtr, LPVOID& lpvData);

	bool AppendObject(CBalBSTOpt& objToAdd);
	bool DeleteObject(CBalBSTOpt& objToDel);
	bool CreateObject(CBufferToStructure& objNewObject);
	bool SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent = true);

	bool ReadB2St(LPBYTE& ptrData, PSIZE_T& ptrNode, LPBYTE byBuffer, DWORD cbBuffer);
	bool DumpB2St(HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount, DWORD dwKeyLen, DWORD dwDataLen);
	bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	bool Load_NoNameCheck(LPCTSTR szFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFileName, bool bEncryptContents = true);
	bool LoadByVer(LPCTSTR szFileName, bool bCheckVersion = true, LPCSTR szVersion = "123456abcdef123456");
	bool SaveByVer(LPCTSTR szFileName, bool bEncryptContents = true, LPCSTR szVersion = "123456abcdef123456");

private:

	DWORD	m_dwSizeOfKey;
	DWORD	m_dwSizeOfData;
	bool	m_bByte;
	bool	m_bWord;
	bool	m_bDword;
	bool	m_bQword;
	CHAR	m_szVersion[19];
	bool	m_bCheckName;

	virtual COMPARE_RESULT Compare(SIZE_T nKey1, SIZE_T nKey2);
	virtual void FreeKey(SIZE_T nKey);
	virtual void FreeData(SIZE_T nData);
};

