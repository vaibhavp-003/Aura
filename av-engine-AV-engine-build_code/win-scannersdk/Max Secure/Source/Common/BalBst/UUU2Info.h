
/*======================================================================================
FILE             : UUU2Info.h
ABSTRACT         : class declaration for 3 level binary tree of uint64 -> uint -> uint -> info structure
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
				  
CREATION DATE    : 27/April/2010
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "balbstopt.h"
#include "uu2info.h"

class CUUU2Info : public CBalBSTOpt
{

public:

	CUUU2Info(bool bIsEmbedded);
	virtual ~CUUU2Info();

	bool AppendItemAscOrder(ULONG64 ulKey, CUU2Info& objUU2Info);
	bool AppendItem(ULONG64 ulKey, CUU2Info& objUU2Info);
	bool DeleteItem(ULONG64 ulKey);
	bool SearchItem(ULONG64 ulKey, CUU2Info& objUU2Info);
	bool UpdateItem(ULONG64 ulKey, CUU2Info& objUU2Info);

	bool Balance();
	bool GetKey(PVOID lpContext, ULONG64& ulKey);
	bool GetData(PVOID lpContext, CUU2Info& objUU2Info);

	bool AppendObject(CBalBSTOpt& objToAdd);
	bool DeleteObject(CBalBSTOpt& objToDel);
	bool CreateObject(CUUU2Info& objNewObject);
	bool SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent = true);

	bool ReadUUU2In(SIZE_T nBaseAddr, LPBYTE& pData, PSIZE_T& pNode, DWORD& dwNodesMade);
	bool DumpUUU2In(HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount);
	bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFileName, bool bEncryptContents = true);

private:

	virtual COMPARE_RESULT Compare(SIZE_T nKey1, SIZE_T nKey2);
	virtual void FreeKey(SIZE_T nKey);
	virtual void FreeData(SIZE_T nData);
};
