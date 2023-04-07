
/*======================================================================================
FILE             : UU2Info .h
ABSTRACT         : class declaration for 2 level binary tree of uint -> uint -> information structure
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
#include "u2info.h"

class CUU2Info : public CBalBSTOpt
{

public:

	CUU2Info(bool bIsEmbedded);
	virtual ~CUU2Info();

	bool AppendItemAscOrder(DWORD dwKey, CU2Info& objU2Info);
	bool AppendItem(DWORD dwKey, CU2Info& objU2Info);
	bool DeleteItem(DWORD dwKey);
	bool SearchItem(DWORD dwKey, CU2Info& objU2Info);
	bool UpdateItem(DWORD dwKey, CU2Info& objU2Info);

	bool Balance();
	bool GetKey(PVOID lpContext, DWORD& dwKey);
	bool GetData(PVOID lpContext, CU2Info& objU2Info);

	bool AppendObject(CBalBSTOpt& objToAdd);
	bool DeleteObject(CBalBSTOpt& objToDel);
	bool CreateObject(CUU2Info& objNewObject);
	bool SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent = true);

	bool ReadUU2In(SIZE_T nBaseAddr, LPBYTE& pData, PSIZE_T& pNode, DWORD& dwNodesMade);
	bool DumpUU2In(HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount);
	bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFileName, bool bEncryptContents = true);

private:

	virtual COMPARE_RESULT Compare(SIZE_T nKey1, SIZE_T nKey2);
	virtual void FreeKey(SIZE_T nKey);
	virtual void FreeData(SIZE_T nData);
};
