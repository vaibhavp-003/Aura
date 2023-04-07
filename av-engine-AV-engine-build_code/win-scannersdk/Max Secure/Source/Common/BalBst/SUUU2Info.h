
/*======================================================================================
FILE             : SUUU2Info.h
ABSTRACT         : class declaration for 4 level binary tree of string -> uint64 -> uint -> uint -> info
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
#include "uuu2info.h"

class CSUUU2Info : public CBalBSTOpt
{

public:

	CSUUU2Info(bool bIsEmbedded);
	virtual ~CSUUU2Info();

	bool AppendItemAscOrder(LPCTSTR szKey, CUUU2Info& objUUU2Info);
	bool AppendItem(LPCTSTR szKey, CUUU2Info& objUUU2Info);
	bool DeleteItem(LPCTSTR szKey);
	bool SearchItem(LPCTSTR szKey, CUUU2Info& objUUU2Info);
	bool UpdateItem(LPCTSTR szKey, CUUU2Info& objUUU2Info);

	bool Balance();
	bool GetKey(PVOID lpContext, LPTSTR& dwKey);
	bool GetData(PVOID lpContext, CUUU2Info& objUUU2Info);

	bool AppendObject(CBalBSTOpt& objToAdd);
	bool DeleteObject(CBalBSTOpt& objToDel);
	bool CreateObject(CSUUU2Info& objNewObject);
	bool SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent = true);

	bool ReadSUUU2In(SIZE_T nBaseAddr, LPBYTE& pData, PSIZE_T& pNode, DWORD& dwNodesMade);
	bool DumpSUUU2In(HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount);
	bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFileName, bool bEncryptContents = true);

private:

	virtual COMPARE_RESULT Compare(SIZE_T nKey1, SIZE_T nKey2);
	virtual void FreeKey(SIZE_T nKey);
	virtual void FreeData(SIZE_T nData);
};
