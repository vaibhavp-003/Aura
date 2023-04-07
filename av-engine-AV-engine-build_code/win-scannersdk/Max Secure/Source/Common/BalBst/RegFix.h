
/*======================================================================================
FILE             : RegFix.h
ABSTRACT         : link list class for handling registry fix database
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
				  
CREATION DATE    : 5/30/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "BalBST.h"
#pragma pack(1)
typedef struct _tagRegistryFix
{
	DWORD	dwRegFixEntryID;
	DWORD	dwSpyNameID;
	BYTE	byFixAction;
	BYTE	byFixType;
	BYTE	byCommonForAll;
	DWORD	dwValueTypeID;
	BYTE	byHiveType;
	DWORD	dwDataPartSize;
	DWORD	dwFixValueSize;
	DWORD	dwValueForXPSize;
	DWORD	dwValueForVistaSize;
	DWORD	dwValueForWindows7Size;

	union
	{
		LPBYTE	pbyDataPart;
		ULONG64 DataPartPad;
	};

	union
	{
		LPBYTE	pbyFixValue;
		ULONG64 FixValuePad;
	};

	union
	{
		LPBYTE	pbyValueForXP;
		ULONG64  ValueForXPPad;
	};

	union
	{
		LPBYTE	pbyValueForVista;
		ULONG64  ValueForVistaPad;
	};

	union
	{
		LPBYTE	pbyValueForWindows7;
		ULONG64  ValueForWindows7Pad;
	};

	union
	{
		LPTSTR	szKeyPart;
		ULONG64 KeyPartPad;
	};

	union
	{
		LPTSTR	szValuePart;
		ULONG64 ValuePartPad;
	};

	union
	{
		struct _tagRegistryFix * pNext;
		ULONG64					 NextPad;
	};

} REGFIX, *PREGFIX;
#pragma pack()

#define SIZE_OF_NON_POINTER_DATA_REG_FIX	(sizeof(REGFIX) -(sizeof(ULONG64)*8))

class CRegFix
{
public:

	CRegFix();
	virtual ~CRegFix();
	bool Add(const REGFIX& RegFixData);
	bool Delete(DWORD dwRegFixEntryID);
	bool Search(REGFIX& RegFixData);
	bool GetFirst(REGFIX& RegFixData);
	bool GetNext(REGFIX& RegFixData);
	bool RemoveAll();
	bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFileName, bool bEncryptContents = true);
	UINT GetCount();
	bool AppendObject(CRegFix& objToAdd);
	bool DeleteObject(CRegFix& objToDel);
	bool SearchObject(CRegFix& objToSearch, bool bAllPresent = true);

protected:

	PREGFIX		m_pHead;
	PREGFIX		m_pCurr;
	LPBYTE		m_byBuffer;
	DWORD		m_nBufferSize;

private:

	bool DeleteData(PREGFIX& pNode);
	PREGFIX GetNode(const REGFIX& RegFixData);
};
