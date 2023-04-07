
/*======================================================================================
FILE             : RemoveDB.h
ABSTRACT         : linklist class for remove database
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
				  
CREATION DATE    : 5/25/2009
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "BalBST.h"
#pragma pack(1)
typedef struct _tagSystemObject						//Should be same as _tagSystemObject_FIXEDSIZE
{
	LONG						iIndex;
	UINT64						u64DateTime;
	DWORD						dwType;
	ULONG64						ulptrHive;
	DWORD						dwRegDataSize;
	DWORD						dwReplaceRegDataSize;
	WORD						wRegDataType;
	BYTE						bDeleteThis;
	DWORD						dwSpywareID;

	union
	{
		LPTSTR					szKey;
		ULONG64					KeyPad;
	};

	union
	{
		LPTSTR					szValue;
		ULONG64					ValuePad;
	};

	union
	{
		LPBYTE					byData;
		ULONG64					DataPad;
	};

	union
	{
		LPBYTE					byReplaceData;
		ULONG64					ReplaceDataPad;
	};

	union
	{
		LPTSTR					szBackupFileName;
		ULONG64					backupFileNamePad;
	};

	union
	{
		struct _tagSystemObject*	pNext;
		ULONG64						NextPad;
	};

} SYS_OBJ, *PSYS_OBJ;								//Should be same as SYS_OBJ_FIXEDSIZE
typedef struct _tagSystemObject_FIXEDSIZE			//Should be same as _tagSystemObject
{
	LONG		iIndex;
	UINT64		u64DateTime;
	DWORD		dwType;
	ULONG64		ulptrHive;
	DWORD		dwRegDataSize;
	DWORD		dwReplaceRegDataSize;
	WORD		wRegDataType;
	BYTE		bDeleteThis;
	DWORD		dwSpywareID;
	TCHAR		szKey[MAX_PATH];
	TCHAR		szValue[MAX_PATH];
	BYTE		byData[MAX_PATH*4];
	BYTE		byReplaceData[MAX_PATH*4];
	TCHAR		szBackupFileName[MAX_PATH];
} SYS_OBJ_FIXEDSIZE, *PSYS_OBJ_FIXEDSIZE;			//Should be same as SYS_OBJ
#pragma pack()

#define SIZE_OF_NON_POINTER_DATA_SYS_OBJ	(sizeof(SYS_OBJ) -(sizeof(ULONG64)*6))

class CRemoveDB
{

public:

	CRemoveDB ();
	virtual ~CRemoveDB ();

	bool Add(SYS_OBJ& SystemObject);
	bool Delete(LONG iIndex);
	bool GetFirst(SYS_OBJ& SystemObject);
	bool GetNext(SYS_OBJ& SystemObject);
	bool SetDeleteFlag(LONG iIndex, bool bDeleteFlag);
	bool DeleteAllMarkedEntries ();
	bool Search(SYS_OBJ& SystemObject);
	bool RemoveAll ();
	bool Save(LPCTSTR szFileName);
	bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	UINT GetCount ();

	bool IsModified()
	{
		return m_bTreeModified;
	}
protected:

	PSYS_OBJ	m_pHead;
	PSYS_OBJ	m_pCurr;
	LPBYTE		m_byBuffer;
	DWORD		m_nBufferSize;

private:

	static LPTSTR m_szGenericName;
	bool m_bTreeModified;
	bool DeleteData(PSYS_OBJ& pNode);
	LPVOID GetNode(const SYS_OBJ& SystemObject);
};
