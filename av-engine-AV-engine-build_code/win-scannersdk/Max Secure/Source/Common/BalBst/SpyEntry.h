
/*======================================================================================
FILE             : SpyEntry.h
ABSTRACT         : class declaration for 1 level binary tree of unsigned integer -> spy entry details
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
				  
CREATION DATE    : 26/April/2010
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "balbstopt.h"
#include "U2Info.h"

#pragma pack(1)
typedef struct _tagSpyData
{
	DWORD	dwIndexDB;
	WORD	eTypeOfEntry;
	SIZE_T	ulHive;
	DWORD	dwRegDataSize;
	DWORD	dwReplaceRegDataSize;
	WORD	wRegDataType;
	DWORD	dwSpywareID;
	BYTE	byStatus;
	BYTE	byChecked;
	BYTE	byThreatLevel;
	ULONG64	ul64DateTime;
	BYTE	byFix_Type;
	BYTE	byFix_Action;
	ULONG64 ulDate;
	DWORD	dwTime;
	LPTSTR	szDateTime;
	LPTSTR	szMachineName;
	LPTSTR	szMachineID;
	LPTSTR	szSpyName;
	LPTSTR	szKey;
	LPTSTR	szValue;
	LPTSTR	szBackupFileName;
	LPBYTE	byData;
	LPBYTE	byReplaceData;
}SPY_DATA, *LPSPY_DATA;
#pragma pack()

const int SIZE_OF_SPY_DATA = sizeof(SPY_DATA);

bool DateTimeForDB(ULONG64 ulDateTime64, ULONG64 &ulDate, DWORD &dwTime);
bool DateTimeForUI(ULONG64 ulDate, DWORD dwTime, LPTSTR szDateTime, SIZE_T cchDateTime);
bool DateTimeForUI(ULONG64 ulDateTime64, LPTSTR szDateTime, SIZE_T cchDateTime);
bool ReduceNoOfDays(ULONG64 &ulDate, ULONG64 ulDays);

class CSpyEntry : public CBalBSTOpt
{
public:
	CSpyEntry();
	virtual ~CSpyEntry();

	virtual void FreeKey(SIZE_T nKey);
	virtual void FreeData(SIZE_T nData);
	virtual COMPARE_RESULT Compare(SIZE_T nKey1, SIZE_T nKey2);
	bool AppendItem(DWORD dwKey, LPCTSTR szMachineID, LPCTSTR szMachineName, ULONG64 ulDate,
					DWORD dwTime, DWORD dwIndexDB, LPSPY_ENTRY_INFO lpSpyEntryInfo);
	bool AppendItemAscOrder(DWORD dwKey, LPCTSTR szMachineID, LPCTSTR szMachineName, ULONG64 ulDate,
							DWORD dwTime, DWORD dwIndexDB, LPSPY_ENTRY_INFO lpSpyEntryInfo);
	bool SearchItem(DWORD dwKey, LPSPY_DATA& lpSpyEntryInfo);
	bool GetKey(PVOID pVPtr, DWORD& dwKey);
	bool GetData(PVOID pVPtr, LPVOID& lpvData);
	bool SetBackupFileName(DWORD dwKey, LPCTSTR szBackupFileName);

	void DeleteData(LPSPY_DATA lpData);
	LPSPY_DATA GetData(LPCTSTR szMachineID, LPCTSTR szMachineName, ULONG64 ulDate,
						DWORD dwTime, DWORD dwIndexDB, LPSPY_ENTRY_INFO lpSpyEntryInfo);

	virtual bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	virtual bool Save(LPCTSTR szFileName, bool bEncryptContents = true);
	virtual bool AppendObject(CBalBSTOpt& objToAdd);
	virtual bool DeleteObject(CBalBSTOpt& objToDel);
};
