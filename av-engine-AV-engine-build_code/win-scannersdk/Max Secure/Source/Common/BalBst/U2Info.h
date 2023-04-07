
/*======================================================================================
FILE             : U2Info .h
ABSTRACT         : class declaration for 1 level binary tree of unsigned integer -> information structure
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

#pragma pack(1)
typedef struct _tagInformation
{
	WORD	eTypeOfEntry;

	union
	{
		SIZE_T	ulHive;
		ULONG64 ulHivePad;
	};

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

	union
	{
		LPTSTR	szSpyName;
		ULONG64	ulSpyNamePad;
	};

	union
	{
		LPTSTR	szKey;
		ULONG64	ulKeyPad;
	};

	union
	{
		LPTSTR	szValue;
		ULONG64	ulValuePad;
	};

	union
	{
		LPTSTR	szBackupFileName;
		ULONG64	ulBackupFileNamePad;
	};

	union
	{
		LPBYTE	byData;
		ULONG64	ulDataPad;
	};

	union
	{
		LPBYTE	byReplaceData;
		ULONG64	ulReplaceDataPad;
	};
}SPY_ENTRY_INFO, *LPSPY_ENTRY_INFO;
#pragma pack()

#define SIZE_OF_STATIC_DATA				(sizeof(SPY_ENTRY_INFO) - (sizeof(ULONG64)*6))

//#pragma pack(1)
//typedef struct _tagSpywareEntryDetails
//{
//	DWORD	dwIndexDB;
//	WORD	eTypeOfEntry;
//	SIZE_T	ulHive;
//	DWORD	dwRegDataSize;
//	DWORD	dwReplaceRegDataSize;
//	WORD	wRegDataType;
//	DWORD	dwSpywareID;
//	BYTE	byStatus;
//	BYTE	byChecked;
//	BYTE	byThreatLevel;
//	ULONG64	ul64DateTime;
//	BYTE	byFix_Type;
//	BYTE	byFix_Action;
//	ULONG64 ulDate;
//	DWORD	dwTime;
//	TCHAR	szDateTime[50];
//	TCHAR	szMachineName[MAX_PATH];
//	TCHAR	szMachineID[MAX_PATH];
//	TCHAR	szSpyName[MAX_PATH];
//	TCHAR	szKey[MAX_PATH];
//	TCHAR	szValue[MAX_PATH];
//	TCHAR	szBackupFileName[MAX_PATH];
//	BYTE	byData[MAX_PATH*4];
//	BYTE	byReplaceData[MAX_PATH*4];
//}SPY_ENTRY_DETAIL, *LPSPY_ENTRY_DETAIL;
//#pragma pack()
//
//#define SIZE_OF_SPY_ENTRY_DETAIL sizeof(SPY_ENTRY_DETAIL)

bool DateTimeForDB(ULONG64 ulDateTime64, ULONG64 &ulDate, DWORD &dwTime);
bool DateTimeForUI(ULONG64 ulDate, DWORD dwTime, LPTSTR szDateTime, SIZE_T cchDateTime);
bool DateTimeForUI(ULONG64 ulDateTime64, LPTSTR szDateTime, SIZE_T cchDateTime);
bool ReduceNoOfDays(ULONG64 &ulDate, ULONG64 ulDays);

class CU2Info : public CBalBSTOpt
{

public:

	CU2Info(bool bIsEmbedded);
	virtual ~CU2Info();

	bool AppendItemAscOrder(DWORD dwKey, LPSPY_ENTRY_INFO lpSpyInfo);
	bool AppendItem(DWORD dwKey, LPSPY_ENTRY_INFO lpSpyInfo);
	bool DeleteItem(DWORD dwKey);
	bool SearchItem(DWORD dwKey, LPSPY_ENTRY_INFO& lpSpyInfo);
	bool UpdateItem(DWORD dwKey, LPSPY_ENTRY_INFO lpSpyInfo);

	bool GetKey(PVOID lpContext, DWORD& dwKey);
	bool GetData(PVOID lpContext, LPSPY_ENTRY_INFO& lpSpyInfo);

	bool AppendObject(CBalBSTOpt& objToAdd);
	bool DeleteObject(CBalBSTOpt& objToDel);
	bool CreateObject(CU2Info& objNewObject);
	bool SearchObject(CBalBSTOpt& objToSearch, bool bAllPresent = true);

	bool ReadU2In(SIZE_T nBaseAddress, LPBYTE& pData, PSIZE_T& pNode, DWORD& dwNodesMade);
	bool DumpU2In(HANDLE hFile, PNODEOPT pNode, DWORD& dwNodesCount);
	bool Load(LPCTSTR szFileName, bool bCheckVersion = true);
	bool Save(LPCTSTR szFileName, bool bEncryptContents = true);

private:

	virtual COMPARE_RESULT Compare(SIZE_T nKey1, SIZE_T nKey2);
	virtual void FreeKey(SIZE_T nKey);
	virtual void FreeData(SIZE_T nData);
	LPSPY_ENTRY_INFO DuplicateSpyInfo(LPSPY_ENTRY_INFO lpSpyInfo);
};
