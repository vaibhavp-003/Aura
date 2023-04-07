/*======================================================================================
FILE             : FSDB.h
ABSTRACT         : file signature database handler class declaration file
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created in 2011 as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura. Hence, it may not be used, copied, 
				  reproduced, transmitted, or stored in any form or by any means, electronic,
				  recording, photocopying, mechanical or otherwise, without the prior written
				  permission of Aura.
				  
CREATION DATE    : 27 May 2011
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "BalBST.h"
#include "PtrStack.h"

const int iELEMENT_SIZE = 12;							//sizeof(ULONG64) + sizeof(DWORD)
const int iMAX_TEMP_FILE_SIZE = 600 * 1024 * 1024;		//size of temp file while creating database 
//Tushar ==> 27 Feb 2017 : Changes made to increase DB size from 450 MB to 600 MB

#define WRITE_BUF_SIZE	(1024 * 64)
#define MAX_DWORD64		((ULONG64)~(ULONG64)0)
#define MAX_DWORD32		((DWORD)~(DWORD)0)

const DWORD dwMAX_OMIT_SIG_CNT = 100;

#pragma pack(1)
typedef struct _tagSigTreeNode STNODE, *LPSTNODE;
struct _tagSigTreeNode
{
	ULONG64		ulSig;
	DWORD		dwSpy;
	LPSTNODE	pLeft;
	LPSTNODE	pRite;
};

typedef struct _tagElement
{
	ULONG64		ulSig;
	DWORD		dwSpy;
}ELMNT, *LPELMNT;

typedef struct _tagSignaturePage
{
	LPVOID		lpPagePtr;
	DWORD		dwUseSigs;
	DWORD		dwMaxSigs;
	DWORD		dwPageOff;
	DWORD		dwPageLen;
	ULONG64		ulFrstSig;
	ULONG64		ulLastSig;
}SIGPAGE, *LPSIGPAGE;
#pragma pack()

class CSigTree
{
public:
	CSigTree();
	virtual ~CSigTree();
	bool Add(ULONG64* pSig, DWORD* pSpy);
	bool AddAtEnd(ULONG64* pSig, DWORD* pSpy);
	bool Del(ULONG64* pSig);
	bool Search(ULONG64* pSig);
	bool GetSmallest(ULONG64* pSig, DWORD* pSpy);
	bool GetLarger(ULONG64* pSig, DWORD* pSpy);
	void RemoveAll();
	void Balance();

private:
	LPSTNODE GetNode(ULONG64* pSig, DWORD* pSpy);
	void FreeNode(LPSTNODE pNode);
	int FullSize(int size);
	void Compress(LPSTNODE pRoot, int count);
	void ConvertVineToTree(LPSTNODE pRoot, int size);
	void ConvertTreeToVine(LPSTNODE pRoot, int &size);

	LPSTNODE m_pRoot, m_pTemp, *m_ppNewNode, m_pParent;
	CPtrStack m_objPtrStk;
};

class CFSDB
{
public:
	CFSDB(int iMemToUseInMB = 4);
	virtual ~CFSDB();
	bool		m_bMapReadOnly, m_bModified, m_bDelEntry;
	CSigTree	m_objSigTree;

	bool SearchSig(PULONG64 pSig, LPDWORD pSpyID);
	bool AddAtEnd(PULONG64 pSig, LPDWORD pSpyID);

	bool GetFirst(PULONG64 pSig, LPDWORD pSpyID);
	bool GetNext(PULONG64 pSig, LPDWORD pSpyID);

	bool RemoveAll(bool bRemoveTree = true);
	bool IsModified();
	void Balance();

	bool Init();
	bool SetTempPath(LPCTSTR szTempPath);

	bool AppendObject(CFSDB& objToAdd);
	bool DeleteObject(CFSDB& objToDel);

	bool Load(LPCTSTR szFileName, bool bCheckVersion = true, bool bEncryptData = true, bool * pbDeleteIfFail = NULL);
	bool Save(LPCTSTR szFileName, bool bCheckVersion = true, bool bEncryptData = true);

private:
	
	LPSIGPAGE	m_pPgTbl;
	HANDLE		m_hFile, m_hMapping;
	TCHAR		m_szTempFilePath[MAX_PATH];
	DWORD		m_dwMaxPageSize, m_dwFileSize, m_dwPgTblArrCnt, m_dwPgTblCurIdx, m_dwCurIdxInPage;
	LPBYTE		m_byWriteBuffer64KB;
	DWORD		m_dwWriteBuffer64KBCurBytes;

	bool MakeTempFile();
	bool MakeMapFileObj(bool * pbErrorOpenFile = 0);
	bool MakePageTable();
	bool FreePageTable();
	bool MapPageOfTable(DWORD iPage);
	bool MakeSigIndex();
	bool Get(ULONG64* pSig, DWORD* pSpyID);
	bool Set(ULONG64* pSig, DWORD* pSpyID);
	bool MergeObject(CFSDB& objFSDB, bool bAdd);
	bool CreateMergerdMainFile(LPCTSTR szFileName);
	DWORD GetPosition(LPELMNT lpRecordSet, DWORD dwRecordCnt, ULONG64 ulSig);
	bool WriteBufferedData(HANDLE hFile, LPVOID lpBuffer, DWORD cbBuffer, bool bUseBuffer);
};
