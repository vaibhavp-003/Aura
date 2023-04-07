/*======================================================================================
FILE             : BlackDBManager.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Tushar Kadam
COMPANY		     : Aura
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 10th May 2016
NOTES		     : Wrapper to handle SD43 Databases (Splited, Small, Delete)
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "FSDB.h"
#include "MaxNewPESig.h"
#include "MaxSmallPESig.h"
#include "MaxQSort.h"

#define SD_DB_FS_BLK_0			_T("SD43_0.DB")
#define SD_DB_FS_BLK_1			_T("SD43_1.DB")
#define SD_DB_FS_BLK_2			_T("SD43_2.DB")
#define SD_DB_FS_BLK_3			_T("SD43_3.DB")
#define SD_DB_FS_BLK_4			_T("SD43_4.DB")
#define SD_DB_FS_BLK_5			_T("SD43_5.DB")
#define SD_DB_FS_BLK_6			_T("SD43_6.DB")
#define SD_DB_FS_BLK_7			_T("SD43_7.DB")
#define SD_DB_FS_BLK_8			_T("SD43_8.DB")
#define SD_DB_FS_BLK_9			_T("SD43_9.DB")
#define SD_DB_FS_BLK_A			_T("SD43_A.DB")
#define SD_DB_FS_BLK_B			_T("SD43_B.DB")
#define SD_DB_FS_BLK_C			_T("SD43_C.DB")
#define SD_DB_FS_BLK_D			_T("SD43_D.DB")
#define SD_DB_FS_BLK_E			_T("SD43_E.DB")
#define SD_DB_FS_BLK_F			_T("SD43_F.DB")

//const int iNEW_SIG_SIZE = 6;
//Ravi ==> Shift to common place
typedef struct _SMALL_DB_ARRAY
{
	CMaxNewPESig	objMaxPESig;
	DWORD			dwVersion;
}DBARRAY,*pDBARRAY;

class CBlackDBManager
{
	//CFSDB m_arrStaticBlackDB[16];
	//CFSDB m_arrNewBlackDB[16];
	CMaxNewPESig	m_arrStaticBlackDB[0x10];
	CMaxNewPESig	m_arrNewBlackDB[0x10]; //No Nead We Can Remove It.

	DBARRAY			**m_pDbArray;
	DBARRAY			**m_pDeleteDBArray;

	DWORD			m_dwSmallDBCnt;
	DWORD			m_dwDeleteDBCnt;

	DWORD			m_dwFirstSmallDBVer;
	DWORD			m_dwFirstDeleteDBVer;
	
	DWORD	GetSignatureIndex(unsigned char *pszSig);
	//int GetSignatureIndex(PULONG64 pSig);
	bool	MergeObject(CFSDB& objFSDB, bool bAdd);
	bool	MergeObject(CMaxNewPESig& objToAdd, bool bAdd);

	DWORD	GetSmallDBCount(LPCTSTR pszDBFolderName);
	DWORD	GetDeleteDBCount(LPCTSTR pszDBFolderName);

	DWORD	LoadSmallDBs(LPCTSTR pszDBFolderName, bool bCheckVersion, bool bEncryptData, bool * pbDeleteIfFail);
	DWORD	LoadDeleteDBs(LPCTSTR pszDBFolderName, bool bCheckVersion, bool bEncryptData, bool * pbDeleteIfFail);

	bool	CreateSmallDBArray();
	bool	CreateDeleteDBArray();

	bool	SearchSigInSmallDs(PULONG64 pSig2Search, LPDWORD pSpyID, DWORD	dwLocalVer = 0x00, bool *pbFoundInDelete = NULL);
	bool	SearchSigInDeleteDbs(PULONG64 pSig2Search, LPDWORD pSpyID, DWORD dwSigMatchVer = 0x00);

	DWORD	GetSD43Ver(LPCTSTR pszFileName);
	void	RemoveSmallDBs();

public:
	CBlackDBManager();
	~CBlackDBManager();
	
	bool Load(LPCTSTR szFolderName, bool bCheckVersion = true, bool bEncryptData = true, bool * pbDeleteIfFail = NULL);
	bool Save(LPCTSTR szFolderName, bool bCheckVersion = true, bool bEncryptData = true);
	bool RemoveAll(bool bRemoveTree = true);
	bool SearchSig(PULONG64 pSig, LPDWORD pSpyID,DWORD	dwLocalVer = 0x00);

	bool AppendObject(CMaxNewPESig& objToAdd);
	bool AppendObject(CFSDB& objToAdd);
	bool DeleteObject(CFSDB& objToDel);
	bool DeleteObject(CMaxNewPESig& objToDel);

	bool IsModified();
	void Balance();

	DWORD	GetHeighestVersion();
	//Remider Foe Ravi : Remove this variable
	//TCHAR	szLogLine[1024];
};