/*======================================================================================
FILE             : WhiteSigDBManager.h
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
NOTES		     : Wrapper to handle SD44 White Databases (Small, Delete)
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "FSDB.h"

//const int iNEW_SIG_SIZE = 6;
//Ravi ==> Shift to common place
typedef struct _SMALL_WHITE_SIG_DB_ARRAY
{
	CFSDB		objMaxPESig;
	DWORD		dwVersion;
}WHITESIGDBARRAY,*pWHITESIGDBARRAY;

class CWhiteSigDBManager
{
	//CFSDB m_arrStaticBlackDB[16];
	//CFSDB m_arrNewBlackDB[16];
	WHITESIGDBARRAY			**m_pDbArray;
	WHITESIGDBARRAY			**m_pDeleteDBArray;
	DWORD					m_dwSmallDBCnt;
	DWORD					m_dwDeleteDBCnt;
	CFSDB					m_WhiteFilePESig;
	DWORD					m_dwFirstSmallDBVer;
	DWORD					m_dwFirstDeleteDBVer;
	
	DWORD	GetSignatureIndex(unsigned char *pszSig);

	DWORD	GetSmallDBCount(LPCTSTR pszDBFolderName);
	DWORD	GetDeleteDBCount(LPCTSTR pszDBFolderName);

	DWORD	LoadSmallDBs(LPCTSTR pszDBFolderName, bool bCheckVersion, bool bEncryptData, bool * pbDeleteIfFail);
	DWORD	LoadDeleteDBs(LPCTSTR pszDBFolderName, bool bCheckVersion, bool bEncryptData, bool * pbDeleteIfFail);

	bool	CreateSmallDBArray();	
	bool	CreateDeleteDBArray();

	bool	SearchSigInSmallDs(PULONG64 pSig2Search, LPDWORD pSpyID, DWORD	dwLocalVer = 0x00, bool *pbFoundInDelete = NULL);
	bool	SearchSigInDeleteDbs(PULONG64 pSig2Search, LPDWORD pSpyID, DWORD dwSigMatchVer = 0x00);

	DWORD	GetSD44Ver(LPCTSTR pszFileName);
	void	RemoveSmallDBs();

public:
	CWhiteSigDBManager();
	~CWhiteSigDBManager();
	
	bool Load(LPCTSTR szFolderName, bool bCheckVersion = true, bool bEncryptData = true, bool * pbDeleteIfFail = NULL);
	//bool Save(LPCTSTR szFolderName, bool bCheckVersion = true, bool bEncryptData = true);
	bool RemoveAll(bool bRemoveTree = true);
	bool SearchSig(PULONG64 pSig, LPDWORD pSpyID,DWORD	dwLocalVer = 0x00);

	//bool AppendObject(CMaxNewPESig& objToAdd);
	//bool AppendObject(CFSDB& objToAdd);
	//bool DeleteObject(CFSDB& objToDel);
	//bool DeleteObject(CMaxNewPESig& objToDel);

	//bool IsModified();
	//void Balance();

	DWORD	GetHeighestVersion();
};