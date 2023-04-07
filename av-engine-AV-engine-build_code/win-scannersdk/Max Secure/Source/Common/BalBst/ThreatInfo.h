
/*======================================================================================
FILE             : ThreatInfo.h
ABSTRACT         : declares class to handle database type of threat info(threat name)
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
				  
CREATION DATE    : 11/Aug/2010
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include <io.h>
#include <time.h>
#include "BalBST.h"
#include "S2UA.h"
#include "U2SA.h"
#include "BufferToStructure.h"

const WORD	MAX_THRT_NAME	= 100;
const WORD	MAX_CATE_NAME	= 50;
const WORD	MAX_CATE_DESC	= 1024;
const WORD	MAX_VRNT_NAME	= 5;

const TCHAR FILE_CAT[] = _T(".CT");
const TCHAR FILE_NAM[] = _T(".NM");
const TCHAR FILE_ID[]  = _T(".ID");

#pragma pack(1)
typedef struct _tagThreatInfo
{
	DWORD	dwThrtID;
	DWORD	dwCateID;
	DWORD	dwNameID;
	CHAR	szVariant[MAX_VRNT_NAME];
	BYTE	byThreatLevel;
}THREAT_INFO, *PTHREAT_INFO, *LPTHREAT_INFO;

typedef struct _tagCategoryInfo
{
	CHAR	szName[MAX_CATE_NAME];
	CHAR	szDesc[MAX_CATE_DESC];
}CATE_INFO, *PCATE_INFO, *LPCATE_INFO;
#pragma pack()

class CThreatInfo
{
public:
	CThreatInfo(bool bForUpdate = false);
	virtual ~CThreatInfo();

	bool AppendItem(DWORD dwSpyID, LPCTSTR szSpyName, DWORD dwCatID, LPCTSTR szCatName, BYTE byThreatLevel,
					LPCTSTR szThreatDescription);
	bool SearchItem(DWORD dwKey, BYTE& byThreatLevel, LPTSTR szThreatDescription, SIZE_T cchThreatDescription,
					LPTSTR szThreatName, SIZE_T cchThreatName);
	DWORD GetCount();
	bool RemoveAll();
	bool IsLoaded();
	bool IsModified();
	bool Balance();
	bool AddDBFile(LPCTSTR szFullFileName);
	bool DelDBFile(LPCTSTR szFullFileName);
	bool Save(LPCTSTR szFilePath, bool bEncryptContents = true);
	bool Load(LPCTSTR szFilePath, bool bEncryptContents = true, bool bCheckVersion = true, bool bCheckIntegrity = true);
	bool SetTempPath(LPCTSTR szTempPath);
	bool PrepareFileNames(LPCTSTR szFilePath, LPTSTR szCateFileName, DWORD cchCateFileName, LPTSTR szNameFileName,
							DWORD cchNameFileName, LPTSTR szIDFileName, DWORD cchIDFileName);

private:

	HANDLE				m_hFile, m_hMMapFile;
	DWORD				m_dwCount, m_dwNameID;
	CHAR				m_szCate[MAX_CATE_NAME];
	CHAR				m_szName[MAX_THRT_NAME];
	CHAR				m_szVrnt[MAX_VRNT_NAME];
	TCHAR				m_szCateT[MAX_CATE_NAME];
	TCHAR				m_szNameT[MAX_THRT_NAME];
	TCHAR				m_szVrntT[MAX_VRNT_NAME];
	TCHAR				m_szTempFileName[MAX_PATH];
	TCHAR				m_szTempFilePath[MAX_PATH];
	CS2UA				m_objNameDB;
	CU2SA				m_objIDDB;
	CBufferToStructure	m_objCateDB;
	bool				m_bModified;
	bool				m_bTempFile;
	bool				m_bForUpdate;
	DWORD				m_dwHdrSize;
	THREAT_INFO			m_ThreatInfo;

	HANDLE CreateTempFile();
	bool GenerateTempFileName();
	bool CleanupTempFiles(LPCTSTR szFolderPath, LPCTSTR szWildCard);
	bool AddThreatEntry(LPTHREAT_INFO lpThreatInfo);
	bool GetItemByIndex(DWORD dwIndex, LPTHREAT_INFO lpThreatInfo);
	bool SplitThreatName(LPCTSTR szCatName, LPCTSTR szSpyName);
	bool ConvertU2A(LPSTR szAnsi, SIZE_T cchAnsi, LPCTSTR szUnicode);
	bool ConvertA2U(LPTSTR szUnicode, SIZE_T cchUnicode, LPCSTR szAnsi);
	bool ConvertU2A_MEM(LPSTR szAnsi, SIZE_T cchAnsi, LPCTSTR szUnicode, SIZE_T cchUnicode);
	bool PrepareEntry(LPTHREAT_INFO lpEntry, DWORD dwSpyID, DWORD dwCatID, BYTE byTLevel, LPCTSTR szTDesc);
	bool GetDataByID(LPTHREAT_INFO lpThreatInfo, BYTE& byTL, LPTSTR szCName, DWORD cchCName,
						LPTSTR szTName, DWORD cchTName, LPTSTR szTDesc, DWORD cchTDesc);
};
