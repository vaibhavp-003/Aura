/*======================================================================================
FILE				: PolyHeuristics.h
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 23rd Feb 2017
NOTES				: This is detection module for malware depending on Heuristic rules from binary data.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
					Heuristic Detection of Trojan depending on Static Analysis and following Rules
					Rule 1 : Files with very HIGH File Version Nos. and NO (empty) company name / product name.
						e.g. 1.0.1680.45680 (etc). High chances of creation through build tools. 
					Rule 2 : File with Digital Signatures but NO (empty) company name / product name.
					Rule 3 : Files with only Integer value in Product name and Company Name.
=====================================================================================*/
#pragma once
#include "polybase.h"

typedef enum _VI_CP
{
	VI_CP_ASCII				= 0,	// 7-bit ASCII
	VI_CP_JAPAN				= 932,	// Japan (Shift - JIS X-0208)
	VI_CP_KOREA				= 949,	// Korea (Shift - KSC 5601)
	VI_CP_TAIWAN			= 950,	// Taiwan (Big5)
	VI_CP_UNICODE			= 1200,	// Unicode
	VI_CP_LATIN2			= 1250,	// Latin-2 (Eastern European)
	VI_CP_CYRILLIC			= 1251,	// Cyrillic
	VI_CP_MULTILNG			= 1252,	// Multilingual
	VI_CP_GREEK				= 1253,	// Greek
	VI_CP_TURKISH			= 1254,	// Turkish
	VI_CP_HEBREW			= 1255,	// Hebrew
	VI_CP_ARABIC			= 1256	// Arabic
} VI_CP;

typedef enum _VI_STR
{
	VI_STR_COMMENTS			= 0,	// Comments
	VI_STR_COMPANYNAME		= 1,	// CompanyName
	VI_STR_FILEDESCRIPTION	= 2,	// FileDescription
	VI_STR_FILEVERSION		= 3,	// FileVersion
	VI_STR_INTERNALNAME		= 4,	// InternalName
	VI_STR_LEGALCOPYRIGHT	= 5,	// LegalCopyright
	VI_STR_LEGALTRADEMARKS	= 6,	// LegalTrademarks
	VI_STR_ORIGINALFILENAME	= 7,	// OriginalFilename
	VI_STR_PRIVATEBUILD		= 8,	// PrivateBuild
	VI_STR_PRODUCTNAME		= 9,	// ProductName
	VI_STR_PRODUCTVERSION	= 10,	// ProductVersion
	VI_STR_SPECIALBUILD		= 11,	// SpecialBuild
	VI_STR_OLESELFREGISTER	= 12	// OLESelfRegister
} VI_STR;

class CPolyHeuristics :	public CPolyBase
{
	VS_FIXEDFILEINFO	m_vsffi;			// Fixed File Info (FFI)
	LPBYTE				m_lpbyVIB;		// Pointer to version info block (VIB)
	BOOL				m_bValid;		// Version info is loaded
	UINT				m_nTransCur;	// Current translation index
	UINT				m_nTransCnt;	// Translations count
	static LPCTSTR		s_ppszStr[ 13];	// String names
	LPDWORD				m_lpdwTrans;	// Pointer to translation array in m_lpbyVIB, LOWORD = LangID and HIWORD = CodePage

	BOOL				GetVersionInfo(IN LPCTSTR lpszFileName);
	BOOL				QueryStringValue(IN  LPCTSTR lpszItem, OUT LPTSTR  lpszValue, IN  INT    nBuf) const;
	BOOL				QueryStringValue(IN INT nIndex, OUT LPTSTR lpszValue, IN INT nBuf) const;
	BOOL				QueryVersionTrans(void);
	inline LANGID		GetCurLID(void)const;
	inline WORD			GetCurCP(void)const;
	inline LANGID		GetLIDByIndex(IN UINT nIndex)const;
	inline WORD			GetCPByIndex(IN UINT nIndex)const;
	BOOL				SetTrans(IN LANGID wLID = LANG_NEUTRAL, IN WORD wCP = VI_CP_UNICODE);
	BOOL				SetTransIndex(IN UINT nIndex = 0);
	INT					FindTrans(IN LANGID wLID, IN WORD wCP)const;
	DWORD				GetTransByIndex(IN UINT nIndex)const;
	inline UINT			GetCurTransIndex(void)const;

	bool GetCompanyName(LPCTSTR lpszFileName, LPTSTR lpszCompanyName);
	bool GetFileVersion(LPCTSTR lpszFileName, LPTSTR lpszFileDescription);//Shweta
	bool GetFileInternalName(LPCTSTR lpszFileName, LPTSTR lpszFileDescription);//Shweta
	bool GetFileDescription(LPCTSTR lpszFileName, LPTSTR lpszFileDescription);
	bool GetInternalNameofFile(LPCTSTR lpszFileName, LPTSTR lpszFileDescription);//Shweta Mulay
	bool GetProductVersion(LPCTSTR lpszFileName, LPTSTR lpszFileDescription);
	bool GetCopyRightInfo(LPCTSTR lpszFileName, LPTSTR lpszCopyWriteInfo);
	bool GetProductName(LPCTSTR lpszFileName, LPTSTR lpszProductName);
	bool GetProductComments(LPCTSTR lpszFileName, LPTSTR lpszProductName);
	bool HasVersionTab(LPCTSTR lpszFileName);

	BOOL	Open(IN LPCTSTR lpszFileName);
	void	Close(void);

	TCHAR	m_szCompanyName[MAX_PATH];
	TCHAR	m_szFileVersion[MAX_PATH];
	TCHAR	m_szFileInternalName[MAX_PATH];
	TCHAR	m_szFileDescription[MAX_PATH];
	TCHAR	m_szProductName[MAX_PATH];
	TCHAR	m_szProductVersion[MAX_PATH];
	TCHAR	m_szProductComment[MAX_PATH];
	TCHAR	m_szCopyRight[MAX_PATH];
	
	int		CheckForFileVersion();
	int		CheckForFakeCerWithNoVerTable();
	int		CheckForSuspProductName();

public:
	CPolyHeuristics(CMaxPEFile *pMaxPEFile);
	~CPolyHeuristics(void);

	int		DetectVirus();
	BOOL	m_bHasVerionTable;
	BOOL	m_bHasCertificateTable;
};

inline UINT CPolyHeuristics::GetCurTransIndex(void)const
{
	return m_nTransCur;
}

inline LANGID CPolyHeuristics::GetLIDByIndex(IN UINT nIndex)const
{
	return LOWORD(GetTransByIndex(nIndex));
}

inline WORD CPolyHeuristics::GetCPByIndex(IN UINT nIndex)const
{
	return HIWORD(GetTransByIndex(nIndex));
}

inline LANGID CPolyHeuristics::GetCurLID(void)const
{
	return GetLIDByIndex(GetCurTransIndex());
}

inline WORD CPolyHeuristics::GetCurCP(void)const
{
	return GetCPByIndex(GetCurTransIndex());
}

