/*======================================================================================
FILE             : VerInfo.h
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 24-Feb-2006
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
#ifndef __VERINFO_H__
#define __VERINFO_H__

#include <afx.h>
#include <commdlg.h>

#if defined(_MSC_VER) &&(_MSC_VER >= 1020)
#pragma once
#endif

#ifndef	_INC_SHLWAPI
#include < Shlwapi.h >
#endif
#pragma comment(lib, "shlwapi.lib")

#ifndef VER_H
#include < WinVer.h >
#endif
#pragma comment(lib, "Version.lib ")

#ifndef _T
#ifndef _INC_TCHAR
#include < TChar.h >
#endif
#endif

#ifndef	ASSERT
#ifndef _INC_CRTDBG
#include < CrtDbg.h >
#endif
#define ASSERT(x)			_ASSERTE(x)
#endif


//#define _wslPackVersion(major, minor)		MAKELONG(minor, major)

#ifndef _free
#define _free(p) {if(p != NULL){ free(p); p = NULL;}}
#endif

#ifndef ASSERT_RETURN
#define ASSERT_RETURN(x) { ASSERT(0); return x;}
#endif

#ifndef DLLVER_MAJOR_MASK

typedef struct _DLLVERSIONINFO2
{
	DLLVERSIONINFO	info1;
	DWORD			dwFlags;// No flags currently defined
	ULONGLONG		ullVersion;
} DLLVERSIONINFO2;

#endif // DLLVER_MAJOR_MASK

#ifndef MAKEDLLVERULL

#define MAKEDLLVERULL(major, minor, build, qfe)\
	(((ULONGLONG)(major)<< 48)|			 \
	(  (ULONGLONG)(minor)<< 32)|			 \
	(  (ULONGLONG)(build)<< 16)|			 \
	(  (ULONGLONG)( qfe)<<  0))

#endif // MAKEDLLVERULL

STDAPI_(HRESULT)DllGetVersion(IN HMODULE hModule, OUT DLLVERSIONINFO* lpDVI);

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

/*
HIWORD(m_vsffi.dwFileVersionMS)
LOWORD(m_vsffi.dwFileVersionMS)
HIWORD(m_vsffi.dwFileVersionLS)
LOWORD(m_vsffi.dwFileVersionLS)
*/

typedef struct tagMAP
{
	DWORD		dwVal;
	LPCTSTR		lpszVal;
} MAP;


class CFileVersionInfo
{
public:	// Construction/destruction:

	CFileVersionInfo(void);
	virtual ~CFileVersionInfo(void);

public:	// Implementation:

	BOOL	Open(IN LPCTSTR lpszFileName);
	BOOL	Open(IN HINSTANCE hInstance);
	void	Close(void);

	BOOL	QueryStringValue(IN LPCTSTR lpszString, OUT LPTSTR lpszValue, IN INT nBuf)const;
	BOOL	QueryStringValue(IN INT nIndex, OUT LPTSTR lpszValue, IN INT nBuf)const;
	LPCTSTR	GetVerStringName(IN INT nIndex);

	BOOL	SetTrans(IN LANGID wLID = LANG_NEUTRAL, IN WORD wCP = VI_CP_UNICODE);
	BOOL	SetTransIndex(IN UINT nIndex = 0);
	INT		FindTrans(IN LANGID wLID, IN WORD wCP)const;
	DWORD	GetTransByIndex(IN UINT nIndex)const;

	bool Is3264BitApp(LPCTSTR szFileName);

	bool HasVersionTab(LPCTSTR lpszFileName);
	bool GetCompanyName(LPCTSTR lpszFileName, LPTSTR lpszCompanyName);
	bool GetLegalCopyright(LPCTSTR lpszFileName, LPTSTR lpszCompanyName);
	bool GetFileInternalName(LPCTSTR lpszFileName, LPTSTR lpszFileDescription);//Shweta
	bool GetFileDescription(LPCTSTR lpszFileName, LPTSTR lpszFileDescription);
	bool DoTheVersionJob(LPCTSTR csFileName, bool bDeleteFile);
	bool CheckNotifyEntry(bool bDeleteFile);
	bool GetInternalNameofFile(LPCTSTR lpszFileName, LPTSTR lpszFileDescription);//Shweta Mulay
	bool GetProductVersion(LPCTSTR lpszFileName, LPTSTR lpszFileDescription);
	//sandip added  07-3-2007
	bool GetProductName(LPCTSTR lpszFileName, LPTSTR lpszProductName);

public: // Static members:

	static BOOL		GetLIDName(IN WORD wLID, OUT LPTSTR lpszName, IN INT nBuf);
	static BOOL		GetCPName(IN WORD wCP, OUT LPCTSTR* ppszName);
	//static DWORD	InstallFile(void);

public: // Inline members

	inline const	VS_FIXEDFILEINFO& GetVSFFI(void)const;
	inline BOOL		IsValid(void)const;

	inline WORD		GetFileVersionMajor(void)const;
	inline WORD		GetFileVersionMinor(void)const;
	inline WORD		GetFileVersionBuild(void)const;
	inline WORD		GetFileVersionQFE(void) const;

	inline WORD		GetProductVersionMajor(void)const;
	inline WORD		GetProductVersionMinor(void)const;
	inline WORD		GetProductVersionBuild(void)const;
	inline WORD		GetProductVersionQFE(void) const;

	inline UINT		GetTransCount(void)const;
	inline UINT		GetCurTransIndex(void)const;
	inline LANGID	GetLIDByIndex(IN UINT nIndex)const;
	inline WORD		GetCPByIndex(IN UINT nIndex)const;
	inline DWORD	GetCurTrans(void)const;
	inline LANGID	GetCurLID(void)const;
	inline WORD		GetCurCP(void)const;

protected:

	BOOL	GetVersionInfo(IN LPCTSTR lpszFileName);
	BOOL	QueryVersionTrans(void);
	bool	ReplaceFileOnRestart(TCHAR const * szExistingFileName, TCHAR const * szNewFileName);

protected: // Members variables

	static LPCTSTR	 s_ppszStr[ 13];	// String names
	VS_FIXEDFILEINFO m_vsffi;			// Fixed File Info (FFI)

	LPBYTE		m_lpbyVIB;		// Pointer to version info block (VIB)
	LPDWORD		m_lpdwTrans;	// Pointer to translation array in m_lpbyVIB, LOWORD = LangID and HIWORD = CodePage
	UINT		m_nTransCur;	// Current translation index
	UINT		m_nTransCnt;	// Translations count
	BOOL		m_bValid;		// Version info is loaded

protected: //static
	static LPCTSTR	s_lpszFVI[ 7];
	static MAP		s_lpVOS[ 14];
	static MAP		s_lpFILT[ 7];
	static MAP		s_lpFNTT[ 4];
	static MAP		s_lpDRVT[ 12];
};

inline BOOL CFileVersionInfo::IsValid(void)const
{
	return m_bValid;
}

inline const VS_FIXEDFILEINFO& CFileVersionInfo::GetVSFFI(void)const
{
	return m_vsffi;
}

inline WORD CFileVersionInfo::GetFileVersionMajor(void)const
{
	ASSERT(m_bValid);
	return HIWORD(m_vsffi.dwFileVersionMS);
}

inline WORD CFileVersionInfo::GetFileVersionMinor(void)const
{
	ASSERT(m_bValid);
	return LOWORD(m_vsffi.dwFileVersionMS);
}

inline WORD CFileVersionInfo::GetFileVersionBuild(void)const
{
	ASSERT(m_bValid);
	return HIWORD(m_vsffi.dwFileVersionLS);
}

inline WORD CFileVersionInfo::GetFileVersionQFE(void)const
{
	ASSERT(m_bValid);
	return LOWORD(m_vsffi.dwFileVersionLS);
}

inline WORD CFileVersionInfo::GetProductVersionMajor(void)const
{
	ASSERT(m_bValid);
	return HIWORD(m_vsffi.dwProductVersionMS);
}

inline WORD CFileVersionInfo::GetProductVersionMinor(void)const
{
	ASSERT(m_bValid);
	return LOWORD(m_vsffi.dwProductVersionMS);
}

inline WORD CFileVersionInfo::GetProductVersionBuild(void)const
{
	ASSERT(m_bValid);
	return HIWORD(m_vsffi.dwProductVersionLS);
}

inline WORD CFileVersionInfo::GetProductVersionQFE(void)const
{
	ASSERT(m_bValid);
	return LOWORD(m_vsffi.dwProductVersionLS);
}

// Translation functions
inline UINT CFileVersionInfo::GetTransCount(void)const
{
	ASSERT(m_bValid);
	return m_nTransCnt;
}

inline UINT CFileVersionInfo::GetCurTransIndex(void)const
{
	ASSERT(m_bValid);
	return m_nTransCur;
}

inline LANGID CFileVersionInfo::GetLIDByIndex(IN UINT nIndex)const
{
	return LOWORD(GetTransByIndex(nIndex));
}

inline WORD CFileVersionInfo::GetCPByIndex(IN UINT nIndex)const
{
	return HIWORD(GetTransByIndex(nIndex));
}

inline DWORD CFileVersionInfo::GetCurTrans(void)const
{
	return GetTransByIndex(GetCurTransIndex());
}

inline LANGID CFileVersionInfo::GetCurLID(void)const
{
	return GetLIDByIndex(GetCurTransIndex());
}

inline WORD CFileVersionInfo::GetCurCP(void)const
{
	return GetCPByIndex(GetCurTransIndex());
}

#endif //__VER_H__
