/*======================================================================================
FILE             : C7zDLL.h
ABSTRACT         : This is header file for Au7zUnpacker.dll operations
DOCUMENTS	     : 
AUTHOR		     : Sandip Sanap
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				without the prior written permission of Aura.	

CREATION DATE    : 11/7/2018
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/
#pragma once

typedef bool (WINAPI *LPFNUn7zArchive)(TCHAR *,TCHAR *,TCHAR *,TCHAR *,TCHAR *);
typedef bool (WINAPI *LPFN7zArchive)(TCHAR *,TCHAR *,TCHAR *,TCHAR *,TCHAR *);
class C7zDLL
{
	
	HMODULE	m_h7zDLL;
    LPFNUn7zArchive m_lpfnUn7zArchive;
	LPFN7zArchive m_lpfn7zArchive;
public:
	C7zDLL(void);
	~C7zDLL(void);

	bool LoadMax7zDll();
	bool UnLoadMax7zDll();
	int  UnMax7zArchive(TCHAR *szFileName, TCHAR *szExtractedPath, TCHAR *szPassword =NULL, TCHAR *szFilterFile = NULL);
	int  UnMax7zArchiveEx(LPCTSTR pszFileName, LPTSTR pszExtractedPath, LPTSTR pszPassword =NULL, LPTSTR pszFilterFile = NULL);
	int  Max7zArchive(LPCTSTR pszFileName, LPCTSTR pszFileFolderPath, LPTSTR pszPassword =NULL);
};
