/*======================================================================================
FILE             : C7zDLL.cpp
ABSTRACT         : This is implementation of C7zDLL Class.
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
NOTES		     : This file contains definitions for loadig, unlaoding, and calling function from
				   Au7zUnpacker.dll.
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "C7zDLL.h"
#include <shlwapi.h>

/*-------------------------------------------------------------------------------------
	Function		: C7zDLL
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Constructor
	Author			: Sandip Sanap
	Description		: Initializes the member varibles
--------------------------------------------------------------------------------------*/
C7zDLL::C7zDLL(void)
{
	m_h7zDLL = NULL;
	m_lpfnUn7zArchive = NULL;
}
/*-------------------------------------------------------------------------------------
	Function		: ~C7zDLL
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Destructor
	Author			: Sandip Sanap
	Description		: Denitializes the member varibles
--------------------------------------------------------------------------------------*/
C7zDLL::~C7zDLL(void)
{
	UnLoadMax7zDll();
}
/*-------------------------------------------------------------------------------------
	Function		: LoadMax7zDll
	In Parameters	: 
	Out Parameters	: bool-returns true if successfully loaded else false
	Purpose			: To load Au7zUnpacker.dll
	Author			: Sandip Sanap
	Description		: Loading the Au7zUnpacker.dll
--------------------------------------------------------------------------------------*/
bool C7zDLL::LoadMax7zDll()
{
	m_h7zDLL = LoadLibrary(_T("Au7zUnpacker.dll"));
	if(m_h7zDLL == NULL)
	{
		return false;
	}
	m_lpfnUn7zArchive = (LPFNUn7zArchive) GetProcAddress(m_h7zDLL, "UnMax7zArchive");
	m_lpfn7zArchive = (LPFN7zArchive) GetProcAddress(m_h7zDLL, "Max7zArchive");
	if(m_lpfnUn7zArchive  == NULL || m_lpfn7zArchive == NULL)
	{	
		UnLoadMax7zDll();	
		return false;
	}
	return true;
}
/*-------------------------------------------------------------------------------------
	Function		: UnLoadMax7zDll
	In Parameters	: 
	Out Parameters	: bool-returns true if successfully Unloaded else false
	Purpose			: To load Au7zUnpacker.dll
	Author			: Sandip Sanap
	Description		: Unloading the Au7zUnpacker.dll and cleanup
--------------------------------------------------------------------------------------*/
bool C7zDLL::UnLoadMax7zDll()
{
	if(m_h7zDLL != NULL)
	{		
		FreeLibrary(m_h7zDLL);
		m_h7zDLL = NULL;
		m_lpfnUn7zArchive = NULL;
		m_lpfn7zArchive = NULL;
	}
//	AddLogEntry(L"Au7zUnpacker Unloaded!!!");
	return true;
}
/*-------------------------------------------------------------------------------------
	Function		: UnMax7zArchive
	In Parameters	: TCHAR *szFileName-file name to be extracted
					  TCHAR *szExtractedPath-Extraction Path
					  TCHAR *szPassword-Password
					  TCHAR *szFilterFile-type of file to be extracted e.g   *.bak *.txt *.exe 
	Out Parameters	: int-returns 0 if HMODULE of loaded dll is NULL else 1
	Purpose			: To call "UnMax7zArchive" function from Au7zUnpacker.dll
	Author			: Sandip Sanap
	Description		: Calling "UnMax7zArchive" function from Au7zUnpacker.dll
--------------------------------------------------------------------------------------*/
int C7zDLL::UnMax7zArchive(TCHAR *szFileName, TCHAR *szExtractedPath, TCHAR *szPassword, TCHAR *szFilterFile)
{
	if (m_h7zDLL == NULL || m_lpfnUn7zArchive == NULL) 
		return 0; 
	TCHAR *szProvidePassword = NULL;
	TCHAR *szFileTypes = NULL;
	if(szExtractedPath==NULL)
	{
		szExtractedPath = new TCHAR[MAX_PATH];
		TCHAR szTempFolderPath[MAX_PATH] = {0};
		// Get temp folder path where to extrat the files
		GetModuleFileName(NULL, szTempFolderPath, MAX_PATH);
		WCHAR *cExtPtr = wcsrchr(szTempFolderPath, '\\');
		if(cExtPtr) *cExtPtr = '\0';
		_stprintf_s(szExtractedPath, MAX_PATH, _T("%s\\TempFolder\\%08x-%05d-%05d"), szTempFolderPath, GetTickCount(), GetCurrentThreadId(), GetCurrentProcessId());		
	}	
	if(szFilterFile!=NULL)
	{
		szFileTypes = new TCHAR[MAX_PATH];
		_stprintf_s(szFileTypes,MAX_PATH,L"%s",szFilterFile);
	}
	if(szPassword!=NULL)
	{
		szProvidePassword = new TCHAR[MAX_PATH];
		_stprintf_s(szProvidePassword,MAX_PATH,L"-p%s",szPassword);
	}
	try
	{
		if(m_lpfnUn7zArchive(L"x",szFileName,szExtractedPath, szProvidePassword,szFileTypes))					
			return 1;		
		else					
			return 0;
		
	}
	catch(...)
	{
		return 0;
	}
	return 1;
}
/*-------------------------------------------------------------------------------------
	Function		: UnMax7zArchiveEx
	In Parameters	: LPCTSTR szFileName-file name to be extracted
					  LPTSTR szExtractedPath-Extraction Path
					  LPTSTR szPassword-Password
					  LPTSTR szFilterFile-type of file to be extracted e.g   *.bak *.txt *.exe 
	Out Parameters	: int-returns 0 if HMODULE of loaded dll is NULL else 1
	Purpose			: To call "UnMax7zArchive" function from Au7zUnpacker.dll
	Author			: Sandip Sanap
	Description		: Calling "UnMax7zArchive" function from Au7zUnpacker.dll
--------------------------------------------------------------------------------------*/
int C7zDLL::UnMax7zArchiveEx(LPCTSTR pszFileName, LPTSTR pszExtractedPath, LPTSTR pszPassword, LPTSTR pszFilterFile)
{
	int iRet = 0;
	if (m_h7zDLL == NULL || m_lpfnUn7zArchive == NULL) 
	{
		return iRet; 
	}
	TCHAR szFilePath[MAX_PATH] = {0};
	_stprintf(szFilePath,_T("%s"),pszFileName);
	/*int iPathLen = lstrlen(szExtractedPath);*/
	int iPathLen = 0;
	if(pszExtractedPath != NULL)
	{
		iPathLen = _tcslen(pszExtractedPath);
	}
	else
	{
		return iRet;
	}

	if(iPathLen == 0)
	{
		TCHAR szTempFolderPath[MAX_PATH] = {0};
		// Get temp folder path where to extrat the files
		GetModuleFileName(NULL, szTempFolderPath, MAX_PATH);
		WCHAR *cExtPtr = wcsrchr(szTempFolderPath, '\\');
		if(cExtPtr) *cExtPtr = '\0';
		_stprintf_s(pszExtractedPath, MAX_PATH, _T("%s\\TempFolder\\%08x-%05d-%05d"), szTempFolderPath, GetTickCount(), GetCurrentThreadId(), GetCurrentProcessId());		
	}	
	TCHAR szExtractPath[MAX_PATH] ={0};
	if(pszExtractedPath!=NULL)
	{		
		_stprintf_s(szExtractPath,MAX_PATH,L"-o%s",pszExtractedPath);
	}
	TCHAR *szPassword =NULL;
	if(pszPassword!=NULL)
	{		
		szPassword = new TCHAR[MAX_PATH];
		_stprintf_s(szPassword,MAX_PATH,L"-p%s",pszPassword);
	}
	
	try
	{
		if(m_lpfnUn7zArchive(L"x",szFilePath,szExtractPath, szPassword,pszFilterFile))		
		{
			iRet = 1;	
		}
		else
		{
			iRet = 0;
		}
	}
	catch(...)
	{
		iRet = 0;
	}
	if(szPassword != NULL)
	{
		delete szPassword;
		szPassword = NULL;
	}
	return iRet;
}

/*-------------------------------------------------------------------------------------
	Function		: Max7zArchive
	In Parameters	: LPCTSTR pszFileName-file name to be created
					  LPCTSTR pszFileFolderPath-Folder or file path to be archived
					  LPCTSTR pszPassword-Password
	Out Parameters	: int-returns 0 if HMODULE of loaded dll is NULL else 1
	Purpose			: To call "Max7zArchive" function from Au7zUnpacker.dll
	Author			: Vikram
	Description		: Calling "Max7zArchive" function from Au7zUnpacker.dll
--------------------------------------------------------------------------------------*/
int C7zDLL::Max7zArchive(LPCTSTR pszFileName, LPCTSTR pszFileFolderPath, LPTSTR pszPassword)
{
	int iRet = 0;
	if (m_h7zDLL == NULL || m_lpfn7zArchive == NULL) 
	{
		return iRet; 
	}
	if(pszFileFolderPath == NULL || pszFileName == NULL)
	{
		return iRet;		
	}	
	TCHAR *szPassword = NULL;
	if(pszPassword!=NULL)
	{
		szPassword = new TCHAR[MAX_PATH];
		_stprintf_s(szPassword,MAX_PATH,L"-p%s",pszPassword);
	}
	TCHAR szDestFilePath[MAX_PATH] = {0};
	_stprintf(szDestFilePath,_T("%s"),pszFileName);

	TCHAR szSrcFilePath[MAX_PATH] = {0};
	_stprintf(szSrcFilePath,_T("%s"),pszFileFolderPath);
	try
	{
		if(m_lpfn7zArchive(L"a",szDestFilePath,szSrcFilePath, szPassword,NULL))		
		{
			iRet = 1;		
		}
		else
		{
			iRet = 0;
		}		
	}
	catch(...)
	{
		iRet = 0;
	}
	if(szPassword != NULL)
	{
		delete szPassword;
		szPassword = NULL;
	}
	return iRet;
}