/*=============================================================================
   FILE		           : ZipArchiveA.h
   ABSTRACT		       : 
   DOCUMENTS	       : 
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 
   NOTES		      : 
   VERSION HISTORY    :
				
=============================================================================*/
#pragma once
#if !defined(AFX_ZIPARCHIVEA_H__A7F528A6_1872_4071_BE66_D56CC2DDE0E6__INCLUDED_)
	#define AFX_ZIPARCHIVEA_H__A7F528A6_1872_4071_BE66_D56CC2DDE0E6__INCLUDED_
	#include "ZipStorageA.h"	// Added by ClassView
#if _MSC_VER > 1000
#endif // _MSC_VER > 1000

#include "ZipExceptionA.h"
#include "ZipCentralDirA.h"	// Added by ClassView
#include "ZipInternalInfoA.h"	// Added by ClassView
#include "zlib.h"
class CZipArchiveA  
{
public:

	enum {open, openReadOnly, create, createSpan};

	static int SingleToWide(CZipAutoBufferA &szSingle, CString& szWide);
	static int WideToSingle(LPCTSTR lpWide, CZipAutoBufferA &szSingle);
	bool TestFile(WORD uIndex, ZIPCALLBACKFUN pCallback = NULL, void* pUserData = NULL, DWORD uBufSize = 65535);
	void CloseFileAfterTestFailed();
	bool SetPassword(LPCTSTR lpszPassword = NULL);
	void SetAdvanced(int iWriteBuffer = 65535, int iExtractBuffer = 16384, int iSearchBuffer = 32768);
	void SetSpanCallback(ZIPCALLBACKFUN pFunc, void* pData = NULL);

	void Open(LPCTSTR szPathName, int iMode = open, int iVolumeSize = 0);
	void Open(CMemFile& mf, int iMode = open);

	bool AddNewFile(LPCTSTR lpszFilePath, int iLevel = -1, bool bFullPath = true, ZIPCALLBACKFUN pCallback = NULL, void* pUserData = NULL, unsigned long nBufSize = 65535);
	bool OpenNewFile(CZipFileHeaderA & header, int iLevel = Z_DEFAULT_COMPRESSION, LPCTSTR lpszFilePath = NULL);
	bool WriteNewFile(void *pBuf, DWORD iSize);
	void SetExtraField(char *pBuf, WORD iSize);
	bool CloseNewFile();
	bool ExtractFile(WORD uIndex, LPCTSTR lpszPath, bool bFullPath = true, LPCTSTR lpszNewName = NULL, ZIPCALLBACKFUN pCallback = NULL, void* pUserData = NULL, DWORD nBufSize = 65535);
	bool OpenFile(WORD uIndex);
	bool Extract(CString csZipFile,CString csExtractPath , LPCTSTR szPassword = 0);
	DWORD ReadFile(void *pBuf, DWORD iSize);
	int GetLocalExtraField(char* pBuf, int iSize);
	int CloseFile(CFile &file);
	int CloseFile(LPCTSTR lpszFilePath = NULL, bool bAfterException = false);
	bool DeleteFile(WORD uIndex);
	void DeleteFiles(CWordArray &aIndexes);
	void DeleteFiles(CStringArray &aNames, bool bCaseSensitive = false);
	bool SetGlobalComment(const CString& szComment);
	CString GetGlobalComment();
	bool SetFileComment(WORD uIndex, CString szComment);
	CString GetArchivePath();
	int GetCurrentDisk();
	int GetSpanMode();
	bool IsFileDirectory(WORD uIndex);
	int FindFile(CString szFileName, bool bCaseSensitive = false);
	void EnableFindFast(bool bEnable = true);

	void SetConvertAfterOpen (bool bConvertAfterOpen)
	{
		if (!IsClosed())
		{
			//TRACE(_T("Set it before opening the archive"));
			return;
		}
		m_centralDir.m_bConvertAfterOpen = bConvertAfterOpen;

	}

	bool GetFileInfo(CZipFileHeaderA & fhInfo, WORD uIndex);
	int  GetNoEntries();
	void Close(bool bAfterException = false);
	bool IsClosed(bool bArchive = true);
	
	bool m_bDetectZlibMemoryLeaks;

	CZipArchiveA();
	virtual ~CZipArchiveA();

//static helper functions  

	static bool ForceDirectory(LPCTSTR lpDirectory);
	static bool IsDriveRemovable(LPCTSTR lpszFilePath);
	static bool DirectoryExists(LPCTSTR lpszDir);
	static int FileExists(LPCTSTR lpszName);
	static CString GetFileTitle(LPCTSTR lpszFilePath);
	static CString GetFileDirAndName(LPCTSTR lpszFilePath);
	static CString GetDrive(LPCTSTR lpszFilePath);
	static CString GetFilePath(LPCTSTR lpszFilePath);
	static CString GetFileExt(LPCTSTR lpszFilePath);
	static CString GetFileName(LPCTSTR lpszFilePath);
	static const DWORD* GetCRCTable();
	
	CZipStorageA* GetStorage()
	{
		return &m_storage;
	}
	
protected:

	DWORD m_keys[3];
	char m_iFileOpened;

	CZipAutoBufferA		m_pszPassword;
	CZipInternalInfoA	m_info;
	CZipStorageA			m_storage;
	CPtrList			m_list;
	CZipCentralDirA		m_centralDir;

	enum {extract = -1, nothing, compress};
	
	bool CryptCheck();
	char CryptDecryptByte();
	void CryptDecode(char &c);
	void EmptyPtrList();
	void CryptDecodeBuffer(DWORD uCount);
	void CryptEncodeBuffer();
	void CryptEncode(char &c);
	void CryptCryptHeader(long iCrc, CZipAutoBufferA& buf);
	void CryptUpdateKeys(char c);
	void CryptInitKeys();
	DWORD CryptCRC32(DWORD l, char c);
	
	bool IsDirectory(DWORD uAttr);
	static int CompareWords(const void *pArg1, const void *pArg2);
	void CheckForError(int iErr);
	void DeleteInternal(WORD uIndex);
	DWORD RemovePackedFile(DWORD uStartOffset, DWORD uEndOffset);
	CZipFileHeaderA* CurrentFile();
	
	static void* myalloc(void* opaque, UINT items, UINT size);
	static void myfree(void* opaque, void* address);
	void ThrowError(int err);
	static TCHAR m_gszCopyright[];	
};

#endif // !defined(AFX_ZIPARCHIVEA_H__A7F528A6_1872_4071_BE66_D56CC2DDE0E6__INCLUDED_)
