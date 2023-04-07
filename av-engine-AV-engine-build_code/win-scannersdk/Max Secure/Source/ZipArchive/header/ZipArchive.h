/*=============================================================================
   FILE		           : ZipArchive.h
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
#if !defined(AFX_ZIPARCHIVE_H__A7F528A6_1872_4071_BE66_D56CC2DDE0E6__INCLUDED_)
	#define AFX_ZIPARCHIVE_H__A7F528A6_1872_4071_BE66_D56CC2DDE0E6__INCLUDED_
	#include "ZipStorage.h"	// Added by ClassView
#if _MSC_VER > 1000
#endif // _MSC_VER > 1000

#include "ZipException.h"
#include "ZipCentralDir.h"	// Added by ClassView
#include "ZipInternalInfo.h"	// Added by ClassView
#include "zlib.h"

#define SIS_SIGN 0x10003A12

#pragma pack(1)
typedef struct SIS_FILE_HEADER
{
	DWORD UID0;
	DWORD UID1;
	DWORD UID2;
	DWORD UID3;
	WORD  Checksum;
	WORD  NoOfLanguages;
	WORD  NoOfFiles;
	WORD  NoOfReq;
	WORD  InstLan;
	WORD  InstFile;
	WORD  InstDrive;
	WORD  NoOfCapabilities;
	DWORD InstallerVer;
	WORD  Options;
	WORD  Type;
	WORD  MajorVer;
	WORD  MinorVer;
	DWORD Varient;
	DWORD LangPointer;
	DWORD FileRecordsPointer;
	DWORD ReqPointer;
	DWORD CertiPointer;
	DWORD CompoNamePointer;	
}SIS_HEADER;

typedef struct EXT_SIS_FILE_RECORDS	//Initialize only if EPOC V.6
{
	DWORD FileRecordType;
	DWORD FileType;
	DWORD FileDetails;
	DWORD SourcenameLen;
	DWORD SourceNameOffset;
	DWORD DestNameLength;	
	DWORD DestNameOffset;
	DWORD FileLength;
	DWORD FileOffset;
	DWORD OrigFileLen;
	DWORD MIMETypeLen;
	DWORD MIMETypePointer;
}EXT_FILE_RECORDS;

typedef struct _FILE_RECORDS
{
	EXT_FILE_RECORDS * pstExtFileRec;
}FILE_RECORDS;
#pragma pack()

class CZipArchive  
{
public:

	enum {open, openReadOnly, create, createSpan};

	static int SingleToWide(CZipAutoBuffer &szSingle, CString& szWide);
	static int WideToSingle(LPCTSTR lpWide, CZipAutoBuffer &szSingle);
	bool TestFile(WORD uIndex, ZIPCALLBACKFUN pCallback = NULL, void* pUserData = NULL, DWORD uBufSize = 65535);
	void CloseFileAfterTestFailed();
	bool SetPassword(LPCTSTR lpszPassword = NULL);
	void SetAdvanced(int iWriteBuffer = 65535, int iExtractBuffer = 16384, int iSearchBuffer = 32768);
	void SetSpanCallback(ZIPCALLBACKFUN pFunc, void* pData = NULL);

	void Open(LPCTSTR szPathName, int iMode = open, int iVolumeSize = 0);
	void Open(CMemFile& mf, int iMode = open);

	bool AddNewFile(LPCTSTR lpszFilePath, int iLevel = -1, bool bFullPath = true, ZIPCALLBACKFUN pCallback = NULL, void* pUserData = NULL, unsigned long nBufSize = 65535);
	bool OpenNewFile(CZipFileHeader & header, int iLevel = Z_DEFAULT_COMPRESSION, LPCTSTR lpszFilePath = NULL);
	bool WriteNewFile(void *pBuf, DWORD iSize);
	void SetExtraField(char *pBuf, WORD iSize);
	bool CloseNewFile();
	bool ExtractFile(WORD uIndex, LPCTSTR lpszPath, bool bFullPath = true, LPCTSTR lpszNewName = NULL, ZIPCALLBACKFUN pCallback = NULL, void* pUserData = NULL, DWORD nBufSize = 65535);
	bool OpenFile(WORD uIndex);
	bool Extract(CString csZipFile,CString csExtractPath , LPCTSTR szPassword = 0);
	bool ExtractSIS(LPCTSTR szZipFile, LPCTSTR szExtractPath, LPCTSTR szPassword = 0);
	HANDLE IsValidSisFile(LPCTSTR szFilePath);
	bool LoadSisFile(HANDLE hFileHandle, SIS_HEADER * pstSisHeader, FILE_RECORDS * pstFilePointers);
	DWORD ExtractFiles(HANDLE hFile, LPCTSTR szDestFilePath, SIS_HEADER * pstSisHeader, FILE_RECORDS * pstFilePointers);
	bool WriteSIS(LPCTSTR szFilePath, bool bCompress, int iCount, HANDLE hFile, SIS_HEADER * pstSisHeader, FILE_RECORDS * pstFilePointers);
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

	bool GetFileInfo(CZipFileHeader & fhInfo, WORD uIndex);
	int  GetNoEntries();
	void Close(bool bAfterException = false);
	bool IsClosed(bool bArchive = true);
	
	bool m_bDetectZlibMemoryLeaks;

	CZipArchive();
	virtual ~CZipArchive();

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
	
	CZipStorage* GetStorage()
	{
		return &m_storage;
	}
	
protected:

	DWORD m_keys[3];
	char m_iFileOpened;

	CZipAutoBuffer		m_pszPassword;
	CZipInternalInfo	m_info;
	CZipStorage			m_storage;
	CPtrList			m_list;
	CZipCentralDir		m_centralDir;

	enum {extract = -1, nothing, compress};
	
	bool CryptCheck();
	char CryptDecryptByte();
	void CryptDecode(char &c);
	void EmptyPtrList();
	void CryptDecodeBuffer(DWORD uCount);
	void CryptEncodeBuffer();
	void CryptEncode(char &c);
	void CryptCryptHeader(long iCrc, CZipAutoBuffer& buf);
	void CryptUpdateKeys(char c);
	void CryptInitKeys();
	DWORD CryptCRC32(DWORD l, char c);
	
	bool IsDirectory(DWORD uAttr);
	static int CompareWords(const void *pArg1, const void *pArg2);
	void CheckForError(int iErr);
	void DeleteInternal(WORD uIndex);
	DWORD RemovePackedFile(DWORD uStartOffset, DWORD uEndOffset);
	CZipFileHeader* CurrentFile();
	
	static void* myalloc(void* opaque, UINT items, UINT size);
	static void myfree(void* opaque, void* address);
	void ThrowError(int err);
	static TCHAR m_gszCopyright[];	
};

#endif // !defined(AFX_ZIPARCHIVE_H__A7F528A6_1872_4071_BE66_D56CC2DDE0E6__INCLUDED_)
