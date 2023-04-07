/*=============================================================================
   FILE		           : ZipArchive.cpp
   ABSTRACT		       : implementation of the CZipArchive class.
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

#include "stdafx.h"
#include "ZipArchive.h"
#include <direct.h>
#include <stdlib.h> // for qsort

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#ifndef DEF_MEM_LEVEL
#if MAX_MEM_LEVEL >= 8
#  define DEF_MEM_LEVEL 8
#else
#  define DEF_MEM_LEVEL  MAX_MEM_LEVEL
#endif
#endif
#define ENCR_HEADER_LEN 12
/*-------------------------------------------------------------------------------------
	Function       : CZipArchive
	Purpose		   : Constructor for class CZipArchive
	Author		   : 
-------------------------------------------------------------------------------------*/
TCHAR CZipArchive::m_gszCopyright[] = {_T("Zip archive creation and modification Copyright 2000 Tadeusz Dracz")};
CZipArchive::CZipArchive()
{
	m_bDetectZlibMemoryLeaks = true;
	m_centralDir.m_pStorage= &m_storage;
	m_info.m_stream.zalloc = (alloc_func)myalloc;
	m_info.m_stream.zfree = (free_func)myfree;
	m_iFileOpened = nothing;
}
/*-------------------------------------------------------------------------------------
	Function       : ~CZipArchive
	Purpose		   : Destructor for class CZipArchive
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipArchive::~CZipArchive()
{
	EmptyPtrList();	
}
/*-------------------------------------------------------------------------------------
	Function       : Open
	In Parameters  : LPCTSTR szPathName, int iMode, int iVolumeSize
	Out Parameters : void
	Purpose		   : Open a zip archive
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::Open(LPCTSTR szPathName, int iMode, int iVolumeSize)
{
	if (!IsClosed())
	{
		TRACE(_T("ZipArchive already opened.\n"));
		return;
	}
	m_pszPassword.Release();
	m_iFileOpened = nothing;
	m_storage.Open(szPathName, iMode, iVolumeSize);
	m_centralDir.Init();
	if ((iMode == open) ||(iMode == openReadOnly))
		m_centralDir.Read();
}
/*-------------------------------------------------------------------------------------
	Function       : Open
	In Parameters  : CMemFile& mf, int iMode
	Out Parameters : void
	Purpose		   : Open or create an archive in CMemFile
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::Open(CMemFile& mf, int iMode)
{
	if (!IsClosed())
	{
		TRACE(_T("ZipArchive already opened.\n"));
		return;
	}
	if (iMode != open && iMode != openReadOnly && iMode != create)
	{
		TRACE(_T("Mode not supported.\n"));
		return;
	}
	m_pszPassword.Release();
	m_iFileOpened = nothing;
	m_storage.Open(mf, iMode);
	m_centralDir.Init();
	if ((iMode == open) ||(iMode == openReadOnly))
		m_centralDir.Read();
}
/*-------------------------------------------------------------------------------------
	Function       : IsClosed
	In Parameters  : bool bArchive
	Out Parameters : bool 
	Purpose		   : test if the archive or the current volume file is closed
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::IsClosed(bool bArchive)
{
	return  bArchive ?(m_storage.GetCurrentDisk() == -1):(!m_storage.m_pFile || m_storage.m_pFile->m_hFile == CFile::hFileNull);
}
/*-------------------------------------------------------------------------------------
	Function       : ThrowError
	In Parameters  : int err
	Out Parameters : void
	Purpose		   : Throw the error by providing Null or File path
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::ThrowError(int err)
{
	AfxThrowZipException(err, IsClosed() ? _T("") : m_storage.m_pFile->GetFilePath());
}
/*-------------------------------------------------------------------------------------
	Function       : DeleteFile
	In Parameters  : WORD uIndex
	Out Parameters : bool
	Purpose		   : delete the file with the given index
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::DeleteFile(WORD uIndex)
{
	if (m_storage.IsSpanMode())
	{
		TRACE(_T("You cannot delete files from the disk spannig archive.\n"));
		return false;
	}
	
	if (m_iFileOpened)
	{
		TRACE(_T("You cannot delete files if there is a file opened.\n"));
		return false;
	}
	
	if (!m_centralDir.IsValidIndex(uIndex))
		return false;
	
	m_info.Init();
	m_centralDir.RemoveFromDisk();
	DeleteInternal(uIndex);
	m_info.m_pBuffer.Release();
	return true;
}
/*-------------------------------------------------------------------------------------
	Function       : GetNoEntries()
	In Parameters  : void
	Out Parameters : int 
	Purpose		   : Retrive the no of entries in a directory
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipArchive::GetNoEntries()
{
	return (int)m_centralDir.m_headers.GetSize();
}
/*-------------------------------------------------------------------------------------
	Function       : GetFileInfo
	In Parameters  : CZipFileHeader & fhInfo, WORD uIndex
	Out Parameters : bool
	Purpose		   : Retrive the All file info and store in CZipFileHeader class
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::GetFileInfo(CZipFileHeader & fhInfo, WORD uIndex)
{
	if (IsClosed())
	{
		TRACE(_T("ZipArchive is closed.\n"));
		return false;
	}
	
	if (!m_centralDir.IsValidIndex(uIndex))
		return false;
	
	fhInfo = *(m_centralDir.m_headers[uIndex]);
	m_centralDir.ConvertFileName(true, false, &fhInfo);
	return true;
}
/*-------------------------------------------------------------------------------------
	Function       : FindFile
	In Parameters  : CString szFileName, bool bCaseSensitive
	Out Parameters : int
	Purpose		   : find the file in the archive
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipArchive::FindFile(CString szFileName, bool bCaseSensitive)
{
	if (IsClosed())
	{
		TRACE(_T("ZipArchive is closed.\n"));
		return (int)-1;
	}
	// this is required for fast finding and is done only once
	if (!m_centralDir.m_bConvertAfterOpen)
	{
		TRACE(_T("Converting all filenames."));
		m_centralDir.ConvertAll();
	}
	if (!m_centralDir.m_bFindFastEnabled)
		EnableFindFast();
	int iResult = m_centralDir.FindFileNameIndex(szFileName, bCaseSensitive);
	return iResult == -1 ? -1 : m_centralDir.m_findarray[iResult].m_uIndex;
}
/*-------------------------------------------------------------------------------------
	Function       : OpenFile
	In Parameters  : WORD uIndex
	Out Parameters : bool
	Purpose		   : open the file with the given index in the archive for extracting
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::OpenFile(WORD uIndex)
{
	if (!m_centralDir.IsValidIndex(uIndex))
		return false;
	
	if (m_storage.IsSpanMode() == 1)
	{
		TRACE(_T("You cannot extract from the span in creation.\n"));
		return false;
	}
	
	if (m_iFileOpened)
	{
		TRACE(_T("A file already opened.\n"));
		return false;
	}
	
	m_info.Init();
	m_centralDir.OpenFile(uIndex);
	if (CurrentFile()->IsEncrypted())
	{
		
		if (m_pszPassword.GetSize() == 0)
		{
			TRACE(_T("Password not set for the encrypted file.\n"));
			return false;
		}
		CryptInitKeys();
		if (!CryptCheck())
			ThrowError(ZIP_BADPASSWORD); // invalid password

	}
	else if (m_pszPassword.GetSize() != 0)
	{
		TRACE(_T("Password set for a not encrypted file. Ignoring password.\n"));
	}
	
	WORD uMethod = CurrentFile()->m_uMethod;
	if ((uMethod != 0) &&(uMethod != Z_DEFLATED))
		ThrowError(ZIP_BADZIPFILE);
			
	if (uMethod == Z_DEFLATED)
	{
		m_info.m_stream.opaque =  m_bDetectZlibMemoryLeaks ? &m_list : 0;
		int err = inflateInit2(&m_info.m_stream, -MAX_WBITS);
		//			* windowBits is passed < 0 to tell that there is no zlib header.
		//          * Note that in this case inflate *requires* an extra "dummy" byte
		//          * after the compressed stream in order to complete decompression and
		//          * return Z_STREAM_END. 
		CheckForError(err);
	}
	m_info.m_uComprLeft = CurrentFile()->m_uComprSize;
	if (CurrentFile()->IsEncrypted())
		m_info.m_uComprLeft -= ENCR_HEADER_LEN;
	m_info.m_uUncomprLeft = CurrentFile()->m_uUncomprSize;
	m_info.m_uCrc32 = 0;
	m_info.m_stream.total_out = 0;
	m_info.m_stream.avail_in = 0;
	
	m_iFileOpened = extract;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function       : GetLocalExtraField
	In Parameters  : char *pBuf, int iSize
	Out Parameters : int
	Purpose		   : get the local extra filed of the currently opened 
					  for extraction file in the archive
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipArchive::GetLocalExtraField(char *pBuf, int iSize)
{
	if (IsClosed())
	{
		TRACE(_T("ZipArchive is closed.\n"));
		return -1;
	}
	
	if (m_iFileOpened != extract)
	{
		TRACE(_T("A file must be opened to get the local extra field.\n"));
		return -1;
	}
	
	int size = m_centralDir.m_pLocalExtraField.GetSize();
	if (!pBuf|| !size)
		return size;
	
	if (iSize < size)
		size = iSize;
	
	memcpy(pBuf, m_centralDir.m_pLocalExtraField, size);
	return size;
}

/*-------------------------------------------------------------------------------------
	Function       : myalloc
	In Parameters  : void* opaque, UINT items, UINT size
	Out Parameters : void*
	Purpose		   : Allcate memory by using new
	Author		   : 
-------------------------------------------------------------------------------------*/
void* CZipArchive::myalloc(void* opaque, UINT items, UINT size)
{
	void* p = new char[size * items];
	if (opaque)
	{
		CPtrList* list  = (CPtrList*) opaque;
		list->AddTail(p);
	}
	return p;
}

/*-------------------------------------------------------------------------------------
	Function       : myfree
	In Parameters  : void* opaque, void* address
	Out Parameters : void
	Purpose		   : Free memory by using delete
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::myfree(void* opaque, void* address)
{
	if (opaque)
	{
		CPtrList* list  = (CPtrList*) opaque;
		POSITION pos = list->Find(address);
		if (pos)
			list->RemoveAt(pos);
	}
	delete[] address;
}

/*-------------------------------------------------------------------------------------
	Function       : CheckForError
	In Parameters  : int iErr
	Out Parameters : void
	Purpose		   : Check for error
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::CheckForError(int iErr)
{
	if ((iErr == Z_OK) ||(iErr == Z_NEED_DICT))
		return;
	
	ThrowError(iErr);
}

/*-------------------------------------------------------------------------------------
	Function       : CurrentFile()
	In Parameters  : void
	Out Parameters : CZipFileHeader*
	Purpose		   : Return the current file header info
	Author		   : 
-------------------------------------------------------------------------------------*/
CZipFileHeader* CZipArchive::CurrentFile()
{
	ASSERT(m_centralDir.m_pOpenedFile);
	return m_centralDir.m_pOpenedFile;
}

/*-------------------------------------------------------------------------------------
	Function       : ReadFile
	In Parameters  : void *pBuf, DWORD iSize
	Out Parameters : DWORD
	Purpose		   : decompress currently opened file to the bufor
	Author		   : 
-------------------------------------------------------------------------------------*/
DWORD CZipArchive::ReadFile(void *pBuf, DWORD iSize)
{
	if (m_iFileOpened != extract)
	{
		TRACE(_T("Current file must be opened.\n"));
		return 0;
	}
	
	if (!pBuf || !iSize)
		return 0;
	
	m_info.m_stream.next_out = (Bytef*)pBuf;
	m_info.m_stream.avail_out = iSize > m_info.m_uUncomprLeft 
		? m_info.m_uUncomprLeft : iSize;
	
	
	DWORD iRead = 0;
	
	// may happen when the file is 0 sized
	bool bForce = m_info.m_stream.avail_out == 0 && m_info.m_uComprLeft > 0;
	while (m_info.m_stream.avail_out > 0 || (bForce && m_info.m_uComprLeft > 0))
	{
		if ((m_info.m_stream.avail_in == 0) &&
			(m_info.m_uComprLeft > 0))
		{
			DWORD uToRead = m_info.m_pBuffer.GetSize();
			if (m_info.m_uComprLeft < uToRead)
				uToRead = m_info.m_uComprLeft;
			
			if (uToRead == 0)
				return 0;
			
			m_storage.Read(m_info.m_pBuffer, uToRead, false);
			CryptDecodeBuffer(uToRead);
			m_info.m_uComprLeft -= uToRead;
			
			m_info.m_stream.next_in = (unsigned char*)(char*)m_info.m_pBuffer;
			m_info.m_stream.avail_in = uToRead;
		}
		
		if (CurrentFile()->m_uMethod == 0)
		{
			DWORD uToCopy = m_info.m_stream.avail_out < m_info.m_stream.avail_in 
				? m_info.m_stream.avail_out : m_info.m_stream.avail_in;
			
			if (uToCopy == 0)
				break;

			memcpy(m_info.m_stream.next_out, m_info.m_stream.next_in, uToCopy);
			
			m_info.m_uCrc32 = crc32(m_info.m_uCrc32, m_info.m_stream.next_out, uToCopy);
			
			m_info.m_uUncomprLeft -= uToCopy;
			m_info.m_stream.avail_in -= uToCopy;
			m_info.m_stream.avail_out -= uToCopy;
			m_info.m_stream.next_out += uToCopy;
			m_info.m_stream.next_in += uToCopy;
            m_info.m_stream.total_out += uToCopy;
			iRead += uToCopy;
		}
		else
		{
			DWORD uTotal = m_info.m_stream.total_out;
			Bytef* pOldBuf =  m_info.m_stream.next_out;
			int err = inflate(&m_info.m_stream, Z_SYNC_FLUSH);
			DWORD uToCopy = m_info.m_stream.total_out - uTotal;
			
			m_info.m_uCrc32 = crc32(m_info.m_uCrc32, pOldBuf, uToCopy);
			
			m_info.m_uUncomprLeft -= uToCopy;
			iRead += uToCopy;
            
			if (err == Z_STREAM_END)
				return iRead;
			
			CheckForError(err);
		}
	}
	return iRead;
}

/*-------------------------------------------------------------------------------------
	Function       : Close
	In Parameters  : bool bAfterException
	Out Parameters : void
	Purpose		   : close archive
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::Close(bool bAfterException)
{
		// if after an exception - the archive may be closed, but the file may be opened
	if (IsClosed() && (!bAfterException || IsClosed(false)))
	{
		TRACE(_T("ZipArchive is already closed.\n"));
		return;
	}
	
	if (!bAfterException)
	{
		if (m_iFileOpened == extract)
			CloseFile(NULL);
		
		if (m_iFileOpened == compress)
			CloseNewFile();

		// write central directory
		m_centralDir.Write();
	}
	else
	{
		m_info.m_pBuffer.Release();
		m_iFileOpened = nothing;
		EmptyPtrList();
	}

	m_centralDir.Clear();
	m_storage.Close(bAfterException);
}

/*-------------------------------------------------------------------------------------
	Function       : SetSpanCallback
	In Parameters  : ZIPCALLBACKFUN pFunc, void* pData
	Out Parameters : void
	Purpose		   : set callback function used during operations on a
					 pkzip compatible disk spanning archive to change disks; 
					set it usualy before opening the archive for reading
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::SetSpanCallback(ZIPCALLBACKFUN pFunc, void* pData)
{
	m_storage.m_pZIPCALLBACKFUN = pFunc;
	m_storage.m_pCallbackData = pData;
}

/*-------------------------------------------------------------------------------------
	Function       : SetAdvanced
	In Parameters  : int iWriteBuffer, int iExtractBuffer, int iSearchBuffer
	Out Parameters : void
	Purpose		   : set advanced options
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::SetAdvanced(int iWriteBuffer, int iExtractBuffer, int iSearchBuffer)
{
	if (!IsClosed())
	{
		TRACE(_T("Set this options before opening the archive.\n"));
		return;
	}
	
	m_storage.m_iWriteBufferSize = iWriteBuffer < 1024 ? 1024 : iWriteBuffer;
	m_centralDir.m_iBufferSize = iSearchBuffer < 1024 ? 1024 : iSearchBuffer;
	m_info.m_iBufferSize = iExtractBuffer < 1024 ? 1024 : iExtractBuffer;
}

/*-------------------------------------------------------------------------------------
	Function       : CloseFile
	In Parameters  : CFile &file
	Out Parameters : int
	Purpose		   : close current file  and update
					date and attribute information of CFile, closes CFile
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipArchive::CloseFile(CFile &file)
{
	CString temp = file.GetFilePath();
	file.Close();
	return CloseFile(temp);
}

/*-------------------------------------------------------------------------------------
	Function       : CloseFile
	In Parameters  : LPCTSTR lpszFilePath, bool bAfterException
	Out Parameters : int
	Purpose		   : Close the file opened for extraction in the archive and copy its date and 
					attributes to the file pointed by \e lpszFilePath
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipArchive::CloseFile(LPCTSTR lpszFilePath, bool bAfterException)
{
	if (m_iFileOpened != extract)
	{
		TRACE(_T("No opened file.\n"));
		return false;
	}

	int iRet = 1;
	if (!bAfterException)
	{
		if (m_info.m_uUncomprLeft == 0)
		{
			if (m_info.m_uCrc32 != CurrentFile()->m_uCrc32)
				ThrowError(ZIP_BADCRC);
		}
		else
			iRet = -1;

				
		if (CurrentFile()->m_uMethod == Z_DEFLATED)
			inflateEnd(&m_info.m_stream);
		
		
		if (lpszFilePath)
		{
			try
			{
				CFileStatus fs;
				fs.m_ctime = fs.m_atime = CTime::GetCurrentTime();
				fs.m_attribute = 0;
				fs.m_mtime = CurrentFile()->GetTime();
				CFile::SetStatus(lpszFilePath, fs);
				if (SetFileAttributes(lpszFilePath, CurrentFile()->m_uExternalAttr) == 0)
					iRet = -2;
			}
			catch (CException* e)
			{
				e->Delete();
				return true;
			}
		}
	}
	m_centralDir.CloseFile();
	m_iFileOpened = nothing;
	m_info.m_pBuffer.Release();
	EmptyPtrList();
	return iRet;
}

/*-------------------------------------------------------------------------------------
	Function       : OpenNewFile
	In Parameters  : CZipFileHeader & header, int iLevel, LPCTSTR lpszFilePath
	Out Parameters : bool
	Purpose		   : add a new file to the zip archive
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::OpenNewFile(CZipFileHeader & header, int iLevel, LPCTSTR lpszFilePath)
{
	if (IsClosed())
	{
		TRACE(_T("ZipArchive is closed.\n"));
		return false;
	}
	
	if (m_iFileOpened)
	{
		TRACE(_T("A file already opened.\n"));
		return false;
	}
	
	if (m_storage.IsSpanMode() == -1)
	{
		TRACE(_T("You cannot add the files to the existing disk spannig archive.\n"));
		return false;
	}
	
	if (GetNoEntries() ==(WORD)USHRT_MAX)
	{
		TRACE(_T("Maximum file count inside archive reached.\n"));
		return false;
	}
	
	
	if (lpszFilePath)
	{
		bool bRet = true;
		CFileStatus fs;
		if (!CFile::GetStatus(lpszFilePath, fs))
			bRet = false;
		else
		{
			header.SetTime(fs.m_mtime);
			header.m_uExternalAttr = ::GetFileAttributes(lpszFilePath); // mfc bug: m_attribute is 1-byte
			if (header.m_uExternalAttr == -1)
				bRet = false;
		}
			
		if (!bRet)
			// do not continue - if the file was a directory then not recognizing it will cause 
			// serious errors 
			return false;
	}

	m_info.Init();
	m_centralDir.AddNewFile(header);

	CString szFileName = CurrentFile()->GetFileName();
	
	if (szFileName.IsEmpty())
	{
		szFileName.Format(_T("file%i"), GetNoEntries());;
		CurrentFile()->SetFileName(szFileName);
	}
	// this ensures the conversion will take place anyway (must take because we are going 
	// 	to write the local header in a moment
	m_centralDir.ConvertFileName(false, m_centralDir.m_bConvertAfterOpen);


	bool bIsDirectory = IsDirectory(CurrentFile()->m_uExternalAttr);
	bool bEncrypted = m_pszPassword.GetSize() != 0;
#ifdef _DEBUG
	if (bIsDirectory && bEncrypted)
		TRACE(_T("Warning! Encrypting a directory. Possible but pointless.\n\
		Clear the password before adding a directory.\n"));
#endif	

	
	if (!CurrentFile()->PrepareData(iLevel, m_storage.IsSpanMode() == 1, bEncrypted))
			ThrowError(ZIP_TOOLONGFILENAME);

	CurrentFile()->WriteLocal(m_storage);
	// we have written the local header, but if we keep filenames not converted
	// in memory , we have to restore the non-converted value
	if (m_centralDir.m_bConvertAfterOpen)
		CurrentFile()->SetFileName(szFileName);
	if (bEncrypted)
	{
		CZipAutoBuffer buf(ENCR_HEADER_LEN);
		// use pseudo-crc since we don't know it yet
		CryptCryptHeader((long)header.m_uModTime << 16, buf);
		m_storage.Write(buf, ENCR_HEADER_LEN, false);
	}
	
	
	m_info.m_uComprLeft = 0;
    m_info.m_stream.avail_in = (uInt)0;
    m_info.m_stream.avail_out = (uInt)m_info.m_pBuffer.GetSize();
    m_info.m_stream.next_out = (unsigned char*)(char*)m_info.m_pBuffer;
    m_info.m_stream.total_in = 0;
    m_info.m_stream.total_out = 0;
	
	if (bIsDirectory && (CurrentFile()->m_uMethod != 0))
		CurrentFile()->m_uMethod = 0;
	
	if (CurrentFile()->m_uMethod == Z_DEFLATED)
    {
        m_info.m_stream.opaque = m_bDetectZlibMemoryLeaks ? &m_list : 0;
		
        int err = deflateInit2(&m_info.m_stream, iLevel,
			Z_DEFLATED, -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY);
		
		CheckForError(err);
    }
	m_iFileOpened = compress;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function       : GetFilePath
	In Parameters  : LPCTSTR lpszFilePath
	Out Parameters : CString
	Purpose		   : Get file path
	Author		   : 
-------------------------------------------------------------------------------------*/
CString CZipArchive::GetFilePath(LPCTSTR lpszFilePath)
{
	TCHAR szDir[_MAX_DIR];
	TCHAR szDrive[_MAX_DRIVE];
	_tsplitpath(lpszFilePath, szDrive, szDir, NULL, NULL);
	return  CString(szDrive) + CString(szDir);
}

/*-------------------------------------------------------------------------------------
	Function       : GetFileExt
	In Parameters  : LPCTSTR lpszFilePath
	Out Parameters : CString
	Purpose		   : Get file extention
	Author		   : 
-------------------------------------------------------------------------------------*/
CString CZipArchive::GetFileExt(LPCTSTR lpszFilePath)
{
   TCHAR szExt[_MAX_EXT];
   _tsplitpath(lpszFilePath, NULL, NULL, NULL, szExt);
   return CString(szExt);
}

/*-------------------------------------------------------------------------------------
	Function       : GetFileTitle
	In Parameters  : LPCTSTR lpszFilePath
	Out Parameters : CString
	Purpose		   : Retrive file title
	Author		   : 
-------------------------------------------------------------------------------------*/
CString CZipArchive::GetFileTitle(LPCTSTR lpszFilePath)
{
	TCHAR szFname[_MAX_FNAME];
	_tsplitpath(lpszFilePath, NULL, NULL, szFname, NULL);
	return  CString(szFname);
}

/*-------------------------------------------------------------------------------------
	Function       : GetFileDirAndName
	In Parameters  : LPCTSTR lpszFilePath
	Out Parameters : CString
	Purpose		   : Get the file directory and directory path
	Author		   : 
-------------------------------------------------------------------------------------*/
CString CZipArchive::GetFileDirAndName(LPCTSTR lpszFilePath)
{
	TCHAR szDir[_MAX_DIR];
	TCHAR szFname[_MAX_FNAME];
	TCHAR szExt[_MAX_EXT];
	_tsplitpath(lpszFilePath, NULL , szDir, szFname, szExt);
	CString Dir = szDir;
	Dir.TrimLeft(_T("\\"));
	CString csFileName(szFname);
	CString csExt(szExt);
	if((csExt.CompareNoCase(L".sd") == 0) && csFileName.Find('.'))
		csExt = L"";
	return  Dir + szFname + csExt;
}


/*-------------------------------------------------------------------------------------
	Function       : GetFileName
	In Parameters  : LPCTSTR lpszFilePath
	Out Parameters : CString
	Purpose		   : get the file name
	Author		   : 
-------------------------------------------------------------------------------------*/
CString CZipArchive::GetFileName(LPCTSTR lpszFilePath)
{
	TCHAR szExt[_MAX_EXT];
	TCHAR szName[_MAX_FNAME];
	_tsplitpath(lpszFilePath, NULL, NULL, szName, szExt);
	CString csFileName(szName);
	CString csExt(szExt);
	if((csExt.CompareNoCase(L".sd") == 0) && csFileName.Find('.'))
		csExt = L"";
	return CString(szName) + csExt;
}

/*-------------------------------------------------------------------------------------
	Function       : ForceDirectory
	In Parameters  : LPCTSTR lpDirectory
	Out Parameters : bool
	Purpose		   : get the force directorypath
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::ForceDirectory(LPCTSTR lpDirectory)
{
	ASSERT(lpDirectory);
	CString szDirectory = lpDirectory;
	szDirectory.TrimRight(_T("\\"));
	if ((GetFilePath(szDirectory) == szDirectory) ||
		(FileExists(szDirectory) == -1))
		return true;
	if (!ForceDirectory(GetFilePath(szDirectory)))
		return false;
	if (!CreateDirectory(szDirectory, NULL))
		return false;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function       : FileExists
	In Parameters  : PCTSTR lpszName
	Out Parameters : int
	Purpose		   : check for file exist or not
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipArchive::FileExists(LPCTSTR lpszName)
{
	CFileFind fileFind;
	if (!fileFind.FindFile(lpszName))
	{
		if (DirectoryExists(lpszName))  // if root ex. "C:\"
			return -1;
		return 0;
	}
	fileFind.FindNextFile();
	return fileFind.IsDirectory() ? -1 : 1;
}

/*-------------------------------------------------------------------------------------
	Function       : DirectoryExists
	In Parameters  : LPCTSTR lpszDir
	Out Parameters : bool
	Purpose		   : check for directory exists or not
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::DirectoryExists(LPCTSTR lpszDir)
{
	TCHAR curPath[_MAX_PATH];   /* Get the current working directory: */
	if (!_tgetcwd(curPath, _MAX_PATH))
		return false;
	if (_tchdir(lpszDir))	// retruns 0 if error
		return false;
	_tchdir(curPath);
	return true;
}

/*-------------------------------------------------------------------------------------
	Function       : IsFileDirectory
	In Parameters  : WORD uIndex
	Out Parameters : bool
	Purpose		   : check if the file with the given index is a directory
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::IsFileDirectory(WORD uIndex)
{
	if (IsClosed())
	{
		TRACE(_T("ZipArchive is closed.\n"));
		return false;
	}
	
	if (!m_centralDir.IsValidIndex(uIndex))
		return false;
	
	return IsDirectory(m_centralDir.m_headers[uIndex]->m_uExternalAttr);
}

/*-------------------------------------------------------------------------------------
	Function       : Extract
	In Parameters  : CString csZipFile,CString csExtractPath 
	Out Parameters : bool
	Purpose		   : Extract all files in zip file to given path
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::Extract(CString csZipFile,CString csExtractPath , LPCTSTR szPassword)
{
	bool bSuccess = false;

	try
	{
		Open(csZipFile, CZipArchive::openReadOnly, 0 );
		
		int iCount = GetNoEntries();
		for(int i=0;i<iCount;i++)
		{
			CZipFileHeader fh;
			GetFileInfo(fh, (WORD)i);
			if(szPassword && fh.IsEncrypted())
			{
				SetPassword(szPassword);
			}

			CString sz = (LPCTSTR)fh.GetFileName();

			ExtractFile((WORD)i,csExtractPath);		
			
		}

		Close();
		bSuccess = true;
	}

	catch (CException* e)
	{
		e->Delete();
		Close(true);
		bSuccess = false;
	}

	return bSuccess;
}

/*-------------------------------------------------------------------------------------
	Function       : ExtractFile
	In Parameters  : WORD uIndex,
							  LPCTSTR lpszPath,             
                              bool bFullPath,              
                              LPCTSTR lpszNewName,          
                              ZIPCALLBACKFUN pCallback,     
                              void* pUserData,              
                              DWORD nBufSize
	Out Parameters : bool
	Purpose		   : fast extracting
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::ExtractFile(WORD uIndex,
							  LPCTSTR lpszPath,             
                              bool bFullPath,              
                              LPCTSTR lpszNewName,          
                              ZIPCALLBACKFUN pCallback,     
                              void* pUserData,              
                              DWORD nBufSize)
{
	if (!nBufSize && !lpszPath)
		return false;
	
	try
	{
		CZipFileHeader header;
		GetFileInfo(header, uIndex); // to ensure that slash and oem conversions take place
		CString szFile = lpszPath, szFileName = lpszNewName ? lpszNewName : header.GetFileName();
		szFile.TrimRight(_T("\\"));
		szFile += _T("\\") + (bFullPath ? GetFileDirAndName(szFileName)
			: GetFileName(szFileName)); // just in case in the archive there are file names with drives
		
		bool bDir = (szFile.Right(1) == _T("\\"));

		if(bDir || IsFileDirectory(uIndex))
		{
			ForceDirectory(szFile);
			SetFileAttributes(szFile, header.m_uExternalAttr);
			return true;
		}

		if (!OpenFile(uIndex))
			return false;

		ForceDirectory(GetFilePath(szFile));
		CFile f(szFile, CFile::modeWrite | CFile::modeCreate | CFile::shareDenyWrite);
		DWORD iRead, iFileLength = pCallback ? header.GetSize() : 0, iSoFar = 0;
		CZipAutoBuffer buf(nBufSize);
		do
		{
			iRead = ReadFile(buf, buf.GetSize());
			if (iRead)
			{	
				f.Write(buf, iRead);
				iSoFar += iRead;
				if (pCallback)
					if (!pCallback(iFileLength, iSoFar, pUserData))
						break;
			}
		}
		while (iRead == buf.GetSize());

		return CloseFile(f) == 1;
	}
	catch(...)
	{
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function       : SetExtraField
	In Parameters  : char *pBuf, WORD iSize
	Out Parameters : void
	Purpose		   : set the extra field in the file header in the central directory
					must be used after opening a new file in the archive, but before closing it
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::SetExtraField(char *pBuf, WORD iSize)
{
	if (m_iFileOpened != compress)
	{
		TRACE(_T("A new file must be opened.\n"));
		return;
	}
	if (!pBuf || !iSize)
		return;
	
	CurrentFile()->m_pExtraField.Allocate(iSize);
	memcpy(CurrentFile()->m_pExtraField, pBuf, iSize);
}

/*-------------------------------------------------------------------------------------
	Function       : WriteNewFile
	In Parameters  : void *pBuf, DWORD iSize
	Out Parameters : bool
	Purpose		   : ompress the contents of the buffer and write it to a new file
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::WriteNewFile(void *pBuf, DWORD iSize)
{
	if (m_iFileOpened != compress)
	{
		TRACE(_T("A new file must be opened.\n"));
		return false;
	}
	
	
    m_info.m_stream.next_in = (unsigned char*)pBuf;
    m_info.m_stream.avail_in = iSize;
    CurrentFile()->m_uCrc32 = crc32(CurrentFile()->m_uCrc32, (unsigned char*)pBuf, iSize);
	
	
    while (m_info.m_stream.avail_in > 0)
    {
        if (m_info.m_stream.avail_out == 0)
        {
			CryptEncodeBuffer();
			m_storage.Write(m_info.m_pBuffer, m_info.m_uComprLeft, false);
			m_info.m_uComprLeft = 0;
            m_info.m_stream.avail_out = m_info.m_pBuffer.GetSize();
            m_info.m_stream.next_out = (unsigned char*)(char*)m_info.m_pBuffer;
        }
		
        if (CurrentFile()->m_uMethod == Z_DEFLATED)
        {
            DWORD uTotal = m_info.m_stream.total_out;
            int err = deflate(&m_info.m_stream,  Z_NO_FLUSH);
			CheckForError(err);
            m_info.m_uComprLeft += m_info.m_stream.total_out - uTotal;
        }
        else
        {
            DWORD uToCopy = (m_info.m_stream.avail_in < m_info.m_stream.avail_out) 
				? m_info.m_stream.avail_in : m_info.m_stream.avail_out;
			
			memcpy(m_info.m_stream.next_out, m_info.m_stream.next_in, uToCopy);
			
            m_info.m_stream.avail_in -= uToCopy;
            m_info.m_stream.avail_out -= uToCopy;
            m_info.m_stream.next_in += uToCopy;
            m_info.m_stream.next_out += uToCopy;
            m_info.m_stream.total_in += uToCopy;
            m_info.m_stream.total_out += uToCopy;
            m_info.m_uComprLeft += uToCopy;
        }
    }
	
	return true;
}

/*-------------------------------------------------------------------------------------
	Function       : CloseNewFile
	In Parameters  : void
	Out Parameters : bool
	Purpose		   : close the new file in the archive
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::CloseNewFile()
{
	if (m_iFileOpened != compress)
	{
		TRACE(_T("A new file must be opened.\n"));
		return false;
	}
	
    m_info.m_stream.avail_in = 0;
    
	int err = Z_OK;
    if (CurrentFile()->m_uMethod == Z_DEFLATED)
        while (err == Z_OK)
		{
			if (m_info.m_stream.avail_out == 0)
			{
				CryptEncodeBuffer();
				m_storage.Write(m_info.m_pBuffer, m_info.m_uComprLeft, false);
				m_info.m_uComprLeft = 0;
				m_info.m_stream.avail_out = m_info.m_pBuffer.GetSize();
				m_info.m_stream.next_out = (unsigned char*)(char*)m_info.m_pBuffer;
			}
			DWORD uTotal = m_info.m_stream.total_out;
			err = deflate(&m_info.m_stream,  Z_FINISH);
			m_info.m_uComprLeft += m_info.m_stream.total_out - uTotal;
		}
		
	if (err == Z_STREAM_END)
		err = Z_OK;
	CheckForError(err);
	
	if (m_info.m_uComprLeft > 0)
	{
		CryptEncodeBuffer();
		m_storage.Write(m_info.m_pBuffer, m_info.m_uComprLeft, false);
	}
	
	if (CurrentFile()->m_uMethod == Z_DEFLATED)
	{
		err = deflateEnd(&m_info.m_stream);
		CheckForError(err);
	}
	
	
	// it may be increased by the encrypted header size
	CurrentFile()->m_uComprSize += m_info.m_stream.total_out;
	CurrentFile()->m_uUncomprSize = m_info.m_stream.total_in;
	
	m_centralDir.CloseNewFile();
	m_iFileOpened = nothing;
	m_info.m_pBuffer.Release();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function       : DeleteFiles
	In Parameters  : CStringArray &aNames, bool bCaseSensitive
	Out Parameters : void
	Purpose		   : delete files from the archive opened in the Delete mode specified by aIndexes
					or aNames.aIndexes is a array of indexes of the files inside the archive;
					the index no. 0 is the first file in the archive
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::DeleteFiles(CStringArray &aNames, bool bCaseSensitive)
{
	CWordArray indexes;
	
	for (WORD i = 0; i < GetNoEntries(); i++)
	{
		CZipFileHeader fh;
		GetFileInfo(fh, i);
		CString szFileName = fh.GetFileName();
		for (int j = 0; j < aNames.GetSize(); j++)
		{
			bool bEqual = (bCaseSensitive ? aNames[j].Collate(szFileName)
				: aNames[j].CollateNoCase(szFileName)) == 0;
			if (bEqual)
			{
				indexes.Add(i);
				break;
			}
		}
	}
	
	DeleteFiles(indexes);
}


/*-------------------------------------------------------------------------------------
	Function       : DeleteFiles
	In Parameters  : CWordArray &aIndexes
	Out Parameters : void
	Purpose		   : Delete all files contain in the WordArray
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::DeleteFiles(CWordArray &aIndexes)
{
	if (IsClosed())
	{
		TRACE(_T("ZipArchive is closed.\n"));
		return;
	}
	
	if (m_storage.IsSpanMode())
	{
		TRACE(_T("You cannot delete files from the disk spannig archive.\n"));
		return;
	}
	
	if (m_iFileOpened)
	{
		TRACE(_T("You cannot delete files if there is a file opened.\n"));
		return;
	}
	
	// sorting the index table using qsort 
	int uSize = (int)aIndexes.GetSize();
	if (!uSize)
		return;
	qsort((void*)&aIndexes[0], uSize, sizeof(WORD), CompareWords);
	
	m_centralDir.RemoveFromDisk();
	
	m_info.Init();
	// remove in a reverse order
	for (int i = uSize - 1; i >= 0; i--)
		DeleteInternal(aIndexes[i]);
	m_info.m_pBuffer.Release();
}

/*-------------------------------------------------------------------------------------
	Function       : RemovePackedFile
	In Parameters  : DWORD uStartOffset, DWORD uEndOffset
	Out Parameters : DWORD
	Purpose		   : Remove the Packed file's from the disk
	Author		   : 
-------------------------------------------------------------------------------------*/
DWORD CZipArchive::RemovePackedFile(DWORD uStartOffset, DWORD uEndOffset)
{
	uStartOffset += m_centralDir.m_uBytesBeforeZip;
	uEndOffset += m_centralDir.m_uBytesBeforeZip;
	DWORD BytesToCopy = static_cast<DWORD>(m_storage.m_pFile->GetLength() - uEndOffset);
	DWORD uTotalToWrite = BytesToCopy;
	
	char* buf = (char*)m_info.m_pBuffer;
	if (BytesToCopy > m_info.m_pBuffer.GetSize()) 
		BytesToCopy = m_info.m_pBuffer.GetSize();
	
	DWORD TotalWritten = 0;
	DWORD size_read;
	
	do
	{
		m_storage.m_pFile->Seek(uEndOffset + TotalWritten, CFile::begin);
		size_read = m_storage.m_pFile->Read(buf, BytesToCopy);
		if (size_read > 0)
		{
			m_storage.m_pFile->Seek(uStartOffset + TotalWritten, CFile::begin);
			m_storage.m_pFile->Write(buf, size_read);
		}
		TotalWritten += size_read;
	}
	while (size_read == BytesToCopy);
	if (uTotalToWrite != TotalWritten)
		ThrowError(CZipException::generic);
	DWORD uRemoved = (uEndOffset - uStartOffset);
	m_storage.m_pFile->SetLength(m_storage.m_pFile->GetLength() - uRemoved);
	return uRemoved;
}


/*-------------------------------------------------------------------------------------
	Function       : DeleteInternal
	In Parameters  : WORD uIndex
	Out Parameters : void
	Purpose		   : Delete all internals of the file
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::DeleteInternal(WORD uIndex)
{
	CZipFileHeader* pfh = m_centralDir.m_headers[uIndex];
	DWORD uOtherOffsetChanged = 0;
	
	if (uIndex == GetNoEntries() - 1) // last entry or the only one entry
		m_storage.m_pFile->SetLength(pfh->m_uOffset + m_centralDir.m_uBytesBeforeZip);						
	else
		uOtherOffsetChanged = RemovePackedFile(pfh->m_uOffset, m_centralDir.m_headers[uIndex + 1]->m_uOffset);
	
	
	m_centralDir.RemoveFile(uIndex);
	
	// teraz uaktualnij offsety w pozosta³ych pozycjach central dir 
	// (update offsets in file headers in the central dir)
	if (uOtherOffsetChanged)
		for (int i = uIndex; i < GetNoEntries(); i++)
			m_centralDir.m_headers[i]->m_uOffset -= uOtherOffsetChanged;
}

/*-------------------------------------------------------------------------------------
	Function       : IsDriveRemovable
	In Parameters  : LPCTSTR lpszFilePath
	Out Parameters : bool
	Purpose		   : check for drive removable or not
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::IsDriveRemovable(LPCTSTR lpszFilePath)
{
	return GetDriveType(GetDrive(lpszFilePath)) == DRIVE_REMOVABLE;
}

/*-------------------------------------------------------------------------------------
	Function       : GetDrive
	In Parameters  : LPCTSTR lpszFilePath
	Out Parameters : CString
	Purpose		   : Get the Drive name
	Author		   : 
-------------------------------------------------------------------------------------*/
CString CZipArchive::GetDrive(LPCTSTR lpszFilePath)
{
	TCHAR szDrive[_MAX_DRIVE];
	_tsplitpath(lpszFilePath, szDrive, NULL, NULL, NULL);
	return szDrive;
}
/*-------------------------------------------------------------------------------------
	Function       : AddNewFile
	In Parameters  : LPCTSTR lpszFilePath,int iLevel,bool bFullPath,ZIPCALLBACKFUN pCallback,void* pUserData,unsigned long nBufSize
	Out Parameters : bool
	Purpose		   : add quickly a new file to the archive
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::AddNewFile(LPCTSTR lpszFilePath,  
							 int iLevel,          
                             bool bFullPath,      
                             ZIPCALLBACKFUN pCallback,
                             void* pUserData,         
                             unsigned long nBufSize)
{
	if (!nBufSize)
		return false;
	
	CZipFileHeader header;
	header.SetFileName(bFullPath ? GetFileDirAndName(lpszFilePath) : GetFileName(lpszFilePath));
	if (header.GetFileNameSize() == 0)
		return false;
	if (!OpenNewFile(header, iLevel, lpszFilePath))
		return false;
	
	if (!IsDirectory(header.m_uExternalAttr))
	{
		CFile f;
		CFileException* e = new CFileException;
		BOOL bRet = f.Open(lpszFilePath, CFile::modeRead | CFile::shareDenyWrite, e);
		e->Delete();
		if (!bRet)
		{
			CloseNewFile();
			return false;
		}
		
		DWORD iRead, iFileLength = pCallback ? static_cast<DWORD>(f.GetLength()) : 0, iSoFar = 0;
		CZipAutoBuffer buf(nBufSize);
		do
		{
			iRead = f.Read(buf, nBufSize);
			if (iRead)
			{
				WriteNewFile(buf, iRead);
				iSoFar += iRead;
				if (pCallback)
					if (!pCallback(iFileLength, iSoFar, pUserData))
						break;
			}
		}
		while (iRead == buf.GetSize());
	}
	CloseNewFile();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function       : GetSpanMode
	In Parameters  : void
	Out Parameters : int
	Purpose		   : return the disk spanning mode of the cuurrent archive
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipArchive::GetSpanMode()
{
	return m_storage.m_iSpanMode * m_storage.IsSpanMode();
}

/*-------------------------------------------------------------------------------------
	Function       : GetArchivePath
	In Parameters  : void
	Out Parameters : Cstring
	Purpose		   : return the path of the currently opended archive volume
	Author		   : 
-------------------------------------------------------------------------------------*/
CString CZipArchive::GetArchivePath()
{
	return m_storage.m_pFile->GetFilePath();
}

/*-------------------------------------------------------------------------------------
	Function       : GetGlobalComment
	In Parameters  : 
	Out Parameters : CString
	Purpose		   : Get the Global Comment
	Author		   : 
-------------------------------------------------------------------------------------*/
CString CZipArchive::GetGlobalComment()
{
	if (IsClosed())
	{
		TRACE(_T("ZipArchive is closed.\n"));
		return _T("");
	}
	CString temp;	
	if (SingleToWide(m_centralDir.m_pszComment, temp) != -1)
		return temp;
	else 
		return _T("");
}

/*-------------------------------------------------------------------------------------
	Function       : SetGlobalComment
	In Parameters  : const CString &szComment
	Out Parameters : bool
	Purpose		   : set the global comment in the archive
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::SetGlobalComment(const CString &szComment)
{
	if (IsClosed())
	{
		TRACE(_T("ZipArchive is closed.\n"));
		return false;
	}
	if (m_storage.IsSpanMode() == -1)
	{
		TRACE(_T("You cannot modify the global comment of the existing disk spanning archive.\n"));
		return false;
	}

	WideToSingle(szComment, m_centralDir.m_pszComment);
	m_centralDir.RemoveFromDisk();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function       : IsDirectory
	In Parameters  : DWORD uAttr
	Out Parameters : bool
	Purpose		   : Check for Directory or not
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::IsDirectory(DWORD uAttr)
{
	return ((uAttr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY);
}

/*-------------------------------------------------------------------------------------
	Function       : GetCurrentDisk
	In Parameters  : 
	Out Parameters : int
	Purpose		   : return the zero-base number of the current disk
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipArchive::GetCurrentDisk()
{
	return m_storage.GetCurrentDisk() + 1;
}

/*-------------------------------------------------------------------------------------
	Function       : SetFileComment
	In Parameters  : WORD uIndex, CString szComment
	Out Parameters : bool
	Purpose		   : set the comment of the file with the given index
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::SetFileComment(WORD uIndex, CString szComment)
{
	if (IsClosed())
	{
		TRACE(_T("ZipArchive is closed.\n"));
		return false;
	}
	if (m_storage.IsSpanMode() == -1)
	{
		TRACE(_T("You cannot modify the file comment in the existing disk spanning archive.\n"));
		return false;
	}
	
	if (!m_centralDir.IsValidIndex(uIndex))
		return false;
	m_centralDir.m_headers[uIndex]->SetComment(szComment);
	m_centralDir.RemoveFromDisk();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function       : CompareWords
	In Parameters  : const void *pArg1, const void *pArg2
	Out Parameters : int
	Purpose		   : Compare the given worlds
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipArchive::CompareWords(const void *pArg1, const void *pArg2)
{
	WORD w1 = *(WORD*)pArg1;
	WORD w2 = *(WORD*)pArg2;
	return w1 == w2 ? 0 :(w1 < w2 ? - 1 : 1);
}

/*-------------------------------------------------------------------------------------
	Function       : CryptInitKeys
	In Parameters  : 
	Out Parameters : void
	Purpose		   : Assign the Crypt init Keys
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::CryptInitKeys()
{
	ASSERT(m_pszPassword.GetSize());
	m_keys[0] = 305419896L;
	m_keys[1] = 591751049L;
	m_keys[2] = 878082192L;
	for (DWORD i = 0; i < m_pszPassword.GetSize(); i++)
		CryptUpdateKeys(m_pszPassword[i]);
}

/*-------------------------------------------------------------------------------------
	Function       : CryptUpdateKeys
	In Parameters  : 
	Out Parameters : void
	Purpose		   : char c
	Author		   : Assign the Crypt updates keys
-------------------------------------------------------------------------------------*/
void CZipArchive::CryptUpdateKeys(char c)
{	
	m_keys[0] = CryptCRC32(m_keys[0], c);
	m_keys[1] += m_keys[0] & 0xff;
	m_keys[1] = m_keys[1] * 134775813L + 1;
	c = char(m_keys[1] >> 24);
	m_keys[2] = CryptCRC32(m_keys[2], c);
}

/*-------------------------------------------------------------------------------------
	Function       : CryptCheck
	In Parameters  : 
	Out Parameters : bool
	Purpose		   : Checking for crypt or not
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::CryptCheck()
{
	CZipAutoBuffer buf(ENCR_HEADER_LEN);
	m_storage.Read(buf, ENCR_HEADER_LEN, false);
	BYTE b = 0;
	for (int i = 0; i < ENCR_HEADER_LEN; i++)
	{
		b = buf[i]; // only temporary
		CryptDecode((char&)b);
	}
	// check the last byte
	if (CurrentFile()->IsDataDescr()) // Data descriptor present
		return BYTE(CurrentFile()->m_uModTime >> 8) == b;
	else
		return BYTE(CurrentFile()->m_uCrc32 >> 24) == b;
}

/*-------------------------------------------------------------------------------------
	Function       : CryptDecryptByte
	In Parameters  : 
	Out Parameters : char
	Purpose		   : Get the Crypt decrypt byte
	Author		   : 
-------------------------------------------------------------------------------------*/
char CZipArchive::CryptDecryptByte()
{
	int temp = (m_keys[2] & 0xffff) | 2;
	return (char)(((temp * (temp ^ 1)) >> 8) & 0xff);
}

/*-------------------------------------------------------------------------------------
	Function       : CryptDecode
	In Parameters  : char &c
	Out Parameters : void
	Purpose		   : 
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::CryptDecode(char &c)
{
	c ^= CryptDecryptByte();
	CryptUpdateKeys(c);
}

/*-------------------------------------------------------------------------------------
	Function       : SetPassword
	In Parameters  : LPCTSTR lpszPassword
	Out Parameters : bool
	Purpose		   : set the password for the file that is going to be opened or created
						use this function BEFORE opening or adding a file
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::SetPassword(LPCTSTR lpszPassword)
{
	if (m_iFileOpened != nothing)
	{
		TRACE(_T("You cannot change the password when the file is opened\n"));
		return false; // it's important not to change the password when the file inside archive is opened
	}
	if (IsClosed())
	{
		TRACE(_T("Setting the password for a closed archive has no effect.\n"));
	}
	if (lpszPassword)
	{
		int iLen = WideToSingle(lpszPassword, m_pszPassword);
		if (iLen == -1)
			return false;
		for (size_t i = 0; (int)i < iLen; i++)
			if (m_pszPassword[i] > 127)
			{
				m_pszPassword.Release();
				TRACE(_T("The password contains forbidden characters. Password cleared.\n"));
				return false;
			}
	}
	else
		m_pszPassword.Release();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function       : CryptCRC32
	In Parameters  : DWORD l, char c
	Out Parameters : DWORD
	Purpose		   : 
	Author		   : 
-------------------------------------------------------------------------------------*/
DWORD CZipArchive::CryptCRC32(DWORD l, char c)
{
	const DWORD *CRC_TABLE = get_crc_table();
	return CRC_TABLE[(l ^ c) & 0xff] ^ (l >> 8);
}

/*-------------------------------------------------------------------------------------
	Function       : CryptCryptHeader
	In Parameters  : long iCrc, CZipAutoBuffer &buf
	Out Parameters : void
	Purpose		   : Crypt the header
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::CryptCryptHeader(long iCrc, CZipAutoBuffer &buf)
{
	CryptInitKeys();
	srand(UINT(GetTickCount()*time(NULL)));
	// genereate pseudo-random sequence
	char c;
	for (int i = 0; i < ENCR_HEADER_LEN - 2; i++)
	{
		int t1 = rand();
		c = (char)(t1 >> 6);
		if (!c)
			c = (char)t1;
		CryptEncode(c);
		buf[i] = c;

	}
	c = (char)((iCrc >> 16) & 0xff);
	CryptEncode(c);
	buf[ENCR_HEADER_LEN - 2] = c;
	c = (char)((iCrc >> 24) & 0xff);
	CryptEncode(c);
	buf[ENCR_HEADER_LEN - 1] = c;
}

/*-------------------------------------------------------------------------------------
	Function       : CryptEncode
	In Parameters  : void
	Out Parameters : char &c
	Purpose		   : 
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::CryptEncode(char &c)
{
	char t = CryptDecryptByte();
	CryptUpdateKeys(c);
	c ^= t;
}

/*-------------------------------------------------------------------------------------
	Function       : CryptEncodeBuffer
	In Parameters  : void
	Out Parameters : void
	Purpose		   : Crypt Encode buffer
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::CryptEncodeBuffer()
{
	if (CurrentFile()->IsEncrypted())
		for (DWORD i = 0; i < m_info.m_uComprLeft; i++)
			CryptEncode(m_info.m_pBuffer[i]);
}

/*-------------------------------------------------------------------------------------
	Function       : CloseFileAfterTestFailed
	In Parameters  : void
	Out Parameters : void
	Purpose		   : Perform the necessary cleanup after the exception 
				     while testing the archive so that next files in the archive can be tested
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::CloseFileAfterTestFailed()
{
	if (m_iFileOpened != extract)
	{
		TRACE(_T("No file opened.\n"));
		return;
	}
	m_info.m_pBuffer.Release();
	m_centralDir.Clear(false);
	m_iFileOpened = nothing;
}

/*-------------------------------------------------------------------------------------
	Function       : TestFile
	In Parameters  : WORD uIndex, ZIPCALLBACKFUN pCallback, void* pUserData, DWORD uBufSize
	Out Parameters : bool
	Purpose		   : Test the file with the given index
			         the function throws CException*, but performs all the necessary cleanup
					 before, so that the next file can be tested after catchig the exception
					 and examining it for the reason of error.
	Author		   : 
-------------------------------------------------------------------------------------*/
bool CZipArchive::TestFile(WORD uIndex, ZIPCALLBACKFUN pCallback, void* pUserData, DWORD uBufSize)
{
	if (!uBufSize)
		return false;
	CZipFileHeader* pHeader = m_centralDir.m_headers[uIndex];
	if (IsFileDirectory(uIndex))
	{
		
			// we do not test whether the password for the encrypted directory
		// is correct, since it seems to be senseless (anyway password 
		// encrypted directories should be avoided - it adds 12 bytes)
		DWORD iSize = pHeader->m_uComprSize;
		if ((iSize != 0 || iSize != pHeader->m_uUncomprSize)
			// different treating compressed directories
			&& !(pHeader->IsEncrypted() && iSize == 12 && !pHeader->m_uUncomprSize))
			ThrowError(CZipException::dirWithSize);
		return true;
	}
	else
	{
		CZipAutoBuffer buf(uBufSize);
		try
		{
			if (!OpenFile(uIndex))
				return false;
			
			DWORD iRead, iSoFar = 0;
			do
			{	
				iRead = ReadFile(buf, buf.GetSize());
				iSoFar += iRead;
				if (pCallback)
					if (!pCallback(pHeader->m_uUncomprSize, iSoFar, pUserData))
						break;
			}
			while (iRead == buf.GetSize());
			CloseFile();
		}
		catch(CException*)
		{
			CloseFileAfterTestFailed();
			throw;
		}
	}
	return true;

}

/*-------------------------------------------------------------------------------------
	Function       : WideToSingle
	In Parameters  : LPCTSTR lpWide, CZipAutoBuffer &szSingle
	Out Parameters : int
	Purpose		   : convert wide character to Multibyte
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipArchive::WideToSingle(LPCTSTR lpWide, CZipAutoBuffer &szSingle)
{
	size_t wideLen = _tcslen(lpWide);
	if (wideLen == 0)
	{
		szSingle.Release();
		return 0;
	}

#ifdef _UNICODE	
	// iLen does not include terminating character
	int iLen = WideCharToMultiByte(CP_ACP,0, lpWide, (int)wideLen, szSingle, 
		0, NULL, NULL);
	if (iLen > 0)
	{
		szSingle.Allocate(iLen, true);
		iLen = WideCharToMultiByte(CP_ACP,0, lpWide , (int)wideLen, szSingle, 
			iLen, NULL, NULL);
		ASSERT(iLen != 0);
	}
	else // here it means error
	{
		szSingle.Release();
		iLen --;
	}
	return iLen;
		
#else // if not UNICODE just copy
	// 	iLen does not include the NULL character
	szSingle.Allocate(wideLen);
	memcpy(szSingle, lpWide, wideLen);
	return wideLen;
#endif

}

/*-------------------------------------------------------------------------------------
	Function       : SingleToWide
	In Parameters  : CZipAutoBuffer &szSingle, CString& szWide
	Out Parameters : int
	Purpose		   : Covert the MultiByte to Widecharacter
	Author		   : 
-------------------------------------------------------------------------------------*/
int CZipArchive::SingleToWide(CZipAutoBuffer &szSingle, CString& szWide)
{
	int singleLen = szSingle.GetSize();
#ifdef _UNICODE	
	// iLen doesn't include terminating character
	int iLen = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szSingle, singleLen, NULL, 0);
	if (iLen > 0)
	{
		iLen = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szSingle, singleLen, 
			szWide.GetBuffer(iLen) , iLen);
		szWide.ReleaseBuffer(iLen);
		ASSERT(iLen != 0);
	}
	else
	{
		szWide.Empty();
		iLen --;
	}
	return iLen;

#else // if not UNICODE just copy
	// 	iLen does not include the NULL character
	memcpy(szWide.GetBuffer(singleLen), szSingle, singleLen);
	szWide.ReleaseBuffer(singleLen);
	return singleLen;
#endif
}

/*-------------------------------------------------------------------------------------
	Function       : GetCRCTable
	In Parameters  : 
	Out Parameters : const DWORD*
	Purpose		   : Get the CRC Table
	Author		   : 
-------------------------------------------------------------------------------------*/
const DWORD* CZipArchive::GetCRCTable()
{
	return get_crc_table();
}

/*-------------------------------------------------------------------------------------
	Function       : CryptDecodeBuffer
	In Parameters  : DWORD uCount
	Out Parameters : void
	Purpose		   : 
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::CryptDecodeBuffer(DWORD uCount)
{
	if (CurrentFile()->IsEncrypted())
		for (DWORD i = 0; i < uCount; i++)
			CryptDecode(m_info.m_pBuffer[i]);
}

/*-------------------------------------------------------------------------------------
	Function       : EmptyPtrList
	In Parameters  : void
	Out Parameters : void
	Purpose		   : 
	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::EmptyPtrList()
{
	if (m_list.GetCount())
	{
		// if some memory hasn't been freed due to an error in zlib, so free it now
		POSITION pos = m_list.GetHeadPosition();
		while (pos)
			delete[] m_list.GetNext(pos);
	}

}

/*-------------------------------------------------------------------------------------
	Function       : EnableFindFast
	In Parameters  : bool bEnable
	Out Parameters : void
	Purpose		   : Enable fast finding by the file name of the files inside the archive.
					Set CZipCentralDir::m_bFindFastEnabled to true, which is required by FindFile.
					Do not enable it, if you don't plan to use FindFile function

	Author		   : 
-------------------------------------------------------------------------------------*/
void CZipArchive::EnableFindFast(bool bEnable)
{
	if (IsClosed())
	{
		TRACE(_T("Set it after opening the archive"));
		return;
	}

	if (m_centralDir.m_bFindFastEnabled == bEnable)
		return;
	m_centralDir.m_bFindFastEnabled = bEnable;
	if (bEnable)
		m_centralDir.BuildFindFastArray();
	else
		m_centralDir.m_findarray.RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function       : ExtractSIS
	In Parameters  : LPCTSTR szZipFile, LPCTSTR szExtractPath, LPCTSTR szPassword
	Out Parameters : bool
	Purpose		   : extract files from sis files
	Author		   : Anand Srivastava
-------------------------------------------------------------------------------------*/
bool CZipArchive::ExtractSIS(LPCTSTR szZipFile, LPCTSTR szExtractPath, LPCTSTR szPassword)
{
	__try
	{
		HANDLE hFile = INVALID_HANDLE_VALUE;
		SIS_HEADER stSisHeader = {0};
		FILE_RECORDS stFilePointers = {0};

		hFile = IsValidSisFile(szZipFile);
		if(INVALID_HANDLE_VALUE == hFile)
		{
			return false;
		}

		if(!LoadSisFile(hFile, &stSisHeader, &stFilePointers))
		{
			CloseHandle(hFile);
			return false;
		}

		if(0 == ExtractFiles(hFile, szExtractPath, &stSisHeader, &stFilePointers))
		{
			delete []stFilePointers.pstExtFileRec;
			CloseHandle(hFile);
			return false;
		}

		delete []stFilePointers.pstExtFileRec;
		CloseHandle(hFile);
		return true;
	}

	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		OutputDebugString(L"Exception in ExtractSIS: ");
		OutputDebugString(szZipFile);
	}

	return false;
}

HANDLE CZipArchive::IsValidSisFile(LPCTSTR szFilePath)
{
	bool bRet = false;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwFileSize = 0, dwSignature = 0, dwBytesRead = 0;

	hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if(INVALID_HANDLE_VALUE == hFile)
	{
		return INVALID_HANDLE_VALUE;
	}

	dwFileSize = GetFileSize(hFile, NULL);
	if(dwFileSize <= 0x44)
	{
		CloseHandle(hFile);
		return INVALID_HANDLE_VALUE;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0x04, 0, FILE_BEGIN))
	{
		CloseHandle(hFile);
		return INVALID_HANDLE_VALUE;
	}

	if(!::ReadFile(hFile, &dwSignature, 0x04, &dwBytesRead, NULL))
	{
		CloseHandle(hFile);
		return INVALID_HANDLE_VALUE;
	}

	if(dwBytesRead != 0x04)
	{
		CloseHandle(hFile);
		return INVALID_HANDLE_VALUE;
	}

	if(dwSignature != SIS_SIGN)
	{
		CloseHandle(hFile);
		return INVALID_HANDLE_VALUE;
	}

	return hFile;
}

bool CZipArchive::LoadSisFile(HANDLE hFileHandle, SIS_HEADER * pstSisHeader, FILE_RECORDS * pstFilePointers)
{
	DWORD dwBytesRead = 0;

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFileHandle, 0, NULL, FILE_BEGIN))
	{
		return false;
	}

	if(!::ReadFile(hFileHandle, pstSisHeader, sizeof(SIS_HEADER), &dwBytesRead, NULL))
	{
		return false;
	}

	if(dwBytesRead != sizeof(SIS_HEADER))
	{
		return false;
	}

	if(pstSisHeader->NoOfFiles > 500)
	{
		pstSisHeader->NoOfFiles = 500;
	}

	pstFilePointers->pstExtFileRec = new EXT_FILE_RECORDS[pstSisHeader->NoOfFiles];
	if(!pstFilePointers->pstExtFileRec)
	{
		return false;
	}

	memset(pstFilePointers->pstExtFileRec, 0x00, pstSisHeader->NoOfFiles * sizeof(EXT_FILE_RECORDS));
	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFileHandle, pstSisHeader->FileRecordsPointer, 0, FILE_BEGIN))
	{
		delete []pstFilePointers->pstExtFileRec;
		return false;
	}

	if(!::ReadFile(hFileHandle, pstFilePointers->pstExtFileRec, pstSisHeader->NoOfFiles * sizeof(EXT_FILE_RECORDS), &dwBytesRead, NULL))
	{
		delete []pstFilePointers->pstExtFileRec;
		return false;
	}

	if(pstSisHeader->NoOfFiles * sizeof(EXT_FILE_RECORDS) != dwBytesRead)
	{
		delete []pstFilePointers->pstExtFileRec;
		return false;
	}

	return true;
}

DWORD CZipArchive::ExtractFiles(HANDLE hFile, LPCTSTR szDestFilePath, SIS_HEADER * pstSisHeader, FILE_RECORDS * pstFilePointers)
{
	bool bIsCompress = false;
	TCHAR temp[0x50] = {0}, szExtractionPath[1024] = {0}, * szDestFileName = 0, * pTemp = NULL;
	DWORD dwBytesRead = 0, dwFilesExtracted = 0, dwAllocSize = 0;

	if((pstSisHeader->Options & 0x00000008) != 0x00000008)
	{
		bIsCompress = true;
	}

	szDestFileName = (LPTSTR) malloc(MAX_PATH * sizeof(TCHAR));
	if(szDestFileName)
	{
		dwAllocSize = MAX_PATH * sizeof(TCHAR);
	}

	for(int i = 0; i < pstSisHeader->NoOfFiles; i++)
	{
		pTemp = NULL;

		if( (pstFilePointers->pstExtFileRec[i].FileType != 0x00) && (pstFilePointers->pstExtFileRec[i].FileType != 0x02) && 
			(pstFilePointers->pstExtFileRec[i].FileType != 0x03) && (pstFilePointers->pstExtFileRec[i].FileType != 0x05))
		{
			continue;
		}

		if (pstFilePointers->pstExtFileRec[i].DestNameLength > 0x00 && pstFilePointers->pstExtFileRec[i].DestNameLength < MAX_PATH)
		{
			if(pstFilePointers->pstExtFileRec[i].DestNameLength > dwAllocSize)
			{
				if(szDestFileName)
				{
					free(szDestFileName);
				}

				szDestFileName = (LPTSTR) malloc(pstFilePointers->pstExtFileRec[i].DestNameLength + sizeof(TCHAR));
				if(szDestFileName)
				{
					dwAllocSize = pstFilePointers->pstExtFileRec[i].DestNameLength + sizeof(TCHAR);
				}
			}

			if(szDestFileName)
			{
				memset(szDestFileName, 0, dwAllocSize);
				SetFilePointer(hFile, pstFilePointers->pstExtFileRec[i].DestNameOffset, 0, FILE_BEGIN);
				::ReadFile(hFile, szDestFileName, pstFilePointers->pstExtFileRec[i].DestNameLength, &dwBytesRead, NULL);
				pTemp = _tcsrchr(szDestFileName, _T('\\'));
				if(pTemp)
				{
					pTemp++;
				}
			}
		}

		if(!pTemp)
		{
			_stprintf_s(temp, 0x50, _T("Temp%04x.tmp"), i);
			pTemp = temp;
		}

		if(_tcslen(szDestFilePath) + _tcslen(pTemp) < _countof(szExtractionPath))
		{
			_stprintf_s(szExtractionPath, 1024, _T("%s\\%s"), szDestFilePath, pTemp);
			if(WriteSIS(szExtractionPath, bIsCompress, i, hFile, pstSisHeader, pstFilePointers))
			{
				dwFilesExtracted++;
			}
		}
	}

	if(szDestFileName)
	{
		free(szDestFileName);
	}

	return dwFilesExtracted;
}

bool CZipArchive::WriteSIS(LPCTSTR szFilePath, bool bCompress, int iCount, HANDLE hFile, SIS_HEADER * pstSisHeader, FILE_RECORDS * pstFilePointers)
{
	HANDLE		hNewFileHandle = INVALID_HANDLE_VALUE;
	DWORD		BytesRead = 0;
	bool		iRetStatus = false; 
	BYTE		*bInBuff =  NULL, *bOutBuff = NULL;
	DWORD		dwRead = 0x00, dwWrite = 0x00;
	z_stream	m_init;
	int			iRet = 0x00;
	bool		bUnCompress = false;

	bInBuff = (BYTE *)malloc(pstFilePointers->pstExtFileRec[iCount].FileLength);
	if(NULL == bInBuff)
	{
		return false;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, pstFilePointers->pstExtFileRec[iCount].FileOffset, 0, FILE_BEGIN))
	{
		free(bInBuff);
		return false;
	}

	if(!::ReadFile(hFile, &bInBuff[0x00], pstFilePointers->pstExtFileRec[iCount].FileLength, &dwRead, NULL))
	{
		free(bInBuff);
		return false;
	}

	if(dwRead != pstFilePointers->pstExtFileRec[iCount].FileLength)
	{
		free(bInBuff);
		return false;
	}

	//Decompressing data using Zlib liabrary....
	if(pstFilePointers->pstExtFileRec[iCount].FileLength < pstFilePointers->pstExtFileRec[iCount].OrigFileLen || bCompress)
	{
		bOutBuff = (BYTE *)malloc(pstFilePointers->pstExtFileRec[iCount].OrigFileLen + 0x01);
		if(!bOutBuff)
		{
			free(bInBuff);
			return false;
		}

		m_init.zalloc = Z_NULL;
		m_init.zfree = Z_NULL;
		m_init.avail_in = pstFilePointers->pstExtFileRec[iCount].FileLength;
		m_init.next_in = &bInBuff[0x00];
		m_init.avail_out = pstFilePointers->pstExtFileRec[iCount].OrigFileLen;
		m_init.next_out = (Bytef*)bOutBuff;
		iRet = inflateInit(&m_init);
		if(Z_OK == iRet)
		{
			m_init.avail_in = pstFilePointers->pstExtFileRec[iCount].FileLength;
			m_init.next_in = &bInBuff[0x00];
			m_init.avail_out = pstFilePointers->pstExtFileRec[iCount].OrigFileLen;
			m_init.next_out = (Bytef*)bOutBuff;

			inflate(&m_init, Z_NO_FLUSH);
			bUnCompress = true;
		}
	}

	hNewFileHandle = CreateFile(szFilePath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(INVALID_HANDLE_VALUE == hNewFileHandle)
	{
		free(bInBuff);
		if(bOutBuff)
		{
			free(bOutBuff);
		}

		return false;
	}

	if(bUnCompress)
	{
		WriteFile(hNewFileHandle,&bOutBuff[0x00],pstFilePointers->pstExtFileRec[iCount].OrigFileLen,&dwWrite,NULL);
	}
	else
	{
		WriteFile(hNewFileHandle,&bInBuff[0x00],pstFilePointers->pstExtFileRec[iCount].FileLength,&dwWrite,NULL);
	}

	CloseHandle(hNewFileHandle);
	if(bUnCompress)
	{
		inflateEnd(&m_init);
	}

	if(bInBuff)
	{
		free(bInBuff);
	}

	if(bOutBuff)
	{
		free(bOutBuff);
	}

	return true;
}
