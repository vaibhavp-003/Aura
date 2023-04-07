/*=============================================================================
   FILE		           : ZipCentralDir.h
   ABSTRACT		       : interface for the CZipCentralDir class.
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

#if !defined(AFX_ZipCentralDir_H__859029E8_8927_4717_9D4B_E26E5DA12BAE__INCLUDED_)
#define AFX_ZipCentralDir_H__859029E8_8927_4717_9D4B_E26E5DA12BAE__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 6011)
#endif

#include "ZipException.h"
#include <afxtempl.h>
#include "ZipFileHeader.h"
#include "ZipAutoBuffer.h"

struct CZipFindFast
{
	CZipFindFast()
	{
		m_uIndex = 0;
		m_pHeader= NULL;
	}
	CZipFindFast(CZipFileHeader* pHeader, WORD uIndex):m_pHeader(pHeader), m_uIndex(uIndex){}
	CZipFileHeader* m_pHeader;
	WORD m_uIndex;
};


class CZipCentralDir  
{

public:
	
	CZipAutoBuffer m_pszComment;
	CZipFileHeader* m_pOpenedFile;
	CZipStorage* m_pStorage;
	bool m_bFindFastEnabled;
	char m_szSignature[4];
	static char m_gszSignature[];
	int m_iBufferSize;
	WORD m_uThisDisk;
	WORD m_uDiskWithCD;
	WORD m_uDiskEntriesNo;
	WORD m_uEntriesNumber;
	DWORD m_uCentrDirPos;
	DWORD m_uBytesBeforeZip;
	DWORD m_uSize;
	DWORD m_uOffset;
	CTypedPtrArray<CPtrArray, CZipFileHeader*> m_headers;
	CZipAutoBuffer m_pLocalExtraField;
	CArray<CZipFindFast, CZipFindFast> m_findarray;

	CZipCentralDir();
	virtual ~CZipCentralDir();

	bool IsValidIndex(WORD uIndex);
	bool m_bOnDisk;
	bool m_bConvertAfterOpen;
	void RemoveFile(WORD uIndex);
	void Clear(bool bEverything = true);
	void CloseFile();
	void OpenFile(WORD uIndex);
	void Read();
	void Init();
	void CloseNewFile();
	void Write();
	void AddNewFile(CZipFileHeader & header);
	void RemoveFromDisk();
	void BuildFindFastArray();
		
	void ConvertFileName(bool bFromZip, bool bAfterOpen, CZipFileHeader* pHeader = NULL)
	{
		if (bAfterOpen != m_bConvertAfterOpen)
			return;
		if (!pHeader)
		{
			pHeader = m_pOpenedFile;
			ASSERT(pHeader);
		}
		pHeader->AnsiOem(!bFromZip);
		pHeader->SlashChange(bFromZip);
	}
	void ConvertAll();
	int FindFileNameIndex(LPCTSTR lpszFileName, bool bCaseSensitive);
	DWORD GetSize(bool bWhole = false);

protected:
	bool RemoveDataDescr(bool bFromBuffer);
	void InsertFindFastElement(CZipFileHeader* pHeader, WORD uIndex);
	void RemoveHeaders();
	void WriteHeaders();
	void ReadHeaders();
	void ThrowError(int err);
	DWORD Locate();	
	DWORD WriteCentralEnd();
	int CompareElement(LPCTSTR lpszFileName, WORD uIndex, bool bCaseSensitive)
	{
		return bCaseSensitive ? m_findarray[uIndex].m_pHeader->GetFileName().Collate(lpszFileName)
			: m_findarray[uIndex].m_pHeader->GetFileName().CollateNoCase(lpszFileName);
	}

};
#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning (default:6011)
#endif
#endif // !defined(AFX_ZipCentralDir_H__859029E8_8927_4717_9D4B_E26E5DA12BAE__INCLUDED_)
