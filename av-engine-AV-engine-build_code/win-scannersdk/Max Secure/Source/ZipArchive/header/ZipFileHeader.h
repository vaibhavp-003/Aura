/*=============================================================================
   FILE		           : ZipFileHeader.h
   ABSTRACT		       : nterface for the CZipFileHeader class.
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

#if !defined(AFX_ZipFileHeader_H__0081FC65_C9C9_4D48_AF72_DBF37DF5E0CF__INCLUDED_)
#define AFX_ZipFileHeader_H__0081FC65_C9C9_4D48_AF72_DBF37DF5E0CF__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "ZipException.h"
#include "ZipStorage.h"
#include "ZipAutoBuffer.h"

class CZipFileHeader  
{
public:	

	char m_szSignature[4];
	WORD m_uVersionMadeBy;
	WORD m_uVersionNeeded;
	WORD m_uFlag;
	WORD m_uMethod;
	WORD m_uModTime;
	WORD m_uModDate;
	DWORD m_uCrc32;
	DWORD m_uComprSize;
	DWORD m_uUncomprSize;
	WORD m_uDiskStart;
	WORD m_uInternalAttr;
	DWORD m_uExternalAttr;
	DWORD m_uOffset;	
	CZipAutoBuffer m_pExtraField;



	bool SetFileName(LPCTSTR lpszFileName);
	bool SetComment(LPCTSTR lpszComment);
	bool IsDataDescr();
	bool IsEncrypted();	
	void AnsiOem(bool bAnsiToOem);
	void SlashChange(bool bWindowsStyle);
	void SetTime(const CTime& time);
	static char m_gszSignature[];
	static char m_gszLocalSignature[];
	WORD GetFileNameSize(){return (WORD)m_pszFileName.GetSize();}
	WORD GetCommentSize(){return (WORD)m_pszComment.GetSize();}
	WORD GetExtraFieldSize(){return (WORD)m_pExtraField.GetSize();}
	DWORD GetSize();
	CString GetFileName();
	CString GetComment();
	CZipFileHeader();
	virtual ~CZipFileHeader();
	CTime GetTime();	
protected:

	CZipAutoBuffer m_pszFileName;	
	CZipAutoBuffer m_pszComment;
	friend class CZipCentralDir;
	friend class CZipArchive;
	bool PrepareData(int iLevel, bool bExtraHeader, bool bEncrypted);
	bool CheckCrcAndSizes(char* pBuf);
	bool Read(CZipStorage *pStorage);
	bool ReadLocal(CZipStorage *pStorage, WORD& iLocExtrFieldSize);
	void GetCrcAndSizes(char * pBuffer);
	void WriteLocal(CZipStorage& storage);	
	DWORD Write(CZipStorage *pStorage);
};
#endif // !defined(AFX_ZipFileHeader_H__0081FC65_C9C9_4D48_AF72_DBF37DF5E0CF__INCLUDED_)
