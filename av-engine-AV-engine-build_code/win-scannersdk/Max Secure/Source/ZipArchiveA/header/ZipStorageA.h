/*=============================================================================
   FILE		           : ZipStorageA.h
   ABSTRACT		       : interface for the CZipStorageA class.
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

#if !defined(AFX_ZIPSTORAGEA_H__941824FE_3320_4794_BDE3_BE334ED8984B__INCLUDED_)
#define AFX_ZIPSTORAGEA_H__941824FE_3320_4794_BDE3_BE334ED8984B__INCLUDED_

#include "ZipBigFileA.h"
#include "ZipAutoBufferA.h"
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

// callback function called when there is a need for a disk change
// calling CZipArchiveA functions, apart from the static ones, may have unexpected results
// iNumber  - disk number needed
// iCode :
//		-1 - disk needed for reading
// other codes occurs during writting
//		>=0 : number of bytes needed
// 		-2 - the file with the archive name already exists on the disk
//		-3 - the disk is probably write - protected
//		-4 - couldn't create a file
//	pData - user defined data
//	return false to abort operation: the proper exception will be thrown
typedef bool (*ZIPCALLBACKFUN )(int iNumber, int iCode, void* pData);

class CZipStorageA  
{

public:
	enum {noSpan, pkzipSpan, tdSpan, suggestedAuto, suggestedTd};
	int m_iSpanMode;
	ZIPCALLBACKFUN m_pZIPCALLBACKFUN;
	static char m_gszExtHeaderSignat[];
	int m_iTdSpanData;
	int m_iWriteBufferSize;
	void* m_pCallbackData;
	CZipBigFileA m_internalfile;
	CFile* m_pFile;

	int IsSpanMode();
	int GetCurrentDisk();
	void Open(CMemFile& mf, int iMode);
	void Flush();
	void UpdateSpanMode(WORD uLastDisk);
	void NextDisk(int iNeeded, LPCTSTR lpszFileName = NULL);
	void Close(bool bAfterException);
	void SetCurrentDisk(int iNumber);
	void ChangeDisk(int iNumber);
	void Open(LPCTSTR szPathName, int iMode, int iVolumeSize);
	void Write(void *pBuf, DWORD iSize, bool bAtOnce);
	DWORD GetPosition();
	DWORD Read(void* pBuf, DWORD iSize, bool bAtOnce);
	CZipStorageA();
	virtual ~CZipStorageA();
	
protected:

	bool m_bNewSpan;
	int m_iCurrentDisk;
	DWORD m_uCurrentVolSize;
	DWORD m_uBytesInWriteBuffer;
	DWORD GetFreeInBuffer();	
	friend class CZipCentralDirA;
	CZipAutoBufferA m_pWriteBuffer;
	
	bool OpenFile(LPCTSTR lpszName, UINT uFlags, bool bThrow = true);
	void CallCallback(int iCode, CString szTemp);
	void WriteInternalBuffer(char *pBuf, DWORD uSize);
	void ThrowError(int err);
	DWORD VolumeLeft();
	DWORD m_uVolumeFreeInBuffer;
	DWORD GetFreeVolumeSpace();	
	DWORD m_iBytesWritten;
	CString GetTdVolumeName(bool bLast, LPCTSTR lpszZipName = NULL);
	CString ChangeTdRead();
	CString ChangePkzipRead();				
};
#endif // !defined(AFX_ZIPSTORAGEA_H__941824FE_3320_4794_BDE3_BE334ED8984B__INCLUDED_)
