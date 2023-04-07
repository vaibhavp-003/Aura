/*======================================================================================
   FILE				: MaxOLE.cpp
   ABSTRACT			: Supportive class for INF File Scanner
   DOCUMENTS		: 
   AUTHOR			: Tushar Kadam
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 22 Jul 2010
   NOTES			: This module manages the scanning for file tyep MICRO (DOC Files). 
					  Macro Extraction function Implimentation
   VERSION HISTORY	: 
=====================================================================================*/
#include "pch.h"
#include "MaxOLE.h"

//MS Office File Versions
static const vba_version_t vba_version[] =
{
	{ { 0x5e, 0x00, 0x00, 0x01 }, "Office 97",              5, FALSE},
	{ { 0x5f, 0x00, 0x00, 0x01 }, "Office 97 SR1",          5, FALSE },
	{ { 0x65, 0x00, 0x00, 0x01 }, "Office 2000 alpha?",     6, FALSE },
	{ { 0x6b, 0x00, 0x00, 0x01 }, "Office 2000 beta?",      6, FALSE },
	{ { 0x6d, 0x00, 0x00, 0x01 }, "Office 2000",            6, FALSE },
	{ { 0x6f, 0x00, 0x00, 0x01 }, "Office 2000",            6, FALSE },
	{ { 0x70, 0x00, 0x00, 0x01 }, "Office XP beta 1/2",     6, FALSE },
	{ { 0x73, 0x00, 0x00, 0x01 }, "Office XP",              6, FALSE },
	{ { 0x76, 0x00, 0x00, 0x01 }, "Office 2003",            6, FALSE },
	{ { 0x79, 0x00, 0x00, 0x01 }, "Office 2003",            6, FALSE },
	{ { 0x60, 0x00, 0x00, 0x0e }, "MacOffice 98",           5, TRUE },
	{ { 0x62, 0x00, 0x00, 0x0e }, "MacOffice 2001",         5, TRUE },
	{ { 0x63, 0x00, 0x00, 0x0e }, "MacOffice X",			6, TRUE },
	{ { 0x64, 0x00, 0x00, 0x0e }, "MacOffice 2004",         6, TRUE },
};

/*-------------------------------------------------------------------------------------------------------
Function		: CMaxOLE
In Parameters	: -
Out Parameters	: -
Author			: Sourabh Kadam
Description		: Defination of Constructer.
-------------------------------------------------------------------------------------------------------*/
CMaxOLE::CMaxOLE()
{
	//m_byReadBuffer				=	NULL;
	//m_byDupReadBuffer			=	NULL;
	m_pDecompressionBuffer		=	NULL;
	m_dwDecompressionBufferSize =	0;
	m_dwEncMacAddr				=	0;
	m_dwMacExtracted			=	0;
	m_dwCntMacroModule			=	0;
	m_bDirProcessed				=	FALSE;
	m_csFilePath				=	_T("");
	m_ppMacrosVar				=	NULL;
	m_pCompressedChunk			=	NULL;
	memset(&m_stDirStream, 0, sizeof(m_stDirStream));
	memset(&m_stDecompressionInfo, 0, sizeof(m_stDecompressionInfo));
}

/*-------------------------------------------------------------------------------------------------------
Function		: ~CMaxOLE
In Parameters	: -
Out Parameters	: -
Author			: Sourabh Kadam
Description		: Defination of Destructer.
-------------------------------------------------------------------------------------------------------*/
CMaxOLE::~CMaxOLE()
{
	ReleaseDirStream();
	ReleaseMacroBuffer();
	if(m_pDecompressionBuffer)
	{
		delete []m_pDecompressionBuffer;
	}
}

/*-------------------------------------------------------------------------------------------------------
Function		: MemCpySafe
In Parameters	: LPVOID lpDst, DWORD cbDst, LPVOID lpSrc, DWORD dwStart, DWORD dwSize, DWORD dwMaxSize
Out Parameters	: void
Purpose			: copy data safely
Author			: Anand Srivastava
Description		: copy data and throw exception if out of bounds
-------------------------------------------------------------------------------------------------------*/
void* CMaxOLE::realloc_ole(void * pexisting, size_t size)
{
	void * p = NULL;

	p = realloc(pexisting, size);
	if(NULL == p)
	{
		//RaiseException(0, 0, 0, NULL);
		throw _T("bad realloc_ole");
		return pexisting;
	}

	return p;
}

/*-------------------------------------------------------------------------------------------------------
Function		: MemCpySafe
In Parameters	: LPVOID lpDst, DWORD cbDst, LPVOID lpSrc, DWORD dwStart, DWORD dwSize, DWORD dwMaxSize
Out Parameters	: void
Purpose			: copy data safely
Author			: Anand Srivastava
Description		: copy data and throw exception if out of bounds
-------------------------------------------------------------------------------------------------------*/
void* CMaxOLE::malloc_ole(size_t size)
{
	void * p = NULL;

	p = malloc(size);
	if(NULL == p)
	{
		//RaiseException(0, 0, 0, 0);
		throw _T("bad malloc_ole");
		return NULL;
	}

	return p;
}

/*-------------------------------------------------------------------------------------------------------
Function		: MemCpySafe
In Parameters	: LPVOID lpDst, DWORD cbDst, LPVOID lpSrc, DWORD dwStart, DWORD dwSize, DWORD dwMaxSize
Out Parameters	: void
Purpose			: copy data safely
Author			: Anand Srivastava
Description		: copy data and throw exception if out of bounds
-------------------------------------------------------------------------------------------------------*/
void CMaxOLE::free_ole(void* pmem)
{
	if(pmem)
	{
		free(pmem);
	}
}

/*-------------------------------------------------------------------------------------------------------
Function		: MemCpySafe
In Parameters	: LPVOID lpDst, DWORD cbDst, LPVOID lpSrc, DWORD dwStart, DWORD dwSize, DWORD dwMaxSize
Out Parameters	: void
Purpose			: copy data safely
Author			: Anand Srivastava
Description		: copy data and throw exception if out of bounds
-------------------------------------------------------------------------------------------------------*/
void CMaxOLE::MemCpySafe(LPVOID lpDst, DWORD cbDst, LPVOID lpSrc, DWORD dwStart, DWORD dwSize, DWORD dwMaxSize)
{
	if(dwStart + dwSize > dwMaxSize)
	{
		//RaiseException(0, 0, 0, 0);
		throw _T("bad MemCpySafe");
		return;
	}
	else
	{
		memcpy_s(lpDst, cbDst, ((LPBYTE)lpSrc) + dwStart, dwSize);
	}
}

/*-------------------------------------------------------------------------------------------------------
Function		: GetWord
In Parameters	: LPVOID lpMemory, DWORD dwStart, DWORD dwMaxSize
Out Parameters	: bool
Purpose			: return word
Author			: Anand Srivastava
Description		: return word and throw exception if out of bounds
-------------------------------------------------------------------------------------------------------*/
WORD CMaxOLE::GetWord(LPVOID lpMemory, DWORD dwStart, DWORD dwMaxSize)
{
	WORD w = 0;

	if(dwStart + sizeof(WORD) > dwMaxSize)
	{
		//RaiseException(0, 0, 0, 0);
		throw _T("bad GetWord");
		return 0;
	}
	else
	{
		w = *((LPWORD)(((LPBYTE)lpMemory) + dwStart));
	}

	return w;
}

/*-------------------------------------------------------------------------------------------------------
Function		: GetDWord
In Parameters	: LPVOID lpMemory, DWORD dwStart, DWORD dwMaxSize
Out Parameters	: bool
Purpose			: return dword safely
Author			: Anand Srivastava
Description		: return dword and throw exception if out of bounds
-------------------------------------------------------------------------------------------------------*/
DWORD CMaxOLE::GetDWord(LPVOID lpMemory, DWORD dwStart, DWORD dwMaxSize)
{
	DWORD d = 0;

	if(dwStart + sizeof(DWORD) > dwMaxSize)
	{
		//RaiseException(0, 0, 0, 0);
		throw _T("bad GetDWord");
		return 0;
	}
	else
	{
		d = *((LPDWORD)(((LPBYTE)lpMemory) + dwStart));
	}

	return d;
}

/*-------------------------------------------------------------------------------------------------------
Function		: CheckForValidOLE
In Parameters	: -
Out Parameters	: bool
Purpose			: Open Storage & Enumerate streams
Author			: Sourabh Kadam
Description		: This Function will Open Storage in read mode and pass handle to ViewDirStorage for 
				  enumerating Storage and Streams.
-------------------------------------------------------------------------------------------------------*/
bool CMaxOLE::CheckForValidOLE()
{
	__try
	{
		return CheckForValidOLE_SEH();
	}

	//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception: CMaxOLE::CheckForValidOLE()")))
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return false;
}

bool CMaxOLE::CheckForValidOLE_SEH()
{
	LPSTORAGE pRootStg = NULL;

	m_bDirProcessed = false;

	//Opening Storage in Read Mode For Traversing the Streams.
	if(FAILED(StgOpenStorage(m_csFilePath, NULL, STGM_SHARE_EXCLUSIVE | STGM_READ, NULL, 0, &pRootStg)))
	{
		DWORD dwError = GetLastError();
		return false;
	}

	ReleaseDirStream();
	ReleaseMacroBuffer();
	if(m_pDecompressionBuffer)
	{
		memset(m_pDecompressionBuffer, 0, m_dwDecompressionBufferSize);
	}

	m_dwLoopCnt = 0;

	//Traversing Storage and Streams for Extraction of Macro.
	if(ViewDirStorage(pRootStg))
	{
		if(m_dwEncMacAddr != 0 && m_dwMacExtracted == 1)
		{
			OleStdRelease(pRootStg);
			return true;
		}
	}

	OleStdRelease(pRootStg);
	return false;
}

/*-------------------------------------------------------------------------------------------------------
Function		: OleStdRelease
In Parameters	: LPSTREAM&
Out Parameters	: -
Purpose			: Release Storage handle
Author			: Sourabh Kadam
Description		: This Function will take storage handle as input and Release storage.
-------------------------------------------------------------------------------------------------------*/
void CMaxOLE::OleStdRelease(LPSTREAM& pUnk)
{
	if(pUnk)
	{
  		pUnk->Release();
		pUnk = NULL;
	}
}

/*-------------------------------------------------------------------------------------------------------
Function		: OleStdRelease
In Parameters	: LPSTORAGE&
Out Parameters	: -
Purpose			: Release Storage handle
Author			: Sourabh Kadam
Description		: This Function will take storage handle as input and Release storage.
-------------------------------------------------------------------------------------------------------*/
void CMaxOLE::OleStdRelease(LPSTORAGE& pUnk)
{
	if(pUnk)
	{
  		pUnk->Release();
		pUnk = NULL;
	}
}

/*-------------------------------------------------------------------------------------------------------
Function		: OleStdRelease
In Parameters	: LPENUMSTATSTG&
Out Parameters	: -
Purpose			: Release Storage handle
Author			: Sourabh Kadam
Description		: This Function will take storage handle as input and Release storage.
-------------------------------------------------------------------------------------------------------*/
void CMaxOLE::OleStdRelease(LPENUMSTATSTG& pUnk)
{
	if(pUnk)
	{
  		pUnk->Release();
		pUnk = NULL;
	}
}

/*-------------------------------------------------------------------------------------------------------
Function		: DecompressStream
In Parameters	: LPBYTE byBuffer, DWORD dwLength
Out Parameters	: -
Purpose			: Decompression of Stream
Author			: Sourabh Kadam
Description		: This Function will loop through compressed chunk and Decompress chunk by chunk.
-------------------------------------------------------------------------------------------------------*/
bool CMaxOLE::DecompressStream(LPBYTE byBuffer, DWORD dwLength)
{
	__try
	{
		//m_byDupReadBuffer = m_byReadBuffer + dwOffset;
		for(m_stDecompressionInfo.CompressedCurrent = 1; m_stDecompressionInfo.CompressedCurrent < m_stDecompressionInfo.CompressedRecordEnd;)
		{
			m_stDecompressionInfo.CompressedChunkStart = m_stDecompressionInfo.CompressedCurrent;
			//m_pCompressedChunk = (CompressedChunk*)(m_byDupReadBuffer + m_stDecompressionInfo.CompressedCurrent);
			//m_pCompressedChunk = (CompressedChunk*)(m_byReadBuffer + m_stDecompressionInfo.CompressedCurrent);
			m_pCompressedChunk = (CompressedChunk*)(byBuffer + m_stDecompressionInfo.CompressedCurrent);
			DecompressCurrentChunk(byBuffer, dwLength);

			if(m_stDecompressionInfo.CompressedCurrent < m_stDecompressionInfo.CompressedRecordEnd)
			{
				AddDecompressionMemory();
			}
		}
		return true;
	}

	//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception: CMaxOLE::DecompressStream()")))
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return false;
}

/*-------------------------------------------------------------------------------------------------------
Function		: ReAllocateDecompressionBuffer
In Parameters	: -
Out Parameters	: -
Purpose			: ReAllocate memory
Author			: Sourabh Kadam
Description		: This Function will reallocate memory.
-------------------------------------------------------------------------------------------------------*/
bool CMaxOLE::ReAllocateDecompressionBuffer()
{
	__try
	{
		if(NULL != m_pDecompressionBuffer)
		{
			memset(m_pDecompressionBuffer, 0, m_dwDecompressionBufferSize);
		}
		else
		{
			m_pDecompressionBuffer = new BYTE[0x1000];
			if(NULL == m_pDecompressionBuffer)
			{
				m_dwDecompressionBufferSize = 0;
				return false;
			}
			m_dwDecompressionBufferSize = 0x1000;
			memset(m_pDecompressionBuffer, 0, m_dwDecompressionBufferSize);
		}

		return true;
	}

	//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception: CMaxOLE::ReAllocateDecompressionBuffer()")))
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return false;
}

/*-------------------------------------------------------------------------------------------------------
Function		: DecompressCurrentChunk
In Parameters	: -
Out Parameters	: bool
Purpose			: Decompress Chunk 
Author			: Sourabh Kadam
Description		: This Function will Decompress memory chunck.
-------------------------------------------------------------------------------------------------------*/
bool CMaxOLE::DecompressCurrentChunk(LPBYTE byBuffer, DWORD dwLength)
{
	__try
	{
		DWORD dwSize = 0;
		DWORD dwFlag = 0;

		dwSize = ExtractSize();
		dwFlag = ExtractFlag();

		m_stDecompressionInfo.DecompressedChunkStart = m_stDecompressionInfo.DecompressedCurrent;
		m_stDecompressionInfo.CompressedEnd =(m_stDecompressionInfo.CompressedRecordEnd < 
											m_stDecompressionInfo.CompressedChunkStart + dwSize ?
											m_stDecompressionInfo.CompressedRecordEnd : 
											m_stDecompressionInfo.CompressedChunkStart + dwSize);
		m_stDecompressionInfo.CompressedCurrent = m_stDecompressionInfo.CompressedChunkStart + 2;

		if(dwFlag == 1)
		{
			while(m_stDecompressionInfo.CompressedCurrent < m_stDecompressionInfo.CompressedEnd)
			{
				DecompressTokenSequence(byBuffer, dwLength);
			}
		}
		else
		{
			DecompressRawChunk(byBuffer, dwLength);
		}

		return true;
	}

	//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception: CMaxOLE::DecompressCurrentChunk()")))
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return false;
}

/*-------------------------------------------------------------------------------------------------------
Function		: ExtractFlag
In Parameters	: -
Out Parameters	: DWORD
Purpose			: Supportive function for DecompressCurrentChunk
Author			: Sourabh Kadam
Description		: This Function will determine flag status.
-------------------------------------------------------------------------------------------------------*/
DWORD CMaxOLE::ExtractFlag()
{
	DWORD dwFlag = 0;

	dwFlag = (m_pCompressedChunk ->Header)& 0x8000;
	dwFlag = dwFlag >> 15;
	return dwFlag;
}

/*-------------------------------------------------------------------------------------------------------
Function		: ExtractSize
In Parameters	: -
Out Parameters	: DWORD
Purpose			: Supportive function for DecompressCurrentChunk
Author			: Sourabh Kadam
Description		: This Function will determine size.
-------------------------------------------------------------------------------------------------------*/
DWORD CMaxOLE::ExtractSize()
{
	DWORD dwSize = 0;

	dwSize = m_pCompressedChunk->Header;
	dwSize = dwSize & 0x0FFF;
	dwSize += 3;
	return dwSize;
}

/*-------------------------------------------------------------------------------------------------------
Function		: DecompressTokenSequence
In Parameters	: -
Out Parameters	: bool
Purpose			: For Decompression
Author			: Sourabh Kadam
-------------------------------------------------------------------------------------------------------*/
bool CMaxOLE::DecompressTokenSequence(LPBYTE byBuffer, DWORD dwLength)
{
	__try
	{
		BYTE byByte;

		//byByte = *(m_byDupReadBuffer + m_stDecompressionInfo.CompressedCurrent);
		//byByte = *(m_byReadBuffer + m_stDecompressionInfo.CompressedCurrent);
		byByte = *(byBuffer + m_stDecompressionInfo.CompressedCurrent);
		m_stDecompressionInfo.CompressedCurrent ++;

		if(m_stDecompressionInfo.CompressedCurrent < m_stDecompressionInfo.CompressedEnd)
		{
			for(int i = 0; i < 8; i ++)
			{
				if(m_stDecompressionInfo.CompressedCurrent < m_stDecompressionInfo.CompressedEnd)
				{
					DecompressToken(byByte, i, byBuffer, dwLength);
				}
			}
		}

		return true;
	}

	//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception: CMaxOLE::DecompressTokenSequence()")))
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return false;
}

/*-------------------------------------------------------------------------------------------------------
Function		: DecompressToken
In Parameters	: -
Out Parameters	: bool
Purpose			: For Decompression
Author			: Sourabh Kadam
-------------------------------------------------------------------------------------------------------*/
bool CMaxOLE::DecompressToken(BYTE byByte, int Index, LPBYTE byBuffer, DWORD dwLength)
{
	__try
	{
		WORD	CopyToken	= 0;
		WORD	Offset		= 0;
		WORD	Length		= 0;
		WORD	OffsetMask	= 0;
		WORD	LengthMask	= 0;
		WORD	BitCount	= 0;
		WORD	MaxLength	= 0;
		WORD	temp1		= 0;
		WORD	temp2		= 0;
		DWORD	CopySource	= 0;
		DWORD	Difference	= 0;
		BYTE	byFlag		=(byByte >> Index)& 1;

		if(byFlag == 0)
		{
			//m_pDecompressionBuffer[m_stDecompressionInfo.DecompressedCurrent]= m_byDupReadBuffer[m_stDecompressionInfo.CompressedCurrent];
			//m_pDecompressionBuffer[m_stDecompressionInfo.DecompressedCurrent]= m_byReadBuffer[m_stDecompressionInfo.CompressedCurrent];
			if(m_stDecompressionInfo.DecompressedCurrent >= m_dwDecompressionBufferSize)
			{
				if(!AddDecompressionMemory())
				{
					return false;
				}
			}

			m_pDecompressionBuffer[m_stDecompressionInfo.DecompressedCurrent] = byBuffer[m_stDecompressionInfo.CompressedCurrent];
			m_stDecompressionInfo.DecompressedCurrent ++;
			m_stDecompressionInfo.CompressedCurrent ++;
		}
		else
		{
			//CopyToken = *(WORD*)(m_byDupReadBuffer + m_stDecompressionInfo.CompressedCurrent);
			//CopyToken = *(WORD*)(m_byReadBuffer + m_stDecompressionInfo.CompressedCurrent);
			CopyToken = *(WORD*)(byBuffer + m_stDecompressionInfo.CompressedCurrent);
			Difference = DWORD(m_stDecompressionInfo.DecompressedCurrent - m_stDecompressionInfo.DecompressedChunkStart);
			BitCount = (WORD)(LogOfBase(Difference, 2) + 0.99999999);
			BitCount =(BitCount > 4 ? BitCount : 4);
			LengthMask = 0xFFFF >> BitCount;
			OffsetMask = ~ LengthMask;
			MaxLength =(0xFFFF >> BitCount) + 3;
			Length =(CopyToken & LengthMask) + 3;
			temp1 = CopyToken & OffsetMask;
			temp2 = 16 - BitCount;
			Offset =(temp1 >> temp2) + 1;

			CopySource = m_stDecompressionInfo.DecompressedCurrent - Offset;

			for(int i = 0; i < Length; i ++)
			{
				if(m_stDecompressionInfo.DecompressedCurrent >= m_dwDecompressionBufferSize)
				{
					if(!AddDecompressionMemory())
					{
						return false;
					}
				}

				m_pDecompressionBuffer[m_stDecompressionInfo.DecompressedCurrent] = m_pDecompressionBuffer[CopySource];
				m_stDecompressionInfo.DecompressedCurrent ++;
				CopySource ++;
			}

			m_stDecompressionInfo.CompressedCurrent += 2;
		}

		return true;
	}

	//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception: CMaxOLE::DecompressToken()")))
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return false;
}

/*-------------------------------------------------------------------------------------------------------
Function		: LogOfBase
In Parameters	: -
Out Parameters	: DOUBLE
Purpose			: For Decompression
Author			: Sourabh Kadam
-------------------------------------------------------------------------------------------------------*/
DOUBLE CMaxOLE::LogOfBase(DWORD Num, int Base)
{
	return ((log((DOUBLE)Num)/ log((DOUBLE)Base)));
}

/*-------------------------------------------------------------------------------------------------------
Function		: DecompressRawChunk
In Parameters	: -
Out Parameters	: bool
Purpose			: For Decompression
Author			: Sourabh Kadam
-------------------------------------------------------------------------------------------------------*/
bool CMaxOLE::DecompressRawChunk(LPBYTE byBuffer, DWORD dwLength)
{
	__try
	{
		if(m_stDecompressionInfo.DecompressedCurrent + 0x1000 > m_dwDecompressionBufferSize)
		{
			return false;
		}

		memcpy_s(m_pDecompressionBuffer + m_stDecompressionInfo.DecompressedCurrent,
				 m_dwDecompressionBufferSize - m_stDecompressionInfo.DecompressedCurrent,
				 byBuffer + m_stDecompressionInfo.CompressedCurrent, 0x1000);
				 //m_byReadBuffer + m_stDecompressionInfo.CompressedCurrent, 0x1000);
				 //m_byDupReadBuffer + m_stDecompressionInfo.CompressedCurrent, 0x1000);
		m_stDecompressionInfo.CompressedCurrent += 0x1000;
		m_stDecompressionInfo.DecompressedCurrent += 0x1000;
		return true;
	}

	//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception: CMaxOLE::DecompressRawChunk()")))
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return false;
}

/*-------------------------------------------------------------------------------------------------------
Function		: AddDecompressionMemory
In Parameters	: -
Out Parameters	: bool
Purpose			: For increasing Decompression memory
Author			: Sourabh Kadam
-------------------------------------------------------------------------------------------------------*/
bool CMaxOLE::AddDecompressionMemory()
{
	__try
	{
		LPBYTE	BufferCopy;

		BufferCopy	=	NULL;
		if(NULL == m_pDecompressionBuffer)
		{
			return false;
		}

		BufferCopy = new BYTE[m_dwDecompressionBufferSize];
		memcpy_s(BufferCopy, m_dwDecompressionBufferSize, m_pDecompressionBuffer, m_dwDecompressionBufferSize);
		delete [] m_pDecompressionBuffer;

		m_dwDecompressionBufferSize += 0x1000;
		m_pDecompressionBuffer = new BYTE[m_dwDecompressionBufferSize];
		memcpy_s(m_pDecompressionBuffer, m_dwDecompressionBufferSize, BufferCopy, m_dwDecompressionBufferSize - 0x1000);

		delete [] BufferCopy;
		return true;
	}

	//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception: CMaxOLE::AddDecompressionMemory()")))
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return false;
}

/*-------------------------------------------------------------------------------------------------------
Function		: InitDirStructure
In Parameters	: -
Out Parameters	: DWORD
Purpose			: For initalising 'Dir' stream structure
Author			: Sourabh Kadam
Description		: This will initialise dir structure ,Which will determine number of macros in VBA
-------------------------------------------------------------------------------------------------------*/
DWORD CMaxOLE::InitDirStructure()
{
	__try
	{
		DWORD dwDecBufPtr = 0;

		m_dwMacExtracted = 0;
		if(m_dwDecompressionBufferSize==0)
		{
			return FALSE;
		}
		MemCpySafe(&m_stDirStream.InformationRecord.SysKindRecord, sizeof(ProjectSysKind),
				   m_pDecompressionBuffer, dwDecBufPtr, sizeof(ProjectSysKind),
				   m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(ProjectSysKind);
		if(m_stDirStream.InformationRecord.SysKindRecord.Id != 0x0001)
		{
			return FALSE;
		}
		MemCpySafe(&m_stDirStream.InformationRecord.LcidRecord, sizeof(ProjectCid), m_pDecompressionBuffer, 
					dwDecBufPtr, sizeof(ProjectCid), m_dwDecompressionBufferSize);	
		dwDecBufPtr += sizeof(ProjectCid);
		if(m_stDirStream.InformationRecord.LcidRecord.Id != 0x0002)
		{
			return FALSE;
		}
		MemCpySafe(&m_stDirStream.InformationRecord.LcidInvokeRecord, sizeof(ProjectlCidInvoke), m_pDecompressionBuffer,
				   dwDecBufPtr, sizeof(ProjectlCidInvoke), m_dwDecompressionBufferSize);
		if(m_stDirStream.InformationRecord.LcidInvokeRecord.Id == 0x0014)
		{
			dwDecBufPtr += sizeof(ProjectlCidInvoke);
		}
		MemCpySafe(&m_stDirStream.InformationRecord.CodePageRecord, sizeof(ProjectCodePage), m_pDecompressionBuffer,
					dwDecBufPtr, sizeof(ProjectCodePage), m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(ProjectCodePage);
		MemCpySafe(&m_stDirStream.InformationRecord.NameRecord, sizeof(ProjectName) - sizeof(LPBYTE), m_pDecompressionBuffer,
				   dwDecBufPtr, sizeof(ProjectName) - sizeof(LPBYTE), m_dwDecompressionBufferSize);	
		dwDecBufPtr = dwDecBufPtr + sizeof(ProjectName) - sizeof(LPBYTE);
		dwDecBufPtr += m_stDirStream.InformationRecord.NameRecord.SizeOfProjectName;
		MemCpySafe(&m_stDirStream.InformationRecord.DocStringRecord,
					sizeof(ProjectDocString) - sizeof(LPBYTE) - sizeof(DWORD) - sizeof(WORD) - sizeof(LPBYTE),
					m_pDecompressionBuffer, dwDecBufPtr, 
					sizeof(ProjectDocString) - sizeof(LPBYTE) - sizeof(DWORD) - sizeof(WORD) - sizeof(LPBYTE),
					m_dwDecompressionBufferSize);
		dwDecBufPtr = dwDecBufPtr + sizeof(ProjectDocString) - sizeof(LPBYTE) - sizeof(DWORD) - sizeof(WORD) - sizeof(LPBYTE);
		if(m_stDirStream.InformationRecord.DocStringRecord.SizeOfDocString != 0)
		{
			dwDecBufPtr += m_stDirStream.InformationRecord.DocStringRecord.SizeOfDocString;
		}
		else
		{
			m_stDirStream.InformationRecord.DocStringRecord.DocString = NULL;
		}
		m_stDirStream.InformationRecord.DocStringRecord.Reserved = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		m_stDirStream.InformationRecord.DocStringRecord.SizeOfDocStringUnicode = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		dwDecBufPtr += m_stDirStream.InformationRecord.DocStringRecord.SizeOfDocStringUnicode;
		m_stDirStream.InformationRecord.HelpFilePathRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		m_stDirStream.InformationRecord.HelpFilePathRecord.SizeOfHelpFile1 = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		if(m_stDirStream.InformationRecord.HelpFilePathRecord.SizeOfHelpFile1 != 0)
		{
			dwDecBufPtr += m_stDirStream.InformationRecord.HelpFilePathRecord.SizeOfHelpFile1;
		}
		else
		{
			m_stDirStream.InformationRecord.HelpFilePathRecord.HelpFile1 = NULL;
		}	
		m_stDirStream.InformationRecord.HelpFilePathRecord.Reserved = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		m_stDirStream.InformationRecord.HelpFilePathRecord.SizeOfHelpFile2 = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		if(m_stDirStream.InformationRecord.HelpFilePathRecord.SizeOfHelpFile2 != 0)
		{
			dwDecBufPtr += m_stDirStream.InformationRecord.HelpFilePathRecord.SizeOfHelpFile2;
		}
		else
		{
			m_stDirStream.InformationRecord.HelpFilePathRecord.HelpFile2 = NULL;
		}

		m_stDirStream.InformationRecord.HelpContextRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		m_stDirStream.InformationRecord.HelpContextRecord.Size = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		m_stDirStream.InformationRecord.HelpContextRecord.HelpContext = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		m_stDirStream.InformationRecord.LibFlagsRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		m_stDirStream.InformationRecord.LibFlagsRecord.Size = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		m_stDirStream.InformationRecord.LibFlagsRecord.ProjectLibFlags = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		m_stDirStream.InformationRecord.VersionRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		m_stDirStream.InformationRecord.VersionRecord.Reserved = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		m_stDirStream.InformationRecord.VersionRecord.VersionMajor = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		m_stDirStream.InformationRecord.VersionRecord.VersionMinor= GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		m_stDirStream.InformationRecord.ConstantsRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		m_stDirStream.InformationRecord.ConstantsRecord.SizeOfConstants = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		if(m_stDirStream.InformationRecord.ConstantsRecord.SizeOfConstants != 0)
		{
			dwDecBufPtr += m_stDirStream.InformationRecord.ConstantsRecord.SizeOfConstants;
		}
		else
		{
			m_stDirStream.InformationRecord.ConstantsRecord.Constants = NULL;
		}
		m_stDirStream.InformationRecord.ConstantsRecord.Reserved = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		m_stDirStream.InformationRecord.ConstantsRecord.SizeOfConstantsUnicode = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		if(m_stDirStream.InformationRecord.ConstantsRecord.SizeOfConstantsUnicode != 0)
		{
			dwDecBufPtr += m_stDirStream.InformationRecord.ConstantsRecord.SizeOfConstantsUnicode;
		}
		else
		{
			m_stDirStream.InformationRecord.ConstantsRecord.ConstantsUnicode = NULL;
		}

		//Next Structure Initialisation
		WORD wProjaectModuleStart = 0x0000;
		do
		{
			m_stDirStream.ReferencesRecord.ReferenceArray.NameRecord.Id =  GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(WORD);
			m_stDirStream.ReferencesRecord.ReferenceArray.NameRecord.SizeOfName =  GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(DWORD);
			if(m_stDirStream.ReferencesRecord.ReferenceArray.NameRecord.SizeOfName != 0)
			{
				dwDecBufPtr += m_stDirStream.ReferencesRecord.ReferenceArray.NameRecord.SizeOfName;
			}
			else
			{
				m_stDirStream.ReferencesRecord.ReferenceArray.NameRecord.Name = NULL;
			}

			m_stDirStream.ReferencesRecord.ReferenceArray.NameRecord.Reserved = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(WORD);
			m_stDirStream.ReferencesRecord.ReferenceArray.NameRecord.SizeOfNameUnicode  = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(DWORD);
			if(m_stDirStream.ReferencesRecord.ReferenceArray.NameRecord.SizeOfNameUnicode != 0)
			{
				dwDecBufPtr += m_stDirStream.ReferencesRecord.ReferenceArray.NameRecord.SizeOfNameUnicode;
			}
			else
			{
				m_stDirStream.ReferencesRecord.ReferenceArray.NameRecord.Name = NULL;
			}

			WORD ReferenceRecordType = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			ReferenceControl varReferenceControl;
			switch(ReferenceRecordType )
			{
			case 0x002F :	
				if(GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize) == 0x0033)
				{
					varReferenceControl.OriginalRecord.Id =  GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(WORD);
					varReferenceControl.OriginalRecord.SizeOfLibidOriginal = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(DWORD);
					if(varReferenceControl.OriginalRecord.SizeOfLibidOriginal != 0)
					{
						dwDecBufPtr += varReferenceControl.OriginalRecord.SizeOfLibidOriginal;
					}
					else
					{
						varReferenceControl.OriginalRecord.LibidOriginal = NULL;
					}

				}
				else
				{
					//return FALSE;
				}
				varReferenceControl.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(WORD);
				varReferenceControl.SizeTwiddled = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(DWORD);
				varReferenceControl.SizeOfLibidTwiddled = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(DWORD);
				if(varReferenceControl.SizeOfLibidTwiddled != 0)
				{
					dwDecBufPtr += varReferenceControl.SizeOfLibidTwiddled;
				}
				else
				{
					varReferenceControl.LibidTwiddled = NULL;
				}

				varReferenceControl.Reserved1 = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(DWORD);
				varReferenceControl.Reserved2 = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(WORD);
				if(varReferenceControl.Reserved2 == 0x003c)
				{
					dwDecBufPtr += sizeof(DWORD);
				}
				do{

					if(GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize) != 0x0030)
					{
						varReferenceControl.NameRecordExtended.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
						dwDecBufPtr += sizeof(WORD);
						varReferenceControl.NameRecordExtended.SizeOfName =  GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
						dwDecBufPtr += sizeof(DWORD);
						if(varReferenceControl.NameRecordExtended.SizeOfName != 0)
						{
							dwDecBufPtr += varReferenceControl.NameRecordExtended.SizeOfName;
						}
						varReferenceControl.NameRecordExtended.Reserved = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
						dwDecBufPtr += sizeof(WORD);
						varReferenceControl.NameRecordExtended.SizeOfNameUnicode = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
						dwDecBufPtr += sizeof(DWORD);
						if(varReferenceControl.NameRecordExtended.SizeOfNameUnicode != 0)
						{
							dwDecBufPtr += varReferenceControl.NameRecordExtended.SizeOfNameUnicode;
						}
					}
					varReferenceControl.Reserved3 = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(WORD);
					varReferenceControl.SizeExtended = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(DWORD);
					dwDecBufPtr += varReferenceControl.SizeExtended; 
				}while(GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize) == 0x0016);

				break;
			case 0x0033 :
				if(GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize) == 0x0033)
				{
					varReferenceControl.OriginalRecord.Id =  GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(WORD);
					varReferenceControl.OriginalRecord.SizeOfLibidOriginal = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(DWORD);
					if(varReferenceControl.OriginalRecord.SizeOfLibidOriginal != 0)
					{
						dwDecBufPtr += varReferenceControl.OriginalRecord.SizeOfLibidOriginal;
					}
					else
					{
						varReferenceControl.OriginalRecord.LibidOriginal = NULL;
					}

				}
				else
				{
					//return FALSE;
				}
				varReferenceControl.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(WORD);
				varReferenceControl.SizeTwiddled = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(DWORD);
				varReferenceControl.SizeOfLibidTwiddled = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(DWORD);
				if(varReferenceControl.SizeOfLibidTwiddled != 0)
				{
					dwDecBufPtr += varReferenceControl.SizeOfLibidTwiddled;
				}
				else
				{
					varReferenceControl.LibidTwiddled = NULL;
				}
				varReferenceControl.Reserved1 = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(DWORD);
				varReferenceControl.Reserved2 = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(WORD);
				if(varReferenceControl.Reserved2 == 0x003c)
				{
					dwDecBufPtr += sizeof(DWORD);

				}
				do{
					varReferenceControl.NameRecordExtended.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(WORD);
					varReferenceControl.NameRecordExtended.SizeOfName =  GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(DWORD);
					if(varReferenceControl.NameRecordExtended.SizeOfName != 0)
					{
						dwDecBufPtr += varReferenceControl.NameRecordExtended.SizeOfName;
					}
					varReferenceControl.NameRecordExtended.Reserved = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(WORD);
					varReferenceControl.NameRecordExtended.SizeOfNameUnicode =  GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(DWORD);
					if(varReferenceControl.NameRecordExtended.SizeOfNameUnicode != 0)
					{
						dwDecBufPtr += varReferenceControl.NameRecordExtended.SizeOfNameUnicode;
					}
					varReferenceControl.Reserved3 =  GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(WORD);
					varReferenceControl.SizeExtended = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(DWORD);
					dwDecBufPtr += varReferenceControl.SizeExtended; 
				}while(GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize) == 0x0016);

				break;
			case 0x000D :	ReferenceRegistered varReferenceRegistered;
				varReferenceRegistered.Id = ReferenceRecordType;
				dwDecBufPtr += sizeof(WORD);
				varReferenceRegistered.Size = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(DWORD);
				varReferenceRegistered.SizeOfLibid = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(DWORD);
				if(varReferenceRegistered.SizeOfLibid !=0)
				{
					dwDecBufPtr += varReferenceRegistered.SizeOfLibid;
				}
				varReferenceRegistered.Reserved1 = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(DWORD);
				varReferenceRegistered.Reserved2 = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(WORD);
				break;
			case 0x000E :
				break;

			default:
				break;
			}
			wProjaectModuleStart = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		}while(wProjaectModuleStart != 0x000F);

		if(wProjaectModuleStart != 0x000F)
			return FALSE;

		DWORD dwNoOfModules;
		m_stDirStream.ModulesRecord.Id = wProjaectModuleStart;
		dwDecBufPtr += sizeof(WORD);
		m_stDirStream.ModulesRecord.Size = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		m_stDirStream.ModulesRecord.Count = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		dwNoOfModules = m_stDirStream.ModulesRecord.Count;
		m_stDirStream.ModulesRecord.ProjectCookieRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		m_stDirStream.ModulesRecord.ProjectCookieRecord.Size = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);
		m_stDirStream.ModulesRecord.ProjectCookieRecord.Cookie = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);
		DWORD dwCntModule = 0;
		m_stDirStream.ModulesRecord.Modules1 = NULL;
		while(dwNoOfModules != 0)
		{
			dwNoOfModules--;
			m_stDirStream.ModulesRecord.Modules1 = (StructModule **)realloc_ole(m_stDirStream.ModulesRecord.Modules1 ,(dwCntModule + 1) * sizeof(StructModule*));
			m_stDirStream.ModulesRecord.Modules1[dwCntModule] = (StructModule*) malloc_ole(sizeof(StructModule));

			m_stDirStream.ModulesRecord.Modules1[dwCntModule]->NameRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			m_stDirStream.ModulesRecord.Modules.NameRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(WORD);

			if(m_stDirStream.ModulesRecord.Modules1[dwCntModule]->NameRecord.Id != 0x0019)
				return 0x0019;

			m_stDirStream.ModulesRecord.Modules1[dwCntModule]->NameRecord.SizeOfModuleName = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			m_stDirStream.ModulesRecord.Modules.NameRecord.SizeOfModuleName = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(DWORD);
			if(m_stDirStream.ModulesRecord.Modules.NameRecord.SizeOfModuleName != 0)
			{
				m_stDirStream.ModulesRecord.Modules1[dwCntModule]->NameRecord.ModuleName = (LPBYTE) malloc_ole(m_stDirStream.ModulesRecord.Modules.NameRecord.SizeOfModuleName);
				if(m_stDirStream.ModulesRecord.Modules.NameRecord.ModuleName)
				{
					free_ole(m_stDirStream.ModulesRecord.Modules.NameRecord.ModuleName);
				}

				m_stDirStream.ModulesRecord.Modules.NameRecord.ModuleName = (LPBYTE) malloc_ole(m_stDirStream.ModulesRecord.Modules.NameRecord.SizeOfModuleName);

				memcpy_s(m_stDirStream.ModulesRecord.Modules1[dwCntModule]->NameRecord.ModuleName, m_stDirStream.ModulesRecord.Modules1[dwCntModule]->NameRecord.SizeOfModuleName, m_pDecompressionBuffer + dwDecBufPtr, m_stDirStream.ModulesRecord.Modules1[dwCntModule]->NameRecord.SizeOfModuleName);
				memcpy_s(m_stDirStream.ModulesRecord.Modules.NameRecord.ModuleName ,m_stDirStream.ModulesRecord.Modules.NameRecord.SizeOfModuleName ,m_pDecompressionBuffer+dwDecBufPtr,m_stDirStream.ModulesRecord.Modules.NameRecord.SizeOfModuleName );	

				dwDecBufPtr += m_stDirStream.ModulesRecord.Modules.NameRecord.SizeOfModuleName ;
			}

			m_stDirStream.ModulesRecord.Modules.NameUnicodeRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(WORD);
			m_stDirStream.ModulesRecord.Modules.NameUnicodeRecord.SizeOfModuleNameUnicode = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(DWORD);
			if(m_stDirStream.ModulesRecord.Modules.NameUnicodeRecord.SizeOfModuleNameUnicode != 0)
			{
				dwDecBufPtr += m_stDirStream.ModulesRecord.Modules.NameUnicodeRecord.SizeOfModuleNameUnicode;
			}

			m_stDirStream.ModulesRecord.Modules.StreamNameRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(WORD);
			m_stDirStream.ModulesRecord.Modules.StreamNameRecord.SizeOfStreamName = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(DWORD);
			if(m_stDirStream.ModulesRecord.Modules.StreamNameRecord.SizeOfStreamName != 0)
			{
				if(m_stDirStream.ModulesRecord.Modules.StreamNameRecord.StreamName)
				{
					free_ole(m_stDirStream.ModulesRecord.Modules.StreamNameRecord.StreamName);
				}

				m_stDirStream.ModulesRecord.Modules.StreamNameRecord.StreamName = (LPBYTE) malloc_ole(m_stDirStream.ModulesRecord.Modules.StreamNameRecord.SizeOfStreamName);
				memcpy_s(m_stDirStream.ModulesRecord.Modules.StreamNameRecord.StreamName, m_stDirStream.ModulesRecord.Modules.StreamNameRecord.SizeOfStreamName, m_pDecompressionBuffer+dwDecBufPtr, m_stDirStream.ModulesRecord.Modules.StreamNameRecord.SizeOfStreamName);
				dwDecBufPtr += m_stDirStream.ModulesRecord.Modules.StreamNameRecord.SizeOfStreamName;
			}
			m_stDirStream.ModulesRecord.Modules.StreamNameRecord.Reserved = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(WORD);
			m_stDirStream.ModulesRecord.Modules.StreamNameRecord.SizeOfStreamNameUnicode = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(DWORD);
			if(m_stDirStream.ModulesRecord.Modules.StreamNameRecord.SizeOfStreamNameUnicode != 0)
			{
				dwDecBufPtr += m_stDirStream.ModulesRecord.Modules.StreamNameRecord.SizeOfStreamNameUnicode ;
			}

			m_stDirStream.ModulesRecord.Modules.DocStringRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(WORD);
			m_stDirStream.ModulesRecord.Modules.DocStringRecord.SizeOfDocString = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(DWORD);
			if(m_stDirStream.ModulesRecord.Modules.DocStringRecord.SizeOfDocString != 0)
			{
				dwDecBufPtr += m_stDirStream.ModulesRecord.Modules.DocStringRecord.SizeOfDocString;
			}
			else
			{
				m_stDirStream.ModulesRecord.Modules.DocStringRecord.DocString = NULL;
			}

			if(m_stDirStream.ModulesRecord.Modules.DocStringRecord.SizeOfDocString != 0)
			{
				m_stDirStream.ModulesRecord.Modules.DocStringRecord.Reserved = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(WORD);
				m_stDirStream.ModulesRecord.Modules.DocStringRecord.SizeOfDocStringUnicode = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				dwDecBufPtr += sizeof(DWORD);
				if(m_stDirStream.ModulesRecord.Modules.DocStringRecord.SizeOfDocStringUnicode != 0)
				{
					dwDecBufPtr += m_stDirStream.ModulesRecord.Modules.DocStringRecord.SizeOfDocStringUnicode;
				}
				else
				{
					m_stDirStream.ModulesRecord.Modules.DocStringRecord.DocStringUnicode = NULL;
				}
			}

			if(GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize) == 0x0048)
			{
				dwDecBufPtr += sizeof(WORD);
				dwDecBufPtr += sizeof(DWORD);
			}

			m_stDirStream.ModulesRecord.Modules1[dwCntModule]->OffsetRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			m_stDirStream.ModulesRecord.Modules.OffsetRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(WORD);
			if(m_stDirStream.ModulesRecord.Modules.OffsetRecord.Id != 0x0031)
				return FALSE;

			m_stDirStream.ModulesRecord.Modules1[dwCntModule]->OffsetRecord.Size = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			m_stDirStream.ModulesRecord.Modules.OffsetRecord.Size = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(DWORD);
			m_stDirStream.ModulesRecord.Modules1[dwCntModule]->OffsetRecord.TextOffset = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			m_stDirStream.ModulesRecord.Modules.OffsetRecord.TextOffset = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(DWORD);

			m_dwEncMacAddr = m_stDirStream.ModulesRecord.Modules.OffsetRecord.TextOffset ;

			m_stDirStream.ModulesRecord.Modules.HelpContextRecord.Id = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(WORD);
			m_stDirStream.ModulesRecord.Modules.HelpContextRecord.Size = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(DWORD);
			m_stDirStream.ModulesRecord.Modules.HelpContextRecord.HelpContext = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(DWORD);

			MemCpySafe(&m_stDirStream.ModulesRecord.Modules.CookieRecord, sizeof(ModuleCookie), m_pDecompressionBuffer, dwDecBufPtr, sizeof(ModuleCookie), m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(ModuleCookie);
			MemCpySafe(&m_stDirStream.ModulesRecord.Modules.TypeRecord, sizeof(ModuleType), m_pDecompressionBuffer, dwDecBufPtr, sizeof(ModuleType), m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(ModuleType);
			MemCpySafe(&m_stDirStream.ModulesRecord.Modules.ReadOnlyRecord, sizeof(ModuleReadonly), m_pDecompressionBuffer, dwDecBufPtr, sizeof(ModuleReadonly), m_dwDecompressionBufferSize);
			dwDecBufPtr += sizeof(ModuleReadonly);
			MemCpySafe(&m_stDirStream.ModulesRecord.Modules.PrivateRecord, sizeof(ModulePrivate), m_pDecompressionBuffer, dwDecBufPtr, sizeof(ModulePrivate), m_dwDecompressionBufferSize);
			if(m_stDirStream.ModulesRecord.Modules.PrivateRecord.Id != 0x0019)
			{
				dwDecBufPtr += sizeof(ModulePrivate);
				m_stDirStream.ModulesRecord.Modules.Terminator = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
				if(m_stDirStream.ModulesRecord.Modules.Terminator != 0x0019)
				{
					dwDecBufPtr += sizeof(WORD);
					m_stDirStream.ModulesRecord.Modules.Reserved = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
					dwDecBufPtr += sizeof(DWORD);
				}
			}
			dwCntModule++;
		}

		m_stDirStream.Terminator = GetWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(WORD);

		m_stDirStream.Reserved = GetDWord(m_pDecompressionBuffer, dwDecBufPtr, m_dwDecompressionBufferSize);
		dwDecBufPtr += sizeof(DWORD);

		return TRUE;
	}

	//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception: CMaxOLE::InitDirStructure()")))
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return FALSE;
}

/*-------------------------------------------------------------------------------------------------------
Function		: ViewDirStorage
In Parameters	: LPSTORAGE
Out Parameters	: HRESULT
Purpose			: For Traversing Storage.
Author			: Sourabh Kadam
Description		: This will traverse Storage , Inintialise 'Dir' structure and Determine no. of macros
-------------------------------------------------------------------------------------------------------*/
HRESULT CMaxOLE::ViewDirStorage(LPSTORAGE pStorage)
{
	__try
	{
		return ViewDirStorage_SEH(pStorage);
	}

	//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception: CMaxOLE::ViewDirStorage()")))
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	
	return FALSE;
}

HRESULT CMaxOLE::ViewDirStorage_SEH(LPSTORAGE pStorage)
{
	LPENUMSTATSTG  pEnum = NULL;
	STATSTG        ss = {0};
	LPSTORAGE      pSubStg = NULL;
	LPSTREAM       pStream = NULL;
	HRESULT        hr = 0;
	ULONG          ulCount = 0;
	LPTSTR		   szType = NULL;
	TCHAR          szTreeString[80] = {0};
	INT            nType = 0;

	hr = pStorage->EnumElements(0, NULL, 0, &pEnum);
	if(NOERROR != hr)
	{	
		OleStdRelease(pEnum);
		return FALSE;
	}

	while(TRUE)
	{
		if(m_dwLoopCnt++ == 1000)
		{
			OleStdRelease(pEnum);
			return FALSE;
		}
		memset(&ss, 0, sizeof(STATSTG));
		hr = pEnum->Next(1, &ss, &ulCount);

		if(S_OK != hr)
		{
			OleStdRelease(pEnum);
			return hr;
		}

		switch(ss.type)
		{
		case STGTY_STREAM:
			szType = _T("Stream");
			nType = TYPE_DOCUMENT;
			break;
		case STGTY_STORAGE:
			szType = _T("Storage");
			nType = TYPE_FOLDER;
			break;
		case STGTY_LOCKBYTES:
			szType = _T("Lockbytes");
			nType = TYPE_FOLDER;
			break;
		case STGTY_PROPERTY:
			szType = _T("Property");
			nType = TYPE_FOLDER;
			break;
		default:
			szType = _T("**Unknown**");
			nType = TYPE_FOLDER;
			break;
		}

		CString strName(ss.pwcsName);
		CString csVBA(_T("Workbook"));
		CString csVBA1(_T("Book"));  
		if(csVBA.CompareNoCase(strName) == 0 || csVBA1.CompareNoCase(strName) == 0)
		{
			// Read the relevant BOF information
			DWORD		dwCount = 0;
			LPSTREAM	pStream_tmp = NULL;
			HRESULT     hrBook = 0;
			XLBOF		xlbof = {0};
			int			iVersion = 0;

			hrBook=pStorage->OpenStream(ss.pwcsName, NULL, STGM_READ | STGM_SHARE_EXCLUSIVE,0, &pStream_tmp);

			//==>sOurabh 17112010
			if(S_OK != hrBook)
			{
				OleStdRelease(pEnum);
				OleStdRelease(pStream_tmp);
				return hr;
			}

			if(hrBook == S_OK)
				pStream_tmp->Read(&xlbof, sizeof(XLBOF), &dwCount);
			OleStdRelease(pStream_tmp);
			// Determine which version to return
			if(xlbof.vers != 0x08) 
			{
				iVersion =(xlbof.vers + 4) / 2;
			}
			else
			{
				switch(xlbof.vers2)
				{
				case 0x0500:  // Either Biff5 or Biff7
					// Biff7's rupYear is at least 1994
					if(xlbof.rupYear < 1994) 
						iVersion = 5;
					break;

					// Check for specific builds of Microsoft Excel 5
					switch(xlbof.rupBuild) 
					{
					case 2412: // XL5a
					case 3218: // XL5c
					case 3321: // NT XL5
						iVersion = 5;
						break;
					default:
						iVersion = 7;
					}
				case 0x0600:  iVersion = 8;
					break;
				}
			}

			// Version not recognized. Perhaps there is a newer version.
			if(iVersion == 0)
				iVersion = -3;

			//Modified ==> Sourabh 12112010
			if(iVersion == -3 || iVersion != 8)		
			{
				OleStdRelease(pEnum);
				return FALSE;
			}

			//Keep this Commented code till testing completion.
			/*CFile file;
			CFileException ex;
			file.Open(_T("c:\\zv\\log\\ExcelDocLog.txt"),CFile::modeWrite|CFile::typeBinary |CFile::modeNoTruncate|CFile::modeCreate,&ex);
			csLogMsg.Format(_T("File: %s , Excel Version %d		\n"),m_csFilePath,iVersion);
			file.SeekToEnd();
			file.Write(csLogMsg,2*csLogMsg.GetLength());
			file.Close();*/

		}

		csVBA.Format(_T("WordDocument"));
		csVBA1.Format(_T("Word"));  
		if(csVBA.CompareNoCase(strName) == 0 || csVBA1.CompareNoCase(strName) == 0)
		{
			// Read the relevant BOF information
			DWORD		dwCount;		
			LPSTREAM	pStream_tmp;
			HRESULT     hrBook;
			FIB fib;
			int			iVersion = 0;

			hrBook=pStorage->OpenStream(ss.pwcsName, NULL, STGM_READ | STGM_SHARE_EXCLUSIVE,0, &pStream_tmp);

			if(S_OK != hrBook)
			{
				OleStdRelease(pEnum);
				OleStdRelease(pStream_tmp);
				return hr;
			}
			if(hrBook == S_OK)
				pStream_tmp->Read(&fib, sizeof(FIB), &dwCount);
			OleStdRelease(pStream_tmp);

			// Determine version to return...
			if(fib.version < 101) 
			{
				OleStdRelease(pEnum);
				return fib.version;
			}

			switch(fib.version) 
			{
			case 101: iVersion = 6;
				break;
			case 103: // fall-through...
				break;
			case 104: iVersion = 7;
				break;
			case 105: iVersion = 8;
				break;
			default: iVersion = 8; // Default, return the latest
			}
			//*        6 for Word 6.0
			//*        7 for Word 7.0 (95)
			//*        8 for Word 8.0 (97)
			//*        Negative if an error occurs...

			// Version not recognized. Perhaps there is a newer version.
			if(iVersion == 0)
				iVersion = -3;

			if(iVersion == -3 || iVersion != 8)
			{
				OleStdRelease(pEnum);
				return FALSE;
			}

			//Keep this Commented code till testing completion.

			/*CFile file;
			CFileException ex;
			file.Open(_T("c:\\zv\\log\\ExcelDocLog.txt"),CFile::modeWrite|CFile::typeBinary |CFile::modeNoTruncate|CFile::modeCreate,&ex);
			csLogMsg.Format(_T("File: %s , Word Version %d		\n"),m_csFilePath,iVersion);
			file.SeekToEnd();
			file.Write(csLogMsg,2*csLogMsg.GetLength());
			file.Close();*/

		}

		memset(szTreeString, 0, sizeof(szTreeString));
		_stprintf_s(szTreeString, _countof(szTreeString), _T("'%s', Type: %s, Size: %lu"), strName, szType, ss.cbSize.LowPart);

		if(STGTY_STREAM == ss.type)
		{
			CString strName(ss.pwcsName);
			CString csVBA(_T("dir")); 

			if(csVBA.CompareNoCase(strName) == 0 && m_bDirProcessed == false)
			{
				hr=pStorage->OpenStream(ss.pwcsName, NULL, STGM_READ | STGM_SHARE_EXCLUSIVE,0, &pStream);
				DWORD ERR = GetLastError();
				if(S_OK != hr)
				{
					OleStdRelease(pEnum);
					OleStdRelease(pStream);
					return hr;
				}

				LPBYTE   pData;
				ULONG    ulsize = ss.cbSize.LowPart;
				ULONG    ulBytesLeft;
				HRESULT  hrW;
				DWORD	 uStreamSize = ss.cbSize.LowPart;

				pData = (LPBYTE)malloc_ole(ss.cbSize.LowPart);
				memset(pData,0x00,ss.cbSize.LowPart);

				hrW = pStream->Read(pData,ulsize,&ulBytesLeft);
				if(S_OK != hrW)
				{
					free_ole(pData);
					OleStdRelease(pEnum);
					OleStdRelease(pStream);
					return hr;
				}

				DWORD				dwpDataPtr = 0;
				const unsigned char vba56_signature[] = { 0xcc, 0x61 };
				unsigned char		version[4] = {0};
				int					is_mac;
				CString				csMsg(_T(""));

				uStreamSize = ulBytesLeft;
				if(*(WORD *)pData + dwpDataPtr == 0x61cc)
				{
					WORD i = 0;
					dwpDataPtr += sizeof(WORD);
					version[3] = *(unsigned char *)(pData + dwpDataPtr);
					dwpDataPtr += sizeof(unsigned char);
					version[2] = *(unsigned char *)(pData + dwpDataPtr);
					dwpDataPtr += sizeof(unsigned char);
					version[1] = *(unsigned char *)(pData + dwpDataPtr);
					dwpDataPtr += sizeof(unsigned char);
					version[0] = *(unsigned char *)(pData + dwpDataPtr);

					for(i = 0; i < NUM_VBA_VERSIONS; i++)
					{
						if(memcmp(version, vba_version[i].signature, sizeof(vba_version[i].signature)) == 0)
						{
							break;
						}

						if (i == NUM_VBA_VERSIONS)
						{

							csMsg.Format(_T("New/Unknown VBA version signature %x %x %x %x\n"),version[0], version[1], version[2], version[3]);
							switch(version[3]) 
							{
							case 0x01:
								csMsg.Format(_T("Guessing little-endian\n"));
								is_mac = FALSE;
								break;
							case 0x0E:
								csMsg.Format(_T("Guessing big-endian\n"));
								is_mac = TRUE;
								break;
							default:
								csMsg.Format(_T("Unable to guess VBA type\n"));
								OleStdRelease(pEnum);
								OleStdRelease(pStream);
								free_ole(pData);
								return FALSE;
							}
						} 
						else 
						{
							csMsg.Format(_T("VBA Project: %s, VBA Version=%d\n"), vba_version[i].name,vba_version[i].vba_version);
							is_mac = vba_version[i].is_mac;
						}
					}
				}

				//m_byReadBuffer = pData; 

				BYTE byBeforeDcmp[0x100] = {0}, byAfterDcmp[0x100] = {0};

				//bBeforeDcmp  = bAfterDcmp = NULL;
				//bBeforeDcmp  = (BYTE *)malloc(0x100);
				//bAfterDcmp	 = (BYTE *)malloc(0x100);
				//memset(bBeforeDcmp,0x00,0x100);
				//memset(bAfterDcmp,0x00,0x100);
				memcpy_s(byBeforeDcmp, 0x100, pData, 0x100);

				if(!ReAllocateDecompressionBuffer())
				{
					OleStdRelease(pEnum);
					OleStdRelease(pStream);
					free_ole(pData);
					return false;
				}

				if(uStreamSize <= 0)
				{
					OleStdRelease(pEnum);
					OleStdRelease(pStream);
					free_ole(pData);
					return false;
				}

				//m_byReadBuffer = pData;
				m_stDecompressionInfo.CompressedRecordEnd = uStreamSize;
				m_stDecompressionInfo.DecompressedCurrent = 0;
				m_stDecompressionInfo.DecompressedChunkStart = 0;

				//if(!DecompressStream(m_byReadBuffer, m_stDecompressionInfo.CompressedRecordEnd))
				if(!DecompressStream(pData, m_stDecompressionInfo.CompressedRecordEnd))
				{
					OleStdRelease(pEnum);
					OleStdRelease(pStream);
					free_ole(pData);
					return false;
				}

				memcpy_s(byAfterDcmp, 0x100, m_pDecompressionBuffer, 0x100);
				if(0 == memcmp(byBeforeDcmp, byAfterDcmp, 0x100))
				{
					OleStdRelease(pEnum);
					OleStdRelease(pStream);
					free_ole(pData);
					return false;
				}

				//free(bBeforeDcmp);
				//free(bAfterDcmp);
				//bBeforeDcmp  =  NULL;
				//bAfterDcmp   =  NULL;

				//Keep this Commented code till testing completion.
				/*CFile file;
				CFileException ex;
				file.Open(_T("c:\\macro.txt"),CFile::modeWrite|CFile::typeBinary|CFile::modeCreate,&ex);
				file.Write(m_pDecompressionBuffer,m_dwDecompressionBufferSize);
				file.Close();*/

				if(!InitDirStructure())
				{
					OleStdRelease(pEnum);
					OleStdRelease(pStream);
					free_ole(pData);
					return false;
				}

				m_bDirProcessed = true;
				OleStdRelease(pStream);
				OleStdRelease(pEnum);
				hr = pStorage->EnumElements(0, NULL, 0, &pEnum);
				free_ole(pData);
			}

			if(m_dwEncMacAddr != 0)
			{
				CString strName(ss.pwcsName);  
				char	szTempString[260] = {0};
				DWORD	dwSize = m_stDirStream.ModulesRecord.Modules.NameRecord.SizeOfModuleName;
				memcpy_s(szTempString,dwSize,m_stDirStream.ModulesRecord.Modules.NameRecord.ModuleName,dwSize);
				CString csVBA(szTempString);

				for(WORD dwCntModule = 0; dwCntModule < m_stDirStream.ModulesRecord.Count; dwCntModule++)
				{
					dwSize = m_stDirStream.ModulesRecord.Modules1[dwCntModule]->NameRecord.SizeOfModuleName;
					memset(szTempString,0,260);
					memcpy_s(szTempString,dwSize,m_stDirStream.ModulesRecord.Modules1[dwCntModule]->NameRecord.ModuleName,dwSize);

					CString csVBA1(szTempString);
					if(csVBA1.CompareNoCase(strName) == 0)
					{
						m_dwEncMacAddr = m_stDirStream.ModulesRecord.Modules1[dwCntModule]->OffsetRecord.TextOffset;
						hr=pStorage->OpenStream(ss.pwcsName, NULL, STGM_READ | STGM_SHARE_EXCLUSIVE,0, &pStream);

						DWORD ERR = GetLastError();
						if(S_OK != hr)
						{
							OleStdRelease(pStream);
							OleStdRelease(pEnum);
							return hr;
						}

						LPBYTE   pData;
						ULONG    ulsize = ss.cbSize.LowPart;
						ULONG    ulBytesLeft;
						HRESULT  hrW;
						DWORD	 uStreamSize = ss.cbSize.LowPart;

						pData = (LPBYTE)malloc_ole(ss.cbSize.LowPart);
						memset(pData,0x00,ss.cbSize.LowPart);
						hrW = pStream->Read(pData,ulsize,&ulBytesLeft);
						if(S_OK != hrW)
						{
							free_ole(pData);
							OleStdRelease(pStream);
							OleStdRelease(pEnum);
							return hr;
						}

						if(!ReAllocateDecompressionBuffer())
						{
							OleStdRelease(pStream);
							OleStdRelease(pEnum);
							free_ole(pData);
							return false;
						}

						uStreamSize = ulBytesLeft;
						if(m_dwEncMacAddr >= uStreamSize)
						{
							OleStdRelease(pStream);
							OleStdRelease(pEnum);
							free_ole(pData);
							return false;
						}

						//m_byReadBuffer = pData + m_dwEncMacAddr;
						m_stDecompressionInfo.CompressedRecordEnd = uStreamSize - m_dwEncMacAddr;
						m_stDecompressionInfo.DecompressedCurrent = 0;
						m_stDecompressionInfo.DecompressedChunkStart = 0;

						if(*(pData + m_dwEncMacAddr) != 0x01)
						{
							OleStdRelease(pStream);
							OleStdRelease(pEnum);
							free_ole(pData);
							return false;
						}

						//if(!DecompressStream(m_byReadBuffer, m_stDecompressionInfo.CompressedRecordEnd))
						if(!DecompressStream(pData + m_dwEncMacAddr, m_stDecompressionInfo.CompressedRecordEnd))
						{
							OleStdRelease(pStream);
							OleStdRelease(pEnum);
							free_ole(pData);
							return false;
						}

						//Keep this code till testing completion.
						//=>
						//CFile file;
						//CFileException ex;
						//CString csFilePathMacro(_T(""));//(m_csFilePath);
						//csFilePathMacro.Format(_T("%s.Macro_%d.Macro"),m_csFilePath,dwCntModule);
						//file.Open(csFilePathMacro,CFile::modeWrite|CFile::typeBinary|CFile::modeCreate,&ex);
						//file.Write(m_pDecompressionBuffer,m_dwDecompressionBufferSize);
						//file.Close();
						//<=

						//==>sOurabh Added on 18112010
						char chDifference = 'a' - 'A';
						for(DWORD i = 0; i < m_dwDecompressionBufferSize; i++)
						{
							if(m_pDecompressionBuffer[i] >= 'A' && m_pDecompressionBuffer[i] <= 'Z')
							{
								m_pDecompressionBuffer[i] = m_pDecompressionBuffer[i] + chDifference;
							}

							//char ch = NULL;

							//ch = (char)m_pDecompressionBuffer[i];
							//if((ch>= 'a') && (ch<= 'z') || (ch>='A') && (ch<='Z'))//convert it into lowercase characters
							//{
							//	if(isupper(ch))
							//	{
							//		ch=tolower(ch);
							//		m_pDecompressionBuffer[i]=ch;
							//	}
							//}
						}//<==sOurabh Added on 18112010

						Macros ** ppHold = (Macros **)realloc_ole(m_ppMacrosVar, (m_dwCntMacroModule + 1) * sizeof(Macros*));
						if(ppHold)
						{
							m_ppMacrosVar = ppHold;
							m_ppMacrosVar[m_dwCntMacroModule] = (Macros *)malloc_ole(sizeof(Macros));
							m_ppMacrosVar[m_dwCntMacroModule]->pbyMacBuff = (LPBYTE)malloc_ole(m_dwDecompressionBufferSize);
							memcpy(m_ppMacrosVar[m_dwCntMacroModule]->pbyMacBuff, m_pDecompressionBuffer, m_dwDecompressionBufferSize);
							m_ppMacrosVar[m_dwCntMacroModule]->dwSizeOfMacro = m_dwDecompressionBufferSize;
							memset(m_ppMacrosVar[m_dwCntMacroModule]->pStreamName, 0, sizeof(m_ppMacrosVar[m_dwCntMacroModule]->pStreamName));
							if(dwSize < sizeof(m_ppMacrosVar[m_dwCntMacroModule]->pStreamName))
							{
								memcpy(m_ppMacrosVar[m_dwCntMacroModule]->pStreamName, szTempString, dwSize);
							}
							else
							{
								memcpy(m_ppMacrosVar[m_dwCntMacroModule]->pStreamName, "LargeName", 9);
							}
							m_dwCntMacroModule++;
							m_dwMacExtracted = 1;
						}

						OleStdRelease(pStream);
						free_ole(pData);
						pData = NULL;
					}
				}
			}
		}

		if(STGTY_STORAGE == ss.type)
		{
			hr=pStorage->OpenStorage(ss.pwcsName, NULL, STGM_READ | STGM_SHARE_EXCLUSIVE,NULL, 0, &pSubStg);
			if(!FAILED(hr))
			{
				ViewDirStorage(pSubStg);
				OleStdRelease(pSubStg);
			}
			else
			{
				if(S_OK != hr)
				{
					OleStdRelease(pSubStg);
					return hr;
				}
			}
		}
	}

	SysFreeString(ss.pwcsName);
	OleStdRelease(pEnum);
	return TRUE;
}

/*-------------------------------------------------------------------------------------------------------
Function		: ReleaseBuffer
In Parameters	: -
Out Parameters	: -
Purpose			: For Free MacroBuffer.
Author			: Sourabh Kadam
Description		: This will free macro buffer
-------------------------------------------------------------------------------------------------------*/
bool CMaxOLE::ReleaseMacroBuffer()
{
	__try
	{
		for(DWORD i = 0; i < m_dwCntMacroModule; i++)
		{
			free_ole(m_ppMacrosVar[i]->pbyMacBuff);
			free_ole(m_ppMacrosVar[i]);
		}

		free_ole(m_ppMacrosVar);
		m_ppMacrosVar = NULL;
		m_dwCntMacroModule = 0;
		return true;
	}

	//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception: MaxOle::ReleaseMacroBuffer()")))
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	m_ppMacrosVar = NULL;
	m_dwCntMacroModule = 0;
	return false;
}

/*-------------------------------------------------------------------------------------------------------
Function		: ReleaseDirStream
In Parameters	: -
Out Parameters	: -
Purpose			: release dir_stream structure memory allocated in initdirstruct
Author			: Anand Srivastava
Description		: release dir_stream structure memory allocated in initdirstruct
-------------------------------------------------------------------------------------------------------*/
bool CMaxOLE::ReleaseDirStream()
{
	for(DWORD i = 0; i < m_stDirStream.ModulesRecord.Count; i++)
	{
		free_ole(m_stDirStream.ModulesRecord.Modules1[i]->NameRecord.ModuleName);
		free_ole(m_stDirStream.ModulesRecord.Modules1[i]);
	}

	free_ole(m_stDirStream.ModulesRecord.Modules1);
	free_ole(m_stDirStream.ModulesRecord.Modules.NameRecord.ModuleName);
	free_ole(m_stDirStream.ModulesRecord.Modules.StreamNameRecord.StreamName);
	memset(&m_stDirStream, 0, sizeof(m_stDirStream));
	return true;
}
