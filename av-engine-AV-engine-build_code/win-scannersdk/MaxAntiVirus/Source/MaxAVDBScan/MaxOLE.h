/*======================================================================================
FILE				: MaxHelp.h
ABSTRACT			: Scanner for File Type : OLE Files
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 22-Apr-2010
NOTES				: This class module identifies and scan file types : OLE.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include "DirStream.h"
#include "DirStreamStruct.h"

#define	 NUM_VBA_VERSIONS 14

enum
{
	TYPE_BULLET = 1,
	TYPE_FOLDER,
	TYPE_STORAGE,
	TYPE_BLANK,
	TYPE_DOCUMENT
};

typedef enum
{
	DUMP_ERROR = -1,
	DUMP_OK = 0
}DUMPRESULT;

class CMaxOLE
{
	LPBYTE		m_pDecompressionBuffer;
	//LPBYTE		m_byReadBuffer;
	//LPBYTE		m_byDupReadBuffer;
	
	BOOL		m_bDirProcessed;
	DIR_STREAM	m_stDirStream;

	DWORD		m_dwEncMacAddr;
	DWORD		m_dwMacExtracted;
	DWORD		m_dwDecompressionBufferSize;
	DWORD		m_dwLoopCnt;
	
	CompressedChunk*		m_pCompressedChunk;
	DecompressionStates		m_stDecompressionInfo;
	
	DWORD		ExtractFlag();
	DWORD		ExtractSize();
	DWORD		InitDirStructure();

	DOUBLE		LogOfBase(DWORD Num, int Base);
	HRESULT		ViewDirStorage(LPSTORAGE pStorage);

	bool		DecompressStream(LPBYTE byBuffer, DWORD dwLength);
	bool		ReAllocateDecompressionBuffer();
	bool		DecompressCurrentChunk(LPBYTE byBuffer, DWORD dwLength);
	bool		DecompressTokenSequence(LPBYTE byBuffer, DWORD dwLength);
	bool		DecompressToken(BYTE byByte, int Index, LPBYTE byBuffer, DWORD dwLength);
	bool		DecompressRawChunk(LPBYTE byBuffer, DWORD dwLength);
	bool		AddDecompressionMemory();

	void		OleStdRelease(LPSTREAM& pUnk);
	void		OleStdRelease(LPSTORAGE& pUnk);
	void		OleStdRelease(LPENUMSTATSTG& pUnk);
	bool		CheckForValidOLE_SEH();
	HRESULT		ViewDirStorage_SEH(LPSTORAGE pStorage);
	void		MemCpySafe(LPVOID lpDst, DWORD cbDst, LPVOID lpSrc, DWORD dwStart, DWORD dwSize, DWORD dwMaxSize);
	WORD		GetWord(LPVOID lpMemory, DWORD dwStart, DWORD dwMaxSize);
	DWORD		GetDWord(LPVOID lpMemory, DWORD dwStart, DWORD dwMaxSize);
	void		free_ole(void* pmem);
	void*		malloc_ole(size_t size);
	void*		realloc_ole(void * pexisting, size_t size);
	bool		ReleaseDirStream();

public:
	CString		m_csFilePath;
	Macros		**m_ppMacrosVar;
	DWORD		m_dwCntMacroModule;

	CMaxOLE();
	~CMaxOLE();

	bool		CheckForValidOLE();
	bool		ReleaseMacroBuffer();

};
