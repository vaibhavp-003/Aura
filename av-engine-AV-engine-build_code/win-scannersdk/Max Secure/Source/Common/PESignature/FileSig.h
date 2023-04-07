
/*======================================================================================
FILE             : FileSig.h
ABSTRACT         : declares file signature creation class
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 11 Apr, 2010.
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "PEConstants.h"
#include "MaxPEFile.h"

int MDFile15MBLimit(HANDLE hFile, BYTE *Signature, unsigned char *buffer, const int iSizeOfBuffer);
int MD5Buffer(LPBYTE byData, SIZE_T cbData, LPBYTE byMD5_16Bytes, SIZE_T cbMD5_16Bytes);
int MDFile(HANDLE hFile, LPBYTE byMD5_16Bytes, SIZE_T cbMD5_16Bytes, DWORD dwOffset);

typedef struct _tagDetailFileInfo
{
	bool		bIsPE;
	ULONG64		ulSignature;
	ULONG64		ulFullFileMD5;
	ULONG64		ul15MBFileMD5;
	char		szMD5[33];
}DTL_FINFO, *PDTL_FINFO, *LPDTL_FINFO;

#define FS_NPE		0x00000000
#define FS_EXE		0x00000001
#define FS_DLL		0x00000002
#define FS_ERR		0xFFFFFFFF

class CFileSig
{
public:
	CFileSig();
	~CFileSig();

	int CreateSignature(LPCTSTR csFilePath, ULONG64& ulSignature);
	int CreateSignature(LPCTSTR csFilePath, PESIGCRC& Signature);
	int CreateSignature(LPCTSTR csFilePath, DTL_FINFO& FileInfo);
	int CreateSignature(CMaxPEFile *pMaxPEFile, ULONG64& ulSignature);

	int OpenFile(LPCTSTR csFilePath);
	int CreatePriSig(LPCTSTR csFilePath, ULONG64& ulPriSig, int* piFirstIndex = 0);
	int CreateSecSig(LPCTSTR csFilePath, ULONG64& ulSecSig, int* piFirstIndex = 0);
	int CreateMD5Sig(LPCTSTR csFilePath, ULONG64& ulMD5Sig);
	int CreateMD5SigEx(LPCTSTR csFilePath, ULONG64& ulMD5Sig);
	int CloseFile();
	int GetFileType();
	void SetSignatureParameters(WORD wEPDeflection1, bool bEPDeflectionForward1,
								WORD wEPDeflection2, bool bEPDeflectionForward2 ,
								WORD wCodeSectionDepth , WORD m_wPriLargestSectionDepth ,
								WORD wOverlaySectionDepth , WORD wSecLargestSectionDepth ,
								WORD wEPSectionDepth);
private:
	WORD					m_wEPDeflection1;
	bool					m_bEPDeflectionForward1;
	WORD					m_wEPDeflection2;
	bool					m_bEPDeflectionForward2;
	WORD					m_wCodeSectionDepth;
	WORD					m_wPriLargestSectionDepth;
	WORD					m_wOverlaySectionDepth;
	WORD					m_wSecLargestSectionDepth;
	WORD					m_wEPSectionDepth;

	LPBYTE					m_byReaderBuffer;
	IMAGE_NT_HEADERS32		m_NTFileHeader;
	IMAGE_DOS_HEADER		m_DosHeader;
	IMAGE_SECTION_HEADER	m_SectionHeader[iMAX_SECTIONS];
	DWORD					m_dwEPRVA;
	DWORD					m_dwEPOffset;
	int						m_iEPSecIndex;
	ULONGLONG				m_ulFileSize;
	DWORD					m_dwSectionsCount;
	DWORD					m_dwOverlayOffset;
	DWORD					m_dwOverlayLength;
	HANDLE					m_hHeap;
	int						m_iFirstSigIndex;
	bool					m_bIsValidPE;
	HANDLE					m_hFile;
	BYTE					m_byDataForSignature[(iMAX_PRI_SIG_LEN * 5) + iMAX_FILE_BEGIN_SEC_SIZE];
	bool					m_bCollectDetails;
	DTL_FINFO				m_FileInfo;
	bool					m_bIsBinary;
	CMaxPEFile*				m_pMaxPEFile;

	// main signature creating functions
	bool GetFirstSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);
	bool GetSecondSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);
	bool GetThirdSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);
	bool GetFourthSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);
	bool GetFifthSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);

	// signature creation helper functions
	DWORD SeekFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
	BOOL ReadBuffer(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

	void ResetData();
	bool IsValidPE(HANDLE hFile);
	LPBYTE Allocate(DWORD dwSize);
	bool RVAToOffset(DWORD dwRVA, DWORD& dwOffset, int& iSectionIndex);
	bool IsValidData(LPBYTE byData, SIZE_T cbData, float fAllow = 70.00);
	bool SortSectionsEPLast(IMAGE_SECTION_HEADER* pSortedSec, DWORD& dwSecSize, bool bKeepOverlayAtTop);
	bool SearchSigAreaForward(HANDLE hFile, DWORD dwOffset, DWORD dwLength, LPBYTE byData, DWORD cbData, 
								DWORD cbSkip, DWORD& dwSigOffset);
	bool SearchSigAreaBackward(HANDLE hFile, DWORD dwOffset, DWORD dwLength, LPBYTE byData, DWORD cbData, 
								DWORD cbSkip, DWORD& dwSigOffset);
	bool GetSigArea(DWORD& dwOffset, DWORD& dwLength, WORD wOffPercent, bool bSearchForward);
	bool GetValidData(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD dwOffset, DWORD dwLength,
						WORD wOffPercent, bool bSearchForward, WORD cbSkip, DWORD& dwSigOffset);
	int GetOriginalSectionIndex(IMAGE_SECTION_HEADER* SortedSections, DWORD dwCount, DWORD dwIndex);
	int OpenFileUsingFileObject(CMaxPEFile *pMaxPEFile);
	int CloseFileUsingFileObject();
};
