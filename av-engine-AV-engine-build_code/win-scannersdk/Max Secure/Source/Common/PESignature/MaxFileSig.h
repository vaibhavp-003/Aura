/*======================================================================================
FILE             : MaxFileSig.h
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
				  
CREATION DATE    : 27 April 2011
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "PEConstants.h"

int MDFile(HANDLE hFile, BYTE *Signature, unsigned char *buffer, const int iSizeOfBuffer);
int MDFile15MBLimit(HANDLE hFile, BYTE *Signature, unsigned char *buffer, const int iSizeOfBuffer);
int MD5Buffer(LPBYTE byData, SIZE_T cbData, LPBYTE byMD5_16Bytes, SIZE_T cbMD5_16Bytes);

const int iSIZE_SIG_RGN		= 128;
const int iSIZE_RDR_BLOCK	= 4 * 1024;

typedef struct _tagDetailMaxFileInfo
{
	bool		bIsPE;
	ULONG64		ulSig;
	ULONG64		ulMD5;
	ULONG64		ulFileSize;
	TCHAR		szMD5[33];
	BYTE		byMD5[16];
}DTL_MAXFINFO, *PDTL_MAXFINFO, *LPDTL_MAXFINFO;

#pragma pack(1)
typedef struct _tagSignatureRegion
{
	BYTE	by1[iSIZE_SIG_RGN];
	BYTE	by2[iSIZE_SIG_RGN];
	BYTE	by3[iSIZE_SIG_RGN];
	BYTE	by4[iSIZE_SIG_RGN];
	BYTE	by5[iSIZE_SIG_RGN];
	BYTE	by6[iSIZE_SIG_RGN];
}SIG_RGN, *LPSIG_RGN;

typedef union _tagSignatureData
{
	SIG_RGN	stRgn;
	BYTE	byData[sizeof(SIG_RGN)];
}SIG_DATA, *PSIG_DATA, *LPSIG_DATA;
#pragma pack()

#define FS_NPE		0x00000000
#define FS_EXE		0x00000001
#define FS_DLL		0x00000002
#define FS_ERR		0xFFFFFFFF

class CMaxFileSig
{
public:
	CMaxFileSig();
	~CMaxFileSig();

	int CreateSignature(LPCTSTR csFilePath, ULONG64& ulSignature);
	int CreateSignature(LPCTSTR csFilePath, DTL_MAXFINFO& FileInfo);
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
	LPBYTE					m_byReaderBlock;
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
	bool					m_bValidPE;
	HANDLE					m_hFile;
	SIG_DATA				m_unSigData;
	bool					m_bIsBinary;
	bool					m_bValidOverlayBlockRead;
	bool					m_bOverlayIsInvalid;

	// main signature creating functions
	bool GetFirstRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset);
	bool GetSecondRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset);
	bool GetThirdRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset);
	bool GetFourthRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset);
	bool GetFifthRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset);
	bool GetSixthRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset);
	bool ReadFlatRegion(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset, int iPart);
	int CollectDataForSignature();
	int CreateSignatureFromData(ULONG64& ulSignature);

	// signature creation helper functions
	void ResetData();
	int OpenFile(LPCTSTR csFilePath);
	int CloseFile();
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
	bool GetBlockData(HANDLE hFile, DWORD dwOffset, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset);
};
