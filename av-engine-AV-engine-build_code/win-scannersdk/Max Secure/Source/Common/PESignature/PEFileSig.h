
/*======================================================================================
FILE             : PEFileSig.h
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

int MDFile15MBLimit(HANDLE hFile, BYTE *Signature, unsigned char *buffer, const int iSizeOfBuffer);

//const int	SIZE_OF_CRC64	 = 8;
//const int	iMAX_SECTIONS	 = 0x40 ;
//const int	iMAX_PRI_SIG_LEN = 0x80 ;
//const int	iMAX_SEC_SIG_LEN = 0x80 ;
//const int	iMAX_MD5_SIG_LEN = 0x10 ;
//const WORD	EXE_SIGNATURE	 = 0x5A4D ;
//const DWORD PE_SIGNATURE	 = 0x00004550 ;
//const DWORD MAX_READ_BUFFER	 = 0x00100000 ;
//const DWORD MAX_HDR_BUFFER	 = 0x00001000 ;
//
//const int	SIG_STATUS_SUCCESS						= 0;
//const int	SIG_STATUS_OPEN_FAILED					= 1;
//const int	SIG_STATUS_NOT_PE_FILE					= 2;
//const int	SIG_STATUS_PRIMARY_SIGNATURE_FAILED		= 3;
//const int	SIG_STATUS_SECONDARY_SIGNATURE_FAILED	= 4;
//const int	SIG_STATUS_MD5_SIGNATURE_FAILED			= 5;
//const int	SIG_STATUS_BUFFER_INVALID				= 6;
//const int	SIG_STATUS_ZERO_BYTE_FILE				= 7;
//
//#pragma pack(1)
//typedef struct _tagPESignatureRaw
//{
//	BYTE	bySig1[iMAX_PRI_SIG_LEN];
//	BYTE	bySig2[iMAX_SEC_SIG_LEN];
//	BYTE	bySig3[iMAX_SEC_SIG_LEN];
//	BYTE	bySig4[iMAX_SEC_SIG_LEN];
//	BYTE	bySig5[iMAX_SEC_SIG_LEN];
//	BYTE	byMD5[iMAX_MD5_SIG_LEN];
//}PESIGRAW, *PPESIGRAW, *LPPESIGRAW;
//#pragma pack()
//
//#pragma pack(1)
//typedef struct _tagPESignatureCRC
//{
//	ULONG64	ulPri;
//	ULONG64	ulSec;
//	ULONG64	ulMD5;
//}PESIGCRC, *PPESIGCRC, *LPPESIGCRC;
//#pragma pack()

class CPEFileSig
{
public:
	CPEFileSig();
	~CPEFileSig();

	int CreateSignature(LPCTSTR csFilePath, PESIGCRC& Signature);
	int OpenFile(LPCTSTR csFilePath);
	int CreatePriSig(LPCTSTR csFilePath, ULONG64& ulPriSig, int* piFirstIndex = 0);
	int CreateSecSig(LPCTSTR csFilePath, ULONG64& ulSecSig, int* piFirstIndex = 0);
	int CreateMD5Sig(LPCTSTR csFilePath, ULONG64& ulMD5Sig);
	int CloseFile();
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

	// main signature creating functions
	bool GetFirstSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);
	bool GetSecondSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);
	bool GetThirdSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);
	bool GetFourthSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);
	bool GetFifthSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);

	// signature creation helper functions
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
};
