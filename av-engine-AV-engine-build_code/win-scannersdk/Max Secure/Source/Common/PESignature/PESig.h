
/*======================================================================================
FILE             : PESig.h
ABSTRACT         : declares pe signatures creation class
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
				  
CREATION DATE    : 25 Dec, 2009.
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "PEConstants.h"

class CPESig
{
public:
	CPESig();
	~CPESig();

	int CreateSignature(LPCTSTR csFilePath, ULONGLONG ulFileSize, PESIG& Signature,
						DWORD& dwPriSigOff, DWORD& dwSecSigOff);
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

	void ResetData();
	bool IsValidPE(HANDLE hFile);
	int IsValidPEReadOnce(HANDLE hFile);
	LPBYTE Allocate(DWORD dwSize);
	bool RVAToOffset(DWORD dwRVA, DWORD& dwOffset, int& iSectionIndex);
	bool IsValidData(LPBYTE byData, SIZE_T cbData, float fAllow = 70.00);
	bool SortSectionsEPLast(IMAGE_SECTION_HEADER* pSortedSec, DWORD& dwSecSize, bool bKeepOverlayAtTop);
	bool GetPriSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);
	bool GetSecSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset);
	bool SearchSigAreaForward(HANDLE hFile, DWORD dwOffset, DWORD dwLength, LPBYTE byData, DWORD cbData, 
								DWORD cbSkip, DWORD& dwSigOffset);
	bool SearchSigAreaBackward(HANDLE hFile, DWORD dwOffset, DWORD dwLength, LPBYTE byData, DWORD cbData, 
								DWORD cbSkip, DWORD& dwSigOffset);
	bool GetSigArea(DWORD& dwOffset, DWORD& dwLength, WORD wOffPercent, bool bSearchForward);
	bool GetValidData(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD dwOffset, DWORD dwLength,
						WORD wOffPercent, bool bSearchForward, WORD cbSkip, DWORD& dwSigOffset);
};
