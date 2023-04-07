
/*======================================================================================
FILE             : FileSig.cpp
ABSTRACT         : defines file signature creation class. Given a file it can create signature
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
				  
CREATION DATE    : 11 Apr, 2010
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "FileSig.h"
#include "BalBST.h"

/*--------------------------------------------------------------------------------------
Function       : CFileSig
In Parameters  : 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CFileSig::CFileSig()
{
	m_wEPDeflection1 = 60;
	m_bEPDeflectionForward1 = false;
	m_wEPDeflection2 = 25;
	m_bEPDeflectionForward2 = true;
	m_wCodeSectionDepth = 40;
	m_wPriLargestSectionDepth = 40;
	m_wOverlaySectionDepth = 40;
	m_wSecLargestSectionDepth = 40;
	m_wEPSectionDepth = 20;

	m_bCollectDetails = false;
	m_byReaderBuffer = NULL;
	memset(&m_DosHeader, 0, sizeof(m_DosHeader));
	memset(&m_NTFileHeader, 0, sizeof(m_NTFileHeader));
	memset(&m_SectionHeader, 0, sizeof(m_SectionHeader));
	m_iFirstSigIndex = -1;
	m_dwEPRVA = 0;
	m_dwEPOffset = 0;
	m_iEPSecIndex = 0;
	m_ulFileSize = 0;
	m_dwSectionsCount = 0;
	m_dwOverlayOffset = 0;
	m_dwOverlayLength = 0;
	m_hHeap = NULL;
	m_ulFileSize = 0;
	m_bIsValidPE = false;
	m_bIsBinary = false;
	m_hFile = INVALID_HANDLE_VALUE;
	m_pMaxPEFile = NULL;

	m_byReaderBuffer = Allocate(MAX_READ_BUFFER);
}

/*--------------------------------------------------------------------------------------
Function       : ~CFileSig
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CFileSig::~CFileSig()
{
	if(m_hHeap)
	{
		if(m_byReaderBuffer)
		{
			HeapFree(m_hHeap, 0, m_byReaderBuffer);
		}

		HeapDestroy(m_hHeap);
	}

	m_hHeap = NULL;
	m_byReaderBuffer = NULL;
	CloseFile();
}

/*--------------------------------------------------------------------------------------
Function       : ResetData
In Parameters  : 
Out Parameters : 
Description    : resets all the class member data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CFileSig::ResetData()
{
	if(m_byReaderBuffer)
	{
		memset(m_byReaderBuffer, 0, MAX_READ_BUFFER);
	}

	memset(&m_DosHeader, 0, sizeof(m_DosHeader));
	memset(&m_NTFileHeader, 0, sizeof(m_NTFileHeader));
	memset(&m_SectionHeader, 0, sizeof(m_SectionHeader));
	m_iFirstSigIndex = -1;
	m_dwEPRVA = 0;
	m_dwEPOffset = 0;
	m_iEPSecIndex = 0;
	m_dwSectionsCount = 0;
	m_dwOverlayOffset = 0;
	m_dwOverlayLength = 0;
	m_ulFileSize = 0;
	m_bIsValidPE = false;
	m_bIsBinary = false;
}

/*--------------------------------------------------------------------------------------
Function       : SetSignatureParameters
In Parameters  : WORD wEPDeflection1, bool bEPDeflectionForward1, WORD wEPDeflection2,
				 bool bEPDeflectionForward2, WORD wCodeSectionDepth,
				 WORD wPriLargestSectionDepth, WORD wOverlaySectionDepth,
				 WORD wSecLargestSectionDepth, WORD wEPSectionDepth 
Out Parameters : void 
Description    : sets the parameters which define locations to pick signature from a file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CFileSig::SetSignatureParameters(WORD wEPDeflection1, bool bEPDeflectionForward1, WORD wEPDeflection2,
									   bool bEPDeflectionForward2, WORD wCodeSectionDepth,
									   WORD wPriLargestSectionDepth, WORD wOverlaySectionDepth,
									   WORD wSecLargestSectionDepth, WORD wEPSectionDepth)
{
	m_wEPDeflection1 = wEPDeflection1;
	m_bEPDeflectionForward1 = bEPDeflectionForward1;
	m_wEPDeflection2 = wEPDeflection2;
	m_bEPDeflectionForward2 = bEPDeflectionForward2;
	m_wCodeSectionDepth = wCodeSectionDepth;
	m_wPriLargestSectionDepth = wPriLargestSectionDepth;
	m_wOverlaySectionDepth = wOverlaySectionDepth;
	m_wSecLargestSectionDepth = wSecLargestSectionDepth;
	m_wEPSectionDepth = wEPSectionDepth;
}

/*--------------------------------------------------------------------------------------
Function       : Allocate
In Parameters  : DWORD dwSize
Out Parameters : LPBYTE 
Description    : create heap and allocate memory
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
LPBYTE CFileSig::Allocate(DWORD dwSize)
{
	LPBYTE lpMemory = NULL;

	if(NULL == m_hHeap)
	{
		m_hHeap = HeapCreate(0, 2 * 1024 * 1024, 0);
		if(NULL == m_hHeap)
		{
			return NULL;
		}
	}

	lpMemory = (LPBYTE)HeapAlloc(m_hHeap, HEAP_ZERO_MEMORY, dwSize);
	return lpMemory;
}

/*--------------------------------------------------------------------------------------
Function       : IsValidData
In Parameters  : LPBYTE byData, SIZE_T cbData, float fAllow, 
Out Parameters : bool 
Description    : check if the passed buffer has non-repetitive data valid data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::IsValidData(LPBYTE byData, SIZE_T cbData, float fAllow)
{
	bool bValidData = true;
	WORD CharList[0x100]={0};
	WORD wAllowedCount = (WORD)(((double)cbData / ((double)100.00)) * ((double)fAllow));

	for(SIZE_T i = 0; i < cbData; i++)
	{
		CharList[byData[i]] ++;
		if(CharList[byData[i]] > wAllowedCount)
		{
			bValidData = false;
			break;
		}
	}

	return bValidData;
}

/*--------------------------------------------------------------------------------------
Function       : GetOriginalSectionIndex
In Parameters  : IMAGE_SECTION_HEADER* SortedSections, DWORD dwCount, DWORD dwIndex
Out Parameters : bool 
Description    : get index of original sections sequence
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::GetOriginalSectionIndex(IMAGE_SECTION_HEADER* SortedSections, DWORD dwCount, DWORD dwIndex)
{
	int iOrgIndex = -1;

	for(DWORD i = 0; i < m_dwSectionsCount && -1 == iOrgIndex; i++)
	{
		if( m_SectionHeader[i].VirtualAddress == SortedSections[dwIndex].VirtualAddress &&
			m_SectionHeader[i].SizeOfRawData == SortedSections[dwIndex].SizeOfRawData &&
			m_SectionHeader[i].PointerToRawData == SortedSections[dwIndex].PointerToRawData)
		{
			iOrgIndex = i;
		}
	}

	return iOrgIndex;
}

/*--------------------------------------------------------------------------------------
Function       : RVAToOffset
In Parameters  : DWORD dwRVA, DWORD& dwOffset, int& iSectionIndex, 
Out Parameters : bool 
Description    : convert rva into file offset
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::RVAToOffset(DWORD dwRVA, DWORD& dwOffset, int& iSectionIndex)
{
	bool bFileOffsetFound = false;
	DWORD dwSecOffset = 0, dwSecLength = 0;

	for(DWORD i = 0; i < m_dwSectionsCount; i++)
	{
		dwSecOffset = m_SectionHeader[i].VirtualAddress;

		if(m_SectionHeader[i].SizeOfRawData)
		{
			dwSecLength = m_SectionHeader[i].SizeOfRawData;
		}
		else if(m_SectionHeader[i].Misc.VirtualSize)
		{
			dwSecLength = m_SectionHeader[i].Misc.VirtualSize;
		}
		else
		{
			dwSecLength = 0;
		}

		if((dwSecOffset <= dwRVA) &&(dwSecOffset + dwSecLength > dwRVA))
		{
			bFileOffsetFound = true;
			dwRVA -= dwSecOffset;
			dwOffset = dwRVA + m_SectionHeader[i].PointerToRawData;
			iSectionIndex = i;
			break;
		}
	}

	/*if(!bFileOffsetFound)
	{
		if(dwRVA <= m_ulFileSize)
		{
			dwOffset = dwRVA;
			iSectionIndex = -1;
			bFileOffsetFound = true;
		}
	}*/

	return bFileOffsetFound;
}

/*--------------------------------------------------------------------------------------
Function       : SortSectionsEPLast
In Parameters  : IMAGE_SECTION_HEADER* pSortedSec, DWORD& dwSecSize, bool bKeepOverlayAtTop, 
Out Parameters : bool 
Description    : sort the sections list and keep EP section last and overlay at top
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::SortSectionsEPLast(IMAGE_SECTION_HEADER* pSortedSec, DWORD& dwSecSize, bool bKeepOverlayAtTop)
{
	bool bChanged = false;
	int iArraySize = 0, iBeginIndex = 0;

	iArraySize = 0;
	if(0 != m_dwOverlayLength)
	{
		pSortedSec[iArraySize].PointerToRawData = m_dwOverlayOffset;
		pSortedSec[iArraySize].SizeOfRawData = m_dwOverlayLength;
		iArraySize++;

		if(bKeepOverlayAtTop)
		{
			iBeginIndex = 1;
		}
	}

	for(DWORD i = 0; i < m_dwSectionsCount; i++)
	{
		if(i == m_iEPSecIndex)
			continue;

		pSortedSec[iArraySize]= m_SectionHeader[i];
		iArraySize++;
	}

	for(int i = iBeginIndex; iArraySize != 0 && i < iArraySize; i++)
	{
		bChanged = false;
		for(int j = iBeginIndex; j < iArraySize - 1; j++)
		{
			if(pSortedSec[j].SizeOfRawData < pSortedSec[j + 1].SizeOfRawData)
			{
				IMAGE_SECTION_HEADER Hold ={0};

				bChanged = true;
				Hold = pSortedSec[j];
				pSortedSec[j]= pSortedSec[j + 1];
				pSortedSec[j + 1]= Hold;
				j--;
			}
		}

		if(false == bChanged)
			break;
	}

	if(-1 != m_iEPSecIndex)
	{
		pSortedSec[iArraySize]= m_SectionHeader[m_iEPSecIndex];
		iArraySize++;
	}

	dwSecSize = iArraySize;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : SearchSigAreaForward
In Parameters  : HANDLE hFile, DWORD dwOffset, DWORD dwLength, LPBYTE byData, 
Out Parameters : bool 
Description    : search for valid signature in the area by moving forward
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::SearchSigAreaForward(HANDLE hFile, DWORD dwOffset, DWORD dwLength, LPBYTE byData,
									 DWORD cbData, DWORD cbSkip, DWORD& dwSigOffset)
{
	bool bFound = false, bSkippedOnce = false;
	DWORD dwBytesToRead = 0, dwBytesRead = 0, dwTotalBytesToRead = 0, dwTotalBytesRead = 0;

	dwTotalBytesToRead = dwLength;
	bSkippedOnce = 0 == cbSkip;

	while(dwTotalBytesRead < dwTotalBytesToRead)
	{
		if(dwTotalBytesToRead - dwTotalBytesRead > MAX_READ_BUFFER)
		{
			dwBytesToRead = MAX_READ_BUFFER;
		}
		else
		{
			dwBytesToRead = dwTotalBytesToRead - dwTotalBytesRead;
		}

		if(INVALID_SET_FILE_POINTER == SeekFilePointer(hFile, dwOffset + dwTotalBytesRead, 0, FILE_BEGIN))
		{
			break;
		}

		if(!ReadBuffer(hFile, m_byReaderBuffer, dwBytesToRead, &dwBytesRead, 0))
		{
			break;
		}

		if(dwBytesRead < cbData)
		{
			break;
		}

		dwBytesRead = dwBytesRead / cbData;
		dwBytesRead = dwBytesRead * cbData;

		for(DWORD i = 0; i < dwBytesRead; i += cbData)
		{
			bFound = IsValidData(m_byReaderBuffer + i, cbData);

			if(bFound)
			{
				if(bSkippedOnce)
				{
					memcpy(byData, m_byReaderBuffer + i, cbData);
					dwSigOffset = dwOffset + dwTotalBytesRead + i;
					break;
				}
				else
				{
					bSkippedOnce = true;
					bFound = false;
				}
			}
		}

		if(bFound)
		{
			break;
		}

		dwTotalBytesRead += dwBytesRead;
	}

	return bFound;
}

/*--------------------------------------------------------------------------------------
Function       : SearchSigAreaBackward
In Parameters  : HANDLE hFile, DWORD dwOffset, DWORD dwLength, LPBYTE byData, 
Out Parameters : bool 
Description    : search for valid signature in the area by moving backward
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::SearchSigAreaBackward(HANDLE hFile, DWORD dwOffset, DWORD dwLength, LPBYTE byData,
									  DWORD cbData, DWORD cbSkip, DWORD& dwSigOffset)
{
	bool bFound = false, bSkippedOnce = false;
	DWORD dwBytesToRead = 0, dwBytesRead = 0, dwTotalBytesToRead = 0, dwTotalBytesRead = 0;
	DWORD dwRemainder = 0, dwReadOffset = 0;

	dwReadOffset = dwOffset + dwLength;
	dwTotalBytesToRead = dwLength;
	bSkippedOnce = 0 == cbSkip;

	while(dwTotalBytesRead < dwTotalBytesToRead)
	{
		if(dwTotalBytesToRead - dwTotalBytesRead > MAX_READ_BUFFER)
		{
			dwBytesToRead = MAX_READ_BUFFER;
		}
		else
		{
			dwBytesToRead = dwTotalBytesToRead - dwTotalBytesRead;
		}

		dwReadOffset -= dwBytesToRead;
		if(INVALID_SET_FILE_POINTER == SeekFilePointer(hFile, dwReadOffset, 0, FILE_BEGIN))
		{
			break;
		}

		if(!ReadBuffer(hFile, m_byReaderBuffer, dwBytesToRead, &dwBytesRead, 0))
		{
			break;
		}

		if(dwBytesToRead < cbData)
		{
			break;
		}

		dwRemainder = dwBytesRead % cbData;
		dwBytesRead = dwBytesRead / cbData;
		dwBytesRead = dwBytesRead * cbData;

		for(int i = dwBytesRead - cbData; i >= 0; i -= cbData)
		{
			bFound = IsValidData(m_byReaderBuffer + i, cbData);

			if(bFound)
			{
				if(bSkippedOnce)
				{
					memcpy(byData, m_byReaderBuffer + i, cbData);
					dwSigOffset = dwReadOffset + dwRemainder + i;
					break;
				}
				else
				{
					bSkippedOnce = true;
					bFound = false;
				}
			}
		}

		if(bFound)
		{
			break;
		}

		dwTotalBytesRead += dwBytesRead;
		dwReadOffset += dwRemainder;
	}

	return bFound;
}

/*--------------------------------------------------------------------------------------
Function       : GetSigArea
In Parameters  : DWORD& dwOffset, DWORD& dwLength, WORD wOffPercent, bool bSearchForward, 
Out Parameters : bool 
Description    : find the file area in which signature will be searched later
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::GetSigArea(DWORD& dwOffset, DWORD& dwLength, WORD wOffPercent, bool bSearchForward)
{
	DWORD dwPercentSize = 0;

	if(0 == dwLength)
	{
		return false;
	}

	if(dwOffset <= m_dwEPOffset && m_dwEPOffset < dwOffset + dwLength)
	{
		if(bSearchForward)
		{
			dwLength =(dwOffset + dwLength) - m_dwEPOffset;
			dwOffset = m_dwEPOffset;
		}
		else
		{
			dwLength = m_dwEPOffset - dwOffset;
		}
	}

	if(0 == dwLength)
	{
		return false;
	}

	dwPercentSize =(DWORD)((((double)dwLength) / ((double)100.00)) * ((double)wOffPercent));

	if(bSearchForward)
	{
		dwOffset += dwPercentSize;
		dwLength -= dwPercentSize;
	}
	else
	{
		dwOffset =(dwOffset + dwLength) - dwPercentSize;
		dwLength = dwPercentSize;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetValidData
In Parameters  : HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD dwOffset, DWORD dwLength, 
Out Parameters : bool 
Description    : get valid signature, decide area then search signature in that area
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::GetValidData(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD dwOffset, DWORD dwLength,
							 WORD wOffPercent, bool bSearchForward, WORD cbSkip, DWORD& dwSigOffset)
{
	if(!GetSigArea(dwOffset, dwLength, wOffPercent, bSearchForward))
	{
		return false;
	}

	if(bSearchForward)
	{
		if(!SearchSigAreaForward(hFile, dwOffset, dwLength, byData, cbData, cbSkip, dwSigOffset))
		{
			return false;
		}
	}
	else
	{
		if(!SearchSigAreaBackward(hFile, dwOffset, dwLength, byData, cbData, cbSkip, dwSigOffset))
		{
			return false;
		}
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetFirstSig
In Parameters  : HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset, 
Out Parameters : bool 
Description    : get valid primary signature for file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::GetFirstSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset)
{
	DWORD dwSortedSections = _countof(m_SectionHeader) + 1;
	IMAGE_SECTION_HEADER SortedSections[_countof(m_SectionHeader) + 1]={0};

	if(-1 != m_iEPSecIndex)
	{
		if(GetValidData(hFile, bySignature, cbSignature, m_SectionHeader[m_iEPSecIndex].PointerToRawData,
						m_SectionHeader[m_iEPSecIndex].SizeOfRawData, m_wEPDeflection1,
						m_bEPDeflectionForward1, 0, dwSigOffset))
		{
			m_iFirstSigIndex = m_iEPSecIndex;
			return true;
		}

		if(GetValidData(hFile, bySignature, cbSignature, m_SectionHeader[m_iEPSecIndex].PointerToRawData,
						m_SectionHeader[m_iEPSecIndex].SizeOfRawData, m_wEPDeflection2,
						m_bEPDeflectionForward2, 0, dwSigOffset))
		{
			m_iFirstSigIndex = m_iEPSecIndex;
			return true;
		}
	}

	SortSectionsEPLast(SortedSections, dwSortedSections, true);
	if(0 == dwSortedSections)
	{
		return false;
	}

	for(DWORD i = 0; dwSortedSections && i < dwSortedSections - 1; i++)
	{
		if(((SortedSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE) ||
			((SortedSections[i].Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE))
		{
			if(GetValidData(hFile, bySignature, cbSignature, SortedSections[i].PointerToRawData,
							SortedSections[i].SizeOfRawData, m_wCodeSectionDepth, true, 0, dwSigOffset))
			{
				m_iFirstSigIndex = GetOriginalSectionIndex(SortedSections, _countof(SortedSections), i);
				return true;
			}
		}
	}

	for(DWORD i = 0; i < dwSortedSections; i++)
	{
		if(((SortedSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE) ||
			((SortedSections[i].Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE))
		{
			if(GetValidData(hFile, bySignature, cbSignature, SortedSections[i].PointerToRawData,
							SortedSections[i].SizeOfRawData, m_wPriLargestSectionDepth, true, 0,
							dwSigOffset))
			{
				m_iFirstSigIndex = GetOriginalSectionIndex(SortedSections, _countof(SortedSections), i);
				return true;
			}
		}
	}

	if(-1 != m_iEPSecIndex)
	{
		if(GetValidData(hFile, bySignature, cbSignature, m_SectionHeader[m_iEPSecIndex].PointerToRawData,
						m_SectionHeader[m_iEPSecIndex].SizeOfRawData, m_wCodeSectionDepth, true, 0,
						dwSigOffset))
		{
			m_iFirstSigIndex = m_iEPSecIndex;
			return true;
		}
	}

	return false;
}

/*--------------------------------------------------------------------------------------
Function       : GetSecondSig
In Parameters  : HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset, 
Out Parameters : bool 
Description    : get valid secondary signature for file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::GetSecondSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset)
{
	DWORD dwSortedSections = _countof(m_SectionHeader) + 1;
	IMAGE_SECTION_HEADER SortedSections[_countof(m_SectionHeader) + 1] = {0};
	DWORD dwBeginIndex = 0;

	if(0 != m_dwOverlayLength)
	{
		if(GetValidData(hFile, bySignature, cbSignature, m_dwOverlayOffset, m_dwOverlayLength,
			m_wOverlaySectionDepth, true, iMAX_PRI_SIG_LEN, dwSigOffset))
		{
			return true;
		}

		dwBeginIndex = 1;
	}

	SortSectionsEPLast(SortedSections, dwSortedSections, true);
	if(0 == dwSortedSections)
	{
		return false;
	}

	for(DWORD i = dwBeginIndex; i < dwSortedSections - 1; i++)
	{
		if(GetValidData(hFile, bySignature, cbSignature, SortedSections[i].PointerToRawData,
			SortedSections[i].SizeOfRawData, m_wSecLargestSectionDepth, true,
			iMAX_PRI_SIG_LEN, dwSigOffset))
		{
			return true;
		}
	}

	if(-1 != m_iEPSecIndex)
	{
		dwBeginIndex = m_dwEPOffset; m_dwEPOffset = MAXDWORD;
		if(GetValidData(hFile, bySignature, cbSignature, m_SectionHeader[m_iEPSecIndex].PointerToRawData,
						m_SectionHeader[m_iEPSecIndex].SizeOfRawData, m_wSecLargestSectionDepth, true,
						iMAX_PRI_SIG_LEN, dwSigOffset))
		{
			m_dwEPOffset = dwBeginIndex;
			return true;
		}
	}

	m_dwEPOffset = dwBeginIndex;
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : GetThirdSig
In Parameters  : HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset
Out Parameters : bool 
Description    : get valid third signature for file, address of entry point
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::GetThirdSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset)
{
	DWORD dwOff = 0, dwLen = 0;

	if((ULONGLONG)m_dwEPOffset > m_ulFileSize)
	{
		return false;
	}

	dwOff = m_dwEPOffset;
	dwLen = ((DWORD)m_ulFileSize) - m_dwEPOffset;
	if(!SearchSigAreaForward(hFile, dwOff, dwLen, bySignature, cbSignature, 0, dwSigOffset))
	{
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetFourthSig
In Parameters  : HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset
Out Parameters : bool 
Description    : get valid fourth signature for file, end of file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::GetFourthSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset)
{
	DWORD dwOff = 0, dwLen = 0;

	if(m_ulFileSize > MAXDWORD)
	{
		dwOff = (DWORD)(((ULONG64)m_ulFileSize) - ((ULONG64)MAXDWORD));
		dwLen = MAXDWORD;
	}
	else
	{
		dwOff = 0;
		dwLen = LODWORD(m_ulFileSize);
	}

	if(!SearchSigAreaBackward(hFile, dwOff, dwLen, bySignature, cbSignature, 0, dwSigOffset))
	{
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetFifthSig
In Parameters  : HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset
Out Parameters : bool 
Description    : get valid primary signature for file, exec section other than used for first
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::GetFifthSig(HANDLE hFile, LPBYTE bySignature, DWORD cbSignature, DWORD& dwSigOffset)
{
	bool bSigFound = false;

	for(DWORD i = 0; i < m_dwSectionsCount && !bSigFound; i++)
	{
		if(i == m_iFirstSigIndex)
		{
			continue;
		}

		if(((m_SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE) ||
			((m_SectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE))
		{
			if(GetValidData(hFile, bySignature, cbSignature, m_SectionHeader[i].PointerToRawData,
							m_SectionHeader[i].SizeOfRawData, 10, true, 0, dwSigOffset))
			{
				bSigFound = true;
			}
		}
	}

	return bSigFound;
}

/*--------------------------------------------------------------------------------------
Function       : IsValidPE
In Parameters  : HANDLE hFile
Out Parameters : bool 
Description    : determine if this is a valid pe file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CFileSig::IsValidPE(HANDLE hFile)
{
	LPBYTE bySignature = 0;
	DWORD dwBytesRead = 0, dwFileSizeLow = 0, dwFileSizeHigh = 0;

	if(m_pMaxPEFile)
	{
		dwFileSizeLow = m_pMaxPEFile->m_dwFileSize;
		dwFileSizeHigh = m_pMaxPEFile->m_dwFileSizeHigh;
		m_ulFileSize = MKQWORD(dwFileSizeHigh,dwFileSizeLow);
	}
	else
	{
		dwFileSizeLow = GetFileSize(hFile, &dwFileSizeHigh);
		m_ulFileSize = MKQWORD(dwFileSizeHigh,dwFileSizeLow);
	}

	//	if(!m_pMaxPEFile->m_bMZFound)
	//	{
	//		return false;
	//	}

	//	m_bIsBinary = true;
	//	if(!m_pMaxPEFile->m_bPEFound)
	//	{
	//		return false;
	//	}

	//	if(!m_pMaxPEFile->m_bSecFound)
	//	{
	//		return false;
	//	}

	//	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > _countof(m_SectionHeader))
	//	{
	//		return false;
	//	}

	//	m_dwEPRVA = m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
	//	m_dwSectionsCount = m_pMaxPEFile->m_stPEHeader.NumberOfSections;
	//	memcpy(m_SectionHeader, m_pMaxPEFile->m_stSectionHeader, sizeof(m_pMaxPEFile->m_stSectionHeader[0]) * m_dwSectionsCount);
	//}

		if(INVALID_SET_FILE_POINTER == SeekFilePointer(hFile, 0, 0, FILE_BEGIN))
		{
			return false;
		}

		if(!ReadBuffer(hFile, &m_DosHeader, sizeof(m_DosHeader), &dwBytesRead, 0))
		{
			return false;
		}

		if(EXE_SIGNATURE != m_DosHeader.e_magic)
		{
			return false;
		}

		m_bIsBinary = true;

		if(INVALID_SET_FILE_POINTER == SeekFilePointer(hFile, m_DosHeader.e_lfanew, 0, FILE_BEGIN))
		{
			return false;
		}

		if(!ReadBuffer(hFile, &m_NTFileHeader, sizeof(m_NTFileHeader), &dwBytesRead, 0))
		{
			return false;
		}

		if(PE_SIGNATURE != m_NTFileHeader.Signature)
		{
			return false;
		}

		if(m_NTFileHeader.FileHeader.NumberOfSections > _countof(m_SectionHeader))
		{
			return false;
		}

		if(m_NTFileHeader.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
		   m_NTFileHeader.FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
		{
			if(m_NTFileHeader.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64))
			{
				return false;
			}

			DWORD dwDifferenceInSize = sizeof(IMAGE_OPTIONAL_HEADER64) - sizeof(IMAGE_OPTIONAL_HEADER32);
			if(INVALID_SET_FILE_POINTER == SeekFilePointer(hFile, dwDifferenceInSize, 0, FILE_CURRENT))
			{
				return false;
			}
		}

		m_dwSectionsCount = m_NTFileHeader.FileHeader.NumberOfSections;
		if(!ReadBuffer(hFile, &m_SectionHeader, sizeof(m_SectionHeader[0]) * m_dwSectionsCount, &dwBytesRead, 0))
		{
			return false;
		}

		m_dwEPRVA = m_NTFileHeader.OptionalHeader.AddressOfEntryPoint;
	//}

	m_dwOverlayOffset = 0;
	m_dwOverlayLength = 0;

	for(DWORD i = 0; i < m_dwSectionsCount; i++)
	{
		if(m_SectionHeader[i].PointerToRawData + m_SectionHeader[i].SizeOfRawData > m_dwOverlayOffset)
		{
			m_dwOverlayOffset = m_SectionHeader[i].PointerToRawData + m_SectionHeader[i].SizeOfRawData;
		}
	}

	m_dwOverlayLength = m_ulFileSize > m_dwOverlayOffset ? (DWORD)m_ulFileSize - m_dwOverlayOffset : 0;

	if(!RVAToOffset(m_dwEPRVA, m_dwEPOffset, m_iEPSecIndex))
	{
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : OpenFile
In Parameters  : LPCTSTR csFilePath
Out Parameters : int
Description    : open the file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::OpenFile(LPCTSTR csFilePath)
{
	if(NULL == m_byReaderBuffer)
	{
		return SIG_STATUS_BUFFER_INVALID;
	}

	if(m_pMaxPEFile)
	{
		return SIG_STATUS_PE_SUCCESS;
	}

	if(INVALID_HANDLE_VALUE != m_hFile)
	{
		return SIG_STATUS_PE_SUCCESS;
	}

	m_hFile = CreateFile(csFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == m_hFile)
	{
		return SIG_STATUS_OPEN_FAILED;
	}

	ResetData();
	m_bIsValidPE = IsValidPE(m_hFile);

	if(0 == m_ulFileSize)
	{
		CloseFile();
		return SIG_STATUS_ZERO_BYTE_FILE;
	}

	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : OpenFileUsingFileObject
In Parameters  : CMaxPEFile *pMaxPEFile
Out Parameters : int
Description    : dont open the file actually, but use the handles and data from object, set members
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::OpenFileUsingFileObject(CMaxPEFile *pMaxPEFile)
{
	if(ERR_OPENING_FILE == pMaxPEFile->m_iErrCode)
	{
		return SIG_STATUS_OPEN_FAILED;
	}

	m_pMaxPEFile = pMaxPEFile;

	ResetData();
	m_bIsValidPE = IsValidPE(m_hFile);
	if(0 == m_ulFileSize)
	{
		m_pMaxPEFile = NULL;
		m_hFile = INVALID_HANDLE_VALUE;
		return SIG_STATUS_ZERO_BYTE_FILE;
	}

	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : CloseFile
In Parameters  : 
Out Parameters : int 
Description    : close file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::CloseFile()
{
	if(m_pMaxPEFile)
	{
		return SIG_STATUS_PE_SUCCESS;
	}

	if(INVALID_HANDLE_VALUE != m_hFile)
	{
		CloseHandle(m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
	}

	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : CloseFileUsingFileObject
In Parameters  : NONE
Out Parameters : int 
Description    : dont close file actually, but reset members
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::CloseFileUsingFileObject()
{
	m_pMaxPEFile = NULL;
	m_hFile = INVALID_HANDLE_VALUE;
	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : SeekFilePointer
In Parameters  : HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod
Out Parameters : DWORD 
Description    : set the file pointer, using file object or api
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
DWORD CFileSig::SeekFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
	if(m_pMaxPEFile)
	{
		DWORD dwResult = 0;
		m_pMaxPEFile->SetFilePointer(lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod, &dwResult);
		return dwResult;
	}
	else
	{
		return SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
	}
}

/*--------------------------------------------------------------------------------------
Function       : ReadBuffer
In Parameters  : HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped
Out Parameters : BOOL
Description    : read buffer from file, using file object if available, else direct API
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
BOOL CFileSig::ReadBuffer(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	if(m_pMaxPEFile)
	{
		return m_pMaxPEFile->ReadBuffer(lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead);
	}
	else
	{
		return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	}
}

/*--------------------------------------------------------------------------------------
Function       : GetFileType
In Parameters  : 
Out Parameters : int 
Description    : return the file type
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::GetFileType()
{
	if(INVALID_HANDLE_VALUE == m_hFile)
	{
		return FS_ERR;
	}

	if(false == m_bIsBinary)
	{
		return FS_NPE;
	}

	if(false == m_bIsValidPE)
	{
		return FS_EXE;
	}

	if((m_NTFileHeader.FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return FS_DLL;
	}

	return FS_EXE;
}

/*--------------------------------------------------------------------------------------
Function       : CreateMD5Sig
In Parameters  : LPCTSTR csFilePath, ULONG64& ulMD5Sig
Out Parameters : int
Description    : create MD5 signature file till 15MB else file size
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::CreateMD5Sig(LPCTSTR csFilePath, ULONG64& ulMD5Sig)
{
	int iRetValue = 0;
	BYTE bySignature[iMAX_MD5_SIG_LEN] = {0};

	iRetValue = OpenFile(csFilePath);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		return iRetValue;
	}

	SeekFilePointer(m_hFile, 0, 0, FILE_BEGIN);
	MDFile15MBLimit(m_hFile, bySignature, m_byReaderBuffer, 64 * 1024);
	CreateCRC64Buffer(bySignature, sizeof(bySignature), ulMD5Sig);

	if(m_bCollectDetails)
	{
		m_FileInfo.ul15MBFileMD5 = ulMD5Sig;
		m_FileInfo.bIsPE = (m_bIsValidPE || m_bIsBinary);

		memset(bySignature, 0, sizeof(bySignature));
		MDFile(m_hFile, bySignature, sizeof(bySignature), 0);
		CreateCRC64Buffer(bySignature, sizeof(bySignature), m_FileInfo.ulFullFileMD5);

		for(int i = 0; i < 16; i++)
		{
			sprintf_s(m_FileInfo.szMD5 + (i * 2), sizeof(m_FileInfo.szMD5) - (i * 2), "%02X", bySignature[i]);
		}

		m_FileInfo.szMD5[32] = 0;
	}

	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : CreateMD5SigEx
In Parameters  : LPCTSTR csFilePath, ULONG64& ulMD5Sig
Out Parameters : int
Description    : create MD5 signature file till 15MB else file size
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::CreateMD5SigEx(LPCTSTR csFilePath, ULONG64& ulMD5Sig)
{
	int iRetValue = 0;
	BYTE bySignature[iMAX_MD5_SIG_LEN] = {0};

	iRetValue = OpenFile(csFilePath);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		return iRetValue;
	}

	SeekFilePointer(m_hFile, 0, 0, FILE_BEGIN);
	MDFile15MBLimit(m_hFile, bySignature, m_byReaderBuffer, 64 * 1024);
	CreateCRC64Buffer(bySignature, sizeof(bySignature), ulMD5Sig);
	
	//if(m_bCollectDetails)
	//{
		m_FileInfo.ul15MBFileMD5 = ulMD5Sig;
		m_FileInfo.bIsPE = (m_bIsValidPE || m_bIsBinary);

		memset(bySignature, 0, sizeof(bySignature));
		MDFile(m_hFile, bySignature, sizeof(bySignature), 0);
		CreateCRC64Buffer(bySignature, sizeof(bySignature), m_FileInfo.ulFullFileMD5);

		for(int i = 0; i < 16; i++)
		{
			sprintf_s(m_FileInfo.szMD5 + (i * 2), sizeof(m_FileInfo.szMD5) - (i * 2), "%02x", bySignature[i]);
		}

		m_FileInfo.szMD5[32] = 0;
	//}

		CreateCRC64Buffer((unsigned char *)&m_FileInfo.szMD5[0x00], 0x21, ulMD5Sig);

	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : CreateSecSig
In Parameters  : LPCTSTR csFilePath, ULONG64& ulSecSig, int* piFirstIndex
Out Parameters : int
Description    : create secondary signature 32 and 64 bit pe file and non pe file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::CreateSecSig(LPCTSTR csFilePath, ULONG64& ulSecSig, int* piFirstIndex)
{
	bool bSuccess = false;
	PESIGRAW RawSig = {0};
	int iRetValue = 0, iTotalSize = 0;
	DWORD dwSigOffset = 0, dwSegment = 0;
	BYTE bySigSixth[iMAX_FILE_BEGIN_SEC_SIZE] = {0};

	iRetValue = OpenFile(csFilePath);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		return iRetValue;
	}

	if(piFirstIndex)
	{
		m_iFirstSigIndex = *piFirstIndex;
	}

	if(m_bIsValidPE)
	{
		bSuccess = GetSecondSig(m_hFile, RawSig.bySig2, sizeof(RawSig.bySig2), dwSigOffset)?true:bSuccess;
		bSuccess = GetThirdSig(m_hFile, RawSig.bySig3, sizeof(RawSig.bySig3), dwSigOffset)?true:bSuccess;
		bSuccess = GetFourthSig(m_hFile, RawSig.bySig4, sizeof(RawSig.bySig4), dwSigOffset)?true:bSuccess;
		bSuccess = GetFifthSig(m_hFile, RawSig.bySig5, sizeof(RawSig.bySig5), dwSigOffset)?true:bSuccess;
	}

	if(!bSuccess)
	{
		dwSegment = (DWORD)(m_ulFileSize/6);		// for 6 signatures

		memset(RawSig.bySig2, 0, sizeof(RawSig.bySig2));
		SeekFilePointer(m_hFile, 1 * dwSegment, 0, FILE_BEGIN);
		ReadBuffer(m_hFile, RawSig.bySig2, sizeof(RawSig.bySig2), &dwSigOffset, 0);

		memset(RawSig.bySig3, 0, sizeof(RawSig.bySig3));
		SeekFilePointer(m_hFile, 2 * dwSegment, 0, FILE_BEGIN);
		ReadBuffer(m_hFile, RawSig.bySig3, sizeof(RawSig.bySig3), &dwSigOffset, 0);

		memset(RawSig.bySig4, 0, sizeof(RawSig.bySig4));
		SeekFilePointer(m_hFile, 3 * dwSegment, 0, FILE_BEGIN);
		ReadBuffer(m_hFile, RawSig.bySig4, sizeof(RawSig.bySig4), &dwSigOffset, 0);

		memset(RawSig.bySig5, 0, sizeof(RawSig.bySig5));
		SeekFilePointer(m_hFile, 4 * dwSegment, 0, FILE_BEGIN);
		ReadBuffer(m_hFile, RawSig.bySig5, sizeof(RawSig.bySig5), &dwSigOffset, 0);

		memset(bySigSixth, 0, sizeof(bySigSixth));
		SeekFilePointer(m_hFile, 5 * dwSegment, 0, FILE_BEGIN);
		ReadBuffer(m_hFile, bySigSixth, sizeof(bySigSixth), &dwSigOffset, 0);
	}
	else
	{
		SeekFilePointer(m_hFile, 0, 0, FILE_BEGIN);
		ReadBuffer(m_hFile, bySigSixth, sizeof(bySigSixth), &dwSigOffset, 0);
	}

	memcpy(m_byDataForSignature + (iMAX_PRI_SIG_LEN * 1), RawSig.bySig2, sizeof(RawSig.bySig2));
	memcpy(m_byDataForSignature + (iMAX_PRI_SIG_LEN * 2), RawSig.bySig3, sizeof(RawSig.bySig3));
	memcpy(m_byDataForSignature + (iMAX_PRI_SIG_LEN * 3), RawSig.bySig4, sizeof(RawSig.bySig4));
	memcpy(m_byDataForSignature + (iMAX_PRI_SIG_LEN * 4), RawSig.bySig5, sizeof(RawSig.bySig5));
	memcpy(m_byDataForSignature + (iMAX_PRI_SIG_LEN * 5), bySigSixth, sizeof(bySigSixth));

	iTotalSize = sizeof(RawSig.bySig2)+ sizeof(RawSig.bySig3)+ sizeof(RawSig.bySig4)+ sizeof(RawSig.bySig5);
	CreateCRC64Buffer(RawSig.bySig2, iTotalSize, ulSecSig);
	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : CreatePriSig
In Parameters  : LPCTSTR csFilePath, ULONG64& ulPriSig, int* piFirstIndex
Out Parameters : int 
Description    : create primary signature of 32 and 64 bit pe file and non pe file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::CreatePriSig(LPCTSTR csFilePath, ULONG64& ulPriSig, int* piFirstIndex)
{
	int iRetValue = 0;
	bool bSuccess = false;
	DWORD dwSigOff = 0, dwSegment = 0;
	BYTE bySignature[iMAX_PRI_SIG_LEN] = {0};

	iRetValue = OpenFile(csFilePath);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		return iRetValue;
	}

	if(m_bIsValidPE)
	{
		bSuccess = GetFirstSig(m_hFile, bySignature, sizeof(bySignature), dwSigOff);
	}

	if(!bSuccess)
	{
		SeekFilePointer(m_hFile, 0, 0, FILE_BEGIN);
		ReadBuffer(m_hFile, bySignature, sizeof(bySignature), &dwSigOff, 0);
	}

	memcpy(m_byDataForSignature + (iMAX_PRI_SIG_LEN * 0), bySignature, sizeof(bySignature));
	CreateCRC64Buffer(bySignature, sizeof(bySignature), ulPriSig);

	if(piFirstIndex)
	{
		*piFirstIndex = m_iFirstSigIndex;
	}

	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : CreateSignature
In Parameters  : LPCTSTR csFilePath, PESIGCRC& Signature
Out Parameters : int 
Description    : create signature of 32 and 64 bit pe file or a non pe file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::CreateSignature(LPCTSTR csFilePath, PESIGCRC& Signature)
{
	int iRetValue = 0;

	CloseFile();
	iRetValue = OpenFile(csFilePath);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		CloseFile();
		return iRetValue;
	}

	iRetValue = CreatePriSig(csFilePath, Signature.ulPri);
	iRetValue = CreateSecSig(csFilePath, Signature.ulSec);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		CloseFile();
		return iRetValue;
	}

	if(m_bCollectDetails)
	{
		CreateMD5Sig(csFilePath, Signature.ulMD5);
	}

	CloseFile();
	return iRetValue;
}

/*--------------------------------------------------------------------------------------
Function       : CreatePriSig
In Parameters  : LPCTSTR csFilePath, ULONG64& ulSignature
Out Parameters : int 
Description    : create file signature
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::CreateSignature(LPCTSTR csFilePath, ULONG64& ulSignature)
{
	int iRetValue = 0;
	PESIGCRC Signature = {0};
	BYTE byMD5[20] = {0};
	int iNonNullChars = 0, iMinNonNullCharsRequired = 20;

	memset(m_byDataForSignature, 0, sizeof(m_byDataForSignature));

	iRetValue = CreateSignature(csFilePath, Signature);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		CloseFile();
		return iRetValue;
	}

	for(int i = 0; i < sizeof(m_byDataForSignature) && (iNonNullChars < iMinNonNullCharsRequired); i++)
	{
		iNonNullChars += m_byDataForSignature[i] ? 1 : 0;
	}

	if(iNonNullChars < iMinNonNullCharsRequired)
	{
		CloseFile();
		return SIG_STATUS_FILE_DATA_ONLY_NULLS;
	}

	MD5Buffer(m_byDataForSignature, sizeof(m_byDataForSignature), byMD5, sizeof(byMD5));
	CreateCRC64Buffer(byMD5, 16, ulSignature);
	CloseFile();
	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : CreateSignature
In Parameters  : LPCTSTR csFilePath, FILEINFO& FileInfo
Out Parameters : int 
Description    : create signature and md5 and check if pe file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::CreateSignature(LPCTSTR csFilePath, DTL_FINFO& FileInfo)
{
	int iRetValue = 0;

	m_bCollectDetails = true;
	memset(&m_FileInfo, 0, sizeof(m_FileInfo));

	iRetValue = CreateSignature(csFilePath, m_FileInfo.ulSignature);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		m_bCollectDetails = false;
		CloseFile();
		return iRetValue;
	}

	memcpy(&FileInfo, &m_FileInfo, sizeof(FileInfo));
	m_bCollectDetails = false;
	CloseFile();
	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : CreateSignature
In Parameters  : CMaxPEFile *pMaxPEFile, FILEINFO& FileInfo
Out Parameters : int 
Description    : create signature and md5 and check if pe file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CFileSig::CreateSignature(CMaxPEFile *pMaxPEFile, ULONG64& ulSignature)
{
	int iReturnValue = SIG_STATUS_OPEN_FAILED;

	if(pMaxPEFile)
	{
		iReturnValue = OpenFileUsingFileObject(pMaxPEFile);
	}

	if(SIG_STATUS_PE_SUCCESS == iReturnValue)
	{
		iReturnValue = CreateSignature(pMaxPEFile->m_szFilePath, ulSignature);
	}

	CloseFileUsingFileObject();
	return iReturnValue;
}

