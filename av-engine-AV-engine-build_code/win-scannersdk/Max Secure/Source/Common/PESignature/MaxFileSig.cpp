/*======================================================================================
FILE             : MaxFileSig.cpp
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
				  
CREATION DATE    : 27 April 2011
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "StdAfx.h"
#include "MaxFileSig.h"
#include "BalBST.h"

/*--------------------------------------------------------------------------------------
Function       : CMaxFileSig
In Parameters  : 
Out Parameters : 
Description    : constructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CMaxFileSig::CMaxFileSig()
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
	m_bValidPE = false;
	m_bIsBinary = false;
	m_hFile = INVALID_HANDLE_VALUE;
	m_bValidOverlayBlockRead = false;
	m_bOverlayIsInvalid = false;

	m_byReaderBuffer = Allocate(MAX_READ_BUFFER);
	m_byReaderBlock = Allocate(iSIZE_RDR_BLOCK);
}

/*--------------------------------------------------------------------------------------
Function       : ~CMaxFileSig
In Parameters  : 
Out Parameters : 
Description    : destructor
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CMaxFileSig::~CMaxFileSig()
{
	if(NULL != m_hHeap)
	{
		HeapDestroy(m_hHeap);
		m_hHeap = NULL;
	}

	CloseFile();
}

/*--------------------------------------------------------------------------------------
Function       : ResetData
In Parameters  : 
Out Parameters : 
Description    : resets all the class member data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
void CMaxFileSig::ResetData()
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
	m_bValidPE = false;
	m_bIsBinary = false;
	m_bValidOverlayBlockRead = false;
	memset(m_byReaderBlock, 0, iSIZE_RDR_BLOCK);
	m_bOverlayIsInvalid = false;
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
void CMaxFileSig::SetSignatureParameters(WORD wEPDeflection1, bool bEPDeflectionForward1, WORD wEPDeflection2,
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
LPBYTE CMaxFileSig::Allocate(DWORD dwSize)
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

	lpMemory =(LPBYTE)HeapAlloc(m_hHeap, HEAP_ZERO_MEMORY, dwSize);
	return lpMemory;
}

/*--------------------------------------------------------------------------------------
Function       : IsValidData
In Parameters  : LPBYTE byData, SIZE_T cbData, float fAllow, 
Out Parameters : bool 
Description    : check if the passed buffer has non-repetitive data valid data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::IsValidData(LPBYTE byData, SIZE_T cbData, float fAllow)
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
int CMaxFileSig::GetOriginalSectionIndex(IMAGE_SECTION_HEADER* SortedSections, DWORD dwCount, DWORD dwIndex)
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
bool CMaxFileSig::RVAToOffset(DWORD dwRVA, DWORD& dwOffset, int& iSectionIndex)
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
bool CMaxFileSig::SortSectionsEPLast(IMAGE_SECTION_HEADER* pSortedSec, DWORD& dwSecSize, bool bKeepOverlayAtTop)
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
bool CMaxFileSig::SearchSigAreaForward(HANDLE hFile, DWORD dwOffset, DWORD dwLength, LPBYTE byData,
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

		if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwOffset + dwTotalBytesRead, 0, FILE_BEGIN))
		{
			break;
		}

		if(!ReadFile(hFile, m_byReaderBuffer, dwBytesToRead, &dwBytesRead, 0))
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

	return (bFound);
}

/*--------------------------------------------------------------------------------------
Function       : SearchSigAreaBackward
In Parameters  : HANDLE hFile, DWORD dwOffset, DWORD dwLength, LPBYTE byData, 
Out Parameters : bool 
Description    : search for valid signature in the area by moving backward
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::SearchSigAreaBackward(HANDLE hFile, DWORD dwOffset, DWORD dwLength, LPBYTE byData,
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
		if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwReadOffset, 0, FILE_BEGIN))
		{
			break;
		}

		if(!ReadFile(hFile, m_byReaderBuffer, dwBytesToRead, &dwBytesRead, 0))
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

	return (bFound);
}

/*--------------------------------------------------------------------------------------
Function       : GetSigArea
In Parameters  : DWORD& dwOffset, DWORD& dwLength, WORD wOffPercent, bool bSearchForward, 
Out Parameters : bool 
Description    : find the file area in which signature will be searched later
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::GetSigArea(DWORD& dwOffset, DWORD& dwLength, WORD wOffPercent, bool bSearchForward)
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
bool CMaxFileSig::GetValidData(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD dwOffset, DWORD dwLength,
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
Function       : GetBlockData
In Parameters  : HANDLE hFile, DWORD dwOffset, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset
Out Parameters : bool 
Description    : read a block size(iSIZE_RDR_BLOCK) and remove nulls and get data if atleast one non null byte
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::GetBlockData(HANDLE hFile, DWORD dwOffset, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset)
{
	DWORD dwBytesRead = 0, dwNonNullChars = 0;

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwOffset, 0, FILE_BEGIN))
	{
		return false;
	}

	if(FALSE == ReadFile(hFile, m_byReaderBlock, iSIZE_RDR_BLOCK, &dwBytesRead, 0))
	{
		return false;
	}

	for(DWORD i = 0; i < dwBytesRead; i++)
	{
		if(m_byReaderBlock[i])
		{
			byData[dwNonNullChars++ % cbData] ^= m_byReaderBlock[i];
		}
	}

	return 0 != dwNonNullChars;
}

/*--------------------------------------------------------------------------------------
Function       : ReadFlatRegion
In Parameters  : HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset, int iPart
Out Parameters : bool 
Description    : divide file in equal parts(max parts of data for signature) and read the asked part
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::ReadFlatRegion(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset, int iPart)
{
	DWORD dwReadBytes = 0;
	ULONG64 ulFSizeWithoutInvalidOverlay = m_ulFileSize;

	if(m_bOverlayIsInvalid)
	{
		ulFSizeWithoutInvalidOverlay -= m_dwOverlayLength;
	}

	dwDataOffset = (DWORD)(ulFSizeWithoutInvalidOverlay / 6) * iPart;
	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwDataOffset, 0, FILE_BEGIN))
	{
		return false;
	}

	if(!ReadFile(hFile, byData, cbData, &dwReadBytes, 0))
	{
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetFirstRgn
In Parameters  : HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset
Out Parameters : bool 
Description    : get valid first signature region data
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::GetFirstRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset)
{
	DWORD dwSortedSections = _countof(m_SectionHeader) + 1;
	IMAGE_SECTION_HEADER SortedSections[_countof(m_SectionHeader) + 1] = {0};

	if(false == m_bValidPE)
	{
		return ReadFlatRegion(hFile, byData, cbData, dwDataOffset, 0);
	}

	if(-1 != m_iEPSecIndex)
	{
		if(GetValidData(hFile, byData, cbData, m_SectionHeader[m_iEPSecIndex].PointerToRawData,
						m_SectionHeader[m_iEPSecIndex].SizeOfRawData, m_wEPDeflection1,
						m_bEPDeflectionForward1, 0, dwDataOffset))
		{
			m_iFirstSigIndex = m_iEPSecIndex;
			return true;
		}

		if(GetValidData(hFile, byData, cbData, m_SectionHeader[m_iEPSecIndex].PointerToRawData,
						m_SectionHeader[m_iEPSecIndex].SizeOfRawData, m_wEPDeflection2,
						m_bEPDeflectionForward2, 0, dwDataOffset))
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
			if(GetValidData(hFile, byData, cbData, SortedSections[i].PointerToRawData,
							SortedSections[i].SizeOfRawData, m_wCodeSectionDepth, true, 0, dwDataOffset))
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
			if(GetValidData(hFile, byData, cbData, SortedSections[i].PointerToRawData,
							SortedSections[i].SizeOfRawData, m_wPriLargestSectionDepth, true, 0,
							dwDataOffset))
			{
				m_iFirstSigIndex = GetOriginalSectionIndex(SortedSections, _countof(SortedSections), i);
				return true;
			}
		}
	}

	if(-1 != m_iEPSecIndex)
	{
		if(GetValidData(hFile, byData, cbData, m_SectionHeader[m_iEPSecIndex].PointerToRawData,
						m_SectionHeader[m_iEPSecIndex].SizeOfRawData, m_wCodeSectionDepth, true, 0,
						dwDataOffset))
		{
			m_iFirstSigIndex = m_iEPSecIndex;
			return true;
		}
	}

	return false;
}

/*--------------------------------------------------------------------------------------
Function       : GetSecondRgn
In Parameters  : HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset
Out Parameters : bool 
Description    : get valid second region data for signature, overlay
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::GetSecondRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset)
{
	DWORD dwSortedSections = _countof(m_SectionHeader) + 1;
	IMAGE_SECTION_HEADER SortedSections[_countof(m_SectionHeader) + 1] = {0};
	DWORD dwBeginIndex = 0, dwRead = 0;

	if(false == m_bValidPE)
	{
		return ReadFlatRegion(hFile, byData, cbData, dwDataOffset, 1);
	}

	if(m_dwOverlayLength && m_byReaderBlock)
	{
		if(GetBlockData(hFile, m_dwOverlayOffset, byData, cbData, dwDataOffset))
		{
			m_bValidOverlayBlockRead = true;
			return true;
		}

		m_bOverlayIsInvalid = true;
		dwBeginIndex = 1;
	}

	SortSectionsEPLast(SortedSections, dwSortedSections, true);
	if(0 == dwSortedSections)
	{
		return false;
	}

	for(DWORD i = dwBeginIndex; i < dwSortedSections - 1; i++)
	{
		if(GetValidData(hFile, byData, cbData, SortedSections[i].PointerToRawData,
			SortedSections[i].SizeOfRawData, m_wSecLargestSectionDepth, true,
			iSIZE_SIG_RGN, dwDataOffset))
		{
			return true;
		}
	}

	if(-1 != m_iEPSecIndex)
	{
		dwBeginIndex = m_dwEPOffset; m_dwEPOffset = MAXDWORD;
		if(GetValidData(hFile, byData, cbData, m_SectionHeader[m_iEPSecIndex].PointerToRawData,
						m_SectionHeader[m_iEPSecIndex].SizeOfRawData, m_wSecLargestSectionDepth, true,
						iSIZE_SIG_RGN, dwDataOffset))
		{
			m_dwEPOffset = dwBeginIndex;
			return true;
		}
	}

	m_dwEPOffset = dwBeginIndex;
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : GetThirdRgn
In Parameters  : HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset
Out Parameters : bool 
Description    : get valid third region data for file, address of entry point
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::GetThirdRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset)
{
	DWORD dwOff = 0, dwLen = 0;

	if(false == m_bValidPE)
	{
		return ReadFlatRegion(hFile, byData, cbData, dwDataOffset, 2);
	}

	if((ULONGLONG)m_dwEPOffset > m_ulFileSize)
	{
		return false;
	}

	dwOff = m_dwEPOffset;
	dwLen = ((DWORD)m_ulFileSize) - m_dwEPOffset;
	if(!SearchSigAreaForward(hFile, dwOff, dwLen, byData, cbData, 0, dwDataOffset))
	{
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetFourthRgn
In Parameters  : HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset
Out Parameters : bool 
Description    : get valid fourth region data for signature, end of file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::GetFourthRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset)
{
	DWORD dwOff = 0, dwLen = 0;

	if(false == m_bValidPE)
	{
		return ReadFlatRegion(hFile, byData, cbData, dwDataOffset, 3);
	}

	if(0 == m_dwOverlayLength || true == m_bOverlayIsInvalid)
	{
		// use this section if overlay present
		return false;
	}

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

	if(!SearchSigAreaBackward(hFile, dwOff, dwLen, byData, cbData, 0, dwDataOffset))
	{
		return false;
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetFifthRgn
In Parameters  : HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset
Out Parameters : bool 
Description    : get valid fifth region for signature, exec section other than used for first
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::GetFifthRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset)
{
	bool bSigFound = false;

	if(false == m_bValidPE)
	{
		if(!ReadFlatRegion(hFile, byData, cbData, dwDataOffset, 4))
		{
			return false;
		}

		return true;
	}

	for(DWORD i = 0; i < m_dwSectionsCount && !bSigFound; i++)
	{
		// if section smaller than 4kb dont consider it for signature data
		if(i == m_iFirstSigIndex || (m_SectionHeader[i].Misc.VirtualSize < 500))
		{
			continue;
		}

		if(((m_SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE) ||
			((m_SectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE))
		{
			if(GetValidData(hFile, byData, cbData, m_SectionHeader[i].PointerToRawData,
							m_SectionHeader[i].SizeOfRawData, 10, true, 0, dwDataOffset))
			{
				bSigFound = true;
			}
		}
	}

	return bSigFound;
}

/*--------------------------------------------------------------------------------------
Function       : GetSixthRgn
In Parameters  : HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset
Out Parameters : bool 
Description    : get rsrc section 4kb data if valid pe else, flat sixth part
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::GetSixthRgn(HANDLE hFile, LPBYTE byData, DWORD cbData, DWORD& dwDataOffset)
{
	DWORD dwReadOffset = -1;

	if(!m_bValidPE)
	{
		return ReadFlatRegion(hFile, byData, cbData, dwDataOffset, 5);
	}

	for(WORD i = 0; i < m_NTFileHeader.FileHeader.NumberOfSections && -1 == dwReadOffset; i++)
	{
		if(!_memicmp(m_SectionHeader[i].Name, ".rsrc\0\0\0", 8) || !_memicmp(m_SectionHeader[i].Name, "rsrc\0\0\0\0", 8))
		{
			dwReadOffset = m_SectionHeader[i].PointerToRawData;
		}
	}

	return GetBlockData(hFile, dwReadOffset, byData, cbData, dwDataOffset);
}

/*--------------------------------------------------------------------------------------
Function       : IsValidPE
In Parameters  : HANDLE hFile, 
Out Parameters : bool 
Description    : determine if this is a valid pe file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CMaxFileSig::IsValidPE(HANDLE hFile)
{
	LPBYTE bySignature = 0;
	DWORD dwBytesRead = 0, dwFileSizeLow = 0, dwFileSizeHigh = 0;

	dwFileSizeLow = GetFileSize(hFile, &dwFileSizeHigh);
	m_ulFileSize = MKQWORD(dwFileSizeHigh,dwFileSizeLow);

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, 0, 0, FILE_BEGIN))
	{
		return false;
	}

	if(!ReadFile(hFile, &m_DosHeader, sizeof(m_DosHeader), &dwBytesRead, 0))
	{
		return false;
	}

	if(EXE_SIGNATURE != m_DosHeader.e_magic)
	{
		return false;
	}

	m_bIsBinary = true;

	if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, m_DosHeader.e_lfanew, 0, FILE_BEGIN))
	{
		return false;
	}

	if(!ReadFile(hFile, &m_NTFileHeader, sizeof(m_NTFileHeader), &dwBytesRead, 0))
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
		if(INVALID_SET_FILE_POINTER == SetFilePointer(hFile, dwDifferenceInSize, 0, FILE_CURRENT))
		{
			return false;
		}
	}

	if(!ReadFile(hFile, &m_SectionHeader, 
				 sizeof(m_SectionHeader[0])* m_NTFileHeader.FileHeader.NumberOfSections,
				 &dwBytesRead, 0))
	{
		return false;
	}

	m_dwEPRVA = m_NTFileHeader.OptionalHeader.AddressOfEntryPoint;
	m_dwSectionsCount = m_NTFileHeader.FileHeader.NumberOfSections;
	m_dwOverlayOffset = 0;
	m_dwOverlayLength = 0;

	for(DWORD i = 0; i < m_dwSectionsCount; i++)
	{
		if(m_SectionHeader[i].PointerToRawData + m_SectionHeader[i].SizeOfRawData > m_dwOverlayOffset)
			m_dwOverlayOffset = m_SectionHeader[i].PointerToRawData + m_SectionHeader[i].SizeOfRawData;
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
int CMaxFileSig::OpenFile(LPCTSTR csFilePath)
{
	if(NULL == m_byReaderBuffer)
	{
		return SIG_STATUS_BUFFER_INVALID;
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
	m_bValidPE = IsValidPE(m_hFile);

	if(0 == m_ulFileSize)
	{
		CloseFile();
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
int CMaxFileSig::CloseFile()
{
	if(INVALID_HANDLE_VALUE != m_hFile)
	{
		CloseHandle(m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
	}

	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : GetFileType
In Parameters  : 
Out Parameters : int 
Description    : return the file type
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CMaxFileSig::GetFileType()
{
	if(INVALID_HANDLE_VALUE == m_hFile)
	{
		return FS_ERR;
	}

	if(false == m_bIsBinary)
	{
		return FS_NPE;
	}

	if(false == m_bValidPE)
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
Function       : CollectDataForSignature
In Parameters  : 
Out Parameters : int 
Description    : collect data from all regions
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CMaxFileSig::CollectDataForSignature()
{
	int iValRgnFound = 0;
	bool bSuccess = false, bFound = false;
	DWORD dwDataOffset = 0;
	ULONG64 ulRgnDataChecksum[6] = {0}, ulHold = 0;

	memset(&m_unSigData, 0, sizeof(m_unSigData));

	if(m_bValidPE)
	{
		if(GetFirstRgn(m_hFile, m_unSigData.stRgn.by1, sizeof(m_unSigData.stRgn.by1), dwDataOffset))
		{
			CreateCRC64Buffer(m_unSigData.stRgn.by1, sizeof(m_unSigData.stRgn.by1), ulRgnDataChecksum[0]);
			iValRgnFound++;
		}

		if(GetSecondRgn(m_hFile, m_unSigData.stRgn.by2, sizeof(m_unSigData.stRgn.by2), dwDataOffset))
		{
			bFound = false;
			CreateCRC64Buffer(m_unSigData.stRgn.by2, sizeof(m_unSigData.stRgn.by2), ulHold);
			for(int i = 0; i < 1 && !bFound; i++)
			{
				bFound = ulHold == ulRgnDataChecksum[i];
			}

			if(bFound)
			{
				memset(m_unSigData.stRgn.by2, 0, sizeof(m_unSigData.stRgn.by2));
			}
			else
			{
				ulRgnDataChecksum[1] = ulHold;
				iValRgnFound++;
			}
		}

		if(GetThirdRgn(m_hFile, m_unSigData.stRgn.by3, sizeof(m_unSigData.stRgn.by3), dwDataOffset))
		{
			bFound = false;
			CreateCRC64Buffer(m_unSigData.stRgn.by3, sizeof(m_unSigData.stRgn.by3), ulHold);
			for(int i = 0; i < 2 && !bFound; i++)
			{
				bFound = ulHold == ulRgnDataChecksum[i];
			}

			if(bFound)
			{
				memset(m_unSigData.stRgn.by3, 0, sizeof(m_unSigData.stRgn.by3));
			}
			else
			{
				ulRgnDataChecksum[2] = ulHold;
				iValRgnFound++;
			}
		}

		if(GetFourthRgn(m_hFile, m_unSigData.stRgn.by4, sizeof(m_unSigData.stRgn.by4), dwDataOffset))
		{
			bFound = false;
			CreateCRC64Buffer(m_unSigData.stRgn.by4, sizeof(m_unSigData.stRgn.by4), ulHold);
			for(int i = 0; i < 3 && !bFound; i++)
			{
				bFound = ulHold == ulRgnDataChecksum[i];
			}

			if(bFound)
			{
				memset(m_unSigData.stRgn.by4, 0, sizeof(m_unSigData.stRgn.by4));
			}
			else
			{
				ulRgnDataChecksum[3] = ulHold;
				iValRgnFound++;
			}
		}

		if(GetFifthRgn(m_hFile, m_unSigData.stRgn.by5, sizeof(m_unSigData.stRgn.by5), dwDataOffset))
		{
			bFound = false;
			CreateCRC64Buffer(m_unSigData.stRgn.by5, sizeof(m_unSigData.stRgn.by5), ulHold);
			for(int i = 0; i < 4 && !bFound; i++)
			{
				bFound = ulHold == ulRgnDataChecksum[i];
			}

			if(bFound)
			{
				memset(m_unSigData.stRgn.by5, 0, sizeof(m_unSigData.stRgn.by5));
			}
			else
			{
				ulRgnDataChecksum[4] = ulHold;
				iValRgnFound++;
			}
		}

		if(GetSixthRgn(m_hFile, m_unSigData.stRgn.by6, sizeof(m_unSigData.stRgn.by6), dwDataOffset))
		{
			bFound = false;
			CreateCRC64Buffer(m_unSigData.stRgn.by6, sizeof(m_unSigData.stRgn.by6), ulHold);
			for(int i = 0; i < 5 && !bFound; i++)
			{
				bFound = ulHold == ulRgnDataChecksum[i];
			}

			if(bFound)
			{
				memset(m_unSigData.stRgn.by6, 0, sizeof(m_unSigData.stRgn.by6));
			}
			else
			{
				ulRgnDataChecksum[5] = ulHold;
				iValRgnFound++;
			}
		}
	}

	m_bValidPE = false;
	if(0 == ulRgnDataChecksum[0])
	{
		if(GetFirstRgn(m_hFile, m_unSigData.stRgn.by1, sizeof(m_unSigData.stRgn.by1), dwDataOffset))
		{
			iValRgnFound += IsValidData(m_unSigData.stRgn.by1, sizeof(m_unSigData.stRgn.by1), 95.00f);
		}
	}

	if(0 == ulRgnDataChecksum[1])
	{
		if(GetSecondRgn(m_hFile, m_unSigData.stRgn.by2, sizeof(m_unSigData.stRgn.by2), dwDataOffset))
		{
			iValRgnFound += IsValidData(m_unSigData.stRgn.by2, sizeof(m_unSigData.stRgn.by2), 95.00f);
		}
	}

	if(0 == ulRgnDataChecksum[2])
	{
		if(GetThirdRgn(m_hFile, m_unSigData.stRgn.by3, sizeof(m_unSigData.stRgn.by3), dwDataOffset))
		{
			iValRgnFound += IsValidData(m_unSigData.stRgn.by3, sizeof(m_unSigData.stRgn.by3), 95.00f);
		}
	}

	if(0 == ulRgnDataChecksum[3])
	{
		if(GetFourthRgn(m_hFile, m_unSigData.stRgn.by4, sizeof(m_unSigData.stRgn.by4), dwDataOffset))
		{
			iValRgnFound += IsValidData(m_unSigData.stRgn.by4, sizeof(m_unSigData.stRgn.by4), 95.00f);
		}
	}

	if(0 == ulRgnDataChecksum[4])
	{
		if(GetFifthRgn(m_hFile, m_unSigData.stRgn.by5, sizeof(m_unSigData.stRgn.by5), dwDataOffset))
		{
			iValRgnFound += IsValidData(m_unSigData.stRgn.by5, sizeof(m_unSigData.stRgn.by5), 95.00f);
		}
	}

	if(0 == ulRgnDataChecksum[5])
	{
		if(GetSixthRgn(m_hFile, m_unSigData.stRgn.by6, sizeof(m_unSigData.stRgn.by6), dwDataOffset))
		{
			iValRgnFound += IsValidData(m_unSigData.stRgn.by6, sizeof(m_unSigData.stRgn.by6), 95.00f);
		}
	}

	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : CreateSignatureFromData
In Parameters  : ULONG64& ulSignature
Out Parameters : int 
Description    : check the data collected from file for nulls etc and then create signature
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CMaxFileSig::CreateSignatureFromData(ULONG64& ulSignature)
{
	BYTE byMD5[16] = {0};
	int iNonNullChars = 0, iMinNonNullCharsRequired = 20;

	for(int i = 0; i < sizeof(m_unSigData.byData) && (iNonNullChars < iMinNonNullCharsRequired); i++)
	{
		iNonNullChars += m_unSigData.byData[i] ? 1 : 0;
	}

	if(iNonNullChars < iMinNonNullCharsRequired)
	{
		return SIG_STATUS_FILE_DATA_ONLY_NULLS;
	}

	MD5Buffer(m_unSigData.byData, sizeof(m_unSigData.byData), byMD5, sizeof(byMD5));
	CreateCRC64Buffer(byMD5, 16, ulSignature);
	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : CreatePriSig
In Parameters  : LPCTSTR csFilePath, ULONG64& ulSignature
Out Parameters : int 
Description    : create file signature
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CMaxFileSig::CreateSignature(LPCTSTR csFilePath, ULONG64& ulSignature)
{
	int iRetValue = 0;

	iRetValue = OpenFile(csFilePath);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		return iRetValue;
	}

	iRetValue = CollectDataForSignature();
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		CloseFile();
		return iRetValue;
	}

	iRetValue = CreateSignatureFromData(ulSignature);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		CloseFile();
		return iRetValue;
	}

	iRetValue = CloseFile();
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		return iRetValue;
	}

	return SIG_STATUS_PE_SUCCESS;
}

/*--------------------------------------------------------------------------------------
Function       : CreateSignature
In Parameters  : LPCTSTR csFilePath, FILEINFO& FileInfo
Out Parameters : int 
Description    : create signature and md5 and check if pe file
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
int CMaxFileSig::CreateSignature(LPCTSTR csFilePath, DTL_MAXFINFO& FileInfo)
{
	int iRetValue = 0;
	BYTE byFullMD5[16] = {0};

	memset(&FileInfo, 0, sizeof(FileInfo));

	iRetValue = OpenFile(csFilePath);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		return iRetValue;
	}

	if(INVALID_SET_FILE_POINTER == SetFilePointer(m_hFile, 0, 0, FILE_BEGIN))
	{
		CloseFile();
		return SIG_STATUS_EPSMD5_SIGNATURE_FAILED;
	}

	if(FALSE == MDFile(m_hFile, byFullMD5, m_byReaderBuffer, MAX_READ_BUFFER))
	{
		CloseFile();
		return SIG_STATUS_EPSMD5_SIGNATURE_FAILED;
	}

	FileInfo.ulFileSize = m_ulFileSize;
	CreateCRC64Buffer(byFullMD5, sizeof(byFullMD5), FileInfo.ulMD5);
	memcpy(FileInfo.byMD5,byFullMD5, sizeof(byFullMD5));
	for(int i = 0; i < 16; i++)
	{
		_stprintf_s(FileInfo.szMD5 + (i * 2), _countof(FileInfo.szMD5) - (i * 2), _T("%02x"), byFullMD5[i]);
	}

	iRetValue = CollectDataForSignature();
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		CloseFile();
		return iRetValue;
	}

	iRetValue = CreateSignatureFromData(FileInfo.ulSig);
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		CloseFile();
		return iRetValue;
	}

	iRetValue = CloseFile();
	if(SIG_STATUS_PE_SUCCESS != iRetValue)
	{
		return iRetValue;
	}

	FileInfo.bIsPE = m_bValidPE;

	return SIG_STATUS_PE_SUCCESS;
}

