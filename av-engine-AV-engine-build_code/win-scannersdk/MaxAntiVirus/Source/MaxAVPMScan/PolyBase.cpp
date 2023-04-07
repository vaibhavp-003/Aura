/*======================================================================================
FILE				: PolyBase.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is Parent class for all virus classes
					  Also contains detection and repair routines for small malwares	
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyBase.h"
#include "PolymorphicVirus.h"
#include "MaxBMAlgo.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyBase
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyBase::CPolyBase(CMaxPEFile *pMaxPEFile):
m_pMaxPEFile(pMaxPEFile),
m_pbyBuff(NULL),
m_arrPatchedCallOffsets(false),
m_pSectionHeader(NULL),
m_dwNoOfBytes(0)
{	
	m_pSectionHeader = &m_pMaxPEFile->m_stSectionHeader[0];
	m_wNoOfSections = m_pMaxPEFile->m_stPEHeader.NumberOfSections;	
	m_wAEPSec		= m_pMaxPEFile->m_wAEPSec;
	m_dwAEPMapped	= m_pMaxPEFile->m_dwAEPMapped;
	m_dwAEPUnmapped	= m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
	m_dwImageBase	= m_pMaxPEFile->m_stPEHeader.ImageBase;
	m_dwInstCount	= 0;	
	_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T(""));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyBase
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyBase::~CPolyBase(void)
{	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: HighLevelDetection
	In Parameters	: 
	Out Parameters	: 1 : if file is corrupt else 0
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Primary check for whether AEP is out of File (Corrupt File)
--------------------------------------------------------------------------------------*/
int	CPolyBase::HighLevelDetection()
{
	if(OUT_OF_FILE == m_wAEPSec)
	{
		if(m_dwAEPUnmapped < (m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress +  m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize))
		{
			m_dwAEPMapped = Rva2FileOffsetEx(m_dwAEPUnmapped, &m_wAEPSec);
			if(m_dwAEPMapped && m_wAEPSec < m_wNoOfSections)
			{
				return 1;
			}
		}	
		return 0;
	}
	return 1;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detection routine
					  Every class derived from this class should override this function	
					  Function scans the file to check is the file is infected by virus	
--------------------------------------------------------------------------------------*/
int CPolyBase::DetectVirus(void)
{
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Repair routine
					  Every class derived from this class should override this function	
--------------------------------------------------------------------------------------*/
int CPolyBase::CleanVirus(void)
{
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: Rva2FileOffsetEx
	In Parameters	: DWORD dwRva, WORD *pwRVASection (IN/OUT)
	Out Parameters	: File Offset 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Converts given RVA to related File-offset
--------------------------------------------------------------------------------------*/
DWORD CPolyBase::Rva2FileOffsetEx(DWORD dwRva, WORD *pwRVASection)
{
	DWORD dwTempRVA = 0, dwTempPRD = 0;	
	WORD wSec = m_wNoOfSections - 0x01;

	if(dwRva >=(m_pSectionHeader[wSec].VirtualAddress + m_pSectionHeader[wSec].SizeOfRawData)) 
	{
		//Overlay data is not dependent on RVA/VA
		dwTempPRD = m_pSectionHeader[wSec].PointerToRawData + m_pSectionHeader[wSec].SizeOfRawData;
		dwTempRVA = m_pSectionHeader[wSec].VirtualAddress + m_pSectionHeader[wSec].SizeOfRawData; 
		return((dwRva - dwTempRVA) + dwTempPRD);
	}

	//Inside the file
	for(wSec = 0x00; wSec < m_wNoOfSections; wSec++)
	{
		if(m_pSectionHeader[wSec].Misc.VirtualSize != 0x00)
		{
			if(dwRva >= m_pSectionHeader[wSec].VirtualAddress && dwRva <(m_pSectionHeader[wSec].VirtualAddress + m_pSectionHeader[wSec].SizeOfRawData)) 
			{
				//Same as Rva2FileOffset function
				if(pwRVASection)
				{
					*pwRVASection = wSec;
				}
				return(dwRva - m_pSectionHeader[wSec].VirtualAddress + m_pSectionHeader[wSec].PointerToRawData);
			}
		}
		else
		{
			if(wSec == 0x00)
			{
				if(m_pSectionHeader[wSec].PointerToRawData == 0x00)
				{
					dwTempPRD = m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 
								m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + 
								(m_pMaxPEFile->m_stPEHeader.NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER);
					dwTempPRD =(((dwTempPRD + m_pMaxPEFile->m_stPEHeader.FileAlignment - 1) 
						/ m_pMaxPEFile->m_stPEHeader.FileAlignment)
									 * m_pMaxPEFile->m_stPEHeader.FileAlignment);
				}
				else
				{
					dwTempPRD = m_pSectionHeader[wSec].PointerToRawData;
				}
				
				if(m_pSectionHeader[wSec].VirtualAddress == 0x00)
					dwTempRVA = m_pMaxPEFile->m_stPEHeader.SectionAlignment;
				else
					dwTempRVA = m_pSectionHeader[wSec].VirtualAddress;
			}
			else
			{
				if(m_pSectionHeader[wSec].PointerToRawData == 0x00)
					dwTempPRD += m_pSectionHeader[wSec - 1].SizeOfRawData;
				else
					dwTempPRD = m_pSectionHeader[wSec].PointerToRawData;

				if(m_pSectionHeader[wSec].VirtualAddress == 0x00)
				{
					dwTempRVA =(((dwTempRVA + m_pSectionHeader[wSec - 1].Misc.VirtualSize + m_pMaxPEFile->m_stPEHeader.SectionAlignment-1) 
									 / m_pMaxPEFile->m_stPEHeader.SectionAlignment)
									 * m_pMaxPEFile->m_stPEHeader.SectionAlignment);
				}
				else
					dwTempRVA = m_pSectionHeader[wSec].VirtualAddress;
			}

			if(dwRva >= dwTempRVA && dwRva <=(dwTempRVA+m_pSectionHeader[wSec].SizeOfRawData))
			{
				if(pwRVASection)
				{
					*pwRVASection = wSec;
				}

				return((dwRva - dwTempRVA) + dwTempPRD);
			}
		}
		if(wSec == m_wNoOfSections - 1)
		{
			break;
		}
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: GetBuffer
	In Parameters	: DWORD	    : No. of Bytes to Read
					  DWORD		:(OPTIONAL) Min Bytes to Read.
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Reads binary buffer from file
--------------------------------------------------------------------------------------*/
bool CPolyBase::GetBuffer(DWORD dwOffset, DWORD dwNumberOfBytesToRead, DWORD dwMinBytesReq)
{
	m_dwNoOfBytes = 0;
	return m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwOffset, dwNumberOfBytesToRead, dwMinBytesReq, &m_dwNoOfBytes);	
}

/*-------------------------------------------------------------------------------------
	Function		: MakeDword
	In Parameters	: char *pString,  char chSearch
	Out Parameters	: DWORD
	Purpose			: 
	Author			: Tushar Kadam
	Description		: converts char string to DWORD. Used in dis-assembly
--------------------------------------------------------------------------------------*/
DWORD CPolyBase::MakeDword(char *pString,  char chSearch)
{	
	char *ptr = strrchr(pString, chSearch);
	if(ptr)
	{
		ptr++;
		int iLen = strlen(ptr);
		for(; iLen > 8; iLen--)
		{
			if(*ptr == 0x46)
				ptr++;
		}
		
		DWORD	dwValue = 0x00;
		char	szString[9] = {0};

		if(iLen == 0x08)
		{
			szString[0] = ptr[6];
			szString[1] = ptr[7];
			szString[2] = ptr[4];
			szString[3] = ptr[5];
			szString[4] = ptr[2];
			szString[5] = ptr[3];
			szString[6] = ptr[0];
			szString[7] = ptr[1];
			szString[8] = '\0';

			sscanf_s(szString, "%X", &dwValue);
		}
		else
			sscanf_s(ptr, "%X", &dwValue);
		
		return dwValue;
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForZeros
	In Parameters	: DWORD dwReadOffset, DWORD dwNumberOfBytes
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: checks for consicutive 0's at given file offset
--------------------------------------------------------------------------------------*/
bool CPolyBase::CheckForZeros(DWORD dwReadOffset, DWORD dwNumberOfBytes)
{
	try
	{		
		DWORD READ_BUFF_SIZE = 0x4000;
		if(READ_BUFF_SIZE > dwNumberOfBytes)
		{
			READ_BUFF_SIZE = dwNumberOfBytes;
		}

		BYTE *pBuffer		= new BYTE[READ_BUFF_SIZE];
		BYTE *pFileBuffer	= new BYTE[READ_BUFF_SIZE];
		
		
		if(!pBuffer || !pFileBuffer)
		{
			return false;
		}

		DWORD dwBytesRead = 0x00;
		for(DWORD dwOffset = dwReadOffset; dwOffset <(dwReadOffset + dwNumberOfBytes); dwOffset += READ_BUFF_SIZE)
		{
			memset(pFileBuffer, 0x00, READ_BUFF_SIZE);
		
			if(m_pMaxPEFile->ReadBuffer(pFileBuffer, dwOffset, READ_BUFF_SIZE, 0, &dwBytesRead))
			{
				if((dwOffset + READ_BUFF_SIZE) > (dwReadOffset + dwNumberOfBytes) || dwBytesRead != READ_BUFF_SIZE)
				{
					dwBytesRead = (dwReadOffset + dwNumberOfBytes) - dwOffset;
				}
                BYTE byTest = pFileBuffer[0];
				memset(pBuffer, byTest, READ_BUFF_SIZE);
				if(memcmp(pBuffer, pFileBuffer, dwBytesRead) != 0)
				{
					delete []pBuffer;
					delete []pFileBuffer;

					return false; //Contains data so do not delete.
				}
			}
		}		
		if(pBuffer)
			delete []pBuffer;
		if(pFileBuffer)
			delete []pFileBuffer;

		return true; //Contains zeros so can be removed
	}
	catch(...)
	{
		OutputDebugString(L"CPolymorphicVirus::CheckForZeros : Exception Cought");
		return false;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CheckPnuemonics
	In Parameters	: BYTE *pBuffer, DWORD dwModeOffset, DWORD dwInstructionCount, char *Opcode, DWORD opLength, char *PnuemonicsToSearch
	Out Parameters	: 1 : if success else 0 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Generates Pnuemonics for CPU Instrctuion from fiven address
--------------------------------------------------------------------------------------*/
int	CPolyBase::CheckPnuemonics(BYTE *pBuffer, DWORD dwModeOffset, DWORD dwInstructionCount, char *Opcode, DWORD opLength, char *PnuemonicsToSearch)
{
	DWORD	dwOffset = 0, dwLength = 0, dwNewInstCount = 0;
	DWORD	dwSize = dwModeOffset;

	t_disasm	da;
	BYTE		B1, B2;
	char		*ptr = NULL;

	while(dwOffset < dwSize)
	{
		if(dwNewInstCount >= dwInstructionCount)
		{
			break;
		}

		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = *((BYTE *)&pBuffer[dwOffset]);
		B2 = *((BYTE *)&pBuffer[dwOffset + 1]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1 == 0xC1 &&(B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset += 0x03;
			continue;
		}
		if(B1 == 0xD1 &&(B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset += 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&pBuffer[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (dwSize - dwOffset))
		{
			break;
		}

		dwNewInstCount++;

		if(dwLength==0x01 && B1==0xE2 && strstr(da.result, "???"))
		{
			dwOffset += 0x02;
			continue;
		}

		if((dwLength >= opLength) && strstr(da.dump, Opcode) && strstr(da.result, PnuemonicsToSearch))
		{
			return 1;
		}
		dwOffset += dwLength;
	}
	return 0;
}


/*-------------------------------------------------------------------------------------
	Function		: CheckPnuemonics
	In Parameters	: BYTE Array					: Main Buffer
					  BYTE Array					: Signature array
					  DWORD dwSizeofMainBuffer	: Size to Compare, 
					  Should be less than 0x30
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund
	Description		: Offsetbased Signature Detection for specific condition
--------------------------------------------------------------------------------------*/
bool CPolyBase::OffSetBasedSignature(BYTE *byteSig, DWORD dwSizeofSig, DWORD *dwIndex)
{
	for(DWORD dwOffset = 0; dwOffset <= m_dwNoOfBytes - (dwSizeofSig + 1); dwOffset++)
	{
		if(memcmp(&m_pbyBuff[dwOffset], byteSig, dwSizeofSig) == 0)
		{
			if(dwIndex)
			{
				*dwIndex = dwOffset;
			}
			return true;
		}
	}	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetPatchedCalls
	In Parameters	: BYTE Array		: AEP Secn Buff from AEP till Section Ends
					  BYTE Array Size	: Size of the Buffer
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund
	Description		: 1)	Saves all the Calls result(i.e Called Address) in Array 
						which goes from from AEP Section to Last Section.
					  2)	Saves the Corresponding Calls Offsets from AEP also.
--------------------------------------------------------------------------------------*/
bool CPolyBase::GetPatchedCalls(DWORD dwSearchStartAddress, DWORD dwSearchEndAddress, WORD wCallToSection, bool bSearchForE9/* = false*/, bool bGetAllCalls/* = false*/, bool bGetFirstPatchedCall/* = false*/)
{
	BYTE *byBuffer = NULL;
	DWORD dwChunk = 0x10000;
	if((dwSearchEndAddress -  dwSearchStartAddress)< dwChunk)
	{
		dwChunk = dwSearchEndAddress -  dwSearchStartAddress;
	}

	byBuffer = new BYTE[dwChunk];
	if(!byBuffer)
	{
		return false;
	}
	TCHAR szMsg[1024] = {0};
	DWORD dwBytesRead = 0, dwCallAddressVA = 0, dwBytesToRead = 0;
	WORD wScanSecNo = 0;
	for(DWORD dwReadOffset = dwSearchStartAddress; dwReadOffset < dwSearchEndAddress; dwReadOffset += dwChunk)
	{
		dwBytesToRead = (dwSearchEndAddress - dwReadOffset) < dwChunk ?  (dwSearchEndAddress - dwReadOffset) : dwChunk;
		if(m_pMaxPEFile->ReadBuffer(byBuffer, dwReadOffset, dwBytesToRead, 0, &dwBytesRead))
		{
			for(DWORD dwOffset = 0; dwOffset < dwBytesRead; dwOffset++)
			{
				if(byBuffer[dwOffset] == 0xE8 || (bSearchForE9 && byBuffer[dwOffset] == 0xE9))
				{
					if(dwBytesRead - dwOffset < E8_INSTRUCTION_SIZE)
					{
						// offset is at the end such that we cannt read DWORD address so read 
						// last 5 bytes again so that we can read the call instruction completely
						if(!m_pMaxPEFile->ReadBuffer(&dwCallAddressVA, dwReadOffset + dwOffset + 1, sizeof(DWORD), sizeof(DWORD)))
						{
							continue;
						}
					}
					else
					{
						dwCallAddressVA = *((DWORD *)&byBuffer[dwOffset + 1]);
					}
					wScanSecNo = m_pMaxPEFile->GetSectionNoFromOffset(dwReadOffset + dwOffset);
					if(OUT_OF_FILE == wScanSecNo)
					{
						continue;
					}
					dwCallAddressVA += m_pSectionHeader[wScanSecNo].VirtualAddress + dwReadOffset - m_pSectionHeader[wScanSecNo].PointerToRawData + dwOffset + E8_INSTRUCTION_SIZE;

					// If call is out of the file then skip
					if(dwCallAddressVA >= (m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize))
					{
						continue;
					}
									
					// check if the call is in the reauired section. If so its patched call.
					if((dwCallAddressVA >= m_pSectionHeader[wCallToSection].VirtualAddress) && (dwCallAddressVA <(m_pSectionHeader[wCallToSection].VirtualAddress + m_pSectionHeader[wCallToSection].Misc.VirtualSize)))
					{					
						// Found patched E8/E9 so maintain the address
						if(bGetAllCalls)
						{
							m_arrPatchedCallOffsets.AppendItem(dwReadOffset + dwOffset, dwCallAddressVA);
						}
						else
						{
							m_arrPatchedCallOffsets.AppendItem(dwCallAddressVA, dwReadOffset + dwOffset);
						}
						if(bGetFirstPatchedCall)
						{
							if(byBuffer)
							{
								delete []byBuffer;
								byBuffer = NULL;
							}
							return true;
						}
					}
				}
			}
		}
	}
	if(byBuffer)
	{
		delete []byBuffer;
		byBuffer = NULL;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolySatir
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolySatir::CPolySatir(CMaxPEFile *pMaxPEFile)
:CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolySatir
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolySatir::~CPolySatir(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Satir Family
--------------------------------------------------------------------------------------*/
int CPolySatir::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;	 

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
	const int SATIR_BUFF_SIZE = 0x40;
	m_pbyBuff = new BYTE[SATIR_BUFF_SIZE];
	if(GetBuffer(0x38, 4, 4))
	{
		if(m_pbyBuff[0] == 0x41 && m_pbyBuff[1] == 0x49 && m_pbyBuff[2] == 0x4E && m_pbyBuff[3] == 0x41)
		{
			if(GetBuffer(m_dwAEPMapped + 0x1, 4, 4))
			{	
				// Virus patches a jump instruction at the start of AEP. Calculate the jump address
				// to match the signature.
				m_dwVirusStartOffset = *((DWORD*)m_pbyBuff) + m_dwAEPUnmapped + 5;					
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwVirusStartOffset, &m_dwVirusStartOffset))
				{
					if(GetBuffer(m_dwVirusStartOffset, SATIR_BUFF_SIZE, SATIR_BUFF_SIZE))
					{
						if(m_pbyBuff[0] == 0x9C && m_pbyBuff[2] == 0x68)
						{
							const BYTE bySignature1[] = {0x5F, 0x81, 0xC7, 0x19, 0x00, 0x00, 0x00, 0xB9, 
														 0xE2, 0x03, 0x00, 0x00, 0x58, 0x31, 0x07, 0x81, 
														 0xC7, 0x04, 0x00, 0x00, 0x00, 0xE2, 0xF6, 0x61, 0x9D};

							if(memcmp(&m_pbyBuff[0xC], bySignature1, sizeof(bySignature1)) == 0x00)
							{
								m_dwDecKey = *((DWORD*)&m_pbyBuff[3]);
								iRetStatus = VIRUS_FILE_REPAIR;
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Satir.994"));	
							}
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of Satir Family
--------------------------------------------------------------------------------------*/
int CPolySatir::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;

	if(GetBuffer(m_dwVirusStartOffset + 3985, 8, 8))
	{
		for(DWORD dwIndex = 0x00; dwIndex < 2; dwIndex++)
		{
			*((DWORD *)&m_pbyBuff[dwIndex * 4]) ^= m_dwDecKey;
		}
		
		if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x01], m_dwAEPMapped, 5, 5))
		{
			return iRetStatus;
		}
	
		m_pMaxPEFile->FillWithZeros(0x38, 0x4);
	
		if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}

/*
CPolyOporto::CPolyOporto(CMaxPEFile *pMaxPEFile)
: CPolyBase(pMaxPEFile)
{
}

CPolyOporto::~CPolyOporto(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
int CPolyOporto::DetectVirus()
{
	if((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0x80000000) == 0x80000000)
	{
		const int OPORTO_BUFF_SIZE = 0x30;
		m_pbyBuff = new BYTE[OPORTO_BUFF_SIZE];				
		if(GetBuffer(m_dwAEPMapped, 6, 6))
		{
			if(m_pbyBuff[0] == 0x68 && m_pbyBuff[5] == 0xC3)
			{
				m_dwVirusStartOffset = *((DWORD *)&m_pbyBuff[1]) - m_dwImageBase;
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwVirusStartOffset, &m_dwVirusStartOffset))
				{
					if(GetBuffer(m_dwVirusStartOffset, OPORTO_BUFF_SIZE, OPORTO_BUFF_SIZE))
					{
						const BYTE bySignature1[] = {0xB8, 0xFB, 0x02, 0x00, 0x00, 0xB9};
						const BYTE bySignature2[] = {0x83, 0xC1, 0x04, 0x48, 0x75, 0xF4};
						const WORD wSignature3  = 0x3181;

						if(memcmp(&m_pbyBuff[0], bySignature1, sizeof(bySignature1)) == 0x00 &&
							memcmp(&m_pbyBuff[16], bySignature2, sizeof(bySignature2)) == 0x00 &&
							*((WORD *)&m_pbyBuff[10]) == wSignature3)
						{
							m_dwDecKey = *((DWORD*)&m_pbyBuff[12]);
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Opotro.3076"));	
							return VIRUS_FILE_REPAIR;
						}
					}
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

int CPolyOporto::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;

	if(GetBuffer(m_dwVirusStartOffset + 118, 12, 12))
	{
		for(DWORD dwIndex = 0; dwIndex < 3; dwIndex++)
		{
			*((DWORD *)&m_pbyBuff[dwIndex * 4]) ^= m_dwDecKey;
		}

		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x03], m_dwAEPMapped, 6, 6))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
	}
	return iRetStatus;
}
*/

/*-------------------------------------------------------------------------------------
	Function		: CPolyKenston
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyKenston::CPolyKenston(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyKenston
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyKenston::~CPolyKenston(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Kenston Family
--------------------------------------------------------------------------------------*/
int CPolyKenston::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;	 	
	if((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xA0000000) == 0xA0000000)
	{
		BYTE byDOSReserved = 0;
		if(!m_pMaxPEFile->ReadBuffer(&byDOSReserved, 0x3B, 1, 1))
		{
			return iRetStatus;
		}
		if(0x61 != byDOSReserved)
		{
			return iRetStatus;
		}

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int KESTON_BUFF_SIZE = 0x700;
		m_pbyBuff = new BYTE[KESTON_BUFF_SIZE];		
		if(GetBuffer(m_dwAEPMapped, KESTON_BUFF_SIZE, KESTON_BUFF_SIZE))
		{
			const BYTE bySignature1[] = {0xB9, 0x52, 0x07, 0x00, 0x00, 0xBB};
			const BYTE bySignature2[] = {0x30, 0x03, 0x43, 0x49, 0x83, 0xF9 , 0x00, 0x75, 0xF7};

			if(m_pbyBuff[10] == 0xB0 &&
				memcmp(&m_pbyBuff[0], bySignature1, sizeof(bySignature1)) == 0x00 &&
				memcmp(&m_pbyBuff[12], bySignature2, sizeof(bySignature2)) == 0x00)
			{
				DWORD dwDecStartRVA = *((DWORD *)&m_pbyBuff[6])- m_dwImageBase, dwDecStartOffset = 0;				
				BYTE byDecKey = m_pbyBuff[11];

				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwDecStartRVA, &dwDecStartOffset))
				{
					dwDecStartOffset -= m_dwAEPMapped; 

					for(DWORD dwIndex = 0, dwIndex2 = 0x65A; dwIndex < 0x75; dwIndex++, dwIndex2++)
					{
						m_pbyBuff[dwIndex] ^= byDecKey;
						m_pbyBuff[dwIndex2] ^= byDecKey;
					}
					const BYTE bySignature[] ={
						0x01, 0x42, 0x6F, 0x6C, 0x65, 0x73, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x4D, 0x61, 0x6E, 0x6E, 0x69, 
						0x6E, 0x67, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61, 0x72, 0x72, 0x6F, 0x67, 0x61, 0x6E, 0x74, 0x20, 
						0x66, 0x61, 0x63, 0x69, 0x73, 0x74, 0x73, 0x2E, 0x20, 0x20, 0x54, 0x68, 0x65, 0x79, 0x20, 0x68, 
						0x61, 0x76, 0x65, 0x20, 0x6E, 0x6F, 0x20, 0x63, 0x6F, 0x6D, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20, 
						0x73, 0x6B, 0x31, 0x6C, 0x6C, 0x7A, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x4B, 0x45, 0x4E, 0x53, 0x54, 
						0x4F, 0x4E, 0x20, 0x48, 0x49, 0x47, 0x48, 0x20, 0x53, 0x43, 0x48, 0x4F, 0x4F, 0x4C, 0x27, 0x73, 
						0x20, 0x20, 0x63, 0x6F, 0x6D, 0x70, 0x75, 0x74, 0x65, 0x72, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 
						0x30, 0x77, 0x6E, 0x33, 0x64};

					if(memcmp(&m_pbyBuff[0x65A], bySignature, sizeof(bySignature)) == 0x00)
					{
						m_dwOriginalAEP = dwDecStartRVA + 0x05 - (*(DWORD *)&m_pbyBuff[dwDecStartOffset + 0xA]);
						if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL))
						{
							iRetStatus = VIRUS_FILE_REPAIR;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Kenston.1895.A"));	
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of Kenston Family
--------------------------------------------------------------------------------------*/
int CPolyKenston::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->FillWithZeros(0x3A, sizeof(WORD)))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped, true))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyCrazyPrier
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyCrazyPrier::CPolyCrazyPrier(CMaxPEFile *pMaxPEFile)
:CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyCrazyPrier
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyCrazyPrier::~CPolyCrazyPrier(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;		
	}
	m_arrPatchedCallOffsets.RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Virus.CrazyPrier Family
--------------------------------------------------------------------------------------*/
int CPolyCrazyPrier::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	const int CrazyPrier_Buff_Size = 0x500;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	m_pbyBuff = new BYTE[CrazyPrier_Buff_Size];

	if(!m_pbyBuff)
	{
		iRetStatus;
	}

	if(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".rsrc", 5) == 0 && 
		m_pSectionHeader[m_wNoOfSections-1].Characteristics == 0xE00000E0 && 
		m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize >= 0x7000 &&
		m_wAEPSec != m_wNoOfSections - 1)
	{
		DWORD dwDecrypKey = 0; 

		if(m_pMaxPEFile->ReadBuffer(&dwDecrypKey, m_pSectionHeader[m_wNoOfSections-1].PointerToRawData, 4, 4, NULL))
		{
			DWORD dwStartOffset;
			if(m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData >= 0xCC00)
			{
				dwStartOffset = m_pSectionHeader[m_wNoOfSections-1].PointerToRawData + 0x80E0;
			}
			else
			{
				dwStartOffset = m_pSectionHeader[m_wNoOfSections-1].PointerToRawData + 0x5700;
			}

			if(GetBuffer(dwStartOffset, CrazyPrier_Buff_Size, CrazyPrier_Buff_Size))
			{
				for(DWORD i = 0x0; i< 0x500; i+= 4)
				{
					*(DWORD *)&m_pbyBuff[i] ^= dwDecrypKey;
				}
				// Sign1: baidu.com
				BYTE byCrazyPrier_Sign1[] = {0x62, 0x61, 0x69, 0x64, 0x75, 0x2E, 0x63, 0x6F, 0x6D};
				// Sign2: home.51
				BYTE byCrazyPrier_Sign2[] = {0x68, 0x6F, 0x6D, 0x65, 0x2E, 0x35, 0x31};

				if(OffSetBasedSignature(byCrazyPrier_Sign1,sizeof(byCrazyPrier_Sign1),NULL) &&
					OffSetBasedSignature(byCrazyPrier_Sign2,sizeof(byCrazyPrier_Sign2),NULL))
				{
					iRetStatus = VIRUS_FILE_REPAIR;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.CrazyPrier.a"));
					return iRetStatus;
				}
			}
		}
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of Virus.CrazyPrier Family
--------------------------------------------------------------------------------------*/
int CPolyCrazyPrier::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	DWORD dwCallAddr = 0, dwJumpLocation = 0, dwCallOffset = 0;

	// added only if condition here
	if(GetPatchedCalls(m_pSectionHeader[m_wAEPSec].PointerToRawData, m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData, m_wNoOfSections - 1, false, true))
	{		
		LPVOID lpPos = m_arrPatchedCallOffsets.GetLowest();
		while(lpPos)
		{
			m_arrPatchedCallOffsets.GetData(lpPos, dwCallAddr);
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwCallAddr, &dwCallOffset))
			{
				if(GetBuffer(dwCallOffset + 5, 5, 5))
				{
					if(m_pbyBuff[0] == 0xE9)
					{
						m_arrPatchedCallOffsets.GetKey(lpPos, dwJumpLocation);
						DWORD dwOriData = (dwCallAddr + 0x5) + *(DWORD *)&m_pbyBuff[1] - dwJumpLocation - (m_pSectionHeader[m_wAEPSec].VirtualAddress - m_pSectionHeader[m_wAEPSec].PointerToRawData);

						if(!m_pMaxPEFile->WriteBuffer(&dwOriData, dwJumpLocation + 1, sizeof(DWORD), sizeof(DWORD)))
						{
							return iRetStatus;
						}
					}
				}
			}
			lpPos = m_arrPatchedCallOffsets.GetLowestNext(lpPos);	
		}
		if(m_pMaxPEFile->RemoveSection(m_wNoOfSections))
		{
			iRetStatus = REPAIR_SUCCESS;
		}	

	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyVB
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyVB::CPolyVB(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyVB
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyVB::~CPolyVB(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of VB Family
--------------------------------------------------------------------------------------*/
int CPolyVB::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		m_wAEPSec == m_wNoOfSections - 1 &&
		memcmp(m_pSectionHeader[0].Name, "TopFox", 6) == 0)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int VB_BUFF_SIZE = 0x1B;
		m_pbyBuff = new BYTE[VB_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, VB_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, VB_BUFF_SIZE))
		{
			BYTE		B1, B2;
			DWORD		dwLength = 0x00, dwInstructionCnt = 0x00, dwStartAddress = 0x00, dwCheckAdd =0x00;
			DWORD		dwValue = 0x00;
			t_disasm	da;

			while(dwStartAddress < m_dwNoOfBytes)
			{
				if(dwInstructionCnt > 0x08)
				{
					return iRetStatus;
				}

				memset(&da, 0x00, sizeof(struct t_disasm)*1);

				B1 = *((BYTE *)&m_pbyBuff[dwStartAddress]);
				B2 = *((BYTE *)&m_pbyBuff[dwStartAddress + 1]);

				//Handling for garbage instruction.
				if(B1==0xC1 && (B2>=0xF0 && B2<=0xF7))
				{
					dwStartAddress+= 0x03;
					continue;
				}
				if(B1==0xD1 && (B2>=0xF0 && B2<=0xF7))
				{
					dwStartAddress+= 0x02;
					continue;
				}
				if(B1==0xD0 && (B2>=0xF0 && B2<=0xF7))
				{
					dwStartAddress+= 0x02;
					continue;
				}
				if(B1==0xD2 && (B2>=0xF0 && B2<=0xF7))
				{
					dwStartAddress+= 0x02;
					continue;
				}
				dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStartAddress], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > m_dwNoOfBytes - dwStartAddress)
				{
					return iRetStatus;
				}
				dwInstructionCnt++;
				dwStartAddress += dwLength;

				if(B1 == 0x60 && dwValue == 0x00 && dwLength == 0x01 && strstr(da.result, "PUSHAD"))
				{
					dwValue++;
					continue;
				}
				if(B1 == 0x6A && dwValue == 0x01 && dwLength == 0x02 && strstr(da.result, "PUSH"))
				{
					dwValue++;
					continue;
				}
				if(B1 == 0x68 && dwValue == 0x02 && dwLength == 0x05 && strstr(da.result, "PUSH"))
				{
					dwValue++;
					continue;
				}
				if(B1 == 0xB8 && dwValue == 0x03 && dwLength == 0x05 && strstr(da.result, "MOV EAX,"))
				{
					dwValue++;
					continue;
				}
				if(B1 == 0xFF && dwValue == 0x04 && dwLength == 0x02 && strstr(da.result, "CALL EAX"))
				{
					dwValue++;
					continue;
				}
				if(B1 == 0x61 && dwValue == 0x05 && dwLength == 0x01 && strstr(da.result, "POPAD"))
				{
					dwValue++;
					continue;
				}
				if(B1 == 0xB8 && dwValue == 0x06 && dwLength == 0x05 && strstr(da.result, "MOV EAX"))
				{
					dwValue++;
					continue;
				}
				if(B1 == 0xFF && dwValue == 0x07 && dwLength == 0x02 && strstr(da.result, "JMP EAX"))
				{
					iRetStatus = VIRUS_FILE_REPAIR;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.VB.AC"));
					break;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of VB Family
--------------------------------------------------------------------------------------*/
int CPolyVB::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;

	DWORD  dwOriAEP = *((DWORD*) &m_pbyBuff[17]) - m_dwImageBase;

	if(!m_pMaxPEFile->WriteAEP(dwOriAEP))
	{
		return iRetStatus;
	}
	
	if(m_pMaxPEFile->FillWithZeros((m_dwAEPMapped-0x04),0x1B))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyKanban
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyKanban::CPolyKanban(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyKanban
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyKanban::~CPolyKanban(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Kanban Family
--------------------------------------------------------------------------------------*/
int CPolyKanban::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > 0x3000)
	{
		WORD wBytesOnLastPage = 0;
		m_pMaxPEFile->ReadBuffer(&wBytesOnLastPage, 2, 2);
		if(0x4AEB != wBytesOnLastPage)
		{
			return iRetStatus;
		}

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		m_pbyBuff = new BYTE[0x40];

		// Check for string KANBAN
		const BYTE KANBAN_SIG1[] = {0x4B, 0x41, 0x4E, 0x42, 0x41, 0x4E};
		if(GetBuffer(m_pMaxPEFile->m_dwFileSize - 0x2581, sizeof(KANBAN_SIG1), sizeof(KANBAN_SIG1)))
		{
			if(memcmp(m_pbyBuff, KANBAN_SIG1, sizeof(KANBAN_SIG1)) == 0)
			{
				// Check for string "INVICTUS" LIBRARY 0.99 BY NBKP
				const BYTE KANBAN_SIG2[] = {0x22, 0x49, 0x4E, 0x56, 0x49, 0x43, 0x54, 0x55, 
					0x53, 0x22, 0x20, 0x4C, 0x49, 0x42, 0x52, 0x41, 
					0x52, 0x59, 0x20, 0x30, 0x2E, 0x39, 0x39, 0x20, 
					0x42, 0x59, 0x20, 0x4E, 0x42, 0x4B, 0x50};
				if(GetBuffer(m_pMaxPEFile->m_dwFileSize - 0x2D7F, sizeof(KANBAN_SIG2), sizeof(KANBAN_SIG2)))
				{
					if(memcmp(m_pbyBuff, KANBAN_SIG2, sizeof(KANBAN_SIG2)) == 0)
					{
						iRetStatus = VIRUS_FILE_REPAIR;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Kanban.A"));
					}
				}				
			}
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of Kanban Family
--------------------------------------------------------------------------------------*/
int CPolyKanban::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;

	DWORD dwOriginalAEP = 0;
	
	if(m_pMaxPEFile->ReadBuffer(&dwOriginalAEP, m_pMaxPEFile->m_dwFileSize - 0x2C27, sizeof(DWORD)))
	{
		if(m_pMaxPEFile->WriteAEP(dwOriginalAEP))
		{
			if(m_pMaxPEFile->TruncateFile(m_pMaxPEFile->m_dwFileSize - 0x2EC2, true))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyKoru
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyKoru::CPolyKoru(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyKoru
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyKoru::~CPolyKoru(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Koru Family
--------------------------------------------------------------------------------------*/
int CPolyKoru::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
		
	WORD wReservedBytes = 0;
	m_pMaxPEFile->ReadBuffer(&wReservedBytes, 0x28, sizeof(WORD), sizeof(WORD));

	if((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xA0000020) == 0xA0000020 && wReservedBytes == 0x5A76)
	{
		BYTE bJmpInst[5] = {0};
		if(m_pMaxPEFile->ReadBuffer(bJmpInst, m_dwAEPMapped, 5, 5))
		{
			// First Byte should be 0xE9 which is JMP 
			if(bJmpInst[0] == 0xE9)
			{			
				// Calculate JMP address
				DWORD dwJumpRVA = *((DWORD *)&bJmpInst[1]) + 0x05 + m_dwAEPUnmapped;

				m_dwJumpOffset = 0x00;
				if((m_wNoOfSections - 1) ==	m_pMaxPEFile->Rva2FileOffset(dwJumpRVA, &m_dwJumpOffset))
				{
					if(m_pbyBuff)
					{
						delete []m_pbyBuff;
						m_pbyBuff = NULL;
					}
					const int KORU_BUFF_SIZE = 0x168;
					m_pbyBuff = new BYTE[KORU_BUFF_SIZE + MAX_INSTRUCTION_LEN];
					if(!m_pbyBuff)
					{
						return iRetStatus;
					}
					memset(m_pbyBuff, 0, KORU_BUFF_SIZE + MAX_INSTRUCTION_LEN);

					if(GetBuffer(m_dwJumpOffset, KORU_BUFF_SIZE, KORU_BUFF_SIZE))
					{
						if(m_pbyBuff[0] == 0xE8 && m_pbyBuff[1] == 0x00 && m_pbyBuff[2] == 0x00 && m_pbyBuff[3] == 0x00  && m_pbyBuff[4] == 0x00)
						{						
							if(GetKoruParam())
							{
								iRetStatus = VIRUS_FILE_REPAIR;
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Koru"));
							}
							
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKoruParam
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Collects all the nccessary parameters required for repair
--------------------------------------------------------------------------------------*/
bool CPolyKoru::GetKoruParam()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD		dwLength = 0, dwOffset=0, dwMatchedInstr = 0;
	t_disasm	da;

	while(dwOffset < 0x100)
	{
		memset(&da, 0x00, sizeof(struct t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	

		if(dwMatchedInstr == 0 && dwLength == 5 || dwLength == 6 && strstr(da.result, "ADD"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 1 && dwLength == 5 && strstr(da.result, "MOV"))
		{
			dwMatchedInstr++;
		}
		else  if(dwMatchedInstr == 2 && dwLength == 8 && strstr(da.result, "XOR"))
		{
			dwMatchedInstr++;
			
			//XOR Key			
			*((DWORD *)&m_pbyBuff[0x160]) ^= *((DWORD *)&m_pbyBuff[dwOffset + 0x4]);
			*((DWORD *)&m_pbyBuff[0x164]) ^= *((DWORD *)&m_pbyBuff[dwOffset + 0x4]);			
		}

		else if(dwMatchedInstr == 3 && dwLength == 1 && strstr(da.result, "DEC"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 4 && dwLength == 2 && strstr(da.result, "OR"))
		{	
			return true;
		}
		dwOffset += dwLength;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of Koru Family
--------------------------------------------------------------------------------------*/
int CPolyKoru::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x163], m_dwAEPMapped, 5, 5))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwJumpOffset - 0xC30, true))
		{
			if(m_pMaxPEFile->FillWithZeros(0x28, 2))	
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyInvictus
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyInvictus::CPolyInvictus(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_dwTruncationOffSet = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyInvictus
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyInvictus::~CPolyInvictus(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Invictus Family
--------------------------------------------------------------------------------------*/
int CPolyInvictus::DetectVirus()
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	DWORD	dwOffSet = 0x00;

	if (m_dwAEPUnmapped == 0x00 && m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData > 0x42C2)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int INVICTUS_BUFF_SIZE = 0x2000;
		m_pbyBuff = new BYTE[INVICTUS_BUFF_SIZE];
		if (NULL == m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 00, INVICTUS_BUFF_SIZE);

		DWORD dwOffSet = m_pMaxPEFile->m_dwFileSize - 0x42C2;

		if(!GetBuffer(dwOffSet,INVICTUS_BUFF_SIZE, 0x1000))
		{
			return iRetStatus;
		}

		BYTE bFirstSig[] = {
			0x60, 0x81, 0xEC, 0x30, 0x01, 0x00, 0x00, 0x8B, 0xEC, 0x33, 0xC9, 0x81, 0xE9, 0x00, 0x86, 0x86, 
			0x87, 0x51, 0x81, 0xF1, 0x45, 0x36, 0x4A, 0x4A};	
		
		BYTE bSecSig[] = {
			0x22, 0x49, 0x4E, 0x56, 0x49, 0x43, 0x54, 0x55, 0x53, 0x22, 0x20, 0x4C, 0x49, 0x42, 0x52, 0x41, 
			0x52, 0x59, 0x20, 0x30, 0x2E, 0x39, 0x39, 0x20, 0x42, 0x59, 0x20, 0x4E, 0x42, 0x4B, 0x50};

		if(memcmp(&m_pbyBuff[0x00], bFirstSig, sizeof(bFirstSig)) == 0x00 && memcmp(&m_pbyBuff[0x143], bSecSig, sizeof(bSecSig)) == 0x00)
		{			
			DWORD dwMappedAddress = 0;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(*((DWORD *)&m_pbyBuff[0x29B]), &dwMappedAddress) && dwMappedAddress < dwOffSet)
			{
				m_dwTruncationOffSet = dwOffSet;
				iRetStatus = VIRUS_FILE_REPAIR;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Invictus.099"));
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Invictus Family
--------------------------------------------------------------------------------------*/
int CPolyInvictus::CleanVirus()
{
	if (m_pMaxPEFile->WriteAEP(*((DWORD *)&m_pbyBuff[0x29B])))
	{
		if (m_pMaxPEFile->TruncateFile(m_dwTruncationOffSet))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyHIV
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyHIV::CPolyHIV(CMaxPEFile *pMaxPEFile): 
CPolyBase(pMaxPEFile),
m_bFoundCallPatched(false)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyHIV
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyHIV::~CPolyHIV(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of HIV Family
--------------------------------------------------------------------------------------*/
int CPolyHIV::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;	
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		//((m_pSectionHeader[m_wNoOfSections-1].Characteristics == 0xC2000040) || (m_pSectionHeader[m_wNoOfSections-1].Characteristics == 0xC0000040)) && 
		 (m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= HIV_VIRUS_CODE_SIZE) &&
		 m_wAEPSec != m_wNoOfSections - 1)		
	{	
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[HIV_BUFF_SIZE];
		if(GetPatchedCalls(m_pSectionHeader[m_wAEPSec].PointerToRawData, m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData , m_wNoOfSections - 1, true))
		{
			DWORD dwVirusStartOffset = 0;
			TCHAR szVirusName[MAX_PATH] = {0};
			
			LPVOID lpPos = m_arrPatchedCallOffsets.GetHighest();			
			while(lpPos)
			{
				m_arrPatchedCallOffsets.GetData(lpPos, m_dwCallPatchAdd);
				m_arrPatchedCallOffsets.GetKey(lpPos, dwVirusStartOffset);
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwVirusStartOffset, &m_dwVirusStartOffset))
				{
					if(CheckSignature())
					{
						m_bFoundCallPatched = true;
						return VIRUS_FILE_REPAIR;
					}
				}
				
				lpPos = m_arrPatchedCallOffsets.GetHighestNext(lpPos);
			}
		}
		// Check if virus dead code is present in the last section 
		m_dwVirusStartOffset = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - HIV_VIRUS_CODE_SIZE;
		if(CheckSignature())
		{
			return VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSignature
	In Parameters	: 
	Out Parameters	: true if sig. match else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of HIV Family
--------------------------------------------------------------------------------------*/
bool CPolyHIV::CheckSignature()
{
	const BYTE HIVSIG1[] = {0x60, 0xE8, 0x09, 0x00, 0x00, 0x00, 0x8B, 0x64, 0x24, 0x08, 0xE9};
	const BYTE HIVSIG2[] = {0x01, 0x00, 0x00, 0x33, 0xD2, 0x64, 0xFF, 0x32, 0x64, 0x89, 0x22, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8D, 0x75, 0x15, 0x8B, 0xFE, 0xB9};
	const BYTE HIVSIG3[] = {0x06, 0x00, 0x00, 0xD6, 0xAD};
	
	if(GetBuffer(m_dwVirusStartOffset, HIV_BUFF_SIZE, HIV_BUFF_SIZE))
	{		
		int iStart = 5;
		if(memcmp(&m_pbyBuff[iStart], HIVSIG1, sizeof(HIVSIG1)) == 0 && 
			memcmp(&m_pbyBuff[iStart + sizeof(HIVSIG1) + 1], HIVSIG2, sizeof(HIVSIG2)) == 0 &&
			memcmp(&m_pbyBuff[iStart + sizeof(HIVSIG1) + sizeof(HIVSIG2) + 2], HIVSIG3, sizeof(HIVSIG3)) == 0)
		{
			if(0x2C == m_pbyBuff[iStart + sizeof(HIVSIG1)] && 0x86 == m_pbyBuff[iStart + sizeof(HIVSIG1) + sizeof(HIVSIG2) + 1])
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.HIV.6680"));	
				m_dwPatchDataOff = 0x14A;
				m_dwOriBytesOffset = m_dwPatchDataOff + 1;
			}
			else if(0x22 == m_pbyBuff[iStart + sizeof(HIVSIG1)] && 0x2E == m_pbyBuff[iStart + sizeof(HIVSIG1) + sizeof(HIVSIG2) + 1])
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.HIV.6382"));	
				m_dwPatchDataOff = 0x13E;
				m_dwOriBytesOffset = m_dwPatchDataOff + 3;
			}
			else if(0x27 == m_pbyBuff[iStart + sizeof(HIVSIG1)] && 0x31 == m_pbyBuff[iStart + sizeof(HIVSIG1) + sizeof(HIVSIG2) + 1])
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.HIV.6340"));	
				m_dwOriBytesOffset = m_dwPatchDataOff = 0x146;
			}
			else if(0x27 == m_pbyBuff[iStart + sizeof(HIVSIG1)] && 0x2F == m_pbyBuff[iStart + sizeof(HIVSIG1) + sizeof(HIVSIG2) + 1])
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.HIV.6386"));	
				m_dwOriBytesOffset = m_dwPatchDataOff = 0x146;
			}
			else
			{
				return false; 
			}
			return true;
		}
	}
	return false; 
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of HIV Family
--------------------------------------------------------------------------------------*/
int CPolyHIV::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	if(m_bFoundCallPatched)
	{
		for(DWORD dwOffset = m_dwPatchDataOff; dwOffset < m_dwPatchDataOff + 0xC; dwOffset += 4)
		{
			*(DWORD *)&m_pbyBuff[dwOffset] ^= *(DWORD *)&m_pbyBuff[0x2F];
		}
		if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwOriBytesOffset], m_dwCallPatchAdd, 0x4, 0x4))
		{
			return iRetStatus;
		}
		if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwOriBytesOffset + 6], m_dwCallPatchAdd + 4, 0x1, 0x1))
		{
			return iRetStatus;
		}				
	}
	m_pMaxPEFile->RepairOptionalHeader(0x16, 0, 0);
	if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyCalm
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyCalm::CPolyCalm(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyCalm
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyCalm::~CPolyCalm(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Calm Family
--------------------------------------------------------------------------------------*/
int CPolyCalm::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if((memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".natasha", 8)== 0) &&
		(((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000000) == 0xE0000000) ||
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xC0000000) == 0xC0000000))&&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) !=  IMAGE_FILE_DLL))
	{		
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int CALM_BUFF_SIZE  = 0x720;
		m_pbyBuff = new BYTE[CALM_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}		
		memset(m_pbyBuff, 0, CALM_BUFF_SIZE);
		if(GetBuffer(m_dwAEPMapped, CALM_BUFF_SIZE, CALM_BUFF_SIZE))
		{
			if(CheckSignature())
			{
				 iRetStatus = VIRUS_FILE_REPAIR;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Clam.1819"));	
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSignature
	In Parameters	: 
	Out Parameters	: true if signature match else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Calm Family
--------------------------------------------------------------------------------------*/
bool CPolyCalm::CheckSignature()
{	
	DWORD dwLength = 0, dwInstructionCnt = 0, dwOffset = 0, dwCount = 0;
	BYTE  bKey = 0;
	t_disasm	da;

	while(dwOffset < 0x20)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);

		if(dwLength == 1 && dwInstructionCnt == 0 && strstr(da.result, "PUSH EAX"))
		{
			dwInstructionCnt++;
		}
		else if(dwLength == 3 && dwInstructionCnt == 1 && strstr(da.result, "ADD EAX,13"))
		{
			dwInstructionCnt++;
		}
		else if(dwLength == 2 && dwInstructionCnt == 2 && strstr(da.result, "MOV ESI,EAX"))
		{
			dwInstructionCnt++;
		}
		else if(dwLength == 2 && dwInstructionCnt == 3 && strstr(da.result, "MOV EDI,ESI"))
		{
			dwInstructionCnt++;
		}
		else if(dwLength == 5 && dwInstructionCnt == 4 && strstr(da.result, "MOV ECX,708"))
		{
			dwInstructionCnt++;
			dwCount = da.immconst;
		}
		else if(dwLength == 1 && dwInstructionCnt == 5 && strstr(da.result, "LODS BYTE PTR [ESI]"))
		{
			dwInstructionCnt++;
		}
		else if(dwLength == 2 && dwInstructionCnt == 6 && strstr(da.result, "XOR AL"))
		{
			for(DWORD dwOffset = 0x13; dwOffset < dwCount + 0x13; dwOffset++)
			{
				m_pbyBuff[dwOffset] ^= (BYTE)da.immconst;
			}
			const BYTE bySignature[] = {0x5B, 0x37, 0x40, 0x00, 0xE9, 0x0F, 0xFA, 0xFF, 0xFF, 
										0x56, 0x52, 0x2E, 0x57, 0x49, 0x4E, 0x33, 0x32, 0x2E, 
										0x43, 0x41, 0x4C, 0x4D, 0x20, 0x76, 0x31, 0x2E, 0x31};			
			if(memcmp(&m_pbyBuff[0x653], bySignature, sizeof(bySignature)) == 0x00)
			{
				return true;
			}
			break;
		}
		dwOffset += dwLength; 
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of calm Family
--------------------------------------------------------------------------------------*/
int CPolyCalm::CleanVirus()
{
    if(m_pMaxPEFile->WriteAEP(*(DWORD *)&m_pbyBuff[0x1C]))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyMogul
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMogul::CPolyMogul(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwVirusStartOffset = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMogul
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMogul::~CPolyMogul(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Mogul Family
--------------------------------------------------------------------------------------*/
int CPolyMogul::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0x80000000)== 0x80000000) && 
		(m_pMaxPEFile->m_stPEHeader.CheckSum == 0) &&
		(m_wAEPSec != m_wNoOfSections - 1))
	{		
		BYTE bInst[0x11] = {0};
		if(m_pMaxPEFile->ReadBuffer(bInst, m_dwAEPMapped, 0x11, 0x11))
		{
			const BYTE MOGUL_SIG[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x2C, 0x24, 0x05, 0x81, 0x04, 0x24};			
			if(memcmp(&bInst[0], MOGUL_SIG, sizeof(MOGUL_SIG)) == 0 && bInst[0x10] == 0xC3)
			{				
				DWORD dwVirusStartRVA = m_dwAEPMapped + *(DWORD*)&bInst[0xC];
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwVirusStartRVA, &m_dwVirusStartOffset))
				{
					if(m_pbyBuff)
					{
						delete []m_pbyBuff;
						m_pbyBuff = NULL;
					}
					m_pbyBuff = new BYTE[MOGUL_BUFF_SIZE + MAX_INSTRUCTION_LEN];
					if(!m_pbyBuff)
					{
						return iRetStatus;
					}
					memset(m_pbyBuff, 0, MOGUL_BUFF_SIZE + MAX_INSTRUCTION_LEN);
					if(GetBuffer(m_dwVirusStartOffset, MOGUL_BUFF_SIZE))   
					{
						if(GetMogulParam(dwVirusStartRVA))
						{
							return VIRUS_FILE_REPAIR;
						}
					}
				}
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Mogul"));
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetMogulParam
	In Parameters	: DWORD dwVirusStartRVA
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Mogul Family
--------------------------------------------------------------------------------------*/
bool CPolyMogul::GetMogulParam(DWORD dwVirusStartRVA)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD		dwLength = 0, dwOffset = 0, dwMatchedInstr = 0, dwTemp = 0, dwWeight = 0, dwDecOffset =0;
	t_disasm	da;

	while(dwOffset < m_dwNoOfBytes)
	{
		memset(&da, 0x00, sizeof(struct t_disasm));
		
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	
		if(dwLength > m_dwNoOfBytes - dwOffset)
		{
			return false;
		}

		if(dwMatchedInstr == 0 && dwLength == 1 && strstr(da.result, "PUSHAD"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 1 && dwLength == 5 && strstr(da.result, "CALL"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 2 && dwLength == 2 && strstr(da.result, "JE"))
		{	
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 3 && dwLength == 6 && strstr(da.result, "ADD"))
		{	
			dwMatchedInstr++;
			for(int dwIdx = 0x2F; dwIdx < 0x2F + 0x1900; dwIdx += 4)
			{
				*(DWORD *)&m_pbyBuff[dwIdx] += da.immconst;
			}
		}
		else if(dwLength == 5 && strstr(da.result, "CALL"))
		{
			dwTemp = dwOffset + dwLength;
			dwWeight = ++dwMatchedInstr;
		}
		else if(dwMatchedInstr == dwWeight && dwLength == 1 && dwTemp == dwOffset && strstr(da.result, "POP EBP"))
		{
			dwTemp = dwOffset + dwLength;
			dwDecOffset =  dwVirusStartRVA + dwOffset;
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == dwWeight + 1 && dwLength == 6 && dwTemp == dwOffset && strstr(da.result, "SUB EBP"))
		{
			dwMatchedInstr++;
			dwDecOffset -= (da.immconst - m_dwImageBase);
		}
		else if(dwLength == 1 && strstr(da.result, "PUSHAD"))
		{
			dwTemp = dwOffset + dwLength;
			dwWeight = ++dwMatchedInstr;
		}
		else if(dwMatchedInstr == dwWeight && dwTemp == dwOffset && dwLength == 6 && strstr(da.result, "LEA ESI"))
		{
			dwDecOffset += (da.adrconst - m_dwImageBase);
			m_pMaxPEFile->Rva2FileOffset(dwDecOffset, &dwDecOffset);
			dwDecOffset -= m_dwVirusStartOffset;
			dwTemp = dwOffset + dwLength;
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == dwWeight + 1 &&  dwTemp == dwOffset  && dwLength == 3 && strstr(da.result, "CMP"))
		{
			if(dwDecOffset + 0x1D > m_dwNoOfBytes)
			{
				return false;
			}
			for(DWORD dwIdx = dwDecOffset; dwIdx < dwDecOffset + 0x1D; dwIdx += 4)
			{
				*(DWORD *)&m_pbyBuff[dwIdx] += 0x12345678;
			}

			const BYTE MOGUL_6800[] = {0x57, 0x69, 0x6E, 0x39, 0x78, 0x2F, 0x4D, 0x6F, 0x67, 0x75, 0x6C, 0x2E, 0x36, 0x38, 0x30, 0x30};
			const BYTE MOGUL_7189[] = {0x57, 0x69, 0x6E, 0x39, 0x78, 0x2F, 0x4D, 0x6F, 0x67, 0x75, 0x6C, 0x2E, 0x37, 0x31, 0x38, 0x39};
			const BYTE MOGUL_6806[] = {0x57, 0x69, 0x6E, 0x39, 0x78, 0x2F, 0x4D, 0x6F, 0x67, 0x75, 0x6C, 0x2E, 0x36, 0x38, 0x30, 0x36};
			const BYTE MOGUL_6845[] = {0x57, 0x69, 0x6E, 0x39, 0x78, 0x2F, 0x4D, 0x6F, 0x67, 0x75, 0x6C, 0x2E, 0x36, 0x38, 0x34, 0x35};

			if(memcmp(&m_pbyBuff[0x134B], MOGUL_6800, sizeof(MOGUL_6800)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Mogul.6800"));
				m_dwOriginalAEP = (*(DWORD *)&m_pbyBuff[0x1772]);
				return true;
			}
			else if(memcmp(&m_pbyBuff[0x14D0], MOGUL_7189, sizeof(MOGUL_7189)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Mogul.7189"));
				m_dwOriginalAEP = (*(DWORD *)&m_pbyBuff[0x18F7]);
				return true;
			}
			else if(memcmp(&m_pbyBuff[0x1351], MOGUL_6806, sizeof(MOGUL_6806)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Mogul.6806"));
				m_dwOriginalAEP = (*(DWORD *)&m_pbyBuff[0x1778]);
				return true;
			}
			else if(memcmp(&m_pbyBuff[0x1351], MOGUL_6845, sizeof(MOGUL_6845)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Mogul.6845"));
				m_dwOriginalAEP = (*(DWORD *)&m_pbyBuff[0x179F]);
				return true;
			}
			break;
		}
		dwOffset += dwLength;
	}	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Satir Family
--------------------------------------------------------------------------------------*/
int CPolyMogul::CleanVirus(void)
{		
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if (m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset))
		{
			if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x11))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolySwaduk
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolySwaduk::CPolySwaduk(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolySwaduk
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: destructor for this class
--------------------------------------------------------------------------------------*/
CPolySwaduk::~CPolySwaduk(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Swaduk Family
--------------------------------------------------------------------------------------*/
int CPolySwaduk::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	const int SWADUKA_BUFF_SIZE = 0x960;
	if(m_dwAEPUnmapped == m_pSectionHeader[0].VirtualAddress && m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x59415753 && m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData > SWADUKA_BUFF_SIZE)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[SWADUKA_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}		
		memset(m_pbyBuff, 0, SWADUKA_BUFF_SIZE);
		if(GetBuffer(m_dwAEPMapped, 0x08, 0x08))
		{
			if(m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0xB8 && m_pbyBuff[6] == 0xFF && m_pbyBuff[7] == 0xE0)
			{
				m_dwJmpOffset = *(DWORD *)&m_pbyBuff[2] - m_dwImageBase;
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwJmpOffset, &m_dwJmpOffset))
				{
					if(m_dwJmpOffset >= m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData)
					{
						if(GetBuffer(m_dwJmpOffset, SWADUKA_BUFF_SIZE, SWADUKA_BUFF_SIZE))
						{
							const BYTE SWADUKA_SIG[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8B, 0xC5, 0x81, 0xED};
							const BYTE SWADUKA_SIG1[] = {0x66, 0xAD, 0x66, 0x33, 0xC2, 0x66, 0xAB, 0xE2, 0xF7, 0xC3};
								
							if(memcmp(&m_pbyBuff[0], SWADUKA_SIG, sizeof(SWADUKA_SIG)) == 0 && 
								memcmp(&m_pbyBuff[0x94D], SWADUKA_SIG1, sizeof(SWADUKA_SIG1)) == 0)
							{
								const BYTE SWADUKA_STUB_SIG[] = {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61,
									                             0x20, 0x67, 0x6F, 0x61, 0x74, 0x20, 0x66, 0x69, 0x6C};
								if(GetBuffer(m_pSectionHeader[1].PointerToRawData, sizeof(SWADUKA_STUB_SIG), sizeof(SWADUKA_STUB_SIG)))
								{
									if(!memcmp(m_pbyBuff, SWADUKA_STUB_SIG, sizeof(SWADUKA_STUB_SIG)))
									{
										iRetStatus = VIRUS_FILE_DELETE;
									}
									else
									{
										iRetStatus = VIRUS_FILE_REPAIR;
									}
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Swaduk.A"));
								}
							}
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Swaduk Family
--------------------------------------------------------------------------------------*/
int CPolySwaduk::CleanVirus(void)
{
	for (DWORD dwCnt = 0x289 ; dwCnt < 0x291; dwCnt += 2)
	{
		*(WORD *)&m_pbyBuff[dwCnt] ^= *(WORD *)&m_pbyBuff[0x949];
	}

	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x289], m_dwAEPMapped, 0x08, 0x08))
	{
		*(WORD *)&m_pbyBuff[0x61D] ^= *(WORD *)&m_pbyBuff[0x949];
		*(WORD *)&m_pbyBuff[0x61F] ^= *(WORD *)&m_pbyBuff[0x949];
		if(m_pMaxPEFile->WriteAEP(*(DWORD *)&m_pbyBuff[0x61D]))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwJmpOffset - 0x08))
			{
				m_pMaxPEFile->RepairOptionalHeader(0x13, 0x00, 0x00);
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolySuperThreat
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolySuperThreat::CPolySuperThreat(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_byXorKey = 0;
	m_dwOriPatchOffset = 0;
	m_iJmpCnt = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolySuperThreat
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolySuperThreat::~CPolySuperThreat(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of SuperThreat Family
--------------------------------------------------------------------------------------*/
int CPolySuperThreat::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->m_stPEHeader.MinorSubsystemVersion == 0x4841 && 
		m_wAEPSec != m_wNoOfSections -1 && 
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000060) == 0xE0000060) && 
		(memcmp(m_pSectionHeader[m_wAEPSec].Name, "AHMED", 5) == 0))
	{		
		if(GetPatchedCalls(m_dwAEPMapped, m_dwAEPMapped + 0x30, m_wNoOfSections - 1))
		{
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			const int SUPERTHREAT_BUFF_SIZE = 0x3600;
			m_pbyBuff = new BYTE[SUPERTHREAT_BUFF_SIZE + MAX_INSTRUCTION_LEN];
			if(!m_pbyBuff)
			{
				return iRetStatus;
			}
			memset(m_pbyBuff, 0, SUPERTHREAT_BUFF_SIZE + MAX_INSTRUCTION_LEN);
			LPVOID lpPos = m_arrPatchedCallOffsets.GetLowest();
			while(lpPos)
			{
				m_arrPatchedCallOffsets.GetKey(lpPos, m_dwOriPatchOffset);
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriPatchOffset,&m_dwOriPatchOffset))
				{
					if(GetBuffer(m_dwOriPatchOffset, SUPERTHREAT_BUFF_SIZE, SUPERTHREAT_BUFF_SIZE))	
					{
						BYTE bySig[] = {0x66, 0x83, 0xC1, 0x45, 0x66, 0x83, 0xE9, 0x45, 0x66, 0x8B};
						if(OffSetBasedSignature(bySig, sizeof(bySig), NULL))
						{
							if(GetSuperThreatParam())
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.SuperThreat.A"));
								if(m_iJmpCnt <= 3)
								{
									return VIRUS_FILE_DELETE;
								}
								return VIRUS_FILE_REPAIR;
							}	 
						}
					}
					lpPos = m_arrPatchedCallOffsets.GetLowestNext(lpPos);
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of SuperThreat Family
--------------------------------------------------------------------------------------*/
bool CPolySuperThreat::GetSuperThreatParam()
{
	DWORD dwLength = 0, dwOffset = 0, dwMatchedInstr = 0, dwDecStartOffset = 0;	    
	BYTE byKey = 0;
	t_disasm da;
	 
   	while(dwOffset < m_dwNoOfBytes && m_iJmpCnt < 4)
	{	
		
		memset(&da, 0x00, sizeof(struct t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	
		if(dwLength > m_dwNoOfBytes - dwOffset)
		{
			break;
		}		
		if(dwMatchedInstr == 0 && dwLength == 5 && strstr(da.result, "MOV EAX") || strstr(da.result, "MOV ECX"))
		{
			dwMatchedInstr++;
			dwDecStartOffset = da.immconst - m_dwImageBase;
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwDecStartOffset, &dwDecStartOffset))
			{
				if(m_iJmpCnt <= 3) //for corrupt sample
				{
					return true;
				}
				return false;
			}
		}
		else if(dwMatchedInstr == 1 && dwLength == 6 && strstr(da.result, "JE"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 2 && dwLength == 2 && strstr(da.result, "MOV CL") || strstr(da.result, "MOV AL"))
		{
			dwMatchedInstr++;			
		}
		else if(dwMatchedInstr == 3 && dwLength == 3 && strstr(da.result, "XOR CL") || strstr(da.result, "XOR AL"))
		{
			dwMatchedInstr++;
			byKey = (BYTE)da.immconst; 
			m_byXorKey ^= byKey; 
			
		}
		else if(dwMatchedInstr == 4 && dwLength == 2 && strstr(da.result, "MOV"))
		{
			dwMatchedInstr++;			
		}
		else if(dwMatchedInstr == 5 && dwLength == 5 && strstr(da.result, "JMP"))
		{	
			DWORD dwDecStartbuff = dwDecStartOffset - m_dwOriPatchOffset;
			DWORD dwBytesToDecrypt = dwDecStartbuff + 0x500;;
			if(dwDecStartbuff > m_dwNoOfBytes || dwBytesToDecrypt > m_dwNoOfBytes)
			{
				return false;
			}
			for(DWORD dwDecOffset = dwDecStartbuff; dwDecOffset < dwBytesToDecrypt; dwDecOffset++)
			{
				m_pbyBuff[dwDecOffset] ^= byKey;
			}
			dwOffset = dwDecStartbuff;
			
			dwMatchedInstr = 0;
			if(++m_iJmpCnt == 4)
			{
				return true;
			}
			continue;
		}		
		dwOffset += dwLength;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of SuperThreat Family
--------------------------------------------------------------------------------------*/
int CPolySuperThreat::CleanVirus(void)
{ 
	if(GetBuffer(m_dwOriPatchOffset + 0x893, 0x30, 0x30))	
	{
		for(int iOffset = 0; iOffset < 0x30 ; iOffset++)
		{
			m_pbyBuff[iOffset] ^= m_byXorKey;
		}
		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0], m_dwAEPMapped, 0x30, 0x30))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwOriPatchOffset ,true))
			{
				if(m_pMaxPEFile->FillWithZeros(m_pMaxPEFile->m_stPEOffsets.MinorSubsystemVersion, 2))
				{
					return REPAIR_SUCCESS;						 
				}
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyKillFile
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyKillFile::CPolyKillFile(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyKillFile
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyKillFile::~CPolyKillFile(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of KillFile Family
--------------------------------------------------------------------------------------*/
int CPolyKillFile:: DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000060) == 0xE0000060 && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > 0xE50))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int KILLFILE_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[KILLFILE_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, KILLFILE_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, KILLFILE_BUFF_SIZE))
		{
			if(GetKillFileParameters())
			{
				if(GetBuffer (m_dwMapVirOffset, KILLFILE_BUFF_SIZE, KILLFILE_BUFF_SIZE))
				{
					const BYTE bySignature[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED};			
					if(memcmp(&m_pbyBuff[0], bySignature, sizeof(bySignature)) == 0x00)
					{
						if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[0x5B] - m_dwImageBase), &m_dwMapSecPatOff))  //Added
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.KillFile"));
							iRetStatus = VIRUS_FILE_REPAIR;
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKillFileParameters
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of KillFile Family
--------------------------------------------------------------------------------------*/
bool CPolyKillFile::GetKillFileParameters()
{
	DWORD		dwLength = 0x00, dwInstructionCnt = 0x00, dwStartAddress = 0x00,  dwOffset = 0x00;
	t_disasm	da;
	while(dwStartAddress < m_dwNoOfBytes && dwInstructionCnt < 0x125)
	{
		memset(&da, 0x00, sizeof(struct t_disasm) * 1);
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStartAddress], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwStartAddress))
		{
			break;
		}
		dwInstructionCnt++;
		dwOffset = dwStartAddress;
		dwStartAddress += dwLength;
		if(m_pbyBuff[dwOffset] == 0xE8  && dwLength == 0x05 && strstr(da.result, "CALL"))
		{
			m_dwJmpPatchOffset = m_dwAEPUnmapped + dwOffset;
			m_dwMapVirOffset = *(DWORD *)&m_pbyBuff[dwOffset + 0x01] + 0x05 + m_dwAEPUnmapped + dwOffset;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwMapVirOffset, &m_dwMapVirOffset))
			{
				if(m_dwMapVirOffset < m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData)
				{
					return true;
				}
			}
			break;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of KillFile Family
--------------------------------------------------------------------------------------*/
int CPolyKillFile::CleanVirus()
{	
	DWORD dwJmpOriValue = *(DWORD *) &m_pbyBuff[0x5F] - 0x05  - m_dwJmpPatchOffset - m_dwImageBase;
	DWORD dwMapJmpPatOff = 0x00;
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwJmpPatchOffset, &dwMapJmpPatOff))
	{
		if(m_pMaxPEFile->WriteBuffer(&dwJmpOriValue, dwMapJmpPatOff + 0x01, 0x04, 0x04))
		{
			DWORD dwMapSecPatOff = 0x00;
			if(m_pMaxPEFile->FillWithZeros(m_dwMapVirOffset, 0x63))
			{				
				if(m_pMaxPEFile->TruncateFileWithFileAlignment(dwMapSecPatOff))
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyDudra
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDudra::CPolyDudra(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDudra
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDudra::~CPolyDudra(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Dudra Family
--------------------------------------------------------------------------------------*/
int CPolyDudra::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

    if(((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0x80000000)== 0x80000000) && 
	 	(m_wAEPSec == m_wNoOfSections - 1) && 
		(m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x2058534C))
	{
		BYTE bInst[0x24] = {0};
		if(m_pMaxPEFile->ReadBuffer(bInst, m_dwAEPMapped + 0x4E, 0x24, 0x24))
		{
			const BYTE bDudra_Sig1[] = {0x81, 0xED, 0x1D, 0x10, 0x40, 0x00};
			const BYTE bDudra_Sig2[] = {0x8D, 0xBD, 0xE2, 0x10, 0x40, 0x00};
			
			if(memcmp(&bInst[0x00], bDudra_Sig1, sizeof(bDudra_Sig1)) == 0x00 && 
				memcmp(&bInst[0x1E], bDudra_Sig2, sizeof(bDudra_Sig2)) == 0x00)
			{	
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				const int DUDRA_BUFF_SIZE = 0x200;
				m_pbyBuff = new BYTE[DUDRA_BUFF_SIZE + MAX_INSTRUCTION_LEN];
				if(!m_pbyBuff)
				{
					return iRetStatus;
				}	
				memset(m_pbyBuff, 0, DUDRA_BUFF_SIZE + MAX_INSTRUCTION_LEN);
				if(!GetBuffer(m_dwAEPMapped + 0xA7, DUDRA_BUFF_SIZE, DUDRA_BUFF_SIZE))
				{
					return iRetStatus;
				}
				
				DWORD dwLength = 0, dwInstructionCnt = 0, dwOffset = 0;
				t_disasm	da;
				
				while(dwOffset < m_dwNoOfBytes)
				{
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwLength > m_dwNoOfBytes - dwOffset)
					{
						break;
					}					
					if(dwLength == 6 && dwInstructionCnt == 0 && strstr(da.result, "XOR"))
					{
						for(int i = 0x3B; i < 0x1B0; i = i + 4)
						{
							 *((DWORD *)&m_pbyBuff[i]) ^= da.immconst;
						}
						const BYTE DUDRA_CHK[] = {0xB9, 0x0C, 0x0A, 0x00, 0x00, 0x8D, 0xBD, 0xF7, 
							0x10, 0x40, 0x00, 0x66, 0x81, 0x2F};

						if(memcmp(&m_pbyBuff[0x3B], DUDRA_CHK, sizeof(DUDRA_CHK)) != 0)
						{
							return iRetStatus;
						}
						*((WORD *)&m_pbyBuff[0x1A2])-= *((WORD *)&m_pbyBuff[0x49]);
						*((WORD *)&m_pbyBuff[0x1A4])-= *((WORD *)&m_pbyBuff[0x49]);
						m_dwOriginalAEP =  *((DWORD *)&m_pbyBuff[0x1A2]) - m_dwImageBase;
						dwInstructionCnt++;
					}
					else if(dwLength == 2 && dwInstructionCnt == 1 && strstr(da.result, "XOR"))
					{
						dwInstructionCnt++;
					}
					else if(dwLength == 3 && dwInstructionCnt == 2 && strstr(da.result, "ADD EDI"))
					{
						dwInstructionCnt++;
					}
					else if(dwLength == 1 && dwInstructionCnt == 3 && strstr(da.result, "DEC") || strstr(da.result, "INC"))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Dudra.5632"));
						return VIRUS_FILE_REPAIR;
					}
					dwOffset += dwLength;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Dudra Family
--------------------------------------------------------------------------------------*/
int CPolyDudra::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped, true))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyBasket
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyBasket::CPolyBasket(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyBasket
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyBasket::~CPolyBasket(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Basket Family
--------------------------------------------------------------------------------------*/
int CPolyBasket::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(((m_pSectionHeader[m_wAEPSec].Characteristics & 0x80000000) == 0x80000000) &&
		((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xA0000020) == 0xA0000020) &&
		m_wAEPSec != m_wNoOfSections - 1)
	{	
		if(GetPatchedCalls(m_dwAEPMapped, m_dwAEPMapped + 0x300 , m_wNoOfSections - 1, true))
		{
			DWORD dwCallAddRVA = 0;

			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}

			const int BASKET_BUFF_SIZE = 0x100;
			m_pbyBuff = new BYTE[BASKET_BUFF_SIZE];

			LPVOID lpPos = m_arrPatchedCallOffsets.GetHighest();
			while(lpPos)
			{
				m_arrPatchedCallOffsets.GetData(lpPos, m_dwCallPatchAdd);
				m_arrPatchedCallOffsets.GetKey(lpPos, m_dwVirusStartOffset);
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwVirusStartOffset, &m_dwVirusStartOffset))
				{
					if(GetBuffer(m_dwVirusStartOffset + 0x9C, BASKET_BUFF_SIZE, BASKET_BUFF_SIZE))
					{
						const BYTE BasketSig[] = {0x8D, 0x14, 0x38, 0x89, 0x55, 0x54, 0x33, 0xD2, 0x6A,
							0x03, 0x5F, 0xF7, 0xF7, 0x8B, 0x7D, 0x24, 0x8B, 0x45,
							0x54, 0x8A, 0x94, 0x3A, 0xF1, 0x0C, 0x00, 0x00, 0x28,
							0x10, 0x8B, 0x45, 0x48, 0x40, 0x3D, 0x2B, 0x0C, 0x00, 
							0x00, 0x89, 0x45, 0x48, 0x72, 0xD6};

						if(memcmp(&m_pbyBuff[0x00], BasketSig, sizeof(BasketSig)) == 0)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Basket.A"));
							return VIRUS_FILE_REPAIR;
						}
					}
				}
				lpPos = m_arrPatchedCallOffsets.GetHighestNext(lpPos);
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Basket Family
--------------------------------------------------------------------------------------*/
int CPolyBasket::CleanVirus(void)
{
	if(GetBuffer(m_dwVirusStartOffset + 0xCC9, 0x5, 0x5))
	{
		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x00], m_dwCallPatchAdd, 0x05, 0x05))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyLazyMin
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyLazyMin::CPolyLazyMin(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwKey = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyLazyMin
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyLazyMin::~CPolyLazyMin(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of LazyMin Family
--------------------------------------------------------------------------------------*/
int CPolyLazyMin::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections - 2 && m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData == 0x7000 && 
		(m_pSectionHeader[m_wNoOfSections - 2].Characteristics & 0xC0000040) == 0xC0000040)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int LAZYMIN_BUFF_SIZE = 0x20;
		m_pbyBuff = new BYTE[LAZYMIN_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}	
		memset(m_pbyBuff, 0, LAZYMIN_BUFF_SIZE + MAX_INSTRUCTION_LEN);

		if(GetBuffer(m_dwAEPMapped, LAZYMIN_BUFF_SIZE, LAZYMIN_BUFF_SIZE))
		{
			DWORD dwLength = 0, dwOffset = 0;
			int iStg = 0;
			t_disasm da;
			m_dwInstCount = 0;
			
			while(dwOffset < m_dwNoOfBytes && m_dwInstCount <= 8)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (m_dwNoOfBytes - dwOffset))
				{
					break;
				}
				m_dwInstCount++;

				if(dwLength == 0x01 && strstr(da.result, "PUSHAD") && iStg == 0)
				{
					iStg++;
				}
				else if(dwLength == 0x05 && strstr(da.result, "MOV ESI,") && iStg == 1)
				{
					iStg++;
				}
				else if(dwLength == 0x05 && strstr(da.result, "MOV EAX,") && iStg == 2)
				{
					m_dwKey = da.immconst;
					iStg++;
				}
				else if(dwLength == 0x05 && strstr(da.result, "MOV ECX,") && iStg == 3)
				{
					iStg++;
				}
				else if(dwLength == 0x02 && strstr(da.result, "XOR ") && iStg == 4)
				{
					iStg++;
				}
				else if(dwLength == 0x03 && strstr(da.result, "ADD ") && iStg == 5)
				{
					iStg++;
				}
				else if(dwLength == 0x01 && strstr(da.result, "???") && iStg == 6 && m_pbyBuff[dwOffset] == 0xE2)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.LazyMin.30"));
					return VIRUS_FILE_REPAIR;
				}
				dwOffset += dwLength; 
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of LazyMin Family
--------------------------------------------------------------------------------------*/
int CPolyLazyMin::CleanVirus(void)
{
	if(GetBuffer(m_dwAEPMapped + 0x4CB, 0x08, 0x08))
	{
		for(int i = 0; i < 8; i += 4)
		{
			*(DWORD *)&m_pbyBuff[i] ^= m_dwKey;
 		}
		if(m_pMaxPEFile->WriteAEP((*(DWORD *)&m_pbyBuff[3] + 0x05 + m_dwAEPUnmapped + 0x4CD)))
		{
			if(m_pMaxPEFile->RemoveLastSections(2, true))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyDeadCode
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDeadCode::CPolyDeadCode(CMaxPEFile *pMaxPEFile)
:CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDeadCode
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDeadCode::~CPolyDeadCode(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Deacode Family
--------------------------------------------------------------------------------------*/
int CPolyDeadCode::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0x80000000) != 0x80000000)
	{
		return iRetStatus;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[DEADCODE_BUFF_SIZE];
	if(!GetBuffer(0x40, 0x10, 0x10))
	{
		return iRetStatus;
	}

	if((*((DWORD *)&m_pbyBuff[0x0])) != 0xDEADC0DE)
	{
		return iRetStatus;
	}

	m_dwVirusJumpOffset = *((DWORD *)&m_pbyBuff[0x4]);
	m_dwDecKey_2 = *((DWORD *)&m_pbyBuff[0x8]);
	m_dwDecKey_1 = *((DWORD *)&m_pbyBuff[0xC]);

	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwVirusJumpOffset, &m_dwVirusJumpOffset))
	{
		return iRetStatus;
	}

	if(GetBuffer(m_dwVirusJumpOffset, DEADCODE_BUFF_SIZE, DEADCODE_BUFF_SIZE))
	{		
		if(GetDeadCodeParam())
		{  											       
			iRetStatus = VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDeadCodeParam
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Deacode Family
--------------------------------------------------------------------------------------*/
bool CPolyDeadCode::GetDeadCodeParam()
{ 
	DWORD   dwLength = 0, dwOffset = 0, dwMatchedInstr = 0, dwDecStartOffset = 0, dwDecStartOffset1 = 0;
	t_disasm	da;

	while(dwOffset < 0x40 && dwMatchedInstr <= 8)
	{
		memset(&da, 0x00, sizeof(struct t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	

		if(dwMatchedInstr == 0 && dwLength == 2 && strstr(da.result, "TEST EBX,EBX"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 1 && dwLength == 2 && strstr(da.result, "JE SHORT"))
		{
			m_dwIndex = m_dwVirusJumpOffset + dwOffset + m_pbyBuff[dwOffset + 1] + dwLength - m_dwVirusJumpOffset;
			if(m_pbyBuff[dwOffset + 1] > 0x7F)
			{
				m_dwIndex -= 0x100;
			}
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 2 && dwLength == 5 && strstr(da.result, "MOV ECX"))
		{

			m_dwNoofBytetoReplace = 0x4C;
			dwDecStartOffset1 = m_dwIndex + 0x370; // Encrypted Signature offset for A+B
			if(da.immconst == 0x2FF)
			{
				//Calculation for Virus.DeadCode.A 
				m_dwIndex += 0x7D2;
				dwDecStartOffset = m_dwIndex - 2;	// Encrypted Original bytes offset
				m_dwNoofBytetoReplace -= 0x2;
			}
			else 
			{
				//Calculation for Virus.DeadCode.B
				m_dwIndex += 0x7E8;	
				dwDecStartOffset = m_dwIndex;		// Encrypted Original bytes offset
			}
			if(m_dwIndex + m_dwNoofBytetoReplace + 4 > DEADCODE_BUFF_SIZE)
			{
				return false;
			}
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 3 && dwLength == 3 && strstr(da.result, "ADD ESI"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 4 && dwLength == 3 && strstr(da.result, "ADD EDI"))
		{
			dwMatchedInstr++;
		}
		if(dwMatchedInstr == 5 && dwLength == 2 && strstr(da.result, "XOR EAX,EDX"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 6 && dwLength == 2 && strstr(da.result,"NEG EAX"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 7 && dwLength == 2&& strstr(da.result, "XOR EAX,EBX"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 8 && dwLength == 3 && (strstr(da.result, "ROR EAX")||strstr(da.result, "ROL EAX")))
		{ 	
			bool RotateLeft = false;
			if(strstr(da.result, "ROL EAX"))
			{
				RotateLeft = true;
			}

			if(!Decryption(dwDecStartOffset1, dwOffset, 0x25, RotateLeft))	// For Signature
			{
				return false;
			}

			// Sign: BlackHand.w32
			BYTE bySign[] = {0x42, 0x6C, 0x61, 0x63, 0x6B, 0x48, 0x61, 0x6E, 0x64, 0x2E, 0x77, 0x33, 0x32};	
			if(!OffSetBasedSignature(bySign,sizeof(bySign),NULL))
			{
				return false;
			}

			// For Getting original patched bytes at AEP
			if(!Decryption(dwDecStartOffset, dwOffset,m_dwNoofBytetoReplace, RotateLeft))  
			{
				return false;
			}

			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.DeadCode"));	
			return true;
		}
		dwOffset += dwLength;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: Decryption
	In Parameters	: DWORD dwDecStartOffset, DWORD dwOffset, DWORD dwDecrypSize, bool bRotateLeft
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption routine for different varients of Deacode Family
--------------------------------------------------------------------------------------*/
bool CPolyDeadCode::Decryption(DWORD dwDecStartOffset, DWORD dwOffset, DWORD dwDecrypSize, bool bRotateLeft)
{
	BYTE byRORCnt = m_pbyBuff[dwOffset + 0x2];

	for(DWORD dwIndex = dwDecStartOffset; dwIndex < dwDecStartOffset + dwDecrypSize; dwIndex += 4)
	{
		*((DWORD *)&m_pbyBuff[dwIndex]) ^=  m_dwDecKey_1;
		*((DWORD *)&m_pbyBuff[dwIndex])  =  0x00  - (*((DWORD *)&m_pbyBuff[dwIndex]));  // For NEG
		*((DWORD *)&m_pbyBuff[dwIndex]) = *((DWORD *)&m_pbyBuff[dwIndex]) ^ m_dwDecKey_2;
		if(bRotateLeft)
		{
			*((DWORD *)&m_pbyBuff[dwIndex])  =  _lrotl(*((DWORD *)&m_pbyBuff[dwIndex]), byRORCnt);
		}
		else
		{
			*((DWORD *)&m_pbyBuff[dwIndex])  =  _lrotr(*((DWORD *)&m_pbyBuff[dwIndex]), byRORCnt);	
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of DeadCode Family
--------------------------------------------------------------------------------------*/
int CPolyDeadCode::CleanVirus()
{
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwIndex], m_dwAEPMapped, m_dwNoofBytetoReplace, m_dwNoofBytetoReplace))
	{	
		if(m_pMaxPEFile->FillWithZeros(0x40, 0x10))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwVirusJumpOffset,true))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyPartriot
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyPartriot::CPolyPartriot(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwKey = m_dwVirusEndAddr = m_dwVirusStartOffset = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyPartriot
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyPartriot::~CPolyPartriot()
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Partriot Family
--------------------------------------------------------------------------------------*/
int CPolyPartriot::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL)!= IMAGE_FILE_DLL) &&
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xA0000020) == 0xA0000020))
	{		
		BYTE CheckPartriot = 0;
		if(!m_pMaxPEFile->ReadBuffer(&CheckPartriot, m_pMaxPEFile->m_stPEHeader.e_lfanew - 1, 1, 1))
		{
			return iRetStatus;
		}
		if(CheckPartriot != 0x2A)
		{
			return iRetStatus;
		}

		const int AEP_BUFF_SIZE = 0x50;
		const int PARTRTIOT_BUFF_SIZE = 0x700;

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PARTRTIOT_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, PARTRTIOT_BUFF_SIZE + MAX_INSTRUCTION_LEN);		
		if(GetBuffer(m_dwAEPMapped, AEP_BUFF_SIZE, AEP_BUFF_SIZE))
		{
			DWORD dwLength = 0, dwOffset = 0;
			int iStg = 0;
			t_disasm da;
			m_dwInstCount = 0;
						
			while(dwOffset < m_dwNoOfBytes)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (m_dwNoOfBytes - dwOffset))
				{
					break;
				}
				
				if(m_pbyBuff[dwOffset] == 0x68  && dwLength == 0x05 && strstr(da.result, "PUSH"))
				{
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[dwOffset + 1] - m_dwImageBase), &m_dwVirusStartOffset))
					{
						if(m_dwVirusStartOffset > (m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 2].PointerToRawData))
						{
							if(GetBuffer(m_dwVirusStartOffset, PARTRTIOT_BUFF_SIZE, PARTRTIOT_BUFF_SIZE))
							{
								if(GetDecryptionData())
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Partriot.A"));
									return VIRUS_FILE_REPAIR;
								}
							}
						}
					}
					break;
				}
				dwOffset += dwLength;
			}			
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: GetDecryptionData
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption routine for different varients of Partriot Family
--------------------------------------------------------------------------------------*/
bool CPolyPartriot::GetDecryptionData()
{
	DWORD dwLength = 0, dwOffset = 0;
	int iStg = 0;
	t_disasm da;
	m_dwInstCount = 0;

	while(dwOffset < m_dwNoOfBytes && m_dwInstCount <= 3)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffset))
		{
			break;
		}
		if((m_pbyBuff[dwOffset] == 0x81 && (dwLength == 6 || dwLength == 7) && strstr(da.result,"XOR DWORD PTR") && m_dwInstCount == 0))
		{
			m_dwInstCount = 1;
			if(dwLength == 7)
			{
				m_dwKey = *(DWORD *)&m_pbyBuff[dwOffset + 3];
			}
			else
			{
				m_dwKey = *(DWORD *)&m_pbyBuff[dwOffset + 2];
			}
		}
		else if(m_pbyBuff[dwOffset] == 0x81 && dwLength == 6 && strstr(da.result,"CMP") && m_dwInstCount == 1)
		{
			if(m_pbyBuff[dwOffset + 0x06] == 0x0F)
			{
				m_dwInstCount = 2;		
			}
		}
		else if(m_pbyBuff[dwOffset] == 0x0F && dwLength == 6 && strstr(da.result,"JNZ") && m_dwInstCount == 2)
		{
			m_dwInstCount = 3;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[dwOffset - 0x4] - m_dwImageBase), &m_dwVirusEndAddr))
			{
				return true;
			}
		}
		dwOffset += dwLength;
	}
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Partriot Family
--------------------------------------------------------------------------------------*/
int CPolyPartriot::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;

	if(GetBuffer((m_dwVirusEndAddr - 0x64), 0x52, 0x52))
	{
		for(int i = 0; i < 0x52; i += 4)
		{
			*(DWORD *)&m_pbyBuff[i] ^= m_dwKey;
		}
		if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwAEPMapped, 0x50, 0x50))
		{
			BYTE ByteToWrite = 0;
			if(m_pMaxPEFile->WriteBuffer(&ByteToWrite, m_pMaxPEFile->m_stPEHeader.e_lfanew - 1, 1, 1))
			{
				if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset, true))
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyKriz
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyKriz::CPolyKriz(CMaxPEFile *pMaxPEFile): 
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyKriz
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyKriz::~CPolyKriz(void)
{	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Kriz Family
--------------------------------------------------------------------------------------*/
int CPolyKriz::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections - 1)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_dwAEPMapped, 3, 3))
		{
			return iRetStatus;
		}
		if(!((m_pbyBuff[1] == 0x9C && m_pbyBuff[2] == 0x60) || (m_pbyBuff[2] == 0x9C && m_pbyBuff[1] == 0x60)))
		{
			return iRetStatus;
		}

		WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
		iRetStatus = DetectKriz();
		SetEvent(CPolymorphicVirus::m_hEvent);
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectKriz
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Kriz Family
--------------------------------------------------------------------------------------*/
int CPolyKriz::DetectKriz()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	const int BUFF_SIZE = 0x100;

	CEmulate objEmulate(m_pMaxPEFile);
	if(!objEmulate.IntializeProcess())
	{
		return iRetStatus;
	}
	objEmulate.SetNoOfIteration(50);
	objEmulate.SetBreakPoint("__isinstruction('call')");
	if(7 != objEmulate.EmulateFile())
	{
		return iRetStatus;
	}
	DWORD dwOffset = objEmulate.GetEip() + 5;

	objEmulate.PauseBreakPoint(0);
	objEmulate.SetBreakPoint("__isinstruction('xor byte ptr')");
	if(7 != objEmulate.EmulateFile())
	{
		return iRetStatus;
	}
	BYTE byDecKey = (BYTE)objEmulate.GetImmidiateConstant();

	DWORD dwDecSizeOffset = objEmulate.GetEip();
	DWORD dwDecSize = 0;
	if(!objEmulate.ReadEmulateBuffer((BYTE *)&dwDecSize, 4, dwDecSizeOffset + objEmulate.GetInstructionLength() - 5))
	{
		return iRetStatus;
	}
	
	objEmulate.PauseBreakPoint(1);
	objEmulate.SetBreakPoint("__isinstruction('jnz ')");
	if(7 != objEmulate.EmulateFile())
	{
		return iRetStatus;
	}		
	DWORD dwDecStartAdd = objEmulate.GetEip() + 2;
	if(!objEmulate.ReadEmulateBuffer(m_pbyBuff, BUFF_SIZE, dwOffset + dwDecSize - BUFF_SIZE))
	{
		return iRetStatus;
	}
	for(DWORD dwIndex = 0; dwIndex < BUFF_SIZE; dwIndex++)
	{
		m_pbyBuff[dwIndex] ^= byDecKey;
	}

	BYTE bySig1[] = {0x53, 0x48, 0x55, 0x54, 0x20, 0x59, 0x4f, 0x55, 0x52, 0x20, 0x46, 0x55, 0x43, 0x4b, 0x49, 0x4e, 0x47, 0x20, 0x4d, 0x4f, 0x55};		 
	BYTE bySig2[] = {0x48, 0x41, 0x50, 0x50, 0x59, 0x20, 0x4e, 0x45, 0x57, 0x20, 0x59, 0x45, 0x41, 0x52, 0x0d, 0x4f, 0x48, 0x20, 0x4d, 0x59, 0x20, 0x43, 0x4f, 0x4d, 0x50, 0x55, 0x54, 0x45, 0x52};
	for(DWORD dwIndex = 0; dwIndex < BUFF_SIZE - sizeof(bySig2); dwIndex++)
	{
		if(memcmp(bySig1, &m_pbyBuff[dwIndex], sizeof(bySig1)) == 0 || memcmp(bySig2, &m_pbyBuff[dwIndex], sizeof(bySig2)) == 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Kriz.4037"));
			iRetStatus = VIRUS_FILE_DELETE;

			if(!objEmulate.ReadEmulateBuffer(m_pbyBuff, BUFF_SIZE, dwDecStartAdd))
			{
				return iRetStatus;
			}
			for(DWORD dwIndex = 0; dwIndex < BUFF_SIZE; dwIndex++)
			{
				m_pbyBuff[dwIndex] ^= byDecKey;
			}
			BYTE byMovInst[] = {0x89, 0x44, 0x24}; 
			for(DWORD dwIndex = 0; dwIndex < BUFF_SIZE - sizeof(byMovInst); dwIndex++)
			{
				if(memcmp(byMovInst, &m_pbyBuff[dwIndex], sizeof(byMovInst)) == 0)
				{
					m_dwOriAEP = *((DWORD *)&m_pbyBuff[dwIndex - 4]);
					if(m_dwOriAEP < m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize)
					{
						return VIRUS_FILE_REPAIR;
					}
				}
			}				
			break;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Kriz Family
--------------------------------------------------------------------------------------*/
int CPolyKriz::CleanVirus()
{
	m_pMaxPEFile->WriteAEP(m_dwOriAEP);
	if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
	{
		m_pMaxPEFile->RepairOptionalHeader(0x13, 0x00, 0x00);
		return REPAIR_SUCCESS;
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyZapRom
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyZapRom::CPolyZapRom(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriByteOffset = 0;
	m_dwCount = 0;	
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyZapRom
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyZapRom::~CPolyZapRom(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of ZapRom Family
--------------------------------------------------------------------------------------*/
int CPolyZapRom::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000000) == 0xE0000000) && (m_wAEPSec == 0))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int ZAPROM_BUFF_SIZE = 0xB00;
		m_pbyBuff = new BYTE[ZAPROM_BUFF_SIZE];	  
		if(GetBuffer(m_dwAEPMapped, ZAPROM_BUFF_SIZE, ZAPROM_BUFF_SIZE))
		{
			const BYTE bySignature[] ={0xE8, 0x9c, 0x0A, 0x00, 0x00}; 
			if(memcmp(&m_pbyBuff[0], bySignature, sizeof(bySignature))== 0)
			{
				DWORD dwLength = 0, dwInstrCount = 0, dwCallOffset = 0xAA1;
				DWORD dwOffset = dwCallOffset;
				t_disasm da = {0x00};

				while(dwOffset < dwCallOffset + 0x20)
				{
					dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);

					if(dwLength == 1 && strstr(da.result,"POP") && dwOffset == dwCallOffset)
					{
						dwInstrCount++;
					}
					else if(dwLength == 6 && dwInstrCount == 1 && strstr(da.result,"XOR"))
					{
						DWORD dwKey = *(DWORD *)&m_pbyBuff[dwOffset + 2];
						
						for(dwOffset = 5; dwOffset < ZAPROM_BUFF_SIZE; dwOffset += 4)
						{
							*(DWORD *)&m_pbyBuff[dwOffset] ^= dwKey;
							if((*(DWORD *)&m_pbyBuff[dwOffset]) == 0)
							{
								break;
							}
						}
						const BYTE bySignature[] = {0xE8, 0x43, 0x00, 0x00, 0x00, 0x50, 0x52, 0x30, 
							0x4D, 0x69, 0x24, 0x45, 0x24, 0x2F, 0x5A, 0x4C, 0x41, 0x24, 0x48, 0xC8};
						
						if(memcmp(&m_pbyBuff[0x5], bySignature, sizeof(bySignature)) == 0)
						{
							iRetStatus = VIRUS_FILE_REPAIR;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.ZapRom"));
						}
						break;
					}
					dwOffset += dwLength;
				}				
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of ZapRom Family
--------------------------------------------------------------------------------------*/
int CPolyZapRom::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	
	DWORD dwOffset = 0x8D; 
	for(DWORD dwCount = 0x83; dwOffset <= 0xA2; dwCount--, dwOffset += 4)
	{
		(*(DWORD *)&m_pbyBuff[dwOffset])++;
		(*(DWORD *)&m_pbyBuff[dwOffset]) = _lrotl((*(DWORD *)&m_pbyBuff[dwOffset]), dwCount);
		(*(DWORD *)&m_pbyBuff[dwOffset]) ^= 0x4146736E;
	}

	m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[dwOffset - 0x13]), &m_dwOriByteOffset);
	
	for(DWORD dwOriByteOffset2 = 0xFF; dwOriByteOffset2 != 0;)
	{
		dwOriByteOffset2 = GetOriginatData(m_dwOriByteOffset);
	}

	DWORD dwRelocAdd  = *(DWORD *)&m_pbyBuff[dwOffset - 0x7];
	DWORD dwImportAdd = *(DWORD *)&m_pbyBuff[dwOffset - 0xB];

	DWORD dwBuffReadAdd = 0;
	m_pMaxPEFile->Rva2FileOffset(dwImportAdd, &dwBuffReadAdd);

	BYTE byBuff[0x100] = {0};
	if(m_pMaxPEFile->ReadBuffer(byBuff, dwBuffReadAdd, 0x100, 0x100))
	{
		DWORD dwImportSize = 0;
		for(; (*(DWORD *)&byBuff[dwImportSize]) != 0; dwImportSize += 4);
		if(m_pMaxPEFile->RepairOptionalHeader(0x20, dwImportAdd, dwImportSize, true))
		{
			if(m_pMaxPEFile->RepairOptionalHeader(0x24, dwRelocAdd, 0, true))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetOriginatData
	In Parameters	: DWORD dwOffset1
	Out Parameters	: File Offset else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Retrievse Repair information
--------------------------------------------------------------------------------------*/
DWORD CPolyZapRom::GetOriginatData(DWORD dwOffset1)
{
	BYTE byBuff[8] = {0};

	if(m_pMaxPEFile->ReadBuffer(byBuff, dwOffset1, 6, 6))
	{
		DWORD dwNoOfBytes = *(WORD *)&byBuff[4];
		
		DWORD dwOriByteOffset2 = 0; 
		m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&byBuff[0]), &dwOriByteOffset2);

		if(m_pMaxPEFile->CopyData(dwOffset1 + 6, m_dwAEPMapped + m_dwCount, dwNoOfBytes))
		{
			m_pMaxPEFile->FillWithZeros(dwOffset1,dwNoOfBytes + 6);
			m_dwOriByteOffset = dwOriByteOffset2;
			m_dwCount += dwNoOfBytes;
			return dwOriByteOffset2;
		}
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyEvol
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyEvol::CPolyEvol(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{	
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyEvol
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: destructor for this class
--------------------------------------------------------------------------------------*/
CPolyEvol::~CPolyEvol(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Evol Family
--------------------------------------------------------------------------------------*/
int CPolyEvol::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData) < m_pMaxPEFile->m_dwFileSize)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int EVOL_BUFF_SIZE = 0x2500;
		m_pbyBuff = new BYTE[EVOL_BUFF_SIZE];	  
		if(GetBuffer(m_dwAEPMapped, EVOL_BUFF_SIZE, 0x1847))
		{
			const BYTE bySignature1[]={0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x04, 0x8B, 0x45, 0x04, 0x89, 0x45, 0x08};
			const BYTE bySignature2[]={0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x04, 0x51};
			if((memcmp(&m_pbyBuff[0], bySignature1, sizeof(bySignature1)) == 0) || 
				(memcmp(&m_pbyBuff[0], bySignature2, sizeof(bySignature2)) == 0))
			{
				DWORD dwOffset = 0;
				DWORD dwJmpOffset;
				while(true)
				{
					for(;m_pbyBuff[dwOffset] != 0xE8 && dwOffset < m_dwNoOfBytes - 5; dwOffset++);
					if(dwOffset == m_dwNoOfBytes - 5)
					{
						return iRetStatus;
					}
					dwJmpOffset = (*(DWORD *)&m_pbyBuff[dwOffset + 1] + (m_dwAEPUnmapped + dwOffset) + 5) - m_dwAEPUnmapped;
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwJmpOffset, NULL))
					{
						if(CheckSignature(dwJmpOffset))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Evol"));
							iRetStatus = VIRUS_FILE_REPAIR;
						}	
						return iRetStatus;
					}
					dwOffset++;
				}							
			}
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSignature
	In Parameters	: 
	Out Parameters	: true if sig match else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Satir Family
--------------------------------------------------------------------------------------*/
bool CPolyEvol::CheckSignature(DWORD dwOffset)
{
	if(!GetBuffer(m_dwAEPMapped + dwOffset, 0x400, 0x300))
	{
		return false;
	}
	
	const BYTE bySig1[] = {0x00, 0x00, 0xF0, 0xBF };
	const BYTE bySig2[] = {0x00, 0x00, 0xF0, 0x77 };
	const BYTE bySig3[] = {0x0F, 0x00, 0x00, 0x55 };
	const BYTE bySig4[] = {0x65, 0x56, 0x4F, 0x4C }; //virus name - eVOL 

	for(DWORD dwOffset = 0; dwOffset <= m_dwNoOfBytes - sizeof(bySig1); dwOffset++)
	{
		if(memcmp(&m_pbyBuff[dwOffset], bySig1, sizeof(bySig1)) == 0)
		{
			for(;dwOffset <= m_dwNoOfBytes -  sizeof(bySig2); dwOffset++)
			{
				if(memcmp(&m_pbyBuff[dwOffset], bySig2, sizeof(bySig2)) == 0)
				{
					for(;dwOffset <= m_dwNoOfBytes -  sizeof(bySig3); dwOffset++)
					{
						if(memcmp(&m_pbyBuff[dwOffset], bySig3, sizeof(bySig3)) == 0)
						{
							for(;dwOffset <= m_dwNoOfBytes -  sizeof(bySig4); dwOffset++)
							{
								if(memcmp(&m_pbyBuff[dwOffset], bySig4, sizeof(bySig4)) == 0)
								{
									return true;
								}
							}
						}
					}
				}
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Evol Family
--------------------------------------------------------------------------------------*/
int CPolyEvol::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[0x10000];	  
	if(!GetBuffer(m_dwAEPMapped, 0x10000, 0x1847))
	{
		return iRetStatus;
	}

	const BYTE bySignature[] = {0x59, 0x5D, 0xC3};
	const BYTE bySignature1[] = {0x55, 0x8B, 0xEC};
	DWORD dwOffset = 0;
	for(int nCount = 0; dwOffset <= (m_dwNoOfBytes - 3) && nCount < 5; dwOffset++)
	{
		if((memcmp(&m_pbyBuff[dwOffset], bySignature, 0x03)== 0) || (memcmp(&m_pbyBuff[dwOffset], bySignature, 0x03)== 0))
		{
			nCount++;
		}
	}
	DWORD dwCertificate = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].Size;
	if(m_pMaxPEFile->CopyData((m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + dwCertificate), m_dwAEPMapped, dwOffset + 3))
	{		
		if(m_pMaxPEFile->TruncateFile((m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + dwCertificate), true))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyMerinos
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMerinos::CPolyMerinos(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMerinos
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMerinos::~CPolyMerinos(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Merinos Family
--------------------------------------------------------------------------------------*/
int CPolyMerinos::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	DWORD dwNumberOfSymbols = 0;
	m_pMaxPEFile->ReadBuffer(&dwNumberOfSymbols, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x10, 4, 4);

	if(dwNumberOfSymbols == 0x40D56780 && m_wAEPSec == m_wNoOfSections - 1 &&
		((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xC0000000) == 0xC0000000) && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) == IMAGE_FILE_DEBUG_STRIPPED) &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int MERINOS_BUFF_SIZE = 0xA00;
		m_pbyBuff = new BYTE[MERINOS_BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped, MERINOS_BUFF_SIZE, MERINOS_BUFF_SIZE))
		{
			DWORD dwOffset = 0;
			BYTE bySig[] = {0xE9, 0xE3, 0x06, 0x00, 0x00};
			if(OffSetBasedSignature(bySig, sizeof(bySig), &dwOffset))
			{
				if(dwOffset < 0x100)
				{
					m_dwOrgAEPBytesOffset = dwOffset + 7;			
					DWORD dwDecLoopOffset, dwLength = 0, dwCount = 0;
					BYTE byAEPdata = 0;
					t_disasm da;

					dwDecLoopOffset = dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwOffset + 5;

					for(DWORD iOffset = m_dwOrgAEPBytesOffset; iOffset < m_dwOrgAEPBytesOffset + 4; iOffset++)
					{
						byAEPdata = m_pbyBuff[iOffset];
						while(dwOffset < MERINOS_BUFF_SIZE && dwCount < 0x0A)
						{
							memset(&da, 0x00, sizeof(struct t_disasm));
							dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
							if(dwLength == 3 && strstr(da.result, "ADD BYTE PTR"))
							{
								dwCount++;
								byAEPdata += m_pbyBuff[dwOffset + 2];
							}
							else if(dwLength == 3 && strstr(da.result, "SUB BYTE PTR"))
							{
								dwCount++;
								byAEPdata -= m_pbyBuff[dwOffset + 2];
							}
							else if(dwLength == 3 && strstr(da.result, "XOR BYTE PTR"))
							{
								dwCount++;
								byAEPdata ^= m_pbyBuff[dwOffset + 2];
							}
							else if(dwLength == 3 && strstr(da.result, "ROR BYTE PTR"))
							{
								dwCount++;
								byAEPdata  = byAEPdata >> ((BYTE)m_pbyBuff[dwOffset + 2] % 8) | byAEPdata << (8 - ((BYTE)m_pbyBuff[dwOffset + 2] % 8));//(BYTE)_lrotr(AEPDATA,(BYTE)m_pbyBuff[dwOffset + 2]);
							}
							else if(dwLength == 3 && strstr(da.result, "ROL BYTE PTR"))
							{
								dwCount++;
								byAEPdata  = byAEPdata << ((BYTE)m_pbyBuff[dwOffset + 2] % 8) | byAEPdata >> (8 - ((BYTE)m_pbyBuff[dwOffset + 2] % 8));//(BYTE)_lrotl(AEPDATA,(BYTE)m_pbyBuff[dwOffset + 2]);
								
							}
							dwOffset += dwLength;
						}
						m_pbyBuff[iOffset] = byAEPdata;
						dwCount = 0;
						dwOffset = dwDecLoopOffset;
					}

					if((m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize) > (*(DWORD *)&m_pbyBuff[m_dwOrgAEPBytesOffset] - m_dwImageBase) &&
					   (*(DWORD *)&m_pbyBuff[m_dwOrgAEPBytesOffset] - m_dwImageBase) > 0)
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Merinos.1763"));
						return VIRUS_FILE_REPAIR;
					}
				}
			}
		}		
	}
	return iRetStatus;	
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Merinos Family
--------------------------------------------------------------------------------------*/
int CPolyMerinos::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteAEP((*(DWORD *)&m_pbyBuff[m_dwOrgAEPBytesOffset] - m_dwImageBase)))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyHalen
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyHalen::CPolyHalen(CMaxPEFile *pMaxPEFile)
:CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyHalen
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyHalen::~CPolyHalen(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Halen Family
--------------------------------------------------------------------------------------*/
int CPolyHalen::DetectVirus(void)
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if  ((m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x4E4C4148 || 
		(m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData)== 0x1))&&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)&&
		((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xA0000020) == 0xA0000020) &&
		(m_wAEPSec == m_wNoOfSections - 1))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int HALEN_BUFF_SIZE = 0x120;
		m_pbyBuff = new BYTE[HALEN_BUFF_SIZE];		
		if(GetBuffer(m_dwAEPMapped, HALEN_BUFF_SIZE, HALEN_BUFF_SIZE))
		{
			BYTE bHalenSigA[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5F, 0x81, 0xC7};

			for(DWORD dwIndex = 0x00; dwIndex < m_dwNoOfBytes - sizeof(bHalenSigA); dwIndex++)
			{
				if (memcmp(&m_pbyBuff[dwIndex],bHalenSigA, sizeof(bHalenSigA)) == 0)
				{
					m_dwAddKey = *(DWORD*)&m_pbyBuff[dwIndex + sizeof(bHalenSigA)];					
					m_dwOffset = m_dwAEPUnmapped + m_dwAddKey + 0x5 + m_dwImageBase;

					DWORD dwLoopSize = *(DWORD*)&m_pbyBuff[dwIndex + m_dwAddKey - 0x05];

					m_DecSize = 0x08;
					if(dwLoopSize==0x250)
					{
						m_dwOffset += 0x778;						
						m_dwReadOffset = 0x2;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Halen.2364"));
					}
					else if(dwLoopSize==0x234)
					{
						m_dwOffset += 0x708;
						m_dwReadOffset = 0x2;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Halen.2252"));
					}
					else if(dwLoopSize==0x23A)
					{
						m_dwOffset += 0x720;
						m_dwReadOffset = 0x3;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Halen.2277"));
					}
					else if(dwLoopSize==0x24A)
					{
						m_dwOffset += 0x760;
						m_dwReadOffset = 0x1;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Halen.2339"));
					}
					else if(dwLoopSize==0x28F)//Also detects 2618
					{	
						m_dwOffset += 0x878;
						m_DecSize = 0x04;
						m_dwReadOffset = 0x0;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Halen.2593"));
					}
					else if(dwLoopSize==0x290)//Also detects 2618
					{
						m_dwOffset += 0x878;
						m_dwReadOffset = 0x1;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Halen.2619"));
					}
					else if(dwLoopSize==0x290)//Also detects 2618
					{
						m_dwOffset += 0x878;
						m_dwReadOffset = 0x1;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Halen.2619"));
					}
					else if(dwLoopSize==0x289)
					{
						m_dwOffset += 0x85C;
						m_dwReadOffset = 0x3;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Halen.2593"));
					}
					else
					{
						return iRetStatus;
					}
					return VIRUS_FILE_REPAIR;
				}
			}
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Halen Family
--------------------------------------------------------------------------------------*/
int CPolyHalen::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[m_DecSize];
	if(m_pbyBuff == NULL)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0x00, m_DecSize);
	
	WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
	iRetStatus = CleanHalen();
	SetEvent(CPolymorphicVirus::m_hEvent);
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanHalen
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Halen Family
--------------------------------------------------------------------------------------*/
int CPolyHalen::CleanHalen(void)
{
	int iRetStatus = REPAIR_FAILED;
	CEmulate objEmulate(m_pMaxPEFile);
	if(objEmulate.IntializeProcess())
	{	
		char szBreakPoint[1024] = {0};
		sprintf_s(szBreakPoint, 1024, "__isinstruction('stosd')");
		objEmulate.SetBreakPoint(szBreakPoint);

		objEmulate.UpdateSpecifyReg(0x6, m_dwOffset);

		DWORD dwStartofDecryption = m_dwAEPUnmapped + 0x11 + m_dwImageBase;
		for(DWORD i = 0; i < m_DecSize / 0x4; i++)
		{ 
			objEmulate.SetEip(dwStartofDecryption);
			if(objEmulate.EmulateFile() != 7)
			{				
				return iRetStatus;
			}
			*(DWORD *)&m_pbyBuff[i * 4] = objEmulate.GetSpecifyRegValue(0);	
		}
		
		DWORD dwAEPToWrite = m_dwAEPUnmapped + m_dwAddKey + 0x05 - *(DWORD*)&m_pbyBuff[m_dwReadOffset];

		if(dwAEPToWrite < m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize)
		{
			if(m_pMaxPEFile->WriteAEP(dwAEPToWrite))
			{
				if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped,true))
				{               
					if(m_pMaxPEFile->RepairOptionalHeader(0x13,0x00,0x00))
					{
						iRetStatus = REPAIR_SUCCESS;
					}
				}
			}	
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyGremo
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyGremo::CPolyGremo(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwJumpFromOffset = 0;
	m_dwCallAddr = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyGremo
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyGremo::~CPolyGremo(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Gremo Family
--------------------------------------------------------------------------------------*/
int CPolyGremo::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD dwPtr2SymbolTable = 0;
	m_pMaxPEFile->ReadBuffer(&dwPtr2SymbolTable, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0xC, 4, 4);

	if((dwPtr2SymbolTable == 0x494C5544 || dwPtr2SymbolTable == 0x736972C9) && 
		m_wAEPSec != m_wNoOfSections - 1 && 
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0x80000000) == 0x80000000)	
	{
		if(GetPatchedCalls(m_dwAEPMapped, m_dwAEPMapped + 0x1000, m_wNoOfSections - 1, false, false, true))
		{
			DWORD OffSet = 0, StartOffset = 0, dwVirusStartOffset = 0, dwNoOfByteToDec = 0;
			BYTE  byRORCnt = 0;

			LPVOID lpPos = m_arrPatchedCallOffsets.GetHighest();
			if(lpPos)
			{   
				m_arrPatchedCallOffsets.GetData(lpPos, m_dwJumpFromOffset);
				m_arrPatchedCallOffsets.GetKey(lpPos, dwVirusStartOffset);

				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwVirusStartOffset, &m_dwCallAddr))
				{
					DWORD GREMO_BUFF_SIZE = (m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData) - m_dwCallAddr;
					if(GREMO_BUFF_SIZE > 0x1000)
					{
						GREMO_BUFF_SIZE = 0x1000;
					}
					if(m_pbyBuff)
					{
						delete []m_pbyBuff;
						m_pbyBuff = NULL;
					}
					m_pbyBuff = new BYTE[GREMO_BUFF_SIZE + MAX_INSTRUCTION_LEN];
					if(!m_pbyBuff)
					{
						return iRetStatus;
					}
					memset(m_pbyBuff, 0, GREMO_BUFF_SIZE + MAX_INSTRUCTION_LEN);
					if(!GetBuffer(m_dwCallAddr, GREMO_BUFF_SIZE, GREMO_BUFF_SIZE))
					{
						return iRetStatus;
					}

					DWORD dwLength = 0, dwOffset = 0, dwMatchedInstr = 0, dwDecStartOffset = 0;
					t_disasm	da;

					if(m_pbyBuff[0x0] == 0x9C && (m_pbyBuff[0x1] == 0x60 || m_pbyBuff[0x1] == 0xF8) && 
						(m_pbyBuff[0x2] == 0xE8 || m_pbyBuff[0x2] == 0x60)&& dwPtr2SymbolTable == 0x494C5544 )
					{
						while(dwOffset < GREMO_BUFF_SIZE - 8 && dwMatchedInstr <= 0x15)
						{
							memset(&da, 0x00, sizeof(struct t_disasm));
							dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	
							if(dwLength > (GREMO_BUFF_SIZE - dwOffset))
							{
								break;
							}
							if(dwMatchedInstr == 0 && dwLength == 1 && strstr(da.result, "PUSHFD"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 1 && dwLength == 1 && strstr(da.result, "PUSHAD"))
							{							
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 2 && dwLength == 5 && strstr(da.result, "CALL"))
							{							
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 3 && dwLength == 2 && strstr(da.result, "SUB EBP,EBP"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 4 && dwLength == 5 && strstr(da.result, "CALL"))
							{
								dwDecStartOffset = dwVirusStartOffset + *(DWORD *)&m_pbyBuff[dwOffset + 1] + (dwOffset + 0x5);
								dwMatchedInstr++;
							}
							if(dwMatchedInstr == 5 && dwLength == 1 && strstr(da.result, "POP ECX"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 6 && dwLength == 2 && strstr(da.result, "XCHG EBP,ECX"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 7 && dwLength == 6&& strstr(da.result, "SUB EBP"))
							{
								dwDecStartOffset -= (*(DWORD *)&m_pbyBuff[dwOffset + 2] - m_dwImageBase);
								StartOffset = dwDecStartOffset;
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 8 && dwLength == 2 && strstr(da.result, "MOV EAX,ECX"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 9 && dwLength == 5 && strstr(da.result, "MOV ECX"))
							{
								dwNoOfByteToDec = *(DWORD *)&m_pbyBuff[dwOffset + 1];
								if(dwNoOfByteToDec == 0x881)
								{
									m_dwReplaceOffSet = 0x82;
								}
								else if(dwNoOfByteToDec == 0x8A0)
								{
									m_dwReplaceOffSet = 0x84;
								}
								else
								{
									return iRetStatus;
								}
								dwMatchedInstr++;
							}
							if(dwMatchedInstr == 0xA && dwLength == 7 && strstr(da.result, "MOV AX"))
							{
								if(*(DWORD *)&m_pbyBuff[dwOffset + 3] < m_dwImageBase)
								{
									return iRetStatus;
								}
								dwDecStartOffset += (*(DWORD *)&m_pbyBuff[dwOffset + 3] - m_dwImageBase);
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 0xB && dwLength == 2 && strstr(da.result,"DEC CX"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 0xC && dwLength == 1&& strstr(da.result, "CDQ"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 0xD && dwLength == 2 && strstr(da.result, "DEC DX"))
							{
								dwMatchedInstr++;
							}
							if(dwMatchedInstr == 0xE && dwLength == 3 && strstr(da.result, "XOR DX,AX"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 0xF && dwLength == 3 && strstr(da.result,"XOR DX,CX"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 0x10 && dwLength == 3&& strstr(da.result,"RCR AX,1"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 0x11 && dwLength == 2 && strstr(da.result,"XOR AH,DL"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 0x12 && dwLength == 2 && strstr(da.result,"XOR AL,DH"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 0x13 && dwLength == 4 && strstr(da.result,"ROL AX"))
							{   
								byRORCnt = m_pbyBuff[dwOffset + 3];
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 0x14 && dwLength == 8 && strstr(da.result,"XOR"))
							{
								if(*(DWORD *)&m_pbyBuff[dwOffset + 4] < m_dwImageBase)
								{
									return iRetStatus;
								}
								OffSet =(*(DWORD *)&m_pbyBuff[dwOffset + 4] - m_dwImageBase);
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 0x15 && dwLength == 2 && strstr(da.result,"ROR EDX,CL"))
							{   
								DWORD dwSecDecKey = 0x0;
								byRORCnt= byRORCnt %16;
								dwSecDecKey =  0x0000ffff;

								if(dwDecStartOffset - dwVirusStartOffset >= GREMO_BUFF_SIZE - 3)
								{
									return iRetStatus;
								}
								while(dwNoOfByteToDec > 0x0)
								{
									dwSecDecKey = dwSecDecKey ^ (*(WORD *)&m_pbyBuff[dwDecStartOffset - dwVirusStartOffset]);
									dwNoOfByteToDec--;
									dwSecDecKey ^= dwNoOfByteToDec;
									//RCR
									WORD dwCarry = *(WORD *)&m_pbyBuff[dwDecStartOffset - dwVirusStartOffset];

									*(WORD *)&m_pbyBuff[dwDecStartOffset - dwVirusStartOffset] = *(WORD *)&m_pbyBuff[dwDecStartOffset - dwVirusStartOffset]>>1;
									if(dwCarry & 0x1)
									{ 
										//XOR with after Convert High bit to Low bit and Lowbit to high bit
										m_pbyBuff[dwDecStartOffset - dwVirusStartOffset + 1] = (m_pbyBuff[dwDecStartOffset - dwVirusStartOffset + 0x1])^LOBYTE(dwSecDecKey);
										m_pbyBuff[dwDecStartOffset - dwVirusStartOffset] = m_pbyBuff[dwDecStartOffset - dwVirusStartOffset]^HIBYTE(dwSecDecKey);
										*(WORD *)&m_pbyBuff[dwDecStartOffset - dwVirusStartOffset] = *(WORD *)&m_pbyBuff[dwDecStartOffset - dwVirusStartOffset] << byRORCnt | *(WORD *)&m_pbyBuff[dwDecStartOffset - dwVirusStartOffset] >> (16 - byRORCnt); 
									}
									if((StartOffset + dwNoOfByteToDec + OffSet) - dwVirusStartOffset > GREMO_BUFF_SIZE - 2)
									{
										return iRetStatus;
									}
									*(WORD *)&m_pbyBuff[(StartOffset + dwNoOfByteToDec + OffSet) - dwVirusStartOffset ] ^= *(WORD *)&m_pbyBuff[dwDecStartOffset - dwVirusStartOffset];
									dwSecDecKey = _lrotr(dwSecDecKey, LOBYTE(dwNoOfByteToDec));
								}
								dwMatchedInstr++;
								if(m_dwReplaceOffSet == 0x84)
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Gremo.2208"));  
								}
					// Done changes here
								else if(m_dwReplaceOffSet == 0x82)  //Done changes here
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Gremo.2343"));
								}
								else 
								{
									return iRetStatus;
								}
								m_dwReplaceOffSet += (dwDecStartOffset - dwVirusStartOffset);
								return VIRUS_FILE_REPAIR;									
							}
							dwOffset += dwLength;
						}	
					}
					else if(dwPtr2SymbolTable == 0x736972C9)
					{
						while(dwOffset < GREMO_BUFF_SIZE && dwMatchedInstr <= 0x6)
						{
							memset(&da, 0x00, sizeof(struct t_disasm));
							dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	
							if(dwLength > (GREMO_BUFF_SIZE - dwOffset))
							{
								break;
							}
							if(dwMatchedInstr == 0 && dwLength == 1 && strstr(da.result, "PUSHFD"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 1 && dwLength == 1 && strstr(da.result, "PUSHAD"))
							{							
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 2 && dwLength == 5 && strstr(da.result, "MOV ECX"))
							{	
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 3 && dwLength == 5 && strstr(da.result, "MOV EAX"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 4 && dwLength == 5 && strstr(da.result, "CALL"))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 5 && dwLength == 3 && (strstr(da.result,"RCL EAX")|| strstr(da.result,"RCR EAX")||strstr(da.result,"ROL ECX")))
							{
								dwMatchedInstr++;
							}
							else if(dwMatchedInstr == 6 && dwLength == 3 && (strstr(da.result,"XOR")||strstr(da.result,"ADD")||strstr(da.result,"SUB")))
							{		
								//Virus.Gremo.3302.dam Detected with this code
								dwMatchedInstr++;
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Gremo.3302"));
								return VIRUS_FILE_DELETE;
							}
							dwOffset += dwLength;
						}		
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Gremo Family
--------------------------------------------------------------------------------------*/
int CPolyGremo::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwReplaceOffSet], m_dwJumpFromOffset - 0x1, 0x5, 0x5))
	{	
		if(m_pMaxPEFile->FillWithZeros(m_pMaxPEFile->m_stPEHeader.e_lfanew + 0xC, 0x4))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwCallAddr))
			{	
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyPaddi
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyPaddi::CPolyPaddi(CMaxPEFile *pMaxPEFile)
:CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyPaddi
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyPaddi::~CPolyPaddi(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Paddi Family
--------------------------------------------------------------------------------------*/
int CPolyPaddi::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections - 1 && (m_pSectionHeader[m_wAEPSec].Characteristics & 0x80000000) == 0x80000000)
	{	
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PADDI_BUFF_SIZE];
		if(!GetBuffer(m_dwAEPMapped, 0x100, 0x100))
		{
			return iRetStatus;
		}
		WORD wVal = 0;
		if(!m_pMaxPEFile->ReadBuffer(&wVal, (m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData - 0x45), 0x02, 0x02))
		{
			return iRetStatus;
		}
		if(*((WORD *)&m_pbyBuff[0]) == wVal)
		{
			DWORD		dwLength = 0, dwMatchedInstr = 0;
			t_disasm	da;
			for(DWORD dwOffset = 0; dwOffset < 0x100;)
			{
				memset(&da, 0x00, sizeof(struct t_disasm));
				dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	

				if(dwMatchedInstr == 0 && dwLength == 5 && strstr(da.result, "MOV"))
				{
					dwMatchedInstr++;
				}
				else if(dwMatchedInstr == 1 && dwLength == 2 && strstr(da.result, "XOR"))
				{
					dwMatchedInstr++;
				}
				else if(dwMatchedInstr == 2 && dwLength == 3  && strstr(da.result, "ADD"))
				{
					dwMatchedInstr++;
				}
				else if(dwMatchedInstr == 3 && dwLength == 6  && strstr(da.result, "ADD"))
				{
					WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
					iRetStatus = DetectPaddi();					
					SetEvent(CPolymorphicVirus::m_hEvent);
					return iRetStatus;
				}
				dwOffset += dwLength;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPaddi
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Paddi Family
--------------------------------------------------------------------------------------*/
int CPolyPaddi::DetectPaddi()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	CEmulate objEmulate(m_pMaxPEFile);
	if(objEmulate.IntializeProcess())
	{
		objEmulate.SetEip(m_dwImageBase + m_dwAEPUnmapped);
	
		char szBreakPoint[1024] = {0};
		sprintf_s(szBreakPoint, 1024, "__isinstruction('xor dword ptr [E')");
		objEmulate.SetBreakPoint(szBreakPoint);
		
		objEmulate.SetNoOfIteration(0x20);
		if(7 == objEmulate.EmulateFile())
		{
			DWORD dwRegNo = objEmulate.GetSrcRegNo();                                                                          
			if(dwRegNo != 0xFFFFFFFF)
			{				
				DWORD dwDecStartOffset = objEmulate.GetMemoryOprand();
				DWORD dwXorKey = objEmulate.GetImmidiateConstant();
				DWORD dwEip = objEmulate.GetEip();
				objEmulate.SetEip(dwEip);
				sprintf_s(szBreakPoint, 1024, "__isinstruction('add %s')",reg32[dwRegNo].c_str());
				objEmulate.SetBreakPoint(szBreakPoint);
				objEmulate.PauseBreakPoint(0);
				objEmulate.ActiveBreakPoint(1);
				if(7 == objEmulate.EmulateFile())
				{
					DWORD dwAddKey = objEmulate.GetImmidiateConstant();
					if(objEmulate.ReadEmulateBuffer(m_pbyBuff, PADDI_BUFF_SIZE, dwDecStartOffset))
					{										
						for (DWORD i = 4; i < PADDI_BUFF_SIZE; i += 4)
						{
							dwXorKey += dwAddKey;
							*((DWORD *)&m_pbyBuff[i]) ^= dwXorKey;
						}						
						
						const BYTE bySignature[] = {0x56,0x69,0x72,0x75,0x73,0x20,0x43,0x6F,0x6E,0x73,0x74,0x72,0x75,0x63,0x74,0x69,0x6F,0x6E,0x20,0x4B,0x69,0x74,0x20,0x76,0x31};
						const BYTE bySignature1[] ={0x57,0x65,0x6C,0x63,0x6F,0x6D,0x65,0x20,0x74,0x6F,0x20,0x74,0x68,0x65,0x20,0x73,0x65,0x63,0x72,0x65,0x74,0x20,0x77,0x6F,0x72,0x6C,0x64,0x20,0x6F,0x66,0x20,0x63,0x6F,0x6D,0x70,0x75,0x74,0x65,0x72,0x20,0x76,0x69,0x72,0x75,0x73,0x65,0x73};
						if(memcmp(&m_pbyBuff[0x648], bySignature, sizeof(bySignature)) == 0 && 
							memcmp(&m_pbyBuff[0x6AC], bySignature1, sizeof(bySignature1)) == 0)
						{
							m_dwOriginalAEP = *((DWORD *)&m_pbyBuff[0x01]) - m_dwImageBase;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Paddi"));
							iRetStatus = VIRUS_FILE_REPAIR;
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Paddi Family
--------------------------------------------------------------------------------------*/
int CPolyPaddi::CleanVirus()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped,true))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyModrin
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyModrin::CPolyModrin(CMaxPEFile *pMaxPEFile)
:CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyModrin
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyModrin::~CPolyModrin(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}		
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Modrin Family
--------------------------------------------------------------------------------------*/
int CPolyModrin::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	m_bVariant = 0;
	if(((m_pSectionHeader[m_wAEPSec].Characteristics & 0xA0000000) == 0xA0000000) &&
		((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xA0000000) == 0xA0000000) &&
		((m_wAEPSec != m_wNoOfSections - 1) || ((m_wAEPSec == m_wNoOfSections -1) && ((m_dwAEPUnmapped % m_pMaxPEFile->m_stPEHeader.FileAlignment) == 0))) &&
		(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x11a00))
	{
		DWORD dwRvaVirusstartoffset = 0;

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int MORIDIN_BUF_SIZE = 0xA0; 
		m_pbyBuff = new BYTE[MORIDIN_BUF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwAEPMapped, 0xA, 0xA))
		{
			return iRetStatus;
		}
		if(m_wAEPSec == 0)
		{
			if(m_pbyBuff[0x6] != 0xC3)
			{
				return iRetStatus;
			}		
			dwRvaVirusstartoffset = *(DWORD *)&m_pbyBuff[0x1];
		}
		else
		{
			dwRvaVirusstartoffset = m_dwAEPUnmapped + m_dwImageBase;
		}		
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset((dwRvaVirusstartoffset - m_dwImageBase), &m_dwVirusStartOffset))
		{
			return iRetStatus;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_dwVirusStartOffset, 0x10, 0x10))
		{
			return iRetStatus;
		}
		BYTE Modrin_Sig[] = {0x58,0x58,0x75,0x01,0xC3};
		if(memcmp(&m_pbyBuff[0x06], Modrin_Sig, sizeof(Modrin_Sig)) != 0)
		{
			return iRetStatus;
		}
		WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
		{		
			CEmulate objEmulate(m_pMaxPEFile);
			if(objEmulate.IntializeProcess())
			{
				objEmulate.SetNoOfIteration(20);
				objEmulate.SetBreakPoint("__isinstruction('jnz')");
				objEmulate.SetEip(dwRvaVirusstartoffset + 0xB);
				if(7 == objEmulate.EmulateFile())
				{					
					DWORD offsetem = objEmulate.GetEip();

					objEmulate.SetEip(offsetem + 0x2);
					objEmulate.SetNoOfIteration(20);
					objEmulate.SetBreakPoint("__isinstruction('xor dword ptr')");

					if(7 == objEmulate.EmulateFile())
					{						
						DWORD dwDeckey = objEmulate.GetImmidiateConstant();
						if(GetBuffer(m_dwVirusStartOffset + 0x11716, MORIDIN_BUF_SIZE, MORIDIN_BUF_SIZE))
						{
							for(DWORD iOffset = 0x00; iOffset < 0x80; iOffset += 4)
							{
								*(DWORD *)&m_pbyBuff[iOffset] ^= dwDeckey;
							}
							const BYTE MODRIN_SIG1[] = {0x50,0x4F,0x4C,0x59,0x2E,0x56,0x61,0x64,0x69,0x6E,0x20,0x62,0x65,0x74,0x61,0x20,
								0x30,0x2E,0x39,0x5D,0x20,0x62,0x79,0x20,0x41,0x73,0x6D,0x6F,0x64,0x65,0x75};
							
							if(memcmp(&m_pbyBuff[0x58], MODRIN_SIG1, sizeof(MODRIN_SIG1)) == 0)
							{
								m_bVariant = 1;
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Multi.Moridin.b"));	
								iRetStatus = VIRUS_FILE_REPAIR;
							}
							else if(memcmp(&m_pbyBuff[0xD], MODRIN_SIG1, sizeof(MODRIN_SIG1)) == 0)
							{
								m_bVariant = 2;
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Multi.Moridin.c"));	
								iRetStatus = VIRUS_FILE_REPAIR;
							}
						}
						else
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Multi.Moridin.b"));	
							iRetStatus = VIRUS_FILE_DELETE;
						}
					}
				}
			}
		}
		SetEvent(CPolymorphicVirus::m_hEvent);
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Modrin Family
--------------------------------------------------------------------------------------*/
int CPolyModrin::CleanVirus(void)
{
	DWORD dwOffset = 0x05,dwAep = m_dwAEPMapped;
	if(m_bVariant == 1)
	{
		dwOffset = 0x50;
	}
	else if((m_bVariant == 2) && (m_wAEPSec == m_wNoOfSections - 1) && (*(DWORD *)&m_pbyBuff[0x3F] == m_dwImageBase))
	{
		if(m_pMaxPEFile->WriteAEP(*(DWORD *)&m_pbyBuff[0x43]))
		{
			dwAep = *(DWORD *)&m_pbyBuff[0x43];
		}
	}
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwOffset], dwAep, 0x7, 0x7))							
	{	
		if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset, true))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolySmash
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolySmash::CPolySmash(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolySmash
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolySmash::~CPolySmash(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;		
	}	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Smash Family
--------------------------------------------------------------------------------------*/
int CPolySmash::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pSectionHeader[m_wNoOfSections - 1].Characteristics == 0xC0000040) &&//changed
		(m_wAEPSec == m_wNoOfSections - 1) &&
		(m_pSectionHeader[m_wNoOfSections -1].SizeOfRawData > 0x2600) &&
		(m_pSectionHeader[m_wNoOfSections -1].SizeOfRawData <= 0x3000) && 
		(m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize == 0x3000))//added
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData];
		if(GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData, m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
		{
			DWORD   dwLength = 0, dwMatchedInstr = 0, dwKey = 0, dwCounter = 0, dwDecCounter = 0,dwInstrCnt = 0;
			t_disasm	da;
			DWORD dwOffset = m_dwAEPMapped - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
			BYTE B1 = 0, B2 = 0, B3 = 0;

			while((dwOffset  < (m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - 0x20)) && (dwMatchedInstr < 5) && (dwInstrCnt < 0x40))//changed condition
			{
				memset(&da, 0x00, sizeof(struct t_disasm));
				B1 = *((BYTE *)&m_pbyBuff[dwOffset]);
				B2 = *((BYTE *)&m_pbyBuff[dwOffset + 1]);
				B3 = *((BYTE *)&m_pbyBuff[dwOffset + 2]);

				//Skipping Some Instructions that couldn't be interpreted by Olly.
				if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
				{
					dwOffset+= 0x03;
					continue;
				}
				if(B1==0xC0 &&(B2>=0xF0 && B2<=0xF7))
				{
					dwOffset+= 0x03;
					continue;
				}
				if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
				{
					dwOffset+= 0x02;
					continue;
				}
				if(B1==0xD0 &&(B2>=0xF0 && B2<=0xF7))
				{
					dwOffset+= 0x02;
					continue;
				}
				if(B1==0xD2 &&(B2>=0xF0 && B2<=0xF7))
				{
					dwOffset+= 0x02;
					continue;
				}
				if(B1==0xD3 &&(B2>=0xF0 && B2<=0xF7)) 
				{
					dwOffset += 0x02;
					continue;
				}
				if(B1 == 0x0F && B2 == 0xAC && B3 == 0xDD)
				{
					dwOffset += 0x04;
					continue;
				}
				if(B1 == 0xF3 && B2 == 0x0F && B3 == 0xBD)
				{
					dwOffset += 0x04;
					continue;
				}
				
				dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, m_dwImageBase, &da, DISASM_CODE);
				dwInstrCnt++;
			
				if(dwLength == 5  && dwMatchedInstr == 0 && strstr(da.result,"MOV E"))
				{
					dwMatchedInstr++;
					dwOffset = (*(DWORD *)&m_pbyBuff[dwOffset + 1] - (m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase));
					if(dwOffset < (m_dwAEPMapped - m_pSectionHeader[m_wAEPSec].PointerToRawData))
					{
						return iRetStatus;
					}
					continue;
				}
				else if(dwLength == 5  && dwMatchedInstr == 1 && strstr(da.result,"MOV E"))
				{
					if(*(DWORD *)&m_pbyBuff[dwOffset + 1] != (m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase))
					{
						return iRetStatus;
					}
					dwMatchedInstr++;
				}
				else if(dwLength == 5  && dwMatchedInstr == 2 && strstr(da.result,"MOV E"))
				{
					dwMatchedInstr++;
					dwCounter = (*(DWORD *)&m_pbyBuff[dwOffset + 1] >> 2) + 1;
					dwDecCounter = *(DWORD *)&m_pbyBuff[dwOffset + 1];
					if(dwDecCounter > m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)
					{
						return iRetStatus;
					}					
				}
				else if((dwLength == 6)  && dwMatchedInstr == 3 &&strstr(da.result,"XOR E") && (*(DWORD *)&m_pbyBuff[dwOffset + 2]) > 0x1000000)
				{
					dwMatchedInstr++;
					dwKey = *(DWORD *)&m_pbyBuff[dwOffset + 2];
				}
				else if((dwLength == 5)  && dwMatchedInstr == 3 &&strstr(da.result,"XOR E") && (*(DWORD *)&m_pbyBuff[dwOffset + 1]) > m_dwImageBase)
				{
					dwMatchedInstr++;
					dwKey = *(DWORD *)&m_pbyBuff[dwOffset + 1];
				}
				else if(dwLength == 2  && (dwMatchedInstr == 4) && strstr(da.result,"XOR E"))
				{
					dwMatchedInstr++;
					for(DWORD iOffset = 0; iOffset <  dwDecCounter - 4; iOffset += 4)
					{
						*(DWORD *)&m_pbyBuff[iOffset] ^= dwKey;
						*(DWORD *)&m_pbyBuff[iOffset] ^= dwCounter;
						dwCounter -= 1;
					}
					BYTE SMASH_sig1[] = {0xE8,0x00,0x00,0x00,0x00,0x5D,0x81,0xED,0xDF,0x10,0x40,0x00,0x55,0x66,0x8C,0xD2,
						0x8B,0x8D,0x75,0x11,0x40,0x00,0x8D,0x85,0xDA,0x10,0x40,0x00,0x2B,0xC1,0xBF,0x8E,
						0xD2,0x9C,0x90,0x87,0xBD,0x03,0x11,0x40,0x00,0x83,0xC2,0x30,0x52,0x8B,0x8D,0x71};
					if(memcmp(&m_pbyBuff[0], SMASH_sig1, sizeof(SMASH_sig1)) == 0)
					{
						BYTE Smash_sig[] = {0xDA,0x10,0x40,0x00,0x00,0x00,0x00,0x00};
						if(OffSetBasedSignature(Smash_sig, sizeof(Smash_sig), &dwOffset))
						{
							m_dwOffset = (*(DWORD *)&m_pbyBuff[dwOffset + 0x10]) - m_dwImageBase; 
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Smash.10262"));
							iRetStatus = VIRUS_FILE_REPAIR;
						}					
					}
					break;
				}
				dwOffset += dwLength;
			}
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Smash Family
--------------------------------------------------------------------------------------*/
int CPolySmash::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteAEP(m_dwOffset))
	{
		if(m_pMaxPEFile->RemoveLastSections(1, true))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyBabylonia
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyBabylonia::CPolyBabylonia(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyBabylonia
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyBabylonia::~CPolyBabylonia(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Babylonia Family
--------------------------------------------------------------------------------------*/
int CPolyBabylonia::DetectVirus(void)
{
	if((m_pSectionHeader[m_wNoOfSections - 1].Characteristics == 0xC0000040) &&
		(m_wAEPSec == 0) && 
		(m_pSectionHeader[m_wAEPSec].Characteristics == 0xE0000020)&&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
	{			
		if(GetPatchedCalls(m_dwAEPMapped,m_dwAEPMapped + 0x100, m_wNoOfSections - 1))
		{			
			if(m_arrPatchedCallOffsets.GetCount())
			{
				LPVOID lpPos = m_arrPatchedCallOffsets.GetFirst();
				m_arrPatchedCallOffsets.GetData(lpPos, m_dwCallPatchAdd);
				m_arrPatchedCallOffsets.GetKey(lpPos, m_dwVirusStartOffset);
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwVirusStartOffset, &m_dwVirusStartOffset))
				{
					if(m_pMaxPEFile->m_dwFileSize - (m_dwVirusStartOffset - 0x6D5) >= 0x2B15)
					{
						if(m_pbyBuff)
						{
							delete []m_pbyBuff;
							m_pbyBuff = NULL;
						}
						const int BUFF_SIZE = 0xB00;
						m_pbyBuff = new BYTE[BUFF_SIZE];
						if(GetBuffer(m_dwVirusStartOffset, BUFF_SIZE, BUFF_SIZE))
						{
							BYTE BABY_SIG[] = {0x9C,0x60,0x83,0xC4,0xE6,0xFC,0x2B,0xC0,0xE8,0x09,0x00,0x00,0x00,0x8B,0x64,0x24,
								0x08,0xE9,0xFB,0x02,0x00,0x00,0x64,0xFF,0x30,0x64,0x89,0x20,0xBE,0xF8,0x00,0xF7,
								0xBF,0x8B,0x36,0x81,0xEE,0xE8,0xFF};
							if(memcmp(&m_pbyBuff[0x00], BABY_SIG, sizeof(BABY_SIG)) == 0)
							{
								*(DWORD *)&m_pbyBuff[0xA80] = ~(*(DWORD *)&m_pbyBuff[0xA80]);
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Babylonia.11036"));							
								return VIRUS_FILE_REPAIR;
							}
						}
					}
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Babylonia Family
--------------------------------------------------------------------------------------*/
int CPolyBabylonia::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0xA80], m_dwCallPatchAdd + 1, 0x4, 0x4))
	{
		if(m_pMaxPEFile->TruncateFileWithFileAlignment(m_dwVirusStartOffset - 0x6D5))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/********************************************************************************************************
Analyst     : Prashant
Type        : Virus + File Infector
Name        : Virus.Fono.15327
Description : 
			Type : Appender
			Size: 1424 byts
			On installation : nothing is happen.
			File Modification :	-nothing
			Registry Modification :- no modification.
			
			From Net : The virus main code stays memory resident under Windows95 as a VxD driver, 
			   hooks file opening procedure and writes to the end of accessed PE executable files.
	     
Intention : Dropped com File address [C:\W95INCA.COM]
********************************************************************************************************/
/*-------------------------------------------------------------------------------------
	Function		: CPolyFono
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyFono::CPolyFono(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOrigAep = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyFono
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyFono::~CPolyFono(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Prashant + Virus Analysis Team
	Description		: Detection routine for different varients of Fono Family
					Type : Appender
					Size: 1424 byts
					On installation : nothing is happen.
					File Modification :	-nothing
					Registry Modification :- no modification.
					From Net : The virus main code stays memory resident under Windows95 as a VxD driver, 
				    hooks file opening procedure and writes to the end of accessed PE executable files.
					Intention : Dropped com File address [C:\W95INCA.COM]
--------------------------------------------------------------------------------------*/
int CPolyFono::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if (m_pMaxPEFile->m_stPEHeader.CheckSum == 0x12345678 && 
	   ((m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000000) == 0xE0000000) && 
	   ((m_wAEPSec == (m_wNoOfSections - 1) || (m_wAEPSec == (m_wNoOfSections - 2))))&& 
		m_dwAEPUnmapped == m_pSectionHeader[m_wAEPSec].VirtualAddress)
	{
		BYTE bySignature[] = {0x43, 0x3A, 0x5C, 0x57, 0x39, 0x35, 0x49, 0x4E, 0x43, 0x41, 0x2E, 0x43, 0x4F, 0x4D};		// C:\W95INCA.COM
		
		bool		bAEPfound = false;
		const		BYTE bySignature1[] = {0xE8, 0x00, 0x01, 0x00, 0x00};								// const addr 20a  dwoffset
		const		BYTE bySignature2[] = {0xE9,0xAA, 0x00, 0x00, 0x00};								// After this Original AEP
		const int	FONO_BUFF_SIZE = 0x9D0;

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;		
		}
		m_pbyBuff = new BYTE[FONO_BUFF_SIZE]; 
		if(!GetBuffer(m_dwAEPMapped, FONO_BUFF_SIZE, FONO_BUFF_SIZE))
		{
			return iRetStatus;
		}
		//-----------------------Decryption---------------
		for(DWORD dwOffset = 0x20; dwOffset <= m_dwNoOfBytes - sizeof(bySignature1); dwOffset++)
		{
			if(memcmp(&m_pbyBuff[dwOffset], bySignature1, sizeof(bySignature1))== 0)
			{
				DWORD dwConst = dwOffset + sizeof(bySignature1);
				dwOffset+= 0x100;
				for(; dwOffset <= m_dwNoOfBytes - sizeof(bySignature1); dwOffset++)
				{
					if(m_pbyBuff[dwOffset] != m_pbyBuff[dwConst + m_pbyBuff[dwOffset]])
					{
						m_pbyBuff[dwOffset] = m_pbyBuff[dwConst + m_pbyBuff[dwOffset]];
					}
					else
					{
						continue;
					}
				}
			}
		}
		//---------------------Detection-------------------
		if(OffSetBasedSignature(bySignature,sizeof(bySignature),NULL))
		{
			for(DWORD dwOffset = 0x20; dwOffset <= m_dwNoOfBytes - sizeof(bySignature1); dwOffset++)
			{
				if(memcmp(&m_pbyBuff[dwOffset], bySignature1, sizeof(bySignature1))== 0)
				{
					DWORD dwConst = dwOffset + sizeof(bySignature1);
					for(; dwOffset <= m_dwNoOfBytes - sizeof(bySignature2); dwOffset++)
					{
						if(memcmp(&m_pbyBuff[dwOffset], bySignature2, sizeof(bySignature2))== 0)
						{
							m_dwOrigAep = *(DWORD *)&m_pbyBuff[dwOffset + sizeof(bySignature2) + 0xAA + 0xC];							
							if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOrigAep, NULL))
							{							
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Virus.W9x.Fono.15327"));
								return VIRUS_FILE_REPAIR;							
							}
						}
					}
					break;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Fono Family
--------------------------------------------------------------------------------------*/
int CPolyFono::CleanVirus()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOrigAep))	
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
		{
			if(m_pMaxPEFile->FillWithZeros(m_pMaxPEFile->m_stPEOffsets.Checksum, sizeof(DWORD)))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolySpiker
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolySpiker::CPolySpiker(CMaxPEFile *pMaxPEFile)
:CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolySpiker
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolySpiker::~CPolySpiker(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;		
	}	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Spiker Family
--------------------------------------------------------------------------------------*/
int CPolySpiker::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL) ||
		!m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress ||
		m_wAEPSec == m_wNoOfSections - 1)
	{
		return iRetStatus;
	}
	
	for(WORD wSection = m_wNoOfSections - 1; wSection > 0; wSection--)
	{
		if(memcmp(m_pSectionHeader[wSection].Name,".rsrc",5) == 0)
		{
			if(((m_pSectionHeader[wSection].Characteristics == 0x40000040) &&
				(m_pSectionHeader[wSection ].SizeOfRawData > 0x1DA00)))
			{
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				m_pbyBuff = new BYTE[0x4000];
				if(!GetBuffer(m_pSectionHeader[wSection].PointerToRawData, 0x4000, 0x4000))
				{
					return iRetStatus;
				}
				
				DWORD dwOffset = 0;
				BYTE Virussize1[] = {0xE6,0x02,0x00,0x00,0xE4,0x04,0x00,0x00};
				if(!OffSetBasedSignature(Virussize1, sizeof(Virussize1), &dwOffset))
				{
					return iRetStatus;
				}
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(*(DWORD *)&m_pbyBuff[dwOffset - 4], &m_dwVirusStartOffset))
				{
					return iRetStatus;
				}
				
				memset(m_pbyBuff, 0x00, 0x4000);
				if(!GetBuffer(m_pSectionHeader[wSection].PointerToRawData + dwOffset, 0x300, 0x300))
				{
					return iRetStatus;
				}
					
				DWORD dwDlloffset = 0;
				BYTE DLLsize1[] = {0x00,0xD8,0x01,0x00,0xE4,0x04,0x00,0x00};
				if(!OffSetBasedSignature(DLLsize1,sizeof(DLLsize1),&dwDlloffset))
				{
					return iRetStatus;
				}

				if(dwDlloffset > 3 && OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(*(DWORD *)&m_pbyBuff[dwDlloffset - 4], &m_dwDllStartOffset))
				{
					if((m_dwVirusStartOffset > m_pSectionHeader[wSection].PointerToRawData) && 
						(m_dwDllStartOffset > m_pSectionHeader[wSection].PointerToRawData))
					{
						DWORD DATA = 0;
						if(m_pMaxPEFile->ReadBuffer(&DATA, m_dwDllStartOffset, 0x04))
						{
							if(DATA == 0x00905A4D)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Spiker.A"));							
								return VIRUS_FILE_REPAIR;
							}										
						}							

					}
				}
			}
			return iRetStatus;																													
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Spiker Family
--------------------------------------------------------------------------------------*/
int CPolySpiker::CleanVirus(void)
{
	if(m_pMaxPEFile->CopyData(m_dwVirusStartOffset, m_dwAEPMapped, 0x2E6))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwDllStartOffset, 0x1D800))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyDieHard
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDieHard::CPolyDieHard(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDieHard
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDieHard::~CPolyDieHard()
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of DieHard Family
--------------------------------------------------------------------------------------*/
int CPolyDieHard::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((((m_pMaxPEFile->m_stPEHeader.CheckSum == 0x62D49A01)||((_tcsstr(m_pMaxPEFile->m_szFilePath, L".tmp")) && (m_pMaxPEFile->m_stPEHeader.CheckSum == 0x00)))
		&& (m_wAEPSec != m_wNoOfSections - 1) &&((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) && 
		(m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0xE000)) ||
		((m_wAEPSec == 0) && (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x18000) && 
		(memcmp(m_pSectionHeader[m_wAEPSec].Name,".nsp0",5) == 0)))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x10];
		if(GetBuffer(m_dwAEPMapped, 0x08, 0x08))
		{
			DWORD dwJmpOffset = *(DWORD *)&m_pbyBuff[1];
			if((dwJmpOffset > m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].VirtualAddress) &&
				(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwJmpOffset - m_dwImageBase, &dwJmpOffset)))
			{
				if(!GetBuffer(dwJmpOffset + 0x1059, 0x10, 0x10))
				{
					return iRetStatus;
				}
				if(m_dwAEPUnmapped == *(DWORD *)&m_pbyBuff[0])
				{
					DWORD dwTruncatOffset = 0;
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[4]) - m_dwImageBase, &dwTruncatOffset))
					{	
						WORD wPEMagic = 0;
						if(m_pMaxPEFile->ReadBuffer(&wPEMagic, dwTruncatOffset, 2, 2))
						{
							if(wPEMagic = 0x5A4D)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.DieHard.A"));	
								return VIRUS_FILE_REPAIR;
							}
						}
					}
				}
			}
		}
	}
	return iRetStatus;	
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of DieHard Family
--------------------------------------------------------------------------------------*/
int CPolyDieHard::CleanVirus()
{
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[8], m_dwAEPMapped, 0x08, 0x08))
	{
		DWORD dwTruncateOffset = 0;
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(*(DWORD *)&m_pbyBuff[4] - m_dwImageBase, &dwTruncateOffset))
		{			
			if(m_pMaxPEFile->TruncateFile(dwTruncateOffset))
			{
				return REPAIR_SUCCESS;
			}
		}
	}	
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyZero
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyZero::CPolyZero(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyZero
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyZero::~CPolyZero(void)
{
  if(m_pbyBuff)
  {
	  delete []m_pbyBuff;
	  m_pbyBuff = NULL;
  }
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Zero Family
--------------------------------------------------------------------------------------*/
int CPolyZero::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD dwTimeDateStamp = 0;
	m_pMaxPEFile->ReadBuffer(&dwTimeDateStamp, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x8, 4, 4);

	BYTE bMajorLinkerVersion = 0;
	m_pMaxPEFile->ReadBuffer(&bMajorLinkerVersion, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x1A, 1, 1);

	if(dwTimeDateStamp == 0x2A425E19 && m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x19 &&  bMajorLinkerVersion == 0x02 )
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int ZERO_BUFF_SIZE = 0x20;
		m_pbyBuff = new BYTE [ZERO_BUFF_SIZE];
		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x200, ZERO_BUFF_SIZE,ZERO_BUFF_SIZE))
		{
			const BYTE byZeroSig1[] = {0xEC, 0x6C, 0x00, 0xEA, 0x44, 0x50, 0x55, 0x03, 0xE8, 0x2C, 0x61, 0x00, 0x8A, 0xAE, 0x85, 0x99};
			const BYTE byZeroSig2[] = {0x40, 0x00, 0x8B, 0xC0, 0x53, 0x56, 0xBE, 0xE0, 0xA5, 0x40, 0x00, 0x83, 0x3E, 0x00, 0x75, 0x3A};	
			if((memcmp(&m_pbyBuff[0], byZeroSig1, sizeof(byZeroSig1)) == 0)||memcmp(&m_pbyBuff[0], byZeroSig2, sizeof(byZeroSig2)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Zero.A"));
				iRetStatus = VIRUS_FILE_REPAIR;
				
				WORD dwCheckMZ = 0;
				if(m_pMaxPEFile->ReadBuffer(&dwCheckMZ, 0x5A00, 0x02))
				{
					if(dwCheckMZ != 0x5A4D)
					{
						iRetStatus = VIRUS_FILE_REPAIR;
					}
				}
			}
		}
	}
	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Zero Family
--------------------------------------------------------------------------------------*/
int CPolyZero::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(0x5A00,0,m_pMaxPEFile->m_dwFileSize - 0x5A00))
	{
		if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize - 0x5A00))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyLuna
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyLuna::CPolyLuna(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwOriAEP = 0x0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyLuna
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyLuna::~CPolyLuna()
{
	if(m_pbyBuff)
	{
		delete m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Luna Family
--------------------------------------------------------------------------------------*/
int CPolyLuna::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	WORD wReservedBytes = 0;
	m_pMaxPEFile->ReadBuffer(&wReservedBytes, 0x12, sizeof(WORD), sizeof(WORD));
	if(m_wAEPSec == m_wNoOfSections - 1 && ((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xA0000020) == 0xA0000020) && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) && wReservedBytes == 0x2A43)
	{
		BYTE bCallInst[5] = {0};
		if(m_pMaxPEFile->ReadBuffer(bCallInst, m_dwAEPMapped, 5, 5))
		{
			// First Byte should be 0xE8 which is CALL 
			if(bCallInst[0] == 0xE8)
			{			
				// Calculate CALL address
				DWORD dwCallRVA = *((DWORD *)&bCallInst[1]) + 0x05 + m_dwAEPUnmapped;
				DWORD dwCallOffset = 0x0;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwCallRVA, &dwCallOffset))
				{
					return iRetStatus;
				}
				
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				const int LUNA_BUFF_SIZE = 0x40;
				m_pbyBuff = new BYTE[LUNA_BUFF_SIZE + MAX_INSTRUCTION_LEN];
				if(!m_pbyBuff)
				{
					return iRetStatus;
				}	
				memset(m_pbyBuff, 0, LUNA_BUFF_SIZE + MAX_INSTRUCTION_LEN);
				if(!GetBuffer(dwCallOffset, LUNA_BUFF_SIZE, LUNA_BUFF_SIZE))
				{
					return iRetStatus;
				}
				
				DWORD dwLength = 0, dwInstructionCnt = 0, dwOffset = 0, dwDecStart = 0;
				t_disasm	da;
				
				while(dwOffset < m_dwNoOfBytes)
				{
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwLength > m_dwNoOfBytes - dwOffset)
					{
						break;
					}					
					if(dwLength == 1 && dwInstructionCnt == 0 && strstr(da.result, "PUSHAD"))
					{
						dwInstructionCnt++;
					}
					else if(dwLength == 5 && dwInstructionCnt == 1 && strstr(da.result, "PUSH"))
					{
						dwDecStart = da.immconst - m_dwImageBase;
						dwInstructionCnt++;
					}
					else if(dwLength == 5 && dwInstructionCnt == 2 && strstr(da.result, "PUSH"))
					{
						dwInstructionCnt++;
					}
					else if(dwLength == 2 && dwInstructionCnt == 3 && strstr(da.result, "XOR EDX,EAX"))
					{
						dwInstructionCnt++;
					}
					else if(dwLength == 3 && dwInstructionCnt == 4 && strstr(da.result, "XOR"))
					{
						BYTE bXorKey = (BYTE)da.immconst;
						if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwDecStart + 0x1EC, &dwDecStart))
						{
							return iRetStatus;
						}
						if(!GetBuffer(dwDecStart, 0x25))
						{
							return iRetStatus;	
						}
						for(int i = 0; i <= 0x25; i++)
						{
							m_pbyBuff[i] ^= bXorKey;
						}
						m_dwOriAEP = *(DWORD *)&m_pbyBuff[0x0] - m_dwImageBase;
						const BYTE LUNA_SIG[]={0x57, 0x69, 0x6E, 0x39, 0x78, 0x2E, 0x4C, 0x75, 0x6E, 0x61, 0x20,
										  0x43, 0x6F, 0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x42, 0x75, 
										  0x6D, 0x62, 0x6C, 0x65, 0x62, 0x65, 0x65};
						if(memcmp(&m_pbyBuff[0x7], LUNA_SIG, sizeof(LUNA_SIG)) == 0x0)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Luna.2757.A"));
							return VIRUS_FILE_REPAIR;
						}
						return iRetStatus;						
					}
					dwOffset += dwLength;
				}
			}
		}
	}
	return iRetStatus;				
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Luna Family
--------------------------------------------------------------------------------------*/
int CPolyLuna::CleanVirus()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriAEP))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped,true))
		{
			if(m_pMaxPEFile->FillWithZeros(0x12, 2))	
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyMarburg
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMarburg::CPolyMarburg(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwVirusOffset = 0;
	m_dwIndex = 0x0;
	m_eDecType = NO_MARBURG_KEY_FOUND;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMarburg
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMarburg::~CPolyMarburg(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Marburg Family
--------------------------------------------------------------------------------------*/
int CPolyMarburg :: DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0x80000000) == 0x80000000) && 
		 m_pMaxPEFile->m_dwFileSize % 101 == 0)
	{		
		DWORD dwJmpOffset = 0,dwJmpOffset1 = 0x0;
		if(GetPatchedCalls(m_dwAEPMapped, m_dwAEPMapped + 0x30, m_wNoOfSections - 1, true))
		{
			if(m_arrPatchedCallOffsets.GetCount())
			{			
				LPVOID lpPos = m_arrPatchedCallOffsets.GetLowest();
				while(lpPos)
				{
					m_arrPatchedCallOffsets.GetKey(lpPos, dwJmpOffset);
					if((OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwJmpOffset, &dwJmpOffset)))
					{
						return iRetStatus;
					}
					lpPos = m_arrPatchedCallOffsets.GetLowestNext(lpPos);
				}
			}
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x200];
		if(!m_pbyBuff)
			return iRetStatus;
		if(!GetBuffer(dwJmpOffset,0x200,0x150))
		{
			return iRetStatus;
		}
		DWORD dwLength = 0, dwInstructionCnt = 0, dwOffset = 0;
		t_disasm	da;
		int			iInstCnt = 0x00;
		
		while(dwOffset < m_dwNoOfBytes)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			iInstCnt++;
			if(dwLength > m_dwNoOfBytes - dwOffset)
			{
				break;
			}					
			if(dwLength == 0x5 && dwInstructionCnt == 0 && strstr(da.result, "CALL") ||  strstr(da.result, "JMP"))
			{
				dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwOffset;
				m_dwVirusOffset = dwOffset + dwJmpOffset + dwLength;
				if(dwJmpOffset > m_dwVirusOffset)
				{	
					break;
				}
			}
			dwOffset += dwLength;
			if (iInstCnt > 0x100)
			{
				break;
			}
		}
		if(CheckSignature(m_dwVirusOffset))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.MarBurg"));
			return VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSignature
	In Parameters	: DWORD dwJmpOffset
	Out Parameters	: true if sig match else flase
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Marburg Family
--------------------------------------------------------------------------------------*/
bool CPolyMarburg :: CheckSignature(DWORD dwJmpOffset)
{
	BYTE bKeyData[8] = {0};
	if(m_pMaxPEFile->ReadBuffer(bKeyData, dwJmpOffset, 8))
	{
		DWORD dwXORKey	= 0xE8 ^ *(DWORD*)&bKeyData[0];
		DWORD dwADDKey	= 0xE8 - *(DWORD*)&bKeyData[0];
		DWORD dwSUBKey	= *(DWORD*)&bKeyData[0] - 0xE8;
		BYTE bXORKey	= 0xE8 ^ bKeyData[0];
		BYTE bADDKey	= 0xE8 - bKeyData[0];

		if((0x00 == (bXORKey ^ bKeyData[4]))&& (0x5D == (bXORKey ^ bKeyData[5])) && (0x8B == (bXORKey ^ bKeyData[6])) && (0xDD == (bXORKey ^ bKeyData[7])))
		{
			m_eDecType = MARBURG_XOR_BYTE;
		}
		else if((0x00 == (BYTE)(bADDKey + bKeyData[4]))&& (0x5D == (BYTE)(bADDKey + bKeyData[5])) && (0x8B == (BYTE)(bADDKey + bKeyData[6])) && (0xDD == (BYTE)(bADDKey + bKeyData[7])))
		{
			m_eDecType = MARBURG_ADD_BYTE;
		}
		else if(0xDD8B5D00 == (*(DWORD*)&bKeyData[4] - dwSUBKey))
		{
			m_eDecType = MARBURG_SUB_DWORD;
		}
        else if(0xDD8B5D00 == (dwXORKey ^ *(DWORD*)&bKeyData[4]))
		{
			m_eDecType = MARBURG_XOR_DWORD;
		}
		else if(0xDD8B5D00 == (dwADDKey + *(DWORD*)&bKeyData[4]))
		{
			m_eDecType = MARBURG_ADD_DWORD;
		}
		if(m_eDecType == NO_MARBURG_KEY_FOUND)
		{
			return false;
		}
	
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
			
		const	DWORD MARBURG_BUFF_SIZE = 0x700;

		m_pbyBuff = new BYTE[MARBURG_BUFF_SIZE];
		if(GetBuffer(m_dwVirusOffset + 0x1014, MARBURG_BUFF_SIZE, MARBURG_BUFF_SIZE))
		{
			for(DWORD dwIndex = 0x00; dwIndex < MARBURG_BUFF_SIZE ;)
			{
				switch(m_eDecType)
				{
				case MARBURG_XOR_DWORD:
					*(DWORD*)&m_pbyBuff[dwIndex] ^= dwXORKey;
					dwIndex += 4;
					break;
				case MARBURG_ADD_DWORD:
					*(DWORD*)&m_pbyBuff[dwIndex] += dwADDKey;
					dwIndex += 4;
					break;
				case MARBURG_XOR_BYTE:
					m_pbyBuff[dwIndex] ^= bXORKey;
					dwIndex++;
					break;
				case MARBURG_ADD_BYTE:
					m_pbyBuff[dwIndex] += bADDKey;
					dwIndex++;
					break;
				case MARBURG_SUB_DWORD:
					*(DWORD*)&m_pbyBuff[dwIndex] -= dwSUBKey;
					dwIndex += 4;
					break;
				}
			}
			BYTE bySignature[]={0xC3, 0x5B, 0x20, 0x4D, 0x61, 0x72, 0x62, 0x75, 0x72, 0x67, 0x20, 0x56, 0x69, 0x52, 0x75, 0x53, 
				                0x20, 0x42, 0x69, 0x6F, 0x43, 0x6F, 0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x47, 0x72, 0x69,  
				                0x59, 0x6F, 0x2F, 0x32, 0x39, 0x41, 0x20, 0x5D};//[ Marburg ViRuS BioCoded by Gri  Yo/29A ]

			if(OffSetBasedSignature(bySignature,sizeof(bySignature),&m_dwIndex))
			{
				if(m_dwIndex == 0x0)
					m_dwIndex = 0x581;
				else
					m_dwIndex = 0x589;
				return true;
			}
		}
	}
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Marburg Family
--------------------------------------------------------------------------------------*/
int CPolyMarburg::CleanVirus()
{
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwIndex], m_dwAEPMapped, 0x100))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwVirusOffset))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyGodog
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyGodog::CPolyGodog(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyGodog
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyGodog::~CPolyGodog(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Godog Family
--------------------------------------------------------------------------------------*/
int CPolyGodog::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x4E696368) && (m_wAEPSec == m_wNoOfSections - 1) &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&		
		((m_dwAEPUnmapped % m_pMaxPEFile->m_stPEHeader.FileAlignment) == 0) && ((m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000000) == 0xE0000000))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x100];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}	
		if(m_pMaxPEFile->m_stPEHeader.FileAlignment == 0x1000)
		{
			m_dwOffset = m_dwAEPMapped - 0x2000;
		}
		else if(m_pMaxPEFile->m_stPEHeader.FileAlignment == 0x200)
		{
			m_dwOffset = m_dwAEPMapped - 0x1800;
		}
		if((m_dwOffset >= m_pSectionHeader[m_wAEPSec].PointerToRawData) && (m_dwOffset <(m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData)))
		{
			if(GetBuffer(m_dwOffset,0x100,0x100))
			{
				BYTE GODOG_SIG[] = {0xBA,0xEC,0x04,0x00,0x00,0x8D,0x9D,0x5E,0x10,0x40,0x00,0x66,0x8B,0x0B,0x66,
					0x81,0xC1,0x32,0x01,0x66,0x33,0x8D,0x13,0x10,0x40,0x00,0x66,0xF7,0xD1,0x66,
					0xF7,0xD9,0x66,0xC1,0xC1,0x12,0x66,0x89,0x0B,0x83,0xC3,0x02,0x83,0xEA,0x01};
				
				if(memcmp(&m_pbyBuff[0x23],GODOG_SIG,sizeof(GODOG_SIG)) == 0)
				{
					WORD wTemp = 0;
					for(DWORD iOffset = 0x96;iOffset < 0x9B;iOffset += 0x2)
					{
						wTemp = *(WORD *)&m_pbyBuff[iOffset];
						wTemp += 0x132;
						wTemp ^= *(WORD *)&m_pbyBuff[0x7];
						wTemp += 0x1;
						wTemp = (wTemp << (0x12 % 0x10)) | (wTemp >> (0x10 - (0x12 % 0x10)));
						*(WORD *)&m_pbyBuff[iOffset] = wTemp;
					}
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Virus.Godog"));
					iRetStatus = VIRUS_FILE_REPAIR;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Godog Family
--------------------------------------------------------------------------------------*/
int CPolyGodog::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pMaxPEFile->WriteAEP(*(DWORD *)&m_pbyBuff[0x97]))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwOffset,false))
		{
			if(m_pMaxPEFile->FillWithZeros(m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x4C, 4))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyXtail
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyXtail::CPolyXtail(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_byType = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyXtail
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyXtail::~CPolyXtail(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of XTail Family
--------------------------------------------------------------------------------------*/
int CPolyXtail::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD dwBaseOfCode = 0;
	WORD wReserved = 0;
	m_pMaxPEFile->ReadBuffer(&dwBaseOfCode, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x2C, 4, 4);
	//m_pMaxPEFile->ReadBuffer(&wReserved, m_pMaxPEFile->m_stPEHeader.e_csum + 0x3A, 2, 2);//not in stub
	if(/*(wReserved == 0x3078) &&*/ (m_dwAEPUnmapped == dwBaseOfCode) &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
	{		
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int BUFF_SIZE = 0x40; 
		m_pbyBuff = new BYTE[BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped, BUFF_SIZE, BUFF_SIZE))
		{
			// Checking for string Xtail
			BYTE Xtail_Sig[] = {0xE9,0xEE,0x03,0x00,0x00,0x58,0x74,0x61,0x69,0x4C,0x20,0x62,0x79,0x20,0x6D,0x31,0x78};
			if(memcmp(m_pbyBuff, Xtail_Sig, sizeof(Xtail_Sig)) == 0)// handling for stub
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Virus.Xtail.a"));
				return VIRUS_FILE_DELETE;
			}
			else if(memcmp(&m_pbyBuff[0x2], Xtail_Sig, sizeof(Xtail_Sig)) == 0)
			{
				m_byType = 1; 
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Virus.Xtail.a"));
				return VIRUS_FILE_REPAIR;
			}
		
			DWORD dwOffset = (*(DWORD *)&m_pbyBuff[0x26]) - m_dwImageBase;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOffset, &dwOffset))
			{
				if(GetBuffer(dwOffset, 0x20, 0x20))
				{
					if(memcmp(&m_pbyBuff[0x0], Xtail_Sig, sizeof(Xtail_Sig)) == 0)
					{
						m_byType = 2;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Virus.Xtail.a"));
						return VIRUS_FILE_REPAIR;
					}
				}
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Xtail Family
--------------------------------------------------------------------------------------*/
int CPolyXtail::CleanVirus()
{
	DWORD dwOffset = 0, dwOriginalAEP = 0;
	if(m_byType == 1) 
	{
		dwOffset = m_dwAEPMapped + 0x4F8;  // Offset of original AEP
		if(m_pMaxPEFile->ReadBuffer(&dwOriginalAEP, dwOffset, 4, 4))
		{
			if(m_pMaxPEFile->WriteAEP(dwOriginalAEP - m_dwImageBase))
			{
				if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x4FE)) // fill with zero cavity
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	else if(m_byType == 2)  
	{
		dwOffset = m_dwAEPMapped + 0x25;
		BYTE byKey;
		if(m_pMaxPEFile->ReadBuffer(&byKey, dwOffset, 1, 1)) //Get count of virus code add in section
		{
			if(byKey * 6 <= 0x40 && byKey > 0)
			{				
				if(GetBuffer(dwOffset + 1, byKey * 6, byKey * 6))
				{
					// Get offset of original AEP
					dwOffset = ((*(DWORD *)&m_pbyBuff[(byKey - 1) * 6]) + (*(WORD *)&m_pbyBuff[(byKey - 1) * 6 + 4])) - m_dwImageBase;
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOffset, &dwOffset))
					{
						if(m_pMaxPEFile->ReadBuffer(&dwOriginalAEP, dwOffset - 6, 4, 4))
						{
							if(m_pMaxPEFile->WriteAEP(dwOriginalAEP - m_dwImageBase))
							{
								WORD byBytesToFillZero;
								for(; byKey > 0; byKey--)// this loop for fill with zero all parts of virus code
								{
									 dwOffset = (*(DWORD *)&m_pbyBuff[(byKey -1) * 6]) - m_dwImageBase;
									 byBytesToFillZero = (*(WORD *)&m_pbyBuff[(byKey - 1) * 6 + 4]);
									 if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOffset,&dwOffset))
									 {
										m_pMaxPEFile->FillWithZeros(dwOffset, byBytesToFillZero);
									 }
								}
								m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, m_pSectionHeader[0x00].PointerToRawData - m_dwAEPUnmapped);
								return REPAIR_SUCCESS;
							}
						}
					}				
				}
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: FindResourceEx
	In Parameters	: LPCTSTR lpstNameID, DWORD dwRead)
	Out Parameters	: 0 or FileOfSet of resource
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Retrives Resource's file offset from resource table 
--------------------------------------------------------------------------------------*/
DWORD CPolyBase::FindResourceEx(LPCTSTR lpstNameID, DWORD dwRead)
{
	DWORD iRetStatus = 0x00;
	DWORD dwRsrcTableOffset = dwRead, dwRsrcTableStart;
	
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress, &dwRsrcTableStart))
	{
		return iRetStatus;
	}

	IMAGE_RESOURCE_DIRECTORY Rsrc_Dir;
	memset(&Rsrc_Dir, 0x00, sizeof(IMAGE_RESOURCE_DIRECTORY));
	
	if(!m_pMaxPEFile->ReadBuffer(&Rsrc_Dir, dwRsrcTableOffset, sizeof(IMAGE_RESOURCE_DIRECTORY), sizeof(IMAGE_RESOURCE_DIRECTORY)))
	{
		return iRetStatus;
	}
	DWORD	dwTotalRsrcEntry = Rsrc_Dir.NumberOfIdEntries + Rsrc_Dir.NumberOfNamedEntries;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pRsrc_Dir_Entry = new IMAGE_RESOURCE_DIRECTORY_ENTRY[dwTotalRsrcEntry];

	if(pRsrc_Dir_Entry == NULL)
	{
		return iRetStatus;
	}
	DWORD	dwReadOffset = dwRsrcTableOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
	if(!m_pMaxPEFile->ReadBuffer(pRsrc_Dir_Entry, dwReadOffset, (sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)*dwTotalRsrcEntry), (sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)*dwTotalRsrcEntry)))
	{
		delete pRsrc_Dir_Entry;
		return iRetStatus;
	}
	
	IMAGE_RESOURCE_DIR_STRING_U Res_Name;
	memset(&Res_Name, 0x00, sizeof(IMAGE_RESOURCE_DIR_STRING_U));
	LPTSTR		lpstRsrcName = NULL;
	WORD		wStrLen = 0x00;
	
	DWORD dwIndex = 0x00;
	for(dwIndex = 0x00; dwIndex < dwTotalRsrcEntry; dwIndex++)
	{	
		if(pRsrc_Dir_Entry[dwIndex].NameIsString)
		{
			dwReadOffset = dwRsrcTableStart + pRsrc_Dir_Entry[dwIndex].NameOffset;
			if(!m_pMaxPEFile->ReadBuffer(&wStrLen, dwReadOffset, sizeof(WORD), sizeof(WORD)))
			{
				delete pRsrc_Dir_Entry;
				return iRetStatus;
			}
			if(wStrLen == 0x00)
			{
				continue;
			}
			lpstRsrcName = new WCHAR[wStrLen+1];
			if(lpstRsrcName == NULL)
			{
				delete pRsrc_Dir_Entry;
				return iRetStatus;
			}
			memset(lpstRsrcName, 0x00, (wStrLen+1)*sizeof(WCHAR));

			if(!m_pMaxPEFile->ReadBuffer(lpstRsrcName, dwReadOffset + sizeof(WORD), wStrLen*sizeof(WCHAR), wStrLen*sizeof(WCHAR)))
			{
				delete pRsrc_Dir_Entry;
				delete lpstRsrcName;
				lpstRsrcName = NULL;
				return iRetStatus;
			}
			if(wcscmp(lpstRsrcName, lpstNameID) == 0x00)
			{
				break;
			}
			if(lpstRsrcName)
			{
				delete lpstRsrcName;
				lpstRsrcName = NULL;
			}
		}
		else
		{
			if(pRsrc_Dir_Entry[dwIndex].Id == *((DWORD*) &lpstNameID[0]))
			{
				break;
			}
		}		
	}

	if(lpstRsrcName)
	{
		delete lpstRsrcName;
		lpstRsrcName = NULL;
	}

	if(dwIndex == dwTotalRsrcEntry)
	{
		delete pRsrc_Dir_Entry;
		return iRetStatus;
	}
	iRetStatus = pRsrc_Dir_Entry[dwIndex].OffsetToDirectory;
	delete pRsrc_Dir_Entry;
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: FindResourceEx
	In Parameters	: LPCTSTR lpstNameID, LPCTSTR lpstLaunguage, LPCTSTR lpstLangID, DWORD &dwRVA, DWORD &dwSize
	Out Parameters	: 0 or FileOfSet of resource
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Retrives Resource's file offset from resource table 
--------------------------------------------------------------------------------------*/
int CPolyBase::FindRes(LPCTSTR lpstNameID, LPCTSTR lpstLaunguage, LPCTSTR lpstLangID, DWORD &dwRVA, DWORD &dwSize)
{
	int iRetStatus = 0x00 ;
	DWORD dwRsrcTableOffset = 0;
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress, &dwRsrcTableOffset))
	{
		return iRetStatus ;
	}
	
	DWORD dwOffset = FindResourceEx(lpstNameID,dwRsrcTableOffset) ;
	if(dwOffset == 0x00)
	{
		return iRetStatus ;
	}
	DWORD dwReadOffset = dwRsrcTableOffset + dwOffset ;
	dwOffset = FindResourceEx(lpstLaunguage,dwReadOffset) ; 
	if(dwOffset == 0x00)
	{
		return iRetStatus ;
	}
	dwReadOffset = dwRsrcTableOffset + dwOffset ;
	dwOffset = FindResourceEx(lpstLangID,dwReadOffset) ; 
	if(dwOffset == 0x00)
	{
		return iRetStatus ;
	}
	BYTE byBuffer[0x08] = {0x00} ;
	dwReadOffset = dwOffset + dwRsrcTableOffset ;
	if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwReadOffset, 8, 8))
	{
		return iRetStatus ;
	}
	dwRVA = *((DWORD*)&byBuffer[0]) ;
	dwSize = *((DWORD*)&byBuffer[4]) ;
	iRetStatus = 0x01 ;

	return iRetStatus ;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyFiasko
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyFiasko::CPolyFiasko(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyFiasko
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyFiasko::~CPolyFiasko(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Fiasko Family
--------------------------------------------------------------------------------------*/
int CPolyFiasko::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) !=  IMAGE_FILE_DLL) &&
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000000) == 0xE0000000) &&
		m_wAEPSec ==  m_wNoOfSections - 1)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int BUFF_SIZE = 0x300;
		m_pbyBuff = new BYTE[BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, BUFF_SIZE);
		if(!GetBuffer(m_dwAEPMapped, 0x60, 0x60))
		{
			return iRetStatus;
		}

		t_disasm	da = {0};
		BYTE		B1 = 0, B2 = 0, byInstMatch = 0;
		DWORD		dwKey = 0, dwAddKey = 0, dwCounter = 0;
		
		m_dwInstCount = 0;
		for(DWORD dwOffset = 0, dwLength = 0; dwOffset < m_dwNoOfBytes && m_dwInstCount < 0x50; dwOffset += dwLength)
		{
			memset(&da, 0x00, sizeof(struct t_disasm) * 1);
			B1 = *((BYTE *)&m_pbyBuff[dwOffset]);
			B2 = *((BYTE *)&m_pbyBuff[dwOffset + 1]);

			//Skipping Some Instructions that couldn't be interpreted by Olly.
			if(B1 == 0xC1 && (B2 >= 0xF0 && B2 <= 0xF7))
			{
				dwOffset += 0x03;
				continue;
			}
			if(B1 == 0xD1 && (B2 >= 0xF0 && B2 <= 0xF7))
			{
				dwOffset += 0x02;
				continue;
			}

			dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwLength > (m_dwNoOfBytes - dwOffset))
			{
				break;
			}

			m_dwInstCount++;

			if(byInstMatch == 0 && dwLength == 5 && strstr(da.result, "MOV E"))
			{
				DWORD dwTemp = *(DWORD *)&m_pbyBuff[dwOffset + 1];
				if(dwTemp - m_dwImageBase !=  m_dwAEPUnmapped + 0x60)
				{
					break;
				}			
				byInstMatch++;
			}
			else if(byInstMatch == 1 && dwLength == 5 && strstr(da.result, "MOV E"))
			{
				dwKey = *(DWORD *)&m_pbyBuff[dwOffset + 1];
				byInstMatch++;
			}
			else if(byInstMatch == 2 && dwLength == 5 && strstr(da.result, "MOV E"))
			{
				dwAddKey = *(DWORD *)&m_pbyBuff[dwOffset + 1];
				byInstMatch++;
			}
			else if(byInstMatch == 3 && dwLength == 5 && strstr(da.result, "MOV E"))
			{
				dwCounter = *(DWORD *)&m_pbyBuff[dwOffset + 1];
				if(dwCounter != 0x271)
				{
					break;
				}
				byInstMatch++;
			}
			else if(byInstMatch == 4 && dwLength == 2 && strstr(da.result, "XOR [E"))
			{
				byInstMatch++;
			}
			else if(byInstMatch == 5 && dwLength == 1 && strstr(da.result, "DEC "))
			{
				byInstMatch++;
			}
			else if(byInstMatch == 6 && dwLength == 2 && strstr(da.result, "JNZ SHORT"))
			{
				if(GetBuffer(m_dwAEPMapped + 0x60, dwCounter, dwCounter))
				{
					for(DWORD i = 0; i < dwCounter; i += 4, dwKey += dwAddKey)
					{
						*(DWORD *)&m_pbyBuff[i] ^= dwKey;
					}
					// mort's virus....FIASKO'99
					const BYTE SIG[] = {0x6D,0x6F,0x72,0x74,0x27,0x73,0x20,0x76,0x69,0x72,0x75,0x73,
						0x00,0xE8,0x1D,0x00,0x00,0x00,0x46,0x49,0x41,0x53,0x4B,0x4F,0x27,0x39,0x39};
					if(memcmp(&m_pbyBuff[0x7E], SIG, sizeof(SIG)) == 0)
					{
						m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[0x71] - m_dwImageBase;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W9X.Fiasko.2508"));	
						iRetStatus = VIRUS_FILE_REPAIR;
					}
				}
				break;
			}
		}
	}
	return iRetStatus;
}
	
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Fiasko Family
--------------------------------------------------------------------------------------*/
int CPolyFiasko::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyRubashka
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyRubashka::CPolyRubashka(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyRubashka
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyRubashka::~CPolyRubashka(void)
{	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Rubashka Family
--------------------------------------------------------------------------------------*/
int CPolyRubashka::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pSectionHeader[m_wNoOfSections - 1].Characteristics == 0xA0000020) //execute,write,code
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int BUFFER_SIZE = 0x100; 
		m_pbyBuff = new BYTE[BUFFER_SIZE];
		if(GetBuffer(m_dwAEPMapped, BUFFER_SIZE, BUFFER_SIZE))
		{
			if(m_pbyBuff[0] == 0x50 && m_pbyBuff[1] == 0xC7 && m_pbyBuff[2] == 0x04 && m_pbyBuff[3] == 0x24 && m_pbyBuff[8] == 0xC3)
			{
				m_dwPushAdd = *(DWORD *)&m_pbyBuff[4];
				WORD  wSecNo = m_pMaxPEFile->Rva2FileOffset(m_dwPushAdd - m_dwImageBase, &m_dwPushAdd);
				if(OUT_OF_FILE != wSecNo && wSecNo == m_wNoOfSections - 1)
				{
					if(GetBuffer(m_dwPushAdd, BUFFER_SIZE, BUFFER_SIZE))
					{
						if(m_pbyBuff[0] == 0x68)
						{
							if(GetRubashkaParameters())
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Virus.Rubashka.5076"));
								return VIRUS_FILE_REPAIR;
							}
						}
					}
				}
			}
			else if(m_pbyBuff[0] == 0x68 && m_wAEPSec == m_wNoOfSections - 1)
			{
				if(GetRubashkaParameters(true))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Virus.Rubashka.5076"));
					return VIRUS_FILE_REPAIR;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Rubashka Family
--------------------------------------------------------------------------------------*/
bool CPolyRubashka::GetRubashkaParameters(bool bCheckCntVal)
{
	m_dwDecStart = *(DWORD *)&m_pbyBuff[1];
	m_dwDecValue = m_dwDecCnt = 0;
	
	for(DWORD dwCnt = 5; dwCnt < m_dwNoOfBytes - 0x07; dwCnt++)
	{
		if(m_pbyBuff[dwCnt] == 0x81 && m_pbyBuff[dwCnt + 1] == 0x34 && m_pbyBuff[dwCnt + 2] == 0x01) //Xor
		{
			m_dwDecValue = *(DWORD *)&m_pbyBuff[dwCnt + 3];
		}
		else if(m_pbyBuff[dwCnt] == 0x31 && m_pbyBuff[dwCnt + 1] == 0x14 && m_pbyBuff[dwCnt + 2] == 0x01)
		{
			m_dwDecValue = *(DWORD *)&m_pbyBuff[dwCnt - 4];
		}
		if(m_dwDecValue != 0 && m_pbyBuff[dwCnt] == 0x81 && m_pbyBuff[dwCnt + 1] == 0xF9) //cmp ecx,0x13d8
		{
			m_dwDecCnt = *(DWORD *)&m_pbyBuff[dwCnt + 2];
		}
		else if(m_dwDecValue != 0 && m_pbyBuff[dwCnt] == 0x3B && m_pbyBuff[dwCnt + 1] == 0xD1) //cmp ecx,0x13d8
		{
			m_dwDecCnt = *(DWORD *)&m_pbyBuff[dwCnt - 4];
		}
		if(bCheckCntVal && m_dwDecCnt > 0 && m_dwDecCnt <= 0x1500 && m_dwDecValue != 0)
		{
			if(m_dwDecCnt == 0x13D8)
			{
				return true;
			}
			break;
		}
		else if(m_dwDecCnt > 0 && m_dwDecCnt <= 0x1500 && m_dwDecValue != 0)
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Rubashka Family
--------------------------------------------------------------------------------------*/
int CPolyRubashka::CleanVirus()
{
	int		iRetStatus = REPAIR_FAILED;
	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[m_dwDecCnt];
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwDecStart - m_dwImageBase, &m_dwDecStart))
	{
		return iRetStatus;
	}
	DWORD	dwOriAEP = 0;
	if(GetBuffer(m_dwDecStart + 0x04, m_dwDecCnt, m_dwDecCnt))
	{
		for(DWORD dwCnt = 0; dwCnt < m_dwDecCnt - 0x10; dwCnt += 8)
		{
			*(DWORD *)&m_pbyBuff[dwCnt] ^= m_dwDecValue;
			*(DWORD *)&m_pbyBuff[dwCnt + 0x04] ^= m_dwDecValue;
			if(m_pbyBuff[dwCnt] == 0x68 && m_pbyBuff[dwCnt + 5] == 0xC3)  //push aep, ret
			{
				dwOriAEP = *(DWORD *)&m_pbyBuff[dwCnt + 1];
				DWORD dwTemp = 0;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwOriAEP - m_dwImageBase, &dwTemp))
				{
					dwOriAEP = 0;
					continue;
				}
				break;
			}
		}
		if(dwOriAEP != 0)
		{
			if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x09))
			{
				if(m_pMaxPEFile->TruncateFile(m_dwPushAdd))
				{
					if(m_pMaxPEFile->WriteAEP(dwOriAEP - m_dwImageBase))
					{
						return REPAIR_SUCCESS;
					}
				}
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyAgentCE
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAgentCE::CPolyAgentCE(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0;
	m_dwOffset = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAgentCE
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyAgentCE::~CPolyAgentCE(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;		
	}	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of AgentCE Family
--------------------------------------------------------------------------------------*/
int CPolyAgentCE::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL))
	{
		return iRetStatus;
	}
	if(((m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - m_dwAEPMapped) < 0x2500) &&
		(m_pSectionHeader[m_wAEPSec].Characteristics == 0xE0000020) && (m_dwAEPMapped > 0x700))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		DWORD dwBufsize = 0x400;
		m_pbyBuff = new BYTE[dwBufsize];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0x00, dwBufsize);

		if(GetBuffer(m_dwAEPMapped - 0x6AA,0x40,0x40))
		{
			BYTE AGENTCE_SIG[] = {0x55,0x8B,0xEC,0x60,0x8B,0x75,0x08,0x8B,0x7D,0x10,0x8B,0x45,0x0C,0xFF,0x70,0x0C,0x8F,0x87,
				0xB4,0x00,0x00,0x00,0xFF,0x70,0x08,0x8F,0x87,0xB8,0x00,0x00,0x00,0x50};
			if(OffSetBasedSignature(AGENTCE_SIG,sizeof(AGENTCE_SIG),&m_dwOffset))
			{	
				DWORD dwOffset = 0;
				if(GetBuffer(m_dwAEPMapped,dwBufsize,dwBufsize))
				{
					BYTE  AGENT_SIG[] = {0xE8,0x00,0x00,0x00,0x00,0x5B,0x81,0xEB};
					if(memcmp(&m_pbyBuff[0x00],AGENT_SIG,sizeof(AGENT_SIG)) == 0)
					{
						BYTE AGENT_SIG1[] = {0xE9,0xBF,0x03,0x00,0x00};
						if(OffSetBasedSignature(AGENT_SIG1,sizeof(AGENT_SIG1),&dwOffset))
						{
							if(dwOffset > 0x20)
							{
								return iRetStatus;
							}
							dwOffset += (*(DWORD *)&m_pbyBuff[dwOffset + 1] + 5);
							if(dwOffset < dwBufsize - 0x5)
							{
								if(m_pbyBuff[dwOffset] != 0xE9)
								{
									return iRetStatus;
								}					
								m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[dwOffset + 1] + (m_dwAEPUnmapped + dwOffset + 5);
								if(m_dwOriginalAEP != m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Agent.CE"));							
									return VIRUS_FILE_REPAIR;
								}
							}
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of AgentCE Family
--------------------------------------------------------------------------------------*/
int CPolyAgentCE::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_wAEPSec != (m_wNoOfSections - 1))
		{
			if(m_pMaxPEFile->FillWithZeros((m_dwAEPMapped - 0x6AA + m_dwOffset),0xAA0))
			{
				if(m_pMaxPEFile->CalculateLastSectionProperties())
				{
					return REPAIR_SUCCESS;
				}
			}
		}
		else if(m_pSectionHeader[m_wNoOfSections -1].PointerToRawData == (m_dwAEPMapped - 0x6A0))
		{
			if(m_pMaxPEFile->RemoveLastSections(1,false))
			{
				return REPAIR_SUCCESS;
			}			
		}
		else if(m_dwAEPMapped >= m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData)
		{
			m_pMaxPEFile->TruncateFileWithFileAlignment(m_dwAEPMapped - 0x6AA + m_dwOffset);
			return REPAIR_SUCCESS;
		}		
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyYounga
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyYounga::CPolyYounga(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{	
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyYounga
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyYounga::~CPolyYounga(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Younga Family
--------------------------------------------------------------------------------------*/
int CPolyYounga::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections - 1 && (m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000020) == 0xE0000020)
	{
		DWORD dwBytes2Read = 0;
		if(!(m_pMaxPEFile->ReadBuffer(&dwBytes2Read, m_dwAEPMapped + 0x12, sizeof(DWORD), sizeof(DWORD))))
		{
			return iRetStatus;
		}

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int YOUNGA_BUFF_SIZE = 0x1152;
		m_pbyBuff = new BYTE[YOUNGA_BUFF_SIZE];	  
		if(NULL == m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, YOUNGA_BUFF_SIZE);

		if(dwBytes2Read + 5 > YOUNGA_BUFF_SIZE)
		{
			dwBytes2Read = YOUNGA_BUFF_SIZE - 5;
		}
		if(!(GetBuffer(m_dwAEPMapped, dwBytes2Read + 5, dwBytes2Read + 5)))
		{
			return iRetStatus;
		}

		CMaxBMAlgo *pBMScan = new CMaxBMAlgo;
		if(pBMScan == NULL)
		{
			return iRetStatus;
		}

		BYTE bySig1[] = {0x4C, 0x69, 0x6C, 0x27, 0x20, 0x44, 0x65, 0x76, 0x69, 0x6C, 0x20, 0x43, 0x6F, 0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20,
			0x42, 0x75, 0x6D, 0x62, 0x6C, 0x65, 0x62, 0x65, 0x65, 0x20};//younga.4434

		if(pBMScan->AddPatetrn2Search(bySig1, sizeof(bySig1)))
		{
			if(pBMScan->Search4Pattern(m_pbyBuff, m_dwNoOfBytes))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Younga.4434"));
				iRetStatus = VIRUS_FILE_REPAIR;
			}
		}

		BYTE bySig2[] = {0x20, 0x59, 0x6F, 0x6E, 0x67, 0x67, 0x61, 0x72, 0x79, 0x21, 0x20, 0x62, 0x79, 0x20, 0x42, 0x75, 0x6D, 0x62, 0x6C, 0x65,
			0x62, 0x65, 0x65, 0x20};//younga.2384

		if(iRetStatus != VIRUS_FILE_REPAIR && pBMScan->AddPatetrn2Search(bySig2, sizeof(bySig2)))
		{
			if(pBMScan->Search4Pattern(m_pbyBuff, m_dwNoOfBytes))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Younga.2384"));
				iRetStatus = VIRUS_FILE_REPAIR;
			}
		}
		delete pBMScan;
		pBMScan = NULL;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Younga Family
--------------------------------------------------------------------------------------*/
int CPolyYounga::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	DWORD dwOffset = 5, dwCRCSize = *(DWORD *)&m_pbyBuff[0x12] + 5;

	BYTE bAH, bAL, bCH, bCL, bDH, bDL;
	WORD wAX, wBX, wCarry = 0, wCarry1 = 0;   
	DWORD dwEAX, dwEBX = 0, dwECX = 0xFFFFFFFF, dwEDX = 0xFFFFFFFF, dwOff = 0x2E5;

	for(DWORD dwCnt = 5; dwCnt < dwCRCSize && dwOffset < m_dwNoOfBytes ; dwCnt++, dwOffset++)
	{
		dwEAX ^= dwEAX; 
		dwEBX ^= dwEBX;

		dwEAX = m_pbyBuff[dwOffset];

		bAL = LOBYTE(dwEAX);
		bAH = HIBYTE(dwEAX);
		bCL = LOBYTE(dwECX);
		bCH = HIBYTE(dwECX);
		bDL = LOBYTE(dwEDX);
		bDH = HIBYTE(dwEDX);

		dwEDX = dwCnt ? 0xFFFF0000 : 0xFFFF00FF;

		dwEDX = (dwEDX + bDH)|0xFFFF0000;

		bAL ^= bCL;
		bCL = bCH;
		bCH = bDL;
		bDL = bDH;
		bDH = 0x08;
		wAX = bAL;
		wBX = (WORD)dwEBX;
		dwECX = bCH;

		dwECX = dwECX<<8;
		dwECX = (dwECX + bCL)|0xFFFF0000;

		while(bDH > 0)
		{
			if((wBX & 0x01)== 0x01)
			{
				wCarry1 = 0x8000;
			}
			wBX=wBX>>1;
			wCarry = wAX & 0x01;

			//RCR
			wAX = wAX>>1;
			wAX = wAX | wCarry1;
			wCarry1 = 0;

			if(wCarry!=0)
			{
				wAX ^= 0x8320;
				wBX ^= 0xEDB8;
				wCarry = 0;
			}
			bDH--;
		}
		dwEAX = wAX;
		dwEBX = wBX;
		dwECX ^= dwEAX;
		dwEDX ^= dwEBX;		
	}

	dwEDX = ~dwEDX;
	dwECX = ~dwECX;
	dwEAX = dwEDX;
	dwEAX = _lrotl(dwEAX,16);
	dwEAX = dwEAX + dwECX;

	bAL = LOBYTE(dwEAX);
	bAH = HIBYTE(dwEAX);
	bAL ^= bAH;  

	*(DWORD *)&m_pbyBuff[1] ^= dwEAX;
	DWORD dwOriginalAEP = *(DWORD *)&m_pbyBuff[1] - m_dwImageBase;
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOriginalAEP, NULL))
	{
		if(m_pMaxPEFile->WriteAEP(dwOriginalAEP))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
	}
	else
	{
		m_pMaxPEFile->CloseFile_NoMemberReset();
		if(DeleteFile(m_pMaxPEFile->m_szFilePath))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	}
	return iRetStatus;

}

/*-------------------------------------------------------------------------------------
	Function		: CPolyHPS
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyHPS::CPolyHPS(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwKey = 0;
	m_dwOffset = 0;
	m_bDecType = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyHPS
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyHPS::~CPolyHPS(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;		
	}	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of HPS Family
--------------------------------------------------------------------------------------*/
int CPolyHPS::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wAEPSec == m_wNoOfSections - 1) && 
		((m_pSectionHeader[m_wAEPSec].Characteristics & 0xC0000000) == 0xC0000000) &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		DWORD dwBufsize = 0x2C;
		m_pbyBuff = new BYTE[dwBufsize + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0x00, dwBufsize + MAX_INSTRUCTION_LEN);

		if(GetBuffer(m_dwAEPMapped, dwBufsize, dwBufsize))
		{
			if(m_pbyBuff[0x00] == 0xE8 && m_pbyBuff[0x05] == 0xE8 && m_pbyBuff[0x0A] == 0xE8 && m_pbyBuff[0xF] == 0xE8)
			{				
				DWORD dwLength = 0, dwOffset = 0, dwCount = 0, dwTempOffset = 0;
				t_disasm	da;
				bool bjmpcheck = false;
				while(dwOffset < dwBufsize)
				{
					memset(&da, 0x00, sizeof(struct t_disasm));
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwOffset > dwBufsize - dwLength)
					{
						break;
					}
					if(dwLength == 5 && strstr(da.result,"CALL") && (*(DWORD *)&m_pbyBuff[dwOffset + 1] > 0xFFFFF000))
					{
						dwCount++;
						if(dwCount == 3)
						{
							dwTempOffset = m_dwAEPUnmapped + dwOffset + *(DWORD *)&m_pbyBuff[dwOffset + 1] + 0x5;							
						}
					}
					if(dwCount == 5 && dwLength == 6 && strstr(da.result,"JE") && (*(DWORD *)&m_pbyBuff[dwOffset + 2]) > 0xFFFF0000)
					{
						m_dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 2] + dwOffset + m_dwAEPUnmapped + dwLength;
						if(m_dwOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment == 0x00)
						{
							bjmpcheck = true;
							break;
						}
					}
					if(dwCount == 5 && dwLength == 6 && strstr(da.result,"J") && !strstr(da.result,"JMP"))
					{
						dwCount++;
					}
					if(dwCount == 6 && dwLength == 5 && strstr(da.result,"JMP")&& (bjmpcheck == false) && (*(DWORD *)&m_pbyBuff[dwOffset + 1]) > 0xFFFF0000)
					{
						m_dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwOffset + m_dwAEPUnmapped + dwLength;
						bjmpcheck = true;
						break;
						
					}
					dwOffset += dwLength;
				}
				if(bjmpcheck == true)
				{
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwTempOffset,&dwTempOffset))
					{
						BYTE byTempBuff[0x2C + MAX_INSTRUCTION_LEN] = {0};
						if(m_pMaxPEFile->ReadBuffer(byTempBuff, dwTempOffset, dwBufsize, dwBufsize))
						{
							dwLength = 0;
							dwOffset = 0;						
							while(dwOffset < 0x20)
							{
								memset(&da, 0x00, sizeof(struct t_disasm));
								dwLength = m_objMaxDisassem.Disasm((char *)&byTempBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
								if(dwLength == 6 && strstr(da.result,"XOR DWORD PTR [") && (byTempBuff[dwOffset + dwLength] == 0xC3))
								{
									m_dwKey = *(DWORD *)&byTempBuff[dwOffset + 2];
									m_bDecType = 1;
									break;
								}
								if(dwLength == 8 && strstr(da.result,"ADD BYTE PTR [") && (byTempBuff[dwOffset + dwLength] == 0xC3))
								{
									m_bDecType = 3;
									m_dwKey = byTempBuff[dwOffset + 7];									
									break;
								}
								if(dwLength == 3 && strstr(da.result,"XOR BYTE PTR [") && (byTempBuff[dwOffset + dwLength] == 0xC3))
								{
									m_bDecType = 4;
									m_dwKey = (0x1000000 * byTempBuff[dwOffset + 2]) + (0x10000 * byTempBuff[dwOffset + 2]) + (0x100 * byTempBuff[dwOffset + 2]) + byTempBuff[dwOffset + 2];									
									break;
								}
								if(dwLength == 7 && strstr(da.result,"SUB DWORD PTR [") && (byTempBuff[dwOffset + dwLength] == 0xC3))
								{
									m_dwKey = *(DWORD *)&byTempBuff[dwOffset + 3];
									m_bDecType = 2;
									break;
								}
								if(dwLength == 2 && strstr(da.result,"INC DWORD PTR [") && (byTempBuff[dwOffset + dwLength] == 0xC3))
								{
									m_bDecType = 5;
									break;
								}
								dwOffset += dwLength;
							}
							if(m_bDecType)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W9x.HPS.5124"));							
								return VIRUS_FILE_REPAIR;
							}
						}
					}				
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of HPS Family
--------------------------------------------------------------------------------------*/
int CPolyHPS::CleanVirus()
{		
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOffset, &m_dwOffset))
	{
		if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x00], m_dwOffset + 0x14, 0x4, 0x4))
		{
			switch(m_bDecType)
			{
			case 1:
				*(DWORD *)&m_pbyBuff[0x00] ^= m_dwKey;
				break;
			case 2:
				*(DWORD *)&m_pbyBuff[0x00] -= m_dwKey;
				break;
			case 3:
				{
					for(int ioffset = 0;ioffset < 4;ioffset++)
					{
						m_pbyBuff[ioffset] += (BYTE)m_dwKey;
					}
					break;
				}
			case 4:
				{
					*(DWORD *)&m_pbyBuff[0x00] ^= m_dwKey;
				}
				break;
			case 5:
				{
					*(DWORD *)&m_pbyBuff[0x00] += 1;				
				}
				break;
			}
			if(m_pMaxPEFile->WriteAEP(*(DWORD *)&m_pbyBuff[0x00]))
			{
				if(m_pMaxPEFile->TruncateFile(m_dwOffset))
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyImplinker
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyImplinker::CPolyImplinker(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwImportoffset = 0;
	m_dwpathOffset =0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyImplinker
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyImplinker::~CPolyImplinker(void)
{
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Implinker Family
--------------------------------------------------------------------------------------*/
int CPolyImplinker::DetectVirus()
{
	if((m_wAEPSec == 0) && (m_pSectionHeader[0].Characteristics == 0x60000020) && (m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress != 0)
		&& (m_pMaxPEFile->m_stPEHeader.DataDirectory[0xC].VirtualAddress == 0))
	{
		DWORD dwOffset = m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress + m_pMaxPEFile->m_stPEHeader.DataDirectory[1].Size;
		if(OUT_OF_FILE != (m_pMaxPEFile->Rva2FileOffset(dwOffset, &dwOffset)))
		{
			const int IMPLINKER_BUFF_SIZE = 0x30;
			BYTE byBuff[IMPLINKER_BUFF_SIZE] = {0};
			DWORD dwTempOffset = 0;
			if(m_pMaxPEFile->ReadBuffer(&dwTempOffset, (dwOffset - 0x14), 0x4, 0x4))
			{
				if((dwTempOffset != 0) && (OUT_OF_FILE != (m_pMaxPEFile->Rva2FileOffset(dwTempOffset, &dwTempOffset))))
				{
					if(m_pMaxPEFile->ReadBuffer(byBuff, dwTempOffset, IMPLINKER_BUFF_SIZE, IMPLINKER_BUFF_SIZE))
					{
						BYTE STARTUP_SIG[] = {0x53,0x74,0x61,0x72,0x74,0x55,0x70};
						if(memcmp(&byBuff[0xA], STARTUP_SIG, 0x7) == 0x00)
						{
							if(m_pMaxPEFile->ReadBuffer(&dwTempOffset, (dwOffset - 0x8), 0x4, 0x4))
							{
								if(OUT_OF_FILE != (m_pMaxPEFile->Rva2FileOffset(dwTempOffset, &dwTempOffset)))
								{
									if(m_pMaxPEFile->ReadBuffer(byBuff, dwTempOffset, IMPLINKER_BUFF_SIZE, IMPLINKER_BUFF_SIZE))
									{
										m_dwpathOffset = dwTempOffset;
										m_dwImportoffset = dwOffset - 0x14;

										BYTE PATH_SIG[] = {0x79,0x73,0x74,0x65,0x6D,0x33,0x32,0x5C,0x6D,0x73,0x30,0x62,0x39,0x32,0x30,0x62,0x2E,0x64,0x6C,0x6C};
										if((memcmp(&byBuff[0x0C], PATH_SIG, 0x14) == 0x00) || (memcmp(&byBuff[0x0A], PATH_SIG, 0x14) == 0x00))
										{
											_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Implinker.a"));							
											return VIRUS_FILE_REPAIR;
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Implinker Family
--------------------------------------------------------------------------------------*/
int CPolyImplinker::CleanVirus()
{	
	if(m_pMaxPEFile->FillWithZeros(m_dwpathOffset, 0x20))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwImportoffset, 0x14))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyKarachun
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyKarachun::CPolyKarachun(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile),
m_dwOriginalAEP(0x00),
m_dwNoPatchedBytes(0x00)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyKarachun
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyKarachun::~CPolyKarachun(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;		
	}	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Detection routine for different varients of Karachun Family
					- Infects AEP that lies in code section only.
					- Variable size of patch at infected AEP
					- Original bytes appended in last section
					- Detection on basis of instruction
--------------------------------------------------------------------------------------*/
int CPolyKarachun::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(m_wAEPSec != 0 || (m_pSectionHeader[m_wAEPSec].Characteristics != 0xC0000040) ||
		(m_pSectionHeader[m_wNoOfSections - 1].Characteristics != 0xC0000040))
	{
		return iRetStatus;
	}

	DWORD dwTimeStamp = 0x00;
	m_pMaxPEFile->ReadBuffer(&dwTimeStamp, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x08, 0x04);
	if(dwTimeStamp != 0x20B638FF)
	{
		return iRetStatus;	
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int KARACHUN_BUFF_SIZE = 0x300;
	m_pbyBuff = new BYTE[KARACHUN_BUFF_SIZE + MAX_INSTRUCTION_LEN]; 
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, KARACHUN_BUFF_SIZE + MAX_INSTRUCTION_LEN);

	DWORD dwReadOff = m_dwAEPMapped + 0x50;
	if(!GetBuffer(dwReadOff, KARACHUN_BUFF_SIZE, KARACHUN_BUFF_SIZE))   // Reading Buffer from AEP + 50
	{
		return iRetStatus;
	}

	DWORD dwOffset = 0x00, dwMatchedInstr = 0x00, dwLength = 0x00;
	BYTE STARTUP_SIG[] = {0xE8, 0x00, 0x00, 0x00, 0x00}, byXORKey, byAEP[4] = {0};
	if(OffSetBasedSignature(STARTUP_SIG, sizeof(STARTUP_SIG), &dwOffset))	// Checking 1st Call from AEP + 50 
	{	
		// Reading encrypted Original AEP
		if(!m_pMaxPEFile->ReadBuffer(&byAEP, dwReadOff + dwOffset + 0xEED,0x4))   
		{
			return iRetStatus;
		}

		//Getting Size of patch at infected AEP in code section
		m_dwNoPatchedBytes = dwOffset + 0x15F4;             

		//Checking Some instructions within 20 bytes
		while(dwOffset < dwOffset + 0x20 && dwOffset < m_dwNoOfBytes)	
		{	
			t_disasm da;
			memset(&da, 0x00, sizeof(struct t_disasm));
			dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwLength > m_dwNoOfBytes - dwOffset)
			{
				break;
			}

			if(dwMatchedInstr == 0x00 && dwLength == 0x01 && strstr(da.result, "POP EDI"))
			{
				dwMatchedInstr++;
			}
			if(dwMatchedInstr == 0x01 && dwLength == 0x03 && strstr(da.result, "SUB EDI,5"))
			{
				dwMatchedInstr++;
			}
			if(dwMatchedInstr == 0x02 && dwLength == 0x02 && strstr(da.result, "MOV ESI,EDI"))
			{
				dwMatchedInstr++;
			}

			if(dwMatchedInstr == 0x03 && dwLength == 0x03 && strstr(da.result, "ADD ESI,1D"))
			{
				dwMatchedInstr++;
			}
			if(dwMatchedInstr == 0x04 && dwLength == 0x05 && strstr(da.result, "MOV ECX,15D7"))
			{
				dwMatchedInstr++;
			}
			if(dwMatchedInstr == 0x05 && dwLength == 0x03 && strstr(da.result, "XOR BYTE PTR [ESI]"))
			{
				byXORKey = m_pbyBuff[dwOffset + 2];				// Getting Encryption Key
				dwMatchedInstr++;
			}
			if(dwMatchedInstr == 0x06 && dwLength == 0x01 && strstr(da.result, "INC ESI"))
			{
				for(int i=0; i < 0x4; i++)
				{
					byAEP[i] ^= byXORKey;						// Decryption for original AEP
				}

				m_dwOriginalAEP = *(DWORD *)&byAEP - m_dwImageBase;

				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Karachun.a"));
				
				if(m_dwOriginalAEP < m_pMaxPEFile->m_stPEHeader.SizeOfImage)
				{					
					return VIRUS_FILE_REPAIR;
				}
				return VIRUS_FILE_DELETE;			
				
			}
			dwOffset += dwLength;
		}	
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Repair routine for different varients of Karachun Family
--------------------------------------------------------------------------------------*/
int CPolyKarachun::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_pSectionHeader[m_wNoOfSections -1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections -1].PointerToRawData - 0x2000, m_dwAEPMapped, m_dwNoPatchedBytes))
	{
		if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
		{
			m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wNoOfSections -1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections -1].PointerToRawData- 0x2000,true);
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyChop
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyChop::CPolyChop(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwVirusStart = 0;
	m_dwOriAEPOffset = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyChop
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyChop::~CPolyChop()
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Chop Family
--------------------------------------------------------------------------------------*/
int CPolyChop::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;	

	DWORD dwChecksum = m_pMaxPEFile->m_stPEHeader.CheckSum;  // Checksum = coke
	if(dwChecksum == 0x454B6F43 && m_wAEPSec == m_wNoOfSections-1 && 
		m_pSectionHeader[m_wNoOfSections - 1].Characteristics == 0xC0000040)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int CHOP_BUFF_SIZE = 0x150;
		m_pbyBuff = new BYTE[CHOP_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, CHOP_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	
		if(!GetBuffer(m_dwAEPMapped, CHOP_BUFF_SIZE, CHOP_BUFF_SIZE))
		{
			return iRetStatus;
		}
		char op = ' ';
		DWORD dwLength = 0,  dwOffset = 0, dwMatchedInstr = 0, dwTruncOffset = 0, dwTruncOffset1 = 0, dwTruncOffset2 = 0;
		t_disasm	da;
		int iFlag = 0;

		while(dwOffset < m_dwNoOfBytes && iFlag < 3)
		{		
			memset(&da, 0x00, sizeof(struct t_disasm));
			dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	
			if(dwLength > (m_dwNoOfBytes - dwOffset))
			{
				break;
			}

			if((dwLength == 0x2 || dwLength == 0x5) && (strstr(da.result, "JMP SHORT") || strstr(da.result, "JMP") ))
			{
				if(dwLength == 0x5)
				{
					dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwOffset;
				}
				else
				{
					dwOffset = m_pbyBuff[dwOffset + 1] + dwOffset;
				}
			}

			if(dwLength == 0x5 && (strstr(da.result, "MOV E")) && iFlag < 2)
			{
				dwTruncOffset = da.immconst;
				WORD wSecNo;
				Rva2FileOffsetEx(dwTruncOffset - m_dwImageBase, &wSecNo);  // Truncate offset should be in last section
				if(m_wNoOfSections - 1 == wSecNo  && dwTruncOffset - m_dwImageBase < m_dwAEPUnmapped)
				{
				
					dwTruncOffset2 = dwTruncOffset - m_dwImageBase;   // Getting Truncate offset
					iFlag++;
				}
				else if(dwTruncOffset == 0xFFFFF120|| dwTruncOffset == 0x00000EE0) // Size of Virus code above Infected AEP
				{
					dwTruncOffset1 = dwTruncOffset;
					iFlag++;
				}
			}
			if(iFlag == 2)
			{
				// Decryption instructions
				if(dwLength == 3 && strstr(da.result, "ADD BYTE PTR [E"))
					op= '+';
				else if(dwLength == 2 && strstr(da.result, "NOT BYTE PTR [E"))
					op = '~';
				else if(dwLength == 3 && strstr(da.result, "SUB BYTE PTR [E"))
					op = '-';
				else if(dwLength == 3 && strstr(da.result, "XOR BYTE PTR [E")) 
					op = '^';

				if ( op!= ' ')
				{
					// Calculations to get accurate truncate offset
					if(dwTruncOffset1 == 0xFFFFF120)
					{
						m_dwVirusStart = dwTruncOffset2 + dwTruncOffset1 + 1;
						if((m_dwAEPUnmapped - m_dwVirusStart) > 0x1000)
						{
							m_dwVirusStart = dwTruncOffset2;		
						}
					}
					else if((dwTruncOffset1 + dwTruncOffset2) > m_dwAEPUnmapped)
					{
						m_dwVirusStart = dwTruncOffset2 - dwTruncOffset1 + 1;
					}
					else
					{
						m_dwVirusStart = dwTruncOffset2;
					}
					iFlag++;
				}
			}
			dwOffset += dwLength;
		}
		if(iFlag == 3)
		{
			if(!GetBuffer(Rva2FileOffsetEx(m_dwVirusStart,0) + 0xA30, 0x50, 0x50))  // getting buffer for Sign
			{
				return iRetStatus;
			}
			if(!DecrypBuff(0x50, op))
			{
				return iRetStatus;
			}
			
			// Sign: W32/Wm.Cocaine by
			BYTE CHOP_SIG1[] = {0x57,0x33,0x32,0x2F,0x57,0x6D,0x2E,0x43,0x6F,0x63,0x61,0x69,0x6E,0x65,0x20,0x62,0x79};
			if(OffSetBasedSignature(CHOP_SIG1,sizeof(CHOP_SIG1),NULL))
			{
				GetBuffer(Rva2FileOffsetEx(m_dwVirusStart, 0) + 0x11E, 4, 4);  // Getting Buffer for Original AEP
				DecrypBuff(4, op);		
				m_dwOriAEPOffset = *(DWORD *)m_pbyBuff + m_dwVirusStart + 0x11D + 0x5;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.CHOP.3808"));
				return VIRUS_FILE_REPAIR;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DecrypBuff
	In Parameters	: 
	Out Parameters	: DWORD dwBytesToDecryp, char Instr
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption of Buffer taken from file
--------------------------------------------------------------------------------------*/
bool CPolyChop::DecrypBuff(DWORD dwBytesToDecryp, char Instr)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD i =0;
	for(i= 0; i< dwBytesToDecryp; i++)
	{
		switch(Instr)
		{
		case '+': 
			m_pbyBuff[i] += 0xDD;	
			break;
		case '~':
			m_pbyBuff[i] = ~m_pbyBuff[i];
			break;
		case '-':
			m_pbyBuff[i] -= 0x80;	
			break;
		case '^':
			m_pbyBuff[i] ^= 0x43;
		}

	}
	return (i == dwBytesToDecryp) ? true : false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of CPolyChop Family
--------------------------------------------------------------------------------------*/
int CPolyChop::CleanVirus()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriAEPOffset))
	{
		if(m_pMaxPEFile->TruncateFile(Rva2FileOffsetEx(m_dwVirusStart,0)))
		{
			m_pMaxPEFile->CalculateChecksum();
			return REPAIR_SUCCESS;
		}
	}

	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyBytesv
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyBytesv::CPolyBytesv(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0x0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyBytesv
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyBytesv::~CPolyBytesv(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Bytesv Family
--------------------------------------------------------------------------------------*/
int CPolyBytesv::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections - 1 && m_dwAEPUnmapped == m_pSectionHeader[m_wAEPSec].VirtualAddress &&
		(memcmp(m_pSectionHeader[m_wAEPSec].Name, ".ByteSV", 7) == 0) && m_pSectionHeader[m_wAEPSec].SizeOfRawData <= 0x1000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int BYTESV1391_BUFF_SIZE = 0x600;
		m_pbyBuff = new BYTE[BYTESV1391_BUFF_SIZE];
		const BYTE BYTESV1391_SIG[] = {0x60,0x9C,0xE8,0x01,0x00,0x00,0x00,0xE5,0x5D,0x81,0xED,0x07,0x10,0x40,0x00,0xB8};
		const BYTE BYTESV1391_SIG1[] = {0x57,0x6F,0x6C,0x66,0x68,0x65,0x61,0x72,0x74}; //Wolfheart
		if(!GetBuffer(m_dwAEPMapped,0x20,0x20))
		{
			return iRetStatus;
		}
		if(memcmp(&m_pbyBuff[0x0],BYTESV1391_SIG,sizeof(BYTESV1391_SIG)) == 0)
		{
			DWORD dwXORKey = *(DWORD *)&m_pbyBuff[0x10];
			DWORD dwADDOff = *(DWORD *)&m_pbyBuff[0x15] - 0x400000;
			DWORD dwDecOff = (m_dwAEPUnmapped - 0x1000)+ dwADDOff;
			DWORD dwDecOffset = 0x0;
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwDecOff,&dwDecOffset))
			{
				return iRetStatus;
			}
			DWORD dwBuffSize = m_pMaxPEFile->m_dwFileSize - dwDecOffset;
			if(dwBuffSize > BYTESV1391_BUFF_SIZE)
				dwBuffSize = 0x600;

			if(!GetBuffer(dwDecOffset,dwBuffSize,dwBuffSize))
			{
				return iRetStatus;
			}
			for(DWORD i = 0x0; i < dwBuffSize; i+= 4)
			{
				*(DWORD *)&m_pbyBuff[i] ^= dwXORKey;
			}
			bool bSign = false, bOffset = false;
			DWORD dwIndex = 0x0;
			const BYTE bChk[] = {0x52,0x8B,0x95};
			for(int i = 0;i < dwBuffSize; i++)
			{
				if(bSign == false)
					if(memcmp(&m_pbyBuff[i],BYTESV1391_SIG1,sizeof(BYTESV1391_SIG1)) == 0)
					{
						bSign = true;
					}

				if(bOffset == false)
					if(memcmp(&m_pbyBuff[i],bChk,sizeof(bChk)) == 0)
					{
						bOffset = true;	
						dwIndex = i;
					}
				if(bSign == true && bOffset == true)
				{
					DWORD dwOriAEPOff = (m_dwAEPUnmapped - 0x1000)+ (*(DWORD *)&m_pbyBuff[dwIndex + sizeof(bChk)] - 0x400000) - dwDecOff;
					m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[dwOriAEPOff];
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Bytesv.1391"));
					return VIRUS_FILE_REPAIR;
				}
			}
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Bytesv.1391"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Bytesv Family
--------------------------------------------------------------------------------------*/
int CPolyBytesv::CleanVirus(void)
{
	int iRetStatus=VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->RemoveLastSections(0x1,true))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyDugert
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDugert::CPolyDugert(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDugert
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDugert::~CPolyDugert(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Dugert Family
--------------------------------------------------------------------------------------*/
int CPolyDugert::DetectVirus(void)
{	
	int iRetStatus = VIRUS_NOT_FOUND;
	if((memcmp(m_pSectionHeader[m_wAEPSec].Name," ",0) == 0) &&
	     m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x3000 && 
		 ((m_wAEPSec == 0 && m_dwAEPMapped == 0x2D6F) || (m_wAEPSec == 1 && m_dwAEPMapped == 0x4BD6)))
 	{
		if(m_pbyBuff)
		{
			delete m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int DUGERT_BUFF_SIZE = 0x1A;
		m_pbyBuff = new BYTE[DUGERT_BUFF_SIZE];
		if(GetBuffer(0x20,DUGERT_BUFF_SIZE,DUGERT_BUFF_SIZE))
		{
			if(*(DWORD *)&m_pbyBuff[0x14] == m_dwAEPMapped)
			{
				BYTE byDugertSig1[] = {0xE0, 0x00, 0x0F, 0x01, 0x0B, 0x01, 0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x1A,0x00,0x00,0x00,0x00,0x00,0x00,0x6F,0x2D,0x00,0x00,0x00,0x10};
				BYTE byDugertSig2[] = {0xE0, 0x00, 0x0F, 0x01, 0x0B, 0x01, 0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x1A,0x00,0x00,0x00,0x00,0x00,0x00,0xD6,0x4B,0x00,0x00,0x00,0x10};

				if((memcmp(byDugertSig1, &m_pbyBuff[0x0], sizeof(byDugertSig1)) == 0 ) ||
					(memcmp(byDugertSig2, &m_pbyBuff[0x0], sizeof(byDugertSig2)) == 0))
	  			{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.HLLP.Dugert.a"));
					return VIRUS_FILE_REPAIR;
				}
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Dugert Family
--------------------------------------------------------------------------------------*/
int CPolyDugert::CleanVirus(void)
{
	int iRetStatus=VIRUS_NOT_FOUND;
	DWORD dwBuffSize = m_pMaxPEFile->m_dwFileSize-0x2;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[dwBuffSize];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	DWORD dwBytes2Read = m_pMaxPEFile->m_dwFileSize-0xED0;
	if(!GetBuffer(0xED0,dwBytes2Read,dwBytes2Read))
	{
		return iRetStatus;
	}
	DWORD dwXORKey = 0xC7, dwDIVKey = 0x85, dwTempKey  = 0x0, k = 0x0;
	bool flag = false;
	for(DWORD j = 0 ;j < dwBuffSize ;j++)
	{
		DWORD dwRemValue = j%dwDIVKey;
		if(j/dwDIVKey)
		{
			dwXORKey = dwTempKey; 
			flag = true;
			if(dwRemValue == 0x0)
				k = 0;
		}
		m_pbyBuff[j] ^= BYTE(dwXORKey);
		if(flag == true)
		{
			dwXORKey+= k * 0x3;
			k++;
		}
		else if(flag == false)
		{
			dwXORKey+= j * 0x3;
		}
		dwTempKey = BYTE(dwXORKey);	
	}
	if(m_pMaxPEFile->WriteBuffer(m_pbyBuff,0x0,dwBuffSize,dwBuffSize))
	 {
		if(m_pMaxPEFile->TruncateFile(dwBytes2Read - 0x2,true))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyPoson4367
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Prajakta
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyPoson4367::CPolyPoson4367(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile),
m_dwVirusOff(0x0),
m_dwDecStart(0x0),
m_dwVirusFileOff(0x0)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyPoson4367
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Prajakta
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyPoson4367::~CPolyPoson4367(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;		
	}	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Prajakta + Virus Analysis Team
	Description		: Detection routine for different varients of Poson4367 Family
--------------------------------------------------------------------------------------*/
int CPolyPoson4367::DetectVirus()
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	DWORD	dwReservedBytes = 0;

	m_pMaxPEFile->ReadBuffer(&dwReservedBytes, 0x10, sizeof(DWORD), sizeof(DWORD));
	if(m_wAEPSec == 0x0 && dwReservedBytes == 0x21212121)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int	POSON4367_BUFF_SIZE = 0x110;
		m_pbyBuff = new BYTE[POSON4367_BUFF_SIZE]; 
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwAEPMapped + 0x1,sizeof(DWORD),sizeof(DWORD)))
		{
			return iRetStatus;
		}
		m_dwVirusOff = *(DWORD *)&m_pbyBuff[0x0] + 0x5 + m_dwAEPUnmapped;

		WORD	wSecNo = m_pMaxPEFile->Rva2FileOffset(m_dwVirusOff,&m_dwVirusFileOff);

		if(m_dwVirusOff > m_pMaxPEFile->m_dwFileSize &&
			(m_pSectionHeader[wSecNo].Characteristics & 0x81000041) != 0x81000041)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwVirusFileOff,POSON4367_BUFF_SIZE,0x3C))
		{
			return iRetStatus;
		}
		if( m_pbyBuff[0x00] == 0xEB && m_pbyBuff[0x01] == 0x01 && m_pbyBuff[0x03] == 0xBE && 
			m_pbyBuff[0x08] == 0xEB && m_pbyBuff[0x09] == 0x01 && m_pbyBuff[0x0B] == 0xB9 &&
			m_pbyBuff[0x13] == 0xE4 && m_pbyBuff[0x14] == 0x40 && m_pbyBuff[0x18] == 0x30 &&
			m_pbyBuff[0x19] == 0x06 && m_pbyBuff[0x1D] == 0x46)
		{
			m_dwDecStart = *(DWORD *)&m_pbyBuff[0x4] - m_dwImageBase;
			DWORD dwDecCnt = *(DWORD *)&m_pbyBuff[0xC];
			BYTE bXORKey = m_pbyBuff[(m_dwDecStart - m_dwVirusOff) + 0x40];
			for(int i = 0x0; i < dwDecCnt ; i++)
			{
				m_pbyBuff[(m_dwDecStart - m_dwVirusOff) + i]^= bXORKey;
			}
			if(m_pbyBuff[(m_dwDecStart - m_dwVirusOff)] == 0xEB && m_pbyBuff[(m_dwDecStart - m_dwVirusOff) + 0x1] == 0x6C && 
				*(DWORD *)&m_pbyBuff[(m_dwDecStart - m_dwVirusOff) + 0x2] == m_dwAEPUnmapped && 
				*(DWORD *)&m_pbyBuff[(m_dwDecStart - m_dwVirusOff) + 0x6] == m_dwDecStart &&
				m_pMaxPEFile->m_dwFileSize - m_dwVirusOff >= 0xF9)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Poson.4367"));
				return VIRUS_FILE_REPAIR;			
			}
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Poson.4367"));
			return VIRUS_FILE_DELETE;		
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Prajakta + Virus Analysis Team
	Description		: Repair routine for different varients of Poson4367 Family
--------------------------------------------------------------------------------------*/
int CPolyPoson4367::CleanVirus()
{
	for(int i = (m_dwDecStart - m_dwVirusOff)+ 0xA; i < ((m_dwDecStart - m_dwVirusOff)+ 0x30); i+= 0xA)
	{
		DWORD	dwVirusOffset = *(DWORD*)&m_pbyBuff[i];
		WORD	wVirusSize = *(WORD*)&m_pbyBuff[i + sizeof(DWORD)];
		if(dwVirusOffset == 0x0 || wVirusSize == 0x0)
		{
			break;
		}
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwVirusOffset,&dwVirusOffset))
		{
			m_pMaxPEFile->FillWithZeros(dwVirusOffset,wVirusSize);
		}
	}	
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[(m_dwDecStart - m_dwVirusOff) + 0x7F],m_dwAEPMapped,sizeof(DWORD)))
	{
		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[(m_dwDecStart - m_dwVirusOff) + 0x85],m_dwAEPMapped + 0x4,0x1))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwVirusFileOff))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyMeginA
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMeginA::CPolyMeginA(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile),
m_dwOriginalAEP(0x0),
m_dwJmpOff(0x0),
m_dwImportRVA(0x0)
{
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMeginA
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMeginA::~CPolyMeginA(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;		
	}	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Prajakta + Virus Analysis Team
	Description		: Detection routine for different varients of MeginA Family
--------------------------------------------------------------------------------------*/
int CPolyMeginA::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wAEPSec == 0x0 || m_wAEPSec == 0x1) && (m_pSectionHeader[m_wAEPSec].Characteristics == 0xC2000040))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x15]; 
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwAEPMapped,0x12,0x12))
		{
			return iRetStatus;
		}
		if(m_pbyBuff[0x0] == 0xE8 && m_pbyBuff[0x5] == 0xB8 && m_pbyBuff[0xA] == 0xFF && m_pbyBuff[0xB] == 0xE0 &&
			m_pbyBuff[0xC] == 0xFF && m_pbyBuff[0xD] == 0x25)
		{
			m_dwImportRVA = m_dwJmpOff = *(DWORD *)&m_pbyBuff[0xE] - m_dwImageBase;
			m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[0x6] - m_dwImageBase;
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwJmpOff,&m_dwJmpOff))
			{
				return iRetStatus;
			}
			DWORD dwSigOff = 0x0;
			const BYTE bMeginA_Sig[] = {0x6B,0x65,0x72,0x6E,0x2E,0x64,0x6C,0x6C,0x00,0x00,0x00,0x00,0x20,0x20,0x4D,
				                    0x62,0x65,0x67,0x69,0x6E}; //kern.dll....  Mbegin
			if(m_pMaxPEFile->ReadBuffer(&dwSigOff,m_dwJmpOff,sizeof(DWORD),sizeof(DWORD)))
			{
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwSigOff,&dwSigOff) || dwSigOff == 0x0)
				{
					return iRetStatus;
				}
				if(!GetBuffer(dwSigOff - 0xC,sizeof(bMeginA_Sig),sizeof(bMeginA_Sig)))
				{
					return iRetStatus;
				}
			}
			if(memcmp(&m_pbyBuff[0x0],bMeginA_Sig,sizeof(bMeginA_Sig)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Megin.A"));
				return VIRUS_FILE_REPAIR;	
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Prajakta + Virus Analysis Team
	Description		: Repair routine for different varients of MeginA Family
--------------------------------------------------------------------------------------*/
int CPolyMeginA::CleanVirus()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped,0x12))
		{
			DWORD dwImportOff = 0x0;
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].VirtualAddress,&dwImportOff))
			{
				return false;
			}
			if(!GetBuffer(dwImportOff,0x10,0x10))
			{
				return false;
			}
			if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x0],m_dwJmpOff,0x10,0x10))
			{
				if(m_pMaxPEFile->FillWithZeros(dwImportOff,m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size + 0x40))
				{
					if(m_pMaxPEFile->RepairOptionalHeader(0x20,m_dwImportRVA,0x0,false))
					{
						if(m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress != 0x0)
						{
							m_pMaxPEFile->RepairOptionalHeader(0x2A,0x0,0x0,true);
						}
						return REPAIR_SUCCESS;
					}
				}
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSigInBuffer
	In Parameters	: DWORD	dwBuffStartPos, DWORD	dwBuffSize2Read, LPCTSTR lpszSig2Check
	Out Parameters	: true is success else false 
	Purpose			: 
	Author			: Tushar Kadam + Gaurav + Virus Analysis Team
	Description		: Common fucntion read buffer from file and search for given signature using CSemiPolyDBScn
					  Limitation		:  Will work only with single signature search	
--------------------------------------------------------------------------------------*/
bool CPolyBase::CheckSigInBuffer(DWORD	dwBuffStartPos, DWORD	dwBuffSize2Read, LPCTSTR lpszSig2Check)
{
	bool	bReturn = false;

	if (dwBuffSize2Read == 0x00 || lpszSig2Check == NULL)
	{
		return bReturn;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	m_pbyBuff = new BYTE[dwBuffSize2Read];

	if(GetBuffer(dwBuffStartPos , dwBuffSize2Read, dwBuffSize2Read))  
	{
		TCHAR				szVirusName[MAX_PATH] = {L"Trojan.PSU.301983.gen"};
		CSemiPolyDBScn		SemiPolyDBScn;
			
		SemiPolyDBScn.LoadSigDBEx(lpszSig2Check,szVirusName, FALSE);
		if(SemiPolyDBScn.ScanBuffer(&m_pbyBuff[0], dwBuffSize2Read , szVirusName)>=0)	
		{
			bReturn = true;
		}
		return bReturn;
	}
	return bReturn;
}


/*-------------------------------------------------------------------------------------
	Function		: CPolyAgentFT
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAgentFT::CPolyAgentFT(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalFileOffset = 0;
	m_dwOriginalFileSize = 0;
	m_dwFillZeroOff = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAgentFT
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyAgentFT::~CPolyAgentFT(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: mutex name :  ??KOLO.PACMAN%CLOCKWORK%KOLOBOK
					  file name  :  wecoxs.~00
                             wecoxs.~01
                             namcap.dat
					 Note        :
					 *> it drops one file in application data i.e \namcap.dat 
					 *> it creates mutex "??KOLO.PACMAN%CLOCKWORK%KOLOBOK"
--------------------------------------------------------------------------------------*/
int CPolyAgentFT::DetectVirus()
{
	int iRetStatus = 0;

	if(m_wAEPSec == 0x0 && m_wNoOfSections == 0x8 && m_dwAEPMapped == 0x5BBB4 &&  m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x5B800)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		int AGENTFT_BUFF_SIZE = 0x1F4;
		m_pbyBuff = new BYTE[AGENTFT_BUFF_SIZE];

		if(GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData + 0x5B471,AGENTFT_BUFF_SIZE, AGENTFT_BUFF_SIZE))
		{
			TCHAR AGENTFT_CZ_Sig[] = {_T("3F3F4B4F4C4F00*5041434D414E25434C4F434B574F524B254B4F4C4F424F4B*7765636F78732E7E3030*7765636F78732E7E3031*6E616D6361702E646174")};
			//??KOLO.*PACMAN%CLOCKWORK%KOLOBOK*wecoxs.~00*wecoxs.~01*namcap.dat

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(AGENTFT_CZ_Sig, _T("Virus.W32.Agent.ft"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], AGENTFT_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{ 
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					m_dwOriginalFileOffset = 0x6B200;

					m_dwOriginalFileSize = m_pMaxPEFile->m_dwFileSize - m_dwOriginalFileOffset;

					m_dwFillZeroOff = m_dwOriginalFileSize - 0x0E;

					WORD	byCheckMz = 0x0;

					if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwOriginalFileOffset,0x2,0x2))
					{
						return VIRUS_FILE_DELETE;
					}
					else if(byCheckMz == 0x5A4D)
					{
						return VIRUS_FILE_REPAIR;
					}
					else
					{
						return VIRUS_FILE_DELETE;
					}

				}

			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of AgentFT Family
--------------------------------------------------------------------------------------*/
int CPolyAgentFT::CleanVirus()
{	
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->CopyData(m_dwOriginalFileOffset, 0, m_dwOriginalFileSize))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwFillZeroOff, 0x08))
		{

			if(m_pMaxPEFile->ForceTruncate(m_dwOriginalFileSize))
			{

				return REPAIR_SUCCESS;
			}

		}
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyRiskToolBitMiner
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyRiskToolBitMiner::CPolyRiskToolBitMiner(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	DWORD m_dwOrigFileOff = 0x0;
	DWORD m_dwOrigFileSize = 0x0;
	bool m_bInfectionCleaned = false;
	DWORD m_SIGNOff = 0x0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyRiskToolBitMiner
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyRiskToolBitMiner::~CPolyRiskToolBitMiner(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Gaurav + Virus Analysis Team
	Description		: Detection routine for different varients of BitMiner Family
--------------------------------------------------------------------------------------*/
int CPolyRiskToolBitMiner::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL && (memcmp(m_pSectionHeader[0x02].Name, ".data", 7) == 0) && (memcmp(m_pSectionHeader[0x03].Name, ".data", 7) == 0) && m_pMaxPEFile->m_stSectionHeader[0x03].SizeOfRawData == 0x0200)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Risk.BitMiner.Gen"));// Heuristic
		return VIRUS_FILE_DELETE;
	}
	
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{

		if(m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x0].VirtualAddress, &m_dwOrigFileOff ))
		{
			DWORD dwoff;
			m_dwOrigFileOff = m_dwOrigFileOff + 0x0C;
			if(m_pMaxPEFile->ReadBuffer(&dwoff,m_dwOrigFileOff,0x04,0x04))
			{
				if(m_pMaxPEFile->Rva2FileOffset(dwoff,&m_dwOrigFileOff))
				{
					if(CheckSigInBuffer(m_dwOrigFileOff,0x010,_T("62776E647769*6E77692E646C6C")))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Risk.BitMiner.Gen"));
						return VIRUS_FILE_DELETE;

					}
				}

			}
		}
	}
	if(CheckSigInBuffer(0x021AB0,0x0D0,_T("6D696E652E707078786D722E636F6D3A35353535*2275736572223A2022343758446864506F7039434D7153786E5A")))
	{		
		m_SIGNOff = 0x021AB0;		
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Risk.BitMiner.Gen"));
		m_dwOrigFileOff = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData;// finding offset of next MZ offset
		m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOff;
		if(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].VirtualAddress != 0x0)//checking for certificate table
		{
			m_dwOrigFileOff = m_dwOrigFileOff + m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].Size;
			m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOff;

		}
		return VIRUS_FILE_REPAIR;
		/*DWORD dwCHECKMZ = 0x0;
		if(m_pMaxPEFile->ReadBuffer(&dwCHECKMZ,m_dwOrigFileOff,0x02,0x02))
		{
		if(dwCHECKMZ == 0x05A4D || dwCHECKMZ == 0x06942)
		return VIRUS_FILE_DELETE;
		else
		return VIRUS_FILE_DELETE;
		}*/


	}
	
	if(CheckSigInBuffer(m_pMaxPEFile->m_dwFileSize - 0x08,0x08,_T("4269744D*696E6572")))
	{

		//this signature checks added bytes used for recursive calls

		if(m_pMaxPEFile->m_dwFileSize == 0x08 || m_pMaxPEFile->m_dwFileSize == 0x0F)
		{
			return VIRUS_FILE_DELETE;
		}

		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Risk.BitMiner.Gen"));
		m_dwOrigFileOff = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
		m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOff;
		if(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].VirtualAddress != 0x0)
		{
			m_dwOrigFileOff = m_dwOrigFileOff + m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].Size;
			m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOff;

		}
		return VIRUS_FILE_REPAIR;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of BitMiner Family
--------------------------------------------------------------------------------------*/
int CPolyRiskToolBitMiner::CleanVirus()
{
	if(CheckSigInBuffer((m_pMaxPEFile->m_dwFileSize - 0x08),0x08,_T("4269744D*696E6572")))
	{
		if(m_dwOrigFileOff == (m_pMaxPEFile->m_dwFileSize - 0x08) )
		{
			if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileOff))
			{
				return REPAIR_SUCCESS;
			}
		}
		else//(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))
		{
			if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))
			{
				if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	else
	{
		BYTE byBitMiner[] = {0x42,0x69,0x74,0x4D,0x69,0x6E,0x65,0x72};


		if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))
		{
			if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
			{
				if(m_pMaxPEFile->WriteBuffer(&byBitMiner,m_dwOrigFileSize,0x08,0x08))
				{
					return REPAIR_SUCCESS;	
				}

			}
		}

	}
	return REPAIR_FAILED;
}


CPolyTrojangenerickdz::CPolyTrojangenerickdz(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile) 
{
	m_dwOrigFileOff = 0x00;
	M_dwVirusData = 0x00;
}
CPolyTrojangenerickdz::~CPolyTrojangenerickdz(void) 
{

	if(m_pbyBuff) {

		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
int CPolyTrojangenerickdz::DetectVirus(void)
{

	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0x00 && m_wNoOfSections == 0x3 && (m_dwAEPMapped== (m_dwAEPUnmapped-0x1000)) && m_pSectionHeader[m_wAEPSec].PointerToRawData==0x1000)
	{    

		DWORD dwStartBuff = m_dwAEPMapped-0x100;

		if(CheckSigInBuffer(dwStartBuff,0x70,_T("010308052001127D0308*0704127D127D03080A070512351D0E081D0E08052001011D030907051D031235*08080E052000128089052000128091042001080E0420010102092002128095")))
		{

			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.generickdz.51307"));
			DWORD byCheckString;
			m_dwOrigFileOff=m_pMaxPEFile->m_dwFileSize-0x4;
			m_pMaxPEFile->ReadBuffer(&byCheckString,m_dwOrigFileOff,0x4,0x4);
			if(byCheckString == 0x6F636C61)
			{
				return VIRUS_FILE_REPAIR;
			} 




		}

	}
	return iRetStatus;
}

int CPolyTrojangenerickdz::CleanVirus()
{

	if(m_wNoOfSections == 0x3 && (m_dwAEPMapped==(m_dwAEPUnmapped-0x1000)))
	{
		m_dwOrigFileOff= m_pSectionHeader[m_wNoOfSections-1].PointerToRawData + m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData;
		if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00,m_pMaxPEFile->m_dwFileSize-m_dwOrigFileOff)) 
		{

			if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize-(m_dwOrigFileOff + 0x4)))
			{
				//if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize-0x4))
				// {
				// m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize-0x4);
				return REPAIR_SUCCESS;
				//}
			}
		}
	}
	return REPAIR_FAILED;
}
