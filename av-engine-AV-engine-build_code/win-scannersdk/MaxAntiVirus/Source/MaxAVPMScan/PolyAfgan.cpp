/*======================================================================================
FILE				: PolyAfgan.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
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
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malwares Virus.Afgan Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyAfgan.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyAfgan
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAfgan::CPolyAfgan(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	memset(&m_oAfgan_Params, 0, sizeof(m_oAfgan_Params));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAfgan
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CPolyAfgan::~CPolyAfgan(void)
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
	Author			: Tushar Kadam
	Description		: Detection routine for different varients of Afgan Family
--------------------------------------------------------------------------------------*/
int CPolyAfgan::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > 0x5DA4)
	{
		m_pbyBuff = new BYTE[AFGAN_BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped, AFGAN_BUFF_SIZE, 0x10))		
		{
			if(*((DWORD *)&m_pbyBuff[0]) == 0xE8EC8B55 && (m_pbyBuff[7] == 0x00 || m_pbyBuff[7] == 0xFF))
			{
				DWORD dwOffsetRVA = *((DWORD *)&m_pbyBuff[0x04]) + m_dwAEPUnmapped + 0x08;
				DWORD dwOffset = 0, dwOrigBytesStartOffset = 0;
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOffsetRVA, &dwOffset))
				{
					if(GetBuffer(dwOffset, AFGAN_BUFF_SIZE, AFGAN_BUFF_SIZE))
					{
						const BYTE AFGAN_A_SIG[] = {
							0x55, 0x8B, 0xEC, 0xE8, 0x24, 0x00, 0x00, 0x00, 0x81, 0xE8, 0x70, 0x19, 0x40, 0x00, 0x81, 0xC0, 
							0xC8, 0x3E, 0x40, 0x00, 0x8B, 0xC0, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64, 0x89, 
							0x25, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x5A, 0x25, 0x00, 0x00, 0x5D, 0xC3, 0x55, 0x8B, 0xEC, 0xE8, 
							0x00, 0x00, 0x00, 0x00, 0x58, 0x83, 0xE8, 0x08, 0x5D, 0xC3, 0x90, 0x90, 0x55, 0x8B, 0xEC, 0x51, 
							0x83, 0x7D, 0x10, 0x00, 0x7E, 0x19, 0x8B, 0x45, 0x08, 0x8A, 0x10, 0x8B, 0x4D, 0x0C, 0x88, 0x11, 
							0xFF, 0x45, 0x0C, 0xFF, 0x45, 0x08, 0xFF, 0x4D, 0x10, 0x83, 0x7D, 0x10, 0x00, 0x7F, 0xE7, 0x83, 
							0x7D, 0x14, 0x00, 0x74, 0x06, 0x8B, 0x45, 0x14, 0x89, 0x45, 0x04, 0x59, 0x5D, 0xC2, 0x10, 0x00, 
							0x55, 0x8B, 0xEC, 0xE8, 0x50, 0x00, 0x00, 0x00};


						const BYTE AFGAN_C_SIG[] = {
							0x55, 0x8B, 0xEC, 0x83, 0xC4, 0xF4, 0x53, 0xE8, 0xCC, 0xFF, 0xFF, 0xFF, 0xE8, 0xC7, 0x00, 0x00,
							0x00, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00, 
							0xE8, 0xB3, 0xFF, 0xFF, 0xFF, 0xE8, 0xD2, 0x02, 0x00, 0x00, 0x89, 0x45, 0xFC, 0xB8, 0xEC, 0x76,
							0x40, 0x00, 0x81, 0xE8, 0x94, 0x1C, 0x40, 0x00, 0xC1, 0xE8, 0x02, 0x89, 0x45, 0xF8, 0xE8, 0x39, 
							0x00, 0x00, 0x00, 0x8B, 0x50, 0x18, 0x89, 0x55, 0xF4, 0x83, 0x7D, 0xF8, 0x00, 0x7E, 0x15, 0x8B, 
							0x4D, 0xF4, 0x8B, 0x45, 0xFC, 0x29, 0x08, 0x83, 0x45, 0xFC, 0x04, 0xFF, 0x4D, 0xF8, 0x83, 0x7D, 
							0xF8, 0x00, 0x7F, 0xEB, 0xE8, 0xCB, 0x2B, 0x00, 0x00, 0x64, 0x8F, 0x05, 0x00, 0x00, 0x00, 0x00, 
							0x58, 0xE8, 0x62, 0x00, 0x00, 0x00, 0x5B, 0x8B, 0xE5, 0x5D, 0xC3, 0x90, 0x55, 0x8B, 0xEC, 0xE8, 
							0x50, 0x00, 0x00, 0x00};

						const BYTE AFGAN_D_SIG[] = {
							0x55, 0x8B, 0xEC, 0xE8, 0xF0, 0x32, 0x00, 0x00, 0xE8, 0x93, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0x90, 
							0x55, 0x8B, 0xEC, 0x51, 0x83, 0x7D, 0x10, 0x00, 0x7E, 0x19, 0x8B, 0x45, 0x08, 0x8A, 0x10, 0x8B, 
							0x4D, 0x0C, 0x88, 0x11, 0xFF, 0x45, 0x0C, 0xFF, 0x45, 0x08, 0xFF, 0x4D, 0x10, 0x83, 0x7D, 0x10, 
							0x00, 0x7F, 0xE7, 0x83, 0x7D, 0x14, 0x00, 0x74, 0x06, 0x8B, 0x45, 0x14, 0x89, 0x45, 0x04, 0x59, 
							0x5D, 0xC2, 0x10, 0x00, 0x55, 0x8B, 0xEC, 0xE8, 0x50, 0x00, 0x00, 0x00};
						
						const BYTE AFGAN_E_SIG[] = {
							0x55, 0x8B, 0xEC, 0x83, 0xC4, 0xF4, 0x53, 0xE8, 0xCC, 0xFF, 0xFF, 0xFF, 0xE8, 0xDB, 0x00, 0x00, 
							0x00, 0x50, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00, 
							0xE8, 0xB3, 0xFF, 0xFF, 0xFF, 0xE8, 0xE6, 0x02, 0x00, 0x00, 0x89, 0x45, 0xFC, 0xB8, 0x0C, 0x77, 
							0x40, 0x00, 0x81, 0xE8, 0xA8, 0x1C, 0x40, 0x00, 0xC1, 0xE8, 0x02, 0x89, 0x45, 0xF8, 0xE8, 0x4D, 
							0x00, 0x00, 0x00, 0x8B, 0x50, 0x18, 0x89, 0x55, 0xF4, 0x83, 0x7D, 0xF8, 0x00, 0x7E, 0x28, 0x8B, 
							0x4D, 0xF4, 0xF7, 0xD1, 0x8B, 0x45, 0xFC, 0x23, 0x08, 0x8B, 0x55, 0xFC, 0x8B, 0x02, 0xF7, 0xD0, 
							0x23, 0x45, 0xF4, 0x03, 0xC8, 0x8B, 0x55, 0xFC, 0x89, 0x0A, 0x83, 0x45, 0xFC, 0x04, 0xFF, 0x4D, 
							0xF8, 0x83, 0x7D, 0xF8, 0x00, 0x7F, 0xD8, 0xE8, 0xD8, 0x2B, 0x00, 0x00, 0x64, 0x8F, 0x05, 0x00, 
							0x00, 0x00, 0x00};

						if(memcmp(AFGAN_A_SIG, &m_pbyBuff[0], sizeof(AFGAN_A_SIG)) == 0)
						{
							m_oAfgan_Params.dwOriginalBytesOffset	= dwOffset + 0x7C;
							m_oAfgan_Params.dwPatchedCodeSizeOffset	= dwOffset + 0x258;
							iRetStatus = VIRUS_FILE_REPAIR;									
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Afgan.A"));
						}
						else if(memcmp(AFGAN_C_SIG, &m_pbyBuff[0], sizeof(AFGAN_C_SIG)) == 0)
						{
							m_oAfgan_Params.dwOriginalBytesOffset	= dwOffset + 0x88;
							m_oAfgan_Params.dwPatchedCodeSizeOffset	= dwOffset + 0x282;
							iRetStatus = VIRUS_FILE_REPAIR;									
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Afgan.C"));
						}
						else if(memcmp(AFGAN_D_SIG, m_pbyBuff, 4) == 0 &&
								memcmp(&AFGAN_D_SIG[7], &m_pbyBuff[7], sizeof(AFGAN_D_SIG) - 8) == 0)
						{
							m_oAfgan_Params.dwOriginalBytesOffset	= dwOffset + 0x50;
							m_oAfgan_Params.dwPatchedCodeSizeOffset	= dwOffset + 0x24A;
							iRetStatus = VIRUS_FILE_REPAIR;									
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Afgan.D"));
						}
						else if(memcmp(AFGAN_E_SIG, &m_pbyBuff[0], sizeof(AFGAN_E_SIG)) == 0)
						{
							m_oAfgan_Params.dwOriginalBytesOffset	= dwOffset + 0x9C;
							m_oAfgan_Params.dwPatchedCodeSizeOffset	= dwOffset + 0x296;
							iRetStatus = VIRUS_FILE_REPAIR;									
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Afgan.E"));
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
	Author			: Tushar Kadam
	Description		: Repair routine for different varients of Afgan Family
--------------------------------------------------------------------------------------*/
int CPolyAfgan::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	
	DWORD dwPatchedCodeSize = 0, dwSubVal = 0;
	if(!m_pMaxPEFile->ReadBuffer(&dwPatchedCodeSize, m_oAfgan_Params.dwPatchedCodeSizeOffset, 4, 4))
	{		
		return iRetStatus;
	}
	if(!m_pMaxPEFile->ReadBuffer(&dwSubVal, m_oAfgan_Params.dwPatchedCodeSizeOffset + 6, 4, 4))
	{		
		return iRetStatus;
	}
	dwPatchedCodeSize -= dwSubVal;

	DWORD dwStartOfReplacement = m_dwAEPMapped - dwPatchedCodeSize + 0xC;
	
	if(!GetBuffer(m_dwAEPMapped + 0x03, 5, 5))
	{
		return iRetStatus;
	}
	if(m_pbyBuff[0] == 0xE8 && m_pbyBuff[0x04] == 0x00)
	{
		dwStartOfReplacement = m_dwAEPMapped;
	}
	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[dwPatchedCodeSize];
	if(NULL == m_pbyBuff)
	{
		return iRetStatus;
	}

	DWORD dwOriginalDataOffset = 0;
	if(!m_pMaxPEFile->ReadBuffer(&dwOriginalDataOffset, m_oAfgan_Params.dwOriginalBytesOffset, 4, 4))
	{
		return iRetStatus;
	}
	dwOriginalDataOffset += m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData; 
	if(!GetBuffer(dwOriginalDataOffset, dwPatchedCodeSize, dwPatchedCodeSize))
	{
		return iRetStatus;
	}
	if(!m_pMaxPEFile->WriteBuffer(m_pbyBuff, dwStartOfReplacement, dwPatchedCodeSize, dwPatchedCodeSize))
	{
		return iRetStatus;
	}

	// Set checksum
	m_pMaxPEFile->RepairOptionalHeader(0x16, 0, 0);

	// Remove virus code
	if(m_pMaxPEFile->ForceTruncate(dwOriginalDataOffset))
	{
		m_pMaxPEFile->CalculateLastSectionProperties();
		iRetStatus = REPAIR_SUCCESS;
	}	
	return iRetStatus;
}
