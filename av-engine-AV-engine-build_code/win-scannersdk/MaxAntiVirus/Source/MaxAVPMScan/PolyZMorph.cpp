/*======================================================================================
FILE				: PolyZMorph.cpp
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
NOTES				: This is detection module for malware Zmorph Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyZMorph.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyZMorph
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyZMorph::CPolyZMorph(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyZMorph
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyZMorph::~CPolyZMorph(void)
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
	Description		: Detection routine for different varients of Zmorph Family
--------------------------------------------------------------------------------------*/
int CPolyZMorph::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->m_stPEHeader.FileAlignment == 0)
	{
		m_pMaxPEFile->m_stPEHeader.FileAlignment = 0x200;
	}

	if(((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xC0000000)== 0xC0000000) && 
		m_wAEPSec == m_wNoOfSections - 1 &&
		(m_dwAEPMapped % m_pMaxPEFile->m_stPEHeader.FileAlignment) == 0 &&
		m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 0x10000)
	{
		m_pbyBuff = new BYTE[ZMORPH_BUFF_SIZE];
		if(!GetBuffer(m_dwAEPMapped, ZMORPH_BUFF_SIZE, ZMORPH_BUFF_SIZE))
		{
			return iRetStatus;
		}
		// Check signature for files that doesnt have encryption
		iRetStatus = CheckSignature();
		if(iRetStatus)
		{
			return iRetStatus;
		}	
				
		// Try to decrypt the code and then check for signature
		if(DecryptCode())
		{
			return CheckSignature();
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSignature
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function verifies the virus code by checking binary signature
--------------------------------------------------------------------------------------*/
int CPolyZMorph::CheckSignature()
{
	DWORD dwInstructionCnt = 0, dwMatchedInstr = 0, dwSig1Offset = 0, dwSig2Offset = 0;
	for(DWORD dwOffset = 0; dwOffset < 9; dwOffset++)
	{	
		if(m_pbyBuff[dwOffset] == 0x52 || m_pbyBuff[dwOffset] == 0x59 || m_pbyBuff[dwOffset] == 0x53 ||	m_pbyBuff[dwOffset] == 0x58 || 
			m_pbyBuff[dwOffset] == 0x57 || m_pbyBuff[dwOffset] == 0x41 || m_pbyBuff[dwOffset] == 0x5E || m_pbyBuff[dwOffset] == 0x4E)
		{
			dwMatchedInstr++;
		}			
		else if(m_pbyBuff[dwOffset] == 0x0F && m_pbyBuff[dwOffset + 1] == 0x82 && dwMatchedInstr == 8)
		{
			dwSig1Offset = (*(DWORD *)&m_pbyBuff[dwOffset + 2]) + dwOffset + 6;
			dwSig2Offset = dwOffset + 6;
			dwMatchedInstr++;
		}
		else if(m_pbyBuff[dwOffset] == 0x0F && m_pbyBuff[dwOffset + 1] == 0x83 && dwMatchedInstr == 8)
		{
			dwSig1Offset = dwOffset + 6;
			dwSig2Offset = (*(DWORD *)&m_pbyBuff[dwOffset + 2]) + dwOffset + 6;
			dwMatchedInstr++;
		}
		if(dwMatchedInstr == 9)
		{
			const BYTE bySig1[] = {0x55, 0x50, 0x56};
			const BYTE bySig2[] = {0x47, 0x0F};
			if(memcmp(&m_pbyBuff[dwSig1Offset], bySig1, sizeof(bySig1)) == 0 && 
				memcmp(&m_pbyBuff[dwSig2Offset + 2], bySig2, sizeof(bySig2)) == 0)		
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.ZMorph.5328"));
			
				// Second detection for AEP
				const BYTE bySignature[] = {0x9D, 0x4B, 0x31, 0x05, 0x68, 0x60, 0x9D, 0x4B, 0x61, 0xC3, 0x68};
				for(DWORD dwOffset = 0x200; dwOffset < ZMORPH_BUFF_SIZE - sizeof(bySignature); dwOffset++)
				{
					if(memcmp(&m_pbyBuff[dwOffset], bySignature, sizeof(bySignature)) == 0x00)
					{
						m_dwOriginalAEP = (*(DWORD *)&m_pbyBuff[dwOffset + 0x0B]) - m_dwImageBase;
						if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP , NULL))
						{
							return VIRUS_FILE_REPAIR;
						}
					}
				}
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptCode
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption routine for virus code
--------------------------------------------------------------------------------------*/
bool CPolyZMorph::DecryptCode()
{
	DWORD dwKeyGenData;
	if(!m_pMaxPEFile->ReadBuffer(&dwKeyGenData, m_dwAEPMapped + KEY_GEN_OFFSET, 4, 4))
	{
		return false;
	}

	BYTE	B1 = 0, B2 = 0, B3 = 0;
	DWORD	dwOffset = 0, dwLength = 0;
	t_disasm da = {0};
	DEC_TYPE eDecType = NO_DEC_FOUND;

	m_objMaxDisassem.InitializeData();	
	m_dwInstCount = 0;

	const DWORD ZMORPH_KEY1 = 0x58535952;
	const DWORD ZMORPH_KEY2 = 0x41535952;

	while(dwOffset < m_dwNoOfBytes)
	{
		if(m_dwInstCount > 0x100)
			break;

		B1 = m_pbyBuff[dwOffset];
		B2 = m_pbyBuff[dwOffset + 1];
		B3 = m_pbyBuff[dwOffset + 2];

		if((B1 == 0xC0 || B1 == 0xC1) && (B2 >= 0xF0 && B2 <= 0xF7) )
		{
			dwOffset+= 0x03;
			continue;
		}
		if((B1 == 0xD0 || B1 == 0xD1 || B1 == 0xD2 || B1 == 0xD3) && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}
		if((B1 == 0x0F && B2 == 0xAC && B3 == 0xDD) || (B1 == 0xF3 && B2 == 0x0F && B3 == 0xBD))
		{
			dwOffset += 0x04;
			continue;
		}
		dwLength = m_objMaxDisassem.Disasm((char* )&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		m_dwInstCount++;

		if(dwLength > 4 && (strstr(da.result, "PUSH") || strstr(da.result, "MOV") || strstr(da.result, "ADD") || strstr(da.result, "SUB") || strstr(da.result, "XOR")))
		{
			if(da.immconst == ZMORPH_KEY1 - dwKeyGenData || da.immconst == ZMORPH_KEY2 - dwKeyGenData)
			{
				eDecType = DEC_ADD;
			}
			if(da.immconst == dwKeyGenData - ZMORPH_KEY1 || da.immconst == dwKeyGenData - ZMORPH_KEY2)
			{
				eDecType = DEC_SUB;
			}
			if(da.immconst == (ZMORPH_KEY1 ^ dwKeyGenData) || da.immconst == (ZMORPH_KEY2 ^ dwKeyGenData))
			{
				eDecType = DEC_XOR;
			}
		}		
		if(eDecType)
		{
			memset(&m_pbyBuff[0], 0, ZMORPH_BUFF_SIZE);
			if(!GetBuffer(m_dwAEPMapped + KEY_GEN_OFFSET, ZMORPH_BUFF_SIZE, ZMORPH_BUFF_SIZE))
			{
				return false;
			}
			for(int i = 0; i < ZMORPH_BUFF_SIZE; i += 4)
			{
				if(eDecType == DEC_ADD)
				{
					*((DWORD *)&m_pbyBuff[i]) += da.immconst;
				}
				else if(eDecType == DEC_SUB)
				{
					*((DWORD *)&m_pbyBuff[i]) -= da.immconst;
				}
				else
				{
					*((DWORD *)&m_pbyBuff[i]) ^= da.immconst;
				}
			}
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of ZMorph Family
--------------------------------------------------------------------------------------*/
int CPolyZMorph::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;	
	m_pMaxPEFile->WriteAEP(m_dwOriginalAEP);
	if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}