/*======================================================================================
FILE				: PolyZperMorph.cpp
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
NOTES				: This is detection module for malware ZperMorph Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyZperMorph.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyZperMorph
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyZperMorph::CPolyZperMorph(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwOriAEP = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyZperMorph
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyZperMorph::~CPolyZperMorph(void)
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
	Description		: Detection routine for different varients of ZperMorph Family
--------------------------------------------------------------------------------------*/
int CPolyZperMorph::DetectVirus()
{

	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wAEPSec == m_wNoOfSections-1) && m_dwAEPUnmapped % m_pMaxPEFile->m_stPEHeader.FileAlignment == 0x00 &&
		m_pSectionHeader[m_wNoOfSections - 1].PointerToRelocations % 0x1000 == 0x1FF &&
		m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x11000)
	{
		m_pbyBuff = new  BYTE[ZPERMORPH_BUFF_SIZE + MAX_INSTRUCTION_LEN];	
		if(NULL == m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, ZPERMORPH_BUFF_SIZE + MAX_INSTRUCTION_LEN);

		if(GetBuffer(m_dwAEPMapped, ZPERMORPH_BUFF_SIZE, 0x10000))
		{
			if(CheckSignature())
			{
				_tcscpy_s(m_szVirusName,MAX_VIRUS_NAME,_T("Virus.W32.ZperMorph"));
				iRetStatus = VIRUS_FILE_REPAIR;
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
	Description		: This function verifies binary code in file buffer for detection
--------------------------------------------------------------------------------------*/
bool CPolyZperMorph::CheckSignature()
{	
	DWORD dwOffset = 0, dwJmpOffset = 0 ;
	bool bCheckInst = false, bCheckInst2 = false;
	m_dwInstCount = 0;

	for(; dwOffset < m_dwNoOfBytes - 5; dwOffset++)
	{
		if(*(DWORD*)&m_pbyBuff[dwOffset]== 0xE9)
		{
			bCheckInst2 = true;
			dwOffset++;
			break;
		}
	}
	while(dwOffset != m_dwNoOfBytes)
	{
		for(;m_pbyBuff[dwOffset] != 0xE9 && dwOffset < m_dwNoOfBytes - 5; dwOffset++);
		dwJmpOffset = (*(DWORD *)&m_pbyBuff[dwOffset + 1] + (m_dwAEPUnmapped + dwOffset) + 5) - m_dwAEPUnmapped;
		if((NEGATIVE_JUMP(dwJmpOffset)))
		{
			dwOffset++;
			continue;
		}
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwJmpOffset, NULL))		
		{
			if(GetInstruction(dwJmpOffset))
			{
				bCheckInst = true;
				dwOffset = dwJmpOffset + 2;
				break;
			}
			else if(bCheckInst2 && m_pbyBuff[dwJmpOffset] == 0xE8)
			{
				bCheckInst = true;
				m_dwInstCount++;
				break;
			}
		}
		dwOffset++;
	}

	while(bCheckInst)
	{
		if(dwOffset > m_dwNoOfBytes)
		{
			return false;
		}
		else if(m_pbyBuff[dwOffset] == 0xE9)//JMP
		{
			dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] +  (dwOffset + 5);
		}
		else if((*(WORD *)&m_pbyBuff[dwOffset]== 0x850f) && m_dwInstCount == 0)//JNE
		{
			dwOffset += 6;
			m_dwInstCount++;
		}		
		else if((*(WORD *)&m_pbyBuff[dwOffset]== 0x840f)&& m_dwInstCount == 0)//JE
		{
			dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 2] +  (dwOffset + 5) + 1;
			m_dwInstCount++;
		}		
		else if(m_pbyBuff[dwOffset] == 0xE8 && m_dwInstCount == 1)
		{
			dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] +  (dwOffset + 5) ;
			m_dwInstCount++;
		}		
		else if(m_pbyBuff[dwOffset] == 0xE8 && m_dwInstCount == 2)
		{
			dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] +  (dwOffset + 5) ;
			m_dwInstCount++;
		}		
		else if(m_pbyBuff[dwOffset] == 0x68 && m_dwInstCount == 3)
		{
			m_dwOriAEP = *(DWORD *)&m_pbyBuff[dwOffset + 1] - m_dwImageBase ;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriAEP, NULL))	
			{
				return true;
			}
			break;
		}
		else
		{
			break;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetInstruction
	In Parameters	: DWORD dwOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function finds the key instruction of virus code
--------------------------------------------------------------------------------------*/
bool CPolyZperMorph::GetInstruction(DWORD dwOffset)
{
	t_disasm da = {0};

	int iLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
	if((strstr(da.result,"SUB E")) || (strstr(da.result,"XOR E")))
	{
		char szTempReg[MAX_PATH] = {0};
		sprintf_s(szTempReg, MAX_PATH, "%s",da.result);

		char *ptr = strchr(szTempReg,'E');
		char *ptr1 = strchr(ptr, ',');
		ptr1++;
		if(memcmp(ptr, ptr1, 3)== 0)
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
	Description		: Repair routine for different varients of ZperMorph Family
--------------------------------------------------------------------------------------*/
int CPolyZperMorph::CleanVirus()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriAEP))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped, true))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}