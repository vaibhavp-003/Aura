/*======================================================================================
FILE				: PolyZperm.cpp
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
NOTES				: This is detection module for malware Zperm Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyZperm.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyZperm
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyZperm::CPolyZperm(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwJumpOffset = m_dwAEPUnmapped;
	m_dwOriAEP = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyZperm
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyZperm::~CPolyZperm(void)
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
	Description		: Detection routine for different varients of Zperm Family
--------------------------------------------------------------------------------------*/
int CPolyZperm::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == m_wNoOfSections - 1 && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > 0x10000 &&
		m_pMaxPEFile->m_stPEHeader.CheckSum == 0X00 && m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x5A)
	{
		m_pbyBuff = new BYTE[ZPERM_BUFF_SIZE + MAX_INSTRUCTION_LEN];	  
		if(NULL == m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, ZPERM_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		
		if(GetBuffer(m_dwAEPMapped, ZPERM_BUFF_SIZE, ZPERM_BUFF_SIZE))
		{
			if(m_pbyBuff[0]== 0xE9 || m_pbyBuff[0]== 0x60 || m_pbyBuff[0]== 0x90 )
			{
				return CheckSignature();
			}
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
	Description		: Veriifies the binary signature for detection of virus 
--------------------------------------------------------------------------------------*/
int CPolyZperm :: CheckSignature()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	DWORD dwLength = 0, dwOffset = 0, dwJumpOffset = 0, dwNOPCount = 0;
	t_disasm da = {0x00};
	m_dwInstCount = 0; 

	while(dwOffset < m_dwNoOfBytes)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > m_dwNoOfBytes - dwOffset)
		{
			return iRetStatus;
		}

		if(dwLength == 0x01 && m_dwInstCount == 0 &&  strstr(da.result, "PUSHAD"))
		{
			m_dwInstCount++;
		}
		else if(dwLength == 0x05 && m_dwInstCount == 1 && strstr(da.result, "MOV EBP"))
		{
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset((da.immconst - m_dwImageBase),&m_dwVirusOffset))
			{
				break;
			}
			m_dwInstCount++;
		}
		else if(dwLength == 0x05 && (m_pbyBuff[dwOffset]== 0xE9))
		{
			if(GetBufferFromJumpOffset(dwOffset))
			{
				continue;
			}
		}
		else if(dwLength == 0x05 && m_dwInstCount == 2 && strstr(da.result, "CALL"))
		{
			m_dwInstCount++;
			if(dwNOPCount > 0x15) //Zperm.B2
			{
				if(GetBufferFromJumpOffset(dwOffset))
				{
					continue;
				}
			}
		}
		else if(dwLength == 0x05 && m_dwInstCount == 3 && strstr(da.result, "CALL"))
		{
			m_dwInstCount++;			
			if(GetBufferFromJumpOffset(dwOffset))
			{
				continue;
			}
		}
		else if(dwLength == 5 && m_dwInstCount == 4 && strstr(da.result,"PUSH"))
		{
			m_dwOriAEP = da.immconst - m_dwImageBase;
			
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Zperm.A"));
			return  VIRUS_FILE_REPAIR;
		}
		else if(dwLength == 5 && m_dwInstCount == 3 && strstr(da.result,"MOV EBX") && da.immconst == 0xBFF70000)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Zperm.B"));          
			return VIRUS_FILE_DELETE;
		}
		else if(dwLength == 1 && m_pbyBuff[dwOffset]== 0x90)	// Zperm.B
		{
			dwNOPCount++;
		}
		dwOffset += dwLength;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetBufferFromJumpOffset
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Retreives buffer by following JMP instruction
--------------------------------------------------------------------------------------*/
bool CPolyZperm::GetBufferFromJumpOffset(DWORD &dwOffset)
{
	DWORD dwJumpOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1];
	m_dwJumpOffset += dwJumpOffset + dwOffset  + 5; 
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwJumpOffset, &dwJumpOffset))
	{   
		if(GetBuffer(dwJumpOffset, ZPERM_BUFF_SIZE, ZPERM_BUFF_SIZE))
		{
			dwOffset = 0;
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
	Description		: Repair routine for different varients of Zperm Family
--------------------------------------------------------------------------------------*/
int CPolyZperm::CleanVirus()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriAEP))
	{
		if(m_pMaxPEFile->RepairOptionalHeader(2, 0, 0))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwVirusOffset, true))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}