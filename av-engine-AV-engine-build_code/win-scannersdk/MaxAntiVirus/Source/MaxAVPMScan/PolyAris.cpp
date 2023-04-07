/*======================================================================================
FILE				: PolyAris.cpp
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
NOTES				: This is detection module for malware Aris Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyAris.h"
#include "PolymorphicVirus.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyAris
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAris::CPolyAris(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAris
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyAris::~CPolyAris(void)
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
	Description		: Detection routine for different varients of Aris Family
--------------------------------------------------------------------------------------*/
int CPolyAris::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections - 1 && m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 0xA000 &&
		(m_pSectionHeader[m_wAEPSec].Characteristics & 0x40000040) == 0x40000040 &&
		m_dwAEPMapped != m_pSectionHeader[m_wAEPSec].PointerToRawData)
	{
		if(GetArisParameters())
		{
			WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
			iRetStatus = DetectAris();
			SetEvent(CPolymorphicVirus::m_hEvent);
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Aris Family using disassembly
--------------------------------------------------------------------------------------*/
int CPolyAris::DetectAris()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	CEmulate objEmulate(m_pMaxPEFile);
	if(!objEmulate.IntializeProcess())
	{
		return iRetStatus;
	}
	char szBreakPoint[1024];
	sprintf_s(szBreakPoint, 1024, "__isinstruction('push')");
	objEmulate.SetBreakPoint(szBreakPoint);
	memset(szBreakPoint, 0, 1024);
	sprintf_s(szBreakPoint, 1024, "__isinstruction('jmp esp')");
	objEmulate.SetBreakPoint(szBreakPoint);
	objEmulate.SetNoOfIteration(2800);
	const int ARIS_DEC_BUFF_SIZE = 0x1200;
	m_pbyBuff = new BYTE[ARIS_DEC_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, ARIS_DEC_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	m_dwBufferCnt = ARIS_DEC_BUFF_SIZE;
	while(m_dwBufferCnt > 0)
	{
		if(7 != objEmulate.EmulateFile())
		{
			return iRetStatus;
		}
		char szInstruction[1024] = {0};                 
		objEmulate.GetInstruction(szInstruction);     
		DWORD dwLen = objEmulate.GetInstructionLength();
		if(strstr(szInstruction, "jmp esp") && dwLen == 2)
		{
			for(DWORD dwCnt = m_dwBufferCnt; dwCnt < (m_dwBufferCnt + 0x20); dwCnt++)
			{
				if(m_pbyBuff[dwCnt] == 0x83 && m_pbyBuff[dwCnt + 1] == 0xEC && m_pbyBuff[dwCnt + 2] == 0x08)
				{
					m_dwBufferCnt = dwCnt;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Aris"));
					iRetStatus = VIRUS_FILE_REPAIR;
					return iRetStatus;
				}
			}
		}
		else if(!strstr(szInstruction, "pushad") && strstr(szInstruction, "push") && dwLen >= 1)
		{
			*(DWORD *)&m_pbyBuff[m_dwBufferCnt] = objEmulate.GetDestinationOprand();
			if(objEmulate.GetInstructionLength() == 0x01)
			{
				objEmulate.SetEip(objEmulate.GetEip() + 0x01);
			}
			m_dwBufferCnt = m_dwBufferCnt - 4;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetArisParameters
	In Parameters	: 
	Out Parameters	: true if success else false 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Generates requied information using disassembly
--------------------------------------------------------------------------------------*/
bool CPolyAris::GetArisParameters()
{
	const int ARIS_BUFF_SIZE = 0x30;
	BYTE *byBuff = new BYTE[ARIS_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!byBuff)
	{
		return false;
	}
	memset(byBuff, 0, ARIS_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(m_pMaxPEFile->ReadBuffer(byBuff, m_dwAEPMapped, ARIS_BUFF_SIZE, ARIS_BUFF_SIZE))
	{
		if(byBuff[0] == 0x60)
		{
			t_disasm da;
			DWORD dwLength = 0x00, dwOffset = 0x00, dwCounter = 0x00, dwOperationFlag = 0;
			m_dwInstCount = 0;
			while(dwOffset < ARIS_BUFF_SIZE && m_dwInstCount <= 0x0D)
			{		
				dwLength = m_objMaxDisassem.Disasm((char *)&byBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (ARIS_BUFF_SIZE - dwOffset))
				{
					break;
				}
				m_dwInstCount++;
				
				if(dwLength == 0x05 && strstr(da.result, "MOV "))
				{
					dwCounter = m_dwInstCount;
				}
				else if((dwLength == 0x05 || dwLength == 0x06) && strstr(da.result, "SUB ") && dwCounter == (m_dwInstCount - 1))
				{
					dwOperationFlag++;
					dwCounter = m_dwInstCount;
				}
				else if((dwLength == 0x05 || dwLength == 0x06) && strstr(da.result, "ADD ") && dwCounter == (m_dwInstCount - 1))
				{
					dwOperationFlag++;
					dwCounter = m_dwInstCount;
				}
				else if(dwLength == 0x01 && strstr(da.result, "PUSH ") && dwCounter == (m_dwInstCount - 1) && dwOperationFlag >= 1)
				{
					if(byBuff)
					{
						delete []byBuff;
						byBuff = NULL;
					}
					return true;
				}
				dwOffset += dwLength;
			}
		}
	}
	if(byBuff)
	{
		delete []byBuff;
		byBuff = NULL;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of Aris Family
--------------------------------------------------------------------------------------*/
int CPolyAris::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	DWORD dwKey = 0;
	for(DWORD dwCnt = m_dwBufferCnt; dwCnt < (m_dwBufferCnt + 0x60); dwCnt++)
	{
		if(m_pbyBuff[dwCnt] == 0xEB && m_pbyBuff[dwCnt + 1] == 0x21 && m_pbyBuff[dwCnt + 2] == 0xB8)
		{
			dwKey = *(DWORD *)&m_pbyBuff[dwCnt + 3];		
		}
		if(m_pbyBuff[dwCnt] == 0xE2 && m_pbyBuff[dwCnt + 1] == 0xF9 && m_pbyBuff[dwCnt + 2] == 0xC3)
		{
			m_dwBufferCnt = dwCnt + 3;
			break;
		}
	}
	for (DWORD dwCnt = m_dwBufferCnt; dwCnt < (m_dwBufferCnt + 0x220); )
	{
		*(DWORD *)&m_pbyBuff[dwCnt] ^= dwKey; 
		dwCnt += 4;
	}
	for (DWORD dwCnt = m_dwBufferCnt; dwCnt < (m_dwBufferCnt + 0x220); dwCnt++)
	{
		if(m_pbyBuff[dwCnt] == 0x61 && m_pbyBuff[dwCnt + 1] == 0x68 && m_pbyBuff[dwCnt + 6] == 0xC3)
		{
			DWORD dwAEPMapped = 0;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(((*(DWORD *)&m_pbyBuff[dwCnt + 2]) - m_dwImageBase), &dwAEPMapped))
			{
				if(m_pMaxPEFile->WriteAEP((*(DWORD *)&m_pbyBuff[dwCnt + 2]) - m_dwImageBase))
				{
					if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
					{
						iRetStatus = REPAIR_SUCCESS;
						break;
					}
				}
			}
		}
	}
	return iRetStatus;
}