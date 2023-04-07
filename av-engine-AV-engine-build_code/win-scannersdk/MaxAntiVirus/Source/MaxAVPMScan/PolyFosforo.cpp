/*======================================================================================
FILE				: PolyFosforo.cpp
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
NOTES				: This is detection module for malware Fosforo Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyFosforo.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyFosforo
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyFosforo::CPolyFosforo(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwOriginaBytesOffset = 0;
	m_dwVirusCodeOffset = 0;
	m_dwPatchOffset = 0;
	m_bNoPatch = false;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyFosforo
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detructor for this class
--------------------------------------------------------------------------------------*/
CPolyFosforo::~CPolyFosforo(void)
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
	Description		: Detection routine for different varients of Fosforo Family
--------------------------------------------------------------------------------------*/
int CPolyFosforo ::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xC0000000) == 0xC0000000) && (m_pMaxPEFile->m_stPEHeader.e_csum == 0x55))
	{
		m_pbyBuff = new BYTE[FOSFORO_BUFF_SIZE + MAX_INSTRUCTION_LEN];	  
		if(NULL == m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, FOSFORO_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	
		if(GetBuffer(m_pSectionHeader[0].PointerToRawData, FOSFORO_BUFF_SIZE , FOSFORO_BUFF_SIZE))
		{
			DWORD dwOffset = 0;
			for(; (*(WORD *)&m_pbyBuff[dwOffset]) != 0x15FF && dwOffset < m_dwNoOfBytes; dwOffset++);
			
			if((*(WORD *)&m_pbyBuff[dwOffset]) == 0x15FF)
			{		
				m_dwPatchOffset = dwOffset + 2;
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[dwOffset + 2] - m_dwImageBase), &m_dwVirusCodeOffset))
				{
					if(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData < m_dwVirusCodeOffset)
					{
					 memset(m_pbyBuff, 0, FOSFORO_BUFF_SIZE + MAX_INSTRUCTION_LEN);
					 if(GetBuffer(m_dwVirusCodeOffset, FOSFORO_BUFF_SIZE, 0x1500))
					 {
						//PUSHAD & POPAD instr. disassemble from if this instr. found
						for(dwOffset = 0 ; (*(WORD *)&m_pbyBuff[dwOffset]) != 0x609C && dwOffset < m_dwNoOfBytes; dwOffset++);
						
						if((*(WORD *)&m_pbyBuff[dwOffset]) == 0x609C)
						{
							if(CheckSignature(dwOffset))
							{
								iRetStatus = VIRUS_FILE_REPAIR;
							}
						}
					 }
					}
				 
				 else //case for samples not having pached kernel call
			      {
				    memset(m_pbyBuff, 0, FOSFORO_BUFF_SIZE + MAX_INSTRUCTION_LEN);
				   if(GetBuffer((m_pMaxPEFile->m_dwFileSize - 0x1B00) , FOSFORO_BUFF_SIZE, 0x1B00))
				    {
					for(dwOffset = 0 ; m_pbyBuff[dwOffset] == 0x00 && dwOffset < m_dwNoOfBytes; dwOffset++);
					m_dwVirusCodeOffset = (m_pMaxPEFile->m_dwFileSize - 0x1B00) + dwOffset;

					//PUSHAD & POPAD instr. disassemble from if this instr. found
					for(dwOffset = 0 ; (*(WORD *)&m_pbyBuff[dwOffset]) != 0x609C && dwOffset < m_dwNoOfBytes; dwOffset++);
						
						m_bNoPatch = true;
						if((*(WORD *)&m_pbyBuff[dwOffset]) == 0x609C)
						{
							if(CheckSignature(dwOffset))
							{
								iRetStatus = VIRUS_FILE_REPAIR;
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
	Function		: CheckSignature
	In Parameters	: DWORD dwOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function search the binary signature in buffer
--------------------------------------------------------------------------------------*/
bool CPolyFosforo::CheckSignature(DWORD dwOffset)
{
   DWORD dwLength = 0, dwWeight = 0, dwKey = 0, dwWt = 0, dwCountFlag = 0;
	BYTE B1 = 0, B2 = 0, B3 = 0;
	t_disasm da = {0};

	while(dwOffset < m_dwNoOfBytes)
	{
		B1 = m_pbyBuff[dwOffset];
		B2 = m_pbyBuff[dwOffset + 1];

		//skip instr. b'coz it unable 2 disassemble
		if(B1 == 0xDE && B2 == 0xBF)
		{
			dwOffset += 6;
			continue;
		}
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			
		if(dwLength > (m_dwNoOfBytes - dwOffset))
		{
			return false;
		}

		//condition for fosforo.aa
		if(dwLength == 2 && m_pbyBuff[dwOffset] == 0xEB && strstr(da.result,"JMP SHORT"))		
		{
			dwOffset += m_pbyBuff[dwOffset + 1] + dwLength;
			continue;
		}
		//decr. start offset
		else if(dwLength == 5 && strstr(da.result,"MOV EDI"))
		{
			m_pMaxPEFile->Rva2FileOffset((da.immconst - m_dwImageBase), &m_dwOriginaBytesOffset);
			dwWt = ++dwWeight;
		}
		else if(dwLength == 5 && dwWeight == dwWt && strstr(da.result,"MOV ECX,"))
		{
			if((da.immconst == 0x497) || (da.immconst == 0x49B) || (da.immconst == 0x4BA) || (da.immconst == 0x4E8) ||
				(da.immconst == 0x4CF) || (da.immconst == 0x46B))
			{
				dwCountFlag = da.immconst;
				dwWeight++;
			}
		}
		else if(dwLength == 2 && dwWeight == dwWt + 1 && strstr(da.result,"MOV EAX,[EDI]"))
		{
			dwWeight++;
		}
		else if(dwLength == 5 && dwWeight == dwWt + 2 && strstr(da.result,"XOR EAX"))
		{
			dwKey = da.immconst;
			dwWeight++;
			break;
		}
		dwOffset += dwLength;
	}

	if(dwWeight != dwWt + 3)
	{
		return false;
	}

	DWORD dwVirSrtingOff = 0, dwVirSrtingOff_1 = 0;

	
	if(dwCountFlag == 0x497 )//fosforo.a
	{
		dwVirSrtingOff = 0x1038; 
	}
	else if(dwCountFlag == 0x49B)//fosforo.a
	{
		dwVirSrtingOff = 0x1048;
	}
	else if(dwCountFlag == 0x4E8)//fosforo.b
	{
		dwVirSrtingOff = 0x117C;
	}
	else if(dwCountFlag == 0x4CF)//fosforo.c
	{
      dwVirSrtingOff = 0x784;
	  dwVirSrtingOff_1 = 0x1138;
	}
	else if(dwCountFlag == 0x46B)//fosforo.d
	{
      dwVirSrtingOff = 0x6C0;
	  dwVirSrtingOff_1 = 0xFA8;
	}
	else                           //fosforo.aa
	{
		dwVirSrtingOff = 0x750;
		dwVirSrtingOff_1 = 0x10E0;
	}

	
	memset(m_pbyBuff, 0, FOSFORO_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(GetBuffer(m_dwOriginaBytesOffset, FOSFORO_BUFF_SIZE, 0x1500))
	{
	for(DWORD dwCount = 0; dwCount < 0x25; dwCount += sizeof(DWORD))
	{
		// To get original kernell call which is @ 0x1E bytes from DecOffset
		*(DWORD *)&m_pbyBuff[ dwCount] ^= dwKey;
		*(DWORD *)&m_pbyBuff[dwVirSrtingOff + dwCount] ^= dwKey;
		if(dwVirSrtingOff_1 != 0)
		{
			*(DWORD *)&m_pbyBuff[dwVirSrtingOff_1 + dwCount] ^= dwKey;
		}
	}
	}

	const BYTE bySignature[] = {0x41, 0x59, 0x41, 0x4B, 0x46, 0x30, 0x53, 0x46, 0x30, 0x52, 0x30, 0x20, 0x76,
		0x69, 0x72, 0x75, 0x73, 0x20, 0x62, 0x79, 0x20, 0x4E, 0x2E, 0x42, 0x2E, 0x4B};  
	const BYTE bySignature2[] = {0x41, 0x59, 0x41, 0x4B};
	
	if(dwCountFlag  == 0x497 )
	{
		if(memcmp(&m_pbyBuff[dwVirSrtingOff + 4],bySignature, sizeof(bySignature)) == 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Fosforo.A"));
			m_dwOriginaBytesOffset = 0x1E;
			return true;
		}
	}
	else if(dwCountFlag == 0x49B)
	{
		if(memcmp(&m_pbyBuff[dwVirSrtingOff + 2],bySignature, sizeof(bySignature)) == 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Fosforo.A"));
			m_dwOriginaBytesOffset = 0x1E;
			return true;
		}
	}
	else if(dwCountFlag == 0x4E8)
	{
		if(memcmp(&m_pbyBuff[dwVirSrtingOff + 3],bySignature, sizeof(bySignature)) == 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Fosforo.B"));
			m_dwOriginaBytesOffset =  0x23;
			return true;
		}
	}
	else if(dwCountFlag == 0x4CF)
	{
		const BYTE bySignature3[] = {0x4B, 0x43, 0x55, 0x46, 0xE8, 0x01, 0x01, 0x00, 0x00, 0x57, 0x50, 0xC7, 0x85, 
			0xD7, 0x2F, 0x40, 0x00, 0x4F, 0x4D, 0x45, 0x4D};
		
		if(memcmp(&m_pbyBuff[dwVirSrtingOff + 3],bySignature3, sizeof(bySignature3)) == 0)
		{
			if(memcmp(&m_pbyBuff[dwVirSrtingOff_1 + 2],bySignature2, sizeof(bySignature2)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Fosforo.C"));
				m_dwOriginaBytesOffset = 0x22;
				return true;
			}
		}

	}
	else if(dwCountFlag == 0x46B)
	{
		const BYTE bySignature3[] ={0x4B, 0X43, 0x55, 0x46, 0xE8, 0xDD, 0x00, 0x00, 0x00, 0x57, 0x50, 0xC7, 0x85, 
			0x48, 0x2E, 0x40, 0x00, 0x4F, 0x4D, 0x45, 0x4D};
		
		if(memcmp(&m_pbyBuff[dwVirSrtingOff + 2],bySignature3, sizeof(bySignature3)) == 0)
		{
			if(memcmp(&m_pbyBuff[dwVirSrtingOff_1 + 3],bySignature2, sizeof(bySignature2)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Fosforo.D"));
				m_dwOriginaBytesOffset = 0x1E;
				return true;
			}
		}

	}
	else    
	{
		const BYTE bySignature1[] = {0x4B, 0x43, 0x55, 0x46, 0xE8, 0xE1, 0x00, 0x00, 0x00, 0x57, 0x50, 0xC7, 0x85, 
			0x82, 0x2F, 0x40, 0x00, 0x4F, 0x4D, 0x45, 0x4D, 0xFF};

		if(memcmp(&m_pbyBuff[dwVirSrtingOff + 2],bySignature1, sizeof(bySignature1)) == 0)
		{
			if(memcmp(&m_pbyBuff[dwVirSrtingOff_1 + 5],bySignature2, sizeof(bySignature2)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Fosforo.AA"));
				m_dwOriginaBytesOffset = 0x22;
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
	Description		: Repair routine for different varients of Fosforo Family
--------------------------------------------------------------------------------------*/
int CPolyFosforo::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;

     if(m_bNoPatch == false)
	 {
	  m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwOriginaBytesOffset], m_pSectionHeader[0].PointerToRawData + m_dwPatchOffset, sizeof(DWORD), sizeof(DWORD));
	 }
		if(m_pMaxPEFile->TruncateFileWithFileAlignment(m_dwVirusCodeOffset))
		{
			if(m_pMaxPEFile->FillWithZeros(0x12, sizeof(WORD)))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
	
	return iRetStatus;
}