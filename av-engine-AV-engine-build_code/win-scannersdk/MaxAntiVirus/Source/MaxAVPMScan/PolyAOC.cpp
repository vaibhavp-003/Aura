/*======================================================================================
FILE				: PolyAOC.cpp
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
NOTES				: This is detection module for malwares AOC Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyAOC.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyAOC
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAOC::CPolyAOC(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwKey1 = m_dwKey2 = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAOC
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyAOC::~CPolyAOC(void)
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
	Description		: Detection routine for different varients of AOC Family
--------------------------------------------------------------------------------------*/
int CPolyAOC::DetectVirus()//for variant 3676.A & 3833 & 3649.A
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == m_wNoOfSections - 1 && 
		(m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000020) == 0xE0000020 &&
		(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".ntext", 6)== 0))
	{
		m_pbyBuff = new BYTE[AOC_BUFF_SIZE + MAX_INSTRUCTION_LEN];	  
		if(NULL == m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, AOC_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, AOC_BUFF_SIZE, 0xFF0))
		{
			if(m_pbyBuff[0] == 0xE8 && ((*(DWORD *)&m_pbyBuff[1] == 0xE57)||(*(DWORD *)&m_pbyBuff[1] == 0xEF4))||(*(DWORD *)&m_pbyBuff[1] == 0xE3C))
			{
				DWORD dwJmpOffset = (*(DWORD *)&m_pbyBuff[1]) + 5;
				if(dwJmpOffset < m_dwNoOfBytes)
				{
					if(CheckSignature(dwJmpOffset))
					{
						iRetStatus = VIRUS_FILE_REPAIR;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.AOC"));
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSignature
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Dis-assembles and checks the instruction parameter
--------------------------------------------------------------------------------------*/
bool CPolyAOC ::CheckSignature(DWORD dwOffset)
{
	DWORD dwLength = 0, dwInstrCount = 0, dwWeight = 0;
	BYTE B1 = 0, B2 = 0, B3 = 0;
	t_disasm da = {0x00};

	while(dwOffset < m_dwNoOfBytes)
	{
		B1 = m_pbyBuff[dwOffset];
		if(dwInstrCount > 100)
		{
			break;
		}
		
		if(0 == m_pbyBuff[dwOffset])
		{
			dwOffset++;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > m_dwNoOfBytes - dwOffset)
		{
			break;
		}
		dwInstrCount++;

		if(dwLength == 0x06 && dwWeight == 0 && strstr(da.result, "MOV EBP,[EBP+4]"))
		{
			dwWeight++;			
		}
		else if((B1 == 0x51 || B1 == 0x57 || B1 == 0x53) && dwLength == 1  && dwWeight == 1 && strstr(da.result,"PUSH"))
		{
			dwWeight++;
		}
		else if(dwLength == 0x05  && dwWeight == 2 && strstr(da.result,"MOV E"))
		{		
			m_dwKey1 = *(DWORD *)&m_pbyBuff[dwOffset + 1];
			while(dwOffset < m_dwNoOfBytes)
			{
				dwOffset += dwLength;
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
				if((dwLength == 0x05 || dwLength == 0x06) && strstr(da.result,"ADD E"))
				{
					m_dwKey1 += *(DWORD *)&m_pbyBuff[dwOffset + dwLength - 4];
				}
				else 
				{
					break;
				}
			}			
			dwWeight++;
		}

		if(dwLength == 0x05  && dwWeight == 3 && strstr(da.result,"MOV E"))
		{		
			m_dwKey2 = *(DWORD *)&m_pbyBuff[dwOffset + 1];
			while(dwOffset < m_dwNoOfBytes)
			{
				dwOffset += dwLength;
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
				if((dwLength == 0x05 || dwLength == 0x06) && strstr(da.result,"ADD E"))
				{
					m_dwKey2 += *(DWORD *)&m_pbyBuff[dwOffset + dwLength - 4];
				}
				else 
				{
					break;
				}
			}			
			dwWeight++;
		}

		else if(dwLength == 0x03 && dwWeight == 4 && strstr(da.result,"XOR [EBP],E"))
		{
			dwWeight++;
		}
		else if((dwLength == 0x05 || dwLength == 0x06) && dwWeight == 5 && strstr(da.result, "ADD E") && da.immconst == 0x1020304)
		{
			dwWeight++;
		}
		else if(dwLength == 0x03 && dwWeight == 6 && strstr(da.result,"XOR [EBP],E"))
		{
			dwWeight++;
		}
		else if((dwLength == 0x05 || dwLength == 0x06) && dwWeight == 7 && strstr(da.result, "SUB E") && da.immconst == 0x1020304)
		{
			return true;
		}
		else if(dwLength == 2 && m_pbyBuff[dwOffset] == 0xEB && strstr(da.result,"JMP SHORT"))		
		{
			dwOffset += m_pbyBuff[dwOffset + 1] + dwLength;
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
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of AOC Family
--------------------------------------------------------------------------------------*/
int CPolyAOC::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;

	int iOffset = 5;
	for(int iCnt = 0x1DE; iCnt > 0; iCnt--)
	{
		*(DWORD *)&m_pbyBuff[iOffset] ^= m_dwKey1;
		m_dwKey1 += 0x1020304;
		iOffset += 4;
		
		*(DWORD *)&m_pbyBuff[iOffset] ^= m_dwKey2;
		m_dwKey2 -= 0x1020304;
		iOffset += 4;
	}
	
	iOffset = 0x26;
	
	for(m_iKeyOffset = 0 ; m_iKeyOffset < iOffset && *(WORD *)&m_pbyBuff[m_iKeyOffset] != 0x3680; m_iKeyOffset++);
	
	if(m_iKeyOffset == iOffset)
	{
		return iRetStatus;
	}
	
	for(; iOffset < 0x26 + 0xED0; iOffset++)
	{
		m_pbyBuff[iOffset] ^=  m_pbyBuff[m_iKeyOffset + 2];
	}

	if(DecryptionBumbulby())
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped, true))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}

bool CPolyAOC::DecryptionBumbulby()
{
	DWORD dwJmpOffset = (*(DWORD *)&m_pbyBuff[m_iKeyOffset + 0x9]) + 5 + (m_iKeyOffset + 0x9);
	DWORD dwOffset = (*(DWORD *)&m_pbyBuff[dwJmpOffset]);

	
	BYTE bAH, bAL, bCH, bCL, bDH, bDL;
	WORD wAX, wBX, wCarry = 0, wCarry1 = 0;   
	DWORD dwEAX, dwEBX = 0, dwECX = 0xFFFFFFFF, dwEDX = 0xFFFF00FF, dwOff = 0x2E5;

	for(DWORD dwCnt = 0; dwCnt < 0xEA; dwCnt++, dwOffset++)
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

	DWORD dwAEPOffset = m_iKeyOffset + 0XE;
	for(int iCnt = 0; iCnt < 4; iCnt++)
	{
		m_pbyBuff[dwAEPOffset + iCnt] += bAH;
		m_pbyBuff[dwAEPOffset + iCnt] ^= bAL;
		m_pbyBuff[dwAEPOffset + iCnt] -= bAH;		
	}

	DWORD dwOriginalAEP = *(DWORD *)&m_pbyBuff[dwAEPOffset] - m_dwImageBase;
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOriginalAEP, NULL))
	{
		if(m_pMaxPEFile->WriteAEP(dwOriginalAEP))
		{
			return true;
		}
	}
	return false;
}


