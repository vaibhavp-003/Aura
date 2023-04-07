/*======================================================================================
FILE				: PolyPolyk.cpp
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
NOTES				: This is detection module for malware PolyK Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyPolyk.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyPolyk
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyPolyk::CPolyPolyk(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_bXorKey = m_bAddKey = m_bUpXorKey = 0;
	m_wCnt1 = m_wOP = m_wOP1 = m_wOP2 = 0; 
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyPolyk
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyPolyk::~CPolyPolyk(void)
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
	Description		: Detection routine for different varients of PolyK Family
--------------------------------------------------------------------------------------*/
int CPolyPolyk::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wAEPSec == 0 || m_wAEPSec == 1)&& (m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wNoOfSections -1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections -1].PointerToRawData) >= 0x13E6 ||
		m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x1600))
	{
		BYTE POLYK_SIG[] = {0x60,0xE8,0x00,0x00,0x00,0x00,0x5D,0x83,0xED,0x06,0x55,0xFC,0x81,0xEC,0x64,0x02,0x00,0x00,0x8B,0xF5,0x8B,0xFC,0xB9,0x63,0x02,0x00,0x00,0xF3,0xA4,0x8B,0xEC,0x8D,0x45,0x24,0xFF,0xE0,0x8D,0x75,0x3F,0x8B,0xFE,0xB9,0x24,0x02,0x00,0x00,0xB3};

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int BUFF_SIZE = 0x1000;
		m_pbyBuff = new BYTE[BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped, 0x40, sizeof(POLYK_SIG)))
		{
			if(memcmp(&m_pbyBuff[0x00], POLYK_SIG, sizeof(POLYK_SIG)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Polyk.A"));
				
				if(m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x1 && 
					m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x1600 &&
					m_dwAEPUnmapped == 0x1000 && m_dwAEPUnmapped == m_pSectionHeader[m_wAEPSec].VirtualAddress)
				{
					return VIRUS_FILE_DELETE;
				}
				
				m_wCnt1 = 0x224;
				if(!SetOperatn(0x29))
				{
					return VIRUS_FILE_DELETE;
				}
				if(!FoundKey( m_dwAEPMapped + 0x1F1, 0x1B1, 0x14, 1))
				{ 
					return iRetStatus;
				}

				m_wCnt1 = 0x117F;
				if(!SetOperatn(0x0))
				{
					return VIRUS_FILE_DELETE;
				}
				if(!FoundKey(((m_pMaxPEFile->m_dwFileSize - 0x13E6) + 0xF12), 0xF11, 0x14, 1))
				{
					return iRetStatus;
				}
				m_wCnt1 = 0x263;
				if(!SetOperatn(0x0))
				{
					return VIRUS_FILE_DELETE;
				}
				if(!FoundKey(((m_pMaxPEFile->m_dwFileSize - 0x13E6) + 0x117F), 0x263, 0x263, 0))
				{
					return iRetStatus;
				}
				return VIRUS_FILE_REPAIR;
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
	Description		: Repair routine for different varients of PolyK Family
--------------------------------------------------------------------------------------*/
int CPolyPolyk::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwAEPMapped, 0x263))
	{
		if(m_pMaxPEFile->TruncateFile(m_pMaxPEFile->m_dwFileSize - 0x13E6, true))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: SetOperatn
	In Parameters	: DWORD dwStartOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: creates a set of operation (CPU instructions)
--------------------------------------------------------------------------------------*/
bool CPolyPolyk::SetOperatn(DWORD dwStartOffset)
{
	DWORD	dwLength = 0, dwOffset = dwStartOffset;
	t_disasm da = {0};
	m_dwInstCount = 0;
	
	m_wOP = 0, m_wOP1 = 0, m_wOP2 = 0, m_wOP3 = 0;
	
	while(dwOffset < dwStartOffset + 0x14 && m_dwInstCount < 0x5)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			

		if(m_dwInstCount == 0x00 && dwLength == 2 && strstr(da.result,"MOV BL"))
		{
			m_bXorKey = LOBYTE(da.immconst);
			m_dwInstCount++;
		}
		else if(m_dwInstCount == 0x01 && dwLength == 3 && strstr(da.result,"ADD BL"))
		{  
			m_bAddKey = LOBYTE(da.immconst);
			m_wOP = 1;
			m_dwInstCount++;
		}
		else if(m_dwInstCount == 0x01 && dwLength == 3 && strstr(da.result,"SUB BL"))
		{
			m_bAddKey = LOBYTE(da.immconst);
			m_wOP = 2;
			m_dwInstCount++;
		}
		else if(m_dwInstCount == 0x02 && dwLength == 2 && strstr(da.result,"XOR BL,CL"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount == 0x03 && dwLength == 2 && strstr(da.result,"ROR BL,1"))
		{
			m_wOP1 = 1;
			m_dwInstCount++;
		}
		else if(m_dwInstCount == 0x03 && dwLength == 2 && strstr(da.result,"ROL BL,1"))
		{   
			m_wOP1 = 2;
			m_dwInstCount++;
		}
		else if(m_dwInstCount == 0x04 && dwLength == 2 && strstr(da.result,"SUB BL,CL"))
		{  
			m_wOP2 = 1;
			m_dwInstCount++;
		}
		else if(m_dwInstCount == 0x04 && dwLength == 2 && strstr(da.result,"ADD BL,CL"))
		{ 
			m_wOP2 = 2;
			m_dwInstCount++;
		}
		dwOffset += dwLength;
	}
	if(m_dwInstCount == 0x5)
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: SetOperatn
	In Parameters	: DWORD OffSet, WORD wCnt, DWORD dwBytes2Read, int flag
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Validates the different combination of keys for decryption
--------------------------------------------------------------------------------------*/
bool CPolyPolyk::FoundKey(DWORD OffSet, WORD wCnt, DWORD dwBytes2Read, int flag)
{ 
	if(flag)
	{ 
		if(!DoDecryption(m_bXorKey , wCnt))
		{
			return false;
		}
	}
	else
	{
		m_bUpXorKey = m_bXorKey;
	}

	if(GetBuffer(OffSet, dwBytes2Read))
	{
		for(DWORD i = 0; i < m_dwNoOfBytes; i++)
		{
			if(m_wOP == 1)
			{
				m_bUpXorKey += m_bAddKey; 
			}
			else if(m_wOP == 2)
			{
				m_bUpXorKey -= m_bAddKey; 
			}
			m_pbyBuff[i] ^= m_bUpXorKey;
			m_wOP3 = 0x1;
			if(!DoDecryption(m_bUpXorKey, 0))
			{
				return false;
			}
		}
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DoDecryption
	In Parameters	: BYTE m_bXorKey, WORD wCnt
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decrypt the buffer using found key
--------------------------------------------------------------------------------------*/
bool CPolyPolyk::DoDecryption(BYTE m_bXorKey, WORD wCnt)
{
	BYTE bRORCnt = 1;
	if(m_wOP == 0 && m_wOP1 == 0 && m_wOP2 == 0)
	{
		return false;
	}
	for(int i = 0; i <= wCnt ; i++)
	{ 
		if(m_wOP == 1 && (m_wOP3 != 1 || wCnt != 0))
		{
			m_bXorKey += m_bAddKey; 
		}
		else if(m_wOP == 2 && (m_wOP3 != 1 || wCnt != 0))
		{
			m_bXorKey -= m_bAddKey; 
		}
		m_bXorKey ^= LOBYTE(m_wCnt1);
		DWORD dwRotateCounter = bRORCnt % 0x08;
		if(m_wOP1 == 1)
		{
			m_bXorKey = m_bXorKey >> dwRotateCounter | m_bXorKey << (0x08 - dwRotateCounter);
		}
		else if(m_wOP1 == 2) 
		{
			m_bXorKey = m_bXorKey << dwRotateCounter | m_bXorKey >> (0x08 - dwRotateCounter);
		}
		if(m_wOP2 == 1)
		{
			m_bXorKey -= LOBYTE(m_wCnt1); 
		}
		if(m_wOP2 == 2)
		{
			m_bXorKey += LOBYTE(m_wCnt1);
		}
		m_wCnt1--;
	}
	m_bUpXorKey = m_bXorKey; 
	return true;
}
