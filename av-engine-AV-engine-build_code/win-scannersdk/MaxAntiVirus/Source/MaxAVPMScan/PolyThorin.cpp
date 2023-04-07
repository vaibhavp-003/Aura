/*======================================================================================
FILE				: PolyThorin.cpp
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
NOTES				: This is detection module for malware Thorin Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyThorin.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyThorin
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyThorin::CPolyThorin(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	memset(&m_stDecryptionParams, 0, sizeof(m_stDecryptionParams));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyThorin
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyThorin::~CPolyThorin(void)
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
	Description		: Detection routine for different varients of Thorin Family
--------------------------------------------------------------------------------------*/
int CPolyThorin::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD dwAEP2SecEndLen = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - m_dwAEPMapped;
	BYTE byBuffer[40] = {0};
	const BYTE byStubSig[] = {	0x5B, 0x57, 0x69, 0x6E, 0x33, 0x32, 0x2E, 0x54, 0x68, 0x6F, 
								0x72, 0x69, 0x6E, 0x5D, 0x00, 0x46, 0x69, 0x72, 0x73, 0x74,
								0x20, 0x47, 0x65, 0x6E, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
								0x6E, 0x20, 0x53, 0x61, 0x6D, 0x70, 0x6C, 0x65};

	if(m_pMaxPEFile->ReadBuffer(&byBuffer[0], m_pSectionHeader[1].PointerToRawData, sizeof(byStubSig), sizeof(byStubSig)))
	{
		if(0 == memcmp(&byBuffer[0], &byStubSig[0], sizeof(byStubSig)))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Thorin"));
			iRetStatus = VIRUS_FILE_DELETE;
		}
	}
	if(m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x4E524854 &&
		m_pSectionHeader[m_wNoOfSections - 1].Characteristics >= 0xE0000000 &&
		m_wNoOfSections - 1 == m_wAEPSec)
	{
		if(dwAEP2SecEndLen > THORIN_BUFF_SIZE)
		{
			dwAEP2SecEndLen = THORIN_BUFF_SIZE;
		}
		m_pbyBuff = new BYTE[THORIN_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, dwAEP2SecEndLen + MAX_INSTRUCTION_LEN);

		if(GetBuffer(m_dwAEPMapped, dwAEP2SecEndLen))
		{
			if(ThorinPrimaryDetection())
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Thorin"));
				iRetStatus = VIRUS_FILE_REPAIR;
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
	Description		: Repair routine for different varients of Thorin Family
--------------------------------------------------------------------------------------*/
int CPolyThorin::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;

	if(0 == ThorinSecondaryDecryption())
	{
		return iRetStatus;
	}
	DWORD dwTemp = 0;
	for(dwTemp = 0x400; dwTemp < 0x700; dwTemp++)
	{
		if(m_pbyBuff[dwTemp] == 0x9D && m_pbyBuff[dwTemp + 1] == 0x61 && 
			(m_pbyBuff[dwTemp + 14] == 0xC3 || m_pbyBuff[dwTemp + 13] == 0xC3))
		{
			break;
		}
	}
	if(dwTemp >= 0x700)
	{
		return iRetStatus;
	}
	
	DWORD dwOEP = 0x00;
	dwOEP = *(DWORD *)&m_pbyBuff[dwTemp + 3];
	if(dwOEP <(m_pSectionHeader[m_wAEPSec].VirtualAddress + m_pSectionHeader[m_wAEPSec].Misc.VirtualSize) && dwOEP >= m_pSectionHeader[0].VirtualAddress)
	{
		m_pMaxPEFile->WriteAEP(dwOEP);
		m_pMaxPEFile->RepairOptionalHeader(0x13, 0x00, 0);
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: ThorinPrimaryDetection
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Top level detection for Thorin Virus
--------------------------------------------------------------------------------------*/
int CPolyThorin::ThorinPrimaryDetection()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	BYTE B1 = 0, B2 = 0;

	m_objMaxDisassem.InitializeData();
	t_disasm	m_da;

	DWORD dwLength = 0, dw2ndDecryptionInstCnt = 0, dwOuterWhileLoopBreak = 0, dwOffset = 0;
	bool bFlag = false, bFlag4TrueDetection = false;

	while(1)
	{
		dwOuterWhileLoopBreak++;
		while(dwOffset < m_dwNoOfBytes)
		{
			if(m_dwInstCount > 400)
				return iRetStatus;

			memset(&m_da, 0x00, sizeof(struct t_disasm));
			B1 = m_pbyBuff[dwOffset];
			B2 = m_pbyBuff[dwOffset + 1];

			//Skipping Some Instructions that couldn't be interpreted by Olly.
			if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
			{
				dwOffset += 0x03;
				continue;
			}
			if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
			{
				dwOffset += 0x02;
				continue;
			}

			dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &m_da, DISASM_CODE);
			if(dwLength >(m_dwNoOfBytes - dwOffset))
			{
				return iRetStatus;
			}
			m_dwInstCount++;
			if(dwLength >= 0x06 && strstr(m_da.result, "ADD DWORD PTR "))
			{
				m_stDecryptionParams.dwDecryptionKey = *((DWORD *)&m_pbyBuff[dwOffset + dwLength - 4]);
				m_stDecryptionParams.eOperation = ADD_DWORD;
				bFlag = true;
				break;
			}
			if(dwLength >= 0x06 && strstr(m_da.result, "SUB DWORD PTR "))
			{
				m_stDecryptionParams.dwDecryptionKey = *((DWORD *)&m_pbyBuff[dwOffset + dwLength - 4]);
				m_stDecryptionParams.eOperation = SUB_DWORD;
				bFlag = true;
				break;
			}
			if(dwLength >= 0x06 && strstr(m_da.result, "XOR DWORD PTR "))
			{
				m_stDecryptionParams.dwDecryptionKey = *((DWORD *)&m_pbyBuff[dwOffset + dwLength - 4]);
				m_stDecryptionParams.eOperation = XOR_DWORD;
				bFlag = true;
				break;
			}			

			if(dwLength == 0x06 && B1 == 0x8D && strstr(m_da.result, "LEA ESI,[EBP+") && dw2ndDecryptionInstCnt == 1)
			{
				dw2ndDecryptionInstCnt++;
				m_stDecryptionParams.dwDecryptionOffset =(*(DWORD *)&m_pbyBuff[dwOffset + 2] - 0x400000) - 0x1000;
			}

			if(dwLength == 0x05 && B1 == 0xBF && strstr(m_da.result, "MOV EDI,") && dw2ndDecryptionInstCnt == 2)
			{
				dw2ndDecryptionInstCnt++;
				m_stDecryptionParams.dwSecondaryDecryptionCounter =	m_da.immconst;
			}

			if(dwLength == 0x05 && B1 == 0x3D && strstr(m_da.result, "CMP EAX,") && dw2ndDecryptionInstCnt == 3)
			{
				dw2ndDecryptionInstCnt++;
				m_stDecryptionParams.dwDecryptionLoopBreakingValue = m_da.immconst;
				iRetStatus = VIRUS_FILE_REPAIR;
				bFlag4TrueDetection = true;
				break;
			}

			dwOffset += dwLength;

		}//while_Inner

		if(bFlag)
		{
			bFlag = false;
			if(ThorinDecryption())
			{
				dwOffset = 0x400;
				if(0x60 == m_pbyBuff[dwOffset] && *((DWORD *)&m_pbyBuff[dwOffset + 1]) == 0xE3DB9B9C)
				{
					m_stDecryptionParams.dwDecryptionCounter = 0;
					m_stDecryptionParams.dwDecryptionKey = 0;
					m_stDecryptionParams.dwDecryptionOffset = 0; 
					m_stDecryptionParams.dwNextLoopOffset = 0;

					dw2ndDecryptionInstCnt = 1;
					m_dwInstCount = 0;

					continue;
				}
			}
		}

		if(bFlag4TrueDetection)
		{
			break;
		}

		if(dwOuterWhileLoopBreak >= 3)	
		{
			//1-For Primary Decryption 
			//2-For Secondary Decryption Params
			//This condition is to avoid indefinite looping
			break;
		}

	}//while_Outer

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: ThorinSecondaryDecryption
	In Parameters	: 
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Second level decryption
--------------------------------------------------------------------------------------*/
int CPolyThorin::ThorinSecondaryDecryption()
{
	int iRetStatus = 0;

	BYTE dwEAX[4] = {0x00}, dwEBX[4] = {0x00}, dwECX[4] = {0x00};
	BYTE dwEDX[4] = {0x00};
	DWORD dwESI = 0x00;
	DWORD dwEDI = 0x00;
	DWORD dwTemp = m_stDecryptionParams.dwDecryptionLoopBreakingValue;
	TCHAR szLogLine[1024] = {01};

	BYTE byCarry = 0x00;
	DWORD dwCounter = 0x00;
	while(1)
	{
		*((DWORD *)&dwECX[0]) = *((DWORD *)&dwEDX[0]) = 0xFFFFFFFF;
		dwEDI = m_stDecryptionParams.dwSecondaryDecryptionCounter;
		dwESI = m_stDecryptionParams.dwDecryptionOffset;
		
		while(1)
		{
			*((DWORD *)&dwEAX[0]) = 0x00;
			*((DWORD *)&dwEBX[0]) = 0x00;

			dwEAX[0] = m_pbyBuff[dwESI++];
			dwEAX[0] ^= dwECX[0];
			dwECX[0] = dwECX[1];
			dwECX[1] = dwEDX[0];
			dwEDX[0] = dwEDX[1];
			dwEDX[1] = 0x08;

			while(1)
			{
				//byCarry = 0x00;
				byCarry = *((WORD *)&dwEBX[0]) & 0x01;
				*((WORD *)&dwEBX[0]) = *((WORD *)&dwEBX[0]) >> 0x01;

				if(byCarry)
				{
					byCarry = *((WORD *)&dwEAX[0]) & 0x01;
					*((WORD *)&dwEAX[0]) = *((WORD *)&dwEAX[0]) | 0x01;
				}
				else
				{
					byCarry = *((WORD *)&dwEAX[0]) & 0x01;
					*((WORD *)&dwEAX[0]) = *((WORD *)&dwEAX[0]) & 0xFFFE;
				}
				//byCarry = *((WORD *)&dwEAX[0]) & 0x01;
				*((WORD *)&dwEAX[0]) = *((WORD *)&dwEAX[0]) >> 0x01 | *((WORD *)&dwEAX[0]) << 15;

				if(byCarry == 0x01)
				{
					*((WORD *)&dwEAX[0]) ^= 0x8320;
					*((WORD *)&dwEBX[0]) ^= 0xEDB8;
				}

				dwEDX[1]--;
				if(dwEDX[1] == 0x00)
				{
					break;
				}
			}

			*((DWORD *)&dwECX[0]) ^= *((DWORD *)&dwEAX[0]);
			*((DWORD *)&dwEDX[0]) ^= *((DWORD *)&dwEBX[0]);
			dwEDI--;
			if(dwEDI == 0x00)
			{
				break;
			}
		}
		*((DWORD *)&dwEDX[0]) = ~*((DWORD *)&dwEDX[0]); 
		*((DWORD *)&dwECX[0]) = ~*((DWORD *)&dwECX[0]); 

		*((DWORD *)&dwEAX[0]) = *((DWORD *)&dwEDX[0]);
		*((DWORD *)&dwEAX[0]) = *((DWORD *)&dwEAX[0]) << 0x10;
		*((WORD *)&dwEAX[0])  = *((WORD *)&dwECX[0]);
		
		if(*((DWORD *)&dwEAX[0]) == dwTemp)
		{
			m_stDecryptionParams.dwDecryptionKey = (DWORD)dwCounter;
			iRetStatus = 1;
			break;
		}
		for(DWORD i = 0; i < m_stDecryptionParams.dwSecondaryDecryptionCounter; i++)
		{
			m_pbyBuff[m_stDecryptionParams.dwDecryptionOffset + i] ^= (BYTE)dwCounter;
		}
		dwCounter++;
		for(DWORD i = 0; i < m_stDecryptionParams.dwSecondaryDecryptionCounter; i++)
		{
			m_pbyBuff[m_stDecryptionParams.dwDecryptionOffset + i] ^= (BYTE)dwCounter;
		}
		if(dwCounter > 0xFF)
		{
			return iRetStatus;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: ThorinDecryption
	In Parameters	: 
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decrypt the buffer for repair
--------------------------------------------------------------------------------------*/
int CPolyThorin::ThorinDecryption()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD dwOffset = 0x400;

	switch(m_stDecryptionParams.eOperation)
	{
	case ADD_DWORD:
		for(DWORD dwCnt = dwOffset; dwCnt < m_dwNoOfBytes + 3; dwCnt += 4)
		{
			*(DWORD *)&m_pbyBuff[dwCnt] += m_stDecryptionParams.dwDecryptionKey; 
		}
		iRetStatus = true;
		break;
	case SUB_DWORD:
		for(DWORD dwCnt = dwOffset; dwCnt < m_dwNoOfBytes + 3; dwCnt += 4)
		{
			*(DWORD *)&m_pbyBuff[dwCnt] -= m_stDecryptionParams.dwDecryptionKey; 
		}
		iRetStatus = true;
		break;
	case XOR_DWORD:
		for(DWORD dwCnt = dwOffset; dwCnt < m_dwNoOfBytes + 3; dwCnt += 4)
		{
			*(DWORD *)&m_pbyBuff[dwCnt] ^= m_stDecryptionParams.dwDecryptionKey; 
		}
		iRetStatus = true;
		break;
	}
	return iRetStatus;
}