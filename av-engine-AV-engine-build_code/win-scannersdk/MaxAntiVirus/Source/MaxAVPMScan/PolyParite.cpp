/*======================================================================================
FILE				: PolyParite.cpp
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
NOTES				: This is detection module for malware Parite Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyParite.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyParite
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyParite::CPolyParite(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	memset(&m_objPariteStruct, 0 , sizeof(PariteStruct));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyParite
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyParite::~CPolyParite(void)
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
	Description		: Detection routine for different varients of Parite Family
--------------------------------------------------------------------------------------*/
int CPolyParite::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	// Skip last sections having SRD zero 
	for(WORD wSec = m_wNoOfSections - 1; m_pSectionHeader[wSec].SizeOfRawData < 0x600; wSec--)
	{
		if(0 == wSec)
		{
			return iRetStatus;	
		}
		m_wNoOfSections--;
	}
	BYTE bLastSection = m_pSectionHeader[m_wNoOfSections-1].Name[0x04];

	m_pbyBuff = new BYTE[PARITE_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, PARITE_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(GetBuffer(m_dwAEPMapped, PARITE_BUFF_SIZE, PARITE_BUFF_SIZE))
	{
		if(GetPariteParams())
		{
			// Try to decrypt the virus code using parametes found from instructions in 1st decryption loop 
			if(!DecryptVirusCode(m_objPariteStruct.dwDecryptionOffsetFromInstr))
			{					
				// 1st attempt of decryption failed so try to decrypt using offset after 1st decryption loop 
				if(!GetBuffer(m_dwAEPMapped, PARITE_BUFF_SIZE, PARITE_BUFF_SIZE))
					return iRetStatus;
				
				if(!DecryptVirusCode(m_objPariteStruct.dwDecryptionOffset))
				{
					// 2nd attempt of decryption failed so try to decrypt virus body using offset 0x28
					if(!GetBuffer(m_dwAEPMapped, PARITE_BUFF_SIZE, PARITE_BUFF_SIZE))
						return iRetStatus;
					
					if(!DecryptVirusCode(PARITE_DEC_OFFSET))
					{
						return iRetStatus;
					}
				}
			}
			// Virus code decryption succeded so fetch the original AEP from the virus code
			// Check if its Parite.C infected file. If so we need to decrypt to get AEP
			if(m_pSectionHeader[m_wAEPSec].Name[0x04] == 0x09)	
			{
				DecryptPariteC_AEP();
			}
			
			// check section name to decide Parite variant name
			BYTE bLastSection = m_pSectionHeader[m_wAEPSec].Name[0x04];
			if(bLastSection == 0x06)
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Parite.A"));		
			else if(bLastSection == 0x07)
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Parite.B"));		
			else if(bLastSection == 0x09)
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Parite.C"));
			else if(bLastSection == 0x02)
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Parite.D"));
			else
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Parite.Gen"));

			DWORD dwOriginalAEP = *((DWORD *)&m_pbyBuff[m_objPariteStruct.dwDecryptionOffset + 0x0C]);
			if(dwOriginalAEP < m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize)
			{
				m_objPariteStruct.dwOriginalAEP = dwOriginalAEP;
				return VIRUS_FILE_REPAIR;
			}
			return VIRUS_FILE_DELETE;
		}
		else if(bLastSection == 0x07)
		{
			if(m_pbyBuff[0x0] == 0x60 && m_pbyBuff[1] == 0xE8 && m_pbyBuff[0x6] == 0x8B && m_pbyBuff[0xA] == 0xE8)
			{
				return iRetStatus;
			}
			memset(m_pbyBuff, 0x00, PARITE_BUFF_SIZE);
			if(GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, PARITE_BUFF_SIZE, PARITE_BUFF_SIZE))
			{
				if(GetPariteParams())
				{					
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Parite.E"));	
					iRetStatus = VIRUS_FILE_DELETE;
				}
			}
		}
	}

	if(m_wNoOfSections >= 7)
	{
		BYTE sig1[] = {0x70, 0x6C, 0x6F, 0x72, 0x65, 0x72, 0x00, 0x50, 0x49, 0x4E, 0x46, 0x00, 0x2A, 0x2E, 0x54, 0x4D, 0x50};
		if(GetBuffer(0x53260, sizeof(sig1), sizeof(sig1)))
		{		
			if(memcmp(m_pbyBuff, sig1, sizeof(sig1)) == 0)
			{
				BYTE sig2[] = {0x72, 0x65, 0x72, 0x00, 0x50, 0x49, 0x4E, 0x46, 0x00, 0x49, 0x6E, 0x69, 0x74, 0x69, 0x61, 0x74, 0x65};
				if(GetBuffer(0x53740, sizeof(sig2), sizeof(sig2)))
				{		
					if(memcmp(m_pbyBuff, sig2, sizeof(sig2)) == 0)
					{
						BYTE sig3[] = {0x78, 0x65, 0x00, 0x2A, 0x2E, 0x73, 0x63, 0x72, 0x00, 0x00, 0x5C, 0x00, 0x00, 0x2A, 0x2E, 0x65, 0x78, 0x65, 0x00, 0x2A, 0x2E, 0x73, 0x63, 0x72, 0x00, 0x2A, 0x2E, 0x2A};
						if(GetBuffer(0x53C30, sizeof(sig3), sizeof(sig3)))
						{
							if(memcmp(m_pbyBuff, sig3, sizeof(sig3)) == 0)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Parite.Q"));	
								iRetStatus = VIRUS_FILE_DELETE;
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
	Function		: DecryptVirusCode
	In Parameters	: DWORD dwDecryptionOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decrypt the buffer from given offset
--------------------------------------------------------------------------------------*/
bool CPolyParite::DecryptVirusCode(DWORD dwDecryptionOffset)
{
	if(0 == dwDecryptionOffset)
	{
		return false;
	}
	m_objPariteStruct.dwKey = *(DWORD *)&m_pbyBuff[dwDecryptionOffset];
	if(m_pSectionHeader[m_wAEPSec].Name[0x04] == 0x02)
	{
		m_objPariteStruct.dwKey ^= PARITE_D_KEY; 
	}
	else
	{
		m_objPariteStruct.dwKey ^= PARITE_KEY; 
	}
	for(DWORD dwOffset = dwDecryptionOffset; dwOffset < m_dwNoOfBytes - 4; dwOffset += 0x04)
	{
		*((DWORD *)&m_pbyBuff[dwOffset]) ^= m_objPariteStruct.dwKey;
	}

	BYTE szPariteSign[] = {0x00, 0x50, 0x49, 0x4E, 0x46, 0x00};
	if(memcmp(szPariteSign, &m_pbyBuff[dwDecryptionOffset + 0x173], 0x06) == 0 || 
		memcmp(szPariteSign, &m_pbyBuff[dwDecryptionOffset + 0x15B], 0x06) == 0)
	{
		m_objPariteStruct.dwDecryptionOffset = dwDecryptionOffset;
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetPariteParams
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Collects require structures
--------------------------------------------------------------------------------------*/
bool CPolyParite::GetPariteParams(void)
{
	BYTE	B1, B2;
	DWORD	dwLength = 0x00, dwStartAddress = 0x00;
	int		iValidInstructionCnt = 0, iTotalInstructionCnt = 0;
	t_disasm	da;

	m_objPariteStruct.dwDecryptionOffset = 0;

	while(dwStartAddress < m_dwNoOfBytes && iTotalInstructionCnt < 0x30)
	{
		memset(&da, 0x00, sizeof(struct t_disasm));

		B1 = *((BYTE*)&m_pbyBuff[dwStartAddress]);
		B2 = *((BYTE*)&m_pbyBuff[dwStartAddress + 1]);

		//Handling for garbage instruction.
		if(B1 == 0xC1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwStartAddress+= 0x03;
			continue;
		}
		if((B1 == 0xD0 || B1 == 0xD1 || B1 == 0xD2) && B2 >= 0xF0 && B2 <= 0xF7)
		{
			dwStartAddress+= 0x02;
			continue;
		}
		
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStartAddress], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwStartAddress))
		{
			return false;
		}

		iTotalInstructionCnt++;
	
		if(iValidInstructionCnt == 0 && dwLength == 0x05 && (B1 == 0x68 && strstr(da.result, "PUSH") || strstr(da.result, "MOV")))
		{
			DWORD dwDecryptionOffsetRVA = *(DWORD *)&m_pbyBuff[dwStartAddress + 1] -  m_dwImageBase;
			DWORD dwDecryptionOffset = 0;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwDecryptionOffsetRVA, &dwDecryptionOffset))
			{
				if(dwDecryptionOffset > m_dwAEPMapped && dwDecryptionOffset < m_dwAEPMapped + 0x50 && m_objPariteStruct.dwDecryptionOffsetFromInstr == 0)
				{
					m_objPariteStruct.dwDecryptionOffsetFromInstr = dwDecryptionOffset - m_dwAEPMapped + 4;
				}
			}
		}
		else if(iValidInstructionCnt == 0 && B1 == 0x31 && dwLength == 0x03 && strstr(da.result, "XOR ["))
		{
			iValidInstructionCnt++;
		}
		else if(iValidInstructionCnt == 1 && ((B1 == 0x83 && dwLength == 0x03 && strstr(da.result, "SUB")) || (dwLength == 0x01 && strstr(da.result, "DEC"))))
		{
			iValidInstructionCnt++;
		}
		else if(iValidInstructionCnt == 2 && B1 == 0x75 && dwLength == 0x02 && strstr(da.result, "JNZ"))
		{
			m_objPariteStruct.dwDecryptionOffset = dwStartAddress + dwLength;
			while(m_pbyBuff[m_objPariteStruct.dwDecryptionOffset] == 0x90)
			{
				m_objPariteStruct.dwDecryptionOffset++;
			}			
			return true;
		}		
		dwStartAddress += dwLength;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Parite Family
--------------------------------------------------------------------------------------*/
int CPolyParite::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	
	DWORD dwTemp = *((DWORD *)&m_pbyBuff[m_objPariteStruct.dwDecryptionOffset + 0x20]) - m_dwImageBase;	
	
	DWORD dwTempOffset = 0;
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwTemp, &dwTempOffset))
	{
		//Tushar ==> 16 Feb 2011 : Added to Handle sections with zero SRD,RVA,VS,PRD etc.
		dwTempOffset = Rva2FileOffsetEx(dwTemp, NULL);
		if(dwTempOffset == 0x00)
			return iRetStatus;
	}
	
	if(m_pSectionHeader[m_wAEPSec].Name[0x04] == 0x02)
	{
		m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_objPariteStruct.dwDecryptionOffset + 0x20 + 0x04], dwTempOffset, 0x08);
	}
	else
	{
		m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_objPariteStruct.dwDecryptionOffset + 0x20 + 0x1C], dwTempOffset, 0x08);
	}

	dwTemp = *((DWORD *)&m_pbyBuff[m_objPariteStruct.dwDecryptionOffset + 0x2C]);
	if(dwTemp && dwTemp < m_pMaxPEFile->m_dwFileSize)
	{
		if(m_pSectionHeader[m_wNoOfSections-1].Name[0x04] == 0x02)
		{
			m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_objPariteStruct.dwDecryptionOffset + 0x20 + 0x04], dwTemp, 0x08);
		}
		else
		{
			m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_objPariteStruct.dwDecryptionOffset + 0x2C + 0x04], dwTemp, 0x08);
		}
	}

	m_pMaxPEFile->WriteAEP(m_objPariteStruct.dwOriginalAEP);
	m_pMaxPEFile->RepairOptionalHeader(0x16, 0, 0);

	// TODO: check samples with overlay to handle overlay shifting. Virus add its 
	// overlay to the file. We need to check whether it maintains the original overlay
	if(0 == m_wAEPSec)
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - m_dwAEPMapped))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	}	
	else if(m_dwAEPMapped == m_pSectionHeader[m_wAEPSec].PointerToRawData)
	{
		if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wAEPSec].PointerToRawData, true))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	}
	else
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptPariteC_AEP
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decrypt the buffer at AEP
--------------------------------------------------------------------------------------*/
void CPolyParite::DecryptPariteC_AEP()
{
	DWORD	dwKeyIndex  = 0x30, dwKeyIndex1 = 0x3C;
	BYTE	byKey[16] = {0x00},	byAL = 0x00, byBL = 0x00;
	DWORD	dwECX = 0x00, dwESI = 0x00, dwEBX = 0x00;
	DWORD	dwTemp = 0x00, dwTemp1 = 0x00, dwTemp2 = 0x00;

	while(dwEBX < 8)
	{
		byAL = m_pbyBuff[m_objPariteStruct.dwDecryptionOffset + dwKeyIndex+dwEBX];
		dwTemp1 = dwEBX;
		dwTemp2 = dwESI;
		dwEBX = dwTemp;
		dwTemp++;
		dwECX = dwEBX;
		dwESI = dwECX - 1;
		if(dwESI == 0xFFFFFFFF)
			dwESI = 0x00;
		dwESI = dwESI >> 0x01;			
		while(1)
		{
			if(dwECX == 0x00)
				break;
			if(byAL <= byKey[dwESI])
				break;
			byBL = byKey[dwESI];
			byKey[dwECX] = byBL;
			dwECX = dwESI;
			dwESI = dwECX - 1;
			if(dwESI == 0xFFFFFFFF)
				dwESI = 0x00;
			dwESI = dwESI >> 0x01;	
		}
		byKey[dwECX] = byAL;
		dwESI = dwTemp2;
		dwEBX = dwTemp1;

		byAL = m_pbyBuff[m_objPariteStruct.dwDecryptionOffset + dwKeyIndex1+dwEBX];
		dwTemp1 = dwEBX;
		dwTemp2 = dwESI;
		dwEBX = dwTemp;
		dwTemp++;
		dwECX = dwEBX;
		dwESI = dwECX - 1;
		if(dwESI == 0xFFFFFFFF)
			dwESI = 0x00;
		dwESI = dwESI >> 0x01;
		while(1)
		{
			if(dwECX == 0x00)
				break;
			if(byAL <= byKey[dwESI])
				break;
			byBL = byKey[dwESI];
			byKey[dwECX] = byBL;
			dwECX = dwESI;
			dwESI = dwECX - 1;
			if(dwESI == -1)
				dwESI = 0x00;
			dwESI = dwESI >> 1;
		}
		byKey[dwECX] = byAL;
		dwESI = dwTemp2;
		dwEBX = dwTemp1;

		dwEBX++;
	}

	for(int i = 0x00; i < 4; i++)
	{
		*((DWORD *)&m_pbyBuff[m_objPariteStruct.dwDecryptionOffset + 0x0C]) ^= *((DWORD *)&byKey[i * 4]);
	}
	return;
}