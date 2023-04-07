/*======================================================================================
FILE				: PolyChamp.cpp
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
NOTES				: This is detection module for malwares Bolzano Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyChamp.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyChamp
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyChamp::CPolyChamp(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwJmpOffset = m_dwOriDataOffset = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyChamp
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyChamp::~CPolyChamp(void)
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
	Description		: Detection routine for different varients of Virus.Champ Family
--------------------------------------------------------------------------------------*/
int CPolyChamp::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000060) == 0xE0000060) ||
		((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE2000240) == 0xE2000240))&&
		(m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) !=  IMAGE_FILE_DLL &&
		m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData <= 0xA000)
	{
		BYTE byBuff[0x20] = {0};			
		if(m_pMaxPEFile->ReadBuffer(byBuff, m_dwAEPMapped, 0x20, 0x20))
		{
			DWORD dwLength = 0;
			t_disasm da = {0};
			for(DWORD dwOffset = 0; dwOffset < 0x20; dwOffset += dwLength)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&byBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			
				if(dwLength == 5 && strstr(da.result, "MOV E"))
				{
					if(m_wNoOfSections - 1 == m_pMaxPEFile->Rva2FileOffset((da.immconst - m_dwImageBase), &m_dwJmpOffset))
					{
						m_pbyBuff = new BYTE[CHAMP_BUFF_SIZE + MAX_INSTRUCTION_LEN];	  
						if(NULL == m_pbyBuff)
						{
							return iRetStatus;
						}
						memset(m_pbyBuff, 0, CHAMP_BUFF_SIZE + MAX_INSTRUCTION_LEN);

						if(GetBuffer(m_dwJmpOffset, CHAMP_BUFF_SIZE, 0x15C0))
						{
							if(m_pbyBuff[5]== 0xE8 && CheckSignature(da.immconst))
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Champ"));
								iRetStatus = VIRUS_FILE_REPAIR;
							}
						}
						break;
					}
				}
			}
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
	Description		: Validates the CPU instruction pattern to detect different varients of Virus.Champ Family
--------------------------------------------------------------------------------------*/
bool CPolyChamp::CheckSignature(DWORD dwJmpVAOffset)
{
	t_disasm da = {0x00};
	
	DWORD dwDecOffset = *(DWORD *)&m_pbyBuff[6] + dwJmpVAOffset + 0x0A;
	m_pMaxPEFile->Rva2FileOffset((dwDecOffset - m_dwImageBase), &dwDecOffset);
	DWORD dwOffset = dwDecOffset - m_dwJmpOffset, dwLength = 0;;
	
	int iNoOfInstrutions = 0;	
	m_dwInstCount = 0;
	Instruction_Set_Struct objInstructionSet[MAX_INSTRUCTIONS] = {0};

	while(dwOffset < m_dwNoOfBytes)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		m_dwInstCount++;

		if((dwLength == 3 && strstr(da.result, "ROL EAX")) ||
			(dwLength == 3 && strstr(da.result, "ROR EAX")) ||
			(dwLength == 6 && strstr(da.result, "ADD EAX")) ||
			(dwLength == 6 && strstr(da.result, "SUB EAX")) ||
			(dwLength == 6 && strstr(da.result, "XOR EAX")) ||
			(dwLength == 1 && strstr(da.result, "INC EAX")) ||
			(dwLength == 1 && strstr(da.result, "DEC EAX")) ||
			(dwLength == 2 && strstr(da.result, "NEG EAX")) || 
			(dwLength == 2 && strstr(da.result, "NOT EAX")))
		{
			objInstructionSet[iNoOfInstrutions].dwInstLen = dwLength;
			strcpy_s(objInstructionSet[iNoOfInstrutions].szOpcode, TEXTLEN, da.dump);
			strcpy_s(objInstructionSet[iNoOfInstrutions++].szPnuemonics, TEXTLEN, da.result);
		}
		else if((dwLength == 1 && m_pbyBuff[dwOffset] == 0xAB && _strcmpi(da.dump, "FFFFFFAB") == 0) || 
			(dwLength == 2 && strstr(da.result,"MOV [EDI],EAX")))
		{
			break;
		}		
		dwOffset += dwLength;
	}

	char *ptr = NULL;
	DWORD dwConstant = 0;
	
	for(DWORD dwOffset = 0xA; dwOffset < m_dwNoOfBytes; dwOffset += 4)
	{
		if(dwOffset < 0x40 || dwOffset >= CHAMP_A_DEC_START_OFFSET)
		{		
			for(int i = 0; i < iNoOfInstrutions; i++)
			{
				dwConstant = 0;
				ptr = strrchr(objInstructionSet[i].szPnuemonics, ',');
				if(ptr)
				{
					ptr++;
					sscanf_s(ptr, "%X", &dwConstant);			
				}

				if(strstr(objInstructionSet[i].szPnuemonics, "ROL EAX"))
				{
					(*(DWORD *)(&m_pbyBuff[dwOffset])) = _lrotl(*(DWORD *)&m_pbyBuff[dwOffset], dwConstant);
				}
				else if(strstr(objInstructionSet[i].szPnuemonics, "ROR EAX"))
				{
					(*(DWORD *)(&m_pbyBuff[dwOffset])) = _lrotr(*(DWORD *)&m_pbyBuff[dwOffset], dwConstant);
				}
				else if(strstr(objInstructionSet[i].szPnuemonics, "ADD EAX"))
				{
					(*(DWORD *)(&m_pbyBuff[dwOffset])) += dwConstant;
				}
				else if(strstr(objInstructionSet[i].szPnuemonics, "SUB EAX"))
				{
					(*(DWORD *)(&m_pbyBuff[dwOffset])) -= dwConstant;
				}
				else if(strstr(objInstructionSet[i].szPnuemonics, "XOR EAX"))
				{
					(*(DWORD *)(&m_pbyBuff[dwOffset])) ^= dwConstant;
				}
				else if(strstr(objInstructionSet[i].szPnuemonics, "INC EAX"))
				{
					(*(DWORD *)(&m_pbyBuff[dwOffset]))++;
				}
				else if(strstr(objInstructionSet[i].szPnuemonics, "DEC EAX"))
				{
					(*(DWORD *)(&m_pbyBuff[dwOffset]))--;
				}
				else if(strstr(objInstructionSet[i].szPnuemonics, "NEG EAX"))
				{
					(*(DWORD *)(&m_pbyBuff[dwOffset])) = ~(*(DWORD *)&m_pbyBuff[dwOffset]) + 1;
				}
				else if(strstr(objInstructionSet[i].szPnuemonics, "NOT EAX"))
				{
					(*(DWORD *)(&m_pbyBuff[dwOffset])) = ~(*(DWORD *)&m_pbyBuff[dwOffset]);
				}
			}
		}
	}
	const BYTE bySignature1[] = {0x4c, 0x65, 0x74, 0x68, 0x61, 0x6c, 0x4d, 0x69, 0x6e, 0x64, 0x2e, 0x43, 0x68, 0x61, 0x6d, 0x70, 0x61, 0x67, 0x6e, 0x65};
	const BYTE bySignature2[] = {0x4a, 0x65, 0x20, 0x74, 0x27, 0x61, 0x69, 0x6d, 0x65, 0x20, 0x4c, 0x61, 0x75, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x20, 0x21};
	const BYTE bySignature3[] = {0x43, 0x6F, 0x75, 0x63, 0x6F, 0x75, 0x20, 0x41, 0x68, 0x69, 0x6E, 0x65, 0x20, 0x21};

	for (DWORD dwIdx = CHAMP_A_DEC_START_OFFSET ; dwIdx < m_dwNoOfBytes - sizeof(bySignature1); dwIdx++)
	{
		if(memcmp(&m_pbyBuff[dwIdx], bySignature1, sizeof(bySignature1)) == 0)
		{
			for(;dwIdx < (m_dwNoOfBytes - sizeof(bySignature2)); dwIdx++)
			{
				if((memcmp(&m_pbyBuff[dwIdx], bySignature2, sizeof(bySignature2)) == 0) || 
					(memcmp(&m_pbyBuff[dwIdx], bySignature3, sizeof(bySignature3)) == 0))
				{
					for(dwOffset = 0; m_pbyBuff[dwOffset] != 0xBD; dwOffset++);	
					m_dwOriDataOffset = (*(DWORD *)&m_pbyBuff[dwOffset + 1]);

					for(dwOffset = 0; dwOffset < 0x40; dwOffset += dwLength)
					{
						dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);

						if(dwLength == 6 && strstr(da.result,"LEA ESI,[EBP"))
						{
							m_dwOriDataOffset += da.adrconst;
							if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset((m_dwOriDataOffset - m_dwImageBase), &m_dwOriDataOffset))
							{								
								m_dwOriDataOffset -= m_dwJmpOffset;
								return (m_dwOriDataOffset < m_dwNoOfBytes) ? true : false;
							}
						}
					}					
					return false;
				}
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
	Description		: Repair routine for different varients of Champ Family
--------------------------------------------------------------------------------------*/
int CPolyChamp::CleanVirus()
{
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwOriDataOffset], m_dwAEPMapped, 0x64, 0x64))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwJmpOffset, true))
		{
			if(m_pMaxPEFile->FillWithZeros(0x12, sizeof(WORD)))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}