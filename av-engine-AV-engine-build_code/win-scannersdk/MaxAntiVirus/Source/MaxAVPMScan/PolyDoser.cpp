/*======================================================================================
FILE				: PolyDoser.cpp
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
NOTES				: This is detection module for malware Doser Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyDoser.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyDoser
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDoser::CPolyDoser(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_eDecType		= NO_DOSER_DEC_FOUND;
	m_byDecKey		= 0x00;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDoser
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDoser::~CPolyDoser(void)
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
	Description		: Detection routine for different varients of Doser Family
--------------------------------------------------------------------------------------*/
int CPolyDoser::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == m_wNoOfSections-1 && 
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000000)  == 0xE0000000)
	{
		m_pbyBuff = new BYTE[DOSER_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(m_pbyBuff == NULL)
		{
			return iRetStatus;
		}
		memset(&m_pbyBuff[0], 0x00, DOSER_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, DOSER_BUFF_SIZE, 0x11A0))
		{
			if(m_pbyBuff[0] == 0xE8)
			{
				if(*(DWORD *)&m_pbyBuff[1] == 0x1056 || *(DWORD *)&m_pbyBuff[1] == 0x11B9 || *(DWORD *)&m_pbyBuff[1] == 0x11B6 || *(DWORD *)&m_pbyBuff[1] == 0x11B7 || *(DWORD *)&m_pbyBuff[1] == 0x1057 || *(DWORD *)&m_pbyBuff[1] == 0x11B2) 
				{
					DWORD dwBufferIndex = (*((DWORD *)&m_pbyBuff[1])) + 5;		
					if(dwBufferIndex > m_dwNoOfBytes)
					{
						return iRetStatus;
					}
					if(CheckDoser4187Sig(dwBufferIndex))
					{
						iRetStatus = VIRUS_FILE_REPAIR;
						if(m_byDecKey == 0xA9 && m_eDecType == DOSER_DEC_DELETE)
						{
							iRetStatus = VIRUS_FILE_DELETE;
						}
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Doser.4187"));	
					}				
					if(CheckDoser4539Sig(dwBufferIndex)) 
					{
						iRetStatus = VIRUS_FILE_REPAIR;
						if(m_eDecType == DOSER_DEC_DELETE)
						{
							iRetStatus = VIRUS_FILE_DELETE;
						}
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Doser.4539.A"));
						return iRetStatus;
					}
					else if(*(DWORD *)&m_pbyBuff[1] == 0x11B2)
					{								
						if(dwBufferIndex > m_dwNoOfBytes)
						{
							return iRetStatus;
						}
						if(CheckDoser4535Sig(dwBufferIndex))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Doser.4535"));
							return VIRUS_FILE_DELETE;
						}
					}
				}				
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckDoser4535Sig
	In Parameters	: 
	Out Parameters	: true if match else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection for Doser.4535
--------------------------------------------------------------------------------------*/
bool CPolyDoser::CheckDoser4535Sig(DWORD dwOffset)
{
	DWORD dwLength = 0, dwInstCount = 0, dwXorOffset = 0;
	BYTE B1 = 0, B2 = 0;
	t_disasm da = {0x00};
	bool bXorFound = false;

	while(dwOffset < m_dwNoOfBytes && dwInstCount <= 0x29)
	{
		B1 = m_pbyBuff[dwOffset];
		B2 = m_pbyBuff[dwOffset + 1];

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if((B1 == 0xC0 || B1 == 0xC1) && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset += 0x03;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffset) || dwLength == 0)
		{
			break;
		}
		dwInstCount++;
		if(dwLength == 0x03 && strstr(da.result, "XOR BYTE PTR [ESI],"))
		{
			dwXorOffset = dwOffset;
			m_byDecKey =  (BYTE)da.immconst;
			if(m_byDecKey == 0xCE || m_byDecKey == 0x97 || m_byDecKey == 0x39)
			{
				bXorFound = true;
			}
		}
		else if(dwLength == 0x02 && strstr(da.result, "JNZ ") && bXorFound) 
		{
			if( B2 > 0x7F)
			{
				dwOffset = dwOffset - (0x100 - B2) + dwLength;
				if(dwXorOffset == dwOffset)
				{
					return true;
				}
			}
		}
		else if(dwLength == 0x01 && strstr(da.result, "???") && bXorFound && m_pbyBuff[dwOffset] == 0xE2)
		{
			if( B2 > 0x7F)
			{
				dwOffset = dwOffset - (0x100 - B2) + 2;
				if(dwXorOffset == dwOffset)
				{
					return true;
				}
			}
		}
		dwOffset += dwLength;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckDoser4187Sig
	In Parameters	: 
	Out Parameters	: true if match else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection for Doser.4187, Doser.4542, Doser.4188
--------------------------------------------------------------------------------------*/
bool CPolyDoser::CheckDoser4187Sig(DWORD dwOffset)
{
	DWORD dwLength = 0, dwInstCount = 0, dwWeight = 0x00;
	BYTE B1 = 0, B2 = 0;
	t_disasm da = {0x00};

	while(dwOffset < m_dwNoOfBytes && dwInstCount <= 0x30)
	{
		B1 = m_pbyBuff[dwOffset];
		B2 = m_pbyBuff[dwOffset + 1];

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if((B1 == 0xC0 || B1 == 0xC1) && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset += 0x03;
			continue;
		}
		if((B1 == 0xD1 && B2 >= 0xF0 && B2 <= 0xF7) || B1 == 0xE2)
		{
			dwOffset += 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffset) || dwLength == 0)
		{
			break;
		}

		dwInstCount++;

		if((dwLength == 0x02 || dwLength == 0x03) && ((strstr(da.result, "ADD [E") && strstr(da.result, ",E")) || strstr(da.result, "ROR BYTE PTR [E")))
		{
			m_eDecType = DOSER_DEC_DELETE;
			m_byDecKey = 0xA9;
			return true;
		}
		else if(dwLength == 0x05 && (strstr(da.result, "PUSH") || strstr(da.result, "MOV ")))
		{
			if(da.immconst == 0x1056 || da.immconst == 0x11B9 || da.immconst == 0x1057 || da.immconst == 0x11B2)
			{
				dwWeight++;
			}
		}
		else if(dwLength == 0x03 && strstr(da.result, "MOV ESI,[ESP]"))
		{
			dwWeight++;
		}
		else if(dwLength == 0x02 && strstr(da.result, "INC BYTE PTR [ESI]"))
		{
			m_eDecType = DOSER_DEC_ADD;
			dwWeight++;
		}
		else if(dwLength == 0x02 && strstr(da.result, "DEC BYTE PTR [ESI]"))
		{
			m_eDecType = DOSER_DEC_SUB;
			dwWeight++;
		}
		else if(dwLength == 0x02 && strstr(da.result, "NOT BYTE PTR [ESI]"))
		{
			m_eDecType = DOSER_DEC_NOT;
			dwWeight++;
		}
		else if(dwLength == 0x02 && strstr(da.result, "NEG BYTE PTR [ESI]"))
		{
			m_eDecType = DOSER_DEC_NEG;
			dwWeight++;
		}
		else if(dwLength == 0x03 && strstr(da.result, "XOR BYTE PTR [ESI],"))
		{
			m_byDecKey =  (BYTE)da.immconst;
			if((m_byDecKey == 0xA9) || (m_byDecKey == 0xCE) || (m_byDecKey == 0x39))
			{
				m_eDecType = DOSER_DEC_XOR;
			}
			return true;
		}
		else if(dwLength == 0x01 && dwWeight >= 0x02 && _strcmpi(da.dump, "FFFFFFC3") == 0 && m_eDecType != NO_DOSER_DEC_FOUND)
		{
			return true;
		}
		else if(dwLength == 0x02 && strstr(da.result, "JNZ ") && m_eDecType == NO_DOSER_DEC_FOUND)
		{
			if( B2 > 0x7F )
			{
				dwOffset = dwOffset - (0x100 - B2) + dwLength;							
			}
			else
			{
				dwOffset += dwLength + B2;				
			}
			continue;
		}
		dwOffset += dwLength;
	}
	return false;
}


/*-------------------------------------------------------------------------------------
	Function		: CheckDoser4539Sig
	In Parameters	: 
	Out Parameters	: true if match else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection for Doser.4539.A, Doser.4540
--------------------------------------------------------------------------------------*/
bool CPolyDoser ::CheckDoser4539Sig(DWORD dwOffset)
{
	DWORD dwLength = 0x00, dwWeight = 0x00,dwInstCount = 0x00;	
	BYTE B1 = 0, B2 = 0;
	int nCaseId = 0x00;
	t_disasm da = {0};

	while(dwOffset < m_dwNoOfBytes && dwInstCount < 0x60)
	{
		B1 = m_pbyBuff[dwOffset];
		B2 = m_pbyBuff[dwOffset + 1];

		if(B1 == 0xE2)
		{
			dwOffset += 2;
			continue;
		}
		if(B1 == 0xC3 || B1 == 0x3F || B1 == 0x00)
		{
			dwOffset += 1;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
		dwInstCount++;
		if(dwLength > (m_dwNoOfBytes - dwOffset))
		{
			break;
		}				

		if(strstr(da.result, "MOV ECX,11B6"))
		{
			dwWeight++;

			dwOffset += dwLength;
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);

			if(dwWeight == 0x01 && dwLength == 0x02 && strstr(da.result, "ADC EDX,EAX"))
			{
				dwWeight++;
				nCaseId = 0x01;
			}
			if(dwWeight == 0x01 && dwLength == 0x02 && strstr(da.result, "OR EDX,EAX"))
			{
				dwWeight++;
				nCaseId = 0x05;
			}
		}
		else if(strstr(da.result,"PUSH 11B6"))
		{
			dwWeight++;
			nCaseId = 0x02;
		}
		else if(strstr(da.result,"XOR BYTE PTR [ESI]") && da.immconst == 0xEF)
		{
			m_byDecKey = (BYTE)da.immconst;
			nCaseId = 0x03;
		}
		else if(strstr(da.result,"MOV ECX,11B0"))
		{
			dwWeight++;
			nCaseId = 0x04;
		}
		else if(strstr(da.result,"MOV ECX,11A6") || strstr(da.result,"MOV ECX,11AE"))
		{
			dwWeight++;
			nCaseId = 0x06;
		}
		else if(strstr(da.result,"MOV ECX,11B7"))
		{
			dwWeight++;
			nCaseId = 0x07;			
		}
		else if(strstr(da.result,"MOV ECX,11") && (dwLength == 5) && (*(DWORD *)&m_pbyBuff[dwOffset + 1] > 0x1150) && (*(DWORD *)&m_pbyBuff[dwOffset + 1] < 0x11C0) )
		{
			dwWeight++;
			nCaseId = 0x06;
		}

		switch(nCaseId)
		{
		case 0x01 ://increment by 1
			if(dwWeight == 0x02 && dwLength == 0x02 && strstr(da.result, "ADC EDX,EDX"))
			{
				dwWeight++;
			}
			else if(dwWeight == 0x03 && dwLength == 0x02 && strstr(da.result, "OR EAX,"))
			{
				dwWeight++;
			}
			else if(dwWeight == 0x04 && dwLength ==0x02 && strstr(da.result, "OR EDX,"))
			{
				dwWeight++;
			}
			else if(dwWeight == 0x05 && dwLength ==0x02 && strstr(da.result, "ADC EAX,EAX"))
			{
				dwWeight++;
			}
			else if(dwWeight == 0x06 && dwLength ==0x03 && strstr(da.result, "MOV ESI,[ESP]"))
			{
				dwWeight++;
			}
			else if(dwWeight == 0x07 && dwLength == 0x02 && strstr(da.result, "INC BYTE PTR [ESI"))
			{
				m_eDecType =  DOSER_DEC_ADD;
				return true;
			}
			break;

		case 0x02: //XOR by 32
			if(dwLength == 0x01 && dwWeight == 0x01 && strstr(da.result,"POP ECX"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x03 && dwWeight ==0x02 && strstr(da.result,"XOR BYTE PTR [ESI],"))
			{
				if( da.immconst == 0x32)
				{		
					m_byDecKey = (BYTE)da.immconst;
					dwWeight++;
				}
			}
			else if(dwLength == 0x02 && dwWeight == 0x03 &&  strstr(da.result,"SUB EAX,EBP"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x04 && strstr(da.result,"XOR EAX,EBP"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x01 && dwWeight == 0x05)
			{
				m_eDecType = DOSER_DEC_XOR;
				return true;
			}
			break;
		case 0x03://XOR with EF

			if(da.immconst == 0XEF)
			{
				m_byDecKey = (BYTE)da.immconst;
				dwWeight++;
			}
			if(dwLength == 0x02 && dwWeight == 0x01 && strstr(da.result,"MOV EAX,EBX"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x02 && strstr(da.result,"OR EAX,EBP"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x03 && strstr(da.result,"ADD EAX,EBP"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x04 && strstr(da.result,"ADC EAX,EBP"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x05 && strstr(da.result,"MOV EAX,EBP"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x06 && strstr(da.result,"OR EAX,EBP"))
			{
				m_eDecType = DOSER_DEC_XOR;
				return true;
			}
			break;

		case 0x04://DEC
			if(dwLength == 0x06 && strstr(da.result,"ADD ECX,") && (*(DWORD *)&m_pbyBuff[dwOffset + 2] < 0x20) && dwWeight == 1)
			{
				dwWeight++;
			}			
			else if(dwLength == 0x02 && dwWeight == 0x02 && strstr(da.result, "DEC BYTE PTR [ESI"))
			{
				m_eDecType = DOSER_DEC_SUB;
				return true;
			}
			break;

		case 0x05://Inc
			if(dwLength == 0x02 && dwWeight == 0x02 && strstr(da.result,"ADD EDX,EDX"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x03 && dwWeight == 0x03 && strstr(da.result,"MOV ESI,[ESP]"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x04 && strstr(da.result,"INC BYTE PTR [ESI"))
			{
				m_eDecType =DOSER_DEC_ADD;
				return true;
			}
			break;
		case 0x06://Inc
			if(dwLength == 0x06 && dwWeight == 0x01 && (strstr(da.result,"ADD ECX,")) && (*(DWORD *)&m_pbyBuff[dwOffset + 2] < 0x20))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x02 && strstr(da.result, "DEC BYTE PTR [ESI"))
			{
				m_eDecType = DOSER_DEC_SUB;
				return true;
			}
			else if(dwLength == 0x02 && dwWeight == 0x02 && strstr(da.result,"INC BYTE PTR [ESI"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x03 && (strstr(da.result,"OR EDX,EBP") || strstr(da.result,"OR EDX,EAX")))
			{
				m_eDecType = DOSER_DEC_ADD;
				return true;
			}
			break;
		case 0x07:
			if(dwLength == 0x02 && dwWeight == 0x01 && strstr(da.result,"OR EAX,EDX"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x02 && strstr(da.result,"MOV EAX,EDX"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x03 && strstr(da.result,"OR EAX,EDX"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x04 && strstr(da.result,"ADD EAX,EDX"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x01 && dwWeight == 0x05 && strstr(da.result,"POP EAX"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x01 && dwWeight == 0x06 && strstr(da.result,"PUSH EAX"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x07 && strstr(da.result,"MOV ESI,EAX"))
			{
				dwWeight++;
			}
			else if(dwLength == 0x02 && dwWeight == 0x08 && strstr(da.result,"INC BYTE PTR [ESI"))
			{
				m_eDecType =DOSER_DEC_ADD;
				m_byDecKey = 0xEF;
				return true;
			}
			break;		
		}		
		dwOffset += dwLength;
	}
	dwOffset= 0, m_dwInstCount = 0;
	while(dwOffset < m_dwNoOfBytes )
	{		
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);


		if(dwLength == 0x05 && strstr(da.result,"CALL "))
		{
			dwWeight++;
		}
		else if(dwLength == 0x01 && dwWeight == 0x01 && strstr(da.result,"POP E"))
		{
			dwWeight++;
		}
		else if(dwLength == 0x01 && dwWeight == 0x02 && _strcmpi(da.dump, "FFFFFFEF") == 0)
		{
			dwLength += 3;
			dwWeight++;
		}
		else if(dwLength == 0x02 && dwWeight == 0x03 && strstr(da.result,"JG SHORT"))
		{
			dwWeight++;
		}
		else if(dwLength == 0x02 && dwWeight == 0x04 && strstr(da.result,"IN EAX,FF"))
		{
			m_eDecType = DOSER_DEC_DELETE;
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
	Description		: Repair routine for different varients of Doser Family
--------------------------------------------------------------------------------------*/
int CPolyDoser::CleanVirus()
{	
	for(DWORD dwIndex = 0x05; dwIndex < 0x1056; dwIndex++)
	{
		switch(m_eDecType)
		{
		case DOSER_DEC_ADD:
			m_pbyBuff[dwIndex]++;
			break;
		case DOSER_DEC_SUB:
			m_pbyBuff[dwIndex]--;
			break;
		case DOSER_DEC_NOT:
			m_pbyBuff[dwIndex] = ~m_pbyBuff[dwIndex];
			break;
		case DOSER_DEC_XOR:
			m_pbyBuff[dwIndex] ^= m_byDecKey;
			break;
		case DOSER_DEC_NEG:
			m_pbyBuff[dwIndex] = ~m_pbyBuff[dwIndex];
			m_pbyBuff[dwIndex] += 1;
			break;
		}
	}

	const BYTE bySign[]={0x66, 0x8B, 0x95};

	// Find key offset & start of decryption
	for(DWORD dwOffset = 0; dwOffset < 0x40; dwOffset++)
	{
		if(memcmp(&m_pbyBuff[dwOffset], &bySign[0], _countof(bySign)) == 0x00)
		{
			BYTE byKeyOffset = m_pbyBuff[dwOffset + 3];
			BYTE byDecStart  = m_pbyBuff[dwOffset + 9];

			DWORD dwLength = 0;
			t_disasm da = {0x00};

			while(dwOffset < 0x60)
			{ 
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
				if(dwLength == 2 && strstr(da.result,"JMP SHORT"))
				{
					dwOffset +=  m_pbyBuff[dwOffset + 1] + dwLength;
					break;
				}
				else if(m_pbyBuff[dwOffset]== 0xE2 && m_pbyBuff[dwOffset + 1]== 0xEB && dwLength == 1)
				{
					dwOffset += 2;
				}
				else
				{
					dwOffset += dwLength;
				}
			}
			WORD wDeckey = *((WORD *)&m_pbyBuff[byKeyOffset]);
			for(DWORD dwIndex = byDecStart; dwIndex < m_dwNoOfBytes - 1; dwIndex += 2)
			{
				wDeckey++;
				wDeckey = wDeckey >> 0x08 | wDeckey << 0x08;
				*((WORD *)&m_pbyBuff[dwIndex]) = *((WORD *)&m_pbyBuff[dwIndex]) >> 0x08 | *((WORD *)&m_pbyBuff[dwIndex]) << 0x08;
				*((WORD *)&m_pbyBuff[dwIndex]) ^= wDeckey;
				*((WORD *)&m_pbyBuff[dwIndex]) = ~*((WORD *)&m_pbyBuff[dwIndex]);
			}

			// Find AEP offset
			dwOffset += 2;
			WORD wAEPOffset = *(WORD *)&m_pbyBuff[dwOffset];
			if(*(DWORD *)&m_pbyBuff[1] != 0x11b2)
			{
				wAEPOffset = wAEPOffset - 0x1000;
			}

			if(*(DWORD *)&m_pbyBuff[wAEPOffset + 4] == m_dwImageBase)
			{
				m_pMaxPEFile->WriteAEP(*((DWORD *)&m_pbyBuff[wAEPOffset]));
				m_pMaxPEFile->RepairOptionalHeader(0x13, 0x00, 0x00);
				if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
				{
					return REPAIR_SUCCESS;
				}
			}
			break;
		}
	}	
	return REPAIR_FAILED;
}
