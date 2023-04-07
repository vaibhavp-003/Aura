/*======================================================================================
FILE				: PolyCensor.cpp
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
CREATION DATE		: 11 Apr 2011
NOTES				: This is detection module for malwares Censor Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyCensor.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyCensor
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyCensor::CPolyCensor(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyCensor
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		:Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyCensor::~CPolyCensor(void)
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
	Description		: Detection routine for different varients of Censor Family
--------------------------------------------------------------------------------------*/
int CPolyCensor::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(m_wAEPSec == 0 &&
		m_pSectionHeader[m_wAEPSec].Characteristics == 0xC0000040 &&
		m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 3000 &&
		m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData	>= 0x3000 &&
		m_pSectionHeader[m_wNoOfSections-1].Characteristics == 0xC0000040 &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics&IMAGE_FILE_DLL)!=IMAGE_FILE_DLL))
	{
		m_pbyBuff = new BYTE[CENSOR_BUFF_SIZE + MAX_INSTRUCTION_LEN];	
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, CENSOR_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, CENSOR_BUFF_SIZE))
		{
			if(GetCensorAParameters())
			{				
				BYTE bBufferAEP[0x4] = {0};
				DWORD dwAEPOffset = m_objCensorAStruct.dwOriAEPAddress + 0x1118 - 0x05; //Fix Aep offset				
				if(!m_pMaxPEFile->ReadBuffer(bBufferAEP, dwAEPOffset, sizeof(DWORD), sizeof(DWORD)))
				{
					return iRetStatus;
				}

				for(int i = 0; i < 4; i++)
				{
					bBufferAEP[i] ^=  m_objCensorAStruct.dwDecryptionKey; //decryption
				}

				DWORD dwOriAEP = *(DWORD *)bBufferAEP - m_dwImageBase;
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOriAEP, NULL) || 0 == dwOriAEP)
				{
					m_objCensorAStruct.dwOriAEPAddress = dwOriAEP;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.9x.Censor.A"));
					iRetStatus = VIRUS_FILE_REPAIR;
				}
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
	Description		: Repair routine for different varients of Censor Family
--------------------------------------------------------------------------------------*/
int CPolyCensor::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	
	DWORD dwVirusAEP = 0;
	m_pMaxPEFile->Rva2FileOffset(m_dwAEPUnmapped, &dwVirusAEP);
	
	m_pMaxPEFile->WriteAEP(m_objCensorAStruct.dwOriAEPAddress);
	
	DWORD dwOriDataOffset = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - 0x3000;
	m_pMaxPEFile->CopyData(dwOriDataOffset, dwVirusAEP, 0x3000);
		
	if(m_pMaxPEFile->TruncateFile(dwOriDataOffset))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetCensorAParameters
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Collects Repair Parameters for Censor
--------------------------------------------------------------------------------------*/
BOOL CPolyCensor::GetCensorAParameters()
{
	BYTE		B1, B2;
	DWORD		dwLength = 0x00, dwInstructionCnt = 0x00, dwStartAddress = 0x00, dwCheckAdd =0x00;
	DWORD		dwValue = 0x00;
	t_disasm	da;

	while(dwStartAddress < m_dwNoOfBytes)
	{
		if(dwInstructionCnt > 0x150)
		{
			return FALSE;
		}

		memset(&da, 0x00, sizeof(struct t_disasm) * 1);

		B1 = *((BYTE*)&m_pbyBuff[dwStartAddress]);
		B2 = *((BYTE*)&m_pbyBuff[dwStartAddress+1]);

		//Handling for garbage instruction.
		if(B1==0xC1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x03;
			continue;
		}
		if(B1==0xD1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x02;
			continue;
		}
		if(B1==0xD0 && (B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x02;
			continue;
		}
		if(B1==0xD2 && (B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x02;
			continue;
		}
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStartAddress], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwStartAddress))
		{
			break;
		}

		dwInstructionCnt++;
		dwStartAddress += dwLength;
	
		//dwOriAEPAddress + 1118 -> AEP
		if(B1 == 0xE8 && dwValue == 0x00 && dwLength == 0x05 && strstr(da.result, "CALL"))
		{
			dwValue++;
			m_objCensorAStruct.dwOriAEPAddress = dwStartAddress + m_dwAEPMapped;
			continue;
		}
		if(B1 == 0x5F && dwValue == 0x01 && dwLength == 0x01 && strstr(da.result, "POP EDI"))
		{
			dwValue++;
			continue;
		}
		if(B1 == 0x83 && dwValue == 0x02 && dwLength == 0x03 && strstr(da.result, "SUB EDI,") && da.immconst == 0x05)
		{
			dwValue++;
			continue;
		}
		if(B1 == 0x8B && dwValue == 0x03 && dwLength == 0x02 && strstr(da.result, "MOV ESI,EDI"))
		{
			dwValue++;
			continue;
		}
		if(B1 == 0x83 && dwValue == 0x04 && dwLength == 0x03 && strstr(da.result, "ADD ESI,") && da.immconst == 0x1D)
		{
			dwValue++;
			continue;
		}
		if(B1 == 0xB9 && dwValue == 0x05 && dwLength == 0x05 && strstr(da.result, "MOV ECX,") && da.immconst == 0x2356)
		{
			dwValue++;
			continue;
		}
		if(B1 == 0x80 && dwValue == 0x06 && dwLength == 0x03 && strstr(da.result, "XOR BYTE PTR [ESI"))
		{
			m_objCensorAStruct.dwDecryptionKey = da.immconst;
			dwValue++;
			continue;
		}
		if(B1 == 0x46 && dwValue == 0x07 && dwLength == 0x01 && strstr(da.result, "INC ESI"))
		{
			return TRUE;	
		}
	}
	return FALSE;
}