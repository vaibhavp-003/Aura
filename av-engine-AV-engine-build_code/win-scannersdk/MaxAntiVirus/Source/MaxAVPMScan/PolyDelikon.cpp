/*======================================================================================
FILE				: PolyDelikon.cpp
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
NOTES				: This is detection module for malware Delikon Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyDelikon.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyDelikon
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDelikon::CPolyDelikon(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDelikon
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDelikon::~CPolyDelikon(void)
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
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: This function check is file is infected by Delikon by 
					  looking at set of instructions 
--------------------------------------------------------------------------------------*/
int CPolyDelikon::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec ==  m_wNoOfSections - 1 && 
		m_pSectionHeader[m_wNoOfSections-1].Characteristics == 0x80000000 && 
		m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x2000 &&  
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
	{		
		m_pbyBuff = new BYTE[DELIKON_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, DELIKON_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, DELIKON_BUFF_SIZE))
		{
			if(GetDelikonParameters())
			{
				DWORD dwMappedReadoffset = 0;
				m_objDelikonStruct.dwVirtualAddress -= m_dwImageBase;
				m_pMaxPEFile->Rva2FileOffset(m_objDelikonStruct.dwVirtualAddress, &dwMappedReadoffset);
				if(dwMappedReadoffset)
				{
					BYTE	bBuffer[4] = {0x00};
					if(m_pMaxPEFile->ReadBuffer(bBuffer, dwMappedReadoffset + DELIKON_AEP_OFFSET, sizeof(DWORD), sizeof(DWORD)))
					{
						for(int i = 0x00; i < 4; i++)
						{
							bBuffer[i] ^= static_cast<BYTE>(m_objDelikonStruct.dwDecryptionKey);
						}
						m_objDelikonStruct.dwVirtualAddress = *((DWORD*) &bBuffer[0]) - m_dwImageBase;

						if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_objDelikonStruct.dwVirtualAddress, NULL))
						{					
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Delikon"));
							iRetStatus= VIRUS_FILE_REPAIR;
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDelikonParameters
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: To detect Delikon, finding Key and OriginalAEP. It traverse 
					  from AEP and check for some specified instruction.
--------------------------------------------------------------------------------------*/
BOOL CPolyDelikon::GetDelikonParameters()
{
	BYTE		B1, B2;
	DWORD		dwLength = 0x00, dwInstructionCnt = 0x00, dwStartAddress = 0x00;
	DWORD		dwValue = 0x00; // It is used for maintaing sequence of instruction.
	t_disasm	da;
		
	while(dwStartAddress < m_dwNoOfBytes)
	{
		if(dwInstructionCnt > 0x40)
			return FALSE;

		memset(&da, 0x00, sizeof(struct t_disasm) * 1);

		B1 = m_pbyBuff[dwStartAddress];
		B2 = m_pbyBuff[dwStartAddress+1];

		//Handling for garbage instruction.
		if(B1 == 0xC1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwStartAddress += 0x03;
			continue;
		}
		if(B1 == 0xD1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwStartAddress += 0x02;
			continue;
		}
		if(B1 == 0xD0 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwStartAddress+= 0x02;
			continue; 
		}
		if(B1 == 0xD2 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwStartAddress += 0x02;
			continue;
		}
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwStartAddress], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwStartAddress))
		{
			return FALSE;
		}
		dwInstructionCnt++;
		dwStartAddress += dwLength;

		if(B1 == 0x90 && dwLength == 0x01 && strstr(da.result,"NOP"))
		{
			continue;
		}
		if(B1 == 0x56 && dwValue == 0x00 && dwLength == 0x01 && strstr(da.result, "PUSH ESI"))
		{
			dwValue++;
			continue;
		}
		if(B1 == 0x57 && dwValue == 0x01 && dwLength == 0x01 && strstr(da.result, "PUSH EDI"))
		{
			dwValue++;
			continue;
		}
		//Gives counter of decryption loop
		if(B1 == 0xB9 && dwValue == 0x02 && dwLength == 0x05 && strstr(da.result, "MOV ECX,") && 
			da.immconst == 0x1660)
		{
			dwValue++;
			continue;
		}
		//Gives Key 
		if(B1 == 0xBA && dwValue == 0x03 && dwLength == 0x05 && strstr(da.result, "MOV EDX,"))
		{
			m_objDelikonStruct.dwDecryptionKey = da.immconst;
			dwValue++;
			continue;
		}
		//Gives AEP Offset (add 0x59 for Original AEP)
		if(B1 == 0xBE && dwValue == 0x04 && dwLength == 0x05 && strstr(da.result, "MOV ESI,"))
		{
			m_objDelikonStruct.dwVirtualAddress = da.immconst;
			dwValue++;
			continue;
		}
		if(B1 == 0x8B && dwValue == 0x05 && dwLength == 0x02 && strstr(da.result, "MOV EDI,ESI"))
		{
			dwValue++;
			continue;
		}
		if(B1 == 0xAC && dwValue == 0x06 && dwLength == 0x01 && strstr(da.result, "LODS BYTE PTR [ESI]"))
		{			
			dwValue++;
			continue;
		}
		if(B1 == 0xAA && dwValue == 0x08 && dwLength == 0x01)
		{	
			//It is a STOS instruction and when it encounter means virus is detected.
			return TRUE;			
		}
		if(B1 == 0x33 && dwValue == 0x07 && dwLength == 0x02 && strstr(da.result, "XOR EAX,EDX"))
		{			
			dwValue++;
			continue;
		}
	}
	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: Repair routine for different varients of Delikon Family
--------------------------------------------------------------------------------------*/
int CPolyDelikon::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	
	m_pMaxPEFile->WriteAEP(m_objDelikonStruct.dwVirtualAddress);
		
	if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}