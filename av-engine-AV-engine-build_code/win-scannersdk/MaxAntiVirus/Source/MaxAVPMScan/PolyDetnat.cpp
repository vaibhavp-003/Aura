/*======================================================================================
FILE				: PolyDetnat.cpp
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
NOTES				: This is detection module for malware Poly Detnat Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyDetnat.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyDetnat
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDetnat::CPolyDetnat(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDetnat
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDetnat::~CPolyDetnat(void)
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
	Description		: Detection routine for different varients of Detnat Family
--------------------------------------------------------------------------------------*/
int CPolyDetnat::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 2 && 
		m_pSectionHeader[m_wNoOfSections-2].Name[0] == 0x00  && 
		m_pSectionHeader[m_wNoOfSections-2].SizeOfRawData > 0x8500 && 
		m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData <= 0x1000 && 
		(m_pSectionHeader[m_wNoOfSections - 2].Misc.VirtualSize == 0x11000 || m_pSectionHeader[m_wNoOfSections - 2].Misc.VirtualSize == 0x12000 || m_pSectionHeader[m_wNoOfSections - 2].Misc.VirtualSize == 0x13000 )&&
		m_pSectionHeader[m_wNoOfSections - 2].Characteristics  == 0xE0000020 && m_pSectionHeader[m_wNoOfSections - 1].Characteristics  == 0xE0000020)
	{
		if(IsDetnat_E())
		{
			if(m_dwVirusExecStartOffset > m_pSectionHeader[m_wNoOfSections-2].PointerToRawData && 
				m_dwVirusExecStartOffset < (m_pSectionHeader[m_wNoOfSections-2].PointerToRawData + m_pSectionHeader[m_wNoOfSections-2].SizeOfRawData))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Detnat"));
				if(GetDetnatEParameter())
				{
					iRetStatus= VIRUS_FILE_REPAIR;
				}
				else
					iRetStatus = VIRUS_FILE_DELETE;		// For Worm.Detnat.e
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: IsDetnat_E
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection for Detnat.E varient
--------------------------------------------------------------------------------------*/
bool CPolyDetnat::IsDetnat_E()
{
	m_objMaxDisassem.InitializeData();
	
	t_disasm	da;
	BYTE		B1 = 0, B2 = 0, B3 = 0;
	BYTE		byGetJump = 0x00;
	DWORD		dwOffSet = 0x00 , dwInstructionCount = 0x00 , dwLength = 0x00 , dwTemp = 0x00;
	DWORD		dwStack[0x20] = {0} , dwTOS = 0x00 ,dwStackSize = 0x20;
	DWORD		dwEAX = 0, dwEBX = 0, dwECX = 0 , dwEDX = 0, dwESI = 0, dwEDI = 0, dwEBP = 0;
	
	DWORD dwAEPRVA	= m_dwAEPUnmapped;	
	DWORD dwAEPOffset = m_dwVirusExecStartOffset = m_dwAEPMapped;
	
	//Tushar ==> 22 Feb 2011 : Changes to strenthen Detnat.E detection
	if(m_dwAEPUnmapped >= m_pSectionHeader[m_wNoOfSections - 2].VirtualAddress && 
		m_dwAEPUnmapped < m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 2].VirtualAddress)
	{
		byGetJump = 0x01;
	}

	m_pbyBuff = new BYTE[DETNAT_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return false;
	}
	memset(m_pbyBuff, 0, DETNAT_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(!GetBuffer(dwAEPOffset, DETNAT_BUFF_SIZE))  
	{
		return false;
	}

	while(dwOffSet < m_dwNoOfBytes)
	{
		
		if(dwInstructionCount > 0x30)
		{
			return false;
		}
		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		
		B1 = *((BYTE*)&m_pbyBuff[dwOffSet]);
		B2 = *((BYTE*)&m_pbyBuff[dwOffSet+1]);
		B3 = *((BYTE*)&m_pbyBuff[dwOffSet + 0x05]);
		
		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x03;
			continue;
		}
		if(B1==0xD1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x02;
			continue;
		}
		if(B1==0xE2 && (B2>=0xF0 && B2<=0xFF)) // Added for 'LOOP' instruction
		{
			dwOffSet+= 0x02;
			continue;
		}
		if(B1==0x00 && B2 == 0x00 && B3 == 0x00)
		{
			return false;
		}
			
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffSet))
		{
			return false;
		}
		dwInstructionCount++;

		if(dwLength==0x01 && _strcmpi(da.dump, "FFFFFFC3")== 0)
		{
			if(dwTOS == 0x00)
			{				
				return false;
			}
			dwOffSet = dwStack[--dwTOS];
			continue;
		}
		
		if(strstr(da.result ,"PUSH "))
		{
			if(dwTOS == dwStackSize)
			{
				return false;
			}
			if(dwLength == 0x01 && strstr(da.result ,"PUSH EAX"))
			{				
				dwStack[dwTOS++] = dwEAX;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH EBX"))
			{				
				dwStack[dwTOS++] = dwEBX;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH ECX"))
			{
				dwStack[dwTOS++] = dwECX;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH EDX"))
			{
				dwStack[dwTOS++] = dwEDX;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH ESI"))
			{
				dwStack[dwTOS++] = dwESI;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH EDI"))
			{
				dwStack[dwTOS++] = dwEDI;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH EBP"))
			{
				dwStack[dwTOS++] = dwEBP;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x05  && B1 == 0x68 && strstr(da.result ,"PUSH "))
			{
				dwStack[dwTOS++] = da.immconst;
				dwOffSet += dwLength;
				continue;
			}
		}

		if(strstr(da.result,"POP "))
		{
			if(dwTOS == 0x00)
			{
				return false;
			}
			if(dwLength == 0x01 && strstr(da.result , "POP EAX"))
			{
				dwEAX  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01  && strstr(da.result , "POP EBX"))
			{
				dwEBX  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01 && strstr(da.result , "POP ECX"))
			{
				dwECX  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01 && strstr(da.result , "POP EDX"))
			{
				dwEDX  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01  && strstr(da.result , "POP ESI"))
			{
				dwESI  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01  && strstr(da.result , "POP EDI"))
			{
				dwEDI  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01  && strstr(da.result , "POP EBP"))
			{
				dwEBP  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}
		}
		if(dwLength==0x05 && B1==0xE9 && strstr(da.result, "JMP "))
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffSet+1]);
			dwOffSet += dwLength + dwTemp;
			dwAEPRVA = dwAEPRVA + dwOffSet;
			if(dwAEPRVA >= m_pSectionHeader[m_wNoOfSections - 2].VirtualAddress && 
				dwAEPRVA < m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 2].VirtualAddress)
			{
				m_pMaxPEFile->Rva2FileOffset(dwAEPRVA, &dwOffSet);
				if(dwOffSet == 0x00)
				{
					return false;
				}
				dwAEPOffset = dwOffSet;
				m_dwVirusExecStartOffset = dwOffSet;
				byGetJump = 0x01;

				if(!GetBuffer(dwOffSet, DETNAT_BUFF_SIZE))
					return false;

				dwOffSet = 0x00;
				continue;
			}
			dwOffSet += dwTemp;
			continue;
		}

		if(dwLength==0x02 && B1==0xEB && strstr(da.result, "JMP SHORT")) 
		{
			if(B2 > 0x7F)
			{
				dwOffSet = dwOffSet -(0x100 - B2) + dwLength;							
			}
			else
			{
				dwOffSet += dwLength + B2;
				
			}
			dwAEPOffset += dwOffSet;
			continue;
		}	
		if(dwLength==0x05 && B1==0xE8 && strstr(da.result, "CALL "))
		{
			if(dwTOS == dwStackSize)
			{
				return false;
			}
			dwStack[dwTOS++] = dwOffSet + dwLength;
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffSet+1]);
			if(byGetJump == 0x01)
			{
				if(((dwTemp & 0x80000000) == 0x80000000 || dwTemp == 0x04))
				{
					return true;
				}
				else
				{
					return false;
				}
			}
			dwOffSet += dwTemp  + dwLength;
			continue;
		}
		if(dwLength==0x03 && strstr(da.result, "ADD EAX,"))
		{
			dwEAX += da.immconst;
			dwOffSet += dwLength;
			continue;
		}
		if(dwLength==0x03 && strstr(da.result, "ADD EBX,"))
		{
			dwEBX += da.immconst;
			dwOffSet += dwLength;
			continue;
		}
		if(dwLength==0x03 && strstr(da.result, "ADD ECX,"))
		{
			dwECX += da.immconst;
			dwOffSet += dwLength;
			continue;
		}
		if(dwLength==0x03 && strstr(da.result, "ADD EDX,"))
		{
			dwEDX += da.immconst;
			dwOffSet += dwLength;
			continue;
		}
		if(dwLength==0x03 && strstr(da.result, "ADD ESI,"))
		{
			dwESI += da.immconst;
			dwOffSet += dwLength;
			continue;
		}
		if(dwLength==0x03 && strstr(da.result, "ADD EDI,"))
		{
			dwEDI += da.immconst;
			dwOffSet += dwLength;
			continue;
		}
		if(dwLength==0x03 && strstr(da.result, "ADD EBP,"))
		{
			dwEBP += da.immconst;
			dwOffSet += dwLength;
			continue;
		}

		dwOffSet += dwLength;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDetnatEParameter
	In Parameters	: 
	Out Parameters	: true if success esle false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Collects the Detnat.E information
--------------------------------------------------------------------------------------*/
bool CPolyDetnat::GetDetnatEParameter() 
{
	m_objMaxDisassem.InitializeData();
	
	t_disasm	da;
	BYTE		B1 , B2 , B3;
	DWORD		dwOffSet = 0x00 , dwInstructionCount = 0x00 /*It is not used*/, dwLength = 0x00 , dwTemp = 0x00 ,dwSize = 0x00;
	DWORD		dwReadOffset = 0x00;
	DWORD		dwStack[0x100] = {0x00}, dwTOS = 0x00 , dwStackSize = 0x100;//Stack variables used for mainataining push pop sequance.
	DWORD		dwEBP , dwEAX , dwEBX , dwECX , dwEDX , dwESI , dwEDI;//Registers that are emulated
	BYTE		byCallFlag = 0x01;/*it is used for to detect second call instruction is encounter or not*/
	BYTE		byDecStart = 0x00;//It is set when decryption is start and reset when finish.
	DWORD		byDecryptionFinish = 0x00;//It is set when decryption is finished and reset when another start.
	int			iCallCount = 0x00 ;
	char		*ptr = NULL ,szREG[4] = {0};//It is used after decryption get finished.
	DWORD		dwDecryptionCount = 0x00;//It store number of decryption is done


	B1 = B2 = B3 = 0x00;
	dwEAX = dwEBX = dwECX = dwEDX = dwESI = dwEDI = dwEBP = 0x00;
	dwSize = m_pSectionHeader[m_wNoOfSections-2].SizeOfRawData;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[dwSize + MAX_INSTRUCTION_LEN];
	if(m_pbyBuff == NULL)
	{
		return false;
	}

	memset(m_pbyBuff, 0x00, dwSize + MAX_INSTRUCTION_LEN);
	dwReadOffset = m_pSectionHeader[m_wNoOfSections-2].PointerToRawData;

	if(!GetBuffer(dwReadOffset, dwSize))   
		return false;

	dwOffSet = m_dwVirusExecStartOffset - m_pSectionHeader[m_wNoOfSections-2].PointerToRawData;

	while(dwOffSet < m_dwNoOfBytes)
	{

		if(dwInstructionCount > 0x550)
		{
			return false;
		}
		memset(&da, 0x00, sizeof(struct t_disasm)*1);

		B1 = m_pbyBuff[dwOffSet];
		B2 = m_pbyBuff[dwOffSet+1];
		B3 = m_pbyBuff[dwOffSet + 0x05];

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x03;
			continue;
		}
		if(B1==0xD1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x02;
			continue;
		}
		if(B1==0xE2 && (B2>=0xF0 && B2<=0xFF)) // Added for 'LOOP' instruction
		{
			dwOffSet+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffSet))
		{
			return false;
		}

		dwInstructionCount++;

		//It is for RET instruction
		if(dwLength==0x01 && _strcmpi(da.dump, "FFFFFFC3")== 0)
		{
			if(dwTOS == 0x00)
			{
				return false;
			}
			dwOffSet = dwStack[--dwTOS];
			continue;
		}

		if(dwLength == 0x01 && (strstr(da.result ,"PUSHAD") || strstr(da.result ,"PUSHFD")))
		{
			if(dwTOS >= dwStackSize - 0x07)
			{
				return false;
			}
			dwStack[dwTOS++] = dwEAX;
			dwStack[dwTOS++] = dwEBX;
			dwStack[dwTOS++] = dwECX;
			dwStack[dwTOS++] = dwEDX;
			dwStack[dwTOS++] = dwESI;
			dwStack[dwTOS++] = dwEDI;
			dwStack[dwTOS++] = dwEBP;
			dwOffSet += dwLength;
			continue;
		}
		if(dwLength == 0x01 && (strstr(da.result ,"POPAD") || (strstr(da.result ,"POPFD"))))
		{
			if(dwTOS <= 0x06)
			{
				return false;
			}

			dwEBP = dwStack[--dwTOS];
			dwEDI = dwStack[--dwTOS];
			dwESI = dwStack[--dwTOS];
			dwEDX = dwStack[--dwTOS];
			dwECX = dwStack[--dwTOS];
			dwEBX = dwStack[--dwTOS];
			dwEAX = dwStack[--dwTOS];
			dwOffSet += dwLength;
			continue;
		}


		if(strstr(da.result ,"PUSH "))
		{
			if(dwTOS == dwStackSize)
			{
				return false;
			}
			if(dwLength == 0x01 && strstr(da.result ,"PUSH EAX"))
			{				
				dwStack[dwTOS++] = dwEAX;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH EBX"))
			{				
				dwStack[dwTOS++] = dwEBX;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH ECX"))
			{
				dwStack[dwTOS++] = dwECX;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH EDX"))
			{
				dwStack[dwTOS++] = dwEDX;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH ESI"))
			{
				dwStack[dwTOS++] = dwESI;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH EDI"))
			{
				dwStack[dwTOS++] = dwEDI;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01  && strstr(da.result ,"PUSH EBP"))
			{
				dwStack[dwTOS++] = dwEBP;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x05  && B1 == 0x68 && strstr(da.result ,"PUSH "))
			{
				dwStack[dwTOS++] = da.immconst;
				dwOffSet += dwLength;
				continue;
			}
		}

		if(strstr(da.result,"POP "))
		{
			if(dwTOS == 0x00)
			{
				return false;
			}
			if(dwLength == 0x01  && strstr(da.result , "POP EAX"))
			{
				dwEAX  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01  && strstr(da.result , "POP EBX"))
			{
				dwEBX  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01  && strstr(da.result , "POP ECX"))
			{
				dwECX  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01  && strstr(da.result , "POP EDX"))
			{
				dwEDX  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01  && strstr(da.result , "POP ESI"))
			{
				dwESI  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01  && strstr(da.result , "POP EDI"))
			{
				dwEDI  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x01 && strstr(da.result , "POP EBP"))
			{
				dwEBP  = dwStack[--dwTOS];
				dwOffSet += dwLength;
				continue;
			}
		}
		if(strstr(da.result ,"J"))
		{
			if(dwLength == 0x02 && B1 == 0x74 && B2 == 0x0F && strstr(da.result ,"JE SHORT") && byDecryptionFinish == 0x03)
			{
				dwOffSet +=dwLength;
				continue;
			}

			if(dwLength==0x05 && B1==0xE9 && strstr(da.result, "JMP "))
			{
				dwTemp = *((DWORD*)&m_pbyBuff[dwOffSet+1]);
				dwOffSet += dwTemp + dwLength;
				continue;
			}
			if(dwLength==0x06 && strstr(da.result, "J"))
			{
				if(byDecryptionFinish == 0x01)
				{
					dwOffSet+=dwLength;
					byDecryptionFinish = 0x02;
					continue;
				}
				dwTemp = *((DWORD*)&m_pbyBuff[dwOffSet+2]);
				dwOffSet += dwTemp + dwLength;
				continue;
			}
			if(strstr(da.result,"JMP E"))
			{
				if(dwLength==0x02 && strstr(da.result, "JMP EAX"))
				{
					dwOffSet = dwEAX;
					continue;
				}
				if(dwLength==0x02 && strstr(da.result, "JMP EBX"))
				{
					dwOffSet = dwEBX;
					continue;
				}
				if(dwLength==0x02 && strstr(da.result, "JMP ECX"))
				{
					dwOffSet = dwECX;
					continue;
				}
				if(dwLength==0x02 && strstr(da.result, "JMP EDX"))
				{
					dwOffSet = dwEDX;
					continue;
				}
				if(dwLength==0x02 && strstr(da.result, "JMP ESI"))
				{
					dwOffSet = dwESI;
					continue;
				}
				if(dwLength==0x02 && strstr(da.result, "JMP EDI"))
				{
					dwOffSet = dwEDI;
					continue;
				}
				if(dwLength==0x02 && strstr(da.result, "JMP EBP"))
				{
					dwOffSet = dwEBP;
					continue;
				}
			}
			if(dwLength==0x02 && strstr(da.result, "J")) 
			{
				if(B2 > 0x7F)
				{
					dwOffSet = dwOffSet -(0x100 - B2) + dwLength;							
				}
				else
				{
					dwOffSet += dwLength + B2;

				}
				continue;
			}
		}
		if(strstr(da.result ,"NOT DWORD PTR ["))
		{
			if(dwLength == 0x02 && strstr(da.result,"NOT DWORD PTR [EAX]"))
			{
				if(dwEAX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEAX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEAX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = ~(*(DWORD *)(&m_pbyBuff[i]));
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"NOT DWORD PTR [EBX]"))
			{
				if(dwEBX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEBX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEBX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = ~(*(DWORD *)(&m_pbyBuff[i]));
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"NOT DWORD PTR [ECX]"))
			{
				if(dwECX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwECX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwECX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = ~(*(DWORD *)(&m_pbyBuff[i]));
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"NOT DWORD PTR [EDX]"))
			{
				if(dwEDX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEDX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEDX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = ~(*(DWORD *)(&m_pbyBuff[i]));
				}
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x02 && strstr(da.result,"NOT DWORD PTR [ESI]"))
			{
				if(dwESI >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwESI % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwESI;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = ~(*(DWORD *)(&m_pbyBuff[i]));
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"NOT DWORD PTR [EDI]"))
			{
				if(dwEDI >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEDI % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEDI;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = ~(*(DWORD *)(&m_pbyBuff[i]));
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"NOT DWORD PTR [EBP]"))
			{
				if(dwEBP >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEBP % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEBP;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = ~(*(DWORD *)(&m_pbyBuff[i]));
				}
				dwOffSet += dwLength;
				continue;
			}
		}
		if(strstr(da.result,"INC DWORD PTR ["))
		{
			if(dwLength == 0x02 && strstr(da.result,"INC DWORD PTR [EAX]"))
			{
				if(dwEAX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEAX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEAX;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) += 0x01;
				}

				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"INC DWORD PTR [EBX]"))
			{
				if(dwEBX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEBX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEBX;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) += 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"INC DWORD PTR [ECX]"))
			{
				if(dwECX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwECX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwECX;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) += 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"INC DWORD PTR [EDX]"))
			{
				if(dwEDX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEDX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEDX;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) += 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"INC DWORD PTR [ESI]"))
			{
				if(dwESI >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwESI % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwESI;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) += 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"INC DWORD PTR [EDI]"))
			{
				if(dwEDI >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEDI % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEDI;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) += 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"INC DWORD PTR [EBP]"))
			{
				if(dwEBP >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEBP % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEBP;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) += 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
		}
		if(dwLength == 0x02 && strstr(da.result,"DEC DWORD PTR ["))
		{
			if(dwLength == 0x02 && strstr(da.result,"DEC DWORD PTR [EAX]"))
			{
				if(dwEAX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEAX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEAX;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) -= 0x01;
				}

				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"DEC DWORD PTR [EBX]"))
			{
				if(dwEBX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEBX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEBX;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) -= 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"DEC DWORD PTR [ECX]"))
			{
				if(dwECX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwECX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwECX;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) -= 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"DEC DWORD PTR [EDX]"))
			{
				if(dwEDX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEDX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEDX;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) -= 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"DEC DWORD PTR [ESI]"))
			{
				if(dwESI >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwESI % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwESI;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) -= 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"DEC DWORD PTR [EDI]"))
			{
				if(dwEDI >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEDI % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEDI;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) -= 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x02 && strstr(da.result,"DEC DWORD PTR [EBP]"))
			{
				if(dwEBP >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEBP % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEBP;i>=0x00;i-=0x04)
				{
					*((DWORD *) (&m_pbyBuff[i])) -= 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
		}
		if(strstr(da.result ,"ROL DWORD PTR ["))
		{
			if(dwLength == 0x03 && strstr(da.result,"ROL DWORD PTR [EAX],"))
			{
				if(dwEAX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEAX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEAX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotl((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}

				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result,"ROL DWORD PTR [EBX],"))
			{
				if(dwEBX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEBX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEBX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotl((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result,"ROL DWORD PTR [ECX],"))
			{
				if(dwECX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwECX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwECX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotl((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result,"ROL DWORD PTR [EDX],"))
			{
				if(dwEDX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEDX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEDX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotl((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x03 && strstr(da.result,"ROL DWORD PTR [ESI],"))
			{
				if(dwESI >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwESI % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwESI;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotl((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result,"ROL DWORD PTR [EDI],"))
			{
				if(dwEDI >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEDI % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEDI;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotl((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result,"ROL DWORD PTR [EBP],"))
			{
				if(dwEBP >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEBP % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEBP;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotl((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}
		}

		if(strstr(da.result ,"ROR DWORD PTR ["))
		{
			if(dwLength == 0x03 && strstr(da.result,"ROR DWORD PTR [EAX],"))
			{
				if(dwEAX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEAX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEAX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotr((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}

				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result,"ROR DWORD PTR [EBX],"))
			{
				if(dwEBX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEBX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEBX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotr((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result,"ROR DWORD PTR [ECX],"))
			{
				if(dwECX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwECX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwECX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotr((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result,"ROR DWORD PTR [EDX],"))
			{
				if(dwEDX >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEDX % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEDX;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotr((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength == 0x03 && strstr(da.result,"ROR DWORD PTR [ESI],"))
			{
				if(dwESI >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwESI % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwESI;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotr((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result,"ROR DWORD PTR [EDI],"))
			{
				if(dwEDI >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEDI % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEDI;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotr((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result,"ROR DWORD PTR [EBP],"))
			{
				if(dwEBP >= m_dwNoOfBytes)
				{
					return false;
				}
				if(dwEBP % 0x04 != 0x00)
				{
					return false;
				}
				for(long int i = dwEBP;i>=0x00;i-=0x04)
				{
					(*(DWORD *)(&m_pbyBuff[i])) = _lrotr((*(DWORD *)(&m_pbyBuff[i])) , da.immconst);
				}
				dwOffSet += dwLength;
				continue;
			}
		}
		//Add start
		if(strstr(da.result,"ADD "))
		{
			if(strstr(da.result ,"ADD ESP,") && dwLength == 0x03 && byCallFlag)
			{
				dwTOS = dwTOS - (da.immconst/0x04);
				dwOffSet += dwLength;
				continue;
			}
			if(strstr(da.result,"ADD DWORD PTR ["))
			{
				if(dwLength == 0x06 && strstr(da.result,"ADD DWORD PTR [EAX]"))
				{
					if(dwEAX >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEAX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEAX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) += da.immconst;
					}

					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"ADD DWORD PTR [EBX]"))
				{
					if(dwEBX >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEBX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEBX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) += da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"ADD DWORD PTR [ECX]"))
				{
					if(dwECX >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwECX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwECX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) += da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"ADD DWORD PTR [EDX]"))
				{
					if(dwEDX >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEDX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEDX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) += da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}

				if(dwLength == 0x06 && strstr(da.result,"ADD DWORD PTR [ESI]"))
				{
					if(dwESI >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwESI % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwESI;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) += da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"ADD DWORD PTR [EDI]"))
				{
					if(dwEDI >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEDI % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEDI;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) += da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"ADD DWORD PTR [EBP]"))
				{
					if(dwEBP >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEBP % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEBP;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) += da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"ADD ["))
			{
				if(strstr(da.result ,",EAX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) += dwEAX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) += dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EBX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) += dwEBX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) += dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",ECX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) += dwECX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) += dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EDX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) += dwEDX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) += dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",ESI") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) += dwESI;
					(*(DWORD *)(&m_pbyBuff[0xA9])) += dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EDI") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) += dwEDI;
					(*(DWORD *)(&m_pbyBuff[0xA9])) += dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EBP") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) += dwEBP;
					(*(DWORD *)(&m_pbyBuff[0xA9])) += dwEBP;
					dwOffSet += dwLength;
					continue;
				}				
			}

			//Another ADD

			if(strstr(da.result,"ADD EAX,"))
			{
				if(strstr(da.result ,"ADD EAX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX + dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EAX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX + dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EAX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX + dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EAX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX + dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EAX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX + dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EAX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX + dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EAX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX + dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EAX,") && byCallFlag)
				{
					dwEAX = dwEAX + da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"ADD EBX,"))
			{
				if(strstr(da.result ,"ADD EBX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX + dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX + dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX + dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX + dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX + dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX + dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX + dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBX,") && byCallFlag)
				{
					dwEBX = dwEBX + da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"ADD ECX,"))
			{
				if(strstr(da.result ,"ADD ECX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX + dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ECX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX + dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ECX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX + dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ECX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX + dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ECX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX + dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ECX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX + dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ECX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX + dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ECX,") && byCallFlag)
				{
					dwECX = dwECX + da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"ADD EDX,"))
			{
				if(strstr(da.result ,"ADD EDX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX + dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX + dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX + dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX + dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX + dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX + dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX + dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDX,") && byCallFlag)
				{
					dwEDX = dwEDX + da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"ADD ESI,"))
			{
				if(strstr(da.result ,"ADD ESI,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI + dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ESI,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI + dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ESI,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI + dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ESI,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI + dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ESI,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI + dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ESI,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI + dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ESI,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI + dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD ESI,") && byCallFlag)
				{
					dwESI = dwESI + da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"ADD EDI,"))
			{
				if(strstr(da.result ,"ADD EDI,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI + dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDI,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI + dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDI,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI + dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDI,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI + dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDI,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI + dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDI,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI + dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDI,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI + dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EDI,") && byCallFlag)
				{
					dwEDI = dwEDI + da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"ADD EBP,"))
			{
				if(strstr(da.result ,"ADD EBP,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP + dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBP,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP + dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBP,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP + dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBP,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP + dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBP,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP + dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBP,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP + dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBP,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP + dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"ADD EBP,") && byCallFlag)
				{
					dwEBP = dwEBP + da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
		}
		//Add finish

		//SUB START
		if(strstr(da.result ,"SUB "))
		{
			if(strstr(da.result ,"SUB DWORD PTR ["))
			{
				if(dwLength == 0x06 && strstr(da.result,"SUB DWORD PTR [EAX]"))
				{
					if(dwEAX >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEAX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEAX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) -= da.immconst;
					}

					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"SUB DWORD PTR [EBX]"))
				{
					if(dwEBX >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEBX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEBX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) -= da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"SUB DWORD PTR [ECX]"))
				{
					if(dwECX >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwECX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwECX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) -= da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"SUB DWORD PTR [EDX]"))
				{
					if(dwEDX >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEDX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEDX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) -= da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}

				if(dwLength == 0x06 && strstr(da.result,"SUB DWORD PTR [ESI]"))
				{
					if(dwESI >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwESI % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwESI;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) -= da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"SUB DWORD PTR [EDI]"))
				{
					if(dwEDI >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEDI % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEDI;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) -= da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"SUB DWORD PTR [EBP]"))
				{
					if(dwEBP >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEBP % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEBP;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) -= da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"SUB [E"))
			{
				if(strstr(da.result ,",EAX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) -= dwEAX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) -= dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EBX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) -= dwEBX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) -= dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",ECX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) -= dwECX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) -= dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EDX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) -= dwEDX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) -= dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",ESI") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) -= dwESI;
					(*(DWORD *)(&m_pbyBuff[0xA9])) -= dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EDI") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) -= dwEDI;
					(*(DWORD *)(&m_pbyBuff[0xA9])) -= dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EBP") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) -= dwEBP;
					(*(DWORD *)(&m_pbyBuff[0xA9])) -= dwEBP;
					dwOffSet += dwLength;
					continue;
				}

			}

			//Another sub
			if(strstr(da.result ,"SUB EAX,"))
			{
				if(strstr(da.result ,"SUB EAX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX - dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EAX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX - dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EAX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX - dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EAX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX - dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EAX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX - dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EAX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX - dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EAX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX - dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EAX,") && byCallFlag)
				{
					dwEAX = dwEAX - da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"SUB EBX,"))
			{
				if(strstr(da.result ,"SUB EBX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX - dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX - dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX - dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX - dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX - dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX - dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX - dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBX,") && byCallFlag)
				{
					dwEBX = dwEBX - da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"SUB ECX,"))
			{
				if(strstr(da.result ,"SUB ECX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX - dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ECX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX - dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ECX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX - dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ECX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX - dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ECX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX - dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ECX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX - dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ECX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX - dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ECX,") && byCallFlag)
				{
					dwECX = dwECX - da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"SUB EDX,"))
			{
				if(strstr(da.result ,"SUB EDX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX - dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX - dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX - dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX - dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX - dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX - dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX - dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDX,")&& byCallFlag)
				{
					dwEDX = dwEDX - da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"SUB ESI,"))
			{
				if(strstr(da.result ,"SUB ESI,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI - dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ESI,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI - dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ESI,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI - dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ESI,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI - dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ESI,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI - dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ESI,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI - dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ESI,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI - dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB ESI,")&& byCallFlag)
				{
					dwESI = dwESI - da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"SUB EDI,"))
			{
				if(strstr(da.result ,"SUB EDI,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI - dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDI,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI - dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDI,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI - dwECX;
					//byCallFlag = 0x00;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDI,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI - dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDI,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI - dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDI,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI - dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDI,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI - dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EDI,") && byCallFlag)
				{
					dwEDI = dwEDI - da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"SUB EBP,"))
			{
				if(strstr(da.result ,"SUB EBP,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP - dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBP,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP - dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBP,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP - dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBP,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP - dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBP,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP - dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBP,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP - dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBP,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP - dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"SUB EBP,") && byCallFlag)
				{
					dwEBP = dwEBP - da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
		}
		//XOR
		if(strstr(da.result ,"XOR "))
		{
			if(strstr(da.result,"XOR DWORD PTR "))
			{
				if(dwLength == 0x06 && strstr(da.result,"XOR DWORD PTR [EAX]"))
				{
					if(dwEAX >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEAX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEAX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) ^= da.immconst;
					}

					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"XOR DWORD PTR [EBX]"))
				{
					if(dwEBX >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEBX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEBX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) ^= da.immconst;
					}
					(*(DWORD *)(&m_pbyBuff[dwEBX])) ^= da.immconst;
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"XOR DWORD PTR [ECX]"))
				{
					if(dwECX >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwECX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwECX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) ^= da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"XOR DWORD PTR [EDX]"))
				{
					if(dwEDX >= m_dwNoOfBytes)
					{
						return false;
					}

					if(dwEDX % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEDX;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) ^= da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}

				if(dwLength == 0x06 && strstr(da.result,"XOR DWORD PTR [ESI]"))
				{
					if(dwESI >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwESI % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwESI;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) ^= da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"XOR DWORD PTR [EDI]"))
				{
					if(dwEDI >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEDI % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEDI;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) ^= da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
				if(dwLength == 0x06 && strstr(da.result,"XOR DWORD PTR [EBP]"))
				{
					if(dwEBP >= m_dwNoOfBytes)
					{
						return false;
					}
					if(dwEBP % 0x04 != 0x00)
					{
						return false;
					}
					for(long int i = dwEBP;i>=0x00;i-=0x04)
					{
						(*(DWORD *)(&m_pbyBuff[i])) ^= da.immconst;
					}
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"XOR ["))
			{
				if(strstr(da.result ,",EAX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) ^= dwEAX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) ^= dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EBX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) ^= dwEBX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) ^= dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",ECX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) ^= dwECX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) ^= dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EDX") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) ^= dwEDX;
					(*(DWORD *)(&m_pbyBuff[0xA9])) ^= dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",ESI") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) ^= dwESI;
					(*(DWORD *)(&m_pbyBuff[0xA9])) ^= dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EDI") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) ^= dwEDI;
					(*(DWORD *)(&m_pbyBuff[0xA9])) ^= dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,",EBP") && dwLength == 0x02 && byDecryptionFinish == 0x03)
				{
					(*(DWORD *)(&m_pbyBuff[0xA5])) ^= dwEBP;
					(*(DWORD *)(&m_pbyBuff[0xA9])) ^= dwEBP;
					dwOffSet += dwLength;
					continue;
				}

			}
			if(strstr(da.result,"XOR EAX,"))
			{
				if(strstr(da.result ,"XOR EAX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX ^ dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EAX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX ^ dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EAX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX ^ dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EAX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX ^ dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EAX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX ^ dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EAX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX ^ dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EAX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEAX = dwEAX ^ dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EAX,") && byCallFlag)
				{
					dwEAX = dwEAX ^ da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"XOR EBX,"))
			{
				if(strstr(da.result ,"XOR EBX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX ^ dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX ^ dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX ^ dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX ^ dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX ^ dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX ^ dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEBX = dwEBX ^ dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBX,") && byCallFlag)
				{
					dwEBX = dwEBX ^ da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"XOR ECX,"))
			{
				if(strstr(da.result ,"XOR ECX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX ^ dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ECX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX ^ dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ECX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX ^ dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ECX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX ^ dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ECX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX ^ dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ECX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX ^ dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ECX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwECX = dwECX ^ dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ECX,") && byCallFlag)
				{
					dwECX = dwECX ^ da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"XOR EDX,"))
			{
				if(strstr(da.result ,"XOR EDX,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX ^ dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDX,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX ^ dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDX,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX ^ dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDX,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX ^ dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDX,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX ^ dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDX,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX ^ dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDX,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEDX = dwEDX ^ dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDX,") && byCallFlag)
				{
					dwEDX = dwEDX ^ da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"XOR ESI,"))
			{
				if(strstr(da.result ,"XOR ESI,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI ^ dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ESI,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI ^ dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ESI,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI ^ dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ESI,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI ^ dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ESI,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI ^ dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ESI,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI ^ dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ESI,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwESI = dwESI ^ dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR ESI,") && byCallFlag)
				{
					dwESI = dwESI ^ da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"XOR EDI,"))
			{
				if(strstr(da.result ,"XOR EDI,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI ^ dwEAX;
					dwOffSet += dwLength;
					continue;
				}

				if(strstr(da.result ,"XOR EDI,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI ^ dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDI,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI ^ dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDI,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI ^ dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDI,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI ^ dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDI,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI ^ dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDI,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEDI = dwEDI ^ dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EDI,") && byCallFlag)
				{
					dwEDI = dwEDI ^ da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result,"XOR EBP,"))
			{
				if(strstr(da.result ,"XOR EBP,EAX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP ^ dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBP,EBX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP ^ dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBP,ECX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP ^ dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBP,EDX") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP ^ dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBP,ESI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP ^ dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBP,EDI") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP ^ dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBP,EBP") && dwLength == 0x02 && byCallFlag)
				{
					dwEBP = dwEBP ^ dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"XOR EBP,") && byCallFlag)
				{
					dwEBP = dwEBP ^ da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
		}


		if(dwLength == 0x06 && strstr(da.result ,"MOV [E") && strstr(da.result ,","))
		{
			dwDecryptionCount++;
			if(dwDecryptionCount>0x09)
			{
				return false;
			}
			ptr = strstr(da.result ,",");
			ptr++;
			for(int i = 0x00;i<3; i++)
			{
				szREG[i] = ptr[i];
			}
			szREG[3] = '\0';
			if(strstr(szREG,"EAX"))
			{
				dwOffSet = dwEAX;
				if(dwEAX == 0x00)
				{
					if(m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0xE8)
					{
						byDecryptionFinish = 0x03;
						continue;
					}
					else
					{
						return false;
					}
				}
				byDecryptionFinish = 0x00;
				continue;
			}
			if(strstr(szREG,"EBX"))
			{
				dwOffSet = dwEBX;
				if(dwEBX == 0x00)
				{
					if(m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0xE8)
					{
						byDecryptionFinish = 0x03;
						continue;
					}
					else
					{
						return false;
					}
				}
				byDecryptionFinish = 0x00;
				continue;
			}
			if(strstr(szREG,"ECX"))
			{
				dwOffSet = dwECX;
				if(dwECX == 0x00)
				{
					if(m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0xE8)
					{
						byDecryptionFinish = 0x03;
						continue;
					}
					else
					{
						return false;
					}
				}
				byDecryptionFinish = 0x00;
				continue;
			}
			if(strstr(szREG,"EDX"))
			{
				dwOffSet = dwEDX;
				if(dwEDX == 0x00)
				{
					if(m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0xE8)
					{
						byDecryptionFinish = 0x03;
						continue;
					}
					else
					{
						return false;
					}
				}
				byDecryptionFinish = 0x00;
				continue;
			}
			if(strstr(szREG,"ESI"))
			{
				dwOffSet = dwESI;
				if(dwESI == 0x00)
				{
					if(m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0xE8)
					{
						byDecryptionFinish = 0x03;
						continue;
					}
					else
					{
						return false;
					}
				}
				byDecryptionFinish = 0x00;
				continue;
			}
			if(strstr(szREG,"EDI"))
			{
				dwOffSet = dwEDI;
				if(dwEDI == 0x00)
				{
					if(m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0xE8)
					{
						byDecryptionFinish = 0x03;
						continue;
					}
					else
					{
						return false;
					}
				}
				byDecryptionFinish = 0x00;
				continue;
			}
			if(strstr(szREG,"EBP"))
			{
				dwOffSet = dwEBP;
				if(dwEBP == 0x00)
				{
					if(m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0xE8)
					{
						byDecryptionFinish = 0x03;
						continue;
					}
					else
					{
						return false;
					}
				}
				byDecryptionFinish = 0x00;
				continue;
			}
		}
		if(strstr(da.result,"MOV "))
		{	
			if(strstr(da.result ,"MOV EAX,"))
			{	
				if(strstr(da.result , "MOV EAX,") && (dwLength == 0x05 || dwLength == 0x06))
				{
					dwEAX = da.immconst;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EAX,EAX"))
				{
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EAX,EBX"))
				{
					dwEAX = dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EAX,ECX"))
				{
					dwEAX = dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EAX,EDX"))
				{
					dwEAX = dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EAX,ESI"))
				{
					dwEAX = dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EAX,EDI"))
				{
					dwEAX = dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EAX,EBP"))
				{
					dwEAX = dwEBP;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"MOV EBX,"))
			{
				if(strstr(da.result ,"MOV EBX,EBX"))
				{
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBX,EAX"))
				{
					dwEBX = dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBX,ECX"))
				{
					dwEBX = dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBX,EDX"))
				{
					dwEBX = dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBX,ESI"))
				{
					dwEBX = dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBX,EDI"))
				{
					dwEBX = dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBX,EBP"))
				{
					dwEBX = dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result , "MOV EBX,") && (dwLength == 0x05 || dwLength == 0x06))
				{
					dwEBX = da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"MOV ECX,"))
			{
				if(strstr(da.result ,"MOV ECX,ECX"))
				{
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ECX,EAX"))
				{
					dwECX = dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ECX,EBX"))
				{
					dwECX = dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ECX,EDX"))
				{
					dwECX = dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ECX,ESI"))
				{
					dwECX = dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ECX,EDI"))
				{
					dwECX = dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ECX,EBP"))
				{
					dwECX = dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result , "MOV ECX,") && (dwLength == 0x05 || dwLength == 0x06))
				{
					dwECX = da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"MOV EDX,"))
			{
				if(strstr(da.result ,"MOV EDX,EDX"))
				{
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDX,EAX"))
				{
					dwEDX = dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDX,EBX"))
				{
					dwEDX = dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDX,ECX"))
				{
					dwEDX = dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDX,ESI"))
				{
					dwEDX = dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDX,EDI"))
				{
					dwEDX = dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDX,EBP"))
				{
					dwEDX = dwEBP;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result , "MOV EDX,") && (dwLength == 0x05 || dwLength == 0x06))
			{
				dwEDX = da.immconst;
				dwOffSet += dwLength;
				continue;
			}
			if(strstr(da.result ,"MOV ESI,"))
			{
				if(strstr(da.result ,"MOV ESI,ESI"))
				{
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ESI,EAX"))
				{
					dwESI = dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ESI,EBX"))
				{
					dwESI = dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ESI,ECX"))
				{
					dwESI = dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ESI,EDX"))
				{
					dwESI = dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ESI,EDI"))
				{
					dwESI = dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV ESI,EBP"))
				{
					dwESI = dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result , "MOV ESI,") && (dwLength == 0x05 || dwLength == 0x06))
				{
					dwESI = da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"MOV EDI,"))
			{
				if(strstr(da.result ,"MOV EDI,EDI"))
				{
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDI,EAX"))
				{
					dwEDI = dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDI,EBX"))
				{
					dwEDI = dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDI,ECX"))
				{
					dwEDI = dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDI,EDX"))
				{
					dwEDI = dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDI,ESI"))
				{
					dwEDI = dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EDI,EBP"))
				{
					dwEDI = dwEBP;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result , "MOV EDI,") && (dwLength == 0x05 || dwLength == 0x06))
				{
					dwEDI = da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
			if(strstr(da.result ,"MOV EBP,"))
			{
				if(strstr(da.result ,"MOV EBP,EAX"))
				{
					dwEBP = dwEAX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBP,EBX"))
				{
					dwEBP = dwEBX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBP,ECX"))
				{
					dwEBP = dwECX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBP,EDX"))
				{
					dwEBP = dwEDX;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBP,ESI"))
				{
					dwEBP = dwESI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBP,EDI"))
				{
					dwEBP = dwEDI;
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result ,"MOV EBP,EBP"))
				{
					dwOffSet += dwLength;
					continue;
				}
				if(strstr(da.result , "MOV EBP,") && (dwLength == 0x05 || dwLength == 0x06))
				{
					dwEBP = da.immconst;
					dwOffSet += dwLength;
					continue;
				}
			}
		}




		if(strstr(da.result ,"INC E"))
		{
			if(dwLength == 0x01 && strstr(da.result,"INC EAX"))
			{
				dwEAX++;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01 && strstr(da.result,"INC EBX"))
			{
				dwEBX++;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01 && strstr(da.result,"INC ECX"))
			{
				dwECX++;
			}
			if(dwLength == 0x01 && strstr(da.result,"INC EDX"))
			{
				dwEDX++;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01 && strstr(da.result,"INC ESI"))
			{
				dwESI++;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01 && strstr(da.result,"INC EDI"))
			{
				dwEDI++;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01 && strstr(da.result,"INC EBP"))
			{
				dwEBP++;
				dwOffSet += dwLength;
				continue;
			}
		}
		if(strstr(da.result,"DEC E"))
		{
			if(dwLength == 0x01 && strstr(da.result,"DEC EAX"))
			{
				dwEAX--;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01 && strstr(da.result,"DEC EBX"))
			{
				dwEBX--;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01 && strstr(da.result,"DEC ECX"))
			{
				dwECX--;
			}
			if(dwLength == 0x01 && strstr(da.result,"DEC EDX"))
			{
				dwEDX--;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01 && strstr(da.result,"DEC ESI"))
			{
				dwESI--;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01 && strstr(da.result,"DEC EDI"))
			{
				dwEDI--;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x01 && strstr(da.result,"DEC EBP"))
			{
				dwEBP--;
				dwOffSet += dwLength;
				continue;
			}
		}

		if(strstr(da.result ,"CMP E"))
		{
			if(dwLength == 0x03 && strstr(da.result , "CMP EAX,0"))
			{
				if(byDecStart == 0x01)
				{
					dwEAX = 0x00;
					byDecStart = 0x00;
				}
				if(dwEAX == 0x00)
				{
					if(byDecryptionFinish == 0x03)
					{
						m_dwOriginalAEP  = m_pSectionHeader[m_wNoOfSections-2].VirtualAddress + 0xA6 + *((DWORD*) (&m_pbyBuff[0xA7])) + 0x05;
						return true;
					}
					byDecryptionFinish = 0x01;
				}
				if(dwEAX != 0x00)
				{
					byDecStart = 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result , "CMP EBX,0"))
			{
				if(byDecStart == 0x01)
				{
					dwEBX = 0x00;
					byDecStart = 0x00;
				}
				if(dwEBX == 0x00)
				{
					if(byDecryptionFinish == 0x03)
					{
						m_dwOriginalAEP = m_pSectionHeader[m_wNoOfSections-2].VirtualAddress + 0xA6 + *((DWORD*) (&m_pbyBuff[0xA7])) + 0x05;
						return true;
					}
					byDecryptionFinish = 0x01;
				}
				if(dwEBX != 0x00)
				{
					byDecStart = 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result , "CMP ECX,0"))
			{
				if(byDecStart == 0x01)
				{
					dwECX = 0x00;
					byDecStart = 0x00;
				}
				if(dwECX == 0x00)
				{
					if(byDecryptionFinish == 0x03)
					{
						m_dwOriginalAEP = m_pSectionHeader[m_wNoOfSections-2].VirtualAddress + 0xA6 + *((DWORD*) (&m_pbyBuff[0xA7])) + 0x05;
						return true;
					}
					byDecryptionFinish = 0x01;
				}
				if(dwECX != 0x00)
				{
					byDecStart = 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result , "CMP EDX,0"))
			{
				if(byDecStart == 0x01)
				{
					dwEDX = 0x00;
					byDecStart = 0x00;
				}
				if(dwEDX == 0x00)
				{
					if(byDecryptionFinish == 0x03)
					{
						m_dwOriginalAEP = m_pSectionHeader[m_wNoOfSections-2].VirtualAddress + 0xA6 + *((DWORD*) (&m_pbyBuff[0xA7])) + 0x05;
						return true;
					}
					byDecryptionFinish = 0x01;
				}
				if(dwEDX != 0x00)
				{
					byDecStart = 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result , "CMP ESI,0"))
			{
				if(byDecStart == 0x01)
				{
					dwESI = 0x00;
					byDecStart = 0x00;
				}
				if(dwESI == 0x00)
				{
					if(byDecryptionFinish == 0x03)
					{
						m_dwOriginalAEP = m_pSectionHeader[m_wNoOfSections-2].VirtualAddress + 0xA6 + *((DWORD*) (&m_pbyBuff[0xA7])) + 0x05;
						return true;
					}
					byDecryptionFinish = 0x01;
				}
				if(dwESI != 0x00)
				{
					byDecStart = 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result , "CMP EDI,0"))
			{
				if(byDecStart == 0x01)
				{
					dwEDI = 0x00;
					byDecStart = 0x00;
				}
				if(dwEDI == 0x00)
				{
					if(byDecryptionFinish == 0x03)
					{
						m_dwOriginalAEP = m_pSectionHeader[m_wNoOfSections-2].VirtualAddress + 0xA6 + *((DWORD*) (&m_pbyBuff[0xA7])) + 0x05;
						return true;
					}
					byDecryptionFinish = 0x01;
				}
				if(dwEDI != 0x00)
				{
					byDecStart = 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength == 0x03 && strstr(da.result , "CMP EBP,0"))
			{
				if(byDecStart == 0x01)
				{
					dwEBP = 0x00;
					byDecStart = 0x00;
				}
				if(dwEBP == 0x00)
				{
					if(byDecryptionFinish == 0x03)
					{
						m_dwOriginalAEP = m_pSectionHeader[m_wNoOfSections-2].VirtualAddress + 0xA6 + *((DWORD*) (&m_pbyBuff[0xA7])) + 0x05;
						return true;
					}
					byDecryptionFinish = 0x01;
				}
				if(dwEBP != 0x00)
				{
					byDecStart = 0x01;
				}
				dwOffSet += dwLength;
				continue;
			}
		}



		if(dwLength==0x05 && B1==0xE8 && strstr(da.result, "CALL "))
		{
			if(dwTOS == dwStackSize)				
			{
				return false;
			}
			iCallCount++;
			if(iCallCount == 0x02)
			{
				byCallFlag = 0x01;
			}
			dwStack[dwTOS++] = dwOffSet + dwLength;
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffSet+1]);
			dwOffSet += dwTemp + dwLength;
			continue;
		}

		dwOffSet += dwLength;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Detnat Family
--------------------------------------------------------------------------------------*/
int CPolyDetnat::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wNoOfSections - 0x02].PointerToRawData))
		{
			iRetStatus = REPAIR_SUCCESS;		 
		}
	}
	return iRetStatus;
}