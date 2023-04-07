/*======================================================================================
FILE				: PolyHatred.cpp
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
NOTES				: This is detection module for malware Poly Hatred Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyHatred.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyHatred
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyHatred::CPolyHatred(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwInstructionOffset = 0;
	memset(&m_objDecryptParameters, 0, sizeof(DECRYPTION_PARAMETERS));
	memset(&m_dwRegisterUsed, 0, sizeof(m_dwRegisterUsed));
	memset(&m_objDetectType, 0, sizeof(Detect_Type));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyHatred
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyHatred::~CPolyHatred(void)
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
	Description		: Detection routine for different varients of Hatred Family
--------------------------------------------------------------------------------------*/
int CPolyHatred::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(((m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x4838) || (m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x4347)) &&
		((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xC0000040) == 0xC0000040) && 
		(m_wAEPSec == m_wNoOfSections - 1) && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)  &&
		(m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize >= 0x2946) &&		
		(m_pMaxPEFile->m_stPEHeader.e_lfanew <= 0x1000))	//offset to pe <= 1000h
	{	
		const int HATRED_BUFF_SIZE = 0x300;
		m_pbyBuff = new BYTE[HATRED_BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped, 0x06, 0x06))
		{
			if(*(WORD *)&m_pbyBuff[0] == 0xE960 && *(DWORD *)&m_pbyBuff[2] >= 0x2200)
			{
				m_dwJumpOffset = *(DWORD*)&m_pbyBuff[2];
				
				if(GetBuffer(m_dwAEPMapped + m_dwJumpOffset + 0x2, 0xB2, 0xB2))
				{
					m_dwInstructionOffset = 0x01;
					do
					{
						if(((m_pbyBuff[m_dwInstructionOffset - 0x01] & 0xB8) == 0xB8) &&
							(*(DWORD*)&m_pbyBuff[m_dwInstructionOffset] == (m_dwAEPUnmapped + 0x06 + m_dwImageBase)))
						{
							if((m_dwAEPUnmapped + 0x2929 - m_pSectionHeader[m_wNoOfSections-1].VirtualAddress) == m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize)
							{
								m_objDetectType.dwVirusCodeOffset = 0x2200;
								m_objDetectType.dwLoopSize = 0x4E1;
								m_objDetectType.dwAEPOffset = 0x138E;
							}
							else if((m_dwAEPUnmapped + 0x2946 - m_pSectionHeader[m_wNoOfSections-1].VirtualAddress) == m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize ||
								m_dwAEPUnmapped + 0x2946 - m_pSectionHeader[m_wNoOfSections-1].VirtualAddress == m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData )
							{
								m_objDetectType.dwVirusCodeOffset = 0x2232;
								m_objDetectType.dwLoopSize = 0x4E8;
								m_objDetectType.dwAEPOffset = 0x13AA;
							}
							else 
							{
								return iRetStatus;
							}
							m_objDecryptParameters.dwOffsettoDecrypt_Register = m_pbyBuff[m_dwInstructionOffset-0x1] - 0xB8;
							m_dwRegisterUsed[m_objDecryptParameters.dwOffsettoDecrypt_Register] = 0x01;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Hatred"));
							return VIRUS_FILE_REPAIR;
						}

					}while(++m_dwInstructionOffset != 0xAE);
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
	Description		: Repair routine for different varients of Hatred Family
--------------------------------------------------------------------------------------*/
int CPolyHatred::CleanVirus()
{
	if(GetParameters())
	{
		memset(m_pbyBuff, 0, 0x300);
		if(GetBuffer(m_dwAEPMapped + m_objDetectType.dwAEPOffset, 0xC, 0xC))
		{
			//To get the Decryption_Key counter to the appropriate value
			if(m_objDecryptParameters.dwDecryptionKey_Operation == 0x00 || m_objDecryptParameters.dwDecryptionKey_Operation == 0x02)
			{
				DWORD dwTemp=m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKey_Counter*m_objDetectType.dwLoopSize;
				PerformOperation(m_objDecryptParameters.dwDecryptionKey_Operation,&m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKeyValue, &dwTemp);
			}
			else if( (m_objDecryptParameters.dwDecryptionKey_Operation == 0x03) && ((m_objDetectType.dwLoopSize%2) == 0x01) )
			{
				PerformOperation(m_objDecryptParameters.dwDecryptionKey_Operation,&m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKeyValue, &m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKey_Counter);
			}

			for(DWORD dwLoop=0x0;dwLoop<0x2;dwLoop++)
			{  
				//1.ADD,SUB,XOR(for Key)  
				PerformOperation(m_objDecryptParameters.dwDecryptionKey_Operation,&m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKeyValue, &m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKey_Counter);

				//2.ADD,SUB,XOR
				PerformOperation(m_objDecryptParameters.dwDecryption_Operation1,(DWORD*)&m_pbyBuff[dwLoop*4], &m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKeyValue);

				//3.ROL,ROR 
				PerformOperation(m_objDecryptParameters.m_objROL_ROR.dwROL_RORType,(DWORD*)&m_pbyBuff[dwLoop*4],&m_objDecryptParameters.m_objROL_ROR.dwROL_RORValue);

				//4.ADD,SUB,XOR
				PerformOperation(m_objDecryptParameters.dwDecryption_Operation2,(DWORD*)&m_pbyBuff[dwLoop*4], (DWORD*)&m_pbyBuff[(dwLoop*4)+0x4]);
			}

			if(*(DWORD*)&m_pbyBuff[(m_objDetectType.dwLoopSize%0x02)+0x01]<=m_pSectionHeader[m_wNoOfSections-1].VirtualAddress +m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize)
			{   
				//Setting the AEP
				if(m_pMaxPEFile->WriteAEP(*(DWORD *)&m_pbyBuff[(m_objDetectType.dwLoopSize%0x02)+0x01]))
				{	
					//Truncating at Virus AEP		
					if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
					{	
						return REPAIR_SUCCESS;
					}		   
				}
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: PerformOperation
	In Parameters	: DWORD dwtype,DWORD *dwA, DWORD *dwB
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Performs binary arithmetic operations of CPU registers
--------------------------------------------------------------------------------------*/
void CPolyHatred::PerformOperation(DWORD dwtype,DWORD *dwA, DWORD *dwB)
{	
	if(dwtype == 0x0)
	{
		*dwA+=*dwB;
	}
	else if(dwtype == 0x02)
	{
		*dwA-=*dwB;
	}
	else if(dwtype == 0x03)
	{
		*dwA^=*dwB;
	}
	else if(dwtype == 0x04) //ROL
	{   		
		m_objDecryptParameters.m_objROL_ROR.dwROL_RORValue%=0x20;
		*dwA=((*dwA<<m_objDecryptParameters.m_objROL_ROR.dwROL_RORValue)|(*dwA>>(0x20-m_objDecryptParameters.m_objROL_ROR.dwROL_RORValue)));
	}
	else if(dwtype == 0x5)//ROR
	{		
		m_objDecryptParameters.m_objROL_ROR.dwROL_RORValue%=0x20;
		*dwA=((*dwA>>m_objDecryptParameters.m_objROL_ROR.dwROL_RORValue)|(*dwA<<(0x20-m_objDecryptParameters.m_objROL_ROR.dwROL_RORValue)));
	}
}

/*-------------------------------------------------------------------------------------
	Function		: GetParameters
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function collects the sequence of CPU instructions.
--------------------------------------------------------------------------------------*/
bool CPolyHatred::GetParameters()
{
	if(GetBuffer(m_dwAEPMapped + m_objDetectType.dwVirusCodeOffset, 0x300, 0x300))
	{
		DWORD dwLength = 0x0;
		DWORD dwOffset = 0x0;
		DWORD dwInstructionCountFound = 0x00;
		t_disasm da = {0x00};
		CHAR TEMPSTRINGXOR[20];
		CHAR TEMPSTRINGADD[20];
		CHAR TEMPSTRINGSUB[20];
		CHAR RegisterBuffNames[8][4]={"EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"};

		while(dwOffset < (0x300-0x20))
		{
			dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);

			if(dwInstructionCountFound==0x00) //Initially keep track of all instructions using mov.These need to be discarded
			{
				if(strstr(da.result,"MOV") || strstr(da.result,"DEC") || strstr(da.result,"INC") || strstr(da.result,"POP")) 
				{
					if(dwLength == 0x02)
					{
						m_dwRegisterUsed[(m_pbyBuff[dwOffset]-0xB0)%4] = 0x01;
					}
					else if(dwLength == 0x04)
					{
						m_dwRegisterUsed[m_pbyBuff[dwOffset+0x1]-0xB8] = 0x01;
					}
					else if(dwLength == 0x05)
					{
						m_dwRegisterUsed[m_pbyBuff[dwOffset]-0xB8] = 0x01;
						if(*(DWORD*)&m_pbyBuff[dwOffset + 0x01] == (m_dwAEPUnmapped + 0x06 + m_dwImageBase))
						{
							dwInstructionCountFound+=0x01;
						}
					}
					else if(dwLength == 0x01)
					{ 
						m_dwRegisterUsed[(m_pbyBuff[dwOffset]-(m_pbyBuff[dwOffset]&0xF0))%8]=0x01;
					}
				}
			}
			else if(dwInstructionCountFound==0x01) //	//To get the decryption key value and register
			{
				if(strstr(da.result,"MOV")&& dwLength == 0x05 && m_dwRegisterUsed[m_pbyBuff[dwOffset]-0xB8] == 0x00)
				{
					m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKeyValue=*(DWORD*)&m_pbyBuff[dwOffset+0x01];
					m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKeyRegister=m_pbyBuff[dwOffset]-0xB8;
					dwInstructionCountFound+=0x01;
				}
			}
			else if(dwInstructionCountFound==0x02) ////To get the Load DWORD Register where Operations will be performed
			{
				if(strstr(da.result,"MOV")&& dwLength == 0x02 && m_pbyBuff[dwOffset] == 0x8B)
				{
					m_objDecryptParameters.dwLoadDword_Register=m_pbyBuff[dwOffset+0x01]/0x08;
					sprintf_s(TEMPSTRINGXOR,20,"XOR %s",RegisterBuffNames[m_objDecryptParameters.dwLoadDword_Register]);
					sprintf_s(TEMPSTRINGADD,20,"ADD %s",RegisterBuffNames[m_objDecryptParameters.dwLoadDword_Register]);
					sprintf_s(TEMPSTRINGSUB,20,"SUB %s",RegisterBuffNames[m_objDecryptParameters.dwLoadDword_Register]);
					dwInstructionCountFound+=0x01;
				}
				else if(strstr(da.result,"MOV")&& dwLength == 0x03 && m_pbyBuff[dwOffset] == 0x8B)
				{
					m_objDecryptParameters.dwLoadDword_Register=(m_pbyBuff[dwOffset+0x01]-0x45)/8;
					sprintf_s(TEMPSTRINGXOR,20,"XOR %s",RegisterBuffNames[m_objDecryptParameters.dwLoadDword_Register]);
					sprintf_s(TEMPSTRINGADD,20,"ADD %s",RegisterBuffNames[m_objDecryptParameters.dwLoadDword_Register]);
					sprintf_s(TEMPSTRINGSUB,20,"SUB %s",RegisterBuffNames[m_objDecryptParameters.dwLoadDword_Register]);
					dwInstructionCountFound+=0x01;
				}
			}
			else if(dwInstructionCountFound==0x03) //To get the operation1 performed
			{
				if( strstr(da.result,(char *)TEMPSTRINGXOR) || strstr(da.result,(char *)TEMPSTRINGADD) || strstr(da.result,(char *)TEMPSTRINGSUB) )
				{
					m_objDecryptParameters.dwDecryption_Operation1 = HINIBBLE(m_pbyBuff[dwOffset]);
					dwInstructionCountFound+=0x01;
				}
			}
			else if(dwInstructionCountFound==0x04) //To get whether ROL or ROR performed
			{
				if(strstr(da.result,"JMP") && dwLength==0x05)
				{
					dwOffset+=*(DWORD*)&m_pbyBuff[dwOffset+0x01];
				}
				if( strstr(da.result,"ROL") || strstr(da.result,"ROR") )
				{
					m_objDecryptParameters.m_objROL_ROR.dwROL_RORType =  (m_pbyBuff[dwOffset+0x01]/0xC8)+0x4;
					m_objDecryptParameters.m_objROL_ROR.dwROL_RORValue = m_pbyBuff[dwOffset+0x02];
					dwInstructionCountFound+=0x01;
				}
			}
			else if(dwInstructionCountFound==0x05) //To get the operation2 performed
			{
				if( strstr(da.result,(char *)TEMPSTRINGXOR) || strstr(da.result,(char *)TEMPSTRINGADD) || strstr(da.result,(char *)TEMPSTRINGSUB) )
				{
					m_objDecryptParameters.dwDecryption_Operation2 = HINIBBLE(m_pbyBuff[dwOffset]);
					sprintf_s(TEMPSTRINGXOR,20,"XOR %s",RegisterBuffNames[m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKeyRegister]);
					sprintf_s(TEMPSTRINGADD,20,"ADD %s",RegisterBuffNames[m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKeyRegister]);
					sprintf_s(TEMPSTRINGSUB,20,"SUB %s",RegisterBuffNames[m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKeyRegister]);
					dwInstructionCountFound+=0x01;
				}
			}
			else if(dwInstructionCountFound==0x06)
			{
				//To get the Operation on Decryption key and the keyCounter
				if( strstr(da.result,(char *)TEMPSTRINGXOR)||  strstr(da.result,(char *)TEMPSTRINGADD) || strstr(da.result,(char *)TEMPSTRINGSUB) )
				{
					m_objDecryptParameters.dwDecryptionKey_Operation=HINIBBLE(m_pbyBuff[dwOffset+0x01])%0xC;
					m_objDecryptParameters.m_objDecryptionKey.dwDecryptionKey_Counter=*(DWORD*)&m_pbyBuff[dwOffset+0x2];
					return true;
				}
			}
			dwOffset+=dwLength;
		}			
	}
	return false;
}



