/*======================================================================================
FILE				: PolyJolla.cpp
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
NOTES				: This is detection module for malware Jolla Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include"PolyJolla.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyJolla
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyJolla::CPolyJolla(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0;
	m_wSectionsToTrucate = 0;
	m_dwReplaceOff = 0;
	m_dwReplaceData = 0;
	m_dwTruncateOffset = 0;	
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyJolla
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyJolla::~CPolyJolla()
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
	Description		: Detection routine for different varients of Jolla Family
--------------------------------------------------------------------------------------*/
int CPolyJolla::DetectVirus()
{
	int iRetStatus = DetectJollaSS();
	if(iRetStatus)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Jolla.A"));
		return iRetStatus;
	}
	return DetectJolla();	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectJollaSS
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for Jolla.SS
--------------------------------------------------------------------------------------*/
int CPolyJolla::DetectJollaSS()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wNoOfSections == 1) && (m_pMaxPEFile->m_stSectionHeader[0].SizeOfRawData > 0x4500) && 
		((memcmp(m_pMaxPEFile->m_stSectionHeader[0].Name,".text",5) == 0) || (memcmp(&m_pMaxPEFile->m_stSectionHeader[0].Name[5],"666",3) == 0)||
		 (memcmp(&m_pMaxPEFile->m_stSectionHeader[0].Name[5],"29a",3) ==0) || (memcmp(&m_pMaxPEFile->m_stSectionHeader[0].Name[5],"29A",3) ==0)))
	{//single section files with EPO 
		if(GetPatchedData())
		{
			if(GetTruncateOffset())
			{
				m_eJollaType = VIRUS_JOLLA_SINGLESEC;
				iRetStatus = VIRUS_FILE_REPAIR;
			}
		}
		else if(DetectDeadCode())
		{
			m_eJollaType = VIRUS_JOLLA_DEADCODE;
			iRetStatus = VIRUS_FILE_REPAIR;
		}
		else
		{
			m_pbyBuff = new BYTE[JOLLA_BUFF_SIZE];
			DWORD dwAEPSection = m_pSectionHeader[0].SizeOfRawData + m_pSectionHeader[0].PointerToRawData;
			if(!GetBuffer(dwAEPSection - JOLLA_BUFF_SIZE, JOLLA_BUFF_SIZE, JOLLA_BUFF_SIZE))
			{
				return iRetStatus;
			}
			DWORD dwCount = m_dwNoOfBytes;
			for(; dwCount > 0 && m_pbyBuff[dwCount - 1] == 0; dwCount--);		
			if(dwCount == 0)
			{
				return iRetStatus;
			}
			if((JOLLA_BUFF_SIZE - dwCount >= 0x0B) && (m_pbyBuff[dwCount - 2] == 0xFF))
			{
				m_dwTruncateOffset = *(DWORD *)&m_pbyBuff[dwCount - 6];
				DWORD dwTruncateOffset = 0;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwTruncateOffset - m_dwImageBase, &dwTruncateOffset))
				{
					return iRetStatus;
				}
				DWORD dwJmpOffset = *(DWORD *) &m_pbyBuff[dwCount - 0x0B];
				dwJmpOffset += (m_pSectionHeader[0].VirtualAddress + (m_pSectionHeader[0].SizeOfRawData - (JOLLA_BUFF_SIZE - dwCount + 0x0C))) + 5;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwJmpOffset, &dwJmpOffset))
				{
					return iRetStatus;
				}
				if(GetBuffer(dwJmpOffset, 0x07, 0x07))
				{
					DWORD dwKey = *(DWORD *)&m_pbyBuff[2];
					if(*(WORD *)&m_pbyBuff[0] == 0x7581)
					{
						dwKey = *(DWORD *)&m_pbyBuff[3];
					}
					if(m_pMaxPEFile->ReadBuffer(&m_dwOriginalAEP, dwTruncateOffset + 0x1FC, 4, 4))
					{
						m_dwOriginalAEP ^= dwKey;
						if(m_dwOriginalAEP < m_pMaxPEFile->m_stPEHeader.SizeOfImage)
						{
							if(m_dwTruncateOffset % m_pMaxPEFile->m_stPEHeader.SectionAlignment)
							{
								m_dwTruncateOffset -= (m_dwTruncateOffset % m_pMaxPEFile->m_stPEHeader.SectionAlignment);
							}
							if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwTruncateOffset - m_dwImageBase, &m_dwTruncateOffset))
							{
								m_dwReplaceData = m_dwOriginalAEP;
								m_dwReplaceOff = m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x28 - 1;
								m_eJollaType = VIRUS_JOLLA_SINGLESEC;
								iRetStatus = VIRUS_FILE_REPAIR;
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
	Function		: GetPatchedData
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Virus patches call from start of the 1st section so search within first 5000 bytes
--------------------------------------------------------------------------------------*/
bool CPolyJolla::GetPatchedData()
{
	m_pbyBuff = new BYTE[0x5000];
	if(!GetBuffer(m_pMaxPEFile->m_stSectionHeader[0].PointerToRawData, 0x5000, 0x5000))
	{
		return false;
	}

	DWORD dwJmpOffset = 0;
	for(int i = 0; i < 0x5000; i++)
	{
		if(m_pbyBuff[i] == 0xE8)
		{				
			dwJmpOffset = *(DWORD *)&m_pbyBuff[i+1] + i + m_pMaxPEFile->m_stSectionHeader[0].PointerToRawData + 5;
			BYTE byTemp[0x05] = {0};				
			if(m_pMaxPEFile->ReadBuffer(byTemp, dwJmpOffset - 5, 0x05,0x05))
			{
				if(byTemp[0] == 0xE9)//If there is another jump just before jump destination then its valid call
				{
					DWORD dwTempJmp = *(DWORD *)&byTemp[1] + dwJmpOffset;
					if(((dwTempJmp - dwJmpOffset) < 0x100) || dwTempJmp > m_pMaxPEFile->m_dwFileSize)
					{
						continue;
					}
					m_dwReplaceOff = m_pMaxPEFile->m_stSectionHeader[0].PointerToRawData + i;
					
					BYTE byBuffer[0x500] = {0};
					if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwTempJmp, 0x500, 0x500))
					{
						return false;
					}
					DWORD dwLength = 0, dwOffset = 0;
					t_disasm da;
					m_dwInstCount = 0;
					Instruction_Set_Struct objInstructionSet[MAX_INSTRUCTIONS] = {0};
					
					while(dwOffset < 0x500 && m_dwInstCount < 3)
					{
						dwLength = m_objMaxDisassem.Disasm((char *)&byBuffer[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
						if(dwLength > (0x500 - dwOffset) || (dwOffset == 0 && !strstr(da.result, "POP")))
						{
							break;
						}
						else if(dwLength == 1 && strstr(da.result, "POP") && m_dwInstCount == 0)
						{
							m_dwInstCount = 1;
						}
						else if((dwLength == 2 || dwLength == 3) && strstr(da.result, "JMP SHORT"))//it uses 1 byte jmps that changes the opcodes
						{
							DWORD dwTemp = byBuffer[dwOffset + 1];
							if(dwLength == 3)
							{
								dwTemp = byBuffer[dwOffset + 2];  
							}
							dwOffset +=dwTemp;
						}
						else if((dwLength == 0x0A ||dwLength == 0x0B) && strstr(da.result,"MOV DWORD PTR ") && m_dwInstCount == 1)
						{
							DWORD dwFileOff = *(DWORD *)&byBuffer[dwOffset + 2] - m_dwImageBase;
							if(dwLength == 0x0B)
							{
								dwFileOff = *(DWORD *)&byBuffer[dwOffset + 3] - m_dwImageBase;
							}
							if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwFileOff, &dwFileOff))
							{
								if(m_dwReplaceOff == dwFileOff)
								{
									m_dwReplaceData = byBuffer[dwOffset + 6];
									return true;
								}
							}
						}							
						dwOffset += dwLength;
					}						
				}					
			}
		}
	}	
	return false;
}


/*-------------------------------------------------------------------------------------
	Function		: GetTruncateOffset
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Disassemble from jump offset till return offset pushed for return is virus start offset
--------------------------------------------------------------------------------------*/
bool CPolyJolla::GetTruncateOffset()
{	
	DWORD dwTemp = 0; 
	if(m_pMaxPEFile->ReadBuffer(&dwTemp, m_dwReplaceOff + 1, 0x04, 0x04))
	{
		dwTemp = dwTemp + m_dwReplaceOff + 5;
		if(GetBuffer(dwTemp, 0x1000, 0x1000))
		{
			DWORD dwLength = 0, dwOffset = 0;
			t_disasm da;
			m_dwInstCount = 0;
			Instruction_Set_Struct objInstructionSet[MAX_INSTRUCTIONS] = {0};
			while(dwOffset < m_dwNoOfBytes && m_dwInstCount < 2)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (m_dwNoOfBytes - dwOffset))
				{
					break;
				}
				else if((dwLength == 2 || dwLength == 3) && strstr(da.result, "JMP SHORT"))
				{
					DWORD dwTemp = m_pbyBuff[dwOffset + 1];
					if(dwLength == 3)
					{
						dwTemp = m_pbyBuff[dwOffset + 2];  
					}
					dwOffset +=dwTemp;
				}
				else if((dwLength == 5 || dwLength == 6) && strstr(da.result, "PUSH") && m_pbyBuff[dwOffset] != 0xFF) 
				{
					DWORD dwVirusOffset = 0;
					if(dwLength == 5)
					{
						dwVirusOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1];
					}
					else
					{
						dwVirusOffset = *(DWORD *)&m_pbyBuff[dwOffset + 2];
					}
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwVirusOffset - m_dwImageBase, &dwVirusOffset))
					{
						m_dwTruncateOffset = dwVirusOffset;
						return true;
					}
				}
				else if(dwLength == 1 && strstr(da.result,"RETN"))
				{
					break;
				}
				dwOffset += dwLength;
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDeadCode
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection of DeadCode (Execution pointer is not going in Infection code)
					  Dead code is of size of 300kb to 500kb starting with aligned offset
					  so checking per 0x1000 bytes from min. virus code size to max. virus code size	
--------------------------------------------------------------------------------------*/
bool CPolyJolla::DetectDeadCode()
{								 
	DWORD dwVirusStartOffset = 0;
	BYTE byBuffer[0x50];
	BYTE bySig[0x50] = {0};
	BYTE bySig1[] = {0x50, 0x41, 0x44, 0x44, 0x49, 0x4E, 0x47, 0x58, 0x58, 0x50, 0x41, 0x44, 0x44, 0x49, 0x4E, 0x47};
	for(int  i = 0x60000; i <= 0x92000 && (m_pMaxPEFile->m_dwFileSize - i > 0); i += 0x1000)
	{
		if(m_pMaxPEFile->ReadBuffer(byBuffer, m_pMaxPEFile->m_dwFileSize - i - 0x50, 0x50, 0x50))
		{
			if((memcmp(byBuffer, bySig, 0x50) == 0) || (memcmp(bySig1, &byBuffer[0x40], 0x10) == 0))
			{
				dwVirusStartOffset = m_pMaxPEFile->m_dwFileSize - i;
				break;
			}
		}
	}
	if(dwVirusStartOffset == 0)
	{
		return false;
	}
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[0x2000];
	if(GetBuffer(dwVirusStartOffset + 0x500, 0x2000, 0x2000))
	{
		BYTE bySig2[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};//from start of the virus code within 500 bytes we get a patch of NOPs(0x90)
		for(int i = 0; i < 0x2000 - 0x0A; i++)											   //which indicates start of decryption routine
		{
			if(memcmp(bySig2, &m_pbyBuff[i], 0x0B) == 0)
			{
				DWORD dwLength = 0, dwOffset = i + 0x0A;
				t_disasm da;
				m_dwInstCount = 0;
				Instruction_Set_Struct objInstructionSet[MAX_INSTRUCTIONS] = {0};
				while(dwOffset < m_dwNoOfBytes && m_dwInstCount < 5)
				{
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwLength > (m_dwNoOfBytes - dwOffset))//It is start of decryption routine dexryption is always 'DWORD XOR'
					{
						break;
					}
					else if(dwLength == 5 && strstr(da.result, "MOV E") && m_dwInstCount == 0)
					{
						m_dwInstCount = 1;
					}
					else if(dwLength == 6 && strstr(da.result, "XOR DWORD PTR") && m_dwInstCount == 1)
					{
						m_dwInstCount++; 
					}
					else if(dwLength == 6 && strstr(da.result, "ADD E") && m_dwInstCount == 2)
					{
						m_dwInstCount++; 
					}
					else if(dwLength == 6 && strstr(da.result, "SUB E") && m_dwInstCount == 3)
					{
						m_dwInstCount++; 
					}
					else if(dwLength == 6 && strstr(da.result, "CMP E") && m_dwInstCount == 4)
					{
						m_dwTruncateOffset = dwVirusStartOffset;
						return true;
					}
					dwOffset += dwLength;
				}
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectJolla
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: second type of infection : adds two sections at the end, last section is a loop that decrypts second last section
					  all data is contained in second last section
--------------------------------------------------------------------------------------*/
int CPolyJolla::DetectJolla()
{							 
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(m_wAEPSec > 2 && (m_wAEPSec == m_wNoOfSections - 1 || m_wAEPSec == m_wNoOfSections - 2) && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) && 
		((m_pSectionHeader[m_wAEPSec].Characteristics & 0x60000020) == 0x60000020) &&
		(m_pSectionHeader[m_wAEPSec - 1].SizeOfRawData >= 0x5000))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}		
		m_pbyBuff = new BYTE[JOLLA_BUFF_SIZE];
		DWORD dwAEPSection = 0;
		if(m_wAEPSec == m_wNoOfSections - 1)
		{
			dwAEPSection = m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
		}
		else
		{
			dwAEPSection = m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 2].PointerToRawData;
		}
		if(!GetBuffer(dwAEPSection - JOLLA_BUFF_SIZE, JOLLA_BUFF_SIZE, JOLLA_BUFF_SIZE))
		{
			return iRetStatus;
		}
		//take buffer from end of the last section and traverse till we get some data
		//It will move a offset to a register and jump to that register
		DWORD dwCount = m_dwNoOfBytes;
		for(; dwCount > 0 && m_pbyBuff[dwCount - 1] == 0; dwCount--);		
		if(dwCount == 0)
		{
			return iRetStatus;
		}
		if((JOLLA_BUFF_SIZE - dwCount >= 0x0B) && (m_pbyBuff[dwCount - 2] == 0xFF))//FFxx : JMP reg
		{
			DWORD dwDecryptStartOffset = *(DWORD *)&m_pbyBuff[dwCount - 6];
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwDecryptStartOffset - m_dwImageBase, &dwDecryptStartOffset))
			{
				return iRetStatus;
			}
			DWORD dwJmpOffset = *(DWORD *) &m_pbyBuff[dwCount - 0x0B];
			dwJmpOffset += (m_pSectionHeader[m_wAEPSec].VirtualAddress + (m_pSectionHeader[m_wAEPSec].SizeOfRawData - (JOLLA_BUFF_SIZE - dwCount + 0x0C))) + 5;
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwJmpOffset, &dwJmpOffset))
			{
				return iRetStatus;
			}
			if(GetBuffer(dwJmpOffset, 0x07, 0x07))
			{
				DWORD dwKey = *(DWORD *)&m_pbyBuff[2];
				if(*(WORD *)&m_pbyBuff[0] == 0x7581)
				{
					dwKey = *(DWORD *)&m_pbyBuff[3];
				}
				if(m_pMaxPEFile->ReadBuffer(&m_dwOriginalAEP, dwDecryptStartOffset + 0x1FC, 4, 4))
				{
					m_dwOriginalAEP ^= dwKey;					
					if(m_dwOriginalAEP < m_pMaxPEFile->m_stPEHeader.SizeOfImage)					
					{
						if(m_wAEPSec == m_wNoOfSections -1)
						{
							m_wSectionsToTrucate = 2;
						}
						else 
						{
							m_wSectionsToTrucate = 3;
						}
						m_eJollaType = VIRUS_JOLLA_A;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Jolla.A"));							
						iRetStatus = VIRUS_FILE_REPAIR;
					}
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
	Description		: Repair routine for different varients of Jolla Family
--------------------------------------------------------------------------------------*/
int CPolyJolla::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	switch(m_eJollaType)
	{
	case VIRUS_JOLLA_SINGLESEC:
		{
			if(m_dwReplaceOff != 0)
			{
				if(m_pMaxPEFile->WriteBuffer(&m_dwReplaceData, m_dwReplaceOff + 1, 0x04, 0x04))
				{
					if(m_dwTruncateOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment)//added 30 May for multiple infection
					{
						m_dwTruncateOffset -= (m_dwTruncateOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment);
					}
					if(m_pMaxPEFile->TruncateFile(m_dwTruncateOffset))
					{
						iRetStatus = REPAIR_SUCCESS;
					}
				}
			}
		}
		break;
	case VIRUS_JOLLA_DEADCODE://Single section with deadcode
		{
			if(m_pMaxPEFile->TruncateFile(m_dwTruncateOffset))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
		break;
	case VIRUS_JOLLA_A: //2 sections appended and AEP at the last section
		{
			if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
			{		
				if(m_pMaxPEFile->RemoveLastSections(m_wSectionsToTrucate))
				{
					iRetStatus = REPAIR_SUCCESS;
				}
			}
		}
		break;
	}
	return iRetStatus;
}