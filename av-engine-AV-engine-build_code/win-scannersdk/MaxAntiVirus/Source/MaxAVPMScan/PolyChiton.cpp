/*======================================================================================
FILE				: PolyChiton.cpp
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
NOTES				: This is detection module for malware Chiton Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyChiton.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyChiton
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyChiton::CPolyChiton(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyChiton
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyChiton::~CPolyChiton(void)
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
	Description		: Detection routine for different varients of Chiton Family
--------------------------------------------------------------------------------------*/
int CPolyChiton::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD i, k;
	BYTE byVirusCode[0x40] = {0}, pKeyBuff[0x100], pBuffer[0x20];

	m_dwDecKeyBuffOffset = m_dwVirusCodeOffset = m_dwDecLength = m_dwPatchedOffset = 0x0;
	m_iDirection = 0;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL || 
		m_wAEPSec == m_wNoOfSections - 1 || m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData < 0x8000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData < 0x40)
	{
		return iRetStatus;
	}
	
	m_pbyBuff = new BYTE[CHITON_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, CHITON_BUFF_SIZE + MAX_INSTRUCTION_LEN);

	for(DWORD dwReadOffset = m_pSectionHeader[m_wAEPSec].PointerToRawData; dwReadOffset <(m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData) - 0x20; dwReadOffset += CHITON_BUFF_SIZE)
	{	
		if(!GetBuffer(dwReadOffset, CHITON_BUFF_SIZE, 0x20))
		{
			return iRetStatus;
		}

		for(i = 0x00; i < m_dwNoOfBytes; i++)
		{
			if( m_pbyBuff[i] != 0x60)
				continue;

			if((m_dwNoOfBytes - i) < 0x20)
			{
				if(!m_pMaxPEFile->ReadBuffer(byVirusCode, dwReadOffset + i, 0x20, 0x20))
				{
					return iRetStatus;
				}
			}
			else
			{
				memcpy(&byVirusCode[0], &m_pbyBuff[i], 0x20);
			}

			//Get virus detection parameters
			if(!GetChitonGenParam(&byVirusCode[0], 0x20))
				continue;

			//If we get all the parameters then check the signature.
			m_dwPatchedOffset = dwReadOffset + i;

			//Read Key Buffer	
			if(!m_pMaxPEFile->ReadBuffer(pKeyBuff, m_dwDecKeyBuffOffset, 0x100, 0x100))
			{
				continue;
			}

			//Check for reverse or foward decryption(++ or --)
			if(m_iDirection) //Reverse Decryption
			{
				if(m_dwVirusCodeOffset < m_dwDecLength)
					continue;
				m_dwVirusCodeOffset -= m_dwDecLength;
			}

			//Read virus code
			if(!m_pMaxPEFile->ReadBuffer(pBuffer, m_dwVirusCodeOffset, 0x20, 0x20))
			{
				continue;
			}

			//Decrypt virus code
			for(k = 0x00; k < 0x20; k++)
			{
				pBuffer[k] = pKeyBuff[pBuffer[k]];
			}

			BYTE ChitonSig[] = { 
				0xFC, 0xE8, 0x5B, 0x00, 0x00, 0x00, 0x6C, 0x4A, 0xEA, 0x14, 0xEE, 0xB9, 0x84, 0x82, 0xAF, 0x5F,
				0xB7, 0x2E, 0x6D, 0x5C, 0x1E, 0xFD, 0xA5, 0x59, 0x75, 0xDA, 0xBF, 0x9E, 0x85, 0x39, 0x39, 0xA7 };
	
			//Detect the Chiton type
			if(memcmp(&pBuffer[0], &ChitonSig[0], sizeof(ChitonSig)) == 0) //Comparing chiton virus signature. It is common for some chiton varients.
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Chiton"));
				return VIRUS_FILE_REPAIR;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetChitonGenParam
	In Parameters	: BYTE *bBuffer, DWORD dwBytesRead
	Out Parameters	: 1 for Suceess else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Chiton Family
--------------------------------------------------------------------------------------*/
int CPolyChiton::GetChitonGenParam(BYTE *bBuffer, DWORD dwBytesRead)
{
	t_disasm da;
	DWORD	dwOffset = 0, dwLength, dwSecNo = 0x00, dwTemp = 0x00, dwTotalInst, dwTempOffset; 
	WORD	wValidInstCnt = 0x00;
	int		OffsetFound, Action, STD_InstFound = 0, iCheckDecDirection = 0;	
	BYTE	B1, B2;
	char *ptr = NULL;

	m_objMaxDisassem.InitializeData();

	OffsetFound = 0;
	m_dwInstCount = 0x00;

	m_dwDecKeyBuffOffset = m_dwVirusCodeOffset = m_dwDecLength = 0x0;
	m_iDirection = 0;
	
	Instruction_Set_Struct objInstructionSet[MAX_INSTRUCTIONS] = {0};
	
	while(dwOffset < dwBytesRead)
	{
		if( m_dwInstCount > 0x20)
			break;

		memset(&da, 0x00, sizeof( struct t_disasm)*1);
		B1 = *((BYTE*)&bBuffer[dwOffset]);
		B2 = *((BYTE*)&bBuffer[dwOffset + 1]);
		
		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if( B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if( B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&bBuffer[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (dwBytesRead - dwOffset))
		{
			break;
		}

		if(dwOffset == 0)
		{
			//First instruction always PUSHAD
			if(dwLength!=0x01 || B1!=0x60 || strstr(da.result, "PUSHAD")==NULL)
				return 0;
			else
			{
				dwOffset += dwLength;
				continue;
			}
		}

		if( dwLength==0x01 && _strcmpi(da.dump, "FFFFFFC3")== 0)
		{
			dwOffset += dwLength;
			continue;
		}

		if( dwLength==0x01 && B1==0xE2 && strstr(da.result, "???"))
		{
			dwOffset += 0x02;
			continue;
		}

		objInstructionSet[m_dwInstCount].dwInstLen = dwLength;
		strcpy_s(objInstructionSet[m_dwInstCount].szOpcode, TEXTLEN, da.dump);
		strcpy_s(objInstructionSet[m_dwInstCount++].szPnuemonics, TEXTLEN, da.result);

		if(dwLength==0x01 && B1==0xFD && strstr(da.result, "STD"))
		{
			dwOffset += dwLength;
			STD_InstFound = 1;
			continue;
		}

		if(dwLength==0x01 && B1==0xAC && strstr(da.result, "LODS BYTE PTR [E") && STD_InstFound)
		{
			dwOffset += dwLength;
			m_iDirection = 1; //Reverse Decryption
			continue;
		}

		//if(dwLength==0x01 && B1==0xAA && strstr(da.result, "STOS BYTE PTR [E") && STD_InstFound)
		if(dwLength==0x01 && B1==0xAA && strstr(da.result, "???") && STD_InstFound)
		{
			dwOffset += dwLength;
			m_iDirection = 1; //Reverse Decryption
			continue;
		}

		if( dwLength==0x05 && strstr(da.result, "MOV") && !OffsetFound)
		{
			dwTempOffset = *(DWORD *)&bBuffer[dwOffset + 1];

			if(dwTemp & 0x80000000)
				return 0;
			
			//We get offset with imagebase
			if(dwTempOffset < m_dwImageBase)
				break;

			dwTempOffset -= m_dwImageBase;
			dwSecNo = m_pMaxPEFile->Rva2FileOffset(dwTempOffset, &dwTempOffset);

			if( dwTempOffset == 0x00)
				break;			

			if(dwSecNo !=(m_wNoOfSections-1))
				break;

			if((dwTempOffset < m_pSectionHeader[dwSecNo].PointerToRawData) ||(dwTempOffset>(m_pSectionHeader[dwSecNo].PointerToRawData + m_pSectionHeader[dwSecNo].SizeOfRawData)))
				break;

			OffsetFound++;
			dwOffset += dwLength;
			wValidInstCnt++;
			continue;
		}

		if(dwLength==0x04 && B1==0xC8 && strstr(da.result, "ENTER") && strstr(da.result, ",0"))
		{
			m_dwDecLength = *(WORD *)&bBuffer[dwOffset + 1];
			if((m_dwDecLength < 0x1000) ||(m_dwDecLength > 0x2000))
				break;
			dwOffset += dwLength;
			wValidInstCnt++;
			continue;
		}

		if(dwLength==0x06 && B1==0x8D && strstr(da.result, "LEA E") && OffsetFound)
		{
			dwOffset += dwLength;
			wValidInstCnt++;
			continue;
		}

		if(dwLength==0x01 && B1==0xD7 && strstr(da.result, "XLAT BYTE PTR [EBX+AL]"))
		{
			dwOffset += dwLength;
			wValidInstCnt++;
			continue;
		}

		if(dwLength==0x02 && strstr(da.result, "CMP") && wValidInstCnt==4)
		{
			dwOffset += dwLength;
			wValidInstCnt++;
			break;
		}
		dwOffset += dwLength;
	}
	
	if(wValidInstCnt != 5)
		return 0;

	dwTotalInst = m_dwInstCount - 1;
	int iFoundXLAT = 0, iRegFound = 0;
	char Register[5]={0};
	
	for(; dwTotalInst >= 0x01; dwTotalInst--)
	{
		if( objInstructionSet[dwTotalInst].dwInstLen==0x01 && strstr(objInstructionSet[dwTotalInst].szPnuemonics,  "XLAT BYTE PTR [EBX+AL]") && !iFoundXLAT)
		{
			iFoundXLAT = 1;
			continue;
		}
		
		if(iFoundXLAT && !iRegFound)
		{
			if( objInstructionSet[dwTotalInst].dwInstLen==0x02 && strstr(objInstructionSet[dwTotalInst].szPnuemonics,  "MOV AL,[E"))
			{
				ptr = strrchr(objInstructionSet[dwTotalInst].szPnuemonics, '[');

				if( !ptr)
					continue;

				ptr++;
				strncpy_s(Register, 5, ptr, 3);
				iRegFound = 1;
				continue;
			}

			if( objInstructionSet[dwTotalInst].dwInstLen==0x01 && strstr(objInstructionSet[dwTotalInst].szPnuemonics,  "LODS BYTE PTR [E"))
			{
				ptr = strrchr(objInstructionSet[dwTotalInst].szPnuemonics, '[');

				if( !ptr)
					continue;

				ptr++;
				strncpy_s(Register, 5, ptr, 3);
				iRegFound = 1;
				continue;
			}
		}

		if(iRegFound)
		{
			//Checking for the decryption direction
			if(!iCheckDecDirection && !(m_iDirection))
			{
				char Instrn2[10]={0};
				DWORD k;
			
				iCheckDecDirection = 1;
				sprintf_s(Instrn2, 10, "DEC %s", Register);
				for(k=dwTotalInst; k < m_dwInstCount - 1; k++)
				{
					if( objInstructionSet[k].dwInstLen==0x01 && strstr(objInstructionSet[k].szPnuemonics, Instrn2))
					{
						m_iDirection = 1; //Reverse Decryption
						break;
					}
				}
			}
			///////////

			//Calculate offsets
			char Instrn1[20]={0};
			sprintf_s(Instrn1, 20, "LEA %s,[", Register);
			if( objInstructionSet[dwTotalInst].dwInstLen==0x06 && strstr(objInstructionSet[dwTotalInst].szPnuemonics, Instrn1))
			{
				Action = 0;
				ptr = strrchr(objInstructionSet[dwTotalInst].szPnuemonics, '-');
				if( !ptr)
				{
					ptr = strrchr(objInstructionSet[dwTotalInst].szPnuemonics, '+');
					if( !ptr)
						continue;
					Action = 1;
				}
				ptr++;
				sscanf_s(ptr, "%X", &dwTemp);

				if(Action) //add
				{
					m_dwVirusCodeOffset = dwTempOffset + dwTemp;
				}
				else
					m_dwVirusCodeOffset = dwTempOffset - dwTemp;

				m_dwDecKeyBuffOffset = dwTempOffset;
				break;
			}
			else if(objInstructionSet[dwTotalInst].dwInstLen==0x06 &&  strstr(objInstructionSet[dwTotalInst].szPnuemonics, "LEA E"))
			{
				Action = 0;
				ptr = strrchr(objInstructionSet[dwTotalInst].szPnuemonics, '-');
				if( !ptr)
				{
					ptr = strrchr(objInstructionSet[dwTotalInst].szPnuemonics, '+');
					if( !ptr)
						continue;
					Action = 1;
				}
				ptr++;
				sscanf_s(ptr, "%X", &dwTemp);

				if(Action)
				{
					m_dwVirusCodeOffset = dwTempOffset;
					m_dwDecKeyBuffOffset = dwTempOffset + dwTemp;
				}
				else
				{
					m_dwVirusCodeOffset = dwTempOffset;
					m_dwDecKeyBuffOffset = dwTempOffset - dwTemp;
				}
				break;
			}
			/////////
			continue;
		}
	}

	if((m_dwDecKeyBuffOffset < m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData) ||(m_dwDecKeyBuffOffset >(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)))
		return 0;

	if((m_dwVirusCodeOffset < m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData) ||(m_dwVirusCodeOffset >(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)))
		return 0;

	if(m_dwVirusCodeOffset && m_dwDecKeyBuffOffset && m_dwDecLength)
		return 1;

	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Chiton Family
--------------------------------------------------------------------------------------*/
int CPolyChiton::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;

	if(m_dwDecLength > 0x10000)
	{
		return iRetStatus;
	}

	//Allocate buffer to read virus code
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[m_dwDecLength + 1];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	
	//Read virus code
	if(!GetBuffer(m_dwVirusCodeOffset, m_dwDecLength, m_dwDecLength))
	{
		return iRetStatus;
	}

	//Read Key Buffer	
	BYTE  pKeyBuff[0x100];
	if(!m_pMaxPEFile->ReadBuffer(pKeyBuff, m_dwDecKeyBuffOffset, 0x100, 0x100))
	{
		return iRetStatus;
	}

	//Decrypt virus code
	for(DWORD dwOffset = 0; dwOffset < m_dwDecLength; dwOffset++)
	{
		m_pbyBuff[dwOffset] = pKeyBuff[m_pbyBuff[dwOffset]];
	}

	//Detect the Chiton type
	BYTE ChitonR_U_Sig[] = {0x89, 0x2D, 0x98, 0x20, 0x40, 0x00, 0xB9, 0xFC, 0x80, 0x00, 0x00, 0xFF, 0xD2, 0xAA, 0xE2, 0xFB,
						     0xFF, 0xD2, 0x0F, 0xB6, 0xC0, 0x0F, 0xAB, 0x43, 0xE0, 0x72, 0xF5, 0x88, 0x04, 0x0B, 0xFE, 0xC1};

	BYTE ChitonE_Sig[] = {0xF2, 0x88, 0x04, 0x0B, 0xFE, 0xC1, 0x75, 0xEB, 0x5F, 0x55, 0x8A, 0xC1, 0xD7, 0x88, 0x0C, 0x06,
						   0xFE, 0xC1, 0x75, 0xF6, 0xE8, 0xC6, 0x06, 0x00, 0x00, 0x25, 0xFC, 0x0F, 0x00, 0x00, 0x8B, 0xC8};

	BYTE ChitonQ_Sig[] = {0x8B, 0xFC, 0xE8, 0xEE, 0x03, 0x00, 0x00, 0x8B, 0xFB, 0xE8, 0x9C, 0xFC, 0xFF, 0xFF, 0x6C, 0x4A,
						   0xEA, 0x14, 0xEE, 0xB9, 0x84, 0x82, 0xFD, 0x48, 0x0D, 0xF0, 0xEE, 0xB9, 0x92, 0x82, 0x9A, 0xFB};

	DWORD dwOrgByteLoc, dwVirusCodeSize;
	if(memcmp(&m_pbyBuff[0x420], &ChitonR_U_Sig[0], 0x20) == 0) //Chiton.R or Chiton.U infection. Both infection almost similar
	{
		dwOrgByteLoc = 0x2C5;
		dwVirusCodeSize = 0x80FC;
	}
	else if(memcmp(&m_pbyBuff[0x469], &ChitonE_Sig[0], 0x20) == 0) //Chiton.E infection
	{
		dwOrgByteLoc = 0x2D9;
		dwVirusCodeSize = 0x8098;
	}
	else if(memcmp(&m_pbyBuff[0x3C5], &ChitonQ_Sig[0], 0x20) == 0) //Chiton.Q infection
	{
		dwOrgByteLoc = 0x2C5;
		dwVirusCodeSize = 0x813C;
	}
	else
	{
		return iRetStatus;
	}

	//Get virus code patched offset in entry point section
	//First 32 bytes are original data of patched location and from 34 to 37(DWORD)is patch location. [33rd byte is not usefull]
	DWORD dwPatchedOffset2 = *((DWORD *)&m_pbyBuff[dwOrgByteLoc + 0x21]); //Skip 1 byte

	//Check for negative value
	if(dwPatchedOffset2 & 0x80000000)
	{
		return iRetStatus;
	}
			
	//Check valid offset or not
	if((dwPatchedOffset2 < m_dwImageBase) ||(dwPatchedOffset2 >(m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)))
	{
		return iRetStatus;
	}

	//convert virtual offset to file offset
	dwPatchedOffset2 -= m_dwImageBase;
	m_pMaxPEFile->Rva2FileOffset(dwPatchedOffset2, &dwPatchedOffset2);

	//check the virus patched offset found in AEP section with the offset calculated after decryption of virus code
	if(dwPatchedOffset2 != m_dwPatchedOffset)
	{
		return iRetStatus;
	}

	//All virus cleaning criteria matched, so repair file.

	//Overwrite patched virus code with original bytes
	if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwOrgByteLoc], dwPatchedOffset2, 0x20,0x20))
	{
		return iRetStatus;
	}
			
	//Calculate exact start location of virus code
	DWORD dwTotalVirusCode =(((dwVirusCodeSize + m_pMaxPEFile->m_stPEHeader.FileAlignment - 1) 
							 / m_pMaxPEFile->m_stPEHeader.FileAlignment)
							 * m_pMaxPEFile->m_stPEHeader.FileAlignment);

	DWORD dwVirusCodeStartOffset = 0;
	//Below code repairs the files in which virus code is added at the end of the last section.
	if(((m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData) - dwTotalVirusCode) < m_dwVirusCodeOffset)
	{		
		//Fill zero to the virus code.(Filling only partial code, decryption length)
		if(!m_pMaxPEFile->FillWithZeros(m_dwVirusCodeOffset, m_dwDecLength))
		{
			return iRetStatus;
		}		
	}	
	//Below code repairs the files which has the virus code from last section PRD itself		
	else if(!m_pMaxPEFile->FillWithZeros(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, dwVirusCodeSize))
	{
		return iRetStatus;
	}		
	m_pMaxPEFile->RepairOptionalHeader(0x16, 0, 0);
	return REPAIR_SUCCESS;
}