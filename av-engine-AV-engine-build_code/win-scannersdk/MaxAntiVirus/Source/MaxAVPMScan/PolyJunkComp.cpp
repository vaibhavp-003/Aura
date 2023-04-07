/*======================================================================================
FILE				: PolyJunkComp.cpp
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
NOTES				: This is detection module for malware JunkComp Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyJunkComp.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyJunkComp
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyJunkComp::CPolyJunkComp(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_dwVirusBodyStart = 0x0;
	memset(szVirCodeReg, 0, 4);
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyJunkComp
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyJunkComp::~CPolyJunkComp(void)
{
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of JunkComp Family
--------------------------------------------------------------------------------------*/
int CPolyJunkComp::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL &&
		m_pMaxPEFile->m_stPEHeader.NumberOfSections > 2 &&
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000060) == 0xE0000060)
	{
		m_pbyBuff = new BYTE[JUNK_COMP_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(m_pbyBuff)
		{
			memset(m_pbyBuff, 0, JUNK_COMP_BUFF_SIZE + MAX_INSTRUCTION_LEN);
			if(GetBuffer(m_dwAEPMapped, JUNK_COMP_BUFF_SIZE, JUNK_COMP_BUFF_SIZE))
			{
				if(GetJunkCompParam())
				{
					iRetStatus = VIRUS_FILE_DELETE;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.JunkComp"));
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: ValidateJmpAddressAndReadBuffer
	In Parameters	: DWORD dwJmpAdd
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: this function validates infected JMP instruction and collects buffer from that address
--------------------------------------------------------------------------------------*/
bool CPolyJunkComp::ValidateJmpAddressAndReadBuffer(DWORD dwJmpAdd)
{	
	if(NEGATIVE_JUMP(dwJmpAdd))
		return false;

	if(dwJmpAdd < (m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize))
	{	
		WORD	wSec = 0;
		DWORD dwJumpOffset = Rva2FileOffsetEx(dwJmpAdd, &wSec);
		if(dwJumpOffset != 0x00)
		{
			if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0], dwJumpOffset, JUNK_COMP_BUFF_SIZE, JUNK_COMP_BUFF_SIZE))
				return true;
		}
	}		
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ValidateVirusBodyStartAddress
	In Parameters	: DWORD dwVirusCodeStartAdd
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function validates infection start offset and collects buffer from that address
--------------------------------------------------------------------------------------*/
bool CPolyJunkComp::ValidateVirusBodyStartAddress(DWORD dwVirusCodeStartAdd)
{
	if(NEGATIVE_JUMP(dwVirusCodeStartAdd))
		return false;

	DWORD dwLastSecStartVA = m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase;
	DWORD dwLastSecEndVA = dwLastSecStartVA + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize;

	if((dwVirusCodeStartAdd < dwLastSecStartVA) || (dwVirusCodeStartAdd >= dwLastSecEndVA))
		return false;

	m_dwVirusBodyStart = dwVirusCodeStartAdd;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: UpdateRegister
	In Parameters	: char *szReg, DWORD dwRegValue, int iOperation, bool bValidate
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Modifies the value of CPU register
--------------------------------------------------------------------------------------*/
bool CPolyJunkComp::UpdateRegister(char *szReg, DWORD dwRegValue, int iOperation, bool bValidate)
{
	int i = 0;
	
	for(i = 0; i < 8; i++)
	{
		if(strcmp(szDefaultReg[i], szReg) == 0)
			break;
	}
	if(i == 8)
		return false;

	switch(iOperation)
	{
		case COPY:
			stJunkCompReg[i].dwRegValue = dwRegValue;
			break;
		
		case ADD:
			stJunkCompReg[i].dwRegValue += dwRegValue;
			break;

		case SUB:
			stJunkCompReg[i].dwRegValue -= dwRegValue;
			break;
		
		case XOR:
			stJunkCompReg[i].dwRegValue ^= dwRegValue;
			break;

		default:
			break;
	}

	if(bValidate)
	{
		if(ValidateVirusBodyStartAddress(stJunkCompReg[i].dwRegValue))
			strcpy_s(szVirCodeReg, 4, stJunkCompReg[i].szReg);
	}
			
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetJunkCompParam
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Gathers all the neccessary parameters for detection and repair
--------------------------------------------------------------------------------------*/
bool CPolyJunkComp::GetJunkCompParam()
{
	t_disasm da;
	DWORD	dwOffset = 0, dwLength; 
	BYTE	B1, B2, B3;

	char szTmpReg[4];
	int iRegCount = 0, i, iValidInst = 0, iExtraInst = 0, iJumpCounts = 0;
	bool bValidRegFound = false, bValidate = false;
	char szDefReg[8][4] = {"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP"};
	char szInstruction[MAX_PATH] = {0};
	DWORD dwJmpAdd = 0, dwReadOffsetRVA = m_dwAEPUnmapped, dwPushValue = 0, dwRegValue = 0;

	for(i = 0; i < 8; i++)
	{
		strcpy_s(szDefaultReg[i], 4, szDefReg[i]);
		strcpy_s(stJunkCompReg[i].szReg, 4, szDefReg[i]);
		stJunkCompReg[i].dwRegValue = 0x0;
	}

	m_objMaxDisassem.InitializeData();
	m_dwInstCount = m_dwVirusBodyStart = 0;

	while(dwOffset < JUNK_COMP_BUFF_SIZE)
	{
		if(m_dwInstCount > 0x300 )
			break;

		if(!m_dwVirusBodyStart && (m_dwInstCount > 0x100))
			break;

		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = *((BYTE*)&m_pbyBuff[dwOffset]);
		B2 = *((BYTE*)&m_pbyBuff[dwOffset + 1]);
		B3 = *((BYTE*)&m_pbyBuff[dwOffset + 2]);
		
		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if(B1==0xD1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (JUNK_COMP_BUFF_SIZE - dwOffset))
		{
			break;
		}

		if(dwLength==0x01 && _strcmpi(da.dump, "FFFFFFC3")== 0)
		{
			dwOffset += dwLength;
			continue;
		}

		if(dwLength==0x01 && B1==0xE2 && strstr(da.result, "???"))
		{
			dwOffset += 0x02;
			continue;
		}

		if(dwLength==0x01 && B1==0xDB && _strcmpi(da.dump, "FFFFFFDB")== 0)
		{
			dwOffset += dwLength;
			continue;
		}

		//C0F7 90		SAL BH,90
		if(dwLength==0x01 && B1==0xC0 && B2==0xF7 && strstr(da.result, "???") && _strcmpi(da.dump, "FFFFFFC0")== 0) 
		{
			dwOffset += 3;
			continue;
		}

		//D3F2		SAL EDX,CL
		if(dwLength==0x01 && B1==0xD3 && B2==0xF2 && strstr(da.result, "???") && _strcmpi(da.dump, "FFFFFFD3")== 0) 
		{
			dwOffset += 2;
			continue;
		}

		m_dwInstCount++;

		if(dwLength==0x02 && B1==0x74 && strstr(da.result, "JE SHORT")) //JE SHORT
		{
			iJumpCounts++;
			dwOffset += dwLength;
			dwJmpAdd = dwReadOffsetRVA + dwOffset + (DWORD)B2;
			if(!ValidateJmpAddressAndReadBuffer(dwJmpAdd))
			{
				break;
			}
			dwReadOffsetRVA = dwJmpAdd;
			dwOffset = 0x00;
			continue;
		}

		if(dwLength==0x02 && B1==0xEB && strstr(da.result, "JMP SHORT")) //JMP SHORT
		{
			iJumpCounts++;
			dwOffset += dwLength;
			dwJmpAdd = dwReadOffsetRVA + dwOffset + (DWORD)B2;
			if(!ValidateJmpAddressAndReadBuffer(dwJmpAdd))
			{
				break;
			}
			dwReadOffsetRVA = dwJmpAdd;
			dwOffset = 0x00;
			continue;
		}

		if(dwLength==0x02 && B1==0x75 && strstr(da.result, "JNZ SHORT")) //JNE SHORT
		{
			dwOffset += dwLength;
			dwJmpAdd = dwReadOffsetRVA + dwOffset + (DWORD)B2;
			if(!ValidateJmpAddressAndReadBuffer(dwJmpAdd))
			{
				break;
			}
			dwReadOffsetRVA = dwJmpAdd;
			dwOffset = 0x00;
			continue;
		}

		//Find virus body start
		if(!m_dwVirusBodyStart)
		{
			bValidate = false;

			//There are two type of MOV EXX, XXXXXXXX
			//1. XX	XXXXXXXX	(Length 5)	 Ex: B9 347FFD21   MOV ECX,21FD7F34 
			//2. XXXX XXXXXXXX	(Length 6)	 Ex: C7C1 347FFD21     MOV ECX,21FD7F34


			//MOV EXX, XXXXXXXX  Type 1. XX	XXXXXXXX	(Length 5)
			if(dwLength==0x05 && (B1>=0xB8 && B1<=0xBF) && strstr(da.result, "MOV E"))
			{
				bValidRegFound = true;
				strncpy_s(szTmpReg, 4, &da.result[4], 3);
				dwRegValue = *(DWORD *)&m_pbyBuff[dwOffset+1];
				if(!m_dwVirusBodyStart)
					bValidate = true;
				UpdateRegister(szTmpReg, dwRegValue, COPY, bValidate);
				dwOffset += dwLength;
				continue;
			}

			//MOV EXX, XXXXXXXX  Type 2. XXXX XXXXXXXX	(Length 6)
			if(dwLength==0x06 && B1==0xC7 && (B2>=0xC0 && B2<=0xC7) && strstr(da.result, "MOV E")) 
			{
				bValidRegFound = true;
				strncpy_s(szTmpReg, 4, &da.result[4], 3);
				dwRegValue = *(DWORD *)&m_pbyBuff[dwOffset+2];
				if(!m_dwVirusBodyStart)
					bValidate = false;
				UpdateRegister(szTmpReg, dwRegValue, COPY, bValidate);
				dwOffset += dwLength;
				continue;
			}

			//PUSH XXXXXXXX
			if(dwLength==0x5 && B1==0x68 && strstr(da.result, "PUSH"))
			{
				dwPushValue = *(DWORD *)&m_pbyBuff[dwOffset + 1];
				dwOffset += dwLength;
				continue;
			}
			
			//LEA EXX, [XXXXXXXX]
			if(dwLength==0x06 && B1==0x8D && strstr(da.result, "LEA E") && strstr(da.result, ",["))
			{
				bValidRegFound = true;
				strncpy_s(szTmpReg, 4, &da.result[4], 3);
				dwRegValue = *(DWORD *)&m_pbyBuff[dwOffset+2];
				if(!m_dwVirusBodyStart)
					bValidate = false;
				UpdateRegister(szTmpReg, dwRegValue, COPY, bValidate);
				dwOffset += dwLength;
				continue;
			}

			//POP EXX
			if(dwPushValue && dwLength==0x1 && (B1>=0x58 && B1<=0x5F) && strstr(da.result, "POP E"))
			{
				bValidRegFound = true;
				strncpy_s(szTmpReg, 4, &da.result[4], 3);
				if(!m_dwVirusBodyStart)
					bValidate = true;
				UpdateRegister(szTmpReg, dwPushValue, COPY, bValidate);
				dwPushValue = 0x0;
				dwOffset += dwLength;
				continue;
			}

			if(bValidRegFound && !m_dwVirusBodyStart)
			{
				//ADD EXX, XXXXXXXX
				if(dwLength==0x06 && B1==0x81 && strstr(da.result, "ADD E"))
				{
					strncpy_s(szTmpReg, 4, &da.result[4], 3);
					dwRegValue = *(DWORD *)&m_pbyBuff[dwOffset+2];
					if(!m_dwVirusBodyStart)
						bValidate = true;
					UpdateRegister(szTmpReg, dwRegValue, ADD, bValidate);
					dwOffset += dwLength;
					continue;
				}

				//XOR EXX, XXXXXXXX
				if(dwLength==0x06 && B1==0x81 && strstr(da.result, "XOR E"))
				{
					strncpy_s(szTmpReg, 4, &da.result[4], 3);
					dwRegValue = *(DWORD *)&m_pbyBuff[dwOffset+2];
					if(!m_dwVirusBodyStart)
						bValidate = true;
					UpdateRegister(szTmpReg, dwRegValue, XOR, bValidate);
					dwOffset += dwLength;
					continue;
				}

				//SUB EXX, XXXXXXXX
				if(dwLength==0x06 && B1==0x81 && strstr(da.result, "SUB E"))
				{
					strncpy_s(szTmpReg, 4, &da.result[4], 3);
					dwRegValue = *(DWORD *)&m_pbyBuff[dwOffset+2];
					if(!m_dwVirusBodyStart)
						bValidate = true;
					UpdateRegister(szTmpReg, dwRegValue, SUB, bValidate);
					dwOffset += dwLength;
					continue;
				}
			}
		}

		//Check some of the JunkComp related instructions
		if(m_dwVirusBodyStart)
		{
			//Check some common instructions after getting virus body start address
			if(dwLength==0x02 && strstr(da.result, szVirCodeReg) && 
				(strstr(da.result, "CMP [E") || strstr(da.result, "TEST [E")))
			{
				sprintf_s(szInstruction, _countof(szInstruction), "CMP [%s],E", szVirCodeReg);
				if(strstr(da.result, szInstruction))
					iExtraInst++;
				else
				{
					sprintf_s(szInstruction, _countof(szInstruction), "TEST [%s],E", szVirCodeReg);
					if(strstr(da.result, szInstruction))
						iExtraInst++;
				}
				dwOffset += dwLength;
				continue;
			}

			if(dwLength==0x06 && strstr(da.result, szVirCodeReg) && 
				(strstr(da.result, "TEST E")))
			{
				sprintf_s(szInstruction, _countof(szInstruction), "TEST %s,", szVirCodeReg);
				if(strstr(da.result, szInstruction))
					iExtraInst++;
				dwOffset += dwLength;
				continue;
			}

			//Virus code start found, follow the register where virus start code stored.
			if(strstr(da.result, szVirCodeReg) &&
				(strstr(da.result, "ADD [E") || strstr(da.result, "SUB [E") || strstr(da.result, "XOR [E")))
			{
				sprintf_s(szInstruction, _countof(szInstruction), "ADD [%s],E", szVirCodeReg);
				if(dwLength==2 && strstr(da.result, szInstruction))
				{
					iValidInst++;
					dwOffset += dwLength;
					continue;
				}

				sprintf_s(szInstruction, _countof(szInstruction), "SUB [%s],E", szVirCodeReg);
				if(dwLength==2 && strstr(da.result, szInstruction))
				{
					iValidInst++;
					dwOffset += dwLength;
					continue;
				}

				sprintf_s(szInstruction, _countof(szInstruction), "XOR [%s],E", szVirCodeReg);
				if(dwLength==2 && strstr(da.result, szInstruction))
				{
					iValidInst++;
					dwOffset += dwLength;
					continue;
				}
			}
		}
		dwOffset += dwLength;
	}
	if(m_dwVirusBodyStart && (iValidInst >= 0x1) && (iExtraInst >= 0x3) && (iJumpCounts > 0xE))
	{
		return true;
	}

	return false;
}