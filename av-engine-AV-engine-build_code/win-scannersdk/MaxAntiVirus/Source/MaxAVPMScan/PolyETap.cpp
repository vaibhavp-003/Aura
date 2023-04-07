/*======================================================================================
FILE				: PolyETap.cpp
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
CREATION DATE		: 08 Aug 2012
NOTES				: This is detection module for malware ETap Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyETap.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyETap
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyETap::CPolyETap(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	memset(&m_objETapStruct, 0, sizeof(ETap_Struct));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyETap
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyETap::~CPolyETap(void)
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
	Description		: Detection routine for different varients of Etap Family
--------------------------------------------------------------------------------------*/
int CPolyETap::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	// Basic checks

	// Check if its .dll or sys file
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL ||
		m_wAEPSec == m_wNoOfSections - 1 || m_pMaxPEFile->m_stPEHeader.Subsystem == 0x01)
	{
		return iRetStatus;
	}

	m_pbyBuff = new BYTE[ETAP_BUFF_SIZE + 6 + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, ETAP_BUFF_SIZE + 6 + MAX_INSTRUCTION_LEN);
	
	// Primary condition. Search for FF25 in first section
	bool bPrimaryCond  = false;	
	WORD wScanSecNo = 0;
	DWORD dwCallAddressVA = 0;
	for(DWORD dwIndex = m_pSectionHeader[0].PointerToRawData; dwIndex < (m_pSectionHeader[0].PointerToRawData + m_pSectionHeader[0].SizeOfRawData); dwIndex += ETAP_BUFF_SIZE)
	{
		if(!GetBuffer(dwIndex, ETAP_BUFF_SIZE + 6, 5))
			return iRetStatus;

		for(DWORD dwCount = 0; dwCount < m_dwNoOfBytes - 5; dwCount++)
		{
			if(m_pbyBuff[dwCount] == (BYTE)0x68 && m_pbyBuff[dwCount + 5] == (BYTE)0xC3)
			{
				DWORD dwPushRVA	= *((DWORD*)&m_pbyBuff [dwCount + 1]) - m_dwImageBase;
				DWORD dwPushAddress = 0;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwPushRVA, &dwPushAddress))
				{
					continue;
				}

				if(dwPushAddress  > m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData && dwPushAddress < (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
				{
					// DWORD lies in last section
					m_objETapStruct.dwVirusStart	= dwPushAddress;
					m_objETapStruct.dwVirusStartRVA = dwPushRVA;
					m_objETapStruct.iDetectionType	= PUSH_PATCH;
					m_objETapStruct.dwVirusStartAdd = dwPushAddress;
					m_objETapStruct.dwPatchAdd		= dwIndex + dwCount;
					m_objETapStruct.dwVirusSection	= LAST_SECTION;

					bPrimaryCond = true;
					break;
				}
				else if(dwPushAddress > m_pSectionHeader[0].PointerToRawData && dwPushAddress < (m_pSectionHeader[0].PointerToRawData + m_pSectionHeader[0].SizeOfRawData))
				{
					// DWORD lies in First section
					m_objETapStruct.dwVirusStart	= dwPushAddress;
					m_objETapStruct.dwVirusStartRVA = dwPushRVA;
					m_objETapStruct.iDetectionType	= PUSH_PATCH;
					m_objETapStruct.dwVirusStartAdd = dwPushAddress;
					m_objETapStruct.dwPatchAdd		= dwIndex + dwCount;
					m_objETapStruct.dwVirusSection	= FIRST_SECTION;

					bPrimaryCond = true;
					break;
				}
				else if(dwPushAddress >= m_pSectionHeader[1].PointerToRawData && dwPushAddress < (m_pSectionHeader[1].PointerToRawData + m_pSectionHeader[1].SizeOfRawData))
				{
					// DWORD lies in second section
					m_objETapStruct.dwVirusStart	= dwPushAddress;
					m_objETapStruct.dwVirusStartRVA = dwPushRVA;
					m_objETapStruct.iDetectionType	= PUSH_PATCH;
					m_objETapStruct.dwVirusStartAdd = dwPushAddress;
					m_objETapStruct.dwPatchAdd		= dwIndex + dwCount;
					m_objETapStruct.dwVirusSection	= SECOND_SECTION;

					bPrimaryCond = true;
					break;
				}
			}
			else if(0 == memcmp(&m_pbyBuff[dwCount], SEARCH_STRING, 2))
			{
				// If matched pickup the DWORD after matched string
 				DWORD dwTemp = *((DWORD*)&m_pbyBuff [dwCount + 2]) - m_dwImageBase;
				DWORD dwFirstAdd = 0x0;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwTemp, &dwFirstAdd))
				{
					continue;
				}

				if(dwFirstAdd > m_pSectionHeader[m_wAEPSec].PointerToRawData && dwFirstAdd < (m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData))
				{
					// DWORD lies in first section
					DWORD dwSecondAddRVA = 0x0;
					if(!m_pMaxPEFile->ReadBuffer(&dwSecondAddRVA, dwFirstAdd,4))
					{
						continue;
					}
					dwSecondAddRVA -= m_dwImageBase;
					DWORD dwSecondAdd = 0x0;
					if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwSecondAddRVA, &dwSecondAdd))
					{
						continue;
					}

					if(dwSecondAdd > m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData && dwSecondAdd < ( m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
					{
						// DWORD lies in last section
						m_objETapStruct.dwVirusStart	= dwSecondAdd;
						m_objETapStruct.dwVirusStartRVA = dwSecondAddRVA;
						m_objETapStruct.iDetectionType	= CALL_PATCH;
						m_objETapStruct.dwVirusStartAdd = dwFirstAdd;
						m_objETapStruct.dwPatchAdd		= dwIndex + dwCount;
						m_objETapStruct.dwVirusSection	= LAST_SECTION;

						bPrimaryCond = true;
						break;
					}
					if(dwSecondAdd > m_pSectionHeader[m_wAEPSec].PointerToRawData && dwSecondAdd < ( m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData))
					{
						// DWORD lies in First section
						m_objETapStruct.dwVirusStart	= dwSecondAdd;
						m_objETapStruct.dwVirusStartRVA = dwSecondAddRVA;
						m_objETapStruct.iDetectionType	= CALL_PATCH;
						m_objETapStruct.dwVirusStartAdd = dwFirstAdd;
						m_objETapStruct.dwPatchAdd		= dwIndex + dwCount;
						m_objETapStruct.dwVirusSection	= FIRST_SECTION;

						bPrimaryCond = true;
						break;
					}

					for(WORD dwCnt = m_wAEPSec + 1; dwCnt < m_wNoOfSections - 1; dwCnt++)
					{
						if(dwSecondAdd == m_pSectionHeader[dwCnt].PointerToRawData)
						{
							m_objETapStruct.dwVirusStart	= dwSecondAdd;
							m_objETapStruct.dwVirusStartRVA = dwSecondAddRVA;
							m_objETapStruct.iDetectionType	= CALL_PATCH;
							m_objETapStruct.dwVirusStartAdd = dwFirstAdd;
							m_objETapStruct.dwPatchAdd		= dwIndex + dwCount;
							m_objETapStruct.dwVirusSection	= SECOND_SECTION;
							bPrimaryCond = true;
							break;
						}
					}
					if(bPrimaryCond)
					{
						break;
					}
				}
			}
			else if(m_pbyBuff[dwCount] == 0xE8 ||m_pbyBuff[dwCount] == 0xE9)
			{
				dwCallAddressVA = *((DWORD *)&m_pbyBuff[dwCount + 1]);
				wScanSecNo = m_pMaxPEFile->GetSectionNoFromOffset(dwIndex + dwCount);
				if(OUT_OF_FILE == wScanSecNo)
				{
					continue;
				}
				dwCallAddressVA += m_pSectionHeader[wScanSecNo].VirtualAddress + dwIndex - m_pSectionHeader[wScanSecNo].PointerToRawData + dwCount + E8_INSTRUCTION_SIZE;
						
				// If call is out of the file then skip
				if(dwCallAddressVA >= (m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize))
				{
					continue;
				}

				// check if the call is in the reauired section. If so its patched call.
				if((dwCallAddressVA >= m_pSectionHeader[0].VirtualAddress) && ((dwCallAddressVA % m_pMaxPEFile->m_stPEHeader.FileAlignment)== 0x00))
				{	
					m_arrPatchedCallOffsets.AppendItem(dwCallAddressVA, dwIndex + dwCount);
				}
			}
		}
		if(bPrimaryCond)
		{
			break;
		}		
	}
	if(!bPrimaryCond)
	{
		if(m_arrPatchedCallOffsets.GetCount())
		{
			DWORD	dwCalledAdd		= 0x00;
			DWORD	dwCalledAddOff	= 0x00;

			LPVOID	lpos = m_arrPatchedCallOffsets.GetHighest();
			m_arrPatchedCallOffsets.GetData(lpos,dwCalledAdd);

			while(lpos)
			{
				m_arrPatchedCallOffsets.GetKey(lpos, dwCalledAdd);

				if(dwCalledAdd % m_pMaxPEFile->m_stPEHeader.FileAlignment== 0x00)
				{
					m_pMaxPEFile->Rva2FileOffset(dwCalledAdd, &dwCalledAddOff);
					m_objETapStruct.dwVirusStart = dwCalledAddOff;
					m_objETapStruct.dwVirusStartRVA = dwCalledAdd;
					m_objETapStruct.dwVirusSection	= FIRST_SECTION;
					bPrimaryCond = true;
					break;
				}
				lpos = m_arrPatchedCallOffsets.GetHighestNext(lpos);
			}
		}
	}
	if(bPrimaryCond)
	{
		if(CheckEtapInstruction())
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.ETap"));
			return VIRUS_FILE_DELETE;
		}
		bPrimaryCond = false;
	}
	if(!bPrimaryCond)
	{
		m_objETapStruct.dwVirusStart	= m_pSectionHeader[0].PointerToRawData;
		m_objETapStruct.dwVirusStartRVA = m_pSectionHeader[0].VirtualAddress;
		m_objETapStruct.iDetectionType	= CALL_PATCH;
		m_objETapStruct.dwVirusStartAdd = 0;
		m_objETapStruct.dwPatchAdd		= 0;
		m_objETapStruct.dwVirusSection	= FIRST_SECTION;
		bPrimaryCond = true;
	}
	if(bPrimaryCond)
	{
		if(CheckEtapInstruction())
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.ETap"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckEtapInstruction
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function checks for Etap Sig. instruction
--------------------------------------------------------------------------------------*/
int CPolyETap::CheckEtapInstruction()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	// check for secondary condition
	memset(m_pbyBuff, 0, ETAP_BUFF_SIZE + 1);
	if(!GetBuffer(m_objETapStruct.dwVirusStart, ETAP_BUFF_SIZE, 0))
	{
		return iRetStatus;
	}

	t_disasm da;
	DWORD dwCallCount = 0, dwIndex = 0, dwInstrucionLen = 0, dwEndLoop = 0;
	DWORD dwStartLoop = 0, dwJmpCount = 0, dwInstAdd = 0, dwInsCnt = 0;
	bool bLoopDetected = false, bMovFound = false;
	while(dwIndex < m_dwNoOfBytes)
	{
		memset(&da, 0, sizeof(t_disasm));
		dwInstAdd = m_objETapStruct.dwVirusStartRVA + dwIndex;
		dwInstrucionLen = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwIndex], MAX_INSTRUCTION_LEN, dwInstAdd, &da, DISASM_CODE);
		if(dwInstrucionLen > (m_dwNoOfBytes - dwIndex))
		{
			return iRetStatus;
		}
		dwInsCnt++;
		if(dwInsCnt > 0x80 && !bMovFound)
		{
			return false;
		}
		if(!_memicmp(da.result, "MOV DWORD PTR [", 15) && dwInstrucionLen == 0xA && dwInsCnt <= 0x70)
		{
			if(m_pbyBuff[dwIndex] == 0xC7 && m_pbyBuff[dwIndex + 1] == 0x05)
			{
				bMovFound = true;
			}
		}
		if(!_memicmp(da.result, "CALL [", 6) || !_memicmp(da.result, "CALL E", 6))
		{
			dwCallCount++;
		}
		if(!_memicmp(da.result, "JNZ ", 4) && dwCallCount > 0x2 )
		{
			dwJmpCount ++;
			if(dwInstAdd > da.jmpconst)
			{
				dwStartLoop = dwIndex-(dwInstAdd - da.jmpconst);
				dwEndLoop = dwIndex + 0x0A;
				if(dwEndLoop - dwStartLoop < 0x500)
				{
					bLoopDetected = true;
					if(bLoopDetected && bMovFound)
					{
						if(GetEtapLoopIns(dwStartLoop, dwEndLoop))
						{
							return VIRUS_FILE_DELETE;
						}
					}
				}
			}
		}
		if(!_memicmp(da.result, "JMP ", 4) && dwCallCount > 0x2 )
		{
			dwJmpCount ++;
			if(dwInstAdd > da.jmpconst)
			{
				dwStartLoop = dwIndex-(dwInstAdd - da.jmpconst);
				dwEndLoop = dwIndex + 0x0A;
				if(dwEndLoop - dwStartLoop < 0x500)
				{
					bLoopDetected = true;
					if(bLoopDetected && bMovFound)
					{
						if(GetEtapLoopIns(dwStartLoop, dwEndLoop))
						{
							return VIRUS_FILE_DELETE;
						}
					}
				}
			}
		}
		dwIndex += dwInstrucionLen;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetEtapLoopIns
	In Parameters	: DWORD dwStartLoop, DWORD dwEndLoop
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function checks for Instruction Loop
--------------------------------------------------------------------------------------*/
int CPolyETap::GetEtapLoopIns(DWORD dwStartLoop, DWORD dwEndLoop)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD dwXORCount = 0x0, dwJMPCount = 0x0, dwInstrucionLen = 0x0, dwInstAdd = 0x0, dwIndex = dwStartLoop;
	BOOL bInstFound = FALSE;
	bool bMovFound = false, bPushFound = false, bPopFound = false;
	t_disasm da;
	while(dwIndex <= dwEndLoop)
	{
		memset(&da,0,sizeof(t_disasm));
		dwInstAdd = m_objETapStruct.dwVirusStartRVA + dwIndex;
		dwInstrucionLen = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwIndex], MAX_INSTRUCTION_LEN, dwInstAdd, &da, DISASM_CODE);
		if(dwInstrucionLen > (dwEndLoop - dwIndex))
		{
			return iRetStatus;
		}
		if(!_memicmp(da.result, "PUSH", 4))
		{
			bPushFound = true;
		}
		if(!_memicmp(da.result, "POP ", 4))
		{
			bPopFound = true;
		}
		if(dwInstrucionLen >= 0x06 && da.adrconst != 0x00 && (strstr(da.result, "MOV E") || strstr(da.result, "PUSH")) 
			&& strstr(da.result, "[E") && (da.adrconst % m_pMaxPEFile->m_stPEHeader.FileAlignment) == 0 && 
			da.adrconst < m_pMaxPEFile->m_stPEHeader.SizeOfImage + m_pMaxPEFile->m_stPEHeader.ImageBase)
		{

			if(da.adrconst > m_dwImageBase)
			{
				da.adrconst -= m_dwImageBase;
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(da.adrconst,NULL))
				{
					bInstFound = TRUE;
				}
			}					
		}
		if(!_memicmp(da.result, "XOR ", 4))
		{
			dwXORCount++;
		}
		if(!_memicmp(da.result, "MOV DWORD PTR [", 15) && dwInstrucionLen == 0xA)
		{
			if(m_pbyBuff[dwIndex] == 0xC7 && m_pbyBuff[dwIndex + 1] == 0x05)
			{
				bMovFound = true;
			}
		}
		if(!_memicmp(da.result, "ADD ", 4) && dwInstrucionLen == 0xA)
		{
			bMovFound = true;
		}
		if(!_memicmp(da.result, "SUB ", 4) && dwInstrucionLen == 0xA)
		{
			bMovFound = true;
		}
		if(!_memicmp(da.result, "AND ", 4) && dwInstrucionLen == 0xA)
		{
			bMovFound = true;
		}
		if(!_memicmp(da.result, "J", 1))
		{
			dwJMPCount++;
		}
		if((dwXORCount >= 1) && (dwJMPCount >= 1) && bInstFound == TRUE && bPushFound && bMovFound && bPopFound)
		{
			iRetStatus = VIRUS_FILE_DELETE;
			break;
		}
		dwIndex += dwInstrucionLen;
	}
	return iRetStatus;
}

