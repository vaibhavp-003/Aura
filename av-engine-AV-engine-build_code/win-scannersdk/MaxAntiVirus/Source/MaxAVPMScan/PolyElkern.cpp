/*======================================================================================
FILE				: PolyElkern.cpp
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
NOTES				: This is detection module for malwares Poly Elkern Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyElkern.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyElkern
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyElkern::CPolyElkern(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_dwElkernAOriAEP = 0;
	memset(&m_ElkernParam, 0, sizeof(m_ElkernParam));
	m_pbyBuff = new BYTE[ELKERNC_BUFF_SIZE];
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyElkern
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyElkern::~CPolyElkern(void)
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
	Description		: Detection routine for different varients of Elkern Family
--------------------------------------------------------------------------------------*/
int CPolyElkern::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(!GetBuffer(m_dwAEPMapped, 7, 7))	
	{
		return iRetStatus;
	}
	
	//First Byte should be 0xE9 which is JMP
	if(m_pbyBuff[0] != 0xE9 && m_pbyBuff[2] != 0xE8 && m_pbyBuff[0] != 0xE8)
	{
		return iRetStatus;
	}

	//Calculate JMP address
	DWORD dwJumpRVA =0;
	if(m_pbyBuff[2]==0xE8)
	{
		dwJumpRVA = *((DWORD *)&m_pbyBuff[3]) + 0x05 + m_dwAEPUnmapped + 0x2;	
	}
	else
		dwJumpRVA = *((DWORD *)&m_pbyBuff[1]) + 0x05 + m_dwAEPUnmapped;	
		
	m_ElkernParam.wVirusSection =	m_pMaxPEFile->Rva2FileOffset(dwJumpRVA, &m_ElkernParam.dwStartOfVirusCode);		
	
	if(m_pbyBuff[0] == 0xE8 && m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 0xC00)
	{
		//Read from JMP address
		if(GetBuffer(m_ElkernParam.dwStartOfVirusCode, ELKERNA_BUFF_SIZE, ELKERNA_BUFF_SIZE))	
		{
			if(0x5D == m_pbyBuff[0] && 0x60 == m_pbyBuff[2] && 0x8D == m_pbyBuff[3])
			{		
				if(GetElkernAParam())
				{
					m_eInfectionType = ELKERN_AB;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Elkern"));
					return VIRUS_FILE_REPAIR;
				}			
			}
		}
	}
	else if(m_pbyBuff[0] == 0xE9) //Changes
	{
		//Read from JMP address
		if(GetBuffer(m_ElkernParam.dwStartOfVirusCode, ELKERNC_BUFF_SIZE, 0x100))	
		{		
			BYTE	bBufferSig[]	= {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8D};
			if(memcmp(&m_pbyBuff[0], bBufferSig, sizeof(bBufferSig)) == 0 || memcmp(&m_pbyBuff[2], bBufferSig, sizeof(bBufferSig)) == 0)
			{
				//Get the Required Parameters for ELkern
				BYTE bBuffer[] = {0xE8, 0xC8, 0x00, 0x00, 0x00, 0xC3, 0x81, 0xED};
				DWORD dwIndex = 0x00;
				if(OffSetBasedSignature(bBuffer, sizeof(bBuffer), &dwIndex))
				{	
					if(dwIndex + 0x14 < m_dwNoOfBytes)
					{
						m_ElkernParam.dwPatchedOffset = dwIndex + sizeof(bBuffer) + 0x0D;						
						m_eInfectionType = ELKERN_C;
						iRetStatus = VIRUS_FILE_REPAIR;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Elkern.C"));
					}
				}
			}
		}
	}
	else if(m_pbyBuff[2] == 0xE8)
	{
		if(GetBuffer(m_dwAEPMapped, 0x40, 0x40))	
		{
			BYTE	bSig1[]	= {0x9C, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8D};
			BYTE	bSig2[] = {0xE8, 0xC8, 0x00, 0x00, 0x00, 0xC3, 0x81, 0xED};
			if(memcmp(&m_pbyBuff[0x0], bSig1, sizeof(bSig1)) == 0 && 
				memcmp(&m_pbyBuff[0x2C], bSig2, sizeof(bSig2)) == 0)
			{	
				m_pMaxPEFile->ReadBuffer(&m_dwElkernAOriAEP, m_ElkernParam.dwStartOfVirusCode + 0x33, 0x4);
				m_eInfectionType = ELKERN_C1;
				iRetStatus = VIRUS_FILE_REPAIR;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Elkern.C"));
		
			}
		}
	}
	return iRetStatus;	
}

/*-------------------------------------------------------------------------------------
	Function		: GetElkernAParam
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function retrieves Parameters for Varient A
--------------------------------------------------------------------------------------*/
int CPolyElkern::GetElkernAParam()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	BYTE		B1 = 0, B2 = 0, bXORKey1 = 0, byROLCnt = 0, bXORKey2 = 0;
	DWORD		dwLength = 0, dwInstructionCnt = 0, dwOffset = 6;
	DWORD		dwMatchedInstr = 0;
	t_disasm	da;

	while(dwOffset < 0x1D)
	{
		if(dwInstructionCnt > 10)
		{
			return iRetStatus;
		}

		memset(&da, 0x00, sizeof(struct t_disasm));

		B1 = *((BYTE *)&m_pbyBuff[dwOffset]);
		B2 = *((BYTE *)&m_pbyBuff[dwOffset + 1]);
		
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	
		dwInstructionCnt++;

		if(B1 == 0x66 && dwMatchedInstr == 0 && dwLength == 4 && strstr(da.result, ",258")|| strstr(da.result, ",256"))
		{
			dwMatchedInstr++;
		}
		else if(B1 == 0xFC && dwMatchedInstr == 1 && dwLength == 1 && strstr(da.result, "CLD"))
		{
			dwMatchedInstr++;
		}
		else if(B1 == 0x8A && dwMatchedInstr == 2 && dwLength == 2 && strstr(da.result, "MOV"))
		{
			dwMatchedInstr++;
		}
		else if(B1 == 0x80 && dwMatchedInstr == 3 && dwLength == 3 && strstr(da.result, "XOR"))
		{
			bXORKey1 = m_pbyBuff[dwOffset + 2];
			dwMatchedInstr++;
		}
		else if(B1 == 0xC0 && dwMatchedInstr == 4 && dwLength == 3 && strstr(da.result, "ROL"))
		{
			byROLCnt = m_pbyBuff[dwOffset + 2];
			dwMatchedInstr++;
		}
		else if(B1 == 0x80 && dwMatchedInstr == 5 && dwLength == 3 && strstr(da.result, "XOR"))
		{
			bXORKey2 = m_pbyBuff[dwOffset + 2];
			dwMatchedInstr++;
		}
		else if(B1 == 0x88 && dwMatchedInstr == 6 && dwLength == 2 && strstr(da.result, "MOV"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 7 && dwLength == 1 && strstr(da.result, "INC"))
		{
			dwMatchedInstr++;
		}
		else if(B1 == 0x66 && dwMatchedInstr == 8 && dwLength == 2 && strstr(da.result, "DEC"))
		{
			dwMatchedInstr++;
		}
		else if(B1 == 0x75 && B2 == 0xEE && dwMatchedInstr == 9 && dwLength == 2 && strstr(da.result, "JNZ"))
		{
			BYTE bOriginalAEP[0x14] = {0};
			if(m_pMaxPEFile->ReadBuffer(bOriginalAEP, m_ElkernParam.dwStartOfVirusCode + 0x176, 0x14, 0x14))
			{
				DWORD dwRotateCounter = byROLCnt % 0x08;
				for(int i = 0; i < 0x14; i++)
				{
					bOriginalAEP[i] ^= bXORKey1;
					bOriginalAEP[i] = bOriginalAEP[i] << dwRotateCounter | bOriginalAEP[i] >> (0x08 - dwRotateCounter);
					bOriginalAEP[i] ^= bXORKey2;
				}
				for(int j = 0;j < 0x14; j++)
				{
					if(bOriginalAEP[j] == 0x2D && bOriginalAEP[j + 0x5] == 0x05)
					{
						m_dwElkernAOriAEP = *((DWORD *)&bOriginalAEP[j + 0x6]);
					}
				}
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwElkernAOriAEP, NULL))
				{
					iRetStatus = VIRUS_FILE_REPAIR;
					break;
				}
			}
		}
		dwOffset += dwLength;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Elkern Family
--------------------------------------------------------------------------------------*/
int CPolyElkern::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;

	if(ELKERN_AB == m_eInfectionType)
	{
		if(m_pMaxPEFile->WriteAEP(m_dwElkernAOriAEP))
		{
			if(m_wAEPSec == m_wNoOfSections - 1)
			{
				return m_pMaxPEFile->TruncateFile(m_dwAEPMapped - 8, true) ? REPAIR_SUCCESS : iRetStatus;
			}
			else
			{
				DWORD dwNoOfBytesFill = m_pSectionHeader[m_wAEPSec + 1].PointerToRawData - (m_dwAEPMapped - 8);
				return m_pMaxPEFile->FillWithZeros(m_dwAEPMapped - 8, dwNoOfBytesFill) ? REPAIR_SUCCESS : iRetStatus;
			}
		}
	}
	
	else if(ELKERN_C == m_eInfectionType)
	{
		//Write the first DWORD 
		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_ElkernParam.dwPatchedOffset], m_dwAEPMapped, sizeof(DWORD), sizeof(DWORD)))
		{
			//Write after that Byte
			if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_ElkernParam.dwPatchedOffset + 7], m_dwAEPMapped + 0x04, 1, 1))
			{	
				m_ElkernParam.dwStartOfVirusCode -= 8;
				DWORD dwVirusCodeSize = m_pSectionHeader[m_ElkernParam.wVirusSection].PointerToRawData + m_pSectionHeader[m_ElkernParam.wVirusSection].SizeOfRawData - m_ElkernParam.dwStartOfVirusCode;
				if(dwVirusCodeSize > 0x136F)
				{
					dwVirusCodeSize = 0x136F;
				}
				
				//Fill with Zero VirusCode
				if(m_pMaxPEFile->FillWithZeros(m_ElkernParam.dwStartOfVirusCode, dwVirusCodeSize))
				{
					iRetStatus = REPAIR_SUCCESS;
				}
			}
		}
	}
	else if(ELKERN_C1 == m_eInfectionType)
	{
		if(m_pMaxPEFile->WriteAEP(m_dwElkernAOriAEP))
		{
			DWORD dwFillBytes = m_pMaxPEFile->m_dwFileSize - (m_dwAEPMapped - 0x8);
			if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped - 0x8,dwFillBytes))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
	}
	return iRetStatus;

}
