/*======================================================================================
FILE				: PolyBolzano.cpp
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
NOTES				: This is detection module for malware Bolzano Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyBolzano.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyBolzano
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyBolzano::CPolyBolzano(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile),
m_dwVirusStartOffset(0),
m_dwCallPatchAdd(0)
{	
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyBolzano
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyBolzano::~CPolyBolzano(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_arrPatchedCallOffsets.RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Bolzano Family
--------------------------------------------------------------------------------------*/
int CPolyBolzano::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(m_wAEPSec == m_wNoOfSections - 1)
	{
		return iRetStatus;
	}

	if(!GetPatchedCalls(m_pSectionHeader[m_wAEPSec].PointerToRawData, m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData, m_wNoOfSections - 1))
	{
		return iRetStatus;
	}

	if(0 == m_arrPatchedCallOffsets.GetCount())
	{
		return iRetStatus;
	}
	
	const int BUFF_SIZE = 0x1100;
	m_pbyBuff = new BYTE[BUFF_SIZE];	
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, BUFF_SIZE);
	
	DWORD dwCalledAdd = 0, dwCounter = 0;

	LPVOID	lpPos = m_arrPatchedCallOffsets.GetHighest();
	while(lpPos)
	{
		m_arrPatchedCallOffsets.GetData(lpPos, m_dwCallPatchAdd);
		m_arrPatchedCallOffsets.GetKey(lpPos, dwCalledAdd);
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwCalledAdd, &m_dwVirusStartOffset))
		{					
			if(DetectBolzano())
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Bolzano.Gen"));
				return VIRUS_FILE_DELETE;
			}			
		}
		lpPos = m_arrPatchedCallOffsets.GetHighestNext(lpPos);
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Bolzano Family
--------------------------------------------------------------------------------------*/
bool CPolyBolzano::DetectBolzano()
{
	const int BOLZANO_BUFF_SIZE = 0x100;
	if(GetBuffer(m_dwVirusStartOffset, BOLZANO_BUFF_SIZE, BOLZANO_BUFF_SIZE))
	{
		if(m_pbyBuff[0] == 0x60)
		{
			t_disasm da;
			DWORD dwLength = 0x00, dwOffset = 0x00, dwInstCount = 0x00;
			int iStg = 0x00;
			while(dwOffset < m_dwNoOfBytes && dwInstCount <= 0x20)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (m_dwNoOfBytes - dwOffset))
				{
					break;
				}
				dwInstCount++;

				if(dwLength == 0x05 && strstr(da.result, "MOV E"))
				{
					if(da.immconst > m_dwImageBase)
					{
						if((da.immconst - m_dwImageBase) % 
							m_pMaxPEFile->m_stPEHeader.FileAlignment == 0x00)
						{
							iStg = 0x01;
						}
					}
				}
				else if(iStg == 0x01)
				{
					if((dwLength == 0x02 && (strstr(da.result,"XOR DWORD PTR[E") || strstr(da.result,"XOR [E"))) ||
						(dwLength == 0x02 && strstr(da.result,"JMP E")) || //Bolzano 2664
						(dwLength == 0x06 && (strstr(da.result,"XOR DWORD PTR[") || strstr(da.result,"XOR [")) && strstr(da.result,",E")))
					{
						return true;
					}
				}
				dwOffset += dwLength;
			}			
		}
	}
	return false;
}
