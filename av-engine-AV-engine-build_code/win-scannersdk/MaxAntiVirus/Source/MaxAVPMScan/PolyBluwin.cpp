/*======================================================================================
FILE				: PolyBluwin.cpp
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
NOTES				: This is detection module for malwares Bluwin Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR	
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyBluwin.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyBluwin
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyBluwin::CPolyBluwin(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_bDecOffset = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyBluwin
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyBluwin ::~CPolyBluwin(void)
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
	Description		: Detection routine for different varients of Bluwin Family
--------------------------------------------------------------------------------------*/
int CPolyBluwin::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections - 1 && (m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xA0000020) == 0xA0000020)
	{
		m_pbyBuff = new BYTE[BLUWIN_BUFF_SIZE];	  
		if(GetBuffer(m_dwAEPMapped, BLUWIN_BUFF_SIZE, BLUWIN_BUFF_SIZE))
		{
			const BYTE bySig1[] = {0x29, 0xC0, 0xFE, 0xC8, 0x08, 0xC0, 0x74, 0x04, 0x75, 0xF8, 0xEB, 0x67};
			const BYTE bySig2[] = {0x29, 0xDB, 0x29, 0xC9,0xB1, 0xED, 0x43, 0x49, 0x75, 0xFC};
			
			if(memcmp(&m_pbyBuff[0], bySig1, sizeof(bySig1)) == 0)
			{
				iRetStatus =  CheckSignature(sizeof(bySig1));
			}
			else if(m_pbyBuff[0] == 0x29 && m_pbyBuff[2] == 0x29 && m_pbyBuff[3] == 0xC9 && m_pbyBuff[4] == 0xB1)
			{
				iRetStatus = CheckSignature(0);
			}
			if(iRetStatus)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Bluwin.A"));
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSignature
	In Parameters	: DWORD dwOffset
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Bluwin Family
--------------------------------------------------------------------------------------*/
int CPolyBluwin::CheckSignature(DWORD dwOffset)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD dwLength = 0, dwInstCount2 = 0;
	t_disasm da = {0x00};
	m_dwInstCount = 0;
	BYTE bKey = 0, byIncFlag = 0;
	BLUWIN_DEC_TYPE eDecType;

	while(dwOffset < 0x3E)
	{
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);

		if(dwLength == 2 && m_dwInstCount == 0 && dwInstCount2 == 0 && strstr(da.result,"SUB"))//case1
		{
			m_dwInstCount++;
			dwOffset += dwLength;
			DWORD dwOff = dwOffset; 
			while(dwOff < dwOffset + 0x10 && dwOff < m_dwNoOfBytes)
			{
				dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOff], 0x20, 0x400000, &da, DISASM_CODE);
				if(dwLength == 2 &&  m_dwInstCount == 1 && strstr(da.result,"SUB"))
				{
					m_dwInstCount++;
				}
				else if(dwLength == 2 &&  m_dwInstCount == 2 && strstr(da.result,"MOV"))
				{
					bKey = (BYTE)da.immconst;
					m_dwInstCount ++ ;
					dwOffset = dwOff;
					break;
				}
				dwOff += dwLength;
			}
			if(m_dwInstCount == 1 || m_dwInstCount == 2)
			{
				dwLength = 0;
				m_dwInstCount = 0;
			}
		}
		else if(dwLength == 5  && strstr(da.result,"CALL"))
		{
			m_bDecOffset = (BYTE)dwOffset + 5 ;
		}
		else if(dwLength == 6  && strstr(da.result,"ADD"))
		{
			m_bDecOffset += (BYTE )da.immconst;
		}
		else if(dwLength == 6  && strstr(da.result,"SUB"))
		{
			m_bDecOffset -= (BYTE)da.immconst;
		}

		if(dwInstCount2 == 0 && (dwLength == 6 || dwLength == 5)  && (strstr(da.result, "OR")||strstr(da.result, "MOV")) && da.immconst == 0xA0F)//case2
		{
			dwInstCount2++;
			dwOffset += dwLength;
			DWORD dwOff = dwOffset; 
			BYTE b1 , b2;
			while(dwOffset < dwOff + 0x1A && dwOffset < m_dwNoOfBytes)
			{
				b1 = m_pbyBuff[dwOffset];
				b2 = m_pbyBuff[dwOffset + 1];
				if((b1 == 0x86 || b1 == 0x88 || b1 == 0x8A) && b2 == 0x05  )
				{
					dwInstCount2++;
					dwOffset += 2;
					continue;
				}
				dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
				if(((dwLength == 5 && strstr(da.result,"MOV")) || (dwLength == 6 && strstr(da.result,"OR")) ||(dwLength == 6 && strstr(da.result,"ADD")) )&& da.immconst != 0)
				{
					bKey = (BYTE)da.immconst;
				}
				else if((dwLength == 2 || dwLength == 6) && dwInstCount2 == 1 && (strstr(da.result,"MOV") || (strstr(da.result,"XCHG"))))
				{
					dwInstCount2++;
				}
				else if(dwLength == 3 && dwInstCount2 == 2 && strstr(da.result,"XOR"))
				{
					eDecType = BLUWIN_DEC_XOR;
					dwInstCount2++;		 
				}
				else if((dwLength == 3 || dwLength == 5) && dwInstCount2 == 2&& strstr(da.result,"ADD"))
				{
					eDecType = BLUWIN_DEC_ADD;
					dwInstCount2++;
				}
				else if(dwLength == 3 && dwInstCount2 == 2 && strstr(da.result,"SUB"))
				{
					eDecType = BLUWIN_DEC_SUB;
					dwInstCount2++;
				}
				else if((dwLength == 2 || dwLength == 6) && dwInstCount2 == 3&& (strstr(da.result,"MOV")||(strstr(da.result,"XCHG"))))
				{
					dwInstCount2++;
				}
				else if((dwLength == 1 || dwLength == 3) && dwInstCount2 == 4 && (strstr(da.result,"INC")||strstr(da.result,"ADD")))
				{
					dwInstCount2++;
				}
				else if((dwLength == 1 || dwLength == 3) && dwInstCount2 == 5 && (strstr(da.result,"INC")||strstr(da.result,"ADD")))
				{
					if(da.immconst == 0)
					{
						byIncFlag = 1;
					}
					else
						byIncFlag = (BYTE)da.immconst;
				}
				else if((dwLength ==3 || dwLength == 1) && dwInstCount2 == 5 && (strstr(da.result,"SUB")||strstr(da.result,"DEC")))
				{
					dwInstCount2++;
				}
				else if((dwLength == 2 || dwLength == 3) && dwInstCount2 == 6 && (strstr(da.result,"OR")|| strstr(da.result,"CMP")))
				{
					dwInstCount2++;
					break;
				}
				dwOffset += dwLength;
			}
		}
		
		dwOffset += dwLength;
	}

	if((m_dwInstCount == 3 || m_dwInstCount == 0) && dwInstCount2 == 7 && bKey != 0)
	{
		const BYTE bySignature[] = {0x89, 0x85, 0x29, 0x08, 0x00, 0x00, 0x8B, 0x34, 0x24, 0x66, 0x29, 0xF6, 0xB9, 0x20, 0x00, 0x00,  
			0x00, 0x66, 0x81, 0x3E, 0x4D, 0x5A, 0x74, 0x0D, 0x81, 0xEE, 0x00, 0x10, 0x00, 0x00, 0xE0, 0xF1, 0xE9, 0x70, 0x01};

		for(DWORD dwIndex = m_bDecOffset; dwIndex < m_dwNoOfBytes; dwIndex++)
		{
			switch(eDecType)
			{
			case BLUWIN_DEC_ADD:
				m_pbyBuff[dwIndex] += bKey;
				bKey += byIncFlag;
				break;

			case BLUWIN_DEC_SUB:
				m_pbyBuff[dwIndex] -= bKey;
				bKey += byIncFlag;
				break;

			case BLUWIN_DEC_XOR:
				m_pbyBuff[dwIndex] ^= bKey;
				bKey += byIncFlag;
				break;
			}
		}
		if(memcmp(&m_pbyBuff[m_bDecOffset + 0x1C ],bySignature, sizeof(bySignature)) == 0)
		{
			iRetStatus = VIRUS_FILE_REPAIR;
		}
		else
			return iRetStatus;
	}
	else if((m_dwInstCount == 3 && dwInstCount2 != 7) || (m_dwInstCount == 0 && dwInstCount2 == 7)||(m_dwInstCount == 0 && dwInstCount2 != 7))
	{
		iRetStatus = VIRUS_FILE_DELETE;
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Bluwin Family
--------------------------------------------------------------------------------------*/
int CPolyBluwin::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;

	DWORD dwOriginalAEP = *(DWORD *)&m_pbyBuff[m_bDecOffset + 0x18];
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOriginalAEP, NULL))
	{
		if(m_pMaxPEFile->WriteAEP(dwOriginalAEP))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped, true))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
	}
	return iRetStatus;
}