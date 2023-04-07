/*======================================================================================
FILE				: PolySfcer.cpp
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
NOTES				: This is detection module for malware Sfcer Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolySfcer.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolySfcer
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolySfcer::CPolySfcer(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{	
	memset(&m_objSfcerParam, 0 , sizeof(m_objSfcerParam));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolySfcer
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolySfcer::~CPolySfcer(void)
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
	Description		: Detection routine for different varients of sfcer Family
					  This function get sfcer decryption parameter. If successfully collect
					  then check for overlay.
--------------------------------------------------------------------------------------*/
int CPolySfcer::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_dwAEPUnmapped == 0x1008 && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics&IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
	{
		m_pbyBuff = new BYTE[SFCER_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(m_pbyBuff)
		{
			memset(m_pbyBuff, 0x00, SFCER_BUFF_SIZE + MAX_INSTRUCTION_LEN);
			if(GetBuffer(m_dwAEPMapped, SFCER_BUFF_SIZE, SFCER_BUFF_SIZE))
			{
				if(GetSfcerParam())
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sfcer"));
					if(m_pMaxPEFile->m_dwFileSize == (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
					{
						iRetStatus = VIRUS_FILE_DELETE;
					}
					else if(m_pMaxPEFile->m_dwFileSize > (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
					{
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
	Description		: Repair routine for different varients of sfcer Family
					  1) ROR or ROL instruction then sfcer.A
					  2) XOR	instruction then sfcer.B according to KK
					     in both case decryption is diffrent.
--------------------------------------------------------------------------------------*/
int CPolySfcer::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	
	DWORD dwChunk = 0x1000;
	DWORD dwSizeOfData = m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData);// Size of Overlay

	if(dwSizeOfData < dwChunk)
	{
		dwChunk = dwSizeOfData;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[dwChunk];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}

	DWORD	dwReadStartAddr = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
	DWORD	dwWriteStartAddr = 0x02;
	BYTE	byDecKey = 0x00;

	for(DWORD dwOffset = 0; dwOffset < dwSizeOfData; dwOffset += dwChunk)
	{		
		memset(m_pbyBuff, 0, dwChunk);
		if(!GetBuffer(dwReadStartAddr + dwOffset, dwChunk))
		{
			return iRetStatus;
		}

		byDecKey = m_objSfcerParam.m_byDecKey;
		switch(m_objSfcerParam.eDecryptionType)
		{
		case DEC_SFCER_ROR:
			for(DWORD dwIndex = dwChunk - 1; dwIndex < dwChunk; dwIndex--)
			{
				byDecKey = byDecKey >> m_objSfcerParam.m_byRORCounter | byDecKey << (BYTE)(0x08 - m_objSfcerParam.m_byRORCounter);
				m_pbyBuff[dwIndex] ^= byDecKey;
				byDecKey--;
			}
			break;
		case DEC_SFCER_ROL:
			for(DWORD dwIndex = dwChunk - 1; dwIndex < dwChunk; dwIndex--)
			{
				byDecKey = byDecKey << m_objSfcerParam.m_byRORCounter | byDecKey >> (BYTE)(0x08 - m_objSfcerParam.m_byRORCounter);
				m_pbyBuff[dwIndex] ^= byDecKey;
				byDecKey--;
			}
			break;
		case DEC_SFCER_XOR:
			for(DWORD dwIndex = dwChunk - 1 ,dwCounter = 0x1000; dwIndex < dwChunk; dwIndex--,dwCounter--)
			{
				m_pbyBuff[dwIndex] ^= m_objSfcerParam.m_byRORCounter;
				m_pbyBuff[dwIndex] ^= HIBYTE(LOWORD(dwCounter));
				byDecKey--;
			}
			break;
			// For future use. Code will be used if we found samples with ADD and SUB decryption
		/*case DEC_SFCER_ADD:
			for(DWORD dwIndex = dwChunk - 1; dwIndex < dwChunk; dwIndex--)
			{
				byDecKey = byDecKey + m_objSfcerParam.m_byRORCounter;;
				m_pbyBuff[dwIndex] ^= byDecKey;
				byDecKey--;
			}
			break;
		case DEC_SFCER_SUB:
			for(DWORD dwIndex = dwChunk - 1; dwIndex < dwChunk; dwIndex--)
			{
				byDecKey = byDecKey - m_objSfcerParam.m_byRORCounter;;
				m_pbyBuff[dwIndex] ^= byDecKey;
				byDecKey--;
			}
			break;*/
		}

		if(!m_pMaxPEFile->WriteBuffer(m_pbyBuff, dwWriteStartAddr + dwOffset, m_dwNoOfBytes, m_dwNoOfBytes))
		{
			return iRetStatus;
		}
	}
	if(m_pMaxPEFile->TruncateFile(dwSizeOfData + 2))
	{
		iRetStatus = REPAIR_SUCCESS;
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSfcerParam
	In Parameters	: 
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Collects the required information
--------------------------------------------------------------------------------------*/
int CPolySfcer::GetSfcerParam()
{
	DWORD	dwOffSet = 0x00 , dwInstructionCount = 0x00 , dwLength = 0x00 , dwTemp = 0x00;
	BYTE	B1 = 0, B2 = 0, B3 = 0;
	DWORD	dwDetectionPhase = 0x00;
	
	int iRetStatus = 0x00;

	t_disasm	da;

	m_objMaxDisassem.InitializeData();
	
	while(dwOffSet < m_dwNoOfBytes)
	{		
		if(dwInstructionCount > 0x20)
		{
			return iRetStatus;
		}
		memset(&da, 0x00, sizeof( struct t_disasm)*1 );

		B1 = m_pbyBuff[dwOffSet] ;
		B2 = m_pbyBuff[dwOffSet+1] ;
		B3 = m_pbyBuff[dwOffSet + 0x05] ;
		
		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if( B1==0xC1 && (B2>=0xF0 && B2<=0xF7) )
		{
			dwOffSet+= 0x03;
			continue;
		}
		if( B1==0xD1 && (B2>=0xF0 && B2<=0xF7) )
		{
			dwOffSet+= 0x02;
			continue;
		}
		if( B1==0xE2 && (B2>=0xF0 && B2<=0xFF) ) // Added for 'LOOP' instruction
		{
			dwOffSet+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char* )&m_pbyBuff[dwOffSet], 0x20, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffSet))
		{
			return iRetStatus;
		}

		dwOffSet += dwLength;
		dwInstructionCount++;

		if(dwLength == 0x02 && strstr(da.result, "MOV ") && (0x08 == strlen(da.result) || (0x09 == strlen(da.result))))
		{
			m_objSfcerParam.m_byDecKey = static_cast<BYTE>(da.immconst);
			dwDetectionPhase = 0x01;			
			continue;
		}
		if(dwLength == 0x03 && strstr(da.result, "MOV ") && strstr(da.result,"[E") && strstr(da.result,"+E") && dwDetectionPhase == 0x01)
		{
			dwDetectionPhase = 0x02;
			continue;
		}
		if(dwLength == 0x03 && dwDetectionPhase == 0x02 && strstr(da.result,"ROR "))
		{
			m_objSfcerParam.m_byRORCounter = static_cast<BYTE>(da.immconst % 0x08);
			m_objSfcerParam.eDecryptionType = DEC_SFCER_ROR;
			dwDetectionPhase = 0x03;
			continue;
		}
		if(dwLength == 0x03 && dwDetectionPhase == 0x02 && strstr(da.result,"ROL "))
		{
			m_objSfcerParam.m_byRORCounter = static_cast<BYTE>(da.immconst % 0x08);
			m_objSfcerParam.eDecryptionType = DEC_SFCER_ROL;
			dwDetectionPhase = 0x03;
			continue;
		}
		if(dwLength == 0x03 && dwDetectionPhase == 0x02 && strstr(da.result,"XOR "))
		{
			m_objSfcerParam.m_byRORCounter = static_cast<BYTE>(da.immconst);
			m_objSfcerParam.eDecryptionType = DEC_SFCER_XOR;
			dwDetectionPhase = 0x03;
			continue;
		}
		// For future use. Code will be used if we found samples with ADD and SUB decryption
		/*if(dwLength == 0x03 && dwDetectionPhase == 0x02 && strstr(da.result,"ADD "))
		{
			m_objSfcerParam.m_byRORCounter = static_cast<BYTE>(da.immconst);
			m_objSfcerParam.eDecryptionType = DEC_SFCER_ADD;
			dwDetectionPhase = 0x03;
			continue;
		}
		if(dwLength == 0x03 && dwDetectionPhase == 0x02 && strstr(da.result,"SUB "))
		{
			m_objSfcerParam.m_byRORCounter = static_cast<BYTE>(da.immconst);
			m_objSfcerParam.eDecryptionType = DEC_SFCER_SUB;
			dwDetectionPhase = 0x03;
			continue;
		}*/
		if(dwLength == 0x02 && strstr(da.result,"XOR ") && dwDetectionPhase == 0x03)
		{
			dwDetectionPhase = 0x04;
			continue;
		}
		if(dwLength == 0x01 && strstr(da.result,"DEC E") && dwDetectionPhase > 0x03)
		{
			dwDetectionPhase++;
			if(dwDetectionPhase >= 0x06)
			{
				iRetStatus = 0x01;
				break;
			}
			continue;
		}
	}
	return iRetStatus;
}
