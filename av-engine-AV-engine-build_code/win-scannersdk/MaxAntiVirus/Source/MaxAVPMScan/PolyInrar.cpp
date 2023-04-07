/*======================================================================================
FILE				: PolyInrar.cpp
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
NOTES				: This is detection module for malware Inrar Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyInrar.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyInrar
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyInrar::CPolyInrar(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_pCRCBuff = NULL;
	m_dwMoveFilePointer = 0x0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyInrar
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyInrar::~CPolyInrar(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	if(m_pCRCBuff)
	{
		delete []m_pCRCBuff;
		m_pCRCBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Inrar Family
--------------------------------------------------------------------------------------*/
int CPolyInrar::DetectVirus(void)
{
	//RAR DataBlock includes either Marker/Archive/File Header block
	BYTE byRARDataBlock_buff[0xB] = {0};

	if(m_pMaxPEFile->m_dwFileSize > 0x30D40)
	{
		if(m_pMaxPEFile->ReadBuffer(byRARDataBlock_buff, 0x00, 0x7, 0x7))
		{
			//Primary Check for RAR files
			if(*(DWORD*)&byRARDataBlock_buff[0] == 0x21726152 && byRARDataBlock_buff[4] == 0x1A )
			{
				const BYTE byInrarSig[] = {
					0x75, 0x53, 0x74, 0x44, 0x69, 0x45, 0x00, 0x57, 0x69, 0x6E, 0x33, 0x32, 0x2E, 0x49, 0x6E,
					0x52, 0x61, 0x72, 0x43, 0x6F, 0x6D, 0x70, 0x61, 0x6E, 0x69, 0x6F, 0x6E, 0x20, 0x62, 0x79, 
					0x20, 0x46, 0x52, 0x69, 0x5A, 0x45, 0x52, 0x60, 0x39, 0x39, 0x0D, 0x0A, 0x6D, 0x61, 0x69,
					0x6C, 0x74, 0x6F, 0x3A, 0x76, 0x36, 0x36, 0x36, 0x78, 0x40, 0x6D, 0x61, 0x69, 0x6C, 0x2E,
					0x72, 0x75, 0x00, 0x2A, 0x2E, 0x72, 0x61, 0x72};

				BYTE byVirusSigbuff[sizeof(byInrarSig)] = {0};
				if(m_pMaxPEFile->ReadBuffer(byVirusSigbuff, m_pMaxPEFile->m_dwFileSize - 0x1F9A, sizeof(byVirusSigbuff), sizeof(byVirusSigbuff)))
				{
					//Just checking 10 bytes first and then the rest
					if((memcmp(byVirusSigbuff, byInrarSig, 0x0A) == 0x00) && 
						(memcmp(&byVirusSigbuff[0xA],&byInrarSig[0xA], sizeof(byInrarSig) - 0x0A) == 0x00))
					{
						m_dwMoveFilePointer += *(WORD*)&byRARDataBlock_buff[5];
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("W32.Inrar.A"));
						return VIRUS_FILE_REPAIR;
					}
				}				
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of inrar Family
--------------------------------------------------------------------------------------*/
int CPolyInrar::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	BYTE byRARDataBlock_buff[0xB] = {0};
	while(m_dwMoveFilePointer <= (m_pMaxPEFile->m_dwFileSize - 0x0B))
	{
		if(!m_pMaxPEFile->ReadBuffer(byRARDataBlock_buff, m_dwMoveFilePointer, 0xB, 0xB))
		{
			return iRetStatus;
		}
		if(byRARDataBlock_buff[0x02] == 0x74)
		{
			DWORD dwHighSizeflag=0x0;
			if((*(WORD*)&byRARDataBlock_buff[3] & 0x0100) == 0x0100)
			{
				dwHighSizeflag += 0x08;
			}
			if(m_dwMoveFilePointer + *(WORD*)&byRARDataBlock_buff[5] > m_pMaxPEFile->m_dwFileSize)
			{
				return iRetStatus;
			}
			DWORD dwRARHdrSize = *(WORD *)&byRARDataBlock_buff[5];
			if(dwRARHdrSize  > MAX_PATH + 0x20 || dwRARHdrSize  < 0x1E)
			{
				return iRetStatus;
			}
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			m_pbyBuff = new BYTE[dwRARHdrSize];
			if(!GetBuffer(m_dwMoveFilePointer, dwRARHdrSize, dwRARHdrSize))
			{				
				return iRetStatus;
			}
			DWORD dwTempCRCHeaderSize = 0x1E + dwHighSizeflag + *(WORD *)&m_pbyBuff[0x1A];
			if(dwTempCRCHeaderSize - 2 < dwRARHdrSize)
			{
				if((*(DWORD*)&m_pbyBuff[dwTempCRCHeaderSize - 0x02] & 0xDFDFDFFF) == 0x44534D2E)
				{
					*(DWORD*)&m_pbyBuff[dwTempCRCHeaderSize - 0x02] = 0x6578652E;
					if(RAR_CRCFunction())
					{
						*(WORD *)&m_pbyBuff[0] = ImplementCRCFunction(&m_pbyBuff[2], dwRARHdrSize - 2);
						if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwMoveFilePointer, *(WORD*)&byRARDataBlock_buff[5]))
						{
							if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize - *(WORD*)&byRARDataBlock_buff[5] - 0x3000))
							{	
								iRetStatus = REPAIR_SUCCESS;
							}	
						}
					}
					return iRetStatus;
				}
			}			
		}
		//0x7B signifies end of reading + also just checking that the flag contains 0x70 else we are
		//reading from the wrong offset
		else if(byRARDataBlock_buff[0x02] == 0x7B || ( (byRARDataBlock_buff[0x02] & 0x70) != 0x70))
		{
			return iRetStatus;
		}
		//To be handled for 64bit.In this case we also need to read the High 4 bytes from another offset i.e.0x20
		m_dwMoveFilePointer += (*(WORD *)&byRARDataBlock_buff[5]) + (*(DWORD *)&byRARDataBlock_buff[7]);
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: ImplementCRCFunction
	In Parameters	: BYTE *ImplementCRCFunction, DWORD dwLoopSize
	Out Parameters	: Calculated CRC Value
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Generates new CRC value for repaired file
--------------------------------------------------------------------------------------*/
WORD CPolyInrar::ImplementCRCFunction(BYTE *ImplementCRCFunction, DWORD dwLoopSize)
{
	DWORD dwCRCCodeData = 0, dwTemp=0, dwCRCValue = 0xFFFFFFFF, dwLoop1 = 0x26;
	BYTE bytemp3 = 0, bytemp4 = 0;
	for(DWORD dwLoop = 0; dwLoop < dwLoopSize; dwLoop++)
	{
		dwCRCCodeData = *(BYTE*)&ImplementCRCFunction[dwLoop];
		dwTemp = dwCRCCodeData;

		//Performing 1 byte XOR and transferring result back to dwTemp
		bytemp3 = BYTE(dwCRCCodeData);
		bytemp4 = BYTE(dwCRCValue);
		bytemp3 ^= bytemp4;
		dwTemp &= 0xFFFFFF00;
		dwTemp += bytemp3;

		dwCRCValue >>= 0x08;
		dwCRCCodeData >>= 0x08;
		dwCRCCodeData <<= 0x18;
		dwCRCValue |= dwCRCCodeData;
		dwTemp <<= 0x02;
		dwCRCValue ^= *(DWORD *)&m_pCRCBuff[dwTemp];
	}
	dwCRCValue = (~dwCRCValue);
	return((WORD)dwCRCValue); 
}

/*-------------------------------------------------------------------------------------
	Function		: RAR_CRCFunction
	In Parameters	: BYTE *ImplementCRCFunction, DWORD dwLoopSize
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Generates new CRC value for repaired file
--------------------------------------------------------------------------------------*/
bool CPolyInrar::RAR_CRCFunction(void)
{
	m_pCRCBuff = new BYTE[0x400];
	if(m_pCRCBuff == NULL)
	{
		return false;
	}
	memset(m_pCRCBuff, 0, 0x400);
	DWORD dwCRCLoopCounter = 0, dwCRCCodeData = 0xFF;
	for(DWORD dwCounter = 0; dwCounter < 0xFF; dwCounter++)
	{
		dwCRCCodeData = 0xFF - dwCounter;
		dwCRCLoopCounter = 0x8;
		BYTE byCarryFlag = 0;
		do
		{
			if((dwCRCCodeData & 0x01) == 0x01)
			{
				byCarryFlag = 0x1;
			}
			
			dwCRCCodeData >>= 1;
			if(byCarryFlag)
			{
				dwCRCCodeData ^= 0xEDB88320;
				byCarryFlag = 0x0;
			}

		}while(--dwCRCLoopCounter != 0);
		*(DWORD *)&m_pCRCBuff[0x3FC - (dwCounter * 0x4)] = dwCRCCodeData;
	}
	return true;
}

