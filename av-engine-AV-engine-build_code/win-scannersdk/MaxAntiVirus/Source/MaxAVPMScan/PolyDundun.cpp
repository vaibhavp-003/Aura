/*======================================================================================
FILE				: PolyDundun.cpp
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
NOTES				: This is detection module for malware Dundun Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyDundun.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyDundun
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDundun::CPolyDundun(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_pbyBuff = new BYTE[DUNDUN_BUFF_SIZE];
	m_wDundunSection = 0x00;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDundun
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDundun::~CPolyDundun(void)
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
	Description		: Detection routine for different varients of Dundun Family
--------------------------------------------------------------------------------------*/
int CPolyDundun::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	BYTE bSecDengDun[] = {0x44, 0x45, 0x4E, 0x47, 0x20, 0x44, 0x55, 0x4E};
	for(WORD wSecCnt =0; wSecCnt <= m_wNoOfSections -1; wSecCnt++)// Modified condition for dundun.1396
	{
		if(memcmp(bSecDengDun, m_pSectionHeader[wSecCnt].Name,sizeof(bSecDengDun)) == 0x00)
		{
			m_wDundunSection = wSecCnt;
		}
	}
	if(m_wNoOfSections > 0x01 && m_wDundunSection!=0x00 && m_pSectionHeader[m_wDundunSection].SizeOfRawData >= DUNDUN_BUFF_SIZE)
	{
		if(memcmp(bSecDengDun, m_pSectionHeader[m_wDundunSection].Name, sizeof(bSecDengDun)) == 0x00)  
		{
			if(GetDundunAEP())
			{
				iRetStatus = VIRUS_FILE_REPAIR;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Dundun.A"));	
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDundunAEP
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function generates original AEP
--------------------------------------------------------------------------------------*/
int CPolyDundun::GetDundunAEP(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(!GetBuffer(m_pSectionHeader[m_wDundunSection].PointerToRawData, DUNDUN_BUFF_SIZE, DUNDUN_BUFF_SIZE))
		return iRetStatus;

	DWORD dwStartofDecryption = 0, dwKeyLocRVA = 0; 
	bool bMovEsi = false, bFound = false, bMovKeys = true;

	for(DWORD dwOffset = 0; dwOffset < 0x50; dwOffset++)
	{
		if(!bMovEsi)
		{
			if(m_pbyBuff[dwOffset] < 0x0F)
				continue;

			if((m_pbyBuff[dwOffset] % 0xB0) <= 0x0F)
			{
				dwStartofDecryption = *((DWORD*)&m_pbyBuff[dwOffset + 1]);
				bMovEsi = true;
				bMovKeys = false;
				continue;
			}
		}

		if(!bMovKeys)
		{
			if(m_pbyBuff[dwOffset] == 0xA1)
			{
				dwKeyLocRVA = *((DWORD*)&m_pbyBuff[dwOffset + 1]);
				bFound = true;
				break;
			}

			if(m_pbyBuff[dwOffset] == 0x8B)
			{
				dwKeyLocRVA = *((DWORD*)&m_pbyBuff[dwOffset + 2]);
				bFound = true;
				break;
			}
		}
	}

	if(!bFound)
		return iRetStatus;

	dwStartofDecryption -= m_dwImageBase;
	dwKeyLocRVA -= m_dwImageBase;

	if(dwKeyLocRVA >(m_dwAEPUnmapped + 0x2000) || 
		dwKeyLocRVA < m_dwAEPUnmapped)
		return iRetStatus;

	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwStartofDecryption, NULL))
		return iRetStatus;

	DWORD dwKeyLoc = 0;
	m_pMaxPEFile->Rva2FileOffset(dwKeyLocRVA, &dwKeyLoc);
	if(dwKeyLoc == 0x00)
		return iRetStatus;

	
	BYTE	byKeys[0x04] = {0};

	if(!m_pMaxPEFile->ReadBuffer(&byKeys, dwKeyLoc, sizeof(DWORD), sizeof(DWORD)))
	{
		return iRetStatus;
	}
	
	DWORD dwOffset = 0;
	dwOffset = (dwStartofDecryption - m_dwAEPUnmapped);
	for(DWORD dwBytesRead = 0; dwBytesRead < 0x04; dwBytesRead++)
	{
		for(DWORD i = 0; i < DUNDUN_DECRY_LEN - dwOffset; i++)
		{
			m_pbyBuff[dwOffset + i] ^= byKeys[dwBytesRead];
		}
	}
	
	
	m_dwOriAEP = *((DWORD *)&m_pbyBuff[dwOffset + 0x2A8 - 0x47]) - m_dwImageBase;
	
	/*For Dundun.1396 added by Satish */
	if(m_pbyBuff[dwOffset] == 0xE8 && *(DWORD *)&m_pbyBuff[dwOffset + 1] == 0x1318 && m_pbyBuff[dwOffset + 5] == 0x1E && (m_wAEPSec == (m_wNoOfSections - 1)))
	{
		m_dwOriAEP = (*(DWORD *)&m_pbyBuff[dwOffset + 0x2AD]) - m_dwImageBase;
	}

	if(m_dwOriAEP == 0 || OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriAEP, NULL))
	{
		iRetStatus = VIRUS_FILE_REPAIR;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Dundun Family
--------------------------------------------------------------------------------------*/
int CPolyDundun::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;

	m_pMaxPEFile->WriteAEP(m_dwOriAEP);
	if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wDundunSection].PointerToRawData))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	
	return iRetStatus;
}
