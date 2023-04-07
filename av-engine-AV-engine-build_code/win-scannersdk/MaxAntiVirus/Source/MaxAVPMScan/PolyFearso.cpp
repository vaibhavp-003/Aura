/*======================================================================================
FILE				: PolyFearso.cpp
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
NOTES				: This is detection module for malware Fearso Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyFearso.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyFearso
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyFearso::CPolyFearso(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	dwOriginalDataOffset=0x137F7;

}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyFearso
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyFearso::~CPolyFearso()
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff=NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Fearso Family
--------------------------------------------------------------------------------------*/
int CPolyFearso::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	const int FEARSO_BUFF_SIZE = 0x31;
	BYTE byBuff[FEARSO_BUFF_SIZE];

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL)==IMAGE_FILE_DLL &&
		m_dwAEPUnmapped == 0xda38 && m_wAEPSec == 0 && m_pSectionHeader[0].SizeOfRawData==0xcc00
		)
	{	
				
		BYTE FearsoB_Sig[] = {0x31, 0xC9, 0x53, 0x8A, 0x4A, 0x01, 0x56, 0x57, 0x89, 0xC3, 0x8D, 0x74, 0x11, 0x0A, 0x8B, 0x7C, 0x11, 0x06, 0x8B, 0x16, 0x8B, 0x46, 0x04, 0x01, 0xD8, 0x8B, 0x12, 0xB9, 0x01, 0x00, 0x00, 0x00, 0xE8, 0x0F, 0x00, 0x00, 0x00, 0x83, 0xC6, 0x08, 0x4F, 0x7F, 0xE7, 0x89, 0xD8, 0x5F, 0x5E, 0x5B, 0xC3};
		//BYTE bBuff[0x31];
		/*if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff=NULL;
			}
		*/
		//memset(m_pbyBuff,0,FEARSO_BUFF_SIZE);
		m_pbyBuff=(BYTE *)malloc(FEARSO_BUFF_SIZE);
		if(GetBuffer(m_pSectionHeader[0].PointerToRawData+0x202c,FEARSO_BUFF_SIZE,FEARSO_BUFF_SIZE))
		//if(m_pMaxPEFile->ReadBuffer(byBuff,m_pSectionHeader[0].PointerToRawData+0x202c,FEARSO_BUFF_SIZE))
		{
			if(memcmp(&m_pbyBuff[0x00], FearsoB_Sig, sizeof(FearsoB_Sig)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Email-Worm.Win32.Fearso.b"));
				return VIRUS_FILE_DELETE;
			}
		}
	}

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL)!=IMAGE_FILE_DLL &&
		m_dwAEPUnmapped == 0x3b10 && m_wAEPSec == 0 && m_pSectionHeader[0].SizeOfRawData==0x2e00
		)
	{			
		BYTE FearsoB_Sig[] = {0x31, 0xC9, 0x53, 0x8A, 0x4A, 0x01, 0x56, 0x57, 0x89, 0xC3, 0x8D, 0x74, 0x11, 0x0A, 0x8B, 0x7C, 0x11, 0x06, 0x8B, 0x16, 0x8B, 0x46, 0x04, 0x01, 0xD8, 0x8B, 0x12, 0xB9, 0x01, 0x00, 0x00, 0x00, 0xE8, 0x0F, 0x00, 0x00, 0x00, 0x83, 0xC6, 0x08, 0x4F, 0x7F, 0xE7, 0x89, 0xD8, 0x5F, 0x5E, 0x5B, 0xC3};

		m_pbyBuff=(BYTE *)malloc(FEARSO_BUFF_SIZE);
		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x1048,FEARSO_BUFF_SIZE,FEARSO_BUFF_SIZE))
		//if(m_pMaxPEFile->ReadBuffer(byBuff,m_pSectionHeader[0].PointerToRawData+0x1048,FEARSO_BUFF_SIZE))
		{
			if(memcmp(&m_pbyBuff[0x00], FearsoB_Sig, sizeof(FearsoB_Sig)) == 0)
			{
				if(m_pMaxPEFile->m_dwFileSize<=79900)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Email-Worm.Win32.Fearso.b"));
					return VIRUS_FILE_DELETE;
				}
				else
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Email-Worm.Win32.Fearso.b"));
					return VIRUS_FILE_REPAIR;

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
	Description		: Repair routine for different varients of Fearso Family
--------------------------------------------------------------------------------------*/
int CPolyFearso::CleanVirus()
{
	DWORD dwOriginalFileSize=m_pMaxPEFile->m_dwFileSize-dwOriginalDataOffset;
	if(m_pMaxPEFile->CopyData(dwOriginalDataOffset,0,dwOriginalFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(dwOriginalFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}