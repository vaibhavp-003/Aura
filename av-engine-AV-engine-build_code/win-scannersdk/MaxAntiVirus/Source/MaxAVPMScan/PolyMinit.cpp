/*======================================================================================
FILE				: PolyMinit.cpp
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
NOTES				: This is detection module for malware Minit Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyMinit.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyMinit
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMinit::CPolyMinit(CMaxPEFile *pMaxPEFile, LPCTSTR pFilename):
CPolyBase(pMaxPEFile),
m_pFileName(pFilename)
{
	m_pbyBuff = new BYTE[SIZE_OF_MINIT_SIGNATURE];
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMinit
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMinit::~CPolyMinit(void)
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
	Description		: Detection routine for different varients of Minit Family
					  In this virus at AEP Call and RET instruction. We follow call
					  and there we check signature. If signature matched virus is 
					  detected.	
--------------------------------------------------------------------------------------*/
int CPolyMinit::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD	dwResID			= 0x65;	//Resource ID
	DWORD	dwResType		= 0x0A;	//Resource ID
	DWORD	dwLangID		= 0x0409;
	
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x03 && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) && 
		m_dwAEPUnmapped == 0x1000)
	{
		const BYTE bySignature[] = {0x20, 0x00, 0x00, 0x8A, 0x56, 0xFF, 0x30, 0x16,
									0xAC, 0x02, 0xD0, 0x80,	0xC2, 0x37, 0xE2, 0xF6,
									0x58, 0x68, 0x0A, 0x10, 0xCA, 0x02, 0xFF, 0xE0};
		
		if(GetBuffer(m_dwAEPMapped, 6, 6))
		{
			if(m_pbyBuff[0] == 0xE8 && m_pbyBuff[5] == 0xC3)
			{
				DWORD dwSignatureOffset = *((DWORD*)&m_pbyBuff[1]) + m_dwAEPMapped + 0xC;
				
				if(GetBuffer(dwSignatureOffset, SIZE_OF_MINIT_SIGNATURE, SIZE_OF_MINIT_SIGNATURE))
				{
					if(!memcmp(bySignature,m_pbyBuff,SIZE_OF_MINIT_SIGNATURE))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Minit"));
						if(!FindRes(LPCTSTR(&dwResType), LPCTSTR(&dwResID), LPCTSTR(&dwLangID), m_dwUnMapAddress, m_dwSize))
						{
							return VIRUS_FILE_DELETE;
						}
						return VIRUS_FILE_REPAIR;
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
	Description		: Repair routine for different varients of Dundun Family
					  This Virus kept original file as a resource. Resource 
					 name is RCDATA. It extract original file from resource and 
					 decrypt the original file.
-------------------------------------------------------------------------------------*/
int CPolyMinit::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
		
	//Image Resource Data Entery offset 
	DWORD dwMapAddress = 0x00;

	//Now read the RVA of the RCDATA resource and mapped to the offset
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwUnMapAddress, &dwMapAddress))
	{
		return FALSE;
	}
	
	//Now read the RCDATA resource that is original file in encrypted form.
	if(m_pbyBuff)
	{
		delete [] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int MAX_BUFF_READ_SIZE = 0x10000;
	m_pbyBuff = new BYTE[MAX_BUFF_READ_SIZE];
	if(m_pbyBuff == NULL)
	{
		return FALSE;
	}
	
	DWORD dwWriteOffset = 0x00;
	DWORD dwBytesWrite = 0x00;

	WORD	wEAX	= 0x00;
	DWORD	dwEDX	= 0x00;
	BYTE	byAL	= 0x00;
	BYTE	byDL	= 0x00;
	BYTE	byBL	= 0x00;
	BYTE	byEBP_1 = 0x75;

	for(DWORD dwReadOffset = dwMapAddress; dwReadOffset < (dwMapAddress + m_dwSize); dwReadOffset += MAX_BUFF_READ_SIZE)
	{
		memset(m_pbyBuff, 0x00, MAX_BUFF_READ_SIZE);
		if(!GetBuffer(dwReadOffset, MAX_BUFF_READ_SIZE))
		{
			return iRetStatus;
		}
		
		//Decryption as per virus logic.		
		for(DWORD dwCounter = 0x00; dwCounter < m_dwNoOfBytes; dwCounter++)
		{
			byAL = static_cast<BYTE>(dwEDX);
			byBL = 0x07;
			wEAX = static_cast<WORD>(byBL * byAL);
			byAL = static_cast<BYTE>(wEAX);
			byAL += 0x04;		
			wEAX = static_cast<WORD>(byDL * byAL);
			byBL = static_cast<BYTE>(wEAX);
			byAL = m_pbyBuff[dwCounter];
			byBL = byBL + byEBP_1;
			byBL = byBL ^ byAL;
			byEBP_1 = byEBP_1 + byBL;
			dwEDX++;
			byDL = static_cast<BYTE>(dwEDX);
			m_pbyBuff[dwCounter] = byBL;		
		}
		if(dwWriteOffset == 0x00 && (m_pbyBuff[0] != 0x4D || m_pbyBuff[1] != 0x5A))
		{
			m_pMaxPEFile->CloseFile_NoMemberReset();
			return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : iRetStatus;
		}

		m_pMaxPEFile->WriteBuffer(m_pbyBuff, dwWriteOffset, m_dwNoOfBytes);
		dwWriteOffset += m_dwNoOfBytes;		
	}	
	
	if(m_pMaxPEFile->ForceTruncate(m_dwSize))
	{
		iRetStatus = REPAIR_SUCCESS;
	}		
	return iRetStatus;
}
