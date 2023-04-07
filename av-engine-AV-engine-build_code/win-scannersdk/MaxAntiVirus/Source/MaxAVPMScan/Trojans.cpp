/*======================================================================================
FILE				: Trojans.cpp
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
NOTES				: This is detection module for different malware (Trojan) Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "Trojans.h"
#include <shlwapi.h>
#include "SemiPolyDBScn.h"
#include "MaxBMAlgo.h"

LPFNUnPackUPXFile CTrojans::m_lpfnUnPackUPXFile = NULL;
HMODULE	CTrojans::m_hUPXUnpacker = NULL;	

/*-------------------------------------------------------------------------------------
	Function		: CTrojans
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CTrojans::CTrojans(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CTrojans
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CTrojans::~CTrojans(void)
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
	Description		: 1 : This function is main scanning handler for different types of Malwares.
--------------------------------------------------------------------------------------*/
int CTrojans::DetectVirus(void)
{
	typedef int (CTrojans::*LPFNDetectVirus)();	
	LPFNDetectVirus pVirusList[] = 
	{	
		&CTrojans::DetectSohanad,
		&CTrojans::DetectKido,
		&CTrojans::DetectPoison,
		&CTrojans::DetectZAccess,
		&CTrojans::DetectJorrik,
		&CTrojans::DetectCosmu,
		&CTrojans::DetectEGDial,
		&CTrojans::DetectInstallCoreBrj,
		&CTrojans::DetectGenomeDLL,
		&CTrojans::DetectAllaple,
		//&CTrojans::DetectSwizzor, 
		&CTrojans::DetectTrojanMonderA,
		&CTrojans::DetectPackedPolyCrypt,
		&CTrojans::DetectKlone,
		&CTrojans::DetectAgentBCN,
		&CTrojans::DetectBlackA,
		&CTrojans::DetectSmartFortress,
		&CTrojans::DetectDCodecPackSJT,		
		&CTrojans::DetectTrojanAutorunDM,
		&CTrojans::DetectPackedKrapIU,
		&CTrojans::DetectLpler,
		&CTrojans::DetectDialerCJ,
		&CTrojans::DetectMufanomAQDA,
		&CTrojans::DetectMudropASJ,
		&CTrojans::DetectInstallCoreA,
		&CTrojans::DetectFrauDropXYRW,
		//&CTrojans::DetectObfuscatedGen,
		&CTrojans::DetectChifraxD,
		&CTrojans::DetectOnlineGameAndWOWMagania,
		&CTrojans::DetectAgentCWA,
		&CTrojans::DetectSytro,
		&CTrojans::DetectSefnit,
		&CTrojans::DetectShiz,
		&CTrojans::DetectDownloaderTibs,
		//&CTrojans::DetectSinowal, //Commented false (+)ve : VB100
		&CTrojans::DetectTepfer,	
		&CTrojans::DetectWebWatcher,
		&CTrojans::DetectSmallVQ,
		&CTrojans::DetectWLordgen,
		&CTrojans::DetectPswRuftarHtm,
		&CTrojans::DetectSafeDecisionINC,
		&CTrojans::DetectLoadMoney,
		&CTrojans::DetectMonderd,
		&CTrojans::DetectAgentXcfc,
		&CTrojans::DetectQhostsBm,
	//	&CTrojans::DetectSolimba,
		&CTrojans::DetectVittaliaInstaller,
		&CTrojans::DetectCinmusAIZH,
		&CTrojans::DetectOptimumInstaller,
		&CTrojans::DetectSpector,
		&CTrojans::DetectMedfos,
		&CTrojans::DetectDNSChangerHD,
		&CTrojans::DetectPackedCpex,
		&CTrojans::DetectPalevo,
		&CTrojans::DetectPSWKatesC,
		&CTrojans::DetectSinowalEEE,
		&CTrojans::DetectKatushaQ,
		&CTrojans::DetectGLDCT,
		&CTrojans::DetectBackDoorLavanDos,
		&CTrojans::DetectDiamin,
		&CTrojans::DetectShipUp,
		&CTrojans::DetectMorstar,
		&CTrojans::DetectYakes,
		&CTrojans::DetectFiseria,
		&CTrojans::DetectNGRBot,
		&CTrojans::DetectOteZinuDl,
		&CTrojans::DetectFlyStudio,
		&CTrojans::DetectAutoitAZA,
		&CTrojans::DetectBankerRTM//added 05-12-2020
	};
	int iRetStatus = VIRUS_NOT_FOUND;
	for(int i = 0; i < _countof(pVirusList); i++)
	{
		iRetStatus = (this->*(pVirusList[i]))();
		if(iRetStatus)
		{					
			return iRetStatus;
		}
	}	

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSohanad
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Sohanad Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectSohanad(void)
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	DWORD	dwBytes2Read = 0x100;
	bool	bAutoITFound = false;
	BYTE	bAutoITSig[] = {0x41, 0x55, 0x33, 0x21, 0x45, 0x41};

	if ((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}

	if (m_wNoOfSections >= 0x06)
	{
		if (m_pSectionHeader[4].Misc.VirtualSize != 0x15000)
			return iRetStatus;

		BYTE bSecNameA[] = {0x2E, 0x70, 0x65, 0x6E, 0x61, 0x73, 0x6B};
		BYTE bSecNameB[] = {0x2E, 0x76, 0x63, 0x2B, 0x2B, 0x00};
		if (memcmp(m_pSectionHeader[0x4].Name,bSecNameA,sizeof(bSecNameA)) == 0x00 ||
			memcmp(m_pSectionHeader[0x4].Name,bSecNameB,sizeof(bSecNameB)) == 0x00)
		{
			if (m_pbyBuff)
			{
				delete []m_pbyBuff; 
				m_pbyBuff = NULL;
			}
			m_pbyBuff = new BYTE[dwBytes2Read];

			BYTE	bAEPBuff[] = {0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB, 0x04, 0x5D, 0x45, 0x55, 0xC3, 0xE8, 0x01};
			if(!GetBuffer(m_dwAEPMapped, dwBytes2Read, sizeof(bAEPBuff) + 1))
				return iRetStatus;

			if (memcmp(&m_pbyBuff[0x00], bAEPBuff, sizeof(bAEPBuff)) != 0x00 && memcmp(&m_pbyBuff[0x01], bAEPBuff, sizeof(bAEPBuff)) != 0x00)
				return iRetStatus;

			if(!GetBuffer(m_pSectionHeader[0x5].PointerToRawData, dwBytes2Read), sizeof(bAutoITSig))
				return iRetStatus;

			for(DWORD i = 0x00; i < dwBytes2Read - sizeof(bAutoITSig); i++)
			{
				if (memcmp(&m_pbyBuff[i], bAutoITSig, sizeof(bAutoITSig)) != 0x00)
				{
					bAutoITFound = true;
					break;
				}
			}
			if (bAutoITFound)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Worm.Sohanad"));
				return VIRUS_FILE_DELETE; 
			}
		}
	}
	else if (m_wNoOfSections == 0x04)
	{
		if (m_pSectionHeader[0].SizeOfRawData != 0x00)
		{
			if(m_pSectionHeader[0].SizeOfRawData != 0x65400)		
				return iRetStatus;

			DWORD dwOffSet = m_pSectionHeader[3].PointerToRawData + 0x35010;

			if (m_pbyBuff)
			{
				delete []m_pbyBuff; 
				m_pbyBuff = NULL;
			}
			m_pbyBuff = new BYTE[dwBytes2Read];

			if(!GetBuffer(dwOffSet, dwBytes2Read, sizeof(bAutoITSig)))
				return iRetStatus;
			if (OffSetBasedSignature(bAutoITSig, sizeof(bAutoITSig), &dwOffSet))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Worm.Sohanad.IT"));
				return VIRUS_FILE_DELETE; 
			}
			else
				return iRetStatus;
		}

		BYTE bSecName[] = {0x55, 0x50, 0x58, 0x31, 0x00};
		if (memcmp(&m_pSectionHeader[0x3].Name[0x02],bSecName,sizeof(bSecName)) != 0x00)
			return iRetStatus;

		DWORD dwOffSet = m_pSectionHeader[3].PointerToRawData + m_pSectionHeader[3].SizeOfRawData - 0x100;

		if (m_pbyBuff)
		{
			delete []m_pbyBuff; 
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[dwBytes2Read];

		if(!GetBuffer(dwOffSet, dwBytes2Read, sizeof(bAutoITSig)))
			return iRetStatus;
		if (OffSetBasedSignature(bAutoITSig, sizeof(bAutoITSig), &dwOffSet))
		{
			bAutoITFound = true;
		}
		if (false == bAutoITFound && (m_pMaxPEFile->m_dwFileSize > (m_pSectionHeader[3].PointerToRawData + m_pSectionHeader[3].SizeOfRawData)))
		{
			dwOffSet = m_pMaxPEFile->m_dwFileSize - 0x100;
			if(!GetBuffer(dwOffSet,dwBytes2Read, sizeof(bAutoITSig)))
				return iRetStatus;
			if (OffSetBasedSignature(bAutoITSig,sizeof(bAutoITSig),&dwOffSet))
			{
				bAutoITFound = true;
			}
		}
		if (bAutoITFound)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Worm.Sohanad"));
			return VIRUS_FILE_DELETE; 
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectKido
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Kido Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectKido(void)
{
	int	iRetStatus = VIRUS_NOT_FOUND;	
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	
	if(m_wNoOfSections != 0x04)
	{
		return iRetStatus;
	}

	// Check overlay size
	if(m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData) < 0x1000)
	{
		return iRetStatus;
	}
	
	if (m_pbyBuff)
	{
		delete []m_pbyBuff; 
		m_pbyBuff = NULL;
	}
	const DWORD dwKidoBuffSize = 0x1500;
	m_pbyBuff = new BYTE[dwKidoBuffSize];
	
	DWORD dwReadPosition = m_pSectionHeader[1].PointerToRawData + m_pSectionHeader[1].SizeOfRawData, dwBytes2Read = 0;
	if (m_pSectionHeader[1].SizeOfRawData > dwKidoBuffSize)
	{
		dwReadPosition -= dwKidoBuffSize;
		dwBytes2Read = dwKidoBuffSize;
	}
	else
	{
		dwReadPosition = m_pSectionHeader[1].PointerToRawData;
		dwBytes2Read = m_pSectionHeader[1].SizeOfRawData;
	}

	if(!GetBuffer(dwReadPosition, dwKidoBuffSize, 0x20))
	{
		return iRetStatus;
	}

	BYTE	bKidoSig1[] = {0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73};
	BYTE	bKidoSig2A[] = {0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x41, 0x6C, 0x6C, 0x6F, 0x63};
	BYTE	bKidoSig2B[] = {0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74};
	BYTE	bKidoSig3A[] = {0x49, 0x73, 0x56, 0x61, 0x6C, 0x69, 0x64, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6F, 0x72};
	BYTE    bKidoSig3B[] = {0x49, 0x6E, 0x69, 0x74, 0x69, 0x61, 0x6C, 0x69, 0x7A, 0x65, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6F, 0x72};
	BYTE	bKidoSig4[] = {0x30, 0x20, 0x30, 0x24, 0x30, 0x28, 0x30, 0x2C, 0x30, 0x30, 0x30, 0x34, 0x30};
	int		iHitCnt = 0x00;

	for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes - 0x20; dwOffset++)
	{
		if(memcmp(&m_pbyBuff[dwOffset], &bKidoSig1[0x00], sizeof(bKidoSig1)) == 0)
		{
			iHitCnt = 0x01;		
		}

		if(iHitCnt >= 0x01)
		{
			if(memcmp(&m_pbyBuff[dwOffset], &bKidoSig2A[0x00], sizeof(bKidoSig2A)) == 0)
			{
				iHitCnt++;		
			}

			if(memcmp(&m_pbyBuff[dwOffset], &bKidoSig2B[0x00], sizeof(bKidoSig2B)) == 0)
			{
				iHitCnt++;		
			}
		}

		if(iHitCnt > 0x02)
		{
			if(memcmp(&m_pbyBuff[dwOffset], &bKidoSig3A[0x00], sizeof(bKidoSig3A)) == 0)
			{
				iHitCnt++;		
			}
			if(memcmp(&m_pbyBuff[dwOffset], &bKidoSig3B[0x00], sizeof(bKidoSig3B)) == 0)
			{
				iHitCnt++;		
			}
		}
	}

	if(iHitCnt < 0x04)
	{
		return iRetStatus;
	}

	dwReadPosition = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
	if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > dwKidoBuffSize)
	{
		dwBytes2Read = dwKidoBuffSize;
	}
	else
	{
		dwBytes2Read = m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
	}

	memset(m_pbyBuff, 0x00, dwKidoBuffSize); 
	if(!GetBuffer(dwReadPosition, dwBytes2Read))
	{
		return iRetStatus;
	}

	for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes - 0x20; dwOffset++)
	{
		if (memcmp(&m_pbyBuff[dwOffset], &bKidoSig4[0x00], sizeof(bKidoSig4)) == 0x00)
		{
			iHitCnt++;		
		}
	}
	if(iHitCnt == 0x05)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Worm.Kido"));
		iRetStatus = VIRUS_FILE_DELETE; 
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectPoison
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Poison Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectPoison()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD dwBaseOfCode = 0;
	if(!m_pMaxPEFile->ReadBuffer(&dwBaseOfCode, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x2C, 4, 4))
	{
		return iRetStatus;
	}

	if(((m_pSectionHeader[0].Characteristics & 0x60000020) == 0x60000020) || (m_pSectionHeader[1].Characteristics == 0xC0000040))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x2000];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, 0x2000);

		if((m_dwAEPUnmapped % 0x100) == 8 || dwBaseOfCode % 0x100 == 0xf8)
		{	

			if(!GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData + 2, 0xC, 0xC))
			{
				return iRetStatus;
			}

			const BYTE bySignature[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB8};
			const BYTE bySignature1[] ={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8D};//new
			if(0 == memcmp(m_pbyBuff, bySignature, 7))
			{
				if((m_pSectionHeader[m_wAEPSec].VirtualAddress + m_dwImageBase + m_pSectionHeader[m_wAEPSec].SizeOfRawData /*m_pMaxPEFile->m_stPEHeader.SectionAlignment*/ == (*(DWORD *)&m_pbyBuff[7]))||
					((m_pSectionHeader[m_wAEPSec + 1].VirtualAddress + m_dwImageBase == (*(DWORD *)&m_pbyBuff[7]))))
				{
					if(GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData /*m_pMaxPEFile->m_stPEHeader.SectionAlignment*/ + 0x3B0, 0x1050, 0x900/*0xF50*/))
					{
						if(GetPoisonSig(0x10, 0xD42, 0xE00 ))
						{					
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("BackDoor.Poison.apei"));
							iRetStatus = VIRUS_FILE_DELETE;
						}
						DWORD	dwOffset = 0x00;
						if (m_pMaxPEFile->ReadBuffer(&dwOffset, m_dwAEPMapped+1,sizeof(DWORD),sizeof(DWORD)))  //pick call addr
						{
							DWORD	dwBuffOff = dwOffset-m_dwImageBase+0x33;
							if (m_pMaxPEFile->ReadBuffer(&dwOffset,dwBuffOff,sizeof(DWORD),sizeof(DWORD)))
							{
								const BYTE bySig[] ={0x8D,0xB5,0x84,0xF0,0xFF,0xFF,0x0F,0x31,0x92,0x33,0xC9,0x69,0xC0,0x05,0x4B,0x56,0xAC,0x83,0xC0,0x01,0x89,0x84,0x8E,0xD9,0x08,0x00,0x00,0x83,0xC1,0x01,0x83,0xF9,0x22};
								if (GetBuffer(dwOffset+dwBuffOff+4,sizeof(bySig),sizeof(bySig)))
								{	
									if( memcmp(m_pbyBuff,bySig,sizeof(bySig))== 0)
									{
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("BackDoor.Poison.cpb"));										
										iRetStatus = VIRUS_FILE_DELETE;

									}

								}

							}
						}
					}
				}
			}
			else if(0 == memcmp(m_pbyBuff, bySignature1, 7))
			{
				if(m_pSectionHeader[m_wAEPSec].VirtualAddress + m_dwImageBase + m_pSectionHeader[m_wAEPSec].SizeOfRawData == (*(DWORD *)&m_pbyBuff[8]))
				{
					if(GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData +m_pSectionHeader[m_wAEPSec].SizeOfRawData, 0x2000, 0xDA0))
					{
						if(GetPoisonSig(0x926, 0x16E8, 0x18C0 ))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("BackDoor.Poison.apfy"));
							iRetStatus = VIRUS_FILE_DELETE;
						}
					}
				}
			}
			else
			{
				BYTE byZeros[0x200] = {0};
				if(GetBuffer(m_dwAEPMapped, sizeof(byZeros), sizeof(byZeros)))
				{
					if(!memcmp(m_pbyBuff, byZeros, sizeof(byZeros)))
					{				
						if(GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pMaxPEFile->m_stPEHeader.SectionAlignment + 0x3B0, 0x1050, 0xF50))
						{
							if(GetPoisonSig(0x10, 0xD42, 0xE00 ))
							{							
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("BackDoor.Poison.zero"));
								iRetStatus = VIRUS_FILE_DELETE;
							}
						}
					}
				}
			}
		}
		else if(m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x200)
		{
			if(!GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData, m_pSectionHeader[m_wAEPSec].SizeOfRawData, m_pSectionHeader[m_wAEPSec].SizeOfRawData))
			{
				return iRetStatus;
			}

			DWORD dwJumpCount = 0;
			DWORD dwJumpOffset = 0;

			for(DWORD dwIndex = m_dwAEPUnmapped - m_pSectionHeader[m_wAEPSec].PointerToRawData; dwIndex < m_dwNoOfBytes; dwIndex++)
			{
				if(m_pbyBuff[dwIndex] == 0xE8 || m_pbyBuff[dwIndex] == 0xE9)//call or jmp
				{
					dwJumpOffset = *(DWORD *)&m_pbyBuff[dwIndex + 1]+ dwIndex  + 5; 
					if(dwJumpOffset < m_pSectionHeader[m_wAEPSec].SizeOfRawData && dwJumpOffset >= 0)
					{
						dwJumpCount++;
						dwIndex = dwJumpOffset - 1;
					}
				}
				else if(m_pbyBuff[dwIndex] == 0xEB )//short jmp
				{

					BYTE bTemp = m_pbyBuff[dwIndex + 1];
					if(bTemp < 0x7F)
					{
						dwJumpOffset = dwIndex +(DWORD)bTemp + 2;
						if(dwJumpOffset < m_pSectionHeader[m_wAEPSec].SizeOfRawData && dwJumpOffset >= 0)
						{
							dwJumpCount++;	
							dwIndex = dwJumpOffset - 1;
						}
					}
					else
					{
						dwJumpOffset = dwIndex +(DWORD)bTemp+ 0xFFFFFF00 + 2;
						if(dwJumpOffset < m_pSectionHeader[m_wAEPSec].SizeOfRawData && dwJumpOffset >= 0)
						{
							dwJumpCount++;
							dwIndex = dwJumpOffset - 1;
						}
					}

				}


				if(dwJumpCount <= 6 && dwJumpOffset == 8)
				{
					break;
				}
				else if(dwJumpCount > 6)
					return iRetStatus;

			}

			if(dwJumpOffset == 8)
			{
				memset(m_pbyBuff, 0, 0x2000);
				if(!GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData + 2, 0xC, 0xC))
				{
					return iRetStatus;
				}

				const BYTE bySignature[] = {0x00, 0x00, 0x00, 0x00, 0xB8};
				//const BYTE bySignature1[] ={0x00, 0x00, 0x00, 0x00, 0x8D};//new
				if(0 == memcmp(&m_pbyBuff[2], bySignature, 5))
				{
					if((m_pSectionHeader[m_wAEPSec].VirtualAddress + m_dwImageBase + m_pSectionHeader[m_wAEPSec].SizeOfRawData /*m_pMaxPEFile->m_stPEHeader.SectionAlignment*/ == (*(DWORD *)&m_pbyBuff[7]))||
						((m_pSectionHeader[m_wAEPSec + 1].VirtualAddress + m_dwImageBase == (*(DWORD *)&m_pbyBuff[7]))))
					{
						if(GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData /*m_pMaxPEFile->m_stPEHeader.SectionAlignment*/ + 0x3B0, 0x1050, 0x900/*0xF50*/))
						{
							if(GetPoisonSig(0x10, 0xD42, 0xE00 ))
							{					
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("BackDoor.Poison.aec"));
								iRetStatus = VIRUS_FILE_DELETE;
							}
						}
					}
				}

			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function verifies the Binary Signature in file buffer
--------------------------------------------------------------------------------------*/
bool CTrojans:: GetPoisonSig(DWORD dwSig1Off, DWORD dwSig3Off, DWORD dwSigOff)
{
	if(!m_pbyBuff || !m_dwNoOfBytes)
	{
		return false;
	}

	for(DWORD i = 0; i < m_dwNoOfBytes; i++)
	{
		m_pbyBuff[i] = m_pbyBuff[i] >= 'A' && m_pbyBuff[i] <= 'Z'? m_pbyBuff[i] + 32: m_pbyBuff[i];
	}

	const BYTE bySig1[] ={0x20, 0x25, 0x73, 0x3a, 0x25, 0x69, 0x20, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e};//http
	const BYTE bySig2[] ={0x76, 0x6f, 0x71, 0x61, 0x2e, 0x69};//voda
	const BYTE bySig3[] ={0xE8, 0x08, 0x00, 0x00, 0x00, 0x61, 0x64, 0x76, 0x70, 0x61, 0x63, 0x6B, 0x00, 0xFF, 0x95, 0x21, 0xF1, 0xFF, 0xFF, 0x68, 0x6B, 0x37};//adpack
	const BYTE bySig4[] ={0x28, 0x00, 0x73, 0x6f, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x5c, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x65, 0x73, 0x5c, 0x68, 0x74, 0x74, 0x70}; //software
	const BYTE bySig5[] ={0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74};//connect
	if((memcmp(&m_pbyBuff[dwSig1Off],bySig1, sizeof(bySig1)) == 0) || (memcmp(&m_pbyBuff[dwSig3Off],bySig3, sizeof(bySig3)) == 0)|| (memcmp(&m_pbyBuff[0x9],bySig5, sizeof(bySig5)) == 0))
	{
		return true;
	}
	for(DWORD dwOffset = dwSigOff; dwOffset <= m_dwNoOfBytes - sizeof(bySig4); dwOffset++)
	{
		if((memcmp(&m_pbyBuff[dwOffset],bySig2, sizeof(bySig2)) == 0) || (memcmp(&m_pbyBuff[dwOffset],bySig4, sizeof(bySig4)) == 0))
		{
			return true;
		}
	}
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectZAccess
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of ZeroAccess Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectZAccess(void)
{	
	int	iRetStatus = VIRUS_NOT_FOUND;
	TCHAR szVirusName[MAX_PATH] = {0};
	
	if(m_pMaxPEFile->m_stPEHeader.Subsystem != 0x01)
		return iRetStatus;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		if (DetectZAccessG())
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.ZAccess.G"));
			return VIRUS_FILE_DELETE;
		}
		if (DetectZAccessE())
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.ZAccess.E"));
			return VIRUS_FILE_DELETE;
		}
		return iRetStatus;
	}

	if (DetectZAccessH())
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.ZAccess.H"));
		return VIRUS_FILE_DELETE;
	}

	if (DetectZAccessJ())
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.ZAccess.J"));
		return VIRUS_FILE_DELETE;
	}

	if (DetectZAccessL())
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.ZAccess.L"));
		return VIRUS_FILE_DELETE;
	}

	if (DetectZAccessC())
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.ZAccess.C"));
		return VIRUS_FILE_DELETE;
	}

	int		i = 0x00;
	BYTE	bSecName[] = {0x2E, 0x64, 0x61, 0x74, 0x61};
	DWORD	dwSecStart = 0x00;

	for (i=0x00; i < m_pMaxPEFile->m_stPEHeader.NumberOfSections; i++)
	{
		if (memcmp(&m_pMaxPEFile->m_stSectionHeader[i].Name[0x00],&bSecName[0x00],sizeof(bSecName)) == 0x00)
		{
			dwSecStart = m_pMaxPEFile->m_stSectionHeader[i].PointerToRawData;
			break;
		}
	}

	if (dwSecStart == 0x00)
		return iRetStatus;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
	const int ZACCESS_BUFF_SIZE		= 0x1750;	
	m_pbyBuff = new BYTE[ZACCESS_BUFF_SIZE];	
	if(GetBuffer(dwSecStart, ZACCESS_BUFF_SIZE, ZACCESS_BUFF_SIZE))
	{
		
		TCHAR szSig_A[] ={ _T("4669727374206169726564206F6E204D617263682031382C2031393735*7772697474656E206279204576657265747420477265656E6261756D20616E64204A696D20467269747A656C6C")};
		TCHAR szSig_B[] ={ _T("6B696E67206F6620746865204C6F6D6261726473*4865206861642061206C617374696E6720696D70616374206F6E204974616C79")};
		TCHAR szSig_C[] ={ _T("5468652031393130204C6F6E646F6E20746F204D616E63686573746572206169722072616365*31302C303030207072697A6520666F7220666C79696E672066726F6D204C6F6E646F6E20746F204D616E6368657374657220696E20756E64657220323420686F757273")};
		TCHAR szSig_D[] ={ _T("546974616E696120636F6E7369737473206F66*457175616C20616D6F756E7473206F662069636520616E6420726F636B")};
		TCHAR szSig_E[] ={ _T("436F6E616E207468652042617262617269616E206973206120313938322066616E746173792066696C6D*7072652D686973746F72696320776F726C64206F66206461726B206D6167696320616E64207361766167657279")};
		TCHAR szSig_F[] ={ _T("54686572652069732065766964656E6365*4C6174652049726F6E2041676520616E6420726F6D616E20736574746C656D656E747320696E207468652041726561")};
		TCHAR szSig_G[] ={ _T("626F64792077617320666F756E642064726F776E6564*5400680065002000650076006900640065006E0063006500200061006700610069006E00730074002000680069006D00")};
		TCHAR szSig_H[] ={ _T("6E0061006D006500640020006300610070007400610069006E0020006F00660020007400680065002000430061006E00750063006B0073*79006F0075006E00670065007300740020006300610070007400610069006E")};
		TCHAR szSig_I[] ={ _T("4C006F007200640020006F00660020007400680065002000520069006E00670073*5361756C205A61656E747A20616E64206469737472696275746F7220556E697465642041727469737473")};
		TCHAR szSig_J[] ={ _T("447572696E6720746865204A6170616E6573652061747461636B206F6E20506561726C20486172626F72*3720446563656D6265722031393431")};
		TCHAR szSig_K[] ={ _T("480069007300200063006F006E006400750063007400200073006500630075007200650064*56006900630074006F007200690061002000430072006F00730073")};
		TCHAR szSig_L[] ={ _T("41667465722061206C656E6774687920626174746C6520776974682063616E636572*6469656420696E2031393831")};
		TCHAR szSig_M[] ={ _T("517565656E2052616E6176616C6F6E61*717565656E2072616E6176616C6F6E61")};
		TCHAR szSig_N[] ={ _T("4D006F0072006F0074006100690020004D007500740069006E0079*6D007500740069006E0079")};
		TCHAR szSig_O[] ={ _T("4772616E642076696C6C6120646520436173746F*76696C6C6120446520636173746F20427261766F")};
		TCHAR szSig_P[] ={ _T("44007200690062006500720067*6A006F00750072006E0061006C006900730074")};

		CSemiPolyDBScn	polydbObj;
		if(polydbObj.LoadSigDBEx(szSig_A, _T("Virus.ZAccess.KA"), TRUE) <= 1)
			return iRetStatus;

		polydbObj.LoadSigDBEx(szSig_B, _T("Virus.ZAccess.KB"), TRUE);
		polydbObj.LoadSigDBEx(szSig_C, _T("Virus.ZAccess.KC"), TRUE);
		polydbObj.LoadSigDBEx(szSig_D, _T("Virus.ZAccess.KD"), TRUE);
		polydbObj.LoadSigDBEx(szSig_E, _T("Virus.ZAccess.KE"), TRUE);
		polydbObj.LoadSigDBEx(szSig_F, _T("Virus.ZAccess.KF"), TRUE);
		polydbObj.LoadSigDBEx(szSig_G, _T("Virus.ZAccess.KG"), TRUE);
		polydbObj.LoadSigDBEx(szSig_H, _T("Virus.ZAccess.KH"), TRUE);
		polydbObj.LoadSigDBEx(szSig_I, _T("Virus.ZAccess.KI"), TRUE);
		polydbObj.LoadSigDBEx(szSig_J, _T("Virus.ZAccess.KJ"), TRUE);
		polydbObj.LoadSigDBEx(szSig_K, _T("Virus.ZAccess.KK"), TRUE);
		polydbObj.LoadSigDBEx(szSig_L, _T("Virus.ZAccess.KL"), TRUE);
		polydbObj.LoadSigDBEx(szSig_M, _T("Virus.ZAccess.KM"), TRUE);
		polydbObj.LoadSigDBEx(szSig_N, _T("Virus.ZAccess.KN"), TRUE);
		polydbObj.LoadSigDBEx(szSig_O, _T("Virus.ZAccess.KO"), TRUE);
		polydbObj.LoadSigDBEx(szSig_P, _T("Virus.ZAccess.KP"), FALSE);

		if(polydbObj.ScanBuffer(&m_pbyBuff[0], ZACCESS_BUFF_SIZE, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName)>0)
			{
				iRetStatus = VIRUS_FILE_DELETE;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			}
		}
	}

	if (iRetStatus == VIRUS_NOT_FOUND)
	{
		//1 : It should have export table
		if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x00].Size == 0x00 || m_pMaxPEFile->m_stPEHeader.DataDirectory[0x00].VirtualAddress == 0x00)
			return iRetStatus;
			
		//2 : It should have import table
		if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x01].Size != 0x28 || m_pMaxPEFile->m_stPEHeader.DataDirectory[0x01].VirtualAddress == 0x00)
			return iRetStatus;

		//3 : It should have Debug Directory
		if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x06].Size != 0x1C || m_pMaxPEFile->m_stPEHeader.DataDirectory[0x06].VirtualAddress == 0x00)
			return iRetStatus;

		memset(&m_pbyBuff[0x00],0x00,ZACCESS_BUFF_SIZE * sizeof(BYTE));
		if (!GetBuffer(m_dwAEPMapped,0x10))
			return iRetStatus;

		BYTE bAEPSig[] = {0x55, 0x8B, 0xEC};
		if(memcmp(m_pbyBuff, bAEPSig, sizeof(bAEPSig)) != 0x00)
			return iRetStatus;
		
		DWORD dwRVA = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x01].VirtualAddress;
		DWORD dwSize = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x01].Size;
		
		WORD	wSecNo = 0x00;
		DWORD dwFileOffSet = Rva2FileOffsetEx(dwRVA,&wSecNo);
		if ((dwFileOffSet + 0x14) < m_pMaxPEFile->m_dwFileSize)
		{
			DWORD	dwValue = 0x00;
			m_pMaxPEFile->ReadBuffer((LPVOID)&dwValue,(dwFileOffSet + 0x10),sizeof(DWORD));
			if (dwValue == 0x00)
				return iRetStatus;

			dwFileOffSet = Rva2FileOffsetEx(dwValue,&wSecNo);
			if ((dwFileOffSet + 0x04) > m_pMaxPEFile->m_dwFileSize)
				return iRetStatus;

			m_pMaxPEFile->ReadBuffer((LPVOID)&dwValue,dwFileOffSet,sizeof(DWORD));
			if (dwValue == 0x00)
				return iRetStatus;

			dwFileOffSet = 0x00;
			dwFileOffSet = Rva2FileOffsetEx(dwValue,&wSecNo);
			memset(&m_pbyBuff[0x00],0x00,ZACCESS_BUFF_SIZE * sizeof(BYTE));
			if (!GetBuffer(dwFileOffSet,ZACCESS_BUFF_SIZE))
				return iRetStatus;
			
			CSemiPolyDBScn	polydbObj2;
			TCHAR			szSig_Import[] = { _T("4D6D416C6C6F636174654D617070696E6741646472657373*52746C437265617465536563757269747944657363726970746F72")};
			TCHAR			szSig_Import_2[] = { _T("52746C437265617465536563757269747944657363726970746F72*4D6D416C6C6F636174654D617070696E6741646472657373")};

			if(polydbObj2.LoadSigDBEx(szSig_Import, _T("Virus.ZAccess.K"), TRUE) <= 1)
				return iRetStatus;
			polydbObj2.LoadSigDBEx(szSig_Import_2, _T("Virus.ZAccess.K"), FALSE);
			if(polydbObj2.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) < 0)
			{
				return iRetStatus;
			}

			dwRVA = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x06].VirtualAddress;
			dwFileOffSet = Rva2FileOffsetEx(dwRVA,&wSecNo);
			m_pMaxPEFile->ReadBuffer((LPVOID)&dwValue,(dwFileOffSet + 0x18),sizeof(DWORD));
			if (dwValue == 0x00)
				return iRetStatus;

			dwFileOffSet = 0x00;
			dwFileOffSet = dwValue;
			memset(&m_pbyBuff[0x00],0x00,ZACCESS_BUFF_SIZE * sizeof(BYTE));
			if (!GetBuffer(dwFileOffSet,0x100))
				return iRetStatus;
			
			BYTE	bDebgSig[] = {0x52, 0x53, 0x44, 0x53};
			BYTE	bDebgSig_2[] = {0x52, 0x94, 0x82, 0x37};
			if (memcmp(&m_pbyBuff[0x00],&bDebgSig[0x00],sizeof(bDebgSig)) == 0x00 ||
				memcmp(&m_pbyBuff[0x00],&bDebgSig_2[0x00],sizeof(bDebgSig_2)) == 0x00)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.ZAccess.KGen"));
				return VIRUS_FILE_DELETE;
			}
		}
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectZAccessC
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of ZeroAccess.C Family
--------------------------------------------------------------------------------------*/
bool CTrojans::DetectZAccessC()
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	m_pbyBuff = new BYTE[0x50];   
	if (GetBuffer(m_dwAEPMapped,0x50))
	{
		BYTE  bAEPSig1[] = {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x81, 0xEC, 0xA4, 0x02, 0x00, 0x00, 0x53, 0x56};
		BYTE  bAEPSig2[] = {0x6A, 0x5C, 0x50, 0xFF, 0x15};
		BYTE  bAEPSig12[] = {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x83, 0xEC, 0x2C, 0x53, 0x56, 0x8B, 0x75, 0x0C};

		if ((memcmp(&m_pbyBuff[0x00],&bAEPSig1[0x00],sizeof(bAEPSig1)) == 0x00 &&
			 memcmp(&m_pbyBuff[0x15],&bAEPSig2[0x00],sizeof(bAEPSig2)) == 0x00) ||
			(memcmp(&m_pbyBuff[0x00],&bAEPSig12[0x00],sizeof(bAEPSig12)) == 0x00 &&
			 memcmp(&m_pbyBuff[0x12],&bAEPSig2[0x00],sizeof(bAEPSig2)) == 0x00))
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectZAccessC
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of ZeroAccess.E Family
--------------------------------------------------------------------------------------*/
bool CTrojans::DetectZAccessE(void)
{
      bool  bRet = false;
            
      if(m_pbyBuff)
      {
            delete []m_pbyBuff;
            m_pbyBuff = NULL;
      }
      m_pbyBuff = new BYTE[ZACCESS_J_BUFF_SIZE + MAX_INSTRUCTION_LEN];

      if (NULL == m_pbyBuff)
      {
            return bRet; 
      }
      memset(m_pbyBuff, 0, ZACCESS_J_BUFF_SIZE + MAX_INSTRUCTION_LEN);
      if(!GetBuffer(m_dwAEPMapped, ZACCESS_J_BUFF_SIZE, ZACCESS_J_BUFF_SIZE))
      {
            return bRet; 
      }

      DWORD       dwLength = 0, dwOffSet = 0,   dwHits = 0x00;
      BYTE        B1 = 0, B2 = 0;
      t_disasm    da;
      DWORD       dwStringOffSet = 0x00, dwTemp = 0x00;
      WORD        wSecNo = 0x00;

      m_dwInstCount = 0;
      while(dwOffSet < m_dwNoOfBytes || m_dwInstCount <= 15)
      {
            memset(&da, 0x00, sizeof(da));

            B1 = *((BYTE*)&m_pbyBuff[dwOffSet]);
            B2 = *((BYTE*)&m_pbyBuff[dwOffSet + 1]);

            //Skipping Some Instructions that couldn't be interpreted by Olly.
            if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
            {
                  dwOffSet+= 0x03;
                  continue;
            }
            if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
            {
                  dwOffSet+= 0x02;
                  continue;
            }
            
            dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN,0x400000, &da, DISASM_CODE);
            m_dwInstCount++;
            
            if(dwHits == 0x00 && dwLength==0x01 && strstr(da.result, "PUSH EBP") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x01 && dwLength==0x02 && strstr(da.result, "MOV EBP,ESP") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x02 && dwLength==0x01 && strstr(da.result, "PUSH EDI") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x03 && dwLength==0x05 && strstr(da.result, "PUSH") != NULL)
            {
                  char  *pTemp = NULL;
                  pTemp = strstr(da.result, "PUSH ");
                  if (pTemp)
                  {
                        pTemp+=0x05;
                        if (pTemp != NULL)
                        {
                              dwStringOffSet = strtol(pTemp,NULL,0x10);
                        }
                  }

                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x04 && dwLength==0x06 && strstr(da.result, "CALL [") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x05 && dwLength==0x03 && strstr(da.result, "MOV EDI,[") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x06 && dwLength==0x01 && strstr(da.result, "POP ECX") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x07 && dwLength==0x03 && strstr(da.result, "PUSH DWORD PTR [") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x08 && dwLength==0x05 && strstr(da.result, "CALL") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x09 && dwLength==0x05 && strstr(da.result, "MOV EAX,[") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if((dwHits == 0x0A || dwHits == 0x0B) && dwLength==0x01 && strstr(da.result, "POP") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  if (dwHits == 0x0C)
                        break;
                  continue;
            }
            dwOffSet += dwLength;
      }

      if (dwHits == 0x0C && dwStringOffSet > m_pMaxPEFile->m_stPEHeader.ImageBase)
      {
            dwStringOffSet -= m_pMaxPEFile->m_stPEHeader.ImageBase;
            dwTemp = Rva2FileOffsetEx(dwStringOffSet,&wSecNo);

            if (dwTemp > (m_pMaxPEFile->m_dwFileSize - 0x50))
                  return bRet;

            memset(m_pbyBuff, 0, ZACCESS_J_BUFF_SIZE + MAX_INSTRUCTION_LEN);
            if(!GetBuffer(dwTemp, 0x50, 0x30))
            {
                  return bRet; 
            }

            
            //Virus Uses one of the following string as OutputDebugString....
            //I'm Luke Skywalker. I'm here to rescue you.
            //Help me, Obi-Wan Kenobi; you're my only hope.
            //Ready are you? What know you of ready?
            //.....

            DWORD i = 0x00;
            dwHits = 0x00;
            for(i = 0x00; i < 0x30 ; i++)
            {
                  if ((m_pbyBuff[i] >= 'a' && m_pbyBuff[i] <= 'z') || (m_pbyBuff[i] >= 'A' && m_pbyBuff[i] <= 'Z') ||
                        (m_pbyBuff[i] >= '0' && m_pbyBuff[i] <= '9') || m_pbyBuff[i] == 0x20 || m_pbyBuff[i] == 0x3F)
                        dwHits++; 
            }
            if (dwHits > 0x25)
                  bRet = true;

      }


      return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectZAccessJ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of ZeroAccess.J Family
--------------------------------------------------------------------------------------*/
bool CTrojans::DetectZAccessJ(void)
{
      bool  bRet = false;
      
      if(m_pbyBuff)
      {
            delete []m_pbyBuff;
            m_pbyBuff = NULL;
      }
      m_pbyBuff = new BYTE[ZACCESS_J_BUFF_SIZE + MAX_INSTRUCTION_LEN];
      if (NULL == m_pbyBuff)
      {
            return bRet; 
      }
      memset(m_pbyBuff, 0, ZACCESS_J_BUFF_SIZE + MAX_INSTRUCTION_LEN);
      if(!GetBuffer(m_dwAEPMapped, ZACCESS_J_BUFF_SIZE, ZACCESS_J_BUFF_SIZE))
      {
            return bRet; 
      }

      DWORD       dwLength = 0, dwOffSet = 0,   dwHits = 0x00;
      BYTE        B1 = 0, B2 = 0;
      t_disasm    da;
      char        szInstr[MAX_PATH] = {0};

      m_dwInstCount = 0;
      while(dwOffSet < m_dwNoOfBytes || m_dwInstCount <= 25)
      {
            memset(&da, 0x00, sizeof(da));

            B1 = *((BYTE*)&m_pbyBuff[dwOffSet]);
            B2 = *((BYTE*)&m_pbyBuff[dwOffSet + 1]);

            //Skipping Some Instructions that couldn't be interpreted by Olly.
            if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
            {
                  dwOffSet+= 0x03;
                  continue;
            }
            if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
            {
                  dwOffSet+= 0x02;
                  continue;
            }
            
            dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN,0x400000, &da, DISASM_CODE);
            m_dwInstCount++;

            if(dwHits == 0x00 && dwLength==0x01 && strstr(da.result, "PUSH EBP") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x01 && dwLength==0x02 && strstr(da.result, "MOV EBP,ESP") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x02 && dwLength==0x06 && strstr(da.result, "SUB ESP,") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x03 && dwLength==0x02 && strstr(da.result, "PUSH 1") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if((dwHits == 0x04 || dwHits == 0x07) && dwLength==0x03 && strstr(da.result, "LEA EAX,[") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if((dwHits == 0x05 || dwHits == 0x09)&& dwLength==0x01 && strstr(da.result, "PUSH EAX") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if((dwHits == 0x06 || dwHits == 0x0A) && dwLength==0x06 && strstr(da.result, "CALL") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x08 && dwLength==0x05 && strstr(da.result, "PUSH") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x0B && dwLength==0x04 && strstr(da.result, "CMP BYTE PTR") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x0C && dwLength==0x06 && strstr(da.result, "JE") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x0D && dwLength==0x05 && strstr(da.result, "MOV EAX,C000000") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  continue;
            }
            if(dwHits == 0x0E && dwLength==0x05 && strstr(da.result, "JMP ") != NULL)
            {
                  dwHits++;
                  dwOffSet += dwLength;
                  break;
            }
            
            dwOffSet += dwLength;
      }
      if (dwHits == 0xF)
            bRet = true;

      return bRet; 
}

/*-------------------------------------------------------------------------------------
	Function		: DetectZAccessG
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of ZeroAccess.G Family
--------------------------------------------------------------------------------------*/
bool CTrojans::DetectZAccessG()
{
	bool	bRet = false;
	BYTE	bAEPSig[] = {0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00/*, 0x50*/};
	BYTE	bSecName[] = {0x2E, 0x49, 0x4E, 0x49, 0x54};
	int		i = 0x00;

	if (m_pMaxPEFile->m_stPEHeader.NumberOfSections < 0x05 || m_pMaxPEFile->m_stPEHeader.NumberOfSections > 0x06)
		return bRet;

	if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x02].Size != 0x00 || m_pMaxPEFile->m_stPEHeader.DataDirectory[0x02].VirtualAddress != 0x00)
		return bRet;
	/*
	if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].Size != 0x00 || m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].VirtualAddress != 0x00)
		return bRet;
	*/

	if (memcmp(&m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].Name[0x00],&bSecName[0x00],sizeof(bSecName)) == 0x00 ||
		memcmp(&m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].Name[0x00],&bSecName[0x01],(sizeof(bSecName) - 0x01)) == 0x00)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}	
		m_pbyBuff = new BYTE[0x50];	
		memset(&m_pbyBuff[0x00],0x00,0x50 * sizeof(BYTE));
		if (!GetBuffer(m_dwAEPMapped,0x50))
			return bRet;

		for(i = 0x00; i < (0x22 - sizeof(bAEPSig)); i++)
		{
			if (memcmp(&m_pbyBuff[i],&bAEPSig[0x00],sizeof(bAEPSig)) == 0x00)
			{
				bRet = true;
			}
		}
	}

	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectZAccessH
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of ZeroAccess.H Family
--------------------------------------------------------------------------------------*/
bool CTrojans::DetectZAccessH(void)
{
	bool	bRet = false;

	if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x01].VirtualAddress != 0xA000)
		return bRet;

	if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x00].VirtualAddress == 0x00 || m_pMaxPEFile->m_stPEHeader.DataDirectory[0x00].Size == 0x00)
		return bRet;

	DWORD	dwOffSet = 0x00;
	WORD	wInSec = 0x00;

	dwOffSet = Rva2FileOffsetEx(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x01].VirtualAddress,&wInSec);
	if (dwOffSet == 0x00 || dwOffSet > m_pMaxPEFile->m_dwFileSize)
		return bRet;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[ZACCESS_J_BUFF_SIZE];
	if(!GetBuffer(dwOffSet, ZACCESS_J_BUFF_SIZE, ZACCESS_J_BUFF_SIZE))
	{
		return bRet; 
	}
	CSemiPolyDBScn	polydbObj;
	TCHAR			szVirusName[MAX_PATH] = {0};
	TCHAR			szSig[] ={_T("6E746F736B726E6C2E6578650048414C*766964656F7072742E737973007464692E737973006E6469732E737973")};
	
	if(polydbObj.LoadSigDBEx(szSig, _T("Virus.ZAccess.H"), FALSE) <= 1)
		return bRet;

	if(polydbObj.ScanBuffer(&m_pbyBuff[0], ZACCESS_J_BUFF_SIZE, szVirusName) >= 0)
	{
		if(_tcslen(szVirusName)>0)
		{
			bRet = true;
		}
	}

	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectZAccessL
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of ZeroAccess.L Family
--------------------------------------------------------------------------------------*/
bool CTrojans::DetectZAccessL(void)
{
	bool	bRet = false;
	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[ZACCESS_J_BUFF_SIZE + MAX_INSTRUCTION_LEN];

	if (NULL == m_pbyBuff)
	{
		return bRet; 
	}
	memset(m_pbyBuff, 0, ZACCESS_J_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(!GetBuffer(m_dwAEPMapped, ZACCESS_J_BUFF_SIZE, ZACCESS_J_BUFF_SIZE))
	{
		return bRet; 
	}
	if (m_pbyBuff[0x00] != 0x56)
		return bRet;


	DWORD		dwLength = 0, dwOffSet = 0,	dwHits = 0x00;
	BYTE		B1 = 0, B2 = 0;
	t_disasm	da;
	
	int			iPushCnt = 0x00, iLCallCnt = 0x00, iSCallCnt = 0x00, iAddCnt = 0x00, iPopCnt = 0x00, iIncCnt = 0x00, iMovCnt = 0x00;

	m_dwInstCount = 0;
	while(dwOffSet < m_dwNoOfBytes || m_dwInstCount <= 125)
	{
		memset(&da, 0x00, sizeof(da));

		B1 = *((BYTE*)&m_pbyBuff[dwOffSet]);
		B2 = *((BYTE*)&m_pbyBuff[dwOffSet + 1]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x02;
			continue;
		}
		
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN,0x400000, &da, DISASM_CODE);
		m_dwInstCount++;

		if(iPushCnt < 0x03 && dwLength==0x01 && strstr(da.result, "PUSH E") != NULL)
		{
			iPushCnt++;
			dwHits++;
			dwOffSet += dwLength;
			continue;
		}

		if(iLCallCnt < 0x04 && dwLength==0x05 && strstr(da.result, "CALL") != NULL)
		{
			iLCallCnt++;
			dwHits++;
			dwOffSet += dwLength;
			continue;
		}
		if(iSCallCnt < 0x01 && dwLength==0x02 && strstr(da.result, "CALL EAX") != NULL)
		{
			iSCallCnt++;
			dwHits++;
			dwOffSet += dwLength;
			continue;
		}

		if(iPopCnt < 0x02 && dwLength==0x01 && (strstr(da.result, "POP EBP") != NULL || strstr(da.result, "POP EAX") != NULL))
		{
			iPopCnt++;
			dwHits++;
			dwOffSet += dwLength;
			continue;
		}
		
		if(iAddCnt < 0x01 && dwLength==0x05 && strstr(da.result, "ADD EAX,") != NULL)
		{
			iAddCnt++;
			dwHits++;
			dwOffSet += dwLength;
			continue;
		}

		if(iMovCnt < 0x01 && dwLength==0x03 && strstr(da.result, "MOV [ESP],EBP") != NULL)
		{
			iMovCnt++;
			dwHits++;
			dwOffSet += dwLength;
			continue;
		}

		if(iIncCnt < 0x01 && dwLength==0x01 && strstr(da.result, "INC E") != NULL)
		{
			iIncCnt++;
			dwHits++;
			dwOffSet += dwLength;
			continue;
		}
		
		if(dwLength==0x01 && strstr(da.result, "???") != NULL)
		{
			break;
		}

		dwOffSet += dwLength;
	}
	if (dwHits == 0xD)
		bRet = true;

	return bRet; 
}

/*-------------------------------------------------------------------------------------
	Function		: DetectJorrik
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Jorrik Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectJorrik()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	/*if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		m_wNoOfSections == 3 && m_dwAEPUnmapped == 0x11B4 && m_dwAEPMapped == m_dwAEPUnmapped &&
		(m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x31000) &&
		((m_pSectionHeader[m_wAEPSec].Characteristics & 0x60000020) == 0x60000020) &&
		((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0x40000040) == 0x40000040))		
	{
		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int JORIK_VB_BUFF = 0x500;
		m_pbyBuff = new BYTE[JORIK_VB_BUFF];
		if(GetBuffer(0x4C00, JORIK_VB_BUFF, JORIK_VB_BUFF))
		{
			CSemiPolyDBScn polydbObj;
			const TCHAR  JORIK_VB_SIG1[] = {_T("4300750062006500200043006900740079*43006F006F007200640073002000200062007900200052006F00620065007200740020005200610079006D0065006E0074")};
			polydbObj.LoadSigDBEx(JORIK_VB_SIG1, _T("Trojan.Jorik.Vobfus.dtmq"), FALSE);
			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}*/

	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		(m_wNoOfSections == 4 || m_wNoOfSections == 5) && (m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > 0xD000) &&
		(m_pSectionHeader[2].SizeOfRawData >= 0x2000 && m_pSectionHeader[2].SizeOfRawData <= 0x3000))
	{
		const int JORRIK_BUFF_SIZE = 0x1000;
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[JORRIK_BUFF_SIZE];		
		if(GetBuffer((m_pSectionHeader[2].PointerToRawData + 0xB00), JORRIK_BUFF_SIZE, JORRIK_BUFF_SIZE))
		{
			BYTE byKey[0x0F] = {0};
			BYTE bySig[] = {0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58}; 
			for(int i = 0; i < JORRIK_BUFF_SIZE - 47; i++)
			{
				if(*(DWORD *)&m_pbyBuff[i] == 0)
				{
					continue;
				}
				if(!strcmp((char *)&m_pbyBuff[i], "kernel32.dll") && (memcmp(bySig, &m_pbyBuff[i + 0x10], 0x10) == 0))
				{					
					memcpy(byKey, &m_pbyBuff[i + 0x38], 0x0F);
					break;
				}
				else if(!strcmp((char *)&m_pbyBuff[i], "Ws2_32.dll"))
				{
					memcpy(byKey, &m_pbyBuff[i + 0x20], 0x0F);
					break;
				}
			}
			
			if(*(DWORD *)&byKey[0] == 0)
			{
				return iRetStatus; 
			}
			
			if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + 0x400, JORRIK_BUFF_SIZE, JORRIK_BUFF_SIZE))
			{
				for(int i = 0; i < JORRIK_BUFF_SIZE - 2; i++)
				{
					WORD wCheck = *(WORD *)&m_pbyBuff[i] ^ *(WORD *)&byKey[0];
					if((wCheck == 0x5A4D) || (*(WORD *)&m_pbyBuff[i] == 0x5A4D))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Jorrik.Slenf.bot"));
						return VIRUS_FILE_DELETE;
					}
				}
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectCosmu
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Cosmu Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectCosmu()
{
	int iRetStatus = DetectCosmuALWB();
	if(iRetStatus)
	{
		return iRetStatus;
	}

	if((m_wAEPSec == 0x01) && (m_pSectionHeader[0].SizeOfRawData == 0x00))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x100];
		if(GetBuffer(m_dwAEPMapped, 0x30, 0x30))
		{
			BYTE bySig[] = {0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x00, 0x08, 0x00, 0x00, 0xDB, 0xE2, 0x9B, 0x0F, 0x01, 0xE0, 0xA8};
			if(memcmp(bySig, m_pbyBuff, sizeof(bySig)) == 0)
			{
				DWORD dwJmpOffset = *(DWORD *)&m_pbyBuff[0x22];
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwJmpOffset - m_dwImageBase, &dwJmpOffset))
				{
					return iRetStatus;
				}
				DWORD dwLength = 0, dwOffset = 0x21;
				t_disasm da;				
				Instruction_Set_Struct objInstructionSet[MAX_INSTRUCTIONS] = {0};				
				while(dwOffset < 0x30)
				{
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwLength > (m_dwNoOfBytes - dwOffset) || (dwOffset == 0x21 && !strstr(da.result, "MOV E")))
					{
						break;
					}
					else if(dwLength == 5 && strstr(da.result, "ADD E"))
					{
						dwJmpOffset += *(DWORD *)&m_pbyBuff[dwOffset + 1];
						break;
					}
					else if(dwLength == 2 && strstr(da.result, "JMP E"))
					{
						break;
					}
					dwOffset += dwLength;
				}				
				if(!GetBuffer(dwJmpOffset + 0xD2, 0x55, 0x55))
				{
					return iRetStatus;
				}

				dwLength = 0;
				dwOffset = 0;
				m_dwInstCount = 0;

				while(dwOffset < 0x55 && m_dwInstCount < 5)
				{
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwLength > m_dwNoOfBytes - dwOffset)
					{
						break;
					}
					else if(dwLength == 1 && strstr(da.result, "POP") && m_dwInstCount ==0)
					{
						m_dwInstCount = 1;
					}
					else if(dwLength == 5 && strstr(da.result, "MOV E") && m_dwInstCount == 1)
					{
						if((*(DWORD *)&m_pbyBuff[dwOffset + 1] == 0x7BD) || (*(DWORD *)&m_pbyBuff[dwOffset + 1] == 0x830))
						{
							m_dwInstCount++;
						}
					}
					else if(dwLength == 2 && strstr(da.result, "SUB") && m_dwInstCount == 2)
					{
						if(m_pbyBuff[dwOffset + 1] == 0xE8)
						{
							m_dwInstCount++;
						}
					}
					else if(dwLength == 3 && strstr(da.result, "CMP BYTE PTR") && m_dwInstCount == 3)
					{
						if(m_pbyBuff[dwOffset + 2] == 0x09)
						{
							m_dwInstCount++;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Cosmu"));
							iRetStatus = VIRUS_FILE_DELETE;
							break;
						}
					}										
					dwOffset += dwLength;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectCosmuALWB
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Cosmu.ALWB Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectCosmuALWB()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 3 && ((m_wAEPSec == 1 && (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x7600) && (memcmp(m_pSectionHeader[0].Name, ".rdata", 0x05) == 0) && 
		!(m_pSectionHeader[m_wAEPSec].Characteristics & 0x20000000)) || 
		(m_wAEPSec == 0 && m_dwAEPMapped == 0x11A0 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x21000 && (memcmp(m_pSectionHeader[1].Name, "ÒuÛŠëÔ", 0x05) == 0))))
	{
		DWORD dwStartOffset = 0x0;
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x500];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0x00, 0x500);

		if(m_wAEPSec == 0)
		{
			dwStartOffset = m_dwAEPMapped + 0x4230;
		}
		else
			dwStartOffset = m_pSectionHeader[m_wAEPSec].PointerToRawData;

		if(!GetBuffer(dwStartOffset, 0x500, 0x500))
		{
			return iRetStatus;
		}
		TCHAR szSigALWB[] = _T("00482D652D6C2D6C2D422D6F2D742D332D542D652D612D4D212121*495F4655434B5F444541445F50504C*434D4448444C525F7B3932323131363734");
		TCHAR szSigJYV[] = _T("4D0064006D004400720076006C002E0063006F006D00*64006C006C0073006500720076002E0063006F006D*6500780070006D006E00670072002E006500780065");  //M.d.m.D.r.v.l...c.o.m.*d.l.l.s.e.r.v...c.o.m*e.x.p.m.n.g.r...e.x.e*
		CSemiPolyDBScn	polydbObj;
		polydbObj.LoadSigDBEx(szSigALWB, _T("Virus.Cosmu.ALWB"), TRUE);
		polydbObj.LoadSigDBEx(szSigJYV, _T("Trojan.W32.Cosmu.JYV"), FALSE);

		TCHAR szVirusName[MAX_PATH] = {0};

		if(polydbObj.ScanBuffer(&m_pbyBuff[0], 0x500, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName)>0)
			{
				iRetStatus = VIRUS_FILE_DELETE;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			}
		}
	}

	return iRetStatus;

}
/*-------------------------------------------------------------------------------------
	Function		: DetectEGDial
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of EGDial Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectEGDial(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if( m_wNoOfSections == 5 && 
	  ((memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name,"oqvrztrg", 8) == 0) && (memcmp(m_pSectionHeader[m_wNoOfSections - 2].Name,"42vab535", 8) == 0))||
	  ((memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name,"xa8yjixo", 8) == 0) && (memcmp(m_pSectionHeader[m_wNoOfSections - 2].Name,"4lan6m81", 8) == 0)))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int EGDIAL_BUFF_SIZE = 0xE0;
		m_pbyBuff = new BYTE[EGDIAL_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}	
		memset(m_pbyBuff, 0, EGDIAL_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		
		if(m_pSectionHeader[0].SizeOfRawData == 0)//upx packed
		{
		   if(GetBuffer(m_pSectionHeader[1].PointerToRawData, EGDIAL_BUFF_SIZE, EGDIAL_BUFF_SIZE))
			{
				const BYTE bySignature1[]= {0x77, 0xFF, 0xFF, 0xFF, 0x56, 0x8B, 0xF1, 0x8B, 0x0E, 0x85, 0xC9, 0x74, 0x08, 0xE8, 0x01, 0x00, 0x00, 0xDD, 0x83, 0x26, 0x00, 0x5E, 0xC3, 0xB8};
				const BYTE bySignature2[]= {0x83, 0x65, 0xFC, 0x00, 0xFD, 0xFF, 0x8F, 0xDD, 0x1C, 0x0A, 0xFF, 0x75, 0x1F, 0x76, 0xEB, 0x02, 0x33, 0xC0, 0x8B, 0x4D, 0xF4, 0x89, 0x06, 0x8B, 0xC6, 0x5E, 0x64, 0x89, 0x0D, 0x00, 0xDB, 0xEF};
				if((memcmp(m_pbyBuff, bySignature1, sizeof(bySignature1))== 0) && (memcmp(&m_pbyBuff[0x30], bySignature2, sizeof(bySignature2))== 0))
				{
					_tcscpy_s(m_szVirusName,MAX_VIRUS_NAME,_T("Dialer.EgroupDial"));
					iRetStatus = VIRUS_FILE_DELETE;
				}
			}
		}
		else
		{
			if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0xC02C, EGDIAL_BUFF_SIZE, EGDIAL_BUFF_SIZE))
			{
				const BYTE bySignature1[] = {0x72, 0x62, 0x00, 0x00, 0x5C, 0x69, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x33, 0x32, 0x2E, 0x65, 0x78, 0x65};
			    const BYTE bySignature2[] = {0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x00, 0x46, 0x4F, 0x52, 0x43, 0x45, 0x5F, 0x50, 0x32, 0x45, 0x00, 0x00, 0x00, 0x46, 0x4F, 0x52, 0x43, 0x45, 0x5F, 0x44, 0x49, 0x41, 0x4C, 0x45, 0x52};
			
				if((memcmp(m_pbyBuff, bySignature1, sizeof(bySignature1))== 0) && (memcmp(&m_pbyBuff[0x98], bySignature2, sizeof(bySignature2))== 0))
				{
					_tcscpy_s(m_szVirusName,MAX_VIRUS_NAME,_T("Dialer.EgroupDial"));
					iRetStatus = VIRUS_FILE_DELETE;
				}
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectInstallCoreBrj
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of InstallCore.BRJ + InstallCore.GEN Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectInstallCoreBrj()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(memcmp(m_pSectionHeader[0].Name, "UPX0", 5) == 0 && m_wNoOfSections == 3 &&
	   m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress != 0 && 
	  (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL && 
	   m_pMaxPEFile->m_dwFileSize > 0x75000 && m_pMaxPEFile->m_dwFileSize < 0x95000 && 
	   (m_dwAEPUnmapped % 0x10) == 0)
	{
		const int ICOREGEN_BUFF_SIZE = 0x1000;
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[ICOREGEN_BUFF_SIZE];
		DWORD dwStartOff = m_pSectionHeader[1].PointerToRawData - 0x30;  
		bool bFirstSigFound = false;
		if(GetBuffer(dwStartOff, ICOREGEN_BUFF_SIZE, ICOREGEN_BUFF_SIZE/4))
		{
			TCHAR szFoundFirstSig[MAX_PATH] = {0};
			TCHAR szSig_FSIG[] ={ _T("332E30330055505821*BF77FEFF041040000307426F6F6C6561")};   //check upx vesion 3.3
			CSemiPolyDBScn	polydbObj1;

			polydbObj1.LoadSigDBEx(szSig_FSIG, _T("FoundFirstSig"), FALSE);
			
			if(polydbObj1.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szFoundFirstSig) >= 0)
			{
				if(_tcslen(szFoundFirstSig) > 0)
				{
					bFirstSigFound = true;
				}
			}
		}
		if(bFirstSigFound)
		{
			bFirstSigFound = false;
			dwStartOff = m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress;
			memset(m_pbyBuff, 0, m_dwNoOfBytes);
			if(GetBuffer(dwStartOff, ICOREGEN_BUFF_SIZE, ICOREGEN_BUFF_SIZE/2))
			{
				TCHAR szVirusName[MAX_PATH] = {0};
				TCHAR szSig_BRJ[] ={ _T("49726F6E*536F75726365*49726F6E*536F75726365*737570706F72744069726F6E2D736F757263652E6E6574")};
				TCHAR szSig_GEN[] ={ _T("496E7374616C6C*436F7265*496E7374616C6C*436F7265*7465616D40696E7374616C6C636F72652E636F6D")};
				CSemiPolyDBScn	polydbObj;

				polydbObj.LoadSigDBEx(szSig_BRJ, _T("BRJ"), TRUE);
				polydbObj.LoadSigDBEx(szSig_GEN, _T("GEN"), FALSE);

				if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
				{
					if(_tcslen(szVirusName) > 0)
					{
						bFirstSigFound = true;
					}
				}
			}
			/*if(bFirstSigFound)
			{
				TCHAR szTempFilePath[MAX_PATH] = {0};
				if(UnPackUPXFile(szTempFilePath))
				{
					CMaxPEFile objUnpackedFile;
					if(objUnpackedFile.OpenFile(szTempFilePath, false))
					{
						if(objUnpackedFile.m_stPEHeader.NumberOfSections == 8 && 
							objUnpackedFile.m_stPEHeader.DataDirectory[4].VirtualAddress == 0 && 
							(objUnpackedFile.m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL &&
							objUnpackedFile.m_dwFileSize > 0xF5000 && objUnpackedFile.m_dwFileSize < 0x115000 &&
							memcmp(objUnpackedFile.m_stSectionHeader[0].Name, "CODE", 4) == 0 && m_wAEPSec == 1 && 
							m_dwAEPUnmapped > 0xC0000)
						{
							dwStartOff = objUnpackedFile.m_dwFileSize - ICOREGEN_BUFF_SIZE;
							memset(m_pbyBuff, 0, m_dwNoOfBytes);
							if(objUnpackedFile.ReadBuffer(m_pbyBuff, dwStartOff, ICOREGEN_BUFF_SIZE, ICOREGEN_BUFF_SIZE/2, &m_dwNoOfBytes))
							{
								TCHAR szVirusName[MAX_PATH] = {0};
								TCHAR szSig_BRJ[] ={ _T("49726F6E*536F75726365*49726F6E*536F75726365*737570706F72744069726F6E2D736F757263652E6E6574")};
								TCHAR szSig_GEN[] ={ _T("496E7374616C6C*436F7265*496E7374616C6C*436F7265*7465616D40696E7374616C6C636F72652E636F6D")};
								CSemiPolyDBScn	polydbObj;

								polydbObj.LoadSigDBEx(szSig_BRJ, _T("InstallCore.BRJ"), TRUE);
								polydbObj.LoadSigDBEx(szSig_GEN, _T("InstallCore.GEN"), FALSE);

								if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
								{
									if(_tcslen(szVirusName) > 0)
									{
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
										iRetStatus = VIRUS_FILE_DELETE;
									}
								}
							}
						}
						objUnpackedFile.CloseFile();
					}
					DeleteFile(szTempFilePath);
				}
			}*/
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: UnPackUPXFile
	In Parameters	: LPTSTR szTempFilePath
	Out Parameters	: true if successfully unpack else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function unpacks the UPX file in %PROGTMP% dir. using  AuUPXUnpacker.dll
--------------------------------------------------------------------------------------*/
bool CTrojans::UnPackUPXFile(LPTSTR szTempFilePath)
{
	if(m_hUPXUnpacker == NULL)
	{
		m_hUPXUnpacker = LoadLibrary(_T("AuUPXUnpacker.dll"));
		if(m_hUPXUnpacker == NULL)
		{
			DWORD dwError = GetLastError();
			return false;
		}

		m_lpfnUnPackUPXFile = (LPFNUnPackUPXFile) GetProcAddress(m_hUPXUnpacker, "UnPackUPXFile");
		if(m_lpfnUnPackUPXFile  == NULL)
		{
			return false;
		}
	}

	GetTempFilePath(szTempFilePath);

	char szFilePath[MAX_PATH] = {0}, szUnpackFilePath[MAX_PATH] = {0};
	sprintf_s(szFilePath, MAX_PATH, "%S", m_pMaxPEFile->m_szFilePath);
	sprintf_s(szUnpackFilePath, MAX_PATH, "%S", szTempFilePath);

	DWORD dwtemp = *((DWORD *)m_pMaxPEFile->m_stSectionHeader[0].Name) & 0x00FFFFFF;
	const int BUFF_SIZE = 0x400;
	BYTE *bySrcBuff = new BYTE[BUFF_SIZE];
	if(!m_pMaxPEFile->ReadBuffer(bySrcBuff,m_pMaxPEFile->m_stSectionHeader[1].PointerToRawData-64, BUFF_SIZE, BUFF_SIZE))
	{
		delete []bySrcBuff;
		bySrcBuff = NULL;
		return false;
	}
	bool bCavity = false;
	DWORD dwboff;
	for(dwboff = 0; dwboff <= (BUFF_SIZE - 4); dwboff++)
	{
		if(bySrcBuff[dwboff] == BYTE(dwtemp) && memcmp((DWORD*)&bySrcBuff[dwboff], &dwtemp, sizeof(WORD) + sizeof(BYTE))==0x00)
		{
			if (dwboff <= 0 || dwboff > 0x30 && dwtemp!=0x21585055)
			{
				dwtemp = 0x21585055;
				dwboff = 0;
			}
			else if(dwboff <= 0 || dwboff > 0x30)
			{
				break;
			}
			else
			{
				break;
			}
		}
	}

	DWORD dwOffset = 0x00;
	bool bLZMA = false;
	if(dwboff <= 0 || dwboff > 0x30)
	{
		memset(bySrcBuff, 0, BUFF_SIZE);
		if(!m_pMaxPEFile->ReadBuffer(bySrcBuff, m_pMaxPEFile->m_dwAEPMapped, 0x40, 0x40))
		{
			delete []bySrcBuff;
			bySrcBuff = NULL;
			return false;
		}

		DWORD dwLength = 0, dwInstructionCountFound = 0;		
		char szInstruction[BUFF_SIZE] = {0x00};
		CEmulate objEmulate(m_pMaxPEFile);
		while(dwOffset < 0x30)
		{
			dwLength = objEmulate.DissassemBuffer((char*)&bySrcBuff[dwOffset], szInstruction);

			if(strstr(szInstruction, "MOV AL ,BYTE PTR [ESI]") && dwLength == 0x02)
			{
				break;
			}
			else if(strstr(szInstruction, "INC ESI") && dwLength == 0x01 && *(WORD *)&bySrcBuff[dwOffset + 0x01] == 0x5346)
			{
				bLZMA = true;
				break;
			}
			dwOffset+=dwLength;
		}
	}
	if(bySrcBuff)
	{
		delete []bySrcBuff;
		bySrcBuff = NULL;
	}

	if(!m_lpfnUnPackUPXFile(szFilePath, szUnpackFilePath, dwOffset, dwboff, bLZMA))
	{
		::DeleteFile(szTempFilePath);
		return false;
	}

	//if(!m_lpfnUnPackUPXFile(szFilePath, szUnpackFilePath))
	//{
	//	::DeleteFile(szTempFilePath);
	//	return false;
	//}

	WIN32_FILE_ATTRIBUTE_DATA FileInfo = {0};
	if(GetFileAttributesEx(szTempFilePath, GetFileExInfoStandard, &FileInfo))
	{
		if(MKQWORD(FileInfo.nFileSizeHigh, FileInfo.nFileSizeLow) > (ULONG64(m_pMaxPEFile->m_dwFileSize)))
		{
			return true;
		}
	}
	::DeleteFile(szTempFilePath);
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectGenomeDLL
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Genome.dll Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectGenomeDLL(void)
{
	int		iRetStatus = VIRUS_NOT_FOUND;

	if ((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}

	if (m_pbyBuff)
	{
		delete []m_pbyBuff; 
		m_pbyBuff = NULL;
	}
	const int GENOME_BUFF_SIZE	= 0x300;
	m_pbyBuff = new BYTE[GENOME_BUFF_SIZE];

	DWORD	dwExportTblRVA = 0x00, dwExportTblAddrs = 0x00, dwSize = 0x00;
	WORD	wInSec = 0x00;
	BYTE	bAEPBuff[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x0C, 0x01, 0x75, 0x05, 0xE8, 0x04, 0x4B, 0x00, 0x00};
	
	if(!GetBuffer(m_dwAEPMapped,0x50))
	{
		return iRetStatus;
	}
	if (memcmp(&m_pbyBuff[0x00],bAEPBuff,sizeof(bAEPBuff)) != 0x00)
	{
		return iRetStatus;
	}

	dwExportTblRVA = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x00].VirtualAddress;
	dwSize = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x00].Size;
	if (dwSize > GENOME_BUFF_SIZE)
	{
		dwSize = GENOME_BUFF_SIZE;
	}

	dwExportTblAddrs = Rva2FileOffsetEx(dwExportTblRVA,&wInSec); 
	if (OUT_OF_FILE == dwExportTblAddrs)
	{
		return iRetStatus;
	}

	BYTE	bExport[] = {0x53, 0x50, 0x49, 0x46, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x49, 
		0x6E, 0x73, 0x74, 0x61, 0x6C, 0x6C, 0x53, 0x50, 0x49, 0x00, 
		0x55, 0x6E, 0x69, 0x6E, 0x73, 0x74, 0x61, 0x6C, 0x6C, 0x53,
		0x50, 0x49, 0x00, 0x57, 0x53, 0x50, 0x53, 0x74, 0x61, 0x72, 
		0x74, 0x75, 0x70, 0x00};

	memset(m_pbyBuff,0x00,sizeof(m_pbyBuff));
	if(GetBuffer(dwExportTblAddrs,dwSize,dwSize))
	{
		for(DWORD i = 0; i < m_dwNoOfBytes; i++)
		{
			if(memcmp(&m_pbyBuff[i], bExport, sizeof(bExport)) == 0x00)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Worm.Genome.dll"));
				return VIRUS_FILE_DELETE; 
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAllaple
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Allaple Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectAllaple(void)
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	BYTE	bSecName[] = {0x72, 0x64, 0x61, 0x74, 0x61};
	
	if (m_wNoOfSections > 0x02 && m_wAEPSec == 0x00 && 
		(memcmp(m_pSectionHeader[0x01].Name,bSecName,sizeof(bSecName)) == 0x00 || 
		 memcmp(&m_pSectionHeader[0x01].Name[0x01],bSecName,sizeof(bSecName)) == 0x00))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int ALLAPLE_BUFF_SIZE	= 0x200;
		m_pbyBuff = new BYTE[ALLAPLE_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if (NULL == m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, ALLAPLE_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(!GetBuffer(m_dwAEPMapped, ALLAPLE_BUFF_SIZE, ALLAPLE_BUFF_SIZE))
		{
			return iRetStatus;
		}

		DWORD	dwLength = 0, dwOffSet = 0,	dwHits = 0x00;
		BOOL	bSmallMOV = FALSE;
		BYTE	B1 = 0, B2 = 0;
		t_disasm	da;

		m_dwInstCount = 0;
		
		while(dwOffSet < m_dwNoOfBytes || m_dwInstCount <= 50)
		{
			memset(&da, 0x00, sizeof(da));

			B1 = *((BYTE*)&m_pbyBuff[dwOffSet]);
			B2 = *((BYTE*)&m_pbyBuff[dwOffSet + 1]);

			//Skipping Some Instructions that couldn't be interpreted by Olly.
			if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
			{
				dwOffSet+= 0x03;
				continue;
			}
			if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
			{
				dwOffSet+= 0x02;
				continue;
			}
			
			dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN,0x400000, &da, DISASM_CODE);
			m_dwInstCount++;

			if(dwLength==0x08 && strstr(da.result, "MOV") != NULL && dwHits == 0x00)
			{
				dwHits++;
			}			
			else if(dwLength==0x04 && strstr(da.result, "MOV") != NULL && dwHits == 0x01)
			{
				dwHits++;
			}			
			else if(dwLength==0x02 && strstr(da.result, "MOV") != NULL && strstr(da.result, ",4") != NULL && dwHits >= 0x01)
			{
				bSmallMOV = TRUE;
			}
			else if(dwLength==0x04 && strstr(da.result, "ADD") != NULL && bSmallMOV == TRUE && dwHits >= 0x01)
			{
				dwHits++;
				bSmallMOV = FALSE;
			}
			if (dwHits >= 0x06)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Worm.Allaple"));
				return VIRUS_FILE_DELETE; 
			}
			dwOffSet += dwLength;
		}
	}
	return iRetStatus; 
}

/*-------------------------------------------------------------------------------------
	Function		: GetTempFilePath
	In Parameters	: LPTSTR szFileName (Product TMP dir path)
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function creates directory in <%ProcDir%>\\TempData with random name
--------------------------------------------------------------------------------------*/
void CTrojans::GetTempFilePath(LPTSTR szFileName)
{
	TCHAR szTempPath[MAX_PATH] = {0};
	// Get temp folder path where to extrat the files
	if(!GetModuleFileName(NULL, szTempPath, MAX_PATH))
	{
	}

	WCHAR *cExtPtr = wcsrchr(szTempPath, '\\');
	*cExtPtr = '\0';

	_tcsncat_s(szTempPath, MAX_PATH, _T("\\TempData"), 10);

	if(FALSE == PathIsDirectory(szTempPath))
	{
		CreateDirectory(szTempPath, 0);
	}

	// Get the file name to create temp file path
	LPCTSTR	szOnlyFileName = m_pMaxPEFile->m_szFilePath? _tcsrchr(m_pMaxPEFile->m_szFilePath, _T('\\')): NULL;

	_stprintf_s(szFileName, MAX_PATH, _T("%s%s_%08x_%05d_%d.tmp"), szTempPath, szOnlyFileName, GetTickCount(), GetCurrentThreadId(), rand());		
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSwizzor
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Swizzor Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectSwizzor()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL || m_wAEPSec != 0x00 ||		
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].VirtualAddress != 0x00)
	{
		return iRetStatus;
	}
	if(m_pbyBuff)
	{
		delete []m_pbyBuff; 
		m_pbyBuff = NULL;
	}
	const int MAX_SWIZZOR_BUFF_SIZE = 0x300;
	m_pbyBuff = new BYTE[MAX_SWIZZOR_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!GetBuffer(m_dwAEPMapped, 0x20, 0x10))
	{
		return iRetStatus;
	}

	if(m_pbyBuff[0x00] == 0xE8 && m_pbyBuff[5] == 0xE9 && m_pbyBuff[0x0A] != 0xCC)
	{
		DWORD dwReadOfdset = m_dwAEPMapped + 0x05 + 0x05 + *((DWORD*)&m_pbyBuff[6]);
		
		memset(m_pbyBuff, 0x00, MAX_SWIZZOR_BUFF_SIZE + MAX_INSTRUCTION_LEN);	
		if(!GetBuffer(dwReadOfdset, 0x300, 0x200))
		{
			return iRetStatus;
		}
		if (m_pbyBuff[0x00] != 0x6A)
		{
			return iRetStatus;
		}

		const BYTE bCallWithImageBase[] = {0x68, 0x00, 0x00, 0x40, 0x00, 0xE8};
		DWORD dwCallOffSet = 0x00;
		for(DWORD i = 0; i < m_dwNoOfBytes - sizeof(bCallWithImageBase); i++)
		{
			if(memcmp(&m_pbyBuff[i], bCallWithImageBase, sizeof(bCallWithImageBase)) == 0x00)
			{
				dwCallOffSet = dwReadOfdset + i + sizeof(bCallWithImageBase) + *((DWORD*)&m_pbyBuff[i + 0x06]) + sizeof(DWORD);
				break;
			}
		}
		if (dwCallOffSet == 0x00 || dwCallOffSet > m_pMaxPEFile->m_dwFileSize)
		{
			return iRetStatus;
		}

		if(!GetBuffer(dwCallOffSet, 0x300, 0x200))
		{
			return iRetStatus;
		}

		t_disasm	da = {0};
		DWORD		dwLength = 0x00, dwOffset = 0x00;
		int			iCount = 0;
		bool		bCall = false;

		m_dwInstCount = 0x00;
		while(dwOffset < m_dwNoOfBytes && m_dwInstCount <= 15)
		{
			dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, m_dwImageBase, &da, DISASM_CODE);
			if(dwLength > m_dwNoOfBytes - dwOffset)
			{
				break;
			}
			m_dwInstCount++;

			if (bCall == true && iCount >= 0x02)
			{
				if (iCount >= 0x02 && dwLength == 0x03 && strstr(da.result, "ADD ESP"))
				{
					iCount++;
					break;
				}
			}

			if (iCount >= 0x02 && dwLength == 0x05 && strstr(da.result, "CALL"))
			{				
				bCall = true;
			}
			else
			{
				bCall = false;
			}

			if(iCount == 0x01 && dwLength == 0x06 && strstr(da.result, "SUB ESP"))
			{
				iCount++;
			}
			else if(iCount == 0x00 && dwLength == 0x01 && strstr(da.result, "PUSH EBP"))
			{
				iCount++;
			}
			dwOffset += dwLength;
		}
		if (iCount == 0x03)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Trojan.Swizzor.J"));
			iRetStatus = VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanMonderA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Monder Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectTrojanMonderA()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_wAEPSec == 0) && m_wNoOfSections == 4 &&
		((m_pSectionHeader[m_wAEPSec].Characteristics & 0x60000020) == 0x60000020) &&
		((m_pSectionHeader[2].Characteristics & 0x40000040) == 0x40000040)&& 
		(memcmp(m_pSectionHeader[2].Name,".rdata",6) == 0)&& (m_pSectionHeader[2].SizeOfRawData <= 0x1000))
	{
		DWORD dwIMportTblRVA = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x01].VirtualAddress;
		if(2 != m_pMaxPEFile->Rva2FileOffset(dwIMportTblRVA, &dwIMportTblRVA))
		{
			return iRetStatus;
		}
		
		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int MONDERA_BUFF_SIZE		= 0x2000;
		m_pbyBuff = new BYTE[MONDERA_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, MONDERA_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(!(GetBuffer(m_dwAEPMapped, MONDERA_BUFF_SIZE, MONDERA_BUFF_SIZE)))
		{
			return iRetStatus;	
		}

		t_disasm da = {0x00};
		DWORD dwOffset = 0;

		while(dwOffset < MONDERA_BUFF_SIZE)
		{
			DWORD dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwLength > (MONDERA_BUFF_SIZE - dwOffset))
			{
				return iRetStatus;
			}
			if(dwLength == 0x02 && (strstr(da.result,"CALL EAX") || strstr(da.result,"JMP EAX")))
			{
				static int iCount = 0;
				if(iCount > 1 && strstr(da.result, "JMP EAX"))
				{						
					int iStart = dwOffset;
					BYTE bySig[] = {0x4D, 0x02, 0x13, 0x50, 0x49, 0x4E, 0x6F, 0x7C};
					for(int iStart = 0; iStart < MONDERA_BUFF_SIZE - sizeof(bySig); iStart++)
					{
						if((memcmp(&m_pbyBuff[iStart], bySig, sizeof(bySig)) == 0))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Monder.GEN"));
							return VIRUS_FILE_DELETE;
						}
					}					
				}
				iCount++;				
			}
			dwOffset +=dwLength;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPackedPolyCrypt
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of PolyCrypt and Lop Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectPackedPolyCrypt()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000000) == 0xE0000000) && 
		((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000000) == 0xE0000000) && 
		((m_dwAEPUnmapped % 4) == 0 || (m_wAEPSec == m_wNoOfSections - 1)))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int POLYCRYPT_D_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[POLYCRYPT_D_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, POLYCRYPT_D_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, POLYCRYPT_D_BUFF_SIZE, POLYCRYPT_D_BUFF_SIZE))
		{
			DWORD dwLength = 0, dwInstrCnt = 0, dwOffset = 0;
			t_disasm	da;			
			BYTE CHECK1[] = {0xE8,0x00,0x00,0x00,0x00};
			BYTE CHECK2[] = {0x5D,0x55,0xBF,0x00,0x10,0x00,0x00};	

			if((memcmp(&m_pbyBuff[0x00], CHECK1, sizeof(CHECK1)) == 0))
			{
				DWORD dwMovOffset = 0, dwJmpOffset = 0;
				while(dwOffset < 0x20)
				{
					memset(&da, 0x00, sizeof(struct t_disasm));
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwLength > 0x20 - dwOffset)
					{
						break;
					}
					else if(dwLength == 5 && dwInstrCnt == 0 && strstr(da.result,"MOV E"))
					{
						dwInstrCnt++;
						dwMovOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1];
					}
					else if(dwLength == 1 && (dwInstrCnt == 0 || dwInstrCnt == 1) && strstr(da.result,"POP E"))
					{
						dwInstrCnt++;
						dwJmpOffset = m_dwAEPUnmapped + 5;
					}
					else if(dwLength == 6 && dwInstrCnt == 1 && strstr(da.result,"ADD E"))
					{
						dwInstrCnt ++;
						dwJmpOffset = dwJmpOffset + *(DWORD *)&m_pbyBuff[dwOffset + 2];
					}
					else if(dwLength == 2 && dwInstrCnt== 2 && strstr(da.result,"ADD E"))
					{
						dwInstrCnt ++;
						dwJmpOffset = dwMovOffset + dwJmpOffset;
					}
					else if(dwLength == 2 && (dwInstrCnt == 2 || dwInstrCnt == 3) && strstr(da.result,"JMP E"))
					{
						break;
					}
					dwOffset += dwLength;
				}			
				if((dwJmpOffset > m_pSectionHeader[m_wNoOfSections -1].VirtualAddress) && (dwJmpOffset < (m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)) && dwInstrCnt >= 2)
				{
					if(OUT_OF_FILE != (m_pMaxPEFile->Rva2FileOffset(dwJmpOffset,&dwJmpOffset)))
					{
						if(GetBuffer(dwJmpOffset, POLYCRYPT_D_BUFF_SIZE, POLYCRYPT_D_BUFF_SIZE))
						{
							BYTE POLYCRYPT_SIG[] = {0x33,0xC0,0x8A,0x17,0x32,0x14,0x18,0x88,0x17,0x40,0x83,0xF8,0x05,0x7C,0x02,0x33,0xC0,0x47,0xE2,0xEE};
							if((m_pbyBuff[0] == 0xE8 || m_pbyBuff[0x5] == 0x58) && (memcmp(&m_pbyBuff[0x2F], POLYCRYPT_SIG, sizeof(POLYCRYPT_SIG)) == 0)) // Added OR condition m_pbyBuff[0x5] == 0x58
							{
								if(m_dwAEPUnmapped == 0x1074 && m_dwAEPUnmapped == m_dwAEPUnmapped)
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:AdWare.Win32.Lop.bb"));
								else 
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Packed.PolyCrypt.gen"));
								iRetStatus = VIRUS_FILE_DELETE;
							}								
						}
					}
				}
			}
			else if((memcmp(&m_pbyBuff[0x00], CHECK2, sizeof(CHECK2)) == 0))
			{
				DWORD dwNegCallOff = 0;
				while(dwOffset < POLYCRYPT_D_BUFF_SIZE)
				{
					memset(&da, 0x00, sizeof(struct t_disasm));
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwLength > POLYCRYPT_D_BUFF_SIZE - dwOffset)
					{
						break;
					}
					else if(dwLength == 5 && strstr(da.result,"CALL") && (*(DWORD *)&m_pbyBuff[dwOffset + 1] > 0xFFFF0000))
					{
						dwNegCallOff = (*(DWORD *)&m_pbyBuff[dwOffset + 1] + m_dwAEPMapped + dwOffset + 5);
						if(dwNegCallOff > (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
						{
							return iRetStatus;
						}
						if(GetBuffer(dwNegCallOff + 0xD,0x50,0x50))
						{
							BYTE packed_sig1[] = {0x8B,0xC2,0xC1,0xE0,0x04,0xBF,0x10,0x00,0x00,0x00,0x8B,0xEB,0xC1,0xE5,0x04,0x2B,0xCD,0x8B,0x6E,
												  0x08,0x33,0xEB,0x2B,0xCD,0x8B,0xEB,0xC1,0xED,0x05,0x33,0xE8,0x2B,0xCD,0x2B,0x4E,
												  0x0C,0x8B,0xE9,0xC1,0xE5,0x04,0x2B,0xDD,0x8B,0x2E,0x33,0xE9,0x2B,0xDD,0x8B,0xE9,
												  0xC1,0xED,0x05,0x33,0xE8,0x2B,0xDD,0x2B,0x5E,0x04,0x2B,0xC2,0x4F,0x75,0xC8,0x5F,
							                      0x5D,0x89,0x1F,0x89,0x4F,0x04,0x59,0xC3};
							if(memcmp(&m_pbyBuff[0x00],packed_sig1,sizeof(packed_sig1)) == 0)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Packed.PolyCrypt.gen"));
								iRetStatus = VIRUS_FILE_DELETE;
							}
						}
						break;
					}
					dwOffset += dwLength;
				}
			}			
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectKlone
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Klone Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectKlone()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_wNoOfSections > 3) && (memcmp(m_pSectionHeader[m_wNoOfSections - 2].Name, ".vmp", 4) == 0) && 
		(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".reloc", 6) == 0) && 
		(m_pSectionHeader[m_wNoOfSections - 1].Characteristics == 0x42000040) &&
		((m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x400) || m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x214))
	{
		BYTE m_byKloneBuff[0x30 + MAX_INSTRUCTION_LEN] = {0};
		if(m_pMaxPEFile->ReadBuffer(m_byKloneBuff, m_dwAEPMapped + 6, 0x04, 0x04))
		{
			DWORD dwRVAOffset = (*(DWORD *)&m_byKloneBuff[0]) + m_dwAEPUnmapped + 10, dwOffset = 0;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwRVAOffset, &dwOffset))
			{
				if(m_pMaxPEFile->ReadBuffer(&m_byKloneBuff[0], dwOffset, 0x30, 0x30))
				{
					if(m_byKloneBuff[0] == 0x68 && m_byKloneBuff[5] == 0xE9)
					{
						dwOffset = *(DWORD *)&m_byKloneBuff[6] + dwRVAOffset + 10;
						if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOffset, &dwOffset))
						{
							m_pMaxPEFile->ReadBuffer(&m_byKloneBuff[0], dwOffset, 0x30, 0x30);
						}
					}

					DWORD dwLength = 0;
					t_disasm da;

					dwOffset = m_dwInstCount = 0;
					while(dwOffset < 0x20)
					{
						dwLength = m_objMaxDisassem.Disasm((char *)&m_byKloneBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
						if(dwLength > dwOffset && strstr(da.result, "PUSH"))
						{
							m_dwInstCount++;
						}
						else if(m_dwInstCount == 1 && dwLength == 1 && strstr(da.result, "PUSH"))
						{
							m_dwInstCount++;
						}
						else if(m_dwInstCount == 2 && dwLength == 1 && strstr(da.result, "PUSH"))
						{
							m_dwInstCount++;
							dwOffset += dwLength + 6;
							continue;
						}
						else if(m_dwInstCount == 3 && dwLength == 5 && strstr(da.result, "PUSH 0"))
						{
							m_dwInstCount++;
						}
						else if(m_dwInstCount == 4 && dwLength == 4 && strstr(da.result, "MOV E"))
						{
							m_dwInstCount++;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Trojan.Klone.Af"));
							return VIRUS_FILE_DELETE;
						}
						dwOffset += dwLength;
					}
				}
			}				
		}
	}
	if((memcmp(m_pSectionHeader[0].Name, ".text", 5) == 0) && (m_pSectionHeader[0].SizeOfRawData == 0x00) && 
		((memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".idata", 6) == 0) || (memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".edata", 6) == 0) ||
		(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".rdata", 6) == 0)) && (m_pSectionHeader[m_wNoOfSections - 1].Characteristics == 0xE0000060))
	{
		BYTE m_byKloneBuff[0x30] = {0};
		if(m_pMaxPEFile->ReadBuffer(&m_byKloneBuff[0], m_dwAEPMapped + 7, 0x04, 0x04))
		{
			DWORD dwOffset = 0, dwRVAOffset = *(DWORD *)&m_byKloneBuff[0] + m_dwAEPUnmapped + 11;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwRVAOffset, &dwOffset))
			{
				if(m_pMaxPEFile->ReadBuffer(&m_byKloneBuff[0], dwOffset, 0x0A, 0x0A))
				{
					if(0xE9 == m_byKloneBuff[5])
					{
						dwOffset = *(DWORD *)&m_byKloneBuff[0x06] + dwRVAOffset + 10;
						if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOffset, &dwOffset))
						{
							if(m_pMaxPEFile->ReadBuffer(&m_byKloneBuff[0], dwOffset, 0x05, 0x05))
							{
								BYTE bySig[] = {0x60, 0x9C, 0xFC};
								if(memcmp(bySig, &m_byKloneBuff[0], sizeof(bySig)) == 0)
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Trojan.Klone.Bp"));
									return VIRUS_FILE_DELETE;	
								}
							}
						}
					}
				}
			}
		}
	}
	if((m_dwAEPMapped == 0x050F) && (m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x0400) )
	{	
		BYTE m_byKloneBuff[0x20];
		BYTE bySig[] = {0x53,0x0C,0x45,0x52,0x52,0x4F,0x52,0x21,0x00,0x43,0x6F,0x72,0x72,0x75,0x70,0x74,0x20,0x44,0x61,0x74,0x61,0x21, 0x00, 0x6A};
		if(m_pMaxPEFile->ReadBuffer(&m_byKloneBuff[0], m_dwAEPMapped - 0x17, 0x20, 0x20))
		{
			if(memcmp(&m_byKloneBuff[0], bySig, sizeof(bySig)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Trojan.Klone.ay"));
				iRetStatus = VIRUS_FILE_DELETE;
			}
		}
	}
	/*----------------------------------------------------------------
	Analyst     : Sandeep
	Type        : Trojan (Packed by Unknown packer)
	Name        : Packed.W32.Klone.ao
	Description : A : Its have rootkit behaviour
	B : Running backdoor process
	------------------------------------------------------------------*/

	//1 : First Two Sections should have same name (in this case blank name)
	//2 : File should not be DLL
	if((memcmp(m_pSectionHeader[0].Name, m_pSectionHeader[1].Name, 8) == 0) && 
		((m_pSectionHeader[0].Misc.VirtualSize == 0x9000) || (m_pSectionHeader[0].Misc.VirtualSize == 0xA000))&&
		(m_pSectionHeader[1].Misc.VirtualSize == 0x2000) &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int BuffSize = 0x1500;
		m_pbyBuff = new BYTE[BuffSize];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}

		DWORD dwOffset = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x01].VirtualAddress;
		if(dwOffset == 0x00)
		{
			return iRetStatus;
		}
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwOffset, &dwOffset))
		{
			return iRetStatus;
		}
		if(!GetBuffer(dwOffset + 0x50, BuffSize, BuffSize))
		{
			return iRetStatus;
		}

		//Strin5gXu.$.P...3*D.....+....Y..TO.bjec.t*x..p9.l.h"d#.`.\.X.Tr (Taken as common Part)
		TCHAR			szSig[] = {_T("537472696E3567587519240150E6008E33*44D4C888A8092B81BC1300591907544F00626A65630374*78E4B67039186C1C682264230060915CC858E45472")};	
		CSemiPolyDBScn	polydbObj;
		TCHAR			szVirusName[MAX_PATH] = {0};

		polydbObj.LoadSigDBEx(szSig, _T("Poly.Trojan.Klone.ao"), FALSE);
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], BuffSize, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAgentBCN
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Agent.BCN Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectAgentBCN()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wNoOfSections >= 2) && (m_pSectionHeader[0].SizeOfRawData >= 0x6000) && (m_pSectionHeader[m_wAEPSec].Characteristics & 0x60000000) == 0x60000000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int BUFF_SIZE = 0x1000;
		m_pbyBuff = new BYTE[BUFF_SIZE];

		DWORD dwBuffSize = 0, dwBytesToRead = 0x200;
		if(!GetBuffer(m_pSectionHeader[0].PointerToRawData, dwBytesToRead, dwBytesToRead))
		{			
			return iRetStatus;		
		}

		dwBuffSize += dwBytesToRead;

		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBuffSize], m_pSectionHeader[0].PointerToRawData + 0x400, dwBytesToRead, dwBytesToRead))
		{			
			return iRetStatus;		
		}

		dwBuffSize += dwBytesToRead;

		if(m_dwAEPMapped <= m_pMaxPEFile->m_dwFileSize)
		{ 
			dwBytesToRead += 0x200;
			if(m_pMaxPEFile->m_dwFileSize - m_dwAEPMapped < 0x400)
			{
				dwBytesToRead = m_pMaxPEFile->m_dwFileSize - m_dwAEPMapped;
			}
			if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBuffSize], m_dwAEPMapped, dwBytesToRead, dwBytesToRead))
			{			
				return iRetStatus;		
			}
			dwBuffSize += dwBytesToRead;
			BYTE pbyBuff[0x8]={0};
			if(!m_pMaxPEFile->ReadBuffer(pbyBuff, 0x1C, 0x8, 0x8))
			{
				return iRetStatus;	
			}
			if(*(DWORD *)&pbyBuff[0x0]!=0x0 && *(DWORD *)&pbyBuff[0x04]!=0x0)
			{
				if( m_pMaxPEFile->m_dwFileSize > 0x14b0 + dwBytesToRead + dwBytesToRead )
				{
					if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBuffSize], 0x14b0, (2*dwBytesToRead), (2*dwBytesToRead)))
					{			
						return iRetStatus;		
					}
					dwBuffSize += dwBytesToRead;
				}
			}
		}

		TCHAR AGENT_SIG1[] = {_T("3C7600004E760000707600007E76000090760000A2760000AE76*558BEC*8BF08A063C2275148A46014684C074043C2275F4803E22750D46EB0A3C207E06*46803E207FFA8A0684C074043C207EE98365E8008D45BC50FF150C104000E85D00000068241040006820104000E834000000F645E80159597406")};
		TCHAR AGENT_SIG2[] = {_T("33C040C36A286870204000E87402000033FF57FF15*395045000075120FB741183D0B010000741F3D0B02000074*EECE6E2C41862EE741D3F3EEA4F7E9912683B4E93782F9FFC4820931052E1DA7DACF6E22FE7FEBED1DCA31760E590D6385A5A750*0D6385A5A750C73AC6EAEC28AFDD25D87D0F6F8E4EC4C057AD425F271DF0B239C2*4DD4DB3E99B9C10DAB07F8A50FA17BB0BB7B4850362139AC5D101A3576*7B70AB358E3D2EB50608A0FAA03346718BE79EE825B6DFEEAA4F5BE0CF227945")};
		TCHAR AGENT_SIG3[] = {_T("4E304EC55B27F6F6EFAEF6F6F634F6F6D0F3F65A315F5666F6F8E224*6E486B5948654E464F4A415D48454F4E6C4A4F5B594B4B*6D49594A356B354B485941E9BC52372D411B69E578595A49477BE648C640BC63*694E404F5D5857202C005849ED454A4849E961443F")};

		CSemiPolyDBScn polydbObj;
		polydbObj.LoadSigDBEx(AGENT_SIG1, _T("Poly.Trojan.Agent.BCN"), TRUE);
		polydbObj.LoadSigDBEx(AGENT_SIG2, _T("Poly.Trojan.Agent.BCN"), TRUE);
		polydbObj.LoadSigDBEx(AGENT_SIG3, _T("Poly.Trojan.Agent.BCN"), FALSE);

		TCHAR szVirusName[MAX_PATH] = {0};
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], dwBuffSize, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName)>0)
			{
				iRetStatus = VIRUS_FILE_DELETE;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectBlackA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Black.A Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectBlackA()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(m_wAEPSec >= 3 && (m_dwAEPUnmapped %0x100) == 0x14 && ((m_pSectionHeader[m_wAEPSec].Characteristics & 0xC0000040) == 0xC0000040) &&
		(memcmp(m_pSectionHeader[0].Name, "   ", 3) == 0) && (memcmp(m_pSectionHeader[1].Name, ".rsrc", 5) == 0) && (memcmp(m_pSectionHeader[2].Name, ".idata", 6) == 0))		
	{
		const int BLACKA_BUFF_SIZE = 0x25;
		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[BLACKA_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, BLACKA_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		
		if(!(GetBuffer(m_dwAEPMapped, BLACKA_BUFF_SIZE, BLACKA_BUFF_SIZE)))
		{
			return iRetStatus;	
		}
		if((m_pbyBuff[0x00] == 0xB8) && (m_pbyBuff[0x05] == 0x60) && (m_pbyBuff[0x06] == 0x0B) && (m_pbyBuff[0x0A] == 0xE8) && 
			(m_pbyBuff[0xF] == 0x58) && (m_pbyBuff[0x10] == 0x05) && (m_pbyBuff[0x15] == 0x80) && (m_pbyBuff[0x18] == 0x75) && (m_pbyBuff[0x1A] == 0x61))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Black.A"));
			iRetStatus = VIRUS_FILE_DELETE;
		}
		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSmartFortress
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of SmartFortress Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectSmartFortress()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == 0 && ((m_wNoOfSections == 3) ||(m_wNoOfSections == 4) ||(m_wNoOfSections == 5)) && ((m_pSectionHeader[m_wAEPSec].Characteristics & 0x60000020) == 0x60000020))
	{
		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int SMARTFORTRESS_BUFF = 0x100;
		m_pbyBuff = new BYTE[SMARTFORTRESS_BUFF + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, SMARTFORTRESS_BUFF + MAX_INSTRUCTION_LEN);

		if(!GetBuffer(m_dwAEPMapped, SMARTFORTRESS_BUFF, SMARTFORTRESS_BUFF))
		{
			return iRetStatus;	
		}
		//****	For "Trojan.SmartFortress.B" ****//
		if((m_pMaxPEFile->m_stPEHeader.ImageBase == 0x410000) && m_dwAEPUnmapped == m_dwAEPMapped && 
			((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0x40000040) == 0x40000040) &&
			(m_pbyBuff[0x00] == 0x6A) && (m_pbyBuff[0x01] == 0x60) && (m_pbyBuff[0x02] == 0x68) && 
			(m_pbyBuff[0x07] == 0xE8) && (m_pbyBuff[0x0C] == 0xBF) && (m_pbyBuff[0x13] == 0xE8) && 
			(m_pbyBuff[0x1F] == 0x56) && (m_pbyBuff[0x20] == 0xFF) && (m_pbyBuff[0x21] == 0x15))
		{
			const BYTE bySig1[] = {0x66, 0x81, 0x38, 0x4D, 0x5A, 0x75, 0x1F, 0x8B, 0x48, 0x3C, 0x03, 0xC8, 0x81, 0x39, 0x50, 0x45, 0x00, 0x00, 0x75, 0x12, 0x0F};
			const BYTE bySig2[] = {0x76, 0xF2, 0x33, 0xC0, 0x39, 0xB1, 0xF8, 0x00, 0x00, 0x00, 0xEB, 0x0E, 0x83, 0x79, 0x74, 0x0E, 0x76, 0xE2, 0x33, 0xC0, 0x39};

			for(DWORD dwOffset = 0; dwOffset < (SMARTFORTRESS_BUFF - sizeof(bySig1)); dwOffset++)
			{
				if((memcmp(&m_pbyBuff[dwOffset], bySig1, sizeof(bySig1)) == 0))
				{
					for(dwOffset; dwOffset < (SMARTFORTRESS_BUFF - sizeof(bySig1)); dwOffset++)
					{
						if(memcmp(&m_pbyBuff[dwOffset], bySig2, sizeof(bySig2)) == 0)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.SmartFortress.B"));
							return VIRUS_FILE_DELETE;							
						}
					}					
				}
			}
		}

		//********* Trojan.SmartFortress.A *******//
		const int SMARTFORTRESS_BUFF_NEW = SMARTFORTRESS_BUFF - 0x0B0;
		t_disasm da = {0x00};
		DWORD dwOffset = 0, dwCount1 = 0, dwCount2 = 0, dwDllOffset = 0, dwDLLSec = 0;
		while(dwOffset < SMARTFORTRESS_BUFF_NEW)
		{
			DWORD dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwLength > (SMARTFORTRESS_BUFF - dwOffset))
			{
				return iRetStatus;
			}				
			if((dwLength == 0x05 && (strstr(da.result, "XOR E") || strstr(da.result, "ADC EAX") || strstr(da.result,"OR EAX") || strstr(da.result,"AND EAX") || strstr(da.result,"SUB EAX"))))  
			{
				dwDllOffset = da.immconst;
				dwDLLSec = m_pMaxPEFile->Rva2FileOffset(dwDllOffset - m_dwImageBase, &dwDllOffset);
				break;
			}
			else if((dwLength == 0x07 && strstr(da.result, "OR DWORD")) ||
				(dwLength == 0x05 && strstr(da.result, "PUSH ")))
			{
				dwDllOffset = da.immconst;
				dwDLLSec = m_pMaxPEFile->Rva2FileOffset(dwDllOffset - m_dwImageBase, &dwDllOffset);
				dwDllOffset = dwDllOffset - 0x15;
				break;
			}
			else if(((dwLength == 0x07 ||dwLength == 0x06)&& ((strstr(da.result, "LEA EAX")) || (strstr(da.result, "LEA ECX")))))
			{
				dwDllOffset = da.adrconst + da.indexed;
				dwDLLSec = m_pMaxPEFile->Rva2FileOffset(dwDllOffset - m_dwImageBase, &dwDllOffset);
				break;
			}
			else if(dwLength == 0x06 && strstr(da.result, "DEC DWORD" ))
			{
				dwDllOffset = da.adrconst;
				dwDLLSec = m_pMaxPEFile->Rva2FileOffset(dwDllOffset - m_dwImageBase, &dwDllOffset);
				dwDllOffset = dwDllOffset - 0x15;
				break;
			}
			dwOffset +=dwLength;
		}

		if(!((dwDLLSec == 2) || (dwDLLSec == 1)))
		{
			return iRetStatus;	
		}

		memset(m_pbyBuff, 0, SMARTFORTRESS_BUFF);
		if(!(GetBuffer(dwDllOffset, SMARTFORTRESS_BUFF_NEW , SMARTFORTRESS_BUFF_NEW )))
		{
			return iRetStatus;	
		}

		const BYTE bySig1[] = {0x2E, 0x2B, 0x6C, 0x6C};//.+ll
		const BYTE bySig2[] = {0x2E, 0x64, 0x2B, 0x6C};//.d+l
		const BYTE bySig3[] = {0x2E, 0x64, 0x6C, 0x2B};//.dl+
		const BYTE bySig4[] = {0x2E, 0x64, 0x6D, 0x6C};//.dml
		const BYTE bySig5[] = {0x6B, 0x62, 0x64, 0x73, 0x67, 0x2E, 0x64, 0x6C, 0x6C};	//----->kbdsg.dll
		const BYTE bySig6[] = {0x7E, 0x64, 0x6C, 0x6C};//"dll
		const BYTE bySig7[] = {0x2D, 0x64, 0x6C, 0x6C};//-dll
		const BYTE bySig8[] = {0x2E, 0x64, 0x6C, 0x6D};//.dlm (P2)
		const BYTE bySig9[] = {0x2F, 0x64, 0x6C, 0x6C};//	/dll----pickbuffer -10 or15
		const BYTE bySig10[] = {0x7E, 0x64, 0x6C, 0x6C};//~dll
		const BYTE bySig11[] = {0x00, 0x7E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C};//.~.d.l.l
		const BYTE bySig12[] = {0x7E, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65};//cipher~exe
		const BYTE bySig13[] = {0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6C, 0x00};//.lll
		const BYTE bySig14[] = {0x2A, 0x6F, 0x63, 0x78};//autoconv~exe
		const BYTE bySig15[] = {0x2A, 0x64, 0x6C, 0x6C};//*dll
		const BYTE bySig16[] = {0x2A, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C};//.*.d.l.l
		const BYTE bySig17[] = {0x2B, 0x64, 0x6C, 0x6C};//+dll
		const BYTE bySig18[] = {0x6C, 0x00, 0x6F, 0x00, 0x61, 0x00, 0x72, 0x00, 0x63, 0x00, 0x6D, 0x00, 0x63, 0x00, 0x66, 0x00, 0x67, 0x00, 0x33, 0x00, 0x32};
		const BYTE bySig19[] = {0x00, 0x74, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x70, 0x00, 0x75, 0x00, 0x79, 0x00, 0x74, 0x00, 0x78, 0x00, 0x63, 0x00, 0x61};
		const BYTE bySig20[] = {0x64, 0x00, 0x61, 0x00, 0x74, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x70, 0x00, 0x69, 0x00, 0x73, 0x00};

		for(DWORD dwOffset = 0; dwOffset <= (SMARTFORTRESS_BUFF_NEW - sizeof(bySig18)); dwOffset++)
		{
			if((memcmp(&m_pbyBuff[dwOffset], bySig1, sizeof(bySig1)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig2, sizeof(bySig2)) == 0) || 
				(memcmp(&m_pbyBuff[dwOffset], bySig3, sizeof(bySig3)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig4, sizeof(bySig4)) == 0) ||
				(memcmp(&m_pbyBuff[dwOffset], bySig5, sizeof(bySig5)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig6, sizeof(bySig6)) == 0) ||
				(memcmp(&m_pbyBuff[dwOffset], bySig7, sizeof(bySig7)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig8, sizeof(bySig8)) == 0) ||
				(memcmp(&m_pbyBuff[dwOffset], bySig9, sizeof(bySig9)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig10, sizeof(bySig10)) == 0) ||
				(memcmp(&m_pbyBuff[dwOffset], bySig11, sizeof(bySig11)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig12, sizeof(bySig12)) == 0) ||
				(memcmp(&m_pbyBuff[dwOffset], bySig13, sizeof(bySig13)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig14, sizeof(bySig14)) == 0) ||
				(memcmp(&m_pbyBuff[dwOffset], bySig15, sizeof(bySig15)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig16, sizeof(bySig16)) == 0) ||
				(memcmp(&m_pbyBuff[dwOffset], bySig17, sizeof(bySig17)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig18, sizeof(bySig18)) == 0) ||
				(memcmp(&m_pbyBuff[dwOffset], bySig19, sizeof(bySig19)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig20, sizeof(bySig20)) == 0))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.SmartFortress.A"));
				return VIRUS_FILE_DELETE;
			}			
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDCodecPackSJT
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Shreyas + Rushikesh + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of CodecPack Family
					  .SJT,.AMPN,.AMYC,.AMZE,.APCZ,.AHZB,.AOPL, etc
--------------------------------------------------------------------------------------*/
int CTrojans::DetectDCodecPackSJT()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	//1 : File Should be either fack UPX packed
	//2 : File Should be delphi file
	if((m_wAEPSec == 0x00) && 
		(((m_wNoOfSections == 3) && (memcmp(m_pSectionHeader[0].Name,"UPX0",4) == 0) && 
		((m_pSectionHeader[0].SizeOfRawData >= 0xA000))) ||
		((m_wNoOfSections >= 0x06 && m_wNoOfSections <= 8) && (memcmp(m_pSectionHeader[1].Name, "DATA", 0x04) == 0) && 
		((m_pSectionHeader[1].SizeOfRawData >= 0xF000 && m_pSectionHeader[0].SizeOfRawData <= 0x9000) ||
		(m_pSectionHeader[1].SizeOfRawData >= 0xC00 && m_pSectionHeader[1].SizeOfRawData <= 0x2000 && m_pSectionHeader[0].SizeOfRawData >= 0x1A000) ||
		(m_pSectionHeader[1].SizeOfRawData >= 0xA000 && m_pSectionHeader[1].SizeOfRawData <= 0xB000  && (m_dwAEPUnmapped % 0x10 != 0x00) /*&& m_pSectionHeader[0].SizeOfRawData == 0xEA00*/) ||
		(m_pSectionHeader[1].SizeOfRawData >= 0x17000 && m_pSectionHeader[1].SizeOfRawData <= 0x19000 && 
		 m_pSectionHeader[0].SizeOfRawData >= 0x1D000 && m_pSectionHeader[0].SizeOfRawData <= 0x1E000) ||
		(m_pSectionHeader[0].SizeOfRawData == 0xA200 && (m_dwAEPUnmapped == 0x3840 || m_dwAEPUnmapped == 0x384C)) ||
		(m_pSectionHeader[0].SizeOfRawData == 0x9C00 && (m_dwAEPUnmapped == 0x38D0 || m_dwAEPUnmapped == 0x38C0)) ||
		((m_pSectionHeader[0].SizeOfRawData == 0xA600 || m_pSectionHeader[0].SizeOfRawData == 0x3000 || m_pSectionHeader[0].SizeOfRawData == 0xA000) && 
		(m_dwAEPUnmapped % 0x10 != 0x00))))))
	{
		if(m_pbyBuff)
		{
			delete m_pbyBuff;
		}
		/*
		Increase Buffer size,
		older SJT_BUFF_SIZE = 0x1000
		New SJT_BUFF_SIZE = 0x2D00
		*/
		m_pbyBuff = new BYTE[SJT_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(DetectCodecPackSJT1() || DetectCodecPackSJT2() || DetectCodecPackSJT3())
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.CodecPack.Gen"));
			iRetStatus = VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDCodecPackSJT1
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Shreyas + Rushikesh + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of CodecPack Family
--------------------------------------------------------------------------------------*/
bool CTrojans::DetectCodecPackSJT1()
{
	bool	bRet = false;

	memset(m_pbyBuff, 0, SJT_BUFF_SIZE);
	if(m_wNoOfSections == 0x06)
	{
		if(!GetBuffer(m_dwAEPMapped, 0x200, 0x00))
		{
			return bRet;
		}
		DWORD		dwLengh = 0, dwOffset = 0, dwCount = 0;
		t_disasm	da;
		if(!(*(BYTE *)&m_pbyBuff[0] == 0x83))
		{
			return bRet;
		}
		while(dwOffset < MAX_INSTRUCTION_LEN + 0x200)
		{
			dwLengh = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwLengh > (0x200 - dwOffset))
			{
				return bRet;
			}
			if(dwLengh == 2 && strstr(da.result, "JNB"))
			{
				dwCount++;
			}
			if(dwCount == 1 && strstr(da.result, "CMP"))
			{
				dwCount++;
			}
			if(dwLengh == 6 && dwCount == 2 && strstr(da.result, "MOV"))
			{
				dwCount++;
			}
			if(dwLengh == 3 && dwCount == 3 && strstr(da.result, "CMP"))
			{
				dwCount++;
			}
			if(dwCount == 4 && strstr(da.result, "XCHG"))
			{
				return true;
			}
			dwOffset +=dwLengh;
		}

	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDCodecPackSJT2
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Shreyas + Rushikesh + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of CodecPack Family
--------------------------------------------------------------------------------------*/
bool CTrojans::DetectCodecPackSJT2()
{
	bool	bRet = false;
	DWORD	dwReadOffset = 0;

	memset(m_pbyBuff, 0, SJT_BUFF_SIZE);
	if(m_wNoOfSections == 3)
	{
		dwReadOffset = m_dwAEPUnmapped + 0x300;
		dwReadOffset = (0x1000*(dwReadOffset / 0x1000));
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwReadOffset, &dwReadOffset))
		{
			return bRet;
		}
	}
	else
	{
		dwReadOffset = m_pSectionHeader[1].PointerToRawData;	//Added to cover more samples of Codecpack.SJT
	}

	if(!GetBuffer(dwReadOffset, SJT_BUFF_SIZE, SJT_BUFF_SIZE))
	{
		return bRet;
	}

	int i = 0;
	for(;i < SJT_BUFF_SIZE - 0x50; i++)
	{
		bool bFlag = false;
		BYTE byKeyDrypt = 0;
		BYTE byKey1 = 0x27;
		BYTE byKey2 = m_pbyBuff[i] ^ 0x2B;
		BYTE byKey3 = m_pbyBuff[i] ^ 0x4D;
		BYTE byKey4 = 0x4B;
		BYTE byBuff[0x120] = {0};

		if(((m_pbyBuff[i] ^ byKey1) == 0x4D)) //&& (((m_pbyBuff[i + 1] ^ byKey1) == 0x5A) || ((m_pbyBuff[i + 2] ^ byKey1) == 0x5A) || ((m_pbyBuff[i + 3] ^ byKey1) == 0x5A)))
		{
			//Note : Checking next 5 bytes for 0x5A {e.g. 0x4D, 0x00, 0x00, 0x5A) 
			int j = i + 1;
			for(; j < i + 6; j++)
			{
				if((m_pbyBuff[j] ^ byKey1) == 0x5A)
				{
					bFlag = true;
					byKeyDrypt = byKey1;
					break;
				}
			}
		}
		else if(((m_pbyBuff[i] ^ byKey4) == 0x4D) && (((m_pbyBuff[i + 1] ^ byKey4) == 0x5A) || ((m_pbyBuff[i + 2] ^ byKey4) == 0x5A) || ((m_pbyBuff[i + 3] ^ byKey4) == 0x5A)))
		{
			bFlag = true;
			byKeyDrypt = byKey4;
		}
		if(((m_pbyBuff[i+1] ^ byKey2) == 0x5A) || ((m_pbyBuff[i+2] ^ byKey2) == 0x5A) || ((m_pbyBuff[i+3] ^ byKey2) == 0x5A) || ((m_pbyBuff[i+4] ^ byKey2) == 0x5A))
		{

			byKeyDrypt = byKey2;
			bFlag = true;
		}
		else if(byKey3 != 0 && ((m_pbyBuff[i + 1] ^ byKey3) == 0x5A) || ((m_pbyBuff[i + 2] ^ byKey3) == 0x5A) || ((m_pbyBuff[i + 3] ^ byKey3) == 0x5A))
		{			
			byKeyDrypt = byKey3;
			bFlag = true;
		}	
		if(bFlag)
		{			
			byBuff[0] = 0x4D;
			for(int j = i + 1, k = 1; j < SJT_BUFF_SIZE && k < 0x120; j++)
			{
				if(m_pbyBuff[j])
				{
					byBuff[k++] = m_pbyBuff[j] ^ byKeyDrypt;
				}
			}
			DWORD dwPEOffset = *(DWORD *)&byBuff[0x3C];
			if((dwPEOffset > 0 && dwPEOffset <= 0x108) && ((*(WORD *)&byBuff[0] == 0x5A4D)  && 
				((*(WORD *)&byBuff[dwPEOffset] == 0x4550) || (*(WORD *)&byBuff[dwPEOffset - 5] == 0x4550) || 
				(*(WORD *)&byBuff[dwPEOffset - 2] == 0x4550) || (*(WORD *)&byBuff[dwPEOffset - 3] == 0x4550) || (*(WORD *)&byBuff[dwPEOffset - 1] == 0x4550))))
			{
				return true;
			}
			else 
			{
				const BYTE bySig[] = {0x4D, 0x38, 0x5A, 0x90};
				for(int x = 0;x <= sizeof(byBuff) - 0x10; x++)
				{
					if(memcmp(&byBuff[x], bySig, sizeof(bySig)) == 0)
						return true;
				}
			}			
			
			bFlag = false;
		}
	}
	//this modificatiion Done by Rushi
	//Variants covered Codecpack.ampn,Codecpack.amyc,Codecpack.amze,Codecpack.apcz,Codecpack.ahzb,Codecpack.aopl,...
	int iCount = 0x0;
	int bBuffCounter = 0x0;
	int byKeyArr[12][4]= {{0xAB, 0xBB, 0x11, 0x0C},
							{0x20, 0X3D, 0x69, 0x44},
							{0x6A, 0x76, 0x04, 0x55},
							{0x7D, 0x21, 0x25, 0xF4},
							{0x3F, 0x0D, 0xA0, 0x11},
							{0x14, 0xD4, 0x80, 0x39},
							{0x9F, 0x9F, 0x18, 0x34},
							{0x52, 0x17, 0x0B, 0xD1},
							{0x44, 0xB3, 0x3B, 0xA1},
							{0x30, 0x35, 0x2E, 0xAD},
							{0xEE, 0x00, 0x8D, 0x8D},
							{0xB9, 0x79, 0xC0, 0x1F}};

	for(i = 0; i < SJT_BUFF_SIZE - 0x50; i++)
	{
		if(m_pbyBuff[i])
		{
			if((m_pbyBuff[i]^0x4D) == byKeyArr[0][0]){iCount = 1;}
			else if((m_pbyBuff[i]^0x4D) == byKeyArr[1][0]){iCount = 2;}
			else if((m_pbyBuff[i]^0x4D) == byKeyArr[2][0]){iCount = 3;}
			else if((m_pbyBuff[i]^0x4D) == byKeyArr[3][0]){iCount = 4;}
			else if((m_pbyBuff[i]^0x4D) == byKeyArr[4][0]){iCount = 5;}
			else if((m_pbyBuff[i]^0x4D) == byKeyArr[5][0]){iCount = 6;}
			else if((m_pbyBuff[i]^0x4D) == byKeyArr[6][0]){iCount = 7;}
			else if((m_pbyBuff[i]^0x4D) == byKeyArr[7][0]){iCount = 8;}
			else if((m_pbyBuff[i]^0x4D) == byKeyArr[8][0]){iCount = 9;}
			else if((m_pbyBuff[i]^0x4D) == byKeyArr[9][0]){iCount = 10;}
			else if((m_pbyBuff[i]^0x4D) == byKeyArr[10][0]){iCount = 11;}
			else if((m_pbyBuff[i]^0x4D) == byKeyArr[11][0]){iCount = 12;}
			if(iCount){bBuffCounter = i;break;}
		}
	}
	if(iCount)
	{
		iCount -=1;
		int bRowKey = 1;
		BYTE byBuff[0x60] = {0};
		byBuff[0] = 0x4D;
		int k = 0;
		int j = bBuffCounter + 1;
		for(j,k = 1; j < SJT_BUFF_SIZE - 0x50 && k < 0x50; j++)
		{
			if((bRowKey ==1) && m_pbyBuff[j] && ((m_pbyBuff[j] ^ byKeyArr[iCount][bRowKey]) == 0x38)){byBuff[k++] = 0x38;bRowKey++;}
			else if((bRowKey ==2) && m_pbyBuff[j] && ((m_pbyBuff[j] ^ byKeyArr[iCount][bRowKey]) == 0x5A)){byBuff[k++] = 0x5A;bRowKey++;}
			else if((bRowKey ==3) && m_pbyBuff[j] && ((m_pbyBuff[j] ^ byKeyArr[iCount][bRowKey]) == 0x90)){byBuff[k++] = 0x90;bRowKey++;break;}
			else if(m_pbyBuff[j]){byBuff[k++] = m_pbyBuff[j];}
		}
		if(bRowKey == 4)
		{
			const BYTE bySig[] = {0x4D, 0x38, 0x5A, 0x90};
			for(int x = 0;x < sizeof(byBuff) - 4; x++)
			{
				if(memcmp(&byBuff[x], bySig, sizeof(bySig)) == 0)
					return true;
			}
		}
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDCodecPackSJT3
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Shreyas + Rushikesh + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of CodecPack Family
--------------------------------------------------------------------------------------*/
bool CTrojans::DetectCodecPackSJT3()
{
	bool bRet = false;
	if(m_wNoOfSections != 0x06 && m_wNoOfSections != 0x03)
	{
		return bRet;
	}
	
	memset(m_pbyBuff, 0x00, SJT_BUFF_SIZE);
	DWORD iCnt = 0x00, jCnt = 0x00, kCnt = 0x00, Cnt = 0x00;
	BYTE	bDummy = 0x00;
	BYTE	bTemp = 0x00;
	BYTE	byRefKey[0x08] = {0x00};
	BYTE	byDecKey[0x100] = {0x00};
//	DWORD	dwReadOffset = 0x1490;
	DWORD	dwKeyOffset = 0x00, dwKeyLength = 0x07;
	DWORD	dwReadOffset = m_pSectionHeader[1].PointerToRawData;;

	if(m_wNoOfSections == 0x03)
	{
		dwReadOffset = 0x3400;
	}

	if(!GetBuffer(dwReadOffset, 0x50, 0x50))
	{
		return bRet;
	}
	for(iCnt = 0x00; iCnt < 0x50; iCnt+= 0x04)
	{
		if(m_pbyBuff[iCnt] == 0x00 && m_pbyBuff[iCnt+1] == 0x00 && m_pbyBuff[iCnt+2] == 0x00 && m_pbyBuff[iCnt+3] == 0x00)
		{
			continue;
		}
		else
		{
			if(m_pbyBuff[iCnt + 0x02] == 0x40 && m_pbyBuff[iCnt + 0x03] == 0x00)
			{
				dwKeyOffset = *(DWORD*) &m_pbyBuff[iCnt] - m_pMaxPEFile->m_stPEHeader.ImageBase;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwKeyOffset, &dwKeyOffset))
				{
					return bRet;
				}
				if(!m_pMaxPEFile->ReadBuffer(&byRefKey[0x00], dwKeyOffset, 0x08, 0x08))
				{
					return bRet;
				}

				if(byRefKey[0x07] == 0x00)
				{
					dwKeyLength = 0x06;
				}
				dwReadOffset = dwReadOffset + iCnt;
				break;
			}
		}
	}
	
	for(int kCnt = 0x00; kCnt < 0x100; kCnt++)
	{
		byDecKey[kCnt] = kCnt;
	}
	
	for(iCnt = 0x00; iCnt < 0x100; iCnt++)
	{
		bDummy = byRefKey[jCnt] + byDecKey[iCnt] + bDummy;
		byDecKey[bDummy] = byDecKey[iCnt];
		jCnt++;
		if(jCnt == dwKeyLength)
		{
			jCnt = 0x00;
		}
	}
	memset(m_pbyBuff, 0x00, SJT_BUFF_SIZE);

	if(!GetBuffer(dwReadOffset + 0x04, 0x10, 0x10))
	{
		return bRet;
	}
	jCnt = 0x00;
	for(iCnt = 0x00; iCnt < 0x10; iCnt++)
	{
		if(m_pbyBuff[iCnt] == 0x00)
		{
			continue;
		}
		BYTE bSwapTemp = 0x00;
		bDummy = 0x00;
		jCnt++;
		bTemp = byDecKey[jCnt] + bTemp;
		bSwapTemp = byDecKey[jCnt] + byDecKey[bTemp];
		byDecKey[bTemp] = bSwapTemp - byDecKey[bTemp];
		byDecKey[jCnt]  = bSwapTemp - byDecKey[jCnt];
		bDummy = byDecKey[bTemp] + byDecKey[jCnt];
		m_pbyBuff[Cnt] = m_pbyBuff[iCnt] ^ byDecKey[bDummy];
		Cnt++;
	}

	const BYTE bySig[] = {0x4D, 0x38, 0x5A, 0x90};
	if(memcmp(&m_pbyBuff[0], &bySig[0], sizeof(DWORD)) == 0x00)
	{
		return true;
	}

	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanAutorunDM
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Autorun.DM Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectTrojanAutorunDM()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if (m_wNoOfSections < 0x3 || 
		m_wAEPSec != 0x0 || 
		((m_dwAEPUnmapped / 0x100) != 0x38 && m_dwAEPUnmapped != 0x1000) || 
		(m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}

	if (m_pSectionHeader[m_wAEPSec].VirtualAddress == 0x1000 &&
		m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x1000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int AUTORUNDM_BUFF_SIZE = 0x1300;
		m_pbyBuff = new BYTE[AUTORUNDM_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		const BYTE AUTORUNDM_SIG1[] = {0x6B,0x72,0x6E,0x6C,0x6E,0x2E,0x66,0x6E,0x65,0x00,0x00,0x00,0x6B,0x72,0x6E,
								       0x6C,0x6E,0x2E,0x66,0x6E,0x72};//krnln.fne krnln.fnr
		const BYTE AUTORUNDM_SIG2[] = {0x6B,0x72,0x6E,0x6C,0x6E,0x0D,0x64,0x30,0x39,0x66,0x32,0x33,0x34,0x30,0x38,
								       0x31,0x38,0x35,0x31,0x31,0x64,0x33,0x39,0x36,0x66,0x36,0x61,0x61,0x66,0x38,
									   0x34,0x34,0x63,0x37,0x65,0x33,0x32,0x35,0x0D,0x34};
										//krnln.d09f2340818511d396f6aaf844c7e325.4
		
		DWORD dwBuffSize = 0x0;
		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBuffSize],0x7000 + 0xE0, 0x150, 0x150))
		{
			return iRetStatus;
		}
		dwBuffSize += 0x150;
		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBuffSize],m_pSectionHeader[m_wAEPSec + 0x2].PointerToRawData + 0xE0, 0x150, 0x150))
		{
			return iRetStatus;
		}
		dwBuffSize += 0x150;
		if(m_wNoOfSections > 0x3)
		{
			if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBuffSize],m_pSectionHeader[m_wAEPSec + 0x3].PointerToRawData + 0x150, 0x1000, 0x1000))
			{
				return iRetStatus;
			}
			dwBuffSize += 0x1000;
		}
		for(DWORD i = 0; i < dwBuffSize - sizeof(AUTORUNDM_SIG1) ; i++)
		{
			if(memcmp(&m_pbyBuff[i], AUTORUNDM_SIG1, sizeof(AUTORUNDM_SIG1)) == 0)
			{				
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Autorun.DM"));
				return VIRUS_FILE_DELETE;
			}
			if ( i < dwBuffSize - sizeof(AUTORUNDM_SIG2))
			{
				if (memcmp(&m_pbyBuff[i], AUTORUNDM_SIG2, sizeof(AUTORUNDM_SIG2)) == 0)
				{				
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Autorun.DM"));
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptAutorunDM
	In Parameters	: 
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption routine for different varients of Autorun.DM Family
--------------------------------------------------------------------------------------*/
int CTrojans::DecryptAutorunDM(int iOp, DWORD dwKey)
{
	for(DWORD j = 0; j < m_pSectionHeader[0].SizeOfRawData ; j += 4)
	{
		if(iOp == 1)
		{
			*(DWORD *)&m_pbyBuff[j] += dwKey;
		}
		else
		{
			*(DWORD *)&m_pbyBuff[j] -= dwKey;
		}
	}
	const BYTE Sig[] = {0x47, 0x65, 0x74, 0x4E, 0x65, 0x77, 0x53, 0x6F, 0x63, 0x6B, 0x00, 0x53,
		0x6F, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x5C, 0x46, 0x6C, 0x79, 0x53, 0x6B, 0x79, 0x5C,
		0x45, 0x5C, 0x49, 0x6E, 0x73, 0x74, 0x61, 0x6C, 0x6C, 0x00, 0x50, 0x61, 0x74, 0x68, 0x00,
		0x4E, 0x6F, 0x74, 0x20, 0x66, 0x6F, 0x75, 0x6E, 0x64};

	if(memcmp(&m_pbyBuff[0x2D], Sig, sizeof(Sig)) == 0)
	{
		return 1;
	}

	const BYTE Sig1[] = {0x81, 0x00};
	const BYTE Sig2[] = {0x81, 0x02};
	for(DWORD i = 0; i < m_pSectionHeader[0].SizeOfRawData; i++)
	{
		if(memcmp(&m_pbyBuff[i], Sig1, sizeof(Sig1)) == 0 || memcmp(&m_pbyBuff[i], Sig2, sizeof(Sig2)) == 0)
		{				
			return *(DWORD *)&m_pbyBuff[i + 2];
		}
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPackedKrapIU
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Frap.IU Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectPackedKrapIU()
{
	int iRetStatus = VIRUS_NOT_FOUND;	
	if((m_dwAEPUnmapped % 0x10 == 0) && (m_wAEPSec != m_wNoOfSections - 1) && 
		(((m_wAEPSec <= 1) && (m_pSectionHeader[m_wAEPSec].PointerToRawData <= 0x800)) || ((m_pSectionHeader[m_wAEPSec].PointerToRawData == 0xC00) && m_wNoOfSections >= 6 && (m_wAEPSec == 2)) || ((m_wNoOfSections == 6) && (memcmp(m_pSectionHeader[0].Name, ".2", 2)== 0))) && 
		(((memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".reloc", 6)== 0)) || ((memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".rsrc", 5)== 0) && m_pSectionHeader[m_wNoOfSections - 1].Characteristics == 0x40000040)) &&
		((m_pSectionHeader[m_wAEPSec].Characteristics == 0x60000020) || ((m_pSectionHeader[m_wAEPSec].Characteristics == 0xE0000020) && (m_wNoOfSections >= 4)) || (memcmp(m_pSectionHeader[m_wAEPSec].Name, ".rdata", 6)== 0)))
	{
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		const int BUFF_SIZE = 0x650;
		m_pbyBuff = new BYTE[BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff,0x00,BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, BUFF_SIZE, BUFF_SIZE))
		{
			if((m_pbyBuff[0x00] == 0x55) && m_pbyBuff[0x1] == 0x8B && m_pbyBuff[0x2] == 0xEC)
			{
				DWORD dwLength = 0, dwInstrCnt = 0, dwOffset = 0,dwCallOffset = 0,dwInstrCnt1 = 0,dwLength1 = 0,dwOffset1 = 0;
				t_disasm	da;
				bool bCallCheck = false;
				const int ZBOT_BUFF_SIZE = 0x200;
				BYTE byZbotBuff[ZBOT_BUFF_SIZE] = {0};
				BYTE FIRSTCHECK[] = {0x55,0x8B,0xEC,0x8B,0x45,0x08,0x8B,0x40,0xFC,0x5D,0xC3};
				BYTE FIRSTCHECK1[] = {0x55,0x8B,0xEC,0x8B,0x45,0x08,0xC6,0x00,0x0F,0x5D,0xC3};
				BYTE FIRSTCHECK2[] ={0x55,0x8B,0xEC,0x51,0xC7,0x45,0xFC,0xD0,0x09,0x00,0x00,0x8B,0x45,0x08,0x8B,0x40};
				BYTE FIRSTCHECK3[] = {0x55,0x8B,0xEC,0x81,0xEC,0x20,0x02,0x00,0x00};
				while(dwOffset < BUFF_SIZE)
				{
					memset(&da, 0x00, sizeof(struct t_disasm));
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwLength > BUFF_SIZE - dwOffset)
					{					
						break;
					}
					else if((bCallCheck == false) && dwLength == 5 && strstr(da.result,"CALL") && ((*(DWORD *)&m_pbyBuff[dwOffset + 1] > 0xFFFFF000) || (*(DWORD *)&m_pbyBuff[dwOffset + 1] < 0x800)))
					{					
						dwCallOffset = m_dwAEPMapped + *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwOffset+ 5;
						if(m_pMaxPEFile->ReadBuffer(byZbotBuff,dwCallOffset,0x10,0x10))
						{
							if((memcmp(&byZbotBuff[0x00],FIRSTCHECK,sizeof(FIRSTCHECK)) == 0) || (memcmp(&byZbotBuff[0x00],FIRSTCHECK1,sizeof(FIRSTCHECK1)) == 0) || (memcmp(&byZbotBuff[0x00],FIRSTCHECK2,sizeof(FIRSTCHECK2)) == 0) || (memcmp(&byZbotBuff[0x00],FIRSTCHECK3,sizeof(FIRSTCHECK3)) == 0))
							{
								bCallCheck = true;							
							}							
						}									
					}
					else if((bCallCheck == true) && (dwInstrCnt == 0) && dwLength == 5 && strstr(da.result,"CALL") && ((*(DWORD *)&m_pbyBuff[dwOffset + 1] > 0xFFFFF000) || (*(DWORD *)&m_pbyBuff[dwOffset + 1] < 0x700)))
					{
						dwCallOffset = m_dwAEPMapped + *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwOffset + 5;
						if(m_pMaxPEFile->ReadBuffer(byZbotBuff, dwCallOffset, ZBOT_BUFF_SIZE, ZBOT_BUFF_SIZE))
						{
							dwOffset1= 0;
							dwInstrCnt1 = 0;
							dwLength1 = 0;
							while(dwOffset1 < ZBOT_BUFF_SIZE)
							{
								memset(&da, 0x00, sizeof(struct t_disasm));
								dwLength1 = m_objMaxDisassem.Disasm((char *)&byZbotBuff[dwOffset1], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
								if(dwLength1 > ZBOT_BUFF_SIZE - dwOffset1)
								{					
									break;
								}
								else if((dwLength1 == 1) && (byZbotBuff[dwOffset1] == 0xC3))
								{
									dwLength1 = 1;
									break;
								}
								else if((dwLength1 == 2) && (dwInstrCnt1 == 0) && strstr(da.result,"MOV E") && strstr(da.result,",[E"))
								{
									if(byZbotBuff[dwOffset1 + dwLength1] == 0x03)
									{
										dwInstrCnt1++;
									}
								}
								else if((dwLength1 == 3 || dwLength1 == 6) && dwInstrCnt1 == 1 && strstr(da.result,"ADD E"))
								{
									if(byZbotBuff[dwOffset1 + dwLength1] == 0x8B || byZbotBuff[dwOffset1 + dwLength1] == 0xA1)
									{
										dwInstrCnt1++;
									}								
								}
								else if((dwLength1 == 3 || dwLength1 == 6 || ((dwLength == 5) && strstr(da.result,"MOV EAX"))) && dwInstrCnt1 == 2 && strstr(da.result,"MOV E"))
								{
									dwInstrCnt1++;
								}
								else if((dwLength1 == 2) && (dwInstrCnt1 == 3) && strstr(da.result,"MOV [E") && strstr(da.result,"],E"))
								{
									if((byZbotBuff[dwOffset1 + dwLength1] != 0xC7) && (byZbotBuff[dwOffset1 + dwLength1] != 0x8B) && (byZbotBuff[dwOffset1 + dwLength1] != 0xA1))
									{
										return iRetStatus;
									}
									dwInstrCnt1++;									
								}							
								else if(dwLength1 == 2 && (dwInstrCnt1 == 4) && (strstr(da.result,"MOV E") || strstr(da.result,"XOR E")) && strstr(da.result,",[E"))
								{
									dwInstrCnt1++;
								}
								else if(dwLength1 == 5 && (dwInstrCnt1 == 4) && strstr(da.result,"CALL") && (*(DWORD *)&byZbotBuff[dwOffset1 + 1] > 0xFFFFFD00))
								{
									dwOffset1 = dwCallOffset + *(DWORD *)&byZbotBuff[dwOffset1 + 1] + dwOffset1 + 5;
									if(m_pMaxPEFile->ReadBuffer(byZbotBuff,dwOffset1,0x1A0,0x1A0))
									{
										dwOffset1 = 0;
										continue;
									}								
								}
								else if((dwLength1 == 6 || dwLength1 == 3) && (dwInstrCnt1 == 5) && strstr(da.result,"XOR E"))
								{
									dwInstrCnt1++;
								}
								else if((dwLength1 == 6 || dwLength1 == 3) && (dwInstrCnt1 == 5 || dwInstrCnt1 == 6) && strstr(da.result,"MOV E"))
								{
									dwInstrCnt1++;
								}
								else if((dwLength1 == 6 || dwLength1 == 3) && (dwInstrCnt1 == 6 || dwInstrCnt1 == 7) && strstr(da.result,"ADD E"))
								{
									dwInstrCnt1++;
								}
								else if((dwLength1 == 2) && ( dwInstrCnt1 == 6 ||dwInstrCnt1 == 7  || dwInstrCnt1 == 8)&& strstr(da.result,"MOV [E") && strstr(da.result,"],E"))
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Packed.Krap.iu"));
									return VIRUS_FILE_DELETE;
								}
								dwOffset1 += dwLength1;
							}
						}					
					}
					else if((bCallCheck == true) && (dwLength == 2) && (dwInstrCnt == 0) && strstr(da.result,"MOV E") && strstr(da.result,",[E"))
					{
						if(m_pbyBuff[dwOffset + dwLength] == 0x03)
						{
							dwInstrCnt++;
						}					
					}
					else if((bCallCheck == true) && (dwLength == 3 || dwLength == 6) && dwInstrCnt == 1 && strstr(da.result,"ADD E"))
					{
						if((m_pbyBuff[dwOffset + dwLength] == 0x8B) || (m_pbyBuff[dwOffset + dwLength] == 0xA1))
						{
							dwInstrCnt++;
						}
					}
					else if((dwLength == 3 || dwLength == 6 || ((dwLength == 5) && strstr(da.result,"MOV EAX"))) && dwInstrCnt == 2 && strstr(da.result,"MOV E"))
					{
						dwInstrCnt++;
					}
					else if((dwLength == 2) && (dwInstrCnt == 3) && strstr(da.result,"MOV [E") && strstr(da.result,"],E"))
					{
						if((m_pbyBuff[dwOffset + dwLength] != 0xC7) && (m_pbyBuff[dwOffset + dwLength] != 0x8B) && (m_pbyBuff[dwOffset + dwLength] != 0xA1))
						{
							return iRetStatus;
						}
						dwInstrCnt++;
					}
					else if((dwLength == 2) && (dwInstrCnt == 4) && (strstr(da.result,"MOV E") || strstr(da.result,"XOE E")) && strstr(da.result,",[E"))
					{
						dwInstrCnt++;
					}				
					else if((dwLength == 6 || dwLength == 3) && (dwInstrCnt == 5) && strstr(da.result,"XOR E"))
					{
						dwInstrCnt++;
					}
					else if((dwLength == 6 || dwLength == 3) && (dwInstrCnt == 5 || dwInstrCnt == 6) && strstr(da.result,"MOV E"))
					{
						dwInstrCnt++;
					}
					else if((dwLength == 6 || dwLength == 3) && (dwInstrCnt == 6 || dwInstrCnt == 7) && strstr(da.result,"ADD E"))
					{
						dwInstrCnt++;
					}
					else if((dwLength == 2) && (dwInstrCnt == 7  || dwInstrCnt == 8)&& strstr(da.result,"MOV [E") && strstr(da.result,"],E"))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Packed.Krap.iu"));
						return VIRUS_FILE_DELETE;
					}
					dwOffset += dwLength;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectLpler
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Lpler Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectLpler(void)
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->m_stPEHeader.Subsystem != 0x02)
		return iRetStatus;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
		return iRetStatus;

	//1 : It should not have export table
	if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x00].Size > 0x00 || m_pMaxPEFile->m_stPEHeader.DataDirectory[0x00].VirtualAddress > 0x00)
		return iRetStatus;
		
	//2 : It should have Resource table
	DWORD	dwResRVA = 0x00;

	dwResRVA = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x02].VirtualAddress;
	if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x02].Size == 0x00 || dwResRVA == 0x00)
		return iRetStatus;

	//3 : It should not have Certificate
	if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].Size > 0x00 || m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].VirtualAddress > 0x00)
		return iRetStatus;

	//4 : It should have overlay
	DWORD	dwFileEnd = 0x00;
	DWORD	dwTemp = 0x00;

	dwFileEnd = ( m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-0x01].SizeOfRawData + 
				  m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-0x01].PointerToRawData);

	if (m_pMaxPEFile->m_dwFileSize <= dwFileEnd || dwFileEnd < 0x500)
	{
		return iRetStatus;
	}

	dwTemp = Rva2FileOffsetEx(dwResRVA,NULL);
	if ((dwTemp + 0x10) > m_pMaxPEFile->m_dwFileSize)
	{
		return iRetStatus;
	}

	WORD	wNoofRes = 0x00;
	DWORD	dwBytesRead = 0x00;
	m_pMaxPEFile->ReadBuffer((LPVOID)&wNoofRes,(dwTemp + 0x0E) ,sizeof(WORD),sizeof(WORD),&dwBytesRead);
	if (wNoofRes != 0x04)
	{
		return iRetStatus;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}	
	m_pbyBuff = new BYTE[0x500];	
	if(GetBuffer((dwFileEnd - 0x500), 0x500, 0x500))
	{
		CSemiPolyDBScn	polydbObj;
		TCHAR			szVirusName[MAX_PATH] = {0};
		TCHAR			szSig[] ={_T("6E616D653D224E756C6C736F66742E4E5349532E65786568656164*3C6465736372697074696F6E3E4E756C6C736F667420496E7374616C6C2053797374656D2076322E33343C2F6465736372697074696F6E3E")};
		TCHAR			szSig_2[] ={_T("6E616D653D224E756C6C736F66742E4E5349532E65786568656164*3C6465736372697074696F6E3E4E756C6C736F667420496E7374616C6C2053797374656D207631382D4A616E2D323031302E6376733C2F6465736372697074696F6E3E")};
		TCHAR			szSig_3[] ={_T("6E616D653D224E756C6C736F66742E4E5349532E65786568656164*3C6465736372697074696F6E3E4E756C6C736F667420496E7374616C6C2053797374656D207632302D4F63742D323030392E6376733C2F6465736372697074696F6E3E")};
		TCHAR			szSig_4[] ={_T("6E616D653D224E756C6C736F66742E4E5349532E65786568656164*3C6465736372697074696F6E3E4E756C6C736F667420496E7374616C6C2053797374656D207632322D4A756C2D323030392E6376733C2F6465736372697074696F6E3E")};
		TCHAR			szSig_5[] ={_T("6E616D653D224E756C6C736F66742E4E5349532E65786568656164*3C6465736372697074696F6E3E4E756C6C736F667420496E7374616C6C2053797374656D2076*323030392E6376733C2F6465736372697074696F6E3E")};

		if(polydbObj.LoadSigDBEx(szSig, _T("Virus.Downloader.Lipler.AXKD"), TRUE) <= 1)
			return iRetStatus;

		polydbObj.LoadSigDBEx(szSig_2, _T("Virus.Downloader.Lipler.AXKD"), TRUE);
		polydbObj.LoadSigDBEx(szSig_3, _T("Virus.Downloader.Lipler.IML"), TRUE);
		polydbObj.LoadSigDBEx(szSig_4, _T("Virus.Downloader.Lipler.IML"), TRUE);
		polydbObj.LoadSigDBEx(szSig_5, _T("Virus.Downloader.Lipler.IML"), FALSE);

		if(polydbObj.ScanBuffer(&m_pbyBuff[0], 0x300, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName)>0)
			{
				iRetStatus = VIRUS_FILE_DELETE;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDialerCJ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Dialer Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectDialerCJ()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == 0x00 && (m_wNoOfSections == 3 || m_wNoOfSections == 4) && 
		(m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x400 || m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x1000) &&
		m_pSectionHeader[m_wAEPSec].SizeOfRawData <= 0xF000 && m_pSectionHeader[m_wAEPSec].VirtualAddress == 0x1000 &&
		((m_pSectionHeader[m_wAEPSec].Characteristics & 0x60000020) == 0x60000020 || 
		(m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000040) == 0xE0000040 ||
		(m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000080) == 0xE0000080) &&
		(m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		m_pbyBuff = new BYTE[DIALER_BUFF_SIZE];
		if(memcmp(m_pSectionHeader[m_wAEPSec].Name, "UPX0", 4) == 0 && m_pSectionHeader[m_wAEPSec].SizeOfRawData != 0x0 && memcmp(m_pSectionHeader[m_wAEPSec + 2].Name, ".avp", 5) == 0)
		{
			if(!GetBuffer(m_pSectionHeader[m_wAEPSec + 1].PointerToRawData, DIALER_BUFF_SIZE, 0x1000))
			{
				return iRetStatus;
			}
		}
		else if(!GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, DIALER_BUFF_SIZE, 0x1000))
		{
			return iRetStatus;
		}
		const BYTE DIALER_SIG1[] = {0x4E,0x00,0x61,0x00,0x6D,0x00,0x65,0x00,0x00,0x00,0x6D,0x00,0x69,0x00,0x63,0x00,0x72,0x00,0x6F};
		const BYTE DIALER_SIG2[] = {0x50,0x00,0x6C,0x00,0x61,0x00,0x79,0x00,0x65,0x00,0x72};
		const BYTE DIALER_SIG6[] = {0x43,0x00,0x6F,0x00,0x6E,0x00,0x66,0x00,0x65,0x00,0x72,0x00,0x6D,0x00,0x61};
		const BYTE DIALER_SIG10[] = {0x4D,0x00,0x69,0x00,0x63,0x00,0x72,0x00,0x6F,0x00,0x44,0x00,0x69,0x00,0x61,0x00,0x6C,0x00,0x65,0x00,0x72};

		for(DWORD dwOffset = 0; dwOffset <= DIALER_BUFF_SIZE - sizeof(DIALER_SIG1); dwOffset++)
		{
			if(memcmp(&m_pbyBuff[dwOffset], DIALER_SIG1, sizeof(DIALER_SIG1))== 0)
			{
				for(dwOffset += sizeof(DIALER_SIG1); dwOffset <= DIALER_BUFF_SIZE - sizeof(DIALER_SIG10); dwOffset++)
				{
					if(memcmp(&m_pbyBuff[dwOffset], DIALER_SIG2, sizeof(DIALER_SIG2))== 0 ||
						memcmp(&m_pbyBuff[dwOffset], DIALER_SIG6, sizeof(DIALER_SIG6))== 0)
					{
						if(DetectDialerCJSig(dwOffset + sizeof(DIALER_SIG2), 0))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Dialer.CJ"));
							return  VIRUS_FILE_DELETE;									
						}												
					}
					else if(memcmp(&m_pbyBuff[dwOffset], DIALER_SIG10, sizeof(DIALER_SIG10))== 0)
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Dialer.CJ"));
						return VIRUS_FILE_DELETE;
					}
				}
				if(DetectDialerCJSig(dwOffset, 1))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Dialer.CJ"));
					return  VIRUS_FILE_DELETE;
				}
				return iRetStatus;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDialerCJSig
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function verifies binary signature for different varients of Dialer.CJ Family
--------------------------------------------------------------------------------------*/
bool CTrojans::DetectDialerCJSig(DWORD dwOffset, DWORD dwOverlayChk)
{
	const BYTE DIALER_SIG3[] = {0x56,0x00,0x69,0x00,0x65,0x00,0x74,0x00,0x61,0x00,0x74,0x00,0x6F};
	const BYTE DIALER_SIG4[] = {0x42,0x00,0x55,0x00,0x4F,0x00,0x4E,0x00,0x5F,0x00,0x44,0x00,0x49,0x00,0x56,0x00,0x45,0x00,0x52,0x00,0x54,0x00,0x49,0x00,0x4D,0x00,0x45,0x00,0x4E,0x00,0x54,0x00,0x4F,0x00,0x21};
	const BYTE DIALER_SIG5[] = {0x35,0x00,0x20,0x00,0x63,0x00,0x6F,0x00,0x6D,0x00,0x6D,0x00,0x61,0x00,0x20,0x00,0x33,0x00,0x20,0x00,0x64,0x00,0x2E,0x00,0x6C,0x00,0x67,0x00,0x73,0x00,0x20,0x00,0x31,0x00,0x38,0x00,0x35,0x00,0x2F,0x00,0x39,0x00,0x39};
	const BYTE DIALER_SIG7[] = {0x41,0x00,0x63,0x00,0x63,0x00,0x65,0x00,0x74,0x00,0x74,0x00,0x6F};
	const BYTE DIALER_SIG8[] = {0x4E,0x00,0x6F,0x00,0x6E,0x00,0x20,0x00,0x61,0x00,0x63,0x00,0x63,0x00,0x65,0x00,0x74,0x00,0x74,0x00,0x6F};
	const BYTE DIALER_SIG9[] = {0x52,0x00,0x41,0x00,0x53,0x00,0x44,0x00,0x69,0x00,0x61,0x00,0x6C,0x00,0x65,0x00,0x72};
	const BYTE DIALER_SIG11[] = {0x51,0x00,0x55,0x00,0x45,0x00,0x53,0x00,0x54,0x00,0x4F,0x00,0x20,0x00,0x53,0x00,0x4F,0x00,0x46,0x00,0x54,0x00,0x57,0x00,0x41,0x00,0x52,0x00,0x45,0x00,0x20,0x00,0x45,0x00,0x27,0x00,0x20,0x00,0x45,0x00,0x53,0x00,0x45,0x00,0x4E,0x00,0x54,0x00,0x45,0x00,0x20,0x00,0x44,0x00,0x41,0x00,0x20,0x00,0x56,0x00,0x49,0x00,0x52,0x00,0x55,0x00,0x53,0x00,0x20,0x00,0x41,0x00,0x4C,0x00,0x20,0x00,0x31,0x00,0x30,0x00,0x30,0x00,0x25};
	const BYTE DIALER_SIG12[] = {0x43,0x00,0x6C,0x00,0x69,0x00,0x63,0x00,0x63,0x00,0x61,0x00,0x20,0x20,0x1C,0x00,0x53,0x00,0x49};
	const BYTE DIALER_SIG13[] = {0x51,0x00,0x75,0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x6F,0x00,0x20,0x00,0x70,0x00,0x72,0x00,0x6F,0x00,0x67,0x00,0x72,0x00,0x61,0x00,0x6D,0x00,0x6D,0x00,0x61};

	if(!dwOverlayChk)
	{
		for(dwOffset ; dwOffset <= DIALER_BUFF_SIZE - sizeof(DIALER_SIG9); dwOffset++)
		{
			if( memcmp(&m_pbyBuff[dwOffset],DIALER_SIG7,sizeof(DIALER_SIG7))== 0 ||
				memcmp(&m_pbyBuff[dwOffset],DIALER_SIG9,sizeof(DIALER_SIG9))== 0)
			{
				for(dwOffset += sizeof(DIALER_SIG7); dwOffset < DIALER_BUFF_SIZE - sizeof(DIALER_SIG8); dwOffset++)
				{
					if(memcmp(&m_pbyBuff[dwOffset], DIALER_SIG8, sizeof(DIALER_SIG8))== 0)
					{
						return true;
					}
				}
				return true;
			}
		}
	}
	else
	{
		DWORD dwOverlaySize = m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData);
		if(dwOverlaySize > DIALER_BUFF_SIZE)
		{
			dwOverlaySize = DIALER_BUFF_SIZE;
		}
		if(!GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, dwOverlaySize, dwOverlaySize))
		{
			return false;
		}
		for(DWORD j = 0; j <= dwOverlaySize - sizeof(DIALER_SIG13); j++)
		{
			if(memcmp(&m_pbyBuff[j],DIALER_SIG3,sizeof(DIALER_SIG3)) == 0 || memcmp(&m_pbyBuff[j],DIALER_SIG4,sizeof(DIALER_SIG4)) == 0 ||
				memcmp(&m_pbyBuff[j],DIALER_SIG5,sizeof(DIALER_SIG5)) == 0 || memcmp(&m_pbyBuff[j],DIALER_SIG11,sizeof(DIALER_SIG11)) == 0 ||
				memcmp(&m_pbyBuff[j],DIALER_SIG12,sizeof(DIALER_SIG12)) == 0 || memcmp(&m_pbyBuff[j],DIALER_SIG13,sizeof(DIALER_SIG13)) == 0)
			{
				return true;
			}
		}
	}
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectMufanomAQDA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Mufanom.aqda Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectMufanomAQDA()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_dwAEPUnmapped % 4) == 0) && (m_wNoOfSections == 4 || (m_wNoOfSections == 5 && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x00)) && 
		m_wAEPSec == 0 && m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 0x6000 &&
		(memcmp(m_pSectionHeader[3].Name, ".reloc", 0x06) == 0) && (m_pSectionHeader[3].SizeOfRawData <= 0x1200) &&
		(memcmp(m_pSectionHeader[2].Name, ".rsrc", 0x05) == 0) && (m_pSectionHeader[2].SizeOfRawData <= 0x2000) &&
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress == 0x00) && (m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress == 0x00) && 
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[0xA].VirtualAddress == 0x00) && (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x6].VirtualAddress == 0x00) &&
		((m_pMaxPEFile->m_stPEHeader.ImageBase == 0x10000000) || (m_pMaxPEFile->m_stPEHeader.ImageBase == 0x400000)))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x100 + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff,0x00,0x100 + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped,0x80,0x80))
		{
			DWORD dwOffset = 0, dwLength = 0, dwTemp = 0;
			t_disasm da;
			while(dwOffset < 0x80)
			{
				memset(&da, 0x00, sizeof(struct t_disasm));
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > 0x80 - dwOffset)
				{					
					break;
				}
				else if(dwLength == 5 && strstr(da.result,"CALL") && (*(DWORD *)&m_pbyBuff[dwOffset + 1] < 0xA0) && (*(DWORD *)&m_pbyBuff[dwOffset + 1] > 0x10))
				{
					dwTemp = dwOffset + m_dwAEPMapped + 5;
					dwOffset = m_dwAEPMapped + dwOffset + *(DWORD *)&m_pbyBuff[dwOffset + 1] + 5;					
					break;
				}
				dwOffset += dwLength;
			}
			if(dwOffset > m_dwAEPMapped)
			{				
				memset(m_pbyBuff,0x00,0x100);
				if(GetBuffer(dwOffset,0x40,0x40))
				{
					if((m_pbyBuff[0x00] == 0x81) && (m_pbyBuff[0x1] == 0x04) && (m_pbyBuff[0x2] == 0x24) && (*(DWORD *)&m_pbyBuff[0x3] < 0x60) && (m_pbyBuff[0x7] == 0xC2) && (m_pbyBuff[0x8] <= 0x20))
					{	
						dwOffset = dwTemp + m_pbyBuff[0x3] - dwOffset;
						if(m_pbyBuff[dwOffset] == 0xC9)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Downloader.Mufanom.aqda"));
							return VIRUS_FILE_DELETE;
						}
					}					
					else
					{
						BYTE byCallcnt = 0;
						dwTemp = dwOffset;
						dwOffset = 0;
						dwLength = 0;
						while(dwOffset < 0x50)
						{
							memset(&da, 0x00, sizeof(struct t_disasm));
							dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
							if(dwLength > 0x50 - dwOffset)
							{					
								break;
							}
							else if(dwLength == 5 && strstr(da.result,"CALL") && (*(DWORD *)&m_pbyBuff[dwOffset + 1] < 0xA0) && (*(DWORD *)&m_pbyBuff[dwOffset + 1] > 0x10))
							{
								byCallcnt++;
								if(byCallcnt == 5)
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Downloader.Mufanom.aqda"));
									return VIRUS_FILE_DELETE;
								}
								dwTemp = dwTemp + dwOffset + *(DWORD *)&m_pbyBuff[dwOffset + 1] + 5;
								if(GetBuffer(dwTemp,0x50,0x50))
								{
									if(byCallcnt == 2 && m_pbyBuff[0x00] == 0x83 && m_pbyBuff[0x1] == 0xC4)
									{
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Downloader.Mufanom.aqda"));
										return VIRUS_FILE_DELETE;
									}
									dwOffset = 0;
									continue;
								}
							}
							dwOffset += dwLength;
						}
					}
				}
			}			
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectMudropASJ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Mudrop.ASJ Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectMudropASJ(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		((m_wNoOfSections == 0x08 && m_dwAEPUnmapped == 0x7E08) || (m_wNoOfSections == 0x02 && m_dwAEPUnmapped == 0x13B0) || (m_wNoOfSections == 0x05 && m_dwAEPUnmapped == 0x30B4)) &&
		(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".rsrc", 5) == 0) &&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress > 0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[2].Size > 0)
	{		
		DWORD dwFileNameOffset = 0;
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(0x407F64 - m_dwImageBase, &dwFileNameOffset))
		{
			return iRetStatus;
		}

		BYTE byMudropSigbuff[0x80] = {0};
		if(!m_pMaxPEFile->ReadBuffer(byMudropSigbuff, dwFileNameOffset, 0x12, 0x12))
		{
			return iRetStatus;
		}

		if(*(DWORD*)&byMudropSigbuff[0] == 0x004F4349 &&  *(DWORD*)&byMudropSigbuff[0x0C] == 0x6966626E && *(WORD*)&byMudropSigbuff[0x10] == 0x656C)
		{
			DWORD dwResID = 0x0A, dwLangID = 0x0204, dwSize = 0, dwRVA = 0;
			if(!FindRes(LPCTSTR(&dwResID), _T("ICO"), LPCTSTR(&dwLangID), dwRVA, dwSize))
			{
				return iRetStatus;
			}

			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwRVA, &dwFileNameOffset))
			{
				return iRetStatus;
			}

			memset(byMudropSigbuff, 0x0, 0x12);
			if(!m_pMaxPEFile->ReadBuffer(byMudropSigbuff, dwFileNameOffset, 0x08, 0x08))
			{
				return iRetStatus;
			}
			if(*(DWORD*)&byMudropSigbuff[0] != 0x02)
			{
				return iRetStatus;
			}
			
			DWORD dwSecondFileOffset = *(DWORD *)&byMudropSigbuff[4];
			if(!m_pMaxPEFile->ReadBuffer(byMudropSigbuff, dwFileNameOffset + 0x4C, 0x08, 0x08))
			{
				return iRetStatus;
			}
			if(*(DWORD*)&byMudropSigbuff[0] == 0x00905A4D && *(DWORD *)&byMudropSigbuff[4] == 0x003)
			{
				if(dwFileNameOffset + 0x4C + dwSecondFileOffset + 0x49CC < m_pMaxPEFile->m_dwFileSize)
				{
					if(m_pMaxPEFile->ReadBuffer(byMudropSigbuff, dwFileNameOffset + 0x4C + dwSecondFileOffset, 0x08, 0x08))
					{
						if(*(DWORD*)&byMudropSigbuff[0] == 0x00905A4D && *(DWORD*)&byMudropSigbuff[4] == 0x003)
						{
							if(dwSecondFileOffset == 0x8D98)
							{
								dwSecondFileOffset = 0x00;
							}
							if(m_pMaxPEFile->ReadBuffer(byMudropSigbuff, dwFileNameOffset + 0x4C + dwSecondFileOffset + 0x49CC, 0x07, 0x07))
							{
								const BYTE bySigMudrop2[] = {0xC7,0x45,0x08,0x6E,0x73,0x61,0x00};
								if(_memicmp(byMudropSigbuff, bySigMudrop2, sizeof(bySigMudrop2)) == 0)
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Dropper.Mudrop.asj"));
									return VIRUS_FILE_DELETE;
								}
							}
						}
					}
				}
				else if((m_pMaxPEFile->ReadBuffer(byMudropSigbuff, dwFileNameOffset + 0x28, 0x08, 0x08)))
				{
					if(*(DWORD *)&byMudropSigbuff[0] == 0x00D39F && *(DWORD *)&byMudropSigbuff[4] == 0x6578652E)
					{
						if(m_pMaxPEFile->ReadBuffer(byMudropSigbuff,dwFileNameOffset+0x4C+0x3C,0x04,0x04))
						{
							DWORD dwOffsetToPE = *(DWORD *)&byMudropSigbuff[0];
							if(m_pMaxPEFile->ReadBuffer(byMudropSigbuff, dwOffsetToPE + dwFileNameOffset + 0x4C + 0x14, 0x04, 0x04))
							{
								DWORD dwSizeOfOE = *(WORD *)&byMudropSigbuff[0];
								if(m_pMaxPEFile->ReadBuffer(byMudropSigbuff, dwOffsetToPE + dwSizeOfOE + dwFileNameOffset + 0x4C + 0x30, 0x04, 0x04))
								{
									if(*(DWORD *)&byMudropSigbuff[0] == 0x32434550) //Checking for PEC2 at the particular offset
									{
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Dropper.Mudrop.asj"));
										return VIRUS_FILE_DELETE;
									}
								}
							}
						}
					}
				}
			}
		}
		else if(m_dwAEPUnmapped == 0x13B0)
		{
			//Case to delete the file after unpacking from PeCompact
			if(m_pMaxPEFile->ReadBuffer(byMudropSigbuff, 0x2128, 0x50, 0x50))
			{
				const BYTE bySigMudrop[] = {0x68,0x00,0x74,0x00,0x74,0x00,0x70,0x00,0x3A,0x00,0x2F,0x00,0x2F,0x00,0x64,0x00,0x6F,0x00,0x77,0x00,0x6E,0x00,0x2E,0x00,0x39,0x00,0x37,
					0x00,0x31,0x00,0x39,0x00,0x39,0x00,0x2E,0x00,0x63,0x00,0x6F,0x00,0x6D,0x00,0x2F,0x00,0x69,0x00,0x6E,0x00,0x73,0x00,0x74,0x00,0x61,0x00,0x6C,0x00,0x6C,0x00,0x32,0x00,
					0x2F,0x00,0x3F,0x00,0x73,0x00,0x6C,0x00,0x33};

				if(memcmp(byMudropSigbuff, bySigMudrop, sizeof(bySigMudrop)) == 0)
				{
					if(m_pMaxPEFile->ReadBuffer(byMudropSigbuff, 0x265E, 0xB, 0xB))
					{
						const BYTE bySigMudrop2[]={0x2F,0x00,0x63,0x00,0x20,0x00,0x64,0x00,0x65,0x00,0x6C};
						if(memcmp(byMudropSigbuff, bySigMudrop2, sizeof(bySigMudrop2)) == 0)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Dropper.Mudrop.asj"));
							return VIRUS_FILE_DELETE;
						}
					}
				}
			}
		}
		else
		{
			//Case to delete the second dropped file
			BYTE byMudropSigbuff[0x20]={0};
			if(!m_pMaxPEFile->ReadBuffer(byMudropSigbuff,0x8A04,0x12,0x12))
			{
				return iRetStatus;
			}

			const BYTE bySigMudrop[] = {0xEF,0xBE,0xAD,0xDE,0x4E,0x75,0x6C,0x6C,0x73,0x6F,0x66,0x74,0x49,0x6E,0x73,0x74,0x41,0x24};
			if(memcmp(byMudropSigbuff, bySigMudrop, sizeof(bySigMudrop)) == 0)
			{
				if(!m_pMaxPEFile->ReadBuffer(byMudropSigbuff,0x49CC,0x07,0x07))
				{
					return iRetStatus;
				}

				const BYTE bySigMudrop2[] = {0xC7,0x45,0x08,0x6E,0x73,0x61,0x00};
				if(_memicmp(byMudropSigbuff, bySigMudrop2, sizeof(bySigMudrop2)) == 0)
				{
					if(m_pMaxPEFile->ReadBuffer(byMudropSigbuff,0x5091,0x20,0x20))
					{
						const BYTE bySigMudrop3[]={0x8B,0xF0,0x81,0xE6,0xFF,0x00,0x00,0x00,0x33,0xF7,0xC1,0xE8,0x08,0x8B,0x34,0xB5,0x00,0x2A,0x42,0x00,0x33,0xC6,0x41,0x4A};
						if(memcmp(byMudropSigbuff, bySigMudrop3, sizeof(bySigMudrop3)) == 0)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Dropper.Mudrop.asj"));
							return VIRUS_FILE_DELETE;
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectInstallCoreA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Dundun Family
					  A : InstallCode.A is Packed Installer which on installation installs webtoolbar without user knowladge.
					  B : Webtoolbar is showing for showing Add hence Adware Category.
					  C : Webtoolbar dose not contains any malicious activity, but it is getting installed without user Intervention,
						So, given 'not-a-virus' sub-category.
					  D : In this version, installer may contains different softwares like, FLV Player, PDF Reader, etc.
					  E : Size of File ranges from 1MB to 1.45MB with typical setup icons.
--------------------------------------------------------------------------------------*/
int CTrojans::DetectInstallCoreA()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
		return iRetStatus;
	
	//1 : Below detection routine is for Mini-Delphi Compiled files.
	if((m_wNoOfSections == 0x08) && 
		(m_pMaxPEFile->m_stPEHeader.Characteristics == 0x818F || m_pMaxPEFile->m_stPEHeader.Characteristics == 0x818E) &&
		(m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x19) &&
		(m_pMaxPEFile->m_stPEHeader.SizeOfImage > m_pSectionHeader[7].PointerToRawData + m_pSectionHeader[7].SizeOfRawData))
	{
		if((m_pSectionHeader[0].SizeOfRawData >= 0xC1000 && m_pSectionHeader[0].SizeOfRawData <= 0xC5C00) &&
			((m_pSectionHeader[1].SizeOfRawData >= 0x5000 && m_pSectionHeader[1].SizeOfRawData <= 0x5200) &&
			(m_pSectionHeader[1].Misc.VirtualSize >= 0x4ED0 && m_pSectionHeader[1].Misc.VirtualSize <= 0x5114))&&
			(m_pSectionHeader[2].SizeOfRawData == 0x00 && m_pSectionHeader[2].Misc.VirtualSize >= 0x3C00) &&
			((m_pSectionHeader[3].SizeOfRawData >= 0x3200 && m_pSectionHeader[3].SizeOfRawData <= 0x3400) &&
			(m_pSectionHeader[3].Misc.VirtualSize >= 0x314A && m_pSectionHeader[3].Misc.VirtualSize <= 0x3300)) &&
			(m_pSectionHeader[4].SizeOfRawData == 0x00 && m_pSectionHeader[4].Misc.VirtualSize == 0x10) &&
			(m_pSectionHeader[5].SizeOfRawData == 0x200 && m_pSectionHeader[5].Misc.VirtualSize == 0x18) &&
			(m_pSectionHeader[6].SizeOfRawData >= 0xB000 && m_pSectionHeader[6].SizeOfRawData <= 0xB600) &&
			(m_pSectionHeader[m_wNoOfSections - 1].Characteristics == 0x50000040))
		{					
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}

			const int INSTALLCORE_BUFF_SIZE = 0x200;
			m_pbyBuff = new BYTE[INSTALLCORE_BUFF_SIZE];
			
			DWORD dwOffset = m_pSectionHeader[0x00].PointerToRawData + m_pSectionHeader[0x00].SizeOfRawData - 0x500;			
			if(!GetBuffer(dwOffset, INSTALLCORE_BUFF_SIZE, INSTALLCORE_BUFF_SIZE))
			{
				return iRetStatus;
			}

			CMaxBMAlgo *pBMScan = new CMaxBMAlgo;
			if(pBMScan == NULL)
			{
				return iRetStatus;
			}

			BYTE bySig1[] = {0x49,0x6E,0x73,0x74,0x61,0x6C,0x6C,0x43,0x6F,0x72,0x65};		//InstallCore Name
			BYTE bySig2[] = {0x57,0x7A,0x74,0x73,0x70,0x67,0x67,0x58,0x63,0x6B,0x76};
			BYTE bySig3[] = {0x44,0x76,0x77,0x6F,0x70,0x65,0x65,0x42,0x74,0x7A,0x6C,0x3D,0x2D,0x6E};	
			BYTE bySig4[] = {0x4B,0x76,0x66,0x70,0x79,0x78,0x78,0x46,0x6D,0x65,0x72,0x3E,0x2F,0x6E};	
		
			if(pBMScan->AddPatetrn2Search(bySig1, sizeof(bySig1)))
			{
				if(pBMScan->Search4Pattern(m_pbyBuff, m_dwNoOfBytes))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:Adware.InstallCore.A"));
					iRetStatus = VIRUS_FILE_DELETE;
				}
			}
			if(iRetStatus == VIRUS_NOT_FOUND && pBMScan->AddPatetrn2Search(bySig2, sizeof(bySig2)))
			{
				if(pBMScan->Search4Pattern(m_pbyBuff, m_dwNoOfBytes))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:Adware.InstallCore.m"));
					iRetStatus = VIRUS_FILE_DELETE;
				}
			}
			if(iRetStatus == VIRUS_NOT_FOUND && pBMScan->AddPatetrn2Search(bySig3, sizeof(bySig3)))
			{
				if(pBMScan->Search4Pattern(m_pbyBuff, m_dwNoOfBytes))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:Adware.InstallCore.e"));
					iRetStatus = VIRUS_FILE_DELETE;
				}
			}
			if(iRetStatus == VIRUS_NOT_FOUND && pBMScan->AddPatetrn2Search(bySig4, sizeof(bySig4)))
			{
				if(pBMScan->Search4Pattern(m_pbyBuff, m_dwNoOfBytes))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:Adware.InstallCore.q"));
					iRetStatus = VIRUS_FILE_DELETE;
				}
			}

			if(pBMScan)
			{
				delete pBMScan;
				pBMScan = NULL;
			}

			if(iRetStatus == VIRUS_FILE_DELETE)
			{
				return iRetStatus;
			}
		}
	}

	//2 : Below detection routine is for Fake UPX Files.
	//File contains all the caracteristics of UPX File but it is not orthodox UPX packer.  
	if((m_wNoOfSections == 0x03) &&
		(memcmp(m_pSectionHeader[0].Name, "UPX0", 4) == 0) && 
		(m_pSectionHeader[0].SizeOfRawData > 0x00) &&
		(m_pMaxPEFile->m_stPEHeader.Characteristics == 0x818F) &&
		(m_pMaxPEFile->m_stPEHeader.CheckSum != 0x00) &&
		(m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x19) &&
		(m_pMaxPEFile->m_stPEHeader.SizeOfImage > m_pSectionHeader[7].PointerToRawData + m_pSectionHeader[7].SizeOfRawData))
	{
		if((m_pSectionHeader[0].SizeOfRawData == m_pSectionHeader[0].Misc.VirtualSize) &&
			(m_pSectionHeader[0].SizeOfRawData >= 0x68000 && m_pSectionHeader[0].SizeOfRawData <= 0x96000) &&
			(m_pSectionHeader[1].SizeOfRawData >= 0x78000 && m_pSectionHeader[1].SizeOfRawData <= 0x9b000))
		{
			DWORD TLSSize = 0x00;
			if(m_pMaxPEFile->ReadBuffer(&TLSSize, 0x1C4, 4, 4))
			{
				if(!(TLSSize == 0x18))
				{
					return iRetStatus;
				}
			}

			//UPX Header
			BYTE	bySig[] = {0x33,0x2E,0x30,0x33,0x00,0x55,0x50,0x58,0x21};
			BYTE	ABuff[0x0A] = {0x00};

			if(m_pMaxPEFile->ReadBuffer(&ABuff ,0x3DB, 0x0A, 0x0A))
			{
				if(memcmp(&ABuff[0x00], bySig, sizeof(bySig)) != 0x00)
				{
					return iRetStatus;
				}
			}
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			m_pbyBuff = new BYTE[0x150];
		
			if(!GetBuffer(0xCB0, 0x150, 0x150))
			{
				return iRetStatus;
			}

			
			TCHAR			szSig[] = {_T("530C8B430803430CE8DBFCFFFF837C24*338D4C240C8D5424048BC5E85DFBFFFF837C240C0075")};
			CSemiPolyDBScn	polydbObj;
			polydbObj.LoadSigDBEx(szSig, _T("not-a-virus:Adware.InstallCore.A"), FALSE);

			TCHAR			szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], 0x150, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectFrauDropXYRW
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of FrauDrop.xyrw Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectFrauDropXYRW()
{
	WORD MajorOSVersion = 0 , MajorSubsystemVersion = 0, MajorLinkerVersion = 0;
	m_pMaxPEFile->ReadBuffer(&MajorLinkerVersion, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x1A, 2, 2);
	m_pMaxPEFile->ReadBuffer(&MajorOSVersion, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x40, 2, 2);
	m_pMaxPEFile->ReadBuffer(&MajorSubsystemVersion, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x48, 2, 2);

	if(m_wNoOfSections >= 0x06 && (m_wAEPSec == 0 || m_wAEPSec == 1) &&
	   MajorLinkerVersion == 0x0A  && m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0 &&
	   MajorOSVersion == 0x05 && m_pMaxPEFile->m_stPEHeader.MinorOSVersion == 0x01 &&
	   MajorSubsystemVersion == 0x05 && m_pMaxPEFile->m_stPEHeader.MinorSubsystemVersion == 0x01 && 
	   m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress > 0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress > 0 &&
	   (m_pSectionHeader[0].Characteristics & 0x60000020) == 0x60000020 && (m_pSectionHeader[1].Characteristics & 0x60000020) == 0x60000020)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x20];
		if(GetBuffer(m_dwAEPMapped, 0x20, 0x20))
		{
			if(m_pbyBuff[0] == 0xE9 || m_pbyBuff[0] == 0x55 || m_pbyBuff[0] == 0x68)
			{
				DWORD dwOffset = 0;
				if(m_pbyBuff[0] == 0xE9)
				{
					dwOffset = *(DWORD *)&m_pbyBuff[1] + 5 + m_dwAEPUnmapped;
				}
				else if(m_pbyBuff[0] == 0x68)
				{
					dwOffset = *(DWORD *)&m_pbyBuff[1] - m_dwImageBase;
				}
				else if(m_pbyBuff[0] == 0x55)
				{
					dwOffset = m_dwAEPUnmapped;
				}
				if(dwOffset != 0 && OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOffset, &dwOffset))
				{
					if(GetBuffer(dwOffset, 0x20, 0x20))
					{
						const BYTE XYRW_SIG[] = {0x55, 0x89, 0xE5, 0xFF, 0x34, 0x2D, 0x14, 0x00, 0x00, 0x00, 0xFF, 0x34, 0x2D, 0x10, 0x00, 0x00,
												 0x00, 0xFF, 0x34, 0x2D, 0x0C, 0x00, 0x00, 0x00, 0xFF, 0x34, 0x2D, 0x08, 0x00, 0x00, 0x00, 0xE8};

						if(!memcmp(m_pbyBuff, XYRW_SIG, sizeof(XYRW_SIG)))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan-Dropper.W32.FrauDrop.xyrw"));
							return VIRUS_FILE_DELETE;
						}
					}
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectChifraxD
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Chifrax.D Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectChifraxD()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == 0x00 && ((m_pSectionHeader[0].Characteristics & 0x60000020) == 0x60000020 || (m_pSectionHeader[0].Characteristics & 0xE0000080) == 0xE0000080)&&
		(m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL &&
		(m_dwAEPUnmapped == 0x645C || m_dwAEPUnmapped == 0x323F || m_dwAEPUnmapped == 0x30FA) &&
		(m_wNoOfSections == 0x3 || m_wNoOfSections == 0x5) && 
		(m_pSectionHeader[0].PointerToRawData == 0x400 || m_pSectionHeader[0].PointerToRawData == 0x1000) &&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress == 0x0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].Size == 0x0 &&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0x2].Size > 0x5C08)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int CHIFRAXD_BUFF_SIZE = 0x3500;
		m_pbyBuff = new BYTE[CHIFRAXD_BUFF_SIZE];
		const BYTE CHIFRAXD_SIG[] = {0x49,0x58,0x50,0x25,0x30,0x33,0x64,0x2E,0x54,0x4D,0x50};
		if(!GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData + 0x368, 0x15, 0x15))
		{
			return iRetStatus;
		}
		if(memcmp(&m_pbyBuff[0], CHIFRAXD_SIG, sizeof(CHIFRAXD_SIG)) == 0)
		{
			DWORD dwChkValue = 0 , dwChkValue1 = 0, dwBuffSize = 0;
			if(m_pSectionHeader[0].PointerToRawData == 0x1000)
			{
				if(!m_pMaxPEFile->ReadBuffer(&dwChkValue, 0x6B5E, sizeof(DWORD), sizeof(DWORD)))
				{
					return iRetStatus;
				}
				if(!m_pMaxPEFile->ReadBuffer(&dwChkValue1, 0x7458, sizeof(DWORD), sizeof(DWORD)))
				{
					return iRetStatus;
				}
			}
			else if(m_pSectionHeader[0].PointerToRawData == 0x400)
			{
				if(!m_pMaxPEFile->ReadBuffer(&dwChkValue, 0x5F5E, sizeof(DWORD), sizeof(DWORD)))
				{ 
					return iRetStatus;
				}
				if(!m_pMaxPEFile->ReadBuffer(&dwChkValue1, 0x6858, sizeof(DWORD), sizeof(DWORD)))
				{
					return iRetStatus;
				}
			}
			if(dwChkValue == dwChkValue1 && dwChkValue != 0x4643534D && dwChkValue1 != 0x4643534D) 
			{
				const BYTE CHIFRAXD_SIG1[] = {0x41,0x00,0x44,0x00,0x4D,0x00,0x51,0x00,0x43,0x00,0x4D,0x00,0x44};
				const BYTE CHIFRAXD_SIG2[] = {0x55,0x00,0x50,0x00,0x52,0x00,0x4F,0x00,0x4D,0x00,0x50,0x00,0x54,0x00,0x07,0x00,0x55,0x00,0x53,0x00,0x52,0x00,0x51,0x00,0x43,0x00,0x4D,0x00,0x44};
				if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBuffSize],m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + 0x300, 0x2000, 0x2000))
				{
					return iRetStatus;
				}
				dwBuffSize += 0x2000;
				if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBuffSize],m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + 0x2500, 0x1500, 0x1500))
				{
					return iRetStatus;
				}
				for(DWORD i = 0; i <= CHIFRAXD_BUFF_SIZE - sizeof(CHIFRAXD_SIG1); i++)
				{
					if(memcmp(&m_pbyBuff[i],CHIFRAXD_SIG1, sizeof(CHIFRAXD_SIG1)) == 0)
					{
						for(DWORD j = 0; j <= CHIFRAXD_BUFF_SIZE - sizeof(CHIFRAXD_SIG2); j++)
						{
							if(memcmp(&m_pbyBuff[j],CHIFRAXD_SIG2, sizeof(CHIFRAXD_SIG2)) == 0)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Chifrax.D"));
								return VIRUS_FILE_DELETE;
							}
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectObfuscatedGen
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Heuristic Detection Technique
				      A : Few Important Header feild which has predefine logic,
						from PE Header's perspective.
					  B : Few compiler related check from header.
					  IMP : It is a Generic detection technique and can be lead to 
							False Detection ((+)ve Positive aswell as false (-)ve).
--------------------------------------------------------------------------------------*/
int CTrojans::DetectObfuscatedGen(void)
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
		return iRetStatus;
	
	if (m_pMaxPEFile->m_wAEPSec != 0x00)
		return iRetStatus;

	DWORD	dwRem = 0x00;

	dwRem = (m_pMaxPEFile->m_stPEHeader.SizeOfImage % m_pMaxPEFile->m_stPEHeader.FileAlignment);
	if (dwRem == 0x00)
		return iRetStatus;

	DWORD	dwNTHdrStart =  m_pMaxPEFile->m_stPEHeader.e_lfanew;
	DWORD	dwSecStart = 0x00;
	BYTE	bPrimarySig[] = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	BYTE	bSecSig[] = {0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int DUMMY_BUFF_SIZE = 0x10;
	m_pbyBuff = new BYTE[DUMMY_BUFF_SIZE];

	if ((dwNTHdrStart + 0x60) > m_pMaxPEFile->m_dwFileSize)
	{
		return iRetStatus;
	}

	dwSecStart = dwNTHdrStart + 0x40;
	memset(&m_pbyBuff[0x00],0x00,sizeof(m_pbyBuff));
	if(!GetBuffer(dwSecStart, DUMMY_BUFF_SIZE, 0x10))
	{
		return iRetStatus;
	}
	if (memcmp(&m_pbyBuff[0x00],&bPrimarySig[0x00],0x10) != 0x00)
	{
		return iRetStatus;
	}

	dwSecStart = dwNTHdrStart + 0x58;
	memset(&m_pbyBuff[0x00],0x00,sizeof(m_pbyBuff));
	if(!GetBuffer(dwSecStart, DUMMY_BUFF_SIZE, 0x08))
	{
		return iRetStatus;
	}
	if (memcmp(&m_pbyBuff[0x00],&bSecSig[0x00],0x08) == 0x00)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Obfuscated.Gen"));
		return VIRUS_FILE_DELETE; 
	}

	return iRetStatus; 
}

/*-------------------------------------------------------------------------------------
	Function		: DetectOnlineGameAndWOWMagania
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Gamethief.OnLineGames Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectOnlineGameAndWOWMagania()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	const int WOW_BUFF_SIZE = 0x128;
	DWORD dwOverLayStart=m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData +  m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
	DWORD dwOverLaySize= m_pMaxPEFile->m_dwFileSize - dwOverLayStart;
	if(dwOverLaySize > 0x1000 || dwOverLaySize < WOW_BUFF_SIZE + 0x100)
	{
		return iRetStatus;
	}
	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[WOW_BUFF_SIZE];

	if(!GetBuffer(dwOverLayStart + 0x100, WOW_BUFF_SIZE, WOW_BUFF_SIZE))
	{		
		return iRetStatus;		
	}

	const BYTE ONLINE_SIG1[] = {0x63, 0x77, 0x77, 0x6B, 0x3D, 0x2C, 0x2C}; //cwwk=,,
	const BYTE ONLINE_SIG2[] = {0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB};
	const BYTE ONLINE_SIG3[] = {0x36, 0x36, 0x36, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB};
	
	if(*(DWORD *)&m_pbyBuff[0x124] != 0x00)
	{
		for(DWORD OffsetAdd = 0; OffsetAdd < WOW_BUFF_SIZE - (0xB4 + sizeof(ONLINE_SIG3));  OffsetAdd++)
		{
			if(memcmp(&m_pbyBuff[OffsetAdd], ONLINE_SIG1, sizeof(ONLINE_SIG1)) == 0 &&
				(memcmp(&m_pbyBuff[OffsetAdd + 0x5A], ONLINE_SIG1, sizeof(ONLINE_SIG1)) == 0 ||
				memcmp(&m_pbyBuff[OffsetAdd + 0x5A], ONLINE_SIG2, sizeof(ONLINE_SIG2)) == 0 ) &&
				memcmp(&m_pbyBuff[OffsetAdd + 0xB4], ONLINE_SIG3, sizeof(ONLINE_SIG3)) == 0)
			{
				//Magania(dgrw,dgwq,dhws,diti,dkei,dkwq,dnyp,dpzc,dtcd),WOW(aauc,abbh,abch,yqt),OnLineGames(bnjq,bnkb,bnow,bnpp),Nbdd.adj
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Trojan-GameThief.W32.OnLineGames"));
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAgentCWA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Agent.CWA Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectAgentCWA()
{
	int iRetStatus = VIRUS_NOT_FOUND;	

	if(m_wAEPSec == 0 && m_wNoOfSections == 0x4 &&
		(m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x400 && memcmp(m_pSectionHeader[m_wAEPSec + 0x2].Name, ".data", 5)== 0) && 
		m_pSectionHeader[m_wAEPSec].Characteristics == 0x60000020 && m_pSectionHeader[m_wAEPSec + 0x2].Characteristics == 0xC0000040)
	{
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		const int BUFF_SIZE = 0x40;
		m_pbyBuff = new BYTE[BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff,0x00,BUFF_SIZE + MAX_INSTRUCTION_LEN);

		if(GetBuffer(m_dwAEPMapped, BUFF_SIZE, BUFF_SIZE))
		{
			if(m_pbyBuff[0x00] == 0x6A && m_pbyBuff[0x01] == 0x02 && m_pbyBuff[0x2] == 0x6A && m_pbyBuff[0x3] == 0x00 && m_pbyBuff[0x4] == 0x68)
			{
				BYTE DLLCHECK[] = {0x6D,0x00,0x63,0x00,0x69,0x00,0x71,0x00,0x74,0x00,0x7A,0x00,0x33,0x00,0x32,0x00,0x2E,0x00,0x64,0x00,0x6C,0x00,0x6C};//m.c.i.q.t.z.3.2...d.l.l
				DWORD	dwLength = 0, dwOffset = 0, dwInstCount = 0,dwCallDllOffset = 0;
				t_disasm da = {0};
				while(dwOffset < BUFF_SIZE && dwInstCount < 0xC)
				{
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			
					if(dwLength > BUFF_SIZE - dwOffset)
					{
						break;
					}
					if((dwInstCount == 0x00 ||dwInstCount == 0x01)  && dwLength == 2  && strstr(da.result,"PUSH"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x02 && dwLength == 5  && strstr(da.result,"PUSH"))
					{
						dwCallDllOffset = *(DWORD *)&m_pbyBuff[dwOffset+ 0x1] - m_dwImageBase;
						if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwCallDllOffset, &dwCallDllOffset))
						{
							return iRetStatus;
						}
						if(dwCallDllOffset == 0x0)
						{
							return iRetStatus;
						}
						BYTE pbyBuffer[0x25] = {0};
						if(!m_pMaxPEFile->ReadBuffer(pbyBuffer, dwCallDllOffset, sizeof(DLLCHECK), sizeof(DLLCHECK)))
						{
							return iRetStatus;
						}

						if(memcmp(&pbyBuffer[0x0], DLLCHECK, sizeof(DLLCHECK)) != 0x00)
						{
							return iRetStatus;
						}
						dwInstCount++;
					}
					else if(dwInstCount == 0x03 && dwLength == 2  && strstr(da.result,"PUSH"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x04 && dwLength == 5  && strstr(da.result,"CALL"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x05 && dwLength == 3 && strstr(da.result,"SUB"))
					{  
						dwInstCount++;
					}
					else if(dwInstCount == 0x06 && dwLength == 5 && strstr(da.result,"CALL"))
					{  
						dwInstCount++;						
					}
					else if((dwInstCount == 0x07  || dwInstCount == 0x08 )&& dwLength == 3 && strstr(da.result,"MOV E"))
					{  
						dwInstCount++;						
					}
					else if(dwInstCount == 0x09 && dwLength == 1 && strstr(da.result,"PUSHAD"))
					{  
						dwInstCount++;						
					}
					else if(dwInstCount == 0x0A && dwLength == 2 && strstr(da.result,"MOV AH"))
					{  
						dwInstCount++;						
					}
					else if(dwInstCount == 0x0B && dwLength == 1  && strstr(da.result,"POPAD"))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Trojan.Agent.CWA"));
						return VIRUS_FILE_DELETE;
					}
					dwOffset += dwLength;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Mangesh Fasale + Mukesh +  Virus Analysis Team
	Description		: Detection routine for different varients of Worm.Sytro Family
					  Worm.Sytro.k, Worm.Sytro.z, Worm.Sytro.J, Worm.Sytro.O
					  A : It is UPX compressed with worm with size changes according to variants.
					  B : It is a replicating P2p worm, which can spread in network using "KAZAA" file sharing Network.	
					  C : Dropes file in %windir%\Temp folder and %temp% folder of current user. (These strings are use as signature)	
--------------------------------------------------------------------------------------*/
int CTrojans::DetectSytro()
{
	if((m_dwAEPUnmapped == 0x1B0B8 || m_dwAEPUnmapped == 0x1B034 || m_dwAEPUnmapped == 0x14FC0 || m_dwAEPUnmapped == 0x1AFD4 || m_dwAEPUnmapped == 0xE330 || m_dwAEPUnmapped == 0xE274 )
		&& (m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x19))
	{
		DWORD dwReadOffset = 0;
		m_pMaxPEFile->ReadBuffer(&dwReadOffset, m_dwAEPMapped - 0x10, sizeof(DWORD), sizeof(DWORD));
		m_pMaxPEFile->Rva2FileOffset(dwReadOffset - m_dwImageBase, &dwReadOffset);

		int	iSecNo = 0x00;
		if (m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x03)
		{
			iSecNo = m_pMaxPEFile->m_wAEPSec;
		}
		for(iSecNo = 0; iSecNo <= 1; iSecNo++)        // added for checking sign in 2nd section for some samples of Worm.sytro.o
		{
			if(dwReadOffset > m_pSectionHeader[iSecNo].PointerToRawData && 
				dwReadOffset < m_pSectionHeader[iSecNo].PointerToRawData + m_pSectionHeader[iSecNo].SizeOfRawData)
			{
				if(CheckSytroSig(dwReadOffset))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Worm.Sytro.k"));
					return VIRUS_FILE_DELETE;
				}
			}
		}

		m_pMaxPEFile->ReadBuffer(&dwReadOffset, m_dwAEPMapped - 0x18, sizeof(DWORD), sizeof(DWORD));
		m_pMaxPEFile->Rva2FileOffset(dwReadOffset-m_dwImageBase,&dwReadOffset);
		if(dwReadOffset > m_pSectionHeader[0].PointerToRawData && 
			dwReadOffset < m_pSectionHeader[0].PointerToRawData + m_pSectionHeader[0].SizeOfRawData)
		{
			if(CheckSytroSig(dwReadOffset))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Worm.Sytro.z"));
				return VIRUS_FILE_DELETE;
			}
		}

	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSytroSig
	In Parameters	: DWORD dwReadOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Mangesh + Virus Analysis Team
	Description		: Reads buffer from given location and searches for Systro Signature.
--------------------------------------------------------------------------------------*/
bool CTrojans :: CheckSytroSig(DWORD dwReadOffset)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int SYTRO_BUFF_SIZE = 0x1000;
	m_pbyBuff = new BYTE[SYTRO_BUFF_SIZE];
	if(!m_pbyBuff)
	{
		return false;
	}

	memset(m_pbyBuff, 0, SYTRO_BUFF_SIZE);
	if(GetBuffer(dwReadOffset, SYTRO_BUFF_SIZE, 0x8A0))
	{
		DWORD dwCount = 0, dwKcount = 0;
		//Bam Margera World In
		const BYTE	bySig[] = {0x42, 0x61, 0x6D, 0x20, 0x4D, 0x61, 0x72, 0x67, 0x65, 0x72, 0x61, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x20, 0x49, 0x6E};
		//Cat Attacks Child
		const BYTE	bySig1[]= {0x43, 0x61, 0x74, 0x20, 0x41, 0x74, 0x74, 0x61, 0x63, 0x6B, 0x73, 0x20, 0x43, 0x68, 0x69, 0x6C, 0x64};
		//Hacker and Stealer
		const BYTE	bySig2[]= {0x48, 0x61, 0x63, 0x6B, 0x65, 0x72, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x53, 0x74, 0x65, 0x61, 0x6C, 0x65, 0x72};
		//KaZaA
		const BYTE bySig3[] = {0x4B, 0x61, 0x5A, 0x61, 0x41};
               
                //Hack into any computer!!.exe
		const BYTE bySig4[] = {0x48, 0x61, 0x63, 0x6B, 0x20, 0x69, 0x6E, 0x74, 0x6F, 0x20, 0x61, 0x6E, 0x79, 0x20, 0x63, 0x6F, 0x6D, 0x70, 0x75, 0x74, 0x65 , 0x72, 0x21, 0x21, 0x2E, 0x65, 0x78, 0x65}; //added

		for (DWORD dwIndex = 0; dwIndex <= m_dwNoOfBytes - sizeof(bySig); dwIndex++)
		{
			if((memcmp(&m_pbyBuff[dwIndex], bySig, sizeof(bySig))== 0) || 
				(memcmp(&m_pbyBuff[dwIndex],bySig1,sizeof(bySig1))==0) || 
				(memcmp(&m_pbyBuff[dwIndex],bySig2,sizeof(bySig2))==0) ||
				(memcmp(&m_pbyBuff[dwIndex],bySig4,sizeof(bySig4))== 0)) 
			{
				dwCount++;
			}
			else if(memcmp(&m_pbyBuff[dwIndex], bySig3, sizeof(bySig3))== 0) 
			{
				dwKcount++;
			}

			if( dwCount == 3 && dwKcount == 1)
			{
				return true;
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSefnit
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Mangesh Fasale + Virus Analysis Team
	Description		: 1) These are DLL files droped by NSIS and executed by rundll32.exe.
					  2) Trojan monitor's search result from all internet browser, and redirect to malicious sites
--------------------------------------------------------------------------------------*/
int CTrojans::DetectSefnit()
{
	int iRetStatus = VIRUS_NOT_FOUND;	

	if(	m_wAEPSec == 0 && m_wNoOfSections == 0x4 && m_dwAEPMapped == m_dwAEPUnmapped &&
		m_pMaxPEFile->m_stPEHeader.Characteristics == 0x2102 && m_dwImageBase == 0x10000000 &&
		m_pMaxPEFile->m_stSectionHeader[0].PointerToRawData == 0x1000 &&
		m_pMaxPEFile->m_stSectionHeader[2].SizeOfRawData <= 0x3000 &&
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[0].Size > 0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[0].Size <= 0xB0))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int SEFNIT_BUFF_SIZE = 0x2000;
		m_pbyBuff = new BYTE[SEFNIT_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}		
		memset(m_pbyBuff, 0, SEFNIT_BUFF_SIZE);
		if(GetBuffer(m_pMaxPEFile->m_stSectionHeader[1].PointerToRawData - 0x2000, SEFNIT_BUFF_SIZE, 0x1000))
		{
			DWORD	dwIndex = 0x00, dwEndOff = 0x00;
			int		nSigNo = 0; 
			bool	bCheck = false;

			const BYTE bySig1[] = {0x89, 0x04, 0x8F};
			const BYTE bySig2[] = {0x89, 0x14, 0x8F};
			const BYTE bySig3[] = {0x89, 0x0C, 0xBA};
			const BYTE bySig4[] = {0x89, 0x3c, 0x8A};

			for(; dwIndex <= m_dwNoOfBytes - sizeof(bySig1); dwIndex++)
			{
				if(memcmp(&m_pbyBuff[dwIndex], bySig1, sizeof(bySig1)) == 0)
				{
					nSigNo = 0x01;
					break;
				}
				else if(memcmp(&m_pbyBuff[dwIndex], bySig2, sizeof(bySig2)) == 0)
				{
					nSigNo = 0x02;
					break;
				}
				else if(memcmp(&m_pbyBuff[dwIndex], bySig3, sizeof(bySig3)) == 0)
				{
					nSigNo = 0x03;
					break;
				}
				else if(memcmp(&m_pbyBuff[dwIndex], bySig4, sizeof(bySig4)) == 0)
				{
					nSigNo = 0x04;
					break;
				}
			}

			dwEndOff = (m_dwNoOfBytes > dwIndex + 0x50) ? (dwIndex + 0x50) : m_dwNoOfBytes;
			dwIndex = (dwIndex > 0x100) ? (dwIndex - 0x100) : 0;

			BYTE bySig1_1[] = {0x8B, 0x04, 0x8E};//, 0x35};
			BYTE bySig2_1[] = {0x8B, 0x14, 0x8E};//, 0x81, 0xF2};
			BYTE bySig3_1[] = {0x8B, 0x0C, 0xBE};//, 0x81, 0xF1};
			BYTE bySig4_1[] = {0x8B, 0x3C, 0x8E};//, 0x81, 0xF7};
			BYTE byTemp = 0;

			switch(nSigNo)
			{
			case 0x01 :

				while(dwEndOff > dwIndex)
				{
					if(memcmp(&m_pbyBuff[dwIndex], bySig1_1, sizeof(bySig1_1))== 0)
					{
						dwIndex += sizeof(bySig2_1);
						while(m_pbyBuff[dwIndex] == 0xEB)
						{
							byTemp = m_pbyBuff[dwIndex + 1]; 

							if(byTemp < 0x7F)
							{
								dwIndex += byTemp + 2;
							}
							else
							{
								dwIndex +=(DWORD)byTemp + 0xFFFFFF00 + 2;
							}
							if(m_pbyBuff[dwIndex] == 0x35)
							{
								bCheck = true;
								break;
							}
						}	
						if(m_pbyBuff[dwIndex] == 0x35)
						{
							bCheck = true;
							break;
						}
					}
					if(bCheck) break;
					else dwIndex++;
				}
				break;

			case 0x02 :

				while(dwEndOff > dwIndex)
				{
					if(memcmp(&m_pbyBuff[dwIndex], bySig2_1, sizeof(bySig2_1))== 0)
					{
						dwIndex += sizeof(bySig2_1);
						while(m_pbyBuff[dwIndex] == 0xEB)
						{
							byTemp = m_pbyBuff[dwIndex + 1]; 

							if(byTemp < 0x7F)
							{
								dwIndex += byTemp + 2;
							}
							else
							{
								dwIndex +=(DWORD)byTemp + 0xFFFFFF00 + 2;
							}
							if(*(WORD*)&m_pbyBuff[dwIndex] == 0xF281)
							{
								bCheck = true;
								break;
							}

						}
						if(*(WORD*)&m_pbyBuff[dwIndex] == 0xF281)
						{
							bCheck = true;
							break;
						}
					}
					if(bCheck) break;
					else dwIndex++;
				}
				break;

			case 0x03 :

				while(dwEndOff > dwIndex)
				{
					if(memcmp(&m_pbyBuff[dwIndex], bySig3_1, sizeof(bySig3_1))== 0)
					{
						dwIndex += sizeof(bySig3_1);
						while(m_pbyBuff[dwIndex] == 0xEB)
						{
							byTemp = m_pbyBuff[dwIndex + 1]; 

							if(byTemp < 0x7F)
							{
								dwIndex += byTemp + 2;
							}
							else
							{
								dwIndex +=(DWORD)byTemp+ 0xFFFFFF00 + 2;
							}

							if(*(WORD*)&m_pbyBuff[dwIndex] == 0xF181)
							{
								bCheck = true;
								break;
							}

						}
						if(*(WORD*)&m_pbyBuff[dwIndex] == 0xF181)
						{
							bCheck = true;
							break;
						}
					}
					if(bCheck) break;
					else dwIndex++;
				}
				break;

			case 0x04 :

				while(dwEndOff > dwIndex)
				{
					if(memcmp(&m_pbyBuff[dwIndex], bySig4_1, sizeof(bySig4_1))== 0)
					{
						dwIndex += sizeof(bySig4_1);
						while(m_pbyBuff[dwIndex] == 0xEB)
						{
							byTemp = m_pbyBuff[dwIndex +1]; 

							if(byTemp < 0x7F)
							{
								dwIndex += byTemp + 2;
							}
							else
							{
								dwIndex +=(DWORD)byTemp+ 0xFFFFFF00 + 2;
							}

							if(*(WORD*)&m_pbyBuff[dwIndex] == 0xF781)
							{
								bCheck = true;
								break;
							}

						}
						if(*(WORD*)&m_pbyBuff[dwIndex] == 0xF781)
						{
							bCheck = true;
							break;
						}
					}
					if(bCheck) break;
					else dwIndex++;
				}
				break;

			default:
				return iRetStatus;
			}

			if(bCheck)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Trojan.Sefnit"));
				return VIRUS_FILE_DELETE;
			}
		}
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectShiz
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of Shiz.gen Family
					  Drop it self at C:\Windows\AppPatch
					  Continuously keep watch at drop file, if we delete that file again it will drop
					  Create Runtime registry Entry
					  After executing it will move itselt to temp folder
--------------------------------------------------------------------------------------*/
int CTrojans::DetectShiz()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	if(m_pMaxPEFile->m_stPEHeader.e_lfanew != 0x80)
	{
		return iRetStatus;
	}
	DWORD dwBaseOfcode = 0;
	m_pMaxPEFile->ReadBuffer(&dwBaseOfcode, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x2C, 4, 4);
	if(dwBaseOfcode + 0x1000 < m_dwAEPUnmapped)
	{
		return iRetStatus;
	}
		
	if((m_wNoOfSections >= 0x06) &&
		(m_pMaxPEFile->m_stPEHeader.CheckSum != 0x00) &&
		(m_pSectionHeader[0].PointerToRawData == 0x400) &&
		(m_pSectionHeader[m_wAEPSec].SizeOfRawData == m_pMaxPEFile->m_stPEHeader.SizeOfCode) &&
		(m_pSectionHeader[m_wAEPSec].Characteristics == 0x60000020)&&
		((m_pMaxPEFile->m_stPEHeader.SizeOfCode >= 0x2000) && (m_pMaxPEFile->m_stPEHeader.SizeOfCode <= 0x3800)) &&
		(m_pSectionHeader[m_wAEPSec + 1].Misc.VirtualSize > m_pSectionHeader[m_wAEPSec + 1].SizeOfRawData) &&
		(memcmp(m_pSectionHeader[m_wNoOfSections - 2].Name, ".rsrc", 5) == 0 ) &&
		(m_pSectionHeader[m_wNoOfSections - 2].Characteristics == 0x40000040) &&
		((m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x400) && (m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData <= 0x600)) &&
		(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".reloc", 6) == 0 ))

	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Trojan.Shiz.gen"));
		return VIRUS_FILE_DELETE;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDownloaderTibs
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Bisht + Virus Analysis Team
	Description		: Detection routine for different varients of Tibs Family
					  A. The following files have been dropped to the system:
			   		  B. Folder/File Operations: Drop rootkit in "C:\WINDOWS\system32\" path and copy of it in "C:\WINDOWS\" 
						with a config file which contains a list of clients for the worm's peer-to-peer network. The peer names and access ports are encoded.
			         C. Registry Operation: Puts its entry in
						HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List\
						HKU\S-1-5-21-1292428093-1078081533-839522115-1003\Software\Microsoft\Windows\CurrentVersion\Run\
						Entry of driver:
						HKLM\SYSTEM\CurrentControlSet\Services\
						HKLM\SYSTEM\CurrentControlSet\Services\noskrnl.sys\ImagePath:
					Signature: Contains a DWORD from where decryption loops starts.
					Note: It drops a rootkit in the system.
--------------------------------------------------------------------------------------*/
int CTrojans::DetectDownloaderTibs()
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) && 
		(( m_wNoOfSections >= 3) && ( m_wNoOfSections <= 5)) &&
		((m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x4000) || 
		(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x3000) || 
		(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x2000)) &&
		((m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x200) || 
		(m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x4200) || 
		(m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x400)))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int TIBS_BUFF_SIZE = 0x80;
		m_pbyBuff = new BYTE[TIBS_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, TIBS_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(!GetBuffer(m_dwAEPMapped, TIBS_BUFF_SIZE, TIBS_BUFF_SIZE))
		{
			return iRetStatus;
		}

		DWORD	dwKey1 = 0x00, dwKey2 = 0x00;

		t_disasm da = {0x00};
		DWORD dwOffset = 0x14, dwCount1 = 0x01, dwProOffset = 0;
		while(dwOffset < TIBS_BUFF_SIZE)
		{
			DWORD dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwLength > (TIBS_BUFF_SIZE - dwOffset))
			{
				return iRetStatus;
			}				
			if((dwLength == 0x05) && (dwCount1 == 0x01) && (strstr(da.result, "MOV EDI,")))
			{
				dwProOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1];
				dwCount1++;
				dwKey1 = dwProOffset + 0xF4C25;
				if(dwKey1 < m_dwImageBase)
				{
					return iRetStatus;
				}
			}
			else if((dwLength == 0x05) && (dwCount1 == 0x02) && (strstr(da.result, "XOR EAX,")))
			{
				dwProOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1];
				dwKey2 = dwProOffset;
				break;				
			}
			dwOffset += dwLength;
		}

		if((dwKey1 == 0x00) ||  (dwKey2 == 0x00))
		{
			return iRetStatus;
		}
		DWORD dwSign1[] = {0x000000E8, 0x8100001B, 0x48ADFD00};
		DWORD dwSign[3]; 
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwKey1 - m_dwImageBase, &dwProOffset))
		{
			return iRetStatus;
		}

		for(int nSigNo = 0; nSigNo < 3; nSigNo++)
		{
			if(m_pMaxPEFile->ReadBuffer(&dwKey1, dwProOffset, 0x04, 0x04))
			{
				dwSign[nSigNo] = dwKey1 ^ dwKey2;
				dwProOffset += 0x08;
			}
		}
		if(dwSign[0] == dwSign1[0] && dwSign[1] == dwSign1[1] && dwSign[2] == dwSign1[2])
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Downloader.Tibs"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;

}

/*-------------------------------------------------------------------------------------
	Function		: DetectSinowal
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Sinowal Family
					  1 : Backdoor.Sinowal Family is Rootkit + Backdoor Family
					  2 : Depending on variant it will behave on infection.
					  3 : It also infects the MBR of Primary Hard Drive
					  4 : Variants Covered
						A : Backdoor.Sinowal.ODQ
						B : Backdoor.Sinowal.OOT
						C : Backdoor.Sinowal.OSV
						D : Backdoor.Sinowal.OYZ
						E : Backdoor.Sinowal.KNF (MBR Dump. Already covered in COM Signature)
					  5 : Detection % = 95%	
					  6 : Follwoing Detection contains the loop which is used string kept in 2nd section for decryption.
--------------------------------------------------------------------------------------*/
int CTrojans::DetectSinowal(void)
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	BYTE	bSecName[] = {0x2E, 0x72, 0x64, 0x61, 0x74, 0x61};

	if (m_pMaxPEFile->m_stPEHeader.NumberOfSections < 0x4)
		return iRetStatus; 

	if (memcmp(&m_pMaxPEFile->m_stSectionHeader[0x01].Name[0x00],&bSecName[0x00],sizeof(bSecName)) != 0x00)
		return iRetStatus;

	if (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].VirtualAddress != 0x00 || m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].Size != 0x00)
		return iRetStatus;

	const int SINOWAL_BUFF_SIZE = 0x150;
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[SINOWAL_BUFF_SIZE + MAX_INSTRUCTION_LEN];

	if (NULL == m_pbyBuff)
	{
		return iRetStatus; 
	}
	memset(m_pbyBuff, 0, SINOWAL_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(!GetBuffer(m_dwAEPMapped, SINOWAL_BUFF_SIZE, SINOWAL_BUFF_SIZE))
	{
		return iRetStatus; 
	}

	DWORD       dwLength = 0, dwOffSet = 0,   dwHits = 0x00;
	BYTE        B1 = 0, B2 = 0;
	t_disasm    da;
	DWORD		dwCallDllOffset = 0x00;
	
	m_dwInstCount = 0;
	while(dwOffSet < m_dwNoOfBytes && m_dwInstCount <= 0x30)
	{
		memset(&da, 0x00, sizeof(da));

		B1 = *((BYTE*)&m_pbyBuff[dwOffSet]);
		B2 = *((BYTE*)&m_pbyBuff[dwOffSet + 1]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN,0x400000, &da, DISASM_CODE);
		m_dwInstCount++;

		if(dwHits == 0x00 && dwLength == 2  && strstr(da.result,"JNZ SHORT"))
		{
			dwHits++;
		}
		else if (dwHits == 0x01 && dwLength == 5  && strstr(da.result,"CALL"))
		{
			dwCallDllOffset = *(DWORD *)&m_pbyBuff[dwOffSet + 0x1];	
			dwCallDllOffset = dwCallDllOffset + dwOffSet + dwLength + m_dwAEPMapped;
			dwHits++;
		}
		else if (dwHits == 0x02 && dwLength == 5  && strstr(da.result,"CALL"))
		{
			dwHits++;
		}
		else if (dwHits == 0x03 && dwLength == 2  && (strstr(da.result,"JE SHORT") || strstr(da.result,"JNZ SHORT")))
		{
			dwHits++;
		}
		else if (dwHits == 0x04 && dwLength == 2  && strstr(da.result,"PUSH 0"))
		{
			dwHits++;
		}
		else if (dwHits == 0x05 && dwLength == 6  && strstr(da.result,"CALL"))
		{
			dwHits++;
			break;
		}
		dwOffSet += dwLength;
	}

	if (dwHits != 0x06 || dwCallDllOffset == 0x00 || dwCallDllOffset >= m_pMaxPEFile->m_dwFileSize)
	{
		return iRetStatus;
	}

	memset(m_pbyBuff, 0, SINOWAL_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(!GetBuffer(dwCallDllOffset, SINOWAL_BUFF_SIZE, SINOWAL_BUFF_SIZE))
	{
		return iRetStatus; 
	}
	
	dwLength = 0;
	dwOffSet = 0;
	dwHits = 0x00;
	m_dwInstCount = 0;
	while(dwOffSet < m_dwNoOfBytes && m_dwInstCount <= 0x64)
	{
		memset(&da, 0x00, sizeof(da));

		B1 = *((BYTE*)&m_pbyBuff[dwOffSet]);
		B2 = *((BYTE*)&m_pbyBuff[dwOffSet + 1]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN,0x400000, &da, DISASM_CODE);
		m_dwInstCount++;

		if(dwHits == 0x00 && dwLength == 1  && strstr(da.result,"PUSH EBP"))
		{
			dwHits++;
		}
		else if (dwHits == 0x01 && dwLength == 6 && strstr(da.result,"SUB ESP,"))
		{
			dwHits++;
		}
		else if ((dwHits == 0x02 || dwHits == 0x03) && dwLength == 1  && strstr(da.result,"PUSH E"))
		{
			dwHits++;
		}
		else if (dwHits == 0x04 && dwLength == 5  && strstr(da.result,"MOV EAX,"))
		{
			dwHits++;
		}
		else if (dwHits == 0x04 && dwLength == 1  && strstr(da.result,"POP E"))
		{
			dwHits++;
		}
		else if (dwHits == 0x04 && dwLength == 6  && strstr(da.result,"POP"))
		{
			dwHits++;
		}
		//added for Trojan.Zapchast.rwe
		else if (dwHits == 0x04 && (dwLength == 0xA || dwLength == 0x7) && strstr(da.result,"MOV DWORD"))
		{
			dwHits++;
		}
		else if (dwHits == 0x05 && dwLength == 5  && strstr(da.result,"MOV ECX,"))
		{
			dwHits++;
		}
		else if (dwHits == 0x05 && dwLength == 1  && strstr(da.result,"POP ECX"))
		{
			dwHits++;
		}
		else if (dwHits == 0x06 && dwLength == 5  && (strstr(da.result,"MOV ESI") || strstr(da.result,"PUSH")))
		{
			dwHits++;
			break;
		}
		dwOffSet += dwLength;
	}

	if (dwHits == 0x07)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Trojan.Sinowal.gen"));
		return VIRUS_FILE_DELETE;
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTepfer
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of Tepfer Family
					  Trojan.PSW.Tepfer.chmq + Packed.Katusha.y 
					  A VC++ Compile files
					  B Checksum is set
					  C No Infection and droping files,
					  D Trojan code is encrypted, 2 encyption is present		
--------------------------------------------------------------------------------------*/
int CTrojans::DetectTepfer()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	if(((m_pSectionHeader[0].SizeOfRawData == 0xC00) || (m_pSectionHeader[0].SizeOfRawData == 0x800))&&
		(m_pSectionHeader[2].SizeOfRawData <= 0x400) && 
		(((m_pSectionHeader[2].Misc.VirtualSize >= 0x87000) && (m_pSectionHeader[2].Misc.VirtualSize <= 0x155000)) ||
		(m_pSectionHeader[2].Misc.VirtualSize == 0x20A)))		
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
	
		m_pbyBuff = new BYTE[0x100];
		DWORD dwBuffOffset		= 0x00;
		// For Trojan.PSW.Tepfer.chmq
		if((m_pMaxPEFile->m_stPEHeader.CheckSum == 0xFFFFFFFF) && (m_pSectionHeader[2].Misc.VirtualSize == 0x153000))
		{
			dwBuffOffset = 0x6FAE;
		}
		// End
		// For Packed.Katusha.y 
		else
		{
			const int BUFF_SIZE = 0x250;
			BYTE byrsrcBuff[BUFF_SIZE]	= {0x00};
			DWORD dwrsrcOffset		= m_pSectionHeader[3].PointerToRawData;
			DWORD dwOffsetToDataDir	= 0x00;
			DWORD Temp1				= 0x00;
			DWORD Temp2				= 0x00;
			BYTE byNoOfID			= 0x00;
			WORD byOffsetToDir		= 0x00;
			if(!m_pMaxPEFile->ReadBuffer(byrsrcBuff, dwrsrcOffset, BUFF_SIZE, BUFF_SIZE))
			{
				return iRetStatus;
			}
			byNoOfID			= *(WORD *)&byrsrcBuff[0x3E];
			dwrsrcOffset		= (byNoOfID * 0x8) - 0x02 + 0x3E;
			if(dwrsrcOffset + 2 > BUFF_SIZE)
			{
				return iRetStatus;
			}
			byOffsetToDir		= *(WORD *)&byrsrcBuff[dwrsrcOffset];
			if(dwrsrcOffset + 0x18 > BUFF_SIZE)
			{
				return iRetStatus;
			}
			dwOffsetToDataDir	= *(DWORD *)&byrsrcBuff[byOffsetToDir + 0x14];
			if(dwOffsetToDataDir + 0x8 > BUFF_SIZE)
			{
				return iRetStatus;
			}
			Temp1				= *(DWORD *)&byrsrcBuff[dwOffsetToDataDir];			
			Temp2				= *(DWORD *)&byrsrcBuff[dwOffsetToDataDir + 0x04];
			dwBuffOffset		= Temp1 + Temp2;


			if(dwBuffOffset < m_pSectionHeader[3].VirtualAddress)
			{
				dwBuffOffset = dwBuffOffset + m_pSectionHeader[3].VirtualAddress;
			}

			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwBuffOffset, &dwBuffOffset))
			{
				return iRetStatus;
			}
		}
		// End
		if(!GetBuffer(dwBuffOffset + 0x38, 0x100, 0x100))		
		{
			return iRetStatus;
		}

		DWORD dwFrtkey		= 0x87213197;
		DWORD bydecSig		= 0x00;
		DWORD dwReadOffset	= 0x00;
		BYTE bySig[]		= {0x50,0x45,0x00,0x00};
		DWORD byPEOffset	= 0x00;

	// Decypt only 2 DWORD and compare
		for(int i = 0; i < 2 && dwReadOffset + byPEOffset + 8 < m_dwNoOfBytes; i++)
		{
			DWORD dwSecKey		= *(DWORD *)&m_pbyBuff[dwReadOffset + byPEOffset];
			DWORD dwValue		= *(DWORD *)&m_pbyBuff[dwReadOffset + byPEOffset + 0x04];
			DWORD dwSwapValue	= 0x00;
			dwValue				= dwValue - dwFrtkey;

		// This loop is for swap DWORD 
			while(dwValue > 0)
			{
				int temp	= 0x00;
				temp		= dwValue % 0x100;
				dwSwapValue = dwSwapValue * 0x100 + temp;
				dwValue		= dwValue / 0x100;

			}
			bydecSig	= dwSwapValue ^ dwSecKey;
			byPEOffset	= bydecSig - 0x3C;
		}
		
		if(bydecSig == 0x00004550)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.PSW.Tepfer.chmq"));		//Packed.Katusha.y also detected
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectWebWatcher
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep + Virus Analysis Team
	Description		: Its a KeyLoger.
					  Not a malicious activity, But its keep watching on system without user knowing so given not-a-virus
					  Sig.		: Checking for WebWatcher
--------------------------------------------------------------------------------------*/
int CTrojans::DetectWebWatcher()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->m_stPEHeader.Subsystem != 0x02)
	{
		return iRetStatus;
	}

	if(m_wNoOfSections >= 0x04 && 
		(memcmp(m_pSectionHeader[0x01].Name, ".rdata", 6) == 0) && 
		(m_pMaxPEFile->m_stSectionHeader[0x01].Characteristics == 0x40000040) &&
		(memcmp(m_pSectionHeader[0x02].Name, ".data", 5) == 0) &&
		(m_pSectionHeader[0].PointerToRawData == 0x1000))
	{ 			
		DWORD dwOffset1 = m_pMaxPEFile->m_stPEHeader.DataDirectory[6].VirtualAddress + 0x400;
		DWORD dwOffset2 = m_pSectionHeader[2].PointerToRawData + 0x200;		
		DWORD dwFirstBuffSize = 0xA800;
		DWORD dwsecondBuffSize = 0x1000;
		if((m_pMaxPEFile->m_dwFileSize - dwOffset1) < dwFirstBuffSize)
		{
			dwFirstBuffSize = m_pSectionHeader[1].SizeOfRawData;
		}

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		
		m_pbyBuff = new BYTE[dwFirstBuffSize + dwsecondBuffSize];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, dwFirstBuffSize + dwsecondBuffSize);

		if(m_pMaxPEFile->m_stPEHeader.DataDirectory[6].VirtualAddress == 0)
		{
			dwOffset1 = m_pSectionHeader[1].PointerToRawData;
		}
		
		if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0], dwOffset1, dwFirstBuffSize, dwFirstBuffSize) && 
			m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwFirstBuffSize], dwOffset2, dwsecondBuffSize, dwsecondBuffSize))
		{	
			CMaxBMAlgo *pBMScan = new CMaxBMAlgo;
			if(pBMScan == NULL)
			{
				return iRetStatus;
			}
			
			BYTE bySig1[] = {0x57,0x00,0x65,0x00,0x62,0x00,0x57,0x00,0x61,0x00,0x74,0x00,0x63,0x00,0x68,0x00,0x65,0x00,0x72};
			BYTE bySig2[] =	{0x77,0x00,0x65,0x00,0x62,0x00,0x77,0x00,0x61,0x00,0x74,0x00,0x63,0x00,0x68,0x00,0x65,0x00,0x72};
			if(pBMScan->AddPatetrn2Search(bySig2, sizeof(bySig2)))
			{
				if(pBMScan->Search4Pattern(m_pbyBuff, dwFirstBuffSize + dwsecondBuffSize))
				{
					if(pBMScan)
					{
						delete pBMScan;
						pBMScan = NULL;
					}
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:Monitor.WebWatcher.gen"));
					return VIRUS_FILE_DELETE;
				}
				else
				{
					if(pBMScan->AddPatetrn2Search(bySig1, sizeof(bySig1)))
					{
						if(pBMScan->Search4Pattern(m_pbyBuff, dwFirstBuffSize + dwsecondBuffSize))
						{
							if(pBMScan)
							{
								delete pBMScan;
								pBMScan = NULL;
							}
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:Monitor.WebWatcher.gen"));
							return VIRUS_FILE_DELETE;
						}
					}
				}
			}
			if(pBMScan)
			{
				delete pBMScan;
				pBMScan = NULL;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSmallVQ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Prashant + Virus Analysis Team
	Description		: Detection routine for different varients of small.vq Family
					  1. It doenlaodes another malware.
					  2. form URL http://awmdabest.com/tbr/sbar.exe
					      http://awmdabest.com/dd/dial.exe	
					  3. for detection on the basis of 2 URL's and file name(t.exe).
					  4. Detection :100%
						   Size : 25kb
						  FSG pack : 3kb
					  A. Installation:
						 1. Try to  create "t.exe" Under "C:\Windows\System32\" (Not success).
						 2. Delete t.exe (Not success).
						 3. Decript URL and trying to download to t.exe (Not Success).
						 4. Create s.bat file.
								  - delete its own file after execution.
						 5. Execute s.bat.
					 B. File Modifications : 
		 				Create file into temp folder s.bat.
					 C. Registry Modifications:
		 				No modification.
--------------------------------------------------------------------------------------*/
int CTrojans::DetectSmallVQ(void)
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	
	if(m_wNoOfSections > 0x3 || m_dwAEPUnmapped != 0x1434 || (m_pSectionHeader[m_wAEPSec].Misc.VirtualSize != 0x3000 && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize != 0x1000))
	{
		return iRetStatus;
	}	

	BYTE bySigFilesName[] = {0x5C, 0x74, 0x2E, 0x65, 0x78, 0x65}; //\t.exe
	const int SMALLVQ_BUFF = 0x20;

	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	m_pbyBuff = new BYTE[SMALLVQ_BUFF];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	DWORD dwFileNameoffset = 0x0;
	m_pMaxPEFile->Rva2FileOffset( 0x2078, &dwFileNameoffset);
	if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwFileNameoffset, 0xA, 0xA))
	{
		if(memcmp(&m_pbyBuff[0x04], bySigFilesName, sizeof(bySigFilesName)) == 0)
		{
			BYTE byLocal = m_pbyBuff[0];
			DWORD dwURLoffset = 0x0;
			m_pMaxPEFile->Rva2FileOffset( 0x3017, &dwURLoffset);
			if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwURLoffset, SMALLVQ_BUFF, SMALLVQ_BUFF))
			{
				for(int i = 0; i < SMALLVQ_BUFF; i++)
				{
					m_pbyBuff[i] = m_pbyBuff[i] - 0x20;
					m_pbyBuff[i] = m_pbyBuff[i] - byLocal;
					m_pbyBuff[i] = m_pbyBuff[i] + 0x20;
					byLocal++;
				}
			}
			BYTE bySmallvqURL1[] = {0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x61, 0x77, 0x6D, 0x64, 0x61, 0x62, 0x65, 0x73, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2f, 0x64, 0x64, 0x2f, 0x64, 0x69, 0x61, 0x6c, 0x2e, 0x65, 0x78, 0x65};
			BYTE bySmallvqURL2[] = {0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x61, 0x77, 0x6D, 0x64, 0x61, 0x62, 0x65, 0x73, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2f, 0x74, 0x62, 0x72, 0x2f, 0x73, 0x62, 0x61, 0x72, 0x2e, 0x65, 0x78};
			if(memcmp(&m_pbyBuff[0x0], bySmallvqURL1, sizeof(bySmallvqURL1)) == 0 || memcmp(&m_pbyBuff[0x0], bySmallvqURL2, sizeof(bySmallvqURL2)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Downloader.Small.vq"));
				return VIRUS_FILE_DELETE;
			}
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectWLordgen
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Satish + Virus Analysis Team
	Description		: Detection routine for different varients of Dundun Family
					  1)Decrypts PE file from Data Section
					  2)it executes that PE file in %temp% folder by Creating thread
					  Detection   : Detecting Decryption Loop
--------------------------------------------------------------------------------------*/
int CTrojans::DetectWLordgen()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections >= 7 && m_wAEPSec == 0 && m_pSectionHeader[m_wAEPSec].SizeOfRawData <= 0x2000 && m_pMaxPEFile->m_stPEHeader.SizeOfStackCommit == 0x4000)
	{	
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		DWORD dwWlordgenBufsize = 0x450;
		m_pbyBuff = new BYTE[dwWlordgenBufsize + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff,0x00,dwWlordgenBufsize + MAX_INSTRUCTION_LEN);
		if(!GetBuffer(m_dwAEPMapped,dwWlordgenBufsize,dwWlordgenBufsize))
		{
			return iRetStatus;
		}
		DWORD dwOffset = 0,dwLength = 0,dwMatchedinst = 0;
		bool bDecOffsetFound = false,bCmp1 = false,bCmp2 = false,bCallCheck = false,bXor = false;
		t_disasm da;
		while(dwOffset < dwWlordgenBufsize)
		{
			memset(&da, 0x00, sizeof(struct t_disasm));
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwOffset > (dwWlordgenBufsize - dwLength))
			{
				break;
			}
			if(dwOffset > 0x35 && bCallCheck == false)
			{
				return iRetStatus;
			}
			if((bCallCheck == false) && (dwLength == 5) && strstr(da.result,"MOV EAX,") && dwOffset < 0x35)
			{
				dwMatchedinst++;
			}
			else if((dwMatchedinst >= 1) && dwLength == 5 && strstr(da.result,"CALL") && dwOffset < 0x35 && (*(DWORD *)&m_pbyBuff[dwOffset + 1] > 0xFFFF0000))
			{
				dwMatchedinst++;
				bCallCheck = true;
			}
			if(dwLength == 5 && dwMatchedinst >= 2 && (strstr(da.result,"MOV E")))
			{
				if(((*(DWORD *)&m_pbyBuff[dwOffset + 1] - m_dwImageBase) > m_pSectionHeader[1].VirtualAddress) &&
					((*(DWORD *)&m_pbyBuff[dwOffset + 1] - m_dwImageBase) < (m_pSectionHeader[1].VirtualAddress + 0x1000)))
				{
					bDecOffsetFound = true;
					if(dwOffset > 0x80)
					{
						bCmp1 = true;
					}
				}
			}
			if(dwOffset > 0x90 && dwLength == 2 && strstr(da.result,"MOV AL,1") && (*(WORD *)&m_pbyBuff[dwOffset + dwLength] == 0x01EB))
			{
				bCmp1 = true;
			}
			else if((bCmp1 == false) && (dwLength == 5 || dwLength == 6) && dwMatchedinst >= 2 && strstr(da.result,"CMP E") && ((m_pbyBuff[dwOffset + dwLength] == 0x7D) || (m_pbyBuff[dwOffset + dwLength] == 0x0F)))
			{
				bCmp1 = true;
			}
			else if((bCmp1 == true) && (dwMatchedinst >= 2) && (strstr(da.result,"MOV") || strstr(da.result,"XOR")) && strstr(da.result,"L,[E"))
			{
				if(bDecOffsetFound == true)
				{
					dwMatchedinst++;
				}
				else if(dwLength == 6 && ((*(DWORD *)&m_pbyBuff[dwOffset + 2] - m_dwImageBase) > m_pSectionHeader[1].VirtualAddress) &&
					((*(DWORD *)&m_pbyBuff[dwOffset + 2] - m_dwImageBase) < m_pSectionHeader[1].VirtualAddress + 0x1000))
				{
					dwMatchedinst++;
				}
			}		
			else if((bCmp1 == true) && dwMatchedinst >= 2 && (dwLength == 2 || dwLength == 3) && strstr(da.result,"XOR") && strstr(da.result,"L,"))
			{
				bXor = true;
				dwMatchedinst++;
			}
			else if((bCmp1 == true) && (bXor == false) && (dwLength == 6) && strstr(da.result,"XOR") && strstr(da.result,"L,[") && da.adrconst != 0)
			{
				bXor = true;
				dwMatchedinst++;
			}
			else if((bXor == true) && dwMatchedinst >= 3 && (strstr(da.result,"MOV [E") || strstr(da.result,"XOR [E")) && strstr(da.result,"L"))
			{
				dwMatchedinst++;
			}
			else if((bXor == true) && dwMatchedinst >= 4 && ((dwLength == 6 || dwLength == 5) || (strstr(da.result,"L"))) && strstr(da.result,"CMP") && da.immconst == 0xFF)
			{
				dwMatchedinst++;
				bCmp2 = true;
			}
			else if((bCmp2 == true) && dwMatchedinst >= 5 && dwLength == 2 && strstr(da.result,"J"))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Dropper.Wlord.Gen"));
				return VIRUS_FILE_DELETE;
			}
			dwOffset += dwLength;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPswRuftarHtm
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Prashant + Virus Analysis Team
	Description		: Detection routine for different varients of Ruftar Family
					  A. Installation:
						- Drop it self in to Temp.
						- Create ufr_files dir in to current dir.
						- create log files contain credential details of user.
				      B. Files modifications :	
						 - Drop it copy at 
							C:\Documents and Settings\admin\Local Settings\Temp\
						 - Create DIR and log files in to current dir.
							1. ufr_files	
							2. NO_PWDS_report_23-02-2013_10-15-23-FKEJ.bin	
					  C. Registry Modifications:
					  Intention  : Mutex Name UFR_Stealer_2600
					  Detection  : 98%
--------------------------------------------------------------------------------------*/
int CTrojans::DetectPswRuftarHtm()
{
	int iRetstatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == 0x0 && ((m_wNoOfSections == 0x03 && (m_dwAEPUnmapped / 0x1000 == 0x0C && m_pSectionHeader[0].Misc.VirtualSize == 0x49000)) || 
		(m_wNoOfSections == 0x04 && m_dwAEPUnmapped / 0x1000 == 0x0C && m_pSectionHeader[0].Misc.VirtualSize == 0xE0C3)))
	{		
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int RUFTAR_HTM_BUFF = 0x20;
		m_pbyBuff = new BYTE[RUFTAR_HTM_BUFF];
		
		if(!m_pbyBuff)
			return iRetstatus;
	
		DWORD dwKeyOffset  = 0x1058;
		DWORD dwDataOffset = 0x115BF;
		DWORD dwBuffOffset = 0x00;

		m_pMaxPEFile->Rva2FileOffset(dwDataOffset, &dwBuffOffset);
		if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0], dwBuffOffset, 0x10, 0x10))
		{
			m_pMaxPEFile->Rva2FileOffset(dwKeyOffset, &dwBuffOffset);
			if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x10], dwBuffOffset, 0x10, 0x10))
			{
				int iKeyID = 0x0F;
				for(int iBuffOfset = 0x0; iBuffOfset <= 0x0F; iBuffOfset++)
				{
					m_pbyBuff[iBuffOfset] = m_pbyBuff[iBuffOfset]^m_pbyBuff[0x10 + iKeyID];
					if(iKeyID == 0x0F)
						iKeyID = 0x00;
					else 
						iKeyID++;
				}
				BYTE byRuftarHtmSign[] = {0x55, 0x46, 0x52, 0x5f, 0x53, 0x74, 0x65, 0x61, 0x6c, 0x65, 0x72, 0x5f, 0x32, 0x36, 0x30, 0x30};// UFR_Stealer_2600
				if(memcmp(&m_pbyBuff[0], byRuftarHtmSign, sizeof(byRuftarHtmSign)) == 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("PSW.Ruftar.htm"));
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	return iRetstatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSafeDecisionINC
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Prashant + Virus Analysis Team
	Description		: Detection routine for different varients of SafeDecision INC Family
					  A. Installation:	
						- Installs the Movie downloader and then Toolbar to IE.
				      B. File Modification 
						- Create files related to Movie downloader and Toolbar.
				      C. Registry Modifications:
						- Adds the registry entry for Movie downloader and toolbar.
					  Intention  : Safe Decision, Inc. 	   
					  Detection  : 99%
--------------------------------------------------------------------------------------*/
int CTrojans::DetectSafeDecisionINC()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	
	if(((((m_wNoOfSections == 0xD && m_wAEPSec == 0xB && m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].PointerToRawData == 0x1B000) ||
		  (m_wNoOfSections == 0x7 && m_wAEPSec == 0x5 && m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].PointerToRawData == 0x1D000))&& (m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize < 0x100))
		|| ((m_wNoOfSections == 0xA || m_wNoOfSections == 0x5) && m_wAEPSec == 0x0 && (m_dwAEPUnmapped & 0xF000) == 0x3000))
		&& (m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0xCA0 || m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x818))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int SAFEDEC_BUFF_SIZE = 0x13;		
		m_pbyBuff = new BYTE[SAFEDEC_BUFF_SIZE];		
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		DWORD dwAddOffset = 0x65D;
		if(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x818)
			dwAddOffset = 0x1F1;

		DWORD dwSignOffset = (m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress + dwAddOffset);
		
		if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwSignOffset, SAFEDEC_BUFF_SIZE, SAFEDEC_BUFF_SIZE))
		{
			BYTE bySafeDecSign[] = {0x53, 0x61, 0x66, 0x65, 0x20, 0x44, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6F, 0x6E, 0x2C, 0x20, 0x49, 0x6E, 0x63}; //Safe Decision, Inc
			if(memcmp(&m_pbyBuff[0x0], bySafeDecSign, sizeof(bySafeDecSign)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("not-a-virus:Trojan.Safe Decision, Inc"));
				return VIRUS_FILE_DELETE;
			}
		}
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectLoadMoney
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of LoadMoney Family
				      Heuristic behaviour
					  Redirect to othersites and downloading, may be malicious site so given not-a-virus
					  It can perform file system changes, memory modifications, registry value changes, and registry key changes.
--------------------------------------------------------------------------------------*/
int CTrojans::DetectLoadMoney()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_dwAEPUnmapped == 0x1140 && m_wNoOfSections == 0x07 && m_pSectionHeader[1].SizeOfRawData == 0xF200 && 
		m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData == 0x200)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int MONEY_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[MONEY_BUFF_SIZE];

		if(!GetBuffer(m_pSectionHeader[1].PointerToRawData + 0xD640, MONEY_BUFF_SIZE, MONEY_BUFF_SIZE))
		{
			return iRetStatus;
		}
		BYTE byKeySearchBuff[0x40] = {0x00};				
		if(!m_pMaxPEFile->ReadBuffer(&byKeySearchBuff, m_pSectionHeader[1].PointerToRawData, 0x40, 0x40))
		{
			return iRetStatus;
		}
		
		BYTE byDecKey = 0x00;
		if(*(DWORD *)&byKeySearchBuff[0x00] == 0x00000001)
		{
			byDecKey = *(BYTE *)&byKeySearchBuff[0x3E];
		}
		else
		{
			byDecKey = *(BYTE *)&byKeySearchBuff[0x1E];
		}

		BYTE bySig[] = {0x5A,0x00,0x6F,0x00,0x6E,0x00,0x65,0x00,0x2E,0x00,0x49,0x00,0x64,0x00,0x65,0x00,0x6E,0x00,0x74,0x00,0x69,0x00,0x66,0x00,0x69,0x00,0x65,0x00,0x72};
		BYTE byDecSig[0x1D] = {0x00};

		CMaxBMAlgo *pMScan = new CMaxBMAlgo;
		if(pMScan == NULL)
		{
			return iRetStatus;
		}
		if(byDecKey != 0x00)
		{
			for(int i = 0x00; i<= sizeof(bySig); i+=2)
			{
				byDecSig[i] = bySig[i] ^ byDecKey;
			}
			if(!pMScan->AddPatetrn2Search(byDecSig, sizeof(byDecSig)))
			{
				delete pMScan;
				pMScan = NULL;
				return iRetStatus;
			}
		}
		else
		{
			if(!pMScan->AddPatetrn2Search(bySig, sizeof(bySig)))
			{
				delete pMScan;
				pMScan = NULL;
				return iRetStatus;
			}
		}
		if(pMScan->Search4Pattern(m_pbyBuff, MONEY_BUFF_SIZE))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-Virus:Adware.LoadMoney.h"));
			iRetStatus = VIRUS_FILE_DELETE;
		}
		delete pMScan;
		pMScan = NULL;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectMonderd
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of Monderd Family
					  Drop .dll @C:\WINDOWS\system32
					  Running backdoor process, take handle of drop .dll
					  This trojan infect computer through a number of methods, Like..Email, p2p sharing etc..
					  A drop DLL, monitor Web browsing and display advertisements
					  Its generic detection of trojan	
--------------------------------------------------------------------------------------*/
int CTrojans::DetectMonderd()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_dwAEPUnmapped < 0x1600) &&
		((m_pSectionHeader[0].Misc.VirtualSize % 0x100) == 0x00) &&
		(m_pSectionHeader[1].SizeOfRawData <= 0x400))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		BYTE dwPrmCheck[0x19] = {0x00};
		bool JmpByte = false;
		if(!m_pMaxPEFile->ReadBuffer(&dwPrmCheck, m_dwAEPMapped, 0x19, 0x19))
		{
			return iRetStatus;
		}
		for(int i = 0; i < 0x19; i++)
		{
			if(dwPrmCheck[i] == 0xEB)
			{
				JmpByte = true;
				break;
			}
		}
		if(JmpByte)
		{
			CEmulate m_objEmulate(m_pMaxPEFile);
			int itemp = 0;
			BYTE bjmp = 0;
			if(!m_objEmulate.IntializeProcess())
			{
				return iRetStatus;
			} 
			m_objEmulate.SetEip(m_dwAEPUnmapped + m_dwImageBase);
			m_objEmulate.SetBreakPoint("__isinstruction('jmp')"); //0
			m_objEmulate.SetBreakPoint("__isinstruction('mov edx')"); //1
			m_objEmulate.SetBreakPoint("__isinstruction('push')"); //2
			m_objEmulate.SetBreakPoint("__isinstruction('mov e')"); //3
			m_objEmulate.SetBreakPoint("__isinstruction('xor e')"); //4 
			m_objEmulate.SetBreakPoint("__isinstruction('pop e')");  //5
			
			m_objEmulate.SetNoOfIteration(130);
			
			m_objEmulate.PauseBreakPoint(2);
			m_objEmulate.PauseBreakPoint(3);
			m_objEmulate.PauseBreakPoint(4);
			m_objEmulate.PauseBreakPoint(5);
			

			char szInstruction[1024] = {0};        

			while(1)
			{
				if(7 != m_objEmulate.EmulateFile(0)) 
				{
					return iRetStatus;
				}
				memset(szInstruction, 0, 1024);
				m_objEmulate.GetInstruction(szInstruction);
				if(strstr(szInstruction,"jmp"))
				{
					bjmp++;
				}
				else if(strstr(szInstruction,"mov edx, 1"))
				{
					m_objEmulate.PauseBreakPoint(1);
					m_objEmulate.ActiveBreakPoint(2);
					m_objEmulate.ActiveBreakPoint(3);
				}
				else if((strstr(szInstruction,"push") || strstr(szInstruction,"mov e")) && m_objEmulate.GetInstructionLength() == 5)
				{
					m_objEmulate.PauseBreakPoint(2);
					m_objEmulate.PauseBreakPoint(3);
					m_objEmulate.ActiveBreakPoint(4);
				}
				else if(strstr(szInstruction,"xor e") && m_objEmulate.GetInstructionLength() == 6)
				{
					itemp = m_objEmulate.GetDestRegNo();
					m_objEmulate.PauseBreakPoint(4);
					m_objEmulate.ActiveBreakPoint(5);
				}
				else if(strstr(szInstruction,"pop e") && (itemp == m_objEmulate.GetDestRegNo()))
				{
					itemp = 20;					
				}
				else if(strstr(szInstruction,"pop e") && bjmp > 0x11)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Monderd.gen"));
					return VIRUS_FILE_DELETE;
				}
			}	
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAgentXcfc
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Agent.Xcfc Family
					  1)it decrypts Code to execute
					  2)After decryption,it tries to write in its own process
					  3)it gets execption while writing,
					  4)Not able to Debug After Changing the file
--------------------------------------------------------------------------------------*/
int CTrojans::DetectAgentXcfc()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_dwAEPUnmapped == 0x3B7EF && m_pSectionHeader[0].SizeOfRawData == 0x4B000 && m_wAEPSec == 0)
	{
		BYTE AGENTXCFC_BUF[0x20] = {0};
		BYTE AGENTXCFC_Sig[] = {0x33, 0xD2, 0x8B, 0xC1, 0xF7, 0x75, 0x18, 0x8B, 0x45, 0x14, 0x8A, 0x04, 0x02, 0x32, 0x04, 0x31, 
								0x32, 0x45, 0x1C, 0x88, 0x04, 0x31, 0x41, 0x3B, 0x4D, 0x10, 0x72, 0xE4, 0x5F, 0x5E, 0x5D, 0xC3};
		if(m_pMaxPEFile->ReadBuffer(&AGENTXCFC_BUF[0x00], 0x8239, 0x20, 0x20))
		{
			if(memcmp(&AGENTXCFC_BUF[0x00], AGENTXCFC_Sig, sizeof(AGENTXCFC_Sig)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Downloader.Agent.xcfc"));
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectQhostsBm
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Qhosts.bm Family
					  1)it infects host file
					  2)All samples are smart installer files
					  3)after installation it contains (1bat file, 1 vbs script file) which changes host file
--------------------------------------------------------------------------------------*/
int CTrojans::DetectQhostsBm()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL || m_pMaxPEFile->m_stPEHeader.DataDirectory[9].VirtualAddress == 0)
	{
		return iRetStatus;
	}
	if(m_wNoOfSections == 8 && (m_pMaxPEFile->m_dwFileSize > (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + 0x2800)))
	{
		const int QHOSTS_BUF_SIZE = 0xC00;
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		
		m_pbyBuff = new BYTE[QHOSTS_BUF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0x00, QHOSTS_BUF_SIZE);
		if(!GetBuffer((m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + 0x1C00), QHOSTS_BUF_SIZE , QHOSTS_BUF_SIZE))
		{
			return iRetStatus;
		}
		DWORD dwOffset = 0,dwNewOffset = 0;
		BYTE BATFILE_SIG[] = {0x25, 0x0D, 0x0A, 0x01, 0x00, 0x00, 0x00};
		if(OffSetBasedSignature(BATFILE_SIG, sizeof(BATFILE_SIG), &dwOffset))
		{
			BYTE QHOSTS_BUFF[0x80] = {0};
			if((dwOffset + 0x90) > QHOSTS_BUF_SIZE)
			{
				return iRetStatus;
			}			
			for(DWORD iOffset = dwOffset + 0x10;iOffset < (dwOffset + 0x8D); iOffset++)
			{
				if(m_pbyBuff[iOffset] == 0x0D && m_pbyBuff[iOffset + 1] == 0x0A)
				{
					iOffset += 1;
					continue;
				}
				QHOSTS_BUFF[dwNewOffset++] = m_pbyBuff[iOffset];
			}
			const BYTE QHOSTS_SIG[] = {0x36, 0x34, 0x2E, 0x36, 0x32, 0x2E, 0x31, 0x39, 0x31, 0x2E, 0x32, 0x32, 0x32, 0x3A, 0x34, 0x33, 0x32, 0x31, 0x2F, 0x73, 0x74, 0x61, 0x74, 0x2F, 0x74, 0x75, 0x6B};

			for(DWORD iOffset = 0; iOffset < (0x80 - sizeof(QHOSTS_SIG)); iOffset++)
			{
				if(memcmp(&QHOSTS_BUFF[iOffset], QHOSTS_SIG, sizeof(QHOSTS_SIG)) == 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Qhosts.bm"));
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSolimba
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep Vasoya + Virus Analysis Team
	Description		: Detection routine for different varients of Simba Family
					  Solimba is an advertising agency,
					  Not Found any malicious Activity,
					  what software they will promote we dont know, may be its harmfull to our system,
					  Also installing third party recommendations software tool,
					  Covered "Adware.Solimba.a", "Trojan.Solimba.gen" and "Trojan.DownloadMR"
--------------------------------------------------------------------------------------*/
int CTrojans::DetectSolimba()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_dwAEPUnmapped == 0x4327 || m_dwAEPUnmapped == 0x323C || m_dwAEPUnmapped == 0x333F) && (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].Size > 0) &&
		(m_wNoOfSections == 0x07 || m_wNoOfSections == 0x05) && 
		(m_pSectionHeader[0].SizeOfRawData == 0x8A00 || m_pSectionHeader[0].SizeOfRawData == 0x5C00) &&
		(m_pSectionHeader[1].SizeOfRawData == 0x200 || m_pSectionHeader[1].SizeOfRawData == 0x1200 || m_pSectionHeader[1].SizeOfRawData == 0x1400) &&
		(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x4600 || m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x6E00 || m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x2800))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x50];
		if(!GetBuffer(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].VirtualAddress + 0x0CB0, 0x50, 0x50))
		{
			return iRetStatus;
		}
		
		CSemiPolyDBScn polydbObj;
		TCHAR szSig[] = {_T("426164616C6F6E6131223020*536F6C696D62612041706C69636163696F6E657320532E4C")};
		TCHAR szVirusName[MAX_PATH] = {0};
		polydbObj.LoadSigDBEx(szSig, _T("not-a-virus:Adware.Solimba.gen"), FALSE);

		if(polydbObj.ScanBuffer(m_pbyBuff, 0x50, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVittaliaInstaller
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Prajakta + Virus Analysis Team
	Description		: Detection routine for different varients of VittaliaInstaller Family
					  A. Vittalia Installer is designed to bundle third party programs typically toolbars & other adware.
		   			  B. When a user attempts to download a file from the web site "www.filewon.com" this installer distributes 
						such adware-type applications.
--------------------------------------------------------------------------------------*/
int CTrojans::DetectVittaliaInstaller()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(((m_wNoOfSections == 0x4 || m_wNoOfSections == 0x5) && m_wAEPSec == 0x0) ||
		(m_wNoOfSections == 0x3 && m_wAEPSec == 0x1)&&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].VirtualAddress != 0x0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].Size != 0x0 &&
		m_pMaxPEFile->m_dwFileSize -(m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData) != 0x0)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int VITTALIA_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[VITTALIA_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		DWORD dwReadOff = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].VirtualAddress + 0x100;
		if(!GetBuffer(dwReadOff,VITTALIA_BUFF_SIZE,VITTALIA_BUFF_SIZE))
		{
			return iRetStatus;
		}
		const BYTE VITTALIA_SIG[] = {0x56,0x69,0x74,0x74,0x61,0x6C,0x69,0x61,0x20,0x49,0x6E,0x74,0x65,0x72,0x6E,
			                     0x65,0x74,0x20,0x53,0x2E,0x4C}; //Vittalia Internet S.L
		const BYTE VITTALIA_SIG1[] = {0x44,0x65,0x73,0x63,0x61,0x72,0x67,0x61,0x20,0x53,0x65,0x67,0x75,0x72,0x61,
					     0x20,0x4C,0x4C,0x43}; //Descarga Segura LLC

		for(int i = 0x0; i < VITTALIA_BUFF_SIZE - sizeof(VITTALIA_SIG); i++)
		{
			if(memcmp(&m_pbyBuff[i],VITTALIA_SIG,sizeof(VITTALIA_SIG)) == 0 || 
				memcmp(&m_pbyBuff[i],VITTALIA_SIG1,sizeof(VITTALIA_SIG1)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:Trojan.Vittalia Installer"));
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectCinmusAIZH
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of cinmus.aizh Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectCinmusAIZH()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.Subsystem == 1) && m_pMaxPEFile->m_stPEHeader.SectionAlignment == 0x80 &&
		m_pMaxPEFile->m_stPEHeader.SizeOfHeaders == 0x300)
	{
		if(m_pMaxPEFile->m_dwFileSize > (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections -1].SizeOfRawData + 0x300))
		{
			if(m_pbyBuff)
			{
				delete[] m_pbyBuff;
				m_pbyBuff = NULL;
			}

			m_pbyBuff = new BYTE[0x300];

			if(!m_pbyBuff)
			{
				return iRetStatus;
			}

			if(!GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData, 0x300, 0x300))
			{
				return iRetStatus;
			}
			BYTE byXorkey = 0x00;

			byXorkey = 0x4d ^ m_pbyBuff[0x4];
			if((byXorkey == 0x00 || (m_pbyBuff[0x5] ^ byXorkey) != 0x5A))
			{
				return iRetStatus;
			}

			for(int i = 0x40; i < 0x44; i++)
			{
				m_pbyBuff[i]^= byXorkey;
			}
			DWORD dwPEOffset = *(DWORD *)&m_pbyBuff[0x40];
			if((dwPEOffset < 0x280) && (dwPEOffset != 0x00))
			{
				m_pbyBuff[dwPEOffset + 0x4]^= byXorkey;
				m_pbyBuff[dwPEOffset + 0x5]^= byXorkey;
			}
			else
			{
				return iRetStatus;
			}
			if(*(WORD *)&m_pbyBuff[dwPEOffset + 0x4] == 0x4550)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:Adware.cinmus.aizh"));
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Satish + Sandeep Vasoya + Virus Analysis Team
	Description		: Detection routine for different varients of Medfos Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectMedfos()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	//File Should be .dll file
	if ((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		return iRetStatus; 
	}

	if(!(m_wNoOfSections == 5 && m_wAEPSec == 0 && 
		(m_pSectionHeader[0].Characteristics == 0x60000020) && m_pMaxPEFile->m_stPEHeader.Subsystem == 2))
	{
		return iRetStatus;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int MEDFOS_BUF_SIZE = 0x250;
	m_pbyBuff = new BYTE[MEDFOS_BUF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0x00, MEDFOS_BUF_SIZE + MAX_INSTRUCTION_LEN);

	if(!GetBuffer(m_dwAEPMapped, MEDFOS_BUF_SIZE, MEDFOS_BUF_SIZE))
	{
		return iRetStatus;
	}

	DWORD		dwValue = *(DWORD *)&m_pbyBuff[0];	
	DWORD		dwOffset = 0,dwLength = 0,dwKeyOffset = 0;
	BYTE		byCallCnt = 0;
	t_disasm	da;

	while(dwOffset < MEDFOS_BUF_SIZE)
	{
		memset(&da, 0x00, sizeof(struct t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwOffset > (MEDFOS_BUF_SIZE - dwLength))
		{
			break;
		}
		else if(strstr(da.result,"CALL") && byCallCnt < 2)
		{
			if(dwLength == 5)
			{
				byCallCnt++;
				if(byCallCnt == 1 && *(DWORD *)&m_pbyBuff[dwOffset + 1] < 0x50)
				{
					dwOffset = dwOffset + *(DWORD *)&m_pbyBuff[dwOffset + 1] + 5;
					byCallCnt--;
					continue;
				}
				if(byCallCnt == 2)
				{
					dwOffset = dwOffset + m_dwAEPMapped + *(DWORD *)&m_pbyBuff[dwOffset + 1] + 5;
					memset(m_pbyBuff, 0x00, MEDFOS_BUF_SIZE + MAX_INSTRUCTION_LEN);
					if(!GetBuffer(dwOffset, MEDFOS_BUF_SIZE, MEDFOS_BUF_SIZE))
					{
						return iRetStatus;
					}
					dwOffset = 0;
					continue;
				}
			}
			else
			{
				return iRetStatus;
			}
		}
		else if(dwLength == 1 && m_pbyBuff[dwOffset] == 0xC3 && byCallCnt < 2)
		{
			return iRetStatus;
		}
		else if(byCallCnt >= 2 && dwLength == 2 && strstr(da.result, "JE") && (m_pbyBuff[dwOffset + dwLength] == 0xD9 || m_pbyBuff[dwOffset + dwLength] == 0xCC))
		{
			dwOffset += m_pbyBuff[dwOffset + 1];
			byCallCnt = 3;
		}
		else if(byCallCnt >= 2 && dwLength == 2 && strstr(da.result, "JNZ") && m_pbyBuff[dwOffset + 1] < 0x80 && (m_pbyBuff[dwOffset + dwLength] == 0xD9 || m_pbyBuff[dwOffset + dwLength] == 0xCC))
		{
			dwOffset += m_pbyBuff[dwOffset + 1];
			byCallCnt = 3;
		}
		else if(byCallCnt >= 2 && (dwLength == 7 || dwLength == 10) && strstr(da.result,"MOV DWORD PTR [E") && (da.immconst > 0x20000) && (da.immconst < 0x60000) && m_pbyBuff[dwOffset+dwLength] == 0xE8)
		{
			dwKeyOffset = da.immconst;
			break;
		}
		dwOffset += dwLength;
	}
	if(dwKeyOffset == 0)
	{
		return iRetStatus;
	}
	else if(dwValue == 0x08247C83)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Medfos.FAYZ"));
		return VIRUS_FILE_DELETE;
	}
	else
	{
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwKeyOffset, &dwKeyOffset))
		{
			return iRetStatus;
		}

		BYTE bOffset[0x60] = {0};
		if(!m_pMaxPEFile->ReadBuffer(&bOffset[0x00],dwKeyOffset,0x60,0x60))
		{
			return iRetStatus;
		}
		DWORD dwDataOffset = 0, dwDataVal = 0, dwKey = 0;

		for(DWORD i = 0x3C; i < 0x50 ;i += 4)
		{
			if(*(DWORD *)&bOffset[i] > 0x30000)
			{
				if(*(DWORD *)&bOffset[i-8] == 0)
				{					
					dwDataOffset = *(DWORD *)&bOffset[i - 0xC] + *(DWORD *)&bOffset[i - 0x10] - 4;
					dwKey = *(DWORD *)&bOffset[i];
					break;
				}				
				dwDataOffset = *(DWORD *)&bOffset[i - 8] + *(DWORD *)&bOffset[i - 0xC] - 4;				
				dwKey = *(DWORD *)&bOffset[i];
				break;
			}
		}
		if(dwDataOffset == 0 || dwKey == 0)
		{
			return iRetStatus;
		}
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwDataOffset,&dwDataOffset))
		{
			return iRetStatus;
		}

		if(!m_pMaxPEFile->ReadBuffer(&dwDataVal,dwDataOffset,0x4,0x4))
		{
			return iRetStatus;
		}
		dwDataVal ^= dwKey;	
		*(DWORD *)&bOffset[0] = dwDataVal;
		if(bOffset[3] == 0xC3 || *(WORD *)&bOffset[0x02] == 0xC3 || ((*(WORD *)&bOffset[0x2] == 0x0) && bOffset[1] == 0xC3) || (*(DWORD *)&bOffset[0] == 0xC3))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Medfos.J"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Satish + Sandeep Vasoya + Prajakta + Virus Analysis Team
	Description		: Detection routine for different varients of OptimumInstaller Family
					  OptimumInstaller, Adware.IBryte.Gen, Adware.IBryte.X
					  Adware.iBryte.jcs, Trojan.BetterInstaller
					  Adware.iBryte.jda	
--------------------------------------------------------------------------------------*/
int CTrojans::DetectOptimumInstaller()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	int iChk = 0x0;

	if	(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1F28 || m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0xEB0 || 
		m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x740 || m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1460 || 
		m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1898 || m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1328)
	{
		iChk = 0x1;
	}
	else if((m_wNoOfSections == 0x7 && m_dwAEPUnmapped == 0x39AC) || (m_wNoOfSections == 0x5 && m_dwAEPUnmapped == 0x323C))
	{
		iChk = 0x2;
	}
    // Add this condition
	if(iChk == 0x00)
	{
		return iRetStatus;
	}
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[0x500];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0x00, 0x500);
		
	if(iChk == 0x1)
	{
		if(m_wNoOfSections == 0x04 || m_wNoOfSections == 0x05)
		{
			if(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1F28 || m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1460)
			{
				BYTE Optimum_Sig[] = {0x4F, 0x70, 0x74, 0x69, 0x6D, 0x75, 0x6D, 0x20, 0x49, 0x6E, 0x73, 0x74, 0x61, 0x6C, 0x6C, 0x65, 0x72};
				if(!GetBuffer(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress + 0x920 , 0x500 ,0x500))
				{
					return iRetStatus;
				}

				if(OffSetBasedSignature(Optimum_Sig,sizeof(Optimum_Sig),NULL))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Not.a.virus.Optimum.Installer"));
					return VIRUS_FILE_DELETE;
				}
			}
			else if(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1898)
			{
				BYTE Optimum_Sig[] = {0x50, 0x72, 0x65, 0x6D, 0x69, 0x75, 0x6D, 0x20, 0x49, 0x6E, 0x73, 0x74, 0x61, 0x6C, 0x6C, 0x65, 0x72};
				if(!GetBuffer(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress + 0x1F0 , 0x500 ,0x500))
				{
					return iRetStatus;
				}

				if(OffSetBasedSignature(Optimum_Sig,sizeof(Optimum_Sig),NULL))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Not.a.virus.Adware.iBryte.jcs"));
					return VIRUS_FILE_DELETE;
				}
			}
		//	Add detection on 17 Dec 2013
			else if(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1328)
			{
				BYTE iBryte_Sig[] = {0x54, 0x49, 0x4E, 0x59, 0x20, 0x49, 0x4E, 0x53, 0x54, 0x41, 0x4C, 0x4C, 0x45, 0x52};
				if(!GetBuffer(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress + 0x700 , 0x100 ,0x100))
				{
					return iRetStatus;
				}

				if(OffSetBasedSignature(iBryte_Sig,sizeof(iBryte_Sig),NULL))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Not.a.virus.Adware.iBryte.jda"));
					return VIRUS_FILE_DELETE;
				}
			}
		// End Detection
			else
			{
				BYTE iBryte_Sig[] = {0x55, 0x04, 0x0A, 0x14, 0x06, 0x69, 0x42, 0x72, 0x79, 0x74, 0x65, 0x31};
				if(!GetBuffer(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress + 0x1E0 , 0x300 ,0x300))
				{
					return iRetStatus;
				}

				if(OffSetBasedSignature(iBryte_Sig,sizeof(iBryte_Sig),NULL))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Not.a.virus.Adware.iBryte.gen"));
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	else if(iChk == 0x2)
	{
		DWORD dwNameID = 0x10, dwLang = 0x0001 , dwLangID = 0x0000, dwRVA = 0x0 , dwSize = 0x0, dwReadOffset = 0x0,dwBytes2Read = 0x0;
		if(FindRes(LPCTSTR(&dwNameID), LPCTSTR(&dwLang), LPCTSTR(&dwLangID), dwRVA, dwSize))
		{
			BYTE bBetterInstallerSig[] = {0x42,0x00,0x65,0x00,0x74,0x00,0x74,0x00,0x65,0x00,0x72,0x00,0x49,0x00,
						      0x6E,0x00,0x73,0x00,0x74,0x00,0x61,0x00,0x6C,0x00,0x6C,0x00,0x65,0x00,0x72}; 
						     //B.e.t.t.e.r.I.n.s.t.a.l.l.e.r 
			
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwRVA, &dwReadOffset))
			{
				return iRetStatus;
			}
			dwBytes2Read = dwSize;
			if(dwSize > 0x300)
				dwBytes2Read = 0x300;
				
			if(!GetBuffer(dwReadOffset, dwBytes2Read, dwBytes2Read))
			{
				return iRetStatus;
			}
			if(OffSetBasedSignature(bBetterInstallerSig,sizeof(bBetterInstallerSig),NULL))
			{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Not.a.virus.Trojan.BetterInstaller"));
					return VIRUS_FILE_DELETE;
			}
		}
	
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSpector
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Spector Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectSpector()
{	
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD dwBufSize = 0x1000;
	bool bJmp = false,bMovJmp = false,bMovCheck = false,bCheck = false;

	if(!(((m_wNoOfSections == 4 || m_wNoOfSections == 5) && m_pMaxPEFile->m_stPEHeader.Characteristics == 0x102 && m_pMaxPEFile->m_stPEHeader.SizeOfImage > 0x80000) || 
		((m_pMaxPEFile->m_stPEHeader.Characteristics == 0x2102) && m_pMaxPEFile->m_stPEHeader.Subsystem == 2 && (m_pMaxPEFile->m_stPEHeader.CheckSum == 0 || (m_pMaxPEFile->m_stPEHeader.MinorImageVersion > 0x10)))))
	{
		return iRetStatus;
	}
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}

	m_pbyBuff = new BYTE[dwBufSize];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0x00, dwBufSize);

	if(!GetBuffer(m_dwAEPMapped,dwBufSize,dwBufSize))
	{
		return iRetStatus;
	}

	DWORD dwOffset = 0,dwLength = 0,dwSBufSize = 0;
	BYTE byInsCnt = 0;
	t_disasm da;
	while(dwOffset < 0x800)
	{
		memset(&da, 0x00, sizeof(struct t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwOffset > (0x800 - dwLength))
		{
			break;
		}
		if(strstr(da.result,"J") && !strstr(da.result,"JMP"))
		{
			return iRetStatus;/*bMovCheck = true;*/
		}
		else if((strstr(da.result,"DEC") || (strstr(da.result,"ADD E") && dwLength == 3)) && dwOffset < 0x35 &&
			((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
		{
			byInsCnt++;
		}
		else if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) && dwOffset > 0x35 && byInsCnt < 4)
		{
			return iRetStatus;
		}
		else if((strstr(da.result, "CALL") || strstr(da.result, "JMP")) && (dwLength == 5))
		{
			if((!(dwOffset > 0x11) && ((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)))
			{
				return iRetStatus;
			}
			if(strstr(da.result, "JMP"))
			{
				bJmp = true;
			}
			dwOffset +=  *(DWORD *)&m_pbyBuff[dwOffset + 1] + m_dwAEPMapped + 5;
			break;
		}
		dwOffset += dwLength;
	}

	if(dwOffset < 0x1000)
	{
		return iRetStatus;
	}
	if(bJmp)
	{
		memset(m_pbyBuff , 0x00, dwBufSize);
		if(!GetBuffer(dwOffset,0x200,0x200))
		{
			return iRetStatus;
		}
		if(m_pbyBuff[0x00] == 0xE8 && m_pbyBuff[0x5] == 0xE9)
		{
			dwOffset += *(DWORD *)&m_pbyBuff[0x6] + 0xA;
		}
		else
		{
			DWORD dwMovOffset = 0;
			for(DWORD iOffset = 0; iOffset < 0x1F0; iOffset++)
			{
				if(*(WORD *)&m_pbyBuff[iOffset] == 0x01C7 && m_pbyBuff[iOffset + 6] == 0xE9)
				{
					dwMovOffset = *(DWORD *)&m_pbyBuff[iOffset + 2] - m_dwImageBase;
					bMovJmp = true;
					break;
				}
			}
			if(bMovJmp)
			{
				if(m_pMaxPEFile->Rva2FileOffset(dwMovOffset,&dwOffset) == OUT_OF_FILE)
				{
					return iRetStatus;
				}
			}
		}
		memset(m_pbyBuff , 0x00, dwBufSize);
		if(bMovJmp)
		{
			dwSBufSize = 0x400;
			if(!GetBuffer(dwOffset + 0x3700, 0x400 ,0x400))
			{
				return iRetStatus;
			}
		}
		else
		{
			if(!GetBuffer(dwOffset + 0x160, 0x20 ,0x20))
			{
				return iRetStatus;
			}
			for(DWORD iOffset = 0; iOffset < 0x16; iOffset++)
			{
				if(m_pbyBuff[iOffset] == 0x68 && m_pbyBuff[iOffset + 5] == 0xE8)
				{
					dwOffset += *(DWORD *)&m_pbyBuff[iOffset + 6] + 0xA + 0x160 + iOffset;
					bCheck = true;
					break;
				}
			}
			if(bCheck)
			{
				if(!GetBuffer(dwOffset,0x100,0x100))
				{
					return iRetStatus;
				}
				bCheck = false;
				for(DWORD iOffset = 0; iOffset < 0x60; iOffset++)
				{
					if(m_pbyBuff[iOffset] == 0x56 && m_pbyBuff[iOffset + 1] == 0xE8 && *(WORD *)&m_pbyBuff[iOffset + 6] == 0xC483)
					{
						dwOffset += *(DWORD *)&m_pbyBuff[iOffset + 2] + iOffset + 6;
						bCheck = true;
						break;
					}
				}
				if(bCheck)
				{
					dwSBufSize = 0x200;
					if(!GetBuffer(dwOffset - dwSBufSize,dwSBufSize,dwSBufSize))
					{
						return iRetStatus;
					}
				}
			}
		}
	}
	else
	{
		dwSBufSize = 0xC00;
		if(!GetBuffer(dwOffset - 0xC00, dwBufSize, dwBufSize))
		{
			return iRetStatus;
		}
	}

	CSemiPolyDBScn polydbObj;
	TCHAR szSig[] = {_T("31118B*408F0300F7*83C10469D25524000081C291C00000")};	
	polydbObj.LoadSigDBEx(szSig, _T("not.a.Virus:Monitor.Spector.gen"), FALSE);
	TCHAR szVirusName[MAX_PATH] = {0};
	if(dwSBufSize > 0)
	{
		if(polydbObj.ScanBuffer(m_pbyBuff, dwSBufSize, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}
	
	bool bloopfound = false;
	BYTE ZeroSig[0x8] = {0};
	BYTE TEMPBUF[0x8] = {0};
	dwOffset = m_pSectionHeader[0].PointerToRawData;
	for(;dwOffset < (m_pSectionHeader[0].PointerToRawData + m_pSectionHeader[0].SizeOfRawData); dwOffset += 0x1000)
	{
		if(!m_pMaxPEFile->ReadBuffer(&TEMPBUF[0x00], dwOffset, 0x8, 0x8))
		{
			return iRetStatus;
		}
		if(memcmp(&TEMPBUF[0x00],ZeroSig,sizeof(ZeroSig)) == 0)
		{
			bloopfound = true;
			break;
		}
	}
	if(!bloopfound)
	{
		return iRetStatus;
	}

	if(!GetBuffer(dwOffset, 0x1000, 0x1000))
	{
		return iRetStatus;
	}
	if(polydbObj.ScanBuffer(m_pbyBuff, 0x1000, szVirusName) >= 0)
	{
		if(_tcslen(szVirusName) > 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return VIRUS_FILE_DELETE;
		}
	}

	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectDNSChangerHD
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Satish + Virus Analysis Team
	Description		: Detection routine for different varients of DNSChanger.hd Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectDNSChangerHD()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(!(m_wNoOfSections == 2 && (m_pSectionHeader[0].Characteristics == 0xE0000020) && 
		(m_pSectionHeader[1].Characteristics == 0xE0000020) && m_pSectionHeader[1].SizeOfRawData == 0x200))
	{
		return iRetStatus;
	}
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}

	DWORD dwBufSize = 0x100;
	m_pbyBuff = new BYTE[dwBufSize + MAX_INSTRUCTION_LEN];

	if(!m_pbyBuff)
	{
		return iRetStatus;
	}

	memset(m_pbyBuff, 0x00, dwBufSize + MAX_INSTRUCTION_LEN);
	
	if(m_wAEPSec == 1)
	{

		if(!GetBuffer(m_dwAEPMapped, dwBufSize, dwBufSize))
		{
			return iRetStatus;
		}		
		
		DWORD dwOffset = 0, dwLength = 0, dwMatchedinst = 0x00, dwCallOffset =0x00;
		BYTE byOffset = 0x00, byReg = 0x00, byDecType = 0x00;
		t_disasm da;

		while(dwOffset < dwBufSize)
		{
			memset(&da, 0x00, sizeof(struct t_disasm));
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwOffset > (dwBufSize - dwLength))
			{
				break;
			}
			
			if(dwOffset > 0x40 && dwMatchedinst < 2)
			{
				return iRetStatus;
			}
			else if(strstr(da.result, "CALL") && dwMatchedinst < 2)
			{
				if(dwLength != 5 && dwMatchedinst == 0x00)
				{
					return iRetStatus;
				}
				dwCallOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwOffset + m_dwAEPUnmapped + 5;
				dwMatchedinst = 1;
			}
			else if(dwMatchedinst == 0x1 && strstr(da.result,"SUB E") && ((*(DWORD *)&m_pbyBuff[dwOffset + 2] < (dwCallOffset + 0x10)) && (*(DWORD *)&m_pbyBuff[dwOffset + 2] > (dwCallOffset - 0x10))))
			{
				if(dwLength != 6 || dwOffset > 0x40)
				{
					return iRetStatus;
				}
				dwCallOffset = *(DWORD *)&m_pbyBuff[dwOffset + 2];
				dwMatchedinst++;			
			}
			else if(dwMatchedinst == 0x2 && dwLength == 6 && strstr(da.result,"ADD E") && (da.immconst >= 0x20 && da.immconst < 0x50))
			{
				byOffset = (BYTE)da.immconst;
				dwMatchedinst++;
			}
			else if(dwMatchedinst == 0x3 && dwLength == 2 && strstr(da.result,"JMP [E"))
			{
				DWORD dwTemp = dwCallOffset + byOffset - m_dwAEPUnmapped;
				byReg = m_pbyBuff[dwOffset + 1] - 0x20;
				if(dwTemp > dwBufSize || (m_pbyBuff[dwTemp] != (byReg + 0x58)))
				{
					return iRetStatus;
				}
				dwMatchedinst++;			
			}
			else if(dwMatchedinst == 0x04 && dwLength == 0x6 && strstr(da.result,"ADD E") && da.immconst == 0x1000)
			{
				dwMatchedinst++;
			}
			else if(dwMatchedinst == 0x05 && dwLength == 0x06 && strstr(da.result,"ADD E"))
			{
				byReg = m_pbyBuff[dwOffset + 1];
				dwCallOffset = *(DWORD *)&m_pbyBuff[dwOffset + 2];
				dwMatchedinst++;
			}
			else if(dwMatchedinst == 0x06 && dwLength == 0x02 && strstr(da.result,"JMP"))
			{
				dwOffset =(BYTE)(m_pbyBuff[dwOffset + 1] + dwOffset);
				byOffset = 0x010;
			}
			else if(dwMatchedinst == 0x06 && dwLength == 0x06 && strstr(da.result,"ADD E") && byOffset == 0x10)
			{
				if(m_pbyBuff[dwOffset + 1] != byReg || (*(DWORD *)&m_pbyBuff[dwOffset + 0xA] != da.immconst))
				{
					return iRetStatus;
				}
				dwCallOffset += (da.immconst + m_dwImageBase + 0x1000);
				dwMatchedinst++;
			}
			else if(dwMatchedinst == 7 && dwLength == 0x2 && strstr(da.result,"SUB [E"))
			{
				byDecType = 0x2;
				break;
			}
			else if(dwMatchedinst == 7 && dwLength == 0x2 && strstr(da.result,"ADD [E"))
			{
				byDecType = 0x1;
				break;
			}
			else if(dwMatchedinst == 7 && dwLength == 0x2 && strstr(da.result,"XOR [E"))
			{
				byDecType = 0x3;
				break;
			}		
			dwOffset += dwLength;
		}

		if(byDecType == 0)
		{
			return iRetStatus;
		}
		

		memset(m_pbyBuff, 0x00, dwBufSize);

		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x00],m_pSectionHeader[0].PointerToRawData + 0xC80, dwBufSize, dwBufSize))
		{
			return iRetStatus;
		}

		switch(byDecType)
		{
		case 1:
			{
				for(BYTE bOffset = 0x00;bOffset < 0xA0;bOffset += 4)
				{
					*(DWORD *)&m_pbyBuff[bOffset] += dwCallOffset;
				}
			}
			break;
		case 2:
			{
				for(BYTE bOffset = 0x00;bOffset < 0xA0;bOffset += 4)
				{
					*(DWORD *)&m_pbyBuff[bOffset] -= dwCallOffset;
				}
			}
			break;
		case 3:
			{
				for(BYTE bOffset = 0x00;bOffset < 0xA0;bOffset += 4)
				{
					*(DWORD *)&m_pbyBuff[bOffset] ^= dwCallOffset;
				}
			}
			break;
		default:
			break;
		}
	}
	else
	{
		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x00],m_pSectionHeader[0].PointerToRawData + 0xC80, dwBufSize, dwBufSize))
		{
			return iRetStatus;
		}
	}
	BYTE DNS_SIG[] = {0x67, 0x6F, 0x66, 0x75, 0x63, 0x6B, 0x79, 0x6F, 0x75, 0x72, 0x73, 0x65, 0x6C, 0x66, 0x2E, 0x6E, 0x65, 0x74};
	if(OffSetBasedSignature(DNS_SIG, sizeof(DNS_SIG), NULL))
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.DNSChanger.hd"));
		return VIRUS_FILE_DELETE;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPackedCpex
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Satish + Virus Analysis Team
	Description		: Detection routine for different varients of Packed.CPEX Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectPackedCpex()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stPEHeader.DataDirectory[2].Size) == m_pMaxPEFile->m_dwFileSize))
	{
		return iRetStatus;
	}	
	BYTE byFileEndBytes[0xA] = {0};
	if(!m_pMaxPEFile->ReadBuffer(&byFileEndBytes[0x00],m_pMaxPEFile->m_dwFileSize - 0xA,0xA,0xA))
	{
		return iRetStatus;
	}
	if(*(WORD *)&byFileEndBytes[0x8] != 0x1B)
	{
		return iRetStatus;
	}
	
	unsigned int bValue = 0,bpower10 = 1;
	int bCount = 0,bDig = 1;
	for(bCount = 7;bCount >= 0;bCount--)
	{
		if(byFileEndBytes[bCount] == 0x20)
		{
			continue;
		}
		if(byFileEndBytes[bCount] > 0x39 || byFileEndBytes[bCount] < 0x30)
		{
			return iRetStatus;
		}
		bValue += ((byFileEndBytes[bCount] % 0x30) * bpower10);
		bpower10 = bpower10 * 10;
	}	
	DWORD dwOffset = m_pMaxPEFile->m_dwFileSize - (bValue + 0xA);
	DWORD dwValue = 0x00;

	if(!m_pMaxPEFile->ReadBuffer(&dwValue,dwOffset,0x2,0x2))
	{
		return iRetStatus;
	}

	if(dwValue == 0xCF4F)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Packed.cpex.based.ht"));
		return VIRUS_FILE_DELETE;
	}
	else
	{
		dwOffset -= 2;
		if(!m_pMaxPEFile->ReadBuffer(&dwValue,dwOffset,0x2,0x2))
		{
			return iRetStatus;
		}
		if(dwValue == 0x5D23)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Packed.Cpex.Based.ht"));
			return VIRUS_FILE_DELETE;
		}		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Prashant + Virus Analysis Team
	Description		: Detection routine for different varients of Palevo Family
			   	      A. Installation:	
						- Copy itself to C:\Documents and Settings\admin\Application Data\.
				      B. File Modification 
						- C:\Documents and Settings\admin\Application Data\<Random>.exe
				      C. Registry Modifications:
						- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman: "C:\Documents and Settings\admin\Application Data\<Random>.exe"
						Intention  : Call sequnce.
						Detection  : 99.00%
--------------------------------------------------------------------------------------*/
int CTrojans::DetectPalevo()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	//---------------------------------P2P-Worm.Palevo.arxz---------------------------------------
	DWORD dwSRD = m_pSectionHeader[m_wAEPSec].SizeOfRawData;
	if(m_wAEPSec == 0x0 && (m_wNoOfSections == 0x4 || m_wNoOfSections == 0x5 || m_wNoOfSections == 0x6) && ((m_dwAEPUnmapped & 0xF00F) == 0x4000 || (m_dwAEPUnmapped & 0xF00F) == 0x5000 || (m_dwAEPUnmapped & 0xF00F) == 0x3000) && 
		(dwSRD == 0xDA00 || dwSRD == 0xDC00 || dwSRD == 0x9800 || dwSRD == 0x9600 || dwSRD == 0x9400))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int PALEVO_BUFF_SIZE = 0x80;
		m_pbyBuff = new BYTE[PALEVO_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwAEPMapped, PALEVO_BUFF_SIZE, PALEVO_BUFF_SIZE))
		{
			return iRetStatus;
		}

		if(m_pbyBuff[0] != 0x55)
			return iRetStatus;

		DWORD dwOffset = 0, dwLength = 0, dwHits = 0;
		t_disasm dasm;
		bool bSkeepPriInst = true;
		while(dwOffset < PALEVO_BUFF_SIZE)
		{
			memset(&dasm, 0x00, sizeof(struct t_disasm));
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset] , MAX_INSTRUCTION_LEN, 0x400000, &dasm, DISASM_CODE);
			if(dwOffset > (PALEVO_BUFF_SIZE - dwLength))
			{
				break;
			}
			if((dwLength == 0x1) && strstr(dasm.result,"PUSH EBP") && dwHits == 0x0)
				dwHits++;
			else if(((dwLength == 0x6) && strstr(dasm.result,"JNB") || ((dwLength == 0x2 || dwLength == 0x5) && strstr(dasm.result,"PUSH"))) && dwHits == 0x1)
				dwHits++;
			else if((((dwLength == 2) && strstr(dasm.result,"JMP E")) || ((dwLength == 1) && strstr(dasm.result,"???"))) && dwHits == 0x2)
				dwHits++;
			else if((dwLength == 5) && strstr(dasm.result,"CALL 003") && dwHits == 0x3)
				dwHits++;
			else if(m_pbyBuff[dwOffset] == 0xC0&& dwHits == 0x4 && dwLength == 0x1)
			{
				dwOffset += 0x3;
				continue;
			}else if(m_pbyBuff[dwOffset] == 0x66 && m_pbyBuff[dwOffset + 1] == 0xC1 && dwHits == 0x4 && dwLength == 0x2)
			{
				dwOffset += 0x4;
				continue;
			}else if(m_pbyBuff[dwOffset] == 0xE0 && dwHits == 0x4 && dwLength == 0x1)
			{
				dwOffset += 0x2;
				continue;
			}
			else if((dwLength == 6) && strstr(dasm.result,"ADD E") && dwHits == 0x04)
				dwHits++;
			else if((dwLength == 2 || dwLength == 5) && strstr(dasm.result,"PUSH") && dwHits == 0x05)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("P2P-Worm.Palevo.arxz"));
				return VIRUS_FILE_DELETE;
			}
			dwOffset += dwLength;		
		}
	}
	//---------------------------------P2P-Worm.Palevo.fuc---------------------------------------
	/*
			ADD DWORD PTR [], Value
			-
			-
			CALL Offset

			this pattern 5 times
	*/
	if(m_wAEPSec == 0x0 && m_dwAEPUnmapped - m_dwAEPMapped == 0xC00 && (m_dwAEPUnmapped % 0x2) == 0x0 && m_wNoOfSections >= 0x3 && m_wNoOfSections <= 0x5
		&& ((dwSRD & 0xF00FF) == 0x10000 || (dwSRD & 0xF00FF) == 0x20000 || (dwSRD & 0xF0FFF) == 0x40000 || (dwSRD & 0xF000) == 0x4000 || (dwSRD & 0xF000) == 0x5000 || (dwSRD & 0xF000) == 0xA000
		|| (dwSRD & 0xF000) == 0xB000 || (dwSRD & 0xF000) == 0xC000 || (dwSRD & 0xF000) == 0xF000 || (dwSRD & 0xF000) == 0x9000))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int PALEVO_BUFF_SIZE = 0x200;
		m_pbyBuff = new BYTE[PALEVO_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwAEPMapped, PALEVO_BUFF_SIZE, PALEVO_BUFF_SIZE))
		{
			return iRetStatus;
		}

		if(m_pbyBuff[0] != 0x55 && m_pbyBuff[0] != 0x50)
			return iRetStatus;

		DWORD dwOffset = 0, dwLength = 0, dwHits = 0;
		t_disasm dasm;
		bool bADDGot= false;
		BYTE bAddChk[0x06] = {0};
		DWORD dwCallOffsets[0x05] = {0};
		while(dwOffset < PALEVO_BUFF_SIZE)
		{
			memset(&dasm, 0x00, sizeof(struct t_disasm));
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset] , MAX_INSTRUCTION_LEN, 0x400000, &dasm, DISASM_CODE);
			if(dwOffset > (PALEVO_BUFF_SIZE - dwLength))
			{
				break;
			}
			else if(((dwLength == 0x07 && strstr(dasm.result, "ADD DWORD PTR [")) || (dwLength == 0x0A && strstr(dasm.result, "ADD DWORD PTR ["))) && bADDGot == false)
			{
				if(dwHits == 0x0)
				{
					if(dwLength == 0x7)
					{
						for(int i = 0; i < 0x03; i++)
							bAddChk[i] = m_pbyBuff[dwOffset + i];
					}
					else if(dwLength == 0x0A)
					{
						for(int i = 0; i < 0x06; i++)
							bAddChk[i] = m_pbyBuff[dwOffset + i];
					}
					bADDGot = true;
				}
				else if(memcmp(&m_pbyBuff[dwOffset], bAddChk, 0x03) == 0x0 || memcmp(&m_pbyBuff[dwOffset], bAddChk, 0x06) == 0x0)
				{
					bADDGot = true;
				}
			}
			else if(dwLength == 0x5 && strstr(dasm.result,"CALL 003") && bADDGot == true)
			{	
				dwCallOffsets[dwHits++] = dwLength + *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwOffset + m_dwAEPUnmapped;
				bADDGot = false;
			}
			if(dwHits == 0x5) // Call search at call body
			{
				bool bCallDetect = false;
				int iCallIndex = 0x1;
				
				if(dwCallOffsets[0] == 0x1000)
					iCallIndex = 0x2;
				
				DWORD dwBuffReadOff  = dwCallOffsets[iCallIndex];
				DWORD dwCallOffset   = 0;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwBuffReadOff, &dwBuffReadOff))
					return iRetStatus;

				if(!GetBuffer(dwBuffReadOff, PALEVO_BUFF_SIZE, PALEVO_BUFF_SIZE))
					return iRetStatus;
				int iCalls = iCallIndex;
				dwOffset = 0;
				while(iCalls < 0x05 && dwCallOffsets[iCalls] < (dwCallOffsets[iCallIndex]+ PALEVO_BUFF_SIZE))
				{	
					while(dwOffset < PALEVO_BUFF_SIZE)
					{
						memset(&dasm, 0x00, sizeof(struct t_disasm));
						dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset] , MAX_INSTRUCTION_LEN, 0x400000, &dasm, DISASM_CODE);
						if(dwOffset > (PALEVO_BUFF_SIZE - dwLength))
						{
							break;
						}
						else if((dwLength == 0x05 && strstr(dasm.result, "CALL 003")))
						{
							dwCallOffset = (dwLength + *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwCallOffsets[iCallIndex] + dwOffset);
							for(int i = 0; i <= iCalls; i++)		// Call matching
								if(dwCallOffsets[i] == dwCallOffset)
								{	
									bCallDetect = true;
									break;
								}
						}
						else if(strstr(dasm.result,"NOP"))
							break;

						if(bCallDetect == true)
							break;
						dwOffset += dwLength;
					}
					if(bCallDetect == true)
							break;
					dwOffset = dwCallOffsets[++iCalls] - dwCallOffsets[iCallIndex];
				}
				if(bCallDetect == true)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("P2P-Worm.Palevo.fuc"));
					return VIRUS_FILE_DELETE;
				}
			}
			dwOffset += dwLength;		
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPSWKatesC
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Prajakta + Virus Analysis Team
	Description		: Detection routine for different varients of PSW.Kates.C Family
					  A. Trojan that attempts to terminate currently-running antivirus and other security programs.
					  B. Some of the security products that it stops are:
						AVG Anti-virus
						GMER Rootkit Detector and Remover
				      C. Arrives in the system as a DLL file that is dropped and loaded by other malware.
--------------------------------------------------------------------------------------*/
int CTrojans::DetectPSWKatesC()
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	DWORD	dwTimeDateStamp = 0;

	m_pMaxPEFile->ReadBuffer(&dwTimeDateStamp, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x8, 4, 4);

	if( m_wNoOfSections == 0x6 && m_wAEPSec == 0x0 && 
		(memcmp(m_pSectionHeader[m_wAEPSec].Name, "CODE", 4) == 0) && 
		m_pSectionHeader[m_wAEPSec + 0x2].SizeOfRawData == 0x0 && dwTimeDateStamp == 0x2A425E19 &&
		(m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int PSWKATESC_BUFF_SIZE = 0x120;
		m_pbyBuff = new BYTE[PSWKATESC_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData + 0xB50, PSWKATESC_BUFF_SIZE, PSWKATESC_BUFF_SIZE))
		{
			return iRetStatus;
		}
		BYTE PSWKATESC_SIG[] = {0x56,0x53,0x50,0x96,0x31,0xC0,0x31,0xC9,0x31}; //VSP.1.1.1

		if(!OffSetBasedSignature(PSWKATESC_SIG,sizeof(PSWKATESC_SIG),NULL))
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwAEPMapped, 0x20, 0x20))
		{
			return iRetStatus;
		}
		if(m_pbyBuff[0x0] == 0x55 && m_pbyBuff[0x1] == 0x8B && m_pbyBuff[0x2] == 0xEC && 
			m_pbyBuff[0x3] == 0x83 && m_pbyBuff[0x4] == 0xC4 && m_pbyBuff[0x5] == 0xC4)
		{
			DWORD		dwLength = 0, dwOffset = 0, dwMatchedInstr = 0,dwCallRVA = 0;
			t_disasm	da;
			while(dwOffset < PSWKATESC_BUFF_SIZE)
			{
				memset(&da, 0x00, sizeof(struct t_disasm));
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (PSWKATESC_BUFF_SIZE - dwOffset))
				{
					return iRetStatus;
				}				
				if(dwLength == 0x05 && dwMatchedInstr == 0x0 && strstr(da.result, "MOV EAX,"))
				{
					if(m_dwAEPUnmapped - (da.immconst - m_dwImageBase)  == 0x30)
						dwMatchedInstr++;
					else 
						return iRetStatus;
				}
				else if(dwLength == 0x5 && dwMatchedInstr == 0x1 && strstr(da.result, "CALL"))
				{	
					dwCallRVA = *((DWORD *)&m_pbyBuff[dwOffset + 1]) + 0x05 + m_dwAEPUnmapped + dwOffset;
					if(dwCallRVA == 0x17FC)
						dwMatchedInstr++;
					else 
						return iRetStatus;
				}
				else if(dwLength == 0x5 && dwMatchedInstr == 0x2 && strstr(da.result, "MOV EAX,1"))
				{	
					dwMatchedInstr++;
				}
				else if(dwLength == 0x5 && dwMatchedInstr == 0x3 && strstr(da.result, "CALL"))
				{	
					dwMatchedInstr++;
				}
				else if(dwLength == 0x5 && dwMatchedInstr == 0x4 && strstr(da.result, "CALL"))
				{	
					dwCallRVA = *((DWORD *)&m_pbyBuff[dwOffset + 1]) + 0x05 + m_dwAEPUnmapped + dwOffset;
					if(dwCallRVA == 0x14F8)
					{
						dwMatchedInstr++;
						break;
					}
					else 
						return iRetStatus;
				}
				dwOffset += dwLength;
			}
			if(dwMatchedInstr == 0x5)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.PSW.Kates.C"));
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSinowalEEE
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Prashant + Virus Analysis Team
	Description		: Detection routine for different varients of Sinowal Family
					  A. Installation:	
						- Create service
						- Copy it self to *.tmp files.
				      B. File Modification 
						- C:\WINDOWS\Temp\4.tmp
						- C:\Documents and Settings\admin\Local Settings\Temp\2.tmp
						- C:\Documents and Settings\admin\Local Settings\Temp\3.tmp
						- C:\WINDOWS\TEMP\5.tmp
					 C. Registry Modifications:
						- HKLM\SYSTEM\CurrentControlSet\Services\
						- HKLM\SYSTEM\CurrentControlSet\Services\{DEF85C80-216A-43ab-AF70-1665EDBE2780}\ImagePath: "\??\C:\WINDOWS\TEMP\5.tmp"
					 Detection  : 100%
--------------------------------------------------------------------------------------*/
int CTrojans::DetectSinowalEEE()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if (m_wAEPSec == 0x0 && m_wNoOfSections >= 0x3 && m_wNoOfSections <= 0x8 && 
		m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 0x5E00 &&  m_pSectionHeader[m_wAEPSec].SizeOfRawData <= 0xC000 && (m_pSectionHeader[m_wAEPSec].SizeOfRawData & 0x00FF) == 0x0 &&
		m_pSectionHeader[m_wAEPSec].Characteristics == 0x68000020 &&
		(m_dwAEPUnmapped % 0x4) == 0x0)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int SINOWAL_BUFF_SIZE = 0x150;
		m_pbyBuff = new BYTE[SINOWAL_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwAEPMapped, SINOWAL_BUFF_SIZE, SINOWAL_BUFF_SIZE))
		{
			return iRetStatus;
		}

		DWORD		dwOffset = 0x0, dwLength = 0x0, dwHits = 0x0;
		DWORD		dwWordOffset = 0x0;
		WORD		wCmpWord = 0x0;
		WORD		wInstCounter = 0x0;
		bool		bMovFound = false;
		bool		bPushFound = false;
		char		*cRegisterSearch = NULL;
		char		cNextInstr[20] = {0};
		char		cNextInstr1[20]	= {0};
		t_disasm	dasm;

		while(dwOffset < SINOWAL_BUFF_SIZE)
		{
			memset(&dasm, 0x00, sizeof(struct t_disasm));
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset] , MAX_INSTRUCTION_LEN, 0x400000, &dasm, DISASM_CODE);
			if(dwOffset > (SINOWAL_BUFF_SIZE - dwLength))
			{
				break;
			}
			wInstCounter++;
			if((dwLength == 0x2) && strstr(dasm.result,"???") && dwHits == 0x0 && m_pbyBuff[dwOffset] == 0x0F && m_pbyBuff[dwOffset + 1] == 0x1F)
			{
				while(bPushFound == false)
				{
					dwOffset++;
					if(m_pbyBuff[dwOffset] >= 0x50 && m_pbyBuff[dwOffset] <= 0x57)
						bPushFound = true;
				}
				continue;
			}
			else if((dwLength == 0x1) && strstr(dasm.result,"PUSH E") && dwHits == 0x0)
			{
				cRegisterSearch = strchr(dasm.result,' ');
				sprintf_s(cNextInstr,20,"POP%s",cRegisterSearch);
				dwHits++;
			}
			else if((dwLength == 0x1) && strstr(dasm.result, cNextInstr) && dwHits == 0x1)
				dwHits++;
			else if(((dwLength == 0x5 && strstr(dasm.result,"JMP 00")) || (dwLength == 0x2 && strstr(dasm.result,"JMP SHORT 00")))  && dwHits == 0x2 && wInstCounter < 0x15)
				dwHits++;
			else if(dwHits >= 0x3 && dwHits <= 0x5)
			{
				if(strstr(dasm.result, "???"))
				{
					bPushFound = false;
					while(bPushFound == false)
					{
						dwOffset++;
						if(m_pbyBuff[dwOffset] == 0x66 && m_pbyBuff[dwOffset + 1] != 0x0F && m_pbyBuff[dwOffset + 2] != 0x1F)
							bPushFound = true;
					}
					continue;
				}
				else if((dwLength == 0x6 || dwLength == 0x7) && strstr(dasm.result,"MOV") && bMovFound == false && m_pbyBuff[dwOffset] == 0x66)
				{
					dwWordOffset = dasm.adrconst - m_dwImageBase;
					if(m_wAEPSec != m_pMaxPEFile->Rva2FileOffset(dwWordOffset, &dwWordOffset))
						return iRetStatus;

					if(!m_pMaxPEFile->ReadBuffer(&wCmpWord, dwWordOffset, 0x02, 0x02))
						return iRetStatus;
					
					cRegisterSearch = strchr(dasm.result, ',');
					cRegisterSearch -= 0x02;
					memset(&cRegisterSearch[2], 0, 1);
					sprintf_s( cNextInstr, 20, "CMP %s", cRegisterSearch);
					sprintf_s(cNextInstr1, 20, "TEST %s", cRegisterSearch);
					bMovFound = true;
					
				}
				else if((dwLength == 0x4 || dwLength == 0x5) && (strstr(dasm.result,cNextInstr) || strstr(dasm.result,cNextInstr1)) && bMovFound == true && m_pbyBuff[dwOffset] == 0x66)
				{
					if(wCmpWord == dasm.immconst)
						dwHits++;
					bMovFound = false;
				}
			}
			if(dwHits == 0x5 && bMovFound == false)
			{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Backdoor.Win32.Sinowal.eee"));
					return VIRUS_FILE_DELETE;
			}
			dwOffset += dwLength;		
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectKatushaQ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Prashant + Virus Analysis Team
	Description		: Detection routine for different varients of Katusha.Q Family
					  A. Installation:	
						- Create its copy in to Application Data and adds entry into registry on windows strat.
				      B. File Modification 
						- C:\Documents and Settings\admin\Local Settings\Application Data\<Randome>\<Randome>.exe
					  C. Registry Modifications:
						- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\gkehokor: "C:\Documents and Settings\admin\Local Settings\Application Data\<Randome>\<Randome>.exe"
					  Detection  : 99.53%(1278)
--------------------------------------------------------------------------------------*/
int CTrojans::DetectKatushaQ()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if (m_wAEPSec == 0x0 && ((m_pSectionHeader[m_wAEPSec].SizeOfRawData & 0xF00) % 0x200) == 0x0 &&
	   ((m_wNoOfSections == 0x04 && 
	   ((m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData & 0xF00FF) == 0x40000 || (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData & 0xF00FF) == 0xE0000 || (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData & 0xF00FF) == 0xF0000)) || 
	   (m_wNoOfSections == 0x05 && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x0)))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int	KATUSHA_BUFF_SIZE = 0xF00;
		m_pbyBuff = new BYTE[KATUSHA_BUFF_SIZE];

		BYTE	byChk1[] = {0x42, 0x00, 0x49, 0x00, 0x4E, 0x00, 0x41, 0x00, 0x52, 0x00, 0x59, 0x00}; //B.I.N.A.R.Y.
		DWORD	dwBufOff = 0x0;
		bool	bChkFound  = false;
		bool	bDetection = false;

		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0], m_pSectionHeader[0x03].PointerToRawData + 0xE0, 0x100, 0x100)) // To read from .rscr section
		{
			for(int i = 0x0; i < (0x100 - sizeof(byChk1)); i++)
			{
				if(memcmp(&m_pbyBuff[i], byChk1, sizeof(byChk1)) == 0x0)
				{	
					bChkFound = true;
					break;
				}
			}
		}
		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0], m_dwAEPMapped, KATUSHA_BUFF_SIZE, KATUSHA_BUFF_SIZE))
		{
			return iRetStatus;
		}

		//-------------------Normalize Buffer(NB) remove 0x90 ----------------
		DWORD	dwFstDetection = 0x0;
		DWORD	dwLstDetection = 0x0;
		int		i = 0x0, iCountNB = 0x0;
		bool	bBreak = false;

		while(iCountNB < 0x4)
		{	
			if(dwFstDetection != 0x0)
			{	
				i = dwFstDetection;
				dwFstDetection = 0x0;
				dwLstDetection = 0x0;
			}
			for(; i < KATUSHA_BUFF_SIZE; i++)
			{
				if(m_pbyBuff[i] == 0x90 && dwLstDetection == 0x0)
				{
					if(dwFstDetection == 0x0)
					{
						dwFstDetection = i;
					}
					if(m_pbyBuff[i + 1] != 0x90 && dwLstDetection == 0x0)
					{	
						dwLstDetection = i;
						break;
					}
					if(iCountNB == 0 && i > 0x150)
					{	
						bBreak = true;
						break;
					}
				}
			}
			if(dwFstDetection != dwLstDetection)
			{	for(int i = dwFstDetection, j = 0; i < 0x200; i++,j++)
				{
					if(j < 0x200 && (dwFstDetection + j) < KATUSHA_BUFF_SIZE)
					{
						m_pbyBuff[i]= m_pbyBuff[dwLstDetection + 1 + j];
					}
					else
					{
						break;	
					}
				}
			}
			else
			{
				dwFstDetection++;
			}
			
			if(bBreak == true)
			{
				break;			
			}
			iCountNB++;
		}
		//-------------------End Normalization----------------------------
		DWORD	dwEAX = 0x0;
		DWORD	dwConstant = 0x0;

		while((dwBufOff) < (KATUSHA_BUFF_SIZE - 0x40))
		{
			if(m_pbyBuff[dwBufOff] == 0xA9 && m_pbyBuff[dwBufOff + 0x5] == 0x74 && m_pbyBuff[dwBufOff + 0x6] == 0x01 && m_pbyBuff[dwBufOff + 0x07] == 0xC3 && m_pbyBuff[dwBufOff + 0x08] == 0x69 && m_pbyBuff[dwBufOff + 0x09] == 0xC0)
			{
				dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x1];
				dwEAX = 0xFFFFFFFF - dwConstant;					// TEST EAX, CONST
				dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x0A];
				dwEAX = dwEAX * dwConstant;							// IMUL EAX * EAX * CONST
				if(m_pbyBuff[dwBufOff + 0x0E] == 0xA9 && m_pbyBuff[dwBufOff + 0x13] == 0x75 && m_pbyBuff[dwBufOff + 0x15] == 0x35 && m_pbyBuff[dwBufOff + 0x1A] == 0x74 && m_pbyBuff[dwBufOff + 0x1C] == 0x05 && m_pbyBuff[dwBufOff + 0x21] == 0x50 && m_pbyBuff[dwBufOff + 0x22] == 0x75 && m_pbyBuff[dwBufOff + 0x23] == 0xDC)
				{
					dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x16];
					dwEAX = dwEAX ^ dwConstant;						// XOR EAX, CONST
					dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x1D];
					dwEAX = dwEAX + dwConstant;						// ADD EAX, CONST
					bDetection = true;
					break;
				}
				if(m_pbyBuff[dwBufOff + 0x0E] == 0x35 && (m_pbyBuff[dwBufOff + 0x13] == 0x74 || m_pbyBuff[dwBufOff + 0x14] == 0x74)) 
				{
					int i = 0x0;
					if(m_pbyBuff[dwBufOff + 0x14] == 0x74)
					{
						i = 0x1;
					}
					if((m_pbyBuff[dwBufOff + 0x15 + i] == 0x2D || m_pbyBuff[dwBufOff + 0x15 + i] == 0x05) && m_pbyBuff[dwBufOff + 0x1A + i] == 0xFF && m_pbyBuff[dwBufOff + 0x1B + i] == 0xD0 && (m_pbyBuff[dwBufOff + 0x1C + i] == 0xC2 || m_pbyBuff[dwBufOff + 0x1C + i] == 0xC3))
					{
						dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x0F];
						dwEAX = dwEAX ^ dwConstant;						// XOR EAX, CONST
						dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x16 + i];
						if(m_pbyBuff[dwBufOff + 0x15 + i] == 0x2D)
						{
							dwEAX = dwEAX - dwConstant;						// SUB EAX, CONST
						}
						else
						{
							dwEAX = dwEAX + dwConstant;						// ADD EAX, CONST
						}
						bDetection = true;
						break;
					}
				}
				if(m_pbyBuff[dwBufOff + 0x0E] == 0x35 && m_pbyBuff[dwBufOff + 0x13] == 0x74 && m_pbyBuff[dwBufOff + 0x15] == 0x05 && m_pbyBuff[dwBufOff + 0x1A] == 0x50 && m_pbyBuff[dwBufOff + 0x1B] == 0x75 && m_pbyBuff[dwBufOff + 0x1C] == 0xE3)
				{
					dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x0F];
					dwEAX = dwEAX ^ dwConstant;						// XOR EAX, CONST
					dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x16];
					dwEAX = dwEAX + dwConstant;						// ADD EAX, CONST
					bDetection = true;
					break;
				}				
			}
			else if(m_pbyBuff[dwBufOff] == 0xA9 && m_pbyBuff[dwBufOff + 0x5] == 0x74 && m_pbyBuff[dwBufOff + 0x6] == 0x01 && m_pbyBuff[dwBufOff + 0x07] == 0xC3 && m_pbyBuff[dwBufOff + 0x08] == 0x05 && m_pbyBuff[dwBufOff + 0x0D] == 0x69 && m_pbyBuff[dwBufOff + 0x0E] == 0xC0)
			{
				dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x01];
				dwEAX = 0xFFFFFFFF - dwConstant - 0x10;					// TEST EAX, CONST
				dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x09];
				dwEAX +=  dwConstant;								//ADD EAX, CONST
				dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x0F];
				dwEAX = dwEAX * dwConstant;							// IMUL EAX * EAX * CONST
				if(m_pbyBuff[dwBufOff + 0x13] == 0x35 && m_pbyBuff[dwBufOff + 0x19] == 0x74 && m_pbyBuff[dwBufOff + 0x1B] == 0x2D && m_pbyBuff[dwBufOff + 0x20] == 0xFF && m_pbyBuff[dwBufOff + 0x21] == 0xD0)
				{
					dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x14];
					dwEAX = dwEAX ^ dwConstant;						// XOR EAX, CONST
					dwConstant = *(DWORD *)&m_pbyBuff[dwBufOff + 0x1C];
					dwEAX = dwEAX - dwConstant;						// SUB EAX, CONST
					bDetection = true;
					break;
				}
			}
			dwBufOff++;
		}
		if(bDetection == true)
		{
			dwEAX = dwEAX - m_dwImageBase;
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwEAX, &dwEAX))
			{
				return iRetStatus;
			}

			if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0], dwEAX, 0x02, 0x02))
			{
				if( bChkFound == true)
				{	if((m_pbyBuff[0] == 0x55 && m_pbyBuff[0x1] == 0xE9) || m_pbyBuff[0] == 0x05)
					{	
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Packed.Katusha.q"));
						return VIRUS_FILE_DELETE;
					}
				}
				else
				{
					if(m_pbyBuff[0] == 0x05)
					{	
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Packed.Krap.ic"));
						return VIRUS_FILE_DELETE;
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectGLDCT
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of Downloader.GLDCT Family
					  Downloader.GLDCT.a, Downloader.GLDCT.i, Downloader.GLDCT.C	
--------------------------------------------------------------------------------------*/
int CTrojans::DetectGLDCT()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x07 && 
		m_dwAEPUnmapped == 0x1140 &&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[9].VirtualAddress != 0x00 &&
		(memcmp(m_pSectionHeader[m_wNoOfSections - 3].Name, ".CRT", 4) == 0x00))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x40];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		DWORD dwReadOff = 0x00;
		if(m_pSectionHeader[1].SizeOfRawData < 0xA000)
		{
			dwReadOff = m_pSectionHeader[1].PointerToRawData + m_pSectionHeader[1].Misc.VirtualSize - 0x1B8;;
		}
		else
		{
			dwReadOff = m_pSectionHeader[1].PointerToRawData + m_pSectionHeader[1].SizeOfRawData - 0x1B70;
		}
			
		if(!GetBuffer(dwReadOff, 0x40, 0x40))
		{
			return iRetStatus;
		}
		// Creating process with this name "48"
		BYTE bSig[] = {0x22,0x00,0x00,0x00,0x22,0x00,0x20,0x00,0x34,0x00,0x38,0x00};
		CMaxBMAlgo pBMScan;
		pBMScan.AddPatetrn2Search(bSig, sizeof(bSig));

		if(pBMScan.Search4Pattern(m_pbyBuff, 0x40))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:Downloader.GLDCT.a"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectBackDoorLavanDos
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Satish + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of Lavandos Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectBackDoorLavanDos()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	if(!(((m_wNoOfSections == 5) || (m_wNoOfSections == 6 && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0)) && m_wAEPSec == 0 && m_pSectionHeader[m_wAEPSec].SizeOfRawData <= 0x5000))
	{
		return iRetStatus;
	}
	
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	DWORD	dwBufSize = 0x400;

	m_pbyBuff = new BYTE[dwBufSize];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}

	memset(m_pbyBuff, 0x00, dwBufSize);
	if(!GetBuffer(m_dwAEPMapped, dwBufSize, dwBufSize))
	{
		return iRetStatus;
	}

	DWORD	dwDecOffset = 0x00, iOffset = 0x00;
	BYTE	byDecKey = 0x00;
	
	for(iOffset = 0x00; iOffset < 0x100; iOffset++)
	{
		if(m_pbyBuff[iOffset] == 0x60 && m_pbyBuff[iOffset + 1] == 0x68 && m_pbyBuff[iOffset + 0x6] == 0xE8 && m_pbyBuff[iOffset + 0xB] == 0x61)
		{
			dwDecOffset = 0x200;
			break;
		}
	}

	if(dwDecOffset != 0x200)
	{
		return iRetStatus;
	}

	for(; iOffset < (dwBufSize - 0x30); iOffset++)
	{
		if(m_pbyBuff[iOffset] == 0xFF && m_pbyBuff[iOffset + 1] == 0x35 && m_pbyBuff[iOffset + 0x6] == 0x68 && m_pbyBuff[iOffset + 0xB] == 0xE8 && m_pbyBuff[iOffset + 0x10] == 0xFF && m_pbyBuff[iOffset + 0x11] == 0xD0)
		{
			dwDecOffset = *(DWORD *)&m_pbyBuff[iOffset + 0x7] - m_dwImageBase;
			break;
		}
	}

	if(dwDecOffset == 0x00)
	{
		return iRetStatus;
	}

	if(m_pMaxPEFile->Rva2FileOffset(dwDecOffset,&dwDecOffset) == OUT_OF_FILE)
	{
		return iRetStatus;
	}

	if(!GetBuffer(dwDecOffset + 0x1, 0xA, 0xA))
	{
		return iRetStatus;
	}

	if(m_pbyBuff[0] == 0)
	{
		return iRetStatus;
	}

	byDecKey = m_pbyBuff[0];
	for(BYTE i = 0; i < 8; i++)
	{
		m_pbyBuff[i + 2] ^= byDecKey;		
		byDecKey = byDecKey << 0x2 | byDecKey >> (0x08 - 0x2);
	}

	if(memcmp(&m_pbyBuff[0x2], "kernel32", 0x8) == 0x00)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Backdoor.Lavandos.a"));
		return VIRUS_FILE_DELETE;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDiamin
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of Diamin Family
--------------------------------------------------------------------------------------*/
int	CTrojans::DetectDiamin()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}

	if (m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x19 &&
		m_pMaxPEFile->m_stPEHeader.SizeOfCode < m_dwAEPUnmapped &&
		m_pMaxPEFile->m_stPEHeader.FileAlignment == 0x200)
	{
		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}	

		DWORD dwBufSize = 0x200;
		m_pbyBuff = new BYTE[dwBufSize];

		if(!m_pbyBuff)
		{
			return iRetStatus;
		}

		memset(m_pbyBuff, 0x00, dwBufSize);
		if(!GetBuffer(m_dwAEPMapped, dwBufSize, dwBufSize))
		{
			return iRetStatus;
		}

		CMaxBMAlgo *pBMScan = new CMaxBMAlgo;
		if(!pBMScan)
		{
			return iRetStatus;
		}
		
		BYTE bSig[] = {0x6C, 0x65, 0x72, 0x4D, 0x69, 0x6E, 0x69}; // Mutex Name "lerMini"
		if(!pBMScan->AddPatetrn2Search(bSig, sizeof(bSig)))
		{
			return iRetStatus;
		}
		if(pBMScan->Search4Pattern(m_pbyBuff,dwBufSize))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Diamin.gen"));
			return VIRUS_FILE_DELETE;
		}

		if(pBMScan)
		{
			delete pBMScan;
			pBMScan = NULL;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectShipUp
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of ShipUp Family
					  Trojan.ShipUp.gen (Covers Almost 50% ShipUP Family Varients)
--------------------------------------------------------------------------------------*/
int CTrojans::DetectShipUp()
{
	int		iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}

	if	(m_wNoOfSections >= 0x05 &&
		(memcmp(m_pSectionHeader[m_wAEPSec].Name, ".text", 0x05) == 0x00) && m_dwAEPUnmapped > 0x20000)
	{
		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}	

		DWORD	dwBufSize = 0x300;
		m_pbyBuff = new BYTE[dwBufSize];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0x00, dwBufSize);

		if(!GetBuffer(m_dwAEPMapped + 0x100, dwBufSize, dwBufSize))
		{
			return iRetStatus;
		}

		t_disasm	da = {0x00};
		DWORD		dwOffset = 0x00, dwCount = 0x00, dwBuffReadOff = 0x00, dwNextOff = 0x00;
		DWORD		dwMovCnt = 0x00, dwPusCnt = 0x00, dwAdCnt = 0x00, dwInstCnt = 0x00;

		for (int i = 0x00; i < dwBufSize; i+=dwNextOff)
		{
			dwNextOff = 0x01;
			if(0xE9 == m_pbyBuff[i] || 0xEB == m_pbyBuff[i])
			{
				dwOffset = i;
				dwNextOff = 0x00;
				dwInstCnt = 0x00;
				dwCount = 0x00;
				while(dwOffset < dwBufSize && dwInstCnt < 0x07)
				{
					DWORD dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					dwInstCnt++;
					if(dwLength > (dwBufSize - dwOffset))
					{
						return iRetStatus;
					}
					
					if((dwLength == 0x05 || dwLength == 0x02) && (strstr(da.result, "JMP")))
					{
						dwCount++;
						dwMovCnt = 0x00;
						dwPusCnt = 0x00;
						dwOffset+=dwLength;
						dwNextOff+=dwLength;
						continue;
					}
					if(dwCount == 0x01 && (strstr(da.result, "MOV")))
					{
						dwMovCnt++;
						dwOffset+=dwLength;
						dwNextOff+=dwLength;
						continue;
					}
					if(dwCount == 0x01 && (strstr(da.result, "PUSH")))
					{
						dwPusCnt++;
						dwOffset+=dwLength;
						dwNextOff+=dwLength;
						continue;
					}
					if((dwLength == 0x05) && (dwPusCnt == 0x02) && (dwMovCnt == 0x02) && (strstr(da.result, "CALL")))
					{
						dwBuffReadOff = *(DWORD *)&m_pbyBuff[dwOffset + 1] + m_dwAEPUnmapped + 0x105 + dwOffset;
						break;
					}
					dwOffset+=dwLength;
					dwNextOff+=dwLength;
				}
				if(dwBuffReadOff != 0x00)
				{
					break;
				}
				continue;
			}
		}
		
		if(dwBuffReadOff == 0x00)
		{
			return iRetStatus;
		}
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwBuffReadOff, &dwBuffReadOff))
		{
			return iRetStatus;
		}

		memset(m_pbyBuff, 0x00, dwBufSize);
		if(!GetBuffer(dwBuffReadOff, 0x100, 0x100))
		{
			return iRetStatus;
		}
		
		for (int i = 0x00; i < 0x100; i++)
		{
			if(0xC3 == m_pbyBuff[i])
			{
				dwOffset = i + 1;
				dwCount = 0x00;
				DWORD dwcalCnt = 0x00;
				dwMovCnt = 0x00, dwAdCnt = 0x00, dwInstCnt = 0x00; 
				while(dwOffset < 0x100 && dwInstCnt < 0x2A)
				{
					DWORD dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwLength > (0x100 - dwOffset))
					{
						return iRetStatus;
					}
					dwInstCnt++;
					if(dwLength == 3 && strstr(da.result, "CMP"))
					{
						dwCount++;
						dwOffset+=dwLength;
						continue;
					}
					if(dwInstCnt > 0x05 && strstr(da.result, "CALL"))
					{
						dwcalCnt++;
						if(dwcalCnt == 0x03)
						{
							return iRetStatus;
						}
						dwOffset+=dwLength;
						continue;
					}
					if(dwCount > 0x00 && strstr(da.result, "MOV"))
					{
						dwMovCnt++;
						dwOffset+=dwLength;
						continue;
					}
					if(dwCount > 0x00 && strstr(da.result, "ADD"))
					{
						dwAdCnt++;
						dwOffset+=dwLength;
						continue;
					}
					
					if(dwMovCnt >= 0x10 && dwAdCnt >= 0x04 && strstr(da.result, "XOR"))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.ShipUp.gen"));
						return VIRUS_FILE_DELETE;
						
					}	
					dwOffset+=dwLength;
				}
			}
		}
	}
	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectMorstar
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep + Virus Analysis Team
	Description		: Detection routine for different varients of Morstar Family
					  Variants Covered : Morstar.O, Morstar.M, Morstar.E	
--------------------------------------------------------------------------------------*/
int CTrojans::DetectMorstar()
{
	int		iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1A38 || m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1A30)
	{
		DWORD	dwBufSize = 0x100;

		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		m_pbyBuff = new BYTE[dwBufSize];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0x00, dwBufSize);

		DWORD	dwReadOff = m_pMaxPEFile->m_dwFileSize - 0x1010;	// + A00
		if(!GetBuffer(dwReadOff, dwBufSize, dwBufSize))
		{
			return iRetStatus;
		}
		
		BYTE bSig1[] = {0x46, 0x49, 0x52, 0x53, 0x45, 0x52, 0x49, 0x41}; // Comapany name "FIRSERIA"
		BYTE bSig2[] = {0x41, 0x70, 0x70, 0x73, 0x20, 0x49, 0x6E, 0x73, 0x74, 0x61, 0x6C, 0x6C, 0x65, 0x72}; // Apps Installer
		
		if(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1A38)
		{
			if(OffSetBasedSignature(bSig1, sizeof(bSig1), NULL))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:Downloader.Morstar.o"));
				return VIRUS_FILE_DELETE;
			}
		}
		else if(m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0x1A30)
		{
			if(OffSetBasedSignature(bSig2,sizeof(bSig2),NULL))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:Downloader.Morstar.m"));
				return VIRUS_FILE_DELETE;
			}
		}
		
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectYakes
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Yakes Family
					  .dwjw,.dwjr,.dwhd,.dwgv,.dwbg,.dwfn,.dwee,.dwec,.dwcc.,
					  .dwbc,dvwx,.dvqt,.dvpx,.dvkc,.dvjj,.dvje,.dvfb,.dveq,
					  .dvdg,.dvbl,.dvba,.dvad,.duyl
--------------------------------------------------------------------------------------*/
int CTrojans::DetectYakes(void)
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	DWORD	dwBuffSize = 0x2A0;
	DWORD	dwBytes2Read = 0x250;
	DWORD	dwDestAddress = 0x00;
	DWORD	dwDestFOffSet = 0x00;
	WORD	wInSec = 0x00;
	bool	bFound = false;
	int		iTry = 0x00;

	if (m_pMaxPEFile->m_stPEHeader.NumberOfSections != 0x05 && m_pMaxPEFile->m_stPEHeader.NumberOfSections != 0x07)
	{
		return iRetStatus;
	}

	if (m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x05)
	{
		if (m_pMaxPEFile->m_stSectionHeader[0x03].VirtualAddress != 0x650000 &&
			m_pMaxPEFile->m_stSectionHeader[0x03].VirtualAddress != 0x64F000 &&
			m_pMaxPEFile->m_stSectionHeader[0x03].VirtualAddress != 0x64E000 &&
			m_pMaxPEFile->m_stSectionHeader[0x03].VirtualAddress != 0x64D000)
		{
			return iRetStatus;
		}
	}
	if (m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x07)
	{
		if (m_pMaxPEFile->m_stSectionHeader[0x04].VirtualAddress != 0x64E000)
		{
			return iRetStatus;
		}
	}

	if (m_pbyBuff)
	{
		delete []m_pbyBuff; 
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[dwBuffSize];

	BYTE	bAEPBuff[] = {0x55, 0x8B, 0xEC};
	if(!GetBuffer(m_dwAEPMapped, dwBuffSize, dwBuffSize))
	{
		return iRetStatus;
	}
	if (memcmp(&m_pbyBuff[0x00],bAEPBuff,sizeof(bAEPBuff)) != 0x00)
	{
		return iRetStatus;
	}

	int		i = 0x05;
	BYTE	byMemBuff[0x40] = {0x00};
	DWORD	dwBytesRead = 0x00;
	for (iTry  = 0x00; iTry < 0x03; iTry++)
	{
		for(; i < (dwBuffSize - 0x06) ; i++)
		{
			if ( m_pbyBuff[i] == 0x3B && 
				(m_pbyBuff[i + 1] == 0x1D || m_pbyBuff[i + 1] == 0x05 || m_pbyBuff[i + 1] == 0x35 ||
				 m_pbyBuff[i + 1] == 0x15 || m_pbyBuff[i + 1] == 0x3D || m_pbyBuff[i + 1] == 0x0D))
			{
				dwDestAddress = *(DWORD *)&m_pbyBuff[i + 2];
				if (dwDestAddress > m_pMaxPEFile->m_stPEHeader.ImageBase)
				{
					dwDestAddress = dwDestAddress  - m_pMaxPEFile->m_stPEHeader.ImageBase;
					dwDestFOffSet = Rva2FileOffsetEx(dwDestAddress,&wInSec);
					if ((wInSec == 0x02 || wInSec == 0x01) && dwDestFOffSet < m_pMaxPEFile->m_dwFileSize)
					{
						i+=2;
						bFound = true;
						break;
					}
				}
			}
		}

		if (bFound == true)
		{
			memset(byMemBuff,0x00,sizeof(byMemBuff));
			dwBytes2Read = 0x35;
			dwBytesRead = 0x00;
			if(!m_pMaxPEFile->ReadBuffer(byMemBuff,dwDestFOffSet,dwBytes2Read,dwBytes2Read, &dwBytesRead))
			{
				return iRetStatus;
			}
			if (dwBytes2Read != dwBytesRead)
			{
				return iRetStatus;
			}

			for(int j = 0x00; j < dwBytes2Read; j++)
			{
				if ((byMemBuff[j] >= 'A' && byMemBuff[j] <= 'Z') ||
					(byMemBuff[j] >= 'a' && byMemBuff[j] <= 'z') ||
					(byMemBuff[j] >= '0' && byMemBuff[j] <= '9'))
				{
				}
				else
				{
					bFound = false;
					break;
				}
			}

			if (bFound == true)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Yakes.DGen"));
				return VIRUS_FILE_DELETE; 
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectFiseria
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Fiseria Family
					  not-a-virus:AdWare.Fiseria(hv,c,w,hx,d,hy,ia,ib,fk,u,d)
--------------------------------------------------------------------------------------*/
int CTrojans::DetectFiseria()
{
	int		iRetStatus = VIRUS_NOT_FOUND;

	if(IMAGE_FILE_DLL == (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL))
		return iRetStatus;

	if((m_wNoOfSections == 0x5 || m_wNoOfSections == 0x4) && m_wAEPSec == 0)
	{
		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}	

		DWORD	dwBuffSize = 0xD00, dwOffset = 0;
		m_pbyBuff = new BYTE[dwBuffSize];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0x00, dwBuffSize);

		if(!GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData, dwBuffSize, dwBuffSize))
		{
			return iRetStatus;
		}
		BYTE bChkBuff[] = {0x6A, 0x0, 0x6A, 0x9, 0x68};
		t_disasm da;
		for(int i = 0; i < dwBuffSize - sizeof(bChkBuff); i++)
		{
			if(memcmp(&m_pbyBuff[i], bChkBuff,  sizeof(bChkBuff)) == 0)
			{
				i += sizeof(bChkBuff);
				DWORD dwCallOffset = 0, dwAddOffset = *(DWORD *)&m_pbyBuff[i];
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwAddOffset - m_dwImageBase,&dwAddOffset))
				{
					i += 0x4;
					if( m_pbyBuff[i] == 0xE8)
					{
						dwCallOffset = *(DWORD *)&m_pbyBuff[i+1] + i + m_pSectionHeader[m_wAEPSec].VirtualAddress + 5;
						if(m_pMaxPEFile->Rva2FileOffset(dwCallOffset,&dwCallOffset) != m_wAEPSec)
						{
							return iRetStatus;
						}
						DWORD dwESI = 0,dwLength = 0;
						dwOffset = dwCallOffset -  m_pSectionHeader[m_wAEPSec].PointerToRawData;

						while(dwOffset < (dwBuffSize - dwLength))
						{
							memset(&da, 0x00, sizeof(struct t_disasm));
							dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
							if(dwOffset > (dwBuffSize - dwLength))
							{
								break;
							}
							if(dwLength == 0x5 && m_pbyBuff[dwOffset] == 0xB9 && *(WORD *)&m_pbyBuff[dwOffset+dwLength+2] == 0xF12B)
							{
								dwESI = *(DWORD *)&m_pbyBuff[dwOffset + 1];
								break;
							}
							dwOffset += dwLength;
						}
						if(dwAddOffset && dwESI)
						{
							BYTE bDecrypKeyBuff[0x12], bDecrypBuff[0x12];
							BYTE bSignBuff[0x12] = {0x6D, 0x00, 0x6C, 0x00, 0x77, 0x00, 0x72, 0x00, 0x5F, 0x00, 0x73, 0x00, 0x6D, 0x00, 0x70, 0x00, 0x6C, 0x00};
							if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwESI - m_dwImageBase,&dwESI))
							{
								if(!m_pMaxPEFile->ReadBuffer(bDecrypKeyBuff,dwESI,0x12,0x12))
									return iRetStatus;
								if(!m_pMaxPEFile->ReadBuffer(bDecrypBuff,dwAddOffset,0x12,0x12))
									return iRetStatus;

								for(i = 0; i<0x12; i=i+2)
								{
									bDecrypBuff[i] ^= bDecrypKeyBuff[i];
								}
								if(memcmp(bDecrypBuff,bSignBuff,sizeof(bSignBuff)) == 0)
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Adware.Fiseria.gen"));
									return VIRUS_FILE_DELETE;
								}
							}
						}
					}
				}
				return iRetStatus;
			}
		}
	}
   return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectNGRBot
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Ngrbot Family
--------------------------------------------------------------------------------------*/
int CTrojans::DetectNGRBot()
{
	int		iRetStatus = VIRUS_NOT_FOUND;

	if(IMAGE_FILE_DLL == (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL))
		return iRetStatus;

	if((((m_wNoOfSections >= 0x4 || m_wNoOfSections <= 6) && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x200) ||  (m_wNoOfSections == 0x7 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x1000))&& 
		(m_wAEPSec == 0x0 || m_wAEPSec == 0x1))
	{
		DWORD	dwOffset = 0,	dwLength = 0, dwConst = 0;
		int iHit = 0;
		t_disasm dasm;

		while(dwOffset < 0x100)
		{
			memset(&dasm, 0x00, sizeof(struct t_disasm));
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pMaxPEFile->m_byAEPBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &dasm, DISASM_CODE);
			if(dwOffset > (0x100 - dwLength))
			{
				break;
			}
			if( 0x5 == dwLength && strstr(dasm.result, "MOV E") && 0 == iHit)
			{
				if(m_wAEPSec != m_pMaxPEFile->Rva2FileOffset(dasm.immconst, 0)) 
					iHit++;
			}
			else if((strstr(dasm.result, "OR E") || strstr(dasm.result, "MOV E")) && 1 == iHit && ((0x6 == dwLength && *(DWORD *)&m_pMaxPEFile->m_byAEPBuff[dwOffset + 2] == 0xFFF0B530) || (0x5 == dwLength && *(DWORD *)&m_pMaxPEFile->m_byAEPBuff[dwOffset + 1] == 0xFFF0B530)))
			{
				iHit++;
			}
			else if(((0x6 == dwLength && *(DWORD *)&m_pMaxPEFile->m_byAEPBuff[dwOffset + 2] == 0xFFFFF319) || (0x5 == dwLength && *(DWORD *)&m_pMaxPEFile->m_byAEPBuff[dwOffset + 1] == 0xFFFFF319)) && strstr(dasm.result, "SUB E") && 2 == iHit)
			{
				iHit++;
			}
			else if(0x5 == dwLength && strstr(dasm.result, "CALL") && 3 == iHit)
			{
				dwConst = *(DWORD *)&m_pMaxPEFile->m_byAEPBuff[dwOffset + 1] + dwOffset + dwLength + m_dwAEPUnmapped;
				if(m_wAEPSec == m_pMaxPEFile->Rva2FileOffset(dwConst, &dwConst))
				{
					if(0x3 == (dwConst - m_pSectionHeader[m_wAEPSec].PointerToRawData))
						iHit++;
				}
				break;
			}
			dwOffset += dwLength;
		}
		if(0x4 == iHit)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Worm.Ngrbot.kpb"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectOteZinuDl
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Santosh Awale + Virus Analysis Team
	Description		: Detection routine for different varients of Otezinu.dl Family
					  loop decrypting the code,this code is then used to write in the files created.
					  *>By using the sign loop this file decrypts some code.
					*>it creates one directory in the "C:\DOCUME~1\admin\LOCALS~1\Temp" folder.
					*>under that it creates one exe file and write its code from the code decrypted.
					*>it creates one .dat file of the same name.
					*>it creates one directory in the current directory,and then creates one .manifest,.rdf,and .js file.
					*>it then creates one directory in that directory and creates two .js file in that directory.
					*>it then creates another directory in the parent directory and creates one .htm, three .js,and one .json file.
					*>and then executes the .exe file. creates in main directory.
					*>this file copies thw whole folder in the "C:\Documents and Settings\admin\Local Settings\Application Data\Google\Chrome SxS\User Data\Default\Extensions" folder.
					*>and then deletes the folder from "C:\DOCUME~1\admin\LOCALS~1\Temp" folder.		
--------------------------------------------------------------------------------------*/
int CTrojans::DetectOteZinuDl()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x5 && m_dwAEPMapped == 0x22FF && m_wAEPSec == 0 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x14A00)
	{
		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}

		DWORD dwBuffSize=0x10;
		m_pbyBuff = new BYTE[dwBuffSize];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		BYTE OTEZINUDL_Sig[] = {0x31,0x01,0x05,0x10,0xB6,0x00,0x5B,0x35,0xC9,0xF3,0xE7,0x1D,0x8D,0x49,0x04,0x4A};
		if(GetBuffer(m_pSectionHeader[0].PointerToRawData+0xB8D4, 0x10, 0x10))
		{
			if(memcmp(&m_pbyBuff[0x00], OTEZINUDL_Sig, sizeof(OTEZINUDL_Sig)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not a virus:Adware.Otezinu.dl"));
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectFlyStudio
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Flystudio Family
					  1 : HackTool Installer
					  2 : Installes or changes registry and windows settings to monitor activities
						e.g. host file, internet chache, etc	
					  Signature Criteria : Taken script code which would be droped by Trojan	
--------------------------------------------------------------------------------------*/
int	CTrojans::DetectFlyStudio()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}

	if (m_pMaxPEFile->m_dwFileSize <= 0x217C00)
	{
		return iRetStatus;
	}

	if(m_wNoOfSections == 0x4 && m_dwAEPMapped == 0xCA80 &&  m_pSectionHeader[0x02].SizeOfRawData == 0x25B000)
	{
		DWORD	dwBuffSize=0x30;

		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[dwBuffSize];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		BYTE	bFlyStudioSig[] = {0x65, 0x76, 0x61, 0x6C, 0x28, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x28, 0x70, 0x2C, 0x61, 0x2C, 0x63, 0x2C, 0x6B, 0x2C, 0x65, 0x2C, 0x64, 0x29, 0x7B, 0x65, 0x3D, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x28, 0x63, 0x29};

		if(GetBuffer(0x217B70, dwBuffSize, dwBuffSize))
		{
			if(memcmp(&m_pbyBuff[0x00], bFlyStudioSig, sizeof(bFlyStudioSig)) == 0x00)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("not-a-virus:HackTool.FlyStudio.Gen"));
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAutoitAZA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Autoit.AZA Family
					  Trojan.Autoit.aza, Trojan.Autoit.cka	
	    				1 : UPX Packed files with Folder Icon
						2 : On execution Creates files with Folder name and hides the folder
						3 : Contains Antidebugging Part, Uses GetPerformanceCounter()
						4 : Kills / Terminates proccesse such as ProcessExplorer, Procmon and TaskMgr
						5 : Dropes file SVCHost.exe in %WINDIR% 
						Signature Criteria : Taken Antidebugging code snipet as signature.
--------------------------------------------------------------------------------------*/
int CTrojans::DetectAutoitAZA()
{
	int		iRetStatus = VIRUS_NOT_FOUND;

	if(IMAGE_FILE_DLL == (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL))
	{
		return iRetStatus;
	}
	if (m_wNoOfSections != 0x04)
	{
		return iRetStatus;
	}

	TCHAR	szLogLine[1024] = {0x00};
	DWORD	dwBuffSize = 0x10;
	if (m_pbyBuff)
	{
		delete []m_pbyBuff; 
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[dwBuffSize];

	BYTE	bAEPBuff[] = {0xE8, 0x16, 0x90, 0x00, 0x00, 0xE9, 0x89, 0xFE, 0xFF, 0xFF, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
	if(!GetBuffer(m_dwAEPMapped, dwBuffSize, dwBuffSize))
	{
		return iRetStatus;
	}

	if (memcmp(&m_pbyBuff[0x00],&bAEPBuff[0x00],sizeof(bAEPBuff)) != 0x00)
	{
		return iRetStatus;
	}

	DWORD	dwJMPOffset = m_dwAEPMapped + 0x9016 + 0x05;

	if (dwJMPOffset >= m_pMaxPEFile->m_dwFileSize)
	{
		return iRetStatus;
	}

	BYTE	bAntiDebug[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x2C, 0xA1, 0x40, 0x0D, 0x49, 0x00};
	if(!GetBuffer(dwJMPOffset, dwBuffSize, dwBuffSize))
	{
		return iRetStatus;
	}

	if (memcmp(&m_pbyBuff[0x00],&bAntiDebug[0x00],sizeof(bAntiDebug)) != 0x00)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Autoit.AZA"));
		return VIRUS_FILE_DELETE;
	}


	return iRetStatus;
}

//added 05-12-2020
/*-------------------------------------------------------------------------------------
	Function		: DetectBankerRTM
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: Detection module for Banker.Win32.RTM family [RTM, RTM.gen, RTM.vho]
	Author			: Tushar Kadam + Ratnakar V Bhosale
	Description		: Detection routine for different varients of RTM Banker Family
--------------------------------------------------------------------------------------*/

int CTrojans::DetectBankerRTM(void)
{
	int		iRetStatus = VIRUS_NOT_FOUND;

	//primary checks
      if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	  {
			if (m_wNoOfSections == 0x05)
			{
				if (CheckBankerRTM() == true)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Banker.Win32.RTM"));
					iRetStatus = VIRUS_FILE_DELETE; 
				}
			}
	  }
  return iRetStatus;
}

bool CTrojans::CheckBankerRTM(void)
{
      bool  bRet = false;
       
      if(m_pbyBuff)
      {
            delete []m_pbyBuff;
            m_pbyBuff = NULL;
      }
      m_pbyBuff = new BYTE[RTM_ACCESS_BUFF_SIZE + MAX_INSTRUCTION_LEN];

      if(NULL == m_pbyBuff)
      {
            return bRet;
      }
      memset(m_pbyBuff, 0, RTM_ACCESS_BUFF_SIZE + MAX_INSTRUCTION_LEN);
      
      if(!GetBuffer(m_dwAEPMapped - 0x1038, RTM_ACCESS_BUFF_SIZE, RTM_ACCESS_BUFF_SIZE))
      {
            return bRet; 
      }
      

      DWORD       dwLength = 0, dwOffSet = 0x00;
      t_disasm    da;
      m_dwInstCount = 0;
      BYTE B1= 0x00,B2= 0x00,B3= 0x00;

      while((dwOffSet < RTM_ACCESS_BUFF_SIZE) && (m_dwInstCount < 21))
	  {
            memset(&da, 0x00, sizeof(da));  
            B1 = *((BYTE*)&m_pbyBuff[dwOffSet]);
		    B2 = *((BYTE*)&m_pbyBuff[dwOffSet + 1]);
		    B3 = *((BYTE*)&m_pbyBuff[dwOffSet + 2]);

		    //Skipping Some Instructions that couldn't be interpreted by Olly.
		    if(B1 == 0xC1 && (B2 >= 0xF0 && B2 <= 0xF7))
		    {
			     dwOffSet += 0x03;
			     continue;
		    }
		    if(B1 == 0xD1 && (B2 >= 0xF0 && B2 <= 0xF7))
		    {
			     dwOffSet += 0x02;
			     continue;
		    }
            dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN,0x400000, &da, DISASM_CODE);
            if(dwLength == 0x01 && B1 == 0xE2 && strstr(da.result, "???"))
		    {
			     dwOffSet += 0x02;
			     continue;
		    }
			if(dwLength == 0x05 && strstr(da.result, "MOV EAX") && m_dwInstCount == 0)
			{
				  m_dwInstCount = 1;
				  dwOffSet += dwLength;
				  continue;
			}
            if(dwLength == 0x05 && strstr(da.result, "MOV") && (m_dwInstCount == 1 || m_dwInstCount == 7))
            {
                  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
            }
            if(dwLength==0x06 && strstr(da.result, "MOV ECX") && (m_dwInstCount == 2 || m_dwInstCount == 17 || m_dwInstCount == 18))
            {
                  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
            }
            if(dwLength==0x02 && strstr(da.result, "MOV EDX,[ECX]") && m_dwInstCount == 3)
			{
                  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
            }
            if(dwLength==0x06 && strstr(da.result, "MOV") && m_dwInstCount == 4)
            {
                  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
            }
			if(dwLength == 0x05 && strstr(da.result, "MOV EAX") && (m_dwInstCount == 5 || m_dwInstCount == 10))
			{
				  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
			}
            if(dwLength==0x05 && strstr(da.result, "SUB EAX") && m_dwInstCount == 6)
            {
                  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
            }
            if(dwLength == 0x02 && strstr(da.result, "MOV EDI,EDI"))
            {
                  //increment offset to skip garbage instructions
				  dwOffSet += dwLength;
				  continue;
            }
            if(dwLength==0x06 && strstr(da.result, "MOV EDX") && (m_dwInstCount == 8 || m_dwInstCount == 17 ||m_dwInstCount == 18))
            {
                  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
            }
            if(dwLength==0x06 && strstr(da.result, "ADD EDX") && m_dwInstCount == 9)
            {
                  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
            }
			if(dwLength == 0x02 && strstr(da.result, "MOV ECX,EDX") && m_dwInstCount == 11)
			{
				  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
			}
			if(dwLength == 0x05 && strstr(da.result, "MOV") && m_dwInstCount == 12)
			{
				  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
			}
			if(dwLength == 0x05 && strstr(da.result, "MOV") && m_dwInstCount == 13)
			{
				  //increment offset to skip garbage instructions through loop
				  dwOffSet += dwLength;
				  continue;
			}
			if(dwLength == 0x06 && strstr(da.result, "XOR") && m_dwInstCount == 13)
			{
				  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
			}
			if(dwLength == 0x05 && strstr(da.result, "MOV EAX,A228") && m_dwInstCount == 14)
			{
				  //increment offset to skip garbage instructions through loop
				  dwOffSet += dwLength;
				  continue;
			}
			if(dwLength == 0x05 && strstr(da.result, "MOV EAX") && m_dwInstCount == 14)
			{
				  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
			}
			if(dwLength == 0xa && strstr(da.result, "MOV") && m_dwInstCount == 15)
			{
				  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
			}
			if(dwLength==0x06 && strstr(da.result, "ADD") && m_dwInstCount == 16)
			{
				  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
			}
			if(dwLength==0x02 && strstr(da.result, "MOV [ECX],EDX") && m_dwInstCount == 19)
			{
                  m_dwInstCount++;
				  dwOffSet += dwLength;
				  continue;
            }
	        if(dwLength == 0x02 && strstr(da.result, "XOR EAX,EAX") && m_dwInstCount == 20)
			{
				  m_dwInstCount++;
				  dwOffSet += dwLength;
                  bRet = true;
				  break;
			}
			dwOffSet += dwLength;
	  }
      return bRet;
}
