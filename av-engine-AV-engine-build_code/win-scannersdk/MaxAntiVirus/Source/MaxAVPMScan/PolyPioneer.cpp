/*======================================================================================
FILE				: PolyPioneer.cpp
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
NOTES				: This is detection module for malware Pioneer Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyPioneer.h"
#include "SemiPolyDBScn.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyPioneer
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyPioneer::CPolyPioneer(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyPioneer
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyPioneer::~CPolyPioneer(void)
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
	Description		: Detection routine for different varients of Pioneer Family
--------------------------------------------------------------------------------------*/
int CPolyPioneer::DetectVirus(void)
{
	int iRetStatus = DetectPioneerL();
	if(iRetStatus)
	{
		m_eInfection = PIONEER_L;
		return iRetStatus;
	}
	iRetStatus = DetectPioneerBF();
	if(iRetStatus)
	{
		m_eInfection = PIONEER_BF;
		return iRetStatus;
	}
	iRetStatus = DetectPioneerCZ();
	if(iRetStatus)
	{
		m_eInfection = PIONEER_CZ;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPioneerL
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for Pioneer.L
					  Checking if the Section Names=GVD + No. of sections=3 + All Section Characteristics=Write + AEP=2nd section + SRD of first section=0
					  These are entry level checks to detect the presence of an infected file
--------------------------------------------------------------------------------------*/
int CPolyPioneer::DetectPioneerL(void)
{
	//Checking if the Section Names=GVD + No. of sections=3 + All Section Characteristics=Write + AEP=2nd section + SRD of first section=0
	//These are entry level checks to detect the presence of an infected file
	if((memcmp(m_pSectionHeader[0].Name, "GVD", 3) == 0 && 
		(memcmp(m_pSectionHeader[1].Name, "GVD", 3))== 0 && 
		(memcmp(m_pSectionHeader[2].Name, "GVD", 3) == 0))&&
		(m_wNoOfSections == 3) && (m_pSectionHeader[0].SizeOfRawData == 0x00) && (m_wAEPSec == 1) && 
		(((m_pSectionHeader[0].Characteristics & 0x80000000) == 0x80000000) &&
		((m_pSectionHeader[1].Characteristics & 0x80000000) == 0x80000000) && 
		((m_pSectionHeader[2].Characteristics & 0x80000000) == 0x80000000)))
	{		
		const int PIONEER_L_BUFF_SIZE = 0x200;
		m_pbyBuff = new BYTE[PIONEER_L_BUFF_SIZE];
		if(GetBuffer(0x400, PIONEER_L_BUFF_SIZE, PIONEER_L_BUFF_SIZE))
		{
			//Pioneer Signature--> @format c:\KILLER.BAT DisableLocal (Actually the above entry level checks are strong enough)
			TCHAR Pioneer_l_Sig[] = {_T("F67FFBFFC38D4000558BEC33C0556829100A64FF30648920FF0500400BDBBBB7B713*10683018C3E9D2FF00EBD6FEFDFEF85DC38BC0832D1E01C33B")};

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(Pioneer_l_Sig, _T("Virus.W32.Pioneer.L"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], PIONEER_L_BUFF_SIZE, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					if(m_pMaxPEFile->m_dwFileSize == 0x1200 || m_pMaxPEFile->m_dwFileSize == 0x1400)
					{
						return VIRUS_FILE_DELETE;
					}
					else
					{
						return VIRUS_FILE_REPAIR;
					}
				}
			}			
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPioneerBF
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for Pioneer.BF
--------------------------------------------------------------------------------------*/
int CPolyPioneer::DetectPioneerBF(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == 0 && ((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000000) == 0xE0000000))
	{		
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int BUFF_SIZE = 0x200;
		m_pbyBuff = new BYTE[BUFF_SIZE];
		if(!GetBuffer(m_dwAEPMapped, BUFF_SIZE, BUFF_SIZE))
		{
			return iRetStatus;
		}
		for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes; dwOffset++)
		{
			if(m_pbyBuff[dwOffset] == 0xE8)
			{
				m_dwPatchedOffset = m_dwAEPMapped + dwOffset + 1;
				m_dwCallAddress = *((DWORD *)&m_pbyBuff[dwOffset + 1]) + m_dwAEPUnmapped + dwOffset + 5;
				if(m_wAEPSec == m_pMaxPEFile->Rva2FileOffset(m_dwCallAddress, &m_dwCallAddress))
				{
					if(!GetBuffer(m_dwCallAddress, 0x20, 0x20))
					{
						return iRetStatus;
					}
					const BYTE bySig[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x2D};
					
					if(memcmp(m_pbyBuff, bySig, sizeof(bySig)) == 0 && 
						m_pbyBuff[0xB] == 0x60 && m_pbyBuff[0xC] == 0x8B && m_pbyBuff[0xD] == 0x98 && 
						m_pbyBuff[0x12] == 0xFF && m_pbyBuff[0x13] == 0xE3)
					{
						if(m_wNoOfSections - 1 == m_pMaxPEFile->Rva2FileOffset(*((DWORD *)&m_pbyBuff[0x14]) - m_dwImageBase, &m_dwLastSecVirusStart))
						{
							m_dwPatchedBytes = *((DWORD *)&m_pbyBuff[0x18]) - m_dwImageBase;
							m_dwPatchedBytes -= (m_dwAEPUnmapped + dwOffset + 5);
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Pioneer.BF"));	
							return VIRUS_FILE_REPAIR;
						}
					}
					return iRetStatus;
				}				
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPioneerCZ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for Pioneer.CZ
--------------------------------------------------------------------------------------*/
int CPolyPioneer::DetectPioneerCZ(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec != 0x0 && m_wAEPSec != 0x1 && m_wAEPSec != 0x2 && m_wAEPSec != 0x3 && m_wAEPSec != 0x4 && m_wAEPSec != 0x7 && m_wAEPSec != 0x8 && m_wAEPSec != 0x9)		// Primary Checks
	{
		return iRetStatus;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	BYTE	PCZ_BUF[0x50] = {0};
	DWORD	dwOffset1 = 0x00, dwCheckOffset = 0x00;

	m_pbyBuff = new BYTE[0x1D];

	if(GetBuffer(m_pMaxPEFile->m_dwFileSize - 0x1D, 0x1D, 0x1D))
	{

		m_dwLastSecVirusStart = *(DWORD *)&m_pbyBuff[0x19] - 0x3A;

		//if(m_dwLastSecVirusStart >= (m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData))
		{

			m_dwPatchedOffset = *(DWORD *)&m_pbyBuff[0x11] - 0x3A;
			dwCheckOffset=*(DWORD *)&m_pbyBuff[0x0D] - 0x3A;

			BYTE byOriAepBytes[0x5] = {0};							// temporary Buffer for copying encrypted 5 bytes at AEP 
			memcpy(byOriAepBytes, m_pbyBuff, 5);
			DWORD dwRvaCheck=*(DWORD *)&m_pMaxPEFile->m_byAEPBuff[0x1]+ 5 + m_dwAEPUnmapped;

			if(OUT_OF_FILE!=m_pMaxPEFile->Rva2FileOffset(dwRvaCheck, &dwOffset1))
			{
				if(m_pMaxPEFile->ReadBuffer(&PCZ_BUF[0x00],dwOffset1, 0x5, 0x5))
				{
					DWORD dwSignStart=*(DWORD *)&PCZ_BUF[0x1]+5+dwRvaCheck+0x46;

					if(OUT_OF_FILE!=m_pMaxPEFile->Rva2FileOffset(dwSignStart, &dwSignStart))
					{
						if(GetBuffer(dwSignStart, 0x1D, 0x1D))
						{
							DWORD dwLength = 0;
							t_disasm da = {0};
							int iInstructionNo = 0;

							for(DWORD dwOffset = 0; dwOffset < 0x1D; dwOffset += dwLength)
							{
								dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE); 

								if(dwLength == 0x3 && iInstructionNo == 0x0 && strstr(da.result, "MOV BL,[EDX+2]"))
								{
									iInstructionNo++;
									continue;
								}
								else if(dwLength == 0x2 && iInstructionNo == 0x1 && strstr(da.result,"TEST BL,BL"))
								{
									iInstructionNo++;
									continue;
								}
								else if(dwLength == 0x2 && iInstructionNo == 0x2 && strstr(da.result, "XOR [ECX],BL"))
								{
									iInstructionNo++;
									continue;
								}
								else if(dwLength == 0x2 && iInstructionNo == 0x3 && strstr(da.result,"NOT BL"))
								{
									if(dwCheckOffset!= m_dwAEPMapped)
									{
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Pioneer.CZ"));
										return VIRUS_FILE_DELETE;
									}

									if(dwCheckOffset == m_dwAEPMapped)
									{
										if(!GetBuffer(m_dwLastSecVirusStart,0x4,0x4))  
										{
											return iRetStatus;
										}
										DWORD dwOriginalByteOffset = *(DWORD *)&m_pbyBuff[0] + m_dwLastSecVirusStart + 0x4;   // calculating start of encrypted 2nd patch for AEP section

										if(dwOriginalByteOffset > m_pMaxPEFile->m_dwFileSize)
										{
											_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Pioneer.CZ"));
											return VIRUS_FILE_DELETE;
										}

										if(!m_pMaxPEFile->ReadBuffer(&m_dwPioneerCZBuffSize, dwOriginalByteOffset, 0x4, 0x4))
										{
											return iRetStatus;
										}
										if(m_dwPioneerCZBuffSize > m_pMaxPEFile->m_dwFileSize)
										{
											_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Pioneer.CZ"));
											return VIRUS_FILE_DELETE;
										}

										if(m_pbyBuff)
										{
											delete []m_pbyBuff;
											m_pbyBuff = NULL;
										}


										m_pbyBuff = new BYTE[m_dwPioneerCZBuffSize + 0x5];
										if(!GetBuffer(dwOriginalByteOffset + 0x4, m_dwPioneerCZBuffSize, m_dwPioneerCZBuffSize))
										{
											return iRetStatus;
										}

										memcpy(&m_pbyBuff[m_dwPioneerCZBuffSize], byOriAepBytes, 5);

										for(DWORD dwCount = 0; dwCount< m_dwPioneerCZBuffSize + 0x5; dwCount++ )  // decryption loop
										{
											if(dwCount< m_dwPioneerCZBuffSize)
											{
												m_pbyBuff[dwCount] ^= 0x3A;
											}

											else 
											{
												m_pbyBuff[dwCount] ^= 0x29;
											}

											m_pbyBuff[dwCount] = ~m_pbyBuff[dwCount];

										}

										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Pioneer.CZ"));
										return VIRUS_FILE_REPAIR;


									}

								}
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
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Pioneer Family
--------------------------------------------------------------------------------------*/
int CPolyPioneer::CleanVirus(void)
{
	if(m_eInfection == PIONEER_L)
	{
		//Data to be copied from offset File Size-1200h and written at offset 0.Size to be written is 1200h bytes + Byte key=7B +Case No.=1
		if(m_pMaxPEFile->CopyData(m_pMaxPEFile->m_dwFileSize - 0x1200, 0x00, 0x1200, 0x1, 0x7B))
		{
			//Truncate file applied after copy data.Set File End=Original File Size
			if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize - 0x1200))
			{
				return REPAIR_SUCCESS;
			}	
		}
	}
	else if(m_eInfection == PIONEER_BF)
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwCallAddress, 0x1C))
		{
			if(m_pMaxPEFile->WriteBuffer(&m_dwPatchedBytes, m_dwPatchedOffset, 4, 4))
			{
				if(m_pMaxPEFile->TruncateFileWithFileAlignment(m_dwLastSecVirusStart))
				{
					m_pMaxPEFile->RepairOptionalHeader(0x16, 0, 0);
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	else if(m_eInfection == PIONEER_CZ)
	{
		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwPioneerCZBuffSize], m_dwAEPMapped, 0x5, 0x5))
		{
			if(!m_pMaxPEFile->WriteBuffer(m_pbyBuff,m_dwPatchedOffset,m_dwPioneerCZBuffSize,m_dwPioneerCZBuffSize))
			{
				return REPAIR_FAILED;
			}
			BYTE byRelocSec[] = {0x2E, 0x72, 0x65, 0x6C, 0x6F, 0x63}; // .reloc
			for (int iCnt = 0; iCnt < m_pMaxPEFile->m_stPEHeader.NumberOfSections; iCnt++)
			{
				if(memcmp(m_pSectionHeader[iCnt].Name, byRelocSec, sizeof(byRelocSec)) == 0)
				{
					if(!m_pMaxPEFile->RepairOptionalHeader(0x24,m_pSectionHeader[iCnt].VirtualAddress,m_pSectionHeader[iCnt].Misc.VirtualSize,TRUE))
						return REPAIR_FAILED;

					break;
				}
			}
			if(m_pMaxPEFile->TruncateFileWithFileAlignment(m_dwLastSecVirusStart))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	/*else if(m_eInfection == PIONEER_CZ)
	{
		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwPioneerCZBuffSize], m_dwAEPMapped, 0x5, 0x5))
		{
			if(m_pMaxPEFile->WriteBuffer(m_pbyBuff,m_dwPatchedOffset,m_dwPioneerCZBuffSize,m_dwPioneerCZBuffSize))
			{
				if(m_pMaxPEFile->TruncateFileWithFileAlignment(m_dwLastSecVirusStart))
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}*/
	return REPAIR_FAILED;
}

