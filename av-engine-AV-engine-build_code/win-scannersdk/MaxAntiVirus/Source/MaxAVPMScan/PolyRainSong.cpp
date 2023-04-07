/*======================================================================================
FILE				: PolyRainSong.cpp
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
NOTES				: This is detection module for malware RainSong Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyRainSong.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyRainSong
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyRainSong::CPolyRainSong(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyRainSong
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyRainSong::~CPolyRainSong(void)
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
	Description		: Detection routine for different varients of RainSong Family
--------------------------------------------------------------------------------------*/
int CPolyRainSong::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000000) == 0xE0000000 || (m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0x20000060) == 0x20000060
		&& (m_wAEPSec != m_wNoOfSections - 1))	
	{	
		if(!GetPatchedCalls(m_dwAEPMapped,m_dwAEPMapped + 0x2000, m_wNoOfSections - 1,true))
		{
			return iRetStatus;
		}
		if(m_arrPatchedCallOffsets.GetCount())
		{
			LPVOID lpPos = m_arrPatchedCallOffsets.GetFirst();
			m_arrPatchedCallOffsets.GetData(lpPos, m_dwCallPatchAdd);
			m_arrPatchedCallOffsets.GetKey(lpPos, m_dwVirusStartOffset);
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwVirusStartOffset, &m_dwVirusStartOffset))
			{
				return iRetStatus;
			}
			DWORD RAINSONG_BUFF_SIZE = (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData) - m_dwVirusStartOffset;
			if(RAINSONG_BUFF_SIZE > 0x3000 || RAINSONG_BUFF_SIZE < 0xF00)
			{
				return VIRUS_NOT_FOUND;
			}
			m_pbyBuff = new BYTE[RAINSONG_BUFF_SIZE];
			bool bcheck = false;
			if(GetBuffer(m_dwVirusStartOffset, RAINSONG_BUFF_SIZE, RAINSONG_BUFF_SIZE))
			{
				const BYTE RainSong3891[] = {0xE8,0x2E,0x0F,0x00,0x00};
				const BYTE RainSong3925[] = {0xE8,0x50,0x0F,0x00,0x00};
				const BYTE RainSong4266[] = {0xE8,0xA5,0x10,0x00,0x00};
				const BYTE RainSong3910[] = {0xE8,0x41,0x0F,0x00,0x00};
				const BYTE RainSong3956[] = {0xE8,0x6F,0x0F,0x00,0x00};
				const BYTE RainSong3874[] = {0xE8,0x1D,0x0F,0x00,0x00};
				const BYTE RainSong4198[] = {0xE8,0x61,0x10,0x00,0x00};

				if((memcmp(&m_pbyBuff[0x00], RainSong3891, sizeof(RainSong3891)) == 0) || 
					(memcmp(&m_pbyBuff[0x00], RainSong3925, sizeof(RainSong3925)) == 0) || 
					(memcmp(&m_pbyBuff[0x00], RainSong3910, sizeof(RainSong3910)) == 0) || 
					(memcmp(&m_pbyBuff[0x00], RainSong3956, sizeof(RainSong3956)) == 0) || 
					(memcmp(&m_pbyBuff[0x00], RainSong3874, sizeof(RainSong3874)) == 0) || 
					(memcmp(&m_pbyBuff[0x00], RainSong4198, sizeof(RainSong4198)) == 0) || 
					(memcmp(&m_pbyBuff[0x00], RainSong4266, sizeof(RainSong4266)) == 0))
				{
					DWORD   dwLength = 0, dwOffset = 0, dwMatchedInstr = 0, dwDecKey = 0 ,dwAddKey = 0,dwSubKey =0,dwDecLen = 0,dwDecDataOffset =0;
					dwOffset = *(DWORD *)&m_pbyBuff[0x1] + 0x05;
					dwDecDataOffset = dwOffset;
					t_disasm	da;

					while(dwOffset < RAINSONG_BUFF_SIZE - 6)
					{
						memset(&da, 0x00, sizeof(struct t_disasm));
						dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, m_dwImageBase, &da, DISASM_CODE);
						if(dwOffset > (RAINSONG_BUFF_SIZE - dwLength))
						{
							break;
						}
						if(dwLength == 5 && dwMatchedInstr == 0 && strstr(da.result,"MOV") && (*(DWORD *)&m_pbyBuff[dwOffset + 0x01] > 0xD800))
						{
							dwMatchedInstr++;														
							dwDecKey = *(DWORD *)&m_pbyBuff[dwOffset + 0x01];
						}
						if(dwLength == 5 && dwMatchedInstr == 1 && strstr(da.result,"MOV") && (*(DWORD *)&m_pbyBuff[dwOffset + 0x01] < 0x500))
						{
							dwMatchedInstr++;														
							dwDecLen = *(DWORD *)&m_pbyBuff[dwOffset + 0x01];
							if((dwDecLen * 4) >= RAINSONG_BUFF_SIZE)
							{
								break;
							}
						}
						if(dwLength == 3 && dwMatchedInstr == 2 && strstr(da.result,"XOR"))
						{
							dwMatchedInstr++;
						}
						if(dwLength == 6 && dwMatchedInstr == 3 && strstr(da.result,"ADD"))
						{
							dwMatchedInstr++;
							dwAddKey = *(DWORD *)&m_pbyBuff[dwOffset + 0x2];
						}
						if(dwLength == 5 && dwMatchedInstr == 3 && strstr(da.result,"ADD"))
						{
							dwMatchedInstr++;
							dwAddKey = *(DWORD *)&m_pbyBuff[dwOffset + 0x1];
						}
						if(dwLength == 6 && (dwMatchedInstr == 3 || dwMatchedInstr == 4) && strstr(da.result,"SUB"))
						{
							dwMatchedInstr++;
							dwSubKey = *(DWORD *)&m_pbyBuff[dwOffset + 0x2];
							bcheck = true;
							break;
						}
						if(dwLength == 5 && (dwMatchedInstr == 3 || dwMatchedInstr == 4) && strstr(da.result,"SUB"))
						{
							dwMatchedInstr++;
							dwSubKey = *(DWORD *)&m_pbyBuff[dwOffset + 0x1];
							bcheck = true;
							break;
						}
						dwOffset += dwLength;			
					}
					if(bcheck == false)
					{
						return iRetStatus;
					}

					if((memcmp(&m_pbyBuff[0x00], RainSong3891, sizeof(RainSong3891)) == 0) ||
						(memcmp(&m_pbyBuff[0x00], RainSong3910, sizeof(RainSong3910)) == 0) ||
						(memcmp(&m_pbyBuff[0x00], RainSong4198, sizeof(RainSong4198)) == 0))
					{
						DecryptRainSong(1,dwDecKey,0,0,0x5,0x5 + (dwDecLen * 4));
					}				
					//decryption for rainsong 4266
					else if(memcmp(&m_pbyBuff[0x00], RainSong4266, sizeof(RainSong4266)) == 0)
					{
						if(dwAddKey == 0x00)
						{							
							DecryptRainSong(3,dwDecKey,dwSubKey,0,0x5,0x5 + (dwDecLen * 4));
						}
						else if((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0x20000060) == 0x20000060)//added
						{
							DecryptRainSong(4,dwDecKey,dwAddKey,dwSubKey,0x5,0x5 + (dwDecLen * 4));
						}

						else
						{						
							DecryptRainSong(2,dwDecKey,dwAddKey,dwSubKey,0x5,0x5 + (dwDecLen * 4));
						}

					}
					else if((memcmp(&m_pbyBuff[0x00], RainSong3874, sizeof(RainSong3874)) == 0) ||
						(memcmp(&m_pbyBuff[0x00], RainSong3925, sizeof(RainSong3925)) == 0) ||
						(memcmp(&m_pbyBuff[0x00], RainSong3956, sizeof(RainSong3956)) == 0))
					{
						if(dwSubKey == 0x01)
						{
							dwSubKey = 0;
						}
						if((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0x20000060) == 0x20000060)
						{
							DecryptRainSong(4,dwDecKey,dwAddKey,dwSubKey,0x5,0x5 + (dwDecLen * 4));
						}
						else
						{
							DecryptRainSong(2,dwDecKey,dwAddKey,dwSubKey,0x5,0x5 + (dwDecLen * 4));
						}
					}

					//after decryption checking for virus signature for each variant.
					const BYTE RainSongSig1[] = {0x41, 0x4E, 0x44, 0x52, 0x49, 0x44, 0x4F, 0x44, 0x54, 0x42};
					const BYTE RainSongSig2[] = {0x39, 0x39, 0x20, 0x57, 0x61, 0x79, 0x73, 0x20, 0x54, 0x6F, 0x20, 0x44, 0x69, 0x65, 0x20, 0x43, 0x6F, 0x64, 0x65, 0x64, 0x20, 0x62};
					const BYTE RainSongSig3[] = {0x52, 0x61, 0x69, 0x6e, 0x20, 0x53, 0x6f, 0x6e, 
						0x67, 0x20, 0x43, 0x6f, 0x64, 0x65, 0x64, 0x20, 
						0x42, 0x79, 0x20, 0x42, 0x75, 0x6d, 0x62, 0x6c,
						0x65, 0x62, 0x65, 0x65, 0x2f, 0x32, 0x39, 0x61};

					if((memcmp(&m_pbyBuff[0xB72], RainSongSig3, sizeof(RainSongSig3)) == 0) ||
						(memcmp(&m_pbyBuff[0xB85], RainSongSig3, sizeof(RainSongSig3)) == 0) ||
						(memcmp(&m_pbyBuff[0xC7B], RainSongSig3, sizeof(RainSongSig3)) == 0)) 


					{
						m_ByVariant = 1;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.RainSong"));							
						return VIRUS_FILE_REPAIR;
					}				
					else if(memcmp(&m_pbyBuff[(dwDecDataOffset - 0x3D)], RainSongSig1, sizeof(RainSongSig1)) == 0 && 
						memcmp(&m_pbyBuff[(dwDecDataOffset - 0x2B)], RainSongSig2, sizeof(RainSongSig2)) == 0)
					{
						m_dwDataDec = *(DWORD *)&m_pbyBuff[0x27D] ^ *(DWORD *)&m_pbyBuff[(dwDecDataOffset - 0x4)];
						if(dwDecDataOffset == 0x10AA)
						{
							m_dwDataDec = *(DWORD *)&m_pbyBuff[0x2A8] ^ *(DWORD *)&m_pbyBuff[(dwDecDataOffset - 0x4)];
						}						
						m_ByVariant = 2;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.RainSong"));							
						return VIRUS_FILE_REPAIR;
					}	
				}			
			}
		}			
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptRainSong
	In Parameters	: BYTE ByDecType,DWORD dwDecKey,DWORD dwAddKey,DWORD dwSubKey,DWORD dwDecStartOffset,DWORD dwDecEndOffset
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption routine
--------------------------------------------------------------------------------------*/
void CPolyRainSong::DecryptRainSong(BYTE ByDecType,DWORD dwDecKey,DWORD dwAddKey,DWORD dwSubKey,DWORD dwDecStartOffset,DWORD dwDecEndOffset)
{
	switch(ByDecType)
	{
	case 1:
		{
			for(DWORD iOffset =  dwDecStartOffset; iOffset < dwDecEndOffset; iOffset += 4)
			{
				*(DWORD *)&m_pbyBuff[iOffset] ^= dwDecKey;
				*(DWORD *)&m_pbyBuff[iOffset]  = ~(*(DWORD *)&m_pbyBuff[iOffset]);
			}
		}
		break;
	case 2:
		{
			for(DWORD iOffset =  dwDecStartOffset; iOffset < dwDecEndOffset; iOffset += 4)
			{
				*(DWORD *)&m_pbyBuff[iOffset] ^= dwDecKey;
				dwDecKey += (dwAddKey - dwSubKey);
			}
		}
		break;
	case 3:
		{
			for(DWORD iOffset =  dwDecStartOffset; iOffset < dwDecEndOffset; iOffset += 4)
			{
				*(DWORD *)&m_pbyBuff[iOffset] ^= dwDecKey;
				dwDecKey -= (dwAddKey - dwSubKey);
			}
		}
	case 4:   //added
		{
			for(DWORD iOffset =  dwDecStartOffset; iOffset < dwDecEndOffset; iOffset += 4)
			{
				*(DWORD *)&m_pbyBuff[iOffset] ^= dwDecKey;
				
			}
		}
		break;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Rainsong Family
--------------------------------------------------------------------------------------*/
int CPolyRainSong::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	if(m_ByVariant == 1)
	{
		DWORD dwOriganalData = 0;
		if(m_pMaxPEFile->ReadBuffer(&dwOriganalData, m_dwAEPMapped, sizeof(DWORD), sizeof(DWORD)))
		{
			if((BYTE)dwOriganalData == 0xE9)
			{
				if(m_pMaxPEFile->WriteAEP((*(DWORD *)&m_pbyBuff[0xB] - m_dwImageBase)))
				{
					m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x5);
					if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset, true))
					{
						return REPAIR_SUCCESS;
					}
				}
			}
		}
		dwOriganalData = *(DWORD *)&m_pbyBuff[0xB] - (m_dwImageBase + m_dwCallPatchAdd + 0x05);
		if(m_pMaxPEFile->WriteBuffer(&dwOriganalData, m_dwCallPatchAdd + 1, sizeof(DWORD), sizeof(DWORD)))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset,true))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	else if(m_ByVariant == 2)
	{
		DWORD dwPatchedCall = m_dwDataDec - (m_dwImageBase + m_dwCallPatchAdd + 0x05);
		if(m_pMaxPEFile->WriteBuffer(&dwPatchedCall, m_dwCallPatchAdd + 1, sizeof(DWORD), sizeof(DWORD)))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset,true))
			{
				iRetStatus = REPAIR_SUCCESS;
			}	
		}
	}
	return iRetStatus;
}