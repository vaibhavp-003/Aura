/*======================================================================================
FILE				: PolyDion.cpp
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
NOTES				: This is detection module for malware Dion Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyDion.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyDion
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDion::CPolyDion(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	memset(&m_stGetTable, 0, sizeof(ReplaceStructure));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDion
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDion::~CPolyDion(void)
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
	Description		: Detection routine for different varients of Dion Family
--------------------------------------------------------------------------------------*/
int CPolyDion::DetectVirus(void)
{	
	if( ((m_pSectionHeader[m_wAEPSec].Characteristics& 0x020)  == 0x00000020) &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
	{	
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int DION_BUFF_SIZE_Sig = sizeof(ReplaceStructure);
		m_pbyBuff = new BYTE[DION_BUFF_SIZE_Sig];
		if(GetBuffer(m_dwAEPMapped, 6, 6))
		{  
			if(*(WORD *)&m_pbyBuff[0] == 0xE890)
			{
				if(m_pMaxPEFile->m_stPEHeader.SizeOfCode >= 0x1810)
				{
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(*(DWORD*)&m_pbyBuff[2] + m_dwAEPUnmapped + 0x06, &m_dwCallAddr))
					{
						m_dwBytesToRead = 0x32;
						if(GetBuffer(m_dwCallAddr, m_dwBytesToRead, m_dwBytesToRead))
						{
							if(CheckInitialParameters() && CheckFurtherParameters())
							{
								if(m_pbyBuff[8] == 0x23)
								{
									m_dwCallAddr += 0x1B;
								}
								if(m_pMaxPEFile->ReadBuffer(&m_stGetTable, m_dwCallAddr + 0x3BC, DION_BUFF_SIZE_Sig, DION_BUFF_SIZE_Sig))
								{
									if( ((m_stGetTable.GetTable[0].Size ==0x43F) && (m_stGetTable.GetTable[1].Size == 0x3F1) && 
										(m_stGetTable.GetTable[2].Size == 0x38B) && (m_stGetTable.GetTable[3].Size == 0x48E) && 
										(m_stGetTable.GetTable[4].Size == 0x372)) ||
										((m_stGetTable.GetTable[0].Size ==0x424) && (m_stGetTable.GetTable[1].Size == 0x404) &&
										(m_stGetTable.GetTable[2].Size == 0x36C) && (m_stGetTable.GetTable[3].Size == 0x486) &&
										(m_stGetTable.GetTable[4].Size == 0x372)))
									{
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("W32.Dion"));
										return VIRUS_FILE_REPAIR;
									}
								}
							}
						}
					}
				}
			}		
			else if(m_dwAEPUnmapped == 0x1020 && m_wNoOfSections == 1 && m_pSectionHeader[0].Characteristics == 0xE0000020 && 
				m_pSectionHeader[0].PointerToRawData == 0x220 && (m_pMaxPEFile->m_dwFileSize == 0x151C || m_pMaxPEFile->m_dwFileSize == 0x14ED))
			{
				m_dwBytesToRead = 0x28;
				if(m_pMaxPEFile->m_dwFileSize == 0x14ED)
				{
					m_dwBytesToRead += 0x0A;
				}
				if(GetBuffer(0x220, m_dwBytesToRead, m_dwBytesToRead))
				{
					if(CheckInitialParameters())
					{
						if(CheckStubName(m_pMaxPEFile->m_szFilePath) || CheckFurtherParameters())
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("W32.Dion"));
							return VIRUS_FILE_DELETE;
						}
					}

					else if(*(DWORD*)&m_pbyBuff[0] == 0x75850FC0 && *(DWORD*)&m_pbyBuff[4] == 0xA1000001 && *(WORD*)&m_pbyBuff[8] == 0x5818)
					{
						if(CheckStubName(m_pMaxPEFile->m_szFilePath))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("W32.Dion"));
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
	Function		: CheckInitialParameters
	In Parameters	: 
	Out Parameters	: true if match else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Top level check to identify infection
--------------------------------------------------------------------------------------*/
bool CPolyDion::CheckInitialParameters()
{
	if((*(DWORD*)&m_pbyBuff[0] == 0x000000E8) && ((*(DWORD*)&m_pbyBuff[5] & 0x21C08158) == 0x21C08158) && ((*(DWORD*)&m_pbyBuff[9] == 0xBD000000)))
	{
		if(((m_pbyBuff[5] % 0x08) == (m_pbyBuff[7]%0x08))&& ((m_pbyBuff[5] % 0x08) == (m_pbyBuff[0x12] % 0x08)))
		{
			if(m_pbyBuff[0x11] == 0x08B)
			{
				return true;
			}
		}		
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckFurtherParameters
	In Parameters	: 
	Out Parameters	: true if match else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Following -ve JUMP for more detection
--------------------------------------------------------------------------------------*/
bool CPolyDion::CheckFurtherParameters()
{
	t_disasm da = {0x00};
	for(DWORD dwOffset = 0x00; dwOffset < m_dwBytesToRead;)
	{
		dwOffset += m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(strstr(da.result, "JNZ"))
		{
			if((m_pbyBuff[dwOffset - 0x02] == 0x75 && m_pbyBuff[dwOffset - 0x01] > 0xDE) &&
				(m_pbyBuff[dwOffset - 0x03] == 0x4D && (*(DWORD*)&m_pbyBuff[dwOffset - 0x07] == 0x04)) &&
				(*(WORD*)&m_pbyBuff[dwOffset - 0x09] == *(WORD*)&m_pbyBuff[0x06]) && 
				(m_pbyBuff[dwOffset - 0x0A] == m_pbyBuff[0x12] && m_pbyBuff[dwOffset - 0x0B] + 0x02 == m_pbyBuff[0x11]))
			{
				return true;
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckStubName
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Retrieves virus stub name which is responsible for infection
--------------------------------------------------------------------------------------*/
bool CPolyDion::CheckStubName(TCHAR Fpath[])
{
	wchar_t *TEndPath5CLocation = _tcsrchr(Fpath, 0x5C) + 0x01;
	wchar_t *TBegPath5CLocation = TEndPath5CLocation;

	while(TEndPath5CLocation != (Fpath + _tcslen(Fpath)))
	{
		//Checking for 8 digits first
		if(!((*TEndPath5CLocation >= 0x030) && (*TEndPath5CLocation < 0x3A)))
		{
			break;
		}
		TEndPath5CLocation++;
	}

	//Checking to see if 8 digits have been read
	if((TEndPath5CLocation - TBegPath5CLocation) == 0x08)
	{
		//Checking for "dll" name
		if(memcmp(TEndPath5CLocation,_T("dll"),0x03)==0x00)
		{
			return true;
		}
		else if(memcmp(TEndPath5CLocation,_T(".dllF_DONTCARE"),0x0D)==0x00)
		{
			return true;
		}
		else if(memcmp(TEndPath5CLocation,_T(".dll"),0x04)==0x00)
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Dion Family
--------------------------------------------------------------------------------------*/
int CPolyDion::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;

	BYTE *bySrcbuff = new BYTE[0x500];
	for(DWORD dwCounter = 0x00; dwCounter < 0x05; dwCounter++)
	{
		if((m_stGetTable.GetTable[dwCounter].OriginalCodeoffset == 0x00) && (m_stGetTable.GetTable[dwCounter].VirusCodeRVA == 0x00)
			&& (m_stGetTable.GetTable[dwCounter].VirusCodeFileOffset >= (m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections-1].VirtualAddress)))
		{
			continue;
		}
		memset(bySrcbuff, 0x00, 0x500);
		if(!m_pMaxPEFile->ReadBuffer(bySrcbuff, m_stGetTable.GetTable[dwCounter].OriginalCodeoffset, m_stGetTable.GetTable[dwCounter].Size, m_stGetTable.GetTable[dwCounter].Size))
		{
			if(bySrcbuff)
			{
				delete[] bySrcbuff;
				bySrcbuff = NULL;
			}
			return iRetStatus;
		}
		if(!m_pMaxPEFile->WriteBuffer(bySrcbuff,m_stGetTable.GetTable[dwCounter].VirusCodeFileOffset,m_stGetTable.GetTable[dwCounter].Size,m_stGetTable.GetTable[dwCounter].Size))
		{
			if(bySrcbuff)
			{
				delete[] bySrcbuff;
				bySrcbuff = NULL;
			}
			return iRetStatus;
		}		
	}
	if(bySrcbuff)
	{
		delete[] bySrcbuff;
		bySrcbuff = NULL;
	}
	if(m_pMaxPEFile->WriteBuffer(&m_stGetTable.OriginalPatch[2],m_dwAEPMapped,0x06,0x06))
	{
		if(m_stGetTable.GetTable[0].OriginalCodeoffset == 0x00)
		{
			m_stGetTable.GetTable[0].OriginalCodeoffset=m_stGetTable.GetTable[0].VirusCodeFileOffset;
		}
		if(m_pMaxPEFile->TruncateFile(m_stGetTable.GetTable[0].OriginalCodeoffset))
		{
			return REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}

