/*======================================================================================
FILE				: PolyMabezat.cpp
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
CREATION DATE		: 17 Mar 2012
NOTES				: This is detection module for malware Polymorphic Mabezat Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyMabezat.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyMabezat
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMabezat::CPolyMabezat(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_pbyBuff = new BYTE[MABEZATGEN_BUFF_SIZE];
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMabezat
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMabezat::~CPolyMabezat(void)
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
	Description		: Detection routine for different varients of Mabezat Family
--------------------------------------------------------------------------------------*/
int CPolyMabezat::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(GetBuffer(m_dwAEPMapped, MABEZATGEN_DETECT_BUFF_SIZE, MABEZATGEN_DETECT_BUFF_SIZE))
	{
		if(m_pbyBuff[0] == 0xBB && m_pbyBuff[0x05] == 0xFF && m_pbyBuff[0x06] == 0xE3)
		{
			DWORD dwRvaJmpValue = *(DWORD *)&m_pbyBuff[0x01] - m_dwImageBase;
			DWORD dwMapJmpValue = 0x00;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwRvaJmpValue, &dwMapJmpValue))
			{
				if(GetBuffer(dwMapJmpValue, MABEZATGEN_DETECT_BUFF_SIZE, MABEZATGEN_DETECT_BUFF_SIZE))
				{
					if(m_pbyBuff[0x05] == 0x93 && m_pbyBuff[0x06] == 0xE9)
					{
						if(GetMabezatParameters(dwRvaJmpValue))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Mabezat.B"));
							if(IsCorruptData())
							{
								iRetStatus = VIRUS_FILE_DELETE;
							}
							else
							{								
								iRetStatus = VIRUS_FILE_REPAIR;
							}
						}
					}
				}
			}
		}
		else if(m_pbyBuff[0] == 0xBB && m_pbyBuff[0x05] == 0x93 && m_pbyBuff[0x06] == 0xE9)
		{
			if(CheckVirusString())
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Mabezat.Dam"));
				iRetStatus = VIRUS_FILE_DELETE;
				
			}
			else if(GetMabezatParameters(m_dwAEPUnmapped))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Mabezat.B"));
				if(IsCorruptData())
				{
					iRetStatus = VIRUS_FILE_DELETE;
				}
				else
				{
					
					iRetStatus = VIRUS_FILE_REPAIR;
				}
			}
		}
		else if(m_pbyBuff[0] == 0x53)
		{
			BYTE byArray[] = {0x53, 0x83, 0xEC, 0x44, 0xB8, 0x23, 0x10, 0x40, 
						      0x00, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x8A, 0x18};
			if(!memcmp(m_pbyBuff, byArray, sizeof(byArray)))
			{
				BYTE bySig[] = {0x88,0x18,0x83,0xC0,0x01,0x83,0xC1,0x01};
					if(!memcmp(&m_pbyBuff[0x13], bySig, sizeof(bySig)))
					{
						iRetStatus = VIRUS_FILE_DELETE;
					}
				if(GetDecryptedData(0x12, 0x05))
				{
					if(GetDecryptedData(0x0E, 0x01))
					{
						if(CheckVirusString())
						{						
						  m_objMabezatGENStruct.dwOriFileSize = *((DWORD*)&m_pbyBuff[8]);
						  iRetStatus = VIRUS_FILE_DELETE;
						}
					}
				}
				if(iRetStatus == VIRUS_FILE_DELETE )
				{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Mabezat.B"));
						 return iRetStatus;
				}
					
			
			}
		}
		else if( m_pbyBuff[0] == 0x00 && m_wAEPSec == m_wNoOfSections - 1 && 
			     m_pSectionHeader[m_wNoOfSections-1].Characteristics && 0x20000000 == 0x20000000 &&
				 m_pMaxPEFile->m_stPEHeader.NumberOfSymbols != 0x4C495645)
		{
			for(WORD wSec =  0; wSec < m_wNoOfSections; wSec++)
			{
				DWORD dwSecAddress = m_pSectionHeader[wSec].VirtualAddress + m_pSectionHeader[wSec].Misc.VirtualSize;
				if(dwSecAddress)
				{
					dwSecAddress += (m_pMaxPEFile->m_stPEHeader.SectionAlignment - (dwSecAddress % m_pMaxPEFile->m_stPEHeader.SectionAlignment));
				}
				if(m_dwAEPUnmapped >= m_pSectionHeader[wSec].VirtualAddress && 
					((m_dwAEPUnmapped < dwSecAddress) || 
					(m_dwAEPUnmapped < (m_pSectionHeader[wSec].VirtualAddress + m_pSectionHeader[wSec].SizeOfRawData))))
				{
					if(wSec != m_wNoOfSections - 1)
					{
						return iRetStatus;
					}
					break;
				}				
			}
			BYTE byZeros[0x50] = {0};
			memset(byZeros, 0, sizeof(byZeros));
			if(!memcmp(m_pbyBuff, byZeros, sizeof(byZeros)))
			{
				iRetStatus = VIRUS_FILE_DELETE;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Mabezat.Dam"));
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetMabezatParameters
	In Parameters	: DWORD dwJmpValue
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: collects the required info from infected JMP instruction
--------------------------------------------------------------------------------------*/
bool CPolyMabezat::GetMabezatParameters(DWORD dwJmpValue)
{
	
	dwJmpValue +=  *(DWORD *)&m_pbyBuff[0x07] + 0x0B;
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwJmpValue, &dwJmpValue))
	{
		if(GetBuffer(dwJmpValue, MABEZATGEN_DETECT_BUFF_SIZE, MABEZATGEN_DETECT_BUFF_SIZE))
		{
			if(GetDecryptedData(0x1A, 0x0D))
			{
				if(GetDecryptedData(0x0E, 0x01))
				{
					if(CheckVirusString())
					{
						m_objMabezatGENStruct.dwOriFileSize = *((DWORD*)&m_pbyBuff[8]);
						return true;
					}
				}
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckVirusString
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Finds the infector dll file (stub) from buffer
--------------------------------------------------------------------------------------*/
bool CPolyMabezat::CheckVirusString()
{
	for(DWORD dwCounter = 0; dwCounter < MABEZATGEN_DETECT_BUFF_SIZE - 11; dwCounter++)
	{
		if(!_memicmp((&m_pbyBuff[dwCounter]), "tazebama.dl", 11))
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDecryptedData
	In Parameters	: DWORD dwKeyOffset, DWORD dwDecOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: using key from file decrypts and collects required information
--------------------------------------------------------------------------------------*/
bool CPolyMabezat::GetDecryptedData(DWORD dwKeyOffset, DWORD dwDecOffset)
{
	DWORD dwRVADecOffset = 0x00;
	m_objMabezatGENStruct.byDecryptionKey = m_pbyBuff[dwKeyOffset];
	if(m_pbyBuff[dwDecOffset] == 0x00 && m_pbyBuff[dwDecOffset + 0x04] == 0xB8)
	{
		dwRVADecOffset = *(DWORD *)&m_pbyBuff[dwDecOffset + 0x05] - m_dwImageBase;
	}
	else
	{
		dwRVADecOffset = *(DWORD *)&m_pbyBuff[dwDecOffset] - m_dwImageBase;
	}
	DWORD dwDecStartOff = 0x00;
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwRVADecOffset , &dwDecStartOff))
	{
		if(GetBuffer(dwDecStartOff, MABEZATGEN_DETECT_BUFF_SIZE, MABEZATGEN_DETECT_BUFF_SIZE))
		{
			for(DWORD dwCounter=0; dwCounter < MABEZATGEN_DETECT_BUFF_SIZE; dwCounter++)
			{
				m_pbyBuff[dwCounter] += m_objMabezatGENStruct.byDecryptionKey;
			}
		}
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsCorruptData
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Validates the decrypted data is valid or corrupt
--------------------------------------------------------------------------------------*/
bool CPolyMabezat::IsCorruptData()
{
	m_objMabezatGENStruct.m_dwOriAEPByteOffset = 0x8000 + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData+ m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size;
	if(m_objMabezatGENStruct.m_dwOriAEPByteOffset >= m_pMaxPEFile->m_dwFileSize)
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Mabezat Family
--------------------------------------------------------------------------------------*/
int CPolyMabezat::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	if(!GetBuffer(m_objMabezatGENStruct.m_dwOriAEPByteOffset + MABEZATGEN_BUFF_SIZE, 0x8, 0x8))	
	{
		return iRetStatus;
	}
		
	
	DWORD dwWriteOffset = 0;
	if((*((DWORD*)&m_pbyBuff[0]) == 0x0 && *((DWORD*)&m_pbyBuff[4]) == 0x0))
	{
		// replace 6E8 bytes at the original aep offset from m_dwOriAEPByteOffset
		dwWriteOffset = m_dwAEPMapped;
	}
	else
	{
		// This is original AEP first 8 bytes. Replace 8 byte at original AEP offset
		if(!m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwAEPMapped, 8, 8))
		{
			return iRetStatus;
		}
		// Replace  6E8 bytes at original AEP-0x708 offset
		dwWriteOffset = m_dwAEPMapped - 0x708;
	}
	// original aep Bytes is at m_dwOriAEPByteOffset
	if(!GetBuffer(m_objMabezatGENStruct.m_dwOriAEPByteOffset, MABEZATGEN_BUFF_SIZE, MABEZATGEN_BUFF_SIZE))
	{
		return iRetStatus;
	}

	if(!m_pMaxPEFile->WriteBuffer(m_pbyBuff, dwWriteOffset, MABEZATGEN_BUFF_SIZE, MABEZATGEN_BUFF_SIZE))
	{
		return iRetStatus;
	}
	if(m_pMaxPEFile->TruncateFile(m_objMabezatGENStruct.dwOriFileSize))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}