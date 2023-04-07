/*======================================================================================
FILE				: Packers.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for Packed malwares.
					  The repair action is : DELETE
VERSION HISTORY		: 
=====================================================================================*/
#include "Packers.h"
#include "SemiPolyDBScn.h"

/*-------------------------------------------------------------------------------------
	Function		: CPackers
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPackers::CPackers(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPackers
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CPackers::~CPackers(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPackers
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detection routine for list of malwares using polymorphism
--------------------------------------------------------------------------------------*/
int CPackers::DetectVirus(void)
{
	typedef int (CPackers::*LPFNDetectVirus)();	
	LPFNDetectVirus pVirusList[] = 
	{
		&CPackers::DetectSVKP,
		//&CPackers::DetectPetite,
		&CPackers::DetectPGPME		
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
	Function		: DetectSVKP
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Poly.Trojan.Packed.SVKP
--------------------------------------------------------------------------------------*/
int CPackers::DetectSVKP(void)
{	
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD dwPtr2SymbolTable=0;
	m_pMaxPEFile->ReadBuffer(&dwPtr2SymbolTable, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0xC, 4, 4);
	
	if(dwPtr2SymbolTable == 0x504b5653 && 
		(m_wAEPSec == m_wNoOfSections - 1 || m_wAEPSec == m_wNoOfSections - 3) && 
		((m_pSectionHeader[m_wAEPSec].Characteristics & 0xC0000040) == 0xC0000040))
	{		
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int SVKP_BUFF_SIZE = 0x350;
		m_pbyBuff = new BYTE[SVKP_BUFF_SIZE];
		if(GetBuffer((m_dwAEPMapped), SVKP_BUFF_SIZE, SVKP_BUFF_SIZE))
		{
			TCHAR SVKP_SIG1[] = {_T("64A023000000EB03C784E884C0EB03C784E97567B9490000008DB5C5*0200005680064446E2FA8B8DC10200005E55516A0056FF95*595D4085C0753C803E00740346EBF846E2E38BC58B4C24202B*5568101000008D85B4000000508D85B4010000506A")};

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(SVKP_SIG1, _T("Poly.Trojan.Packed.SVKP"), FALSE);
					
			TCHAR szVirusName[MAX_PATH] = {0};
			if((polydbObj.ScanBuffer(&m_pbyBuff[0], SVKP_BUFF_SIZE, szVirusName) >= 0))
				
				if(_tcslen(szVirusName) > 0)
				{
					iRetStatus = VIRUS_FILE_DELETE;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPetite
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Poly.Trojan.Packed.Petite
--------------------------------------------------------------------------------------*/
int CPackers::DetectPetite()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wAEPSec > 0 && m_pSectionHeader[m_wAEPSec].PointerToRawData < m_pSectionHeader[m_wAEPSec - 1].PointerToRawData) || 
		m_pSectionHeader[m_wAEPSec].PointerToRawData > m_pSectionHeader[m_wAEPSec + 1].PointerToRawData ||
		m_pSectionHeader[m_wAEPSec].PointerToRawData < m_pSectionHeader[m_wAEPSec + 1].PointerToRawData)
	{ 
		if (m_pbyBuff)
		{
			delete []m_pbyBuff; 
			m_pbyBuff = NULL;
		}		
		const int PETITE_BUFF_SIZE = 0x20;
		m_pbyBuff = new BYTE[PETITE_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, PETITE_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		
		bool bSecFound = false;
		for(int i = 0; i < m_wNoOfSections ; i++)
		{
			if((memcmp(m_pSectionHeader[i].Name, ".petite", 7) == 0) || (m_pSectionHeader[i].PointerToRawData == 0x00 && m_pSectionHeader[i].SizeOfRawData == 0x00) || m_wAEPSec == 0x0)
			{
				bSecFound = true;
				break;
			}
		}
		if(bSecFound)
		{
			if(!GetBuffer(m_dwAEPMapped, PETITE_BUFF_SIZE))
			{
				return iRetStatus;
			}
			if(m_pbyBuff[0] == 0xB8 && *((DWORD *)&m_pbyBuff[1])- m_dwImageBase == m_pSectionHeader[m_wAEPSec].VirtualAddress && m_pbyBuff[1] == 0x0 && m_pbyBuff[0x10] == 0x0)
			{
				DWORD dwLength = 0, dwInstructionCnt = 0, dwOffset = 0;
				t_disasm	da;
				while(dwOffset < m_dwNoOfBytes)
				{
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwLength > m_dwNoOfBytes - dwOffset)
					{
						break;
					}
					if(dwLength == 5 && dwInstructionCnt == 0 && strstr(da.result, "MOV EAX"))
					{
						dwInstructionCnt++;
					}
					else if(dwLength == 5 && dwInstructionCnt == 1 && strstr(da.result, "PUSH"))
					{
						dwInstructionCnt++;
					}
					else if(dwLength == 7 && dwInstructionCnt == 2 && strstr(da.result, "PUSH DWORD PTR"))
					{
						dwInstructionCnt++;
					}
					else if(dwLength == 7 && dwInstructionCnt == 3 && strstr(da.result, "MOV"))
					{
						dwInstructionCnt++;
					}
					else if(dwLength == 2 && dwInstructionCnt == 4 && strstr(da.result, "PUSHF"))
					{
						dwInstructionCnt++;
					}
					else if(dwLength == 1 && dwInstructionCnt == 5 && strstr(da.result, "PUSHAD"))
					{
						dwInstructionCnt++;
					}
					else if(dwLength == 1 && dwInstructionCnt == 6 && strstr(da.result, "PUSH EAX"))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Poly.Trojan.Packed.Petite"));
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
	Function		: DetectPGPME
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.PGPME
--------------------------------------------------------------------------------------*/
int	CPackers::DetectPGPME()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL)!=IMAGE_FILE_DLL) &&
		m_wAEPSec == m_wNoOfSections - 1 &&
		m_dwAEPMapped - m_pSectionHeader[m_wAEPSec].PointerToRawData > 0x200 && 
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xC0000040) == 0xC0000040) && 
		m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 4000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}		
		m_pbyBuff = new BYTE[PGPME_BUFF_SIZE];

		TCHAR szVirusName[MAX_PATH] = {0};
		TCHAR PGPME_Sig[] ={_T("0D0A0D0A2D2D2D2D2D424547494E2050475020*2D2D2D2D2D0D0A56657273696F6E")};
		if(GetBuffer(m_dwAEPMapped - PGPME_BUFF_SIZE, PGPME_BUFF_SIZE, PGPME_BUFF_SIZE))
		{
			CSemiPolyDBScn objPolyDB;
			objPolyDB.LoadSigDBEx(PGPME_Sig, _T("Virus.PGPME"), FALSE);
			if(objPolyDB.ScanBuffer(&m_pbyBuff[0], PGPME_BUFF_SIZE, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName)>0)
				{
					iRetStatus = VIRUS_FILE_DELETE;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				}
			}
		}
	}
	return iRetStatus;
}