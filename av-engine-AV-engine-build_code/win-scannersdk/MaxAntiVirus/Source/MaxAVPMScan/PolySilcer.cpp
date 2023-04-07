/*======================================================================================
FILE				: PolySilcer.cpp
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
NOTES				: This is detection module for malware Silcer Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolySilcer.h"
#include "PtrStack.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolySilcer
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolySilcer::CPolySilcer(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolySilcer
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolySilcer::~CPolySilcer(void)
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
	Description		: Detection routine for different varients of Silcer Family
					  This function check is file is infected by Silcer by 
					  looking at set of instructions and also checks DOS
					  header checksum for 4844 value
--------------------------------------------------------------------------------------*/
int CPolySilcer::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	// Virus sets checksum of DOS header to 4844 so check for that
	if( ((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL && m_pMaxPEFile->m_stPEHeader.e_csum == 0x4844)||
		(m_wAEPSec == m_wNoOfSections - 1 && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > 0x7000))
	{
		m_pbyBuff = new BYTE[SILCER_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, SILCER_BUFF_SIZE + MAX_INSTRUCTION_LEN);

		if(GetBuffer(m_dwAEPMapped, SILCER_BUFF_SIZE))
		{		
			DWORD dwOriginalAEPLoc = GetSilcerParamters();
			if(dwOriginalAEPLoc)
			{			
				DWORD dwOriginalAEP  = 0;
				if(m_pMaxPEFile->ReadBuffer(&dwOriginalAEP, dwOriginalAEPLoc, sizeof(DWORD), sizeof(DWORD)))
				{
					if(dwOriginalAEP)
					{
						m_dwSilcerOriginalAEP = dwOriginalAEP - m_dwImageBase;						
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Silcer"));
						iRetStatus = VIRUS_FILE_REPAIR;			
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSilcerParamters
	In Parameters	: 
	Out Parameters	: Returns file offset of original AEP bytes kept by virus 
	Purpose			: 
	Author			: Rupali Sonawane + Virus Analysis Team
	Description		: The function looks for sepcific set of instructions to 
					  detect infection of virus silcer.
--------------------------------------------------------------------------------------*/
int	CPolySilcer::GetSilcerParamters()
{			
	t_disasm da;
	
	DWORD	dwOffset = 0, dwLength, dwConst1 = 0, dwConst2 = 0, dwStartInstrAdd = 0, dwAEPLocation = 0;  
	bool	bFound1stInst = false, bFoundSubEBPInst = false, bFoundSubInst = false;

	BYTE	B1, B2;
	
	m_objMaxDisassem.InitializeData();

	CPtrStack	stAddrCalConsts;
	
	while(dwOffset < m_dwNoOfBytes)
	{		
		memset(&da, 0x00, sizeof(struct t_disasm) * 1);
		B1 = m_pbyBuff[dwOffset] ;
		B2 = m_pbyBuff[dwOffset + 1] ;

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1 == 0xC1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset+= 0x03 ;
			continue ;
		}
		if(B1 == 0xD1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset+= 0x02 ;
			continue ;
		}

		if(B1 == 0xC3 || B1 == 0xC2)
		{				
			break;
		}
		
		dwLength = m_objMaxDisassem.Disasm((char* )&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffset))
		{
			return 0;
		}

		if(dwLength == 0x01 && B1 == 0xE2 && strstr(da.result, "???"))
		{
			dwOffset += 0x02 ;
			continue ;
		}
		// Look for the call instruction as its the first instruction of virus code
		// Sometimes it keeps NOPs befor call instruction. Virus uses the address of 
		// the call instruction for calculating the location of original AEP bytes
		if(!dwStartInstrAdd && dwLength == 0x05 && B1 == 0xE8 && strstr(da.result, "CALL ") )
		{
			dwStartInstrAdd = m_dwAEPMapped + dwOffset + m_pSectionHeader[m_wAEPSec].VirtualAddress - 
				m_pSectionHeader[m_wAEPSec].PointerToRawData + m_dwImageBase; 
		}

		if(dwLength == 0x01 && B1 == 0x5D && strstr(da.result, "POP EBP"))
		{
			bFound1stInst = true;
		}
		if(bFound1stInst)
		{
			if(dwLength == 0x03 && B1 == 0x83 && B2 == 0xED && strstr(da.result, "SUB EBP,5"))
			{
				bFoundSubEBPInst = true;
			}
			if(bFoundSubEBPInst)
			{
				if(dwLength == 0x05 && B1 == 0xB8 && strstr(da.result, "MOV EAX,"))
				{
					// Constant in this instrution gets used for address calculation
					dwConst1 = *((DWORD* )&m_pbyBuff[dwOffset + 1]);
					stAddrCalConsts.Push((LPVOID)dwConst1);				
				}
				if(!stAddrCalConsts.IsEmpty())
				{
					if(dwLength == 0x02 && B1 == 0x2B && B2 == 0xE8 && strstr(da.result, "SUB EBP,EAX"))
					{
						bFoundSubInst = true;
					}
					if(bFoundSubInst)
					{
						if(dwLength == 0x06 && B1 == 0x8B && B2 == 0x85 && strstr(da.result, "MOV EAX,[EBP+"))
						{
							// Ths is one more constant that gets used for address calculation
							// These 2 constants and starting address of the virus code are used
							// to get the location where the original AEP is kept
							dwConst2 = *((DWORD* )&m_pbyBuff[dwOffset + 2]);
														
							while(!stAddrCalConsts.IsEmpty())
							{
								dwConst1 = (DWORD)stAddrCalConsts.Pop();
								
								dwAEPLocation = dwConst2 + dwStartInstrAdd - dwConst1;
								
								// Got the VA address now convert it to the file offset
								dwAEPLocation += m_pSectionHeader[m_wAEPSec].PointerToRawData - m_pSectionHeader[m_wAEPSec].VirtualAddress - 
												m_dwImageBase;
								if(dwAEPLocation < (m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData))
								{
									return dwAEPLocation;
								}
							}
						}
					}
				}
			}
		}		
		dwOffset += dwLength ;
	}
	return 0;	
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Rupali Sonawane + Virus Analysis Team
	Description		: The function repair file infected by Silcer. It assumes the
					  file is rescanned before calling the function and original
					  AEP is set to member variable m_dwSilcerOriginalAEP
--------------------------------------------------------------------------------------*/
int CPolySilcer::CleanVirus()
{	
	int iRetStatus = REPAIR_FAILED;
	
	// Set the Original AEP
	m_pMaxPEFile->WriteAEP(m_dwSilcerOriginalAEP);
		
	// Set Image size and size of code
	DWORD dwOriginalAEPSection = m_pMaxPEFile->Rva2FileOffset(m_dwSilcerOriginalAEP, NULL);
	m_pMaxPEFile->RepairOptionalHeader(4, m_pSectionHeader[dwOriginalAEPSection].SizeOfRawData, 0);
	
	if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}