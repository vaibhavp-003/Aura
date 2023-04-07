/*======================================================================================
FILE				: PolyTrojanPatched.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malware Trojan.Patched Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyTrojanPatched.h"
#include "SemiPolyDBScn.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyTrojanPatched
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyTrojanPatched::CPolyTrojanPatched(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0; 
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyTrojanPatched
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyTrojanPatched::~CPolyTrojanPatched(void)
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
	Description		: Detection routine for different varients of Trojan.Patched Family
					  This function call indivdual detection routines for different patched trojans
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectVirus(void)
{
	typedef int (CPolyTrojanPatched::*LPFNDetectVirus)();	
	LPFNDetectVirus pVirusList[] = 
	{
		&CPolyTrojanPatched::DetectTrojanPatchedlp,
		&CPolyTrojanPatched::DetectTrojanPatchedkl,
		&CPolyTrojanPatched::DetectTrojanPatchedJa,
		&CPolyTrojanPatched::DetectTrojanPatchedLK,
		&CPolyTrojanPatched::DetectTrojanPatchedMK,
		&CPolyTrojanPatched::DetectTrojanPatchedEH,
		&CPolyTrojanPatched::DetectTrojanPatchedGO,
		&CPolyTrojanPatched::DetectTrojanPatchedJI,
		&CPolyTrojanPatched::DetectTrojanPatchedDR,
		&CPolyTrojanPatched::DetectTrojanPatchedBZ,
		&CPolyTrojanPatched::DetectTrojanPatchedJ,
		&CPolyTrojanPatched::DetectTrojanPatchedJH,
		&CPolyTrojanPatched::DetectTrojanPatchedHL,
		&CPolyTrojanPatched::DetectTrojanPatchedDQ,
		&CPolyTrojanPatched::DetectTrojanPatchedOD,
		&CPolyTrojanPatched::DetectTrojanPatchedDY,
		&CPolyTrojanPatched::DetectTrojanPatchedAL,
		&CPolyTrojanPatched::DetectTrojanPatchedBJ,
		&CPolyTrojanPatched::DetectTrojanPatchedBH,
		&CPolyTrojanPatched::DetectTrojanPatchedOK,
		&CPolyTrojanPatched::DetectTrojanPatchedDK,
		&CPolyTrojanPatched::DetectTrojanPatchedMU,
		&CPolyTrojanPatched::DetectTrojanPatchedOM,
		&CPolyTrojanPatched::DetectTrojanPatchedLQ,
		&CPolyTrojanPatched::DetectTrojanPatchedDO,
		&CPolyTrojanPatched::DetectTrojanPatchedMJ,
		&CPolyTrojanPatched::DetectTrojanPatchedHB,
		&CPolyTrojanPatched::DetectTrojanPatchedHG,
		&CPolyTrojanPatched::DetectTrojanPatchedHZ,
		&CPolyTrojanPatched::DetectTrojanPatchedHP,
		&CPolyTrojanPatched::DetectTrojanPatchedHI,
		&CPolyTrojanPatched::DetectTrojanPatchedDZ,
		&CPolyTrojanPatched::DetectTrojanPatchedMY,
		&CPolyTrojanPatched::DetectTrojanPatchedKa
	};

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	int iRetStatus = VIRUS_NOT_FOUND;
	m_pbyBuff = new BYTE[PATCHED_BUFF_SIZE + MAX_INSTRUCTION_LEN];

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
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Trojan.Patched Family
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanVirus(void)
{
	typedef int (CPolyTrojanPatched::*LPFNCleanVirus)();	
	struct
	{
		PATCHED_VIRUS ePatchedType;
		LPFNCleanVirus lpfnCleanVirus;
	}pVirusList[] = 
	{
		{TrojanPatchedlp, &CPolyTrojanPatched::CleanTrojanPatchedlp},
		{TrojanPatchedkl, &CPolyTrojanPatched::CleanTrojanPatchedkl},
		{TrojanPatchedJa, &CPolyTrojanPatched::CleanTrojanPatchedJa},
		{TrojanPatchedLK, &CPolyTrojanPatched::CleanTrojanPatchedLK},
		{TrojanPatchedMK, &CPolyTrojanPatched::CleanTrojanPatchedMK},
		{TrojanPatchedEH, &CPolyTrojanPatched::CleanTrojanPatchedEH},
		{TrojanPatchedGO, &CPolyTrojanPatched::CleanTrojanPatchedGO},
		{TrojanPatchedJI, &CPolyTrojanPatched::CleanTrojanPatchedJI},
		{TrojanPatchedDR, &CPolyTrojanPatched::CleanTrojanPatchedDR},
		{TrojanPatchedBZ, &CPolyTrojanPatched::CleanTrojanPatchedBZ},
		{TrojanPatchedJ, &CPolyTrojanPatched::CleanTrojanPatchedJ},
		{TrojanPatchedJH, &CPolyTrojanPatched::CleanTrojanPatchedJH},
		{TrojanPatchedHL, &CPolyTrojanPatched::CleanTrojanPatchedHL},
		{TrojanPatchedDQ, &CPolyTrojanPatched::CleanTrojanPatchedDQ},
		{TrojanPatchedOD, &CPolyTrojanPatched::CleanTrojanPatchedOD},
		{TrojanPatchedDY, &CPolyTrojanPatched::CleanTrojanPatchedDY},
		{TrojanPatchedAL, &CPolyTrojanPatched::CleanTrojanPatchedAL},
		{TrojanPatchedBJ, &CPolyTrojanPatched::CleanTrojanPatchedBJ},
		{TrojanPatchedBH, &CPolyTrojanPatched::CleanTrojanPatchedBH},
		{TrojanPatchedOK, &CPolyTrojanPatched::CleanTrojanPatchedOK},
		{TrojanPatchedDK, &CPolyTrojanPatched::CleanTrojanPatchedDK},
		{TrojanPatchedMU, &CPolyTrojanPatched::CleanTrojanPatchedMU},
		{TrojanPatchedOM, &CPolyTrojanPatched::CleanTrojanPatchedOM},
		{TrojanPatchedDO, &CPolyTrojanPatched::CleanTrojanPatchedDO},
		{TrojanPatchedMJ, &CPolyTrojanPatched::CleanTrojanPatchedMJ},
		{TrojanPatchedHG, &CPolyTrojanPatched::CleanTrojanPatchedHG},
		{TrojanPatchedHZ, &CPolyTrojanPatched::CleanTrojanPatchedHZ},
		{TrojanPatchedHP, &CPolyTrojanPatched::CleanTrojanPatchedHP},
		{TrojanPatchedHI, &CPolyTrojanPatched::CleanTrojanPatchedHI},
		{TrojanPatchedDZ, &CPolyTrojanPatched::CleanTrojanPatchedDZ},
		{TrojanPatchedKa, &CPolyTrojanPatched::CleanTrojanPatchedKa}
	};

	int iRetStatus = REPAIR_FAILED;
	for(int i = 0; i < _countof(pVirusList); i++)
	{
		if(pVirusList[i].ePatchedType == m_eVirusDetected)
		{
			return (this->*(pVirusList[i].lpfnCleanVirus))();			
		}
	}		
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedlp
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Rupali Sonawane + Virus Analysis Team
	Description		: This function checks if the file has patched call to load the 
					  some dll dropped by trojan. For that it looks for the kernel 
					  call at the AEP.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedlp()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	BYTE	bBuffer[PATCHED_LP_BYTES] = {0};

	// Read buffer at AEP to check whether any call is patched
	if(!m_pMaxPEFile->ReadBuffer(bBuffer, m_dwAEPMapped, PATCHED_LP_BYTES, PATCHED_LP_BYTES))
		return iRetStatus;

	if(bBuffer[0] == 0x68 && bBuffer[5] == 0xFF &&	bBuffer[6] == 0x15)
	{				
		// As AEP is at Kernel call read the dll that its trying to load
		DWORD dwDataRVAOffset = *(DWORD *)&bBuffer[1];
		
		// Read the dll name maintained in the file
		dwDataRVAOffset -= m_dwImageBase;
		m_pMaxPEFile->Rva2FileOffset(dwDataRVAOffset, &m_dwDLLFileOffset);
		if(m_dwDLLFileOffset > m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)
			return iRetStatus;
		
		BYTE bDLLSig[] = {0x2e, 0x00, 0x64, 0x00, 0x6c, 0x00, 0x6c, 0x00};
		
		memset(bBuffer, 0x00, PATCHED_LP_BYTES);
		if(m_pMaxPEFile->ReadBuffer(bBuffer, m_dwDLLFileOffset, PATCHED_LP_BYTES, PATCHED_LP_BYTES))
		{
			for(DWORD dwOffset = 0; dwOffset < (PATCHED_LP_BYTES - sizeof(bDLLSig)); dwOffset++)
			{
				// Check the data read for dll name
				if(memcmp(&bBuffer[dwOffset], bDLLSig, sizeof(bDLLSig)) == 0)
				{
					// Now we are sure that its trying to load some dll at start
					m_eVirusDetected = TrojanPatchedlp;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.lp"));
					iRetStatus = VIRUS_FILE_REPAIR;
					break;
				}
			}			
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedlp
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Rupali Sonawane + Virus Analysis Team
	Description		: Repair routine for different varients of Trojan.Patched.LP Family
					  This function repairs file by removing patched call and 
					  setting AEP to original value. It uses m_dwDLLFileOffset 
					  which is set by function DetectTrojanPatchedlp
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedlp()
{
	int iRetStatus = REPAIR_FAILED;

	// Virus keeps the original patched bytes, data and AEP at the end of AEP 
	// section so scan the section from end to find the original data 
	
	DWORD dwOffset = m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - PATCHED_LP_SCAN_BYTES;
	if(dwOffset < m_pSectionHeader[m_wAEPSec].PointerToRawData)
		return iRetStatus;

	BYTE bBuffer[PATCHED_LP_SCAN_BYTES] = {0};
	DWORD dwBytesRead = 0;
	if(m_pMaxPEFile->ReadBuffer(bBuffer, dwOffset, PATCHED_LP_SCAN_BYTES, 0, &dwBytesRead))
	{
		for(DWORD dwCnt = dwBytesRead - 1; dwCnt > 0; dwCnt--)
		{
			// Skip the zeros from end of the section
			if(bBuffer[dwCnt] == 0)
				continue;

			// Found nonzero value 
			
			// Set AEP to the original AEP
			DWORD dwOriginalAEP = *(DWORD *)&bBuffer[dwCnt - AEP_BYTES_OFFSET];
			
			// Check whether the found AEP lies in the 1st section if not return
			if(!(dwOriginalAEP > m_pSectionHeader[m_wAEPSec].VirtualAddress && 
				dwOriginalAEP < m_pSectionHeader[m_wAEPSec].VirtualAddress + m_pSectionHeader[m_wAEPSec].Misc.VirtualSize))
				return iRetStatus;

			m_pMaxPEFile->WriteAEP(dwOriginalAEP);

			// Replaced patched loadlibrary call with the original kernel call			
			if(!m_pMaxPEFile->WriteBuffer(&bBuffer[dwCnt - 3], m_dwAEPMapped + 7, sizeof(DWORD), sizeof(DWORD)))
				return iRetStatus;

			// Repalce dll name kept by trojan with the original bytes 
			BYTE bFillBuff[PATCHED_LP_BYTES]= {0};
			if(!m_pMaxPEFile->ReadBuffer(bFillBuff, (dwOffset + dwCnt - AEP_BYTES_OFFSET + sizeof(DWORD)), PATCHED_LP_BYTES, PATCHED_LP_BYTES))
				return iRetStatus;	
	
			if(!m_pMaxPEFile->WriteBuffer(bFillBuff, m_dwDLLFileOffset, PATCHED_LP_BYTES, PATCHED_LP_BYTES))
				return iRetStatus;
						
			// Fill the bytes maintained by virus by zeros
			if(m_pMaxPEFile->FillWithZeros((dwOffset + dwCnt - AEP_BYTES_OFFSET - 1), AEP_BYTES_OFFSET + 2))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
			break;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedkl
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function checks if buffer at the AEP is replaced by 
					  virus with its code by checking set of instructions.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedkl()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	// Read buffer at AEP to check whether any call is patched
	if(!GetBuffer(m_dwAEPMapped, PATCHED_BUFF_SIZE, PATCHED_BUFF_SIZE))
		return iRetStatus;

	BYTE bySignature[MAX_PATH]; 
	memcpy(bySignature, PATCHED_KL_SIG, sizeof(PATCHED_KL_SIG));
	for(int iOffset = m_dwNoOfBytes - sizeof(PATCHED_KL_SIG) - 1; iOffset >= 0; iOffset--)
	{
		// Check for the Trojan patch kl signature. It has hlp.dat file path.
		if(memcmp(&m_pbyBuff[iOffset], bySignature, sizeof(PATCHED_KL_SIG)) == 0)
		{
			m_PatchedlpStruct.dwOriginalBytesOffset = 0;
			m_PatchedlpStruct.dwSizeOfBuff = 0;
			if(!GetTrojanPatchedklParams(iOffset))
			{
				return iRetStatus;
			}

			DWORD dwSecNo = m_pMaxPEFile->Rva2FileOffset(m_PatchedlpStruct.dwOriginalBytesOffset, 
											&m_PatchedlpStruct.dwOriginalBytesOffset);
			
			// Check whether offset lies in the AEP section and length is valid
			if(m_PatchedlpStruct.dwOriginalBytesOffset != 0 &&
				//dwSecNo == m_wAEPSec && 
				m_PatchedlpStruct.dwSizeOfBuff <= PATCHED_BUFF_SIZE)
			{
				m_eVirusDetected = TrojanPatchedkl;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.kl"));
				iRetStatus = VIRUS_FILE_REPAIR;
				if(m_PatchedlpStruct.dwOriginalBytesOffset > m_pMaxPEFile->m_dwFileSize)
				{
					iRetStatus = VIRUS_FILE_DELETE;
				}
			}
			break;
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetTrojanPatchedklParams
	In Parameters	: DWORD dwBytesRead
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get required information for detection of Trojan.Packed.KL
--------------------------------------------------------------------------------------*/
bool CPolyTrojanPatched::GetTrojanPatchedklParams(DWORD dwBytesRead)
{
	BYTE		B1, B2;
	DWORD		dwLength = 0x00, dwInstructionCnt = 0x00, dwOffSet = 0x00;
	DWORD		dwValidIstrCnt = 0x00; // It is used for maintaing sequence of instruction.
	t_disasm	da;
		
	while(dwOffSet < dwBytesRead)
	{
		if(dwInstructionCnt > 0x80)
			return FALSE;

		memset(&da, 0x00, sizeof(struct t_disasm)*1);

		B1 = m_pbyBuff[dwOffSet];
		B2 = m_pbyBuff[dwOffSet + 1];

		//Handling for garbage instruction.
		if(B1 == 0xC1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet += 0x03;
			continue;
		}
		if(B1 == 0xD1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet += 0x02;
			continue;
		}
		if(B1 == 0xD0 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet += 0x02;
			continue;
		}
		if(B1 == 0xD2 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x02;
			continue;
		}
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (dwBytesRead - dwOffSet))
		{
			return FALSE;
		}
		
		dwInstructionCnt++;
		dwOffSet += dwLength;

		if(B1 == 0x90 && dwLength == 0x01 && strstr(da.result,"NOP"))
		{
			continue;
		}
		
		if(B1 == 0xFF && B2 == 0xD1 && dwLength == 2 && strstr(da.result, "CALL ECX"))
		{
			dwValidIstrCnt++;
			continue;
		}
		if(B1 == 0xFF && B2 == 0xD0 && dwLength == 2 && strstr(da.result, "CALL EAX"))
		{
			dwValidIstrCnt++;
			continue;
		}
		if(B1 == 0xBF && (dwValidIstrCnt == 4 || dwValidIstrCnt == 3) && dwLength == 5 && strstr(da.result, "MOV EDI,"))
		{
			dwValidIstrCnt++;
			continue;
		}
		if(B1 == 0xBE && (dwValidIstrCnt == 5 || dwValidIstrCnt == 4) && dwLength == 5 && strstr(da.result, "MOV ESI,"))
		{
			// Got offset of original bytes
			m_PatchedlpStruct.dwOriginalBytesOffset = *((DWORD*)&m_pbyBuff[dwOffSet - dwLength + 1]);
			dwValidIstrCnt++;
			continue;
		}
		if(B1 == 0xB9 && (dwValidIstrCnt == 5 || dwValidIstrCnt == 6) && dwLength == 5 && strstr(da.result, "MOV ECX,"))
		{
			// Got size of patched code
			m_PatchedlpStruct.dwSizeOfBuff = *((DWORD*)&m_pbyBuff[dwOffSet - dwLength + 1]);
			return true;
		}		
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedkl
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Rupali Sonawane + Virus Analysis Team
	Description		: Repair routine for different varients of Trojan.Patched.KL Family
					  This function repairs file by replacing the buffer written
					  by virus at AEP
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedkl()
{
	int iRetStatus = REPAIR_FAILED;
		
	// Read original code maintained by virus at the end of AEP section 	
	memset(m_pbyBuff, 0, PATCHED_BUFF_SIZE);
	if(!GetBuffer(m_PatchedlpStruct.dwOriginalBytesOffset, m_PatchedlpStruct.dwSizeOfBuff, m_PatchedlpStruct.dwSizeOfBuff))
		return iRetStatus;	

	// Replaced patched code with the original code
	if(!m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwAEPMapped, m_PatchedlpStruct.dwSizeOfBuff, m_PatchedlpStruct.dwSizeOfBuff))
		return iRetStatus;
						
	// Fill the bytes maintained by virus by zeros
	if(m_pMaxPEFile->FillWithZeros(m_PatchedlpStruct.dwOriginalBytesOffset, m_PatchedlpStruct.dwSizeOfBuff))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedJa
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Manjunath + Virus Analysis Team
	Description		: Detection routine for Trojan.Patched.JA
					  This function detects virus code in last section (or at AEP)	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedJa()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	BYTE bSig[] = {0x7C, 0x24, 0x08, 0x01, 0x75};
	
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL) &&
		((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000060) == 0xE0000060) &&
		(m_dwAEPMapped == m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData))
	{
		const int BUFF_SIZE	= 0x200;

		if(GetBuffer(m_dwAEPMapped, BUFF_SIZE, BUFF_SIZE))
		{
			for(int i = 0; i < 20; i++)
			{
				if(memcmp(&m_pbyBuff[i], &bSig[0], _countof(bSig)) == 0)
				{
					if(GetTrojanPatchedJaParam())
					{				
						// Infected AEP points to Last section RVA, because we are deleting last section 
						// added by virus AEP has to be inside last section RVA.
						if(m_dwOriginalAEP >= m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress) 
						{
							iRetStatus = VIRUS_FILE_DELETE;
						}
						else
						{
							iRetStatus = VIRUS_FILE_REPAIR;
						}						
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.ja"));
						m_eVirusDetected = TrojanPatchedJa;
						break;
					}
				}
			}
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetTrojanPatchedJaParam
	In Parameters	: 
	Out Parameters	: true if successfully found OAEP else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Finds the OAEP for Trojan.Patched.JA
--------------------------------------------------------------------------------------*/
bool CPolyTrojanPatched::GetTrojanPatchedJaParam()
{
	t_disasm da;
	DWORD	dwOffset = 0, dwLength; 
	BYTE	B1, B2, B3;

	int iInstFound = 0, iValidInst = 0;
	char szReg1[4]={0}, szReg2[4]={0}, szReg3[4]={0}, szReg4[4] = {0}, szTmpReg[4] = {0}, szJumReg[4] = {0};
	DWORD dwReg1 = 0, dwReg2 = 0;
	DWORD dwJmpOrCallValue = 0, dwBase = 0, dwOAEP = 0, dwReg3 = 0, dwReg4 = 0, dwValue = 0;
	char *ptr1, *ptr2;

	m_objMaxDisassem.InitializeData();

	m_dwInstCount = 0x00;

	while(dwOffset < m_dwNoOfBytes)
	{
		if(m_dwInstCount > 0x20)
			break;

		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = *((BYTE *)&m_pbyBuff[dwOffset]);
		B2 = *((BYTE *)&m_pbyBuff[dwOffset + 1]);
		B3 = *((BYTE *)&m_pbyBuff[dwOffset + 2]);
		
		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1 == 0xC1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffset += 0x03;
			continue;
		}
		if(B1 == 0xD1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffset += 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffset))
		{
			break;
		}

		if(dwLength == 0x01 && _strcmpi(da.dump, "FFFFFFC3")== 0)
		{
			dwOffset += dwLength;
			continue;
		}

		if(dwLength == 0x01 && B1 == 0xE2 && strstr(da.result, "???"))
		{
			dwOffset += 0x02;
			continue;
		}

		if(dwLength == 0x01 && B1 == 0x90 && strstr(da.result, "NOP")) //Skip NOP instructions
		{
			dwOffset += dwLength;
			continue;
		}

		m_dwInstCount++;

		if(!iInstFound && dwLength == 0x05 && B1 == 0x83 && B2 == 0x7C && strstr(da.result, "CMP DWORD PTR"))
		{
			dwOffset += dwLength;
			iInstFound++;
			continue;
		}//OR
		if(!iInstFound && dwLength == 0x05 && B1 == 0x80 && B2 == 0x7C && strstr(da.result, "CMP BYTE PTR"))
		{
			dwOffset += dwLength;
			iInstFound++;
			continue;
		}

		if(iInstFound==1 && dwLength == 0x02 && B1 == 0x75 && strstr(da.result, "JNZ SHORT")) //JNE SHORT
		{
			dwOffset += dwLength;
			dwJmpOrCallValue = B2;
			if((dwOffset + dwJmpOrCallValue) < m_dwNoOfBytes)
			{
				iInstFound++;
				dwOffset += dwJmpOrCallValue;
			}
			continue;
		}

		if(iInstFound==2 && dwLength == 0x06 && B1 == 0x0F && strstr(da.result, "J")) //JA JE etc
		{
			dwJmpOrCallValue = *(DWORD *)&m_pbyBuff[dwOffset + 2];
			dwOffset += dwLength;
			if((dwOffset + dwJmpOrCallValue) < m_dwNoOfBytes)
			{
				iInstFound++;
				dwOffset += dwJmpOrCallValue;
			}
			continue;
		}//OR
		if(iInstFound==2 && dwLength == 0x05 && B1 == 0xE9 && strstr(da.result, "JMP"))
		{
			dwJmpOrCallValue = *(DWORD *)&m_pbyBuff[dwOffset + 1];
			dwOffset += dwLength;
			if((dwOffset + dwJmpOrCallValue) < m_dwNoOfBytes)
			{
				iInstFound++;
				dwOffset += dwJmpOrCallValue;
			}
			if(NEGATIVE_JUMP(dwJmpOrCallValue))
			{
				if(((dwOffset + dwJmpOrCallValue + m_dwAEPUnmapped) < m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress) &&
					((dwOffset + dwJmpOrCallValue + m_dwAEPUnmapped) >= m_pSectionHeader[0].VirtualAddress))
				{
					dwOAEP = dwOffset + dwJmpOrCallValue + m_dwAEPUnmapped;
					break;
				}
			}
			continue;
		}

		if(iInstFound == 3 && dwLength == 0x05 && B1 == 0xE8 && strstr(da.result, "CALL"))
		{
			dwJmpOrCallValue = *(DWORD *)&m_pbyBuff[dwOffset + 1];
			dwOffset += dwLength;
			if(dwJmpOrCallValue > 0xFF)
				continue;
			if((dwOffset + dwJmpOrCallValue) < m_dwNoOfBytes)
			{
				iInstFound++;
				dwBase = dwOffset;
				dwOffset += dwJmpOrCallValue;
			}
			continue;
		}

		if(iInstFound != 4 && !dwBase) //Dont go further if desired value not found
		{
			dwOffset += dwLength;
			continue;
		}

		if(!iValidInst && dwLength == 0x01 && (B1 >= 0x58 && B1 <= 0x5F) && strstr(da.result, "POP E"))
		{
			dwOffset += dwLength;
			iValidInst++;
			strncpy_s(szReg1, 4, &da.result[4], 3);
			dwReg1 = dwBase;
			continue;
		}

		if(!dwReg3 && iValidInst==1 && dwLength == 0x06 && B1 == 0x8D && strstr(da.result, "LEA "))
		{
			dwReg3 = *(DWORD *)&m_pbyBuff[dwOffset + 2];
			strncpy_s(szReg3, 4, &da.result[4], 3);
			dwOffset += dwLength;
			continue;
		}
		if(dwReg3 && !dwReg4 && iValidInst==1 && dwLength == 0x06 && B1 == 0x8D && strstr(da.result, "LEA "))
		{
			dwReg4 = *(DWORD *)&m_pbyBuff[dwOffset + 2];
			strncpy_s(szReg4, 4, &da.result[4], 3);
			dwOffset += dwLength;
			continue;
		}
		if(dwReg3 && dwReg4 && dwLength == 2 && strstr(da.result, "SUB") && strstr(da.result, szReg3) && strstr(da.result, szReg4))
		{
			ptr1 = strstr(da.result, szReg3);
			ptr2 = strstr(da.result, szReg4);
			if(ptr1 > ptr2)
			{
				dwValue = dwReg4 - dwReg3;
				strcpy_s(szTmpReg, 4, szReg4);
			}
			else
			{
				dwValue = dwReg3 - dwReg4;
				strcpy_s(szTmpReg, 4, szReg3);
			}
			dwOffset += dwLength;
			continue;
		}

		if(iValidInst==1 && dwValue && dwLength == 0x03 && B1 == 0x8B && strstr(da.result, "MOV E") && 
			strstr(da.result,szTmpReg) && strstr(da.result,szReg1))
		{
			dwOffset += dwLength;
			
			if((dwBase + dwValue) < (m_dwNoOfBytes - 4))
			{
				strncpy_s(szReg2, 4, &da.result[4], 3);
				dwReg2 = *(DWORD *)&m_pbyBuff[dwBase + dwValue];
				iValidInst++;
			}
			continue;
		}//OR
		if(iValidInst==1 && !dwValue && dwLength == 0x03 && B1 == 0x8B && strstr(da.result, "MOV E") && strstr(da.result,szReg1))
		{
			dwOffset += dwLength;
			
			if((dwBase + B3) < (m_dwNoOfBytes - 4))
			{
				strncpy_s(szReg2, 4, &da.result[4], 3);
				dwReg2 = *(DWORD *)&m_pbyBuff[dwBase + B3];
				iValidInst++;
			}
			continue;
		}

		if(iValidInst != 2) //Dont go further if desired value not found
		{
			dwOffset += dwLength;
			continue;
		}
		
		if(!dwOAEP && dwLength<=0x03)
		{
			if((B1>=0x40 && B1<=0x47) && strstr(da.result, "INC") && strstr(da.result, szReg1))
			{
				dwOffset += dwLength;
				dwReg1++;
				continue;
			}

			if((B1>=0x48 && B1<=0x4F) && strstr(da.result, "DEC") && strstr(da.result, szReg1))
			{
				dwOffset += dwLength;
				dwReg1--;
				continue;
			}

			if((B1>=0x40 && B1<=0x47) && strstr(da.result, "INC") && strstr(da.result, szReg2))
			{
				dwOffset += dwLength;
				dwReg2++;
				continue;
			}

			if((B1>=0x48 && B1<=0x4F) && strstr(da.result, "DEC") && strstr(da.result, szReg2))
			{
				dwOffset += dwLength;
				dwReg2--;
				continue;
			}

			if(dwLength == 3 && B1 == 0x83 &&(B2>=0xC0 && B1<=0xC7) && strstr(da.result, "ADD") && strstr(da.result, szReg2))
			{
				dwOffset += dwLength;
				dwReg2 += (DWORD)B3;
				continue;
			}

			if(dwLength == 3 && B1 == 0x83 &&(B2>=0xC0 && B1<=0xC7) && strstr(da.result, "ADD") && strstr(da.result, szReg1))
			{
				dwOffset += dwLength;
				dwReg1 += (DWORD)B3;
				continue;
			}
		}

		if(!dwOAEP && dwReg1 && dwReg2 && szReg1[0] && szReg2[0])
		{
			if(iValidInst==2 && dwLength == 0x02 && B1 == 0x03 && strstr(da.result, "ADD") && strstr(da.result, szReg1) && strstr(da.result, szReg2))
			{
				dwOffset += dwLength;
				dwOAEP = dwReg1 + dwReg2 + m_dwAEPUnmapped;
				strncpy_s(szJumReg, 4, &da.result[4], 3);
				continue;
			}
		}

		if(dwOAEP && szJumReg[0])
		{
			if(dwLength == 3 && B1 == 0x83 && strstr(da.result, "ADD") && strstr(da.result, szJumReg))
			{
				dwOffset += dwLength;
				dwOAEP += (DWORD)B3;
				continue;
			}

			if(dwLength == 2 && B1 == 0xFF && strstr(da.result, "JMP") && strstr(da.result, szJumReg))
			{
				dwOffset += dwLength;
				break;
			}
		}

		if(dwLength == 0x01 && B1 == 0xC3 && strstr(da.result, "???"))
		{
			dwOffset += dwLength;
			break;
		}

		dwOffset += dwLength;
	}

	if(dwOAEP)
	{
		m_dwOriginalAEP = dwOAEP;
		return true;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedJa
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Manjunath + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.JA 
	                  This function repairs file by setting Original lAEP and 
					  removes last section added by virus.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedJa()
{
	m_pMaxPEFile->WriteAEP(m_dwOriginalAEP);
	m_pMaxPEFile->RemoveLastSections();
	return REPAIR_SUCCESS;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedLK
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for Trojan.Patched.LK
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedLK()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->m_stPEHeader.LoaderFlags == 0) 
	{	
		return iRetStatus;
	}
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.LoaderFlags, &m_dwDataAddr))
	{
		return iRetStatus;
	}
	
	DWORD iBufferSize = 0;
	if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[iBufferSize], m_dwAEPMapped, 0x05, 0x05))
	{
		return iRetStatus;
	}
	iBufferSize += 0x05;
	
	if((m_pbyBuff[0x0] != 0xE8) && (m_pbyBuff[0x0] != 0xE9))
	{
		return iRetStatus;
	}
	if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[iBufferSize], m_dwDataAddr, 0x20, 0x20))
	{
		return iRetStatus;
	}
	iBufferSize += 0x20;
	
	//Calculate call
	if((*(DWORD *)&m_pbyBuff[0x1] + m_dwAEPUnmapped + 0x5) == *(DWORD *)&m_pbyBuff[0x9])
	{
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[0x1] + m_dwAEPUnmapped + 0x5), &m_dwReplaceOffSet))
		{
			return iRetStatus;
		}
		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[iBufferSize], m_dwReplaceOffSet, 0x07, 0x07))
		{
			return iRetStatus;
		}
		iBufferSize += 0x07;
		if(m_pbyBuff[0x2A] == 0xff && m_pbyBuff[0x2B] == 0x15)
		{				
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(*(DWORD *)&m_pbyBuff[0x26] - m_dwImageBase, &m_dwDLLFileOffset))
			{
				return iRetStatus;
			}
			if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[iBufferSize], m_dwDLLFileOffset, 0x09, 0x09))
			{
				return iRetStatus;
			}
			iBufferSize += 0x09;
			const BYTE bySignature[]={0x00, 0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C};
			for(int i = 0x2C; i < 0x50; i++)
			{
				if((memcmp(&m_pbyBuff[i], bySignature, sizeof(bySignature)) == 0) )
				{
					m_eVirusDetected = TrojanPatchedLK;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.LK"));
					return VIRUS_FILE_REPAIR;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedLK
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for different varients of Dundun Family
					  This function repairs file by setting Original AEP Byte and 
					  replaced patched bytes into the section added by virus.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedLK()
{
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x19], m_dwReplaceOffSet + 0x7, 0x4, 0x4) &&	
		m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x1D], m_dwAEPMapped, 0x5, 0x5))
	{
		if(m_pMaxPEFile->FillWithZeros(m_pMaxPEFile->m_stPEOffsets.LoaderFlags, 0x04) && 
			m_pMaxPEFile->FillWithZeros(m_dwDataAddr, 0x20)&& m_pMaxPEFile->FillWithZeros(m_dwDLLFileOffset, 0x9))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedMK
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.MK
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedMK()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	DWORD iBufferSize = 0;
	if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[iBufferSize], m_dwAEPMapped, 0x0C, 0x0C))
	{
		return iRetStatus;
	}
	iBufferSize += 0x0C;
	
	if(m_pbyBuff[0x0]!=0x55 || *(DWORD *)&m_pbyBuff[0x01] != 0xEC83EC8B || *(WORD *)&m_pbyBuff[0x06] != 0x850F)
	{
		return iRetStatus;
	}
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[0x8] + m_dwAEPUnmapped + 0xC), &m_dwReplaceOffSet))
	{
		return iRetStatus;
	}
	m_dwDataAddr = m_dwReplaceOffSet + 0x5;
	if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[iBufferSize], m_dwReplaceOffSet, 0x05, 0x05))
	{
		return iRetStatus;
	}
	iBufferSize += 0x5;
	if(m_pbyBuff[0x0C] != 0xE9 && m_pbyBuff[0x0C] != 0xE8)
	{
		return iRetStatus;
	}
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[0xD] + *(DWORD *)&m_pbyBuff[0x8] + m_dwAEPUnmapped + 0x11), &m_dwReplaceOffSet))
	{
		return iRetStatus;
	}
	if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[iBufferSize], m_dwReplaceOffSet, 0x20, 0x20))
	{
		return iRetStatus;
	}
	iBufferSize += 0x20;
	
	DWORD	dwLength = 0, dwOffset = 0x11; 
	BYTE	byDecKey = 0;
	t_disasm da = {0};
	m_dwInstCount = 0;

	while(dwOffset < 0x31)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			

		if(m_dwInstCount == 0x0 && dwLength == 1 && strstr(da.result, "POP") )
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount = 0x01 && dwLength == 5 && strstr(da.result, "MOV EAX"))
		{
			m_dwInstCount++;
			byDecKey = LOBYTE(da.immconst);
		}
		else if(m_dwInstCount = 0x02 && dwLength ==  5 && strstr(da.result, "MOV ECX") )
		{
			m_dwInstCount++;
			
		}
		else if(m_dwInstCount = 0x03 && dwLength ==  2 && strstr(da.result, "XOR [E") )
		{
			if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[iBufferSize], m_dwDataAddr, 0x9, 0x9))
			{
				iBufferSize += 0x9;
			}
			for(DWORD i = 0x31; i < 0x3A; i++)
			{
				m_pbyBuff[i] ^=  byDecKey;
				byDecKey -= 1;
			}
			m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[0x36];

			m_eVirusDetected = TrojanPatchedMK;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.MK"));
			return VIRUS_FILE_REPAIR;
		}
		dwOffset += dwLength;
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedMK
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.MK
					  This function repairs file by setting Original AEP and 
					  removed patched bytes into the last section added by virus.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedMK()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x0C) && 
			m_pMaxPEFile->FillWithZeros(m_pMaxPEFile->m_stPEOffsets.Checksum, 0x4))
		{
			if( m_pMaxPEFile->TruncateFile(m_dwReplaceOffSet))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedEH
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.EH
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedEH()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
	m_pbyBuff = new BYTE[PATCHED_EH_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(m_pbyBuff == NULL)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, PATCHED_EH_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(!GetBuffer(m_dwAEPMapped, PATCHED_EH_BUFF_SIZE, PATCHED_EH_BUFF_SIZE))
	{
		return iRetStatus;
	}

	DWORD	dwLength = 0, dwOffset = 0;
	t_disasm da = {0};
	m_dwInstCount = 0;

	while(dwOffset < PATCHED_EH_BUFF_SIZE - 5)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
		if(dwLength > PATCHED_EH_BUFF_SIZE - dwOffset)
		{
			break;
		}
		if(dwLength == 0x5 && strstr(da.result, "JMP") )
		{  
			m_dwJumpFrom = m_dwAEPMapped + dwOffset + 0x6;
			m_dwDataAddr = m_dwReplaceOffSet = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] + m_dwAEPUnmapped + dwOffset  + 0x5;
			if(GetTrojanPatchedEHParam())
			{
				return VIRUS_FILE_REPAIR;
			}
		}
		dwOffset += dwLength;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedEH
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Collected required info for : Trojan.Patched.EH
--------------------------------------------------------------------------------------*/
bool CPolyTrojanPatched::GetTrojanPatchedEHParam()
{ 	
	WORD wSec = m_pMaxPEFile->Rva2FileOffset(m_dwReplaceOffSet, &m_dwReplaceOffSet);
	if(OUT_OF_FILE == wSec)
	{
		return false;
	}
	m_dwNoOfbyteToRead = m_pSectionHeader[wSec].PointerToRawData + m_pSectionHeader[wSec].SizeOfRawData - m_dwReplaceOffSet; 
	if(m_dwNoOfbyteToRead > PATCHED_EH_BUFF_SIZE - 5)
	{
		return false;
	}
	BYTE byBuff[PATCHED_EH_BUFF_SIZE] = {0};
	if(!m_pMaxPEFile->ReadBuffer(byBuff, m_dwReplaceOffSet, 0x05, 0x05))
	{
		return false;
	}
	DWORD dwCallAddress=0;	
	if(byBuff[0x00] == 0xE9 || byBuff[0x00] == 0xE8)
	{
		dwCallAddress = *(DWORD *)&byBuff[0x1] + m_dwDataAddr + 0x5;
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwCallAddress, &m_dwDataAddr))
		{
			return false;
		}
		if(!m_pMaxPEFile->ReadBuffer(byBuff, m_dwDataAddr, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{
			return false;
		}
	}
	else if(byBuff[0x00] == 0x60 || (byBuff[0x00] == 0x8B && byBuff[0x01] == 0xC0 && byBuff[0x02] == 0x60))
	{
		if(!m_pMaxPEFile->ReadBuffer(byBuff, m_dwReplaceOffSet, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{
			return false;
		}
	}
	else
	{
		return false;
	}

	DWORD	dwLength = 0,dwOffset = 0;
	t_disasm da = {0};
	m_dwInstCount = 0;

	while(dwOffset < m_dwNoOfbyteToRead && m_dwInstCount <= 0xF)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&byBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			

		if(m_dwInstCount==0x00 && dwLength ==  1 && strstr(da.result,"PUSHAD") )
		{
			m_dwInstCount++;
		}		
		else if(m_dwInstCount==0x01 && dwLength ==5 && strstr(da.result,"PUSH"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x02 && dwLength ==3 && strstr(da.result,"XOR [E"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x03 && dwLength ==5 && strstr(da.result,"PUSH"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x04 && dwLength ==3 && strstr(da.result,"XOR [E"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x05 && dwLength ==1 && strstr(da.result,"PUSH ESP"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x06 && dwLength ==2 && strstr(da.result,"CALL") )
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x07 && dwLength ==  1 && strstr(da.result,"POP") )
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x08 && dwLength ==  1 && strstr(da.result,"POP") )
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x09 && dwLength ==1 && strstr(da.result,"POPAD"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x0A && dwLength ==5 && strstr(da.result,"CALL"))
		{   
			dwCallAddress=da.immconst + m_dwDataAddr + dwOffset + 0x5;
			m_dwInstCount++;
		}
		else if((m_dwInstCount==0x0B ||m_dwInstCount==0x0A) && dwLength ==1 && strstr(da.result,"POP"))
		{ 
			m_dwInstCount++;
		}
		else if((m_dwInstCount==0x0C ||m_dwInstCount==0x0B) && (dwLength == 5 ||dwLength == 6) && strstr(da.result,"ADD") )
		{
			m_dwInstCount++;
			m_dwOriData = da.immconst;
		}
		else if((m_dwInstCount==0x0D ||m_dwInstCount==0x0C) && dwLength ==  2 && strstr(da.result,"MOV") )
		{
			m_dwInstCount++;
		}
		else if((m_dwInstCount==0xE ||m_dwInstCount==0x0D)&& dwLength ==  2 && strstr(da.result,"CALL") )
		{
			m_dwInstCount++;
		}
		else if((m_dwInstCount == 0xF ||m_dwInstCount == 0xE)&& dwLength ==  5 && strstr(da.result,"JMP") )
		{       
			m_dwNoOfbyteToRead = dwOffset + dwLength + 0x5;
			m_dwOriData += dwCallAddress + m_dwImageBase;
			if(m_dwInstCount == 0x0E)
			{
				DWORD dwCallOffset = 0;
				m_pMaxPEFile->Rva2FileOffset(dwCallAddress + *(DWORD *)&byBuff[dwOffset + 0x1] + dwOffset + dwLength, &dwCallOffset);
				if(m_dwJumpFrom != dwCallOffset)
				{
					return false;
				}
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.EH"));
			}
			else if(m_dwInstCount == 0x0F)
			{				
				DWORD dwCallOffset = 0;
				m_pMaxPEFile->Rva2FileOffset(m_dwDataAddr + *(DWORD *)&byBuff[dwOffset+0x1]+ dwOffset + dwLength , &dwCallOffset);
				if(m_dwJumpFrom != dwCallOffset)
				{
					return false;
				}
				m_dwDataAddr = m_dwReplaceOffSet;
				if(byBuff[0x00] == 0x60)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.FH"));
				}
				else
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.EK"));
				}
			}
			m_eVirusDetected = TrojanPatchedEH;				
			return true;
		}
		dwOffset += dwLength;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedEH
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.EH
					  This function repairs file patched bytes on Kernal32.dll API 
					  DesibleThreadLibraryCalls call and remove jump address in 
					  any section added by virus.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedEH()
{
	WORD wData = 0x15ff;
	
	if(m_pMaxPEFile->WriteBuffer(&m_dwOriData, m_dwJumpFrom - 0x4, 0x4, 0x4) &&	
		m_pMaxPEFile->WriteBuffer(&wData, m_dwJumpFrom - 0x6, 0x02, 0x02))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwReplaceOffSet, 0x05) && 
			m_pMaxPEFile->FillWithZeros(m_dwDataAddr, m_dwNoOfbyteToRead - 0x5))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedGO
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.GO
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedGO()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wAEPSec == 0) && 
		(m_pMaxPEFile->m_stPEHeader.Subsystem == 0x02) && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL))
	{	
		int PATCHED_GO_BUFF_SIZE = 0x500;
		
		DWORD dwEndOfAEPSec = m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData;
		if(dwEndOfAEPSec > m_dwAEPMapped && dwEndOfAEPSec - m_dwAEPMapped <= 0x500) 
		{
			PATCHED_GO_BUFF_SIZE = dwEndOfAEPSec - m_dwAEPMapped;
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PATCHED_GO_BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped, PATCHED_GO_BUFF_SIZE, PATCHED_GO_BUFF_SIZE))
		{
			//Check for Virus.Patched.Go  
			const BYTE bySignature[] = {0x83,0x7C,0x24,0x08,0x01,0x75,0x19,0x6A,0x00,0x6A,0x00,0x68,0xBC,0x6C,0x90,0x7C,0x68,0x77,0x1D,0x80,0x7C,0x6A,0x00,0x6A,0x00,0xB8,0x2F,0x08,0x81,0x7C,0xFF,0xD0,0xE9};
			for(int i = 0; i < PATCHED_GO_BUFF_SIZE - 25; i++)
			{
				if(memcmp(&m_pbyBuff[i], bySignature, sizeof(bySignature)) == 0)
				{    
					if(i == 0)
					{
						m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[0x21] + m_dwAEPUnmapped + 0x25;
						if(m_dwOriginalAEP < m_pMaxPEFile->m_stPEHeader.SizeOfImage)
						{
							m_eVirusDetected = TrojanPatchedGO;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.GO"));
							return VIRUS_FILE_REPAIR;
						}
					}
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.HS"));
					return VIRUS_FILE_DELETE;
				}
			}			
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedGO
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.GO
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedGO()
{  	
	BYTE byBuffer[]={0x8D,0x54,0x24,0x04,0xE8,0x38,0x36,0x00,0x00,0x52,0x9B,0xD9,0x3C,0x24,0x74,0x54,
		0x66,0x81,0x3C,0x24,0x7F,0x02,0x74,0x06,0xD9,0x2D,0xF8,0x4B,0xC0,0x77,0xD9,0xF2,0x9B,0xDF,0xE0,0x9E,0x7A};
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{			
		if(m_pMaxPEFile->WriteBuffer(byBuffer, m_dwAEPMapped, 0x25, 0x25))
		{	
			return REPAIR_SUCCESS;
		}		   
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedJI
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Rushikesh + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.JI
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedJI()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wAEPSec == m_wNoOfSections - 1 ) &&
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xC0000040) == 0xC0000040) && 
		(m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData <= 0x1000) &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL) && 
		 (m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress == 0x0))               // contraint added to skip samples of Virus.Win32.Redart.2796
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PATCHED_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, PATCHED_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(!GetBuffer(m_dwAEPMapped, PATCHED_BUFF_SIZE, PATCHED_BUFF_SIZE))
		{
			return iRetStatus;	
		}
		if(m_pbyBuff[0] != 0x60 && m_pbyBuff[0] != 0x55)
		{
			return iRetStatus;		
		}
		const BYTE bySig1[] = {0xE8, 0x00, 0x00, 0x00, 0x00};
		const BYTE bySig2[] = {0x81, 0xED};
		DWORD dwValEBP = 0, dwStart = 0;
		
		for(int i = 0; i < PATCHED_BUFF_SIZE - sizeof(bySig1); i++)
		{
			if(memcmp(&m_pbyBuff[i], bySig1, sizeof(bySig1)) == 0)
			{
				dwValEBP = i + 5 + m_dwAEPUnmapped + m_dwImageBase;
				for(int j = i; j < PATCHED_BUFF_SIZE - sizeof(bySig2); j++)
				{
					if(memcmp(&m_pbyBuff[j], bySig2 , sizeof(bySig2)) == 0)
					{
						dwStart = j;
						break;				
					}
				}
				break;
			}
		}
		if(dwStart == 0)
		{
			return iRetStatus;
		}

		t_disasm da = {0x00};
		DWORD dwValOfAEP = 0, dwNxtVal = 0, dwValECX = 0, dwValEDX = 0;
		while(dwStart < PATCHED_BUFF_SIZE)
		{
			DWORD dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwStart], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwLength > (PATCHED_BUFF_SIZE - dwStart))
			{
				return iRetStatus;
			}
			if(dwLength == 0x06 && strstr(da.result, "SUB EBP"))
			{
				dwValEBP -= da.immconst;
			}
			if((dwLength == 0x06 && strstr(da.result, "MOV E")) ||
				(dwLength == 0x06 && strstr(da.result, "ADD E")) ||
				(dwLength == 0x04 && strstr(da.result, "MOV [")) ||
				(dwLength == 0x02 && strstr(da.result, "XOR E")) ||
				(dwLength == 0x03 && strstr(da.result, "SUB E")) || 
				(dwLength == 0x05 && strstr(da.result, "CALL ")))
			{
				if((dwLength == 6) && (strstr(da.result, "MOV ECX")))
				{
					m_pMaxPEFile->Rva2FileOffset(dwValEBP + da.adrconst - m_dwImageBase , &dwNxtVal);
					m_pMaxPEFile->ReadBuffer(&dwValECX, dwNxtVal, 4, 4);
				}
				else if((dwLength == 6) && (strstr(da.result, "MOV EDX")))
				{
					m_pMaxPEFile->Rva2FileOffset(dwValEBP + da.adrconst - m_dwImageBase , &dwNxtVal);
					m_pMaxPEFile->ReadBuffer(&dwValEDX, dwNxtVal, 4, 4);
				}
				else if((dwLength == 2) && (strstr(da.result, "XOR E")))
				{
					dwValOfAEP += dwValECX ^ dwValEDX;					
				}
				else if(dwLength == 0x03 && strstr(da.result, "SUB E"))
				{
					dwValOfAEP -=da.immconst;
				}
				else if((da.adrconst != 0) && (dwLength == 6))
				{
					m_pMaxPEFile->Rva2FileOffset(dwValEBP + da.adrconst - m_dwImageBase , &dwNxtVal);
					m_pMaxPEFile->ReadBuffer(&dwNxtVal, dwNxtVal, 4, 4);
					dwValOfAEP += dwNxtVal;
				}
				else if((dwLength == 4) || (dwLength == 5))
				{
					break;
				}
			}
			dwStart += dwLength;
		}
		m_dwOriginalAEP = dwValOfAEP - m_dwImageBase;			
		if(m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL) != m_wNoOfSections - 1)
		{
			m_eVirusDetected = TrojanPatchedJI;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.JI"));
			return VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedJI
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Rushikesh + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.JI
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedJI()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if( m_pMaxPEFile->RemoveLastSections())
		{
			return REPAIR_SUCCESS;	
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedDR
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.DR + Trojan.Patched.QQ
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedDR()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wAEPSec == 0) && 
		((m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0xA)||
		(m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x0))&&
		((m_pMaxPEFile->m_stPEHeader.MinorOSVersion == 0x1)||
		(m_pMaxPEFile->m_stPEHeader.MinorOSVersion == 0x0))&&
		(m_pMaxPEFile->m_stPEHeader.MinorSubsystemVersion == 0x0)&&
		(m_pMaxPEFile->m_stPEHeader.Subsystem == 0x02) && 
		(m_pMaxPEFile->m_stPEHeader.NumberOfSections ==0x4)&&
		((m_pMaxPEFile->m_stPEHeader.Characteristics ==0x210E)
		||(m_pMaxPEFile->m_stPEHeader.Characteristics ==0x2102))&&
		(m_pSectionHeader[0].Characteristics == 0x60000020)&&
		(m_pSectionHeader[1].Characteristics == 0xC0000040)&&
		(m_pSectionHeader[2].Characteristics == 0x40000040)&&
		(m_pSectionHeader[3].Characteristics == 0x42000040))
	{	         
		int PATCHED_DR_BUFF_SIZE = 0x45;
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PATCHED_DR_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, PATCHED_DR_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, PATCHED_DR_BUFF_SIZE, PATCHED_DR_BUFF_SIZE))
		{   
			const BYTE bySignature[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x83,0x7D,0x0C,0x01,0x75,0x05,0xE8,0x5D,0x07,0x00,0x00,
				0x5D,0x90,0x90,0x90,0x90,0x90,0x8B,0xFF,0x55,0x8B,0xEC,0x81,0xEC,0x6C,0x05,0x00,0x00,0xA1};
			const BYTE bySignature_1[] = {0x55,0x8b,0xec,0x81,0xec,0x60,0x05,0x00,0x00,0x53,0x56,0x33,0xf6,0x46,0x39,0x75,0x0c,0x57,0x0f,0x85,0x0c,0x02,0x00,0x00,0xc7,0x45,0xfc,0x24,0x01,0x00,0x00,0x64,0xa1,0x18,0x00,0x00,0x00,0x8b,0x40,0x30,0x8b,0x80,0xd4,0x01};
			if((memcmp(&m_pbyBuff[0], bySignature, sizeof(bySignature)) == 0)
				||(memcmp(&m_pbyBuff[0], bySignature_1, sizeof(bySignature_1)) == 0))
			{ 				
				if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0], 0x2038, 0x17, 0x17))
				{
					return iRetStatus;
				}

				if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x17], 0x2048, 0x17, 0x17))
				{
					return iRetStatus;
				}
				if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x2E], 0x2110, 0x17, 0x17))
				{
					return iRetStatus;
				}

				//Check for clean file
				const BYTE byCheckSig[] = {0x41,0x00,0x70,0x00,0x70,0x00,0x49,0x00,0x6E,0x00,0x69,0x00,0x74,
					0x00,0x5F,0x00,0x44,0x00,0x4C,0x00,0x4C,0x00,0x73};
				if((memcmp(&m_pbyBuff[0x0], byCheckSig, sizeof(byCheckSig)) == 0) ||
					(memcmp(&m_pbyBuff[0x17], byCheckSig, sizeof(byCheckSig)) == 0)||
					(memcmp(&m_pbyBuff[0x2E], byCheckSig, sizeof(byCheckSig)) == 0))
				{
					return iRetStatus;
				}

				//Check for Virus.Patched.DR 
				const BYTE bySignature1[] = {0x70,0x00,0x49,0x00,0x6E,0x00,0x69,0x00,0x74,0x00,0x5F,0x00,0x44,0x00,0x4C,0x00,0x4C,0x00,0x73};
				//Check for Virus.Patched.GQ
				const BYTE bySignatureGq[] = {0x41,0x00,0x70,0x00,0x70,0x00,0x69,0x00,0x6E,0x00,0x68,0x00,0x74,0x00,0x5F,0x00,0x44,0x00,0x4C,0x00,0x4C,0x00,0x73};
				if((memcmp(&m_pbyBuff[0x4], bySignature1, sizeof(bySignature1)) == 0) ||
					(memcmp(&m_pbyBuff[0x1B], bySignature1, sizeof(bySignature1)) == 0)||
					(memcmp(&m_pbyBuff[0x2E], bySignatureGq, sizeof(bySignatureGq)) == 0))
				{ 
					m_dwDataAddr = 0x2048;
					if(memcmp(&m_pbyBuff[0x4], bySignature1, sizeof(bySignature1)) == 0 )
					{
						m_dwDataAddr = 0x2038;
					}
					if(memcmp(&m_pbyBuff[0x2E], bySignatureGq, sizeof(bySignatureGq)) == 0 )
					{
						m_dwDataAddr = 0x2110;
					}
					m_eVirusDetected = TrojanPatchedDR;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.DR"));
					return VIRUS_FILE_REPAIR;
				}
				else 
				{
					//Check for Virus.Patched.QQ & others  
					int counter = 0, i = 0;
					while((i <= 0x45) && (counter < 0x14))
					{
						counter = 0;
						for (int j = 0; j < 0x17; j++)
						{
							if(m_pbyBuff[j + i] == byCheckSig[j])
							{
								counter++;
							}
						}
						i += 0x17;
					}
					if(counter >= 0x14 )
					{ 
						m_dwDataAddr = 0x2048;
						if(i == 0x17)
						{
							m_dwDataAddr = 0x2038;
						}
						m_eVirusDetected = TrojanPatchedDR;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.QQ"));
						return VIRUS_FILE_REPAIR;
					}
				}
			}

			
			//Check for Virus.Patched.HQ
			else 
			{
				DWORD	dwLength = 0, dwOffset = 0, dwInstCount = 0;
				t_disasm da = {0};

				while(dwOffset < m_dwNoOfBytes && dwInstCount < 0xD)
				{
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			
					if(dwLength > m_dwNoOfBytes - dwOffset)
					{
						break;
					}

					if(dwInstCount == 0x00 && dwLength == 4 && strstr(da.result,"MOV EAX"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x01 && dwLength == 2 && strstr(da.result,"MOV EDI,EDI"))
					{  
						dwInstCount++;
					}
					else if(dwInstCount == 0x02 && dwLength == 1 && strstr(da.result,"DEC EAX"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x03 && dwLength == 2 && strstr(da.result,"JNZ"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x04 && dwLength == 1 && strstr(da.result,"PUSH EAX"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x05 && dwLength == 1 && strstr(da.result,"PUSH EAX"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x06 && dwLength == 5 && strstr(da.result,"PUSH"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x07 && dwLength == 5 && strstr(da.result,"PUSH"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x08 && dwLength == 1 && strstr(da.result,"PUSH EAX"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x09 && dwLength == 1 && strstr(da.result,"PUSH EAX"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x0A && dwLength == 5 && strstr(da.result,"MOV EAX"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x0B && dwLength == 2 && strstr(da.result,"CALL EAX"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x0C && dwLength == 5 && strstr(da.result,"JMP"))
					{
						dwInstCount++;
						m_dwOriginalAEP = (*(DWORD *)&m_pbyBuff[dwOffset+1] + m_dwAEPUnmapped + 0x23 );
						if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, 0))
						{
							return iRetStatus;
						}

						if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0], 0x2D7E8, 0x23, 0x23))
						{
							m_dwDataAddr = 0x0;
							m_eVirusDetected = TrojanPatchedDR;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.HQ"));
							return VIRUS_FILE_REPAIR;
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
	Function		: CleanTrojanPatchedDR
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.DR + Trojan.Patched.QQ
					  This function repairs file patched bytes on the API 
					  APPINIT_DLL(For Regedit),Replace with the original data.	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedDR()
{  	
	BYTE byBuffer[]={0x41,0x00,0x70,0x00,0x70,0x00,0x49,0x00,0x6E,0x00,0x69,0x00,0x74,0x00,0x5F,0x00,0x44,0x00,0x4C,0x00,0x4C,0x00,0x73};

	if(m_dwDataAddr == 0)
	{
		if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
		{
			m_pMaxPEFile->RepairOptionalHeader(0x16, 0, 0);
			if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x0], m_dwAEPMapped, 0x23, 0x23))
			{					
				if(m_pSectionHeader[0x3].PointerToRawData + m_pSectionHeader[0x3].SizeOfRawData == m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].VirtualAddress &&
					m_pMaxPEFile->m_dwFileSize == m_pMaxPEFile->m_stPEHeader.DataDirectory[0x4].VirtualAddress)
				{
					m_pMaxPEFile->FillWithZeros(m_pMaxPEFile->m_stPEOffsets.NoOfDataDirs + 0x24, 0x8);
				}
				return REPAIR_SUCCESS;
			}
		}
	}
	else if(m_pMaxPEFile->WriteBuffer(byBuffer, m_dwDataAddr, sizeof(byBuffer), sizeof(byBuffer)))
	{	
		return REPAIR_SUCCESS;
	}		   

	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedBZ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.BZ
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedBZ()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[PATCH_BZ_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, PATCH_BZ_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(!(GetBuffer(m_dwAEPMapped, PATCH_BZ_BUFF_SIZE, PATCH_BZ_BUFF_SIZE )))
	{
		return iRetStatus;	
	}
	if(m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0x68 &&	m_pbyBuff[6] == 0xFF &&	m_pbyBuff[7] == 0x15 && m_pbyBuff[0xD] == 0xE9)
	{
		BYTE bySig1[] = {0x75, 0x73, 0x65, 0x72 ,0x73, 0x36, 0x34, 0x2E, 0x64, 0x61, 0x74};		//users64.dat
		BYTE bySig2[] = {0x75, 0x73, 0x65, 0x72, 0x73, 0x33, 0x32, 0x2E, 0x64, 0x61, 0x74};		//users32.dat
		BYTE bySig3[] = {0x68,0x6F,0x74,0x64,0x6F,0x67,0x2E,0x64,0x6C,0x6C};					//hotdog.dll
		BYTE bySig4[] = {0x64,0x75,0x72,0x6E,0x65,0x77,0x33,0x32,0x2E,0x64,0x61,0x74};			//durnew32.dat
		BYTE bySig5[] = {0x70, 0x72, 0x65, 0x74, 0x65, 0x63, 0x2E, 0x64, 0x61, 0x74};  			//pretec.dat
		
		for(DWORD dwOffset = 0; dwOffset < (PATCH_BZ_BUFF_SIZE - sizeof(bySig1)); dwOffset++)
		{
			if((memcmp(&m_pbyBuff[dwOffset], bySig1, sizeof(bySig1)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig2, sizeof(bySig2)) == 0) || 
				(memcmp(&m_pbyBuff[dwOffset], bySig3, sizeof(bySig3)) == 0) || (memcmp(&m_pbyBuff[dwOffset], bySig4, sizeof(bySig4)) == 0) ||
				(memcmp(&m_pbyBuff[dwOffset], bySig5, sizeof(bySig5)) == 0))
			{			
				m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[0xE] + m_dwAEPUnmapped + 0x0D + 5;
				if(m_dwOriginalAEP < m_pMaxPEFile->m_stPEHeader.SizeOfImage)
				{
					m_eVirusDetected = TrojanPatchedBZ;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.BZ"));
					return VIRUS_FILE_REPAIR;
				}
			}
		}
	}
	else if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL) && (m_wAEPSec == 0))
	{
		BYTE bySig1[] = {0xE9};
		DWORD dwFileRVA = 0, dwSecNo = 100, dwRVAOfJump = 0;
		for(DWORD dwOffset = 0; dwOffset < (PATCH_BZ_BUFF_SIZE - sizeof(bySig1)); dwOffset++)
		{
			if((memcmp(&m_pbyBuff[dwOffset], bySig1, sizeof(bySig1)) == 0))
			{
				dwFileRVA = *(DWORD *)&m_pbyBuff[dwOffset + 1] + m_dwAEPUnmapped + dwOffset + 5;
				dwRVAOfJump = m_dwAEPUnmapped + dwOffset;
				m_pMaxPEFile->Rva2FileOffset(dwRVAOfJump , &m_dwJumpFrom);  //jump offset(Offset of E9)
				dwSecNo = m_pMaxPEFile->Rva2FileOffset(dwFileRVA , &m_dwPatched_KZ_Offset); // jump address;
				break;
			}
		}		
		if(dwSecNo != m_wAEPSec)
		{
			return iRetStatus;			
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PATCH_KZ_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, PATCH_KZ_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(!(GetBuffer(m_dwPatched_KZ_Offset, PATCH_KZ_BUFF_SIZE, PATCH_KZ_BUFF_SIZE )))
		{
			return iRetStatus;	
		}
		if(m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0x9C &&	m_pbyBuff[19] == 0xFF && m_pbyBuff[20] == 0x10 && m_pbyBuff[23] == 0xE9)
		{
			BYTE bySig[] = {0x3A, 0x5C, 0x72, 0x65, 0x6C, 0x65, 0x61, 0x73, 0x65, 0x5C, 0x33, 0x36, 0x30};	//	:\release\360mon.dll
			for(DWORD dwOffset = 0; dwOffset < (PATCH_KZ_BUFF_SIZE - sizeof(bySig)); dwOffset++)
			{
				if(m_pbyBuff[dwOffset] == 0xE9)
				{
					DWORD dwRVA2 = *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwFileRVA + dwOffset + 5;
					m_dwPatched_KZ_DWORD = dwRVA2 - dwRVAOfJump - 5;
				}
				else if((memcmp(&m_pbyBuff[dwOffset], bySig, sizeof(bySig)) == 0))
				{
					iRetStatus = VIRUS_FILE_REPAIR;
					m_eVirusDetected = TrojanPatchedBZ;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.KZ"));
					return iRetStatus;
					break;
				}
			}
			return iRetStatus;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedBZ
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.BZ
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedBZ()
{
	if(m_dwOriginalAEP != 0)
	{
		if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
		{
			m_pMaxPEFile->FillWithZeros(m_dwAEPMapped,PATCH_BZ_BUFF_SIZE);
			return REPAIR_SUCCESS;		
		}
	}
	else 
	{
		m_pMaxPEFile->WriteBuffer(&m_dwPatched_KZ_DWORD,m_dwJumpFrom + 1,4,4);
		m_pMaxPEFile->FillWithZeros(m_dwPatched_KZ_Offset,PATCH_KZ_BUFF_SIZE);
		return REPAIR_SUCCESS;		
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedJ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.J 
	                  This function use for dectection with find the original AEP inside  virus code.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedJ()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->m_stPEHeader.Subsystem == 0x02 && (m_pSectionHeader[m_wAEPSec].Characteristics == 0x60000020))
	{	         
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int PATCHED_J_BUFF_SIZE = 0x30;
		m_pbyBuff = new BYTE[PATCHED_J_BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped, PATCHED_J_BUFF_SIZE, PATCHED_J_BUFF_SIZE))
		{
			const BYTE bySignature[] = {0x6d,0x73,0x76,0x63,0x72,0x6c,0x2e,0x64,0x6c,0x6c,0x00,0xff,0x15};
			for(int i = 0; i < PATCHED_J_BUFF_SIZE - sizeof(bySignature); i++)
			{
				if(memcmp(&m_pbyBuff[i], bySignature, sizeof(bySignature)) == 0)
				{  	
					DWORD	dwLength = 0, dwOffset = 0, dwInstCount = 0;
					t_disasm da = {0};

					while(dwOffset <= 0x30 && dwInstCount < 0x5)
					{
						dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			
						if(dwInstCount==0x00 && dwLength ==1 && strstr(da.result,"PUSHAD"))
						{
							dwInstCount++;
						}
						else if(dwInstCount==0x01 && dwLength ==5 && strstr(da.result,"CALL"))
						{  
							dwInstCount++;
						}
						else if(dwInstCount==0x02 && dwLength ==1 && strstr(da.result,"INS DWORD"))
						{
							dwInstCount++;
						}
						else if(dwInstCount==0x03 && dwLength ==1 && strstr(da.result,"POPAD"))
						{
							dwInstCount++;
						}
						else if(dwInstCount==0x04 && dwLength ==5 && strstr(da.result,"JMP"))
						{
							dwInstCount++;
							m_dwNoOfbyteToRead = dwOffset + dwLength;
							m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] + m_dwAEPUnmapped + m_dwNoOfbyteToRead;
							m_eVirusDetected = TrojanPatchedJ;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.J"));
							return VIRUS_FILE_REPAIR;
						}
						dwOffset += dwLength;
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedJ
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.J
	                  This function delete patched bytes and repair original AEP  
					  also patched Bytes FillWithZeros .
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedJ()
{  	
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{ 
		if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, m_dwNoOfbyteToRead))
		{
			if(m_pMaxPEFile->RepairOptionalHeader(0x16, 0, 0))
			{
				return REPAIR_SUCCESS;
			}	
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedJH
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.JH
					  This function use for dectection with find the original AEP inside virus code.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedJH()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	m_dwNoOfbyteToRead = m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - m_dwAEPMapped;
	if(m_dwNoOfbyteToRead > 0x10000 || m_dwNoOfbyteToRead < 0x10)
	{
		return iRetStatus;
	}
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[m_dwNoOfbyteToRead];
	if(m_pbyBuff == NULL)
	{
		return iRetStatus;
	}

	if(!GetBuffer(m_dwAEPMapped, 0xD, 0xD))
	{
		return iRetStatus;
	}

	if(m_pbyBuff[0x00] == 0x60 && m_pbyBuff[0x01] == 0x9C && m_pbyBuff[0x02] == 0x68 && m_pbyBuff[0x07] == 0x68 && m_pbyBuff[0x0C] == 0x68 )
	{		
		if(!GetBuffer(m_dwAEPMapped, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{
			return iRetStatus;
		}
		DWORD	dwLength = 0, dwOffset = 0;
		t_disasm da = {0};
		m_dwInstCount = 0;
		while(dwOffset < m_dwNoOfbyteToRead && m_dwInstCount < 0x15)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   

			if(m_dwInstCount==0x00 && dwLength ==1 && strstr(da.result,"PUSHAD"))
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x01 && dwLength ==1 && strstr(da.result,"PUSHFD"))
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x02 && dwLength ==5 && strstr(da.result,"PUSH"))
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x03 && dwLength ==5 && strstr(da.result,"PUSH"))
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x04 && dwLength == 5 && strstr(da.result,"PUSH") )
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x05 && dwLength == 1 && strstr(da.result,"PUSH") )
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x06 && dwLength ==5 && strstr(da.result,"MOV EAX"))
			{  				
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x07 && dwLength ==2 && strstr(da.result,"CALL EAX"))
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x08 && dwLength ==3 && strstr(da.result,"ADD ESP"))
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x09 && dwLength ==2 && strstr(da.result,"XOR EAX,EAX"))
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x0A && dwLength == 1 && strstr(da.result,"PUSH") )
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x0B && dwLength == 5 && strstr(da.result,"PUSH") )
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x0C && dwLength == 5 && strstr(da.result,"PUSH") )
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x0D && dwLength == 5 && strstr(da.result,"PUSH") )
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x0E && dwLength == 1 && strstr(da.result,"PUSH") )
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x0F && dwLength == 5 && strstr(da.result,"MOV EAX") )
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x10 && dwLength ==3 && strstr(da.result,"ADD ESP"))
			{  				
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x11 && dwLength == 1 && strstr(da.result,"POPFD") )
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x12 && dwLength == 1 && strstr(da.result,"POPAD") )
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x13 && dwLength == 5 && strstr(da.result,"MOV EAX"))
			{  		
				m_dwOriginalAEP = da.immconst - m_dwImageBase;
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x14 && dwLength == 1 && strstr(da.result,"PUSH EAX") )
			{
				m_dwInstCount++;

				m_eVirusDetected = TrojanPatchedJH;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.JH"));
				return VIRUS_FILE_REPAIR;
			}
			dwOffset += dwLength;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedJH
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.JH
					  This function repairs file patched bytes on Kernal32.dll API 
					  DesibleThreadLibraryCalls call and remove jump address in 
					  any section added by virus.	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedJH()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{ 	
		if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, m_dwNoOfbyteToRead) && m_pMaxPEFile->RepairOptionalHeader(0x16, 0, 0))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedHL
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.HL
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedHL()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int PATCHED_HL_BUFF_SIZE = 0x20;
	BYTE pbyBuff[PATCHED_HL_BUFF_SIZE] = {0};
	if(!m_pMaxPEFile->ReadBuffer(pbyBuff, m_dwAEPMapped, PATCHED_HL_BUFF_SIZE, PATCHED_HL_BUFF_SIZE))
	{
		return iRetStatus;
	}
	DWORD dwCallOffset = 0;
	if(pbyBuff[0x00] == 0xE9 || pbyBuff[0x00] == 0xE8)
	{
		dwCallOffset = *(DWORD *)&pbyBuff[0x1] + m_dwAEPUnmapped + 0x5;
	}
	else if(pbyBuff[0x00] == 0x68 )
	{
		DWORD	dwLength = 0, dwOffset = 0;
		t_disasm da = {0};
		m_dwInstCount = 0;

		while(dwOffset < PATCHED_HL_BUFF_SIZE && m_dwInstCount < 0x8)
		{

			dwLength = m_objMaxDisassem.Disasm((char *)&pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   

			if(m_dwInstCount==0x00 && dwLength ==5 && strstr(da.result,"PUSH"))
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x01 && dwLength ==1 && strstr(da.result,"POP EAX"))
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x02 && dwLength ==5 && strstr(da.result,"CALL"))
			{
				m_dwJumpFrom = *(DWORD *)&pbyBuff[dwOffset + 1] + dwOffset + dwLength + m_dwAEPUnmapped +*(DWORD *)&pbyBuff[0x1];
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x03 && dwLength ==1 && strstr(da.result,"POP EAX"))
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x04 && dwLength == 3 && (strstr(da.result,"MOV EDX")||strstr(da.result,"MOV ECX")) )
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x05 && dwLength == 2 && (strstr(da.result,"ADD EAX,EDX") ||strstr(da.result,"ADD EAX,ECX") ))
			{
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x06 && dwLength ==3 && strstr(da.result,"SUB EAX"))
			{  
				m_dwJumpFrom -= da.immconst;
				m_dwInstCount++;
			}
			else if(m_dwInstCount==0x07 && dwLength ==  1 && strstr(da.result,"PUSH EAX") )
			{
				m_dwInstCount++;
				dwCallOffset = m_dwJumpFrom;
				break;				
			}
			dwOffset += dwLength;
		}
	}

	if(dwCallOffset == 0)
	{
		return iRetStatus;
	}
		
	WORD wSec = m_pMaxPEFile->Rva2FileOffset(dwCallOffset, &m_dwJumpFrom);
	if(OUT_OF_FILE == wSec)
	{
		return iRetStatus;
	}
	//Cavity handling
	DWORD dwCavityStart = m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x18 + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + (m_pMaxPEFile->m_stPEHeader.NumberOfSections * 0x28);
	if(m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress !=0x0 )
	{
		dwCavityStart += m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].Size;
	}
	
	DWORD dwBytesToRead = 0; 
	if(m_dwJumpFrom <= m_pSectionHeader[0].PointerToRawData)
	{
		dwBytesToRead = m_pSectionHeader[0].PointerToRawData - m_dwJumpFrom;
	}
	//Overlay handling
	else 
	{
		if(m_dwJumpFrom >= m_pSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections - 0x1].PointerToRawData +
		m_pSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections - 0x1].SizeOfRawData &&
		m_dwJumpFrom <= m_pMaxPEFile->m_dwFileSize)
		{
			dwBytesToRead = m_pMaxPEFile->m_dwFileSize-m_dwJumpFrom;
		}
		else
		{
			dwBytesToRead = m_pSectionHeader[wSec].PointerToRawData + m_pSectionHeader[wSec].SizeOfRawData - m_dwJumpFrom; 
		}
	}
	if(dwBytesToRead > 0x1000)
	{
		return iRetStatus;
	}	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[dwBytesToRead + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, dwBytesToRead + MAX_INSTRUCTION_LEN);
	if(GetBuffer(m_dwJumpFrom, dwBytesToRead, dwBytesToRead))
	{
		if(GetTrojanPatchedHLParam())
		{
			m_eVirusDetected = TrojanPatchedHL;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.HL"));
			return VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetTrojanPatchedHLParam
	In Parameters	: 
	Out Parameters	: true if success else  false
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Collects the parameters for repair
--------------------------------------------------------------------------------------*/
bool CPolyTrojanPatched::GetTrojanPatchedHLParam()
{
	DWORD	dwLength = 0, dwOffset = 0;
	t_disasm da = {0};
	m_dwInstCount = 0;

	while(dwOffset < m_dwNoOfBytes && m_dwInstCount < 0xF)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > m_dwNoOfBytes - dwOffset)
		{
			return false;
		}
		if(m_dwInstCount==0x00 && dwLength ==1 && strstr(da.result,"PUSHAD"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x01 && dwLength ==5 && strstr(da.result,"CALL"))
		{
			m_dwReplaceOffSet = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] + m_dwJumpFrom + dwOffset + dwLength;
			m_dwReplaceOffSet-=m_dwJumpFrom;
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x02 && dwLength ==1 && strstr(da.result,"POP E"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x03 && dwLength ==2 &&(strstr(da.result,"CALL EAX")||strstr(da.result,"JMP")||strstr(da.result,"JE")))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x04 && dwLength ==3 && strstr(da.result,"LEA ESI,[E"))
		{
			m_dwReplaceOffSet+=m_pbyBuff[dwOffset+ 0x2];
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x05 && dwLength ==2 && strstr(da.result,"PUSH 0"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x06 && dwLength ==1 && strstr(da.result,"PUSH ESP"))
		{
			m_dwInstCount++;
		}
		else if((m_dwInstCount==0x07 || m_dwInstCount==0x08) && dwLength ==2 && strstr(da.result,"PUSH"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0x09 && dwLength ==1 && strstr(da.result,"PUSH EDI"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0xA && dwLength ==5 && strstr(da.result,"MOV EAX"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0xB && dwLength ==2 && strstr(da.result,"CALL EAX"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0xC && dwLength ==2 && strstr(da.result,"PUSH"))
		{
			m_dwNoOfByteReplace=da.immconst;
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0xC && dwLength ==5 && strstr(da.result,"MOV ECX"))
		{
			m_dwNoOfByteReplace=*(DWORD *)&m_pbyBuff[dwOffset+ 0x1];
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0xD && dwLength ==1 && strstr(da.result,"POP EAX"))
		{
			m_dwInstCount++;
		}
		else if(m_dwInstCount==0xE && dwLength ==1 && strstr(da.result,"POPAD"))
		{
			m_dwInstCount++;
			return true;
		}
		dwOffset += dwLength;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Ravi Prakash Mishra	 + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.HL
					  This function repairs file patched bytes on Kernal32.dll API 
					  DesibleThreadLibraryCalls call and remove jump address in 
					  any section added by virus.	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedHL()
{
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwReplaceOffSet], m_dwAEPMapped, m_dwNoOfByteReplace, m_dwNoOfByteReplace))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwJumpFrom, m_dwNoOfBytes))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra	 + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.DQ
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedDQ()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(	m_pSectionHeader[m_wAEPSec].Characteristics == 0xE0000020)
	{	         
		DWORD PATCHED_MP_BUFF_SIZE = 0x200;
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PATCHED_MP_BUFF_SIZE];
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_dwAEPMapped, 0x5, 0x5))
		{
			return iRetStatus;
		}

		if(m_pbyBuff[0x00] != 0xE9 && m_pbyBuff[0x00] != 0xE8)
		{
			return iRetStatus;
		}
		DWORD dwCallOffset=0;
		dwCallOffset = *(DWORD *)&m_pbyBuff[0x1] + m_dwAEPUnmapped + 0x5;
		WORD wSec = m_pMaxPEFile->Rva2FileOffset(dwCallOffset, &m_dwReplaceOffSet);
		if(OUT_OF_FILE == wSec || m_dwReplaceOffSet > m_pMaxPEFile->m_dwFileSize)
		{
			return iRetStatus;
		}
		if(m_dwReplaceOffSet > m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)
		{
			m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize - m_dwReplaceOffSet;
		}
		else
		{
			m_dwNoOfbyteToRead = m_pSectionHeader[wSec].PointerToRawData + m_pSectionHeader[wSec].SizeOfRawData - m_dwReplaceOffSet;
		}
		if(PATCHED_MP_BUFF_SIZE < m_dwNoOfbyteToRead  && m_dwNoOfbyteToRead > 0x30)
		{
			m_dwNoOfbyteToRead = PATCHED_MP_BUFF_SIZE;
		}
		else
		{
			return iRetStatus;
		}
		if(GetBuffer(m_dwReplaceOffSet, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{
			DWORD	dwLength = 0, dwOffset=0, dwInstCount = 0;
			t_disasm da = {0};

			while(dwOffset < m_dwNoOfbyteToRead - 6 && dwInstCount < 0xA)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			

				if(dwInstCount==0x00 && dwLength ==1 && strstr(da.result,"POP EAX"))
				{
					dwInstCount++;
				}
				else if(dwInstCount==0x01 && dwLength ==1 && strstr(da.result,"PUSHAD"))
				{  
					dwInstCount++;
				}
				else if(dwInstCount==0x02 && dwLength ==5 && strstr(da.result,"MOV ECX"))
				{
					dwInstCount++;
				}
				else if(dwInstCount==0x03 && dwLength ==5 && strstr(da.result,"PUSH"))
				{
					dwInstCount++;
				}
				else if(dwInstCount==0x04 && dwLength ==3 && strstr(da.result,"XOR [ESP]"))
				{
					dwInstCount++;
				}
				else if(dwInstCount==0x05 && dwLength ==5 && strstr(da.result,"PUSH"))
				{
					dwInstCount++;
				}
				else if(dwInstCount==0x06 && dwLength ==3 && strstr(da.result,"XOR [ESP]"))
				{
					dwInstCount++;
				}
				else if(dwInstCount==0x07 && dwLength ==1 && strstr(da.result,"PUSH ESP"))
				{
					dwInstCount++;
				}
				else if(dwInstCount==0x08 && dwLength ==5 && strstr(da.result,"ADD EAX"))
				{
					if(*(DWORD *)&m_pbyBuff[dwOffset+ dwLength]!=0xD3FF188B || 
						*(WORD *)&m_pbyBuff[dwOffset+ dwLength + 0x4]!=0x5B58 || 
						m_pbyBuff[dwOffset+ dwLength + 0x6]!=0x61)
					{
						return iRetStatus;
					}

					dwInstCount++;
				}
				else if(dwInstCount==0x09 && dwLength ==5 && strstr(da.result,"JMP"))
				{
					dwInstCount++;
					m_dwNoOfbyteToRead = (dwOffset+ dwLength);
					m_dwOriginalAEP=*(DWORD *)&m_pbyBuff[dwOffset+ 0x1]+ dwCallOffset + m_dwNoOfbyteToRead;
					m_eVirusDetected = TrojanPatchedDQ;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.DQ"));
					return VIRUS_FILE_REPAIR;
				}

				dwOffset += dwLength;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedDQ
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.DQ
					  This function patched bytes  fill with zeros and repair original AEP	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedDQ()
{  	
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{ 
		if(m_pMaxPEFile->FillWithZeros(m_dwReplaceOffSet, m_dwNoOfbyteToRead) && m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x5))
		{
			return REPAIR_SUCCESS;
		}
	}		   
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedOD
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.OD + Trojan.Patched.DL
					  This function use for dectection with find the original patched byte on call & systemcall.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedOD()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	const int PATCHED_OD_BUFF_SIZE = 0x1000;
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[PATCHED_OD_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, PATCHED_OD_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(GetBuffer(m_dwAEPMapped, PATCHED_OD_BUFF_SIZE, PATCHED_OD_BUFF_SIZE))
	{		
		DWORD	dwLength = 0, dwOffset = 0;
		t_disasm da = {0};
		m_dwInstCount = 0;
		while(dwOffset < PATCHED_OD_BUFF_SIZE && m_dwInstCount < 0x5)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
			if(dwLength > (PATCHED_OD_BUFF_SIZE - dwOffset))
			{
				break;
			}
			if(dwLength == 5 && strstr(da.result,"CALL"))
			{
				m_dwInstCount++;
				m_dwJumpFrom = m_dwAEPUnmapped + dwOffset;
				m_dwDataAddr = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] + dwLength + dwOffset + m_dwAEPUnmapped;

				if(GetTrojanPatchedODParam())
				{
					m_eVirusDetected = TrojanPatchedOD;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.OD"));
					return VIRUS_FILE_REPAIR;
				}
			}
			if(dwLength == 5 && strstr(da.result,"JMP") && m_dwInstCount == 0x0)
			{				
				m_dwJumpFrom = m_dwAEPUnmapped + dwOffset;
				m_dwDataAddr = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] + dwLength + dwOffset + m_dwAEPUnmapped;

				if(GetTrojanPatchedODParam())
				{
					m_eVirusDetected = TrojanPatchedOD;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.DL"));
					return VIRUS_FILE_REPAIR;
				}
			}
			dwOffset += dwLength;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetTrojanPatchedODParam
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Collectes the patch call information for repair
--------------------------------------------------------------------------------------*/
bool CPolyTrojanPatched::GetTrojanPatchedODParam()
{	
	WORD wSec = m_pMaxPEFile->Rva2FileOffset(m_dwDataAddr, &m_dwTruncateOffset);
	if(OUT_OF_FILE == wSec)
	{
		return false;
	}

	//Cavity handling
	DWORD dwCavityStart = m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x18 + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + (m_pMaxPEFile->m_stPEHeader.NumberOfSections * 0x28);
	if(m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress != 0x0 )
	{
		dwCavityStart += m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].Size;
	}
	
	if(m_dwTruncateOffset >= dwCavityStart && m_dwTruncateOffset <= m_pSectionHeader[0].PointerToRawData)
	{
		m_dwNoOfbyteToRead = m_pSectionHeader[0].PointerToRawData - m_dwTruncateOffset;
	}
	else 
	{
		if(m_dwTruncateOffset >= m_pSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections - 0x1].PointerToRawData +
			m_pSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections - 0x1].SizeOfRawData &&
			m_dwTruncateOffset <= m_pMaxPEFile->m_dwFileSize)	//Overlay handling
		{
			m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize-m_dwTruncateOffset;
		}
		else
		{  //Section  handling
			m_dwNoOfbyteToRead = m_pSectionHeader[wSec].PointerToRawData + m_pSectionHeader[wSec].SizeOfRawData - m_dwTruncateOffset; 
		}
	}
	if(m_dwNoOfbyteToRead < 0x27)
	{
		return false;
	}

	if(m_dwNoOfbyteToRead > 0x200)
	{
		m_dwNoOfbyteToRead = 0x200;
	}
	
	BYTE pbyBuff[0x200 + MAX_INSTRUCTION_LEN] = {0};
	if(m_pMaxPEFile->ReadBuffer(pbyBuff, m_dwTruncateOffset - 0x4, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
	{ 
		DWORD dwInftype =0x0;
		//Signature for Virus.Patched.OD
		const BYTE Sig[] = {0x42,0x54,0x43,0x48,0x60,0x68};//BTCH`h
		const BYTE Sig1[] = {0x41,0xFF,0xD3,0xEB,0x5A,0x33,0xDB,0x0F,0xBE,0x10,0x3A,0xD6,0x74,0x08,0xC1,0xCB,0x0D,0x03,0xDA,0x40,0xEB};
		const BYTE Sig2[] = {0x04,0x00,0x4C,0x4F,0x56,0x45};//Love
		
		//Signature for Virus.Patched.DL
		const BYTE SigDL[] = {0x5F,0x64,0xA1,0x30,0x00,0x00,0x00,0x8B,0x40,0x0C,0x8B,0x70,0x1C,0xAD,0x8B,0x68,0x08,0x8B,0xF7};//BTCH`h
		const BYTE SigDL1[] = {0x51,0x56,0x8B,0x75,0x3C,0x8B,0x74,0x2E,0x78,0x03,0xF5,0x56,0x8B,0x76,0x20,0x03,0xF5,0x33,0xC9,0x49,0x41,0xAD,0x03,0xC5,0x33,0xDB,0x0F,0xBE,0x10,0x3A,0xD6,0x74,0x08,0xC1,0xCB,0x0D,0x03,0xDA,0x40,0xEB,0xF1,0x3B,0x1F,0x75,0xE7,0x5E,0x8B,0x5E,0x24,0x03,0xDD,0x66,0x8B,0x0C,0x4B,0x8B,0x5E,0x1C,0x03,0xDD,0x8B,0x04,0x8B,0x03,0xC5,0x5E,0x59};
		const BYTE SigDL2[] = {0x8E,0x4E,0x0E,0xEC,0x61,0x90};
		if(pbyBuff[0x04]== 0x60 && pbyBuff[0x05]== 0xEB)
		{
			dwInftype++;
		}
		for(DWORD dwOffset = 0; dwOffset <= m_dwNoOfbyteToRead - sizeof(Sig); dwOffset++)
		{
			if((memcmp(&pbyBuff[dwOffset], Sig, sizeof(Sig)) == 0) || ((memcmp(&pbyBuff[dwOffset], SigDL, sizeof(SigDL)) == 0) && dwInftype !=0x0))
			{
				for(dwOffset += sizeof(Sig); dwOffset <= m_dwNoOfbyteToRead - sizeof(Sig1); dwOffset++)
				{
					if((memcmp(&pbyBuff[dwOffset], Sig1, sizeof(Sig1)) == 0)|| ((memcmp(&pbyBuff[dwOffset], SigDL1, sizeof(SigDL1)) == 0) && dwInftype !=0x0)) 
					{
						for(dwOffset += sizeof(Sig1); dwOffset <= m_dwNoOfbyteToRead - sizeof(Sig2); dwOffset++)
						{
							if(memcmp(&pbyBuff[dwOffset], Sig2, sizeof(Sig2)) == 0)
							{  																		
								m_dwDLLFileOffset = 0;
								m_dwNoOfbyteToRead = dwOffset + sizeof(Sig2) + 0x4;
								if(pbyBuff[dwOffset - 0x7] == 0x61 && *(WORD *)&pbyBuff[dwOffset - 0x6] == 0x25FF)
								{
									m_dwOriData = *(DWORD *)&pbyBuff[dwOffset - 0x4];
									m_dwDLLFileOffset = 1;

								}
								else if(pbyBuff[dwOffset - 0x7]== 0x61 && pbyBuff[dwOffset - 0x6]== 0x68)
								{
									m_dwOriData = *(DWORD *)&pbyBuff[dwOffset - 0x5] - (m_dwJumpFrom + 0x5)- m_dwImageBase;
								}
								return true;			
							}
							if((memcmp(&pbyBuff[dwOffset], SigDL2, sizeof(SigDL2)) == 0) && dwInftype !=0x0)
							{
								m_dwNoOfbyteToRead = dwOffset + sizeof(SigDL2) + 0x4;
								m_dwOriData = *(DWORD *)&pbyBuff[dwOffset + sizeof(SigDL2)+ 0x2];
								m_dwDLLFileOffset =1;
								return true;
							}
						}
						return false;
					}
				}
				return false;
			}
		}		
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedOD
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.OD + Trojan.Patched.OD
					  This function repairs file patched bytes on call or system call.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedOD()
{	
	
	m_pMaxPEFile->Rva2FileOffset(m_dwJumpFrom, &m_dwJumpFrom);	
	if(m_dwDLLFileOffset)
	{
		BYTE byBuffer[] = {0xFF,0x15};
		if(!m_pMaxPEFile->WriteBuffer(byBuffer, m_dwJumpFrom, sizeof(byBuffer), sizeof(byBuffer)))
		{	
			return REPAIR_FAILED;
		}
		if(!m_pMaxPEFile->WriteBuffer(&m_dwOriData, m_dwJumpFrom + 0x2, 0x4, 0x4))
		{
			return REPAIR_FAILED;
		}
	}
	else if(!m_pMaxPEFile->WriteBuffer(&m_dwOriData, m_dwJumpFrom + 0x1, 0x4, 0x4))
	{
		return REPAIR_FAILED;
	}

	if(m_pMaxPEFile->FillWithZeros(m_dwTruncateOffset , m_dwNoOfbyteToRead - 0x4 ))
	{
		return REPAIR_SUCCESS;
	}

	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedDY
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.DY
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedDY()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(	(m_wAEPSec == 0) && m_wNoOfSections > 3 &&
		(m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0xA) &&
		(m_pMaxPEFile->m_stPEHeader.MinorOSVersion == 0x1) &&
		(m_pMaxPEFile->m_stPEHeader.MinorSubsystemVersion == 0x0) &&
		(m_pMaxPEFile->m_stPEHeader.Subsystem == 0x02) || (m_pMaxPEFile->m_stPEHeader.Subsystem == 0x03) && 
		(m_pMaxPEFile->m_stPEHeader.Characteristics ==0x210E) &&
		(m_pSectionHeader[0].Characteristics == 0x60000020) &&
		(m_pSectionHeader[1].Characteristics == 0xC0000040) &&
		(m_pSectionHeader[2].Characteristics == 0x40000040) &&
		(m_pSectionHeader[3].Characteristics == 0x42000040))
	{	         
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		int PATCHED_DY_BUFF_SIZE = 0x30;
		m_pbyBuff = new BYTE[PATCHED_DY_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, PATCHED_DY_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, PATCHED_DY_BUFF_SIZE, PATCHED_DY_BUFF_SIZE))
		{  			
			if(m_pbyBuff[0x0] == 0x68 && m_pbyBuff[0x5] == 0xE8 && m_pbyBuff[0xA] == 0x83 &&  m_pbyBuff[0xE] == 0xB8)
			{
				DWORD	dwLength = 0, dwOffset = 0, dwInstCount = 0;
				t_disasm da = {0};

				while(dwOffset < m_dwNoOfBytes && dwInstCount < 0x5)
				{
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			
					if(dwLength > m_dwNoOfBytes - dwOffset)
					{
						break;
					}
					if(dwInstCount == 0x00 && dwLength == 5  && strstr(da.result,"PUSH"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x01 && dwLength == 5  && strstr(da.result,"CALL"))
					{  
						dwInstCount++;
					}
					else if(dwInstCount == 0x02 && dwLength == 4  && strstr(da.result,"SUB DWORD PTR [ESP],A"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x03 && dwLength == 5  && strstr(da.result,"MOV EAX"))
					{
						dwInstCount++;
					}
					else if(dwInstCount == 0x04 && dwLength == 2  && strstr(da.result,"JMP EAX"))
					{				
						m_eVirusDetected = TrojanPatchedDY;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.DY"));
						return VIRUS_FILE_REPAIR;
					}
					dwOffset += dwLength;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedDY
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.DY
					  This function repairs file patched bytes,
					  Replace with the original data.	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedDY()
{  	
	BYTE byBuffer[]={0x8B,0xFF,0x55,0x8B,0xEC,0x83,0x7D,0x0C,0x01,0x0F,0x84,0xF3,0x29,0x00,0x00,0x5D,0x90,0x90,0x90,0x90,0x90};
		
	if(m_pMaxPEFile->WriteBuffer(byBuffer, m_dwAEPMapped, sizeof(byBuffer), sizeof(byBuffer)))
	{	
		return REPAIR_SUCCESS;
	}		   

	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedAL
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.AL
					  This function use for dectection with find the original data inside  virus code.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedAL()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pSectionHeader[m_wAEPSec].Characteristics == 0xE0000020)
	{	         
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PATCHED_LP_SCAN_BYTES];
		m_dwNoOfbyteToRead = 0, m_dwOriginalAEP = 0;

		//Cavity handling
		DWORD dwCavityStart = m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x18 + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + (m_pMaxPEFile->m_stPEHeader.NumberOfSections * 0x28);
		if(m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress != 0x0 )
		{
			dwCavityStart += m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].Size;
		}

		DWORD dwBytesToRead = 0; 
		if(m_dwAEPMapped >= dwCavityStart && m_dwAEPMapped <= m_pSectionHeader[0].PointerToRawData)
		{
			m_dwNoOfbyteToRead = m_pSectionHeader[0].PointerToRawData - m_dwAEPMapped;
		}
		//overlay handling	
		if(m_dwAEPMapped > m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)
		{
			m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize - m_dwAEPMapped;
		}
		//Read AEP Section data 
		else
		{
			m_dwNoOfbyteToRead = m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - m_dwAEPMapped;
		}
		if(m_dwNoOfbyteToRead < 14)
		{
			return iRetStatus;
		}
		if(PATCHED_LP_SCAN_BYTES < m_dwNoOfbyteToRead)
		{
			m_dwNoOfbyteToRead = PATCHED_LP_SCAN_BYTES;
		}
		if( m_pSectionHeader[m_wAEPSec].PointerToRawData == m_dwAEPMapped && m_wAEPSec == m_wNoOfSections - 1 )
		{
			m_dwTruncateOffset = 1;
		}
		if(GetBuffer(m_dwAEPMapped, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{	
			if(m_pbyBuff[0x00] == 0x60 || (m_pbyBuff[0x00] == 0x90 && m_pbyBuff[0x01] == 0x60))
			{
				DWORD	dwLength = 0,dwOffset = 0,dwInstCount = 0;
				t_disasm da = {0};

				while(dwOffset < m_dwNoOfbyteToRead - 5 && dwInstCount < 0x10)
				{
					dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			

					if(dwInstCount==0x00 && dwLength ==1 && strstr(da.result,"PUSHAD"))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0x01 && (dwLength ==6 || dwLength ==7 )&& (strstr(da.result,"MOV EAX,FS:[30]") ||strstr(da.result,"MOV EDX,FS:[30]")))
					{  
						dwInstCount++;
					}
					else if(dwInstCount==0x02 && dwLength ==3 && (strstr(da.result,"MOV EAX,[EAX+C]")||strstr(da.result,"MOV EDX,[EDX+C]")))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0x03 && dwLength ==3 && strstr(da.result,"MOV ESI,["))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0x04 && dwLength ==1 && strstr(da.result,"LODS DWORD PTR [ESI]"))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0x05 && dwLength ==3 && strstr(da.result,"MOV"))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0x06 && dwLength ==3 && strstr(da.result,"MOV"))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0x07 && dwLength ==4 && strstr(da.result,"MOV"))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0x08 && dwLength ==2 && strstr(da.result,"ADD"))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0x09  && dwLength ==3 && strstr(da.result,"MOV"))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0x0A  && dwLength ==3 && strstr(da.result,"MOV"))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0x0B && dwLength ==2 && strstr(da.result,"ADD"))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0x0C && dwLength ==2 && strstr(da.result,"PUSH 0"))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0xD && dwLength ==1 && strstr(da.result,"POPAD"))
					{
						dwInstCount++;
					}
					else if(dwInstCount==0xE && dwLength ==5 && strstr(da.result,"JMP"))
					{
						m_dwNoOfbyteToRead = (dwOffset+ dwLength);
						m_dwOriginalAEP =  *(DWORD *)&m_pbyBuff[dwOffset+ 0x1]+ m_dwAEPUnmapped + m_dwNoOfbyteToRead;
						m_eVirusDetected = TrojanPatchedAL;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.AL"));
						return VIRUS_FILE_REPAIR; 
					}
					dwOffset += dwLength;
				}
			}
			//corrupt file handiling
			else if(m_dwTruncateOffset)
			{
				const BYTE bySig[] = {0x68,0x47,0x65,0x74,0x50};
				const BYTE bySig1[] = {0xB8,0x72,0x6F,0x63,0x41};
				const BYTE bySig2[] = {0x4C,0x69,0x62,0x72};
				const BYTE bySig3[] = {0x4C,0x6F,0x61,0x64};
				const BYTE bySig4[] = {0x61,0xE9};
				
				for(DWORD dwOffset = 0; dwOffset <= m_dwNoOfbyteToRead - sizeof(bySig); dwOffset++)
				{
					if(memcmp(&m_pbyBuff[dwOffset], bySig, sizeof(bySig)) == 0x00)
					{
						for(dwOffset += sizeof(bySig); dwOffset <= m_dwNoOfbyteToRead - sizeof(bySig1); dwOffset++)
						{
							if(memcmp(&m_pbyBuff[dwOffset], bySig1, sizeof(bySig1)) == 0x00)
							{
								for(dwOffset += sizeof(bySig1); dwOffset <= m_dwNoOfbyteToRead - sizeof(bySig2); dwOffset++)
								{
									if(memcmp(&m_pbyBuff[dwOffset], bySig2, sizeof(bySig2)) == 0x00)
									{
										for(dwOffset += sizeof(bySig2); dwOffset <= m_dwNoOfbyteToRead - sizeof(bySig3); dwOffset++)
										{
											if(memcmp(&m_pbyBuff[dwOffset], bySig3, sizeof(bySig3)) == 0x00)
											{
												for(dwOffset += sizeof(bySig3); dwOffset <= m_dwNoOfbyteToRead - sizeof(bySig4); dwOffset++)
												{
													if(memcmp(&m_pbyBuff[dwOffset], bySig4, sizeof(bySig4)) == 0x00)
													{	
														m_dwOriginalAEP=*(DWORD *)&m_pbyBuff[dwOffset + 0x2]+ m_dwAEPUnmapped + dwOffset + 0x5;														
														m_eVirusDetected = TrojanPatchedAL;
														_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.AL"));
														return VIRUS_FILE_REPAIR;
													}
												}
												return iRetStatus;
											}
										}
										return iRetStatus;
									}
								}
								return iRetStatus;
							}
						}
						return iRetStatus;
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedAL
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.AL
					  This function patched bytes  fill with zeros if no any new section added by virus 
					  else remove section which is added by virus and repair original AEP.	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedAL()
{  	
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{ 
		if(m_dwTruncateOffset==0)
		{
			if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, m_dwNoOfbyteToRead))
			{
				return REPAIR_SUCCESS;
			}
		}
		if( m_pMaxPEFile->RemoveLastSections())
		{
			return REPAIR_SUCCESS;	
		}
	}		   

	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedBJ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.BJ
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedBJ()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(	(m_wAEPSec == 0) && 
		(m_pMaxPEFile->m_stPEHeader.MinorSubsystemVersion == 0x0)&&
		(m_pMaxPEFile->m_stPEHeader.Subsystem == 0x02)||
		(m_pMaxPEFile->m_stPEHeader.Subsystem == 0x03)&& 
		(m_pMaxPEFile->m_stPEHeader.NumberOfSections >= 0x3)&&
		(m_pSectionHeader[m_wAEPSec].Characteristics == 0x60000020))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_dwNoOfbyteToRead = 0;
		m_dwNoOfbyteToRead = m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - m_dwAEPMapped; 
		if(m_dwNoOfbyteToRead < 0x20)
		{
			return iRetStatus;
		}
		if(m_dwNoOfbyteToRead > 0x200)
		{
			m_dwNoOfbyteToRead = 0x200;
		}
		m_pbyBuff = new BYTE[m_dwNoOfbyteToRead + MAX_INSTRUCTION_LEN];

		if(!GetBuffer(m_dwAEPMapped, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{
			return iRetStatus;
		}

		if(m_pbyBuff[0x0] != 0x68 && m_pbyBuff[0x07] != 0x64 && m_pbyBuff[0x0A] != 0x64)
		{
			return iRetStatus;
		}

		DWORD	dwLength = 0, dwOffset = 0, dwInstCount = 0;
		t_disasm da = {0};

		while(dwOffset < m_dwNoOfbyteToRead && dwInstCount < 0x13)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			
			if(dwLength > m_dwNoOfBytes - dwOffset)
			{
				break;
			}
			if(dwInstCount == 0x00 && dwLength == 5  && strstr(da.result,"PUSH"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x01 && dwLength == 2 && strstr(da.result,"XOR E"))
			{  
				dwInstCount++;
			}
			else if(dwInstCount == 0x02 && dwLength == 3  && strstr(da.result,"PUSH DWORD PTR FS:[E"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x03 && dwLength == 3  && strstr(da.result,"MOV FS:[E"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x04 && dwLength == 2  && strstr(da.result,"XOR"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x05 && dwLength == 2 && strstr(da.result,"PUSH"))
			{  
				dwInstCount++;
			}
			else if(dwInstCount == 0x06 && dwLength == 1  && strstr(da.result,"POP ECX"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x07 && dwLength == 1  && strstr(da.result,"PUSH E"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x08 && dwLength == 2  && strstr(da.result,"PUSH"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x09 && dwLength == 2 && strstr(da.result,"MOV E"))
			{  
				dwInstCount++;
			}
			else if(dwInstCount == 0x0A && dwLength == 3  && strstr(da.result,"SUB ESP,"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x0B && dwLength == 2  && strstr(da.result,"MOV E"))
			{
				dwInstCount++;

			}
			else if(dwInstCount == 0x0C && dwLength == 5  && strstr(da.result,"PUSH"))
			{
				DWORD dwCount = dwInstCount;
				DWORD dwCallOffset = *(DWORD *)&m_pbyBuff[dwOffset + 0x1]-m_dwImageBase;
				WORD wSec = m_pMaxPEFile->Rva2FileOffset(dwCallOffset, &dwCallOffset);
				if(OUT_OF_FILE == wSec || m_wAEPSec != wSec || dwCallOffset == 0x0 )
				{
					return iRetStatus;
				}
				dwCallOffset -= m_dwAEPMapped;
				const BYTE bySig[] = {0x2E, 0x65, 0x78, 0x65};//.exe
				const BYTE bySig1[] = {0x2E, 0x45, 0x58, 0x45};//.EXE
				const BYTE bySig2[] = {0x2E, 0x65, 0x58, 0x45};//.Exe
				
				for(DWORD i = dwCallOffset; i < m_dwNoOfbyteToRead - sizeof(bySig); i++)
				{
					if((memcmp(&m_pbyBuff[i], bySig, sizeof(bySig)) == 0)||(memcmp(&m_pbyBuff[i], bySig1, sizeof(bySig1)) == 0) ||(memcmp(&m_pbyBuff[i], bySig2, sizeof(bySig2)) == 0))
					{
						dwInstCount++;
						m_dwNoOfbyteToRead = i + sizeof(bySig) + 0x2;
						break;
					}
				}
				if(dwCount == dwInstCount)
				{
					return iRetStatus;
				}
			}
			else if(dwInstCount == 0x0D && dwLength == 1 && strstr(da.result,"PUSH E"))
			{  
				dwInstCount++;
			}
			else if(dwInstCount == 0x0E && dwLength == 3  && strstr(da.result,"ADD ESP,"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x0F && dwLength == 3 && strstr(da.result,"POP DWORD PTR FS:[E"))
			{  
				dwInstCount++;
			}
			else if(dwInstCount == 0x10 && dwLength == 5  && strstr(da.result,"PUSH"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x11 && dwLength == 5  && strstr(da.result,"PUSH"))
			{
				m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] - m_dwImageBase;
				dwInstCount++;
			}
			else if(dwInstCount == 0x12 && dwLength == 2  && strstr(da.result,"XOR EAX,EAX"))
			{				
				m_eVirusDetected = TrojanPatchedBJ;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.BJ"));
				return VIRUS_FILE_REPAIR;
			}
			dwOffset += dwLength;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedBJ
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : TRojan.Patched.BJ
					  This function repairs file by setting Original AEP Byte and 
					  replaced patched bytes with CC.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedBJ()
{
	int iRetStatus = REPAIR_FAILED;

	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{	
		BYTE *pbyBuffer = new BYTE[m_dwNoOfbyteToRead];
		if(!pbyBuffer)
		{
			return false;
		}
		memset(pbyBuffer, 0xCC, m_dwNoOfbyteToRead);
		if(m_pMaxPEFile->WriteBuffer(pbyBuffer, m_dwAEPMapped, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{
			if(m_pMaxPEFile->FillWithZeros(m_pMaxPEFile->m_stPEOffsets.Checksum, 0x4))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
		delete []pbyBuffer;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedBH
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.BH
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedBH()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	const int PATCHED_BH_BUFF_SIZE = 0x200;
	if((m_wAEPSec == 0) && 
		(m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x00)&&
		(m_pMaxPEFile->m_stPEHeader.MinorOSVersion == 0x1)&&
		(m_pMaxPEFile->m_stPEHeader.MinorSubsystemVersion == 0x0)&&
		(m_pMaxPEFile->m_stPEHeader.Subsystem == 0x02) && 
		(m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x3)&&
		(m_pMaxPEFile->m_stPEHeader.Characteristics == 0x010F)&&
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].VirtualAddress != 0x0) &&
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size != 0x0) &&
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size <= PATCHED_BH_BUFF_SIZE) &&
		(m_pSectionHeader[0].Characteristics == 0x60000020)&&
		(m_pSectionHeader[1].Characteristics == 0xC0000040)&&
		(m_pSectionHeader[2].Characteristics == 0x40000040))
	{	         
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PATCHED_BH_BUFF_SIZE];
		
		const BYTE byCheckSig[] = {0x56,0x68,0x08,0x2b,0x00,0x01,0xff,0x15,0x88,0x10,0x00,0x01,0x6a,0x01,0xff,0x15,0x84,0x10,0x00,0x01,0xff,0x15,0x80,0x10,0x00,0x01,0x50,0xe8,0x9d,0x00,0x00,0x00,0xb8,0x48,0x40,0x00,0x01,0x68,0x20,0x40,0x00,0x01,0xa3,0x4c,0x40,0x00,0x01,0xa3,0x48,0x40,0x00,0x01,0xff,0x15,0x7c,0x10,0x00,0x01,0xff,0x15,0x78,0x10,0x00,0x01,0x50,0xe8,0x8d,0x01,0x00,0x00,0x8b,0xf0,0x85,0xf6,0x74,0x2a,0x57,0x56,0xe8,0x99,0x02,0x00,0x00,0xe8,0xd7,0x00,0x00,0x00,0x8b,0xf8,0x85,0xff,0x74};
		if(!GetBuffer(m_dwAEPMapped, sizeof(byCheckSig), sizeof(byCheckSig)))
		{ 
			return iRetStatus;
		}
		if(memcmp(m_pbyBuff, byCheckSig, sizeof(byCheckSig)) == 0)
		{
			DWORD dwCavityStart = m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x18 + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + (m_pMaxPEFile->m_stPEHeader.NumberOfSections * 0x28);
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwCavityStart, &dwCavityStart))
			{
				return iRetStatus;
			}
			if(!GetBuffer(dwCavityStart, m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size, m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size))
			{
				return iRetStatus;
			}
			m_dwDLLFileOffset=0;
			const BYTE byDllName[] = {0x4D,0x53,0x43,0x4F,0x52,0x45,0x2E,0x44,0x4C,0x4C};//MSCORE.DLL 
			for(DWORD Offset = 0; Offset <= m_dwNoOfbyteToRead - sizeof(byDllName); Offset++)
			{
				if(memcmp(&m_pbyBuff[Offset], byDllName, sizeof(byDllName)) == 0)
				{
					m_dwDLLFileOffset= dwCavityStart + Offset;
					m_eVirusDetected = TrojanPatchedBH;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.BH"));
					return VIRUS_FILE_REPAIR;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedBH
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.BH
					  This function repairs file replace this MSCORE.DLL  on the place of RPCRT4.dll 
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedBH()
{  	
	BYTE byBuffer[]={0x52,0x50,0x43,0x52,0x54,0x34,0x2E,0x64,0x6C,0x6C};//RPCRT4.dll

	if(m_pMaxPEFile->WriteBuffer(byBuffer, m_dwDLLFileOffset, sizeof(byBuffer), sizeof(byBuffer)))
	{
		return REPAIR_SUCCESS;
	}		   
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedOK
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine : Trojan.Patched.OK
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedOK()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_dwAEPMapped ==0x6C0 && m_wAEPSec == 0 && m_pMaxPEFile->m_stPEHeader.Magic == 0x010B &&
		m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x0A && m_pMaxPEFile->m_stPEHeader.MinorSubsystemVersion == 0x0 &&
		m_pMaxPEFile->m_stPEHeader.Subsystem == 0x02 && m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x4 &&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0x0].VirtualAddress != 0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[0x0].Size != 0 &&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0x5].VirtualAddress != 0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[0x5].Size > 0xC)
	{
		WORD dwReserved = 0x0; 
		m_pMaxPEFile->ReadBuffer(&dwReserved, 0x1A, 0x2, 0x2);
		if(dwReserved != 0x1990)
		{
			return iRetStatus;
		}
		int PATCHED_OK_BUFF_SIZE = m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - m_dwAEPMapped;
		if(PATCHED_OK_BUFF_SIZE < 0x400 || PATCHED_OK_BUFF_SIZE > 0x15000)
		{
			return iRetStatus;
		}
		if(PATCHED_OK_BUFF_SIZE > 0x10000)
		{
			PATCHED_OK_BUFF_SIZE = 0x10000;
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PATCHED_OK_BUFF_SIZE];
		if(m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress != 0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].Size != 0)
		{			
			if(!GetBuffer(m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress, m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].Size, m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].Size))
			{
				return iRetStatus;
			}
			const BYTE byCheckDll[] = {0x6E,0x74,0x64,0x6C,0x6C,0x2E,0x64,0x6C,0x6C};//ntdll.dll

			bool bFound = false;
			for(DWORD j = 0; j <= m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].Size  - sizeof(byCheckDll); j++)
			{
				if(_memicmp(&m_pbyBuff[j], byCheckDll, sizeof(byCheckDll)) == 0)
				{
					bFound = true;
					break;
				}
			}
			if(!bFound)
			{
				return iRetStatus;
			}
		}

		if(GetBuffer(m_dwAEPMapped, PATCHED_OK_BUFF_SIZE, PATCHED_OK_BUFF_SIZE))
		{	
			//Check for clean file
			const BYTE byCheckSig[] = {0x8B,0xFF,0x55,0x8B,0xEC,0x8B,0x45,0x0C,0x33,0xC9,0x2B,0xC1,0x74,0x26,0x48,0x0F};
			if(memcmp(&m_pbyBuff[0x0], byCheckSig, sizeof(byCheckSig)) != 0) 
			{
				return iRetStatus;
			}
			DWORD	dwLength = 0, dwOffset = 0;
			t_disasm da = {0};
			while(dwOffset < m_dwNoOfBytes - MAX_INSTRUCTION_LEN)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
				if(dwLength == 5 && m_pbyBuff[dwOffset]== 0xE9 &&  strstr(da.result,"JMP"))
				{			
					m_dwJumpFrom = m_dwAEPUnmapped + dwOffset;
					m_dwDataAddr = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] + dwLength + dwOffset + m_dwAEPUnmapped;

					if(GetTrojanPatchedOKParam())
					{
						m_eVirusDetected = TrojanPatchedOK;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.OK"));
						return VIRUS_FILE_REPAIR;
					}
				}
				dwOffset += dwLength;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetTrojanPatchedOKParam
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		:
--------------------------------------------------------------------------------------*/
bool CPolyTrojanPatched::GetTrojanPatchedOKParam()
{	
	WORD wSec = m_pMaxPEFile->Rva2FileOffset(m_dwDataAddr, &m_dwTruncateOffset);
	if(OUT_OF_FILE == wSec)
	{
		return false;
	}
	if(m_dwTruncateOffset >= m_pSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections - 0x1].PointerToRawData +
		m_pSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections - 0x1].SizeOfRawData &&
		m_dwTruncateOffset <= m_pMaxPEFile->m_dwFileSize)	//Overlay handling
	{
		m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize - m_dwTruncateOffset;
	}
	else
	{  //Section  handling
		m_dwNoOfbyteToRead = m_pSectionHeader[wSec].PointerToRawData + m_pSectionHeader[wSec].SizeOfRawData - m_dwTruncateOffset; 
	}

	if(m_dwNoOfbyteToRead < 0x36)
	{
		return false;
	}
	if(m_dwNoOfbyteToRead > 0x50)
	{
		m_dwNoOfbyteToRead = 0x50;
	}
	BYTE pbyBuff[0x50 + MAX_INSTRUCTION_LEN] = {0};
	if(m_pMaxPEFile->ReadBuffer(pbyBuff, m_dwTruncateOffset, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
	{ 
		const BYTE Sig[] = {0x58,0x75,0x73,0x72,0x64,0x70,0x61,0x2E,0x64,0x6C,0x6C};//Xusrdpa.dll
		const BYTE Sig1[] = {0x62,0x64,0x63,0x61,0x70,0x45,0x78,0x33,0x32,0x2e,0x64,0x6c,0x6c};//bdcapEx32.dll 
		bool bSigMatch = false;

		for(DWORD dwOffsetAdd = 0; dwOffsetAdd <= m_dwNoOfbyteToRead - sizeof(Sig1); dwOffsetAdd++)
		{
			if(memcmp(&pbyBuff[dwOffsetAdd], Sig, sizeof(Sig)) == 0)
			{
				bSigMatch = true;
				m_dwNoOfbyteToRead = dwOffsetAdd + sizeof(Sig);
			}
			if(memcmp(&pbyBuff[dwOffsetAdd], Sig1, sizeof(Sig1)) == 0)
			{
				bSigMatch = true;
				m_dwNoOfbyteToRead = dwOffsetAdd + sizeof(Sig1);
			}
			if(bSigMatch)
			{				
				DWORD	dwLength = 0, dwOffset = 0;
				t_disasm da = {0};

				DWORD dwInstCount=0;
				while(dwOffset < m_dwNoOfbyteToRead - sizeof(Sig))
				{
					dwLength = m_objMaxDisassem.Disasm((char *)&pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   

					if(dwInstCount ==0x0 && dwLength == 6  && strstr(da.result,"CALL ["))
					{						
						m_dwOriData = *(DWORD *)&pbyBuff[dwOffset + 0x2];
						dwInstCount++;
					}

					else if(dwInstCount == 0x01 && dwLength == 5 && strstr(da.result,"JMP"))
					{
						if(m_dwJumpFrom + 0x6 == *(DWORD *)&pbyBuff[dwOffset + 0x1]+dwLength + dwOffset + m_dwDataAddr)
						{
							if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwJumpFrom,&m_dwJumpFrom))
							{
								return false;
							}
							return true;
						}
					}
					dwOffset += dwLength;
				}				
			}
		}
	}
	return false;	
}		


/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedOK
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.OK
					  This function repairs file by fill with zero on inserted dll into a import table.	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedOK()
{ 
	BYTE pbyBuffer[] = {0xFF, 0x15};
	if(m_pMaxPEFile->WriteBuffer(pbyBuffer, m_dwJumpFrom, sizeof(pbyBuffer), sizeof(pbyBuffer)))
	{	
		if(m_pMaxPEFile->WriteBuffer(&m_dwOriData, m_dwJumpFrom + sizeof(pbyBuffer), sizeof(m_dwOriData), sizeof(m_dwOriData)))
		{
			if(m_pMaxPEFile->FillWithZeros(0x1A, 0x2))
			{
				if(m_pMaxPEFile->FillWithZeros(m_dwTruncateOffset- 0x1, m_dwNoOfbyteToRead + 0x1))
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedDK
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.Dk
					  This function use for dectection with find the original patched byte on call .	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedDK()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections >= 3 && m_pSectionHeader[m_wAEPSec].Characteristics >= 0x60000000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x30 + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, 0x30 + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, 0x30, 0x1C))
		{		
			DWORD	dwLength = 0, dwOffset = 0, dwInstCount = 0;
			t_disasm da = {0};
			while(dwOffset < m_dwNoOfBytes && dwInstCount < 0x5)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
				if(dwLength > m_dwNoOfBytes - dwOffset)
				{
					break;
				}
				if(dwInstCount == 0x00 && dwLength == 1  && strstr(da.result,"PUSHAD"))
				{
					dwInstCount++;
				}
				else if(dwInstCount == 0x01 && dwLength == 5 && strstr(da.result,"PUSH"))
				{  
					dwInstCount++;
				}
				else if(dwInstCount == 0x02 && dwLength == 6  && strstr(da.result,"CALL ["))
				{				
					dwInstCount++;
				}
				else if(dwInstCount == 0x03 && dwLength == 1  && strstr(da.result,"POPAD"))
				{
					dwInstCount++;
				}
				else if(dwInstCount == 0x04 && dwLength == 5  && strstr(da.result,"JMP"))
				{
					dwInstCount++;
					m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] + dwLength + dwOffset + m_dwAEPUnmapped ;
					if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, 0))
					{
						return iRetStatus;
					}
					const BYTE PACHEDDK[] = {0x74,0x33,0x32,0x64,0x6D,0x2E,0x64,0x61,0x74};
					for(DWORD i = dwOffset + dwLength; i < m_dwNoOfBytes; i++)
					{
						if(memcmp(&m_pbyBuff[i], PACHEDDK, sizeof(PACHEDDK))== 0)
						{
							m_dwNoOfbyteToFill = i + sizeof(PACHEDDK);
							m_eVirusDetected = TrojanPatchedDK;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.DK"));
							return VIRUS_FILE_REPAIR;
						}
					}	
				}
				dwOffset += dwLength;
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
	Description		: Repair routine for : Trojan.Patched.DK
					  This function repairs file patched bytes on call or system call.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedDK()
{	
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, m_dwNoOfbyteToFill))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedMU
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan>patched.MU
					  This function use for dectection with find the original patched byte on call .	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedMU()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	const int PATCHED_MU_BUFF_SIZE = 0x1000;
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[PATCHED_MU_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, PATCHED_MU_BUFF_SIZE + MAX_INSTRUCTION_LEN);

	if(GetBuffer(m_dwAEPMapped, PATCHED_MU_BUFF_SIZE, PATCHED_MU_BUFF_SIZE))
	{		
		DWORD	dwLength = 0, dwOffset = 0, m_dwCallCount = 0;
		t_disasm da = {0};

		while(dwOffset < PATCHED_MU_BUFF_SIZE && m_dwCallCount < 0x3)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
			if(dwLength == 5 && strstr(da.result,"CALL"))
			{		
				m_dwOriData = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] + dwLength + dwOffset + m_dwAEPUnmapped;
				if(m_dwOriData > m_dwAEPUnmapped)
				{
					m_dwCallCount++;
					if(GetTrojanPatchedMUParam())
					{
						if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriByteOffset, &m_dwOriByteOffset))
						{
							return iRetStatus;
						}
						if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_dwOriByteOffset, m_dwNoOfByteReplace, m_dwNoOfByteReplace))
						{ 
							return iRetStatus;
						}
						m_eVirusDetected = TrojanPatchedMU;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.MU"));
						return VIRUS_FILE_REPAIR;
					}
				}
			}
			dwOffset += dwLength;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetTrojanPatchedMUParam
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: This function collects the information for Trojan.Patched.MU
--------------------------------------------------------------------------------------*/
bool CPolyTrojanPatched::GetTrojanPatchedMUParam()
{	
	WORD wSec = m_pMaxPEFile->Rva2FileOffset(m_dwOriData, &m_dwReplaceOffSet);
	if(OUT_OF_FILE == wSec)
	{
		return false;
	}
	m_dwNoOfbyteToRead = m_pSectionHeader[wSec].PointerToRawData + m_pSectionHeader[wSec].SizeOfRawData - m_dwReplaceOffSet; 
	if(m_dwNoOfbyteToRead < 0x1A)
	{
		return false;
	}
	if(m_dwNoOfbyteToRead > 0x100)
	{
		m_dwNoOfbyteToRead = 0x100;
	}

	BYTE pbyBuff[0x200 + MAX_INSTRUCTION_LEN] = {0};
	if(m_pMaxPEFile->ReadBuffer(pbyBuff, m_dwReplaceOffSet, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
	{ 
		if(pbyBuff[0x0]!=0x68)
		{
			return false;
		}
		DWORD	dwLength = 0, dwOffset = 0, dwInstCount = 0,dwAdd=0;
		m_dwNoOfByteReplace=0,m_dwJumpFrom=0;
		t_disasm da = {0};

		while(dwOffset < m_dwNoOfbyteToRead && dwInstCount < 0x8)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			
			if(dwLength > m_dwNoOfbyteToRead - dwOffset)
			{
				break;
			}
			if(dwInstCount == 0x00 && dwLength == 5  && strstr(da.result,"PUSH"))
			{
				dwAdd =*(DWORD *)&pbyBuff[dwOffset + 0x1];
				dwInstCount++;
			}
			else if(dwInstCount == 0x01 && dwLength == 1 && strstr(da.result,"POP EAX"))
			{  
				dwInstCount++;
			}
			else if(dwInstCount == 0x02 && dwLength == 5  && strstr(da.result,"CALL"))
			{
				m_dwJumpFrom = *(DWORD *)&pbyBuff[dwOffset+ 0x1 ]+ dwLength + m_dwOriData + dwOffset + dwAdd ;
				dwInstCount++;
			}
			else if(dwInstCount == 0x03 && dwLength == 1  && strstr(da.result,"POP EAX"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x04 && dwLength == 3  && strstr(da.result,"MOV EDX,[EAX-"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x05 && dwLength == 2 && strstr(da.result,"ADD EAX,EDX"))
			{  
				dwInstCount++;
			}
			else if(dwInstCount == 0x06 && dwLength == 3  && strstr(da.result,"SUB EAX,"))
			{
				m_dwJumpFrom -= pbyBuff[dwOffset + 0x2];
				m_dwNoOfByteReplace = dwLength + dwOffset + 0x4;//change if requred
				if(CheckTrojanPatchedMU())
				{
					return true;
				}
				dwInstCount++;
			}			
			dwOffset += dwLength;
		}				
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckTrojanPatchedMU
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection for Trojan.Patched.MU
--------------------------------------------------------------------------------------*/
bool CPolyTrojanPatched::CheckTrojanPatchedMU()
{
	WORD wSec = m_pMaxPEFile->Rva2FileOffset(m_dwJumpFrom, &m_dwTruncateOffset);
	if(OUT_OF_FILE == wSec)
	{
		return false;
	}
	m_dwNoOfbyteToRead=0;
	m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize - m_dwTruncateOffset; 

	if(m_dwNoOfbyteToRead < 0x100)
	{
		return false;
	}

	if(m_dwNoOfbyteToRead > 0x200)
	{
		m_dwNoOfbyteToRead = 0x200;
	}

	BYTE pbyBuffer[0x200 + MAX_INSTRUCTION_LEN] = {0};
	if(m_pMaxPEFile->ReadBuffer(pbyBuffer, m_dwTruncateOffset, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
	{ 
		if(pbyBuffer[0x0]!= 0xEB)
		{
			return false;
		}
		DWORD	dwLength = 0, dwOffset = 0, dwInstCount = 0,dwNextCallOff=0,dwByteOff=0;
		t_disasm da = {0};
		m_dwNoOfbyteToFill=0;

		while(dwOffset < m_dwNoOfbyteToRead && dwInstCount < 0x13)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&pbyBuffer[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   			
			if(dwLength > m_dwNoOfbyteToRead - dwOffset)
			{
				break;
			}
			if(dwInstCount == 0x00 && dwLength == 2  && strstr(da.result,"JMP SHORT"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x01 && dwLength == 5 && strstr(da.result,"CALL"))
			{  
				dwInstCount++;
			}
			else if(dwInstCount == 0x02 && dwLength == 1  && strstr(da.result,"PUSHAD"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x03 && dwLength == 1  && strstr(da.result,"PUSHFD"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x04 && dwLength == 5  && strstr(da.result,"CALL"))
			{
				dwNextCallOff = *(DWORD *)&pbyBuffer[dwOffset+ 0x1 ]+ dwLength + dwOffset + m_dwJumpFrom;
				dwInstCount++;
			}
			else if(dwInstCount == 0x05 && dwLength == 1 && strstr(da.result,"POP EBX"))
			{  
				dwInstCount++;
			}
			else if(dwInstCount == 0x06 && dwLength == 5  && strstr(da.result,"MOV EDI"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x07 && dwLength == 3  && strstr(da.result,"LEA ESI,[EBX+"))
			{
				dwByteOff =pbyBuffer[dwOffset+ 0x2]+ dwNextCallOff;

				dwInstCount++;
			}
			else if(dwInstCount == 0x08 && dwLength == 2  && strstr(da.result,"MOV CL,[ESI]"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x09 && dwLength == 2 && strstr(da.result,"TEST CL,CL"))
			{  
				dwInstCount++;
			}
			else if(dwInstCount == 0x0A && dwLength == 3  && strstr(da.result,"LEA EAX,[ESI+"))
			{
				dwByteOff += pbyBuffer[dwOffset+ 0x2];
				m_dwNoOfbyteToFill= dwByteOff - m_dwJumpFrom;
				const BYTE PACHEDMU[] = {0x44,0x52,0x56};
				const BYTE PACHEDMU1[] = {0x64,0x72,0x76};
				DWORD i=dwOffset;
				while(i < m_dwNoOfbyteToRead - dwOffset)
				{
					if(memcmp(&pbyBuffer[i], PACHEDMU, sizeof(PACHEDMU))== 0 || memcmp(&pbyBuffer[i], PACHEDMU1, sizeof(PACHEDMU1))== 0)
					{
						m_dwNoOfbyteToFill = i + sizeof(PACHEDMU);
						break;
					}
					i++;
				}
				if(m_dwNoOfbyteToFill == (dwByteOff - m_dwJumpFrom))
				{
					return false;
				}
				dwInstCount++;
			}
			else if(dwInstCount == 0x0B && dwLength == 1  && strstr(da.result,"PUSH EAX"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x0C && dwLength == 2  && strstr(da.result,"CALL EDI"))
			{				
				dwInstCount++;
			}
			else if(dwInstCount == 0x0D && dwLength == 3  && strstr(da.result,"LEA ESI,[EBX+"))
			{
				m_dwOriByteOffset = dwNextCallOff + pbyBuffer[dwOffset+ 0x2];
				dwInstCount++;
			}
			else if(dwInstCount == 0x0E && dwLength == 3 && strstr(da.result,"MOV EDI,[EBX+"))
			{  
				dwInstCount++;
			}
			else if(dwInstCount == 0x0F && dwLength == 2  && strstr(da.result,"ADD EDI,EBX"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x10 && dwLength == 3  && strstr(da.result,"ADD EDI"))
			{				
				dwInstCount++;
			}
			else if(dwInstCount == 0x11 && dwLength == 1  && strstr(da.result,"POPFD"))
			{
				dwInstCount++;
			}	
			else if(dwInstCount == 0x12 && dwLength == 1  && strstr(da.result,"POPAD"))
			{
				dwInstCount++;
				return true;
			}
			dwOffset += dwLength;
		}				
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedMU
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.MU
					  This function repairs file patched bytes on call or system call.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedMU()
{	
	if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwReplaceOffSet, m_dwNoOfByteReplace, m_dwNoOfByteReplace))
	{		
		if(m_pMaxPEFile->FillWithZeros(m_dwTruncateOffset, m_dwNoOfbyteToFill))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;	
}


/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedLQ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.LQ
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedLQ()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections >= 0x4 && m_wAEPSec == 0x0 && m_pSectionHeader[m_wAEPSec].Characteristics >= 0x60000000 )
	{
		m_dwNoOfbyteToRead = m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - m_dwAEPMapped;
		if(m_dwNoOfbyteToRead < 0x30)
		{
			return iRetStatus;
		}
		const int PATCHED_LQ_BUFF_SIZE = 0x1000;
		if( m_dwNoOfbyteToRead > PATCHED_LQ_BUFF_SIZE)
		{
			m_dwNoOfbyteToRead = PATCHED_LQ_BUFF_SIZE;
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PATCHED_LQ_BUFF_SIZE];

		if(!GetBuffer(m_dwAEPMapped, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{
			return iRetStatus;
		}

		if(*(DWORD *)&m_pbyBuff[0x0] == 0x83EC8B55)
		{
			const BYTE PACHEDLQ_Sig[] = {0x75,0x08,0x33,0xC0,0x33,0xC9,0x88,0x42,0x08,0xB1,0x07,0x8B,0xC6,0x24,0x0F,0x3C,0x0A,0x1C,0x69,0x2F,0x88,0x04,0x11,0xC1,0xEE,0x04,0x49,0x79,0xEE,0x5E,0xC9,0xC2};

			for(DWORD dwOffset = 0; dwOffset < m_dwNoOfbyteToRead - sizeof(PACHEDLQ_Sig); dwOffset++)
			{
				if(memcmp(&m_pbyBuff[dwOffset], PACHEDLQ_Sig, sizeof(PACHEDLQ_Sig)) == 0)
				{
					m_dwNoOfbyteToFill = 0x0;
					const BYTE PACHEDLQ[] = {0x2E,0x64,0x6C,0x6C,0x00,0x53,0x66,0x63,0x47,0x65,0x74,0x46,0x69,0x6C,0x65,0x73};

					if(m_pSectionHeader[m_wAEPSec + 0x1].SizeOfRawData >= 0x200)
					{
						if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_pSectionHeader[m_wAEPSec + 0x1].PointerToRawData + m_pSectionHeader[m_wAEPSec + 0x1].SizeOfRawData - 0x200 , 0x200, 0x200))
						{ 
							return iRetStatus;
						}
						m_dwNoOfbyteToFill =0x200;
					}
					else if(m_pSectionHeader[m_wAEPSec + 0x1].SizeOfRawData < 0x200 && m_pSectionHeader[m_wAEPSec + 0x1].SizeOfRawData >=  sizeof(PACHEDLQ))
					{
						m_dwNoOfbyteToFill = m_pSectionHeader[m_wAEPSec + 0x1].SizeOfRawData;
						if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_pSectionHeader[m_wAEPSec + 0x1].PointerToRawData, m_dwNoOfbyteToFill, m_dwNoOfbyteToFill))
						{
							return iRetStatus;
						}
					}
					if(m_dwNoOfbyteToFill != 0)
					{							
						for(DWORD dwOffset = 0; dwOffset < m_dwNoOfbyteToFill - sizeof(PACHEDLQ); dwOffset++)
						{
							if(memcmp(&m_pbyBuff[dwOffset], PACHEDLQ, sizeof(PACHEDLQ))== 0)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.LQ"));
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
	Function		: DetectTrojanPatchedDO
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.DO
					  This function use for dectection with find the original patched byte on call
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedDO()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	const int PATCHED_DO_BUFF_SIZE = 0x200;
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[PATCHED_DO_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, PATCHED_DO_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(GetBuffer(m_dwAEPMapped, PATCHED_DO_BUFF_SIZE, PATCHED_DO_BUFF_SIZE))
	{		
		DWORD	dwLength = 0x0, dwOffset = 0x0,dwCallCount = 0x0;
		t_disasm da = {0};

		while(dwOffset < PATCHED_DO_BUFF_SIZE && dwCallCount < 0x5)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
			if(dwLength > PATCHED_DO_BUFF_SIZE - dwOffset)
			{
				break;
			}
			if(dwLength == 0x5 && strstr(da.result,"CALL"))
			{
				dwCallCount++;
				m_dwJumpFrom = m_dwAEPUnmapped + dwOffset;
				m_dwDataAddr = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] + dwLength + dwOffset + m_dwAEPUnmapped;

				if(GetTrojanPatchedDOParam())
				{
					m_eVirusDetected = TrojanPatchedDO;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.DO"));
					return VIRUS_FILE_REPAIR;
				}
			}
			dwOffset += dwLength;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetTrojanPatchedDOParam
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Collects basic information for : Trojan.Patched.DO
--------------------------------------------------------------------------------------*/
bool CPolyTrojanPatched::GetTrojanPatchedDOParam()
{	
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwDataAddr, &m_dwTruncateOffset))
	{
		return false;
	}
	if(m_pMaxPEFile->m_dwFileSize > m_dwTruncateOffset )
	{  
		m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize - m_dwTruncateOffset; 
	}
	if(m_dwNoOfbyteToRead < 0x20)
	{
		return false;
	}
	if(m_dwNoOfbyteToRead > 0x200)
	{
		m_dwNoOfbyteToRead = 0x200;
	}
	BYTE pbyBuff[0x200 + MAX_INSTRUCTION_LEN] = {0};
	if(m_pMaxPEFile->ReadBuffer(pbyBuff, m_dwTruncateOffset, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
	{
		if(pbyBuff[0x0]!=0x60)
		{
			return false;
		}

		DWORD	dwLength = 0x0, dwOffset = 0x0,dwInstCount = 0x0;
		t_disasm da = {0};

		while(dwOffset < m_dwNoOfbyteToRead && dwInstCount < 0x5)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
			if(dwLength > m_dwNoOfbyteToRead - dwOffset)
			{
				break;
			}
			if(dwInstCount == 0x00 && dwLength == 0x1  && strstr(da.result,"PUSHAD"))
			{
				dwInstCount++;
				const BYTE bySig[] = {0x53,0x6F,0x66,0x74,0x77,0x61,0x72,0x65,0x5C,0x47,0x6F,0x6F,0x67,0x6C,0x65,0x5C};
				// Software\Google\...

				for(DWORD i = dwOffset + dwLength; i < m_dwNoOfbyteToRead; i++)
				{
					if(memcmp(&pbyBuff[i], bySig, sizeof(bySig))== 0)
					{
						dwInstCount++;		
						break;
					}
				}
			}
			else if(dwInstCount == 0x02 && dwLength == 0x5  && strstr(da.result,"CALL"))
			{
				DWORD dwCallOffset=*(DWORD *)&pbyBuff[dwOffset + 0x1] + dwLength + dwOffset + m_dwDataAddr;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwCallOffset, &dwCallOffset))
				{
					return false;
				}
				dwOffset = dwCallOffset - m_dwTruncateOffset - dwLength;
				dwInstCount++;
			}
			else if(dwInstCount == 0x03 && dwLength == 0x1  && strstr(da.result,"POPAD"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x04 && dwLength == 0x5  && strstr(da.result,"PUSH"))
			{
				m_dwOriData =*(DWORD *)&pbyBuff[dwOffset + 0x1]- m_dwImageBase;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriData, 0))
				{
					return false;
				}				
				m_dwOriData =m_dwOriData - m_dwJumpFrom - 0x5 ;
				m_dwNoOfbyteToRead = dwOffset + dwLength;
				dwInstCount++;
				return true;
			}
			dwOffset += dwLength;
		}	
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.DO
					  This function repairs file patched bytes on call.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedDO()
{
	if(m_pMaxPEFile->WriteBuffer(&m_dwOriData, m_dwAEPMapped + m_dwJumpFrom - m_dwAEPUnmapped + 0x1 , sizeof(DWORD), sizeof(DWORD)))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwTruncateOffset , m_dwNoOfbyteToRead ))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedMJ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.MJ
					  This function use for dectection with find the original patched byte on call	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedMJ()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections != 0x4 || m_wAEPSec != 0x0 || m_dwAEPUnmapped !=0x1642)
	{
		return iRetStatus;
	}
	//Section Characteristics check
	if(	m_pSectionHeader[0x0].Characteristics != 0x60000020 || m_pSectionHeader[0x1].Characteristics !=  0xC0000040 ||
		m_pSectionHeader[0x2].Characteristics != 0x40000040 || m_pSectionHeader[0x3].Characteristics !=  0x42000040 )
	{
		return iRetStatus;
	}	
	if(	m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size == 0x50 && m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress == 0x270 && 
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].Size == 0x4C && memcmp(m_pSectionHeader[0x2].Name, ".rsrc", 5) == 0)
	{
		const int PATCHED_MJ_BUFF_SIZE = 0x400;
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_dwTruncateOffset =0x0;
		m_pbyBuff = new BYTE[PATCHED_MJ_BUFF_SIZE];
		if(!GetBuffer(0xA26, 0x5, 0x5))
		{
			return iRetStatus;
		}
		//Check for Patched call 
		if((m_pbyBuff[0x0]!=0xE8 && m_pbyBuff[0x0]!=0xE9 )|| *(DWORD *)&m_pbyBuff[0x1]==0x0)
		{
			return iRetStatus;
		}
		m_dwTruncateOffset =*(DWORD *)&m_pbyBuff[0x1]+ 0x162B;	
		WORD wSec=m_pMaxPEFile->Rva2FileOffset(m_dwTruncateOffset, &m_dwTruncateOffset);
		if(OUT_OF_FILE ==wSec || wSec !=m_wAEPSec || m_dwTruncateOffset ==0x0)
		{
			return iRetStatus;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_pSectionHeader[0x2].PointerToRawData + 0x250, PATCHED_MJ_BUFF_SIZE, PATCHED_MJ_BUFF_SIZE))
		{
			return iRetStatus;
		}
		// Check for Clean file 
		const BYTE bySig[] = {0x28,0x00,0x78,0x00,0x70,0x00,0x73,0x00,0x70,0x00,0x5f,0x00,0x73,0x00,0x70,0x00,0x32,0x00,0x5f,0x00,0x72,0x00,0x74,0x00,0x6d,0x00,0x2e,0x00,0x30,0x00,0x34,0x00,0x30,0x00,0x38,0x00,0x30,0x00,0x33,0x00,0x2d,0x00,0x32,0x00,0x31,0x00,0x35,0x00,0x38};
		const BYTE bySig1[] = {0x77,0x00,0x73,0x00,0x32,0x00,0x68,0x00,0x65,0x00,0x6c,0x00,0x70,0x00,0x2e,0x00,0x64,0x00,0x6c,0x00,0x6c};

		for(DWORD dwOffset = 0; dwOffset <= PATCHED_MJ_BUFF_SIZE - sizeof(bySig); dwOffset++)
		{
			if(memcmp(&m_pbyBuff[dwOffset], bySig, sizeof(bySig)) == 0)
			{	
				for(dwOffset += sizeof(bySig); dwOffset <= PATCHED_MJ_BUFF_SIZE - sizeof(bySig1); dwOffset++)
				{
					if(memcmp(&m_pbyBuff[dwOffset], bySig1, sizeof(bySig1)) == 0x00)
					{
						if(m_pMaxPEFile->m_dwFileSize > m_dwTruncateOffset )
						{  
							m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize - m_dwTruncateOffset + 0x20; 
						}
						if(m_dwNoOfbyteToRead < 0x35)
						{
							return iRetStatus;
						}
						if(m_dwNoOfbyteToRead > 0x40)
						{
							m_dwNoOfbyteToRead = 0x40;
						}
						if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_dwTruncateOffset - 0x20, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
						{
							return iRetStatus;
						}
						//Check for file is ws2help.dll file or Not 
						DWORD dwSigFind=0x0;
						const BYTE bySigDll[] = {0x77,0x73,0x32,0x68,0x65,0x6C,0x70,0x2E,0x70,0x64,0x62};
						for(DWORD dwSigOffSet=0;dwSigOffSet < 0x20 - sizeof(bySigDll);dwSigOffSet++)
						{
							if(memcmp(&m_pbyBuff[dwSigOffSet], bySigDll, sizeof(bySigDll))== 0)
							{
								dwSigFind++;
								break;
							}
						}
						if(dwSigFind==0)
						{
							return iRetStatus;
						}

						DWORD	dwLength = 0x0, dwInsCount = 0x0;
						dwOffset = 0x20;
						t_disasm da = {0};
						//Virus Code check and calculate Number of byte patched by Virus.
						while(dwOffset < m_dwNoOfbyteToRead && dwInsCount < 0x3)
						{
							dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
							if(dwLength > m_dwNoOfbyteToRead  - dwOffset)
							{
								return iRetStatus;
							}
							if(dwInsCount ==0x0 && dwLength == 1 && strstr(da.result,"PUSHAD"))
							{
								dwInsCount++;
							}
							else if(dwInsCount ==0x01 && dwLength == 5 && strstr(da.result,"MOV E"))
							{
								//Check API which is same name of Virus File name Loaded by virus.  
								const BYTE bySig2[] = {0x53,0x6C,0x65,0x65,0x70};
								//File name is sleep 
								DWORD dwLoadFileOffSet = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] - m_dwImageBase;
								if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwLoadFileOffSet, &dwLoadFileOffSet)|| dwLoadFileOffSet ==0x0)
								{
									return iRetStatus;
								}
								BYTE pbyBuff[0x5]={0};
								if(!m_pMaxPEFile->ReadBuffer(pbyBuff, dwLoadFileOffSet, 0x5, 0x5))
								{
									return iRetStatus;
								}
								if(!memcmp(&pbyBuff[0x0], bySig2, sizeof(bySig2))== 0)
								{
									return iRetStatus;
								}
								dwInsCount++;
							}		
							else if(dwInsCount ==0x02 && dwLength == 1 && strstr(da.result,"POPAD"))
							{
								dwInsCount++;
								//Calculate Number of byte to fill with zero
								m_dwNoOfbyteToRead = dwOffset + dwLength - 0x20;
								m_eVirusDetected = TrojanPatchedMJ;
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.MJ"));
								return VIRUS_FILE_REPAIR;
							}
							dwOffset += dwLength;
						}						
					}					
				}
				return iRetStatus;
			}			
		}
		return iRetStatus;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedMJ
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.MJ
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedMJ()
{
	BYTE pbyBuffer[]={0xC3,0x90,0x90,0x90,0x90};
	if(m_pMaxPEFile->WriteBuffer(pbyBuffer, 0xA26, sizeof(pbyBuffer), sizeof(pbyBuffer)))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwTruncateOffset , m_dwNoOfbyteToRead ))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedHB
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.HB
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedHB()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec !=0x00 || (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	if(m_wNoOfSections >= 0x4 && m_pSectionHeader[m_wAEPSec].Characteristics >= 0x60000020 && m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 0x1000) 
	{
		m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize - m_dwAEPMapped; 
		if(m_dwNoOfbyteToRead < 0x2A)
		{
			return iRetStatus;
		}
		if(m_dwNoOfbyteToRead > 0x30)
		{
			m_dwNoOfbyteToRead = 0x30;
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[m_dwNoOfbyteToRead + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, m_dwNoOfbyteToRead + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{	
			const BYTE bySigAepByte[] = {0x8B,0x44,0x24,0x08,0x48,0x75,0x15,0x50,0x50,0x68};	
			if(memcmp(m_pbyBuff, bySigAepByte, sizeof(bySigAepByte)) != 0)
			{
				return iRetStatus;
			}
			DWORD	dwLength = 0, dwOffset = 0;
			t_disasm da = {0};
			DWORD dwInstCount = 0;
			while(dwOffset < m_dwNoOfbyteToRead && dwInstCount < 0x7)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
				if(dwLength > m_dwNoOfbyteToRead - dwOffset)
				{
					break;
				}
				if(dwInstCount <= 0x1 && dwLength == 5  && strstr(da.result,"PUSH"))
				{
					dwInstCount++;
				}
				else if((dwInstCount == 0x02 || dwInstCount == 0x03) && dwLength == 1 && strstr(da.result,"PUSH"))
				{  
					dwInstCount++;
				}
				else if(dwInstCount == 0x04 && dwLength == 5  && strstr(da.result,"MOV EAX,"))
				{				
					dwInstCount++;
				}
				else if(dwInstCount == 0x05 && dwLength == 2 && strstr(da.result,"CALL"))
				{				
					dwInstCount++;
				}
				else if(dwInstCount == 0x06 && dwLength == 5  && strstr(da.result,"JMP"))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.HB"));
					return VIRUS_FILE_DELETE;
				}
				dwOffset += dwLength;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedOM
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.OM
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedOM()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.MinorSubsystemVersion == 0x0) && (m_pMaxPEFile->m_stPEHeader.Subsystem == 0x02 || m_pMaxPEFile->m_stPEHeader.Subsystem == 0x03)&& 
		(m_pMaxPEFile->m_stPEHeader.NumberOfSections >= 0x3) &&
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].VirtualAddress !=0x00) && (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size >= 0x28) &&
		((m_pMaxPEFile->m_stPEHeader.DataDirectory[0x6].VirtualAddress == 0x0000 && m_pMaxPEFile->m_stPEHeader.DataDirectory[0x6].Size == 0x0000) || 
		(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".Silvana", 8) == 0 ) || (memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".NewIT", 6) == 0)) &&
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress == 0x0000) && (m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].Size ==0x0000))
	{
		//Check section where Current Import Address Table Present 
		m_dwDLLFileOffset = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].VirtualAddress;
		WORD wSec = m_pMaxPEFile->Rva2FileOffset(m_dwDLLFileOffset, &m_dwDLLFileOffset);
		if(OUT_OF_FILE == wSec  || m_dwDLLFileOffset == 0x0 )
		{
			return iRetStatus;
		}
		if(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size > m_pSectionHeader[wSec].SizeOfRawData)
		{
			//corrupt infected File handling..
			m_dwNoOfbyteToRead = m_pSectionHeader[wSec].PointerToRawData + m_pSectionHeader[wSec].SizeOfRawData - m_dwDLLFileOffset; 
		}
		else
		{
			m_dwNoOfbyteToRead = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size;
		}
		const int PATCHED_OM_BUFF_SIZE = 0x1000;
		if(m_dwNoOfbyteToRead >= m_pMaxPEFile->m_dwFileSize || m_dwNoOfbyteToRead > PATCHED_OM_BUFF_SIZE )
		{
			return iRetStatus;
		}

		//Corrupt File handling which is not store Full size of Import Address Table
		if(m_dwDLLFileOffset+ m_dwNoOfbyteToRead + 0x14 <= m_pMaxPEFile->m_dwFileSize)
		{
			m_dwNoOfbyteToRead +=0x14;
		}
		if(PATCHED_OM_BUFF_SIZE < m_dwNoOfbyteToRead)
		{
			return iRetStatus;
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}		
		m_pbyBuff = new BYTE[PATCHED_OM_BUFF_SIZE];
				
		//Get Current Import Address Table Data
		if(!GetBuffer(m_dwDLLFileOffset, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{			
			return iRetStatus;		
		}
		m_dwImportTableAdd = *(DWORD *)&m_pbyBuff[0x10];
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwImportTableAdd, 0))
		{
				return iRetStatus;
		}
		if(m_dwImportTableAdd ==0x0 || *(DWORD *)&m_pbyBuff[0x0] > m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].VirtualAddress )
		{
			return iRetStatus;
		}

		DWORD dwSigMatchedCount=0x0,dwCheckEndOfImportTable=0x0;
		//Calculate No.Of item Present into Import address Table also calcutale Size for searching Original Import table data.
		const BYTE byCheckEndOfImport[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		for(DWORD i = 0x10; i < m_dwNoOfbyteToRead - sizeof(byCheckEndOfImport) ; i += 0x14)
		{	
			dwSigMatchedCount++;
			//check Import Address Table end.
			if(memcmp(&m_pbyBuff[i + 0x4], byCheckEndOfImport, sizeof(byCheckEndOfImport)) == 0x00)
			{
				dwCheckEndOfImportTable++;
				break;
			}			
			if(m_dwImportTableAdd > *(DWORD *)&m_pbyBuff[i + 0x14] && *(DWORD *)&m_pbyBuff[i + 0x4]!=0x0 && *(DWORD *)&m_pbyBuff[i + 0x10]!= 0x0)
			{
				m_dwImportTableAdd = *(DWORD *)&m_pbyBuff[i + 0x14];
			}			
		}
		if(m_dwImportTableAdd != 0x0 && dwCheckEndOfImportTable !=0x0)
		{
			DWORD dwImportTableAdd = 0x0;
			WORD wSection = m_pMaxPEFile->Rva2FileOffset(m_dwImportTableAdd, &dwImportTableAdd);
			if(OUT_OF_FILE == wSection)
			{
				return iRetStatus;
			}
			//Search Original Bytes Where Point out current Import Address Table data.
			dwImportTableAdd=m_pSectionHeader[wSection].PointerToRawData ;
			m_dwNoOfbyteToFill=m_pSectionHeader[wSection].SizeOfRawData;
			m_dwImportTableAdd=m_pSectionHeader[wSection].VirtualAddress;
			m_dwSize = dwSigMatchedCount * 0x14;

			if(m_dwNoOfbyteToFill > 0xA0000 || m_dwNoOfbyteToFill < m_dwSize)
			{
				return iRetStatus;
			}
			BYTE *pbyBuff = new BYTE[0xA0000];
			if(pbyBuff)
			{
				if(m_pMaxPEFile->ReadBuffer(pbyBuff, dwImportTableAdd, m_dwNoOfbyteToFill, m_dwNoOfbyteToFill))
				{ 								
					for(DWORD dwOffset = 0; dwOffset < (m_dwNoOfbyteToFill - m_dwSize); dwOffset++)
					{
						if(memcmp(&pbyBuff[dwOffset], &m_pbyBuff[0x0], 0x4) == 0x00 && memcmp(&pbyBuff[dwOffset + 0xC], &m_pbyBuff[0xC], 0x8) == 0x00)
						{
							if( m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].VirtualAddress == m_dwImportTableAdd + dwOffset)
							{
								delete []pbyBuff;
								pbyBuff = NULL;
								return iRetStatus;
							}
							//check Import Address Table end.
							if(memcmp(&pbyBuff[dwOffset + m_dwSize - 0x14], byCheckEndOfImport, sizeof(byCheckEndOfImport)) == 0x00 ||
								(memcmp(&pbyBuff[dwOffset + m_dwSize - 0x14], &m_pbyBuff[m_dwSize - 0x14], 0x4) == 0x00 &&
								 memcmp(&pbyBuff[dwOffset + m_dwSize - 0x8], &m_pbyBuff[m_dwSize - 0x8], 0x8) == 0x00 &&
								 memcmp(&pbyBuff[dwOffset + m_dwSize ], byCheckEndOfImport, sizeof(byCheckEndOfImport)) == 0x0))
							{								
								DWORD dwCurrentImportOffset=0x14,dwSigCount=0x02;
								if(dwSigMatchedCount >0x1)
								{
									for(DWORD dwCheckOffset = dwOffset + 0x14 ; dwCheckOffset < dwOffset + m_dwSize - 0x14 ; dwCheckOffset+=0x14)
									{
										//compared Copy Import Address Table data into a original Import Address Table data
										dwSigCount++;
										if((!memcmp(&pbyBuff[dwCheckOffset], &m_pbyBuff[dwCurrentImportOffset], 0x4) == 0x00) || (!memcmp(&pbyBuff[dwCheckOffset + 0xC], &m_pbyBuff[dwCurrentImportOffset + 0xC], 0x8) == 0x00))
										{
											break;
										}												
										dwCurrentImportOffset +=0x14;
									}
								}
								if(dwSigCount == dwSigMatchedCount )
								{													
									m_dwTruncateOffset=0;	
									//Check Current Import Table if last section and section name is this.
									if(wSec == m_pMaxPEFile->m_stPEHeader.NumberOfSections -1 && memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".Silvana", 8) == 0 )
									{
										m_dwTruncateOffset=1;
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.LM"));
									}
									else if(wSec == m_pMaxPEFile->m_stPEHeader.NumberOfSections -1 && memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".NewIT", 6) == 0)
									{
										m_dwTruncateOffset=1;
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.OM"));
									}
									else if(m_wAEPSec != m_wNoOfSections - 1 && memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".idata", 6) != 0)    // Changes done here to skip samples of Virus.Win32.Score.3072.c
									{
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.OF"));
									}
									else
									{
										delete []pbyBuff;
										pbyBuff = NULL;
										return iRetStatus;
									}
									//Calculate Original Offset address of Import Address Table ans Size
									m_dwImportTableAdd += dwOffset;
									m_eVirusDetected = TrojanPatchedOM;
									iRetStatus = VIRUS_FILE_REPAIR;						
									break;
								}
							}
						}
					}	
				}
				delete []pbyBuff;
				pbyBuff = NULL;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedOM
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.OM
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedOM()
{
	if(m_pMaxPEFile->WriteBuffer(&m_dwImportTableAdd, m_pMaxPEFile->m_stPEOffsets.NoOfDataDirs + 0xC, sizeof(DWORD), sizeof(DWORD)))
	{
		if(m_pMaxPEFile->WriteBuffer(&m_dwSize, m_pMaxPEFile->m_stPEOffsets.NoOfDataDirs + 0x10, sizeof(DWORD), sizeof(DWORD)))
		{
			if(m_dwTruncateOffset != 0)
			{
				if(m_pMaxPEFile->RemoveLastSections())
				{
					return REPAIR_SUCCESS;
				}
			}
			else if(m_pMaxPEFile->FillWithZeros(m_dwDLLFileOffset, m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedHG
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for: Trojan.Patched.HG
					  A : AEP changed on infection.
                      B : AEP Starts from Patched Bytes and no.of bytes patched varies from file to file.
                      C : Patched Bytes -> it's a function to load libray which is having malicious program.
		              D : After Loading malicious Libray takes jump to original AEP.	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedHG()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL || 
		(m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000000) != 0xE0000000)
	{
		return iRetStatus;
	}
	if(m_wNoOfSections >= 0x4) 
	{
		m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize - m_dwAEPMapped; 
		if(m_dwNoOfbyteToRead < 0x50)
		{
			return iRetStatus;
		}
		if(m_dwNoOfbyteToRead > 0x60)
		{
			m_dwNoOfbyteToRead = 0x60;
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[m_dwNoOfbyteToRead + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, m_dwNoOfbyteToRead + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{				
			if(m_pbyBuff[0x0]!= 0x83 || m_pbyBuff[0x01]!= 0x7C)
			{
				return iRetStatus;
			}
			DWORD	dwLength = 0, dwOffset = 0, dwCallOffset = 0, dwOriByteOff = 0;
			t_disasm da = {0};
			DWORD dwInstCount = 0;
			while(dwOffset < m_dwNoOfbyteToRead && dwInstCount < 0xE)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
				if(dwLength > m_dwNoOfbyteToRead - dwOffset)
				{
					break;
				}
				if(dwInstCount == 0x0 && dwLength == 5  && strstr(da.result,"CMP DWORD PTR [E"))
				{
					dwInstCount++;
				}
				else if(dwInstCount == 0x01  && dwLength == 2 && strstr(da.result,"JNZ"))
				{  
					//Calculate offset to obtain original AEP after 1st JMP 
					dwOriByteOff = m_pbyBuff[dwOffset + 0x1]+ dwOffset + dwLength;
					//Calculate no. of bytes patched by virus
					m_dwNoOfbyteToRead = m_pbyBuff[dwOffset + 0x1] + dwOffset + dwLength + 0x5;
					if(m_dwNoOfbyteToRead > 0x60)
					{
						return iRetStatus;
					}
					dwCallOffset = m_pbyBuff[dwOffset + 0x1] + dwLength + dwOffset + m_dwAEPUnmapped;
					if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwCallOffset, &dwCallOffset))
					{
						return iRetStatus;
					}
					dwInstCount++;
				}
				else if(dwInstCount == 0x02 && dwLength == 7  && strstr(da.result,"CMP BYTE PTR ["))
				{				
					dwInstCount++;
				}
				else if(dwInstCount == 0x03  && dwLength == 2 && strstr(da.result,"JNZ"))
				{  
					//Calculate offset to obtain original AEP after 2nd JMP 
					DWORD dwOriginalAEPOffset = m_pbyBuff[dwOffset + 0x1] + dwLength + dwOffset + m_dwAEPUnmapped;
					if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwOriginalAEPOffset, &dwOriginalAEPOffset))
					{
						return iRetStatus;
					}
					//Comparing above 2 calculated offsets which must be same
					if(dwOriginalAEPOffset != dwCallOffset)
					{
						return iRetStatus;
					}
					dwInstCount++;
				}
				else if(dwInstCount == 0x04 && dwLength == 1 && strstr(da.result,"PUSHAD"))
				{				
					dwInstCount++;
				}
				else if((dwInstCount == 0x5 || dwInstCount == 0x06 ) && dwLength == 5  && strstr(da.result,"MOV"))
				{
					dwInstCount++;
				}
				else if((dwInstCount == 0x08 ||dwInstCount == 0x07) && dwLength == 2  && strstr(da.result,"MOV EAX,"))
				{				
					dwInstCount++;
				}
				else if((dwInstCount == 0x09 || dwInstCount == 0x0B)&& dwLength == 2 && strstr(da.result,"CALL"))
				{				
					dwInstCount++;
				}
				else if(dwInstCount == 0x0A && dwLength == 5 && strstr(da.result,"PUSH"))
				{				
					dwInstCount++;
				}
				else if(dwInstCount == 0x0C && dwLength == 1 && strstr(da.result,"POPAD"))
				{				
					dwInstCount++;
				}
				else if(dwInstCount == 0x0D && dwLength == 5 &&  dwOriByteOff == dwOffset && strstr(da.result,"JMP"))
				{
					dwInstCount++;
					//Original AEP calculation
					m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[dwOffset + 0x1] + dwLength + dwOffset + m_dwAEPUnmapped;
					if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, 0))
					{
						return iRetStatus;
					}
					m_eVirusDetected = TrojanPatchedHG;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.HG"));
					return VIRUS_FILE_REPAIR;
				}
				dwOffset += dwLength;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedHG
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.HG
					  This function repairs files by replacing original AEP & patched bytes by zero.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedHG()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, m_dwNoOfbyteToRead))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedHZ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.HZ
					   A : AEP changed on infection.
                       B : AEP Starts from Patched Bytes and no.of bytes patched varies from file to file.
                       C : Patched Bytes -> it's a function to load library and Load %System%\wsconfig.db file 
						   which performs malicious activity.
		               D : After Loading Library ,it configures itself & takes jump to original AEP.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedHZ()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL || ( m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000000)!=0xE0000000)
	{
		return iRetStatus;
	}
	if(m_wNoOfSections >= 0x4) 
	{ 
		 if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int PATCHED_HZ_BUFF_SIZE	= 0x200;
		m_pbyBuff = new BYTE[PATCHED_HZ_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return false;
		}
		memset(m_pbyBuff, 0, PATCHED_HZ_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_dwAEPMapped, 0x5 , 0x5))
		{
			return iRetStatus;
		}
		//Check call at AEP
		if(m_pbyBuff[0x0]!= 0xE9 && m_pbyBuff[0x0]!= 0xE8 )
		{
			return iRetStatus;
		}		
        DWORD dwJumpTo = *(DWORD *)&m_pbyBuff[0x01] + m_dwAEPUnmapped + 0x5;
        DWORD dwJumpToUnmapped = dwJumpTo;
		WORD wSec = m_pMaxPEFile->Rva2FileOffset(dwJumpTo, &dwJumpTo);
		if(OUT_OF_FILE == wSec)
		{
			return iRetStatus;
		}					
		m_dwNoOfbyteToRead=0;
		m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize - dwJumpTo; 
		if(m_dwNoOfbyteToRead < 0x105)
		{
			return iRetStatus;
		}
		if(m_dwNoOfbyteToRead > PATCHED_HZ_BUFF_SIZE)
		{
			m_dwNoOfbyteToRead = PATCHED_HZ_BUFF_SIZE;
		}			
		if(GetBuffer(dwJumpTo, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{				
			if(m_pbyBuff[0x0]!=0x60 || m_pbyBuff[0x01]!=0x9C)
			{
				return iRetStatus;
			}
			DWORD	dwLength = 0, dwOffset = 0, dwInstCount = 0;
			t_disasm da = {0};
			while(dwOffset < m_dwNoOfbyteToRead && dwInstCount < 0xC)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
				if(dwLength > m_dwNoOfbyteToRead - dwOffset)
				{
					break;
				}
				if(dwInstCount <= 0x2 && dwLength == 5  && strstr(da.result,"PUSH"))
				{
					dwInstCount++;
				}
				else if((dwInstCount==0x03 || dwInstCount==0x05 ) && dwLength == 3  && strstr(da.result,"ADD"))
				{				
					dwInstCount++;
				}
				else if((dwInstCount==0x04 || dwInstCount==0x06 ) && dwLength == 2 && strstr(da.result,"TEST"))
				{ 
					dwInstCount++;
				}
				else if(dwInstCount==0x07 && dwLength == 6 && strstr(da.result,"MOV EAX,FS:[30]"))
				{ 
				//Loop taken as signature where library is loaded   
				const BYTE bySig[] = {0x64,0xA1,0x30,0x00,0x00,0x00,0x8B,0x40,0x0C,0x8B,0x40,0x1C,0x8B,0x00,0x8B,0x40,0x08,0x8B,0xE8,0x8B,0x40,0x3C,0x8B,0x44,0x05,0x78,0x8B,0x4C,0x05,0x18,0x8B,0x5C,0x05,0x20};
				const BYTE bySig1[] = {0x8B,0x74,0x05,0x24,0x03,0xF5,0x0F,0xB7,0x34,0x4E,0x8B,0x7C,0x05,0x1C,0x03,0xFD,0x8B,0x3C,0xB7,0x03,0xFD,0x8B,0xC7};
				for(dwOffset; dwOffset <= m_dwNoOfbyteToRead - sizeof(bySig) && dwInstCount ==0x7 ;dwOffset++)
				{
					if(memcmp(&m_pbyBuff[dwOffset], bySig, sizeof(bySig))== 0)
					{	
						dwInstCount++;
						for(dwOffset += sizeof(bySig); dwOffset <= m_dwNoOfbyteToRead - sizeof(bySig1) && dwInstCount ==0x8; dwOffset++)
						{
							if(memcmp(&m_pbyBuff[dwOffset], bySig1, sizeof(bySig1)) == 0x00)
							{
								dwOffset +=sizeof(bySig1);
								dwInstCount++;
								break;			
							}
						}
						}
				}
				if(dwInstCount !=0x9)
				{
					return iRetStatus;
				}
				}
				else if(dwInstCount == 0x09 && dwLength == 1 && strstr(da.result,"POPFD"))
				{				
					dwInstCount++;
				}		
				else if(dwInstCount == 0x0A && dwLength == 1 && strstr(da.result,"POPAD"))
				{				
					dwInstCount++;
				}
				else if(dwInstCount == 0x0B && dwLength == 5  && strstr(da.result,"JMP"))
				{
					dwInstCount++;
					//Original AEP calculation
					m_dwOriginalAEP=*(DWORD *)&m_pbyBuff[dwOffset + 0x1] + dwLength + dwOffset + dwJumpToUnmapped;
					if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, 0))
					{
						return iRetStatus;
					}
					m_dwReplaceOffSet =0x0;
					//check if new section added by patched virus
					if(wSec == m_wAEPSec && m_wAEPSec == m_pMaxPEFile->m_stPEHeader.NumberOfSections - 0x1 
						&& m_dwAEPMapped == m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData)
					{
						m_dwReplaceOffSet =0x1;
					}
					//Calculate no. of bytes patched by virus
					m_dwNoOfbyteToRead = dwOffset + dwLength;
					m_eVirusDetected = TrojanPatchedHZ;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.HZ"));
					return VIRUS_FILE_REPAIR;
				}
				dwOffset += dwLength;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedHZ
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.HZ
					  This function repairs files by replacing original AEP & patched bytes by zero & 
					  if new Section added by Virus then remove that section. 
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedHZ()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_dwReplaceOffSet!= 0x0)
		{
			if(m_pMaxPEFile->RemoveLastSections())
			{
				return REPAIR_SUCCESS;
			}
		}
		else if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped , sizeof(DWORD)+ 0x1 ))
		{
			if(m_pMaxPEFile->FillWithZeros(m_dwJumpFrom , m_dwNoOfbyteToRead ))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedHP
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.HP
					  A : Virus Infect on only Srf.dll file.
                      B : only three bytes patched.
                      C : Patched Bytes -> it's an operation of XOR eax,eax and INC eax. 	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedHP()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec != 0x0 || m_pMaxPEFile->m_stPEHeader.Subsystem != 0x03 || 
		m_pMaxPEFile->m_stPEHeader.NumberOfSections != 0x4 || m_pSectionHeader[m_wAEPSec].SizeOfRawData != 0x018000)
	{
		return iRetStatus;
	}
	if((m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x0A) && (m_pMaxPEFile->m_stPEHeader.MinorOSVersion == 0x1) &&
		(m_pMaxPEFile->m_stPEHeader.MinorSubsystemVersion == 0x0A) && (m_pMaxPEFile->m_stPEHeader.Characteristics ==0x210E)&&
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].VirtualAddress !=0x0) && (m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size !=0x0) &&
		(m_pSectionHeader[0].Characteristics == 0x60000020) && (m_pSectionHeader[1].Characteristics == 0xC0000040)&&
		(m_pSectionHeader[2].Characteristics == 0x40000040) && (m_pSectionHeader[3].Characteristics == 0x42000040))
	{	 
		BYTE pbyBuff[0x04]= {0};
		if(!m_pMaxPEFile->ReadBuffer(pbyBuff, 0xECE9, 0x4, 0x4))
		{
			return iRetStatus;
		}
		if(*(WORD *)&pbyBuff[0x0] != 0x9090 || pbyBuff[0x02] != 0x90)
		{
			return iRetStatus;
		}
		int PATCHED_HP_BUFF_SIZE = 0x280;
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[PATCHED_HP_BUFF_SIZE];		
		if(!GetBuffer(0x754, PATCHED_HP_BUFF_SIZE, PATCHED_HP_BUFF_SIZE))
		{ 
			return iRetStatus;
		}
		//Check for clean file
		const BYTE byCheckSig[] = {0x53,0x00,0x66,0x00,0x63,0x00,0x41,0x00,0x70,0x00,0x69};//S.f.c.A.p.i
		const BYTE byCheckSig1[] = {0x73,0x00,0x75,0x00,0x62,0x00,0x73,0x00,0x79,0x00,0x73,0x00,0x5c,0x00,0x73,0x00,0x6d,0x00,0x5c,0x00,0x73,0x00,0x66,0x00,0x63,0x00,0x5c,0x00,0x64,0x00,0x6c,0x00,0x6c};//s.u.b.s.y.s.\.s.m.\.s.f.c.\.d.l.l
		const BYTE byCheckSig2[] = {0x57,0x00,0x69,0x00,0x6e,0x00,0x6c,0x00,0x6f,0x00,0x67,0x00,0x6f,0x00,0x6e,0x00,0x00,0x00,0x53,0x00,0x66,0x00,0x63,0x00,0x53,0x00,0x63,0x00,0x61};//W.i.n.l.o.g.o.n...S.f.c.S.c.a.n
		if(memcmp(&m_pbyBuff[0x0], byCheckSig, sizeof(byCheckSig)) == 0 && 
			memcmp(&m_pbyBuff[0x34], byCheckSig1, sizeof(byCheckSig1)) == 0 && 
			memcmp(&m_pbyBuff[0x262], byCheckSig2, sizeof(byCheckSig2)) == 0)
		{						
			m_eVirusDetected = TrojanPatchedHP;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.HP"));
			return VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedHP
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.HP
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedHP()
{  	
	BYTE byBuffer[] = {0x33,0xC0,0x40};

	if(m_pMaxPEFile->WriteBuffer(byBuffer, 0xECE9, sizeof(byBuffer), sizeof(byBuffer)))
	{
		return REPAIR_SUCCESS;
	}		   
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedHI
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.HI
					  A : Infection on only GetProcessAddress API.
                      B : Patched Bytes start From New GetProcessAddress.
                      C : Patched Bytes -> it's a function to load library and Load %System%\wsconfig.db file 
						  which performs malicious activity.
		              D : After Loading Library ,it configures itself & jump to original GetProcessAddress API loop .
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedHI()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL || m_wAEPSec != 0x0  || 
		m_dwAEPUnmapped != 0xB63E || m_wNoOfSections != 0x4)
	{
		return iRetStatus;
	}
	if((m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x0A)&& (m_pMaxPEFile->m_stPEHeader.MinorOSVersion == 0x1)&&
		(m_pMaxPEFile->m_stPEHeader.MinorSubsystemVersion == 0x00)&& (m_pMaxPEFile->m_stPEHeader.Characteristics ==0x210E)&&
		(m_pSectionHeader[0].Characteristics == 0x60000020)&& (m_pSectionHeader[1].Characteristics == 0xC0000040)&&
		(m_pSectionHeader[2].Characteristics == 0x40000040)&&(m_pSectionHeader[3].Characteristics == 0x42000040))
	{
		//Cavity handling
		DWORD dwCavityStart = m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x18 + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + (m_pMaxPEFile->m_stPEHeader.NumberOfSections * 0x28);
		if(m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].VirtualAddress != 0x0 )
		{
			dwCavityStart += m_pMaxPEFile->m_stPEHeader.DataDirectory[0xB].Size;
		}	
		m_dwNoOfbyteToRead = m_pSectionHeader[0x0].PointerToRawData - dwCavityStart; 
		if(m_dwNoOfbyteToRead < 0x60)
		{
			return iRetStatus;
		}
		if(m_dwNoOfbyteToRead > 0x200)
		{
			m_dwNoOfbyteToRead = 0x200;
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int PATCHED_HI_BUFF_SIZE	= 0x200;
		m_pbyBuff = new BYTE[PATCHED_HI_BUFF_SIZE];
		if(GetBuffer(dwCavityStart, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
		{ 
			const BYTE Sig[] = {0xe8,0x22,0x00,0x00,0x00,0x80,0x38,0x00,0x75,0x18,0xfe,0x00,0x6a,0x00,0x6a,0x00,0x6a,0x00,0xe8,0x02,0x00,0x00,0x00,0xeb,0x16,0x6a,0x00,0x6a,0x00,0xe8,0xcf,0x03,0x01,0x00,0xe9,0x33,0xab,0x00,0x00,0xe8,0x01,0x00,0x00,0x00};
			const BYTE Sig1[] = {0x52,0x65,0x67,0x4f,0x70,0x65,0x6e,0x4b,0x65,0x79,0x45,0x78,0x41,0x00,0x90,0x53,0xe8,0xf4,0xaa,0x00,0x00,0x97,0x09,0xff,0x0f,0x84,0x84,0x00,0x00,0x00,0xe8,0x11,0x00,0x00,0x00,0x52,0x65,0x67,0x51,0x75,0x65,0x72,0x79,0x56,0x61,0x6c,0x75,0x65,0x45,0x78,0x41};
			const BYTE Sig2[] = {0xe8,0x12,0x00,0x00,0x00,0x53,0x4f,0x46,0x54,0x57,0x41,0x52,0x45,0x5c,0x4c,0x69,0x63,0x65,0x6e,0x73,0x65,0x73,0x00,0x90,0x68,0x02,0x00,0x00,0x80,0xff,0xd7,0x5f,0x09,0xff,0x74,0x35,0x31,0xc9,0x31,0xf6,0xe8,0x3d,0x00,0x00 ,0x00};
			for(DWORD dwOffset = 0; dwOffset <= m_dwNoOfbyteToRead - sizeof(Sig); dwOffset++)
			{
				m_dwNoOfbyteToFill = m_dwNoOfbyteToRead - dwOffset;
				m_dwReplaceOffSet = dwCavityStart + dwOffset;
				if(memcmp(&m_pbyBuff[dwOffset], Sig, sizeof(Sig)) == 0)
				{
					for(dwOffset += sizeof(Sig); dwOffset <= m_dwNoOfbyteToRead - sizeof(Sig1); dwOffset++)
					{
						if(memcmp(&m_pbyBuff[dwOffset], Sig1, sizeof(Sig1)) == 0) 
						{
							for(dwOffset += sizeof(Sig1); dwOffset <= m_dwNoOfbyteToRead - sizeof(Sig2); dwOffset++)
							{
								if(memcmp(&m_pbyBuff[dwOffset], Sig2, sizeof(Sig2)) == 0)
								{ 
									m_dwTruncateOffset =0x0;
									if(!m_pMaxPEFile->ReadBuffer(&m_dwTruncateOffset, 0x20B4, 0x4, 0x4))
									{ 
										return iRetStatus;
									}
									WORD wSec = m_pMaxPEFile->Rva2FileOffset(m_dwTruncateOffset, &m_dwTruncateOffset);
									if((OUT_OF_FILE == wSec) || (m_dwTruncateOffset !=0x000834c9)) 
									{
										return iRetStatus;
									}
									m_eVirusDetected = TrojanPatchedHI;
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.Hi"));
									return VIRUS_FILE_REPAIR;
								}
							}
							return iRetStatus;
						}
					}
					return iRetStatus;
				}
			}
			return iRetStatus;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedHI
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair Routine for :  Trojan.Patched.HI
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedHI()
{  	
	BYTE byBuffer[]={0x30,0xAE,0x00,0x00};

	if(m_pMaxPEFile->WriteBuffer(byBuffer, 0x20B4, sizeof(byBuffer), sizeof(byBuffer)))
	{
		if( m_pMaxPEFile->FillWithZeros(m_dwReplaceOffSet , m_dwNoOfbyteToFill ))
		{
			if( m_pMaxPEFile->FillWithZeros(m_dwTruncateOffset , 0x3F ))
			{
				return REPAIR_SUCCESS;
			}
		}
	}		   
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedDZ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.DZ
					  A : AEP changed on infection.
                      B : AEP Starts from Patched Bytes and no.of bytes patched varies from file to file.
                      C : Patched Bytes -> it's a function to load mmc.exe (mmc.exe is the Microsoft Management Console application and is used to display various management plug-ins accessed from the Control Panel, such as the Device Manager)
					      and Load %System%\Kernel32.dll file. 
					  D : After Loading file ,it configures itself & takes jump to original AEP.	
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedDZ()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL || m_dwAEPUnmapped != 0x18E0
		|| m_pMaxPEFile->m_stPEHeader.SizeOfCode != m_pSectionHeader[0x0].SizeOfRawData || m_pMaxPEFile->m_stPEHeader.SizeOfCode != 0x5B200  )
	{
		return iRetStatus;
	}
	m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize - m_dwAEPMapped; 
	if(m_dwNoOfbyteToRead < 0x50)
	{
		return iRetStatus;
	}
	if(m_dwNoOfbyteToRead > 0x70)
	{
		m_dwNoOfbyteToRead = 0x70;
	}
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int PATCHED_DZ_BUFF_SIZE	= 0x70;
	m_pbyBuff = new BYTE[PATCHED_DZ_BUFF_SIZE];
	if(GetBuffer(m_dwAEPMapped, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
	{ 
		const BYTE Sig[] = {0x57,0x69,0x6e,0x45,0x78,0x65,0x63,0x00,0x6b,0x65,0x72,0x6e,0x65,0x6c,0x33,0x32,0x2e,0x64,0x6c,0x6c};
		const BYTE Sig1[] = {0x43,0x3a,0x5c,0x57,0x49,0x4e,0x44,0x4f,0x57,0x53,0x5c,0x73,0x79,0x73,0x74,0x65,0x6d,0x33,0x32,0x5c,0x6d,0x6d,0x63,0x2e,0x65,0x78,0x65};
		for(DWORD dwOffset = 0x30; dwOffset <= m_dwNoOfbyteToRead - sizeof(Sig); dwOffset++)
		{
			if(memcmp(&m_pbyBuff[dwOffset], Sig, sizeof(Sig)) == 0)
			{
				m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[dwOffset - 0x4 ]+ dwOffset + m_dwAEPUnmapped;
				WORD wSec = m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, 0);
				if(OUT_OF_FILE == wSec || m_dwOriginalAEP == 0x0) 
				{
					return iRetStatus;
				}
				for(dwOffset += sizeof(Sig); dwOffset <= m_dwNoOfbyteToRead - sizeof(Sig1); dwOffset++)
				{
					if(memcmp(&m_pbyBuff[dwOffset], Sig1, sizeof(Sig1)) == 0) 
					{
						m_dwNoOfbyteToRead = dwOffset + sizeof(Sig1);
						m_eVirusDetected = TrojanPatchedDZ;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Patched.DZ"));
						return VIRUS_FILE_REPAIR;
					}
				}
				return iRetStatus;
			}
		}
		return iRetStatus;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedDZ
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.DZ
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedDZ()
{  	
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if( m_pMaxPEFile->FillWithZeros(m_dwAEPMapped , m_dwNoOfbyteToRead ))
		{
			DWORD dwSize = m_pMaxPEFile->m_dwFileSize - m_pSectionHeader[0x0].PointerToRawData,dwOffsetNext=0x0;
			DWORD dwCheckAdd = m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x58;
			DWORD dwSectionStart = m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x18 + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader ;
			if( m_pMaxPEFile->FillWithZeros(dwCheckAdd  , 0x4 ))
			{
				for(DWORD dwOffset = 1; dwOffset <= m_wNoOfSections; dwOffset++)
				{
					if(dwOffset > 0x01)
					{
						if( !m_pMaxPEFile->FillWithZeros(dwSectionStart + 0x10 , 0x4 ))
						{
							return REPAIR_FAILED;
						}
						dwOffsetNext = 0x4;
					}
					if(!m_pMaxPEFile->WriteBuffer(&dwSize, dwSectionStart + 0x10 + dwOffsetNext, 0x4, 0x4))
					{
						return REPAIR_FAILED;					
					}
					if(dwOffset == 1)
					{
						dwSize +=  m_pSectionHeader[0].PointerToRawData;
					}
					dwSectionStart += 0x28;
				}
				return REPAIR_SUCCESS;
			}
		}
	}		   
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTrojanPatchedMY
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.MY
					  A : Infection on only GetProcessAddress API.
                      B : Patched Bytes start From New GetProcessAddress.
                      C : Patched Bytes -> it's a function to load library ,which performs malicious activity.
		              D : After Loading Library ,it configures itself & jump to original GetProcessAddress API loop .  
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedMY()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL || m_wAEPSec != 0x0  || m_dwAEPUnmapped != 0x12C0 || m_wNoOfSections != 0x4)
	{
		return iRetStatus;
	}
	if(	(m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x0A)&& 
		(m_pMaxPEFile->m_stPEHeader.MinorOSVersion == 0x1)&&
		(m_pMaxPEFile->m_stPEHeader.MinorSubsystemVersion == 0x00)&&
		(m_pMaxPEFile->m_stPEHeader.Characteristics ==0x210E)&&
		(m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 0x14C00))
		
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int PATCHED_MY_BUFF_SIZE	= 0x300;
		m_pbyBuff = new BYTE[PATCHED_MY_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - PATCHED_MY_BUFF_SIZE , PATCHED_MY_BUFF_SIZE , PATCHED_MY_BUFF_SIZE ))
		{
			return iRetStatus;
		}
		TCHAR szVirusName[MAX_PATH] = {0};
		TCHAR Check_Sig[] = _T("696D6D33322E706462*493E8B348B03F533FFFC33C0AC3AC47407C1CF0D03F8EBF23B7C2408*646E6574636F6D33");
		TCHAR Check_Sig1[] = _T("696D6D33322E706462*596884E2828351F7542404FF542404589D*64336478395F30392E646C6C");
		CSemiPolyDBScn polydbObj;
		polydbObj.LoadSigDBEx(Check_Sig, _T("Virus.Patched.MY"), TRUE);
		polydbObj.LoadSigDBEx(Check_Sig1, _T("Virus.Patched.MY"), FALSE);
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], PATCHED_MY_BUFF_SIZE, szVirusName) >= 0)
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
	Function		: DetectTrojanPatchedKA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Detection routine for : Trojan.Patched.KA
					  A : AEP changed on infection.
                      B : AEP Starts from Patched Bytes and no.of bytes patched varies from file to file.
					  C : It's add Two new section ,if file is packed then add code at the last section .
                      D : Patched Bytes -> it's a function to configer download data from net
					  E : After configures itself & takes jump to original AEP.
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::DetectTrojanPatchedKa()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec ==0x0)
	{
		return iRetStatus;
	}

	WORD wSec = m_pMaxPEFile->Rva2FileOffset(m_dwAEPUnmapped - 0x18, 0);
	if(OUT_OF_FILE == wSec || m_wAEPSec != wSec) 
	{
		return iRetStatus;
	}
	m_dwNoOfbyteToRead = m_pMaxPEFile->m_dwFileSize - m_dwAEPMapped; 
	if(m_dwNoOfbyteToRead < 0x50)
	{
		return iRetStatus;
	}
	if(m_dwNoOfbyteToRead > 0x200)
	{
		m_dwNoOfbyteToRead = 0x200;
	}
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int PATCHED_KA_BUFF_SIZE	= 0x200;
	m_pbyBuff = new BYTE[PATCHED_KA_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, PATCHED_KA_BUFF_SIZE + MAX_INSTRUCTION_LEN);

	if(GetBuffer(m_dwAEPMapped - 0x18, m_dwNoOfbyteToRead, m_dwNoOfbyteToRead))
	{ 
		if(*(DWORD *)&m_pbyBuff[0] != m_dwImageBase )
		{
			return iRetStatus;
		}

		if((m_pbyBuff[0x18]!=0xE8 && m_pbyBuff[0x18]!=0xE9 )|| 
			(m_pbyBuff[0x1D]!=0xE8 && m_pbyBuff[ 0x1D ]!=0xE9) )
		{
			return iRetStatus;
		}

		DWORD dwOffset = *(DWORD *)&m_pbyBuff[0x19] + 0x1D;
		if(NEGATIVE_JUMP(dwOffset))
		{
			return iRetStatus;
		}

		DWORD	dwLength = 0, dwInstCount = 0;
		t_disasm da = {0};
		while(dwOffset < m_dwNoOfbyteToRead && dwInstCount < 0x8)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);   
			if(dwLength > m_dwNoOfbyteToRead - dwOffset)
			{
				break;
			}
			if(dwInstCount == 0x0 && dwLength == 1  && strstr(da.result,"POP EAX"))
			{
				dwInstCount++;
			}
			else if(dwInstCount == 0x01 && dwLength == 2  && strstr(da.result,"MOV EDX,EAX"))
			{				
				dwInstCount++;
			}
			else if(dwInstCount ==0x02 && dwLength == 5 && strstr(da.result,"AND EAX,"))
			{ 
				if((*(DWORD *)&m_pbyBuff[dwOffset + 0x1 ] & (m_dwAEPUnmapped + 0x5)) != (m_dwAEPUnmapped - 0x18) )
				{
					return iRetStatus;
				}
				dwInstCount++;

			}
			else if((dwInstCount ==0x03 || dwInstCount ==0x05 || dwInstCount ==0x07)&& dwLength == 2 && strstr(da.result,"PUSH DWORD PTR [EAX]"))
			{
				if(dwInstCount == 0x7)
				{
					TCHAR szVirusName[MAX_PATH] = {0};
					TCHAR Patched_Sig[] = _T("558BEC81C4DCFDFFFF5356578B45148B5D10035D0C8B3B83C3048D500C8B128955FC8D50108B3283C0148B008945F88B*55FC8B4DF8C002038032FFC00A024249");
					CSemiPolyDBScn polydbObj;
					polydbObj.LoadSigDBEx(Patched_Sig, _T("Virus.Patched.Ka"), FALSE);
					if(polydbObj.ScanBuffer(&m_pbyBuff[0], PATCHED_KA_BUFF_SIZE, szVirusName) >= 0)
					{
						if(_tcslen(szVirusName) > 0)
						{
							m_dwOriginalAEP=*(DWORD *)&m_pbyBuff[0x8] - m_dwImageBase;
							if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, 0))
							{
								return iRetStatus;
							}

							m_eVirusDetected = TrojanPatchedKa;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
							return VIRUS_FILE_REPAIR;					
						}
					}
				}
				dwInstCount++;
			}
			else if((dwInstCount == 0x04 || dwInstCount == 0x06 )&& dwLength == 3 && strstr(da.result,"ADD EAX,"))
			{ 
				dwInstCount++;				
			}
			dwOffset += dwLength;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTrojanPatchedKa
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Repair routine for : Trojan.Patched.KA
--------------------------------------------------------------------------------------*/
int CPolyTrojanPatched::CleanTrojanPatchedKa()
{  	
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if( m_pMaxPEFile->TruncateFile(m_dwAEPMapped - 0x18))
		{
			return REPAIR_SUCCESS;
		}
	}		   
	return REPAIR_FAILED;
}






