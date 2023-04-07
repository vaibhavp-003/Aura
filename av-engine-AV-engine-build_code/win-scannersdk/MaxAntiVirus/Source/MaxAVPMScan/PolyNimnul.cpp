/*======================================================================================
FILE				: PolyNimnul.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Yash Gund + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 05 Mar 2011
NOTES				: This is detection module for malware Nimnul Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 18 Aug 2011 : Added New Function for Nimnul.D Detection 
					  18 Aug 2011 : Added New Function for Nimnul.C Detection	
=====================================================================================*/
#include "PolyNimnul.h"
#include "SemiPolyDBScn.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyNimnul
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyNimnul::CPolyNimnul(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_pbyBuff = new BYTE[NIMNUL_BUFF_SIZE];		
	memset(&m_stParamas,0x00,sizeof(NIMNUL_E_PARAM));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyNimnul
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyNimnul::~CPolyNimnul(void)
{
	bIsNimnulE = FALSE;
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
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Detection routine for different varients of Nimnul Family
--------------------------------------------------------------------------------------*/
int CPolyNimnul::DetectVirus(void)
{	
	return DetectNimnul(m_dwAEPMapped, m_wAEPSec);
}

/*-------------------------------------------------------------------------------------
	Function		: DetectNimnul
	In Parameters	: DWORD dwAEP, WORD wAEPSection, bool bSecondAttempt
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Detection routine for different varients of NImnul Family
					+ AEP should be in Last Section
					+ AEP offset == Last Section Pointer to Raw Data
					+ Matches AEP bytes and then searches for JMPoffset bytes
--------------------------------------------------------------------------------------*/
int CPolyNimnul::DetectNimnul(DWORD dwAEP, WORD wAEPSection, bool bSecondAttempt /*= false*/)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	//AEP Section should be last
	if((wAEPSection == m_wNoOfSections - 1 && dwAEP == m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData) || 
		(wAEPSection == m_wNoOfSections - 2 && dwAEP == m_pSectionHeader[m_wNoOfSections - 2].PointerToRawData) || 
		bSecondAttempt)
	{	
		//Tushar --> Minimum required bytes it reduced to 0x250;
		if(!GetBuffer(dwAEP, NIMNUL_BUFF_SIZE, 0x250))
		{
			return iRetStatus;
		}

		//Tushar --> 08 Aug 2011 : Handling for Currupt Samples : (Bytes at AEP are Zero)
		if(dwAEP == m_pSectionHeader[m_wNoOfSections-1].PointerToRawData)
		{
			BYTE byCurruptAEP[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
			if(memcmp(&m_pbyBuff[0x00], byCurruptAEP, sizeof(byCurruptAEP)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Nimnul.Crpt"));
				iRetStatus = VIRUS_FILE_DELETE;
				return iRetStatus;
			}
		}

		//Compare AEP bytes
		BYTE byAEP[NIMNUL_AEPBUFF_SIZE] = {0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8B, 0xC5, 0x81, 0xED};
		
		if(memcmp(&m_pbyBuff[0], &byAEP[0], NIMNUL_AEPBUFF_SIZE) == 0)
		{
			//Tushar ==> 11 Nov 2011 : Nimnul.A Chnages
			BYTE byBytesOrgAEP[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00};
			BYTE byBytesOrgAEP_2[] = {0x06, 0x00, 0x00, 0x00}; 
			//This DWORD is Used as reference for AEP Offset and subtracted from DUMMY CALL RETN Addrs to get Actual AEP.

			DWORD dwOrgAEP = 0x00, dwOffSet = 0x00;

			if(!GetBuffer(dwAEP + 0x250, NIMNUL_BUFF_SIZE, 0x500))
			{
				return iRetStatus;
			}
			if(!OffSetBasedSignature(&byBytesOrgAEP[0x00],sizeof(byBytesOrgAEP),&dwOffSet))
			{
				if(!OffSetBasedSignature(&byBytesOrgAEP_2[0x00],sizeof(byBytesOrgAEP_2),&dwOffSet))
				{
					return iRetStatus;
				}
				else
				{
					dwOffSet += sizeof(byBytesOrgAEP_2);
				}
			}
			else
			{
				dwOffSet+=sizeof(byBytesOrgAEP);
			}

			dwOffSet = (dwOffSet +  0x250 + dwAEP);
			if(!m_pMaxPEFile->ReadBuffer(&dwOrgAEP, dwOffSet, sizeof(DWORD), sizeof(DWORD)))
			{
				return iRetStatus;
			}

			dwOrgAEP = m_dwAEPUnmapped - dwOrgAEP;

			if(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".text", 7) == 0)
			{
				m_dwOriginalNimnulAEP = dwOrgAEP;
				m_wNoOfSec = m_wNoOfSections - 1;
				m_dwOriginalOffset = m_pMaxPEFile->m_dwFileSize - 0x0291A5;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Nimnul.A"));
				return VIRUS_FILE_REPAIR;	
			}

			if(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".text", 7) == 0)
			{
				m_dwOriginalNimnulAEP = dwOrgAEP;
				m_wNoOfSec = m_wNoOfSections - 1;
				m_dwOriginalOffset = m_pMaxPEFile->m_dwFileSize - 0x0291A5;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Nimnul.A"));
				return VIRUS_FILE_REPAIR;	
			}

			m_dwOriginalNimnulAEP = dwOrgAEP;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Nimnul.A"));
			iRetStatus = VIRUS_FILE_REPAIR;			
		}
		else//Detection for Nimnul.D + Nimnul.C
		{	
			if(!(m_pbyBuff[0] == 0x55))
			{
				return iRetStatus;
			}
			
			DWORD dwOrgAEPOffSet = DetectNimnulC();
			if (0x00 == dwOrgAEPOffSet)
			{
				dwOrgAEPOffSet = DetectNimnulD();
			}
			if (0x00 == dwOrgAEPOffSet)
			{
				dwOrgAEPOffSet = DetectNimnulF();
			}
			if (0x00 == dwOrgAEPOffSet)
			{
				return iRetStatus;
			}
			
			if(!GetBuffer(m_dwAEPMapped + dwOrgAEPOffSet, 0x05, 0x05))
			{
				return iRetStatus;
			}

			//Tushar --> Removed Second Condition of Negative Jump Checking;
			if(m_pbyBuff[0x00] == 0xE9)
			{
				m_dwOriginalNimnulAEP  = *((DWORD *)&m_pbyBuff[1]);
				m_dwOriginalNimnulAEP += dwOrgAEPOffSet + m_dwAEPUnmapped + 0x05;
			
				switch(dwOrgAEPOffSet)
				{
				case NIMNUL_C_AEPOFFSET:
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Nimnul.C"));
					break;
				case NIMNUL_D_AEPOFFSET:
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Nimnul.D"));
					break;
				}		
				
				//Tushar --> Added below code to check for Original AEP is in file or not;
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriginalNimnulAEP, NULL))
				{
					iRetStatus = VIRUS_FILE_DELETE;
				}
				else
				{
					iRetStatus = VIRUS_FILE_REPAIR;
				}
			}
			else if(m_pbyBuff[0x00] == 0x04)
			{
				m_dwOriginalNimnulAEP  = *((DWORD *)&m_pbyBuff[1]);
				m_dwOriginalNimnulAEP += 0x26C + m_dwAEPUnmapped + 0x05;
				
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Nimnul.F"));
				
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriginalNimnulAEP, NULL))
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
	
	if(VIRUS_NOT_FOUND == iRetStatus && wAEPSection == 0x00 && (memcmp(&(m_pSectionHeader[m_wAEPSec].Name[0x5]), "FMX", 3) != 0))
	{
		if(!GetBuffer(dwAEP, NIMNUL_BUFF_SIZE, 0x250))
		{
			return iRetStatus;
		}
		if (DetectNimnulE())
		{
			bIsNimnulE = TRUE;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Nimnul.E"));
			if (m_stParamas.dwResOffSet == 0x00 || m_stParamas.dwFPatchSize == 0x00)
				iRetStatus = VIRUS_FILE_DELETE;		
			else
				iRetStatus = VIRUS_FILE_REPAIR;			

			return iRetStatus;
		}
	}

	if(VIRUS_NOT_FOUND == iRetStatus && !memcmp(m_pSectionHeader[0].Name, ".rmnet", 6) && 
		!memcmp(m_pSectionHeader[1].Name, "UPX1", 4) && !memcmp(m_pSectionHeader[2].Name, ".rsrc", 5))
	{
		const int NIMNUL_DZ_BUFF_SIZE = 0x500;
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[NIMNUL_DZ_BUFF_SIZE];	
		if(GetBuffer(0x4400, NIMNUL_DZ_BUFF_SIZE, NIMNUL_DZ_BUFF_SIZE))
		{
			TCHAR szVirusName[MAX_PATH] = {0};
			TCHAR szSig_DZ[] ={_T("2E726D6E6574*7765626167656E742E646C6C*44726F7046696C654E616D65203D2022737663686F73742E65786522*524D4E6574776F726B")};
			
			CSemiPolyDBScn	polydbObj;
			polydbObj.LoadSigDBEx(szSig_DZ, _T("Virus.Nimnul.dz"), FALSE);              // Kas detection Agent.dz
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], NIMNUL_DZ_BUFF_SIZE, szVirusName) >= 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				iRetStatus = VIRUS_FILE_DELETE;
				return iRetStatus;
			}
		}
		if(m_pSectionHeader[0].SizeOfRawData == 0)
		{
			if(GetBuffer(m_dwAEPMapped - NIMNUL_DZ_BUFF_SIZE - 0x300, NIMNUL_DZ_BUFF_SIZE, NIMNUL_DZ_BUFF_SIZE))
			{
				TCHAR szVirusName[MAX_PATH] = {0};
				//taking signature from packed file as upx packing is modified by virus & cannot be unpacked using upx tools or algorithm
				TCHAR szSig_DZ[] ={_T("47686959686A6D4E6B4C6F777151005372*762E657865*726D6E6574")};
				
				CSemiPolyDBScn	polydbObj1;
				polydbObj1.LoadSigDBEx(szSig_DZ, _T("Virus.Nimnul.dz"), FALSE);              // Kas detection Agent.dz
				if(polydbObj1.ScanBuffer(&m_pbyBuff[0], NIMNUL_DZ_BUFF_SIZE, szVirusName) >= 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					iRetStatus = VIRUS_FILE_DELETE;
					return iRetStatus;
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
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of Nimnul Family
--------------------------------------------------------------------------------------*/
int CPolyNimnul::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	
	DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;//Added
	DWORD dwOverlaySize = m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData);//Added

	if(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".text", 7) == 0)
	{
		if(m_pMaxPEFile->WriteAEP(m_dwOriginalNimnulAEP))
		{
			if(m_pMaxPEFile->ForceTruncate(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData))
			{
				if(m_pMaxPEFile->WriteBuffer(&m_dwOriginalOffset, m_pMaxPEFile->m_stPEOffsets.SizeOfImage, sizeof(DWORD), 0x08))
				{
					if(m_pMaxPEFile->FillWithZeros((m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + m_pMaxPEFile->m_stPEOffsets.Magic + ((m_pMaxPEFile->m_stPEHeader.NumberOfSections - 2) * 0x040) - sizeof(DWORD)),0x40))
					{
						if(m_pMaxPEFile->WriteBuffer(&m_wNoOfSec, m_pMaxPEFile->m_stPEOffsets.NumberOfSections, 0x02,0x02))
						{
							if(m_pMaxPEFile->CalculateChecksum())
							{
								return REPAIR_SUCCESS;
							}
						}
					}
				}
			}

		}
	}


	if (TRUE == bIsNimnulE)
	{
		iRetStatus = CleanNimnulE();
		return iRetStatus; 
	}

	DWORD dwAEP = 0;
	WORD  wAEPSection = m_pMaxPEFile->Rva2FileOffset(m_dwAEPUnmapped, &dwAEP);
	WORD  wOriAEPSection = m_pMaxPEFile->Rva2FileOffset(m_dwOriginalNimnulAEP, &dwAEP);

	//Added by Rupali on 2 Apr 11. To hadle corrupt multiple infection by Yash
	//SizeofRawData Check for Some Virut.CE file corruption issue (if Last two section have Same PRD)
	if((m_pSectionHeader[wAEPSection - 1].SizeOfRawData != 0x00) &&
		wOriAEPSection != wAEPSection - 1 &&
		DetectNimnul(m_pSectionHeader[wAEPSection - 1].PointerToRawData, wAEPSection - 1, true))
	{
		dwAEP = m_pSectionHeader[wAEPSection - 1].PointerToRawData;
		wAEPSection -= 1;
	}
	//End
	m_pMaxPEFile->WriteAEP(m_dwOriginalNimnulAEP);
	
	//Added
	if(dwOverlaySize >0)
	{

		if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[wAEPSection].PointerToRawData ,true))
			iRetStatus = REPAIR_SUCCESS;
	}
	else
	{

		if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[wAEPSection].PointerToRawData))
			iRetStatus = REPAIR_SUCCESS;
	}

	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: GetNimnulGenParameter
	In Parameters	: DWORD *dwFirst, DWORD *dwSecond
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: It gives TWO Parameters for AEP Calculation.
--------------------------------------------------------------------------------------*/
bool CPolyNimnul::GetNimnulGenParameter(DWORD *dwFirst, DWORD *dwSecond)
{	
	//Matches first two Instruction Opcode Push and Call
	DWORD dwTemp = *((DWORD *)&m_pbyBuff[0]);
	if(dwTemp != 0x0000E860)
	{
		return false;
	}

	t_disasm da;
	DWORD dwLen = 0, dwStart = 0, dwInsCount = 0;
	BYTE byJMPOffset[NIMNUL_JMPBUFF_SIZE] = {0x44, 0x24, 0x1C, 0x61, 0xFF, 0xE0};
	bool bCheck = false;

	//Finds First Argument
	while(dwStart < 0x100)
	{
		dwInsCount++;
		dwLen = m_objMaxDisassem.Disasm((char* )&m_pbyBuff[dwStart], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLen > (0x100 - dwStart))
		{
			break;
		}
		dwStart += dwLen;

		if(dwInsCount == 0x5 && strstr(da.result, "SUB EBP"))
		{
			*dwFirst = *(DWORD *)(&m_pbyBuff[0] + 0x0B);
			bCheck = true;
			break;
		}
	}
	//Searches Second Argument
	for(dwStart = 0; dwStart <= NIMNUL_BUFF_SIZE; dwStart++)
	{
		if(memcmp(&m_pbyBuff[dwStart], byJMPOffset, NIMNUL_JMPBUFF_SIZE) == 0 && bCheck)
		{
			*dwSecond = *(DWORD *)(&m_pbyBuff[dwStart] - 0x05);
			break;
		}
	}
	return bCheck;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectNimnulD
	In Parameters	: 
	Out Parameters	: DWORD : Return the displacement of Original AEP Jump from Infected AEP. 
	Purpose			: 
	Author			: Tushar Kadam + Neeraj + Virus Analysis Team
	Description		: Detection routine for varient : Nimnul.D
--------------------------------------------------------------------------------------*/
DWORD CPolyNimnul::DetectNimnulD()
{
	DWORD	dwRet = 0x00;
	BYTE bArray[] = {0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x84, 0x00, 0x00, 0x00, 0x64, 
					 0xFF, 0x35, 0x30, 0x00, 0x00, 0x00, 0x58, 0x89, 0x45, 0xDC};
	DWORD dwIndex = 0x00;
	if(!OffSetBasedSignature(bArray,sizeof(bArray),&dwIndex))
	{
		return dwRet;
	}

	if(dwIndex)
	{
		return dwRet;
	}
	
	dwRet = NIMNUL_D_AEPOFFSET; 

	return dwRet;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectNimnulC
	In Parameters	: 
	Out Parameters	: DWORD : Return the displacement of Original AEP Jump from Infected AEP. 
	Purpose			: 
	Author			: Tushar Kadam + Neeraj + Virus Analysis Team
	Description		: Detection routine for varient : Nimnul.C
--------------------------------------------------------------------------------------*/
DWORD CPolyNimnul::DetectNimnulC()
{
	DWORD	dwRet = 0x00;
	
	BYTE bNimNulCSig[] = {0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x84, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xEC};
	DWORD dwIndex = 0x00;

	if(!OffSetBasedSignature(bNimNulCSig,sizeof(bNimNulCSig),&dwIndex))
	{
		return dwRet;
	}

	if(dwIndex)
	{
		return dwRet;
	}

	dwRet = NIMNUL_C_AEPOFFSET;
	return dwRet;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectNimnulE
	In Parameters	: 
	Out Parameters	: true if success else false 
	Purpose			: 
	Author			: Tushar Kadam + Neeraj + Virus Analysis Team
	Description		: Detection routine for varient : Nimnul.E
--------------------------------------------------------------------------------------*/
BOOL CPolyNimnul::DetectNimnulE()
{
	DWORD	bRet = FALSE;
	DWORD	dwTemp = 0x00;
	
	//EB4483E2F031C931C031F651B9100000000FB6840D
	BYTE bNimNulESigM[] = {0x8D, 0x15, 0x70, 0x04, 0x00, 0x00, 0x89, 0xF5, 0xEB, 0x44, 0x83, 0xE2, 0xF0, 0x31, 0xC9, 0x31, 
						  0xC0, 0x31, 0xF6, 0x51, 0xB9, 0x10, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x84, 0x0D, 0xEE, 0x04, 0x00};

	BYTE bNimNulESigM_1[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x8D, 0x7E, 0x15, 0x29, 0xF8, 0x01, 0xC6, 0x01, 0xC1, 0x01,
							0xC3, 0x50, 0x89, 0xF5, 0x60, 0x8D, 0x15, 0x90, 0x04, 0x00, 0x00, 0xEB, 0x44, 0x83, 0xE2, 0xF0};

	BYTE bNimNulESig2[] = {0x83, 0xC3, 0x10, 0x83, 0xC7, 0x10, 0x83, 0xC1, 0x10, 0x39, 0xD1, 0x75, 0xC6, 0xC3, 0x56, 0x51};
	BYTE bNimNulESig2_1[] = {0xB9, 0x10, 0x00, 0x00, 0x00, 0x8A, 0x84, 0x0D, 0x0E, 0x05, 0x00, 0x00, 0x88, 0x44, 0x0F, 0xFF};

	if (m_pbyBuff[0x00] == 0x60 && m_pbyBuff[0x01] == 0xBE)
	{
		if (memcmp(&m_pbyBuff[0x10],bNimNulESigM,sizeof(bNimNulESigM)) == 0x00)
		{
			if (memcmp(&m_pbyBuff[0x50],bNimNulESig2,sizeof(bNimNulESig2)) == 0x00)
			{
				bRet = TRUE;
			}
		}
		if (memcmp(&m_pbyBuff[0x10],bNimNulESigM_1,sizeof(bNimNulESigM_1)) == 0x00)
		{
			if (memcmp(&m_pbyBuff[0x50],bNimNulESig2_1,sizeof(bNimNulESig2_1)) == 0x00)
			{
				bRet = TRUE;
			}
		}
	}
	else if (m_pbyBuff[0x00] == 0x83 && m_pbyBuff[0x01] == 0xEC && m_pbyBuff[0x02] == 0x04 && m_pbyBuff[0x03] == 0x60)
	{
		bRet = TRUE;
	}
	else if(m_pbyBuff[0x00] == 0xEB || m_pbyBuff[0x00] == 0xE9)
	{
		if (m_pbyBuff[0x00] == 0xEB)
		{
			dwTemp = m_pbyBuff[0x01] + 0x02;
		}
		else
		{
			dwTemp = *((DWORD *)&m_pbyBuff[0x01]) + 0x05;
		}

		if (dwTemp <= 0x250)
		{
			if (m_pbyBuff[dwTemp] == 0x60)
				bRet = TRUE;
		}
		
	}

	if (bRet == TRUE)
	{
		DWORD	dwResOffSet = 0x00, dwTemp = 0x00;
		DWORD	dwReqiredOffSet = 0x00, dwResSize = 0x00;
		WORD	wNameIDs = 0x00, i = 0x00;

		dwTemp = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x02].VirtualAddress;
		if (dwTemp != 0x00)
		{
			m_pMaxPEFile->Rva2FileOffset(dwTemp,&dwResOffSet);
			if (dwResOffSet != 0x00)
			{
				m_pMaxPEFile->ReadBuffer((LPVOID)&wNameIDs,dwResOffSet + 0x0C,sizeof(WORD),sizeof(WORD));
				if (0x00 != wNameIDs) 
				{
					for(i = 0x00; i<wNameIDs; i++)
					{
						dwReqiredOffSet = IsRequiredResource(dwResOffSet,i,dwResSize);
						if (dwReqiredOffSet)
						{
							break;
						}
					}
				}
			}
		}
		m_stParamas.dwResOffSet = dwReqiredOffSet;
		m_stParamas.dwResSize = dwResSize;

		if (m_stParamas.dwResOffSet > 0x00)
		{
			BYTE bNim3Sig[] = {/*0x31, 0xC9, */0x31, 0xC0, 0x51, 0xB9, 0x10, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x44, 0x0E, 0xFF, 0x8A,
								   0x04, 0x03, 0x88, 0x84, 0x0D, 0x2F, 0x06, 0x00, 0x00, 0xE2, 0xEF, 0xB9, 0x10, 0x00, 0x00, 0x00};
			if (bRet == TRUE && m_stParamas.dwNimnulType == 0x03)
			{
				
				if(GetBuffer((m_stParamas.dwResOffSet + 0x20), 0x20, 0x20))
				{
					if(memcmp(&m_pbyBuff[0x00], &bNim3Sig[0x00], sizeof(bNim3Sig)) != 0)
					{
						m_stParamas.dwResOffSet = 0;
						bRet = FALSE;
					}
				}
			}

			if (bRet == TRUE && m_stParamas.dwNimnulType == 0x04)
			{
				if(GetBuffer((m_stParamas.dwResOffSet + 0x23), 0x20, 0x20))
				{
					if(memcmp(&m_pbyBuff[0x00], &bNim3Sig[0x00], 0x13) != 0)
					{
						m_stParamas.dwResOffSet = 0;
						bRet = FALSE;
					}
				}
			}
			
			if (bRet == TRUE)
			{
				BYTE byBuff[0x30] = {0};
				if(m_pMaxPEFile->ReadBuffer(byBuff, (m_stParamas.dwResOffSet + m_stParamas.dwFPatchDisplacement), sizeof(byBuff), sizeof(byBuff)))
				{
					if(memcmp(byBuff, m_pbyBuff, sizeof(byBuff)) == 0)
					{
						m_stParamas.dwResOffSet = 0;
					}
				}
			}
		}
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanNimnulE
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for Nimnul.E
--------------------------------------------------------------------------------------*/
int CPolyNimnul::CleanNimnulE(void)
{
	int		iRetStatus = REPAIR_FAILED;
	DWORD	dwResOffSet = 0x00, dwTemp = 0x00;
	//DWORD	dwResSize = 0x00;
	WORD	wNameIDs = 0x00, i = 0x00;


	//0x6D
	if (m_stParamas.dwResOffSet > 0x00)
	{
		//dwReqiredOffSet+=0x4BC;
		if(!GetBuffer((m_stParamas.dwResOffSet + m_stParamas.dwFPatchDisplacement), m_stParamas.dwFPatchSize, m_stParamas.dwFPatchSize))
		{
			return iRetStatus;
		}
		m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x00],m_dwAEPMapped,m_stParamas.dwFPatchSize,m_stParamas.dwFPatchSize);

		if (m_stParamas.dwSPatchDisplacement > 0x00)
		{
			if(!GetBuffer((m_stParamas.dwResOffSet + m_stParamas.dwSPatchDisplacement), 0x10, 0x10))
			{
				return iRetStatus;
			}
			m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x00],m_dwAEPMapped + m_stParamas.dwPatchDiff,0x10,0x10);
		}
		iRetStatus = REPAIR_SUCCESS;

		m_pMaxPEFile->FillWithZeros(m_stParamas.dwResOffSet,m_stParamas.dwResSize);
	}

	return iRetStatus;	
}

/*-------------------------------------------------------------------------------------
	Function		: IsRequiredResource
	In Parameters	: DWORD dwBaseResAddrs, int iResCount, DWORD &dwResSize
	Out Parameters	: File offset
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Checks if stub is present in Resource
--------------------------------------------------------------------------------------*/
DWORD CPolyNimnul::IsRequiredResource(DWORD dwBaseResAddrs, int iResCount, DWORD &dwResSize)
{
	DWORD	dwRet = 0x00;
	DWORD	dwReadOffSet = 0x00, dwNewOffSet = 0x00;
	DWORD	dwResRVA = 0x00;

	dwReadOffSet = dwBaseResAddrs + 0x10 + (0x08 * iResCount);
	dwReadOffSet += 0x04;

	m_pMaxPEFile->ReadBuffer((LPVOID)&dwNewOffSet,dwReadOffSet,sizeof(DWORD),sizeof(DWORD));
	if (dwNewOffSet == 0x00)
		return dwRet; 

	if (dwNewOffSet > 0x80000000)
	{
		dwNewOffSet = dwNewOffSet % 0x80000000; 
	}
	dwNewOffSet += dwBaseResAddrs;

	//We are at Name ID Directory Level
	dwReadOffSet = dwNewOffSet + 0x14;
	dwNewOffSet = 0x00;
	m_pMaxPEFile->ReadBuffer((LPVOID)&dwNewOffSet,dwReadOffSet,sizeof(DWORD),sizeof(DWORD));
	if (dwNewOffSet == 0x00)
		return dwRet; 

	if (dwNewOffSet > 0x80000000)
	{
		dwNewOffSet = dwNewOffSet % 0x80000000; 
	}
	dwNewOffSet += dwBaseResAddrs;

	//We are at Language ID Directory Level
	dwReadOffSet = dwNewOffSet + 0x14;
	dwNewOffSet = 0x00;
	m_pMaxPEFile->ReadBuffer((LPVOID)&dwNewOffSet,dwReadOffSet,sizeof(DWORD),sizeof(DWORD));
	if (dwNewOffSet == 0x00)
		return dwRet; 

	if (dwNewOffSet > 0x80000000)
	{
		dwNewOffSet = dwNewOffSet % 0x80000000; 
	}
	dwNewOffSet += dwBaseResAddrs;
	dwReadOffSet = dwNewOffSet;

	//We are at Data Entry Level
	m_pMaxPEFile->ReadBuffer((LPVOID)&dwResRVA,dwReadOffSet,sizeof(DWORD),sizeof(DWORD));
	if (dwResRVA == 0x00)
		return dwRet; 

	m_pMaxPEFile->ReadBuffer((LPVOID)&dwNewOffSet,(dwReadOffSet + 0x04),sizeof(DWORD),sizeof(DWORD));
	dwResSize =  dwNewOffSet;

	m_pMaxPEFile->Rva2FileOffset(dwResRVA,&dwReadOffSet);
	if (dwReadOffSet == 0x00)
		return dwRet;

	//We are at Resource Level
	m_pMaxPEFile->ReadBuffer((LPVOID)&dwNewOffSet,dwReadOffSet,sizeof(DWORD),sizeof(DWORD));
	switch(dwNewOffSet)
	{
	case  0x00000490:
		{
			dwRet = dwReadOffSet;
			m_stParamas.dwFPatchDisplacement = 0x4BC;
			m_stParamas.dwSPatchDisplacement = 0x9AB;
			m_stParamas.dwPatchDiff = 0x4EF;
			m_stParamas.dwFPatchSize = 0x6F;
			m_stParamas.dwNimnulType = 0x01;
		}
		break;
	case 0x000004B0:
		{
			dwRet = dwReadOffSet;
			m_stParamas.dwFPatchDisplacement = 0x4FC;
			m_stParamas.dwSPatchDisplacement = 0xA1B;
			m_stParamas.dwPatchDiff = 0x51F;
			m_stParamas.dwFPatchSize = 0x7F;
			m_stParamas.dwNimnulType = 0x02;
		}
		break;
	case 0x00000650:
		{
			dwRet = dwReadOffSet;
			m_stParamas.dwFPatchDisplacement = 0x658;
			m_stParamas.dwSPatchDisplacement = 0x00;
			m_stParamas.dwPatchDiff = 0x00;
			m_pMaxPEFile->ReadBuffer((LPVOID)&dwNewOffSet,(dwReadOffSet + 0x654),sizeof(DWORD),sizeof(DWORD));
			m_stParamas.dwFPatchSize = dwNewOffSet;
			m_stParamas.dwNimnulType = 0x03;
		}
		break;
	case 0x00000660:
		{
			dwRet = dwReadOffSet;
			m_stParamas.dwFPatchDisplacement = 0x668;
			m_stParamas.dwSPatchDisplacement = 0x00;
			m_stParamas.dwPatchDiff = 0x00;
			m_pMaxPEFile->ReadBuffer((LPVOID)&dwNewOffSet,(dwReadOffSet + 0x664),sizeof(DWORD),sizeof(DWORD));
			m_stParamas.dwFPatchSize = dwNewOffSet;
			m_stParamas.dwNimnulType = 0x04;
		}
		break;
	}
	return dwRet;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectNimnulF
	In Parameters	: 
	Out Parameters	: AEP
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection of varient Nimnu.F
--------------------------------------------------------------------------------------*/
DWORD CPolyNimnul::DetectNimnulF()
{
	DWORD	dwRet = 0x00;
	
	BYTE bNimNulFSig[] = {0x8B, 0x45, 0xFC, 0xC7, 0x00, 0x83, 0xC4, 0x04, 0xE9, 0x8B, 0x45, 0xFC, 0xC7, 0x40, 0x04};
	DWORD dwIndex = 0x00;

	if(!OffSetBasedSignature(bNimNulFSig,sizeof(bNimNulFSig),&dwIndex))
	{
		return dwRet;
	}

	if(!dwIndex)
	{
		return dwRet;
	}

	dwRet = NIMNUL_F_AEPOFFSET;
	return dwRet;
}