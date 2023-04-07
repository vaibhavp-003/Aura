/*======================================================================================
FILE				: PolySality.cpp
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
NOTES				: This is detection module for malware Sality Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolySality.h"
#include "PolymorphicVirus.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolySality
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolySality::CPolySality(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{		
	m_pbyBuff = new BYTE[SALITY_BUFFER_SIZE];

	memset(&m_SalityParam, 0x00, sizeof(SALITY_PARAMS));
	m_dwNoOfBytes	= 0x00;
	m_dwSalityType	= 0x00;
	m_dwInstCount	= 0x00;	
	m_dwOriByteReplacementOff = m_dwAEPMapped;
	m_dwbufferReadRVA = 0;
	eSalityGenType = NO_VIRUS_FOUND;
	memset(m_objInstructionSet, 0, sizeof(m_objInstructionSet));
}	

/*-------------------------------------------------------------------------------------
	Function		: ~CPolySality
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolySality::~CPolySality(void)
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
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Detection routine for different varients of Sality Family
--------------------------------------------------------------------------------------*/
int CPolySality::DetectVirus(void)
{
	int	 iRetStatus = VIRUS_NOT_FOUND;
	
	if(!m_pbyBuff)
		return iRetStatus;
	
	iRetStatus = DetectSalityDriver();
	if(iRetStatus)
	{
		return iRetStatus;
	}
	
	iRetStatus = DetectSalityStub();
	if(iRetStatus)
	{
		return iRetStatus;
	}	

	if(0 == m_wNoOfSections)
	{
		return iRetStatus;	
	}
	WORD wAEPSec = m_wAEPSec;
	
	//This is Primary Check for Sality                          ..........added by mangesh to handle files which is not having sality code in last section
	for(;m_wNoOfSections - 1 != m_wAEPSec && m_wNoOfSections > 0; m_wNoOfSections--)
	{
		if((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000000)== 0xE0000000)
			break;
	}
	if(m_wNoOfSections - 1 == m_wAEPSec && (m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000000) != 0xE0000000)
		return iRetStatus;

	// Skip last sections having SRD zero 
	while(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0 || CheckForZeros(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
	{
		m_wNoOfSections--;
		if(0 == m_wNoOfSections)
		{
			return iRetStatus;	
		}
	}

	/*iRetStatus = DetectSalityEx();
	if(iRetStatus)
	{
		return iRetStatus;
	}*/
	iRetStatus = DetectSalityBHTrojan();
	if(iRetStatus)
	{
		return iRetStatus;
	}
	
	DWORD dwAEPMapped = m_dwAEPMapped;  // AEP is changed and detected as sality then write new AEP ....... added by mangesh
	DWORD dwAEPUnmapped = m_dwAEPUnmapped;
	
	
	iRetStatus = DetectSalityVirusType();

	if(!iRetStatus)
	{
		m_dwAEPMapped = dwAEPMapped;
		m_dwAEPUnmapped = dwAEPUnmapped;
		m_wAEPSec = wAEPSec;
	}

	if(iRetStatus)
	{
		if((m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > m_pMaxPEFile->m_dwFileSize))
		{
			iRetStatus =  VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSalityVirusType
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Determine the infection type of sality
--------------------------------------------------------------------------------------*/
int CPolySality::DetectSalityVirusType()
{	
	int	iRetStatus = VIRUS_NOT_FOUND;


	// Sality.T Detection by Adnan	
	m_dwInstCount = 0x00;
	iRetStatus = DetectSalityT();
	if(iRetStatus)
	{
		return iRetStatus;
	}

	m_dwInstCount = 0x00;
	iRetStatus = DetectSalityU();
	if(iRetStatus)
	{
		return iRetStatus;
	}

	m_dwInstCount = 0x00;
	iRetStatus = DetectSalityAEorAF();
	if(iRetStatus)
	{
		return iRetStatus;
	}


	m_dwbufferReadRVA = m_dwAEPUnmapped;
	if(!GetBuffer(m_dwAEPMapped, AEP_PATCHED_BUFFER_SIZE, 0x300))
	{
		return iRetStatus;	
	}

	CheckPushAndRet();

	if(!GetSalityStartAddress())
	{
		//iRetStatus = DeleteDeadCodeSamples();
		return iRetStatus;
	}
	if(m_SalityParam.m_dwAEPPatchCnt > 0x300)
	{
		//iRetStatus = DeleteDeadCodeSamples();
		return iRetStatus;
	}
	DWORD dwTemp = GetEmulatedRegister(0x00, m_SalityParam.m_dwAEPPatchCnt, m_SalityParam.m_szReqReg, m_dwbufferReadRVA + m_dwImageBase, 0x01);
	if(dwTemp == 0)
	{
		return iRetStatus;
	}

	//This is Secondary Check
	DWORD dwCheck = m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize;
	if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize)
		dwCheck = m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;

	if(!(dwTemp >=(m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)&&
		dwTemp <(m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + dwCheck)))
	{

		if(false == ((dwTemp >=(m_dwImageBase + m_pSectionHeader[m_wAEPSec].VirtualAddress + m_pSectionHeader[m_wAEPSec].Misc.VirtualSize) &&
			dwTemp <(m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + dwCheck))))
		{
			if(false == (m_wAEPSec == m_wNoOfSections - 2 && (dwTemp >=(m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 2].VirtualAddress)&&  //sality code in second last section
				dwTemp <(m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 2].VirtualAddress+m_pSectionHeader[m_wNoOfSections - 2].Misc.VirtualSize))))
				//iRetStatus = DeleteDeadCodeSamples();
				return iRetStatus;
		}
	}

	m_SalityParam.m_dwLastSecJumpRVA = dwTemp - m_dwImageBase;
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_SalityParam.m_dwLastSecJumpRVA, &m_SalityParam.m_dwLastSecJumpOffset))
	{
		return iRetStatus;
	}

	memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
	if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, 0x20))
		return iRetStatus;

	if(CheckForZeros(m_SalityParam.m_dwLastSecJumpOffset, 0x20))
	{
		return iRetStatus;
	}

	if(!GetFirstInst())
		return iRetStatus;

	// Sality detection by Adnan 
	iRetStatus = DetectSalityOG();
	if(iRetStatus)
	{
		return iRetStatus;
	}

	m_dwInstCount = 0x00;
	iRetStatus = DetectSalityBH();
	if(iRetStatus)
	{
		return iRetStatus;
	}

	m_dwInstCount = 0x00;
	iRetStatus = DetectSalityAA(false);
	if(iRetStatus)
	{
		return iRetStatus;
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSalityBHTrojan
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Determine the Nonrepairable Sality.BH infection
--------------------------------------------------------------------------------------*/
int CPolySality::DetectSalityBHTrojan()
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections  == 0x01 && 
		(m_pSectionHeader[0].Characteristics & 0xE0000000)== 0xE0000000 && 
		(m_pSectionHeader[0].SizeOfRawData + m_pSectionHeader[0].PointerToRawData)<= 0x2B000)
	{
		if(m_pMaxPEFile->m_dwFileSize <= 0x2B000)
		{
			// Signature contains LordPE string
			BYTE bSig1[] = {0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 
							0x04, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 
							0x4c, 0x01, 0x01, 0x00, 0x79, 0x72, 0x66, 0x3c, 
							0x5b, 0x4c, 0x6f, 0x72, 0x64, 0x50, 0x45, 0x5d};  
			
			// Signature contains Hello world caption string
			BYTE bSig2[] = {0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 
							0x6F, 0x00, 0x20, 0x00, 0x77, 0x00, 0x6F, 0x00, 
							0x72, 0x00, 0x6C, 0x00, 0x64, 0x00, 0x21, 0x00, 
							0x00, 0x00, 0x00, 0x00, 0x43, 0x00, 0x61, 0x00, 
							0x70, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E};
			
			if(GetBuffer(0, 0x20, 0x20))
			{
				if(memcmp(m_pbyBuff, bSig1, sizeof(bSig1))== 0)
				{
					memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
					if(GetBuffer(0x200, 0x100, 0x100))
					{
						for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes - sizeof(bSig2); dwOffset++)
						{
							if(memcmp(&m_pbyBuff[dwOffset], bSig2, sizeof(bSig2))== 0)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.BH"));		
								iRetStatus = VIRUS_FILE_DELETE;
								break;
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
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of Dundun Family
--------------------------------------------------------------------------------------*/
int CPolySality::CleanVirus(void)
{
	int	iRetStatus = REPAIR_FAILED;

	if(!m_dwSalityType)
		return iRetStatus;

	switch(m_dwSalityType)
	{
	case VIRUS_SALITY_AA:
		iRetStatus = CleanSalityGen();
		break;
	case VIRUS_SALITY_BH:
		iRetStatus = CleanSalityBH();
		if(!iRetStatus)
		{
			m_pMaxPEFile->CloseFile_NoMemberReset();
			DeleteFile(m_pMaxPEFile->m_szFilePath);
			iRetStatus = REPAIR_SUCCESS;
		}
		break;
	case VIRUS_SALITY_OG:
		iRetStatus = CleanSalityOG();
		break;
	case VIRUS_SALITY_AE:
		iRetStatus = CleanSalityAE();
		break;
	case VIRUS_SALITY_AF:
		iRetStatus = CleanSalityAF();
		break;
	case VIRUS_SALITY_T:
		iRetStatus = CleanSalityT();
		break;
	case VIRUS_SALITY_U:
		iRetStatus = CleanSalityU();
		break;
	case VIRUS_SALITY_EX:
		iRetStatus = CleanSalityEx();
		break;
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: GetSalityStartAddress
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Finds the starting file offset of infection
--------------------------------------------------------------------------------------*/
bool CPolySality::GetSalityStartAddress()
{
	DWORD	dwFlag = 0, dwPushCounter = 0, dwStartAddress = 0;
	DWORD	dwTemp = 0, dwESP = 0, dwInstructionCount = 0;
	char	*ptr = NULL;
	char	szTempReg[MAX_PATH]={0};
	char	szTempReqReg[MAX_REG_LEN] = {0x00};
	bool	bMOVDInstFound = false;
	BYTE	B1 = 0, B2 = 0, B3 = 0;

	t_disasm da;

	DWORD dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStartAddress], 0x20,0x400000, &da, DISASM_CODE);

	if(dwLength == 0x01 && strstr(da.result, "PUSHAD"))
	{
		m_SalityParam.m_bIsPUSHADAEP = TRUE;
	}

	while(dwStartAddress < m_dwNoOfBytes - 2)
	{
		B1 = *((BYTE *)(m_pbyBuff + dwStartAddress));
		B2 = *((BYTE *)(m_pbyBuff + dwStartAddress + 0x01));
		B3 = *((BYTE *)(m_pbyBuff + dwStartAddress + 0x02));


		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x03;
			continue;
		}
		if(B1==0xC0 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x02;
			continue;
		}
		if(B1==0xD0 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x02;
			continue;
		}
		if(B1==0xD2 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x02;
			continue;
		}
		if(B1==0xD3 &&(B2>=0xF0 && B2<=0xF7)) 
		{
			dwStartAddress += 0x02;
			continue;
		}
		if(B1 == 0x0F && B2 == 0xAC && B3 == 0xDD)
		{
			dwStartAddress += 0x04;
			continue;
		}
		if(B1 == 0xF3 && B2 == 0x0F && B3 == 0xBD)
		{
			dwStartAddress += 0x04;
			continue;
		}
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStartAddress], 0x20,0x400000, &da, DISASM_CODE);
 		dwStartAddress += dwLength;
		dwInstructionCount++;

		if(dwInstructionCount > 0x100)
			break;

		if(B1 == 0xE8 && dwLength == 0x05 && strstr(da.result, "CALL")&& dwFlag == 0x00)
		{
			m_SalityParam.m_bMultipleCalls++;
			dwTemp = *((DWORD *)(&m_pbyBuff[dwStartAddress - dwLength + 0x01]));

			if(NEGATIVE_JUMP(dwTemp) || (dwStartAddress+dwTemp) >= 0x300)    //.........added by mangesh
			{
				continue;
			}
			if(!(NEGATIVE_JUMP(dwTemp)) && (dwStartAddress+dwTemp) < 0x300)   //.........added by mangesh
			{
				t_disasm da1 = {0};
				dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStartAddress+dwTemp], 0x20,0x400000, &da1, DISASM_CODE);
				if((!strcmp(da1.dump,"FFFFFFC3")) && (da1.immconst == 0))
				{
					continue;
				}
				else
				{
					dwStartAddress += dwTemp;
					dwFlag = 0x01;
				}
			}							
		}
		if(dwFlag == 1 && !strcmp(da.dump,"FFFFFFC3"))
		{
			return false;
		}
		if(B1 == 0xE9 && dwLength == 0x05 && strstr(da.result, "JMP "))
		{
			dwTemp = *((DWORD *)(&m_pbyBuff[dwStartAddress - dwLength + 0x01]));
			dwTemp = m_dwAEPUnmapped + dwTemp + dwStartAddress;
			m_dwbufferReadRVA = dwTemp;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwTemp, &dwTemp))
			{
				if(!GetBuffer(dwTemp, 0x300, 0x300))


				{
					return false;
				}
				if(m_pbyBuff[0] == 0xC3 && dwFlag == 0x02)
				{
					m_SalityParam.m_bIsJUMP = FALSE;
					m_SalityParam.m_dwAEPPatchCnt = dwStartAddress;
					m_dwbufferReadRVA = m_dwAEPUnmapped;
					if(!GetBuffer(m_dwAEPMapped, 0x300, 0x300))
					{
						return false;
					}
					return true;
				}
				dwStartAddress = 0;
			}
			else
			{
				m_dwbufferReadRVA = m_dwAEPUnmapped;
			}
		}
		if(B1 == 0xFF && B2 == 0x15 && dwLength == 0x06 && strstr(da.result  , "CALL"))
		{
			m_SalityParam.m_bMultipleCalls += 2;
			if(dwPushCounter)
				dwPushCounter--;
		}

		if(dwLength == 0x02 && B1 == 0xEB && strstr(da.result, "JMP "))
		{
			BYTE bTemp = m_pbyBuff[dwStartAddress - 1];
			if(bTemp < 0x7F)
			{
				dwStartAddress +=(DWORD)bTemp;
			} 
			else
			{
				dwStartAddress -= (DWORD)(0x100 - bTemp);
			}
		}
		if(dwLength == 0x06 && B1 == 0x81 && B2==0xC4 && strstr(da.result,"ADD ESP,")&& dwFlag == 0x01)
		{
			dwTemp = *((DWORD *)(&m_pbyBuff[dwStartAddress - dwLength + 0x02]));
			dwESP += dwTemp;
			if(dwESP % sizeof(DWORD)== 0x00)
			{
				if(dwPushCounter >= dwESP/sizeof(DWORD))
				{
					dwPushCounter -= dwESP/sizeof(DWORD);
					dwESP = 0x00;
				}
			}
		}
		if(dwLength == 0x06 && B1 == 0x81 && B2==0xEC && strstr(da.result,"SUB ESP,")&& dwFlag == 0x01)
		{
			dwTemp = *((DWORD *)(&m_pbyBuff[dwStartAddress - dwLength + 0x02]));
			dwESP -= dwTemp;
			if(dwESP % sizeof(DWORD)== 0x00 && !(NEGATIVE_JUMP(dwESP)))
			{
				if(dwPushCounter >= dwESP/sizeof(DWORD))
				{
					dwPushCounter -= dwESP/sizeof(DWORD);
					dwESP = 0x00;
				}
			}
		}

		if(strstr(da.result  , "PUSH")&& dwFlag == 1)
		{
			dwPushCounter++;
		}
		if(strstr(da.result  , "POP")&& dwFlag == 1)
		{
			if(dwPushCounter)
				dwPushCounter--;
			else
			{
				sprintf_s(szTempReg, MAX_PATH, "%s",da.result);
				ptr = strchr(szTempReg,'E');
				if(ptr && strlen(ptr)== 0x03)
				{
					strcpy_s(m_SalityParam.m_szReqReg ,4,ptr);
					strcpy_s(szTempReqReg, 4, ptr);
					dwFlag = 0x02;
				}
			}
		}
		if(strstr(da.result,"JMP E")&& dwFlag == 2)
		{
			sprintf_s(szTempReg, MAX_PATH, "%s", da.result);
			ptr = strchr(szTempReg,'E');

			if(ptr && strlen(ptr)== 0x03)
			{
				if(strcmp(ptr, szTempReqReg))
					return false;
				m_SalityParam.m_dwAEPPatchCnt = dwStartAddress;
				m_SalityParam.m_bIsJUMP = TRUE;
				return true;
			}
		}
		
		if(strstr(da.result, "MOVD MM"))
		{
			bMOVDInstFound = true;
		}
		if(strstr(da.result, "MOVD E")&& strstr(da.result, "MM")&& bMOVDInstFound == true)
		{
			char *p = strstr(da.result,"E");
			if(p!=NULL)
			{
				memcpy_s(szTempReqReg ,MAX_REG_LEN,p,3);
				p=NULL;
			}
		}
		if((!strcmp(da.dump,"FFFFFFC3"))&&(dwFlag == 0x02)&&(da.immconst == 0))
		{
			m_SalityParam.m_bIsJUMP = FALSE;
			m_SalityParam.m_dwAEPPatchCnt = dwStartAddress;
			return true;
		}		
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetEmulatedRegister
	In Parameters	: DWORD dwStartAddress , DWORD dwEndAddress ,char *szRequiredRegister, DWORD dwDisasmStartAddr,int iStep
	Out Parameters	: Register value
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Get Register value using dis-assembler
--------------------------------------------------------------------------------------*/
DWORD CPolySality::GetEmulatedRegister(DWORD dwStartAddress , DWORD dwEndAddress ,char *szRequiredRegister, DWORD dwDisasmStartAddr,int iStep)
{
	
	char	szMov[MAX_REG_LEN] = {0}, szXor[MAX_REG_LEN] = {0}, szAnd[MAX_REG_LEN] = {0}, szXCHG[MAX_REG_LEN] = {0};
	char	szXADD[MAX_REG_LEN]={0}, szReg[MAX_REG_LEN] = {0};
	char	szAdd[MAX_REG_LEN] = {0} ,szSub[MAX_REG_LEN]={0};
	
	const	DWORD MAX_STACK_SIZE = 0x50;
	DWORD	dwPushStack[MAX_STACK_SIZE] = {0};
	DWORD	dwTopOfStack = 0x0;
	DWORD	dwConstValue = 0x00; //Tushar ==> 29 Dec 2010 : Used in MOVD Instruction
	bool	bMOVDInstructionFlag = false; //Tushar ==> 29 Dec 2010 : Used in MOVD Instruction
	DWORD     dwEAX = 0x00;
	DWORD     dwEBX = 0x00;
	DWORD     dwECX = 0x00;
	DWORD     dwEDX = 0x00;
	DWORD     dwESI = 0x00;
	DWORD     dwEDI = 0x00;
	DWORD	  dwEBP = 0x00;
	///////////////////////////////////////////

	t_disasm	da;
	DWORD dwLength = 0;
	bool  bFlag;
	BYTE B1 = 0x00, B2 = 0x00, B3 = 0x00;
	DWORD dwESP = 0x00;

	bFlag = false;

	strcpy_s(szReg, MAX_REG_LEN, szRequiredRegister);
	sprintf_s(szSub, 0x0B, "SUB %s,E", szReg);
	sprintf_s(szMov, 0x0B, "MOV  %s,E", szReg);
	sprintf_s(szAdd, 0x0B, "ADD %s,E", szReg);
	sprintf_s(szXor, 0x0B, "XOR %s,E", szReg);
	sprintf_s(szAnd, 0x0B, "AND %s,E", szReg);
	sprintf_s(szXCHG, 0x0B, "XCHG %s,E", szReg);
	sprintf_s(szXADD, 0x0B, "XADD %s,E", szReg);

	///////////// For Required register position
	dwLength = 0x00;
	DWORD dwTemp = 0x00;
	DWORD dwFlag = 0x00;

	bFlag = true;  /// For setting required register to zero
	dwLength = 0;
	//Tushar ==> 15 Nov 2010 : Commented this Line, we have handled it in if statements below.
	//dwEndAddress -= 0x10;

	if(dwEndAddress < 10)
	{
		return 0;
	}
	for(;dwStartAddress<dwEndAddress - 2;)
	{
		if(dwTopOfStack >= MAX_STACK_SIZE)
		{
			return 0x00;
		}
		B1 = m_pbyBuff[dwStartAddress];
		//Adnan
		B2 = m_pbyBuff[dwStartAddress + 0x01];

		// Added by Rupali on 2 Mar 2011. Fix for Sality.BH repair failed samples by Adnan.
		B3 = m_pbyBuff[dwStartAddress + 0x02];
		// End

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x03;
			continue;
		}

		// Added by Rupali on 2 Mar 2011. Fix for Sality.BH repair failed samples by Adnan.
		//SAL AL,C8
		if(B1==0xC0 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x03;
			continue;
		}
		//End

		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x02;
			continue;
		}
		if(B1==0xD0 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x02;
			continue;
		}
		if(B1==0xD2 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress+= 0x02;
			continue;
		}

		// Added by Rupali on 2 Mar 2011. Fix for Sality.BH repair failed samples by Adnan.
		if(B1==0xD3 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwStartAddress += 0x02;
			continue;
		}
		if(B1 == 0x0F && B2 == 0xAC && B3 == 0xDD)
		{
			dwStartAddress += 0x04;
			continue;
		}
		if(B1 == 0xF3 && B2 == 0x0F && B3 == 0xBD)
		{
			dwStartAddress += 0x04;
			continue;
		}
		//End

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStartAddress], 0x20,dwDisasmStartAddr, &da, DISASM_CODE);
		dwStartAddress += dwLength;
		if(!iStep)
		{
			if((strstr(da.result,szAdd)|| strstr(da.result,szAnd)|| strstr(da.result,szSub)|| strstr(da.result,szXADD)|| strstr(da.result,szXCHG)|| strstr(da.result,szXor))&&(da.immconst == 0x0))
			{
				if(!strcmp(szReg ,"EAX"))
					dwEAX = 0;
				else if(!strcmp(szReg ,"EBX"))
					dwEBX = 0;
				else if(!strcmp(szReg ,"ECX"))
					dwECX = 0;
				else if(!strcmp(szReg ,"EDX"))
					dwEDX = 0;
				else if(!strcmp(szReg ,"ESI"))
					dwESI = 0;
				else if(!strcmp(szReg ,"EDI"))
					dwEDI = 0;
				else
					dwEBP = 0;
			}	
		}
		// Handling Call
		if(iStep == 0x1)
		{
			if(dwLength == 0x05 && B1 ==0xE8 &&  strstr(da.result,"CALL")&& dwFlag == 0x00)
			{
				DWORD dwTemp1 = *((DWORD*)&m_pbyBuff[dwStartAddress - dwLength + 0x01]);

				BYTE byZeros[0x50] = {0};
				DWORD dwZeroTemp = 0;
				m_pMaxPEFile->Rva2FileOffset(dwTemp1+m_dwAEPUnmapped + dwStartAddress, &dwZeroTemp);//skip fake calls  .... added by    __mangesh
				
				if(NEGATIVE_JUMP(dwTemp1) || (dwStartAddress+dwTemp1) >= m_dwNoOfBytes)
				{
					continue;
				}
				
				if(dwZeroTemp > m_dwAEPMapped && (dwZeroTemp- m_dwAEPMapped) < m_dwNoOfBytes-0x50)
				{
					if(!memcmp(&m_pbyBuff[dwZeroTemp- m_dwAEPMapped], byZeros, sizeof(byZeros))) 
					{
						continue;
					}
				}

				if(!(NEGATIVE_JUMP(dwTemp1)) && (dwStartAddress+dwTemp1) < m_dwNoOfBytes)
				{
					dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStartAddress+dwTemp1], 0x20,0x400000, &da, DISASM_CODE);
					if((!strcmp(da.dump,"FFFFFFC3")) && (da.immconst == 0))
					{
						continue;
					}
					else
					{
						if(dwTopOfStack >= MAX_STACK_SIZE)
						{
							return 0x00;
						}
						dwPushStack[dwTopOfStack++] = dwDisasmStartAddr + dwStartAddress;
						dwStartAddress += dwTemp1;
						dwFlag = 0x01;
						continue;
					}
				}		
			}
			if(dwLength == 0x06 && B1 ==0xFF && B2 ==0x15 &&  strstr(da.result,"CALL"))
			{
				if(dwTopOfStack)
					dwTopOfStack--;
			}
			if(dwLength == 0x02 && B1 == 0xEB && strstr(da.result, "JMP "))
			{
				BYTE bTemp = m_pbyBuff[dwStartAddress-1];
				if(bTemp < 0x7F)
				{
					dwStartAddress +=(DWORD)bTemp;
				}
			}
			if(B1 == 0xE9 && dwLength == 0x05 && strstr(da.result,"JMP "))
			{
				DWORD dwTemp1 = *((DWORD*)&m_pbyBuff[dwStartAddress - dwLength + 0x01]);
				if(!(NEGATIVE_JUMP(dwTemp1)))
					dwStartAddress += dwTemp1;
			}
			if(dwLength == 0x06 && B1 == 0x81 && B2==0xC4 && strstr(da.result,"ADD ESP,")&& dwFlag == 0x01)
			{
				dwTemp = *((DWORD *)&m_pbyBuff[dwStartAddress - dwLength + 0x02]);
				dwESP += dwTemp;
				if(dwESP % sizeof(DWORD)== 0x00)
				{
					if(dwTopOfStack >= dwESP/sizeof(DWORD))
					{
						dwTopOfStack -= dwESP/sizeof(DWORD);
						dwESP = 0x00;
					}
				}
			}
			if(dwLength == 0x06 && B1 == 0x81 && B2==0xEC && strstr(da.result,"SUB ESP,")&& dwFlag == 0x01)
			{
				dwTemp = *((DWORD *)&m_pbyBuff[dwStartAddress - dwLength + 0x02]);
				if(dwESP == 0x00 && dwTemp % sizeof(DWORD) == 0x00)
				{
					dwTopOfStack += dwTemp/sizeof(DWORD);
					if(dwTopOfStack >= MAX_STACK_SIZE)
					{
						return 0x00;
					}
					continue;
				}
				dwESP -= dwTemp;
				if(dwESP % sizeof(DWORD)== 0x00)
				{
					if(dwTopOfStack >= dwESP/sizeof(DWORD))
					{
						dwTopOfStack -= dwESP/sizeof(DWORD);
						if(dwTopOfStack >= MAX_STACK_SIZE)
						{
							return 0x00;
						}
						dwESP = 0x00;
					}
				}
			}
			if(!strcmp(da.result ,"FFFFFFC3"))
				dwTopOfStack--;
		}

		if(strstr(da.result,"PUSH "))
		{
			char *cptr1 = NULL;
			cptr1 = strrchr(da.result,' ');
			if(cptr1 == NULL)//Tushar ==> 20 Nov 2010 : For Crash dump Analysis //Tushar ==> 20 Nov 2010 : For Crash dump Analysis
				break;
			cptr1++;
			if(dwTopOfStack >= MAX_STACK_SIZE)
			{
				return 0x00;
			}
			if(!strcmp(cptr1,"EAX")|| !strcmp(cptr1,"EBX")|| !strcmp(cptr1,"ECX")|| !strcmp(cptr1,"EDX")|| !strcmp(cptr1,"ESI")|| !strcmp(cptr1,"EDI")|| !strcmp(cptr1,"EBP"))
			{
				
				if(strstr(da.result,"PUSH EAX"))
					dwPushStack[dwTopOfStack++] = dwEAX;
				else if(strstr(da.result,"PUSH EBX"))
					dwPushStack[dwTopOfStack++] = dwEBX;
				else if(strstr(da.result,"PUSH ECX"))
					dwPushStack[dwTopOfStack++] = dwECX;
				else if(strstr(da.result,"PUSH EDX"))
					dwPushStack[dwTopOfStack++] = dwEDX;
				else if(strstr(da.result,"PUSH ESI"))
					dwPushStack[dwTopOfStack++] = dwESI;
				else if(strstr(da.result,"PUSH EDI"))
					dwPushStack[dwTopOfStack++] = dwEDI;
				else //if(strstr(da.result,"PUSH EBP"))
					dwPushStack[dwTopOfStack++] = dwEBP;
			}
			else
			{
				sscanf_s(cptr1, "%X", &dwTemp);
				dwPushStack[dwTopOfStack++] = dwTemp;					
			}
		}
		else if(strstr(da.result,"POP "))
		{
			char *cptr1 = NULL;
			cptr1 = strrchr(da.result,' ');
			if(cptr1 == NULL)//Tushar ==> 20 Nov 2010 : For Crash dump Analysis
				break;
			cptr1++;
			//	if(cptr1[0] == 'E')
			//	{
			if(dwTopOfStack == 0x00)
			{
				if(strstr(da.result,"POP EAX"))
					dwEAX = dwPushStack[dwTopOfStack];
				else if(strstr(da.result,"POP EBX"))
					dwEBX = dwPushStack[dwTopOfStack];
				else if(strstr(da.result,"POP ECX"))
					dwECX = dwPushStack[dwTopOfStack];
				else if(strstr(da.result,"POP EDX"))
					dwEDX = dwPushStack[dwTopOfStack];
				else if(strstr(da.result,"POP ESI"))
					dwESI = dwPushStack[dwTopOfStack];
				else if(strstr(da.result,"POP EDI"))
					dwEDI = dwPushStack[dwTopOfStack];
				else if(strstr(da.result,"POP EBP"))
					dwEBP = dwPushStack[dwTopOfStack];
			}
			else
			{
				if(strstr(da.result,"POP EAX"))
					dwEAX =  dwPushStack[--dwTopOfStack];
				else if(strstr(da.result,"POP EBX"))
					dwEBX = dwPushStack[--dwTopOfStack];
				else if(strstr(da.result,"POP ECX"))
					dwECX = dwPushStack[--dwTopOfStack];
				else if(strstr(da.result,"POP EDX"))
					dwEDX = dwPushStack[--dwTopOfStack];
				else if(strstr(da.result,"POP ESI"))
					dwESI = dwPushStack[--dwTopOfStack];
				else if(strstr(da.result,"POP EDI"))
					dwEDI = dwPushStack[--dwTopOfStack];
				else if(strstr(da.result,"POP EBP"))
					dwEBP = dwPushStack[--dwTopOfStack];
			}
			//	}
		}
		else if(strstr(da.result,"MOV "))
		{
			char *cptr1 = NULL;
			cptr1 = strrchr(da.result,',');
			if(cptr1 == NULL)//Tushar ==> 20 Nov 2010 : For Crash dump Analysis
				break;
			cptr1++;
			if(!strcmp(cptr1,"EAX")|| !strcmp(cptr1,"EBX")|| !strcmp(cptr1,"ECX")|| !strcmp(cptr1,"EDX")|| !strcmp(cptr1,"ESI")|| !strcmp(cptr1,"EDI")|| !strcmp(cptr1,"EBP"))	
			{
				////////  For MOv 
				if(strstr(da.result,"MOV EAX,E"))
				{
					if(!strcmp(da.result,"MOV EAX,EBX"))
						dwEAX = dwEBX;
					else if(!strcmp(da.result,"MOV EAX,ECX"))
						dwEAX = dwECX;
					else if(!strcmp(da.result,"MOV EAX,EDX"))
						dwEAX = dwEDX;
					else if(!strcmp(da.result,"MOV EAX,ESI"))
						dwEAX = dwESI;
					else if(!strcmp(da.result,"MOV EAX,EDI"))
						dwEAX = dwEDI;
					else if(!strcmp(da.result,"MOV EAX,EBP"))
						dwEAX = dwEBP;
				}
				else if(strstr(da.result,"MOV EBX,E"))
				{
					if(!strcmp(da.result,"MOV EBX,EAX"))
						dwEBX = dwEAX;
					else if(!strcmp(da.result,"MOV EBX,ECX"))
						dwEBX = dwECX;
					else if(!strcmp(da.result,"MOV EBX,EDX"))
						dwEBX = dwEDX;
					else if(!strcmp(da.result,"MOV EBX,ESI"))
						dwEBX = dwESI;
					else if(!strcmp(da.result,"MOV EBX,EDI"))
						dwEBX = dwEDI;
					else if(!strcmp(da.result,"MOV EBX,EBP"))
						dwEBX = dwEBP;
				}
				else if(strstr(da.result,"MOV ECX,E"))
				{
					if(!strcmp(da.result,"MOV ECX,EAX"))
						dwECX = dwEAX;
					else if(!strcmp(da.result,"MOV ECX,EBX"))
						dwECX = dwEBX;
					else if(!strcmp(da.result,"MOV ECX,EDX"))
						dwECX = dwEDX;
					else if(!strcmp(da.result,"MOV ECX,ESI"))
						dwECX = dwESI;
					else if(!strcmp(da.result,"MOV ECX,EDI"))
						dwECX = dwEDI;
					else if(!strcmp(da.result,"MOV ECX,EBP"))
						dwECX = dwEBP;
				}
				else if(strstr(da.result,"MOV EDX,E"))
				{
					if(!strcmp(da.result,"MOV EDX,EAX"))
						dwEDX = dwEAX;
					else if(!strcmp(da.result,"MOV EDX,EBX"))
						dwEDX = dwEBX;
					else if(!strcmp(da.result,"MOV EDX,ECX"))
						dwEDX = dwECX;
					else if(!strcmp(da.result,"MOV EDX,ESI"))
						dwEDX = dwESI;
					else if(!strcmp(da.result,"MOV EDX,EDI"))
						dwEDX = dwEDI;
					else if(!strcmp(da.result,"MOV EDX,EBP"))
						dwEDX = dwEBP;
				}
				else if(strstr(da.result,"MOV ESI,E"))
				{
					if(!strcmp(da.result,"MOV ESI,EAX"))
						dwESI = dwEAX;
					else if(!strcmp(da.result,"MOV ESI,EBX"))
						dwESI = dwEBX;
					else if(!strcmp(da.result,"MOV ESI,ECX"))
						dwESI = dwECX;
					else if(!strcmp(da.result,"MOV ESI,EDX"))
						dwESI = dwEDX;
					else if(!strcmp(da.result,"MOV ESI,EDI"))
						dwESI = dwEDI;
					else if(!strcmp(da.result,"MOV ESI,EBP"))
						dwESI = dwEBP;
				}
				else if(strstr(da.result,"MOV EDI,E"))
				{
					if(!strcmp(da.result,"MOV EDI,EAX"))
						dwEDI = dwEAX;
					else if(!strcmp(da.result,"MOV EDI,EBX"))
						dwEDI = dwEBX;
					else if(!strcmp(da.result,"MOV EDI,ECX"))
						dwEDI = dwECX;
					else if(!strcmp(da.result,"MOV EDI,EDX"))
						dwEDI = dwEDX;
					else if(!strcmp(da.result,"MOV EDI,ESI"))
						dwEDI = dwESI;
					else if(!strcmp(da.result,"MOV EDI,EBP"))
						dwEDI = dwEBP;
				}
				else
				{
					if(!strcmp(da.result,"MOV EBP,EAX"))
						dwEBP = dwEAX;
					else if(!strcmp(da.result,"MOV EBP,EBX"))
						dwEBP = dwEBX;
					else if(!strcmp(da.result,"MOV EBP,ECX"))
						dwEBP = dwECX;
					else if(!strcmp(da.result,"MOV EBP,EDX"))
						dwEBP = dwEDX;
					else if(!strcmp(da.result,"MOV EBP,ESI"))
						dwEBP = dwESI;
					else if(!strcmp(da.result,"MOV EBP,EDI"))
						dwEBP = dwEDI;
				}
			}
			else
			{
				sscanf_s(cptr1, "%X", &dwTemp);
				if(da.immconst ||(!strchr(cptr1,'L')&& !strchr(cptr1,'H')&& !strchr(cptr1,'X')))
				{
					if(strstr(da.result,"MOV EAX"))
						dwEAX = dwTemp;
					else if(strstr(da.result,"MOV EBX"))
						dwEBX = dwTemp;
					else if(strstr(da.result,"MOV ECX"))
						dwECX = dwTemp;
					else if(strstr(da.result,"MOV EDX"))
						dwEDX = dwTemp;
					else if(strstr(da.result,"MOV ESI"))
						dwESI = dwTemp;
					else if(strstr(da.result,"MOV EDI"))
						dwEDI = dwTemp;
					else if(strstr(da.result,"MOV EBP"))
						dwEBP = dwTemp;
				}
			}				
		}
		/////////////////////////// For Addition
		else if(strstr(da.result,"ADD ")&& da.result[0] == 'A')
		{
			char *cptr1 = NULL;
			cptr1 = strrchr(da.result,',');
			if(cptr1 == NULL)//Tushar ==> 20 Nov 2010 : For Crash dump Analysis
				break;
			cptr1++;
			if(!strcmp(cptr1,"EAX")|| !strcmp(cptr1,"EBX")|| !strcmp(cptr1,"ECX")|| !strcmp(cptr1,"EDX")|| !strcmp(cptr1,"ESI")|| !strcmp(cptr1,"EDI")|| !strcmp(cptr1,"EBP"))	
			{
				if(strstr(da.result,"ADD EAX,E"))
				{
					if(!strcmp(da.result,"ADD EAX,EBX"))
						dwEAX = dwEAX + dwEBX;
					else if(!strcmp(da.result,"ADD EAX,ECX"))
						dwEAX = dwEAX + dwECX;
					else if(!strcmp(da.result,"ADD EAX,EDX"))
						dwEAX = dwEAX + dwEDX;
					else if(!strcmp(da.result,"ADD EAX,ESI"))
						dwEAX = dwEAX + dwESI;
					else if(!strcmp(da.result,"ADD EAX,EDI"))
						dwEAX = dwEAX + dwEDI;
					else if(!strcmp(da.result,"ADD EAX,EAX"))
						dwEAX = dwEAX + dwEAX;
					else if(!strcmp(da.result,"ADD EAX,EBP"))
						dwEAX = dwEAX + dwEBP;
				}
				else if(strstr(da.result,"ADD EBX,E"))
				{
					if(!strcmp(da.result,"ADD EBX,EAX"))
						dwEBX = dwEBX + dwEAX;
					else if(!strcmp(da.result,"ADD EBX,EBX"))
						dwEBX = dwEBX + dwEBX;
					else if(!strcmp(da.result,"ADD EBX,ECX"))
						dwEBX = dwEBX + dwECX;
					else if(!strcmp(da.result,"ADD EBX,EDX"))
						dwEBX = dwEBX + dwEDX;
					else if(!strcmp(da.result,"ADD EBX,EDI"))
						dwEBX = dwEBX + dwEDI;
					else if(!strcmp(da.result,"ADD EBX,ESI"))
						dwEBX = dwEBX + dwESI;
					else if(!strcmp(da.result,"ADD EBX,EBP"))
						dwEBX = dwEBX + dwEBP;
				}
				else if(strstr(da.result,"ADD ECX,E"))
				{
					if(!strcmp(da.result,"ADD ECX,EAX"))
						dwECX = dwECX + dwEAX;
					else if(!strcmp(da.result,"ADD ECX,EBX"))
						dwECX = dwECX + dwEBX;
					else if(!strcmp(da.result,"ADD ECX,ECX"))
						dwECX = dwECX + dwECX;
					else if(!strcmp(da.result,"ADD ECX,EDX"))
						dwECX = dwECX + dwEDX;
					else if(!strcmp(da.result,"ADD ECX,ESI"))
						dwECX = dwECX + dwESI;
					else if(!strcmp(da.result,"ADD ECX,EDI"))
						dwECX = dwECX + dwEDI;
					else if(!strcmp(da.result,"ADD ECX,EBP"))
						dwECX = dwECX + dwEBP;
				}
				else if(strstr(da.result,"ADD EDX,E"))
				{
					if(!strcmp(da.result,"ADD EDX,EAX"))
						dwEDX = dwEDX + dwEAX;
					else if(!strcmp(da.result,"ADD EDX,EBX"))
						dwEDX = dwEDX + dwEBX;
					else if(!strcmp(da.result,"ADD EDX,ECX"))
						dwEDX = dwEDX + dwECX;
					else if(!strcmp(da.result,"ADD EDX,EDX"))
						dwEDX = dwEDX + dwEDX;
					else if(!strcmp(da.result,"ADD EDX,ESI"))
						dwEDX = dwEDX + dwESI;
					else if(!strcmp(da.result,"ADD EDX,EDI"))
						dwEDX = dwEDX + dwEDI;
					else if(!strcmp(da.result,"ADD EDX,EBP"))
						dwEDX = dwEDX + dwEBP;
				}
				else if(strstr(da.result,"ADD ESI,E"))
				{
					if(!strcmp(da.result,"ADD ESI,EAX"))
						dwESI = dwESI + dwEAX;
					else if(!strcmp(da.result,"ADD ESI,EBX"))
						dwESI = dwESI + dwEBX;
					else if(!strcmp(da.result,"ADD ESI,ECX"))
						dwESI = dwESI + dwECX;
					else if(!strcmp(da.result,"ADD ESI,EDX"))
						dwESI = dwESI + dwEDX;
					else if(!strcmp(da.result,"ADD ESI,EDI"))
						dwESI = dwESI + dwEDI;
					else if(!strcmp(da.result,"ADD ESI,ESI"))
						dwESI = dwESI + dwESI;
					else if(!strcmp(da.result,"ADD ESI,EBP"))
						dwESI = dwESI + dwEBP;
				}
				else if(strstr(da.result,"ADD EDI,E"))
				{
					if(!strcmp(da.result,"ADD EDI,EAX"))
						dwEDI = dwEDI + dwEAX;
					else if(!strcmp(da.result,"ADD EDI,EBX"))
						dwEDI = dwEDI + dwEBX;
					else if(!strcmp(da.result,"ADD EDI,ECX"))
						dwEDI = dwEDI + dwECX;
					else if(!strcmp(da.result,"ADD EDI,EDX"))
						dwEDI = dwEDI + dwEDX;
					else if(!strcmp(da.result,"ADD EDI,ESI"))
						dwEDI = dwEDI + dwESI;
					else if(!strcmp(da.result,"ADD EDI,EDI"))
						dwEDI = dwEDI + dwEDI;
					else if(!strcmp(da.result,"ADD EDI,EBP"))
						dwEDI = dwEDI + dwEBP;					
				}
				else
				{
					if(!strcmp(da.result,"ADD EBP,EAX"))
						dwEBP = dwEBP + dwEAX;
					else if(!strcmp(da.result,"ADD EBP,EBX"))
						dwEBP = dwEBP + dwEBX;
					else if(!strcmp(da.result,"ADD EBP,ECX"))
						dwEBP = dwEBP + dwECX;
					else if(!strcmp(da.result,"ADD EBP,EDX"))
						dwEBP = dwEBP + dwEDX;
					else if(!strcmp(da.result,"ADD EBP,ESI"))
						dwEBP = dwEBP + dwESI;
					else if(!strcmp(da.result,"ADD EBP,EDI"))
						dwEBP = dwEBP + dwEDI;
					else if(!strcmp(da.result,"ADD EBP,EBP"))
						dwEBP = dwEBP + dwEBP;					
				}
			}
			else 
			{
				sscanf_s(cptr1, "%X", &dwTemp);
				if(da.immconst ||(!strchr(cptr1,'L')&& !strchr(cptr1,'H')&& !strchr(cptr1,'X')))
				{
					if(strstr(da.result,"ADD EAX"))
						dwEAX = dwEAX + dwTemp;
					else if(strstr(da.result,"ADD EBX"))
						dwEBX = dwEBX + dwTemp;
					else if(strstr(da.result,"ADD ECX"))
						dwECX = dwECX + dwTemp;
					else if(strstr(da.result,"ADD EDX"))
						dwEDX = dwEDX + dwTemp;
					else if(strstr(da.result,"ADD ESI"))
						dwESI = dwESI + dwTemp;
					else if(strstr(da.result,"ADD EDI"))
						dwEDI = dwEDI + dwTemp;
					else if(strstr(da.result,"ADD EBP"))
						dwEBP = dwEBP + dwTemp;
				}
			}
		}
		/////////////////////////////////For Substraction
		else if(strstr(da.result,"SUB "))
		{
			char *cptr1 = NULL;
			cptr1 = strrchr(da.result,',');
			if(cptr1 == NULL)//Tushar ==> 20 Nov 2010 : For Crash dump Analysis
				break;
			cptr1++;	
			if(!strcmp(cptr1,"EAX")|| !strcmp(cptr1,"EBX")|| !strcmp(cptr1,"ECX")|| !strcmp(cptr1,"EDX")|| !strcmp(cptr1,"ESI")|| !strcmp(cptr1,"EDI")|| !strcmp(cptr1,"EBP"))	
			{
				if(strstr(da.result,"SUB EAX,E"))
				{
					if(!strcmp(da.result,"SUB EAX,EAX"))
						dwEAX = dwEAX - dwEAX;
					else if(!strcmp(da.result,"SUB EAX,EBX"))
						dwEAX = dwEAX - dwEBX;
					else if(!strcmp(da.result,"SUB EAX,ECX"))
						dwEAX = dwEAX - dwECX;
					else if(!strcmp(da.result,"SUB EAX,EDX"))
						dwEAX = dwEAX - dwEDX;
					else if(!strcmp(da.result,"SUB EAX,EDI"))
						dwEAX = dwEAX - dwEDI;
					else if(!strcmp(da.result,"SUB EAX,ESI"))
						dwEAX = dwEAX - dwESI;
					else if(!strcmp(da.result,"SUB EAX,EBP"))
						dwEAX = dwEAX - dwEBP;
				}
				else if(strstr(da.result,"SUB EBX,E"))
				{
					if(!strcmp(da.result,"SUB EBX,EAX"))
						dwEBX = dwEBX - dwEAX;
					else if(!strcmp(da.result,"SUB EBX,EBX"))
						dwEBX = dwEBX - dwEBX;
					else if(!strcmp(da.result,"SUB EBX,ECX"))
						dwEBX = dwEBX - dwECX;
					else if(!strcmp(da.result,"SUB EBX,EDX"))
						dwEBX = dwEBX - dwEDX;
					else if(!strcmp(da.result,"SUB EBX,ESI"))
						dwEBX = dwEBX - dwESI;
					else if(!strcmp(da.result,"SUB EBX,EDI"))
						dwEBX = dwEBX - dwEDI;
					else if(!strcmp(da.result,"SUB EBX,EBP"))
						dwEBX = dwEBX - dwEBP;
				}
				else if(strstr(da.result,"SUB ECX,E"))
				{
					if(!strcmp(da.result,"SUB ECX,EAX"))
						dwECX = dwECX - dwEAX;
					else if(!strcmp(da.result,"SUB ECX,EBX"))
						dwECX = dwECX - dwEBX;
					else if(!strcmp(da.result,"SUB ECX,ECX"))
						dwECX = dwECX - dwECX;
					else if(!strcmp(da.result,"SUB ECX,EDX"))
						dwECX = dwECX - dwEDX;
					else if(!strcmp(da.result,"SUB ECX,ESI"))
						dwECX = dwECX - dwESI;
					else if(!strcmp(da.result,"SUB ECX,EDI"))
						dwECX = dwECX - dwEDI;
					else if(!strcmp(da.result,"SUB ECX,EBP"))
						dwECX = dwECX - dwEBP;
				}
				else if(strstr(da.result,"SUB EDX,E"))
				{
					if(!strcmp(da.result,"SUB EDX,EAX"))
						dwEDX = dwEDX - dwEAX;
					else if(!strcmp(da.result,"SUB EDX,EBX"))
						dwEDX = dwEDX - dwEBX;
					else if(!strcmp(da.result,"SUB EDX,ECX"))
						dwEDX = dwEDX - dwECX;
					else if(!strcmp(da.result,"SUB EDX,EDX"))
						dwEDX = dwEDX - dwEDX;
					else if(!strcmp(da.result,"SUB EDX,ESI"))
						dwEDX = dwEDX - dwESI;
					else if(!strcmp(da.result,"SUB EDX,EDI"))
						dwEDX = dwEDX - dwEDI;
					else if(!strcmp(da.result,"SUB EDX,EBP"))
						dwEDX = dwEDX - dwEBP;
				}
				else if(strstr(da.result,"SUB ESI,E"))
				{
					if(!strcmp(da.result,"SUB ESI,EAX"))
						dwESI = dwESI - dwEAX;
					else if(!strcmp(da.result,"SUB ESI,EBX"))
						dwESI = dwESI - dwEBX;
					else if(!strcmp(da.result,"SUB ESI,ECX"))
						dwESI = dwESI - dwECX;
					else if(!strcmp(da.result,"SUB ESI,EDX"))
						dwESI = dwESI - dwEDX;
					else if(!strcmp(da.result,"SUB ESI,EDI"))
						dwESI = dwESI - dwEDI;
					else if(!strcmp(da.result,"SUB ESI,ESI"))
						dwESI = dwESI - dwESI;
					else if(!strcmp(da.result,"SUB ESI,EBP"))
						dwESI = dwESI - dwEBP;
				}
				else if(strstr(da.result,"SUB EDI,E"))
				{
					if(!strcmp(da.result,"SUB EDI,EAX"))
						dwEDI = dwEDI - dwEAX;
					else if(!strcmp(da.result,"SUB EDI,EBX"))
						dwEDI = dwEDI - dwEBX;
					else if(!strcmp(da.result,"SUB EDI,ECX"))
						dwEDI = dwEDI - dwECX;
					else if(!strcmp(da.result,"SUB EDI,EDX"))
						dwEDI = dwEDI - dwEDX;
					else if(!strcmp(da.result,"SUB EDI,ESI"))
						dwEDI = dwEDI - dwESI;
					else if(!strcmp(da.result,"SUB EDI,EDI"))
						dwEDI = dwEDI - dwEDI;
					else if(!strcmp(da.result,"SUB EDI,EBP"))
						dwEDI = dwEDI - dwEBP;
				}
				else
				{
					if(!strcmp(da.result,"SUB EBP,EAX"))
						dwEBP = dwEBP - dwEAX;
					else if(!strcmp(da.result,"SUB EBP,EBX"))
						dwEBP = dwEBP - dwEBX;
					else if(!strcmp(da.result,"SUB EBP,ECX"))
						dwEBP = dwEBP - dwECX;
					else if(!strcmp(da.result,"SUB EBP,EDX"))
						dwEBP = dwEBP - dwEDX;
					else if(!strcmp(da.result,"SUB EBP,ESI"))
						dwEBP = dwEBP - dwESI;
					else if(!strcmp(da.result,"SUB EBP,EDI"))
						dwEBP = dwEBP - dwEDI;
					else if(!strcmp(da.result,"SUB EBP,EBP"))
						dwEBP = dwEBP - dwEBP;												
				}
			}
			else
			{
				sscanf_s(cptr1, "%X", &dwTemp);
				if(da.immconst ||(!strchr(cptr1,'L')&& !strchr(cptr1,'H')&& !strchr(cptr1,'X')))
				{
					if(strstr(da.result,"SUB EAX"))
						dwEAX = dwEAX - dwTemp;
					else if(strstr(da.result,"SUB EBX"))
						dwEBX = dwEBX - dwTemp;
					else if(strstr(da.result,"SUB ECX"))
						dwECX = dwECX - dwTemp;
					else if(strstr(da.result,"SUB EDX"))
						dwEDX = dwEDX - dwTemp;
					else if(strstr(da.result,"SUB ESI"))
						dwESI = dwESI - dwTemp;
					else if(strstr(da.result,"SUB EDI"))
						dwEDI = dwEDI - dwTemp;
					else if(strstr(da.result,"SUB EBP"))
						dwEBP = dwEBP - dwTemp;
				}
			}
		}
		////////////////////////////////FOR XOR operation			
		else if(strstr(da.result,"XOR ")&& da.result[0] == 'X')
		{
			char *cptr1 = NULL;
			cptr1 = strrchr(da.result,',');
			if(cptr1 == NULL)//Tushar ==> 20 Nov 2010 : For Crash dump Analysis
				break;
			cptr1++;
			if(!strcmp(cptr1,"EAX")|| !strcmp(cptr1,"EBX")|| !strcmp(cptr1,"ECX")|| !strcmp(cptr1,"EDX")|| !strcmp(cptr1,"ESI")|| !strcmp(cptr1,"EDI")|| !strcmp(cptr1,"EBP"))	
			{
				if(strstr(da.result,"XOR EAX,E"))
				{
					if(!strcmp(da.result,"XOR EAX,EAX"))
						dwEAX = dwEAX ^ dwEAX;
					else if(!strcmp(da.result,"XOR EAX,EBX"))
						dwEAX = dwEAX ^ dwEBX;
					else if(!strcmp(da.result,"XOR EAX,ECX"))
						dwEAX = dwEAX ^ dwECX;
					else if(!strcmp(da.result,"XOR EAX,EDX"))
						dwEAX = dwEAX ^ dwEDX;
					else if(!strcmp(da.result,"XOR EAX,ESI"))
						dwEAX = dwEAX ^ dwESI;
					else if(!strcmp(da.result,"XOR EAX,EDI"))
						dwEAX = dwEAX ^ dwEDI;
					else if(!strcmp(da.result,"XOR EAX,EBP"))
						dwEAX = dwEAX ^ dwEBP;
				}
				else if(strstr(da.result,"XOR EBX,E"))
				{
					if(!strcmp(da.result,"XOR EBX,EAX"))
						dwEBX = dwEBX ^ dwEAX;
					else if(!strcmp(da.result,"XOR EBX,EBX"))
						dwEBX = dwEBX ^ dwEBX;
					else if(!strcmp(da.result,"XOR EBX,ECX"))
						dwEBX = dwEBX ^ dwECX;
					else if(!strcmp(da.result,"XOR EBX,EDX"))
						dwEBX = dwEBX ^ dwEDX;
					else if(!strcmp(da.result,"XOR EBX,ESI"))
						dwEBX = dwEBX ^ dwESI;
					else if(!strcmp(da.result,"XOR EBX,EDI"))
						dwEBX = dwEBX ^ dwEDI;
					else if(!strcmp(da.result,"XOR EBX,EBP"))
						dwEBX = dwEBX ^ dwEBP;
				}
				else if(strstr(da.result,"XOR ECX,E"))
				{
					if(!strcmp(da.result,"XOR ECX,EAX"))
						dwECX = dwECX ^ dwEAX;
					else if(!strcmp(da.result,"XOR ECX,EBX"))
						dwECX = dwECX ^ dwEBX;
					else if(!strcmp(da.result,"XOR ECX,ECX"))
						dwECX = dwECX ^ dwECX;
					else if(!strcmp(da.result,"XOR ECX,EDX"))
						dwECX = dwECX ^ dwEDX;
					else if(!strcmp(da.result,"XOR ECX,ESI"))
						dwECX = dwECX ^ dwESI;
					else if(!strcmp(da.result,"XOR ECX,EDI"))
						dwECX = dwECX ^ dwEDI;
					else if(!strcmp(da.result,"XOR ECX,EBP"))
						dwECX = dwECX ^ dwEBP;
				}
				else if(strstr(da.result,"XOR EDX,E"))
				{
					if(!strcmp(da.result,"XOR EDX,EAX"))
						dwEDX = dwEDX ^ dwEAX;
					else if(!strcmp(da.result,"XOR EDX,EBX"))
						dwEDX = dwEDX ^ dwEBX;
					else if(!strcmp(da.result,"XOR EDX,ECX"))
						dwEDX = dwEDX ^ dwECX;
					else if(!strcmp(da.result,"XOR EDX,EDX"))
						dwEDX = dwEDX ^ dwEDX;
					else if(!strcmp(da.result,"XOR EDX,ESI"))
						dwEDX = dwEDX ^ dwESI;
					else if(!strcmp(da.result,"XOR EDX,EDI"))
						dwEDX = dwEDX ^ dwEDI;
					else if(!strcmp(da.result,"XOR EDX,EBP"))
						dwEDX = dwEDX ^ dwEBP;
				}
				else if(strstr(da.result,"XOR ESI,E"))
				{
					if(!strcmp(da.result,"XOR ESI,EAX"))
						dwESI = dwESI ^ dwEAX;
					else if(!strcmp(da.result,"XOR ESI,EBX"))
						dwESI = dwESI ^ dwEBX;
					else if(!strcmp(da.result,"XOR ESI,ECX"))
						dwESI = dwESI ^ dwECX;
					else if(!strcmp(da.result,"XOR ESI,EDX"))
						dwESI = dwESI ^ dwEDX;
					else if(!strcmp(da.result,"XOR ESI,EDI"))
						dwESI = dwESI ^ dwEDI;
					else if(!strcmp(da.result,"XOR ESI,ESI"))
						dwESI = dwESI ^ dwESI;
					else if(!strcmp(da.result,"XOR ESI,EBP"))
						dwESI = dwESI ^ dwEBP;
				}
				else if(strstr(da.result,"XOR EDI,E"))
				{
					if(!strcmp(da.result,"XOR EDI,EAX"))
						dwEDI = dwEDI ^ dwEAX;
					else if(!strcmp(da.result,"XOR EDI,EBX"))
						dwEDI = dwEDI ^ dwEBX;
					else if(!strcmp(da.result,"XOR EDI,ECX"))
						dwEDI = dwEDI ^ dwECX;
					else if(!strcmp(da.result,"XOR EDI,EDX"))
						dwEDI = dwEDI ^ dwEDX;
					else if(!strcmp(da.result,"XOR EDI,ESI"))
						dwEDI = dwEDI ^ dwESI;
					else if(!strcmp(da.result,"XOR EDI,EDI"))
						dwEDI = dwEDI ^ dwEDI;
					else if(!strcmp(da.result,"XOR EDI,EBP"))
						dwEDI = dwEDI ^ dwEBP;
				}
				else
				{
					if(!strcmp(da.result,"XOR EBP,EAX"))
						dwEBP = dwEBP ^ dwEAX;
					else if(!strcmp(da.result,"XOR EBP,EBX"))
						dwEBP = dwEBP ^ dwEBX;
					else if(!strcmp(da.result,"XOR EBP,ECX"))
						dwEBP = dwEBP ^ dwECX;
					else if(!strcmp(da.result,"XOR EBP,EDX"))
						dwEBP = dwEBP ^ dwEDX;
					else if(!strcmp(da.result,"XOR EBP,ESI"))
						dwEBP = dwEBP ^ dwESI;
					else if(!strcmp(da.result,"XOR EBP,EDI"))
						dwEBP = dwEBP ^ dwEDI;
					else if(!strcmp(da.result,"XOR EBP,EBP"))//Tushar ==> Modified on 10 Nov 2010
						dwEBP = dwEBP ^ dwEBP;
				}
			}
			else
			{
				sscanf_s(cptr1, "%X", &dwTemp);
				if(da.immconst ||(!strchr(cptr1,'L')&& !strchr(cptr1,'H')&& !strchr(cptr1,'X')))
				{
					if(strstr(da.result,"XOR EAX"))
						dwEAX = dwEAX ^ dwTemp;
					else if(strstr(da.result,"XOR EBX"))
						dwEBX = dwEBX ^ dwTemp;
					else if(strstr(da.result,"XOR ECX"))
						dwECX = dwECX ^ dwTemp;					
					else if(strstr(da.result,"XOR EDX"))
						dwEDX = dwEDX ^ dwTemp;
					else if(strstr(da.result,"XOR EDI"))
						dwEDI = dwEDI ^ dwTemp;
					else if(strstr(da.result,"XOR ESI"))
						dwESI = dwESI ^ dwTemp;
					else if(strstr(da.result,"XOR EBP"))
						dwEBP = dwEBP ^ dwTemp;	
				}
			}
		}
		else if(strstr(da.result,"OR")&& da.result[0] == 'O')
		{
			char *cptr1 = NULL;
			cptr1 = strrchr(da.result,',');
			if(cptr1 == NULL)//Tushar ==> 20 Nov 2010 : For Crash dump Analysis
				break;
			cptr1++;
			if(!strcmp(cptr1,"EAX")|| !strcmp(cptr1,"EBX")|| !strcmp(cptr1,"ECX")|| !strcmp(cptr1,"EDX")|| !strcmp(cptr1,"ESI")|| !strcmp(cptr1,"EDI")|| !strcmp(cptr1,"EBP"))	
			{
				if(strstr(da.result,"OR EAX,E"))
				{
					if(!strcmp(da.result,"OR EAX,EAX"))
						dwEAX = dwEAX | dwEAX;
					else if(!strcmp(da.result,"OR EAX,EBX"))
						dwEAX = dwEAX | dwEBX;
					else if(!strcmp(da.result,"OR EAX,ECX"))
						dwEAX = dwEAX | dwECX;
					else if(!strcmp(da.result,"OR EAX,EDX"))
						dwEAX = dwEAX | dwEDX;
					else if(!strcmp(da.result,"OR EAX,ESI"))
						dwEAX = dwEAX | dwESI;
					else if(!strcmp(da.result,"OR EAX,EDI"))
						dwEAX = dwEAX | dwEDI;
					else if(!strcmp(da.result,"OR EAX,EBP"))
						dwEAX = dwEAX | dwEBP;
				}
				else if(strstr(da.result,"OR EBX,E"))
				{	
					if(!strcmp(da.result,"OR EBX,EAX"))
						dwEBX = dwEBX | dwEAX;
					else if(!strcmp(da.result,"OR EBX,EBX"))
						dwEBX = dwEBX | dwEBX;
					else if(!strcmp(da.result,"OR EBX,ECX"))
						dwEBX = dwEBX | dwECX;
					else if(!strcmp(da.result,"OR EBX,EDX"))
						dwEBX = dwEBX | dwEDX;
					else if(!strcmp(da.result,"OR EBX,ESI"))
						dwEBX = dwEBX | dwESI;
					else if(!strcmp(da.result,"OR EBX,EDI"))
						dwEBX = dwEBX | dwEDI;
					else if(!strcmp(da.result,"OR EBX,EBP"))
						dwEBX = dwEBX | dwEBP;
				}
				else if(strstr(da.result,"OR ECX,E"))
				{
					if(!strcmp(da.result,"OR ECX,EAX"))
						dwECX = dwECX | dwEAX;
					else if(!strcmp(da.result,"OR ECX,EBX"))
						dwECX = dwECX | dwEBX;
					else if(!strcmp(da.result,"OR ECX,ECX"))
						dwECX = dwECX | dwECX;
					else if(!strcmp(da.result,"OR ECX,EDX"))
						dwECX = dwECX | dwEDX;
					else if(!strcmp(da.result,"OR ECX,ESI"))
						dwECX = dwECX | dwESI;
					else if(!strcmp(da.result,"OR ECX,EDI"))
						dwECX = dwECX | dwEDI;
					else if(!strcmp(da.result,"OR ECX,EBP"))
						dwECX = dwECX | dwEBP;
				}
				else if(strstr(da.result,"OR EDX,E"))
				{
					if(!strcmp(da.result,"OR EDX,EAX"))
						dwEDX = dwEDX | dwEAX;
					else if(!strcmp(da.result,"OR EDX,EBX"))
						dwEDX = dwEDX | dwEBX;
					else if(!strcmp(da.result,"OR EDX,ECX"))
						dwEDX = dwEDX | dwECX;
					else if(!strcmp(da.result,"OR EDX,EDX"))
						dwEDX = dwEDX | dwEDX;
					else if(!strcmp(da.result,"OR EDX,ESI"))
						dwEDX = dwEDX | dwESI;
					else if(!strcmp(da.result,"OR EDX,EDI"))
						dwEDX = dwEDX | dwEDI;
					else if(!strcmp(da.result,"OR EDX,EBP"))
						dwEDX = dwEDX | dwEBP;
				}
				else if(strstr(da.result,"OR EDI,E"))
				{
					if(!strcmp(da.result,"OR EDI,EAX"))
						dwEDI = dwEDI | dwEAX;
					else if(!strcmp(da.result,"OR EDI,EBX"))
						dwEDI = dwEDI | dwEBX;
					else if(!strcmp(da.result,"OR EDI,ECX"))
						dwEDI = dwEDI | dwECX;
					else if(!strcmp(da.result,"OR EDI,EDX"))
						dwEDI = dwEDI | dwEDX;
					else if(!strcmp(da.result,"OR EDI,ESI"))
						dwEDI = dwEDI | dwESI;
					else if(!strcmp(da.result,"OR EDI,EDI"))
						dwEDI = dwEDI | dwEDI;
					else if(!strcmp(da.result,"OR EDI,EBP"))
						dwEDI = dwEDI | dwEBP;
				}
				else if(strstr(da.result,"OR ESI,E"))
				{	
					if(!strcmp(da.result,"OR ESI,EAX"))
						dwESI = dwESI | dwEAX;
					else if(!strcmp(da.result,"OR ESI,EBX"))
						dwESI = dwESI | dwEBX;
					else if(!strcmp(da.result,"OR ESI,ECX"))
						dwESI = dwESI | dwECX;
					else if(!strcmp(da.result,"OR ESI,EDX"))
						dwESI = dwESI | dwEDX;
					else if(!strcmp(da.result,"OR ESI,EDI"))
						dwESI = dwESI | dwEDI;
					else if(!strcmp(da.result,"OR ESI,ESI"))
						dwESI = dwESI | dwESI;
					else if(!strcmp(da.result,"OR ESI,EBP"))
						dwESI = dwESI | dwEBP;
				}
				else
				{
					if(!strcmp(da.result,"OR EBP,EAX"))
						dwEBP = dwEBP | dwEAX;
					else if(!strcmp(da.result,"OR EBP,EBX"))
						dwEBP = dwEBP | dwEBX;
					else if(!strcmp(da.result,"OR EBP,ECX"))
						dwEBP = dwEBP | dwECX;
					else if(!strcmp(da.result,"OR EBP,EDX"))
						dwEBP = dwEBP | dwEDX;
					else if(!strcmp(da.result,"OR EBP,EDI"))
						dwEBP = dwEBP | dwEDI;
					else if(!strcmp(da.result,"OR EBP,ESI"))
						dwEBP = dwEBP | dwESI;
					else if(!strcmp(da.result,"OR EBP,EBP"))//Tushar ==> Modified on 10 Nov 2010
						dwEBP = dwEBP | dwEBP;				
				}
			}
			else
			{
				sscanf_s(cptr1, "%X", &dwTemp);
				if(da.immconst ||(!strchr(cptr1,'L')&& !strchr(cptr1,'H')&& !strchr(cptr1,'X')))
				{
					if(strstr(da.result,"OR EAX"))
						dwEAX = dwEAX | dwTemp;
					else if(strstr(da.result,"OR EBX"))	
						dwEBX = dwEBX | dwTemp;
					else if(strstr(da.result,"OR ECX"))
						dwECX = dwECX | dwTemp;
					else if(strstr(da.result,"OR EDX"))
						dwEDX = dwEDX | dwTemp;		
					else if(strstr(da.result,"OR EDI"))
						dwEDI = dwEDI | dwTemp;
					else if(strstr(da.result,"OR ESI"))
						dwESI = dwESI | dwTemp;
					else if(strstr(da.result,"OR EBP"))
						dwEBP = dwEBP | dwTemp;
				}		
			}
		}
		else if(strstr(da.result,"AND"))
		{
			char *cptr1 = NULL;
			cptr1 = strrchr(da.result,',');
			if(cptr1 == NULL)//Tushar ==> 20 Nov 2010 : For Crash dump Analysis
				break;
			cptr1++;
			if(!strcmp(cptr1,"EAX")|| !strcmp(cptr1,"EBX")|| !strcmp(cptr1,"ECX")|| !strcmp(cptr1,"EDX")|| !strcmp(cptr1,"ESI")|| !strcmp(cptr1,"EDI")|| !strcmp(cptr1,"EBP"))	
			{
				if(strstr(da.result,"AND EAX,E"))
				{
					if(!strcmp(da.result,"AND EAX,EAX"))
						dwEAX = dwEAX & dwEAX;
					else if(!strcmp(da.result,"AND EAX,EBX"))
						dwEAX = dwEAX & dwEBX;
					else if(!strcmp(da.result,"AND EAX,ECX"))
						dwEAX = dwEAX & dwECX;
					else if(!strcmp(da.result,"AND EAX,EDX"))
						dwEAX = dwEAX & dwEDX;
					else if(!strcmp(da.result,"AND EAX,ESI"))
						dwEAX = dwEAX & dwESI;
					else if(!strcmp(da.result,"AND EAX,EDI"))
						dwEAX = dwEAX & dwEDI;
					else if(!strcmp(da.result,"AND EAX,EBP"))
						dwEAX = dwEAX & dwEBP;
				}
				else if(strstr(da.result,"AND EBX,E"))
				{
					if(!strcmp(da.result,"AND EBX,EAX"))
						dwEBX = dwEBX & dwEAX;
					else if(!strcmp(da.result,"AND EBX,EBX"))
						dwEBX = dwEBX & dwEBX;
					else if(!strcmp(da.result,"AND EBX,ECX"))
						dwEBX = dwEBX & dwECX;
					else if(!strcmp(da.result,"AND EBX,EDX"))
						dwEBX = dwEBX & dwEDX;
					else if(!strcmp(da.result,"AND EBX,ESI"))
						dwEBX = dwEBX & dwESI;
					else if(!strcmp(da.result,"AND EBX,EDI"))
						dwEBX = dwEBX & dwEDI;
					else if(!strcmp(da.result,"AND EBX,EBP"))
						dwEBX = dwEBX & dwEBP;
				}
				else if(strstr(da.result,"AND ECX,E"))
				{
					if(!strcmp(da.result,"AND ECX,EAX"))
						dwECX = dwECX & dwEAX;
					else if(!strcmp(da.result,"AND ECX,EBX"))
						dwECX = dwECX & dwEBX;
					else if(!strcmp(da.result,"AND ECX,ECX"))
						dwECX = dwECX & dwECX;
					else if(!strcmp(da.result,"AND ECX,EDX"))
						dwECX = dwECX & dwEDX;
					else if(!strcmp(da.result,"AND ECX,ESI"))
						dwECX = dwECX & dwESI;
					else if(!strcmp(da.result,"AND ECX,EDI"))
						dwECX = dwECX & dwEDI;
					else if(!strcmp(da.result,"ANd ECX,EBP"))
						dwECX = dwECX & dwEBP;
				}
				else if(strstr(da.result,"AND EDX,E"))	
				{
					if(!strcmp(da.result,"AND EDX,EAX"))
						dwEDX = dwEDX & dwEAX;
					else if(!strcmp(da.result,"AND EDX,EBX"))
						dwEDX = dwEDX & dwEBX;
					else if(!strcmp(da.result,"AND EDX,ECX"))
						dwEDX = dwEDX & dwECX;
					else if(!strcmp(da.result,"AND EDX,EDX"))
						dwEDX = dwEDX & dwEDX;
					else if(!strcmp(da.result,"AND EDX,ESI"))
						dwEDX = dwEDX & dwESI;
					else if(!strcmp(da.result,"AND EDX,EDI"))
						dwEDX = dwEDX & dwEDI;
					else if(!strcmp(da.result,"ANd EDX,EBP"))
						dwEDX = dwEDX & dwEBP;
				}
				else if(strstr(da.result,"AND ESI,E"))
				{
					if(!strcmp(da.result,"AND ESI,EAX"))
						dwESI = dwESI & dwEAX;
					else if(!strcmp(da.result,"AND ESI,EBX"))
						dwESI = dwESI & dwEBX;
					else if(!strcmp(da.result,"AND ESI,ECX"))
						dwESI = dwESI & dwECX;
					else if(!strcmp(da.result,"AND ESI,EDX"))
						dwESI = dwESI & dwEDX;
					else if(!strcmp(da.result,"AND ESI,EDI"))
						dwESI = dwESI & dwEDI;
					else if(!strcmp(da.result,"AND ESI,ESI"))
						dwESI = dwESI & dwESI;
					else if(!strcmp(da.result,"AND ESI,EBP"))
						dwESI = dwESI & dwEBP;
				}
				else if(strstr(da.result,"AND EDI,E"))
				{
					if(!strcmp(da.result,"AND EDI,EAX"))
						dwEDI = dwEDI & dwEAX;
					else if(!strcmp(da.result,"AND EDI,EBX"))
						dwEDI = dwEDI & dwEBX;
					else if(!strcmp(da.result,"AND EDI,ECX"))
						dwEDI = dwEDI & dwECX;
					else if(!strcmp(da.result,"AND EDI,EDX"))
						dwEDI = dwEDI & dwEDX;
					else if(!strcmp(da.result,"AND EDI,ESI"))
						dwEDI = dwEDI & dwESI;
					else if(!strcmp(da.result,"AND EDI,EDI"))
						dwEDI = dwEDI & dwEDI;
					else if(!strcmp(da.result,"AND EDI,EBP"))
						dwEDI = dwEDI & dwEBP;
				}
				else
				{
					if(!strcmp(da.result,"AND EBP,EAX"))
						dwEBP = dwEBP & dwEAX;
					else if(!strcmp(da.result,"AND EBP,EBX"))
						dwEBP = dwEBP & dwEBX;
					else if(!strcmp(da.result,"AND EBP,ECX"))
						dwEBP = dwEBP & dwECX;
					else if(!strcmp(da.result,"AND EBP,EDX"))
						dwEBP = dwEBP & dwEDX;
					else if(!strcmp(da.result,"AND EBP,ESI"))
						dwEBP = dwEBP & dwESI;
					else if(!strcmp(da.result,"AND EBP,EDI"))
						dwEBP = dwEBP & dwEDI;
					else if(!strcmp(da.result,"AND EBP,EBP"))
						dwEBP = dwEBP & dwEBP;
				}
			}
			else
			{
				sscanf_s(cptr1, "%X", &dwTemp);
				if(da.immconst ||(!strchr(cptr1,'L')&& !strchr(cptr1,'H')&& !strchr(cptr1,'X')))
				{			
					if(strstr(da.result,"AND EAX"))
						dwEAX = dwEAX & dwTemp;
					else if(strstr(da.result,"AND EBX"))
						dwEBX = dwEBX & dwTemp;
					else if(strstr(da.result,"AND ECX"))
						dwECX = dwECX & dwTemp;
					else if(strstr(da.result,"AND EDX"))
						dwEDX = dwEDX & dwTemp;
					else if(strstr(da.result,"AND EDI"))
						dwEDI = dwEDI & dwTemp;
					else if(strstr(da.result,"AND ESI"))
						dwESI = dwESI & dwTemp;
					else if(strstr(da.result,"AND EBP"))
						dwEBP = dwEBP & dwTemp;
				}
			}
		}
		/////////////////////XADD Instruction
		else if(strstr(da.result,"XADD E"))
		{
			DWORD dwTemp=0;

			if(strstr(da.result,"XADD EAX,E"))
			{
				dwTemp=dwEAX;
				if(!strcmp(da.result,"XADD EAX,EAX"))
					dwEAX=dwTemp;
				else if(!strcmp(da.result,"XADD EAX,EBX"))
				{dwEAX+=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XADD EAX,ECX"))
				{dwEAX+=dwECX;dwECX=dwTemp;}
				else if(!strcmp(da.result,"XADD EAX,EDX"))
				{dwEAX+=dwEDX;dwEDX=dwTemp;}	
				else if(!strcmp(da.result,"XADD EAX,ESI"))
				{dwEAX+=dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XADD EAX,EDI"))
				{dwEAX=dwEAX + dwEDI;dwEDI=dwTemp;}
				else if(!strcmp(da.result,"XADD EAX,EBP"))
				{dwEAX=dwEAX + dwEBP;dwEBP=dwTemp;}
			}
			else if(strstr(da.result,"XADD EBX,E"))
			{
				dwTemp=dwEBX;
				if(!strcmp(da.result,"XADD EBX,EBX"))
					dwEBX=dwTemp;
				else if(!strcmp(da.result,"XADD EBX,EAX"))
				{dwEBX=dwEBX + dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XADD EBX,ECX"))
				{dwEBX=dwEBX + dwECX;dwECX=dwTemp;}
				else if(!strcmp(da.result,"XADD EBX,EDX"))
				{dwEBX=dwEBX + dwEDX;dwEDX=dwTemp;}	
				else if(!strcmp(da.result,"XADD EBX,ESI"))
				{dwEBX=dwEBX + dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XADD EBX,EDI"))
				{dwEBX=dwEBX + dwEDI;dwEDI=dwTemp;}
				else if(!strcmp(da.result,"XADD EBX,EBP"))
				{dwEBX=dwEBX + dwEBP;dwEBP=dwTemp;}
			}
			else if(strstr(da.result,"XADD ECX,E"))
			{
				dwTemp=dwECX;
				if(!strcmp(da.result,"XADD ECX,ECX"))
					dwECX=dwTemp;
				else if(!strcmp(da.result,"XADD ECX,EAX"))
				{dwECX += dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XADD ECX,EBX"))
				{dwECX+=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XADD ECX,EDX"))
				{dwECX+=dwEDX;dwEDX=dwTemp;}	
				else if(!strcmp(da.result,"XADD ECX,ESI"))
				{dwECX+=dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XADD ECX,EDI"))
				{dwECX+=dwEDI;dwEDI=dwTemp;}
				else if(!strcmp(da.result,"XADD ECX,EBP"))
				{dwECX+=dwEBP;dwEBP=dwTemp;}
			}
			else if(strstr(da.result,"XADD EDX,E"))
			{
				dwTemp=dwEDX;
				if(!strcmp(da.result,"XADD EDX,EDX"))
					dwEDX=dwTemp;
				else if(!strcmp(da.result,"XADD EDX,EAX"))
				{dwEDX+=dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XADD EDX,EBX"))
				{dwEDX+=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XADD EDX,ECX"))
				{dwEDX+=dwECX;dwECX=dwTemp;}
				else if(!strcmp(da.result,"XADD EDX,ESI"))
				{dwEDX+=dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XADD EDX,EDI"))
				{dwEDX+=dwEDI;dwEDI=dwTemp;}
				else if(!strcmp(da.result,"XADD EDX,EBP"))
				{dwEDX+=dwEBP;dwEBP=dwTemp;}
			}
			else if(strstr(da.result,"XADD ESI,E"))
			{
				dwTemp=dwESI;
				if(!strcmp(da.result,"XADD ESI,ESI"))
					dwESI=dwTemp;
				else if(!strcmp(da.result,"XADD ESI,EAX"))
				{dwESI+=dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XADD ESI,EBX"))
				{dwESI+=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XADD ESI,ECX"))
				{dwESI+=dwECX;dwECX=dwTemp;}
				else if(!strcmp(da.result,"XADD ESI,EDX"))
				{dwESI+=dwEDX;dwEDX=dwTemp;}
				else if(!strcmp(da.result,"XADD ESI,EDI"))
				{dwESI+=dwEDI;dwEDI=dwTemp;}
				else if(!strcmp(da.result,"XADD ESI,EBP"))
				{dwESI+=dwEBP;dwEBP=dwTemp;}
			}
			else if(strstr(da.result,"XADD EDI,E"))
			{
				dwTemp=dwEDI;
				if(!strcmp(da.result,"XADD EDI,EDI"))
					dwEDI=dwTemp;
				else if(!strcmp(da.result,"XADD EDI,EAX"))
				{dwEDI+=dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XADD EDI,EBX"))
				{dwEDI+=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XADD EDI,ECX"))
				{dwEDI+=dwECX;dwECX=dwTemp;}
				else if(!strcmp(da.result,"XADD EDI,EDX"))
				{dwEDI+=dwEDX;dwEDX=dwTemp;}
				else if(!strcmp(da.result,"XADD EDI,ESI"))
				{dwEDI+=dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XADD EDI,EBP"))
				{dwEDI+=dwEBP;dwEBP=dwTemp;}
			}
			else if(strstr(da.result,"XADD EBP,E"))
			{
				dwTemp=dwEBP;
				if(!strcmp(da.result,"XADD EBP,EBP"))
					dwEBP=dwTemp;
				else if(!strcmp(da.result,"XADD EBP,EAX"))
				{dwEBP+=dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XADD EBP,EBX"))
				{dwEBP+=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XADD EBP,ECX"))
				{dwEBP+=dwECX;dwECX=dwTemp;}
				else if(!strcmp(da.result,"XADD EBP,EDX"))
				{dwEBP+=dwEDX;dwEDX=dwTemp;}
				else if(!strcmp(da.result,"XADD EBP,ESI"))
				{dwEBP+=dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XADD EBP,EDI"))
				{dwEBP+=dwEDI;dwEDI=dwTemp;}
			}						
		}
		///////////////////////////////////For XCHG ninstruction
		else if(strstr(da.result,"XCHG E"))
		{
			if(strstr(da.result,"XCHG EAX,E"))
			{
				DWORD dwTemp=dwEAX;
				if(!strcmp(da.result,"XCHG EAX,EBX"))
				{dwEAX=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EAX,ECX"))
				{dwEAX=dwECX;dwECX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EAX,EDX"))
				{dwEAX=dwEDX;dwEDX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EAX,ESI"))
				{dwEAX=dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XCHG EAX,EDI"))
				{dwEAX=dwEDI;dwEDI=dwTemp;}
				else if(!strcmp(da.result,"XCHG EAX,EBP"))
				{dwEAX=dwEBP;dwEBP=dwTemp;}
			}
			else if(strstr(da.result,"XCHG EBX,E"))
			{
				DWORD dwTemp=dwEBX;
				if(!strcmp(da.result,"XCHG EBX,EAX"))
				{dwEBX=dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EBX,ECX"))
				{dwEBX=dwECX;dwECX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EBX,EDX"))
				{dwEBX=dwEDX;dwEDX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EBX,ESI"))
				{dwEBX=dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XCHG EBX,EDI"))
				{dwEBX=dwEDI;dwEDI=dwTemp;}
				else if(!strcmp(da.result,"XCHG EBX,EBP"))
				{dwEBX=dwEBP;dwEBP=dwTemp;}
			}
			else if(strstr(da.result,"XCHG ECX,E"))
			{
				DWORD dwTemp=dwECX;
				if(!strcmp(da.result,"XCHG ECX,EAX"))
				{dwECX=dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XCHG ECX,EBX"))
				{dwECX=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XCHG ECX,EDX"))
				{dwECX=dwEDX;dwEDX=dwTemp;}
				else if(!strcmp(da.result,"XCHG ECX,ESI"))
				{dwECX=dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XCHG ECX,EDI"))
				{dwECX=dwEDI;dwEDI=dwTemp;}
				else if(!strcmp(da.result,"XCHG ECX,EBP"))
				{dwECX=dwEBP;dwEBP=dwTemp;}
			}
			else if(strstr(da.result,"XCHG EDX,E"))
			{
				DWORD dwTemp=dwEDX;
				if(!strcmp(da.result,"XCHG EDX,EAX"))
				{dwEDX=dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EDX,EBX"))
				{dwEDX=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EDX,ECX"))
				{dwEDX=dwECX;dwECX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EDX,ESI"))
				{dwEDX=dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XCHG EDX,EDI"))
				{dwEDX=dwEDI;dwEDI=dwTemp;}
				else if(!strcmp(da.result,"XCHG EDX,EBP"))
				{dwEDX=dwEBP;dwEBP=dwTemp;}
			}
			else if(strstr(da.result,"XCHG ESI,E"))
			{
				DWORD dwTemp=dwESI;
				if(!strcmp(da.result,"XCHG ESI,EAX"))
				{dwESI=dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XCHG ESI,EBX"))
				{dwESI=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XCHG ESI,ECX"))
				{dwESI=dwECX;dwECX=dwTemp;}	//Tushar ==> 15 Nov 2010
				else if(!strcmp(da.result,"XCHG ESI,EDX"))
				{dwESI=dwEDX;dwEDX=dwTemp;}
				else if(!strcmp(da.result,"XCHG ESI,EDI"))
				{dwESI=dwEDI;dwEDI=dwTemp;}
				else if(!strcmp(da.result,"XCHG ESI,EBP"))
				{dwESI=dwEBP;dwEBP=dwTemp;}
			}
			else if(strstr(da.result,"XCHG EDI,E"))
			{
				DWORD dwTemp=dwEDI;
				if(!strcmp(da.result,"XCHG EDI,EAX"))
				{dwEDI=dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EDI,EBX"))
				{dwEDI=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EDI,ECX"))
				{dwEDI=dwECX;dwECX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EDI,EDX"))
				{dwEDI=dwEDX;dwEDX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EDI,ESI"))
				{dwEDI=dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XCHG EDI,EBP"))
				{dwEDI=dwEBP;dwEBP=dwTemp;}
			}
			else //if(strstr(da.result,"XCHG EBP,E"))
			{
				DWORD dwTemp=dwEBP;
				if(!strcmp(da.result,"XCHG EBP,EAX"))
				{dwEBP=dwEAX;dwEAX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EBP,EBX"))
				{dwEBP=dwEBX;dwEBX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EBP,ECX"))
				{dwEBP=dwECX;dwECX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EBP,EDX"))
				{dwEBP=dwEDX;dwEDX=dwTemp;}
				else if(!strcmp(da.result,"XCHG EBP,ESI"))
				{dwEBP=dwESI;dwESI=dwTemp;}
				else if(!strcmp(da.result,"XCHG EBP,EDI"))
				{dwEBP=dwEDI;dwEDI=dwTemp;}
			}
		}

		////////////////LEA instruction
		else if(strstr(da.result,"LEA E"))
		{
			char *cptr1 = NULL;
			cptr1 = strrchr(da.result,',');
			if(cptr1 == NULL)//Tushar ==> 20 Nov 2010 : For Crash dump Analysis
				break;
			cptr1++;
			if(strstr(cptr1,"[EAX]")|| strstr(cptr1,"[EBX]")|| strstr(cptr1,"[ECX]")|| strstr(cptr1,"[EDX]")|| strstr(cptr1,"[EDI]")|| strstr(cptr1,"[ESI]")|| strstr(cptr1,"[EBP]"))
			{
				if(strstr(da.result,"LEA EAX,[E"))
				{
					if(!strcmp(da.result,"LEA EAX,[EBX]"))
						dwEAX=dwEBX;
					else if(!strcmp(da.result,"LEA EAX,[ECX]"))
						dwEAX=dwECX;
					else if(!strcmp(da.result,"LEA EAX,[EDX]"))
						dwEAX=dwEDX;
					else if(!strcmp(da.result,"LEA EAX,[ESI]"))
						dwEAX=dwESI;
					else if(!strcmp(da.result,"LEA EAX,[EDI]"))
						dwEAX=dwEDI;
					else //if(!strcmp(da.result,"LEA EAX,[EBP]"))
						dwEAX=dwEBP;
				}
				else if(strstr(da.result,"LEA EBX,[E"))
				{
					if(!strcmp(da.result,"LEA EBX,[EAX]"))
						dwEBX=dwEAX;
					else if(!strcmp(da.result,"LEA EBX,[ECX]"))
						dwEBX=dwECX;
					else if(!strcmp(da.result,"LEA EBX,[EDX]"))
						dwEBX=dwEDX;
					else if(!strcmp(da.result,"LEA EBX,[ESI]"))
						dwEBX=dwESI;
					else if(!strcmp(da.result,"LEA EBX,[EDI]"))
						dwEBX=dwEDI;
					else //if(!strcmp(da.result,"LEA EBX,[EBP]"))
						dwEBX=dwEBP;
				}
				else if(strstr(da.result,"LEA ECX,[E"))
				{
					if(!strcmp(da.result,"LEA ECX,[EAX]"))
						dwECX=dwEAX;
					else if(!strcmp(da.result,"LEA ECX,[EBX]"))
						dwECX=dwEBX;
					else if(!strcmp(da.result,"LEA ECX,[EDX]"))
						dwECX=dwEDX; //Tushar ==> Modified
					else if(!strcmp(da.result,"LEA ECX,[ESI]"))
						dwECX=dwESI;
					else if(!strcmp(da.result,"LEA ECX,[EDI]"))
						dwECX=dwEDI;
					else //if(!strcmp(da.result,"LEA ECX,[EBP]"))
						dwECX=dwEBP;
				}
				else if(strstr(da.result,"LEA EDX,[E"))
				{
					if(!strcmp(da.result,"LEA EDX,[EAX]"))
						dwEDX=dwEAX;
					else if(!strcmp(da.result,"LEA EDX,[EBX]"))
						dwEDX=dwEBX;
					else if(!strcmp(da.result,"LEA EDX,[ECX]"))
						dwEDX=dwECX;
					else if(!strcmp(da.result,"LEA EDX,[ESI]"))
						dwEDX=dwESI;
					else if(!strcmp(da.result,"LEA EDX,[EDI]"))
						dwEDX=dwEDI;
					else //if(!strcmp(da.result,"LEA EDX,[EBP]"))
						dwEDX=dwEBP;
				}
				else if(strstr(da.result,"LEA EDI,[E"))
				{
					if(!strcmp(da.result,"LEA EDI,[EAX]"))
						dwEDI=dwEAX;
					else if(!strcmp(da.result,"LEA EDI,[EBX]"))
						dwEDI=dwEBX;
					else if(!strcmp(da.result,"LEA EDI,[ECX]"))
						dwEDI=dwECX;
					else if(!strcmp(da.result,"LEA EDI,[EDX]"))
						dwEDI=dwEDX;
					else if(!strcmp(da.result,"LEA EDI,[ESI]"))
						dwEDI=dwESI;
					else //if(!strcmp(da.result,"LEA EDI,[EBP]"))
						dwEDI=dwEBP;
				}
				else if(strstr(da.result,"LEA ESI,[E"))
				{
					if(!strcmp(da.result,"LEA ESI,[EAX]"))
						dwESI=dwEAX;
					else if(!strcmp(da.result,"LEA ESI,[EBX]"))
						dwESI=dwEBX;
					else if(!strcmp(da.result,"LEA ESI,[ECX]"))
						dwESI=dwECX;
					else if(!strcmp(da.result,"LEA ESI,[EDX]"))
						dwESI=dwEDX;
					else if(!strcmp(da.result,"LEA ESI,[EDI]"))
						dwESI=dwEDI;
					else //if(!strcmp(da.result,"LEA ESI,[EBP]"))
						dwESI=dwEBP;
				}
				else if(strstr(da.result,"LEA EBP,[E"))
				{
					if(!strcmp(da.result,"LEA EBP,[EAX]"))
						dwEBP=dwEAX;
					else if(!strcmp(da.result,"LEA EBP,[EBX]"))
						dwEBP=dwEBX;
					else if(!strcmp(da.result,"LEA EBP,[ECX]"))
						dwEBP=dwECX;
					else if(!strcmp(da.result,"LEA EBP,[EDX]"))
						dwEBP=dwEDX;
					else if(!strcmp(da.result,"LEA EBP,[EDI]"))
						dwEBP=dwEDI;
					else //if(!strcmp(da.result,"LEA EBP,[ESI]"))
						dwEBP=dwESI;
				}
			}
			else
			{
				cptr1++;
				char *cptr2 = NULL;
				cptr2 = cptr1;
				int i = strlen(cptr2);
				if(i > 0)
				{
					cptr2[i-1] = '\0';
					sscanf_s(cptr2, "%X", &dwTemp);
				}
				if(strstr(da.result,"LEA EAX,["))
					dwEAX = dwTemp;
				else if(strstr(da.result,"LEA EBX,["))
					dwEBX = dwTemp;
				else if(strstr(da.result,"LEA ECX,["))
					dwECX = dwTemp;
				else if(strstr(da.result,"LEA EDX,["))
					dwEDX = dwTemp;
				else if(strstr(da.result,"LEA EDI,["))
					dwEDI = dwTemp;
				else if(strstr(da.result,"LEA ESI,["))
					dwESI = dwTemp;
				else //if(strstr(da.result,"LEA EBP,["))
					dwEBP = dwTemp;			
			}
		}
		////////////////////////////////IMUL r,r,imm instruction
		else if(strstr(da.result,"IMUL E"))
		{
			char *cptr1 = NULL;
			cptr1 = strrchr(da.result,',');
			if(cptr1 == NULL)//Tushar ==> 20 Nov 2010 : For Crash dump Analysis
				break;
			cptr1++;

			char *cptr2=NULL;
			cptr2 =strchr(da.result,',');
			if(cptr2 == NULL)//Tushar ==> 20 Nov 2010 : For Crash dump Analysis
				break;
			cptr2++;

			if(!(strcmp(cptr1,"EAX")|| strcmp(cptr1,"EBX")|| strcmp(cptr1,"ECX")|| strcmp(cptr1,"EDX")|| strcmp(cptr1,"EDI")|| strcmp(cptr1,"ESI")||strcmp(cptr1,"EBP")))
			{
				continue;
			}
			if(!strcmp(cptr2,"EAX")|| !strcmp(cptr2,"EBX")|| !strcmp(cptr2,"ECX")|| !strcmp(cptr2,"EDX")|| !strcmp(cptr2,"EDI")|| !strcmp(cptr2,"ESI")|| !strcmp(cptr2,"EBP"))
			{
				continue;
			}
			sscanf_s(cptr1, "%X", &dwTemp);

			if(strstr(da.result,"IMUL EAX,E"))
			{
				if(strstr(da.result,"IMUL EAX,EAX,"))
					dwEAX=dwEAX*dwTemp;
				else if(strstr(da.result,"IMUL EAX,EBX,"))
					dwEAX=dwEBX*dwTemp;
				else if(strstr(da.result,"IMUL EAX,ECX,"))
					dwEAX=dwECX*dwTemp;
				else if(strstr(da.result,"IMUL EAX,EDX,"))
					dwEAX=dwEDX*dwTemp;
				else if(strstr(da.result,"IMUL EAX,EDI,"))
					dwEAX=dwEDI*dwTemp;
				else if(strstr(da.result,"IMUL EAX,ESI,"))
					dwEAX=dwESI*dwTemp;
				else	//if(strstr(da.result,"IMUL EAX,EBP,"))
					dwEAX=dwEBP*dwTemp;
			}
			else if(strstr(da.result,"IMUL EBX,E"))
			{
				if(strstr(da.result,"IMUL EBX,EAX,"))
					dwEBX=dwEAX*dwTemp;
				else if(strstr(da.result,"IMUL EBX,EBX,"))
					dwEBX=dwEBX*dwTemp;
				else if(strstr(da.result,"IMUL EBX,ECX,"))
					dwEBX=dwECX*dwTemp;
				else if(strstr(da.result,"IMUL EBX,EDX,"))
					dwEBX=dwEDX*dwTemp;
				else if(strstr(da.result,"IMUL EBX,EDI,"))
					dwEBX=dwEDI*dwTemp;
				else if(strstr(da.result,"IMUL EBX,ESI,"))
					dwEBX=dwESI*dwTemp;
				else //if(strstr(da.result,"IMUL EBX,EBP,"))
					dwEBX=dwEBP*dwTemp;
			}
			else if(strstr(da.result,"IMUL ECX,E"))
			{
				if(strstr(da.result,"IMUL ECX,EAX,"))
					dwECX=dwEAX*dwTemp;
				else if(strstr(da.result,"IMUL ECX,EBX,"))
					dwECX=dwEBX*dwTemp;
				else if(strstr(da.result,"IMUL ECX,ECX,"))
					dwECX=dwECX*dwTemp;
				else if(strstr(da.result,"IMUL ECX,EDX,"))
					dwECX=dwEDX*dwTemp;
				else if(strstr(da.result,"IMUL ECX,EDI,"))
					dwECX=dwEDI*dwTemp;
				else if(strstr(da.result,"IMUL ECX,ESI,"))
					dwECX=dwESI*dwTemp;
				else	//if(strstr(da.result,"IMUL ECX,EBP,"))
					dwECX=dwEBP*dwTemp;
			}
			else if(strstr(da.result,"IMUL EDX,E"))
			{
				if(strstr(da.result,"IMUL EDX,EAX,"))
					dwEDX=dwEAX*dwTemp;
				else if(strstr(da.result,"IMUL EDX,EBX,"))
					dwEDX=dwEBX*dwTemp;
				else if(strstr(da.result,"IMUL EDX,ECX,"))
					dwEDX=dwECX*dwTemp;
				else if(strstr(da.result,"IMUL EDX,EDX,"))
					dwEDX=dwEDX*dwTemp;
				else if(strstr(da.result,"IMUL EDX,EDI,"))
					dwEDX=dwEDI*dwTemp;
				else if(strstr(da.result,"IMUL EDX,ESI,"))
					dwEDX=dwESI*dwTemp;
				else //if(strstr(da.result,"IMUL EDX,EBP,"))
					dwEDX=dwEBP*dwTemp;
			}
			else if(strstr(da.result,"IMUL EDI,E"))
			{
				if(strstr(da.result,"IMUL EDI,EAX,"))
					dwEDI=dwEAX*dwTemp;
				else if(strstr(da.result,"IMUL EDI,EBX,"))
					dwEDI=dwEBX*dwTemp;
				else if(strstr(da.result,"IMUL EDI,ECX,"))
					dwEDI=dwECX*dwTemp;
				else if(strstr(da.result,"IMUL EDI,EDX,"))
					dwEDI=dwEDX*dwTemp;
				else if(strstr(da.result,"IMUL EDI,EDI,"))
					dwEDI=dwEDI*dwTemp;
				else if(strstr(da.result,"IMUL EDI,ESI,"))
					dwEDI=dwESI*dwTemp;
				else //if(strstr(da.result,"IMUL EDI,EBP,"))
					dwEDI=dwEBP*dwTemp;
			}
			else if(strstr(da.result,"IMUL ESI,E"))
			{
				if(strstr(da.result,"IMUL ESI,EAX,"))
					dwESI=dwEAX*dwTemp;
				else if(strstr(da.result,"IMUL ESI,EBX,"))
					dwESI=dwEBX*dwTemp;
				else if(strstr(da.result,"IMUL ESI,ECX,"))
					dwESI=dwECX*dwTemp;
				else if(strstr(da.result,"IMUL ESI,EDX,"))
					dwESI=dwEDX*dwTemp;
				else if(strstr(da.result,"IMUL ESI,EDI,"))
					dwESI=dwEDI*dwTemp;
				else if(strstr(da.result,"IMUL ESI,ESI,"))
					dwESI=dwESI*dwTemp;
				else //if(strstr(da.result,"IMUL ESI,EBP,"))
					dwESI=dwEBP*dwTemp;
			}
			else if(strstr(da.result,"IMUL EBP,E"))
			{
				if(strstr(da.result,"IMUL EBP,EAX,"))
					dwEBP=dwEAX*dwTemp;
				else if(strstr(da.result,"IMUL EBP,EBX,"))
					dwEBP=dwEBX*dwTemp;
				else if(strstr(da.result,"IMUL EBP,ECX,"))
					dwEBP=dwECX*dwTemp;
				else if(strstr(da.result,"IMUL EBP,EDX,"))
					dwEBP=dwEDX*dwTemp;
				else if(strstr(da.result,"IMUL EBP,EDI,"))
					dwEBP=dwEDI*dwTemp;
				else if(strstr(da.result,"IMUL EBP,ESI,"))
					dwEBP=dwESI*dwTemp;
				else //if(strstr(da.result,"IMUL EBP,EBP,"))
					dwEBP=dwEBP*dwTemp;
			}
		}

		//Tushar ==> 29 Dec 2010 : Added to Handle 'MOVD MM0' instruction found in Sality.BH
		else if(strstr(da.result,"MOVD MM")&& iStep)
		{
			char *cptr1 = NULL;
			cptr1 = strchr(da.result,',');

			if(cptr1 == NULL)
				break;
			cptr1++;
			if(da.immconst == 0x00)
			{
				if(strstr(da.result,"EAX"))
				{
					dwConstValue = dwEAX;
					bMOVDInstructionFlag = true;
				}
				else if(strstr(da.result,"EBX"))
				{
					dwConstValue = dwEBX;
					bMOVDInstructionFlag = true;
				}
				else if(strstr(da.result,"ECX"))
				{
					dwConstValue = dwECX;
					bMOVDInstructionFlag = true;
				}
				else if(strstr(da.result,"EDX"))
				{
					dwConstValue = dwEDX;
					bMOVDInstructionFlag = true;
				}
				else if(strstr(da.result,"ESI"))
				{
					dwConstValue = dwESI;
					bMOVDInstructionFlag = true;
				}
				else if(strstr(da.result,"EDI"))
				{
					dwConstValue = dwEDI;
					bMOVDInstructionFlag = true;
				}
				else if(strstr(da.result,"EBP"))
				{
					dwConstValue = dwEBP;
					bMOVDInstructionFlag = true;
				}
			}
		}
		//Tushar ==> 29 Dec 2010 : Added to Handle 'MOVD' instruction found in Sality.BH
		else if(strstr(da.result,"MOVD E")&& strstr(da.result,"MM")&& iStep && bMOVDInstructionFlag)
		{
			char *cptr1 = NULL;
			cptr1 = strchr(da.result,'E');
			if(cptr1 == NULL)
				break;
			cptr1++;
			if(da.immconst == 0x00)
			{
				if(strstr(da.result,"EAX"))
				{
					dwEAX = dwConstValue;
					strcpy_s(szReg, MAX_REG_LEN, "EAX");
				}
				else if(strstr(da.result,"EBX"))
				{
					dwEBX = dwConstValue;
					strcpy_s(szReg, MAX_REG_LEN, "EBX");
				}
				else if(strstr(da.result,"ECX"))
				{
					dwECX = dwConstValue;
					strcpy_s(szReg, MAX_REG_LEN, "ECX");
				}
				else if(strstr(da.result,"EDX"))
				{
					dwEDX = dwConstValue;
					strcpy_s(szReg, MAX_REG_LEN, "EDX");
				}
				else if(strstr(da.result,"ESI"))
				{
					dwESI = dwConstValue;
					strcpy_s(szReg, MAX_REG_LEN, "ESI");
				}
				else if(strstr(da.result,"EDI"))
				{
					dwEDI = dwConstValue;
					strcpy_s(szReg, MAX_REG_LEN, "EDI");
				}
				else if(strstr(da.result,"EBP"))
				{
					dwEBP = dwConstValue;
					strcpy_s(szReg, MAX_REG_LEN, "EBP");
				}
				bMOVDInstructionFlag = false;
			}
		}
	}

	if(!strcmp(szReg ,"EAX"))
		return dwEAX;
	else if(!strcmp(szReg ,"EBX"))
		return dwEBX;
	else if(!strcmp(szReg ,"ECX"))
		return dwECX;
	else if(!strcmp(szReg ,"EDX"))
		return dwEDX;
	else if(!strcmp(szReg ,"ESI"))
		return dwESI;
	else if(!strcmp(szReg ,"EDI"))
		return dwEDI;
	else if(!strcmp(szReg ,"EBP"))
		return dwEBP;
	else //Tushar ==> 18 Nov 2010 : Added else case to Handle default value in worst case 
		return 0x00;

}

/*-------------------------------------------------------------------------------------
	Function		: GetFirstInst
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Get the first instruction at the begining of virus binary code
--------------------------------------------------------------------------------------*/
bool CPolySality::GetFirstInst()
{
	t_disasm da;

	memset(&da, 0x00, sizeof(da));
	m_objMaxDisassem.Disasm((char*)&m_pbyBuff[0], 0x20, 0x400000, &da, DISASM_CODE);

	int iLength = strlen(da.result)+ 0x01;
	if(iLength <= MAX_INST_SIZE)
	{
		strcpy_s(m_SalityParam.m_szFirstVirusInst, iLength, da.result);
		if(m_SalityParam.m_szFirstVirusInst[0] != 0x00)
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSalityOG
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Detection routine for varient : Sality.OG
--------------------------------------------------------------------------------------*/
int CPolySality::DetectSalityOG()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	bool bFlag = false;
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics&IMAGE_FILE_DLL)==IMAGE_FILE_DLL))
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);

	if(m_pSectionHeader[m_wNoOfSections-1].NumberOfLinenumbers != 0x14 && 
		m_SalityParam.m_bIsPUSHADAEP)
	{
		return iRetStatus;
	}

	m_SalityParam.m_SalityOGParam.dwCounter	= 0x00;
	m_SalityParam.m_SalityOGParam.dwKey		= 0x00;
	m_SalityParam.m_SalityOGParam.dwType	= 0x00;

	const int BUFFER_SIZE = 0x1000;
	char szTemp[MAX_INST_SIZE] = {0};

	sprintf_s(szTemp,MAX_INST_SIZE, "SUB %s,", m_SalityParam.m_szReqReg);
	if(szTemp[0] == 0x00)
	{
		return iRetStatus;
	}

	char *ptr = strstr(m_SalityParam.m_szFirstVirusInst, szTemp);
	if(ptr == NULL)
	{
		return iRetStatus;
	}

	ptr = strstr(m_SalityParam.m_szFirstVirusInst, ",");
	if(ptr == NULL)
	{
		return iRetStatus;
	}
	ptr++;

	DWORD dwTemp = 0x00;
	sscanf_s(ptr, "%X", &dwTemp);

	if(((m_SalityParam.m_dwLastSecJumpOffset - dwTemp)% m_pMaxPEFile->m_stPEHeader.FileAlignment != 0x00))
	{
		return iRetStatus;
	}

	m_SalityParam.m_dwVirusRVA		= m_SalityParam.m_dwLastSecJumpRVA - dwTemp;
	m_SalityParam.m_dwVirusOffSet	= m_SalityParam.m_dwLastSecJumpOffset - dwTemp;
	m_SalityParam.m_dwVirusBodySize =(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)
										- m_SalityParam.m_dwVirusOffSet;

	if(m_SalityParam.m_dwVirusBodySize < 0x10000)
	{
		return iRetStatus;
	}

	if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, 0x500, 0x500))
		return iRetStatus;

	if(!GetSalityOGPrimarDecParam())
		return iRetStatus;

	if(m_SalityParam.m_SalityOGParam.dwCounter > BUFFER_SIZE)
		return iRetStatus;

	memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
	if(!GetBuffer(m_SalityParam.m_dwVirusOffSet, BUFFER_SIZE))
		return iRetStatus;

	if(m_dwNoOfBytes != BUFFER_SIZE)
		return iRetStatus;

	DWORD j = 0x00;
	switch(m_SalityParam.m_SalityOGParam.dwType)
	{
	case DEC_TYPE_ADD:
		for(j = 0x00; j < m_SalityParam.m_SalityOGParam.dwCounter; j += 0x04)
		{
			*((DWORD *)&m_pbyBuff[j])+= m_SalityParam.m_SalityOGParam.dwKey;
		}
		break;

	case DEC_TYPE_SUB:
		for(j = 0x00; j < m_SalityParam.m_SalityOGParam.dwCounter; j += 0x04)
		{
			*((DWORD *)&m_pbyBuff[j])-= m_SalityParam.m_SalityOGParam.dwKey;
		}
		break;

	case DEC_TYPE_XOR:
		for(j = 0x00; j < m_SalityParam.m_SalityOGParam.dwCounter; j += 0x04)
		{
			*((DWORD *)&m_pbyBuff[j])^= m_SalityParam.m_SalityOGParam.dwKey;
		}
		break;
	default:
		return iRetStatus;
	}
	if(GetSalityDecryptKeyModeEx())
	{
		bFlag = true;
	}

	if(bFlag)
	{
		if(CheckSalityOGSig()) //added by ....  __mangesh
		{
			m_dwSalityType	=  VIRUS_SALITY_OG;
			iRetStatus		= VIRUS_FILE_REPAIR;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.OG"));
		}
	}
	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSalityOGSig
	In Parameters	: 
	Out Parameters	: TRUE is match else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Confirmation for : Sality.OG
--------------------------------------------------------------------------------------*/
BOOL CPolySality::CheckSalityOGSig()
{
	int iRetStatus = false;
	
	BYTE	szKey1[0x16] = {0}, szKey2[0x100] = {0}, bVirusFound = 0;
	DWORD	dwTempOffset = m_SalityParam.m_dwVirusOffSet + 0x1000;
	DWORD	dwTemp = 0, dwOffset = 0;
	DWORD	dwTempTempOffset = 0x00;

	for(int iCnt = 0; iCnt < 0x02; iCnt++)
	{
		if(!m_pMaxPEFile->ReadBuffer(szKey1, dwTempOffset, 0x16, 0x16))
			return iRetStatus;
				
		if(m_SalityParam.m_SalityAAParam.dwType)
		{
			for(int iOffset = 0; iOffset < iCnt + 1; iOffset++)
			{
				switch(m_SalityParam.m_SalityAAParam.dwType)
				{
				case DEC_TYPE_ADD:
					*((DWORD *)&szKey1[iOffset * 4])+= m_SalityParam.m_SalityAAParam.dwKey;
					break;

				case DEC_TYPE_SUB:
					*((DWORD *)&szKey1[iOffset * 4])-= m_SalityParam.m_SalityAAParam.dwKey;
					break;

				case DEC_TYPE_XOR:
					*((DWORD *)&szKey1[iOffset * 4])^= m_SalityParam.m_SalityAAParam.dwKey;
					break;
				}
			}
		}

		DWORD	EDX = 0x00;
		BYTE	AL = 0x00, AH = 0x00, DL = 0x00, DH = 0x00;

		for(dwOffset = 0x03; dwOffset < 0x16; dwOffset++)
		{
			for(dwTemp = 0; dwTemp < 0x100; dwTemp++)
				szKey2[dwTemp] =(unsigned char)dwTemp;

			DL = DH = 0;

			for(dwTemp = 0; dwTemp < 0x100; dwTemp++)
			{
				if(DH > dwOffset)
					DH = 0x00;

				DL += szKey1[DH];
				AL = szKey2[dwTemp];
				DL += AL;
				EDX = DL;
				AH = szKey2[EDX];
				szKey2[EDX] = AL;
				szKey2[dwTemp] = AH;

				DH++;
			}

			memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE * sizeof(BYTE));
			if(!GetBuffer(dwTempOffset + 0x116, 0x3000, 0x3000))
				return iRetStatus;

			BYTE BL = 0 , CH  = 0;
			EDX = 0x01;

			for(dwTemp = 0; dwTemp < m_dwNoOfBytes; dwTemp++)
			{
				if(EDX > 0xFF)
					EDX = 0x00;

				BL += szKey2[EDX];
				AL = szKey2[EDX];
				CH = szKey2[BL];
				szKey2[BL] = AL;
				szKey2[EDX] = CH;
				AL += CH;
				AL = szKey2[AL];
				m_pbyBuff[dwTemp] ^= AL;

				EDX++;
			}

			BYTE bySignature[] = { 0x4F, 0x70, 0x31, 0x6D, 0x75, 0x74, 0x78, 0x39, 0x00, 
								   0x41, 0x70, 0x31, 0x6D, 0x75, 0x74, 0x78, 0x37, 0x00 };
			BYTE  bySignature2[] = {0x75, 0x78, 0x4A, 0x4C, 0x70, 0x65, 0x31, 0x6D, 0x00, 0x41, 0x70, 0x31, 0x6D, 0x75};

			for(EDX = 0x00; EDX <= 0x15; EDX++)
			{
				if((memcmp(bySignature, &m_pbyBuff[0x65D + EDX], sizeof(bySignature))== 0) || (memcmp(bySignature2, &m_pbyBuff[0x65D + EDX], sizeof(bySignature2))== 0))
				{
					bVirusFound = 0x01;
					break;
				}
			}
			if(bVirusFound)
				break;
			else
			{
				dwTempTempOffset = CheckForValidDecryption();
				if(dwTempTempOffset != 0x00)
				{
					bVirusFound = 0x02;
					break;
				}
			}
		}
		if(bVirusFound)
			break;
	}
	if(!bVirusFound)
	{
		return iRetStatus;
	}
	if(bVirusFound == 0x02)
	{
		dwTempOffset = dwTempTempOffset;
		dwTemp = *((DWORD*)&m_pbyBuff[dwTempOffset+ 0x06 +0x2C]);

		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwTempOffset + 0x06 + 0x2C + 0x04], m_dwAEPMapped, dwTemp, dwTemp))
		{
			iRetStatus = RemoveSalityVirusCode();
		}
		return iRetStatus;
	}	
	if(bVirusFound != 0x02)
	{
		BYTE	bTempSign[] = {0x00, 0x00, 0x28, 0x00, 0x00, 0x00};
		bVirusFound = 0x00;
		dwTemp = 0x1600;
		DWORD dwCounter = 0x00, dwAEPBytesCount[10] = {0x00};
		for(dwOffset = 0x1250; dwOffset < dwTemp; dwOffset++)
		{
			if(memcmp(&m_pbyBuff[dwOffset], bTempSign, 0x06)== 0)
			{			
				dwAEPBytesCount[dwCounter++] = dwOffset;
				dwTemp = dwOffset + 0x100 + 0x06;
				dwOffset += 0x06;
				bVirusFound += 0x01;
			}
		}
		if(dwOffset >= dwTemp && bVirusFound == 0x00)
		{
			return iRetStatus;
		}
		

		for(dwOffset = dwCounter - 1; dwOffset >= 0x00; dwOffset--)
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwAEPBytesCount[dwOffset]+ 0x06 +0x2C]);
			if(dwTemp <= 0x300 && dwTemp != 0x00)
			{
				break;
			}
		}
		if(dwTemp > 0x300)
		{
			return iRetStatus;
		}
		else
		{
			m_SalityParam.m_SalityOGParam.dwOrgBytesOffset = dwAEPBytesCount[dwOffset];
			m_SalityParam.m_SalityOGParam.dwReplaceBytes = dwTemp; 
			return true;
		}

	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSalityOGPrimarDecParam
	In Parameters	: 
	Out Parameters	: true is match else false
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Determines first key for detection
--------------------------------------------------------------------------------------*/
bool CPolySality::GetSalityOGPrimarDecParam()
{
	DWORD		dwLength = 0x00, dwOffset = 0x00, dwTemp = 0x00;
	DWORD		dwPush = 0x00, dwPop = 0x00;
	t_disasm	da;
	BYTE		B1 = 0x00, B2 = 0x00;
	char		chJump = 0x00, szRegister[5]={0}, szAdd[10]={0}, szSub[10]={0}, szXor[10]={0};
	char		*ptr = NULL;

	m_objMaxDisassem.InitializeData();

	while(dwOffset < m_dwNoOfBytes - 2)
	{
		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = *((BYTE*)&m_pbyBuff[dwOffset]);
		B2 = *((BYTE*)&m_pbyBuff[dwOffset+1]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);

		if(dwLength==0x02 && strstr(da.result, "JMP SHORT"))
		{
			dwOffset += dwLength + B2;
			continue;
		}
		if(dwLength==0x05 && B1==0xE9 && strstr(da.result, "JMP "))
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffset+1]);
			dwOffset += dwLength + dwTemp;

			if(dwOffset >= m_dwNoOfBytes)
				break;

			continue;
		}

		if(dwLength==0x02 && strstr(da.result, "MOV E")&&(strstr(da.result, ",[EAX]")||strstr(da.result, ",[EBX]")||strstr(da.result, ",[ECX]")||strstr(da.result, ",[EDX]")))
		{
			ptr = strstr(da.result, "MOV E");
			if(ptr)
			{
				ptr += strlen("MOV E")- 1;

				szRegister[0] = ptr[0];
				szRegister[1] = ptr[1];
				szRegister[2] = ptr[2];
				szRegister[3] = '\0';

				sprintf_s(szAdd, 0x0A, "ADD %s,", szRegister);
				sprintf_s(szSub, 0x0A, "SUB %s,", szRegister);
				sprintf_s(szXor, 0x0A, "XOR %s,", szRegister);
				chJump = 0x01;
			}

			dwOffset += dwLength;
			continue;
		}
		if(dwLength==0x02 && chJump==0x00 && strstr(da.result, "PUSH DWORD PTR [E"))
		{
			chJump = 0x01;
			dwPush += 0x01;
			dwOffset += dwLength;
			continue;
		}
		if(chJump==0x01 && strstr(da.result, "PUSH "))
		{
			dwPush += 0x01;
			dwOffset += dwLength;
			continue;
		}
		if(chJump==0x01 && strstr(da.result, "POP "))
			dwPop += 0x01;

		if(chJump==0x01 && dwPush==dwPop && strstr(da.result, "POP "))
		{
			szRegister[0] = da.result[4];
			szRegister[1] = da.result[5];
			szRegister[2] = da.result[6];
			szRegister[3] = '\0';

			sprintf_s(szAdd, 0x0A, "ADD %s,", szRegister);
			sprintf_s(szSub, 0x0A, "SUB %s,", szRegister);
			sprintf_s(szXor, 0x0A, "XOR %s,", szRegister);
			dwOffset += dwLength;
			continue;
		}

		if(dwLength==0x02 && chJump==0x02)
		{
			if(strstr(da.result, "POP DWORD PTR [E")||(strstr(da.result, "MOV [E")&& strstr(da.result, szRegister)))
			{
				chJump = 0x03;
				dwOffset += dwLength;
				continue;
			}
		}
		if(dwLength==0x02 && chJump==0x03 && B1==0x75 && strstr(da.result, "JNZ SHORT "))
		{
			chJump = 0x04;
			dwOffset += dwLength;
			continue;
		}
		if(dwLength==0x06 && chJump==0x03 && B1==0x0F && B2==0x85 && strstr(da.result, "JNZ "))
		{
			chJump = 0x04;
			dwOffset += dwLength;
			continue;
		}
		if(dwLength==0x06 && chJump==0x01 && strlen(szAdd)&& strlen(szSub)&& strlen(szXor))
		{
			if(strstr(da.result, szAdd))
			{
				ptr = strchr(da.result, ',');
				if(ptr)
				{
					ptr++;
					sscanf_s(ptr, "%X", &dwTemp);
					m_SalityParam.m_SalityOGParam.dwKey = dwTemp;
					m_SalityParam.m_SalityOGParam.dwType = DEC_TYPE_ADD;
					chJump=0x02;
				}
			}
			if(strstr(da.result, szSub))
			{
				ptr = strchr(da.result, ',');
				if(ptr)
				{
					ptr++;
					sscanf_s(ptr, "%X", &dwTemp);
					m_SalityParam.m_SalityOGParam.dwKey = dwTemp;
					m_SalityParam.m_SalityOGParam.dwType = DEC_TYPE_SUB;
					chJump=0x02;
				}
			}
			if(strstr(da.result, szXor))
			{
				ptr = strchr(da.result, ',');
				if(ptr)
				{
					ptr++;
					sscanf_s(ptr, "%X", &dwTemp);
					m_SalityParam.m_SalityOGParam.dwKey = dwTemp;
					m_SalityParam.m_SalityOGParam.dwType = DEC_TYPE_XOR;
					chJump=0x02;
				}
			}

			dwOffset += dwLength;
			continue;
		}

		if(dwLength==0x06 && chJump==0x04 && strstr(da.result, "SUB E"))
		{
			ptr = strchr(da.result, ',');
			if(ptr)
			{
				ptr++;
				sscanf_s(ptr, "%X", &dwTemp);
				m_SalityParam.m_SalityOGParam.dwCounter = dwTemp;
				break;
			}
		}

		dwOffset += dwLength;
	}

	if(chJump < 0x04)
		return false;

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSalityDecryptKeyModeEx
	In Parameters	: 
	Out Parameters	: true is match else false
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Determines key pattern
--------------------------------------------------------------------------------------*/
bool CPolySality::GetSalityDecryptKeyModeEx()
{
	char	*ptr = NULL;
	char	szAdd[10] = {0} , szSub[10] = {0} , szXor[10] = {0};
	DWORD	i, dwTemp;

	m_SalityParam.m_SalityAAParam.dwKey = 0x00;
	m_SalityParam.m_SalityAAParam.dwType = 0x00;

	m_objMaxDisassem.InitializeData();

	//Checkin CMP ECX,0 Instruction
	for(i=0; i<(m_dwNoOfBytes-3); i++)
	{
		if(m_pbyBuff[i]==0x83 && m_pbyBuff[i+1]==0xF9 && m_pbyBuff[i+2]==0x00)
		{

			if(i>=(m_dwNoOfBytes-3))
				return false;

			bool bRetStatus = GetDecryptKeyModeInstruction(i + 3);
			if((m_SalityParam.m_SalityAAParam.dwType)&&(m_SalityParam.m_SalityAAParam.dwKey))
				return true;

			if(bRetStatus == true)
			{
				break;
			}
		}
	}
	if(!m_dwInstCount || m_dwInstCount > MAX_INSTRUCTIONS)
		return false;	

	char *pRegister = strrchr(m_objInstructionSet[m_dwInstCount-1].szPnuemonics, ',');
	if(!pRegister)
		return false;

	pRegister++;
	if(strlen(pRegister)!= 0x03)
		return false;

	i=0;
	if(!GetInitialRegisterValue(pRegister, &i, &m_SalityParam.m_SalityAAParam.dwKey))
		return false;

	strcpy_s(szAdd, 10, "");
	strcpy_s(szSub, 10, "");
	strcpy_s(szXor, 10, "");
	sprintf_s(szAdd, 10, "ADD %s,", pRegister);
	sprintf_s(szSub, 10, "SUB %s,", pRegister);
	sprintf_s(szXor, 10, "XOR %s,", pRegister);

	for(; i< m_dwInstCount; i++)
	{
		ptr = NULL;
		if(m_objInstructionSet[i].dwInstLen==0x06)
		{
			ptr = strrchr(m_objInstructionSet[i].szPnuemonics, ',');
			if(strstr(m_objInstructionSet[i].szPnuemonics, szAdd)&& ptr)
			{
				ptr++;
				sscanf_s(ptr, "%X", &dwTemp);
				m_SalityParam.m_SalityAAParam.dwKey += dwTemp;
				continue;
			}
			if(strstr(m_objInstructionSet[i].szPnuemonics, szSub)&& ptr)
			{
				ptr++;
				sscanf_s(ptr, "%X", &dwTemp);
				m_SalityParam.m_SalityAAParam.dwKey -= dwTemp;
				continue;
			}
			if(strstr(m_objInstructionSet[i].szPnuemonics, szXor)&& ptr)
			{
				ptr++;
				sscanf_s(ptr, "%X", &dwTemp);
				m_SalityParam.m_SalityAAParam.dwKey ^= dwTemp;
			}
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDecryptKeyModeInstruction
	In Parameters	: 
	Out Parameters	: true is match else false
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Determines decryption instruction
--------------------------------------------------------------------------------------*/
bool CPolySality::GetDecryptKeyModeInstruction(DWORD dwStart)
{
	DWORD		dwOffset = 0, dwLength, dwTemp = 0;
	t_disasm	da;
	BYTE		B1, B2;
	char		chJump  = 0;
	DWORD	dwInstCount = 0;
	dwOffset = dwStart;

	while(dwOffset < m_dwNoOfBytes - 2)
	{
		if(m_dwInstCount > 0x100 || dwInstCount > 0x500)
			break;

		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = *((BYTE*)&m_pbyBuff[dwOffset]);
		B2 = *((BYTE*)&m_pbyBuff[dwOffset+1]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
		dwInstCount++;
		if(dwLength==0x02 && B1==0x7C && strstr(da.result, "JL SHORT"))
		{
			dwOffset += dwLength + B2;
			chJump = 0x01;
			continue;
		}
		if(dwLength==0x06 && B1==0x0F && B2==0x8C && strstr(da.result, "JL "))
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffset+2]);
			if((dwTemp+dwOffset+dwLength)> m_dwNoOfBytes)
				break;

			dwOffset += dwLength + dwTemp;
			chJump = 0x01;
			continue;
		}
		if(dwLength==0x06 && B1==0x0F && B2==0x8D && strstr(da.result, "JGE "))
		{
			dwOffset += dwLength;
			chJump = 0x01;
			continue;
		}

		if(chJump)
		{
			m_objInstructionSet[m_dwInstCount].dwInstLen = dwLength;
			strcpy_s(m_objInstructionSet[m_dwInstCount].szOpcode, TEXTLEN, da.dump);
			strcpy_s(m_objInstructionSet[m_dwInstCount++].szPnuemonics, TEXTLEN, da.result);
		}

		if(dwLength==0x02 &&(strstr(da.result, "JMP SHORT")|| strstr(da.result, "JB SHORT")))
		{
			dwTemp = MakeDword(da.dump, ' ');
			dwOffset += dwLength + dwTemp;
			continue;
		}
		if(dwLength==0x05 && B1==0xE9 && strstr(da.result, "JMP "))
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffset+1]);
			dwOffset += dwLength + dwTemp;

			if(dwOffset >= m_dwNoOfBytes)
				break;

			continue;
		}

		if(dwLength==0x06 && B1==0x81 && B2==0x06 && strstr(da.result, "ADD DWORD PTR [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_ADD;
			m_SalityParam.m_SalityAAParam.dwKey = dwTemp = *((DWORD*)&m_pbyBuff[dwOffset+2]);
			chJump = 0x02;
			break;
		}
		if(dwLength==0x06 && strstr(da.result, "SUB DWORD PTR [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_SUB;
			m_SalityParam.m_SalityAAParam.dwKey  = dwTemp = *((DWORD*)&m_pbyBuff[dwOffset+2]);
			chJump = 0x02;
			break;
		}
		if(dwLength==0x06 && strstr(da.result, "XOR DWORD PTR [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_XOR;
			m_SalityParam.m_SalityAAParam.dwKey  = dwTemp = *((DWORD *)&m_pbyBuff[dwOffset+2]);
			chJump = 0x02;
			break;
		}

		//ECX
		if(dwLength==0x02 && B1==0x01 && B2==0x0E && strstr(da.result, "ADD [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_ADD;
			chJump = 0x02;
			break;
		}
		if(dwLength==0x02 && B1==0x29 && B2==0x0E && strstr(da.result, "SUB [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_SUB;
			chJump = 0x02;
			break;
		}
		if(dwLength==0x02 && B1==0x31 && B2==0x0E && strstr(da.result, "XOR [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_XOR;
			chJump = 0x02;
			break;
		}

		//EDX
		if(dwLength==0x02 && B1==0x01 && B2==0x16 && strstr(da.result, "ADD [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_ADD;
			chJump = 0x02;
			break;
		}
		if(dwLength==0x02 && B1==0x29 && B2==0x16 && strstr(da.result, "SUB [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_SUB;
			chJump = 0x02;
			break;
		}
		if(dwLength==0x02 && B1==0x31 && B2==0x16 && strstr(da.result, "XOR [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_XOR;
			chJump = 0x02;
			break;
		}

		//EBX
		if(dwLength==0x02 && B1==0x01 && B2==0x1E && strstr(da.result, "ADD [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_ADD;
			chJump = 0x02;
			break;
		}
		if(dwLength==0x02 && B1==0x29 && B2==0x1E && strstr(da.result, "SUB [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_SUB;
			chJump = 0x02;
			break;
		}
		if(dwLength==0x02 && B1==0x31 && B2==0x1E && strstr(da.result, "XOR [ESI],"))
		{
			m_SalityParam.m_SalityAAParam.dwType = DEC_TYPE_XOR;
			chJump = 0x02;
			break;
		}
		dwOffset += dwLength;
	}

	if(chJump < 0x02)
		return false;

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetInitialRegisterValue
	In Parameters	: 
	Out Parameters	: true is match else false
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Gets basic information to start decryption
--------------------------------------------------------------------------------------*/
bool CPolySality::GetInitialRegisterValue(char *pszReg, DWORD *piStart, DWORD *pKey)
{
	DWORD	i = 0x00, dwTemp = 0x00;
	int		dwStackTop = 0x00, iPopTop = 0x00, iPushTop = 0x00;
	char	bPopInst = 0x00, *ptr = NULL;
	char	*pPushStack[0x100] = { 0 };
	char	*pPopStack[0x100] = { 0 };
	char	szMov[11]={0}, szXor[13]={0}, szAnd[11]={0}, szSub[13]={0}, szPop[8]={0};

	sprintf_s(szMov, 11, "MOV %s,", pszReg);
	sprintf_s(szXor, 13, "XOR %s,%s", pszReg, pszReg);
	sprintf_s(szAnd, 11, "AND %s,0", pszReg);
	sprintf_s(szSub, 13, "SUB %s,%s", pszReg, pszReg);
	sprintf_s(szPop, 8, "POP %s", pszReg);

	bPopInst = 0x00;
	dwTemp = 0x00;
	iPopTop = iPushTop = dwStackTop = 0;

	i = m_dwInstCount -1;
	for(; i > 0x00; i--)
	{
		ptr = NULL;
		if(strstr(m_objInstructionSet[i].szPnuemonics, "POP "))
		{
			if(iPopTop>=0x00 && iPopTop<0x100)
				pPopStack[iPopTop++] = m_objInstructionSet[i].szPnuemonics;
			//continue;
		}

		if(strstr(m_objInstructionSet[i].szPnuemonics, "PUSH "))
		{
			if(iPopTop>0x00 && iPopTop<0x100)
			{
				if(bPopInst && strstr(pPopStack[iPopTop-1], szPop))
				{
					ptr = strrchr(m_objInstructionSet[i].szPnuemonics, ' ');
					if(ptr && strstr(m_objInstructionSet[i].szPnuemonics, "PUSH EAX")==NULL&&strstr(m_objInstructionSet[i].szPnuemonics, "PUSH EBX")==NULL&&strstr(m_objInstructionSet[i].szPnuemonics, "PUSH ECX")==NULL&&strstr(m_objInstructionSet[i].szPnuemonics, "PUSH EDX")==NULL&& strstr(m_objInstructionSet[i].szPnuemonics, " [")==NULL)
					{
						ptr++;
						sscanf_s(ptr, "%X", &dwTemp);
						*pKey = dwTemp;
						*piStart = i + 1;
						break;
					}
					else
						pPushStack[iPushTop++] = m_objInstructionSet[i].szPnuemonics;
				}
				else
					pPushStack[iPushTop++] = m_objInstructionSet[i].szPnuemonics;
			}
			//continue;
		}
		if(strstr(m_objInstructionSet[i].szPnuemonics, szPop))
		{
			bPopInst = 0x01;
			continue;
		}

		if(strstr(m_objInstructionSet[i].szPnuemonics, "PUSH "))
		{
			if(iPushTop>0x00 && iPopTop>0x00 && iPushTop<0x100)
			{
				pPushStack[--iPushTop] = NULL;
				pPopStack[--iPopTop] = NULL;
			}

			continue;
		}
		if(strstr(m_objInstructionSet[i].szPnuemonics, szXor)|| strstr(m_objInstructionSet[i].szPnuemonics, szAnd)|| strstr(m_objInstructionSet[i].szPnuemonics, szSub))//strstr(m_objInstructionSet[i].szPnuemonics, szMov)||
		{
			*pKey = 0x00;
			*piStart = i + 1;
			break;
		}
		if(strstr(m_objInstructionSet[i].szPnuemonics, szMov)&& m_objInstructionSet[i].dwInstLen==0x05)
		{
			ptr = strrchr(m_objInstructionSet[i].szPnuemonics, ',');
			if(ptr)
			{
				ptr++;
				sscanf_s(ptr, "%X", &dwTemp);
				*pKey = dwTemp;
				*piStart = i + 1;
				break;
			}
		}
	}

	if(i >= m_dwInstCount)
		return false; 

	return true;	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for Sality.BH
--------------------------------------------------------------------------------------*/
int CPolySality::DetectSalityBH()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	DWORD dwTemp = m_SalityParam.m_dwLastSecJumpRVA % 0x100;//m_pMaxPEFile->m_stPEHeader.FileAlignment;       added by __mangesh.

	m_SalityParam.m_dwVirusOffSet	= m_SalityParam.m_dwLastSecJumpOffset - dwTemp;
	m_SalityParam.m_dwVirusRVA		= m_SalityParam.m_dwLastSecJumpRVA - dwTemp;
	m_SalityParam.m_dwVirusBodySize	= (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData) - m_SalityParam.m_dwVirusOffSet;

	if(m_SalityParam.m_dwVirusBodySize < 0x10000)
		return iRetStatus;

	m_SalityParam.m_SalityBHParam.dw16ByteKeyOffset	= 0x00;
	m_SalityParam.m_SalityBHParam.dwKey				= 0x00;

	memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
	if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, 0x1000, 0x1000))
		return iRetStatus;

	if(!GetSalityBHKeyEx())
		return iRetStatus;

	const DWORD BUFFER_SIZE = 0x300;
	BYTE szATKey[BUFFER_SIZE] = {0};

	m_dwNoOfBytes = 0;
	if(!m_pMaxPEFile->ReadBuffer(szATKey, m_SalityParam.m_dwLastSecJumpOffset, BUFFER_SIZE, BUFFER_SIZE, &m_dwNoOfBytes))
		return iRetStatus;
	
	DWORD dwKeyLen = m_dwNoOfBytes - 0x20;
	DWORD dwTempKeyLen = dwKeyLen;
	if(!GetBuffer(m_SalityParam.m_dwVirusOffSet + 0x1116, 0x08, 0x08))
		return iRetStatus;

	BYTE szBuffer1[0x08] = {0x00};
	memcpy(szBuffer1, m_pbyBuff, 0x08);

	DWORD	dwTemp1 = 0;
	DWORD	dwKeyLoc = 0x1C;
	DWORD	dwATKey = 0x3F;

	for(DWORD i = 0x00; i < m_dwNoOfBytes; i += 0x08)
	{
		dwATKey = 0x3F;
		dwKeyLoc = 0x1C;

		while(true)
		{
			if(dwATKey%0x02)
				dwTemp = *((DWORD*)&m_pbyBuff[i+0x04]);
			else
				dwTemp = *((DWORD*)&m_pbyBuff[i]);

			dwTemp1 = dwTemp*64;

			dwTemp1 = dwTemp1 ^(dwTemp >> 0x08);
			dwTemp1 = dwTemp + dwTemp1 + i + m_SalityParam.m_SalityBHParam.dwKey;

			dwTemp1 = dwTemp1 + *((DWORD*)&szATKey[dwKeyLen + dwKeyLoc])+ dwATKey;

			if(dwATKey%0x02)
				*((DWORD*)&m_pbyBuff[i])= *((DWORD*)&m_pbyBuff[i])- dwTemp1;
			else
				*((DWORD*)&m_pbyBuff[i+0x04])= *((DWORD*)&m_pbyBuff[i+0x04])- dwTemp1;

			if(dwKeyLoc == 0x00)
				dwKeyLoc = 0x1C;
			else
				dwKeyLoc -= 0x04;

			if(dwATKey == 0x00)
				break;

			dwATKey -= 0x01;
		}

		if(i == 0x00)
		{
			//Tushar --> Added second condition. This will improve detection of Sality.BH. Already added in Sality.V
			if(((*((DWORD*)&m_pbyBuff[0x00]))== 0xE8 &&(*((DWORD*)&m_pbyBuff[0x04]))== 0xC58B5D00)||
				((*((DWORD*)&m_pbyBuff[0x00]))== 0 &&(*((DWORD*)&m_pbyBuff[0x04])== 0)))
			{
				m_SalityParam.m_SalityBHParam.dw16ByteKeyOffset = m_SalityParam.m_dwLastSecJumpOffset + dwKeyLen;
				
				m_dwSalityType =  VIRUS_SALITY_BH;
				iRetStatus = VIRUS_FILE_REPAIR;	
				if(CheckForZeros(m_SalityParam.m_dwVirusOffSet + 0x1116 + 0x600, 0x50))
				{
					iRetStatus = VIRUS_FILE_DELETE;				
				}
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.BH"));		
				return iRetStatus;
			}
			else
			{				
				if(dwKeyLen == 0x00)
				{
					if(m_SalityParam.m_SalityBHParam.dwKey == 0x00)
						return iRetStatus;
					dwKeyLen = dwTempKeyLen;
					m_SalityParam.m_SalityBHParam.dwKey = 0x00;
				}
				memcpy(m_pbyBuff, szBuffer1, 0x08);
				i -= 0x08;
				dwKeyLen -= 0x01;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSalityBHKeyEx
	In Parameters	: 
	Out Parameters	: true is match else false
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Yash Gund + Virus Analysis Team
	Description		: Gets key for Sality.BH varient
--------------------------------------------------------------------------------------*/
bool CPolySality::GetSalityBHKeyEx()
{	
	DWORD	dwStartAddress = 0 , dwEndAddress =0, dwLength = 0 , dwRecur = 0;
	int		iCount = 0;
	char	szReg[0x05] = {0}, *ptr = NULL;
	t_disasm	da;	
	BYTE B1 = 0x00, B2 = 0x00, B3 = 0x00;

	for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes - 2;)
	{
		B1 = m_pbyBuff[dwOffset];
		B2 = m_pbyBuff[dwOffset + 0x01];
		B3 = m_pbyBuff[dwOffset + 0x02];

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		//SAL AL,C8
		if(B1==0xC0 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}
		if(B1==0xD0 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}
		if(B1==0xD2 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}
		if(B1==0xD3 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset += 0x02;
			continue;
		}
		if(B1 == 0x0F && B2 == 0xAC && B3 == 0xDD)
		{
			dwOffset += 0x04;
			continue;
		}
		if(B1 == 0xF3 && B2 == 0x0F && B3 == 0xBD)
		{
			dwOffset += 0x04;
			continue;
		}
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20,0x400000, &da, DISASM_CODE);

		dwOffset += dwLength;
		dwRecur++;

		if((strstr(da.result,"ADD E")&& strstr(da.result,"[ESP]")))
		{
			iCount++;
			if(iCount == 0x1)
			{
				dwStartAddress = dwOffset - dwLength;				
			}
			
		}			
		if((strstr(da.result,"ADD E")&& strstr(da.result,"[E"))&& 
			iCount >= 0x02 &&(strstr(da.result,"[ESP]")== NULL))
		{
			ptr = NULL;
			ptr = strchr(da.result,'E');
			strncpy_s(szReg, 0x05, ptr, 3);
			szReg[3] = '\0';
			m_dwInstCount = dwRecur;
			dwEndAddress  = dwOffset - dwLength;
			break;
		}

	}
	if(szReg[0] != 'E')
	{
		return false;
	}

	DWORD dwKey = GetEmulatedRegister(dwStartAddress,dwEndAddress,szReg,0x400000,0x0);
	if(dwKey != 0x00)
	{
		m_SalityParam.m_SalityBHParam.dwKey = dwKey;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep Vayosa + Virus Analysis Team
	Description		: Detection routine for Sality.AA
--------------------------------------------------------------------------------------*/
int CPolySality::DetectSalityAA(bool bDeadCode)
{
	int	iRetStatus = VIRUS_NOT_FOUND ;

	WORD wTempSecNo =  m_pMaxPEFile->GetSectionNoFromOffset(m_SalityParam.m_dwLastSecJumpOffset);
	if(OUT_OF_FILE == wTempSecNo)
	{
		return iRetStatus;
	}

	bool bCheck = false , bCheck2 = false, bCheck3 = false;
	BOOL bTest = FALSE;
	for(int dwIndex = m_wNoOfSections-1; dwIndex >= 0; dwIndex--)
	{
		if(m_pSectionHeader[dwIndex].NumberOfLinenumbers || 
			m_pSectionHeader[dwIndex].PointerToLinenumbers )
		{
			bCheck = true;
			break;
		}
	}
	
	
	char szSecondSecName[8] = {0};         //some files not having bCheck property.        ..........added by _mangesh
	char szLastSecName[8] = {0};
	char szTest[8] = {0};
	memcpy(szSecondSecName, m_pSectionHeader[1].Name, 0x08);
	memcpy(szLastSecName, m_pSectionHeader[wTempSecNo].Name, 0x08);
	
	if(memcmp(szLastSecName,szTest,8)!= 0 && (memcmp(szSecondSecName,szTest,8))!= 0) //skip files if section not having name
	{
		if(strstr(&szLastSecName[1],&szSecondSecName[1]) && (m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000000)== 0xE0000000)
		{
			bCheck2 = true;
		}
		// Add on 2nd June, 2014
		if(strstr(&szLastSecName[1],&szSecondSecName[1]) || (m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000000)== 0xE0000000)
		{
			bCheck3		= true;
		}
	}

	//if(true == bCheck || bCheck2 == true)
	if(true == bCheck || bCheck2 == true || (bCheck3 == true && bDeadCode == true)) // add 2nd June, 2014 by Sandeep
	{
		//Tushar --> Contains un-alligned part of Virus Body
		DWORD dwTemp = m_SalityParam.m_dwLastSecJumpOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment;

		memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
		m_SalityParam.m_dwVirusOffSet = m_SalityParam.m_dwLastSecJumpOffset;
		m_SalityParam.m_dwVirusRVA = m_SalityParam.m_dwLastSecJumpRVA;

		const int BUFFER_SIZE = 0x1000;
		if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, BUFFER_SIZE, BUFFER_SIZE))
			return iRetStatus;

		if(!GetSalityDecryptKeyModeEx())
		{
			m_SalityParam.m_bSalityAADEC = FALSE;
		}

		//Tushar --> This Part is to delete Currupt Sality.AA files.(Only with unalligned body)
		if(dwTemp > 0x00 && bCheck)
		{
			if(Detect4ValidDec()!= TRUE)
			{
				iRetStatus = VIRUS_FILE_DELETE;
			}
		}
		bTest = SalityGenDecryption();   //added by mangesh
	//	if(FALSE == bTest && (bCheck || bCheck2))    
		if(FALSE == bTest && (bCheck || bCheck2 || (bCheck3 == true && bDeadCode == true))) // Added on 2nd June, 2014 by Sandeep
		{
			bTest = SalityAA_DEC();
			if(FALSE == bTest)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.AA"));
				m_dwSalityType	= VIRUS_SALITY_AA;
				iRetStatus = VIRUS_FILE_DELETE;
				return iRetStatus;
			}	
			
		}
		if(bTest)
		{
			iRetStatus = VIRUS_FILE_REPAIR;
			m_dwSalityType	= VIRUS_SALITY_AA;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.AA"));	
		}
		if(m_SalityParam.m_SalityAAParam.dwType == 0x00 || 
			m_SalityParam.m_SalityAAParam.dwType > 0x03)
		{
			return iRetStatus;		
		}
		m_SalityParam.m_bSalityAADEC=TRUE;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanSalityBH
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Sandeep Vayosa + Virus Analysis Team
	Description		: Repair routine for Sality.BH
--------------------------------------------------------------------------------------*/
int CPolySality::CleanSalityBH()
{
	int iRetStatus = REPAIR_FAILED;
	

	BYTE	szATKey[0x20] = {0};
	
	if(!m_pMaxPEFile->ReadBuffer(szATKey, m_SalityParam.m_SalityBHParam.dw16ByteKeyOffset, 0x20, 0x20))
		return iRetStatus;
	
	memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
	if(!GetBuffer(m_SalityParam.m_dwVirusOffSet + 0x1116, SALITY_BUFFER_SIZE, SALITY_BUFFER_SIZE))
		return iRetStatus;

	DWORD dwKeyLen = 0, dwTemp = 0, dwTemp1 = 0, dwOffset = 0, dwKeyLoc = 0x1C, dwATKey = 0x3F;

	for(dwOffset = 0; dwOffset < m_dwNoOfBytes; dwOffset += 0x08)
	{
		dwATKey = 0x3F;
		dwKeyLoc = 0x1C;
		while(true)
		{
			if(dwATKey%0x02)
				dwTemp = *((DWORD *)&m_pbyBuff[dwOffset + 0x04]);
			else
				dwTemp = *((DWORD *)&m_pbyBuff[dwOffset]);

			dwTemp1 = dwTemp * 64;
			dwTemp1 ^=(dwTemp >> 0x08);
			dwTemp1 += dwTemp + dwOffset + m_SalityParam.m_SalityBHParam.dwKey;
			dwTemp1 += *((DWORD *)&szATKey[dwKeyLen + dwKeyLoc])+ dwATKey;

			if(dwATKey % 0x02)
				*((DWORD *)&m_pbyBuff[dwOffset])-= dwTemp1;
			else
				*((DWORD *)&m_pbyBuff[dwOffset + 0x04])-= dwTemp1;

			if(dwKeyLoc == 0x00)
				dwKeyLoc = 0x1C;
			else
				dwKeyLoc -= 0x04;

			if(dwATKey == 0x00)
				break;

			dwATKey -= 0x01;
		}           
	}
	BYTE  bSignature[] = {0x75, 0x78, 0x4A, 0x4C, 0x70, 0x65, 0x31, 0x6D, 0x00, 0x41, 0x70, 0x31, 0x6D, 0x75};

	if(memcmp(bSignature, &m_pbyBuff[0x670], sizeof(bSignature))!= 0 &&  
		memcmp(bSignature, &m_pbyBuff[0x671], sizeof(bSignature))!= 0 &&  
		memcmp(bSignature, &m_pbyBuff[0x672], sizeof(bSignature))!= 0 &&
		(!((*((DWORD *)&m_pbyBuff[0x00]))== 0 &&(*((DWORD *)&m_pbyBuff[0x04])== 0))))//Tushar --> For Integration
	{
		return iRetStatus;
	}
	GetOriByteReplacementOff();

	
	BYTE bTempSign[] = {0x49, 0x85, 0xC9, 0x74, 0x15, 0x41, 0x81};  //....added by __mangesh (removed logic 2 find 0000280000 bytes 2 get original bytes)
	DWORD dwSubKey = 0, dwAddKey = 0;
	int nVirusFound = 0, i = 0;
	DWORD dwCounter = 0x00;

	if(memcmp(&m_pbyBuff[0x6ED],bTempSign,7)== 0)
	{
		if(m_pbyBuff[0x6ED + 0x7]== 0xe9)
		   dwSubKey = *(DWORD *)&m_pbyBuff[0x6F5];
		
		else if(m_pbyBuff[0x6ED + 0x7]== 0xC1)
		    dwAddKey = *(DWORD *)&m_pbyBuff[0x6F5];
		
		else return false;

	}
	if(dwSubKey)
	{
		dwCounter = *(DWORD *)&m_pbyBuff[0x1774] - dwSubKey;
	}
	else if(dwAddKey)
	{
	   dwCounter = *(DWORD *)&m_pbyBuff[0x1774] + dwAddKey;
	}
	else if(*(DWORD *)&m_pbyBuff[0x1770] == 0x01000000)
	{
		dwCounter = *(DWORD *)&m_pbyBuff[0x1774];
	}
   
	if(dwCounter < 0x300 && dwCounter  != 0x00)
	{
		if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x1778], m_dwOriByteReplacementOff, dwCounter, dwCounter))
			return iRetStatus;
	}
		

	if(dwCounter == 0x00 || dwCounter > 0x300)
	{
		DWORD	dwFirst = 0x00, dwSecond = 0x00;
		BYTE	bTempBuffer1[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8B, 0xC5};
		BYTE	bTempBuffer2[] = {0x8A, 0x9D};

		for(int iVar =0; iVar < 100;iVar++)
		{
			if(memcmp(&m_pbyBuff[iVar], bTempBuffer1,8)==0)
			{
				dwFirst =(*(DWORD*)&m_pbyBuff[iVar + 10]);
				if(memcmp(&m_pbyBuff[iVar + 14], bTempBuffer2,2)==0)
				{
					dwSecond =(*(DWORD*)&m_pbyBuff[iVar + 16]);
					break;
				}
			}
		}

		DWORD dwVirCodeStart = m_SalityParam.m_dwVirusOffSet + 0x1116;
		dwVirCodeStart =(dwVirCodeStart + 0x05)-(dwFirst - m_dwImageBase);
		dwVirCodeStart += dwSecond;
		DWORD dwTemp =(dwVirCodeStart + 0x05)-(m_SalityParam.m_dwVirusOffSet+0x1116) - m_dwImageBase;
		dwCounter =(*(DWORD*)&m_pbyBuff[dwTemp - 0x04]);

		
		if(dwCounter > 0x300 || (!dwFirst && !dwSecond)) //to handle files which does not having any matched strings ... added by mangesh
		{
			m_pMaxPEFile->CloseFile_NoMemberReset();
			return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : iRetStatus;
		}

		if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwTemp], m_dwOriByteReplacementOff, dwCounter, dwCounter))
			return iRetStatus;
	}
	
	iRetStatus = RemoveSalityVirusCode();
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanSalityOG
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Sandeep Vayosa + Virus Analysis Team
	Description		: Repair routine for Sality.OG
--------------------------------------------------------------------------------------*/
int CPolySality::CleanSalityOG()
{
	int iRetStatus = REPAIR_FAILED;


		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_SalityParam.m_SalityOGParam.dwOrgBytesOffset + 0x06 + 0x2C + 0x04], m_dwAEPMapped, m_SalityParam.m_SalityOGParam.dwReplaceBytes, m_SalityParam.m_SalityOGParam.dwReplaceBytes))
		{
			iRetStatus = RemoveSalityVirusCode();
		}
		
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSalityAEorAF
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep Vayosa + Virus Analysis Team
	Description		: Detection routine for Sality AE & Sality.AF
--------------------------------------------------------------------------------------*/
int CPolySality::DetectSalityAEorAF()
{	
	int iRetStatus = VIRUS_NOT_FOUND;
	int iEmulateStatus = 0;
	DWORD dwEIP = 0;
	m_SalityParam.m_SalityAEParam.bDeleteFile = false;

    //Tushar --> This is Used with Sality.AE as it is depend on Virus Section Name.
	DWORD dwWeightage = 0x00; 
	bool bAEPMinus = false, bPatch = false;

	BYTE szSecName[4] = {0};
	memcpy(szSecName, m_pSectionHeader[m_wNoOfSections-1].Name, 0x04);

	if(szSecName[0] != 0x2E )
	{
		if(szSecName[0] >=0x61 && szSecName[0] <= 0x7A)
		{
			szSecName[0] = szSecName[0] - 0x20;
		}
	}
	for(DWORD dwIndex = 1; dwIndex < 0x04; dwIndex++)
	{
		if(szSecName[dwIndex] >=0x61 && szSecName[dwIndex] <= 0x7A)
		{
			szSecName[dwIndex] = szSecName[dwIndex] - 0x20;
		}
	}

	DWORD dwSecName = *((DWORD *)&szSecName[0]);
	if(dwSecName)	
	{
		DWORD dwReadSecName = 0x00;
		DWORD dwBytesToCheck = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
		DWORD dwOffset = m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x16000 ? dwBytesToCheck - 0x16000 : m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
		
		for(; dwOffset < dwBytesToCheck; dwOffset += m_pMaxPEFile->m_stPEHeader.FileAlignment)
		{
			if(m_pMaxPEFile->ReadBuffer(&dwReadSecName, dwOffset, 0x04, 0x04))
			{
				if(dwSecName == dwReadSecName)
				{
					//Tushar --> For Integration
					dwWeightage++;
					m_SalityParam.m_SalityAEParam.dwTruncateOffset = dwOffset;
					m_SalityParam.m_SalityAEParam.dwTruncateRVA =  m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + (dwOffset - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData);
					m_SalityParam.m_SalityAEParam.bSectionName = TRUE;
				}
			}
		}
	}

	memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
	if(!GetBuffer(m_dwAEPMapped, 0x1000, 0x1000))
		return iRetStatus;

	DWORD dwCallOffset = 0x00;
	DWORD dwTempOffset = TraceCALLInstruction(m_dwAEPUnmapped, &dwCallOffset);	
	
	if(dwTempOffset)
	{
		
		m_SalityParam.m_dwLastSecJumpOffset = dwTempOffset;
		memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
		if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, 0x20, 0x20))
			return iRetStatus;

		if(!GetFirstInst())
			return iRetStatus;

		if(!(strstr(m_SalityParam.m_szFirstVirusInst, "PUSHAD")))
			dwTempOffset = 0;
	}

	if(dwTempOffset == 0x00)
	{
		DWORD dwReadOff = m_dwAEPMapped - 0x1000;
		
		memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
		if(m_dwAEPMapped < 0x1000 )
		{
			dwReadOff = m_pSectionHeader[m_wAEPSec].PointerToRawData;
		}
		
	if(!GetBuffer(dwReadOff, 0x1000, 0x1000))
			return iRetStatus;

		dwCallOffset = 0x00;
		dwTempOffset = TraceCALLInstruction(m_dwAEPUnmapped - 0x1000, &dwCallOffset);
		if(dwTempOffset)													//added by mangesh
			bAEPMinus = true;

	}
	
	if(dwTempOffset)
	{
		
		m_SalityParam.m_dwLastSecJumpOffset = dwTempOffset;
		memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
		if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, 0x20, 0x20))
			return iRetStatus;

		if(!GetFirstInst())
			return iRetStatus;

		if(!(strstr(m_SalityParam.m_szFirstVirusInst, "PUSHAD")))
		{
			dwTempOffset = 0;
			bAEPMinus = false;
		}
		
	}
	if(dwTempOffset == 0x00 && m_wAEPSec != m_wNoOfSections-1)
	{
		if(!GetPatchedCalls(m_pSectionHeader[m_wAEPSec].PointerToRawData, m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData, m_wNoOfSections - 1))
		{
			return iRetStatus;
		}
		if(m_arrPatchedCallOffsets.GetCount())
		{
			DWORD dwCalledAdd = 0, dwCalledAddOff = 0;
			LPVOID	lpos = m_arrPatchedCallOffsets.GetHighest();

			while(lpos)
			{
				m_arrPatchedCallOffsets.GetKey(lpos, dwCalledAdd);
				m_arrPatchedCallOffsets.GetData(lpos,dwCallOffset);
				m_SalityParam.m_dwLastSecJumpRVA = dwCalledAdd;
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwCalledAdd, &dwCalledAddOff))
				{					
					m_SalityParam.m_dwLastSecJumpOffset = dwCalledAddOff;
					memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
					if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, 0x20, 0x20))
						break;//return iRetStatus;

					if(!GetFirstInst())
						return iRetStatus;

					if(!(strstr(m_SalityParam.m_szFirstVirusInst, "PUSHAD")))
						dwTempOffset = 0x00;
					else
					{
						dwTempOffset = dwCalledAddOff;
						if(dwTempOffset)							//added by mangesh
							bPatch = true;

						break;
					}
				}
				lpos = m_arrPatchedCallOffsets.GetHighestNext(lpos);
			}
		}
	}
	if(dwTempOffset)
	{
		m_SalityParam.m_dwLastSecJumpOffset = dwTempOffset;
		memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
		if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, 0x20, 0x20))
			return iRetStatus;

		if(!GetFirstInst())
			return iRetStatus;

		if(!(strstr(m_SalityParam.m_szFirstVirusInst, "PUSHAD")))
			dwTempOffset = 0x00;
		
		
		DWORD dwStart = m_SalityParam.m_dwLastSecJumpOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment;
		m_SalityParam.m_dwVirusOffSet = m_SalityParam.m_dwLastSecJumpOffset - dwStart;

		if(GetBuffer(m_SalityParam.m_dwVirusOffSet, 0x1000, 0x1000))
		{
			m_SalityParam.m_SalityAFParam.dwDecOffset = m_SalityParam.m_dwLastSecJumpRVA + 
														m_dwImageBase;
			
		if(m_SalityParam.m_SalityAEParam.bSectionName != TRUE)    // added by _mangesh
		{
			if(dwSecName == *(DWORD*)m_pbyBuff)
			{
				m_SalityParam.m_SalityAEParam.dwTruncateOffset = m_SalityParam.m_dwVirusOffSet;
				m_SalityParam.m_SalityAEParam.dwTruncateRVA =  m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + (m_SalityParam.m_dwVirusOffSet - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData);
				m_SalityParam.m_SalityAEParam.bSectionName = TRUE;
			}
		}
		

			if(m_SalityParam.m_SalityAEParam.bSectionName == TRUE)
			{
				if(GetSalityAEKeyModeEx(dwStart))
				{
					if(CheckSalityAESig())
					{
						if(bAEPMinus == true)												//added by mangesh
						{
							m_SalityParam.m_dwAddressofPatchedBytes = m_dwAEPMapped + dwCallOffset - 0x1000;
						}
						else if(bPatch == true)
						{
							m_SalityParam.m_dwAddressofPatchedBytes = dwCallOffset;// - 1 ;
						}
						else
						{
							m_SalityParam.m_dwAddressofPatchedBytes = m_dwAEPMapped + dwCallOffset;
						}
						
						if(m_SalityParam.m_SalityAEParam.bDeleteFile == true)//files not having original data
						{
							iRetStatus		= VIRUS_FILE_DELETE;
							m_dwSalityType	= VIRUS_SALITY_AE;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.AE"));
						}
						else
						{
							iRetStatus		= VIRUS_FILE_REPAIR;
							m_dwSalityType	= VIRUS_SALITY_AE;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.AE"));
						}
					}
				}
			}

			if(GetSalityAFKeyMode(dwStart))
			{
				if(CheckSalityAFSig())
				{
					m_SalityParam.m_dwAddressofPatchedBytes = m_dwAEPMapped + dwCallOffset;
					iRetStatus		= VIRUS_FILE_REPAIR;
					m_dwSalityType	= VIRUS_SALITY_AF;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.AF"));			
				}
			}
		}
	}
	else
	{
		//Tushar --> For Integration
		dwWeightage++;

		DWORD   dwRVATempOffset = 0x00;
		for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes; dwOffset++)
		{
			if(m_pbyBuff[dwOffset] == 0xE9 && m_pbyBuff[dwOffset + 4] == 0xFF)
			{
				dwTempOffset = *((DWORD *)&m_pbyBuff[dwOffset + 1]);
				dwTempOffset += m_dwAEPUnmapped + dwOffset + 0x05;

				if(dwTempOffset <(m_pSectionHeader[0].VirtualAddress + m_pSectionHeader[0].SizeOfRawData))
				{
					dwRVATempOffset = dwTempOffset;
					if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwRVATempOffset, &dwTempOffset))
					{
						continue;
					}

					memset(m_pbyBuff, 0x00, 0x200);
					if(!GetBuffer(dwTempOffset, 0x200, 0x200))
					{
						continue;
					}

					dwTempOffset = TraceCALLInstruction(dwRVATempOffset, &dwCallOffset);
					if(!dwTempOffset)
						return iRetStatus;
					
					
					m_SalityParam.m_dwLastSecJumpOffset = dwTempOffset;

					memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
					if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, 0x20, 0x20))
						return iRetStatus;

					if(!GetFirstInst())
						return iRetStatus;

					if(!(strstr(m_SalityParam.m_szFirstVirusInst, "PUSHAD")))
						return iRetStatus;

					DWORD dwStart = m_SalityParam.m_dwLastSecJumpOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment;
					m_SalityParam.m_dwVirusOffSet = m_SalityParam.m_dwLastSecJumpOffset - dwStart;

					if(GetBuffer(m_SalityParam.m_dwVirusOffSet,0x1000,0x1000))
					{	
						if(m_SalityParam.m_SalityAEParam.bSectionName == TRUE)
						{
							if(GetSalityAEKeyModeEx(dwStart))
							{
								if(CheckSalityAESig())
								{
									if(bAEPMinus == true)												//added by mangesh
									{
										m_SalityParam.m_dwAddressofPatchedBytes = m_dwAEPMapped + dwCallOffset - 0x1000;
									}
									else if(bPatch == true)
									{
										m_SalityParam.m_dwAddressofPatchedBytes = dwCallOffset ;//- 1 ;
									}
									else
									{
										m_SalityParam.m_dwAddressofPatchedBytes = m_dwAEPMapped + dwCallOffset;
									}

									if(m_SalityParam.m_SalityAEParam.bDeleteFile == true)//files not having original data
									{
										iRetStatus		= VIRUS_FILE_DELETE;
										m_dwSalityType	= VIRUS_SALITY_AE;
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.AE"));

									}
								   else
									{
										m_SalityParam.m_dwAddressofPatchedBytes = dwRVATempOffset + dwCallOffset;
										iRetStatus		= VIRUS_FILE_REPAIR;
										m_dwSalityType	= VIRUS_SALITY_AE;
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.AE"));
									}
								}
							}										
						}
					}
				}
			}				
		}
	}

	//DEAD CODE DETECTION
	//Tushar --> In case of Sality.AE we find body of virus using Name of Infected Section. 
	// If it founds but call to virus body is not preset then we will try with below logic.
	// This will search required instructions in Virus Body. Its for Valid DEADCODE of Virus.Sality.AE
	if(iRetStatus == VIRUS_NOT_FOUND && dwWeightage == 0x02)
	{
		BYTE	pBuffer[0x500];
		DWORD	dwCount = 0x00;
		memset(pBuffer, 0x00, 0x500);
		if(!m_pMaxPEFile->ReadBuffer(pBuffer, m_SalityParam.m_SalityAEParam.dwTruncateOffset, 0x500, 0, &dwCount))
			return iRetStatus;

		DWORD	dwOffset = 0x00;
		DWORD	dwCurPos = 0x00;	
		dwOffset = GetPushADInst(pBuffer,dwOffset,dwCount);
		while(dwOffset)
		{
			dwCurPos = dwOffset;
			m_SalityParam.m_dwLastSecJumpOffset = m_SalityParam.m_SalityAEParam.dwTruncateOffset + dwCurPos;

			memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
			if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, 0x20, 0x20))
				return iRetStatus;

			if(!GetFirstInst())
				return iRetStatus;

			if(!(strstr(m_SalityParam.m_szFirstVirusInst, "PUSHAD")))
				return iRetStatus;

			DWORD dwStart = m_SalityParam.m_dwLastSecJumpOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment;
			m_SalityParam.m_dwVirusOffSet = m_SalityParam.m_dwLastSecJumpOffset - dwStart;

			if(GetBuffer(m_SalityParam.m_dwVirusOffSet,0x1000,0x1000))
			{	
				if(GetSalityAEKeyModeEx(dwStart))
				{
					if(CheckSalityAESig())
					{
						if(m_SalityParam.m_SalityAEParam.bDeleteFile == true)//files not having original data
						{
							iRetStatus		= VIRUS_FILE_DELETE;
							m_dwSalityType	= VIRUS_SALITY_AE;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.AE"));
							break;

						}
						else
						{
							m_SalityParam.m_dwAddressofPatchedBytes = 0xFFFFFFFF;  // do not replace original bytes, bcoz it is deadcode.    added by .....mangesh
							iRetStatus		= VIRUS_FILE_REPAIR;
							m_dwSalityType	= VIRUS_SALITY_AE;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.AE"));
						    break;
						}
					}
				}
				if(GetSalityAFKeyMode(dwStart))
				{
					if(CheckSalityAFSig())
					{
						m_SalityParam.m_dwAddressofPatchedBytes = 0xFFFFFFFF;
						iRetStatus		= VIRUS_FILE_REPAIR;
						m_dwSalityType	= VIRUS_SALITY_AF;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.AF"));
						break;
					}
				}
			}
			dwOffset = GetPushADInst(pBuffer,(dwCurPos+1),dwCount);
		}
	}
	return iRetStatus;
	}

/*-------------------------------------------------------------------------------------
	Function		: CheckSalityAESig
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Mangesh Fasale + Virus Analysis Team
	Description		: Binary Signature validation for Sality.AE
--------------------------------------------------------------------------------------*/
BOOL CPolySality::CheckSalityAESig()                    //.....added by   _mangesh
{
	bool bRetStatus = false;
	memset(m_pbyBuff, 0x00, 0x3000);
	if(!GetBuffer(m_SalityParam.m_dwVirusOffSet + 0x1116, 0x3000, 0x2000))
		return FALSE;

	BYTE bVirusFound = 0x00;
	BYTE bySignature[] = {0x41, 0x70, 0x31, 0x6D, 0x75, 0x74, 0x78, 0x37, 0x00};
    DWORD dwOffset = 0;
	for(dwOffset = 0x250; dwOffset < 0x700; dwOffset++)
	{
		if(memcmp(bySignature, &m_pbyBuff[dwOffset], sizeof(bySignature))== 0)
		{
			bVirusFound = 0x01;
			break;
		}
	}

	if(!bVirusFound)
	{
		for(DWORD dwIndex = 0; dwIndex < m_dwNoOfBytes - 4; dwIndex += 0x04)
		{
			switch(m_SalityParam.m_SalityAEParam.dwType)
			{
			case 0x01:
				*((DWORD *)&m_pbyBuff[dwIndex])+= m_SalityParam.m_SalityAEParam.dwKey;
				break;

			case 0x02:
				*((DWORD *)&m_pbyBuff[dwIndex])-= m_SalityParam.m_SalityAEParam.dwKey;
				break;

			case 0x03:
				*((DWORD *)&m_pbyBuff[dwIndex])^= m_SalityParam.m_SalityAEParam.dwKey;
				break;
			}
		}
	}

	//BYTE bVirusFound = 0x00;
	//BYTE bySignature[] = {0x41, 0x70, 0x31, 0x6D, 0x75, 0x74, 0x78, 0x37, 0x00};
	if(!bVirusFound)
	{
		for(dwOffset = 0x250; dwOffset < 0x700; dwOffset++)
		{
			if(memcmp(bySignature, &m_pbyBuff[dwOffset], sizeof(bySignature))== 0)
			{
				bVirusFound = 0x01;
				break;
			}
		}
	}
	if(!bVirusFound)
	{
		return bRetStatus;
	}

	BYTE	bTempSign[] = {0x00, 0x00, 0x28, 0x00, 0x00, 0x00};
	DWORD	 dwTempOffset = 0, dwTemp = 0x1600, dwIndex = 0x1150;
	
	int nVirusFound[8] = {0x00}, i=0;	// files having more than 1 TempSign ..... added by mangesh

	
	for(; dwIndex < dwTemp; dwIndex++)
	{
		if(memcmp(&m_pbyBuff[dwIndex], bTempSign, sizeof(bTempSign))== 0)
		{
			nVirusFound[i++] = dwIndex;
			dwTemp = dwIndex + 0x100 + 0x06;
			dwIndex += 0x06;
		}
	}

	if(dwIndex >= dwTemp && nVirusFound[0] == 0x00)
	{
		m_SalityParam.m_SalityAEParam.bDeleteFile = true;
		return true;
	}

	m_SalityParam.m_SalityAEParam.dwPatchedOffset = nVirusFound[i-1];
	m_SalityParam.m_SalityAEParam.dwNoPachedBytes = *((DWORD *)&m_pbyBuff[m_SalityParam.m_SalityAEParam.dwPatchedOffset + 0x06 + 0x2C]);
	if(m_SalityParam.m_SalityAEParam.dwNoPachedBytes > 0x10 || m_SalityParam.m_SalityAEParam.dwNoPachedBytes == 0)
	{
		m_SalityParam.m_SalityAEParam.dwNoPachedBytes = 0x05;
		bRetStatus = true;
	}
	else bRetStatus = true;

return bRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSalityAFESig
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Mangesh Fasale + Virus Analysis Team
	Description		: Binary Signature validation for Sality.AF
--------------------------------------------------------------------------------------*/
BOOL CPolySality :: CheckSalityAFSig()      //.....added by   _mangesh
{
	bool iRetStatus = false;
    
	m_SalityParam.m_SalityAFParam.dwDecOffset -= m_dwImageBase;

	DWORD dwDecOffset = 0x00;
	m_pMaxPEFile->Rva2FileOffset(m_SalityParam.m_SalityAFParam.dwDecOffset,&dwDecOffset);

	memset(m_pbyBuff, 0x00, 0x3000);
	if(!GetBuffer(dwDecOffset, 0x3000, 0x2000))
		return iRetStatus;

	m_SalityParam.m_SalityAFParam.dwKey[0] += m_SalityParam.m_SalityAFParam.dwKey[1];

	DWORD dwOffset = 0;
	for(; dwOffset < m_dwNoOfBytes-4; dwOffset += 0x04)
	{
		switch(m_SalityParam.m_SalityAFParam.dwType)
		{
		case 0x01:
			*((DWORD *)&m_pbyBuff[dwOffset])+= m_SalityParam.m_SalityAFParam.dwKey[0];
			break;

		case 0x02:
			*((DWORD *)&m_pbyBuff[dwOffset])-= m_SalityParam.m_SalityAFParam.dwKey[0];
			break;

		case 0x03:
			*((DWORD *)&m_pbyBuff[dwOffset])^= m_SalityParam.m_SalityAFParam.dwKey[0];
			break;
		}

		m_SalityParam.m_SalityAFParam.dwKey[0x01] -= 0x01;
		m_SalityParam.m_SalityAFParam.dwKey[0] += m_SalityParam.m_SalityAFParam.dwKey[0x01];
	}

	m_SalityParam.m_SalityAFParam.byVirusFound = 0x00;
	BYTE	bySignature[] = { 0x4F, 0x70, 0x31, 0x6D, 0x75, 0x74, 0x78, 0x39, 0x00,
							  0x41, 0x70, 0x31, 0x6D, 0x75, 0x74, 0x78, 0x37, 0x00 };

	BYTE  bySignature1[] = {0x75, 0x78, 0x4A, 0x4C, 0x70, 0x65, 0x31, 0x6D, 0x00, 0x41, 0x70, 0x31, 0x6D, 0x75};

	for(dwOffset = 0x450; dwOffset < 0x700; dwOffset++)
	{
		if((memcmp(bySignature, &m_pbyBuff[dwOffset], sizeof(bySignature))== 0) || (memcmp(bySignature1, &m_pbyBuff[dwOffset], sizeof(bySignature1))== 0))
		{
			m_SalityParam.m_SalityAFParam.byVirusFound = 0x01;
			iRetStatus = true;
			break;
		}
	}
return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanSalityAE
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for Sality.AE
--------------------------------------------------------------------------------------*/
int CPolySality::CleanSalityAE()
{		
	int iRetStatus = REPAIR_FAILED;
	
	if(m_SalityParam.m_dwAddressofPatchedBytes == 0xFFFFFFFF)
	{
		if(m_SalityParam.m_SalityAEParam.bSectionName && m_SalityParam.m_SalityAEParam.dwTruncateOffset)
		{
			m_SalityParam.m_dwLastSecJumpOffset =  m_SalityParam.m_SalityAEParam.dwTruncateOffset;
		}
		if(0==(m_SalityParam.m_SalityAEParam.dwTruncateOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment))
		{
			m_SalityParam.m_dwVirusOffSet = m_SalityParam.m_SalityAEParam.dwTruncateOffset;
		}
		iRetStatus = RemoveSalityVirusCode();
	}

	else if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_SalityParam.m_SalityAEParam.dwPatchedOffset + 0x06 + 0x2C + 0x04], m_SalityParam.m_dwAddressofPatchedBytes, m_SalityParam.m_SalityAEParam.dwNoPachedBytes, m_SalityParam.m_SalityAEParam.dwNoPachedBytes))
	{
		if(m_SalityParam.m_SalityAEParam.bSectionName && m_SalityParam.m_SalityAEParam.dwTruncateOffset)
		{
			m_SalityParam.m_dwLastSecJumpOffset =  m_SalityParam.m_SalityAEParam.dwTruncateOffset;
		}
		if(0==(m_SalityParam.m_SalityAEParam.dwTruncateOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment))
		{
			m_SalityParam.m_dwVirusOffSet = m_SalityParam.m_SalityAEParam.dwTruncateOffset;
		}
		iRetStatus = RemoveSalityVirusCode();
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanSalityAF
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for Sality.AF
--------------------------------------------------------------------------------------*/
int CPolySality::CleanSalityAF()
{
	int iRetStatus = REPAIR_FAILED;
	
	BYTE	bTempSign[] = {0x00, 0x00, 0x28, 0x00, 0x00, 0x00};
	DWORD	dwTemp = 0x1600,dwTempOffset = 0,dwOffset = 0;

	BYTE bVirusFound1 = 0x00;
	for(dwOffset = 0x1150; dwOffset < dwTemp; dwOffset++)
	{
		if(memcmp(&m_pbyBuff[dwOffset], bTempSign, sizeof(bTempSign))== 0)
		{
			dwTempOffset = dwOffset;
			dwTemp = dwOffset + 0x100 + 0x06;
			dwOffset += 0x06;
			bVirusFound1 += 0x01;
			if(bVirusFound1 == 0x02)
				break;
		}
	}

	if(dwOffset >= dwTemp && bVirusFound1 == 0x00)
	{
		const int XOR_OFFSET = 0x6E4;
		const int SUB_OFFSET = 0x6EA;
		const int COUNTER_OFFSET = 0x1770;
		if((*(DWORD*)&m_pbyBuff[COUNTER_OFFSET] == 0x01000000) &&
			((*(DWORD*)&m_pbyBuff[COUNTER_OFFSET+4] ^ *(DWORD*)&m_pbyBuff[XOR_OFFSET])-
			*(DWORD*)&m_pbyBuff[SUB_OFFSET]) == 0x05)
		{
			if(TRUE == RepairSalityGen(0x05,COUNTER_OFFSET+8))
			{
				iRetStatus = REPAIR_SUCCESS;
 			}
		}
		else if(m_SalityParam.m_SalityAFParam.byVirusFound) // files havin sality sig but not having original bytes ..... added by __mangesh
		{
		    m_pMaxPEFile->CloseFile_NoMemberReset();
			return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : iRetStatus;
		}
		return iRetStatus;
	}

	dwTemp = *((DWORD*)&m_pbyBuff[dwTempOffset + 0x06 + 0x2C]);
	if(dwTemp > 0x10 || dwTemp == 0x00)
	{
		dwTemp = 0x05;			
	}

	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwTempOffset + 0x06 + 0x2C + 0x04], m_SalityParam.m_dwAddressofPatchedBytes, dwTemp, dwTemp))
	{		
		iRetStatus = RemoveSalityVirusCode();
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSalityAEKeyModeEx
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Key mode generation for Sality.AE
--------------------------------------------------------------------------------------*/
bool CPolySality::GetSalityAEKeyModeEx(DWORD dwStart)
{
	DWORD	dwLength = 0, dwTemp = 0, dwPush = 0, dwPop = 0, dwBreakTest = 0;
	BYTE	B1 = 0, B2 = 0;
	char	chJump = 0, szRegister[5]={0}, szAdd[10]={0}, szSub[10]={0}, szXor[10]={0};
	char	*ptr = NULL;

	DWORD dwOffset = dwStart;
	while(dwOffset < m_dwNoOfBytes - 2)
	{
		t_disasm da = {0};
		
		B1 = *((BYTE*)&m_pbyBuff[dwOffset]);
		B2 = *((BYTE*)&m_pbyBuff[dwOffset+1]);

		if(dwBreakTest > dwOffset)
			break;

		dwBreakTest = dwOffset;

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if((B1==0xC0||B1==0xC1)&&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if((B1==0xD0 || B1==0xD1 || B1==0xD2 || B1==0xD3) &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
		if(0 == dwLength)
		{
			break;
		}

		if(dwLength==0x01 && _strcmpi(da.dump, "FFFFFFC3")== 0)
			break;
		if(dwLength==0x02 && strstr(da.result, "JMP SHORT"))
		{
			dwOffset += dwLength + B2;
			continue;
		}
		if(dwLength==0x05 && B1==0xE9 && strstr(da.result, "JMP "))
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffset+1]);
			dwOffset += dwLength + dwTemp;

			if(dwOffset >= m_dwNoOfBytes)
				break;

			continue;
		}
		if(dwLength==0x05 && B1==0xE8 && chJump==0x00 && strstr(da.result, "CALL "))
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffset+1]);
			if(NEGATIVE_JUMP(dwTemp))
				break;

			dwOffset += dwLength + dwTemp;
			if(dwOffset >= m_dwNoOfBytes)
				break;

			chJump = 0x01;
			continue;
		}

		if(dwLength==0x02 && chJump==0x01 && strstr(da.result, "MOV E")&&(strstr(da.result, ",[EAX]")||strstr(da.result, ",[EBX]")||strstr(da.result, ",[ECX]")||strstr(da.result, ",[EDX]")))
		{
			ptr = strstr(da.result, "MOV E");
			if(ptr)
			{
				ptr += strlen("MOV E")- 1;

				szRegister[0] = ptr[0];
				szRegister[1] = ptr[1];
				szRegister[2] = ptr[2];
				szRegister[3] = '\0';

				sprintf_s(szAdd, 0x0A, "ADD %s,", szRegister);
				sprintf_s(szSub, 0x0A, "SUB %s,", szRegister);
				sprintf_s(szXor, 0x0A, "XOR %s,", szRegister);
				chJump = 0x02;
			}

			dwOffset += dwLength;
			continue;
		}
		if(dwLength==0x02 && chJump==0x01 && strstr(da.result, "PUSH DWORD PTR [E"))
		{
			chJump = 0x02;
			dwPush += 0x01;
			dwOffset += dwLength;
			continue;
		}
		if(chJump==0x02 && strstr(da.result, "PUSH "))
		{
			dwPush += 0x01;
			dwOffset += dwLength;
			continue;
		}
		if(chJump==0x02 && strstr(da.result, "POP "))
			dwPop += 0x01;

		if(chJump==0x02 && dwPush==dwPop && strstr(da.result, "POP "))
		{
			szRegister[0] = da.result[4];
			szRegister[1] = da.result[5];
			szRegister[2] = da.result[6];
			szRegister[3] = '\0';

			sprintf_s(szAdd, 0x0A, "ADD %s,", szRegister);
			sprintf_s(szSub, 0x0A, "SUB %s,", szRegister);
			sprintf_s(szXor, 0x0A, "XOR %s,", szRegister);
			dwOffset += dwLength;
			continue;
		}

		if(dwLength==0x02 && chJump==0x03)
		{
			if(strstr(da.result, "POP DWORD PTR [E")||(strstr(da.result, "MOV [E")&& strstr(da.result, szRegister)))
			{
				chJump = 0x04;
				dwOffset += dwLength;
				break;
			}
		}

		if(dwLength==0x06 && chJump==0x02 && strlen(szAdd)&& strlen(szSub)&& strlen(szXor))
		{
			if(strstr(da.result, szAdd))
			{
				ptr = strchr(da.result, ',');
				if(ptr)
				{
					ptr++;
					sscanf_s(ptr, "%X", &dwTemp);
					m_SalityParam.m_SalityAEParam.dwKey = dwTemp;
					m_SalityParam.m_SalityAEParam.dwType = 0x01;
					chJump = 0x03;
				}
			}
			if(strstr(da.result, szSub))
			{
				ptr = strchr(da.result, ',');
				if(ptr)
				{
					ptr++;
					sscanf_s(ptr, "%X", &dwTemp);
					m_SalityParam.m_SalityAEParam.dwKey = dwTemp;
					m_SalityParam.m_SalityAEParam.dwType = 0x02;
					chJump = 0x03;
				}
			}
			if(strstr(da.result, szXor))
			{
				ptr = strchr(da.result, ',');
				if(ptr)
				{
					ptr++;
					sscanf_s(ptr, "%X", &dwTemp);
					m_SalityParam.m_SalityAEParam.dwKey = dwTemp;
					m_SalityParam.m_SalityAEParam.dwType = 0x03;
					chJump = 0x03;
				}
			}

			dwOffset += dwLength;
			continue;
		}

		dwOffset += dwLength;
	}

	if(chJump < 0x04)
		return false;

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSalityAFKeyMode
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Key mode generation for Sality.AF
--------------------------------------------------------------------------------------*/
bool CPolySality::GetSalityAFKeyMode(DWORD dwStart)
{	
	m_SalityParam.m_SalityAFParam.dwKey[0]  = 0x00;
	m_SalityParam.m_SalityAFParam.dwKey[1]  = 0x00;
	m_SalityParam.m_SalityAFParam.dwType	= 0x00;

	DWORD	dwNextStart = 0, dwRange = 0, dwRanges[5] = {0}, dwRegValues[5]={0};
	DWORD	dwValue = 0x00, dwNumRegs = 0, i = 0x00 , j = 0x00;

	DWORD dwTemp = dwStart;
	GetInstructionSet(m_pbyBuff, m_dwNoOfBytes, 0x01, &dwTemp);
	if(!m_dwInstCount)
		return false;

	DWORD dwLocation = m_dwInstCount -1;

	char *ptr = NULL;
	if(strstr(m_objInstructionSet[dwLocation].szPnuemonics, "POP DWORD PTR [E"))
	{
		i = dwLocation - 0x01;
		j = i - 0x10;
		for(; i>j; i--)
		{
			ptr = NULL;
			ptr = strstr(m_objInstructionSet[i].szPnuemonics, "PUSH E");
			if(ptr)
			{
				ptr += 0x04;
				break;
			}
		}
	}
	else
		ptr = strrchr(m_objInstructionSet[dwLocation].szPnuemonics, ',');

	if(NULL == ptr)
		return false;

	ptr++;
	if(strlen(ptr)!= 0x03)
		return false;

	m_SalityParam.m_SalityAFParam.dwDecOffset +=(dwTemp - dwStart);
	
	char szRequiredReg[0x05], szAddReg[0x09], szSubReg[0x09], szXorReg[0x09];
	char szNextRegs[5][10] = {0};
	
	strcpy_s(szRequiredReg, 0x05, ptr);
	sprintf_s(szAddReg, 0x09, "ADD %s", szRequiredReg);
	sprintf_s(szSubReg, 0x09, "SUB %s", szRequiredReg);
	sprintf_s(szXorReg, 0x09, "XOR %s", szRequiredReg);

	char chImpInst = 0x00;
	dwLocation--;
	for(; dwLocation>0; dwLocation--)
	{
		if(m_objInstructionSet[dwLocation].dwInstLen==0x02 &&((strstr(m_objInstructionSet[dwLocation].szPnuemonics, "MOV E")&&(strstr(m_objInstructionSet[dwLocation].szPnuemonics, "X]")||strstr(m_objInstructionSet[dwLocation].szPnuemonics, "I]")))
			|| strstr(m_objInstructionSet[dwLocation].szPnuemonics, "PUSH DWORD PTR [E")))
		{
			chImpInst = 0x01;
			break;
		}

		if(m_objInstructionSet[dwLocation].dwInstLen != 0x02)
			continue;

		ptr = NULL;
		if(strstr(m_objInstructionSet[dwLocation].szPnuemonics, szAddReg))
		{
			if(!m_SalityParam.m_SalityAFParam.dwType)
				m_SalityParam.m_SalityAFParam.dwType=0x01;

			ptr = strrchr(m_objInstructionSet[dwLocation].szPnuemonics, ',');
		}

		if(strstr(m_objInstructionSet[dwLocation].szPnuemonics, szSubReg))
		{
			if(! m_SalityParam.m_SalityAFParam.dwType)
				m_SalityParam.m_SalityAFParam.dwType=0x02;
			ptr = strrchr(m_objInstructionSet[dwLocation].szPnuemonics, ',');
		}

		if(strstr(m_objInstructionSet[dwLocation].szPnuemonics, szXorReg))
		{
			if(!m_SalityParam.m_SalityAFParam.dwType)
				m_SalityParam.m_SalityAFParam.dwType=0x03;
			ptr = strrchr(m_objInstructionSet[dwLocation].szPnuemonics, ',');
		}

		if(NULL == ptr)
			continue;

		ptr++;
	
		strcpy_s(&szNextRegs[dwNumRegs++][0], 0x0A, ptr);
		dwRanges[dwRange++] = dwLocation;

		sprintf_s(szAddReg, 0x09, "ADD %s", ptr);
		sprintf_s(szSubReg, 0x09, "SUB %s", ptr);
		sprintf_s(szXorReg, 0x09, "XOR %s", ptr);
	}

	if(dwNumRegs == 0x00 || chImpInst == 0x00)
		return false;

	i = j = 0x00;
	dwLocation -= 0x01;

	for(; dwNumRegs>0x00; dwNumRegs--)
	{
		dwTemp = 0x00;
		GetGivenRegisterValue(dwLocation, &szNextRegs[dwNumRegs-1][0], &dwTemp, &dwNextStart);

		sprintf_s(szAddReg, 0x09, "ADD %s", &szNextRegs[dwNumRegs-1][0]);
		sprintf_s(szSubReg, 0x09, "SUB %s", &szNextRegs[dwNumRegs-1][0]);
		sprintf_s(szXorReg, 0x09, "XOR %s", &szNextRegs[dwNumRegs-1][0]);

		for(; dwNextStart<dwLocation; dwNextStart++)
		{
			i = 0x00;
			ptr = NULL;
			if(strstr(m_objInstructionSet[dwNextStart].szPnuemonics, szAddReg))
			{
				i = 0x01;
				ptr = strrchr(m_objInstructionSet[dwNextStart].szPnuemonics, ',');
			}

			if(strstr(m_objInstructionSet[dwNextStart].szPnuemonics, szSubReg))
			{
				i = 0x02;
				ptr = strrchr(m_objInstructionSet[dwNextStart].szPnuemonics, ',');
			}

			if(strstr(m_objInstructionSet[dwNextStart].szPnuemonics, szXorReg))
			{
				i = 0x03;
				ptr = strrchr(m_objInstructionSet[dwNextStart].szPnuemonics, ',');
			}

			if(NULL == ptr)
				continue;

			ptr++;
			sscanf_s(ptr, "%X", &dwValue);


			switch(i)
			{
			case 1:
				dwTemp += dwValue;
				break;
			case 2:
				dwTemp -= dwValue;
				break;
			case 3:
				dwTemp ^= dwValue;
				break;
			}
		}

		dwRegValues[dwNumRegs-1] = dwTemp;
	}

	m_SalityParam.m_SalityAFParam.dwKey[0] = dwRegValues[0x00];
	m_SalityParam.m_SalityAFParam.dwKey[1] = dwRegValues[0x01];

	dwLocation = 0x00;
	strcpy_s(szRequiredReg, 0x05, "");

	GetRequiredRegister(szRequiredReg, &dwLocation);

	sprintf_s(szAddReg, 0x09, "ADD %s", szRequiredReg);
	sprintf_s(szSubReg, 0x09, "SUB %s", szRequiredReg);
	sprintf_s(szXorReg, 0x09, "XOR %s", szRequiredReg);

	if(dwLocation >= m_dwInstCount)
		return false;

	chImpInst = 0x00;
	for(; dwLocation<m_dwInstCount; dwLocation++)
	{

		if(m_objInstructionSet[dwLocation].dwInstLen==0x02 &&((strstr(m_objInstructionSet[dwLocation].szPnuemonics, "MOV E")&&(strstr(m_objInstructionSet[dwLocation].szPnuemonics, "X]")||strstr(m_objInstructionSet[dwLocation].szPnuemonics, "I]")))
			|| strstr(m_objInstructionSet[dwLocation].szPnuemonics, "PUSH DWORD PTR [E")))
			break;

		if(chImpInst && strstr(m_objInstructionSet[dwLocation].szPnuemonics, "PUSH ")&& strstr(m_objInstructionSet[dwLocation].szPnuemonics, szRequiredReg))
			break;

		i = 0x00;
		ptr = NULL;
		if(strstr(m_objInstructionSet[dwLocation].szPnuemonics, szAddReg))
		{
			i = 0x01;
			ptr = strrchr(m_objInstructionSet[dwLocation].szPnuemonics, ',');
		}

		if(strstr(m_objInstructionSet[dwLocation].szPnuemonics, szSubReg))
		{
			i = 0x02;
			ptr = strrchr(m_objInstructionSet[dwLocation].szPnuemonics, ',');
		}

		if(strstr(m_objInstructionSet[dwLocation].szPnuemonics, szXorReg))
		{
			i = 0x03;
			ptr = strrchr(m_objInstructionSet[dwLocation].szPnuemonics, ',');
		}

		if(NULL == ptr)
			continue;

		dwValue = 0x00;
		ptr++;
		sscanf_s(ptr, "%X", &dwValue);
		chImpInst = 0x01;

		switch(i)
		{
		case 1:
			m_SalityParam.m_SalityAFParam.dwDecOffset += dwValue;
			break;
		case 2:
			m_SalityParam.m_SalityAFParam.dwDecOffset -= dwValue;
			break;
		case 3:
			m_SalityParam.m_SalityAFParam.dwDecOffset ^= dwValue;
			break;
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: TraceCALLInstruction
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Identify the CALL patch for Virus Code Jump
--------------------------------------------------------------------------------------*/
DWORD CPolySality::TraceCALLInstruction(DWORD dwRVAAEP, DWORD *dwCallOffset)
{
	bool bLastSecNameUPX = false;
	int  iEmulateStatus = 0;

	if(*((DWORD*)&m_pSectionHeader[m_wNoOfSections-1].Name[1]) == 0x30585055)
		bLastSecNameUPX = true;
	

	DWORD dwRVAVirOffset = 0x00, dwCallAddress = 0 ,dwEIP = 0, dwJumpAdd = 0;
	BYTE byRead[4] = {0};
	for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes; dwOffset++)
	{
		if(m_pbyBuff[dwOffset]==0xE8)
		{
			dwCallAddress = *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwRVAAEP + dwOffset + 0x05;
			if(dwCallAddress >= m_SalityParam.m_SalityAEParam.dwTruncateRVA && 
				dwCallAddress <=(m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize))
			{
				
				dwRVAVirOffset = dwCallAddress;
				m_pMaxPEFile->Rva2FileOffset(dwCallAddress,&dwCallAddress);
				if(dwCallAddress==0x00)
					continue;

				m_SalityParam.m_dwLastSecJumpRVA = dwRVAVirOffset;
				*dwCallOffset = dwOffset;
				break;
			}

			else if(bLastSecNameUPX == true && dwCallAddress >= m_pSectionHeader[m_wNoOfSections - 2].VirtualAddress && 
				dwCallAddress <=(m_pSectionHeader[m_wNoOfSections - 2].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 2].Misc.VirtualSize))
			{
				dwRVAVirOffset = dwCallAddress;
				m_pMaxPEFile->Rva2FileOffset(dwCallAddress,&dwCallAddress);
				if(dwCallAddress==0x00)
					continue;

				m_SalityParam.m_dwLastSecJumpRVA = dwRVAVirOffset;
				*dwCallOffset = dwOffset;
				break;
			}
			else
				dwCallAddress=0x00;
		}
	}
	
	if(dwCallAddress == 0 && m_wAEPSec == m_wNoOfSections - 1 && m_SalityParam.m_SalityAEParam.bSectionName == TRUE) // aep in last section so we have to check PUSHAD @ every call(for sality.AE)...... added by _mangesh
	{
		WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
		{
			CEmulate objEmulate(m_pMaxPEFile);
			if(objEmulate.IntializeProcess())
			{
				objEmulate.SetNoOfIteration(0x100);
				objEmulate.SetBreakPoint("__isinstruction('call')");
				objEmulate.SetBreakPoint("__isinstruction('pushad')");
				objEmulate.PauseBreakPoint(1);
				objEmulate.SetEip(m_dwAEPUnmapped + m_dwImageBase);
				while(true)
				{
					iEmulateStatus = objEmulate.EmulateFile();
					if(iEmulateStatus != 7)
					{
						break;
					}
					if(iEmulateStatus == 7)
					{
						dwCallAddress = objEmulate.GetEip() - m_dwImageBase;
						objEmulate.ReadEmulateBuffer(byRead,sizeof(DWORD),dwCallAddress+1+m_dwImageBase);
						dwJumpAdd = *(DWORD*)&byRead + 5 + objEmulate.GetEip();
						m_pMaxPEFile->Rva2FileOffset(dwCallAddress,&dwEIP);
						
						if(dwJumpAdd - m_dwImageBase < m_SalityParam.m_SalityAEParam.dwTruncateRVA )
						{
							iEmulateStatus = 0;
							objEmulate.SetEip(dwJumpAdd);
							continue;
						}

						objEmulate.PauseBreakPoint(0);
						objEmulate.ActiveBreakPoint(1);
						iEmulateStatus = 0;
						iEmulateStatus = objEmulate.EmulateFile();

						if(iEmulateStatus != 7)
						{
							break;
						}

						if(iEmulateStatus == 7)
						{
							dwCallAddress = objEmulate.GetEip();
							if(m_SalityParam.m_SalityAEParam.dwTruncateRVA + m_dwImageBase <= dwCallAddress && dwJumpAdd == dwCallAddress)
							{
								dwRVAVirOffset = dwCallAddress;
								m_pMaxPEFile->Rva2FileOffset((dwCallAddress - m_dwImageBase),&dwCallAddress);
								m_SalityParam.m_dwLastSecJumpRVA = dwRVAVirOffset;
								*dwCallOffset = dwEIP - m_dwAEPMapped;
								break;
							}

							else
							{
								objEmulate.ActiveBreakPoint(0);
								objEmulate.PauseBreakPoint(1);
							}
						}
					}
				}
			}
		}
		SetEvent(CPolymorphicVirus::m_hEvent);	
	}
	return dwCallAddress;
}

/*-------------------------------------------------------------------------------------
	Function		: GetInstructionSet
	In Parameters	: BYTE *pBuff, DWORD dwSize, BYTE bEndOpt, DWORD *pCallLocation
	Out Parameters	: CALL offset
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Finds the CALL instruction patched by Virus
--------------------------------------------------------------------------------------*/
DWORD CPolySality::GetInstructionSet(BYTE *pBuff, DWORD dwSize, BYTE bEndOpt, DWORD *pCallLocation)
{
	DWORD		dwOffset, dwLength, dwTemp, dwCallLoc;
	DWORD		dwTotalInstCnt;
	t_disasm	da;
	BYTE		*pBuffer, B1, B2;
	char		chBaseAddrss;

	pBuffer = NULL;
	dwCallLoc = dwLength = dwOffset = dwTemp = dwTotalInstCnt = 0x00;
	if(bEndOpt)
		dwOffset = *pCallLocation;
	*pCallLocation = 0x00;
	chBaseAddrss = 0x00;
	B1 = B2 = 0x00;

	if(pBuff == NULL)
		return 1;

	pBuffer = pBuff;

	while(dwOffset < dwSize - 2)
	{
		if(m_dwInstCount>0x250 ||dwTotalInstCnt>0x450)
			break;

		memset(&da, 0x00, sizeof(struct t_disasm));
		B1 = *((BYTE*)&pBuffer[dwOffset]);
		B2 = *((BYTE*)&pBuffer[dwOffset+1]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if((B1==0xC0 || B1==0xC1)&&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if((B1==0xD0 || B1==0xD1 || B1==0xD2 || B1==0xD3)&&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)pBuffer+dwOffset, 0x20, 0x400000, &da, DISASM_CODE);

		dwTotalInstCnt++;
		if(dwLength==0x01 && dwTotalInstCnt>0x08 && _strcmpi(da.dump, "FFFFFFC3")== 0)
			break;
		if(dwLength==0x02 && B1==0xFF && B2>=0xE0 && B2<=0xE6 && strstr(da.result, "JMP E"))
			break;
		if(chBaseAddrss)
		{
			m_objInstructionSet[m_dwInstCount].dwInstLen = dwLength;
			strcpy_s(m_objInstructionSet[m_dwInstCount].szOpcode, TEXTLEN, da.dump);
			strcpy_s(m_objInstructionSet[m_dwInstCount++].szPnuemonics, TEXTLEN, da.result);
		}

		if(dwLength==0x02 &&(strstr(da.result, "JMP SHORT")|| strstr(da.result, "JB SHORT")))
		{
			dwTemp = MakeDword(da.dump, ' ');
			dwOffset += dwLength + dwTemp;
			continue;
		}
		if(dwLength==0x05 && B1==0xE9 && strstr(da.result, "JMP "))
		{
			dwTemp = *((DWORD*)&pBuffer[dwOffset+1]);
			dwOffset += dwLength + dwTemp;

			if(dwOffset >= m_dwNoOfBytes)
				break;

			continue;
		}
		if(dwLength==0x05 && B1==0xE8 &&(!chBaseAddrss)&& strstr(da.result, "CALL "))
		{
			dwTemp = *((DWORD*)&pBuffer[dwOffset+1]);
			if((dwTemp+dwOffset)>= m_dwNoOfBytes)
			{
				dwOffset += dwLength;
				continue;
			}

			if(dwTemp <0x100)
			{
				chBaseAddrss = 0x01;
				dwCallLoc = dwOffset + 0x05;
				dwOffset += dwLength + dwTemp;
				continue;
			}
		}

		if(!bEndOpt)
		{
			dwOffset += dwLength;
			continue;
		}

		if(bEndOpt == 0x01)
		{
			if(dwLength==0x02 && chBaseAddrss)
			{
				if(strstr(da.result, "POP DWORD PTR [E")|| strstr(da.result, "MOV [E"))
					break;
			}
		}

		if(bEndOpt == 0x02)
		{
			if(dwLength==0x03 && strstr(da.result, "SHR E"))
				chBaseAddrss = 0x01;

			if(chBaseAddrss && B1==0x03 && dwLength==0x02 && strstr(da.result, "ADD E")&& strstr(da.result, ",[E"))
				break;
		}

		dwOffset += dwLength;
	}

	*pCallLocation = dwCallLoc;
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: GetGivenRegisterValue
	In Parameters	: DWORD dwStart, char *pszReg, DWORD *pdwValue, DWORD *pdwNextStart
	Out Parameters	: Register Value
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Find the register value after instruction
--------------------------------------------------------------------------------------*/
DWORD CPolySality::GetGivenRegisterValue(DWORD dwStart, char *pszReg, DWORD *pdwValue, DWORD *pdwNextStart)
{
	char	szTemp[0x10] = {0}, szNextReg[0x07] = {0}, *ptr = NULL, *ptr1 = NULL;
	char	szMov[0x09] = {0}, szXor[0x09] = {0}, szAnd[0x09] = {0}, szLea[0x09] = {0};
	char	szImul[0x0A] = {0};
	char	szAdd[0x0A] = {0};

	char	szPushStack[0x20][0x20] = {0};
	char	szPopStack[0x20][0x20] = {0}, szPop[0x09];
	DWORD	dwPushTop = 0x00, dwPopTop=0x00;

	DWORD	i, dwValue, j;

	j = i = dwValue = 0x00;

	if(dwStart == 0x00)
		return dwValue;

	sprintf_s(szNextReg, 0x07, " %s,E", pszReg);
	sprintf_s(szMov, 0x09, "MOV %s", pszReg);
	sprintf_s(szAdd, 0x09, "ADD %s", pszReg);
	sprintf_s(szXor, 0x09, "XOR %s", pszReg);
	sprintf_s(szAnd, 0x09, "AND %s", pszReg);
	sprintf_s(szLea, 0x09, "LEA %s", pszReg);
	sprintf_s(szImul, 0x0A, "IMUL %s", pszReg);
	sprintf_s(szPop, 0x09, "POP %s", pszReg);

	i = dwStart;
	for(; i>0; i--)
	{
		dwValue = 0x00;
		ptr = NULL;
		if(strstr(m_objInstructionSet[i].szPnuemonics, "POP "))
		{
			strcpy_s(&szPopStack[dwPopTop++][0], 0x20, m_objInstructionSet[i].szPnuemonics);
			continue;
		}

		if(strstr(m_objInstructionSet[i].szPnuemonics, "PUSH "))
			strcpy_s(&szPushStack[dwPushTop++][0], 0x20, m_objInstructionSet[i].szPnuemonics);

		if((dwPopTop==dwPushTop)&&(dwPopTop<0x20)&&(dwPushTop<0x20))
		{
			if(dwPopTop && dwPushTop)
			{
				if(strstr(&szPopStack[dwPopTop-1][0], szPop)!= NULL)
					ptr = strrchr(&szPushStack[dwPushTop-1][0], ' ');	
			}
			else
			{
				if(dwPopTop>=0x00 && dwPushTop>=0x00)
				{
					if(strstr(&szPopStack[dwPopTop][0], szPop)!= NULL)
						ptr = strrchr(&szPushStack[dwPushTop][0], ' ');
				}
			}

			if(ptr)
			{
				ptr++;
				if(strlen(ptr)== 0x03 &&(ptr[2]=='X' || ptr[2]=='I' || ptr[2]=='P'))
					return 0;

				sscanf_s(ptr, "%X", &dwValue);

				if(pdwNextStart)
					*pdwNextStart = i +1;
				*pdwValue = dwValue;
				return 1;
			}
		}

		ptr = strstr(m_objInstructionSet[i].szPnuemonics, szMov);
		if(ptr)
		{
			ptr += strlen(szMov)+ 1;
			if(strlen(ptr)== 0x03 &&(ptr[2]=='X' || ptr[2]=='I' || ptr[2]=='P'))
				return 0;

			sscanf_s(ptr, "%X", &dwValue);
			if(pdwNextStart)
				*pdwNextStart = i +1;
			*pdwValue = dwValue;
			return 1;
		}

		ptr = strstr(m_objInstructionSet[i].szPnuemonics, szAdd);
		if(ptr)
		{
			ptr += strlen(szAdd)+ 1;
			if(strlen(ptr)== 0x03 &&(ptr[2]=='X' || ptr[2]=='I' || ptr[2]=='P'))
				return 0;
		}

		ptr = strstr(m_objInstructionSet[i].szPnuemonics, szXor);
		if(ptr)
		{
			ptr += strlen(szXor)+ 1;
			if(strlen(ptr)== 0x03 &&(ptr[2]=='X' || ptr[2]=='I' || ptr[2]=='P'))
				return 0;

			sscanf_s(ptr, "%X", &dwValue);
			if(dwValue)
				continue;

			if(pdwNextStart)
				*pdwNextStart = i + 1;
			*pdwValue = dwValue;
			return 1;

		}
		ptr = strstr(m_objInstructionSet[i].szPnuemonics, szAnd);
		if(ptr)
		{
			ptr += strlen(szAnd)+ 1;
			if(strlen(ptr)== 0x03 &&(ptr[2]=='X' || ptr[2]=='I' || ptr[2]=='P'))
				return 0;

			sscanf_s(ptr, "%X", &dwValue);
			if(dwValue)
				continue;
			if(pdwNextStart)
				*pdwNextStart = i +1;
			*pdwValue = dwValue;
			return 1;
		}

		ptr = strstr(m_objInstructionSet[i].szPnuemonics, szLea);
		if(ptr)
		{
			ptr += 0x09;
			if(strlen(ptr)> 0x03 &&(ptr[2]=='X' || ptr[2]=='I' || ptr[2]=='P'))
				return 0;

			ptr1 = strrchr(ptr, ']');
			if(ptr1)
			{
				memset(szTemp, 0x00, 0x10);
				j = ptr1-ptr;
				if(j>0x08)
					return 0;

				strncpy_s(szTemp, 0x10, ptr, j);
				sscanf_s(szTemp, "%X", &dwValue);
				if(pdwNextStart)
					*pdwNextStart = i +1;

				*pdwValue = dwValue;
				return 1;
			}
			return 0;
		}

		ptr = strstr(m_objInstructionSet[i].szPnuemonics, szImul);
		if(ptr)
		{
			sprintf_s(szTemp, 0x10, ",%s,0", pszReg);
			if(strstr(m_objInstructionSet[i].szPnuemonics, szTemp))
			{
				if(pdwNextStart)
					*pdwNextStart = i + 1;
				*pdwValue = 0x00;
				return 1;
			}
		}
	}

	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: GetRequiredRegister
	In Parameters	: char *pRegister, DWORD *pLocation
	Out Parameters	: Register
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Finds the which register keep the counter register
--------------------------------------------------------------------------------------*/
DWORD CPolySality::GetRequiredRegister(char *pRegister, DWORD *pLocation)
{
	char *ptr = NULL;
	DWORD	dwCount, dwPushCount, dwPopCount, dwEspCount;
	DWORD	dwTemp, dwLastEsp;

	dwTemp = dwLastEsp = dwEspCount = dwPopCount = 0x00;
	dwPushCount = 0x01;

	for(dwCount=0; dwCount < m_dwInstCount; dwCount++)
	{
		if(dwPushCount == dwPopCount)
			break;

		//Avoiding standard Windows API calls ie CALL[41B3F8] UnMapViewOfFile
		if(strstr(m_objInstructionSet[dwCount].szPnuemonics, "CALL ["))
			dwPopCount++;

		if(strstr(m_objInstructionSet[dwCount].szPnuemonics, "PUSH "))
			dwPushCount++;
		if(strstr(m_objInstructionSet[dwCount].szPnuemonics, "POP "))
			dwPopCount++;

		if(strstr(m_objInstructionSet[dwCount].szPnuemonics, "ADD ESP,")|| strstr(m_objInstructionSet[dwCount].szPnuemonics, "SUB ESP,"))
		{
			if(GetEspValue(dwCount, &dwEspCount, &dwLastEsp))
			{
				dwCount = dwLastEsp;
				if(dwEspCount)
				{
					dwPopCount += dwEspCount/4;
					dwEspCount = dwEspCount%4;
				}
			}
		}
	}

	if(dwCount == m_dwInstCount)
		return 1;

	ptr = strrchr(m_objInstructionSet[dwCount-1].szPnuemonics, ' ');
	if(!ptr)
		return 2;

	ptr++;
	if(strlen(ptr)!= 0x03)
		return 3;

	strcpy_s(pRegister,5,ptr);
	*pLocation = dwCount;
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: GetEspValue
	In Parameters	: DWORD dwInitial, DWORD *dwValue, DWORD *pdwCount
	Out Parameters	: TRUE 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Finds ESP register value
--------------------------------------------------------------------------------------*/
BOOL CPolySality::GetEspValue(DWORD dwInitial, DWORD *dwValue, DWORD *pdwCount)
{
	DWORD	dwTemp;
	bool	bEspInst = false;
	char	*ptr = NULL;

	dwTemp = 0x00;

	for(; dwInitial<m_dwInstCount; dwInitial++)
	{
		if(strstr(m_objInstructionSet[dwInitial].szPnuemonics, "ADD ESP,"))
		{
			bEspInst = true;
			ptr = strrchr(m_objInstructionSet[dwInitial].szPnuemonics, ',');
			if(ptr)
			{
				ptr++;
				sscanf_s(ptr, "%X", &dwTemp);
				*dwValue += dwTemp;

				*pdwCount = dwInitial;
				dwTemp = 0x00;
			}
		}

		if(strstr(m_objInstructionSet[dwInitial].szPnuemonics, "SUB ESP,"))
		{
			bEspInst = true;
			ptr = strrchr(m_objInstructionSet[dwInitial].szPnuemonics, ',');
			if(ptr)
			{
				ptr++;
				sscanf_s(ptr, "%X", &dwTemp);
				*dwValue -= dwTemp;

				*pdwCount = dwInitial;
				dwTemp = 0x00;
			}
		}
	}
	return bEspInst;
}

/*-------------------------------------------------------------------------------------
	Function		: RemoveSalityVirusCode
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Removes sality code added in file.
--------------------------------------------------------------------------------------*/
int CPolySality::RemoveSalityVirusCode()
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pMaxPEFile->TruncateFile(m_SalityParam.m_dwVirusOffSet))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSalityT
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Adnan + Virus Analysis Team
	Description		: Detection routine for : Sality.T
					  This function searches Six continuous instruction at AEP,
					  in available buffer of 16 BYTE. All are written in sequance.
--------------------------------------------------------------------------------------*/
int CPolySality::DetectSalityT()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics&IMAGE_FILE_DLL)==IMAGE_FILE_DLL))
	{
		return iRetStatus;
	}
	if(!GetBuffer(m_dwAEPMapped, 
		m_SalityParam.m_SalityTParam.T_AEP_PATCHED_COUNT,
		m_SalityParam.m_SalityTParam.T_AEP_PATCHED_COUNT))
	{
		return iRetStatus;
	}

	t_disasm	da;
	DWORD		dwOffset = 0;
	DWORD		dwLength;
	DWORD		dwTemp = 0;
	DWORD		dwCount = 0;
	m_dwInstCount = 0;

	while(dwOffset < m_dwNoOfBytes - 2)
	{
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
		m_dwInstCount++;
		dwOffset += dwLength;
		if(m_dwInstCount > 6)
		{
			return iRetStatus;
		}

		if(strstr(da.result,"???"))
		{
			return iRetStatus;
		}

		if(dwCount == 0x00 && dwLength == 1 && strstr(da.result, "PUSHAD"))
		{
			dwCount++; 
			continue;
		}
		if(dwCount == 1 && dwLength == 5 && strstr(da.result, "CALL "))
		{
			dwCount++; 
			dwTemp = *((DWORD *)&m_pbyBuff[dwOffset - dwLength + 1])+ dwOffset;
		}
		if(dwCount == 2 && dwLength == 1 && strstr(da.result,"POP E"))
		{
			dwCount++; 
			continue;
		}
		if(dwCount == 3 && dwLength == 1 && strstr(da.result,"PUSH E"))
		{
			dwCount++; 
			continue;
		}
		if(dwCount == 4 && dwLength == 6 && strstr(da.result, "ADD E"))
		{
			dwCount++; 
			m_SalityParam.m_dwLastSecJumpRVA = dwTemp + *((DWORD*)&m_pbyBuff[dwOffset - dwLength + 2])+
														m_dwAEPUnmapped;

			m_SalityParam.m_dwVirusRVA = m_SalityParam.m_dwLastSecJumpRVA;

			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_SalityParam.m_dwLastSecJumpRVA, 
											&m_SalityParam.m_dwLastSecJumpOffset))
			{
				return iRetStatus;
			}
			
			m_SalityParam.m_dwVirusOffSet = m_SalityParam.m_dwLastSecJumpOffset;
			if(m_SalityParam.m_dwLastSecJumpOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment != 0x00)
			{
				return iRetStatus;
			}
			if(!(m_SalityParam.m_dwLastSecJumpOffset >= m_pSectionHeader[m_wNoOfSections-1].PointerToRawData && 
			  m_SalityParam.m_dwLastSecJumpOffset <(m_pSectionHeader[m_wNoOfSections-1].PointerToRawData + m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData)))
			{
				return iRetStatus;
			}

			continue;
		}
		if(dwCount == 5 && dwLength == 2 && strstr(da.result, "JMP E"))
		{			
			//Here we read one constant key that is needed for decryption.
			if(m_pMaxPEFile->ReadBuffer(&m_SalityParam.m_SalityTParam.wDeckey, m_SalityParam.m_dwVirusOffSet + 0x10, sizeof(WORD), sizeof(WORD)))
			{
				dwCount++;
			}
			break;
		}
	}
	if(dwCount == 6)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[SALITY_BUFFER_SIZE	];
		if(m_pbyBuff == NULL)
		{
			return iRetStatus;
		}

		if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset + m_SalityParam.m_SalityTParam.T_DEC_START_OFFSET,
			m_SalityParam.m_SalityTParam.T_DEC_COUNTER, 
			m_SalityParam.m_SalityTParam.T_DEC_COUNTER))
		{
			return iRetStatus;
		}

		DWORD	dwDecKey = 0x00, dwIndex = 0x00;
		
		//Decryption Loop
		for(dwIndex = 0x500; dwIndex < m_SalityParam.m_SalityTParam.T_DEC_COUNTER; dwIndex += 2)
		{
			dwDecKey =(static_cast<WORD>(dwIndex))* m_SalityParam.m_SalityTParam.wDeckey;
			dwDecKey = dwDecKey -(dwIndex/2);
			*((WORD *)&m_pbyBuff[dwIndex])^= dwDecKey;
		}
		
		//Tushar --> Sality.T is File Infector Type Virus. Drops .dll file in System32.
		//Tushar --> The Signature we are checking is the Start of DLL.
		//Tushar --> This to check for correct decryption.(We are setting wrong AEP Bytes in some cases)
		BYTE	bSig2Check[] = {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00};
		
		for(dwIndex = 0x500; dwIndex < m_SalityParam.m_SalityTParam.T_DEC_COUNTER; dwIndex++)
		{
			if(memcmp(&m_pbyBuff[dwIndex], bSig2Check, sizeof(bSig2Check))== 0)
			{
				m_dwIndex = dwIndex;
				iRetStatus = VIRUS_FILE_REPAIR;
				m_dwSalityType = VIRUS_SALITY_T;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.T"));
				 break;

			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanSalityT
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: Repair routine for : Sality.t
					  This function decrypt the virus code as per virus logic.
					  Then it replaces original 16 bytes at AEP.
--------------------------------------------------------------------------------------*/
int	CPolySality::CleanSalityT()
{
	int	iRetStatus = REPAIR_FAILED;
	
			m_dwIndex -= 0x1F;
			
			// Replace bytes at AEP.
			if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwIndex], m_dwAEPMapped, (m_SalityParam.m_SalityTParam.T_AEP_PATCHED_COUNT - 1), (m_SalityParam.m_SalityTParam.T_AEP_PATCHED_COUNT -1)))
			{
				iRetStatus = RemoveSalityVirusCode();
			}
		
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForValidDecryption
	In Parameters	: 
	Out Parameters	: Offset of Sig
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: Searches for binary signature (Mutex) in decrypted code for validation
--------------------------------------------------------------------------------------*/
DWORD CPolySality::CheckForValidDecryption()
{
	DWORD	dwRetStatus = 0x00;
	if((*(DWORD *)&m_pbyBuff[0])== 0x00 && *((DWORD *)&m_pbyBuff[4])== 0x00)
	{
		BYTE	bTempSign[] = {0x00, 0x00, 0x28, 0x00, 0x00, 0x00};
		BYTE	bVirusFound = 0x00;
		DWORD	dwTemp = 0x1800; 
		DWORD	dwOffset = 0x00;
		DWORD	dwTempOffset = 0x00;
		for(dwOffset = 0x1250; dwOffset < dwTemp; dwOffset++)
		{
			if(memcmp(&m_pbyBuff[dwOffset], bTempSign, 0x06)== 0)
			{
				dwTempOffset = dwOffset;
				dwTemp = dwOffset + 0x100 + 0x06;
				dwOffset += 0x06;
				bVirusFound += 0x01;
				if(bVirusFound == 0x02)
					break;
			}
		}
		if(dwOffset >= dwTemp && bVirusFound == 0x00)
		{
			return dwRetStatus;
		}

		dwTemp = *((DWORD *)&m_pbyBuff[dwTempOffset + 0x06 + 0x2C]);
		if(dwTemp < 0x300)
		{
			dwRetStatus = dwTempOffset;
		}		
	}
	return dwRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSalityU
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: Detection for : Sality.U
					  This function Searches 2 Signatures at AEP. Gets Information
					  for cleaning.	
--------------------------------------------------------------------------------------*/
int CPolySality::DetectSalityU()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL)!= IMAGE_FILE_DLL)&&
		(m_pSectionHeader[m_wNoOfSections-1].PointerToLinenumbers != 0x00))
	{
		if(GetBuffer(m_dwAEPMapped, 
						m_SalityParam.m_SalityUParam.AEP_PATCHED_COUNT,
						m_SalityParam.m_SalityUParam.AEP_PATCHED_COUNT))
		{
			BYTE		bAEPSig1[] = {0x60, 0xE8, 0x54, 0x00, 0x00, 0x00, 0x8D, 0xBD};
			BYTE		bAEPSig2[] = {0x04, 0x24, 0xDB, 0x44, 0x24, 0x04, 0xDE, 0xC1, 
									  0xDB, 0x1C, 0x24, 0x8B, 0x14, 0x24, 0xB9, 0x00};

			if(memcmp(&m_pbyBuff[0], bAEPSig1, sizeof(bAEPSig1))== 0)
			{
				if(memcmp(&m_pbyBuff[0x20], bAEPSig2, sizeof(bAEPSig2))== 0)
				{
					m_SalityParam.m_SalityUParam.wDeckey = *((WORD *)&m_pbyBuff[0x66]);
					DWORD dwTemp = *((DWORD *)&m_pbyBuff[0xD]);
					dwTemp = dwTemp + m_dwAEPUnmapped;

					DWORD dwOffset = 0x00;
					m_pMaxPEFile->Rva2FileOffset(dwTemp,&dwOffset);

					m_SalityParam.m_dwLastSecJumpOffset = dwOffset;
					m_SalityParam.m_dwVirusOffSet = dwOffset;

					dwTemp = *((DWORD *)&m_pbyBuff[0x2F]);
					if (0x2800 == dwTemp)
					{
						m_SalityParam.m_SalityUParam.dwLoopCounter = dwTemp;
						m_SalityParam.m_SalityUParam.dwOrgBytesOffSet = 0x24A;
					}
					else if (0x3000 == dwTemp)
					{
						m_SalityParam.m_SalityUParam.dwLoopCounter = dwTemp;
						m_SalityParam.m_SalityUParam.dwOrgBytesOffSet = 0x3DE;
					}
					else
						return iRetStatus;

					if(	m_SalityParam.m_dwLastSecJumpOffset <= m_pMaxPEFile->m_dwFileSize - m_SalityParam.m_SalityUParam.DEC_COUNTER)
					{
						iRetStatus		= VIRUS_FILE_REPAIR;
						m_dwSalityType	= VIRUS_SALITY_U;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.U"));
					}
					else
					{
						iRetStatus		= VIRUS_FILE_DELETE;
						m_dwSalityType	= VIRUS_SALITY_U;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.U"));
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanSalityU
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for : Sality.U
					  This function decrypt the virus code as per virus logic.
					  Then it replaces original 0x6A bytes at AEP.	
--------------------------------------------------------------------------------------*/
int	CPolySality::CleanSalityU()
{
	int	iRetStatus = REPAIR_FAILED;
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[m_SalityParam.m_SalityTParam.T_DEC_COUNTER];
	if(m_pbyBuff == NULL)
	{
		return iRetStatus;
	}

	if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset,
					m_SalityParam.m_SalityUParam.DEC_COUNTER, 
					m_SalityParam.m_SalityUParam.DEC_COUNTER))
	{
		return iRetStatus;
	}

	DWORD	dwDecKey = 0x00, dwSecKey = m_SalityParam.m_SalityUParam.dwLoopCounter;
	
	//Decryption Loop
	for(DWORD dwIndex = 0x000; dwIndex < m_SalityParam.m_SalityUParam.DEC_COUNTER; dwIndex += 2)
	{
		dwDecKey =(static_cast<WORD>(dwSecKey))* m_SalityParam.m_SalityUParam.wDeckey;
		dwDecKey = dwDecKey -(dwSecKey * 2);
		*((WORD *)&m_pbyBuff[dwIndex])^= dwDecKey;
		dwSecKey--;
	}
	
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_SalityParam.m_SalityUParam.dwOrgBytesOffSet], m_dwAEPMapped, m_SalityParam.m_SalityUParam.AEP_PATCHED_COUNT, m_SalityParam.m_SalityUParam.AEP_PATCHED_COUNT))
	{
		iRetStatus = RemoveSalityVirusCode();
	}

	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: GetPushADInst
	In Parameters	: BYTE *pBuff,DWORD dwStart, DWORD dwRange
	Out Parameters	: File offset
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function will search PUSHAD instruction in given buffer.
	                  This is used to handle deadcode of Sality.AE Virus  
--------------------------------------------------------------------------------------*/
DWORD CPolySality::GetPushADInst(BYTE *pBuff,DWORD dwStart, DWORD dwRange)
{

	 DWORD dwTemp = 0;               //Olly uanble 2 iterprete most of instructions  added by...........mangesh 
	 DWORD dwOffset = dwStart;
	 while(dwOffset < dwRange)
	 {
		 if((*((BYTE*)&pBuff[dwOffset])) == 0x60)
		 {
			 dwTemp = dwOffset;
			 break;
		 }
		 else dwOffset++;
	 }
	/*DWORD	dwLength = 0, dwTemp = 0;
	BYTE	B1 = 0, B2 = 0;

	DWORD dwOffset = dwStart;
	while(dwOffset < dwRange)
	{
		t_disasm da = {0};
		
		B1 = *((BYTE*)&pBuff[dwOffset]);
		B2 = *((BYTE*)&pBuff[dwOffset+1]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if((B1 == 0xC0 || B1 == 0xC1)&&(B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&pBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
		if(0 == dwLength)
		{
			break;
		}
		if(dwLength==0x01 && strstr(da.result, "PUSHAD"))
		{
			dwTemp = dwOffset;
			break;;
		}
		dwOffset += dwLength;
	}*/

	return dwTemp;
}

/*-------------------------------------------------------------------------------------
	Function		: Detect4ValidDec
	In Parameters	: 
	Out Parameters	: TRUE if success else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function will Decrypt first five bytes of Virus Body for Valid .
	                  Expected Result is 'E8 00000000' on success. Used this function with Sality.AA only(Both Types).
--------------------------------------------------------------------------------------*/
BOOL CPolySality::Detect4ValidDec()
{
	BOOL			bResult = FALSE;
	unsigned char	szKey1[0x16] = {0};
	unsigned char	szKey2[0x100] = {0};
	unsigned char	szBuf[0x05] = {0};
	DWORD			dwBytesRead = 0x00;
		
	DWORD dwOffVirus	= m_SalityParam.m_dwLastSecJumpOffset;
	DWORD dwTempOffset	= m_SalityParam.m_dwLastSecJumpOffset + 0x1000;

	if(!m_pMaxPEFile->ReadBuffer(szKey1, dwTempOffset, 0x16, 0x16))
		return bResult;
	
	DWORD	EDX = 0, dwOffset, dwTemp;
	BYTE	AL = 0, AH = 0, DL = 0, DH = 0, bVirusFound = 0;

	for(dwOffset = 0x03; dwOffset < 0x10; dwOffset++)
	{
		for(dwTemp = 0; dwTemp < 0x100; dwTemp++)
		{
			szKey2[dwTemp] =(unsigned char)dwTemp;
		}

		DL = DH = 0;

		for(dwTemp = 0; dwTemp < 0x100; dwTemp++)
		{
			if(DH > dwOffset)
				DH = 0x00;

			DL += szKey1[DH];
			AL = szKey2[dwTemp];
			DL += AL;
			EDX = DL;
			AH = szKey2[EDX];
			szKey2[EDX] = AL;
			szKey2[dwTemp] = AH; 

			DH++;
		}

		memset(szBuf, 0x00, 0x05 * sizeof(BYTE));
		if(!m_pMaxPEFile->ReadBuffer(szBuf,(dwTempOffset + 0x116), 0x04, 0, &dwBytesRead))
			break;

		EDX = 0x01;
		BYTE BL = 0, CH = 0;

		for(dwTemp = 0; dwTemp < dwBytesRead; dwTemp++)
		{
			if(EDX > 0xFF)
				EDX = 0x00;

			BL += szKey2[EDX];
			AL = szKey2[EDX];
			CH = szKey2[BL];
			szKey2[BL] = AL;
			szKey2[EDX] = CH;
			AL += CH;
			AL = szKey2[AL];
			szBuf[dwTemp] ^= AL;

			EDX++;
		}

		if(szBuf[0x00] == 0xE8 && szBuf[0x01] == 0x00 && szBuf[0x02] == 0x00 && szBuf[0x03] == 0x00)
		{
			bVirusFound = 0x01;
			break;
		}
	}
	if(bVirusFound)
	{
		return TRUE;
	}

	//Tushar --> Sality.AA with Decryption
	dwOffVirus	= m_SalityParam.m_dwLastSecJumpOffset;
	DWORD dwMode		= m_SalityParam.m_SalityAAParam.dwType;
	DWORD dwKey			= m_SalityParam.m_SalityAAParam.dwKey;
	dwTempOffset		= dwOffVirus + 0x1000;
	
	for(int iCnt = 0; iCnt < 2; iCnt++)
	{
		if(!m_pMaxPEFile->ReadBuffer(szKey1, dwTempOffset, 0x16, 0x16))
		{
			return bResult;
		}
		
		if(dwMode)
		{
			for(int iOffset = 0; iOffset <(iCnt + 1); iOffset++)
			{
				switch(dwMode)
				{
				case 1:
					*((DWORD *)&szKey1[iOffset*4])+= dwKey;
					break;

				case 2:
					*((DWORD *)&szKey1[iOffset*4])-= dwKey;
					break;

				case 3:
					*((DWORD *)&szKey1[iOffset*4])^= dwKey;
					break;
				}
			}
		}

		DWORD	EDX = 0;
		BYTE	AL = 0, AH = 0, DL = 0, DH = 0;
		for(int iOffset = 0x03; iOffset < 0x16; iOffset++)
		{
			for(dwTemp = 0; dwTemp < 0x100; dwTemp++)
				szKey2[dwTemp] =(unsigned char)dwTemp;

			DL = DH = 0;
			for(dwTemp = 0; dwTemp < 0x100; dwTemp++)
			{
				if(DH > iOffset)
					DH = 0x00;

				DL += szKey1[DH];
				AL = szKey2[dwTemp];
				DL += AL;
				EDX = DL;
				AH = szKey2[EDX];
				szKey2[EDX] = AL;
				szKey2[dwTemp] = AH;

				DH++;
			}

			memset(szBuf, 0x00, 0x05);
			if(!m_pMaxPEFile->ReadBuffer(szBuf, dwTempOffset + 0x116, 0x04, 0, &dwBytesRead))
				return bResult;

			EDX = 0x01;
			BYTE BL = 0, CH = 0;
			for(dwTemp = 0; dwTemp < dwBytesRead; dwTemp++)
			{
				if(EDX > 0xFF)
					EDX = 0x00;

				BL += szKey2[EDX];
				AL = szKey2[EDX];
				CH = szKey2[BL];
				szKey2[BL] = AL;
				szKey2[EDX] = CH;
				AL += CH;
				AL = szKey2[AL];
				szBuf[dwTemp] ^= AL;

				EDX++;
			}

			if(szBuf[0x00] == 0xE8 && szBuf[0x01] == 0x00 && szBuf[0x02] == 0x00 && szBuf[0x03] == 0x00)
			{
				bVirusFound = 0x01;
				break;
			}
		}
		if(bVirusFound)
			break;
	}
	if(bVirusFound)
	{
		return TRUE;
	}
	return bResult;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSalityYSig
	In Parameters	: 
	Out Parameters	: TRUE if sig Match else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for  : Sality.Y
--------------------------------------------------------------------------------------*/
BOOL CPolySality::CheckSalityYSig()
{
	BYTE bySignature[] = { 0x4F,0x70,0x31,0x6D,0x75,0x74,0x78,0x39,0x00 };
	BYTE byConfirmed[] = { 0x24,0x81,0x04,0x24,0x66,0x17,0x40,0x00,0xC3 };

	if(memcmp(bySignature, &m_pbyBuff[0x47C], sizeof(bySignature))== 0 && 
		memcmp(byConfirmed, &m_pbyBuff[0x7C4], sizeof(byConfirmed))== 0)
	{
		return TRUE;
	}	
	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSalityAASig
	In Parameters	: 
	Out Parameters	: TRUE if sig Match else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for  : Sality.AA
--------------------------------------------------------------------------------------*/
BOOL CPolySality::CheckSalityAASig()
{
	unsigned char szSignature[] = { 0x4F, 0x70, 0x31, 0x6D, 0x75, 0x74, 0x78, 0x39, 0x00};
	if(memcmp(szSignature, &m_pbyBuff[0x65D], sizeof(szSignature))== 0 ||
		memcmp(szSignature, &m_pbyBuff[0x586], sizeof(szSignature))== 0 )
	{
		return TRUE;
	}
	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSalityVSig
	In Parameters	: 
	Out Parameters	: TRUE if sig Match else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for  : Sality.V
--------------------------------------------------------------------------------------*/
BOOL CPolySality::CheckSalityVSig()
{
	BOOL bRetSatus = FALSE;
	unsigned char szSignature[] = { 0xBA, 0xC2, 0xCE, 0x00, 0x00 };	
	if(memcmp(szSignature, &m_pbyBuff[0], 0x05)!= 0)
		return bRetSatus;

	if(m_pbyBuff[0x09] != 0x66 || m_pbyBuff[0x0A] != 0x69)
		return bRetSatus;

	DWORD	EAX = 0, ECX = 0;
	DWORD dwTemp = 0x00;
	WORD	AX = 0, CX = 0, wKey = *((WORD*)&m_pbyBuff[0x0C]);
	for(dwTemp = 0x28; dwTemp < m_dwNoOfBytes; dwTemp += 0x02)
	{
		AX = CX * wKey;
		EAX = AX;
		ECX = ECX >> 0x01;
		EAX = EAX - ECX;
		ECX = ECX << 0x01;

		AX =(WORD)(EAX & 0xFFFF);

		*((WORD *)&m_pbyBuff[dwTemp])= *((WORD *)&m_pbyBuff[dwTemp])^ AX;
		CX += 0x02;
		ECX = CX;
	}

	if(m_pbyBuff[0x31] != 0xB9)
		return bRetSatus;

	dwTemp = *((DWORD*)&m_pbyBuff[0x32]);
	if(dwTemp > 0x300)
		return bRetSatus;

	unsigned char szConfirmed[] = {0x8D,0xB5,0x16,0x19,0x00,0x00 };
	if(memcmp(szConfirmed, &m_pbyBuff[0x2B], 0x06)!= 0)
		return bRetSatus;

	bRetSatus = TRUE;
	return bRetSatus;
}

/*-------------------------------------------------------------------------------------
	Function		: SalityGenDecryption
	In Parameters	: 
	Out Parameters	: TRUE if sig Match else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Generic decryption routine
--------------------------------------------------------------------------------------*/
BOOL CPolySality::SalityGenDecryption()
{
	BOOL bRetStatus = FALSE;

	DWORD dwTempOffset	= m_SalityParam.m_dwLastSecJumpOffset + 0x1000;

	unsigned char szKey1[0x16] = {0};
	if(!m_pMaxPEFile->ReadBuffer(szKey1, dwTempOffset, 0x16, 0x16))
		return bRetStatus;

	unsigned char szKey2[0x100] = {0};
	DWORD	EDX = 0, dwOffset, dwTemp;
	BYTE	AL = 0, AH = 0, DL = 0, DH = 0;

	for(dwOffset = 0x03; dwOffset < 0x16; dwOffset++)
	{
		for(dwTemp = 0; dwTemp < 0x100; dwTemp++)
		{
			szKey2[dwTemp] =(unsigned char)dwTemp;
		}

		DL = DH = 0;

		for(dwTemp = 0; dwTemp < 0x100; dwTemp++)
		{
			if(DH > dwOffset)
				DH = 0x00;

			DL += szKey1[DH];
			AL = szKey2[dwTemp];
			DL += AL;
			EDX = DL;
			AH = szKey2[EDX];
			szKey2[EDX] = AL;
			szKey2[dwTemp] = AH; 

			DH++;
		}

		memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE * sizeof(BYTE));
		if(!GetBuffer(dwTempOffset + 0x116, 0x3000, 0x3000))
			break;

		EDX = 0x01;
		BYTE BL = 0, CH = 0;

		for(dwTemp = 0; dwTemp < m_dwNoOfBytes; dwTemp++)
		{
			if(EDX > 0xFF)
				EDX = 0x00;

			if(dwTemp == 0xF0)
			{
				if(CheckSalityVSig())
				{
					eSalityGenType = SALITY_V;
					bRetStatus = TRUE;
					return bRetStatus;
				}
			}

			BL += szKey2[EDX];
			AL = szKey2[EDX];
			CH = szKey2[BL];
			szKey2[BL] = AL;
			szKey2[EDX] = CH;
			AL += CH;
			AL = szKey2[AL];
			m_pbyBuff[dwTemp] ^= AL;
			
			EDX++;
		}
		
		if(CheckSalityAASig())
		{
			eSalityGenType = SALITY_AA;
			break;
		}
		if(CheckSalityYSig())
		{
			eSalityGenType = SALITY_Y;
			break;
		}		
	}
	if(eSalityGenType != NO_VIRUS_FOUND)
		bRetStatus = TRUE;
	return bRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: SalityAA_DEC
	In Parameters	: 
	Out Parameters	: TRUE if sig Match else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: decryption routine for Sality.AA
--------------------------------------------------------------------------------------*/
BOOL CPolySality::SalityAA_DEC()
{
	BOOL bRetStatus = FALSE;
	int iRetStatus = REPAIR_FAILED;

	DWORD dwOffVirus	= m_SalityParam.m_dwLastSecJumpOffset;
	DWORD dwMode		= m_SalityParam.m_SalityAAParam.dwType;
	DWORD dwKey			= m_SalityParam.m_SalityAAParam.dwKey;
	DWORD dwTempOffset	= dwOffVirus + 0x1000;
		
	DWORD dwTemp = 0;
	BYTE szKey1[0x16]= {0}, szKey2[0x100] = {0};
	for(int iCnt = 0; iCnt < 2; iCnt++)
	{
		if(!m_pMaxPEFile->ReadBuffer(szKey1, dwTempOffset, 0x16, 0x16))
		{
			return iRetStatus;
		}

		if(dwMode)
		{
			for(int iOffset = 0; iOffset <(iCnt + 1); iOffset++)
			{
				switch(dwMode)
				{
				case 1:
					*((DWORD *)&szKey1[iOffset*4])+= dwKey;
					break;

				case 2:
					*((DWORD *)&szKey1[iOffset*4])-= dwKey;
					break;

				case 3:
					*((DWORD *)&szKey1[iOffset*4])^= dwKey;
					break;
				}
			}
		}

		DWORD	EDX = 0;
		BYTE	AL = 0, AH = 0, DL = 0, DH = 0;
		for(int iOffset = 0x03; iOffset < 0x16; iOffset++)
		{
			for(dwTemp = 0; dwTemp < 0x100; dwTemp++)
				szKey2[dwTemp] =(unsigned char)dwTemp;

			DL = DH = 0;
			for(dwTemp = 0; dwTemp < 0x100; dwTemp++)
			{
				if(DH > iOffset)
					DH = 0x00;

				DL += szKey1[DH];
				AL = szKey2[dwTemp];
				DL += AL;
				EDX = DL;
				AH = szKey2[EDX];
				szKey2[EDX] = AL;
				szKey2[dwTemp] = AH;

				DH++;
			}

			memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
			if(!GetBuffer(dwTempOffset + 0x116, 0x3000, 0x3000))
				return iRetStatus;

			EDX = 0x01;
			BYTE BL = 0, CH = 0;
			for(dwTemp = 0; dwTemp < m_dwNoOfBytes; dwTemp++)
			{
				if(EDX > 0xFF)
					EDX = 0x00;

				BL += szKey2[EDX];
				AL = szKey2[EDX];
				CH = szKey2[BL];
				szKey2[BL] = AL;
				szKey2[EDX] = CH;
				AL += CH;
				AL = szKey2[AL];
				m_pbyBuff[dwTemp] ^= AL;
				
				EDX++;
			}
			
			if(CheckSalityAASig())
			{
				eSalityGenType = SALITY_AA;
				break;
			}
			if(CheckSalityYSig())
			{
				eSalityGenType = SALITY_Y;
				break;
			}
			if(CheckSalityVSig())
			{
				eSalityGenType = SALITY_V;
				break;
			}
			if(CheckForValidDecryption())
			{
				eSalityGenType = SALITY_AA_DEC_ZERO;
				break;
			}
		}
		if(eSalityGenType != NO_VIRUS_FOUND)
		{
			bRetStatus = TRUE;
			break;
		}
	}
	return bRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSalityVCounterAndOffset
	In Parameters	: 
	Out Parameters	: TRUE if sig Match else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get infection code size of offset for Sality.V 
--------------------------------------------------------------------------------------*/
BOOL CPolySality::GetSalityVCounterAndOffset()
{
	DWORD dwCounter = 0x00;
	DWORD dwOffset = 0x00;
	dwCounter = *((DWORD*)&m_pbyBuff[0x32]);
	dwOffset = 0x1916 - 0x1116;
	if(RepairSalityGen(dwCounter, dwOffset))
		return TRUE;

	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSalityYCounterAndOffset
	In Parameters	: 
	Out Parameters	: TRUE if sig Match else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get infection code size of offset for Sality.Y 
--------------------------------------------------------------------------------------*/
BOOL CPolySality::GetSalityYCounterAndOffset()
{
	DWORD dwCounter = 0x00;
	DWORD dwOffset = 0x00;
	for(dwOffset = 0x7CD; dwOffset < 0x7E0; dwOffset++)
	{
		if(m_pbyBuff[dwOffset]==0x00 && m_pbyBuff[dwOffset + 1]==0x00 && m_pbyBuff[dwOffset + 2]==0x01)
		{
			dwCounter = *((DWORD *)&m_pbyBuff[dwOffset + 0x03]);
			break;
		}
	}

	if(dwOffset >= 0x7E0 || dwCounter > 0x300)
	{
		return FALSE;
	}
	dwOffset = dwOffset + 0x03 + 0x04;
	if(RepairSalityGen(dwCounter, dwOffset))
		return TRUE;

	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSalityAACounterAndOffset
	In Parameters	: 
	Out Parameters	: TRUE if sig Match else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get infection code size of offset for Sality.AA 
--------------------------------------------------------------------------------------*/
BOOL CPolySality::GetSalityAACounterAndOffset()
{
	
	BYTE bTempSign1[] = {0x00, 0x00, 0x28, 0x00, 0x00, 0x00};
	BYTE bTempSign2[] = {0x00, 0x00, 0x28, 0x11, 0x00, 0x00};   
	BYTE bTempSign[] = {0x49, 0x85, 0xC9, 0x74, 0x15, 0x41, 0x81, 0xF1};
	DWORD dwXorKey = 0;
	int nVirusFound = 0, i = 0;
	DWORD dwTemp = 0x1600;
	DWORD dwTempOffset = 0x00;

	DWORD dwCounter = 0x00;
	DWORD dwOffset = 0x00;

	if(memcmp(&m_pbyBuff[0x6D8],bTempSign,8)== 0)
	{
		dwXorKey = *(DWORD *)&m_pbyBuff[0x6E0];
	}
	if(dwXorKey)
	{
		dwCounter = *(DWORD *)&m_pbyBuff[0x1774] ^ dwXorKey;
	}
	else if(*(DWORD *)&m_pbyBuff[0x1770] == 0x01000000)
	{
		dwCounter = *(DWORD *)&m_pbyBuff[0x1774];
	}
	
	BOOL	bSecMarkerFound = FALSE;  
	DWORD	dwAlternateCntr = 0x00, dwAlternateOffSet = 0x00;
	if(dwCounter < 0x10 || dwCounter > 0x300)
	{
		for(dwOffset = 0x1250; dwOffset < dwTemp; dwOffset++)
		{
			if((memcmp(&m_pbyBuff[dwOffset], bTempSign1, 0x06)== 0 ))
			{
				dwTempOffset = dwOffset;
				//dwTemp = dwOffset + 0x100 + 0x06;
				dwOffset += 0x06;
				nVirusFound += 0x01;
				if(nVirusFound == 0x02)
				{
					dwOffset = dwTempOffset + 0x06 + 0x2C + 0x04;
					dwCounter = *((DWORD *)&m_pbyBuff[dwTempOffset + 0x06 + 0x2C]);
					break;
				}
				else if (bSecMarkerFound == TRUE)
				{
					dwAlternateOffSet = dwTempOffset + 0x06 + 0x2C + 0x04;
					dwAlternateCntr = *((DWORD *)&m_pbyBuff[dwTempOffset + 0x06 + 0x2C]);
				}
			}
			if(((memcmp(&m_pbyBuff[dwOffset], bTempSign2, 0x06)== 0)))
			{
				dwTempOffset = dwOffset;
				//dwTemp = dwOffset + 0x100 + 0x06;
				dwOffset += 0x06;
				if (nVirusFound == 1)
				{
					dwOffset = dwTempOffset + 0x06 + 0x2C + 0x04;
					dwCounter = *((DWORD *)&m_pbyBuff[dwTempOffset + 0x06 + 0x2C]);
					break;
				}
				else
					bSecMarkerFound = TRUE;
			}
		}
		if (nVirusFound == 0x01 && bSecMarkerFound == TRUE)
		{
			dwOffset = dwAlternateOffSet;
			dwCounter = dwAlternateCntr;
		}
		if(dwOffset >= dwTemp && nVirusFound == 0x00)
		{	
			return FALSE;
		}

	}
	
	if(dwCounter > 0x300)
	{
		return FALSE;
	}
	if(!dwOffset)
	dwOffset = 0x1778;

	if(RepairSalityGen(dwCounter, dwOffset))
		return TRUE;

	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSalityAADECCounterAndOffset
	In Parameters	: 
	Out Parameters	: TRUE if sig Match else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get infection code size of offset for Sality.D, Sality.E 
--------------------------------------------------------------------------------------*/
BOOL CPolySality::GetSalityAADECCounterAndOffset()
{
	DWORD dwTemp = CheckForValidDecryption();
	DWORD dwCounter = *((DWORD *)&m_pbyBuff[dwTemp+ 0x06 + 0x2C]);
	if(dwCounter > 0x300)
	{
		return FALSE;
	}
	DWORD dwOffset = dwTemp + 0x06 + 0x2C + 0x04;	
	if(RepairSalityGen(dwCounter, dwOffset))
		return TRUE;

	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanSalityGen
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Sality Family
--------------------------------------------------------------------------------------*/
int CPolySality::CleanSalityGen()
{
	int iRetStatus = REPAIR_FAILED;
		
	switch(eSalityGenType)
	{
	case SALITY_AA:
		if(GetSalityAACounterAndOffset())
			iRetStatus = REPAIR_SUCCESS;
		else
		{
			m_pMaxPEFile->CloseFile_NoMemberReset();
			DeleteFile(m_pMaxPEFile->m_szFilePath);
			iRetStatus = REPAIR_SUCCESS;
		}
		break;
	case SALITY_AA_DEC_ZERO:
		if(GetSalityAADECCounterAndOffset())
			iRetStatus = REPAIR_SUCCESS;
		break;
	case SALITY_V:
		if(GetSalityVCounterAndOffset())
			iRetStatus = REPAIR_SUCCESS;
		break;
	case SALITY_Y:
		if(GetSalityYCounterAndOffset())
			iRetStatus = REPAIR_SUCCESS;
		break;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: RepairSalityGen
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Sality Family
--------------------------------------------------------------------------------------*/
int CPolySality::RepairSalityGen(DWORD dwCounter, DWORD dwOffset)
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwOffset], m_dwAEPMapped, dwCounter, dwCounter))
	{
		if(m_pMaxPEFile->WriteAEP(m_dwAEPUnmapped))//....... added by mangesh
		{
			iRetStatus = RemoveSalityVirusCode();
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSalityEx
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for : Sality.EX
--------------------------------------------------------------------------------------*/
int CPolySality::DetectSalityEx()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wAEPSec == m_wNoOfSections - 1 || m_wAEPSec == m_wNoOfSections - 2)&& (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL)  != IMAGE_FILE_DLL &&
		m_pSectionHeader[m_wAEPSec].SizeOfRawData <= SALITY_BUFFER_SIZE)
	{
		t_disasm da;
		DWORD dwLength, dwOffset;
		dwLength = dwOffset = 0;
		m_dwInstCount = 0;
		int iFlag = 0;
		//int iIndex = 0;
		m_iIndex = 0;

 		memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
		if(!GetBuffer(m_dwAEPMapped, m_pSectionHeader[m_wAEPSec].SizeOfRawData, m_pSectionHeader[m_wAEPSec].SizeOfRawData))
		{
			return iRetStatus;
		}
		while(dwOffset < m_dwNoOfBytes)
		{	
			dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20,0x400000, &da, DISASM_CODE);
			if(m_pbyBuff[dwOffset] == 0xC3 && dwLength == 0x01)
			{
				break;
			}
			if(strstr(da.result, "???"))
			{
				return iRetStatus;
			}
			if(dwLength == 0x05 && strstr(da.result,"PUSH ") && iFlag == 0)
			{
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(*((DWORD*)&m_pbyBuff[dwOffset+1]) - m_dwImageBase, NULL))
				{
					m_dwSalityExAEP = *((DWORD*)&m_pbyBuff[dwOffset+1]) - m_dwImageBase ;
					iFlag = 1;
					m_dwInstCount++;
				}
			}
			if(dwLength == 0x05 && strstr(da.result, "MOV ") && *((DWORD*)&m_pbyBuff[dwOffset+1]) > m_dwImageBase)
			{
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset( *((DWORD*)&m_pbyBuff[dwOffset+1]) - m_dwImageBase,
											&m_objStructSalityExParams[m_iIndex].dwStartOffset))
				{
					m_dwInstCount++;
					return iRetStatus;
				}
			}
			if(dwLength == 0x05 && strstr(da.result, "CMP ") && *((DWORD*)&m_pbyBuff[dwOffset+1]) > m_dwImageBase)
			{
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset( *((DWORD*)&m_pbyBuff[dwOffset+1]) - m_dwImageBase, 
					&m_objStructSalityExParams[m_iIndex].dwSize))
				{
					m_objStructSalityExParams[m_iIndex].dwSize -= m_objStructSalityExParams[m_iIndex].dwStartOffset;
					m_dwInstCount++;
				}
			}
			if(dwLength == 0x03 && strstr(da.result, "XOR BYTE PTR [E"))
			{
				m_objStructSalityExParams[m_iIndex].byDecKey = m_pbyBuff[dwOffset+2];
				m_objStructSalityExParams[m_iIndex].dwType = 1;
				m_iIndex++;
			}
			dwOffset+=dwLength;
		}
		if(m_iIndex >= 2 && m_dwInstCount >= 3)
		{
			m_dwSalityType	=  VIRUS_SALITY_EX;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality"));		
			iRetStatus = VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanSalityEx
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for : Sality.EX 
--------------------------------------------------------------------------------------*/
int CPolySality::CleanSalityEx()
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pbyBuff != NULL)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
	for(int i = 0; i < m_iIndex; i++)
	{
		m_pMaxPEFile->CopyData(m_objStructSalityExParams[i].dwStartOffset, 
			m_objStructSalityExParams[i].dwStartOffset,
			m_objStructSalityExParams[i].dwSize, 
			1, 
			(DWORD)m_objStructSalityExParams[i].byDecKey);
	}
	
	m_pMaxPEFile->WriteAEP(m_dwSalityExAEP);
	
	if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckPushAndRet
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Finds the PUSH and RET Instruction
--------------------------------------------------------------------------------------*/
void CPolySality::CheckPushAndRet()
{
	DWORD dwTempRVA = 0;
	if(m_pbyBuff[0] == 0x68 && m_pbyBuff[5] == 0xC3)
	{
		dwTempRVA = (*((DWORD*)&m_pbyBuff[1]))- m_dwImageBase;		
	}
	else if(m_pbyBuff[0] == 0xE9)
	{
		dwTempRVA = (*((DWORD*)&m_pbyBuff[1])) + m_dwAEPUnmapped + 5;
	}
	else
	{
		return;
	}
	DWORD dwTempOffset = 0;
	WORD wSec = m_pMaxPEFile->Rva2FileOffset(dwTempRVA, &dwTempOffset);
	if(OUT_OF_FILE != wSec)
	{		
		m_dwbufferReadRVA = m_dwAEPUnmapped	= dwTempRVA;
		m_dwAEPMapped = dwTempOffset;
		m_wAEPSec = wSec;
		GetBuffer(m_dwAEPMapped, AEP_PATCHED_BUFFER_SIZE, 0x300);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: GetOriByteReplacementOff
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Finds fileoffset of original bytes that are patched by Virus
--------------------------------------------------------------------------------------*/
void CPolySality::GetOriByteReplacementOff()
{
	t_disasm da = {0};
	DWORD	dwLength = 0, dwOffset = 0;
	DWORD	dwnoInst = 0;
	
	while(dwnoInst < 10)
	{
		dwnoInst++;
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
		
		if(dwLength == 0x05 && strstr(da.result, "SUB E")  && da.immconst < m_dwImageBase)
		{
			m_dwOriByteReplacementOff = m_SalityParam.m_dwVirusRVA + 0x1116 + 5 - da.immconst;
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriByteReplacementOff, &m_dwOriByteReplacementOff))
			{
				m_dwOriByteReplacementOff = m_dwAEPMapped;
			}
			break;
		}
		dwOffset+=dwLength;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSalityStub
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + MAngesh Fasale + Virus Analysis Team
	Description		: Detection of Sality.Stub
--------------------------------------------------------------------------------------*/
int CPolySality::DetectSalityStub()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_wAEPSec == 0 && m_pSectionHeader[0].SizeOfRawData != 0 && (memcmp(m_pSectionHeader[0].Name, "UPX0", 4) == 0))||
		((m_wNoOfSections == 3 || m_wNoOfSections == 7 || m_wNoOfSections == 6/* only added no of section chk for some samples of sality.ag*/) && m_pSectionHeader[0].SizeOfRawData != 0 && (memcmp(m_pSectionHeader[m_wNoOfSections - 2].Name, ".CRT", 4) == 0)) ||
		(_tcsstr(m_pMaxPEFile->m_szFilePath, L".tmp") && (m_wNoOfSections == 7 || m_wNoOfSections == 6) && (memcmp(m_pSectionHeader[3].Name, ".data", 5) == 0)))//for unpacked files
	{		
		DWORD dwReadOffset = 0;
		if((memcmp(m_pSectionHeader[0].Name, "UPX0", 4) == 0) || (memcmp(m_pSectionHeader[m_wNoOfSections - 2].Name, ".CRT", 4) == 0))
		{
			dwReadOffset = m_pSectionHeader[0].PointerToRawData + 0xE50;  //sality.aa unpacked in 1st section. & sality.bj
			if(CheckSalityStubSig(dwReadOffset))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.aa"));
				return VIRUS_FILE_DELETE;
			}

			dwReadOffset = m_pSectionHeader[1].PointerToRawData; ////sality.ag unpacked in 1st section.
			if(CheckSalityStubSig(dwReadOffset))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.ag"));
				return VIRUS_FILE_DELETE;
			}
			else
			{
				dwReadOffset = m_pSectionHeader[3].PointerToRawData + 0xC60; //sality.aa unpacked properly.
				if(CheckSalityStubSig(dwReadOffset))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.aa"));
					return VIRUS_FILE_DELETE;
				}
			}
		}
		if (m_wNoOfSections == 6)
		{
			dwReadOffset = m_pSectionHeader[3].PointerToRawData + 0x1000;//sality.ag unpacked properly.
			if(CheckSalityStubSig(dwReadOffset))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.ag"));
				return VIRUS_FILE_DELETE;
			}
		}

	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckSalityStubSig
	In Parameters	: 
	Out Parameters	: TRUE if sig match else FALSE
	Purpose			: 
	Author			: Tushar Kadam + Mangesh Fasale + Virus Analysis Team
	Description		: Detection of Sality.Stub
--------------------------------------------------------------------------------------*/
BOOL CPolySality :: CheckSalityStubSig(DWORD dwReadOffset)
{
	const int SALITY_BUFF_SIZE = 0x200;
	if(GetBuffer(dwReadOffset, SALITY_BUFF_SIZE, SALITY_BUFF_SIZE))
	{
		const BYTE bSig[] = {0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6B, 0x75, 0x6B, 0x75, 0x74, 0x72, 0x75, 0x73, 0x74, 0x6E, 0x65, 0x74, 0x37, 0x37,
			0x37, 0x2E, 0x69, 0x6E, 0x66, 0x6F, 0x2F, 0x68, 0x6F, 0x6D, 0x65, 0x2E, 0x67, 0x69, 0x66, 0x00, 0x68, 0x74, 0x74, 0x70, 0x3A, 
			0x2F, 0x2F, 0x6B, 0x75, 0x6B, 0x75, 0x74, 0x72, 0x75, 0x73, 0x74, 0x6E, 0x65, 0x74, 0x38, 0x38, 0x38, 0x2E, 0x69, 0x6E, 0x66,
			0x6F, 0x2F, 0x68, 0x6F, 0x6D, 0x65, 0x2E, 0x67, 0x69, 0x66, 0x00, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6B, 0x75, 0x6B,
			0x75, 0x74, 0x72, 0x75, 0x73, 0x74, 0x6E, 0x65, 0x74, 0x39, 0x38, 0x37};

		for(DWORD dwIndex = 0; dwIndex < SALITY_BUFF_SIZE - sizeof(bSig); dwIndex++)
		{
			if(memcmp(&m_pbyBuff[dwIndex], bSig, sizeof(bSig)) == 0)
			{
				return true;
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSalityDriver
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Mangesh Fasale + Virus Analysis Team
	Description		: Detection of Sality file system driver
--------------------------------------------------------------------------------------*/
int CPolySality::DetectSalityDriver()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->m_stPEHeader.Subsystem == 0x01 && m_dwAEPUnmapped < 0x800 &&
		m_pSectionHeader[m_wAEPSec].SizeOfRawData < 0xA00 && m_pSectionHeader[0x02].SizeOfRawData <= 0x200)
	{		
		DWORD dwBuffReadOffet = 0x00;
		BYTE bDecKey = 0x00;
		BYTE bBeforeDec[0x08];
		BYTE bAftDec[] = {0x65,0x73,0x65,0x74,0x2E,0x63,0x6F,0x6D}; //eset.com
		if(!m_pMaxPEFile->ReadBuffer(&dwBuffReadOffet, m_pSectionHeader[2].PointerToRawData, 0x04, 0x04))
		{
			return iRetStatus;
		}
		dwBuffReadOffet = dwBuffReadOffet - m_pMaxPEFile->m_stPEHeader.ImageBase;
		if(!m_pMaxPEFile->ReadBuffer(&bBeforeDec, dwBuffReadOffet - 0x0C, 0x08, 0x08))
		{
			return iRetStatus;
		}
		bDecKey = bBeforeDec[0] ^ bAftDec[0];
		for(int i = 0; i < 0x08; i++)
		{
			bBeforeDec[i] = bBeforeDec[i] ^ bDecKey;
		}
		if(memcmp(bAftDec, bBeforeDec, sizeof(bAftDec)) == 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sality.drv.a"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DeleteDeadCodeSamples
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sandeep Voyasa + Virus Analysis Team
	Description		: Detection of Dead code (execution pointer is not goining in this code)
--------------------------------------------------------------------------------------*/
int CPolySality::DeleteDeadCodeSamples()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	m_wNoOfSections = m_pMaxPEFile->m_stPEHeader.NumberOfSections;
	if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData < 0x10000 ||
		(m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL ||
		(m_wNoOfSections <= 0x02) ||
		(m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0x20000000) != 0x20000000)
	{
		return iRetStatus;
	}
	//Find starting of Sality code
	bool	bDeadCode = true;
	BYTE	byZeros[0x20]	= {0x00};
	BYTE	byZlib[0x4]		= {0x7A, 0x6C, 0x62};
	BYTE	byRar[0x4]		= {0x52, 0x61, 0x72};
	BYTE	byFFS[0x4]		= {0x46, 0x46, 0x53, 0x21};
	BYTE	byPadding[0x09]	= {0x50, 0x41, 0x44, 0x44, 0x49, 0x4E, 0x47, 0x58, 0x58};
	DWORD	dwIndex			= 0x00;
	DWORD	dwReadOff		= m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
	DWORD	dwSubOffset		= m_pMaxPEFile->m_stPEHeader.FileAlignment + 0x20;
	DWORD	dwLastSecSize	= m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
//	memset(byZeros, 0x00, 0x20);
	memset(m_pbyBuff, 0x00, SALITY_BUFFER_SIZE);
	
	if((strstr((const char *)m_pSectionHeader[m_wNoOfSections - 1].Name, (const char *)m_pSectionHeader[1].Name)))
	{
		if(memcmp(m_pSectionHeader[1].Name, byZeros, 0x08) == 0x00)
		{
			return iRetStatus;
		}

		m_SalityParam.m_dwLastSecJumpOffset = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
		if((dwLastSecSize - m_SalityParam.m_dwLastSecJumpOffset) < 0x10000)
		{
			return iRetStatus;	//return false if last section data fill with zeros
		}

		iRetStatus = DetectSalityAA(bDeadCode);
		if(iRetStatus)
		{
			return VIRUS_FILE_DELETE;
		}
		return iRetStatus;
	}
	for(dwReadOff; dwReadOff >= m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + dwSubOffset; dwReadOff-=m_pMaxPEFile->m_stPEHeader.FileAlignment)
	{
		/*if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwReadOff - dwSubOffset, 0x20, 0x20))
		{
			return iRetStatus;
		}*/
		if(!GetBuffer(dwReadOff - dwSubOffset, 0x20, 0x20))
		{
			return iRetStatus;
		}
		if((memcmp(m_pbyBuff, byZeros, 0x20) == 0x00))
		{
			m_SalityParam.m_dwLastSecJumpOffset = dwReadOff - m_pMaxPEFile->m_stPEHeader.FileAlignment;
			if((dwLastSecSize - m_SalityParam.m_dwLastSecJumpOffset) < 0x10000)
			{
				return iRetStatus;	//return false if last section data fill with zeros
			}

			memset(m_pbyBuff, 0x00, 0x20);
			if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, 0x1000, 0x00))
			{
				return iRetStatus;
			}
			
			if((OffSetBasedSignature(byZeros, 0x06, &dwIndex)) || (OffSetBasedSignature(byRar, 0x03, &dwIndex)) || (OffSetBasedSignature(byZlib, 0x03, &dwIndex)) ||
				(OffSetBasedSignature(byFFS, 0x04, &dwIndex)))
			{
				return iRetStatus;
			}

			iRetStatus = DetectSalityAA(bDeadCode);
			if(iRetStatus)
			{
				return VIRUS_FILE_DELETE;
			}
			break;
		}
		if(OffSetBasedSignature(byPadding, 0x09, &dwIndex))
		{
			m_SalityParam.m_dwLastSecJumpOffset = dwReadOff - m_pMaxPEFile->m_stPEHeader.FileAlignment ;
			if((dwLastSecSize - m_SalityParam.m_dwLastSecJumpOffset) < 0x10000)
			{
				return iRetStatus;	//return false if last section data fill with PADDING
			}
			
			memset(m_pbyBuff, 0x00, 0x20);
			if(!GetBuffer(m_SalityParam.m_dwLastSecJumpOffset, 0x1000, 0x00))
			{
				return iRetStatus;
			}
			
			if((OffSetBasedSignature(byZeros, 0x06, &dwIndex)) || (OffSetBasedSignature(byRar, 0x03, &dwIndex)) || (OffSetBasedSignature(byZlib, 0x03, &dwIndex)) ||
				(OffSetBasedSignature(byFFS, 0x04, &dwIndex)))
			{
				return iRetStatus;
			}

			iRetStatus = DetectSalityAA(bDeadCode);
			if(iRetStatus)
			{
				return VIRUS_FILE_DELETE;
			}
			break;
		}
	}
	return iRetStatus;
}
