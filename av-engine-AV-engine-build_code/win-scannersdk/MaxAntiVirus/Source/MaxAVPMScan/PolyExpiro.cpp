/*======================================================================================
FILE				: PolyExpiro.cpp
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
NOTES				: This is detection module for malware Expiro Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyExpiro.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyExpiro
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyExpiro::CPolyExpiro(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_dwOAEPExpiro = 0;
	m_pbyBuff = new BYTE[EXPIRO_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	m_iExpiroType = 0;
	m_bDelFlag = false;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyExpiro
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyExpiro::~CPolyExpiro(void)
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
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Detection routine for different varients of Expiro Family
					  1. Normal Infection With Negative Jump to OAEP.
					  2. New infection Patch at Original Address of Entry Point.
--------------------------------------------------------------------------------------*/
int CPolyExpiro::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	//Detection for Virus.Expiro.AR & Virus.Expiro.NR

	
	//added
	//if ((m_wAEPSec == 0x00 && m_pSectionHeader[m_wNoOfSections -1].SizeOfRawData > 0x500 && (m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000000) == 0xE0000000) || (m_wAEPSec == 0x00 && m_pSectionHeader[m_wNoOfSections -1].SizeOfRawData > 0x500 && (m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0x40000000) == 0x40000000)) //Added 06 Sep 2018
	/*
	//REMOVED : Virus Total False (+)ve
	if(m_wAEPSec == 0x00 && (m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000000) == 0xE0000000 && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > 0x500) //Added 11 Sep
	{
		t_disasm	da;
		DWORD		dwCMPOffset = 0, dwLength = 0, dwBuffSize = 0x10000, dwLastSecOffset = 0, dwTempOffset = 0;   
		int iMov =0, iLea = 0, iMul = 0, iAdd = 0, iXOR = 0, iSec = 0;

		for(DWORD dwOffset = 0; dwOffset < (0x400 - MAX_INSTRUCTION_LEN);)
		{
			memset(&da, 0x00, sizeof(struct t_disasm));
			dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);

			if((dwLength == 0x7 || dwLength == 0x5) && (strstr(da.result, "MOV")))
			{
				if(dwLength == 0x5 && (da.immconst > m_dwImageBase))
				{
					dwLastSecOffset = da.immconst;
					dwTempOffset = dwOffset;
				}
				iMov++;
			}
			else if(dwLength == 0x6 && (strstr(da.result, "LEA")))
			{
				iLea++;
			}
			else if(dwLength == 0x3 && (strstr(da.result, "MUL")))
			{
				iMul++;
			}
			else if(strstr(da.result,"XOR"))
			{
				iXOR++;
			}
			else if(strstr(da.result,"ADD"))
			{
				if(dwLength == 0x6 && (da.immconst > m_dwImageBase))
				{
					dwLastSecOffset = da.immconst;
					dwTempOffset = dwOffset;
				}
				iAdd++;
			}
			else if(dwLength == 0x3 && strstr(da.result,"CMP E"))
			{
				dwCMPOffset = dwOffset;
			}
			else if(((iMov >= 2 || iLea >= 2) && iMul >= 1 && iAdd >= 1 && iXOR >= 1) && dwLength == 1 && m_pbyBuff[dwOffset] == 0xC3 &&
				((dwOffset - dwCMPOffset) > 0xA) && ((dwOffset - dwTempOffset) < 0x20))
			{
				iSec = m_pMaxPEFile->Rva2FileOffset(dwLastSecOffset - m_dwImageBase,&dwLastSecOffset);
				if((iSec > 0) || (dwLastSecOffset > m_pMaxPEFile->m_dwFileSize))
				{
					m_dwPatchSize = dwOffset+1;
					m_iExpiroType = 3;
					if(m_pMaxPEFile->m_dwFileSize < (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Expiro.AR"));
						return VIRUS_FILE_DELETE;
					}
					//-----------------To get original Size of last section---------------
					if(m_pbyBuff)
					{
						delete []m_pbyBuff;
						m_pbyBuff =NULL;
					}

					if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData < 0x10000)
						dwBuffSize = m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;

					m_pbyBuff = new BYTE[dwBuffSize];
					if(!GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - dwBuffSize, dwBuffSize, dwBuffSize))
					{
						return VIRUS_NOT_FOUND;
					}
					DWORD i = dwBuffSize -1;
					for(i = dwBuffSize -1; i >= 0; i--)
					{
						if(m_pbyBuff[i] != 0)
						{
							if(m_pbyBuff[i - 0x1] == 0)
							{
								m_dwOAEPExpiro = *(DWORD *)&m_pbyBuff[i - 0x4];
							}
							break;
						}
					}
					//----------------------End----------------------------
					if(m_dwOAEPExpiro == 0)
						return VIRUS_NOT_FOUND;

					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Expiro.AR")); //Added 06 Sep 2018
					if((m_dwOAEPExpiro > m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData) || (i == dwBuffSize - 1)) 
						return VIRUS_FILE_DELETE;
					m_dwOAEPExpiro = m_dwOAEPExpiro + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
					return VIRUS_FILE_REPAIR;
				}
				else
					return iRetStatus;
			}
			dwOffset+=dwLength;
		}
	}
	//}
	*/
//Added Sagar
/*
	if (CheckSigInBuffer(m_dwAEPMapped,0x10,_T("605589E581*EC08010000")))
	{

		t_disasm	da;
		DWORD		dwCMPOffset = 0, dwLength = 0, dwBuffSize = 0x10000, dwLastSecOffset = 0, dwTempOffset = 0;   
		int iMov =0, iLea = 0, iMul = 0, iAdd = 0, iXOR = 0, iSec = 0;

		for(DWORD dwOffset = 0; dwOffset < (0x400 - MAX_INSTRUCTION_LEN);)
		{
			memset(&da, 0x00, sizeof(struct t_disasm));
			dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);

			if((dwLength == 0x7 || dwLength == 0x5) && (strstr(da.result, "MOV")))
			{
				if(dwLength == 0x5 && (da.immconst > m_dwImageBase))
				{
					dwLastSecOffset = da.immconst;
					dwTempOffset = dwOffset;
				}
				iMov++;
			}
			else if(dwLength == 0x6 && (strstr(da.result, "LEA")))
			{
				iLea++;
			}
			else if(dwLength == 0x3 && (strstr(da.result, "MUL")))
			{
				iMul++;
			}
			else if(strstr(da.result,"XOR"))
			{
				iXOR++;
			}
			else if(strstr(da.result,"ADD"))
			{
				if(dwLength == 0x6 && (da.immconst > m_dwImageBase))
				{
					dwLastSecOffset = da.immconst;
					dwTempOffset = dwOffset;
				}
				iAdd++;
			}
			else if(dwLength == 0x3 && strstr(da.result,"CMP E"))
			{
				dwCMPOffset = dwOffset;
			}
			else if(((iMov >= 2 || iLea >= 2) && iMul >= 1 && iAdd >= 1 && iXOR >= 1) && dwLength == 1 && m_pbyBuff[dwOffset] == 0xC3 &&
				((dwOffset - dwCMPOffset) > 0xA) && ((dwOffset - dwTempOffset) < 0x20))
			{

				iSec = m_pMaxPEFile->Rva2FileOffset(dwLastSecOffset - m_dwImageBase,&dwLastSecOffset);
				if((iSec > 0) || (dwLastSecOffset > m_pMaxPEFile->m_dwFileSize))
				{
					if (CheckSigInBuffer(m_dwAEPMapped,0x40,_T("605589E581EC08010000C745E40C000000*C745F80E000000C745CC04000000C745*F403000000C745B4080000008B45CC83")))
					{
						m_dwPatchSize = dwOffset+1;
						m_iExpiroType = 3;
						if(m_pMaxPEFile->m_dwFileSize < (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Expiro.AR"));
							return VIRUS_FILE_DELETE;
						}
						//-----------------To get original Size of last section---------------
						if(m_pbyBuff)
						{
							delete []m_pbyBuff;
							m_pbyBuff =NULL;
						}

						if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData < 0x10000)
							dwBuffSize = m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;

						m_pbyBuff = new BYTE[dwBuffSize];
						if(!GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - dwBuffSize, dwBuffSize, dwBuffSize))
						{
							return VIRUS_NOT_FOUND;
						}
						DWORD i = dwBuffSize -1;
						for(i = dwBuffSize -1; i >= 0; i--)
						{
							if(m_pbyBuff[i] != 0)
							{
								if(m_pbyBuff[i - 0x1] == 0)
								{
									m_dwOAEPExpiro = *(DWORD *)&m_pbyBuff[i - 0x4];
								}
								break;
							}
						}
						//----------------------End----------------------------
						if(m_dwOAEPExpiro == 0)
							return VIRUS_NOT_FOUND;

						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Expiro.AR")); //Added 06 Sep 2018
						if((m_dwOAEPExpiro > m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData) || (i == dwBuffSize - 1)) 
							return VIRUS_FILE_DELETE;
						m_dwOAEPExpiro = m_dwOAEPExpiro + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
						return VIRUS_FILE_REPAIR;
					}
				}
				else
					return iRetStatus;
			}
			dwOffset+=dwLength;
		}
	}
	*/
	if(m_pMaxPEFile->m_dwFileSize > 0x800)
	{
		if(!GetBuffer(0x00,0x400,0x400))
		{
			return iRetStatus;
		}
		BYTE byENDBuffer[0x400] = {0x00};
		m_pMaxPEFile->ReadBuffer(byENDBuffer,(m_pMaxPEFile->m_dwFileSize-0x400),0x400);
		
		if(byENDBuffer[0x00] == 0x4D &&  m_pbyBuff[0x00] == 0x4D)
		{
			if(memcmp(&byENDBuffer[0x00],&m_pbyBuff[0x00],0x100) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Expiro.Gen.7"));		
				return VIRUS_FILE_DELETE;

			}
		}
		
	}
	if(!GetBuffer(m_dwAEPMapped,0x400,0x400))
	{
		return iRetStatus;
	}

	if(m_dwAEPUnmapped == 0x16B4 && m_wNoOfSections == 4)
	{
		const BYTE bySignature[] = {0x44, 0x43, 0x49, 0x41, 0x43, 0x42, 0x46, 0x49, 0x4A, 0x48, 0x49, 0x46, 0x46, 0x42, 0x49, 0x47, 
			0x43, 0x41, 0x41, 0x47, 0x49, 0x44, 0x4A, 0x45, 0x42, 0x49, 0x47, 0x4A, 0x47, 0x43, 0x42, 0x46};
		if(GetBuffer(m_pSectionHeader[0].PointerToRawData, sizeof(bySignature), sizeof(bySignature)))
		{
			if(memcmp(m_pbyBuff, bySignature, sizeof(bySignature)) == 0)  
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Expiro.AB"));		
				return VIRUS_FILE_DELETE;
			}
		}
	}

	//First Type Expiro With Negative Jump to Original AEP
	if(m_wAEPSec != 0x00 && m_wNoOfSections >= 2 && m_dwAEPMapped == m_pSectionHeader[m_wAEPSec].PointerToRawData)
	{
		if(m_pMaxPEFile->m_byAEPBuff[0]==0x60 && (m_pMaxPEFile->m_byAEPBuff[1] == 0xE8 || m_pMaxPEFile->m_byAEPBuff[1] == 0x90))
		{
			int iJmpOffset = 0;
			for(iJmpOffset = 0; iJmpOffset < 6; iJmpOffset++)
			{			
				if(m_pMaxPEFile->m_byAEPBuff[iJmpOffset] == 0xE8)
					break;
			}
			if(iJmpOffset == 6)
			{
				return iRetStatus;
			}
			//First Level Detection At Address of Entry Point
			if(GetExpiroAEP())
			{
				DWORD dwCallOffset = *((DWORD *)&m_pMaxPEFile->m_byAEPBuff[iJmpOffset + 1]);
				dwCallOffset += (m_dwAEPUnmapped + iJmpOffset + 0x5);

				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwCallOffset, &dwCallOffset))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Expiro.Gen"));		
					if(dwCallOffset > m_pMaxPEFile->m_dwFileSize)
					{
						return  VIRUS_FILE_DELETE;
					}

					if(GetBuffer(dwCallOffset, 0x20))
					{
						int iPushCnt = 0;
						BYTE byZeros[0x20] = {0};
						//Second Level Detection at CALL offset 
						for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes; dwOffset++)
						{
							if(m_pbyBuff[dwOffset] == 0x50 || m_pbyBuff[dwOffset] == 0x51 || m_pbyBuff[dwOffset] == 0x52 || m_pbyBuff[dwOffset] == 0x53 ||
								m_pbyBuff[dwOffset] == 0x54 || m_pbyBuff[dwOffset] == 0x55 || m_pbyBuff[dwOffset] == 0x56 ||m_pbyBuff[dwOffset] == 0x57 )
							{
								iPushCnt++;
								if(iPushCnt == 3)
								{
									m_iExpiroType = 1;
									return  VIRUS_FILE_REPAIR;
								}
							}
							else if(!memcmp(m_pbyBuff, byZeros, sizeof(byZeros)))
							{
								m_iExpiroType = 1;
								return  VIRUS_FILE_REPAIR;
							}

						}
					}
				}
			}
		}
	}

	//Second Type Expiro Detection Virus Code execution, Patch at Original Address of entry Point  
	// Variants : Expiro.W, Expiro.Ai, Expiro.Ae, Expiro.AQ              ... added by mangesh
	if(m_wNoOfSections >= 0x02 && ((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000000) == 0xE0000000))
	{
		if(GetBuffer(m_dwAEPMapped, EXPIRO_BUFF_SIZE, 0x30)) 
		{
			if(CheckPushInstructions())
			{
				if(GetPatchSize())
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Expiro.W"));	
					if(m_bDelFlag)
					{
						return VIRUS_FILE_DELETE;
					}
					if(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData < m_pMaxPEFile->m_dwFileSize )
					{
						m_iExpiroType = 2;											
						return VIRUS_FILE_REPAIR;
					}	
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}

	if(m_wAEPSec == 0)
	{
		t_disasm	da;
		DWORD		dwCMPOffset = 0, dwLength = 0, dwBuffSize = 0x10000, dwLastSecOffset = 0, dwTempOffset = 0,dwCallFirst = 0, dwCallFirstOffset = 0,dwCallSecOffset = 0,dwVirtalCall = 0,dwEip = 0, dwValue = 0;   
		DWORD		dwSHORTJMP = 0,dwRetOffset = 0 ;
		BOOL		bFound  = false;
		int			iMov =0, iLea = 0, iMul = 0, iAdd = 0, iXOR = 0, iSec = 0, iInsCnt = 0;
		char		szRegister[5]={0}, szRegister1[5]={0}, szMOV[1024] = {0}; 

		for(DWORD dwOffset = 0; dwOffset < (0x400 - MAX_INSTRUCTION_LEN);)
		{
			memset(&da, 0x00, sizeof(struct t_disasm));
			dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	
			if(iInsCnt == 0x0 && dwLength == 0x5 && (strstr(da.result, "CALL")) )
			{
				dwTempOffset =  dwOffset + *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwLength;
				dwCallFirstOffset = dwOffset;
				dwCallFirst = dwTempOffset; 

				if(dwTempOffset - dwOffset < 0x30)
				{
					iInsCnt++;	
				}
			}
			else if(iInsCnt == 0x1 && dwLength == 0x5 && (strstr(da.result, "CALL")) )
			{
				dwTempOffset =  dwOffset + *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwLength;
				if(( dwOffset - dwCallFirstOffset  > 0x20) || dwCallFirst != dwTempOffset)
				{
					break;
				}
				dwCallSecOffset = dwOffset;
				iInsCnt++;
			}
			else if(iInsCnt == 0x2 && dwLength == 0x2  && (strstr(da.result,"JE SHORT") || strstr(da.result,"JNE SHORT") || strstr(da.result,"JNZ SHORT")))
			{
				dwSHORTJMP = dwOffset;
				iInsCnt++;
			}
			else if(iInsCnt == 0x3 && dwLength == 1 && strstr(da.result,"???"))//RETN
			{
				if(dwOffset > (dwCallFirst + 0x1A) && dwOffset < (dwCallFirst + 0x30))
				{
					bFound = true;
					dwRetOffset = dwOffset;
					dwOffset = dwCallSecOffset + 4;
					iInsCnt++;
				}
				else
					break;
			}
			else if(iInsCnt == 0x4 && dwLength == 2 && strstr(da.result,"MOV E") && bFound && (strstr(da.result, ",[EAX]")||strstr(da.result, ",[EBX]")||strstr(da.result, ",[ECX]")||strstr(da.result, ",[EDX]") || strstr(da.result, ",[ESI]") || strstr(da.result, ",[EDI]")))
			{
				/*
				if((dwOffset - dwCallSecOffset)< 0x13) 
				{
					CEmulate	objEmulate(m_pMaxPEFile);
					DWORD		dwRegVal=-1;
					int			iReg=-1;
					char		szInstruction[1024]={0};
					char		*ptr = NULL;

					if(!objEmulate.IntializeProcess())
					{
						break;
					}
					ptr = strstr(da.result, "MOV E");
					if(ptr)
					{
						ptr += strlen("MOV E")- 1;

						szRegister[0] = ptr[0];
						szRegister[1] = ptr[1];
						szRegister[2] = ptr[2];
						szRegister[3] = '\0';

						szRegister1[0] = ptr[5];
						szRegister1[1] = ptr[6];
						szRegister1[2] = ptr[7];
						szRegister1[3] = '\0';
					}

					sprintf_s(szMOV, 1024, "__isinstruction('MOV %s ,DWORD PTR [%s]')", szRegister,szRegister1);

					objEmulate.SetBreakPoint(szMOV);
					objEmulate.ActiveBreakPoint(0);
					objEmulate.SetNoOfIteration(0x4000);

					if(7!=objEmulate.EmulateFile())
					{
						break;
					}
					dwEip = objEmulate.GetEip();
					if(!strcmp(szRegister1,"EAX"))	iReg=0;
					else if(!strcmp(szRegister1,"ECX"))	iReg=1;
					else if(!strcmp(szRegister1,"EDX"))	iReg=2;
					else if(!strcmp(szRegister1,"EBX"))	iReg=3;
					else if(!strcmp(szRegister1,"ESI"))	iReg=6;
					else if(!strcmp(szRegister1,"EDI"))	iReg=7;
					if (-1==iReg)
						break;


					dwValue= objEmulate.GetSpecifyRegValue(iReg);
					if(dwValue < m_dwImageBase)
						dwValue = dwValue - 0x400;
					else
						dwValue = (dwValue - 0x400) - m_dwImageBase;

					if(0 == m_pMaxPEFile->Rva2FileOffset(dwEip- m_dwImageBase,&dwEip))
					{
						dwEip = dwEip - m_dwAEPMapped;
						if(dwEip == dwOffset)
						{
							iSec = m_pMaxPEFile->Rva2FileOffset(dwValue,&dwEip);
							if(m_wNoOfSections -1 ==  iSec)
							{
								dwOffset = dwRetOffset -1;
								iInsCnt++;
							}
						}
					}
				}
				else
					break;
					*/
					break;
			}
			else if(iInsCnt == 0x5 && dwLength == 1 && strstr(da.result,"???"))
			{
				m_dwPatchSize = dwOffset + 1;
				m_dwOAEPExpiro = dwValue - m_dwPatchSize;
				if(m_wNoOfSections-1 == m_pMaxPEFile->Rva2FileOffset(m_dwOAEPExpiro,&m_dwOAEPExpiro))
				{
					m_iExpiroType = 3;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Expiro.NS"));
					return VIRUS_FILE_REPAIR;
				}
				else 
					break;
			}
			else if(dwOffset > 0x250)
				break;

			dwOffset = dwOffset + dwLength;

		}
		return iRetStatus;
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetExpiroAEP
	In Parameters	: 
	Out Parameters	: true if Instruction match else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Expiro Family
--------------------------------------------------------------------------------------*/
bool CPolyExpiro::GetExpiroAEP()
{
	DWORD dwLen = 0, dwStart = 0, dwInsCount = 0;
	bool bCallSet = false, bPopSet = false, bPushSet = false;
	t_disasm da;

	//First Type of Infection Detection Negative Jump
	while(dwStart < 0x20)
	{
		dwLen = m_objMaxDisassem.Disasm((char* )&m_pMaxPEFile->m_byAEPBuff[dwStart], MAX_INSTRUCTION_LEN, m_dwImageBase + m_dwAEPUnmapped + dwStart, &da, DISASM_CODE);
		if(dwLen > (0x20 - dwStart))
		{
			return false;
		}
		dwStart += dwLen;
		if(strstr(da.result, "PUSHAD") && dwStart == 0x01)
		{
			bPushSet = true;
			continue;
		}
		else if(strstr(da.result, "NOP"))
		{
			continue;
		}
		else if(strstr(da.result, "POPAD"))
		{
			bPopSet = true;
			continue;
		}
		else if(strstr(da.result, "CALL ") && bCallSet == false && bPopSet == false && bPushSet)
		{
			bCallSet = true;
			continue;
		}
		else if(strstr(da.result, "JMP ") && bCallSet && bPopSet)
		{
			m_dwOAEPExpiro = da.jmpconst;
			return true;
		}
		else 
		{
			return false;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckPushInstructions
	In Parameters	: 
	Out Parameters	: true if Instruction match else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Finds PUSH instruction
--------------------------------------------------------------------------------------*/
bool CPolyExpiro::CheckPushInstructions()
{
	DWORD dwOffset = 0;
	DWORD dwBytesToCheck = 0x30;
	for(;dwOffset < dwBytesToCheck; dwOffset++)
	{
		if(m_pbyBuff[dwOffset] == 0x60 || m_pbyBuff[dwOffset] == 0x50)
		{
			break;
		}
	}

	int iPushCnt = 0;
	if(m_pbyBuff[dwOffset] == 0x60)
	{
		for(dwOffset = dwOffset + 1; dwOffset < dwBytesToCheck; dwOffset++)
		{
			if(m_pbyBuff[dwOffset] == 0x89 && iPushCnt == 1)
			{
				return true;
			}
			if(m_pbyBuff[dwOffset] == 0x55)
			{
				iPushCnt++;
			}
			/*else if(m_pbyBuff[dwOffset] != 0x90)
			{
			return false;
			}*/
		}
	}
	else if(m_pbyBuff[dwOffset] == 0x50)
	{
		for(dwOffset = dwOffset + 1; dwOffset < dwBytesToCheck; dwOffset++)
		{
			if(m_pbyBuff[dwOffset] == 0x89 && iPushCnt == 8)
			{
				return true;
			}
			else if(m_pbyBuff[dwOffset] == 0x51 || m_pbyBuff[dwOffset] == 0x52 || m_pbyBuff[dwOffset] == 0x53 ||
				m_pbyBuff[dwOffset] == 0x54 || m_pbyBuff[dwOffset] == 0x55 || m_pbyBuff[dwOffset] == 0x56 ||m_pbyBuff[dwOffset] == 0x57 ||
				m_pbyBuff[dwOffset] == 0x50)
			{
				iPushCnt++;
			}
			/*else if(m_pbyBuff[dwOffset] != 0x90)
			{
			return false;
			}*/
		}
	}
	return false;

}

/*-------------------------------------------------------------------------------------
	Function		: GetPatchSize
	In Parameters	: 
	Out Parameters	: true if Instruction match else false
	Purpose			: 
	Author			: Tushar Kadam + Mangesh + Virus Analysis Team
	Description		: Determines Virus Overload Size
--------------------------------------------------------------------------------------*/
bool CPolyExpiro::GetPatchSize()  
{
	DWORD	dwOffset = 0, dwLength = 0, dwCounterIndex = 0, dwOff = 0;
	char	*ptr = NULL, *ptr1 = NULL;
	char	szTempReg[MAX_PATH] = {0}, szTempReqReg[0x10] = {0}, szReqReg[0x15] = {0};
	m_dwInstCount = 1;
	bool	bFlag = false, bCounterFlag = false, bJBECount = false;

	t_disasm da;

	while(dwOffset < m_dwNoOfBytes - 2)
	{

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);

		if((strstr(da.result, "MOVZX EDX")) && (dwLength == 4 || dwLength == 3) &&  m_dwInstCount == 1)
		{
			m_dwInstCount++;
		}
		else if((strstr(da.result,"XOR E"))  && dwLength == 2 &&  m_dwInstCount == 2)
		{
			m_dwInstCount++;
		}
		else if(strstr(da.result, "MOV [E") && (strstr(da.result, "X") || strstr(da.result, "I")) && strstr(da.result, "L") &&  m_dwInstCount == 3)
		{
			dwOff = dwOffset;
			m_dwInstCount++;
		}
		else if((((strstr(da.result, "INC DWORD PTR [E"))||(strstr(da.result, "DEC DWORD PTR [E"))) || (strstr(da.result, "INC E")) ) &&  m_dwInstCount == 4)
		{
			m_dwInstCount++;
			break;

		}
		dwOffset += dwLength;
	}

	if(m_dwInstCount != 5)
	{
		return false;
	}

	dwOffset = dwOff;
	while(dwOffset < m_dwNoOfBytes)
	{
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(strstr(da.result, "MOV [E") && (strstr(da.result, "X") || strstr(da.result, "I")) && strstr(da.result, "L"))		
		{
			if(*(WORD*)&m_pbyBuff[dwOffset + dwLength] == 0x4DFF)//0x48b8)//
			{
				bCounterFlag = true;
			}

			if((dwLength == 3 && strstr(da.result, "+E")) || dwLength == 2) 
			{
				sprintf_s(szTempReg, MAX_PATH, "%s",da.result);
				ptr = strchr(szTempReg,'E');
				if(dwLength == 3)
				{
					ptr1 = strchr(ptr,'+');
					bFlag = true;
				}
				else
				{
					ptr1 = strchr(ptr,']');
				}

				*ptr1 = 0;
				if(ptr)
				{
					strcpy_s(szReqReg, 4, ptr);
					strcpy_s(szTempReqReg, 4, ptr);
					if(bCounterFlag == true)
					{
						dwOffset += dwLength;
						continue;
					}
					else
					{
						break;
					}
				}
			}			
		}
		if(strstr(da.result, "DEC") && dwLength == 3 && (*(WORD*)&m_pbyBuff[dwOffset] == 0x4DFF)) //decryption start from bottom to top
		{
			if(ptr != NULL)
				*ptr = 0;
			if(ptr1 != NULL)
				*ptr1 = 0;
			ptr1 = strrchr(da.result,'-');
			if(ptr1 == NULL)
				break;
			ptr1++;
			ptr = strchr(ptr1,']');
			dwCounterIndex =  strtol(ptr1,&ptr,16);      
			if(! dwCounterIndex ||  dwCounterIndex >0x50)
			{
				return false;
			}
			else
			{
				break;
			}
		}
		dwOffset += dwLength;
	}

	if(szReqReg[0] != 0)
	{
		m_dwPatchSize = GetEmulatedRegister(0x00, dwOffset, szReqReg, m_dwAEPUnmapped + m_dwImageBase, dwCounterIndex);
		if(!bFlag && !dwCounterIndex)
		{
			m_dwPatchSize -= 3;
		}
		if(m_dwPatchSize > m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase)
		{
			m_dwPatchSize -= m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase;
			if(m_dwPatchSize > m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)				// added condition to avoid false detection
				return false;
			return true;
		}
		//Added for Expiro.AP	
		else if(m_dwPatchSizeAP < m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase && (bFlag == true))
		{
			m_dwPatchSizeAP += m_dwExpiroAPAddValue;
			m_dwPatchSizeAP -= m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase;
			m_dwPatchSize = m_dwPatchSizeAP;
			return true;
		}
		else
		{
			m_bDelFlag = true;
			return true;
		}
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetEmulatedRegister
	In Parameters	: DWORD dwStartAddress, DWORD dwEndAddress, char *szRequiredRegister, DWORD dwDisasmStartAddr, DWORD dwCounter
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Mangesh + Virus Analysis Team
	Description		: Determines differnt CPU register values after set of instruction
--------------------------------------------------------------------------------------*/
DWORD CPolyExpiro::GetEmulatedRegister(DWORD dwStartAddress, DWORD dwEndAddress, char *szRequiredRegister, DWORD dwDisasmStartAddr, DWORD dwCounter) //added by  __mangesh 
{
	const	DWORD MAX_STACK_SIZE = 0x150;
	DWORD   dwEPBStack[MAX_STACK_SIZE] = {0};
	DWORD   dwEAX = 0x00;
	DWORD   dwEBX = 0x00;
	DWORD   dwECX = 0x00;
	DWORD   dwEDX = 0x00;
	DWORD   dwESI = 0x00;
	DWORD   dwEDI = 0x00;
	DWORD	dwEBP = 0x00;
	int		nIndex = 0;
	bool	bExpiroAPFlag = false;

	t_disasm	da;
	DWORD dwLength = 0, dwESP = 0, dwTemp = 0;
	bool  bFlag = true, bSubFlag = false;
	BYTE B1 = 0x00, B2 = 0x00, B3 = 0x00;
	m_dwInstCount = 0; 

	if(dwEndAddress < 10)
	{
		return 0;
	}
	for(;dwStartAddress < m_dwNoOfBytes && m_dwInstCount < m_dwNoOfBytes;)
	{
		B1 = m_pbyBuff[dwStartAddress];
		B2 = m_pbyBuff[dwStartAddress + 0x01];	
		if(B1 == 0x89 && B2 == 0xE5)
		{
			dwStartAddress+= 0x02;
			continue;
		}
		if(dwStartAddress == dwEndAddress)
		{
			break;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStartAddress], 0x20,dwDisasmStartAddr, &da, DISASM_CODE);
		dwStartAddress += dwLength;	
		m_dwInstCount++;

		if(dwLength == 0x02 && B1 == 0xEB && strstr(da.result, "JMP "))
		{
			BYTE bTemp = m_pbyBuff[dwStartAddress-1];
			if(bTemp < 0x7F)
			{
				dwStartAddress +=(DWORD)bTemp;
			}
			else
			{
				dwStartAddress +=(DWORD)bTemp+ 0xFFFFFF00;
			}

		}
		if(B1 == 0xE9 && dwLength == 0x05 && strstr(da.result,"JMP "))
		{
			DWORD dwTemp1 = *((DWORD*)&m_pbyBuff[dwStartAddress - dwLength + 0x01]);
			if((NEGATIVE_JUMP(dwTemp1)))
			{
				dwStartAddress += dwTemp1;
			}
			else dwStartAddress += dwTemp1;
		}
		if(B1 == 0x72 && dwLength == 2 &&  strstr(da.result,"JB "))
		{

			BYTE bTemp = m_pbyBuff[dwStartAddress-1];
			if(bTemp < 0x7F)
			{
				dwStartAddress +=(DWORD)bTemp;
			}
			else
			{
				dwStartAddress +=(DWORD)bTemp+ 0xFFFFFF00;
			}
		}

		//////////////////////////////mov EBP STACK
		else if((strstr(da.result,"MOV [EBP-")) || (strstr(da.result,"MOV DWORD PTR [EBP-")))//for byte ptr & dword ptr
		{
			bool bFlag = false;
			char *cptr1 = NULL;
			char *cIndexPtr = NULL,  *CTempptr = NULL;
			cptr1 = strrchr(da.result,',');

			if(cptr1 == NULL)
				break;
			cptr1++;

			cIndexPtr = strrchr(da.result,'-');
			if(cIndexPtr == NULL)
				break;
			cIndexPtr++;
			CTempptr = strchr(cIndexPtr,']');
			nIndex =  strtol(cIndexPtr,&CTempptr,16);

			if(!strcmp(cptr1,"AL") || !strcmp(cptr1,"BL") ||!strcmp(cptr1,"CL") ||!strcmp(cptr1,"DL"))
			{
				bFlag = true;
			}


			if(!strcmp(cptr1,"EAX")|| !strcmp(cptr1,"AL") || !strcmp(cptr1,"EBX")||!strcmp(cptr1,"BL") || !strcmp(cptr1,"ECX")||!strcmp(cptr1,"CL") || !strcmp(cptr1,"EDX")||!strcmp(cptr1,"DL") || !strcmp(cptr1,"ESI")|| !strcmp(cptr1,"EDI"))	
			{
				if(strstr(da.result,"EBX")|| strstr(da.result,"BL"))
				{
					if(bFlag)
					{
						dwEPBStack[nIndex] &= 0xFFFFFF00;
						dwEPBStack[nIndex] += BYTE(dwEAX);
					}
					else 
					{
						dwEPBStack[nIndex] = dwEBX;
					}
				}
				else if(strstr(da.result,"EC")|| strstr(da.result,"CL"))
				{
					if(bFlag)
					{
						dwEPBStack[nIndex] &= 0xFFFFFF00;
						dwEPBStack[nIndex] += BYTE(dwECX);
					}
					else 
					{
						dwEPBStack[nIndex] = dwECX;
					}
				}
				else if(strstr(da.result,"EDI"))
					dwEPBStack[nIndex] = dwEDI;
				else if(strstr(da.result,"ESI"))
					dwEPBStack[nIndex] = dwESI;
				else if(strstr(da.result,"EDX") ||strstr(da.result,"DL"))
				{
					if(bFlag)
					{
						dwEPBStack[nIndex] &= 0xFFFFFF00;
						dwEPBStack[nIndex] += BYTE(dwEDX);
					}
					else
					{
						dwEPBStack[nIndex] = dwEDX;
					}
				}
				else if(strstr(da.result,"EAX") || strstr(da.result,"AL"))
				{
					if(bFlag)
					{
						dwEPBStack[nIndex] &= 0xFFFFFF00;
						dwEPBStack[nIndex] += BYTE(dwEAX);
					}
					else
					{
						dwEPBStack[nIndex] = dwEAX;
					}
				}
			}

			else
			{
				sscanf_s(cptr1, "%X", &dwTemp);
				if(da.immconst ||(!strchr(cptr1,'L')&& !strchr(cptr1,'H')&& !strchr(cptr1,'X')))
				{
					if(bFlag)
					{
						dwEPBStack[nIndex] &= 0xFFFFFF00;
						dwEPBStack[nIndex]  += (BYTE)dwTemp;
					}
					else
					{
						dwEPBStack[nIndex]  = dwTemp;
					}
				}
			}				
		}	
		else if(strstr(da.result,"MOV E") )
		{
			char *cIndexPtr = NULL,  *CTempptr = NULL;
			char *cptr1 = NULL;
			bool bFlag = false;

			if(strstr(da.result,"[EBP-"))
			{
				cptr1 = strrchr(da.result,',');

				if(cptr1 == NULL)
					break;
				cptr1++;

				cIndexPtr = strrchr(da.result,'-');
				if(cIndexPtr == NULL)
					break;
				cIndexPtr++;
				CTempptr = strchr(cIndexPtr,']');
				nIndex =  strtol(cIndexPtr,&CTempptr,16);

				if(!strcmp(cptr1,"AL") || !strcmp(cptr1,"BL") ||!strcmp(cptr1,"CL") ||!strcmp(cptr1,"DL"))
				{
					bFlag = true;
				}

			}
			else
			{
				cptr1 = strrchr(da.result,',');
				if(cptr1 == NULL)
					break;
				cptr1++;
			}
			if(strstr(da.result,"[EBP-")||!strcmp(cptr1,"EAX")|| !strcmp(cptr1,"AL") || !strcmp(cptr1,"EBX")||!strcmp(cptr1,"BL") || !strcmp(cptr1,"ECX")||!strcmp(cptr1,"CL") || !strcmp(cptr1,"EDX")||!strcmp(cptr1,"DL") || !strcmp(cptr1,"ESI")|| !strcmp(cptr1,"EDI") ||!strcmp(cptr1,"EBP"))	
			{
				////////  For MOv 
				if(strstr(da.result,"MOV EAX,") || strstr(da.result,"MOV AL,"))
				{
					if(strstr(da.result,"MOV EAX,EBX"))
						dwEAX = dwEBX;
					else if(strstr(da.result,"MOV EAX,ECX"))
						dwEAX = dwECX;
					else if(strstr(da.result,"MOV EAX,EDX"))
						dwEAX = dwEDX;
					else if(strstr(da.result,"MOV EAX,ESI"))
						dwEAX = dwESI;
					else if(strstr(da.result,"MOV EAX,EDI"))
						dwEAX = dwEDI;
					else if(strstr(da.result,"MOV EAX,EBP"))
						dwEAX = dwEBP;
					else if(strstr(da.result,"[EBP-"))
					{  
						if(bFlag)
						{
							dwEAX &= 0xFFFFFF00;
							dwEAX += (BYTE)dwEPBStack[nIndex];
						}
						else dwEAX = dwEPBStack[nIndex];
					}
				}
				else if(strstr(da.result,"MOV EBX,") || strstr(da.result,"MOV BL,"))
				{
					if(strstr(da.result,"MOV EBX,EAX"))
						dwEBX = dwEAX;
					else if(strstr(da.result,"MOV EBX,ECX"))
						dwEBX = dwECX;
					else if(strstr(da.result,"MOV EBX,EDX"))
						dwEBX = dwEDX;
					else if(strstr(da.result,"MOV EBX,ESI"))
						dwEBX = dwESI;
					else if(strstr(da.result,"MOV EBX,EDI"))
						dwEBX = dwEDI;
					else if(strstr(da.result,"MOV EBX,EBP"))
						dwEBX = dwEBP;
					else if(strstr(da.result,"[EBP-"))
					{
						if(bFlag)
						{
							dwEBX &= 0xFFFFFF00;
							dwEBX += (BYTE)dwEPBStack[nIndex];
						}					
						else dwEBX = dwEPBStack[nIndex];
					}
				}
				else if(strstr(da.result,"MOV ECX,")||strstr(da.result,"MOV CL,"))
				{
					if(strstr(da.result,"MOV ECX,EAX"))
						dwECX = dwEAX;
					else if(strstr(da.result,"MOV ECX,EBX"))
						dwECX = dwEBX;
					else if(strstr(da.result,"MOV ECX,EDX"))
						dwECX = dwEDX;
					else if(strstr(da.result,"MOV ECX,ESI"))
						dwECX = dwESI;
					else if(strstr(da.result,"MOV ECX,EDI"))
						dwECX = dwEDI;
					else if(strstr(da.result,"MOV ECX,EBP"))
						dwECX = dwEBP;
					else if(strstr(da.result,"[EBP-"))
					{
						if(bFlag)
						{
							dwECX &= 0xFFFFFF00;
							dwECX += (BYTE)dwEPBStack[nIndex];
						}
						else dwECX = dwEPBStack[nIndex];
					}
				}
				else if(strstr(da.result,"MOV EDX,")|| strstr(da.result,"MOV DL,"))
				{
					if(strstr(da.result,"MOV EDX,EAX"))
						dwEDX = dwEAX;
					else if(!strcmp(da.result,"MOV EDX,EBX"))
						dwEDX = dwEBX;
					else if(strstr(da.result,"MOV EDX,ECX"))
						dwEDX = dwECX;
					else if(strstr(da.result,"MOV EDX,ESI"))
						dwEDX = dwESI;
					else if(strstr(da.result,"MOV EDX,EDI"))
						dwEDX = dwEDI;
					else if(strstr(da.result,"MOV EDX,EBP"))
						dwEDX = dwEBP;
					else if(strstr(da.result,"[EBP-"))
					{
						if(bFlag)
						{
							dwEDX &= 0xFFFFFF00;
							dwEDX += (BYTE)dwEPBStack[nIndex];
						}
						else dwEDX = dwEPBStack[nIndex];
					}
				}
				else if(strstr(da.result,"MOV ESI,"))
				{
					if(strstr(da.result,"MOV ESI,EAX"))
						dwESI = dwEAX;
					else if(strstr(da.result,"MOV ESI,EBX"))
						dwESI = dwEBX;
					else if(strstr(da.result,"MOV ESI,ECX"))
						dwESI = dwECX;
					else if(strstr(da.result,"MOV ESI,EDX"))
						dwESI = dwEDX;
					else if(strstr(da.result,"MOV ESI,EDI"))
						dwESI = dwEDI;
					else if(strstr(da.result,"MOV ESI,EBP"))
						dwESI = dwEBP;
					else if(strstr(da.result,"[EBP-"))
						dwESI = dwEPBStack[nIndex];
				}
				else if(strstr(da.result,"MOV EDI,"))
				{
					if(strstr(da.result,"MOV EDI,EAX"))
						dwEDI = dwEAX;
					else if(strstr(da.result,"MOV EDI,EBX"))
						dwEDI = dwEBX;
					else if(strstr(da.result,"MOV EDI,ECX"))
						dwEDI = dwECX;
					else if(strstr(da.result,"MOV EDI,EDX"))
						dwEDI = dwEDX;
					else if(strstr(da.result,"MOV EDI,ESI"))
						dwEDI = dwESI;
					else if(strstr(da.result,"MOV EDI,EBP"))
						dwEDI = dwEBP;
					else if(strstr(da.result,"[EBP-"))
						dwEDI = dwEPBStack[nIndex];
				}
				else
				{
					if(strstr(da.result,"MOV EBP,EAX"))
						dwEBP = dwEAX;
					else if(strstr(da.result,"MOV EBP,EBX"))
						dwEBP = dwEBX;
					else if(strstr(da.result,"MOV EBP,ECX"))
						dwEBP = dwECX;
					else if(strstr(da.result,"MOV EBP,EDX"))
						dwEBP = dwEDX;
					else if(strstr(da.result,"MOV EBP,ESI"))
						dwEBP = dwESI;
					else if(strstr(da.result,"MOV EBP,EDI"))
						dwEBP = dwEDI;
				}

			}
			else
			{
				sscanf_s(cptr1, "%X", &dwTemp);
				if(da.immconst ||(!strchr(cptr1,'L')&& !strchr(cptr1,'H')&& !strchr(cptr1,'X')))
				{
					if(strstr(da.result,"MOV EAX")||strstr(da.result,"MOV AL,"))
					{
						if(bFlag)
						{
							dwEAX &= 0xFFFFFF00;
							dwEAX += (BYTE)dwTemp;
						}
						else dwEAX = dwTemp;
					}
					else if(strstr(da.result,"MOV EBX")||strstr(da.result,"MOV BL,"))
					{
						if(bFlag)
						{
							dwEBX &= 0xFFFFFF00;
							dwEBX += (BYTE)dwTemp;
						}
						else dwEBX = dwTemp;
					}
					else if(strstr(da.result,"MOV ECX")||strstr(da.result,"MOV CL,"))
					{
						if(bFlag)
						{
							dwECX &= 0xFFFFFF00;
							dwECX += (BYTE)dwTemp;
						}
						else dwECX = dwTemp;
					}
					else if(strstr(da.result,"MOV EDX")||strstr(da.result,"MOV DL,"))
					{
						if(bFlag)
						{
							dwEDX &= 0xFFFFFF00;
							dwEDX += (BYTE)dwTemp;
						}
						else dwEDX = dwTemp;
					}
					else if(strstr(da.result,"MOV ESI"))
					{
						if(bFlag)
						{
							dwESI &= 0xFFFFFF00;
							dwESI += (BYTE)dwTemp;
						}
						else dwESI = dwTemp;
					}
					else if(strstr(da.result,"MOV EDI"))
						dwEDI = dwTemp;
					else if(strstr(da.result,"MOV EBP"))
						dwEBP = dwTemp;
				}
			}				
		}
		/////////////////////////// Addition 2 EbpStack
		else if(strstr(da.result,"ADD [EBP-")|| (strstr(da.result,"ADD DWORD PTR [EBP-")))
		{
			char *cptr1 = NULL;
			char *cIndexPtr = NULL,  *CTempptr = NULL;
			cptr1 = strrchr(da.result,',');

			if(cptr1 == NULL)
				break;
			cptr1++;

			cIndexPtr = strrchr(da.result,'-');
			if(cIndexPtr == NULL)
				break;
			cIndexPtr++;
			CTempptr = strchr(cIndexPtr,']');
			nIndex =  strtol(cIndexPtr,&CTempptr,16);
			//*CTempptr = 0;


			if(!strcmp(cptr1,"EAX")|| !strcmp(cptr1,"AL") || !strcmp(cptr1,"EBX")||!strcmp(cptr1,"BL") || !strcmp(cptr1,"ECX")||!strcmp(cptr1,"CL") || !strcmp(cptr1,"EDX")||!strcmp(cptr1,"DL") || !strcmp(cptr1,"ESI")|| !strcmp(cptr1,"EDI"))	
			{
				if(strstr(da.result,"EAX"))
					dwEPBStack[nIndex] += dwEAX;
				else if(strstr(da.result,"EBX"))
					dwEPBStack[nIndex] += dwEBX;
				else if(strstr(da.result,"ECX"))
					dwEPBStack[nIndex] += dwECX;
				else if(strstr(da.result,"EDI"))
					dwEPBStack[nIndex] += dwEDI;
				else if(strstr(da.result,"ESI"))
					dwEPBStack[nIndex] += dwESI;
				else if(strstr(da.result,"EDX"))
					dwEPBStack[nIndex] += dwEDX;
				else if(strstr(da.result,"EBP"))
					dwEPBStack[nIndex] += dwEBP;
				else if(strstr(da.result,"AL"))
					dwEPBStack[nIndex] += (BYTE)dwEAX;
				else if(strstr(da.result,"BL"))
					dwEPBStack[nIndex] += (BYTE)dwEBX;
				else if(strstr(da.result,"CL"))
					dwEPBStack[nIndex] += (BYTE)dwECX;
				else if(strstr(da.result,"DL"))
					dwEPBStack[nIndex] += (BYTE)dwEDX;
			}

			else
			{
				sscanf_s(cptr1, "%X", &dwTemp);
				if(da.immconst ||(!strchr(cptr1,'L')&& !strchr(cptr1,'H')&& !strchr(cptr1,'X')))
				{

					dwEPBStack[nIndex]  += dwTemp;

				}
			}				
		}	

		/////////////////////////// For Addition

		else if(strstr(da.result,"ADD ")&& da.result[0] == 'A')
		{
			char *cIndexPtr = NULL,  *CTempptr = NULL;
			char *cptr1 = NULL;

			bool bFlag = false;

			if(strstr(da.result,"[EBP-"))
			{

				cptr1 = strrchr(da.result,',');

				if(cptr1 == NULL)
					break;
				cptr1++;

				cIndexPtr = strrchr(da.result,'-');
				if(cIndexPtr == NULL)
					break;
				cIndexPtr++;
				CTempptr = strchr(cIndexPtr,']');
				nIndex =  strtol(cIndexPtr,&CTempptr,16);
				if(strstr(da.result,"BYTE PTR"))
				{
					bFlag = true;
				}

			}
			else
			{

				cptr1 = strrchr(da.result,',');
				if(cptr1 == NULL)
					break;
				cptr1++;
			}
			if(strstr(da.result,"[EBP-")|| !strcmp(cptr1,"EAX")|| !strcmp(cptr1,"EBX")|| !strcmp(cptr1,"ECX")|| !strcmp(cptr1,"EDX")|| !strcmp(cptr1,"ESI")|| !strcmp(cptr1,"EDI")|| !strcmp(cptr1,"EBP"))	
			{
				if(strstr(da.result,"ADD EAX"))
				{
					if(!strcmp(da.result,"ADD EAX,EBX"))
						dwEAX = dwEAX + dwEBX;
					else if(strstr(da.result,"ADD EAX,ECX"))
						dwEAX = dwEAX + dwECX;
					else if(strstr(da.result,"ADD EAX,EDX"))
						dwEAX = dwEAX + dwEDX;
					else if(strstr(da.result,"ADD EAX,ESI"))
						dwEAX = dwEAX + dwESI;
					else if(strstr(da.result,"ADD EAX,EDI"))
						dwEAX = dwEAX + dwEDI;
					else if(strstr(da.result,"ADD EAX,EAX"))
						dwEAX = dwEAX + dwEAX;
					else if(strstr(da.result,"ADD EAX,EBP"))
						dwEAX = dwEAX + dwEBP;
					else if(strstr(da.result,"[EBP-"))
						dwEAX += dwEPBStack[nIndex];
				}
				else if(strstr(da.result,"ADD EBX"))
				{
					if(strstr(da.result,"ADD EBX,EAX"))
						dwEBX = dwEBX + dwEAX;
					else if(strstr(da.result,"ADD EBX,EBX"))
						dwEBX = dwEBX + dwEBX;
					else if(strstr(da.result,"ADD EBX,ECX"))
						dwEBX = dwEBX + dwECX;
					else if(strstr(da.result,"ADD EBX,EDX"))
						dwEBX = dwEBX + dwEDX;
					else if(strstr(da.result,"ADD EBX,EDI"))
						dwEBX = dwEBX + dwEDI;
					else if(strstr(da.result,"ADD EBX,ESI"))
						dwEBX = dwEBX + dwESI;
					else if(strstr(da.result,"ADD EBX,EBP"))
						dwEBX = dwEBX + dwEBP;
					else if(strstr(da.result,"[EBP-"))
						dwEBX += dwEPBStack[nIndex];
				}
				else if(strstr(da.result,"ADD ECX"))
				{
					if(strstr(da.result,"ADD ECX,EAX"))
						dwECX = dwECX + dwEAX;
					else if(strstr(da.result,"ADD ECX,EBX"))
						dwECX = dwECX + dwEBX;
					else if(strstr(da.result,"ADD ECX,ECX"))
						dwECX = dwECX + dwECX;
					else if(strstr(da.result,"ADD ECX,EDX"))
						dwECX = dwECX + dwEDX;
					else if(strstr(da.result,"ADD ECX,ESI"))
						dwECX = dwECX + dwESI;
					else if(strstr(da.result,"ADD ECX,EDI"))
						dwECX = dwECX + dwEDI;
					else if(strstr(da.result,"ADD ECX,EBP"))
						dwECX = dwECX + dwEBP;
					else if(strstr(da.result,"[EBP-"))
						dwECX += dwEPBStack[nIndex];
				}
				else if(strstr(da.result,"ADD EDX"))
				{
					if(strstr(da.result,"ADD EDX,EAX"))
						dwEDX = dwEDX + dwEAX;
					else if(strstr(da.result,"ADD EDX,EBX"))
						dwEDX = dwEDX + dwEBX;
					else if(strstr(da.result,"ADD EDX,ECX"))
						dwEDX = dwEDX + dwECX;
					else if(strstr(da.result,"ADD EDX,EDX"))
						dwEDX = dwEDX + dwEDX;
					else if(strstr(da.result,"ADD EDX,ESI"))
						dwEDX = dwEDX + dwESI;
					else if(strstr(da.result,"ADD EDX,EDI"))
						dwEDX = dwEDX + dwEDI;
					else if(strstr(da.result,"ADD EDX,EBP"))
						dwEDX = dwEDX + dwEBP;
					else if(strstr(da.result,"[EBP-"))
						dwEDX += dwEPBStack[nIndex];
				}
				else if(strstr(da.result,"ADD ESI"))
				{
					if(strstr(da.result,"ADD ESI,EAX"))
						dwESI = dwESI + dwEAX;
					else if(strstr(da.result,"ADD ESI,EBX"))
						dwESI = dwESI + dwEBX;
					else if(strstr(da.result,"ADD ESI,ECX"))
						dwESI = dwESI + dwECX;
					else if(strstr(da.result,"ADD ESI,EDX"))
						dwESI = dwESI + dwEDX;
					else if(strstr(da.result,"ADD ESI,EDI"))
						dwESI = dwESI + dwEDI;
					else if(strstr(da.result,"ADD ESI,ESI"))
						dwESI = dwESI + dwESI;
					else if(strstr(da.result,"ADD ESI,EBP"))
						dwESI = dwESI + dwEBP;
					else if(strstr(da.result,"[EBP-"))
						dwESI += dwEPBStack[nIndex];
				}
				else if(strstr(da.result,"ADD EDI"))
				{
					if(strstr(da.result,"ADD EDI,EAX"))
						dwEDI = dwEDI + dwEAX;
					else if(strstr(da.result,"ADD EDI,EBX"))
						dwEDI = dwEDI + dwEBX;
					else if(strstr(da.result,"ADD EDI,ECX"))
						dwEDI = dwEDI + dwECX;
					else if(strstr(da.result,"ADD EDI,EDX"))
						dwEDI = dwEDI + dwEDX;
					else if(strstr(da.result,"ADD EDI,ESI"))
						dwEDI = dwEDI + dwESI;
					else if(strstr(da.result,"ADD EDI,EDI"))
						dwEDI = dwEDI + dwEDI;
					else if(strstr(da.result,"ADD EDI,EBP"))
						dwEDI = dwEDI + dwEBP;
					else if(strstr(da.result,"[EBP-"))
						dwEDI += dwEPBStack[nIndex];
				}
				else
				{
					if(strstr(da.result,"ADD EBP,EAX"))
						dwEBP = dwEBP + dwEAX;
					else if(strstr(da.result,"ADD EBP,EBX"))
						dwEBP = dwEBP + dwEBX;
					else if(strstr(da.result,"ADD EBP,ECX"))
						dwEBP = dwEBP + dwECX;
					else if(strstr(da.result,"ADD EBP,EDX"))
						dwEBP = dwEBP + dwEDX;
					else if(strstr(da.result,"ADD EBP,ESI"))
						dwEBP = dwEBP + dwESI;
					else if(strstr(da.result,"ADD EBP,EDI"))
						dwEBP = dwEBP + dwEDI;
					else if(strstr(da.result,"ADD EBP,EBP"))
						dwEBP = dwEBP + dwEBP;	
					else if(strstr(da.result,"[EBP-"))
						dwEBP += dwEPBStack[nIndex];
				}
			}
			else 
			{
				sscanf_s(cptr1, "%X", &dwTemp);
				if(da.immconst ||(!strchr(cptr1,'L')&& !strchr(cptr1,'H')&& !strchr(cptr1,'X')))
				{
					if(strstr(da.result,"ADD EAX"))
						dwEAX = dwEAX + dwTemp;
					else if(strstr(da.result,"ADD EBX")) //Changes done for Expiro.ap
					{
						dwEBX = dwEBX + dwTemp;
						if(bExpiroAPFlag == false)
						{
							m_dwPatchSizeAP = dwEBX;
							bExpiroAPFlag = true;
						}
						m_dwExpiroAPAddValue = dwTemp;
					}
					else if(strstr(da.result,"ADD ECX"))
						dwECX = dwECX + dwTemp;
					else if(strstr(da.result,"ADD EDX"))
						dwEDX = dwEDX + dwTemp;
					else if(strstr(da.result,"ADD ESI")) //Changes done for Expiro.ap
					{
						dwESI = dwESI + dwTemp;
						if(bExpiroAPFlag == false)
						{
							m_dwPatchSizeAP = dwESI;
							bExpiroAPFlag = true;
						}
						m_dwExpiroAPAddValue = dwTemp;
					}
					else if(strstr(da.result,"ADD EDI"))
						dwEDI = dwEDI + dwTemp;
					else if(strstr(da.result,"ADD EBP"))
						dwEBP = dwEBP + dwTemp;
				}
			}			
		}		

		/////////////////////////////////For Substraction for EXPIRO.AE
		else if(strstr(da.result,"SUB "))
		{
			char *cptr1 = NULL;
			cptr1 = strrchr(da.result,',');
			if(cptr1 == NULL)
				break;
			cptr1++;	

			sscanf_s(cptr1, "%X", &dwTemp);
			if(da.immconst ||(!strchr(cptr1,'L')&& !strchr(cptr1,'H')&& !strchr(cptr1,'X')))
			{
				if(strstr(da.result,"SUB EAX"))
				{
					dwEAX = dwEAX - dwTemp;
				}
				else if(strstr(da.result,"SUB EBX"))
				{
					dwEBX = dwEBX - dwTemp;
				}
				else if(strstr(da.result,"SUB ECX"))
				{
					dwECX = dwECX - dwTemp;
				}
				else if(strstr(da.result,"SUB EDX"))
				{
				}
				else if(strstr(da.result,"SUB ESI"))
				{
					dwESI = dwESI - dwTemp;
				}
				else if(strstr(da.result,"SUB EDI"))
				{
					dwEDI = dwEDI - dwTemp;
				}
				else if(strstr(da.result,"SUB EBP"))
				{
					dwEBP = dwEBP - dwTemp;
				}
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
			if(strstr(cptr1,"[EAX")|| strstr(cptr1,"[EBX")|| strstr(cptr1,"[ECX")|| strstr(cptr1,"[EDX")|| strstr(cptr1,"[EDI")|| strstr(cptr1,"[ESI")|| strstr(cptr1,"[EBP"))
			{
				if(strstr(da.result,"LEA EAX,[EAX"))
				{
					dwEAX += 3; 
				}
				else if(strstr(da.result,"LEA EBX,[EBX"))
				{
					dwEAX += 3; 
				}
				else if(strstr(da.result,"LEA ECX,[ECX"))
				{
					dwEAX += 3; 
				}
				else if(strstr(da.result,"LEA EDX,[EDX"))
				{
					dwEAX += 3; 
				}
				else if(strstr(da.result,"LEA ESI,[ESI"))
				{
					dwEAX += 3; 
				}
				else if(strstr(da.result,"LEA EDI,[EDI"))
				{
					dwEAX += 3; 
				}
				else if(strstr(da.result,"LEA EBP,[EBP"))
				{
					dwEAX += 3; 
				}

			}
		}
		else if(strstr(da.result,"MUL DWORD PTR [EBP-"))
		{
			char *cIndexPtr = NULL,  *CTempptr = NULL;
			cIndexPtr = strrchr(da.result,'-');
			if(cIndexPtr == NULL)
				break;
			cIndexPtr++;
			CTempptr = strchr(cIndexPtr,']');
			nIndex =  strtol(cIndexPtr,&CTempptr,16);
			dwEAX *= dwEPBStack[nIndex];
		}
	}

	if(!strcmp(szRequiredRegister ,"EAX"))
	{
		if(dwCounter && dwEAX > m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase + 0x500) // for reverse decryption & not having require reg case = [EAX+EDX]
		{
			return dwEAX -  dwEPBStack[dwCounter];
		}

		return dwEAX;
	}
	else if(!strcmp(szRequiredRegister ,"EBX"))
	{
		if(dwCounter && dwEBX > m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase + 0x500)
		{
			return dwEBX -  dwEPBStack[dwCounter];
		}

		return dwEBX;
	}
	else if(!strcmp(szRequiredRegister ,"ECX"))
	{
		if(dwCounter && dwECX > m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase + 0x500)
		{
			return dwECX -  dwEPBStack[dwCounter];
		}

		return dwECX;
	}
	else if(!strcmp(szRequiredRegister ,"EDX"))
	{
		if(dwCounter && dwEDX > m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase + 0x500)
		{
			return dwEDX -  dwEPBStack[dwCounter];
		}

		return dwEDX;
	}
	else if(!strcmp(szRequiredRegister ,"ESI"))
	{
		if(dwCounter && dwESI > m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase + 0x500)
		{
			return dwESI -  dwEPBStack[dwCounter];
		}

		return dwESI;
	}
	else if(!strcmp(szRequiredRegister ,"EDI"))
	{
		if(dwCounter && dwEDI > m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase + 0x500)
		{
			return dwEDI -  dwEPBStack[dwCounter];
		}

		return dwEDI;
	}
	else if(!strcmp(szRequiredRegister ,"EBP"))
	{
		if(dwCounter && dwEBP > m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_dwImageBase + 0x500)
		{
			return dwEBP -  dwEPBStack[dwCounter];
		}

		return dwEBP;
	}
	else 
		return 0x00;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Expiro Family
					  It Cleans Two types of Expiro Infection
						1. Normal Infection With Negative Jump to OAEP.
						2. New infection Patch at Original Address of Entry Point.
--------------------------------------------------------------------------------------*/
int CPolyExpiro::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	if(!m_iExpiroType)
	{	
		return iRetStatus;
	}

	switch(m_iExpiroType)
	{
		//First Type Expiro With Negative Jump 
	case 1:
		{	
			if(m_dwOAEPExpiro)
			{
				m_pMaxPEFile->WriteAEP(m_dwOAEPExpiro - m_dwImageBase);	
				if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wAEPSec].PointerToRawData))
				{
					iRetStatus = REPAIR_SUCCESS;
				}
			}
		}
		break;
		//Expiro Type 2 No Negative Jump Direct Start of Virus Code (ReplacOriginalData)
	case 2:
		{			
			if(m_pMaxPEFile->CopyData(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, m_dwAEPMapped, m_dwPatchSize))
			{
				if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData))
				{
					iRetStatus = REPAIR_SUCCESS;
				}
			}
		}
		break;

	case 3:
		// Repair for Virus.W32.Expiro.AR
		if(m_pMaxPEFile->CopyData(m_dwOAEPExpiro,m_dwAEPMapped,m_dwPatchSize))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwOAEPExpiro,false))
				iRetStatus = REPAIR_SUCCESS;
		}
		break;
	}
	return iRetStatus;
}

