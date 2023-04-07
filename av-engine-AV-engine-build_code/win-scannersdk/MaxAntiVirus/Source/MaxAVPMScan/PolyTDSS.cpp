/*======================================================================================
FILE				: PolyTDSS.cpp
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
NOTES				: This is detection module for malware TDSS Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyTDSS.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyTDSS
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyTDSS::CPolyTDSS(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyTDSS
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyTDSS::~CPolyTDSS(void)
{
	if(NULL != m_pbyBuff)
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
	Author			: Tushar Kadam + Omkar Pardeshi + Virus Analysis Team
	Description		: Detection routine for different varients of TDSS Family
--------------------------------------------------------------------------------------*/
int CPolyTDSS::DetectVirus()
{	
	int	iRetStatus = VIRUS_NOT_FOUND;
	
	iRetStatus = DetectTdssD();
	if(iRetStatus)
	{
		return iRetStatus;
	}
	iRetStatus = DetectTdssAA();
	if(iRetStatus)
	{
		return iRetStatus;
	}
	iRetStatus = DetectTdssZ();
	if(iRetStatus)
	{
		return iRetStatus;
	}
	return iRetStatus;	
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Omkar Pardeshi + Virus Analysis Team
	Description		: Detection routine for : Tdss.D
--------------------------------------------------------------------------------------*/
int CPolyTDSS::DetectTdssD()
{	
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->m_stPEHeader.Subsystem == 0x01 && m_wAEPSec == m_wNoOfSections - 2)
	{ 
		const int TDSS_BUFF_SIZE = 100;
		m_pbyBuff = new BYTE[TDSS_BUFF_SIZE + MAX_INSTRUCTION_LEN];	
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, TDSS_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(!GetBuffer(m_dwAEPMapped, TDSS_BUFF_SIZE, TDSS_BUFF_SIZE))
		{
			return iRetStatus;
		}
		DWORD dwStart = 0, dwLength = 0, dwSeq = 0;
		t_disasm da;
		
		//Start Disassembly
		while(dwStart < TDSS_BUFF_SIZE)
		{	 
			dwLength = m_objMaxDisassem.Disasm((char* )&m_pbyBuff[dwStart], MAX_INSTRUCTION_LEN, m_dwImageBase, &da, DISASM_CODE);
			if(dwLength > (TDSS_BUFF_SIZE - dwStart))
			{
				return iRetStatus;
			}
			if(strstr(da.result, "PUSH EBP") && dwLength == 1 && dwSeq == 0)
			{
				dwSeq++;			
			}
			if(strstr(da.result, "MOV EBP,ESP") && dwLength == 2 && dwSeq == 1)
			{
				dwSeq++;			
			}
			if(strstr(da.result, "MOV EAX,[ECX+C]") && da.adrconst == 0x0C && dwLength == 3 && dwSeq == 2)
			{
				dwSeq++;			
			}
			if(strstr(da.result, "MOV EDX,[EAX+3C]") && da.adrconst == 0x3C && dwLength == 3 && dwSeq == 3)
			{
				dwSeq++;			
			}
			if(strstr(da.result, "MOV EBX,[EDX+EAX+88]") && da.adrconst == 0x88 && dwLength == 7 && dwSeq == 4)
			{
				dwSeq++;			
			}
			if(strstr(da.result, "ADD EBX,EAX") && dwLength == 2 && dwSeq == 5)
			{
				dwSeq++;			
			}
			if(strstr(da.result, "MOV EAX,[ECX+14]") && da.adrconst == 0x14 && dwLength == 3 && dwSeq == 6)
			{
				dwSeq++;			
			}
			if(strstr(da.result, "MOV EAX,[EAX]") && dwLength == 2 && dwSeq == 7)
			{
				dwSeq++;			
			}
			if(strstr(da.result, "CMP [EAX+38]") && da.adrconst==0x38 && dwLength == 4 && dwSeq == 8)
			{
				dwSeq++;			
			}
			if(strstr(da.result, "MOV EAX,[EAX+18]") && da.adrconst == 0x18 && dwLength == 3 && dwSeq == 9)
			{
				dwSeq++;			
			}
			if(strstr(da.result, "MOV ESI")  && dwSeq == 10)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.TDSS.D"));
				return VIRUS_FILE_REPAIR;		
			}
			dwStart += dwLength;	
		}//end while
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Omkar Pardeshi + Virus Analysis Team
	Description		: Detection routine for : Tdss.AA
--------------------------------------------------------------------------------------*/
int CPolyTDSS::DetectTdssAA()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections >= 5 && m_wAEPSec == 0 && ((m_pSectionHeader[m_wAEPSec].Characteristics & 0x60000020) == 0x60000020) &&
	   m_pSectionHeader[m_wAEPSec].Misc.VirtualSize <= 0x4000 && m_dwAEPMapped < 0x2000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int TDSSAA_BUFF_SIZE = 0x800;
		m_pbyBuff = new BYTE[TDSSAA_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, TDSSAA_BUFF_SIZE + MAX_INSTRUCTION_LEN);

		if(!GetBuffer(m_pSectionHeader[0].PointerToRawData, TDSSAA_BUFF_SIZE, TDSSAA_BUFF_SIZE))
		{			
			return iRetStatus;		
		}
		DWORD dwOffset = 0, dwLength = 0, dwResOffset = 0, dwResLength = 0, dwDissamble = 0;
		int iStg = 0, iNextInsCnt = 0;
		m_dwInstCount = 0;
		t_disasm da = {0};
		BYTE B1, B2, B3, B5;
		while(dwOffset < TDSSAA_BUFF_SIZE && m_dwInstCount <= 0x200)
		{
			B1 = m_pbyBuff[dwOffset];
			B2 = m_pbyBuff[dwOffset + 1];
			B3 = m_pbyBuff[dwOffset + 2];
			B5 = m_pbyBuff[dwOffset + 5];
			if(iStg == 0 && B1 == 0x83 && B2 == 0xC0 && B3 == 0x01 && dwDissamble == 0)
			{
				dwDissamble = 1;
			}
			if(iStg == 0 && B1 == 0x40 && dwDissamble == 0)
			{
				dwDissamble = 1;
			}
			if(iStg == 0 && B1 == 0x05 && B5 == 0x2D && dwDissamble == 0)
			{
				dwDissamble = 1;
			}
			if(iStg == 0 && B1 == 0x83 && B2 == 0xE8 && B3 == 0xFF && dwDissamble == 0)
			{
				dwDissamble = 1;
			}
			dwLength = 0;
			if(dwDissamble == 1 || iStg > 0)
			{
				dwDissamble = 0;
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (TDSSAA_BUFF_SIZE - dwOffset))
				{
					break;
				}
				m_dwInstCount++;
				if(dwLength == 0x01 && strstr(da.result, "INC EAX") &&  iStg == 0)
				{
					iStg++;
					dwResOffset = dwOffset;
					dwResLength = dwLength;
				}
				if(dwLength == 0x03 && (strstr(da.result, "ADD EAX,1") || strstr(da.result, "SUB EAX,-1")) && iStg == 0)
				{
					iStg++;
					dwResOffset = dwOffset;
					dwResLength = dwLength;
				}
				if(dwLength == 0x05 && strstr(da.result, "ADD EAX,") && da.immconst > 1 && iStg == 0)
				{
					if(m_pbyBuff[dwOffset + dwLength] == 0x2D)
					{
						if(da.immconst - *(DWORD *)&m_pbyBuff[dwOffset + dwLength + 1] == 1)
						{
							iStg++;
							dwResOffset = dwOffset;
							dwResLength = dwLength;
						}
					}
				}
				if(iStg > 0)
				{
					iNextInsCnt++;
				}
				if(iNextInsCnt >= 30)
				{
					iNextInsCnt = 0;
					iStg = 0;
					dwOffset = dwResLength + dwResOffset;
					continue;
				}
				if(dwLength == 0x02 && strstr(da.result, "JMP SHORT") && iStg > 0)
				{
					BYTE bTemp = m_pbyBuff[dwOffset + 1];
					if(bTemp < 0x7F)
					{
						dwOffset +=(DWORD)bTemp + dwLength;
					}
					else
					{
						dwOffset +=(DWORD)bTemp+ 0xFFFFFF00 + dwLength;
					}
					if(dwOffset > TDSSAA_BUFF_SIZE - MAX_INSTRUCTION_LEN)
					{
						dwOffset = dwResLength + dwResOffset;
					}
					continue;
				}
				if(dwLength == 0x05 && strstr(da.result, "JMP ") && iStg > 0)
				{
					dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwOffset + dwLength;
					if(dwOffset > TDSSAA_BUFF_SIZE - MAX_INSTRUCTION_LEN)
					{
						dwOffset = dwResLength + dwResOffset;
					}
					continue;
				}
				if(dwLength == 0x03 && strstr(da.result, "MOVZX EAX,AL") && iStg == 1)
				{
					iStg++;
					iNextInsCnt = 0;
				}
				if(dwLength == 0x02 && (strstr(da.result, "XOR AH,AH") || strstr(da.result, "XOR EAX,EAX")) && iStg == 1)
				{
					iStg++;
					iNextInsCnt = 0;
				}
				if(dwLength == 0x04 && (strstr(da.result, "MOV CL,[ESP+EAX+14]") || strstr(da.result, "MOV CL,[EAX+ESP+14]")) && iStg == 2)
				{
					iStg++;
					iNextInsCnt = 0;
				}
				if(dwLength == 0x04 && (strstr(da.result, "MOV ECX,[ESP+EAX+14]") || strstr(da.result, "MOV ECX,[EAX+ESP+14]")) && iStg == 2)
				{
					iStg++;
					iNextInsCnt = 0;
				}
				if(dwLength == 0x04 && (strstr(da.result, "PUSH DWORD PTR [ESP+EAX+14]") || strstr(da.result, "PUSH DWORD PTR [EAX+ESP+14]")) && iStg == 2)
				{
					iStg++;
					iNextInsCnt = 0;
				}
				if(dwLength == 0x03 && (strstr(da.result, "MOVZX E") && strstr(da.result, "X,CL")) && iStg == 3)
				{
					iStg++;
					iNextInsCnt = 0;
				}
				if(dwLength == 0x02 && strstr(da.result, "L,CL") && iStg == 3)
				{
					iStg++;
					iNextInsCnt = 0;
				}
				if(dwLength == 0x03 && strstr(da.result, "MOVZX EDX,DL") && iStg == 4)
				{
					iStg++;
					iNextInsCnt = 0;

				}
				if(dwLength == 0x02 && (strstr(da.result, "XOR DH,DH") || strstr(da.result, "XOR BH,BH")) && iStg == 4)
				{
					iStg++;
					iNextInsCnt = 0;
				}
				if((dwLength == 0x04 && 
					(strstr(da.result, "MOV DL,[ESP+ESI+14]") || strstr(da.result, "MOV EDX,[ESI+ESP+14]") ||
					 strstr(da.result, "MOV BH,[ESP+ESI+14]") || strstr(da.result, "MOV EDX,[ESP+ESI+14]"))
					&& iStg == 5))
				{
					iStg++;
					iNextInsCnt = 0;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Packed.W32.TDSS.AA"));
					return  VIRUS_FILE_DELETE;
				}
				if(dwLength == 0x03 && (strstr(da.result, "MOV D") || strstr(da.result, ",[ESP+ESI]")) && iStg == 5)
				{
					iStg++;
					iNextInsCnt = 0;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Packed.W32.TDSS.AA"));
					return  VIRUS_FILE_DELETE;
				}
			}
			DWORD dwLen = dwLength == 0 ? 1 : dwLength;
			dwOffset += dwLen;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Omkar Pardeshi + Virus Analysis Team
	Description		: Detection routine for : Tdss.Z
--------------------------------------------------------------------------------------*/
int CPolyTDSS::DetectTdssZ()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections >= 0x04 && m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size == 0 && m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 0x50 &&
		((m_wAEPSec == 0 && m_pSectionHeader[m_wAEPSec].VirtualAddress == 0x1000) || (m_wAEPSec >= 0 && m_pSectionHeader[m_wAEPSec].VirtualAddress >= 0x5000))&& 
		(m_pSectionHeader[m_wAEPSec].Characteristics & 0x60000020) == 0x60000020)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int TDSSZ_BUFF_SIZE = 0x2500;
		m_pbyBuff = new BYTE[TDSSZ_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, TDSSZ_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		DWORD dwChunk = m_pSectionHeader[m_wAEPSec].SizeOfRawData < TDSSZ_BUFF_SIZE ? m_pSectionHeader[m_wAEPSec].SizeOfRawData : TDSSZ_BUFF_SIZE;
		if(!GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData, dwChunk, dwChunk))
		{
			return iRetStatus;
		}

		for(DWORD dwReadOffset = 0; dwReadOffset < dwChunk; dwReadOffset++)
		{
			if((m_pbyBuff[dwReadOffset] == 0x55 && m_pbyBuff[dwReadOffset + 1] == 0x8B && m_pbyBuff[dwReadOffset + 2] == 0xEC) ||
				(m_pbyBuff[dwReadOffset] == 0x6A && m_pbyBuff[dwReadOffset + 1] == 0x00) ||
				(m_pbyBuff[dwReadOffset] == 0x81 && m_pbyBuff[dwReadOffset + 1] == 0xEC))
			{
				if(CheckTdssZInstructions(dwReadOffset))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Packed.W32.TDSS.Z"));
					return  VIRUS_FILE_DELETE;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckTdssZInstructions
	In Parameters	: DWORD dwOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Omkar Pardeshi + Virus Analysis Team
	Description		: Checks Instruction disassembly
--------------------------------------------------------------------------------------*/
bool CPolyTDSS::CheckTdssZInstructions(DWORD dwOffset)
{
	t_disasm da;
	m_dwInstCount = 0;
	DWORD dwLength = 0x00, dwInsCnt = 0, dwValidIns = 0, dwSubCnt = 0, dwJnzValue = 0;
	bool bXorFnd = false, bStosFnd = false, bSubFnd = false, bAddFnd = false, bRotFnd = false, bCntFnd = false, bJnzFnd = false; 

	while(dwOffset < m_dwNoOfBytes && m_dwInstCount <= 0x70)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffset))
		{
			break;
		}
		m_dwInstCount++;
		if(dwLength == 0x01 && strstr(da.result, "LODS ") && strstr(da.result,"PTR [ESI]") && dwInsCnt == 0)
		{
			dwInsCnt++;
			dwJnzValue = dwOffset;
		}
		if(dwLength == 0x02 && strstr(da.result, "PUSH DWORD PTR [ESI]") && dwInsCnt == 0)
		{
			dwInsCnt++;
			dwJnzValue = dwOffset;
		}
		if(dwInsCnt >= 1)
		{
			dwValidIns++;
		}
		if(dwValidIns > 0x19)
		{
			dwInsCnt	= 0;
			dwValidIns	= 0;
		}
		if(strstr(da.result, "XOR ") && dwInsCnt > 0)
		{
			dwInsCnt++;
			bXorFnd = true;
		}
		if(dwLength == 0x01 && strstr(da.result, "???") && dwInsCnt > 0) //STOS DWORD PTR [EDI]
		{
			dwInsCnt++;
			bStosFnd = true;
		}
		if(strstr(da.result, "SUB ") && dwInsCnt > 0)
		{
			dwInsCnt++;
			dwSubCnt++;
			bSubFnd = true;
		}
		if(strstr(da.result, "ADD ") && dwInsCnt > 0)
		{
			dwInsCnt++;
			dwSubCnt++;
			bAddFnd = true;
		}
		if(strstr(da.result, "ROR ") && dwInsCnt > 0)
		{
			dwInsCnt++;
			bRotFnd = true;
		}
		if(strstr(da.result, "ROL ") && dwInsCnt > 0)
		{
			dwInsCnt++;
			bRotFnd = true;
		}
		if(strstr(da.result, "TEST ECX,ECX") && dwInsCnt > 0)
		{
			dwInsCnt++;
			bCntFnd = true;
		}
		if(strstr(da.result, "POP ECX") && dwInsCnt > 0)
		{
			dwInsCnt++;
			bCntFnd = true;
		}
		if(strstr(da.result, "DEC ECX") && dwInsCnt > 0)
		{
			dwInsCnt++;
			bCntFnd = true;
		}
		if(strstr(da.result, "SUB ECX,1") && dwInsCnt > 0)
		{
			dwInsCnt++;
			bCntFnd = true;
		}
		if(strstr(da.result, "ADD ECX,-1") && dwInsCnt > 0)
		{
			dwInsCnt++;
			bCntFnd = true;
		}
		if(strstr(da.result, "JNZ ") && dwInsCnt > 0)
		{
			dwInsCnt++;
			if(dwJnzValue == *(DWORD *)&m_pbyBuff[dwOffset + 2] + dwOffset + dwLength)
			{
				bJnzFnd = true;
			}
		}
		if(dwInsCnt <= 0x19 && dwSubCnt >= 0x03 && bXorFnd && bStosFnd && bSubFnd && bAddFnd && bRotFnd && bCntFnd && bJnzFnd)
		{
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of TDSS Family
--------------------------------------------------------------------------------------*/
int CPolyTDSS::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;

	DWORD dwOrignalAep = 0;
	if(m_pMaxPEFile->ReadBuffer(&dwOrignalAep, (m_pSectionHeader[m_wNoOfSections-2].PointerToRawData + 8), sizeof(DWORD), sizeof(DWORD)))
	{
		m_pMaxPEFile->WriteAEP(dwOrignalAep);

		//fill virus stub with zero
		if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, TDSS_PATCH_LEN))
		{			
			iRetStatus = REPAIR_SUCCESS;
		}
	}
	return iRetStatus;    
}