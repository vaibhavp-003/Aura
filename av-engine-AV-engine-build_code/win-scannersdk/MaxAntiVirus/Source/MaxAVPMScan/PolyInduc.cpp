/*======================================================================================
FILE				: PolyInduc.cpp
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
NOTES				: This is detection module for malware Induc Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyInduc.h"
//#include "SemiPolyDBScn.h"
#include "MaxBMAlgo.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyInduc
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyInduc::CPolyInduc(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyInduc
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyInduc::~CPolyInduc(void)
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
	Description		: Detection routine for different varients of Induc Family
--------------------------------------------------------------------------------------*/
int CPolyInduc::DetectVirus(void)
{
	typedef int (CPolyInduc::*LPFNDetectVirus)();	
	LPFNDetectVirus pVirusList[] = 
	{	
		&CPolyInduc::DetectInducLG,
		&CPolyInduc::DetectInducIF,
		&CPolyInduc::DetectInducA,
		&CPolyInduc::DetectInducB	
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
	Function		: DetectInducA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for Induc.A
--------------------------------------------------------------------------------------*/
int CPolyInduc::DetectInducA(void)
{	
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(m_pSectionHeader[0].SizeOfRawData > 0x6000 && m_wNoOfSections >= 0x02 ||
		(m_pSectionHeader[0].SizeOfRawData > 0x6000 && m_wNoOfSections == 1 && memcmp(m_pSectionHeader[0].Name, ".maxs01", 7) == 0))//After Unpack FSG & MEW
	{		
		// This Part is to Identify Delphi File
		CMaxBMAlgo	*pBMScan = new CMaxBMAlgo;
		if (NULL == pBMScan)
		{
			return iRetStatus;
		}	

		BYTE byDelphiSig[] = {
			0x53, 0x4F, 0x46, 0x54, 0x57, 0x41, 0x52, 0x45, 0x5C, 0x42, 0x6F, 0x72, 0x6C, 0x61, 0x6E, 0x64, 
			0x5C, 0x44, 0x65, 0x6C, 0x70, 0x68, 0x69, 0x5C, 0x52, 0x54, 0x4C}; 

		if(pBMScan->AddPatetrn2Search(byDelphiSig, sizeof(byDelphiSig)))
		{		
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			m_pbyBuff = new BYTE[INDUC_BUFF_SIZE];
			if(GetBuffer(0x2000, 0x3000, 0x3000))
			{
				if(pBMScan->Search4Pattern(m_pbyBuff, m_dwNoOfBytes))
				{		
					delete pBMScan;
					pBMScan = NULL;

					// This Part is detect Induc.A Virus
					pBMScan = new CMaxBMAlgo;
					if (NULL == pBMScan)
					{
						return iRetStatus;
					}

					BYTE	byInducSig[] = {0x2D, 0x00, 0x00, 0x00, 0x75, 0x73, 0x65, 0x73, 0x20, 0x77, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73};
					if(pBMScan->AddPatetrn2Search(byInducSig, sizeof(byInducSig)))
					{
						memset(m_pbyBuff, 0x00, INDUC_BUFF_SIZE);
						if(GetBuffer(0x4000, INDUC_BUFF_SIZE, 0x10))
						{
							if(pBMScan->Search4Pattern(m_pbyBuff, m_dwNoOfBytes))
							{
								iRetStatus = VIRUS_FILE_DELETE;
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Induc.A"));		
							}
						}
						if(VIRUS_NOT_FOUND == iRetStatus && m_pSectionHeader[0].SizeOfRawData > 0x9000)
						{
							DWORD dwNextBuff = m_pSectionHeader[0].SizeOfRawData - 0x9000;
							if(dwNextBuff > 0x4000)
							{
								dwNextBuff = 0x4000;
							}
							memset(m_pbyBuff, 0x00, INDUC_BUFF_SIZE);
							if(GetBuffer(0x4000 + m_dwNoOfBytes, dwNextBuff, 0x10))
							{
								if (pBMScan->Search4Pattern(m_pbyBuff, m_dwNoOfBytes))
								{
									iRetStatus = VIRUS_FILE_DELETE;
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Induc.A"));		
								}	
							}
						}
					}
				}
			}
		}
		delete pBMScan;
		pBMScan = NULL;	
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectInducLG
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for Induc.L and Induc.G 
--------------------------------------------------------------------------------------*/
int CPolyInduc::DetectInducLG()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pSectionHeader[0].SizeOfRawData > 0x3000 && m_wNoOfSections > 0x02 && m_wAEPSec == 0)
	{
		BYTE byAEPSig[] = {0x55, 0x8B, 0xEC, 0x83, 0xC4, 0xF0, 0xB8}; 
		BYTE byBuff[10] = {0}; 
		if(m_pMaxPEFile->ReadBuffer(byBuff, m_dwAEPMapped, 10, sizeof(byAEPSig)))
		{
			if(memcmp(&byBuff[0], byAEPSig, sizeof(byAEPSig)) == 0)
			{
				BYTE byInduc_LG_Sig[] = {
					0x44, 0x51, 0x70, 0x6D, 0x64, 0x57, 0x35, 0x6A, 0x64, 0x47,
					0x6C, 0x76, 0x62, 0x69, 0x42, 0x48, 0x62, 0x47, 0x39, 0x69}; 
			
				CMaxBMAlgo	*pBMScan = new CMaxBMAlgo;
				if (NULL == pBMScan)
					return iRetStatus;

				if(pBMScan->AddPatetrn2Search(byInduc_LG_Sig,sizeof(byInduc_LG_Sig)))
				{			
					DWORD dwOffset = (m_dwAEPMapped > INDUC_LG_BUFF_SIZE) ? m_dwAEPMapped - INDUC_LG_BUFF_SIZE : 0;						
					
					if(m_pbyBuff)
					{
						delete []m_pbyBuff;
						m_pbyBuff = NULL;
					}
					m_pbyBuff = new BYTE[INDUC_LG_BUFF_SIZE];			
					if(GetBuffer(dwOffset, (m_dwAEPMapped - dwOffset), (m_dwAEPMapped - dwOffset)))
					{
						if(pBMScan->Search4Pattern(m_pbyBuff, m_dwNoOfBytes))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Induc.lg"));
							iRetStatus = VIRUS_FILE_DELETE;
						}
					}
				}
				delete pBMScan;
				pBMScan = NULL;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectInducIF
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for Induc.IF
--------------------------------------------------------------------------------------*/
int CPolyInduc::DetectInducIF()
{
	if(m_pSectionHeader[0].SizeOfRawData > 0x3000 && m_wNoOfSections > 0x02 && m_wAEPSec == 0 && m_pSectionHeader[2].SizeOfRawData == 0x0000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x50];			
		if(GetBuffer(0x23F0, 0x50, 0x30))
		{
			BYTE bInducSig[] = {0x54, 0x24, 0x04, 0x89, 0x02, 0x8B, 0xC3, 0x83, 0xC4, 0x0C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3, 
								0x00, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x20, 0x6D, 0x79, 0x5F, 0x61, 0x72, 0x72, 0x61, 0x79, 
								0x3A, 0x61, 0x72, 0x72, 0x61, 0x79, 0x20, 0x5B, 0x30, 0x2E, 0x2E, 0x00, 0x00, 0x00, 0x5D, 
								0x20, 0x6F, 0x66};
			
			if(memcmp(&m_pbyBuff[0x00], bInducSig, sizeof(bInducSig)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Induc.if"));
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectInducB
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for Induc.B 
--------------------------------------------------------------------------------------*/
int CPolyInduc::DetectInducB(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x3 && memcmp(m_pSectionHeader[m_wAEPSec].Name, ".naked2", 7) == 0 && 
		memcmp(m_pSectionHeader[0].Name, ".naked1", 7) == 0 && m_pSectionHeader[0].SizeOfRawData == 0x0 && m_pSectionHeader[0].PointerToRawData == 0x0
		&& m_pMaxPEFile->m_stPEHeader.CheckSum == 0x0 && m_dwAEPUnmapped == 0x28050 &&
		m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x13400 && m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x400 &&
		m_pSectionHeader[m_wAEPSec].VirtualAddress == 0x28000 && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x14000 &&
		m_pSectionHeader[m_wAEPSec].Characteristics  == 0xE0000040)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int INDUCB_BUFF_SIZE = 0x200;
		m_pbyBuff = new BYTE[INDUCB_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		const BYTE INDUCB_SIG1[] = {0x53,0xFF,0x4F,0x46,0x54,0x57,0x41,0x52,0x45,0x5C,0xFF,0x42,0x6F,0x72,0x6C,0x61,0x6E,0x64,0x5C,0xFF,0x44,0x65,0x6C,0x70,0x68,0x69,0x5C,0x52,0xFF,0x54,0x4C};
		const BYTE INDUCB_SIG2[] = {0x2D,0x20,0x1B,0x60,0x73,0x65,0xC0,0x73,0x20,0x2F,0xC4,0x64,0x6F,0x77,0xC5,0x73};
		if(!GetBuffer(0x2DB6, 0x20, 0x20))
		{
			return iRetStatus;
		}
		if(memcmp(&m_pbyBuff[0], INDUCB_SIG1, sizeof(INDUCB_SIG1)) == 0)
		{
			if(!GetBuffer(0x58CE , 0x10, 0x10))
			{
				return iRetStatus;
			}
			if(memcmp(&m_pbyBuff[0], INDUCB_SIG2, sizeof(INDUCB_SIG2)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Induc.B"));	
				DWORD dwOverlayStart = m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
				if(dwOverlayStart > m_pMaxPEFile->m_dwFileSize || dwOverlayStart == m_pMaxPEFile->m_dwFileSize)
				{
					return VIRUS_FILE_DELETE;
				}
				if(!GetBuffer(dwOverlayStart, INDUCB_BUFF_SIZE, INDUCB_BUFF_SIZE))
				{
					return iRetStatus;
				}
				if(m_pbyBuff[0] == 0x4D && m_pbyBuff[1] == 0x5A)
				{
					m_dwReplaceOffset = dwOverlayStart;
					m_dwTruncateSize =  m_pMaxPEFile->m_dwFileSize - m_dwReplaceOffset;
					return VIRUS_FILE_REPAIR;
				}
				return VIRUS_FILE_DELETE;
			}
		}
	}
	/*
	Commented for VB100 False (+)ve
	//neeraj 14-7-12
	else if(m_wNoOfSections >= 7 && 
		   (memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".data", 5) == 0) && 
		  ((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000040) == 0xE0000040)) 
	{
		if(m_wAEPSec == 0)
		{
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			const int INDUCB_BUFF_SIZE = 0x120;
			m_pbyBuff = new BYTE[INDUCB_BUFF_SIZE];
			if(!m_pbyBuff)
			{
				return iRetStatus;
			}
			if(!GetPatchedCalls(m_dwAEPMapped, m_dwAEPMapped + 0x100, m_wNoOfSections - 1, true, true))
			{
				return iRetStatus;
			}
			DWORD dwCalledAdd = 0;
			BYTE  byKey = 0;
			if(m_arrPatchedCallOffsets.GetCount())
			{	
				LPVOID	lpos = m_arrPatchedCallOffsets.GetHighest();
				while(lpos)
				{
					m_arrPatchedCallOffsets.GetData(lpos, dwCalledAdd);
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwCalledAdd, &dwCalledAdd))
					{
						if(GetBuffer(dwCalledAdd, INDUCB_BUFF_SIZE, INDUCB_BUFF_SIZE))
						{
							if(m_pbyBuff[0] == 0x60)
							{
								DWORD dwCnt = 0;
								for(dwCnt = 0; dwCnt < INDUCB_BUFF_SIZE - 0x10; dwCnt++)
								{
									if(m_pbyBuff[dwCnt] == 0x30 && m_pbyBuff[dwCnt + 1] == 0x10 &&     //Xor,inc,dec
									   m_pbyBuff[dwCnt + 2] == 0x40 && m_pbyBuff[dwCnt + 3] == 0x49)
									{
										byKey = m_pbyBuff[dwCnt - 4];
										break;
									}
								}
								if(byKey > 0)
								{
									for(DWORD dwCount = dwCnt + 0x0F; dwCount < INDUCB_BUFF_SIZE - 0x10; dwCount++)
									{
										m_pbyBuff[dwCount] ^= byKey;
									}
								}
								if(CheckInducBDecData(dwCnt, INDUCB_BUFF_SIZE - 0x10))
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Induc.B"));
									return VIRUS_FILE_DELETE;
								}
							}
						}
					}
					lpos = m_arrPatchedCallOffsets.GetHighestNext(lpos);
				}
			}
		}
	}
	*/
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckInducBDecData
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function retrieves decryption data for induc.B  
--------------------------------------------------------------------------------------*/
bool CPolyInduc::CheckInducBDecData(DWORD dwStartIndex, DWORD dwEndIndex)
{
	t_disasm da;
	m_dwInstCount = 0;
	DWORD dwOffset = dwStartIndex, dwLength = 0, dwInstCnt = 0;
	while(dwOffset < dwEndIndex && m_dwInstCount <= 0x20)
	{		
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (dwEndIndex - dwOffset))
		{
			break;
		}
		m_dwInstCount++;
		if(dwLength == 0x05 && strstr(da.result, "JMP ") && dwInstCnt == 0)
		{
			DWORD dwOffsetTemp = dwOffset + *(DWORD *)&m_pbyBuff[dwOffset + 1] + 5;
			if(dwOffsetTemp < dwEndIndex)
			{
				dwOffset = dwOffsetTemp;
				dwInstCnt++;
				continue;
			}
		}
		if(dwLength == 0x02 && strstr(da.result, "PUSH 40") && dwInstCnt == 1)
		{
			dwInstCnt++;
		}
		if(dwLength == 0x05 && strstr(da.result, "PUSH 1000") && dwInstCnt == 2)
		{
			dwInstCnt++;
		}
		if(dwLength == 0x06 && strstr(da.result, "CALL [EBP+") && dwInstCnt == 3)
		{
			dwInstCnt++;
		}
		if(dwLength == 0x02 && strstr(da.result, "MUL EDX") && dwInstCnt == 4)
		{
			dwInstCnt++;
		}
		if(dwLength == 0x06 && strstr(da.result, "MOV EAX,[ECX+C]") && dwInstCnt == 5)
		{
			dwInstCnt++;
		}
		if(dwLength == 0x03 && strstr(da.result, "ADD [ESP],EBP") && dwInstCnt == 6)
		{
			dwInstCnt++;
		}
		if(dwLength == 0x05 && strstr(da.result, "PUSH 0") && dwInstCnt == 7)
		{
			dwInstCnt++;
		}
		if(dwLength == 0x05 && strstr(da.result, "CALL") && dwInstCnt == 8)
		{
			if(*(DWORD *)&m_pbyBuff[dwOffset + 1] == 0x05)
			{
				return true;
			}
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
	Description		: Repair routine for different varients of Induc Family
--------------------------------------------------------------------------------------*/
int CPolyInduc::CleanVirus(void)
{	
	int iRetStatus = REPAIR_FAILED;
	if(m_pMaxPEFile->CopyData(m_dwReplaceOffset, 0, m_dwTruncateSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwTruncateSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}