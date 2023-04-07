/*======================================================================================
FILE				: PolyLevi.cpp
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
NOTES				: This is detection module for malware Levi Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyLevi.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyLevi
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyLevi::CPolyLevi(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyLevi
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyLevi::~CPolyLevi(void)
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
	Description		: Detection routine for different varients of Levi Family
--------------------------------------------------------------------------------------*/
int CPolyLevi::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	WORD wReservedBytes = 0;
	m_pMaxPEFile->ReadBuffer(&wReservedBytes, 0x28, sizeof(WORD), sizeof(WORD));
	if(wReservedBytes != 0x0001 || m_wAEPSec != m_wNoOfSections - 1)
	{
		return iRetStatus;
	}

	m_pbyBuff = new BYTE[LEVI_BUFF_SIZE];	
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	if(GetBuffer(m_dwAEPMapped, LEVI_BUFF_SIZE, LEVI_BUFF_SIZE))
	{
		// Detection for Levi.2961, Levi.2973 ,Levi.3090, Levi.3137
		const BYTE bySignature[] = {0x0A, 0x10, 0x40, 0x00};
		const BYTE bySignature1[] = {0x42, 0x10, 0x40, 0x00};

		if(m_pbyBuff[0] == 0x50 && m_pbyBuff[1] == 0x60 && m_pbyBuff[5] == 0xE8 && 
			(memcmp(&m_pbyBuff[0x13], bySignature, sizeof(bySignature)) == 0) && 
			(memcmp(&m_pbyBuff[0x24], bySignature1, sizeof(bySignature1)) == 0)) 
		{		
			iFlag = 0x01;			// done changes here 

			if(GetLeviParam())
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Levi"));
				return VIRUS_FILE_REPAIR;
			}
		}

		//Detection for Levi.3236
		const BYTE Levi3236Sig1[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x8B, 0x2C, 0x24};
		const BYTE Levi3236Sig2[] = {0x81, 0xED, 0x07, 0x10, 0x40, 0x00};
		const BYTE Levi3236Sig3[] = {0xB9, 0x1D, 0x03, 0x00, 0x00};

		if(m_pbyBuff[0] == 0x60 && m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x556E6169 && 
			(memcmp(&m_pbyBuff[0x2], Levi3236Sig1, sizeof(Levi3236Sig1))==0) && 
			(memcmp(&m_pbyBuff[0xC], Levi3236Sig2, sizeof(Levi3236Sig2))==0)&&
			(memcmp(&m_pbyBuff[0x1A], Levi3236Sig3, sizeof(Levi3236Sig3))==0))
		{
			if(m_pMaxPEFile->ReadBuffer(&m_dwOriginalAEP, m_dwAEPMapped - 0xAB2, 4, 4))
			{
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Levi.3236"));
					return VIRUS_FILE_REPAIR;
				}
			}
		}

		// Detection for Levi.3040
		const BYTE Levi3040Sig1[] = {0x81, 0xED, 0x07, 0x10, 0x40, 0x00};
		const BYTE Levi3040Sig2[] = {0x8D, 0xB5, 0x2F, 0x10, 0x40, 0x00};
		const BYTE Levi3040Sig3[] = {0xB9, 0xEC, 0x02, 0x00, 0x00};

		if(m_pbyBuff[0] == 0x60 && m_pbyBuff[2] == 0xE8 && m_pbyBuff[8] == 0x8B 
			&& m_pbyBuff[9] == 0x2C && m_pbyBuff[10] == 0x24 && 
			(memcmp(&m_pbyBuff[0xC], Levi3040Sig1, sizeof(Levi3040Sig1))==0) && 
			(memcmp(&m_pbyBuff[0x13], Levi3040Sig2, sizeof(Levi3040Sig2))==0) &&
			(memcmp(&m_pbyBuff[0x1A], Levi3040Sig3, sizeof(Levi3040Sig3))==0))
		{	
			DWORD dwKey = 0;
			if(m_pMaxPEFile->ReadBuffer(&dwKey, m_dwAEPMapped + 0x21, 4))
			{
				BYTE byAEP[8] = {0};
				if(m_pMaxPEFile->ReadBuffer(byAEP , m_dwAEPMapped + 0x8D3, 8, 8))				
				{
					for(DWORD i = 0; i < 8; i += 4)
					{
						*((DWORD *) &byAEP[i]) = *((DWORD *) &byAEP[i]) ^ dwKey;
					}
					m_dwOriginalAEP =  *((DWORD *)&byAEP[0x3]);
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Levi.3040"));
						return VIRUS_FILE_REPAIR;
					}
				}
			}
		}

		// Detection for Levi.3205
		const BYTE Levi3205Sig[] = {0x60, 0xE8, 0x06, 0x00, 0x00, 0x00, 0x8B, 0x64, 0x24, 0x08, 0xEB, 0x0C,
			0x33, 0xD2, 0x64, 0xFF, 0x32, 0x64, 0x89, 0x22, 0xFE, 0x02, 0xEB, 0xE8, 
			0x33, 0xD2, 0x64, 0x8F, 0x02, 0x5A, 0x61, 0x50, 0x60};

		if(memcmp(m_pbyBuff, Levi3205Sig, sizeof(Levi3205Sig)) == 0) 
		{
			if(GetLeviParam())
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Levi.3205"));
				return VIRUS_FILE_REPAIR;
			}
		}
		
		// Detection for Levi.3244
		const BYTE Levi3244Sig1[] = {0x81, 0xED, 0x07, 0x00, 0x41, 0x00};
		const BYTE Levi3244Sig2[] = {0x8D, 0xB5, 0x2F, 0x00, 0x41, 0x00};
		const BYTE Levi3244Sig3[] = {0x83, 0xC6, 0x04};
		
		if(m_pbyBuff[0] == 0x60 && m_pbyBuff[2] == 0xE8 && m_pbyBuff[8] == 0x8B
			&& m_pbyBuff[9] == 0x2C && m_pbyBuff[0xA] == 0x24 && 
			(memcmp(&m_pbyBuff[0xC], Levi3244Sig1, sizeof(Levi3244Sig1)) == 0) && 
			(memcmp(&m_pbyBuff[0x13], Levi3244Sig2, sizeof(Levi3244Sig2)) == 0) &&
			(memcmp(&m_pbyBuff[0x29], Levi3244Sig3, sizeof(Levi3244Sig3)) == 0))			
		{	
			DWORD dwKey = 0;
			if(m_pMaxPEFile->ReadBuffer(&dwKey, m_dwAEPMapped + 0x21, 4))
			{
				BYTE byAEP[8] = {0};
				if(m_pMaxPEFile->ReadBuffer(byAEP, m_dwAEPMapped + 0x8DB, 8, 8))				
				{
					for(DWORD i = 0; i < 8; i += 4)
					{
						*((DWORD *) &byAEP[i]) = *((DWORD *) &byAEP[i]) ^ dwKey;
					}
					m_dwOriginalAEP =  *((DWORD *)&byAEP[0x3]);
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Levi.3244"));
						return VIRUS_FILE_REPAIR;
					}
				}
			}
		}
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: GetLeviParam
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for varients  : Levi.2961, Levi.2973, Levi.3205 ,Levi.3090, Levi.3137
--------------------------------------------------------------------------------------*/
int CPolyLevi::GetLeviParam()
{
	int iRetStatus = VIRUS_NOT_FOUND;
		
	DWORD		dwLength = 0,  dwOffset = 0, dwMatchedInstr = 0, dwXORKey = 0, dwConstantVal = 0;	    
	t_disasm	da;
	BYTE byAEP[8] = {0};

	while(dwOffset < m_dwNoOfBytes)
	{		
		memset(&da, 0x00, sizeof(struct t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	
		
		if(dwMatchedInstr == 0 && dwLength == 5 && strstr(da.result, "MOV"))
		{
			dwMatchedInstr++;
			dwConstantVal = da.immconst;			
		}
		else if(dwMatchedInstr == 1 && dwLength == 6 && strstr(da.result, "LEA"))
		{
			dwMatchedInstr++;
		}
		else  if(dwMatchedInstr == 2 && dwLength == 6 && strstr(da.result, "XOR"))
		{
			dwMatchedInstr++;
			dwXORKey = da.immconst;	// XOR Key
		}
		else if(dwMatchedInstr == 3 && dwLength == 3 && strstr(da.result, "ADD"))
		{
			dwMatchedInstr++;
		}
		else if(dwMatchedInstr == 4 && dwLength == 1 && strstr(da.result, "DEC"))
		{	
			if(dwConstantVal == 0x2D4) //Levi.2961
			{
				dwOffset = 0xAD6;
			}
			else if(dwConstantVal == 0x2D7) //Levi.2973
			{
				dwOffset = 0xAE2;
			}
			else if(dwConstantVal == 0x309) //Levi.3205, 3137    
			{
				if(iFlag == 0x01)			 //Done changes here
					dwOffset = 0xBAA;		//Levi.3137
				else
					dwOffset = 0xBC9;		//Levi.3205
			}
			else if(dwConstantVal == 0x2F4) //Levi.3090
			{
				dwOffset = 0xB56;
			}
			else
			{
				return false;
			}
			
			if(m_pMaxPEFile->ReadBuffer(byAEP, m_dwAEPMapped + dwOffset, 8, 8)) 
			{
				*((DWORD *) &byAEP[0]) ^= dwXORKey;
				m_dwOriginalAEP =  *((DWORD *)&byAEP[0]);

				if(dwConstantVal == 0x2F4) //Levi.3090
				{
					*((DWORD *) &byAEP[4]) ^= dwXORKey;
					m_dwOriginalAEP =  *((DWORD *)&byAEP[0x1]);
				}
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL))
				{
					return true;
				}
			}
			return false;		
		}
		dwOffset += dwLength;
	}
	return iRetStatus;
}		

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Levi Family
--------------------------------------------------------------------------------------*/
int CPolyLevi::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x556E6169) //Levi.3236
		{
			m_pMaxPEFile->TruncateFile(m_dwAEPMapped - 0xEA6,true);
			m_pMaxPEFile->FillWithZeros(0xCC,4);			
		}
		else
		{
			m_pMaxPEFile->TruncateFile(m_dwAEPMapped,true);
		}	

		if(m_pMaxPEFile->FillWithZeros(0x28, 1))
		{
			return REPAIR_SUCCESS;						 
		}
	}
	return iRetStatus;
}