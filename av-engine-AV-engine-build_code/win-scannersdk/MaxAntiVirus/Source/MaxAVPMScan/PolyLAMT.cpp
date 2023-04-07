/*======================================================================================
FILE				: PolyLAMT.cpp
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
NOTES				: This is detection module for malware LAMT Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyLAMT.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyLAMT
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyLAMT::CPolyLAMT(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyLAMT
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyLAMT::~CPolyLAMT(void)
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
	Description		: Detection routine for different varients of LAMT Family
--------------------------------------------------------------------------------------*/
int CPolyLAMT::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pSectionHeader[m_wNoOfSections-1].Name[1] == 0x4C && 
		m_pSectionHeader[m_wNoOfSections-1].Name[2] == 0x4D && 
		m_pSectionHeader[m_wNoOfSections-1].Name[3] == 0x54 && 
		m_pSectionHeader[m_wNoOfSections-1].Name[4] == 0x2D && 
		m_pSectionHeader[m_wNoOfSections-1].Name[5] == 0x41 && 
		m_wNoOfSections > 1 &&  
		m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData >= 0xC00 && 
		(m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL)!= IMAGE_FILE_DLL && 
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000000)== 0xE0000000)
	{
		BYTE bSignature1[] = { 0x8B, 0x04, 0x24, 0x60, 0x9C, 0xE8, 0x04, 0x00, 0x00, 0x00 };
		BYTE bSignature2[] = { 0x5D, 0x81, 0xED, 0x11, 0x10, 0x40, 0x00, 0x89, 0x85, 0x11, 0x10, 0x40,
							   0x00, 0x8D, 0x95, 0x47, 0x15, 0x40, 0x00, 0x8B, 0x8D, 0x51, 0x15, 0x40,
							   0x00, 0x89, 0x0A, 0x8D, 0xBD, 0x40, 0x10, 0x40, 0x00, 0x8B, 0xF7, 0x8D,
							   0x85, 0x22, 0x1B, 0x40, 0x00, 0xFF, 0xD0 };
		
		m_pbyBuff = new BYTE[LAMT_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, LAMT_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(!GetBuffer(m_dwAEPMapped, LAMT_SIG_BUFF_SIZE, LAMT_SIG_BUFF_SIZE))
		{
			return iRetStatus;
		}

		if(m_dwNoOfBytes == LAMT_SIG_BUFF_SIZE &&
			memcmp(m_pbyBuff, bSignature1, 10)== 0 && 
			memcmp(&m_pbyBuff[14], bSignature2, 43)== 0)
		{
			if(GetBuffer(m_dwAEPMapped + 0xB1B, LAMT_BUFF_SIZE))
			{
				if(GetLAMTParamters())
				{
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL))
					{						
						iRetStatus = VIRUS_FILE_REPAIR;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.LAMT"));		
					}
				}
			}
		}	
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: GetLAMTParamters
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: 10 Jan 2011 : For decryption o W23.LAMT
--------------------------------------------------------------------------------------*/
bool CPolyLAMT::GetLAMTParamters()
{
	BYTE byAEP[4] = {0};
	if(!m_pMaxPEFile->ReadBuffer(byAEP, m_dwAEPMapped + 0x54A, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}

	m_objMaxDisassem.InitializeData();
	BYTE B1, B2;
	DWORD dwOffSet = 0x00 , dwLength = 0x00;

	B1 = B2 = 0x00;
	t_disasm da;

	while(dwOffSet < m_dwNoOfBytes)
	{
		B1 = m_pbyBuff[dwOffSet];
		B2 = m_pbyBuff[dwOffSet + 0x01];
		
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x02;
			continue;
		}
		if(B1==0xE2 &&(B2>=0xF0 && B2<=0xFF))// Added for 'LOOP' instruction
		{
			dwOffSet+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char* )&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffSet))
		{
			return false;
		}
		
		if(B1 == 0x90 && dwLength == 0x01 && strstr(da.result,"NOP"))
		{
			dwOffSet += dwLength;
			continue;
		}

		if(B1 == 0xF6 && dwLength == 0x02 && strstr(da.result,"NOT AL"))
		{
			byAEP[0] = ~byAEP[0];
			byAEP[1] = ~byAEP[1];
			byAEP[2] = ~byAEP[2];
			byAEP[3] = ~byAEP[3];
			dwOffSet += dwLength;
			continue;
		}
		if(B1 == 0xF6 && dwLength == 0x02 && strstr(da.result,"NEG AL"))
		{
			byAEP[0] = ~byAEP[0] + 0x01;
			byAEP[1] = ~byAEP[1] + 0x01;
			byAEP[2] = ~byAEP[2] + 0x01;
			byAEP[3] = ~byAEP[3] + 0x01;
			dwOffSet += dwLength;
			continue;
		}

		if(B1 == 0x04 && dwLength == 0x02 && strstr(da.result,"ADD AL,"))
		{
			byAEP[0] +=(BYTE)da.immconst;
			byAEP[1] +=(BYTE)da.immconst;
			byAEP[2] +=(BYTE)da.immconst;
			byAEP[3] +=(BYTE)da.immconst;
			dwOffSet += dwLength;
			continue;
		}
		if(B1 == 0x2C && dwLength == 0x02 && strstr(da.result,"SUB AL,"))
		{
			byAEP[0] -=(BYTE)da.immconst;
			byAEP[1] -=(BYTE)da.immconst;
			byAEP[2] -=(BYTE)da.immconst;
			byAEP[3] -=(BYTE)da.immconst;
			dwOffSet += dwLength;
			continue;
		}
		if(/*B1 == 0x2C &&*/ dwLength == 0x02 && strstr(da.result,"XOR AL,"))
		{
			byAEP[0] ^=(BYTE)da.immconst;
			byAEP[1] ^=(BYTE)da.immconst;
			byAEP[2] ^=(BYTE)da.immconst;
			byAEP[3] ^=(BYTE)da.immconst;
			dwOffSet += dwLength;
			continue;
		}

		if(/*B1 == 0x2C &&*/ dwLength == 0x02 && strstr(da.result,"DEC AL"))
		{
			byAEP[0] -=(BYTE)0x01;
			byAEP[1] -=(BYTE)0x01;
			byAEP[2] -=(BYTE)0x01;
			byAEP[3] -=(BYTE)0x01;
			dwOffSet += dwLength;
			continue;
		}

		if(dwLength == 0x02 && strstr(da.result,"INC AL"))
		{
			byAEP[0] +=(BYTE)0x01;
			byAEP[1] +=(BYTE)0x01;
			byAEP[2] +=(BYTE)0x01;
			byAEP[3] +=(BYTE)0x01;
			dwOffSet += dwLength;
			continue;
		}

		if(dwLength == 0x03 && strstr(da.result,"ROL AL,"))
		{
			da.immconst = da.immconst % 0x08;
			
			byAEP[0] = byAEP[0] << da.immconst | byAEP[0] >>(0x08 - da.immconst); 
			byAEP[1] = byAEP[1] << da.immconst | byAEP[1] >>(0x08 - da.immconst);
			byAEP[2] = byAEP[2] << da.immconst | byAEP[2] >>(0x08 - da.immconst);
			byAEP[3] = byAEP[3] << da.immconst | byAEP[3] >>(0x08 - da.immconst);
			
			dwOffSet += dwLength;
			continue;
		}
		if(dwLength == 0x03 && strstr(da.result,"ROR AL,"))
		{
			da.immconst = da.immconst % 0x08;
			
			byAEP[0] = byAEP[0] >> da.immconst | byAEP[0] <<(0x08 - da.immconst); 
			byAEP[1] = byAEP[1] >> da.immconst | byAEP[1] <<(0x08 - da.immconst);
			byAEP[2] = byAEP[2] >> da.immconst | byAEP[2] <<(0x08 - da.immconst);
			byAEP[3] = byAEP[3] >> da.immconst | byAEP[3] <<(0x08 - da.immconst);
			dwOffSet += dwLength;
			continue;
		}
		if(B1 == 0xAA && dwLength == 0x01 && strstr(da.result ,"???"))
		{
			m_dwOriginalAEP =(*(DWORD *)&byAEP[0])- m_dwImageBase;
			return true;
		}
		dwOffSet += dwLength;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of LAMT Family
--------------------------------------------------------------------------------------*/
int CPolyLAMT::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	
	m_pMaxPEFile->WriteAEP(m_dwOriginalAEP);	
	if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}
