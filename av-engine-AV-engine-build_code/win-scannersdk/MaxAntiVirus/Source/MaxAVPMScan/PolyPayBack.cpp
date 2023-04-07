/*======================================================================================
FILE				: PolyPayBack.cpp
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
NOTES				: This is detection module for malware PayBack Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyPayBack.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyPayBack
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyPayBack::CPolyPayBack(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	memset(&m_objPayback_Struct, 0x00, sizeof(Payback_Struct));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyPayBack
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyPayBack::~CPolyPayBack(void)
{
	delete []m_pbyBuff;
	m_pbyBuff = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Omkar + Virus Analysis Team
	Description		: Detection routine for different varients of PayBack Family
--------------------------------------------------------------------------------------*/
int CPolyPayBack::DetectVirus()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	
	m_pbyBuff = new BYTE[DECRYPTN_LOOP_SZ + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, DECRYPTN_LOOP_SZ + MAX_INSTRUCTION_LEN);
	if(GetBuffer(m_dwAEPMapped, 0x9, 0x9))
	{
		t_disasm da;
		DWORD dwStart = 0, dwLength = 0, dwSeq = 0; 
		bool bInstFound = false;
		while( dwStart < 0x9)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwStart], MAX_INSTRUCTION_LEN, m_dwImageBase, &da, DISASM_CODE);
			if(dwLength > (0x9 - dwStart))
			{
				break;
			}			
			// Patch At AEP of Size 9
			if(strstr(da.result, "PUSH EAX") && dwLength == 1 && dwSeq == 0)
			{
				dwSeq++;
				dwStart += dwLength;
				continue;
			}
			else if(strstr(da.result, "MOV DWORD PTR [ESP]") && dwLength == 7 && dwSeq == 1)
			{
				m_objPayback_Struct.dwDecryptionLOff = da.immconst - m_dwImageBase;				
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_objPayback_Struct.dwDecryptionLOff, &m_objPayback_Struct.dwDecryptionLOff))
				{
					bInstFound = true;
				}				
				break;
			}
			// Decryption Loop At AEP
			else if(strstr(da.result, "PUSH") && dwLength == 5 && dwSeq == 0)
			{				
				m_objPayback_Struct.dwDecryptionLOff = m_dwAEPMapped;		
				bInstFound = true;
				break;
			}
			dwStart += dwLength;
		}
		if(bInstFound)
		{
			if(GetDecryptionParameters())
			{
				if(DecryptAepBuffer())
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Payback"));
					iRetStatus = VIRUS_FILE_REPAIR;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDecryptionParameters
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Omkar + Virus Analysis Team
	Description		: Dissassemble virus body to get parameter for  decryption
--------------------------------------------------------------------------------------*/
bool CPolyPayBack::GetDecryptionParameters()
{
	const int VIRUS_SIG_SIZE = 48;
	const BYTE bySignature[VIRUS_SIG_SIZE] = {
		0x00, 0x00, 0x56, 0x69, 0x72, 0x75, 0x73, 0x3A, 
		0x27, 0x50, 0x4F, 0x4C, 0x59, 0x4D, 0x45, 0x52,
		0x41, 0x53, 0x45, 0x2D, 0x42, 0x27, 0x2E, 0x20, 
		0x43, 0x6F, 0x64, 0x65, 0x64, 0x20, 0x62, 0x79,
		0x20, 0x50, 0x61, 0x79, 0x62, 0x61, 0x63, 0x6B, 
		0x28, 0x52, 0x75, 0x73, 0x73, 0x69, 0x61, 0x29};
	
	// Decryption buffer size 7D
	if(GetBuffer(m_objPayback_Struct.dwDecryptionLOff, DECRYPTN_LOOP_SZ, DECRYPTN_LOOP_SZ))
	{
		t_disasm da;
		DWORD dwStart = 0, dwLength = 0,dwSeq= 0; 
		while(dwStart < DECRYPTN_LOOP_SZ)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwStart], MAX_INSTRUCTION_LEN, m_dwImageBase, &da, DISASM_CODE);
			if(dwLength > (DECRYPTN_LOOP_SZ - dwStart))
			{
				return false;
			}

			if(strstr(da.result, "PUSH") && dwLength == 5 && dwSeq == 0)
			{
				m_objPayback_Struct.dwVirusBodyOffset = da.immconst-m_dwImageBase + 4;
				m_objPayback_Struct.dwAEPBuffOffset   = da.immconst-m_dwImageBase + 4 + 0xF1C;
				m_objPayback_Struct.dwVirusSignOffset = da.immconst-m_dwImageBase + 4 + 0x12F4;
				dwSeq++;
				dwStart += dwLength;
				continue;
			}	
			if((strstr(da.result, "XOR ECX") && dwLength == 2 && dwSeq == 1) || 
			(strstr(da.result, "MOV EAX,[ESP]") && dwLength == 3 && dwSeq == 2))
			{
				dwSeq++;
			}
			if(strstr(da.result, "MOV EDX,") && dwLength == 5 && dwSeq == 3)
			{
				m_objPayback_Struct.dwDecryptionKey = da.immconst;
			}
			if(strstr(da.result, "XOR [ECX+EAX],EDX") && dwLength == 3 && dwSeq == 3)
			{
				dwSeq++;
			}
			if(strstr(da.result, "XOR DWORD PTR [ECX+EAX]") && dwLength == 7 && dwSeq == 3)
			{
				m_objPayback_Struct.dwDecryptionKey = da.immconst;
				dwSeq++;
			}
			if((strstr(da.result, "CMP") || strstr(da.result, "MOV")) && dwSeq == 4)
			{
				if(da.immconst == VIRUS_BODY_SZ)
				{
					// check for virus signature 12F4 dwVirusSignOffset					
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_objPayback_Struct.dwVirusSignOffset, &m_objPayback_Struct.dwVirusSignOffset))
					{
						if(GetBuffer(m_objPayback_Struct.dwVirusSignOffset, VIRUS_SIG_SIZE, VIRUS_SIG_SIZE))
						{						
							for(int i = 0; i <= 44; i += 4)
							{
								*(DWORD *)&m_pbyBuff[i] ^= m_objPayback_Struct.dwDecryptionKey;
							} 
							//Check For virus Sign
							if(!memcmp(m_pbyBuff, bySignature, VIRUS_SIG_SIZE))
							{
								return true;
							}
						}
					}
				}
			}
			dwStart += dwLength;				
		}//end while
	}// end if
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptAepBuffer
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Omkar + Virus Analysis Team
	Description		: Decrypt and get aep
--------------------------------------------------------------------------------------*/
bool CPolyPayBack::DecryptAepBuffer()
{
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_objPayback_Struct.dwAEPBuffOffset, &m_objPayback_Struct.dwAEPBuffOffset))
	{
		if(GetBuffer(m_objPayback_Struct.dwAEPBuffOffset, 0x8, 0x8))
		{  
			*(DWORD*)&m_pbyBuff[0] ^= m_objPayback_Struct.dwDecryptionKey;
			*(DWORD*)&m_pbyBuff[4] ^= m_objPayback_Struct.dwDecryptionKey;
			m_objPayback_Struct.dwOrignalAep = *(DWORD*)&m_pbyBuff[1];
			m_objPayback_Struct.dwOrignalAep -= m_dwImageBase;
			return true; 
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of PayBack Family
					  Perform cleaning of virus body by fill zero	
--------------------------------------------------------------------------------------*/
int CPolyPayBack::CleanVirus()
{
	if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x9))
	{
		m_pMaxPEFile->WriteAEP(m_objPayback_Struct.dwOrignalAep);

		// Fill virus body with zero
		m_pMaxPEFile->FillWithZeros(m_objPayback_Struct.dwDecryptionLOff, DECRYPTN_LOOP_SZ);
		DWORD dwFileOffset = 0;
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_objPayback_Struct.dwVirusBodyOffset, &dwFileOffset))
		{
			m_pMaxPEFile->FillWithZeros(dwFileOffset, VIRUS_BODY_SZ);
		}
		return REPAIR_SUCCESS;						
	}
	return REPAIR_FAILED;
}