/*======================================================================================
FILE				: PolyAlma.cpp
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
NOTES				: This is detection module for malwares Alma Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyAlma.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyAlma
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAlma::CPolyAlma(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
    m_pbyBuff = NULL;	 
	memset(&m_objAlma_Struct, 0x00, sizeof(Alma_Struct));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAlma
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyAlma::~CPolyAlma(void)
{
	delete []m_pbyBuff;
	m_pbyBuff = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Omakar Pardeshi + Virus Analysis Team
	Description		: Detection routine for different varients of Alma Family
					  Initialise structure for virus perfrom decryption of virus body
--------------------------------------------------------------------------------------*/
int CPolyAlma::DetectVirus()
{
	int	iRetStatus = VIRUS_NOT_FOUND;	

	// Detection of Virus.W32.Alma.2414(OLD),Alma.37195,Alma,37274
	if(m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x616D6C41 && m_wAEPSec == m_wNoOfSections - 1)
	{       
		const DWORD ALMA_SIG_SIZE = 0x17;
		m_pbyBuff = new BYTE[ALMA_SIG_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, ALMA_SIG_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, ALMA_SIG_SIZE, ALMA_SIG_SIZE))
		{   
			//Detection for Virus.W32.Alma.2414(OLD)
			if(m_pbyBuff[0] == 0xE8 && m_pbyBuff[1] == 0x00)
			{
				const BYTE bySignature[] = { 
					0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x68, 0x05, 
					0x10, 0x40, 0x00, 0x58, 0x2B, 0xD8, 0x53, 0x5D, 
					0x8D, 0xBD,	0x21, 0x10, 0x40, 0x00, 0xB9};

				if(!memcmp(m_pbyBuff, bySignature, sizeof(bySignature)))  
				{
					// Read XOR key
					BYTE byKey = 0;
					if(m_pMaxPEFile->ReadBuffer(&byKey, m_dwAEPMapped + 0x1D, 1))
					{
						// Read AEP
						BYTE byAEP[4] = {0};
						if(m_pMaxPEFile->ReadBuffer(byAEP, m_dwAEPMapped + 0x25D, 4))
						{
							// Decrypt AEP			
							for(int i = 0; i < 4; i++)
							{
								byAEP[i] ^= byKey;			 
							}
							m_dwOriginalAEP = *((DWORD *)(byAEP)) - m_dwImageBase;
							if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL))
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Alma.37195"));
								iRetStatus = VIRUS_FILE_REPAIR;
							}
						}
					}
				}
			}
			//Detection for Virus.W32.Alma.2414 (NEW)
			else if(m_pbyBuff[0] == 0xE8 && m_pbyBuff[1] == 0x08)
			{
				const BYTE bySignature[] = { 
					0xE8, 0x08, 0x00, 0x00, 0x00, 0x81, 0xEA, 0x09, 0x10,
					0x40, 0x00, 0xEB, 0x03, 0x5A, 0xEB, 0xF5, 0x87, 0xD5, 0xB0 };

				if(!memcmp(m_pbyBuff, bySignature, sizeof(bySignature)))  
				{
					// Read For add key
					BYTE byKey = 0; BYTE *m_pbyBuff2 = 0;
					if(m_pMaxPEFile->ReadBuffer(&byKey, m_dwAEPMapped + 0x13, 1))
					{
						// Read Buffer Size For Decryption
						DWORD DeyBuffSize=0;
						if(m_pMaxPEFile->ReadBuffer(&DeyBuffSize, m_dwAEPMapped + 0x15, 4))
						{
							if(DeyBuffSize < 0x1000)
							{
								// Read Buffer For Decryption
								BYTE *pbyBuff = new BYTE[DeyBuffSize];
								if(pbyBuff)
								{
									m_pMaxPEFile->ReadBuffer(pbyBuff, m_dwAEPMapped + 0x33,DeyBuffSize);

									//Decrypt Buffer
									for(DWORD dwOffset = 0; dwOffset <= DeyBuffSize; dwOffset++)
									{
										pbyBuff[dwOffset] += byKey;
										byKey--;				 
									}
									//Logic for Calculate AEP
									*(DWORD *)&pbyBuff[356] += *(DWORD *)&pbyBuff[0x925];
									*(DWORD *)&pbyBuff[360] ^= *(DWORD *)&pbyBuff[0x913];
									m_dwOriginalAEP = *((DWORD*)(&pbyBuff[359]))- m_dwImageBase;
									if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL))
									{
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Alma.2414"));
										iRetStatus = VIRUS_FILE_REPAIR;
									}
									delete []pbyBuff;
									pbyBuff = NULL;
								}
							}
						}
					}
				}
			}
		}		
	}

	// Detection of Virus Virus.Win32.Alma.5319
	else if(m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x2058534C && m_wAEPSec == m_wNoOfSections - 1 &&	
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0x00000060)== 0x00000060)
	{			
		// Get 1st decrytion loop parameters
		if(!Get1stDeCryptionParameters())
		{
			return iRetStatus;		
		}
		//Check 1st decrytion loop parameters
		if(m_objAlma_Struct.dwCnstSubKey1 != 0x40101D ||
			m_objAlma_Struct.dwCnstLeaKey1 != 0x4010E2 ||
			m_objAlma_Struct.dwDecryptionCount1 != 0x4F9)
		{
			return iRetStatus;			
		}
		DWORD dw1stDecryptionOffsetInBuff = m_objAlma_Struct.dwDecryptionOffset1;
		dw1stDecryptionOffsetInBuff -= m_dwImageBase;
		dw1stDecryptionOffsetInBuff -= m_dwAEPUnmapped;
		//1st decrytion loop
		for(DWORD dwOffset = 0; dwOffset < m_objAlma_Struct.dwDecryptionCount1; dwOffset++)
		{
			*(DWORD *)&m_pbyBuff[dw1stDecryptionOffsetInBuff] ^= m_objAlma_Struct.dwDecryptionXorKey1;		
			dw1stDecryptionOffsetInBuff += 0x4;
		}

		// Get 2nd decrytion loop parameters
		if(!Get2ndDeCryptionParameters())
		{
			return iRetStatus;		
		}
		//Check 2nd decrytion loop parameters
		if(m_objAlma_Struct.dwDecryptionCount2 != 0x13D1 ||
			m_objAlma_Struct.dwCnstLeaKey2 != 0x4010F6)
		{
			return iRetStatus;
		}
		m_objAlma_Struct.dwDecryptionOffset2 -= m_dwImageBase;	 
		DWORD dw2ndDecryptionOffsetInBuff = m_objAlma_Struct.dwDecryptionOffset2 - m_dwAEPUnmapped;

		//2nd decrytion loop
		for(DWORD dwOffset = 0; dwOffset < m_objAlma_Struct.dwDecryptionCount2; dwOffset++)
		{
			m_pbyBuff[dw2ndDecryptionOffsetInBuff] -= m_objAlma_Struct.dwDecryptionSubKey2;
			dw2ndDecryptionOffsetInBuff++;
			m_objAlma_Struct.dwDecryptionSubKey2--;
		} 
		iRetStatus = GetOrignalAep();
		if(iRetStatus)
		{		
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Alma.5319"));
			}
		}
	}// end if Alma.5319 detection
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetOrignalAep
	In Parameters	: 
	Out Parameters	: DWORD AEP / 0 if Aep not found
	Purpose			: 
	Author			: Tushar Kadam + Omkar Pardeshi
	Description		: Get Orignal Aep from decrypted buffer for W32.Alma.5319
--------------------------------------------------------------------------------------*/
int CPolyAlma::GetOrignalAep()
{
	int iRetStatus = VIRUS_NOT_FOUND;	
	DWORD dwTargetAEP = 0, dwSeq = 0,dwLength = 0;

	m_objAlma_Struct.dwEBP -= m_dwImageBase;
	DWORD dwStart = m_objAlma_Struct.dwEBP - m_dwAEPUnmapped;

	//Start Disassembly
	t_disasm da;	 
	while(dwStart < m_objAlma_Struct.dwStbSiz)
	{
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStart], MAX_INSTRUCTION_LEN, m_dwImageBase, &da, DISASM_CODE);
		if(dwLength > (m_objAlma_Struct.dwStbSiz - dwStart))
		{
			break;
		}
		if(strstr(da.result, "PUSH"))
		{
			dwTargetAEP = da.immconst;
			dwSeq = dwStart;
		}				 		 
		if(dwStart ==(dwSeq+5)&& _strcmpi(da.dump, "FFFFFFC3")== 0)
		{		
			iRetStatus = VIRUS_FILE_REPAIR;
			m_dwOriginalAEP = dwTargetAEP  - m_dwImageBase;
			break;
		}  	
		dwStart += dwLength;
	}// end while
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: Get1stDeCryptionParameters
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Omkar Pardeshi
	Description		: Dissassemble virus body to get parameter for 1st level decryption
--------------------------------------------------------------------------------------*/
bool CPolyAlma::Get1stDeCryptionParameters()
{
	m_objAlma_Struct.dwStbSiz =(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)- m_dwAEPMapped;
	if(m_objAlma_Struct.dwStbSiz > 0x10000)
	{
		m_objAlma_Struct.dwStbSiz = 0x10000;
	}
	//read virus buff
	if(m_pbyBuff != NULL)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
    m_pbyBuff = new BYTE[m_objAlma_Struct.dwStbSiz];
	if(m_pbyBuff == NULL)
	{
		return false;
	}
	memset(m_pbyBuff, 0, m_objAlma_Struct.dwStbSiz);
	if(!GetBuffer(m_dwAEPMapped, m_objAlma_Struct.dwStbSiz, 0x1000))
	{
		return false;
	}

	t_disasm da;
	DWORD   dwLength = 0, dwStart = 0;	 	
	DWORD	dwCounter = 0,  dwKey = 0;
	DWORD	dwInstCnt = 0x00;
	DWORD   dwSeq=0;
	// Decryption Loop 1
	while(dwStart < m_dwNoOfBytes)
	{
		if(dwInstCnt > 0x50)
		{
			return false;
		}
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStart], MAX_INSTRUCTION_LEN, m_dwImageBase , &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwStart))
		{
			return false;
		}
		dwInstCnt++;		
		if(strstr(da.result, "CALL")&& dwLength == 0x5 && dwSeq == 0)
		{
			m_objAlma_Struct.dwDecryptionOffset1 = *(DWORD*)(m_pbyBuff + dwStart + 1)+ 0x05 +
				                                    m_dwAEPUnmapped + dwStart;
			m_objAlma_Struct.dwDecryptionOffset1  += m_dwImageBase;
			dwSeq++;
		}
		if(strstr(da.result, "SUB EBP")&& dwLength == 0x6 && dwSeq == 1)
		{
			m_objAlma_Struct.dwCnstSubKey1 = da.immconst;
			m_objAlma_Struct.dwDecryptionOffset1 -= da.immconst;
			m_objAlma_Struct.dwEBP = m_objAlma_Struct.dwDecryptionOffset1;
			dwSeq++;

		}
		// start of encrypted virus
		if(strstr(da.result, "LEA EDI")&& dwLength == 6 && dwSeq == 2)
		{
			m_objAlma_Struct.dwCnstLeaKey1 = da.adrconst;
			m_objAlma_Struct.dwDecryptionOffset1 += da.adrconst;
			dwSeq++;

		}
		// get counter
		if(strstr(da.result, "MOV ECX")&& dwLength == 5 && dwSeq == 3)
		{
			m_objAlma_Struct.dwDecryptionCount1 = da.immconst;
			dwSeq++;
		}
		if(strstr(da.result, "XOR DWORD PTR [EDI]")&& dwLength == 6 && dwSeq == 4)
		{
			m_objAlma_Struct.dwDecryptionXorKey1 = da.immconst;
			break;
		}
		dwStart += dwLength;
	} 
   return true;
}


/*-------------------------------------------------------------------------------------
	Function		: Get2ndDeCryptionParameters
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Omkar Pardeshi
	Description		: Dissassemble virus body to get parameter for 2nd  level decryption
--------------------------------------------------------------------------------------*/
bool CPolyAlma::Get2ndDeCryptionParameters()
{
	DWORD dwLength = 0, dwSeq = 0;
	DWORD dwStart  = m_objAlma_Struct.dwDecryptionOffset1;
	dwStart -= m_dwImageBase;
	dwStart  = dwStart- m_dwAEPUnmapped;

	//Start Disassembly
	t_disasm da;
	while(dwStart < m_dwNoOfBytes)
	{	 
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStart], MAX_INSTRUCTION_LEN, m_dwImageBase, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwStart))
		{
			break;
		}
		if(strstr(da.result, "MOV ECX")&& dwLength == 5 && dwSeq == 0)
		{
			m_objAlma_Struct.dwDecryptionCount2=da.immconst;	
			dwSeq++;
		}
		// start of encrypted virus
		if(strstr(da.result, "LEA ESI")&& dwLength == 6 && dwSeq == 1)
		{
			m_objAlma_Struct.dwCnstLeaKey2=da.adrconst;
			m_objAlma_Struct.dwEBP+=da.adrconst;
			m_objAlma_Struct.dwDecryptionOffset2=m_objAlma_Struct.dwEBP;
			dwSeq++;
		}
		if(strstr(da.result, "MOV AL")&& dwLength == 2 && dwSeq == 2)
		{
			m_objAlma_Struct.dwDecryptionSubKey2=(BYTE)da.immconst;
			break;	
		}
		dwStart += dwLength;		    
	 }// end while
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Omkar Pardeshi
	Description		: Repair routine for different varients of Alcaul Family
--------------------------------------------------------------------------------------*/
int CPolyAlma::CleanVirus()
{
	// Set original AEP
	m_pMaxPEFile->WriteAEP(m_dwOriginalAEP);

	//Win32 Version Value
	m_pMaxPEFile->RepairOptionalHeader(0x13, 0, 0);
	
	// Remove virus code
	if(m_pMaxPEFile->TruncateFileWithFileAlignment(m_dwAEPMapped))
	{
		return REPAIR_SUCCESS;						 
	}					
	return REPAIR_FAILED;
}
