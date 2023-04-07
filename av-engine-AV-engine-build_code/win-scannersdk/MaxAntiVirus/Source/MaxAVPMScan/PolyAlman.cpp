/*======================================================================================
FILE				: PolyAlman.cpp
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
NOTES				: This is detection module for malwares Alman Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyAlman.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyAlman
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAlman::CPolyAlman(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{	
	m_dwAEP = 0x00;
	m_dwSetEndAddress = 0x00;
	m_dwTempEBP_8 = 0x00;
	m_dwCounter = 0x00;
	m_dwOriginalAEP = 0x00;

	m_pbyAlmanBPatchedBuff = NULL;
	memset(&m_objAlmanStruct, 0 , sizeof(m_objAlmanStruct));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAlman
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAlman::~CPolyAlman(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	if(m_pbyAlmanBPatchedBuff)
	{
		delete []m_pbyAlmanBPatchedBuff;
		m_pbyAlmanBPatchedBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Detection routine for different varients of Alma Family
--------------------------------------------------------------------------------------*/
int CPolyAlman::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	/*if(m_wAEPSec == m_wNoOfSections - 1)
	{
		return iRetStatus;
	}*/

	if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData < 3)
	{
		m_wNoOfSections--;
	}	

	if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > 0x100)
	{		
		iRetStatus  = GetAlmanParamters();
		if(iRetStatus == VIRUS_FILE_REPAIR)
		{			
			if(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData >= m_pMaxPEFile->m_dwFileSize)
			{
				iRetStatus = VIRUS_FILE_DELETE;
			}
			else if(m_eInfectionType == ALMAN_B)
			{
				if(REPAIR_SUCCESS == DecryptAlmanB())
				{
					iRetStatus = VIRUS_FILE_REPAIR;
				}
				else
				{
					iRetStatus = VIRUS_FILE_DELETE;
				}
			}
			else if(m_eInfectionType == ALMAN_A)
			{
				if(m_objAlmanStruct.dwDecCounter == 0x4CD)
				{
					if(!DecryptAlman_4CD())
					{
						iRetStatus = VIRUS_FILE_DELETE;
					}
				}
				else
				{
					if(!DecryptAlmanA())
					{
						iRetStatus = VIRUS_FILE_DELETE;
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetAlmanParamters
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Read structures from file for detection and repair
--------------------------------------------------------------------------------------*/
int CPolyAlman::GetAlmanParamters()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD	dwOffSet = 0x00 , dwInstructionCount = 0x00 , dwLength = 0x00 , dwTemp = 0x00;
	int		iStg1 = 0 , iStg2 = 0 , iStg3 = 0, iStg4 = 0;
	BYTE	B1 = 0, B2 = 0, B3 = 0;
	bool	bCheckForAlmanA = false;
	
	t_disasm	da;

	m_objMaxDisassem.InitializeData();

	DWORD dwVirusRVA	= m_dwAEPUnmapped;
	DWORD dwReadOffSet	= m_dwAEPMapped;

	m_pbyBuff = new BYTE[ALMAN_PATCHED_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, ALMAN_PATCHED_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	
	if(!GetBuffer(dwReadOffSet, ALMAN_BUFF_SIZE))   
		return iRetStatus;

	while(dwOffSet < m_dwNoOfBytes)
	{		
		if(dwInstructionCount > 0x200)
		{
			return iRetStatus;
		}
		memset(&da, 0x00, sizeof( struct t_disasm)*1 );

		B1 = m_pbyBuff[dwOffSet];
		B2 = m_pbyBuff[dwOffSet+1];
		B3 = m_pbyBuff[dwOffSet + 0x05];
		
		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if( B1==0xC1 && (B2>=0xF0 && B2<=0xF7) )
		{
			dwOffSet+= 0x03;
			continue;
		}
		if( B1==0xD1 && (B2>=0xF0 && B2<=0xF7) )
		{
			dwOffSet+= 0x02;
			continue;
		}
		if( B1==0xE2 && (B2>=0xF0 && B2<=0xFF) ) // Added for 'LOOP' instruction
		{
			dwOffSet+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char* )&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffSet))
		{
			return iRetStatus;
		}
		dwInstructionCount++;

		if( dwLength==0x01 && _strcmpi(da.dump, "FFFFFFC3" )== 0 )
		{
			dwOffSet += dwLength;
			continue;
		}
		
		if(dwLength == 0x05 && B1 == 0xE8 && strstr(da.result, "CALL ") && iStg1 == 1 && iStg2 == 1 && iStg3 == 1 && iStg4 == 1)
		{
			dwTemp = *((DWORD* )&m_pbyBuff[dwOffSet+1]);
			if(dwTemp == 0xFFFFFFED)
			{
				if(m_eInfectionType == ALMAN_A)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Alman.A"));
				}
				else
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Alman.B"));			
				}
				iRetStatus = VIRUS_FILE_REPAIR;
				break;
			}
		}
		if(dwLength==0x05 && ((B1 == 0xE9 && strstr(da.result, "JMP ")) || (B1 == 0xE8 && strstr(da.result, "CALL "))))
		{
			dwVirusRVA += *((DWORD* )&m_pbyBuff[dwOffSet+1]) + dwOffSet	+ dwLength;
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwVirusRVA, &dwReadOffSet))
			{
				dwOffSet += dwLength;
				continue;
			}			
			if(!GetBuffer(dwReadOffSet, ALMAN_BUFF_SIZE))
			{
				return iRetStatus;
			}
			dwOffSet = 0x00;
			continue;
		}		
		if(dwLength == 0x05 && B1 == 0x68 && strstr(da.result, "PUSH ") && B3 == 0xC3)
		{
			dwTemp = *((DWORD* )&m_pbyBuff[dwOffSet+1]);
			dwTemp = dwTemp - m_dwImageBase;
			if(dwTemp & 0x80000000)
			{
				return iRetStatus;
			}
			
			dwOffSet = dwTemp - m_pSectionHeader[m_wAEPSec].VirtualAddress;
			if(dwTemp & 0x80000000)
			{
				return iRetStatus;
			}
			dwVirusRVA = dwTemp;

			dwReadOffSet = m_pSectionHeader[m_wAEPSec].PointerToRawData + dwOffSet;

			if(dwReadOffSet == 0x00)
				return iRetStatus;
			
			if(!GetBuffer(dwReadOffSet, ALMAN_BUFF_SIZE) )
				return iRetStatus;

			dwOffSet = 0x00;
			continue;
		}

		if( dwLength==0x01 && strstr(da.result, "POP E" ) )
		{
			iStg1 = 0x01;
			iStg2 = 0x00;
			iStg3 = 0x00;
			iStg4 = 0x00;
			
			dwOffSet = dwOffSet + dwLength;
			continue;
		}

		if( dwLength==0x05 && strstr(da.result, "MOV E" ) && ((da.immconst & 0x49E) == 0x49E || da.immconst == 0x2AD || da.immconst == 0x4CD) && iStg1 == 1 )
		{
			if(da.immconst == 0x2AD)
			{
				m_eInfectionType = ALMAN_A;
			}
			else if(da.immconst == 0x4CD)
			{
				m_eInfectionType = ALMAN_A;
				m_objAlmanStruct.dwDecCounter = 0x4CD;
			}
			else
			{
				m_eInfectionType = ALMAN_B;
			}

			iStg2 = 0x01;
			iStg3 = 0x00;
			iStg4 = 0x00;
			
			dwOffSet = dwOffSet + dwLength;
			continue;
		}

		if( dwLength==0x04 && strstr(da.result, "XOR BYTE PTR" ) && iStg1 == 1 &&  iStg2 == 1)
		{
			iStg3 = 0x01;
			iStg4 = 0x00;
			
			m_objAlmanStruct.byDecryptionKey = (BYTE) da.immconst;
			m_objAlmanStruct.dwAddorXOR = 0x00;

			dwOffSet = dwOffSet + dwLength;
			continue;
		}
		
		if( dwLength==0x04 && strstr(da.result, "ADD BYTE PTR" ) && iStg1 == 1  && iStg2 == 1)
		{
			iStg3 = 0x01;
			iStg4 = 0x00;
			
			m_objAlmanStruct.byDecryptionKey = (BYTE) da.immconst;
			m_objAlmanStruct.dwAddorXOR = 0x01;

			dwOffSet = dwOffSet + dwLength;
			continue;
		}
		
		if ( dwLength==0x02 && strstr(da.result, "JMP SHORT " ) && iStg1 == 1 && iStg2 == 1 && iStg3 == 1)
		{
			iStg4 = 0x01;
						
			m_objAlmanStruct.dwStartAddress = dwVirusRVA + dwOffSet + B2 + dwLength;
			m_objAlmanStruct.dwSizeofReplacement = dwOffSet + B2 + dwLength + 0x02AD;
			dwOffSet = dwOffSet + dwLength;
			continue;
		}
		dwOffSet += dwLength;		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of Alman Family
--------------------------------------------------------------------------------------*/
int CPolyAlman::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	if(m_eInfectionType == ALMAN_A)
	{
		if(m_objAlmanStruct.dwDecCounter == 0x4CD)
		{
			iRetStatus = CleanAlman_4CD();
		}
		else
		{
			iRetStatus = CleanAlmanA();
		}
	}
	else if(m_eInfectionType == ALMAN_B)
	{
		iRetStatus = CleanAlmanB();
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptAlman_4CD
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Decrypt Buffer Alman varient 0x4CD encryption
--------------------------------------------------------------------------------------*/
bool CPolyAlman::DecryptAlman_4CD()
{
	const int ALMAN_4CD = 0x04CD;

	DWORD dwSetFileOffset = 0x00; 
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_objAlmanStruct.dwStartAddress, &dwSetFileOffset))
	{
		return false;
	}
	if(m_pbyBuff)
	{
		delete [] m_pbyBuff;
		m_pbyBuff = NULL;
	}

	m_pbyBuff = new BYTE[ALMAN_4CD];
	if(m_pbyBuff == NULL)
	{
		return false;
	}

	memset(m_pbyBuff, 0, ALMAN_BUFF_SIZE);
	if(!GetBuffer(dwSetFileOffset, ALMAN_4CD, ALMAN_4CD))
	{
		return false;
	}

	for(DWORD dwOffset  = 0; dwOffset < ALMAN_4CD; dwOffset++)
	{
		if(m_objAlmanStruct.dwAddorXOR == 0x00)
		{
			m_pbyBuff[dwOffset] ^= m_objAlmanStruct.byDecryptionKey;
		}
		else 
		{
			m_pbyBuff[dwOffset] += m_objAlmanStruct.byDecryptionKey;
		}
	}
	m_wInfectedSecNo = m_pMaxPEFile->Rva2FileOffset(*((DWORD *)&m_pbyBuff[0x242]), NULL);
	if(m_wInfectedSecNo == OUT_OF_FILE)
	{
		return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanAlman_4CD
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Clean Alman varient with 0x4CD encryption
--------------------------------------------------------------------------------------*/
int CPolyAlman::CleanAlman_4CD()
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	DWORD	dwCounter = m_objAlmanStruct.dwStartAddress - m_dwAEPUnmapped + 0x4CD;
	m_pbyBuff = new BYTE[dwCounter];
	if(m_pbyBuff == NULL)
	{
		return iRetStatus;
	}
	if(!GetBuffer(m_pSectionHeader[m_wInfectedSecNo].PointerToRawData + 0x08, dwCounter, dwCounter))
	{
		return iRetStatus;
	}

	DWORD dwOriginalAEP = *((DWORD *) &m_pbyBuff[0]);
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwOriginalAEP, NULL))
	{
		return iRetStatus;
	}

	if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x04], m_dwAEPMapped, dwCounter, dwCounter))
	{
		return iRetStatus;
	}

	m_pMaxPEFile->WriteAEP(dwOriginalAEP);
	
	if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wInfectedSecNo].PointerToRawData))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;

}

/*-------------------------------------------------------------------------------------
	Function		: DecryptAlmanA
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Decrypt Buffer for Alman varient A
--------------------------------------------------------------------------------------*/
bool CPolyAlman::DecryptAlmanA()
{
	DWORD dwSetFileOffset = 0; 
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_objAlmanStruct.dwStartAddress, &dwSetFileOffset))
	{
		return false;
	}

	memset(m_pbyBuff, 0, ALMAN_BUFF_SIZE);
	if(!GetBuffer(dwSetFileOffset, ALMAN_BUFF_SIZE, ALMAN_BUFF_SIZE))
	{
		return false;
	}

	for(DWORD dwOffset  = 0; dwOffset < ALMAN_BUFF_SIZE; dwOffset++)
	{
		if(m_objAlmanStruct.dwAddorXOR == 0x00)
		{
			m_pbyBuff[dwOffset] ^= m_objAlmanStruct.byDecryptionKey;
		}
		else 
		{
			m_pbyBuff[dwOffset] += m_objAlmanStruct.byDecryptionKey;
		}
	}
	m_dwOriginalAEP = (*(DWORD *)&m_pbyBuff[0x028B]);
	
	if(m_objAlmanStruct.dwSizeofReplacement > ALMAN_PATCHED_BUFF_SIZE)
	{
		return false;
	}

	if(!GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, m_objAlmanStruct.dwSizeofReplacement, m_objAlmanStruct.dwSizeofReplacement))
	{
		return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanAlmanA
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Clean Alman varient : A
					+ Find Decryption Type ADD or XOR.
					+ Find Decryption Key.
					+ Perform Decryption.
					+ Find Original AEP and Set.
					+ ReplaceOriginal AEP patched bytes from last section.
					+ Remove Last Section
--------------------------------------------------------------------------------------*/
int CPolyAlman::CleanAlmanA()
{
	if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwAEPMapped, m_objAlmanStruct.dwSizeofReplacement, m_objAlmanStruct.dwSizeofReplacement))
	{
		//Set Address of Entry Point
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL))
		{
			m_pMaxPEFile->WriteAEP(m_dwOriginalAEP);
		
			//Setting Values of Instruction Pointer & CS to 0x0000
			m_pMaxPEFile->FillWithZeros(0x14, 4);
			
			//Remove the Last Section After Replacing First section bytes
			if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData))
			{	
				return REPAIR_SUCCESS;
			}	
		}
		else
		{
			m_pMaxPEFile->CloseFile_NoMemberReset();
			return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : REPAIR_FAILED;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanAlmanB
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Clean Alman varient : B
--------------------------------------------------------------------------------------*/
int CPolyAlman::CleanAlmanB()
{
	int iRetStatus = REPAIR_FAILED;
	
	if(m_pbyAlmanBPatchedBuff == NULL)
		return iRetStatus;

	m_pMaxPEFile->WriteAEP(m_dwOriginalAEP);	

	m_pMaxPEFile->WriteBuffer(m_pbyAlmanBPatchedBuff, m_dwAEP, m_dwCounter, m_dwCounter);

	if(m_pMaxPEFile->TruncateFile(m_dwSetEndAddress))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptAlmanB
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Decryption for Alman varient : B
--------------------------------------------------------------------------------------*/
int	CPolyAlman::DecryptAlmanB()
{
	int iRetStatus = REPAIR_FAILED;

	if(m_objAlmanStruct.byDecryptionKey == 0x00)
	{
		return iRetStatus;
	}

	DWORD dwSetFileOffset; 
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_objAlmanStruct.dwStartAddress, &dwSetFileOffset))
	{
		return iRetStatus;
	}

	memset(m_pbyBuff, 0x00, ALMAN_B_BUFF_SIZE);
	if(!GetBuffer(dwSetFileOffset, ALMAN_B_BUFF_SIZE, ALMAN_B_BUFF_SIZE))
	{
		return iRetStatus;
	}

	for(int i = 0; i < ALMAN_B_BUFF_SIZE; i++)
	{
		if(m_objAlmanStruct.dwAddorXOR  == 0x1)
		{
			*(m_pbyBuff + i) += m_objAlmanStruct.byDecryptionKey;
		}
		else
		{
			*(m_pbyBuff + i) ^= m_objAlmanStruct.byDecryptionKey;
		}
	}

	m_dwOriginalAEP = *((DWORD *)&m_pbyBuff[0x277]);
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP, NULL))
	{
		return iRetStatus;
	}
	
	DWORD dwEBP__18 = 0, dwEBP__14 = 0 ,dwEBP_10 = 0, dwEBP__8 = 0, dwEBP__0C = 0xFFFFFFFF;
	DWORD dwTempEDX = 0, dwTempEBX = 0, dwTempECX = 0,dwTempESI = 0,dwTempEDI = 0;
	DWORD dwEAX = 0,dwEBX = 0,  dwESI = 0, dwEDI = 0;
	signed int dwECX = 0, dwEDX = 0;

	DWORD dwEBP_0C	= *((DWORD *) (&m_pbyBuff[0x129]));
	DWORD dwEBP__10 = *((DWORD *) (&m_pbyBuff[0x348]));
	DWORD dwEBP_8	= *((DWORD *) (&m_pbyBuff[0xFF]));
	DWORD dwEBP__4	= m_dwImageBase;
		
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwEBP_8, &dwSetFileOffset))
	{
		return iRetStatus;
	}
	DWORD dwSize = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - dwSetFileOffset;
	m_dwTempEBP_8 = dwEBP_8;

	//Added for calculating offset where last decrypted buffer going to be write 29 NOV 2010
	DWORD dwTemp1 = m_objAlmanStruct.dwStartAddress + m_dwImageBase  + 0x24E + 0x5;
	if(dwTemp1 < *((DWORD *) (&m_pbyBuff[0x256])))
	{
		return iRetStatus;
	}

	dwTemp1 = dwTemp1 - *((DWORD *) (&m_pbyBuff[0x256])); //[0x256] => 0x401253
	DWORD dwTemp2 = *((DWORD *) (&m_pbyBuff[0x289])) + dwTemp1; // [0x289] => 0x401000
	DWORD dwTemp3 = *((DWORD *) (&m_pbyBuff[0x291])) - m_dwImageBase - 
					m_objAlmanStruct.dwStartAddress; //[0x291] => 0x40149A

	if(dwTemp1 + dwTemp3 != 0x49A)
	{
		return iRetStatus;
	}

	DWORD dwTemp4 = *((DWORD *) (&m_pbyBuff[dwTemp1 + dwTemp3]));
	//dwTemp5 contain RVA of where to write decrypted Buffer
	DWORD dwTemp5 = dwTemp2 - dwTemp4 - m_dwImageBase;
	
	if(dwSize > MAX_ALLOC_SIZE)
	{
		return iRetStatus;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[dwSize];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}

	memset(m_pbyBuff, 0x00, dwSize);
	if(!GetBuffer(dwSetFileOffset, dwSize))
	{
		return iRetStatus;
	}
	
	m_pbyAlmanBPatchedBuff = new BYTE[ALMAN_PATCHED_BUFF_SIZE];
	if(!m_pbyAlmanBPatchedBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyAlmanBPatchedBuff, 0x00, ALMAN_PATCHED_BUFF_SIZE);

	//Second decryption
	dwEBP_8= 0;
	BYTE bCL = 0 , bDL = 0, bBL = 0;
	
	while(1)
	{
		lable_10015E4:

		dwEBX = dwEBP_10;
		dwESI = dwEBP_8;
		dwEDX = dwEAX;
		dwEDX = dwEDX >> 3;

		if(dwEDX > (signed long)dwSize)
		{
			return iRetStatus;
		}

		dwEDX = *((DWORD *) (&m_pbyBuff[dwEDX]));
		dwECX = dwEAX;
		dwECX = dwECX & 0x00000007;
		bCL = (BYTE) dwECX;
		dwEDX = dwEDX >> bCL;
		dwECX = 0x0;
		dwEDX = dwEDX & 0x00000001;
		dwEAX += 1;
		if(dwEDX == dwECX)
			goto lable_10016E2;
		dwEDX = dwEBP__10;
		if((signed int)dwEDX < dwECX)
			goto lable_1001615;
		dwEDX = dwEDX + dwEBX;
		dwEBP__4 = dwEDX;
		goto lable_1001623;

		lable_1001615://lable
		dwEBP__4 = dwEBX;
		if(dwEDX >= -0x400)
			goto lable_1001623;
		dwEBP__4 = dwECX;

		lable_1001623://lable
		dwEDX = 0x0;
		dwEBP__8 = dwECX;

		lable_1001628:

		dwEDI = dwEAX;
		dwEDI = dwEDI >> 0x3;

		if(dwEDI > dwSize)
		{
			return iRetStatus;
		}
		dwEDI = *((DWORD *) (&m_pbyBuff[dwEDI]));
		dwECX = dwEAX;
		dwECX = dwECX & 0x00000007;
		bCL = (BYTE) dwECX;
		dwEDI = dwEDI >> bCL;
		dwECX = dwEDX;
		dwEDI = dwEDI & 0x00000001;
		bCL = (BYTE) dwECX;
		dwEDI = dwEDI << bCL;
		dwEBP__8 = dwEBP__8 | dwEDI;
		dwEDX += 1;
		dwEAX += 1;
		if(dwEDX < 0x0A )
			goto lable_1001628;
		dwEDX = dwEAX;
		dwEDX = dwEDX >> 0x3;
		if(dwEDX > (signed long)dwSize)
		{
			return iRetStatus;
		}
		dwEDX = *((DWORD *) (&m_pbyBuff[dwEDX]));
		dwECX = dwEAX;
		dwECX = dwECX & 0x00000007;
		bCL = (BYTE) dwECX;
		dwEDX = dwEDX >> bCL;
		dwEBX = 0x0;
		dwEDI = dwEAX + 0x1;
		dwEDX = dwEDX & 0x00000001;
		dwEBP__0C = dwEDX;
		if(dwEDX == 0x0)
			goto lable_100167C;

		lable_1001664:

		dwEDX = dwEDI;
		dwEDX = dwEDX >>0x3;
		if(dwEDX > (signed long)dwSize)
		{
			return iRetStatus;
		}
		dwEDX = *((DWORD *) (&m_pbyBuff[dwEDX]));
		dwECX = dwEDI;
		dwECX = dwECX & 0x00000007;
		bCL = (BYTE) dwECX;
		dwEDX = dwEDX >> bCL;
		dwEBX += 0x1;
		dwEDX = dwEDX & 0x00000001;
		dwEDI += 0x1;
		if(dwEDX != 0x0)
			goto lable_1001664;

		lable_100167C:

		dwEBP__18 = 0x0;
		dwEBP__0C = 0x0;

		lable_1001684:

		dwEDX = dwEDI;
		dwEDX = dwEDX >> 0x3;
		if(dwEDX > (signed long)dwSize)
		{
			return iRetStatus;
		}
		dwEDX = *((DWORD *) (&m_pbyBuff[dwEDX]));
		dwECX = dwEDI;
		dwECX = dwECX & 0x00000007;
		bCL = (BYTE) dwECX;
		dwEDX = dwEDX >> bCL;
		dwECX = dwEBP__18;
		dwEDX = dwEDX & 0x00000001;
		bCL = (byte) dwECX;
		dwEDX = dwEDX << bCL;
		dwEBP__0C = dwEBP__0C | dwEDX;
		dwEBP__18 += 0x1;
		dwEDI += 0x1;
		if(dwEBP__18 < 0x3)
			goto lable_1001684;
		dwECX = dwEBP__0C;
		dwECX = (dwEBX * 8) + dwECX + 0x1;
		dwEAX = dwEAX + dwEBX + 0x4;
		dwEBP__0C = dwECX;
		dwEBP__18 = dwEAX;
		
		dwTempECX = dwECX;
		dwTempEDI = dwEDI;
		dwTempESI = dwESI;
		dwECX = dwEBP__0C;
		dwEDI = dwEBP__14;
		dwESI = dwEBP__8 + dwEBP__4;
		for(int i = 0; i < dwECX; i++)
		{
			if(dwEDI >= 0x1000 || dwESI >= 0x1000)
			{
				return iRetStatus;
			}

			m_pbyAlmanBPatchedBuff[dwEDI++] = m_pbyAlmanBPatchedBuff[dwESI++];
		}
		dwECX = dwTempECX;
		dwESI = dwTempESI;
		dwEDI = dwTempEDI;

		dwECX = dwEBP__0C;
		//dwEAX = dwEBP_14;
		dwEBP__14 += dwECX;
		dwEBP__10 += dwECX;
		m_dwCounter += dwECX;

		dwEDI = 0x0;
		dwEAX = dwEBP__18;

		goto lable_1001717;

		lable_10016E2:

		dwEBP__18 = dwECX;
		dwEDX = dwEDX & 0xFFFFFF00;
		
		lable_10016E7:

		dwEBX = dwEAX;
		dwEBX = dwEBX >> 0x3;
		if(dwEBX > dwSize)
		{
			return iRetStatus;
		}
		dwEBX = *((DWORD *) (&m_pbyBuff[dwEBX]));
		dwECX = dwEAX;
		dwECX = dwECX & 0x00000007;
		bCL = (BYTE) dwECX;
		dwEBX = dwEBX >> bCL;

		dwECX = dwEBP__18;

		bBL = (BYTE) dwEBX;
		bBL = bBL & 0x01;
		dwEBX = dwEBX & 0xffffff01;
		bCL = (BYTE) dwECX;

		bBL = bBL << bCL;
		bDL = (BYTE) dwEDX;
		bDL = bDL | bBL;

		dwTempEDX  = (DWORD) bDL;
		dwEDX = dwEDX | dwTempEDX;
		dwTempEBX = (DWORD) bBL;
		dwEBX = dwEBX | dwTempEBX;

		dwEBP__18++;
		dwEAX++;
		if(dwEBP__18 < 0x8)
			goto lable_10016E7;

		dwECX = dwEBP__14;
		dwEBP__14++;
		dwEBP__10++;

		if(dwECX >= 0x1000)
		{
			return iRetStatus;
		}
		m_pbyAlmanBPatchedBuff[dwECX] = (BYTE) dwEDX;
		m_dwCounter++;
		if(m_dwCounter >= 0x1000)
		{
			return iRetStatus;
		}

		lable_1001717:

		if(dwEAX < dwEBP_0C)
			goto lable_10015E4;
		else 
			break;
	}

	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwTemp5, &m_dwAEP))
	{
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwTempEBP_8, &m_dwSetEndAddress))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}
