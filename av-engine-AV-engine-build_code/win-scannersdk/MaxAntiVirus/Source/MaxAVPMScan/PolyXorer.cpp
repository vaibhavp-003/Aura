/*======================================================================================
FILE				: PolyXorer.cpp
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
NOTES				: This is detection module for malware Xorer Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyXorer.h"
#include "MaxBMAlgo.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyXorer
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyXorer::CPolyXorer(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyXorer
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyXorer::~CPolyXorer(void)
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
	Description		: Detection routine for different varients of Xorer Family
--------------------------------------------------------------------------------------*/
int CPolyXorer::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	/*if(m_wAEPSec != 0 || m_wNoOfSections < 0x3 //|| m_pSectionHeader[2].SizeOfRawData < 0x1000 ||
		|| (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}*/
	const int XORER_BUFF_SIZE = 0x1500;
	m_pbyBuff = new BYTE[XORER_BUFF_SIZE];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, XORER_BUFF_SIZE);
	if(!GetBuffer(m_dwAEPMapped + 0x75, 0x20, 0x20))
	{
		return iRetStatus;	
	}
	DWORD dwLength = 0, dwInstructionCnt = 0, dwOffset = 0 ,dwOff = 0;
	int iXorerSigCnt = 0;
	t_disasm	da;
	bool bChk = false;
	while(dwOffset < m_dwNoOfBytes && dwInstructionCnt < 0x6)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);

		if(dwLength == 2 && dwInstructionCnt == 0 && strstr(da.result, "JNZ"))
		{
			dwInstructionCnt++;
		}
		else if(dwLength == 5 && dwInstructionCnt == 1 && strstr(da.result, "PUSH"))
		{
			dwInstructionCnt++;
		}
		else if(dwLength == 6 && dwInstructionCnt == 2 && strstr(da.result, "CALL"))
		{
			dwInstructionCnt++;
		}
		else if(dwLength == 1 && dwInstructionCnt == 3 && strstr(da.result, "POP ECX"))
		{
			dwInstructionCnt++;
		}
		else if(dwLength == 5 && dwInstructionCnt == 4 && strstr(da.result, "CALL"))
		{
			dwInstructionCnt++;
		}
		else if(dwLength == 5 && dwInstructionCnt == 5 && strstr(da.result, "PUSH"))
		{
			dwOff = da.immconst - m_dwImageBase;
			dwInstructionCnt++;
		}
		dwOffset += dwLength; 
	}
	BYTE XorerSig[9][35]= {
								{0x6E,0x65,0x74,0x63,0x66,0x67,0x2E,0x64,0x6C,0x6C}, 				//netcfg.dll
								{0x6C,0x73,0x61,0x73,0x73,0x2E,0x65,0x78,0x65},						//lsass.exe
								{0x70,0x61,0x67,0x65,0x66,0x69,0x6C,0x65,0x2E,0x70,0x69,0x66},		//pagefile.pif
								{0x41,0x55,0x54,0x4F,0x52,0x55,0x4E,0x2E,0x49,0x4E,0x46},			//AUTORUN.INF
								{0x6E,0x65,0x74,0x63,0x66,0x67,0x2E,0x30,0x30,0x30},				//netcfg.000
								{0x73,0x6D,0x73,0x73,0x2E,0x65,0x78,0x65},						    //smss.exe
								{0x64,0x6E,0x73,0x71,0x2E,0x64,0x6C,0x6C},						    //dnsq.dll
								{0x4E,0x65,0x74,0x41,0x70,0x69,0x30,0x30,0x30,0x2E,0x73,0x79,0x73},	//NetApi000.sys
								{0x70,0x61,0x67,0x65,0x2E,0x70,0x69,0x66},						    //page.pif
							};
	CMaxBMAlgo	*pBMScan = new CMaxBMAlgo;
	if (NULL == pBMScan)
	{
		return iRetStatus;
	}
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwOff, &dwOff) || dwOff == 0x0)
	{
		return false;
	}
	if(!GetBuffer(dwOff, XORER_BUFF_SIZE, XORER_BUFF_SIZE))
	{
		return iRetStatus;
	}
	for(int j = 0; j < 0x20; j++)
	{
		if(m_pbyBuff[j] == 0x78 && m_pbyBuff[j + 1] == 0x56 && m_pbyBuff[j + 2] == 0x34 && m_pbyBuff[j + 3] == 0x12)
		{
			bChk = true;
		}
	}
	if(!bChk)
	{
		return iRetStatus;
	}
	for(int i = 0; i < _countof(XorerSig); i++)
	{
		if(!pBMScan->AddPatetrn2Search(XorerSig[i],strlen((const char*)XorerSig[i])))
		{
			return iRetStatus;
		}
		if(pBMScan->Search4Pattern(&m_pbyBuff[0x0], m_dwNoOfBytes))
		{
			iXorerSigCnt++;
		}
	}
	if(iXorerSigCnt >= 2)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Xorer"));
		return VIRUS_FILE_REPAIR;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Xoxer Family
--------------------------------------------------------------------------------------*/
int CPolyXorer::CleanVirus(void)
{
	DWORD dwStartOfSecondDecryp = 0, dwAddRva = 0, dwDisplacement = 0, dwDecLength = 0, dwOrgFileOffset = 0, dwOrgFileSize = 0, dwDecLevel = 0;
	bool bAddValFound = false, bLoopFound = false, bNoDecFound = false;
	const int XORER_BUFF_SIZE = 0x10000; 
	BYTE *pbyBuffer = new BYTE[XORER_BUFF_SIZE];
	DWORD dwSize = m_pSectionHeader[0].SizeOfRawData < XORER_BUFF_SIZE ? m_pSectionHeader[0].SizeOfRawData : XORER_BUFF_SIZE;
	if(m_pMaxPEFile->ReadBuffer(pbyBuffer, m_pSectionHeader[0].PointerToRawData, dwSize, dwSize, &dwSize))
	{
		for(DWORD dwCnt = 0; dwCnt < dwSize; dwCnt++)
		{
			//Search for Add in data section at 30 or 40 offset 
			if((pbyBuffer[dwCnt] == 0x81 || pbyBuffer[dwCnt] == 0x83) && pbyBuffer[dwCnt + 1] == 0x05 && (pbyBuffer[dwCnt + 2] == 0x30 || pbyBuffer[dwCnt + 2] == 0x40) &&
			 ((*(DWORD *)&pbyBuffer[dwCnt + 2] & m_pMaxPEFile->m_stPEHeader.ImageBase) == m_pMaxPEFile->m_stPEHeader.ImageBase))
			{
				DWORD dwAddOffset = 0;
				dwAddRva = *(DWORD *)&pbyBuffer[dwCnt + 2];
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwAddRva - m_pMaxPEFile->m_stPEHeader.ImageBase, &dwAddOffset))
				{
					return false;
				}
				BYTE byAddValue[0x10] = {0};
				if(!m_pMaxPEFile->ReadBuffer(&byAddValue, dwAddOffset, 0x10, 0x10))
				{
					return false;
				}
				dwStartOfSecondDecryp = *(DWORD *)&pbyBuffer[dwCnt + 6] + *(DWORD *)&byAddValue[0];
				if(pbyBuffer[dwCnt] == 0x83)
				{
					dwStartOfSecondDecryp = *(BYTE *)&pbyBuffer[dwCnt + 6] + *(DWORD *)&byAddValue[0];
				}
				if(dwStartOfSecondDecryp > 0x500)
				{
					return false;
				}
				dwDecLength = *(DWORD *)&byAddValue[0x0C];
								
				/********** added **********/
				if(dwDecLength == (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
				{
					dwDecLength = dwDecLength;
				}
				else if(dwDecLength == 0x18F9C && dwStartOfSecondDecryp == 0x267)
				{
					dwStartOfSecondDecryp += 0x1C; 
				}
				/*else if(dwDecLength == 0x18F9C  && dwStartOfSecondDecryp == 0x243)
				{
					dwStartOfSecondDecryp += 0x3C; 
				}*/
				/*else if((dwDecLength == 0x18F9C || dwDecLength == 0x1C000))
				{
					DWORD dwTempLen = 0;
					if(m_pMaxPEFile->ReadBuffer(&dwTempLen,m_pMaxPEFile->m_dwFileSize - 4,4,4))
					{
						if((m_pMaxPEFile->m_dwFileSize % m_pMaxPEFile->m_stPEHeader.FileAlignment != 0))
						{
							if((dwTempLen < m_pMaxPEFile->m_dwFileSize) && (dwTempLen < 0xF00000) && (dwTempLen > 0x1000))
							{
								dwDecLength = dwTempLen;
							}						
						}
						else
						{
							return REPAIR_FAILED;							
						}
					}
				}*/
				/*else
				{
					return REPAIR_FAILED;
				}*/
				/*********** added ****************/

				bAddValFound = true;
				break;
			}
		}
		if(!bAddValFound)
		{
			//Add Value not found then sample do not have decryption, check for stub or else copy data as it is.
			DWORD dwLSSize = m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData > m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize ?  m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData : m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize;
			if(m_pMaxPEFile->m_dwFileSize <= m_pMaxPEFile->m_stPEHeader.SizeOfImage)
			{
				m_pMaxPEFile->CloseFile_NoMemberReset();
				return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : REPAIR_FAILED;
			}
			bNoDecFound = true;
		}
		if(!bNoDecFound)
		{
			DWORD dwNextCnt = 0;
			for(DWORD dwCnt = 0; dwCnt < dwSize; dwCnt++)
			{
				if(pbyBuffer[dwCnt] == 0x8B && pbyBuffer[dwCnt + 1] == 0x0D)
				{
					if(*(DWORD *)&pbyBuffer[dwCnt + 2] == dwAddRva)
					{
						bLoopFound = true;						
						if(pbyBuffer[dwCnt + 6] == 0x83 && pbyBuffer[dwCnt + 7] == 0xC1)
						{
							dwStartOfSecondDecryp = dwStartOfSecondDecryp + pbyBuffer[dwCnt + 8];
						}
						dwNextCnt = dwCnt;
						break;
					}
				}
			}			
			if(dwNextCnt == 0)
			{
				return false;
			}
			for(DWORD dwCnt = dwNextCnt; dwCnt < dwSize; dwCnt++)
			{
				if(pbyBuffer[dwCnt] == 0x83 && pbyBuffer[dwCnt + 1] == 0xC1 && pbyBuffer[dwCnt + 3] == 0xEB)
				{
					dwDisplacement = pbyBuffer[dwCnt + 2];
					break;
				}
				else if(pbyBuffer[dwCnt] == 0x81 && pbyBuffer[dwCnt + 1] == 0xC1)
				{
					dwDisplacement = *(DWORD *)&pbyBuffer[dwCnt + 2];
					break;
				}
			}
			if(dwDisplacement == 0)
			{
				return false;
			}
			else
			{
				if(!GetXorerMZOffset(dwOrgFileOffset, dwOrgFileSize, dwDecLevel, dwDecLength))
				{					
					m_pMaxPEFile->CloseFile_NoMemberReset();
					return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : REPAIR_FAILED;
				}
			}
		}
		else
		{
			if(!GetXorerMZOffset(dwOrgFileOffset, dwOrgFileSize, dwDecLevel, dwDecLength))
			{			
				m_pMaxPEFile->CloseFile_NoMemberReset();
				return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : REPAIR_FAILED;
			}
			dwDecLevel = 0;
		}
		if(dwStartOfSecondDecryp == 0x27B && m_dwAEPUnmapped == 0x7A76 && m_wNoOfSections == 3)
		{
			dwStartOfSecondDecryp += 1;
		}
		if(CopyXorerData(dwOrgFileOffset, 0, dwOrgFileSize, 0xFF, dwDecLength, dwStartOfSecondDecryp ,dwDisplacement, dwDecLevel))
		{
			if(m_pMaxPEFile->ForceTruncate(dwOrgFileSize))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: GetXorerMZOffset
	In Parameters	: DWORD &dwOriFileOffset, DWORD &dwOriFileSize, DWORD &dwDecLevel, DWORD &dwDecLen
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get Binary file start (MZ) offset
--------------------------------------------------------------------------------------*/
bool CPolyXorer::GetXorerMZOffset(DWORD &dwOriFileOffset, DWORD &dwOriFileSize, DWORD &dwDecLevel, DWORD &dwDecLen)
{
	BYTE	byNewTemp[0x101] = {0};	
	DWORD dwTemp = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
	if(!m_pMaxPEFile->ReadBuffer(&byNewTemp, dwTemp , 0x101, 0x101))
	{
		return false;
	}
	DWORD dwCnt = 0;
	for(dwCnt = 0; dwCnt <= 0x100; dwCnt++)
	{
		if((byNewTemp[dwCnt] == 0xB2) && (byNewTemp[dwCnt + 1] == 0x5A || byNewTemp[dwCnt + 1] == 0xA5))
		{
			dwOriFileOffset = dwCnt + dwTemp;
			dwDecLevel = 6;
			break;
		}
		if((byNewTemp[dwCnt] == 0x4D) && (byNewTemp[dwCnt + 1] == 0x5A))
		{
			dwOriFileOffset = dwCnt + dwTemp;
			dwDecLevel = 4;
			break;
		}
	}
	if(dwCnt == 0x101)
	{
		return false;
	}
	dwOriFileSize = *(DWORD *)&byNewTemp[dwCnt- 0x8];
	
	///**** added ****/
	//if(dwCnt > 0xB)
	//{
	//	if(dwDecLnth > dwOriFileSize)
	//	{		
	//		DWORD dwTempdecLen = 0;
	//		dwTempdecLen = *(DWORD *)&byNewTemp[0] + dwCnt - 0x8;
	//		if(dwTempdecLen != dwDecLnth && (dwTempdecLen < m_pMaxPEFile->m_dwFileSize))
	//		{
	//			dwDecLnth = dwTempdecLen;
	//			//return false;
	//		}		
	//	}	
	//}
	/****** added ****/

	//Check original file size valid or not
	if(((dwOriFileOffset + dwOriFileSize) > m_pMaxPEFile->m_dwFileSize) || (dwOriFileSize == 0))
	{
		return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CopyXorerData
	In Parameters	: DWORD &dwOriFileOffset, DWORD &dwOriFileSize, DWORD &dwDecLevel, DWORD &dwDecLen
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get infector buffer
--------------------------------------------------------------------------------------*/
bool CPolyXorer::CopyXorerData(DWORD dwReadStartAddr, 
								 DWORD dwWriteStartAddr, 
								 DWORD dwSizeOfData, 
						         DWORD dwKey/* = 0*/,
						         DWORD dwDecryptionSize/* = 0*/,
						         DWORD dwStartOfSecondDecryp/* = 0*/,
						         DWORD dwDisplacement/* = 0*/,
						         DWORD dwDecLevel/* = 6*/)
{
	BYTE *byBuffer = NULL;
	try
	{
		DWORD dwChunk = 0x10000;
		bool bcheckff = true;
		if(dwSizeOfData < dwChunk)
		{
			dwChunk = dwSizeOfData;
		}

		byBuffer = new BYTE[dwChunk];
		if(!byBuffer)
		{
			return false;
		}
		if(0 == dwDecryptionSize)
		{
			dwDecryptionSize = dwSizeOfData;
		}

		DWORD dwBytesRead = 0, dwDecryptionCnt = 0, dwSecDecryptionCnt = dwStartOfSecondDecryp, dwSecCnt = dwSecDecryptionCnt;
		bool bRet = true;
		for(DWORD dwOffset = 0; dwOffset < dwSizeOfData; dwOffset += dwChunk)
		{		
			memset(byBuffer, 0, dwChunk);
			if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwReadStartAddr + dwOffset, dwChunk, 0, &dwBytesRead))
			{
				bRet = false;
				break;
			}
			if((dwOffset + dwChunk) > dwSizeOfData || dwBytesRead != dwChunk)
			{				
				dwBytesRead = dwSizeOfData - dwOffset;				
			}
			// Xorer Dr decryption
			if(dwDecryptionSize && (dwDecryptionCnt <= dwDecryptionSize) && dwDecLevel)
			{
				DWORD dwCnt = 0, dwFirstDecDisp = 2;  
				BYTE EncMZ[] = {0xB2, 0xA5};

				//Some variants of Xorer in first level encryption encrypts every byte and some variants encrypts leaving one byte in between
				//If every byte is encrypted then we get B2A5 in first two bytes otherwise we get B25A
				if(((dwDecLevel | 2) == dwDecLevel) && !memcmp(&byBuffer[0], EncMZ, _countof(EncMZ)))
					dwFirstDecDisp = 1;

				for(dwCnt = 0; (dwCnt < dwBytesRead) && (dwDecryptionCnt < dwDecryptionSize); dwCnt += dwFirstDecDisp, dwDecryptionCnt += dwFirstDecDisp)	
				{
					if((dwDecLevel | 2) == dwDecLevel) //1st level
					{
						byBuffer[dwCnt] ^= dwKey;
					}							
				}				
				if((dwSecDecryptionCnt <= dwDecryptionSize) && ((dwDecLevel | 4) == dwDecLevel))
				{
					for(; dwSecCnt < dwBytesRead && dwSecDecryptionCnt < dwDecryptionSize; dwSecCnt += dwDisplacement, dwSecDecryptionCnt += dwDisplacement)
					{
						byBuffer[dwSecCnt] ^= dwKey;
					}
					dwSecCnt -= dwDisplacement;
					dwSecCnt = dwDisplacement - (dwBytesRead - dwSecCnt);
				}
			}

			if(!m_pMaxPEFile->WriteBuffer(byBuffer, dwWriteStartAddr + dwOffset, dwBytesRead, dwBytesRead))
			{
				bRet = false;
				break;
			}
		}
		delete [] byBuffer;
		byBuffer = NULL;
		return bRet;
	}
	catch(...)
	{
		if(byBuffer)
		{
			delete [] byBuffer;
			byBuffer = NULL;
		}
		OutputDebugString(L"Exception in CPolyXorerDr::CopyXorerData");
		return false;
	}
	return false;
}
