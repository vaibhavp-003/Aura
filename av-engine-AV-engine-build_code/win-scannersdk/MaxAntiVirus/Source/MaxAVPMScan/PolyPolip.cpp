/*======================================================================================
FILE				: PolyPolip.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Rupali Sonawane + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malware Polip Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyPolip.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyPolip
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Rupali Sonawane
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyPolip::CPolyPolip(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_pbyBuff = new BYTE[CALL_BUFF_SIZE];
	m_iNoOfParts = 0;
	m_bCallInAEPSec = false;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyPolip
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Rupali Sonawane
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyPolip::~CPolyPolip(void)
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
	Author			: Rupali Sonawane + Virus Analysis Team
	Description		: Detection routine for different varients of Dundun Family
					  This function check is file is infected by Polip.A by 
					  looking into section header properties. If matches then
					  checks the section for virus code
--------------------------------------------------------------------------------------*/
int CPolyPolip::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		WORD wVirusSection = GetPolipAVirusSection();
		if(!wVirusSection || wVirusSection == m_wAEPSec)
			return iRetStatus;

		// Search for the virus decryption code in virus section. Virus keeps its
		// encryped code in the 1st half of the virus section and decryption code
		// is in the 2nd half so skip first POLIP_ENCRY_CODE_SIZE byets. 
			
		DWORD dwScanStartOffset = POLIP_ENCRY_CODE_SIZE;
		if(POLIP_ENCRY_CODE_SIZE > (m_pSectionHeader[wVirusSection].SizeOfRawData / 2)) 
		{
			dwScanStartOffset = (m_pSectionHeader[wVirusSection].SizeOfRawData / 2);
		}
		dwScanStartOffset += m_pSectionHeader[wVirusSection].PointerToRawData;
		if(PolipA_ScanVirusSection(wVirusSection, wVirusSection, dwScanStartOffset))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Polip.A"));
			iRetStatus = VIRUS_FILE_REPAIR;
		}
		else
		{
			// Some times call to the decryption code lies at the end of AEP section
			// so if call is not present in the virus section then scan 0x1000 bytes
			// at the end of AEP section
			dwScanStartOffset = m_dwAEPMapped;
			if(m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - dwScanStartOffset > POLIPA_AEP_SEC_BUFF)
			{
				dwScanStartOffset = m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - POLIPA_AEP_SEC_BUFF;
			}		
			if(PolipA_ScanVirusSection(wVirusSection, m_wAEPSec, dwScanStartOffset))
			{
				m_bCallInAEPSec = true;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Polip.A"));
				iRetStatus = VIRUS_FILE_REPAIR;
			}
		}
	}		
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: PolipA_ScanVirusSection
	In Parameters	: WORD wVirusSection, WORD wScanSection, DWORD dwScanStartOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Rupali Sonawane + Virus Analysis Team
	Description		: This function scans all E8 calls in the section to get offset 
				  which calls the routine which has virus decryption code.
--------------------------------------------------------------------------------------*/
bool CPolyPolip::PolipA_ScanVirusSection(WORD wVirusSection, WORD wScanSection, DWORD dwScanStartOffset)
{
	CU2U arrScannedCalls(false);
	
	BYTE *bBuffer = NULL;
	bBuffer = new BYTE[POLIP_BUFF_SIZE];
	if(bBuffer == NULL)
	{
		return false;
	}
	
	DWORD dwBytesRead = 0, dwCallAddressVA = 0, dwCallAddress = 0, dwTemp = 0;
	
	DWORD dwReadOffset = dwScanStartOffset;
	for(; dwReadOffset < m_pSectionHeader[wScanSection].PointerToRawData + m_pSectionHeader[wScanSection].SizeOfRawData; dwReadOffset += POLIP_BUFF_SIZE)
	{
		dwBytesRead = 0;
		memset(bBuffer, 0x00, POLIP_BUFF_SIZE);
		if(m_pMaxPEFile->ReadBuffer(bBuffer, dwReadOffset, POLIP_BUFF_SIZE, 0, &dwBytesRead))
		{
			for(DWORD dwOffset = 0; dwOffset < dwBytesRead; dwOffset++)
			{
				if(bBuffer[dwOffset] != 0xE8)
					continue;

				if(dwBytesRead - dwOffset < E8_INSTRUCTION_SIZE)
				{
					// offset is at the end such that we cannt read DWORD address so read 
					// last 5 bytes again so that we can read the call instruction completely
					if(m_pMaxPEFile->ReadBuffer(&dwCallAddressVA, dwReadOffset + dwOffset + 1, sizeof(DWORD), sizeof(DWORD)))
						continue;
				}
				else
				{
					dwCallAddressVA = *((DWORD *) &bBuffer[dwOffset + 1]);
				}
				dwCallAddressVA += m_pSectionHeader[wScanSection].VirtualAddress + dwReadOffset - m_pSectionHeader[wScanSection].PointerToRawData + dwOffset + E8_INSTRUCTION_SIZE;
				
				// If call is out of the virus section then skip
				if(!((dwCallAddressVA >= m_pSectionHeader[wVirusSection].VirtualAddress) && (dwCallAddress < (m_pSectionHeader[wVirusSection].VirtualAddress + m_pSectionHeader[wVirusSection].Misc.VirtualSize))))
					continue;

				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwCallAddressVA, &dwCallAddress))
					continue;
				
				// Check if the call is already scanned if so skip it
				if(arrScannedCalls.SearchItem(dwCallAddress, dwTemp))
					continue;
				arrScannedCalls.AppendItem(dwCallAddress, dwCallAddress);

				if(GetBuffer(dwCallAddress, CALL_BUFF_SIZE))
				{
					if(m_pbyBuff[0] == 0x55 && m_pbyBuff[1] == 0x8B && m_pbyBuff[2] == 0xEC)
					{
						if(CheckPolipALoop())
						{
							m_dwVirusCallAddress = dwCallAddressVA;
							m_dwAEPSecCallAddress = dwReadOffset + dwOffset;
							
							if(bBuffer)
							{
								delete []bBuffer;
								bBuffer = NULL;
							}
							return true;						
						}
					}
				}
			}
		}
	}
	if(bBuffer)
	{
		delete []bBuffer;
		bBuffer = NULL;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetPolipAVirusSection
	In Parameters	: 
	Out Parameters	: Section No. containing virus code 
	Purpose			: 
	Author			: Rupali Sonawane + Virus Analysis Team
	Description		: The function looks at the section properties to return the 
					  possibly Polip.A infected section no
--------------------------------------------------------------------------------------*/
WORD CPolyPolip::GetPolipAVirusSection()
{
	for(int iCnt = m_wNoOfSections - 1; iCnt >= 0; iCnt--)
	{
		if((_tcscmp((wchar_t *) m_pSectionHeader[iCnt].Name, L"") == 0) &&
			m_pSectionHeader[iCnt].SizeOfRawData >= 0xD000 && 
			m_pSectionHeader[iCnt].NumberOfLinenumbers == 0 && 
			m_pSectionHeader[iCnt].NumberOfRelocations == 0 && 
			m_pSectionHeader[iCnt].PointerToLinenumbers == 0 && 
			m_pSectionHeader[iCnt].PointerToRelocations == 0 && 
			m_pSectionHeader[iCnt].Characteristics == 0xE0000060)  
		{
			// 1st check is passed so proceed with next check
			return iCnt;
		}
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckPolipALoop
	In Parameters	: 
	Out Parameters	: Returns 1 if successful otherwise 0 
	Purpose			: 
	Author			: Rupali Sonawane + Virus Analysis Team
	Description		: This function does detection of the call that has major 
					  funcionality of the virus. Virus decrypts the virus code & 
					  patched call buffer in different parts by giving call to 
					  to decryption routines and copies part of virus code from 
					  buffer to file offset. So the call should have has atleast 
					  7 decryption calls and loop to copy the decrypted virus code
--------------------------------------------------------------------------------------*/
int	CPolyPolip::CheckPolipALoop()
{
	DWORD	dwOffset = 0, dwLength, dwCallInstrCnt = 0, dwXORKey = 0;
	bool	bFoundMOVInstr = false, bFoundAddrInstr = false;
	bool	bFoundPUSHInstr = false, bFoundCopyLoop = false;
	
	t_disasm da;
	BYTE	 B1, B2;
	
	m_objMaxDisassem.InitializeData();
		
	while(dwOffset < m_dwNoOfBytes - 2)
	{		
		memset(&da, 0x00, sizeof(struct t_disasm) * 1);
		B1 = *((BYTE*)&m_pbyBuff[dwOffset]);
		B2 = *((BYTE*)&m_pbyBuff[dwOffset + 1]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1 == 0xC1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if(B1 == 0xD1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}

		if(B1 == 0xC2 || B1 == 0xC3)
		{
			break;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);

		if(dwLength == 0x01 && B1 == 0xE2 && strstr(da.result, "???"))
		{
			dwOffset += 0x02;
			continue;
		}
		
		// Checking instruction for the call which calls decryption in 6 parts and
		// it has a loop to copy the virus code and transfers control to the virus code
		if(dwLength == 0x05 && B1 == 0xE8 && strstr(da.result, "CALL "))
		{
			dwCallInstrCnt++;
		}
		
		if(dwLength == 0x05 && strstr(da.result, "MOV E") && strstr(da.result, ",141"))
		{
			if(*(DWORD *)&m_pbyBuff[dwOffset + 1] == 0x141)
			{
				bFoundMOVInstr = true;			
			}
		}
		if(strstr(da.result, "PUSH DWORD PTR [E"))
		{
			if(bFoundMOVInstr)// && bFoundAddrInstr) 
				bFoundPUSHInstr = true;
		}
		if(strstr(da.result, "POP DWORD PTR [E"))
		{
			if(bFoundPUSHInstr) 
				bFoundCopyLoop = true;
		}
		
		// TODO : can add dec and JNE instructions		
		dwOffset += dwLength;
	}
	if(dwCallInstrCnt >= 7 && bFoundCopyLoop)
	{
		return 1;
	}
	return 0;
}


/*-------------------------------------------------------------------------------------
	Function		: GetOriginalPatchedBytes
	In Parameters	: 
	Out Parameters	: Returns 1 if successful otherwise 0 
	Purpose			: 
	Author			: Rupali Sonawane + Virus Analysis Team
	Description		: This function uses virus code offset found in detect method 
					  to decrypt virus code. After decryption searches for original
					  patched call addresses.
--------------------------------------------------------------------------------------*/
int CPolyPolip::GetOriginalPatchedBytes()
{
	int iRetStatus = REPAIR_FAILED;

	DWORD dwCallOffset = 0;
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwVirusCallAddress, &dwCallOffset))
	{
		return iRetStatus;
	}

	memset(m_pbyBuff, 0, CALL_BUFF_SIZE);
	if(GetBuffer(dwCallOffset, CALL_BUFF_SIZE))
	{	
		m_iNoOfParts = GetPolipParams();
		if(-1 == m_iNoOfParts)
		{	
			m_pMaxPEFile->CloseFile_NoMemberReset();
			return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : iRetStatus;
		}
		else if(m_iNoOfParts)
		{					
			// Decrypt the parts to get the original patched bytes  
			if(DecryptPolipAParts())	
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}		
	}	
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: GetPolipParams
	In Parameters	: 
	Out Parameters	: Returns 1 if successful otherwise 0 
	Purpose			: 
	Author			: Rupali Sonawane + Virus Analysis Team
	Description		: This function maintains stack through the call to get all
					  parameters for repair.
--------------------------------------------------------------------------------------*/
int	CPolyPolip::GetPolipParams()
{			
	CPtrStack dwPolipStack;
	int iStackCnt = 0;
	t_disasm da;
	
	char	szAddrCalReg[0x05] = {0}, szAddrCalReg1[0x05] = {0}, szAddrCalReg2[0x05] = {0};
	DWORD	dwOffset = 0, dwLength, dwCallInstrCnt = 0, dwBytesRead2 = 0; 
	DWORD	dwValueToPush, dwCallAddress, dwCallAddressRVA, dwAddrCal;
	bool	bFound1stInst = false, bFound2ndInst = false;
	int		iCnt = 0;	
	BYTE	B1, B2;
	
	m_objMaxDisassem.InitializeData();
	
	while(dwOffset < m_dwNoOfBytes - 2)
	{		
		memset(&da, 0x00, sizeof(struct t_disasm) * 1);
		B1 = *((BYTE*)&m_pbyBuff[dwOffset]);
		B2 = *((BYTE*)&m_pbyBuff[dwOffset + 1]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1 == 0xC1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if(B1 == 0xD1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}

		if(B1 == 0xC3 || B1 == 0xC2)
		{				
			break;
		}
		
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);

		if(dwLength == 0x01 && B1 == 0xE2 && strstr(da.result, "???"))
		{
			dwOffset += 0x02;
			continue;
		}

		// Traverse the call instruction to get the parmeters and to maintain the stack
		if(dwLength==0x05 && B1==0xE8 && strstr(da.result, "CALL "))
		{			
			dwCallAddressRVA = *((DWORD *) &m_pbyBuff[dwOffset + 1]);
			dwCallAddressRVA += m_dwVirusCallAddress + dwOffset + dwLength;

			// If call is out of the file then skip					
			if(dwCallAddressRVA >= (m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize))
			{
				dwOffset += dwLength;
				continue;
			}

			m_pMaxPEFile->Rva2FileOffset(dwCallAddressRVA, &dwCallAddress);
			
			if(dwCallAddress == 0x00)
			{
				dwOffset += dwLength;
				continue;
			}
						
			BYTE pbCallBuffer[POLIP_BUFF_SIZE] = {0};
	
			memset(pbCallBuffer, 0x00, POLIP_BUFF_SIZE);
			if(m_pMaxPEFile->ReadBuffer(pbCallBuffer, dwCallAddress, POLIP_BUFF_SIZE, 0, &dwBytesRead2))
			{
				BYTE byZeros[0x200] = {0};
				if(memcmp(pbCallBuffer, byZeros, sizeof(byZeros)) == 0)
				{
					dwPolipStack.RemoveAll();
					return -1;	
				}

				DWORD dwCallOffset = 0, dwLen = 0, dwXORKey = 0;
				bFound1stInst = bFound2ndInst = false;
				
				while(dwCallOffset < dwBytesRead2 - 2)
				{		
					memset(&da, 0x00, sizeof(struct t_disasm) * 1); 
					B1 = *((BYTE*)&pbCallBuffer[dwCallOffset]);
					B2 = *((BYTE*)&pbCallBuffer[dwCallOffset + 1]);

					//Skipping Some Instructions that couldn't be interpreted by Olly.
					if(B1 == 0xC1 && (B2 >= 0xF0 && B2 <= 0xF7))
					{
						dwCallOffset+= 0x03;
						continue;
					}
					if(B1 == 0xD1 && (B2 >= 0xF0 && B2 <= 0xF7))
					{
						dwCallOffset+= 0x02;
						continue;
					}

					if(B1 == 0xC3)
					{				
						break;
					}
					if(B1 == 0xC2)
					{
						for(int iCnt = 0; iCnt < B2; iCnt += 4)
						{
							dwPolipStack.Pop();
						}
						break;
					}
					
					dwLen = m_objMaxDisassem.Disasm((char*)&pbCallBuffer[dwCallOffset], 0x20, 0x400000, &da, DISASM_CODE);

					if(dwLen == 0x01 && B1 == 0xE2 && strstr(da.result, "???"))
					{
						dwCallOffset += 0x02;
						continue;
					}
					// Check instructions for the 2nd call which has address calculation 
					// for the decryption		
					if(dwLen == 0x03 && strstr(da.result, "MOV E") && strstr(da.result, ",[EBP+10]"))
					{			
						bFound1stInst = true;
					}
					if(dwLen == 0x03 && strstr(da.result, "MOV E") && strstr(da.result, ",[EBP+8]"))
					{		
						if(bFound1stInst)
						{
							szAddrCalReg2[0] = szAddrCalReg1[0] = szAddrCalReg[0] = da.result[4];
							szAddrCalReg2[1] = szAddrCalReg1[1] = szAddrCalReg[1] = da.result[5];
							szAddrCalReg2[2] = szAddrCalReg1[2] = szAddrCalReg[2] = da.result[6];
							szAddrCalReg2[3] = szAddrCalReg1[3] = szAddrCalReg[3] = '\0';
							bFound2ndInst = true;
						}			
					}
					if(bFound2ndInst && !dwXORKey)
					{
						if(dwLen > 0x04 && strstr(da.result, "XOR") &&
							(strstr(da.result, szAddrCalReg) || strstr(da.result, szAddrCalReg1) || strstr(da.result, szAddrCalReg2)))
						{								
							m_arrPolipConstants[iCnt].dwVirtualAddress = (DWORD)dwPolipStack.Pop();
							dwPolipStack.Pop();
							m_arrPolipConstants[iCnt].dwSizeOfDecryptionBuffer = (DWORD)dwPolipStack.Pop();
							m_arrPolipConstants[iCnt].dwDecryptionKey = (DWORD)dwPolipStack.Pop();
													
							// Address Calculation
							dwAddrCal = m_arrPolipConstants[iCnt].dwSizeOfDecryptionBuffer;
							
							dwAddrCal = dwAddrCal << 2;

							if(dwLen == 0x05)
								dwXORKey = *((DWORD*)&pbCallBuffer[dwCallOffset + 1]);
							else
								dwXORKey = *((DWORD*)&pbCallBuffer[dwCallOffset + 2]);

							m_arrPolipConstants[iCnt].dwVirtualAddress ^=  dwXORKey; 

							m_arrPolipConstants[iCnt].dwVirtualAddress += dwAddrCal;
							m_arrPolipConstants[iCnt].dwVirtualAddress -=  m_dwImageBase;

							// Its dword counter convert it to no of bytes
							m_arrPolipConstants[iCnt].dwSizeOfDecryptionBuffer *= 4;

							// virus decryption if from down to up so reduce it by size
							m_arrPolipConstants[iCnt].dwVirtualAddress -=  m_arrPolipConstants[iCnt].dwSizeOfDecryptionBuffer;

							m_arrPolipConstants[iCnt].dwSizeOfDecryptionBuffer += 4;

							iCnt++;						
							break;
						}
						// Till the time we dont get XOR key trace the register. Currently handled only MOV and XCHG instruction.
						if(dwLen == 0x02 && strstr(da.result, "MOV E") && strstr(da.result + 7, szAddrCalReg))
						{
							szAddrCalReg1[0] = da.result[4];
							szAddrCalReg1[1] = da.result[5];
							szAddrCalReg1[2] = da.result[6];
							szAddrCalReg1[3] = '\0';
						}
						if(strstr(da.result, "XCHG") && strstr(da.result, szAddrCalReg))
						{							
							if(strstr(da.result + 8, szAddrCalReg))
							{
								szAddrCalReg2[0] = da.result[5];
								szAddrCalReg2[1] = da.result[6];
								szAddrCalReg2[2] = da.result[7];
								szAddrCalReg2[3] = '\0';
							}
							else
							{
								szAddrCalReg2[0] = da.result[9];
								szAddrCalReg2[1] = da.result[0xa];
								szAddrCalReg2[2] = da.result[0xb];
								szAddrCalReg2[3] = '\0';
							}
						}
					}
					dwCallOffset += dwLen;
				}				
			}
		}
		// Maintain the stack
		if(dwLength == 0x05 && B1 == 0x68 && strstr(da.result, "PUSH "))
		{
			// Valid push instrution
			dwValueToPush = *((DWORD*)&m_pbyBuff[dwOffset + 1]);
			dwPolipStack.Push((LPVOID)dwValueToPush);							
		}
		if(dwLength == 0x01 && strstr(da.result, "PUSH E"))
		{
			// Dummy instruction but needed to handle to maintain the stack
			dwValueToPush = 0;
			dwPolipStack.Push((LPVOID)dwValueToPush);										
		}
		if(dwLength == 0x01 && strstr(da.result, "POP E"))
		{
			// Dummy instruction but needed to handle to maintain the stack
			dwPolipStack.Pop();
		}

		if(strstr(da.result, "PUSH DWORD PTR [E"))
		{
			// Dummy instruction but needed to handle to maintain the stack
			dwValueToPush = 0;
			dwPolipStack.Push((LPVOID)dwValueToPush);													
		}
		if(strstr(da.result, "POP DWORD PTR [E"))
		{
			// Dummy instruction but needed to handle to maintain the stack
			dwPolipStack.Pop();			
		}
		if(dwLength == 0x06 && B1 == 0xFF && B2 == 0x35 && strstr(da.result, "PUSH DWORD PTR ["))
		{
			// Dummy instruction but needed to handle to maintain the stack
			dwValueToPush = 0;
			dwPolipStack.Push((LPVOID)dwValueToPush);										
		}
		if(dwLength == 0x06 && B1 == 0x8F && B2 == 0x05 && strstr(da.result, "POP DWORD PTR ["))
		{
			// Dummy instruction but needed to handle to maintain the stack
			dwPolipStack.Pop();		
		}
		if(dwLength == 0x03 && B1 == 0x83 && B2 == 0xc4 && strstr(da.result, "ADD ESP,"))
		{
			// Dummy instruction but needed to handle to maintain the stack
			BYTE bElementsToRemove = *((BYTE*)&m_pbyBuff[dwOffset + 2]);
			for(int iCnt = 0; iCnt < bElementsToRemove; iCnt += 4)
			{
				dwPolipStack.Pop();				
			}			
		}
		// Exit codition 
		if(dwLength == 0x05 && strstr(da.result, "MOV E") && strstr(da.result, ",141"))
		{
			DWORD dwVal = *((DWORD*)&m_pbyBuff[dwOffset + 1]);
			if(dwVal == 0x141)
			{
				break;			
			}
		}
		dwOffset += dwLength;
	}
	dwPolipStack.RemoveAll();
	return (iCnt > 4 ? iCnt:0);	
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Rupali Sonawane + Virus Analysis Team
	Description		: The function maintains the addresses where virus has patched
					  the call and calls PolipA_ScanVirusSection function to 
					  replace	the patches call with the original call also removes 
					  the infected section
--------------------------------------------------------------------------------------*/
int CPolyPolip::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;

	WORD wVirusSection = GetPolipAVirusSection();
	if(wVirusSection)
	{
		bool bFoundPatchedCall = false;
		DWORD dwCallAddressVA = 0, dwCallAddress = 0;
		const BYTE bSignature[] = {0x55, 0x8B, 0xEC, 0x83, 0xEC};
		const int SIGNATURE_LEN = sizeof(bSignature);
		BYTE bBytesFromFile[SIGNATURE_LEN];
		
		for(DWORD dwReadOffset = m_pSectionHeader[m_wAEPSec].PointerToRawData; dwReadOffset < m_pSectionHeader[m_wAEPSec].SizeOfRawData; dwReadOffset += POLIP_BUFF_SIZE)
		{
			if(GetBuffer(dwReadOffset, POLIP_BUFF_SIZE))
			{
				for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes; dwOffset++)
				{
					if(m_pbyBuff[dwOffset] != 0xE8)
						continue;
					
					if(m_dwNoOfBytes - dwOffset < E8_INSTRUCTION_SIZE)
					{
						// offset is at the end such that we cannt read DWORD address so read 
						// last 5 bytes again so that we can read the call instruction completely
						if(m_pMaxPEFile->ReadBuffer(&dwCallAddressVA, dwReadOffset + dwOffset + 1, sizeof(DWORD), sizeof(DWORD)))
							continue;
					}
					else
					{
						dwCallAddressVA = *((DWORD *) &m_pbyBuff[dwOffset + 1]);
					}
					dwCallAddressVA += m_pSectionHeader[m_wAEPSec].VirtualAddress + dwReadOffset - m_pSectionHeader[m_wAEPSec].PointerToRawData  + 
										dwOffset + E8_INSTRUCTION_SIZE;
						
					// If call is out of the file then skip
					if(dwCallAddressVA >= (m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize))
						continue;
					
					m_pMaxPEFile->Rva2FileOffset(dwCallAddressVA, &dwCallAddress);
					if(dwCallAddress == 0x00)
						continue;

					// check if the call is in the virus section. If so its virus patched call.
					if((dwCallAddress >= m_pSectionHeader[wVirusSection].PointerToRawData) && 
						(dwCallAddress < (m_pSectionHeader[wVirusSection].SizeOfRawData + m_pSectionHeader[wVirusSection].PointerToRawData)))
					{
						memset(bBytesFromFile, 0x00, SIGNATURE_LEN);
						if(m_pMaxPEFile->ReadBuffer(bBytesFromFile, dwCallAddress, SIGNATURE_LEN, SIGNATURE_LEN))
							continue;
						
						if(memcmp(bBytesFromFile, bSignature, SIGNATURE_LEN) != 0) 
							continue;
					
						// Found patched E8 so maintain the address
						m_arrPatchedCallOffsets.AppendItem(dwReadOffset + dwOffset, dwReadOffset + dwOffset);
					}
				}
			}
		}
		if(GetOriginalPatchedBytes())
		{
			if(m_bCallInAEPSec)
			{
				m_pMaxPEFile->FillWithZeros(m_dwAEPSecCallAddress, m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData - m_dwAEPSecCallAddress);
			}

			//Delete no name Section added by virus
			if(m_pMaxPEFile->RemoveSection(wVirusSection + 1))
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
	}	
	m_arrPatchedCallOffsets.RemoveAll();
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DecryptPolipAParts
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Rupali Sonawane + Manjunath + Virus Analysis Team
	Description		: Repair routine for different varients of Polip Family
--------------------------------------------------------------------------------------*/
bool CPolyPolip::DecryptPolipAParts()
{
	DWORD dwBytesRead = 0, dwBytesToRead, dwTotalBytesToRead = 0, dwFileOffset;

	//Sort according to file offset
	SortPolipFunctionParameters();

	for(int i = 0; i < m_iNoOfParts; i++)
	{
		dwTotalBytesToRead += m_arrPolipConstants[i].dwSizeOfDecryptionBuffer;
	}

	BYTE *pbReadBuff = NULL;
	pbReadBuff = new BYTE[dwTotalBytesToRead];
	if(pbReadBuff == NULL)
		return false;
	
	dwTotalBytesToRead = 0;
	for(int i = 0; i < m_iNoOfParts; i++)
	{
		dwBytesToRead = m_arrPolipConstants[i].dwSizeOfDecryptionBuffer;
		m_pMaxPEFile->Rva2FileOffset(m_arrPolipConstants[i].dwVirtualAddress, &dwFileOffset);
	
		memset(&pbReadBuff[dwTotalBytesToRead], 0x00, dwBytesToRead);
		if(!m_pMaxPEFile->ReadBuffer(&pbReadBuff[dwTotalBytesToRead], dwFileOffset, dwBytesToRead, dwBytesToRead, &dwBytesRead))
		{
			if(pbReadBuff)
			{
				delete []pbReadBuff;
				pbReadBuff = NULL;
			}
			return false;
		}
		PolipFirstLevelDecryption(&pbReadBuff[dwTotalBytesToRead], dwBytesRead, m_arrPolipConstants[i].dwDecryptionKey);		
		dwTotalBytesToRead += dwBytesRead;
	}

	if(!PolipSecondLevelDecryption(pbReadBuff, dwTotalBytesToRead))
	{
		if(pbReadBuff)
		{
			delete []pbReadBuff;
			pbReadBuff = NULL;
		}
		return false;
	}

	// Cleaning code. Overwrite patch bytes
	/*if(0x15ff != *(WORD *)&pbReadBuff[dwTotalBytesToRead - 0x107] && 0x25ff != *(WORD *)&pbReadBuff[dwTotalBytesToRead - 0x107])
	{
		if(pbReadBuff)
		{
			delete []pbReadBuff;
			pbReadBuff = NULL;
		}
		return false;
	}*/

	
	DWORD dwPatchOffset, dwBytesWritten = 0;
	DWORD dwNoOfTimesPatched = 0;

	for(DWORD dwOffset = 0x00; dwOffset < 0xBD; dwOffset += 4)
	{
		dwPatchOffset =  *(DWORD *)&pbReadBuff[dwTotalBytesToRead - 0xBD + dwOffset];
		if(dwPatchOffset == 0x00 || OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwPatchOffset, &dwFileOffset))
		{
			break;
		}
				
		if(!m_pMaxPEFile->WriteBuffer(&pbReadBuff[dwTotalBytesToRead - 0x107], dwFileOffset, 0x06, 0x06))
		{
			if(pbReadBuff)
			{
				delete []pbReadBuff;
				pbReadBuff = NULL;
			}
			return false;
		}
		dwNoOfTimesPatched++;		
	}
	
	if(pbReadBuff)
	{
		delete []pbReadBuff;
		pbReadBuff = NULL;
	}

	if(0 != m_arrPatchedCallOffsets.GetCount())
	{
		if(dwNoOfTimesPatched != m_arrPatchedCallOffsets.GetCount())
			return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: SortPolipFunctionParameters
	In Parameters	: 
	Out Parameters	: TRUE if success else FALSE
	Purpose			: 
	Author			: Rupali Sonawane + Manjunath + Virus Analysis Team
	Description		: 
--------------------------------------------------------------------------------------*/
BOOL CPolyPolip::SortPolipFunctionParameters()
{
    DWORD dwMin;
	int minat;
	POLIP_CONSTANTS_STRUCT temp;

	for(int i = 0x00; i < (m_iNoOfParts - 1); i++)
	{
		minat = i;
		dwMin = m_arrPolipConstants[i].dwVirtualAddress;

		for(int j = i + 1; j < m_iNoOfParts; j++)
		{
			if(dwMin > m_arrPolipConstants[j].dwVirtualAddress)
			{
				minat = j;
				dwMin = m_arrPolipConstants[j].dwVirtualAddress;
			}
		}
		temp = m_arrPolipConstants[i];
		m_arrPolipConstants[i] = m_arrPolipConstants[minat];
		m_arrPolipConstants[minat] = temp;	
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: PolipFirstLevelDecryption
	In Parameters	: BYTE *Buff, DWORD BuffLen, DWORD Key
	Out Parameters	: TRUE if success else FALSE
	Purpose			: 
	Author			: Rupali Sonawane + Manjunath + Virus Analysis Team
	Description		: 
--------------------------------------------------------------------------------------*/
BOOL CPolyPolip::PolipFirstLevelDecryption(BYTE *Buff, DWORD BuffLen, DWORD Key)
{
	DWORD i;
	DWORD EncValue = 0x00, DecValue = 0x00, Length = 0x00;
	unsigned long eValue[2];

	//To make sure buffer length is always multiple of 4
	Length = BuffLen - (BuffLen % 4); 

	for(i = 0x00; i < Length; i += 0x04)
	{
		EncValue = *(DWORD *)&Buff[i]; 
		eValue[0] = LOWORD(EncValue);
		eValue[1] = HIWORD(EncValue);
		DecryptPolipUsingXTEA(5, &eValue[0], Key);
		DecValue = MAKELONG(eValue[0], eValue[1]);
		memcpy(&Buff[i], &DecValue, 4);
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptPolipUsingXTEA
	In Parameters	: unsigned int num_rounds, unsigned long *value, unsigned long key
	Out Parameters	: TRUE if success else FALSE
	Purpose			: 
	Author			: Rupali Sonawane + Manjunath + Virus Analysis Team
	Description		: Decryption routine : XTEA
--------------------------------------------------------------------------------------*/
BOOL CPolyPolip::DecryptPolipUsingXTEA(unsigned int num_rounds, unsigned long *value, unsigned long key) 
{
    unsigned int i;
	unsigned long delta=0x9E37F9B9, sum=0x1717E09D;

	WORD v0 = (WORD)value[0], v1 = (WORD)value[1];
    for (i = 0; i < num_rounds; i++) 
	{
		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ LOWORD((sum + key));
		sum -= delta;
		v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ HIWORD((sum + key));
		if (sum == 0x00)
			break;
    }
    value[0] = v0; value[1] = v1;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: PolipSecondLevelDecryption
	In Parameters	: BYTE *Buff,  DWORD BuffLen
	Out Parameters	: TRUE if success else FALSE
	Purpose			: 
	Author			: Rupali Sonawane + Virus Analysis Team
	Description		: Decryption routine : Second Level
--------------------------------------------------------------------------------------*/
BOOL CPolyPolip::PolipSecondLevelDecryption(BYTE *Buff,  DWORD BuffLen)
{
	const BYTE FirstDecSig[] = { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5A, 0xB9, 0x3B, 
								0x01, 0x00, 0x00, 0x81, 0xB4, 0x8A, 0x0F, 0x00, 0x00, 0x00 };

	const BYTE SecDecSig[] = { 0x8B, 0x74, 0x24, 0x2C, 0x8B, 0xFA, 0x8D, 0x86, 0x17, 
								0x05, 0x00, 0x00, 0xB9, 0x45, 0x71, 0x00, 0x00, 0xB2 };

	if (BuffLen < 0x141)
		return false;

	if(BuffLen < PATCH_BUFF_SIZE + BUFF_OFFSET)
		return false;

	if(memcmp(&Buff[EXTRA_BYTES], &FirstDecSig[0], sizeof(FirstDecSig)) != 0) 
		return false;
	
	//Decryption of virus code that has key to decrypt patched bytes
	DWORD dwKey = *(DWORD *)&Buff[EXTRA_BYTES + 0x13];
	for(DWORD dwOffset = VIRUS_CODE_SIZE; dwOffset > 0; dwOffset--)
	{
		*(DWORD *)&Buff[EXTRA_BYTES + (dwOffset * 0x04) + 0x06 + 0x0F] ^=  dwKey;
	}

	if(memcmp(&Buff[EXTRA_BYTES + 0x3D], &SecDecSig[0], sizeof(SecDecSig)) != 0) 
		return false;
	
	//Decryption of buffer containing original patched bytes 
	dwKey = Buff[EXTRA_BYTES + 0x4F];
	for(DWORD dwOffset = 0; dwOffset < PATCH_BUFF_SIZE; dwOffset++)
	{
		Buff[BUFF_OFFSET + dwOffset] ^=  LOBYTE(dwKey);
		dwKey++;
	}
	return true;
}