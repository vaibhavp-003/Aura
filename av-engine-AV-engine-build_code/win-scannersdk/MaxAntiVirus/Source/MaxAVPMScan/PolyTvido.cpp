/*======================================================================================
FILE				: PolyTvido.cpp
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
NOTES				: This is detection module for malware Tvido Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyTvido.h"
#include "PolymorphicVirus.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyTvido
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyTvido::CPolyTvido(CMaxPEFile *pMaxPEFile)
:CPolyBase(pMaxPEFile)
{
	m_dwHdrSigStart = 0x00;
	ResetParam();
}

/*-------------------------------------------------------------------------------------
	Function		: ResetParam
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Initializes all variables required for detection
--------------------------------------------------------------------------------------*/
void CPolyTvido::ResetParam()
{
	m_dwDecKey		= 0;
	m_dwStartOfDec	= 0;
	m_dwType		= 0;
	m_dwKeyChngType = 0;
	m_dwKeyChngKey	= 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyTvido
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyTvido::~CPolyTvido(void)
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
	Description		: Detection routine for different varients of Tvido Family
--------------------------------------------------------------------------------------*/
int CPolyTvido::DetectVirus(void)
{	
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData == 0x00 && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x00 &&
		_tcscmp((wchar_t *) m_pSectionHeader[m_wNoOfSections - 1].Name, L"") == 0 &&
		_tcscmp((wchar_t *) m_pSectionHeader[m_wNoOfSections - 2].Name, L"") == 0)
	{	
		m_pbyBuff = new BYTE[TVIDO_BUFF_SIZE];		
		if(GetBuffer(0x00, 0x50, 0x40))
		{
			BYTE bTvidoSigA[] = {0x56, 0x69, 0x72, 0x75, 0x73, 0x20, 0x57, 0x65, 0x65, 0x44, 0x20, 0x76, 0x31, 0x2E, 0x31, 0x20,
				0x4D, 0x61, 0x64, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x42, 0x65, 0x6C, 0x61, 0x72, 0x75, 0x73, 0x21};

			BYTE bTvidoSigB[] = {0x56, 0x69, 0x72, 0x75, 0x73, 0x20, 0x57, 0x65, 0x65, 0x44, 0x20, 0x32, 0x2E, 0x30, 0x20,
				0x4D, 0x61, 0x64, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x42, 0x65, 0x6C, 0x61, 0x72, 0x75, 0x73, 0x21};

			for(DWORD dwIndex = 0x00; dwIndex < m_dwNoOfBytes - sizeof(bTvidoSigA); dwIndex++)
			{
				if (memcmp(&m_pbyBuff[dwIndex], bTvidoSigA, sizeof(bTvidoSigA)) == 0)
				{
					m_dwHdrSigStart = dwIndex;
					m_dwTvidoType = 0x01;
					break;
				}
				if (memcmp(&m_pbyBuff[dwIndex], bTvidoSigB, sizeof(bTvidoSigB)) == 0)
				{
					m_dwHdrSigStart = dwIndex;
					m_dwTvidoType = 0x02;
					break;
				}
			}
			if(m_dwTvidoType)
			{
				memset(m_pbyBuff, 0x00, TVIDO_BUFF_SIZE);
				if(GetBuffer(m_dwAEPMapped, 0x10, 0x05))
				{
					if(m_dwTvidoType == 0x01 && m_pbyBuff[0x00] == 0xE8)
					{
						DWORD dwOffset = *((DWORD *)&m_pbyBuff[0x01]) + 0x05 + m_dwAEPUnmapped;
						if(dwOffset == m_pSectionHeader[m_wNoOfSections - 2].VirtualAddress)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Tvido.A"));
							return VIRUS_FILE_REPAIR;
						}
					}
					else if(m_dwTvidoType == 0x02 && m_pbyBuff[0x00] == 0x60 && m_pbyBuff[0x01] == 0xE8)
					{
						DWORD dwOffset = *((DWORD *)&m_pbyBuff[0x02]) + 0x06 + m_dwAEPUnmapped;
						if(dwOffset == m_pSectionHeader[m_wNoOfSections - 2].VirtualAddress)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Tvido.B"));
							return VIRUS_FILE_REPAIR;
						}
					}
				}
			}			
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Tvido Family
--------------------------------------------------------------------------------------*/
int CPolyTvido::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	if(m_dwTvidoType == 0x01)
	{
		iRetStatus = CleanTvidoA();
	}
	else if(m_dwTvidoType == 0x02)
	{
		WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
		iRetStatus = CleanTvidoB();
		SetEvent(CPolymorphicVirus::m_hEvent);
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTvidoA
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for : Virus.W32.Tvido.A
--------------------------------------------------------------------------------------*/
int CPolyTvido::CleanTvidoA()
{
	int iRetStatus = REPAIR_FAILED;

	if(GetBuffer(m_pSectionHeader[m_wNoOfSections - 2].PointerToRawData, TVIDO_BUFF_SIZE, TVIDO_BUFF_SIZE))
	{		
		DWORD dwDecKey = *((DWORD *)&m_pbyBuff[TVIDO_KEY_POS]);
		DWORD dwStartKey = dwDecKey, dwNewKey = 0x00;

		for(int i = TVIDO_DEC_POS; i < TVIDO_BUFF_SIZE; i++)
		{
			dwNewKey = dwStartKey;
			m_pbyBuff[i] ^= *((BYTE *)&dwNewKey);
			dwStartKey = ((dwStartKey << TVIDO_ROL_KEY) | (dwStartKey >> (0x20 - TVIDO_ROL_KEY)));
		}

		m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0xAFF], m_dwAEPMapped, 5);

		if(m_pMaxPEFile->CopyData(m_pSectionHeader[0].PointerToRawData, m_pSectionHeader[m_wNoOfSections - 2].PointerToRawData, m_pMaxPEFile->m_dwFileSize - m_pSectionHeader[0].PointerToRawData))
		{
			WORD wSec = 0x00;
			for(; wSec < m_wNoOfSections - 0x02; wSec++)
			{
				m_pSectionHeader[wSec].PointerToRawData -= m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData;
				m_pMaxPEFile->WriteSectionCharacteristic(wSec, m_pSectionHeader[wSec].PointerToRawData, SEC_PRD);
			}
			m_pSectionHeader[wSec].PointerToRawData = m_pMaxPEFile->m_dwFileSize - m_pSectionHeader[0].PointerToRawData;
			m_pMaxPEFile->WriteSectionCharacteristic(wSec, m_pSectionHeader[wSec].PointerToRawData, SEC_PRD);
		}

		m_pMaxPEFile->FillWithZeros(m_dwHdrSigStart, 0x20);				
		if(m_pMaxPEFile->RemoveLastSections(2))
		{
			iRetStatus = REPAIR_SUCCESS;
		}		
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanTvidoB
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for : Virus.W32.Tvido.B
					  // Breakpoint number description
					  // 0. Detect decryption type and decryption key
	                  // 1. Detect counter
	                  // 2. Detect decryption key change type and key.	
--------------------------------------------------------------------------------------*/
int CPolyTvido::CleanTvidoB()
{	
	// Breakpoint number description
	// 0. Detect decryption type and decryption key
	// 1. Detect counter
	// 2. Detect decryption key change type and key.

	int iRetStatus = REPAIR_FAILED;

	CEmulate objEmulate(m_pMaxPEFile);
	if(!objEmulate.IntializeProcess())
	{
		return iRetStatus;
	}

	char szBreakPoint[1024] = {0};
	char szInstruction[1024] = {0};
	objEmulate.SetBreakPoint("__isinstruction('xor dword ptr [e')");
	objEmulate.SetBreakPoint("__isinstruction('add dword ptr [e')");
	objEmulate.SetBreakPoint("__isinstruction('sub dword ptr [e')");

	objEmulate.SetBreakPoint("__isinstruction('cmp e')");
	objEmulate.SetBreakPoint("__isinstruction('test e')");

	//This breakpoint modified for every decryption so it modified every time 
	objEmulate.SetBreakPoint("");
	objEmulate.SetBreakPoint("");
	objEmulate.SetBreakPoint("");
	objEmulate.SetBreakPoint("");
	objEmulate.SetBreakPoint("");

	m_pbyBuff = new BYTE[TVIDO_B_BUFF_SIZE];
	if(m_pbyBuff == NULL)
	{
		return iRetStatus;
	}

	DWORD	dwRegNo = 0; //This contains register number (0 - 7)  of decryption key

	for (DWORD dwDecCount = 0; dwDecCount < 20; dwDecCount++)
	{
		// Only for decryption instruction breakpoint make active
		objEmulate.PauseBreakPoint(3);
		objEmulate.PauseBreakPoint(4);

		objEmulate.PauseBreakPoint(5);
		objEmulate.PauseBreakPoint(6);
		objEmulate.PauseBreakPoint(7);
		objEmulate.PauseBreakPoint(8);
		objEmulate.PauseBreakPoint(9);

		objEmulate.ActiveBreakPoint(0);
		objEmulate.ActiveBreakPoint(1);
		objEmulate.ActiveBreakPoint(2);

		objEmulate.SetNoOfIteration(0x200);
		ResetParam();

		if(7 != objEmulate.EmulateFile())
		{
			return iRetStatus;
		}

		m_dwStartOfDec = objEmulate.GetMemoryOprand();
		if(0 == GetDecParam(objEmulate))
		{
			return iRetStatus;
		}

		dwRegNo = objEmulate.GetSrcRegNo();
		if(dwRegNo == 0xFFFFFFFF)
		{
			return iRetStatus;
		}

		objEmulate.PauseBreakPoint(0);
		objEmulate.PauseBreakPoint(1);
		objEmulate.PauseBreakPoint(2);

		objEmulate.ActiveBreakPoint(3);
		objEmulate.ActiveBreakPoint(4);

		objEmulate.SetNoOfIteration(0x200);

		while(true)
		{
			if(7 != objEmulate.EmulateFile())
			{
				return iRetStatus;
			}
			
			char szInstruction[1024] = {0};
			objEmulate.GetInstruction(szInstruction);
			DWORD dwLen = objEmulate.GetInstructionLength();

			if(strstr(szInstruction, "cmp e"))
			{
				if(dwLen != 3 || !strstr(szInstruction, ",0"))
				{
					continue;
				}
			}
			else if(strstr(szInstruction, "test e"))
			{
				if(!strstr(szInstruction, ",e"))
				{
					continue;
				}
			}
			else
			{
				break;
			}

			m_dwNoOfBytes = objEmulate.GetDestinationOprand();
			if(m_dwNoOfBytes == 0)
			{
				objEmulate.SetNoOfIteration(1);
				objEmulate.PauseBreakPoint(3);
				objEmulate.PauseBreakPoint(4);
				objEmulate.EmulateFile();
				objEmulate.SetNoOfIteration(0x200);
				objEmulate.ActiveBreakPoint(3);
				objEmulate.ActiveBreakPoint(4);
				continue;
			}
			else if(-1 == m_dwNoOfBytes || m_dwNoOfBytes >= TVIDO_B_BUFF_SIZE)
			{
				return iRetStatus;
			}

			m_dwNoOfBytes+=4;
			break;
		}

		memset(szBreakPoint, 0, 1024);
		sprintf_s(szBreakPoint, 1024, "__isinstruction('add %s')", reg32[dwRegNo].c_str());
		objEmulate.ModifiedBreakPoint(szBreakPoint, 5);

		memset(szBreakPoint, 0, 1024);
		sprintf_s(szBreakPoint, 1024, "__isinstruction('sub %s')", reg32[dwRegNo].c_str());
		objEmulate.ModifiedBreakPoint(szBreakPoint, 6);

		memset(szBreakPoint, 0, 1024);
		sprintf_s(szBreakPoint, 1024, "__isinstruction('xor %s')", reg32[dwRegNo].c_str());
		objEmulate.ModifiedBreakPoint(szBreakPoint, 7);

		memset(szBreakPoint, 0, 1024);
		sprintf_s(szBreakPoint, 1024, "__isinstruction('rol %s')", reg32[dwRegNo].c_str());
		objEmulate.ModifiedBreakPoint(szBreakPoint, 8);

		memset(szBreakPoint, 0, 1024);
		sprintf_s(szBreakPoint, 1024, "__isinstruction('ror %s')", reg32[dwRegNo].c_str());
		objEmulate.ModifiedBreakPoint(szBreakPoint, 9);
		

		objEmulate.ActiveBreakPoint(0);
		objEmulate.ActiveBreakPoint(1);
		objEmulate.ActiveBreakPoint(2);

		objEmulate.PauseBreakPoint(3);
		objEmulate.PauseBreakPoint(4);

		objEmulate.ActiveBreakPoint(5);
		objEmulate.ActiveBreakPoint(6);
		objEmulate.ActiveBreakPoint(7);
		objEmulate.ActiveBreakPoint(8);
		objEmulate.ActiveBreakPoint(9);

		objEmulate.SetNoOfIteration(200);

		if(7 == objEmulate.EmulateFile())
		{
			GetKyChangeParameter(objEmulate);
		}

		if(!objEmulate.ReadEmulateBuffer(m_pbyBuff, m_dwNoOfBytes, m_dwStartOfDec))
		{
			break;
		}

		DoDecryption();
		objEmulate.SetEip(m_dwStartOfDec);

		if(m_pbyBuff && m_pbyBuff[0] == 0xE8 && *((DWORD*)&m_pbyBuff[1]) == 0x00)
		{	
			DWORD dwTemp = 0x00;
			dwTemp = *((DWORD*)&m_pbyBuff[0x21]);
			if(dwTemp > m_dwNoOfBytes)
			{
				return iRetStatus;
			}

			m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwTemp+5], m_dwAEPMapped, 0x06);

			if(m_pMaxPEFile->CopyData(m_pSectionHeader[0].PointerToRawData, m_pSectionHeader[m_wNoOfSections - 2].PointerToRawData, m_pMaxPEFile->m_dwFileSize - m_pSectionHeader[0].PointerToRawData))
			{
				WORD wSec = 0x00;
				for(; wSec < m_wNoOfSections - 0x02; wSec++)
				{
					m_pSectionHeader[wSec].PointerToRawData -= m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData;
					m_pMaxPEFile->WriteSectionCharacteristic(wSec, m_pSectionHeader[wSec].PointerToRawData, SEC_PRD);
				}
				m_pSectionHeader[wSec].PointerToRawData = m_pMaxPEFile->m_dwFileSize - m_pSectionHeader[0].PointerToRawData;
				m_pMaxPEFile->WriteSectionCharacteristic(wSec, m_pSectionHeader[wSec].PointerToRawData, SEC_PRD);
			}

			m_pMaxPEFile->FillWithZeros(m_dwHdrSigStart, 0x1F);				
			if(m_pMaxPEFile->RemoveLastSections(2))
			{
				iRetStatus = REPAIR_SUCCESS;
				return iRetStatus;
			}	
		}
		if(!objEmulate.WriteBuffer(m_pbyBuff, m_dwNoOfBytes, m_dwStartOfDec))
		{
			return iRetStatus;
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDecParam
	In Parameters	: 
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Collected the decryption information using emulator
--------------------------------------------------------------------------------------*/
int CPolyTvido::GetDecParam(CEmulate &objEmulate)
{
	char szInstruction[1024] = {0};
	objEmulate.GetInstruction(szInstruction);

	if(strstr(szInstruction, "add dword ptr"))
	{
		m_dwType = 1;
		m_dwDecKey= objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction, "sub dword ptr"))
	{
		m_dwType = 2;
		m_dwDecKey = objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction, "xor dword ptr"))
	{
		m_dwType = 3;
		m_dwDecKey = objEmulate.GetImmidiateConstant(); 
	}
	else 
	{
		return 0;
	}
	return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: DoDecryption
	In Parameters	: 
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function performs the decryption
--------------------------------------------------------------------------------------*/
int CPolyTvido::DoDecryption()
{
	switch(m_dwType)
	{
	case 1:
		for(DWORD dwTemp = 4; dwTemp < m_dwNoOfBytes - 3; dwTemp+=4)
		{
			*((DWORD*) &m_pbyBuff[dwTemp]) += m_dwDecKey;
			if(m_dwKeyChngType != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 2:
		for(DWORD dwTemp = 4; dwTemp < m_dwNoOfBytes - 3; dwTemp+=4)
		{
			*((DWORD*) &m_pbyBuff[dwTemp]) -= m_dwDecKey;
			if(m_dwKeyChngType != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 3:
		for(DWORD dwTemp = 4; dwTemp < m_dwNoOfBytes - 3; dwTemp+=4)
		{
			if(m_dwKeyChngType != 0)
			{
				DecryptKey();
			}
			*((DWORD*) &m_pbyBuff[dwTemp]) ^= m_dwDecKey;
		}
		break;
	}
	return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKyChangeParameter
	In Parameters	: 
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function performs the decryption using emulator because 
					  this virus as multiple decryption loops
--------------------------------------------------------------------------------------*/
int CPolyTvido::GetKyChangeParameter(CEmulate &objEmulate)
{
	char szInstruction[1024] = {0};

	objEmulate.GetInstruction(szInstruction);
	if(strstr(szInstruction, "add e"))
	{
		m_dwKeyChngType = 1;
		m_dwKeyChngKey = objEmulate.GetImmidiateConstant();
	}
	else if(strstr(szInstruction, "xor e"))
	{
		m_dwKeyChngType = 2;
		m_dwKeyChngKey = objEmulate.GetImmidiateConstant();
	}
	else if(strstr(szInstruction, "sub e"))
	{
		m_dwKeyChngType = 3;
		m_dwKeyChngKey = objEmulate.GetImmidiateConstant();
	}
	else if(strstr(szInstruction, "rol e"))
	{
		m_dwKeyChngType = 4;
		m_dwKeyChngKey = objEmulate.GetImmidiateConstant();
		m_dwKeyChngKey = m_dwKeyChngKey % 32;
	}
	else if(strstr(szInstruction, "ror e"))
	{
		m_dwKeyChngType = 5;
		m_dwKeyChngKey = objEmulate.GetImmidiateConstant();
		m_dwKeyChngKey = m_dwKeyChngKey % 32;
	}
	else 
	{
		return 0;
	}
	return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptKey
	In Parameters	: 
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decrypts buffer and retrieves the key for next decryption
--------------------------------------------------------------------------------------*/
int CPolyTvido::DecryptKey()
{
	switch(m_dwKeyChngType)
	{
	case 1:
		m_dwDecKey += m_dwKeyChngKey;
		break;
	case 2:
		m_dwDecKey ^= m_dwKeyChngKey;
		break;
	case 3:
		m_dwDecKey -= m_dwKeyChngKey;
		break;
	case 4:
		m_dwDecKey = m_dwDecKey << m_dwKeyChngKey | m_dwDecKey >> (32 - m_dwKeyChngKey);
		break;
	case 5:
		m_dwDecKey = m_dwDecKey >> m_dwKeyChngKey | m_dwDecKey << (32 - m_dwKeyChngKey);
		break;
	}
	return 1;
}
