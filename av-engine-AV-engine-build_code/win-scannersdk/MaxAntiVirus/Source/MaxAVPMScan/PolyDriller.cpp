/*======================================================================================
FILE				: PolyDriller.cpp
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
NOTES				: This is detection module for malware Driller Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyDriller.h"
#include "PolymorphicVirus.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyDriller
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDriller::CPolyDriller(CMaxPEFile *pMaxPEFile)
:CPolyBase(pMaxPEFile)
{
	m_dwKey = 0;
	m_dwType = 0;
	m_dwKeyChngKey = 0;
	m_dwKeyChngType = 0;
	m_eDrillerType = NO_DRILLER;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDriller
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDriller::~CPolyDriller(void)
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
	Description		: Detection routine for different varients of Driller Family
--------------------------------------------------------------------------------------*/
int CPolyDriller::DetectVirus()
{
	WaitForSingleObject(CPolymorphicVirus::m_hEvent, 100);
	int iRetStatus = DetectDrillerA();
	if(iRetStatus)
	{
		SetEvent(CPolymorphicVirus::m_hEvent);	
		return iRetStatus;
	}
	iRetStatus = DetectDrillerB();
	SetEvent(CPolymorphicVirus::m_hEvent);	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDrillerA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for varient Driller.A 
--------------------------------------------------------------------------------------*/
int CPolyDriller::DetectDrillerA()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if	(m_dwAEPUnmapped <= (m_pSectionHeader[m_wAEPSec].VirtualAddress + 0x300) && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= DRILLER_A_CODE_SIZE  &&
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xA0000000) == 0xA0000000 &&
		m_wAEPSec != m_wNoOfSections-1)
	{
		DWORD	dwVirusCodeSize = m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
		if(dwVirusCodeSize > 0x9200)
		{
			dwVirusCodeSize = 0x9200;
		}
		m_pbyBuff = new BYTE[dwVirusCodeSize];
		if(m_pbyBuff == NULL)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwAEPMapped, 0x200, 0x100))
		{
			return iRetStatus;
		}
		if(!IsDriller())
		{
			return iRetStatus;
		}
		CEmulate objEmulate(m_pMaxPEFile);
		if(0 == objEmulate.IntializeProcess())
		{
			return iRetStatus;
		}
		
		objEmulate.SetNoOfIteration(250);

		char szBreakPoint[1024] = {0};
		sprintf_s(szBreakPoint, 1024, "__isinstruction('xor dword ptr [e')");
		objEmulate.SetBreakPoint(szBreakPoint);

		memset(szBreakPoint, 0, 1024);
		sprintf_s(szBreakPoint, 1024, "__isinstruction('add dword ptr [e')");
		objEmulate.SetBreakPoint(szBreakPoint);

		memset(szBreakPoint, 0, 1024);
		sprintf_s(szBreakPoint, 1024, "__isinstruction('sub dword ptr [e')");
		objEmulate.SetBreakPoint(szBreakPoint);

		if(7 == objEmulate.EmulateFile())
		{
			if(0 == GetDecryptionParameter(objEmulate))
			{
				return iRetStatus;
			}			
			memset(m_pbyBuff, 0, dwVirusCodeSize);
			if(!objEmulate.ReadEmulateBuffer(m_pbyBuff, dwVirusCodeSize, m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress))
			{
				return iRetStatus;
			}
			m_dwNoOfBytes = dwVirusCodeSize;
			if(0 == DoDecryption(0))
			{
				return iRetStatus;
			}

			if(!objEmulate.WriteBuffer(m_pbyBuff, dwVirusCodeSize, m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress))
			{
				return iRetStatus;
			}

			iRetStatus = VIRUS_FILE_DELETE;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Driller"));

			objEmulate.SetEip(m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress);
			objEmulate.SetNoOfIteration(50);
			
			bool bLoop = true;
			while(7 == objEmulate.EmulateFile() && bLoop)
			{
				memset(szBreakPoint, 0, 1024);
				objEmulate.GetInstruction(szBreakPoint);
				if(!strstr(szBreakPoint, ",e"))
				{
					continue;
				}
				
				bLoop = false;
				DWORD	dwRegNo = objEmulate.GetSrcRegNo();
				if(dwRegNo == 0xFFFFFFFF)
				{
					return iRetStatus;
				}
				if(0 == GetDecryptionParameter(objEmulate))
				{
					return iRetStatus;
				}
				DWORD	dwTemp = objEmulate.GetMemoryOprand();
				if(dwTemp < m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)
				{
					return iRetStatus;
				}
				if((dwTemp - (m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)) > 0x100)
				{
					return iRetStatus;
				}
				dwTemp -= (m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress);

				memset(szBreakPoint, 0, 1024);
				sprintf_s(szBreakPoint, 1024, "__isinstruction('add %s')", reg32[dwRegNo].c_str());
				objEmulate.ModifiedBreakPoint(szBreakPoint, 0);

				memset(szBreakPoint, 0, 1024);
				sprintf_s(szBreakPoint, 1024, "__isinstruction('xor %s')", reg32[dwRegNo].c_str());
				objEmulate.ModifiedBreakPoint(szBreakPoint, 1);

				memset(szBreakPoint, 0, 1024);
				sprintf_s(szBreakPoint, 1024, "__isinstruction('sub %s')", reg32[dwRegNo].c_str());
				objEmulate.ModifiedBreakPoint(szBreakPoint, 2);

				memset(szBreakPoint, 0, 1024);
				sprintf_s(szBreakPoint, 1024, "__isinstruction('rol %s')", reg32[dwRegNo].c_str());
				objEmulate.SetBreakPoint(szBreakPoint);

				memset(szBreakPoint, 0, 1024);
				sprintf_s(szBreakPoint, 1024, "__isinstruction('ror %s')", reg32[dwRegNo].c_str());
				objEmulate.SetBreakPoint(szBreakPoint);
				
				if(7 != objEmulate.EmulateFile())
				{
					return iRetStatus;
				}

				if(0 == GetKyChangeParameter(objEmulate))
				{
					return iRetStatus;
				}

				m_dwNoOfBytes = 0x400;
				if(0 == DoDecryption(dwTemp))
				{
					return iRetStatus;
				}
				
				m_dwOriAEP = *((DWORD*)&m_pbyBuff[0x215]);
				if(m_dwOriAEP < m_dwImageBase || OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriAEP - m_dwImageBase, NULL))
				{
					return iRetStatus;
				}
				m_eDrillerType = DRILLER_A;
				iRetStatus = VIRUS_FILE_REPAIR;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Driller.A"));
				break;
			}
		}		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanDrillerA
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for Driller.A
--------------------------------------------------------------------------------------*/
int CPolyDriller::CleanDrillerA()
{
	int iRetStatus = REPAIR_FAILED;
	DWORD	dwNoBytesToReplace = 0;
	if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData < 0x9200)
	{
		dwNoBytesToReplace = m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - 0x5200;
	}
	else
	{
		dwNoBytesToReplace = 0x4000;
	}
	if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x5200], m_pSectionHeader[m_wAEPSec].PointerToRawData, dwNoBytesToReplace, dwNoBytesToReplace))
	{
		return iRetStatus;
	}
	m_pMaxPEFile->WriteAEP(m_dwOriAEP - m_dwImageBase);
	if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanDrillerB
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for Driller.B
--------------------------------------------------------------------------------------*/
int CPolyDriller::CleanDrillerB()
{
	int iRetStatus = REPAIR_FAILED;
	if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x30BC], m_pSectionHeader[m_wAEPSec].PointerToRawData, 0x2000, 0x2000))
	{
		return iRetStatus;
	}
	m_pMaxPEFile->WriteAEP(m_dwOriAEP - m_dwImageBase);
	if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for Driller varients
--------------------------------------------------------------------------------------*/
int CPolyDriller::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	switch(m_eDrillerType)
	{
	case DRILLER_A:
		iRetStatus = CleanDrillerA();
		return iRetStatus;
	case DRILLER_B:
		iRetStatus = CleanDrillerB();
		return iRetStatus;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDecryptionParameter
	In Parameters	: CEmulate &objEmulate (Emulator Object)
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Collects all required info using emulator;
--------------------------------------------------------------------------------------*/
int CPolyDriller::GetDecryptionParameter(CEmulate &objEmulate)
{
	char szInstruction[1024] = {0};

	objEmulate.GetInstruction(szInstruction);
	if(strstr(szInstruction, "add dword ptr"))
	{
		m_dwType = 1;
		m_dwKey = objEmulate.GetImmidiateConstant();
	}
	else if(strstr(szInstruction, "xor dword ptr"))
	{
		m_dwType = 2;
		m_dwKey = objEmulate.GetImmidiateConstant();
	}
	else if(strstr(szInstruction, "sub dword ptr"))
	{
		m_dwType = 3;
		m_dwKey = objEmulate.GetImmidiateConstant();
	}
	else 
	{
		return 0;
	}
	return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: DoDecryption
	In Parameters	: DWORD dwIndex
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption routine
--------------------------------------------------------------------------------------*/
int CPolyDriller::DoDecryption(DWORD dwIndex)
{
	switch(m_dwType)
	{
	case 1:
		for(DWORD i = dwIndex; i < m_dwNoOfBytes; i+=4)
		{
			*((DWORD*)&m_pbyBuff[i]) += m_dwKey;
			if(m_dwKeyChngType != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 2:
		for(DWORD i = dwIndex; i < m_dwNoOfBytes ; i+=4)
		{
			*((DWORD*)&m_pbyBuff[i]) ^= m_dwKey;
			if(m_dwKeyChngType != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 3:
		for(DWORD i = dwIndex; i < m_dwNoOfBytes; i+=4)
		{
			*((DWORD*)&m_pbyBuff[i]) -= m_dwKey;
			if(m_dwKeyChngType != 0)
			{
				DecryptKey();
			}
		}
	}
	return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKyChangeParameter
	In Parameters	: CEmulate &objEmulate
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function retrieves parameters using Emulator
--------------------------------------------------------------------------------------*/
int CPolyDriller::GetKyChangeParameter(CEmulate &objEmulate)
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
	Description		: Array of Decryption key
--------------------------------------------------------------------------------------*/
int CPolyDriller::DecryptKey()
{
	switch(m_dwKeyChngType)
	{
	case 1:
		m_dwKey += m_dwKeyChngKey;
		break;
	case 2:
		m_dwKey ^= m_dwKeyChngKey;
		break;
	case 3:
		m_dwKey -= m_dwKeyChngKey;
		break;
	case 4:

		m_dwKey = m_dwKey << m_dwKeyChngKey | m_dwKey >> (32 - m_dwKeyChngKey);
		break;
	case 5:
		m_dwKey = m_dwKey >> m_dwKeyChngKey | m_dwKey << (32 - m_dwKeyChngKey);
		break;
	}
	return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDrillerB
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: dtection for Driller.B
--------------------------------------------------------------------------------------*/
int CPolyDriller::DetectDrillerB()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(m_dwAEPUnmapped <= (m_pSectionHeader[m_wAEPSec].VirtualAddress + 0x200) && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= DRILLER_B_CODE_SIZE  &&
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xA0000000) == 0xA0000000 &&
		m_wAEPSec != m_wNoOfSections-1)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[DRILLER_B_CODE_SIZE];
		if(m_pbyBuff == NULL)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwAEPMapped, 0x200, 0x100))
		{
			return iRetStatus;
		}
		if(!IsDriller())
		{
			return iRetStatus;
		}

		CEmulate objEmulate(m_pMaxPEFile);
		if(0 == objEmulate.IntializeProcess())
		{
			return iRetStatus;
		}
		objEmulate.SetNoOfIteration(250);
		char szBreakPoint[1024] = {0};
		
		sprintf_s(szBreakPoint, 1024, "__isinstruction('xor dword ptr [e')");
		objEmulate.SetBreakPoint(szBreakPoint);

		memset(szBreakPoint, 0, 1024);
		sprintf_s(szBreakPoint, 1024, "__isinstruction('add dword ptr [e')");
		objEmulate.SetBreakPoint(szBreakPoint);

		memset(szBreakPoint, 0, 1024);
		sprintf_s(szBreakPoint, 1024, "__isinstruction('sub dword ptr [e')");
		objEmulate.SetBreakPoint(szBreakPoint);

		if(7 == objEmulate.EmulateFile())
		{
			if(0 == GetDecryptionParameter(objEmulate))
			{
				return iRetStatus;
			}
			memset(m_pbyBuff, 0, DRILLER_B_CODE_SIZE);
			if(!objEmulate.ReadEmulateBuffer(m_pbyBuff, DRILLER_B_CODE_SIZE, m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress))
			{
				return iRetStatus;
			}
			m_dwNoOfBytes = DRILLER_B_CODE_SIZE;
			if(0 == DoDecryption(0))
			{
				return iRetStatus;
			}

			if(!objEmulate.WriteBuffer(m_pbyBuff, DRILLER_B_CODE_SIZE, m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress))
			{
				return iRetStatus;
			}

			objEmulate.SetEip(m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress);
			objEmulate.SetNoOfIteration(50);
			
			bool bLoop = true;
			while(7 == objEmulate.EmulateFile() && bLoop)
			{
				memset(szBreakPoint, 0, 1024);
				objEmulate.GetInstruction(szBreakPoint);
				if(!strstr(szBreakPoint, ",e"))
				{
					continue;
				}
				
				bLoop = false;

				DWORD	dwRegNo = objEmulate.GetSrcRegNo();
				if(dwRegNo == 0xFFFFFFFF)
				{
					return iRetStatus;
				}
				if(0 == GetDecryptionParameter(objEmulate))
				{
					return iRetStatus;
				}
				DWORD	dwTemp = objEmulate.GetMemoryOprand();
				if(dwTemp < m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)
				{
					return iRetStatus;
				}
				if((dwTemp - (m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)) > 0x100)
				{
					return iRetStatus;
				}
				dwTemp -= (m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress);

				m_dwNoOfBytes = 0x400;
				if(0 == DoDecryption(dwTemp))
				{
					return iRetStatus;
				}

				m_dwOriAEP = *((DWORD*)&m_pbyBuff[0x1B0]);
				if(m_dwOriAEP < m_dwImageBase || OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwOriAEP - m_dwImageBase, NULL))
				{
					return iRetStatus;
				}
				m_eDrillerType = DRILLER_B;
				iRetStatus = VIRUS_FILE_REPAIR;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Driller.B"));
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: IsDriller
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Top level dtection for Driller
--------------------------------------------------------------------------------------*/
bool CPolyDriller::IsDriller()
{
	DWORD	dwLength = 0, dwOffset = 0x00;
	t_disasm	da = {0};

	while(dwOffset < m_dwNoOfBytes)
	{
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);

		if(dwLength == 10 && da.adrconst != 0x00 &&
			((m_wNoOfSections-1) == m_pMaxPEFile->Rva2FileOffset((da.adrconst-m_dwImageBase),NULL)))
		{
			return true;
		}
		dwOffset += dwLength;
	}
	return false;
}