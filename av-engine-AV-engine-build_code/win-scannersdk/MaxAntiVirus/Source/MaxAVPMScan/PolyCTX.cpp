/*======================================================================================
FILE				: PolyCTX.cpp
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
NOTES				: This is detection module for malware CTX Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyCTX.h"
#include "PolymorphicVirus.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyCTX
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyCTX::CPolyCTX(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_dwVirusStartAdd	= 0;
	m_dwCounter			= 0;
	m_dwKey				= 0;
	m_dwCalllOffset		= 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyCTX
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyCTX::~CPolyCTX(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_arrPatchedCallOffsets.RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of CTX Family
--------------------------------------------------------------------------------------*/
int CPolyCTX::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x2800 && 
		(m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		DWORD		dwSize = m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData;
		if(dwSize - m_dwAEPMapped >= 0x30000)
		{
			dwSize = m_dwAEPMapped + 0x30000;
		}
		if(!GetPatchedCalls(m_dwAEPMapped, dwSize, m_wNoOfSections - 1, true))
		{
			return iRetStatus;
		}

		WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
		iRetStatus = DetectCTX();
		SetEvent(CPolymorphicVirus::m_hEvent);	
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectCTX
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of CTX Family
--------------------------------------------------------------------------------------*/
int CPolyCTX::DetectCTX(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	char szBreakPoint[1024];
	int iEmulateStatus = 0; 
	DWORD dwTemp = 0;

	if(m_arrPatchedCallOffsets.GetCount())
	{
		DWORD	dwMCallAddr = 0, dwCallAddr = 0; 

		LPVOID lpPos = m_arrPatchedCallOffsets.GetHighest();
		if(lpPos)
		{
			m_arrPatchedCallOffsets.GetKey(lpPos, dwCallAddr);
			m_arrPatchedCallOffsets.GetData(lpPos, m_dwCalllOffset);

			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwCallAddr, &dwMCallAddr))
			{
				return iRetStatus;
			}
			if(!(dwMCallAddr >= (m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections-1].PointerToRawData +
				m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections-1].SizeOfRawData -
				m_pMaxPEFile->m_stPEHeader.SectionAlignment - 0x100)))
			{
				return iRetStatus;
			}
			CEmulate objEmulate(m_pMaxPEFile);
			if(!objEmulate.IntializeProcess())
			{
				return iRetStatus;
			}

			objEmulate.SetEip(m_dwImageBase+dwCallAddr);

			objEmulate.SetBreakPoint("__isinstruction('xor byte ptr [e')");
			objEmulate.SetBreakPoint("__isinstruction('add byte ptr [e')");
			objEmulate.SetBreakPoint("__isinstruction('sub byte ptr [e')");
			objEmulate.SetBreakPoint("__isinstruction('not byte ptr [e')");
			objEmulate.SetBreakPoint("__isinstruction('inc byte ptr [e')");
			objEmulate.SetBreakPoint("__isinstruction('dec byte ptr [e')");

			objEmulate.SetBreakPoint("__isinstruction('xor dword ptr [e')");
			objEmulate.SetBreakPoint("__isinstruction('add dword ptr [e')");
			objEmulate.SetBreakPoint("__isinstruction('sub dword ptr [e')");
			objEmulate.SetBreakPoint("__isinstruction('not dword ptr [e')");
			objEmulate.SetBreakPoint("__isinstruction('inc dword ptr [e')");
			objEmulate.SetBreakPoint("__isinstruction('dec dword ptr [e')");

			objEmulate.SetNoOfIteration(115);

			while(true)
			{
				iEmulateStatus = objEmulate.EmulateFile();
				if(7 == iEmulateStatus)
				{
					dwTemp = objEmulate.GetMemoryOprand();
					if(dwTemp == -1 || dwTemp <= m_dwImageBase)
					{
						continue;
					}
					if(((dwTemp - m_dwImageBase) % m_pMaxPEFile->m_stPEHeader.FileAlignment) == 0 )
					{
						m_dwVirusStartAdd = dwTemp;
						break;
					}
					else
					{
						continue;
					}
				}
				else 
				{
					return iRetStatus;
				}
			}

			memset(szBreakPoint, 0, 1024);
			sprintf_s(szBreakPoint, 1024, "__lastmodified(0)==0x%08x", m_dwVirusStartAdd);
			objEmulate.SetBreakPoint(szBreakPoint);

			memset(szBreakPoint, 0, 1024);
			
			objEmulate.SetBreakPoint("__isinstruction('jz')");
			objEmulate.SetBreakPoint("__isinstruction('jnz')");
			objEmulate.SetBreakPoint("__isinstruction('je')");
			objEmulate.SetBreakPoint("__isinstruction('jne')");

			objEmulate.PauseBreakPoint(0);
			objEmulate.PauseBreakPoint(1);
			objEmulate.PauseBreakPoint(2);
			objEmulate.PauseBreakPoint(3);
			objEmulate.PauseBreakPoint(4);
			objEmulate.PauseBreakPoint(5);

			objEmulate.PauseBreakPoint(6);
			objEmulate.PauseBreakPoint(7);
			objEmulate.PauseBreakPoint(8);
			objEmulate.PauseBreakPoint(9);
			objEmulate.PauseBreakPoint(10);
			objEmulate.PauseBreakPoint(11);


			m_pbyBuff = new BYTE [CTX6886_BUFF_SIZE];
			if(m_pbyBuff == NULL)
			{
				return iRetStatus;
			}
			bool bLoop = true;
			while(1)
			{
				memset(&m_pbyBuff[0], 0, CTX6886_BUFF_SIZE);
				bLoop = true;
				objEmulate.PauseBreakPoint(13);
				objEmulate.PauseBreakPoint(14);
				objEmulate.PauseBreakPoint(15);
				objEmulate.PauseBreakPoint(16);

				objEmulate.ActiveBreakPoint(12);
				objEmulate.SetNoOfIteration(200);
				
				if(7 != objEmulate.EmulateFile())
				{
					return iRetStatus;
				}

				objEmulate.PauseBreakPoint(12);
				objEmulate.ActiveBreakPoint(13);
				objEmulate.ActiveBreakPoint(14);
				objEmulate.ActiveBreakPoint(15);
				objEmulate.ActiveBreakPoint(16);
				objEmulate.SetNoOfIteration(200);

				if(0 == GetDecParam(objEmulate))
				{
					return iRetStatus;
				}

				while(1)
				{
					if( 7 == objEmulate.EmulateFile())
					{
						DWORD	dwLen = objEmulate.GetInstructionLength();
						if(dwLen < 5)
						{
							continue;
						}
						dwTemp = objEmulate.GetJumpAddress();
						if(((signed int)(objEmulate.GetEip() - dwTemp) > 30) || 
							((signed int)(dwTemp - objEmulate.GetEip()) > 30))
						{	
							if(objEmulate.GetEip() > m_dwVirusStartAdd &&  (objEmulate.GetEip() - m_dwVirusStartAdd) < CTX6886_BUFF_SIZE)
							{
								objEmulate.ModifiedZeroFlag(true);
								m_dwCounter = objEmulate.GetEip() - m_dwVirusStartAdd;
								break;
							}
							else
							{
								return iRetStatus;
							}
						}
						else
						{
							continue;
						}
					}					
					else
					{
						return iRetStatus;
					}
				}
				if(!objEmulate.ReadEmulateBuffer(m_pbyBuff, m_dwCounter, m_dwVirusStartAdd))
				{
					return iRetStatus;
				}
				if(0 == DoDecryption())
				{
					return iRetStatus;
				}
				if(*((DWORD*)&m_pbyBuff[0]) == 0xE8)
				{
					iRetStatus = VIRUS_FILE_REPAIR;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.CTX"));
					return iRetStatus;
				}
				if(!objEmulate.WriteBuffer(m_pbyBuff, m_dwCounter, m_dwVirusStartAdd))
				{
					return iRetStatus;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DoDecryption
	In Parameters	: 
	Out Parameters	: 1 for Success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption routine for CTX Family
--------------------------------------------------------------------------------------*/
int CPolyCTX::DoDecryption()
{
	DWORD dwVirBodyCnt = 1;

	switch(eOperation)
	{
	case BYTE_XOR :
		for(DWORD dwBuffIndex = 1; dwBuffIndex < m_dwCounter; dwBuffIndex++)
		{
			m_pbyBuff[dwBuffIndex] ^=(BYTE)m_dwKey;
		}
		break;

	case BYTE_ADD:
		for(DWORD dwBuffIndex = 1; dwBuffIndex < m_dwCounter ; 
			dwBuffIndex++)
		{
			m_pbyBuff[dwBuffIndex] +=(BYTE)m_dwKey;
		}			
		break;

	case BYTE_NOT:
		for(DWORD dwBuffIndex = 1; dwBuffIndex < m_dwCounter ; 
			dwBuffIndex++)
		{
			m_pbyBuff[dwBuffIndex] = ~(m_pbyBuff[dwBuffIndex]);
		}			
		break;

	case BYTE_SUB:
		for(DWORD dwBuffIndex = 1; dwBuffIndex < m_dwCounter ; 
			dwBuffIndex++)
		{
			m_pbyBuff[dwBuffIndex] = m_pbyBuff[dwBuffIndex] -(BYTE)m_dwKey;
		}			
		break;

	case DWORD_NOT:
		for(DWORD dwBuffIndex = 4; dwBuffIndex < m_dwCounter; 
			dwBuffIndex+=4)
		{
			*(DWORD *)&m_pbyBuff[dwBuffIndex] = ~(*(DWORD *)&m_pbyBuff[dwBuffIndex]);
			dwVirBodyCnt++;
		}
		break;

	case DWORD_SUB:
		for(DWORD dwBuffIndex = 4; dwBuffIndex < m_dwCounter; 
			dwBuffIndex+=4)
		{
			*(DWORD *)&m_pbyBuff[dwBuffIndex] -= m_dwKey;
			dwVirBodyCnt++;
		}
		break;

	case DWORD_ADD:
		for(DWORD dwBuffIndex = 4; dwBuffIndex < m_dwCounter; 
			dwBuffIndex+=4)
		{
			*(DWORD *)&m_pbyBuff[dwBuffIndex] += m_dwKey;
			dwVirBodyCnt++;
		}
		break;

	case DWORD_XOR:
		for(DWORD dwBuffIndex = 4; dwBuffIndex < m_dwCounter; 
			dwBuffIndex+=4)
		{
			*(DWORD *)&m_pbyBuff[dwBuffIndex] ^= m_dwKey;
			dwVirBodyCnt++;
		}
		break;
	}
	return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDecParam
	In Parameters	: 
	Out Parameters	: 1 for Success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Collects the Decryption Parameters
--------------------------------------------------------------------------------------*/
int CPolyCTX::GetDecParam(CEmulate &objEmulate)
{
	int iRetStatus = 0;
	char szInstruction[1024] = {0};

	objEmulate.GetInstruction(szInstruction);
	eOperation = DEFAULT_OPERATION;
	if(strstr(szInstruction, "add byte ptr"))
	{
		eOperation = BYTE_ADD;
		m_dwKey = (BYTE)objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction, "sub byte ptr"))
	{
		eOperation = BYTE_SUB;
		m_dwKey = (BYTE)objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction, "xor byte ptr"))
	{
		eOperation = BYTE_XOR;
		m_dwKey = (BYTE)objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction, "not byte ptr"))
	{
		eOperation = BYTE_NOT;
	}
	else if(strstr(szInstruction, "inc byte ptr"))
	{
		eOperation = BYTE_ADD;
		m_dwKey = 1; 
	}
	else if(strstr(szInstruction, "dec byte ptr"))
	{
		eOperation = BYTE_SUB;
		m_dwKey = 1; 
	}
	else if(strstr(szInstruction, "add dword ptr"))
	{
		eOperation = DWORD_ADD;
		m_dwKey = objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction, "sub dword ptr"))
	{
		eOperation = DWORD_SUB;
		m_dwKey = objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction, "xor dword ptr"))
	{
		eOperation = DWORD_XOR;
		m_dwKey = objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction, "not dword ptr"))
	{
		eOperation = DWORD_NOT;		
	}
	else if(strstr(szInstruction, "inc dword ptr"))
	{
		eOperation = DWORD_ADD;
		m_dwKey = 1; 
	}
	else if(strstr(szInstruction, "dec dword ptr"))
	{
		eOperation = DWORD_SUB;
		m_dwKey = 1; 
	}
	if(eOperation != DEFAULT_OPERATION)
	{
		iRetStatus = 1;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of CTX Family
--------------------------------------------------------------------------------------*/
int CPolyCTX::CleanVirus()
{
	int	iRetStatus = REPAIR_FAILED;

	DWORD dwBuffIndex = 0; 
	BYTE	bySignature[] = {0x6A, 0x05, 0xE8, 0x05, 0x00, 0x00, 0x00};

	for(DWORD dwIndex = 0; dwIndex < 0x400; dwIndex++)
	{
		if(0 == memcmp(&m_pbyBuff[dwIndex], &bySignature[0], sizeof(bySignature)))
		{
			dwBuffIndex = dwIndex + sizeof(bySignature);
			break;
		}
	}

	if((m_pbyBuff[dwBuffIndex] == 0xFF && m_pbyBuff[dwBuffIndex+1] == 0x15)|| m_pbyBuff[dwBuffIndex] == 0xE8)
	{

		m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwBuffIndex], m_dwCalllOffset, 5);			
		m_pMaxPEFile->Rva2FileOffset(m_dwVirusStartAdd-m_dwImageBase, &m_dwVirusStartAdd);
		if(m_pMaxPEFile->TruncateFile(m_dwVirusStartAdd, true))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}

