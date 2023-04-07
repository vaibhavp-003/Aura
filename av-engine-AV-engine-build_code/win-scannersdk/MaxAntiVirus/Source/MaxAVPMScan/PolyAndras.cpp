/*======================================================================================
FILE				: PolyAndras.cpp
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
NOTES				: This is detection module for malwares PolyAndras Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyAndras.h"
#include "PolymorphicVirus.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyAndras
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAndras::CPolyAndras(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_dwKey				= 0;
	m_dwVirusStartAdd   = 0;
	m_dwOriAEPOffset    =  0xEDB;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAndras
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyAndras::~CPolyAndras(void)
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
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Detection routine for different varients of Alma Family
--------------------------------------------------------------------------------------*/
int CPolyAndras::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections-1 && 
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xA0000020)  == 0xA0000020 &&
		(m_dwAEPUnmapped % 0x100) == 0x84)
	{
		WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
		iRetStatus = DetectAndras();
		SetEvent(CPolymorphicVirus::m_hEvent);
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAndras
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Detection routine for varient : Virus.Andras.7300
--------------------------------------------------------------------------------------*/
int CPolyAndras::DetectAndras()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	CEmulate objEmulate(m_pMaxPEFile);
	if(objEmulate.IntializeProcess())
	{		
		objEmulate.SetBreakPoint("__isinstruction('sub dword ptr')");
		objEmulate.SetBreakPoint("__isinstruction('sub word ptr')");
		objEmulate.SetBreakPoint("__isinstruction('sub byte ptr')");
		objEmulate.SetBreakPoint("__isinstruction('add dword ptr')");
		objEmulate.SetBreakPoint("__isinstruction('add word ptr')");
		objEmulate.SetBreakPoint("__isinstruction('add byte ptr')");
		objEmulate.SetBreakPoint("__isinstruction('dec dword ptr')");
		objEmulate.SetBreakPoint("__isinstruction('dec word ptr')");
		objEmulate.SetBreakPoint("__isinstruction('dec byte ptr')");
		objEmulate.SetBreakPoint("__isinstruction('inc dword ptr')");
		objEmulate.SetBreakPoint("__isinstruction('inc word ptr')");
		objEmulate.SetBreakPoint("__isinstruction('inc byte ptr')");
		objEmulate.SetBreakPoint("__isinstruction('neg dword ptr')");
		objEmulate.SetBreakPoint("__isinstruction('neg word ptr')");
		objEmulate.SetBreakPoint("__isinstruction('neg byte ptr')");
		objEmulate.SetBreakPoint("__isinstruction('not dword ptr')");
		objEmulate.SetBreakPoint("__isinstruction('not word ptr')");
		objEmulate.SetBreakPoint("__isinstruction('not byte ptr')");
		objEmulate.SetBreakPoint("__isinstruction('xor dword ptr')");
		objEmulate.SetBreakPoint("__isinstruction('xor word ptr')");
		objEmulate.SetBreakPoint("__isinstruction('xor byte ptr')");

		objEmulate.SetNoOfIteration(600);
		if(7 == objEmulate.EmulateFile())
		{
			m_dwKey = objEmulate.GetImmidiateConstant();
			
			char szInstruction[1024] = {0};
			objEmulate.GetInstruction(szInstruction);
			if(GetDecryptionParam(szInstruction))
			{
				if(GetDecryptedData())
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Andras.7300"));
					iRetStatus = VIRUS_FILE_REPAIR;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDecryptionParam
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Dissassemble virus body to get parameter decryption
--------------------------------------------------------------------------------------*/
bool CPolyAndras::GetDecryptionParam(char *szInstruction)
{	
	m_eDecType = ANDRAS_DEFAULT;

	if(strstr(szInstruction, "add dword ptr"))
	{
		m_eDecType = ANDRAS_DWORD_ADD;
	}
	else if(strstr(szInstruction, "add word ptr"))
	{
		m_eDecType = ANDRAS_WORD_ADD;
	}
	else if(strstr(szInstruction, "add byte ptr"))
	{
		m_eDecType = ANDRAS_BYTE_ADD;
	}
	else if(strstr(szInstruction, "sub dword ptr"))
	{
		m_eDecType = ANDRAS_DWORD_SUB;
	}
	else if(strstr(szInstruction, "sub word ptr"))
	{
		m_eDecType = ANDRAS_WORD_SUB;
	}
	else if(strstr(szInstruction, "sub byte ptr"))
	{
		m_eDecType = ANDRAS_BYTE_SUB;
	}
	else if(strstr(szInstruction, "xor dword ptr"))
	{
		m_eDecType = ANDRAS_DWORD_XOR;
	}
	else if(strstr(szInstruction, "xor word ptr"))
	{
		m_eDecType = ANDRAS_WORD_XOR;
	}
	else if(strstr(szInstruction, "xor byte ptr"))
	{
		m_eDecType = ANDRAS_BYTE_XOR;
	}
	else if(strstr(szInstruction, "dec dword ptr"))
	{
		m_eDecType = ANDRAS_DWORD_SUB;
		m_dwKey = 1;
	}
	else if(strstr(szInstruction, "dec word ptr"))
	{
		m_eDecType = ANDRAS_WORD_SUB;
		m_dwKey = 1;
	}
	else if(strstr(szInstruction, "dec byte ptr"))
	{
		m_eDecType = ANDRAS_BYTE_SUB;
		m_dwKey = 1;
	}
	else if(strstr(szInstruction, "not dword ptr"))
	{
		m_eDecType = ANDRAS_DWORD_NEG;
		m_dwKey = 0;
	}
	else if(strstr(szInstruction, "not word ptr"))
	{
		m_eDecType = ANDRAS_WORD_NEG;
		m_dwKey = 0;
	}
	else if(strstr(szInstruction, "not byte ptr"))
	{
		m_eDecType = ANDRAS_BYTE_NEG;
		m_dwKey = 0;
	}
	else if(strstr(szInstruction, "neg dword ptr"))
	{
		m_eDecType = ANDRAS_DWORD_NEG;
		m_dwKey = 1;
	}
	else if(strstr(szInstruction, "neg word ptr"))
	{
		m_eDecType = ANDRAS_WORD_NEG;
		m_dwKey = 1;
	}
	else if(strstr(szInstruction, "neg byte ptr"))
	{
		m_eDecType = ANDRAS_BYTE_NEG;
		m_dwKey = 1;
	}
	else if(strstr(szInstruction, "inc byte ptr"))
	{
		m_eDecType = ANDRAS_BYTE_ADD;
		m_dwKey = 1;
	}
	else if(strstr(szInstruction, "inc word ptr"))
	{ 
		m_eDecType = ANDRAS_WORD_ADD;
		m_dwKey = 1;
	}
	else if(strstr(szInstruction, "inc dword ptr"))
	{
		m_eDecType = ANDRAS_DWORD_ADD;
		m_dwKey = 1;
	}
	if(m_eDecType != ANDRAS_DEFAULT)
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDecryptedData
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption routin for different parameters
--------------------------------------------------------------------------------------*/
bool CPolyAndras::GetDecryptedData()
{	
	m_pbyBuff = new BYTE[ANDRAS_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(m_pbyBuff == NULL)
	{
		return false;
	}

	m_dwVirusStartAdd = m_dwAEPMapped - 0x1C84;

	memset(&m_pbyBuff[0], 0x00, ANDRAS_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(GetBuffer(m_dwVirusStartAdd, ANDRAS_BUFF_SIZE, ANDRAS_BUFF_SIZE))
	{		
		for(DWORD dwIndex = 0; dwIndex < ANDRAS_BUFF_SIZE;)
		{
			switch(m_eDecType)
			{
			case ANDRAS_DWORD_ADD:
				*(DWORD *)&m_pbyBuff[dwIndex] += m_dwKey;
				dwIndex += 4;
				break;

			case ANDRAS_WORD_ADD:
				*(WORD *)&m_pbyBuff[dwIndex] += (WORD)m_dwKey;
				dwIndex += 2;
				break;

			case ANDRAS_BYTE_ADD:
				m_pbyBuff[dwIndex] += (BYTE)m_dwKey;
				dwIndex ++;
				break;

			case ANDRAS_DWORD_SUB:
				*(DWORD *)&m_pbyBuff[dwIndex] -= m_dwKey;
				dwIndex += 4;
				break;

			case ANDRAS_WORD_SUB:
				*(WORD *)&m_pbyBuff[dwIndex] -= (WORD)m_dwKey;
				dwIndex += 2;
				break;

			case ANDRAS_BYTE_SUB:
				m_pbyBuff[dwIndex] -= (BYTE)m_dwKey;
				dwIndex ++;
				break;

			case ANDRAS_DWORD_XOR:
				*(DWORD *)&m_pbyBuff[dwIndex] ^= m_dwKey;
				dwIndex += 4;
				break;

			case ANDRAS_WORD_XOR:
				*(WORD *)&m_pbyBuff[dwIndex] ^= m_dwKey;
				dwIndex += 2;
				break;

			case ANDRAS_BYTE_XOR:
				m_pbyBuff[dwIndex] ^= m_dwKey;
				dwIndex ++;
				break;

			case ANDRAS_DWORD_NEG:
				*(DWORD *)&m_pbyBuff[dwIndex] = ~(*(DWORD *)&m_pbyBuff[dwIndex]) + m_dwKey;
				dwIndex += 4;
				break;

			case ANDRAS_WORD_NEG:
				*(WORD *)&m_pbyBuff[dwIndex] = ~(*(WORD *)&m_pbyBuff[dwIndex]) + (WORD)m_dwKey;
				dwIndex += 2;
				break;

			case ANDRAS_BYTE_NEG:
				m_pbyBuff[dwIndex] = ~(m_pbyBuff[dwIndex]) + (BYTE)m_dwKey;
				dwIndex ++;
				break;
			}
		}
		BYTE bySignature[] = {0x2A, 0x41, 0x4E, 0x44, 0x52, 0x41, 0x53, 0x2A, 0x20, 0x62, 0x79, 0x20, 0x50, 0x6F, 0x69,
			0x6E, 0x74, 0x65, 0x72, 0x3D, 0x26, 0x48, 0x65, 0x6C, 0x6C};

		if(0 == memcmp(&m_pbyBuff[0x40], &bySignature[0], sizeof(bySignature)))
		{
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
	Author			: Tushar Kadam + Yash Gund + Virus Analysis Team
	Description		: Repair routine for different varients of Andras Family
--------------------------------------------------------------------------------------*/
int CPolyAndras :: CleanVirus()
{
	if(m_pMaxPEFile->WriteAEP((*(DWORD *)&m_pbyBuff[m_dwOriAEPOffset])))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwVirusStartAdd, true))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}