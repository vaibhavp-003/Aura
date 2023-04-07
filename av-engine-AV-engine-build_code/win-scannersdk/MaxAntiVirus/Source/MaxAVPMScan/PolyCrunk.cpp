/*======================================================================================
FILE				: PolyCrunk.cpp
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
NOTES				: This is detection module for malware Crunk Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyCrunk.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyCrunk
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyCrunk::CPolyCrunk(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwVirusStartOffset = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyCrunk
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyCrunk::~CPolyCrunk(void)
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
	Description		: Detection routine for different varients of Crunk Family
--------------------------------------------------------------------------------------*/
int CPolyCrunk::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	WORD wReservedbits = 0;
	if(!m_pMaxPEFile->ReadBuffer(&wReservedbits,0x34,0x2,0x2))
	{
		return iRetStatus;
	}
	if( (wReservedbits == 0x3031) && ((m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000000) == 0xE0000000 )&& 
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xA0000020) == 0xA0000020 )&& 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[0xA].VirtualAddress == 0x00) &&
		(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > 0x3C00))
	{
		if(GetPatchedCalls(m_dwAEPMapped, m_dwAEPMapped + 0x1000, m_wNoOfSections - 1, true))
		{
			const int CRUNK_BUFF_SIZE = 0x3C00;
			m_pbyBuff = new BYTE[CRUNK_BUFF_SIZE];
			if(!m_pbyBuff)
			{
				return iRetStatus;
			}
			memset(m_pbyBuff, 0x00, CRUNK_BUFF_SIZE);

			LPVOID lpPos = m_arrPatchedCallOffsets.GetHighest();			
			while(lpPos)
			{			
				m_arrPatchedCallOffsets.GetData(lpPos, m_dwCallPatchAdd);
				m_arrPatchedCallOffsets.GetKey(lpPos, m_dwCallAddRVA);

				if((OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwCallAddRVA, &m_dwVirusStartOffset)) && (m_dwCallAddRVA % m_pMaxPEFile->m_stPEHeader.FileAlignment == 0) &&
					(((m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData) - m_dwCallAddRVA) > 0x3000)) 
				{
					if(GetBuffer(m_dwVirusStartOffset, CRUNK_BUFF_SIZE, CRUNK_BUFF_SIZE))
					{
						if(GetCrunkParam())
						{							
							return VIRUS_FILE_REPAIR;						
						}
					}
				}
				lpPos = m_arrPatchedCallOffsets.GetHighestNext(lpPos);
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetCrunkParam
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Collects repair info for different varients of Crunk Family
--------------------------------------------------------------------------------------*/
bool CPolyCrunk::GetCrunkParam()
{
	DWORD dwLength = 0, dwOffset = 0, dwMatchedInstr = 0, dwFirstConst = 0, dwDectype = 0;
	t_disasm da;

	while(dwOffset < 0x500 && dwMatchedInstr <= 2)
	{
		memset(&da, 0x00, sizeof(struct t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);		
		if(dwLength > (0x500 - dwOffset))
		{
			return false;
		}
		else if(m_pbyBuff[dwOffset] == 0xDC && (m_pbyBuff[dwOffset + 1] < 0xDF && m_pbyBuff[dwOffset + 1] > 0xD1))//disassembler issue
		{
			dwOffset += 2;
			continue;
		}
		else if(dwMatchedInstr == 0 && dwLength == 5 && strstr(da.result, "CALL") && (*(DWORD *)&m_pbyBuff[dwOffset + 1] == 0x00))
		{
			dwMatchedInstr++;
			dwFirstConst = m_dwCallAddRVA + m_dwImageBase + dwOffset + 5;
		}
		else if(dwMatchedInstr == 1 && dwLength == 6 && (strstr(da.result, "SUB")) && (da.immconst) > m_dwImageBase)
		{
			dwMatchedInstr++;
			m_dwDecStartOffset = dwFirstConst + (dwFirstConst - *(DWORD *)&m_pbyBuff[dwOffset + 2]) + 4;
			m_dwDecStartOffset = m_dwDecStartOffset - (m_dwCallAddRVA + m_dwImageBase);
		}
		else if(dwMatchedInstr == 2 && dwLength == 6 && (strstr(da.result, "SUB DWORD")))
		{
			dwMatchedInstr++;
			dwDectype = 1;
			break;			
		}
		else if(dwMatchedInstr == 2 && dwLength == 6 && (strstr(da.result, "ADD DWORD")))
		{
			dwMatchedInstr++;
			dwDectype = 2;
			break;
		}
		else if(dwMatchedInstr == 2 && dwLength == 6 && (strstr(da.result, "XOR DWORD")))
		{
			dwMatchedInstr++;
			dwDectype = 3;
			break;			
		}
		else if(dwMatchedInstr == 1 && dwLength == 6 && (strstr(da.result, "ADD") && ((da.immconst) > 0 && (da.immconst) < 0x1000)))
		{
			dwMatchedInstr++;
			m_dwDecStartOffset = dwFirstConst + *(DWORD *)&m_pbyBuff[dwOffset+2];
			m_dwDecStartOffset = m_dwDecStartOffset - (m_dwCallAddRVA + m_dwImageBase);
		}
		else if(dwMatchedInstr == 2 && dwLength == 5 && (strstr(da.result, "MOV") && ((da.immconst)== 0x9E3779B9)))
		{
			dwMatchedInstr++;
			dwDectype = dwFirstConst = 0;
			DecryptBuffer(dwFirstConst, dwDectype, (*(DWORD *)&m_pbyBuff[dwOffset + 1]), m_dwDecStartOffset + 0x27A8, m_dwDecStartOffset + 0x27D0 + (m_dwCallPatchAdd - m_dwAEPMapped + 5));
			DecryptBuffer(dwFirstConst, dwDectype, (*(DWORD *)&m_pbyBuff[dwOffset + 1]), m_dwDecStartOffset + 0x36C8, m_dwDecStartOffset + 0x36E8);
		}
		dwOffset += dwLength;
	}
	if(dwDectype > 0)
	{
		dwFirstConst=0;
		DecryptBuffer(*(DWORD *)&m_pbyBuff[dwOffset + 2], dwDectype, dwFirstConst, m_dwDecStartOffset + 0x27B4, (m_dwDecStartOffset + 0x27B4 + (m_dwCallPatchAdd - m_dwAEPMapped + 5)));
		DecryptBuffer(*(DWORD *)&m_pbyBuff[dwOffset + 2], dwDectype, dwFirstConst, m_dwDecStartOffset + 0x36C4, (m_dwDecStartOffset + 0x36E4));
	}
	
	const BYTE CrunkSig[] = {0x43, 0x72, 0x61, 0x6e, 0x6b, 0x20, 0x62, 0x79, 0x20, 0x6d, 0x31, 0x78, 0x00};
	if(memcmp(&m_pbyBuff[m_dwDecStartOffset + 0x36C7], CrunkSig, sizeof(CrunkSig)) == 0)
	{
		m_dwVariant = 2;
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Crunk.B"));
		return true;
	}
	else if(memcmp(&m_pbyBuff[m_dwDecStartOffset + 0x36C8], CrunkSig, sizeof(CrunkSig)) == 0)
	{
		m_dwVariant = 1;
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Crunk.A"));
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptBuffer
	In Parameters	: DWORD dwDeckey, DWORD d_type, DWORD dwConstkey, DWORD DataStartOffset, DWORD DataEndOffset
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryps the buffer to repair file
--------------------------------------------------------------------------------------*/
int CPolyCrunk::DecryptBuffer(DWORD dwDeckey, DWORD d_type, DWORD dwConstkey, DWORD DataStartOffset, DWORD DataEndOffset)
{	
	switch(d_type)
	{
	case 0: 
		{
			DWORD dwConst=0,dwDecdata=0;
			for(DWORD iOffset = DataStartOffset; iOffset < DataEndOffset; iOffset += 8)
			{
				dwDecdata = *(DWORD *)&m_pbyBuff[iOffset];
				dwConst = (dwConstkey << 5);
				for(int i = 0x20; i > 0; i -= 1)
				{
					dwDeckey = ((dwDecdata << 4) + *(DWORD *)&m_pbyBuff[m_dwDecStartOffset - 8]);
					dwDeckey ^= (dwDecdata + dwConst);
					dwDeckey ^= ((dwDecdata >> 5) + *(DWORD *)&m_pbyBuff[m_dwDecStartOffset - 4]);
					*(DWORD *)&m_pbyBuff[iOffset + 4] -= dwDeckey;
					dwDeckey = ((*(DWORD *)&m_pbyBuff[iOffset + 4]) << 4) + (*(DWORD *)&m_pbyBuff[m_dwDecStartOffset  - 0x10]);
					dwDeckey ^= (*(DWORD *)&m_pbyBuff[iOffset + 4] + dwConst);
					dwDeckey ^= (*(DWORD *)&m_pbyBuff[iOffset + 4] >> 5) +  (*(DWORD *)&m_pbyBuff[m_dwDecStartOffset  - 0x0C]);
					dwDecdata -=  dwDeckey;
					dwConst -= dwConstkey;
				}
				*(DWORD *)&m_pbyBuff[iOffset] = dwDecdata;
			}
			break;
		}			
	case 1:
		{
			for(DWORD iOffset = DataStartOffset; iOffset <= DataEndOffset; iOffset += 4)
			{
				*(DWORD *)&m_pbyBuff[iOffset] -= dwDeckey;
			}
			break;
		}
	case 2:
		{
			for(DWORD iOffset = DataStartOffset; iOffset <= DataEndOffset; iOffset += 4)
			{
				*(DWORD *)&m_pbyBuff[iOffset] += dwDeckey;
			}
			break;
		}
	case 3:
		{
			for(DWORD iOffset = DataStartOffset; iOffset <= DataEndOffset; iOffset += 4)
			{
				*(DWORD *)&m_pbyBuff[iOffset] ^= dwDeckey;
			}
			break;
		}
	}
	return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Crunk Family
--------------------------------------------------------------------------------------*/
int CPolyCrunk::CleanVirus(void) 
{
	int iRetStatus = REPAIR_FAILED;
	if(m_dwVariant == 1)
	{
		DWORD ReplaceOffset=0,NumofBytes=0;
		for(DWORD iOffset = m_dwDecStartOffset + 0x27AD; iOffset <= m_dwDecStartOffset + 0x27AD + (m_dwCallPatchAdd - m_dwAEPMapped + 5);)
		{

			if(!(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[iOffset] - m_dwImageBase), &ReplaceOffset)))
			{
				NumofBytes = *(DWORD *)&m_pbyBuff[iOffset+4];
				m_pMaxPEFile->WriteBuffer(&m_pbyBuff[iOffset+8],ReplaceOffset,NumofBytes,NumofBytes);
				iOffset += (NumofBytes + 8);
			}
			m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[iOffset] - m_dwImageBase), &NumofBytes);
			if(ReplaceOffset > NumofBytes)
			{
				if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset))
				{
					if(m_pMaxPEFile->FillWithZeros(0x34,0x2))
					{
						iRetStatus = REPAIR_SUCCESS;
						break;
					}
				}
			}
		}
	}
	else if(m_dwVariant == 2)
	{
		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwDecStartOffset + 0x27B4], m_dwAEPMapped , m_dwCallPatchAdd - m_dwAEPMapped + 5 , m_dwCallPatchAdd - m_dwAEPMapped + 5))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset))
			{
				if(m_pMaxPEFile->FillWithZeros(0x34,0x2))
				{
					iRetStatus = REPAIR_SUCCESS;
				}
			}
		}
	}
	return iRetStatus;
}