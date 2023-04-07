/*======================================================================================
FILE				: PolyVirut.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malware Virut Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
					  There are four different types of infection pattern in this virus
					  Also hooks the system API like CreateFile, CreateFileEx etc (This part is managed in Memory Scanner)	
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyVirut.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyVirut
	In Parameters	: CMaxPEFile *pMaxPEFile , bool bPolyCleanFlag
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyVirut::CPolyVirut(CMaxPEFile *pMaxPEFile, bool bPolyCleanFlag):
CPolyBase(pMaxPEFile),
m_bPolyCleanFlag(bPolyCleanFlag),
m_objVirutGenParam(false, sizeof(DWORD), sizeof(VIRUT_PARAM), sizeof(DWORD))
{
	m_pbyBuff				= NULL;
	m_dwOverlaySize			= 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyVirut
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyVirut::~CPolyVirut(void)
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
	Author			: Tushar Kadam + Ajay Vishwakarma + Rohit Vyas + Virus Analysis Team
	Description		: Detection routine for different varients of Virut Family
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(0 == m_wNoOfSections)
	{
		return iRetStatus;	
	}
	
	// Skip last sections having SRD zero or section with all bytes as zeros
	while(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0 || CheckForZeros(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
	{
		m_wNoOfSections--;
		if(0 == m_wNoOfSections)
		{
			return iRetStatus;	
		}
	}
	DWORD dwAEPMapped	= m_dwAEPMapped;
	DWORD dwAEPUnmapped = m_dwAEPUnmapped;
	iRetStatus = DetectVirutCE();
	if(iRetStatus)
	{
		m_eInfectionType = VIRUT_CE;
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Virut.CE"));			
		return iRetStatus;
	}
	m_dwAEPMapped	= dwAEPMapped;
	m_dwAEPUnmapped = dwAEPUnmapped;
	iRetStatus = DetectVirutFileInfector();
	if(iRetStatus)
	{
		return iRetStatus;
	}

	iRetStatus = DetectVirutGen();
	if(iRetStatus)
	{
		return iRetStatus;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirutGen
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Rohit Vyas + Virus Analysis Team
	Description		: Detection routine for different varients of Virut Family
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirutGen()
{	
	int iRetStatus = VIRUS_NOT_FOUND;
	m_dwOverlaySize = m_pMaxPEFile->m_dwFileSize -(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData);
	//Checks for last or second last section.
	if(((m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x2400 || m_dwOverlaySize >= 0x2400) && 
		(m_pSectionHeader[m_wNoOfSections -1].Characteristics & 0xE0000000) == 0xE0000000) ||
		((m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData >= 0x2400 || m_dwOverlaySize >= 0x2400) && 
		(m_pSectionHeader[m_wNoOfSections -2].Characteristics & 0xE0000000) == 0xE0000000))
	{
		m_pbyBuff = new BYTE[VIRUT_GEN_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0x00, VIRUT_GEN_BUFF_SIZE);

		//Heuristicly deleting some non repairable files (which are coming in counts of hundereds from customer) of which PE signature cannot be added
		if(NonRepairablefile())
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Virut.Gen"));
			iRetStatus = VIRUS_FILE_DELETE;
			return iRetStatus;
		}
		if(GetVirutGenType())
		{
			m_objVirutGenParam.Balance();
			P_VIRUT_PARAM lpVirutGenParam;
			LPVOID lpPos = m_objVirutGenParam.GetHighest();
			m_objVirutGenParam.GetData(lpPos,(LPVOID &)lpVirutGenParam);
			if(lpVirutGenParam->InfectionType > 0x00)
			{
				iRetStatus = VIRUS_FILE_REPAIR;
				m_eInfectionType = VIRUT_GEN;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Virut.Gen"));
			}
		}
	}
	if(!m_bPolyCleanFlag)
	{
		m_objVirutGenParam.RemoveAll();
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: NonRepairablefile
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Rohit Vyas + Virus Analysis Team
	Description		: Detection routine for nonrepairable varients of Virut Family
--------------------------------------------------------------------------------------*/
int CPolyVirut::NonRepairablefile()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_dwAEPMapped == 0 && m_wNoOfSections == 2 &&
	 ((m_pSectionHeader[m_wNoOfSections -1].Characteristics & 0xE0000000) == 0xE0000000) &&
	 ((m_pSectionHeader[m_wNoOfSections -2].Characteristics & 0xE0000000) == 0xE0000000))
	{
		iRetStatus = VIRUS_FILE_REPAIR;
		return iRetStatus;
	}
	/*
	BYTE byUPX1[] = {0x55, 0x50, 0x58, 0x31};
	if((memcmp(m_pSectionHeader[m_wNoOfSections -2].Name, byUPX1, sizeof(byUPX1)) == 0 && 
	  (m_pSectionHeader[m_wNoOfSections -2].Characteristics & 0xE0000000) == 0xE0000000))
	{
		if(m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData != 0 && m_pSectionHeader[m_wNoOfSections - 2].PointerToRawData != 0)
		{
			if(GetBuffer(m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 2].PointerToRawData - 0x200, 0x200, 0x100))
			{
				if(FindVirutGenSig(m_pbyBuff, m_dwNoOfBytes))
				{
					iRetStatus = VIRUS_FILE_REPAIR;
					return iRetStatus;
				}
			}
		}
	}
	*/

	//Handling of RLPACKED Corrupt files.
	BYTE byPACK[] = {0x2E, 0x70, 0x61, 0x63, 0x6B, 0x65, 0x64};
	for(int i = 0; i < m_wNoOfSections; i++)
	{
		if(memcmp(m_pSectionHeader[i].Name, byPACK, sizeof(byPACK)) == 0)
		{
			if(GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData - 0x200, 0x200, 0x200))
			{
				if(FindVirutGenSig(m_pbyBuff, m_dwNoOfBytes))
				{
					iRetStatus = VIRUS_FILE_REPAIR;
					return iRetStatus;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetVirutGenType
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for type of infection like Overlay, call patching, AEP obfuscation etc 
--------------------------------------------------------------------------------------*/
int CPolyVirut::GetVirutGenType()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	m_objVirutGenParam.RemoveAll();
	

	//Entry point directly pointing to Init.
	iRetStatus = DetectVirutGenAepInit();
	if(iRetStatus)
	{
		if(!m_bPolyCleanFlag)
		{
			return iRetStatus;
		}
	}

	if(!m_pMaxPEFile->m_b64bit)
	{
		iRetStatus = DetectVirutGenCallPatchInit();
		if(iRetStatus)
		{
			if(!m_bPolyCleanFlag)
			{
				return iRetStatus;
			}
		}
	}
	
	iRetStatus = DetectVirutGenOverlyInit();
	if(iRetStatus)
	{
		if(!m_bPolyCleanFlag)
		{
			return iRetStatus;
		}
	}

	
	if(m_objVirutGenParam.GetCount())
	{
		P_VIRUT_PARAM lpVirutGenParam;
		LPVOID lpPos = m_objVirutGenParam.GetHighest();
		m_objVirutGenParam.GetData(lpPos,(LPVOID &)lpVirutGenParam);
		if(lpVirutGenParam->dwDecLength != 0x00)
		{
			iRetStatus = VIRUS_FILE_REPAIR;
		}
	}
	else //Check for Dead code. Only called once no valid infection found 05 July 2011
	{
		iRetStatus = DetectVirutGenDeadCode();
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirutGenOverlyInit
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for type of infection : Overlay
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirutGenOverlyInit()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(m_pMaxPEFile->m_dwFileSize <=(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
	{
		return iRetStatus;
	}

	DWORD dwOverlayOffset	=(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData);
	DWORD dwOverlaySize		= m_pMaxPEFile->m_dwFileSize - dwOverlayOffset;

	if(dwOverlaySize < 0x200)
		return iRetStatus;
	DWORD dwMinimumSize = (m_pMaxPEFile->m_dwFileSize - dwOverlayOffset) > 0x200 ? 0x200 : (m_pMaxPEFile->m_dwFileSize - dwOverlayOffset);
	memset(m_pbyBuff, 0, m_dwNoOfBytes);
	if(GetBuffer(dwOverlayOffset, 0x500, dwMinimumSize))
	{
		VIRUT_PARAM objVirutParam;
		memset(&objVirutParam, 0, sizeof(VIRUT_PARAM));

		objVirutParam.dwRvaVirus = m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;			
		objVirutParam.dwModeOffset	= m_dwNoOfBytes;

		if(GetVirutGenParams(m_pbyBuff, objVirutParam))
		{
			if(DetectVirutGenSig(objVirutParam))
			{
				objVirutParam.InfectionType			= 0x03;
				objVirutParam.dwVirusCallOffset		= dwOverlayOffset;
				objVirutParam.CallFoundLocInBuff	= 0x0;
				m_objVirutGenParam.AppendItem((LPVOID)&objVirutParam.dwRvaVirus,(LPVOID)&objVirutParam);
				iRetStatus = VIRUS_FILE_REPAIR;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirutGenOverlyInit
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for type of infection : CALL Patch at AEP
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirutGenCallPatchInit()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD dwEndAddr = m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData;
	if(m_wAEPSec == m_wNoOfSections - 1 && (dwEndAddr - m_dwAEPMapped) > 0x50000)
	{
		dwEndAddr = m_dwAEPMapped + 0x50000;
	}
	bool bEnd_E8_SearchFlag = false;
	DWORD dwTemp = 0, dwCallVal = 0, dwDistFromAEP = 0, dwValue = 0;
	BYTE  tBuff[0x20] = {0}, DllFuncCall[]= {0xFF, 0x25};
	for(DWORD dwReadOffset = m_dwAEPMapped; dwReadOffset < dwEndAddr && !bEnd_E8_SearchFlag; dwReadOffset += VIRUT_GEN_BUFF_SIZE)
	{
		if(!GetBuffer(dwReadOffset, VIRUT_GEN_BUFF_SIZE))
		{
				break;
		}
		if(dwReadOffset < (m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData) && (dwReadOffset + m_dwNoOfBytes) > (m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData))
		{
			m_dwNoOfBytes = (m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData) - dwReadOffset;
		}
		if(m_dwNoOfBytes < 0x5)
		{			
			break;
		}
		for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes - 0x05; dwOffset++)
		{
			if(m_pbyBuff[dwOffset] != 0xE8)
			{
				continue;
			}
			dwTemp		= *((DWORD *)&m_pbyBuff[dwOffset + 1]);
			dwCallVal	= dwTemp;
			dwTemp	   += m_dwAEPUnmapped + dwDistFromAEP + dwOffset + 0x05;
			if(dwTemp >= (m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize))
			{
				if(dwTemp >= (m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
				{
					continue;
				}
			}
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwTemp, &dwValue))
			{
				continue;
			}

			m_pMaxPEFile->ReadBuffer(tBuff, dwValue, 0x20);

			if((tBuff[0] >= 0x58) && (tBuff[0] <= 0x5F))//Skip POP Exx
			{
				continue;
			}
			if((dwCallVal < 0x100))
			{
				//Check for DLL calls. Some Call leads us to another call where some dll functions are called.
				if(memcmp(tBuff, &DllFuncCall, 2)== 0)
				{
					continue;
				}
			}
			if(CheckPnuemonics(tBuff, 0x20, 0x12, "60", 0x01, "PUSHAD"))
			{
				DWORD dwCallRVA;
				if(!DetectVirutGenCallPatch(dwOffset, dwDistFromAEP + dwOffset, dwCallRVA))
				{
					continue;
				}
				else
				{
					iRetStatus = VIRUS_FILE_REPAIR;
				}
				if(!m_bPolyCleanFlag)
				{
					bEnd_E8_SearchFlag = true;
					break;
				}
				//If infected code found in overlay, clean overlay and then look for other infections
				if(DetectVirutGenOverlayInfection(dwCallRVA))
				{
					break;
				}
			}
		}
		dwDistFromAEP += VIRUT_GEN_BUFF_SIZE;
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectVirutGenDeadCode
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Detection routine for type of infection : Dead code
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirutGenDeadCode()
{
	int		iRetStatus	= VIRUS_NOT_FOUND;
	BYTE	bSigBuff[]	= {0x55, 0x8B, 0xEC, 0xE8};
	int		iSigFound	= 0, i = 0;
	VIRUT_PARAM objVirutParam;
	DWORD FileAlignment = m_pMaxPEFile->m_stPEHeader.FileAlignment;
	DWORD dwReadOffset	= m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;

	if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData > 0x100000) // putting some max limit to check the deadcode 
	{
		dwReadOffset += m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - 0x100000;
	}
	dwReadOffset = ((dwReadOffset + FileAlignment - 1) / FileAlignment) * FileAlignment;
	for(; dwReadOffset < (m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData); dwReadOffset += FileAlignment)
	{
		if(!GetBuffer(dwReadOffset, 0x160, 0x160))
		{
			break;
		}
		for(i = 0; i < 0x47; i++)
		{
			if(memcmp(&m_pbyBuff[i], &bSigBuff[0], 0x4) == 0)
			{
				iSigFound = 1;
				break;
			}
		}
		if(iSigFound)
		{
			if(!GetBuffer(dwReadOffset + i, 0x160, 0x160))
			{
				break;
			}
			if(GetVirutGenDeadInitCodeParam(&m_pbyBuff[0], 0x160))
			{
					objVirutParam.InfectionType			= 0x05;
					objVirutParam.dwVirusCallOffset		= 0x0;
					objVirutParam.CallFoundLocInBuff	= 0x0;
					objVirutParam.dwRvaVirus			= m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + (dwReadOffset - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData);
					m_objVirutGenParam.AppendItem((LPVOID)&objVirutParam.dwRvaVirus,(LPVOID)&objVirutParam);
					iRetStatus = VIRUS_FILE_REPAIR;
					return iRetStatus;
			}
			else
			{
				continue;
			}
		}

		//Check for direct signatures
		if(FindVirutGenSig(&m_pbyBuff[0], 0x160))
		{
			if(GetVirutGenDeadDecCodeParam(&m_pbyBuff[0], 0x160))
			{
				objVirutParam.InfectionType			= 0x04;
				objVirutParam.dwVirusCallOffset		= 0x0;
				objVirutParam.CallFoundLocInBuff	= 0x0;
				objVirutParam.dwRvaVirus			= m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + (dwReadOffset - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData);
				m_objVirutGenParam.AppendItem((LPVOID)&objVirutParam.dwRvaVirus,(LPVOID)&objVirutParam);
				iRetStatus = VIRUS_FILE_REPAIR;
				return iRetStatus;
			}
		}
	}

	if(m_dwOverlaySize > 0)
	{
		if(GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData, 0x160, 0x160))
		{
			if(FindVirutGenSig(&m_pbyBuff[0], 0x160))
			{
				if(GetVirutGenDeadDecCodeParam(&m_pbyBuff[0], 0x160))
				{
					objVirutParam.InfectionType			= 0x04;
					objVirutParam.dwVirusCallOffset		= 0x0;
					objVirutParam.CallFoundLocInBuff	= 0x0;
					objVirutParam.dwRvaVirus			= m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
					m_objVirutGenParam.AppendItem((LPVOID)&objVirutParam.dwRvaVirus,(LPVOID)&objVirutParam);
					iRetStatus = VIRUS_FILE_REPAIR;
					return iRetStatus;
				}
			}
		}
	}
	
	//Handling of Backdoor.win32.Wootbot.Gen files in which Deadcode is not at alinged offset
	BYTE bySecNAH[] = {0x2E, 0x6E, 0x61, 0x68};
	if(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, bySecNAH, sizeof(bySecNAH))== 0 && 
	  (m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000000) == 0xE0000000)
	{
		BYTE byAEPBuff[0x10] = {0};
		if(m_pMaxPEFile->ReadBuffer(byAEPBuff, m_dwAEPMapped, 0x10, 0x10))
		{
			if(byAEPBuff[0] == 0x55)
			{
				for(DWORD dwCount = 1; dwCount < 0xB; dwCount++)
				{
					if(byAEPBuff[dwCount] == 0xE9)
					{
						DWORD dwJmpOffset = *(DWORD *)&byAEPBuff[dwCount + 1] + 0x05 + dwCount + m_dwAEPUnmapped;
						if(dwJmpOffset >= m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)
						{
							if(m_pMaxPEFile->Rva2FileOffset(dwJmpOffset, &dwJmpOffset))
							{
								BYTE byJmpBuff[0x500] = {0};
								DWORD dwBytesRead = 0;
								if(m_pMaxPEFile->ReadBuffer(byJmpBuff, dwJmpOffset, 0x500, 0x400, &dwBytesRead))
								{
									for(DWORD dwCnt = 0; dwCnt < dwBytesRead - 4; dwCnt++)
									{
										if(memcmp(&byJmpBuff[dwCnt], &bSigBuff[0], 0x4) == 0)
										{
											if(GetBuffer(dwJmpOffset + dwCnt, 0x160, 0x160))
											{
												if(GetVirutGenDeadInitCodeParam(&m_pbyBuff[0], 0x160))
												{
														objVirutParam.InfectionType			= 0x05;
														objVirutParam.dwVirusCallOffset		= 0x0;
														objVirutParam.CallFoundLocInBuff	= 0x0;
														objVirutParam.dwRvaVirus			= m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + (dwJmpOffset + dwCnt - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData);
														m_objVirutGenParam.AppendItem((LPVOID)&objVirutParam.dwRvaVirus,(LPVOID)&objVirutParam);
														iRetStatus = VIRUS_FILE_REPAIR;
														return iRetStatus;
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetVirutGenDeadDecCodeParam
	In Parameters	: BYTE *pBuffer, DWORD dwBufferSize, bool bCheckCall
	Out Parameters	: 1 if found else 0
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: This function retrieves information Dead code
--------------------------------------------------------------------------------------*/
int	CPolyVirut::GetVirutGenDeadDecCodeParam(BYTE *pBuffer, DWORD dwBufferSize, bool bCheckCall/* = true*/)
{
	int	  iFound	= 0, iRequiredInst = bCheckCall ? 0 : 1;
	DWORD dwOffset	= 0, dwLength = 0, dwNewInstCount = 0;
	DWORD dwSize	= dwBufferSize - 0x3;
	BYTE  B1, B2, B3;
	char  *	ptr;
	ptr = NULL;
	t_disasm	da;
	bool bANDInstrFound = false;
	while(dwOffset < dwSize - 2)
	{
		if(dwNewInstCount >= 0x100)
		{
			break;
		}
		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = *((BYTE*)&pBuffer[dwOffset]);
		B2 = *((BYTE*)&pBuffer[dwOffset + 1]);
		B3 = *((BYTE*)&pBuffer[dwOffset + 2]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1 == 0xC1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset += 0x03;
			continue;
		}
		if(B1 == 0xD1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset += 0x02;
			continue;
		}
		dwLength = m_objMaxDisassem.Disasm((char*)&pBuffer[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
		if(dwLength == 0x01 && B1 == 0xE2 && strstr(da.result, "???"))
		{
			dwOffset += 0x02;
			continue;
		}
		//Only increase instruction count for valid instructions
		dwNewInstCount++;
		if(iRequiredInst == 0 && dwLength == 0x05 && B1 == 0xE8 && B2 == 0x00 && B3 == 0x00 && strstr(da.result, "CALL "))//check
		{
			dwOffset	+= dwLength;
			iRequiredInst = 1;
			continue;
		}
		if(iRequiredInst == 1 && dwLength == 0x3 && B1 == 0x8B && B2 == 0x04 && B3 == 0x24 && strstr(da.result, "MOV EAX,[ESP]"))//check
		{
			dwOffset	+= dwLength;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 2 && dwLength == 0x7 && B1 == 0x80 && B2 == 0xB8 && strstr(da.result, "CMP BYTE PTR [E") && strstr(da.result, "E8"))//check
		{
			dwOffset	+= dwLength;
			iRequiredInst++;
			continue;
		}//OR
		if(iRequiredInst == 2 && dwLength == 3 && B1 == 0x80 && B3 == 0xE8 && strstr(da.result, "CMP ") && strstr(da.result, ",E8"))//check
		{
			dwOffset	+= dwLength;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 3 && dwLength == 0x6 && B1 == 0x8D && B2 == 0xB5 && strstr(da.result, "LEA ESI,[EBP+"))
		{
			dwOffset	+= dwLength;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 4 && dwLength == 0x5 && B1 == 0xB9 && strstr(da.result, "MOV ECX,"))
		{
			dwOffset	+= dwLength;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 5 && dwLength == 0x1 && B1 == 0xF3 && B2 == 0xA4 && strstr(da.result, "???"))//REP MOVS BYTE PTR ES:[EDI],BYTE PTR DS:[ESI]
		{
			dwOffset	+= 2; //2 bcz dissasembler unable to show instruction
			iRequiredInst++;
			continue;
		}
		if(dwLength == 0x6 && B1 == 0x81 && B2 == 0xE3 && strstr(da.result, "AND EBX,FFFFF000"))
		{
			bANDInstrFound = true;
			dwOffset	+= dwLength;
			//iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 6 && dwLength == 0x7 && B1 == 0x81 && B2 == 0x7B && B3 == 0x4E && strstr(da.result, "CMP DWORD PTR [EBX+4E],73696854"))//check
		{
			dwOffset	+= dwLength;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst >= 7)
		{
			break;
		}
		dwOffset += dwLength;
	}
	if(iRequiredInst >= 6)
	{
		iFound = 1;
	}
	return iFound;
}

/*-------------------------------------------------------------------------------------
	Function		: GetVirutGenDeadInitCodeParam
	In Parameters	: BYTE *pBuffer, DWORD dwBufferSize
	Out Parameters	: 1 if found else 0
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: This function retrieves information Dead code
--------------------------------------------------------------------------------------*/
int	CPolyVirut::GetVirutGenDeadInitCodeParam(BYTE *pBuffer, DWORD dwBufferSize)
{
	int iFound = 0, iRequiredInst = 0;
	DWORD	dwOffset = 0, dwLength = 0, dwNewInstCount = 0, dwBase = 0;
	DWORD	dwSize = dwBufferSize - 0x3;
	BYTE	B1, B2, B3;
	char	*ptr;
	ptr =	NULL;
	t_disasm	da;
	while(dwOffset < dwSize - 2)
	{
		if(dwNewInstCount >= 0x100)
		{
			break;
		}
		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = *((BYTE*)&pBuffer[dwOffset]);
		B2 = *((BYTE*)&pBuffer[dwOffset + 1]);
		B3 = *((BYTE*)&pBuffer[dwOffset + 2]);
		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1 == 0xC1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset += 0x03;
			continue;
		}
		if(B1 == 0xD1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset += 0x02;
			continue;
		}
		dwLength = m_objMaxDisassem.Disasm((char*)&pBuffer[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);
		if(dwLength == 0x01 && B1 == 0xE2 && strstr(da.result, "???"))
		{
			dwOffset += 0x02;
			continue;
		}
		//Only increase instruction count for valid instructions
		dwNewInstCount++;
		if(iRequiredInst == 0 && dwLength == 0x01 && B1 == 0x55 && strstr(da.result, "PUSH EBP"))
		{
			dwOffset += 0x01;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 1 && dwLength == 0x2 && B1 == 0x8B && B2 == 0xEC && strstr(da.result, "MOV EBP,ESP"))
		{
			dwOffset += 2;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 2 && dwLength == 0x5 && B1 == 0xE8 && strstr(da.result, "CALL "))
		{
			dwOffset += 0x5;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 3 && dwLength == 0x6 && B1 == 0x67 && B2 == 0x64 && B3 == 0xFF && strstr(da.result, "PUSH DWORD PTR FS:[0]"))
		{
			dwOffset += 6;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 4 && dwLength == 0x6 && B1 == 0x67 && B2 == 0x64 && B3 == 0x89 && strstr(da.result, "MOV FS:[0],ESP"))
		{
			dwOffset += 6;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 5 && dwLength == 0x5 && strstr(da.result, "MOV E") && (strstr(da.result, ",2") || strstr(da.result, ",00002")))
		{
			DWORD dwDecLength = *(DWORD *)&pBuffer[dwOffset + 1];
			if(dwDecLength < 0x2000 && dwDecLength > 0x2A00)
			{
				dwOffset += 5;
				continue;
			}
			dwOffset += 5;
			iRequiredInst++;
			continue;
		}//OR
		if(iRequiredInst == 5 && dwLength == 0x6 && strstr(da.result, "XOR E") && (strstr(da.result, ",2") || strstr(da.result, ",00002")))
		{
			DWORD dwDecLength = *(DWORD *)&pBuffer[dwOffset+2];
			if(dwDecLength < 0x2000 && dwDecLength > 0x2A00)
			{
				dwOffset += 6;
				continue;
			}
			dwOffset += 6;
			iRequiredInst++;
			continue;
		}//OR
		if(iRequiredInst == 5 && dwLength == 0x6 && strstr(da.result, "OR E") && (strstr(da.result, ",2") || strstr(da.result, ",00002")))
		{
			DWORD dwDecLength = *(DWORD *)&pBuffer[dwOffset + 2];
			if(dwDecLength < 0x2000 && dwDecLength > 0x2A00)
			{
				dwOffset += 6;
				continue;
			}
			dwOffset += 6;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 6 && dwLength == 0x5 && B1 == 0xE8 && strstr(da.result, "CALL "))
		{
			DWORD dwTemp = *(DWORD *)&pBuffer[dwOffset + 1];
			if((dwOffset + dwLength + dwTemp)> dwSize)
			{
				dwOffset += 5;
				continue;
			}
			dwBase		= dwOffset + dwLength;			
			dwOffset	= dwOffset + dwLength + dwTemp;
			continue;
		}
		if(iRequiredInst == 6 && dwLength == 0x2 && B1 == 0x8A && strstr(da.result, "MOV AL,[E"))
		{
			dwOffset += 2;
			iRequiredInst++;
			continue;
		}//OR
		if(iRequiredInst == 6 && dwLength == 0x2 && B1 == 0x86 && strstr(da.result, "XCHG [E") && strstr(da.result, "AL"))//check
		{
			dwOffset += 2;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 7 && dwLength == 0x3 && B1 == 0x66 && B2 == 0x29 && strstr(da.result, "SUB AX,"))
		{
			dwOffset += 3;
			iRequiredInst++;
			continue;
		}//OR
		if(iRequiredInst == 7 && dwLength == 0x3 && B1 == 0x66 && B2 == 0x31 && strstr(da.result, "XOR AX,"))
		{
			dwOffset += 3;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 8 && dwLength == 0x2 && B1 == 0x88 && strstr(da.result, "MOV [E") && strstr(da.result, ",AL"))//check
		{
			dwOffset += 2;
			iRequiredInst++;
			continue;
		}//OR
		if(iRequiredInst == 8 && dwLength == 0x2 && B1 == 0x86 && strstr(da.result, "XCHG [E") && strstr(da.result, "AL"))//check
		{
			dwOffset += 2;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 9 && dwLength == 0x03 && strstr(da.result, "CMP E") && strstr(da.result, ",0"))
		{
			dwOffset = dwOffset + 3;
			iRequiredInst++;
			continue;
		}//OR
		if(iRequiredInst == 9 && dwLength == 0x02 && strstr(da.result, "OR E")&& strstr(da.result, ",E"))
		{
			dwOffset = dwOffset + 2;
			iRequiredInst++;
			continue;
		}
		if(iRequiredInst == 10 && dwLength == 0x2 && B1 == 0xFF && strstr(da.result, "JMP E"))
		{
			dwOffset += 2;
			iRequiredInst++;
			continue;
		}
		if(dwLength == 0x1 && B1 == 0xC3 && strstr(da.result, "???"))//RETN
		{
			if(iRequiredInst == 11)
			{
				dwOffset += 2;
				iRequiredInst++;
				break;
			}
			else if(dwBase)
			{
				dwOffset = dwBase;
				continue;
			}
		}
		if(iRequiredInst >= 12)
		{
			break;
		}
		dwOffset += dwLength;
	}
	if(iRequiredInst >= 12)
	{
		iFound = 1;
	}
	return iFound;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirutGenOverlayInfection
	In Parameters	: DWORD &dwCallRVA : Patched CALL rva
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Detection routine for type of infection : Overlay
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirutGenOverlayInfection(DWORD &dwCallRVA)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->m_dwFileSize <= (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
	{
		return iRetStatus;
	}
	DWORD dwOverlayOffset	= (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData);
	DWORD dwOverlaySize		=  m_pMaxPEFile->m_dwFileSize - dwOverlayOffset;

	if(dwOverlaySize < 0x200)
	{
		return iRetStatus;
	}
	P_VIRUT_PARAM lpVirutParam;
	if(!m_objVirutGenParam.SearchItem((LPVOID)&dwCallRVA,(LPVOID &)lpVirutParam))
	{
		return iRetStatus;
	}
	DWORD dwOffset = lpVirutParam->dwVirusCallOffset + lpVirutParam->InitExitOffset;
	//Check minimum bytes from dwOffset : to handle corrupt files with Overlay having only init code
	DWORD dwMinimumSize = (m_pMaxPEFile->m_dwFileSize - dwOffset) > 0x200 ? 0x200 : (m_pMaxPEFile->m_dwFileSize - dwOffset);
	BYTE	byBuffer[0x500] = {0};
	DWORD	dwBytesRead		= 0;
	if(m_pMaxPEFile->ReadBuffer(byBuffer, dwOffset, 0x500, dwMinimumSize, &dwBytesRead))
	{
		VIRUT_PARAM objVirutParam;
		memset(&objVirutParam, 0, sizeof(VIRUT_PARAM));
		objVirutParam.dwModeOffset	= dwBytesRead;
		objVirutParam.dwRvaVirus	= dwOffset;
		if(GetVirutGenParams(byBuffer, objVirutParam))
		{
			if(objVirutParam.dwRvaVirus < (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
			{
				return iRetStatus;
			}
			objVirutParam.dwRvaVirus += m_dwImageBase;
			if(DetectVirutGenSig(objVirutParam))
			{				
				objVirutParam.InfectionType			= 0x03;
				objVirutParam.CallFoundLocInBuff	= (dwOffset - m_dwAEPMapped) + 0x05;
				m_objVirutGenParam.AppendItem((LPVOID)&objVirutParam.dwRvaVirus,(LPVOID)&objVirutParam);
				iRetStatus = VIRUS_FILE_REPAIR;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirutGenCallPatch
	In Parameters	: DWORD dwFoundOffset, DWORD dwDistFromAEP, DWORD &dwCallRVA
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Detection routine for type of infection : CALL Patch
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirutGenCallPatch(DWORD dwFoundOffset, DWORD dwDistFromAEP, DWORD &dwCallRVA)
{		
	int		iRetStatus			= VIRUS_NOT_FOUND;
	DWORD	dwTemp				= *((DWORD *)&m_pbyBuff[dwFoundOffset+1])+ dwDistFromAEP + 0x05 + m_dwAEPUnmapped;
	DWORD	dwVirusCallOffset	= 0;
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwTemp, &dwVirusCallOffset))
	{
		return iRetStatus;
	}
	//Check minimum bytes from dwVirusCallOffset : to handle corrupt files with Overlay having only init code
	DWORD	dwMinimumSize	= (m_pMaxPEFile->m_dwFileSize - dwVirusCallOffset) > 0x200 ? 0x200 : (m_pMaxPEFile->m_dwFileSize - dwVirusCallOffset);
	BYTE	bBuffer[0x500]	= {0};
	DWORD	dwBytesRead		= 0; 
	if(m_pMaxPEFile->ReadBuffer(bBuffer, dwVirusCallOffset, 0x500, dwMinimumSize, &dwBytesRead))
	{
		VIRUT_PARAM objVirutParam;
		memset(&objVirutParam, 0, sizeof(VIRUT_PARAM));
		objVirutParam.dwModeOffset	= dwBytesRead;
		objVirutParam.dwRvaVirus	= dwTemp + m_dwImageBase;
		if(GetVirutGenParams(bBuffer, objVirutParam))
		{
			if(DetectVirutGenSig(objVirutParam))
			{
				LPVOID lpTemp						= NULL;
				objVirutParam.InfectionType			= 0x02;
				objVirutParam.dwVirusCallOffset		= dwVirusCallOffset;
				objVirutParam.CallFoundLocInBuff	= dwDistFromAEP;
				if(m_objVirutGenParam.SearchItem((LPVOID)&objVirutParam.dwRvaVirus, lpTemp))
				{
					m_objVirutGenParam.UpdateItem((LPVOID)&objVirutParam.dwRvaVirus,(LPVOID)&objVirutParam);
					return iRetStatus;
				}
				m_objVirutGenParam.AppendItem((LPVOID)&objVirutParam.dwRvaVirus,(LPVOID)&objVirutParam);
				dwCallRVA = objVirutParam.dwRvaVirus;
				iRetStatus = VIRUS_FILE_REPAIR;
			}
		}
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectVirutGenAepInit
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Detection routine for type of infection : AEP INIT Code
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirutGenAepInit()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	//Check minimum bytes from AEP : to handle corrupt fles with AEP in Overlay having only init code
	DWORD dwMinimumSize = (m_pMaxPEFile->m_dwFileSize - m_dwAEPMapped) > 0x200 ? 0x200 : (m_pMaxPEFile->m_dwFileSize - m_dwAEPMapped);
	if(GetBuffer(m_dwAEPMapped, 0x250, dwMinimumSize))
	{
		VIRUT_PARAM objVirutParam;
		memset(&objVirutParam, 0, sizeof(VIRUT_PARAM));
		objVirutParam.dwModeOffset	= m_dwNoOfBytes;
		objVirutParam.dwRvaVirus	= m_dwAEPUnmapped + m_dwImageBase;
		
		if(GetVirutGenParams(m_pbyBuff, objVirutParam))
		{
			if(DetectVirutGenSig(objVirutParam))
			{
				LPVOID lpTemp;
				if(!m_objVirutGenParam.SearchItem((LPVOID)&objVirutParam.dwRvaVirus, lpTemp))
				{
					objVirutParam.InfectionType			= 0x01;
					objVirutParam.CallFoundLocInBuff	= 0;
					m_objVirutGenParam.AppendItem((LPVOID)&objVirutParam.dwRvaVirus,(LPVOID)&objVirutParam);		
					iRetStatus = VIRUS_FILE_REPAIR;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetVirutGenParams
	In Parameters	: BYTE *pBuffer, VIRUT_PARAM &objVirutParam
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: This function collects the required information for other functions
--------------------------------------------------------------------------------------*/
int	CPolyVirut::GetVirutGenParams(BYTE *pBuffer, VIRUT_PARAM &objVirutParam)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD		dwOffset = 0, dwVirusOffset = 0, dwLength = 0, dwTemp = 0, dwLocation = 0;
	DWORD		dwCallLocation = 0, dwCall[3]={0}, dwNumCall = 0, dwDummyInstLen = 0, dwByteReplOff = 0;
	t_disasm	da;
	BYTE		B1, B2, B = 0;
	char		chBaseAddrss = 0, *ptr = NULL, szOffReg[0x05] = {0}, szKeyReg[0x05] = {0};		

	DWORD dwSize = objVirutParam.dwModeOffset;
	objVirutParam.dwModeOffset = 0x00;

	m_objMaxDisassem.InitializeData();
	m_dwInstCount = 0;
	Instruction_Set_Struct objInstructionSet[MAX_INSTRUCTIONS] = {0};
	while((dwSize >= 2) && (dwOffset < dwSize - 2))
	{
		if(m_dwInstCount > 0x100)
		{
			break;
		}

		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = pBuffer[dwOffset];
		B2 = pBuffer[dwOffset+1];

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1 == 0xC1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset += 0x03;
			continue;
		}
		if(B1 == 0xD1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset += 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&pBuffer[dwOffset], 0x20, 0x400000, &da, DISASM_CODE);

		if(dwLength == 0x01 && B1 == 0xE2 && strstr(da.result, "???"))
		{
			dwOffset += 0x02;
			continue;
		}

		if(chBaseAddrss)
		{
			objInstructionSet[m_dwInstCount].dwInstLen = dwLength;
			strcpy_s(objInstructionSet[m_dwInstCount].szOpcode, TEXTLEN, da.dump);
			strcpy_s(objInstructionSet[m_dwInstCount++].szPnuemonics, TEXTLEN, da.result);
		}

		if(dwLength == 0x01 && B1 == 0xC3 && chBaseAddrss && dwCallLocation && strstr(da.result, "???"))
		{
			if(B > 0x00 && B < 0x03)
			{
				dwOffset = dwCall[--B];
			}
			else
			{
				if(chBaseAddrss == 0x01)
					dwVirusOffset = dwOffset = dwCallLocation;
				else
					dwOffset += dwLength;
			}
			continue;
		}
		if(dwLength == 0x02 && B1 == 0xFF && chBaseAddrss && dwCallLocation && strstr(da.result, "JMP E"))
		{
			if(B > 0x00 && B < 0x03)
			{
				dwVirusOffset = dwOffset = dwCall[--B];
			}
			else
			{
				if(chBaseAddrss == 0x01)
					dwVirusOffset = dwOffset = dwCallLocation;
				else
					dwOffset += dwLength;
			}
			continue;
		}

		if(dwLength == 0x02 && B1 == 0xB1 && chBaseAddrss == 0x00 && strlen(da.result) > 0x07 && strstr(da.result, "MOV CL,"))
		{
			chBaseAddrss	= 0x01;
			dwNumCall		= 0x01;
			ptr				= &da.result[0x07];
			sscanf_s(ptr, "%X", &dwTemp);
			objVirutParam.dwVirutKey = dwTemp;
			dwOffset += dwLength;
			continue;
		}

		if(dwLength == 0x05 && B1 == 0xE8 && strstr(da.result, "CALL "))
		{
			dwTemp = *((DWORD*)&pBuffer[dwOffset + 1]);
			if((dwTemp+dwOffset) >= dwSize)
			{
				dwOffset += dwLength;
				continue;
			}

			BYTE DllFuncCall[]  = {0xFF, 0x25};
			BYTE bZeroBuff[0xA] = {0}; //05 July 2011
			if((dwTemp < 0x100))
			{
				//Check for DLL calls. Some Call leads us to another call where some dll functions are called.
				if(memcmp(&pBuffer[dwOffset + dwTemp + dwLength], &DllFuncCall, 2) == 0)
				{
					dwOffset += dwLength;
					continue;
				}
				//Check for zeros in call location. Some Call leads us to location where we get only zeroes.(Checking 10 zeroes)//05 July 2011
				if(memcmp(&pBuffer[dwOffset + dwTemp + dwLength], &bZeroBuff, 0xA) == 0)
				{
					dwOffset += dwLength;
					continue;
				}
			}

			if(dwTemp < 0x100 &&(!chBaseAddrss))
			{
				chBaseAddrss = 0x01;
				dwNumCall++;
				dwCallLocation = dwOffset + dwLength;
				
				//Handle Samples with First call followed by POP Instruction.(First call is Valid)
				B1 = *((BYTE*)&pBuffer[dwOffset + dwLength + dwTemp]);
				dwDummyInstLen = m_objMaxDisassem.Disasm((char*)&pBuffer[dwOffset + dwLength + dwTemp], 0x20, 0x400000, &da, DISASM_CODE);

				if(B1 >= 0x58 && B1 <= 0x5F && dwDummyInstLen == 0x01 && strstr(da.result, "POP E"))
				{
					dwLocation = m_dwInstCount;
					if(!dwVirusOffset)
						dwVirusOffset = dwOffset + dwLength;
					if(B < 0x03)
						dwCall[B++] = dwOffset + dwLength;
				}
				dwOffset += dwLength + dwTemp;
				continue;
			}
			if(((dwTemp < 0x100)||(dwTemp & 0xFF000000)) && dwNumCall)
			{
				B1 = *((BYTE*)&pBuffer[dwOffset + dwLength + dwTemp]);
				dwDummyInstLen = m_objMaxDisassem.Disasm((char *)&pBuffer[dwOffset + dwLength + dwTemp], 0x20, 0x400000, &da, DISASM_CODE);
				if(B1 >= 0x58 && B1 <= 0x5F && dwDummyInstLen == 0x01 && strstr(da.result, "POP E"))
				{
					dwVirusOffset = dwOffset + dwLength;
				}

				dwLocation = m_dwInstCount;
				if(!dwVirusOffset)
					dwVirusOffset	= dwOffset + dwLength;
				if(!dwCallLocation)
					dwCallLocation	= dwOffset + dwLength;

				if(B < 0x03)
					dwCall[B++]		= dwOffset + dwLength;
				dwOffset = dwOffset + dwTemp + dwLength;
				continue;
			}
		}

		if(dwLength == 0x03 && B1 == 0x66 &&(B2 == 0x29 ||B2 == 0x31) && chBaseAddrss == 0x02)
		{
			if(strstr(da.result, "ADD "))
				objVirutParam.dwVirutMode = 0x01;

			if(strstr(da.result, "SUB "))
				objVirutParam.dwVirutMode = 0x02;

			if(strstr(da.result, "XOR "))
				objVirutParam.dwVirutMode = 0x03;

			ptr = strrchr(da.result, ',');
			if(!ptr)
				break;

			ptr++;
			if(strlen(ptr)!= 0x02)
				break;

			objVirutParam.dwModeOffset = dwOffset;
			sprintf_s(szKeyReg, 0x05, "E%s", ptr);
			dwOffset += dwLength;
			chBaseAddrss = 0x03;

			continue;
		}
		if((dwLength == 0x02 || dwLength == 0x03)&& strlen(da.result) > 0x0A && chBaseAddrss == 0x01 &&(strstr(da.result, "MOV AL,[E") ||
			strstr(da.result, "MOV BL,[E") || strstr(da.result, "MOV CL,[E") || strstr(da.result, "MOV DL,[E")))
		{
			szOffReg[0]		= da.result[0x08];szOffReg[1] = da.result[0x09];szOffReg[2] = da.result[0x0A];
			szOffReg[3]		= '\0';
			chBaseAddrss	= 0x02;
			dwOffset		+= dwLength;
			dwByteReplOff	= dwOffset; //To handle Vipre detection after MAX AV clean //05 July 2011
			continue;
		}
		if((dwLength == 0x02 || dwLength == 0x03) && strstr(da.result, "XCHG [E") && chBaseAddrss == 0x01)
		{
			szOffReg[0]		= da.result[0x06];szOffReg[1] = da.result[0x07];szOffReg[2] = da.result[0x08];
			szOffReg[3]		= '\0';
			chBaseAddrss	= 0x02;
			dwOffset		+= dwLength;
			dwByteReplOff	= dwOffset; //To handle Vipre detection after MAX AV clean //05 July 2011
			continue;
		}

		//Terminating conditions
		if(dwLength == 0x02 && chBaseAddrss == 0x03 && B1 == 0x75 && strstr(da.result, "JNZ SHORT "))
		{
			if(dwByteReplOff < dwOffset)//05 July 2011
				m_dwInitLen = dwOffset + dwLength;
			else
				m_dwInitLen = dwByteReplOff + dwLength;
			break;
		}

		if(dwLength == 0x03 && chBaseAddrss == 0x03 && strstr(da.result, "CMP E") && strstr(da.result, ",0"))
		{
			if(dwByteReplOff < dwOffset)//05 July 2011
				m_dwInitLen = dwOffset + dwLength;
			else
				m_dwInitLen = dwByteReplOff + dwLength;
			break;
		}
		dwOffset += dwLength;
	}

	if(m_dwInstCount > 0x100)
		return iRetStatus;

	if(chBaseAddrss < 0x03 || strlen(szOffReg) <0x03 || strlen(szKeyReg) <0x03)
		return iRetStatus;

	if((!dwVirusOffset) && (!dwCallLocation))
		return iRetStatus;

	if(m_dwInitLen)
		objVirutParam.InitExitOffset = m_dwInitLen;
	else
		objVirutParam.InitExitOffset = 0x00;

	if((!dwVirusOffset)&& dwCallLocation)
		dwVirusOffset = dwCallLocation;

	char szOffAdd[0x09] = {0}, szOffSub[0x09] = {0};
	sprintf_s(szOffAdd, 0x09, "ADD %s", szOffReg);
	sprintf_s(szOffSub, 0x09, "SUB %s", szOffReg);

	char szKeyAdd[0x09] = {0}, szKeySub[0x09] = {0}, szKeyInc[0x09] = {0};
	sprintf_s(szKeyAdd, 0x09, "ADD %s", &szKeyReg[1]);
	sprintf_s(szKeySub, 0x09, "SUB %s", &szKeyReg[1]);
	sprintf_s(szKeyInc, 0x09, "INC %s", szKeyReg);

	dwLength = m_dwInstCount - 1;
	for(; dwLength >= 0x01; dwLength--)
	{
		//How much value Increment of Key in successive iteration
		if(objInstructionSet[dwLength].dwInstLen == 0x01 && strstr(objInstructionSet[dwLength].szPnuemonics, szKeyInc)&& dwLocation <= dwLength)
		{
			objVirutParam.dwIncrementalKey	= 0x01;
			objVirutParam.dwVirutMode		= ((objVirutParam.dwVirutMode)&0xFF) + 0xF100;
		}
		if(objInstructionSet[dwLength].dwInstLen == 0x05 && dwLocation <= dwLength)
		{
			ptr = strrchr(objInstructionSet[dwLength].szPnuemonics, ',');
			if(!ptr)
				continue;
			ptr++;
			sscanf_s(ptr, "%X", &dwTemp);

			if(strstr(objInstructionSet[dwLength].szPnuemonics, szKeyAdd))
			{
				objVirutParam.dwIncrementalKey	= dwTemp;
				objVirutParam.dwVirutMode		= ((objVirutParam.dwVirutMode)&0xFF) + 0xF100;
				continue;
			}
			if(strstr(objInstructionSet[dwLength].szPnuemonics, szKeySub))
			{
				objVirutParam.dwIncrementalKey	= dwTemp;
				objVirutParam.dwVirutMode		= ((objVirutParam.dwVirutMode)&0xFF) + 0xF200;
				continue;
			}
		}

		//Getting Decryption Counter, Start of Virus Offset, Decryption Key
		if(objInstructionSet[dwLength].dwInstLen == 0x05 && strstr(objInstructionSet[dwLength].szPnuemonics, "MOV E"))
		{
			ptr = strrchr(objInstructionSet[dwLength].szPnuemonics, ',');
			if(!ptr)
				continue;
			ptr++;
			sscanf_s(ptr, "%X", &dwTemp);
			if(strstr(objInstructionSet[dwLength].szPnuemonics, szKeyReg))
			{
				objVirutParam.dwVirutKey = dwTemp;
				continue;
			}

			if(dwTemp > 0x2000 && dwTemp < 0x3000 && !(objVirutParam.dwDecLength))
				objVirutParam.dwDecLength = dwTemp;
			continue;
		}
		if(objInstructionSet[dwLength].dwInstLen == 0x06 &&
		  (strstr(objInstructionSet[dwLength].szPnuemonics, "ADD E")	||
		   strstr(objInstructionSet[dwLength].szPnuemonics, "SUB E")	||
		   strstr(objInstructionSet[dwLength].szPnuemonics, "OR E")	||
		   strstr(objInstructionSet[dwLength].szPnuemonics, "XOR E")))
		{
			ptr = strrchr(objInstructionSet[dwLength].szPnuemonics, ',');
			if(!ptr)
				continue;
			ptr++;
			
			// Check whether offset calculation instrution contains '-' sign with 
			// the constant if so we need to reverse the action. 
			bool bNegativeFlag = false;
			if(strrchr(ptr, '-'))
			{
				bNegativeFlag = true;
				ptr++;
			}
			sscanf_s(ptr, "%X", &dwTemp);
			// Check whether offset calculation instrution contains "FFFF" with 
			// the constant then its in 1st complement form so we can XOR it
			// with FFFF, add 1 and reverse the action to get the correct offset. 
			if(strstr(ptr, "FFFF"))
			{
				// Toggle the flag so that it works if both '-' and FFFF are in 
				// present in the instrution
				bNegativeFlag = !bNegativeFlag;
				ptr += 4;
				sscanf_s(ptr, "%X", &dwTemp);
				dwTemp ^= 0xFFFF;
				dwTemp++;
			}
			if(strstr(objInstructionSet[dwLength].szPnuemonics, szKeyReg))
			{
				objVirutParam.dwVirutKey = dwTemp;
				continue;
			}
			if(dwTemp > 0x2000 && dwTemp < 0x3000 && !(objVirutParam.dwDecLength))
			{
				objVirutParam.dwDecLength = dwTemp;
				continue;
			}
			if(bNegativeFlag)
			{
				if(strstr(objInstructionSet[dwLength].szPnuemonics, szOffAdd))
				{
					dwVirusOffset -= dwTemp;
					continue;
				}
				if(strstr(objInstructionSet[dwLength].szPnuemonics, szOffSub))
				{
					dwVirusOffset += dwTemp;
					continue;
				}
			}
			else
			{
				if(strstr(objInstructionSet[dwLength].szPnuemonics, szOffAdd))
				{
					dwVirusOffset += dwTemp;
					continue;
				}
				if(strstr(objInstructionSet[dwLength].szPnuemonics, szOffSub))
				{
					dwVirusOffset -= dwTemp;
					continue;
				}
			}
		}

		if(objInstructionSet[dwLength].dwInstLen == 0x02 && strstr(objInstructionSet[dwLength].szPnuemonics, "MOV CL"))
		{
			ptr = strrchr(objInstructionSet[dwLength].szPnuemonics, ',');
			if(!ptr)
				continue;
			ptr++;
			sscanf_s(ptr, "%X", &dwTemp);
			objVirutParam.dwVirutKey = dwTemp;
		}
	}
	if(0 == objVirutParam.dwDecLength)
		return iRetStatus;

	if(dwVirusOffset)
		objVirutParam.dwRvaVirus += dwVirusOffset; 

	iRetStatus = VIRUS_FILE_REPAIR;
	return iRetStatus;
}



/*-------------------------------------------------------------------------------------
	Function		: DetectVirutGenSig
	In Parameters	: BVIRUT_PARAM objVirutParams
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Checks Signature first in Buffer than in Decrypted Buffer 
--------------------------------------------------------------------------------------*/
bool CPolyVirut::DetectVirutGenSig(VIRUT_PARAM objVirutParams)
{
	DWORD dwRvaVirusCode	= objVirutParams.dwRvaVirus - m_dwImageBase;
	DWORD dwVirusCodeOffset = 0;
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwRvaVirusCode, &dwVirusCodeOffset))
	{
		dwVirusCodeOffset = Rva2FileOffsetEx(dwRvaVirusCode, NULL);
		if(dwVirusCodeOffset == 0x00)
		{
			return false;
		}
	}
	DWORD dwMinimumSize = (m_pMaxPEFile->m_dwFileSize - dwVirusCodeOffset) > 0x160 ? 0x160 : (m_pMaxPEFile->m_dwFileSize - dwVirusCodeOffset);
	BYTE  bBuff[0x160]  = {0};
	DWORD dwBytesRead   = 0;
	if(m_pMaxPEFile->ReadBuffer(bBuff, dwVirusCodeOffset, 0x160, dwMinimumSize, &dwBytesRead))
	{
		if(FindVirutGenSig(&bBuff[0], dwBytesRead))
		{
			return true; 
		}
		DecryptVirutGen(&bBuff[0], dwBytesRead, &objVirutParams);
		return FindVirutGenSig(&bBuff[0], dwBytesRead);
	}
	return false;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectVirutGenSig
	In Parameters	: BVIRUT_PARAM objVirutParams
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Finds signature in the buffer
--------------------------------------------------------------------------------------*/
bool CPolyVirut::FindVirutGenSig(BYTE *pBuffer, DWORD dwBuffSize)
{
	BYTE	bVirDSig1[] = {0x81,0x7B,0x4E,0x54,0x68,0x69,0x73};
	BYTE	bVirDSig2[] = {0x00,0x80,0x8B,0x5C,0x24,0x04,0x74};
	
	if(NEGATIVE_JUMP(dwBuffSize) || dwBuffSize < 0x10)
	{
		return false;
	}
	
	for(DWORD dwOffset = 0; dwOffset < dwBuffSize - 0x10; dwOffset++)
	{
		if(memcmp(bVirDSig1, &pBuffer[dwOffset], sizeof(bVirDSig1))== 0)
		{
			return true;
		}
		if(memcmp(bVirDSig2, &pBuffer[dwOffset], sizeof(bVirDSig2))== 0)
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirutGenSig
	In Parameters	: BYTE *pBuffer, DWORD dwDecLength, VIRUT_PARAM *pVirutParams
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Decrypt Buffer by Key
--------------------------------------------------------------------------------------*/
void CPolyVirut::DecryptVirutGen(BYTE *pBuffer, DWORD dwDecLength, VIRUT_PARAM *pVirutParams)
{
	WORD	wKey = pVirutParams->dwVirutKey & 0x0000FFFF, wAX = 0;
	BYTE	AL = 0x00;
	
	for(DWORD dwOffset = 0; dwOffset < dwDecLength; dwOffset++)
	{
		AL = pBuffer[dwOffset];
		wAX =(wAX & 0xFF00)+ AL;

		switch(pVirutParams->dwVirutMode & 0xFF)
		{
			case 1:
				wAX += wKey;
				break;
			case 2:
				wAX -= wKey;
				break;
			case 3:
				wAX = wAX ^ wKey;
				break;
		}

		AL = wAX & 0xFF;

		switch(pVirutParams->dwVirutMode & 0xFF00)
		{
			case 0xF100:
				wKey +=(WORD)pVirutParams->dwIncrementalKey;
				break;
			case 0xF200:
				wKey -=(WORD)pVirutParams->dwIncrementalKey;
				break;
		}
		pBuffer[dwOffset] = AL;
	}
	return;	
}
//Virut.Gen Ends


/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Repair routine for : Virut.CE
--------------------------------------------------------------------------------------*/
int CPolyVirut::CleanVirutCE(void)
{
	int iRetStatus = REPAIR_FAILED;

	m_dwType = VirutCEParam.dwType;
	if(m_dwType == 6)
	{
		return m_pMaxPEFile->TruncateFile(VirutCEParam.dwVirusRva, true);
	}

	m_dwVirusRva		= VirutCEParam.dwVirusRva;
	m_dwKey				= VirutCEParam.dwKey;
	m_dwOperation		= VirutCEParam.dwOperation;
	m_dwVirusBody		= VirutCEParam.dwVirusBody;
	m_dwVirusExecStart	= VirutCEParam.dwVirusExecStart;
	m_dwJumpLocation	= VirutCEParam.dwJumpLocation;
	m_dwOriginalAep		= VirutCEParam.dwOriginalAep;
	m_dwInitCodeRVA		= VirutCEParam.dwInitCodeRVA;
	if(m_dwType == 0x00)
	{
		return iRetStatus;
	}

	m_dwVirusRva -= m_dwImageBase;
	
	DWORD	dwInfAep = m_dwAEPUnmapped;
	DWORD	dwVirusOffset = 0x00;
	WORD	wSecNo = m_pMaxPEFile->Rva2FileOffset(m_dwVirusRva, &dwVirusOffset);
	if(dwVirusOffset == 0)
	{
		return iRetStatus;
	}

	m_pbyBuff = NULL;
	DWORD dwPos = 0, dwSuccess = 0, dwFoundLoc = 0, dwTruncateOffset = 0;

	switch(m_dwType)
	{
		case 0x01:
			m_dwAEPUnmapped = m_dwOriginalAep - m_dwImageBase;
			m_pMaxPEFile->WriteAEP(m_dwAEPUnmapped);
			dwTruncateOffset = GetJumps(NULL, 0, dwVirusOffset, wSecNo, true);
			break;

		case 0x02:
			{
				dwSuccess = AllocateBuffer(&m_pbyBuff);
				if(dwSuccess)
					break;
				dwSuccess = DecryptBuffer(dwVirusOffset, m_pbyBuff, &dwPos);
				if(dwSuccess)
				{
					m_pbyBuff = NULL;//Tushar ==> 06 Dec 2010 : Added to handle deletion of Buffer
					break;
				}

				dwSuccess = GetSetJumpBytes(TRUE, dwPos, m_dwAEPMapped, m_dwJumpLocation, m_dwImageBase + m_dwAEPUnmapped, &dwFoundLoc);
				if(!dwSuccess)
				{
					dwTruncateOffset = GetJumps(m_pbyBuff, m_dwVirusBody, dwVirusOffset, wSecNo, false);
					break;
				}

				DWORD dwAEP = 0;
				//03012011 :- Added last paramater			
				dwSuccess = GetVirutCEAEPEx(dwPos,(m_dwVirusExecStart-m_dwVirusRva), m_dwImageBase+m_dwVirusExecStart, &dwAEP); //Tushar ==> 06 Dec 2010 : Newly Added Last Two Parameters
				if(dwSuccess)
				{
					if(m_pbyBuff)
					{
						delete [] m_pbyBuff;
						m_pbyBuff = NULL;
					}
					m_pMaxPEFile->CloseFile_NoMemberReset();
					return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : iRetStatus;
				}
				
				m_dwAEPUnmapped = dwAEP - m_dwImageBase;
				m_pMaxPEFile->WriteAEP(m_dwAEPUnmapped);
				dwTruncateOffset = GetJumps(m_pbyBuff, m_dwVirusBody, dwVirusOffset, wSecNo, false);
			}
			break;

		case 0x03:
			dwSuccess = AllocateBuffer(&m_pbyBuff);
			if(dwSuccess)
				break;
			dwSuccess = DecryptBuffer(dwVirusOffset, m_pbyBuff, &dwPos);
			if(dwSuccess)
			{
				m_pbyBuff = NULL;
				break;
			}
			
			dwSuccess = NewGetSetJumpBytes(TRUE, dwPos, &dwFoundLoc); //manjunath
			dwTruncateOffset = GetJumps(m_pbyBuff, m_dwVirusBody, dwVirusOffset, wSecNo, false);
			if(dwSuccess || dwTruncateOffset == 0)
			{
				m_pMaxPEFile->CloseFile_NoMemberReset();
				return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : iRetStatus;
			}
			break;

		case 0x04:
			m_pMaxPEFile->WriteBuffer(&m_dwOperation, m_dwVirusExecStart, 0x04);			
			m_pMaxPEFile->WriteBuffer(&m_dwKey, m_dwJumpLocation, 0x01);			
			dwTruncateOffset = GetJumps(NULL, 0, dwVirusOffset, wSecNo, true);
			break;


		case 0x05: //Added on 03 Nov 2010 for Handling Virut.CF
			dwSuccess = AllocateBuffer(&m_pbyBuff);
			if(dwSuccess)
				break;
			dwSuccess = DecryptBuffer(dwVirusOffset, m_pbyBuff, &dwPos);
			if(dwSuccess)
				break;
			dwSuccess = GetSetJumpBytes(TRUE, dwPos, m_dwAEPMapped, m_dwJumpLocation, m_dwImageBase + m_dwAEPUnmapped, &dwFoundLoc);

			break;		
		
		default:
			dwSuccess = 0x01;
	}

	if(m_pbyBuff)
	{
		delete [] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	if(dwSuccess)
	{
		m_pMaxPEFile->CloseFile_NoMemberReset();
		return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : iRetStatus;
	}

	dwPos = m_pMaxPEFile->m_stPEHeader.NumberOfSections;		//If Last section's Size is Zero
	if(m_pSectionHeader[dwPos - 1].SizeOfRawData == 0x00)
	{
		dwPos -= 0x01;
	}

	if(((m_pMaxPEFile->m_dwFileSize > m_pSectionHeader[dwPos-1].PointerToRawData + m_pSectionHeader[dwPos - 1].SizeOfRawData + 0x50)&& 
		!CheckForZeros(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData,(m_pMaxPEFile->m_dwFileSize -(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))))|| 
	  ((m_dwVirusRva == m_dwAEPUnmapped)&&(m_dwType != 0x01))|| 
	  (m_dwType == 0x04 && m_dwVirusBody == 0x10))	
	{
		if(dwTruncateOffset != 0x00 && dwTruncateOffset < dwVirusOffset)
		{
			dwVirusOffset = dwTruncateOffset;
		}		
		if(m_pMaxPEFile->TruncateFile(dwVirusOffset, true))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
		return iRetStatus;
	}

	//Tushar ==> 08 Dec 2010 : To Fill InitCode(i.e Decryption Code)with Zeros
	DWORD dwInitCodeOffset = 0x00;
	DWORD dwInitCodeScNo = m_pMaxPEFile->Rva2FileOffset(m_dwInitCodeRVA, &dwInitCodeOffset);
	if(dwInitCodeOffset)
	{
		DWORD dwSizeOfBuff = 0x50;
		BYTE byBuff[0x50] = {0};

		//This condition is added to handle notepad file corruption(Manjunath)
		if(((m_pSectionHeader[dwInitCodeScNo].PointerToRawData + m_pSectionHeader[dwInitCodeScNo].SizeOfRawData)- dwInitCodeOffset)< dwSizeOfBuff)
		{
			dwSizeOfBuff =(m_pSectionHeader[dwInitCodeScNo].PointerToRawData + m_pSectionHeader[dwInitCodeScNo].SizeOfRawData)- dwInitCodeOffset;
		}
		if(!m_pMaxPEFile->WriteBuffer(byBuff, dwInitCodeOffset, dwSizeOfBuff, dwSizeOfBuff))
		{
			m_pMaxPEFile->FillWithZeros(dwInitCodeOffset, 0x32);
		}
	}
	//Tushar ==> 09 Feb 2011 : Changes to Handle Size of Image Parameters
	if(m_wAEPSec ==(m_wNoOfSections - 1)&& m_dwAEPMapped < dwVirusOffset && m_dwType == 0x01)
	{
		dwVirusOffset = m_dwAEPMapped;
		m_dwVirusRva = dwInfAep;
	}

	if(dwTruncateOffset != 0x00 && dwTruncateOffset < dwVirusOffset)
	{
		dwVirusOffset = dwTruncateOffset;
	}
	
	if(m_pMaxPEFile->TruncateFile(dwVirusOffset, true))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirutCE
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Detection routine for : Virut.CE
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirutCE()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000000)!= 0xE0000000) &&
	   ((m_pSectionHeader[m_wNoOfSections - 2].Characteristics & 0xE0000000)!= 0xE0000000))
	{
		return iRetStatus;
	}
	
	bool bNoofSecChanged = false;
	//Virus code will be in last section but in case of multiple infection virus code in last but one section also.
	if((m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData < 0x4000) &&
		(m_wNoOfSections > 1) && 
		(m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData > 0x4000) && 
		((m_pSectionHeader[m_wNoOfSections - 2].Characteristics & 0xE0000000)== 0xE0000000))
	{
		bNoofSecChanged = true;
		m_wNoOfSections--;
	}
	if(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x2000)
	{	
		memset(&VirutCEParam, 0, sizeof(VIRUTCE_PARAM));
		m_dwVirusRva = m_dwVirusBody = m_dwKey = m_dwOperation = m_dwVirusExecStart = m_dwJumpLocation = m_dwOriginalAep = m_dwType = m_dwInitCodeRVA = 0x00;

		//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		//Check for viruses AEP in last section. AEP directly points to virus body.
		//Here also no need to check for call patches, bcz we wont get any kernal in virus body
		//dwType = 0x01
		//Some times in multiple infection, we are not able to remove last section added by virus.
		//in that case we may get infection in last but one section also
		//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		if((m_wAEPSec ==(m_wNoOfSections - 1))|| 
		  ((m_wNoOfSections > 1)&&(m_wAEPSec ==(m_wNoOfSections - 2))&& 
		  ((m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000000)== 0xE0000000)))
		{
			iRetStatus = DetectVirut_CE_LastSectionAepInit(m_wAEPSec + 1);
			if(iRetStatus)
			{
				return iRetStatus;
			}
		}

		//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		//Entry point directly pointing to Init code. Normally at the end of the AEP section
		//Here no need to check for call patches, bcz we wont get any kernal call in virus init code 
		//dwType = 0x02
		//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		iRetStatus = DetectVirut_CE_AepInit();
		if(iRetStatus) 	
		{
			if(!m_bPolyCleanFlag)
				return iRetStatus;
		}

		//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		//Check for JMP patches in AEP section from(AEP - 0x500)to 0xD000 bytes.
		//We get two type of jump patches. One points to decryption loop/init code at the end of the AEP section
		//and another points directly to last section virus body.
		//dwType = 0x03 and dwType = 0x04
		//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
		if(!m_pMaxPEFile->m_b64bit)
		{		
			iRetStatus = DetectVirutCE_JumpPatch();
			if(iRetStatus)
			{
				return iRetStatus;
			}
		}

		/////////////////////New Type of Virut.Ce : Neeraj 23-12-2011///////////////////////////////////
		//Added Last Section of random name with read - write property & may or may not contain dead code
		//Secondlast section (originally last) with read - write - execute propety, always have deadcode
		m_wNoOfSections = m_pMaxPEFile->m_stPEHeader.NumberOfSections;
		if (m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x00)
		{
			m_wNoOfSections--;
		}
		if(((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000000)== 0xE0000000) &&
		  ((m_pSectionHeader[m_wNoOfSections - 2].Characteristics & 0xE0000000)== 0xE0000000))
		{
			iRetStatus = DetectVirutCE_DeadCode2();
			if(iRetStatus)
			{
				return iRetStatus;
			}
		}

		// Check for deadcode 
		//	WORD wSecForDeadCode	= bNoofSecChanged ? m_wNoOfSections : m_wNoOfSections - 1;
		//	DWORD dwDeadCodeOffset	= GetJumps(NULL, 0, 0, wSecForDeadCode, true);		
		//	if(dwDeadCodeOffset)
		//	{
		//		if(m_dwAEPMapped > dwDeadCodeOffset)
		//		{
		//			return VIRUS_FILE_DELETE;			
		//		}
		//		VirutCEParam.dwVirusRva = dwDeadCodeOffset;
		//		VirutCEParam.dwType		= 0x06;
		//		return VIRUS_FILE_REPAIR;			
		//	}


		if(VirutCEParam.dwType != 0x00)
		{
			iRetStatus = VIRUS_FILE_REPAIR;
		}		
	}
	if(bNoofSecChanged && VIRUS_NOT_FOUND == iRetStatus)
	{
		m_wNoOfSections++;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirut_CE_LastSectionAepInit
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Detection routine for : Virut.CE (AEP Obfuscation + INIT)
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirut_CE_LastSectionAepInit(DWORD dwDeadcode)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD dwTemp = m_dwImageBase, dwVirusCodeOffset = 0;

	int RetVal = GetVirutCEAEPEx_New(&dwVirusCodeOffset, &dwTemp, dwDeadcode);

	if(RetVal == 0x00)
	{
		//Validate AEP(dwOriginalAep)23 May 2011
		if(dwTemp < m_dwImageBase)
			return iRetStatus;
		if((dwTemp - m_dwImageBase)> 
			(m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize))
			return iRetStatus;
		//End

		if((dwVirusCodeOffset < m_dwAEPMapped)&& dwVirusCodeOffset)
			VirutCEParam.dwVirusRva = m_dwAEPUnmapped + m_dwImageBase -(m_dwAEPMapped - dwVirusCodeOffset);
		else
			VirutCEParam.dwVirusRva = m_dwAEPUnmapped + m_dwImageBase;
		
		if(!IsValidVirusCode(VirutCEParam.dwVirusRva))
		{
			VirutCEParam.dwVirusRva = 0x00;
			return iRetStatus;
		}

		VirutCEParam.dwVirusBody = 0x10;
		VirutCEParam.dwKey = 0x00;
		VirutCEParam.dwOperation = 0x00;
		VirutCEParam.dwVirusExecStart = 0x00;
		VirutCEParam.dwJumpLocation = 0x00;
		VirutCEParam.dwOriginalAep = dwTemp;
		VirutCEParam.dwInitCodeRVA = 0x00;
		VirutCEParam.dwType = 0x01;
		iRetStatus = VIRUS_FILE_REPAIR;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirut_CE_AepInit
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Detection routine for : Virut.CE (AEP + INIT)
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirut_CE_AepInit()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	//handling for Virus.Win32.Nakuru.A as virus code matches with Virut Init Code
	if(m_pMaxPEFile->m_dwFileSize > m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + 0xF)
	{
		BYTE byNakuruSig[] = {0x6B, 0x73, 0x70, 0x6F, 0x6F, 0x6C, 0x64, 0x2E, 0x65, 0x78, 0x65};
 		BYTE byBuffer[0xB] = {0};
		DWORD dwBytesRead = 0;
		if(m_pMaxPEFile->ReadBuffer(byBuffer, m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + 0x05, 0x0B, 0x0B, &dwBytesRead))
		{
			if(!memcmp(byBuffer, byNakuruSig, dwBytesRead))
			{
				return iRetStatus;
			}
		}
		

	}
	DWORD	dwTemp = 0;
	DWORD	iBufIndex = 0;
	
	m_dwKey = m_dwOperation = m_dwJumpLocation = m_dwOriginalAep = m_dwType = m_dwInitCodeRVA = 0;
	
	m_dwVirusRva		= m_dwAEPUnmapped;
	m_dwVirusExecStart= m_dwImageBase;
	m_dwVirusBody		= m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize;

	
	int dwRet = GetVirutCEParamEx(m_dwAEPMapped, &dwTemp, iBufIndex);

	//To handle MPRESS packed files, only init code
	if(dwRet != 0)
	{
		if(strstr((char *)m_pSectionHeader[0].Name, ".MPRESS1"))
		{
			dwRet = GetVirutCEAEPEx_New(&m_dwAEPMapped, &dwTemp, m_wAEPSec + 1);
			if(0 == dwRet)
			{
				return VIRUS_FILE_DELETE;
			}
		}
	}

	//Tushar ==> 29 Nov 2010 : Added by Ajay to Handle REscan Issue...
	if(m_dwVirusExecStart > m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)
	{
		DWORD dwVirusExecStartOffset = 0x00;
		m_pMaxPEFile->Rva2FileOffset(m_dwVirusExecStart, &dwVirusExecStartOffset);

		BYTE byTempBuffer1[10] = {0} , byTempBuffer[10] = {0};
		DWORD dwBytesRead = 0x00;
		
		if(!m_pMaxPEFile->ReadBuffer(byTempBuffer1, dwVirusExecStartOffset, 10, 0, &dwBytesRead))
		{
			return iRetStatus;
		}

		if(!memcmp(byTempBuffer1, byTempBuffer, dwBytesRead))
		{
			return iRetStatus;
		}
	}

	if(dwRet == 0x00)
	{
		if(IsValidVirusCode(m_dwVirusRva))
		{
			m_dwJumpLocation = dwTemp;
			m_dwType = 0x02;

			VirutCEParam.dwVirusRva = m_dwVirusRva;
			VirutCEParam.dwVirusBody = m_dwVirusBody;
			VirutCEParam.dwKey = m_dwKey;
			VirutCEParam.dwOperation = m_dwOperation;
			VirutCEParam.dwVirusExecStart = m_dwVirusExecStart;
			VirutCEParam.dwJumpLocation = m_dwJumpLocation;
			VirutCEParam.dwOriginalAep = 0x00;
			VirutCEParam.dwInitCodeRVA = m_dwInitCodeRVA;
			VirutCEParam.dwType = 0x02;
			
			iRetStatus = VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirut_CE_AepInit
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Detection routine for : JMP Patch
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirutCE_JumpPatch()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD j = 0, dwBytesRead = 0;
	DWORD dwTempOffset1, dwTemp1, iBufIndex, dwTemp2; 
	DWORD dwVirusExecStartOffset = 0x00;
	int dwRetVal = 0x01;
	BYTE tmpBuff[MAX_PATH];

	m_dwVirusRva = m_dwVirusBody = m_dwKey = m_dwOperation = m_dwVirusExecStart = m_dwJumpLocation = m_dwOriginalAep = m_dwType = m_dwInitCodeRVA = 0;
	
	DWORD dwReadBuffSize = 0x1024;
	BYTE *bReadBuff = new BYTE[dwReadBuffSize];
	if(!bReadBuff)
		return 0x00;

	//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	//Search for E9(Jump)patch from location AEP - 0x500 to 0xD000 bytes
	//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	DWORD dwNegDistFromAEP = 0x00, dwSearchStartLoc = m_dwAEPMapped;
	
	if(m_wAEPSec != m_wNoOfSections)//Skip if AEP in last section
	{
		dwNegDistFromAEP = 0x500;
		if((m_pSectionHeader[m_wAEPSec].PointerToRawData + dwNegDistFromAEP)>= m_dwAEPMapped)
		{
			dwSearchStartLoc = m_pSectionHeader[m_wAEPSec].PointerToRawData;
			if(m_dwAEPMapped >= m_pSectionHeader[m_wAEPSec].PointerToRawData)
			{
				dwNegDistFromAEP = m_dwAEPMapped - m_pSectionHeader[m_wAEPSec].PointerToRawData;
			}
			else
			{
				dwNegDistFromAEP = m_dwAEPMapped - m_pSectionHeader[m_wAEPSec].VirtualAddress;
			}
		}	
		else
		{
			dwSearchStartLoc = m_dwAEPMapped - dwNegDistFromAEP;
		}
	}
	
	BOOL End_E9_SearchFlag = FALSE;
	DWORD dwDistFromStartLoc = 0x00;
	for(DWORD dwReadOffset = dwSearchStartLoc; dwReadOffset <(m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData)&& !End_E9_SearchFlag; dwReadOffset += dwReadBuffSize)
	{
		//Limit is set to 0xD000 bcz scanning time increases if the AEP section size is too big(JMP patched 0xCB8A distance from AEP for sample 9948D7E4.exe)
		if(dwDistFromStartLoc > 0x13000)
			break;

		m_pMaxPEFile->ReadBuffer(bReadBuff, dwReadOffset, dwReadBuffSize, 0, &dwBytesRead);
		
		if((dwReadOffset + dwBytesRead)>(m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData))
			dwBytesRead =(m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData)- dwReadOffset;

		if(dwBytesRead < 0x5)
		{
			if(bReadBuff)
			{
				delete []bReadBuff;
				bReadBuff = NULL;
			}
			break;
		}
		for(j=0; j<dwBytesRead-0x05; j++)
		{
			if(!(bReadBuff[j] == 0xE9))
				continue;

			dwTemp1 = *((DWORD*)&bReadBuff[j+1]);

			dwTemp1 = dwTemp1 + m_dwAEPUnmapped + dwDistFromStartLoc - dwNegDistFromAEP + j + 0x05;

			if(dwTemp1 >=(m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress+m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize))
			{
				if(dwTemp1 >=(m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress+m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
					continue;
			}

			dwTempOffset1 = 0x00;
			 m_pMaxPEFile->Rva2FileOffset(dwTemp1, &dwTempOffset1);
			if(dwTempOffset1 == 0x00)
				continue;

			

			m_dwVirusRva = dwTemp1;
			m_dwVirusExecStart = m_dwImageBase;
			m_dwVirusBody = m_pSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].VirtualAddress + m_pSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].Misc.VirtualSize;
		
			iBufIndex = j;
			
			dwTemp2 = dwTemp1; //Taking backup for further use

			dwRetVal = 0x01;
		
			DWORD dwSize = 0;
			m_pMaxPEFile->ReadBuffer(tmpBuff, dwTempOffset1, 0x50, 0, &dwSize);
			if(dwSize < 0x30)
				continue;
			
			//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
			//Here we check for JMP patch which is pointing to decryption loop or init code at the end of AEP section.(dwType == 0x03)
			//1. Check for JMP instruction within 0x15 instructions.
			//2. Check Jump address is greater than Jump found location.(i.e forward jump)
			//3. Check whether the JMP location within AEP section.
			//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
			if((CheckPnuemonics(tmpBuff, dwSize, 0x25, "E9", 0x05, "JMP")|| CheckPnuemonics(tmpBuff, dwSize, 0x25, "EB", 0x02, "JMP SHORT"))&& //Check for "JMP" or "JMP SHORT" instruction within 0xA instruction count
			  (dwTempOffset1 >(dwReadOffset + j + 0x05))&& //Check Jmp location is greater than current Jump found offset
			  ((dwTempOffset1 <=(m_pSectionHeader[m_wAEPSec].PointerToRawData+m_pSectionHeader[m_wAEPSec].SizeOfRawData))))//Some sample whcih are wrongly infected/disinfected has zeroes at the entry point. so "> AEP " condition removed. In proper virut.CE infection init code location always
			{
				//Check for E9(JMP)for decryption loop. Decryption is required.
				dwRetVal = GetVirutCEParamEx(dwTempOffset1, &dwTemp1, iBufIndex);

				if(dwRetVal == 0x00)
				{
					//Tushar ==> 29 Nov 2010 : Added by Ajay to reduce rescan Issue...
					if(m_dwVirusExecStart > m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)
					{
						dwVirusExecStartOffset = 0x00;
						m_pMaxPEFile->Rva2FileOffset(m_dwVirusExecStart, &dwVirusExecStartOffset);
						if(dwVirusExecStartOffset == 0x00)
							continue;
						
						BYTE byTempBuffer1[10] = {0} , byTempBuffer[10] = {0};
						if(!m_pMaxPEFile->ReadBuffer(byTempBuffer1, dwVirusExecStartOffset, 10, 0, &dwBytesRead))
						{
							continue;
						}
						if(!memcmp(byTempBuffer1,byTempBuffer,dwBytesRead))
						{
							continue;
						}
					}

					if(!IsValidVirusCode(m_dwVirusRva))
					{
						continue;
					}
					
					if((dwTemp1 != j)||(dwDistFromStartLoc < dwNegDistFromAEP))//In some case we get virus code before analysisng actual patched jump bytes. Actual location comes from GetVirutCEParamEx function
						m_dwJumpLocation = dwTemp1;
					else
						m_dwJumpLocation = dwTemp1 +(dwDistFromStartLoc - dwNegDistFromAEP);
					
					m_dwType = 0x03;

					if(m_dwVirusRva > VirutCEParam.dwVirusRva)
					{
						VirutCEParam.dwVirusRva = m_dwVirusRva;
						VirutCEParam.dwVirusBody = m_dwVirusBody;
						VirutCEParam.dwKey = m_dwKey;
						VirutCEParam.dwOperation = m_dwOperation;
						VirutCEParam.dwVirusExecStart = m_dwVirusExecStart;
						VirutCEParam.dwJumpLocation = m_dwJumpLocation;
						VirutCEParam.dwOriginalAep = 0x00;
						VirutCEParam.dwInitCodeRVA = m_dwInitCodeRVA;
						VirutCEParam.dwType = 0x03;

						if(!m_bPolyCleanFlag)
						{
							End_E9_SearchFlag = TRUE;
							break;
						}
					}
				}
			}

			//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
			//Here we checking for Jump patch directly to last section. No decryption, directly we get JMP bytes.(dwType = 0x04)
			//1. Init code not found in first section.
			//2. JMP location within last section.
			//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
			if(dwRetVal &&((dwTempOffset1 >= m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData)&&(dwTempOffset1 <=(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData+m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))))
			{
				//Check if jump address is poinintg to last section or not
				if(dwTemp2 < m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)
					continue;
				if(VirutCE_CheckForJumpBytes(dwTempOffset1, dwSearchStartLoc, dwDistFromStartLoc + j, m_dwAEPUnmapped + m_dwImageBase - dwNegDistFromAEP, dwTemp2 + m_dwImageBase))
				{
					m_dwType = 0x04;
					if(!m_bPolyCleanFlag)
					{
						End_E9_SearchFlag = TRUE;
						break;
					}
				}
			}
		}
		dwDistFromStartLoc += dwReadBuffSize;
	}

	if(bReadBuff)
	{
		delete []bReadBuff;
		bReadBuff = NULL;
	}
	
	if(m_dwType != 0x00)
		iRetStatus = VIRUS_FILE_REPAIR;

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: VirutCE_CheckForJumpBytes
	In Parameters	: DWORD dwStartLoc, DWORD dwSearchStartLoc, DWORD dwJmpLoc, DWORD dwImageLoc, DWORD dwJumpRVA
	Out Parameters	: 0 if failure else > 0
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: This function follows the JMP instruction and check destination buffer
--------------------------------------------------------------------------------------*/
DWORD CPolyVirut::VirutCE_CheckForJumpBytes(DWORD dwStartLoc, DWORD dwSearchStartLoc, DWORD dwJmpLoc, DWORD dwImageLoc, DWORD dwJumpRVA)
{
	DWORD dwBytesRead, dwBytesToRead;
	DWORD dwFoundLoc;
	DWORD dwTmpStartLoc, dwNewVirusRVA;

	m_dwKey = m_dwJumpLocation = m_dwOperation = m_dwVirusExecStart = 0x00;
	dwNewVirusRVA = 0x00;
	dwBytesToRead = 0x00;

	if(m_pbyBuff)
	{
		delete [] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[0x1030];
	if(!m_pbyBuff)
		return 0x00;

	//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	//1. Check Patched bytes from "dwStartLoc" to "dwStartLoc + 0x1024"
	//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	dwFoundLoc = 0x00;
	dwNewVirusRVA = dwJumpRVA;  //Forward search
	dwTmpStartLoc = dwStartLoc;
	
	if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwTmpStartLoc, 0x1024, 0xA, &dwBytesRead))
	{
		if(!GetSetJumpBytes(FALSE, dwBytesRead - 0xA, dwSearchStartLoc, dwJmpLoc, dwImageLoc, &dwFoundLoc))
		{
			if(IsValidVirusCode(dwNewVirusRVA))
			{
				if(dwNewVirusRVA > VirutCEParam.dwVirusRva)
				{
					VirutCEParam.dwVirusRva = dwNewVirusRVA;
					VirutCEParam.dwVirusBody = dwFoundLoc;
					VirutCEParam.dwKey = m_dwKey;
					VirutCEParam.dwOperation = m_dwOperation;
					VirutCEParam.dwVirusExecStart = m_dwVirusExecStart;
					VirutCEParam.dwJumpLocation = m_dwJumpLocation;
					VirutCEParam.dwOriginalAep = 0x00;
					VirutCEParam.dwInitCodeRVA = 0x00;
					VirutCEParam.dwType = 0x04;
				}
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				return 0x01;
			}
		}
	}

	//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	//2. Check Patched bytes from "dwStartLoc" to "dwStartLoc - 0x1024"
	//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	dwFoundLoc = 0x00;
	if((dwStartLoc - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData)<= 0x1024)
	{
		dwTmpStartLoc = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
	}
	else
		dwTmpStartLoc =(dwStartLoc - 0x1024);

	dwNewVirusRVA =  dwJumpRVA -(dwStartLoc - dwTmpStartLoc); //Backward search

	if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwTmpStartLoc, 0x1024, 0xA, &dwBytesRead))
	{
		if(!GetSetJumpBytes(FALSE, dwBytesRead - 0xA, dwSearchStartLoc, dwJmpLoc, dwImageLoc, &dwFoundLoc))
		{
			if(IsValidVirusCode(dwNewVirusRVA + dwFoundLoc))
			{
				if(dwNewVirusRVA > VirutCEParam.dwVirusRva)
				{
					VirutCEParam.dwVirusRva = dwNewVirusRVA + dwFoundLoc;
					VirutCEParam.dwVirusBody = dwStartLoc -(dwTmpStartLoc + dwFoundLoc);
					VirutCEParam.dwKey = m_dwKey;
					VirutCEParam.dwOperation = m_dwOperation;
					VirutCEParam.dwVirusExecStart = m_dwVirusExecStart;
					VirutCEParam.dwJumpLocation = m_dwJumpLocation;
					VirutCEParam.dwOriginalAep = 0x00;
					VirutCEParam.dwInitCodeRVA = 0x00;
					VirutCEParam.dwType = 0x04;
				}
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				return 0x01;
			}
		}
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
	m_pbyBuff = new BYTE[0x8005];
	if(!m_pbyBuff)
		return 0x00;

	//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	//3. Check Patched bytes from "dwStartLoc + 0x1024" to "+0x8000"
	//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	dwFoundLoc = 0x00;
	dwBytesToRead = 0x8000;
	dwTmpStartLoc = dwStartLoc + 0x1024 - 0x0A;
	dwNewVirusRVA = dwJumpRVA; //Forward search

	if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwTmpStartLoc, dwBytesToRead, 0xA, &dwBytesRead))
	{
		if(!GetSetJumpBytes(FALSE, dwBytesRead - 0xA, dwSearchStartLoc, dwJmpLoc, dwImageLoc, &dwFoundLoc))
		{
			if(IsValidVirusCode(dwNewVirusRVA))
			{
				if(dwNewVirusRVA > VirutCEParam.dwVirusRva)
				{
					VirutCEParam.dwVirusRva = dwNewVirusRVA;
					VirutCEParam.dwVirusBody = dwFoundLoc;
					VirutCEParam.dwKey = m_dwKey;
					VirutCEParam.dwOperation = m_dwOperation;
					VirutCEParam.dwVirusExecStart = m_dwVirusExecStart;
					VirutCEParam.dwJumpLocation = m_dwJumpLocation;
					VirutCEParam.dwOriginalAep = 0x00;
					VirutCEParam.dwInitCodeRVA = 0x00;
					VirutCEParam.dwType = 0x04;
				}
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				return 0x01;
			}
		}
	}

	//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	//4. Check Patched bytes from "dwStartLoc - 0x1024" to "-0x8000"
	//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++==
	dwFoundLoc = 0x00;
	dwBytesToRead = 0x8000;
	if((dwStartLoc - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData)<=(0x8000 + 0x1024 + 0xA))//We already comapred -(0x1024 - 0xA)at section 2.
	{
		dwTmpStartLoc = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
		dwBytesToRead =(dwStartLoc - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData);
		if(dwBytesToRead > 0x8000)
			dwBytesToRead = 0x8000;
	}
	else
		dwTmpStartLoc = dwStartLoc -(0x8000 + 0x1024 + 0xA);

	dwNewVirusRVA =  dwJumpRVA -(dwStartLoc - dwTmpStartLoc); //Backward search

	if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwTmpStartLoc, dwBytesToRead, 0xA, &dwBytesRead))
	{
		if(!GetSetJumpBytes(FALSE, dwBytesRead - 0xA, dwSearchStartLoc, dwJmpLoc, dwImageLoc, &dwFoundLoc))
		{
			if(IsValidVirusCode(dwNewVirusRVA + dwFoundLoc))
			{
				if(dwNewVirusRVA > VirutCEParam.dwVirusRva)
				{
					VirutCEParam.dwVirusRva = dwNewVirusRVA + dwFoundLoc;
					VirutCEParam.dwVirusBody = dwStartLoc -(dwTmpStartLoc + dwFoundLoc);
					VirutCEParam.dwKey = m_dwKey;
					VirutCEParam.dwOperation = m_dwOperation;
					VirutCEParam.dwVirusExecStart = m_dwVirusExecStart;
					VirutCEParam.dwJumpLocation = m_dwJumpLocation;
					VirutCEParam.dwOriginalAep = 0x00;
					VirutCEParam.dwInitCodeRVA = 0x00;
					VirutCEParam.dwType = 0x04;
				}
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				return 0x01;
			}
		}
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	return 0x00;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSetJumpBytes
	In Parameters	: BOOL bWrite, DWORD dwPos, DWORD dwStartLoc, DWORD dwJmpLocn, DWORD dwImgageLocn, DWORD *dwFoundLoc
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Get set of JMP instructions
--------------------------------------------------------------------------------------*/
int	CPolyVirut::GetSetJumpBytes(BOOL bWrite, DWORD dwPos, DWORD dwStartLoc, DWORD dwJmpLocn, DWORD dwImgageLocn, DWORD *dwFoundLoc)//Manjunath 29 April 2011
{
	DWORD	i, dwBytesRead, dwTemp;
	char	bJumpWrittenCount;

	bJumpWrittenCount = 0x00;
	dwBytesRead = 0x00;
	for(i=0; i<dwPos; i++)
	{
		if(bJumpWrittenCount == 0x02)
			return 0;

		if(m_pbyBuff[i]==0xC6 && m_pbyBuff[i+1]==0x05)
		{
			dwTemp = *((DWORD*)&m_pbyBuff[i+2]);
			if(dwTemp ==(dwImgageLocn+dwJmpLocn))
			{
				if(bWrite)
				{
					m_pMaxPEFile->WriteBuffer(&m_pbyBuff[i+6], dwStartLoc + dwJmpLocn, 1);
				}
				else
				{
					m_dwJumpLocation = dwStartLoc + dwJmpLocn;
					m_dwKey = m_pbyBuff[i+6];
				}

				bJumpWrittenCount += 0x01;
				dwBytesRead = 0x01;
			}

			if(dwTemp ==(dwImgageLocn+dwJmpLocn+0x04))
			{
				if(bWrite)
				{
					m_pMaxPEFile->WriteBuffer(&m_pbyBuff[i + 6], dwStartLoc + dwJmpLocn + 0x04, 0x01);
				}
				else
				{
					m_dwJumpLocation = dwStartLoc + dwJmpLocn + 0x04;
					m_dwKey = m_pbyBuff[i+6];
				}
				
				bJumpWrittenCount += 0x01;
			}
		}

		if(m_pbyBuff[i]==0xC7 && m_pbyBuff[i+1]==0x05)
		{
			dwTemp = *((DWORD*)&m_pbyBuff[i+2]);
			if(dwTemp ==(dwImgageLocn+dwJmpLocn + dwBytesRead))
			{
				if(bWrite)
				{
					m_pMaxPEFile->WriteBuffer(&m_pbyBuff[i + 6], dwStartLoc + dwJmpLocn + dwBytesRead, 0x04);					
				}
				else
				{
					m_dwVirusExecStart = dwStartLoc+dwJmpLocn+dwBytesRead;
					m_dwOperation = *((DWORD*)&m_pbyBuff[i+6]);
					*dwFoundLoc = i; //manjunath
				}
				bJumpWrittenCount += 0x01;
			}

			if(dwTemp ==(dwImgageLocn+dwJmpLocn + 0x04))
			{
				if(bWrite)
				{
					m_pMaxPEFile->WriteBuffer(&m_pbyBuff[i + 6], dwStartLoc + dwJmpLocn + 0x04, 0x04);
				}
				else
				{
					m_dwVirusExecStart = dwStartLoc+dwJmpLocn+0x04;
					m_dwOperation = *((DWORD*)&m_pbyBuff[i+6]);
					*dwFoundLoc = i; //manjunath
				}
				bJumpWrittenCount += 0x01;
			}
		}
	}

	return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: AllocateBuffer
	In Parameters	: BYTE **pbBuffer
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: This function dynamically allocates buffer
--------------------------------------------------------------------------------------*/
DWORD CPolyVirut::AllocateBuffer(BYTE **pbBuffer)
{
	*pbBuffer = new BYTE[m_dwVirusBody+0x08];
	if(!(*pbBuffer))
		return 1;

	memset(*pbBuffer, 0x00, m_dwVirusBody+0x08);
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptBuffer
	In Parameters	: DWORD dwOffSet, BYTE *pBuffer, DWORD *pTotalDecypt
	Out Parameters	: 0 if failure else > 0
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: This function decrypts buffer
--------------------------------------------------------------------------------------*/
DWORD CPolyVirut::DecryptBuffer(DWORD dwOffSet, BYTE *pBuffer, DWORD *pTotalDecypt)
{
	DWORD	dwTempCount, dwBytesRead, dwPos, i, dwTemp;
	BYTE	bJumpWrittenCount, bCarry;

	*pTotalDecypt = 0x00;
	dwTempCount = m_dwVirusBody + 0x08;

	m_pMaxPEFile->ReadBuffer(pBuffer, dwOffSet, dwTempCount, 0, &dwBytesRead);
	if(m_dwVirusBody >= dwBytesRead)
	{
		delete [] pBuffer;
		pBuffer = NULL;
		return 2;
	}

	switch(m_dwOperation)
	{
		case 0x01://Ok
			dwPos = m_dwVirusBody + 0x04 ;
			for(i=0; i<dwPos; i+= 0x04)
				*((DWORD*)&pBuffer[i])= *((DWORD*)&pBuffer[i])+ m_dwKey;
			break;
		case 0x03://Ok
			dwPos = m_dwVirusBody + 0x04 ;
			for(i=0; i<dwPos; i+= 0x04)
				*((DWORD*)&pBuffer[i])= *((DWORD*)&pBuffer[i])- m_dwKey;
			break;

		case 0x06://ROL
			dwPos = m_dwVirusBody;
			for(i=0x00; i<(m_dwVirusBody+0x04); i+= 0x04)
			{
				dwTemp = *((DWORD*)&pBuffer[dwPos]);
				*((DWORD*)&pBuffer[dwPos])=((dwTemp<<m_dwKey)|(dwTemp>>(0x20-m_dwKey)));
				dwPos -= 0x04;
			}
			dwPos = m_dwVirusBody + 0x04;
			break;

		case 0x07://ROR
			dwPos = m_dwVirusBody + 0x04 ;
			for(i=0x00; i<dwPos; i +=0x04)
			{
				dwTemp = *((DWORD*)&pBuffer[i]);
				*((DWORD*)&pBuffer[i])=((dwTemp>>m_dwKey)|(dwTemp<<(0x20-m_dwKey)));
			}
			break;

		case 0x100://add word Ok
			dwPos = m_dwVirusBody + 0x02;
			for(i=0; i<dwPos; i+= 0x02)
				*((WORD*)&pBuffer[i])= *((WORD*)&pBuffer[i])+(WORD)m_dwKey;
			break;

		//Tushar ==> Added on 10 Nov 2010 for Handling of Virut.CF
        //Tushar ==> 26 Nov 2010 : Changes to Handle Negative Key e.g. 0xFF__
		case 0x101://Adc WORD
			//Tushar ==> 06 Dec 2010 : Replaced this case with new logic designed by Ajay
			dwPos = m_dwVirusBody;
			bJumpWrittenCount = 0x00;
			bCarry = 0x00;
			for(i=0x00; i<=m_dwVirusBody; i+=2, dwPos-=2)
			{
				if((*((WORD*)&pBuffer[dwPos])+(WORD)m_dwKey)>= 0xFFFF)
					bJumpWrittenCount = 0;

				*((WORD*)&pBuffer[dwPos])= *((WORD*)&pBuffer[dwPos])+(WORD)m_dwKey + bJumpWrittenCount;

				if((bCarry +(WORD)m_dwKey + bJumpWrittenCount)> 0xFFFF)
					bJumpWrittenCount = 0x01;
				else
					bJumpWrittenCount = 0x00;
			}
			dwPos = m_dwVirusBody +1;
			break;

		case 0x102://SUB word Ok
			dwPos = m_dwVirusBody + 0x02;
			for(i=0; i<dwPos; i+= 0x02)
				*((WORD*)&pBuffer[i])= *((WORD*)&pBuffer[i])-(WORD)m_dwKey;
			break;

        //Tushar ==> 26 Nov 2010 : Added for Handling SUB Instruction
		case 0x103://SBB WORD Ok
			dwPos = m_dwVirusBody /*+ 0x02 */;
			bJumpWrittenCount = 0x00;
			for(i=0x00; i<=m_dwVirusBody; i+=2, dwPos-=2)
			{
				bCarry = pBuffer[dwPos];

				*((WORD*)&pBuffer[dwPos])= *((WORD*)&pBuffer[dwPos])-(WORD)m_dwKey - bJumpWrittenCount;

				if((*((WORD*)&pBuffer[dwPos])-(WORD)m_dwKey)> 0xFFFF)
					bJumpWrittenCount = 0x01;
				else
					bJumpWrittenCount = 0x00;
			}

			dwPos = m_dwVirusBody +1;
			break;

		case 0x1000://Add BYTE Ok
			dwPos = m_dwVirusBody + 1;
			for(i=0x00; i<dwPos; i++)
				pBuffer[i] = pBuffer[i] +(BYTE)m_dwKey;
			break;

		case 0x1001://Adc BYTE Ok
			dwPos = m_dwVirusBody;
			bJumpWrittenCount = 0x00;
			for(i=0x00; i<=m_dwVirusBody; i++, dwPos--)
			{
				bCarry = pBuffer[dwPos];
				pBuffer[dwPos] = pBuffer[dwPos] +(BYTE)m_dwKey + bJumpWrittenCount;

				if((bCarry +(BYTE)m_dwKey + bJumpWrittenCount)> 0xFF)
					bJumpWrittenCount = 0x01;
				else
					bJumpWrittenCount = 0x00;
			}
			dwPos = m_dwVirusBody +1;
			break;

		case 0x1002://Sub BYTE Ok
			dwPos = m_dwVirusBody + 1;
			for(i=0x00; i<dwPos; i++)
				pBuffer[i] = pBuffer[i] -(BYTE)m_dwKey;
			break;

		case 0x1003://SBB BYTE Ok
			dwPos = m_dwVirusBody;
			bJumpWrittenCount = 0x00;
			for(i=0x00; i<=m_dwVirusBody; i++, dwPos--)
			{
				bCarry = pBuffer[dwPos];
				pBuffer[dwPos] = pBuffer[dwPos] -(BYTE)m_dwKey - bJumpWrittenCount;

				if(bCarry <((BYTE)m_dwKey + bJumpWrittenCount))
					bJumpWrittenCount = 0x01;
				else
					bJumpWrittenCount = 0x00;
			}
			dwPos = m_dwVirusBody +1;
			break;

		default:
			delete [] pBuffer;
			pBuffer = NULL;
			return 3;
	}

	*pTotalDecypt = dwPos;
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: NewGetSetJumpBytes
	In Parameters	: BOOL bWrite, DWORD dwPos, DWORD *dwFoundLoc
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Follows the JMP instruction is first set is not matched
--------------------------------------------------------------------------------------*/
int	CPolyVirut::NewGetSetJumpBytes(BOOL bWrite, DWORD dwPos, DWORD *dwFoundLoc)
{
	DWORD	i, dwBytesRead, dwTemp;
	char	bJumpWrittenCount;
	DWORD   dwTmpAepSecStart, dwTmpAepSecEnd, dwTmpFileOffset, dwTmpVar;

	dwTmpAepSecStart = dwTmpAepSecEnd = dwTmpFileOffset = dwTmpVar = 0x00;

	dwTmpAepSecStart = m_pSectionHeader[m_wAEPSec].VirtualAddress +  m_dwImageBase;
	dwTmpAepSecEnd = m_pSectionHeader[m_wAEPSec].VirtualAddress +  m_pSectionHeader[m_wAEPSec].Misc.VirtualSize + m_dwImageBase;

	*dwFoundLoc = 0x00;
	bJumpWrittenCount = 0x00;
	dwBytesRead = 0x00;
	
	for(i=0; i<dwPos; i++)
	{
		if(bJumpWrittenCount == 0x02)
		{
			return 0;
		}

		if(m_pbyBuff[i]==0xC6 && m_pbyBuff[i+1]==0x05)
		{
			dwTemp = *((DWORD*)&m_pbyBuff[i+2]);

			if((dwTemp > dwTmpAepSecStart)&&(dwTemp < dwTmpAepSecEnd))
			{
				dwTmpVar = m_pMaxPEFile->Rva2FileOffset(dwTemp -  m_dwImageBase, &dwTmpFileOffset);
				if(bWrite)
				{
					m_pMaxPEFile->WriteBuffer(&m_pbyBuff[i + 6], dwTmpFileOffset, 0x01);
				}
				else
				{
					m_dwJumpLocation = dwTmpFileOffset;
					m_dwKey = m_pbyBuff[i+6];
				}

				bJumpWrittenCount += 0x01;
				dwBytesRead = 0x01;
			}
		}

		if(m_pbyBuff[i]==0xC7 && m_pbyBuff[i+1]==0x05)
		{
			dwTemp = *((DWORD*)&m_pbyBuff[i+2]);
			if((dwTemp > dwTmpAepSecStart)&&(dwTemp < dwTmpAepSecEnd))
			{
				dwTmpVar = m_pMaxPEFile->Rva2FileOffset(dwTemp -  m_dwImageBase, &dwTmpFileOffset);
				if(bWrite)
				{
					m_pMaxPEFile->WriteBuffer(&m_pbyBuff[i + 6], dwTmpFileOffset, 0x04);
				}
				else
				{
					m_dwVirusExecStart = dwTmpFileOffset;
					m_dwOperation = *((DWORD*)&m_pbyBuff[i+6]);
					*dwFoundLoc = i; //manjunath
				}
				bJumpWrittenCount += 0x01;
			}

		}
	}
	return 1;
}


/*-------------------------------------------------------------------------------------
	Function		: IsValidVirusCode
	In Parameters	: DWORD dwVirusRva
	Out Parameters	: true if success esle false
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Validates the virus code instruction
					  Checks for zeroes in virus code
--------------------------------------------------------------------------------------*/
bool CPolyVirut::IsValidVirusCode(DWORD dwVirusRva)
{
	DWORD dwTmpVirusRva, dwTmpVirusOffset, dwTmpVirusCodeSec;
	
	dwTmpVirusRva = dwVirusRva -  m_dwImageBase;
	dwTmpVirusOffset = dwTmpVirusCodeSec = 0x00;
	dwTmpVirusCodeSec = m_pMaxPEFile->Rva2FileOffset(dwTmpVirusRva, &dwTmpVirusOffset);
	
	if((dwTmpVirusCodeSec == OUT_OF_FILE)||(dwTmpVirusOffset == 0x00))
		return false;

	if(!CheckForZeros(dwTmpVirusOffset, 0x30))
		return true;

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetVirutCEAEPEx_New
	In Parameters	: DWORD *dwVirusCodeOffset, DWORD *pOriginalAEP, DWORD dwCodeSec
	Out Parameters	: > 0 for success else 0
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Virut.ce Detection around AEP
					  Changed buffer passing to file handle. Required bytes will be read inside the function
					  Used if AEP in last section	
--------------------------------------------------------------------------------------*/
int	CPolyVirut::GetVirutCEAEPEx_New(DWORD *dwVirusCodeOffset, DWORD *pOriginalAEP, DWORD dwCodeSec)
{	
	m_objMaxDisassem.InitializeData();

	DWORD		dwOffSet, dwLength, dwTemp, dwImageBase, dwBase, dwBaseLocation, dwValue;
	DWORD		dwTempValue, dwVirusBase, dwBytesRead, dwNewReadOffset, dwReadOffSet, dwLastSecRVA, dwLastSecSRD, dwLastSecPRD;
	t_disasm	da;
	BYTE		B1, B2, B3;
	BYTE		bInstFound;
	int			iStg1, iStg2;
	BYTE		pBuffer[0x300] = {0};

	dwVirusBase = m_dwImageBase+m_dwAEPUnmapped;
	dwImageBase = *pOriginalAEP;
	dwReadOffSet = m_dwAEPMapped;

	*pOriginalAEP = dwBase = dwBaseLocation = dwValue = dwTempValue = dwTemp = dwBytesRead = dwNewReadOffset = 0x00;
	B1 = B2 = B3 = bInstFound = 0x00;
	iStg1 = iStg2 = 0;
	
	dwLastSecRVA = m_pSectionHeader[dwCodeSec - 1].VirtualAddress; 
	dwLastSecSRD = m_pSectionHeader[dwCodeSec - 1].SizeOfRawData;
	dwLastSecPRD = m_pSectionHeader[dwCodeSec - 1].PointerToRawData;

	if(!m_pMaxPEFile->ReadBuffer(pBuffer, dwReadOffSet, 0x300, 0, &dwBytesRead))
		return 1;

	m_dwInstCount = 0x00;
	dwOffSet = 0x00;
	while(dwOffSet < dwBytesRead - 2)
	{
		if(m_dwInstCount>100)
			return 3;

		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = pBuffer[dwOffSet];
		B2 = pBuffer[dwOffSet+1];
		B3 = pBuffer[dwOffSet+2];
		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&pBuffer[dwOffSet], 0x20, 0x400000, &da, DISASM_CODE);
		m_dwInstCount++;

		if(dwLength==0x01 && dwBase && bInstFound==0x02 &&(B1==0xC2 || B1==0xC3)&& strstr(da.result, "???"))
		{
			//dwOffSet = dwBaseLocation; //manju check this
			dwReadOffSet = dwBaseLocation;
			if(!m_pMaxPEFile->ReadBuffer(pBuffer, dwReadOffSet, 0x200, 0, &dwBytesRead))
				return 3;

			dwOffSet = 0x00;
			continue;
		}

		if(dwLength==0x02 && B1==0xEB && strstr(da.result, "JMP SHORT"))//|| strstr(da.result, "JB SHORT")))
		{
			if(B2 > 0x7F)
				dwOffSet = dwOffSet -(0x100 - B2)+ dwLength;
			else
				dwOffSet += dwLength + B2;

			//manjunath
			dwNewReadOffset = dwReadOffSet + dwOffSet;
			dwReadOffSet = dwNewReadOffset;

			if(!m_pMaxPEFile->ReadBuffer(pBuffer, dwReadOffSet, 0x200, 0, &dwBytesRead))
				return 3;
			
			dwOffSet = 0x00;
			//end

			continue;
		}

		
		if(dwLength==0x05 && B1==0xE9 && strstr(da.result, "JMP "))
		{
			dwTemp = *((DWORD*)&pBuffer[dwOffSet+1]);
			dwNewReadOffset = dwOffSet + dwLength + dwTemp;
			dwNewReadOffset += dwReadOffSet;

			//Check for negative value
			if(NEGATIVE_JUMP(dwNewReadOffset))
			{
				dwOffSet += dwLength;
				continue;
			}

			//Check Jump location going outside the last section(here AEP section is the last section)
			if((dwNewReadOffset < dwLastSecPRD)||(dwNewReadOffset >= (dwLastSecPRD + dwLastSecSRD)))
			{
				dwOffSet += dwLength;
				continue;
			}

			dwReadOffSet = dwNewReadOffset;

			if(!m_pMaxPEFile->ReadBuffer(pBuffer, dwReadOffSet, 0x200, 0, &dwBytesRead))
				return 3;
			
			dwOffSet = 0x00;
			continue;
		}

		//Manjunath. To handle Following Jump 
		//JMP DWORD PTR SS:[ARG.RETADDR] or JMP DWORD PTR SS:[ESP+20]
		//It returns to the location to the next instruction after CALL
		if(dwLength==0x04 && B1==0xFF && strstr(da.result, "JMP [ESP+")&& dwBase && dwBaseLocation)
		{
			dwReadOffSet = dwBaseLocation;

			if(!m_pMaxPEFile->ReadBuffer(pBuffer, dwBaseLocation, 0x200, 0, &dwBytesRead))
				return 3;
			
			dwOffSet = 0x00;
			continue;
		}
		//////////end

		    // 17122010 :- verify in case of bad results if this variable causes problem
		if(dwLength==0x05 && B1==0xE8 && dwBase==0x00 && strstr(da.result, "CALL "))
		{
			dwTemp = *((DWORD*)&pBuffer[dwOffSet+1]);
			dwNewReadOffset = dwOffSet + dwLength + dwTemp;
			dwNewReadOffset += dwReadOffSet;

			//Check for negative value
			if(NEGATIVE_JUMP(dwNewReadOffset))
			{
				dwOffSet += dwLength;
				continue;
			}

			//Check Call location going outside the last section
			if((dwNewReadOffset < dwLastSecPRD) ||(dwNewReadOffset >= (dwLastSecPRD + dwLastSecSRD)))
			{
				dwOffSet += dwLength;
				continue;
			}
			
			//Store the next instruction address after call(To return same sequence of instruction)
			dwBaseLocation = dwReadOffSet + dwOffSet + dwLength;

			//Virutal address of call instruction location + dwLength.(Used while calculating OAEP)
			dwBase = dwVirusBase +(dwNewReadOffset - m_dwAEPMapped)- dwTemp;

			dwReadOffSet = dwNewReadOffset;

			if(!m_pMaxPEFile->ReadBuffer(pBuffer, dwReadOffSet, 0x200, 0, &dwBytesRead))
				return 3;
						
			dwOffSet = 0x00;
			continue;
		}

		//searching AEP
		if(dwBase)
		{
			if(dwLength==0x05 && strstr(da.result, "PUSH "))
			{
				dwValue = *((DWORD*)&pBuffer[dwOffSet+1]);

				if(dwValue < dwImageBase && dwValue >(dwImageBase + dwLastSecRVA + dwLastSecSRD))
				{
						dwValue = 0x00;
				}
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x04 && B2==0x74 && B3==0x24 && strstr(da.result, "PUSH DWORD PTR [ESP+"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if((dwLength==0x04 || dwLength==0x03)&& dwValue && strstr(da.result, "POP DWORD PTR ["))
			{
				if(dwValue >= dwVirusBase)
				{
					dwOffSet += dwLength;
					continue;
				}

				*pOriginalAEP = dwValue;
				break;
			}

			if(dwLength==0x08 && B1==0xC7 && B2==0x44 && B3==0x24 && bInstFound && strstr(da.result, "MOV DWORD PTR [ESP+"))
			{
				dwValue = *((DWORD*)&pBuffer[dwOffSet+4]);
				if((dwValue > dwImageBase)&&(dwValue <(dwImageBase + dwLastSecRVA + dwLastSecSRD)))
				{
					bInstFound = 0x02;
				}
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength==0x06 && B1==0x8D && B2==0x9B && bInstFound==0x02 && strstr(da.result, "[EBX-100]"))
			{
				*pOriginalAEP = dwValue;
				break;
			}
			//Tushar ==> 09 Dec 2010 : Iexplore sample shows "MOV EBP"(which makes 'bInstFound=0x01')after "ADD EAX" hence 0x02 changes to 0x01. Hence XCHG fails and so Cleaning fails. Hance, this inst placed before MOV EBP
			if(dwLength==0x03 && B1==0x87 && B2==0x43 && bInstFound==0x02 && strstr(da.result, "XCHG [")&& strstr(da.result, "],EAX"))
			{
				*pOriginalAEP = dwValue;
				dwOffSet += dwLength;
				break;
			}

			if((dwLength==0x03||dwLength==0x04)&& B1==0x8B &&(B2==0x2C||B2==0x6C)&& B3==0x24 && strstr(da.result, "MOV EBP,["))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}

			//In this inst, the OEP with IamgeBase value is directly saved in dwValue var.
			if(dwLength==0x05 && B1==0xBD && strstr(da.result, "MOV EBP,"))
			{
				//15122010 : To avoid change of value in dwValue var as it is the OriAEP val if below condition is true.
				if(bInstFound == 0x02)
				{
					dwOffSet += dwLength;
					continue;
				}

				dwValue = *((DWORD*)&pBuffer[dwOffSet+1]);
				bInstFound = 0x01;
				dwOffSet += dwLength;
				//31122010 :- To handle special case in which during detection garbage ADD EBX inst is found and which overwrites the OEP in dwValue saved in this inst..
				iStg1 = 1;
				continue;
			}
			if(dwLength==0x07 && B1==0xC7 && B2==0x43 && bInstFound && strstr(da.result, "MOV DWORD PTR ["))
			{
				*pOriginalAEP = *((DWORD*)&pBuffer[dwOffSet+3]);
				break;
			}
			if(dwLength==0x08 && B1==0x81 && B2==0x44 && B3==0x24 && bInstFound && strstr(da.result, "ADD DWORD PTR [ESP+"))
			{
				dwValue = *((DWORD*)&pBuffer[dwOffSet+4]);
				*pOriginalAEP = dwValue + dwBase;
				break;
			}

			//Spl Case for XCHNG
			if(dwLength==0x03 && B1==0x83 && B2==0xC3 && bInstFound && dwValue && strstr(da.result, "ADD EBX,"))//manjunath 17 May 2011
			{
				*pOriginalAEP = dwValue + dwBase;
				break;
			}
			//Spl Case for XCHNG
			if(dwLength==0x06 && B1==0x81 && B2==0xEB && bInstFound && strstr(da.result, "SUB EBX,"))
			{
				if((dwValue & dwVirusBase)&& !(dwValue&0xF0000000))
				{
					*pOriginalAEP = dwValue;
					break;
				}

				if((dwValue > dwImageBase)&&(dwValue < 0xF0000000))
				{
					*pOriginalAEP = dwValue;
					break;
				}

				if((dwValue&0xF0000000)== 0xF0000000)
				{
					*pOriginalAEP = dwValue + dwBase;
					break;
				}

				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x04 && B1==0x87 && B2==0x6C && B3==0x24 && bInstFound && strstr(da.result, "XCHG [ESP+"))
			{
				//Tushar ==> 06 Dec 2010 : Added by Ajay(inner if condition will skip if bInstFound != 0x02. i.e not the earlier req inst are found. This condition was used to handle scapegoat samples with -ve keys and ADC inst.)
				if((dwLength==0x03 || dwLength==0x04)&& B1==0x87 &&(B2==0x6B || B2==0x6C)&& bInstFound==0x02 && strstr(da.result, "XCHG [")&& strstr(da.result, "],EBP"))
				{
					*pOriginalAEP = dwValue + dwBase;
					dwOffSet += dwLength;		//changed for 1366BD35.EXE double infection // this cause a problem for df ui so i delete the comment da8dcd49.exe
					break;
				}

				bInstFound = 0x02;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength==0x04 && B1==0x11 && B2==0x6C && B3==0x24 && bInstFound && strstr(da.result, "ADC [ESP+"))//||strstr(da.result, "ADD [ESP+")))
			{
				*pOriginalAEP = dwValue + dwBase;
				break;
			}

			if((dwLength==0x03||dwLength==0x02)&& B1==0x01 &&(B2==0x69||B2==0x6B||B2==0x2B)&& bInstFound==0x02 && strstr(da.result, "ADD [")&& strstr(da.result, "],EBP"))
			{
				//03012011 :- To handle false detection encountered in other inst.. which skipped correct detection in this inst...
				if(dwTempValue)
				{
					*pOriginalAEP = dwTempValue + dwBase;
					if(*pOriginalAEP <(m_dwImageBase + dwLastSecRVA + dwLastSecSRD))
					{
						break;
					}
				}

				*pOriginalAEP = dwValue + dwBase;
				break;
			}

			if(dwLength==0x03 && B1==0x0F && B2==0xC1 && bInstFound==0x02 && strstr(da.result, "XADD [")&& strstr(da.result, "],EBP"))
			{
				*pOriginalAEP = dwValue + dwBase;
				break;
			}

			if(dwLength==0x02 && B1==0x33 && B2==0xED && strstr(da.result, "XOR EBP,EBP"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength==0x03 && B1==0x83 && B2==0xE5 && strstr(da.result, "AND EBP,"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength==0x02 && B1==0x2B && B2==0xED && strstr(da.result, "SUB EBP,EBP"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x02 && B1==0x2B && B2==0xC0 && strstr(da.result, "SUB EAX,EAX"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x06 && B1==0x81 && B2==0xED && bInstFound && strstr(da.result, "SUB EBP,"))
			{
				*pOriginalAEP = 0x00 - *((DWORD*)&pBuffer[dwOffSet+2]);
				if(NEGATIVE_JUMP(*pOriginalAEP))//manjunath 19 May 2011. Chek for negative OAEP
				{
					*pOriginalAEP = 0x00;
					continue;
				}
				break;
			}

			if(dwLength==0x06 && B1==0x81 && B2==0xCD && bInstFound && strstr(da.result, "OR EBP,"))
			{
				dwValue = *((DWORD*)&pBuffer[dwOffSet+2]);
				bInstFound = 0x02;
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x06 && B1==0x81 && B2==0xC5 && bInstFound && strstr(da.result, "ADD EBP,"))
			{
				dwValue = *((DWORD*)&pBuffer[dwOffSet+2]);
				bInstFound = 0x02;
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x05 && B1==0x05 && bInstFound && strstr(da.result, "ADD EAX,"))
			{
				//30122010 :- To handle situation in which OEP is already obts in dwValue through "MOV DWORD PTR [ESP+" inst but 
				//			  not yet saved in "*pOriginalAEP" var as the final stage "[EBX-100]" inst has not yet been met. And before that Current inst changes the value of OriAEP saved in dwValue
				//			  sample name for below condition : 91761491.exe 
				if(bInstFound == 0x02)
				{
					dwOffSet += dwLength;
					continue;
				}

				//31122010 :- To verify if OEP is saved from MOV EBP,OEPDWord(iStg1)and XCHG ,EBP is also met. Thus avoiding overwritting value of OEP saved in before inst.
				if(iStg2)
				{
					bInstFound = 0x02;
					dwOffSet += dwLength;
					continue;
				}

				//03012011 :- To avoid overwritting of OEP saved in dwValue var by DWord found in garbage ADD EAX inst...
				if(dwValue)
				{
					dwTempValue = *((DWORD*)&pBuffer[dwOffSet+1]);
					if((dwTempValue>dwValue)&&(dwTempValue >(dwLastSecRVA + dwLastSecSRD))) //DWord val not in address range of file. so dont save this dword.
					{
						dwOffSet += dwLength;
						continue;
					}
				}

				dwValue = *((DWORD*)&pBuffer[dwOffSet+1]);
				bInstFound = 0x02;
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x06 && B1==0x81 && B2==0xF5 && bInstFound && strstr(da.result, "XOR EBP,"))
			{
				//17122010 :- To avoid change of value of bInstFound in case Garbage inst is encountered here after Req is already found. In already found case bInstFound will be equal to 0x02
				if(bInstFound==0x02)
				{
					//03012011 :- To handle overcomming of a detection which is actually false. And this inst with next XCHG is true detection...
					dwTempValue = *((DWORD*)&pBuffer[dwOffSet+2]);

					dwOffSet += dwLength;
					continue;
				}

				//15122010
				dwValue = *((DWORD*)&pBuffer[dwOffSet+2]);   //Restored from dwOffSet+1 to dwOffSet+2
				bInstFound += 0x01;
				dwOffSet += dwLength;

				continue;
			}

			//iStg1=1 is done when OEP is found in MOV EBP,OEPDWord.
			if(dwLength==0x03 && B1==0x87 && B2==0x6B &&(bInstFound==0x02 || iStg1==1)&& strstr(da.result, "XCHG [")&& strstr(da.result, "],EBP"))
			{
				//31122010 :- To identify MOV EBP,OEPDWord inst is found and Current inst is second stage. Waiting for "spl case for XCHG inst". 
				//In Below condition iStg2 set true is used in ADD EAX inst to verify and to avoid overwritting of OEP saved in dwValue var. 
				if(iStg1==1)
				{
					iStg2=1;
					dwOffSet += dwLength;
					continue;
				}

				*pOriginalAEP = dwValue;

				//29122010 :-	To handle case in which OEP is calculated using both i.e Addr obtd after CALL inst and value in XOR etc inst ... 
				//				This case can be identified when the dwValue will be NEGATIVE.
				if((dwValue & 0xF0000000)== 0xF0000000)
				{
					*pOriginalAEP = dwValue + dwBase;
				}

				//03012011 :- To handle overcomming of a detection which is actually false. And this inst with earlier XOR EBP inst is true detection...
				if(dwTempValue &&(dwTempValue & 0xF0000000)==0xF0000000)
				{
					*pOriginalAEP = dwTempValue + dwBase;
				}


				dwOffSet += dwLength;
				//continue;
				break;
			}

			if(dwLength==0x08 && B1==0x81 && B2==0x6C && B3==0x24 && bInstFound && strstr(da.result, "SUB DWORD PTR [ESP+"))
			{
				*pOriginalAEP = dwBase - *((DWORD*)&pBuffer[dwOffSet+4]);
				break;
			}
			//manjunath 17 May 2011 for instruction like
			//816B 13 E6970000     SUB DWORD PTR DS:[EBX+13], 97E6
			if(dwLength==0x07 && B1==0x81 &&((B2 >= 0x68)&&(B2 <= 0x6B))&& bInstFound && strstr(da.result, "SUB DWORD PTR [E")&& strstr(da.result, "+"))
			{
				*pOriginalAEP = dwBase - *((DWORD*)&pBuffer[dwOffSet+3]);
				break;
			}
			///end
			if(dwLength==0x08 && B1==0x81 && B2==0x74 && B3==0x24 && bInstFound && strstr(da.result, "XOR DWORD PTR [ESP+"))
			{
				*pOriginalAEP = dwBase ^ *((DWORD*)&pBuffer[dwOffSet+4]);
				break;
			}

			if(dwLength==0x04 && B1==0x01 && B2==0x6C && B3==0x24 && bInstFound==0x02 && dwValue && strstr(da.result, "ADD [ESP+")&& strstr(da.result, "],EBP"))
			{
				*pOriginalAEP = dwBase  + dwValue;
				break;
			}

			if(dwLength==0x04 && B1==0xFF && B2==0x64 && B3==0x24 && strstr(da.result, "JMP [ESP+"))
			{
				bInstFound++;
				//dwOffSet = dwBaseLocation; //manju check this
				if(!m_pMaxPEFile->ReadBuffer(pBuffer, dwBaseLocation, 0x200, 0, &dwBytesRead))
					return 3;
				dwOffSet = 0x00;
				continue;
			}
			if(dwLength==0x02 && B1==0xFF && B2==0xE5 && bInstFound==0x02 && dwValue && strstr(da.result, "JMP E"))
			{
				*pOriginalAEP = dwBase  + dwValue;
				break;
			}
			if((dwLength==0x04||dwLength==0x05)&& B1==0x0F && B2==0xC1 && bInstFound && strstr(da.result, "XADD [")&& strstr(da.result, "],EBP"))
			{
				*pOriginalAEP = dwBase  + dwValue;
				break;
			}
		}
		dwOffSet += dwLength;
	}

	if(dwOffSet >= 0x3000)
		return 1;

	if(NEGATIVE_JUMP(*pOriginalAEP))//manjunath 19 May 2011. Chek for negative OAEP
		return 2;

	*dwVirusCodeOffset = dwReadOffSet;

	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: GetVirutCEParamEx
	In Parameters	: DWORD *dwVirusCodeOffset, DWORD *pOriginalAEP, DWORD dwCodeSec
	Out Parameters	: > 0 for success else 0
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Virut.ce Detection around AEP
--------------------------------------------------------------------------------------*/
int	CPolyVirut::GetVirutCEParamEx(DWORD dwJumpOffset, DWORD *pJumpOffSet, int iBufIndex=0)
{
	m_objMaxDisassem.InitializeData();
	t_disasm	da;

	BYTE	B1, B2, B3, B4, B5; // B5 - 16 Nov 2010 to indicate and break while loop when jump encountered in last section.
	BYTE	bBuffer[0x300] = {0};

	DWORD	dwOffSet, dwRvaOffSet, dwReadOffSet, dwLocation, dwTemp, dwBytesRead;
	DWORD	dwLength, dwJmpLocation, dwE9Location, dwImageBase, dwLastSecVirSize;
	DWORD   dwTempJmpOffset=0;
	int		i1stJmpFlag=0;
	DWORD	dwAEPSecRVA	= m_pSectionHeader[m_wAEPSec].VirtualAddress;
	DWORD	dwAEPSecVirtualSize	= m_pSectionHeader[m_wAEPSec].Misc.VirtualSize;
	DWORD   dwAEP = m_dwAEPUnmapped;
	DWORD	dwLastSecRVA, dwLastSecVS;

	B1 = B2 = B4 = B3 = B5 = 0x00;
	dwE9Location = dwJmpLocation = dwOffSet = dwBytesRead = dwTemp = dwLocation = 0x00;

	dwLastSecRVA = m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress;
	dwLastSecVS = m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize; 
	dwLastSecVirSize = m_dwVirusBody;
	dwReadOffSet = dwJumpOffset;
	dwImageBase = m_dwVirusExecStart;
	dwRvaOffSet = m_dwVirusRva;

	int istg1=0, istg2=0, istg3=0, istg4=0, istg5=0; //istg var added on 12 Nov 2010 to verify detection pattern of virut.ce met. 
	int index=0, iInJmpFound=0 ,iMovCntFound=0 , iInsideJmpCnt=0; 

	m_dwKey = m_dwOperation = 0x00;
	m_dwVirusExecStart = m_dwVirusBody = m_dwVirusRva = 0x00;

	char *szReqReg1, *szReqReg2, szReqReg3[4], szReqReg4[4];

	if(!m_pMaxPEFile->ReadBuffer(bBuffer, dwReadOffSet, 0x300, 0, &dwBytesRead))
		return 1;

	DWORD dwFlagForNewVariant=0, dwLastSecJmpOffset=0; 

	m_dwInstCount = 0x00;

	dwTemp = 0x00;
	while(dwOffSet < dwBytesRead - 2)
	{
		if(B3 > 0x18)      // value changed from 0x07 to 0x0A to 0x18 on 10 Nov 2010 to handle any invaid or valid jumps till count 0x18 to avoid breaking of loop before a required jump is found.
			return 2;  

		if(m_dwInstCount>500)  // value changed from 200 to 500 on 10 Nov 2010 as jump to be found in buffer of size 5000 read fails due to instruction count exceeding earlier value of 200
			return 3;
		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = *((BYTE*)&bBuffer[dwOffSet]);
		B2 = *((BYTE*)&bBuffer[dwOffSet+1]);

		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)bBuffer+dwOffSet, 0x20, 0x400000, &da, DISASM_CODE);
		m_dwInstCount++;

		if(dwLength==0x01 && _strcmpi(da.dump, "FFFFFFC3")== 0)
		{
			dwOffSet += dwLength;
			continue;
		}

		//searching Last Jump to get Virus exectuion start
		if(dwLength==0x06 && B4==0x01 && B1==0x0F && B2==0x82 && strstr(da.result, "JB "))
		{
			B4 = 0x02;
			dwOffSet += dwLength;
			continue;
		}
		if(dwLength==0x02 && B4==0x01 &&(B1==0x72||B1==0x73||B1==0x77||B1==0x79||B1==0x7F)&&(strstr(da.result, "JB SHORT ")||strstr(da.result, "JG SHORT ")||strstr(da.result, "JNB SHORT ")||strstr(da.result, "JNS SHORT ")||strstr(da.result, "JA SHORT ")))
		{
			B4 = 0x02;
			dwOffSet += dwLength;
			continue;
		}
		if(dwLength==0x06 && B4==0x01 && B1==0x0F &&(B2==0x83||B2==0x87||B2==0x89||B2==0x8F)&&(strstr(da.result, "JNB ")||strstr(da.result, "JNS ")||strstr(da.result, "JG ")||strstr(da.result, "JA ")))
		{
			B4 = 0x02;
			dwOffSet += dwLength;
			continue;
		}

		if(dwLength==0x02 && B1==0xEB && strstr(da.result, "JMP SHORT"))//|| strstr(da.result, "JB SHORT")))
		{
			B3++;               //added on 10 Nov 2010. actually just replaced from end of function to the start of it.

			if(B2 > 0x7F)
			{
				dwOffSet = dwOffSet -(0x100 - B2)+ dwLength;

				if(!dwJmpLocation)				//Tracing Exact E9 Location
					dwE9Location += dwOffSet;

				dwRvaOffSet += dwOffSet;
				dwOffSet += dwReadOffSet;
			}
			else
			{
				dwOffSet += dwLength + B2;

				if(!dwJmpLocation)				//Tracing Exact E9 Location
					dwE9Location += dwOffSet;

				dwRvaOffSet += dwOffSet;
				dwOffSet += dwReadOffSet;
			}

			//09122010 : To handle the correct return value for dwJmpLocation = iBuffIndex, in case of MOV REG,DWORD inst after JMP found in Buffer of 0x3000
			// Note : This case also seperates the dwVirusBody value which can obtained by either MOV or PUSH inst...............
			if(iMovCntFound && !istg1 && !istg2 && !dwJmpLocation)
			{
				dwJmpLocation = iBufIndex;
			}


			dwReadOffSet = dwOffSet;

			if(!m_pMaxPEFile->ReadBuffer(bBuffer, dwOffSet, 0x200, 0, &dwBytesRead))
				return 1;

			dwOffSet = 0x00;
			continue;
		}
		if(dwLength==0x05 && B1==0xE9 && strstr(da.result, "JMP "))
		{

			//09122010 : To indicate 1 jmp has been met. So MOV inst after this is found only after JMP. So Push/Pop and iStg's and other logics skipped in detection of this type of sample.
			if(!(i1stJmpFlag))
				i1stJmpFlag = 1;

			iInsideJmpCnt += 1;

			B3++;       //added on 10 Nov 2010

			//Tushar ==> 06 Dec 2010 : Added this condition for Handling case of : First JUMP points to INIT code
			if(m_dwVirusBody  >= 0x4000 && m_dwVirusBody < 0x7000  && m_dwKey && m_dwOperation && !dwJmpLocation && iBufIndex != 0x00 &&(B4 == 0x02 ||(istg1 == 1 && istg2 == 1 && istg3 == 1 && istg4 == 1)))
				dwJmpLocation = iBufIndex;

			//Tushar ==> 06 Dec 2010 : Ajay to handle Direct PUSH & POP Encountered after 'E9' found in Buff 0f 0x5000 to return correct dwJmpLocation
			if(m_dwVirusBody  >= 0x4000 && m_dwVirusBody < 0x7000  && !dwJmpLocation && iBufIndex != 0x00 && istg1 == 1 && istg2 == 1)
				dwJmpLocation = iBufIndex;

			//13122010 : To handle the correct return value for dwJmpLocation = iBuffIndex, in case of MOV REG,DWORD inst after JMP found in Buffer of 0x3000
			//Note : This case also seperates the dwVirusBody value which can obtained by either MOV or PUSH inst...............
			if(iMovCntFound && !istg1 && !istg2 && !dwJmpLocation)
				dwJmpLocation = iBufIndex;

			//Tushar ==> 06 Dec 2010 : Added this condition for Handling case of : Sequence of Multiple JUMP Sequences points to INIT code
			// if-else added on 10 nov 2010 to get proper value of offset of required jump instruction(for Decryption loop)from AEP
			if(!dwJmpLocation  &&  iBufIndex==0)   
				dwJmpLocation = dwE9Location + dwOffSet;
			else if(!dwJmpLocation)//added on 10 Nov 2010	
				dwJmpLocation = /*dwE9Location +*/ dwRvaOffSet - dwAEP + dwOffSet;  //Tushar ==> 09 Dec 2010 : 

			//27122010 : To handle the case in which 1st jmp takes to 2nd jmp and then 2nd jmp takes to InitCode
			//iInsideJmpCnt var is used to indicate the number of times an 'E9' has been encountered in this loop of 0x300 bytes.
			if(dwJmpLocation && i1stJmpFlag && !istg1 && !istg2 && !iMovCntFound && !m_dwVirusBody && iBufIndex!=0 && iInsideJmpCnt>1)
				//break;
				dwJmpLocation = dwRvaOffSet - dwAEP + dwOffSet;

			/////////////  i1stJmpFlag is a global/member var. so use local var here, if convinient for better results.......

			//added on 12 Nov 2010
			dwTempJmpOffset =  dwRvaOffSet - dwAEP + dwOffSet;

			dwTemp = *((DWORD*)&bBuffer[dwOffSet+1]);
			dwOffSet += dwLength + dwTemp;
			dwRvaOffSet += dwOffSet;
			dwOffSet += dwReadOffSet;
			dwReadOffSet = dwOffSet;

			if(B4 == 0x02)
			{
				dwOffSet = 0x00;
				m_dwVirusExecStart = dwRvaOffSet;
				break;
			}

			m_pMaxPEFile->ReadBuffer(bBuffer, dwOffSet, 0x200, 0, &dwBytesRead);			
			if((!(dwTemp & 0x80000000)) && dwBytesRead != 0x00 && dwRvaOffSet>dwAEPSecRVA && dwRvaOffSet<dwAEPSecVirtualSize + dwAEPSecRVA)// && dwTemp > 0x1000)
			{
				dwFlagForNewVariant = 0x01;
			}
			if(dwRvaOffSet >(dwAEPSecVirtualSize + dwAEPSecRVA)&& istg1 && istg2 && istg3 && istg4 &&(!(dwTemp & 0x80000000)))
			{
				dwLastSecJmpOffset = dwRvaOffSet;
				B5 = 0x1;
				break;
			}

			dwOffSet = 0x00;
			continue;
		}

		//Getting Counter
		if(dwLength==0x05 && strstr(da.result, "MOV "))
		{
			dwTemp = *((DWORD*)&bBuffer[dwOffSet+1]);
			if(dwTemp >= 0x4000 && dwTemp < 0x5000)//Tushar ==> 09 Dec 2010 : Extended if condition
			{
				m_dwVirusBody = dwTemp;
				//Tushar ==> 08 Dec 2010 : To Fill Init Code with Zeros.
				m_dwInitCodeRVA = dwRvaOffSet;

				//15122010   //09122010 : To handle the correct return value for dwJmpLocation = iBuffIndex, in case of MOV REG,DWORD inst after JMP found in Buffer of 0x3000
				// Note : This case also seperates the dwVirusBody value which can be obtained by either MOV or PUSH inst...............
				if(!iInJmpFound)
					iMovCntFound = 1;
			}


		}
		if(dwLength==0x05 && strstr(da.result, "PUSH "))
		{
			dwTemp = *((DWORD*)&bBuffer[dwOffSet+1]);

			if(dwTemp >= 0x4000 && dwTemp < 0x7000)// changed from 0x5000 to 0x7000 on 11 Nov 2010
			{
				//Tushar ==> 06 Dec 2010 : Added following Checks
				istg1 = 1;
				istg2 = 0x0;
				istg3 = 0x0;
				istg4 = 0x0;
				/**************************************************/
				m_dwVirusBody = dwTemp;

				//Tushar ==> 08 Dec 2010 : To Fill Init Code with Zeros.
				m_dwInitCodeRVA = dwRvaOffSet; 
			}
		}

		// added on 12 nov 2010 to verify 2nd stage of 4 stages of generic virut.ce detection pattern met.
		if(dwLength==0x01 && strstr(da.result, "POP ")&& istg1==1 && istg2==0 && istg3==0 && istg4==0 && istg5==0)
		{
			istg2 = 1; 
			//Tushar ==> 06 Dec 2010 : Added these initialization
			istg3 = 0x00;
			istg4 = 0x00;

			szReqReg1 = strstr(da.result, "E");
			if(szReqReg1)
			{
				for(index=0; index<3; index++)
				{
					szReqReg3[index] = szReqReg1[index];
				}
				szReqReg3[index]='\0';
			}			
		}

		// 16 Nov 2010 to verify 4th stage of 4 stages of generic virut.ce detection pattern met.
		if(dwLength==0x03 && strstr(da.result, "SUB ")&& istg1==1 && istg2==1 && istg3==1 && istg4==0 && istg5==0)
		{
			szReqReg2 = strstr(da.result, "E");
			if(szReqReg2)
			{
				for(index=0; index<3; index++)
				{
					szReqReg4[index] = szReqReg2[index];
				}
				szReqReg4[index]='\0';
			}
			if(!strcmp(szReqReg4,szReqReg3))
				istg4 = 1;
		}

		if(dwLength==0x07 && B1==0xC1 && B2>=0x80 && B2<=0x83 && strstr(da.result, "ROL DWORD PTR [")!=NULL)
		{
			istg3 = 1;
			dwTemp = *((DWORD*)&bBuffer[dwOffSet+2]);
			// Modified by Rupali on 31-12-2010. Checking the address in the valid region is enough. 
			// and operation with dwImagebase gives incorrect results in case of large files.
			// Adding dwLastSecRVA to get the correct Max Valid address range. 
			if((dwTemp > dwImageBase)&&(dwTemp <(dwImageBase + dwLastSecRVA + dwLastSecVirSize)))
			{
				m_dwVirusRva = dwTemp;
				m_dwKey = *((BYTE*)&bBuffer[dwOffSet+6]);
				m_dwOperation = 0x06;

				B4 = 0x01;
			}
			dwOffSet += dwLength;
			continue;
		}

		if(dwLength==0x07 && B1==0xC1 && B2>=0x88 && B2<=0x8C && strstr(da.result, "ROR DWORD PTR [")!=NULL)
		{
			istg3 = 1;
			m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+2]);
			m_dwKey = *((BYTE*)&bBuffer[dwOffSet+6]);
			m_dwOperation = 0x07;

			B4 = 0x01;
		}

		if(dwLength==0x0A && B1==0x81 && B2>=0x80 && B2<=0x83 && strstr(da.result, "ADD DWORD PTR [")!=NULL)
		{
			istg3 = 1;
			m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+2]);
			m_dwKey = *((DWORD*)&bBuffer[dwOffSet+6]);
			m_dwOperation = 0x01;

			B4 = 0x01;
		}

		if(dwLength==0x0A && B1==0x81 && B2>=0xA8 && B2<=0xAB && strstr(da.result, "SUB DWORD PTR [")!=NULL)
		{
			istg3 = 1;
			m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+2]);
			m_dwKey = *((DWORD*)&bBuffer[dwOffSet+6]);
			m_dwOperation = 0x03;

			B4 = 0x01;
		}
		if(dwLength==0x0A && B1==0x81 && B2>=0x80 && B2<=0x83 && strstr(da.result, "XOR DWORD PTR [")!=NULL)
		{
			istg3 = 1;
			m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+2]);
			m_dwKey = *((DWORD*)&bBuffer[dwOffSet+6]);
			m_dwOperation = 0x05;

			B4 = 0x01;
		}

		if(dwLength==0x09 && B1==0x66 && B2>=0x81 && strstr(da.result, "ADD WORD PTR [")!=NULL)
		{
			istg3 = 1;
			m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+3]);
			m_dwKey = *((WORD*)&bBuffer[dwOffSet+7]);
			m_dwOperation = 0x100;

			B4 = 0x01;
		}

		//Added on 03 Nov 2010 for Handling new Variant of Virut.CF
		if(dwLength==0x09 && B1==0x66 && B2>=0x81 && strstr(da.result, "ADC WORD PTR [")!=NULL)
		{
			istg3 = 1; 
			m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+3]);
			m_dwKey = *((WORD*)&bBuffer[dwOffSet+7]);
			m_dwOperation = 0x101;

			B4 = 0x01;
		}

		if(dwLength==0x09 && B1==0x66 && B2>=0x81 && strstr(da.result, "SUB WORD PTR [")!=NULL)
		{
			istg3 = 1;
			m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+3]);
			m_dwKey = *((WORD*)&bBuffer[dwOffSet+7]);
			m_dwOperation = 0x102;

			B4 = 0x01;
		}

		if(dwLength==0x09 && B1==0x66 && B2>=0x81 && strstr(da.result, "SBB WORD PTR [")!=NULL)
		{
			istg3 = 1;
			m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+3]);
			m_dwKey = *((WORD*)&bBuffer[dwOffSet+7]);
			m_dwOperation = 0x103;

			B4 = 0x01;
		}

		if(dwLength==0x07 && B1==0x80 && B2>=0x7F && B2<=0x82 && strstr(da.result, "ADD BYTE PTR [")!=NULL)
		{
			istg3 = 1;
			dwTemp = *((DWORD*)&bBuffer[dwOffSet+2]);
			//31122010 :- Added by Rupali to avoid issues due to ImageBase calculation
			//if(((dwTemp&dwImageBase)==dwImageBase)&& dwTemp<(dwImageBase+dwLastSecVirSize))
			if((dwTemp > dwImageBase)&&(dwTemp <(dwImageBase + dwLastSecRVA + dwLastSecVirSize)))
			{
				m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+2]);
				m_dwKey = bBuffer[dwOffSet+6];
				m_dwOperation = 0x1000;

				B4 = 0x01;
			}
			else
				dwTemp = 0x00;
		}

		if(dwLength==0x07 && B1==0x80 && B2>=0x8F && B2<=0x92 && strstr(da.result, "ADC BYTE PTR [")!=NULL)
		{
			istg3 = 1;
			m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+2]);
			m_dwKey = bBuffer[dwOffSet+6];
			m_dwOperation = 0x1001;

			B4 = 0x01;
		}

		if(dwLength==0x07 && B1==0x80 && B2>=0xA8 && B2<=0xAB && strstr(da.result, "SUB BYTE PTR [")!=NULL)
		{
			istg3 = 1;
			m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+2]);
			m_dwKey = bBuffer[dwOffSet+6];
			m_dwOperation = 0x1002;

			B4 = 0x01;
		}

		if(dwLength==0x07 && B1==0x80 && B2>=0x97 && B2<=0x9A && strstr(da.result, "SBB BYTE PTR [")!=NULL)
		{
			istg3 = 1;
			m_dwVirusRva = *((DWORD*)&bBuffer[dwOffSet+2]);
			m_dwKey = bBuffer[dwOffSet+6];
			m_dwOperation = 0x1003;

			B4 = 0x01;
		}

		dwOffSet += dwLength;
	}

	// by Adnan 16 Nov 2010 to handle type 2 & type 5 after above checks fail in case of istg
	//Tushar ==> 06 Dec 2010 : Commented Second and THird condition to reduce redundancy 
	if((B5 == 0x01))//&&(dwOperation == 0x101 || dwOperation == 0x103))
	{
		*pJumpOffSet = dwJmpLocation;
		//Tushar ==> 06 Dec 2010 : Added this condition and commented next if loop
		m_dwVirusExecStart = dwRvaOffSet;

		return 0x00; //Tushar ==> 06 Dec 2010 : Also changed the return Type
	}

	if(B4 != 0x02)
		return 3;

	if(m_dwVirusBody<0x4000 || m_dwVirusExecStart<dwJumpOffset)
		return 4;

	if(pJumpOffSet)
		*pJumpOffSet = dwJmpLocation;

	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: GetVirutCEAEPEx
	In Parameters	: DWORD dwSize, DWORD dwExecStart, DWORD dwVirusBase, DWORD *pOriginalAEP
	Out Parameters	: > 0 for success else 0
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Virut.ce Detection around AEP
--------------------------------------------------------------------------------------*/
int	CPolyVirut::GetVirutCEAEPEx(DWORD dwSize, DWORD dwExecStart, DWORD dwVirusBase, DWORD *pOriginalAEP)
{
	m_objMaxDisassem.InitializeData();

	DWORD		dwOffSet, dwLength, dwTemp, dwImageBase;
	DWORD		dwBase, dwBaseLocation, dwValue;
	t_disasm	da;
	BYTE		B1, B2, B3;
	BYTE		bInstFound;
	DWORD		dwTempValue = 0x00; //Tushar => 06 Dec 2010 : Newly Added
	DWORD		dwLastSecSRD, dwLastSecRVA;

	dwLastSecSRD = m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
	dwLastSecRVA = m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress;

	dwImageBase = m_dwImageBase;
	*pOriginalAEP = dwBase = dwBaseLocation = dwValue = dwTempValue = dwTemp = 0x00;
	B1 = B2 = B3 = bInstFound = 0x00;
	int iStg1=0, iStg2=0;

	m_dwInstCount = 0x00;
	dwOffSet = dwExecStart;
	while(dwOffSet < dwSize - 2)
	{
		if(m_dwInstCount>100)
			return 3;

		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = m_pbyBuff[dwOffSet];
		B2 = m_pbyBuff[dwOffSet+1];
		B3 = m_pbyBuff[dwOffSet+2];
		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1==0xC1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x03;
			continue;
		}
		if(B1==0xD1 &&(B2>=0xF0 && B2<=0xF7))
		{
			dwOffSet+= 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], 0x20, 0x400000, &da, DISASM_CODE);
		m_dwInstCount++;

		if(dwLength==0x01 && dwBase && bInstFound==0x02 &&(B1==0xC2 || B1==0xC3)&& strstr(da.result, "???"))
		{
			dwOffSet = dwBaseLocation;
			continue;
		}

		if(dwLength==0x02 && B1==0xEB && strstr(da.result, "JMP SHORT"))//|| strstr(da.result, "JB SHORT")))
		{
			if(B2 > 0x7F)
				dwOffSet = dwOffSet -(0x100 - B2)+ dwLength;
			else
				dwOffSet += dwLength + B2;
			continue;
		}

		
		if(dwLength==0x05 && B1==0xE9 && strstr(da.result, "JMP "))
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffSet+1]);
			if((dwTemp & 0xF0000000)!= 0xF0000000)
			{
				if((dwTemp+ dwLength+ dwOffSet)>= dwSize)
				{
					dwOffSet += dwLength;
					continue;
				}
			}			
			dwOffSet += dwTemp + dwLength;
			continue;
		}

		  // 17122010 :- verify in case of bad results if this variable causes problem
		if(dwLength==0x05 && B1==0xE8 && dwBase==0x00 && strstr(da.result, "CALL "))
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffSet+1]);
			if((dwTemp+ dwLength+ dwOffSet)>= dwSize)
			{				
				dwOffSet += dwLength;
				continue;
			}

			dwBaseLocation = dwOffSet + dwLength;
			dwBase = dwVirusBase + dwOffSet - dwExecStart + dwLength;
			dwOffSet += dwTemp + dwLength;
			continue;

		}

		//searching AEP
		if(dwBase)
		{
			if(dwLength==0x05 && strstr(da.result, "PUSH "))
			{
				dwValue = *((DWORD*)&m_pbyBuff[dwOffSet+1]);

				if(dwValue < dwImageBase && dwValue >(dwImageBase + dwLastSecRVA + dwLastSecSRD))
				{
					dwValue = 0x00;
				}		

				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x04 && B2==0x74 && B3==0x24 && strstr(da.result, "PUSH DWORD PTR [ESP+"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if((dwLength==0x04 || dwLength==0x03)&& dwValue && strstr(da.result, "POP DWORD PTR ["))
			{
				if(dwValue >= dwVirusBase)
				{
					dwOffSet += dwLength;
					continue;
				}

				*pOriginalAEP = dwValue;
				break;
			}

			if(dwLength==0x08 && B1==0xC7 && B2==0x44 && B3==0x24 && bInstFound && strstr(da.result, "MOV DWORD PTR [ESP+"))
			{
				dwValue = *((DWORD*)&m_pbyBuff[dwOffSet+4]);
				if((dwValue > dwImageBase)&&(dwValue < dwImageBase + dwLastSecRVA + dwLastSecSRD))
					bInstFound = 0x02;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength==0x06 && B1==0x8D && B2==0x9B && bInstFound==0x02 && strstr(da.result, "[EBX-100]"))
			{
				*pOriginalAEP = dwValue;
				break;
			}
			//15122010
			//Tushar ==> 09 Dec 2010 : Iexplore sample shows "MOV EBP"(which makes 'bInstFound=0x01')after "ADD EAX" hence 0x02 changes to 0x01. Hence XCHG fails and so Cleaning fails. Hance, this inst placed before MOV EBP
			if(dwLength==0x03 && B1==0x87 && B2==0x43 && bInstFound==0x02 && strstr(da.result, "XCHG [")&& strstr(da.result, "],EAX"))
			{
				*pOriginalAEP = dwValue;
				dwOffSet += dwLength;
				//continue;
				break;
			}

			if((dwLength==0x03||dwLength==0x04)&& B1==0x8B &&(B2==0x2C||B2==0x6C)&& B3==0x24 && strstr(da.result, "MOV EBP,["))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}

			//In this inst, the OEP with IamgeBase value is directly saved in dwValue var.
			if(dwLength==0x05 && B1==0xBD && strstr(da.result, "MOV EBP,"))
			{
				//15122010 : To avoid change of value in dwValue var as it is the OriAEP val if below condition is true.
				if(bInstFound == 0x02)
				{
					dwOffSet += dwLength;
					continue;
				}

				dwValue = *((DWORD*)&m_pbyBuff[dwOffSet+1]);
				bInstFound = 0x01;
				dwOffSet += dwLength;
				//31122010 :- To handle special case in which during detection garbage ADD EBX inst is found and which overwrites the OEP in dwValue saved in this inst..
				iStg1 = 1;
				continue;
			}
			if(dwLength==0x07 && B1==0xC7 && B2==0x43 && bInstFound && strstr(da.result, "MOV DWORD PTR ["))
			{
				*pOriginalAEP = *((DWORD*)&m_pbyBuff[dwOffSet+3]);
				break;
			}
			if(dwLength==0x08 && B1==0x81 && B2==0x44 && B3==0x24 && bInstFound && strstr(da.result, "ADD DWORD PTR [ESP+"))
			{
				dwValue = *((DWORD*)&m_pbyBuff[dwOffSet+4]);
				*pOriginalAEP = dwValue + dwBase;
				break;
			}

			//Spl Case for XCHNG
			//if(dwLength==0x03 && B1==0x83 && B2==0xC3 && bInstFound && strstr(da.result, "ADD EBX,"))//manjunath 17 May 2011 commented. For some files(peview.exe..etc)wrong entry point calculation
			if(dwLength==0x03 && B1==0x83 && B2==0xC3 && bInstFound && dwValue && strstr(da.result, "ADD EBX,"))//manjunath 17 May 2011
			{
				*pOriginalAEP = dwValue + dwBase;
				break;
			}
			//Spl Case for XCHNG
			if(dwLength==0x06 && B1==0x81 && B2==0xEB && bInstFound && strstr(da.result, "SUB EBX,"))
			{
				if((dwValue & dwVirusBase)&& !(dwValue&0xF0000000))
				{
					*pOriginalAEP = dwValue;
					break;
				}

				if((dwValue > dwImageBase)&&(dwValue < 0xF0000000))
				{
					*pOriginalAEP = dwValue;
					break;
				}

				if((dwValue&0xF0000000)== 0xF0000000)
				{
					*pOriginalAEP = dwValue + dwBase;
					break;
				}

				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x04 && B1==0x87 && B2==0x6C && B3==0x24 && bInstFound && strstr(da.result, "XCHG [ESP+"))
			{
				//Tushar ==> 06 Dec 2010 : Added by Ajay(inner if condition will skip if bInstFound != 0x02. i.e not the earlier req inst are found. This condition was used to handle scapegoat samples with -ve keys and ADC inst.)
				if((dwLength==0x03 || dwLength==0x04)&& B1==0x87 &&(B2==0x6B || B2==0x6C)&& bInstFound==0x02 && strstr(da.result, "XCHG [")&& strstr(da.result, "],EBP"))
				{
					*pOriginalAEP = dwValue + dwBase;
					dwOffSet += dwLength;		//changed for 1366BD35.EXE double infection // this cause a problem for df ui so i delete the comment da8dcd49.exe
					break;
				}

				bInstFound = 0x02;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength==0x04 && B1==0x11 && B2==0x6C && B3==0x24 && bInstFound && strstr(da.result, "ADC [ESP+"))//||strstr(da.result, "ADD [ESP+")))
			{
				*pOriginalAEP = dwValue + dwBase;
				break;
			}

			//if((dwLength==0x03||dwLength==0x02)&& B1==0x01 &&(B2==0x69||B2==0x2B)&& bInstFound==0x02 && strstr(da.result, "ADD [")&& strstr(da.result, "],EBP"))
			if((dwLength==0x03||dwLength==0x02)&& B1==0x01 &&(B2==0x69||B2==0x6B||B2==0x2B)&& bInstFound==0x02 && strstr(da.result, "ADD [")&& strstr(da.result, "],EBP"))
			{
				//03012011 :- To handle false detection encountered in other inst.. which skipped correct detection in this inst...
				if(dwTempValue)
				{
					*pOriginalAEP = dwTempValue + dwBase;
					if(*pOriginalAEP <(m_dwImageBase + dwLastSecRVA + dwLastSecSRD))
					{
						break;
					}
				}

				*pOriginalAEP = dwValue + dwBase;
				break;
			}

			if(dwLength==0x03 && B1==0x0F && B2==0xC1 && bInstFound==0x02 && strstr(da.result, "XADD [")&& strstr(da.result, "],EBP"))
			{
				*pOriginalAEP = dwValue + dwBase;
				break;
			}

			if(dwLength==0x02 && B1==0x33 && B2==0xED && strstr(da.result, "XOR EBP,EBP"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength==0x03 && B1==0x83 && B2==0xE5 && strstr(da.result, "AND EBP,"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength==0x02 && B1==0x2B && B2==0xED && strstr(da.result, "SUB EBP,EBP"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x02 && B1==0x2B && B2==0xC0 && strstr(da.result, "SUB EAX,EAX"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x06 && B1==0x81 && B2==0xED && bInstFound && strstr(da.result, "SUB EBP,"))
			{
				*pOriginalAEP = 0x00 - *((DWORD*)&m_pbyBuff[dwOffSet+2]);
				if(NEGATIVE_JUMP(*pOriginalAEP))//manjunath 19 May 2011. Check for negative OAEP
				{
					*pOriginalAEP = 0x00;
					continue;
				}
				break;
			}

			if(dwLength==0x06 && B1==0x81 && B2==0xCD && bInstFound && strstr(da.result, "OR EBP,"))
			{
				dwValue = *((DWORD*)&m_pbyBuff[dwOffSet+2]);
				bInstFound = 0x02;
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x06 && B1==0x81 && B2==0xC5 && bInstFound && strstr(da.result, "ADD EBP,"))
			{
				dwValue = *((DWORD*)&m_pbyBuff[dwOffSet+2]);
				bInstFound = 0x02;
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x05 && B1==0x05 && bInstFound && strstr(da.result, "ADD EAX,"))
			{
				//30122010 :- To handle situation in which OEP is already obts in dwValue through "MOV DWORD PTR [ESP+" inst but 
				//			  not yet saved in "*pOriginalAEP" var as the final stage "[EBX-100]" inst has not yet been met. And before that Current inst changes the value of OriAEP saved in dwValue
				//			  sample name for below condition : 91761491.exe 
				if(bInstFound == 0x02)
				{
					dwOffSet += dwLength;
					continue;
				}
				//31122010 :- To verify if OEP is saved from MOV EBP,OEPDWord(iStg1)and XCHG ,EBP is also met. Thus avoiding overwritting value of OEP saved in before inst.
				if(iStg2)
				{
					bInstFound = 0x02;
					dwOffSet += dwLength;
					continue;
				}

				//03012011 :- To avoid overwritting of OEP saved in dwValue var by DWord found in garbage ADD EAX inst...
				if(dwValue)
				{
					dwTempValue = *((DWORD*)&m_pbyBuff[dwOffSet+1]);
					if((dwTempValue>dwValue)&&(dwTempValue >(dwLastSecRVA + dwLastSecSRD))) //DWord val not in address range of file. so dont save this dword.
					{
						dwOffSet += dwLength;
						continue;
					}
				}

				dwValue = *((DWORD*)&m_pbyBuff[dwOffSet+1]);
				bInstFound = 0x02;
				dwOffSet += dwLength;
				continue;
			}

			if(dwLength==0x06 && B1==0x81 && B2==0xF5 && bInstFound && strstr(da.result, "XOR EBP,"))
			{
				if(bInstFound==0x02)
				{
					//03012011 :- To handle overcomming of a detection which is actually false. And this inst with next XCHG is true detection...
					dwTempValue = *((DWORD*)&m_pbyBuff[dwOffSet+2]);

					dwOffSet += dwLength;
					continue;
				}

				dwValue = *((DWORD*)&m_pbyBuff[dwOffSet+2]);   //Restored from dwOffSet+1 to dwOffSet+2
				bInstFound += 0x01;
				dwOffSet += dwLength;

				continue;
			}

			//iStg1=1 is done when OEP is found in MOV EBP,OEPDWord.
			if(dwLength==0x03 && B1==0x87 && B2==0x6B &&(bInstFound==0x02 || iStg1==1)&& strstr(da.result, "XCHG [")&& strstr(da.result, "],EBP"))
			{
				//31122010 :- To identify MOV EBP,OEPDWord inst is found and Current inst is second stage. Waiting for "spl case for XCHG inst". 
				//In Below condition iStg2 set true is used in ADD EAX inst to verify and to avoid overwritting of OEP saved in dwValue var. 
				if(iStg1==1)
				{
					iStg2=1;
					dwOffSet += dwLength;
					continue;
				}

				*pOriginalAEP = dwValue;

				//29122010 :-	To handle case in which OEP is calculated using both i.e Addr obtd after CALL inst and value in XOR etc inst ... 
				//				This case can be identified when the dwValue will be NEGATIVE.
				if((dwValue & 0xF0000000)== 0xF0000000)
				{
					*pOriginalAEP = dwValue + dwBase;
				}

				//03012011 :- To handle overcomming of a detection which is actually false. And this inst with earlier XOR EBP inst is true detection...
				if(dwTempValue &&(dwTempValue & 0xF0000000)==0xF0000000)
				{
					*pOriginalAEP = dwTempValue + dwBase;
				}


				dwOffSet += dwLength;
				if(NEGATIVE_JUMP(*pOriginalAEP))
				{
					continue;
				}
				break;
			}

			if(dwLength==0x08 && B1==0x81 && B2==0x6C && B3==0x24 && bInstFound && strstr(da.result, "SUB DWORD PTR [ESP+"))
			{
				*pOriginalAEP = dwBase - *((DWORD*)&m_pbyBuff[dwOffSet+4]);
				break;
			}
			//manjunath 17 May 2011 for instruction like
			//816B 13 E6970000     SUB DWORD PTR DS:[EBX+13], 97E6
			if(dwLength==0x07 && B1==0x81 &&((B2 >= 0x68)&&(B2 <= 0x6B))&& bInstFound && strstr(da.result, "SUB DWORD PTR [E")&& strstr(da.result, "+"))
			{
				*pOriginalAEP = dwBase - *((DWORD*)&m_pbyBuff[dwOffSet+3]);
				break;
			}
			///end
			if(dwLength==0x08 && B1==0x81 && B2==0x74 && B3==0x24 && bInstFound && strstr(da.result, "XOR DWORD PTR [ESP+"))
			{
				*pOriginalAEP = dwBase ^ *((DWORD*)&m_pbyBuff[dwOffSet+4]);
				break;
			}

			if(dwLength==0x04 && B1==0x01 && B2==0x6C && B3==0x24 && bInstFound==0x02 && dwValue && strstr(da.result, "ADD [ESP+")&& strstr(da.result, "],EBP"))
			{
				*pOriginalAEP = dwBase  + dwValue;
				break;
			}

			if(dwLength==0x04 && B1==0xFF && B2==0x64 && B3==0x24 && strstr(da.result, "JMP [ESP+"))
			{
				bInstFound++;
				dwOffSet = dwBaseLocation;
				continue;
			}
			if(dwLength==0x02 && B1==0xFF && B2==0xE5 && bInstFound==0x02 && dwValue && strstr(da.result, "JMP E"))
			{
				*pOriginalAEP = dwBase  + dwValue;
				break;
			}
			if((dwLength==0x04||dwLength==0x05)&& B1==0x0F && B2==0xC1 && bInstFound && strstr(da.result, "XADD [")&& strstr(da.result, "],EBP"))
			{
				*pOriginalAEP = dwBase  + dwValue;
				break;
			}
		}
		dwOffSet += dwLength;
	}

	if(dwOffSet >= dwSize)
		return 1;

	if(NEGATIVE_JUMP(*pOriginalAEP))//manjunath 19 May 2011. Chek for negative OAEP
		return 2;

	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: GetJumps
	In Parameters	: BYTE *byBuffer, DWORD dwNoBytesRead, DWORD dwBufferReadOffset, WORD wCallToSection, bool bIsRead
	Out Parameters	: CALL File offset
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Creates a array of all JMP Instructions in buffer
--------------------------------------------------------------------------------------*/
DWORD CPolyVirut::GetJumps(BYTE *byBuffer, DWORD dwNoBytesRead, DWORD dwBufferReadOffset, WORD wCallToSection, bool bIsRead/* = false*/)
{
	if(bIsRead == true)
	{
		byBuffer = new BYTE [VIRUT_VIRUS_CODE_SIZE];
		if(byBuffer == NULL)
		{
			return 0x00;
		}
		dwBufferReadOffset = m_pSectionHeader[wCallToSection].PointerToRawData + m_pSectionHeader[wCallToSection].SizeOfRawData - VIRUT_VIRUS_CODE_SIZE;
			
		m_pMaxPEFile->ReadBuffer(byBuffer, dwBufferReadOffset, VIRUT_VIRUS_CODE_SIZE, 0, &dwNoBytesRead);
	}

	DWORD dwCallAddressVA = 0;
	
	for(DWORD dwOffset = 0; dwOffset < dwNoBytesRead; dwOffset++)
	{
		if(byBuffer[dwOffset] != 0xE9)
		{
			continue;
		}

		dwCallAddressVA = *((DWORD *)&byBuffer[dwOffset + 1]);
		if(!NEGATIVE_JUMP(dwCallAddressVA))
			continue;
		
		dwCallAddressVA += m_pSectionHeader[wCallToSection].VirtualAddress + dwBufferReadOffset - m_pSectionHeader[wCallToSection].PointerToRawData + 
									dwOffset + E8_INSTRUCTION_SIZE;
					
		// If call is out of the file then skip
		if(dwCallAddressVA >=(m_pSectionHeader[wCallToSection].VirtualAddress + m_pSectionHeader[wCallToSection].Misc.VirtualSize))
			continue;

		// check if the call is in the reauired section. If so its patched call.
		if((dwCallAddressVA >= m_pSectionHeader[wCallToSection].VirtualAddress)&& 
			(dwCallAddressVA < (m_pSectionHeader[wCallToSection].VirtualAddress + m_pSectionHeader[wCallToSection].Misc.VirtualSize)))
		{					
			// Found patched E8 so maintain the address
			m_arrPatchedCallOffsets.AppendItem(dwCallAddressVA, dwCallAddressVA);
		}			
	}
	
	if(bIsRead == true)
	{
		delete []byBuffer;
		byBuffer = NULL;
	}

	if(m_arrPatchedCallOffsets.GetCount()== 0)
	{
		return 0x00;
	}
	
	DWORD	dwCalledAdd		= 0x00;
	DWORD	dwCalledAddOff	= 0x00;
	LPVOID	lpos = m_arrPatchedCallOffsets.GetLowest();
	
	
	while(lpos)
	{
		m_arrPatchedCallOffsets.GetData(lpos, dwCalledAdd);
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwCalledAdd, &dwCalledAddOff))
		{
			lpos = m_arrPatchedCallOffsets.GetLowestNext(lpos);
			continue;
		}
		if(dwCalledAddOff % m_pMaxPEFile->m_stPEHeader.FileAlignment== 0x00 ||	CheckForZeros(dwCalledAddOff - 0x20, 0x20))
		{
			DWORD	dwViruSize = m_pSectionHeader[wCallToSection].PointerToRawData+m_pSectionHeader[wCallToSection].SizeOfRawData - dwCalledAddOff;
			if(dwViruSize < 0x4000 || dwViruSize > 0x9000)
			{
				lpos = m_arrPatchedCallOffsets.GetLowestNext(lpos);
				dwCalledAddOff = 0x00;
				continue;
			}
			break;
		}
		else
		{
			dwCalledAddOff = 0x00;
		}

		lpos = m_arrPatchedCallOffsets.GetLowestNext(lpos);
	}	
	return dwCalledAddOff;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirutCE_DeadCode2
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Dead code detection type 2
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirutCE_DeadCode2()
{
	int iRetStatus = 0;
	WORD wDeadCodeSec = m_wNoOfSections;
	for(DWORD dwSecCnt = wDeadCodeSec; dwSecCnt > 0; dwSecCnt--)
	{
		if((m_pSectionHeader[dwSecCnt - 1].Characteristics & 0xE0000000)== 0xE0000000)
		{
			wDeadCodeSec = (WORD)(dwSecCnt);
			const int VIRUT_DEADCODE_BUFF = 0x1100;
			BYTE *byBuff = new BYTE[VIRUT_DEADCODE_BUFF];
			if(!byBuff)
			{
				return iRetStatus;
			}
			memset(byBuff, 0, VIRUT_DEADCODE_BUFF);
			DWORD dwBuffOffStart = 0x00, dwStoreVal = 0x00, dwStoreVal2 = 0x00;
			DWORD dwBuffRvaStart = m_pSectionHeader[wDeadCodeSec - 1].SizeOfRawData + m_pSectionHeader[wDeadCodeSec - 1].VirtualAddress - VIRUT_DEADCODE_BUFF;
			dwStoreVal = dwBuffRvaStart;
			WORD wRetSec = m_pMaxPEFile->Rva2FileOffset(dwBuffRvaStart, &dwBuffOffStart);
			if(wRetSec == wDeadCodeSec - 1)
			{
				if(m_pMaxPEFile->ReadBuffer(byBuff, dwBuffOffStart, VIRUT_DEADCODE_BUFF, VIRUT_DEADCODE_BUFF))
				{
					BYTE *byBuff1 = new BYTE[VIRUT_DEADCODE_BUFF];
					if(!byBuff1)
					{
						delete []byBuff;
						return iRetStatus;
					}
					memset(byBuff1, 0, VIRUT_DEADCODE_BUFF);
					for(DWORD dwCnt = VIRUT_DEADCODE_BUFF - 1; dwCnt > 0; dwCnt--)
					{
						dwBuffRvaStart = dwStoreVal;
						if(byBuff[dwCnt] == 0xE9)
						{
							if(NEGATIVE_JUMP(*(DWORD *)&byBuff[dwCnt + 1]))
							{
								dwBuffRvaStart = dwBuffRvaStart + dwCnt + *(DWORD *)&byBuff[dwCnt + 1] + 5;
								dwBuffRvaStart -= 0x300;
								dwStoreVal2 = dwBuffRvaStart;
								if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwBuffRvaStart, &dwBuffOffStart))
								{
									DWORD dwBuffSize = 0x600;
									if((dwBuffOffStart + 0x600 > m_pSectionHeader[wDeadCodeSec].PointerToRawData + m_pSectionHeader[wDeadCodeSec].SizeOfRawData) &&
										m_pSectionHeader[wDeadCodeSec].PointerToRawData + m_pSectionHeader[wDeadCodeSec].SizeOfRawData > dwBuffOffStart)
									{
										dwBuffSize = m_pSectionHeader[wDeadCodeSec].PointerToRawData + m_pSectionHeader[wDeadCodeSec].SizeOfRawData - dwBuffOffStart;
									}									
									if(dwBuffSize > 0x10 && m_pMaxPEFile->ReadBuffer(byBuff1, dwBuffOffStart, dwBuffSize , dwBuffSize))
									{
										for(DWORD dwCnt1 = 0x0; dwCnt1 < dwBuffSize - 0x10; dwCnt1++)
										{
											if(byBuff1[dwCnt1] == 0x83 && byBuff1[dwCnt1 + 1] == 0x3C && byBuff1[dwCnt1 + 2] == 0x24 &&
											  (byBuff1[dwCnt1 + 3] == 0xFE || byBuff1[dwCnt1 + 3] == 0xFF))
											{
												bool dwAEPFound = false; 
												for(DWORD dwCnt2 = dwCnt1 - 6; dwCnt2 < dwCnt1; dwCnt2++)
												{
													if(byBuff1[dwCnt2] == 0xE9 || byBuff1[dwCnt2] == 0xEB)
													{
														dwAEPFound = true;
														break;
													}
												}
												if(!dwAEPFound)
												{
													for(DWORD dwCnt3 = dwCnt1; dwCnt3 < dwCnt1 + 0x10; dwCnt3++)
													{
														if(byBuff1[dwCnt3] == 0x60)
														{
															dwAEPFound = true;
															break;
														}
													}
												}
												if(dwAEPFound)
												{
													dwBuffRvaStart = dwStoreVal2;
													dwBuffRvaStart = dwBuffRvaStart + dwCnt1; 
													m_dwAEPUnmapped = dwBuffRvaStart;
													if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwBuffRvaStart, &m_dwAEPMapped))
													{
														iRetStatus = DetectVirut_CE_LastSectionAepInit(wDeadCodeSec);
														if(iRetStatus)
														{
															if(byBuff)
															{
																delete []byBuff;
																byBuff = NULL;
															}
															if(byBuff1)
															{
																delete []byBuff1;
																byBuff1 = NULL;
															}
															return iRetStatus;
														}
													}
												}
											}
											/*else if(byBuff1[dwCnt1] == 0x60)
											{
												for(DWORD dwCnt2 = dwCnt1; dwCnt2 < dwCnt1 + 0x10; dwCnt2++)
												{
													if(byBuff1[dwCnt2] == 0xE8)
													{
														dwBuffRvaStart = dwStoreVal2;
														dwBuffRvaStart = dwBuffRvaStart + dwCnt1; 
														m_dwAEPUnmapped = dwBuffRvaStart;
														if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwBuffRvaStart, &m_dwAEPMapped))
														{
															iRetStatus = DetectVirut_CE_LastSectionAepInit(wDeadCodeSec);
															if(iRetStatus)
															{
																if(byBuff)
																{
																	delete []byBuff;
																	byBuff = NULL;
																}
																if(byBuff1)
																{
																	delete []byBuff1;
																	byBuff1 = NULL;
																}
																return iRetStatus;
															}
														}
													}
												}
											}*/
										}
									}
								}
							}
						}
					}
					if(byBuff1)
					{
						delete []byBuff1;
						byBuff1 = NULL;
					}
				}
			}
			if(byBuff)
			{
				delete []byBuff;
				byBuff = NULL;
			}
		}
	}
	return iRetStatus;
}

//Virut CE Ends
/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: This function just rewrite the Aep found in detection and 
					  truncate the file from the AEP and calculate last section
					  data size.
--------------------------------------------------------------------------------------*/
int CPolyVirut::DetectVirutFileInfector()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL)== IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}

	if(CheckForZeros(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
	{
		m_wNoOfSections--;
	}
	
	if(m_wAEPSec != 0 || m_wAEPSec == (m_wNoOfSections - 1) || (m_wNoOfSections == 2 && m_pSectionHeader[0].SizeOfRawData == 0x1E00 && m_pSectionHeader[0].PointerToRawData == m_dwAEPMapped)) 
	{	
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[VIRUT_FI_BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped, VIRUT_FI_BUFF_SIZE, MAX_INSTRUCTION_LEN))
		{
			iRetStatus = GetVirutFIParams();
			if(iRetStatus)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Virut"));								
				if(m_dwVirutFIOriginalAEP == 0 || OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwVirutFIOriginalAEP, NULL))
				{
					m_eInfectionType = VIRUT_FI;
				}
				else
				{
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetVirutFIParams
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: Function is added for all variants of virut(File Infector)
--------------------------------------------------------------------------------------*/
int CPolyVirut::GetVirutFIParams()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD		dwOffSet = 0, dwLength = 0, dwTemp = 0, dwBase = 0, dwInstCount = 0;
	BYTE		B1 = 0, B2 = 0, B3 = 0, bInstFound = 0;
	t_disasm	da;

	while(dwOffSet < m_dwNoOfBytes - 2)
	{
		if(dwInstCount > 30)
			return iRetStatus;

		memset(&da, 0x00, sizeof(struct t_disasm)*1);
		B1 = m_pbyBuff[dwOffSet];
		B2 = m_pbyBuff[dwOffSet+1];
		B3 = m_pbyBuff[dwOffSet+2];
		
		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1 == 0xC1 &&(B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffSet += 0x03;
			continue;
		}
		if(B1 == 0xD1 &&(B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffSet += 0x02;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffSet], 0x20, 0x400000, &da, DISASM_CODE);
		dwInstCount++;

		if(dwLength == 0x02 && B1 == 0xEB && strstr(da.result, "JMP SHORT"))
		{
			if(B2 > 0x7F)
				dwOffSet = dwOffSet -(0x100 - B2)+ dwLength;
			else
				dwOffSet += dwLength + B2;
			continue;
		}
		if(dwLength == 0x05 && B1 == 0xE8 && dwBase == 0x00 && strstr(da.result, "CALL "))
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffSet + 1]);
			if((dwTemp + dwLength + dwOffSet)>= m_dwNoOfBytes)
			{
				dwOffSet += dwLength;
				continue;
			}
			
			dwBase = dwOffSet + dwLength + m_dwAEPUnmapped + m_dwImageBase; 
			dwOffSet += dwTemp + dwLength;
			continue;			
		}
		if(dwLength == 0x05 && B1 == 0xE9 && strstr(da.result, "JMP "))
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffSet+1]);
			if((dwTemp & 0xF0000000)!= 0xF0000000)
			{
				if((dwTemp + dwLength + dwOffSet)>= m_dwNoOfBytes)
				{
					dwOffSet += dwLength;
					continue;
				}
			}
			dwOffSet += dwTemp + dwLength;
			continue;
		}
		if(dwBase)
		{
			if(B1==0x87 && B2==0x6C && B3==0x24 && dwLength==0x04 && strstr(da.result,"XCHG [ESP+4],EBP"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if(B1==0x89 && B2==0x6C && B3==0x24 && dwLength==0x04 && strstr(da.result,"MOV [ESP+4],EBP"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if((dwLength==0x03||dwLength==0x04)&& B1==0x8B &&(B2==0x2C||B2==0x6C)&& B3==0x24 && strstr(da.result, "MOV EBP,["))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength==0x04 && strstr(da.result,"MOV E")&& strstr(da.result,"[ESP+4]"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength==0x04 && strstr(da.result,"XOR E")&& strstr(da.result,"[ESP+4]"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if(dwLength==0x04 && B2==0x74 && B3==0x24 && strstr(da.result, "PUSH DWORD PTR [ESP+"))
			{
				bInstFound = 0x01;
				dwOffSet += dwLength;
				continue;
			}
			if(bInstFound && B1==0x81 && B2==0x6C && B3==0x24 && dwLength==0x08 && strstr(da.result,"SUB DWORD PTR [ESP+4],"))
			{
				m_dwVirutFIOriginalAEP = dwBase - *((DWORD*)&m_pbyBuff[dwOffSet + 4]);
				m_dwVirutFIOriginalAEP -= m_dwImageBase;
				iRetStatus = VIRUS_FILE_REPAIR;
				break;
			}
		}
		dwOffSet += dwLength;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirutFileInfector
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: Repair routine for different varients of Dundun Family
	                  This function just rewrite the Aep found in detection and 
					  truncate the file from the AEP and calculate last section
					  data size.  
--------------------------------------------------------------------------------------*/
int CPolyVirut::CleanVirutFileInfector()
{
	int iRetStatus = REPAIR_FAILED;
	
	//Rewrite AEP 
	m_pMaxPEFile->WriteAEP(m_dwVirutFIOriginalAEP);
	if(m_wAEPSec != m_wNoOfSections-1)
	{
		m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, m_pSectionHeader[m_wAEPSec].PointerToRawData+m_pSectionHeader[m_wAEPSec].SizeOfRawData-m_dwAEPMapped);
		return REPAIR_SUCCESS;
	}
	if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped, true))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}
// Virut file infectors Ends

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Virut Family
--------------------------------------------------------------------------------------*/
int CPolyVirut::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;

	switch(m_eInfectionType)
	{
	case VIRUT_CE:
		iRetStatus = CleanVirutCE();
		break;
	case VIRUT_FI:
		iRetStatus = CleanVirutFileInfector();
		break;
	case VIRUT_GEN:
		iRetStatus = CleanVirutGen();
		break;		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirutGen
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Virut Family
--------------------------------------------------------------------------------------*/
int CPolyVirut::CleanVirutGen()
{
	int iRetStatus = REPAIR_FAILED;
	P_VIRUT_PARAM lpVirutGenParam;
	LPVOID lpPos = m_objVirutGenParam.GetHighest();
	m_objVirutGenParam.GetData(lpPos,(LPVOID &)lpVirutGenParam);
	DWORD dwRvaVirus = 0x00, dwVirusOffset = 0; 
	WORD wVirusCodeSecNo = 0;

	if(lpVirutGenParam->InfectionType > 3)//Dead codes
	{
		if(lpVirutGenParam->InfectionType == 6)//Overlay dead code
			dwVirusOffset = lpVirutGenParam->dwRvaVirus;
		else
		{
			dwRvaVirus = lpVirutGenParam->dwRvaVirus - m_dwImageBase;
			wVirusCodeSecNo = m_pMaxPEFile->Rva2FileOffset(dwRvaVirus, &dwVirusOffset);
			if(OUT_OF_FILE == wVirusCodeSecNo)
			{
				// Neeraj 17-4-12
				dwVirusOffset = Rva2FileOffsetEx(dwRvaVirus, NULL);
				if(dwVirusOffset == 0 || dwVirusOffset <(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
				{
					return iRetStatus;
				}
			}
		}
	}
	else
	{
		dwRvaVirus = lpVirutGenParam->dwRvaVirus - m_dwImageBase;
		wVirusCodeSecNo = m_pMaxPEFile->Rva2FileOffset(dwRvaVirus, &dwVirusOffset);
		if(OUT_OF_FILE == wVirusCodeSecNo)
		{
			dwVirusOffset = Rva2FileOffsetEx(dwRvaVirus, NULL);
			if(dwVirusOffset == 0 || dwVirusOffset <(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
			{
						return iRetStatus;
			}
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		DWORD dwDecLength = lpVirutGenParam->dwDecLength;
		m_pbyBuff = new BYTE[dwDecLength];
		DWORD dwMinimumSize = (m_pMaxPEFile->m_dwFileSize - dwVirusOffset) < 0x1500 ? (m_pMaxPEFile->m_dwFileSize - dwVirusOffset) : 0x1500;
		if(dwMinimumSize < MAX_INSTRUCTION_LEN)
		{
			return iRetStatus;
		}
		if(!GetBuffer(dwVirusOffset, dwDecLength, dwMinimumSize))
		{
			return iRetStatus;
		}
	}
	switch(lpVirutGenParam->InfectionType)
	{
		case 1:
			iRetStatus = CleanVirutGenAEPInit(lpVirutGenParam, dwVirusOffset, wVirusCodeSecNo);
			break;
		case 2:
			iRetStatus = CleanVirutGenCallPatch(lpVirutGenParam, dwVirusOffset, wVirusCodeSecNo);
			break;
		case 3:
			iRetStatus = CleanVirutGenOverlay(lpVirutGenParam, dwVirusOffset);
			break;
		case 4:
		case 5:
		case 6:
			iRetStatus = CleanVirutGenDeadCode(dwVirusOffset);
			break;
		default:
			break;
	}
	m_objVirutGenParam.RemoveAll();
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirutGenDeadCode
	In Parameters	: DWORD dwVirusOffset
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Virut Family
--------------------------------------------------------------------------------------*/
int CPolyVirut::CleanVirutGenDeadCode(DWORD dwVirusOffset)
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pMaxPEFile->TruncateFile(dwVirusOffset, true))
	{
		iRetStatus = REPAIR_SUCCESS;
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirutGenOverlay
	In Parameters	: P_VIRUT_PARAM lpVirutGenParam, DWORD dwVirusOffset
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Virut Family : Overlay Type
--------------------------------------------------------------------------------------*/
int CPolyVirut::CleanVirutGenOverlay(P_VIRUT_PARAM lpVirutGenParam, DWORD dwVirusOffset)
{	
	int iRetStatus = REPAIR_FAILED;
	DWORD dwMinimumSize = m_dwNoOfBytes < 0x150 ? m_dwNoOfBytes : 0x150;
	if(dwMinimumSize < MAX_INSTRUCTION_LEN)
	{
		return iRetStatus;
	}
	if(!FindVirutGenSig(&m_pbyBuff[0], dwMinimumSize))
	{
		DecryptVirutGen(&m_pbyBuff[0], m_dwNoOfBytes, lpVirutGenParam);
		if(!FindVirutGenSig(&m_pbyBuff[0], dwMinimumSize))
		{
			return iRetStatus;
		}
	}
	DWORD	dwAepBytesOffset = 0, dwTemp = 0, dwTemp1 = 0, dwTempOffset = 0, dwIncrementalKey = 0x00;
	for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes - 0x10; dwOffset++)
	{
		//Check E800000000
		if(m_pbyBuff[dwOffset] == 0xE8 && m_pbyBuff[dwOffset + 2] == 0x00 && m_pbyBuff[dwOffset + 3] == 0x00 && 
		   m_pbyBuff[dwOffset + 4] == 0x00 && dwTempOffset == 0x00)
		{
			dwTempOffset = dwOffset + 0x05;
			dwAepBytesOffset = dwTempOffset + lpVirutGenParam->dwRvaVirus; 
			continue;
		}
		//Check 816C2404
		if(m_pbyBuff[dwOffset]==0x81 && m_pbyBuff[dwOffset+1]==0x6C && m_pbyBuff[dwOffset+2]==0x24 && m_pbyBuff[dwOffset+3]==0x04)
		{
			dwTemp = *((DWORD*)&m_pbyBuff[dwOffset+4]);
			continue;
		}
		//81ED
		if(m_pbyBuff[dwOffset]==0x81 && m_pbyBuff[dwOffset+1]==0xED && dwAepBytesOffset)
		{
			dwTemp1 = *((DWORD*)&m_pbyBuff[dwOffset+2]);
			if(dwTemp1 < m_dwImageBase)
			{
				dwAepBytesOffset -= dwTemp1;
			}
			continue;
		}
		//8DB5
		if(m_pbyBuff[dwOffset]==0x8D && m_pbyBuff[dwOffset+1]==0xB5 && dwAepBytesOffset)
		{
			dwTemp1 = *((DWORD*)&m_pbyBuff[dwOffset+2]);
			if(dwTemp1 < m_dwImageBase)
			{
				dwAepBytesOffset += dwTemp1;
			}
			continue;
		}
		//B9F3A4
		if(m_pbyBuff[dwOffset]==0xB9 && m_pbyBuff[dwOffset+5]==0xF3 && m_pbyBuff[dwOffset+6]==0xA4)
		{
			dwIncrementalKey = *((DWORD*)&m_pbyBuff[dwOffset+1]);
			break;
		}
	}
	if((!dwTempOffset)||(!dwTemp)||(!dwAepBytesOffset)||(dwIncrementalKey > 0x200))
	{
		return iRetStatus;
	}

	dwAepBytesOffset  -= lpVirutGenParam->dwRvaVirus;
	if(dwAepBytesOffset > lpVirutGenParam->dwDecLength)
	{
		return iRetStatus;
	}
	if(dwIncrementalKey != 0x00)
	{
		m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwAepBytesOffset], m_dwAEPMapped, dwIncrementalKey);
	}

	if(m_wAEPSec != (m_wNoOfSections - 1) && (lpVirutGenParam->dwModeOffset > 0x100))
	{
		memset(m_pbyBuff, 0x00, lpVirutGenParam->dwDecLength);
		if(lpVirutGenParam->dwModeOffset + m_dwAEPMapped < m_pMaxPEFile->m_dwFileSize)
		{
			m_pMaxPEFile->WriteBuffer(m_pbyBuff, lpVirutGenParam->dwModeOffset + m_dwAEPMapped - 0x18, 0x30);
		}
	}
	if(dwVirusOffset%m_pMaxPEFile->m_stPEHeader.FileAlignment)
	{
		dwVirusOffset -= dwVirusOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment;
	}
	if(m_pMaxPEFile->TruncateFile(dwVirusOffset, true))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirutGenCallPatch
	In Parameters	: P_VIRUT_PARAM lpVirutGenParam, DWORD dwVirusOffset, WORD wVirusCodeSecNo
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Virut Family : CALL Patch
--------------------------------------------------------------------------------------*/
int CPolyVirut::CleanVirutGenCallPatch(P_VIRUT_PARAM lpVirutGenParam, DWORD dwVirusOffset, WORD wVirusCodeSecNo)
{
	int iRetStatus = REPAIR_FAILED;
	DWORD dwMinimumSize = m_dwNoOfBytes < 0x150 ? m_dwNoOfBytes : 0x150;
	if(dwMinimumSize < MAX_INSTRUCTION_LEN)
	{
		return iRetStatus;
	}
	if(!FindVirutGenSig(&m_pbyBuff[0], dwMinimumSize))
	{
		DecryptVirutGen(&m_pbyBuff[0], m_dwNoOfBytes, lpVirutGenParam);
		if(!FindVirutGenSig(&m_pbyBuff[0], dwMinimumSize))
		{
			return iRetStatus;
		}
	}
	DWORD dwOffset = 0;
	for(dwOffset = m_dwNoOfBytes - 0x03; dwOffset > 0x1000; dwOffset--)
	{
		if(m_pbyBuff[dwOffset - 0x01] == 0xFF && m_pbyBuff[dwOffset] == 0x15)
		{
			break;
		}
	}
	// Added condition to repair the file if E8 call is patched instead of FF15.
	DWORD dwBytesToWrites = 0x06;	
	if(dwOffset <= 0x1000)
	{
		for(dwOffset = m_dwNoOfBytes - 0x03; dwOffset > m_dwNoOfBytes - 0x120; dwOffset--)
		{
			if(m_pbyBuff[dwOffset] == 0xe8)
			{		
				dwBytesToWrites = 5;
				dwOffset++;
				break;
			}
		}
		if(dwOffset == m_dwNoOfBytes - 0x100)
		{
			return iRetStatus;
		}
	}
	m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwOffset - 0x01], m_dwAEPMapped + lpVirutGenParam->CallFoundLocInBuff, dwBytesToWrites);

	memset(m_pbyBuff, 0x00, lpVirutGenParam->dwDecLength);	
	m_pMaxPEFile->WriteBuffer(m_pbyBuff, lpVirutGenParam->dwVirusCallOffset, lpVirutGenParam->InitExitOffset);
	
	if(dwVirusOffset >= m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData && dwVirusOffset < (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
	{
		if(dwVirusOffset%m_pMaxPEFile->m_stPEHeader.FileAlignment)
		{
			dwVirusOffset = dwVirusOffset - (dwVirusOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment);
		}
	}
	DWORD dwOverlayStart = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
	if(m_pMaxPEFile->m_dwFileSize != dwOverlayStart)
	{
		if(!CheckForZeros(dwOverlayStart, m_pMaxPEFile->m_dwFileSize - dwOverlayStart) == 0x00)
		{
			if((dwOverlayStart - dwVirusOffset) > 0x3000 || m_pMaxPEFile->m_dwFileSize >= dwOverlayStart)
			{
				m_pMaxPEFile->WriteBuffer(m_pbyBuff, dwVirusOffset, lpVirutGenParam->dwDecLength);
				return REPAIR_SUCCESS;
			}
		}
	}
	if((wVirusCodeSecNo != (m_wNoOfSections - 1))&&(wVirusCodeSecNo != OUT_OF_FILE))
	{
		m_pMaxPEFile->WriteSectionCharacteristic(wVirusCodeSecNo, dwVirusOffset - m_pSectionHeader[wVirusCodeSecNo].PointerToRawData, SEC_SRD);		
	}
	else
	{
		m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData = dwVirusOffset - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
		m_pMaxPEFile->WriteSectionCharacteristic(m_wNoOfSections - 1, dwVirusOffset - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, SEC_SRD);
		
		m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize = lpVirutGenParam->dwRvaVirus - m_dwImageBase - m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress;
		m_pMaxPEFile->WriteSectionCharacteristic(m_wNoOfSections - 1, m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize, SEC_VS);
	}
	// Calculate image size correctly if empty last section is present
	if(m_wNoOfSections < m_pMaxPEFile->m_stPEHeader.NumberOfSections)
	{
		m_pMaxPEFile->WriteNumberOfSections(m_wNoOfSections);
	}
	if(m_pMaxPEFile->TruncateFile(dwVirusOffset, true))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirutGenAEPInit
	In Parameters	: P_VIRUT_PARAM lpVirutGenParam, DWORD dwVirusOffset, WORD wVirusCodeSecNo
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ajay Vishwakarma + Virus Analysis Team
	Description		: Repair routine for different varients of Virut Family : AEP Patch
--------------------------------------------------------------------------------------*/
int CPolyVirut::CleanVirutGenAEPInit(P_VIRUT_PARAM lpVirutGenParam, DWORD dwVirusOffset, WORD wVirusCodeSecNo)
{
	int iRetStatus = REPAIR_FAILED;
	DWORD dwMinimumSize = m_dwNoOfBytes < 0x150 ? m_dwNoOfBytes : 0x150;
	if(dwMinimumSize < MAX_INSTRUCTION_LEN)
	{
		return iRetStatus;
	}
	if(!FindVirutGenSig(&m_pbyBuff[0], dwMinimumSize))
	{
		DecryptVirutGen(m_pbyBuff, m_dwNoOfBytes, lpVirutGenParam);
	}

	DWORD dwIncrementalKey	= lpVirutGenParam->dwIncrementalKey;
	DWORD dwAepBytesOffset = 0, dwTemp = 0, dwTemp1 = 0, dwTempOffset = 0;
	for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes - 0x10; dwOffset++)
	{
		// Check E8000000
		if(m_pbyBuff[dwOffset] == 0xE8 && m_pbyBuff[dwOffset + 2] == 0x00 && m_pbyBuff[dwOffset + 3] == 0x00 && m_pbyBuff[dwOffset + 4] == 0x00 &&
			dwTempOffset == 0x00)
		{
			dwTempOffset = dwOffset + 0x05;
			dwAepBytesOffset = dwTempOffset + lpVirutGenParam->dwRvaVirus; 
			continue;
		}
		// Check 816C2404
		if(m_pbyBuff[dwOffset] == 0x81 && m_pbyBuff[dwOffset + 1] == 0x6C && m_pbyBuff[dwOffset + 2] == 0x24 && m_pbyBuff[dwOffset + 3] == 0x04)
		{
			dwTemp = *((DWORD *)&m_pbyBuff[dwOffset + 4]);
			continue;
		}
		// Check 81ED
		if(m_pbyBuff[dwOffset] == 0x81 && m_pbyBuff[dwOffset + 1] == 0xED && dwAepBytesOffset)
		{
			dwTemp1 = *((DWORD *)&m_pbyBuff[dwOffset + 2]);
			if(dwTemp1 < m_dwImageBase)
			{
				dwAepBytesOffset -= dwTemp1;
			}
			continue;
		}
		// Check 8DB5
		if(m_pbyBuff[dwOffset] == 0x8D && m_pbyBuff[dwOffset + 1] == 0xB5 && dwAepBytesOffset)
		{
			dwTemp1 = *((DWORD *)&m_pbyBuff[dwOffset + 2]);
			if(dwTemp1 < m_dwImageBase)
			{
				dwAepBytesOffset += dwTemp1;
			}
			continue;
		}
		// Check B9xxxxxxxxxxF3A4
		if(m_pbyBuff[dwOffset] == 0xB9 && m_pbyBuff[dwOffset + 5] == 0xF3 && m_pbyBuff[dwOffset + 6] == 0xA4)
		{
			dwIncrementalKey = *((DWORD *)&m_pbyBuff[dwOffset+1]);
			break;
		}
	}

	if((!dwTempOffset)||(!dwTemp)||(!dwAepBytesOffset)||(dwIncrementalKey > 0x200))
	{
		if(FindVirutGenSig(m_pbyBuff, dwMinimumSize))
		{
			m_pMaxPEFile->CloseFile_NoMemberReset();
			return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : iRetStatus;
		}
		return iRetStatus;
	}
	if(!FindVirutGenSig(m_pbyBuff, dwMinimumSize))
	{
		return iRetStatus;
	}
	dwAepBytesOffset -= lpVirutGenParam->dwRvaVirus;
	//if(dwAepBytesOffset > lpVirutGenParam->dwDecLength)
	//In Some files we get wrong dwAepBytesOffset but it is not usefull in cleaning of virus where dwIncrementalKey = 0
	//i.e We have to just calculate new AEP not the replacing the buffer near AEP.
	if((NEGATIVE_JUMP(dwAepBytesOffset)||(dwAepBytesOffset > lpVirutGenParam->dwDecLength))&&(dwIncrementalKey != 0x00))
	{
		return iRetStatus;
	}
	DWORD dwRvaVirus = lpVirutGenParam->dwRvaVirus - m_dwImageBase;
	if(dwIncrementalKey == 0x00)
	{
		m_pMaxPEFile->WriteAEP(dwRvaVirus + dwTempOffset - dwTemp);
	}
	else
	{
		m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwAepBytesOffset], m_dwAEPMapped, dwIncrementalKey);
	}

	if(m_wAEPSec !=(m_wNoOfSections - 1) && ((lpVirutGenParam->dwModeOffset) > 0x100))
	{
		memset(m_pbyBuff, 0x00, lpVirutGenParam->dwDecLength);
		if(lpVirutGenParam->dwModeOffset + m_dwAEPMapped < m_pMaxPEFile->m_dwFileSize)
		{
			m_pMaxPEFile->WriteBuffer(m_pbyBuff, lpVirutGenParam->dwModeOffset + m_dwAEPMapped - 0x18, 0x30);
		}
	}
	else if((lpVirutGenParam->InitExitOffset != 0x00)&& (dwIncrementalKey < lpVirutGenParam->dwDecLength)&& ((dwIncrementalKey == 0x00)||
		   ((m_dwAEPMapped + dwIncrementalKey)<(m_dwAEPMapped + lpVirutGenParam->CallFoundLocInBuff))))
	{
		memset(m_pbyBuff, 0x00, lpVirutGenParam->dwDecLength);
		if(lpVirutGenParam->dwModeOffset + m_dwAEPMapped < m_pMaxPEFile->m_dwFileSize)
		{
			m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwAEPMapped + lpVirutGenParam->CallFoundLocInBuff, lpVirutGenParam->InitExitOffset);
		}
	}

	if(dwVirusOffset >= m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData && dwVirusOffset < (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
	{
		if(dwVirusOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment)
			dwVirusOffset = dwVirusOffset - dwVirusOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment;
	}
	
	DWORD dwOverlayStart = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
	if(m_pMaxPEFile->m_dwFileSize != dwOverlayStart)
	{
		if(!CheckForZeros(dwOverlayStart, m_pMaxPEFile->m_dwFileSize - dwOverlayStart))
		{
			if((dwOverlayStart - dwVirusOffset)> 0x3000 || m_pMaxPEFile->m_dwFileSize >= dwOverlayStart)
			{
				m_pMaxPEFile->FillWithZeros(dwVirusOffset, lpVirutGenParam->dwDecLength);
				return REPAIR_SUCCESS;
			}
		}
	}
	if(m_wAEPSec ==(m_wNoOfSections - 1))
	{
		if(dwIncrementalKey == 0x00)
		{
			dwVirusOffset = m_dwAEPMapped;
		}
		if(dwRvaVirus % m_pMaxPEFile->m_stPEHeader.FileAlignment)
		{
			dwRvaVirus -= (dwRvaVirus % m_pMaxPEFile->m_stPEHeader.FileAlignment);
		}
		if(dwRvaVirus == m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)
		{
			dwRvaVirus = m_dwAEPUnmapped;
		}
	}
	if((wVirusCodeSecNo != (m_wNoOfSections - 1)) && (wVirusCodeSecNo != OUT_OF_FILE))
	{
		m_pMaxPEFile->WriteSectionCharacteristic(wVirusCodeSecNo, dwVirusOffset - m_pSectionHeader[wVirusCodeSecNo].PointerToRawData, SEC_SRD);
	}
	else
	{
		m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData = dwVirusOffset - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
		m_pMaxPEFile->WriteSectionCharacteristic(m_wNoOfSections - 1, dwVirusOffset - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, SEC_SRD);
		m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize = dwRvaVirus - m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress;
		m_pMaxPEFile->WriteSectionCharacteristic(m_wNoOfSections - 1, m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize, SEC_VS);
	}
	// Calculate image size correctly if empty last section is present
	if(m_wNoOfSections < m_pMaxPEFile->m_stPEHeader.NumberOfSections)
	{
		m_pMaxPEFile->WriteNumberOfSections(m_wNoOfSections);
	}
	if(m_pMaxPEFile->TruncateFile(dwVirusOffset, true))
	{
		iRetStatus = REPAIR_SUCCESS;
	}
	return iRetStatus;
}