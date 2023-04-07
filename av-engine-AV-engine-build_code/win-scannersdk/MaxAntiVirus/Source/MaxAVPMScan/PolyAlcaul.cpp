/*======================================================================================
FILE				: PolyAlcaul.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malwares Virus.Alcaul.H Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyAlcaul.h"
#include "SemiPoly.h"
#include "SemiPolyDBScn.h"
#include "MaxBMAlgo.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyAlcaul
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAlcaul::CPolyAlcaul(CMaxPEFile *pMaxPEFile):CPolyBase(pMaxPEFile)
{
	m_dwOrigAEP = 0;
	m_dwReplaceOffset = 0; //Added
	m_dwOrigFileSize = 0;  //Added
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAlcaul
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyAlcaul::~CPolyAlcaul()
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
	Author			: Tushar Kadam
	Description		: Detection routine for different varients of Alcaul Family
--------------------------------------------------------------------------------------*/
int CPolyAlcaul::DetectVirus()
{
	int iRetStatus = DetectAlcaulH();
	int iRetStatus1 = DetectAlcaulB(); //Added
	if(iRetStatus)
	{
		return iRetStatus;
	}
	else if(iRetStatus1)	//Added
	{
	  return iRetStatus1;	//Added
	}			//Added

	return DetectAlcaulF();
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Repair routine for different varients of Alcaul Family
--------------------------------------------------------------------------------------*/
int CPolyAlcaul::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	if(m_eVirusType == VIRUS_TYPE_ALCAUL_H)
	{
		iRetStatus = CleanAlcaulH();
	}
	else if(m_eVirusType == VIRUS_TYPE_ALCAUL_F)
	{
		iRetStatus = CleanAlcaulF();
	}
	else if(m_eVirusType == VIRUS_TYPE_ALCAUL_B) //Added
	{
	    iRetStatus = CleanAlcaulB();		//Added
	}						//Added
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAlcaulH
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detection routine for different varients of Alcaul.H varient
--------------------------------------------------------------------------------------*/
int CPolyAlcaul::DetectAlcaulH()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD dwTimeDateStamp = 0;
	m_pMaxPEFile->ReadBuffer(&dwTimeDateStamp, m_pMaxPEFile->m_stPEHeader.e_lfanew + 8, 4, 4);
	if(dwTimeDateStamp == 0x656D6974 && m_wAEPSec == m_wNoOfSections - 1 && 
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000020) == 0xE0000020)	
	{
		const int ALCAUL_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[ALCAUL_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, ALCAUL_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, ALCAUL_BUFF_SIZE, ALCAUL_BUFF_SIZE))
		{
			if(GetDecryptionData())
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Alcaul.H"));
				m_eVirusType = VIRUS_TYPE_ALCAUL_H;
				iRetStatus = VIRUS_FILE_REPAIR;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDecryptionData
	In Parameters	: 
	Out Parameters	: bool : true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Get Decryptionn data for detection and repair info
--------------------------------------------------------------------------------------*/
bool CPolyAlcaul::GetDecryptionData()
{
	DWORD dwLength = 0, dwOffset = 0, dwDecryptOff = 0;
	int iNoOfInstrutions = 0;
	t_disasm da;
	m_dwInstCount = 0;

	Instruction_Set_Struct objInstructionSet[MAX_INSTRUCTIONS] = {0};

	while(dwOffset < m_dwNoOfBytes && m_dwInstCount <= 8)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffset))
		{
			break;
		}
		if(m_pbyBuff[dwOffset] == 0xE8  && dwLength == 0x05 && strstr(da.result, "CALL") && m_dwInstCount == 0 )		
		{
			if(*(DWORD *)&m_pbyBuff[dwOffset + 1] == 0)
			{
				dwDecryptOff = m_dwAEPUnmapped + dwOffset + 5;
				m_dwInstCount++;
			}
		}
		else if(m_pbyBuff[dwOffset] == 0x81 && dwLength == 0x06 &&strstr(da.result,"SUB E") && m_dwInstCount == 1 && da.immconst != 0)
		{	
			dwDecryptOff -= *(DWORD*)&m_pbyBuff[dwOffset + 2]; 
			m_dwInstCount++;			
		}
		else if(m_pbyBuff[dwOffset] == 0x8D && dwLength == 0x06 && strstr(da.result,"LEA") && m_dwInstCount == 2)
		{
			dwDecryptOff += *(DWORD*)&m_pbyBuff[dwOffset + 2]; 
			m_dwInstCount++;
		}
		else if((0x57 < m_pbyBuff[dwOffset] && m_pbyBuff[dwOffset] < 0x5F) && dwLength == 0x01 && strstr(da.result,"POP E") && m_dwInstCount == 3)
		{				
			m_dwInstCount++;
		}
		else if(((dwLength == 2 && strstr(da.result, "ROL E")) ||
				 (dwLength == 2 && strstr(da.result, "ROR E")) ||
				 (dwLength == 6 && strstr(da.result, "ADD E")) ||
				 (dwLength == 6 && strstr(da.result, "SUB E")) ||
				 (dwLength == 6 && strstr(da.result, "XOR E")) ||
				 (dwLength == 1 && strstr(da.result, "INC E")) ||
				 (dwLength == 1 && strstr(da.result, "DEC E")) ||
				 (dwLength == 2 && strstr(da.result, "NEG E")) || 
				 (dwLength == 2 && strstr(da.result, "NOT E"))) && m_dwInstCount == 4)
		{
			objInstructionSet[iNoOfInstrutions].dwInstLen = dwLength;
			strcpy_s(objInstructionSet[iNoOfInstrutions].szOpcode, TEXTLEN, da.dump);
			strcpy_s(objInstructionSet[iNoOfInstrutions++].szPnuemonics, TEXTLEN, da.result);
		}
		else if(dwLength == 1 && strstr(da.result, "PUSH"))
		{
			break;
		}		
		dwOffset += dwLength;
	}
		
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwDecryptOff, &dwDecryptOff))
	{
		if(dwDecryptOff > (m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 2].PointerToRawData))
		{
			if(m_pMaxPEFile->ReadBuffer(&m_dwOrigAEP,(dwDecryptOff + 0x24), 4, 4))
			{
				char *ptr = NULL;
				DWORD dwConstant = 0;

				for(int i = 0; i < iNoOfInstrutions; i++)
				{
					dwConstant = 0;
					ptr = strrchr(objInstructionSet[i].szPnuemonics, ',');
					if(ptr)
					{
						ptr++;
						sscanf_s(ptr, "%X", &dwConstant);			
					}
					if(strstr(objInstructionSet[i].szPnuemonics, "ROL E"))
					{
						m_dwOrigAEP = _lrotl(m_dwOrigAEP, dwConstant);
					}
					else if(strstr(objInstructionSet[i].szPnuemonics, "ROR E"))
					{
						m_dwOrigAEP = _lrotr(m_dwOrigAEP, dwConstant);
					}
					else if(strstr(objInstructionSet[i].szPnuemonics, "ADD E"))
					{
						m_dwOrigAEP += dwConstant;
					}
					else if(strstr(objInstructionSet[i].szPnuemonics, "SUB E"))
					{
						m_dwOrigAEP -= dwConstant;
					}
					else if(strstr(objInstructionSet[i].szPnuemonics, "XOR E"))
					{
						m_dwOrigAEP ^= dwConstant;
					}
					else if(strstr(objInstructionSet[i].szPnuemonics, "INC E"))
					{
						m_dwOrigAEP++;
					}
					else if(strstr(objInstructionSet[i].szPnuemonics, "DEC E"))
					{
						m_dwOrigAEP--;
					}
					else if(strstr(objInstructionSet[i].szPnuemonics, "NEG E"))
					{
						m_dwOrigAEP = ~m_dwOrigAEP + 1;
					}
					else if(strstr(objInstructionSet[i].szPnuemonics, "NOT E"))
					{
						m_dwOrigAEP = ~m_dwOrigAEP;
					}
				}
				m_dwOrigAEP = m_dwOrigAEP >> 8;
				return true;
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanAlcaulH
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Repair routine for different varients of Alcaul.H varient
--------------------------------------------------------------------------------------*/
int CPolyAlcaul::CleanAlcaulH()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOrigAEP))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
		{			
			if(m_pMaxPEFile->FillWithZeros(m_pMaxPEFile->m_stPEHeader.e_lfanew + 8, 4))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectAlcaulF
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Repair routine for different varients of Alcaul.H varient
					- Prepends 6144(0x1800)bytes.
					- Drops kamikaze.vbs in current directory
--------------------------------------------------------------------------------------*/
int CPolyAlcaul::DetectAlcaulF(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	// These are entry level checks to detect the presence of an infected file					    
	if(m_wNoOfSections != 0x03 || m_dwAEPMapped != 0x1090 ||
		m_wAEPSec != 0x0 || m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections-2].PointerToRawData != 0x00 ||
		m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections-2].SizeOfRawData != 0x00)
	{
		return iRetStatus;
	}

	// Primary Ckecking of constant string (KAM)at the end of infected file
	const BYTE dwValidateBuff[] = {0x4B, 0x41, 0x4D};
	BYTE bybuff[sizeof(dwValidateBuff)] = {0};

	if(!m_pMaxPEFile->ReadBuffer(bybuff, m_pMaxPEFile->m_dwFileSize - 0x03, sizeof(dwValidateBuff),sizeof(dwValidateBuff)))
	{
		return iRetStatus;
	}

	if(memcmp(bybuff, dwValidateBuff, sizeof(dwValidateBuff)) != 0x00)
	{
		return iRetStatus;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	const int HllpAlcaulF_BUFF_SIZE = 0x250;
	m_pbyBuff = new BYTE[HllpAlcaulF_BUFF_SIZE];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}

	//Sign: some bytes from start of virus code*kamikaze*C.:.\.k.a.m.i.k.a.z.e...v.b.p
	const TCHAR szHllpAlcaulF_Sig[] = {_T("4B7065E51B478C9023F53F84622B*6B616D696B617A65*43003A005C006B0061006D0069006B0061007A0065002E007600620070")};		
	CSemiPolyDBScn polydbObj;
	polydbObj.LoadSigDBEx(szHllpAlcaulF_Sig, _T("Virus.W32.HLLP.Alcaul.F"), FALSE);

	if(!GetBuffer(m_dwAEPMapped, HllpAlcaulF_BUFF_SIZE, HllpAlcaulF_BUFF_SIZE))
	{
		return iRetStatus;
	}

	TCHAR szVirusName[MAX_PATH] = {0};
	if(polydbObj.ScanBuffer(m_pbyBuff, HllpAlcaulF_BUFF_SIZE, szVirusName) >= 0)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
		if(_tcslen(szVirusName) > 0)
		{
			DWORD dwStartOfOverlay = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
			DWORD dwOverlaySize = m_pMaxPEFile->m_dwFileSize - dwStartOfOverlay;

			// Original file Can be from 0x1800 within 100 bytes or in overlay
			if(!GetBuffer(0x1800, 0x100, 0x100)) // getting buffer from 0x1800
			{
				return iRetStatus;
			}
	
			BYTE HllpAlcaulF_Sig1[] = {0x4D,0x5A};
			DWORD dwIndex = 0;
			if(OffSetBasedSignature(HllpAlcaulF_Sig1, sizeof(HllpAlcaulF_Sig1), &dwIndex)) //checking MZ from 0x1800 offset 
			{
				m_dwOriginalFileSize = m_pMaxPEFile->m_dwFileSize - 0x1803 - dwIndex;
				m_dwOriginalFileStart = 0x1800 + dwIndex;
				m_eVirusType = VIRUS_TYPE_ALCAUL_F;
				return VIRUS_FILE_REPAIR;
			}
			else if(dwStartOfOverlay != 0 && dwOverlaySize > 0x05)
			{
				if(!GetBuffer(dwStartOfOverlay, 0x100, 0x100))// Getting buffer from overlay
				{
					return iRetStatus;
				}
				if(OffSetBasedSignature(HllpAlcaulF_Sig1, sizeof(HllpAlcaulF_Sig1), &dwIndex))//checking for MZ from overlay
				{
					m_dwOriginalFileStart = dwStartOfOverlay + dwIndex;
					m_dwOriginalFileSize = dwOverlaySize - 0x03 - dwIndex;
					m_eVirusType = VIRUS_TYPE_ALCAUL_F;
					return VIRUS_FILE_REPAIR;
				}
			}
			else
			{
				return VIRUS_FILE_DELETE;
			}
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanAlcaulF
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Alisha
	Description		: Repair routine for different varients of Alcaul.F varient
--------------------------------------------------------------------------------------*/
int CPolyAlcaul::CleanAlcaulF()
{
	if(m_pMaxPEFile->CopyData(m_dwOriginalFileStart, 0x00, m_dwOriginalFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOriginalFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAlcaulB
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Alisha
	Description		: Detection routine for different varients of Alcaul.B
--------------------------------------------------------------------------------------*/
int CPolyAlcaul::DetectAlcaulB(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0 && m_wNoOfSections == 0x3 && (m_dwAEPMapped == 0x1074 || m_dwAEPMapped == 0x1060) && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x1000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int	ALCAULB_BUFF_SIZE = 0x200;
		m_pbyBuff = new BYTE[ALCAULB_BUFF_SIZE];

		DWORD	dwStartBuff = 0x0;
		if(m_dwAEPMapped == 0x1074)
		{
			dwStartBuff = 0x1110;
		}
		else 
		{
			dwStartBuff = 0x224C;
		}

		if(GetBuffer(dwStartBuff, ALCAULB_BUFF_SIZE, ALCAULB_BUFF_SIZE))
		{
			TCHAR ALCAULB_CZ_Sig[] = {_T("61006C0043006F005000610055004C0000*730061006E0064007700690063006800*6500780065")};
			TCHAR ALCAULB_CZ_Sig1[] = {_T("101240001C12400000F030*C4104000C41040008010400078*73616E6477696368686561646572")};

			CSemiPolyDBScn polydbObj;

			polydbObj.LoadSigDBEx(ALCAULB_CZ_Sig, _T("Virus.W32.HLLP.Alcaul.B"), TRUE);
			polydbObj.LoadSigDBEx(ALCAULB_CZ_Sig1, _T("Virus.W32.HLLP.Alcaul.B"), FALSE);


			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0],ALCAULB_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					m_dwReplaceOffset  = m_pSectionHeader[m_wAEPSec].PointerToRawData + 0x600;

					m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize - 0x2C08;

					WORD	byCheckMz = 0x0;

					if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwReplaceOffset,0x2,0x2))
					{
						return VIRUS_FILE_DELETE;
					}
					else if(byCheckMz == 0x5A4D)
					{

						m_eVirusType = VIRUS_TYPE_ALCAUL_B;
						return VIRUS_FILE_REPAIR;
					}
					else
					{
						return VIRUS_FILE_DELETE;
					}


				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanAlcaulB
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Repair routine for different varients of Alcaul.B
--------------------------------------------------------------------------------------*/
int CPolyAlcaul::CleanAlcaulB()
{
	if(m_pMaxPEFile->CopyData(m_dwReplaceOffset, 0x00, m_dwOrigFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}
