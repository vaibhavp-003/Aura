/*======================================================================================
FILE				: PolyHezhi.cpp
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
NOTES				: This is detection module for malware Hezhi Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyHezhi.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyHezhi
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyHezhi::CPolyHezhi(CMaxPEFile *pMaxPEFile): 
CPolyBase(pMaxPEFile), m_dwOrgDataOff(0), m_dwStrDecOff(0), m_dwOrgAEP(0)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyHezhi
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyHezhi::~CPolyHezhi(void)
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
	Description		: Detection routine for different varients of Hezhi Family
--------------------------------------------------------------------------------------*/
int CPolyHezhi::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL || m_pMaxPEFile->m_bIsVBFile == true)
	{
		return iRetStatus;
	}	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[0x200];
	if(!m_pbyBuff)
	{
		return VIRUS_NOT_FOUND;
	}
	if(!GetBuffer(m_dwAEPMapped,0x200,0x200))
	{
		return VIRUS_NOT_FOUND;
	}

	t_disasm	da;
	DWORD		dwLength	= 0,
				dwKey		= 0,
				dwOffSet	= 0,
				dwReg1		= 0,	// Decryption size
				dwReg2		= 0,	// Decryption offset
				dwDecSize	= 0;
	stMovs		stStack[20] = {0};
	CHAR		szReg1[3]	= {0},
				szReg2[3]	= {0},
				*szRegs[8]	= {"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"};
	int			iReg1		= -1,
				iReg2		= -1,
				iTOP		= 0,
				iDecCount	= 0,
				iPushADStk[20] = {0},
				iTOPpushad  = -1;
	WORD		wNOT		= 0xF7D0,
				wADD		= 0x81C0,
				wROL		= 0xC1C0,
				wROR		= 0xC1C8,
				wSUB		= 0x81E8;
	bool		bDecBuffRead= false,
				bDecDone	= false;

	while(dwOffSet < m_dwNoOfBytes)
	{	
		memset(&da, 0x00, sizeof(struct t_disasm) * 1);
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffSet], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffSet))
		{
			return iRetStatus;
		}

		if(strstr(da.result ,"MOV DX,DS") && 3 <= iDecCount)
		{
			bDecDone = true;
			break;

		}
		else if(strstr(da.result ,"PUSHAD"))
		{
			if(iTOPpushad < 20)
			{
				iTOPpushad++;
			}
		}
		else if(strstr(da.result ,"POPAD"))
		{
			if(iTOPpushad > -1)
			{
				iTOP -= iPushADStk[iTOPpushad];
				iPushADStk[iTOPpushad--] = 0;
			}

		}
		else if(strstr(da.result ,"PUSH E"))
		{
			if(m_pbyBuff[dwOffSet + 0x6] == (m_pbyBuff[dwOffSet] + 0x8))
			{
				dwOffSet += 0x7;
				continue;
			}

		}
		else if(strstr(da.result ,"MOV E"))
		{
			if(iTOP < 20)
			{
				stStack[iTOP].dwOffset = dwOffSet;
				stStack[iTOP++].bRegister= m_pbyBuff[dwOffSet];
				if(-1 != iTOPpushad)
				{
					iPushADStk[iTOPpushad]++;
				}
			}
			dwOffSet += dwLength;
			continue;

		}
		else if(strstr(da.result ,"XOR DWORD") && 0x7 == dwLength)
		{
			dwKey = da.immconst;
			char	*pReg = NULL;
			pReg = strstr(da.result, "+");
			
			if(NULL != pReg)
			{
				pReg++;
				memcpy(szReg2, pReg, 3);
				pReg -= 4;
				if (pReg != NULL)
				{
					memcpy(szReg1, pReg, 3);
				}
			}
			else
			{
				dwOffSet += 0x7;
				continue;
			}

			for(int i = 0; i < 8; i++)
			{
				if(memcmp(szReg1, szRegs[i], 3)==0 && -1 == iReg1)
				{
					iReg1 = i ;
				}
				else if(memcmp(szReg2, szRegs[i], 3)==0 && -1 == iReg2)
				{
					iReg2 = i;
				}
			}
			if(iReg1 == -1 || iReg2 == -1)
			{
				dwOffSet += 0x7;
				continue;
			}

			//- to get mov offset
			DWORD	dwTemp = 0, dwOffSetRe	= 0;
			
			for(int i = --iTOP; i >= 0; i--)
			{
				if(stStack[i].bRegister == (0xB8 + iReg1) && dwTemp == 0)
				{
					dwTemp = stStack[i].dwOffset;
				}
				else if(stStack[i].bRegister == (0xB8 + iReg2) && dwOffSetRe == 0)
				{
					dwOffSetRe = stStack[i].dwOffset;
				}
				else
				{
					break;
				}
			}
			// get min offset
			if(dwOffSetRe > dwTemp)
			{
				dwOffSetRe = dwTemp;
			}
			//- Getting Offset and size of Decryption data
			DWORD	dwLengthRe		= 0,
					dwRegStack[10]  = {0};
			int		iTOPRegSk		= -1;
			BYTE	bInst[2]	= {0}; 
			bool	bReg1Push	= false,
					bReg2Push	= false;
			
			while(dwOffSetRe < dwOffSet)
			{
				memset(&da, 0x00, sizeof(struct t_disasm) * 1);
				dwLengthRe = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffSetRe], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				bInst[0] = m_pbyBuff[dwOffSetRe + 1];
				bInst[1] = m_pbyBuff[dwOffSetRe];
				
				if(strstr(da.result,"MOV E") && dwLengthRe == 5)
				{
					if(m_pbyBuff[dwOffSetRe] == (0xB8 + iReg1) && bReg1Push == false)
					{
						dwReg1 = da.immconst;
					}
					else if(m_pbyBuff[dwOffSetRe] == (0xB8 + iReg2) && bReg2Push == false)
					{
						dwReg2 = da.immconst;
					}

				}
				else if(strstr(da.result,"PUSHAD"))
				{
					dwRegStack[++iTOPRegSk] = dwReg1;
					dwRegStack[++iTOPRegSk]	= dwReg2;

				}
				else if(strstr(da.result,"POPAD"))
				{
					dwReg2 = dwRegStack[iTOPRegSk--];
					dwReg1 = dwRegStack[iTOPRegSk--];

				}
				else if(strstr(da.result,"PUSH E"))
				{
					if(m_pbyBuff[dwOffSetRe] == (0x50 + iReg1))
					{
						bReg1Push = true;
					}
					else if(m_pbyBuff[dwOffSetRe] == (0x50 + iReg2))
					{
						bReg2Push = true;	
					}
				}
				else if(strstr(da.result,"POP E"))
				{
					if(m_pbyBuff[dwOffSetRe] == (0x58 + iReg1))
					{
						bReg1Push = false;
					}
					else if(m_pbyBuff[dwOffSetRe] == (0x58 + iReg2))
					{
						bReg2Push = false;	
					}
				}
				else if(strstr(da.result,"ADD E"))
				{
					if(*(WORD*)&bInst[0] == (wADD + iReg1) && bReg1Push == false)
					{
						dwReg1 += da.immconst;
					}
					else if(*(WORD*)&bInst[0] == (wADD + iReg2) && bReg2Push == false)
					{
						dwReg2 += da.immconst;
					}
				}
				else if(strstr(da.result,"SUB E"))
				{
					if(*(WORD*)&bInst[0] == (wSUB + iReg1) && bReg1Push == false)
					{
						dwReg1 -= da.immconst;
					}
					else if(*(WORD*)&bInst[0] == (wSUB + iReg2) && bReg2Push == false)
					{
						dwReg2 -= da.immconst;
					}
				}
				else if(strstr(da.result,"ROL E"))
				{
					if(*(WORD*)&bInst[0] == (wROL + iReg1) && bReg1Push == false)
					{
						dwReg1 = _lrotl(dwReg1, da.immconst);
					}
					else if(*(WORD*)&bInst[0] == (wROL + iReg2) && bReg2Push == false)
					{
						dwReg2 = _lrotl(dwReg2, da.immconst);
					}
				}
				else if(strstr(da.result,"ROR E"))
				{
					if(*(WORD*)&bInst[0] == (wROR + iReg1) && bReg1Push == false)
					{
						dwReg1 = _lrotr(dwReg1, da.immconst);
					}
					else if(*(WORD*)&bInst[0] == (wROR + iReg2) && bReg2Push == false)
					{
						dwReg2 = _lrotr(dwReg2, da.immconst);
					}
				}
				dwOffSetRe += dwLengthRe;
			}
			//- Decryption 
			if((m_wNoOfSections - 1) == m_pMaxPEFile->Rva2FileOffset((dwReg2 - m_dwImageBase), &dwReg2))
			{
				if(false == bDecBuffRead)
				{
					m_dwStrDecOff = dwReg2;
					bDecBuffRead = true;
					if(m_pbyBuff)
					{
						delete[] m_pbyBuff;
					}
					if (dwReg1 > m_pMaxPEFile->m_dwFileSize)
					{
						return VIRUS_NOT_FOUND;
					}
					m_pbyBuff = new BYTE[dwReg1 + 0x4];

					if(!m_pbyBuff)
					{
						return VIRUS_NOT_FOUND;
					}
					
					if(!GetBuffer(dwReg2, dwReg1 + 0x4, dwReg1))
					{
						return VIRUS_NOT_FOUND;
					}

					for(int i = dwReg1; i >= 0; i--)
					{
						*(DWORD*)&m_pbyBuff[i] ^= dwKey;
					}
					iDecCount++;
					dwDecSize = dwReg1;
					dwOffSet = 0;
				}
				else
				{
					for(int i = dwDecSize; i >= (dwDecSize - dwReg1); i--)
					{
						*(DWORD*)&m_pbyBuff[i] ^= dwKey;
					}
					iDecCount++;
					dwOffSet = dwReg2 - m_dwStrDecOff;
				}
				//----ReSetting
				iReg1 = iReg2 = -1;
				for(int i = 0; i <= iTOPpushad; i++)
				{
					iPushADStk[i] = 0;
				}
				iTOPpushad = iTOP  = 0;
				continue;
			}
			dwOffSet += dwLength;
			continue;
		}//--end XOR 
		else if(bDecBuffRead && strstr(da.result ,"CALL 00") && 0x5 == dwLength)	
		{
			if(0x58 == m_pbyBuff[dwOffSet + 0x5] && 0xBE == m_pbyBuff[dwOffSet + 0x6] && 0xBB == m_pbyBuff[dwOffSet + 0xB])
			{
				DWORD	dwLengthRe  = 0,
						dwOffSetRe	= dwOffSet + 0x19;
				int		iInstCnt	= 0;

				dwReg1 = *(DWORD *)&m_pbyBuff[dwOffSet + 0x7];	// MOV ESI, const
				dwReg2 = *(DWORD *)&m_pbyBuff[dwOffSet + 0xC];	// MOV EBX, const
				dwReg1 -= dwReg2;								// SUB ESI, EBX
				dwReg2 = *(DWORD *)&m_pbyBuff[dwOffSet + 0x15];	// MOV EBX, const
				dwOffSet += (dwReg1 + dwLength);				// ADD EAX, ESI

				
				while(dwOffSetRe < dwOffSet && iInstCnt < 3)
				{
					memset(&da, 0x00, sizeof(struct t_disasm) * 1);
					dwLengthRe = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffSetRe], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					iInstCnt++;
					if(strstr(da.result,"XOR") && dwLengthRe == 7)
					{
						for(int i = dwDecSize; i >= dwOffSet; i--)
						{
							*(DWORD*)&m_pbyBuff[i] ^= da.immconst;
						}
						iDecCount++;
						break;
						
					}
					else if(strstr(da.result,"ADD"))
					{
						for(int i = dwOffSet; i <= dwDecSize; i+=4)
						{
							*(DWORD*)&m_pbyBuff[i] += da.immconst;	
						}
						iDecCount++;
						break;

					}
					else if(strstr(da.result,"SUB"))
					{
						for(int i = dwOffSet; i <= dwDecSize; i+=4)
						{
							*(DWORD*)&m_pbyBuff[i] -= da.immconst;	
						}
						iDecCount++;
						break;

					}
					else if(strstr(da.result,"NOT E"))
					{
						for(int i = dwOffSet; i <= dwDecSize; i+=4)
						{
							*(DWORD*)&m_pbyBuff[i] = ~*(DWORD*)&m_pbyBuff[i];	
						}
						iDecCount++;
						break;

					}
					else if(strstr(da.result,"ROL E"))
					{
						for(int i = dwOffSet; i <= dwDecSize; i+=4)
						{
							*(DWORD*)&m_pbyBuff[i] = _lrotl(*(DWORD*)&m_pbyBuff[i], da.immconst);
						}
						iDecCount++;
						break;

					}
					else if(strstr(da.result,"ROR E"))
					{
						for(int i = dwOffSet; i <= dwDecSize; i+=4)
						{
							*(DWORD*)&m_pbyBuff[i] = _lrotr(*(DWORD*)&m_pbyBuff[i], da.immconst);
						}
						iDecCount++;
						break;
					}
					dwOffSetRe += dwLengthRe;
				}
				continue;
			}
		}
		dwOffSet += dwLength;
	}
	if(bDecDone)// Original Data 
	{
		BYTE	byOrigAEP[]		= {0x57, 0x6A, 0x00, 0x68, 0x00, 0x02, 0x00, 0x00, 0x56, 0x53, 0x50, 0xFF, 0x97},
				byOrgDataChk[]	= {0x60, 0xB9, 0xFC, 0x01, 0x00, 0x00, 0x8D, 0xB7};
		int		i = 0;

		// Original AEP
		for(i = 0x580; i < 0xA00; i++)
		{
			if(memcmp(byOrigAEP, &m_pbyBuff[i], sizeof(byOrigAEP))==0 && m_pbyBuff[i - 0x5] == 0xBB)
			{
				m_dwOrgAEP = *(DWORD *)&m_pbyBuff[i - 0x4] - m_dwImageBase;
				break;
			}
		}
		// Original Data at AEP
		for(i = 0x1000; i < 0x1800; i++)
		{
			if(memcmp(byOrgDataChk, &m_pbyBuff[i], sizeof(byOrgDataChk))==0)
			{
				m_dwOrgDataOff = *(DWORD *)&m_pbyBuff[i + 0x8];
				dwKey		   = *(DWORD *)&m_pbyBuff[*(DWORD *)&m_pbyBuff[i + 0xE]];

				for(i = m_dwOrgDataOff; i < (m_dwOrgDataOff + 0x1FC); i++)
				{
					*(DWORD *)&m_pbyBuff[i] ^= dwKey;
				}

				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Hezhi.Gen"));
				return VIRUS_FILE_REPAIR;
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Hezhi Family
--------------------------------------------------------------------------------------*/
int CPolyHezhi::CleanVirus()
{
	if(m_dwOrgAEP != 0)
		if(m_dwOrgAEP != m_dwAEPUnmapped)
		{
			m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x200);
			m_pMaxPEFile->WriteAEP(m_dwOrgAEP);
			m_pMaxPEFile->Rva2FileOffset(m_dwOrgAEP, &m_dwAEPMapped);
		}

	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwOrgDataOff], m_dwAEPMapped, 0x200))
		if(m_pMaxPEFile->TruncateFile(m_dwStrDecOff))
		{
			return REPAIR_SUCCESS;
		}
	return REPAIR_FAILED;
}