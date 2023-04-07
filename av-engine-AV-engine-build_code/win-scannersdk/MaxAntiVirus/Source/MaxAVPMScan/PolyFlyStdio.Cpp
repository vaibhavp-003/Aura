/*======================================================================================
FILE				: PolyFlyStdio.cpp
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
NOTES				: This is detection module for malware FlyStdio Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyFlyStdio.h"
#include "PolymorphicVirus.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyFlyStdio
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyFlyStdio::CPolyFlyStdio(CMaxPEFile *pMaxPEFile): 
CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyFlyStdio
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyFlyStdio::~CPolyFlyStdio(void)
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
	Description		: Detection routine for different varients of FlyStdio Family
						A : not-a-virus.Flystdio.L: one or two time encryptions present.
						B : Always start decryption from first section Pointer to raw data,
						C : It deletes the original file from which it was executed once it is installed on the computer. 
						D : Flystudio.L does not spread automatically using its own means. 
							It needs an attacking user's intervention in order to reach the affected computer.
							The means of transmission used include, among others, pendrive,
 							email messages with attached files, Internet downloads, FTP, IRC channels, peer-to-peer (P2P) file sharing networks, etc.
						F : It is possibly  to load by hiding within the system WIN.INI file and the strings "run=" and "load=".
--------------------------------------------------------------------------------------*/
int CPolyFlyStdio::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections < 0x4 || (m_wAEPSec != 0 && m_wAEPSec != m_wNoOfSections - 1 )|| (m_pSectionHeader[0].Characteristics & 0xE0000000) != 0xE0000000)
	{
		return iRetStatus;
	}

	if(((m_pSectionHeader[0].Misc.VirtualSize == 0x634  && m_pSectionHeader[0].SizeOfRawData == 0x800 )||
		(m_pSectionHeader[0].Misc.VirtualSize == 0x800  && m_pSectionHeader[0].SizeOfRawData == 0x800 ) ||
		(m_pSectionHeader[0].Misc.VirtualSize == 0x22C && m_pSectionHeader[0].SizeOfRawData == 0x400)  ||
		(m_pSectionHeader[0].Misc.VirtualSize == 0x1000 && m_pSectionHeader[0].SizeOfRawData == 0x1000))&&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].VirtualAddress == 0x2038 &&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size == 0x50 &&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0xC].VirtualAddress == 0x2000 && 
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0xC].Size == 0x38) 
	{
		WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
		iRetStatus = IsFlyStdioFile();
		SetEvent(CPolymorphicVirus::m_hEvent);
	}
	else if(m_pSectionHeader[0x2].SizeOfRawData >= 0x2000 && (m_pSectionHeader[0x2].PointerToRawData == 0x8000 || m_pSectionHeader[0x2].PointerToRawData == 0x7000)&&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].VirtualAddress >= 0x6654 && m_pMaxPEFile->m_stPEHeader.DataDirectory[0x1].Size == 0x3C &&
		((m_pMaxPEFile->m_stPEHeader.DataDirectory[0xC].VirtualAddress >= 0x6000 && m_pMaxPEFile->m_stPEHeader.DataDirectory[0xC].Size >= 0xB8) ||
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[0xC].VirtualAddress == 0x0)))
	{
		WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
		iRetStatus = IsFlyStdioFile();
		SetEvent(CPolymorphicVirus::m_hEvent);
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: IsFlyStdioFile
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of FlyStdio Family
--------------------------------------------------------------------------------------*/
int CPolyFlyStdio::IsFlyStdioFile()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	m_pbyBuff = new BYTE[FLYSTDIO_BUFF_SIZE];
	if(!GetBuffer(m_dwAEPMapped, 0x12, 0x12))
	{
		return iRetStatus;
	}
	DWORD		dwLength = 0,dwOffset=0, dwMatchedInstr = 0;
	t_disasm	da;
	while(dwOffset < 0x12 && dwMatchedInstr < 0x6)
	{
		memset(&da, 0x00, sizeof(struct t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	
		if(dwLength > 0x12 - dwOffset)
		{
			break;
		}
		if(dwMatchedInstr < 0x5 && dwLength == 1 && strstr(da.result, "PUSH"))
		{
			dwMatchedInstr++;
		}					
		else if(dwMatchedInstr == 0x5 && ((dwLength == 6 && (strstr(da.result,"JN") || strstr(da.result,"JMP")||strstr(da.result,"JE") || strstr(da.result,"JB"))) 
			|| (dwLength == 5 && strstr(da.result,"CALL"))))

		{
			dwMatchedInstr++;
		}
		if(dwMatchedInstr >0x5)
		{
			CEmulate objEmulate(m_pMaxPEFile);
			if(objEmulate.IntializeProcess())
			{
				objEmulate.SetEip(m_dwImageBase + m_dwAEPUnmapped);

				char szBreakPoint[1024] = {0};
				sprintf_s(szBreakPoint, 1024, "__isinstruction('push')");
				objEmulate.SetBreakPoint(szBreakPoint);

				memset(szBreakPoint, 0, 1024);
				sprintf_s(szBreakPoint, 1024, "__isinstruction('add')");
				objEmulate.SetBreakPoint(szBreakPoint);

				memset(szBreakPoint, 0, 1024);
				sprintf_s(szBreakPoint, 1024, "__isinstruction('sub')");
				objEmulate.SetBreakPoint(szBreakPoint);

				memset(szBreakPoint, 0, 1024);
				sprintf_s(szBreakPoint, 1024, "__isinstruction('add dword ptr [e')");
				objEmulate.SetBreakPoint(szBreakPoint);

				memset(szBreakPoint, 0, 1024);
				sprintf_s(szBreakPoint, 1024, "__isinstruction('sub dword ptr [e')");
				objEmulate.SetBreakPoint(szBreakPoint);
				DWORD dwStartOffset=0,dwDecStartOffset=0,dwDecStart=0;

				objEmulate.PauseBreakPoint(1);
				objEmulate.PauseBreakPoint(2);
				objEmulate.PauseBreakPoint(3);
				objEmulate.SetNoOfIteration(0x2);
				if(7 != objEmulate.EmulateFile())
				{
					return iRetStatus;
				}
				DWORD dwRegNoDecData = objEmulate.GetDestRegNo();                                                                          
				if(dwRegNoDecData == 0xFFFFFFFF)
				{
					return iRetStatus;
				}
				objEmulate.PauseBreakPoint(0);
				objEmulate.ActiveBreakPoint(1);
				objEmulate.ActiveBreakPoint(2);
				objEmulate.PauseBreakPoint(3);
				objEmulate.PauseBreakPoint(4);
				objEmulate.SetNoOfIteration(0x10);
				bool bLoop = true;
				while(7 == objEmulate.EmulateFile() && bLoop)
				{
					if(0x6 != objEmulate.GetInstructionLength())
					{
						continue;
					}
					bLoop = false;
					DWORD dwAddByte = objEmulate.GetImmidiateConstant();
					DWORD dwRegNo = objEmulate.GetDestRegNo();                                                                          
					if(dwRegNo == 0xFFFFFFFF)
					{
						return iRetStatus;
					}
					DWORD dwBuffOffSet = objEmulate.GetSpecifyRegValue(dwRegNo);
					memset(szBreakPoint, 0, 1024);
					objEmulate.GetInstruction(szBreakPoint);
					if(strstr(szBreakPoint, "add"))
					{
						dwBuffOffSet +=dwAddByte;
					}
					else if(strstr(szBreakPoint, "sub"))
					{
						dwBuffOffSet -=dwAddByte;
					}
					objEmulate.PauseBreakPoint(1);
					objEmulate.PauseBreakPoint(2);
					objEmulate.ActiveBreakPoint(3);
					objEmulate.ActiveBreakPoint(4);

					DWORD dwEmuCount=0, dwAction=0,dwCheckNoofDecLoop=0x0,dwTableStartOffset=0x0;
					//Corrupt file handling if encryptions is there but number of encryptions present is zero.
					if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwBuffOffSet - m_dwImageBase, &dwTableStartOffset))
					{
						return iRetStatus;
					}
					if(!m_pMaxPEFile->ReadBuffer(&dwCheckNoofDecLoop,dwTableStartOffset, 0x04, 0x04))
					{
						return iRetStatus;
					}
					if(dwCheckNoofDecLoop ==0x00)
					{
						return iRetStatus;
					}
					//we will opent this commented part if we will need 2 time decryption in any file till now close it.
					//	while(dwEmuCount < 2)
					//	{
					objEmulate.SetNoOfIteration(0x30);
					if(7 == objEmulate.EmulateFile() &&(dwDecStartOffset ==0 || dwDecStartOffset == objEmulate.GetMemoryOprand()))
					{	
						dwEmuCount++;												
						dwDecStartOffset = objEmulate.GetMemoryOprand();
						WORD wDecSec =m_pMaxPEFile->Rva2FileOffset(dwDecStartOffset-m_dwImageBase, &dwDecStart);
						if(OUT_OF_FILE == wDecSec)
						{
							return iRetStatus;
						}
						memset(szBreakPoint, 0, 1024);
						objEmulate.GetInstruction(szBreakPoint);
						if(strstr(szBreakPoint, "add dword ptr [e"))
						{
							dwAction=1;
						}
						else if(strstr(szBreakPoint, "sub dword ptr [e"))
						{
							dwAction=2;
						}
						DWORD dwKey = objEmulate.GetImmidiateConstant();
						DWORD dwNoofByteToDec = objEmulate.GetSpecifyRegValue(dwRegNoDecData);
						if(dwNoofByteToDec > m_pSectionHeader[wDecSec].SizeOfRawData || dwAction==0 || dwNoofByteToDec > FLYSTDIO_BUFF_SIZE)
						{
							return iRetStatus;
						}
						if(dwEmuCount==1)
						{
							if(!GetBuffer(dwDecStart, dwNoofByteToDec, dwNoofByteToDec))
							{
								return iRetStatus;
							}
						}
						//Detection using signature Based
						if(IsFlyStdioSig(dwKey,dwAction,dwNoofByteToDec))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Not-a-Virus.FlyStdio.L"));
							return VIRUS_FILE_DELETE;
						}
						if(dwEmuCount ==1 )
						{
							DWORD dwMappedBuffOffSet=0;
							if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwBuffOffSet - m_dwImageBase, &dwMappedBuffOffSet))
							{
								return iRetStatus;
							}
							if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,dwMappedBuffOffSet, 0x30, 0x30))
							{
								return iRetStatus;
							}
							if(dwDecStartOffset == (*(DWORD *)&m_pbyBuff[0x4])+ dwBuffOffSet + 0x4 && dwNoofByteToDec == *(DWORD *)&m_pbyBuff[0x8] )
							{	
								//Detection using condition Based
								if(IsFlyStdioCheck(dwBuffOffSet))
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Not-a-Virus.FlyStdio"));
									return VIRUS_FILE_DELETE;
								}
							}
							return iRetStatus;
							//need 2 time decryption  then only open it.
							//DWORD dwEip = objEmulate.GetEip() + objEmulate.GetInstructionLength();
							//objEmulate.SetEip(dwEip);		
						}
					}
					//}need 2 time decryption  then only open it.
				}
			}
		}
		dwOffset += dwLength;
	}
	return iRetStatus;

}

/*-------------------------------------------------------------------------------------
	Function		: IsFlyStdioSig
	In Parameters	: (DWORD dwKey,DWORD dwAction,DWORD dwNoofByteToDec
	Out Parameters	: true is sig. present else false
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: Checks for Binary Signature. This Function Use for Signature Base detection after first time decryption
--------------------------------------------------------------------------------------*/
bool CPolyFlyStdio::IsFlyStdioSig(DWORD dwKey,DWORD dwAction,DWORD dwNoofByteToDec)
{
	const BYTE FlySig[] = {0x6B, 0x72, 0x6E, 0x6C, 0x6E, 0x2E, 0x66, 0x6E, 0x72, 0x00, 0x6B, 0x72, 0x6E, 0x6C, 
							0x6E, 0x2E, 0x66, 0x6E, 0x65, 0x00, 0x47, 0x65, 0x74, 0x4E, 0x65, 0x77, 0x53, 0x6F, 0x63, 0x6B, 0x00, 0x53,
							0x6F, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x5C, 0x46, 0x6C, 0x79, 0x53, 0x6B, 0x79};
							//krnln.fnr.krnln.fne.GetNewSock.Software\FlySky
	const BYTE FlyStdioSig[] = {0x6B, 0x72, 0x6E, 0x6C, 0x6E, 0x2E, 0x66, 0x6E, 0x65, 0x00, 0x00, 0x00, 0x6B, 0x72,
								0x6E, 0x6C, 0x6E, 0x2E, 0x66, 0x6E, 0x72};
							//krnln.fne...krnln.fnr

	if(dwNoofByteToDec < sizeof(FlySig)+ sizeof(FlyStdioSig))
	{
		return false;
	}
	//Data decription with current operator
	for(DWORD j = 0; j < dwNoofByteToDec ; j += 4)
	{
		if(dwAction == 1)
		{
			*(DWORD *)&m_pbyBuff[j] += dwKey;
		}
		else
		{
			*(DWORD *)&m_pbyBuff[j] -= dwKey;
		}
	}

	//Check Signature It's a flystdio file or not 
	if(memcmp(&m_pbyBuff[0x0], FlyStdioSig, sizeof(FlyStdioSig)) == 0 || memcmp(&m_pbyBuff[0x19], FlySig, sizeof(FlySig)) == 0 )
	{
		return true;;
	}
	return false;
}


/*-------------------------------------------------------------------------------------
	Function		: IsFlyStdioCheck
	In Parameters	: DWORD dwBuffOffSet
	Out Parameters	: true for success else false
	Purpose			: 
	Author			: Tushar Kadam + Ravi Prakash Mishra + Virus Analysis Team
	Description		: This Function Use for Condition Base detection after first time decryption if Pe-Crypt.CF Condition matched then Dected.
--------------------------------------------------------------------------------------*/
bool CPolyFlyStdio::IsFlyStdioCheck(DWORD dwBuffOffSet)
{	
	bool bRetStatus = false;
	DWORD dwCountDec=*(DWORD *)&m_pbyBuff[0x0];
	DWORD dwDecFileOffset = 0x0,NumberOfByteSec =0x0,dwReadByte=0x0,Offset=0x4;

	BYTE pbyBuffer[0x200 + MAX_INSTRUCTION_LEN] = {0};
	for(DWORD i=0x0; i< dwCountDec;i++)
	{
		dwDecFileOffset = *(DWORD *)&m_pbyBuff[Offset]+ dwBuffOffSet + Offset ;
		WORD wSec = m_pMaxPEFile->Rva2FileOffset(dwDecFileOffset - m_dwImageBase, &dwDecFileOffset);
		if(OUT_OF_FILE == wSec )
		{
			return bRetStatus;
		}
		NumberOfByteSec= *(DWORD *)&m_pbyBuff[Offset+0x4] * 0x04;
		if( dwDecFileOffset != m_pSectionHeader[wSec].PointerToRawData && NumberOfByteSec > m_pSectionHeader[wSec].SizeOfRawData && wSec !=m_wAEPSec)
		{
			return bRetStatus;
		}				
		if(dwDecFileOffset + NumberOfByteSec < m_pSectionHeader[wSec].PointerToRawData + m_pSectionHeader[wSec].SizeOfRawData)
		{
			dwReadByte= (m_pSectionHeader[wSec].PointerToRawData + m_pSectionHeader[wSec].SizeOfRawData)-(dwDecFileOffset + NumberOfByteSec );
			if(dwReadByte >0x08)
			{
				dwReadByte =0x08;
			}
			if(!m_pMaxPEFile->ReadBuffer(pbyBuffer,dwDecFileOffset + NumberOfByteSec , dwReadByte, dwReadByte))
			{
				return bRetStatus;
			}
			if((*(DWORD *)&pbyBuffer[0x00]!=0x00 && wSec !=m_wAEPSec) )
			{
				return bRetStatus;
			}
		}
		if(i == dwCountDec -1)
		{
			return true;
		}
		Offset+=0x8;
	}
	return bRetStatus;
}
