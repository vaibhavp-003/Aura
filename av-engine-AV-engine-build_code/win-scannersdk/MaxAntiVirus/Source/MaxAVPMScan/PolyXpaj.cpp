/*======================================================================================
FILE				: PolyXpaj.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Neeraj Singh + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malware Xpaj Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyXpaj.h"
#include "PolymorphicVirus.h"
#include "depacks.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyXpaj
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyXpaj::CPolyXpaj(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile),
m_dwCounter1A(0),
m_dwCounter2A(0),
m_bDelete(0)
{	
	m_bRelocPresent = false;

	memset(&m_structRelTable,0x00,sizeof(m_structRelTable));	
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyXpaj
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyXpaj::~CPolyXpaj(void)
{
	if(m_pbyBuff)
	{
		VirtualFree((void*)m_pbyBuff, 0, MEM_RELEASE);
		m_pbyBuff = NULL;
	}
	m_arrPatchedCallOffsets.RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Detection routine for different varients of Xpaj Family
--------------------------------------------------------------------------------------*/
int CPolyXpaj::DetectVirus() 
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections - 1 || m_pSectionHeader[m_wAEPSec].SizeOfRawData < 0x50)
	{
		return iRetStatus;
	}

	m_pbyBuff = (BYTE*)VirtualAlloc(NULL, XPAJ_GEN_BUFF_SIZE + MAX_INSTRUCTION_LEN, MEM_COMMIT, PAGE_READWRITE);
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, XPAJ_GEN_BUFF_SIZE + MAX_INSTRUCTION_LEN);

	bool bSecFound = false;
	for(WORD wSec = m_wNoOfSections - 1; wSec >= m_wAEPSec; wSec--)
	{
		if(m_pSectionHeader[wSec].SizeOfRawData >= XPAJ_GEN_STUB_SIZE)
		{
			bSecFound = true;
			break;
		}
		if(wSec == m_wAEPSec)
		{
			break;
		}
	}

	if(!bSecFound)
	{
		return iRetStatus;
	}
		
	DWORD dwChunk = m_pSectionHeader[m_wAEPSec].SizeOfRawData < 0x10000 ? m_pSectionHeader[m_wAEPSec].SizeOfRawData : 0x10000;	
	BYTE *byBuffer = new BYTE[dwChunk];
	if(!byBuffer)
	{
		return iRetStatus;
	}
	memset(byBuffer, 0, dwChunk);
	dwChunk -= 4; // Reduce by 2 as we will be checking next 2 bytes after offset
	
	DWORD dwBytesRead = 0;
	for(DWORD dwReadOffset = m_pSectionHeader[m_wAEPSec].PointerToRawData; dwReadOffset < (m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData); dwReadOffset += dwChunk)
	{
		if(m_pMaxPEFile->ReadBuffer(byBuffer, dwReadOffset, dwChunk, 0, &dwBytesRead))
		{
			for(DWORD dwOffset = 0; dwOffset < dwBytesRead; dwOffset++)
			{
				if(byBuffer[dwOffset] == 0x55)
				{
					if((byBuffer[dwOffset + 1] == 0x89  && byBuffer[dwOffset + 2] == 0xE5   && 
						byBuffer[dwOffset + 3] == 0x83  && byBuffer[dwOffset + 4] == 0xEC ) || 
					   (byBuffer[dwOffset + 1] == 0x8B  && byBuffer[dwOffset + 2] == 0xEC   && 
					    byBuffer[dwOffset + 3] == 0x83  && byBuffer[dwOffset + 4] == 0xEC )) 
					{
						m_dwCalledAddRVA = dwReadOffset + dwOffset + m_pSectionHeader[m_wAEPSec].VirtualAddress - m_pSectionHeader[m_wAEPSec].PointerToRawData;
						if(dwBytesRead - dwOffset < XPAJ_GEN_BUFF_SIZE)
						{
							if(GetBuffer(dwReadOffset + dwOffset, XPAJ_GEN_BUFF_SIZE, XPAJ_GEN_BUFF_SIZE))
							{
								if(CheckXpajGenInstructions(m_pbyBuff))
								{
									if(byBuffer)
									{
										delete []byBuffer;
										byBuffer = NULL;
									}
										
									iRetStatus = VIRUS_FILE_REPAIR;
									
									WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
									{
										CEmulate objEmulate(m_pMaxPEFile);
										if(!objEmulate.IntializeProcess())
										{
											_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Xpaj.Dam"));
											iRetStatus = VIRUS_FILE_DELETE;
										}
									}
									SetEvent(CPolymorphicVirus::m_hEvent);	
									return iRetStatus;
								}
							}						
						}
						else
						{						
							if(CheckXpajGenInstructions(&byBuffer[dwOffset]))
							{
 								if(byBuffer)
								{
									delete []byBuffer;
									byBuffer = NULL;
								}
								
								iRetStatus = VIRUS_FILE_REPAIR;
									
								WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
								{
									CEmulate objEmulate(m_pMaxPEFile);
									if(!objEmulate.IntializeProcess())
									{
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Xpaj.Dam"));
										iRetStatus = VIRUS_FILE_DELETE;
									}
								}
								SetEvent(CPolymorphicVirus::m_hEvent);	
								return iRetStatus;
							}
						}
					}
				}
			}
		}
	}
	if(byBuffer)
	{
		delete []byBuffer;
		byBuffer = NULL;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckXpajGenInstructions
	In Parameters	: BYTE *pbyBuff
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Finds Xpaj code Instruction
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::CheckXpajGenInstructions(BYTE *pbyBuff) 
{
	t_disasm da;
	DWORD dwLength = 0x00, dwOffset = 0x00, dwFirstCallFlag = 0x00,dwJmpflag = 0x00,dwCallOffset = 0x00,dwJmpOffset1 = 0x00;
	int iStg = 0, iXor = 0, iOr = 0, iCallCnt = 0;
	BYTE bCallCnt = 0;
	BYTE JmpbyBuff[XPAJ_GEN_BUFF_SIZE] = {0};
	bool bCallcheck = false,bJmpCheck = false;
	m_dwInstCount = 0;
	while(dwOffset < XPAJ_GEN_BUFF_SIZE && m_dwInstCount <= 0x100)
	{
		if(bJmpCheck == true)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&JmpbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		}
		else
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		}
		if(dwLength > (XPAJ_GEN_BUFF_SIZE - dwOffset))
		{
			break;
		}		
		m_dwInstCount++;
		if(dwLength == 0x02 && strstr(da.result, "MOV ") && iStg == 0)
		{
			iStg++;
		}
		else if(dwLength == 0x03 && strstr(da.result, "SUB ") && iStg == 1)
		{
			iStg++;
		}
		else if(dwLength == 0x01 && strstr(da.result, "PUSH ") && iStg >= 2 && iStg < 5)
		{
			iStg++;
		}
		else if(dwLength == 0x05 && strstr(da.result,"JMP") && iStg >=2 && iStg <=5 && dwOffset <= 0x25 && bJmpCheck == false && (iCallCnt == 0))
		{			
			DWORD dwRVAJmpOffset =  *(DWORD *)&pbyBuff[dwOffset + 0x01] + m_dwCalledAddRVA + dwOffset + 0x05;
			DWORD dwJmpOffset = 0x00;			
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwRVAJmpOffset, &dwJmpOffset))
			{
				if(m_pMaxPEFile->ReadBuffer(&JmpbyBuff[0],dwJmpOffset,XPAJ_GEN_BUFF_SIZE,XPAJ_GEN_BUFF_SIZE))
				{
					bJmpCheck = true;					
					dwJmpOffset1 = dwRVAJmpOffset;
					dwOffset = 0;
					continue;
				}
			}
		}
		else if( strstr(da.result, "JE ") || strstr(da.result, "JZ ") || strstr(da.result, "JNZ ") ||
				 strstr(da.result, "JG ") || strstr(da.result, "JL ") || strstr(da.result, "JNB "))
		{
			return false;
		}
		else if(dwFirstCallFlag == 0x00 && (dwLength == 0x01 || dwLength == 0x03) && strstr(da.result, "???"))
		{
			return false;
		}
		else if(dwFirstCallFlag == 0x00 && dwLength == 0x06 && strstr(da.result, "CALL "))
		{
			return false;
		}
		else if(dwFirstCallFlag == 0x00 && dwOffset > 0x28)
		{
			return false;
		}
		else if(dwFirstCallFlag == 0x00 && dwLength == 0x05 && strstr(da.result, "CALL ") && (iStg == 5))
		{			
			if(iCallCnt++ > 1)
			{
				break;
			}
			
			DWORD dwRVAJmpOffset =  *(DWORD *)&pbyBuff[dwOffset + 0x01] + m_dwCalledAddRVA + dwOffset + 0x05;
			DWORD dwJmpOffset = 0x00;

			if(bJmpCheck == true)
			{
				dwRVAJmpOffset = *(DWORD *)&JmpbyBuff[dwOffset + 0x01] + dwJmpOffset1 + dwOffset + 0x05;
			}

			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwRVAJmpOffset, &dwJmpOffset))
			{				
				BYTE byBuff[XPAJ_GEN_BUFF_SIZE + MAX_INSTRUCTION_LEN] = {0};

				if(m_pMaxPEFile->ReadBuffer(byBuff, dwJmpOffset, XPAJ_GEN_BUFF_SIZE, XPAJ_GEN_BUFF_SIZE))
				{
					DWORD dwLength1 = 0x00, dwOffset1 = 0x00, dwInstCount = 0x00;
					int iMatchedInst = 0,iMatchedInstMov = 0;
					while(dwOffset1 < XPAJ_GEN_BUFF_SIZE && dwInstCount < 0x18)
					{
						dwLength1 = m_objMaxDisassem.Disasm((char *)&byBuff[dwOffset1], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
						if(dwLength1 > (XPAJ_GEN_BUFF_SIZE - dwOffset1))
						{
							break;
						}
						dwInstCount++;

						if(dwLength1 == 0x03 && strstr(da.result, "MOV "))
						{
							iMatchedInst++;							
						}
						else if(strstr(da.result,"MOV"))
						{
							iMatchedInstMov++;
						}						
						else if(((dwLength1 == 0x01 && byBuff[dwOffset1] == 0xC3 && strstr(da.result, "???") && iMatchedInst >= 2) ||
								(dwLength1 == 0x05 && strstr(da.result, "JMP") && iMatchedInst >= 1)) && dwInstCount <= 0x08)
						{
							dwCallOffset = dwOffset1 + dwLength1 + dwRVAJmpOffset;
							dwOffset1 = dwOffset1 + *(DWORD *)&byBuff[dwOffset1 + 1];							
							if(dwOffset1 <= XPAJ_GEN_BUFF_SIZE)
							{
								if(byBuff[dwOffset1] == 0xE8)
								{
									if(m_dwCalledAddRVA == (*(DWORD *)&byBuff[dwOffset1 + 1] + 5 + dwOffset1 + dwRVAJmpOffset))
									{
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Xpaj.Gen"));
										return true;
									}
								}
							}
							else if(strstr(da.result, "JMP"))
							{
								DWORD dwRVATemp = 0,dwTemp = 0;
								dwRVATemp = dwOffset1 + dwRVAJmpOffset;
								BYTE tempBuf[0x5] = {0};
								if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwRVATemp, &dwTemp))
								{
									if(m_pMaxPEFile->ReadBuffer(tempBuf,dwTemp,5,5))
									{
										if(tempBuf[0] == 0xE8)
										{
											if(m_dwCalledAddRVA == (*(DWORD *)&tempBuf[1] + 5 + dwOffset1 + dwRVAJmpOffset))
											{
												_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Xpaj.Gen"));
												return true;
											}
										}
									}
								}								
							}							
							dwFirstCallFlag = 0x01;							
							break;
						}
						else if((dwJmpflag == 0x00) && (dwLength1 == 0x01 && byBuff[dwOffset1] == 0xC3 && strstr(da.result, "???") && iMatchedInst >= 2) && dwInstCount > 0x8)
						{
							dwCallOffset = dwOffset1 + dwLength1 + dwRVAJmpOffset;
							dwJmpflag = 0x5;
							dwFirstCallFlag = 0x3;
							break;
						}
						else if((dwJmpflag == 0x00) && dwLength1 < 0x5 && strstr(da.result,"JMP") && (iMatchedInstMov >= 1 || iMatchedInst >= 1))
						{
							dwCallOffset = dwOffset1 + dwLength1 + dwRVAJmpOffset;
							dwJmpflag = 0x1;
							dwFirstCallFlag = 0x03;
							//break;
						}				
						else if(dwLength1 == 0x5 && strstr(da.result,"JMP"))
						{
							DWORD dwRVATemp = 0,dwTemp = 0;
							BYTE tempBuf[0x5] = {0};
							dwRVATemp = dwOffset1 + *(DWORD *)&byBuff[dwOffset1 + 1] + dwRVAJmpOffset;
							if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwRVATemp, &dwTemp))
							{
								if(dwInstCount <= 8 ||(dwInstCount >=0x8 && iMatchedInst >= 1) || (iMatchedInstMov >= 1) || dwJmpflag == 0x1 || dwJmpflag == 0x05)
								{									
									if(m_pMaxPEFile->ReadBuffer(tempBuf,dwTemp,5,5))
									{
										if(tempBuf[0] == 0xE8)
										{
											if(m_dwCalledAddRVA == (*(DWORD *)&tempBuf[1] + 5 + dwRVATemp))
											{
												_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Xpaj.Gen"));
												return true;
											}
										}
									}
								}								
							}
							break;
						}
						else if((dwLength1 == 0x5 || dwLength1 == 0x6) && strstr(da.result,"CALL"))
						{							
							break;
						}
						else if((dwLength1 == 0x01 && byBuff[dwOffset1] == 0xC3 && strstr(da.result, "???")))
						{
							break;
						}
						else if(dwInstCount >= 0x8 && ( strstr(da.result, "JE ") || strstr(da.result, "JZ ") || strstr(da.result, "JNZ ") ||
								 strstr(da.result, "JG ") || strstr(da.result, "JL ") || strstr(da.result, "JNB ")))
						{
							return false;
						}
						dwOffset1 += dwLength1;
					}					
				}
			}
			iStg++;
		}					
		else if (dwFirstCallFlag == 0x01 || dwJmpflag == 0x05 || dwJmpflag == 0x1)
		{
			if ((dwFirstCallFlag == 0x01) && (/*dwLength == 0x05 ||*/ dwLength == 0x06) && strstr(da.result, "CALL ") && iStg > 5)
			{
				return false;
			}
			else if((dwJmpflag == 0x05 || dwJmpflag == 0x01) && (dwLength == 6) && strstr(da.result,"CALL"))
			{
				return false;
			}
			else if( strstr(da.result, "JE ") || strstr(da.result, "JZ ") || strstr(da.result, "JNZ ") ||
				     strstr(da.result, "JG ") || strstr(da.result, "JL ") || strstr(da.result, "JNB ")&& iStg > 5)
			{
				return false;
			}
			else if ( (dwLength == 0x03 || dwLength == 0x05) && strstr(da.result, "MOV "))
			{
				iStg++;
			}
			else if ( dwLength == 0x05 && strstr(da.result, "JMP ") && iStg >= 5)     
			{

				DWORD dwRVAJmpOffset =  *(DWORD *)&pbyBuff[dwOffset + 0x01] + m_dwCalledAddRVA + dwOffset + 0x05;
				DWORD dwJmpOffset = 0x00;
				if(bJmpCheck == true)
				{
					dwRVAJmpOffset = *(DWORD *)&JmpbyBuff[dwOffset + 0x01] + dwJmpOffset1 + dwOffset + 0x05;
				}
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwRVAJmpOffset, &dwJmpOffset))
				{
					BYTE byBuff[XPAJ_GEN_BUFF_SIZE + MAX_INSTRUCTION_LEN] = {0};
					if(m_pMaxPEFile->ReadBuffer(byBuff, dwJmpOffset - 0x05, XPAJ_GEN_BUFF_SIZE, XPAJ_GEN_BUFF_SIZE))
					{
						if(byBuff[0] == 0xE8)
						{
							dwRVAJmpOffset = *(DWORD *)&byBuff[0x01] + dwRVAJmpOffset;
							if(dwRVAJmpOffset == m_dwCalledAddRVA || dwRVAJmpOffset == m_dwCalledAddRVA - 2)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Xpaj.Gen"));
								return true;
							}
						}
					}
				}
			}
			else if (strstr(da.result, "XOR "))
			{
				iXor++;
			}
			else if (strstr(da.result, "OR "))
			{
				iOr++;
			}
			else if ((dwFirstCallFlag == 0x1) && (((dwLength == 2 || dwLength == 3) && strstr(da.result, "JMP ") || (dwLength == 1 && strstr(da.result, "???"))))
				 && iStg >= 0x11 && m_dwInstCount >= 0x30 && (iXor >= 3 || iOr >= 3))     
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Xpaj.Gen"));
				return true;
			}
			else if((m_dwInstCount > 0x20) && strstr(da.result,"CALL") && (dwLength == 0x05))
			{
				DWORD dwTemp = (dwOffset + dwLength + *(DWORD *)&pbyBuff[dwOffset + 0x1] + m_dwCalledAddRVA);
				if(bJmpCheck == true)
				{
					dwTemp = (dwOffset + dwLength + *(DWORD *)&JmpbyBuff[dwOffset + 0x1] + dwJmpOffset1);
				}
				if((dwTemp - dwCallOffset) <= 0xA && (dwCallOffset != 0) && bCallCnt == 0)
				{
					bCallcheck = true;
				}
				else
				{
					return false;
				}
			}
			else if((bCallcheck == true) && (((dwLength == 2 || dwLength == 3) && strstr(da.result, "JMP ") || (dwLength == 1 && strstr(da.result, "???"))))
				 && iStg >= 0x11 && m_dwInstCount >= 0x30 && (iXor >= 3 || iOr >= 3))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Xpaj.Gen"));
				return true;
			}
			else if(strstr(da.result,"JMP") || (dwLength == 1 && strstr(da.result, "???")))
			{
				return false;
			}
			else if(strstr(da.result,"CALL") && dwLength == 5)
			{
				if(bCallcheck == true)
				{
					return false;
				}
				bCallCnt++;
			}
		}
		dwOffset += dwLength;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Repair routine for different varients of xpaj Family
--------------------------------------------------------------------------------------*/
int CPolyXpaj::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pbyBuff)
	{
		VirtualFree((void*)m_pbyBuff, 0, MEM_RELEASE);
		m_pbyBuff = NULL;
	}
	 
	if(m_pMaxPEFile->m_stPEHeader.DataDirectory[5].VirtualAddress != 0 && 
	   m_pMaxPEFile->m_stPEHeader.DataDirectory[5].Size != 0)
	{
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[5].VirtualAddress, &m_dwRelocStart))
		{
			m_dwRelocSize   = m_pMaxPEFile->m_stPEHeader.DataDirectory[5].Size;
			m_bRelocPresent = true;
		}
	}

	m_bImageSizeModified = false;
	if((m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData - m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize) > 0x4 &&
	   (m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData - m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize) < 0x1000)
	{
		m_bImageSizeModified = true;
		m_pMaxPEFile->m_stPEHeader.SizeOfImage += m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData - m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize;
		m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize = m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData;
	}

	WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
	iRetStatus = _CleanVirus();
	SetEvent(CPolymorphicVirus::m_hEvent);	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Repair routine for different varients of xpaj Family
--------------------------------------------------------------------------------------*/
int CPolyXpaj::_CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	
	CEmulate objEmulate(m_pMaxPEFile);
	if(!objEmulate.IntializeProcess())
	{
		return iRetStatus;
	}

	objEmulate.SetEip(m_dwCalledAddRVA + m_dwImageBase);
	objEmulate.SetNoOfIteration(0x200000);
	objEmulate.SetBreakPoint("__isinstruction('call e')");
	
	char szBreakPoint[1024] = {0};
	
	while(1)
	{
		if(7 == objEmulate.EmulateFile(false))
		{
			if(2 != objEmulate.GetInstructionLength())
			{
				continue;
			}
			if(objEmulate.GetDestinationOprand() < m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize + m_dwImageBase &&
			   objEmulate.GetDestinationOprand() >= m_pSectionHeader[m_wAEPSec].VirtualAddress + m_dwImageBase)
			{
				sprintf_s(szBreakPoint, 1024, "eip >= %d", objEmulate.GetDestinationOprand());
				objEmulate.ModifiedBreakPoint(szBreakPoint, 0);
				if(7 != objEmulate.EmulateFile(false))
				{
					continue;
				}
				if(!DecryptData(objEmulate))
				{
					m_pMaxPEFile->CloseFile_NoMemberReset();
					return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : iRetStatus;
				}
				if(!GetXpajType(objEmulate))
				{
					if((m_bDelete == 1) || (m_bDelete == 2))
					{
						m_pMaxPEFile->CloseFile_NoMemberReset();
						return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : iRetStatus;
					}
					return iRetStatus;
				}
				DWORD dwVirusStratOff  = 0;
				DWORD dwSecNo = m_pMaxPEFile->Rva2FileOffset(m_dwVirusStartRVA - m_dwImageBase, &dwVirusStratOff);
				if(dwSecNo == OUT_OF_FILE)
				{
					return iRetStatus;
				}
				if(dwVirusStratOff + m_dwVirusCodeSize > m_pSectionHeader[dwSecNo].PointerToRawData + m_pSectionHeader[dwSecNo].SizeOfRawData)
				{
					m_dwVirusCodeSize = m_pSectionHeader[dwSecNo].PointerToRawData + m_pSectionHeader[dwSecNo].SizeOfRawData - dwVirusStratOff; 
				}
				if(m_pMaxPEFile->FillWithZeros(dwVirusStratOff, m_dwVirusCodeSize))
				{
					if(m_bImageSizeModified)
					{
						m_pMaxPEFile->WriteSectionCharacteristic(m_wNoOfSections - 1, m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize, SEC_VS);
						m_pMaxPEFile->CalculateImageSize();
					}
					m_pMaxPEFile->CalculateChecksum();
					return REPAIR_SUCCESS;
				}
			}
		}
		else
		{    
			m_pMaxPEFile->CloseFile_NoMemberReset();
			return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : iRetStatus;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptData
	In Parameters	: CEmulate &objEmulate
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function decrypts the file buffer using Emulator.
					  This is point where emulation of virtual machine(VM) is stopped & first decryption begins.
                      Current Eip is at virus code which is called by VM. Data at Eip is already decrypted by emulator, now this
                      decrypted data decrypts virus code. First if (8B,44) is for decrypting data & else (83,C4) is to handle
                      files which already have decrypted data.
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::DecryptData(CEmulate &objEmulate)
{
	m_pbyBuff = (BYTE*)VirtualAlloc(NULL, XPAJ_GEN_VIRT_SIZE, MEM_COMMIT, PAGE_READWRITE);
	if(m_pbyBuff == NULL)
	{
		return false;
	}
	memset(m_pbyBuff, 0x00, XPAJ_GEN_VIRT_SIZE);
	DWORD dwXorKey = 0, dwAddKey = 0, dwCarry = 0, dwStoreCarry = 0, dwDecKey = 0;
	unsigned __int64 iDecKey = 0;
	DWORD dwEip = objEmulate.GetEip();
	objEmulate.ReadEmulateBuffer(m_pbyBuff, 0x40, dwEip);
	m_dwNoOfBytes = 0x40;
	
	DWORD dwLength = 0x00, dwOffset = 0x00, dwType = 0x00, dwJmpOff = 0x00;
	BYTE byRor = 0;
	t_disasm da = {0};
	while(dwOffset < m_dwNoOfBytes)
	{
		memset(&da, 0x00, sizeof(t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		dwOffset += dwLength;

		if(strstr(da.result, "RCL E") && strstr(da.result, ",CL"))
		{
			dwType++;
			continue;
		}
		if(strstr(da.result, "ROR EDX") && dwLength == 2 && (dwType == 0))//added
		{
			dwType = 3;
			continue;
		}
		if(strstr(da.result, "XOR E") && dwLength == 0x06)
		{
			dwType++;
			dwXorKey = *(DWORD *)&m_pbyBuff[dwOffset - dwLength + 2];
			break;
		}
		if(strstr(da.result, "JMP") && dwLength == 0x05)
		{
			dwJmpOff = *(DWORD *)&m_pbyBuff[dwOffset -dwLength + 1] + dwEip + dwOffset;
		}
		if(m_pbyBuff[dwOffset-dwLength] == 0xC2 && m_pbyBuff[dwOffset-dwLength+1] == 0x14)
		{
			break;
		}
	}
	
	if(m_pbyBuff[0x0] == 0x8B && m_pbyBuff[0x01] == 0x44)
	{
		objEmulate.ReadEmulateBuffer(m_pbyBuff, 0x20 + 0x04, objEmulate.GetSpecifyRegValue(4)); 
		m_dwDecStartRVA		= *(DWORD *)&m_pbyBuff[0x04];
		m_dwDecSize			= *(DWORD *)&m_pbyBuff[0x08];
		iDecKey				= *(DWORD *)&m_pbyBuff[0x0C];
		dwAddKey			= *(DWORD *)&m_pbyBuff[0x10];
		m_dwVirusCodeSize	= *(DWORD *)&m_pbyBuff[0x18];
		m_dwVirusStartRVA	= *(DWORD *)&m_pbyBuff[0x1C];
		DWORD dwFisrtVal	= *(DWORD *)&m_pbyBuff[0x14];
		DWORD dwDecStartOff = 0;
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwDecStartRVA - m_dwImageBase, &dwDecStartOff))
		{
			if(!GetBuffer(dwDecStartOff, m_dwDecSize * 0x04, m_dwDecSize * 0x04))
			{
				return false;
			}
			DWORD dwTempDecSize =  m_dwDecSize;
			for(DWORD dwCnt = 0; dwCnt < m_dwDecSize; dwCnt++)
			{
				if(dwCnt == 0)
				{
					*(DWORD *)&m_pbyBuff[0] = dwFisrtVal;
				}
				else
				{
					*(DWORD *)&m_pbyBuff[dwCnt * 0x04] ^=  dwDecKey;
				}
				iDecKey = iDecKey + (unsigned __int64 )(dwAddKey);
				dwDecKey = (DWORD)iDecKey;
				if(dwType == 0x02)
				{
					dwStoreCarry = (DWORD)(iDecKey / 0x100000000);
					if (dwStoreCarry >= 0x01)
					{
						dwStoreCarry = 0x01;
					}
					else
					{
						dwStoreCarry = 0;
					}
					
					for ( DWORD dwRot = 0; dwRot < ((BYTE)dwTempDecSize % 32); dwRot++)
					{
						if (dwRot != 0)
						{
							dwStoreCarry = dwCarry;
						}
						dwCarry = dwDecKey & 0X80000000;
						dwDecKey = dwDecKey << 1;
						if(dwStoreCarry > 0x00)
						{
							dwDecKey = dwDecKey | 0x01;
						}
					}
					dwDecKey ^=  dwXorKey;
				}
				else if(dwType == 4)//added
				{
					dwDecKey = _lrotr(dwDecKey,1);
					dwDecKey ^= dwXorKey;
				}
				iDecKey = dwDecKey;
				dwTempDecSize--;
			}
		}
	}
	else
	{
		return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetXpajType
	In Parameters	: CEmulate &objEmulate
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: This function determines the type of infection
					  There are 3 types of infection
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::GetXpajType(CEmulate &objEmulate)
{
	m_dwInfectionType = 0;
	DWORD dwCnt  = 0;
	if((m_pbyBuff[0x00] == 0x60 && m_pbyBuff[0x01] == 0xE8 && m_pbyBuff[0x02] == 0x00 &&
	   m_pbyBuff[0x03] == 0x00 && m_pbyBuff[0x04] == 0x00 && m_pbyBuff[0x05] == 0x00) || (m_pbyBuff[0x00] == 0xE9 && m_pbyBuff[0x01] == 0x08 && m_pbyBuff[0x02] == 0x00 &&
	   m_pbyBuff[0x03] == 0x00 && m_pbyBuff[0x04] == 0x00 && m_pbyBuff[0x05] == 0xE9))//checking(either push,call or 2 jumps)
	{
		m_dwInfectionType = 3; //Xpaj.GenA , Xpaj.GenB and Xpaj.GenC
	}
	if(!m_dwInfectionType)
	{
		for(dwCnt = 0; dwCnt < m_dwDecSize * 4; dwCnt++)
		{
			if(m_pbyBuff[dwCnt] == 0xE8 && m_pbyBuff[dwCnt + 0x05] == 0xFF && m_pbyBuff[dwCnt + 0x06] == 0x34 &&
				m_pbyBuff[dwCnt + 0x07] == 0x24 && m_pbyBuff[dwCnt + 0x08] == 0xE8 && m_pbyBuff[dwCnt + 0x0D] == 0xC3)
			{
				m_dwInfectionType = 1; //Xpaj.Gen and Xpaj.A
				break;
			}
		}
	}
	if(m_dwInfectionType == 1)
	{
		if(CheckVirusTypeGen(objEmulate, dwCnt))
		{
			return true;
		}
	}
	else if(m_dwInfectionType == 3)
	{
		if(CheckVirusTypeGenA(objEmulate, dwCnt))
		{
			return true;
		}
	}

	m_pMaxPEFile->CloseFile_NoMemberReset();
	return DeleteFile(m_pMaxPEFile->m_szFilePath) ? true : false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckVirusTypeGenA
	In Parameters	: CEmulate &objEmulate, DWORD dwCnt
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: This function determines the type of infection
					  GenA
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::CheckVirusTypeGenA(CEmulate &objEmulate, DWORD dwCnt)
{
	if(!objEmulate.WriteBuffer(m_pbyBuff, m_dwDecSize*4, m_dwDecStartRVA, true))
	{
		return false;
	}
	DWORD dwCallCnt = 0, dwOffset = dwCnt, dwLength = 0, dwMovCnt = 0, dwRetVal = 0, dwRetOffset = 0, dwBuffIndex = 0;
	t_disasm da = {0};
	bool bStartDec = false;
	int iValidIns = 0;
	
	BYTE *byBuff = new BYTE[XPAJ_DECRYPT1_BUFF];
	memset(byBuff, 0, XPAJ_DECRYPT1_BUFF);

	while(dwOffset < m_dwNoOfBytes)
	{
		if(m_dwInstCount > 0x100)
		{
			break;
		}
		memset(&da, 0x00, sizeof(t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		m_dwInstCount++;
		if(strstr(da.result, "CALL ") && dwLength == 5 && 
		  (iValidIns == 0  || iValidIns == 4 || iValidIns == 8 || iValidIns == 10 || iValidIns == 11 || iValidIns == 13 || 
		   iValidIns == 14 || iValidIns == 15))
		{
			iValidIns++;
			if(dwCallCnt == 0)
			{
				m_dwKeyA = *(DWORD *)&m_pbyBuff[dwOffset + 1] + 0x05 + dwOffset + m_dwDecStartRVA;
				dwCallCnt++;
			}
			else if(dwCallCnt == 1 || dwCallCnt == 7 || dwCallCnt == 8)
			{
				if(dwCallCnt == 8)
				{
					dwRetVal = dwOffset + 5 + dwCnt + m_dwDecStartRVA;
					bStartDec = true;
				}
				else if(dwCallCnt == 7)
				{
					dwRetOffset = dwOffset + 5;
				}
				dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] + 0x05 + dwOffset;
				dwCallCnt++;
				continue;
			}
			else
			{
				dwCallCnt++;
			}
		}
		else if(strstr(da.result, "CLD") && dwLength == 1 && iValidIns == 16)
		{
			break;
		}
		else if(strstr(da.result, "SUB EDI,") && dwLength == 6 && m_dwKeyA != 0 && dwCallCnt == 1 && iValidIns == 1)
		{
			iValidIns++;
			m_dwKeyA = m_dwKeyA - *(DWORD *)&m_pbyBuff[dwOffset + 2];
		}
		else if(strstr(da.result, "XOR EDI,EDI") && dwLength == 2 && m_dwKeyA != 0)
		{
			m_dwKeyA = 0;
			iValidIns--;
		}
		else if(strstr(da.result, "ADD EDI,") && dwLength == 6 && m_dwKeyA == 0)
		{
			m_dwKeyA = *(DWORD *)&m_pbyBuff[dwOffset + 2];
			iValidIns++;
		}
		else if(strstr(da.result, "MOV EAX,") && dwLength == 5 && 
			   (iValidIns == 2 || iValidIns == 3 || iValidIns == 5 || iValidIns == 6 || iValidIns == 7 || 
				iValidIns == 9 || iValidIns == 12))
		{
			iValidIns++;
			if(dwMovCnt == 2)
			{
				m_dwFirstKeyA = *(DWORD *)&m_pbyBuff[dwOffset + 1];
			}
			else if(dwMovCnt == 3)
			{
				m_dwSecondKeyA = *(DWORD *)&m_pbyBuff[dwOffset + 1];
			}
			else if(dwMovCnt == 4)
			{
				m_dwCounter1A = *(DWORD *)&m_pbyBuff[dwOffset + 1];
			}
			else if(dwMovCnt == 5)
			{
				m_dwCopyStartA = *(DWORD *)&m_pbyBuff[dwOffset + 1];
			}
			else if(dwMovCnt == 6)
			{
				m_dwCounter2A = *(DWORD *)&m_pbyBuff[dwOffset + 1];
			}
			dwMovCnt++;
		}
		if(m_dwCounter1A > XPAJ_DECRYPT1_BUFF)
		{
			return false;
		}
		if(dwCallCnt == 4)
		{
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwCopyStartA, &m_dwCopyStartA))
			{
				if(0x10000 > m_dwCounter1A)
				{
					if(!m_pMaxPEFile->ReadBuffer(byBuff, m_dwCopyStartA, m_dwCounter1A, m_dwCounter1A))
					{
						if(byBuff)
						{
							delete[] byBuff;
							byBuff = NULL;
						}
						return false;
					}
				}
			}
			if(!DecryptGenA1(byBuff))
			{
				if(byBuff)
				{
					delete[] byBuff;
					byBuff = NULL;
				}
				return false;
			}
			dwCallCnt++;
		}
		dwOffset += dwLength;
	}
	if((dwCallCnt == 9) && bStartDec)
	{
		DWORD dwStackStart = objEmulate.GetSpecifyRegValue(4);
		BYTE byStack[0x50] = {0};
		BYTE *byBuff2 = new BYTE[XPAJ_DECRYPT2_BUFF];
		if(!byBuff2)
		{
			return false;
		}
		
		memset(byBuff2, 0, XPAJ_DECRYPT2_BUFF);

		m_dwFirstAllocAddress	= objEmulate.AddVirtualPointer((DWORD)byBuff, 1, XPAJ_DECRYPT1_BUFF);
		m_dwSecondAllocAddress	= objEmulate.AddVirtualPointer((DWORD)byBuff2, 2, XPAJ_DECRYPT2_BUFF);

		UpdateStack(byStack, dwRetVal, dwStackStart);

		//APLIB Decompression
		DWORD dwOut = aP_depack_safe(byBuff, *(DWORD*)&byStack[4], byBuff2, *(DWORD*)&byStack[0], 0, NULL);
		if(dwOut==0xFFFFFFFF || dwOut<*(DWORD*)&byStack[0])
		{
			if(byBuff2)
			{
				delete[] byBuff2;
				byBuff2=NULL;
			}

			if(byBuff)
			{
				delete[] byBuff;
				byBuff = NULL;
			}
			return false;
			
		}

		objEmulate.WriteBuffer(byStack, 0x50, dwStackStart);
		UpdateRegisters(objEmulate, dwStackStart);

		//if(7 == objEmulate.EmulateFile(false))
		{
			if(byBuff)
			{
				delete[] byBuff;
				byBuff = NULL;
			}
			dwOffset = dwRetOffset;
			m_dwInstCount = 0;
			while(dwOffset < m_dwNoOfBytes)
			{
				if(m_dwInstCount > 0x8)
				{
					break;
				}
				memset(&da, 0x00, sizeof(t_disasm));
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				m_dwInstCount++;
				if(strstr(da.result, "MOV EAX,") && dwLength == 5)
				{
					dwBuffIndex = da.immconst;
					*(DWORD *)&byBuff2[0x04] = m_dwImageBase;
					break;
				}
				dwOffset += dwLength;
			}
			if(GetKeysXpajGenA(objEmulate, dwBuffIndex, byBuff2))
			{
				if(DecryptBuffXpajGenA(byBuff2, 0x10, m_dwArrStart - m_dwSecondAllocAddress, byBuff2))
				{
					m_dwEAX = *(DWORD *)&byBuff2[m_dwEBX + 4 - m_dwSecondAllocAddress];
					m_dwEBX = *(DWORD *)&byBuff2[m_dwEBX - m_dwSecondAllocAddress];
					memset(m_pbyBuff, 0, m_dwDecSize * 4);
					if(m_dwEAX > XPAJ_GEN_VIRT_SIZE)
					{
						m_pMaxPEFile->CloseFile_NoMemberReset();
						return DeleteFile(m_pMaxPEFile->m_szFilePath) ? true : false;
					}
					objEmulate.ReadEmulateBuffer(m_pbyBuff, m_dwEAX, m_dwEBX + m_dwImageBase);

					if(DecryptBuffXpajGenA(byBuff2, m_dwEAX, 0, m_pbyBuff))
					{
						DWORD dwTempOff = 0;
						if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwEBX, &dwTempOff))
						{
							if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, dwTempOff, m_dwEAX, m_dwEAX))
							{
								m_dwEAX = m_dwEBX;
								if(DecryptTableXpajA(1))
								{
									if(byBuff2)
									{
										delete[] byBuff2;
										byBuff2 = NULL;
									}									
									return true;
								}
							}
						}
					}
				}
			}
		}
		if(byBuff2)
		{
			delete[] byBuff2;
			byBuff2 = NULL;
		}	
	}
	if(byBuff)
	{
		delete[] byBuff;
		byBuff = NULL;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptBuffXpajGenA
	In Parameters	: LPBYTE byBuffer, DWORD dwDecCnt, DWORD dwTemp, LPBYTE byTableBuffer
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Decryption routine for GenA
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::DecryptBuffXpajGenA(LPBYTE byBuffer, DWORD dwDecCnt, DWORD dwTemp, LPBYTE byTableBuffer)
{
	DWORD dwEAX = 0, dwEBX = 0, dwECX = 0, dwEDX = 0, dwEDI = 0, dwESI = 0, dwDivident = 0;
	BYTE byEAX[4] = {0};
	BYTE byEDX[4] = {0};
	dwESI = m_dwECX  - m_dwSecondAllocAddress;
	for(DWORD dwCnt = 0; dwCnt <= dwDecCnt; dwCnt++)
	{
		dwEAX = 0xFFFFFFFF;
		dwEDI = dwEAX * 0x64;
		dwEAX = *(DWORD *)&byBuffer[dwESI];
		dwEAX = dwEAX << 0x0B;
		dwEAX = dwEAX ^ (*(DWORD *)&byBuffer[dwESI]);
		//push,call,ret

		dwEDX = *(DWORD *)&byBuffer[dwESI + 0x04];
		*(DWORD *)&byBuffer[dwESI] += dwEDX;
		dwECX = *(DWORD *)&byBuffer[dwESI + 0x08];
		*(DWORD *)&byBuffer[dwESI + 0x04] += dwECX;
		//push,call,ret

		dwEBX = *(DWORD *)&byBuffer[dwESI + 0x0C];
		*(DWORD *)&byBuffer[dwESI + 0x08] += dwEBX;
		dwEBX = dwEBX >> 0x13;
		dwEBX = dwEBX ^ (*(DWORD *)&byBuffer[dwESI + 0x0C]);
		dwEBX = dwEBX ^ dwEAX;
		dwEAX = dwEAX >> 0x08;
		dwEBX = dwEBX ^ dwEAX;
		*(DWORD *)&byBuffer[dwESI + 0x0C] = dwEBX;
		dwEAX = dwEBX;
		dwEAX += dwECX;
		dwEDX = 0;

		//DIV EDI
		dwDivident = dwEAX;
		dwEAX = dwEAX / dwEDI;
		dwEAX = dwDivident - (dwEAX * dwEDI);
		
		//push,call,ret
		dwEDI = dwEDI >> 0x01;
		dwEDI = dwEDI >> 0x1F;
		dwEDI = ~dwEDI;
		dwEDI = dwEDI & 0x64;
		dwEAX = dwEAX / dwEDI;

		if(dwCnt != 0)
		{
			dwEDX = *(DWORD *)&byEDX[0];
			dwEDX += dwEAX;
			dwTemp++;
		}
		else
		{
			dwEDX = dwEAX;
		}

		*(DWORD *)&byEAX[0] = dwEAX;
		*(DWORD *)&byEDX[0] = dwEDX;
		byEAX[0] =  byTableBuffer[dwTemp];
		byEAX[0] = byEAX[0] ^ byEDX[0];
		byTableBuffer[dwTemp] = byEAX[0];
		byEDX[0] = byEDX[0] + byEAX[0];
		if(dwCnt != dwDecCnt)
		{
			byBuffer[dwESI] += byEAX[0]; 
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKeysXpajGenA
	In Parameters	: LPBYTE byBuffer, DWORD dwDecCnt, DWORD dwTemp, LPBYTE byTableBuffer
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Search "lea ecx ,dword ptr [ebx" in call-push-call's first call to get m_dwKeyA,
                      then go to second call - debug upto JE (flag to check data decrypted or not) - then search for
                      "MOV DWORD PTR [ESP ( ] / +" followed by Push 10 (6A 10) to get m_dwECX ( = data + m_dwKeyA),
                      then again go to JE & this time take jmp & search for "MOV ESI,[" to get m_dwEBX & 
                      "MOV EDI,[" to get m_dwArrStart
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::GetKeysXpajGenA(CEmulate &objEmulate, DWORD dwBuffIndex, LPBYTE byBuffer)
{
	bool bNotRepaired = false,bEcxFound = false;
	objEmulate.PauseBreakPoint(0);
	objEmulate.SetNoOfIteration(0x200);
	objEmulate.SetBreakPoint("__isinstruction('lea ecx ,dword ptr [ebx')");         //breakpoint 2
	objEmulate.SetEip(m_dwSecondAllocAddress + dwBuffIndex);
	while(1)
	{
		if(7 == objEmulate.EmulateFile(false))
		{
			if(6 != objEmulate.GetInstructionLength())
			{
				continue;
			}
			else
			{
				m_dwKeyA = objEmulate.GetSpecifyRegValue(3); 
				break;
			}
		}
		else
		{
			m_bDelete = 1;
			return false;
		}
	}
	
	objEmulate.PauseBreakPoint(1);
	objEmulate.SetBreakPoint("__isinstruction('ret')");                                //breakpoint 3
	
	DWORD dwOffset = dwBuffIndex, dwLength = 0, dwEAXConst = 0, dwValidIns = 0, dwRetOffset = 0, dwCallCnt = 0;
	bool bCountFound = false;
	t_disasm da = {0};
	m_dwInstCount = 0;
	while(dwOffset < m_dwCounter2A)
	{
		if(m_dwInstCount > 0x200)
		{
			break;
		}
		memset(&da, 0x00, sizeof(t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char *)&byBuffer[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		m_dwInstCount++;
		if((bNotRepaired == true) && dwLength == 6 && strstr(da.result,"SUB ESI,"))
		{
			for (DWORD dwCnt = dwOffset; dwCnt < dwOffset + 0x20; dwCnt++)
			{
				if(byBuffer[dwCnt] == 0x6A && byBuffer[dwCnt + 1] == 0x10)
				{
					m_dwECX = *(DWORD *)&byBuffer[dwOffset + 2] + m_dwKeyA;
					bEcxFound = true;
					break;
				}
			}
			if(bEcxFound = true)
			{
				dwOffset = dwRetOffset;
				continue;
			}
		}
		else if((bNotRepaired == true) && dwLength == 6 && (strstr(da.result,"AND EAX,") || ((strstr(da.result,"XOR EAX,") && ((*(DWORD *)&byBuffer[dwOffset + 2] + m_dwKeyA) > m_dwSecondAllocAddress) && ((*(DWORD *)&byBuffer[dwOffset + 2] + m_dwKeyA) < (m_dwSecondAllocAddress + 0x10000))))))
		{
			DWORD dwCnt = 0;
			for (dwCnt = dwOffset; dwCnt < dwOffset + 0x20; dwCnt++)
			{
				if(byBuffer[dwCnt] == 0x6A && byBuffer[dwCnt + 1] == 0x10)
				{
					m_dwECX = *(DWORD *)&byBuffer[dwOffset + 2] + m_dwKeyA;
					bEcxFound = true;
					break;
				}
			}
			if((bEcxFound == true) && byBuffer[dwCnt + 2] == 0x68)
			{
				m_dwArrStart = *(DWORD *)&byBuffer[dwCnt + 3] + m_dwKeyA;
				m_dwEBX = m_dwArrStart + 0x08;
				return true;
			}
			else if(bEcxFound == true)
			{
				dwOffset = dwRetOffset;
				continue;
			}
		}		
		else if(strstr(da.result, "CALL ") && dwLength == 5)
		{
			if(dwCallCnt == 0)
			{
				dwCallCnt++;
				dwOffset = dwOffset + 0x05;
			}
			else if(byBuffer[dwOffset-5] == 0x68)
			{
				DWORD dwOldOffset = dwOffset - 5 + m_dwSecondAllocAddress;
				dwOffset += *((DWORD*)&byBuffer[dwOffset + 1]) + 0x05;
				if(dwOffset < m_dwCounter2A && byBuffer[dwOffset] == 0x9C)
				{
					objEmulate.SetEip(dwOldOffset);
					if(7 != objEmulate.EmulateFile(false))
					{
						break;
					}
					objEmulate.ReadEmulateBuffer((BYTE*)&dwEAXConst, 4, objEmulate.GetSpecifyRegValue(4));
					dwOffset = dwEAXConst - m_dwSecondAllocAddress;
				}
			}
			else
			{
				dwOffset = dwOffset + 0x05 + *(DWORD *)&byBuffer[dwOffset + 1];
			}
			continue;
		}
		else if(strstr(da.result, "JE ") && dwLength == 6)
		{
			dwRetOffset = dwOffset + dwLength + *(DWORD *)&byBuffer[dwOffset + 2];
			dwValidIns++;
		}
		else if(strstr(da.result, "JMP ") && dwLength == 5)
		{
			dwOffset = dwOffset + 0x05 + *(DWORD *)&byBuffer[dwOffset + 1];
			dwValidIns++;
			continue;
		}
		else if(strstr(da.result, "PUSH") && dwLength == 5)
		{
			if(byBuffer[dwOffset + 5] == 0x6A && byBuffer[dwOffset + 6] == 0x10)
			{
				m_dwECX = *(DWORD *)&byBuffer[dwOffset + 1] + m_dwKeyA;
				dwOffset = dwRetOffset;
				continue;
			}
			else if(bNotRepaired == true && (byBuffer[dwOffset + 0x5] == 0xE9) && ((*(DWORD *)&byBuffer[dwOffset + 6] + dwOffset) < 0xF000))
			{
				DWORD dwTempOffset = dwOffset + (*(DWORD *)&byBuffer[dwOffset + 6]) + 0xA;
				if(byBuffer[dwTempOffset] == 0x6A && byBuffer[dwTempOffset + 1] == 0x10)
				{
					m_dwECX = *(DWORD *)&byBuffer[dwOffset + 1] + m_dwKeyA;					
					dwOffset = dwRetOffset;
					continue;
				}
			}
			else if(byBuffer[dwOffset + 0x05] == 0x68 && byBuffer[dwOffset + 0x0A] == 0xE8)
			{
				DWORD dwTempOffset = dwOffset; 
				DWORD dwOldOffset = dwOffset + 5 + m_dwSecondAllocAddress;
				dwTempOffset += *((DWORD*)&byBuffer[dwTempOffset + 0x0B]) + 0x0A + 0x05;
				if(dwOffset < m_dwCounter2A && byBuffer[dwTempOffset] == 0x9C)
				{
					objEmulate.SetEip(dwOldOffset);
					if(7 != objEmulate.EmulateFile(false))
					{
						break;
					}
					objEmulate.ReadEmulateBuffer((BYTE*)&dwEAXConst, 4, objEmulate.GetSpecifyRegValue(4));
					dwTempOffset = dwEAXConst - m_dwSecondAllocAddress;
					if(byBuffer[dwTempOffset] == 0x6A && byBuffer[dwTempOffset + 1] == 0x10)
					{
						m_dwECX = *(DWORD *)&byBuffer[dwOffset + 1] + m_dwKeyA;
						dwOffset = dwRetOffset;
						continue;
					}
				}
			}
		}
		else if(strstr(da.result, "MOV DWORD PTR [ESP],") && dwLength == 7)
		{
			if(byBuffer[dwOffset + 7] == 0x6A && byBuffer[dwOffset + 8] == 0x10)
			{
				m_dwECX = *(DWORD *)&byBuffer[dwOffset + 3] + m_dwKeyA;
				dwOffset = dwRetOffset;
				continue;
			}
		}
		else if(strstr(da.result, "MOV DWORD PTR [ESP+") && dwLength == 8)
		{
			for (DWORD dwCnt = dwOffset; dwCnt < dwOffset + 0x20; dwCnt++)
			{
				if(byBuffer[dwCnt] == 0x6A && byBuffer[dwCnt + 1] == 0x10)
				{
					m_dwECX = *(DWORD *)&byBuffer[dwOffset + 4] + m_dwKeyA;
					dwOffset = dwRetOffset;
					bCountFound = true;
					break;
				}
			}
			if(bCountFound)
			{
				bCountFound = false;
				continue;
			}
		}
		else if(dwValidIns >= 0x02 && strstr(da.result, "MOV ESI,[") && dwLength == 6)
		{
			m_dwEBX = *(DWORD *)&byBuffer[dwOffset + 2] + m_dwKeyA;
			dwValidIns++;
		}
		else if(dwValidIns >= 0x03 && strstr(da.result, "MOV EDI,[") && dwLength == 6)
		{
			m_dwArrStart = *(DWORD *)&byBuffer[dwOffset + 2] + m_dwKeyA;
			return true;
		}
		else if(strstr(da.result,"CMP EAX,1") && m_dwCounter1A > 0xA000 && (byBuffer[dwOffset + dwLength] == 0x0F) && (byBuffer[dwOffset + dwLength + 1] == 0x84))
		{
			bNotRepaired = true;			
		}
		dwOffset += dwLength;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: UpdateRegisters
	In Parameters	: CEmulate &objEmulate, DWORD dwStackStart
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Reinitialize register value of Emulator
--------------------------------------------------------------------------------------*/
void CPolyXpaj::UpdateRegisters(CEmulate &objEmulate, DWORD dwStackStart)
{
	objEmulate.UpdateSpecifyReg(0, m_dwCounter1A);
	objEmulate.UpdateSpecifyReg(1, m_dwCounter2A);
	objEmulate.UpdateSpecifyReg(2, m_dwCounter2A);
	objEmulate.UpdateSpecifyReg(3, m_dwFirstAllocAddress);
	objEmulate.UpdateSpecifyReg(4, dwStackStart);
	objEmulate.UpdateSpecifyReg(5, dwStackStart + 0x50);
	objEmulate.UpdateSpecifyReg(6, m_dwFirstAllocAddress);
	objEmulate.UpdateSpecifyReg(7, m_dwSecondAllocAddress);
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: UpdateStack
	In Parameters	: LPBYTE byStackArr, DWORD dwRetVal, DWORD dwStackStart
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Reinitialize Stack
--------------------------------------------------------------------------------------*/
void CPolyXpaj::UpdateStack(LPBYTE byStackArr, DWORD dwRetVal, DWORD dwStackStart)
{
	*(DWORD *)&byStackArr[0x00] = m_dwCounter2A;
	*(DWORD *)&byStackArr[0x04] = m_dwCounter1A;
	*(DWORD *)&byStackArr[0x08] = m_dwKeyA;
	*(DWORD *)&byStackArr[0x0C] = m_dwImageBase;
	*(DWORD *)&byStackArr[0x10] = dwStackStart + 0x50;
	*(DWORD *)&byStackArr[0x14] = dwStackStart + 0x28;
	*(DWORD *)&byStackArr[0x18] = m_dwFirstAllocAddress;
	*(DWORD *)&byStackArr[0x1C] = m_dwCounter2A;
	*(DWORD *)&byStackArr[0x20] = m_dwCounter1A;
	*(DWORD *)&byStackArr[0x24] = m_dwSecondAllocAddress;
	*(DWORD *)&byStackArr[0x28] = dwRetVal;
	*(DWORD *)&byStackArr[0x2C] = m_dwFirstAllocAddress;
	*(DWORD *)&byStackArr[0x30] = m_dwCounter1A;
	*(DWORD *)&byStackArr[0x34] = m_dwSecondAllocAddress;
	*(DWORD *)&byStackArr[0x38] = m_dwCounter2A;
	*(DWORD *)&byStackArr[0x3C] = m_dwCounter2A;
	*(DWORD *)&byStackArr[0x40] = m_dwKeyA;
	*(DWORD *)&byStackArr[0x44] = m_dwFirstAllocAddress;
	*(DWORD *)&byStackArr[0x48] = m_dwCounter1A;
	*(DWORD *)&byStackArr[0x4C] = m_dwImageBase;
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptGenA1
	In Parameters	: LPBYTE byBuffer
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Decryption routine for xpaj type 1
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::DecryptGenA1(LPBYTE byBuffer)
{
	DWORD dwESI = 0, dwEDI = m_dwSecondKeyA;
	BYTE byEBX[4] = {0};
	BYTE byEDX[4] = {0};
	*(DWORD *)&byEBX[0] = m_dwFirstKeyA;
	for(dwESI = 0; dwESI < m_dwCounter1A; dwESI++)
	{
		byEBX[0]			+= byEDX[0];
		byBuffer[dwESI]		^= byEBX[0];
		byEDX[0]	     	 = byBuffer[dwESI];
		*(DWORD *)&byEBX[0] += dwEDI;
		*(DWORD *)&byEBX[0]  = _lrotl(*(DWORD *)&byEBX[0], 8); 
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckVirusTypeGen
	In Parameters	: CEmulate &objEmulate, DWORD dwCnt
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Validation for for xpaj type 1
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::CheckVirusTypeGen(CEmulate &objEmulate, DWORD dwCnt)
{
	m_dwInfectionType = 0;
	if(!objEmulate.WriteBuffer(m_pbyBuff, m_dwDecSize*4, m_dwDecStartRVA, true))
	{
		return false;
	}
	objEmulate.SetEip(m_dwDecStartRVA + dwCnt);
	objEmulate.SetNoOfIteration(150);
	objEmulate.PauseBreakPoint(0);
	objEmulate.SetBreakPoint("__isinstruction('add ecx ,1')");                          //breakpoint 1
	objEmulate.SetBreakPoint("__isinstruction('call')");                                //breakpoint 2
	if(7 != objEmulate.EmulateFile(false))
	{
		m_bDelete = 1;
		return false;
	}
	BYTE byCheckInstruction[2] = {0};
	while(1)
	{
		if(7 == objEmulate.EmulateFile(false))
		{
			char szInstruction[1024];
			objEmulate.GetInstruction(szInstruction);
			if(strstr(szInstruction, "call"))
			{
				if(objEmulate.ReadEmulateBuffer(byCheckInstruction, 0x02, objEmulate.GetEip() + 0x05))
				{
					if((byCheckInstruction[0] == 0x89 || byCheckInstruction[1] == 0xC3))
					{
						m_dwInfectionType = 2;
						break;
					}
					else
					{
						continue;
					}
				}
			}
			else if(strstr(szInstruction, "add ecx"))
			{
				m_dwInfectionType = 1;
				break;
			}
		}
		else
		{
			m_bDelete = 1;
			return false;
		}
	}
	if(m_dwInfectionType == 1)
	{
		if(CleanXpajGen(objEmulate, dwCnt))
		{
			if(GetEAX())
			{
				if(DecryptTableGen())
				{
					return true;
				}
			}
		}
	}
	else if(m_dwInfectionType == 2)
	{
		if(CleanXpajA(objEmulate, dwCnt))
		{
			if(GetEAX())
			{
				if(DecryptTableXpajA(0))
				{
					return true;
				}
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanXpajGen
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for xpaj type1
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::CleanXpajGen(CEmulate &objEmulate, DWORD dwCnt)
{
	objEmulate.SetNoOfIteration(150);
	objEmulate.PauseBreakPoint(1);
	objEmulate.PauseBreakPoint(2);
	objEmulate.SetBreakPoint("__isinstruction('ret')");                                 //breakpoint 3
	DWORD dwEAX = 0;
	while(1)
	{
		if(7 == objEmulate.EmulateFile(false))
		{
			if(objEmulate.GetInstructionLength() == 0x01)
			{
				dwEAX = objEmulate.GetSpecifyRegValue(0);
				break;
			}
		}
		else
		{
			return false;
		}
	}

	objEmulate.SetNoOfIteration(200);
	objEmulate.PauseBreakPoint(3);
	objEmulate.SetBreakPoint("__isinstruction('lea ecx ,dword ptr [ebx')");             //breakpoint 4
	while(1)
	{
		if(7 == objEmulate.EmulateFile(false))
		{
			if(objEmulate.GetInstructionLength() == 0x06)
			{
				m_dwECX = objEmulate.GetMemoryOprand();
				break;
			}
		}
		else
		{
			return false;
		}
	}
	
	objEmulate.SetNoOfIteration(300);
	objEmulate.PauseBreakPoint(4);
	objEmulate.SetBreakPoint("__isinstruction('mov ebx ,eax')");                        //breakpoint 5
	objEmulate.SetBreakPoint("__isinstruction('and ebx ,dword ptr [e')");               //breakpoint 6
	objEmulate.SetBreakPoint("__isinstruction('and ebx ,eax')");
	if(7 == objEmulate.EmulateFile(false))
	{
		m_dwFirstKey = objEmulate.GetSpecifyRegValue(0);
	}
	else
	{
		return false;
	}
	objEmulate.SetNoOfIteration(30);
	objEmulate.PauseBreakPoint(5);
	objEmulate.PauseBreakPoint(6);
	objEmulate.PauseBreakPoint(7);
	objEmulate.SetBreakPoint("__isinstruction('mov edx ,eax')");                        //breakpoint 7
	objEmulate.SetBreakPoint("__isinstruction('sub edx ,eax')");						 //breakpoint 8
	if(7 == objEmulate.EmulateFile(false))
	{
		m_dwSecondKey = objEmulate.GetSpecifyRegValue(0);
	}
	else
	{
		return false;
	}

	objEmulate.PauseBreakPoint(8);
	objEmulate.PauseBreakPoint(9);
	objEmulate.SetBreakPoint("__isinstruction('ret 4')");
	objEmulate.SetNoOfIteration(100);
	DWORD dwOffset = dwCnt + 8;
	m_dwNoOfBytes = m_dwDecSize*4;
	DWORD dwEAXConst = 0, dwPushValue = 0;
	m_dwInstCount = 0;
	m_dwEBX = 0;
	bool bZeroFlag = false, bFlag = false;
	t_disasm da = {0};
	while(dwOffset < m_dwNoOfBytes)
	{
		if(m_dwInstCount > 80)
		{
			break;
		}
		DWORD dwLength = 0x00;
		memset(&da, 0x00, sizeof(t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		dwOffset += dwLength;
		m_dwInstCount++;

		if(strstr(da.result, "JMP ")  && dwLength == 5)
		{
			dwOffset += *((DWORD*)&m_pbyBuff[dwOffset-dwLength+1]);
			continue;
		}

		if(strstr(da.result, "CALL ") && dwLength == 5)
		{
			if(m_pbyBuff[dwOffset-dwLength-5] == 0x68)
			{
				DWORD	dwOldOffset = dwOffset-dwLength-5 + m_dwDecStartRVA;
				dwOffset += *((DWORD*)&m_pbyBuff[dwOffset-dwLength+1]);
				if(dwOffset < m_dwNoOfBytes && m_pbyBuff[dwOffset] == 0x9C)
				{
					objEmulate.SetEip(dwOldOffset);
					if(7 != objEmulate.EmulateFile(false))
					{
						break;
					}
					objEmulate.ReadEmulateBuffer((BYTE*)&dwEAXConst, 4, objEmulate.GetSpecifyRegValue(4));
					dwOffset = dwEAXConst - m_dwDecStartRVA;
				}
			}
			else
			{
				dwOffset += *((DWORD*)&m_pbyBuff[dwOffset-dwLength+1]);
			}
			continue;
		}

		if(m_dwEBX == 0x00 && strstr(da.result, "MOV EBX") && dwLength == 0x05)
		{
			m_dwEBX = *((DWORD*)&m_pbyBuff[dwOffset-dwLength+1]);
			if(m_dwEBX % 0x1000 != 0x00)
			{
				m_dwEBX = 0;
			}
			continue;
		}
		if(m_dwEBX == 0x00 && strstr(da.result, "AND EBX") && dwLength == 0x06)
		{
			m_dwEBX = *((DWORD*)&m_pbyBuff[dwOffset-dwLength+2]);
			if(m_dwEBX % 0x1000 != 0x00)
			{
				m_dwEBX = 0;
			}
			continue;
		}
		if(m_dwEBX == 0x00 && strstr(da.result, "SUB EBX") && dwLength == 0x06 && (!strstr(da.result, "SUB EBX,[")))
		{
			m_dwEBX = *((DWORD*)&m_pbyBuff[dwOffset-dwLength+2]);
			if(m_dwEBX % 0x1000 != 0x00)
			{
				m_dwEBX = 0;
			}
			continue;
		}
		if(m_dwEBX == 0x00 && strstr(da.result, "OR EBX,") && dwLength == 0x06)
		{
			m_dwEBX = *((DWORD*)&m_pbyBuff[dwOffset-dwLength+2]);
			if(m_dwEBX % 0x1000 != 0x00)
			{
				m_dwEBX = 0;
			}
			continue;
		}
		if(m_dwEBX == 0x00 && strstr(da.result, "MOV DWORD PTR [ESP+") && dwLength == 0x08)
		{
			m_dwEBX = *((DWORD*)&m_pbyBuff[dwOffset-dwLength+4]);
			if(m_dwEBX % 0x1000 != 0x00)
			{
				m_dwEBX = 0;
			}
			continue;
		}
		
		if(m_dwEBX != 0x00 && strstr(da.result, "PUSH ") && dwLength == 0x05 &&
			(m_pbyBuff[dwOffset] == 0xE8 || m_pbyBuff[dwOffset] == 0xE9) &&
			(!NEGATIVE_JUMP(*((DWORD*)&m_pbyBuff[dwOffset-dwLength+1]))))
		{
			dwPushValue = *((DWORD*)&m_pbyBuff[dwOffset-dwLength+1]);
			dwEAX = dwEAX + (dwPushValue - m_dwEBX);
			m_dwFourthKey = dwEAX;
			bFlag = true;
			break;
		}

		if(m_dwEBX != 0x00 && strstr(da.result, "MOV DWORD PTR [ESP],") &&
			dwLength == 0x07 && (m_pbyBuff[dwOffset] == 0xE8 || m_pbyBuff[dwOffset] == 0xE9) &&
			(!NEGATIVE_JUMP(*((DWORD*)&m_pbyBuff[dwOffset-dwLength+3]))))
		{
			dwPushValue = *((DWORD*)&m_pbyBuff[dwOffset-dwLength+3]);
			dwEAX = dwEAX + (dwPushValue - m_dwEBX);
			m_dwFourthKey = dwEAX;
			bFlag = true;
			break;
		}

		if(m_dwEBX != 0x00 && strstr(da.result, "XCHG [ESP],E") &&
			dwLength == 0x03 && (m_pbyBuff[dwOffset] == 0xE8 || m_pbyBuff[dwOffset] == 0xE9) &&
			(!NEGATIVE_JUMP(*((DWORD*)&m_pbyBuff[dwOffset-dwLength-4]))))
		{
			dwPushValue = *((DWORD*)&m_pbyBuff[dwOffset-dwLength-4]);
			dwEAX = dwEAX + (dwPushValue - m_dwEBX);
			m_dwFourthKey = dwEAX;
			bFlag = true;
			break;
		}

		if(strstr(da.result, "AND E") && da.immconst == 0x00 && dwLength == 0x03)
		{
			bZeroFlag = true;
		}
		if(m_dwEBX == 0x00 && strstr(da.result, "ADD EBX") && dwLength == 6)
		{
			m_dwEBX = *((DWORD*)&m_pbyBuff[dwOffset-dwLength+2]);
			bZeroFlag = false;
			continue;
		}
		if(bZeroFlag == true && strstr(da.result, "JE") && dwLength == 0x02)
		{
			if(m_pbyBuff[dwOffset-dwLength+1] <= 0x7F)
			{
				dwOffset = dwOffset + m_pbyBuff[dwOffset-dwLength+1];
			}
			else
			{
				dwOffset = dwOffset + (0x100 - m_pbyBuff[dwOffset-dwLength+1]);
			}
			bFlag = false;
			continue;
		}
	}
	if(bFlag)
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanXpajA
	In Parameters	: CEmulate &objEmulate, DWORD dwCnt
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for xpaj type1
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::CleanXpajA(CEmulate &objEmulate, DWORD dwCnt)
{
	objEmulate.SetNoOfIteration(150);
	objEmulate.PauseBreakPoint(1);
	objEmulate.PauseBreakPoint(2);
	objEmulate.SetBreakPoint("__isinstruction('mov ebx ,eax')");							//breakpoint 3
	if(7 == objEmulate.EmulateFile(false))
	{
		m_dwFirstKey = objEmulate.GetSpecifyRegValue(0);
	}
	else
	{
		return false;
	}
	objEmulate.SetNoOfIteration(20);
	objEmulate.PauseBreakPoint(3);
	objEmulate.SetBreakPoint("__isinstruction('mov edx ,eax')");							//breakpoint 4
	objEmulate.SetBreakPoint("__isinstruction('sub edx ,eax')");							//breakpoint 5
	if(7 == objEmulate.EmulateFile(false))
	{
		m_dwSecondKey = objEmulate.GetSpecifyRegValue(0);
	}
	else
	{
		return false;
	}
	objEmulate.SetNoOfIteration(20);
	objEmulate.PauseBreakPoint(4);
	objEmulate.PauseBreakPoint(5);
	objEmulate.SetBreakPoint("__isinstruction('call')");									//breakpoint 6
	DWORD dwCallEip = 0, dwThirdKey = 0, dwEAX = 0;
	BYTE byCheckInstruction[2] = {0};
	while(1)
	{
		if(7 == objEmulate.EmulateFile(false))
		{
			if(objEmulate.ReadEmulateBuffer(byCheckInstruction, 0x02, objEmulate.GetEip() + 0x05))
			{
				if((byCheckInstruction[0] == 0x89 || byCheckInstruction[1] == 0xC1))
				{
					dwCallEip = objEmulate.GetJumpAddress();
					break;
				}
				else
				{
					continue;
				}
			}
		}
		else
		{
			return false;
		}
	}
	objEmulate.SetNoOfIteration(20);
	objEmulate.PauseBreakPoint(6);
	objEmulate.SetBreakPoint("__isinstruction('mov ecx ,eax')");							//breakpoint 7
	if(7 == objEmulate.EmulateFile(false))
	{
		dwThirdKey = objEmulate.GetSpecifyRegValue(0);
	}
	else
	{
		return false;
	}
	objEmulate.SetNoOfIteration(100);
	objEmulate.PauseBreakPoint(7);
	objEmulate.SetBreakPoint("__isinstruction('cmp dword ptr [ebx + 1h],eax')");			//breakpoint 8
	if(7 == objEmulate.EmulateFile(false))
	{
		if(dwThirdKey == objEmulate.GetSpecifyRegValue(0))
		{
			objEmulate.UpdateSpecifyReg(3, dwCallEip);
		}
		dwThirdKey = (dwThirdKey ^ m_dwFirstKey) + m_dwSecondKey;
	}
	else
	{
		return false;
	}
	objEmulate.SetNoOfIteration(100);
	objEmulate.PauseBreakPoint(8);
	objEmulate.SetBreakPoint("__isinstruction('lea ecx ,dword ptr [ebx')");				//breakpoint 9
	if(7 == objEmulate.EmulateFile(false))
	{
		dwEAX = objEmulate.GetSpecifyRegValue(3);
		m_dwECX = objEmulate.GetMemoryOprand();
		objEmulate.PauseBreakPoint(8);
	}
	else
	{
		return false;
	}

	m_dwNoOfBytes = m_dwDecSize*4;
	m_dwInstCount = 0;
	m_dwEBX = 0;
	DWORD dwCallCnt = 0, dwOffset = dwCnt, dwLength = 0;
	t_disasm da = {0};
	while(dwOffset < m_dwNoOfBytes)
	{
		if(m_dwInstCount > 80)
		{
			break;
		}
		memset(&da, 0x00, sizeof(t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		m_dwInstCount++;
		if(strstr(da.result, "CALL ") && dwLength == 5)
		{
			if(dwCallCnt == 0)
			{
				dwOffset += dwLength;
				dwCallCnt++;
				continue;
			}
			dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] + 0x05 + dwOffset;
			continue;
		}
		if(strstr(da.result, "PUSH ") && dwLength == 5)
		{
			if(m_pbyBuff[dwOffset + 5] == 0xE8)
			{
				m_dwFourthKey = *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwEAX;
				if(m_dwFourthKey > m_dwECX && 
				   m_dwFourthKey < (m_pSectionHeader[m_wNoOfSections-1].VirtualAddress + m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize + m_dwImageBase))
				{
					return true;
				}
			}
			dwOffset += dwLength;
			continue;
		}
		if(strstr(da.result, "MOV DWORD PTR [ESP],") && dwLength == 7)
		{
			if(m_pbyBuff[dwOffset + 7] == 0xE8)
			{
				m_dwFourthKey = *(DWORD *)&m_pbyBuff[dwOffset + 3] + dwEAX;
				if(m_dwFourthKey > m_dwECX && 
				   m_dwFourthKey < (m_pSectionHeader[m_wNoOfSections-1].VirtualAddress + m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize + m_dwImageBase))
				{
					return true;
				}
			}
			dwOffset += dwLength;
			continue;
		}
		if(strstr(da.result, "MOV DWORD PTR [ESP+") && dwLength == 8)
		{
			if(m_pbyBuff[dwOffset + 0xB] == 0xE8)
			{
				m_dwFourthKey = *(DWORD *)&m_pbyBuff[dwOffset + 4] + dwEAX;
				if(m_dwFourthKey > dwEAX && 
				   m_dwFourthKey < (m_pSectionHeader[m_wNoOfSections-1].VirtualAddress + m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize + m_dwImageBase))
				{
					return true;
				}
			}
			dwOffset += dwLength;
			continue;
		}
		if(strstr(da.result, "SUB EAX,") && dwLength == 6)
		{
			if(m_pbyBuff[dwOffset + 0x6] == 0xF7 && m_pbyBuff[dwOffset + 0x7] == 0xD8 && m_pbyBuff[dwOffset + 0x8] == 0x87 &&
			   m_pbyBuff[dwOffset + 0x9] == 0x04 && m_pbyBuff[dwOffset + 0xA] == 0x24)
			{
				m_dwFourthKey = *(DWORD *)&m_pbyBuff[dwOffset + 2] + dwEAX;
				if(m_dwFourthKey > m_dwECX && 
				   m_dwFourthKey < (m_pSectionHeader[m_wNoOfSections-1].VirtualAddress + m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize + m_dwImageBase))
				{
					return true;
				}
			}
			dwOffset += dwLength;
			continue;
		}
		dwOffset += dwLength;
	}		
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptTableXpajA
	In Parameters	: DWORD dwFlag
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption routine for XpajA
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::DecryptTableXpajA(DWORD dwFlag)
{
	bool bRetStatus = false;
	if(m_pbyBuff)
	{
		VirtualFree((void*)m_pbyBuff, 0, MEM_RELEASE);
		m_pbyBuff = NULL;
	}
	DWORD dwEaxOff = 0;
	DWORD dwVirusCodeSec = m_pMaxPEFile->Rva2FileOffset(m_dwEAX, &dwEaxOff);
	DWORD dwBuffSize = m_pSectionHeader[dwVirusCodeSec].SizeOfRawData + m_pSectionHeader[dwVirusCodeSec].PointerToRawData - dwEaxOff;
	if(dwBuffSize > 0x8000)
	{
		dwBuffSize = 0x8000;
	}
	BYTE *byBuffer = new BYTE[dwBuffSize];
	memset(byBuffer, 0x00, dwBuffSize);
	if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwEaxOff, dwBuffSize, dwBuffSize))
	{
		if(byBuffer)
		{
			delete[] byBuffer;
			byBuffer = NULL;
		}
		return bRetStatus;
	}
	DWORD	dwRelBaseAdrs = 0, dwCallpatchCount = 0, dwTableIndex = 0, dwImageBaseCounter = 0x00, dwECX = 0, dwEAX = 0, dwSizeToWrite = 0;
	DWORD	dwCounter = 0, dwDisplacement = 0, dwNexPtr = 0x00, dwPatchedRVA = 0x00, dwTemp = 0x0, dwNOPCount = 8, dwPatchedOff = 0;
	DWORD	dwAllPatchRVA[200] = {0x00};
	m_dwFirstKey = *(DWORD *)&byBuffer[0];
	for(DWORD i = 0; i < 150; i++)
	{
		if(dwTableIndex + 0x450 >= dwBuffSize)
		{
			break;
		}
		dwTemp = *((DWORD*)&byBuffer[dwTableIndex]);
		if((dwTemp ^ m_dwFirstKey) == -1 || (dwTemp ^ m_dwFirstKey) == 1)
		{
			if (true == m_bRelocPresent)
			{
				ReapirRelocationTable();
			}
			bRetStatus = true;
			break;
		}
		
		dwNexPtr			= *((DWORD*)&byBuffer[dwTableIndex+0x04]) ^ m_dwFirstKey;
		dwPatchedRVA		= *((DWORD*)&byBuffer[dwTableIndex+0x08]) ^ m_dwFirstKey;
		dwCounter			= *((DWORD*)&byBuffer[dwTableIndex+0x10]) ^ m_dwFirstKey;
		dwDisplacement		= *((DWORD*)&byBuffer[dwTableIndex+0x1C]) ^ m_dwFirstKey;
		dwImageBaseCounter	= *((DWORD*)&byBuffer[dwTableIndex+0x14]) ^ m_dwFirstKey;
		
		bool bPatchRVAFound = false;
		for(DWORD j = 0x00; j < dwCallpatchCount; j++)
		{
			if(dwPatchedRVA == dwAllPatchRVA[j])
			{
				dwTableIndex += dwNexPtr;
				bPatchRVAFound = true;
			}
		}
		if(bPatchRVAFound == true)
		{
			continue;
		}
		else
		{
			dwAllPatchRVA[dwCallpatchCount++] = dwPatchedRVA;
		}
		if(dwCounter >= 0x400 || dwDisplacement > 0x50)
		{
			m_bDelete = 2;
			break;
		}
		for(DWORD dwCnt = 0; dwCnt < dwCounter; dwCnt++)
		{
			byBuffer[dwTableIndex+dwDisplacement+dwCnt] ^= (BYTE)m_dwFirstKey;
		}

		if(dwImageBaseCounter != 0x00)
		{
			dwECX				= *((DWORD*)&byBuffer[dwTableIndex+0x18]) ^ m_dwFirstKey;
			dwECX				= dwTableIndex + dwECX;
			for(DWORD dwIndex = 0; dwIndex < dwImageBaseCounter; dwIndex++)
			{
				dwEAX = (*((DWORD*)&byBuffer[dwECX]) ^ m_dwFirstKey) + dwDisplacement;
				if(m_bRelocPresent)
				{
					dwRelBaseAdrs  = dwEAX +  dwPatchedRVA - dwDisplacement - 0x08;
					AddRelocTableEntry(dwRelBaseAdrs);
				}
				if(dwEAX + dwTableIndex < dwBuffSize - 4)
				{
					*((DWORD*)&byBuffer[dwEAX + dwTableIndex]) += m_dwImageBase;
				}
				dwECX += 4;
			}
		}
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwPatchedRVA, &dwPatchedOff))
		{
			break;
		}
		
		if(dwCounter == 0x05)
		{
			if(byBuffer[dwTableIndex+dwDisplacement] == 0xE9)
			{
				byBuffer[dwTableIndex+dwDisplacement] = 0xE8;
			}
			DWORD dwWriteValue = *(DWORD *)&byBuffer[dwTableIndex+dwDisplacement+1] + 0x05 + dwTableIndex+dwDisplacement + m_dwEAX;
			dwWriteValue = dwWriteValue - dwPatchedRVA;
			*((DWORD*)&byBuffer[dwTableIndex+dwDisplacement+1]) = dwWriteValue;
			if(!m_pMaxPEFile->WriteBuffer(&byBuffer[dwTableIndex+dwDisplacement], dwPatchedOff-5, dwCounter, dwCounter))
			{
				break;
			}
		}
		else
		{
			ReslovePatchedDataCallJMP(&byBuffer[dwTableIndex+dwDisplacement+dwNOPCount], dwCounter-5, dwTableIndex+dwDisplacement + m_dwEAX, dwPatchedRVA);
			if(dwFlag == 0)
			{
				dwSizeToWrite = dwCounter - dwNOPCount;
			}
			else if(dwFlag == 1)
			{
				dwSizeToWrite = dwCounter - dwNOPCount - 5;
			}
			if(!m_pMaxPEFile->WriteBuffer(&byBuffer[dwTableIndex+dwDisplacement+dwNOPCount], dwPatchedOff, dwSizeToWrite, dwSizeToWrite))
			{
				break;
			}
		}

		dwTableIndex += dwNexPtr;
	}
	if(byBuffer)
	{
		delete[] byBuffer;
		byBuffer = NULL;
	}
	return bRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptTableGen
	In Parameters	: DWORD dwFlag
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption routine
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::DecryptTableGen()
{
	bool bRetStatus = false;

	DWORD	dwTableIndex = m_dwEAX - (m_dwDecStartRVA - m_dwImageBase);
	DWORD	dwRelBaseAdrs = 0, dwCallpatchCount = 0, dwImageBaseCounter = 0x00, dwECX = 0, dwEAX = 0;
	DWORD	dwCounter = 0, dwDisplacement = 0, dwNexPtr = 0x00, dwPatchedRVA = 0x00, dwTemp = 0x0, dwNOPCount = 8, dwPatchedOff = 0;
	DWORD	dwAllPatchRVA[200] = {0x00};

	for(DWORD i = 0; i < 150; i++)
	{
		if((dwTableIndex + 0x500) >= m_dwDecSize * 4)
		{
			return bRetStatus;
		}
		dwTemp = *((DWORD*)&m_pbyBuff[dwTableIndex]);
		if((dwTemp ^ m_dwFirstKey) == -1 || (dwTemp ^ m_dwFirstKey) == 1)
		{
			if (true == m_bRelocPresent)
				ReapirRelocationTable();
			bRetStatus = true;
			break;
		}
		
		dwNexPtr			= *((DWORD*)&m_pbyBuff[dwTableIndex + 0x04]) ^ m_dwFirstKey;
		dwPatchedRVA		= *((DWORD*)&m_pbyBuff[dwTableIndex + 0x08]) ^ m_dwFirstKey;
		dwCounter			= *((DWORD*)&m_pbyBuff[dwTableIndex + 0x10]) ^ m_dwFirstKey;
		dwDisplacement		= *((DWORD*)&m_pbyBuff[dwTableIndex + 0x1C]) ^ m_dwFirstKey;
		dwImageBaseCounter	= *((DWORD*)&m_pbyBuff[dwTableIndex + 0x14]) ^ m_dwFirstKey;
		
		bool bPatchRVAFound = false;
		for(DWORD j = 0x00; j < dwCallpatchCount; j++)
		{
			if(dwPatchedRVA == dwAllPatchRVA[j])
			{
				dwTableIndex += dwNexPtr;
				bPatchRVAFound = true;
			}
		}
		if(bPatchRVAFound == true)
		{
			continue;
		}
		else
		{
			dwAllPatchRVA[dwCallpatchCount++] = dwPatchedRVA;
		}
		if(dwCounter >= 0x450 || dwDisplacement > 0x50)
		{
			break;
		}
		for(DWORD dwCnt = 0; dwCnt < dwCounter; dwCnt++)
		{
			m_pbyBuff[dwTableIndex+dwDisplacement+dwCnt] ^= (BYTE)m_dwFirstKey;
		}

		if(dwImageBaseCounter != 0x00)
		{
			dwECX				= *((DWORD*)&m_pbyBuff[dwTableIndex+0x18]) ^ m_dwFirstKey;
			dwECX				= dwTableIndex + dwECX;

			for(DWORD dwIndex = 0; dwIndex < dwImageBaseCounter; dwIndex++)
			{
				dwEAX = (*((DWORD*)&m_pbyBuff[dwECX]) ^ m_dwFirstKey) + dwDisplacement;
				if(m_bRelocPresent)
				{
					dwRelBaseAdrs  = dwEAX +  dwPatchedRVA - dwDisplacement - 0x08;
					AddRelocTableEntry(dwRelBaseAdrs);
				}
				if(dwEAX + dwTableIndex < ((m_dwDecSize * 4) - 4))
				{
					*((DWORD*)&m_pbyBuff[dwEAX + dwTableIndex]) += m_dwImageBase;
				}
				dwECX += 4;
			}
		}
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwPatchedRVA, &dwPatchedOff))
		{
			break;
		}
		
		if(dwCounter == 0x05)
		{
			if(m_pbyBuff[dwTableIndex + dwDisplacement] == 0xE9)
			{
				m_pbyBuff[dwTableIndex + dwDisplacement] = 0xE8;
			}
			DWORD dwWriteValue = *(DWORD *)&m_pbyBuff[dwTableIndex + dwDisplacement + 1] + 0x05 + dwTableIndex + dwDisplacement + m_dwDecStartRVA - m_dwImageBase;
			dwWriteValue = dwWriteValue - dwPatchedRVA;
			*((DWORD*)&m_pbyBuff[dwTableIndex+dwDisplacement + 1]) = dwWriteValue;
			if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwTableIndex+dwDisplacement], dwPatchedOff - 5, dwCounter, dwCounter))
			{
				break;
			}
		}
		else
		{
			ReslovePatchedDataCallJMP(&m_pbyBuff[dwTableIndex + dwDisplacement + dwNOPCount], dwCounter - 5, dwTableIndex + dwDisplacement + m_dwDecStartRVA - m_dwImageBase, dwPatchedRVA);
			if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[dwTableIndex + dwDisplacement + dwNOPCount], dwPatchedOff, dwCounter - dwNOPCount - 5, dwCounter - dwNOPCount - 5))
			{
				break;
			}
		}
		dwTableIndex += dwNexPtr;
	}
	return bRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: ReapirRelocationTable
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Repair routine for different varients of Dundun Family
--------------------------------------------------------------------------------------*/
void CPolyXpaj::ReapirRelocationTable()
{
	DWORD	dwIndex = 0x00, i = 0x00, dwSize = 0x00, dwOffSet = 0x00, dwDisplacement = 0x00;

	for(i=0x00;i < m_structRelTable.dwBaseEntries;i++)
	{
		dwOffSet	= m_dwRelocStart + m_dwRelocSize;
		dwSize		= 0x00;

		m_pMaxPEFile->WriteBuffer(&m_structRelTable.dwBaseAdrs[i], dwOffSet,sizeof(DWORD), sizeof(DWORD));
		dwDisplacement = dwOffSet + 0x04;
		m_pMaxPEFile->WriteBuffer(&dwSize, dwDisplacement, sizeof(DWORD), sizeof(DWORD));
		dwDisplacement += 0x04;

		for(dwIndex = 0x00; dwIndex < m_structRelTable.dwRelEntries; dwIndex++)
		{
			if (m_structRelTable.dwRelAdressArray[dwIndex][0x00] ==  m_structRelTable.dwBaseAdrs[i])
			{
				m_pMaxPEFile->WriteBuffer(&m_structRelTable.dwRelAdressArray[dwIndex][0x01], dwDisplacement,sizeof(WORD), sizeof(WORD));
				dwDisplacement += 0x02;
				dwSize += 0x02;
			}
		}
		if(dwSize  %4 != 0x00)
		{
			WORD	wT = 0x00;
			m_pMaxPEFile->WriteBuffer(&wT, dwDisplacement, sizeof(WORD), sizeof(WORD));
			dwDisplacement += 0x02;
			dwSize += 0x02;
		}
		dwSize+=0x08;
		m_pMaxPEFile->WriteBuffer(&dwSize, dwOffSet + 0x04, sizeof(DWORD), sizeof(DWORD));
		m_dwRelocSize += dwSize;
		m_pMaxPEFile->RepairOptionalHeader(0x024, m_pMaxPEFile->m_stPEHeader.DataDirectory[0x05].VirtualAddress, m_dwRelocSize,true);
	}
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: AddRelocTableEntry
	In Parameters	: DWORD dwAddress
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Reapirs relocation table
--------------------------------------------------------------------------------------*/
void CPolyXpaj::AddRelocTableEntry(DWORD dwAddress)
{
	
	if (dwAddress == 0x00)
		return;

	if (m_structRelTable.dwRelEntries >= 0x50)
		return;

	DWORD dwBaseAddr = (dwAddress / 0x01000) * 0x1000;
	DWORD dwRelAddrs = 	dwAddress % 0x01000;
	DWORD i = 0x00;
	bool  bFound = false;	

	for (i = 0x00; i < m_structRelTable.dwBaseEntries; i++)
	{
		if (m_structRelTable.dwBaseAdrs[i] == dwBaseAddr)
		{
			bFound = true;
			break;
		}
	}
	if (false == bFound)
	{
		m_structRelTable.dwBaseAdrs[m_structRelTable.dwBaseEntries] = dwBaseAddr;
		m_structRelTable.dwBaseEntries++;
	}
	m_structRelTable.dwRelAdressArray[m_structRelTable.dwRelEntries][0x00] = dwBaseAddr;
	m_structRelTable.dwRelAdressArray[m_structRelTable.dwRelEntries][0x01] = 0x03000 + dwRelAddrs;
	m_structRelTable.dwRelEntries++;
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: CalculateRetAdd
	In Parameters	: DWORD dwPushVal, DWORD dwRetAdd, DWORD dwCallRawData, DWORD dwEAXConst
	Out Parameters	: File Offset
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Finds return address
--------------------------------------------------------------------------------------*/
DWORD CPolyXpaj::CalculateRetAdd(DWORD dwPushVal, DWORD dwRetAdd, DWORD dwCallRawData, DWORD dwEAXConst)
{
	return dwPushVal + dwRetAdd + dwCallRawData + dwEAXConst;
}

/*-------------------------------------------------------------------------------------
	Function		: GetEAX
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Get EAX Register values
--------------------------------------------------------------------------------------*/
bool CPolyXpaj::GetEAX()
{
	DWORD dwEBX = 0x00, dwEDX = 0x00, dwCounter = 0x00, dwEAX = 0x00, dwTemp = 0x00, dwECX = 0x00; 
	BYTE byDecBuffer[0x02] = {0};
	m_dwEAX = 0;
	for(DWORD dwCnt = 0; dwCnt < 4; dwCnt++)
	{
		dwCounter	= m_dwFourthKey - m_dwECX;
		dwEBX		= m_dwFirstKey;
		dwEDX		= m_dwSecondKey;
		dwECX		= dwCounter;
		dwCounter	= dwCounter >> 2;
		for(DWORD dwCnt1 = 0; dwCnt1 < dwCounter; dwCnt1++)
		{
			dwEBX += dwEDX;
		}

		dwTemp = m_dwFourthKey - m_dwDecStartRVA;
		if(dwTemp > m_dwDecSize * 4)
		{
			return false;
		}
		byDecBuffer[0] = m_pbyBuff[dwTemp];

		dwECX = dwECX & 0x03;
		dwECX = dwECX << 0x03;
		dwEBX = _lrotr(dwEBX, (BYTE)dwECX);
		dwEAX += byDecBuffer[0] ^ (BYTE)dwEBX;
		dwEAX = _lrotr(dwEAX, 0x08);
		m_dwFourthKey++;
	}
	m_dwEAX = dwEAX;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ReslovePatchedDataCallJMP
	In Parameters	: BYTE *byBuffer, DWORD dwCounter, DWORD dwBuffReadRVA, DWORD dwReplacementRVA
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Finds sthe JMP call patched by Virus
--------------------------------------------------------------------------------------*/
void CPolyXpaj::ReslovePatchedDataCallJMP(BYTE *byBuffer, DWORD dwCounter, DWORD dwBuffReadRVA, DWORD dwReplacementRVA)
{
	if(byBuffer == NULL)
	{
		return;
	}

	DWORD	dwLength, dwOffset;
	dwLength = dwOffset = 0;
	t_disasm da = {0};
	BYTE B1, B2, B3;

	while(dwOffset < dwCounter)
	{
		B1 = byBuffer[dwOffset];
		B2 = byBuffer[dwOffset + 0x01];
		B3 = byBuffer[dwOffset + 0x02];
		//Skipping Some Instructions that couldn't be interpreted by Olly.
		if(B1 == 0xD9 && B2 >= 0x58 && B2 <= 0x5D)
		{
			dwOffset += 0x03;
			continue;
		}
		if(B1==0xD9 && B2 >= 0x98 && B2 <= 0x9D)
		{
			dwOffset += 0x06;
			continue;
		}		
		if(B1==0xC1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if(B1==0xC0 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if(B1==0xD1 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}
		if(B1==0xD0 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}
		if(B1==0xD2 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}
		if(B1==0xD3 && (B2>=0xF0 && B2<=0xF7))
		{
			dwOffset += 0x02;
			continue;
		}
		if(B1 == 0x0F && B2 == 0xAC && B3 == 0xDD)
		{
			dwOffset += 0x04;
			continue;
		}
		if(B1 == 0xF3 && B2 == 0x0F && B3 == 0xBD)
		{
			dwOffset += 0x04;
			continue;
		}	

		memset(&da, 0, sizeof(t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char *)&byBuffer[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		
		if(dwLength >= 0x05 && ((strstr(da.result, "CALL") && byBuffer[dwOffset] == 0xE8) || (strstr(da.result, "J") && !strstr(da.result, "JMP ["))))
		{
			if((*(DWORD *)&byBuffer[dwOffset + dwLength - 4]+dwOffset+5) > dwCounter || 
				(NEGATIVE_JUMP((*(DWORD *)&byBuffer[dwOffset + dwLength - 4]+dwOffset+5)) && 
				(0x100000000 - (*(DWORD *)&byBuffer[dwOffset + dwLength - 4]+dwOffset+5))) > dwOffset)
			{
				DWORD dwWriteValue = *(DWORD *)&byBuffer[dwOffset + dwLength - 4] + 0x05 + dwBuffReadRVA + dwOffset;
				dwWriteValue = dwWriteValue - (dwReplacementRVA+dwOffset) + 3;
				*((DWORD*)&byBuffer[dwOffset + dwLength - 4]) = dwWriteValue;
			}
		}
		dwOffset += dwLength;
	}
}
