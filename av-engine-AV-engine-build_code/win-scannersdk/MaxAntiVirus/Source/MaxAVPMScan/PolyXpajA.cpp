/*======================================================================================
FILE				: PolyXpajA.cpp
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
NOTES				: This is detection module for malware Xpaj.A Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyXpajA.h"
#include "PolymorphicVirus.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyXpajA
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyXpajA::CPolyXpajA(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{	
	m_dwFirstKey     = 0;
	m_dwSecondKey    = 0;
	m_dwThirdKey     = 0;
	m_dwFourthKey    = 0;
	m_dwKey          = 0;
	m_dwCalledAdd    = 0;
	m_dwCalledAddOff = 0;
	m_dwECX          = 0;
	m_dwEAX          = 0;
	m_dwTruncateOff  = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyXpajA
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyXpajA::~CPolyXpajA(void)
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
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Detection routine for different varients of Xpaj.A Family
--------------------------------------------------------------------------------------*/
int CPolyXpajA::DetectVirus() 
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections - 1)
	{
		return iRetStatus;
	}

	m_pbyBuff = new BYTE[XPAJ_A_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0, XPAJ_A_BUFF_SIZE + MAX_INSTRUCTION_LEN);

	for(WORD wSec = m_wNoOfSections - 1; wSec > m_wAEPSec; wSec--)
	{
		if ((m_pSectionHeader[wSec].Characteristics & 0x80000000) !=  0x80000000)
		{
			continue;
		}
		if(m_pSectionHeader[wSec].SizeOfRawData >= XPAJ_A_STUB_SIZE)
		{			
			if(!GetPatchedCalls(m_pSectionHeader[m_wAEPSec].PointerToRawData, m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData, wSec, false, true))
			{
				return iRetStatus;
			}
			if(m_arrPatchedCallOffsets.GetCount())
			{	
				LPVOID	lpos = m_arrPatchedCallOffsets.GetHighest();
				while(lpos)
				{
					m_arrPatchedCallOffsets.GetData(lpos, m_dwCalledAdd);
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwCalledAdd, &m_dwCalledAddOff))
					{
						if(GetBuffer(m_dwCalledAddOff, XPAJ_A_BUFF_SIZE, XPAJ_A_BUFF_SIZE))
						{
							if(m_pbyBuff[0] == 0xE8)
							{
								 DWORD dwRetVal = CheckXpajAInstructions();
								 if(dwRetVal == 1)
								 {
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Xpaj.A"));
									return VIRUS_FILE_REPAIR;
								 }
							}
						}
					}
					lpos = m_arrPatchedCallOffsets.GetHighestNext(lpos);
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckXpajAInstructions
	In Parameters	: 
	Out Parameters	: 1 for success else 0
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Thsi function find the Xpaj A detection instructions
--------------------------------------------------------------------------------------*/
int CPolyXpajA::CheckXpajAInstructions() 
{	
	int iRetStatus = 0;
	DWORD dwLength = 0, dwOffset = 0;
	int iStg = 0;
	t_disasm da;
	m_dwInstCount = 0;
	
	while(dwOffset < m_dwNoOfBytes && m_dwInstCount <= 0x08)
	{
		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffset))
		{
			break;
		}
		m_dwInstCount++;

		if(dwLength == 0x05 && strstr(da.result, "CALL ") && iStg == 0)
		{
			if(*((DWORD*)&m_pbyBuff[dwOffset+1]) < 0x50)
			{
				iStg = 1;
			}
		}
		if(iStg == 1 && strstr(da.result, "JMP ") && (dwLength == 2 || dwLength == 5))
		{
			dwOffset = m_pbyBuff[dwOffset + 1] + dwLength + dwOffset;
			m_dwInstCount--;
			continue;
		}
		if(iStg == 1 && strstr(da.result,"PUSH DWORD PTR [ESP"))
		{
			iStg++;
		}
		if(iStg == 2 && dwLength == 0x05 && strstr(da.result,"CALL "))
		{
			iRetStatus = 1;
			return iRetStatus;
		}
		dwOffset += dwLength;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of xpaj.a Family
--------------------------------------------------------------------------------------*/
int CPolyXpajA::CleanVirus()
{
	WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
	int iRetStatus = _CleanVirus();
	SetEvent(CPolymorphicVirus::m_hEvent);	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: _CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of xpaj.a Family
--------------------------------------------------------------------------------------*/
int CPolyXpajA::_CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	CEmulate objEmulate(m_pMaxPEFile);
	if(!objEmulate.IntializeProcess())
	{
		return iRetStatus;
	}
	objEmulate.SetEip(m_dwCalledAdd + m_dwImageBase);
	objEmulate.SetBreakPoint("__isinstruction('call ')");
	objEmulate.SetBreakPoint("__isinstruction('mov ebx ,eax')");
	objEmulate.SetBreakPoint("__isinstruction('mov edx ,eax')");
	objEmulate.SetBreakPoint("__isinstruction('mov ecx ,eax')");
	objEmulate.SetBreakPoint("__isinstruction('cmp dword ptr [ebx + 1h],eax')");
	objEmulate.SetBreakPoint("__isinstruction('lea ecx ,dword ptr [ebx')");
	objEmulate.SetBreakPoint("__isinstruction('sub ebx ,dword ptr [')");
	objEmulate.SetBreakPoint("__isinstruction('sub ecx ,')");
	objEmulate.SetBreakPoint("__isinstruction('xchg edx ,eax')");
	objEmulate.SetBreakPoint("__isinstruction('xor ecx ,')");
	objEmulate.SetBreakPoint("__isinstruction('add ecx ,')");
	objEmulate.SetBreakPoint("__isinstruction('or ebx ,')");
	objEmulate.SetBreakPoint("__isinstruction('xchg ebx ,eax')");
	objEmulate.SetBreakPoint("__isinstruction('xchg ecx ,eax')");
	objEmulate.SetBreakPoint("__isinstruction('sub esp ,')");
	objEmulate.SetBreakPoint("__isinstruction('and ebx ,')");//added one break point
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
	objEmulate.PauseBreakPoint(12);
	objEmulate.PauseBreakPoint(13);
	objEmulate.PauseBreakPoint(14);
	objEmulate.PauseBreakPoint(15);//added one condition

	BYTE byCheckInstruction[2] = {0};
	char szInstruction[1024];
	bool bIsCall = false;
	DWORD dwCallEip = 0, dwCallCnt = 0;
	while(1)
	{
		if(7 == objEmulate.EmulateFile())
		{
			objEmulate.GetInstruction(szInstruction);
			if(objEmulate.GetInstructionLength() == 0x05 && strstr(szInstruction, "call"))
			{
				if(objEmulate.ReadEmulateBuffer(byCheckInstruction, 0x02, objEmulate.GetEip() + 0x05))
				{
					if(dwCallCnt == 0 && 
					   ((byCheckInstruction[0] == 0x8B && byCheckInstruction[1] == 0xD8) ||
					   ((byCheckInstruction[0] == 0x89 || byCheckInstruction[0] == 0x87) && byCheckInstruction[1] == 0xC3) ||
					   (byCheckInstruction[0] == 0x83 && (byCheckInstruction[1] == 0xCB || byCheckInstruction[1] == 0xE3))))//added one condition
					{
						m_dwTruncateOff = objEmulate.GetJumpAddress() - m_dwImageBase;
						objEmulate.ActiveBreakPoint(1);
						objEmulate.ActiveBreakPoint(11);
						objEmulate.ActiveBreakPoint(12);
						objEmulate.ActiveBreakPoint(15);
						objEmulate.PauseBreakPoint(0);
						dwCallCnt++;
						continue;		
					}
					else if(dwCallCnt == 1 && ((byCheckInstruction[0] == 0x89 || byCheckInstruction[0] == 0x87) && byCheckInstruction[1] == 0xC2))
					{
						objEmulate.ActiveBreakPoint(2);
						objEmulate.ActiveBreakPoint(8);
						objEmulate.PauseBreakPoint(0);
						dwCallCnt++;
						continue;		
					}
					else if(dwCallCnt == 2 &&(byCheckInstruction[0] == 0x89 || byCheckInstruction[0] == 0x8B || byCheckInstruction[0] == 0x2B || byCheckInstruction[0] == 0x33
						  || byCheckInstruction[0] == 0x23 || byCheckInstruction[0] == 0x87 || (byCheckInstruction[0] == 0x83 && (byCheckInstruction[1] == 0xEC || byCheckInstruction[1] == 0xC9))))
					{
						dwCallEip = objEmulate.GetJumpAddress();
						objEmulate.ActiveBreakPoint(3);
						objEmulate.ActiveBreakPoint(7);
						objEmulate.ActiveBreakPoint(9);
						objEmulate.ActiveBreakPoint(10);
						objEmulate.ActiveBreakPoint(13);
						objEmulate.ActiveBreakPoint(14);
						objEmulate.PauseBreakPoint(0);
						continue;		
					}
				}
			}
			if((objEmulate.GetInstructionLength() == 0x02 &&
			  (strstr(szInstruction, "mov") || strstr(szInstruction, "sub") || strstr(szInstruction, "xchg") || strstr(szInstruction, "xor") || 
			  strstr(szInstruction, "add") || strstr(szInstruction, "or"))) || ((objEmulate.GetInstructionLength() == 3 && strstr(szInstruction, "and ebx"))))//added one condition
			{
				if((byCheckInstruction[0] == 0x8B && byCheckInstruction[1] == 0xD8) ||
				   ((byCheckInstruction[0] == 0x89 || byCheckInstruction[0] == 0x87) && byCheckInstruction[1] == 0xC3) ||
				   (byCheckInstruction[0] == 0x83 && (byCheckInstruction[1] == 0xCB || byCheckInstruction[1] == 0xE3)))//added one condition
				{
					m_dwFirstKey = objEmulate.GetSpecifyRegValue(0);
					objEmulate.ActiveBreakPoint(0);
					objEmulate.PauseBreakPoint(1);
					objEmulate.PauseBreakPoint(11);
					objEmulate.PauseBreakPoint(12);
					objEmulate.PauseBreakPoint(15);//added one condition
					continue;
				}
				else if(((byCheckInstruction[0] == 0x89 || byCheckInstruction[0] == 0x87) && byCheckInstruction[1] == 0xC2))
				{
					m_dwSecondKey = objEmulate.GetSpecifyRegValue(0);
					objEmulate.ActiveBreakPoint(0);
					objEmulate.PauseBreakPoint(2);
					objEmulate.PauseBreakPoint(8);
					continue;
				}
				else if((byCheckInstruction[0] == 0x89 || byCheckInstruction[0] == 0x8B || byCheckInstruction[0] == 0x2B || byCheckInstruction[0] == 0x33
					  || byCheckInstruction[0] == 0x23 || byCheckInstruction[0] == 0x87 || (byCheckInstruction[0] == 0x83 && (byCheckInstruction[1] == 0xEC || byCheckInstruction[1] == 0xC9))))//added one condition
				{
					m_dwThirdKey = objEmulate.GetSpecifyRegValue(0);
					objEmulate.ActiveBreakPoint(4);
					objEmulate.PauseBreakPoint(3);
					objEmulate.PauseBreakPoint(7);
					objEmulate.PauseBreakPoint(9);
					objEmulate.PauseBreakPoint(10);
					objEmulate.PauseBreakPoint(13);
					objEmulate.PauseBreakPoint(14);
					continue;
				}
			}
			if(objEmulate.GetInstructionLength() == 0x03 && strstr(szInstruction, "cmp"))
			{
				if(m_dwThirdKey == objEmulate.GetSpecifyRegValue(0))
				{
					objEmulate.UpdateSpecifyReg(3, dwCallEip);
				}
				m_dwThirdKey = (m_dwThirdKey ^ m_dwFirstKey) + m_dwSecondKey;
				objEmulate.ActiveBreakPoint(5);
				objEmulate.PauseBreakPoint(4);
				continue;
			}
			if(objEmulate.GetInstructionLength() == 0x06 && strstr(szInstruction, "lea"))
			{
				m_dwKey = objEmulate.GetSpecifyRegValue(3);
				m_dwECX = objEmulate.GetMemoryOprand();
				bIsCall = true;
				break;
			}
		}
		else
		{
			return false;
		}
	}
	if(bIsCall)
	{
		if(GetFourthKey())
		{
			if(GetEAX())
			{
				if(GetOriginalValue())
				{
					iRetStatus = REPAIR_SUCCESS;
					return iRetStatus;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetFourthKey
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: This function finds the fourth decryption key using diss-assembler
--------------------------------------------------------------------------------------*/
bool CPolyXpajA::GetFourthKey()
{
	BYTE *byBuffer = new BYTE[XPAJ_A_BUFF_SIZE];
	memset(byBuffer, 0, XPAJ_A_BUFF_SIZE);
	DWORD dwStart = m_dwCalledAddOff;
	DWORD dwBytesRead = 0, dwCallCnt  = 0;
	if(!m_pMaxPEFile->ReadBuffer(byBuffer, m_dwCalledAddOff, XPAJ_A_BUFF_SIZE, XPAJ_A_BUFF_SIZE, &dwBytesRead))
	{
		if(byBuffer)
		{
			delete[] byBuffer;
			byBuffer = NULL;
		}
		return false;
	}
	t_disasm da;
	DWORD dwLength = 0, dwOffset = 0;
	while(dwOffset < dwBytesRead)
	{
		if(m_dwInstCount > 0x80)
		{
			break;
		}
		memset(&da, 0x00, sizeof(t_disasm));
		dwLength = m_objMaxDisassem.Disasm((char *)&byBuffer[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		m_dwInstCount++;
		if(strstr(da.result, "CALL ") && dwLength == 5)
		{
			if(dwCallCnt == 0)
			{
				dwOffset += dwLength;
				dwCallCnt++;
				continue;
			}
			dwStart = *(DWORD *)&byBuffer[dwOffset + 1] + 0x05 + dwStart + dwOffset;
			if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwStart, XPAJ_A_BUFF_SIZE, XPAJ_A_BUFF_SIZE, &dwBytesRead))
			{
				if(byBuffer)
				{
					delete[] byBuffer;
					byBuffer = NULL;
				}
				return false;
			}
			dwOffset = 0;
			continue;
		}
		if(strstr(da.result, "JMP ") && dwLength == 2)
		{
			dwStart = byBuffer[dwOffset + 1] + 0x02 + dwStart + dwOffset;
			if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwStart, XPAJ_A_BUFF_SIZE, XPAJ_A_BUFF_SIZE, &dwBytesRead))
			{
				if(byBuffer)
				{
					delete[] byBuffer;
					byBuffer = NULL;
				}
				return false;
			}
			dwOffset = 0;
			continue;
		}
		if(strstr(da.result, "PUSH ") && dwLength == 5)
		{
			if(byBuffer[dwOffset + 5] == 0xE8)
			{
				m_dwFourthKey = *(DWORD *)&byBuffer[dwOffset + 1] + m_dwKey;
				if(m_dwFourthKey > m_dwECX && 
				   m_dwFourthKey < (m_pSectionHeader[m_wNoOfSections-1].VirtualAddress + m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize + m_dwImageBase))
				{
					if(byBuffer)
					{
						delete[] byBuffer;
						byBuffer = NULL;
					}
					return true;
				}
			}
			dwOffset += dwLength;
			continue;
		}
		if(strstr(da.result, "MOV DWORD PTR [ESP],") && dwLength == 7)
		{
			if(byBuffer[dwOffset + 7] == 0xE8)
			{
				m_dwFourthKey = *(DWORD *)&byBuffer[dwOffset + 3] + m_dwKey;
				if(m_dwFourthKey > m_dwECX && 
				   m_dwFourthKey < (m_pSectionHeader[m_wNoOfSections-1].VirtualAddress + m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize + m_dwImageBase))
				{
					if(byBuffer)
					{
						delete[] byBuffer;
						byBuffer = NULL;
					}
					return true;
				}
			}
			dwOffset += dwLength;
			continue;
		}
		if(strstr(da.result, "MOV DWORD PTR [ESP+") && dwLength == 8)
		{
			if(byBuffer[dwOffset + 0xB] == 0xE8)
			{
				m_dwFourthKey = *(DWORD *)&byBuffer[dwOffset + 4] + m_dwKey;
				if(m_dwFourthKey > m_dwECX && 
				   m_dwFourthKey < (m_pSectionHeader[m_wNoOfSections-1].VirtualAddress + m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize + m_dwImageBase))
				{
					if(byBuffer)
					{
						delete[] byBuffer;
						byBuffer = NULL;
					}
					return true;
				}
			}
			dwOffset += dwLength;
			continue;
		}
		if(strstr(da.result, "SUB EAX,") && dwLength == 6)
		{
			if(byBuffer[dwOffset + 0x6] == 0xF7 && byBuffer[dwOffset + 0x7] == 0xD8 && byBuffer[dwOffset + 0x8] == 0x87 &&
			   byBuffer[dwOffset + 0x9] == 0x04 && byBuffer[dwOffset + 0xA] == 0x24)
			{
				m_dwFourthKey = *(DWORD *)&byBuffer[dwOffset + 2] + m_dwKey;
				if(m_dwFourthKey > m_dwECX && 
				   m_dwFourthKey < (m_pSectionHeader[m_wNoOfSections-1].VirtualAddress + m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize + m_dwImageBase))
				{
					if(byBuffer)
					{
						delete[] byBuffer;
						byBuffer = NULL;
					}
					return true;
				}
			}
			dwOffset += dwLength;
			continue;
		}
		dwOffset += dwLength;
	}
	if(byBuffer)
	{
		delete[] byBuffer;
		byBuffer = NULL;
	}		
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetOriginalValue
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: Finds the original call patch values and other information
--------------------------------------------------------------------------------------*/
bool CPolyXpajA::GetOriginalValue()
{
	DWORD dwCallCount = m_arrPatchedCallOffsets.GetCount();
	BYTE  *byJumpArr = new BYTE[dwCallCount * 4];
	if(!byJumpArr)
	{
		return false;
	}
	memset(byJumpArr, 0, dwCallCount * 4);
	DWORD dwCnt = 0, dwData = 0;
	LPVOID	lpos1 = m_arrPatchedCallOffsets.GetHighest();
	while(lpos1)
	{
		m_arrPatchedCallOffsets.GetKey(lpos1, dwData);
		dwData += m_pSectionHeader[m_wAEPSec].VirtualAddress - m_pSectionHeader[m_wAEPSec].PointerToRawData;
		*(DWORD *)&byJumpArr[dwCnt] = dwData;
		dwCnt += 0x04;
		lpos1 = m_arrPatchedCallOffsets.GetHighestNext(lpos1);
	}			
	DWORD dwStartRVA = m_dwEAX, dwStartOff = 0, dwBytesToRead = ((dwCallCount+1) * 0x1D);
	
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwStartRVA, &dwStartOff))
	{
		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[dwBytesToRead + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return false;
		}
		memset(m_pbyBuff, 0, dwBytesToRead + MAX_INSTRUCTION_LEN);
	
		if(GetBuffer(dwStartOff, dwBytesToRead, dwBytesToRead))
		{
			DWORD dwXORValue = 0, dwBuffCnt = 0;
			for (DWORD dwCnt = 0; dwCnt < dwCallCount; dwCnt++)
			{
				dwBuffCnt += 0x08;
				dwXORValue = *(DWORD *)&m_pbyBuff[dwBuffCnt] ^ m_dwFirstKey;
				for (DWORD dwCnt1 = 0; dwCnt1 < dwCallCount * 4; )
				{
					if(dwXORValue == *(DWORD *)&byJumpArr[dwCnt1] + 0x05)
					{
						dwBuffCnt += 0x10;
						for(DWORD dwCnt2 = dwBuffCnt; dwCnt2 < dwBuffCnt + 5; dwCnt2 ++)
						{
							m_pbyBuff[dwCnt2] ^= (BYTE)m_dwFirstKey;
						}
						DWORD dwOriginalCall = (dwStartRVA + dwBuffCnt + *(DWORD *)&m_pbyBuff[dwBuffCnt +1] + 0x05) - *(DWORD *)&byJumpArr[dwCnt1] - 0x05;
						if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&byJumpArr[dwCnt1]), &dwStartOff))
						{
							if(m_pMaxPEFile->WriteBuffer(&dwOriginalCall, dwStartOff + 1, 0x04, 0x04))
							{
								break;
							}
						}
					}
					dwCnt1 += 0x04;
				}
				dwBuffCnt += 0x05;
			}
			if(byJumpArr)
			{
				delete []byJumpArr; 
				byJumpArr = NULL;
			}
			if(m_dwTruncateOff != 0)
			{
				if(m_pMaxPEFile->Rva2FileOffset(m_dwTruncateOff, &m_dwTruncateOff))
				{
					if(m_dwTruncateOff % m_pMaxPEFile->m_stPEHeader.FileAlignment)
					{
						m_dwTruncateOff = m_dwTruncateOff - (m_dwTruncateOff % m_pMaxPEFile->m_stPEHeader.FileAlignment);
					}
					if(m_pMaxPEFile->TruncateFile(m_dwTruncateOff))
					{
						return true;
					}
				}
			}
		}
	}
	if(byJumpArr)
	{
		delete []byJumpArr; 
		byJumpArr = NULL;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetEAX
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Neeraj Singh + Virus Analysis Team
	Description		: This function evaluates the possible EAX register value
--------------------------------------------------------------------------------------*/
bool CPolyXpajA::GetEAX()
{
	DWORD dwEBX = 0x00, dwEDX = 0x00, dwCounter = 0x00, dwEAX = 0x00, dwTemp = 0x00, dwECX = 0x00; 
	BYTE byDecBuffer[0x02] = {0};
	for(DWORD dwCnt = 0; dwCnt < 4; dwCnt++)
	{
		dwCounter = m_dwFourthKey - m_dwECX;
		dwEBX = m_dwFirstKey;
		dwEDX = m_dwSecondKey;
		dwECX = dwCounter;
		dwCounter = dwCounter >> 2;
		for(DWORD dwCnt1 = 0; dwCnt1 < dwCounter; dwCnt1++)
		{
			dwEBX += dwEDX;
		}
		dwTemp = m_dwFourthKey - m_dwImageBase;
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwTemp, &dwTemp)) //doubt
		{
			if(m_pMaxPEFile->ReadBuffer(byDecBuffer, dwTemp, 0x01, 0x01))
			{
				dwECX = dwECX & 0x03;
				dwECX = dwECX << 0x03;
				dwEBX = _lrotr(dwEBX, (BYTE)dwECX);
				dwEAX += byDecBuffer[0] ^ (BYTE)dwEBX;
			}
		}
		dwEAX = _lrotr(dwEAX, 0x08);
		m_dwFourthKey++;
	}
	m_dwEAX = dwEAX;
	return true;
}



