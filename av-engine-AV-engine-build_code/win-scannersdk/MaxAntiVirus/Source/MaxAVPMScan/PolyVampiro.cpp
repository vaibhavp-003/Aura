/*======================================================================================
FILE				: PolyVampiro.cpp
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
NOTES				: This is detection module for malware Vampiro Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
					  Emulation is used for detection for this family 
					  as virus is very complecated and virus code is very scattered.
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyVampiro.h"
#include "PolymorphicVirus.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyVampiro
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyVampiro::CPolyVampiro(CMaxPEFile *pMaxPEFile)
:CPolyBase(pMaxPEFile)
{
	m_dwKey = 0;
	m_dwType = 0;
	m_byCheck = 0;
	
	memset(&m_dwKeyChngKey[0], 0, sizeof(DWORD) * 5);
	memset(&m_dwKeyChngType[0], 0, sizeof(DWORD) * 5);
	m_dwCounter = 0;	
	m_byCheck = 0;
	memset(szRegName, 0,3*5);
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyVampiro
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyVampiro::~CPolyVampiro(void)
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
	Description		: Detection routine for different varients of Vampiro Family
--------------------------------------------------------------------------------------*/
int CPolyVampiro::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData >= 0x2700 && 
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xC0000000) == 0xC0000000 &&
		m_wNoOfSections - 1 != m_wAEPSec)
	{		
		if(!GetPatchedCalls(m_pSectionHeader[m_wAEPSec].PointerToRawData, m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData, m_wNoOfSections - 1, true))
		{
			return iRetStatus;
		}

		if(m_arrPatchedCallOffsets.GetCount())
		{
			m_pbyBuff = new BYTE[MAX_VAMPIRO_BUFF_SIZE + MAX_INSTRUCTION_LEN];
			if(!m_pbyBuff)
			{
				return iRetStatus;
			}
			memset(m_pbyBuff, 0, MAX_VAMPIRO_BUFF_SIZE + MAX_INSTRUCTION_LEN);

			DWORD  dwCalledAddOff = 0;

			WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
			LPVOID	lpos = m_arrPatchedCallOffsets.GetHighest();
			while(lpos)
			{
				m_arrPatchedCallOffsets.GetKey(lpos, m_dwCalledAdd);
				m_arrPatchedCallOffsets.GetData(lpos, m_dwPatcedAddr);
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwCalledAdd, &dwCalledAddOff)&& 
					(dwCalledAddOff % m_pMaxPEFile->m_stPEHeader.FileAlignment == 0x00))
				{					
					if(GetBuffer(dwCalledAddOff, MAX_VAMPIRO_BUFF_SIZE, 0x1000))
					{				
						// first bytes  of virus code should be 9c60 or 609c i.e. pushad/pushfd
						if((m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0x9C) || (m_pbyBuff[0] == 0x9C && m_pbyBuff[1] == 0x60))
						{
							iRetStatus = PrimaryDetection();
							if(iRetStatus)
							{
								SetEvent(CPolymorphicVirus::m_hEvent);	
								return iRetStatus;
							}
						}
						memset(m_pbyBuff, 0, MAX_VAMPIRO_BUFF_SIZE + MAX_INSTRUCTION_LEN);
					}
				}
				lpos = m_arrPatchedCallOffsets.GetHighestNext(lpos);
			}
			SetEvent(CPolymorphicVirus::m_hEvent);	
		}
	}
	return iRetStatus;	
}


/*-------------------------------------------------------------------------------------
	Function		: PrimaryDetection
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Primary top level checks for virus detection
--------------------------------------------------------------------------------------*/
int CPolyVampiro::PrimaryDetection()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	CEmulate objEmulate(m_pMaxPEFile);
	if(0 == objEmulate.IntializeProcess())
	{
		return iRetStatus;
	}

	objEmulate.SetBreakPoint("__isinstruction('rol dword ptr [e')");//0
	objEmulate.SetBreakPoint("__isinstruction('ror dword ptr [e')");//1
	objEmulate.SetBreakPoint("__isinstruction('add dword ptr [e')");//2
	objEmulate.SetBreakPoint("__isinstruction('sub dword ptr [e')");//3
	objEmulate.SetBreakPoint("__isinstruction('xor dword ptr [e')");//4

	objEmulate.SetBreakPoint("__isinstruction('rol word ptr [e')");//5
	objEmulate.SetBreakPoint("__isinstruction('ror word ptr [e')");//6
	objEmulate.SetBreakPoint("__isinstruction('add word ptr [e')");//7
	objEmulate.SetBreakPoint("__isinstruction('sub word ptr [e')");//8
	objEmulate.SetBreakPoint("__isinstruction('xor word ptr [e')");//9

	objEmulate.SetBreakPoint("__isinstruction('rol byte ptr [e')");//10
	objEmulate.SetBreakPoint("__isinstruction('ror byte ptr [e')");//11
	objEmulate.SetBreakPoint("__isinstruction('add byte ptr [e')");//12
	objEmulate.SetBreakPoint("__isinstruction('sub byte ptr [e')");//13
	objEmulate.SetBreakPoint("__isinstruction('xor byte ptr [e')");//14
	objEmulate.SetBreakPoint("__isinstruction('cmp')");//15
	objEmulate.SetBreakPoint("__isinstruction('xor e')");//16
	objEmulate.SetBreakPoint("__isinstruction('add e')");//17
	objEmulate.SetBreakPoint("__isinstruction('sub e')");//18
	objEmulate.SetBreakPoint("__isinstruction('or e')");//19
	objEmulate.SetBreakPoint("__isinstruction('jmp')");//20

	objEmulate.PauseBreakPoint(15);
	objEmulate.PauseBreakPoint(16);
	objEmulate.PauseBreakPoint(17);
	objEmulate.PauseBreakPoint(18);
	objEmulate.PauseBreakPoint(19);
	objEmulate.PauseBreakPoint(20);	
	objEmulate.SetNoOfIteration(0x200);
	objEmulate.SetEip(m_dwImageBase + m_dwCalledAdd);

	if(7 == objEmulate.EmulateFile())
	{
		m_byCheck = 7;
		
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Vampiro.Gen"));
		iRetStatus = VIRUS_FILE_REPAIR;
		
		for(int i = 0; i < 0x20; i++)
		{
			if(m_pbyBuff[i] == 0xE8)
			{
				DWORD dwCallOffset = *(DWORD *)&m_pbyBuff[i + 1];			
				dwCallOffset += i + 5;
				if((dwCallOffset < 0x30) && (m_pbyBuff[dwCallOffset] == 0xC3))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.trus.a"));
					iRetStatus = VIRUS_FILE_DELETE;
					break;
				}
			}
		}
		m_iVariant = DetectVampiroDec(objEmulate);
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Vampiro Family
--------------------------------------------------------------------------------------*/
int CPolyVampiro::CleanVirus(void)
{
	switch(m_iVariant)
	{
	case 0: 
		{
			m_pMaxPEFile->CloseFile_NoMemberReset();
			return DeleteFile(m_pMaxPEFile->m_szFilePath)? REPAIR_SUCCESS : REPAIR_FAILED;		
		}
	case 1://replaced FF15 call
		{
			WORD REPLACEBY = 0x15FF;
			m_pMaxPEFile->WriteBuffer(&REPLACEBY,m_dwPatcedAddr,2,2);
			m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwOffset + 4],(m_dwPatcedAddr + 2),4,4);				
		}
		break;
	case 2://Replaced E8 call
		{
			BYTE REPLACEBY = 0xE8;
			m_pMaxPEFile->WriteBuffer(&REPLACEBY,m_dwPatcedAddr,1,1);
			m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwOffset + 4],(m_dwPatcedAddr + 1),4,4);
		}
		break;
	case 3://multiple decryptions
		{
			DWORD dwpatchedAddr = *((DWORD*)&m_pbyBuff[m_dwOffset]); 
			if(OUT_OF_FILE !=(m_pMaxPEFile->Rva2FileOffset(dwpatchedAddr,&dwpatchedAddr)))
			{
				if(dwpatchedAddr == m_dwPatcedAddr)
				{
					m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwOffset - 5],m_dwPatcedAddr,5,5);
				}
			}
		}
		break;
	case 4://multiple decryptions
		{				
			m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwOffset - 0xD0],m_dwPatcedAddr,5,5);				
		}
		break;
	}
	
	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwCalledAdd, &m_dwCalledAdd))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwCalledAdd,true))
		{
			return REPAIR_SUCCESS;
		}
	}

	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVampiroDec
	In Parameters	: CEmulate &objEmulate
	Out Parameters	: >0 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function detects the start address of decryption loop and infection type
--------------------------------------------------------------------------------------*/
int CPolyVampiro::DetectVampiroDec(CEmulate &objEmulate)
{
	int iRetStatus = 0;
	bool bCheck = false;
	char szTempInstr[MAX_INSTRUCTION_LEN + 0xA] = {0};
	DWORD dwEmulateStartOff = 0, dwDecStartOffset = 0, dwDecBufStart = 0, dwNumofDec = 1, FIRST_EIP = 0;
	DWORD dwRegValue[8] = {0}, dwPreCounter = MAX_VAMPIRO_BUFF_SIZE, BPValue = 21;
	KeyOPerations KeyOPs[0x30] = {0};
	JumpData JmpData[10] = {0}; 

	dwEmulateStartOff = dwDecBufStart = m_dwImageBase + m_dwCalledAdd;

	//This loop detects the decryption instruction and all decryption parameters
	while(1)
	{		

		bCheck = false;
		FIRST_EIP = 0;		
		memset(szTempInstr,0x00,0x2A);
		memset(dwRegValue,0x00,(8*4));		

		if(7 == m_byCheck)
		{
			FIRST_EIP = objEmulate.GetEip();
			if((objEmulate.GetMemoryOprand() < m_dwImageBase) || (objEmulate.GetMemoryOprand() > (m_dwImageBase + m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)))
			{
				objEmulate.SetEip((objEmulate.GetEip() + objEmulate.GetInstructionLength()));
				if(7 != objEmulate.EmulateFile())
				{
					return iRetStatus;
				}
				continue;
			}
	
			//Store EIP of the decryption instruction 
			for(int i = 0; i < 8; i++)
			{
				dwRegValue[i] = objEmulate.GetSpecifyRegValue(i);
			}
		}
		else if(dwNumofDec > 1)
		{
			return iRetStatus;
		}

		bool bIsKeyReg = false;
		if(!GetDecryptionParameter(objEmulate, bIsKeyReg))//To get initial value of the key & instrucion used for decryption  
		{
			return iRetStatus;
		}

		dwDecStartOffset = objEmulate.GetMemoryOprand();//Starting address of the decryption

		if(bIsKeyReg == true)
		{
			m_byKeyRegNo = (BYTE)objEmulate.GetSrcRegNo();	//Get Register for key
			switch(m_byKeyRegNo)
			{
			case 0:
				strcpy_s(&szRegName[0][0],4,"eax");
				strcpy_s(&szRegName[1][0],4,"al");
				strcpy_s(&szRegName[2][0],4,"ah");
				objEmulate.SetBreakPoint("__isinstruction('ax')");//18
				objEmulate.SetBreakPoint("__isinstruction(' al')");//19
				objEmulate.SetBreakPoint("__isinstruction(' ah')");//20
				break;
			case 1:
				strcpy_s(&szRegName[0][0],4,"ecx");
				strcpy_s(&szRegName[1][0],4,"cl");
				strcpy_s(&szRegName[2][0],4,"ch");
				objEmulate.SetBreakPoint("__isinstruction('cx')");
				objEmulate.SetBreakPoint("__isinstruction(' cl')");
				objEmulate.SetBreakPoint("__isinstruction(' ch')");
				break;
			case 2:
				strcpy_s(&szRegName[0][0],4,"edx");
				strcpy_s(&szRegName[1][0],4,"dl");
				strcpy_s(&szRegName[2][0],4,"dh");
				objEmulate.SetBreakPoint("__isinstruction('dx')");
				objEmulate.SetBreakPoint("__isinstruction(' dl')");
				objEmulate.SetBreakPoint("__isinstruction(' dh')");
				break;
			case 3:
				strcpy_s(&szRegName[0][0],4,"ebx");
				strcpy_s(&szRegName[1][0],4,"bl");
				strcpy_s(&szRegName[2][0],4,"bh");
				objEmulate.SetBreakPoint("__isinstruction('bx')");
				objEmulate.SetBreakPoint("__isinstruction(' bl')");
				objEmulate.SetBreakPoint("__isinstruction(' bh')");
				break;
			case 4:
				strcpy_s(&szRegName[0][0],4,"esp");
				objEmulate.SetBreakPoint("__isinstruction('sp')");
				break;
			case 5:
				strcpy_s(&szRegName[0][0],4,"ebp");
				objEmulate.SetBreakPoint("__isinstruction('bp')");
				break;
			case 6:
				strcpy_s(&szRegName[0][0],4,"esi");
				objEmulate.SetBreakPoint("__isinstruction('si')");
				break;
			case 7:
				strcpy_s(&szRegName[0][0],4,"edi");
				objEmulate.SetBreakPoint("__isinstruction('di')");
				break;
			}
		}
		objEmulate.ActiveBreakPoint(15);
		objEmulate.ActiveBreakPoint(16);
		objEmulate.ActiveBreakPoint(17);
		objEmulate.ActiveBreakPoint(18);
		objEmulate.ActiveBreakPoint(19);
		objEmulate.ActiveBreakPoint(20);
		objEmulate.SetNoOfIteration(500);		

		int i = 0, j = 0, k = 0;
		DWORD dwNegJmpEip = 0;
		DWORD dwJmpOff = 0;		
		DWORD dwDecLimit = 0x00;
		bool EndLoop = false;

		//Emulating the loop for once to get operations on the key and counter value		
		while(1)
		{
			if(7 != objEmulate.EmulateFile(false))
			{
				return iRetStatus;
			}

			memset(szTempInstr, 0, MAX_INSTRUCTION_LEN);
			objEmulate.GetInstruction(szTempInstr);			
			if(FIRST_EIP == (objEmulate.GetEip()))
			{
				EndLoop = true;
				break;
			}
			if(bIsKeyReg)//If key is a register then store all operations on it into structure KeyOPs
			{
				if(strstr(szTempInstr,*szRegName)||strstr(szTempInstr,&szRegName[0][1])||((strstr(szTempInstr,szRegName[1])||strstr(szTempInstr,szRegName[2])) && m_byKeyRegNo < 4))
				{
					if((strstr(szTempInstr,"inc")||strstr(szTempInstr,"dec")||strstr(szTempInstr,"add")||strstr(szTempInstr,"sub")||strstr(szTempInstr,"xor")||strstr(szTempInstr,"push")||strstr(szTempInstr,"pop")||
						strstr(szTempInstr,"rol")||strstr(szTempInstr,"ror")||strstr(szTempInstr,"xchg")||strstr(szTempInstr,"mov")||strstr(szTempInstr,"not")) && (objEmulate.GetSrcRegNo() != objEmulate.GetDestRegNo()))
					{
						strcpy_s(KeyOPs[i].szInstrName, MAX_INSTRUCTION_LEN, szTempInstr);
						KeyOPs[i].dwOperand = objEmulate.GetImmidiateConstant();
						KeyOPs[i].m_byInstrLen = (BYTE)objEmulate.GetInstructionLength();
						KeyOPs[i].byDestReg = (BYTE)objEmulate.GetDestRegNo();
						KeyOPs[i].bySrcReg = (BYTE)objEmulate.GetSrcRegNo();
						KeyOPs[i].SrcRegValue = objEmulate.GetSpecifyRegValue(KeyOPs[i].bySrcReg);
						KeyOPs[i++].DestRegValue = objEmulate.GetDestinationOprand();							
					}
				}
			}				
			if((strstr(szTempInstr,"cmp")||strstr(szTempInstr,"xor")||strstr(szTempInstr,"add")||strstr(szTempInstr,"sub")||strstr(szTempInstr,"or")) && ((6 == objEmulate.GetInstructionLength())|| (3 == objEmulate.GetInstructionLength())))
			{
				//Virus checks counter with all above instructions followed by JE instruction
				BYTE byBuff[0x20];
				DWORD byOffset = 0;
				DWORD dweip = objEmulate.GetEip();
				objEmulate.ReadEmulateBuffer(byBuff, 0x0C, dweip);
				byOffset = objEmulate.GetInstructionLength();
				if((*(WORD *)&byBuff[byOffset] == 0x840f) || byBuff[byOffset] == 0x74)//74 == JE short
				{
					JmpData[j].Eip = dweip + byOffset;
					JmpData[j].JmpOffset = *(DWORD *)&byBuff[byOffset + 2];
					JmpData[j].CounterReg = objEmulate.GetDestRegNo();
					JmpData[j].CounterValue = objEmulate.GetDestinationOprand();
					if(byBuff[byOffset] == 0x74)
					{							
						JmpData[j].JmpOffset = byBuff[byOffset + 1];
						JmpData[j].JmpOffset = JmpData[j].JmpOffset + JmpData[j].Eip + 2;
					}
					else
					{
						JmpData[j].JmpOffset = JmpData[j].JmpOffset + JmpData[j].Eip + 6;
					}
					if(byOffset == 6)
					{

						JmpData[j++].CmpOffset = *(DWORD *)&byBuff[2];
					}
					else
					{
						JmpData[j++].CmpOffset = 0x00;
					}
				}
			}
			else if(strstr(szTempInstr,"jmp") && (5 == objEmulate.GetInstructionLength()))
			{
				if(objEmulate.GetJumpAddress() < objEmulate.GetEip())//Negative jump 
				{						
					if(dwNegJmpEip <= objEmulate.GetEip())
					{							
						dwNegJmpEip = objEmulate.GetEip();
					}
				}				
			}						
		}				
		for(int i = 0; i < j; i++)
		{
			if(JmpData[i].JmpOffset > dwNegJmpEip)//if JE offset > negative jump then its breaking condition
			{	
				dwEmulateStartOff = JmpData[i].JmpOffset;
				m_dwCounter = dwRegValue[JmpData[i].CounterReg] - JmpData[i].CmpOffset;
				dwDecLimit = dwRegValue[JmpData[i].CounterReg] - JmpData[i].CounterValue;
				if(dwDecLimit <= 4 && dwDecLimit > 0)//Check whether counter value is changed between comparision and decryption
				{
					dwDecLimit = dwRegValue[JmpData[i].CounterReg] - JmpData[i].CounterValue;
				}
				else if(((~(dwDecLimit)) <= 3) && ((~(dwDecLimit)) >= 0))
				{
					dwDecLimit = ~(dwDecLimit)+ 1;
				}
				else
				{
					dwDecLimit = 0x00;
				}
				if((~(m_dwCounter) > (0x2000 - (dwNumofDec * 0x300))) && ~(m_dwCounter) < dwPreCounter)
				{
					m_dwCounter = ~(m_dwCounter)+1;
					bCheck = true;
					break;
				}
				else if((m_dwCounter > (0x2000 - (dwNumofDec * 0x300))) && (m_dwCounter < dwPreCounter))
				{
					bCheck = true;
					break;
				}								
			}
		}
		if(bCheck != true && (EndLoop == true))
		{
			return iRetStatus;
		}

		m_dwNoOfBytes = m_dwCounter;		
		if(bCheck)
		{
			DWORD dwEBP = 0,dwPatched = 0;	
			if(bIsKeyReg)
			{
				if(0 == GetKeyChangeParameter(&KeyOPs[0]))//filter key operations and keep only valid one's
				{
					m_dwKeyChngType[0] = 0;
				}
				if(m_byKeyRegNo < 4)
				{
					objEmulate.PauseBreakPoint(BPValue++);
					objEmulate.PauseBreakPoint(BPValue++);
					objEmulate.PauseBreakPoint(BPValue++);
				}
				else
				{
					objEmulate.PauseBreakPoint(BPValue++);
				}
			}
			if(m_dwType > 9 && m_dwType < 99)//decryption is wordwise
			{
				m_dwNoOfBytes += 2;
			}
			else if(m_dwType > 0 && m_dwType < 9)//decryption is DWORD wise
			{
				m_dwNoOfBytes += 4;
			}
			else//decryption is byte wise
			{
				m_dwNoOfBytes += 1;
			}
			memset(m_pbyBuff, 0, dwPreCounter);
			if(dwDecStartOffset > (dwDecBufStart + (0x2200 - (dwNumofDec * 0x200))))
			{
				if(!objEmulate.ReadEmulateBuffer(m_pbyBuff, m_dwNoOfBytes, (dwDecStartOffset - m_dwCounter)))
				{
					return iRetStatus;
				}
				DoDecryptionRev(dwDecLimit);//decryption starts from bottom to top
				dwDecBufStart = (dwDecStartOffset - m_dwCounter);
			}
			else
			{
				if(!objEmulate.ReadEmulateBuffer(m_pbyBuff, m_dwNoOfBytes, (dwDecStartOffset)))
				{
					return iRetStatus;
				}
				DoDecryption(0);
				dwDecBufStart = dwDecStartOffset;
			}		

			if(dwNumofDec == 1)//If No. of decryptions is one then check call 0x89e and 0xd91 
			{
				BYTE CHECKCALL1_SIG[] = {0xE8,0x9E,0x08,0x00,0x00};
				BYTE CHECKCALL2_SIG[] = {0xE8,0x33,0x0A,0x00,0x00};
				if(OffSetBasedSignature(CHECKCALL1_SIG, sizeof(CHECKCALL1_SIG), &m_dwOffset) || (OffSetBasedSignature(CHECKCALL2_SIG, sizeof(CHECKCALL2_SIG), &m_dwOffset)))
				{
					DWORD iOffset = 0;				
					BYTE CHECK2_SIG[] = {0xE8,0x05,0x00,0x00,0x00};
					iOffset = *((DWORD*)&m_pbyBuff[m_dwOffset + 1]) + 0x6 + m_dwOffset;
					if(iOffset > MAX_VAMPIRO_BUFF_SIZE - 0x13)
					{
						return iRetStatus;
					}
					if(memcmp(&m_pbyBuff[iOffset],CHECK2_SIG,sizeof(CHECK2_SIG))==0)
					{						
						dwEBP = dwDecBufStart + iOffset + 5;
						dwEBP -= *((DWORD*)&m_pbyBuff[iOffset + 0xF]);
					}

					BYTE CHECKCALL3_SIG[] = {0xE8,0x91,0x0D,0x00,0x00};
					BYTE CHECKCALL4_SIG[] = {0xE8,0x16,0x0F,0x00,0x00};
					if(memcmp(&m_pbyBuff[m_dwOffset + 0x41],CHECKCALL3_SIG,sizeof(CHECKCALL3_SIG))==0)
					{						
						m_dwOffset = (dwEBP + 0x403F38) - dwDecBufStart;
					}
					else if(memcmp(&m_pbyBuff[m_dwOffset + 0x51],CHECKCALL4_SIG,sizeof(CHECKCALL4_SIG))==0)
					{							
						m_dwOffset = (dwEBP + 0x4040CD) - dwDecBufStart;
					}
					if(*((DWORD*)&m_pbyBuff[m_dwOffset]) == (m_dwImageBase + m_dwCalledAdd))
					{
						if(*((DWORD*)&m_pbyBuff[m_dwOffset + 8]) == 1)
						{
							return 1;
						}
						else if(*((DWORD*)&m_pbyBuff[m_dwOffset + 8]) == 0)
						{
							if(CalculateCallAdderess())
							{
								return 2;
							}
							return iRetStatus;
						}
					}
				}
			}		
			m_dwOffset = 0; 
			BYTE CHECK1_SIG[] = {0x00,0x00,0xE8,0x09,0x00,0x00,0x00,0x8B,0x64,0x24,0x08,0xE9};
			for(DWORD iOffset= 0x00; iOffset < 0x2A0; iOffset++)
			{
				if(memcmp(&m_pbyBuff[iOffset],CHECK1_SIG,sizeof(CHECK1_SIG))==0)//Multiple decryptions
				{
					DWORD dwCallVal = 0;
					if(!objEmulate.WriteBuffer(m_pbyBuff,m_dwNoOfBytes,dwDecBufStart))
					{
						return iRetStatus;
					}
					objEmulate.ReadEmulateBuffer((BYTE *)&dwCallVal,0x04,(dwDecBufStart + iOffset - 0x2));
					m_dwOffset = dwCallVal + iOffset + 0x2;
					if(m_dwOffset > MAX_VAMPIRO_BUFF_SIZE - 4)
					{
						return iRetStatus;
					}

					BYTE CHECK2_SIG[] = {0xE8,0x00,0x00,0x00,0x00};
					DWORD dwEBP = 0;
					if(memcmp(&m_pbyBuff[m_dwOffset],CHECK2_SIG,sizeof(CHECK2_SIG))==0)
					{						
						dwEBP = (dwDecBufStart + m_dwOffset + 5);
						dwEBP -= *((DWORD*)&m_pbyBuff[m_dwOffset + 0x9]);
						if(dwCallVal == 0x3BA)
						{
							m_dwOffset = (dwEBP + 0x4024A6) - dwDecBufStart;												
						}
						else
						{
							m_dwOffset = (dwEBP + 0x402112) - dwDecBufStart;
						}
						dwPatched = *((DWORD*)&m_pbyBuff[m_dwOffset]);
						if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwPatched, &dwPatched))
						{
							return iRetStatus;
						}
						break;
					}
				}
			}

			if(dwPatched == m_dwPatcedAddr)
			{
				return 3;
			}
			else if(dwPatched == m_dwAEPMapped)
			{
				return 4;
			}
			else
			{
				if(!objEmulate.WriteBuffer(m_pbyBuff,m_dwNoOfBytes,dwDecBufStart))
				{
					return iRetStatus;
				}
				objEmulate.PauseBreakPoint(15);
				objEmulate.PauseBreakPoint(16);
				objEmulate.PauseBreakPoint(17);
				objEmulate.PauseBreakPoint(18);
				objEmulate.PauseBreakPoint(19);
				objEmulate.PauseBreakPoint(20);					
				dwPreCounter = m_dwCounter;

				m_dwCounter = 0;
				m_dwNoOfBytes = 0;
				memset(m_dwKeyChngKey,0x00,5*0x4);
				memset(m_dwKeyChngType,0x00,5*0x04);
				memset(KeyOPs, 0, sizeof(KeyOPerations)*0x30);
				memset(szRegName, 0,3*5);
				objEmulate.SetNoOfIteration(0x250);
				objEmulate.SetEip(dwEmulateStartOff);
				dwNumofDec++;
				m_byCheck = 0;
				if(7 == objEmulate.EmulateFile())//emulate for next decryption
				{
					m_byCheck = 7;
				}
			}			
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDecryptionParameter
	In Parameters	: CEmulate &objEmulate, bool &bIsKeyReg
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function collects parameters required for decryption. key, length etc.
--------------------------------------------------------------------------------------*/
int CPolyVampiro::GetDecryptionParameter(CEmulate &objEmulate, bool &bIsKeyReg)
{
	char szInstruction[0x50] = {0};
	char *szTempPtr = NULL;

	objEmulate.GetInstruction(szInstruction);

	szTempPtr = strrchr(szInstruction,',');	
	if(strstr(szTempPtr, ",e")||strstr(szTempPtr,"x")||strstr(szTempPtr,"i")||strstr(szTempPtr,"p")||strstr(szTempPtr,"l"))
	{
		bIsKeyReg = true;
	}
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
	else if(strstr(szInstruction, "rol dword ptr"))
	{
		m_dwType = 4;
		m_dwKey = objEmulate.GetImmidiateConstant();
	}
	else if(strstr(szInstruction, "ror dword ptr"))
	{
		m_dwType = 5;
		m_dwKey = objEmulate.GetImmidiateConstant();
	}

	else if(strstr(szInstruction, "add word ptr"))
	{
		m_dwType = 11;
		m_dwKey = objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction,"xor word ptr"))
	{
		m_dwType = 21;
		m_dwKey = objEmulate.GetImmidiateConstant();
	}
	else if(strstr(szInstruction, "sub word ptr"))
	{
		m_dwType = 31;
		m_dwKey = objEmulate.GetImmidiateConstant();
	}
	else if(strstr(szInstruction,"rol word ptr"))
	{
		m_dwType = 41;
		m_dwKey = objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction,"ror word ptr"))
	{
		m_dwType = 51;
		m_dwKey = objEmulate.GetImmidiateConstant(); 
	}

	else if(strstr(szInstruction, "add byte ptr"))
	{
		m_dwType = 101;
		m_dwKey = objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction,"xor byte ptr"))
	{
		m_dwType = 201;
		m_dwKey = objEmulate.GetImmidiateConstant();
	}
	else if(strstr(szInstruction, "sub byte ptr"))
	{
		m_dwType = 301;
		m_dwKey = objEmulate.GetImmidiateConstant();
	}
	else if(strstr(szInstruction,"rol byte ptr"))
	{
		m_dwType = 401;
		m_dwKey = objEmulate.GetImmidiateConstant(); 
	}
	else if(strstr(szInstruction,"ror byte ptr"))
	{
		m_dwType = 501;
		m_dwKey = objEmulate.GetImmidiateConstant(); 
	}
	else 
	{
		return false;
	}	
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKeyChangeParameter
	In Parameters	: KeyOPerations *KeyOPs
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function collects parameters required for decryption. key, length etc.
--------------------------------------------------------------------------------------*/
int CPolyVampiro::GetKeyChangeParameter(KeyOPerations *KeyOPs)
{	
	int iRetstatus = 0,j =0,k=0;
	char TempReg[10] = {0};
	for(k = 30 ; (k >= 0) && (KeyOPs[k].m_byInstrLen == 0);k--);

	if(strstr(KeyOPs[k].szInstrName,"mov") && (m_dwKey == KeyOPs[k].DestRegValue))
	{
		return 1;
	}
	else if(strstr(KeyOPs[k].szInstrName,"xchg") && ((m_dwKey == KeyOPs[k].SrcRegValue) || (m_dwKey == KeyOPs[k].DestRegValue)))
	{
		return 1;
	}
	for(int i = 0; ((i < 0x30) && (KeyOPs[i].m_byInstrLen > 0)); i++)
	{
		if(strstr(KeyOPs[i].szInstrName,"push"))
		{
			int j = 0;
			for(j = i+1; (j < 0x30 && KeyOPs[i].m_byInstrLen > 0); j++)
			{
				if(strstr(KeyOPs[j].szInstrName,"push")||KeyOPs[j].m_byInstrLen == 0)
					break;//If push followed by push ignore first push
				else if(strstr(KeyOPs[j].szInstrName,"pop"))//if POP instruction found ignore all instructions inbetween 
				{
					i = j;
					break;
				}
			}
		}
		if(strstr(KeyOPs[i].szInstrName,"xchg") && KeyOPs[i].m_byInstrLen == 2)
		{
			BYTE TempSrcReg = KeyOPs[i].bySrcReg;
			BYTE TempDestReg = KeyOPs[i].byDestReg;
			for(int j = i + 1; (j < 0x30 && KeyOPs[j].m_byInstrLen > 0); j++)
			{
				if(strstr(KeyOPs[j].szInstrName,"xchg") && (((TempSrcReg == KeyOPs[j].bySrcReg) && (TempDestReg == KeyOPs[j].byDestReg)) ||
					((TempDestReg == KeyOPs[j].bySrcReg) && (TempSrcReg == KeyOPs[j].byDestReg))))
				{
					//check pair XCHG-XCHG and skip instruction inbetween
					i = j;
					break;
				}
				else if(strstr(KeyOPs[j].szInstrName,"mov") && (((TempSrcReg == KeyOPs[j].bySrcReg) && (TempDestReg == KeyOPs[j].byDestReg)) ||
					((TempDestReg == KeyOPs[j].bySrcReg) && (TempSrcReg == KeyOPs[j].byDestReg)))) 
				{
					//check pair XCHG-MOV and skip instruction inbetween
					i = j;
					break;
				}
			}			
		}
		else if(strstr(KeyOPs[i].szInstrName,"mov") && ((m_byKeyRegNo == KeyOPs[i].bySrcReg) && (KeyOPs[i].m_byInstrLen == 2)))
		{
			BYTE byTempReg = KeyOPs[i].byDestReg;
			BYTE bySrcReg  = KeyOPs[i].bySrcReg;
			DWORD dwkeyData = KeyOPs[i].SrcRegValue;
			for(int j = i + 1; (j < 0x30 && KeyOPs[j].m_byInstrLen > 0); j++)
			{
				if(strstr(KeyOPs[j].szInstrName,"mov") && ((m_byKeyRegNo == KeyOPs[j].bySrcReg) && (byTempReg ==KeyOPs[j].byDestReg)))
				{
					break;// if mov folllowed by mov with same reg as src and dest
				}
				else if(strstr(KeyOPs[j].szInstrName,"xchg") && (((byTempReg == KeyOPs[j].bySrcReg) && (m_byKeyRegNo == KeyOPs[j].byDestReg)) || 
					((m_byKeyRegNo == KeyOPs[j].bySrcReg) && (byTempReg == KeyOPs[j].byDestReg))))
				{
					//check pair MOV-XCHG and skip instruction inbetween
					if((dwkeyData == KeyOPs[j].SrcRegValue) || (dwkeyData == KeyOPs[j].DestRegValue))
					{
						i = j;
						break;
					}
				}
				else if(strstr(KeyOPs[j].szInstrName,"mov") && ((byTempReg == KeyOPs[j].bySrcReg) && m_byKeyRegNo == KeyOPs[j].byDestReg))
				{
					//check pair MOV-MOV and skip instruction inbetween
					if(dwkeyData == KeyOPs[j].SrcRegValue)
					{
						i = j;
						break;
					}
				}
			}
			for(int j = i+1;((j < i + 5)&& KeyOPs[j].m_byInstrLen > 0);j++)
			{
				if(strstr(KeyOPs[j].szInstrName,"mov") && ((dwkeyData == KeyOPs[j].SrcRegValue)) && (byTempReg == KeyOPs[j].bySrcReg) && (bySrcReg == KeyOPs[j].byDestReg))
				{
					i = j;
					break;
				}
				else if(strstr(KeyOPs[j].szInstrName,"xchg") && ((m_byKeyRegNo == KeyOPs[j].bySrcReg) && (byTempReg == KeyOPs[j].byDestReg)))
				{
					if(dwkeyData == (KeyOPs[j].DestRegValue - 1) || dwkeyData == (KeyOPs[j].SrcRegValue - 1) || dwkeyData == (KeyOPs[j].DestRegValue + 1) || dwkeyData == (KeyOPs[j].SrcRegValue + 1))
					{
						i = j + 1;
						break;
					}
				}
			}
		}		
		else if(strstr(KeyOPs[i].szInstrName, "add"))
		{
			char srcReg[4] = {0};
			//strncpy(srcReg, &KeyOPs[i].szInstrName[4], 3);
			memcpy(srcReg, &KeyOPs[i].szInstrName[4], 3);
			if(strstr(srcReg,*szRegName)||strstr(srcReg,&szRegName[0][1])||((strstr(srcReg,szRegName[1])||strstr(srcReg,szRegName[2])) && m_byKeyRegNo < 4))
			{
				m_dwKeyChngType[j] = 1;//ADD DWORD PTR
				if(strstr(srcReg,szRegName[1]) && m_byKeyRegNo < 4)
				{
					m_dwKeyChngType[j] = 12;//ADD BYTE AL,const
				}
				else if(strstr(srcReg,szRegName[2]) && m_byKeyRegNo < 4)
				{
					m_dwKeyChngType[j] = 13;//ADD BYTE AH,const
				}
				if(KeyOPs[i].m_byInstrLen == 5)
				{
					m_dwKeyChngType[j] = 11;//ADD DWORD PTR
				}			
				m_dwKeyChngKey[j++] = KeyOPs[i].dwOperand;
				iRetstatus = 1;
			}
		}
		else if(strstr(KeyOPs[i].szInstrName, "xor"))
		{
			char srcReg[4] = {0};
			//strncpy(srcReg, &KeyOPs[i].szInstrName[4], 3);
			memcpy(srcReg, &KeyOPs[i].szInstrName[4], 3);
			if(strstr(srcReg,*szRegName)||strstr(srcReg,&szRegName[0][1])||((strstr(srcReg,szRegName[1])||strstr(srcReg,szRegName[2])) && m_byKeyRegNo < 4))
			{
				m_dwKeyChngType[j] = 2;//XOR DWORD PTR
				if(strstr(srcReg,szRegName[1]) && m_byKeyRegNo < 4)
				{
					m_dwKeyChngType[j] = 22; 
				}
				else if(strstr(srcReg,szRegName[2]) && m_byKeyRegNo < 4)
				{
					m_dwKeyChngType[j] = 23;
				}
				else if(KeyOPs[i].m_byInstrLen == 5)
				{
					m_dwKeyChngType[j] = 21;//XOR WORD PTR
				}			
				m_dwKeyChngKey[j++] = KeyOPs[i].dwOperand;
				iRetstatus = 1;
			}
		}
		else if(strstr(KeyOPs[i].szInstrName, "sub"))
		{
			char srcReg[4] = {0};
			//strncpy(srcReg, &KeyOPs[i].szInstrName[4], 3);//SUB DWORD PTR
			memcpy(srcReg, &KeyOPs[i].szInstrName[4], 3);
			if(strstr(srcReg,*szRegName)||strstr(srcReg,&szRegName[0][1])||((strstr(srcReg,szRegName[1])||strstr(srcReg,szRegName[2])) && m_byKeyRegNo < 4))
			{
				m_dwKeyChngType[j] = 3;
				if(strstr(srcReg,szRegName[1]) && m_byKeyRegNo < 4)
				{
					m_dwKeyChngType[j] = 33; 
				}
				else if(strstr(srcReg,szRegName[2]) && m_byKeyRegNo < 4)
				{
					m_dwKeyChngType[j] = 32;
				}
				else if(KeyOPs[i].m_byInstrLen == 5)
				{
					m_dwKeyChngType[j] = 31;//SUB WORD PTR
				}			
				m_dwKeyChngKey[j++] = KeyOPs[i].dwOperand;
				iRetstatus = 1;
			}
		}
		else if(strstr(KeyOPs[i].szInstrName, "rol"))
		{
			char srcReg[4] = {0};
			//strncpy(srcReg, &KeyOPs[i].szInstrName[4], 3);
			memcpy(srcReg, &KeyOPs[i].szInstrName[4], 3);
			if(strstr(srcReg,*szRegName)||strstr(srcReg,&szRegName[0][1])||((strstr(srcReg,szRegName[1])||strstr(srcReg,szRegName[2])) && m_byKeyRegNo < 4))
			{
				m_dwKeyChngType[j] = 4;//ROL DWORD PTR
				m_dwKeyChngKey[j] = KeyOPs[i].dwOperand;
				if(KeyOPs[i].m_byInstrLen == 4)
				{
					m_dwKeyChngType[j] = 41;//ROL WORD PTR				
					m_dwKeyChngKey[j++] = m_dwKeyChngKey[j] % 16;				
				}
				else if(strstr(KeyOPs[i].szInstrName, "h ,") && m_byKeyRegNo < 4)
				{
					m_dwKeyChngType[j] = 42;				
					m_dwKeyChngKey[j++] = m_dwKeyChngKey[j] % 8;
				}
				else if(strstr(KeyOPs[i].szInstrName, "l ,") && m_byKeyRegNo < 4)
				{
					m_dwKeyChngType[j] = 43;				
					m_dwKeyChngKey[j++] = m_dwKeyChngKey[j] % 8;
				}
				else
				{
					m_dwKeyChngKey[j++] = m_dwKeyChngKey[j] % 32;
				}
				iRetstatus = 1;
			}
		}
		else if(strstr(KeyOPs[i].szInstrName, "ror"))
		{
			char srcReg[4] = {0};
			//strncpy(srcReg, &KeyOPs[i].szInstrName[4], 3);
			memcpy(srcReg, &KeyOPs[i].szInstrName[4], 3);
			if(strstr(srcReg,*szRegName)||strstr(srcReg,&szRegName[0][1])||((strstr(srcReg,szRegName[1])||strstr(srcReg,szRegName[2])) && m_byKeyRegNo < 4))
			{
				m_dwKeyChngType[j] = 5;//ROR DWORD PTR
				m_dwKeyChngKey[j] = KeyOPs[i].dwOperand;
				if(KeyOPs[i].m_byInstrLen == 4)
				{
					m_dwKeyChngType[j] = 51;//ROR WORD PTR
					m_dwKeyChngKey[j] = KeyOPs[i].dwOperand;
					m_dwKeyChngKey[j++] = m_dwKeyChngKey[j] % 16;				
				}
				else if(strstr(KeyOPs[i].szInstrName, "h ,") && m_byKeyRegNo < 4)
				{
					m_dwKeyChngType[j] = 52;
					m_dwKeyChngKey[j] = KeyOPs[i].dwOperand;
					m_dwKeyChngKey[j++] = m_dwKeyChngKey[j] % 8;
				}
				else if(strstr(KeyOPs[i].szInstrName, "l ,") && m_byKeyRegNo < 4)
				{
					m_dwKeyChngType[j] = 53;				
					m_dwKeyChngKey[j++] = m_dwKeyChngKey[j] % 8;
				}
				else
				{
					m_dwKeyChngKey[j++] = m_dwKeyChngKey[j] % 32;
				}
			}
			iRetstatus = 1;
		}
		else if(strstr(KeyOPs[i].szInstrName, "inc"))
		{
			m_dwKeyChngType[j] = 6;//INC EAX
			if(KeyOPs[i].m_byInstrLen == 2)
			{
				m_dwKeyChngType[j] = 61;//INC AX
			}
			j++;
			iRetstatus = 1;
		}
		else if(strstr(KeyOPs[i].szInstrName, "dec"))
		{
			m_dwKeyChngType[j] = 7;//DEC EAX
			if(KeyOPs[i].m_byInstrLen == 2)
			{
				m_dwKeyChngType[j] = 71;//DEC AX
			}
			j++;
			iRetstatus = 1;
		}
		else if(strstr(KeyOPs[i].szInstrName, "not"))
		{
			m_dwKeyChngType[j] = 8;//NOT EAX

			if(strstr(KeyOPs[i].szInstrName, "h"))
			{
				m_dwKeyChngType[j] = 81;//NOT AH
			}
			else if(strstr(KeyOPs[i].szInstrName, "l"))
			{
				m_dwKeyChngType[j] = 83;//NOT AL
			}
			else if(KeyOPs[i].m_byInstrLen == 3)
			{
				m_dwKeyChngType[j] = 82;//NOT AX
			}
			j++;
			iRetstatus = 1;
		}
		else if(!KeyOPs[i].m_byInstrLen)
		{
			break;
		}
	}
	return iRetstatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptKey
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function retrieves decryption key
--------------------------------------------------------------------------------------*/
void CPolyVampiro::DecryptKey()//Do operations on the key
{
	WORD wTempKey = 0;
	BYTE bTempKey = 0;
	for(int j = 0; j < 5; j++)
	{	
		switch(m_dwKeyChngType[j])
		{
		case 1://ADD
			m_dwKey += m_dwKeyChngKey[j];
			break;
		case 11:
			wTempKey = ((WORD)m_dwKey + (WORD)m_dwKeyChngKey[j]);
			m_dwKey =((m_dwKey >> 16) << 16) + wTempKey;
			break;
		case 12:
			bTempKey = (BYTE)m_dwKey;
			bTempKey += (BYTE)m_dwKeyChngKey[j];
			m_dwKey = ((m_dwKey >> 8) << 8) + bTempKey;
			break;
		case 13:
			bTempKey = (BYTE)(m_dwKey >> 8);
			bTempKey += (BYTE)m_dwKeyChngKey[j];
			m_dwKey = ((m_dwKey >> 16) << 16) + (BYTE)m_dwKey + (bTempKey << 8);
			break;

		case 2://XOR
			m_dwKey ^= m_dwKeyChngKey[j];
			break;
		case 21:
			wTempKey = (WORD)m_dwKey;
			wTempKey ^= m_dwKeyChngKey[j];
			m_dwKey =((m_dwKey >> 16) << 16) + wTempKey;
			break;
		case 22:
			bTempKey = (BYTE)m_dwKey;
			bTempKey ^= m_dwKeyChngKey[j];
			m_dwKey = ((m_dwKey >> 8) << 8) + bTempKey;
			break;	
		case 23:
			bTempKey = (BYTE)(m_dwKey >> 8);
			bTempKey ^= m_dwKeyChngKey[j];
			m_dwKey = ((m_dwKey >> 16) << 16) + (BYTE)m_dwKey + (bTempKey << 8);
			break;

		case 3://SUB
			m_dwKey -= m_dwKeyChngKey[j];
			break;
		case 31:
			wTempKey = ((WORD)m_dwKey - (WORD)m_dwKeyChngKey[j]);
			m_dwKey =((m_dwKey >> 16) << 16) + wTempKey;
			break;
		case 32:
			bTempKey = (BYTE)(m_dwKey >> 8);
			bTempKey -= (BYTE)m_dwKeyChngKey[j];
			m_dwKey = ((m_dwKey >> 16) << 16) + (BYTE)m_dwKey + (bTempKey << 8);
			break;
		case 33:
			bTempKey = (BYTE)m_dwKey - (BYTE)m_dwKeyChngKey[j];
			m_dwKey = ((m_dwKey >> 8) << 8) +  bTempKey;
			break;

		case 4://ROL
			m_dwKey = m_dwKey << m_dwKeyChngKey[j] | m_dwKey >> (32 - m_dwKeyChngKey[j]);
			break;
		case 41:
			wTempKey = (WORD)m_dwKey << m_dwKeyChngKey[j] | (WORD)m_dwKey >> (16 - m_dwKeyChngKey[j]);
			m_dwKey = ((m_dwKey >> 16) << 16) + wTempKey;
			break;
		case 42:
			bTempKey = (BYTE)(m_dwKey >> 8);
			bTempKey = bTempKey << m_dwKeyChngKey[j] | bTempKey >> (8 - m_dwKeyChngKey[j]);
			m_dwKey = ((m_dwKey >> 16)<< 16) +  ((m_dwKey << 24) >> 24) + (bTempKey << 8);
			break;
		case 43:
			bTempKey = (BYTE)m_dwKey;
			bTempKey = bTempKey << m_dwKeyChngKey[j] | bTempKey >> (8 - m_dwKeyChngKey[j]);
			m_dwKey = ((m_dwKey >> 8) << 8) +  bTempKey;
			break;

		case 5://ROR
			m_dwKey = m_dwKey >> m_dwKeyChngKey[j] | m_dwKey << (32 - m_dwKeyChngKey[j]);
			break;
		case 51:
			wTempKey = (WORD)m_dwKey >> m_dwKeyChngKey[j] | (WORD)m_dwKey << (16 - m_dwKeyChngKey[j]);
			m_dwKey = ((m_dwKey >> 16) << 16) + wTempKey;
			break;
		case 52:
			bTempKey = (BYTE)(m_dwKey >> 8);
			bTempKey = bTempKey >> m_dwKeyChngKey[j] | bTempKey << (8 - m_dwKeyChngKey[j]);
			m_dwKey = ((m_dwKey >> 16)<< 16) +  ((m_dwKey << 24) >> 24) + (bTempKey << 8);
			break;
		case 53:
			bTempKey = (BYTE)(m_dwKey);
			bTempKey = bTempKey >> m_dwKeyChngKey[j] | bTempKey << (8 - m_dwKeyChngKey[j]);
			m_dwKey = ((m_dwKey >> 8) << 8) +  bTempKey;
			break;

		case 6://INC
			m_dwKey += 1;
			break;
		case 61://inc ax
			wTempKey = (WORD)m_dwKey;
			wTempKey += 1;
			m_dwKey = ((m_dwKey >> 16) << 16) + wTempKey;
			break;

		case 7://DEC
			m_dwKey -= 1;
			break;
		case 71:
			wTempKey = (WORD)m_dwKey;
			wTempKey -= 1;
			m_dwKey = ((m_dwKey >> 16) << 16) + wTempKey;
			break;

		case 8://NOT
			m_dwKey = ~m_dwKey;
			break;
		case 81:
			bTempKey = (BYTE)(m_dwKey >> 8);
			bTempKey = ~bTempKey;
			m_dwKey = ((m_dwKey >> 16)<< 16) +  ((m_dwKey << 24) >> 24) + (bTempKey << 8);
			break;
		case 82:
			wTempKey = ~(WORD)m_dwKey;
			m_dwKey = ((m_dwKey >> 16)<< 16)|(wTempKey);
			break;
		case 83:
			bTempKey = (BYTE)m_dwKey;
			bTempKey = ~bTempKey;
			m_dwKey = ((m_dwKey >> 8)<< 8) +  bTempKey;
			break;

		case 0:
			break;
		}
	}
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: DoDecryption
	In Parameters	: DWORD dwIndex
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function performance decryption according to decryption Instruction
--------------------------------------------------------------------------------------*/
void CPolyVampiro::DoDecryption(DWORD dwIndex)
{
	switch(m_dwType)
	{
	case 1://ADD DWORD PTR
		for(DWORD i = 4; i < m_dwNoOfBytes - 3; i+=4)
		{
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();					
			}
			*((DWORD*)&m_pbyBuff[i]) += m_dwKey;			
		}
		break;
	case 11://ADD WORD PTR
		for(DWORD i = 2; i <= m_dwNoOfBytes - 1; i += 2)
		{
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();					
			}
			*((WORD*)&m_pbyBuff[i]) += (WORD)m_dwKey;			
		}
		break;
	case 101://ADD BYTE PTR
		for(DWORD i = 1; i <= m_dwNoOfBytes ; i += 1)
		{
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();					
			}
			m_pbyBuff[i] += (BYTE)m_dwKey;			
		}
		break;
	case 2://XOR DWORD PTR
		for(DWORD i = 4; i <= (m_dwNoOfBytes - 3) ; i += 4)
		{
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();					
			}
			*((DWORD*)&m_pbyBuff[i]) ^= m_dwKey;			
		}
		break;
	case 21 ://XOR WORD PTR
		for(DWORD i = 2; i <= (m_dwNoOfBytes - 1) ; i += 2)
		{
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();					
			}
			*((WORD*)&m_pbyBuff[i]) ^= m_dwKey;			
		}
		break;
	case 201://XOR BYTE PTR
		for(DWORD i = 1; i <= m_dwNoOfBytes ; i += 1)
		{
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();					
			}
			m_pbyBuff[i] ^= (BYTE)m_dwKey;			
		}
		break;
	case 3://SUB DWORD PTR
		for(DWORD i = 4; i <= m_dwNoOfBytes - 3; i+=4)
		{
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();					
			}
			*((DWORD*)&m_pbyBuff[i]) -= m_dwKey;			
		}
		break;
	case 31://SUB WORD PTR
		for(DWORD i = 2; i <= m_dwNoOfBytes - 1; i+=2)
		{
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();					
			}
			*((WORD*)&m_pbyBuff[i]) -= (WORD)m_dwKey;			
		}
		break;
	case 301://SUB BYTE PTR
		for(DWORD i = 1; i <= m_dwNoOfBytes ; i += 1)
		{
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();					
			}
			m_pbyBuff[i] -= (BYTE)m_dwKey;			
		}
		break;
	case 4://ROL DWORD PTR
		{		
			for(DWORD i = 4; i <= m_dwNoOfBytes - 3; i+=4)
			{
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();					
				}
				*((DWORD*)&m_pbyBuff[i]) = _lrotl(*((DWORD*)&m_pbyBuff[i]),(BYTE)m_dwKey);				
			}
		}
		break;
	case 41://ROL WORD PTR
		{

			for(DWORD i = 2; i <= m_dwNoOfBytes - 1; i+=2)
			{
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();					
				}
				*(WORD *)&m_pbyBuff[i] = (*(WORD *)&m_pbyBuff[i] << ((WORD)m_dwKey%0x10)) | (*(WORD *)&m_pbyBuff[i]>>(0x10 - ((WORD)m_dwKey%0x10)));				
			}
		}
		break;
	case 401://ROL BYTE PTR
		{

			for(DWORD i = 1; i <= m_dwNoOfBytes; i++)
			{
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();					
				}
				m_pbyBuff[i] = (m_pbyBuff[i] << ((BYTE)m_dwKey%0x08)) | (m_pbyBuff[i] >> (0x08 - ((BYTE)m_dwKey%0x08)));				
			}
		}
		break;

	case 5://ROR DWORD PTR
		{		
			for(DWORD i = 4; i <= m_dwNoOfBytes - 3; i+=4)//check
			{
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();					
				}
				*((DWORD*)&m_pbyBuff[i]) = _lrotr(*((DWORD*)&m_pbyBuff[i]),(BYTE)m_dwKey);							
			}
		}
		break;

	case 51://ROR WORD PTR
		{				
			for(DWORD i = 2; i <= m_dwNoOfBytes - 2; i += 2)
			{
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();					
				}
				*(WORD *)&m_pbyBuff[i] = (*(WORD *)&m_pbyBuff[i] >> (m_dwKey%0x10)) | (*(WORD *)&m_pbyBuff[i] << (0x10 - (m_dwKey%0x10)));				
			}	
		}
		break;
	case 501://ROR BYTE PTR
		{			
			for(DWORD i = 1 ; i <= m_dwNoOfBytes; i += 1)
			{
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();					
				}	
				m_pbyBuff[i] = (m_pbyBuff[i] >> (m_dwKey % 8)) | (m_pbyBuff[i] << (0x08 - (m_dwKey % 8)));				
			}
		}
		break;
	}
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: DoDecryptionRev
	In Parameters	: DWORD dwIndex
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function performance decryption according to decryption Instruction
--------------------------------------------------------------------------------------*/
void CPolyVampiro::DoDecryptionRev(int dwDecLimit)
{
	switch(m_dwType)
	{
	case 1://ADD DWORD PTR
		for(int i = m_dwNoOfBytes - 4; i >= dwDecLimit; i-=4)
		{
			*((DWORD*)&m_pbyBuff[i]) += m_dwKey;
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 11://ADD WORD PTR
		for(int i = m_dwNoOfBytes - 2; i >= dwDecLimit; i-=2)//check
		{
			*(WORD*)&m_pbyBuff[i] += (WORD)m_dwKey;
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 101://ADD BYTE PTR
		for(int i = m_dwNoOfBytes - 1; i >= dwDecLimit ; i -= 1)
		{
			m_pbyBuff[i] += (BYTE)m_dwKey;
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 2://XOR DWORD PTR
		for(int i = m_dwNoOfBytes - 4; i >= dwDecLimit; i -= 4)
		{
			*((DWORD*)&m_pbyBuff[i]) ^= m_dwKey;
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 21 ://XOR WORD PTR
		for(int i = m_dwNoOfBytes - 2; i >= dwDecLimit; i -= 2)
		{
			*((WORD*)&m_pbyBuff[i]) ^= m_dwKey;
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 201 ://XOR BYTE PTR
		for(int i = m_dwNoOfBytes - 1; i >= dwDecLimit; i -= 1)
		{
			m_pbyBuff[i] ^= (BYTE)m_dwKey;
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();
			}
		}
		break;


	case 3://SUB DWORD PTR
		for(int i = m_dwNoOfBytes - 4; i >= dwDecLimit; i -= 4)
		{
			*((DWORD*)&m_pbyBuff[i]) -= m_dwKey;
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 31://SUB WORD PTR
		for(int i = m_dwNoOfBytes - 2; i >= dwDecLimit; i -= 2)
		{
			*((WORD*)&m_pbyBuff[i]) -= (WORD)m_dwKey;
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 301://SUB BYTE PTR
		for(int i = m_dwNoOfBytes - 1; i >= dwDecLimit; i -= 1)
		{
			m_pbyBuff[i] -= (BYTE)m_dwKey;
			if(m_dwKeyChngType[0] != 0)
			{
				DecryptKey();
			}
		}
		break;
	case 4://ROL DWORD PTR
		{		
			for(int i = m_dwNoOfBytes - 4; i >= dwDecLimit; i -= 4)
			{
				*((DWORD*)&m_pbyBuff[i]) = _lrotl(*((DWORD*)&m_pbyBuff[i]),(BYTE)m_dwKey);
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();
				}				
			}
		}
		break;

	case 41://ROL WORD PTR
		{			

			for(int i = m_dwNoOfBytes - 2; i >= dwDecLimit; i-=2)
			{
				*(WORD *)&m_pbyBuff[i] = (*(WORD *)&m_pbyBuff[i] << (m_dwKey%0x10)) | (*(WORD *)&m_pbyBuff[i]>>(0x10 - (m_dwKey%0x10)));
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();					
				}	
			}
		}
		break;
	case 401://ROL BYTE PTR
		{

			for(int i = m_dwNoOfBytes - 1; i >= dwDecLimit; i -= 1)
			{
				m_pbyBuff[i] = (m_pbyBuff[i] << (m_dwKey%0x08)) | (m_pbyBuff[i] >> (0x08 - (m_dwKey%0x08)));
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();
				}
			}
		}
		break;

	case 5://ROR DWORD PTR
		{
			for(int i = (m_dwNoOfBytes - 4); i >= dwDecLimit; i -= 4)//check
			{
				*((DWORD*)&m_pbyBuff[i]) = _lrotr(*((DWORD*)&m_pbyBuff[i]),(BYTE)m_dwKey);
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();
				}	
			}
		}
		break;
	case 51://ROR WORD PTR
		{			
			for(int i = m_dwNoOfBytes - 2; i >= dwDecLimit; i -= 2)
			{
				*(WORD *)&m_pbyBuff[i] = *(WORD *)&m_pbyBuff[i] >> (m_dwKey % 0x10) | *(WORD *)&m_pbyBuff[i] << (0x10 - (m_dwKey % 0x10));
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();					
				}	
			}	
		}
		break;
	case 501://ROR BYTE PTR
		{			
			for(int i = m_dwNoOfBytes - 1; i >= dwDecLimit; i -= 1)
			{
				m_pbyBuff[i] = (m_pbyBuff[i] >> (m_dwKey%8)) | (m_pbyBuff[i] << (0x08 - (m_dwKey%8)));
				if(m_dwKeyChngType[0] != 0)
				{
					DecryptKey();					
				}	
			}
		}
		break;
	}
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: CalculateCallAdderess
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function finds and replaces CALL instruction adressese modified by Virus
--------------------------------------------------------------------------------------*/
bool CPolyVampiro::CalculateCallAdderess()//calculating the original call value
{
	BYTE CHECK_CALLFF[]={0xFF,0x25,0x00,0x00,0x00,0x00};	
	DWORD dwCALLOFFSET = 0;
	DWORD patchedOffset = *((DWORD*)&m_pbyBuff[m_dwOffset]);
	if(memcpy(&CHECK_CALLFF[2],&m_pbyBuff[m_dwOffset+ 4],4))
	{
		for(DWORD iOffset = m_dwAEPMapped;iOffset < (m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData);iOffset += 0x1000)
		{
			if(GetBuffer(iOffset,0x1000,0x1000))
			{
				if(OffSetBasedSignature(CHECK_CALLFF,sizeof(CHECK_CALLFF),&dwCALLOFFSET))
				{
					dwCALLOFFSET =((iOffset+dwCALLOFFSET) -  m_dwAEPMapped) - ((m_dwPatcedAddr - m_dwAEPMapped) + 5);
					if(memcpy(&m_pbyBuff[m_dwOffset + 4],&dwCALLOFFSET,4))
					{
						if(memcpy(&m_pbyBuff[m_dwOffset],&patchedOffset,4))
						{
							return true;
						}
					}
				}
			}
		}
	}
	return false;
}
