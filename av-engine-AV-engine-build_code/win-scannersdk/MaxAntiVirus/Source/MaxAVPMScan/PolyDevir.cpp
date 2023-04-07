/*======================================================================================
FILE				: PolyDevir.cpp
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
NOTES				: This is detection module for malware Devir Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyDevir.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyDevir
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDevir::CPolyDevir(CMaxPEFile *pMaxPEFile):
CPolyBase(pMaxPEFile)
{
	m_pbyBuff = NULL;
	m_bBuffer = NULL;
	memset(&m_objDevirDecInfo, 0x00 , sizeof(DEVIR_DEC_INFO));		
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDevir
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDevir::~CPolyDevir(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	if(m_bBuffer)
	{
		delete []m_bBuffer;
		m_bBuffer = NULL;
	}
}


/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: This function collects first and second decryption parameter
					  and decrypt the encrypted body accordingly.
--------------------------------------------------------------------------------------*/
int CPolyDevir::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	// Primary checks for W32.Devir
	if( ((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) && 
		(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x2D00) && 
		((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000000) == 0xE0000000) &&
		m_dwAEPUnmapped == m_pSectionHeader[0].VirtualAddress)
	{
		m_pbyBuff = new BYTE[DEVIR_BUFF_SIZE + MAX_INSTRUCTION_LEN];	
		if(m_pbyBuff == NULL)
		{
			return false;
		}
		memset(m_pbyBuff, 0x00, DEVIR_BUFF_SIZE + MAX_INSTRUCTION_LEN);

		//Read 0x1000 bytes from AEP
		if(!GetBuffer(m_dwAEPMapped, DEVIR_BUFF_SIZE, DEVIR_BUFF_SIZE))
		{
			return iRetStatus;
		}
	
		//This function collects all parameter for decryption.
		if(!DetectAndGetDecParameter())
		{
			return iRetStatus;
		}

		//It is freed because we need to read encrypted data in it.
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int FIRST_DEC_BUFF_SIZE = m_objDevirDecInfo.dwDecLength * sizeof(DWORD);
		m_pbyBuff = new BYTE[FIRST_DEC_BUFF_SIZE];
		if(m_pbyBuff == NULL)
		{
			return iRetStatus;
		}

		memset(m_pbyBuff, 0x00, FIRST_DEC_BUFF_SIZE);
		
		//This variable is used for calculate starting second decryption index in buffer.
		DWORD dwFirstDecStartOffset = m_objDevirDecInfo.dwDecStartOffset;
		if(dwFirstDecStartOffset != m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData)
		{
			return iRetStatus;
		}
		
		if(!GetBuffer(m_objDevirDecInfo.dwDecStartOffset, FIRST_DEC_BUFF_SIZE, FIRST_DEC_BUFF_SIZE))
		{
			return iRetStatus;
		}

		m_objDevirDecInfo.dwIndex = 0x00;
		if(DecryptBuffer())
		{
			// If we reach up to this level then it is confirmed file is infected 
			// by Devir. So if we din't get parameter for secind decrtption then 
			// we need to delete the file.
			iRetStatus = VIRUS_FILE_DELETE;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Devir"));
			
			//Now collect information for second decryption.
			memset(&m_objDevirDecInfo, 0x00 , sizeof(DEVIR_DEC_INFO));		
			if(DetectAndGetDecParameter())
			{
				// Here we caluclate index rom where in first decrypted buffer
				// decond decryption start.
				m_objDevirDecInfo.dwIndex = m_objDevirDecInfo.dwDecStartOffset - 
											dwFirstDecStartOffset;
				if(DecryptBuffer())
				{
					if(*((DWORD*)&m_pbyBuff[m_objDevirDecInfo.dwIndex]) == 0x000000E8 &&
						*((DWORD*)&m_pbyBuff[m_objDevirDecInfo.dwIndex + 4]) == 0xED815D00)
					{
						iRetStatus = VIRUS_FILE_REPAIR;
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: Repair routine for different varients of Devir Family
					  This function decrypt the encrypted body as per virus logic. After 
					  decryption it rewrite the original AEP and remove last section.	
--------------------------------------------------------------------------------------*/
int CPolyDevir::CleanVirus()
{
	int iRetStatus = REPAIR_FAILED;
	
	// Here we used decrypted buffer in detection. So if it is NULL then we cannot proceed.
	if(m_pbyBuff == NULL)
		return iRetStatus;

	DWORD	dwDecStartIndex = m_objDevirDecInfo.dwIndex + 0xD0;
	DWORD	dwDecLength = *((DWORD*)&m_pbyBuff[dwDecStartIndex]);//it is consatnt 0x3B18
	dwDecStartIndex+= 4;
	
	if(dwDecLength > 0x3C00)
	{
		return iRetStatus;
	}

	 // m_bBuffer contains decrypted data After third 
	m_bBuffer = new BYTE[dwDecLength];
	if(m_bBuffer == NULL)
	{
		return iRetStatus;
	}
	memset(m_bBuffer, 0x00, dwDecLength);

	//dwTemp contains DWORD value read every time from encrypted buffer for decryption.
	DWORD	dwTemp = *((DWORD*)&m_pbyBuff[dwDecStartIndex]);
	dwDecStartIndex+= 4;

	// dwDecCounter needed in decryption when it is zero it is reinialized by 0x20.
	DWORD	dwDecCounter = 0x20;
	
	//dwLoopTerminationCounter is an index into decrypted buffer. It reaches up to dwDecLength
	DWORD			dwLoopTerminationCounter = 0x00;
	DWORD			dwEAX = 0x00, dwECX = 0x00, dwEBX = 0x00;
	BYTE			byCarryFlag = 0x00;
	DWORD			dwTempEAX = 0x00;
	unsigned int	i = 0x00;

	while(1)
	{		
		dwECX = 0x01;
		dwEAX = 0x00;
		do
		{
			byCarryFlag = HIBYTE((HIWORD(dwTemp & 0x80000000)));
			dwTemp = dwTemp << 1;
			if(byCarryFlag != 0x00)
			{
				dwEBX = 1;
				dwECX--;
				dwEBX = dwEBX << static_cast<BYTE>(dwECX);
				dwECX++;
				dwEAX = dwEAX | dwEBX;
			}
			dwDecCounter--;
			if(dwDecCounter == 0x00)
			{
				dwTemp = *((DWORD*)&m_pbyBuff[dwDecStartIndex]);
				dwDecStartIndex+= 4;
				dwDecCounter = 0x20;
			}
			dwECX--;
		}while(dwECX != 0x00);

		if(static_cast<BYTE>(dwEAX) == 0x01)
		{
			dwECX = 0x07;
			dwEAX = 0x00;
			do
			{
				byCarryFlag = HIBYTE((HIWORD(dwTemp & 0x80000000)));
				dwTemp = dwTemp << 1;
				if(byCarryFlag != 0x00)
				{
					dwEBX = 1;
					dwECX--;
					dwEBX = dwEBX << static_cast<BYTE>(dwECX);
					dwECX++;
					dwEAX = dwEAX | dwEBX;
				}
				dwDecCounter--;
				if(dwDecCounter == 0x00)
				{
					dwTemp = *((DWORD*)&m_pbyBuff[dwDecStartIndex]);
					dwDecStartIndex+=4;
					dwDecCounter = 0x20;
				}
				dwECX--;
			}while(dwECX != 0x00);
			dwTempEAX = dwEAX;
			dwECX = 0x0D;
			dwEAX = 0x00;
			do
			{
				byCarryFlag = HIBYTE((HIWORD(dwTemp & 0x80000000)));
				dwTemp = dwTemp << 1;
				if(byCarryFlag != 0x00)
				{
					dwEBX = 1;
					dwECX--;
					dwEBX = dwEBX << static_cast<BYTE>(dwECX);
					dwECX++;
					dwEAX = dwEAX | dwEBX;
				}
				dwDecCounter--;
				if(dwDecCounter == 0x00)
				{
					dwTemp = *((DWORD*)&m_pbyBuff[dwDecStartIndex]);
					dwDecStartIndex+= 4;
					dwDecCounter = 0x20;
				}
				dwECX--;
			}while(dwECX != 0x00);

			dwEBX = dwLoopTerminationCounter - dwEAX;
			if(dwEBX > dwDecLength)
				return iRetStatus;

			dwECX = dwTempEAX;
			if((dwECX + dwLoopTerminationCounter > dwDecLength) || (dwECX + dwEBX > dwDecLength))
			{
				return iRetStatus;
			}
			for(i=0x00; i < dwECX; i++,dwLoopTerminationCounter++,dwEBX++)
			{
				m_bBuffer[dwLoopTerminationCounter] = m_bBuffer[dwEBX];
			}
			if(dwLoopTerminationCounter >= dwDecLength)
				break;
			continue;
		}

		dwECX = 0x08;
		dwEAX = 0x00;
		do
		{
			//Decryption Loop
			byCarryFlag = HIBYTE((HIWORD(dwTemp & 0x80000000)));
			dwTemp = dwTemp << 1;
			if(byCarryFlag != 0x00)
			{
				dwEBX = 1;
				dwECX--;
				dwEBX = dwEBX << static_cast<BYTE>(dwECX);
				dwECX++;
				dwEAX = dwEAX | dwEBX;
			}
			dwDecCounter--;
			if(dwDecCounter == 0x00)
			{
				dwTemp = *((DWORD*)&m_pbyBuff[dwDecStartIndex]);
				dwDecStartIndex+= 4;
				dwDecCounter = 0x20;
			}
			dwECX--;
		}while(dwECX != 0x00);

		m_bBuffer[dwLoopTerminationCounter++] = static_cast<BYTE>(dwEAX);

		if(dwLoopTerminationCounter >= dwDecLength)
			break;
	}
	DWORD dwOriginalAEP = *((DWORD *)&m_bBuffer[0x0C]) - m_dwImageBase;

	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwOriginalAEP, &dwTemp))
	{
		return iRetStatus;
	}	
	if(m_pMaxPEFile->WriteBuffer(&m_bBuffer[0x2B18], m_dwAEPMapped, DEVIR_BUFF_SIZE))
	{
		m_pMaxPEFile->WriteAEP(dwOriginalAEP);
		if(m_pMaxPEFile->TruncateFile(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData))
		{
			iRetStatus = REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAndGetDecParameter
	In Parameters	: 
	Out Parameters	: 1 for Success else false
	Purpose			: 
	Author			: Tushar Kadam + Adnan Naya + Virus Analysis Team
	Description		: 1) It follows only unconditional (E9) JUMP(5 Bytes).
					  2) It search for ADD\SUB\XOR [E##],E## instruction.
					  3) It detect dec key cjhange type and value from instructio
					 	 ADD szREG,#Immediate, SUB szREG,#Immediate, XOR szREG,#Immediate.
					  4) It collects counter from Instruction DEC E##. ranges from (0x900 to 0x1100)
--------------------------------------------------------------------------------------*/
int CPolyDevir::DetectAndGetDecParameter()
{
	const int	MAX_STACK_SIZE = 0x10;
	
	int		iRetStatus = 0x00;
	
	DWORD	dwOffset = 0, dwLength = 0, dwTemp = 0;
	DWORD	dwEAX = 0, dwEBX = 0, dwECX = 0, dwEDX = 0;
	DWORD	dwESI = 0, dwEDI = 0, dwEBP = 0;
	DWORD	dwStack[MAX_STACK_SIZE] = {0}, dwTOS = 0x00;
	DWORD	dwImageBase = m_dwImageBase;

	BYTE	B1 = 0, B2 = 0, B3 = 0;

	char	szADD[TEXTLEN] = {0x00};
	char	szSUB[TEXTLEN] = {0x00};
	char	szXOR[TEXTLEN] = {0x00};

	t_disasm	da = {0};

	m_objMaxDisassem.InitializeData();	
	m_dwInstCount = 0;

	while(dwOffset < m_dwNoOfBytes)
	{
		if(m_dwInstCount > 0x200)
			return iRetStatus;

		B1 = m_pbyBuff[dwOffset];
		B2 = m_pbyBuff[dwOffset+1];
		B3 = m_pbyBuff[dwOffset+2];

		if( B1==0xC1 && (B2>=0xF0 && B2<=0xF7) )
		{
			dwOffset+= 0x03;
			continue;
		}
		if( B1==0xC0 && (B2>=0xF0 && B2<=0xF7) )
		{
			dwOffset+= 0x03;
			continue;
		}
		if( B1==0xD1 && (B2>=0xF0 && B2<=0xF7) )
		{
			dwOffset+= 0x02;
			continue;
		}
		if( B1==0xD0 && (B2>=0xF0 && B2<=0xF7) )
		{
			dwOffset+= 0x02;
			continue;
		}
		if( B1==0xD2 && (B2>=0xF0 && B2<=0xF7) )
		{
			dwOffset+= 0x02;
			continue;
		}
		if( B1==0xD3 && (B2>=0xF0 && B2<=0xF7) )
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
		dwLength = m_objMaxDisassem.Disasm((char* )&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffset))
		{
			return iRetStatus;
		}
		m_dwInstCount++;

		if(dwLength == 0x05 && B1 == 0xE9 && strstr(da.result, "JMP "))
		{
			dwTemp = *((DWORD *)&m_pbyBuff[dwOffset+1]);
			if(!NEGATIVE_JUMP(dwTemp))
			{
				dwOffset += dwTemp;
			}
		}
		if( dwLength == 0x02 && 
			(strstr(da.result,"SUB E") || strstr(da.result,"XOR E")) && 
			strstr(da.result,",E"))
		{
			if(strstr(da.result, "EAX,EAX"))
				dwEAX = 0x00;
			else if(strstr(da.result, "EBX,EBX"))
				dwEBX = 0x00;
			else if(strstr(da.result, "ECX,ECX"))
				dwECX = 0x00;
			else if(strstr(da.result, "EDX,EDX"))
				dwEDX = 0x00;
			else if(strstr(da.result, "ESI,ESI"))
				dwESI = 0x00;
			else if(strstr(da.result, "EDI,EDI"))
				dwEDI = 0x00;
			else if(strstr(da.result, "EBP,EBP"))
				dwEBP = 0x00;
		}
		if(dwLength > 4 && m_objDevirDecInfo.DecType == NO_DEC_FOUND)
		{
			if(strstr(da.result,"ADD E"))
			{	
				if(strstr(da.result, "EAX"))
					dwEAX += da.immconst;
				else if(strstr(da.result, "EBX"))
					dwEBX += da.immconst;
				else if(strstr(da.result, "ECX"))
					dwECX += da.immconst;
				else if(strstr(da.result, "EDX"))
					dwEDX += da.immconst;
				else if(strstr(da.result, "ESI"))
					dwESI += da.immconst;
				else if(strstr(da.result, "EDI"))
					dwEDI += da.immconst;
				else if(strstr(da.result, "EBP"))
					dwEBP += da.immconst;
			}
			else if(strstr(da.result,"SUB E"))
			{
				if(strstr(da.result, "EAX"))
					dwEAX -= da.immconst;
				else if(strstr(da.result, "EBX"))
					dwEBX -= da.immconst;
				else if(strstr(da.result, "ECX"))
					dwECX -= da.immconst;
				else if(strstr(da.result, "EDX"))
					dwEDX -= da.immconst;
				else if(strstr(da.result, "ESI"))
					dwESI -= da.immconst;
				else if(strstr(da.result, "EDI"))
					dwEDI -= da.immconst;
				else if(strstr(da.result, "EBP"))
					dwEBP -= da.immconst;
			}
			else if(strstr(da.result,"XOR E"))
			{
				if(strstr(da.result, "EAX"))
					dwEAX ^= da.immconst;
				else if(strstr(da.result, "EBX"))
					dwEBX ^= da.immconst;
				else if(strstr(da.result, "ECX"))
					dwECX ^= da.immconst;
				else if(strstr(da.result, "EDX"))
					dwEDX ^= da.immconst;
				else if(strstr(da.result, "ESI"))
					dwESI ^= da.immconst;
				else if(strstr(da.result, "EDI"))
					dwEDI ^= da.immconst;
				else if(strstr(da.result, "EBP"))
					dwEBP ^= da.immconst;
			}
			else if(strstr(da.result,"MOV E"))
			{
				if(strstr(da.result, "EAX"))
					dwEAX = da.immconst;
				else if(strstr(da.result, "EBX"))
					dwEBX = da.immconst;
				else if(strstr(da.result, "ECX"))
					dwECX = da.immconst;
				else if(strstr(da.result, "EDX"))
					dwEDX = da.immconst;
				else if(strstr(da.result, "ESI"))
					dwESI = da.immconst;
				else if(strstr(da.result, "EDI"))
					dwEDI = da.immconst;
				else if(strstr(da.result, "EBP"))
					dwEBP = da.immconst;
			}
			else if(strstr(da.result,"PUSH "))
			{
				if(dwTOS < MAX_STACK_SIZE)
					dwStack[dwTOS++] = da.immconst;
			}
		}
		if(dwTOS < MAX_STACK_SIZE && dwLength == 0x01 && strstr(da.result, "PUSH E"))
		{
			char *ptr = strstr(da.result,"E");
			if(ptr == NULL)
				break;
			ptr[3] = '\0';
			if(strstr(ptr,"EAX"))
			{
				dwStack[dwTOS++] = dwEAX;
			}
			else if(strstr(ptr,"EBX"))
			{
				dwStack[dwTOS++] = dwEBX;
			}
			else if(strstr(ptr,"ECX"))
			{
				dwStack[dwTOS++] = dwECX;
			}
			else if(strstr(ptr,"EDX"))
			{
				dwStack[dwTOS++] = dwEDX;
			}
			else if(strstr(ptr,"ESI"))
			{
				dwStack[dwTOS++] = dwESI;
			}
			else if(strstr(ptr,"EDI"))
			{
				dwStack[dwTOS++] = dwEDI;
			}
			else if(strstr(ptr,"EBP"))
			{
				dwStack[dwTOS++] = dwEBP;
			}

		}
		if(dwTOS >= 0x01 && strstr(da.result,"POP E"))
		{
			char *ptr = strstr(da.result,"E");
			if(ptr == NULL)
				break;
			ptr[3] = '\0';
			if(strstr(ptr,"EAX"))
			{
				dwEAX = dwStack[--dwTOS];
			}
			else if(strstr(ptr,"EBX"))
			{
				dwEBX = dwStack[--dwTOS];
			}
			else if(strstr(ptr,"ECX"))
			{
				dwECX = dwStack[--dwTOS];
			}
			else if(strstr(ptr,"EDX"))
			{
				dwEDX = dwStack[--dwTOS];
			}
			else if(strstr(ptr,"ESI"))
			{
				dwESI = dwStack[--dwTOS];
			}
			else if(strstr(ptr,"EDI"))
			{
				dwEDI = dwStack[--dwTOS];
			}
			else if(strstr(ptr,"EBP"))
			{
				dwEBP = dwStack[--dwTOS];
			}

		}
		if(dwLength > 4 && m_objDevirDecInfo.DecType != NO_DEC_FOUND 
			&& m_objDevirDecInfo.DecKeyChangeType == NO_DEC_FOUND)
		{
			if(strstr(da.result, szADD))
			{
				m_objDevirDecInfo.DecKeyChangeType = DEC_ADD;
				m_objDevirDecInfo.dwkeyChangeValue = da.immconst;
			}
			else if(strstr(da.result, szSUB))
			{
				m_objDevirDecInfo.DecKeyChangeType = DEC_SUB;
				m_objDevirDecInfo.dwkeyChangeValue = da.immconst;
			}
			else if(strstr(da.result, szXOR))
			{
				m_objDevirDecInfo.DecKeyChangeType = DEC_XOR;
				m_objDevirDecInfo.dwkeyChangeValue = da.immconst;
			}
		}
		if( dwLength == 0x01 && 
			strstr(da.result ,"DEC E") && 
			m_objDevirDecInfo.DecKeyChangeType != NO_DEC_FOUND)
		{
			char *ptr = strstr(da.result," E");
			if(ptr == NULL)
				break;
			ptr++;
			ptr[3] = '\0';
			if(strstr(ptr,"EAX"))
			{
				if(dwEAX > 0x1100 || dwEAX < 0x900)
				{
					dwOffset += dwLength;
					continue;
				}
				m_objDevirDecInfo.dwDecLength  = dwEAX;
			}
			else if(strstr(ptr,"EBX") )
			{
				if(dwEBX > 0x1100 || dwEBX < 0x900)
				{
					dwOffset += dwLength;
					continue;
				}
				m_objDevirDecInfo.dwDecLength = dwEBX;
			}
			else if(strstr(ptr,"ECX"))
			{
				if(dwECX > 0x1100 || dwECX < 0x900)
				{
					dwOffset += dwLength;
					continue;
				}
				m_objDevirDecInfo.dwDecLength = dwECX;
			}
			else if(strstr(ptr,"EDX"))
			{
				if(dwEDX > 0x1100 || dwEDX < 0x900)
				{
					dwOffset += dwLength;
					continue;
				}
				m_objDevirDecInfo.dwDecLength = dwEDX;
			}
			else if(strstr(ptr,"ESI"))
			{
				if(dwESI > 0x1100 || dwESI < 0x900)
				{
					dwOffset += dwLength;
					continue;
				}
				m_objDevirDecInfo.dwDecLength = dwESI;
			}
			else if(strstr(ptr,"EDI"))
			{
				if(dwEDI > 0x1100 || dwEDI < 0x900)
				{
					dwOffset += dwLength;
					continue;
				}
				m_objDevirDecInfo.dwDecLength = dwEDI;
			}
			else if(strstr(ptr,"EBP"))
			{
				if(dwEBP > 0x1100 || dwEBP < 0x900)
				{
					dwOffset += dwLength;
					continue;
				}
				m_objDevirDecInfo.dwDecLength = dwEBP;
			}
			iRetStatus = 0x01;
			break;
		}
		if((strstr(da.result,"ADD DWORD PTR [E") || strstr(da.result,"ADD [E")) && 
			strstr(da.result,",E"))
		{
			char *ptr = strstr(da.result, ",E");
			if(ptr == NULL)
				break;
			ptr++;
			ptr[3] = '\0';

			sprintf_s(szADD, TEXTLEN, "ADD %s,",ptr);
			sprintf_s(szSUB, TEXTLEN, "SUB %s,",ptr);
			sprintf_s(szXOR, TEXTLEN, "XOR %s,",ptr);
			
			m_objDevirDecInfo.DecType = DEC_ADD;
			if(strstr(ptr,"EAX"))
			{
				m_objDevirDecInfo.dwDecKey = dwEAX;
			}
			else if(strstr(ptr,"EBX"))
			{
				m_objDevirDecInfo.dwDecKey = dwEBX;
			}
			else if(strstr(ptr,"ECX"))
			{
				m_objDevirDecInfo.dwDecKey = dwECX;
			}
			else if(strstr(ptr,"EDX"))
			{
				m_objDevirDecInfo.dwDecKey = dwEDX;
			}
			else if(strstr(ptr,"ESI"))
			{
				m_objDevirDecInfo.dwDecKey = dwESI;
			}
			else if(strstr(ptr,"EDI"))
			{
				m_objDevirDecInfo.dwDecKey = dwEDI;
			}
			else if(strstr(ptr,"EBP"))
			{
				m_objDevirDecInfo.dwDecKey = dwEBP;
			}

			ptr = NULL;
			ptr = strstr(da.result,"[E");
			if(ptr == NULL)
				break;
			ptr++;
			ptr[3] = '\0';
			if(strstr(ptr,"EAX"))
			{
				dwTemp = dwEAX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EBX"))
			{
				dwTemp = dwEBX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"ECX"))
			{
				dwTemp = dwECX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EDX"))
			{
				dwTemp = dwEDX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"ESI"))
			{
				dwTemp = dwESI;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EDI"))
			{
				dwTemp = dwEDI;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EBP"))
			{
				dwTemp = dwEBP;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
		}
		if((strstr(da.result,"SUB DWORD PTR [E") || strstr(da.result,"SUB [E")) && strstr(da.result,",E"))
		{
			char *ptr = strstr(da.result, ",E");
			if(ptr == NULL)
				break;
			ptr++;
			ptr[3] = '\0';

			sprintf_s(szADD, TEXTLEN, "ADD %s,",ptr);
			sprintf_s(szSUB, TEXTLEN, "SUB %s,",ptr);
			sprintf_s(szXOR, TEXTLEN, "XOR %s,",ptr);

			m_objDevirDecInfo.DecType = DEC_SUB;
			if(strstr(ptr,"EAX"))
			{
				m_objDevirDecInfo.dwDecKey = dwEAX;
			}
			else if(strstr(ptr,"EBX"))
			{
				m_objDevirDecInfo.dwDecKey = dwEBX;
			}
			else if(strstr(ptr,"ECX"))
			{
				m_objDevirDecInfo.dwDecKey = dwECX;
			}
			else if(strstr(ptr,"EDX"))
			{
				m_objDevirDecInfo.dwDecKey = dwEDX;
			}
			else if(strstr(ptr,"ESI"))
			{
				m_objDevirDecInfo.dwDecKey = dwESI;
			}
			else if(strstr(ptr,"EDI"))
			{
				m_objDevirDecInfo.dwDecKey = dwEDI;
			}
			else if(strstr(ptr,"EBP"))
			{
				m_objDevirDecInfo.dwDecKey = dwEBP;
			}
			ptr = NULL;
			ptr = strstr(da.result,"[E");
			if(ptr == NULL)
				break;
			ptr++;
			ptr[3] = '\0';
			if(strstr(ptr,"EAX"))
			{
				dwTemp = dwEAX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EBX"))
			{
				dwTemp = dwEBX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"ECX"))
			{
				dwTemp = dwECX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EDX"))
			{
				dwTemp = dwEDX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"ESI"))
			{
				dwTemp = dwESI;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EDI"))
			{
				dwTemp = dwEDI;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EBP"))
			{
				dwTemp = dwEBP;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
		}
		if((strstr(da.result,"XOR DWORD PTR [E") || strstr(da.result,"XOR [E")) && strstr(da.result,",E"))
		{
			char *ptr = strstr(da.result, ",E");
			if(ptr == NULL)
				break;
			ptr++;
			ptr[3] = '\0';

			sprintf_s(szADD, TEXTLEN, "ADD %s,",ptr);
			sprintf_s(szSUB, TEXTLEN, "SUB %s,",ptr);
			sprintf_s(szXOR, TEXTLEN, "XOR %s,",ptr);

			m_objDevirDecInfo.DecType = DEC_XOR;
			if(strstr(ptr,"EAX"))
			{
				m_objDevirDecInfo.dwDecKey = dwEAX;
			}
			else if(strstr(ptr,"EBX"))
			{
				m_objDevirDecInfo.dwDecKey = dwEBX;
			}
			else if(strstr(ptr,"ECX"))
			{
				m_objDevirDecInfo.dwDecKey = dwECX;
			}
			else if(strstr(ptr,"EDX"))
			{
				m_objDevirDecInfo.dwDecKey = dwEDX;
			}
			else if(strstr(ptr,"ESI"))
			{
				m_objDevirDecInfo.dwDecKey = dwESI;
			}
			else if(strstr(ptr,"EDI"))
			{
				m_objDevirDecInfo.dwDecKey = dwEDI;
			}
			else if(strstr(ptr,"EBP"))
			{
				m_objDevirDecInfo.dwDecKey = dwEBP;
			}
			ptr = NULL;
			ptr = strstr(da.result,"[E");
			if(ptr == NULL)
				break;
			ptr++;
			ptr[3] = '\0';
			if(strstr(ptr,"EAX"))
			{
				dwTemp = dwEAX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EBX"))
			{
				dwTemp = dwEBX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"ECX"))
			{
				dwTemp = dwECX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EDX"))
			{
				dwTemp = dwEDX;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"ESI"))
			{
				dwTemp = dwESI;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EDI"))
			{
				dwTemp = dwEDI;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
			else if(strstr(ptr,"EBP"))
			{
				dwTemp = dwEBP;
				if(dwTemp <= dwImageBase)
					break;
				if(m_pMaxPEFile->Rva2FileOffset(dwTemp - dwImageBase, &dwTemp) == OUT_OF_FILE)
					break;
				m_objDevirDecInfo.dwDecStartOffset = dwTemp;						
			}
		}
		dwOffset += dwLength;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptBuffer
	In Parameters	: 
	Out Parameters	: 1 if success else 0
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: It decrypt the buffer as per collected decryption information.
--------------------------------------------------------------------------------------*/
int CPolyDevir::DecryptBuffer()
{
	for( DWORD dwIndex = m_objDevirDecInfo.dwIndex; 
		(dwIndex < (m_objDevirDecInfo.dwDecLength * 4) + m_objDevirDecInfo.dwIndex - 3) && 
		((dwIndex)<m_dwNoOfBytes-3); dwIndex += 4)
	{
		switch(m_objDevirDecInfo.DecType)
		{
		case DEC_ADD:
			*((DWORD *)&m_pbyBuff[dwIndex]) += m_objDevirDecInfo.dwDecKey;
			break;
		case DEC_SUB:
			*((DWORD *)&m_pbyBuff[dwIndex]) -= m_objDevirDecInfo.dwDecKey;
			break;
		case DEC_XOR:
			*((DWORD *)&m_pbyBuff[dwIndex]) ^= m_objDevirDecInfo.dwDecKey;
			break;
		}
		switch(m_objDevirDecInfo.DecKeyChangeType)
		{
		case DEC_ADD:
			m_objDevirDecInfo.dwDecKey += m_objDevirDecInfo.dwkeyChangeValue;
			break;
		case DEC_SUB:
			m_objDevirDecInfo.dwDecKey -= m_objDevirDecInfo.dwkeyChangeValue;
			break;
		case DEC_XOR:
			m_objDevirDecInfo.dwDecKey ^= m_objDevirDecInfo.dwkeyChangeValue;
			break;
		}
	}
	return 0x01;
}