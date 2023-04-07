/*======================================================================================
FILE				: PolyRansom.cpp
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
NOTES				: This is detection module for malware Ransom Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyRansom.h"
#include "SemiPolyDBScn.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyRansom
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyRansom::CPolyRansom(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{

}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyRansom
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyRansom::~CPolyRansom(void)
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
	Description		: Detection routine for different varients of Ransom Family
--------------------------------------------------------------------------------------*/
int CPolyRansom::DetectVirus()
{
	int iReturnStatus=VIRUS_NOT_FOUND;

	if(0x2>=m_wNoOfSections 
		//&& (0x115C==m_pMaxPEFile->m_stSectionHeader[1].Misc.VirtualSize || 0x0==m_pMaxPEFile->m_stSectionHeader[1].Misc.VirtualSize ) 
		&& 0x200== m_pMaxPEFile->m_stSectionHeader[0].PointerToRawData
		&& 0x0c==m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion 
		&& 0x10f==m_pMaxPEFile->m_stPEHeader.Characteristics 
		&& (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL)!=IMAGE_FILE_DLL)
	{
		return DetectPolyRansom();
	}
	if (VIRUS_FILE_DELETE == DetectPolyRansomB())
	{
		return VIRUS_FILE_DELETE;
	}
	if (VIRUS_FILE_DELETE == DetectPolyRansomC())
	{
		return VIRUS_FILE_DELETE;
	}
	if (VIRUS_FILE_DELETE == DetectPolyRansomE())
	{
		return VIRUS_FILE_DELETE;
	}
	if (VIRUS_FILE_DELETE == DetectPolyRansomF())
	{
		return VIRUS_FILE_DELETE;
	}
	if (VIRUS_FILE_DELETE == DetectPolyRansomI())
	{
		return VIRUS_FILE_DELETE;
	}
	if (VIRUS_FILE_DELETE == DetectPolyRansomK())
	{
		return VIRUS_FILE_DELETE;
	}
	if(VIRUS_FILE_DELETE == DetectPolyRansomCry())
	{
		return VIRUS_FILE_DELETE;
	}
	 	
	return iReturnStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Ransom Family
--------------------------------------------------------------------------------------*/
int CPolyRansom::CleanVirus()
{

	return VIRUS_FILE_REPAIR;

}


/*-------------------------------------------------------------------------------------
	Function		: DetectPolyRansom
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Gajanan + Virus Analysis Team
	Description		: 1. Decryption on 0x401000 upto 1st call [REG]
				      2. Sig Check at 0x401000 + 0x5 (Decryption)
				      3. Delete encrypted file.
--------------------------------------------------------------------------------------*/
int CPolyRansom::DetectPolyRansom()//DetectPolyRansom.a
{
	int			iReturnStatus = VIRUS_NOT_FOUND;

	//Added this check for Handling currupt File
	/*if (m_pMaxPEFile->m_dwFileSize < m_pMaxPEFile->m_stSectionHeader[0].SizeOfRawData);
	{
		return iReturnStatus;
	}*/

	BYTE		bPolyRansomSig[]={0x33, 0xC9, 0x8D, 0x35, 0x20, 0x10, 0x40, 0x00, 0x31, 0x06, 0x83, 0xC6, 0x04, 0x83, 0xC1, 0x04, 0x81, 0xF9};//, 0x82, 0x04, 0x00, 0x00, 0x7C, 0xF0, 0x90, 0x90, 0x90};// Change/Update Sig as per Decryption in future.
	CEmulate	objEmulate(m_pMaxPEFile);
	DWORD		dwRegVal=-1;
	int			iReg=-1;
	char		szInstruction[1024]={0};
	DWORD		dwXORKey = 0;

	if(!objEmulate.IntializeProcess())//File having VS + RVA > 10MB are skipped.
	{
		return iReturnStatus;
	}

	objEmulate.SetBreakPoint("__isinstruction('cmp e')");
	objEmulate.SetBreakPoint("__isinstruction('call e')");

	objEmulate.ActiveBreakPoint(0);
	objEmulate.ActiveBreakPoint(1);
	objEmulate.SetNoOfIteration(0x7000);
	if(7!=objEmulate.EmulateFile())
	{
		return iReturnStatus;
	}
	objEmulate.GetInstruction(szInstruction);
	if(strstr(szInstruction,"cmp e"))
	{
		DWORD dwOffset = objEmulate.GetEip();
			DWORD dwCmpOffset = dwOffset;
			if(m_pbyBuff)
				delete m_pbyBuff;

			m_pbyBuff=new BYTE[0x25];
			if(!m_pbyBuff)
			{
				return iReturnStatus;
			}
			if(!objEmulate.ReadEmulateBuffer(m_pbyBuff,0x25,dwOffset))
			{
				return iReturnStatus;
			}
			dwOffset -= m_pMaxPEFile->m_stPEHeader.ImageBase;
			DWORD dwJMPRVA = *(DWORD *)&m_pbyBuff[0x4] + dwOffset + 0x2 + 0x6;
			DWORD dwJMPoffset = 0, dwSize = 0;
			char szMOV[1024] = {0}, szXOR[1024] = {0};
			char szRegister[5]={0};
			m_pMaxPEFile->Rva2FileOffset(dwJMPRVA,&dwJMPoffset);
			dwSize = dwOffset - dwJMPRVA;
		
		if(m_pbyBuff)
		delete m_pbyBuff;

		m_pbyBuff= new BYTE[dwSize];
		if(!m_pbyBuff)
		{
			return iReturnStatus;
		}

		if(!GetBuffer(dwJMPoffset,dwSize,dwSize))
			return iReturnStatus;

		DWORD dwLength = 0;
		t_disasm da;
		dwOffset = 0;
		while(dwOffset < dwSize)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwLength > (dwSize - dwOffset))
			{
				break;
			}

			if(dwLength==0x02 && strstr(da.result, "MOV E")&&(strstr(da.result, ",[EAX]")||strstr(da.result, ",[EBX]")||strstr(da.result, ",[ECX]")||strstr(da.result, ",[EDX]") || strstr(da.result, ",[ESI]") || strstr(da.result, ",[EDI]")))
			{

				char		*ptr = NULL;
				ptr = strstr(da.result, "MOV E");
				if(ptr)
				{
					ptr += strlen("MOV E")- 1;

					szRegister[0] = ptr[0];
					szRegister[1] = ptr[1];
					szRegister[2] = ptr[2];
					szRegister[3] = '\0';
				}
				sprintf_s(szMOV, 1024, "__isinstruction('MOV %s ,DWORD PTR [')", szRegister);
				sprintf_s(szXOR, 1024, "__isinstruction('XOR %s ,E')", szRegister);
				break;
			}
			dwOffset += dwLength;
		}
		objEmulate.PauseBreakPoint(0);
		objEmulate.PauseBreakPoint(1);
		objEmulate.SetBreakPoint(szMOV);//2
		objEmulate.SetBreakPoint(szXOR);//3
		objEmulate.PauseBreakPoint(3);
		objEmulate.ActiveBreakPoint(2);
		objEmulate.SetNoOfIteration(dwSize);
		objEmulate.SetEip(dwJMPRVA + m_pMaxPEFile->m_stPEHeader.ImageBase);

		if(7!=objEmulate.EmulateFile())
		{
			return iReturnStatus;
		}
		objEmulate.PauseBreakPoint(2);
		objEmulate.ActiveBreakPoint(3);
		objEmulate.SetNoOfIteration(dwSize);
		if(7!=objEmulate.EmulateFile())					// After getting MOV insytruction search for XOR 
		{
			return iReturnStatus;
		}
		objEmulate.GetInstruction(szInstruction);
		DWORD dwValue = objEmulate.GetSrcRegNo();
		dwXORKey = objEmulate.GetSpecifyRegValue(dwValue);


		objEmulate.SetEip(dwCmpOffset + 0x8);
		objEmulate.PauseBreakPoint(0);
		objEmulate.PauseBreakPoint(2);
		objEmulate.PauseBreakPoint(3);
		objEmulate.ActiveBreakPoint(1);
		objEmulate.SetNoOfIteration(0x7000);//0x1F00
		if(7!=objEmulate.EmulateFile())
		{
			return iReturnStatus;
		}
		memset(szInstruction, 0, 1024);
		objEmulate.GetInstruction(szInstruction);
	}

	if(!strcmp(szInstruction,"call eax "))	iReg=0;
	else if(!strcmp(szInstruction,"call ecx "))	iReg=1;
	else if(!strcmp(szInstruction,"call edx "))	iReg=2;
	else if(!strcmp(szInstruction,"call ebx "))	iReg=3;
	else if(!strcmp(szInstruction,"call esi "))	iReg=6;
	else if(!strcmp(szInstruction,"call edi "))	iReg=7;
	if (-1==iReg)	return iReturnStatus;


	dwRegVal= objEmulate.GetSpecifyRegValue(iReg);
	if(dwRegVal != 0x401000)
	{
		return iReturnStatus;
	}
	m_pbyBuff=new BYTE[0x25];
	if(!m_pbyBuff)
	{
		return iReturnStatus;
	}
	if(!objEmulate.ReadEmulateBuffer(m_pbyBuff,0x25,dwRegVal))
	{
		return iReturnStatus;
	}
	// add sig
	if( memcmp(&m_pbyBuff[5],bPolyRansomSig,sizeof(bPolyRansomSig))==0)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.PolyRansom.a"));		
		return VIRUS_FILE_DELETE;
	}

	if(dwXORKey != 0)
	{
		for(int i = 4; i<0x21; i+=4)
			*(DWORD*)&m_pbyBuff[i] ^= dwXORKey;
	}
	if(m_pbyBuff[0]==0xb8)//MOV EAX
	{
		if(m_pbyBuff[5]==0x90)//NOP
		{ 
			BYTE bPolyRansomSig1[]={ 0xe9, 0x80 ,0x00 ,0x00 ,0x00};  //JMP 0040108B
			BYTE bPolyRansomSig2[]={0x61, 0x31, 0x6, 0x60}; // POPAD,XOR,PUSHAD
			for( int i = 6; i< 0x21; i++)
			{
				if((memcmp(&m_pbyBuff[i],bPolyRansomSig1,sizeof( bPolyRansomSig1))) || (memcmp(&m_pbyBuff[i],bPolyRansomSig2,sizeof( bPolyRansomSig2)))==0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.PolyRansom.a"));		
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}

	return iReturnStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectPolyRansomB
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ramandeep + Alisha + Sneha	Virus Analysis Team
	Description		: Detection routine for Ransom.B
--------------------------------------------------------------------------------------*/
int CPolyRansom:: DetectPolyRansomB()
{
	
	int iRetStatus = VIRUS_NOT_FOUND; 
	BYTE bMajorLinkerVersion = 0;
	WORD wMajorOSVersion = 0;



	m_pMaxPEFile->ReadBuffer(&bMajorLinkerVersion, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x1A, 1, 1);	
	m_pMaxPEFile->ReadBuffer(&wMajorOSVersion, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x40, 2, 2);

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	if (m_wAEPSec==0x0 && (m_dwAEPUnmapped==0x1000 || m_dwAEPUnmapped==0x1400 || m_dwAEPUnmapped==0xA0F27 || m_dwAEPUnmapped==0xA0885 || 
		m_dwAEPUnmapped==0xA0D6F || m_dwAEPUnmapped== 0xA24C2 || m_dwAEPUnmapped== 0x96B49 || m_dwAEPUnmapped== 0x81098 || m_dwAEPUnmapped== 0x95D56
		|| m_dwAEPUnmapped==0xA06B1 || m_dwAEPUnmapped==0x154DD0) && (m_wNoOfSections == 0x03 ||m_wNoOfSections == 0x04 || m_wNoOfSections == 0x05)&&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[14].Size ==0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size ==0
		&&(m_pMaxPEFile->m_stPEHeader.SizeOfHeaders==0x600 || m_pMaxPEFile->m_stPEHeader.SizeOfHeaders==0x1000) &&m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion==0xc
		&& m_pMaxPEFile->m_stPEHeader.Characteristics==0x10f && bMajorLinkerVersion==0x5 && wMajorOSVersion==0x4
		&& m_pMaxPEFile->m_stPEHeader.DataDirectory[12].Size <=0x40)// Added

	{        
		DWORD	dwBuffOffset =0;
		int RANSOM_BUFF_SIZE =0xC;


		RANSOM_BUFF_SIZE =0x2A;
		dwBuffOffset=0x400;									 
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}  

		m_pbyBuff = new BYTE[RANSOM_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}

		if(!GetBuffer(dwBuffOffset,RANSOM_BUFF_SIZE,RANSOM_BUFF_SIZE))
		{
			return iRetStatus;
		}


		CSemiPolyDBScn	objdbscan;
		TCHAR			szVirusName[MAX_PATH] = {0};
		LPCTSTR			szagentn = (_T("6A00680530400068003040006A00E817040000*6A00E816040000E817040000E81E040000E813040000C3"));
		objdbscan.LoadSigDBEx(szagentn, _T("Virus.PolyRansom.b"), FALSE);	


		if(objdbscan.ScanBuffer(&m_pbyBuff[0], RANSOM_BUFF_SIZE, szVirusName)>= 0)
		{
			if(_tcslen(szVirusName)>0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}


	}
	if (m_wAEPSec==0x0 && m_dwAEPUnmapped==0x1000 && (m_pSectionHeader[m_wAEPSec].SizeOfRawData == m_pSectionHeader[m_wAEPSec].Misc.VirtualSize) && (m_wNoOfSections == 0x03 ||m_wNoOfSections == 0x04)&&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[14].Size ==0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size ==0
		&&m_pMaxPEFile->m_stPEHeader.SizeOfHeaders==0x200 &&m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion==0xc
		&& m_pMaxPEFile->m_stPEHeader.Characteristics==0x30f && bMajorLinkerVersion==0x5 && wMajorOSVersion==0x4
		&& m_pMaxPEFile->m_stPEHeader.DataDirectory[12].Size <=0x40 )
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}  

		m_pbyBuff = new BYTE[0x5];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		DWORD dwBuffOffset = m_pMaxPEFile->m_stPEHeader.SizeOfHeaders;
		if(!GetBuffer(dwBuffOffset+0x23,0x5,0x5))
		{
			return iRetStatus;
		}

		BYTE SignBuff[] = {0x76, 0x32, 0x2E, 0x31, 0x39};

		if(memcmp(&m_pbyBuff[0],&SignBuff[0],0x5) == 0)
		{
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			} 
			m_pbyBuff = new BYTE[0x300];
			if(!m_pbyBuff)
			{
				return iRetStatus;
			}

			if(!GetBuffer(m_dwAEPMapped,0x300,0x300))
			{
				return iRetStatus;
			}

			DWORD dwLength = 0;
			t_disasm da = {0};
			int iInstrstCnt = 0;
			DWORD dwJMPDistance = 0;

			DWORD dwOffset=0, dwTempOffset = 0;

			while(dwOffset<0x300)
			{
				if(!dwTempOffset)
				{
					dwOffset=dwOffset+dwLength;
				}
				dwTempOffset = 0;
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE); 

				if(dwLength == 0x5  && strstr(da.result, "CALL"))
				{
					continue;
				}
				else if(dwLength == 0x5 && strstr(da.result, "CMP"))
				{
					if(da.immconst <0xFFFFFFF)
						break;
					continue;
				}
				else if(dwLength == 0x6 && strstr(da.result, "JN"))
				{
					dwTempOffset = (*(DWORD *)&m_pbyBuff[dwOffset + 0x2] + dwOffset + 6);
					if(dwTempOffset >0x300)
						break;
					dwOffset = dwTempOffset;
					iInstrstCnt++;
					continue;
				}
				else if(iInstrstCnt >= 0x2 && dwLength == 0x5 && strstr(da.result, "JMP"))
				{
					//dwTempOffset = (*(DWORD *)&m_pbyBuff[dwOffset + 0x1] + dwOffset + 5);
					dwJMPDistance =   da.jmpconst - (m_dwAEPUnmapped + m_dwImageBase);

					if(dwJMPDistance > 0xB0000)
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, L"Virus.PolyRansom.B1");
						return VIRUS_FILE_DELETE;
					}
					else if(dwJMPDistance >= 0x71EE5 && dwJMPDistance <= 0x76B1D) //added for MPRESS FILE
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, L"Virus.PolyRansom.B1");
						return VIRUS_FILE_DELETE;
					}
					else
						break;
				}

			}
		}

	}
	return iRetStatus; //if
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPolyRansomB
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Aniket Deshmukh + Virus Analysis Team
	Description		: Detection routine for Ransom.E
					  1) virus sample drops two exe of same varient in two different locations
						- C:\Documents and Settings\admin\Application Data\cacleate
						- C:\WINDOWS\system32
			          2) Virus sample only affects pdf files, it encrypts data of pdf and converts it into application file.
			     	  3) sample detection is 100 percent 1342/1342.
					  Signature candidate: loop shifting important data to address 30000 and api calls.
--------------------------------------------------------------------------------------*/
int CPolyRansom::DetectPolyRansomE()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader .Characteristics & IMAGE_FILE_DLL ) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	if(m_wAEPSec == 0x0 && m_dwAEPUnmapped == 0x1407 && m_wNoOfSections == 0x0005
		&& m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x800 )
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int POLYRANSOME_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[POLYRANSOME_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0x00, POLYRANSOME_BUFF_SIZE);

		if(!GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x400, POLYRANSOME_BUFF_SIZE, POLYRANSOME_BUFF_SIZE))
		{
			return iRetStatus;
		}

		CSemiPolyDBScn objdbscan;
		TCHAR szVirusName[MAX_PATH] = {0};
		LPCTSTR szPolyransomE = (_T("BB78563412B978563412BA78563412FF15*24204000A300304000E813000000FF15*282040006A0050FF152C20400033C05BC3"));//loop shifting important data to address 30000 and api calls
		
		objdbscan.LoadSigDBEx(szPolyransomE,_T("Virus.PolyRansom.e"),FALSE);
		if(objdbscan.ScanBuffer(&m_pbyBuff[0],POLYRANSOME_BUFF_SIZE,szVirusName)>=0)
		{
			if(_tcslen(szVirusName)>0)
			{
				_tcscpy_s(m_szVirusName,MAX_VIRUS_NAME,szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPolyRansomB
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ramndeep Singh + Virus Analysis Team
	Description		: Detection routine for Ransom.F
					  1) virus sample drops two exe of same varient in two different locations
						- C:\Documents and Settings\admin\Application Data\cacleate
						- C:\WINDOWS\system32
			          2) Virus sample only affects pdf files, it encrypts data of pdf and converts it into application file.
			     	  3) sample detection is 100 percent 1342/1342.
					  Signature candidate: loop shifting important data to address 30000 and api calls.
--------------------------------------------------------------------------------------*/
int CPolyRansom:: DetectPolyRansomF()
{

	int iRetStatus = VIRUS_NOT_FOUND; 
	BYTE bMajorLinkerVersion = 0;
	WORD wMajorOSVersion = 0;	

	m_pMaxPEFile->ReadBuffer(&bMajorLinkerVersion, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x1A, 1, 1);	
	m_pMaxPEFile->ReadBuffer(&wMajorOSVersion, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x40, 2, 2);

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	if (m_wAEPSec==0x0 && (m_dwAEPUnmapped >= 0x1000 && m_dwAEPUnmapped <= 0x1200 ) &&( m_wNoOfSections == 0x04 ||m_wNoOfSections == 0x03 )&&
		m_pMaxPEFile->m_stPEHeader.DataDirectory[14].Size ==0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size ==0
		&&m_pMaxPEFile->m_stPEHeader.SizeOfHeaders==0x600 &&m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion==0xc
		&& m_pMaxPEFile->m_stPEHeader.Characteristics==0x10f && bMajorLinkerVersion==0x5 && wMajorOSVersion==0x4
		&& m_pMaxPEFile->m_stPEHeader.DataDirectory[12].Size <=0x50 &&  m_pMaxPEFile->m_stPEHeader.CheckSum ==0 &&
		m_pSectionHeader[m_wAEPSec + 2].SizeOfRawData == 0x800 && m_pSectionHeader[m_wAEPSec + 2].Characteristics == 0xE0000020 )


	{        
		DWORD	dwBuffOffset =0;
		int RANSOM_BUFF_SIZE =0x13;
		dwBuffOffset=m_pSectionHeader[m_wAEPSec].PointerToRawData ;

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}  

		m_pbyBuff = new BYTE[RANSOM_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}

		if(!GetBuffer((dwBuffOffset+0x400),RANSOM_BUFF_SIZE,RANSOM_BUFF_SIZE))
		{
			return iRetStatus;
		}

		int i=0;

		unsigned char	szFirstCheck[] = {0xE5,0x5E,0x70,0x75,0x24,0x63};
		unsigned char	szSecondCheck[] = {0x63,0x6D,0xE5};
		unsigned char	szThirdCheck[] = {0x62,0x62,0x61,0x8F,0x67};


		if(memcmp(&m_pbyBuff[i],&szFirstCheck[0] ,sizeof(szFirstCheck))==0)
		{
			i=i+9;
			if (memcmp(&m_pbyBuff[i],&szSecondCheck[0],sizeof(szSecondCheck))==0)
			{
				i=i+4;					
				if ( memcmp(&m_pbyBuff[i],&szThirdCheck[0],sizeof(szThirdCheck))==0)
				{  

					RANSOM_BUFF_SIZE =0x2A;
					dwBuffOffset=0x400;									 
					if(m_pbyBuff)
					{
						delete []m_pbyBuff;
						m_pbyBuff = NULL;
					}  

					m_pbyBuff = new BYTE[RANSOM_BUFF_SIZE];
					if(!m_pbyBuff)
					{
						return iRetStatus;
					}

					if(!GetBuffer(dwBuffOffset,RANSOM_BUFF_SIZE,RANSOM_BUFF_SIZE))
					{
						return iRetStatus;
					}


					CSemiPolyDBScn	objdbscan;
					TCHAR			szVirusName[MAX_PATH] = {0};
					LPCTSTR			szagentn = (_T("6A00680530400068003040006A00E817040000*6A00E816040000E817040000E81E040000E813040000C3"));
					objdbscan.LoadSigDBEx(szagentn, _T("Virus.PolyRansom.f"), FALSE);	


					if(objdbscan.ScanBuffer(&m_pbyBuff[0], RANSOM_BUFF_SIZE, szVirusName)>= 0)
					{
						if(_tcslen(szVirusName)>0)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
							return VIRUS_FILE_DELETE;
						}
					}	  
				}
				return iRetStatus;//3
			}
			return iRetStatus;//2
		}
		return iRetStatus;//1
	}
	return iRetStatus; //if
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPolyRansomK
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Sneha + Ramndeep Singh + Virus Analysis Team
	Description		: Detection routine for Ransom.K
--------------------------------------------------------------------------------------*/
int CPolyRansom::DetectPolyRansomK()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec != 0x0 && m_wAEPSec != 0x4 )
		return iRetStatus;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	DWORD dwStartOffset = 0;
	if(m_dwAEPMapped == m_pSectionHeader[m_wAEPSec].PointerToRawData)
		dwStartOffset = m_dwAEPMapped;
	else if(m_dwAEPMapped == 0xB400 || m_dwAEPMapped == 0xB600)       //added
		dwStartOffset = m_pSectionHeader[m_wAEPSec].PointerToRawData;
	else 
		return iRetStatus;

	const int RANSOM_BUFF_SIZE = 0x40;
	m_pbyBuff = new BYTE[RANSOM_BUFF_SIZE];

	if(GetBuffer(dwStartOffset,RANSOM_BUFF_SIZE,RANSOM_BUFF_SIZE))
	{

		DWORD dwLength = 0;
		t_disasm da = {0};
		int iInstructionNo = 0;

		DWORD dwOffset=0;

		while(dwOffset<0x40)
		{
			dwOffset=dwOffset+dwLength;
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE); 

			if(dwLength == 0x2 && iInstructionNo == 0x0 && strstr(da.result, "PUSH 40"))
			{
				iInstructionNo++;
				continue;
			}
			else if(dwLength == 0x5 && iInstructionNo == 0x1 &&( strstr(da.result,"PUSH 1000") || strstr(da.result,"PUSH 3000")))
			{
				iInstructionNo++;
				continue;
			}
			else if(dwLength == 0x2 && iInstructionNo == 0x2 && strstr(da.result, "PUSH 0"))
			{
				iInstructionNo++;
				continue;
			}
			else if(dwLength == 0x5 && iInstructionNo == 0x3 && strstr(da.result,"CALL"))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.polyransom.k"));
				return VIRUS_FILE_DELETE;
			}
		}
	}

	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectPolyRansomK
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ramndeep Singh + Virus Analysis Team
	Description		: Detection routine for Ransom.I and Ransom.h
--------------------------------------------------------------------------------------*/
int CPolyRansom::DetectPolyRansomI()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(((m_wNoOfSections != 0x6 && m_dwAEPMapped !=0x0613) || ( m_wNoOfSections != 0x5 && m_dwAEPMapped !=0x0AB0)) &&  m_pSectionHeader[m_wAEPSec].SizeOfRawData!= 0x0800)		// Primary Checks
		return iRetStatus;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	const int RANSOM_BUFF_SIZE = 0x21;
	DWORD dwStartOffset = 0;
	m_pbyBuff = new BYTE[RANSOM_BUFF_SIZE];
	if(m_dwAEPMapped == 0x613)
		dwStartOffset = 0x58F;
	else if(m_dwAEPMapped == 0xAB0)
		dwStartOffset = 0x5B0;


	if(!GetBuffer(dwStartOffset, RANSOM_BUFF_SIZE, RANSOM_BUFF_SIZE))
	{
		return iRetStatus;
	}

	CSemiPolyDBScn	objdbscan;
	TCHAR			szVirusName[MAX_PATH] = {0};
	LPCTSTR			szPOLYRANSOMI = (_T("8B4C24188B54241C8A0188024241*894C241833FF8954241C85*FEFFFF"));


	objdbscan.LoadSigDBEx(szPOLYRANSOMI, _T("virus.polyransom.i"), FALSE);



	if(objdbscan.ScanBuffer(&m_pbyBuff[0], RANSOM_BUFF_SIZE, szVirusName)>= 0)
	{
		if(_tcslen(szVirusName)>0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return VIRUS_FILE_DELETE;
		}
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPolyRansomCry
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Ramndeep Singh + Virus Analysis Team
	Description		: Detection routine for Ransom.d and Ransom.cry 
--------------------------------------------------------------------------------------*/
int CPolyRansom::DetectPolyRansomCry()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader .Characteristics & IMAGE_FILE_DLL ) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}


	if((memcmp(m_pSectionHeader[m_wAEPSec + 2].Name, ".data", 4) != 0) || m_wNoOfSections != 0x4)
	{
		return iRetStatus;
	}
	const int RANSOM_BUFF_SIZE = (m_pSectionHeader[2].SizeOfRawData/2) + 0x500;
	m_pbyBuff = new BYTE[RANSOM_BUFF_SIZE];

	if(!GetBuffer(m_pSectionHeader[2].PointerToRawData, RANSOM_BUFF_SIZE, RANSOM_BUFF_SIZE))
	{
		return iRetStatus;
	}

	CSemiPolyDBScn	objdbscan;
	TCHAR			szVirusName[MAX_PATH] = {0};
	LPCTSTR			szPOLYRANSOMCRY = (_T("57414E4143525921*4D6963726F736F667420456E68616E6365642052534120616E6420414553*43727970746F677261706869632050726F7669646572"));
	LPCTSTR         szPOLYRANSOMCRY1 = (_T("520045004300590043004C00450000000000250073005C00250073*0025007300000000002E0057004E0043005200590054"));

	objdbscan.LoadSigDBEx(szPOLYRANSOMCRY, _T("Trojan.Ransom.Wanna.d"), TRUE);
	objdbscan.LoadSigDBEx(szPOLYRANSOMCRY1, _T("Trojan.Ransom.Wanna1.d"), FALSE);

	if(objdbscan.ScanBuffer(&m_pbyBuff[0], RANSOM_BUFF_SIZE, szVirusName)>= 0)
	{
		if(_tcslen(szVirusName)>0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return VIRUS_FILE_DELETE;
		}
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPolyRansomC
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Santosh Awale + Sneha Kurade + Virus Analysis Team
	Description		: Detection routine for Ransom.c
--------------------------------------------------------------------------------------*/
int CPolyRansom::DetectPolyRansomC()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if( m_wNoOfSections == 0x0005
		&& (m_pSectionHeader[0].Characteristics==0x60000020 ||  m_pSectionHeader[0].Characteristics==0xE0000020) // Added
		&& (m_pSectionHeader[1].Characteristics==0x40000040 ||  m_pSectionHeader[1].Characteristics==0xC0000040)
		&& (m_pSectionHeader[2].Characteristics==0xC0000040)
		&& (m_pSectionHeader[3].Characteristics==0x40000040 ||  m_pSectionHeader[3].Characteristics==0xC0000040)
		&& (m_pSectionHeader[4].Characteristics==0x42000040 ||  m_pSectionHeader[4].Characteristics==0xC2000040 ||  m_pSectionHeader[4].Characteristics==0xE2000040)) //Added Sneha 20 Nov 2019
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int RANSOMC_BUFF_SIZE = 0x30;
		m_pbyBuff = new BYTE[RANSOMC_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0x00, RANSOMC_BUFF_SIZE);

		DWORD ReadOffset=m_dwAEPMapped - 0x2EA;

		if(!GetBuffer(ReadOffset, RANSOMC_BUFF_SIZE, RANSOMC_BUFF_SIZE))
		{
			return iRetStatus;
		}

		CSemiPolyDBScn	objdbscan;
		TCHAR			szVirusName[MAX_PATH] = {0};
		LPCTSTR			szRansomC = (_T("8A4424148B1602C30FB6C8*8B442410D3CA33D02BD38916*83C6044B75E3"));

		objdbscan.LoadSigDBEx(szRansomC,_T("Virus.w32.PolyRansom.C"),FALSE);
		if(objdbscan.ScanBuffer(&m_pbyBuff[0],RANSOMC_BUFF_SIZE,szVirusName)>=0)
		{
			if(_tcslen(szVirusName)>0)
			{
				_tcscpy_s(m_szVirusName,MAX_VIRUS_NAME,szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}