/*======================================================================================
   FILE				: MaxCursor.cpp
   ABSTRACT			: Supportive class for CUR File Scanner
   DOCUMENTS		: 
   AUTHOR			: Tushar Kadam
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 22 Jul 2010
   NOTES			: This module manages the scanning for file tyep CUR (Mouse Cursor). 
   VERSION HISTORY	: 
=====================================================================================*/
#include "MaxELF.h"

/*-------------------------------------------------------------------------------------
	Function		: CMaxELF
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CMaxELF::CMaxELF()
{
	m_pProgHeader = NULL;
	m_pSecHeader = NULL;
	memset(&m_stFileHeader, 0, sizeof(m_stFileHeader));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CMaxELF
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CMaxELF::~CMaxELF()
{
	if(m_pProgHeader)
	{
		delete m_pProgHeader;
		m_pProgHeader = NULL;
	}
	if(m_pSecHeader)
	{
		delete m_pSecHeader;
		m_pSecHeader = NULL;
	}
}
/*-------------------------------------------------------------------------------------
	Function		: IsValidELFFile
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Validates file type for ELF File
--------------------------------------------------------------------------------------*/
bool CMaxELF::IsValidELFFile(CMaxPEFile *pMaxPEFile)
{
	bool bRet = false;
		
	if(!pMaxPEFile->ReadBuffer(&m_stFileHeader, 0, sizeof(m_stFileHeader), sizeof(m_stFileHeader)))
	{
		return bRet;
	}
	if((*(DWORD *)&m_stFileHeader) != 0x464C457F)
	{
		return bRet;
	}
	if(m_stFileHeader.ELF_DATA==0x2)
	{
		if(!ConvertBEFileHeaderToLE())
		{
			return bRet;
		}
	}

	if (m_stFileHeader.ELF_SNO_OF_ELE <= 0x00 || m_stFileHeader.ELF_SNO_OF_ELE > 0x30)
	{
		return bRet;
	}

	DWORD dwBytesToRead = m_stFileHeader.ELF_PNO_OF_ELE * m_stFileHeader.ELF_PROGHEADER_ELE_SIZE;
	if(dwBytesToRead == 0 || dwBytesToRead > 0x200)
	{
		return bRet;
	}
	
	if(m_pProgHeader)
	{
		delete(m_pProgHeader);
		m_pProgHeader = NULL;
	}
	
	m_pProgHeader = new PROGRAM_HEADER[m_stFileHeader.ELF_PNO_OF_ELE];
	memset(m_pProgHeader, 0, dwBytesToRead);	
	
	if(pMaxPEFile->ReadBuffer(m_pProgHeader, m_stFileHeader.ELF_PROG_HEADER_OFF, dwBytesToRead, dwBytesToRead))
	{		
		if(m_stFileHeader.ELF_DATA==0x2)
	    {
			if(!ConvertBEProgramHeaderToLE())
		    {
			   return bRet;
		    }
			
		}
	}
	dwBytesToRead = m_stFileHeader.ELF_SNO_OF_ELE * m_stFileHeader.ELF_SECHEADER_ELE_SIZE;
	if(dwBytesToRead == 0)
	{
		return bRet;
	}
	
	if(m_pSecHeader)
	{
		delete(m_pSecHeader);
		m_pSecHeader = NULL;
	}
	m_pSecHeader = new SECTION_HEADER[m_stFileHeader.ELF_SNO_OF_ELE];
	memset(m_pSecHeader, 0, dwBytesToRead);
	if(pMaxPEFile->ReadBuffer(m_pSecHeader, m_stFileHeader.ELF_SECTION_HEADER_OFFSET, dwBytesToRead, dwBytesToRead))
	{		
		if(m_stFileHeader.ELF_DATA==0x2)
	    {
			if(!ConvertBESectionHeaderToLE())
		    {
			   return bRet;
		    }
			
		}
	}
	return true;
}
/*-------------------------------------------------------------------------------------
	Function		: ConvertBEFileHeaderToLE
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: sagar bade
	Description		: Converts File Header from Big Ending ==> Little Indian
--------------------------------------------------------------------------------------*/
bool CMaxELF::ConvertBEFileHeaderToLE()
{
	m_stFileHeader.ELF_TYPE = _byteswap_ushort(m_stFileHeader.ELF_TYPE);
	m_stFileHeader.ELF_MACHINE = _byteswap_ushort(m_stFileHeader.ELF_MACHINE);
	m_stFileHeader.ELF_VER = _byteswap_ulong(m_stFileHeader.ELF_VER);
	m_stFileHeader.ELF_ENTRY = _byteswap_ulong(m_stFileHeader.ELF_ENTRY);
	m_stFileHeader.ELF_PROG_HEADER_OFF = _byteswap_ulong(m_stFileHeader.ELF_PROG_HEADER_OFF);
	m_stFileHeader.ELF_SECTION_HEADER_OFFSET = _byteswap_ulong(m_stFileHeader.ELF_SECTION_HEADER_OFFSET);
	m_stFileHeader.ELF_FLAGS = _byteswap_ulong(m_stFileHeader.ELF_FLAGS);
	m_stFileHeader.ELF_HEADER_SIZE = _byteswap_ushort(m_stFileHeader.ELF_HEADER_SIZE);
	m_stFileHeader.ELF_PROGHEADER_ELE_SIZE = _byteswap_ushort(m_stFileHeader.ELF_PROGHEADER_ELE_SIZE);
	m_stFileHeader.ELF_PNO_OF_ELE = _byteswap_ushort(m_stFileHeader.ELF_PNO_OF_ELE);
	m_stFileHeader.ELF_SECHEADER_ELE_SIZE = _byteswap_ushort(m_stFileHeader.ELF_SECHEADER_ELE_SIZE);
	m_stFileHeader.ELF_SNO_OF_ELE = _byteswap_ushort(m_stFileHeader.ELF_SNO_OF_ELE);
	m_stFileHeader.ELF_SHEADER_STR_INDX = _byteswap_ushort(m_stFileHeader.ELF_SHEADER_STR_INDX);
	return true;
}
/*-------------------------------------------------------------------------------------
	Function		: ConvertBESectionHeaderToLE
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: sagar bade
	Description		: Converts Section Header from Big Ending ==> Little Indian
--------------------------------------------------------------------------------------*/
bool CMaxELF::ConvertBESectionHeaderToLE()
{
	//m_pSecHeader. = _byteswap_ulong(m_pSecHeader.SH_NAME);
	for(WORD i = 0; i < m_stFileHeader.ELF_SNO_OF_ELE; i++)
	{

	m_pSecHeader[i].SH_NAME = _byteswap_ulong(m_pSecHeader[i].SH_NAME);
	m_pSecHeader[i].SH_TYPE = _byteswap_ulong(m_pSecHeader[i].SH_TYPE);
	m_pSecHeader[i].SH_FLAGS = _byteswap_ulong(m_pSecHeader[i].SH_FLAGS);
	m_pSecHeader[i].SH_ADDR = _byteswap_ulong(m_pSecHeader[i].SH_ADDR);
	m_pSecHeader[i].SH_OFFSET = _byteswap_ulong(m_pSecHeader[i].SH_OFFSET);
	m_pSecHeader[i].SH_SIZE = _byteswap_ulong(m_pSecHeader[i].SH_SIZE);
	m_pSecHeader[i].SH_LINK = _byteswap_ulong(m_pSecHeader[i].SH_LINK);
	m_pSecHeader[i].SH_INFO = _byteswap_ulong(m_pSecHeader[i].SH_INFO);
	m_pSecHeader[i].SH_ADDRALIGN = _byteswap_ulong(m_pSecHeader[i].SH_ADDRALIGN);
	m_pSecHeader[i].SH_ENTSIZE = _byteswap_ulong(m_pSecHeader[i].SH_ENTSIZE);
	}
	return true;
}
/*-------------------------------------------------------------------------------------
	Function		: ConvertBEProgramHeaderToLE
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: sagar bade
	Description		: Converts Program Header from Big Ending ==> Little Indian
--------------------------------------------------------------------------------------*/
bool CMaxELF::ConvertBEProgramHeaderToLE()
{
	for(int i = 0; i < m_stFileHeader.ELF_PNO_OF_ELE; i++)
	{

	m_pProgHeader[i].P_TYPE = _byteswap_ulong(m_pProgHeader[i].P_TYPE);
	m_pProgHeader[i].P_OFFSET = _byteswap_ulong(m_pProgHeader[i].P_OFFSET);
	m_pProgHeader[i].P_VADDR = _byteswap_ulong(m_pProgHeader[i].P_VADDR);
	m_pProgHeader[i].P_PADDR = _byteswap_ulong(m_pProgHeader[i].P_PADDR);
	m_pProgHeader[i].P_FILESZ = _byteswap_ulong(m_pProgHeader[i].P_FILESZ);
	m_pProgHeader[i].P_MEMSZ = _byteswap_ulong(m_pProgHeader[i].P_MEMSZ);
	m_pProgHeader[i].P_FLAGS = _byteswap_ulong(m_pProgHeader[i].P_FLAGS);
	m_pProgHeader[i].P_ALIGN = _byteswap_ulong(m_pProgHeader[i].P_ALIGN);
	}
	return true;
}
/*-------------------------------------------------------------------------------------
	Function		: GetBuffer
	In Parameters	: LPBYTE byBuffer, DWORD& cbBuffer, CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Get binary buffer from ELF File
--------------------------------------------------------------------------------------*/
bool CMaxELF::GetBuffer(LPBYTE byBuffer, DWORD& cbBuffer, CMaxPEFile *pMaxPEFile)
{
	if(cbBuffer < ELF_BUFF_SIZE)
	{
		return false;
	}

	DWORD dwFileAddr = 0;
	DWORD dwImageBase = m_pProgHeader[0].P_VADDR;
	DWORD dwImageSize =dwImageBase+m_pProgHeader[0].P_FILESZ;
	
	for(int i = 0; i < m_stFileHeader.ELF_PNO_OF_ELE; i++)
	{
		if(dwImageBase > m_pProgHeader[i].P_VADDR && m_pProgHeader[i].P_VADDR > 0)
		{
			dwImageBase = m_pProgHeader[i].P_VADDR;		
			dwImageSize = ( m_pProgHeader[i].P_FILESZ + dwImageBase);
		}
	}
	DWORD dwBufOff=0x0;
	for(WORD i = 0x0; i < m_stFileHeader.ELF_SNO_OF_ELE; i++)
	{
		if(dwImageSize > m_pSecHeader[i].SH_ADDR && m_pSecHeader[i].SH_ADDR > 0)
		{
			DWORD dwBytestoread=0x1000;
			if(m_pSecHeader[i].SH_SIZE<0x1000)
			{
				dwBytestoread=m_pSecHeader[i].SH_SIZE;

			}
			if(pMaxPEFile->ReadBuffer(&byBuffer[dwBufOff], (m_pSecHeader[i].SH_ADDR-dwImageBase), dwBytestoread, dwBytestoread, &cbBuffer))
			{
				dwBufOff+=cbBuffer;
			}				
		}

	}
	cbBuffer=dwBufOff;

	/*dwFileAddr = (m_stFileHeader.ELF_ENTRY - dwImageBase); 
	if(pMaxPEFile->ReadBuffer(byBuffer, dwFileAddr, ELF_BUFF_SIZE, 0, &cbBuffer))
	{
		if(cbBuffer == ELF_BUFF_SIZE || cbBuffer == (pMaxPEFile->m_dwFileSize - dwFileAddr))
		{
			return true;
		}
	}*/
	return true;
}

bool CMaxELF::GetFileBuffer(LPBYTE byBuffer, DWORD dwStartOffset, DWORD& cbBufSize, DWORD& dwNormalisedBUfSize, CMaxPEFile *m_pMaxPEFile)
{
	DWORD dwBytesToRead = MAX_FILE_READ_BUFFER, dwBytesRead = 0;
	if((dwStartOffset + MAX_FILE_READ_BUFFER) > m_pMaxPEFile->m_dwFileSize)
	{
		dwBytesToRead = m_pMaxPEFile->m_dwFileSize - dwStartOffset;
	}

	if(m_pMaxPEFile->ReadBuffer(byBuffer, dwStartOffset, dwBytesToRead, 0, &dwBytesRead))
	{
		cbBufSize = dwBytesRead;
		dwNormalisedBUfSize = NormalizeBuffer(byBuffer, dwBytesRead);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: NormalizeBuffer
	In Parameters		: LPBYTE byBuffer, DWORD cbBuffer
	Out Parameters		: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Normalizes buffer before scanning
--------------------------------------------------------------------------------------*/
DWORD CMaxELF::NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer)
{
	DWORD dwOut = 0;
	bool bFound = false;
	char arrList[] = {'\t', '\n', '\r', ' ', '\0'};

	if(!byBuffer || !cbBuffer)
	{
		return cbBuffer;
	}

	for(DWORD i = 0; i < cbBuffer; i++)
	{
		bFound = false;
		for(DWORD j = 0; j < sizeof(arrList); j++)
		{
			if(byBuffer[i] == arrList[j])
			{
				bFound = true;
				break;
			}
		}

		if(!bFound)
		{
			byBuffer[dwOut++] = byBuffer[i] >= 'A' && byBuffer[i] <= 'Z'? byBuffer[i] + 32: byBuffer[i];
		}
	}
	return dwOut;
}
