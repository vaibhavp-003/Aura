/*======================================================================================
   FILE				: MACFileScanner.cpp
   ABSTRACT			: Supportive class for MAC File Scanner
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
   NOTES			: This module manages the scanning for file tyep MAC. 
   VERSION HISTORY	: 
=====================================================================================*/
#include "MACFileScanner.h"

/*-------------------------------------------------------------------------------------
	Function		: CMACFileScanner
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CMACFileScanner::CMACFileScanner(CMaxPEFile *pMaxPEFile)
{
	m_pMaxPEFile = pMaxPEFile;
	m_bIsBigEndian = false;
	m_iFileType = MAC_FILE_METADATA;	
	m_pobjLoadCmds = NULL;
	memset(&m_objMACO32,0x00,sizeof(m_objMACO32));
	memset(&m_objMACO64,0x00,sizeof(m_objMACO64));
}

/*-------------------------------------------------------------------------------------
	Function		: ~CMACFileScanner
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CMACFileScanner::~CMACFileScanner(void)
{
	if (m_pobjLoadCmds != NULL)
	{
		DWORD	ulCmd = 0x00;
		switch(m_iFileType)
		{
		case MAC_FILE_OBJ_32:
			{
				ulCmd = m_objMACO32.ncmds;
				
			}
			break;
		case MAC_FILE_OBJ_64:
			{
				ulCmd = m_objMACO64.ncmds;
			}
			break;
		}
		for(DWORD i = 0x00; i < ulCmd; i++)
		{
			free(m_pobjLoadCmds[i]);
		}
		free(m_pobjLoadCmds);
		m_pobjLoadCmds = NULL;
	}
	memset(&m_objMACO32,0x00,sizeof(m_objMACO32));
	memset(&m_objMACO64,0x00,sizeof(m_objMACO64));
}

/*-------------------------------------------------------------------------------------
	Function		: CheckMACMagic
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checks for valid MAC file binary Signature
--------------------------------------------------------------------------------------*/
bool CMACFileScanner::CheckMACMagic()
{
	bool bRet = false;
	unsigned char bMAC_MetaSig[] = {0x00, 0x00, 0x01, 0x00};
	unsigned char bMAC_O_32_LE[] = {0xCE, 0xFA, 0xED, 0xFE};
	unsigned char bMAC_O_64_LE[] = {0xCF, 0xFA, 0xED, 0xFE};
	unsigned char bMAC_O_32_BE[] = {0xFE, 0xED, 0xFA, 0xCE};
	unsigned char bMAC_O_64_BE[] = {0xFE, 0xED, 0xFA, 0xCF};
	unsigned char bMAC_MetaSig2[] = {0x23, 0x21, 0x2F, 0x62, 0x69, 0x6E};
	unsigned char bMAC_MetaSigLarge[] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
	unsigned char bHeaderBuff[0x90] = {0x00};
	m_bIsBigEndian = false;

    DWORD ulBytesRead = 0;
	if(!m_pMaxPEFile->ReadBuffer(bHeaderBuff,0x00, sizeof(bHeaderBuff), sizeof(bHeaderBuff), &ulBytesRead))
    {
        return bRet;
    }
    if(ulBytesRead != sizeof(bHeaderBuff))
    {
        return bRet;
    }
	
    if (memcmp(bHeaderBuff, bMAC_MetaSig, sizeof(bMAC_MetaSig)) == 0)
	{
		m_iFileType = MAC_FILE_METADATA;
		return true;
	}
	if (memcmp(bHeaderBuff, bMAC_MetaSig2, sizeof(bMAC_MetaSig2)) == 0)
	{
		m_iFileType = MAC_FILE_METADATA;
		return true;
	}
	if (memcmp(bHeaderBuff, bMAC_O_32_BE, sizeof(bMAC_O_32_BE)) == 0)
	{
		m_bIsBigEndian = true;
		m_iFileType = MAC_FILE_OBJ_32;
		return true;
	}
	if (memcmp(bHeaderBuff, bMAC_O_64_BE, sizeof(bMAC_O_64_BE)) == 0)
	{
		m_bIsBigEndian = true;
		m_iFileType = MAC_FILE_OBJ_64;
		return true;
	}
	if (memcmp(bHeaderBuff, bMAC_O_32_LE, sizeof(bMAC_O_32_LE)) == 0)
	{
		m_iFileType = MAC_FILE_OBJ_32;
		return true;
	}
	if (memcmp(bHeaderBuff, bMAC_O_64_LE, sizeof(bMAC_O_64_LE)) == 0)
	{
		m_iFileType = MAC_FILE_OBJ_64;
		return true;
	}

	/*for (unsigned int i = 0x00; i < (ulBytesRead - sizeof(bMAC_MetaSigLarge)); i++)
	{
		if (memcmp(&bHeaderBuff[i], bMAC_MetaSigLarge, sizeof(bMAC_MetaSigLarge)) == 0)
		{
			m_iFileType = MAC_FILE_METADATA;
			return true;
		}
	}*/

	if (memcmp(bHeaderBuff, bMAC_MetaSigLarge, sizeof(bMAC_MetaSigLarge)) == 0)
	{
		m_iFileType = MAC_FILE_METADATA;
		return true;
	}

	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: IsValidMACFile
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Validates the MAC file type
--------------------------------------------------------------------------------------*/
bool CMACFileScanner::IsValidMACFile()
{
	bool		bRet = false;
	DWORD		ulBytesRead = 0x00;
	DWORD		ulFileSize = m_pMaxPEFile->m_dwFileSize;
    
	if (ulFileSize <= sizeof(MAC_HEADER_32))
	{
		return bRet;
	}
	if (!CheckMACMagic())
	{
		return bRet;
	}

	switch(m_iFileType)
	{
		case MAC_FILE_OBJ_32:
			{
				//if (!m_pMaxSecureFile->ReadFile(0, (unsigned char *)&m_objMACO32, sizeof(MAC_HEADER_32), &ulBytesRead))
				if (!m_pMaxPEFile->ReadBuffer((unsigned char *)&m_objMACO32, 0x00, sizeof(MAC_HEADER_32), sizeof(MAC_HEADER_32), &ulBytesRead))
				{
					return bRet;
				}
			}
			break;
		case MAC_FILE_OBJ_64:
			{
				if (!m_pMaxPEFile->ReadBuffer((unsigned char *)&m_objMACO64, 0x00, sizeof(m_objMACO64), sizeof(m_objMACO64), &ulBytesRead))
				{
					return bRet;
				}
			}
			break;
	}

	if (m_bIsBigEndian == true)
	{
		ConvertBEHeaderToLE();
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ConvertBEHeaderToLE
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Converts values from Big Ending => Little Ending
--------------------------------------------------------------------------------------*/
bool	CMACFileScanner::ConvertBEHeaderToLE()
{
	switch(m_iFileType)
	{
	case MAC_FILE_OBJ_32:
		{
			//__builtin_bswap32 => _byteswap_ulong
			m_objMACO32.magic = _byteswap_ulong(m_objMACO32.magic);
			m_objMACO32.cputype = _byteswap_ulong(m_objMACO32.cputype);
			m_objMACO32.cpusubtype = _byteswap_ulong(m_objMACO32.cpusubtype);
			m_objMACO32.filetype = _byteswap_ulong(m_objMACO32.filetype);
			m_objMACO32.ncmds = _byteswap_ulong(m_objMACO32.ncmds);
			m_objMACO32.sizeofcmds = _byteswap_ulong(m_objMACO32.sizeofcmds);
			m_objMACO32.flags = _byteswap_ulong(m_objMACO32.flags);
		}
		break;
	case MAC_FILE_OBJ_64:
		{
			m_objMACO64.magic = _byteswap_ulong(m_objMACO64.magic);
			m_objMACO64.cputype = _byteswap_ulong(m_objMACO64.cputype);
			m_objMACO64.cpusubtype = _byteswap_ulong(m_objMACO64.cpusubtype);
			m_objMACO64.filetype = _byteswap_ulong(m_objMACO64.filetype);
			m_objMACO64.ncmds = _byteswap_ulong(m_objMACO64.ncmds);
			m_objMACO64.sizeofcmds = _byteswap_ulong(m_objMACO64.sizeofcmds);
			m_objMACO64.flags = _byteswap_ulong(m_objMACO64.flags);
			m_objMACO64.reserved = _byteswap_ulong(m_objMACO64.reserved);
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ConvertBESegmentToLE
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Converts values from Little Ending ==> Big Ending
--------------------------------------------------------------------------------------*/
bool	CMACFileScanner::ConvertBESegmentToLE(void *pSegCmd)
{
	switch(m_iFileType)
	{
	case MAC_FILE_OBJ_32:
		{
			LPMAC_SEGMENT_COMMAND_32 pTemp = (LPMAC_SEGMENT_COMMAND_32)pSegCmd;
			
			pTemp->cmd = _byteswap_ulong(pTemp->cmd);
			pTemp->cmdsize = _byteswap_ulong(pTemp->cmdsize);
			pTemp->vmaddr = _byteswap_ulong(pTemp->vmaddr);
			pTemp->vmsize = _byteswap_ulong(pTemp->vmsize);
			pTemp->fileoff = _byteswap_ulong(pTemp->fileoff);
			pTemp->filesize = _byteswap_ulong(pTemp->filesize);
			pTemp->maxprot = _byteswap_ulong(pTemp->maxprot);
			pTemp->initprot = _byteswap_ulong(pTemp->initprot);
			pTemp->nsects = _byteswap_ulong(pTemp->nsects);
			pTemp->flags = _byteswap_ulong(pTemp->flags);
		}
		break;
	case MAC_FILE_OBJ_64:
		{
			LPMAC_SEGMENT_COMMAND_64 pTemp = (LPMAC_SEGMENT_COMMAND_64)pSegCmd;
			
			pTemp->cmd = _byteswap_ulong(pTemp->cmd);
			pTemp->cmdsize = _byteswap_ulong(pTemp->cmdsize);
			pTemp->vmaddr = _byteswap_uint64(pTemp->vmaddr);
			pTemp->vmsize = _byteswap_uint64(pTemp->vmsize);
			pTemp->fileoff = _byteswap_uint64(pTemp->fileoff);
			pTemp->filesize = _byteswap_uint64(pTemp->filesize);
			pTemp->maxprot = _byteswap_ulong(pTemp->maxprot);
			pTemp->initprot = _byteswap_ulong(pTemp->initprot);
			pTemp->nsects = _byteswap_ulong(pTemp->nsects);
			pTemp->flags = _byteswap_ulong(pTemp->flags);
		}
		break;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetBuffer
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Get Buffer for Scanning from file type MAC
--------------------------------------------------------------------------------------*/
bool CMACFileScanner::GetBuffer(LPBYTE byBuffer, DWORD& cbBuffer)
{
	bool		bRet = false;
	DWORD		ulBufferSize = 0x00;

	switch(m_iFileType)
	{
	case MAC_FILE_METADATA:
		{
			DWORD ulBytesToRead = m_pMaxPEFile->m_dwFileSize;
			if (ulBytesToRead > MAC_BUFF_SIZE)
			{
				ulBytesToRead = MAC_BUFF_SIZE;
			}
            m_pMaxPEFile->ReadBuffer(byBuffer, 0x00, ulBytesToRead, ulBytesToRead, &ulBufferSize);        
		}
		break;
	case MAC_FILE_OBJ_32:
		{
			if (!GetMAC32FileBuffer(byBuffer, cbBuffer))
			{
				return bRet;
			}
			
		}
		break;
	case MAC_FILE_OBJ_64:
		{
			if (!GetMAC64FileBuffer(byBuffer, cbBuffer))
			{
				return bRet;
			}
		}
	}

	return true;
}


/*-------------------------------------------------------------------------------------
	Function		: GetMACHeaderStruct
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Loads Binary header for file type MAC
--------------------------------------------------------------------------------------*/
bool CMACFileScanner::GetMACHeaderStruct()
{
	bool		bRet = false;
	DWORD		ulNoofCMDS = 0x00, ulCmd = 0x00, ulSize = 0x00, ulOffSet = 0x00, ulBytesRead = 0x00;

	switch(m_iFileType)
	{
	case MAC_FILE_OBJ_32:
		{
			ulNoofCMDS = m_objMACO32.ncmds;
			ulOffSet = sizeof(MAC_HEADER_32);
		}
		break;
	case MAC_FILE_OBJ_64:
		{
			ulNoofCMDS = m_objMACO64.ncmds;
			ulOffSet = sizeof(MAC_HEADER_64);
		}
		break;
	}

	
	m_pobjLoadCmds = (LPMAC_LOAD_COMMAND *)calloc(ulNoofCMDS,sizeof(LPMAC_LOAD_COMMAND));
	if (m_pobjLoadCmds == NULL)
	{
		return bRet;
	}

	
	for(DWORD i = 0x00; i < ulNoofCMDS; i++)
	{
		m_pobjLoadCmds[i] = (LPMAC_LOAD_COMMAND)calloc(0x01,sizeof(MAC_LOAD_COMMAND));

		m_pMaxPEFile->ReadBuffer((unsigned char *)&ulCmd, ulOffSet, sizeof(DWORD), sizeof(DWORD), &ulBytesRead);
		m_pMaxPEFile->ReadBuffer((unsigned char *)&ulSize, (ulOffSet + sizeof(DWORD)), sizeof(DWORD), sizeof(DWORD), &ulBytesRead);
		if (m_bIsBigEndian == true)
		{
			ulCmd = _byteswap_ulong(ulCmd);
			ulSize = _byteswap_ulong(ulSize);
		}
		ulOffSet+=ulSize;
		m_pobjLoadCmds[i]->cmd = ulCmd;
		m_pobjLoadCmds[i]->cmdsize = ulSize;
		m_pobjLoadCmds[i]->offset = ulOffSet;
	}

	return true;
}
/*-------------------------------------------------------------------------------------
	Function		: GetMAC32FileBuffer
	In Parameters	: unsigned char *byBuffer, DWORD &cbBuffer
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Get MAC File Buffer for 32Bit
--------------------------------------------------------------------------------------*/ 
bool CMACFileScanner::GetMAC32FileBuffer(unsigned char *byBuffer, DWORD &cbBuffer)
{
	bool					bRet = false;
	MAC_SEGMENT_COMMAND_32	objSegCmd = {0x00};
	DWORD					ulBytesRead = 0x00, ulOffSet = 0x00;

	cbBuffer = 0x00;

	if (!GetMACHeaderStruct())
	{
		return bRet;
	}

	m_ulTextSecOffSet = 0x00;
	m_ulTextSecSize = 0x00;
	m_ulStringSecStart = 0x00;
	m_ulStringSecSize = 0x00;
	
	for (DWORD i = 0x00; i < m_objMACO32.ncmds; i++)
	{
		if (m_pobjLoadCmds[i]->cmd != 0x01)
		{
			continue;
		}
		m_pMaxPEFile->ReadBuffer((unsigned char *)&objSegCmd, m_pobjLoadCmds[i]->offset, sizeof(MAC_SEGMENT_COMMAND_32), sizeof(MAC_SEGMENT_COMMAND_32), &ulBytesRead);
		ulOffSet = m_pobjLoadCmds[i]->offset + ulBytesRead;
		if ((strstr(objSegCmd.segname,"__TEXT") != NULL) /*|| (strstr(objSegCmd.segname,"__DATA") != NULL)*/)
		{
			if (true== m_bIsBigEndian)
			{
				ConvertBESegmentToLE((void *)&objSegCmd);
			}
			LPMAC_SECTION_32	pSecArray = NULL;
			pSecArray = (LPMAC_SECTION_32)calloc(objSegCmd.nsects,sizeof(MAC_SECTION_32));
			//m_pMaxSecureFile->ReadFile(ulOffSet, (unsigned char *)&pSecArray[0x00], (objSegCmd.nsects * sizeof(MAC_SEGMENT_COMMAND_32)), &ulBytesRead);
			m_pMaxPEFile->ReadBuffer((unsigned char *)&pSecArray[0x00], ulOffSet, (objSegCmd.nsects * sizeof(MAC_SECTION_32)), (objSegCmd.nsects * sizeof(MAC_SECTION_32)), &ulBytesRead);
			for(DWORD j = 0x00; j < objSegCmd.nsects; j++)
			{
				if (strstr(pSecArray[j].sectname,"__text") != NULL)
				{
					m_ulTextSecOffSet = ((m_bIsBigEndian) ? _byteswap_ulong(pSecArray[j].offset) : pSecArray[j].offset);
					m_ulTextSecSize = ((m_bIsBigEndian) ? _byteswap_ulong(pSecArray[j].size) : pSecArray[j].size);
				}
				if (strstr(pSecArray[j].sectname,"__cstring") != NULL)
				{
					m_ulStringSecStart = ((m_bIsBigEndian) ? _byteswap_ulong(pSecArray[j].offset) : pSecArray[j].offset);
					m_ulStringSecSize = ((m_bIsBigEndian) ? _byteswap_ulong(pSecArray[j].size) : pSecArray[j].size);
				}
				if (m_ulTextSecOffSet > 0x00 && m_ulStringSecStart > 0x00)
				{
					break;
				}
			}
			if (pSecArray != NULL)
			{
				free(pSecArray);
				pSecArray = NULL;
			}
		}
		if (m_ulTextSecOffSet > 0x00 && m_ulStringSecStart > 0x00)
		{
			break;
		}

	}

	//Tushar --> Reding Buffer frm above addresses.
	DWORD	ulBytes2Read = 0x7800, ulFileSize = 0x00;

	ulBytesRead = 0x00;
	ulFileSize  = m_pMaxPEFile->m_dwFileSize;	
	//1 : _TEXT : __text
	if (m_ulTextSecSize < 0x7800)
	{
		if ((m_ulTextSecOffSet + m_ulTextSecSize) >= ulFileSize)
		{
			ulBytes2Read = (ulFileSize - m_ulTextSecOffSet);
		}
		else
		{
			ulBytes2Read = m_ulTextSecSize;
		}
	}
	if (m_ulTextSecOffSet > ulFileSize)
	{
		return bRet;
	}
	m_pMaxPEFile->ReadBuffer(&byBuffer[0x00], m_ulTextSecOffSet, ulBytes2Read, ulBytes2Read, &ulBytesRead);
	cbBuffer = ulBytesRead;

	//2 : _TEXT : __cstring
	ulBytesRead = 0x00;
	ulBytes2Read = 0x1000;
	if (m_ulStringSecSize < 0x1000)
	{
		ulBytes2Read = m_ulStringSecSize;
	}
	
	m_pMaxPEFile->ReadBuffer(&byBuffer[cbBuffer], m_ulStringSecStart, ulBytes2Read, ulBytes2Read, &ulBytesRead);
	cbBuffer += ulBytesRead;


	if (cbBuffer == 0x00)
	{
		ulBytesRead = 0x00;
		if (ulFileSize < 0x8C00)
			ulBytes2Read = ulFileSize;
		else
			ulBytes2Read = 0x8C00;
		
		m_pMaxPEFile->ReadBuffer(&byBuffer[cbBuffer], 0x00, ulBytes2Read, ulBytes2Read, &ulBytesRead);
		cbBuffer += ulBytesRead;
		return true;
	}

	//3 : MAC Header Part
	ulBytesRead = 0x00;
	ulBytes2Read = 0x400;
	
	m_pMaxPEFile->ReadBuffer(&byBuffer[cbBuffer], 0x00, ulBytes2Read, ulBytes2Read, &ulBytesRead);
	cbBuffer += ulBytesRead;

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetMAC64FileBuffer
	In Parameters	: unsigned char *byBuffer, DWORD &cbBuffer
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Get MAC File Buffer for 64Bit
--------------------------------------------------------------------------------------*/
bool CMACFileScanner::GetMAC64FileBuffer(unsigned char *byBuffer, DWORD &cbBuffer)
{
	bool					bRet = false;
	MAC_SEGMENT_COMMAND_64	objSegCmd = {0x00};
	DWORD					ulBytesRead = 0x00, ulOffSet = 0x00;

	cbBuffer = 0x00;

	if (!GetMACHeaderStruct())
	{
		return bRet;
	}

	m_ulTextSecOffSet = 0x00;
	m_ulStringSecStart = 0x00;
	m_ulStringSecSize = 0x00;
	m_ulTextSecSize = 0x00;
	
	for (DWORD i = 0x00; i < m_objMACO64.ncmds; i++)
	{
		if (m_pobjLoadCmds[i]->cmd != 0x19)
		{
			continue;
		}
		m_pMaxPEFile->ReadBuffer((unsigned char *)&objSegCmd, m_pobjLoadCmds[i]->offset, sizeof(MAC_SEGMENT_COMMAND_64), sizeof(MAC_SEGMENT_COMMAND_64), &ulBytesRead);
		ulOffSet = m_pobjLoadCmds[i]->offset + ulBytesRead;
		if ((strstr(objSegCmd.segname,"__TEXT") != NULL) /*|| (strstr(objSegCmd.segname,"__DATA") != NULL)*/)
		{
			if (true== m_bIsBigEndian)
			{
				ConvertBESegmentToLE((void *)&objSegCmd);
			}
			LPMAC_SECTION_64	pSecArray = NULL;
			pSecArray = (LPMAC_SECTION_64)calloc(objSegCmd.nsects,sizeof(MAC_SECTION_64));

			m_pMaxPEFile->ReadBuffer((unsigned char *)&pSecArray[0x00], ulOffSet, (objSegCmd.nsects * sizeof(MAC_SECTION_64)), (objSegCmd.nsects * sizeof(MAC_SECTION_64)), &ulBytesRead);
			for(DWORD j = 0x00; j < objSegCmd.nsects; j++)
			{
				if (strstr(pSecArray[j].sectname,"__text") != NULL)
				{
					m_ulTextSecOffSet = ((m_bIsBigEndian) ? _byteswap_ulong(pSecArray[j].offset) : pSecArray[j].offset);
					m_ulTextSecSize = ((m_bIsBigEndian) ? _byteswap_uint64(pSecArray[j].size) : pSecArray[j].size);
				}
				if (strstr(pSecArray[j].sectname,"__cstring") != NULL)
				{
					m_ulStringSecStart = ((m_bIsBigEndian) ? _byteswap_ulong(pSecArray[j].offset) : pSecArray[j].offset);
					m_ulStringSecSize = ((m_bIsBigEndian) ? _byteswap_uint64(pSecArray[j].size) : pSecArray[j].size);
				}
				if (m_ulTextSecOffSet > 0x00 && m_ulStringSecStart > 0x00)
				{
					break;
				}
			}
			if (pSecArray != NULL)
			{
				free(pSecArray);
				pSecArray = NULL;
			}
		}
		if (m_ulTextSecOffSet > 0x00 && m_ulStringSecStart > 0x00)
		{
			break;
		}

	}

	//Tushar --> Reding Buffer frm above addresses.
	DWORD	ulBytes2Read = 0x7800;
    
	ulBytesRead = 0x00;
	DWORD ulFileSize  = m_pMaxPEFile->m_dwFileSize;
	//1 : _TEXT : __text
	if (m_ulTextSecSize < 0x7800)
	{
		if ((m_ulTextSecOffSet + m_ulTextSecSize) >= ulFileSize)
		{
			ulBytes2Read = (ulFileSize - m_ulTextSecOffSet);
		}
		else
		{
			ulBytes2Read = m_ulTextSecSize;
		}
	}
	if (m_ulTextSecOffSet > ulFileSize)
	{
		return bRet;
	}
	m_pMaxPEFile->ReadBuffer( &byBuffer[0x00], m_ulTextSecOffSet, ulBytes2Read, ulBytes2Read, &ulBytesRead);
	cbBuffer = ulBytesRead;

	//2 : _TEXT : __cstring
	ulBytesRead = 0x00;
	ulBytes2Read = 0x2000;
	if (m_ulStringSecSize < 0x1000)
	{
		ulBytes2Read = m_ulStringSecSize;
	}
	
	m_pMaxPEFile->ReadBuffer(&byBuffer[cbBuffer], m_ulStringSecStart, ulBytes2Read, ulBytes2Read, &ulBytesRead);
	cbBuffer += ulBytesRead;

	if (cbBuffer == 0x00)
	{
		ulBytesRead = 0x00;
		if (ulFileSize < 0x8C00)
			ulBytes2Read = ulFileSize;
		else
			ulBytes2Read = 0x8C00;
		
		m_pMaxPEFile->ReadBuffer(&byBuffer[cbBuffer], 0x00, ulBytes2Read, ulBytes2Read, &ulBytesRead);
		cbBuffer += ulBytesRead;
		return true;
	}


	//3 : MAC Header Part
	ulBytesRead = 0x00;
	ulBytes2Read = 0x400;
	
	m_pMaxPEFile->ReadBuffer(&byBuffer[cbBuffer], 0x00, ulBytes2Read, ulBytes2Read, &ulBytesRead);
	cbBuffer += ulBytesRead;

	return true;
}