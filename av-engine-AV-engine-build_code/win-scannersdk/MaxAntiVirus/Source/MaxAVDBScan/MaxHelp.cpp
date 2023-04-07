/*======================================================================================
   FILE				: MaxHelp.cpp
   ABSTRACT			: Supportive class for CHM File Scanner
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
   NOTES			: This module manages the scanning for file tyep CHM (Help File). 
   VERSION HISTORY	: 
=====================================================================================*/
#pragma once
#include "pch.h"
#include "MaxHelp.h"

/*-------------------------------------------------------------------------------------
	Function		: CMaxHelp
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CMaxHelp::CMaxHelp()
{
	m_dwReadOffset = 0;
	m_dwReadDIROffset = 0;
	m_dwDIRSize = 0;
	m_dwTotalFileSize=0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CMaxHelp
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CMaxHelp::~CMaxHelp()
{
}

/*-------------------------------------------------------------------------------------
Function		: IsValidHelpFile
Out Parameters	: Return true if Valid Help File else return false
Purpose			: To find this is valid help file or not
Author			: Prajakta 
--------------------------------------------------------------------------------------*/
bool CMaxHelp::IsValidHelpFile(CMaxPEFile *pMaxPEFile)
{
	if(pMaxPEFile->m_dwFileSize == 0 || pMaxPEFile->m_dwFileSize > MAX_FILE_SIZE_TO_SCAN)
	{
		return false;
	}
	
	unsigned char	szHLPHeader[0x16] = {0};
	unsigned char	szMGHeader[] = {0x3F,0x5F,0x03,0x00};
	unsigned char	szIDMGHeader[] = {0x3B,0x29};
	m_dwReadOffset=0;

	if(pMaxPEFile->ReadBuffer(szHLPHeader, 0x00, 0x15, 0x15))
	{
		if (memcmp(&szHLPHeader[0x00], &szMGHeader[0], sizeof(szMGHeader)) == 0 &&
			*(DWORD *)&szHLPHeader[0x4] != 0x00 && *(DWORD *)&szHLPHeader[0x4] < pMaxPEFile->m_dwFileSize && 
			*(DWORD *)&szHLPHeader[0xC] != 0x00 && *(DWORD *)&szHLPHeader[0xC] <= pMaxPEFile->m_dwFileSize)
		{
			m_dwReadDIROffset = *(DWORD *)&szHLPHeader[0x4];
			m_dwTotalFileSize = *(DWORD *)&szHLPHeader[0xC];
			if(pMaxPEFile->ReadBuffer(szHLPHeader, m_dwReadDIROffset, 0x10, 0x10))
			{
				if(*(DWORD *)&szHLPHeader[0x0] != 0x00 && *(DWORD *)&szHLPHeader[0x0] <= pMaxPEFile->m_dwFileSize && 
					*(DWORD *)&szHLPHeader[0x4] != 0x00 && *(DWORD *)&szHLPHeader[0x4] <= pMaxPEFile->m_dwFileSize &&
					memcmp(&szHLPHeader[0x09], &szIDMGHeader[0], sizeof(szIDMGHeader)) == 0)
				{
					m_dwDIRSize = *(DWORD *)&szHLPHeader[0x0];
					if(m_dwDIRSize > MAX_FILE_READ_BUFFER)
					{
						m_dwDIRSize = MAX_FILE_READ_BUFFER;
					}
					return true;
				}
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: IsExploitHelp
Out Parameters	: Return value
				  1 For Corrupt File
				  2 For Repair File
				  0 For Non Detected
Purpose			: To find the Currupt Help (.hlp) File and Offset to pick up buffer for scanning.
Author			: Prajakta 
--------------------------------------------------------------------------------------*/
bool CMaxHelp::TraverseDirectoy(LPBYTE byBuffer, CMaxPEFile *pMaxPEFile)
{
	bool bRet = false;
	if(!pMaxPEFile->ReadBuffer(byBuffer, m_dwReadDIROffset, m_dwDIRSize, m_dwDIRSize))
	{
		return bRet;
	}
	if(m_dwReadDIROffset + m_dwDIRSize > pMaxPEFile->m_dwFileSize || m_dwTotalFileSize == 0 || m_dwTotalFileSize > pMaxPEFile->m_dwFileSize)
	{
		return bRet;
	}
	if(!(*(WORD *)&byBuffer[0x1F] == 0x0000 && *(WORD *)&byBuffer[0x25] == 0xFFFF))
	{	
		return bRet;
	}
	DWORD dwEntriesCnt = *(DWORD *)&byBuffer[0x2B];
	if(dwEntriesCnt > 0x4000)
	{
		dwEntriesCnt =  0x4000;
	}

	DWORD i = 0x37, dwCounter = 1;
	m_dwReadOffset = 0;
	while(i < m_dwDIRSize &&  dwCounter <= dwEntriesCnt)
	{
		if(byBuffer[i] == 0x00)
		{	
			if(m_dwReadOffset < *(DWORD *)&byBuffer[i + 0x1])
			{
				m_dwReadOffset = *(DWORD *)&byBuffer[i + 0x1];
			}
			i += 4;
			dwCounter++;
		}
		i++;
	}
	if(m_dwReadOffset != 0 && m_dwReadOffset < pMaxPEFile->m_dwFileSize)
	{			
		bRet = true;
	}		
	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: GetHelpBuffer
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer, DWORD& cbBufSize, int iIndex,CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Get scan buffer from CHM File
--------------------------------------------------------------------------------------*/
bool CMaxHelp::GetHelpBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD& cbBufSize, int iIndex,CMaxPEFile *pMaxPEFile)
{
	if(MAX_FILE_SIZE_TO_SCAN > (pMaxPEFile->m_dwFileSize - m_dwReadOffset) && m_dwReadOffset <= pMaxPEFile->m_dwFileSize)
	{	
		DWORD dwBytesRead = 0;
		if(pMaxPEFile->ReadBuffer(byBuffer, m_dwReadOffset, MAX_FILE_READ_BUFFER, 0, &dwBytesRead))
		{			
			cbBufSize = dwBytesRead;
			dwNormalisedBufSize = NormalizeBuffer(byBuffer, dwBytesRead);
			m_dwReadOffset += dwBytesRead;
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: NormalizeBuffer
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Normalize buffer for Text scanning
--------------------------------------------------------------------------------------*/
DWORD CMaxHelp::NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer)
{
	DWORD dwOut = 0;
	bool bFound = false;
	char arrList[] = {'\t', '\n', '\r', ' ', '\0','.','0'};

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
	return true;
}
