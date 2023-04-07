/*======================================================================================
   FILE				: MaxRTF.cpp
   ABSTRACT			: Supportive class for RTF File Scanner
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
   NOTES			: This module manages the scanning for file tyep RTF. 
   VERSION HISTORY	: 
=====================================================================================*/
#pragma once
#include "pch.h"
#include "MaxRTF.h"

/*-------------------------------------------------------------------------------------
	Function		: CMaxRTF
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CMaxRTF::CMaxRTF()
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CMaxRTF
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CMaxRTF::~CMaxRTF()
{
}

/*-------------------------------------------------------------------------------------
	Function		: IsValidRTFFile
	In Parameters	: CMaxPEFile *m_pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checks for Valid RTF File
--------------------------------------------------------------------------------------*/
bool CMaxRTF::IsValidRTFFile(CMaxPEFile *m_pMaxPEFile)
{
	if(m_pMaxPEFile->m_dwFileSize == 0 || m_pMaxPEFile->m_dwFileSize > MAX_FILE_SIZE_TO_SCAN)
	{
		return false;
	}

	BYTE byCheckHeader[5] = {0};
	if(m_pMaxPEFile->ReadBuffer(byCheckHeader, 0, 5, 5))
	{	
		BYTE RTF_SIG[5] = {0x7B, 0x5C, 0x72, 0x74, 0x66};
		if(memcmp(byCheckHeader, RTF_SIG, sizeof(RTF_SIG)) == 0)
		{
			return true;
		}
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetFileBuffer
	In Parameters	: LPBYTE byBuffer, DWORD dwStartOffset, DWORD& cbBufSize, DWORD& dwNormalisedBUfSize, CMaxPEFile *m_pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Gets scanning binary buffer from RTF File
--------------------------------------------------------------------------------------*/
bool CMaxRTF::GetFileBuffer(LPBYTE byBuffer, DWORD dwStartOffset, DWORD& cbBufSize, DWORD& dwNormalisedBUfSize, CMaxPEFile *m_pMaxPEFile)
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
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Normalizes buffer before scanning
--------------------------------------------------------------------------------------*/
DWORD CMaxRTF::NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer)
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

/*-------------------------------------------------------------------------------------
	Function		: Check4RtfExploitEx
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checks for possible RTF Exploit
--------------------------------------------------------------------------------------*/
bool CMaxRTF::Check4RtfExploitEx(LPBYTE byBuffer, DWORD dwBufferSize,CMaxPEFile *m_pMaxPEFile)
{
	DWORD dwRemainingSize = 0, dwBytesToRead = 0, dwShpOffset = 0;
	bool bShp = false, bSnProperty = false, bSvValue = false;
	
	BYTE snProperty[0xA] = {0x70,0x66,0x72,0x61,0x67,0x6D,0x65,0x6E,0x74,0x73};
	
	BYTE svFirst8Bytes[8][8] = {
		{0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31},
		{0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37},
		{0x34,0x33,0x32,0x31,0x39,0x38,0x37,0x30},
		{0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66},
		{0x61,0x31,0x62,0x32,0x63,0x33,0x64,0x34},
		{0x3B,0x31,0x31,0x31,0x31,0x31,0x31,0x31},
		{0x30,0x31,0x31,0x31,0x31,0x31,0x31,0x31},
		{0x39,0x33,0x32,0x66,0x64,0x30,0x65,0x34}};

	memset(byBuffer, 0, dwBufferSize);
	
	if(m_pMaxPEFile->m_dwFileSize < dwBufferSize)
	{
		dwBytesToRead = m_pMaxPEFile->m_dwFileSize;
		dwRemainingSize = 0;
	}
	else
	{
		dwBytesToRead = dwBufferSize;
		dwRemainingSize = m_pMaxPEFile->m_dwFileSize - (dwBufferSize);
	}

	if(m_pMaxPEFile->ReadBuffer(&byBuffer[0], 0, dwBytesToRead, dwBytesToRead))
	{
		for(DWORD dwIndex = 0;dwIndex < (dwBytesToRead - 5); dwIndex++)
		{
			if((byBuffer[dwIndex + 1] == 0x5C) && (byBuffer[dwIndex + 2] == 0x73) && (byBuffer[dwIndex+3] == 0x68) && (byBuffer[dwIndex + 4] == 0x70))
			{
				dwShpOffset = dwIndex;
				bShp = true;
				break;
			}
		}
		if(bShp == true)
		{
			for(DWORD dwIndex = dwShpOffset; dwIndex < dwBytesToRead - 4; dwIndex++)
			{
				if((byBuffer[dwIndex + 1] == 0x5C) && (byBuffer[dwIndex + 2] == 0x73) && (byBuffer[dwIndex + 3] == 0x76))
				{
					BYTE SemiCount = 0;
					DWORD dwOffset = 0;
					for(dwOffset = dwIndex + 5; (dwOffset < (dwBytesToRead - 0x20)); dwOffset++)
					{
						if((byBuffer[dwOffset] == 0x3B))
						{	
							if(++SemiCount == 2)
							{
								break;
							}							
						}
						else if(byBuffer[dwOffset] == 0x7D)
						{
							break;
						}
					}
					for(dwOffset = dwOffset+1; dwOffset < (dwBytesToRead - 0x10);dwOffset++)
					{
						if(byBuffer[dwOffset] != 0x20)
						{
							break;
						}
					}
					for(DWORD iOffset = dwOffset ;iOffset < (dwOffset+0x10);iOffset++)
					{						
						byBuffer[iOffset] = byBuffer[iOffset] >= 'A' && byBuffer[iOffset] <= 'Z'? byBuffer[iOffset] + 32:byBuffer[iOffset];
					}
					for(int i = 0; i < 8; i++)
					{
						if(memcmp((char *)(&svFirst8Bytes[i][0]), &byBuffer[dwOffset], 8) == 0)
						{	
							bSvValue = true;
							break;
						}
					}					
				}
			}
		}
	}		
	if(!bShp)
	{
		return bShp;
	}

	if(m_pMaxPEFile->m_dwFileSize < dwBufferSize)
	{
		dwBytesToRead = m_pMaxPEFile->m_dwFileSize - dwShpOffset;
		dwRemainingSize = 0;
	}
	else
	{
		dwBytesToRead = dwBufferSize;
		dwRemainingSize = m_pMaxPEFile->m_dwFileSize - (dwBufferSize + dwShpOffset);
	}
	
	memset(byBuffer, 0, sizeof(byBuffer));
	for(DWORD dwIndex = dwShpOffset; dwIndex < m_pMaxPEFile->m_dwFileSize;dwIndex += dwBufferSize)
	{
		if(m_pMaxPEFile->ReadBuffer(&byBuffer[0], dwIndex, dwBytesToRead, dwBytesToRead))
		{
			for(DWORD i =0;i < (dwBytesToRead - 0x30); i++)
			{
				if((byBuffer[i+1] == 0x5C) && (byBuffer[i+2] == 0x73) && (byBuffer[i+3] == 0x6E))
				{
					for(DWORD iOffset = i + 5;iOffset < (i + 0x20) ; iOffset++)
					{
						if(byBuffer[iOffset] == 0x70 || byBuffer[iOffset] == 0x50)
						{
							for(DWORD dwValOffset= iOffset;dwValOffset <  (iOffset + 0xA) ;dwValOffset++)
							{
								byBuffer[dwValOffset] = byBuffer[dwValOffset] >= 'A' && byBuffer[dwValOffset] <= 'Z'? byBuffer[dwValOffset] + 32:byBuffer[dwValOffset];
							}							
							if(memcmp((char *)(&snProperty[0]),&byBuffer[iOffset],0x5) == 0)
							{
								bSnProperty = true;
								break;
							}
						}
					}
					break;
				}						
			}
		}
		if(bSnProperty)
		{
			break;
		}
		dwShpOffset += dwBufferSize;
		if(dwRemainingSize > dwBufferSize)
		{
			dwBytesToRead = dwBufferSize;
			dwRemainingSize -= dwBufferSize;
		}
		else
		{
			dwBytesToRead = dwRemainingSize;
			dwRemainingSize = 0;
		}		
	}
	if(!bSnProperty)
	{
		return bSnProperty;
	}
	if(bSvValue && bSnProperty) 
	{
		return true;
	}	
	return false;	
}