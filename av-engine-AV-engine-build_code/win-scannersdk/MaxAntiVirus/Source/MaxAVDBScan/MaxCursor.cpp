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
#pragma once
#include "pch.h"
#include "MaxCursor.h"

/*-------------------------------------------------------------------------------------
	Function		: CMaxCursor
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CMaxCursor::CMaxCursor()
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CMaxCursor
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CMaxCursor::~CMaxCursor()
{
}

/*-------------------------------------------------------------------------------------
	Function		: IsValidICONFile
	In Parameters	: MaxPEFile Object
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checking for Valid ICON File 
--------------------------------------------------------------------------------------*/
bool CMaxCursor::IsValidICONFile(CMaxPEFile *pMaxPEFile)
{
	m_dwReadOffset = 0;

	if(pMaxPEFile->m_dwFileSize == 0 || pMaxPEFile->m_dwFileSize > MAX_FILE_SIZE_TO_SCAN)
	{
		return false;
	}

	TCHAR *szExt =_tcsrchr(pMaxPEFile->m_szFilePath, _T('.'));
	if(szExt)
	{
		_tcsupr_s(szExt, _tcslen(szExt) + 1);
		if(_tcsstr(szExt,_T(".ICO")) != NULL || _tcsstr(szExt,_T(".CUR")) != NULL )
		{
			unsigned char	szHeader[0x15] = {0};
			unsigned char	szICHeader[] = {0x00, 0x00};
			unsigned char	szICOHeader[] = {0x01, 0x00};
			unsigned char	szCURHeader[] = {0x02, 0x00};

			if(pMaxPEFile->ReadBuffer(szHeader, 0x00, 0x10, 0x10))
			{
				if (memcmp(&szHeader[0x00], &szICHeader[0], sizeof(szICHeader)) == 0  && 
					(memcmp(&szHeader[0x02], &szICOHeader[0], sizeof(szICOHeader)) == 0 || memcmp(&szHeader[0x02], &szCURHeader[0], sizeof(szCURHeader)) == 0) &&
					*(WORD *)&szHeader[0x6] != 0x00 && *(DWORD *)&szHeader[0xE] != 0x00)
				{
					return true;
				}
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetICONBuffer
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer, DWORD& cbBufSize, int iIndex, CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Gets buffer from ICON File 
--------------------------------------------------------------------------------------*/
bool CMaxCursor::GetICONBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD& cbBufSize, int iIndex, CMaxPEFile *pMaxPEFile)
{
	if(MAX_FILE_SIZE_TO_SCAN > (pMaxPEFile->m_dwFileSize - m_dwReadOffset) && m_dwReadOffset <= pMaxPEFile->m_dwFileSize)
	{		
		DWORD dwBytesRead = 0;
		if(pMaxPEFile->ReadBuffer(byBuffer, m_dwReadOffset, MAX_FILE_READ_BUFFER, 0, &dwBytesRead))
		{			
			cbBufSize = dwBytesRead;
			NormalizeBuffer(byBuffer, dwBytesRead);
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
	Description		: Normalize buffer rea from file to lower case
--------------------------------------------------------------------------------------*/
DWORD CMaxCursor::NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer)
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

/*-------------------------------------------------------------------------------------
	Function		: IsValidANIFile
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checks for Valid ANI (Animation) File type
--------------------------------------------------------------------------------------*/
bool CMaxCursor::IsValidANIFile(CMaxPEFile *pMaxPEFile)
{
	bool bRet = false;
	RIFF_ANI_FILE  stRiffFile = {0};
	m_dwReadBuffOffset = m_dwReadOffset = 0;
	
	if(!pMaxPEFile->ReadBuffer(&stRiffFile, 0, sizeof(stRiffFile), sizeof(stRiffFile)))
	{
		return bRet;
	}

	if(stRiffFile.FormID== 0x4E4F4341 && stRiffFile.FileId == 0x46464952)//ACON && RIFF
	{
		m_dwReadOffset = sizeof(stRiffFile);
		return true;
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
	Function		: IsExploitANI
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checks for possibel exploit in ANI (Animation) File type
--------------------------------------------------------------------------------------*/
bool CMaxCursor::IsExploitANI(CMaxPEFile *pMaxPEFile)
{
	if(pMaxPEFile->m_dwFileSize == 0 || pMaxPEFile->m_dwFileSize > MAX_FILE_SIZE_TO_SCAN)
	{
		return false;
	}
	DWORD dwBytesRead = 0;
	BYTE pbyBuff[0x200] = {0};	
	ANI_CHUNK stAniChunk = {0};

	while(1)
	{
		m_dwReadOffset += dwBytesRead ;
		if(m_dwReadOffset >= pMaxPEFile->m_dwFileSize)
		{
			break;
		}
		if(pMaxPEFile->ReadBuffer(&stAniChunk, m_dwReadOffset, sizeof(stAniChunk), sizeof(stAniChunk)))
		{

			switch (stAniChunk.ChunkID)
			{
			case 0x20716573://seq
				{
					SEQUENCE stSequence = {0};
					if(pMaxPEFile->ReadBuffer(&stSequence, m_dwReadOffset, sizeof(stSequence), sizeof(stSequence)))
					{
						if(stSequence.Size > pMaxPEFile->m_dwFileSize || stSequence.Size > 0x200)
						{
							return false;
						}
						else if(pMaxPEFile->ReadBuffer(pbyBuff, m_dwReadOffset, stSequence.Size, 0, &dwBytesRead))
						{
							if(CheckExploit(pbyBuff,dwBytesRead))
							{
								return true;
							}
							dwBytesRead += 8; 
						}
					}
				}
				break;
			case 0x5453494c://LIST
				{
					if(stAniChunk.SubChunk == 0x4f464e49)//INFO
					{
						LIST_INFO stListInfo = {0};
						if(pMaxPEFile->ReadBuffer(&stListInfo, m_dwReadOffset, sizeof(stListInfo), sizeof(stListInfo)))
						{
							if(stListInfo.ListSize > pMaxPEFile->m_dwFileSize || stListInfo.ListSize > 0x200)
							{
								return false;
							}
							else if(pMaxPEFile->ReadBuffer(pbyBuff, m_dwReadOffset, stListInfo.ListSize, 0, &dwBytesRead))
							{

								if(CheckExploit(pbyBuff,dwBytesRead))
								{
									return true;
								}
								dwBytesRead += 8; 
							}
						}
					}
					else if(stAniChunk.SubChunk == 0x6d617266)//fram
					{
						LIST_FRAME stListfram = {0};
						if(pMaxPEFile->ReadBuffer(&stListfram, m_dwReadOffset, sizeof(stListfram), sizeof(stListfram)))
						{
							dwBytesRead = stListfram.ListSize + 8; 
							m_dwReadBuffOffset = m_dwReadOffset;
						}
					}
					else
					{
						dwBytesRead = 4;
					}
				}
				break;
			case 0x65746172://rate
				{
					RATE stRate = {0};
					if(pMaxPEFile->ReadBuffer(&stRate, m_dwReadOffset, sizeof(stRate), sizeof(stRate)))
					{
						if(stRate.Size > pMaxPEFile->m_dwFileSize || stRate.Size > 0x200)
						{
							return false;
						}
						else if(pMaxPEFile->ReadBuffer(pbyBuff, m_dwReadOffset, stRate.Size, 0, &dwBytesRead))
						{
							if(CheckExploit(pbyBuff,dwBytesRead))
							{
								return true;
							}
							dwBytesRead += 8; 
						}
					}
				}
				break;
			case 0x68696e61://anih
				{
					ANI_HEADER stAniHeader = {0};
					if(pMaxPEFile->ReadBuffer(&stAniHeader, m_dwReadOffset, sizeof(stAniHeader), sizeof(stAniHeader)))
					{
						if(stAniHeader.Size != 0x24)
						{
							return true;
						}
						else if(stAniHeader.Size > pMaxPEFile->m_dwFileSize || stAniHeader.Size > 0x200)
						{
							return false;
						}
						else if(pMaxPEFile->ReadBuffer(pbyBuff, m_dwReadOffset, stAniHeader.Size, 0, &dwBytesRead))
						{
							if(CheckExploit(pbyBuff,dwBytesRead))
							{
								return true;
							}
							dwBytesRead += 8; 
						}
					}
				}
				break;
			case 0x4C495354://TSIL
				return true;
			default:
				dwBytesRead = 4;
				break;
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckExploit
	In Parameters	: LPBYTE byBuffer, DWORD dwNoOfBytes
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checks for possibel exploit in ANI (Animation) File type
--------------------------------------------------------------------------------------*/
bool CMaxCursor::CheckExploit(LPBYTE byBuffer, DWORD dwNoOfBytes)
{
	for(DWORD i = 0; i < dwNoOfBytes; i++ )
	{
		if((*(DWORD *)&byBuffer[i]== 0x68696e61 && byBuffer[i+4] != 0x24) || (*(DWORD *)&byBuffer[i]== 0x4C495354))//TSIL
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetANIBuffer
	In Parameters	: LPBYTE byBuffer, DWORD& cbBufSize, CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Retrievs buffer from ANI file
--------------------------------------------------------------------------------------*/
bool CMaxCursor::GetANIBuffer(LPBYTE byBuffer, DWORD& cbBufSize, CMaxPEFile *pMaxPEFile)
{
	if(m_dwReadBuffOffset < pMaxPEFile->m_dwFileSize)
	{
		DWORD dwBytesRead = 0;
		if(!pMaxPEFile->ReadBuffer(byBuffer, m_dwReadBuffOffset, MAX_FILE_READ_BUFFER, 0, &dwBytesRead))
		{
			return false;
		}

		if(0 == dwBytesRead)
		{
			m_dwReadOffset = pMaxPEFile->m_dwFileSize;
			return false;
		}

		m_dwReadBuffOffset += dwBytesRead;
		cbBufSize = dwBytesRead;
		return true;
	}	
	return false;

}