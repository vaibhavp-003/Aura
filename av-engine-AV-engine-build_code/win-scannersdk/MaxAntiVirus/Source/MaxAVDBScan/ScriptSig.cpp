/*======================================================================================
   FILE				: ScriptSig.cpp
   ABSTRACT			: Supportive class for Script File Scanner
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
   NOTES			: This module manages the scanning for file tyep Script (.html, .asp, .js). 
   VERSION HISTORY	: 
=====================================================================================*/
#include "pch.h"
#include "ScriptSig.h"

LPCSTR g_szHdrTags1[] =
{
	"<html",
	"</html>",
	"<?php",
	"<script",
	"<iframe",
	"<!doctype",
	"wscript.sh",
	"vbscript",
	"<object",
	"<applet",
	"<?xml",
	"<assembly",
	"<?php",
	"<head",
	"<body",
	"href",
	"png",
	"execute(",
	"var"
};

LPCSTR g_szHdrTags2[] =
{
	"dim",
	"xml",
	"response",
	"execute",
	"replace",
	"vbscript",
	"var"
};

/*-------------------------------------------------------------------------------------
	Function		: CScriptSig
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CScriptSig::CScriptSig()
{
	m_byReadBuffer = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_FILE_READ_BUFFER);
	m_byReadEndBuffer=(LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_FILE_END_READ_BUFFER);
	ResetMemberVariables();

	m_dwEscapeChrCnt = 0x00;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CScriptSig
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CScriptSig::~CScriptSig()
{
	if(m_byReadBuffer)
	{
		HeapFree(GetProcessHeap(), 0, m_byReadBuffer);
	}
	if(m_byReadEndBuffer)
	{
		HeapFree(GetProcessHeap(), 0, m_byReadEndBuffer);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: ResetMemberVariables
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Internal Function 
	Author			: Tushar Kadam
	Description		: Initializes memory of all required structures
--------------------------------------------------------------------------------------*/
void CScriptSig::ResetMemberVariables()
{
	if(m_byReadBuffer)
	{
		memset(m_byReadBuffer, 0, MAX_FILE_READ_BUFFER);
		m_cbReadBuffer = MAX_FILE_READ_BUFFER;
	}
	else
	{
		m_cbReadBuffer = 0;
	}  
	if(m_byReadEndBuffer)
	{
		memset(m_byReadEndBuffer, 0, MAX_FILE_END_READ_BUFFER);
		m_cbReadBuffer1 = MAX_FILE_END_READ_BUFFER;

	}
	else
	{
		m_cbReadBuffer1 = 0;
	} 
	
	m_dwTotalBytesRead = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: NormalizeBuffer
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer
	Out Parameters	: 
	Purpose			: Internal Function 
	Author			: Tushar Kadam
	Description		: Normalize text based buffer for scanning
--------------------------------------------------------------------------------------*/
DWORD CScriptSig::NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer)
{
	DWORD dwOut = 0;
	bool bFound = false;
	char arrList[] = {'\t', '\n', '\r', ' ', '\0'};

	if(!byBuffer || !cbBuffer)
	{
		return cbBuffer;
	}

	m_dwEscapeChrCnt = 0x00;
	for(DWORD i = 0; i < cbBuffer; i++)
	{
		bFound = false;
		for(DWORD j = 0; j < sizeof(arrList); j++)
		{
			if(byBuffer[i] == arrList[j])
			{
				if (byBuffer[i] != ' ')
				{
					m_dwEscapeChrCnt++;
				}
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
	Function		: MemStr
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer, LPCSTR bySubStr, DWORD cbSubStr
	Out Parameters	: LPBYTE : Buffer pointer
	Purpose			: Internal Function 
	Author			: Tushar Kadam
	Description		: searches string pattern in input buffer
--------------------------------------------------------------------------------------*/
LPBYTE CScriptSig::MemStr(LPBYTE byBuffer, DWORD cbBuffer, LPCSTR bySubStr, DWORD cbSubStr)
{
	bool bFound = false;
	DWORD i = 0;

	if(cbBuffer < cbSubStr)
	{
		return NULL;
	}

	for(i = 0; i <= cbBuffer - cbSubStr; i++)
	{
		bFound = true;
		for(DWORD j = 0, k = i; j < cbSubStr; j++, k++)
		{
			if(byBuffer[k] != bySubStr[j])
			{
				bFound = false;
				break;
			}
		}

		if(bFound)
		{
			break;
		}
	}

	return bFound? byBuffer + i: NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: IsValidScriptExtension
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: bool : true if valid script file else false
	Purpose			: Internal Function 
	Author			: Tushar Kadam
	Description		: Determine whether input file has script extension
--------------------------------------------------------------------------------------*/
bool CScriptSig::IsValidScriptExtension(CMaxPEFile *pMaxPEFile)
{
	TCHAR		szFilePath[1024] = {0x00};
	TCHAR		szFileExt[1024] = {0x00};
	TCHAR		*pTemp = NULL;

	if (pMaxPEFile == NULL)
	{
		return false;
	}

	_stprintf(szFilePath,L"%s", pMaxPEFile->m_szFilePath);
	
	pTemp = _tcsrchr(szFilePath,L'.');
	if (pTemp == NULL)
	{
		return false;
	}

	if (_tcslen(pTemp) >= 1024)
	{
		return false;
	}

	_tcscpy(szFileExt,pTemp);
	_tcslwr(szFileExt);

	if (_tcsstr(L".vbs,.html,.js",szFileExt) != NULL)
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsItValidScript
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: bool : true if valid script file else false
	Purpose			: Internal Function 
	Author			: Tushar Kadam
	Description		: Determine whether input file is script file or not
--------------------------------------------------------------------------------------*/
bool CScriptSig::IsItValidScript(CMaxPEFile *pMaxPEFile)
{
	ULONG64 ulFileSize = 0;
	DWORD dwSizeLow = 0, dwSizeHigh = 0;
	bool bValid = false;

	ResetMemberVariables();
	if(!m_byReadBuffer || !m_cbReadBuffer)
	{
		return bValid;
	}

	if(pMaxPEFile->m_dwFileSize == 0 || pMaxPEFile->m_dwFileSize > MAX_FILE_SIZE_TO_SCAN)
	{
		return bValid;
	}

	if (IsValidScriptExtension(pMaxPEFile))
	{
		return true;
	}

	if(!pMaxPEFile->ReadBuffer(m_byReadBuffer, 0, m_cbReadBuffer, 0, &m_dwTotalBytesRead))
	{
		return bValid;
	}

	m_cbReadBuffer = NormalizeBuffer(m_byReadBuffer, m_dwTotalBytesRead);
	if(0 == m_cbReadBuffer)
	{
		return bValid;
	}

	if(m_byReadBuffer[0] == 0xFF && m_byReadBuffer[1] == 0xD8)
	{	
		return true;
	}

	if(m_byReadBuffer[0] == 0x67 && m_byReadBuffer[1] == 0x69 && m_byReadBuffer[2] == 0x66)
	{
		return true;
	}

	if(m_byReadBuffer[0] == 0x65 && m_byReadBuffer[1] == 0x72)
	{
		return true;
	}

	for(int i = 0; i < _countof(g_szHdrTags1); i++)
	{
		if(MemStr(m_byReadBuffer, m_cbReadBuffer, g_szHdrTags1[i], strlen(g_szHdrTags1[i])))
		{
			bValid = true;
			break;
		}
	}

	if(bValid)
	{
		return bValid;
	}

	/*if(!MemStr(m_byReadBuffer, m_cbReadBuffer, "<%", 2))
	{
		return bValid;
	}*/
	if(!MemStr(m_byReadBuffer, m_cbReadBuffer, "<%", 2))
	{
		//Added by Ramandeep for script files  to check end of file for tags
		if(pMaxPEFile->ReadBuffer(m_byReadEndBuffer,( pMaxPEFile->m_dwFileSize - MAX_FILE_END_READ_BUFFER) , MAX_FILE_END_READ_BUFFER,0,&m_dwTotalBytesRead))
		{  
			m_cbReadBuffer1 = NormalizeBuffer(m_byReadEndBuffer, m_dwTotalBytesRead);

			for(int i = 0; i < _countof(g_szHdrTags1); i++)
			{
				if(0 == m_cbReadBuffer1)
				{
					break;
				}
				if(MemStr(m_byReadEndBuffer, m_cbReadBuffer1, g_szHdrTags1[i], strlen(g_szHdrTags1[i])))
				{
					bValid = true;
					break;
				}
			}
		}
		return bValid;
	}

	for(int i = 0; i < _countof(g_szHdrTags2); i++)
	{
		if(MemStr(m_byReadBuffer, m_cbReadBuffer, g_szHdrTags2[i], strlen(g_szHdrTags2[i])))
		{
			bValid = true;
			break;
		}
	}

	return bValid;
}

/*-------------------------------------------------------------------------------------
	Function		: GetFileBuffer
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer, DWORD& cbBufSize, int iIndex, CMaxPEFile *pMaxPEFile
	Out Parameters	: bool : true if success else false
	Purpose			: Internal Function 
	Author			: Tushar Kadam
	Description		: Collects buffer from file
--------------------------------------------------------------------------------------*/
bool CScriptSig::GetFileBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD& cbBufSize, int iIndex, CMaxPEFile *pMaxPEFile)
{
	if(0 == iIndex)
	{
		if(m_cbReadBuffer > cbBuffer)
		{
			return false;
		}

		cbBufSize = m_cbReadBuffer;
		memcpy(byBuffer, m_byReadBuffer, m_cbReadBuffer);
		return true;
	}
	else if(m_dwTotalBytesRead < pMaxPEFile->m_dwFileSize)
	{
		DWORD dwBytesRead = 0;

		if(m_dwTotalBytesRead > MAX_SIG_SIZE_IN_BYTES)
		{
			m_dwTotalBytesRead -= MAX_SIG_SIZE_IN_BYTES;
		}

		if(!pMaxPEFile->ReadBuffer(m_byReadBuffer, m_dwTotalBytesRead, MAX_FILE_READ_BUFFER, 0, &dwBytesRead))
		{
			return false;
		}

		if(0 == dwBytesRead)
		{
			m_dwTotalBytesRead = pMaxPEFile->m_dwFileSize;
			return false;
		}

		m_dwTotalBytesRead += dwBytesRead;
		m_cbReadBuffer = NormalizeBuffer(m_byReadBuffer, dwBytesRead);
		if(m_cbReadBuffer > cbBuffer)
		{
			return false;
		}

		cbBufSize = m_cbReadBuffer;
		memcpy(byBuffer, m_byReadBuffer, m_cbReadBuffer);
		return true;
	}
	else
	{
		return false;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: GetJClassFileBuffer
	In Parameters	: LPBYTE byBuffer, DWORD& cbBufSize, int iIndex, DWORD& dwTotalBytesRead, CMaxPEFile *pMaxPEFile
	Out Parameters	: bool : true if success else false
	Purpose			: Internal Function 
	Author			: Tushar Kadam
	Description		: Collects buffer from file Java Class file
--------------------------------------------------------------------------------------*/
bool CScriptSig::GetJClassFileBuffer(LPBYTE byBuffer, DWORD& cbBufSize, int iIndex, DWORD& dwTotalBytesRead, CMaxPEFile *pMaxPEFile)
{
	DWORD dwBytesRead = 0;
	if(iIndex == 0)
	{
		if(pMaxPEFile->m_dwFileSize == 0 || pMaxPEFile->m_dwFileSize > MAX_FILE_SIZE_TO_SCAN)
		{
			return false;
		}
		if(!pMaxPEFile->ReadBuffer(byBuffer, 0, MAX_FILE_READ_BUFFER, 0, &dwBytesRead))
		{
			return false;
		}
		dwTotalBytesRead = dwBytesRead;
	}
	else if(dwTotalBytesRead < pMaxPEFile->m_dwFileSize)
	{
		if(dwTotalBytesRead > MAX_SIG_SIZE_IN_BYTES)
		{
			dwTotalBytesRead -= MAX_SIG_SIZE_IN_BYTES;
		}
		if(!pMaxPEFile->ReadBuffer(byBuffer, dwTotalBytesRead, MAX_FILE_READ_BUFFER, 0, &dwBytesRead))
		{
			return false;
		}
		dwTotalBytesRead += dwBytesRead;
	}
	cbBufSize = dwBytesRead;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetJClassFileBuffer
	In Parameters	: LPBYTE byBuffer, DWORD& cbBufSize, int iIndex, DWORD& dwTotalBytesRead, CMaxPEFile *pMaxPEFile
	Out Parameters	: bool : true if success else false
	Purpose			: Internal Function 
	Author			: Tushar Kadam
	Description		: Collects buffer from file Java Class file
--------------------------------------------------------------------------------------*/
bool CScriptSig::CheckForExploitScript(LPBYTE pbyBuffer, DWORD cbBufSize)
{
	bool bRetValue = false;

	if (pbyBuffer == NULL || cbBufSize == 0x00)
	{
		return bRetValue;
	}
	if (cbBufSize < 0x150)
	{
		return bRetValue;
	}

	if (m_dwEscapeChrCnt > 0x30)
	{
		return bRetValue;
	}

	bool	bVarPresent = false;
	int		iIndex = 0x00;
	DWORD	dwStartOffSet = 0x00;
	DWORD   dwCnt = 0x00;

	for (iIndex = 0x00; iIndex < 0x12; iIndex++)
	{	
		if (pbyBuffer[iIndex] == 0x76 && pbyBuffer[iIndex + 1] == 0x61 && pbyBuffer[iIndex + 2] == 0x72)
		{
			dwStartOffSet = iIndex;
			bVarPresent = true;
			break;
		}
	}
	for (iIndex = 0x00; iIndex < 0x170; iIndex++)//	5E Search in file
	{	
		if (pbyBuffer[iIndex] == 0x35 && pbyBuffer[iIndex + 1] == 0x65)
		{
			dwCnt++;
		}
	}
    if(dwCnt == 0x06 || dwCnt == 0x05) //added
	{
	  dwStartOffSet = iIndex;
    }

	if(!bVarPresent)
	{
		return bRetValue;
	}

	DWORD	dwAssignmentCnt = 0x00;
	DWORD	dwLimit = dwStartOffSet + 0x150;
	DWORD	iSemiColCnt = 0x00;

	if (dwLimit > cbBufSize)
	{
		return bRetValue;
	}

	for (iIndex = dwStartOffSet; iIndex < dwLimit; iIndex++)
	{
		if (pbyBuffer[iIndex] == 0x3D)// || pbyBuffer[iIndex] == 0x2B || pbyBuffer[iIndex] == 0x27)
		{
			if (pbyBuffer[iIndex-1] != 0x3D)
			{
				dwAssignmentCnt++;
			}
		}
		if (pbyBuffer[iIndex] == 0x2B)// || pbyBuffer[iIndex] == 0x2B || pbyBuffer[iIndex] == 0x27)
		{
			if (pbyBuffer[iIndex-1] != 0x2B)
			{
				dwAssignmentCnt++;
			}
		}
		if (pbyBuffer[iIndex] == 0x3B)// || pbyBuffer[iIndex] == 0x2B || pbyBuffer[iIndex] == 0x27)
		{
			if (pbyBuffer[iIndex-1] != 0x3B)
			{
				iSemiColCnt++;
				dwAssignmentCnt++;
			}
		}
	}

	if (dwAssignmentCnt > 0x20 && iSemiColCnt < 0x0A)
	{
		bRetValue = true;	
	}

	return bRetValue;
}