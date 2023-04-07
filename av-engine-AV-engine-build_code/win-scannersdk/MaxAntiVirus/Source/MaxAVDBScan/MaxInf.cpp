/*======================================================================================
   FILE				: MaxHelp.cpp
   ABSTRACT			: Supportive class for INF File Scanner
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
   NOTES			: This module manages the scanning for file tyep INF (Auto launch). 
   VERSION HISTORY	: 
=====================================================================================*/
#include "pch.h"
#include "MaxInf.h"

/*-------------------------------------------------------------------------------------
	Function		: CMaxInf
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CMaxInf :: CMaxInf()
{
	m_dwBytesRead = m_dwTotalBytesRead = m_cbReadBuffer = 0;

	m_byReadBuffer = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_BUFFER_SIZE);
	m_cbReadBuffer = m_byReadBuffer? MAX_BUFFER_SIZE: 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CMaxInf
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CMaxInf :: ~CMaxInf()
{
	if(m_byReadBuffer)
	{
		HeapFree(GetProcessHeap(), 0, m_byReadBuffer);
	}

	m_byReadBuffer = NULL;
	m_dwBytesRead = m_dwTotalBytesRead = m_cbReadBuffer = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: IsThisValidFile
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Validates INF file on extenssion basis
--------------------------------------------------------------------------------------*/
bool CMaxInf::IsThisValidFile(LPCTSTR szFilePath)
{
	LPCTSTR szExt = _tcsrchr(szFilePath, _T('.'));
	return szExt && !_tcsicmp(szExt, _T(".inf"));
}

/*-------------------------------------------------------------------------------------
	Function		: ReadBuffer
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer, DWORD &dwBytesRead, CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Read buffer from INF File
--------------------------------------------------------------------------------------*/
bool CMaxInf::ReadBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD &dwBytesRead, CMaxPEFile *pMaxPEFile)
{
	DWORD dwBytesToRead = 0;

	if(m_dwTotalBytesRead >= pMaxPEFile->m_dwFileSize)
	{
		return false;
	}
	
	if(cbBuffer >= pMaxPEFile->m_dwFileSize - m_dwTotalBytesRead)
	{
		dwBytesToRead = pMaxPEFile->m_dwFileSize - m_dwTotalBytesRead;
	}
	else
	{
		dwBytesToRead = cbBuffer;
	}

	dwBytesRead = 0;
	if(!pMaxPEFile->ReadBuffer(byBuffer, m_dwTotalBytesRead, dwBytesToRead, dwBytesToRead, &dwBytesRead))
	{
		return false;
	}
	
	if(byBuffer[0] == 0 && dwBytesRead == 1)
	{
		return false;
	}
		
	if(m_dwTotalBytesRead < pMaxPEFile->m_dwFileSize && 0 != dwBytesRead)
	{
		DWORD dwBytesToShiftBack = 0;

		for(int iBackwards = ((int)dwBytesRead - 1); iBackwards > -1; iBackwards--)
		{
			if(byBuffer[iBackwards] == '\n')
			{
				break;
			}

			dwBytesToShiftBack++;
		}
		if(dwBytesRead != dwBytesToShiftBack)
		{
			dwBytesRead -= dwBytesToShiftBack;
		}
	}

	m_dwTotalBytesRead += dwBytesRead;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: NormalizeBuffer
	In Parameters	: LPBYTE byBuffer, DWORD& cbBuffer
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Mornalize buffer for scanning
--------------------------------------------------------------------------------------*/
bool CMaxInf::NormalizeBuffer(LPBYTE byBuffer, DWORD& cbBuffer)
{
	DWORD dwOut = 0;

	if(!byBuffer || !cbBuffer)
	{
		return false;
	}

	for(DWORD i = 0; i < cbBuffer; i++)
	{
		if(byBuffer[i])
		{
			byBuffer[dwOut++] = byBuffer[i];
		}
	}

	cbBuffer = dwOut;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetOneLine
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer, DWORD dwIndex, DWORD& dwLength
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Get Single text line
--------------------------------------------------------------------------------------*/
bool CMaxInf::GetOneLine(LPBYTE byBuffer, DWORD cbBuffer, DWORD dwIndex, DWORD& dwLength)
{
	if(!byBuffer || !cbBuffer)
	{
		return false;
	}
	if(dwIndex >= cbBuffer)
	{
		return false;
	}

	dwLength = 0;
	for(DWORD i = dwIndex; i < cbBuffer; i++)
	{
		dwLength++;
		if(byBuffer[i] == '\n')
		{
			break;
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetBuffer
	In Parameters	: LPBYTE byBuffer, DWORD& cbBuffer, CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Get Binary Buffer for Scanning : File Type INF
--------------------------------------------------------------------------------------*/
bool CMaxInf::GetBuffer(LPBYTE byBuffer, DWORD& cbBuffer, CMaxPEFile *pMaxPEFile)
{
	DWORD dwIndex = 0, dwLength = 0, dwKeyWordLen = 0;
	m_dwScanBuffCnt = 0;
	if(0 == pMaxPEFile->m_dwFileSize)
	{
		return false;
	}
	LPCSTR szSigKeyWords[] = 
	{
		"[autorun",
		"open",
		"icon",
		"label",
		"action",
		"useautoplay",
		"shellexecute",
		"shell"
	};

	m_dwTotalBytesRead = m_dwBytesRead = 0;
	while(ReadBuffer(m_byReadBuffer, m_cbReadBuffer, m_dwBytesRead, pMaxPEFile))
	{
		if(m_dwScanBuffCnt > MAX_INF_SIG_LEN)
		{
			break;
		}
		NormalizeBuffer(m_byReadBuffer, m_dwBytesRead);
		dwIndex = dwLength = 0;
		while(GetOneLine(m_byReadBuffer, m_dwBytesRead, dwIndex, dwLength))
		{
			if(m_dwScanBuffCnt > MAX_INF_SIG_LEN)
			{
				break;
			}

			if(!_memicmp(&m_byReadBuffer[dwIndex],";",sizeof(BYTE)))
			{
				dwIndex += dwLength;
				continue;
			}
			
			bool bFlag = false; 			
			for(DWORD j = dwIndex; j < dwIndex + dwLength; j++)
			{
				for(DWORD i = 0; i < _countof(szSigKeyWords); i++)
				{
					dwKeyWordLen = strlen(szSigKeyWords[i]);
					if(j + dwKeyWordLen < dwIndex + dwLength && !_memicmp(&m_byReadBuffer[j], szSigKeyWords[i], dwKeyWordLen))
					{
						memcpy_s(byBuffer + m_dwScanBuffCnt, cbBuffer - m_dwScanBuffCnt, m_byReadBuffer + dwIndex, dwLength);
						m_dwScanBuffCnt += dwLength;
						bFlag = true; 
						break;
					}
				}
				if(bFlag)
				{
					break;
				}
			}

			dwIndex += dwLength;
		}
	}
	
	DWORD dwOut = 0;
	for(DWORD i=0; i<m_dwScanBuffCnt; i++)
	{
		if(byBuffer[i] != '\n' && byBuffer[i] != '\r')
		{
			byBuffer[dwOut++] = byBuffer[i];
		}
	}
	
	cbBuffer = dwOut;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: MakeSignature
	In Parameters	: LPTSTR szSig, DWORD cchSig, LPBYTE byBuffer, DWORD cbBuffer
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Creats Cross signature from Buffer
--------------------------------------------------------------------------------------*/
bool CMaxInf::MakeSignature(LPTSTR szSig, DWORD cchSig, LPBYTE byBuffer, DWORD cbBuffer)
{
	TCHAR szOneByte[20] = {0};
	memset(szSig, 0, cchSig * sizeof(TCHAR));
	DWORD dwStarOffset = cbBuffer/2;

	if(cbBuffer < MIN_INF_SIG_LEN)
	{
		return false;
	}
	else
	{
		cbBuffer = cbBuffer > MAX_INF_SIG_LEN - 1? MAX_INF_SIG_LEN - 1: cbBuffer;
	}

	for(DWORD i = 0; i < cbBuffer; i++)
	{
		if(i == dwStarOffset)
		{
			memset(szOneByte, 0, sizeof(szOneByte));
			_tcscpy_s(szOneByte, _countof(szOneByte), L"*");
			_tcscat_s(szSig, cchSig, szOneByte);
		}
		memset(szOneByte, 0, sizeof(szOneByte));
		_itot_s(byBuffer[i], szOneByte, _countof(szOneByte), 16);
		_tcsupr_s(szOneByte, _countof(szOneByte));
		
		if(0 == szOneByte[1])
		{
			szOneByte[1] = szOneByte[0];
			szOneByte[0] = _T('0');
			szOneByte[2] = _T('\0');
		}
		_tcscat_s(szSig, cchSig, szOneByte);
	}
	
	return true;
}