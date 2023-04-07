/*======================================================================================
   FILE				: PDFSig.cpp
   ABSTRACT			: Supportive class for PDF File Scanner
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
   NOTES			: This module manages the scanning for file tyep PDF. 
   VERSION HISTORY	: 
=====================================================================================*/
#include "pch.h"
#include "PDFSig.h"

HMODULE	CPDFSig::m_hDll = NULL;
LPFN_DecryptPDFFile	CPDFSig::m_lpfnDecryptPDFFile = NULL;

/*-------------------------------------------------------------------------------------
	Function		: CPDFSig
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CPDFSig::CPDFSig()
{
	m_hFileDec = INVALID_HANDLE_VALUE;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPDFSig
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CPDFSig::~CPDFSig()
{
}

/*-------------------------------------------------------------------------------------
	Function		: LoadDll
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Loads DecryptPDFFile.dll for retrieval fo internal structure
--------------------------------------------------------------------------------------*/
bool CPDFSig::LoadDll()
{
	m_hDll = LoadLibrary(PDF_DLL_NAME);
	if(!m_hDll)
	{
		return false;
	}

	m_lpfnDecryptPDFFile = (LPFN_DecryptPDFFile)GetProcAddress(m_hDll, "DecryptPDFFile");
	if(!m_lpfnDecryptPDFFile)
	{
		m_lpfnDecryptPDFFile = NULL;
		FreeLibrary(m_hDll);
		m_hDll = NULL;
		return false;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: UnLoadDll
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Unload Loads DecryptPDFFile.dll
--------------------------------------------------------------------------------------*/
bool CPDFSig::UnLoadDll()
{
	if(m_hDll)
	{
		FreeLibrary(m_hDll);
	}

	m_hDll = NULL;
	m_lpfnDecryptPDFFile = NULL;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: IsValidPDFFile
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checks whether input file is valid PDF File
--------------------------------------------------------------------------------------*/
bool CPDFSig::IsValidPDFFile(LPCTSTR szFilePath, CMaxPEFile* pMaxPEFile)
{
	BYTE byHeader[10] = {0};

	if(!pMaxPEFile)
	{
		return false;
	}

	if(pMaxPEFile->m_dwFileSize >= 10*1024*1024)
	{
		return false;
	}

	if(!pMaxPEFile->ReadBuffer(byHeader, 0, strlen(PDF_HDR_SIGNATURE)))
	{
		return false;
	}

	if(memcmp(byHeader, PDF_HDR_SIGNATURE, strlen(PDF_HDR_SIGNATURE)))
	{
		return false;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptPDFFile
	In Parameters	: LPCTSTR szFilePath
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Decrypts PDF structures
--------------------------------------------------------------------------------------*/
bool CPDFSig::DecryptPDFFile(LPCTSTR szFilePath)
{
	int iStatus = 0;
	TCHAR szTempFolderPath[MAX_PATH] = {0};

	if(!m_lpfnDecryptPDFFile)
	{
		return false;
	}

	GetTempPath(_countof(szTempFolderPath), szTempFolderPath);
	if(_taccess_s(szTempFolderPath, 0))
	{
		return false;
	}

	DeleteFile(m_szDecryptedFile);
	GetTempFileName(szTempFolderPath, _T("max"), 0, m_szDecryptedFile);
	if(_taccess_s(m_szDecryptedFile, 0))
	{
		return false;
	}

	if(!m_lpfnDecryptPDFFile(szFilePath, m_szDecryptedFile, &iStatus))
	{
		if(iStatus)
		{
			UnLoadDll();
			LoadDll();
		}

		return false;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetOneObjectFromBuffer
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer, DWORD& dwObjLen
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: extracts one by one objects from PDF file
--------------------------------------------------------------------------------------*/
void CPDFSig::GetOneObjectFromBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD& dwObjLen)
{
	for(DWORD dwIndex = 0; dwIndex + sizeof(OBJ_END_MARKER) <= cbBuffer; dwIndex++)
	{
		if(byBuffer[dwIndex + 0] == OBJ_END_MARKER[0] && byBuffer[dwIndex + 5] == OBJ_END_MARKER[5])
		{
			if(byBuffer[dwIndex + 1] == OBJ_END_MARKER[1] && byBuffer[dwIndex + 4] == OBJ_END_MARKER[4])
			{
				if(byBuffer[dwIndex + 2] == OBJ_END_MARKER[2] && byBuffer[dwIndex + 3] == OBJ_END_MARKER[3])
				{
					dwObjLen = dwIndex + sizeof(OBJ_END_MARKER);
					break;
				}
			}
		}
	}
}

/*-------------------------------------------------------------------------------------
	Function		: NormalizeBuffer
	In Parameters	: LPBYTE byBuffer, DWORD cbBuffer
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Normalize PDF buffer for Test searching
--------------------------------------------------------------------------------------*/
DWORD CPDFSig::NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer)
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
	Function		: GetOneScript
	In Parameters	: LPBYTE byData, unsigned int& cbData
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Get Script from PDF file
--------------------------------------------------------------------------------------*/
bool CPDFSig::GetOneScript(LPBYTE byData, unsigned int& cbData)
{
	bool bDataFound = true;
	DWORD dwObjLen = 0, dwRemainingSpaceInBuffer = 0, dwBR = 0, dwDataInBuffer = 0;

	while(true)
	{
		dwObjLen = MAXDWORD;
		GetOneObjectFromBuffer(byData + m_dwBytesUsed, m_dwBytesRead - m_dwBytesUsed, dwObjLen);
		if(MAXDWORD != dwObjLen)
		{
			cbData = NormalizeBuffer(byData + m_dwBytesUsed, dwObjLen);
			memmove(byData, byData + m_dwBytesUsed, cbData);
			m_dwBytesUsed += dwObjLen;
			break;
		}
		else if(0 == m_dwBytesUsed && m_dwBytesRead == m_dwMaxReadBuffer)
		{
			cbData = NormalizeBuffer(byData, m_dwBytesRead);
			m_dwBytesUsed = m_dwBytesRead;
			break;
		}
		else if(m_bFullFileRead && m_dwBytesUsed < m_dwBytesRead)
		{
			cbData = NormalizeBuffer(byData + m_dwBytesUsed, m_dwBytesRead - m_dwBytesUsed);
			memmove(byData, byData + m_dwBytesUsed, cbData);
			m_dwBytesUsed = m_dwBytesRead;
			break;
		}
		else
		{
			if(m_dwBytesUsed < m_dwBytesRead)
			{
				dwDataInBuffer = m_dwBytesRead - m_dwBytesUsed;
				dwRemainingSpaceInBuffer = m_dwMaxReadBuffer - dwDataInBuffer;
				memmove(byData, byData + m_dwBytesUsed, dwDataInBuffer);
			}
			else
			{
				dwBR = dwDataInBuffer = 0;
				dwRemainingSpaceInBuffer = m_dwMaxReadBuffer;
			}

			if(m_bFullFileRead && 0 == dwDataInBuffer)
			{
				bDataFound = false;
				break;
			}

			ReadFile(m_hFileDec, byData + dwDataInBuffer, dwRemainingSpaceInBuffer, &dwBR, 0);
			m_dwBytesUsed = 0;
			m_dwTotalBytesRead += dwBR;
			m_dwBytesRead = dwDataInBuffer + dwBR;
			m_bFullFileRead = m_dwTotalBytesRead >= m_dwFileSize;
		}
	}

	if(bDataFound)
	{
		m_dwMaxScripts++;
	}

	return bDataFound;
}

/*-------------------------------------------------------------------------------------
	Function		: EnumFirstScript
	In Parameters	: LPBYTE byScript, unsigned int& cbScript
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Gets first script file
--------------------------------------------------------------------------------------*/
bool CPDFSig::EnumFirstScript(LPBYTE byScript, unsigned int& cbScript)
{
	m_dwMaxReadBuffer = cbScript;
	m_bFullFileRead = false;
	m_dwFileSize = m_dwTotalBytesRead = m_dwMaxScripts = m_dwBytesUsed = m_dwBytesRead = 0;

	m_hFileDec = CreateFile(m_szDecryptedFile, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE == m_hFileDec)
	{
		return false;
	}

	m_dwFileSize = GetFileSize(m_hFileDec, 0);
	if(!ReadFile(m_hFileDec, byScript, cbScript, &m_dwBytesRead, 0))
	{
		CloseEnum();
		return false;
	}

	m_dwTotalBytesRead = m_dwBytesRead;
	m_bFullFileRead = m_dwTotalBytesRead >= m_dwFileSize;
	if(!GetOneScript(byScript, cbScript))
	{
		return false;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: EnumNextScript
	In Parameters	: LPBYTE byScript, unsigned int& cbScript
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Gets remaining scripts in sequence from PDF file
--------------------------------------------------------------------------------------*/
bool CPDFSig::EnumNextScript(LPBYTE byScript, unsigned int& cbScript)
{
	if(m_dwMaxScripts >= MAX_SCRIPTS_EXTRACT)
	{
		return false;
	}

	if(!GetOneScript(byScript, cbScript))
	{
		return false;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CloseEnum
	In Parameters	: LPBYTE byScript, unsigned int& cbScript
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Quits script enumeration operation
--------------------------------------------------------------------------------------*/
bool CPDFSig::CloseEnum()
{
	if(INVALID_HANDLE_VALUE != m_hFileDec)
	{
		CloseHandle(m_hFileDec);
		m_hFileDec = INVALID_HANDLE_VALUE;
	}

	DeleteFile(m_szDecryptedFile);
	return true;
}

