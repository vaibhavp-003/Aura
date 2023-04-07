/*======================================================================================
   FILE				: ScanFileManager.cpp
   ABSTRACT			: Supportive class for ScanManager
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
   NOTES			: This module is actually scan the file. 
   VERSION HISTORY	: 
=====================================================================================*/
#pragma once
#include "pch.h"
#include "MaxConstant.h"
#include "ScanFileManager.h"
#include "MaxPEFile.h"
#include "PatternFileScanner.h"

/*-------------------------------------------------------------------------------------
	Function		: CScanFileManager
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CScanFileManager::CScanFileManager(CMaxPEFile *pMaxPEFile):
m_iBufferSize(0),
m_bFlagForBuffer(false),
m_szDOSSIG("DOSSIG"),
m_szCOMSIG("COMSIG"), 
m_szSentence("This file size in bytes is equal to "),
m_pMaxPEFile(pMaxPEFile)
{
	memset(m_szVirusName, 0, sizeof(m_szVirusName));
	memset(m_szFile2Scan, 0, sizeof(m_szFile2Scan));
	memset(m_szScnBuffer, 0, sizeof(m_szScnBuffer));
	memset(&m_stPERegions, 0xFF, sizeof(m_stPERegions));
	m_dwFileSize = m_pMaxPEFile->m_dwFileSize; 

	m_pMacFile = NULL;
	m_pMacFile = new CMACFileScanner(m_pMaxPEFile);
}

/*-------------------------------------------------------------------------------------
	Function		: CScanFileManager
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: detructor for CScanFileManager
--------------------------------------------------------------------------------------*/
CScanFileManager::~CScanFileManager(void)
{
	memset(m_szFile2Scan, 0, sizeof(m_szFile2Scan));
	memset(m_szScnBuffer, 0, sizeof(m_szScnBuffer));

	if (m_pMacFile != NULL)
	{
		delete m_pMacFile;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: OpenPEFile4ScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Opens Microsoft Binary Executable for scanning
--------------------------------------------------------------------------------------*/
int CScanFileManager::OpenPEFile4ScanningEx()
{
	// Till this point we are confirm About Valid PS File. We can Read The Buffer for Scanning 
	InitScanBuffer();
	
	// Part 1 : 0x300 bytes from the start of the file
	DWORD dwBytesRead = 0;
	if(m_stPERegions.FileStart)
	{
		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], 0, 0x300, 0, &dwBytesRead))
		{
			m_iBufferSize += dwBytesRead;
		}
	}

	// Part 2: 0x250 bytes from first cavity i.e. from section header end
	DWORD dwOffset = m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	dwOffset += m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + m_pMaxPEFile->m_stPEHeader.NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;
	if(dwOffset < m_dwFileSize && m_stPERegions.Cavity1)
	{
		dwBytesRead = 0;
		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwOffset, 0x250, 0, &dwBytesRead))
		{
			m_iBufferSize += dwBytesRead;
		}
	}
	
	// Part 3: 0x500 bytes from part of cavity if virus Lamewin.
	IMAGE_SECTION_HEADER *SectionHeader = &m_pMaxPEFile->m_stSectionHeader[0];
	dwOffset += 0x450;
	if(dwOffset + 0x500 < SectionHeader[0].PointerToRawData && m_stPERegions.Cavity2)
	{ 	
		dwBytesRead = 0;
		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwOffset, 0x500, 0, &dwBytesRead))
		{
			m_iBufferSize += dwBytesRead;
		}
	}
	
	// Part 4: 0x500 bytes from Address of entry point.	
	DWORD dwAEPFileOffset = 0, dwAEPSection = 0;
	for (int iCnt = m_pMaxPEFile->m_stPEHeader.NumberOfSections -1; iCnt >= 0; iCnt--)
	{			
		if(!dwAEPSection)
		{
			if((m_pMaxPEFile->m_stSectionHeader[iCnt].VirtualAddress <= m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint) && 
				((m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint <= (m_pMaxPEFile->m_stSectionHeader[iCnt].VirtualAddress + m_pMaxPEFile->m_stSectionHeader[iCnt].Misc.VirtualSize)) ||
				(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint <= (m_pMaxPEFile->m_stSectionHeader[iCnt].VirtualAddress + m_pMaxPEFile->m_stSectionHeader[iCnt].SizeOfRawData))))
			{
				dwAEPFileOffset = m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint - m_pMaxPEFile->m_stSectionHeader[iCnt].VirtualAddress + m_pMaxPEFile->m_stSectionHeader[iCnt].PointerToRawData;
				dwAEPSection	= iCnt;
				break;
			}
		}
	}

	if(dwAEPFileOffset == 0x00)
	{
		// Check if AEP is in the Cavity 
		for(int iCnt = 0; iCnt < m_pMaxPEFile->m_stPEHeader.NumberOfSections; iCnt++)
		{	
			if(0 != SectionHeader[iCnt].SizeOfRawData)
			{
				if(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint < SectionHeader[iCnt].PointerToRawData)
				{
					dwAEPFileOffset = m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
					m_pMaxPEFile->m_wAEPSec = 0; 
					break;
				}
			}
		}
	}	
	if(dwAEPFileOffset > 0 && m_stPERegions.AEP)
	{
		dwBytesRead = 0;
		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwAEPFileOffset, 0x500, 0, &dwBytesRead))
		{
			m_iBufferSize += dwBytesRead;
			if(m_szScnBuffer[m_iBufferSize - dwBytesRead] == 0xE9 || m_szScnBuffer[m_iBufferSize - dwBytesRead] == 0xE8)
			{
				DWORD dwCallAddress = *((DWORD *)&m_szScnBuffer[m_iBufferSize - dwBytesRead + 1]) + m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint + 5;
				m_pMaxPEFile->Rva2FileOffset(dwCallAddress, &dwCallAddress);
				if(dwCallAddress < m_dwFileSize)
				{
					if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwCallAddress, 0x100, 0, &dwBytesRead))
					{
						m_iBufferSize += dwBytesRead;
					}	
				}
			}
		}
	}

	// Part 5: 0x350 bytes from end of AEP section for virus Huhk.C
	if(m_pMaxPEFile->m_wAEPSec != OUT_OF_FILE && m_stPERegions.EndOfAEPSec)
	{
		if(SectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData > 0x500)
		{
			dwBytesRead = 0;
			dwOffset = SectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData + SectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData - 0x350;
			if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwOffset, 0x350, 0, &dwBytesRead))
			{
				m_iBufferSize += dwBytesRead;
			}
		}
	}
	DWORD dwLastSection = 0;
	for(WORD wSec = m_pMaxPEFile->m_stPEHeader.NumberOfSections - 1; wSec >= 0; wSec--)
	{
		if(SectionHeader[wSec].PointerToRawData != 0 || SectionHeader[wSec].SizeOfRawData != 0)
		{
			dwLastSection = wSec;
			break;
		}
		if(wSec == 0)
		{
			break;
		}
	}

	// Part 6: 0x500 bytes from start of last section
	dwOffset = SectionHeader[dwLastSection].PointerToRawData;
	if (dwOffset < m_dwFileSize && m_stPERegions.StartOfLastSec)
	{
		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwOffset, 0x500, 0, &dwBytesRead))
		{
			m_iBufferSize += dwBytesRead;
		}
	}
	
	// Part 7: 0x1250 bytes from end of last section
	if (m_stPERegions.EndOfLastSec)
	{
		dwOffset = (m_dwFileSize > 0x1250) ? SectionHeader[dwLastSection].PointerToRawData + SectionHeader[dwLastSection].SizeOfRawData - 0x1250 : 0;
		if(dwOffset >= 0)
		{
			dwBytesRead = 0;
			if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwOffset, 0x1250, 0, &dwBytesRead))
			{
				m_iBufferSize += dwBytesRead;
			}
		}		
	}

	// Part 8: 0x500 bytes from data of the UPX section
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 2 && m_stPERegions.UPXSec)
	{
		// Check first 2 sections having name UPX
		BYTE byUPX[] = {0x55, 0x50, 0x58};
		if(	memcmp(SectionHeader[0].Name, byUPX, sizeof(byUPX)) == 0 &&
			memcmp(SectionHeader[1].Name, byUPX, sizeof(byUPX)) == 0 )
		{		
			// Check for section having SRD zero and VS nonzero
			for(int iCnt = 0; iCnt < m_pMaxPEFile->m_stPEHeader.NumberOfSections; iCnt++)
			{			
				if(SectionHeader[iCnt].SizeOfRawData == 0 && SectionHeader[iCnt].Misc.VirtualSize != 0)
				{
					// Check for AEP location. If AEP is in the second half of the section then read 
					// buffer from start of the section otherwise read it from the mid of the section
					if(m_pMaxPEFile->m_wAEPSec != OUT_OF_FILE)

					{
						dwOffset = SectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData + (SectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData / 2);
						if(dwAEPFileOffset >= dwOffset)
						{
							dwOffset = SectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData;
						}
						dwBytesRead = 0;
						if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwOffset, 0x500, 0, &dwBytesRead))
						{
							m_iBufferSize += dwBytesRead;
						}
					}
				}
			}
		}
	}

	// Part 9: 0x200 bytes from start of .data section
	if(m_stPERegions.StartOfDataSec)
	{		
		// Base of data offset
		dwOffset = m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 0x18;
		if(m_pMaxPEFile->ReadBuffer(&dwOffset, dwOffset, 4, 4)) 
		{
			if(dwOffset)
			{
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOffset, &dwOffset))
				{
					dwBytesRead = 0;
					if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwOffset, 0x200, 0, &dwBytesRead))
					{
						m_iBufferSize += dwBytesRead;
					}
				}
			}
		}
		// if .data section is not Base of Data read 0x200 bytes from .data section PRD
		for (int iCnt = 0; iCnt < m_pMaxPEFile->m_stPEHeader.NumberOfSections; iCnt++)
		{		
			BYTE byDataSec[] = {0x2E, 0x64, 0x61, 0x74}; // .data
			if(memcmp(SectionHeader[iCnt].Name, byDataSec, sizeof(byDataSec)) == 0)
			{
				if(dwOffset != SectionHeader[iCnt].PointerToRawData) 
				{
					dwBytesRead = 0;
					if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], SectionHeader[iCnt].PointerToRawData, 0x200, 0, &dwBytesRead))
					{
						m_iBufferSize += dwBytesRead;
					}
					break;
				}
			}		
		}
	}
	

	// Part 10: 0x1200 bytes from start 3rd section of Petite packed file for Virus Ridnu 
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections == 5 && 
		memcmp(SectionHeader[3].Name, ".rsrc", 5) == 0 &&
		(memcmp(SectionHeader[0].Name, SectionHeader[1].Name, sizeof(SectionHeader[0].Name)) == 0) &&
		(memcmp(SectionHeader[0].Name, SectionHeader[2].Name, sizeof(SectionHeader[0].Name)) == 0) &&
		(memcmp(SectionHeader[0].Name, SectionHeader[4].Name, sizeof(SectionHeader[0].Name)) == 0))
	{
		dwBytesRead = 0;
		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], SectionHeader[2].PointerToRawData + 0x1D00, 0x1200, 0, &dwBytesRead))
		{
			m_iBufferSize += dwBytesRead;
		}
	}

	// Part 11: 0x500 bytes from from start of overlay
	dwOffset = SectionHeader[dwLastSection].PointerToRawData + SectionHeader[dwLastSection].SizeOfRawData;
	if((m_dwFileSize - dwOffset) > 0 && m_stPERegions.StartOfOverlay) 
	{
		// Overlay is present so read 0x500 bytes or size of overlay if its less than 0x500.
		dwBytesRead = 0;
		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwOffset, 0x500, 0, &dwBytesRead))
		{
			m_iBufferSize += dwBytesRead;
		}
	}
	
	// Part 12: 0x500 bytes from from end of overlay
	if((m_dwFileSize - dwOffset) > 0x500 && m_stPERegions.EndOfOverlay) 
	{
		// Overlay is greater than 0x500 bytes so read 500 bytes from end of the file.
		dwOffset += 0x500; 
		if((m_dwFileSize - dwOffset) > 0x500)
		{
			dwOffset = m_dwFileSize - 0x500;
		}
		dwBytesRead = 0;
		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwOffset, 0x500, 0, &dwBytesRead))
		{
			m_iBufferSize += dwBytesRead;
		}
	}

	// Part 13: File version information
	dwBytesRead = GetFileVersionInfoSize(m_pMaxPEFile->m_szFilePath, NULL);
	if(dwBytesRead)
	{
		if(dwBytesRead > SCAN_BUFFER_LEN - m_iBufferSize)
		{
			dwBytesRead = SCAN_BUFFER_LEN - m_iBufferSize;
		}
		if(GetFileVersionInfo(m_pMaxPEFile->m_szFilePath, NULL, dwBytesRead, &m_szScnBuffer[m_iBufferSize]))
		{
			m_iBufferSize += dwBytesRead; 
		}
	}
	//	Part 14: Reading .rdata section   Newly Added
	BYTE byRDataSec[] = {0x2E, 0x72, 0x64, 0x61, 0x74}; // .rdata
	for (int iCnt = 0; iCnt < m_pMaxPEFile->m_stPEHeader.NumberOfSections; iCnt++)
	{
		if(memcmp(SectionHeader[iCnt].Name, byRDataSec, sizeof(byRDataSec)) == 0)
		{
			dwBytesRead = 0;
			DWORD dwBuffSize = 0;
			if(SectionHeader[iCnt].Misc.VirtualSize > 0x2000)
				dwBuffSize = 0x2000;
			else
				dwBuffSize = SectionHeader[iCnt].Misc.VirtualSize;

			if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], SectionHeader[iCnt].PointerToRawData, dwBuffSize, 0, &dwBytesRead))
			{
				m_iBufferSize += dwBytesRead;
			}
			break;
		}
	}

	if(m_pMaxPEFile->m_bIsVBFile)
	{
		dwBytesRead = 0;
		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], m_pMaxPEFile->m_dwVBSigOff, 0x60, 0, &dwBytesRead))
		{
			m_iBufferSize += dwBytesRead;
		}
	}
	return ERR_SUCCESS;
}

/*-------------------------------------------------------------------------------------
	Function		: InitScanBuffer
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Internal Function to initialize scan buffer
--------------------------------------------------------------------------------------*/
int CScanFileManager::InitScanBuffer(void)
{
	memset(m_szScnBuffer, 0, sizeof(m_szScnBuffer));
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: GetBuffer4Scanning
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Retrieves Buffer for scanning according to file type
--------------------------------------------------------------------------------------*/
int CScanFileManager::GetBuffer4Scanning()
{
	_tcscpy_s(m_szFile2Scan, MAX_PATH, m_pMaxPEFile->m_szFilePath);
	if(_tcslen(m_szFile2Scan) == 0)
	{
		//AddLogEntry(L"ERR_ZERO_LEN_INPUT");
		return ERR_ZERO_LEN_INPUT;
	}

	//AddLogEntry(L"GetBuffer4Scanning : Checking For File Type");

	int iRetVal = CheckFileTypeEx();
	if(iRetVal != 0)
	{
		switch(iRetVal)
		{
		case VIRUS_FILE_TYPE_PE: //Tushar-->PE File
			if (OpenPEFile4ScanningEx() != ERR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;
		case VIRUS_FILE_TYPE_DOS: //Tushar-->16 bit Dos File (exe + com)
			if (OpenDOSFile4ScanningEx() != ERR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;
		case VIRUS_FILE_TYPE_COM: //Tushar-->16 bit COM File (Non MZ)
			if (OpenCOMFile4ScanningEx() != ERR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;
		case VIRUS_FILE_TYPE_REG:
			if (OpenREGFileForScanningEx() != ERR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;
		case VIRUS_FILE_TYPE_WMA: //Tushar-->WMA File (MP3, DAT)
			if (OpenWMAFile4ScanningEx() != ERR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;		
		case VIRUS_FILE_TYPE_BAT:
			if (OpenBATFile4ScanningEx() != ERR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;
		case VIRUS_FILE_TYPE_INF:
			if (OpenInfFile4ScanningEx() != ERR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;
		case VIRUS_FILE_TYPE_PDF:
			if (OpenPdfFileForScanningEx() != ERR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;
		case VIRUS_FILE_TYPE_DEX:
			if (OpenDexFileForScanningEx() != ERR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;
		case VIRUS_FILE_TYPE_SIS:
			if(OpenSisFileForScanningEx() != ERROR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;
		case VIRUS_FILE_TYPE_ELF:
			if (OpenELFFileForScanningEx() != ERR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;	
		case VIRUS_FILE_TYPE_MAC:
			if (OpenMACFileForScanningEx() != ERR_SUCCESS)
				iRetVal = ERR_INVALID_FILE;
			break;	
		}
	}
	return iRetVal;
}

/******************************************************************************
Function Name	:	CheckFileTypeEx
Author			:	Tushar Kadam
Scope			:	Private
Input			:	
Output			:   int --> (Success) One of the File Type given below
							(Fail) 0

100			unknown file type
 01			PE executable file type
 02         16 Bit Dos base file type
 03			com file
 04			html + php file (Script File)
 05			MP3 File
 06			SIS File
*******************************************************************************/
int CScanFileManager::CheckFileTypeEx()
{	
	//if (Check4PEFile() == true)
	if(m_pMaxPEFile->m_bPEFile == true)
	{
		return VIRUS_FILE_TYPE_PE;
	}
	if(Check4DOSFileEx())
	{
		return VIRUS_FILE_TYPE_DOS;
	}
	if(Check4WMAFileEx())
	{
		return VIRUS_FILE_TYPE_WMA;
	}
	if(m_objMaxELF.IsValidELFFile(m_pMaxPEFile))
	{
		return VIRUS_FILE_TYPE_ELF;
	}
	if(m_pMacFile->IsValidMACFile())
	{
		return VIRUS_FILE_TYPE_MAC;
	}
	if(CheckForDexEx())
	{
		return VIRUS_FILE_TYPE_DEX;
	}
	if(CheckForSis())
	{
		return VIRUS_FILE_TYPE_SIS;
	}
	if(CheckForJClass())
	{
		return VIRUS_FILE_TYPE_JCLASS;
	}
	if(Check4MSOfficeFileEx())
	{
		return VIRUS_FILE_TYPE_OLE;
	}
	if(CheckForPDFFileEx())
	{
		return VIRUS_FILE_TYPE_PDF;
	}
	if(CheckForRegFile())
	{
		return VIRUS_FILE_TYPE_REG;
	}
	if(m_objMaxRTF.IsValidRTFFile(m_pMaxPEFile))
	{
		return VIRUS_FILE_TYPE_RTF;
	}
	if(m_objMaxCursor.IsValidICONFile(m_pMaxPEFile))
	{
		return VIRUS_FILE_TYPE_ICON;
	}
	if(m_objMaxCursor.IsValidANIFile(m_pMaxPEFile))
	{
		return VIRUS_FILE_TYPE_CUR;
	}
	if(m_objMaxTTF.IsValidTTFFile(m_pMaxPEFile))
	{
		return VIRUS_FILE_TYPE_TTF;
	}
	if(m_objMaxHelp.IsValidHelpFile(m_pMaxPEFile))  
	{
		return VIRUS_FILE_TYPE_HELP;
	}
	if(m_objScript.IsItValidScript(m_pMaxPEFile))
	{
		return VIRUS_FILE_TYPE_SCRIPT;
	}
	// Check for exclude file types
	if(Check4OtherFileTypes())
	{
		return 0;
	}
	if(Check4BATFileEx())
	{
		return VIRUS_FILE_TYPE_BAT;
	}
	if(m_objMaxInf.IsThisValidFile(m_pMaxPEFile->m_szFilePath))
	{
		return VIRUS_FILE_TYPE_INF;
	}
	// If no file type found then return as COM file type
	if(Check4COM16FileEx())
	{
		return VIRUS_FILE_TYPE_COM;
	}
	return 0;
}

/******************************************************************************
Function Name	:	Check4DOSFileEx
Author			:	Tushar Kadam
Scope			:	Private
Input			:	
Output			:   int --> (Success) One of the File Type given below
							(Fail) 0
01			PE executable file type
02			16 Bit Dos base file type
*******************************************************************************/
bool CScanFileManager::Check4DOSFileEx()
{
	WORD wMZ = 0;
	if(m_pMaxPEFile->ReadBuffer(&wMZ, 0, sizeof(WORD), sizeof(WORD)))
	{
		if (wMZ == 0x5A4D)
		{
			return true;
		}
	}
	return false;
}

bool CScanFileManager::Check4PEFile()
{
	WORD wMZ = 0;
	if (m_pMaxPEFile->ReadBuffer(&wMZ, 0, sizeof(WORD), sizeof(WORD)))
	{
		if (wMZ == 0x5A4D)
		{
			if (m_pMaxPEFile->m_bPEFile == true)
			{
				return true;
			}
		}
	}
	return false;
}

/******************************************************************************
Function Name	:	Check4WMAFileEx
Author			:	Tushar kadam
Scope			:	Private
Input			:	
Output			:   int --> (Success) One of the File Type given below
							(Fail) 0
 05			WMA + MP3 file (Media Files)
*******************************************************************************/
bool CScanFileManager::Check4WMAFileEx()
{
	unsigned char	szHeader[17] = {0};
	unsigned char	szWMAHeader[] = {0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11,0xA6,0xD9,0x00,0xAA,0x00,0x62,0xCE,0x6C};

	if(m_pMaxPEFile->ReadBuffer(szHeader, 0, 0x10, 0x10))
	{
		if (memcmp(&szHeader[0], &szWMAHeader[0], sizeof(szWMAHeader)) == 0)
		{
			return true;
		}
	}
	return false;
}

/******************************************************************************
Function Name	:	GetRemBuff4Scanning
Author			:	Tushar Kadam
Scope			:	Public
Input			:	
Output			:   int --> ERR_SUCCESS

It is only for SCRIPT File. We have to Send full file for Scanning in 10KB buffer.
Scaner should call this function if reading script file, till end of file.
Termination condition is either return value OR buffer size
*******************************************************************************/
int CScanFileManager::GetRemBuff4Scanning()
{
	InitScanBuffer();
	if(m_bFlagForBuffer)
	{
		// Read the 10kb buffer from end of the file
		DWORD dwBytesRead = m_dwFileSize - sizeof(m_szScnBuffer);
		SendFileForNormalize(dwBytesRead);				
		return 1;
	}
	return ERR_REACH_FILE_END; // file is less than 10kb
}

/*-------------------------------------------------------------------------------------
	Function		: CreateDOS32Sig
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Create cross signature for file type MS-DOS
--------------------------------------------------------------------------------------*/
bool CScanFileManager::CreateDOS32Sig(LPTSTR szSig, DWORD cchSig)
{
	TCHAR	szDummy[MAX_PATH] = {0};
	int		iReadBuffIndex = 0x00;
	int		iPercentageVal = 0x00;
	int		iTotalPartsCnt = 0;
	int		iSigLenGeneratedCnt = 0;
	int		iSigLen = 0, iStarCount = 0;
	DWORD	dwNonFileBytesSize = 0, dwFileBytesSize = 0;

	/*handling small file signatures with DOSSIG at the end in buffer*/
	if(m_iBufferSize > 6 && !memcmp(m_szScnBuffer + (m_iBufferSize - 6), m_szDOSSIG, 6))
	{
		dwNonFileBytesSize = strlen(m_szSentence) + strlen(m_szDOSSIG) + 8;
		dwFileBytesSize = m_iBufferSize - dwNonFileBytesSize;

		if(dwFileBytesSize > 200)
		{
			if((200 + dwNonFileBytesSize + 2) * sizeof(TCHAR) >= cchSig)
			{
				return false;
			}
		}
		else
		{
			if((dwFileBytesSize + dwNonFileBytesSize + 2) * sizeof(TCHAR) >= cchSig)
			{
				return false;
			}
		}

		memset(szSig, 0, cchSig * sizeof(TCHAR));

		//add data read from file in signature as hex
		if(dwFileBytesSize > 200)
		{
			//add sentence and file size in signature as hex
			for(DWORD i = 0, iLen = strlen(m_szSentence) + 8; i < iLen; i++)
			{
				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}

			iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));

			for(DWORD i = strlen(m_szSentence) + 8, iLen = strlen(m_szSentence) + 8 + 100; i < iLen; i++)
			{
				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}

			iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));

			for(DWORD i = m_iBufferSize - (100 + 6); i < m_iBufferSize - 6; i++)
			{
				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}

			iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));

			//add DOSSIG in signature as hex
			for(DWORD i = m_iBufferSize - 6; i < m_iBufferSize; i++)
			{
				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}
		}
		else
		{
			//add sentence and file size in signature as hex
			for(DWORD i = 0, iLen = strlen(m_szSentence) + 8; i < iLen; i++)
			{
				if(iSigLen && ((iSigLen - iStarCount) % 100 == 0))
				{
					iStarCount++;
					iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));
				}

				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}
			
			for(DWORD i = strlen(m_szSentence) + 8, iLen = strlen(m_szSentence) + 8 + dwFileBytesSize; i < iLen; i++)
			{
				if(iSigLen && ((iSigLen - iStarCount) % 100 == 0))
				{
					iStarCount++;
					iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));
				}

				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}

			//add DOSSIG in signature as hex
			for(DWORD i = m_iBufferSize - 6; i < m_iBufferSize; i++)
			{
				if(iSigLen && ((iSigLen - iStarCount) % 100 == 0))
				{
					iStarCount++;
					iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));
				}

				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}
		}

		return true;
	}
	/*handling small file signatures with DOSSIG at the end in buffer*/

	/********************	HANDLING OF FIRST PART OF SIGNATURE   ********************/

	memset(szSig, 0, cchSig * sizeof(TCHAR)); // Added by Ajay to test last 7 files skipping detection

	for( ; iReadBuffIndex < SIG_FIRST_PART_LEN ; iReadBuffIndex++)
	{
		_stprintf_s(szSig + (iReadBuffIndex * 2), cchSig - (iReadBuffIndex * 2), _T("%02X"), m_szScnBuffer[iReadBuffIndex]);
	}

	iTotalPartsCnt++;
	iSigLenGeneratedCnt += SIG_FIRST_PART_LEN;

	/********************	  END 	 ********************/

	/********************	HANDLING OF FIRST_BUT_OTHER PARTS OF SIGNATURE   ********************/

	int		iMatchCnt = 0;
	bool	bValidSigPart = true;
	int		iPartStartBuffIndex = 0;
	int		iDummyIndx = 0;
	int		iLastIndexToCompare = 0;
	bool	bWhileLoopFlag4Overlay = false;
	bool	bOverlayChecked = false;
	bool	bCurPartConcatenated = false;
	DWORD	dwMaxSigSize = m_bFlag4Overlay ? MAX_SIG_LEN + SIG_FIRST_BUT_OTHER_PARTS_LEN : MAX_SIG_LEN;

	//while(true)
	while(iSigLenGeneratedCnt < dwMaxSigSize)
	{
		iMatchCnt = 0;
		bValidSigPart = true;
		iPartStartBuffIndex = 0;
		iLastIndexToCompare = 0;
		bWhileLoopFlag4Overlay = false;

		//Traversing the buffer till Zeros or 90's or 3 Consecutive characters are NOT Encountered
		//Idea is to Discard these Non Required bytes from the Consideration (Dummy) buffer
		//m_iBufferSize is always greater than 0x200

		for ( ; (DWORD)iReadBuffIndex < m_iBufferSize - 3; iReadBuffIndex++)
		{
			if( 0x00 == m_szScnBuffer[iReadBuffIndex] ||
			    0x90 == m_szScnBuffer[iReadBuffIndex] ||
				m_szScnBuffer[iReadBuffIndex] == m_szScnBuffer[iReadBuffIndex + 1] ||  //1st and 2nd byte same
				m_szScnBuffer[iReadBuffIndex] == m_szScnBuffer[iReadBuffIndex + 2] ||  //2nd and 3rd byte same 
				m_szScnBuffer[iReadBuffIndex + 1] == m_szScnBuffer[iReadBuffIndex + 2]) //1st and 3rd byte same
			{
				continue;
			}
			else
			{
				//Not Zeros, Not 90's, Not 3 Consecutive characters Repetitive Found.
				//So Data must be Read into Consideration (Dummy) buffer.
				break;
			}
		}

		if((DWORD)iReadBuffIndex >= m_iBufferSize - 3)
		{
			break;
		}

		iPartStartBuffIndex = iReadBuffIndex;

		//Check if Remaining bytes in buffer is sufficiently available for the signature (not just the part) 
		//to be created

		if((m_iBufferSize - (DWORD)iPartStartBuffIndex) <= (MAX_SIG_LEN - ((DWORD)iSigLenGeneratedCnt)))
		{
			return false;
		}

		iDummyIndx = 0;
		memset(szDummy, 0, _countof(szDummy)); //Added by Ajay for the last 8 samples. Change done by Anand Sir
		
		//Sufficient bytes exists. So copy Req bytes from Read buffer to Consideration (Dummy) buffer

		for(int i = 0; iReadBuffIndex < (iPartStartBuffIndex + SIG_FIRST_BUT_OTHER_PARTS_LEN) ; iReadBuffIndex++,  iDummyIndx += 2, i++)
		{
			//Added on Tuesday Night. Change done by Anand Sir
			if((DWORD)iReadBuffIndex >= m_iBufferSize)
			{
				return false;
			}
			_stprintf_s(szDummy + (i * 2), _countof(szDummy) - (i * 2), L"%02X", m_szScnBuffer[iReadBuffIndex]);
		}

		//Check if Overlay Index in Buffer is Reached and then Restart the loop for the Overlay Sig Part

		if(iReadBuffIndex >= m_iOverlayStartIndexInBuff && !bOverlayChecked && m_bFlag4Overlay)
		{
			bOverlayChecked = true;
			iReadBuffIndex = m_iOverlayStartIndexInBuff;
			continue;
		}

		//iPercentageVal is the Max No of Times a byte can occur in a part.
		//It is subject to iAccuracy Val set as Macro and is actually some Percentage of the Sig Part.

		iPercentageVal = (int) PERCENTAGE(SIG_FIRST_BUT_OTHER_PARTS_LEN);

		//0x26 bytes are Read in Dummy Buffer.
		//Verify if Valid Bytes Present from which Signature can be Picked
		//else Discard this Buffer and Consider another part

		iLastIndexToCompare = iPartStartBuffIndex + SIG_FIRST_BUT_OTHER_PARTS_LEN - iPercentageVal;

		for(int i = iPartStartBuffIndex ; i < iLastIndexToCompare ; i++)
		{
			for(int j = i + 1 ; j < (iPartStartBuffIndex + SIG_FIRST_BUT_OTHER_PARTS_LEN) ; j++)
			{
				if(m_szScnBuffer[i] == m_szScnBuffer[j])
				{
					iMatchCnt++;
					if(iMatchCnt >= iPercentageVal)
					{
						bValidSigPart = false;
						break;
					}
				}
			}

			iMatchCnt = 0;

			if(false == bValidSigPart)
			{
				break;
			}
		}

		//Dummy Buffer verfied and Signature Part can be picked from it.
		if(bValidSigPart)
		{
			//For Without overlay Handling
			if(!m_bFlag4Overlay)
			{
				_tcscat_s(szSig, cchSig, L"*");
				_tcscat_s(szSig, cchSig, szDummy);
				iTotalPartsCnt++;
				iSigLenGeneratedCnt += SIG_FIRST_BUT_OTHER_PARTS_LEN;
			}
			else 
			{
				if(bOverlayChecked && iTotalPartsCnt <= MAX_PARTS_CNT) //With Overlay Handling
				{
					_tcscat_s(szSig, cchSig, L"*");
					_tcscat_s(szSig, cchSig, szDummy);
					bCurPartConcatenated = true;
					iTotalPartsCnt++;
					iSigLenGeneratedCnt += SIG_FIRST_BUT_OTHER_PARTS_LEN;
				}
				else if(iTotalPartsCnt < MAX_PARTS_CNT)
				{
					_tcscat_s(szSig, cchSig, L"*");
					_tcscat_s(szSig, cchSig, szDummy);
					bCurPartConcatenated = true;
					iTotalPartsCnt++;
					iSigLenGeneratedCnt += SIG_FIRST_BUT_OTHER_PARTS_LEN;
				}
			}

			if(!m_bFlag4Overlay)
			{
				if(MAX_PARTS_CNT  == iTotalPartsCnt)
				{
					break;
				}
			}
			else
			{
				if(m_iOverlaySize <= 0x200 && MAX_PARTS_CNT == iTotalPartsCnt)
				{
					break;
				}

				if((MAX_PARTS_CNT + 1) == iTotalPartsCnt )
				{
					break;
				}
			}
		}
	}//while(true)

	/****************************	  END 	 ******************************/

	int	iZeroCnt = 0x00;
	iReadBuffIndex = 0x00;
	iSigLen = _tcslen(szSig);
	for(iReadBuffIndex = 0x1A ; iReadBuffIndex < (iSigLen-1) ; iReadBuffIndex += 2)
	{
		if(szSig[iReadBuffIndex] == '*')
		{
			iReadBuffIndex--;
			continue;
		}

		if (szSig[iReadBuffIndex] == '0' && szSig[iReadBuffIndex + 1] == '0')
		{
			iZeroCnt++;
		}
	}

	if(MAX_PARTS_CNT < iTotalPartsCnt)
	{
		if(iZeroCnt > 50)
		{
			return false;
		}
	}
	else if(iZeroCnt > 40)
	{
		return false;			
	}

	if(MAX_PARTS_CNT > iTotalPartsCnt)
	{
		return false;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: GetBufferByDOSFormat
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Create cross signature for file type MS-DOS
--------------------------------------------------------------------------------------*/
bool CScanFileManager::GetBufferByDOSFormat()
{
	DWORD dwBytesRead = 0;
	StructDosHeader objDosHeader = {0};

	m_iBufferSize = 0;
	m_iOverlaySize = 0;
	m_bFlag4Overlay = false;
	m_iOverlayStartIndexInBuff = 0;

	if(!m_pMaxPEFile->ReadBuffer(&objDosHeader, 0, sizeof(StructDosHeader), sizeof(StructDosHeader)))
	{
		return false;
	}

	if(m_dwFileSize <= 1536) //1024 + 512 //0x600
	{
		
		if((sizeof(m_szScnBuffer) - m_iBufferSize) < m_dwFileSize)
		{
			return false;
		}

		dwBytesRead = 0;
		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], 0, m_dwFileSize, 0, &dwBytesRead))
		{
			return false;
		}

		m_iBufferSize += dwBytesRead;
	}
	else
	{
		int iDosFileEnd = ((objDosHeader.Pages_In_File - 1) * 512)  + objDosHeader.Bytes_On_Last_Page;

		if(objDosHeader.Pages_In_File <= 2)
		{
			return false;
		}

		if(m_dwFileSize > (DWORD)iDosFileEnd)
		{
			m_iOverlaySize = m_dwFileSize - iDosFileEnd;
			if(m_iOverlaySize && ((m_iOverlaySize & 0x80000000) != 0x80000000))
			{
				m_bFlag4Overlay = true;
			}
		}
		//02 Jun 2011
		else //25062011
		{
			iDosFileEnd = m_dwFileSize;
		}

		if((sizeof(m_szScnBuffer) - m_iBufferSize) < 0x1A)
		{
			return false;
		}

		dwBytesRead = 0x00;
		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], 0, 0x1A, 0, &dwBytesRead))
		{
			return false;
		}

		m_iBufferSize += dwBytesRead;
		dwBytesRead = 0x00;

		DWORD dwLastPgOff = ((objDosHeader.Pages_In_File - 1) * 0x200);

		//02 Jun 2011
		//To handle condition in which value of Bytes_on_Last_Page is a garbage one.
		dwBytesRead = 0x400 + objDosHeader.Bytes_On_Last_Page - 0x1A;
		if(dwBytesRead > 0x600)
		{
			dwBytesRead = 0x400 - 0x1A;			
		}

		DWORD  dwBytesToRead = dwBytesRead; 
		
		if((sizeof(m_szScnBuffer) - m_iBufferSize) < dwBytesToRead)
		{
			return false;
		}

		if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], (dwLastPgOff - 0x400 + 0x1A), dwBytesToRead, 0, &dwBytesRead))
		{
			return false;
		}

		if(0 == dwBytesRead)
		{
			return false;
		}

		m_iBufferSize += dwBytesRead;

		if(m_bFlag4Overlay)
		{
			if(0x600 >= m_iOverlaySize)
			{
				m_iOverlayStartIndexInBuff = m_iBufferSize;

				if((sizeof(m_szScnBuffer) - m_iBufferSize) < (DWORD)m_iOverlaySize)
				{
					return false;
				}

				dwBytesRead = 0x00;
				if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], m_dwFileSize - m_iOverlaySize, m_iOverlaySize, 0, &dwBytesRead))
				{
					return false;
				}

				m_iBufferSize += dwBytesRead;
			}
			else
			{
				m_iOverlayStartIndexInBuff = m_iBufferSize;
	
				if((sizeof(m_szScnBuffer) - m_iBufferSize) < 0x600)
				{
					return false;
				}

				dwBytesRead = 0x00;
				if(m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], m_dwFileSize - 0x600, 0x600, 0, &dwBytesRead))
				{
					return false;
				}

				m_iBufferSize += dwBytesRead;
			}
		}
	}

	if(m_iBufferSize < 0x200)
	{
		return false;
	}

	TCHAR szCheckSig[MAX_PATH * 2] = {0}; //max_path is enough sig size
	if(!CreateDOS32Sig(szCheckSig, _countof(szCheckSig)))
	{
		return false;
	}

	return true;
}


/*-------------------------------------------------------------------------------------
	Function		: GetBufferBySentenceFormat
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Create cross signature for file type MS-DOS in Sentense format (INI)
--------------------------------------------------------------------------------------*/
bool CScanFileManager::GetBufferBySentenceFormat()
{
	DWORD dwBytesRead = 0, dwBytesToRead = 0, cbBuffer = 0;
	LPBYTE byBuffer = NULL;

	m_iBufferSize = 0;
	memset(m_szScnBuffer, 0, sizeof(m_szScnBuffer));
	m_iOverlaySize = 0;
	m_iBufferSize = 0;
	m_bFlag4Overlay = false;
	m_iOverlayStartIndexInBuff = 0;

	//small file sentence in hex
	for(DWORD i = 0, iLen = strlen(m_szSentence); i < iLen; i++)
	{
		m_iBufferSize += sprintf_s((LPSTR)m_szScnBuffer + m_iBufferSize, sizeof(m_szScnBuffer) - m_iBufferSize, "%c", m_szSentence[i]);
	}

	//file size in hex
	m_iBufferSize += sprintf_s((LPSTR)m_szScnBuffer + m_iBufferSize, sizeof(m_szScnBuffer) - m_iBufferSize, "%08u", m_dwFileSize);

	//format of data to be put in m_szScnBuffer: Sentence0000FileSizeFileBytesDOSSIG
	cbBuffer = sizeof(m_szScnBuffer) - (m_iBufferSize + strlen(m_szDOSSIG) + 1);
	byBuffer = m_szScnBuffer + m_iBufferSize;
	
	// if our read buffer is larger than file size read full file
	if(cbBuffer >= m_dwFileSize)
	{
		if(!m_pMaxPEFile->ReadBuffer(byBuffer, 0, cbBuffer, 0, &dwBytesRead))
		{
			return false;
		}
	}
	else
	{
		DWORD dwTotalBytesRead = 0;

		dwBytesToRead = cbBuffer / 2;

		if(!m_pMaxPEFile->ReadBuffer(byBuffer, 0, dwBytesToRead, 0, &dwBytesRead))
		{
			return false;
		}

		if(!m_pMaxPEFile->SetFilePointer(-(LONG)dwBytesToRead, 0, FILE_END))
		{
			return false;
		}

		dwTotalBytesRead = dwBytesRead;
		dwBytesRead = 0;

		if(!m_pMaxPEFile->ReadBuffer(byBuffer + dwTotalBytesRead, dwBytesToRead, &dwBytesRead))
		{
			return false;
		}

		dwTotalBytesRead += dwBytesRead;
		dwBytesRead = dwTotalBytesRead;
	}

	//non null bytes of file in hex
	for(DWORD i = 0; i < dwBytesRead; i++)
	{
		if(i >= 1 && byBuffer[i - 1] == byBuffer[i])
		{
			;
		}
		else
		if(i >= 2 && byBuffer[i - 2] == byBuffer[i])
		{
			;
		}
		else
		if(byBuffer[i])
		{
			m_szScnBuffer[m_iBufferSize++] = byBuffer[i];
		}
	}

	//DOSSIG in hex
	for(DWORD i = 0, iLen = strlen(m_szDOSSIG); i < iLen; i++)
	{
		m_iBufferSize += sprintf_s((LPSTR)m_szScnBuffer + m_iBufferSize, sizeof(m_szScnBuffer) - m_iBufferSize, "%c", m_szDOSSIG[i]);
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenDOSFile4ScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: opens file for scanning : file type MS-DOS
--------------------------------------------------------------------------------------*/
int CScanFileManager::OpenDOSFile4ScanningEx()
{
	//10 Aug 2011 : DOS Changes
	if(m_dwFileSize > 512)
	{
		if(GetBufferByDOSFormat())
		{
			return ERR_SUCCESS;
		}

		if(GetBufferBySentenceFormat())
		{
			return ERR_SUCCESS;
		}
	}
	else
	{
		if(GetBufferBySentenceFormat())
		{
			return ERR_SUCCESS;
		}
	}

	return !ERR_SUCCESS;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenWMAFile4ScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: opens file for scanning : file type WMA (Windows media accelarator
--------------------------------------------------------------------------------------*/
int CScanFileManager::OpenWMAFile4ScanningEx()
{
	InitScanBuffer();

	DWORD dwBytesRead = 0, dwAEP = 0;	
	if(!m_pMaxPEFile->ReadBuffer(&dwAEP, 0x10, sizeof(DWORD), sizeof(DWORD), &dwBytesRead))
	{
		return ERR_IN_READING_FILE;
	}
	if(dwAEP > m_dwFileSize)
	{
		return ERR_INVALID_FILE;
	}

	if (dwAEP < 0x200)
	{
		dwBytesRead = dwAEP;
		dwAEP = 0;
	}
	else
	{
		dwBytesRead = 0x200;
		dwAEP  =  dwAEP - 0x200;
	}
	if(!m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], dwAEP, dwBytesRead, 0, &dwBytesRead))
	{
		return ERR_IN_READING_FILE;
	}
	m_iBufferSize = m_iBufferSize + dwBytesRead;

	return ERR_SUCCESS;
}

/******************************************************************************
Function Name	:	Check4WMAFileEx
Author			:	Tushar Kadam
Scope			:	Private
Input			:	
Output			:   int --> (Success) One of the File Type given below
							(Fail) 0
 05			WMA + MP3 file (Media Files)
*******************************************************************************/
bool CScanFileManager::Check4COM16FileEx()
{
	if(m_dwFileSize < 0x100000)
	{
		return true;
	}
	
	TCHAR *szExt = _tcsrchr(m_szFile2Scan, _T('.'));
	if(szExt)
	{
		_tcsupr_s(szExt, _tcslen(szExt) + 1);
		if(_tcsstr(szExt,_T(".LNK")) != NULL)
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenWMAFile4ScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: opens file for scanning : file type BAT
--------------------------------------------------------------------------------------*/
bool CScanFileManager::Check4BATFileEx()
{
	if (m_dwFileSize < 0x10000)
	{
		TCHAR *szExt = _tcsrchr(m_szFile2Scan, _T('.'));
		if(szExt)
		{
			_tcsupr_s(szExt, _tcslen(szExt) + 1);
			if((_tcsstr(szExt,_T(".BAT")) != NULL) || (_tcsstr(szExt,_T(".INI")) != NULL) || (_tcsstr(szExt,_T(".REG")) != NULL))
			{
				return true;
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenCOMFile4ScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: opens file for scanning : file type COM
--------------------------------------------------------------------------------------*/
//AjayCOMSentenceFormat : 19 Aug 2011
int CScanFileManager::OpenCOMFile4ScanningEx()
{
	if(GetBufferByCOMFormat())
	{
		return ERR_SUCCESS;
	}
	
	if(GetCOMBufferBySentenceFormat())
	{
		return ERR_SUCCESS;
	}

	return ERR_INVALID_FILE;
}

/*-------------------------------------------------------------------------------------
	Function		: GetBufferByCOMFormat
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Gets buffer from file : file type COM
--------------------------------------------------------------------------------------*/
bool CScanFileManager::GetBufferByCOMFormat()
{	
	if(m_dwFileSize < 0x1400)	
	{
		DWORD dwBytesRead = 0;
		if(m_pMaxPEFile->ReadBuffer(m_szScnBuffer, 0, m_dwFileSize, 0, &dwBytesRead))
		{
			m_iBufferSize = dwBytesRead;
			if(m_szScnBuffer[0] == 0xFF && m_szScnBuffer[1] == 0xFE)
			{
				for(int i = 0, j = 0; i < m_iBufferSize; i = i + 2, j++)
				{					
					m_szScnBuffer[m_iBufferSize + j] = m_szScnBuffer[i];
				}
				m_iBufferSize += dwBytesRead / 2;		
			}
			return true;
		}	
	}	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetCOMBufferBySentenceFormat
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Gets buffer from file : file type COM
--------------------------------------------------------------------------------------*/
//AjayCOMSentenceFormat : 19 Aug 2011
bool CScanFileManager::GetCOMBufferBySentenceFormat()
{
	DWORD dwBytesRead = 0, dwBytesToRead = 0, cbBuffer = 0;
	LPBYTE byBuffer = NULL;

	m_iBufferSize = 0;
	memset(m_szScnBuffer, 0, sizeof(m_szScnBuffer));
	m_iOverlaySize = 0;
	m_iBufferSize = 0;
	m_bFlag4Overlay = false;
	m_iOverlayStartIndexInBuff = 0;

	//small file sentence in bytes
	for(DWORD i = 0, iLen = strlen(m_szSentence); i < iLen; i++)
	{
		m_iBufferSize += sprintf_s((LPSTR)m_szScnBuffer + m_iBufferSize, sizeof(m_szScnBuffer) - m_iBufferSize, "%c", m_szSentence[i]);
	}

	//file size in hex
	m_iBufferSize += sprintf_s((LPSTR)m_szScnBuffer + m_iBufferSize, sizeof(m_szScnBuffer) - m_iBufferSize, "%08u", m_dwFileSize);

	//format of data to be put in m_szScnBuffer: Sentence0000FileSizeFileBytesCOMSIG
	cbBuffer = sizeof(m_szScnBuffer) - (m_iBufferSize + strlen(m_szCOMSIG) + 1);
	byBuffer = m_szScnBuffer + m_iBufferSize;

	// if our read buffer is larger than file size read full file
	if(cbBuffer >= m_dwFileSize)
	{
		if(!m_pMaxPEFile->ReadBuffer(byBuffer, 0, cbBuffer, 0, &dwBytesRead))
		{
			return false;
		}
	}
	else
	{
		DWORD dwTotalBytesRead = 0;

		dwBytesToRead = cbBuffer / 2;

		if(!m_pMaxPEFile->ReadBuffer(byBuffer, 0, dwBytesToRead, 0, &dwBytesRead))
		{
			return false;
		}

		if(!m_pMaxPEFile->SetFilePointer(-(LONG)dwBytesToRead, 0, FILE_END))
		{
			return false;
		}

		dwTotalBytesRead = dwBytesRead;
		dwBytesRead = 0;

		if(!m_pMaxPEFile->ReadBuffer(byBuffer + dwTotalBytesRead, dwBytesToRead, &dwBytesRead))
		{
			return false;
		}

		dwTotalBytesRead += dwBytesRead;
		dwBytesRead = dwTotalBytesRead;
	}

	//non null bytes of file in hex
	for(DWORD i = 0; i < dwBytesRead; i++)
	{
		if(i >= 1 && byBuffer[i - 1] == byBuffer[i])
		{
			;
		}
		else
		if(i >= 2 && byBuffer[i - 2] == byBuffer[i])
		{
			;
		}
		else
		if(byBuffer[i])
		{
			m_szScnBuffer[m_iBufferSize++] = byBuffer[i];
		}
	}

	//COMSIG in bytes
	for(DWORD i = 0, iLen = strlen(m_szCOMSIG); i < iLen; i++)
	{
		m_iBufferSize += sprintf_s((LPSTR)m_szScnBuffer + m_iBufferSize, sizeof(m_szScnBuffer) - m_iBufferSize, "%c", m_szCOMSIG[i]);
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CreateDOS16Sig
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Create cross signature for DOC file (16 bit)
--------------------------------------------------------------------------------------*/
//AjayCOMSentenceFormat : 19 Aug 2011
bool CScanFileManager::CreateDOS16Sig(LPTSTR szSig, DWORD cchSig)
{
	int		iSigLen = 0, iStarCount = 0;
	DWORD	dwNonFileBytesSize = 0, dwFileBytesSize = 0;

	/*handling small file signatures with COMSIG at the end in buffer*/
	if(m_iBufferSize > 6 && !memcmp(m_szScnBuffer + (m_iBufferSize - 6), m_szCOMSIG, 6))
	{
		dwNonFileBytesSize = strlen(m_szSentence) + strlen(m_szCOMSIG) + 8;
		dwFileBytesSize = m_iBufferSize - dwNonFileBytesSize;

		if(dwFileBytesSize > 200)
		{
			if((200 + dwNonFileBytesSize + 2) * sizeof(TCHAR) >= cchSig)
			{
				return false;
			}
		}
		else
		{
			if((dwFileBytesSize + dwNonFileBytesSize + 2) * sizeof(TCHAR) >= cchSig)
			{
				return false;
			}
		}

		memset(szSig, 0, cchSig * sizeof(TCHAR));

		//add data read from file in signature as hex
		if(dwFileBytesSize > 200)
		{
			//add sentence and file size in signature as hex
			for(DWORD i = 0, iLen = strlen(m_szSentence) + 8; i < iLen; i++)
			{
				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}

			iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));

			for(DWORD i = strlen(m_szSentence) + 8, iLen = strlen(m_szSentence) + 8 + 100; i < iLen; i++)
			{
				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}

			iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));

			for(DWORD i = m_iBufferSize - (100 + 6); i < m_iBufferSize - 6; i++)
			{
				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}

			iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));

			//add COMSIG in signature as hex
			for(DWORD i = m_iBufferSize - 6; i < m_iBufferSize; i++)
			{
				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}
		}
		else
		{
			//add sentence and file size in signature as hex
			for(DWORD i = 0, iLen = strlen(m_szSentence) + 8; i < iLen; i++)
			{
				if(iSigLen && ((iSigLen - iStarCount) % 100 == 0))
				{
					iStarCount++;
					iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));
				}

				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}
			
			for(DWORD i = strlen(m_szSentence) + 8, iLen = strlen(m_szSentence) + 8 + dwFileBytesSize; i < iLen; i++)
			{
				if(iSigLen && ((iSigLen - iStarCount) % 100 == 0))
				{
					iStarCount++;
					iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));
				}

				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}

			//add COMSIG in signature as hex
			for(DWORD i = m_iBufferSize - 6; i < m_iBufferSize; i++)
			{
				if(iSigLen && ((iSigLen - iStarCount) % 100 == 0))
				{
					iStarCount++;
					iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%s"), _T("*"));
				}

				iSigLen += _stprintf_s(szSig + iSigLen, cchSig - iSigLen, _T("%02X"), m_szScnBuffer[i]);
			}
		}

	/*END OF handling small file signatures with DOSSIG at the end in buffer*/
	}//if end for OLD Logic and SENTENCE format seperation...
	else
	{
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		///												OLD LOGIC															 ///	
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		TCHAR	szDummy[5] = {0};
		int		iCnt = 0x00;
		int		j = 0x00;
		bool	bSigPartFound = false, bLower2ndPartTaken = false;

		memset(szSig, 0, cchSig * sizeof(TCHAR));

		if(m_iBufferSize < 0xC3)
		{
			return false;
		}

		//Tushar ==> First Part
		for(iCnt = 0; iCnt < 24 ;iCnt++)
		{
			_stprintf_s(szDummy, 5, L"%02X", m_szScnBuffer[iCnt + j]);
			_tcscat_s(szSig, cchSig, szDummy);
		}
		_tcscat_s(szSig, cchSig, L"*");

		//Tushar ==> Second Part
		for(iCnt = 80; iCnt < 125; iCnt++)
		{
			if(m_szScnBuffer[iCnt] != 0x00  && m_szScnBuffer[iCnt] != 0x90 && (m_szScnBuffer[iCnt] != m_szScnBuffer[iCnt+1]))
			{
				for(j = 0; j < 16; j++)
				{
					_stprintf_s(szDummy, 5, L"%02X", m_szScnBuffer[iCnt + j]);
					_tcscat_s(szSig, cchSig, szDummy);
				}

				bSigPartFound = true;
				bLower2ndPartTaken = true;
				break;
			}
		}

		if(bSigPartFound == false)
		{
			for(iCnt = 24; iCnt < 40; iCnt++)
			{
				_stprintf_s(szDummy, 5, L"%02X", m_szScnBuffer[iCnt]);
				_tcscat_s(szSig, cchSig, szDummy);
			}
		}

		bSigPartFound = false;

		//Tushar ==> Third Part
		for(iCnt = 135; iCnt < 195; iCnt++)
		{
			if(m_szScnBuffer[iCnt] != 0x00 && m_szScnBuffer[iCnt] != 0x90 && (m_szScnBuffer[iCnt] != m_szScnBuffer[iCnt+1]))
			{
				_tcscat_s(szSig, cchSig, L"*");

				for(j = 0; j < 16; j++)
				{
					_stprintf_s(szDummy, 5, L"%02X", m_szScnBuffer[iCnt + j]);
					_tcscat_s(szSig, cchSig, szDummy);
				}

				bSigPartFound = true;
				break;
			}
		}

		if(bSigPartFound == false && !bLower2ndPartTaken)
		{
			_tcscat_s(szSig, cchSig, L"*");
			for(iCnt = 40; iCnt < 56; iCnt++)
			{
				_stprintf_s(szDummy, 5, L"%02X", m_szScnBuffer[iCnt]);
				_tcscat_s(szSig, cchSig, szDummy);
			}
		}

		bSigPartFound = false;
		bool bFlag = false;

		//14042011 :- Ajay : 4th Part Sig
		//Extended Signature Part by Ajay :- As Virus Code Generally lies in the end of the file
		if(m_iBufferSize > (0xC3 + 0x96))
		{
			//1st Consider 0x96 bytes
			for (iCnt = m_iBufferSize - 0x96 /*195*/; iCnt < m_iBufferSize ;iCnt++)
			{
				if (m_szScnBuffer[iCnt] != 0x00 && m_szScnBuffer[iCnt] != 0x90 && (m_szScnBuffer[iCnt] != m_szScnBuffer[iCnt+1]))
				{
					if((m_iBufferSize - iCnt) < 10)  // To ensure last part contains atleast 10 bytes
						break;

					_tcscat_s(szSig, cchSig, L"*");

					for (j = 0; j < 24 && j<(m_iBufferSize - iCnt); j++)
					{
						_stprintf_s(szDummy, 5, L"%02X", m_szScnBuffer[iCnt + j]);
						_tcscat_s(szSig, cchSig, szDummy);
					}

					bSigPartFound = true;
					break;
				}
			}

			if(bSigPartFound == false)
			{
				for(iCnt = 0xC3; iCnt < m_iBufferSize-0x96 ;iCnt++)
				{
					if(m_szScnBuffer[iCnt] != 0x00 && m_szScnBuffer[iCnt] != 0x90 && (m_szScnBuffer[iCnt] != m_szScnBuffer[iCnt+1]))
					{
						if((m_iBufferSize - iCnt) < 16)  // To ensure last part contains atleast 16 bytes
							break;

						_tcscat_s(szSig, cchSig, L"*");

						for(j = 0; j < 24 && j<(m_iBufferSize - iCnt); j++)
						{
							_stprintf_s(szDummy, 5, L"%02X", m_szScnBuffer[iCnt + j]);
							_tcscat_s(szSig, cchSig, szDummy);
						}

						bSigPartFound = true;
						break;
					}
				}
			}
		}
		else if( m_iBufferSize > 0xC3 && m_iBufferSize <=  (0xC4 + 0x96) && bSigPartFound == false) /*bSigPartFound == false*/
		{
			for(iCnt = 0xC4/*m_iBufferSize-0x96*/ /*195*/; iCnt < m_iBufferSize ;iCnt++)
			{
				if(m_szScnBuffer[iCnt] != 0x00 && m_szScnBuffer[iCnt] != 0x90 && (m_szScnBuffer[iCnt] != m_szScnBuffer[iCnt+1]))
				{
					if((m_iBufferSize - iCnt) < 16)  // To ensure last part contains atleast 16 bytes
						break;

					_tcscat_s(szSig, cchSig, L"*");

					for(j = 0; j < 24 && j<(m_iBufferSize - iCnt); j++)
					{
						_stprintf_s(szDummy, 5, L"%02X", m_szScnBuffer[iCnt + j]);
						_tcscat_s(szSig, cchSig, szDummy);
					}

					bSigPartFound = true;
					break;
				}
			}
		}

		int iZeroCnt = 0x00, iWildCharCnt=0x00;
		j = _tcslen(szSig);
		for(iCnt = 0x00; iCnt < j - 1; iCnt += 2)
		{
			if(szSig[iCnt] == '*')
			{
				iWildCharCnt++;
				iCnt--;
				continue;
			}

			if(szSig[iCnt] == '0' && szSig[iCnt+1] == '0')
				iZeroCnt++;
		}

		if(iZeroCnt > 30)
		{
			return false;
		}

		//29042011 :- Ajay - To skip sigs with just 1 *
		if(iWildCharCnt < 0x02)
		{
			return false;
		}

	}//else for OLD LOGIC and SENTENCE format seperation

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenBATFile4ScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Open file for scanning : file type BAT
--------------------------------------------------------------------------------------*/
int CScanFileManager::OpenBATFile4ScanningEx()
{
	DWORD	dwReadByte = 0x00;
	if (m_dwFileSize == 0x0)
	{
		return ERR_ZERO_LEN_FILE;
	}

	InitScanBuffer();

	if(!m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[0], 0, 0x5000, 0, &dwReadByte))
	{
		return ERR_IN_READING_FILE;
	}

	DWORD	dwCountPrev = 0x00;
	byte	by=0x00;
	for(DWORD dwCount = 0; dwCount <= dwReadByte; dwCount++)
	{
		by = m_szScnBuffer[dwCount];
		if((by >= 0x41) && (by <= 0x5A))
		{
			by+=0x20;
		}
		if((by <= 0x20) || (by == 0xFF) || (by == 0xFE))
		{
			continue;
		}
		else
			m_szScnBuffer[dwCountPrev++] = by;
	}
	m_iBufferSize = dwCountPrev;

	return ERR_SUCCESS;
}

int CScanFileManager::OpenInfFile4ScanningEx()
{
	m_iBufferSize = sizeof(m_szScnBuffer);
	memset(m_szScnBuffer, 0, sizeof(m_szScnBuffer));
	return m_objMaxInf.GetBuffer(m_szScnBuffer, (DWORD&)m_iBufferSize, m_pMaxPEFile)? ERR_SUCCESS: ERR_INVALID_FILE;
}

/******************************************************************************
Function Name	:	Check4MSOfficeFileEx
Author			:	Sourabh	
Scope			:	Private
Input			:	
Output			:   int --> (Success) One of the File Type given below
							(Fail) 0
 06			XLS + DOC file (Media Files)
*******************************************************************************/
bool CScanFileManager::Check4MSOfficeFileEx()
{
	bool			bValidOLE			= false;
	unsigned char	szHeader[8]			= {0};
	unsigned char	szSkipMSI[1]		= {0};
	unsigned char	szMSOfficeHeader[]	= {0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1};
	unsigned char	szMAGIC_VALUE_ONE[] = {0xE9};
	DWORD			dwBytesRead			= 0;

	if(m_pMaxPEFile->ReadBuffer(szHeader, 0, 8, 8))
	{
		if(memcmp(&szHeader[0], &szMSOfficeHeader[0], 0x8) == 0)
		{
			BYTE bSkipMSI = 0;
			if(m_pMaxPEFile->ReadBuffer(&bSkipMSI, 0x2C, 1, 1))
			{
				if(bSkipMSI != 0xE9)	//Skipping MSI Files
				{
					m_pMaxPEFile->CloseFile_NoMemberReset();
					m_objOLEScan.m_csFilePath = m_szFile2Scan;
					bValidOLE = m_objOLEScan.CheckForValidOLE();
					if(!m_pMaxPEFile->OpenFile_NoMemberReset(m_szFile2Scan))
					{
						m_pMaxPEFile->CloseFile();
					}
				}
			}
		}
	}

	return bValidOLE;
}

/******************************************************************************
Function Name	:	CheckForDexEx
Author			:	Tushar & Anand
Scope			:	Private
Input			:	
Output			:   true if dex file, else false
*******************************************************************************/
bool CScanFileManager::CheckForDexEx()
{
	BYTE	bDexHeader[] = {0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00};
	BYTE    bDexHeader1[] = {0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x36, 0x00};  // dex.036   added by Himanshu
	BYTE	bBuffer[0x80] = {0};
	DWORD	dwBytesRead = 0x00;

	if(!m_pMaxPEFile->ReadBuffer(bBuffer, 0, sizeof(bBuffer), 0, &dwBytesRead))
	{
		return false;
	}

	if(0x00 == dwBytesRead)
	{
		return false;
	}

	if(memcmp(&bBuffer[0x00], &bDexHeader[0x00], sizeof(bDexHeader)) == 0x00 || memcmp(&bBuffer[0x00], &bDexHeader1[0x00], sizeof(bDexHeader)) == 0x00)
	{
		return true;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForSis
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Check for valid Symbian OS file (SIS)
--------------------------------------------------------------------------------------*/
bool CScanFileManager::CheckForSis()
{
	unsigned char	szHeader[0x11] = {0};
	unsigned char	szSISHeader[] = {0x12, 0x3A, 0x00, 0x10};
	unsigned char	szSISDllHeader[] = {0x79, 0x00, 0x00, 0x10};
	unsigned char	szSISExeHeader[] = {0x7A, 0x00, 0x00, 0x10};

	if(m_pMaxPEFile->ReadBuffer(szHeader, 0x00, 0x10, 0x10))
	{
		if (memcmp(&szHeader[0x00], &szSISExeHeader[0], sizeof(szSISExeHeader)) == 0)
		{
			return true;
		}
		if (memcmp(&szHeader[0x00], &szSISDllHeader[0], sizeof(szSISDllHeader)) == 0)
		{
			return true;
		}
		if (memcmp(&szHeader[0x04], &szSISHeader[0], sizeof(szSISHeader)) == 0)
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: SendFileForNormalize
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Normalize the buffer to lower case for text base scanning (script)
--------------------------------------------------------------------------------------*/
//Tushar ==> 09 Feb 2011 : Added this function to read whole 20kb file at a time
void CScanFileManager::SendFileForNormalize(DWORD dwRead)
{	
	DWORD dwBytesRead = 0;

	m_iBufferSize = 0x00;

	if (m_dwFileSize < 0x5000)
	{
		if(!m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[0], 0, m_dwFileSize, 0, &dwBytesRead))
			return;
		m_iBufferSize = dwBytesRead;
	}
	else
	{
		if(!m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[0], 0, 0x2800, 0, &dwBytesRead))
			return;
		m_iBufferSize = dwBytesRead;

		dwBytesRead = 0x00;
		if(!m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[m_iBufferSize], (m_dwFileSize - 0x2800), 0x2800, 0, &dwBytesRead))
			return;
		m_iBufferSize+= dwBytesRead;

	}
	
	DWORD dwCountPrev = 0;
	char ch;
	for(DWORD dwCount = 0; dwCount <= m_iBufferSize; dwCount++)
	{
		ch = (char)m_szScnBuffer[dwCount];
		if((ch >= 'a') && (ch <= 'z') || (ch >= 'A') && (ch <= 'Z'))
		{
			if(isupper(ch))
			{
				ch = tolower(ch);
			}
		}
		else if((ch == ' ') || (ch == '+') || (ch == '*') || 
				(ch < 0x20) || (ch == 0xFF) || (ch == 0xFE))
		{
				continue;
		}
		m_szScnBuffer[dwCountPrev++] = ch;
	}
	m_iBufferSize = dwCountPrev;
	
}

/*-------------------------------------------------------------------------------------
	Function		: Check4OtherFileTypes
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Check for file types that we don't scan (header based banary checking)
--------------------------------------------------------------------------------------*/
int CScanFileManager::Check4OtherFileTypes()
{
	BYTE		bELFSig[]		= {0x7F, 0x45, 0x4C, 0x46};
	BYTE		bRARSig[]		= {0x52, 0x61, 0x72, 0x21};
	BYTE		bZIPSig[]		= {0x50, 0x4B, 0x03, 0x04};
	BYTE		bZIPSig_1[] 	= {0x50, 0x4B, 0x30, 0x30, 0x50, 0x4B, 0x03, 0x04};
	BYTE		bGZipSig[]		= {0x1F, 0x8B};
	BYTE		bBZipSig[]		= {0x42, 0x5A, 0x68};
	BYTE		bARJSig[]		= {0x60, 0xEA};
	BYTE		bMSSZDDSig[]	= {0x53, 0x5A,0x44,0x44};
	BYTE		bMSCABSig[] 	= {0x4D,0x53,0x43,0x46};
	BYTE		bMSCHMSig[] 	= {0x49,0x54,0x53,0x46};
	BYTE		bGIFSig[]		= {0x47,0x49,0x46};
	BYTE		bBMPSig[]		= {0x42,0x4D};
	BYTE		bJPEGSig[]		= {0xFF,0xD8,0xFF};
	BYTE		bPNGSig[]		= {0x89,0x50,0x4E,0x47};	

	BYTE		bJPEGSig_1[]	= {0x4A,0x46,0x49,0x46}; //Offset : 0x06
	BYTE		bJPEGSig_2[]	= {0x45,0x78,0x69,0x66}; //Offset : 0x06
	BYTE		bSISSig[]		= {0x19,0x04,0x00,0x10}; //Offset : 0x08

	BYTE		bPDFSig[]		= {0x25, 0x50, 0x44, 0x46};
	BYTE		bMSISig[]		= {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
	BYTE		bFLVSig[]		= {0x46, 0x4C, 0x56};
	BYTE		bCURSig[]		= {0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x20, 0x20, 0x00, 0x00};
	BYTE		bICONSig[]		= {0x00, 0x00, 0x01, 0x00};

	BYTE		bHeaderBuff[25] = {0};
			
	if(!m_pMaxPEFile->ReadBuffer(bHeaderBuff, 0, 20, 20))
	{
		return 0x00;
	}

	if (memcmp(&bHeaderBuff[0],bELFSig,0x4) == 0x00)
		return VIRUS_FILE_TYPE_ELF;
	if (memcmp(&bHeaderBuff[0],bRARSig,0x4) == 0x00)
		return VIRUS_FILE_TYPE_RAR;
	if (memcmp(&bHeaderBuff[0],bZIPSig,0x4) == 0x00)
		return VIRUS_FILE_TYPE_ZIP;
	if (memcmp(&bHeaderBuff[0],bZIPSig_1,0x8) == 0x00)
		return VIRUS_FILE_TYPE_ZIP;

	if (memcmp(&bHeaderBuff[0],bGZipSig,0x2) == 0x00)
		return VIRUS_FILE_TYPE_GZ;
	if (memcmp(&bHeaderBuff[0],bBZipSig,0x3) == 0x00)
		return VIRUS_FILE_TYPE_BZ;
	if (memcmp(&bHeaderBuff[0],bARJSig,0x2) == 0x00)
		return VIRUS_FILE_TYPE_ARJ;
	if (memcmp(&bHeaderBuff[0],bMSSZDDSig,0x4) == 0x00)
		return VIRUS_FILE_TYPE_MSSZDD;
	if (memcmp(&bHeaderBuff[0],bMSCABSig,0x4) == 0x00)
		return VIRUS_FILE_TYPE_MSCAB;

	if (memcmp(&bHeaderBuff[0],bMSCHMSig,0x4) == 0x00)
		return VIRUS_FILE_TYPE_MSCHM;
	if (memcmp(&bHeaderBuff[0],bGIFSig,0x3) == 0x00)
		return VIRUS_FILE_TYPE_GIF;
	if (memcmp(&bHeaderBuff[0],bBMPSig,0x2) == 0x00)
		return VIRUS_FILE_TYPE_BMP;
	if (memcmp(&bHeaderBuff[0],bJPEGSig,0x3) == 0x00)
		return VIRUS_FILE_TYPE_JPEG;
	if (memcmp(&bHeaderBuff[0],bPNGSig,0x4) == 0x00)
		return VIRUS_FILE_TYPE_PNG;

	if (memcmp(&bHeaderBuff[6],bJPEGSig_1,0x4) == 0x00)
		return VIRUS_FILE_TYPE_JPEG;
	if (memcmp(&bHeaderBuff[6],bJPEGSig_2,0x4) == 0x00)
		return VIRUS_FILE_TYPE_JPEG;
	if (memcmp(&bHeaderBuff[8],bSISSig,0x4) == 0x00)
		return VIRUS_FILE_TYPE_SIS;

	//if (memcmp(&bHeaderBuff[0],bPDFSig,sizeof(bPDFSig)) == 0x00)
	//	return VIRUS_FILE_TYPE_PDF;
	if (memcmp(&bHeaderBuff[0],bMSISig,sizeof(bMSISig)) == 0x00)
		return VIRUS_FILE_TYPE_MSI;
	if (memcmp(&bHeaderBuff[0],bFLVSig,sizeof(bFLVSig)) == 0x00)
		return VIRUS_FILE_TYPE_FLV;
	if (memcmp(&bHeaderBuff[0],bCURSig,sizeof(bCURSig)) == 0x00)
		return VIRUS_FILE_TYPE_CUR;
	if (memcmp(&bHeaderBuff[0],bICONSig,sizeof(bICONSig)) == 0x00)
		return VIRUS_FILE_TYPE_ICON;
		
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForPDFFileEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Determines whether fil is PDF type
--------------------------------------------------------------------------------------*/
bool CScanFileManager::CheckForPDFFileEx()
{
	if(!m_objPDFSig.IsValidPDFFile(m_szFile2Scan, m_pMaxPEFile))
	{
		return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenPdfFileForScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Opens the PDF file for Scanning
--------------------------------------------------------------------------------------*/
int CScanFileManager::OpenPdfFileForScanningEx()
{
	m_iBufferSize = 10;
	return ERR_SUCCESS;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenDexFileForScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Opens the DEX (Android) file for Scanning
--------------------------------------------------------------------------------------*/
int CScanFileManager::OpenDexFileForScanningEx()
{
	BYTE	bBuffer[0x80] = {0};
	DWORD	dwBytesRead = 0x00;
	BOOL	bRet = FALSE;
	TCHAR	szTempSig[MAX_PATH] = {0x00};
	TCHAR	szCurChar[0x05] = {0x00};
	DWORD	i = 0x00;

	if(!m_pMaxPEFile->ReadBuffer(bBuffer, 0, sizeof(bBuffer), 0x70, &dwBytesRead))
	{
		return ERR_INVALID_FILE;
	}
	
	m_dwTotalDataSize = *(DWORD *)&bBuffer[0x68];
	m_dwStartOffDex = *(DWORD *)&bBuffer[0x6C];

	//1 : File Size in Bytes
	for(i = 0x20; i < 0x24; i++)
	{
		if(bBuffer[i] != 0x00)
		{
			_stprintf_s(szCurChar, 0x05, L"%02X", bBuffer[i]);
			_tcscat_s(szTempSig, _countof(szTempSig), szCurChar);
		}
	}

	//2 : Number of classes in the class list
	for(i = 0x38; i < 0x3C; i++)
	{
		if(bBuffer[i] != 0x00)
		{
			_stprintf_s(szCurChar, 0x05, L"%02X", bBuffer[i]);
			_tcscat_s(szTempSig, _countof(szTempSig), szCurChar);
		}
	}

	//3 : Absolute offset of the class list & Number of fields in the field table
	for(i = 0x40; i < 0x48; i++)
	{
		if(bBuffer[i] != 0x00)
		{
			_stprintf_s(szCurChar, 0x05, L"%02X", bBuffer[i]);
			_tcscat_s(szTempSig, _countof(szTempSig), szCurChar);
		}
	}

	//4 & 5: 
	// 1 : Number of methods in the method table
	// 2 : Absolute offset of the method table
	// 3 : Number of class definitions in the class definition table
	// 4 : Absolute offset of the class definition table
	for(i = 0x4C; i < 0x5C; i++)
	{
		if(bBuffer[i] != 0x00)
		{
			_stprintf_s(szCurChar, 0x05, L"%02X", bBuffer[i]);
			_tcscat_s(szTempSig, _countof(szTempSig), szCurChar);
		}
	}

	//6 : Extended Header
	for(i = 0x60; i < 0x70; i++)
	{
		if(bBuffer[i] != 0x00)
		{
			_stprintf_s(szCurChar, 0x05, L"%02X", bBuffer[i]);
			_tcscat_s(szTempSig, _countof(szTempSig), szCurChar);
		}
	}

	if(0x00 >= _tcslen(szTempSig))
	{
		return ERR_INVALID_FILE;
	}

	_tcscpy_s((LPTSTR)m_szScnBuffer, sizeof(m_szScnBuffer) / sizeof(TCHAR), szTempSig);
	m_iBufferSize = _tcslen((LPTSTR)m_szScnBuffer);
	return ERROR_SUCCESS;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenSisFileForScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Opens the SIS (Symbian) file for Scanning
--------------------------------------------------------------------------------------*/
int CScanFileManager::OpenSisFileForScanningEx()
{
	DWORD	dwReadByte = 0x00;

	if (m_dwFileSize == 0x0)
	{
		return ERR_ZERO_LEN_FILE;
	}

	if (m_dwFileSize > 0x5000)
	{
		if(!m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[0], 0, 0x2800, 0, &dwReadByte))
		{
			return ERR_IN_READING_FILE;
		}

		m_iBufferSize = dwReadByte;
		dwReadByte = 0x00;
		if(!m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[0], m_dwFileSize - 0x2800,0x2800, 0, &dwReadByte))
		{
			return ERR_IN_READING_FILE;
		}

		m_iBufferSize += dwReadByte;
	}
	else
	{
		if(!m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[0], 0, m_dwFileSize, 0, &dwReadByte))
		{
			return ERR_IN_READING_FILE;
		}

		m_iBufferSize = dwReadByte;
	}

	return ERR_SUCCESS;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenELFFileForScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Opens the ELF file for Scanning
--------------------------------------------------------------------------------------*/
int CScanFileManager::OpenELFFileForScanningEx()
{
	m_iBufferSize = sizeof(m_szScnBuffer);
	memset(m_szScnBuffer, 0, sizeof(m_szScnBuffer));
	return m_objMaxELF.GetBuffer(m_szScnBuffer, (DWORD&)m_iBufferSize, m_pMaxPEFile)? ERR_SUCCESS: ERR_INVALID_FILE;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenMACFileForScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Opens the MAC file for Scanning
--------------------------------------------------------------------------------------*/
int CScanFileManager::OpenMACFileForScanningEx()
{
	m_iBufferSize = sizeof(m_szScnBuffer);
	memset(m_szScnBuffer, 0, sizeof(m_szScnBuffer));
	return m_pMacFile->GetBuffer(m_szScnBuffer, (DWORD&)m_iBufferSize)? ERR_SUCCESS: ERR_INVALID_FILE;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForRegFile
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Check for valid registry file
--------------------------------------------------------------------------------------*/
bool CScanFileManager::CheckForRegFile()
{
	BYTE	bRegSigV4[] = {0x52, 0x45, 0x47, 0x45, 0x44, 0x49, 0x54, 0x34}; 
	BYTE	bRegSig[] = {0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 
		0x00, 0x20, 0x00, 0x52, 0x00, 0x65, 0x00, 0x67, 0x00, 0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 
		0x72, 0x00, 0x79, 0x00, 0x20, 0x00, 0x45, 0x00, 0x64, 0x00, 0x69, 0x00, 0x74, 0x00};

	BYTE	pszBuffer[0x30] = {0};

	if(m_pMaxPEFile->ReadBuffer(&pszBuffer[0x00], 0x00, 0x30, 0x30))
	{
		for(int i = 0x00; i < 0x04; i++)
		{
			if ((memcmp(&pszBuffer[i], &bRegSig[0], sizeof(bRegSig)) == 0) || (memcmp(&pszBuffer[i], &bRegSigV4[0], sizeof(bRegSigV4)) == 0))
			{
				return true;
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: OpenREGFileForScanningEx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Opens the Registry Export file for Scanning
--------------------------------------------------------------------------------------*/
int CScanFileManager::OpenREGFileForScanningEx()
{
	if (m_dwFileSize == 0x0)
	{
		return ERR_ZERO_LEN_FILE;
	}

	InitScanBuffer();

	DWORD	dwReadByte = 0x00;
	if (m_dwFileSize > 0x5000)
	{
		if(!m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[0], 0, 0x5000, 0, &dwReadByte))
		{
			return ERR_IN_READING_FILE;
		}
	}
	else
	{
		if(!m_pMaxPEFile->ReadBuffer(&m_szScnBuffer[0], 0, m_dwFileSize, 0, &dwReadByte))
		{
			return ERR_IN_READING_FILE;
		}
	}

	m_iBufferSize = dwReadByte;
	DWORD	dwCountPrev = 0x00;
	if (m_iBufferSize > 0x00)
	{
		for(DWORD i = 0x00; i< m_iBufferSize; i++)
		{
			if (m_szScnBuffer[i] >= 0x41 && m_szScnBuffer[i] <= 0x5A)
			{
				m_szScnBuffer[i] = m_szScnBuffer[i] + 0x20;
			}
			if (m_szScnBuffer[i] == 0x00)
			{
				continue;
			}

			m_szScnBuffer[dwCountPrev++] = m_szScnBuffer[i];
		}
		m_iBufferSize = dwCountPrev;
	}

	return ERR_SUCCESS;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForJClass
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Determines whether file is JAVA Class file
--------------------------------------------------------------------------------------*/
bool CScanFileManager::CheckForJClass()
{
	BYTE byBuffHeader[0x04] = {0};
	if(m_pMaxPEFile->ReadBuffer(byBuffHeader, 0x00, 0x04, 0x04))
	{
		if(byBuffHeader[0] == 0xCA && byBuffHeader[1] == 0xFE && byBuffHeader[2] == 0xBA && byBuffHeader[3] == 0xBE)
		{
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDexMapDetails
	In Parameters	: DWORD &dwMapOffset, DWORD &dwMapSize
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Creates Dex (Android) file mapping 
--------------------------------------------------------------------------------------*/
bool CScanFileManager::GetDexMapDetails(DWORD &dwMapOffset, DWORD &dwMapSize)
{
	DEX_HEADER objDexHeader;
	if(!m_pMaxPEFile->ReadBuffer(&objDexHeader, 0, sizeof(DEX_HEADER), sizeof(DEX_HEADER)))
	{
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(&dwMapSize, objDexHeader.Map_Off, 4, 4))
	{
		return false;
	}
	
	if(dwMapSize > m_pMaxPEFile->m_dwFileSize || dwMapSize == 0)
	{
		return false;
	}
	dwMapOffset = objDexHeader.Map_Off + 4;
	return true;	
}

/*-------------------------------------------------------------------------------------
	Function		: GetDexFileBuffer
	In Parameters	: BYTE **byBuffer, DWORD& cbBuffer
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Gets Dex (Android) file foe scanning
--------------------------------------------------------------------------------------*/
bool CScanFileManager::GetDexFileBuffer(BYTE **byBuffer, DWORD& cbBuffer)
{
	DWORD dwMapSize = 0, dwMapOffset = 0;
	if(!GetDexMapDetails(dwMapOffset, dwMapSize))
	{
		return false;
	}

	MAP_ITEM *pMapItems = new MAP_ITEM[dwMapSize];
	if(!m_pMaxPEFile->ReadBuffer(pMapItems, dwMapOffset, dwMapSize * sizeof(MAP_ITEM), dwMapSize * sizeof(MAP_ITEM)))
	{
		delete []pMapItems;
		return false;
	}
	DWORD dwCodeOffset = 0, dwCodeSize = 0, dwStringOffset = 0, dwStringSize = 0; 
	for(DWORD i = 0; i < dwMapSize; i++)
	{
		DWORD dwSizeofSection = (i == dwMapSize - 1) ? (m_pMaxPEFile->m_dwFileSize -  pMapItems[i].offset): (pMapItems[i + 1].offset - pMapItems[i].offset);
		switch(pMapItems[i].type)
		{		
		case TYPE_CODE_ITEM:
			{
				dwCodeOffset = pMapItems[i].offset;
				dwCodeSize = dwSizeofSection;
				break;
			}
		case TYPE_STRING_DATA_ITEM:			
			{
				dwStringOffset = pMapItems[i].offset;
				dwStringSize = dwSizeofSection;
				break;
			}
		}
	}
	cbBuffer = dwCodeSize + dwStringSize;
	if(cbBuffer > m_pMaxPEFile->m_dwFileSize)
	{
		delete []pMapItems;
		return false;
	}
	*byBuffer = new BYTE[cbBuffer];
	if(!byBuffer)
	{
		delete []pMapItems;
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(*byBuffer, dwCodeOffset, dwCodeSize, dwCodeSize))
	{
		delete []pMapItems;
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(*byBuffer + dwCodeSize, dwStringOffset, dwStringSize, dwStringSize))
	{
		delete []pMapItems;
		return false;
	}

	/*TCHAR szBinFilePath[MAX_PATH] = {0};
	_tcscpy_s(szBinFilePath, MAX_PATH, m_pMaxPEFile->m_szFilePath);
	_tcscat_s(szBinFilePath, MAX_PATH, L".bin");
	HANDLE hBinFile = CreateFile(szBinFilePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, 
		NULL, 
		CREATE_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN, 
		NULL);

	if(INVALID_HANDLE_VALUE != hBinFile)
	{
		DWORD dwBytesWritten = 0;
		WriteFile(hBinFile, *byBuffer, cbBuffer, &dwBytesWritten, NULL);
	}
	CloseHandle(hBinFile);*/
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: Check4LinkInfection
	In Parameters	: 
	Out Parameters	: 0 : not found, 1 : repaire, 2 : delete
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Check the link (shortcut) file for possible infection
--------------------------------------------------------------------------------------*/
int CScanFileManager::Check4LinkInfection()
{
	TCHAR *pszExt = _tcsrchr(m_szFile2Scan, _T('.'));
	if(pszExt)
	{
		_tcsupr_s(pszExt, _tcslen(pszExt) + 1);
		if(_tcsstr(pszExt,_T(".LNK")) == NULL)
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}

	HRESULT					hRes = E_FAIL;
    CComPtr<IShellLink>		ipShellLink = NULL ;
    TCHAR					szPath [ MAX_PATH ] = { 0 } ;
    TCHAR					szDesc [ MAX_PATH ] = { 0 } ;
    WIN32_FIND_DATA			wfd = { 0 } ;
    WCHAR					wszTemp [ MAX_PATH ] = { 0 } ;
	int						iDirtyLnk = 0x00;

	hRes = CoInitialize ( NULL ) ;

	// Get a pointer to the IShellLink interface
	hRes = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&ipShellLink);
	COCREATE_OUTPUTDEBUGSTRING(hRes);
	if ( FAILED ( hRes ) )
	{
		CoUninitialize() ;
		return 0x00 ;
	}

    // Get a pointer to the IPersistFile interface
    CComQIPtr<IPersistFile> ipPersistFile ( ipShellLink ) ;

    // IMP: IPersistFile is using LPCOLESTR, so make sure that the string is Unicode
    // Open the shortcut file and initialize it from its contents
    hRes = ipPersistFile -> Load ( m_szFile2Scan , STGM_READ ) ;
    if ( FAILED ( hRes ) )
    {
        CoUninitialize() ;
        return 0x00 ;
    }

   	// Get the path to the shortcut target
	TCHAR		szArguments[MAX_PATH] = {0x00};
	int			cbArguments = MAX_PATH;
	
	hRes = ipShellLink->GetArguments(szArguments, cbArguments);
	//AddLogEntry(_T("#### TUSHAR Link GetArguments: %s, %s"),m_szFile2Scan, szArguments);
	
	HRESULT		hResTmp = E_FAIL;
	TCHAR		szExePath[MAX_PATH] = {0x00};
	int			cbPathLen = MAX_PATH;

	hResTmp = ipShellLink->GetPath(szExePath, cbPathLen, &wfd, SLGP_RAWPATH);
	_tcslwr(szExePath);

	if(_tcsstr(szArguments,_T("http://127.0.0.1")) != NULL || _tcsstr(szArguments,_T("http:\\localhost")) != NULL) //Added to avoid false detection
	{
		return iDirtyLnk;
	}

	if (_tcsstr(szArguments,_T(".")) == NULL)
	{
		return iDirtyLnk;
	}

	//AddLogEntry(_T("#### TUSHAR Target Path: %s"),szExePath);
	if (_tcsstr(szExePath,_T("\\firefox.exe")) != NULL || _tcsstr(szExePath,_T("\\chrome.exe")) != NULL || _tcsstr(szExePath,_T("\\opera.exe")) != NULL || _tcsstr(szExePath,_T("\\iexplore.exe")) != NULL)		
	{
		if (_tcslen(szArguments) > 0x00)
		{
			strcpy(m_szVirusName,"Trojan.Adware.LNKInf.gen");
			iDirtyLnk = 0x01;
		}
	}

	if (iDirtyLnk == false)
	{
		CPatternFileScanner		objCPatternFileScanner;
		TCHAR					*pTemp = NULL;
		TCHAR					szArgumentsOld[MAX_PATH] = {0x00};
		
		_tcscpy(szArgumentsOld,szArguments);
		pTemp = _tcsrchr(szArguments,_T('\\'));
		if (pTemp != NULL)
		{
			pTemp++;
			_tcscpy(szArguments,pTemp);
			if (_tcsstr(szArguments,_T("\\")) == NULL)
			{
				if (_tcsstr(szExePath,_T("\\rundll32.exe")) != NULL)
				{
					if (_tcslen(szArguments) > 40)
					{
						if (_tcslen(szArgumentsOld) - _tcslen(szArguments) < 4)
						{
							if(!objCPatternFileScanner.RandomNamePatternScanner(szArguments))
							{
								strcpy(m_szVirusName,"Trojan.Adware.LNKInf.Gen1");
								iDirtyLnk = 0x02;
							}
						}
					}
				}
			}
		}
	}

	CoUninitialize() ;
	return iDirtyLnk;

}