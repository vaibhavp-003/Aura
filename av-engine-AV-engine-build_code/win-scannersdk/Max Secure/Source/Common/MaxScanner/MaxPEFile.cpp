/*======================================================================================
FILE             : MaxPEFile.cpp
ABSTRACT         : This module is core part of all scaners
DOCUMENTS	     : 
AUTHOR		     : Rupali Sonawane + Tushar Kadam + Ravi Bisht + Swapnil Shanghai
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				without the prior written permission of Aura.	

CREATION DATE    : 23/05/2010
NOTES		     : This module is handles all file related I/O operations
VERSION HISTORY  : 23 May 2010 : Comman - Basic I/O handling for FILE
				   07 Jul 2010 : Handling for 64Bit Files
				   30 Sep 2014 : Handling for buffer curruptions
				   19 Mar 2015 : Changes in Unapcker file Handling
				   05 Jun 2018 : Changes in PE Structure for ML Scanner
======================================================================================*/
#include "pch.h"
#include "MaxPEFile.h"
#include "Imagehlp.h"
#include <shlwapi.h>
#include <Shellapi.h>
#include <cmath>
#include "Resmd5.h"

using namespace std;

DWORD m_dwTotalUnPackingTime = 0;
DWORD m_dwTotalUPXPackedFiles = 0;
DWORD m_dwTotalUPXUnPackedFiles = 0;

LPFNUnpackFile CMaxPEFile::m_lpfnUnpackFile = NULL;
HMODULE CMaxPEFile::m_hUnpacker = NULL;

#define MKQWORD(h,l)	((((unsigned __int64)(h))<<32)|(l))

/*-------------------------------------------------------------------------------------
	Function		: CMaxPEFile
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CMaxPEFile::CMaxPEFile(void):
m_b64bit(false),
m_dwFileSize(0),
m_dwFileSizeHigh(0),
m_dwAEPMapped(0),
m_wAEPSec(0),
m_bPacked(false),
m_bPEFile(false),
m_bMZFound(false),
m_bPEFound(false),
m_bSecFound(false),
m_pAEPSectionBuffer(NULL),
m_dwAEPSectionSize(-1),
m_dwAEPSectionStartPos(-1),
m_byVirusRevIDs(NULL),
m_iMZOffset(0)
{
	m_hFileHandle = INVALID_HANDLE_VALUE;
	memset(&m_stPEHeader, 0, sizeof(m_stPEHeader));
	memset(&m_stPEOffsets, 0, sizeof(m_stPEOffsets));
	memset(m_stSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER) * MAX_SEC_NO);
	m_iErrCode = ERR_INCORRECT_HDR;
	wmemset(m_szFilePath, 0, MAX_PATH);
	m_dwFileSizeHigh = 0;
	m_dwFileSize = 0;
	m_dwSharedMode = MAXDWORD;
	m_dwDesirecAccess = MAXDWORD;

	m_bIsVBFile = false;	
	m_dwVBSigOff = 0x00;

	memset(&m_byAEPBuff[0x00], 0, sizeof(BYTE) * 0x100);
	_stprintf_s(m_szResourceMD5, L"");
}

/*-------------------------------------------------------------------------------------
	Function		: ~CMaxPEFile
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CMaxPEFile::~CMaxPEFile(void)
{
	CloseFile();
}

/*-------------------------------------------------------------------------------------
	Function		: CloseFile
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Close File Handle open for IO
--------------------------------------------------------------------------------------*/
void CMaxPEFile::CloseFile()
{
	m_dwAEPSectionSize = -1;
	m_dwAEPSectionStartPos = -1;
	if(m_pAEPSectionBuffer)
	{
		GlobalFree(m_pAEPSectionBuffer);
		//delete [] m_pAEPSectionBuffer;
		m_pAEPSectionBuffer = NULL;
	}

	if(INVALID_HANDLE_VALUE != m_hFileHandle)
	{
		CloseHandle(m_hFileHandle);
		m_hFileHandle = INVALID_HANDLE_VALUE;
	}
	wmemset(m_szFilePath, 0, MAX_PATH);
	m_dwFileSizeHigh = 0;
	m_dwFileSize = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: CloseFile
	In Parameters	: LPCTSTR szFilePath, bool bOpenToRepair, bool bUnpackFile
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Open File to perform I/O Operation on File
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::OpenFile(LPCTSTR szFilePath, bool bOpenToRepair, bool bUnpackFile/* = false*/)
{

	m_iMZOffset = 0;
	m_dwDesirecAccess = GENERIC_READ;
	m_dwSharedMode = FILE_SHARE_READ;
	if(bOpenToRepair)
	{
		m_dwDesirecAccess = GENERIC_READ | GENERIC_WRITE;
		SetFileAttributes(szFilePath, FILE_ATTRIBUTE_NORMAL);
	}

	CloseFile();

	wcscpy_s(m_szFilePath, szFilePath);
	m_hFileHandle = CreateFile(szFilePath, m_dwDesirecAccess, m_dwSharedMode, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(INVALID_HANDLE_VALUE == m_hFileHandle)
	{
		m_iErrCode = ERR_OPENING_FILE;
		return false;
	}

	CheckForValidPEFile(m_hFileHandle, bOpenToRepair, bUnpackFile);
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForValidPEFile
	In Parameters	: LPCTSTR szFilePath, bool bOpenToRepair, bool bUnpackFile
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Validates Microsoft executable file (PE File)
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::CheckForValidPEFile(HANDLE hFileHandle, bool bOpenToRepair, bool bUnpackFile/* = false*/)
{
	if(LoadPEFile(hFileHandle, bOpenToRepair))
	{
		DWORD dwStartTime = GetTickCount();
		if(bUnpackFile)
		{	
			if(LoadUnpackerDLL())
			{
				TCHAR szTempFilePath[MAX_PATH] = {0};
				if(1 == m_lpfnUnpackFile(m_szFilePath, szTempFilePath))
				{
					
					m_bPacked = true;
					CloseFile();
					m_dwTotalUnPackingTime += (GetTickCount() - dwStartTime);
					m_dwTotalUPXUnPackedFiles++;
					return OpenFile(szTempFilePath, bOpenToRepair);
				}
			}
		}
		m_dwTotalUnPackingTime += (GetTickCount() - dwStartTime);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: LoadPEFile
	In Parameters	: HANDLE hFileHandle, bool bOpenToRepair
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Loads Microsoft executable file (PE File) in memory
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::LoadPEFile(HANDLE hFileHandle, bool bOpenToRepair)
{
	m_bSecFound = m_bPEFile = m_bPEFound = m_bMZFound = false;

	if(INVALID_HANDLE_VALUE == hFileHandle)
	{
		return false;
	}

	m_hFileHandle = hFileHandle;
	m_dwFileSize = GetFileSize(m_hFileHandle, &m_dwFileSizeHigh);

	IMAGE_DOS_HEADER stImageDosHeader;		
	memset(&stImageDosHeader, 0, sizeof(stImageDosHeader));
	
	DWORD dwBytesRead = 0;
	if(!ReadBuffer(&stImageDosHeader, 0, sizeof(stImageDosHeader), sizeof(stImageDosHeader)))
	{
		m_iErrCode = ERR_NON_PE_FILE;
		return false;
	}
	if(stImageDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		m_iErrCode = ERR_NON_PE_FILE;
		return false;
	}

	m_bMZFound = true;
	DWORD dwSignature = 0;
	if(!ReadBuffer(&dwSignature, stImageDosHeader.e_lfanew, sizeof(DWORD), sizeof(DWORD)))
	{
		m_iErrCode = ERR_DOS_FILE;
		return false;
	}
	if(dwSignature != IMAGE_NT_SIGNATURE)
	{
		m_iErrCode = ERR_DOS_FILE;
		return false;
	}

	m_bPEFound = true;
	IMAGE_FILE_HEADER stImageFileHeader;
	memset(&stImageFileHeader, 0, sizeof(stImageFileHeader));
	
	if(!ReadBuffer(&stImageFileHeader, stImageDosHeader.e_lfanew + 4, sizeof(stImageFileHeader), sizeof(stImageFileHeader)))
	{
		return false;
	}
	if(stImageFileHeader.NumberOfSections > _countof(m_stSectionHeader) || 0 == stImageFileHeader.NumberOfSections)
	{
		return false;
	}
	m_stPEHeader.e_csum					= stImageDosHeader.e_csum;
	m_stPEHeader.e_lfanew				= stImageDosHeader.e_lfanew;
	m_stPEHeader.NumberOfSections		= stImageFileHeader.NumberOfSections;
	m_stPEHeader.Characteristics		= stImageFileHeader.Characteristics;
	m_stPEHeader.SizeOfOptionalHeader	= stImageFileHeader.SizeOfOptionalHeader;
	m_stPEHeader.NumberOfSymbols		= stImageFileHeader.NumberOfSymbols;
	
	if(IMAGE_FILE_MACHINE_IA64 == stImageFileHeader.Machine || IMAGE_FILE_MACHINE_AMD64 == stImageFileHeader.Machine)
	{
		//Read 64 bit header and fill the structure
		if(!Load64BitHeader())
		{
			return false;
		}
		m_b64bit = true;
	}
	else
	{
		// read 32 bit header and fill the structure
		if(!Load32BitHeader())
		{
			return false;
		}
	}	

	DWORD dwSectionStart = m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + m_stPEHeader.SizeOfOptionalHeader;

	memset(&m_stSectionHeader, 0, sizeof(m_stSectionHeader));
	if(!ReadBuffer(m_stSectionHeader, dwSectionStart, sizeof(m_stSectionHeader[0])* m_stPEHeader.NumberOfSections, sizeof(m_stSectionHeader[0])* m_stPEHeader.NumberOfSections))
	{
		return false;
	}

	m_bSecFound = true;
	m_wAEPSec = Rva2FileOffset(m_stPEHeader.AddressOfEntryPoint, &m_dwAEPMapped);
	if(m_wAEPSec != OUT_OF_FILE)
	{
		m_dwAEPSectionSize = m_stSectionHeader[m_wAEPSec].SizeOfRawData;
		m_dwAEPSectionStartPos = m_stSectionHeader[m_wAEPSec].PointerToRawData;
	}

	if(bOpenToRepair)
	{
		LoadOffsets();
	}

	//Added for Detection of VB Files...
	ReadBuffer(&m_byAEPBuff[0x0],m_dwAEPMapped, 0x100, 0x100); 
	m_bIsVBFile = CheckForVBFiles();

	m_bPEFile = true;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: Load32BitHeader
	In Parameters	: HANDLE hFileHandle, bool bOpenToRepair
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Loads 32 Bit Microsoft executable file (PE File) in memory
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::Load32BitHeader()
{
	DWORD dwBytesRead = 0;
	IMAGE_OPTIONAL_HEADER32 stImageOptionalHeader;
	memset(&stImageOptionalHeader, 0, sizeof(stImageOptionalHeader));
	ReadBuffer(&stImageOptionalHeader, sizeof(stImageOptionalHeader), &dwBytesRead);
	if(dwBytesRead == sizeof(stImageOptionalHeader))
	{
		m_stPEHeader.AddressOfEntryPoint		= stImageOptionalHeader.AddressOfEntryPoint;
		m_stPEHeader.CheckSum					= stImageOptionalHeader.CheckSum;
		m_stPEHeader.FileAlignment				= (0 == stImageOptionalHeader.FileAlignment) ? 0x200 : stImageOptionalHeader.FileAlignment; 
		m_stPEHeader.ImageBase					= stImageOptionalHeader.ImageBase;
		m_stPEHeader.Magic						= stImageOptionalHeader.Magic;
		m_stPEHeader.MinorLinkerVersion			= stImageOptionalHeader.MinorLinkerVersion;
		

		//Features Added for ML *************************************************
		m_stPEHeader.MajorLinkerVersion			= stImageOptionalHeader.MajorLinkerVersion;
		m_stPEHeader.SizeOfInitializedData		= stImageOptionalHeader.SizeOfInitializedData;
		m_stPEHeader.MajorOperatingSystemVersion = stImageOptionalHeader.MajorOperatingSystemVersion;
		m_stPEHeader.MajorSubsystemVersion		= stImageOptionalHeader.MajorSubsystemVersion;
		m_stPEHeader.DllCharacteristics			= stImageOptionalHeader.DllCharacteristics;
		m_stPEHeader.SizeOfStackReserve			= stImageOptionalHeader.SizeOfStackReserve;
		m_stPEHeader.BaseOfData					= stImageOptionalHeader.BaseOfData;
		//				 **************************************************

		m_stPEHeader.SectionAlignment			= (0 == stImageOptionalHeader.SectionAlignment) ? 0x1000 : stImageOptionalHeader.SectionAlignment;
		m_stPEHeader.MinorOSVersion				= stImageOptionalHeader.MinorOperatingSystemVersion;
		m_stPEHeader.MajorImageVersion			= stImageOptionalHeader.MajorImageVersion;;
		m_stPEHeader.MinorImageVersion			= stImageOptionalHeader.MinorImageVersion;;
		m_stPEHeader.MinorSubsystemVersion		= stImageOptionalHeader.MinorSubsystemVersion;
		m_stPEHeader.SizeOfCode					= stImageOptionalHeader.SizeOfCode;
		m_stPEHeader.SizeOfImage				= stImageOptionalHeader.SizeOfImage;
		m_stPEHeader.Subsystem					= stImageOptionalHeader.Subsystem;
		m_stPEHeader.SizeOfStackCommit			= stImageOptionalHeader.SizeOfStackCommit;
		m_stPEHeader.Win32VersionValue			= stImageOptionalHeader.Win32VersionValue;
		m_stPEHeader.SizeOfHeaders				= stImageOptionalHeader.SizeOfHeaders;
		m_stPEHeader.LoaderFlags				= stImageOptionalHeader.LoaderFlags;
		m_stPEHeader.NumberOfRvaAndSizes	= stImageOptionalHeader.NumberOfRvaAndSizes;
		memcpy(m_stPEHeader.DataDirectory, stImageOptionalHeader.DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES*sizeof(IMAGE_DATA_DIRECTORY));
		return true;
	}	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: Load32BitHeader
	In Parameters	: HANDLE hFileHandle, bool bOpenToRepair
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Loads 64 Bit Microsoft executable file (PE File) in memory
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::Load64BitHeader()
{
	DWORD dwBytesRead = 0;
	IMAGE_OPTIONAL_HEADER64 stImageOptionalHeader;
	memset(&stImageOptionalHeader, 0, sizeof(stImageOptionalHeader));
	ReadBuffer(&stImageOptionalHeader, sizeof(stImageOptionalHeader), &dwBytesRead);
	if(dwBytesRead == sizeof(stImageOptionalHeader))
	{
		m_stPEHeader.AddressOfEntryPoint	= stImageOptionalHeader.AddressOfEntryPoint;
		m_stPEHeader.CheckSum				= stImageOptionalHeader.CheckSum;
		m_stPEHeader.FileAlignment			= (0 == stImageOptionalHeader.FileAlignment) ? 0x200 : stImageOptionalHeader.FileAlignment; 
		m_stPEHeader.ImageBase				= HIDWORD64(stImageOptionalHeader.ImageBase);
		m_stPEHeader.Magic					= stImageOptionalHeader.Magic;
		m_stPEHeader.MinorLinkerVersion		= stImageOptionalHeader.MinorLinkerVersion;
		
		//Features Added for ML *************************************************
		m_stPEHeader.MajorLinkerVersion			= stImageOptionalHeader.MajorLinkerVersion;
		m_stPEHeader.SizeOfInitializedData		= stImageOptionalHeader.SizeOfInitializedData;
		m_stPEHeader.MajorOperatingSystemVersion = stImageOptionalHeader.MajorOperatingSystemVersion;
		m_stPEHeader.MajorSubsystemVersion		= stImageOptionalHeader.MajorSubsystemVersion;
		m_stPEHeader.DllCharacteristics			= stImageOptionalHeader.DllCharacteristics;
		m_stPEHeader.SizeOfStackReserve			= stImageOptionalHeader.SizeOfStackReserve;
		m_stPEHeader.BaseOfData					= 0; // Field Not Present, Added for the sake of uniformity
		//				 **************************************************
		
		m_stPEHeader.SectionAlignment		= (0 == stImageOptionalHeader.SectionAlignment) ? 0x1000 : stImageOptionalHeader.SectionAlignment;
		m_stPEHeader.MinorOSVersion			= stImageOptionalHeader.MinorOperatingSystemVersion;
		m_stPEHeader.MajorImageVersion			= stImageOptionalHeader.MajorImageVersion;;
		m_stPEHeader.MinorImageVersion			= stImageOptionalHeader.MinorImageVersion;;
		m_stPEHeader.MinorSubsystemVersion	= stImageOptionalHeader.MinorSubsystemVersion;
		m_stPEHeader.SizeOfCode				= stImageOptionalHeader.SizeOfCode;
		m_stPEHeader.SizeOfImage			= stImageOptionalHeader.SizeOfImage;
		m_stPEHeader.Subsystem				= stImageOptionalHeader.Subsystem;
		m_stPEHeader.SizeOfStackCommit		= HIDWORD64(stImageOptionalHeader.SizeOfStackCommit);
		m_stPEHeader.Win32VersionValue		= stImageOptionalHeader.Win32VersionValue;
		m_stPEHeader.LoaderFlags			= stImageOptionalHeader.LoaderFlags;
		m_stPEHeader.NumberOfRvaAndSizes	= stImageOptionalHeader.NumberOfRvaAndSizes;
		memcpy(m_stPEHeader.DataDirectory, stImageOptionalHeader.DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES*sizeof(IMAGE_DATA_DIRECTORY));
		return true;
	}	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: Load32BitHeader
	In Parameters	: HANDLE hFileHandle, bool bOpenToRepair
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Map frequently required File Offsets of PE Header
--------------------------------------------------------------------------------------*/
void CMaxPEFile::LoadOffsets()
{		
	m_stPEOffsets.NumberOfSections		= m_stPEHeader.e_lfanew + 0x06;
	
	m_stPEOffsets.Magic					= m_stPEHeader.e_lfanew + 0x18;
	m_stPEOffsets.MinorLinkerVersion	= m_stPEHeader.e_lfanew + 0x1B;
	m_stPEOffsets.SizeOfCode			= m_stPEHeader.e_lfanew + 0x1C;
	m_stPEOffsets.AddressOfEntryPoint	= m_stPEHeader.e_lfanew + 0x28;
	m_stPEOffsets.SectionAlignment		= m_stPEHeader.e_lfanew + 0x38;
	m_stPEOffsets.MinorOSVersion		= m_stPEHeader.e_lfanew + 0x42;
	m_stPEOffsets.MinorSubsystemVersion	= m_stPEHeader.e_lfanew + 0x4A;
	m_stPEOffsets.Win32VersionValue 	= m_stPEHeader.e_lfanew + 0x4C;
	m_stPEOffsets.SizeOfImage			= m_stPEHeader.e_lfanew + 0x50;
	m_stPEOffsets.Checksum				= m_stPEHeader.e_lfanew + 0x58;		
		
	if(m_b64bit)
	{
		m_stPEOffsets.ImageBase				= m_stPEHeader.e_lfanew + 0x30;
		m_stPEOffsets.NoOfDataDirs			= m_stPEHeader.e_lfanew + 0x84;
	}
	else
	{
		m_stPEOffsets.BaseOfData			= m_stPEHeader.e_lfanew + 0x30;
		m_stPEOffsets.ImageBase				= m_stPEHeader.e_lfanew + 0x34;
		m_stPEOffsets.LoaderFlags			= m_stPEHeader.e_lfanew + 0x70;
		m_stPEOffsets.NoOfDataDirs			= m_stPEHeader.e_lfanew + 0x74;
	}
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: SetFilePointer
	In Parameters	: HANDLE hFileHandle, bool bOpenToRepair
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Moves file pointer for I/O operation in memory
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::SetFilePointer(LONG lDistanceToMove, PLONG lpDistanceToMoveHigh/* = NULL*/, DWORD dwMoveMethod/* = FILE_BEGIN*/, LPDWORD pdwRawResult/* = 0*/)
{
	DWORD dwRes = 0;

	dwRes = ::SetFilePointer(m_hFileHandle, lDistanceToMove + m_iMZOffset, lpDistanceToMoveHigh, dwMoveMethod);

	if(pdwRawResult)
	{
		*pdwRawResult = dwRes - m_iMZOffset;
	}

	return INVALID_SET_FILE_POINTER != dwRes;
}

/*-------------------------------------------------------------------------------------
	Function		: ReadBuffer
	In Parameters	: LPVOID pbReadBuffer, DWORD dwBytesToRead, DWORD * pdwBytesRead
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Retrives buffer from File
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::ReadBuffer(LPVOID pbReadBuffer, DWORD dwBytesToRead, DWORD * pdwBytesRead/* = NULL*/)
{
	DWORD dwBytesRead = 0;

	if(!pbReadBuffer)
	{
		return false;
	}

	if(!ReadFile(m_hFileHandle, pbReadBuffer, dwBytesToRead, &dwBytesRead, NULL))
	{
		return false;
	}

	if(pdwBytesRead)
	{
		*pdwBytesRead = dwBytesRead;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: ReadBuffer
	In Parameters	: LPVOID pbReadBuffer, DWORD dwReadOffset, DWORD dwBytesToRead, DWORD dwMinBytesReq, DWORD *pdwBytesRead
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Retrives buffer from File
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::ReadBuffer(LPVOID pbReadBuffer, DWORD dwReadOffset, DWORD dwBytesToRead, DWORD dwMinBytesReq/* = 0*/, DWORD *pdwBytesRead/* = NULL*/)
{
	if(dwReadOffset > m_dwFileSize || !pbReadBuffer)
	{
		//AddLogEntry(L"Read Buffer Error: dwReadOffset > m_dwFileSize || !pbReadBuffer");
		return false;
	}

	if((m_dwAEPSectionSize != -1) // can we try to read the buffer or did we try and were not able to read?
		&& (dwReadOffset >= m_dwAEPSectionStartPos) && (dwReadOffset < (m_dwAEPSectionStartPos + m_dwAEPSectionSize))	// is offset in AEP section?
		&& (dwBytesToRead < (m_dwAEPSectionSize - (dwReadOffset - m_dwAEPSectionStartPos))))	// is required data size crossing the AEP section size limit?
	{
		if(!m_pAEPSectionBuffer)	// Read the section if not in memory yet!
		{
			InitAEPSection();
		}
		if(m_pAEPSectionBuffer)
		{
			memcpy(pbReadBuffer, &m_pAEPSectionBuffer[dwReadOffset - m_dwAEPSectionStartPos], dwBytesToRead);
			if(dwBytesToRead && dwBytesToRead >= dwMinBytesReq)
			{
				if(pdwBytesRead)
				{
					*pdwBytesRead = dwBytesToRead;
				}
				return true;
			}
		}
	}

	DWORD dwBytesRead = 0x00;
	DWORD dwSetFileOffSet = ::SetFilePointer(m_hFileHandle, dwReadOffset + m_iMZOffset, NULL, FILE_BEGIN);
	if(dwSetFileOffSet == dwReadOffset + m_iMZOffset)
	{
		if(ReadFile(m_hFileHandle, pbReadBuffer, dwBytesToRead, &dwBytesRead, NULL))
		{
			if (dwBytesRead && dwBytesRead >= dwMinBytesReq)
			{
				if(pdwBytesRead)
				{
					*pdwBytesRead = dwBytesRead;
				}
				return true;
			}
		}
	}
	//AddLogEntry(L"Read Buffer Error:");
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: WriteBuffer
	In Parameters	: LPVOID pbReadBuffer, DWORD dwReadOffset, DWORD dwBytesToRead, DWORD dwMinBytesReq, DWORD *pdwBytesRead
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Writes buffer in to File
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::WriteBuffer(LPVOID pbWriteBufer, DWORD dwWriteOffset, DWORD dwBytesToWrite, DWORD dwMinBytesReq/* = 0*/, DWORD *pdwBytesWritten/* = NULL*/)
{
	if(pbWriteBufer)
	{
		DWORD dwBytesWritten = 0x00;
		DWORD dwSetFileOffSet = ::SetFilePointer(m_hFileHandle, dwWriteOffset + m_iMZOffset, NULL, FILE_BEGIN);
		if(dwSetFileOffSet == dwWriteOffset + m_iMZOffset)
		{
			if(WriteFile(m_hFileHandle, pbWriteBufer, dwBytesToWrite, &dwBytesWritten, NULL))
			{
				if (dwBytesWritten && dwBytesWritten >= dwMinBytesReq)
				{
					if(pdwBytesWritten)
					{
						*pdwBytesWritten = dwBytesWritten;
					}
					return true;
				}
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CalculateImageSize
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Calculates Image File Size of PE file using PE Header
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::CalculateImageSize()
{
	if(0 == m_stPEHeader.NumberOfSections)
	{
		return true;
	}
	DWORD dwLastSecRVA = m_stSectionHeader[m_stPEHeader.NumberOfSections - 1].VirtualAddress;
	DWORD dwOffset = m_stPEOffsets.Magic + m_stPEHeader.SizeOfOptionalHeader + ((m_stPEHeader.NumberOfSections - 1) * IMAGE_SIZEOF_SECTION_HEADER) + 0x08;
	
	DWORD dwLastSecVS = 0;
	
	if(!ReadBuffer(&dwLastSecVS, dwOffset, 4, 4))
	{
		return false;
	}

	dwOffset += 0x08;
	DWORD dwLastSecSRD = 0;

	if(!ReadBuffer(&dwLastSecSRD, dwOffset, 4, 4))
	{
		return false;
	}
	
	DWORD dwSecAlignment = m_stPEHeader.SectionAlignment, dwImageSize = 0;

	if( dwLastSecVS % dwSecAlignment )
	{
		dwImageSize = dwLastSecVS - (dwLastSecVS % dwSecAlignment) + dwSecAlignment;
	}
	else
	{
		dwImageSize = dwLastSecVS;     
	}
    dwImageSize += dwLastSecRVA;

	if(WriteBuffer(&dwImageSize, m_stPEOffsets.SizeOfImage, 4, 4))
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CalculateLastSectionProperties
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Part of repaire action. Writes characteristic of Last Section
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::CalculateLastSectionProperties()
{
	if(0 == m_stPEHeader.NumberOfSections)
	{
		return true;
	}
	// Search for the last section having non zero SRD 
	int iLastSection = 0; 	
	for(int iSec = m_stPEHeader.NumberOfSections - 1; iSec > 0; iSec--) 
	{
		//Check whether the SRD of section is non zero
		if(m_stSectionHeader[iSec].SizeOfRawData != 0x00) 
		{
			iLastSection = iSec;
			break;
		}
	}	

	if(m_stSectionHeader[iLastSection].PointerToRawData > m_dwFileSize)
	{
		m_stSectionHeader[iLastSection].PointerToRawData = m_stSectionHeader[iLastSection - 1].PointerToRawData + m_stSectionHeader[iLastSection - 1].SizeOfRawData;
		WriteSectionCharacteristic(iLastSection, m_stSectionHeader[iLastSection].PointerToRawData, SEC_PRD);
	}

	DWORD dwSRD = GetFileSize(m_hFileHandle, 0) - m_stSectionHeader[iLastSection].PointerToRawData;
	WriteSectionCharacteristic(iLastSection, dwSRD, SEC_SRD);
	
	return CalculateImageSize();
}

/*-------------------------------------------------------------------------------------
	Function		: RemoveSection
	In Parameters	: WORD wSecNoToRemove, bool bTruncateOverlay
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Part of repaire action. Removes Last Section from File (Appender type viruses)
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::RemoveSection(WORD wSecNoToRemove, bool bTruncateOverlay/* = false*/)
{
	if(wSecNoToRemove == 1 || wSecNoToRemove > m_stPEHeader.NumberOfSections ||	m_stPEHeader.NumberOfSections < 2)
	{
		return false;
	}

	WORD wRemSection = wSecNoToRemove - 1;
	if(wSecNoToRemove ==  m_stPEHeader.NumberOfSections) 
	{
		return RemoveLastSections(1, bTruncateOverlay);
	}

	DWORD dwRemoveSectionPRD	= m_stSectionHeader[wRemSection].PointerToRawData;
	DWORD dwEndOfRemoveSection	= dwRemoveSectionPRD +  m_stSectionHeader[wRemSection].SizeOfRawData;
	
	//Make removed section Size of raw data to 0
	m_stSectionHeader[wRemSection].SizeOfRawData = 0x00; 
	WriteSectionCharacteristic(wRemSection, 0, SEC_SRD);

	DWORD dwPRD = m_stSectionHeader[wRemSection].PointerToRawData;
	for(WORD dwSec = 0x01; dwSec <= m_stPEHeader.NumberOfSections - wSecNoToRemove; dwSec++) 
	{
		m_stSectionHeader[wRemSection + dwSec].PointerToRawData = dwPRD;
		WriteSectionCharacteristic(wRemSection + dwSec, dwPRD, SEC_PRD);
		dwPRD = m_stSectionHeader[wRemSection + dwSec].PointerToRawData + m_stSectionHeader[wRemSection + dwSec].SizeOfRawData;
	}

	// Shift data up
	if(dwEndOfRemoveSection < m_dwFileSize)
	{
		DWORD dwSectionData = m_dwFileSize - dwEndOfRemoveSection;
		
		if ( !CopyData(dwEndOfRemoveSection, dwRemoveSectionPRD, dwSectionData) )
			return false;

		dwRemoveSectionPRD += dwSectionData;		
	}

	// Calculate image size and truncate the file
	::SetFilePointer(m_hFileHandle, dwRemoveSectionPRD + m_iMZOffset, 0, FILE_BEGIN);
	if(!SetEndOfFile(m_hFileHandle))
	{
		return false;
	}
	CalculateImageSize();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: RemoveLastSections
	In Parameters	: WORD wSecNoToRemove, bool bTruncateOverlay
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Part of repaire action. Removes Last Section from File (Appender type viruses)
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::RemoveLastSections(WORD wNoofSectionsToRemove/* = 1*/, bool bTruncateOverlay/* = false*/)
{	
	// Check for first valid section to removed 
	WORD wRemoveStartSection = m_stPEHeader.NumberOfSections - wNoofSectionsToRemove;
	while(wRemoveStartSection < m_stPEHeader.NumberOfSections - 1 && m_stSectionHeader[wRemoveStartSection].PointerToRawData == 0)
	{
		wRemoveStartSection++;
	}

	// Calculate last section no by checking its PRD and SRD
	WORD wLastSection = m_stPEHeader.NumberOfSections - 1;
	DWORD dwEndOfLastSec = m_stSectionHeader[wLastSection].PointerToRawData + m_stSectionHeader[wLastSection].SizeOfRawData;				
	while(wLastSection > wRemoveStartSection && dwEndOfLastSec == 0)
	{
		wLastSection--;
		dwEndOfLastSec = m_stSectionHeader[wLastSection].PointerToRawData + m_stSectionHeader[wLastSection].SizeOfRawData;
	}
	if(dwEndOfLastSec == 0)
	{
		return false;
	}
	
	// Calculate start from which to truncate the file
	DWORD dwRemoveStartSectionPRD = m_stSectionHeader[wRemoveStartSection].PointerToRawData; 
	if(dwEndOfLastSec < m_dwFileSize && !bTruncateOverlay)
	{
		DWORD dwSizeOfOverlay = GetFileSize(m_hFileHandle, 0) - dwEndOfLastSec;			
		if(!CopyData(dwEndOfLastSec, dwRemoveStartSectionPRD, dwSizeOfOverlay))
		{
			return false;
		}
		dwRemoveStartSectionPRD  += dwSizeOfOverlay;
	}		
	
	::SetFilePointer(m_hFileHandle, dwRemoveStartSectionPRD + m_iMZOffset, 0, FILE_BEGIN);
	if(!SetEndOfFile(m_hFileHandle))
	{
		return false;
	}
	
	// Fill the section headers with zeros
	DWORD dwSecHeaderOffset = m_stPEOffsets.Magic + m_stPEHeader.SizeOfOptionalHeader + (wRemoveStartSection * IMAGE_SIZEOF_SECTION_HEADER);	
	if(!FillWithZeros(dwSecHeaderOffset, wNoofSectionsToRemove * IMAGE_SIZEOF_SECTION_HEADER))
	{
		return false;
	}

	// Write number of sections
	if(!WriteNumberOfSections(wRemoveStartSection))
	{
		return false;
	}

	// If removed section is added by virus at the offset of bound imaport table then set its address to zero
	DWORD dwBoundImpAddr = 0;
	if(ReadBuffer(&dwBoundImpAddr,  m_stPEOffsets.NoOfDataDirs + 0x5C, sizeof(DWORD), sizeof(DWORD)))
	{
		if(dwBoundImpAddr >= dwSecHeaderOffset && dwBoundImpAddr < dwSecHeaderOffset + IMAGE_SIZEOF_SECTION_HEADER)
		{
			RepairOptionalHeader(42, 0, 0, true);			
		}
	}
	CalculateImageSize();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: WriteAEP
	In Parameters	: DWORD dwAEPToWrite
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Part of repaire action. Re-writes Address of Entry point
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::WriteAEP(DWORD dwAEPToWrite)
{
	if(WriteBuffer(&dwAEPToWrite, m_stPEOffsets.AddressOfEntryPoint, sizeof(DWORD), sizeof(DWORD)))
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: WriteNumberOfSections
	In Parameters	: DWORD dwAEPToWrite
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Part of repaire action. Re-writes No. of sections
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::WriteNumberOfSections(WORD wNumberOfSections)
{
	m_stPEHeader.NumberOfSections = wNumberOfSections;
	if(WriteBuffer(&wNumberOfSections, m_stPEOffsets.NumberOfSections, sizeof(WORD), sizeof(WORD)))
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: TruncateFile
	In Parameters	: DWORD dwTruncateOffset, bool bTruncateOverlay
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Part of repaire action. Truncates file from bottom or removes binary data from inbetween
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::TruncateFile(DWORD dwTruncateOffset, bool bTruncateOverlay/* = false*/)
{
	DWORD dwStartOfOverlay = m_stSectionHeader[m_stPEHeader.NumberOfSections - 1].PointerToRawData + m_stSectionHeader[m_stPEHeader.NumberOfSections - 1].SizeOfRawData;
	DWORD dwSizeOfOverlay = 0;
	bool bOverlay = false;
	if(m_dwFileSize > dwStartOfOverlay) 
	{
		dwSizeOfOverlay = m_dwFileSize - dwStartOfOverlay;
		bOverlay  = true;
	}
	
	// Get the section number where truncate offset lies
	WORD wTruncateSec =  GetSectionNoFromOffset(dwTruncateOffset);
	if(OUT_OF_FILE != wTruncateSec)
	{		
		// If the truncate offset is at the start of the section the remove the sections 
		if(dwTruncateOffset == m_stSectionHeader[wTruncateSec].PointerToRawData)
		{
			return RemoveLastSections(m_stPEHeader.NumberOfSections  - wTruncateSec, bTruncateOverlay);
		}
		// If trucate offset is not in the last section then remove the sections below it
		if(wTruncateSec < m_stPEHeader.NumberOfSections - 1)
		{
			RemoveLastSections(m_stPEHeader.NumberOfSections  - wTruncateSec - 1, bTruncateOverlay);
		}
		// Reduce the size of raw data of the section
		WriteSectionCharacteristic(wTruncateSec, dwTruncateOffset - m_stSectionHeader[wTruncateSec].PointerToRawData, SEC_SRD);

		// Move the overlay before truncating the file
		if(bOverlay && !bTruncateOverlay)
		{
			DWORD dwStartOfOverlay = m_stSectionHeader[wTruncateSec].PointerToRawData + m_stSectionHeader[wTruncateSec].SizeOfRawData;
			if(!CopyData(dwStartOfOverlay, dwTruncateOffset, dwSizeOfOverlay))
			{
				return false;
			}
			dwTruncateOffset  += dwSizeOfOverlay;
		}	
	}

	// Truncate the file
	::SetFilePointer(m_hFileHandle, dwTruncateOffset + m_iMZOffset, 0, FILE_BEGIN);
	if(SetEndOfFile(m_hFileHandle))
	{
		CalculateImageSize();
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: ForceTruncate
	In Parameters	: DWORD dwTruncateOffset
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Part of repaire action. Truncates file from bottom
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::ForceTruncate(DWORD dwTruncateOffset)
{
	// Truncate the file
	::SetFilePointer(m_hFileHandle, dwTruncateOffset + m_iMZOffset, 0, FILE_BEGIN);
	if(SetEndOfFile(m_hFileHandle))
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: FillWithZeros
	In Parameters	: DWORD dwTruncateOffset
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Part of repaire action. Fill butter with 0's if truncation is not possible
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::FillWithZeros(DWORD dwStartOffset, DWORD dwSize)
{
	DWORD dwChunk = 0x1000;
	if(dwSize < dwChunk)
	{
		dwChunk = dwSize;
	}

	BYTE *pbyBuffer = new BYTE[dwChunk];
	if(!pbyBuffer)
	{
		return false;
	}
	memset(pbyBuffer, 0, dwChunk);
	
	DWORD dwBytesToWrite = dwChunk, dwBytesWritten = 0;
	::SetFilePointer(m_hFileHandle, dwStartOffset + m_iMZOffset, 0, FILE_BEGIN);

	for(DWORD dwTotalBytesWritten = 0x00; dwTotalBytesWritten < dwSize; dwTotalBytesWritten	+= dwBytesWritten)
	{		
		if(dwSize - dwTotalBytesWritten < dwChunk)
		{
			dwBytesToWrite = dwSize - dwTotalBytesWritten;
		}
		WriteFile(m_hFileHandle, pbyBuffer, dwBytesToWrite, &dwBytesWritten, 0);
		if(0 == dwBytesWritten)
		{
			break;
		}
	}
	delete []pbyBuffer;
	return true;
}

/******************************************************************************
Function Name	:	CopyData
Author			:	Rupali	
Input			:	dwReadStartAddr		: File offset of data to copy.
					dwWriteStartAddr	: File offset of data to be copied at.
					dwSizeOfData		: Size of data to copy
Output			:   Returns true if data copy is suceesful else returns false.
Description		:	Function copies data from sorce oddset to destination in 
					chunks OF 64kb buffer. Seperated this function as it is 
					required for copying data in ReplaceOriginalData and also
					to copy overlay in case of RemovelastSection.
*******************************************************************************/
bool CMaxPEFile::CopyData(DWORD dwReadStartAddr, DWORD dwWriteStartAddr, DWORD dwSizeOfData, DWORD dwCaseNo/* = 0*/, DWORD dwKey/* = 0*/)
{
	BYTE *byBuffer = NULL;
	try
	{
		DWORD dwChunk = 0x10000;
		if(dwSizeOfData < dwChunk)
		{
			dwChunk = dwSizeOfData;
		}

		byBuffer = new BYTE[dwChunk];
		if(!byBuffer)
		{
			return false;
		}

		DWORD dwBytesRead = 0;
		bool bRet = true;
		for(DWORD dwOffset = 0; dwOffset < dwSizeOfData; dwOffset += dwChunk)
		{		
			memset(byBuffer, 0, dwChunk);
			if(!ReadBuffer(byBuffer, dwReadStartAddr + dwOffset, dwChunk, 0, &dwBytesRead))
			{
				bRet = false;
				break;
			}
			if((dwOffset + dwChunk) > dwSizeOfData || dwBytesRead != dwChunk)
			{
				dwBytesRead = dwSizeOfData - dwOffset;
			}
			switch(dwCaseNo)
			{
			case 1:
				for(DWORD dwIndex = 0; dwIndex < dwBytesRead; dwIndex++)
				{
					byBuffer[dwIndex] ^= (BYTE)dwKey;
				}
				break;
			}			
			if(!WriteBuffer(byBuffer, dwWriteStartAddr + dwOffset, dwBytesRead, dwBytesRead))
			{
				bRet = false;
				break;
			}
		}
		delete [] byBuffer;
		byBuffer = NULL;
		return bRet;
	}
	catch(...)
	{
		if(byBuffer)
		{
			delete [] byBuffer;
			byBuffer = NULL;
		}
		return false;
	}
}

/*-------------------------------------------------------------------------------------
Function		: RepairOptionalHeader
In Parameters	: Three DWORD Values 
					1. Field no to modify
					2. New value to write 
					3. New value to write for data directories
Out Parameters	: bool
Purpose			: Repair Optional Header Values Specifically Directories (RVA & Size)
Author			: Yash Gund
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::RepairOptionalHeader(int iAttribute, DWORD dwAttributeValue, DWORD dwDataDirSize, bool bForceSetDataDirSize /*= false*/)
{
	DWORD dwOffset = 0x00, dwNoOfBytesToWrite = sizeof(DWORD);

	switch(iAttribute)
	{
	case 1://Offset of Optional Header
		{
			dwOffset = 0x3C;
		}
		break;
	case 2://Offset of Minor Linker Version
		{
			dwOffset = m_stPEOffsets.MinorLinkerVersion;
		}
		break;
	case 4://Size Of Code
		{
			dwOffset = m_stPEOffsets.SizeOfCode;
		}
		break;
	case 9://Base Of Data
		{
			dwOffset = m_stPEOffsets.BaseOfData;
		}
		break;
	case 0x0A://Image Base
		{
			dwOffset = m_stPEOffsets.ImageBase;
		}
		break;
	case 0x0B://Section Alignment
		{
			dwOffset = m_stPEOffsets.SectionAlignment;
		}
		break;
	case 0x0E://Minor Operating System Version
		{
			dwOffset = m_stPEOffsets.MinorOSVersion;
			dwNoOfBytesToWrite = sizeof(WORD);
		}
		break;
	case 0x13://Win32 Version Value
		{
			dwOffset = m_stPEOffsets.Win32VersionValue;
		}
		break;
	case 0x16://Checksum
		{
			dwOffset = m_stPEOffsets.Checksum;
		}
		break;
	default:
		if(iAttribute < 0x1E)
		{
			return false;
		}
		break;
	}

	if(iAttribute > 0x1E)
	{
		dwOffset = m_stPEOffsets.NoOfDataDirs + 0x04 + (iAttribute - 0x1F) * 8;		
	}
	
	if(dwOffset < m_stPEHeader.SizeOfOptionalHeader + m_stPEOffsets.Magic)
	{		
		if(!WriteBuffer(&dwAttributeValue, dwOffset, dwNoOfBytesToWrite, dwNoOfBytesToWrite))
		{
			return false;
		}
		
		//RVA of DATA Directories 
		if(iAttribute > 0x1E && (dwDataDirSize || bForceSetDataDirSize))
		{	
			//Size of Data Directories
			if(!WriteBuffer(&dwDataDirSize, dwOffset + 4, sizeof(DWORD), sizeof(DWORD)))
			{
				return false;
			}
		}
	}
	return true;	
}

/*-------------------------------------------------------------------------------------
	Function		: WriteSectionCharacteristic
	In Parameters	: WORD wSectionNo, DWORD dwAtributeValue, DWORD dwAtributeOffset
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Changes characteristics of given section
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::WriteSectionCharacteristic(WORD wSectionNo, DWORD dwAtributeValue, DWORD dwAtributeOffset)
{
	DWORD dwOffset = m_stPEOffsets.Magic + m_stPEHeader.SizeOfOptionalHeader + wSectionNo * 40 + dwAtributeOffset;
	return WriteBuffer(&dwAtributeValue, dwOffset, sizeof(DWORD), sizeof(DWORD));
}

/*-------------------------------------------------------------------------------------
	Function		: CalculateChecksum
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: calculate checksum of PE File
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::CalculateChecksum()
{
	DWORD dwCheckSum = 0, dwHeaderSum = 0;
	MapFileAndCheckSum(m_szFilePath, &dwHeaderSum, &dwCheckSum);	
	return WriteBuffer(&dwCheckSum, m_stPEOffsets.Checksum, sizeof(DWORD), sizeof(DWORD));
}

/*-------------------------------------------------------------------------------------
	Function		: Rva2FileOffset
	In Parameters	: DWORD dwRVAAddress, DWORD *pdwFileOffset
	Out Parameters	:  section no. for file offset
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Returns realted file offset for given RVA
--------------------------------------------------------------------------------------*/
WORD CMaxPEFile::Rva2FileOffset(DWORD dwRVAAddress, DWORD *pdwFileOffset)
{	
	if(m_stPEHeader.NumberOfSections > 0 && dwRVAAddress < m_stSectionHeader[0].VirtualAddress)
	{
		if(pdwFileOffset)
		{
			*pdwFileOffset = dwRVAAddress;
		}
		return 0;
	}

	for(WORD wSec =  m_stPEHeader.NumberOfSections - 0x01; wSec >= 0; wSec--)
	{
		DWORD dwSecAddress = m_stSectionHeader[wSec].VirtualAddress + m_stSectionHeader[wSec].Misc.VirtualSize;
		if(dwSecAddress)
		{
			dwSecAddress += (m_stPEHeader.SectionAlignment - (dwSecAddress % m_stPEHeader.SectionAlignment));
		}
		if(dwRVAAddress >= m_stSectionHeader[wSec].VirtualAddress && 
			((dwRVAAddress < dwSecAddress) || 
			(dwRVAAddress < (m_stSectionHeader[wSec].VirtualAddress + m_stSectionHeader[wSec].SizeOfRawData))))
		{
			if(pdwFileOffset)
			{
				*pdwFileOffset = dwRVAAddress - m_stSectionHeader[wSec].VirtualAddress + m_stSectionHeader[wSec].PointerToRawData;
			}
			return wSec;
		}
		if(wSec == 0x00)
		{
			break;
		}
	}
	return OUT_OF_FILE;
}

/*-------------------------------------------------------------------------------------
	Function		: GetSectionNoFromOffset
	In Parameters	: 
	Out Parameters	: section no. for file offset
	Purpose			: 
	Author			: Tushar Kadam
	Description		: returns section i which input file offset belongs
--------------------------------------------------------------------------------------*/
WORD CMaxPEFile::GetSectionNoFromOffset(DWORD dwFileOffset)
{
	for(WORD wSec =  m_stPEHeader.NumberOfSections - 0x01; wSec >= 0; wSec--)
	{
		if(dwFileOffset >=  m_stSectionHeader[wSec].PointerToRawData && dwFileOffset <(m_stSectionHeader[wSec].PointerToRawData + m_stSectionHeader[wSec].SizeOfRawData))
		{
			return wSec;
		}
		if(wSec == 0x00)
		{
			break;
		}
	}	
	return OUT_OF_FILE;
}

/*-------------------------------------------------------------------------------------
	Function		: SetFileName
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Delete File 
--------------------------------------------------------------------------------------*/
void CMaxPEFile::SetFileName(LPCTSTR szFilePath)
{
	wcscpy_s(m_szFilePath, szFilePath);
}

/*-------------------------------------------------------------------------------------
	Function		: DeletePEFile
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Delete File 
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::DeletePEFile()
{	
	CloseFile();
	return (TRUE == DeleteFile(m_szFilePath)) ? true : false;
}

/*-------------------------------------------------------------------------------------
	Function		: TruncateFileWithFileAlignment
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Truncate the data from buttom and write 0's for file allignment 
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::TruncateFileWithFileAlignment(DWORD dwTruncateOffset)
{
	DWORD dwAlignOffset = ((dwTruncateOffset + m_stPEHeader.FileAlignment - 1) / m_stPEHeader.FileAlignment) * m_stPEHeader.FileAlignment;
		
	if(dwAlignOffset > dwTruncateOffset)
	{
		FillWithZeros(dwTruncateOffset, dwAlignOffset - dwTruncateOffset);		
		dwTruncateOffset = dwAlignOffset;
	}
	return TruncateFile(dwTruncateOffset, true); 
}

/*-------------------------------------------------------------------------------------
	Function		: GetImportAndNameTableRVA
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Returns RVA Corresponding to the DLL File present in the Import table
--------------------------------------------------------------------------------------*/
// Returns RVA Corresponding to the DLL File present in the Import table
bool CMaxPEFile::GetImportAndNameTableRVA(char* szDllName, IMAGE_IMPORT_DESCRIPTOR &objIMPORTTable)
{
	bool bRetStatus = false;
	if(szDllName == NULL)
	{
		return bRetStatus;
	}

	DWORD dwImpDirTableSize = m_stPEHeader.DataDirectory[1].Size, dwImpDirTableOff = 0x00;
	Rva2FileOffset(m_stPEHeader.DataDirectory[1].VirtualAddress, &dwImpDirTableOff);
	if(dwImpDirTableOff == 0x00 || dwImpDirTableSize > 0x1000)
	{
		return bRetStatus;
	}

	BYTE *byBuffer = new BYTE[dwImpDirTableSize];
	if(byBuffer == NULL)
	{
		return bRetStatus;
	}
	if(ReadBuffer(byBuffer, dwImpDirTableOff, dwImpDirTableSize, dwImpDirTableSize))
	{
		DWORD dwDLLNameLen = strlen(szDllName);
		if(dwDLLNameLen < 100)
		{
			_strlwr_s(szDllName, dwDLLNameLen + 1);

			char szReadDllName[100] = {0};
			DWORD dwReadDllNameOff = 0x00;

			for(DWORD iCnt = 0; iCnt < dwImpDirTableSize; iCnt += 20)
			{
				memset(&szReadDllName[0], 0, 100);
				dwReadDllNameOff = 0;
				Rva2FileOffset(*((DWORD*)&byBuffer[iCnt + 12]), &dwReadDllNameOff);
				if(dwReadDllNameOff != 0)
				{					
					if(ReadBuffer(&szReadDllName[0], dwReadDllNameOff, dwDLLNameLen, dwDLLNameLen))
					{
						_strlwr_s(szReadDllName, 100);
						if(strcmp(szDllName, szReadDllName) == 0x00)
						{
							memcpy(&objIMPORTTable, &byBuffer[iCnt], sizeof(IMAGE_IMPORT_DESCRIPTOR));
							bRetStatus = true;
							break;
						}
					}
				}
			}
		}
	}
	if(byBuffer)
	{
		delete []byBuffer;
		byBuffer = NULL;
	}
	return bRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetFunNameRva
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Return RVA Corresponding to the Function Name
--------------------------------------------------------------------------------------*/
// Return RVA Corresponding to the Function Name
DWORD CMaxPEFile::GetFunNameRva(char *szFunName, DWORD dwFunNameTableOff)
{
	DWORD dwRetStatus = 0;
	if(dwFunNameTableOff == 0x00 || szFunName == NULL)
	{
		return dwRetStatus;
	}
	DWORD dwFunNameOff = 0x00;
	DWORD dwFunNameLen = strlen(szFunName);
	if(dwFunNameLen > 100)
	{
		return dwRetStatus;
	}
	char szReadFunName[100] = {0x00};
	for(int i = 0; i < 200; i++) // Putting max limit of 200 for no of APIs
	{
		dwFunNameOff = 0x00;
		memset(&szReadFunName[0], 0x00, 100);

		if(!ReadBuffer(&dwFunNameOff, dwFunNameTableOff, 0x04, 0x04))
		{
			return dwRetStatus;
		}
		dwFunNameTableOff += 4;
		
		Rva2FileOffset(dwFunNameOff, &dwFunNameOff);
		if(dwFunNameOff == 0x00)
		{
			return dwRetStatus;
		}
		dwFunNameOff = dwFunNameOff + 2;
		if(!ReadBuffer(&szReadFunName[0], dwFunNameOff, dwFunNameLen, dwFunNameLen))
		{
			return dwRetStatus;
		}
		if(strcmp(szFunName, szReadFunName) == 0x00)
		{
			return dwFunNameOff;
		}
	}
	return dwRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: ValidateFile
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Check for Currupt Header
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::ValidateFile()
{
	if(!CheckForValidPEFile(m_hFileHandle))
	{		
		return false;
	}
	
	// Check the mapped AEP is out of file
	if(m_dwAEPMapped > m_dwFileSize)
	{
		return false;
	}

	if(0 == m_dwAEPMapped && m_stPEHeader.AddressOfEntryPoint > m_dwFileSize)
	{
		return false;
	}

	// AEP section should have execute property
	/*if((m_stSectionHeader[m_wAEPSec].Characteristics & 0x20000000) != 0x20000000)
		return ERR_INCORRECT_AEP;*/

	// Check the section sizes in header; the PRD + SRD cannot be beyond file size
	for(int iSec = m_stPEHeader.NumberOfSections - 1; iSec > 0; iSec--) 
	{
		if(m_stSectionHeader[iSec].PointerToRawData + m_stSectionHeader[iSec].SizeOfRawData > m_dwFileSize) 
		{
			return false;
		}
	}	
	
	/*if((m_stPEHeader.Characteristics&IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		// Check the byte pointed by AEP it cannot be zero
		BYTE bAEPData;
		if(!ReadBuffer(&bAEPData, m_dwAEPMapped, 1, 1))
			return false;

		if(0 == bAEPData)
			return false;
	}*/

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: LoadUnpackerDLL
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Rupali Sonawane + Tushar Kadam
	Description		: Loads AuUnpacker.dll
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::LoadUnpackerDLL()
{	
	if(m_lpfnUnpackFile == NULL)
	{
		m_hUnpacker = LoadLibrary(_T("AuUnpacker.dll"));
		if(m_hUnpacker == NULL)
		{
			return false;
		}

		m_lpfnUnpackFile = (LPFNUnpackFile)GetProcAddress(m_hUnpacker, "UnPackFile");
		if(m_lpfnUnpackFile  == NULL)
		{
			return false;
		}
	}	
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DeleteTempFile
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Rupali Sonawane Tushar Kadam
	Description		: Deletes all remaining files in <PROGDIR>\TMP folder created by AuUnpacker
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::DeleteTempFile()
{
	if(INVALID_HANDLE_VALUE != m_hFileHandle)
	{
		CloseHandle(m_hFileHandle);
		m_hFileHandle = INVALID_HANDLE_VALUE;
	}
	return (TRUE == DeleteFile(m_szFilePath)) ? true : false;
}

/*-------------------------------------------------------------------------------------
	Function		: UnloadUnpacker
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Unloads AuUnpacker Dll
--------------------------------------------------------------------------------------*/
void CMaxPEFile::UnloadUnpacker()
{
	if(m_hUnpacker)
	{
		LPFNUnloadDlls lpfnUnloadDll = (LPFNUnloadDlls) GetProcAddress(m_hUnpacker, "UnloadDlls");
		if(lpfnUnloadDll)
		{
			lpfnUnloadDll();
		}
		FreeLibrary(m_hUnpacker);
		m_hUnpacker = NULL;
		m_lpfnUnpackFile = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: OpenFile_NoMemberReset
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Open file without structure changes. required for two step repairing
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::OpenFile_NoMemberReset(LPCTSTR szFilePath)
{
	if(INVALID_HANDLE_VALUE != m_hFileHandle)
	{
		return true;
	}

	if(MAXDWORD == m_dwSharedMode && MAXDWORD == m_dwDesirecAccess)
	{
		return false;
	}

	m_hFileHandle = CreateFile(szFilePath, m_dwDesirecAccess, m_dwSharedMode, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(INVALID_HANDLE_VALUE == m_hFileHandle)
	{
		m_iErrCode = ERR_OPENING_FILE;
		return false;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CloseFile_NoMemberReset
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Close file without structure changes. required for two step repairing
--------------------------------------------------------------------------------------*/
void CMaxPEFile::CloseFile_NoMemberReset()
{
	if(INVALID_HANDLE_VALUE != m_hFileHandle)
	{
		CloseHandle(m_hFileHandle);
		m_hFileHandle = INVALID_HANDLE_VALUE;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: IsValidResourcTable
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checks the file for Valid Resource table
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::IsValidResourcTable()
{	
	if(m_stPEHeader.NumberOfRvaAndSizes < 3)
	{
		return true;
	}
	DWORD dwBaseResAT = m_stPEHeader.DataDirectory[2].VirtualAddress;
	DWORD dwSizeofdata = m_stPEHeader.DataDirectory[2].Size;	
	if(dwSizeofdata == 0 && dwBaseResAT == 0)
	{
		return true;
	}
	if(dwSizeofdata == 0 || dwBaseResAT == 0)
	{
		return false;
	}

	DWORD dwBaseResATFileOffset =0;
	if(OUT_OF_FILE == Rva2FileOffset(dwBaseResAT, &dwBaseResATFileOffset))
	{
		return false;
	}

	WORD wNoofNamed = 0x00;
	DWORD dwOffset = dwBaseResATFileOffset;
	if(!ReadBuffer(&wNoofNamed, dwOffset+ 0x0C, sizeof(WORD), sizeof(WORD)))
	{
		return false;
	}
	WORD wNoofID = 0x00;
	if(!ReadBuffer(&wNoofID, dwOffset+ 0x0E, sizeof(WORD), sizeof(WORD)))
	{
		return false;
	}
	if(wNoofNamed == 0 && wNoofID == 0)
		return false;

	DWORD dwOffSetOfDir = 0, dwOffSetOfDir1 = 0, dwOffSetOfDir2 = 0;	
	for(int i = 0; i < wNoofNamed + wNoofID; i++)
	{
		if(!ReadBuffer(&dwOffSetOfDir, (dwOffset + 0x14), sizeof(DWORD), sizeof(DWORD)))
		{
			return false;
		}

		WORD wNoofNameEntry = 0;
		if(!ReadBuffer(&wNoofNameEntry, (dwBaseResATFileOffset +(dwOffSetOfDir^0x80000000)+0xC), sizeof(WORD), sizeof(WORD)))
		{
			return false;
		}
		WORD wNoofIDEntry = 0;
		if(!ReadBuffer(&wNoofIDEntry, (dwBaseResATFileOffset +(dwOffSetOfDir^0x80000000)+0xE), sizeof(WORD), sizeof(WORD)))
		{
			return false;
		}
		if(wNoofIDEntry == 0 && wNoofNameEntry == 0)
		{
			return false;
		}

		for(int j = 0; j < wNoofIDEntry + wNoofNameEntry; j++)
		{
			if(!ReadBuffer(&dwOffSetOfDir1, (dwBaseResATFileOffset +(dwOffSetOfDir^0x80000000)+0x14), sizeof(DWORD), sizeof(DWORD)))
			{
				return false;
			}
			WORD wNoofIDEntries = 0;
			if(!ReadBuffer(&wNoofIDEntries, (dwBaseResATFileOffset +(dwOffSetOfDir1^0x80000000)+0xE), sizeof(WORD), sizeof(WORD)))
			{
				return false;
			}

			for(int k = 0; k < wNoofIDEntries; k++)
			{  
				WORD wNoofIDEntrie=0;
				if(!ReadBuffer(&dwOffSetOfDir2, (dwBaseResATFileOffset +(dwOffSetOfDir1^0x80000000)+0x14), sizeof(DWORD), sizeof(DWORD)))
				{
					return false;
				}
				if(dwBaseResATFileOffset + dwOffSetOfDir2 > m_dwFileSize)
				{
					return false;
				}
				DWORD dwResOffset = 0;	
				if(!ReadBuffer(&dwResOffset, dwBaseResATFileOffset + dwOffSetOfDir2, sizeof(DWORD), sizeof(DWORD)))
				{
					return false;
				}
				if(OUT_OF_FILE ==  Rva2FileOffset(dwResOffset, 0))
				{
					return false;
				}
				DWORD dwSize = 0;	
				if(!ReadBuffer(&dwSize, dwBaseResATFileOffset + dwOffSetOfDir2 + 4, sizeof(DWORD), sizeof(DWORD)))
				{
					return false;
				}
				if(dwSize == 0 || dwSize > m_dwFileSize)
				{
					return false;
				}
				dwOffSetOfDir1 += 0x8;
			}
			dwOffSetOfDir += 0x8;
		}
		dwOffset += 0x8;
	}
	return true;
}
/*-------------------------------------------------------------------------------------
	Function		: IsValidImportTable
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checks the file for Valid Import table
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::IsValidImportTable()
{
	if(m_stPEHeader.NumberOfRvaAndSizes < 2)
	{
		return true;
	}
	DWORD dwBaseRVA = m_stPEHeader.DataDirectory[1].VirtualAddress;
	DWORD dwSizeofdata = m_stPEHeader.DataDirectory[1].Size;	

	if(dwSizeofdata == 0 && dwBaseRVA == 0)
	{
		return true;
	}
	if(dwSizeofdata == 0 || dwBaseRVA == 0)
	{
		return false;
	}
	if(OUT_OF_FILE == Rva2FileOffset(dwBaseRVA, &dwBaseRVA))
	{
		return false;
	}
	for(DWORD dwOffset = dwBaseRVA; dwOffset < dwBaseRVA + dwSizeofdata - 0x14; dwOffset += 0x14)
	{	
		DWORD dwImportAddresOfTable = 0, dwNamedRVA = 0;
		if(!ReadBuffer(&dwNamedRVA, dwOffset + 0x0C, sizeof(DWORD), sizeof(DWORD)))
		{
			return false;
		}
		if(!ReadBuffer(&dwImportAddresOfTable, dwOffset + 0x10, sizeof(DWORD), sizeof(DWORD)))
		{
			return false;
		}
		if(dwNamedRVA == 0 || dwImportAddresOfTable == 0) 
		{
			return false;
		}
		DWORD dwDllRVACheck = 0, dwTableRVACheck = 0;
		if(OUT_OF_FILE == Rva2FileOffset(dwNamedRVA, &dwNamedRVA))
		{
			return false;
		}
		if(OUT_OF_FILE == Rva2FileOffset(dwImportAddresOfTable, &dwImportAddresOfTable))
		{
			return false;
		}
		if(dwOffset + 0x10 < dwImportAddresOfTable) 
		{
			return false;
		}

		if(!ReadBuffer(&dwDllRVACheck, dwNamedRVA, sizeof(DWORD), sizeof(DWORD)))
		{
			return false;
		}
		if(!ReadBuffer(&dwTableRVACheck, dwImportAddresOfTable, sizeof(DWORD), sizeof(DWORD)))
		{
			return false;
		}
		if(dwDllRVACheck == 0 || dwTableRVACheck == 0)
		{
			return false;
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: IsValidExportTable
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Checks the file for Valid Export table
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::IsValidExportTable()
{
	if(m_stPEHeader.NumberOfRvaAndSizes == 0)
	{
		return true;
	}
	DWORD dwBaseRVA = m_stPEHeader.DataDirectory[0].VirtualAddress;
	DWORD dwSizeofdata = m_stPEHeader.DataDirectory[0].Size;	
	if(dwSizeofdata == 0 && dwBaseRVA == 0)
	{
		return true;
	}
	if(dwSizeofdata == 0 ||dwBaseRVA == 0)
	{
		return false;
	}

	DWORD dwOffset = 0;
	if(OUT_OF_FILE == Rva2FileOffset(dwBaseRVA, &dwOffset))
	{
		return false;
	}

	DWORD dwNameRVA = 0;
	if(!ReadBuffer(&dwNameRVA, dwOffset+ 0x0C, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}
	if(dwNameRVA == 0)
	{
		return false;
	}
	if(OUT_OF_FILE == Rva2FileOffset(dwNameRVA, &dwNameRVA))
	{
		return false;
	}
	DWORD dwNameofDll = 0x00; 
	if(!ReadBuffer(&dwNameofDll, dwNameRVA, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}
	if(dwNameofDll ==0x00)
	{
		return false;
	}
	
	DWORD dwNoOfFun = 0;
	if(!ReadBuffer(&dwNoOfFun, dwOffset+ 0x14, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}
	DWORD dwNoOfName = 0;
	if(!ReadBuffer(&dwNoOfName, dwOffset+ 0x18, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}
	DWORD dwAddOfTableRVA = 0;
	if(!ReadBuffer(&dwAddOfTableRVA, dwOffset+ 0x1C, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}

	DWORD dwNamePointerRVA = 0;
	if(!ReadBuffer(&dwNamePointerRVA, dwOffset+ 0x20, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}
	if(dwNamePointerRVA != dwAddOfTableRVA + (dwNoOfFun * 0x4))
	{
		return false;
	}

	DWORD dwOrdinalTableRVA = 0;
	if(!ReadBuffer(&dwOrdinalTableRVA, dwOffset+ 0x24, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}
	if(dwOrdinalTableRVA != dwNamePointerRVA +(dwNoOfName * 0x4))
	{
		return false;
	}
	if(OUT_OF_FILE == Rva2FileOffset(dwNamePointerRVA, &dwNamePointerRVA))
	{
		return false;
	}

	// Commented for now as its checking all the function names in the export table
	/*DWORD dwFunNameRVA = 0,dwFunNameData = 0;
	for(DWORD i = dwNamePointerRVA; i < dwNamePointerRVA + (dwNoOfName * 0x4); i += 0x4)
	{
		if(!ReadBuffer(&dwFunNameRVA, i, sizeof(DWORD), sizeof(DWORD)))
		{
			return false;
		}
		if(OUT_OF_FILE == Rva2FileOffset(dwFunNameRVA, &dwFunNameRVA))
		{
			return false;
		}
		if(!ReadBuffer(&dwFunNameData, dwFunNameRVA, sizeof(DWORD), sizeof(DWORD)))
		{
			return false;
		}		
		if(dwFunNameData == 0)
		{
			return false;
		}
	}*/
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: InitAEPSection
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: AEP Section Initialization
--------------------------------------------------------------------------------------*/
void CMaxPEFile::InitAEPSection()
{
	if(m_dwAEPSectionSize > 5 * 1024 * 1024)	// limit memory allocaton to 5 MB
	{
		m_dwAEPSectionSize = -1;					// Dont try to read the section data again!
		m_dwAEPSectionStartPos = -1;				// Dont try to read the section data again!
		m_pAEPSectionBuffer = NULL;
		return ;
	}

	// can we try to read the buffer or did we try and were not able to read?
	if((m_pAEPSectionBuffer == NULL) && (m_dwAEPSectionSize > 0) && (m_dwAEPSectionStartPos > 0))
	{
		bool bAEPReadSuccess = false;
		//m_pAEPSectionBuffer = new BYTE[m_dwAEPSectionSize];
		//memset(m_pAEPSectionBuffer, 0, m_dwAEPSectionSize);
		m_pAEPSectionBuffer = (LPBYTE)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT | GMEM_SHARE, m_dwAEPSectionSize);

		DWORD dwSetFileOffSet = ::SetFilePointer(m_hFileHandle, m_dwAEPSectionStartPos + m_iMZOffset, NULL, FILE_BEGIN);
		if(dwSetFileOffSet == m_dwAEPSectionStartPos + m_iMZOffset)
		{
			DWORD dwBytesRead = 0;
			if(ReadFile(m_hFileHandle, m_pAEPSectionBuffer, m_dwAEPSectionSize, &dwBytesRead, NULL))
			{
				if(m_dwAEPSectionSize == dwBytesRead)
				{
					bAEPReadSuccess = true;
				}
			}
		}

		if(!bAEPReadSuccess)
		{
			m_dwAEPSectionSize = -1;					// Dont try to read the section data again!
			m_dwAEPSectionStartPos = -1;				// Dont try to read the section data again!
			GlobalFree(m_pAEPSectionBuffer);
			//delete [] m_pAEPSectionBuffer;
			m_pAEPSectionBuffer = NULL;
		}
	}
}

/*-------------------------------------------------------------------------------------
	Function		: SearchForPEHdr
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Searches for existance of another PE file in overlay or resource
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::SearchForPEHdr()
{
	const int HDR_BUFF_SIZE = 0x100;

	if (m_dwFileSize <= HDR_BUFF_SIZE)
	{
		return false;
	}

	BYTE *byBuff = new BYTE[HDR_BUFF_SIZE];
	if(!byBuff)
	{
		return false;
	}

	memset((void *)byBuff,0x00,HDR_BUFF_SIZE);

	if(ReadBuffer(byBuff, 0, HDR_BUFF_SIZE, HDR_BUFF_SIZE))
	{
		for(int iOffset = 0; iOffset < HDR_BUFF_SIZE - 2; iOffset++)
		{
			if((*(WORD *)&byBuff[iOffset]) == IMAGE_DOS_SIGNATURE)
			{
				if(byBuff)
				{
					delete []byBuff;
					byBuff = NULL;
				}
				m_iMZOffset = iOffset;
				return LoadPEFile(m_hFileHandle, false);
			}
		}
	}
	if(byBuff)
	{
		delete []byBuff;
		byBuff = NULL;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsReloadedPE
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: 
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::IsReloadedPE()
{
	return m_iMZOffset ? true : false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForVBFiles
	In Parameters	: 
	Out Parameters	: true is success else false
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Determines whether file is Visul Basic Compiled (VB)
--------------------------------------------------------------------------------------*/
bool CMaxPEFile::CheckForVBFiles()
{
	if(m_byAEPBuff[0] != 0x68)
	{
		return false;
	}

	DWORD	dwVBRVA = *(DWORD *)&m_byAEPBuff[0x01] - m_stPEHeader.ImageBase ;
	DWORD	dwVBOffset = 0x00;
	if(OUT_OF_FILE == Rva2FileOffset(dwVBRVA, &dwVBOffset)) 
	{
		return false;
	}
	if(ReadBuffer(&dwVBOffset, dwVBOffset,0x04,0x04))
	{
		if(dwVBOffset == 0x21354256)
		{
			m_dwVBSigOff = dwVBRVA;
			return true;
		}
	}
	return false;
}

double CMaxPEFile::GetEntropy(const DWORD bytes_count[256], DWORD total_length)
{
	double entropy = 0.0;

	for (DWORD i = 0; i < 256; i++)
	{
		double temp = 0;
		if (total_length)
			temp = static_cast<double>(bytes_count[i]) / total_length;
		if (temp > 0.)
			entropy -= temp * (log(temp) / log(2.0));
	}

	return entropy;
}

BOOL CMaxPEFile::GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT)
{
	BOOL		bRetValue = FALSE;
	TCHAR		szOut[MAX_PATH] = { 0x00 };

	if (pszAnsiIN == NULL || pszUnicodeOUT == NULL)
	{
		return bRetValue;
	}

	int iRetLen = MultiByteToWideChar(CP_ACP, 0, pszAnsiIN, strlen(pszAnsiIN), szOut, MAX_PATH);

	if (iRetLen > 0x00)
	{
		_tcscpy(pszUnicodeOUT, szOut);
	}

	return bRetValue;
}


bool CMaxPEFile::GetEntropy()
{
	//Variable Initialization
	DWORD	dwTempPRD = 0; //Temporary PointerToRawData;
	DWORD	dwSizeRD = 0;
	DWORD	dwBytesCount[256] = { 0 };
	WORD	wSec = 0x00;
	DWORD	NoOfBytesToRead = 0;
	double	dummy = 0.0;
	double	TotalEntropy = 0.0;

	//OutputDebugString(L"TEST : GetEntropy : Inside");

	m_mlFeatureData.m_dSectionMeanEntropy = 0.0;
	m_mlFeatureData.m_dSectionMaxEntropy = 0;		//As Entropy ranges from 0 to 8 only
	m_mlFeatureData.m_dSectionMinEntropy = 10.0;

	//OutputDebugString(L"TEST : GetEntropy : Level 1");

	int checkOverlayCount = 0;
	if (!m_stPEHeader.NumberOfSections)
	{
		m_mlFeatureData.m_dSectionMinEntropy = 0;		//Skipping Entropy Calculation Altogether
		return false;
	}

	//OutputDebugString(L"TEST : GetEntropy : Level 2");

	for (wSec = 0x00; wSec < m_stPEHeader.NumberOfSections; wSec++)
	{
		//OutputDebugString(L"TEST : GetEntropy : Level For 2.1");
		for (int ii = 0; ii < 256; ii++)
		{
			dwBytesCount[ii] = 0;
		}
		//OutputDebugString(L"TEST : GetEntropy : Level For 2.2");
		if (m_stSectionHeader[wSec].Misc.VirtualSize != 0x00)
		{
			//OutputDebugString(L"TEST : GetEntropy : Level For 2.3");
			dwTempPRD = m_stSectionHeader[wSec].PointerToRawData;
			dwSizeRD = m_stSectionHeader[wSec].SizeOfRawData;
			//OutputDebugString(L"TEST : GetEntropy : Level For 2.4");
			if (!dwTempPRD || !dwSizeRD)
			{
				m_mlFeatureData.m_dSectionMinEntropy = 0.0;
				continue;
			}
			//OutputDebugString(L"TEST : GetEntropy : Level For 2.5");

			if (m_mlFeatureData.m_pbyBuff != NULL)
			{
				delete[]m_mlFeatureData.m_pbyBuff;
				m_mlFeatureData.m_pbyBuff = NULL;
			}
			//OutputDebugString(L"TEST : GetEntropy : Level For 2.6");
			m_mlFeatureData.m_pbyBuff = new BYTE[dwSizeRD];
			//OutputDebugString(L"TEST : GetEntropy : Level For 2.7");
			if (!m_mlFeatureData.m_pbyBuff)
			{
				m_mlFeatureData.m_dSectionMinEntropy = 0;
				continue;	//Skipping Section
			}

			//OutputDebugString(L"TEST : GetEntropy : Level For 2.8");

			NoOfBytesToRead = (dwSizeRD);
			if (ReadBuffer(m_mlFeatureData.m_pbyBuff,dwTempPRD, NoOfBytesToRead, NoOfBytesToRead))
			{
				//OutputDebugString(L"TEST : GetEntropy : Level For 2.9");
				DWORD iter = 0;
				for (iter = 0; iter < NoOfBytesToRead; ++iter)
				{
					++dwBytesCount[static_cast<unsigned char>(m_mlFeatureData.m_pbyBuff[iter])];
				}
				//OutputDebugString(L"TEST : GetEntropy : Level For 2.10");

				if (memcmp(m_stSectionHeader[wSec].Name, ".rsrc", 5) == 0)
				{
					if (dwSizeRD > (5 * 1024 * 1024))
					{
						_tcscpy(m_szResourceMD5, L"100");
					}
					else
					{
						//OutputDebugString(L"TEST : GetEntropy : Before RSRC Entropy Calculation");
						CMaxMD5  objResmd5;
						objResmd5.digestString(&m_mlFeatureData.m_pbyBuff[0x00], NoOfBytesToRead);

						//OutputDebugString(L"TEST : GetEntropy : After RSRC Entropy Calculation");

						GetUnicodeString(objResmd5.digestChars, m_szResourceMD5);
						//OutputDebugString(L"TEST : GetEntropy : After Unicodeconversion");
					}
				}
				//OutputDebugString(L"TEST : GetEntropy : Level For 2.11");
			}
			else
			{
				m_mlFeatureData.m_dSectionMinEntropy = 0.0;
				if (m_mlFeatureData.m_pbyBuff != NULL)
				{
					delete[]m_mlFeatureData.m_pbyBuff;
					m_mlFeatureData.m_pbyBuff = NULL;
				}
				continue;
			}
			//OutputDebugString(L"TEST : GetEntropy : Level For 2.12");
		}
		else
		{
			return false;
		}

		//OutputDebugString(L"TEST : GetEntropy : Level For 2.13");

		DWORD total_length = NoOfBytesToRead;
		dummy = GetEntropy(dwBytesCount, total_length);
		TotalEntropy += dummy;
		if (dummy > m_mlFeatureData.m_dSectionMaxEntropy)
			m_mlFeatureData.m_dSectionMaxEntropy = dummy;
		if (dummy < m_mlFeatureData.m_dSectionMinEntropy)
			m_mlFeatureData.m_dSectionMinEntropy = dummy;
	}

	//OutputDebugString(L"TEST : GetEntropy : Before MeanEntropy Calculation");

	m_mlFeatureData.m_dSectionMeanEntropy = (TotalEntropy) / (static_cast<double>(m_stPEHeader.NumberOfSections));

	//OutputDebugString(L"TEST : GetEntropy : After MeanEntropy Calculation");

	if (m_mlFeatureData.m_pbyBuff)
	{

		delete[]m_mlFeatureData.m_pbyBuff;
		m_mlFeatureData.m_pbyBuff = NULL;
	}

	return true;
}

bool CMaxPEFile::ParseResourceTreeEx(PIMAGE_RESOURCE_DIRECTORY pResDir, DWORD dwResourceDirectory, DWORD dwOffset)
{

	DWORD	dwTotalRsrcEntry = pResDir->NumberOfIdEntries + pResDir->NumberOfNamedEntries;
	if (dwTotalRsrcEntry > 0x50 || dwTotalRsrcEntry <= 0)
	{
		m_mlFeatureData.m_dResourceMinEntropy = 0.0;
		m_mlFeatureData.m_dwResourceMinSize = 0;
		return false;
	}
	if (pResDir == NULL)
	{
		m_mlFeatureData.m_dResourceMinEntropy = 0.0;
		m_mlFeatureData.m_dwResourceMinSize = 0;
		return false;
	}
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pRsrc_Dir_Entry = new IMAGE_RESOURCE_DIRECTORY_ENTRY[dwTotalRsrcEntry];
	if (pRsrc_Dir_Entry == NULL)
	{
		m_mlFeatureData.m_dResourceMinEntropy = 0.0;
		m_mlFeatureData.m_dwResourceMinSize = 0;
		return false;
	}
	memset(pRsrc_Dir_Entry, 0x00, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * dwTotalRsrcEntry);


	DWORD	dwReadOffset = dwOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
	if (!ReadBuffer(pRsrc_Dir_Entry, dwReadOffset, (sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * dwTotalRsrcEntry), (sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * dwTotalRsrcEntry)))
	{
		delete[]pRsrc_Dir_Entry;
		pRsrc_Dir_Entry = NULL;
		m_mlFeatureData.m_dResourceMinEntropy = 0.0;
		m_mlFeatureData.m_dwResourceMinSize = 0;
		return false;
	}

	DWORD dwIndex = 0x00;
	for (dwIndex = 0x00; dwIndex < dwTotalRsrcEntry; dwIndex++)
	{
		m_mlFeatureData.m_dwCurruptResCounter++;

		if (m_mlFeatureData.m_dwCurruptResCounter == 0x1F4)
		{
			if (m_mlFeatureData.m_dwTotalNoOfResources == 0x00)
			{
				m_mlFeatureData.m_bResCurrupted = true;
			}
		}

		if (pRsrc_Dir_Entry[dwIndex].DataIsDirectory)
		{
			if (!pRsrc_Dir_Entry[dwIndex].OffsetToDirectory)
			{
				//dwIndex++;
				continue;
			}
			IMAGE_RESOURCE_DIRECTORY ResourceRoot;
			memset(&ResourceRoot, 0x00, sizeof(IMAGE_RESOURCE_DIRECTORY));
			//dwResourceDirectory + pRsrc_Dir_Entry[dwIndex].OffsetToDirectory;
			//m_pMaxPEFile->SetFilePointer(0x00);
			if (!ReadBuffer(&ResourceRoot, dwResourceDirectory + pRsrc_Dir_Entry[dwIndex].OffsetToDirectory, sizeof(IMAGE_RESOURCE_DIRECTORY), sizeof(IMAGE_RESOURCE_DIRECTORY)))
			{
				m_mlFeatureData.m_dResourceMinEntropy = 0.0;
				m_mlFeatureData.m_dwResourceMinSize = 0;
				if (pRsrc_Dir_Entry != NULL)
				{
					delete[]pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}
			if (m_mlFeatureData.m_dwTotalNoOfResources >= 1400 || m_mlFeatureData.m_bResCurrupted == true)
			{
				m_mlFeatureData.m_dResourceMinEntropy = 0.0;
				m_mlFeatureData.m_dwResourceMinSize = 0;
				if (pRsrc_Dir_Entry != NULL)
				{
					delete[]pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}

			if (!ParseResourceTreeEx(&ResourceRoot, dwResourceDirectory, dwResourceDirectory + pRsrc_Dir_Entry[dwIndex].OffsetToDirectory))
			{
				m_mlFeatureData.m_dResourceMinEntropy = 0.0;
				m_mlFeatureData.m_dwResourceMinSize = 0;
				if (pRsrc_Dir_Entry != NULL)
				{
					delete[]pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}

		}
		else
		{
			if (!pRsrc_Dir_Entry[dwIndex].OffsetToData)
			{
				continue;
			}

			PIMAGE_RESOURCE_DATA_ENTRY pRsrc_Entry = new IMAGE_RESOURCE_DATA_ENTRY;
			if (pRsrc_Entry == NULL)
			{
				continue;
			}

			memset(pRsrc_Entry, 0x00, sizeof(IMAGE_RESOURCE_DATA_ENTRY));
			if (!ReadBuffer(pRsrc_Entry, dwResourceDirectory + pRsrc_Dir_Entry[dwIndex].OffsetToDirectory, (sizeof(IMAGE_RESOURCE_DATA_ENTRY)), (sizeof(IMAGE_RESOURCE_DATA_ENTRY))))
			{
				if (pRsrc_Entry != NULL)
				{
					delete pRsrc_Entry;
					pRsrc_Entry = NULL;
				}
				m_mlFeatureData.m_dResourceMinEntropy = 0.0;
				m_mlFeatureData.m_dwResourceMinSize = 0;
				if (pRsrc_Dir_Entry != NULL)
				{
					delete[]pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}
			DWORD dwSizeRD = 0;
			if (pRsrc_Entry->Size > 0 && pRsrc_Entry->Size < 0xA00000)
			{
				dwSizeRD = pRsrc_Entry->Size;
			}
			if (dwSizeRD <= 0)
			{
				m_mlFeatureData.m_dwResourceMinSize = 0;
				m_mlFeatureData.m_dResourceMinEntropy = 0.0;
				if (pRsrc_Entry != NULL)
				{
					delete pRsrc_Entry;
					pRsrc_Entry = NULL;
				}
				if (pRsrc_Dir_Entry != NULL)
				{
					delete[]pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}

			m_mlFeatureData.m_dwResourceTotalSize += dwSizeRD;

			if (dwSizeRD > m_mlFeatureData.m_dwResourceMaxSize)
				m_mlFeatureData.m_dwResourceMaxSize = dwSizeRD;
			if (dwSizeRD < m_mlFeatureData.m_dwResourceMinSize)
				m_mlFeatureData.m_dwResourceMinSize = dwSizeRD;

			if (m_mlFeatureData.m_pbyBuff)
			{
				delete[]m_mlFeatureData.m_pbyBuff;
				m_mlFeatureData.m_pbyBuff = NULL;
			}
			m_mlFeatureData.m_pbyBuff = new BYTE[dwSizeRD];
			if (m_mlFeatureData.m_pbyBuff == NULL)
			{
				m_mlFeatureData.m_dResourceMinEntropy = 0.0;
				m_mlFeatureData.m_dwResourceMinSize = 0;
				if (pRsrc_Entry != NULL)
				{
					delete pRsrc_Entry;
					pRsrc_Entry = NULL;
				}
				if (pRsrc_Dir_Entry != NULL)
				{
					delete[]pRsrc_Dir_Entry;
					pRsrc_Dir_Entry = NULL;
				}
				return false;
			}
			memset(m_mlFeatureData.m_pbyBuff, 0x00, sizeof(BYTE) * dwSizeRD);
			DWORD dwRVA2Data = pRsrc_Entry->OffsetToData;
			DWORD dwFileOffset = 0;
			DWORD dummy = Rva2FileOffset(dwRVA2Data, &dwFileOffset);

			DWORD dwBytesCount[256] = { 0 };
			if (ReadBuffer(m_mlFeatureData.m_pbyBuff,dwFileOffset, dwSizeRD, dwSizeRD))
			{
				DWORD iter = 0;
				for (iter = 0; iter < dwSizeRD; ++iter)
				{
					++dwBytesCount[static_cast<unsigned char>(m_mlFeatureData.m_pbyBuff[iter])];
				}
			}
			else
			{
				//m_dResourceMinEntropy = 0.0;
				//m_dwResourceMinSize = 0;

				if (m_mlFeatureData.m_pbyBuff)
				{
					delete[]m_mlFeatureData.m_pbyBuff;
					m_mlFeatureData.m_pbyBuff = NULL;
				}

				if (pRsrc_Entry != NULL)
				{
					delete pRsrc_Entry;
					pRsrc_Entry = NULL;
				}
				continue;
				//Throw Appropriate exception
			}

			DWORD total_length = dwSizeRD;
			double dTempHolder = GetEntropy(dwBytesCount, dwSizeRD);

			if (dTempHolder > m_mlFeatureData.m_dResourceMaxEntropy)
			{
				m_mlFeatureData.m_dResourceMaxEntropy = dTempHolder;
			}
			if (dTempHolder < m_mlFeatureData.m_dResourceMinEntropy)
			{
				m_mlFeatureData.m_dResourceMinEntropy = dTempHolder;
			}

			m_mlFeatureData.m_dResourceTotalEntropy += dTempHolder;

			if (m_mlFeatureData.m_pbyBuff)
			{
				delete[]m_mlFeatureData.m_pbyBuff;
				m_mlFeatureData.m_pbyBuff = NULL;
			}
			if (pRsrc_Entry != NULL)
			{
				delete pRsrc_Entry;
				pRsrc_Entry = NULL;
			}
			//DWORD myOffsetToData = pResData->OffsetToData;
			m_mlFeatureData.m_dwTotalNoOfResources++;
		}
	}
	if (pRsrc_Dir_Entry != NULL)
	{
		delete[]pRsrc_Dir_Entry;
		pRsrc_Dir_Entry = NULL;
	}
}


bool CMaxPEFile::GetResourceEntropyEx()
{
	m_mlFeatureData.m_dResourceMaxEntropy = 0.0;
	m_mlFeatureData.m_dResourceMinEntropy = 10.0;
	m_mlFeatureData.m_dResourceMeanEntropy = 0.0;

	m_mlFeatureData.m_dResourceTotalEntropy = 0.0;
	m_mlFeatureData.m_dwTotalNoOfResources = 0;

	m_mlFeatureData.m_dwResourceMaxSize = 0;
	m_mlFeatureData.m_dResourceMeanSize = 0;
	m_mlFeatureData.m_dwResourceMinSize = UINT_MAX;
	m_mlFeatureData.m_dwResourceTotalSize = 0;

	double		dTemp = 0.0;
	DWORD		dwResourceDirectoryVA = m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	WORD		wSec = 0x00;

	if (!dwResourceDirectoryVA)
	{
		m_mlFeatureData.m_dResourceMinEntropy = 0.0;
		m_mlFeatureData.m_dwResourceMinSize = 0;
		return false;
	}

	bool isResourceHeaderValid = false;

	for (wSec = 0x00; wSec < m_stPEHeader.NumberOfSections; ++wSec)
	{
		if (m_stSectionHeader[wSec].VirtualAddress == dwResourceDirectoryVA && !memcmp(m_stSectionHeader[wSec].Name, ".rsrc", 5))
		{
			isResourceHeaderValid = true;
			m_mlFeatureData.m_dwResourceOffsetLimit = (m_stSectionHeader[wSec].PointerToRawData + m_stSectionHeader[wSec].SizeOfRawData);
			DWORD dummy = 0;
			if (m_stSectionHeader[wSec].PointerToRawData >= m_dwFileSize)
			{
				m_mlFeatureData.m_dwResourceMinSize = 0;
				m_mlFeatureData.m_dResourceMinEntropy = 0.0;
				return false;
			}
			else if (Rva2FileOffset(dwResourceDirectoryVA, &dummy) >= m_mlFeatureData.m_dwResourceOffsetLimit)
			{
				m_mlFeatureData.m_dwResourceMinSize = 0;
				m_mlFeatureData.m_dResourceMinEntropy = 0.0;
				return false;
			}
			break;
		}
	}

	if (!isResourceHeaderValid)
	{
		m_mlFeatureData.m_dResourceMinEntropy = 0.0;
		m_mlFeatureData.m_dwResourceMinSize = 0;
		return false;
	}
	bool iRetStatus = false;
	DWORD dwResourceDirectory = 0;
	//	DWORD no_use = m_pMaxPEFile->Rva2FileOffset(dwResourceDirectoryVA, &dwResourceDirectory);


	if (OUT_OF_FILE == Rva2FileOffset(m_stPEHeader.DataDirectory[2].VirtualAddress, &dwResourceDirectory))
	{
		return iRetStatus;
	}

	IMAGE_RESOURCE_DIRECTORY ResourceRoot;
	memset(&ResourceRoot, 0x00, sizeof(IMAGE_RESOURCE_DIRECTORY));

	if (!ReadBuffer(&ResourceRoot, dwResourceDirectory, sizeof(IMAGE_RESOURCE_DIRECTORY), sizeof(IMAGE_RESOURCE_DIRECTORY)))
	{
		return iRetStatus;
	}

	if (!dwResourceDirectory)
	{
		m_mlFeatureData.m_dResourceMinEntropy = 0.0;
		m_mlFeatureData.m_dwResourceMinSize = 0;
		return false;
	}

	m_mlFeatureData.m_pResDir = &ResourceRoot;

	DWORD	dwTotalRsrcEntry = ResourceRoot.NumberOfIdEntries + ResourceRoot.NumberOfNamedEntries;
	if (dwTotalRsrcEntry > 0x30 || dwTotalRsrcEntry <= 0)
	{
		m_mlFeatureData.m_dResourceMinEntropy = 0.0;
		m_mlFeatureData.m_dwResourceMinSize = 0;
		return false;
	}
	if (!ParseResourceTreeEx(&ResourceRoot, dwResourceDirectory, dwResourceDirectory))
	{
		if (m_mlFeatureData.m_pbyBuff)
		{
			delete[]m_mlFeatureData.m_pbyBuff;
			m_mlFeatureData.m_pbyBuff = NULL;
		}
		m_mlFeatureData.m_dResourceMinEntropy = 0.0;
		m_mlFeatureData.m_dwResourceMinSize = 0;
		return false;
	}
	if (m_mlFeatureData.m_dResourceMinEntropy == 10)
	{
		m_mlFeatureData.m_dResourceMinEntropy = 0;
	}
	if (m_mlFeatureData.m_dwResourceMinSize == UINT_MAX)
	{
		m_mlFeatureData.m_dwResourceMinSize = 0;
	}

	if (m_mlFeatureData.m_dwTotalNoOfResources)
		m_mlFeatureData.m_dResourceMeanEntropy = (m_mlFeatureData.m_dResourceTotalEntropy / (double)(m_mlFeatureData.m_dwTotalNoOfResources));

	if (m_mlFeatureData.m_dwTotalNoOfResources)
		m_mlFeatureData.m_dResourceMeanSize = (m_mlFeatureData.m_dwResourceTotalSize / (double)m_mlFeatureData.m_dwTotalNoOfResources);

	if (m_mlFeatureData.m_pbyBuff)
	{
		delete[]m_mlFeatureData.m_pbyBuff;
		m_mlFeatureData.m_pbyBuff = NULL;
	}

	return true;
}

void CMaxPEFile::GetNoOfImportsEx()
{
	m_mlFeatureData.m_dwImportsNbDLL = 0;
	m_mlFeatureData.m_dwImportsNb = 0;
	//PDWORD pImageBase = &m_dwImageBase;
	DWORD dwImportDirectoryVA = m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;


	DWORD dwImportSize = m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	DWORD dummy = Rva2FileOffset(dwImportDirectoryVA, &dummy);
	if (!dwImportDirectoryVA)
	{
		return;
	}

	if (m_mlFeatureData.m_pbyBuff)
	{
		delete[]m_mlFeatureData.m_pbyBuff;
		m_mlFeatureData.m_pbyBuff = NULL;
	}

	DWORD dwImportDirectory = 0;
	DWORD dum = Rva2FileOffset(dwImportDirectoryVA, &dwImportDirectory);

	DWORD FileSize = m_dwFileSize;
	if (dwImportDirectory >= FileSize)
		return;

	DWORD dwTotalImport = sizeof(IMAGE_IMPORT_DESCRIPTOR);
	if (dwImportSize > dwTotalImport)
	{
		dwTotalImport = dwImportSize / dwTotalImport;
	}
	else
	{
		return;
	}
	if (dwTotalImport <= 0)
	{
		return;
	}
	PIMAGE_IMPORT_DESCRIPTOR pImport_Descr = new IMAGE_IMPORT_DESCRIPTOR[dwTotalImport];
	if (pImport_Descr == NULL)
	{
		return;
	}
	memset(pImport_Descr, 0x00, sizeof(IMAGE_IMPORT_DESCRIPTOR) * dwTotalImport);


	if (!ReadBuffer(pImport_Descr, dwImportDirectory, sizeof(IMAGE_IMPORT_DESCRIPTOR) * dwTotalImport, sizeof(IMAGE_IMPORT_DESCRIPTOR) * dwTotalImport))
	{
		if (pImport_Descr != NULL)
		{
			delete[]pImport_Descr;
			pImport_Descr = NULL;
		}
		m_mlFeatureData.m_dwImportsNb = 0;
		return;
	}
	DWORD dwTempOffsetHolder = 0;
	DWORD dwNewOffset = 0;
	DWORD dwCounter = 0x00;
	while (pImport_Descr[dwCounter].Name != 0 && dwCounter < dwTotalImport)
	{
		m_mlFeatureData.m_dwImportsNbDLL++;
		dwNewOffset = 0x00;

		if (pImport_Descr[dwCounter].OriginalFirstThunk != 0)
		{
			Rva2FileOffset(pImport_Descr[dwCounter].OriginalFirstThunk, &dwTempOffsetHolder);
			if (!dwTempOffsetHolder)
			{
				//dwCounter++;
				//continue;
				if (pImport_Descr != NULL)
				{
					delete[]pImport_Descr;
					pImport_Descr = NULL;
				}
				m_mlFeatureData.m_dwImportsNb = 0;
				m_mlFeatureData.m_dwImportsNbDLL = 0;
				return;
			}
			dwNewOffset += dwTempOffsetHolder;
		}
		else
		{
			Rva2FileOffset(pImport_Descr[dwCounter].FirstThunk, &dwTempOffsetHolder);
			if (!dwTempOffsetHolder)
			{
				//dwCounter++;
				//continue;
				if (pImport_Descr != NULL)
				{
					delete[]pImport_Descr;
					pImport_Descr = NULL;
				}
				m_mlFeatureData.m_dwImportsNb = 0;
				m_mlFeatureData.m_dwImportsNbDLL = 0;
				return;
			}
			dwNewOffset += dwTempOffsetHolder;
		}


		if (m_b64bit)
		{
			//pimage_thunk_data64 = reinterpret_cast<PIMAGE_THUNK_DATA64>(pHintName);
			IMAGE_THUNK_DATA64 pimage_thunk_data64;

			DWORD dwSize = sizeof(IMAGE_THUNK_DATA64);
			memset(&pimage_thunk_data64, 0, dwSize);
			if (!ReadBuffer(&pimage_thunk_data64, dwNewOffset, dwSize, dwSize))
			{
				if (pImport_Descr != NULL)
				{
					delete[]pImport_Descr;
					pImport_Descr = NULL;
				}
				m_mlFeatureData.m_dwImportsNb = 0;
				m_mlFeatureData.m_dwImportsNbDLL = 0;
				return;
			}
			while (pimage_thunk_data64.u1.AddressOfData != 0)
			{
				//pimage_thunk_data64++;
				dwNewOffset += dwSize;
				memset(&pimage_thunk_data64, 0, dwSize);
				if (!ReadBuffer(&pimage_thunk_data64, dwNewOffset, dwSize, dwSize))
				{
					if (pImport_Descr != NULL)
					{
						delete[]pImport_Descr;
						pImport_Descr = NULL;
					}
					m_mlFeatureData.m_dwImportsNb = 0;
					m_mlFeatureData.m_dwImportsNbDLL = 0;
					return;
				}
				m_mlFeatureData.m_dwImportsNb++;
			}
		}
		else
		{
			//pimage_thunk_data32= reinterpret_cast<PIMAGE_THUNK_DATA32>(pHintName);
			IMAGE_THUNK_DATA32 pimage_thunk_data32;
			DWORD dwSize = sizeof(IMAGE_THUNK_DATA32);
			memset(&pimage_thunk_data32, 0, dwSize);
			if (!ReadBuffer(&pimage_thunk_data32, dwNewOffset, dwSize, dwSize))
			{
				if (pImport_Descr != NULL)
				{
					delete[]pImport_Descr;
					pImport_Descr = NULL;
				}
				m_mlFeatureData.m_dwImportsNb = 0;
				m_mlFeatureData.m_dwImportsNbDLL = 0;
				return;
			}
			while (pimage_thunk_data32.u1.AddressOfData != 0)
			{
				///pimage_thunk_data32++;
				dwNewOffset += dwSize;
				memset(&pimage_thunk_data32, 0, dwSize);
				if (!ReadBuffer(&pimage_thunk_data32, dwNewOffset, dwSize, dwSize))
				{
					if (pImport_Descr != NULL)
					{
						delete[]pImport_Descr;
						pImport_Descr = NULL;
					}
					m_mlFeatureData.m_dwImportsNb = 0;
					m_mlFeatureData.m_dwImportsNbDLL = 0;
					return;
				}
				m_mlFeatureData.m_dwImportsNb++;
			}
		}
		dwCounter++;
	}
}

/******************************************************************************
Function Name	:	Calculate_Section_Min_Mean_RawSize
Author			:	Harshvardhan Patel
Output			:   void
Description		:	Calculates Min/Mean Section RawSize
*******************************************************************************/
void CMaxPEFile::GetSecMinMeanRSize()
{
	WORD wSec = 0x00;
	DWORD SizeSum = 0;
	m_mlFeatureData.m_dwSectionMinRawSize = MAXDWORD;
	m_mlFeatureData.m_dSectionMeanRawSize = 0.0;

	for (wSec = 0x00; wSec < m_stPEHeader.NumberOfSections; ++wSec)
	{
		SizeSum += m_stSectionHeader[wSec].SizeOfRawData;
		if (m_stSectionHeader[wSec].SizeOfRawData < m_mlFeatureData.m_dwSectionMinRawSize)
			m_mlFeatureData.m_dwSectionMinRawSize = m_stSectionHeader[wSec].SizeOfRawData;
	}
	if (m_stPEHeader.NumberOfSections)
		m_mlFeatureData.m_dSectionMeanRawSize = (SizeSum / (double)m_stPEHeader.NumberOfSections);
	else
	{
		m_mlFeatureData.m_dwSectionMinRawSize = 0;
	}
}
/******************************************************************************
Function Name	:	Calculate_Section_Min_Mean_RawSize
Author			:	Harshvardhan Patel
Output			:   void
Description		:	Calculates Min/Mean Section VirtualSize
*******************************************************************************/
void CMaxPEFile::GetSecMaxMeanVSize()
{
	WORD wSec = 0x00;
	DWORD SizeSum = 0;
	m_mlFeatureData.m_dwSectionMaxVirtualSize = 0;
	m_mlFeatureData.m_dSectionMeanVirtualSize = 0.0;

	for (wSec = 0x00; wSec < m_stPEHeader.NumberOfSections; ++wSec)
	{
		SizeSum += m_stSectionHeader[wSec].Misc.VirtualSize;
		if (m_stSectionHeader[wSec].Misc.VirtualSize > m_mlFeatureData.m_dwSectionMaxVirtualSize)
			m_mlFeatureData.m_dwSectionMaxVirtualSize = m_stSectionHeader[wSec].Misc.VirtualSize;
	}
	if (m_stPEHeader.NumberOfSections)
		m_mlFeatureData.m_dSectionMeanVirtualSize = (SizeSum / (double)m_stPEHeader.NumberOfSections);
}


bool CMaxPEFile::CalculateMLFeatures()
{
	bool	bRetValue = false;

	//OutputDebugString(L"TEST : Inside CalculateMLFeatures");
	//OutputDebugString(m_szFilePath);

	if (m_bPEFile == false)
	{
		return bRetValue;
	}

	//Initializing Features
	m_mlFeatureData.m_dSectionMeanEntropy = 0.0;
	m_mlFeatureData.m_dSectionMaxEntropy = 0;		//As Entropy ranges from 0 to 8 only
	m_mlFeatureData.m_dSectionMinEntropy = 0;

	m_mlFeatureData.m_dResourceMaxEntropy = 0.0;
	m_mlFeatureData.m_dResourceMinEntropy = 0.0;
	m_mlFeatureData.m_dResourceMeanEntropy = 0.0;

	m_mlFeatureData.m_dResourceTotalEntropy = 0.0;
	m_mlFeatureData.m_dwTotalNoOfResources = 0;

	m_mlFeatureData.m_dwResourceMaxSize = 0;
	m_mlFeatureData.m_dResourceMeanSize = 0;
	m_mlFeatureData.m_dwResourceMinSize = 0;
	m_mlFeatureData.m_dwResourceTotalSize = 0;

	m_mlFeatureData.m_dwImportsNbDLL = 0;
	m_mlFeatureData.m_dwImportsNb = 0;

	m_mlFeatureData.m_dSectionMeanRawSize = 0;
	m_mlFeatureData.m_dwSectionMinRawSize = 0;

	m_mlFeatureData.m_dSectionMeanVirtualSize = 0;
	m_mlFeatureData.m_dwSectionMaxVirtualSize = 0;

	m_mlFeatureData.m_pbyBuff = NULL;
	

	DWORD dwFileSize = m_dwFileSize;

	//Checking For Invalid Sections .....Can be Optimized
	bool hasInvalidSections = false;
	if (m_stPEHeader.NumberOfSections >= 0 && (m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		if (m_stPEHeader.NumberOfSections == 0 && (m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
		{
			hasInvalidSections = true;

		}
		for (DWORD i = 0; i < m_stPEHeader.NumberOfSections; i++)
		{
			if (m_stSectionHeader[i].PointerToRawData >= dwFileSize && m_stSectionHeader[i].SizeOfRawData != 0)
			{
				hasInvalidSections = true;
			}

		}
	}
	//*******************************

	if (hasInvalidSections == true)
		return bRetValue;

	DWORD dwOverlaySize = m_dwFileSize - (m_stSectionHeader[m_stPEHeader.NumberOfSections - 1].PointerToRawData + m_stSectionHeader[m_stPEHeader.NumberOfSections - 1].SizeOfRawData);


	if (dwOverlaySize >
		(2 * (m_stSectionHeader[m_stPEHeader.NumberOfSections - 1].PointerToRawData
			+ m_stSectionHeader[m_stPEHeader.NumberOfSections - 1].SizeOfRawData)))
	{
		if (m_stPEHeader.DataDirectory[0x04].Size != 0x00)
		{
			return bRetValue;
		}
	}

	GetEntropy();

	GetResourceEntropyEx();
	
	GetNoOfImportsEx();

	GetSecMinMeanRSize();

	
	GetSecMaxMeanVSize();

	
	//Freeing the buffers used
	if (m_mlFeatureData.m_pbyBuff)
	{
		delete[]m_mlFeatureData.m_pbyBuff;
		m_mlFeatureData.m_pbyBuff = NULL;
	}

	/*
	int iVerInfoCount = 0;

	CFileVersionInfo objFileVer;
	if (objFileVer.Open(m_pMaxPEFile->m_szFilePath) != FALSE)
	{
		iVerInfoCount = objFileVer.GetCountForML();
		featureValues[27] = static_cast<float>(iVerInfoCount);
	}
	else
	{
		featureValues[27] = 0;
	}
	*/
	

	SummerizedMLFeatures();

	return bRetValue;
}

bool CMaxPEFile::SummerizedMLFeatures()
{
	bool	bRetValue = false;
	TCHAR	szLogLine[1024] = { 0x00 };

	//featureMap["Characteristics"]
	m_mlFeatureData.m_featureValues[0] = (m_stPEHeader.Characteristics);
	
	//featureMap["MajorLinkerVersion"]
	m_mlFeatureData.m_featureValues[1] = (unsigned int)(m_stPEHeader.MajorLinkerVersion);
	
	//featureMap["SizeOfCode"]
	m_mlFeatureData.m_featureValues[2] = (m_stPEHeader.SizeOfCode);
	
	//featureMap["SizeOfInitializedData"]
	m_mlFeatureData.m_featureValues[3] = (m_stPEHeader.SizeOfInitializedData);
	
	//featureMap["AddressOfEntryPoint"]
	m_mlFeatureData.m_featureValues[4] = (unsigned int)(m_stPEHeader.AddressOfEntryPoint);

	//featureMap["MajorOperatingSystemVersion"]
	m_mlFeatureData.m_featureValues[5] = (m_stPEHeader.MajorOperatingSystemVersion);

	//featureMap["MajorSubsystemVersion"]
	m_mlFeatureData.m_featureValues[6] = (m_stPEHeader.MajorSubsystemVersion);

	//featureMap["CheckSum"]
	m_mlFeatureData.m_featureValues[7] = (m_stPEHeader.CheckSum);

	//featureMap["Subsystem"]
	m_mlFeatureData.m_featureValues[8] = (m_stPEHeader.Subsystem);

	//featureMap["DllCharacteristics"]
	m_mlFeatureData.m_featureValues[9] = (m_stPEHeader.DllCharacteristics);

	//featureMap["SizeOfStackReserve"]
	m_mlFeatureData.m_featureValues[10] = (m_stPEHeader.SizeOfStackReserve);

	//featureMap["SectionsNb"]
	m_mlFeatureData.m_featureValues[11] = (m_stPEHeader.NumberOfSections);

	//featureMap["SectionsMeanEntropy"]
	m_mlFeatureData.m_featureValues[12] = (m_mlFeatureData.m_dSectionMeanEntropy);

	//featureMap["SectionsMinEntropy"]
	m_mlFeatureData.m_featureValues[13] = (m_mlFeatureData.m_dSectionMinEntropy);

	//featureMap["SectionsMaxEntropy"]
	m_mlFeatureData.m_featureValues[14] = (m_mlFeatureData.m_dSectionMaxEntropy);

	//featureMap["SectionsMeanRawsize"]
	m_mlFeatureData.m_featureValues[15] = (m_mlFeatureData.m_dSectionMeanRawSize);

	//featureMap["SectionsMinRawsize"]
	m_mlFeatureData.m_featureValues[16] = (m_mlFeatureData.m_dwSectionMinRawSize);

	//featureMap["SectionsMeanVirtualsize"]
	m_mlFeatureData.m_featureValues[17] = (m_mlFeatureData.m_dSectionMeanVirtualSize);

	//featureMap["SectionMaxVirtualsize"]
	m_mlFeatureData.m_featureValues[18] = (m_mlFeatureData.m_dwSectionMaxVirtualSize);

	//featureMap["ImportsNbDLL"]
	m_mlFeatureData.m_featureValues[19] = (m_mlFeatureData.m_dwImportsNbDLL);

	//featureMap["ImportsNb"]
	//featureValues[21] = (m_dwImportsNb);

	//featureMap["ResourcesMeanEntropy"]
	m_mlFeatureData.m_featureValues[20] = (m_mlFeatureData.m_dResourceMeanEntropy);

	//featureMap["ResourcesMinEntropy"]
	m_mlFeatureData.m_featureValues[21] = (m_mlFeatureData.m_dResourceMinEntropy);

	//featureMap["ResourcesMaxEntropy"]
	m_mlFeatureData.m_featureValues[22] = (m_mlFeatureData.m_dResourceMaxEntropy);

	//featureMap["ResourcesMeanSize"]
	m_mlFeatureData.m_featureValues[23] = (m_mlFeatureData.m_dResourceMeanSize);

	//featureMap["ResourcesMinSize"]
	m_mlFeatureData.m_featureValues[24] = (m_mlFeatureData.m_dwResourceMinSize);

	//featureMap["ResourcesMaxSize"]
	m_mlFeatureData.m_featureValues[25] = (m_mlFeatureData.m_dwResourceMaxSize);

	//featureMap["LoadConfigurationSize"]
	m_mlFeatureData.m_featureValues[26] = ((unsigned int)(m_stPEHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size));

	m_mlFeatureData.m_featureValues[27] = 0;

	m_mlFeatureData.m_bAllFeaturesGenerated = true;
	
	/*
	for (int i = 0; i <= 27; i++)
	{
		_stprintf(szLogLine, L"TEST m_featureValues[%d] : %f", i,m_mlFeatureData.m_featureValues[i]);
		OutputDebugString(szLogLine);

	}
	*/
	return bRetValue;
}

DWORD WINAPI CalculateMLFeaturesThread(LPVOID lpParam)
{
	CMaxPEFile* pThis = (CMaxPEFile*)lpParam;
	pThis->m_bMLThreadIsRunning = TRUE;


	pThis->CalculateMLFeatures();

	pThis->m_bMLThreadIsRunning = FALSE;

	return 0x00;
}

bool CMaxPEFile::GenMLFeatures()
{
	bool	bRetValue = false;
	DWORD	dwTdreadID = 0x00;

	if (m_bMLThreadIsRunning == TRUE)
	{
		return false;
	}

	m_hMLFeatureGenThread = NULL;

	m_hMLFeatureGenThread = CreateThread(NULL, 0, CalculateMLFeaturesThread, (LPVOID)this, 0, &dwTdreadID);

	if (m_hMLFeatureGenThread != NULL)
	{
		WaitForSingleObject(m_hMLFeatureGenThread, INFINITE);
		bRetValue = true;
	}

	return bRetValue;
}