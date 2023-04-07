/*=============================================================================
   FILE			: FileHeaderInfo.h
   ABSTRACT		: Reads the PE header 
   DOCUMENTS	: 
   AUTHOR		: 
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 20/09/2006
   NOTES		:
VERSION HISTORY	: 06 Jan 2008, Nupur : This file will read the ascii CRC values.  
============================================================================*/
#pragma once
#include "PEFormat.h"
#include "Crc64.h"
#include "S2S.h"

const int		MAX_NO_OF_IMPORT_TABLE_DATA	= 100;
const int		DD_EXPORT_DIRECTORY_TABLE	= 0;
const int		DD_IMPORT_DIRECTORY_TABLE	= 1;
const int		DD_RESOURCE_TABLE			= 2;
const int		DD_CERTIFICATE_TABLE		= 4;
const int		DD_RELOCATION_TABLE			= 5;
const int		DD_DEBUG_DIRECTORY_TABLE	= 6;
	
const int		WIN_32_BIT_MACHINE_CODE		= 332;

const int		MAX_NO_OF_IMPORT_DIR_TABLE	= 2;
const int		MAX_NO_OF_SECTIONS			= 64;

const BYTE		NULL_CRC_VALUE_4096_SIZE[8]	= {0xa5,0x0f,0x57,0xa4,0x29,0xcb,0xcb,0x64};
const BYTE		NULL_CRC_VALUE_2048_SIZE[8]	= {0xe2,0xc7,0xe4,0x24,0x18,0x16,0xdf,0x1c};
const BYTE		NULL_CRC_VALUE_1024_SIZE[8]	= {0x30,0xe4,0x96,0x04,0xe9,0xc6,0x1e,0xc3};
const BYTE		NULL_CRC_VALUE_512_SIZE[8]	= {0x36,0x3f,0xda,0x35,0x44,0xd7,0x49,0x96};
const BYTE		NULL_CRC_VALUE_256_SIZE[8]	= {0x3b,0x73,0xe8,0x47,0x32,0x34,0xab,0x0b};
const BYTE		NULL_CRC_VALUE_128_SIZE[8]	= {0xfc,0xb5,0x0a,0x16,0xb7,0xd6,0xa1,0xf3};
const BYTE		NULL_CRC_VALUE_64_SIZE[8]	= {0x40,0x24,0x0c,0x68,0xa5,0x5e,0x2a,0x7b};
const BYTE		NULL_CRC_VALUE_32_SIZE[8]	= {0x30,0xcc,0xab,0x3e,0x86,0x1f,0x5a,0x93};
const BYTE		NULL_CRC_VALUE_16_SIZE[8]	= {0xc6,0xc4,0x56,0xdf,0xe8,0xfc,0x85,0x97};
const BYTE		NULL_CRC_VALUE_8_SIZE[8]	= {0x03,0x53,0x41,0x42,0xa6,0xce,0x56,0x6d};
const BYTE		NULL_CRC_VALUE_0_SIZE[8]	= {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

const BYTE		INVALID_TYPE_14_CRCVALUE[8]	= {0x15,0x1c,0x3a,0x91,0x5e,0xc8,0x24,0xe1};
const BYTE		INVALID_TYPE_15_CRCVALUE[8]	= {0x01,0xb2,0x8f,0xc4,0xda,0x1f,0x2b,0xcd};

/*
const CStringA	NULL_CRC_VALUE_4096_SIZE	= "a50f57a429cbcb64";
const CStringA	NULL_CRC_VALUE_2048_SIZE	= "e2c7e4241816df1c";
const CStringA	NULL_CRC_VALUE_1024_SIZE	= "30e49604e9c61ec3";
const CStringA	NULL_CRC_VALUE_512_SIZE		= "363fda3544d74996";
const CStringA	NULL_CRC_VALUE_256_SIZE		= "3b73e8473234ab0b";
const CStringA	NULL_CRC_VALUE_128_SIZE		= "fcb50a16b7d6a1f3";
const CStringA	NULL_CRC_VALUE_64_SIZE		= "40240c68a55e2a7b";
const CStringA	NULL_CRC_VALUE_32_SIZE		= "30ccab3e861f5a93";
const CStringA	NULL_CRC_VALUE_16_SIZE		= "c6c456dfe8fc8597";
const CStringA	NULL_CRC_VALUE_8_SIZE		= "03534142a6ce566d";
*/

#ifdef _NOT_USING_DLL_EXPORT
class CFileHeaderInfo
#else
class CFileHeaderInfo
#endif
{
	//File Header related fucntions
	HMODULE m_hDisasmEngineDll;

	LARGE_INTEGER m_EntryPoint;
	LARGE_INTEGER m_iFileLength;

	TCHAR *m_sFileName;
	WCHAR *m_FullFilePathWithWildCard;

	unsigned char *m_MD5Signature, *m_ExecPathCrc, *m_ExecWidthCrc;
	unsigned char *m_ExecPath, *m_ExecWidth, *m_Exec16Path, *m_Exec16Width;
	unsigned char *m_DOSHeader , *m_ExtendedHeader , *m_OptionalHeader;
	unsigned char *m_SectionHeader, *m_DebugDirectory, *m_ImportDirectoryTable;

	int m_iInternalFileType;
	int m_iEntryPointSectionNumber;
	int m_iNewEntryPointSectionNumber;

	// Helper Functions
	int _GetSectionNumberByAddOfEntryPt();
	long _GetFileOffset(unsigned long ulRVA);
	bool _ValidateSectionInfo(int iSectionNo, int iSizeOfBlock);
	bool _GetCorruptSectionCrcNew(CFile &oFile, unsigned int iSizeOfBlock, LPBYTE lpCRCValue);
	int _GetSectionNoOfResourceTable();
	int _GetSectionNoOfRelocationTable();
	int _GetSectionNumberByVirtualAddress(unsigned long int uliVirtualAddress, unsigned int iSizeOfBlocks);
	int _GetEndOfSectionsPos();
	bool _GetCRCValue(CFile &oFile, int iDataSize, LPBYTE lpCRCValue);
	int _GetLastSectionsPos(int iSizeOfBlock);

	CCrc64 m_objCrc64;
	CS2S m_objDatabase;
	bool m_bImportDBLoaded;
	CFile *m_pLogFile;

protected:
	PMS_IMAGE_DOS_HEADER *m_pDosHeader;
	PMS_IMAGE_OPTIONAL_HEADER *m_pOptionalHeader;
	PMS_IMAGE_SECTION_HEADER *m_pSectionHeader;
	PMS_IMAGE_FILE_HEADER *m_pExtendedHeader;
	PMS_IMAGE_DATA_DIRECTORY *m_pDataDirectory;
	PMS_IMAGE_IMPORT_DIRECTORY_TABLE *m_pImportDirectoryTable;

public:
	CFileHeaderInfo(void);
	virtual ~CFileHeaderInfo(void);

public:
	bool IsInitialized();
	bool LoadDatabase(const CString &csDBFile, CString csLogFolderPath);
	bool UnLoadDatabase();

	bool GetFileHeaderInfo(const TCHAR *sFileName, bool bCheckNullExec, int iExecutableType);

	LPBYTE GetMD5Signature();
	LPBYTE GetExecWidthCRC();
	LPBYTE GetExecPathCRC();
	LARGE_INTEGER GetFileLength();
	bool GetSectionSignature(int iGroupType, int iSizeOfBlock, LPBYTE lpCRCValue);
};
