/*======================================================================================
FILE             : MaxPEFile.h
ABSTRACT         : This module is core part of all scaners
DOCUMENTS	     : 
AUTHOR		     : Tushar Kadam + Ravi Bisht + Swapnil Shanghai
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
#pragma once
#include "pch.h"

class CMaxPEFile;

typedef int (*LPFNExtractFile)(LPCTSTR szFileName, LPTSTR szExtractPath);
typedef bool (*LPFNExtractNonPEFile)(int iFileType, LPCTSTR szFileName, LPTSTR szExtractPath);
typedef int (*LPFNUnpackFileNew)(CMaxPEFile *pInputFile, CMaxPEFile *pOutputFile);
typedef int (*LPFNUnpackFile)(LPCTSTR szFileToUnPack, LPTSTR szUnpackFilePath);
typedef void (*LPFNUnloadDlls)();

const int MAX_VIRUS_NAME = 60;

#define HIDWORD64(l) ((DWORD)(((DWORDLONG)(l)>>32) & 0xFFFFFFFF))
#define LODWORD64(l) ((DWORD)(((DWORDLONG)(l)) & 0xFFFFFFFF))
#define HINIBBLE(l) ((BYTE)(((BYTE)(l)>>4) & 0xF))

const int OUT_OF_FILE	= 0xFF;
const int MAX_SEC_NO	= 100;

const int SEC_VS	= 0x8;
const int SEC_SRD	= 0x10;
const int SEC_PRD	= 0x14;
	
typedef struct _tagPE_HEADER
{
    WORD		e_csum;                      // Checksum
    LONG		e_lfanew;                    // File address of new exe header

    WORD		NumberOfSections;
    WORD		Characteristics;
    WORD		SizeOfOptionalHeader;
    DWORD		NumberOfSymbols;

	//Features Added For ML *************************************************

	BYTE		MajorLinkerVersion;
	DWORD		SizeOfInitializedData;
	WORD		MajorOperatingSystemVersion;
	WORD		MajorSubsystemVersion;
	WORD		DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	DWORD		BaseOfData; // 64-bit header doesn't have this,
							// Hence initialized as 0 for 64 bit files

	//				**************************************************

	WORD        Magic;
	BYTE		MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       AddressOfEntryPoint;
    DWORD		ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD		MinorOSVersion;
	WORD		MajorImageVersion;
    WORD		MinorImageVersion;
    WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       CheckSum;
    WORD        Subsystem;
	DWORD		SizeOfStackCommit;
	DWORD		SizeOfHeaders;
    DWORD		LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}PE_HEADER;

typedef struct _tagPE_OFFSETS
{
	DWORD	NumberOfSections;
	DWORD	Magic;
	DWORD	MinorLinkerVersion;
	DWORD	SizeOfCode;
	DWORD	AddressOfEntryPoint;
	DWORD	BaseOfData;
	DWORD	ImageBase;
	DWORD	SectionAlignment;
	DWORD	MinorOSVersion;
	DWORD	MinorSubsystemVersion;
	DWORD	Win32VersionValue;
	DWORD	SizeOfImage;
	DWORD	Checksum;
    DWORD	LoaderFlags;
	DWORD	NoOfDataDirs;
}PE_OFFSETS;

typedef struct _tagML_DATA
{
	//Added to reduce revaluation of features while ML scanning
	float		m_featureValues[28] = { 0 };  //Array to store features
	double		m_dSectionMeanEntropy;
	double		m_dSectionMaxEntropy;
	double		m_dSectionMinEntropy;

	double		m_dResourceMinEntropy;
	double		m_dResourceMaxEntropy;
	double		m_dResourceMeanEntropy;
	double		m_dResourceTotalEntropy;
	DWORD		m_dwTotalNoOfResources;
	DWORD		m_dwResourceMaxSize;
	double		m_dResourceMeanSize;
	DWORD		m_dwResourceMinSize;
	DWORD		m_dwResourceTotalSize;
	DWORD		m_dwResourceOffsetLimit;
	DWORD		m_dwCurruptResCounter = 0x00;
	bool		m_bResCurrupted = false;
	DWORD		m_dwImportsNb;
	DWORD		m_dwImportsNbDLL;
	double						m_dSectionMeanRawSize;
	DWORD						m_dwSectionMinRawSize;
	double						m_dSectionMeanVirtualSize;
	DWORD						m_dwSectionMaxVirtualSize;
	PIMAGE_RESOURCE_DIRECTORY	m_pResDir = NULL;	//Pointer to base of Resource Directory
	BYTE*						m_pbyBuff = NULL;
	bool						m_bAllFeaturesGenerated = false;
}ML_DATA;

enum
{
	VALID_PE_FILE = 0,
	ERR_INCORRECT_HDR,
	ERR_INCORRECT_AEP,
	ERR_INCORRECT_SEC_PROPERTIES,
	ERR_OPENING_FILE,
	ERR_DOS_FILE,
	ERR_NON_PE_FILE
};

class CMaxPEFile
{
	//HANDLE	m_hFileHandle;
	int		m_iMZOffset;

	bool Load32BitHeader();
	bool Load64BitHeader();
	void LoadOffsets();
	bool LoadPEFile(HANDLE hFileHandle, bool bOpenToRepair);
	bool LoadUnpackerDLL();

	static HMODULE m_hUnpacker;
	static LPFNUnpackFile m_lpfnUnpackFile;

	BYTE  *m_pAEPSectionBuffer;
	DWORD m_dwAEPSectionSize;
	DWORD m_dwAEPSectionStartPos;
	void InitAEPSection();

	bool CheckForVBFiles();

	BOOL	GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT);

	/*Added to Improvise ML SPEED*/
	bool	GetEntropy();
	double	GetEntropy(const DWORD bytes_count[256], DWORD total_length);
	bool	GetResourceEntropyEx();
	bool	ParseResourceTreeEx(PIMAGE_RESOURCE_DIRECTORY pResDir, DWORD dwResourceDirectory, DWORD dwOffset);
	void	GetNoOfImportsEx();
	void	GetSecMinMeanRSize();
	void	GetSecMaxMeanVSize();
	bool	SummerizedMLFeatures();

	
public:
	CMaxPEFile(void);
	~CMaxPEFile(void);
	
	PE_HEADER	m_stPEHeader;
	PE_OFFSETS	m_stPEOffsets;
	IMAGE_SECTION_HEADER m_stSectionHeader[MAX_SEC_NO];
	
	TCHAR	m_szFilePath[MAX_PATH];
	BYTE	*m_byVirusRevIDs;

	DWORD	m_dwDesirecAccess;
	DWORD	m_dwSharedMode;
	DWORD	m_dwFileSizeHigh;
	DWORD	m_dwFileSize;
	DWORD	m_dwAEPMapped;
	WORD	m_wAEPSec;
	bool	m_b64bit;
	int		m_iErrCode;
	bool	m_bPacked;
	bool	m_bPEFile = false;
	bool	m_bMZFound;
	bool	m_bPEFound;
	bool	m_bSecFound;

	bool OpenFile(LPCTSTR szFilePath, bool bOpenToRepair, bool bUnpackFile = false);
	bool CheckForValidPEFile(HANDLE hFileHandle, bool bOpenToRepair = false, bool bUnpackFile = false);
	void CloseFile();
	bool OpenFile_NoMemberReset(LPCTSTR szFilePath);
	void CloseFile_NoMemberReset();

	bool SetFilePointer(LONG lDistanceToMove, PLONG lpDistanceToMoveHigh = NULL, DWORD dwMoveMethod = FILE_BEGIN, LPDWORD pdwRawResult = 0);
	bool ReadBuffer(LPVOID pbReadBuffer, DWORD dwBytesToRead, DWORD *pdwBytesRead = NULL);
	bool ReadBuffer(LPVOID pbReadBuffer, DWORD dwReadOffset, DWORD dwBytesToRead, DWORD dwMinBytesReq = 0, DWORD *pdwBytesRead = NULL);
	bool WriteBuffer(LPVOID pbWriteBufer, DWORD dwWriteOffset, DWORD dwBytesToWrite, DWORD dwMinBytesReq = 0, DWORD *pdwBytesWritten = NULL);
	
	bool CalculateLastSectionProperties();
	bool CalculateChecksum();
	bool CalculateImageSize();
	
	bool RemoveSection(WORD wSecNoToRemove, bool bTruncateOverlay = false); 
	bool RemoveLastSections(WORD wNoofSections = 1, bool bTruncateOverlay = false); 
	
	bool WriteAEP(DWORD dwAEPToWrite);
	bool WriteNumberOfSections(WORD wNumberOfSections);
	bool WriteSectionCharacteristic(WORD wSectionNo, DWORD dwAtributeValue, DWORD dwAtributeOffset);
	bool RepairOptionalHeader(int iAttribute, DWORD dwValToWrite, DWORD dwValToWriteDD, bool bForceSetDataDirSize = false);
	
	bool TruncateFile(DWORD dwTruncateOffset, bool bTruncateOverlay = false);
	bool ForceTruncate(DWORD dwTruncateOffset);
	bool TruncateFileWithFileAlignment(DWORD dwTruncateOffset);
	
	bool FillWithZeros(DWORD dwStartOffset, DWORD dwSize);
	bool CopyData(DWORD dwReadStartAddr, DWORD dwWriteStartAddr, DWORD dwSizeOfData, DWORD dwCaseNo = 0, DWORD dwKey = 0);
	bool GetImportAndNameTableRVA(char* szDllName, IMAGE_IMPORT_DESCRIPTOR &objIMPORTTable);

	WORD Rva2FileOffset(DWORD dwRVAAddress, DWORD *pdwFileOffset);
	WORD GetSectionNoFromOffset(DWORD dwFileOffset);

	DWORD GetFunNameRva(char *szFunName, DWORD dwFunNameTableOff);

	void SetFileName(LPCTSTR szFilePath);
	bool DeletePEFile();
	bool DeleteTempFile();
	bool ValidateFile();
	bool IsValidResourcTable();
	bool IsValidImportTable();
	bool IsValidExportTable();
	bool SearchForPEHdr();
	bool IsReloadedPE();
	
	static void UnloadUnpacker();

	//Added for handling VB File's Detection...
	BYTE	m_byAEPBuff[0x100];	// 100 bytes from AEP 
	bool	m_bIsVBFile;		
	DWORD	m_dwVBSigOff;	// point to VB sign

	HANDLE	m_hFileHandle;

	ML_DATA	m_mlFeatureData;
	bool	CalculateMLFeatures();
	TCHAR	m_szResourceMD5[33] = { 0x00 };
	
	HANDLE		m_hMLFeatureGenThread = NULL;
	bool		GenMLFeatures();
	BOOL		m_bMLThreadIsRunning = FALSE;
};
