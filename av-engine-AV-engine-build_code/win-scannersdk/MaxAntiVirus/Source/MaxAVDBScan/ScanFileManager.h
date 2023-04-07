/*======================================================================================
FILE				: ScanFileManager.h
ABSTRACT			: Manages file scanning of different types
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 22-Apr-2010
NOTES				: Manages file scanning of different types.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once

#include <tchar.h>
#include <shlwapi.h>
#include "MaxInf.h"
#include "ScriptSig.h"
#include "MaxPEFile.h"
#include "PDFSig.h"
#include "MaxOLE.h"
#include "MaxELF.h"
#include "MaxRTF.h"
#include "MaxCursor.h"
#include "MaxTTF.h"
#include "MaxHelp.h"
#include "MACFileScanner.h"

#ifndef CSCANFILEMANAGER
	#define CSCANFILEMANAGER
#endif

#ifndef RETURN_VALUES
	#include "RetValues.h"
#endif

#define iAccuracy				26
#define PERCENTAGE(NoOfBytes)	(((iAccuracy * (NoOfBytes)) / 100) + 2)
#define MAX_PARTS_CNT			4
#define MAX_SIG_LEN				(SIG_FIRST_PART_LEN + (SIG_FIRST_BUT_OTHER_PARTS_LEN * (MAX_PARTS_CNT - 1)))

typedef struct dexheader
{
	char Magic[8];
	DWORD Checksum;
	BYTE Signature[20];
	DWORD File_Size;
	DWORD Header_Size;
	DWORD Endian_Tag;
	DWORD Link_Size;
	DWORD Link_Off;
	DWORD Map_Off;
	DWORD String_Ids_Size;
	DWORD String_Ids_Off;
	DWORD type_ids_size;
	DWORD type_ids_off;
	DWORD proto_ids_size;
	DWORD proto_ids_off;
	DWORD field_ids_size;
	DWORD field_ids_off;
	DWORD method_ids_size;
	DWORD method_ids_off;
	DWORD class_defs_size;
	DWORD class_defs_off;
	DWORD data_size;
	DWORD data_off;
	BYTE raw_data[0x40];
}DEX_HEADER;

typedef struct _map_item
{
	WORD type;
	WORD unused;
	DWORD size;
	DWORD offset;
}MAP_ITEM;

#define TYPE_CODE_ITEM					0x2001
#define TYPE_STRING_DATA_ITEM			0x2002

enum eSignaturePartsLength
{
	SIG_FIRST_PART_LEN	= 26,
	SIG_FIRST_BUT_OTHER_PARTS_LEN = 38,
};

typedef struct _16DOS_HEADER
{
	unsigned short Signature;
	unsigned short Bytes_On_Last_Page;
	unsigned short Pages_In_File;
	unsigned short Relocations;
	unsigned short Size_Of_Header_Paragraphs;
	unsigned short Min_extra_paragraphs;
	unsigned short Max_extra_paragraphs;
	unsigned short Ss;
	unsigned short Sp;
	unsigned short Checksum;
	unsigned short Ip;
	unsigned short Cs;
	unsigned short Reloc_table_offset;
	unsigned short Overlay_number;
}StructDosHeader;

class CScanFileManager
{
	TCHAR	m_szFile2Scan[MAX_PATH];
	DWORD	m_dwFileSize;
	DWORD   m_dwTotalDataSize;
	bool	m_bFlagForBuffer;

	int InitScanBuffer(void);

	int CheckFileTypeEx();
	
	bool Check4PEFile();
	bool Check4DOSFileEx();
	bool Check4WMAFileEx();
	bool Check4COM16FileEx();
	bool Check4BATFileEx();
	bool CheckForPDFFileEx();
	bool Check4MSOfficeFileEx();
	bool CheckForDexEx();
	bool CheckForSis();
	bool CheckForRegFile();
	bool CheckForJClass();
	int Check4OtherFileTypes();

	int OpenPEFile4ScanningEx();
	int OpenDOSFile4ScanningEx();
	int OpenWMAFile4ScanningEx();
	int OpenCOMFile4ScanningEx();
	int OpenBATFile4ScanningEx();
	int OpenInfFile4ScanningEx();
	int OpenPdfFileForScanningEx();
	int OpenDexFileForScanningEx();
	int OpenSisFileForScanningEx();
	int OpenREGFileForScanningEx();
	int OpenELFFileForScanningEx();
	int	OpenMACFileForScanningEx();
	
	//10 Aug 2011 : DOS Changes
	bool GetBufferByDOSFormat();	
	bool CreateDOS32Sig(LPTSTR szSig, DWORD cchSig);
	bool GetBufferBySentenceFormat();

	//AjayCOMSentenceFormat : 19 Aug 2011
	bool GetBufferByCOMFormat();
	bool CreateDOS16Sig(LPTSTR szSig, DWORD cchSig);
	bool GetCOMBufferBySentenceFormat();

	void SendFileForNormalize(DWORD dwRead);

public:
	char			m_szVirusName[MAX_VIRUS_NAME];
	BYTE			m_szScnBuffer[SCAN_BUFFER_LEN];
	BYTE            m_szScriptBuffer[SCAN_SCRIPT_BUFFER_LEN];
	unsigned int	m_iBufferSize;
	CMaxOLE			m_objOLEScan;
	CMaxInf			m_objMaxInf;
	CScriptSig		m_objScript;
	CMaxPEFile		*m_pMaxPEFile;
	CPDFSig			m_objPDFSig;
	CMaxELF			m_objMaxELF;
	CMaxRTF			m_objMaxRTF;
	CMaxCursor		m_objMaxCursor;
	CMaxTTF			m_objMaxTTF;
	CMaxHelp		m_objMaxHelp;
	CMACFileScanner	*m_pMacFile;
	PERegions		m_stPERegions;
	DWORD	m_dwStartOffDex;

	//10 Aug 2011 : DOS Changes
	LPCSTR			m_szDOSSIG;
	LPCSTR			m_szSentence;
	int				m_iOverlayStartIndexInBuff;
	bool			m_bFlag4Overlay;
	int				m_iOverlaySize;

	//AjayCOMSentenceFormat : 19 Aug 2011
	LPCSTR			m_szCOMSIG;

	CScanFileManager(CMaxPEFile *pMaxPEFile);
	~CScanFileManager(void);
	
	int GetBuffer4Scanning();
	int GetRemBuff4Scanning();	
	bool GetDexFileBuffer(BYTE **byBuffer, DWORD& cbBuffer);
	bool GetDexMapDetails(DWORD &dwMapOffset, DWORD &dwMapSize);

	int	Check4LinkInfection();

	int CloseFileHandle(void);
};
