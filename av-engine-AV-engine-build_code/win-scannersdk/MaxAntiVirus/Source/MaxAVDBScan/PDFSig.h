/*======================================================================================
FILE				: PDFSig.h
ABSTRACT			: Scanner for File Type : PDF Files
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
NOTES				: This class module identifies and scan file types : PDF.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include "MaxPEFile.h"

typedef bool (*LPFN_DecryptPDFFile)(LPCTSTR szPDFFilePath, LPCTSTR szTmpFilePath, int * piStatus);
typedef bool (*LPFN_ExtractScriptFromPDF)(LPCTSTR szPDFFilePath, LPCTSTR szTmpFilePath);

const DWORD MAX_VALID_PDF_SIZE	= 0x00A00000;			//10 * 1024 * 1024 dont scan files larger than this size
const DWORD READER_BUFFER_SIZE	= 0x00010000;			//64 * 1024 reader buffer size
const CHAR	PDF_HDR_SIGNATURE[]	= ("%PDF-");			//header signature found at the begining
const TCHAR PDF_DLL_NAME[]		= _T("AuPDFDecrypt.dll");	//name of decrypter dll
const DWORD	MAX_SCRIPTS_EXTRACT = 1000;					//maximum scripts to extract from a pdf file
const BYTE	OBJ_END_MARKER[]	= {0x65, 0x6E, 0x64, 0x6F, 0x62, 0x6A};	//sequence of bytes which marks end of one object

class CPDFSig
{
public:
	CPDFSig();
	virtual ~CPDFSig();

	bool CloseEnum();
	bool DecryptPDFFile(LPCTSTR szFilePath);
	bool EnumNextScript(LPBYTE byScript, unsigned int& cbScript);
	bool EnumFirstScript(LPBYTE byScript, unsigned int& cbScript);
	bool IsValidPDFFile(LPCTSTR szFilePath, CMaxPEFile* pMaxPEFile);

	static bool LoadDll();
	static bool UnLoadDll();


private:
	TCHAR		m_szDecryptedFile[MAX_PATH];
	DWORD		m_dwFileSize;
	DWORD		m_dwTotalBytesRead;
	DWORD		m_dwMaxScripts;
	HANDLE		m_hFileDec;
	DWORD		m_dwMaxReadBuffer;
	DWORD		m_dwBytesRead;
	DWORD		m_dwBytesUsed;
	bool		m_bFullFileRead;

	static HMODULE		m_hDll;
	static LPFN_DecryptPDFFile			m_lpfnDecryptPDFFile;

	bool GetOneScript(LPBYTE byData, unsigned int& cchData);
	DWORD NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer);
	void GetOneObjectFromBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD& dwObjLen);
};
