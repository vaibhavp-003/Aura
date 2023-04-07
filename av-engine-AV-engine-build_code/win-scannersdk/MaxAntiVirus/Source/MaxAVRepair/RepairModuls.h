/*======================================================================================
FILE             : RepaireModuls.h
ABSTRACT         : This module repaires virus files deteted by AuAVDBScan.dll
DOCUMENTS	     : 
AUTHOR		     : Tushar Kadam + Virus Team
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : June 2010
NOTES		     : This module repaires virus files deteted by AuAVDBScan.dll
				   Contains set of predefine Constants and Repaire routines that can be released in DSVRepaire.db	
VERSION HISTORY  : 
======================================================================================*/

#pragma once
#include "atlstr.h"
#include "math.h"
#include "Constants.h"
#include "fdi.h"
#include "MaxPEFile.h"
#include <shlobj.h>

const int MAX_BUFF_SIZE			= 1024;
const int MAX_INPUT_STR_PARAM	= 50;

enum { TYPE_BULLET = 1, TYPE_FOLDER, TYPE_STORAGE, TYPE_BLANK, TYPE_DOCUMENT };

typedef NTSTATUS (WINAPI *RTLDecompressBuffer) (USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);

class CRepairModuls
{
public:
	CRepairModuls(CMaxPEFile *pMaxPEFile, LPCTSTR szOriginalFilePath);
	~CRepairModuls(void);

	CString 	m_csFilePath;
	CString 	m_csModParam;
	bool		m_bStubDeleted; 
	CMaxPEFile	*m_pMaxPEFile;
	CString 	m_csOriginalFilePath;

	bool OpenFile(CString csFilePath);
	void CloseFileHandle();
	bool ReadPeFile();	
	bool RepairDelete();
	bool GetParameters();
	bool RepairQuarantine();
	bool RewriteAddressOfEntryPoint();
	bool RemoveLastSection();
	bool SetFileEnd();
	bool SetFileEndEx();
	bool SetFileEndWithFileAlignment();
	bool TruncateEP();
	bool RepairOptionalHeader();
	bool RepairSectionHeader();
	bool ReplaceOriginalData();
	bool ReplaceOriDataDecryption();
	bool ReplaceDataInReadBuffer();
	bool FillWithZero();
	bool CalculateLastSectionDataSize();
	bool CalculateImageSize();
	bool CalculateChecksum();
	bool CalculateSectionAlignment();
	bool CheckForVirusStub(bool bDoNotDelete = false);
	bool FixResource();
	bool FixResName();
	void FiXRes(IMAGE_RESOURCE_DIRECTORY *dir, BYTE **root, DWORD delta);
	bool Check4String();
	bool SpecialRepair();	
	bool ReturnValue();
	bool GetBufferforDecryption();
	bool WriteDWORD();
	bool RepairLamer();

	//virus specific fumctions
	bool DWordXOR();
	bool DecryptionSalityFloatXOR();
	bool RepairHidragA();
	bool RepairChimeraA();
	bool RepairDownloaderBL();
	bool RepairXorer();
	bool RepairSmallA();
	bool DecryptionSalityFloatXOREx();
	bool RenameFile();

	// Modified by Rupali on 19-11-2010 for OLE and WMA file repair changes
	bool Check4OLEFile();
	bool CleanOLEMacro();
	bool CleanWMAFile();
	bool CleanLNKFile();
	// End

	bool CleanScriptFile(int iFunc);
	bool CleanHLPFile();
	bool RepairPIONEERBT();

	bool RepairRecyl();
	bool RepairShipUp();
	bool RepairRansom();
	bool RepairLAMEREL();
	bool RepairPIONEERCZ();

	bool RepairMultiLevPrependerInf();
	bool RepairLamerCQ();

private:
	static BYTE	*m_pbySrcBytesBlk;  
	static BYTE	*m_pbyDstBytesBlk;
	static DWORD   m_dwBytesRead;
	static DWORD   m_dwBytesWrite;
	
	static void HUGE * FAR DIAMONDAPI mem_alloc(ULONG cb);
	static void FAR DIAMONDAPI mem_free(__in_opt void HUGE *pv);

	static INT_PTR FAR DIAMONDAPI file_open(__in LPSTR pszFile, int oflag, int pmode);
	static UINT FAR DIAMONDAPI file_read(__in INT_PTR hf, __out_ecount(cb) void FAR *pv, UINT cb);
	static UINT FAR DIAMONDAPI file_write(__in INT_PTR hf, __in_ecount(cb) void FAR *pv, UINT cb);

	static int FAR DIAMONDAPI file_close(__in INT_PTR hf);
	static long FAR DIAMONDAPI file_seek(__in INT_PTR hf, long dist, int seektype);
	static INT_PTR FAR DIAMONDAPI notification_function(FDINOTIFICATIONTYPE fdint, PFDINOTIFICATION pfdin);

	bool DecompressMemory(BYTE *pbySourceMem, BYTE *pbyDestinationMem, DWORD dwSizeOfBlk, DWORD &dwBytesWritten);

	PIMAGE_SECTION_HEADER m_pSectionHeader;
	
	BYTE		*m_byReadBuffer;
	DWORD		m_dwSizeofBuff;
	DWORD		m_dwStartofDecryption;
	DWORD		m_dwDecryptionLength;
	
	DWORD		m_dwFileSize;
	DWORD		m_dwAEPMapped;
	WORD		m_wNoOfSecs;

	DWORD_PTR	m_dwArgs[15];
	DWORD_PTR	m_dwSaveArgs[10];
	DWORD_PTR	m_dwReturnValues[10];
	BYTE		m_byArg[MAX_INPUT_STR_PARAM];
	int			m_iStep;
	int			m_iSaveArg;
	bool		m_bInternalCall;
	int			m_ibyArgLen;

	// Added by Rupali on 06-12-2010 for Script file repair changes
	DWORD	m_dwBufferSize;
	BYTE	*m_pbyParameter;
	int		m_iParameterlen;
	
	bool	ScriptRepair(char *szTagStart, char *szTagEnd, int iRepairOffset = 0);
	bool	ScriptTagRepair();
	bool	CleanPNGFile();
	bool	ReadScriptFile(int iFunc);
	bool	GetParameterForScript();
	//End

	DWORD_PTR EvaluateExpression(const char * str);

	DWORD	GetMappedAddress(DWORD Address);
	bool	WriteSectionCharacteristic(LPCVOID Value, int SectionNo, int CharType);
	bool	CopyData(DWORD dwReadStartAddr, 
					 DWORD dwWriteStartAddr,
					 DWORD dwSizeOfData, 
					 DWORD dwOperation = 0, 
					 DWORD dwKey = 0,
					 DWORD dwDecryptionSize = 0,
					 DWORD dwStartOfSecondDecryp = 0,
					 DWORD dwDisplacement = 0,
					 DWORD dwDecLevel = 6);	
	bool	GetLastSectionInfo(BYTE *pStartHeader, DWORD dwStartHeaderLen, IMAGE_SECTION_HEADER *pSection_Header, bool &bSecHeaderOutOfStartHeader);
	bool	CheckAEPSection();
	bool	SearchForMZPE(BYTE *bySearchString, DWORD dwStringLen, DWORD dwStartAddress, DWORD dwEndAddress);
	int		FindRes(LPCTSTR lpstNameID, LPCTSTR lpstLaunguage, LPCTSTR lpstLangID, DWORD &dwRVA, DWORD &dwSize);
	DWORD	FindResourceEx(LPCTSTR lpstNameID,DWORD dwRead);
	DWORD	FindAEPForVelost(DWORD dwOffSet);	
	bool	GetValueNextToString();
		
	bool	RepairImporterA();
	bool	RepairRenameFile();
	bool	RepairApathy();
	bool	RepairSalityByteXOR();
	bool	RepairVelost123341();
	bool	RepairRenamer();
	bool	RepairOtwycalG();	
	bool	RepairWarray();
	bool	Repair_HLLC_Ext();
	bool	RepairStream();	
	bool	RepairNemsiB();
	bool	RepairTinitA();
	bool	RepairAssill();
	bool	RepairWinemmem();
	bool	RepaireSaburex();
	bool	Repair9XCIH();
	bool	RepairChitonB();
	bool	RepairMuceB();
	bool	RepairPadic();
	bool	RepairEmar();
	bool	RepairRedemption();
	bool	RepairKiro();
	bool	RepairKlez();
	bool	RepairTrionC();	
	bool	InterChangeSectionHeaders(WORD wSection1, WORD wSection2);
	bool	RepairDOCPACK();

	
	bool	Decryption_RainSong();
	bool	Decryption_Bartel(DWORD dwOrignalFileSize, DWORD dwKey);
	bool	Decryption_Artelad_2173(DWORD  dwKey1, DWORD dwKey2);
	bool	Decryption_Lamewin();
	bool	Decryption_Killis();
	bool	DecryptionOroch5420();
	bool	Decryption_Alisar(DWORD dwBufferSize);
	bool	DecryptGlkajC(BYTE* byBuffer, DWORD dwBuffSize);
	void	DecryptAssill(DWORD	dwNTHeaderStartOffset);	
	void	DecryptRenamedFile(HANDLE hFileHandle);
	bool	DecryptionRosec();
	bool	DecryptionTupac();
	void	DecryptionSavior(DWORD dwFirstArg);
	void	DecryptionAdson1734();
	bool	DecryptionRamdile();
	bool	DecryptionCabres();
//	void	DecryptionLamerEL();
//	int		DecryptionLamerEL(DWORD m_dwOffset);
//	int		DecryptionLamerEL(DWORD dwDecStart,DWORD dwXorKey);

	// Added by Rupali on 13-11-2010 for OLE repair changes
	bool	m_bMacroClean;
	HRESULT ViewStorage(LPSTORAGE pStorage);
	void	OleStdRelease(LPUNKNOWN pUnk);
	//End

	RTLDecompressBuffer	m_pRtlDecompressBuffer;
};
