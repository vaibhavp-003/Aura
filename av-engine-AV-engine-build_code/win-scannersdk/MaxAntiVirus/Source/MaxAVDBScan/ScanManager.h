/*======================================================================================
FILE				: ScanManager.h
ABSTRACT			: Wrapper for ScanFileManager class
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
NOTES				: Wrapper for ScanFileManager class
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include <afx.h>
#include "RetValues.h"
#include "MaxConstant.h"
#include "TreeManager.h"
#include "ScanFileManager.h"
#include "MaxPEFile.h"
#include "S2S.h"
#include "MaxIconScanner.h"
#include "Resmd5.h"
#include "MaxYara.h"
#include "MaxExceptionFilter.h"


#ifndef RETURN_VALUES
	#include	"RetValues.h"	
#endif

class CScanManager
{
	HANDLE	m_hEvent;

	DWORD m_dwTotalSignatures;

	CTreeManager m_FileInfectorTree;
	CTreeManager m_ScriptTree;
	CTreeManager m_WMATree;
	CTreeManager m_16DOSTree;
	CTreeManager m_16COMTree;
	CTreeManager m_INFTree;
	CTreeManager m_PDFTree;
	CTreeManager m_OLETree;
	CS2S		 m_DexS2S;
	CTreeManager m_DexTree;
	CTreeManager m_SISTree;
	CTreeManager m_RTFTree;
	CTreeManager m_CursorTree;

	CTreeManager m_DigiScanTree;

	CMaxIconScanner	m_MaxIcnScnMgr;

	CTreeManager m_YaraTree;
	CTreeManager m_VBPETree;
	
	int SetDebugPrivileges(void);
	void CleanupMaxInTemp();
	DWORD	LoadSignatureDBS2S(LPCTSTR szDBPath, LPCTSTR szDBName, CS2S& objDB);
	
	
	DWORD m_dwTotalInitTime;
	DWORD m_dwTotalScanTime;
	DWORD m_dwNoOfFilesScanned;

	WCHAR	m_szDBPath[1024];
	
	DWORD	LaunchAndroidDBLaodingThread();
	HANDLE	m_hAndroidDBThread;
	CS2S	m_objMaxRepairVirDB; //For Loading Repair Database 

public:

	SENDMESSAGETOUI m_lpSendMessaegToUI;
	
	CScanManager(void);
	~CScanManager(void);	
	
	DWORD SetProductRegistryPath(LPCTSTR szKeyPath);
	DWORD ScanFile(CMaxPEFile *pMaxPEFile, LPTSTR szVirusName, LPTSTR szMacroName, DWORD &dwThreatID);
	int LoadSignatureDB(LPCTSTR szDBPath);
	int UnloadDatabase(void);
	bool GetPEBuffer(CMaxPEFile *pMaxPEFile, BYTE *pBuff, unsigned int iBuffSize, unsigned int &iRetBuffSize, PERegions *pPERegions);
	bool GetDexBuffer(CMaxPEFile *pMaxPEFile, BYTE *pBuff, unsigned int iBuffSize, unsigned int &iRetBuffSize); 

	bool ScanDigiCert(CMaxPEFile *pMaxPEFile, LPSTR szVirusName);
	bool ScanFullFile4Yara(CMaxPEFile *pMaxPEFile);
	bool GetIMPHashforYARA(CMaxPEFile *pMaxPEFile,char *szImpHash);
	bool ValidatePERules(CMaxPEFile *pMaxPEFile, LPTSTR pszPERules);

	bool ScanFullFile4YaraWithExp(CMaxPEFile *pMaxPEFile);

	bool	m_bIsUSBScan;
	bool	m_bIsActMonScan;
	bool	m_bIsCryptMonScan;
	DWORD	LoadAndroidDBs();
	DWORD	m_dwAndroidSigCount;
	BOOL	m_bAndroidDBLoaded;
	bool	m_bSkipYara;
	bool	m_bIsMemoryScan;
	bool	m_bRepairDBLoaded;

	DWORD	m_dwBufferReadingTime = 0x00;
	DWORD	m_dwBufferScanTime = 0x00;

	DWORD	m_dwPEScanTime = 0x00;
	DWORD	m_dwDOSScanTime = 0x00;
	DWORD	m_dwCOMScanTime = 0x00;
	DWORD	m_dwRegScanTime = 0x00;
	DWORD	m_dwWMAScanTime = 0x00;
	DWORD	m_dwScriptScanTime = 0x00;
	DWORD	m_dwOLEScanTime = 0x00;
	DWORD	m_dwINFScanTime = 0x00;
	DWORD	m_dwPDFScanTime = 0x00;
	DWORD	m_dwDEXScanTime = 0x00;
	DWORD	m_dwMACScanTime = 0x00;
	DWORD	m_dwRTFScanTime = 0x00;
	DWORD	m_dwICOScanTime = 0x00;
	DWORD	m_dwCurScanTime = 0x00;
	DWORD	m_dwJCLASSScanTime = 0x00;
	DWORD	m_dwTTFScanTime = 0x00;
	DWORD	m_dwHLPScanTime = 0x00;

	DWORD	m_dwPEFileScanTime = 0x00;
	DWORD	m_dwDIGIScanTime = 0x00;
	DWORD	m_dwPEICOScanTime = 0x00;
};
