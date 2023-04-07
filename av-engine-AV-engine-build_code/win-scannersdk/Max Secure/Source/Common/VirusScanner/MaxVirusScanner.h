/*======================================================================================
   FILE				: VirusScanner.h
   ABSTRACT			: This class is responsible to scan viruses
   DOCUMENTS		: 
   AUTHOR			: Shweta Mulay
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created in 2008 as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 09-Dec-2008
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/	
#pragma once
#include "MaxPEFile.h"
#include "VirusScannerBase.h"
#include "S2S.h"

typedef DWORD (*LPFN_SetProductRegistryPath)(LPCTSTR szKeyPath);
typedef DWORD (*LPFN_LoadSigDBByPath)(LPCTSTR szDBPath, bool bIsUsbScan, bool bIsActMonScan);
typedef DWORD (*LPFN_UnLoadSigDB)();
typedef DWORD (*LPFN_DBRepairFile)(CMaxPEFile *pMaxPEFile, LPTSTR szParam, LPCTSTR szOriginalFilePath);
typedef DWORD (*LPFN_UnLoadScanner)();
typedef DWORD (*LPFN_CleanPolyMorphic)(CMaxPEFile *pMaxPEFile, LPTSTR pVirusName, bool bClean);
typedef int	  (*LPFN_SendFile4Scanning)(CMaxPEFile *pMaxPEFile, LPTSTR sz_ThreatName, LPTSTR sz_OLE_MacroName, DWORD &dwSpyID, bool bSkipYara);
typedef void  (*LPFN_GetVirusRevIDS)(BYTE *byRevID);

typedef DWORD (*LPFN_CheckWhiteCertorComp)(CMaxPEFile *pMaxPEFile);
typedef DWORD (*LPFN_LoadDigiCertDB)(LPCTSTR pszDBPath);

typedef DWORD(*LPFN_GetBufferReadTime)();
typedef DWORD(*LPFN_GetBufferScanTime)();


class CMaxVirusScanner : public CVirusScannerBase
{
public:
	CMaxVirusScanner();
	~CMaxVirusScanner(void);

	bool	InitializeVirusScanner(const CString &csDBPath, BYTE *pPolyVirusRevIDS);
	bool	DeInitializeVirusScanner();
	DWORD	ScanFile(PMAX_SCANNER_INFO pScanInfo);
	DWORD	RepairFile(PMAX_SCANNER_INFO pScanInfo);

	DWORD GetVirDBScanTime(){return m_dwVirDBScanTime;}
	DWORD GetVirDBRepairTime(){return m_dwVirDBRepairTime;}
	DWORD GetVirPolyScanTime(){return m_dwVirPolyScanTime;}
	DWORD GetVirPolyRepairTime(){return m_dwVirPolyRepairTime;}

	DWORD GetDBBufferReadTime();
	DWORD GetDBBufferScanTime();

	DWORD IsWhiteDigiCertORCompany(PMAX_SCANNER_INFO pScanInfo);

	DWORD	m_dwDetectedByPoly;
	DWORD	m_dwDetectedByDB;
	DWORD	m_dwDetectedByDigi;
	DWORD	m_dwDetectedByIcon;
	DWORD	m_dwDetectedByYara;

	bool	m_bSKipYaraScanner;	

private:

	DWORD	m_dwVirDBScanTime;
	DWORD	m_dwVirDBRepairTime;
	DWORD	m_dwVirPolyScanTime;
	DWORD	m_dwVirPolyRepairTime;

	bool	m_bRepairLoadModuleFailed;
	bool	m_bPolyScanLoadModuleFailed;
	HMODULE			m_hDBScan;
	HMODULE			m_hPMScan;
	HMODULE			m_hDBRepair;
	LPFN_LoadSigDBByPath			m_lpfnLoadDBByPath;
	LPFN_UnLoadSigDB				m_lpfnUnLoadDB;
	LPFN_SendFile4Scanning			m_lpfnScanFile;
	LPFN_DBRepairFile				m_lpfnRepairFile;
	LPFN_CleanPolyMorphic			m_lpfnScanAndCleanPM;
	LPFN_UnLoadScanner				m_lpfnUnLoadScanner;
	LPFN_SetProductRegistryPath		m_lpfnSetProductRegistryPath;
	LPFN_GetVirusRevIDS				m_lpfnGetVirusRevIDS;

	LPFN_CheckWhiteCertorComp		m_lpfnCheckWhiteDigiCert;
	LPFN_LoadDigiCertDB				m_lpfnLoadDigiCertDB;

	CS2S m_objMaxRepairVirDB;

	LPFN_GetBufferReadTime			m_lpfnGetBufferReadTime = NULL;
	LPFN_GetBufferScanTime			m_lpfnGetBufferScanTime = NULL;
};
