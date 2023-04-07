/*======================================================================================
   FILE				: VirusScanner.cpp
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
#include "pch.h"
#include "MaxVirusScanner.h"
#include "MaxExceptionFilter.h"
#include "SDSystemInfo.h"
#include "Registry.h"
#include <atlbase.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: constructor
In Parameters	:
Out Parameters	:
Purpose			: Init class objects
Author			: Shweta Mulay
Description		: init class variables
--------------------------------------------------------------------------------------*/
CMaxVirusScanner::CMaxVirusScanner(): CVirusScannerBase(), m_objMaxRepairVirDB(false)
{
	m_bRepairLoadModuleFailed = false;
	m_bPolyScanLoadModuleFailed = false;
	m_hDBScan = m_hPMScan = m_hDBRepair = NULL;
	m_lpfnLoadDBByPath = NULL;
	m_lpfnUnLoadDB = NULL;
	m_lpfnScanFile = NULL;
	m_lpfnRepairFile = NULL;
	m_lpfnUnLoadScanner = NULL;
	m_lpfnScanAndCleanPM = NULL;
	m_lpfnSetProductRegistryPath = NULL;
	m_lpfnGetVirusRevIDS = NULL;
	m_lpfnCheckWhiteDigiCert = NULL;
	m_lpfnLoadDigiCertDB = NULL;

	m_dwDetectedByPoly = 0x00;
	m_dwDetectedByDB = 0x00;
	m_dwDetectedByDigi = 0x00;
	m_dwDetectedByIcon = 0x00;
	m_dwDetectedByYara = 0x00;
}

/*-------------------------------------------------------------------------------------
Function		: destructor
In Parameters	:
Out Parameters	:
Purpose			: Deinitialize the dll
Author			: Shweta Mulay
Description		: Deinit dll and unload virus database
--------------------------------------------------------------------------------------*/
CMaxVirusScanner::~CMaxVirusScanner()
{
}

/*-------------------------------------------------------------------------------------
Function		: InitializeVirusScanner
In Parameters	: LPVOID, LPVOID, LPCTSTR
Out Parameters	: bool
Purpose			: Initialize the virus scanner dll
Author			: Shweta Mulay
Description		: Initialize the virus scanner dll and load database
--------------------------------------------------------------------------------------*/
bool CMaxVirusScanner::InitializeVirusScanner(const CString &csDBPath, BYTE *pPolyVirusRevIDS)
{
	m_dwVirDBScanTime = m_dwVirDBRepairTime = m_dwVirPolyScanTime = m_dwVirPolyRepairTime = 0;

	if(m_hDBScan && m_hPMScan)
	{
		return true;
	}

	if(!m_hDBScan)
	{
		m_hDBScan = LoadLibrary(_T("AuAVDBScan.dll"));
		if(NULL == m_hDBScan)
		{
			AddLogEntry(_T("Unable to load AuAVDBScan.dll"));
			//return false;
		}
	}

	if(!m_hPMScan)
	{
		m_hPMScan = LoadLibrary(_T("AuAVPMScan.dll"));
		if(NULL == m_hPMScan)
		{
			int	iError = GetLastError();
			TCHAR	szLogLine[1024] = {0x0};
			AddLogEntry(_T("Unable to load AuAVPMScan.dll"));
			//return false;
		}
	}

	if(!m_lpfnLoadDBByPath || !m_lpfnUnLoadDB || !m_lpfnScanFile || !m_lpfnSetProductRegistryPath)
	{
		if(m_hDBScan)
		{
			m_lpfnLoadDBByPath = (LPFN_LoadSigDBByPath)GetProcAddress(m_hDBScan, "LoadSigDBByPath");
			m_lpfnUnLoadDB = (LPFN_UnLoadSigDB)GetProcAddress(m_hDBScan, "UnLoadSigDB");
			m_lpfnScanFile = (LPFN_SendFile4Scanning)GetProcAddress(m_hDBScan, "DBScanFile");
			m_lpfnSetProductRegistryPath = (LPFN_SetProductRegistryPath)GetProcAddress(m_hDBScan, "SetProductRegistryPath");
			m_lpfnGetBufferScanTime = (LPFN_GetBufferScanTime)GetProcAddress(m_hDBScan, "GetBufferReadTime");
			m_lpfnGetBufferScanTime = (LPFN_GetBufferScanTime)GetProcAddress(m_hDBScan, "GetBufferScanTime");
		}
	}

	if(!m_lpfnLoadDBByPath || !m_lpfnUnLoadDB || !m_lpfnScanFile || !m_lpfnSetProductRegistryPath)
	{
		AddLogEntry(_T("Unable to get functions from AuAVDBScan.dll"));
		//return false;
	}

	if(!m_lpfnScanAndCleanPM && m_hPMScan)
	{
		m_lpfnScanAndCleanPM = (LPFN_CleanPolyMorphic)GetProcAddress(m_hPMScan, "PolyScanOrCleanFile");
	}

	if(!m_lpfnCheckWhiteDigiCert && m_hPMScan)
	{
		m_lpfnCheckWhiteDigiCert = (LPFN_CheckWhiteCertorComp)GetProcAddress(m_hPMScan, "CheckValidDigiCert");
	}

	if(!m_lpfnUnLoadScanner && m_hPMScan)
	{
		m_lpfnUnLoadScanner = (LPFN_UnLoadScanner)GetProcAddress(m_hPMScan, "UnLoadScanner");
	}

	if(!m_lpfnGetVirusRevIDS && m_hPMScan)
	{
		m_lpfnGetVirusRevIDS = (LPFN_GetVirusRevIDS)GetProcAddress(m_hPMScan, "GetVirusRevIDS");
	}

	if(!m_lpfnScanAndCleanPM || !m_lpfnUnLoadScanner || !m_lpfnGetVirusRevIDS)
	{
		AddLogEntry(_T("Unable to get functions from AuAVPMScan.dll"));
		//return false;
	}

	if(m_lpfnGetVirusRevIDS && pPolyVirusRevIDS)
	{
		m_lpfnGetVirusRevIDS(pPolyVirusRevIDS);
	}

	if(m_lpfnSetProductRegistryPath)
	{
		AddLogEntry(_T("Setting reg key path for virus databases: %s"), CSystemInfo::m_csProductRegKey, 0, true, LOG_DEBUG);
		m_lpfnSetProductRegistryPath(CSystemInfo::m_csProductRegKey);	//req when dbs are corrupt to set live update registry
	}

	if(m_lpfnLoadDBByPath)
	{
		int iRetValue = m_lpfnLoadDBByPath(csDBPath,m_bUSBScan,m_bIsActMon);

		if(0 >= iRetValue)
		{
			CString csString;
			csString.Format(_T("Failed loading virus sigdb, return value: %i"), iRetValue);
			AddLogEntry(csString);
			//return false;
		}
	}

	if(!m_objMaxRepairVirDB.Load(csDBPath + VIRUS_DB_REPAIR))
	{
		CRegistry objRegitry;
		objRegitry.Set(CSystemInfo::m_csProductRegKey, _T("AutoDatabasePatch"), 1, HKEY_LOCAL_MACHINE);
		AddLogEntry(_T("Load Repair DB Failed, DB update set!"));
		//return false;
	}

	if(!m_lpfnRepairFile)
	{
		if(m_bRepairLoadModuleFailed)
		{
			AddLogEntry(_T("!m_bRepairLoadModuleFailed"));
			//return false;
		}

		m_hDBRepair = LoadLibrary(_T("AuAVRepair.dll"));
		if(NULL == m_hDBRepair)
		{
			AddLogEntry(_T("Loading AuAVRepair.dll failed"));
			m_bRepairLoadModuleFailed = true;
			//return false;
		}

		if(m_hDBRepair)
		{
			m_lpfnRepairFile = (LPFN_DBRepairFile)GetProcAddress(m_hDBRepair, "_DBRepairFile");
			if(NULL == m_lpfnRepairFile)
			{
				AddLogEntry(_T("CleanFile not found in AuAVRepair.dll"));
				m_bRepairLoadModuleFailed = true;
			//	return false;
			}
		}
	}

	AddLogEntry(_T("Virus Scanner Init Success!"));
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: DeInitializeVirusScanner
In Parameters	:
Out Parameters	: bool
Purpose			: DeInitialize the virus scanner dll
Author			: Shweta Mulay
Description		: Unload the virus scanner dll and unload database
--------------------------------------------------------------------------------------*/
bool CMaxVirusScanner::DeInitializeVirusScanner()
{
	AddLogEntry(_T("UnLoading Virus Scanner!"));
	
	m_objMaxRepairVirDB.RemoveAll();

	if(m_lpfnUnLoadDB)
	{
		m_lpfnUnLoadDB();
	}

	if(m_hDBScan)
	{
		FreeLibrary(m_hDBScan);
	}

	if(m_lpfnUnLoadScanner)
	{
		m_lpfnUnLoadScanner();
	}

	if(m_hPMScan)
	{
		FreeLibrary(m_hPMScan);
	}

	if(m_hDBRepair)
	{
		FreeLibrary(m_hDBRepair);
	}

	m_hDBScan = m_hPMScan = m_hDBRepair = NULL;
	m_lpfnLoadDBByPath = NULL;
	m_lpfnUnLoadDB = NULL;
	m_lpfnUnLoadScanner = NULL;
	m_lpfnScanFile = NULL;
	m_lpfnRepairFile = NULL;
	m_lpfnScanAndCleanPM = NULL;
	m_lpfnCheckWhiteDigiCert = NULL;

	return true;
}

DWORD CMaxVirusScanner::IsWhiteDigiCertORCompany(PMAX_SCANNER_INFO pScanInfo)
{
	DWORD	dwRetValue = 0x00;
	
	__try
	{
		if(m_lpfnCheckWhiteDigiCert)
		{
			dwRetValue = m_lpfnCheckWhiteDigiCert(pScanInfo->pMaxPEFile);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Could not Check for Cert!"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
	}

	return dwRetValue;
}

DWORD CMaxVirusScanner::ScanFile(PMAX_SCANNER_INFO pScanInfo)
{
	DWORD dwScanResult = SCAN_ACTION_CLEAN;
	__try
	{
		DWORD dwStartTime = GetTickCount();
		if((m_lpfnScanAndCleanPM) && (!pScanInfo->SkipPolyMorphicScan))
		{
			pScanInfo->dwStartTickCount	= GetTickCount();
			dwScanResult = m_lpfnScanAndCleanPM(pScanInfo->pMaxPEFile, pScanInfo->szThreatName, false);
			if(SCAN_ACTION_DELETE == dwScanResult)
			{
				pScanInfo->ThreatDetected = true;
				pScanInfo->eMessageInfo = Virus_File;
				pScanInfo->eDetectedBY = Detected_BY_MaxVirus_Poly;
				AddLogEntry(L"##### MAV-POL-Q  : %s : %s", pScanInfo->szFileToScan, pScanInfo->szThreatName, true, LOG_DEBUG);
				m_dwVirPolyScanTime += (GetTickCount() - dwStartTime);
				return dwScanResult;
			}
			else if(SCAN_ACTION_REPAIR == dwScanResult)
			{
				pScanInfo->ThreatDetected = true;
				pScanInfo->eMessageInfo = Virus_File_Repair;
				pScanInfo->eDetectedBY = Detected_BY_MaxVirus_Poly;
				AddLogEntry(L"##### MAV-POL-R  : %s : %s", pScanInfo->szFileToScan, pScanInfo->szThreatName, true, LOG_DEBUG);
				m_dwVirPolyScanTime += (GetTickCount() - dwStartTime);
				return dwScanResult;
			}
			else if(SCAN_ACTION_TIMEOUT == dwScanResult)
			{
				AddLogEntry(L">>>>> MAV-POL-S-TIMEOUT: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
			else
			{
				AddLogEntry(L">>>>> MAV-POL-CLN: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
		}
		else
		{
			AddLogEntry(L"##### MAV-POLSKIP: %s : %s", pScanInfo->szFileToScan, pScanInfo->szThreatName, true, LOG_DEBUG);
		}
		m_dwVirPolyScanTime += (GetTickCount() - dwStartTime);

		dwStartTime = GetTickCount();
		if(m_lpfnScanFile)
		{
			pScanInfo->dwStartTickCount	= GetTickCount();
			
			dwScanResult = m_lpfnScanFile(pScanInfo->pMaxPEFile, pScanInfo->szThreatName, pScanInfo->szOLEMacroName, pScanInfo->ulThreatID,m_bSKipYaraScanner);
			if(SCAN_ACTION_DELETE == dwScanResult)
			{
				pScanInfo->ThreatDetected = true;
				pScanInfo->eMessageInfo = Virus_File;
				//pScanInfo->eDetectedBY = Detected_BY_MaxVirus_DB;
				if (pScanInfo->ulThreatID == 270594)
				{
					m_dwDetectedByIcon++;
					pScanInfo->eDetectedBY = Detected_BY_MaxVirus_Icon;
				}
				else if (pScanInfo->ulThreatID == 161086)
				{
					m_dwDetectedByDigi++;
					pScanInfo->eDetectedBY = Detected_BY_MaxVirus_Digicert;
				}
				else if (pScanInfo->ulThreatID == 121218)
				{
					m_dwDetectedByYara++;
					pScanInfo->eDetectedBY = Detected_BY_Max_Yara;
				}
				else
				{
					m_dwDetectedByDB++;
					pScanInfo->eDetectedBY = Detected_BY_MaxVirus_DB;
				}
				AddLogEntry(L"##### MAV-DB-Q   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szThreatName, true, LOG_DEBUG);
				m_dwVirDBScanTime += (GetTickCount() - dwStartTime);
				return dwScanResult;
			}
			else if(SCAN_ACTION_REPAIR == dwScanResult)
			{
				pScanInfo->ThreatDetected = true;
				pScanInfo->eMessageInfo = Virus_File_Repair;
				pScanInfo->eDetectedBY = Detected_BY_MaxVirus_DB;
				AddLogEntry(L"##### MAV-DB-R   : %s : %s", pScanInfo->szFileToScan, pScanInfo->szThreatName, true, LOG_DEBUG);
				m_dwVirDBScanTime += (GetTickCount() - dwStartTime);
				return dwScanResult;
			}
			else if(SCAN_ACTION_TIMEOUT == dwScanResult)
			{
				AddLogEntry(L">>>>> MAV-DB-S-TIMEOUT : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
			else
			{
				AddLogEntry(L">>>>> MAV-DB-CLN : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
		}
		else
		{
			AddLogEntry(L"##### MAV-DB-SKIP: %s : %s", pScanInfo->szFileToScan, pScanInfo->szThreatName, true, LOG_DEBUG);
		}
		m_dwVirDBScanTime += (GetTickCount() - dwStartTime);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Could not scan for virus!"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
	}

	return dwScanResult;
}

DWORD CMaxVirusScanner::RepairFile(PMAX_SCANNER_INFO pScanInfo)
{
	DWORD dwRepairSuccess = REAPIR_STATUS_SUCCESS;
	__try
	{
		if(pScanInfo->eDetectedBY == Detected_BY_MaxVirus_Poly)
		{
			DWORD dwStartTime = GetTickCount();
			pScanInfo->dwStartTickCount	= GetTickCount();
			dwRepairSuccess = m_lpfnScanAndCleanPM(pScanInfo->pMaxPEFile, pScanInfo->szThreatName, true);
			if(dwRepairSuccess == REAPIR_STATUS_SUCCESS)
			{
				pScanInfo->ThreatRepaired = true;
				AddLogEntry(L"##### MAV-POL-R-S: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
			else if(dwRepairSuccess == REAPIR_STATUS_TIMEOUT)
			{
				AddLogEntry(L">>>>> MAV-POL-R-TIMEOUT : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
			else
			{
				pScanInfo->ThreatNonCurable = true;
				AddLogEntry(L"----- MAV-POL-R-F: %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
			m_dwVirPolyRepairTime += (GetTickCount() - dwStartTime);
		}
		else if(pScanInfo->eDetectedBY == Detected_BY_MaxVirus_DB)
		{
			LPTSTR szParam;
			DWORD dwStartTime = GetTickCount();
			if(pScanInfo->ulThreatID != -1)
			{
				TCHAR szVirusID[MAX_PATH] = {0};
				_stprintf_s(szVirusID, MAX_PATH, L"%d", pScanInfo->ulThreatID);
				if(!m_objMaxRepairVirDB.SearchItem(szVirusID, szParam))
				{
					szParam = L"FF";
					/*
					AddLogEntry(L"----- MAV-DB-R-F : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
					pScanInfo->ThreatNonCurable = true;
					m_dwVirDBRepairTime += (GetTickCount() - dwStartTime);
					return dwRepairSuccess;
					*/
				}
			}
			else if(0 < _tcslen(pScanInfo->szOLEMacroName))
			{
				szParam = pScanInfo->szOLEMacroName;
			}

			pScanInfo->dwStartTickCount	= GetTickCount();
			dwRepairSuccess = m_lpfnRepairFile(pScanInfo->pMaxPEFile, szParam, pScanInfo->szFreshFile);
			if(dwRepairSuccess == REAPIR_STATUS_SUCCESS)
			{
				pScanInfo->ThreatRepaired = true;
				AddLogEntry(L"##### MAV-DB-R-S : %s : %s", pScanInfo->szFileToScan, szParam, true, LOG_DEBUG);
			}
			else if(dwRepairSuccess == REAPIR_STATUS_TIMEOUT)
			{
				AddLogEntry(L">>>>> MAV-DB-R-TIMEOUT : %s", pScanInfo->szFileToScan, 0, true, LOG_DEBUG);
			}
			else
			{
				pScanInfo->ThreatNonCurable = true;
				AddLogEntry(L"----- MAV-DB-R-F : %s : %s", pScanInfo->szFileToScan, szParam, true, LOG_DEBUG);
			}
			m_dwVirDBRepairTime += (GetTickCount() - dwStartTime);
		}
		return dwRepairSuccess;
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Could not repair Virus!"), (pScanInfo->IsChildFile ? pScanInfo->szContainerFileName : pScanInfo->szFileToScan)))
	{
	}

	return dwRepairSuccess;
}

DWORD  CMaxVirusScanner::GetDBBufferReadTime()
{
	DWORD	dwResult = 0x00;
	if (m_lpfnGetBufferReadTime != NULL)
	{
		dwResult = m_lpfnGetBufferReadTime();
	}
	return dwResult;
}

DWORD  CMaxVirusScanner::GetDBBufferScanTime()
{
	DWORD	dwResult = 0x00;
	if (m_lpfnGetBufferScanTime != NULL)
	{
		dwResult = m_lpfnGetBufferScanTime();
	}
	return dwResult;
}