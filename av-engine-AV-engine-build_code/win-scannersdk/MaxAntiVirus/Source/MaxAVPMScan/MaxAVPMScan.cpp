/*======================================================================================
FILE				: MaxAVPMScan.cpp
ABSTRACT			: AuAVPMScan.dll module.
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
CREATION DATE		: 25 Jun 2010
NOTES				: This is main polymorphic scanning engine of Max Antivirus.
VERSION HISTORY		: 
=====================================================================================*/
#include "MaxAVPMScan.h"
#include "variables.h"
#include "MaxExceptionFilter.h"
#include "PolymorphicVirus.h"
#include "Trojans.h"
//#include "BlackDigiSign.h"


//#ifdef _DEBUG
//#define new DEBUG_NEW
//#undef THIS_FILE
//static char THIS_FILE[] = __FILE__;
//#endif

extern DWORD m_dwTotalScanTime;
extern DWORD m_dwTotalRepairTime;
extern DWORD m_dwNoOfFilesScanned;
extern DWORD m_dwNoOfFilesRepaired;

//TCHAR	g_szDigiCertDBPath[MAX_PATH] = {0x00};

//CMaxDigiSign m_gpMaxDigiCertScanner;

BOOL WINAPI DllMain(HINSTANCE hInstDLL,  // handle to DLL module
					DWORD fdwReason,     // reason for calling function
					LPVOID lpReserved )  // reserved
{
	// Perform actions based on the reason for calling.

	switch( fdwReason ) 
	{ 
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
			CMaxExceptionFilter::InitializeExceptionFilter();
			CEmulate::IntializeSystem();
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.		
		break;

	case DLL_PROCESS_DETACH:
		{
			CMaxPEFile::UnloadUnpacker();
			if(CTrojans::m_hUPXUnpacker)
			{		
				FreeLibrary(CTrojans::m_hUPXUnpacker);
				CTrojans::m_hUPXUnpacker = NULL;
				CTrojans::m_lpfnUnPackUPXFile = NULL;
			}
			CEmulate::DeIntializeSystem();
			if(CPolymorphicVirus::m_hEvent)
			{
				CloseHandle(CPolymorphicVirus::m_hEvent);
				CPolymorphicVirus::m_hEvent = NULL;
			}
		}
		break;
	}

	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

/*-------------------------------------------------------------------------------------
	Function		: GetVirusRevIDS
	In Parameters	: BYTE *byRevID 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Reurns existing versions of sub categoris of viruses
--------------------------------------------------------------------------------------*/
DLL_EXPORT void GetVirusRevIDS(BYTE *byRevID)
{	
	byRevID[0x0] = GR0_REV_ID.u.ID.byRevNo;
	byRevID[0x1] = GR1_REV_ID.u.ID.byRevNo;
	byRevID[0x2] = GR2_REV_ID.u.ID.byRevNo;
	byRevID[0x3] = GR3_REV_ID.u.ID.byRevNo;
	byRevID[0x4] = GR4_REV_ID.u.ID.byRevNo;
	byRevID[0x5] = GR5_REV_ID.u.ID.byRevNo;
	byRevID[0x6] = GR6_REV_ID.u.ID.byRevNo;
	byRevID[0x7] = GR7_REV_ID.u.ID.byRevNo;
	byRevID[0x8] = GR8_REV_ID.u.ID.byRevNo;
	byRevID[0x9] = GR9_REV_ID.u.ID.byRevNo;
	byRevID[0xA] = GRA_REV_ID.u.ID.byRevNo;
	byRevID[0xB] = GRB_REV_ID.u.ID.byRevNo;
	byRevID[0xC] = GRC_REV_ID.u.ID.byRevNo;
	byRevID[0xD] = GRD_REV_ID.u.ID.byRevNo;
	byRevID[0xE] = GRE_REV_ID.u.ID.byRevNo;
	byRevID[0xF] = GRF_REV_ID.u.ID.byRevNo;
	return;
}


/*-------------------------------------------------------------------------------------
	Function		: LoadDigiSignDB
	In Parameters	: LPCTSTR pFileName, LPTSTR pVirusName, bool bClean 
	Out Parameters	: Action taken on file by Scanner
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Main entry point function for polymorphic scanning
--------------------------------------------------------------------------------------*/
/*
DLL_EXPORT DWORD LoadDigiSignDB(LPCTSTR	pszDigiCertDBFile)
{
	DWORD	dwRetStatus;

	//CMaxDigiSign	m_gpMaxDigiCertScanner;
	//dwRetStatus = m_gpMaxDigiCertScanner.LoadDatabase(pszDigiCertDBFile);

	//_tcscpy(g_szDigiCertDBPath,pszDigiCertDBFile);
	
	return dwRetStatus;
}
*/
/*-------------------------------------------------------------------------------------
	Function		: CheckValidDigiCert
	In Parameters	: LPCTSTR pFileName, LPTSTR pVirusName, bool bClean 
	Out Parameters	: Action taken on file by Scanner
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Main entry point function for polymorphic scanning
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD CheckValidDigiCert(CMaxPEFile *pMaxPEFile)
{
	DWORD dwRetVal = SCAN_ACTION_CLEAN;

	if (!pMaxPEFile)
	{
		return dwRetVal;
	}

	CPolymorphicVirus objPolyMorphicVirus(pMaxPEFile);
	dwRetVal = objPolyMorphicVirus.CheckWhiteDigiCert();
	
	return dwRetVal;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanPolyMorphic
	In Parameters	: LPCTSTR pFileName, LPTSTR pVirusName, bool bClean 
	Out Parameters	: Action taken on file by Scanner
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Main entry point function for polymorphic scanning
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD CleanPolyMorphic(LPCTSTR pFileName, LPTSTR pVirusName, bool bClean)
{
	DWORD dwRetVal = SCAN_ACTION_CLEAN; 	
	CMaxPEFile objMaxPEFile;

	if(objMaxPEFile.OpenFile(pFileName, bClean, !bClean))
	//if(objMaxPEFile.OpenFile(pFileName, bClean))
	{		
		objMaxPEFile.m_byVirusRevIDs = new BYTE[16];
		memset(objMaxPEFile.m_byVirusRevIDs, 0, 16);
		
		CPolymorphicVirus objPolyMorphicVirus(&objMaxPEFile);
		dwRetVal = objPolyMorphicVirus.CleanPolyMorphicEx(pVirusName, bClean);
		
		if(objMaxPEFile.m_bPacked)
		{
			objMaxPEFile.DeleteTempFile();			
			if(dwRetVal == SCAN_ACTION_CLEAN)
			{
				objMaxPEFile.m_bPacked = false;
				if(objMaxPEFile.OpenFile(pFileName, bClean))
				{
					memset(objMaxPEFile.m_byVirusRevIDs, 0, 16);
					dwRetVal = objPolyMorphicVirus.CleanPolyMorphicEx(pVirusName, bClean);
				}
			}
		}
		
		if(objMaxPEFile.m_byVirusRevIDs)
		{
			delete []objMaxPEFile.m_byVirusRevIDs;
			objMaxPEFile.m_byVirusRevIDs  = NULL;
		}
	}
	
	return dwRetVal;
}

/*-------------------------------------------------------------------------------------
	Function		: PolyScanOrCleanFile
	In Parameters	: LPCTSTR pFileName, LPTSTR pVirusName, bool bClean 
	Out Parameters	: Action taken on file by Scanner
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Entry point function for polymorphic scanning and repair
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD PolyScanOrCleanFile(CMaxPEFile *pMaxPEFile, LPTSTR pVirusName, bool bClean)
{	
	DWORD				dwRetValue = VIRUS_NOT_FOUND;
	CPolymorphicVirus	objPolyMorphicVirus(pMaxPEFile);

	if (bClean == false)
	{
		pMaxPEFile->GenMLFeatures();
	}

	dwRetValue = objPolyMorphicVirus.CleanPolyMorphicEx(pVirusName, bClean);
	
	return dwRetValue;
}

/*-------------------------------------------------------------------------------------
	Function		: ConvertTime
	In Parameters	: DWORD dwTotalTime, int &iHours, int &iMinutes, int &iSeconds, int &iMilliSeconds
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: converts time in H-M-S-MS format
--------------------------------------------------------------------------------------*/
void ConvertTime(DWORD dwTotalTime, int &iHours, int &iMinutes, int &iSeconds, int &iMilliSeconds)
{
	while(dwTotalTime >= (60 * 60 * 1000))
	{
		dwTotalTime -= 60 * 60 * 1000;
		iHours++;
	}

	while(dwTotalTime >= (60 * 1000))
	{
		dwTotalTime -= 60 * 1000;
		iMinutes++;
	}

	while(dwTotalTime >= 1000)
	{
		dwTotalTime -= 1000;
		iSeconds++;
	}

	iMilliSeconds = dwTotalTime;
	//printf("%02i:%02i:%02i:%03i", iHours, iMinutes, iSeconds , iMilliSeconds);
}

/*-------------------------------------------------------------------------------------
	Function		: UnLoadScanner
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Unloads polymorphic scanning engine
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD UnLoadScanner()
{
	WCHAR *wcsTemp = new WCHAR[MAX_PATH*2];
	wmemset(wcsTemp, 0, MAX_PATH*2);
	swprintf_s(wcsTemp, MAX_PATH*2, _T("TNFS: %d, TNFR: %d, VPOLYST: %d, VPOLYRT: %d"), m_dwNoOfFilesScanned, m_dwNoOfFilesRepaired, m_dwTotalScanTime, m_dwTotalRepairTime);
	AddLogEntry(wcsTemp);

	int iTotalScanHours = 0, iTotalScanMinutes = 0, iTotalScanSeconds = 0, iTotalScanMilliSeconds = 0;
	int iTotalRepairHours = 0, iTotalRepairMinutes = 0, iTotalRepairSeconds = 0, iTotalRepairMilliSeconds = 0;
	int iTotalUPXUnPackHours = 0, iTotalUPXUnPackMinutes = 0, iTotalUPXUnPackSeconds = 0, iTotalUPXUnPackMilliSeconds = 0;

	ConvertTime(m_dwTotalScanTime, iTotalScanHours, iTotalScanMinutes, iTotalScanSeconds, iTotalScanMilliSeconds);
	ConvertTime(m_dwTotalRepairTime, iTotalRepairHours, iTotalRepairMinutes, iTotalRepairSeconds, iTotalRepairMilliSeconds);
	
	wmemset(wcsTemp, 0, MAX_PATH*2);
	swprintf_s(wcsTemp, MAX_PATH*2, _T("Total VirusPoly Scan Time : Hours: %02d, Minutes: %02d, Seconds: %02d, MilliSeconds: %02d\r\n\t\t\t\t  Total VirusPoly Repair Time : Hours: %02d, Minutes: %02d, Seconds: %02d, MilliSeconds: %02d\r\n\t\t\t\t  Total UPX UnPack Time : Hours: %02d, Minutes: %02d, Seconds: %02d, MilliSeconds: %02d"),
								iTotalScanHours, iTotalScanMinutes, iTotalScanSeconds, iTotalScanMilliSeconds,
								iTotalRepairHours, iTotalRepairMinutes, iTotalRepairSeconds, iTotalRepairMilliSeconds, 
								iTotalUPXUnPackHours, iTotalUPXUnPackMinutes, iTotalUPXUnPackSeconds, iTotalUPXUnPackMilliSeconds);
	AddLogEntry(wcsTemp);

	delete [] wcsTemp;
	wcsTemp = NULL;

	return 0;
}
