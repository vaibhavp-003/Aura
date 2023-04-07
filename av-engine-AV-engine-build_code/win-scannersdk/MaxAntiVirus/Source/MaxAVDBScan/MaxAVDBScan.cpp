/*======================================================================================
   FILE				: MaxAVDBScan.cpph
   ABSTRACT			: Max Virus Database based detection module
   DOCUMENTS		: 
   AUTHOR			: Tushar Kadam + Ravi Bisht
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 22 Jul 2010
   NOTES			: This module is Part of Virus Scanner (MVS). 
					  This module loads the database in form of Tree (Aho-corasick and Boyer-Moore)
					  according to file types (Binary header base)	
   VERSION HISTORY	: 
=====================================================================================*/
#pragma once
#include "pch.h"
#include "MaxAVDBScan.h"
#include "ScanManager.h"
#include "PatternFileScanner.h"
#include "MaxPEFile.h"

CScanManager g_objScanManager;
CPatternFileScanner g_objPatternScanner;

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
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;

	case DLL_PROCESS_DETACH:
		// Perform any necessary cleanup.
		g_objScanManager.UnloadDatabase();
		g_objPatternScanner.RandomNamePatternUnLoad();
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

/*-------------------------------------------------------------------------------------
	Function		: ScanFileByPattern
	In Parameters	: LPCTSTR szFilePath (File2Scan), bool bSigCreated, ULONG64 ulSignature (PE Signature), BYTE& byVerTabInfo (Versio Info), DWORD dwLocalDBVer
	Out Parameters	: 1 : true : Pattern Matched 
					  2 : false : failed	
	Purpose			: File is scanned for Pattern (Characteristics) Rules
	Author			: Tushar Kadam
	Description		: File is scanned for Pattern (Characteristics) Rules
--------------------------------------------------------------------------------------*/
DLL_EXPORT bool ScanFileByPattern(LPCTSTR szFilePath, bool bSigCreated, ULONG64 ulSignature, BYTE& byVerTabInfo, DWORD dwLocalDBVer = 0x00)
{
	return g_objPatternScanner.ScanFileByPattern(szFilePath, bSigCreated, ulSignature, byVerTabInfo,dwLocalDBVer);
}

/*-------------------------------------------------------------------------------------
	Function		: GetPatterScanVersion
	In Parameters	: 
	Out Parameters	: Current Pattern Version (For Local DB)
	Purpose			: Return current Pattern Scan Version
	Author			: Tushar Kadam
	Description		: Return Pattern scanner version for local DB Purpose
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD GetPatterScanVersion()
{
	return g_objPatternScanner.GetCurrentVersion();
}

/*-------------------------------------------------------------------------------------
	Function		: SetProductRegistryPath
	In Parameters	: Product Registry Path
	Out Parameters	: DWORD
	Purpose			: Sets Product's Registry Path
	Author			: Tushar Kadam
	Description		: Sets Product's Registry Path for Internal Used
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD SetProductRegistryPath(LPCTSTR szKeyPath)
{
	g_objScanManager.SetProductRegistryPath(szKeyPath);
	return TRUE;
}

/*-------------------------------------------------------------------------------------
	Function		: LoadSigDB
	In Parameters	: 
	Out Parameters	: DWORD : No. of Signature loaded
	Purpose			: Loading Antivirus DB Database
	Author			: Tushar Kadam
	Description		: Function loads all the database in different trees respective of file type.
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD LoadSigDB()
{
	return g_objScanManager.LoadSignatureDB(_T(""));
}

/*-------------------------------------------------------------------------------------
	Function		: LoadSigDBByPath
	In Parameters	: LPCTSTR szDBPath, bool bIsUsbScan (For Pen drive)
	Out Parameters	: DWORD : No. of Signature loaded
	Purpose			: Loading Antivirus DB Database from respective path
	Author			: Tushar Kadam
	Description		: Function loads all the database in different trees respective of file type.
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD LoadSigDBByPath(LPCTSTR szDBPath, bool bIsUsbScan = false, bool bIsActMonScan = false)
{
	g_objPatternScanner.RandomNamePatternLoad(szDBPath);
	g_objScanManager.m_bIsUSBScan = bIsUsbScan;
	g_objScanManager.m_bIsActMonScan = bIsActMonScan;
	if (bIsActMonScan)
	{
		g_objScanManager.m_bIsUSBScan = true;
	}
	return g_objScanManager.LoadSignatureDB(szDBPath);
}

/*-------------------------------------------------------------------------------------
	Function		: UnLoadSigDB
	In Parameters	: 
	Out Parameters	: 
	Purpose			: Unloading of Database
	Author			: Tushar Kadam
	Description		: Remove all the trees from memory and other allocated resources
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD UnLoadSigDB()
{
	CMaxPEFile::UnloadUnpacker();
	return g_objScanManager.UnloadDatabase();
}

/*-------------------------------------------------------------------------------------
	Function		: SendFile4Scanning
	In Parameters	: LPCTSTR szFilePath (File2Scan), LPTSTR szVirusName (Return), LPTSTR szMacroName, DWORD &dwThreatID
	Out Parameters	: 
	Purpose			: Scan File
	Author			: Tushar Kadam
	Description		: Scan file depending on file's binary type in respective scan tree
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD SendFile4Scanning(LPCTSTR szFilePath, LPTSTR szVirusName, LPTSTR szMacroName, DWORD &dwThreatID)
{
	//TCHAR		szLogLine[1024] = {0x00};
	DWORD dwRetVal = SCAN_ACTION_CLEAN; 	
	
	CMaxPEFile objMaxPEFile;
	if(objMaxPEFile.OpenFile(szFilePath, false, true))
	{	
		dwRetVal = g_objScanManager.ScanFile(&objMaxPEFile, szVirusName, szMacroName, dwThreatID);
		if(objMaxPEFile.m_bPacked)
		{
			objMaxPEFile.DeleteTempFile();	
			if(dwRetVal == SCAN_ACTION_CLEAN)
			{
				objMaxPEFile.m_bPacked = false;
				if(objMaxPEFile.OpenFile(szFilePath, false))
				{
					dwRetVal = g_objScanManager.ScanFile(&objMaxPEFile, szVirusName, szMacroName, dwThreatID);
				}			
			}
		}
	}
	return dwRetVal;
}

/*-------------------------------------------------------------------------------------
	Function		: DBScanFile
	In Parameters	: LPCTSTR szFilePath (File2Scan), LPTSTR szVirusName (Return), LPTSTR szMacroName, DWORD &dwThreatID
	Out Parameters	: 
	Purpose			: Scan File
	Author			: Tushar Kadam
	Description		: Scan file depending on file's binary type in respective scan tree
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD DBScanFile(CMaxPEFile *pMaxPEFile, LPTSTR szVirusName, LPTSTR szMacroName, DWORD &dwThreatID, bool bSkipYara)
{
	TCHAR		szLogLine[1024] = {0x00};

	g_objScanManager.m_bSkipYara = bSkipYara;
	return g_objScanManager.ScanFile(pMaxPEFile, szVirusName, szMacroName, dwThreatID);
}

/*-------------------------------------------------------------------------------------
	Function		: GetPEScanBuffer
	In Parameters	: LPCTSTR szFilePath, BYTE *pBuff, unsigned int iBuffSize, unsigned int &iRetBuffSize, PERegions *pPERegions
	Out Parameters	: 
	Purpose			: Get the buffer for scanning / analysis
	Author			: Tushar Kadam
	Description		: Get buffer from file for signature making 
					  Max Buff size for PE file is 20480	
--------------------------------------------------------------------------------------*/
DLL_EXPORT bool GetPEScanBuffer(LPCTSTR szFilePath, BYTE *pBuff, unsigned int iBuffSize, unsigned int &iRetBuffSize, PERegions *pPERegions)// Max Buff size for PE file is 20480
{
	CMaxPEFile objMaxPEFile;
	if(objMaxPEFile.OpenFile(szFilePath, false))
	{	
		return g_objScanManager.GetPEBuffer(&objMaxPEFile, pBuff, iBuffSize, iRetBuffSize, pPERegions);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetDEXScanBuffer
	In Parameters	: LPCTSTR szFilePath, BYTE *pBuff, unsigned int iBuffSize, unsigned int &iRetBuffSize
	Out Parameters	: 
	Purpose			: Get Buffer for Dex Fle
	Author			: Tushar Kadam
	Description		: Retrieve buffer from dex file (Classes.dex ==> Android File(.APK))
--------------------------------------------------------------------------------------*/
DLL_EXPORT bool GetDEXScanBuffer(LPCTSTR szFilePath, BYTE *pBuff, unsigned int iBuffSize, unsigned int &iRetBuffSize)
{
	CMaxPEFile objMaxPEFile;
	if(objMaxPEFile.OpenFile(szFilePath, false))
	{	
		return g_objScanManager.GetDexBuffer(&objMaxPEFile, pBuff, iBuffSize, iRetBuffSize);
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: LoadDigiSigDBByPath
	In Parameters	: LPCTSTR szDBPath, bool bIsUsbScan (For Pen drive)
	Out Parameters	: DWORD : No. of Signature loaded
	Purpose			: Loading Black DigiSign DB Database from respective path
	Author			: Tushar Kadam
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD LoadDigiSigDBByPath(LPCTSTR szDBPath)
{
	//g_objPatternScanner.RandomNamePatternLoad(szDBPath);
	//g_objScanManager.m_bIsUSBScan = bIsUsbScan;
	
	/*if (bIsActMonScan)
	{
		g_objScanManager.m_bIsUSBScan = true;
	}
	*/
	g_objScanManager.m_bIsCryptMonScan = true;
	return g_objScanManager.LoadSignatureDB(szDBPath);
}
/*-------------------------------------------------------------------------------------
	Function		: SendFile4DigiScan
	In Parameters	: LPCTSTR szFilePath (File2Scan), LPTSTR szVirusName (Return), LPTSTR szMacroName, DWORD &dwThreatID
	Out Parameters	: 
	Purpose			: Scan File
	Author			: Tushar Kadam
	Description		: Scan file depending on file's binary type in respective scan tree
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD SendFile4DigiScan(LPCTSTR szFilePath)
{
	char	szVirusName[MAX_VIRUS_NAME] = {0x00};
	DWORD	dwRetStatus = 0x00;
	//memset(szVirusName, 0, sizeof(szVirusName));
	strcpy(szVirusName,"");

	CMaxPEFile objMaxPEFile;
	if(objMaxPEFile.OpenFile(szFilePath, false, true))
	{	
		if (g_objScanManager.ScanDigiCert(&objMaxPEFile, szVirusName))
		{
			dwRetStatus = 0x01;
		}
	}
	return dwRetStatus;
	
}

/*-------------------------------------------------------------------------------------
	Function		: LoadSigDBByPath
	In Parameters	: LPCTSTR szDBPath, bool bIsUsbScan (For Pen drive)
	Out Parameters	: DWORD : No. of Signature loaded
	Purpose			: Loading Antivirus DB Database from respective path
	Author			: Tushar Kadam
	Description		: Function loads all the database in different trees respective of file type.
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD SetScannerParams(bool bIsMemScan = false, bool bIsUsbScan = false, bool bIsActMonScan = false)
{
	g_objScanManager.m_bIsMemoryScan = bIsMemScan;
	g_objScanManager.m_bIsUSBScan = bIsUsbScan;
	g_objScanManager.m_bIsActMonScan = bIsActMonScan;
	if (bIsActMonScan)
	{
		g_objScanManager.m_bIsUSBScan = true;
	}
	return 0x01;
}

/*-------------------------------------------------------------------------------------
	Function		: GetBufferReadTime
	In Parameters	: 
	Out Parameters	:
	Purpose			: Get Tick Count for Buffer Reading
	Author			: Tushar Kadam
	Description		: Get Tick Count for Buffer Reading
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD GetBufferReadTime()
{
	return g_objScanManager.m_dwBufferReadingTime;
}

/*-------------------------------------------------------------------------------------
	Function		: GetBufferScanTime
	In Parameters	:
	Out Parameters	:
	Purpose			: Get Tick Count for Buffer Reading
	Author			: Tushar Kadam
	Description		: Get Tick Count for Buffer Reading
--------------------------------------------------------------------------------------*/
DLL_EXPORT DWORD GetBufferScanTime()
{
	return g_objScanManager.m_dwBufferScanTime;
}