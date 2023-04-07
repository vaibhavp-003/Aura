/*======================================================================================
FILE             : StartupScanner.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
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
				  
CREATION DATE    : 20/12/2010 8:14:24 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "StartupScanner.h"
#include "MaxExceptionFilter.h"
#include "..\SDScanner.h"
#include <comdef.h>
#include "ReferencesScanner.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CStartupScanner
In Parameters  : void
Out Parameters : 
Description    : 
Author & Date  : Anand Srivastava, 20-12-2010
--------------------------------------------------------------------------------------*/
CStartupScanner::CStartupScanner(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : ~CStartupScanner
In Parameters  : void
Out Parameters : 
Description    : 
Author & Date  : Anand Srivastava, 20-12-2010
--------------------------------------------------------------------------------------*/
CStartupScanner::~CStartupScanner(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : IsScanningStopped
In Parameters  : 
Out Parameters : bool
Description    : return true if scanning is to be stopped
Author & Date  : Anand Srivastava, 20-12-2010
--------------------------------------------------------------------------------------*/
bool CStartupScanner::IsScanningStopped()
{
	return m_bStopScanning;
}

/*--------------------------------------------------------------------------------------
Function       : ScanStartupFiles
In Parameters  : bool bDeepScan
Out Parameters : void 
Description    : 
Author & Date  : Anand Srivastava, 20-12-2010
--------------------------------------------------------------------------------------*/
void CStartupScanner::ScanStartupFiles(bool bDeepScan)
{
	m_bDeepScan = bDeepScan;

	AddLogEntry(Starting_Startup_Scanner, L"Startup Scan");
	SendScanStatusToUI(Starting_Startup_Scanner);

	TCHAR chDriveToScan[3] = {0};
	chDriveToScan[0] = m_oDBPathExpander.GetOSDriveLetter();
	chDriveToScan[1] = ':';

	m_pMaxScanner->m_oLocalSignature.LoadLocalDatabase(chDriveToScan, Scanner_Type_Max_Startup);

	EnumerateAllStartupFiles();

	m_pMaxScanner->m_oLocalSignature.UnLoadLocalDatabase();

	AddLogEntry(Starting_Startup_Scanner, L"Startup Scan", 0, 0, 0, 0, false);
}

/*--------------------------------------------------------------------------------------
Function       : SendStatusTOGUI
In Parameters  : bCString csFileName,INT_PTR iTotalEntries,INT_PTR iCounter
Out Parameters : void 
Description    : Sending percnetage status on gui for startup entries.
Author & Date  : Sandip Sanap, 03-07-2018
--------------------------------------------------------------------------------------*/
void CStartupScanner::SendStatusTOGUI(CString csFileName,INT_PTR iTotalEntries,INT_PTR iCounter)
{
	static int iPercentage=5;
	long lDivider= iTotalEntries/6;
	if(iCounter<6)
		iPercentage=5;
	if((iCounter%lDivider)==0 && iPercentage<=10)
	{
		iPercentage=iPercentage+1;
		CString csPercentage;
		csPercentage.Format(L"%d", iPercentage);		
		//SendScanStatusToUI(Status_Bar_File_Report, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0);
		//SendScanStatusToUI(Status_Bar_File_Report, 0, 0, csFileName, csPercentage, 0, 0, 0, 0, 0, 0); //Commented to Check
	}

}
/*--------------------------------------------------------------------------------------
Function       : ScanFile
In Parameters  : LPCTSTR szFilePath, LPVOID lpThis, bool& bStopScan,INT_PTR iTotalEntries,INT_PTR iCounter
Out Parameters : bool 
Description    : scan file using
Author & Date  : Anand Srivastava, 20-12-2010
--------------------------------------------------------------------------------------*/
bool ScanFile(LPCTSTR szFilePath, LPVOID lpThis, bool& bStopScan,INT_PTR iTotalEntries,INT_PTR iCounter)
{
	CStartupScanner* pStartupScanner = (CStartupScanner*)lpThis;

	//AddLogEntry(L"Scan Startup File: %s", szFilePath, 0, true, LOG_DEBUG);	
	if(!pStartupScanner)
	{
		return false;
	}	

	if(pStartupScanner->IsScanningStopped())
	{
		AddLogEntry(L"Set scanning stop in startup scanner", 0, 0, true, LOG_DEBUG);
		bStopScan = true;
		return false;
	}	
	bool bReturn = pStartupScanner->ScanStartupFile(szFilePath);
	if(iTotalEntries>0&&iCounter>0)
		pStartupScanner->SendStatusTOGUI(szFilePath,iTotalEntries,iCounter);

	return bReturn;
}

/*--------------------------------------------------------------------------------------
Function       : ScanStartupFile
In Parameters  : LPCTSTR szFilePath
Out Parameters : bool 
Description    : scan file using
Author & Date  : Anand Srivastava, 20-12-2010
--------------------------------------------------------------------------------------*/
bool CStartupScanner::ScanStartupFile(LPCTSTR szFilePath)
{
	if(_taccess_s(szFilePath, 0))
	{
		return false;
	}

	MAX_SCANNER_INFO oScannerInfo = {0};
	oScannerInfo.eMessageInfo = File;
	oScannerInfo.eScannerType = Scanner_Type_Max_Startup;
	_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), szFilePath);
	m_pMaxScanner->ScanFile(&oScannerInfo);
	if((oScannerInfo.ThreatDetected == 1) || (oScannerInfo.ThreatSuspicious == 1))
	{
		SendScanStatusToUI(&oScannerInfo);
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : EnumerateAllStartupFiles
In Parameters  : 
Out Parameters : bool 
Description    : 
Author & Date  : Anand Srivastava, 20-12-2010
--------------------------------------------------------------------------------------*/
bool CStartupScanner::EnumerateAllStartupFiles()
{
	CReferencesScanner objRefScan;
	DWORD dwRefIDs = REF_ID_RUN|REF_ID_SERVICES|REF_ID_POL_EXP_RUN|REF_ID_IMG_FILE|REF_ID_USER_INIT|
					 REF_ID_SHELL|REF_ID_BHO|REF_ID_SSODL|REF_ID_SEH|REF_ID_STS|REF_ID_APP_INIT|
					 REF_ID_NOTIFY|REF_ID_TOOLBAR|REF_ID_MENU_EXT|REF_ID_ACTIVEX|/*REF_ID_SHRD_DLLS| //uncommon spyware location, takes long on white machine
					 REF_ID_UNINSTALL|*/REF_ID_INST_COMP; // excluding autorun, job

	objRefScan.SetCallbackForFiles(ScanFile, this);
	objRefScan.CheckAndReportReferences(_T("dummy"), 0, dwRefIDs, 0);
	objRefScan.DumpLog();
	return true;
}
