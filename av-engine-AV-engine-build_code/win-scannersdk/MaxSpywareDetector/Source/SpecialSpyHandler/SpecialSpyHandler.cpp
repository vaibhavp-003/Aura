
/*======================================================================================
FILE             : SpecialSpyHandler.cpp
ABSTRACT         : Contains the exported functions from this dll
DOCUMENTS	     : SpecialSpyHandler_DesignDoc.doc
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
				  
CREATION DATE    : 05/23/2009 3:20 PM
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#include "pch.h"
#include "SpecialSpyHandler.h"
#include "SplSpyWrapper.h"
#include "SpecialSpyHandler.h"
#include "MaxExceptionFilter.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// The one and only CSpecialSpyHandlerApp object
CSpecialSpyHandlerApp g_objSplSpyHandlerApp;

BEGIN_MESSAGE_MAP(CSpecialSpyHandlerApp, CWinApp)
END_MESSAGE_MAP()

/*--------------------------------------------------------------------------------------
Function       : CSpecialSpyHandlerApp::CSpecialSpyHandlerApp
In Parameters  : 
Out Parameters : 
Description    : constructor of the class
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CSpecialSpyHandlerApp::CSpecialSpyHandlerApp()
{
}

/*--------------------------------------------------------------------------------------
Function       : CSpecialSpyHandlerApp::~CSpecialSpyHandlerApp
In Parameters  : 
Out Parameters : 
Description    : if wrapper object is active delete it and set pointer to null
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CSpecialSpyHandlerApp::~CSpecialSpyHandlerApp()
{
	if ( m_pSplSpyWrapper )
	{
		delete m_pSplSpyWrapper ;
		m_pSplSpyWrapper = NULL ;
	}

	// close the log file
	AddLogEntry ( (const TCHAR *)NULL , (const TCHAR *)NULL , (const TCHAR *)NULL , false ) ;
}

/*--------------------------------------------------------------------------------------
Function       : CSpecialSpyHandlerApp::InitInstance
In Parameters  : 
Out Parameters : BOOL 
Description    : CSpecialSpyHandlerApp initialization
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
BOOL CSpecialSpyHandlerApp::InitInstance()
{
	CWinApp::InitInstance();
	CMaxExceptionFilter::InitializeExceptionFilter();
	return TRUE;
}

/*-------------------------------------------------------------------------------------
	Function		: StartSplScan
	In Parameters	: SENDSCANMESSAGE , LPVOID , bool , CString
	Out Parameters	: 
	Author			: Anand Srivastava
	Description		: call start scanning of this class which in turns call
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void StartScanning(SENDMESSAGETOUI lpSendMessaegToUI, SCAN_OPTIONS &sScanOptions, const TCHAR *strDrivesToScan)
{
	CString csDrives = strDrivesToScan;
	//CString csRoot = CSystemInfo::m_strRoot;
	//csRoot.MakeLower();

	//if(csDrives.Find(csRoot) != -1)
	{
		AddLogEntry(_T("Start Scan"), 0, 0, true, LOG_DEBUG);
		g_objSplSpyHandlerApp.StartSpecialSpywareScan ( lpSendMessaegToUI , sScanOptions.SignatureScan , sScanOptions.IsUSBScanner, csDrives) ;
		AddLogEntry(_T("End Scan"), 0, 0, true, LOG_DEBUG);
	}
}

/*-------------------------------------------------------------------------------------
	Function		: StopScanning
	In Parameters	: 
	Out Parameters	: 
	Author			: Anand Srivastava
	Description		: call stop scanning
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void StopScanning()
{
	g_objSplSpyHandlerApp . StopSplScan() ;
}

/*-------------------------------------------------------------------------------------
	Function		: RemoveSplSpys
	In Parameters	: 
	Out Parameters	: 
	Author			: Anand Srivastava
	Description		: exported function to quarantine special spyware
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void RemoveSplSpys()
{
	g_objSplSpyHandlerApp . RemoveSpecialSpyware() ;
}

/*-------------------------------------------------------------------------------------
	Function		: IsRestartRequired
	In Parameters	: 
	Out Parameters	: bool
	Author			: Anand Srivastava
	Description		: exported function to check if restart needed
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool IsRestartRequired()
{
	return g_objSplSpyHandlerApp . IsRestartNeeded() ;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanUSB
	In Parameters	: LPCTSTR szFoldersList
	Out Parameters	: 
	Author			: Anand Srivastava
	Description		: exported function to scan USB drive items
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void ScanUSB(LPCTSTR szFoldersList, SENDMESSAGETOUI lpSndMsg)
{
	g_objSplSpyHandlerApp.ScanUSB(szFoldersList, lpSndMsg);
}

/*-------------------------------------------------------------------------------------
	Function		: CSpecialSpyHandlerApp::StartSpecialSpywareScan
	In Parameters	: SENDMESSAGETOUI lpSndMessage, const bool bFullScan , const CString& csDrives
	Out Parameters	: 
	Author			: Anand Srivastava
	Description		: create wrapper object and initiate scanning
--------------------------------------------------------------------------------------*/
void CSpecialSpyHandlerApp :: StartSpecialSpywareScan ( SENDMESSAGETOUI lpSndMessage, const bool bFullScan, const bool bUSBScan, const CString& csDrives)
{
	m_pSplSpyWrapper = new CSplSpyWrapper ( lpSndMessage , csDrives ) ;

	if ( m_pSplSpyWrapper )
	{
		m_pSplSpyWrapper -> InitSplSpyScan ( bFullScan, bUSBScan ) ;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CSpecialSpyHandlerApp::StopSplScan
	In Parameters	: 
	Out Parameters	: 
	Author			: Anand Srivastava
	Description		: set the flag to stop the scan
--------------------------------------------------------------------------------------*/
void CSpecialSpyHandlerApp :: StopSplScan()
{
	if ( m_pSplSpyWrapper )
	{
		m_pSplSpyWrapper -> SignalStopScanning() ;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CSpecialSpyHandlerApp::RemoveSpecialSpyware
	In Parameters	: 
	Out Parameters	: 
	Author			: Anand Srivastava
	Description		: call wrapper function to quarantine
--------------------------------------------------------------------------------------*/
void CSpecialSpyHandlerApp :: RemoveSpecialSpyware()
{
	if ( m_pSplSpyWrapper )
	{
		m_pSplSpyWrapper -> RemoveSpecialSpywares() ;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CSpecialSpyHandlerApp::IsRestartNeeded
	In Parameters	: 
	Out Parameters	: bool
	Author			: Anand Srivastava
	Description		: return the value in flag to determine if restart needed
--------------------------------------------------------------------------------------*/
bool CSpecialSpyHandlerApp :: IsRestartNeeded()
{
	if ( ! m_pSplSpyWrapper )
	{
		return ( false ) ;
	}

	bool bRestartNeeded = m_pSplSpyWrapper -> m_bRestartMachineAfterQuarantine ;
	m_pSplSpyWrapper -> m_bRestartMachineAfterQuarantine = false ;

	//2.5.1.07
	if ( m_pSplSpyWrapper -> CheckForCompulsoryDeleteOnRestartList() )
	{
		bRestartNeeded = true ;
	}

	return ( bRestartNeeded ) ;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanUSB
	In Parameters	: const CString& csCmdLineArg, SENDMESSAGETOUI lpSndMessage
	Out Parameters	: bool
	Author			: Anand Srivastava
	Description		: scan USB drive related special spyware
--------------------------------------------------------------------------------------*/
bool CSpecialSpyHandlerApp::ScanUSB(const CString& csCmdLineArg, SENDMESSAGETOUI lpSndMessage)
{
	m_pSplSpyWrapper = new CSplSpyWrapper(lpSndMessage, csCmdLineArg);
	if(m_pSplSpyWrapper)
	{
		m_pSplSpyWrapper->InitSplSpyScan(false, true);
	}

	return true;
}

int CSpecialSpyHandlerApp::ExitInstance()
{
	return CWinApp::ExitInstance();
}
