/*======================================================================================
FILE             : ProcessScanner.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshan Singh Virdi
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
				  
CREATION DATE    : 8/1/2009 6:59:54 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "ProcessScanner.h"
#include "MaxExceptionFilter.h"
#include "..\SDScanner.h"
#include <comdef.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

BOOL CALLBACK MyProcHandler(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess,
							LPVOID pThis, bool &bStopEnum);
BOOL CALLBACK MyProcModuleHandler(DWORD dwProcessID, HANDLE hProcess, LPCTSTR szProcessPath, 
								  HMODULE hModule, LPCTSTR szModulePath, LPVOID pThis, bool &bStopEnum);
BOOL CALLBACK ProcScanThreadHandler(DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath,
									LPVOID pThis, bool &bStopEnum);

/*--------------------------------------------------------------------------------------
Function       : CProcessScanner::CProcessScanner
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CProcessScanner::CProcessScanner(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : CProcessScanner::~CProcessScanner
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CProcessScanner::~CProcessScanner(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : CProcessScanner::ScanProcesses
In Parameters  : bool bDeepScan
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CProcessScanner::ScanProcesses(bool bDeepScan)
{
	__try
	{
		m_bDeepScan = bDeepScan;
		AddLogEntry(Starting_Process_Scanner, L"Processes Scan");
		SendScanStatusToUI(Starting_Process_Scanner);

		TCHAR chDriveToScan[3] = {0};
		chDriveToScan[0] = m_oDBPathExpander.GetOSDriveLetter();
		chDriveToScan[1] = ':';

		m_pMaxScanner->m_oMaxProcessScanner.Init();
		m_pMaxScanner->m_oLocalSignature.LoadLocalDatabase(chDriveToScan, Scanner_Type_Max_ProcScan);

		m_oEnumProcess.EnumAllThreadsInSystem((THREADHANDLER)ProcScanThreadHandler, this);
		if(m_pMaxScanner->m_oMaxProcessScanner.IsKidoThreadFound())
		{
			m_oEnumProcess.EnumAllThreadsInSystem((THREADHANDLER)ProcScanThreadHandler, this);
		}	
		wmemset(m_strProcessName, 0, MAX_PATH);
		m_oEnumProcess.EnumRunningProcesses((PROCESSHANDLER)MyProcHandler, this);

		m_pMaxScanner->m_oLocalSignature.UnLoadLocalDatabase();
		m_pMaxScanner->m_oMaxProcessScanner.DeInit();

		AddLogEntry(Starting_Process_Scanner, L"Processes Scan", 0, 0, 0, 0, false);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
		_T("MaxScanner Process Scan Module")))
	{
	}
}

/*--------------------------------------------------------------------------------------
Function       : MyProcHandler
In Parameters  : LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, LPVOID pThis, 
				bool &bStopEnum, 
Out Parameters : BOOL CALLBACK 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
BOOL CALLBACK MyProcHandler(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, LPVOID pThis, bool &bStopEnum)
{
	CProcessScanner *pProcMon = (CProcessScanner *)pThis;
	if(pProcMon)
	{
		CString csPath(szExePath);
		if(csPath.GetLength() > 0)
		{
			csPath.MakeLower();
			MAX_SCANNER_INFO oScannerInfo = {0};
			oScannerInfo.hProcessHandleIDToScan = hProcess;
			oScannerInfo.eMessageInfo = Process;
			oScannerInfo.eScannerType = Scanner_Type_Max_ProcScan;
			oScannerInfo.ulProcessIDToScan = dwProcessID;
			_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), csPath);
			pProcMon->CheckProcess(&oScannerInfo, bStopEnum);
		}
	}
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : MyProcModuleHandler
In Parameters  : DWORD dwProcessID, HANDLE hProcess, LPCTSTR szProcessPath, HMODULE hModule, 
					LPCTSTR szModulePath, LPVOID pThis, bool &bStopEnum, 
Out Parameters : BOOL CALLBACK 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
BOOL CALLBACK MyProcModuleHandler(DWORD dwProcessID, HANDLE hProcess, LPCTSTR szProcessPath, 
								  HMODULE hModule, LPCTSTR szModulePath, LPVOID pThis, bool &bStopEnum)
{
	CProcessScanner *pProcMon = (CProcessScanner *)pThis;
	if(pProcMon)
	{
		CString csPath(szModulePath);
		if(csPath.GetLength() > 0)
		{
			csPath.MakeLower();
			MAX_SCANNER_INFO oScannerInfo = {0};
			oScannerInfo.eMessageInfo = Module;
			oScannerInfo.eScannerType = Scanner_Type_Max_ModuleScan;
			oScannerInfo.ulProcessIDToScan = dwProcessID;
			oScannerInfo.hProcessHandleIDToScan = hProcess;
			oScannerInfo.hModuleHandleToScan = hModule;
			_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), szModulePath);
			_tcscpy_s(oScannerInfo.szContainerFileName, _countof(oScannerInfo.szContainerFileName), szProcessPath);
			pProcMon->CheckProcess(&oScannerInfo, bStopEnum);
		}
	}
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : ProcScanThreadHandler
In Parameters  : DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath, LPVOID pThis, bool &bStopEnum
Out Parameters : BOOL
Description    : global function to receive callback, later it calls class function to scan
Author & Date  : Anand Srivastava, 11-Dec-2010
--------------------------------------------------------------------------------------*/
BOOL CALLBACK ProcScanThreadHandler(DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath, LPVOID pThis, bool &bStopEnum)
{
	CProcessScanner *pProcMon = (CProcessScanner*)pThis;
	if(pProcMon)
	{
		pProcMon->ScanThread(dwProcessID, dwThreadID, szProcImgPath, pThis, bStopEnum);
	}
	return TRUE;
}

bool CProcessScanner::ScanThread(DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath, LPVOID pThis, bool &bStopEnum)
{
	bStopEnum = m_bStopScanning;
	if(m_bStopScanning)
	{
		return false;
	}

	MAX_SCANNER_INFO oScannerInfo = {0};
	oScannerInfo.eScannerType = Scanner_Type_Max_ThreadScan;
	oScannerInfo.ulProcessIDToScan = dwProcessID;
	oScannerInfo.ulThreadIDToScan = dwThreadID;
	_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), szProcImgPath);
	m_pMaxScanner->m_oMaxProcessScanner.ScanThread(&oScannerInfo, bStopEnum);
	if((oScannerInfo.ThreatDetected == 1) || (oScannerInfo.ThreatSuspicious == 1))
	{
		SendScanStatusToUI(&oScannerInfo);
	}

	return false;
}

/*--------------------------------------------------------------------------------------
Function       : CProcessScanner::CheckProcess
In Parameters  : PMAX_SCANNER_INFO pScannerInfo, bool &bStopEnum 
Out Parameters : bool 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CProcessScanner::CheckProcess(PMAX_SCANNER_INFO pScannerInfo, bool &bStopEnum)
{
	bStopEnum = m_bStopScanning;
	if(m_bStopScanning)
	{
		return false;
	}

#ifndef WIN64
	if((pScannerInfo->eMessageInfo == Process) && (pScannerInfo->ulProcessIDToScan > 0))
	{
		m_pMaxScanner->m_oMaxProcessScanner.CheckFunctionAddress(pScannerInfo);
		pScannerInfo->ThreatDetected = 0;
		pScannerInfo->ThreatSuspicious = 0;

		SendScanStatusToUI(pScannerInfo);
	}
#endif

	m_pMaxScanner->ScanFile(pScannerInfo);
	if((pScannerInfo->ThreatDetected == 1) || (pScannerInfo->ThreatSuspicious == 1))
	{
		SendScanStatusToUI(pScannerInfo);
		return true;
	}

	if(pScannerInfo->eMessageInfo == Process)
	{
		//Commented on: 07-June-2011
		//As scanning these entries slows down the scanner drastically
		//m_oEnumProcess.EnumProcessModuleList(pScannerInfo->ulProcessIDToScan, pScannerInfo->szFileToScan, (PROCESSMODULEHANDLER)MyProcModuleHandler, this, true);
	}
	return false;
}