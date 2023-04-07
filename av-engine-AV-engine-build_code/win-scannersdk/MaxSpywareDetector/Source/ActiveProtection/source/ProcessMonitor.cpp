/*======================================================================================
   FILE				: ProcessMonitor.cpp
   ABSTRACT			: Module for active monitoring of processes
   DOCUMENTS		: 
   AUTHOR			: Darshan Singh Virdi
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 20 Jan 2008
   NOTES			: 
   VERSION HISTORY	: 
=====================================================================================*/
#include "pch.h"
#include "ProcessMonitor.h"
#include "ActiveProtection.h"
#include "MaxExceptionFilter.h"
#include "QuarantineFile.h"
#include <atlbase.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

UINT DelayedNewFileScanner(LPVOID lpVoid);

typedef BOOL WINAPI EnumProcesses(DWORD *, DWORD, DWORD *);
typedef BOOL WINAPI EnumProcessModules(HANDLE, HMODULE*, DWORD, DWORD*);
typedef BOOL WINAPI GetModuleFileNameExA(HANDLE, HMODULE, LPSTR, DWORD);

static HMODULE g_psapi = NULL;
static EnumProcesses *pEnumProcesses = NULL;
static EnumProcessModules *pEnumProcessModules = NULL;
static GetModuleFileNameExA *pGetModuleFileNameExA = NULL;


BOOL CALLBACK MyProcModuleHandler(DWORD dwProcessID, HANDLE hProcess, LPCTSTR szProcessPath, 
								  HMODULE hModule, LPCTSTR szModulePath, LPVOID pThis, bool &bStopEnum);

BOOL CALLBACK MyProcHandler(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, 
							HANDLE hProcess, LPVOID pThis, bool &bStopEnum);

/*-------------------------------------------------------------------------------------
	Function		: CProcessMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: CProcessMonitor initialization
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CProcessMonitor::CProcessMonitor():m_bMessageDisplayed(false), m_pThis(NULL), m_pMsgHandler(NULL), m_objFilesToDelete(false)
{
	m_bAutoQuarantine = false;
	m_bThrdMonStopSignal = false;
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
	m_hDBEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
	m_pDelPendFileThread = NULL;
	m_pIdleScanThread = NULL;
	link_psapi();
	SetStartupKeys();
	m_lpfnWhiteCerScan = NULL;
	m_lpfnWhiteCerScanIni = NULL;
	m_lpfnWhiteExpParse = NULL;
	m_lpfnSetAppDataPath = NULL;
	m_lpfnCheckBlackFile = NULL;
	m_lpfnCheckFileInAppData = NULL;
	InitializePatternDLL();
}

/*-------------------------------------------------------------------------------------
	Function		: ~CProcessMonitor
	In Parameters	: -
	Out Parameters	: -
	Purpose			: Destructor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CProcessMonitor::~CProcessMonitor()
{
	CloseHandle(m_hEvent);
	m_hEvent = NULL;
	CloseHandle(m_hDBEvent);
	m_hDBEvent = NULL;

	if(g_psapi != NULL)
	{
		FreeLibrary(g_psapi);
		g_psapi = NULL;
	}

	if(m_hWhiteCerScanDll != NULL)
	{
		FreeLibrary(m_hWhiteCerScanDll);
		m_hWhiteCerScanDll = NULL;
	}
	if(m_hRansomPatternScanDll != NULL)
	{
		FreeLibrary(m_hRansomPatternScanDll);
		m_hRansomPatternScanDll = NULL;
	}

}

/*-------------------------------------------------------------------------------------
	Function		: SetHandler
	In Parameters	: LPVOID pMessageHandler: Function pointer for displaying message to user
					  LPVOID lpThis			: Class pointer 
	Out Parameters	: bool
	Purpose			: Start File System monitor
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CProcessMonitor::SetHandler(LPVOID pMessageHandler, LPVOID lpThis)
{
	if(pMessageHandler)
	{
		m_pMsgHandler = (ACTMON_MESSAGEPROCHANDLER)pMessageHandler;
	}

	if(lpThis)
	{
		m_pThis = lpThis;
	}
}

UINT ThreadDeletePendingFiles(LPVOID lpVoid)
{
	CProcessMonitor *pThis = (CProcessMonitor*)lpVoid;
	if(pThis)
	{
		pThis->DeletePendingFiles();
	}
	return 0;
}

UINT ThreadStartIdleScan(LPVOID lpVoid)
{
	CProcessMonitor *pThis = (CProcessMonitor*)lpVoid;
	if(pThis)
	{
		pThis->m_oIdleScan.m_bStopScanning = false;
		pThis->m_oIdleScan.SetProcessMonitorPointer((LPVOID)pThis);
		pThis->m_oIdleScan.StartIdleScan();
	}
	return 0;
}

bool CProcessMonitor::StartMonitor()
{
	//AddLogEntry(_T("Kido Service DLL Found:"), 0, 0, true, LOG_DEBUG);
	theApp.m_objMaxWhiteListMgr.CheckWhiteList();
	//if(theApp.m_objMaxWhiteListMgr.m_dwWhiteListEnable)
	{
		theApp.m_objMaxWhiteListMgr.LoadDB();
	}
	m_bIsMonitoring = false;	
	DWORD dwValue = 0;
	m_bAutoQuarantine = false;
	CRegKey objRegKey;
	if(objRegKey.Open(HKEY_LOCAL_MACHINE, CSystemInfo::m_csProductRegKey) == ERROR_SUCCESS)
	{
		if(objRegKey.QueryDWORDValue(L"ScanQuarantine",dwValue) == ERROR_SUCCESS)
		{
			m_bAutoQuarantine = dwValue? true:false;
		}
	}
	
	wmemset(m_chDriveToScan, 0, 3);
	m_chDriveToScan[0] = m_objSysInfo.m_strRoot.GetAt(0);
	m_chDriveToScan[1] = ':';

	if(!m_pMaxScanner)
	{
		m_pMaxScanner = new CMaxScanner;
		if(m_pMaxScanner)
		{
			m_pMaxScanner->m_dwActmonScan = 1;
			m_pMaxScanner->m_oMaxProcessScanner.Init();
			m_pMaxScanner->InitializeScanner(m_csMaxDBPath);
			m_pMaxScanner->m_oLocalSignature.LoadLocalDatabase(m_chDriveToScan, Scanner_Type_Max_ActMonModuleScan);
		}
	}		

	SetAutomationLabStatus();

	m_bIsMonitoring = true;

	SetEvent(m_hEvent);
	SetEvent(m_hDBEvent);

	AddLogEntry(_T("ThreadDeletePendingFiles:"), 0, 0, true, LOG_DEBUG);
	m_pDelPendFileThread = AfxBeginThread(ThreadDeletePendingFiles, this, THREAD_PRIORITY_NORMAL, NULL, CREATE_SUSPENDED, NULL);
	if(m_pDelPendFileThread)
	{
		m_pDelPendFileThread->m_bAutoDelete = FALSE;
		m_pDelPendFileThread->ResumeThread();
	}
	AddLogEntry(_T("ThreadStartIdleScan:"), 0, 0, true, LOG_DEBUG);
	//m_pIdleScanThread = AfxBeginThread(ThreadStartIdleScan, this, THREAD_PRIORITY_LOWEST, NULL, CREATE_SUSPENDED, NULL);
	if(m_pIdleScanThread)
	{
		m_pIdleScanThread->m_bAutoDelete = FALSE;
		m_pIdleScanThread->ResumeThread();
	}

	return true;
}

struct THREADINFO
{
	LPVOID pThis;
	TCHAR szKeyName[MAX_PATH];
	TCHAR szValueName[MAX_PATH];
	TCHAR szDataName[MAX_PATH];
};

UINT DelayedKidoThreadScan(LPVOID lpParam)
{
	THREADINFO *pThreadInfo = (THREADINFO*)lpParam;
	if(pThreadInfo)
	{
		CProcessMonitor *pThis = (CProcessMonitor*)pThreadInfo->pThis;
		pThis->CheckKidoKey(pThreadInfo->szKeyName, pThreadInfo->szValueName, pThreadInfo->szDataName);

		delete pThreadInfo;
		pThreadInfo = NULL;
	}

	return 0;
}
//sType =1 means replicating call
void CProcessMonitor::ReportKidoEntry(CString csFileName, short sType)
{
	MAX_SCANNER_INFO oScannerInfo = {0};
	oScannerInfo.eMessageInfo = File;
	oScannerInfo.SkipPatternScan = true;
	oScannerInfo.SkipPolyMorphicScan = false;
	oScannerInfo.eScannerType = Scanner_Type_Max_SignatureScan;
	_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), csFileName);
	m_pMaxScanner->ScanFile(&oScannerInfo);

	if(!oScannerInfo.IsWhiteFile)
	{
		//sType = 1 means replicating call
		WriteSignatureToIni(csFileName, oScannerInfo.szFileSig, sType);

		MAX_SCANNER_INFO oScannerInfo = {0};
		oScannerInfo.eScannerType = Scanner_Type_Max_SignatureScan;
		oScannerInfo.ulThreatID = 3393581;
		_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), csFileName);
		oScannerInfo.ThreatDetected = 1;
		oScannerInfo.AutoQuarantine = 1;
		SendScanStatusToUI(&oScannerInfo, CALL_TYPE_F_EXECUTE, true);
	}
}

void CProcessMonitor::WriteSignatureToIni(LPCTSTR szFileName, LPCTSTR szFileSig, short sType)
{
	bool bFileStatus = false, bSigStatus = false;

	AddLogEntry(L">>>>> WriteSignatureToIni: szFileSig: %s, szFileName: %s", szFileSig, szFileName, true, LOG_DEBUG);
	
	//Dont make File path entry for Replication.
	if(sType == 0)
	{
		//OutputDebugStringA(szFileName);
		bFileStatus = WriteInfoInSection(_T("FileList"), _T("NoOfEntries"), szFileName, NULL);
	}

	if(_tcscmp(szFileSig, _T("0000000000000000")) != 0)
	{
	//	OutputDebugStringA(szFileName);
		bSigStatus = WriteInfoInSection(_T("Signature"), _T("Count"), szFileSig, szFileName);
	}

	if(bFileStatus || bSigStatus)	// reload only if new entry has been added!
	{
		m_pMaxScanner->ReloadInstantINI();
	}
	ReloadLoadExcludeDB();
	return;
}

bool CProcessMonitor::WriteInfoInSection(LPCTSTR szSectionName, LPCTSTR szCountName, LPCTSTR szValueToAdd, LPCTSTR szValueToAdd2)
{
	bool bAlreadyPresent = false;
	TCHAR szCount[50] = {0}, szExistingSig[MAX_PATH] = {0}, szNewValue[MAX_PATH] = {0};
	int iCount = 0;
	int iLenToCompare = 16;

	if(!szValueToAdd)
	{
		return false;
	}
	
	if(_tcslen(szValueToAdd) == 0)
	{
		return false;
	}

	if(szValueToAdd2)
	{
		if(_tcslen(szValueToAdd2) == 0)
		{
			return false;
		}
	}

	CString csInstScanIni = CSystemInfo::m_strAppPath + _T("Setting\\InstantScan.ini");

	GetPrivateProfileString(szSectionName, szCountName, _T("0"), szCount, _countof(szCount), csInstScanIni);
	iCount = _tcstol(szCount, 0, 10);

	if(szValueToAdd2)	// Adding Signature to INI!
	{
		iLenToCompare = 16;
		_stprintf_s(szNewValue, _countof(szNewValue), _T("%s*%s"), szValueToAdd, szValueToAdd2);
	}
	else
	{
		_stprintf_s(szNewValue, _countof(szNewValue), _T("%s"), szValueToAdd);
		iLenToCompare = _tcslen(szNewValue);
	}

	for(int i = 1; i <= iCount; i++)
	{
		memset(szExistingSig, 0, sizeof(szExistingSig));
		_stprintf_s(szCount, _countof(szCount), _T("%i"), i);
		GetPrivateProfileString(szSectionName, szCount, _T(""), szExistingSig, _countof(szExistingSig), csInstScanIni);
		if(_tcsnicmp(szExistingSig, szNewValue, iLenToCompare) == 0)
		{
			bAlreadyPresent = true;
			break;
		}
	}

	if(!bAlreadyPresent)
	{
		iCount++;
		_stprintf_s(szCount, _countof(szCount), _T("%i"), iCount);
		WritePrivateProfileString(szSectionName, szCountName, szCount, csInstScanIni);
		WritePrivateProfileString(szSectionName, szCount, szNewValue, csInstScanIni);
		AddLogEntry(L">>>>> Added new entry in INI: szSectionName: %s, szNewValue: %s", szSectionName, szNewValue, true, LOG_DEBUG);
	}

	return !bAlreadyPresent;
}

bool CProcessMonitor::CheckKidoKey(CString csRegKey, CString csRegValue, CString csRegData)
{
	BOOL bKidoFound = FALSE;

	int iWaitTime = 50;
	if(csRegData.Find(L".tmp") != -1)	// wait for more time when a .tmp file is found!
		iWaitTime = 500;

	for(int iCtr = 0; iCtr < iWaitTime && !m_bThrdMonStopSignal; iCtr++)	// wait for about 15 seconds
	{
		Sleep(2);
	}

	WaitForSingleObject(m_hEvent, INFINITE);	// Scan one file at a time!

	CEnumProcess oEnumProcess;
	m_pMaxScanner->m_oMaxProcessScanner.ResetKidoInfectionStatus();

	oEnumProcess.EnumAllThreadsInSystem((THREADHANDLER)ProcMonThreadHandler, this);
	if(m_pMaxScanner->m_oMaxProcessScanner.IsKidoThreadFound())
	{
		oEnumProcess.EnumAllThreadsInSystem((THREADHANDLER)ProcMonThreadHandler, this);
	}

	bKidoFound = m_pMaxScanner->m_oMaxProcessScanner.GetKidoInfectionStatus();

	SetEvent(m_hEvent);

	CString csParam(L""), csKey(csRegKey);
	csKey.Replace(L"\\registry\\machine\\", L"");
	if(csRegData.Find(L".tmp") != -1)
	{
		csParam = csRegData;
		csParam.Replace(L"\\??\\", L"");

		AddLogEntry(_T("Kido Service EXE Found: %s"), csParam, 0, true, LOG_DEBUG);
		ReportKidoEntry(csParam);

		WaitForSingleObject(m_hDBEvent, INFINITE);	// Scan one file at a time!
		m_objFilesToDelete.AppendItem(csParam, 0);
		SetEvent(m_hDBEvent);

		m_objRegistry.DeleteRegKey(HKEY_LOCAL_MACHINE, csKey);

		CEnumProcess oEnumProcess;
		oEnumProcess.EnumRunningProcesses((PROCESSHANDLER)MyProcHandler, this);
	}
	else if(bKidoFound)
	{
		if(m_objRegistry.Get(csKey + L"\\Parameters", L"ServiceDLL", csParam, HKEY_LOCAL_MACHINE))
		{
			AddLogEntry(_T("Kido Service DLL Found: %s"), csParam, 0, true, LOG_DEBUG);
			ReportKidoEntry(csParam);

				WaitForSingleObject(m_hDBEvent, INFINITE);	// Scan one file at a time!
				m_objFilesToDelete.AppendItem(csParam, 0);
				SetEvent(m_hDBEvent);
		}
		else
		{
			AddLogEntry(L"^^^^^ Failed to read servicedll path: " + csKey + L"\\Parameters - " + csRegKey, 0, 0, true, LOG_DEBUG);
		}
		m_objRegistry.DeleteRegKey(HKEY_LOCAL_MACHINE, csKey);
		
		CEnumProcess oEnumProcess;
		oEnumProcess.EnumRunningProcesses((PROCESSHANDLER)MyProcHandler, this);
	}
	
	return false;
}

bool CProcessMonitor::DeletePendingFiles()
{
	while(m_bIsMonitoring)
	{
		WaitForSingleObject(m_hDBEvent, INFINITE);	// Scan one file at a time!

		LPVOID pos = m_objFilesToDelete.GetFirst();
		while(pos && m_bIsMonitoring)
		{
			LPTSTR szFileName = NULL;
			m_objFilesToDelete.GetKey(pos, szFileName);

			if(_waccess(szFileName, 0) == 0)
			{
				if(::DeleteFile(szFileName))
				{
				}
			}
			else
			{
				m_objFilesToDelete.DeleteItem(szFileName);
				break;
			}

			pos = m_objFilesToDelete.GetNext(pos);
		}
		SetEvent(m_hDBEvent);

		if(m_bIsMonitoring)
		{
			CloseProcessedThreads();
			Sleep(1000);
		}
	}
	return true;
}

bool CProcessMonitor::ScanThreads(const CString &csRegKey, const CString &csRegValue, const CString &csRegData)
{
	//if(csRegData.Find(L".tmp") == -1)
	//{
		// we need to let this service key get created. 
		// because when we receive this event the parameter key is not yet created in the service key
		// we check for kido after a seconds by then the ServiceDLL value is set and we can also clean up the dll
		THREADINFO *pThreadInfo = new THREADINFO;
		memset(pThreadInfo, 0, sizeof(pThreadInfo));
		pThreadInfo->pThis = this;
		_tcscpy_s(pThreadInfo->szKeyName, (LPCTSTR)csRegKey);
		_tcscpy_s(pThreadInfo->szValueName, (LPCTSTR)csRegValue);
		_tcscpy_s(pThreadInfo->szDataName, (LPCTSTR)csRegData);
		AfxBeginThread(DelayedKidoThreadScan, (LPVOID)pThreadInfo);
	//}
	//else
	//{
	//	CheckKidoKey(csRegKey, csRegValue, csRegData);
	//}
	return false;
}

bool CProcessMonitor::HandleExisting()
{
	m_bThrdMonStopSignal = false;
	m_oEnumProcess.EnumAllThreadsInSystem((THREADHANDLER)ProcMonThreadHandler, this);
	if(m_pMaxScanner->m_oMaxProcessScanner.IsKidoThreadFound())
	{
		m_oEnumProcess.EnumAllThreadsInSystem((THREADHANDLER)ProcMonThreadHandler, this);
	}
	m_oEnumProcess.EnumRunningProcesses((PROCESSHANDLER)MyProcHandler, this);
	
	return true;
}


bool CProcessMonitor::StopMonitor()
{

	m_bIsMonitoring = false;
	m_bThrdMonStopSignal = true;

	if(m_pDelPendFileThread)
	{
		if(m_pDelPendFileThread->m_hThread != INVALID_HANDLE_VALUE)
		{
			OutputDebugString(L"##### WaitForSingleObject Delete Pending Thread Started!");
			if(WaitForSingleObject(m_pDelPendFileThread->m_hThread, 30000) == WAIT_TIMEOUT)
			{
				OutputDebugString(L"##### WaitForSingleObject Delete Pending Thread TIMEDOUT!");
			}
			OutputDebugString(L"##### WaitForSingleObject Delete Pending Thread Finished!");
		}
		delete m_pDelPendFileThread;
		m_pDelPendFileThread = NULL;
	}

	if(m_pIdleScanThread)
	{
		if(m_pIdleScanThread->m_hThread != INVALID_HANDLE_VALUE)
		{
			OutputDebugString(L"##### WaitForSingleObject Stop IDLE Scan Thread!");
			m_oIdleScan.StopIdleScan();
			if(WaitForSingleObject(m_pIdleScanThread->m_hThread, 30000) == WAIT_TIMEOUT)
			{
				OutputDebugString(L"##### WaitForSingleObject Stop IDLE Scan Thread TIMEDOUT!");
			}
			OutputDebugString(L"##### WaitForSingleObject Stop IDLE Scan Thread Finished!");
		}
		delete m_pIdleScanThread;
		m_pIdleScanThread = NULL;
		m_oIdleScan.m_bStopScanning = false;
	}

	WaitForSingleObject(m_hDBEvent, INFINITE);	// Scan one file at a time!

	CloseAllThreads();

	CActiveMonitor::FreeThreatManager();	//Only process monitor can init Threat Manager, hence only he gets to free it

	if(m_pMaxScanner)
	{
		m_pMaxScanner->m_oLocalSignature.UnLoadLocalDatabase();

		m_pMaxScanner->m_oMaxProcessScanner.DeInit();
		m_pMaxScanner->DeInitializeScanner();

		delete m_pMaxScanner;
		m_pMaxScanner = NULL;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: MyProcHandler
	In Parameters	: LPCTSTR : The executable file name
					: LPCTSTR : The execuatble full file path
					: HANDLE  : hProcess
					: DWORD   : Process ID
					: LPVOID  : The application handler i.e. this class
					: bool	  : Stop Enumeration further
	Out Parameters	: BOOL - Always returns true
	Purpose			: Callback function used for enumerating running processes
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
BOOL CALLBACK MyProcHandler(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, 
							LPVOID pThis, bool &bStopEnum)
{
	CProcessMonitor *pProcMon = (CProcessMonitor *)pThis;
	if(pProcMon)
	{
		CString csPath(szExePath);
		if(csPath.GetLength() > 0)
		{
			if(csPath.Find(L':') == csPath.ReverseFind(L':'))
			{
				csPath.MakeLower();
				MAX_SCANNER_INFO oScannerInfo = {0};
				oScannerInfo.hProcessHandleIDToScan = hProcess;
				oScannerInfo.eMessageInfo = Process;
				oScannerInfo.eScannerType = Scanner_Type_Max_ActMonProcScan;
				oScannerInfo.ulProcessIDToScan = dwProcessID;
				_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), csPath);
				pProcMon->CheckProcess(&oScannerInfo, CALL_TYPE_F_EXECUTE, bStopEnum);
			}
		}
	}
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : CProcessScanner::CheckProcess
In Parameters  : const CString &csProcessPath, DWORD dwProcessID, SD_Message_Info eTypeOfScanner, 
Out Parameters : bool 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CProcessMonitor::CheckProcess(PMAX_SCANNER_INFO pScannerInfo, int iTypeOfCall, bool &bStopEnum)
{
	if(!m_bIsMonitoring)
	{
		//SetEvent(m_hEvent);
		return false;
	}

	CString csProcessPath(pScannerInfo->szFileToScan);
	if(csProcessPath.Find(':') == -1)
	{
		//SetEvent(m_hEvent);
		return false;
	}

	csProcessPath.Replace(L"\\??\\",L"");

	if(::PathIsDirectory(csProcessPath))
	{
		//SetEvent(m_hEvent);
		return false;
	}

	if(m_lpfnCheckBlackFile != NULL)
	{
		if(m_lpfnCheckBlackFile(csProcessPath) == 1)
		{
			//SetEvent(m_hEvent);
			return true;
		}
	}

	if(m_lpfnCheckFileInAppData != NULL)
	{
		if(m_lpfnCheckFileInAppData(csProcessPath) == 1)
		{
			//SetEvent(m_hEvent);
			return true;
		}
	}

	

#ifndef WIN64
	if((pScannerInfo->eMessageInfo == Process) && (pScannerInfo->ulProcessIDToScan > 0))
	{
		//CString csTemp;
		//csTemp.Format(L"CheckFunctionAddress: %d, %s", pScannerInfo->ulProcessIDToScan, pScannerInfo->szFileToScan);
		//AddLogEntry(csTemp);
		m_pMaxScanner->m_oMaxProcessScanner.CheckFunctionAddress(pScannerInfo);
		pScannerInfo->ThreatDetected = 0;
		pScannerInfo->ThreatSuspicious = 0;
		//m_pMaxScanner->m_oMaxProcessScanner.CheckForNimnulHandles(pScannerInfo);
		SendScanStatusToUI(pScannerInfo, iTypeOfCall);
	}
#endif

	if((csProcessPath.Find(L"\\auliveupdate.exe") != -1) || (csProcessPath.Find(L"\\auscanner.exe") != -1)
		|| (csProcessPath.Find(L"\\autray.exe") != -1) || (csProcessPath.Find(L"\\auusb.exe") != -1)
		|| (csProcessPath.Find(L"\\aumainui.exe") != -1) || (csProcessPath.Find(L"\\auwatchdogservice.exe") != -1) 
		|| (csProcessPath.Find(L"\\ausrvopt.exe") != -1) 
		|| (csProcessPath.Find(L"\\auactmon.exe") != -1) || (csProcessPath.Find(L"\\aumailproxy.exe") != -1)
		|| (csProcessPath.Find(L"\\escanmon.exe") != -1) || (csProcessPath.Find(L"\\econser.exe") != -1)
		|| (csProcessPath.Find(L"\\consctl.exe") != -1) || (csProcessPath.Find(L"\\avpmapp.exe") != -1)
		|| (csProcessPath.Find(L"\\mwaser.exe") != -1) || (csProcessPath.Find(L"\\mwagent.exe") != -1)
		|| (csProcessPath.Find(L"\\econceal.exe") != -1) || (csProcessPath.Find(L"\\traysser.exe") != -1)
		|| (csProcessPath.Find(L"\\trayicos.exe") != -1) || (csProcessPath.Find(L"\\escanpro.exe") != -1)
		|| (csProcessPath.Find(L"\\mwavscan.exe") != -1) || (csProcessPath.Find(L"\\auprocscn.exe") != -1)
		|| (csProcessPath.Find(L"\\audbserver.exe") != -1)
		|| (csProcessPath.Find(L"\\aufwpnp.exe") != -1) )
	{
		SetEvent(m_hEvent);
		return false;
	}

	if(csProcessPath.Trim().GetLength() == 0)
	{
		SetEvent(m_hEvent);
		return false;
	}

	if(pScannerInfo->ulReplicatingProcess == 1)
	{
		AddReplicationLog(_T("[toBlock = 1] Process Accessing = %s, File Accessed = %s Block Access = %d\n"),pScannerInfo->szContainerFileName,pScannerInfo->szFileToScan,pScannerInfo->ulReplicatingProcess);
		SetEvent(m_hEvent);
		return false;
	}

	if(pScannerInfo->ulReplicatingProcess == 2)
	{
		AddReplicationLog(_T("[toBlock = 2] Process Accessing = %s, File Accessed = %s Block Access = %d\n"),pScannerInfo->szContainerFileName,pScannerInfo->szFileToScan,pScannerInfo->ulReplicatingProcess);
	}

	if(pScannerInfo->ulReplicatingProcess == 2)
	{
		pScannerInfo->eMessageInfo = File;
		pScannerInfo->eDetectedBY = Detected_BY_Max_Pattern;
		pScannerInfo->ThreatDetected = 1;
		pScannerInfo->ulThreatID = 7604;	//using trojan.agent
	
		if((pScannerInfo->ulReplicatingProcess == 1))
		{
			TCHAR strPathName[MAX_PATH];

			GetProcessNameByPid((ULONG) pScannerInfo->ulProcessIDToScan, &strPathName[0]);
			
			if(wcslen(strPathName) >= 5)
			{
				ReportKidoEntry(strPathName, 1);
			}
		}
		
		ReportKidoEntry(pScannerInfo->szFileToScan, 1);
		SetEntryStatus(pScannerInfo->szFileToScan, pScannerInfo->ulThreatID, (int&)pScannerInfo->eMessageInfo, (int&)pScannerInfo->eDetectedBY, pScannerInfo->szThreatName, pScannerInfo->szOLEMacroName);

		SetEvent(m_hEvent);

		CEnumProcess oEnumProcess;
		oEnumProcess.EnumRunningProcesses((PROCESSHANDLER)MyProcHandler, this);
		return false;
	}

	/*
	if(_waccess(csProcessPath, 0))
	{
		SetEvent(m_hEvent);
		return false;
	}

	HANDLE	hDummyHandle = INVALID_HANDLE_VALUE;
	hDummyHandle = CreateFile(pScannerInfo->szFileToScan,GENERIC_READ,FILE_SHARE_READ | FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if (hDummyHandle != INVALID_HANDLE_VALUE)
	{
		DWORD dwFileSz = GetFileSize(hDummyHandle,NULL);

		CloseHandle(hDummyHandle);
		hDummyHandle = INVALID_HANDLE_VALUE;
		if (dwFileSz >= (99 * 1024 * 1024))
		{
			return false;
		}
	}
	*/

	bool bDisplayPrompt = true;
	if(pScannerInfo->eScannerType != Scanner_Type_Max_SignatureScan)
	{
		if(AlreadyChecked(pScannerInfo->szFileToScan, pScannerInfo->ulThreatID, (int&)pScannerInfo->eMessageInfo, (int&)pScannerInfo->eDetectedBY, pScannerInfo->szThreatName, pScannerInfo->szOLEMacroName))
		{
			if(m_pMaxScanner->IsExcluded(pScannerInfo->ulThreatID, pScannerInfo->szThreatName, pScannerInfo->szFileToScan))
			{
				SetEvent(m_hEvent);
				return false;
			}

			if(pScannerInfo->eDetectedBY != Detected_BY_NONE)
			{
				bDisplayPrompt = false;
			}
		}
	}

	//Tushar Kadam ==>  To handle Pattern Trojans like IMG001.exe etc from execution
	if(iTypeOfCall == CALL_TYPE_F_EXECUTE || iTypeOfCall == CALL_TYPE_F_CREATE || iTypeOfCall == CALL_TYPE_F_OPEN || iTypeOfCall == CALL_TYPE_F_NEW_FILE)
	{
		pScannerInfo->SkipPatternScan = false;
	}
	else
	{
		pScannerInfo->SkipPatternScan = true;
	}

	if(iTypeOfCall != CALL_TYPE_F_EXECUTE)	// scan for polymorphic virus only incase of file being executed
	{
		pScannerInfo->SkipPolyMorphicScan = false;
	}

	m_pMaxScanner->m_bRefScan = false;	//false or true. If execute call it is off else on as per Tushar's sir requirement 14-9-2022
	if (iTypeOfCall == CALL_TYPE_F_EXECUTE)	// scan for polymorphic virus only incase of file being executed
	{
		m_pMaxScanner->m_bRefScan = false;	
	}
	

	m_pMaxScanner->ScanFile(pScannerInfo);
	
	if((pScannerInfo->IsExcluded == 0) && 
		((pScannerInfo->ThreatDetected == 1) || (pScannerInfo->ThreatSuspicious == 1)))
	{
		if((!pScannerInfo->SkipPolyMorphicScan) && (pScannerInfo->eScannerType != Scanner_Type_Max_SignatureScan))
		{
			SetEntryStatus(pScannerInfo->szFileToScan, pScannerInfo->ulThreatID, (int&)pScannerInfo->eMessageInfo, (int&)pScannerInfo->eDetectedBY, pScannerInfo->szThreatName, pScannerInfo->szOLEMacroName);
		}
		AddLogEntry(L"##### File Infected: File: %s, FileSig: %s", pScannerInfo->szFileToScan,pScannerInfo->szFileSig, true);
		if(IsSystemProcess(csProcessPath))
		{
			if(!m_bMessageDisplayed && m_pMsgHandler)
			{
				m_bMessageDisplayed = true;
				AddLogEntry(L"##### System File Infected: Process: %s, File: %s", csProcessPath, pScannerInfo->szContainerFileName, true, LOG_DEBUG);
				m_pMsgHandler(SETINFECTEDSYSTEMFILE, csProcessPath, L"", pScannerInfo->szContainerFileName, m_pThis);
			}
		}
		else
		{
			/*
			DWORD dwProcID = 0x00;
			dwProcID = m_oEnumProcess.GetProcessIDByName(csProcessPath);
			if (dwProcID > 100)
			{
				//objEnumProc.SuspendProcess(dwProcID);
				m_oEnumProcess.KillProcess(dwProcID);
			}
			*/
			SendScanStatusToUI(pScannerInfo, iTypeOfCall, bDisplayPrompt);
		}
		SetEvent(m_hEvent);
		return true;
	}
	if((!pScannerInfo->SkipPolyMorphicScan) && (pScannerInfo->eScannerType != Scanner_Type_Max_SignatureScan))
	{
		SetEntryStatus(pScannerInfo->szFileToScan, pScannerInfo->ulThreatID, (int&)pScannerInfo->eMessageInfo, (int&)pScannerInfo->eDetectedBY, pScannerInfo->szThreatName, pScannerInfo->szOLEMacroName);
	}
	if(pScannerInfo->eMessageInfo == Process)
	{
		//Commented on: 07-June-2011
		//As scanning these entries slows down the scanner drastically
		//m_oEnumProcess.EnumProcessModuleList(pScannerInfo->ulProcessIDToScan, pScannerInfo->szFileToScan, (PROCESSMODULEHANDLER)MyProcModuleHandler, this, true);
	}
	
	SetEvent(m_hEvent);

	return false;
}
bool CProcessMonitor::IsSystemProcess(CString &csProcessPath)
{
	if((csProcessPath.Find(L"system32\\smss.exe") != -1) || (csProcessPath.Find(L"system32\\csrss.exe") != -1)
		|| (csProcessPath.Find(L"system32\\winlogon.exe") != -1) || (csProcessPath.Find(L"system32\\services.exe") != -1) 
		|| (csProcessPath.Find(L"system32\\svchost.exe") != -1) || (csProcessPath.Find(L"system32\\spoolsv.exe") != -1) 
		|| (csProcessPath.Find(L"system32\\lsass.exe") != -1))
	{
		return true;
	}
	return false;
}

BOOL CALLBACK ProcMonThreadHandler(DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath, LPVOID pThis, bool &bStopEnum)
{
	CProcessMonitor *pProcMon = (CProcessMonitor*)pThis;
	if(pProcMon)
	{
		pProcMon->ScanThread(dwProcessID, dwThreadID, szProcImgPath, pThis, bStopEnum);
	}
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function       : ScanThread
In Parameters  : DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath, LPVOID pThis, bool &bStopEnum
Out Parameters : bool
Purpose		   : scan this thread
Author		   : Anand Srivastava
-------------------------------------------------------------------------------------*/
bool CProcessMonitor::ScanThread(DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath, LPVOID pThis, bool &bStopEnum)
{
	MAX_SCANNER_INFO oScannerInfo = {0};
	oScannerInfo.eScannerType = Scanner_Type_Max_ThreadScan;
	oScannerInfo.ulProcessIDToScan = dwProcessID;
	oScannerInfo.ulThreadIDToScan = dwThreadID;

	_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), szProcImgPath);

	m_pMaxScanner->m_oMaxProcessScanner.ScanThread(&oScannerInfo, bStopEnum);
	if((oScannerInfo.ThreatDetected == 1) || (oScannerInfo.ThreatSuspicious == 1))
	{
		SendScanStatusToUI(&oScannerInfo, CALL_TYPE_F_EXECUTE);
	}
	return true;
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
	CProcessMonitor *pProcMon = (CProcessMonitor *)pThis;
	if(pProcMon)
	{
		CString csPath(szModulePath);
		if(csPath.GetLength() > 0)
		{
			csPath.MakeLower();
			MAX_SCANNER_INFO oScannerInfo = {0};
			oScannerInfo.eMessageInfo = Module;
			oScannerInfo.eScannerType = Scanner_Type_Max_ActMonModuleScan;
			oScannerInfo.ulProcessIDToScan = dwProcessID;
			oScannerInfo.hProcessHandleIDToScan = hProcess;
			oScannerInfo.hModuleHandleToScan = hModule;
			_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), szModulePath);
			_tcscpy_s(oScannerInfo.szContainerFileName, _countof(oScannerInfo.szContainerFileName), szProcessPath);
			pProcMon->CheckProcess(&oScannerInfo, CALL_TYPE_F_EXECUTE, bStopEnum);
		}
	}
	return TRUE;
}

bool CProcessMonitor::AddInRestartDeleteIni(RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID,LPCTSTR szValue)
{
	CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
	WCHAR strCount[50] = {0};
	WCHAR strValue[MAX_PATH*4] = {0};

	WCHAR *szSection[8] = {
							L"File_Delete", L"File_Backup",
							L"Folder", L"RegistryKey",
							L"RegistryValue", L"RegistryData",
							L"File_Rename", L"File_Replace" 
						};

	LPTSTR lpszSection = NULL;

	if(eRD_Type == RD_FILE_DELETE)
	{
		lpszSection = szSection[0];
	}
	else if(eRD_Type == RD_FILE_BACKUP)
	{
		lpszSection = szSection[1];
	}
	else if(eRD_Type == RD_FOLDER)
	{
		lpszSection = szSection[2];
	}
	else if(eRD_Type == RD_KEY)
	{
		lpszSection = szSection[3];
	}
	else if(eRD_Type == RD_VALUE)
	{
		lpszSection = szSection[4];
	}
	else if(eRD_Type == RD_DATA)
	{
		lpszSection = szSection[5];
	}
	else if(eRD_Type == RD_FILE_RENAME)
	{
		lpszSection = szSection[6];
	}
	else if(eRD_Type == RD_FILE_REPLACE)
	{
		lpszSection = szSection[7];
	}

	if(lpszSection == NULL)
	{
		return FALSE;
	}

	CreateWormstoDeleteINI(strINIPath);

	UINT ulWormCnt = GetPrivateProfileIntW(lpszSection, L"WormCnt", 0, strINIPath);
	swprintf_s(strCount, _countof(strCount), L"%d", ++ulWormCnt);
	WritePrivateProfileStringW(lpszSection, L"WormCnt", strCount, strINIPath);

	swprintf_s(strValue, _countof(strValue), L"%ld^%s", ulSpyNameID, szValue);
	WritePrivateProfileStringW(lpszSection, strCount, strValue, strINIPath);
	AddLogEntry(L"^^^^^: %s", szValue, 0, true, LOG_DEBUG);
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : CQuarantineFile::CreateWormstoDeleteINI
In Parameters  : CString strINIPath,
Out Parameters : void
Description    :
Author         : Vaibhav Desai
--------------------------------------------------------------------------------------*/
void CProcessMonitor::CreateWormstoDeleteINI(CString strINIPath)
{
	if(_waccess_s(strINIPath, 0) != 0)
	{
		// UTF16-LE BOM(FFFE)
		WORD wBOM = 0xFEFF;
		DWORD NumberOfBytesWritten;
		HANDLE hFile = ::CreateFile(strINIPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		::WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, NULL);
		::CloseHandle(hFile);
		WritePrivateProfileStringW(L"File_Delete", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Backup", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"Folder", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryData", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryValue", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"RegistryKey", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Rename", L"WormCnt", L"0", strINIPath);
		WritePrivateProfileStringW(L"File_Replace", L"WormCnt", L"0", strINIPath);
	}
}

void CProcessMonitor::SetAutomationLabStatus()
{
	if(m_pMaxScanner)
	{
		DWORD dwAutomationLab = 0;
		CRegistry oReg;
		oReg.Get(CSystemInfo::m_csProductRegKey, AUTOLATION_LAB_VAL, dwAutomationLab, HKEY_LOCAL_MACHINE);
		bool bAutomationLab = (dwAutomationLab == 1 ? true : false);
		m_pMaxScanner->SetAutomationLabStatus(bAutomationLab);
	}
}

void CProcessMonitor::GetProcessNameByPid(ULONG uPid, TCHAR * strFinal)
{
	char pname_buf[MAX_PATH] = {0};
	HANDLE h_process = NULL;
	HMODULE hMods[1024] = {0};
	TCHAR str[MAX_PATH] = {0};
	ULONG n;

	h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, uPid);
	if(h_process)
	{
		if (h_process != NULL)
			pEnumProcessModules(h_process, hMods, 1024, &n);

		if(pGetModuleFileNameExA(h_process, hMods[0], pname_buf, MAX_PATH))
		{
			
			swprintf_s(str, MAX_PATH, L"%S", pname_buf);
			memcpy(strFinal,str,MAX_PATH);
		}
		CloseHandle(h_process);
	}
	return;
}

void CProcessMonitor::link_psapi()
{
	g_psapi = LoadLibrary(L"psapi.dll");
	if(g_psapi == NULL)
	{
		// no psapi.dll - log it!
		return;
	}
	pEnumProcesses = (EnumProcesses *)GetProcAddress(g_psapi, "EnumProcesses");
	pEnumProcessModules = (EnumProcessModules *)GetProcAddress(g_psapi, "EnumProcessModules");

#ifdef UNICODE
	pGetModuleFileNameExA = (GetModuleFileNameExA *)GetProcAddress(g_psapi, "GetModuleFileNameExA");
#else
	pGetModuleFileNameExA = (GetModuleFileNameEx *)GetProcAddress(g_psapi, "GetModuleFileNameExA");
	pGetProcessImageFilename = (GetProcessImageFileName *) GetProcAddress(g_psapi,"GetProcessImageFileName");
#endif

	if(pEnumProcesses == NULL || pEnumProcessModules == NULL || pGetModuleFileNameExA == NULL)
	{
		// invalid psapi.dll?
		FreeLibrary(g_psapi);
		g_psapi = NULL;
	}
}

void CProcessMonitor::SetStartupKeys()
{
	HKEY hKey;
	DWORD dwLen;
    DWORD dwKeyEn = 0;
	DWORD dwType = REG_DWORD;

	if(::RegOpenKeyEx(HKEY_LOCAL_MACHINE, ACTMON_REG_KEY, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{		
		if(::RegQueryValueEx(hKey, L"EnableCopyPaste", NULL, &dwType,(LPBYTE)&dwKeyEn, &dwLen) == ERROR_SUCCESS)
		{
			if(::RegSetValueEx(hKey,L"EnableCopyPaste",NULL,REG_DWORD,(LPBYTE) &dwKeyEn,sizeof(DWORD)) == ERROR_SUCCESS)
			{
			}
		}

		if(::RegQueryValueEx(hKey, L"EnableReplicating", NULL, &dwType,(LPBYTE)&dwKeyEn, &dwLen) == ERROR_SUCCESS)
		{
			if(::RegSetValueEx(hKey,L"EnableReplicating",NULL,REG_DWORD,(LPBYTE) &dwKeyEn,sizeof(DWORD)) == ERROR_SUCCESS)
			{
			}
		}

		RegCloseKey(hKey);
	}
}

bool CProcessMonitor::NewFileScanner(PMAX_SCANNER_INFO pScannerInfo)
{
	if(m_bIsMonitoring)
	{
		pScannerInfo->pThis = this;
		CWinThread* pThread = AfxBeginThread(DelayedNewFileScanner, (LPVOID)pScannerInfo, THREAD_PRIORITY_LOWEST, NULL, CREATE_SUSPENDED, NULL);
		if(pThread)
		{
			AddToThreadList(pThread);
			pThread->m_bAutoDelete = FALSE;
			pThread->ResumeThread();
		}
	}
	return false;
}

UINT DelayedNewFileScanner(LPVOID lpVoid)
{
	PMAX_SCANNER_INFO pScannerInfo = (PMAX_SCANNER_INFO)lpVoid;
	if(pScannerInfo)
	{
		CProcessMonitor *pThis = (CProcessMonitor *)pScannerInfo->pThis;
		if(pThis)
		{
			bool bStopEnum = false;
			pScannerInfo->pThis = NULL;
			Sleep(500);
			pThis->CheckProcess(pScannerInfo, CALL_TYPE_F_NEW_FILE, bStopEnum);
			delete pScannerInfo;
			pScannerInfo = NULL;
		}
	}
	return 0;
}

bool CProcessMonitor::SuspendIdleScan()
{
	if(m_pIdleScanThread && m_pIdleScanThread->m_hThread)
	{
		m_pIdleScanThread->SuspendThread();
		return true;
	}
	return false;
}

bool CProcessMonitor::ResumeIdleScan()
{
	if(m_pIdleScanThread && m_pIdleScanThread->m_hThread)
	{
		m_pIdleScanThread->ResumeThread();
		return true;
	}
	return false;
}

void CProcessMonitor::InitializePatternDLL()
{
	m_hWhiteCerScanDll = NULL;
	m_hWhiteCerScanDll = LoadLibrary(_T("AuWhiteCerScan.dll"));
	if(m_hWhiteCerScanDll != NULL)
	{
		m_lpfnWhiteCerScanIni = (LPFN_WhiteCerScanIni)GetProcAddress(m_hWhiteCerScanDll, "SetFilterINI");
		if(m_lpfnWhiteCerScanIni != NULL)
		{
			if(PathFileExists(CSystemInfo::m_strAppPath + _T("Setting\\RegularExp.ini")))
				m_lpfnWhiteCerScanIni((LPCTSTR)(CSystemInfo::m_strAppPath + _T("Setting\\RegularExp.ini")));
		}
		m_lpfnWhiteExpParse = (LPFN_WhiteExpParse)GetProcAddress(m_hWhiteCerScanDll, "ExpressionParsing");
		m_lpfnWhiteCerScan = (LPFN_WhiteCerScan)GetProcAddress(m_hWhiteCerScanDll, "IsWhitePublisher");
	}

	m_hRansomPatternScanDll = NULL;
	m_hRansomPatternScanDll = LoadLibrary(_T("AuRansomPatternScan.dll"));
	if(m_hRansomPatternScanDll != NULL)
	{
		m_lpfnSetAppDataPath = (LPFN_SetAppDataPath)GetProcAddress(m_hRansomPatternScanDll, "SetAppDataPath");
		if(m_lpfnSetAppDataPath != NULL)
		{
			CString csAppDataPath;
			CString csLocalAppDataPath;
			CRegistry oRegistry; 
			oRegistry.Get(CSystemInfo::m_csProductRegKey, _T("APPDATA"), csAppDataPath, HKEY_LOCAL_MACHINE);
			oRegistry.Get(CSystemInfo::m_csProductRegKey, _T("APPDATA_LOCAL"), csLocalAppDataPath, HKEY_LOCAL_MACHINE);
			if(!csAppDataPath.IsEmpty() && !csLocalAppDataPath.IsEmpty())
			{
				csAppDataPath = csAppDataPath.MakeLower();
				csLocalAppDataPath = csLocalAppDataPath.MakeLower();				
				m_lpfnSetAppDataPath((LPCTSTR)csAppDataPath, (LPCTSTR)csLocalAppDataPath);
			}
		}
		m_lpfnCheckBlackFile = (LPFN_CheckBlackFile)GetProcAddress(m_hRansomPatternScanDll, "CheckFileWithPattern");
		m_lpfnCheckFileInAppData = (LPFN_CheckFileInAppData)GetProcAddress(m_hRansomPatternScanDll, "CheckFileInAppData");
	}
}
