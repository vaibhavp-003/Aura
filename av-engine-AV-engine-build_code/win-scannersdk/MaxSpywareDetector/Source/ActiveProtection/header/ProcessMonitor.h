/*======================================================================================
   FILE				: ProcessMonitor.h
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

#pragma once
#include "ActiveMonitor.h"
#include "EnumProcess.h"
#include "FileSig.h"
#include "IdleScan.h"

typedef BOOL (CALLBACK *THREADHANDLER)(DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath, LPVOID pThis, bool &bStopEnum);
BOOL CALLBACK ProcMonThreadHandler(DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath, LPVOID pThis, bool &bStopEnum);
typedef DWORD (*LPFN_WhiteCerScan)(LPCTSTR szFilePath);
typedef void (*LPFN_WhiteCerScanIni)(LPCTSTR szFilePath);
typedef DWORD (*LPFN_WhiteExpParse)(LPCTSTR szFilePath);
typedef void	(*LPFN_SetAppDataPath) (LPCTSTR szAppDataPath, LPCTSTR szLocalAppDataPath);
typedef DWORD	(*LPFN_CheckBlackFile) (LPCTSTR szFilePath);
typedef DWORD	(*LPFN_CheckFileInAppData)(LPCTSTR szFilePath);

typedef LONG NTSTATUS;

class CProcessMonitor : public CActiveMonitor
{
public:
	CProcessMonitor();
	virtual ~CProcessMonitor();

	bool StartMonitor();
	bool StopMonitor();
	void SetHandler(LPVOID pMessageHandler, LPVOID lpThis);
	bool ScanThreads(const CString &csRegKey, const CString &csRegValue, const CString &csRegData);
	bool CheckKidoKey(CString csRegKey, CString csRegValue, CString csRegData);
	bool HandleExisting();
	bool NewFileScanner(PMAX_SCANNER_INFO pScannerInfo);
	bool CheckProcess(PMAX_SCANNER_INFO pScannerInfo, int iTypeOfCall, bool &bStopEnum);
	bool ScanThread(DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath, LPVOID pThis, bool &bStopEnum);
	bool m_bThrdMonStopSignal;
	bool DeletePendingFiles();
	CIdleScan	 m_oIdleScan;
	bool SuspendIdleScan();
	bool ResumeIdleScan();
				
private:

	CWinThread *m_pDelPendFileThread;
	CWinThread *m_pIdleScanThread;
	HANDLE m_hEvent, m_hDBEvent;
	bool m_bMessageDisplayed;
	LPVOID m_pThis;
	ACTMON_MESSAGEPROCHANDLER m_pMsgHandler;
	bool IsSystemProcess(CString &csProcessName);
	void ReportKidoEntry(CString csFileName, short sType = 0);
	void WriteSignatureToIni(LPCTSTR szFileName, LPCTSTR szFileSig, short sType = 0);
	bool WriteInfoInSection(LPCTSTR szSectionName, LPCTSTR szCountName, LPCTSTR szValueToAdd, LPCTSTR szValueToAdd2);

	void CreateWormstoDeleteINI(CString strINIPath);
	bool AddInRestartDeleteIni(RESTART_DELETE_TYPE eRD_Type, ULONG ulSpyNameID, LPCTSTR szValue);
	void SetAutomationLabStatus();
	void link_psapi();
	void GetProcessNameByPid(ULONG uPid, TCHAR * strFinal);

	void CleanUp();
	TCHAR m_chDriveToScan[3];

	CS2U		 m_objFilesToDelete;
	CFileSig	 m_objFileSig;
	CEnumProcess m_oEnumProcess;
	void SetStartupKeys();

	HMODULE m_hWhiteCerScanDll;
	HMODULE m_hRansomPatternScanDll;
	LPFN_WhiteCerScan m_lpfnWhiteCerScan;
	LPFN_WhiteCerScanIni m_lpfnWhiteCerScanIni;
	LPFN_WhiteExpParse m_lpfnWhiteExpParse;
	LPFN_SetAppDataPath		m_lpfnSetAppDataPath;
	LPFN_CheckBlackFile		m_lpfnCheckBlackFile;
	LPFN_CheckFileInAppData	m_lpfnCheckFileInAppData;
	void InitializePatternDLL();
};


