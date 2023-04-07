#include "pch.h"
#include "BKComDll.h"
#include "ScanProcess.h"
#include "Registry.h"
#include "SDSystemInfo.h"
#include "Enumprocess.h"
#include "DBPathExpander.h"
#include "DirectoryManager.h"

bool CScanProcess::m_bQFullDiskError(false);

void Process_DoEvents()
{
	MSG oMSG;
	while (::PeekMessage(&oMSG, NULL, 0, 0, PM_NOREMOVE))
	{
		if (::GetMessage(&oMSG, NULL, 0, 0))
		{
			::TranslateMessage(&oMSG);
			::DispatchMessage(&oMSG);
		}
		else
		{
			break;
		}
	}
}

CScanProcess::CScanProcess():m_objReportedSpyMap(), m_objScanTextLookup(false), m_objThreadSync(NULL)
{
	m_iScanType = 0;
	m_bScanInProgress = false;
	m_dwSpywareFound = 0;
	m_dwQuarantineFailedCount = 0;
	m_iPercentage = 0;
	m_dwFilesScanned = 0;
	m_csDriveNames = _T("");
	m_objScanTextLookup = false;
	m_csActionQuarantine = _T("");
	m_csActionVirus = _T("");
	m_csActionRootkit = _T("");
	m_csActionSystemFile = _T("");
	m_bQuarantineStopped = false;
	m_bRestartRequired = false;
	m_bRestartEntryFound = false;
	m_iSuspendProcessCnt = 0;
	m_iCountSpywareFound = 0;
	
	m_csFolderToScan = _T("");
	m_bQuarantineProcess = false;
	m_bAppClosing = false;
	m_bisDiskFull = false;
	m_bCriticalScan = false;
	m_iShowScanStatus = 0;


	ZeroMemory(&m_sScanRequest, sizeof(MAX_PIPE_DATA_REG));
	m_dwFilesScanned = 0;
	m_pQuarantineThread = NULL;
	m_pScanFromUIThread = NULL;
	m_bRestartEntryFound = false;
	m_pMaxSecureDispatcher = NULL;
	m_chScanFromUIStage = 0;
	m_bRegisteredSession = false;		//***Make it true only 1st time when registration is successful at first time
	m_pMaxSecureDispatcher = NULL;
	m_bShutdown = FALSE;
	m_bUIClose = false;
	m_bScanningClosed = false;
	m_bSignatureScan = false;
	m_nProcessInspected = 0;
	m_nCookiesInspected = 0;
}
CScanProcess::~CScanProcess()
{
}

/*--------------------------------------------------------------------------------------
Function       : CallScanFromUI
In Parameters  : void
Out Parameters : bool
Description    : Call from UI with scan options
--------------------------------------------------------------------------------------*/
bool CScanProcess::CallScanFromUI()
{
	bool bRet = false;
	DWORD dwVal = 0;
	CRegistry objRegistry;
	
	theApp.m_objScanStatusData = { 0 };
	theApp.m_pObjMaxCommunicatorServer = new CMaxCommunicatorServer(theApp.m_csGUID, CScanProcess::OnScanDataReceivedCallBack, sizeof(MAX_PIPE_DATA_REG));
	theApp.m_pObjMaxCommunicatorServer->Run();

	DWORD dwCleanTemp = 0;
	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("CleanTemp"), dwCleanTemp, HKEY_LOCAL_MACHINE);
	if (dwCleanTemp)
		SHEmptyRecycleBin(NULL, NULL, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);

	CString csTempFolder;
	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("TempFolderPath"), csTempFolder, HKEY_LOCAL_MACHINE);

	memset(&m_szReportPathBuffer, 0, MAX_PATH);
	wcscpy_s(m_szReportPathBuffer, csTempFolder);
	wcscat_s(m_szReportPathBuffer, L"UAVMEM");
	
	DeallocateMemoryForReport();

	CDirectoryManager oDirectoryManager;
	oDirectoryManager.MaxCreateDirectory(m_szReportPathBuffer);

	theApp.eScanStartedBy = (ENUM_SCAN_CONDITION)m_objScanStartInfo.iMessageId;
	if (theApp.eScanStartedBy == ENUM_SC_AUTOSCAN)
	{
		m_iScanType = ENUM_SCAN_QUICK;
		StartAutoScan();
	}
	else if (theApp.eScanStartedBy == ENUM_SC_SCHEDULED)
	{
		StartAutoScan();
	}
	else
	{
		m_iScanType = m_objScanStartInfo.iScanType;
		m_bDeepScan = m_objScanStartInfo.iDeepScan;
		m_bCriticalScan = m_objScanStartInfo.iCriticalScan;
		m_bShutdown = m_objScanStartInfo.iShutdownFinish;
		StartManualScan();
	}


	return bRet;
}



/*--------------------------------------------------------------------------------------
Function       : DestroyCommObject
In Parameters  : void
Out Parameters : void
Description    : Destory communication server
--------------------------------------------------------------------------------------*/
void CScanProcess::DestroyCommObject()
{
	if (theApp.m_pObjMaxCommunicatorServer)
	{
		delete theApp.m_pObjMaxCommunicatorServer;
		theApp.m_pObjMaxCommunicatorServer = NULL;
	}
}

/*--------------------------------------------------------------------------------------
Function       : StartScan
In Parameters  : CString csDrive, bool bSignatureScan, bool bVirusScan, bool bRootkitScan, bool bKeyLoggerScan, bool bHeuristicScan, bool bDBScan, bool bCustomScan, bool bDeepScan, bool bAutoQuarantine
Out Parameters : void
Description    : Start scanning process
--------------------------------------------------------------------------------------*/
void CScanProcess::StartScan(CString csDrive, bool bSignatureScan, bool bVirusScan, bool bRootkitScan, bool bKeyLoggerScan, bool bHeuristicScan, bool bDBScan, bool bCustomScan, bool bDeepScan, bool bAutoQuarantine)
{
	m_bRestartRequired = false;
	CheckAndExitScanner();
	CRegKey objRegKey;
	LONG lResult = 0;
	lResult = objRegKey.Open(HKEY_LOCAL_MACHINE, CSystemInfo::m_csProductRegKey);
	DWORD dwStatus = 0;
	if (lResult == ERROR_SUCCESS)
	{
		objRegKey.QueryDWORDValue(L"ShowUIStatus", dwStatus);
	}
	//m_objReportedSpyMap.RemoveAll();

	//IsRootkitQuarantineEnabled();


	//m_bOpenHTMLFile = false;
	//m_bOpenExportFile = false;

	//InitializeExportLog();

	m_bSplSpywareFound = false;
	m_iCountSpywareFound = 0;

	// Prepare the structure to be sent to the WatchDog Service to start the scan
	// The following structure holds the data required by the WatchDog Service to launch the command line scanner.
	m_sScanRequest.sScanOptions.SignatureScan = bSignatureScan;
	m_sScanRequest.sScanOptions.VirusScan = bVirusScan;
	m_sScanRequest.sScanOptions.RootkitScan = bRootkitScan;
	m_sScanRequest.sScanOptions.KeyLoggerScan = bKeyLoggerScan;
	m_sScanRequest.sScanOptions.HeuristicScan = bHeuristicScan;
	m_sScanRequest.sScanOptions.DBScan = bDBScan;
	m_sScanRequest.sScanOptions.CustomScan = bCustomScan;
	m_sScanRequest.sScanOptions.DeepScan = bDeepScan;
	if (bCustomScan) // to make auto quarantine off for network scan
	{
		CString csMachineName = csDrive.Left(csDrive.Find(L"\\", csDrive.Find(L"\\") + 3));
		csMachineName = csMachineName.Mid(2);
		csMachineName.Trim();
		TCHAR szHostname[MAX_PATH] = { 0 };
		DWORD dwSize = UNLEN + 1;
		GetComputerName(szHostname, &dwSize);
		CString csHostname(szHostname);
		csHostname.Trim();
		//if(csDrive.GetAt(1)==L'\\' && (csMachineName.CompareNoCase(csHostname)!=0) )//
		//{			
		//	m_sScanRequest.sScanOptions.AutoQuarantine = false;
		//}
		//else
		//{
		m_sScanRequest.sScanOptions.AutoQuarantine = bAutoQuarantine;
		/*}*/
	}
	else
	{
		m_sScanRequest.sScanOptions.AutoQuarantine = bAutoQuarantine;
	}
	wcscpy_s(m_sScanRequest.strValue, csDrive);
	wcscpy_s(m_sScanRequest.szGUID, theApp.m_csGUID);

	m_bScanningProcess = true;

	CRegistry	objReg;
	CString csTemp;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("TempFolderPath"), csTemp, HKEY_LOCAL_MACHINE);
	if (csTemp.GetLength() == 0)
	{
		WCHAR szBuff[1024] = { 0 };
		GetTempPath(1024, szBuff);
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("TempFolderPath"), szBuff, HKEY_LOCAL_MACHINE);
	}
	else if (csTemp.Find(_T("WINDOWS")) != -1 || csTemp.Find(_T("Windows")) != -1
		|| csTemp.Find(_T("windows")) != -1)
	{
		objReg.DeleteValue(CSystemInfo::m_csProductRegKey, _T("TempFolderPath"), HKEY_LOCAL_MACHINE);
		WCHAR szBuff[1024] = { 0 };
		GetTempPath(1024, szBuff);
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("TempFolderPath"), szBuff, HKEY_LOCAL_MACHINE);
	}
	/*csTemp = L"";
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("TempIEPath"), csTemp, HKEY_LOCAL_MACHINE);
	if(csTemp.GetLength() == 0)
	{*/
	TCHAR szPath[MAX_PATH] = { 0 };
	if (SUCCEEDED(SHGetFolderPath(0, CSIDL_INTERNET_CACHE, NULL, 0, szPath)))
	{
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("TempIEPath"), szPath, HKEY_LOCAL_MACHINE);
	}
	//}
	csTemp = _T("");
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("USERPROFILE"), csTemp, HKEY_LOCAL_MACHINE);
	if (csTemp.GetLength() == 0)
	{
		WCHAR szBuff[1024] = { 0 };
		SHGetFolderPath(0, CSIDL_PROFILE, 0, 0, szBuff);
		if (szBuff[0])
		{
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("USERPROFILE"), szBuff, HKEY_LOCAL_MACHINE);
		}
	}

	csTemp = _T("");
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("APPDATA"), csTemp, HKEY_LOCAL_MACHINE);
	if (csTemp.GetLength() == 0)
	{
		WCHAR szBuff[1024] = { 0 };
		SHGetFolderPath(0, CSIDL_APPDATA, 0, 0, szBuff);
		if (szBuff[0])
		{
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("APPDATA"), szBuff, HKEY_LOCAL_MACHINE);
		}
	}

	csTemp = _T("");
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("APPDATA_LOCAL"), csTemp, HKEY_LOCAL_MACHINE);
	if (csTemp.GetLength() == 0)
	{
		WCHAR szBuff[1024] = { 0 };
		SHGetFolderPath(0, CSIDL_LOCAL_APPDATA, 0, 0, szBuff);
		if (szBuff[0])
		{
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("APPDATA_LOCAL"), szBuff, HKEY_LOCAL_MACHINE);
		}
	}

	////7-11-22: Start the Scanner here via the WatchDog Service
	//if (m_bCriticalScan)
	//{
	//	AfxBeginThread(GetCPUUsageThread, this);
	//}

	if (!CanTheScannerGoAhead())
	{
		return;
	}

	m_bCriticalScan = false;
	AfxBeginThread(CScanProcess::WDExecutionThread, this);
	
}

/*--------------------------------------------------------------------------------------
Function       : CheckAndExitScanner
In Parameters  : void
Out Parameters : void
Description    : Exit scanner if running
--------------------------------------------------------------------------------------*/
void CScanProcess::CheckAndExitScanner(void)
{
	if (theApp.m_bScannerRunning == true)
	{
		AddLogEntry(_T(">>> Sending request to the AuScanner to Exit..."), 0, 0, true, LOG_DEBUG);

		CMaxCommunicator objMaxCommunicator(theApp.m_csScannerID, true);
		MAX_PIPE_DATA sPipeData = { 0 };
		sPipeData.eMessageInfo = Exit_Scanner;
		objMaxCommunicator.SendData(&sPipeData, sizeof(MAX_PIPE_DATA));

		theApp.m_bScannerRunning = false;
	}
}

/*--------------------------------------------------------------------------------------
Function       : GetLatestOSName
In Parameters  : CString& csOsVersion
Out Parameters : bool
Description    : Get OS Product name
--------------------------------------------------------------------------------------*/
bool CScanProcess::GetLatestOSName(CString& csOsVersion)
{
	//CString		csOsVersion;
	CRegistry	objRegistry;
	CString		csAPPPath;

	//HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
	objRegistry.Get(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", _T("ProductName"), csAPPPath, HKEY_LOCAL_MACHINE);

	//CSystemInfo::m_strAppPath
	if (CSystemInfo::m_bIsOSX64)
	{
		csOsVersion.Format(L"%s 64 bit", csAPPPath);
	}
	else
	{
		csOsVersion.Format(L"%s 32 bit", csAPPPath);
	}

	return true;

}

/*--------------------------------------------------------------------------------------
Function       : CanTheScannerGoAhead
In Parameters  : void
Out Parameters : bool
Description    : To check is some critical process is pending before scanner start
--------------------------------------------------------------------------------------*/
bool CScanProcess::CanTheScannerGoAhead()
{
	bool bGoAhead = true;

	//if (m_bRestartEntryFound)
	//{
	//	////////OnTimer(TIMER_PAUSE_HANDLER);		//7-11-22: Pause scanner and all the status in OnTimer	
	//	//m_stScanProgressGif.Stop();
	//	//m_stScanProgressGif.UnLoad();
	//	/*CYesNoMsgBoxDlg objMessageBoxDlg(this);													//7-11-22: Send Message to UI to notify critical threats found. Restart the PC now to clean these threats			
	//	objMessageBoxDlg.m_csMessage = theApp.m_pResMgr->GetString(_T("IDS_CRITICAL_THREATS_FOUND"));
	//	bGoAhead = IDCANCEL == objMessageBoxDlg.DoModal();
	//	if (bGoAhead)
	//	{
	//		m_stPercentageLabel.ShowWindow(SW_SHOW);
	//		SetTimer(TIMER_SCAN_STATUS, 100, 0);
	//		m_tsScanPauseResumeElapsedTime += ((CTime::GetCurrentTime() - m_tsScanPauseResumeTime));
	//	}*/
	//}

	//if (false == bGoAhead)
	//{
	//	if (!theApp.m_bAutoQuarantine)
	//	{
	//		if (m_pQuarantineThread && m_pQuarantineThread->m_hThread)
	//		{
	//			WaitForSingleObject(m_pQuarantineThread->m_hThread, INFINITE);
	//		}
	//	}

	//	CEnumProcess objEnumProcess;
	//	objEnumProcess.RebootSystem(0);
	//}

	// if stop button clciked, dont return true - either restart(when entry foud) or return false
	if (m_bStopScanning)
	{
		bGoAhead = false;
	}

	m_chScanFromUIStage = bGoAhead ? 2 : 0;
	return bGoAhead;
}
/*--------------------------------------------------------------------------------------
Function       : WDExecutionThread
In Parameters  : LPVOID lpParam
Out Parameters : UINT
Description    : To start scanner from service
--------------------------------------------------------------------------------------*/
UINT CScanProcess::WDExecutionThread(LPVOID lParam)
{
	theApp.AddExcludeEntriesDB();
	CScanProcess* pObj = (CScanProcess*)lParam;
	if (!pObj)
	{
		return 1;
	}
	for (int iCtr = 0; iCtr < 15; iCtr++)
	{
		AddLogEntry(L"Asking watchdog to launch AuScanner!");
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, true);
		objMaxCommunicator.SendData(&pObj->m_sScanRequest, sizeof(MAX_PIPE_DATA_REG));
		objMaxCommunicator.ReadData(&pObj->m_sScanRequest, sizeof(MAX_PIPE_DATA_REG));
		if (pObj->m_sScanRequest.eMessageInfo == Scanner_Is_Ready)
		{
			AddLogEntry(L"Successfully launched AuScanner!");
			theApp.m_bScannerRunning = true;
			break;
		}
		else
		{
			AddLogEntry(L"Failed communication with watchdog! Going to Retry!");
			Sleep(1000);
		}
	}
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : OnScanDataReceivedCallBack
In Parameters  : LPVOID lpParam,
Out Parameters : void
Description    : Call back for data recive from backend communicator.
--------------------------------------------------------------------------------------*/
void CScanProcess::OnScanDataReceivedCallBack(LPVOID lpParam)
{
	__try
	{
		LPMAX_PIPE_DATA sMaxPipeData = (MAX_PIPE_DATA*)lpParam;
		if (sMaxPipeData)
		{
			if (sMaxPipeData->eMessageInfo == Register_WD_PID)
			{
				OutputDebugString(L"Got the Register_WD_PID Event");
				if (!theApp.m_bRegWDThreadRunning)
				{
					AfxBeginThread(theApp.WDConnectionThread, &theApp);
				}
				return;
			}
			if (sMaxPipeData->eMessageInfo == DiskFullMessage)
			{
				m_bQFullDiskError = true;
				return;
			}
			if (sMaxPipeData->eMessageInfo == Pause_Scanning)
			{
				if (theApp.m_bScannerRunning)
				{
					/*CSDUINew* pObjUI = (CSDUINew*)theApp.m_pMainWnd;*/
					//pObjUI->OnBnClickedButtonScanResumePause();
					sMaxPipeData->eMessageInfo = Scanner_Paused;
				}
				else
				{
					sMaxPipeData->eMessageInfo = Scanner_NotRunning;
				}
				// Send the same Message back to the System Tray
				theApp.m_pObjMaxCommunicatorServer->SendResponse(sMaxPipeData);
				return;
			}
			if (sMaxPipeData->eMessageInfo == Finished_LiveUpdate)
			{
				/*CSDUINew* pObjUI = (CSDUINew*)theApp.m_pMainWnd;			*/
				return;
			}

			if (sMaxPipeData->eMessageInfo == WD_ShutdownSD)
			{
				theApp.ShutdownScannersAndCloseUI();
			}

			if (sMaxPipeData->sScanOptions.RegFixOptionScan == 1)
			{
				//CRegistryFix::OnCallBackDataReceived(sMaxPipeData);
			}
			else
			{
				theApp.m_objScanProcess.HandleScannerData(lpParam);
			}
		}
	}
	__except (CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Scan CallBack Mode")))
	{

	}
}

/*--------------------------------------------------------------------------------------
Function       : HandleScannerData
In Parameters  : LPVOID lpParam,
Out Parameters : void
Description    : Prepared scanned data for display and update status bar.
--------------------------------------------------------------------------------------*/
void CScanProcess::HandleScannerData(LPVOID lpParam)
{
	MAX_PIPE_DATA* sMaxPipeData = (MAX_PIPE_DATA*)lpParam;
	if (sMaxPipeData->eMessageInfo == SendGuid)
	{
		theApp.m_csScannerID = sMaxPipeData->strValue;
		return;
	}
	else if (sMaxPipeData->eMessageInfo < SD_Message_Info_TYPE_REG)// Its a File system Message
	{
		ShowScannedData(*sMaxPipeData);
	}
	else if (sMaxPipeData->eMessageInfo < SD_Message_Info_TYPE_INFO)// Its a Registry Message
	{
		MAX_PIPE_DATA_REG* sMaxPipeData_Reg = (MAX_PIPE_DATA_REG*)lpParam;
		ShowScannedData(*sMaxPipeData_Reg);
	}
	else if (sMaxPipeData->eMessageInfo < SD_Message_Info_TYPE_ADMIN)// Its a Information Message
	{
		LPTSTR lpScanText = NULL;

		//if (m_objScanTextLookup.SearchItem(sMaxPipeData->eMessageInfo, &lpScanText))			//UI: Send data enum to WPF to load string
		//{
		//	//m_stScanStatusBar.SetWindowText(lpScanText);
		//}
		SetPercentage(m_iPercentage);
		if (theApp.m_pSendMsgUltraUI != NULL)
		{
			theApp.m_objScanStatusData.iMessageId = sMaxPipeData->eMessageInfo;
			theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
		}
	}

	if (m_bStopScanning)
	{
		//m_stScanStatusBar.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_SCANSTOPPRDMSG_EN")));		//UI: Stop Scanning status to WPF
		if (theApp.m_pSendMsgUltraUI != NULL)
		{
			theApp.m_objScanStatusData.iMessageId = Stop_Scanning;
			theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
		}
	}

	// Check if Special Spyware
	if (false == m_bSplSpywareFound)
	{
		CheckIfSpecialSpyware((SD_Message_Info)sMaxPipeData->eMessageInfo);
	}

	if (sMaxPipeData->eMessageInfo >= Starting_Process_Scanner)
	{
		if (2 == m_chScanFromUIStage)
		{
			m_chScanFromUIStage = 3;
		}
	}

	if (sMaxPipeData->eMessageInfo == Starting_Rootkit_Process_Scanner ||
		sMaxPipeData->eMessageInfo == Starting_Rootkit_FileSystem_Scanner ||
		sMaxPipeData->eMessageInfo == Starting_Rootkit_Registry_Scanner ||
		sMaxPipeData->eMessageInfo == Starting_Process_Scanner ||
		sMaxPipeData->eMessageInfo == Starting_Signature_And_Virus_Scanner ||
		sMaxPipeData->eMessageInfo == Starting_Signature_Scanner)
	{
		//Handle Pause Resume Stop button enabling!
		//ShowPauseResumeStopButtons(true, false, true, false);
	}

	if (Finished_Scanning == sMaxPipeData->eMessageInfo)					//UI: Scanning Finished
	{
		theApp.m_objThreatInfo.RemoveAll();
		m_chScanFromUIStage = 0;
		m_objScannerDB.WriteCountInINI();
		//Save the Scanning Results  after the scan is finished.
		m_objScannerDB.SaveScanDBFile();
		m_objScannerDB.UnLoadScanDB();
		if (m_bAppClosing)
		{
			CheckAndExitScanner();
			PostQuitMessage(0);
			return;
		}
		//m_stScanProgressGif.ShowHundredPercent();							//UI: Set UI percentage 100%
		if (!m_bStopScanning)
			m_iPercentage = 100;

		if (theApp.m_bAutoQuarantine)
		{
			if (m_bSplSpywareFound)
			{
				/***********************************/
				// Special Spyware Handling here!
				/***********************************/
				CMaxCommunicator objMaxCommunicator(theApp.m_csScannerID);
				MAX_PIPE_DATA pPipeData = { 0 };
				pPipeData.eMessageInfo = Perform_SplQuarantine;
				objMaxCommunicator.SendData(&pPipeData, sizeof(MAX_PIPE_DATA));
				// Set to FALSE so that this message is not sent to the scanner again
				m_bSplSpywareFound = false;

				//Handle Later
				//RootkitQuarantineHandling();
				//ScapeGoatQuarantineHandling();
			}
			DeleteTemporaryAndInternetFiles();
		}

		if (m_bRestartRequired)
		{
			OnScanningFinishedPostMessage(0, 0);
			//m_stScanProgressGif.Stop();
			//m_stScanProgressGif.UnLoad();
			//m_stPercentageLabel.ShowWindow(SW_HIDE);						//UI: Hide Percentage label
			HandleQuarantineRestart(m_dwSpywareFound - m_dwQuarantineFailedCount/*sMaxPipeData->ulSpyNameID*/, m_dwSpywareFound);
			m_bIsFullScanRequired = false;
		}
		if (m_dwSpywareFound == 0)
		{
			// This handles the case of Excluded entries
			// i.e Scanner finds entries, reports to the UI,
			// But since it is excluded, UI doesnot show the entries in the Tree
			// and hence, 'm_dwSpywareFound' is ZERO.
			// Ask the Scanner to Exit
			//CheckAndExitScanner();

			// Set the Scanner Variables to FALSE
			//theApp.m_bScannerRunning = false;
			m_bScanningProcess = false;
			OnScanningFinishedPostMessage(0, 0);
			if (m_bUIClose)
			{
				//PostMessage(WM_QUIT);
				return;
			}
			else
				return;
		}
		m_bScanningProcess = false;
		OnScanningFinishedPostMessage(0, 0);
	}

	if (Report_Scanner_Failure == sMaxPipeData->eMessageInfo)
	{
		AddLogEntry(_T(">>> Scanner Crashed...Report_Scanner_Failure"));
		// Reset the UI, delete any found entries from the UI Tree Control
		//m_stScanProgressGif.ShowHundredPercent();						//UI: Percentage 100%
		theApp.m_bScannerRunning = false;
		m_bScanningProcess = false;
		m_dwSpywareFound = 0;
		//theApp.m_treeList->DeleteAllItems();							//UI: Empty tree list
		//PostMessage(WM_USER_HIDE_TRIAL_MESSAGE, NULL, NULL);
		OnScanningFinishedPostMessage(0, 0);
		return;
	}
	if (m_bUIClose)
	{
		CheckAndExitScanner();
		//CloseUI();
	}
}

/*--------------------------------------------------------------------------------------
Function       : ShowScannedData
In Parameters  : MAX_PIPE_DATA_REG& sMaxPipeDataReg,
Out Parameters : void
Description    : Prepare data to dispaly.
--------------------------------------------------------------------------------------*/
void CScanProcess::ShowScannedData(MAX_PIPE_DATA_REG& sMaxPipeDataReg)
{
	const int SIZEOFBUFFER = 1024 * 4;
	TCHAR strValue[SIZEOFBUFFER] = { 0 };
	theApp.PrepareValueForDispaly(sMaxPipeDataReg, strValue, SIZEOFBUFFER);

	bool bUseSpyID = true;
	CString csSpyName;
	CString csHelpInfo;
	BYTE bThreatIndex = 0;
	
	if (((sMaxPipeDataReg.ulSpyNameID == 0) || (_tcslen(sMaxPipeDataReg.strValue) != 0))
		&& ((sMaxPipeDataReg.eMessageInfo == Virus_Process) || (sMaxPipeDataReg.eMessageInfo == Virus_File)
			|| (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair_Report)
			|| (sMaxPipeDataReg.eMessageInfo == Virus_Process_Report) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Report)))
	{
		bUseSpyID = false;
		csSpyName = sMaxPipeDataReg.strValue;
		bThreatIndex = -1;
		csHelpInfo = _T("Threat");
	}
	else
	{
		CString strKeyValue = sMaxPipeDataReg.strValue;
		if (!strKeyValue.IsEmpty())
		{
			strKeyValue += _T(".");
		}
		if (theApp.GetThreatInfo(sMaxPipeDataReg.ulSpyNameID, csSpyName, bThreatIndex, csHelpInfo, strKeyValue, sMaxPipeDataReg.eMessageInfo) == false)
		{
			bThreatIndex = -1;
		}
	}
	//HTREEITEM hItem;
	UScanUIReport objUScanUIReport = { 0 };
	if (theApp.m_bAutoQuarantine)
	{
		if (sMaxPipeDataReg.eStatus == eStatus_Detected)
		{
			m_bRestartRequired = true;
			m_dwQuarantineFailedCount++;
		}
		////CString csStatus = _T("Cleaned or Repaired");//CheckForStatus(sMaxPipeDataReg.eStatus, (SD_Message_Info)sMaxPipeDataReg.eMessageInfo);	//UI Threat status: Cleaned, Repaired
		
		/*hItem = PopulateIntoTree(csSpyName,																			//UI Report data
			strValue,	
			(SD_Message_Info)sMaxPipeDataReg.eMessageInfo,
			bThreatIndex,
			csHelpInfo,
			sMaxPipeDataReg.ulSpyNameID,
			csStatus, bUseSpyID);*/
		
		UpdateDetectionStatus(0);
		
		if (theApp.m_pSendDetectionToUltraUI != NULL)
		{
			objUScanUIReport.dwIndex = 0;// From New Memory storage code
			objUScanUIReport.iActionStatus = CheckForStatus(sMaxPipeDataReg.eStatus, (SD_Message_Info)sMaxPipeDataReg.eMessageInfo);
			objUScanUIReport.iMessageId = sMaxPipeDataReg.eMessageInfo;
			_tcscpy_s(objUScanUIReport.szPath, strValue);
			_tcscpy_s(objUScanUIReport.szSpyName, csSpyName);
			theApp.m_pSendDetectionToUltraUI(objUScanUIReport);
		}
	}
	else
	{
		/*hItem = PopulateIntoTree(csSpyName,																			//UI Report Data
			strValue,
			(SD_Message_Info)sMaxPipeDataReg.eMessageInfo,
			bThreatIndex,
			csHelpInfo,
			sMaxPipeDataReg.ulSpyNameID,
			L"", bUseSpyID);*/
		

		UpdateDetectionStatus(1);
		if (theApp.m_pSendDetectionToUltraUI != NULL)
		{
			objUScanUIReport.dwIndex = m_objReport.AddRecordtoReportQueue(&sMaxPipeDataReg, 1);// From New Memory storage code
			objUScanUIReport.iActionStatus = ScanActionStatus::None;
			objUScanUIReport.iMessageId = sMaxPipeDataReg.eMessageInfo;
			_tcscpy_s(objUScanUIReport.szPath, strValue);
			_tcscpy_s(objUScanUIReport.szSpyName, csSpyName);
			theApp.m_pSendDetectionToUltraUI(objUScanUIReport);
		}
		
	}
	/*if (hItem)																										//UI Data structure attached to perform operation 
	{
		theApp.m_treeList->AddStructure(hItem, sMaxPipeDataReg);
	}*/
}

/*--------------------------------------------------------------------------------------
Function       : ShowScannedData
In Parameters  : MAX_PIPE_DATA& sMaxPipeData
Out Parameters : void
Description    : Prepare data to dispaly.
--------------------------------------------------------------------------------------*/
void CScanProcess::ShowScannedData(MAX_PIPE_DATA& sMaxPipeData)
{
	//if(m_bStatus)
	{
		if (sMaxPipeData.eMessageInfo == FilePath_Report)
		{
			//PathSetDlgItemPath(this->m_hWnd, IDC_STATIC_STATUS_BAR_LABEL, sMaxPipeData.strValue);						//UI: Status file path update
			//m_stScanStatusBar.SetWindowText(sMaxPipeData.strValue);
			if (theApp.m_pSendMsgUltraUI != NULL)
			{
				theApp.m_objScanStatusData.iMessageId = sMaxPipeData.eMessageInfo;
				_tcscpy_s(theApp.m_objScanStatusData.szData, sMaxPipeData.strValue);
				theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
			}
			return;
		}
		if (sMaxPipeData.eMessageInfo == Status_Bar_File_Report)
		{
			int iPercentage = _wtoi(sMaxPipeData.strFreshFile);
			SetPercentage(iPercentage);
			if (sMaxPipeData.ulSpyNameID > 0)
			{
				if (m_dwFilesScanned != sMaxPipeData.ulSpyNameID)
				{
					m_dwFilesScanned = sMaxPipeData.ulSpyNameID;
					//IncreamentFileScannedCnt();																		//UI: Status Scanned file counter
				}

				//m_dwFilesScanned = sMaxPipeData.ulSpyNameID;
				/*
				CString csStr;
				csStr.Format(L"%s                         ",theApp.m_pResMgr->GetString(_T("IDS_ADD_COLON")));
				m_stFilesScannedCount.SetWindowText(csStr);
				csStr.Format(L"%s%d",theApp.m_pResMgr->GetString(_T("IDS_ADD_COLON")),m_dwFilesScanned);
				m_stFilesScannedCount.SetWindowText(csStr);
				*/
				
			}
			if (theApp.m_pSendMsgUltraUI != NULL)
			{
				theApp.m_objScanStatusData.iMessageId = sMaxPipeData.eMessageInfo;
				theApp.m_objScanStatusData.iPercentage = m_iPercentage;
				theApp.m_objScanStatusData.dwFilesCount = m_dwFilesScanned;
				theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
			}
			if (!m_bPauseScanning)
			{//PathSetDlgItemPath(this->m_hWnd, IDC_STATIC_STATUS_BAR_LABEL, sMaxPipeData.strValue);					//UI: Update file path
				if (theApp.m_pSendMsgUltraUI != NULL)
				{
					theApp.m_objScanStatusData.iMessageId = sMaxPipeData.eMessageInfo;
					_tcscpy_s(theApp.m_objScanStatusData.szData, sMaxPipeData.strValue);
					theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
				}
			}
				
			return;
		}
	}

	bool bUseSpyID = true;
	CString csSpyName;
	CString csHelpInfo;
	CString csScanStatus = _T("Scanning for");
	BYTE bThreatIndex = 0;
	CString strKeyValue = sMaxPipeData.strFreshFile;
	if (!strKeyValue.IsEmpty())
	{
		strKeyValue += _T(".");
	}
	if (theApp.GetThreatInfo(sMaxPipeData.ulSpyNameID, csSpyName, bThreatIndex, csHelpInfo, strKeyValue, sMaxPipeData.eMessageInfo) == false)
	{
		bThreatIndex = -1;
	}
	/*if (m_bStatus)																									//UI: SplSpy_Report
	{
		if (sMaxPipeData.eMessageInfo == SplSpy_Report)
		{
			csScanStatus = csScanStatus + _T(" ") + csSpyName;
			m_stScanStatusBar.SetWindowText(csScanStatus);
			return;
		}
	}*/
	//HTREEITEM hItem = NULL;

	UScanUIReport objUScanUIReport = { 0 };
	if (theApp.m_bAutoQuarantine)
	{
		if (sMaxPipeData.eStatus == eStatus_Detected)
		{
			m_bRestartRequired = true;
			m_dwQuarantineFailedCount++;
		}
		/*CString csStatus = CheckForStatus(sMaxPipeData.eStatus, (SD_Message_Info)sMaxPipeData.eMessageInfo);							//UI Threat status: Cleaned, Repaired
		hItem = PopulateIntoTree(csSpyName,																								//UI Report data
			sMaxPipeData.strValue,
			(SD_Message_Info)sMaxPipeData.eMessageInfo,
			bThreatIndex,
			csHelpInfo,
			sMaxPipeData.ulSpyNameID,
			csStatus, bUseSpyID);*/
		
		UpdateDetectionStatus(0);
		
		if (theApp.m_pSendDetectionToUltraUI != NULL)
		{
			objUScanUIReport.dwIndex = 0;// From New Memory storage code
			objUScanUIReport.iActionStatus = CheckForStatus(sMaxPipeData.eStatus, (SD_Message_Info)sMaxPipeData.eMessageInfo);
			objUScanUIReport.iMessageId = sMaxPipeData.eMessageInfo;
			_tcscpy_s(objUScanUIReport.szPath, sMaxPipeData.strValue);
			_tcscpy_s(objUScanUIReport.szSpyName, csSpyName);
			theApp.m_pSendDetectionToUltraUI(objUScanUIReport);
		}
	}
	else
	{
		/*hItem = PopulateIntoTree(csSpyName,																							//UI Report data
			sMaxPipeData.strValue,
			(SD_Message_Info)sMaxPipeData.eMessageInfo,
			bThreatIndex,
			csHelpInfo,
			sMaxPipeData.ulSpyNameID,
			L"", bUseSpyID);*/
		
		UpdateDetectionStatus(1);

		if (theApp.m_pSendDetectionToUltraUI != NULL)
		{
			objUScanUIReport.dwIndex = m_objReport.AddRecordtoReportQueue(&sMaxPipeData, 0);// From New Memory storage code
			objUScanUIReport.iActionStatus = ScanActionStatus::None;
			objUScanUIReport.iMessageId = sMaxPipeData.eMessageInfo;
			_tcscpy_s(objUScanUIReport.szPath, sMaxPipeData.strValue);
			_tcscpy_s(objUScanUIReport.szSpyName, csSpyName);
			theApp.m_pSendDetectionToUltraUI(objUScanUIReport);
		}
		
	}
	/*if (hItem)																														//UI Data structure attached to perform operation 
	{
		theApp.m_treeList->AddStructure(hItem, sMaxPipeData);
	}*/
}

/*--------------------------------------------------------------------------------------
Function       : CheckIfSpecialSpyware
In Parameters  : SD_Message_Info eMessageInfo,
Out Parameters : void
Description    : Check given messageinfo typa is special scan or not.
--------------------------------------------------------------------------------------*/
void CScanProcess::CheckIfSpecialSpyware(SD_Message_Info eMessageInfo)
{
	if (((eMessageInfo >= Special_Process) && ((eMessageInfo <= Special_Folder_Report)))
		|| ((eMessageInfo >= Special_RegKey) && ((eMessageInfo <= Special_RegFix_Report))))
	{
		m_bSplSpywareFound = true;
	}
}

/*--------------------------------------------------------------------------------------
Function       : DeleteTemporaryAndInternetFiles
In Parameters  : void,
Out Parameters : void
Description    : Delete temp and temporary internet files.
--------------------------------------------------------------------------------------*/
void CScanProcess::DeleteTemporaryAndInternetFiles(void)
{
	if (m_bQuarantineStopped == true)
	{
		return;
	}

	CRegistry objReg;
	DWORD dwTempIE = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, CLEANTEMPIEKEY, dwTempIE, HKEY_LOCAL_MACHINE);
	if (dwTempIE == 1)
	{
		AddLogEntry(_T(">>> Deleting Temp Internet Files..."), 0, 0, true, LOG_DEBUG);
		//m_stScanStatusBar.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_DELIEFILESMSG_EN")));					//UI: Removing files from Temporary Internet Files Folder...
		if (theApp.m_pSendMsgUltraUI != NULL)
		{
			theApp.m_objScanStatusData.iMessageId = Delete_TempFile;
			theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
		}
		DeleteCache();
	}
}
/*-------------------------------------------------------------------------------------
Function		: DeleteCache
In Parameters	: -
Out	Parameters	: void
Purpose			: To delete internet history
--------------------------------------------------------------------------------------*/
void CScanProcess::DeleteCache()
{
	CDBPathExpander oDBPathExpander;
	CStringArray arrAllTempIEPath;
	CString csTempIEFolder = _T("");
	oDBPathExpander.GetCompleteUsersPath(arrAllTempIEPath, true);
	for (int iIndex = 0; iIndex < arrAllTempIEPath.GetCount(); iIndex++)
	{
		csTempIEFolder = arrAllTempIEPath.GetAt(iIndex);
		//OutputDebugString(_T("Deleting Temp IE Contents from Folder: ") + csTempIEFolder);
		CDirectoryManager oDirectoryManager;
		oDirectoryManager.MaxDeleteDirectoryContents(csTempIEFolder, true);
	}
}
/*--------------------------------------------------------------------------------------
Function       : HandleQuarantineRestart
In Parameters  : ULONG ulQuarantinedCount, ULONG ulTotalCount,
Out Parameters : void
Description    : If quarantine required restart, ask user for restart, when user pressed on yes reboot the system.
--------------------------------------------------------------------------------------*/
void CScanProcess::HandleQuarantineRestart(ULONG ulQuarantinedCount, ULONG ulTotalCount)
{
	if (m_bAppClosing)
		return;
	/****************************************************/
	// In case where the remaining spyware count is ZERO,
	// we just need to show the Restart Message.
	/****************************************************/
	CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
	if (!PathFileExists(strINIPath))
	{
		/*CSmallMsgBox objMessageBox(this);												//UI: Spyware cleaned message with count
		objMessageBox.m_csMessage.Format(_T("%lu %s"), ulTotalCount, static_cast<LPCTSTR>(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_SPYQUASUCMSG_EN"))));
		objMessageBox.DoModal();*/
		return;
	}
	int iRet = 0;
	if ((ulTotalCount - ulQuarantinedCount) > 0)
	{
		//CYesNoMsgBoxDlg oYesNo(this);																	//UI: To clean spyware restart PC.
		//oYesNo.m_csMessage.Format(_T("%lu %s.\r\n\r\n%s"),
		//	ulQuarantinedCount,
		//	static_cast<LPCTSTR>(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_SPYQUASUCMSG_EN"))),		//UI: Spyware cleaned
		//	static_cast<LPCTSTR>(theApp.m_pResMgr->GetString(_T("IDS_QUARANTINE_REBOOT"))));			//UI: To clean the remaining %S threat, PC reboot is required. \nClick on 'OK' to restart your PC now.

		/*CString csCount;																				//UI: Counter calculate
		csCount.Format(_T("%d"), ulTotalCount - ulQuarantinedCount);
		oYesNo.m_csMessage.Replace(_T("%S"), csCount);
		iRet = static_cast<int>(oYesNo.DoModal());*/
	}
	else
	{
		/*CYesNoMsgBoxDlg oYesNo(this);																	//UI: Required Product Name and restart message
		oYesNo.m_csMessage.Format(_T("%s %s"),															//UI: needs to restart your PC to completely remove the spyware. \n\nClick on 'OK' to restart your PC now or 'Cancel' to restart later.
			(LPCTSTR)CSystemInfo::m_csProductName,
			static_cast<LPCTSTR>(theApp.m_pResMgr->GetString(_T("IDS_RESTART_MSG1_EN"))));
		iRet = static_cast<int>(oYesNo.DoModal());*/
	}
	
	//if (iRet == IDOK)																					//UI: If reply ok Restart machine, get this data from UI and perform operations
	//{
	//	AddLogEntry(_T(">>> Restarting System after Quarantine..."), 0, 0, true, LOG_DEBUG);
	//	// set key for full scan on restart
	//	CRegistry objRegistry;
	//	CString csAPPPath;
	//	DWORD dwValue = 0;
	//	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("AutoScan"), dwValue, HKEY_LOCAL_MACHINE);
	//	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("AppPath"), csAPPPath, HKEY_LOCAL_MACHINE);
	//	//if(!dwValue)
	//	{
	//		objRegistry.Set(RUN_REG_PATH, _T("FULLSCAN"), csAPPPath + _T(" -FULLSCAN"), HKEY_LOCAL_MACHINE);
	//	}
	//	
	//	//CEnumProcess objEnumProc;
	//	//objEnumProc.RebootSystem();
	//}
	//else
	{
		m_dwQuarantineFailedCount = 0;
	}
	if (theApp.m_pSendMsgUltraUI != NULL)
	{
		theApp.m_objScanStatusData.iMessageId = Restart_Required;
		theApp.m_objScanStatusData.dwThreatCount = m_dwSpywareFound;
		theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
	}
}

/*-------------------------------------------------------------------------------------
Function		: OnScanningFinishedPostMessage
In Parameters	: WPARAM, LPARAM
Out	Parameters	: void
Purpose			: To perform the post scan process
--------------------------------------------------------------------------------------*/
void CScanProcess::OnScanningFinishedPostMessage(WPARAM, LPARAM)
{
	//HandleCount();																		//UI: If required to track threat counts to send it to server

	CRegistry objReg;
	time_t tim = time(NULL);
	/*objReg.Set(CUserTrackingSystem::m_csTrackingKey, TRACKER_LAST_SCAN_CHECKED, tim, HKEY_LOCAL_MACHINE);*/		//UI: If required to track threat counts to send it to server

	if (m_bAppClosing)
		return;

	if (!m_bStopScanning)
		m_iPercentage = 100;

	m_bScanningProcess = false;

	//Store stats of scan
	//time_t tim = time(NULL);
	CString csMessage;
	csMessage.Format(_T("%ld"), tim);
	WritePrivateProfileString(_T("SCAN_STATUS"), _T("TIME"), csMessage, CSystemInfo::m_strSettingPath + _T("ScanStat.ini"));
	csMessage = _T("");
	csMessage.Format(_T("%ld"), m_dwSpywareFound);
	WritePrivateProfileString(_T("SCAN_STATUS"), _T("THREATS_FOUND"), csMessage, CSystemInfo::m_strSettingPath + _T("ScanStat.ini"));
	/*csMessage = _T("");
	csMessage.Format(_T("%ld"), m_dwSpywareFound);
	WritePrivateProfileString(_T("SCAN_STATUS"), _T("THREATS_CLEAN"), csMessage, CSystemInfo::m_strSettingPath + _T("ScanStat.ini"));
	*/csMessage = _T("");
	csMessage.Format(_T("%d"), m_iPercentage);
	WritePrivateProfileString(_T("SCAN_STATUS"), _T("PERCENTAGE"), csMessage, CSystemInfo::m_strSettingPath + _T("ScanStat.ini"));
	csMessage = _T("");
	csMessage.Format(_T("%d"), m_iShowScanStatus);
	WritePrivateProfileString(_T("SCAN_STATUS"), _T("SCAN_TYPE"), csMessage, CSystemInfo::m_strSettingPath + _T("ScanStat.ini"));
	csMessage = _T("");
	csMessage.Format(_T("%ld"), m_dwFilesScanned);
	WritePrivateProfileString(_T("SCAN_STATUS"), _T("FILES_SCAN"), csMessage, CSystemInfo::m_strSettingPath + _T("ScanStat.ini"));

	m_bScanInProgress = false;
	
	CString csData;
	csData.Format(L"%d%%  ", m_iPercentage);
	//m_stPercentageLabel.SetWindowText(csData);							//UI: Percentage Update in UI;
	
	
	CString csDevDmp = CSystemInfo::m_strAppPath + _T("DevDMP");
	CDirectoryManager objDirectoryManager;
	objDirectoryManager.MaxDeleteDirectory(csDevDmp, true);
	
	
	AddLogEntry(_T(">>> Scanning process completed..."), 0, 0, true, LOG_DEBUG);
	/*CString csLabel;
	csLabel.Format(_T("%s%d"), theApp.m_pResMgr->GetString(_T("IDS_ADD_COLON")), m_dwSpywareFound);		//UI: Threat found counter
	m_stThreatsFoundCount.SetWindowText(csLabel);*/

	/*if (m_iScanType == ENUM_SCAN_CUSTOM)																//UI: In custom scan reset path edit box 
	{
		SetTextRichEditCtrl(_T(""));
	}*/
	if (theApp.m_pSendMsgUltraUI != NULL)
	{
		theApp.m_objScanStatusData.iMessageId = Finished_Scanning;
		theApp.m_objScanStatusData.iPercentage = m_iPercentage;
		theApp.m_objScanStatusData.dwFilesCount = m_dwFilesScanned;
		theApp.m_objScanStatusData.dwThreatCount = m_dwSpywareFound;
		_tcscpy_s(theApp.m_objScanStatusData.szData, _T(""));
		theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
	}
	//Increment ItemsToClean Count
	//CUserTrackingSystem::AddCount(TRACKER_ITEMS_TO_CLEAN_COUNT, (DWORD)m_dwSpywareFound);

	////int iCntWorm = m_dwSpywareFound; //theApp.m_treeList->GetChildCount();													//UI: get total threat count
	DWORD dw = 1;

	////Handle Scan Buttons																				//UI Update button status
	//m_btnScanPauseResume.SetSkin(theApp.m_hResDLL, IDB_BITMAP_SCAN_RESUME_NORMAL, IDB_BITMAP_SCAN_RESUME_OVER, IDB_BITMAP_SCAN_RESUME_OVER, IDB_BITMAP_SCAN_RESUME_DISABLE, IDB_BITMAP_SCAN_RESUME_FOCUS, IDB_BITMAP_SCAN_PAUSE_MASK, 0, 0, 0);
	//m_btnScanPauseResume.SetTextColorA(theApp.INNER_UI_BUTTON_TEXT_RGB, theApp.INNER_UI_BUTTON_OVER_TEXT_RGB, theApp.INNER_UI_BUTTON_OVER_TEXT_RGB);
	//m_btnScanPauseResume.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_SCAN_RESUME_BTN")));
	//
	//m_btnScanPauseResume.EnableWindow(FALSE);
	//m_btnScanStop.EnableWindow(FALSE);
	//m_btnStartScan.EnableWindow(TRUE);

	//m_btnScanPauseResume.ShowWindow(SW_HIDE);
	//m_btnStartScan.ShowWindow(SW_SHOW);

	//m_stPercentageLabel.ShowWindow(SW_HIDE);

	objReg.Get(CSystemInfo::m_csProductRegKey, _T("FullScanDone"), dw, HKEY_LOCAL_MACHINE);
	if (0 == dw)//Not yet done Full Scan at least once.
	{
		if (m_iScanType == ENUM_SCAN_FULL)
		{
			dw = 1;
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("FullScanDone"), dw, HKEY_LOCAL_MACHINE);
		}
	}
	if (m_iScanType == ENUM_SCAN_FULL)
	{
		dw = 1;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("FullScanDoneML"), dw, HKEY_LOCAL_MACHINE);
	}
	
	CString csAddLogEntryStatus;
	if (m_dwSpywareFound != 0)
	{
		//PostMessage(WM_USER_SHOW_TRIAL_MESSAGE, NULL, NULL);
		//ShowScanReport(true);
		if (theApp.m_bAutoQuarantine)
		{
			//if (m_bStopScanning)																			//UI: update status
			//	m_csStatusText.Format(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_STOP_SPYCOUNTFOUNDMSG1_EN")), m_iCountSpywareFound/*iSpyCnt*/, iCntWorm);
			//else
			//	m_csStatusText.Format(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_SPYCOUNTFOUNDMSG1_EN")), m_iCountSpywareFound/*iSpyCnt*/, iCntWorm);

			/*m_btnClean.EnableWindow(FALSE);																//UI: disable enable button
			m_chkSelectAll.EnableWindow(FALSE);
			m_stSelectAll.EnableWindow(FALSE);*/

			csMessage = _T("");
			csMessage.Format(_T("%ld"), m_dwSpywareFound);
			WritePrivateProfileString(_T("SCAN_STATUS"), _T("THREATS_CLEAN"), csMessage, CSystemInfo::m_strSettingPath + _T("ScanStat.ini"));
			//ShowScanStatus(true);																			//UI: Update controls data
			//SelectScanType();
			
		}
		else
		{
			
			//ShowScanStatus(true);																			//UI: Update controls data
			//SelectScanType();
			

			//if (m_bStopScanning)																			//UI: update status
			//	m_csStatusText.Format(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_STOP_SPYCOUNTFOUNDMSG_EN")), m_iCountSpywareFound/*iSpyCnt*/, iCntWorm);
			//else
			//	m_csStatusText.Format(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_SPYCOUNTFOUNDMSG_EN")), m_iCountSpywareFound/*iSpyCnt*/, iCntWorm);
		}
		//csAddLogEntryStatus.Format(_T("%d Spyware found with %d associated."), m_iCountSpywareFound/*iSpyCnt*/, iCntWorm);			//UI: update status
		//m_stScanStatusBar.SetWindowText(csAddLogEntryStatus);
		//User should not be able to close when Log is getting created


	}
	else
	{
		//EnableAllControls(TRUE);																					//UI: Enable disable controls
		

		csMessage = _T("");
		csMessage.Format(_T("%ld"), 0);
		WritePrivateProfileString(_T("SCAN_STATUS"), _T("THREATS_CLEAN"), csMessage, CSystemInfo::m_strSettingPath + _T("ScanStat.ini"));

		//ShowScanStatus(true);																						//UI: Update controls data
		//SelectScanType();
		
		//m_csStatusText = theApp.m_pResMgr->GetString(_T("IDS_MAINUI_NOSPYFOUNDMSG_EN"));							//UI: update status
		bool bDisplayMessage = false;
		if (CSystemInfo::m_iVirusScanFlag)
		{
			if (theApp.m_iControlFlag == 0)
				bDisplayMessage = true;
		}
		
		if (bDisplayMessage && !m_bShutdown)
		{
			if (theApp.eScanStartedBy == ENUM_SC_SCHEDULED)
			{
				if (!m_bStopScanning)
				{
					if (OnCompleteScheduleScan())
					{
						theApp.eScanStartedBy = ENUM_SC_DO_NOT_RUN_SCAN;
						return;
					}
				}
			}
			else
			{
				int iRet;
				bool bDialogFlag = true;
				REGISTRATION_STATUS eStatus = theApp.GetRegisrationStatus();			//UI: registration checks
				{
					//UI: registration checks Unregister copy or expired
				}				
			}
		}
	}

	/*CString csElaspedTime;																			//UI: Total scan time message
	m_stElapsedTime.GetWindowTextW(csElaspedTime);
	m_csStatusText += _T(" ") + theApp.m_pResMgr->GetString(_T("IDS_TOTAL_SCAN_TIME")) + csElaspedTime;
	csAddLogEntryStatus += _T("  Total Scan Time:") + csElaspedTime;

	AddLogEntry(csAddLogEntryStatus);*/

	WriteSpywareCounts();

	if ((m_bShutdown && !m_dwSpywareFound) ||
		(m_bShutdown && m_dwSpywareFound && theApp.m_bAutoQuarantine)
		)
	{
		CRegistry objRegistry;
		objRegistry.Set(CSystemInfo::m_csProductRegKey, _T("IsScan"), 0, HKEY_LOCAL_MACHINE);

		CEnumProcess objEnumProcess;
		objEnumProcess.RebootSystem(1);
	}

	if (m_dwSpywareFound != 0)
	{
		/*m_chkSelectAll.SetCheck(1);																//UI: Select all threats
		m_bSelAll = CRadioCheckPos::CheckCheckBox(theApp.m_hResDLL, &m_chkSelectAll);*/
		bool bDisplayMessage = false;
		if (CSystemInfo::m_iVirusScanFlag)
		{
			if (theApp.m_iControlFlag == 0)
				bDisplayMessage = true;
		}
		
		//if(m_iControlFlag == 0)// make it >= if code is for unregister copy
		if (bDisplayMessage)
		{
			if (theApp.eScanStartedBy != ENUM_SC_CUSTOMSCAN)
			{
			/*	if (m_pQuarantineThread)											//UI: Quarantine process is done by other function
				{
					SuspendThread(m_pQuarantineThread->m_hThread);

					delete m_pQuarantineThread;
					m_pQuarantineThread = NULL;
				}
				m_pQuarantineThread = AfxBeginThread(CScanProgressDlg::QuarantineThread, this, 0, 0, CREATE_SUSPENDED);
				if (m_pQuarantineThread)
				{
					m_pQuarantineThread->m_bAutoDelete = FALSE;
					m_pQuarantineThread->ResumeThread();
				}*/
			}
			else
			{
				theApp.eScanStartedBy = ENUM_SC_DO_NOT_RUN_SCAN;
			}
		}
		else if (theApp.eScanStartedBy != ENUM_SC_DO_NOT_RUN_SCAN)
		{
			int iRet = 0;
			CString csRegVal = _T("");
			DWORD dQuarantine = 0;
			

			REGISTRATION_STATUS eStatus = theApp.GetRegisrationStatus();
			if ((theApp.eScanStartedBy == ENUM_SC_SCHEDULED) &&
				(eStatus != STATUS_UNREGISTERED_COPY) && (eStatus != STATUS_SUBSCRIPTION_EXPIRED))
			{
				csRegVal = _T("Quarantine");
			}
			else
			{
				if (m_bStopScanning)
				{
					m_bStopScanning = false;
					bool bDialogFlag = true;
					//if ((eStatus == STATUS_UNREGISTERED_COPY) || (eStatus == STATUS_SUBSCRIPTION_EXPIRED))		//UI: registration checks Unregister copy or expired
					
					//else {
						//CMessageBoxDlg objMsg(this);																//UI: Abort message
						////CSmallMsgBox objMsg(this);
						//objMsg.m_csMessage = theApp.m_pResMgr->GetString(L"IDS_SCAN_ABORTED_USER");
						//CString csWormsFound;
						//if (theApp.m_bAutoQuarantine)
						//	csWormsFound = theApp.m_pResMgr->GetString(L"IDS_MAINUI_WORMSCLEAN_EN ");
						//else
						//	csWormsFound = theApp.m_pResMgr->GetString(L"IDS_MAINUI_WORMSFOUND_EN");
						//CString csData;
						//csData.Format(L"\n\n%s: %d\n\n%s %d",
						//	csWormsFound, iCntWorm,
						//	theApp.m_pResMgr->GetString(L"IDS_FILES_SCANNED"), m_dwFilesScanned);
						//objMsg.m_csMessage += csData;
						//objMsg.DoModal();
						//theApp.RemoveHandle();
					//}
				}
				else if (theApp.m_bAutoQuarantine && !m_bAppClosing)
				{
					if (!m_bRestartRequired)
					{
						//CMessageBoxDlg objMsg(this);															//UI: Message for auto clean
						////CSmallMsgBox objMsg(this);

						//objMsg.m_csMessage = theApp.m_pResMgr->GetString(L"IDS_AUTOCLEAN_MSG");
						//CString csWormsFound = theApp.m_pResMgr->GetString(L"IDS_MAINUI_WORMSCLEAN_EN ");
						//CString csData;
						//csData.Format(L"\n\n%s: %d\n\n%s %d",
						//	csWormsFound, iCntWorm,
						//	theApp.m_pResMgr->GetString(L"IDS_FILES_SCANNED"), m_dwFilesScanned);
						//objMsg.m_csMessage += csData;
						//objMsg.DoModal();
						//theApp.RemoveHandle();
					}
				}
				else if (!m_bAppClosing)
				{
					if ((eStatus == STATUS_UNREGISTERED_COPY) || (eStatus == STATUS_SUBSCRIPTION_EXPIRED))
					{
						iRet = IDOK;
					}
					else
					{
						/*CQuarentinePopup objQuarantine(this);									//UI: Threat message
						objQuarantine.m_SpyCount = iCntWorm;
						objQuarantine.m_dwFilesScanned = m_dwFilesScanned;
						iRet = static_cast<int>(objQuarantine.DoModal());
						theApp.RemoveHandle();*/
					}
				}
			}

			if (theApp.eScanStartedBy == ENUM_SC_SCHEDULED)
			{
				// CRegistry objReg;
				dQuarantine = 0;
				objReg.Get(CSystemInfo::m_csProductRegKey, csRegVal, dQuarantine, HKEY_LOCAL_MACHINE);
			}
			if (theApp.eScanStartedBy == ENUM_SC_CUSTOMSCAN)
			{
				dQuarantine = 0;
			}

			if ((iRet == IDOK) || (dQuarantine == 1))
			{
				if ((theApp.eScanStartedBy == ENUM_SC_SCHEDULED) && (dQuarantine == 1))
				{
					Sleep(5000);
				}

				/*if (m_pQuarantineThread)																	//UI: Quarantine process is done by other function
				{
					SuspendThread(m_pQuarantineThread->m_hThread);

					delete m_pQuarantineThread;
					m_pQuarantineThread = NULL;
				}*/
				//Handle Scan Pause Resume Button
				//EnableDisablePauseResumeStopButton(false, false, false);
				/*m_pQuarantineThread = AfxBeginThread(CScanProgressDlg::QuarantineThread, this, 0, 0, CREATE_SUSPENDED);
				if (m_pQuarantineThread)
				{
					m_pQuarantineThread->m_bAutoDelete = FALSE;
					m_pQuarantineThread->ResumeThread();
					Invalidate(1);
				}*/
			}
			else if (iRet == IDCANCEL)
			{
				csMessage = _T("");
				csMessage.Format(_T("%d"), 0);
				WritePrivateProfileString(_T("SCAN_STATUS"), _T("THREATS_CLEAN"), csMessage, CSystemInfo::m_strSettingPath + _T("ScanStat.ini"));

				/*ShowScanStatus(true);																					//UI: Update controls data
				SelectScanType();*/
				

				if (theApp.IsSDReadyForFullScan(true) == true)
					theApp.IsSDReadyForFullScan(false);
				theApp.eScanStartedBy = ENUM_SC_DO_NOT_RUN_SCAN;
			}
			else
			{
				if (theApp.eScanStartedBy == ENUM_SC_SCHEDULED)
				{
					m_bUIClose = true;
					OnCompleteScheduleScan();
				}

				if (theApp.IsSDReadyForFullScan(true) == true)
					theApp.IsSDReadyForFullScan(false);
				theApp.eScanStartedBy = ENUM_SC_DO_NOT_RUN_SCAN;
			}
		}
	}
	else
	{
		if (theApp.eScanStartedBy == ENUM_SC_SCHEDULED)
		{
			m_bUIClose = true;
			m_bQuarantineProcess = false;
			OnCompleteScheduleScan();
		}
		if (!m_bAppClosing)
		{
			if (theApp.IsSDReadyForFullScan(true) == true)
				theApp.IsSDReadyForFullScan(false);
			theApp.eScanStartedBy = ENUM_SC_DO_NOT_RUN_SCAN;
		}
	}
	/*if (!m_bAppClosing)													//UI: Send message 
		m_stScanStatusBar.SetWindowText(m_csStatusText);*/
	CRegistry objRegistry;
	DWORD dwFScan = 0;
	objRegistry.Set(CSystemInfo::m_csProductRegKey, _T("IsScan"), dwFScan, HKEY_LOCAL_MACHINE);

	dwFScan = 0;
	theApp.m_pSendMsgUltraUI = NULL;
	theApp.m_pSendDetectionToUltraUI = NULL;

	//return 0;
}

/*-------------------------------------------------------------------------------------
Function		: OnScanStop
In Parameters	: 
Out	Parameters	: void
Purpose			: Stop scanner call
--------------------------------------------------------------------------------------*/
void CScanProcess::OnScanStop()
{
	if (m_bQuarantineProcess == true)
	{
		AddLogEntry(_T(">>> Quarantine Process stopped by user..."), 0, 0, true, LOG_DEBUG);
		//m_stScanStatusBar.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_QUASTOPPRDMSG_EN")));					//UI: Cleaning process stopped by user.
		m_bQuarantineStopped = true;
	}
	else
	{
		/*************************************/
		// Ask User whether to Abort Scan!!!
		/*************************************/
		/*CYesNoSmallMsgBox objMsgBox(this);																				//UI: Abort Scan
		objMsgBox.m_csMessage = theApp.m_pResMgr->GetString(_T("IDS_ABORT_SCAN"));
		objMsgBox.m_csYesMessage = theApp.m_pResMgr->GetString(_T("IDS_YES_EN"));
		objMsgBox.m_csNoMessage = theApp.m_pResMgr->GetString(_T("IDS_NO_EN"));
		if (IDOK == objMsgBox.DoModal())*/
		{
			//m_bDrawWithWhiteColor = false;
			m_bShutdown = FALSE;
			m_bScanningClosed = true;
			
			m_csFolderToScan = _T("");

			//m_btnScanPauseResume.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_SCAN_PAUSE_BTN")));					//UI: Pause button text
			
			AddLogEntry(_T(">>> Scan Process stopped by user..."), 0, 0, true, LOG_DEBUG);
			m_bStopScanning = true;
			//m_stScanStatusBar.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_SCANSTOPPRDMSG_EN")));				//UI: Scanning stopped by user.
			StopScanner(Stop_Scanning);
			m_bPauseScanning = false;
		}		
	}
}

/*-------------------------------------------------------------------------------------
Function		: StopScanner
In Parameters	: int iType
Out	Parameters	: bool
Purpose			: To perform the post scan process
--------------------------------------------------------------------------------------*/
bool CScanProcess::StopScanner(int iType)
{
	MAX_PIPE_DATA sMaxPipeData = { 0 };
	CMaxCommunicator objMaxCommunicator(theApp.m_csScannerID);

	if (1 == m_chScanFromUIStage)
	{
		m_objThreadSync.Acquire();
		if (m_pScanFromUIThread && m_pScanFromUIThread->m_hThread)
		{
			ResumeThread(m_pScanFromUIThread->m_hThread);
			if (m_pMaxSecureDispatcher)
			{
				MAX_PIPE_DATA sMaxPipeData = { 0 };
				MAX_DISPATCH_MSG sMaxDispatchMessage;

				memset(&sMaxDispatchMessage, 0, sizeof(sMaxDispatchMessage));
				sMaxDispatchMessage.eDispatch_Type = eStopScanning;
				//sMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
				m_pMaxSecureDispatcher(&sMaxDispatchMessage, &sMaxPipeData);
			}

			bool bTerminateThread = true;
			DWORD dwWaitRes = 0;
			while (true)
			{
				dwWaitRes = WaitForSingleObject(m_pScanFromUIThread->m_hThread, 100);
				if (dwWaitRes == WAIT_OBJECT_0)
				{
					bTerminateThread = false;
					break;
				}
				else if (dwWaitRes == WAIT_ABANDONED)
				{
					break;
				}
				else if (dwWaitRes == WAIT_FAILED)
				{
					break;
				}
				else if (dwWaitRes == WAIT_TIMEOUT)
				{
				}

				Process_DoEvents();
			}

			if (bTerminateThread)
			{
				SuspendThread(m_pScanFromUIThread->m_hThread);
				TerminateThread(m_pScanFromUIThread->m_hThread, 0);
			}

			delete m_pScanFromUIThread;
			m_pScanFromUIThread = NULL;
		}

		m_objThreadSync.Release();
	}
	else
	{
		// Resume the state of the Scanning (in case it is suspended)
		sMaxPipeData.eMessageInfo = Resume_Scanning;
		objMaxCommunicator.SendData(&sMaxPipeData, sizeof(MAX_PIPE_DATA));

		sMaxPipeData.eMessageInfo = iType;
		if (!objMaxCommunicator.SendData(&sMaxPipeData, sizeof(MAX_PIPE_DATA)))
		{
			return false;
		}
	}

	return true;
}

/*-------------------------------------------------------------------------------------
Function		: PrepareForScan
In Parameters	: 
Out	Parameters	: void
Purpose			: Prepare all the data to start scan
--------------------------------------------------------------------------------------*/
void CScanProcess::PrepareForScan()
{
	
	m_bScanningClosed = false;
	//if (m_iScanType != 6)
	//{
	//	//m_stPercentageLabel.ShowWindow(SW_SHOW);															//UI: Show percentage label
	//}

	m_bScanInProgress = true;

	//m_btnScanPauseResume.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_SCAN_PAUSE_BTN")));			//UI: Pause button text
	
	m_bStopScanning = false;
	m_bDoKeyLoggerScan = true;
	m_bDoVirusScan = false;
	m_bPauseScanning = false;
	theApp.m_bAutoQuarantine = false;

	CRegistry objReg;
	DWORD dwVal = 1;
	objReg.Get(CSystemInfo::m_csProductRegKey, KEYLOGGERSCANKEY, dwVal, HKEY_LOCAL_MACHINE);
	if (!dwVal)
	{
		m_bDoKeyLoggerScan = false;
	}

	dwVal = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), dwVal, HKEY_LOCAL_MACHINE);
	if (dwVal)
	{
		theApp.m_bAutoQuarantine = true;
	}

	int iRegValue = (int)theApp.GetRegisrationStatus();
	bool bRegistrationStatus = false;
	if (iRegValue == STATUS_REGISTERED_COPY)
	{
		bRegistrationStatus = true;
	}
	if (bRegistrationStatus == false)
	{
		theApp.m_bAutoQuarantine = false;
	}
	//CheckFreeDiskSpace();			//UI: Send message to UI for disk space error

	
	CString csFolderPath = _T("");

	if (CSystemInfo::m_iVirusScanFlag == 1)
	{
		m_bVirusScan = true;
	}

	m_nRegKeyValueInspected = 0;
	m_nFileFolderInspected = 0;
	m_dwSpywareFound = 0;
	m_iPercentage = 0;
	m_dwFilesScanned = 0;

	CString csData;
	csData.Format(L"%d%%  ", m_iPercentage);
	//m_stPercentageLabel.SetWindowText(csData);																//UI: Status update percentage
	CString csWormsFound;
	

	if (theApp.eScanStartedBy == ENUM_SC_SCHEDULED)
	{
		DWORD dwScanOption = 0;
		objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("ScanOption"), dwScanOption, HKEY_LOCAL_MACHINE);
		theApp.m_bAutoQuarantine = false;
		DWORD dwQuarantine = 0;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("Quarantine"), dwQuarantine, HKEY_LOCAL_MACHINE);
		if (dwQuarantine == 1 && bRegistrationStatus)
		{
			theApp.m_bAutoQuarantine = true;
		}
		
		if (dwScanOption == 0)
		{
			m_iScanType = ENUM_SCAN_QUICK;
		}
		else
		{
			m_iScanType = ENUM_SCAN_FULL;
			DWORD dwScanType = 0;
			objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("AllowSignScan"), dwScanType, HKEY_LOCAL_MACHINE);
			if (dwScanType == 1)
			{
				m_bSignatureScan = true;
			}
			dwScanType = 0;

			objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("DeepScan"), dwScanType, HKEY_LOCAL_MACHINE);
			if (dwScanType)
			{
				m_bDeepScan = true;
			}

			dwScanType = 0;

			objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("VirusScan"), dwScanType, HKEY_LOCAL_MACHINE);
			if (dwScanType)
			{
				m_bDoVirusScan = true;
			}
		}

		CString csDriveName;
		objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("ScheduleDrives"), csDriveName, HKEY_LOCAL_MACHINE);
		m_csDriveNames = csDriveName;
	}

	m_csDriveNames.Trim();

	DWORD dwFScan = 1;
	objReg.Set(CSystemInfo::m_csProductRegKey, _T("IsScan"), dwFScan, HKEY_LOCAL_MACHINE);
	m_iShowScanStatus = m_iScanType;

	if (m_iScanType == ENUM_SCAN_QUICK)
	{
		AddLogEntry(_T(">>> Starting Quick Scan..."), 0, 0, true, LOG_DEBUG);

		WCHAR csWinDir[MAX_PATH] = _T("");
		UINT uRetVal = GetWindowsDirectory(csWinDir, MAX_PATH);
		if (0 != uRetVal)
		{
			m_csDriveNames = csWinDir;
			int iFind = m_csDriveNames.Find(_T(':'), 0);
			m_csDriveNames = m_csDriveNames.Mid(0, iFind + 1);
			m_csDriveNames += _T("|");
		}

		StartScan(m_csDriveNames, false, false, false, false, false, true, false, false, theApp.m_bAutoQuarantine);
	}
	else if (m_iScanType == ENUM_SCAN_CUSTOM)
	{
		AddLogEntry(_T(">>> Starting Custom Scan..."), 0, 0, true, LOG_DEBUG);
		m_csDriveNames = m_csFolderToScan;
		StartScan(m_csDriveNames, false, m_bDoVirusScan, false, false, false, false, true, m_bDeepScan, theApp.m_bAutoQuarantine);
	}
	else if (m_iScanType == ENUM_SCAN_FULL)
	{
		if (m_bDeepScan)
		{
			AddLogEntry(_T(">>> Starting Deep Scan..."), 0, 0, true, LOG_DEBUG);
		}
		else
		{
			AddLogEntry(_T(">>> Starting Full Scan..."), 0, 0, true, LOG_DEBUG);
		}
		//StartScannerFromUI();
		StartScan(m_csDriveNames, true, m_bDoVirusScan, false, m_bDoKeyLoggerScan, false, true, false, m_bDeepScan, theApp.m_bAutoQuarantine);
	}
	else if (m_iScanType == 6)
	{
		AddLogEntry(_T(">>> Starting Mobile Scan..."), 0, 0, true, LOG_DEBUG);
		m_csDriveNames = m_csFolderToScan;
		StartScan(m_csDriveNames, false, m_bDoVirusScan, false, false, false, false, true, m_bDeepScan, theApp.m_bAutoQuarantine);
	}
	m_csFolderToScan = _T("");
	m_csDriveNames = _T("");

}

/*-------------------------------------------------------------------------------------
Function		: CheckFreeDiskSpace
In Parameters	:
Out	Parameters	: void
Purpose			: Check disk free space
--------------------------------------------------------------------------------------*/
void CScanProcess::CheckFreeDiskSpace()
{
	try
	{
		CString csFolderPath;
		csFolderPath = CSystemInfo::m_strAppPath + QUARENTINE_FOLDER_NAME;
		CFileFind objFile;

		if (objFile.FindFile(csFolderPath))
		{
			DWORD64 dwSize = 0;
			DWORD dwSizeQ = (DWORD)(2 * 1024 * 1024 * 1024);
			DWORD dwFile = 0, dwDir = 0;
			TCHAR szTmp[50] = { 0 };
			dwSize = GetFolderSize(csFolderPath, &dwFile, &dwDir);
			_i64tow_s(dwSize, szTmp, 50, 10);
			wcscat_s(szTmp, 50, _T(" Bytes"));
			if (dwSize > dwSizeQ)
			{
				m_bisDiskFull = true;
				/*objMsg.m_csMessage = theApp.m_pResMgr->GetString(_T("IDS_QUARANTINE_STORE_LIMIT_MSG_EN"));		//UI: Your Quarantine folder has exceeded the 2 GB size. To create the space you may delete the quarantined backup 
				if (IDOK == objMsg.DoModal())*/
				{
					m_bisDiskFull = false;
					Delete(csFolderPath, TRUE);
				}
			}
		}
	}
	catch (...)
	{
	}
}

/*-------------------------------------------------------------------------------------
Function		: GetFolderSize
In Parameters	: LPCTSTR - path
				  DWORD * - number of files
				  DWORD * - number of folders
Out	Parameters	: DWORD64 - size
Purpose			: To retrieve the size of the folder
--------------------------------------------------------------------------------------*/
DWORD64 CScanProcess::GetFolderSize(LPCTSTR szPath, DWORD* dwFiles, DWORD* dwFolders)
{
	TCHAR szFileFilter[512] = { 0 };
	TCHAR szFilePath[512] = { 0 };
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA oFileInfo = { 0 };
	DWORD64    dwSize = 0;

	wcscpy_s(szFilePath, 512, szPath);
	wcscat_s(szFilePath, 512, _T("\\"));
	wcscpy_s(szFileFilter, 512, szFilePath);
	wcscat_s(szFileFilter, 512, _T("*.*"));

	hFind = FindFirstFile(szFileFilter, &oFileInfo);
	do
	{
		if (oFileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (!wcscmp(oFileInfo.cFileName, _T(".")) || !wcscmp(oFileInfo.cFileName, _T("..")))
			{
				;//Do nothing for _T(".")and _T("..")folders
			}
			else
			{
				TCHAR szTemp[512] = { 0 };
				wcscpy_s(szTemp, 512, szFilePath);
				wcscat_s(szTemp, 512, oFileInfo.cFileName);
				dwSize = dwSize + GetFolderSize(szTemp);
				if (dwFolders != NULL)
				{
					++(*dwFolders);
				}
			}
		}
		else
		{
			if (dwFiles != NULL)
			{
				++(*dwFiles);
			}
		}
		dwSize += oFileInfo.nFileSizeLow;

	} while (FindNextFile(hFind, &oFileInfo));
	FindClose(hFind);
	return dwSize;
}


/*-------------------------------------------------------------------------------------
Function		: Delete
In Parameters	: LPCTSTR - directory name
BOOL - include subdirectory flag
Out	Parameters	: bool - flag
Purpose			: to delete files and sub folders in directory
--------------------------------------------------------------------------------------*/
BOOL CScanProcess::Delete(LPCTSTR lpDirectoryName, BOOL bSubDir)
{
	CFileFind	oFileFind;
	BOOL		bContinue = FALSE;
	CString csFileName;
	if ((bContinue = oFileFind.FindFile(lpDirectoryName)) != 0)
	{
		while (bContinue)
		{
			bContinue = oFileFind.FindNextFile();
			if (oFileFind.IsDots())
			{
				continue;
			}
			if (oFileFind.IsDirectory() && bSubDir)
			{
				WCHAR lpszSubDirPath[MAX_PATH] = { 0 };
				wcscpy_s(lpszSubDirPath, MAX_PATH, oFileFind.GetFilePath());
				wcscat_s(lpszSubDirPath, MAX_PATH, _T("\\*.*"));
				Delete(lpszSubDirPath, TRUE);
			}
			if (oFileFind.IsDirectory())
			{
				csFileName = oFileFind.GetFileName();
				if (csFileName.CompareNoCase(_T("Quarantine")) != 0)
					RemoveDirectory(oFileFind.GetFilePath());
			}
			else
			{
				CString csFileName = oFileFind.GetFilePath();
				CFileFind filefind;
				BOOL bPresent = filefind.FindFile(csFileName);
				if (!bPresent)
					return FALSE;
				filefind.FindNextFile();

				//csFileName
				//Remove Read only attri
				DWORD dwAttrs = GetFileAttributes(csFileName);
				if (dwAttrs != INVALID_FILE_ATTRIBUTES && dwAttrs & FILE_ATTRIBUTE_READONLY)
				{
					SetFileAttributes(csFileName, dwAttrs ^ FILE_ATTRIBUTE_READONLY);
				}
				if (csFileName.CompareNoCase(_T("ServerVersionEx.txt")) != 0)
				{
					csFileName.MakeLower();
					if (csFileName.Find(_T("exclude")) == -1)
					{
						//m_stScanStatusBar.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_DELETING_STATUS_EN")) + csFileName);				//UI: send message: Deleting Temp/Temp IE- 
						DeleteFile(csFileName);
					}
				}
			}
		}
		oFileFind.Close();
	}
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : OnCompleteScheduleScan
In Parameters  :
Out Parameters : bool
Description    : On schedule scan complete, check for reboot or log off setting and act accordingly.
--------------------------------------------------------------------------------------*/
bool CScanProcess::OnCompleteScheduleScan()
{
	DWORD dwShutDown = 0;
	m_bUIClose = true;
	CRegistry objReg;
	CEnumProcess objEnumProcess;

	objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("ShutDown"), dwShutDown, HKEY_LOCAL_MACHINE);
	if (dwShutDown != 0)
	{
		if (dwShutDown == 1)
		{
			objEnumProcess.RebootSystem(dwShutDown);// Shut down
			return true;
		}
		else if (dwShutDown == 2)// Log off
		{
			//Close and Exit Scanner Then Log off
			if (StopScanner(Stop_Exit_Scanner))
			{
				objEnumProcess.RebootSystem(dwShutDown);
			}
			return true;
		}
	}

	return false;
}
/*-------------------------------------------------------------------------------------
Function		: WriteSpywareCounts
In Parameters	: -
Out	Parameters	: void
Purpose			: to write spy count
--------------------------------------------------------------------------------------*/
void CScanProcess::WriteSpywareCounts()
{
	unsigned int iWormCnt = m_dwSpywareFound;
	CString configFile = CSystemInfo::m_strAppPath + WORMSCOUNTINI;
	CString csKey = _T("");
	CString csSection = _T("Worms");
	csKey = FOLDER;
	CString csData;
	csData.Format(_T("%d"), m_nFileFolderInspected);
	WritePrivateProfileStringW(csSection, csKey, csData, configFile);
	csKey = PROCESS;
	csData.Format(_T("%d"), m_nProcessInspected);
	WritePrivateProfileStringW(csSection, csKey, csData, configFile);
	csKey = FILEWORM;
	csData.Format(_T("%d"), m_nFileFolderInspected);
	WritePrivateProfileStringW(csSection, csKey, csData, configFile);
	csKey = COOKIE;
	csData.Format(_T("%d"), m_nCookiesInspected);
	WritePrivateProfileStringW(csSection, csKey, csData, configFile);
	csKey = REGISTRYKEY;
	csData.Format(_T("%d"), m_nRegKeyValueInspected);
	WritePrivateProfileStringW(csSection, csKey, csData, configFile);

	csSection = _T("summary");
	csKey = _T("SpyCounts");
	csKey = _T("WormCounts");
	csData.Format(_T("%d"), iWormCnt);
	WritePrivateProfileStringW(csSection, csKey, csData, configFile);
	csKey = _T("ScannedWormCount");
	WCHAR szBuffer[MAX_PATH] = { 0 };
	GetPrivateProfileStringW(csSection, csKey, _T(""), szBuffer, MAX_PATH, configFile);
	unsigned int iOldcnt = _wtoi(szBuffer);
	iWormCnt = iWormCnt + iOldcnt;
	csData.Format(_T("%d"), iWormCnt);
	WritePrivateProfileStringW(csSection, csKey, csData, configFile);
}

/*--------------------------------------------------------------------------------------
Function       : StartAutoScan
In Parameters  : void
Out Parameters : void
Description    : Start auto scan and Scheduled Scan
--------------------------------------------------------------------------------------*/
void CScanProcess::StartAutoScan()
{
	if (m_bScanInProgress == true || m_bQuarantineProcess == true)
	{
		//Do nothing as scan is already running!
		return;
	}

	m_chScanFromUIStage = 1;

	PrepareForScan();
}

/*-------------------------------------------------------------------------------------
Function		: StartManualScan
In Parameters	: -
Out	Parameters	: void
Purpose			: Start manual scan on user demand
--------------------------------------------------------------------------------------*/
void CScanProcess::StartManualScan()
{
	
	if (m_bScanInProgress == true || m_bQuarantineProcess == true)
	{
		//Do nothing as scan is already running!
		return;
	}
	m_chScanFromUIStage = 1;

	m_bScanningClosed = false;
	theApp.eScanStartedBy = ENUM_SC_USERCLICKED;

	//Check for Custom scan path and Drive Check Status!

	m_csFolderToScan = m_objScanStartInfo.szPath;						//Newly Added: File path for scan
	if (m_iScanType == ENUM_SCAN_CUSTOM)
	{
		/*///Newly Added for custom scan
		m_bSignatureScan = true;
		m_bDoVirusScan = true;
		m_bDeepScan = true;*/
		
		if (m_csFolderToScan == _T(""))
		{
			//Reading text from control
			CString csPath = m_objScanStartInfo.szPath;		//GetTextFromRichEditCtrl();			//UI: File\Folder path to scan
			if ((csPath != L""))
			{
				if (PathFileExists(csPath))
				{
					m_csFolderToScan = csPath;
				}
				else
				{
					/*m_objMessageBoxDlg.m_csMessage = theApp.m_pResMgr->GetString(_T("IDS_SELECT_VALID_FOLDER"));		//UI: Message Invalid path
					m_objMessageBoxDlg.DoModal();
					theApp.RemoveHandle();
					SetTextRichEditCtrl(L"");*/
					return;
				}
			}
			else if (csPath == L"")
			{
				/*m_objMessageBoxDlg.m_csMessage = theApp.m_pResMgr->GetString(_T("IDS_SELECT_SOME_FOLDER"));			//UI: Message Empty path
				m_objMessageBoxDlg.DoModal();
				theApp.RemoveHandle();
				SetTextRichEditCtrl(L"");*/
				return;
			}
		}

		if (m_csFolderToScan != _T(""))
		{
			if (!theApp.IsSDReadyForFullScan(true))
			{
				return;
			}

			m_bVirusScan = 1; //m_chkVirusScan.GetCheck() == BST_CHECKED;
			m_bDeepScan = 1; //m_chkDeepScan.GetCheck() == BST_CHECKED;

			CRegistry objReg;
			DWORD dwNotRegister = 0;
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dwNotRegister, HKEY_LOCAL_MACHINE);
			if (dwNotRegister)
			{
				if (CSystemInfo::m_iVirusScanFlag != 1)
					m_bVirusScan = 0;
				m_bDeepScan = 0;
			}
			//m_csDriveNames = m_csFolderToScan;
		}
		else
		{
			return;
		}
	}
	else if (m_iScanType == ENUM_SCAN_FULL)
	{
		theApp.eScanStartedBy = ENUM_SC_FORCEFULLSCAN;
		CString csData(_T(""));
		m_csDriveNames = _T("");
		//CString m_csAllDrives = _T("");
		//int iFind = 0;

		m_csDriveNames = m_objScanStartInfo.szPath;											//UI: File\Folder path to scan. New Added. It should be separated "|"
		
		CRegistry objReg;
		objReg.Set(CSystemInfo::m_csProductRegKey, DRIVEKEY, m_csDriveNames, HKEY_LOCAL_MACHINE);

		if (m_csDriveNames.GetLength() == 0)								//UI: Message if path is empty
		{
			return;
		}
	}


	m_chScanFromUIStage = 1;

	PrepareForScan();

}

/*-------------------------------------------------------------------------------------
Function		: ScanResumePause
In Parameters	: -
Out	Parameters	: void
Purpose			: Resume or pause scanner
--------------------------------------------------------------------------------------*/
void CScanProcess::ScanResumePause()
{
	if (m_bScanInProgress)
	{
		// m_chScanFromUIStage is 2 when UI scan is done, and service scan has not started, its intializing...
		// so dont suspend or resume, but user can click close
		if (2 == m_chScanFromUIStage)
		{
			return;
		}

		m_bPauseScanning = true;
		
		m_bScanInProgress = false;
	
		if (1 == m_chScanFromUIStage)
		{
			m_objThreadSync.Acquire();
			if (m_pScanFromUIThread && m_pScanFromUIThread->m_hThread)
			{
				SuspendThread(m_pScanFromUIThread->m_hThread);
			}
			m_objThreadSync.Release();
		}

		// Send Message to the Pause Scanning
		MAX_PIPE_DATA sMaxPipeData = { 0 };
		CMaxCommunicator objMaxCommunicator(theApp.m_csScannerID);
		sMaxPipeData.eMessageInfo = Pause_Scanning;
		objMaxCommunicator.SendData(&sMaxPipeData, sizeof(MAX_PIPE_DATA));

		/*m_stScanStatusBar.GetWindowText(m_csLastStatusBarMessage);					//UI: Scanning paused by user.
		m_stScanStatusBar.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_SCANPAUSEMSG_EN")));*/

		//OnTimer(TIMER_PAUSE_HANDLER);

	}
	else
	{
		// m_chScanFromUIStage is 2 when UI scan is done, and service scan has not started, its intializing...
		// so dont suspend or resume, but user can click close
		if (2 == m_chScanFromUIStage)
		{
			return;
		}

		m_bScanInProgress = true;
		
		m_bPauseScanning = false;
		
		if (1 == m_chScanFromUIStage)
		{
			m_objThreadSync.Acquire();
			if (m_pScanFromUIThread && m_pScanFromUIThread->m_hThread)
			{
				ResumeThread(m_pScanFromUIThread->m_hThread);
			}
			m_objThreadSync.Release();
		}

		// Send Message to the AuScanner to Resume Scanning
		MAX_PIPE_DATA sMaxPipeData = { 0 };
		CMaxCommunicator objMaxCommunicator(theApp.m_csScannerID);
		sMaxPipeData.eMessageInfo = Resume_Scanning;
		objMaxCommunicator.SendData(&sMaxPipeData, sizeof(MAX_PIPE_DATA));
	}
}

/*--------------------------------------------------------------------------------------
Function       : UICloseEvent
In Parameters  : void
Out Parameters : bool
Description    : Close event from UI
--------------------------------------------------------------------------------------*/
bool CScanProcess::UICloseEvent()
{
	static int s_nCloseCnt = 0;
	bool bRet = false;
	if (m_pQuarantineThread)
	{
		WaitForSingleObject(m_pQuarantineThread->m_hThread, INFINITE);
		delete m_pQuarantineThread;
		m_pQuarantineThread = NULL;
	}


	m_bShutdown = false;

	DeallocateMemoryForReport();

	if (theApp.m_bScannerRunning == true || 1 == m_chScanFromUIStage)
	{
		if (m_bScanningProcess == true || 1 == m_chScanFromUIStage)
		{

			bRet = true;
			m_bAppClosing = true;
			if (StopScanner(Stop_Exit_Scanner))
			{
				DestroyCommObject();
			}

		}
		else if (m_bQuarantineProcess)
		{
			AddLogEntry(_T(">>> Closing Application while quarantine is in progress..."));
			m_bAppClosing = true;
		}
		else
		{
			bRet = true;
			AddLogEntry(_T(">>> Closing Application while AuScanner process is alive..."));
			m_bAppClosing = true;
			CheckAndExitScanner();
			
			AddLogEntry(_T(">>> Quitting Application..."));
			return bRet;
		}
	}
	else
	{
		DestroyCommObject();

		AddLogEntry(_T(">>> Quitting Application..."));
		bRet = true;
		return bRet;
	}

	s_nCloseCnt++;
	if (s_nCloseCnt == 2)
	{
		s_nCloseCnt = 0;
		AddLogEntry(_T(">>> Force Ending Application..."));
		DestroyCommObject();
		bRet = true;
	}
	
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : IsScannerRunning
In Parameters  : void
Out Parameters : int
Description    : Is scanner is running status
--------------------------------------------------------------------------------------*/
int CScanProcess::IsScannerRunning()
{
	int bRet = ScanCurrentStatus::Stop;
	if (theApp.m_bScannerRunning == true || 1 == m_chScanFromUIStage)
	{
		if (m_bPauseScanning)
		{
			bRet = ScanCurrentStatus::Pause;
		}
		if (m_bScanningProcess == true || 1 == m_chScanFromUIStage)
		{
			bRet = ScanCurrentStatus::Scanning;
		}
	}
	else if (theApp.m_bScannerRunning == false)
	{
		bRet = ScanCurrentStatus::NoScanner;
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CheckForStatus
In Parameters  : eEntry_Status eStatus, SD_Message_Info eMessageInfo
Out Parameters : int
Description    : Is scanner is running
--------------------------------------------------------------------------------------*/
int CScanProcess::CheckForStatus(eEntry_Status eStatus, SD_Message_Info eMessageInfo)
{
	int iStatus = ScanActionStatus::Cleaned;
	
	if (eStatus == eStatus_Detected && eMessageInfo == Virus_File_Repair)
	{
		iStatus = ScanActionStatus::Repaired;
	}
	else if (eStatus == eStatus_Repaired && eMessageInfo == Virus_File_Repair)
	{
		iStatus = ScanActionStatus::Repaired;
	}
	return iStatus;
}

/*--------------------------------------------------------------------------------------
Function       : AllocateMemoryForReport
In Parameters  : 
Out Parameters : bool
Description    : To allocate memory for report structure
--------------------------------------------------------------------------------------*/
bool CScanProcess::AllocateMemoryForReport()
{
	if (!m_bReportMemAllocate)
	{
		CRegistry objReg;
		TCHAR szTempFilename[MAX_PATH] = { 0 };

		if (_waccess(m_szReportPathBuffer, 0) != 0)
		{
			CDirectoryManager oDirectoryManager;
			oDirectoryManager.MaxCreateDirectory(m_szReportPathBuffer);
		}
		UINT uRetVal = GetTempFileName(m_szReportPathBuffer, L"UAV_", 0, szTempFilename);
		if (uRetVal == 0)
		{
			return false;
		}

		if (!m_objReport.AllocateMemMapFile(szTempFilename))
		{
			AddLogEntry(L"Unable to initialize scan report memory");
		}
		m_bReportMemAllocate = true;
		return true;
	}
	return false;
	
}

/*--------------------------------------------------------------------------------------
Function       : DeallocateMemoryForReport
In Parameters  :
Out Parameters : bool
Description    : To deallocate memory for report structure
--------------------------------------------------------------------------------------*/
bool CScanProcess::DeallocateMemoryForReport()
{
	m_objReport.ReleaseMemMapFile();
	CDirectoryManager oDirectoryManager;
	oDirectoryManager.MaxDeleteDirectoryContents(m_szReportPathBuffer, true);
	m_bReportMemAllocate = false;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : UpdateDetectionStatus
In Parameters  : int iLoadMem
Out Parameters : bool
Description    : Update detection status
--------------------------------------------------------------------------------------*/
bool CScanProcess::UpdateDetectionStatus(int iLoadMem)
{
	if (iLoadMem == 1)
	{
		AllocateMemoryForReport();
	}	
	m_dwSpywareFound++;
	if (theApp.m_pSendMsgUltraUI != NULL)
	{
		theApp.m_objScanStatusData.iMessageId = Status_Bar_File_Report;
		theApp.m_objScanStatusData.dwThreatCount = m_dwSpywareFound;
		theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : DoQuarantineWork
In Parameters  : DWORD dwQuarantineDataLength, DWORD* ptrQuarantineData, DWORD dwTotalCount, DWORD& dwTotalQuarantineCount
Out Parameters : void
Description    : Do actualquarantine work here.Check any entry is selected or not.
				 Stop system restore and send data to backend for quarantine.
--------------------------------------------------------------------------------------*/
void CScanProcess::DoQuarantineWork(DWORD dwQuarantineDataLength, DWORD* ptrQuarantineData, DWORD dwTotalCount, DWORD* ptrQuarantinedData)
{	
	//CheckFreeDiskSpace();										//UI: Disk full check on UI side

	/*if (m_bisDiskFull)
	{
		theApp.eScanStartedBy = ENUM_SC_DO_NOT_RUN_SCAN;
		return;
	}*/

	theApp.m_pSendMsgUltraUI = NULL;
	theApp.m_pSendDetectionToUltraUI = NULL;

	m_iSelectedCnt = 0; // To count no.of entries selected for quarantine
	m_iSelectedCnt = dwQuarantineDataLength;
	// Nothing selected for Quarantine !!!!
	if (m_iSelectedCnt == 0)
	{
		AddLogEntry(L"No entries for Quarantine");
		return;
	}

	

	AddLogEntry(_T(">>> Quarantine Started..."), 0, 0, true, LOG_DEBUG);

	// This means a REGISTERED USER
	try
	{
		m_bQuarantineProcess = true;
		SendQuarantineData(dwQuarantineDataLength, ptrQuarantineData, dwTotalCount, ptrQuarantinedData);
		m_bQuarantineProcess = false;
		m_bQuarantineStopped = false;
		m_bQFullDiskError = false;
		/**************************************************/

		
		//m_stScanStatusBar.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_QUAFINISHEDMSG_EN")));		//UI: Finish Quarantine process

	}
	catch (...)
	{
	}
	AddLogEntry(_T(">>> Quarantine Completed..."), 0, 0, true, LOG_DEBUG);
	if (m_bUIClose)
	{
		CheckAndExitScanner();
		m_bQuarantineProcess = false;
	}
}

/*--------------------------------------------------------------------------------------
Function       : SendQuarantineData
In Parameters  : DWORD dwQuarantineDataLength, DWORD* ptrQuarantineData, DWORD dwTotalCount, DWORD& dwTotalQuarantineCount
Out Parameters : void
Description    : Send data for quarantine to backend communicator.
--------------------------------------------------------------------------------------*/
void CScanProcess::SendQuarantineData(DWORD dwQuarantineDataLength, DWORD* ptrQuarantineData, DWORD dwTotalCount, DWORD* ptrQuarantinedData)
{
	ULONG ulEntriesSendForQuarantine = 0;
	MAX_DISPATCH_MSG stMaxDispatchMessage;

	CreateDirectory(CSystemInfo::m_strAppPath + (CString)QUARANTINEFOLDER, 0);

	CMaxCommunicator objMaxCommunicator(theApp.m_csScannerID);
	MAX_PIPE_DATA pPipeData = { 0 };

	/***********************************/
	// Special Spyware Handling here!
	/***********************************/
	m_bIsFullScanRequired = false;
	CMapStringToString objSpecialSpyMap;
	if (m_iScanType == ENUM_SCAN_QUICK)
	{
		AddSpecialSpywareNames(objSpecialSpyMap);
	}

	if (m_bSplSpywareFound)
	{
		pPipeData.eMessageInfo = Perform_SplQuarantine;
		objMaxCommunicator.SendData(&pPipeData, sizeof(MAX_PIPE_DATA));
		// Set to FALSE so that this message is not sent to the scanner again
		m_bSplSpywareFound = false;
	}

	CString csSpywareName;
	int nShowCnt = 0;
	DWORD dwThreatCounts = 0;
	while (dwThreatCounts < dwQuarantineDataLength)
	{
		if ((true == m_bQuarantineStopped) || (true == m_bAppClosing))
		{
			break;
		}
		MAX_PIPE_DATA_REG oPipeDataReg = { 0 };
		m_objReport.GetRecordFromReportQueue(ptrQuarantineData[dwThreatCounts], &oPipeDataReg);
		csSpywareName = (LPCTSTR)oPipeDataReg.strValue;


		SD_Message_Info eWormType = (SD_Message_Info)oPipeDataReg.eMessageInfo;
		if ((((eWormType >= Rootkit_Process) && (eWormType <= Rootkit_Folder_Report))
			|| ((eWormType >= Rootkit_RegKey) && (eWormType <= Rootkit_RegVal_Report))))
		{
		}
		else if (oPipeDataReg.eMessageInfo < SD_Message_Info_TYPE_REG)// Its a File system Message
		{
			pPipeData.eMessageInfo = oPipeDataReg.eMessageInfo;
			pPipeData.sScanOptions = oPipeDataReg.sScanOptions;
			_tcscpy_s(pPipeData.strValue, oPipeDataReg.strKey);
			_tcscpy_s(pPipeData.strFreshFile, oPipeDataReg.strValue);
			pPipeData.ulSpyNameID = oPipeDataReg.ulSpyNameID;

			if (pPipeData.eMessageInfo % 2 == 0)
			{
				//if (1 == m_chScanFromUIStage)
				//{
				//	if (m_pMaxSecureDispatcher)
				//	{
				//		stMaxDispatchMessage.eDispatch_Type = eQuarantine;
				//		//stMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
				//		m_pMaxSecureDispatcher(&stMaxDispatchMessage, &pPipeData);
				//	}
				//}
				//else
				{
					objMaxCommunicator.SendData(&pPipeData, sizeof(MAX_PIPE_DATA));
				}

				/**************************************/
				// Show Quaratine status message here
				/**************************************/
				//PathSetDlgItemPath(this->m_hWnd, IDC_STATIC_STATUS_BAR_LABEL, csQuarantineMsg + theApp.m_treeList->GetItemText(hChildItem, COLUMN_1));	//UI: Update quarantine status
				//m_stScanStatusBar.SetWindowText(csQuarantineMsg + theApp.m_treeList->GetItemText(hChildItem, COLUMN_1));
			}
		}
		else if (oPipeDataReg.eMessageInfo < SD_Message_Info_TYPE_INFO)// Its a Registry Message
		{
			if (oPipeDataReg.eMessageInfo % 2 == 0)
			{
				//if (1 == m_chScanFromUIStage)
				//{
				//	if (m_pMaxSecureDispatcher)
				//	{
				//		stMaxDispatchMessage.eDispatch_Type = eQuarantine;
				//		//stMaxDispatchMessage.pSendMessageToUI = SendMessageToUI;
				//		m_pMaxSecureDispatcher(&stMaxDispatchMessage, pPipeDataReg);
				//	}
				//}
				//else
				{
					objMaxCommunicator.SendData(&oPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
				}
				/**************************************/
				// Show Quaratine status message here
				/**************************************/
				//PathSetDlgItemPath(this->m_hWnd, IDC_STATIC_STATUS_BAR_LABEL, csQuarantineMsg + theApp.m_treeList->GetItemText(hChildItem, COLUMN_1));	//UI: Update quarantine status
				//m_stScanStatusBar.SetWindowText(csQuarantineMsg + theApp.m_treeList->GetItemText(hChildItem, COLUMN_1));
			}
		}
		ulEntriesSendForQuarantine++;
		if (m_iScanType == ENUM_SCAN_QUICK && m_bIsFullScanRequired == false)
		{
			CString csTempSpyName = csSpywareName;
			CString csRetName;
			if (objSpecialSpyMap.Lookup(csTempSpyName.MakeLower(), csRetName))
			{
				m_bIsFullScanRequired = true;
			}
		}
		ptrQuarantinedData[dwThreatCounts] = ptrQuarantineData[dwThreatCounts];
		dwThreatCounts++;
		
	}
	/************************************************************************/
	// This is user is clicked the CLOSE button from the UI.
	// Based of the value of the variable 'm_bAppClosing',
	// send Finished_Quaratine, followed by Exit_Scanner to the AuScanner.
	/************************************************************************/
	if (m_bAppClosing)
	{
		pPipeData.eMessageInfo = Finished_Quarantine;
		objMaxCommunicator.SendData(&pPipeData, sizeof(MAX_PIPE_DATA));

		pPipeData.eMessageInfo = Exit_Scanner;
		objMaxCommunicator.SendData(&pPipeData, sizeof(MAX_PIPE_DATA));

		PostQuitMessage(0);
		return;
	}
	
	if (!m_bStopScanning)
		DeleteTemporaryAndInternetFiles();
		/****************************************/
		// Finished Quaratine Handling here!
		/****************************************/
	pPipeData.eMessageInfo = Finished_Quarantine;
	if (objMaxCommunicator.SendData(&pPipeData, sizeof(MAX_PIPE_DATA)))
	{
		if (objMaxCommunicator.ReadData((LPVOID)&pPipeData, sizeof(MAX_PIPE_DATA)))
		{
			if (theApp.eScanStartedBy == ENUM_SC_SCHEDULED)
			{
				m_bUIClose = true;
				if (OnCompleteScheduleScan())
				{
					return;
				}
			}
		

			theApp.eScanStartedBy = ENUM_SC_DO_NOT_RUN_SCAN;
			if (theApp.IsSDReadyForFullScan(true) == true && theApp.IsSDReadyForFullScan(false) == true)
			{
				/*********************************************/
				// Show 'Quarantine Over' Message Box here
				/*********************************************/
				if (pPipeData.eMessageInfo == Restart_Required)
				{
					HandleQuarantineRestart(pPipeData.ulSpyNameID, ulEntriesSendForQuarantine);							//UI: Handle Restart event
					m_bIsFullScanRequired = false;
				}
			}
		}
	}
	//m_stScanStatusBar.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_MAINUI_QUAFINISHEDMSG_EN")));						//UI: Quarantine finish message

	/**************************************************/
	// If all the items in the tree are removed,
	// then there is no more data to quaranatine, so
	// sending 'Exit_Scanner' here
	/**************************************************/
	if (dwTotalCount == dwThreatCounts)
	{
		AddLogEntry(_T(">>> Sending Exit Scanner to Scanner - No more entries to Quarantine..."), 0, 0, true, LOG_DEBUG);
		pPipeData.eMessageInfo = Exit_Scanner;
		objMaxCommunicator.SendData(&pPipeData, sizeof(MAX_PIPE_DATA));
		theApp.m_bScannerRunning = false;
		return;
	}
	
}
/*--------------------------------------------------------------------------------------
Function       : AddSpecialSpywareNames
In Parameters  : CMapStringToString & objSpecialSpyMap,
Out Parameters : bool
Description    : Create map for spyware name, which handled specially.
--------------------------------------------------------------------------------------*/
bool CScanProcess::AddSpecialSpywareNames(CMapStringToString& objSpecialSpyMap)
{
	objSpecialSpyMap.SetAt(_T("adware.aurora"), _T("Adware.Aurora"));
	objSpecialSpyMap.SetAt(_T("adware.hotbar"), _T("Adware.HotBar"));
	objSpecialSpyMap.SetAt(_T("adware.2nd thought"), _T("Adware.2nd Thought"));
	objSpecialSpyMap.SetAt(_T("adware.surfsidekick"), _T("Adware.SurfSideKick"));
	objSpecialSpyMap.SetAt(_T("adware.websearch"), _T("Adware.WebSearch"));
	objSpecialSpyMap.SetAt(_T("adware.ieplugin"), _T("Adware.IEPlugin"));
	objSpecialSpyMap.SetAt(_T("adware.home search assistant"), _T("Adware.Home Search Assistant"));
	objSpecialSpyMap.SetAt(_T("trojan.mailer"), _T("Trojan.Mailer"));
	objSpecialSpyMap.SetAt(_T("trojan.downloader"), _T("Trojan.Downloader"));
	objSpecialSpyMap.SetAt(_T("adware.istbar"), _T("Adware.ISTBar"));
	objSpecialSpyMap.SetAt(_T("clkoptimizer"), _T("ClkOptimizer"));
	objSpecialSpyMap.SetAt(_T("adwarewebhancer"), _T("Adware.WebHancer"));
	objSpecialSpyMap.SetAt(_T("adware.newdotnet"), _T("Adware.NewDotNet"));
	objSpecialSpyMap.SetAt(_T("adware.180 search assistant"), _T("Adware.180 Search Assistant"));
	objSpecialSpyMap.SetAt(_T("adware.common name"), _T("Adware.Common Name"));
	objSpecialSpyMap.SetAt(_T("adware.look2me"), _T("Adware.Look2Me"));
	objSpecialSpyMap.SetAt(_T("backdoor.haxdoor"), _T("Backdoor.Haxdoor"));
	objSpecialSpyMap.SetAt(_T("adware.purityscan"), _T("Adware.Purity Scan"));
	objSpecialSpyMap.SetAt(_T("trojan.qoolaid"), _T("Trojan.Qoolaid"));
	objSpecialSpyMap.SetAt(_T("adware.e2give"), _T("Adware.E2Give"));
	objSpecialSpyMap.SetAt(_T("worm.blackmal"), _T("Worm.Blackmal"));
	objSpecialSpyMap.SetAt(_T("fake anti spyware.error safe"), _T("Fake Anti Spyware.Error Safe"));
	objSpecialSpyMap.SetAt(_T("trojan.ntrootkit"), _T("Trojan.NTRootKit"));
	objSpecialSpyMap.SetAt(_T("keylogger.xpcspy"), _T("KeyLogger.XPCSpy"));
	objSpecialSpyMap.SetAt(_T("adware.ruins"), _T("Adware.Ruins"));
	objSpecialSpyMap.SetAt(_T("adware.lop"), _T("Adware.LOP"));
	objSpecialSpyMap.SetAt(_T("trojan.vxgame"), _T("Trojan.Vxgame"));

	return true;
}

/*--------------------------------------------------------------------------------------
Function       :SetPercentage
In Parameters  : int iPercentage
Out Parameters : void
Description    : Set Scan Percentage
--------------------------------------------------------------------------------------*/
void CScanProcess::SetPercentage(int iPercentage)
{
	if (iPercentage < 4)
	{
		m_iPercentage = 1;
	}
	else if(m_iPercentage < iPercentage)
	{
		m_iPercentage = iPercentage;
	}
	theApp.m_objScanStatusData.iPercentage = m_iPercentage;
}