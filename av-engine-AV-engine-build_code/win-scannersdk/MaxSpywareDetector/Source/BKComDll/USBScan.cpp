#include "pch.h"
#include "BKComDll.h"
#include "USBScan.h"
#include "Enumprocess.h"
#include "DirectoryManager.h"

UINT EnumThread(LPVOID lpParam);
CMaxDSrvWrapper* CUSBScan::m_pMaxDSrvWrapper = NULL;

CUSBScan::CUSBScan()
{
	m_dwTotalFilesScanned = 0;
	m_dwThreatCount = 0;
	m_pThreadScanner = NULL;
	m_pThreadQuarantine = NULL;
	m_bStop = FALSE;
	m_eProcessStatus = Nothing;
	m_bStartedScanner = false;
	m_bShutdown = false;
}

CUSBScan::~CUSBScan()
{
}

/*-------------------------------------------------------------------------------------
Function		: LaunchScan
In Parameters	: -
Out	Parameters	: bool
Purpose			: Lauch scanning
--------------------------------------------------------------------------------------*/
bool CUSBScan::LaunchScan()
{
	bool bRet = false;
	if (theApp.IsSDReadyForFullScan(true))
	{
		m_pThreadScanner = AfxBeginThread(EnumThread, this, THREAD_PRIORITY_NORMAL, NULL, CREATE_SUSPENDED, NULL);
		if (m_pThreadScanner)
		{
			m_pThreadScanner->m_bAutoDelete = FALSE;
			m_pThreadScanner->ResumeThread();
		}
	}
	else
	{
		//Unable to launch scanner
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: LaunchScan
In Parameters	: -
Out	Parameters	: bool
Purpose			: Lauch scanning
--------------------------------------------------------------------------------------*/
UINT EnumThread(LPVOID lpParam)
{
	DWORD dwVal = 0;
	int iRegValue = (int)theApp.GetRegisrationStatus();
	bool bRegistrationStatus = false;
	if (iRegValue == STATUS_REGISTERED_COPY)
	{
		bRegistrationStatus = true;
	}
	CRegistry objRegistry;
	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), dwVal, HKEY_LOCAL_MACHINE);
	if (dwVal == 1 && bRegistrationStatus)
	{
		theApp.m_bAutoQuarantine = true;
	}
	else
	{
		theApp.m_bAutoQuarantine = false;
	}
	_TUCHAR* guidStr = 0x00;
	GUID guid;
	CoCreateGuid(&guid);
	UuidToString(&guid, (RPC_WSTR*)&guidStr);
	theApp.m_objUSBScan.m_csGUID = CString(L"\\\\.\\pipe\\{") + guidStr + L"}";
	RpcStringFree((RPC_WSTR*)&guidStr);
	guidStr = NULL;

	theApp.m_pObjMaxCommunicatorServer = new CMaxCommunicatorServer(theApp.m_objUSBScan.m_csGUID, CUSBScan::OnScanDataReceivedCallBack, sizeof(MAX_PIPE_DATA_REG));
	theApp.m_pObjMaxCommunicatorServer->Run();
	
	theApp.m_objUSBScan.m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
	theApp.m_objUSBScan.m_pMaxDSrvWrapper->InitializeDatabase();


	CString csTempFolder;
	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("TempFolderPath"), csTempFolder, HKEY_LOCAL_MACHINE);

	memset(&theApp.m_objScanProcess.m_szReportPathBuffer, 0, MAX_PATH);
	wcscpy_s(theApp.m_objScanProcess.m_szReportPathBuffer, csTempFolder);
	wcscat_s(theApp.m_objScanProcess.m_szReportPathBuffer, L"UAVMEM");

	theApp.m_objScanProcess.DeallocateMemoryForReport();

	CDirectoryManager oDirectoryManager;
	oDirectoryManager.MaxCreateDirectory(theApp.m_objScanProcess.m_szReportPathBuffer);

	BOOL	bIsRightClickScan = FALSE;
	CString csCommand = theApp.m_objUSBScan.m_objScanStartInfo.szPath;
	if (csCommand.Find(L"-SHOWUI") != -1)
	{
		theApp.m_objUSBScan.m_bCustomScan = true;
		csCommand.Replace(L"-SHOWUI", BLANKSTRING);
		bIsRightClickScan = TRUE;
	}
	
	if (csCommand.Find(L"-CUSTOMSCAN") != -1)
	{
		theApp.m_objUSBScan.m_bCustomScan = true;
		theApp.m_objUSBScan.m_bDeepScan = true;	
	}
	
	int iIndex = csCommand.Find('-');
	if (iIndex != -1)
	{
		csCommand.Delete(0, iIndex + 1);
		iIndex = csCommand.Find(' ');
		if (iIndex != -1)
		{
			csCommand.Delete(0, iIndex + 1);
		}
	}
	AddLogEntry(_T("USB drive : %s"), csCommand, 0, true);
	AddLogEntry(_T("Start scan"), 0, 0, true);
	theApp.m_objUSBScan.m_bStartedScanner = theApp.m_objUSBScan.StartScan(csCommand, true, false, false, false, false, true, false, theApp.m_objUSBScan.m_bDeepScan, theApp.m_bAutoQuarantine);
	return 1;
}

/*-------------------------------------------------------------------------------------
Function		: CloseUI
In Parameters	: -
Out	Parameters	: bool
Purpose			: Close all the handles
--------------------------------------------------------------------------------------*/
bool CUSBScan::CloseUI()
{
	bool bRet = false;
	m_bStop = TRUE;

	MAX_PIPE_DATA sMaxPipeData = { 0 };
	CMaxCommunicator objMaxCommunicator(theApp.m_objUSBScan.m_csScannerID);
	sMaxPipeData.eMessageInfo = Stop_Exit_Scanner;
	objMaxCommunicator.SendData(&sMaxPipeData, sizeof(MAX_PIPE_DATA));

	if (m_pThreadScanner)
	{
		if (WAIT_TIMEOUT == WaitForSingleObject(m_pThreadScanner->m_hThread, 2))
		{
			SuspendThread(m_pThreadScanner->m_hThread);
		}

		delete m_pThreadScanner;
		m_pThreadScanner = NULL;
	}

	/*if (m_pThreadQuarantine)
	{
		if (WAIT_TIMEOUT == WaitForSingleObject(m_pThreadQuarantine->m_hThread, 2))
		{
			SuspendThread(m_pThreadQuarantine->m_hThread);
		}

		delete m_pThreadQuarantine;
		m_pThreadQuarantine = NULL;
	}*/
	if (theApp.m_pObjMaxCommunicatorServer)
	{
		delete theApp.m_pObjMaxCommunicatorServer;
		theApp.m_pObjMaxCommunicatorServer = NULL;
	}
	bRet = true;
	return bRet;
}
/*-------------------------------------------------------------------------------------
Function		: StopScan
In Parameters	: -
Out	Parameters	: bool
Purpose			: Stop scanning process
--------------------------------------------------------------------------------------*/
bool CUSBScan::StopScan()
{
	bool bRet = false;
	m_bStop = TRUE;
	
	if (m_eProcessStatus == Scanning)
	{
		MAX_PIPE_DATA sMaxPipeData = { 0 };
		CMaxCommunicator objMaxCommunicator(theApp.m_objUSBScan.m_csScannerID);
		sMaxPipeData.eMessageInfo = Stop_Scanning;
		objMaxCommunicator.SendData(&sMaxPipeData, sizeof(MAX_PIPE_DATA));
	}
	return bRet;
}

///*-------------------------------------------------------------------------------------
//Function		: QuarantineThread
//In Parameters	: -LPVOID lpVoid
//Out	Parameters	: UINT
//Purpose			: To start quarantine process thread
//--------------------------------------------------------------------------------------*/
//UINT QuarantineThread(LPVOID lpVoid)
//{
//	theApp.m_objUSBScan.QuarantineData();
//	return 0;
//}

///*-------------------------------------------------------------------------------------
//Function		: StartQuarantineProcess
//In Parameters	: 
//Out	Parameters	: void
//Purpose			: To start quarantine process
//--------------------------------------------------------------------------------------*/
//void CUSBScan::StartQuarantineProcess()
//{
//	m_pThreadQuarantine = AfxBeginThread(QuarantineThread, NULL, 0, 0, CREATE_SUSPENDED);
//	if (m_pThreadQuarantine)
//	{
//		m_pThreadQuarantine->m_bAutoDelete = FALSE;
//		m_pThreadQuarantine->ResumeThread();
//	}
//}

/*-------------------------------------------------------------------------------------
Function		: QuarantineData
In Parameters	: DWORD dwQuarantineDataLength, DWORD* ptrQuarantineData, DWORD dwTotalCount, DWORD* ptrQuarantinedData
Out	Parameters	: void
Purpose			: Send data for quarantine to backend communicator.
--------------------------------------------------------------------------------------*/
void CUSBScan::QuarantineData(DWORD dwQuarantineDataLength, DWORD* ptrQuarantineData, DWORD dwTotalCount, DWORD* ptrQuarantinedData)
{
	m_bStop = FALSE;
	m_eProcessStatus = Quarantine;
	theApp.m_pSendMsgUltraUI = NULL;
	theApp.m_pSendDetectionToUltraUI = NULL;
	
	CMaxCommunicator objMaxCommunicator(theApp.m_objUSBScan.m_csScannerID);

	CString csSpywareName;
	DWORD dwThreatCounts = 0;
	while (dwThreatCounts < dwQuarantineDataLength)
	{
		if (m_bStop)
			break;

		MAX_PIPE_DATA_REG oPipeDataReg = { 0 };
		theApp.m_objScanProcess.m_objReport.GetRecordFromReportQueue(ptrQuarantineData[dwThreatCounts], &oPipeDataReg);
		objMaxCommunicator.SendData(&oPipeDataReg, sizeof(MAX_PIPE_DATA_REG));

		ptrQuarantinedData[dwThreatCounts] = ptrQuarantineData[dwThreatCounts];
		dwThreatCounts++;
	}
	
	MAX_PIPE_DATA oMaxPipeData = { 0 };
	oMaxPipeData.eMessageInfo = Finished_Quarantine;
	BOOL bRestart = FALSE;
	if (objMaxCommunicator.SendData(&oMaxPipeData, sizeof(MAX_PIPE_DATA)))
	{
		if (objMaxCommunicator.ReadData((LPVOID)&oMaxPipeData, sizeof(MAX_PIPE_DATA)))
		{
			if (oMaxPipeData.eMessageInfo == Restart_Required)
			{
				/****************************************************/
				// In case where the remaining spyware count is ZERO,
				// we just need to show the Restart Message.
				/****************************************************/
				CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
				if (PathFileExists(strINIPath))
				{
					bRestart = TRUE;
					//CYesNoMsgBoxDlg objYesNoMsgBox;
					//objYesNoMsgBox.m_csMessage.Format(L"%s %s", CSystemInfo::m_csProductName, theApp.m_pResMgr->GetString(L"IDS_RESTART_MSG1_EN"));
					//if (objYesNoMsgBox.DoModal() == IDOK)
					//{
					//	AddLogEntry(_T(">>> Restarting System after Quarantine..."), 0, 0, true);

					//	// set key for full scan on restart
					//	CRegistry objRegistry;
					//	CString csAPPPath;
					//	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("AppPath"), csAPPPath, HKEY_LOCAL_MACHINE);
					//	objRegistry.Set(RUN_REG_PATH, _T("FULLSCAN"), csAPPPath + _T(" -FULLSCAN"), HKEY_LOCAL_MACHINE);

					//	CEnumProcess objEnumProc;
					//	objEnumProc.RebootSystem();
					//	return;
					//}
					//UI: restart required message to UI restart message
				}
			}
		}
	}
	if (dwTotalCount == dwThreatCounts)
	{
		AddLogEntry(_T(">>> Sending Exit Scanner to Scanner - No more entries to Quarantine..."), 0, 0, true, LOG_DEBUG);
		oMaxPipeData.eMessageInfo = Stop_Exit_Scanner;
		objMaxCommunicator.SendData(&oMaxPipeData, sizeof(MAX_PIPE_DATA));
		theApp.m_bScannerRunning = false;
		m_eProcessStatus = Nothing;
		return;
	}

	m_eProcessStatus = Nothing;
}

/*-------------------------------------------------------------------------------------
Function		: StopControls
In Parameters	:
Out	Parameters	: void
Purpose			: Perform stop scanning by event
--------------------------------------------------------------------------------------*/
void CUSBScan::StopControls()
{
	m_bStartedScanner = false;
	
	m_eProcessStatus = Nothing;
	
	if (true == m_bShutdown)
	{
		CEnumProcess objEnumProcess;
		objEnumProcess.RebootSystem(1);
	}

	if (m_bRestartRequired)
	{
		m_bRestartRequired = false;
		CString strINIPath = CSystemInfo::m_strAppPath + MAXMANAGER_INI;
		if (PathFileExists(strINIPath))
		{
			//CYesNoMsgBoxDlg objYesNoMsgBox;
			//objYesNoMsgBox.m_csMessage.Format(L"%s %s", CSystemInfo::m_csProductName, theApp.m_pResMgr->GetString(L"IDS_RESTART_MSG1_EN"));
			//if (objYesNoMsgBox.DoModal() == IDOK)
			//{
			//	AddLogEntry(_T(">>> Restarting System after Quarantine..."), 0, 0, true);

			//	// set key for full scan on restart
			//	CRegistry objRegistry;
			//	CString csAPPPath;
			//	objRegistry.Get(CSystemInfo::m_csProductRegKey, _T("AppPath"), csAPPPath, HKEY_LOCAL_MACHINE);
			//	objRegistry.Set(RUN_REG_PATH, _T("FULLSCAN"), csAPPPath + _T(" -FULLSCAN"), HKEY_LOCAL_MACHINE);

			//	CEnumProcess objEnumProc;
			//	objEnumProc.RebootSystem();
			//	return;
			//}
			//UI: Send message to ui for restart
		}
	}

	if (!m_bStop)
	{
		//UI: Scan Completed message
		//m_stFileNameDisplay.SetWindowText(theApp.m_pResMgr->GetString(_T("IDS_STATIC_SCAN_COMPLETE")));
	}
	else
	{
		//UI: Scan Abort
	}	
}
/*-------------------------------------------------------------------------------------
Function		: StartScan
In Parameters	: CString csDrive, bool bSignatureScan, bool bVirusScan, bool bRootkitScan, bool bKeyLoggerScan, bool bHeuristicScan, bool bDBScan, bool bCustomScan, bool bDeepScan, bool bAutoQuarantine
Out	Parameters	: bool
Purpose			: Launch scanner
--------------------------------------------------------------------------------------*/
bool CUSBScan::StartScan(CString csDrive, bool bSignatureScan, bool bVirusScan, bool bRootkitScan, bool bKeyLoggerScan, bool bHeuristicScan, bool bDBScan, bool bCustomScan, bool bDeepScan, bool bAutoQuarantine)
{
	m_eProcessStatus = Scanning;
	m_bRestartRequired = false;

	// Prepare the structure to be sent to the WatchDog Service to start the scan
	// The following structure holds the data required by the WatchDog Service to launch the command line scanner.
	MAX_PIPE_DATA m_sScanRequest = { 0 };
	m_sScanRequest.sScanOptions.IsUSBScanner = true;
	m_sScanRequest.sScanOptions.SignatureScan = bSignatureScan;
	m_sScanRequest.sScanOptions.VirusScan = bVirusScan;
	m_sScanRequest.sScanOptions.RootkitScan = bRootkitScan;
	m_sScanRequest.sScanOptions.KeyLoggerScan = bKeyLoggerScan;
	m_sScanRequest.sScanOptions.HeuristicScan = bHeuristicScan;
	m_sScanRequest.sScanOptions.DBScan = bDBScan;
	m_sScanRequest.sScanOptions.CustomScan = bCustomScan;
	m_sScanRequest.sScanOptions.DeepScan = bDeepScan;
	m_sScanRequest.sScanOptions.AutoQuarantine = bAutoQuarantine;

	wcscpy_s(m_sScanRequest.strValue, csDrive);
	wcscpy_s(m_sScanRequest.szGUID, theApp.m_objUSBScan.m_csGUID);

	MAX_PIPE_DATA_REG sScanRequestReg = { 0 };
	sScanRequestReg.sScanOptions.IsUSBScanner = true;
	sScanRequestReg.sScanOptions.SignatureScan = bSignatureScan;
	sScanRequestReg.sScanOptions.VirusScan = bVirusScan;
	sScanRequestReg.sScanOptions.RootkitScan = bRootkitScan;
	sScanRequestReg.sScanOptions.KeyLoggerScan = bKeyLoggerScan;
	sScanRequestReg.sScanOptions.HeuristicScan = bHeuristicScan;
	sScanRequestReg.sScanOptions.DBScan = bDBScan;
	sScanRequestReg.sScanOptions.CustomScan = bCustomScan;
	sScanRequestReg.sScanOptions.DeepScan = bDeepScan;
	sScanRequestReg.sScanOptions.AutoQuarantine = bAutoQuarantine;

	wcscpy_s(sScanRequestReg.strValue, csDrive);
	wcscpy_s(sScanRequestReg.szGUID, theApp.m_objUSBScan.m_csGUID);

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

	bool bScannerStarted = false;

	// Start the Scanner here via the WatchDog Service
	CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
	bScannerStarted = objMaxCommunicator.SendData(&sScanRequestReg, sizeof(MAX_PIPE_DATA_REG));
	
	return bScannerStarted;
}

/*-------------------------------------------------------------------------------------
Function		: OnScanDataReceivedCallBack
In Parameters	: LPVOID lpParam
Out	Parameters	: void
Purpose			: Scan data callback from server
--------------------------------------------------------------------------------------*/
void CUSBScan::OnScanDataReceivedCallBack(LPVOID lpParam)
{
	LPMAX_PIPE_DATA sMaxPipeData = (MAX_PIPE_DATA*)lpParam;
	if (sMaxPipeData)
	{
		if (sMaxPipeData->eMessageInfo == Report_Scanner_Failure)
		{
			AddLogEntry(_T(">>> Scanner Crashed...Report_Scanner_Failure"));
			if (theApp.m_pSendMsgUltraUI != NULL)
			{
				theApp.m_objScanStatusData.iMessageId = sMaxPipeData->eMessageInfo;
				theApp.m_objScanStatusData.iPercentage = 100;
				theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
			}
			theApp.m_objUSBScan.StopControls();
		}
		else if (sMaxPipeData->eMessageInfo == Finished_Scanning)
		{
			if (theApp.m_pSendMsgUltraUI != NULL)
			{
				theApp.m_objScanStatusData.iMessageId = sMaxPipeData->eMessageInfo;
				theApp.m_objScanStatusData.iPercentage = 100;
				theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
			}
			theApp.m_objUSBScan.StopControls();			
		}
		else if (sMaxPipeData->eMessageInfo == SendGuid)
		{
			theApp.m_objUSBScan.m_csScannerID = sMaxPipeData->strValue;
		}
		else if (sMaxPipeData->eMessageInfo < SD_Message_Info_TYPE_REG)
		{

			if (sMaxPipeData->eMessageInfo == Status_Bar_File_Report || sMaxPipeData->eMessageInfo == Status_Bar_File
				|| sMaxPipeData->eMessageInfo == FilePath_Report)
			{
				if (_tcslen(sMaxPipeData->strValue) > 0)
				{
					int iPercentage = _wtoi(sMaxPipeData->strFreshFile);
					//pDlg->UpdateFileStatusSEH(iPercentage, sMaxPipeData->strValue, sMaxPipeData->ulSpyNameID);
					//UI: Update status data in UI
					if (theApp.m_pSendMsgUltraUI != NULL)
					{
						theApp.m_objScanStatusData.iMessageId = sMaxPipeData->eMessageInfo;
						theApp.m_objScanStatusData.iPercentage = iPercentage;
						theApp.m_objScanStatusData.dwFilesCount = sMaxPipeData->ulSpyNameID;
						_tcscpy_s(theApp.m_objScanStatusData.szData, sMaxPipeData->strValue);
						theApp.m_pSendMsgUltraUI(theApp.m_objScanStatusData);
					}
				}
			}
			else
			{
				BYTE bThreatIndex = 0;
				CString csVirusName = m_pMaxDSrvWrapper->GetSpyName(sMaxPipeData->ulSpyNameID, bThreatIndex);
				//CString csStatus = theApp.CheckForStatus((SD_Message_Info)sMaxPipeData->eMessageInfo);		//UI: Update scan status

				int iThreatIndex = static_cast<int>(bThreatIndex);
				//pDlg->InsertItem(sMaxPipeData->eMessageInfo, sMaxPipeData->strValue, csVirusName, csVirusName, 0, sMaxPipeData->ulSpyNameID, csStatus, iThreatIndex);
				//UI: Update in array

				/*MAX_PIPE_DATA_REG* pMaxPipeData = theApp.GetMaxPipeData(sMaxPipeData, sizeof(MAX_PIPE_DATA));
				theApp.m_objListItems.InsertAt(0, pMaxPipeData);*/
				//UI: Set pipe data
				theApp.m_objUSBScan.m_dwThreatCount++;
				UScanUIReport objUScanUIReport = { 0 };
				if (theApp.m_bAutoQuarantine)
				{
					if (sMaxPipeData->eStatus == eStatus_Detected)
					{
						theApp.m_objUSBScan.m_bRestartRequired = true;
					}
					theApp.m_objScanProcess.UpdateDetectionStatus(0);
					if (theApp.m_pSendDetectionToUltraUI != NULL)
					{
						objUScanUIReport.dwIndex = 0;// From New Memory storage code
						objUScanUIReport.iActionStatus = theApp.m_objScanProcess.CheckForStatus(sMaxPipeData->eStatus, (SD_Message_Info)sMaxPipeData->eMessageInfo);
						objUScanUIReport.iMessageId = sMaxPipeData->eMessageInfo;
						_tcscpy_s(objUScanUIReport.szPath, sMaxPipeData->strValue);
						_tcscpy_s(objUScanUIReport.szSpyName, csVirusName);
						theApp.m_pSendDetectionToUltraUI(objUScanUIReport);
					}
				}
				else
				{
					theApp.m_objScanProcess.UpdateDetectionStatus(1);
					if (theApp.m_pSendDetectionToUltraUI != NULL)
					{
						objUScanUIReport.dwIndex = theApp.m_objScanProcess.m_objReport.AddRecordtoReportQueue(sMaxPipeData, 0);// From New Memory storage code
						objUScanUIReport.iActionStatus = ScanActionStatus::None;
						objUScanUIReport.iMessageId = sMaxPipeData->eMessageInfo;
						_tcscpy_s(objUScanUIReport.szPath, sMaxPipeData->strValue);
						_tcscpy_s(objUScanUIReport.szSpyName, csVirusName);
						theApp.m_pSendDetectionToUltraUI(objUScanUIReport);
					}
				}
			}
		}
		else if (sMaxPipeData->eMessageInfo < SD_Message_Info_TYPE_INFO)
		{
			MAX_PIPE_DATA_REG* sMaxPipeData_Reg = (MAX_PIPE_DATA_REG*)lpParam;
			BYTE bThreatIndex = 0;
			bool bUseSpyID = true;
			CString csVirusName;
			const int SIZEOFBUFFER = 1024 * 4;
			TCHAR strValue[SIZEOFBUFFER] = { 0 };

			theApp.PrepareValueForDispaly(*sMaxPipeData_Reg, strValue, SIZEOFBUFFER);
			if (((sMaxPipeData_Reg->ulSpyNameID == 0) || (_tcslen(sMaxPipeData_Reg->strValue) != 0))
				&& ((sMaxPipeData_Reg->eMessageInfo == Virus_Process) || (sMaxPipeData_Reg->eMessageInfo == Virus_File)
					|| (sMaxPipeData_Reg->eMessageInfo == Virus_File_Repair) || (sMaxPipeData_Reg->eMessageInfo == Virus_File_Repair_Report)
					|| (sMaxPipeData_Reg->eMessageInfo == Virus_Process_Report) || (sMaxPipeData_Reg->eMessageInfo == Virus_File_Report)))
			{
				bUseSpyID = false;
				csVirusName = sMaxPipeData_Reg->strValue;
				bThreatIndex = -1;
			}
			else
			{
				csVirusName = m_pMaxDSrvWrapper->GetSpyName(sMaxPipeData_Reg->ulSpyNameID, bThreatIndex);
			}
			int iThreatIndex = static_cast<int>(bThreatIndex);
			//CString csStatus = theApp.CheckForStatus((SD_Message_Info)sMaxPipeData->eMessageInfo);
			//pDlg->InsertItem(sMaxPipeData_Reg->eMessageInfo, strValue, csVirusName, csVirusName, 0, sMaxPipeData_Reg->ulSpyNameID, csStatus, iThreatIndex);
			//UI: Update threat info to UI

			/*MAX_PIPE_DATA_REG* pMaxPipeData = theApp.GetMaxPipeData(sMaxPipeData_Reg, sizeof(MAX_PIPE_DATA_REG));
			theApp.m_objListItems.InsertAt(0, pMaxPipeData);*/

			theApp.m_objUSBScan.m_dwThreatCount++;
			UScanUIReport objUScanUIReport = { 0 };
			if (theApp.m_bAutoQuarantine)
			{
				if (sMaxPipeData_Reg->eStatus == eStatus_Detected)
				{
					theApp.m_objUSBScan.m_bRestartRequired = true;
				}
				theApp.m_objScanProcess.UpdateDetectionStatus(0);

				if (theApp.m_pSendDetectionToUltraUI != NULL)
				{
					objUScanUIReport.dwIndex = 0;// From New Memory storage code
					objUScanUIReport.iActionStatus = theApp.m_objScanProcess.CheckForStatus(sMaxPipeData_Reg->eStatus, (SD_Message_Info)sMaxPipeData_Reg->eMessageInfo);
					objUScanUIReport.iMessageId = sMaxPipeData_Reg->eMessageInfo;
					_tcscpy_s(objUScanUIReport.szPath, strValue);
					_tcscpy_s(objUScanUIReport.szSpyName, csVirusName);
					theApp.m_pSendDetectionToUltraUI(objUScanUIReport);
				}
			}
			else
			{
				theApp.m_objScanProcess.UpdateDetectionStatus(1);

				if (theApp.m_pSendDetectionToUltraUI != NULL)
				{
					objUScanUIReport.dwIndex = theApp.m_objScanProcess.m_objReport.AddRecordtoReportQueue(sMaxPipeData_Reg, 1);// From New Memory storage code
					objUScanUIReport.iActionStatus = ScanActionStatus::None;
					objUScanUIReport.iMessageId = sMaxPipeData_Reg->eMessageInfo;
					_tcscpy_s(objUScanUIReport.szPath, strValue);
					_tcscpy_s(objUScanUIReport.szSpyName, csVirusName);
					theApp.m_pSendDetectionToUltraUI(objUScanUIReport);
				}
			}
		}
	}
}

/*-------------------------------------------------------------------------------------
Function		: ShutdownStatus
In Parameters	: bool bShutdown
Out	Parameters	: void
Purpose			: Shutdown status
--------------------------------------------------------------------------------------*/
void CUSBScan::ShutdownStatus(bool bShutdown)
{
	m_bShutdown = bShutdown;
}