// BKComDll.cpp : Defines the initialization routines for the DLL.
//

#include "pch.h"
#include "BKComDll.h"
#include "CustomSettings.h"
#include "AdvanceSettings.h"
#include "ExtensionList.h"
#include "RecoverRemovedSpywares.h"
#include "MaxDSrvWrapper.h"
#include "SDSystemInfo.h"
#include "ExcludeDlg.h"
#include "ScanGraph.h"
#include "SchedulerMgr.h"
#include "ScanByName.h"
#include "ProxySetting.h"
#include "ProductInformation.h"
#include "MaxWhiteListDlg.h"
#include "PasswordManager.h"
#include "USBManager.h"
#include "USBDriveList.h"
#include "RegAuth.h"
#include "Enumprocess.h"
#include "ExecuteProcess.h"
#include "CommonFileIntegrityCheck.h"

//Global Objects
CCustomSettings g_objCustomSettings;
CAdvanceSettings g_objAdvanceSettings;
CRegistrationStatus g_objRegStatus;
CExtensionList g_objExtensionList;
CRecoverRemovedSpywares g_objRecoverRemovedSpywares;
CExcludeDlg g_objCExcludeDlg;
CScanByName g_objCScanByName;
CProxySetting g_objCProxySetting;
CProductInformation g_objCProductInfo;
CMaxWhiteListDlg  g_objMaxWhiteListMgr;
CPasswordManager g_objPasswordManager;
//CUSBManager g_objUSBManager;
//CUSBDriveList g_objDeviceList;
CRegAuth g_objRegAuth;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//
//TODO: If this DLL is dynamically linked against the MFC DLLs,
//		any functions exported from this DLL which call into
//		MFC must have the AFX_MANAGE_STATE macro added at the
//		very beginning of the function.
//
//		For example:
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// normal function body here
//		}
//
//		It is very important that this macro appear in each
//		function, prior to any calls into MFC.  This means that
//		it must appear as the first statement within the
//		function, even before any object variable declarations
//		as their constructors may generate calls into the MFC
//		DLL.
//
//		Please see MFC Technical Notes 33 and 58 for additional
//		details.
//

// CBKComDllApp

BEGIN_MESSAGE_MAP(CBKComDllApp, CWinApp)
END_MESSAGE_MAP()


int CBKComDllApp::m_iControlFlag = 1;
UINT AFX_CDECL CheckPrerequisitesThread(LPVOID lpThis);

// CBKComDllApp construction

/*--------------------------------------------------------------------------------------
Function       : CBKComDllApp()
In Parameters  : 
Out Parameters : 
Description    : Constructur of CBKComDllApp class
--------------------------------------------------------------------------------------*/
CBKComDllApp::CBKComDllApp():m_objWDMaxCommunicator(_NAMED_PIPE_WATCHDOG_PROCESSES, false), m_obgRegProcess(EWD_REG)
{
	m_bAutoQuarantine = false;
	m_bRegWDThreadRunning = false;

	m_hAppStopEvent = NULL;
	m_pWinThread = NULL;
	m_pSendMsgUltraUI = NULL;
	m_pSendDetectionToUltraUI = NULL;
	ZeroMemory(&m_sMaxWDData, sizeof(MAX_WD_DATA));
	m_pObjMaxCommunicatorServer = NULL;
	LoadLoggingLevel();
}


// The one and only CBKComDllApp object
CBKComDllApp theApp;

//Initial values
bool CBKComDllApp::m_bUISrvRunning = false;
bool CBKComDllApp::m_bScannerRunning = false;

/*--------------------------------------------------------------------------------------
Function       : InitInstance
In Parameters  :
Out Parameters :
Description    : CBKComDllApp initialization
--------------------------------------------------------------------------------------*/
BOOL CBKComDllApp::InitInstance()
{
	CWinApp::InitInstance();
	CMaxExceptionFilter::InitializeExceptionFilter();
	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : ExitInstance
In Parameters  :
Out Parameters :
Description    : CBKComDllApp Deinitialization
--------------------------------------------------------------------------------------*/
int CBKComDllApp::ExitInstance()
{
	if (theApp.m_obgRegProcess.IsRegisteredWithWatchDog())
	{
		theApp.m_obgRegProcess.WDRegisterProcess(eMaxSDUI, WD_StoppingApp, &theApp.m_objWDMaxCommunicator, Stop_Exit_Scanner, _NAMED_ACTION_PIPE_UI_TO_SCANNER);
	}
	return CWinApp::ExitInstance();
}

/*--------------------------------------------------------------------------------------
Function       : GetCustomSetting
In Parameters  : int CustomSettingLength, int* CustomSetting
Out Parameters : void
Description    : Get Custom Setting from registry.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetCustomSetting(int CustomSettingLength, int* CustomSetting)
{

	g_objCustomSettings.GetCustomSetting(CustomSettingLength, CustomSetting);
}

/*--------------------------------------------------------------------------------------
Function       : SetCustomSetting
In Parameters  : int iSetting, int iValue
Out Parameters : void
Description    : Set Custom Settings to registry.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void SetCustomSetting(int iSetting, int iValue)
{
	g_objCustomSettings.SetCustomSetting(iSetting, iValue);
}

/*--------------------------------------------------------------------------------------
Function       : GetAdvanceSettings
In Parameters  : int iAdvanceSettingLength, int* ptrAdvanceSetting
Out Parameters : void
Description    : Get Advance Settings to registry.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetAdvanceSettings(int iAdvanceSettingLength, int* ptrAdvanceSetting)
{

	g_objAdvanceSettings.GetAdvanceSettingsData(iAdvanceSettingLength, ptrAdvanceSetting);
}

/*--------------------------------------------------------------------------------------
Function       : SetAdvanceSettings
In Parameters  : int iSetOption, int iSetVal
Out Parameters : void
Description    : Set Advance Settings to registry.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void SetAdvanceSettings(int iSetOption, int iSetVal)
{
	g_objAdvanceSettings.SetAdvanceSettingsData(iSetOption, iSetVal);
}

/*--------------------------------------------------------------------------------------
Function       : CheckRegistrationStatus
In Parameters  : 
Out Parameters : bool
Description    : Returns registration status.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool CheckRegistrationStatus()
{
	bool bRegStatus = false;
	bRegStatus = g_objRegStatus.ChkRegStatus();

	return bRegStatus;
}

/*--------------------------------------------------------------------------------------
Function       : ApplyExtensionList
In Parameters  : int iListSize, wchar_t** ppNames
Out Parameters : void
Description    : Set Excluded extensions to Exclude Extension DB.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void ApplyExtensionList(int iListSize, wchar_t** ppNames)
{
	g_objExtensionList.OnClickedApply(iListSize, ppNames);
}

/*--------------------------------------------------------------------------------------
Function       : GetExtensionListCnt
In Parameters  : 
Out Parameters : int
Description    : Get excluded extensions count from DB.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) int GetExtensionListCnt()
{
	int iExtCount = 0;
	iExtCount = g_objExtensionList.GetExtensionCnt();
	return iExtCount;
}
/*--------------------------------------------------------------------------------------
Function       : GetExtensionList
In Parameters  : ExludeExtensions * pExtensionArray, int size
Out Parameters : void
Description    : Get excluded extensions into structure if array.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetExtensionList(ExludeExtensions * pExtensionArray, int size)
{
	g_objExtensionList.FillExtensionArray(pExtensionArray, size);

}

/*--------------------------------------------------------------------------------------
Function       : QuarantineDBCount
In Parameters  : 
Out Parameters : int
Description    : Get Quarantained files count from QuarantainRemoveDB.DB.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) int QuarantineDBCount()
{
	int iRetCount = 0; 
	iRetCount = g_objRecoverRemovedSpywares.GetQuarantainDBCount();
	return iRetCount;
}

/*--------------------------------------------------------------------------------------
Function       : ReadQuarantineData
In Parameters  : QuarantainData * pQuarantineArray, int size
Out Parameters : void
Description    : Get Quarantained data into array of structure.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void ReadQuarantineData(QuarantainData * pQuarantineArray, int size)
{
	g_objRecoverRemovedSpywares.OnClickedLoadQuarantineDB(pQuarantineArray, size);
}

/*------------------------------------------------------------------------------------------------------------------------------------------------
Function       : RecoverData
In Parameters  : QuarantainData * pQuarantineArray, int pQuarantineArraySize, int iRecoverLength, int* ptrRecoveredIndexArray,int iAction
Out Parameters : void
Description    : Recover Data
------------------------------------------------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void RecoverData(QuarantainData * pQuarantineArray, int pQuarantineArraySize, int iRecoverLength, int* ptrRecoveredIndexArray,int iAction)
{
	g_objRecoverRemovedSpywares.OnClickedRecoverFiles(pQuarantineArray, pQuarantineArraySize, iRecoverLength, ptrRecoveredIndexArray, iAction);
}

/*-----------------------------------------------------------------------------------------------------
Function       : CloseRecoveryScanner
In Parameters  : 
Out Parameters : void
Description    : Close scanner after recovery (AuScanner.exe /x )
------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void CloseRecoveryScanner()
{
	g_objRecoverRemovedSpywares.ShutdownRecoveryScanner();
}

/*-----------------------------------------------------------------------------------------------------
Function       : GetExcludeCount
In Parameters  :
Out Parameters : int
Description    : Get count of excluded files and folders.
------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) int GetExcludeCount()
{
	return g_objCExcludeDlg.GetExldCount();
}

/*-----------------------------------------------------------------------------------------------------
Function       : ReadExcludeData
In Parameters  : ExcludeData * pExcludeDataArray, int ExcludeDataSize
Out Parameters : void
Description    : Get excluded files and folders data into structure array
------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void ReadExcludeData(ExcludeData * pExcludeDataArray, int ExcludeDataSize)
{
	g_objCExcludeDlg.FillRecoverListCtrlEx(pExcludeDataArray, ExcludeDataSize);
}

/*-----------------------------------------------------------------------------------------------------
Function       : ExcludeFolder
In Parameters  : wchar_t csFolderPath[]
Out Parameters : int
Description    : This function for exclude selected folder.
------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) int ExcludeFolder(wchar_t csFolderPath[])
{
	return g_objCExcludeDlg.Exclude(csFolderPath);
}

/*-----------------------------------------------------------------------------------------------------
Function       : RecoverExcludedData
In Parameters  : ExcludeData * pExcludeDataArray, int ExcludeDataSize
Out Parameters : void
Description    : This function for recover already excluded data.
------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void RecoverExcludedData(ExcludeData * pExcludeDataArray, int ExcludeDataSize)
{
	g_objCExcludeDlg.RecoverExData(pExcludeDataArray, ExcludeDataSize);
}

///*-----------------------------------------------------------------------------------------------------
//Function       : CreateScanPipeComEx
//In Parameters  : 
//Out Parameters : void
//Description    : 
//------------------------------------------------------------------------------------------------------*/
//extern "C" __declspec(dllexport) void CreateScanPipeComEx()
//{
//	if (theApp.m_bUISrvRunning == false)
//	{
//		theApp.m_bUISrvRunning = true;
//		theApp.m_pSendMsgUltraUI = NULL;
//		theApp.m_objPipeCom.CreateUIComServer();
//	}
//}
//
///*--------------------------------------------------------------------------------------
//Function       : CreateScanPipeCom
//In Parameters  : SENDTDSSMESSAGETOULTRAUI pSendMsgUltraUI
//Out Parameters : void
//Description    : Create ScanUI pipe communication server
//--------------------------------------------------------------------------------------*/
//extern "C" __declspec(dllexport) void CreateScanPipeCom(SENDTDSSMESSAGETOULTRAUI pSendMsgUltraUI)
//{
//	if (theApp.m_bUISrvRunning == false)
//	{
//		theApp.m_bUISrvRunning = true;
//		theApp.m_pSendMsgUltraUI = NULL;
//		if (pSendMsgUltraUI)
//		{
//			theApp.m_pSendMsgUltraUI = pSendMsgUltraUI;
//		}
//		theApp.m_objPipeCom.CreateUIComServer();
//	}
//}

/*--------------------------------------------------------------------------------------
Function       : StartScanFromUI
In Parameters  : SENDTDSSMESSAGETOULTRAUI pSendMsgUltraUI
Out Parameters : void
Description    : Create ScanUI pipe communication server
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void StartScanFromUI(SENDTDSSMESSAGETOULTRAUI pSendMsgUltraUI, SENDDETECTIONTOULTRAUI pSendDetectionToUltraUI, UScanStartInfo oScanStartInfo)
{
	theApp.m_pSendDetectionToUltraUI = NULL;
	theApp.m_pSendMsgUltraUI = NULL;
	if (pSendMsgUltraUI)
	{
		theApp.m_pSendMsgUltraUI = pSendMsgUltraUI;
	}
	if (pSendDetectionToUltraUI)
	{
		theApp.m_pSendDetectionToUltraUI = pSendDetectionToUltraUI;
	}
	memcpy(&theApp.m_objScanProcess.m_objScanStartInfo, &oScanStartInfo,sizeof(UScanStartInfo));
	theApp.m_objScanProcess.CallScanFromUI();

}

/*--------------------------------------------------------------------------------------
Function       : StartScanFromUSB
In Parameters  : SENDTDSSMESSAGETOULTRAUI pSendMsgUltraUI
Out Parameters : void
Description    : Create ScanUI pipe communication server
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void StartScanFromUSB(SENDTDSSMESSAGETOULTRAUI pSendMsgUltraUI, SENDDETECTIONTOULTRAUI pSendDetectionToUltraUI, UScanStartInfo oScanStartInfo)
{
	theApp.m_pSendMsgUltraUI = NULL;
	theApp.m_pSendDetectionToUltraUI = NULL;
	if (pSendMsgUltraUI)
	{
		theApp.m_pSendMsgUltraUI = pSendMsgUltraUI;
	}
	if (pSendDetectionToUltraUI)
	{
		theApp.m_pSendDetectionToUltraUI = pSendDetectionToUltraUI;
	}
	memcpy(&theApp.m_objUSBScan.m_objScanStartInfo, &oScanStartInfo, sizeof(UScanStartInfo));
	theApp.m_objUSBScan.LaunchScan();

}

/*--------------------------------------------------------------------------------------
Function       : RestartActmonProtection
In Parameters  : 
Out Parameters : bool
Description    : Restart Actmon 
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool RestartActmonProtection()
{
	bool bRet = theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, OFF);

	for (int i = 0; i < 400; i++)
	{
		Sleep(5);
	}

	bRet = theApp.m_objPipeCom.PostMessageToProtection(SETPROCESS, ON);
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : SendMessageToSrv
In Parameters  :int iType, int iStatus
Out Parameters : bool
Description    : Send message to service
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool SendMessageToSrv(int iType, int iStatus)
{
	bool bRetVal = false;
	/*if (iType == GameMode)
	{
		CMaxDSrvWrapper objMaxDSrvWrapper;
		bool bRetVal = objMaxDSrvWrapper.SetGamingMode(iStatus);
	}*/
	bRetVal = theApp.m_objPipeCom.PostMessageToService(iType, iStatus);
	return bRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : LaunchWPFUI
In Parameters  :
Out Parameters : bool
Description    : Call when WPF UI is launched
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool LaunchWPFUI()
{
	bool bRetVal = false;
	theApp.m_hAppStopEvent = NULL;
	theApp.m_pWinThread = NULL;
	theApp.m_bRegWDThreadRunning = false;
	ZeroMemory(&theApp.m_sMaxWDData, sizeof(MAX_WD_DATA));
	theApp.m_hAppStopEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);

	_TUCHAR* guidStr = 0x00;
	GUID guid;
	CoCreateGuid(&guid);
	UuidToString(&guid, (RPC_WSTR*)&guidStr);
	theApp.m_csGUID = CString(L"\\\\.\\pipe\\{") + guidStr + L"}";
	RpcStringFree((RPC_WSTR*)&guidStr);
	guidStr = NULL;

	
	theApp.LaunchOtherProcess();

	//At the end off all UI related code
	theApp.m_pWinThread = AfxBeginThread(theApp.WDConnectionThread, theApp);

	return bRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : CloseWPFUI
In Parameters  :
Out Parameters : bool
Description    : Call when WPF UI is about to close
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool CloseWPFUI()
{
	bool bRetVal = false;
	bRetVal = theApp.CallCloseWPFUI();	
	return bRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : CloseUSBUI
In Parameters  :
Out Parameters : bool
Description    : Call when USB WPF UI is about to close
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool CloseUSBUI()
{
	bool bRetVal = false;
	bRetVal = theApp.m_objUSBScan.CloseUI();
	return bRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : UsbShutdownStatus
In Parameters  :
Out Parameters : bool
Description    : Update Usb scanner shutdown status
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void UsbShutdownStatus(bool bShutdown)
{
	theApp.m_objUSBScan.ShutdownStatus(bShutdown);
}

/*--------------------------------------------------------------------------------------
Function       : ShutdownRebootSystem
In Parameters  : int iStatus
Out Parameters : void
Description    : Shutdown or reboot system
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void ShutdownRebootSystem(int iStatus)
{
	CEnumProcess objEnumProcess;
	objEnumProcess.RebootSystem(iStatus);			//0: Reboot, 1: Shutdown, 2:Logoff
}

/*--------------------------------------------------------------------------------------
Function       : CheckScannerRunningState
In Parameters  :
Out Parameters : bool
Description    : Check if scanner is running or not
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool CheckScannerRunningState()
{
	bool bRetVal = false;
	bRetVal = theApp.m_objScanProcess.IsScannerRunning();
	return bRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : DoManualQuarantine
In Parameters  : DWORD iQuarantineDataLength, DWORD * ptrQuarantineData, DWORD iTotalCount
Out Parameters : void
Description    : Do manual quarantine from scanner
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void DoManualQuarantine(DWORD iQuarantineDataLength, DWORD * ptrQuarantineData, DWORD iTotalCount, DWORD * ptrQuarantinedResult)
{

	theApp.m_objScanProcess.DoQuarantineWork(iQuarantineDataLength, ptrQuarantineData, iTotalCount, ptrQuarantinedResult);
}

/*--------------------------------------------------------------------------------------
Function       : DoManualUSBQuarantine
In Parameters  : DWORD iQuarantineDataLength, DWORD * ptrQuarantineData, DWORD iTotalCount
Out Parameters : void
Description    : Do manual quarantine from scanner
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void DoManualUSBQuarantine(DWORD iQuarantineDataLength, DWORD * ptrQuarantineData, DWORD iTotalCount, DWORD * ptrQuarantinedResult)
{

	theApp.m_objUSBScan.QuarantineData(iQuarantineDataLength, ptrQuarantineData, iTotalCount, ptrQuarantinedResult);
}

/*--------------------------------------------------------------------------------------
Function       : PauseResumeScanner
In Parameters  : 
Out Parameters : void
Description    : Pause and resume scanner from ui
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void PauseResumeScanner()
{
	theApp.m_objScanProcess.ScanResumePause();
}

/*--------------------------------------------------------------------------------------
Function       : StopScanner
In Parameters  :
Out Parameters : void
Description    : Stop scanner from ui
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void StopScanner()
{
	theApp.m_objScanProcess.OnScanStop();
}

/*--------------------------------------------------------------------------------------
Function       : StopUSBScanner
In Parameters  :
Out Parameters : void
Description    : Pause and resume scanner from ui
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void StopUSBScanner()
{
	theApp.m_objUSBScan.StopScan();
}

/*--------------------------------------------------------------------------------------
Function       : GetScannerGraphData
In Parameters  :
Out Parameters : void
Description    : Get scanner result from db to draw a graph
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetScannerGraphData(LPUScanGraphInfo pScanGraphData)
{
	CScanGraph objScanGraph;
	objScanGraph.GetScanGraphData(pScanGraphData);
}

/*--------------------------------------------------------------------------------------
Function       : GetSchedulerData
In Parameters  :
Out Parameters : void
Description    : Get scheduler data
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetSchedulerData(LPUScanSchedulerData pScanSchData)
{
	CSchedulerMgr objSchedulerMgr;
	objSchedulerMgr.GetSchedulerSettings(pScanSchData);
}

/*--------------------------------------------------------------------------------------
Function       : SetSchedulerData
In Parameters  :
Out Parameters : void
Description    : Set scheduler data
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void SetSchedulerData(UScanSchedulerData objScanSchData)
{
	CSchedulerMgr objSchedulerMgr;
	objSchedulerMgr.SetSchedulerSettings(objScanSchData);
}

/*--------------------------------------------------------------------------------------
Function       : CancelScheduler
In Parameters  :
Out Parameters : bool
Description    : Cancel scan scheduler
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool CancelScheduler()
{
	bool bRetVal = false;
	CSchedulerMgr objSchedulerMgr;
	bRetVal = objSchedulerMgr.ClearScheduledScan();
	return bRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : GetFullScanReportData
In Parameters  :
Out Parameters : DWORD
Description    : Get the count of Full scan report
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) DWORD GetFullScanReportDataLength()
{
	return theApp.m_objFullScanReport.GetScanFullReportCount();
}
/*--------------------------------------------------------------------------------------
Function       : ShowFullScanHistory
In Parameters  : LPUFullScanReport pFullScanReport, DWORD dwReportLength
Out Parameters : void
Description    : Get the Full scan report
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void ShowFullScanHistory(LPUFullScanReport pFullScanReport, DWORD dwReportLength)
{
	theApp.m_objFullScanReport.ShowAvScanHistory(pFullScanReport, dwReportLength);
}

/*--------------------------------------------------------------------------------------
Function       : UpdateFullScanReportData
In Parameters  : LPUFullScanReport pFullScanReport, DWORD dwReportLength
Out Parameters : void
Description    : Update Full scan report
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void UpdateFullScanReportData(LPUFullScanReport pFullScanReport, DWORD dwReportLength)
{
	theApp.m_objFullScanReport.UpdateAvScanHistory(pFullScanReport, dwReportLength);
}

/*--------------------------------------------------------------------------------------
Function       : GetAppFolderPath
In Parameters  : TCHAR *szAppPath
Out Parameters : void
Description    : Get application folder path
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetAppFolderPath(TCHAR *szAppPath)
{
	_tcscpy(szAppPath, CSystemInfo::m_strAppPath);
}

/*--------------------------------------------------------------------------------------
Function       : CallCloseWPFUI
In Parameters  :
Out Parameters : bool
Description    : Call when WPF UI is about to close
--------------------------------------------------------------------------------------*/
bool CBKComDllApp::CallCloseWPFUI()
{
	theApp.m_objScanProcess.UICloseEvent();
	if (theApp.m_pWinThread)
	{
		if (theApp.m_hAppStopEvent)
		{
			SetEvent(theApp.m_hAppStopEvent);
		}
	}
	if (theApp.m_hAppStopEvent)
	{
		::CloseHandle(theApp.m_hAppStopEvent);
		theApp.m_hAppStopEvent = NULL;
	}
	if (m_pObjMaxCommunicatorServer)
	{
		delete m_pObjMaxCommunicatorServer;
		m_pObjMaxCommunicatorServer = NULL;
	}
	return true;
}
/*--------------------------------------------------------------------------------------
Function       : WDConnectionThread
In Parameters  : LPVOID lParam,
Out Parameters : UINT
Description    : Register process for watch dog connection
--------------------------------------------------------------------------------------*/
UINT CBKComDllApp::WDConnectionThread(LPVOID lParam)
{
	theApp.m_bRegWDThreadRunning = true;
	if (theApp.m_obgRegProcess.WDRegisterProcess(eMaxSDUI, WD_StartingApp, &theApp.m_objWDMaxCommunicator, Stop_Exit_Scanner, _NAMED_ACTION_PIPE_UI_TO_SCANNER))
	{
		theApp.m_bRegWDThreadRunning = false;
		return 0;
	}
	while (1)
	{
		DWORD dwWait = WaitForSingleObject(theApp.m_hAppStopEvent, 3000);
		if (WAIT_OBJECT_0 == dwWait)
		{
			break;
		}
		else if (WAIT_TIMEOUT == dwWait)
		{
			if (theApp.m_obgRegProcess.WDRegisterProcess(eMaxSDUI, WD_StartingApp, &theApp.m_objWDMaxCommunicator, Stop_Exit_Scanner, _NAMED_ACTION_PIPE_UI_TO_SCANNER))
			{
				break;
			}
		}
		else
		{
			break;
		}
	}
	theApp.m_bRegWDThreadRunning = false;
	return 0;
}


/*--------------------------------------------------------------------------------------
Function       : ShutdownScannersAndCloseUI
In Parameters  : void,
Out Parameters : void
Description    : Send close request to option and recover scanner.
--------------------------------------------------------------------------------------*/
void CBKComDllApp::ShutdownScannersAndCloseUI()
{
	//UI close all required handles.
	//OnBnClickedButtonMainback();
	return;
}

/*--------------------------------------------------------------------------------------
Function       : PrepareValueForDispaly
In Parameters  : MAX_PIPE_DATA_REG& sMaxPipeDataReg, WCHAR *strValue, int iSizeOfBuffer,
Out Parameters : void
Description    : Prepare reg key to display on UI.
--------------------------------------------------------------------------------------*/
void CBKComDllApp::PrepareValueForDispaly(MAX_PIPE_DATA_REG& sMaxPipeDataReg, WCHAR* strValue, int iSizeOfBuffer)
{
	if ((sMaxPipeDataReg.eMessageInfo == Network) || (sMaxPipeDataReg.eMessageInfo == Network_Report))
	{
		swprintf_s(strValue, iSizeOfBuffer, L"%s : %s", sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
	}
	else if ((sMaxPipeDataReg.eMessageInfo == AppInit) || (sMaxPipeDataReg.eMessageInfo == AppInit_Report))
	{
		LPCTSTR lpstrHive = (sMaxPipeDataReg.Hive_Type == HKEY_LOCAL_MACHINE ? _T("HKEY_LOCAL_MACHINE") : _T("HKEY_USERS"));
		if (sMaxPipeDataReg.strKey)
		{
			size_t iLen = wcslen(sMaxPipeDataReg.strKey);
			if (sMaxPipeDataReg.strKey[iLen - 1] == '\\')
			{
				sMaxPipeDataReg.strKey[iLen - 1] = '\0';
			}
		}
		swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"\\\"%s\" : \"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue, (LPCTSTR)sMaxPipeDataReg.bData, (LPCTSTR)sMaxPipeDataReg.bReplaceData);
	}
	else if ((sMaxPipeDataReg.eMessageInfo == Module) || (sMaxPipeDataReg.eMessageInfo == Module_Report))
	{
		swprintf_s(strValue, iSizeOfBuffer, L"%s : %s", sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
	}
	else if ((sMaxPipeDataReg.eMessageInfo == Virus_Process) || (sMaxPipeDataReg.eMessageInfo == Virus_File)
		|| (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair_Report)
		|| (sMaxPipeDataReg.eMessageInfo == Virus_Process_Report) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Report)
		|| (sMaxPipeDataReg.eMessageInfo == Cookie_New))
	{
		wcscpy_s(strValue, iSizeOfBuffer, sMaxPipeDataReg.strKey);
	}
	else
	{
		LPCTSTR lpstrHive = (sMaxPipeDataReg.Hive_Type == HKEY_LOCAL_MACHINE ? _T("HKEY_LOCAL_MACHINE") : _T("HKEY_USERS"));
		if (sMaxPipeDataReg.strKey)
		{
			size_t iLen = wcslen(sMaxPipeDataReg.strKey);
			if (sMaxPipeDataReg.strKey[iLen - 1] == '\\')
			{
				sMaxPipeDataReg.strKey[iLen - 1] = '\0';
			}
		}
		if (sMaxPipeDataReg.iSizeOfData > 0)
		{
			if (sMaxPipeDataReg.Type_Of_Data == REG_DWORD && sMaxPipeDataReg.iSizeOfData > 0)
			{
				DWORD dwData = 0;
				memcpy(&dwData, sMaxPipeDataReg.bData, sMaxPipeDataReg.iSizeOfData);
				if (sMaxPipeDataReg.eMessageInfo == RegFix)
				{
					DWORD dwReplaceData = 0;
					if (sMaxPipeDataReg.bReplaceData && sMaxPipeDataReg.iSizeOfReplaceData > 0)
					{
						memcpy(&dwReplaceData, sMaxPipeDataReg.bReplaceData, sMaxPipeDataReg.iSizeOfReplaceData);
					}
					swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"\\\"%d\" : \"%d\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue, dwData, dwReplaceData);
				}
				else
				{
					swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"\\\"%d\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue, dwData);
				}
			}
			else if (((sMaxPipeDataReg.Type_Of_Data == REG_SZ) || (sMaxPipeDataReg.Type_Of_Data == REG_EXPAND_SZ))
				&& (sMaxPipeDataReg.iSizeOfData > 0))
			{
				if ((sMaxPipeDataReg.eMessageInfo == RegFix) && (sMaxPipeDataReg.bReplaceData && sMaxPipeDataReg.iSizeOfReplaceData > 0))
				{
					swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"\\\"%s\" : \"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue, (LPCTSTR)sMaxPipeDataReg.bData, (LPCTSTR)sMaxPipeDataReg.bReplaceData);
				}
				else
				{
					swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"\\\"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue, (LPCTSTR)sMaxPipeDataReg.bData);
				}
			}
			else // Binary || Multi_SZ Data
			{
				swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
			}
		}
		else if (wcslen(sMaxPipeDataReg.strValue) > 0)
		{
			swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
		}
		else
		{
			swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s", lpstrHive, sMaxPipeDataReg.strKey);
		}
	}
}


/*--------------------------------------------------------------------------------------
Function       : GetThreatInfo
In Parameters  : ULONG ulSpyName, CString& csSpyName, BYTE& bThreatIndex, CString& csHelpInfo, CString csKeyValue, int iTypeId
Out Parameters : bool
Description    : Get threat info
--------------------------------------------------------------------------------------*/
bool CBKComDllApp::GetThreatInfo(ULONG ulSpyName, CString& csSpyName, BYTE& bThreatIndex, CString& csHelpInfo, CString csKeyValue, int iTypeId)
{
	if (m_objThreatInfo.IsLoaded() == false)
	{
		CRegistry objReg;
		CString csMaxDBPath;
		objReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
		m_objThreatInfo.SetTempPath(csMaxDBPath);
		//m_objThreatInfo.Load(csMaxDBPath + SD_DB_SPYNAME);
	}

	TCHAR strSpyName[MAX_PATH] = { 0 };
	TCHAR strHelpInfo[1024] = { 0 };
	LPCTSTR strCatName = NULL;
	ULONG ulCatID = 0;
	if (m_objThreatInfo.SearchItem(ulSpyName, bThreatIndex, strHelpInfo, 1024, strSpyName, MAX_PATH))
	{
		if (iTypeId == /*Cookie*/ Cookie_New)
		{
			//csSpyName = csKeyValue+CString(strSpyName);
			csSpyName = csKeyValue + L"Tracking.Cookies";
		}
		else
		{
			csSpyName = CString(strSpyName);
		}

		csHelpInfo = CString(strHelpInfo);
		return true;
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : GetRegisrationStatus
In Parameters  : 
Out Parameters : REGISTRATION_STATUS
Description    :Get registration status
--------------------------------------------------------------------------------------*/
REGISTRATION_STATUS CBKComDllApp::GetRegisrationStatus()
{
	m_iControlFlag = 1;		//If register 1 else 0
	DWORD dwReg = 0;
	CRegistry objReg;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("QuarantinedCnt"), dwReg, HKEY_LOCAL_MACHINE);
	if (dwReg == 0)
	{
		m_iControlFlag = 1;
		return STATUS_REGISTERED_COPY;
	}
	else
	{
		m_iControlFlag =0;
	}
	return STATUS_UNREGISTERED_COPY;
}

/*-------------------------------------------------------------------------------------
Function		: IsSDReadyForFullScan
In Parameters	: -
Out	Parameters	: bool
Purpose			: Check on client machine all database present or not
--------------------------------------------------------------------------------------*/
bool CBKComDllApp::IsSDReadyForFullScan(bool bFullScan)
{
	CRegistry objReg;
	CString csMaxDBPath;
	objReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	if (bFullScan == false)
	{
		CRegistry objReg;
		DWORD dwValue = 0;
		objReg.Get(CSystemInfo::m_csProductRegKey, _T("FULLLIVEUPDATE"), dwValue, HKEY_LOCAL_MACHINE);
		if (dwValue == 1)
		{
			objReg.Set(CSystemInfo::m_csProductRegKey, _T("FULLLIVEUPDATE"), 0, HKEY_LOCAL_MACHINE);
			AddLogEntry(L"Ask for live update due to database file corrupted");

			AddLogEntry(L"FIC issue found. Launching Liveupdate with AUTOFULLUPDATE.");
			CString	csAppPath = CSystemInfo::m_strAppPath + (CString)LIVEUPDATE_EXE;
			SetLastError(0);

			MAX_PIPE_DATA_REG sRequest = { 0 };
			sRequest.eMessageInfo = Start_LiveUpdate_process;
			wcscpy_s(sRequest.strValue, L"-AUTOFULLUPDATE");
			CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
			objMaxCommunicator.SendData(&sRequest, sizeof(MAX_PIPE_DATA_REG));
		}
		//return true;
	}

	return true;
}

/*------------------------------------------------------------------------------------------------------------------------------------------------
Function       : GetScanByNameCount
In Parameters  : int iScanByNameArrayLen, int* ptrScanByNameCountArray
Out Parameters : void
Description    : Returns Scan by name files count
------------------------------------------------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetScanByNameCount(int iScanByNameArrayLen, int* ptrScanByNameCountArray)
{
	g_objCScanByName.ScanByNameCount(iScanByNameArrayLen, ptrScanByNameCountArray);
}

/*------------------------------------------------------------------------------------------------------------------------------------------------
Function       : GetScanByNameData
In Parameters  : ScanByNameFiles * pScanByNameDataArray, int iScanByNameDataSize
Out Parameters : void
Description    : Get Scan by name data
------------------------------------------------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetScanByNameData(ScanByNameFiles * pScanByNameDataArray, int iScanByNameDataSize)
{
	g_objCScanByName.GetScanByNameData(pScanByNameDataArray, iScanByNameDataSize);
}

/*------------------------------------------------------------------------------------------------------------------------------------------------
Function       : SetScanByNameData
In Parameters  : ScanByNameFiles * pScanByNameDataArray, int iScanByNameDataSize
Out Parameters : void
Description    : Set Scan by name data
------------------------------------------------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void SetScanByNameData(ScanByNameFiles * pScanByNameDataArray, int iScanByNameDataSize)
{
	g_objCScanByName.AddScanByNameData(pScanByNameDataArray, iScanByNameDataSize);
}

/*------------------------------------------------------------------------------------------------------------------------------------------------
Function       : RemoveScanByNameData
In Parameters  : ScanByNameFiles * pScanByNameDataArray, int iScanByNameDataSize
Out Parameters : void
Description    : Remove Scan By name data
------------------------------------------------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void RemoveScanByNameData(ScanByNameFiles * pScanByNameDataArray, int iScanByNameDataSize)
{
	g_objCScanByName.OnClickRemove(pScanByNameDataArray, iScanByNameDataSize);
}

/*------------------------------------------------------------------------------------------------------------------------------------------------
Function       : GetScanByNameCount
In Parameters  : int iScanByNameArrayLen, int* ptrScanByNameCountArray
Out Parameters : void
Description    : Returns Scan by name files count
------------------------------------------------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void ApplyScanByName()
{
	g_objCScanByName.OnClickApply();
}

/*------------------------------------------------------------------------------------------------------------------------------------------------
Function       : GetProxySetting
In Parameters  : ProxySetting * pProxySettingArray
Out Parameters : void
Description    : This function is for to get proxy setting from ProxySetting.ini
------------------------------------------------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetProxySetting(ProxySetting * pProxySettingArray)
{
	g_objCProxySetting.GetProxySetting(pProxySettingArray);
}

/*------------------------------------------------------------------------------------------------------------------------------------------------
Function       : SetProxySetting
In Parameters  : ProxySetting * pProxySettingArray
Out Parameters : void
Description    : This function is for to get proxy setting from ProxySetting.ini
------------------------------------------------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void SetProxySettings(ProxySetting * pProxySettingArray)
{
	g_objCProxySetting.SetProxySettings(pProxySettingArray);
}

/*------------------------------------------------------------------------------------------------------------------------------------------------
Function       : GetProductInformation
In Parameters  : ProductInfo * pProductInfoArray
Out Parameters : void
Description    : This function is for to get product information from registry.
------------------------------------------------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetProductInformation(ProductInfo * pProductInfoArray)
{
	g_objCProductInfo.GetCurrentVersions(pProductInfoArray);
}


/*--------------------------------------------------------------------------------------
Function       : GetApplicationWhiteListStatus
In Parameters  : 
Out Parameters : int
Description    : Get Application White List Status from Registry and returs it.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) int GetApplicationWhiteListStatus()
{ 
	int iRetuStatus = g_objMaxWhiteListMgr.GetWhiteListStatus();
	return iRetuStatus;
}

/*--------------------------------------------------------------------------------------
Function       : SetApplicationWhiteListStatus
In Parameters  :
Out Parameters : void
Description    : Set Application White List Status To Registry.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void SetApplicationWhiteListStatus(int iValue)
{
	g_objMaxWhiteListMgr.SetWhiteListStatusEx(iValue);

}


/*-------------------------------------------------------------------------------------------------------------------
Function       : ListedAppCount
In Parameters  : int iListedAppArrayLen, int* ptrListedAppArrayCountArray
Out Parameters : void
Description    : Returns White Listed and Black Listed Application Count count
-------------------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetListedAppCount(int* ptrListedAppArrayCountArray)
{
	g_objMaxWhiteListMgr.GetListedAppsCnt(ptrListedAppArrayCountArray);
}

/*--------------------------------------------------------------------------------------
Function       : GetListedApplications
In Parameters  :
Out Parameters : void
Description    : Get White listed and Black listed application from our DB.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetListedApplications(WhiteListedApps * pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps * pBlackListedAppData, int iBlackListedAppDataSize)
{
	g_objMaxWhiteListMgr.FillListedApps(pWhiteListedAppData, iWhiteListedAppDataSize, pBlackListedAppData, iBlackListedAppDataSize);
}


/*-----------------------------------------------------------------------------------------------------------
Function       : SetListedApplications
In Parameters  :
Out Parameters : void
Description    : Get White listed and Black listed application to our DB and send message to protection.
-----------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void SetListedApplications(WhiteListedApps * pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps * pBlackListedAppData, int iBlackListedAppDataSize)
{
	g_objMaxWhiteListMgr.SetListedAppsIntoDB(pWhiteListedAppData, iWhiteListedAppDataSize, pBlackListedAppData, iBlackListedAppDataSize);
}


/*-------------------------------------------------------------------------------------------------------------------
Function       : GetCryptExtCnt
In Parameters  : 
Out Parameters : int
Description    : Returns White Listed and Black Listed Application Count count
-------------------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) int GetCryptExtCnt()
{
	int iExtCnt = 0;
	iExtCnt = g_objMaxWhiteListMgr.GetCryptMonExtCnt();
	return iExtCnt;
}


/*--------------------------------------------------------------------------------------
Function       : GetExtForCryptMon
In Parameters  :
Out Parameters : void
Description    : Get Extensions from our DB.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetExtForCryptMon(CrptExtList * pCryptMonExt, int iCryptMonExtSize)
{
	g_objMaxWhiteListMgr.FillExtForCrypt(pCryptMonExt, iCryptMonExtSize);
}


/*-----------------------------------------------------------------------------------------------------------
Function       : SetDataForCrypMon
In Parameters  :
Out Parameters : void
Description    : Get White listed and Black listed application to our DB and send message to protection.
-----------------------------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void SetDataForCrypMon(WhiteListedApps * pWhiteListedAppData, int iWhiteListedAppDataSize, BlackListedApps * pBlackListedAppData, int iBlackListedAppDataSize, CrptExtList * pCryptMonExt, int iCryptMonExtSize)
{
	g_objMaxWhiteListMgr.SetCryptMonDataIntoDB(pWhiteListedAppData, iWhiteListedAppDataSize, pBlackListedAppData, iBlackListedAppDataSize, pCryptMonExt, iCryptMonExtSize);
}


/*--------------------------------------------------------------------------------------
Function       : GetCryptMonStatus
In Parameters  :
Out Parameters : int
Description    : Get Cryptmon from Registry and returs it.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) int GetCryptMonStatus()
{
	int iRetuStatus = g_objMaxWhiteListMgr.GetCryptMonStatus();
	return iRetuStatus;
}


/*--------------------------------------------------------------------------------------
Function       : SetCryptMonStatus
In Parameters  : int
Out Parameters : void
Description    : Set CryptMon Status To Registry.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void SetCryptMonStatus(int iValue)
{
	g_objMaxWhiteListMgr.SetCryptMonStatus(iValue);
}


/*--------------------------------------------------------------------------------------
Function       : GetPassMgrStatus
In Parameters  : int PassMgrDataLen, int* PassMgrData
Out Parameters : void
Description    : Get Passward manager from registry.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetPassMgrStatus(int PassMgrDataLen, int* PassMgrData)
{
	g_objPasswordManager.GetPassStatusFromReg(PassMgrDataLen, PassMgrData);
}

/*--------------------------------------------------------------------------------------
Function       : SetPassMgrStatus
In Parameters  : int iPassSetting, int iValue
Out Parameters : void
Description    : 
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void SetPassMgrStatus(int iPassSetting, int iValue)
{
	g_objPasswordManager.SetPassSettingToReg(iPassSetting, iValue);
}

/*--------------------------------------------------------------------------------------
Function       : StorePassword
In Parameters  : PasswordDetails * sPasswordDetails
Out Parameters : void
Description    : 
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void StorePassword(PasswordDetails * sPasswordDetails)
{
	g_objPasswordManager.StorePassword(sPasswordDetails);
}

/*--------------------------------------------------------------------------------------
Function       : RemovePassword
In Parameters  : 
Out Parameters : void
Description    :
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool RemovePassword()
{
	bool bRetStatus = g_objPasswordManager.RemovePassword();
	return bRetStatus;
}


/*--------------------------------------------------------------------------------------
Function       : StorePassword
In Parameters  : PasswordDetails * sPasswordDetails
Out Parameters : void
Description    :
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void ForgetPassword(PasswordDetails * sPasswordDetails)
{
	g_objPasswordManager.ShowPassword(sPasswordDetails);
}


/*--------------------------------------------------------------------------------------
Function       : VerifyPassword
In Parameters  : 
Out Parameters : void
Description    :
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void VerifyPassword(WCHAR * csPassword)
{
	g_objPasswordManager.VerifyPassword(csPassword);
}


/*--------------------------------------------------------------------------------------
Function       : GetUSBSettings
In Parameters  : USBSetting * pUSBSetting
Out Parameters : void
Description    : Get USB Related Settings from registry.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetUSBSettings(USBSetting * pUSBSetting)
{ 
	CUSBManager objUSBManager;
	objUSBManager.GetUSBSettings(pUSBSetting);
}

/*--------------------------------------------------------------------------------------
Function       : SetUSBSettings
In Parameters  : USBSetting * pUSBSetting
Out Parameters : void
Description    : Get USB Related Settings from registry.
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void SetUSBSettings(USBSetting * pUSBSetting)
{
	CUSBManager objUSBManager;
	objUSBManager.SetUSBSettings(pUSBSetting);
}

/*--------------------------------------------------------------------------------------
Function       : GetUSBAttachedList
In Parameters  : 
Out Parameters : void
Description    : 
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetUSBAttachedList(AttachedUSB * pAttachedUSB , int ipAttachedUSBCnt)
{
	CUSBDriveList objDeviceList;
	objDeviceList.LoadListControl(pAttachedUSB, ipAttachedUSBCnt);
}

/*--------------------------------------------------------------------------------------
Function       : GetUSBAttachedList
In Parameters  :
Out Parameters : void
Description    :
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) int GetAttachedUSBCount()
{
	CUSBDriveList objDeviceList;
	int iUSBDev = 0;
	iUSBDev = objDeviceList.GetUSBCount();
	return iUSBDev;
}

/*--------------------------------------------------------------------------------------
Function       : WhiteListUSB
In Parameters  :
Out Parameters : void
Description    :
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void WhiteListUSB(AttachedUSB * pAttachedUSB, TCHAR * szName)
{
	CUSBDriveList objDeviceList;
	objDeviceList.WhiteListUSB(pAttachedUSB, szName);
	//g_objDeviceList.LoadListControl(pAttachedUSB, ipAttachedUSBCnt);
}


/*--------------------------------------------------------------------------------------
Function       : WhiteListUSB
In Parameters  :
Out Parameters : void
Description    :
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetUSBWhiteListData(AttachedUSB * pAttachedUSB, int iAttachedUSBCnt)
{
	CUSBManager g_objUSBManager;
	g_objUSBManager.LoadUSBList(pAttachedUSB, iAttachedUSBCnt);
}

extern "C" __declspec(dllexport) int GetUSBWhiteListDataCnt()
{
	int iUCnt = 0;
	CUSBManager g_objUSBManager;
	iUCnt = g_objUSBManager.LoadUSBListCnt();
	return iUCnt;
}


/*--------------------------------------------------------------------------------------
Function       : WhiteListUSB
In Parameters  :
Out Parameters : void
Description    :
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void DeleteUSBWhiteListData(AttachedUSB * pAttachedUSB, int iAttachedUSBCnt)
{
	CUSBManager g_objUSBManager;
	g_objUSBManager.DeleteUSBList(pAttachedUSB, iAttachedUSBCnt);
}


/*--------------------------------------------------------------------------------------
Function       :
In Parameters  :
Out Parameters :
Description    :
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) int IsProductionMode()
{
	int iRetStatus = g_objRegAuth.IsProductionMode();
	return iRetStatus;
}

/*--------------------------------------------------------------------------------------
Function       : 
In Parameters  :
Out Parameters : 
Description    :
--------------------------------------------------------------------------------------*/

extern "C" __declspec(dllexport) int StoreRegTokens(TCHAR * szRefresh_token, TCHAR * szRegInfo, TCHAR * szExpInfo)
{
	return g_objRegAuth.SetLoginInfo(szRefresh_token, szRegInfo, szExpInfo);
}

/*
extern "C" __declspec(dllexport) void StoreRegTokens(TCHAR * szRefresh_token, TCHAR * szRegInfo, TCHAR * szExpInfo, TCHAR * szSubscibeInfo)
{
	g_objRegAuth.SetLoginInfo(szRefresh_token, szRegInfo, szExpInfo, szSubscibeInfo);
*/

/*--------------------------------------------------------------------------------------
Function       :
In Parameters  :
Out Parameters :
Description    :
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void GetRefreshToken(RefreshToken * pRefreshToken)
{
	g_objRegAuth.GetRefreshTokenFromReg(pRefreshToken);
}

/*--------------------------------------------------------------------------------------
Function       :
In Parameters  :
Out Parameters :
Description    :
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void UpdateToken(TCHAR * szRefresh_token, TCHAR * szRegInfo, TCHAR * szExpInfo)
{
	g_objRegAuth.UpdateToken(szRefresh_token, szRegInfo, szExpInfo);
}

/*--------------------------------------------------------------------------------------
Function       :
In Parameters  :
Out Parameters :
Description    :
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) void LogOff()
{
	g_objRegAuth.LogOff();
}


extern "C" __declspec(dllexport) int GetLoginStatus()
{
	int iRetStatus = g_objRegAuth.IsLogin();
	return iRetStatus;
}

extern "C" __declspec(dllexport) int GetCurrentLanguage()
{
	DWORD dwCurrentLanguage = 0x00;
	CProductInfo objPrd;
	CString csIniPath = objPrd.GetAppInstallPath();
	csIniPath += CString(SETTING_FOLDER) + CString(CURRENT_SETTINGS_INI);
	WCHAR szBuffer[6] = { 0 };
	GetPrivateProfileString(_T("Language"), _T("CurrentLanguage"), _T("0"), szBuffer, 6, csIniPath);
	dwCurrentLanguage = _wtoi(szBuffer);
	return dwCurrentLanguage;
}

extern "C" __declspec(dllexport) void SetCurrentLanguage(int iLang)
{
	CProductInfo objPrd;
	CString csIniPath = objPrd.GetAppInstallPath();
	csIniPath += CString(SETTING_FOLDER) + CString(CURRENT_SETTINGS_INI);
	CString csOption;
	csOption.Format(L"%d", iLang);
	WritePrivateProfileString(_T("Language"), _T("CurrentLanguage"), csOption, csIniPath);
}


/*--------------------------------------------------------------------------------------
Function       : LaunchOtherProcess
In Parameters  :
Out Parameters : bool
Description    : Call when WPF UI is Launched
--------------------------------------------------------------------------------------*/
bool CBKComDllApp::LaunchOtherProcess()
{
	bool bServiceStarted = false, bTriedLaunchingOnce = false;
	CExecuteProcess oExecuteProcess;
	CEnumProcess objEnumProcess;
	AfxBeginThread(CheckPrerequisitesThread, this);
	for (int iWait = 0; iWait < 60; iWait++)
	{
		if (objEnumProcess.IsProcessRunning(MAXWATCHDOG_SVC_EXE, false, false))
		{
			bServiceStarted = true;
			break;
		}
		else
		{
			if (!bTriedLaunchingOnce)
			{
				bTriedLaunchingOnce = true;
				CString	csAppPath = CSystemInfo::m_strAppPath + SRV_OPT_EXE;
				ShellExecute(NULL, _T("open"), csAppPath, _T("RESTARTMSG"), NULL, SW_SHOWNORMAL);
				Sleep(5 * 1000);
			}
		}
		Sleep(1000);
	}

	if (bServiceStarted == false)
	{
		CString	csAppPath = CSystemInfo::m_strAppPath + SRV_OPT_EXE;
		ShellExecute(NULL, _T("open"), csAppPath, _T("RESTARTMSG"), NULL, SW_SHOWNORMAL);
		return FALSE;
	}
	CString csFilePath = CSystemInfo::m_strAppPath + (CString)ACT_MON_TRAY_EXE;
	
	if (oExecuteProcess.StartProcessWithToken(csFilePath, _T("-NOSPL"), EXPLORE_EXE) == FALSE)
	{
		ShellExecute(NULL, _T("open"), csFilePath, _T("-NOSPL"), NULL, SW_SHOW);
	}
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: CheckPrerequisitesThread
In Parameters	: -
Out	Parameters	: bool
Purpose			: runs in a separate thread for calling CheckPrequisites
--------------------------------------------------------------------------------------*/
UINT AFX_CDECL CheckPrerequisitesThread(LPVOID lpThis)
{
	theApp.CheckPrequisites();
	CProductInfo objPrd;
	objPrd.DumpVersionInfo();
	return 0;
}
/*-------------------------------------------------------------------------------------
Function		: CheckPrequisites
In Parameters	: -
Out	Parameters	: bool
Purpose			: Check on client machine all files present or not with exact MD5
--------------------------------------------------------------------------------------*/
bool CBKComDllApp::CheckPrequisites()
{
	CRegistry objReg;
	CString csMaxDBPath;
	DWORD dwDabaseCorrupt = 0;
	DWORD dwPatch = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("AutoDatabasePatch"), dwDabaseCorrupt, HKEY_LOCAL_MACHINE);
	////objReg.Get(CSystemInfo::m_csProductRegKey, _T("AutoProductPatch"), dwPatch, HKEY_LOCAL_MACHINE);
	
	CCommonFileIntegrityCheck objCommonFileIntegrityCheck((TCHAR*)(LPCTSTR)(CSystemInfo::m_strAppPath + SD_DB_FILE_INTEGRITY_CHECK));
	if (objCommonFileIntegrityCheck.CheckBinaryFileMD5((TCHAR*)(LPCTSTR)CSystemInfo::m_strAppPath) == false)
	{
		dwPatch = 1;
		objReg.Set(CSystemInfo::m_csProductRegKey, _T("AutoProductPatch"), dwPatch, HKEY_LOCAL_MACHINE);
		AddLogEntry(L"FIC issue found. Launching Liveupdate with AUTOPRODUCTPATCH.");
		CString	csAppPath = CSystemInfo::m_strAppPath + (CString)LIVEUPDATE_EXE;
		SetLastError(0);

		MAX_PIPE_DATA_REG sRequest = { 0 };
		sRequest.eMessageInfo = Start_LiveUpdate_process;
		wcscpy_s(sRequest.strValue, L"-AUTOPRODUCTPATCH");
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
		objMaxCommunicator.SendData(&sRequest, sizeof(MAX_PIPE_DATA_REG));
	}
	else if (dwDabaseCorrupt == 1)
	{
		MAX_PIPE_DATA_REG sRequest = { 0 };
		sRequest.eMessageInfo = Start_LiveUpdate_process;
		wcscpy_s(sRequest.strValue, L"-AUTODATABASEPATCH");
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
		objMaxCommunicator.SendData(&sRequest, sizeof(MAX_PIPE_DATA_REG));
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : OpenUSBActivityLog
In Parameters  :
Out Parameters : bool
Description    : Open Usb Activity Log
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool OpenUSBActivityLog()
{
	CUSBManager objUSBManager;
	return objUSBManager.ViewUSBActivityLog();
}

/*--------------------------------------------------------------------------------------
Function       : AddExcludeEntriesinDB
In Parameters  :
Out Parameters : bool
Description    : Add exclude data folder in DB
--------------------------------------------------------------------------------------*/
extern "C" __declspec(dllexport) bool AddExcludeEntriesinDB()
{
	return g_objCExcludeDlg.AddExcludeEntriesinExDB();
}
bool CBKComDllApp::AddExcludeEntriesDB()
{
	return g_objCExcludeDlg.AddExcludeEntriesinExDB();
}