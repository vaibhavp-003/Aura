#include "pch.h"
#include <shlwapi.h>
#include "MaxSecureScanner.h"
#include "ReferencesScanner.h"
#include "MaxExceptionFilter.h"
#include "OptionTabFunctions.h"
#include "SUUU2Info.h"
#include "UUU2Info.h"
#include "UU2Info.h"
#include "S2U.h"
#include "CPUInfo.h"
#include "ProductInfo.h"
#include "SDSystemInfo.h"
#include "MaxSecure.h"
#include "ProcessSync.h"
#include "UserTrackingSystem.h"

extern CMaxSecureApp theApp;

SENDMESSAGETOUI		CMaxSecureScanner::m_pSendMessageToUI		= NULL;
STARTSCANNING		CMaxSecureScanner::m_lpStartScanning		= NULL;
STOPSCANNING		CMaxSecureScanner::m_lpStopScanning			= NULL;
PERFORMDBACTION		CMaxSecureScanner::m_lpPerformDBAction		= NULL;
PERFORMREGACTION	CMaxSecureScanner::m_lpPerformRegAction		= NULL;
REMOVESPLSPY		CMaxSecureScanner::m_lpRemoveSplSpy			= NULL;
QUARANTINERTKT		CMaxSecureScanner::m_lpQuarantineRtKtFile	= NULL;
ISRESTARTREQUIRED	CMaxSecureScanner::m_lpSplSpyRestartRequired = NULL;
STARTSCANNINGForRef	CMaxSecureScanner::m_lpStartScanningForRef	= NULL;
PERFORMRECOVER		CMaxSecureScanner::m_lpRecoverAction		= NULL;
PERFORMSCANFILE		CMaxSecureScanner::m_lpScanFileAction		= NULL;
PERFORMQUARANTINE	CMaxSecureScanner::m_lpPerformQuarantine	= NULL;
INITIALIZEDLL		CMaxSecureScanner::m_lInitializeDLL			= NULL;
DEINITIALIZEDLL		CMaxSecureScanner::m_lDeInitializeDLL		= NULL;
RELOADMAILSCANERDB	CMaxSecureScanner::m_lpReloadMailScannerDB	= NULL;
SKIPFOLDER          CMaxSecureScanner::m_lpSkipFolder           = NULL;
MAX_PIPE_DATA		CMaxSecureScanner::m_oMaxPipeData			= {0};
CSysFiles			CMaxSecureScanner::m_objSysFiles;
CReferencesScanner	CMaxSecureScanner::m_objRefScanner;
CS2U				CMaxSecureScanner::m_objFilesList(false);
CS2U				CMaxSecureScanner::m_objFoldersList(false);
CU2U				CMaxSecureScanner::m_oSpyNameFoundDB(false);
bool				CMaxSecureScanner::m_bThreatCommunity		= false;
CZipArchive			CMaxSecureScanner::m_Arc;
ULONG64				CMaxSecureScanner::m_ulDate = 0;
DWORD				CMaxSecureScanner::m_dwTime = 0;
CU2Info				CMaxSecureScanner::m_objSpyFoundList(true);
ULONG				CMaxSecureScanner::m_iIndex					= 0;
bool				CMaxSecureScanner::m_bNewFilesAdded			= false;
bool				CMaxSecureScanner::m_bStopScanning			= false;
CMaxDSrvWrapper		*CMaxSecureScanner::m_pMaxDSrvWrapper		= NULL;
CThreatInfo			*CMaxSecureScanner::m_pThreatInfo			= NULL;
CMapStringToString	CMaxSecureScanner::m_objSpyFoundIDMapping;
DWORD				CMaxSecureScanner::m_dwAutomationLab = 0;
DWORD				CMaxSecureScanner::m_dwCookiesCount = 0;
DWORD				CMaxSecureScanner::m_dwTrojanCount = 0;
DWORD				CMaxSecureScanner::m_dwVirusCount = 0;

CString m_csScanDetectedIni=L"";
/*--------------------------------------------------------------------------------------
Function       : CMaxSecureScanner
In Parameters  : 
Out Parameters : 
Description    : Constructor
Author & Date  : Darshan Singh Virdi & 23 Apr, 2010.
---------------- ----------------------------------------------------------------------*/
CMaxSecureScanner::CMaxSecureScanner(void)
{
	memset(m_hScanDll, 0, sizeof(m_hScanDll));
	m_pMaxPipeDataCmd = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : ~CMaxSecureScanner
In Parameters  : 
Out Parameters : 
Description    : Destructor
Author & Date  : Darshan Singh Virdi & 23 Apr, 2010.
--------------------------------------------------------------------------------------*/
CMaxSecureScanner::~CMaxSecureScanner(void)
{
	for(int i = 0; i < _countof(m_hScanDll); i++)
	{
		if(m_hScanDll[i])
		{
			FreeLibrary(m_hScanDll[i]);
			m_hScanDll[i] = NULL;
		}
	}
	m_pMaxPipeDataCmd = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxSecureScanner::StartScanningWithParams
In Parameters  : LPMAX_PIPE_DATA lpMaxPipeData, 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 23 Apr, 2010.
--------------------------------------------------------------------------------------*/
void CMaxSecureScanner::StartScanningWithParams(LPMAX_PIPE_DATA lpMaxPipeData)
{
	if(m_bStopScanning)
	{
		SendMessageToUI(Finished_Scanning);
		return;
	}
	CCPUInfo objCPUInfo;
	int indexScanType = eSCANDB;
	int iUsbScan = 0;
	int iMacLearning = 0;
	iUsbScan = lpMaxPipeData->sScanOptions.IsUSBScanner;
	iMacLearning = lpMaxPipeData->sScanOptions.MachineLearning;
	if(objCPUInfo.GetMajorOSVersion() >= 6)
	{
		indexScanType = eAntiRootkit;
	}
	else
	{
		indexScanType = eSCANDB;
	}

	m_objFilesList.RemoveAll();
	m_objFoldersList.RemoveAll();
	m_objSpyFoundList.RemoveAll();
	m_iIndex = 0;

	time_t ltime = 0;
	time(&ltime);

	m_ulDate = 0;
	m_dwTime = 0;

	DateTimeForDB(ltime, m_ulDate, m_dwTime);

	CRegistry objReg;
	DWORD dw = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("ThreatCommunity"), dw, HKEY_LOCAL_MACHINE);
	if (dw == 1)
	{
		CMaxSecureScanner::m_bThreatCommunity = true;
	}

	m_dwAutomationLab = 0;
	objReg.Get(CSystemInfo::m_csProductRegKey, AUTOLATION_LAB_VAL, m_dwAutomationLab, HKEY_LOCAL_MACHINE);
	
	CString csMaxDBPath;
	objReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	m_objSysFiles.LoadSysDB(csMaxDBPath);

	m_csScanDetectedIni =L"";
	objReg.Get(CSystemInfo::m_csProductRegKey,_T("AppFolder"),m_csScanDetectedIni,HKEY_LOCAL_MACHINE);
	if(!m_csScanDetectedIni.IsEmpty())
	{
		m_csScanDetectedIni.Format(_T("%sSetting\\wormcounts.ini"),m_csScanDetectedIni);
	}

	bool bRegFixScan = (lpMaxPipeData->sScanOptions.DBScan || lpMaxPipeData->sScanOptions.SignatureScan);

	m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
	m_pMaxDSrvWrapper->InitializeDatabase();

	
	for(int iScanType = indexScanType; iScanType < eMaxScanners; iScanType++)
	{
		if(m_bStopScanning)
		{
			break;
		}

		
		m_lpStartScanning = NULL;
		m_lpStopScanning = NULL;
		if(iScanType == eSCANDB)
		{
			memcpy(&m_oMaxPipeData, lpMaxPipeData, sizeof(m_oMaxPipeData));
			lpMaxPipeData->sScanOptions.RegFixScan = 0;
			lpMaxPipeData->sScanOptions.RegFixOptionScan = 0;
			lpMaxPipeData->sScanOptions.IsUSBScanner = iUsbScan;
		}
        else if((iScanType == eKeylogger) && (!lpMaxPipeData->sScanOptions.KeyLoggerScan))
		{
			continue;
		}
        //Pavan : Commented this block to Run SpecialSpyScan on Right-Click scan & USB Scan
		/*else if((iScanType == eSplSpy) && (lpMaxPipeData->sScanOptions.CustomScan))
		{
			continue;
		} */       
		else if((iScanType == eVirusScan))
		{
			//Handled in SDScanner
			continue;
		}
		else if((iScanType == eAntiRootkit) && (!lpMaxPipeData->sScanOptions.RootkitScan))
		{
			continue;
		}
		else if((iScanType == eRegFixScan))
		{
			if(!bRegFixScan)
			{
				continue;
			}
			memset(&lpMaxPipeData->sScanOptions, 0, sizeof(SCAN_OPTIONS));
			lpMaxPipeData->sScanOptions.RegFixScan = 1;
			lpMaxPipeData->sScanOptions.IsUSBScanner = iUsbScan;
			//lpMaxPipeData->sScanOptions.MachineLearning = iMacLearning;
		}
        else if((iScanType == eReferenceScan))
		{
			if(!bRegFixScan)
			{
				continue;
			}
			dw = 0;
			objReg.Get(CSystemInfo::m_csProductRegKey, _T("ScanQuarantine"), dw, HKEY_LOCAL_MACHINE);
			memset(&lpMaxPipeData->sScanOptions, 0, sizeof(SCAN_OPTIONS));
			lpMaxPipeData->sScanOptions.ReferenceScan = 1;
			lpMaxPipeData->sScanOptions.IsUSBScanner = iUsbScan;
			//lpMaxPipeData->sScanOptions.MachineLearning = iMacLearning;
			if(dw)
			{
		    	lpMaxPipeData->sScanOptions.AutoQuarantine = 1;
			}
		}

		ScanUsingLibrary((SCANNER_TYPE)iScanType, lpMaxPipeData->sScanOptions, lpMaxPipeData->strValue);
		SendPercentageStatusToUI((SCANNER_TYPE)iScanType);
	}

	SendMessageToUI(Finished_Scanning);
	m_objFilesList.RemoveAll();
	m_objFoldersList.RemoveAll();

	m_objRefScanner.DumpLog();

	m_pMaxDSrvWrapper->DeInitializeDatabase();
	delete m_pMaxDSrvWrapper;
	m_pMaxDSrvWrapper = NULL;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxSecureScanner::ScanUsingLibrary
In Parameters  : SCANNER_TYPE eScanType, SCAN_OPTIONS &sScanOptions, const TCHAR *strDrivesToScan, 
Out Parameters : bool 
Description    : 
Author & Date  : Darshan Singh Virdi & 23 Apr, 2010.
--------------------------------------------------------------------------------------*/
bool CMaxSecureScanner::ScanUsingLibrary(SCANNER_TYPE eScanType, SCAN_OPTIONS &sScanOptions, 
									const TCHAR *strDrivesToScan)
{
	bool bRet = true;

	__try
	{
		if(eScanType == eSCANDB || eScanType == eRegFixScan || eScanType == eReferenceScan)
		{
			eScanType = eScanType == eReferenceScan ? eReferenceScan : eSCANDB;
			if(!m_hScanDll[eScanType])
			{
				m_hScanDll[eScanType] = ::LoadLibrary(_T("AuCoreScanner.dll"));
			}

			if(!m_hScanDll[eScanType])
			{
				return false;
			}

			m_lpPerformDBAction = (PERFORMDBACTION)GetProcAddress(m_hScanDll[eScanType], 
									"PerformDBAction");
			m_lpPerformRegAction = (PERFORMREGACTION)GetProcAddress(m_hScanDll[eScanType],
									"PerformRegAction");
			m_lpRecoverAction = (PERFORMRECOVER)GetProcAddress(m_hScanDll[eSCANDB], 
									"PerformRecoverAction");
			m_lpScanFileAction = (PERFORMSCANFILE)GetProcAddress(m_hScanDll[eSCANDB], 
									"PerformScanFile");
		}
		else if(eScanType == eKeylogger)
		{
			if(!m_hScanDll[eScanType])
			{
				m_hScanDll[eScanType] = ::LoadLibrary(_T("KeyloggerHandler.dll"));
			}

			if(!m_hScanDll[eScanType])
			{
				return false;
			}
			AddLogEntry(Starting_KeyLogger_Scanner, L"Keylogger Scan");
		}
		else if(eScanType == eSplSpy)
		{
			if(!m_hScanDll[eScanType])
			{
				m_hScanDll[eScanType] = ::LoadLibrary(_T("AuSpecialSpyHandler.dll"));
			}

			if(!m_hScanDll[eScanType])
			{
				return false;
			}

			m_lpRemoveSplSpy = (REMOVESPLSPY)GetProcAddress(m_hScanDll[eScanType], "RemoveSplSpys");
			m_lpSplSpyRestartRequired = (ISRESTARTREQUIRED)GetProcAddress(m_hScanDll[eScanType], "IsRestartRequired");

			AddLogEntry(Starting_SpecialSpy_Scanner, L"Special Spy Scan");
		}
		else if(eScanType == eAntiRootkit)
		{
			if(!m_hScanDll[eScanType])
			{
				m_hScanDll[eScanType] = ::LoadLibrary(_T("AntiRootKitDLL.dll"));
			}

			if(!m_hScanDll[eScanType])
			{
				return false;
			}

			m_lpQuarantineRtKtFile = (QUARANTINERTKT)GetProcAddress(m_hScanDll[eScanType], "QuarantineFile");
			/*if(eScanType == eAntiRootkit_Process)
			{
				AddLogEntry(Starting_Rootkit_Process_Scanner, L"Rootkit scan");
			}
			else
			{
				AddLogEntry(Starting_Rootkit_FileSystem_Scanner, L"Rootkit scan");
			}*/
		}

		if(eReferenceScan == eScanType)
		{
			m_lpStartScanningForRef = (STARTSCANNINGForRef)GetProcAddress(m_hScanDll[eScanType], "StartScanningForReferences");
		}
		else
		{
			m_lpStartScanning = (STARTSCANNING)GetProcAddress(m_hScanDll[eScanType], "StartScanning");
		}

		m_lpStopScanning = (STOPSCANNING)GetProcAddress(m_hScanDll[eScanType], "StopScanning");
		if(m_hScanDll[eScanType])
		{
			if(!m_bStopScanning)
			{
				if(eReferenceScan == eScanType)
				{
					m_lpStartScanningForRef((SENDMESSAGETOUIMS)SendMessageToUI, sScanOptions,
										strDrivesToScan, &m_objFilesList, &m_objFoldersList);
				}
				else
				{
					m_lpStartScanning((SENDMESSAGETOUIMS)SendMessageToUI, sScanOptions, strDrivesToScan);
				}
			}
		}

		m_lpStartScanning = NULL;
		m_lpStopScanning = NULL;
		m_lpStartScanningForRef = NULL;
		if(eScanType == eKeylogger)
		{
			AddLogEntry(Starting_KeyLogger_Scanner, L"Keylogger Scan", 0, false);
		}
		else if(eScanType == eSplSpy)
		{
			AddLogEntry(Starting_SpecialSpy_Scanner, L"Special Spy Scan", 0, false);
		}
		/*else if(eScanType == eAntiRootkit_Process)
		{
			AddLogEntry(Starting_Rootkit_Process_Scanner, L"Rootkit scan", 0, false);
		}*/
		else if(eScanType == eAntiRootkit)
		{
			AddLogEntry(Starting_Rootkit_FileSystem_Scanner, L"Rootkit scan", 0, false);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("MaxScanner DB Scanning Mode")))
	{
	}
	return bRet; 
}

/*--------------------------------------------------------------------------------------
Function       : CMaxSecureScanner::StartScanningFromUI
In Parameters  : LPMAX_PIPE_DATA lpMaxPipeData
Out Parameters : bool 
Description    : 
Author & Date  : Anand Srivastava & 16 Dec 2011
--------------------------------------------------------------------------------------*/
bool CMaxSecureScanner::StartScanningFromUI(LPMAX_PIPE_DATA lpMaxPipeData)
{
	CString csMaxDBPath;
	CRegistry objReg;

	objReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	m_objSysFiles.LoadSysDB(csMaxDBPath);

	LoadMaxSDScanner();

	if(NULL == m_hScanDll[eAntiRootkit])
	{
		m_hScanDll[eAntiRootkit] = ::LoadLibrary(_T("AntiRootKitDLL.dll"));
		if(NULL == m_hScanDll[eAntiRootkit])
		{
			return false;
		}
	}

	m_lpStartScanning = (STARTSCANNING)GetProcAddress(m_hScanDll[eAntiRootkit], "StartScanning");
	m_lpStopScanning = (STOPSCANNING)GetProcAddress(m_hScanDll[eAntiRootkit], "StopScanning");
	if(NULL == m_lpStartScanning || NULL == m_lpStopScanning)
	{
		FreeLibrary(m_hScanDll[eAntiRootkit]);
		m_hScanDll[eAntiRootkit] = NULL;
		return false;
	}

	if(!m_pMaxDSrvWrapper)
	{
		m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
		m_pMaxDSrvWrapper->InitializeDatabase();
	}

	m_oMaxPipeData.sScanOptions.AutoQuarantine = lpMaxPipeData->sScanOptions.AutoQuarantine;
	// Not used now 21-9-2022
	//m_lpStartScanning((SENDMESSAGETOUI)SendMessageToUI, lpMaxPipeData->sScanOptions, lpMaxPipeData->strValue);

	m_pMaxDSrvWrapper->DeInitializeDatabase();
	delete m_pMaxDSrvWrapper;
	m_pMaxDSrvWrapper = NULL;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : AddToScannedList
In Parameters  : LPCTSTR szScannedFilePath, DWORD dwSpyID
Out Parameters : void 
Description    : add files and folder entries to separate lists for reference scan
Author & Date  : Anand Srivastava & 8 March 2010
--------------------------------------------------------------------------------------*/
bool CMaxSecureScanner::AddToScannedList(LPCTSTR szScannedObjectPath, DWORD dwSpyID, bool bIsFile)
{
	CString csFilePath(szScannedObjectPath);
	csFilePath.MakeLower();

	if(BLANKSTRING == csFilePath)
	{
		return false;
	}

	if(bIsFile)
	{
		m_objFilesList.AppendItem(csFilePath, dwSpyID);
	}
	else
	{
		m_objFoldersList.AppendItem(csFilePath, dwSpyID);
	}

	return true;
}

BOOL CMaxSecureScanner::SendVoidMessageToUI(LPVOID lpVoid, DWORD dwSize)
{
	BOOL bRetVal = FALSE;

	RC_MAX_PIPE_DATA* pRCMaxPipeData = (RC_MAX_PIPE_DATA*)lpVoid;
	CString csDisplayName = pRCMaxPipeData->strDisplayName;
	if(csDisplayName.IsEmpty())
		return bRetVal;

	CString csKey = pRCMaxPipeData->strKey;
	CString csValue = pRCMaxPipeData->strValue;
	HKEY hRoot = NULL;
	DWORD dwType = 0;
	SD_Message_Info eSDMessageInfo;
	ULONG ulSpyNameID = 2890764;

	if( (!csDisplayName.CompareNoCase(L"Startup Program"))
		|| (!csDisplayName.CompareNoCase(L"Start Menu Item")) || (!csDisplayName.CompareNoCase(L"Shared DLL"))
		|| (!csDisplayName.CompareNoCase(L"Application Info")) || (!csDisplayName.CompareNoCase(L"Logged On User"))
		)
	{
		csKey = SplitRegKey(pRCMaxPipeData->strKey, hRoot);
		CRegistry objReg;
		if(!csValue.IsEmpty())
		{
			eSDMessageInfo = (SD_Message_Info)RegValue;

			if(!objReg.GetValueType(csKey, csValue, dwType, hRoot))
			{
				if( (!csValue.CompareNoCase(L"(Default)")) && (objReg.GetValueType(csKey, L"", dwType, hRoot)) )
					csValue = L"";
				else
					return bRetVal;
			}

			if(dwType == REG_BINARY)
				return bRetVal;

			CString csData = pRCMaxPipeData->strData;
			if(csData.IsEmpty())
			{
				BYTE byte[1000];
				objReg.Get(csKey, csValue, dwType, byte, 1000, hRoot);
				if(wcslen((const wchar_t*)byte))
					return bRetVal;
			}
		}
		else
		{
			eSDMessageInfo = (SD_Message_Info)RegKey;

			HKEY hKey;
			if(!objReg.Open(csKey, hKey, hRoot, KEY_ALL_ACCESS))
				return bRetVal;

			objReg.CloseKey(hKey);
		}
	}
	else
	{
		AddLogEntry(L"Skipping unidentified entry");
		return bRetVal;
	}

	//Report only following entries to UI, other entries will be delete directly
	if( (!csDisplayName.CompareNoCase(L"Shared DLL")) )
	{
		bRetVal = SendMessageToUI(eSDMessageInfo, eStatus_Detected, ulSpyNameID, hRoot, csKey, csValue, dwType, 
			(LPBYTE)pRCMaxPipeData->strData, wcslen(pRCMaxPipeData->strData)*sizeof(TCHAR),NULL);
	}
	else
	{
		MAX_PIPE_DATA_REG pipeData = {0};
		memset(&pipeData, 0, sizeof(MAX_PIPE_DATA_REG));

		pipeData.eMessageInfo = eSDMessageInfo;
		pipeData.ulSpyNameID = ulSpyNameID;
		pipeData.Hive_Type = hRoot;
		pipeData.iSizeOfData = wcslen(pRCMaxPipeData->strData)*sizeof(TCHAR);
		pipeData.Type_Of_Data = dwType;
		_tcscpy_s(pipeData.strKey, MAX_PATH, csKey);
		_tcscpy_s(pipeData.strValue, MAX_PATH, csValue);
		memcpy_s(pipeData.bData, sizeof(pipeData.bData), pRCMaxPipeData->strData, pipeData.iSizeOfData);

		Quarantine(&pipeData,NULL);
	}

	return bRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxDBScanner::SendMessageToUI
In Parameters  : SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, HKEY Hive_Type, 
					const WCHAR *strKey, const WCHAR *strValue, int Type_Of_Data, LPBYTE lpbData, 
					int iSizeOfData, REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
					int iSizeOfReplaceData, 
Out Parameters : BOOL CALLBACK 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
BOOL CALLBACK CMaxSecureScanner::SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus, 
												const ULONG ulSpyName, 
											 HKEY Hive_Type, const WCHAR *strKey, const WCHAR *strValue, 
											 int Type_Of_Data, LPBYTE lpbData, int iSizeOfData, 
											 REG_FIX_OPTIONS *psReg_Fix_Options, LPBYTE lpbReplaceData, 
											 int iSizeOfReplaceData, PMAX_SCANNER_INFO pScanInfo)
{
	try
	{
		time_t ltime = 0;
		time(&ltime);

		TCHAR szReplaceFile[MAX_PATH] = {0};
		if (pScanInfo != NULL)
		{
			if (m_objSysFiles.CheckSystemFile(eTypeOfScanner, strKey, szReplaceFile, _countof(szReplaceFile)))
			{
				if (szReplaceFile[0])
				{
					SendMessageToUI(System_File_Replace, eStatus, ulSpyName, 0, strKey, szReplaceFile);
					AddLogEntry(_T("SysFile-> %s"), strKey);
					AddLogEntry(_T("SysFile Replace-> %s"), szReplaceFile);
				}
				else
				{
					//SendMessageToUI(System_File_Replace_Report, eStatus, ulSpyName, 0, strKey);
					AddLogEntry(_T("SysFile: %s -> ReportOnly"), strKey);
				}

				return TRUE;
			}
		}
		else
		if(m_objSysFiles.CheckSystemFile(eTypeOfScanner, strKey, szReplaceFile, _countof(szReplaceFile)))
		{
			if(szReplaceFile[0])
			{
				SendMessageToUI(System_File_Replace, eStatus, ulSpyName, 0, strKey, szReplaceFile);
				AddLogEntry(_T("SysFile-> %s"), strKey);
				AddLogEntry(_T("SysFile Replace-> %s"), szReplaceFile);
			}
			else
			{
				//SendMessageToUI(System_File_Replace_Report, eStatus, ulSpyName, 0, strKey);
				AddLogEntry(_T("SysFile: %s -> ReportOnly"), strKey);
			}

			return TRUE;
		}

		MAX_PIPE_DATA_REG pipeData = {0};
		const int SIZEOFBUFFER = 1024*4;
		TCHAR strDisplayValue[SIZEOFBUFFER] = {0};

		memset(&pipeData, 0, sizeof(MAX_PIPE_DATA_REG));
		pipeData.eMessageInfo = eTypeOfScanner;
		pipeData.ulSpyNameID = ulSpyName;
		pipeData.Hive_Type = Hive_Type;
		pipeData.iSizeOfData = iSizeOfData;
		pipeData.iSizeOfReplaceData = iSizeOfReplaceData;
		pipeData.Type_Of_Data = Type_Of_Data;
		if(strKey)
		{
			_tcscpy_s(pipeData.strKey, MAX_PATH, strKey);
		}
		if(strValue)
		{
			_tcscpy_s(pipeData.strValue, MAX_PATH, strValue);
		}
		if(lpbData)
		{
			if(iSizeOfData < sizeof(pipeData.bData))
			{
				memcpy_s(pipeData.bData, sizeof(pipeData.bData), lpbData, iSizeOfData);
			}
			else
			{
				return TRUE;
			}
		}
		if(psReg_Fix_Options)
		{
			memcpy_s(&pipeData.sReg_Fix_Options, sizeof(REG_FIX_OPTIONS), psReg_Fix_Options, sizeof(REG_FIX_OPTIONS));
		}
		if(lpbReplaceData)
		{
			if(iSizeOfReplaceData < sizeof(pipeData.bReplaceData))
			{
				memcpy_s(pipeData.bReplaceData, sizeof(pipeData.bReplaceData), lpbReplaceData, iSizeOfReplaceData);
			}
			else
			{
				return TRUE;
			}
		}

		bool bReportEntryToUI = false;

		if((eTypeOfScanner == Status_Bar_File) || (eTypeOfScanner == Status_Bar_File_Report))
		{
			bReportEntryToUI = true;
		}
		else
		{
			// Handling for Reference Scanning and Registry Fix Scanning!
			if((eTypeOfScanner < SD_Message_Info_TYPE_REG) || (Virus_File == eTypeOfScanner)) // Its a File system Message
			{
				if(m_pThreatInfo || (m_pMaxDSrvWrapper && m_pMaxDSrvWrapper->IsExcluded(ulSpyName, strValue, strKey) == false))
				{
					m_oSpyNameFoundDB.AppendItem(ulSpyName, 0);

					switch(eTypeOfScanner)
					{
					case File:
					case MD5:
					case ExecPath:
					case GenPEScan:
					case Special_File:
					case KeyLogger_File:
					case FilePath:
					case SplSpy:
					case Pattern_File:
					case Virus_File:
					{
						m_objRefScanner.CheckAndReportReferences(strKey, ulSpyName, REF_ID_ALL, SendMessageToUI);
						AddToScannedList(strKey, ulSpyName, true);							
					}
					break;

					case Process:
					case Process_Report:
					case Cookie:
					case Cookie_Report:
					case Folder:
					case Folder_Report:
					case File_Report:
					case MD5_Report:
					case ExecPath_Report:
					case GenPEScan_Report:
					case Rootkit_Process:
					case Rootkit_Process_Report:
					case Rootkit_File:
					case Rootkit_File_Report:
					case Rootkit_Folder:
					case Rootkit_Folder_Report:
					case Special_Process:
					case Special_Process_Report:
					case Special_File_Report:
					case Special_Folder:
					case Special_Folder_Report:
					case KeyLogger_Process:
					case KeyLogger_Process_Report:
					case KeyLogger_File_Report:
					case KeyLogger_Folder:
					case KeyLogger_Folder_Report:
					case FilePath_Report:
					case SplSpy_Report:
					case System_File_Replace:
					case System_File_Replace_Report:
					case Recursive_Quarantine:
					case Recursive_Quarantine_Report:
					case Pattern_File_Report:							
						{
							AddToScannedList(strKey, ulSpyName, false);
						}
						break;
					}
					bReportEntryToUI = true;
				}
				else
				{
					pipeData.eStatus = eStatus_Excluded;
					UpdateSpyFoundStatus(&pipeData);
					AddLogEntry(L"Excluded Folder Entry: %s",strKey);
				}
			}
			else if(eTypeOfScanner < SD_Message_Info_TYPE_INFO) // Its a Registry Message
			{
				if(eTypeOfScanner == RegFix)
				{
					if(psReg_Fix_Options->FIX_TYPE == FIX_TYPE_ONLY_IF_SPY_FOUND)
					{
						DWORD dwTemp = 0;
						if(!m_oSpyNameFoundDB.SearchItem(ulSpyName, dwTemp))
						{
							return FALSE;
						}
					}
				}

				PrepareValueToDispaly(pipeData, strDisplayValue, SIZEOFBUFFER );

				if(m_pThreatInfo || (m_pMaxDSrvWrapper && m_pMaxDSrvWrapper->IsExcluded(pipeData.ulSpyNameID, strValue, strDisplayValue) == false))
				{
					m_oSpyNameFoundDB.AppendItem(ulSpyName, 0);

					bReportEntryToUI = true;
				}
				else
				{
					pipeData.eStatus = eStatus_Excluded;
					UpdateSpyFoundStatus(&pipeData);
					AddLogEntry(L"Excluded Entry: %s",strDisplayValue);
				}
			}
			else if(eTypeOfScanner < SD_Message_Info_TYPE_ADMIN) // Its a Information Message
			{
				bReportEntryToUI = true;
				; // do nothing
			}
			else // Its a Administrative task Message
			{
				bReportEntryToUI = true;
				; // do nothing
			}
		}

		if(eTypeOfScanner == Finished_Scanning)
		{
			StartUpdateCount(L"VirusCount",m_dwVirusCount);
			StartUpdateCount(L"CookiesCount",m_dwCookiesCount);
			StartUpdateCount(L"TrojanCount",m_dwTrojanCount);
			SaveSpyFoundDB();
		}

		if(bReportEntryToUI)
		{
			if((eTypeOfScanner != Status_Bar_File) && (eTypeOfScanner != Status_Bar_File_Report)
				&& (eStatus == eStatus_Detected))
			{
				if(m_oMaxPipeData.sScanOptions.AutoQuarantine == 0)
				{
					if(eTypeOfScanner == Virus_File_Repair)
					{
						m_dwVirusCount++;
						//StartUpdateCount(L"VirusCount");
					}
					else
					{
						if(pipeData.eMessageInfo == Cookie_New)
						{
							m_dwCookiesCount++;
							//StartUpdateCount(L"CookiesCount");
						}
						else
						{
							m_dwTrojanCount++;
							//StartUpdateCount(L"TrojanCount");
						}
					}
				}
				
				
				if(m_oMaxPipeData.sScanOptions.AutoQuarantine == 1)
				{
					if(Quarantine(&pipeData, pScanInfo))
					{
						eStatus = pipeData.eStatus;
					}
				}
				
			}

			if(!m_dwAutomationLab)
			{
				if((eTypeOfScanner != Status_Bar_File) && (eTypeOfScanner != Status_Bar_File_Report))
				{
					if((eTypeOfScanner < SD_Message_Info_TYPE_REG) || (Virus_File == eTypeOfScanner)
						|| (eTypeOfScanner < SD_Message_Info_TYPE_INFO))
					{
						/*----------------------------------------------------------
								A D D E D  T O  M A K E  S P Y F O U N D  DB
						----------------------------------------------------------*/			
						//To Add in Spy Found DB
						AddInSpyFoundListStruct(&pipeData);
						/*----------------------------------------------------------*/		
					}
				}
			}

			if(m_pSendMessageToUI)
			{
				if(m_pThreatInfo && ulSpyName > 0)				// Handling for SDK
				{
					BYTE byThreatLevel = 0;
					TCHAR szThreatInfo[1024] = {0};
					TCHAR szThreatName[MAX_PATH] = {0};
					LPTSTR szKeyValue = (LPTSTR)strValue;
					if(wcslen(szKeyValue) != 0 )
					{
						_tcscat(szKeyValue,_T(".")); 
					}
					GetThreatInfo(ulSpyName, &byThreatLevel, szThreatName, MAX_PATH, szThreatInfo, 1024, szKeyValue, eTypeOfScanner);

					m_pSendMessageToUI(eTypeOfScanner, eStatus, ulSpyName, Hive_Type, strKey, szThreatName, Type_Of_Data, 
						lpbData, iSizeOfData, psReg_Fix_Options, lpbReplaceData, iSizeOfReplaceData);
				}
				else
				{
					m_pSendMessageToUI(eTypeOfScanner, eStatus, ulSpyName, Hive_Type, strKey, strValue, Type_Of_Data, 
						lpbData, iSizeOfData, psReg_Fix_Options, lpbReplaceData, iSizeOfReplaceData);
				}
			}
		}
		return TRUE;
	}
	catch(...)
	{
	}
	return FALSE;
}

void CMaxSecureScanner::StopScanning()
{
	m_bStopScanning = true;
	if(m_lpStopScanning)
	{
		m_lpStopScanning();
	}
}

void CMaxSecureScanner::SpecialQuarantine()
{
	if(m_lpRemoveSplSpy)
	{
		m_lpRemoveSplSpy();
	}
}

void CMaxSecureScanner::RestartRequired(LPMAX_PIPE_DATA lpMaxParam)
{
	lpMaxParam->ulSpyNameID = 0;			// Default Restart NOT required
	if(m_lpSplSpyRestartRequired)
	{
		if(m_lpSplSpyRestartRequired())
		{
			lpMaxParam->ulSpyNameID = 1;	// Restart IS required
		}
	}
}

void CMaxSecureScanner::SaveQuarantineDB(LPMAX_PIPE_DATA_REG lpMaxParam)
{
	if(m_lpPerformDBAction && m_lpPerformDBAction((LPMAX_PIPE_DATA)lpMaxParam))
	{
		lpMaxParam->ulSpyNameID = 1;
	}
}

bool CMaxSecureScanner::Quarantine(LPMAX_PIPE_DATA_REG lpMaxParam, PMAX_SCANNER_INFO pScanInfo)
{
	if(lpMaxParam->eMessageInfo < SD_Message_Info_TYPE_REG) //File System Message
	{
		if(m_lpPerformDBAction)
		{
			if(m_lpPerformDBAction((LPMAX_PIPE_DATA)lpMaxParam))
			{
				//m_dwQCount++;
				if(lpMaxParam->eMessageInfo == Virus_File_Repair)
					lpMaxParam->eStatus = eStatus_Repaired;
				else
					lpMaxParam->eStatus = eStatus_Quarantined;				

				UpdateSpyFoundStatus(lpMaxParam);
				return true;
			}
			else
			{
				//m_dwFailQCount++;
			}
		}
	}
	else if(lpMaxParam->eMessageInfo < SD_Message_Info_TYPE_INFO) //Registry Message
	{
		if(lpMaxParam->eMessageInfo == Cookie_New)
		{
			if(m_lpPerformDBAction)
			{
				if(m_lpPerformDBAction((LPMAX_PIPE_DATA)lpMaxParam))
				{
					//m_dwQCount++;
					if(lpMaxParam->eMessageInfo == Virus_File_Repair)
						lpMaxParam->eStatus = eStatus_Repaired;
					else
						lpMaxParam->eStatus = eStatus_Quarantined;				

					UpdateSpyFoundStatus(lpMaxParam);
					return true;
				}
				else
				{
					//m_dwFailQCount++;
				}
			}
		}
		else if(m_lpPerformRegAction)
		{
			if(m_lpPerformRegAction((LPMAX_PIPE_DATA_REG)lpMaxParam, pScanInfo))
			{
				//m_dwQCount++;
				if(lpMaxParam->eMessageInfo == Virus_File_Repair)
					lpMaxParam->eStatus = eStatus_Repaired;
				else
					lpMaxParam->eStatus = eStatus_Quarantined;

				UpdateSpyFoundStatus(lpMaxParam);
				return true;
			}
			else
			{
				//m_dwFailQCount++;
			}
		}
	}
	return false;
}

void CMaxSecureScanner::Recover(LPMAX_PIPE_DATA_REG lpMaxParam)
{
	if(!m_hScanDll[eSCANDB])
	{
		m_hScanDll[eSCANDB] = ::LoadLibrary(_T("AuCoreScanner.dll"));
		if(m_hScanDll[eSCANDB])
		{
			m_lpRecoverAction = (PERFORMRECOVER)GetProcAddress(m_hScanDll[eSCANDB], "PerformRecoverAction");
		}
	}

	if(!m_lpRecoverAction)
	{
		return;
	}

	if(m_lpRecoverAction(lpMaxParam, false))
	{
		//count++;
	}
}

void CMaxSecureScanner::ScanFile(LPMAX_PIPE_DATA_REG lpMaxParam)
{
	if(!m_hScanDll[eSCANDB])
	{
		m_hScanDll[eSCANDB] = ::LoadLibrary(_T("AuCoreScanner.dll"));
		if(m_hScanDll[eSCANDB])
		{
			m_lpScanFileAction = (PERFORMSCANFILE)GetProcAddress(m_hScanDll[eSCANDB], "PerformScanFile");
		}
	}

	if(!m_lpScanFileAction)
	{
		return;
	}

	m_lpScanFileAction(lpMaxParam);
}

void CMaxSecureScanner::Delete(LPMAX_PIPE_DATA_REG lpMaxParam)
{
	if(_waccess_s(lpMaxParam->strBackup, 0) == 0)
	{
		DeleteFile(lpMaxParam->strBackup);
	}
}

void CMaxSecureScanner::OptionTab(LPOPTION_DATA lpMaxParam)
{
	COptionTabFunctions	objOptionTabCommon;
	lpMaxParam->bReturn = objOptionTabCommon.DllFunction(lpMaxParam->iOper, lpMaxParam->strValue, lpMaxParam->hWnd);
}

void CMaxSecureScanner::ProcessCmdLog(LPVOID lpVoid)
{
	m_pMaxPipeDataCmd = NULL;
	m_pMaxPipeDataCmd = (LPMAX_PIPE_DATA_CMD)lpVoid;
}

void CMaxSecureScanner::ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid)
{
	SetSendMessage(lpDispatchMessage->pSendMessageToUI);

	if(eScanFromUI != lpDispatchMessage->eDispatch_Type && eDeInitScanDll != lpDispatchMessage->eDispatch_Type)
	{
		if(!m_lInitializeDLL)	//Is the DLL Loaded?
		{
			LoadMaxSDScanner();
		}
	}

	switch(lpDispatchMessage->eDispatch_Type)
	{
	case eInitScanDll:
		if(m_lInitializeDLL)	// Load all databases and prepare for scanning!
		{
			m_bStopScanning = false;
			
			bool	bIsUsbScan = false;
			bool	bIsMachineLearning = false;
			if (lpVoid != NULL)
			{
				LPMAX_PIPE_DATA	pTempPIP = (LPMAX_PIPE_DATA)lpVoid;
				bIsUsbScan = pTempPIP->sScanOptions.IsUSBScanner;
				bIsMachineLearning = pTempPIP->sScanOptions.MachineLearning;
			}
			m_lInitializeDLL((SENDMESSAGETOUIMS)SendMessageToUI,bIsUsbScan,bIsMachineLearning,m_pMaxPipeDataCmd);
		}
		break;
	case eDeInitScanDll:
		{
			if(m_pThreatInfo)
			{
				m_pThreatInfo->RemoveAll();
				delete m_pThreatInfo;
				m_pThreatInfo = NULL;
			}

			if(m_lDeInitializeDLL)
			{
				m_lDeInitializeDLL();
			}
		}
		break;
	case eStartScanning:
		{
			StartScanningWithParams((LPMAX_PIPE_DATA)lpVoid);
		}
		break;
	case eScanFromUI:
		{
			StartScanningFromUI((LPMAX_PIPE_DATA)lpVoid);
		}
		break;
	case eStopScanning:
		{
			StopScanning();
		}
		break;
	case eSaveQuarantineDB:
		{
			SaveQuarantineDB((LPMAX_PIPE_DATA_REG)lpVoid);
		}
		break;
	case eQuarantine:
		{
			Quarantine((LPMAX_PIPE_DATA_REG)lpVoid, NULL);
		}
		break;
	case eSpecialQuarantine:
		{
			SpecialQuarantine();
		}
		break;
	case eRestartRequired:
		{
			RestartRequired((LPMAX_PIPE_DATA)lpVoid);
		}
		break;
	case eRecover:
		{
			Recover((LPMAX_PIPE_DATA_REG)lpVoid);
		}
		break;
	case eScanFile:
		{
			ScanFile((LPMAX_PIPE_DATA_REG)lpVoid);
		}
		break;
	case eDelete:
		{
			Delete((LPMAX_PIPE_DATA_REG)lpVoid);
		}
		break;
	case eOptionTab:
		{
			OptionTab((LPOPTION_DATA)lpVoid);
		}
		break;
	case eRestartQuarantine:
		{
			if(m_lpPerformQuarantine)
			{
				m_lpPerformQuarantine((SENDMESSAGETOUIMS)SendMessageToUI);
			}
			if(m_lDeInitializeDLL)
			{
				m_lDeInitializeDLL();
			}
		}
		break;
	case eReloadMailScannerDB:
		{
			if(m_lpReloadMailScannerDB)
			{
				m_lpReloadMailScannerDB();
			}
		}
		break;
	case eSkipFolder:
		{
			if(m_lpSkipFolder)
			{
				m_lpSkipFolder();
			}
		
		}
	}
}

void CMaxSecureScanner::LoadMaxSDScanner()
{
	if(!m_hScanDll[eSCANDB])
	{
		m_hScanDll[eSCANDB] = ::LoadLibrary(_T("AuCoreScanner.dll"));
	}

	if(!m_hScanDll[eSCANDB])
	{
		return;
	}

	m_lInitializeDLL = (INITIALIZEDLL)GetProcAddress(m_hScanDll[eSCANDB], 
												"InitializeDLL");
	m_lDeInitializeDLL = (DEINITIALIZEDLL)GetProcAddress(m_hScanDll[eSCANDB], 
												"DeInitializeDLL");

	m_lpPerformQuarantine = (PERFORMQUARANTINE)GetProcAddress(m_hScanDll[eSCANDB], 
												"PerformQuarantine");
	m_lpPerformDBAction = (PERFORMDBACTION)GetProcAddress(m_hScanDll[eSCANDB], 
												"PerformDBAction");
	m_lpPerformRegAction = (PERFORMREGACTION)GetProcAddress(m_hScanDll[eSCANDB],
												"PerformRegAction");
	m_lpRecoverAction = (PERFORMRECOVER)GetProcAddress(m_hScanDll[eSCANDB], 
												"PerformRecoverAction");
	m_lpScanFileAction = (PERFORMSCANFILE)GetProcAddress(m_hScanDll[eSCANDB], 
												"PerformScanFile");
	m_lpReloadMailScannerDB = (RELOADMAILSCANERDB)GetProcAddress(m_hScanDll[eSCANDB], 
												"ReLoadMailScanerDB");
	m_lpSkipFolder = (SKIPFOLDER)GetProcAddress(m_hScanDll[eSCANDB],
												"SkipFolder");
}

void CMaxSecureScanner::PrepareValueToDispaly(MAX_PIPE_DATA_REG& sMaxPipeDataReg, WCHAR *strValue, int iSizeOfBuffer)
{
	if((sMaxPipeDataReg.eMessageInfo == Network) || (sMaxPipeDataReg.eMessageInfo == Network_Report))
	{
		swprintf_s(strValue, iSizeOfBuffer, L"%s : %s", sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
	}
	else if((sMaxPipeDataReg.eMessageInfo == AppInit) || (sMaxPipeDataReg.eMessageInfo == AppInit_Report))
	{
		LPCTSTR lpstrHive = (sMaxPipeDataReg.Hive_Type == HKEY_LOCAL_MACHINE ? _T("HKEY_LOCAL_MACHINE"): _T("HKEY_USERS"));
		if(sMaxPipeDataReg.strKey)
		{
			size_t iLen = wcslen(sMaxPipeDataReg.strKey);
			if(sMaxPipeDataReg.strKey[iLen-1] == '\\')
			{
				sMaxPipeDataReg.strKey[iLen-1] = '\0';
			}
		}
		swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"\\\"%s\" : \"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue, (LPCTSTR)sMaxPipeDataReg.bData, (LPCTSTR)sMaxPipeDataReg.bReplaceData);
	}
	else if((sMaxPipeDataReg.eMessageInfo == Module) || (sMaxPipeDataReg.eMessageInfo == Module_Report))
	{
		swprintf_s(strValue, iSizeOfBuffer, L"%s : %s", sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
	}
	else if((sMaxPipeDataReg.eMessageInfo == Virus_Process) || (sMaxPipeDataReg.eMessageInfo == Virus_File)
		|| (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Repair_Report)
		|| (sMaxPipeDataReg.eMessageInfo == Virus_Process_Report) || (sMaxPipeDataReg.eMessageInfo == Virus_File_Report))
	{
		wcscpy_s(strValue, iSizeOfBuffer, sMaxPipeDataReg.strKey);
	}
	else
	{
		LPCTSTR lpstrHive = (sMaxPipeDataReg.Hive_Type == HKEY_LOCAL_MACHINE ? _T("HKEY_LOCAL_MACHINE"): _T("HKEY_USERS"));
		if(sMaxPipeDataReg.strKey)
		{
			size_t iLen = wcslen(sMaxPipeDataReg.strKey);
			if(sMaxPipeDataReg.strKey[iLen-1] == '\\')
			{
				sMaxPipeDataReg.strKey[iLen-1] = '\0';
			}
		}
		if(sMaxPipeDataReg.iSizeOfData > 0)
		{
			if(sMaxPipeDataReg.Type_Of_Data == REG_DWORD && sMaxPipeDataReg.iSizeOfData > 0)
			{
				DWORD dwData = 0;
				memcpy(&dwData, sMaxPipeDataReg.bData, sMaxPipeDataReg.iSizeOfData);
				if(sMaxPipeDataReg.eMessageInfo == RegFix)
				{
					DWORD dwReplaceData = 0;
					if(sMaxPipeDataReg.bReplaceData && sMaxPipeDataReg.iSizeOfReplaceData > 0)
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
			else if(((sMaxPipeDataReg.Type_Of_Data == REG_SZ) || (sMaxPipeDataReg.Type_Of_Data == REG_EXPAND_SZ))
				&&(sMaxPipeDataReg.iSizeOfData > 0))
			{
				if((sMaxPipeDataReg.eMessageInfo == RegFix) && (sMaxPipeDataReg.bReplaceData && sMaxPipeDataReg.iSizeOfReplaceData > 0))
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
		else if(wcslen(sMaxPipeDataReg.strValue) > 0)
		{
			swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s\\\"%s\"", lpstrHive, sMaxPipeDataReg.strKey, sMaxPipeDataReg.strValue);
		}
		else
		{
			swprintf_s(strValue, iSizeOfBuffer, L"%s\\%s", lpstrHive, sMaxPipeDataReg.strKey);
		}
	}
}

void CMaxSecureScanner::AddAllLogFilesToZip()
{
	CProductInfo objPrdInfo;
	CFileFind objFinder;
	BOOL bMoreFiles = FALSE;
	int iCnt = 0;
	LPCTSTR szExtension = 0;

	CString csExeInstallPath = objPrdInfo.GetInstallPath();
	CString csFolderToCopy;
	csFolderToCopy = csExeInstallPath + LOGFOLDER + _T("\\");
	bMoreFiles = objFinder.FindFile(csFolderToCopy + _T("*.*"));
	if(!bMoreFiles)
	{
		return;
	}

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile();
		if(objFinder.IsDots() || objFinder.IsDirectory())
		{
			continue;
		}

		CString csFileToZip = objFinder.GetFilePath();
		m_Arc.AddNewFile(csFileToZip, -1, false);

		szExtension = _tcsrchr(csFileToZip, _T('.'));
		if(szExtension)
		{
			if(!_tcsicmp(szExtension, _T(".dmp")))
			{
				DeleteFile(csFileToZip);
			}
		}
	}
	objFinder.Close();
}

/*--------------------------------------------------------------------------------------
	Function       : IsFileLargerThanSize
	In Parameters  : LPCTSTR szFilePath, DWORD dwMaxSize
	Out Parameters : bool
	Description    : check the file size, return true if larger than the specified size
	Author & Date  : Anand Srivastava & 26/Feb/2011
--------------------------------------------------------------------------------------*/
bool CMaxSecureScanner::IsFileLargerThanSize(LPCTSTR szFilePath, DWORD dwMaxSize)
{
	WIN32_FILE_ATTRIBUTE_DATA FileInfo = {0};

	if(!GetFileAttributesEx(szFilePath, GetFileExInfoStandard, &FileInfo))
	{
		return false;
	}

	return MKQWORD(FileInfo.nFileSizeHigh, FileInfo.nFileSizeLow) >= (ULONG64(dwMaxSize));
}

/*--------------------------------------------------------------------------------------
	Function       : SaveSpyFoundDB
	In Parameters  : 
	Out Parameters : void 
	Description    : To Save SpyFound.db
	Author & Date  : Ramkrushna Shelke & 22 Dec, 2010.
--------------------------------------------------------------------------------------*/
void CMaxSecureScanner::SaveSpyFoundDB()
{	
	try
	{
		CSUUU2Info objScanInfo(false);
		CUUU2Info objDateInfo(true);
		CUU2Info objTimeInfo(true);

		CString csMachineID = L"";

		CRegistry objReg;
		if(!objReg.Get(CSystemInfo::m_csProductRegKey, L"MachineID", csMachineID, HKEY_LOCAL_MACHINE))
		{
			csMachineID = L"";
		}

		if(!m_objSpyFoundList.GetFirst())
		{
			SPY_ENTRY_INFO DummySpyInfo = {0};
			m_objSpyFoundList.AppendItem(((DWORD)-1), &DummySpyInfo);
		}

		objTimeInfo.AppendItem(m_dwTime, m_objSpyFoundList);
		objDateInfo.AppendItem(m_ulDate, objTimeInfo);
		objScanInfo.AppendItem(csMachineID, objDateInfo);

		objScanInfo.Balance();

		CProductInfo objPrdInfo;
		CString csExeInstallPath = objPrdInfo.GetInstallPath();

		TCHAR szFullFilePath[MAX_PATH] = {0};
		swprintf(szFullFilePath, MAX_PATH, L"%s%s", CSystemInfo::m_strAppPath, L"DBLock.txt");
		//Lock Set to Saving SpyFound.DB
		CProcessSync oProcessSync;
		while(!oProcessSync.SetLock(szFullFilePath))
		{
			Sleep(5);
		}

		if(_waccess(csExeInstallPath + L"\\LogFolder" , 0) != 0)
		{
			::CreateDirectory(csExeInstallPath + L"\\LogFolder", NULL);
		}

		CSUUU2Info objFullScanInfo(false);
		objFullScanInfo.Load(csExeInstallPath + L"\\LogFolder\\SpyFound.DB");
		objFullScanInfo.AppendObject(objScanInfo);
		objFullScanInfo.Balance();
		objFullScanInfo.Save(csExeInstallPath + L"\\LogFolder\\SpyFound.DB");
		m_objSpyFoundList.RemoveAll();
		m_objSpyFoundIDMapping.RemoveAll();

		//Releasing Lock 
		oProcessSync.ReleaseLock();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception in :: Scanner::SaveSpyFoundDB"));
	}
}

/*--------------------------------------------------------------------------------------
	Function       : AddInSpyFoundListStruct
	In Parameters  : MAX_PIPE_DATA_REG *pipeData
	Out Parameters : void 
	Description    : To add SPY Struct in the DB
	Author & Date  : Ramkrushna Shelke & 7 Jan, 2011.
--------------------------------------------------------------------------------------*/
void CMaxSecureScanner::AddInSpyFoundListStruct(LPMAX_PIPE_DATA_REG pMaxRegPipeData)
{
	time_t ltime = 0;
	time(&ltime);

	SPY_ENTRY_INFO oDBObj = {0};
	oDBObj.eTypeOfEntry = pMaxRegPipeData->eMessageInfo;
	oDBObj.dwSpywareID = pMaxRegPipeData->ulSpyNameID;
	oDBObj.ulHive = (ULONG64)pMaxRegPipeData->Hive_Type;
	oDBObj.dwRegDataSize = (DWORD)pMaxRegPipeData->iSizeOfData;
	oDBObj.dwReplaceRegDataSize = (DWORD)pMaxRegPipeData->iSizeOfReplaceData;
	oDBObj.szKey = (LPTSTR)pMaxRegPipeData->strKey;
	oDBObj.szValue = (LPTSTR)pMaxRegPipeData->strValue;
	oDBObj.byData = pMaxRegPipeData->bData;
	oDBObj.byReplaceData = pMaxRegPipeData->bReplaceData;
	oDBObj.wRegDataType = pMaxRegPipeData->Type_Of_Data;
	oDBObj.byFix_Action = pMaxRegPipeData->sReg_Fix_Options.FIX_ACTION;
	oDBObj.byFix_Type = pMaxRegPipeData->sReg_Fix_Options.FIX_TYPE;
	oDBObj.ul64DateTime = ltime;
	oDBObj.szBackupFileName = pMaxRegPipeData->strBackup;

	oDBObj.byStatus = (BYTE)pMaxRegPipeData->eStatus;
	m_objSpyFoundList.AppendItemAscOrder(++m_iIndex, &oDBObj);

	CString csKey, csValue;
	csKey.Format(L"%ld", m_iIndex);
	if(pMaxRegPipeData->strValue)
		csValue.Format(L"%ld_%s_%s", pMaxRegPipeData->ulSpyNameID, pMaxRegPipeData->strKey, pMaxRegPipeData->strValue);
	else
		csValue.Format(L"%ld_%s_", pMaxRegPipeData->ulSpyNameID, pMaxRegPipeData->strKey);

	m_objSpyFoundIDMapping.SetAt(csValue, csKey);
}

void CMaxSecureScanner::UpdateSpyFoundStatus(LPMAX_PIPE_DATA_REG pMaxPipeRegData)
{
	CString csKey, csValue;
	
	//Pavan : Increment ItemsCleaned or ItemsQuarantined Count
	if(pMaxPipeRegData->eStatus == eStatus_Repaired)
	{
		//OutputDebugString(_T("eStatus_Repaired"));
		CUserTrackingSystem::IncrementCount(TRACKER_ITEMS_CLEANED_COUNT);
	}
	else if(pMaxPipeRegData->eStatus == eStatus_Quarantined)
	{
		//OutputDebugString(_T("eStatus_Quarantined"));
		CUserTrackingSystem::IncrementCount(TRACKER_ITEMS_QUARANTINED_COUNT);
	}

	
	if(pMaxPipeRegData->strValue)
		csValue.Format(L"%ld_%s_%s", pMaxPipeRegData->ulSpyNameID, pMaxPipeRegData->strKey, pMaxPipeRegData->strValue);
	else
		csValue.Format(L"%ld_%s_", pMaxPipeRegData->ulSpyNameID, pMaxPipeRegData->strKey);
	m_objSpyFoundIDMapping.Lookup(csValue, csKey);

	if(csKey.IsEmpty())
		return;

	DWORD dwIndex = (DWORD)_wtol(csKey);
	LPSPY_ENTRY_INFO pDBObj = {0};
	int iCount = m_objSpyFoundList.GetCount();
	m_objSpyFoundList.SearchItem(dwIndex, pDBObj);
	if(!pDBObj)
		return;

	pDBObj->byStatus = (BYTE)pMaxPipeRegData->eStatus;
	Release((LPVOID&)pDBObj->szBackupFileName);
	pDBObj->szBackupFileName = DuplicateString(pMaxPipeRegData->strBackup);
	m_objSpyFoundList.UpdateItem(dwIndex, pDBObj);
}

CString CMaxSecureScanner::SplitRegKey(CString csRegPath, HKEY& hRoot)
{
	CString csKey;
	hRoot = NULL;
	int iPos = csRegPath.Find('\\');
	if(iPos == -1)
		return csKey;

	CString csRoot = csRegPath.Left(iPos);
	csKey = csRegPath.Mid(iPos+1);
	if(!csRoot.CompareNoCase(L"HKEY_CLASSES_ROOT"))
		hRoot = HKEY_CLASSES_ROOT;
	else if(!csRoot.CompareNoCase(L"HKEY_CURRENT_USER"))
		hRoot = HKEY_CURRENT_USER;
	else if(!csRoot.CompareNoCase(L"HKEY_LOCAL_MACHINE"))
		hRoot = HKEY_LOCAL_MACHINE;
	else if(!csRoot.CompareNoCase(L"HKEY_USERS"))
		hRoot = HKEY_USERS;
	else if(!csRoot.CompareNoCase(L"HKEY_CURRENT_CONFIG"))
		hRoot = HKEY_CURRENT_CONFIG;

	return csKey;
}

BOOL CMaxSecureScanner::SendPercentageStatusToUI(SCANNER_TYPE eScanType)
{
	BOOL bRet = FALSE;
	int iPercent = 0;

	switch(eScanType)
	{
	case eSplSpy:
		{
			iPercent = 91;
			bRet = TRUE;
		}
		break;
	case eKeylogger:
		{
			iPercent = 93;
			bRet = TRUE;
		}
		break;
	default:
		{
			bRet = FALSE;
		}
		break;
	}

	if(bRet)
	{
		CString csPercentage;
		csPercentage.Format(L"%d", iPercent);
		SendMessageToUI(Status_Bar_File_Report,eStatus_Detected, 0, 0, 0, csPercentage, 0, 0, 0, 0, 0, 0);
	}
	return bRet;
}

bool CMaxSecureScanner::GetThreatInfo(ULONG ulThreatID, BYTE* byThreatLevel, LPTSTR szThreatName, DWORD cchThreatName, LPTSTR szThreatInfo, DWORD cchThreatInfo, LPTSTR szKeyValue, int iTypeId)
{
	BYTE bThreatLevel = NULL;

	if(m_pThreatInfo->SearchItem(ulThreatID, bThreatLevel, szThreatInfo, cchThreatInfo, szThreatName, cchThreatName))
	{
		if(iTypeId == Cookie_New)
		{
			_tcscat(szKeyValue, szThreatName);
			szThreatName = szKeyValue;
		}
		*byThreatLevel = bThreatLevel;
	}
	else
	{
		return false;
	}

	return true;
}
/*--------------------------------------------------------------------------------------
Function       : CMaxSecureScanner::StartUpdateCount
In Parameters  : CString csKey,DWORD dwCount, 
Out Parameters : bool 
Description    : 
Author & Date  : 
--------------------------------------------------------------------------------------*/
bool CMaxSecureScanner::StartUpdateCount(CString csKey,DWORD dwCount)
{
	/*if(dwCount== 0)
	{
		int iCount = GetPrivateProfileInt(L"SCAN_COUNTS", csKey,0, m_csScanDetectedIni);
		dwCount = iCount+1;
	}*/
	CString csCount;
	csCount.Format(_T("%d"),dwCount);
	WritePrivateProfileStringW(L"SCAN_COUNTS", csKey, csCount, m_csScanDetectedIni);
	return true;
}