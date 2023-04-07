#pragma once
#include "MaxConstant.h"
#include "S2U.h"
#include "U2U.h"
#include "ReferencesScanner.h"
#include "SysFiles.h"
#include "ZipArchive.h"
#include "S2S.h"
#include "U2Info.h"
#include "MaxDSrvWrapper.h"
#include "ThreatInfo.h"

class CMaxSecureScanner
{
public:
	CMaxSecureScanner(void);
	virtual ~CMaxSecureScanner(void);
	
	void ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid);
	void SpecialQuarantine();
	void RestartRequired(LPMAX_PIPE_DATA lpMaxParam);
	void Recover(LPMAX_PIPE_DATA_REG lpMaxParam);
	void ScanFile(LPMAX_PIPE_DATA_REG lpMaxParam);
	void Delete(LPMAX_PIPE_DATA_REG lpMaxParam);
	void SaveQuarantineDB(LPMAX_PIPE_DATA_REG lpMaxParam);

	void StartScanningWithParams(LPMAX_PIPE_DATA lpMaxPipeData);
	void StopScanning();
	void OptionTab(LPOPTION_DATA lpMaxParam);
	
	void SetSendMessage(SENDMESSAGETOUI pSendMessageToUI)
	{
		m_pSendMessageToUI = pSendMessageToUI;
	}
	
	bool StartScanningFromUI(LPMAX_PIPE_DATA lpMaxPipeData);
	void ProcessCmdLog(LPVOID lpVoid);

private:

	static ULONG64 m_ulDate;
	static DWORD m_dwTime;

	static CThreatInfo		*m_pThreatInfo;
	static CMaxDSrvWrapper	*m_pMaxDSrvWrapper;
	static bool m_bStopScanning;
	enum SCANNER_TYPE
	{
		eAntiRootkit,
		eSCANDB,
		eVirusScan,
		eSplSpy, 
		eKeylogger,
		eRegFixScan,
		eRegistryScan,
		eReferenceScan,
		eMaxScanners,		//-> This must always be the last value in enum!
	};
	HMODULE m_hScanDll[eMaxScanners];
	bool ScanUsingLibrary(SCANNER_TYPE eScanType, SCAN_OPTIONS &sScanOptions, const TCHAR *strDrivesToScan);
	void LoadMaxSDScanner();

	//static members
	static MAX_PIPE_DATA		m_oMaxPipeData;
	static SENDMESSAGETOUI		m_pSendMessageToUI;
	static STARTSCANNING		m_lpStartScanning;
	static STARTSCANNINGForRef	m_lpStartScanningForRef;
	static STOPSCANNING			m_lpStopScanning;
	static PERFORMDBACTION		m_lpPerformDBAction;
	static PERFORMREGACTION		m_lpPerformRegAction;
	static REMOVESPLSPY			m_lpRemoveSplSpy;
	static QUARANTINERTKT		m_lpQuarantineRtKtFile;
	static ISRESTARTREQUIRED	m_lpSplSpyRestartRequired;
	static PERFORMRECOVER		m_lpRecoverAction;
	static PERFORMSCANFILE		m_lpScanFileAction;
	static PERFORMQUARANTINE	m_lpPerformQuarantine;
	static INITIALIZEDLL		m_lInitializeDLL;
	static DEINITIALIZEDLL		m_lDeInitializeDLL;
	static RELOADMAILSCANERDB	m_lpReloadMailScannerDB;
	static SKIPFOLDER           m_lpSkipFolder;
	
	static CS2U					m_objFilesList;
	static CS2U					m_objFoldersList;
	static CU2U					m_oSpyNameFoundDB;
	static CReferencesScanner	m_objRefScanner;
	static CSysFiles			m_objSysFiles;
	static DWORD				m_dwAutomationLab;

	static bool Quarantine(LPMAX_PIPE_DATA_REG lpMaxParam, PMAX_SCANNER_INFO pScanInfo);
	static void PrepareValueToDispaly(MAX_PIPE_DATA_REG& sMaxPipeDataReg, WCHAR *strValue, int iSizeOfBuffer);
	static bool AddToScannedList(LPCTSTR szScannedObjectPath, DWORD dwSpyID, bool bIsFile);
	static BOOL CALLBACK SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus = eStatus_NotApplicable, 
										const ULONG ulSpyName = 0, 
										HKEY Hive_Type = 0, const WCHAR *strKey = 0, const WCHAR *strValue = 0, 
										int Type_Of_Data = 0, LPBYTE lpbData = 0, int iSizeOfData = 0, 
										REG_FIX_OPTIONS *psReg_Fix_Options = 0, LPBYTE lpbReplaceData = 0, 
										int iSizeOfReplaceData = 0, PMAX_SCANNER_INFO pScanInfo =NULL);

	static BOOL CALLBACK SendVoidMessageToUI(LPVOID lpVoid, DWORD dwSize);
	static CString SplitRegKey(CString csRegPath, HKEY& hRoot);
	static CZipArchive m_Arc;
	static bool m_bNewFilesAdded;
	void AddAllLogFilesToZip();
	static bool IsFileLargerThanSize(LPCTSTR szFilePath, DWORD dwMaxSize);
	static void SaveSpyFoundDB();
	static void AddInSpyFoundListStruct(LPMAX_PIPE_DATA_REG pipeData);
	static void UpdateSpyFoundStatus(LPMAX_PIPE_DATA_REG pMaxPipeRegData);
	static CMapStringToString	m_objSpyFoundIDMapping;

	static bool GetThreatInfo(ULONG ulThreatID, BYTE* byThreatLevel, LPTSTR szThreatName, DWORD cchThreatName, LPTSTR szThreatInfo, DWORD cchThreatInfo, LPTSTR szKeyValue, int iTypeId);


	//CString m_csZipFilename;
	static bool			m_bThreatCommunity;
	static CU2Info		m_objSpyFoundList;
	static ULONG		m_iIndex;
	BOOL SendPercentageStatusToUI(SCANNER_TYPE eScanType);
	MAX_PIPE_DATA_CMD * m_pMaxPipeDataCmd;

	static DWORD m_dwCookiesCount;
	static DWORD m_dwTrojanCount;
	static DWORD m_dwVirusCount;
	static bool StartUpdateCount(CString csKey,DWORD dwCount=0);

};
