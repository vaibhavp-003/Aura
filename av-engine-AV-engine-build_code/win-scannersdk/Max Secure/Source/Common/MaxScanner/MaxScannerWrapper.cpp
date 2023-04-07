#include "stdafx.h"
#include "MaxScannerWrapper.h"
#include "EnumProcess.h"
#include "SDSystemInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CMaxScannerWrapper::CMaxScannerWrapper()
{
	m_bScannerInit = false;
	m_pCommClient = NULL;
	m_bScannerReady = false;
	memset(&m_stScannerInfo, 0, sizeof(m_stScannerInfo));
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
	m_pMaxDSrvWrapper = NULL;
	ConnectServerNew();
	InitializeScanner();
}

CMaxScannerWrapper::~CMaxScannerWrapper()
{
	DeInitializeScanner();
	DisConnectServer();

	if(m_hEvent)
	{
		CloseHandle(m_hEvent);
		m_hEvent = NULL;
	}
}

bool CMaxScannerWrapper::ConnectServerNew()
{
	bool bReturnVal = false;
	bReturnVal = ConnectServer();
	if(!bReturnVal)
	{
		// WatchDog should restart AuDBServer!
		CString csPath = GetInstallPath() + L"AuDBServer.exe";

		// Kill is AuDBServer is Hung!
		CEnumProcess oEnumProcess;
		oEnumProcess.IsProcessRunning(csPath, true);

		AddLogEntry(_T("Re-Launch AuDBServer: %s"), csPath);
		
		{
			// Ask WatchDog to re-laungh the AuDBServer!
			MAX_PIPE_DATA_REG sScanRequest = {0};
			sScanRequest.eMessageInfo = LaunchAppAsSystem;
			_tcscpy_s(sScanRequest.strValue, csPath);
			CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
			objMaxCommunicator.SendData(&sScanRequest, sizeof(MAX_PIPE_DATA_REG));
		}

		// Try once again!
		bReturnVal = ConnectServer();
	}
	return bReturnVal;
}

bool CMaxScannerWrapper::ConnectServer()
{
	try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(m_pCommClient)
		{
			SetEvent(m_hEvent);
			return true;
		}

		m_pCommClient = new CMaxCommunicator(_NAMED_PIPE_SCANNERCLIENT_TO_SCANNERSERVER);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		for(int i = 0; i < 10; i++)
		{
			memset(&m_stScannerInfo, 0, sizeof(m_stScannerInfo));
			m_stScannerInfo.eMessageInfo = SCANNER_IsScannerReady;
			m_pCommClient->SendData(&m_stScannerInfo, sizeof(m_stScannerInfo));
			m_pCommClient->ReadData(&m_stScannerInfo, sizeof(m_stScannerInfo));
			if(SCANNER_ScannerReady == m_stScannerInfo.eMessageInfo)
			{
				m_bScannerReady = true;
				break;
			}
			else
			{
				AddLogEntry(L"ScannerServer not found, hence waiting for 2 seconds to try again");
				Sleep(2 * 1000);
			}
		}

		if(!m_bScannerReady)
		{
			AddLogEntry(L"ScannerServer not found, Scanner server not connected");
			delete m_pCommClient;
			m_pCommClient = NULL;
		}

		SetEvent(m_hEvent);
		return m_bScannerReady;
	}
	catch(...)
	{
		AddLogEntry(L"Exception in ScannerWrapper::ConnectServer!");
	}
	SetEvent(m_hEvent);
	return false;
}

bool CMaxScannerWrapper::DisConnectServer()
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(m_pCommClient)
		{
			m_pCommClient->Close();
			delete m_pCommClient;
			m_pCommClient = NULL;
		}
		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in ScannerWrapper::DisConnectServer!");
	}
	SetEvent(m_hEvent);
	return false;
}

CString CMaxScannerWrapper::GetInstallPath()
{
	try
	{
        TCHAR sExeFileName[MAX_FILE_PATH]={0};
		GetModuleFileName(0, sExeFileName, MAX_FILE_PATH);

 		CString csInstallPath;
		csInstallPath = sExeFileName;

		int iPos = 0;
		iPos = csInstallPath.ReverseFind('\\');
		if(iPos == -1)
		{
			return (csInstallPath + BACK_SLASH);
		}
		else
		{
			csInstallPath = csInstallPath.Mid(0, iPos);
			return (csInstallPath + BACK_SLASH);
		}
	}
	catch(...)
	{
	}
	return CString(_T(""));
}

bool CMaxScannerWrapper::InitializeScanner()
{
	try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(m_bScannerInit)
		{
			SetEvent(m_hEvent);
			return true;
		}

		if(!m_bScannerReady)
		{
			AddLogEntry(L"ScannerServer not found, initialize Scanner failed");
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stScannerInfo, 0, sizeof(m_stScannerInfo));
		m_stScannerInfo.eMessageInfo = SCANNER_FinalConstruct;
		m_pCommClient->SendData(&m_stScannerInfo, sizeof(m_stScannerInfo));
		m_pCommClient->ReadData(&m_stScannerInfo, sizeof(m_stScannerInfo));
		m_bScannerInit = (m_stScannerInfo.eMessageInfo == SCANNER_ScannerReady);

		if(!m_pMaxDSrvWrapper)
		{
			m_pMaxDSrvWrapper = new CMaxDSrvWrapper;
			if(m_pMaxDSrvWrapper)
			{
				m_pMaxDSrvWrapper->InitializeVirusScanner();
			}
		}

		SetEvent(m_hEvent);
		return m_bScannerInit;
	}
	catch(...)
	{
		AddLogEntry(L"Exception in ScannerWrapper::InitializeScanner!");
	}

	SetEvent(m_hEvent);
	return false;
}

void CMaxScannerWrapper::DeInitializeScanner()
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(m_bScannerInit && m_pCommClient)
		{
			m_bScannerInit = false;

			WaitForScanToFinish();
			
			memset(&m_stScannerInfo, 0, sizeof(m_stScannerInfo));
			m_stScannerInfo.eMessageInfo = SCANNER_FinalRelease;
			m_pCommClient->SendData(&m_stScannerInfo, sizeof(m_stScannerInfo));
			m_pCommClient->ReadData(&m_stScannerInfo, sizeof(m_stScannerInfo));
		}

		if(m_pMaxDSrvWrapper)
		{
			m_pMaxDSrvWrapper->DeInitializeVirusScanner();
			delete m_pMaxDSrvWrapper;
			m_pMaxDSrvWrapper = NULL;
		}

		SetEvent(m_hEvent);
		return;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in ScannerWrapper::DeInitializeScanner!");
	}
	SetEvent(m_hEvent);
	return;
}

bool CMaxScannerWrapper::SetAutomationLabStatus(bool bAutomationLab)
{
	__try
	{
		if(m_bScannerInit)
		{
			WaitForSingleObject(m_hEvent, INFINITE);
			m_bScannerInit = false;

			WaitForScanToFinish();
			
			if(m_pCommClient)
			{
				MAX_SCANNER_INFO oScanInfo = {0};
				oScanInfo.eMessageInfo = SCANNER_SetAutomationLabStatus;
				m_pCommClient->SendData(&oScanInfo, sizeof(MAX_SCANNER_INFO));
				m_pCommClient->ReadData(&oScanInfo, sizeof(MAX_SCANNER_INFO));
				m_bScannerInit = true;
			}
			SetEvent(m_hEvent);
			return true;
		}
		return false;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in ScannerWrapper::SetAutomationLabStatus!");
		SetEvent(m_hEvent);
	}
	return false;
}

bool CMaxScannerWrapper::ReloadInstantINI()
{
	if(!m_bScannerInit)
	{
		return false;
	}
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		m_bScannerInit = false;

		WaitForScanToFinish();
		
		if(m_pCommClient)
		{
			MAX_SCANNER_INFO oScanInfo = {0};
			oScanInfo.eMessageInfo = SCANNER_ReloadInstantINI;
			m_pCommClient->SendData(&oScanInfo, sizeof(MAX_SCANNER_INFO));
			m_pCommClient->ReadData(&oScanInfo, sizeof(MAX_SCANNER_INFO));
			m_bScannerInit = true;
		}
		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in ScannerWrapper::ReloadInstantINI!");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxScannerWrapper::ReloadMailScannerDB()
{
	if(!m_bScannerInit)
	{
		return false;
	}
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		m_bScannerInit = false;

		WaitForScanToFinish();
		
		if(m_pCommClient)
		{
			MAX_SCANNER_INFO oScanInfo = {0};
			oScanInfo.eMessageInfo = SCANNER_ReloadMailScannerDB;
			m_pCommClient->SendData(&oScanInfo, sizeof(MAX_SCANNER_INFO));
			m_pCommClient->ReadData(&oScanInfo, sizeof(MAX_SCANNER_INFO));
			m_bScannerInit = true;
		}
		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in ScannerWrapper::ReloadMailScannerDB!");
	}
	SetEvent(m_hEvent);
	return false;
}

bool CMaxScannerWrapper::ScanFile(PMAX_SCANNER_INFO pScanInfo)
{
	if(!m_bScannerInit)
	{
		OutputDebugString(L"##### ScannerWrapper::Skipped File Scanning #####");
		OutputDebugString(pScanInfo->szFileToScan);
		return false;
	}

	__try
	{
		::InterlockedIncrement(&m_lScanFileCount);
		if(m_pCommClient)
		{
			pScanInfo->eMessageInfo = SCANNER_ScanFile;
			m_oLocalSignature.GetFileSignature(pScanInfo->szFileToScan, pScanInfo->oPEFileSigLocal, pScanInfo->oVirusDBLocal);
			m_pCommClient->SendData(pScanInfo, sizeof(MAX_SCANNER_INFO));
			m_pCommClient->ReadData(pScanInfo, sizeof(MAX_SCANNER_INFO));
			if((pScanInfo->oPEFileSigLocal.UpdateLocalDB) && (!pScanInfo->SkipPolyMorphicScan))
			{
				m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, pScanInfo->oPEFileSigLocal, pScanInfo->oVirusDBLocal);
			}
		}
		::InterlockedDecrement(&m_lScanFileCount);
		return ((pScanInfo->ThreatDetected == 1) || (pScanInfo->ThreatSuspicious == 1) ? true : false);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in ScannerWrapper::ScanFile!");
	}
	::InterlockedDecrement(&m_lScanFileCount);
	return false;
}

bool CMaxScannerWrapper::ScanAlternateDataStream(PMAX_SCANNER_INFO pScanInfo)
{
	if(!m_bScannerInit)
	{
		OutputDebugString(L"##### ScannerWrapper::Skipped ADS Scanning #####");
		OutputDebugString(pScanInfo->szFileToScan);
		return false;
	}

	__try
	{
		::InterlockedIncrement(&m_lScanFileCount);
		if(m_pCommClient)
		{
			pScanInfo->eMessageInfo = SCANNER_ScanADS;
			m_oLocalSignature.GetFileSignature(pScanInfo->szFileToScan, pScanInfo->oPEFileSigLocal, pScanInfo->oVirusDBLocal);
			m_pCommClient->SendData(pScanInfo, sizeof(MAX_SCANNER_INFO));
			m_pCommClient->ReadData(pScanInfo, sizeof(MAX_SCANNER_INFO));
			if((pScanInfo->oPEFileSigLocal.UpdateLocalDB) && (!pScanInfo->SkipPolyMorphicScan))
			{
				m_oLocalSignature.SetFileSignature(pScanInfo->szFileToScan, pScanInfo->oPEFileSigLocal, pScanInfo->oVirusDBLocal);
			}
		}
		::InterlockedDecrement(&m_lScanFileCount);
		return ((pScanInfo->ThreatDetected == 1) || (pScanInfo->ThreatSuspicious == 1) ? true : false);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in ScannerWrapper::ScanFile!");
	}
	::InterlockedDecrement(&m_lScanFileCount);
	return false;
}

void CMaxScannerWrapper::WaitForScanToFinish()
{
	while(m_lScanFileCount > 0)
	{
		Sleep(2);
	}
}

bool CMaxScannerWrapper::IsExcluded(ULONG ulThreatID, LPCTSTR szThreatName, LPCTSTR szPath)
{
	return m_pMaxDSrvWrapper && m_pMaxDSrvWrapper->IsExcluded(ulThreatID, szThreatName, szPath);
}

bool CMaxScannerWrapper::GetThreatName(ULONG ulThreatID, TCHAR *szThreatName)
{
	if(m_pMaxDSrvWrapper)
	{
		BYTE byThreatLevel = 0;
		CString csThreatName = m_pMaxDSrvWrapper->GetSpyName(ulThreatID, byThreatLevel);
		_tcscpy_s(szThreatName, MAX_PATH, csThreatName);
		return true;
	}
	return false;
}
