// MaxDBCache.cpp : Implementation of CMaxDBScanner

#include "stdafx.h"
#include <shlobj.h>
#include "MaxDBScanner.h"
#include "Registry.h"
#include "MaxExceptionFilter.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CMaxDBScanner::CMaxDBScanner()
{
	m_lInstanceCount = 0;
	m_lScanFileCount = 0;
	m_pMaxScanner = NULL;
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
}

CMaxDBScanner::~CMaxDBScanner()
{
	if(m_pMaxScanner)
	{
		delete m_pMaxScanner;
		m_pMaxScanner = NULL;
	}
	if(m_hEvent)
	{
		CloseHandle(m_hEvent);
		m_hEvent = NULL;
	}
}

void CMaxDBScanner::OnDataReceivedCallBack(LPVOID lpParam)
{
	MAX_SCANNER_INFO *pData = (MAX_SCANNER_INFO*)lpParam;
	__try
	{
		bool bSendResponse = true;

		if(!pData)
		{
			return;
		}

		switch(pData->eMessageInfo)
		{
		case SCANNER_FinalConstruct:
			{
				if(g_objDBScanner.FinalConstruct())
				{
					pData->eMessageInfo = SCANNER_ScannerReady;
				}
			}
			break;
		case SCANNER_FinalRelease:
			{
				g_objDBScanner.FinalRelease();
			}
			break;
		case SCANNER_ExitScanner:
			{
				g_objDBScanner.UnloadMainScanner();
				SetEvent(g_hServerRunningEvent);
			}
		case SCANNER_UnloadScanner:
			{
				g_objDBScanner.UnloadMainScanner();
			}
			break;
		case SCANNER_ReloadScanner:
			{
				if(g_objDBScanner.ReloadScanner())
				{
					pData->eMessageInfo = SCANNER_ScannerReady;
				}
			}
			break;
		case SCANNER_IsScannerReady:
			{
				pData->eMessageInfo = SCANNER_ScannerReady;
			}
			break;
		case SCANNER_SetAutomationLabStatus:
			{
				g_objDBScanner.SetAutomationLabStatus();
			}
			break;
		case SCANNER_ReloadInstantINI:
			{
				g_objDBScanner.ReloadInstantINI();
			}
			break;
		case SCANNER_ReloadMailScannerDB:
			{
				g_objDBScanner.ReloadMailScannerDB();
			}
			break;
		case SCANNER_ScanFile:
			{
				g_objDBScanner.ScanFile(pData);
			}
			break;
		case SCANNER_ScanADS:
			{
				g_objDBScanner.ScanAlternateDataStream(pData);
			}
			break;
		default:
			{
				TCHAR szMessage[50] = {0};
				_stprintf_s(szMessage, 50, _T("%u"), pData->eMessageInfo);
				AddLogEntry(L"Unknown message to DBScanner Server: %s", szMessage);
				pData->eMessageInfo = SCANNER_UnSupportedCall;
				_tcscpy_s(pData->szFileToScan, _countof(pData->szFileToScan), _T("Unsupported call"));
			}
			break;
		}

		if(bSendResponse)
		{
			g_objCommScanner.SendResponse(pData);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
}

bool CMaxDBScanner::ReloadScanner()
{
	bool bReturnVal = false;

	WaitForSingleObject(CMaxDBScanner::m_hEvent, INFINITE);
	m_bScannerReady = false;

	__try
	{
		UnloadScanner();
		bReturnVal = LoadScanner();
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	SetEvent(CMaxDBScanner::m_hEvent);
	return bReturnVal;
}

bool CMaxDBScanner::LoadScanner()
{
	if(!m_pMaxScanner)
	{
		OutputDebugString(L"##### LoadScanner - START!");
		CString csDPPath;
		CRegistry oRegKey;
		oRegKey.Get(m_strProductKey, CURRENT_MAX_DB_VAL, csDPPath, HKEY_LOCAL_MACHINE);

		TCHAR chDriveToScan[3] = {0};
		chDriveToScan[0] = _T('X');
		chDriveToScan[1] = _T(':');

		m_pMaxScanner = new CMaxScanner;
		m_pMaxScanner->InitializeScanner(csDPPath);
		OutputDebugString(L"##### LoadScanner - DONE!");
		m_bScannerReady = true;
		return true;
	}
	return false;
}

bool CMaxDBScanner::FinalConstruct()
{
	::InterlockedIncrement(&m_lInstanceCount);
	if(m_lInstanceCount == 1)
	{
		WaitForSingleObject(CMaxDBScanner::m_hEvent, INFINITE);

		__try
		{
			LoadScanner();
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
		}

		SetEvent(CMaxDBScanner::m_hEvent);
	}
	return true;
}

void CMaxDBScanner::UnloadMainScanner()
{
	WaitForSingleObject(CMaxDBScanner::m_hEvent, INFINITE);
	m_bScannerReady = false;

	__try
	{
		m_lInstanceCount = 0;
		if(m_pMaxScanner)
		{
			OutputDebugString(L"##### WaitForScanToFinish(START) - UnloadMainScanner!");
			WaitForScanToFinish();
			OutputDebugString(L"##### WaitForScanToFinish(DONE) - UnloadMainScanner!");

			OutputDebugString(L"##### UnloadMainScanner - START!");
			m_pMaxScanner->DeInitializeScanner();
			delete m_pMaxScanner;
			m_pMaxScanner = NULL;
			OutputDebugString(L"##### UnloadMainScanner - DONE!");
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	SetEvent(CMaxDBScanner::m_hEvent);
}

bool CMaxDBScanner::UnloadScanner()
{
	__try
	{
		if(m_pMaxScanner)
		{
			OutputDebugString(L"##### WaitForScanToFinish(START) - UnloadScanner!");
			WaitForScanToFinish();
			OutputDebugString(L"##### WaitForScanToFinish(DONE) - UnloadScanner!");

			OutputDebugString(L"##### UnloadScanner - START!");
			m_pMaxScanner->DeInitializeScanner();
			delete m_pMaxScanner;
			m_pMaxScanner = NULL;
			OutputDebugString(L"##### UnloadScanner - DONE!");
			return true;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return false;
}

void CMaxDBScanner::FinalRelease()
{
	::InterlockedDecrement(&m_lInstanceCount);
	if(m_lInstanceCount == 0)
	{
		WaitForSingleObject(CMaxDBScanner::m_hEvent, INFINITE);
		m_bScannerReady = false;
		__try
		{
			UnloadScanner();
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
		}
		SetEvent(CMaxDBScanner::m_hEvent);
	}
}

void CMaxDBScanner::InitialSettings()
{
	SetInstallPath();
	SetProductRegKey();
}

bool CMaxDBScanner::SetInstallPath()
{
	try
	{
		TCHAR sExeFileName[MAX_FILE_PATH]={0};
		GetModuleFileName((HINSTANCE)&__ImageBase, sExeFileName, MAX_FILE_PATH);

		CString csInstallPath;
		csInstallPath = sExeFileName;

		int iPos = 0;
		iPos = csInstallPath.ReverseFind('\\');
		if(iPos == -1)
		{
			m_strInstallPath = csInstallPath + BACK_SLASH;
		}
		else
		{
			csInstallPath = csInstallPath.Mid(0, iPos);
			m_strInstallPath = (csInstallPath + BACK_SLASH);
		}
	}
	catch(...)
	{
	}
	return true;
}

bool CMaxDBScanner::SetProductRegKey()
{
	m_csCurrentSettingIniPath = m_strInstallPath + SETTING_FOLDER + CURRENT_SETTINGS_INI;
	TCHAR szData[MAX_PATH] = {0};
	GetPrivateProfileString(SETTING_VAL_INI, _T("PRODUCT_REG"), _T(""), szData, MAX_PATH, m_csCurrentSettingIniPath);
	m_strProductKey = szData;
	LoadLoggingLevel(m_strProductKey);
	return true;
}

bool CMaxDBScanner::SetAutomationLabStatus()
{
	if(m_bScannerReady)
	{
		WaitForSingleObject(CMaxDBScanner::m_hEvent, INFINITE);
		m_bScannerReady = false;
		if(m_pMaxScanner)
		{
			OutputDebugString(L"##### WaitForScanToFinish(START) - SetAutomationLabStatus!");
			WaitForScanToFinish();
			OutputDebugString(L"##### WaitForScanToFinish(DONE) - SetAutomationLabStatus!");

			OutputDebugString(L"##### SetAutomationLabStatus - START!");
			CRegistry oRegKey;
			DWORD dwValue = 0;
			oRegKey.Get(m_strProductKey, _T("AutomationLab"), dwValue, HKEY_LOCAL_MACHINE);
			m_pMaxScanner->SetAutomationLabStatus((dwValue == 1 ? true : false));
			OutputDebugString(L"##### SetAutomationLabStatus - DONE!");
			m_bScannerReady = true;
		}
		SetEvent(CMaxDBScanner::m_hEvent);
	}
	return true;
}

bool CMaxDBScanner::ReloadInstantINI()
{
	if(m_bScannerReady)
	{
		WaitForSingleObject(CMaxDBScanner::m_hEvent, INFINITE);
		m_bScannerReady = false;
		if(m_pMaxScanner)
		{
			OutputDebugString(L"##### WaitForScanToFinish(START) - ReloadInstantINI!");
			WaitForScanToFinish();
			OutputDebugString(L"##### WaitForScanToFinish(DONE) - ReloadInstantINI!");

			OutputDebugString(L"##### ReloadInstantINI - START!");
			m_pMaxScanner->ReloadInstantINI();
			OutputDebugString(L"##### ReloadInstantINI - DONE!");
			m_bScannerReady = true;
		}
		SetEvent(CMaxDBScanner::m_hEvent);
	}
	return true;
}

bool CMaxDBScanner::ReloadMailScannerDB()
{
	if(m_bScannerReady)
	{
		WaitForSingleObject(CMaxDBScanner::m_hEvent, INFINITE);
		m_bScannerReady = false;
		if(m_pMaxScanner)
		{
			OutputDebugString(L"##### WaitForScanToFinish(START) - ReloadMailScannerDB!");
			WaitForScanToFinish();
			OutputDebugString(L"##### WaitForScanToFinish(DONE) - ReloadMailScannerDB!");

			OutputDebugString(L"##### ReloadMailScannerDB - START!");
			m_pMaxScanner->ReloadMailScannerDB();
			OutputDebugString(L"##### ReloadMailScannerDB - DONE!");
			m_bScannerReady = true;
		}
		SetEvent(CMaxDBScanner::m_hEvent);
	}
	return true;
}

bool CMaxDBScanner::ScanFile(PMAX_SCANNER_INFO pScanInfo)
{
	bool bReturnVal = false;
	__try
	{
		if(!m_bScannerReady)
		{
			WaitForSingleObject(CMaxDBScanner::m_hEvent, INFINITE);
			OutputDebugString(L"##### File Waited For Scanning #####");
			OutputDebugString(pScanInfo->szFileToScan);
			SetEvent(CMaxDBScanner::m_hEvent);
		}

		::InterlockedIncrement(&m_lScanFileCount);
		if(m_pMaxScanner && m_bScannerReady)
		{
			bReturnVal = m_pMaxScanner->ScanFile(pScanInfo);
		}
		::InterlockedDecrement(&m_lScanFileCount);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return bReturnVal;
}

bool CMaxDBScanner::ScanAlternateDataStream(PMAX_SCANNER_INFO pScanInfo)
{
	bool bReturnVal = false;
	__try
	{
		if(!m_bScannerReady)
		{
			WaitForSingleObject(CMaxDBScanner::m_hEvent, INFINITE);
			OutputDebugString(L"##### ADS Waited For Scanning #####");
			OutputDebugString(pScanInfo->szFileToScan);
			SetEvent(CMaxDBScanner::m_hEvent);
		}

		::InterlockedIncrement(&m_lScanFileCount);
		if(m_pMaxScanner && m_bScannerReady)
		{
			bReturnVal = m_pMaxScanner->ScanAlternateDataStream(pScanInfo);
		}
		::InterlockedDecrement(&m_lScanFileCount);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return bReturnVal;
}

void CMaxDBScanner::WaitForScanToFinish()
{
	while(m_lScanFileCount > 0)
	{
		Sleep(2);
	}
}