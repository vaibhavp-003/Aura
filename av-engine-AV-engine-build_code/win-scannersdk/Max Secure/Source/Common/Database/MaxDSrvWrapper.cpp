#include "pch.h"
#include "MaxDSrvWrapper.h"
#include "EnumProcess.h"
#include "SDSystemInfo.h"

CMaxDSrvWrapper::CMaxDSrvWrapper()
{
	m_bDBInit = false;
	m_pCommClient = NULL;
	m_bServerReady = false;
	memset(&m_stData, 0, sizeof(m_stData));
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);

	ConnectServerNew();
	InitializeDatabase();
}

CMaxDSrvWrapper::~CMaxDSrvWrapper(void)
{
	DeInitializeDatabase();
	DisConnectServer();

	if(m_hEvent)
	{
		CloseHandle(m_hEvent);
		m_hEvent = NULL;
	}
}

bool CMaxDSrvWrapper::ConnectServerNew()
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

		// Ask WatchDog to re-laungh the AuDBServer!
		MAX_PIPE_DATA_REG sScanRequest = { 0 };
		sScanRequest.eMessageInfo = LaunchAppAsSystem;
		_tcscpy_s(sScanRequest.strValue, csPath);
		CMaxCommunicator objMaxCommunicator(_NAMED_PIPE_UI_TO_SERVICE, false);
		objMaxCommunicator.SendData(&sScanRequest, sizeof(MAX_PIPE_DATA_REG));


		// Try once again!
		bReturnVal = ConnectServer();
	}
	return bReturnVal;
}

bool CMaxDSrvWrapper::ConnectServer()
{
	try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(m_pCommClient)
		{
			SetEvent(m_hEvent);
			return true;
		}

		m_pCommClient = new CMaxCommunicator(_NAMED_PIPE_DBCLIENT_TO_DBSERVER);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		for(int i = 0; i < 10; i++)
		{
			memset(&m_stData, 0, sizeof(m_stData));
			m_stData.eMessageInfo = DBC_IsServerReady;
			m_pCommClient->SendData(&m_stData, sizeof(m_stData));
			m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
			if(DBC_ServerReady == m_stData.eMessageInfo)
			{
				m_bServerReady = true;
				break;
			}
			else
			{
				AddLogEntry(L"DBServer not found, hence waiting for 2 seconds to try again");
				Sleep(2 * 1000);
			}
		}

		if(!m_bServerReady)
		{
			AddLogEntry(L"DBServer not found, db server not connected");
			delete m_pCommClient;
			m_pCommClient = NULL;
		}

		SetEvent(m_hEvent);
		return m_bServerReady;
	}

	catch(...)
	{
		AddLogEntry(L"Exception in DSrvWrapper::ConnectServer!");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::DisConnectServer()
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
		AddLogEntry(L"Exception in DSrvWrapper::DisConnectServer!");
	}

	SetEvent(m_hEvent);
	return false;
}


bool CMaxDSrvWrapper::InitializeVirusScanner()
{
	return InitializeDatabase();
}

void CMaxDSrvWrapper::DeInitializeVirusScanner()
{
	DeInitializeDatabase();
}

bool CMaxDSrvWrapper::InitializeDatabase()
{
	try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(m_bDBInit)
		{
			SetEvent(m_hEvent);
			return true;
		}

		if(!m_bServerReady)
		{
			AddLogEntry(L"DBServer not found, initialize database failed");
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_FinalConstruct;
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		m_bDBInit = chTRUE == m_stData.szGUID[0];
		SetEvent(m_hEvent);
		return m_bDBInit;
	}
	catch(...)
	{
		AddLogEntry(L"Exception in DSrvWrapper::InitializeDatabase!");
	}

	SetEvent(m_hEvent);
	return false;
}

void CMaxDSrvWrapper::DeInitializeDatabase()
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(m_bDBInit && m_pCommClient)
		{
			m_bDBInit = false;
			memset(&m_stData, 0, sizeof(m_stData));
			m_stData.eMessageInfo = DBC_FinalRelease;
			m_pCommClient->SendData(&m_stData, sizeof(m_stData));
			m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		}

		SetEvent(m_hEvent);
		return;

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::DeInitializeDatabase!");
	}

	SetEvent(m_hEvent);
	return;
}

bool CMaxDSrvWrapper::Exclude(ULONG ulThreatID, CString csThreatName, CString csPath)
{
	try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_Exclude;
		m_stData.ulSpyNameID = ulThreatID;
		_tcscpy_s(m_stData.strKey, _countof(m_stData.strKey), csThreatName);
		_tcscpy_s(m_stData.strValue, _countof(m_stData.strValue), csPath);
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	catch(...)
	{
		AddLogEntry(L"Exception in DSrvWrapper::Exclude");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::Recover(ULONG ulThreatID, CString csThreatName, CString csPath)
{
	try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_Recover;
		m_stData.ulSpyNameID = ulThreatID;
		_tcscpy_s(m_stData.strKey, _countof(m_stData.strKey), csThreatName);
		_tcscpy_s(m_stData.strValue, _countof(m_stData.strValue), csPath);
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	catch(...)
	{
		AddLogEntry(L"Exception in DSrvWrapper::Recover");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::IsExcluded(ULONG ulThreatID, CString csThreatName, CString csPath)
{
	try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_IsExcluded;
		m_stData.ulSpyNameID = ulThreatID;
		_tcscpy_s(m_stData.strKey, _countof(m_stData.strKey), csThreatName);
		_tcscpy_s(m_stData.strValue, _countof(m_stData.strValue), csPath);
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(chTRUE != m_stData.bReplaceData[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	catch(...)
	{
		AddLogEntry(L"Exception in DSrvWrapper::IsExcluded");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::GetThreatInfo(ULONG ulSpyName, CString &csSpyName, BYTE &bThreatIndex, CString &csHelpInfo, CString csKeyValue, int iTypeId)
{
	try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			bThreatIndex = 50;
			csSpyName = _T("Malware.Generic.512");
			csHelpInfo = _T("Malicious software designed to infiltrate a computer system without the owner's informed consent.");
			SetEvent(m_hEvent);
			return true;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_GetThreatInfo;
		m_stData.ulSpyNameID = ulSpyName;
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(iTypeId == Cookie_New)
		{
			csSpyName.Format(_T("%s%s"), csKeyValue,m_stData.strKey);
		}
		else
		{
			csSpyName.Format(_T("%s"), m_stData.strKey);
		}
		bThreatIndex = (BYTE)m_stData.strValue[0];
		csHelpInfo.Format(_T("%s"), ((LPTSTR)m_stData.bData));
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	catch(...)
	{
		AddLogEntry(L"Exception in DSrvWrapper::GetThreatInfo");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::AddToRemoveDB(PSYS_OBJ_FIXEDSIZE pSysObj)
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_AddToRemoveDB;
		memcpy(((LPBYTE)&m_stData) + sizeof(m_stData.eMessageInfo), pSysObj, sizeof(SYS_OBJ_FIXEDSIZE));
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::AddToRemoveDB");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::AddMailToRemoveDB(PSYS_OBJ_FIXEDSIZE pSysObj)
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_AddMailToRemoveDB;
		memcpy(((LPBYTE)&m_stData) + sizeof(m_stData.eMessageInfo), pSysObj, sizeof(SYS_OBJ_FIXEDSIZE));
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::AddMailToRemoveDB");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::AddFileToRescannedDB(LPCTSTR szFilePath, LPCTSTR szSpyName)
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_AddFileToRescannedDB;
		_tcscpy_s(m_stData.strKey, _countof(m_stData.strKey), szFilePath);
		_tcscpy_s(m_stData.strValue, _countof(m_stData.strValue), szSpyName);
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::AddFileToRescannedDB");
	}

	SetEvent(m_hEvent);
	return false;
}

CString CMaxDSrvWrapper::GetSpyName(ULONG ulSpyName, BYTE &byThreatLevel)
{
	CString csSpyName = L"", csHelpInfo, csKeyValue;
	int iTypeId = 0;
	csKeyValue = L"";
	try
	{
		GetThreatInfo(ulSpyName, csSpyName, byThreatLevel, csHelpInfo, csKeyValue, iTypeId);
		return csSpyName;
	}
	catch(...)
	{
		AddLogEntry(L"Exception in DSrvWrapper::GetSpyName");
	}

	csSpyName = BLANKSTRING;
	return csSpyName;
}

bool CMaxDSrvWrapper::GetRemoveDBData(ULONG ulSpyID, MAX_PIPE_DATA_REG *pMaxPipeDataReg)
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		pMaxPipeDataReg->eMessageInfo = DBC_GetRemoveDBData;
		pMaxPipeDataReg->ulSpyNameID = ulSpyID;
		m_pCommClient->SendData(pMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		m_pCommClient->ReadData(pMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		if(chTRUE != pMaxPipeDataReg->szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::GetRemoveDBData");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::GetMailRemoveDBData(ULONG ulSpyID, MAX_PIPE_DATA_REG *pMaxPipeDataReg)
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		pMaxPipeDataReg->eMessageInfo = DBC_GetMailRemoveDBData;
		pMaxPipeDataReg->ulSpyNameID = ulSpyID;
		m_pCommClient->SendData(pMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		m_pCommClient->ReadData(pMaxPipeDataReg, sizeof(MAX_PIPE_DATA_REG));
		if(chTRUE != pMaxPipeDataReg->szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::GetMailRemoveDBData");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::ReloadDatabase()
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_ReloadAllDB;
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::ReloadDatabase");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::ReloadRemoveDB()
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_ReloadRemoveDB;
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::ReloadRemoveDB");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::ReloadMailRemoveDB()
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_ReloadMailRemoveDB;
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::ReloadMailRemoveDB");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::SetGamingMode(bool bStatus)
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_SetGamingMode;
		m_stData.ulSpyNameID = bStatus;
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}
		
		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::SetGamingMode");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::GetScanStatus(LPCTSTR szFilePath, ULONG &ulStatus)
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_GetScanStatus;
		m_stData.ulSpyNameID = ulStatus;
		_tcscpy_s(m_stData.strKey, _countof(m_stData.strKey), szFilePath);
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		ulStatus = m_stData.ulSpyNameID;
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::GetScanStatus");
	}

	SetEvent(m_hEvent);
	return false;
}

bool CMaxDSrvWrapper::SetScanStatus(LPCTSTR szFilePath, ULONG ulStatus)
{
	__try
	{
		WaitForSingleObject(m_hEvent, INFINITE);
		if(!m_pCommClient)
		{
			SetEvent(m_hEvent);
			return false;
		}

		memset(&m_stData, 0, sizeof(m_stData));
		m_stData.eMessageInfo = DBC_SetScanStatus;
		m_stData.ulSpyNameID = ulStatus;
		_tcscpy_s(m_stData.strKey, _countof(m_stData.strKey), szFilePath);
		m_pCommClient->SendData(&m_stData, sizeof(m_stData));
		m_pCommClient->ReadData(&m_stData, sizeof(m_stData));
		if(chTRUE != m_stData.szGUID[0])
		{
			SetEvent(m_hEvent);
			return false;
		}

		SetEvent(m_hEvent);
		return true;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		AddLogEntry(L"Exception in DSrvWrapper::GetScanStatus");
	}

	SetEvent(m_hEvent);
	return false;
}

CString CMaxDSrvWrapper::GetInstallPath()
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