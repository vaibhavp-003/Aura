// MaxDBCache.cpp : Implementation of CMaxDBCache

#include "pch.h"
#include <shlobj.h>
#include "MaxDBCache.h"
#include "MaxExceptionFilter.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

extern bool RegisterWithWD();
extern BYTE HEADER_S2U[24];

CMaxDBCache::CMaxDBCache():m_objRescanDB(false),m_objFileScanStatus(false)
{
	m_lInstanceCount = 0;
	m_csLocalDBVersion = "000005000005000005";
	m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);

	::ZeroMemory(m_szAppPath,sizeof(m_szAppPath));
	SHGetFolderPath ( 0, CSIDL_COMMON_APPDATA  , 0 , 0, m_szAppPath );
}

CMaxDBCache::~CMaxDBCache()
{
	if(m_hEvent)
	{
		CloseHandle(m_hEvent);
		m_hEvent = NULL;
	}
}

void CMaxDBCache::OnDataReceivedCallBack(LPVOID lpParam)
{
	MAX_PIPE_DATA_REG *pData = (MAX_PIPE_DATA_REG*)lpParam;
	__try
	{
		bool bSendResponse = true;

		if(!pData)
		{
			return;
		}

		switch(pData->eMessageInfo)
		{
		case DBC_FinalConstruct:
			{
				pData->szGUID[0] = g_objDBCache.FinalConstruct();
			}
			break;
		case DBC_FinalRelease:
			{
				g_objDBCache.FinalRelease();
			}
			break;
		case DBC_ReloadAllDB:
			{
				pData->szGUID[0] = g_objDBCache.ReloadAllDB();
			}
			break;
		case DBC_IsExcluded:
			{
				bool bIsExcluded = false;
				pData->szGUID[0] = g_objDBCache.IsExcluded(&bIsExcluded, pData->ulSpyNameID, pData->strKey, pData->strValue);
				pData->bReplaceData[0] = bIsExcluded;
			}
			break;
		case DBC_Exclude:
			{
				pData->szGUID[0] = g_objDBCache.Exclude(pData->ulSpyNameID, pData->strKey, pData->strValue);
			}
			break;
		case DBC_Recover:
			{
				pData->szGUID[0] = g_objDBCache.Recover(pData->ulSpyNameID, pData->strKey, pData->strValue);
			}
			break;
		case DBC_GetThreatInfo:
			{
				LPTSTR szThDesc = 0;
				BYTE byThLvl = 0;
				LPTSTR szKeyValue = 0;

				szThDesc = (LPTSTR)pData->bData;
				szKeyValue = pData->strValue;
				if(wcslen(szKeyValue) != 0 )
				{
					_tcscat(szKeyValue,_T(".")); 
				}
								
				pData->szGUID[0] = g_objDBCache.GetThreatInfo(pData->ulSpyNameID, &byThLvl, pData->strKey,
					_countof(pData->strKey), szThDesc, 1024, szKeyValue, pData->eMessageInfo);
				pData->strValue[0] = byThLvl;
			}
			break;
		case DBC_GetRemoveDBData:
			{
				pData->szGUID[0] = g_objDBCache.GetRemoveDBData(pData->ulSpyNameID, pData);
			}
			break;
		case DBC_AddToRemoveDB:
			{
				PSYS_OBJ_FIXEDSIZE pstSysObjFS = (PSYS_OBJ_FIXEDSIZE)(((LPBYTE)pData) + sizeof(pData->eMessageInfo));
				pData->szGUID[0] = g_objDBCache.AddToRemoveDB(pstSysObjFS);
			}
			break;
		case DBC_AddFileToRescannedDB:
			{
				pData->szGUID[0] = g_objDBCache.AddFileToRescannedDB(pData->strKey, pData->strValue);
			}
			break;
		case DBC_SetGamingMode:
			{
				pData->szGUID[0] = g_objDBCache.SetGamingMode(pData->ulSpyNameID);
			}
			break;
		case DBC_GetScanStatus:
			{
				pData->szGUID[0] = g_objDBCache.GetScanStatus(pData->strKey, &pData->ulSpyNameID);
			}
			break;
		case DBC_SetScanStatus:
			{
				pData->szGUID[0] = g_objDBCache.SetScanStatus(pData->strKey, pData->ulSpyNameID);
			}
			break;
		case DBC_ReloadRemoveDB:
			{
				pData->szGUID[0] = g_objDBCache.ReloadRemoveDB();
			}
			break;
		case DBC_AddMailToRemoveDB:
			{
				PSYS_OBJ_FIXEDSIZE pstSysObjFS = (PSYS_OBJ_FIXEDSIZE)(((LPBYTE)pData) + sizeof(pData->eMessageInfo));
				pData->szGUID[0] = g_objDBCache.AddMailToRemoveDB(pstSysObjFS);
			}
			break;
		case DBC_GetMailRemoveDBData:
			{
				pData->szGUID[0] = g_objDBCache.GetMailRemoveDBData(pData->ulSpyNameID, pData);
			}
			break;
		case DBC_ReloadMailRemoveDB:
			{
				pData->szGUID[0] = g_objDBCache.ReloadMailRemoveDB();
			}
			break;
		case DBC_IsServerReady:
			{
				pData->eMessageInfo = DBC_ServerReady;
			}
			break;
		case Register_WD_PID:		//other than DB Cache message
			{
				bSendResponse = false;
				RegisterWithWD();
			}
			break;
		default:
			{
				TCHAR szMessage[50] = {0};
				_stprintf_s(szMessage, 50, _T("%u"), pData->eMessageInfo);
				AddLogEntry(L"Unknown message to DBCache Server: %s", szMessage);
				pData->eMessageInfo = DBC_UnSupportedCall;
				pData->ulSpyNameID = DBC_UnSupportedCall;
				_tcscpy_s(pData->strKey, _countof(pData->strKey), _T("Unsupported call"));
			}
			break;
		}

		if(bSendResponse)
		{
			g_objCommServer.SendResponse(pData);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
}

bool CMaxDBCache::ReloadAllDB()
{
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);

	ClearAllDB();
	LoadAllDB();

	SetEvent(CMaxDBCache::m_hEvent);
	return true;
}

bool CMaxDBCache::LoadAllDB()
{
	try
	{
		m_objExcludeDB.ReLoadExcludeDB();
		m_objRemoveDB.Load(m_csRemoveDB);
		m_objMailRemoveDB.Load(m_csMailRemoveDB);
		m_objRescanDB.Load(m_csRescannedDB);

		CRegKey objRegKey;
		LRESULT lResult = objRegKey.Open(HKEY_LOCAL_MACHINE, m_strProductKey, KEY_QUERY_VALUE);
		TCHAR szDBPath[MAX_PATH] = {0};
		if(lResult == ERROR_SUCCESS)
		{
			ULONG ulSize = MAX_PATH;
			objRegKey.QueryStringValue(CURRENT_MAX_DB_VAL, szDBPath, &ulSize);
		}
		objRegKey.Close();
		m_objThreatInfo.SetTempPath(szDBPath);
		/*if(!m_objThreatInfo.Load(szDBPath + CString(SD_DB_SPYNAME)))
		{
			HKEY hKey = NULL;
			DWORD dwData = 1, dwRetVal = RegOpenKeyEx(HKEY_LOCAL_MACHINE, m_strProductKey, 0, KEY_WRITE, &hKey);
			if(ERROR_SUCCESS == dwRetVal)
			{
				RegSetValueEx(hKey, _T("AutoDatabasePatch"), 0, REG_DWORD, (LPBYTE)&dwData, sizeof(dwData));
				RegCloseKey(hKey);
			}
		}*/

		GetCurrentDBVersion();
		m_objFileScanStatus.LoadByVer(m_csFileScanStatus, true, m_csLocalDBVersion);
	}
	catch(...)
	{
	}
	return true;
}

bool CMaxDBCache::ClearAllDB()
{
	try
	{
		m_objRemoveDB.Save(m_csRemoveDB);
		m_objMailRemoveDB.Save(m_csMailRemoveDB);
		m_objRemoveDB.RemoveAll();
		m_objMailRemoveDB.RemoveAll();
		m_objRescanDB.RemoveAll();
		m_objThreatInfo.RemoveAll();
		m_objFileScanStatus.Balance();
		m_objFileScanStatus.SaveByVer(m_csFileScanStatus, true, m_csLocalDBVersion);
	}
	catch(...)
	{
	}
	return true;
}

bool CMaxDBCache::SetFullLiveUpdate()
{
	try
	{
		CRegKey objRegKey;
		LRESULT lResult = objRegKey.Open(HKEY_LOCAL_MACHINE, m_strProductKey);	
		if(lResult == ERROR_SUCCESS)
		{
			DWORD dwValue = 1;
			objRegKey.SetDWORDValue(L"FULLLIVEUPDATE", dwValue);
		}
		objRegKey.Close();
	}
	catch(...)
	{
	}

	return true;
}

bool CMaxDBCache::FinalConstruct()
{
	::InterlockedIncrement(&m_lInstanceCount);
	if(m_lInstanceCount == 1)
	{
		WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
		LoadAllDB();
		SetEvent(CMaxDBCache::m_hEvent);
	}
	return true;
}

void CMaxDBCache::FinalRelease()
{
	::InterlockedDecrement(&m_lInstanceCount);
	if(m_lInstanceCount == 0)
	{
		WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
		ClearAllDB();
		SetEvent(CMaxDBCache::m_hEvent);
	}
	else
	{
		WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
		m_objRemoveDB.Save(m_csRemoveDB);
		m_objMailRemoveDB.Save(m_csMailRemoveDB);
		m_objFileScanStatus.Balance();
		m_objFileScanStatus.SaveByVer(m_csFileScanStatus, true, m_csLocalDBVersion);
		SetEvent(CMaxDBCache::m_hEvent);
	}
}

bool CMaxDBCache::SetInstallPath()
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

bool CMaxDBCache::SetProductRegKey()
{
	m_csCurrentSettingIniPath = m_strInstallPath + SETTING_FOLDER + CURRENT_SETTINGS_INI;
	TCHAR szData[MAX_PATH] = {0};
	GetPrivateProfileString(SETTING_VAL_INI, _T("PRODUCT_REG"), _T(""), szData, MAX_PATH, m_csCurrentSettingIniPath);
	m_strProductKey = szData;
	LoadLoggingLevel(m_strProductKey);
	return true;
}

bool CMaxDBCache::IsExcluded(bool * bIsExcluded, ULONG ulThreatID, LPCTSTR pThreatName, LPCTSTR pPath)
{
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
	bool bRet = false;
	if(!bRet)
	{
		LPTSTR lpData = NULL;
		bRet = m_objRescanDB.SearchItem(pPath, lpData);
	}
	if(!bRet)
	{
		bRet = m_objExcludeDB.IsFolderExcluded(pPath);
	}
	if(!bRet)
	{
		bRet = m_objExcludeDB.IsExcluded(ulThreatID, pThreatName, pPath);
	}

	*bIsExcluded = bRet;
	SetEvent(CMaxDBCache::m_hEvent);
	return bRet;
}

bool CMaxDBCache::Exclude(ULONG ulThreatID, LPCTSTR pThreatName, LPCTSTR pPath)
{
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);

	bool bResult = false;
	if(m_objExcludeDB.Exclude(ulThreatID, pThreatName, pPath))
	{
		m_objExcludeDB.SaveExcludeDB();
		bResult = true;
	}

	SetEvent(CMaxDBCache::m_hEvent);
	return bResult;
}

bool CMaxDBCache::Recover(ULONG ulThreatID, LPCTSTR pThreatName, LPCTSTR pPath)
{
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);

	bool bResult = false;
	if(m_objExcludeDB.Recover(ulThreatID, pThreatName, pPath))
	{
		m_objExcludeDB.SaveExcludeDB();
		bResult = true;
	}

	SetEvent(CMaxDBCache::m_hEvent);
	return bResult;
}

bool CMaxDBCache::GetThreatInfo(ULONG ulThreatID, BYTE* byThreatLevel, LPTSTR szThreatName, DWORD cchThreatName, LPTSTR szThreatInfo, DWORD cchThreatInfo, LPTSTR szKeyValue, int iTypeId)
{
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
	BYTE bThreatLevel = NULL;

	if(m_objThreatInfo.SearchItem(ulThreatID, bThreatLevel, szThreatInfo, cchThreatInfo, szThreatName, cchThreatName))
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
		SetEvent(CMaxDBCache::m_hEvent);
		return false;
	}

	if(_tcscmp(szThreatName, L"Malware.Generic.512") == 0)
	{
		TCHAR szFormat[MAX_PATH] = {0};
		_stprintf_s(szFormat, L"Failed to retrieve Threat Name for ID: %ld", ulThreatID);
		AddLogEntry(szFormat);
	}

	SetEvent(CMaxDBCache::m_hEvent);
	return true;
}

bool CMaxDBCache::GetRemoveDBData(ULONG ulSpyID, MAX_PIPE_DATA_REG * pMaxPipeDataReg)
{
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
	SYS_OBJ oRemoveDB = {0};
	bool bFound = false, bResult = false;

	oRemoveDB.iIndex = ulSpyID;
	bFound = m_objRemoveDB.Search(oRemoveDB);
	if(bFound)
	{
		pMaxPipeDataReg->eMessageInfo = oRemoveDB.dwType;
		pMaxPipeDataReg->ulSpyNameID = oRemoveDB.dwSpywareID;
		pMaxPipeDataReg->Hive_Type = (HKEY)oRemoveDB.ulptrHive;
		if(oRemoveDB.szKey)
		{
			wcscpy_s(pMaxPipeDataReg->strKey, oRemoveDB.szKey);
		}
		if(oRemoveDB.szValue)
		{
			wcscpy_s(pMaxPipeDataReg->strValue, oRemoveDB.szValue);
		}
		if(oRemoveDB.dwRegDataSize)
		{
			memcpy_s(pMaxPipeDataReg->bData, MAX_PATH*4, oRemoveDB.byData, oRemoveDB.dwRegDataSize);
		}
		if(oRemoveDB.dwReplaceRegDataSize)
		{
			memcpy_s(pMaxPipeDataReg->bReplaceData, MAX_PATH*4, oRemoveDB.byReplaceData, oRemoveDB.dwReplaceRegDataSize);
		}
		pMaxPipeDataReg->iSizeOfData = oRemoveDB.dwRegDataSize;
		pMaxPipeDataReg->iSizeOfReplaceData = oRemoveDB.dwReplaceRegDataSize;
		pMaxPipeDataReg->Type_Of_Data = oRemoveDB.wRegDataType;
		wcscpy_s(pMaxPipeDataReg->strBackup, oRemoveDB.szBackupFileName);
		bResult = true;
	}

	SetEvent(CMaxDBCache::m_hEvent);
	return bResult;
}

bool CMaxDBCache::AddToRemoveDB(PSYS_OBJ_FIXEDSIZE pSysObjFixed)
{
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
	bool bResult = false;
	SYS_OBJ oSysObj = {0};

	oSysObj.dwType = pSysObjFixed->dwType;
	oSysObj.dwSpywareID = pSysObjFixed->dwSpywareID;
	oSysObj.szKey = pSysObjFixed->szKey;
	oSysObj.szBackupFileName = pSysObjFixed->szBackupFileName;
	oSysObj.u64DateTime = pSysObjFixed->u64DateTime;
	oSysObj.ulptrHive = pSysObjFixed->ulptrHive;
	oSysObj.szValue = pSysObjFixed->szValue;
	oSysObj.byData = pSysObjFixed->byData;
	oSysObj.dwRegDataSize = pSysObjFixed->dwRegDataSize;
	oSysObj.byReplaceData = pSysObjFixed->byReplaceData;
	oSysObj.dwReplaceRegDataSize = pSysObjFixed->dwReplaceRegDataSize;
	oSysObj.wRegDataType = pSysObjFixed->wRegDataType;

	if(m_objRemoveDB.Add(oSysObj))
	{
		bResult = true;
	}
	SetEvent(CMaxDBCache::m_hEvent);
	return bResult;
}

bool CMaxDBCache::AddFileToRescannedDB(LPCTSTR szFilePath, LPCTSTR szSpyName)
{
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
	bool bResult = false;
	LPTSTR lpData = NULL;

	if(!m_objRescanDB.SearchItem(szFilePath, lpData))
	{
		if(m_objRescanDB.AppendItem(szFilePath, szSpyName))
		{
			m_objRescanDB.Balance();
			m_objRescanDB.Save(m_csRescannedDB);
			bResult = true;
		}
	}

	SetEvent(CMaxDBCache::m_hEvent);
	return bResult;
}

bool CMaxDBCache::SetGamingMode(ULONG ulGamingMode)
{
	BOOL bRetVal = FALSE;

	if(ulGamingMode)
	{
		bRetVal = SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
	}
	else
	{
		bRetVal = SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
	}

	return bRetVal? true: false;
}

bool CMaxDBCache::GetScanStatus(LPCTSTR szFileName, ULONG* ulStatus)
{
	bool bRetVal = false;
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
	bRetVal = m_objFileScanStatus.SearchItem(szFileName, ulStatus);
	SetEvent(CMaxDBCache::m_hEvent);
	return bRetVal;
}

bool CMaxDBCache::SetScanStatus(LPCTSTR szFileName, ULONG ulStatus)
{
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
	if(ulStatus == FSS_SCAN_COMPLETED || ulStatus == FSS_REPAIR_COMPLETED)
	{
		m_objFileScanStatus.DeleteItem(szFileName);
	}
	else
	{
		if(!m_objFileScanStatus.UpdateData(szFileName, ulStatus))
		{
			m_objFileScanStatus.AppendItem(szFileName, ulStatus);
		}
	}
	SetEvent(CMaxDBCache::m_hEvent);
	return true;
}

void CMaxDBCache::GetCurrentDBVersion()
{
	try
	{
		CRegKey objRegKey;
		LRESULT lResult = objRegKey.Open(HKEY_LOCAL_MACHINE, m_strProductKey, KEY_QUERY_VALUE);
		if(lResult == ERROR_SUCCESS)
		{
			TCHAR szData[MAX_PATH] = {0};
			CString csDatabase = _T("000000");

			wmemset(szData, 0, MAX_PATH);
			ULONG ulLen = MAX_PATH;
			objRegKey.QueryStringValue(L"VirusVersionNo", szData, &ulLen);
			CString csVirusPatch = CString(szData);

			wmemset(szData, 0, MAX_PATH);
			ulLen = MAX_PATH;
			objRegKey.QueryStringValue(VIRUSDBUPDATECOUNT, szData, &ulLen);
			CString csVirusDBUpdateCount = CString(szData);

			csDatabase.Remove('.');
			csVirusPatch.Remove('.');
			csVirusDBUpdateCount.Remove('.');
			csDatabase = csDatabase.Right(6);
			csVirusPatch = csVirusPatch.Right(6);
			csVirusDBUpdateCount = csVirusDBUpdateCount.Right(6);
			m_csLocalDBVersion.Format("%06S%06S%06S", csDatabase, csVirusPatch, csVirusDBUpdateCount);
			if(m_csLocalDBVersion.Trim().GetLength() < 18)
			{
				m_csLocalDBVersion = "000005000005000005";
			}
			objRegKey.Close();
		}
	}
	catch(...)
	{

	}
}

bool CMaxDBCache::ReloadRemoveDB()
{
	try
	{
		WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
		m_objRemoveDB.RemoveAll();
		m_objRemoveDB.Load(m_csRemoveDB);
		SetEvent(CMaxDBCache::m_hEvent);
		return true;
	}
	catch(...)
	{

	}

	SetEvent(CMaxDBCache::m_hEvent);
	return true;
}

bool CMaxDBCache::AddMailToRemoveDB(PSYS_OBJ_FIXEDSIZE pSysObjFixed)
{
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
	bool bResult = false;
	SYS_OBJ oSysObj = {0};

	oSysObj.dwType = pSysObjFixed->dwType;
	oSysObj.dwSpywareID = pSysObjFixed->dwSpywareID;
	oSysObj.szKey = pSysObjFixed->szKey;
	oSysObj.szBackupFileName = pSysObjFixed->szBackupFileName;
	oSysObj.u64DateTime = pSysObjFixed->u64DateTime;
	oSysObj.ulptrHive = pSysObjFixed->ulptrHive;
	oSysObj.szValue = pSysObjFixed->szValue;
	oSysObj.byData = pSysObjFixed->byData;
	oSysObj.dwRegDataSize = pSysObjFixed->dwRegDataSize;
	oSysObj.byReplaceData = pSysObjFixed->byReplaceData;
	oSysObj.dwReplaceRegDataSize = pSysObjFixed->dwReplaceRegDataSize;
	oSysObj.wRegDataType = pSysObjFixed->wRegDataType;

	if(m_objMailRemoveDB.Add(oSysObj))
	{
		bResult = true;
	}

	SetEvent(CMaxDBCache::m_hEvent);
	return bResult;
}

bool CMaxDBCache::GetMailRemoveDBData(ULONG ulSpyID, MAX_PIPE_DATA_REG * pMaxPipeDataReg)
{
	WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
	SYS_OBJ oRemoveDB = {0};
	bool bFound = false, bResult = false;

	oRemoveDB.iIndex = ulSpyID;
	bFound = m_objMailRemoveDB.Search(oRemoveDB);
	if(bFound)
	{
		pMaxPipeDataReg->eMessageInfo = oRemoveDB.dwType;
		pMaxPipeDataReg->ulSpyNameID = oRemoveDB.dwSpywareID;
		pMaxPipeDataReg->Hive_Type = (HKEY)oRemoveDB.ulptrHive;
		if(oRemoveDB.szKey)
		{
			wcscpy_s(pMaxPipeDataReg->strKey, oRemoveDB.szKey);
		}
		if(oRemoveDB.szValue)
		{
			wcscpy_s(pMaxPipeDataReg->strValue, oRemoveDB.szValue);
		}
		if(oRemoveDB.dwRegDataSize)
		{
			memcpy_s(pMaxPipeDataReg->bData, MAX_PATH*4, oRemoveDB.byData, oRemoveDB.dwRegDataSize);
		}
		if(oRemoveDB.dwReplaceRegDataSize)
		{
			memcpy_s(pMaxPipeDataReg->bReplaceData, MAX_PATH*4, oRemoveDB.byReplaceData, oRemoveDB.dwReplaceRegDataSize);
		}
		pMaxPipeDataReg->iSizeOfData = oRemoveDB.dwRegDataSize;
		pMaxPipeDataReg->iSizeOfReplaceData = oRemoveDB.dwReplaceRegDataSize;
		pMaxPipeDataReg->Type_Of_Data = oRemoveDB.wRegDataType;
		wcscpy_s(pMaxPipeDataReg->strBackup, oRemoveDB.szBackupFileName);
		bResult = true;
	}

	SetEvent(CMaxDBCache::m_hEvent);
	return bResult;
}

bool CMaxDBCache::ReloadMailRemoveDB()
{
	try
	{
		WaitForSingleObject(CMaxDBCache::m_hEvent, INFINITE);
		m_objMailRemoveDB.RemoveAll();
		m_objMailRemoveDB.Load(m_csMailRemoveDB);
		SetEvent(CMaxDBCache::m_hEvent);
	}
	catch(...)
	{

	}
	return true;
}

void CMaxDBCache::InitialSettings()
{
	SetInstallPath();
	SetProductRegKey();

	m_objExcludeDB.SetDatabasePath(m_strInstallPath + _T("Quarantine\\"));
	m_csRemoveDB = m_strInstallPath + SD_DB_REMOVE;
	m_csMailRemoveDB = m_strInstallPath + SD_DB_MAIL_REMOVE;
	m_csRescannedDB = m_strInstallPath + RESCAN_FILES_DB;
	m_csFileScanStatus = m_strInstallPath + SD_DB_FILE_SCAN_STATUS;

	CString csActMonKey = m_strProductKey + _T("\\Active Protection");
	CRegKey objRegKey;
	LRESULT lResult = objRegKey.Open(HKEY_LOCAL_MACHINE, csActMonKey, KEY_QUERY_VALUE);
	if(lResult == ERROR_SUCCESS)
	{
		DWORD dwData = 0;
		objRegKey.QueryDWORDValue(GAMINGMODE_KEY, dwData);
		if(1 == dwData)
		{
			SetGamingMode(1);
		}
	}
	objRegKey.Close();	
}