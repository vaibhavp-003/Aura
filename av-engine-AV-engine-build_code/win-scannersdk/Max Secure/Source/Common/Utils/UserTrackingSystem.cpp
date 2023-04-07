#include "pch.h"
#include "UserTrackingSystem.h"
#include "SDSystemInfo.h"
CString CUserTrackingSystem::m_csAppFolder = _T("");
CString CUserTrackingSystem::m_csProductKey = _T("");
CString CUserTrackingSystem::m_csTrackingKey = _T("");
CRegistry CUserTrackingSystem::m_oRegistry;

CUserTrackingSystem::CUserTrackingSystem(void)
{

}

CUserTrackingSystem::~CUserTrackingSystem(void)
{

}

void CUserTrackingSystem::SetAppFolder(CString csAppFolder)
{
	m_csAppFolder = csAppFolder;
}

void CUserTrackingSystem::SetProductKey(CString csProductKey)
{
	m_csProductKey = CSystemInfo::m_csProductRegKey;
	m_csTrackingKey = m_csProductKey + TRACKER_KEY;
	m_oRegistry.Get(m_csProductKey, _T("AppFolder"), m_csAppFolder, HKEY_LOCAL_MACHINE);
}

bool CUserTrackingSystem::IncrementCount(CString csEventName)
{
	DWORD dwCount = 0;
	if(m_oRegistry.Get(m_csTrackingKey, csEventName, dwCount, HKEY_LOCAL_MACHINE))
	{
		dwCount++;
	}
	else
	{
		dwCount = 1;	// first call!
	}

	if(!m_oRegistry.Set(m_csTrackingKey, csEventName, dwCount, HKEY_LOCAL_MACHINE))
	{
		return false;
	}

	return true;
}

bool CUserTrackingSystem::AddCount(CString csEventName, DWORD dwCount)
{
	DWORD dwOldCount = 0;
	if(m_oRegistry.Get(m_csTrackingKey, csEventName, dwOldCount, HKEY_LOCAL_MACHINE))
	{
		dwCount += dwOldCount;
	}

	if(!m_oRegistry.Set(m_csTrackingKey, csEventName, dwCount, HKEY_LOCAL_MACHINE))
	{
		return false;
	}

	return true;
}

CString CUserTrackingSystem::GetTrackingInfo()
{
	if(m_csTrackingKey.Trim().GetLength() == 0)
	{
		AddLogEntry(L"Missing Track key!");
		return _T("");
	}

	//AddLogEntry(L"Track Key: %s", m_csTrackingKey, 0, true, LOG_DEBUG);

	CString csTemp;
	CString csParamList;

	DWORD dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_QUICKSCAN_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P50=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_FULLSCAN_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P51=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_CUSTOMSCAN_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P52=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csProductKey, _T("Language"), dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P53=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_ITEMS_CLEANED_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P54=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_ITEMS_QUARANTINED_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P55=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_ITEMS_TO_CLEAN_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P56=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_ITEMS_TO_QUARANTINE_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P57=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_BUY_NOW_CLICK, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P58=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_REGISTER_NOW_CLICK, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P59=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_CLEAN_CLICKED, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P61=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_LIVEUPDATE_LAUNCHED, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P62=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_MAINUI_LAUNCHED, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P63=") + csTemp;
	}

	csTemp = _T("");
	if(m_oRegistry.Get(m_csProductKey, _T("VendorName"), csTemp, HKEY_LOCAL_MACHINE))
	{
		if(csTemp.IsEmpty() == false)
			csParamList += _T("&P64=") + csTemp;
	}

	//AddLogEntry(L"ParamList: %s", csParamList, 0, true, LOG_DEBUG);

	return csParamList;
}

CString CUserTrackingSystem::GetEliteTrackingInfo()
{
	if(m_csTrackingKey.Trim().GetLength() == 0)
	{
		AddLogEntry(L"Missing Track key!");
		return _T("");
	}

	//AddLogEntry(L"Track Key: %s", m_csTrackingKey, 0, true, LOG_DEBUG);

	CString csTemp;
	CString csParamList;


	// SiteURL=<P2>
	// dt=<usercurrenttime>
	// gid=<P9>
	// tz=<usertimezone>
	// ln=<max/language>
	// lc=<status of userlic free/eval/reg>
	// bief=<P56+P57>
	// bief=<P56+P57>
	// biefx=<P54+P55>
	// bieq=<P54+P55>
	// bqsc=<P50>
	// bfsc=<P51>
	// bcsc=<P52>
	// os=<os of user list provided>
	// ver=<list of all our version>


	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_QUERY, csTemp, HKEY_LOCAL_MACHINE))
	{
		csParamList = csTemp;
	}
	
	//1. Get SID
	
	//2. Get Current Time
	time_t tmCurrentTime = time(NULL);
	csTemp = _T("");
	csTemp.Format(_T("%ld"), tmCurrentTime);
	csParamList.Replace(_T("%dt%"), csTemp);

	//3.Get GID
	csTemp = _T("");
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_MACHINE_GUID, csTemp, HKEY_LOCAL_MACHINE))
	{
		csParamList.Replace(_T("%GID%"), csTemp);
	}

	//4. Get User's Time Zone
	long iTimeZoneDiff = 0;
	_get_timezone(&iTimeZoneDiff);
	csTemp = _T("");
	csTemp.Format(_T("%ld"), iTimeZoneDiff);
	csParamList.Replace(_T("%tz%"), csTemp);

	//5. Get Language
	csParamList.Replace(_T("%ln%"), GetCurrentLanguage());
	
	//6.Get status of user’s license 
	
	//7. Get number of issues found 
	DWORD dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_ITEMS_TO_CLEAN_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
	}

	DWORD dwTemp2 = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_ITEMS_TO_QUARANTINE_COUNT, dwTemp2, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp+dwTemp2);
	}
	csParamList.Replace(_T("%bief%"), csTemp);

	//7. Get number of issues fixed
	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_ITEMS_CLEANED_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
	}
	csParamList.Replace(_T("%biefx%"), csTemp);

	//8. Get number of issues Quarantined
	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_ITEMS_QUARANTINED_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
	}
	csParamList.Replace(_T("%bieq%"), csTemp);

	DWORD dwAllScanCount = 0;
	//9. Number Of Times Quick Scan Run
	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_QUICKSCAN_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		dwAllScanCount = dwTemp;
		csTemp.Format(_T("%d"), dwTemp);
	}
	csParamList.Replace(_T("%bqsc%"), csTemp);
	
	//9. Number Of Times Full Scan Run
	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_FULLSCAN_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		dwAllScanCount += dwTemp;
		csTemp.Format(_T("%d"), dwTemp);
	}
	csParamList.Replace(_T("%bfsc%"), csTemp);

	//9. Number Of Times Custom Scan Run
	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_CUSTOMSCAN_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		dwAllScanCount += dwTemp;
		csTemp.Format(_T("%d"), dwTemp);
	}
	csParamList.Replace(_T("%bcsc%"), csTemp);
	
	//10. How many times Main UI is launched
	dwTemp = 0;
	m_oRegistry.Get(m_csTrackingKey, _T("FirstTimeRun"), dwTemp, HKEY_LOCAL_MACHINE);
	if(dwTemp)
	{
		csTemp.Format(_T("%d"), 0);
		csParamList.Replace(_T("%bis%"), csTemp);		
	}
	else
	{
		m_oRegistry.Get(m_csTrackingKey, TRACKER_MAINUI_LAUNCHED, dwTemp, HKEY_LOCAL_MACHINE);
		csTemp.Format(_T("%d"), dwTemp);
		csParamList.Replace(_T("%bis%"), csTemp);	
	}

	

	//9. Users OS
	csTemp = _T("");
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_OS, csTemp, HKEY_LOCAL_MACHINE))
	{
		csParamList.Replace(_T("%os%"), csTemp);
	}	
	
	/*dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_ITEMS_QUARANTINED_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P55=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_ITEMS_TO_QUARANTINE_COUNT, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P57=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_BUY_NOW_CLICK, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P58=") + csTemp;
	}

	dwTemp = 0;
	if(m_oRegistry.Get(m_csTrackingKey, TRACKER_REGISTER_NOW_CLICK, dwTemp, HKEY_LOCAL_MACHINE))
	{
		csTemp.Format(_T("%d"), dwTemp);
		csParamList += _T("&P59=") + csTemp;
	}*/

	//AddLogEntry(L"ParamList: %s", csParamList, 0, true, LOG_DEBUG);

	return csParamList;
}

CString CUserTrackingSystem::GetCurrentLanguage()
{
	DWORD dwCurrentLanguage = 0;
	
	m_oRegistry.Get(m_csProductKey, LANGUAGE, dwCurrentLanguage, HKEY_LOCAL_MACHINE);
	
	switch((int)dwCurrentLanguage)
	{
	case 1:
		return _T("ge");
	case 2:
		return _T("fr");
	case 3:
		return _T("sp");
	case 4:
		return _T("ru");
	case 5:
		return _T("jp");
	default:
		return _T("en");
	}
}


