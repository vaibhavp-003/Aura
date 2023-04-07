#include "pch.h"
#include "BKComDll.h"
#include "SchedulerMgr.h"


/*-------------------------------------------------------------------------------------
Function		: CSchedulerMgr
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor for class CSchedulerMgr
--------------------------------------------------------------------------------------*/
CSchedulerMgr::CSchedulerMgr()
{
	m_iSignatueScan = 1;
	m_iCompressScan = 0;
	m_iScanQuarantine = 0;
}

/*-------------------------------------------------------------------------------------
Function		: :~CSchedulerMgr
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor for class CSchedulerMgr
--------------------------------------------------------------------------------------*/
CSchedulerMgr::~CSchedulerMgr()
{

}
/*-------------------------------------------------------------------------------------
Function		: GetSchedulerSettings
In Parameters	: 
Out Parameters	: void
Purpose			: Get scheduler settings
--------------------------------------------------------------------------------------*/
void CSchedulerMgr::GetSchedulerSettings(LPUScanSchedulerData pScanScheduler)
{	
	ReadRegistrySettings(pScanScheduler);
}

/*-------------------------------------------------------------------------------------
Function		: SetSchedulerSettings
In Parameters	: 
Out Parameters	: void
Purpose			: Set scheduler settings
--------------------------------------------------------------------------------------*/
void CSchedulerMgr::SetSchedulerSettings(UScanSchedulerData objScanScheduler)
{
	OnCreateTask(objScanScheduler);
}
/*-------------------------------------------------------------------------------------
Function		: ReadRegistrySettings
In Parameters	: void
Out	Parameters	: bool
Purpose			: To read the schedule info from registry
--------------------------------------------------------------------------------------*/
bool CSchedulerMgr::ReadRegistrySettings(LPUScanSchedulerData pScanScheduler)
{
	CRegKey objRegKey;
	CRegistry objReg;
	memset(pScanScheduler,0,sizeof(UScanSchedulerData));
	CStringArray objValArr;
	objValArr.RemoveAll();
	objReg.EnumValues(CSystemInfo::m_csSchedulerRegKey, objValArr, HKEY_LOCAL_MACHINE);
	pScanScheduler->iScanSchStatus = 0;
	if (objValArr.GetCount() > 4)// check all parameters are in place
	{
		pScanScheduler->iScanSchStatus = 1;
		objRegKey.Open(HKEY_LOCAL_MACHINE, CSystemInfo::m_csSchedulerRegKey);
		WCHAR chSchTime[9];
		DWORD dwSize = 9;
		CString csSchInfo;
		objRegKey.QueryStringValue(_T("Time"), chSchTime, &dwSize);
		_tcscpy(pScanScheduler->szSchTime, chSchTime);
		
		DWORD dwSchDay = 0;
		objRegKey.QueryDWORDValue(_T("Day"), dwSchDay);
		
		
		DWORD dwHoursOrMin = 0;
		objRegKey.QueryDWORDValue(_T("HoursOrMins"), dwHoursOrMin);
		
		if (dwSchDay == DAILYSCAN)
		{
			pScanScheduler->iScanFreq = 0;
		}
		else if (dwSchDay == HOURLYSCAN)
		{
			pScanScheduler->iScanFreq = 2;
			pScanScheduler->iHrMins = dwHoursOrMin-1;
		}
		else if (dwSchDay == MINUTESSCAN)
		{
			pScanScheduler->iScanFreq = 3;
			pScanScheduler->iHrMins = dwHoursOrMin - 1;
		}
		else if (dwSchDay != 0 && dwSchDay <= 7)
		{
			pScanScheduler->iScanFreq = 1;
			pScanScheduler->iDay = dwSchDay-1;
		}
	
		DWORD dwQuarantine = 0;
		DWORD dwShutDown = 0;
		objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("ScanOption"), dwQuarantine, HKEY_LOCAL_MACHINE);
		pScanScheduler->iScanOption = dwQuarantine;
		if (pScanScheduler->iScanOption == 0)
		{
			m_iSignatueScan = 0;
			_tcscpy(pScanScheduler->szPath, L"");
		}
		else
		{
			m_iSignatueScan = 1;
			CString csDrives;
			objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("ScheduleDrives"), csDrives, HKEY_LOCAL_MACHINE);
			_tcscpy(pScanScheduler->szPath, csDrives);
			DWORD dwDeepScan = 0;
			objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("DeepScan"), dwDeepScan, HKEY_LOCAL_MACHINE);			

			pScanScheduler->iDeepScan = dwDeepScan;
		}

		objReg.Get(CSystemInfo::m_csProductRegKey, _T("Quarantine"), dwQuarantine, HKEY_LOCAL_MACHINE);
		if (dwQuarantine == 0)
		{
			pScanScheduler->iAction = 0;
		}
		else
		{
			pScanScheduler->iAction = 1;
		}
		
		objReg.Get(CSystemInfo::m_csSchedulerRegKey, _T("ShutDown"), dwShutDown, HKEY_LOCAL_MACHINE);
		pScanScheduler->iShutdownAction = dwShutDown;
		
		objRegKey.Close();
		return true;
	}
	else
	{
		pScanScheduler->iScanFreq = 0;
	}
	
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: OnCreateTask
In Parameters	: void
Out	Parameters	: void
Purpose			: To write the schedule info to registry
--------------------------------------------------------------------------------------*/
void CSchedulerMgr::OnCreateTask(UScanSchedulerData objScanScheduler)
{
	if (objScanScheduler.iScanOption == 1)
	{
		if (!theApp.IsSDReadyForFullScan(true))
		{
			return;
		}
	}

	if (objScanScheduler.iScanOption == 1)
	{
		CRegistry objReg;
		if (objScanScheduler.iDeepScan == 1)
		{
			objReg.Set(CSystemInfo::m_csSchedulerRegKey, _T("DeepScan"), 1, HKEY_LOCAL_MACHINE);
		}
		else
		{
			objReg.Set(CSystemInfo::m_csSchedulerRegKey, _T("DeepScan"), 0, HKEY_LOCAL_MACHINE);
		}
		if (CSystemInfo::m_iVirusScanFlag == 1)
		{
			objReg.Set(CSystemInfo::m_csSchedulerRegKey, _T("VirusScan"), 1, HKEY_LOCAL_MACHINE);
		}
		else
		{
			objReg.Set(CSystemInfo::m_csSchedulerRegKey, _T("VirusScan"), 0, HKEY_LOCAL_MACHINE);
		}
	}
	
	CRegKey		objRegKey;
	DWORD		dwVal = 0;
	CString		csTime;
	int iDay = 8;
	int iHoursorMins = 0;

	if (objRegKey.Create(HKEY_LOCAL_MACHINE, CSystemInfo::m_csSchedulerRegKey) != ERROR_SUCCESS)
	{
		return;
	}

	int hrTimeSpan = 0;
	int minTimeSpan = 0;
	if (objScanScheduler.iScanFreq == 0)
	{
		iDay = DAILYSCAN;
	}
	else if (objScanScheduler.iScanFreq == 2)
	{
		iDay = HOURLYSCAN;
		iHoursorMins = objScanScheduler.iHrMins + 1;
		hrTimeSpan = iHoursorMins;
	}
	else if (objScanScheduler.iScanFreq == 3)
	{
		iDay = MINUTESSCAN;
		iHoursorMins = objScanScheduler.iHrMins + 1;
		minTimeSpan = iHoursorMins * 10;
	}
	else
	{
		iDay = objScanScheduler.iDay + 1;
	}
	if (objScanScheduler.iScanOption == 0)
	{
		m_iSignatueScan = 0;
	}
	else
	{
		m_iSignatueScan = 1;
	}
	objRegKey.SetDWORDValue(_T("HoursOrMins"), (DWORD)iHoursorMins);
	objRegKey.SetDWORDValue(_T("AllowSignScan"), (DWORD)m_iSignatueScan);
	objRegKey.SetDWORDValue(_T("AllowCompressScan"), (DWORD)m_iCompressScan);
	objRegKey.SetDWORDValue(_T("Day"), iDay);
	csTime.Format(_T("%s"), objScanScheduler.szSchTime);
	int iSchHr = 0;
	int iSchMin = 0;
	int iPos = csTime.Find(':');
	if (iPos != -1)
	{
		iSchHr = _wtoi(csTime.Left(iPos));
		iSchMin = _wtoi(csTime.Mid(iPos + 1));
	}
	
	objRegKey.SetStringValue(_T("Time"), csTime);

	CTime curTime = CTime::GetCurrentTime();
	CTimeSpan timespan(0, hrTimeSpan, minTimeSpan, 0);
	CTime NewTime = curTime + timespan;
	csTime = _T("");
	csTime.Format(_T("%d:%d:%d:%d:%d"), NewTime.GetHour(), NewTime.GetMinute(), NewTime.GetDay(), NewTime.GetMonth(), NewTime.GetYear());
	objRegKey.SetStringValue(_T("NextScheduleTime"), csTime);

	objRegKey.SetDWORDValue(_T("ScanOption"), (DWORD)objScanScheduler.iScanOption);
	objRegKey.SetStringValue(_T("ScheduleDrives"), _T(""));
	
	objRegKey.SetStringValue(_T("ScheduleDrives"), objScanScheduler.szPath);
	
	if ((iDay == DAILYSCAN) || (iDay < DAILYSCAN && iDay == curTime.GetDayOfWeek()))
	{
		CTime CheckTime(curTime.GetYear(), curTime.GetMonth(), curTime.GetDay(), iSchHr, iSchMin, 59);
		if (CheckTime < curTime)
		{
			CString csdate;
			csdate.Format(_T("%d/%d/%d"), curTime.GetMonth(), curTime.GetDay(), curTime.GetYear());
			objRegKey.SetStringValue(_T("LastScanDate"), csdate);
		}
		else
		{
			objRegKey.SetStringValue(_T("LastScanDate"), _T(""));
		}
	}
	else
	{
		objRegKey.SetStringValue(_T("LastScanDate"), _T(""));
	}
	objRegKey.Close();

	if (objRegKey.Open(HKEY_LOCAL_MACHINE, CSystemInfo::m_csProductRegKey) != ERROR_SUCCESS)
	{
		return;
	}
	if (objScanScheduler.iAction == 1)
	{
		dwVal = 1;
		objRegKey.SetDWORDValue(_T("Quarantine"), dwVal);
	}
	else
	{
		dwVal = 0;
		objRegKey.SetDWORDValue(_T("Quarantine"), dwVal);
	}
	objRegKey.Close();

	if (objRegKey.Open(HKEY_LOCAL_MACHINE, CSystemInfo::m_csSchedulerRegKey) != ERROR_SUCCESS)
	{
		return;
	}

	objRegKey.SetDWORDValue(_T("ShutDown"), (DWORD)objScanScheduler.iShutdownAction);
	objRegKey.Close();	
}

/*-------------------------------------------------------------------------------------
Function		: ClearScheduledScan
In Parameters	: void
Out	Parameters	: void
Purpose			: Clear Schedule Scan
--------------------------------------------------------------------------------------*/
bool CSchedulerMgr::ClearScheduledScan()
{
	CStringArray objValArr;
	CRegistry objReg;
	if (objReg.KeyExists(CSystemInfo::m_csProductRegKey, HKEY_LOCAL_MACHINE))
	{
		objReg.EnumValues(CSystemInfo::m_csSchedulerRegKey, objValArr, HKEY_LOCAL_MACHINE);
		for (int i = 0; i < objValArr.GetCount(); i++)
		{
			objReg.DeleteValue(CSystemInfo::m_csSchedulerRegKey, objValArr.GetAt(i), HKEY_LOCAL_MACHINE);
		}
		return true;

	}
	else
		return false;
}