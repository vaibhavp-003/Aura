#include "pch.h"
#include "BKComDll.h"
#include "SDSystemInfo.h"
#include "ScanGraph.h"
#include "SUUU2Info.h"
#include "UUU2Info.h"
#include "UU2Info.h"

/*-------------------------------------------------------------------------------------
Function		: CScanGraph
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor for class CScanGraph
--------------------------------------------------------------------------------------*/
CScanGraph::CScanGraph()
{
	
}

/*-------------------------------------------------------------------------------------
Function		: :~CScanGraph
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor for class CScanGraph
--------------------------------------------------------------------------------------*/
CScanGraph::~CScanGraph()
{

}

/*-------------------------------------------------------------------------------------
Function		: DateTimeForUI
In Parameters	:
Out Parameters	: void
Purpose			: Get date time
--------------------------------------------------------------------------------------*/
bool CScanGraph::DateTimeForUI(ULONG64 ulDate, DWORD dwTime, LPTSTR szDateTime, SIZE_T cchDateTime)
{
	struct tm timeinfo = { 0 };
	ulDate += dwTime;
	localtime_s(&timeinfo, (time_t*)&ulDate);
	memset(szDateTime, 0, cchDateTime * sizeof(TCHAR));
	return !!wcsftime(szDateTime, cchDateTime, _T("%d %b %Y"), &timeinfo);
}

/*-------------------------------------------------------------------------------------
Function		: GetScanGraphData
In Parameters	: LPUScanGraphInfo pScanGraphData
Out Parameters	: void
Purpose			: Get graph data
--------------------------------------------------------------------------------------*/
void CScanGraph::GetScanGraphData(LPUScanGraphInfo pScanGraphData)
{
	try
	{
		int m_iShowCount = 0;
		CStringArray m_csDateArray;
		DWORD m_TotalDetectedCount = 0;
		CString m_sSpyFoundDbPath = CSystemInfo::m_strAppPath + _T("LogFolder\\SpyFound.db");
		CString m_sSpyFoundActDbPath = CSystemInfo::m_strAppPath + _T("LogFolder\\SpyFoundAct.db");
		CSUUU2Info objFullScanHistoryDB(false);
		CUUU2Info  objDateInfo(true);
		CUU2Info   objTimeInfo(true);
		CU2Info	   objSpyFoundList(true);
		LPSPY_ENTRY_INFO lpSpyEntryInfo = NULL;

		DWORD	 dwTime = 0;
		ULONG64  ulDate = 0;
		DWORD	 dwDetectedCount = 0, dwDeleteCount = 0;
		DWORD    dwQuarantineCount = 0, dwRecoverCount = 0;
		LPVOID   lTimePos, lPos;
		TCHAR	 szDateTime[100] = { 0 };
		int		 iScanCount = 1;


		if (m_sSpyFoundDbPath.Trim().GetLength() == 0)
		{
			return;
		}

		if (!objFullScanHistoryDB.Load(m_sSpyFoundDbPath))
		{
			return;
		}
		//return;

		if (!objFullScanHistoryDB.SearchItem(_T(""), objDateInfo))
			return;

		LPVOID lDatePos = objDateInfo.GetHighest();
		if (!lDatePos)
			return;

		//CMaxDSrvWrapper objMaxDSrvWrapper(COINIT_MULTITHREADED);
		//objMaxDSrvWrapper.InitializeDatabase();
		bool bLoaded = false;
		while (lDatePos)
		{
			ulDate = 0;
			objDateInfo.GetKey(lDatePos, ulDate);
			if (!objDateInfo.GetData(lDatePos, objTimeInfo))
				return;

			lTimePos = objTimeInfo.GetHighest();
			if (!lTimePos)
				return;
			if (bLoaded)
			{
				break;
			}

			while (lTimePos)
			{
				if (bLoaded)
				{
					break;
				}
				dwTime = dwDetectedCount = 0;
				dwDeleteCount = dwQuarantineCount = dwRecoverCount = 0;
				objTimeInfo.GetKey(lTimePos, dwTime);
				if (!objTimeInfo.GetData(lTimePos, objSpyFoundList))
					return;

				dwDetectedCount = objSpyFoundList.GetCount();
				if (dwDetectedCount == 0)
					return;

				DateTimeForUI(ulDate, dwTime, szDateTime, 100);
				int iItemCount = 0;
				lPos = objSpyFoundList.GetHighest();
				if (m_iShowCount > 3)
				{
					bLoaded = true;
					break;
				}
				m_csDateArray.Add(szDateTime);
				while (lPos)
				{
					lpSpyEntryInfo = NULL;
					DWORD dwKey = 0;
					objSpyFoundList.GetKey(lPos, dwKey);

					if (dwKey == -1)	//Handling required when 0 spyware's found!
					{
						dwDetectedCount = 0;
						break;
					}
					CString csStatus = L"Cleaned";
					if (objSpyFoundList.GetData(lPos, lpSpyEntryInfo))
					{
						switch (lpSpyEntryInfo->byStatus)
						{
						case eStatus_Deleted:
							dwDeleteCount++;
							csStatus = L"Repaired";
							break;
						case eStatus_Quarantined:
							dwQuarantineCount++;
							break;
						case eStatus_Recovered:
							dwRecoverCount++;
							break;
						case eStatus_Repaired:
							csStatus = L"Repaired";
							break;
						case eStatus_Detected:
							csStatus = L"Clean";
							break;
						case eStatus_Excluded:
							csStatus = L"Excluded";
							break;
						}
					}

					/*if(m_TotalDetectedCount >= 40000)
					{
						break;
					}*/

					if (dwDetectedCount > 0)
					{
						m_TotalDetectedCount++;
						iItemCount++;
					}
					lPos = objSpyFoundList.GetHighestNext(lPos);
				}
				TCHAR szItemCount[MAX_PATH];
				if (iItemCount != 0)
					swprintf_s(szItemCount, MAX_PATH, L">> Threats Count:%d", iItemCount);
				else
					swprintf_s(szItemCount, MAX_PATH, L">> No Threats Found");

				lTimePos = objTimeInfo.GetHighestNext(lTimePos);
				iScanCount++;
				pScanGraphData[m_iShowCount].dwThreatCount = iItemCount;
				_tcscpy(pScanGraphData[m_iShowCount].szDate, szDateTime);
				m_iShowCount++;
			}
			lDatePos = objDateInfo.GetHighestNext(lDatePos);
		}
		while (m_iShowCount <= 3)
		{
			pScanGraphData[m_iShowCount].dwThreatCount = 0;
			_tcscpy(pScanGraphData[m_iShowCount].szDate, L"");
			m_iShowCount++;
		}

	}

	catch (...)
	{
		AddLogEntry(_T("Exception in COverviewMain::AvScanHistory"));
	}
}
