#include "pch.h"
#include "BKComDll.h"
#include "FullScanReport.h"
#include "SUUU2Info.h"
#include "UUU2Info.h"
#include "UU2Info.h"


CU2Info	CFullScanReport::m_objSpyFoundList(true);
ULONG	CFullScanReport::m_iIndex = 0;

void GetMonthInNumberString(TCHAR* szMonth);

bool DateTimeForDB_R(LPTSTR szDateTime, ULONG64& ulDate, DWORD& dwTime);
bool DateTimeForDB_RAct(LPTSTR szDateTime, ULONG64& ulDate, DWORD& dwTime);
bool DateTimeForUIAct(ULONG64 ulDate, DWORD dwTime, LPTSTR szDateTime, SIZE_T cchDateTime);

/*-------------------------------------------------------------------------------------
Function		: CFullScanReport
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor for class CFullScanReport
--------------------------------------------------------------------------------------*/
CFullScanReport::CFullScanReport()
{
	m_sSpyFoundDbPath = CSystemInfo::m_strAppPath + _T("LogFolder\\SpyFound.db");
	m_sSpyFoundActDbPath = CSystemInfo::m_strAppPath + _T("LogFolder\\SpyFoundAct.db");
	m_pFullScanReportLink = NULL;
	m_pHeadReportLink = NULL;
}

/*-------------------------------------------------------------------------------------
Function		: :~CFullScanReport
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor for class CFullScanReport
--------------------------------------------------------------------------------------*/
CFullScanReport::~CFullScanReport()
{
	DestoryData();
}

/*-------------------------------------------------------------------------------------
Function		: :ShowAvScanHistory
In Parameters	: - LPUFullScanReport pFullScanReport, DWORD dwReportLength
Out Parameters	: - void
Purpose			: Get report from db
--------------------------------------------------------------------------------------*/
void CFullScanReport::ShowAvScanHistory(LPUFullScanReport pFullScanReport, DWORD dwReportLength)
{
	try
	{
		if (m_pFullScanReportLink != NULL && dwReportLength == m_dwTotalListCount)
		{
			m_pHeadReportLink = m_pFullScanReportLink;
			DWORD dwReportCount = 0;
			while (m_pHeadReportLink != NULL && dwReportCount< dwReportLength)
			{
				memcpy(&pFullScanReport[dwReportCount], &m_pHeadReportLink->objFullScanReport, sizeof(UFullScanReport));
				m_pHeadReportLink = m_pHeadReportLink->pLinkNode;
				dwReportCount++;
			}
			DestoryData();
		}

	}
	catch (...)
	{
		AddLogEntry(_T("Exception in CFullScanReport::AvScanHistory"));
	}
}
//void CFullScanReport::ShowAvScanHistory(LPUFullScanReport pFullScanReport, DWORD dwReportLength)
//{
//	try
//	{
//		DWORD dwTotalDetectedCount = 0;
//		DWORD dwTotalListCount = 0;
//		CSUUU2Info objFullScanHistoryDB(false);
//		CUUU2Info  objDateInfo(true);
//		CUU2Info   objTimeInfo(true);
//		CU2Info	   objSpyFoundList(true);
//		LPSPY_ENTRY_INFO lpSpyEntryInfo = NULL;
//
//		DWORD	 dwTime = 0;
//		ULONG64  ulDate = 0;
//		DWORD	 dwDetectedCount = 0, dwDeleteCount = 0;
//		DWORD    dwQuarantineCount = 0, dwRecoverCount = 0;
//		LPVOID   lTimePos, lPos;
//		TCHAR	 szDateTime[100] = { 0 };
//		int		 iScanCount = 1;
//		HTREEITEM hParent, htreeitem;
//
//		if (m_sSpyFoundDbPath.Trim().GetLength() == 0)
//		{
//			return;
//		}
//
//		if (!objFullScanHistoryDB.Load(m_sSpyFoundDbPath))
//		{
//			goto Actmon;
//		}
//		//return;
//
//		if (!objFullScanHistoryDB.SearchItem(_T(""), objDateInfo))
//			return;
//
//		LPVOID lDatePos = objDateInfo.GetHighest();
//		if (!lDatePos)
//			return;
//
//		//HTREEITEM hParentScanner = m_stTreeControl.GetTreeCtrl().InsertItem(theApp.m_pResMgr->GetString(_T("IDS_ON_DEMAND_SCANNING")), NULL, TVI_SORT);
//		while (lDatePos)
//		{
//			ulDate = 0;
//			objDateInfo.GetKey(lDatePos, ulDate);
//			if (!objDateInfo.GetData(lDatePos, objTimeInfo))
//				return;
//
//			lTimePos = objTimeInfo.GetHighest();
//			if (!lTimePos)
//				return;
//
//			while (lTimePos)
//			{
//				dwTime = dwDetectedCount = 0;
//				dwDeleteCount = dwQuarantineCount = dwRecoverCount = 0;
//				objTimeInfo.GetKey(lTimePos, dwTime);
//				if (!objTimeInfo.GetData(lTimePos, objSpyFoundList))
//					return;
//
//				dwDetectedCount = objSpyFoundList.GetCount();
//				if (dwDetectedCount == 0)
//					return;
//
//				DateTimeForUI(ulDate, dwTime, szDateTime, 100);
//
//
//				int iItemCount = 0;
//				//hParent = m_stTreeControl.GetTreeCtrl().InsertItem(szDateTime, hParentScanner, TVI_SORT);
//
//				//m_stTreeControl.GetTreeCtrl().SetItemImage(hParent, 0, 1);
//
//				lPos = objSpyFoundList.GetHighest();
//				while (lPos)
//				{
//					lpSpyEntryInfo = NULL;
//					DWORD dwKey = 0;
//					objSpyFoundList.GetKey(lPos, dwKey);
//
//					if (dwKey == -1)	//Handling required when 0 spyware's found!
//					{
//						dwDetectedCount = 0;
//						break;
//					}
//					CString csStatus = L"Cleaned";
//					if (objSpyFoundList.GetData(lPos, lpSpyEntryInfo))
//					{
//						switch (lpSpyEntryInfo->byStatus)
//						{
//						case eStatus_Deleted:
//							dwDeleteCount++;
//							csStatus = L"Repaired";
//							break;
//						case eStatus_Quarantined:
//							dwQuarantineCount++;
//							break;
//						case eStatus_Recovered:
//							dwRecoverCount++;
//							break;
//						case eStatus_Repaired:
//							csStatus = L"Repaired";
//							break;
//						case eStatus_Detected:
//							csStatus = L"Clean";
//							break;
//						case eStatus_Excluded:
//							csStatus = L"Excluded";
//							break;
//						}
//					}
//
//					if (dwTotalDetectedCount >= 40000)
//					{
//						break;
//					}
//
//					if (dwDetectedCount > 0)
//					{
//						int iImage = 2;
//						BYTE bThreatIndex;
//						CString csSpyName;
//						CString csHelpInfo;
//						CString csType;
//
//						if (((lpSpyEntryInfo->dwSpywareID == 0) || ((lpSpyEntryInfo->szValue) && (_tcslen(lpSpyEntryInfo->szValue) != 0)))
//							&& ((lpSpyEntryInfo->eTypeOfEntry == Virus_Process) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File)
//								|| (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Repair) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Repair_Report)
//								|| (lpSpyEntryInfo->eTypeOfEntry == Virus_Process_Report) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Report)))
//						{
//							csSpyName = lpSpyEntryInfo->szValue;
//							bThreatIndex = -1;
//							csHelpInfo = _T("A computer virus is a computer program that can copy itself and infect a computer without permission or knowledge of the user. A virus might corrupt or delete data on your computer, use your e-mail program to spread itself to other computers, or even erase everything on your hard disk. It often attaches itself to an executable file or an application. A computer virus is not standalone and needs a host file or program to work or replicate.");
//						}
//						else
//						{
//							CString strKeyValue = lpSpyEntryInfo->szValue;
//							if (!strKeyValue.IsEmpty())
//							{
//								strKeyValue += _T(".");
//							}
//							if (GetThreatInfo(lpSpyEntryInfo->dwSpywareID, csSpyName, bThreatIndex, csHelpInfo, strKeyValue, lpSpyEntryInfo->eTypeOfEntry) == false)
//							{
//								bThreatIndex = -1;
//							}
//						}
//
//						/*TCHAR szSpyID[MAX_PATH] = { 0 };
//						swprintf_s(szSpyID, MAX_PATH, L"%ld", lpSpyEntryInfo->dwSpywareID);
//
//						int threatIndex = static_cast<int>(bThreatIndex);
//						GetImageAndType((SD_Message_Info)lpSpyEntryInfo->eTypeOfEntry, iImage, threatIndex, csType, csSpyName);
//						
//						htreeitem = m_stTreeControl.GetTreeCtrl().InsertItem(csSpyName, hParent, TVI_SORT);
//						m_stTreeControl.GetTreeCtrl().SetItemImage(htreeitem, iImage, iImage);
//						m_stTreeControl.SetItemText(htreeitem, 1, lpSpyEntryInfo->szKey);
//						m_stTreeControl.SetItemText(htreeitem, 2, CString(_T("File")));
//						m_stTreeControl.SetItemText(htreeitem, 3, csStatus);
//						m_stTreeControl.SetItemText(htreeitem, 4, szSpyID);
//
//						TCHAR szTypeOfEntry[10] = { 0 };
//						_stprintf(szTypeOfEntry, L"%d", lpSpyEntryInfo->eTypeOfEntry);
//						m_stTreeControl.SetItemText(htreeitem, 5, szTypeOfEntry);
//
//						m_stTreeControl.GetTreeCtrl().SetItemState(htreeitem, TVIS_OVERLAYMASK, INDEXTOOVERLAYMASK(1));*/
//
//						pFullScanReport[dwTotalListCount].iScannerType = ScanFullReportType::OnDemand;
//						pFullScanReport[dwTotalListCount].iActionStatus = lpSpyEntryInfo->byStatus;
//						pFullScanReport[dwTotalListCount].dwSpyID = lpSpyEntryInfo->dwSpywareID;
//						pFullScanReport[dwTotalListCount].iTypeOfEntry = lpSpyEntryInfo->eTypeOfEntry;
//						_tcscpy(pFullScanReport[dwTotalListCount].szSpyName, csSpyName);
//						_tcscpy(pFullScanReport[dwTotalListCount].szPath, lpSpyEntryInfo->szKey);
//						_tcscpy(pFullScanReport[dwTotalListCount].szDateTime, szDateTime);
//
//						dwTotalDetectedCount++;
//						dwTotalListCount++;
//						iItemCount++;
//					}
//					lPos = objSpyFoundList.GetHighestNext(lPos);
//				}
//				if (iItemCount != 0)
//				{
//					pFullScanReport[dwTotalListCount].iScannerType = ScanFullReportType::OnDemand;
//					dwTotalListCount++;
//				}
//				lTimePos = objTimeInfo.GetHighestNext(lTimePos);
//				iScanCount++;
//			}
//			lDatePos = objDateInfo.GetHighestNext(lDatePos);
//		}
//		////////////////////////Actmon
//	Actmon:
//		if (m_sSpyFoundActDbPath.Trim().GetLength() == 0)
//		{
//			return;
//		}
//		objFullScanHistoryDB.RemoveAll();
//		objDateInfo.RemoveAll();
//
//		if (!objFullScanHistoryDB.Load(m_sSpyFoundActDbPath))
//			return;
//
//		if (!objFullScanHistoryDB.SearchItem(_T(""), objDateInfo))
//			return;
//
//		lDatePos = objDateInfo.GetHighest();
//		if (!lDatePos)
//			return;
//		//hParentScanner = m_stTreeControl.GetTreeCtrl().InsertItem(theApp.m_pResMgr->GetString(_T("IDS_ON_ACTIVE_MONITOR")), NULL, TVI_SORT);
//		while (lDatePos)
//		{
//			ulDate = 0;
//			objDateInfo.GetKey(lDatePos, ulDate);
//			if (!objDateInfo.GetData(lDatePos, objTimeInfo))
//				return;
//
//			lTimePos = objTimeInfo.GetHighest();
//			if (!lTimePos)
//				return;
//
//			while (lTimePos)
//			{
//				dwTime = dwDetectedCount = 0;
//				dwDeleteCount = dwQuarantineCount = dwRecoverCount = 0;
//				objTimeInfo.GetKey(lTimePos, dwTime);
//				if (!objTimeInfo.GetData(lTimePos, objSpyFoundList))
//					return;
//
//				dwDetectedCount = objSpyFoundList.GetCount();
//				if (dwDetectedCount == 0)
//					return;
//
//				DateTimeForUIAct(ulDate, dwTime, szDateTime, 100);
//
//
//				int iItemCount = 0;
//				/*hParent = m_stTreeControl.GetTreeCtrl().InsertItem(szDateTime, hParentScanner, TVI_SORT);
//
//				m_stTreeControl.GetTreeCtrl().SetItemImage(hParent, 0, 1);*/
//
//				lPos = objSpyFoundList.GetHighest();
//				while (lPos)
//				{
//					lpSpyEntryInfo = NULL;
//					DWORD dwKey = 0;
//					objSpyFoundList.GetKey(lPos, dwKey);
//
//					if (dwKey == -1)	//Handling required when 0 spyware's found!
//					{
//						dwDetectedCount = 0;
//						break;
//					}
//					CString csStatus = L"Cleaned";
//					if (objSpyFoundList.GetData(lPos, lpSpyEntryInfo))
//					{
//						switch (lpSpyEntryInfo->byStatus)
//						{
//						case eStatus_Deleted:
//							dwDeleteCount++;
//							csStatus = L"Repaired";
//							break;
//						case eStatus_Quarantined:
//							dwQuarantineCount++;
//							break;
//						case eStatus_Recovered:
//							dwRecoverCount++;
//							break;
//						case eStatus_Repaired:
//							csStatus = L"Repaired";
//							break;
//						case eStatus_Detected:
//							csStatus = L"Clean";
//							break;
//						case eStatus_Excluded:
//							csStatus = L"Excluded";
//							break;
//						}
//					}
//
//					if (dwTotalDetectedCount >= 40000)
//					{
//						break;
//					}
//
//					if (dwDetectedCount > 0)
//					{
//						int iImage = 2;
//						BYTE bThreatIndex;
//						CString csSpyName;
//						CString csHelpInfo;
//						CString csType;
//
//						if (((lpSpyEntryInfo->dwSpywareID == 0) || ((lpSpyEntryInfo->szValue) && (_tcslen(lpSpyEntryInfo->szValue) != 0)))
//							&& ((lpSpyEntryInfo->eTypeOfEntry == Virus_Process) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File)
//								|| (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Repair) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Repair_Report)
//								|| (lpSpyEntryInfo->eTypeOfEntry == Virus_Process_Report) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Report)))
//						{
//							csSpyName = lpSpyEntryInfo->szValue;
//							bThreatIndex = -1;
//							csHelpInfo = _T("A computer virus is a computer program that can copy itself and infect a computer without permission or knowledge of the user. A virus might corrupt or delete data on your computer, use your e-mail program to spread itself to other computers, or even erase everything on your hard disk. It often attaches itself to an executable file or an application. A computer virus is not standalone and needs a host file or program to work or replicate.");
//						}
//						else
//						{
//							CString strKeyValue = lpSpyEntryInfo->szValue;
//							if (!strKeyValue.IsEmpty())
//							{
//								strKeyValue += _T(".");
//							}
//							if (GetThreatInfo(lpSpyEntryInfo->dwSpywareID, csSpyName, bThreatIndex, csHelpInfo, strKeyValue, lpSpyEntryInfo->eTypeOfEntry) == false)
//							{
//								bThreatIndex = -1;
//							}
//						}
//
//						pFullScanReport[dwTotalListCount].iScannerType = ScanFullReportType::Actmon;
//						pFullScanReport[dwTotalListCount].iActionStatus = lpSpyEntryInfo->byStatus;
//						pFullScanReport[dwTotalListCount].dwSpyID = lpSpyEntryInfo->dwSpywareID;
//						pFullScanReport[dwTotalListCount].iTypeOfEntry = lpSpyEntryInfo->eTypeOfEntry;
//						_tcscpy(pFullScanReport[dwTotalListCount].szSpyName, csSpyName);
//						_tcscpy(pFullScanReport[dwTotalListCount].szPath, lpSpyEntryInfo->szKey);
//						_tcscpy(pFullScanReport[dwTotalListCount].szDateTime, szDateTime);
//
//						dwTotalDetectedCount++;
//						dwTotalListCount++;
//						iItemCount++;
//					}
//					lPos = objSpyFoundList.GetHighestNext(lPos);
//				}
//				if (iItemCount != 0)
//				{
//					pFullScanReport[dwTotalListCount].iScannerType = ScanFullReportType::OnDemand;
//					dwTotalListCount++;
//				}
//				lTimePos = objTimeInfo.GetHighestNext(lTimePos);
//				iScanCount++;
//			}
//			lDatePos = objDateInfo.GetHighestNext(lDatePos);
//		}
//
//	}
//	catch (...)
//	{
//		AddLogEntry(_T("Exception in COverviewMain::AvScanHistory"));
//	}
//}

/*-------------------------------------------------------------------------------------
Function		: :GetScanFullReportCount
In Parameters	: - void
Out Parameters	: - void
Purpose			: Get total count of reports
--------------------------------------------------------------------------------------*/
DWORD CFullScanReport::GetScanFullReportCount()
{
	DWORD dwReportLength = 0;
	try
	{
		DestoryData();
		DWORD dwTotalDetectedCount = 0;
		m_dwTotalListCount = 0;
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
		HTREEITEM hParent, htreeitem;

		if (m_sSpyFoundDbPath.Trim().GetLength() == 0)
		{
			return dwReportLength;
		}

		if (!objFullScanHistoryDB.Load(m_sSpyFoundDbPath))
		{
			goto Actmon;
		}
		
		if (!objFullScanHistoryDB.SearchItem(_T(""), objDateInfo))
			return dwReportLength;

		LPVOID lDatePos = objDateInfo.GetHighest();
		if (!lDatePos)
			return dwReportLength;

		//HTREEITEM hParentScanner = m_stTreeControl.GetTreeCtrl().InsertItem(theApp.m_pResMgr->GetString(_T("IDS_ON_DEMAND_SCANNING")), NULL, TVI_SORT);
		while (lDatePos)
		{
			ulDate = 0;
			objDateInfo.GetKey(lDatePos, ulDate);
			if (!objDateInfo.GetData(lDatePos, objTimeInfo))
				return dwReportLength;

			lTimePos = objTimeInfo.GetHighest();
			if (!lTimePos)
				return dwReportLength;

			while (lTimePos)
			{
				dwTime = dwDetectedCount = 0;
				dwDeleteCount = dwQuarantineCount = dwRecoverCount = 0;
				objTimeInfo.GetKey(lTimePos, dwTime);
				if (!objTimeInfo.GetData(lTimePos, objSpyFoundList))
					return dwReportLength;

				dwDetectedCount = objSpyFoundList.GetCount();
				if (dwDetectedCount == 0)
					return dwReportLength;

				DateTimeForUI(ulDate, dwTime, szDateTime, 100);


				int iItemCount = 0;
				//hParent = m_stTreeControl.GetTreeCtrl().InsertItem(szDateTime, hParentScanner, TVI_SORT);

				//m_stTreeControl.GetTreeCtrl().SetItemImage(hParent, 0, 1);

				lPos = objSpyFoundList.GetHighest();
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

					if (dwTotalDetectedCount >= 40000)
					{
						break;
					}

					if (dwDetectedCount > 0)
					{
						int iImage = 2;
						BYTE bThreatIndex;
						CString csSpyName;
						CString csHelpInfo;
						CString csType;

						if (((lpSpyEntryInfo->dwSpywareID == 0) || ((lpSpyEntryInfo->szValue) && (_tcslen(lpSpyEntryInfo->szValue) != 0)))
							&& ((lpSpyEntryInfo->eTypeOfEntry == Virus_Process) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File)
								|| (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Repair) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Repair_Report)
								|| (lpSpyEntryInfo->eTypeOfEntry == Virus_Process_Report) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Report)))
						{
							csSpyName = lpSpyEntryInfo->szValue;
							bThreatIndex = -1;
							csHelpInfo = _T("A computer virus is a computer program that can copy itself and infect a computer without permission or knowledge of the user. A virus might corrupt or delete data on your computer, use your e-mail program to spread itself to other computers, or even erase everything on your hard disk. It often attaches itself to an executable file or an application. A computer virus is not standalone and needs a host file or program to work or replicate.");
						}
						else
						{
							CString strKeyValue = lpSpyEntryInfo->szValue;
							if (!strKeyValue.IsEmpty())
							{
								strKeyValue += _T(".");
							}
							if (GetThreatInfo(lpSpyEntryInfo->dwSpywareID, csSpyName, bThreatIndex, csHelpInfo, strKeyValue, lpSpyEntryInfo->eTypeOfEntry) == false)
							{
								bThreatIndex = -1;
							}
						}
						TCHAR szSpyName[MAX_PATH] = { 0 };
						_tcscpy(szSpyName, csSpyName);
						/*TCHAR szSpyID[MAX_PATH] = { 0 };
						swprintf_s(szSpyID, MAX_PATH, L"%ld", lpSpyEntryInfo->dwSpywareID);

						int threatIndex = static_cast<int>(bThreatIndex);
						GetImageAndType((SD_Message_Info)lpSpyEntryInfo->eTypeOfEntry, iImage, threatIndex, csType, csSpyName);

						htreeitem = m_stTreeControl.GetTreeCtrl().InsertItem(csSpyName, hParent, TVI_SORT);
						m_stTreeControl.GetTreeCtrl().SetItemImage(htreeitem, iImage, iImage);
						m_stTreeControl.SetItemText(htreeitem, 1, lpSpyEntryInfo->szKey);
						m_stTreeControl.SetItemText(htreeitem, 2, CString(_T("File")));
						m_stTreeControl.SetItemText(htreeitem, 3, csStatus);
						m_stTreeControl.SetItemText(htreeitem, 4, szSpyID);

						TCHAR szTypeOfEntry[10] = { 0 };
						_stprintf(szTypeOfEntry, L"%d", lpSpyEntryInfo->eTypeOfEntry);
						m_stTreeControl.SetItemText(htreeitem, 5, szTypeOfEntry);

						m_stTreeControl.GetTreeCtrl().SetItemState(htreeitem, TVIS_OVERLAYMASK, INDEXTOOVERLAYMASK(1));*/

						/*pFullScanReport[dwTotalListCount].iScannerType = ScanFullReportType::OnDemand;
						pFullScanReport[dwTotalListCount].iActionStatus = lpSpyEntryInfo->byStatus;
						pFullScanReport[dwTotalListCount].dwSpyID = lpSpyEntryInfo->dwSpywareID;
						pFullScanReport[dwTotalListCount].iTypeOfEntry = lpSpyEntryInfo->eTypeOfEntry;
						_tcscpy(pFullScanReport[dwTotalListCount].szSpyName, csSpyName);
						_tcscpy(pFullScanReport[dwTotalListCount].szPath, lpSpyEntryInfo->szKey);
						_tcscpy(pFullScanReport[dwTotalListCount].szDateTime, szDateTime);*/
						CreateReportList(ScanFullReportType::OnDemand, lpSpyEntryInfo->byStatus, lpSpyEntryInfo->dwSpywareID, lpSpyEntryInfo->eTypeOfEntry,
							szSpyName, lpSpyEntryInfo->szKey, szDateTime);
						dwTotalDetectedCount++;
						m_dwTotalListCount++;
						iItemCount++;
					}
					lPos = objSpyFoundList.GetHighestNext(lPos);
				}
				if (iItemCount == 0)
				{
					//pFullScanReport[dwTotalListCount].iScannerType = ScanFullReportType::OnDemand;
					CreateReportList(ScanFullReportType::OnDemand, 0, 0, 0,	L"", L"", szDateTime);
					m_dwTotalListCount++;
				}
				lTimePos = objTimeInfo.GetHighestNext(lTimePos);
				iScanCount++;
			}
			lDatePos = objDateInfo.GetHighestNext(lDatePos);
		}
		dwReportLength = m_dwTotalListCount;
		////////////////////////Actmon
	Actmon:
		if (m_sSpyFoundActDbPath.Trim().GetLength() == 0)
		{
			return dwReportLength;
		}
		objFullScanHistoryDB.RemoveAll();
		objDateInfo.RemoveAll();

		if (!objFullScanHistoryDB.Load(m_sSpyFoundActDbPath))
			return dwReportLength;

		if (!objFullScanHistoryDB.SearchItem(_T(""), objDateInfo))
			return dwReportLength;

		lDatePos = objDateInfo.GetHighest();
		if (!lDatePos)
			return dwReportLength;
		//hParentScanner = m_stTreeControl.GetTreeCtrl().InsertItem(theApp.m_pResMgr->GetString(_T("IDS_ON_ACTIVE_MONITOR")), NULL, TVI_SORT);
		while (lDatePos)
		{
			ulDate = 0;
			objDateInfo.GetKey(lDatePos, ulDate);
			if (!objDateInfo.GetData(lDatePos, objTimeInfo))
				return dwReportLength;

			lTimePos = objTimeInfo.GetHighest();
			if (!lTimePos)
				return dwReportLength;

			while (lTimePos)
			{
				dwTime = dwDetectedCount = 0;
				dwDeleteCount = dwQuarantineCount = dwRecoverCount = 0;
				objTimeInfo.GetKey(lTimePos, dwTime);
				if (!objTimeInfo.GetData(lTimePos, objSpyFoundList))
					return dwReportLength;

				dwDetectedCount = objSpyFoundList.GetCount();
				if (dwDetectedCount == 0)
					return dwReportLength;

				DateTimeForUIAct(ulDate, dwTime, szDateTime, 100);


				int iItemCount = 0;
				/*hParent = m_stTreeControl.GetTreeCtrl().InsertItem(szDateTime, hParentScanner, TVI_SORT);

				m_stTreeControl.GetTreeCtrl().SetItemImage(hParent, 0, 1);*/

				lPos = objSpyFoundList.GetHighest();
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

					if (dwTotalDetectedCount >= 40000)
					{
						break;
					}

					if (dwDetectedCount > 0)
					{
						int iImage = 2;
						BYTE bThreatIndex;
						CString csSpyName;
						CString csHelpInfo;
						CString csType;

						if (((lpSpyEntryInfo->dwSpywareID == 0) || ((lpSpyEntryInfo->szValue) && (_tcslen(lpSpyEntryInfo->szValue) != 0)))
							&& ((lpSpyEntryInfo->eTypeOfEntry == Virus_Process) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File)
								|| (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Repair) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Repair_Report)
								|| (lpSpyEntryInfo->eTypeOfEntry == Virus_Process_Report) || (lpSpyEntryInfo->eTypeOfEntry == Virus_File_Report)))
						{
							csSpyName = lpSpyEntryInfo->szValue;
							bThreatIndex = -1;
							csHelpInfo = _T("A computer virus is a computer program that can copy itself and infect a computer without permission or knowledge of the user. A virus might corrupt or delete data on your computer, use your e-mail program to spread itself to other computers, or even erase everything on your hard disk. It often attaches itself to an executable file or an application. A computer virus is not standalone and needs a host file or program to work or replicate.");
						}
						else
						{
							CString strKeyValue = lpSpyEntryInfo->szValue;
							if (!strKeyValue.IsEmpty())
							{
								strKeyValue += _T(".");
							}
							if (GetThreatInfo(lpSpyEntryInfo->dwSpywareID, csSpyName, bThreatIndex, csHelpInfo, strKeyValue, lpSpyEntryInfo->eTypeOfEntry) == false)
							{
								bThreatIndex = -1;
							}
						}

						//pFullScanReport[dwTotalListCount].iScannerType = ScanFullReportType::Actmon;
						//pFullScanReport[dwTotalListCount].iActionStatus = lpSpyEntryInfo->byStatus;
						//pFullScanReport[dwTotalListCount].dwSpyID = lpSpyEntryInfo->dwSpywareID;
						//pFullScanReport[dwTotalListCount].iTypeOfEntry = lpSpyEntryInfo->eTypeOfEntry;
						//_tcscpy(pFullScanReport[dwTotalListCount].szSpyName, csSpyName);
						//_tcscpy(pFullScanReport[dwTotalListCount].szPath, lpSpyEntryInfo->szKey);
						//_tcscpy(pFullScanReport[dwTotalListCount].szDateTime, szDateTime);

						TCHAR szSpyName[MAX_PATH] = { 0 };
						_tcscpy(szSpyName, csSpyName);

						CreateReportList(ScanFullReportType::Actmon, lpSpyEntryInfo->byStatus, lpSpyEntryInfo->dwSpywareID, lpSpyEntryInfo->eTypeOfEntry,
							szSpyName, lpSpyEntryInfo->szKey, szDateTime);

						dwTotalDetectedCount++;
						m_dwTotalListCount++;
						iItemCount++;
					}
					lPos = objSpyFoundList.GetHighestNext(lPos);
				}
				if (iItemCount == 0)
				{
					//pFullScanReport[dwTotalListCount].iScannerType = ScanFullReportType::Actmon;
					CreateReportList(ScanFullReportType::Actmon, 0, 0, 0, L"", L"", szDateTime);
					m_dwTotalListCount++;
				}
				lTimePos = objTimeInfo.GetHighestNext(lTimePos);
				iScanCount++;
			}
			lDatePos = objDateInfo.GetHighestNext(lDatePos);
		}
		dwReportLength = m_dwTotalListCount;
		CString csLog;
		csLog.Format(_T("total List Count : % d"), m_dwTotalListCount);
		OutputDebugStringW(csLog);

	}
	catch (...)
	{
		AddLogEntry(_T("Exception in COverviewMain::AvScanHistory"));
	}
	return dwReportLength;
}

/*-------------------------------------------------------------------------------------
Function		: _DateTimeForDB
In Parameters	: ULONG64 ulDateTime64, ULONG64& ulDate, DWORD& dwTime
Out Parameters	: bool
Purpose			: Date time conversion
--------------------------------------------------------------------------------------*/
bool _DateTimeForDB(ULONG64 ulDateTime64, ULONG64& ulDate, DWORD& dwTime)
{
	struct tm timeinfo = { 0 };
	localtime_s(&timeinfo, (time_t*)&ulDateTime64);
	dwTime = (timeinfo.tm_hour * 60 * 60) + (timeinfo.tm_min * 60) + timeinfo.tm_sec;
	ulDate = ulDateTime64 - dwTime;
	return true;
}
/*-------------------------------------------------------------------------------------
Function		: _DateTimeForDBAct
In Parameters	: ULONG64 ulDateTime64, ULONG64& ulDate, DWORD& dwTime, DWORD dwMilliSec
Out Parameters	: bool
Purpose			: Date time conversion
--------------------------------------------------------------------------------------*/
bool _DateTimeForDBAct(ULONG64 ulDateTime64, ULONG64& ulDate, DWORD& dwTime, DWORD dwMilliSec)
{
	struct tm timeinfo = { 0 };
	localtime_s(&timeinfo, (time_t*)&ulDateTime64);
	dwTime = (timeinfo.tm_hour * 60 * 60) + (timeinfo.tm_min * 60) + timeinfo.tm_sec;
	ulDate = ulDateTime64 - dwTime;
	dwTime = 1000 * (dwTime)+dwMilliSec;
	return true;
}
/*-------------------------------------------------------------------------------------
Function		: _DateTimeForUI
In Parameters	: ULONG64 ulDate, DWORD dwTime, LPTSTR szDateTime, SIZE_T cchDateTime
Out Parameters	: bool
Purpose			: Date time conversion
--------------------------------------------------------------------------------------*/
bool _DateTimeForUI(ULONG64 ulDate, DWORD dwTime, LPTSTR szDateTime, SIZE_T cchDateTime)
{
	struct tm timeinfo = { 0 };
	ulDate += dwTime;
	localtime_s(&timeinfo, (time_t*)&ulDate);
	memset(szDateTime, 0, cchDateTime * sizeof(TCHAR));
	return !!wcsftime(szDateTime, cchDateTime, _T("%d %b, %Y [%H:%M:%S]"), &timeinfo);
}

/*-------------------------------------------------------------------------------------
Function		: _DateTimeForUI
In Parameters	: ULONG64 ulDateTime64, LPTSTR szDateTime, SIZE_T cchDateTime
Out Parameters	: bool
Purpose			: Date time conversion
--------------------------------------------------------------------------------------*/
bool _DateTimeForUI(ULONG64 ulDateTime64, LPTSTR szDateTime, SIZE_T cchDateTime)
{
	struct tm timeinfo = { 0 };
	localtime_s(&timeinfo, (time_t*)&ulDateTime64);
	memset(szDateTime, 0, cchDateTime * sizeof(TCHAR));
	return !!wcsftime(szDateTime, cchDateTime, _T("%d %b, %Y [%H:%M:%S]"), &timeinfo);
}

/*-------------------------------------------------------------------------------------
Function		: DateTimeForUIAct
In Parameters	:ULONG64 ulDate, DWORD dwTime, LPTSTR szDateTime, SIZE_T cchDateTime
Out Parameters	: bool
Purpose			: Date time conversion
--------------------------------------------------------------------------------------*/
bool DateTimeForUIAct(ULONG64 ulDate, DWORD dwTime, LPTSTR szDateTime, SIZE_T cchDateTime)
{
	struct tm timeinfo = { 0 };
	DWORD iMilli = (dwTime % 1000);
	dwTime -= iMilli;
	dwTime /= 1000;

	ulDate += dwTime;
	localtime_s(&timeinfo, (time_t*)&ulDate);
	memset(szDateTime, 0, cchDateTime * sizeof(TCHAR));

	!!wcsftime(szDateTime, cchDateTime, _T("%d %b, %Y [%H:%M:%S"), &timeinfo);
	_stprintf(szDateTime, _T("%s.%d]"), szDateTime, iMilli);
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: DateTimeForDB_R
In Parameters	: LPTSTR szDateTime, ULONG64& ulDate, DWORD& dwTime
Out Parameters	: bool
Purpose			: Date time conversion
--------------------------------------------------------------------------------------*/
bool DateTimeForDB_R(LPTSTR szDateTime, ULONG64& ulDate, DWORD& dwTime)
{
	struct tm* tmtime = NULL;
	TCHAR szDate[3] = { 0 }, szMonth[5] = { 0 }, szYear[5] = { 0 };
	TCHAR szHour[3] = { 0 }, szMinute[3] = { 0 }, szSecond[3] = { 0 };


	if (!szDateTime || _tcslen(szDateTime) != 23)
	{
		return false;
	}

	szDate[0] = szDateTime[0];
	szDate[1] = szDateTime[1];
	szMonth[0] = szDateTime[3];
	szMonth[1] = szDateTime[4];
	szMonth[2] = szDateTime[5];
	szYear[0] = szDateTime[8];
	szYear[1] = szDateTime[9];
	szYear[2] = szDateTime[10];
	szYear[3] = szDateTime[11];
	szHour[0] = szDateTime[14];
	szHour[1] = szDateTime[15];
	szMinute[0] = szDateTime[17];
	szMinute[1] = szDateTime[18];
	szSecond[0] = szDateTime[20];
	szSecond[1] = szDateTime[21];
	GetMonthInNumberString(szMonth);

	time_t ltime;
	time(&ltime);

	tmtime = gmtime(&ltime);

	tmtime->tm_mday = _ttoi(szDate);
	tmtime->tm_mon = _ttoi(szMonth);
	tmtime->tm_year = _ttoi(szYear) - 1900;
	tmtime->tm_hour = _ttoi(szHour);
	tmtime->tm_min = _ttoi(szMinute);
	tmtime->tm_sec = _ttoi(szSecond);
	ltime = mktime(tmtime);
	if (_DateTimeForDB(ltime, ulDate, dwTime))
		return true;

	return false;
}

/*-------------------------------------------------------------------------------------
Function		: DateTimeForDB_RAct
In Parameters	: LPTSTR szDateTime, ULONG64& ulDate, DWORD& dwTime
Out Parameters	: bool
Purpose			: Date time conversion
--------------------------------------------------------------------------------------*/
bool DateTimeForDB_RAct(LPTSTR szDateTime, ULONG64& ulDate, DWORD& dwTime)
{
	struct tm* tmtime = NULL;
	TCHAR szDate[3] = { 0 }, szMonth[5] = { 0 }, szYear[5] = { 0 };
	TCHAR szHour[3] = { 0 }, szMinute[3] = { 0 }, szSecond[3] = { 0 };
	TCHAR szMilli[3] = { 0 };

	if (!szDateTime || _tcslen(szDateTime) != 27)
	{
		return false;
	}

	szDate[0] = szDateTime[0];
	szDate[1] = szDateTime[1];
	szMonth[0] = szDateTime[3];
	szMonth[1] = szDateTime[4];
	szMonth[2] = szDateTime[5];
	szYear[0] = szDateTime[8];
	szYear[1] = szDateTime[9];
	szYear[2] = szDateTime[10];
	szYear[3] = szDateTime[11];
	szHour[0] = szDateTime[14];
	szHour[1] = szDateTime[15];
	szMinute[0] = szDateTime[17];
	szMinute[1] = szDateTime[18];
	szSecond[0] = szDateTime[20];
	szSecond[1] = szDateTime[21];
	szMilli[0] = szDateTime[23];
	szMilli[1] = szDateTime[24];
	szMilli[2] = szDateTime[25];
	GetMonthInNumberString(szMonth);

	time_t ltime;
	time(&ltime);

	tmtime = gmtime(&ltime);

	tmtime->tm_mday = _ttoi(szDate);
	tmtime->tm_mon = _ttoi(szMonth);
	tmtime->tm_year = _ttoi(szYear) - 1900;
	tmtime->tm_hour = _ttoi(szHour);
	tmtime->tm_min = _ttoi(szMinute);
	tmtime->tm_sec = _ttoi(szSecond);
	DWORD dwMilli = _ttoi(szMilli);
	ltime = mktime(tmtime);
	if (_DateTimeForDBAct(ltime, ulDate, dwTime, dwMilli))
		return true;

	return false;
}

/*-------------------------------------------------------------------------------------
Function		: GetMonthInNumberString
In Parameters	: LPTSTR szMonth
Out Parameters	: void
Purpose			: Get month in number from string
--------------------------------------------------------------------------------------*/
void GetMonthInNumberString(LPTSTR szMonth)
{
	int iNullLocation = 1;
	if (!szMonth || !(*szMonth))
	{
		return;
	}

	if (0 == _tcsicmp(szMonth, L"Jan"))
	{
		szMonth[0] = L'0';
	}
	else if (0 == _tcsicmp(szMonth, L"Feb"))
	{
		szMonth[0] = L'1';
	}
	else if (0 == _tcsicmp(szMonth, L"Mar"))
	{
		szMonth[0] = L'2';
	}
	else if (0 == _tcsicmp(szMonth, L"Apr"))
	{
		szMonth[0] = L'3';
	}
	else if (0 == _tcsicmp(szMonth, L"May"))
	{
		szMonth[0] = L'4';
	}
	else if (0 == _tcsicmp(szMonth, L"Jun"))
	{
		szMonth[0] = L'5';
	}
	else if (0 == _tcsicmp(szMonth, L"Jul"))
	{
		szMonth[0] = L'6';
	}
	else if (0 == _tcsicmp(szMonth, L"Aug"))
	{
		szMonth[0] = L'7';
	}
	else if (0 == _tcsicmp(szMonth, L"Sep"))
	{
		szMonth[0] = L'8';
	}
	else if (0 == _tcsicmp(szMonth, L"Oct"))
	{
		szMonth[0] = L'9';
	}
	else if (0 == _tcsicmp(szMonth, L"Nov"))
	{
		szMonth[0] = L'1';
		szMonth[1] = L'0';
		iNullLocation = 2;
	}
	else if (0 == _tcsicmp(szMonth, L"Dec"))
	{
		szMonth[0] = L'1';
		szMonth[1] = L'1';
		iNullLocation = 2;
	}
	szMonth[iNullLocation] = L'\0';
}

/*-------------------------------------------------------------------------------------
Function		: GetThreatInfo
In Parameters	: ULONG ulSpyName, CString& csSpyName, BYTE& bThreatIndex, CString& csHelpInfo, CString csKeyValue, int iTypeId
Out Parameters	: bool
Purpose			: Get threat name type information
--------------------------------------------------------------------------------------*/
bool CFullScanReport::GetThreatInfo(ULONG ulSpyName, CString& csSpyName, BYTE& bThreatIndex, CString& csHelpInfo, CString csKeyValue, int iTypeId)
{
	if (m_objThreatInfo.IsLoaded() == false)
	{
		CRegistry objReg;
		CString csMaxDBPath;
		objReg.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
		m_objThreatInfo.SetTempPath(csMaxDBPath);
	}

	TCHAR strSpyName[MAX_PATH] = { 0 };
	TCHAR strHelpInfo[1024] = { 0 };
	LPCTSTR strCatName = NULL;
	ULONG ulCatID = 0;
	if (m_objThreatInfo.SearchItem(ulSpyName, bThreatIndex, strHelpInfo, 1024, strSpyName, MAX_PATH))
	{
		if (iTypeId == /*Cookie*/ Cookie_New)
		{
			csSpyName = csKeyValue + CString(strSpyName);
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

/*-------------------------------------------------------------------------------------
Function		: UpdateAvScanHistory
In Parameters	: 
Out Parameters	: void
Purpose			: Update Scan history data
--------------------------------------------------------------------------------------*/
void CFullScanReport::UpdateAvScanHistory(LPUFullScanReport pFullScanReport, DWORD dwReportLength)
{
	CSUUU2Info objScanInfo(true);
	CUUU2Info objDateInfo(true);
	CUU2Info objTimeInfo(true);
	CString csMachineID = _T("");

	SetFileAttributes(m_sSpyFoundDbPath, FILE_ATTRIBUTE_NORMAL);
	DeleteFile(m_sSpyFoundDbPath);
	SetFileAttributes(m_sSpyFoundActDbPath, FILE_ATTRIBUTE_NORMAL);
	DeleteFile(m_sSpyFoundActDbPath);
	m_iIndex = 0;

	CString csCurrentParentDate = L"";
	int iOnDemandOrActmon = ScanFullReportType::OnDemand;
	if (dwReportLength > 0)
	{
		iOnDemandOrActmon = pFullScanReport[0].iScannerType;
	}
	DWORD dwScanReportData = 0;
	bool bDataToCommit = false;
	bool bSameParent = false;
	bool bLastCommit = false;
	CString cslog;
	OutputDebugString(L"Update History");
	DWORD dwCounter = 0;
	while (dwScanReportData < dwReportLength)
	{
		if (iOnDemandOrActmon == pFullScanReport[dwScanReportData].iScannerType)
		{
			bSameParent = true;
		}
		else
		{
			bSameParent = false;
		}
		if (bSameParent || bDataToCommit)
		{
			if (bSameParent && (csCurrentParentDate.CompareNoCase(pFullScanReport[dwScanReportData].szDateTime) == 0 || csCurrentParentDate.IsEmpty()))
			{
				if (_tcslen(pFullScanReport[dwScanReportData].szPath) > 0 && _tcslen(pFullScanReport[dwScanReportData].szSpyName) > 0)
				{
					csCurrentParentDate = pFullScanReport[dwScanReportData].szDateTime;
					CString csValue = pFullScanReport[dwScanReportData].szSpyName;
					CString csSpyPath = pFullScanReport[dwScanReportData].szPath;
					DWORD dwTypeOfEntry = (eEntry_Status)pFullScanReport[dwScanReportData].iTypeOfEntry;
					DWORD dwSpyID = pFullScanReport[dwScanReportData].dwSpyID;
					eEntry_Status enumStatus = (eEntry_Status)pFullScanReport[dwScanReportData].iActionStatus;
					AddInSpyFoundListStruct((SD_Message_Info)dwTypeOfEntry, dwSpyID, csSpyPath, csValue, enumStatus);
					cslog.Format(_T("Threats:%d, CrrParent:%s, Spy:%s, Path:%s"), dwScanReportData, csCurrentParentDate, csValue, csSpyPath);
				}
				else
				{
					csCurrentParentDate = pFullScanReport[dwScanReportData].szDateTime;
					cslog.Format(_T("No Threats:%d, CrrParent:%s"), dwScanReportData, csCurrentParentDate);
				}
				//OutputDebugString(cslog);
				bDataToCommit = true;
				if (dwReportLength == (dwScanReportData + 1))
				{
					bLastCommit = true;
				}
				else
				{
					dwScanReportData++;
					continue;
				}
			}

			CString csDateText = csCurrentParentDate;
			csCurrentParentDate = pFullScanReport[dwScanReportData].szDateTime;

			if (csDateText.Trim().GetLength() != 0)
			{
				ULONG64 ulDate = 0;
				DWORD dwTime = 0;
				OutputDebugString(L"Before:" + csDateText);
				if (iOnDemandOrActmon == ScanFullReportType::OnDemand)
					DateTimeForDB_R(csDateText.GetBuffer(), ulDate, dwTime);
				else
					DateTimeForDB_RAct(csDateText.GetBuffer(), ulDate, dwTime);
				csDateText.ReleaseBuffer();
				ULONG64 ulDate1 = ulDate;
				DWORD dwTime1 = dwTime;
				TCHAR szDateTime[MAX_PATH] = { 0 };
				DateTimeForUI(ulDate1, dwTime1, szDateTime, MAX_PATH);
				OutputDebugString(szDateTime);

				if (!m_objSpyFoundList.GetFirst())
				{
					SPY_ENTRY_INFO DummySpyInfo = { 0 };
					m_objSpyFoundList.AppendItem(((DWORD)-1), &DummySpyInfo);
				}
				objTimeInfo.AppendItem(dwTime, m_objSpyFoundList);
				objDateInfo.AppendItem(ulDate, objTimeInfo);
				m_objSpyFoundList.RemoveAll();
				dwCounter++;
			}
			bDataToCommit = false;
			if (bLastCommit == false && bSameParent)
			{
				continue;
			}
		}
		if (objDateInfo.GetCount() > 0)
		{
			objScanInfo.AppendItem(csMachineID, objDateInfo);
			objScanInfo.Balance();

			if (m_sSpyFoundDbPath.GetLength() > 0)
			{
				CString sSpyFoundDb = m_sSpyFoundDbPath;

				if (iOnDemandOrActmon == ScanFullReportType::OnDemand)
					sSpyFoundDb = m_sSpyFoundDbPath;
				else
					sSpyFoundDb = m_sSpyFoundActDbPath;
				CSUUU2Info objFullScanInfo(false);
				objFullScanInfo.Load(sSpyFoundDb);
				objFullScanInfo.AppendObject(objScanInfo);
				objFullScanInfo.Balance();
				objFullScanInfo.Save(sSpyFoundDb);
				m_objSpyFoundList.RemoveAll();
			}
		}
		if (iOnDemandOrActmon == ScanFullReportType::OnDemand)
		{
			cslog.Format(_T("OnD Count: %d"), dwCounter);
			dwCounter = 0;
		}
		else
		{
			cslog.Format(_T("Act Count: %d"), dwCounter);
			dwCounter = 0;
		}
		OutputDebugStringW(cslog);
		cslog.Format(_T("total Count : % d"), dwReportLength);
		OutputDebugStringW(cslog);
		objTimeInfo.RemoveAll();
		objDateInfo.RemoveAll();
		objScanInfo.RemoveAll();
		iOnDemandOrActmon = pFullScanReport[dwScanReportData].iScannerType;
		if (bLastCommit)
		{
			break;
		}
	}
}

/*-------------------------------------------------------------------------------------
Function		: AddInSpyFoundListStruct
In Parameters	: SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, const WCHAR* strKey, const WCHAR* strValue, eEntry_Status eStatus
Out Parameters	: void
Purpose			: Append Scan history data object
--------------------------------------------------------------------------------------*/
void CFullScanReport::AddInSpyFoundListStruct(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, const WCHAR* strKey, const WCHAR* strValue, eEntry_Status eStatus)
{
	SPY_ENTRY_INFO oDBObj = { 0 };
	oDBObj.eTypeOfEntry = eTypeOfScanner;
	oDBObj.dwSpywareID = ulSpyName;
	oDBObj.szKey = (LPTSTR)strKey;
	oDBObj.szValue = (LPTSTR)strValue;
	oDBObj.byStatus = (BYTE)eStatus;
	m_objSpyFoundList.AppendItemAscOrder(++m_iIndex, &oDBObj);
}
/*-------------------------------------------------------------------------------------
Function		: :DestoryData
In Parameters	: -
Out Parameters	: -bool
Purpose			: Delete linklist memory
--------------------------------------------------------------------------------------*/
bool CFullScanReport::DestoryData()
{
	bool bRet = false;
	if (m_pFullScanReportLink != NULL)
	{
		m_pHeadReportLink = m_pFullScanReportLink;
		LPUFullScanReportLink pTempReportLink = NULL;
		while (m_pHeadReportLink != NULL)
		{
			pTempReportLink = m_pHeadReportLink->pLinkNode;
			free(m_pHeadReportLink);
			m_pHeadReportLink = pTempReportLink;
		}
		m_pFullScanReportLink = NULL;
		m_pHeadReportLink = NULL;
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: :DestoryData
In Parameters	: -int iScannerType, int iActionStatus, DWORD dwSpyID, int iTypeOfEntry, TCHAR* szSpyName, TCHAR* szPath, TCHAR* szDateTime
Out Parameters	: -void
Purpose			: Create Report linklist 
--------------------------------------------------------------------------------------*/
void CFullScanReport::CreateReportList(int iScannerType, int iActionStatus, DWORD dwSpyID, int iTypeOfEntry, TCHAR* szSpyName, TCHAR* szPath, TCHAR* szDateTime)
{
	LPUFullScanReportLink pTempReportLink = new UFullScanReportLink;
	memset(pTempReportLink, 0, sizeof(UFullScanReportLink));
	pTempReportLink->objFullScanReport.iScannerType = iScannerType;
	pTempReportLink->objFullScanReport.iActionStatus = iActionStatus;
	pTempReportLink->objFullScanReport.dwSpyID = dwSpyID;
	pTempReportLink->objFullScanReport.iTypeOfEntry = iTypeOfEntry;
	_tcscpy(pTempReportLink->objFullScanReport.szSpyName, szSpyName);
	_tcscpy(pTempReportLink->objFullScanReport.szPath, szPath);
	_tcscpy(pTempReportLink->objFullScanReport.szDateTime, szDateTime);
	pTempReportLink->pLinkNode = NULL;
	
	if (m_pFullScanReportLink == NULL)
	{
		m_pFullScanReportLink = pTempReportLink;
		m_pHeadReportLink = m_pFullScanReportLink;
		return;
	}
	else
	{
		m_pHeadReportLink->pLinkNode = pTempReportLink;
		m_pHeadReportLink = pTempReportLink;
	}

}