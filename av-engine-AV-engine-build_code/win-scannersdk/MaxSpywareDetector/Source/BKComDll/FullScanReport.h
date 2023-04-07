#pragma once
#include "ThreatInfo.h"
#include "U2Info.h"
class CFullScanReport
{
public:
	CFullScanReport();
	~CFullScanReport();
	void ShowAvScanHistory(LPUFullScanReport pFullScanReport, DWORD dwReportLength);
	void UpdateAvScanHistory(LPUFullScanReport pFullScanReport, DWORD dwReportLength);
	DWORD GetScanFullReportCount();
private:
	CString m_sSpyFoundDbPath;
	CString m_sSpyFoundActDbPath;
	CThreatInfo m_objThreatInfo;
	static CU2Info		m_objSpyFoundList;
	static ULONG		m_iIndex;
	DWORD m_dwTotalListCount;

	LPUFullScanReportLink m_pFullScanReportLink;
	LPUFullScanReportLink m_pHeadReportLink;
	bool DestoryData();
	bool GetThreatInfo(ULONG ulSpyName, CString& csSpyName, BYTE& bThreatIndex, CString& csHelpInfo, CString csKeyValue, int iTypeId);
	void AddInSpyFoundListStruct(SD_Message_Info eTypeOfScanner, const ULONG ulSpyName, const WCHAR* strKey, const WCHAR* strValue, eEntry_Status eStatus);
	void CreateReportList(int iScannerType, int iActionStatus, DWORD dwSpyID, int iTypeOfEntry, TCHAR* szSpyName, TCHAR* szPath, TCHAR* szDateTime);

};

