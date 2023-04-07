#include "pch.h"
#include "InstantScanner.h"
#include "SDSystemInfo.h"

CInstantScanner::CInstantScanner(void):m_objFileNameDB(false), m_objSignatureDB(false)
{
}

CInstantScanner::~CInstantScanner(void)
{
}

void CInstantScanner::LoadEntriesFromINI()
{
	TCHAR szWinPath[MAX_PATH] = {0}, szSysPath[MAX_PATH] = {0};
	CString csFilePath;

	m_objFileNameDB.RemoveAll();
	m_objSignatureDB.RemoveAll();

	GetWindowsDirectory(szWinPath, _countof(szWinPath));
	GetWindowsDirectory(szSysPath, _countof(szSysPath));
	_tcscat_s(szSysPath, _countof(szSysPath), _T("\\System32"));

	CString csFileName = CSystemInfo::m_strAppPath + _T("Setting\\InstantScan.ini");
	if(_waccess_s(csFileName, 0) != 0)
	{
		return;
	}
	
	UINT ulNoOfEntries = GetPrivateProfileIntW(_T("FileList"), _T("NoOfEntries"), 0, csFileName);
	WCHAR lpstrFileToScan[MAX_PATH] = {0};

	for(UINT iCtr = 1; iCtr <= ulNoOfEntries; iCtr++)
	{
		CString csEntry;
		csEntry.Format(_T("%d"), iCtr);
		GetPrivateProfileStringW(_T("FileList"), csEntry, 0, lpstrFileToScan, MAX_PATH, csFileName);

		_tcslwr_s(lpstrFileToScan);
		csFilePath.Format(_T("%s"), lpstrFileToScan);
		csFilePath.Replace(_T("%sysdir%"), szSysPath);
		csFilePath.Replace(_T("%windir%"), szWinPath);

		//m_objFileNameDB.AppendItem(lpstrFileToScan, 295);		//SpyName Trojan.Agent  Changes By Ravi 6-April-2016  File path was old
		csFilePath.MakeLower();
		m_objFileNameDB.AppendItem(csFilePath, 295);		//SpyName Trojan.Agent
	}

	
	ulNoOfEntries = GetPrivateProfileIntW(_T("Signature"), _T("Count"), 0, csFileName);
	for(UINT iCtr = 1; iCtr <= ulNoOfEntries; iCtr++)
	{
		CString csEntry;
		csEntry.Format(_T("%d"), iCtr);
		GetPrivateProfileStringW(_T("Signature"), csEntry, 0, lpstrFileToScan, MAX_PATH, csFileName);

		if(_T('*') == lpstrFileToScan[16])
		{
			ULONG64 ulSig = 0;

			lpstrFileToScan[16] = 0;
			ulSig = _tcstoui64(lpstrFileToScan, NULL, 16);
			m_objSignatureDB.AppendItem(ulSig, _T("Unused"));		//SpyName Trojan.Agent
		}
	}

	m_objFileNameDB.Balance();
	m_objSignatureDB.Balance();

}

bool CInstantScanner::ScanFile(LPCTSTR lpstrFileToScan, bool bSigCreated, ULONG64 ulSignature)
{
	LPTSTR szData = 0;

	CS2U objTempFileNameDB(true);
	objTempFileNameDB.SetDataPtr(m_objFileNameDB.GetDataPtr(), 0, 0);

	if(objTempFileNameDB.SearchItem(lpstrFileToScan, NULL))
	{
		return true;
	}

	if(bSigCreated)
	{
		CQ2S objTempSignatureDB(true);
		objTempSignatureDB.SetDataPtr(m_objSignatureDB.GetDataPtr(), 0, 0);

		if(objTempSignatureDB.SearchItem(ulSignature, szData))
		{
			return true;
		}
	}

	return false;
}
