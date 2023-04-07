#pragma once
#include "pch.h"
#include "SDSystemInfo.h"
#include "FileSig.h"

typedef struct _ScanByNameFiles
{
	wchar_t szFilePath[260];
} ScanByNameFiles;

class CScanByName
{
public:
	CScanByName();
	~CScanByName();

public:
	CString m_csINIFileName;
	CFileSig* m_pFileSig;
	CStringArray csScanByNameArray;
	CStringArray csScanByNameWormArray;
	void ScanByNameCount(int iScanByNameArrayLen, int* ptrScanByNameCountArray);
	void GetScanByNameData(ScanByNameFiles* pScnByNameDataArray, int iScanByNameDataSize);
	void AddScanByNameData(ScanByNameFiles* pScnByNameDataArray, int iScanByNameDataSize);
	void RemoveEntryFromLocalDB(LPCTSTR pszFilePath);
	void OnClickApply();
	void OnClickRemove(ScanByNameFiles* pScnByNameDataArray, int iScanByNameDataSize);
	void CreateWormstoDeleteINI(CString strINIPath);
};