#include "SDSystemInfo.h"
#include "CommonFunctions.h"
#include "DirectoryManager.h"

#pragma once

class UpdateManager
{
public:
	UpdateManager(void);
	~UpdateManager(void);

	bool ExtractAndUpdateDownloads();
	void SetSDKParams(LIVEUPDATE_INFO *pUpdateInfo);
	bool ExtractDeltaFile(const CString &csDeltaFileName);

private:

	CString m_csServerVersionTXT;
	CString m_csDeltaVersionINI;
	CString m_csDeltaDetails;//DELTADETAILS

	CString m_csDownLoadPath;
	CString m_csIniPath;

	CStringArray m_csDBFileNames;

	bool m_bMaxDBMergeSuccess;
	CCommonFunctions m_objCommonFunctions;
	CDirectoryManager m_oDirectoryManager;

	bool ReadAllSectionNameFromIni();
	BOOL CheckVersionNumber(const CString &csSectionName);
	int CheckExistance(const CString &csSectionName, LPCTSTR szKeyName, const CString &csFileName, int iType);
	bool GetMD5Signature(const CString &csFileName, CString &csMD5);
	void MergeMaxDeltasEx();

};
