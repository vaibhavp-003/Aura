#include "SDSystemInfo.h"
#include "CommonFunctions.h"
#include "DirectoryManager.h"
#include "C7zDLL.h"

#pragma once

class CUpdateManagerEx
{
public:
	CUpdateManagerEx(void);
	~CUpdateManagerEx(void);

	bool ExtractAndUpdateDownloads();
	void SetSDKParams();
	bool ExtractDeltaFile(const CString &csDeltaFileName);
	void CopyDelta();

private:

	CString m_csServerVersionTXT;
	CString m_csDeltaVersionINI;
	CString m_csDeltaDetails;//DELTADETAILS
	CString m_csMaxDBVersionNo;
	CString m_csDeltaFileName;
	CString m_csSDKDetails;

	CString m_csDownLoadPath;
	CString m_csSettingIniPath;


	//CString m_csExtractFolderPath;

	CStringArray m_csDBFileNames;
	C7zDLL	m_obj7zDLL;

	bool m_bMaxDBMergeSuccess;
	bool m_bCopySuccess;
	bool m_bPartialDatabaseMerged;
	CCommonFunctions m_objCommonFunctions;
	CDirectoryManager m_oDirectoryManager;

	bool ReadAllSectionNameFromIni();
	BOOL CheckVersionNumber(const CString &csSectionName);
	int CheckExistance(const CString &csSectionName, LPCTSTR szKeyName, const CString &csFileName, int iType);
	bool GetMD5Signature(const CString &csFileName, CString &csMD5);
	void MergeMaxDeltasEx();
	void CopyDBFilesToData(CString csDbPath, CString csMergePath);
	CString GetDeltaVersion(const CString &csFileName);
	bool RenameDataFolder(CString csFileToMerge);
	bool ExtractAndMergeZipFile(CString csZipFilePath);
	void CopyZipFilesToFolder(CString csDbPath, CString csMergePath);
};
