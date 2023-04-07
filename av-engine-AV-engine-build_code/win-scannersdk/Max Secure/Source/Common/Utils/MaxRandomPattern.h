#pragma once
#include <Python.h>
class CMaxRandomPattern
{
	bool		GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT);
	bool		GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT);
	bool		IsValidFile2Scan(LPCTSTR pszFile2Check);
	bool		CheckScanPatternDigi(LPCTSTR pszFile2Scan);
	bool		IsKnowCompanyName(LPCTSTR pszComName2Check);
	int			LoadCompanyNameList();
	bool		IsPatternPresent(LPCTSTR pszPattern2Scan);
	bool		IsFileLessMalware(LPCTSTR szFilePath);
	CStringArray	m_csCompanySafeList;
	
	bool		m_bRandPatternLoaded;
	PyObject	*m_pMaxRandLrnLib, *m_pMaxRandLrnModule, *m_pImportDict;
	PyObject	*m_pMaxFileLessLib, *m_pMaxFileLessModule, *m_pImportFileLessDict;
	TCHAR		szLogLine[1024];
	

public:
	CMaxRandomPattern(void);
	~CMaxRandomPattern(void);
	
	//bool	InitializeScanner(LPCTSTR pszClassifierPath,LPCTSTR pszFeaturesPath);
	bool	UnloadDB();
	bool	CheckInitializeScan(LPCTSTR pszDBPath,bool bMLScanner);
	bool	CheckScanPattern(LPCTSTR pszFile2Scan);
	bool	InitializeScanner(LPCTSTR pszDBPath,bool bRPScanner);
	bool	ScanPattern(LPCTSTR pszFile2Scan);
	bool	ScanFLessMal(LPCTSTR szFilePath);
private :
	CString		GetAllUserAppDataPath();
	CString		GetAPPDataPath();
	CString		GetProgramFilesDir();
	CString		GetProgramFilesDirX64();
	CString		m_csAppDataPath;
	CString		m_csProgFiles;
	CString		m_csProgFilesx86;
	CString		m_csProgData;
	CString		m_csAppDataTempPath;
	
};
