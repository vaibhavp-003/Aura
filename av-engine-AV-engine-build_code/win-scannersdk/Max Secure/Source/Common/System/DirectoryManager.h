#pragma once

class CDirectoryManager
{
public:
	CDirectoryManager(void);
	virtual ~CDirectoryManager(void);

	bool MaxCreateDirectoryForFile(LPCTSTR szFilePath);
	bool MaxCreateDirectory(LPCTSTR szPath);
	bool MaxDeleteDirectory(LPCTSTR szPath, bool bRecursive);
	bool MaxDeleteDirectoryContents(LPCTSTR szPath, bool bRecursive);
	bool MaxDeleteDirectory(LPCTSTR szPath, LPCTSTR szIgnorePath, bool bRecursive);
	bool MaxDeleteDirectory(LPCTSTR szPath, bool bRecursive, bool bAddRestartDelete);
	bool MaxDeleteDirectory(LPCTSTR szPath, LPCTSTR szIgnorePath, bool bRecursive, bool bAddRestartDelete);
	bool MaxMoveDirectory(LPCTSTR szDstPath, LPCTSTR szSrcPath, bool bRecursive, bool bOverWrite, bool bIgnoreOnOverWriteFail = false);
	bool MaxCopyDirectory(LPCTSTR szDstPath, LPCTSTR szSrcPath, bool bRecursive, bool bOverWrite,
							CStringArray* pcsarrIgnoreList=NULL, CStringArray* pcsarrAllowedList=NULL,
							bool bContinueIfFail = false);
	bool AppendString(LPTSTR szFinal, DWORD cchFinal, LPCTSTR szAppend);
	bool FormatStrings(LPTSTR szFinal, DWORD cchFinal, LPCTSTR szFormat, ...);
	bool JoinStrings(LPTSTR szDest, SIZE_T cchDest, LPCTSTR szFirst, ...);
	bool IsFilePresentInList(CString csFileName, CStringArray* pcsarrList);
	void MaxDeleteTempData(LPCTSTR szPath);
	bool IsImportantDir(LPCTSTR szPath);
};
