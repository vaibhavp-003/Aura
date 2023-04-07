/*======================================================================================
   FILE				: RegPathExpander.h
   ABSTRACT			: Registry PathExpander Class
   COMPANY			: Aura 
   AUTHOR			: Darshan Singh Virdi
   CREATION DATE	: 09-Sep-2006
   DESCRIPTION		: This class is responsible to handle all types of Paths in the registry
   VERSION HISTORY	: 
======================================================================================*/
#pragma once
#include "S2S.h"

class CRegPathExpander
{
public:
	bool m_bCheckFontDirectory;
	bool m_bStopScanning;
	CMapStringToString m_arrCheckedPath;
	CStringArray m_arrOtherPaths;
	CString	m_csFileFound;

	CRegPathExpander();
	virtual ~CRegPathExpander();
	bool DoesFileExist(CString csInPath);
	bool DoesFileOrFolderExist(CString csInPath);
	CString ExpandPath(CString filePath);
	CString ExpandTag(CString csFilePath);
	bool CheckIfFolder(CString csPath);

	CString GetWindowsDir()
	{
		return m_WINDOWS;
	}
	CString GetTempDir()
	{
		return m_TempDir;
	}
	CString GetTempInternetDir()
	{
		return m_TempInternetDir;
	}

	CStringArray &GetValidDriveArray()
	{
		return m_arrValidHardDrives;
	}

	bool IsPathStyle()
	{
		return m_bIsPathStyle;
	}

	CString GetStartMenuFolder()
	{
		return m_StartMenu;
	}

	CString GetCommonStartMenuFolder()
	{
		return m_CommonStartMenu;
	}
	CString GetCommonStartMenuProgramsFolder()
	{
		return m_CommonStartMenuPrograms;
	}
	
private: // Member functions
	void _InitDefaultPaths();
	bool _EnumForFolderPath(CString csPath);
	void _LoadValidDriveList();
	bool _CheckIgnoreList(CString csInPath);
	bool _CheckInOtherPaths(CString &csInpath);
	bool _CheckValidDrive(CString &csInpath);
	CString _GetFolderPath(int nFolder);
	CString _GetSingleFileName(CString csInPath);
	bool _GetSysWowPath(CString &csInpath);
	bool _CheckOnDrive(CString &csInpath, bool bCheckOtherPath = true);
	bool _CheckOnDriveNew(CString &csInpath, bool bCheckOtherPath = true);
	bool _CheckForExistance(CString csInPath);
	bool _TokenizeStringAndCheckPath(CString csInPath);
	bool _CheckForToken(CString csInPath, const TCHAR *cToken);
	bool _CheckBlankSpacePath(CString csInPath);
	bool _CheckDoubleQuotePath(CString csInPath, CString &csOutPath);
	bool _CheckAtTheRatePath(CString csInPath, CString &csOutPath);
	bool _CheckCommaPath(CString csInPath, CString &csOutPath);
	bool _CheckForwardSlash(CString csInPath, CString &csOutPath);
	bool _CheckBackwardSlash(CString csInPath, CString &csOutPath);
	bool _CheckBlankSpacePath(CString csInPath, CString &csOutPath);
	bool _CheckAPPDataPath(CString csInPath, CString &csOutPath);
	bool _CheckSpecialTags(CString csInPath, CString &csOutPath);
	bool _CheckSquareBracketsPath(CString csInPath, CString &csOutPath);
	bool _CheckPercentAndHyphenPath(CString csInPath, CString &csOutPath);
	bool _CheckDoubleQuoteAndHyphenPath(CString csInPath, CString &csOutPath);
	bool _CheckBracketAndMissingDotPath(CString csInPath, CString &csOutPath);
	bool _CheckReverseDotSpacePath(CString csInPath,CString &csOutPath);
	bool _VerifyParentFolderRights(const CString &csInpath);
	// Data Members
	bool m_bIgnoreFolder;
	bool m_bIsPathStyle;
	CStringArray m_arrValidHardDrives;
	CStringArray m_arrIgnoreIniList;
	TCHAR m_strOSVersion[MAX_PATH];
	CString m_PROGRAM_FILES;	
	CString m_PROGRAM_FILES_X86;	
	CString m_SYSTEM_WOW64;
	CString m_PROGRAM_FILES_COMMON;
	CString m_PROGRAM_FILES_COMMON_X86;
	CString m_WINDOWS;
	CString m_SYSTEM;
	CString m_ROOT;
	CString m_UserProfile;
	CString m_AppData;
	CString m_LocalAppData;
	CString m_ResourceDir;
	CString m_StartMenu;
	CString m_CommonStartMenu;
	CString m_TempDir;
	CString m_TempInternetDir;
	CString m_WebDir;
	CString m_csAllUserProfile;
	CString m_CommonStartMenuPrograms;
	CS2S m_ParsedFileList;
};