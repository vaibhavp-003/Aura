/*======================================================================================
   FILE				: RegPathExpander.cpp
   ABSTRACT			: Registry PathExpander Class
   COMPANY			: Aura 
   AUTHOR			: Darshan Singh Virdi
   CREATION DATE	: 09-Sep-2006
   DESCRIPTION		: This class is responsible to handle all types of Paths in the registry
   VERSION HISTORY	: 
======================================================================================*/
#include "pch.h"
#include <io.h>
//#include <shfolder.h>
#include <shlobj.h>
#include <windows.h>
#include "Registry.h"
#include "CPUinfo.h"
#include "RegPathExpander.h"

/*-------------------------------------------------------------------------------------
	Function		: CRegPathExpander
	In Parameters	: None
	Out Parameters	: None
	Purpose			: Constructor, Inits all default values
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CRegPathExpander::CRegPathExpander(void):m_ParsedFileList(false)
{
	m_bCheckFontDirectory	= false;
	m_bStopScanning			= false;
	m_bIsPathStyle			= false;
	
	m_PROGRAM_FILES				= this->_GetFolderPath( CSIDL_PROGRAM_FILES );
	m_PROGRAM_FILES_X86			= m_PROGRAM_FILES + _T(" (x86)");
	m_PROGRAM_FILES_COMMON		= this->_GetFolderPath( CSIDL_PROGRAM_FILES_COMMON );
	m_PROGRAM_FILES_COMMON_X86  = m_PROGRAM_FILES_X86 + _T("\\Common Files");
	m_WINDOWS					= this->_GetFolderPath( CSIDL_WINDOWS );
	m_SYSTEM					= this->_GetFolderPath( CSIDL_SYSTEM );
	m_SYSTEM_WOW64				= m_WINDOWS + _T("\\SysWOW64");
	m_AppData					= this->_GetFolderPath( CSIDL_APPDATA );		// C:\Documents and Settings\username\Application Data
	m_LocalAppData				= this->_GetFolderPath( CSIDL_LOCAL_APPDATA );	// C:\Documents and Settings\username\Local Settings\Application Data
	m_ResourceDir				= m_WINDOWS + _T("\\Resources");
	m_ROOT						= m_PROGRAM_FILES.Mid(0, m_PROGRAM_FILES.Find( _T(":"))+1);
	m_StartMenu					= this->_GetFolderPath( CSIDL_STARTMENU );			// C:\Documents and Settings\username\Start menu
	m_CommonStartMenu			= this->_GetFolderPath( CSIDL_COMMON_STARTMENU );	// C:\Documents and Settings\All Users\Start menu
	m_CommonStartMenuPrograms	= this->_GetFolderPath( CSIDL_COMMON_PROGRAMS );	// C:\Documents and Settings\All Users\Start menu\Programs

	m_TempInternetDir			= this->_GetFolderPath( CSIDL_INTERNET_CACHE );
	m_TempDir					= m_TempInternetDir;
	m_TempDir.Replace(_T("\\temporary internet files"), _T("\\temp"));

	m_WebDir					= m_WINDOWS + _T("\\web");
	m_UserProfile				= this->_GetFolderPath( CSIDL_PROFILE );
	//adding one more tag.
	m_csAllUserProfile =  this->_GetFolderPath( CSIDL_COMMON_STARTMENU );
	int iPosition = m_csAllUserProfile.ReverseFind(L'\\');
	m_csAllUserProfile = m_csAllUserProfile.Mid(0,iPosition);

	_LoadValidDriveList();
}

CRegPathExpander::~CRegPathExpander()
{
	m_arrOtherPaths.RemoveAll();
	m_arrValidHardDrives.RemoveAll();
	m_arrCheckedPath.RemoveAll();
}

/*-------------------------------------------------------------------------------------
	Function		: ExpandPath
	In Parameters	: CString filePath, file path to be expanded
	Out Parameters	: CString, Expanded file path
	Purpose			: Expands the given file path according to the Environment variables
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CString CRegPathExpander::ExpandPath(CString filePath)
{
	//expanding the path tag only.: Avinash Bhardwaj
	if(filePath.Replace( CONST_PROGRAM_FILES_COMMON_DIR		, m_PROGRAM_FILES_COMMON) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_PROGRAM_FILES_DIR		, m_PROGRAM_FILES		) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_PROFILE_DIR				, m_UserProfile			) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_USER_APPDATA_DIR		, m_AppData				) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_LOCAL_APPDATA_DIR		, m_LocalAppData		) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_RESOURCE_DIR			, m_ResourceDir		) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_WINDOWS_DIR				, m_WINDOWS 		) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_SYSTEM_ROOT				, m_WINDOWS			) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_SYSTEM_DRIVE			, m_ROOT			) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_WEB_DIR					, m_WebDir			) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_TEMP_DIR				, m_TempDir			) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_PROGRAM_FILES_X86_DIR	, m_PROGRAM_FILES_X86) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_PROGRAM_FILES_X86_DIR	, m_SYSTEM_WOW64	) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_PROGRAM_FILES_COMMON_X86 , m_PROGRAM_FILES_COMMON_X86 ) != 0)
		m_bIsPathStyle = true;
	else if (filePath.Replace( CONST_PROGRAM_W6432 , m_PROGRAM_FILES ) != 0)
		m_bIsPathStyle = true;
	else if (filePath.Replace( CONST_COMMON_W6432 , m_PROGRAM_FILES_COMMON ) != 0)
		m_bIsPathStyle = true;
	else if(filePath.Replace( CONST_ALL_USER_PROFILE , m_csAllUserProfile ) != 0)
		m_bIsPathStyle = true;

	CString csOutPath = filePath;
	TCHAR pathbuffer[MAX_PATH] = {0};
	if(!csOutPath.IsEmpty() && csOutPath.GetLength()<=MAX_PATH)
	{
		_wsearchenv_s((LPCTSTR)csOutPath, _T("PATH"), pathbuffer, MAX_PATH);
	}
	
	if(wcslen(pathbuffer) != 0)
	{
		m_bIsPathStyle = true;
		csOutPath = pathbuffer;
	}
	else 
		csOutPath = filePath;

	csOutPath.Trim();
	return csOutPath;
}

/*-------------------------------------------------------------------------------------
	Function		: _GetFolderPath
	In Parameters	: int nFolder, The type of folder to be retrieved
	Out Parameters	: CString, Folder path according to the system
	Purpose			: Retrieves the Actual folder path from the system
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CString CRegPathExpander::_GetFolderPath(int nFolder)
{
	CString csOutput;
	TCHAR szPath[MAX_FILE_PATH] = {0};
	
	if( SUCCEEDED(SHGetFolderPath(0, nFolder, NULL, 0, szPath)))
	{
		csOutput = szPath;
		return csOutput.MakeLower();
	}
	else
	{
		return _T("");
	}
}

/*-------------------------------------------------------------------------------------
	Function		: _InitDefaultPaths
	In Parameters	: None
	Out Parameters	: None
	Purpose			: Inits more paths, like .NET environments path
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CRegPathExpander::_InitDefaultPaths()
{
}

/*-------------------------------------------------------------------------------------
	Function		: _EnumForFolderPath
	In Parameters	: CString csPath
	Out Parameters	: None
	Purpose			: Eunmerates Folder path
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_EnumForFolderPath(CString csPath)
{
	bool bAllWell = true;
	try
	{
		csPath += _T("\\*.*");
		CFileFind finder;
		if(!finder.FindFile(csPath))
		{
			finder.Close();
			return bAllWell;
		}
		BOOL bRet = TRUE;
		while(bRet)
		{
			if( m_bStopScanning)
				break;
			bRet = finder.FindNextFile();
	
			if (finder.IsDots())
				continue;

			//Nupur: Skipping symbolic links/junction points
			if( finder.MatchesMask(FILE_ATTRIBUTE_REPARSE_POINT))
				continue;
	
			if (finder.IsDirectory())
			{
				m_arrOtherPaths.Add(finder.GetFilePath());
				bAllWell = _EnumForFolderPath(finder.GetFilePath());
				if(!bAllWell)
					break;
			}
		}
		finder.Close();	
	}
	catch(...)
	{
		bAllWell = false;
		AddLogEntry(_T("Exception caught in CRegPathExpander::_EnumForFolderPath: " )+ csPath);
	}
	return bAllWell;
}

/*-------------------------------------------------------------------------------------
	Function		: _GetSysWowPath
	In Parameters	: CString csInPath, the path to be replaced with SysWow path
	Out Parameters	: TRUE if the file is replaced else False
	Purpose			: Converts the x64 path to syswow path and vise versa
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_GetSysWowPath(CString &csInpath)
{
	if(csInpath.Replace(m_PROGRAM_FILES_COMMON, m_PROGRAM_FILES_COMMON_X86) != 0)
		return true;
	else if(csInpath.Replace(m_PROGRAM_FILES, m_PROGRAM_FILES_X86) != 0)
		return true;
	else if(csInpath.Replace(m_SYSTEM, m_SYSTEM_WOW64) != 0)
		return true;
	else if(csInpath.Replace(m_PROGRAM_FILES_COMMON_X86, m_PROGRAM_FILES_COMMON) != 0)
		return true;
	else if(csInpath.Replace(m_PROGRAM_FILES_X86, m_PROGRAM_FILES) != 0)
		return true;
	else if(csInpath.Replace(m_SYSTEM_WOW64, m_SYSTEM) != 0)
		return true;

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckOnDrive
	In Parameters	: CString csInPath, the file to be searched for
	Out Parameters	: TRUE if the file is valid else False
	Purpose			: Directly searches the filesystem for the given file
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckOnDrive(CString &csInpath, bool bCheckOtherPath)
{
	CString csCheckPathInpath(csInpath);
	if(_CheckOnDriveNew(csCheckPathInpath, bCheckOtherPath))
		return true;

#ifdef WIN64
	csCheckPathInpath = csInpath;
	if(_GetSysWowPath(csCheckPathInpath))
	{
		if(_CheckOnDriveNew(csCheckPathInpath, bCheckOtherPath))
		{
			return true;
		}
	}
#endif
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckOnDriveNew
	In Parameters	: CString csInPath, the file to be searched for
	Out Parameters	: TRUE if the file is valid else False
	Purpose			: Directly searches the filesystem for the given file
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckOnDriveNew(CString &csInpath, bool bCheckOtherPath)
{
	try
	{
		TCHAR pathbuffer[MAX_FILE_PATH] = {0};
		if(GetLongPathName(csInpath, pathbuffer, MAX_FILE_PATH) != 0)
		{
			m_csFileFound = pathbuffer;
			csInpath = pathbuffer;
		}

		if(m_bStopScanning)
			return true;

		if(csInpath.Find(_T("*")) != -1) //Filename with '*' isnot valid
			return true;

		if(csInpath.GetLength() > 2)
		{
			// Checking network drive path takes ages to return, atleast 15 seconds for each file
			// hence ignoring all network file paths
			if((csInpath[0] == _T('\\')) && (csInpath[1] == _T('\\')))
				return true;
		}

		if(_waccess(csInpath, 0) == 0)
		{
			m_csFileFound = csInpath;
			if(m_bIgnoreFolder)
			{
				if(_wchdir((LPCTSTR)csInpath)) // return FALSE if this is a Directory and not a file
					return true;
			}
			else
				return true;
		}
		else
		{
			CFileFind finder;
			if(finder.FindFile(csInpath))
			{
				finder.Close();
				m_csFileFound = csInpath;
				return true;
			}

			if(!_CheckValidDrive(csInpath)) // file is not in a valid drive, ignore this entry
				return true;

			if(bCheckOtherPath)
			{
				if(_CheckInOtherPaths(csInpath))
				{
					m_csFileFound = csInpath;
					if(m_bIgnoreFolder)
					{
						if(_wchdir((LPCTSTR)csInpath)) // return FALSE if this is a Directory and not a file
							return true;
					}
					else
						return true;
				}
			}
		}

		//Ravi ==> Added this check to Handle StartUp scan Crash on Win10 (Problem with .sys files)
		if(csInpath.Find(L":\\") != -1)
		{
			//Check for file existence i.e, filename without file extention is given
			HMODULE hFileHndle = LoadLibrary((LPCTSTR)csInpath);
			if(hFileHndle == NULL)
			{
				DWORD dwError = GetLastError();
				if(dwError != ERROR_MOD_NOT_FOUND)
					return true;
			}
			else
			{
				::FreeLibrary(hFileHndle);
				hFileHndle = NULL;
				m_csFileFound = csInpath;
				return true;
			}
		}

		// SMA: For Vista Standard user : False positive issue.
		if(_VerifyParentFolderRights(csInpath))
			return true;

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegPathExpander::_CheckOnDrive : ") + csInpath);
		return true;
	}	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _VerifyParentFolderRights
	In Parameters	: CString csInPath, the path to be searched for
	Out Parameters	: TRUE if the folder is valid else False
	Purpose			: On Vista standard user, it gives invalid path for paths
					  existing at other users as it is not having access to those paths
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_VerifyParentFolderRights(const CString &csInpath)
{
	WCHAR strWorkingDir[MAX_PATH] = {0};
	try
	{
		CString csToken, csPathToCheck;
		bool bPathExists = false;
		int iPos = 0;

		if(!_wgetcwd(strWorkingDir, MAX_PATH))
			return false;

		CString csInputPath = csInpath;
		if(csInputPath.Find('\\') == -1)
		{
			_wchdir(strWorkingDir);
			return false;
		}

		csToken = csInputPath.Tokenize(L"\\", iPos);
		csPathToCheck = csToken;
		while(csToken != L"")
		{
			if(_wchdir(csPathToCheck) == 0)
				bPathExists = true;
			else
			{
				if(errno == ENOENT)
					bPathExists = false;
				else if(errno == EACCES)	 // ignore directories where we get 'access denined'
					bPathExists = true;
				break;
			}
			csToken = csInputPath.Tokenize(L"\\", iPos);
			csPathToCheck += L"\\" + csToken;
		}
		_wchdir(strWorkingDir);
		return bPathExists;
	}
	catch(...)
	{
		_wchdir(strWorkingDir);
		AddLogEntry(_T("Exception caught in CRegPathExpander::_VerifyParentFolderRights : ") + csInpath);
		return true;
	}	

	_wchdir(strWorkingDir);
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckInOtherPaths
	In Parameters	: CString csInPath, the file to be searched for
	Out Parameters	: TRUE if the file is valid else False
	Purpose			: Searches in other paths, like .NET framework installation dir
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckInOtherPaths(CString &csInpath)
{
	bool bReturnVal = false;

	// We will ignore this check for a file which has a ':\'
	if((csInpath.Find(_T(':')) != -1) || (csInpath.Find(_T('"')) != -1)
		|| (csInpath.Find(_T('<')) != -1) || (csInpath.Find(_T('>')) != -1)
		|| (csInpath.Find(_T('?')) != -1) || (csInpath.Find(_T('*')) != -1)
		|| (csInpath.Find(_T('|')) != -1) || (csInpath.Find(_T('/')) != -1))
		return false;

	if(((csInpath[0] == _T('%')) || (csInpath[1] == _T('%'))) && (csInpath.Find(_T("%\\")) != -1))
		return false;

	if(m_bStopScanning)
		return true;

	if(m_bCheckFontDirectory)
	{
		if(_waccess(m_WINDOWS + _T("\\Fonts\\") + csInpath, 0) == 0)
		{
			csInpath = m_WINDOWS + _T("\\Fonts\\") + csInpath;
			return true;
		}
		else
		{
			return false;
		}
	}

	CString csOrgPath = csInpath;
	CString csOut;
	if(m_arrCheckedPath.Lookup(csInpath, csOut))
	{
		if(csOut == _T("1"))
			return true;
		else
			return false;
	}

	if(m_arrOtherPaths.GetCount() == 0)
		_InitDefaultPaths();

	// giving benefit of doubt if we were not able to scan
	// the hard disk for all valid paths!
	if(m_arrOtherPaths.GetCount() == 0)
		return true;

	INT_PTR nCount = m_arrOtherPaths.GetCount();
	for(INT_PTR i=0; i < nCount; i++)
	{
		if(m_bStopScanning) // breaking without complete check so return true
		{
			bReturnVal = true;
			break;
		}
		if(_waccess(m_arrOtherPaths[i] + BACK_SLASH + csInpath, 0) == 0)
		{
			csInpath = m_arrOtherPaths[i] + BACK_SLASH + csInpath;
			bReturnVal = true;
			break;
		}
	}

	if(bReturnVal)
		m_arrCheckedPath.SetAt(csOrgPath, _T("1"));
	else
		m_arrCheckedPath.SetAt(csOrgPath, _T("0"));
	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckValidDrive
	In Parameters	: CString csInPath, the file to be searched for
	Out Parameters	: TRUE if the file is not in the VALID Drive List else False
	Purpose			: Check the first three chars for Drive letter, if the drive letter is not
					  found in our valid drive list, then we give benefit of doubt to this file
					  and return TRUE
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckValidDrive(CString &csInpath)
{
	bool bReturnVal = false;

	if(csInpath.GetLength() < 3)
		return true;  // we dont know the drive letter, considering it as a valid drive file

	// We will ONLY check for a file which has a ':\' in its name
	if((csInpath[1] != _T(':')) || (csInpath[2] != _T('\\')))
		return true; // we dont know the drive letter, considering it as a valid drive file

	for(int i=0; i < m_arrValidHardDrives.GetCount(); i++)
	{
		if(m_arrValidHardDrives[i].CompareNoCase(csInpath.Left(3)) == 0)
		{
			m_bIsPathStyle = true;
			bReturnVal = true; // This file belongs to one of the valid drives
			break;
		}
	}
	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
	Function		: _GetSingleFileName
	In Parameters	: CString csInPath, path to be parsed
	Out Parameters	: CString, parsed file name
	Purpose			: Extracts the dll file name from the given path
					E.G: rundll32 googletoolbar1.dll, someparam
					E.G: rundll32.exe googletoolbar1.dll, someparam
					E.G: regsvr32 /u /s "e:\program files\google\googletoolbar1.dll"
					E.G: rundll32 sqlsun,OpenSavedDsQuery
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CString CRegPathExpander::_GetSingleFileName(CString csInPath)
{
	CString csOutpath;
	CString csTemp1 = m_SYSTEM + _T("\\rundll32 ");
	CString csTemp2 = m_SYSTEM + _T("\\rundll32.exe ");
	if((csInPath.Left(9) == _T("rundll32 ")) || (csInPath.Left(13) == _T("rundll32.exe ")) ||
		(csInPath.Left(csTemp1.GetLength()) == csTemp1) || 
		(csInPath.Left(csTemp2.GetLength()) == csTemp2))
	{
		m_bIsPathStyle = true;
		csInPath = csInPath.Mid(csInPath.Find(' '));
		int nSize = csInPath.GetLength();
		for(int i = 0; i < nSize ; i++)
		{
			if(csInPath[i] == ',')			// May or may not be there!
				break;
			else
				csOutpath += csInPath[i];
		}
		// Darshan
		// Add .dll to the path if its missing in the registry entry!
		if(csOutpath.Right(4) != _T(".dll"))
			csOutpath += _T(".dll");
		csOutpath = ExpandPath(csOutpath.Trim());
		return csOutpath;
	}

	csTemp1 = m_SYSTEM + _T("\\regsvr32 ");
	csTemp2 = m_SYSTEM + _T("\\regsvr32.exe ");
	if((csInPath.Left(9) == _T("regsvr32 ")) || (csInPath.Left(13) == _T("regsvr32.exe ")) ||
		(csInPath.Left(csTemp1.GetLength()) == csTemp1) || 
		(csInPath.Left(csTemp2.GetLength()) == csTemp2))
	{
		m_bIsPathStyle = true;
		csOutpath = csInPath.Mid(csInPath.Find(' '));
		csOutpath.Replace(_T("/u"), _T(""));
		csOutpath.Replace(_T("/s"), _T(""));
		csOutpath = ExpandPath(csOutpath.Trim());
		return csOutpath;
	}

	//This code has been added for handling a special type of entry in run which passes rundll32.exe as parameter
	//to some executable. For extracting such path we'll have to take the exe path before rundll32.exe
	//adding code for a new path.
	//For Ex- "c:\progra~1\landesk\ldclient\softmon.exe" /r rundll32.exe streamci,streamingdevicesetup
	int iRDllPos = csInPath.Find(L"rundll32"); //looking for rundll32 or rundll32.exe
	int iExePos = csInPath.Find(L".exe"); // looking for .exe's location
	if(iRDllPos != -1 && iExePos != -1 && iExePos < iRDllPos)
	{
		csOutpath = csInPath.Left(iExePos+4);
		return csOutpath ;
	}
	return csInPath;
}

/*-------------------------------------------------------------------------------------
	Function		: _LoadValidDriveList
	In Parameters	: None
	Out Parameters	: None
	Purpose			: Loads the list of all drives which are currently valid
					  Used to ignore files which are placed on a removal driver
					//[2580] Missing: g:\it54\bin\intel.rel\itircl54.dll
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CRegPathExpander::_LoadValidDriveList()
{
	TCHAR cDrive;
	DWORD dwDrivesOnSystem = GetLogicalDrives();
	UINT  uDriveType;
	TCHAR szDriveRoot[] = _T("x:\\");
	m_arrValidHardDrives.RemoveAll();

	for(cDrive = _T('A'); cDrive <= _T('Z'); cDrive++, dwDrivesOnSystem >>= 1)
	{
		if(!(dwDrivesOnSystem & 1))
			continue;

		szDriveRoot[0] = cDrive;
		uDriveType = GetDriveType(szDriveRoot);

		switch(uDriveType)
		{
			case DRIVE_NO_ROOT_DIR:
			case DRIVE_UNKNOWN:
			{
				continue;
			}
			break;
			case DRIVE_REMOVABLE:
			{
				continue;
			}
			break;
			case DRIVE_FIXED:
			{
				m_arrValidHardDrives.Add(szDriveRoot);
				continue;
			}
			break;
			case DRIVE_REMOTE:
			{
				continue;
			}
			break;
			case DRIVE_CDROM:
			{
				continue;
			}
			break;
			case DRIVE_RAMDISK:
			{
				continue;
			}
			break;
			default:
			{
			}
		}
	}
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckDoubleQuotePath
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					// E.G: "%programfiles%\Adobe\Acrobat 7.0\Reader\AcroRd32Info.exe" /PDFShell
					// E.G: "E:\Program Files\Adobe\Acrobat 7.0\Reader\AcroRd32Info.exe" /PDFShell
					// E.G: "%programfiles%\internet explorer\iexplore.exe",-32528
					// E.G: "%SystemRoot%\System32\dmview.ocx"
					// E.G: "e:\progra~1\micros~4\office11\excel.exe",1
					// E.G: "E:\Program Files\Microsoft Visual Studio\Common\MSDev98\Bin\msdev.exe,<" "%1"
					// E.G: "%ProgramFiles%\Internet Explorer\Connection Wizard"
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckDoubleQuotePath(CString csInPath, CString &csOutPath)
{
	int iSlashPos = csInPath.Find(BACK_SLASH);
	int iQuotePos = csInPath.Find(_T('"'));
	csOutPath = _T("");
	
	if((iSlashPos > 0) && (iQuotePos == 0))
	{
		csInPath = csInPath.Mid(1);
		if(csInPath.Find(_T('"')) == -1) // Must have 2 double quotes to be labled as a valid path
			return false;
		
		int nPathLen = csInPath.GetLength();
		for(int i = 0; i < nPathLen; i++)
		{
			if((csInPath[i] == _T('"')) || (csInPath[i] == _T(',')))
				break;
			else
				csOutPath += csInPath[i];
		}
		m_bIsPathStyle = true;
		csOutPath = ExpandPath(csOutPath);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckAtTheRatePath
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					// E.G: @shdoclc.dll,-867
					// E.G: @E:\Windows\System32\shdoclc.dll
					// E.G: @"E:\Program Files\Windows NT\Accessories\WORDPAD.EXE",-208
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckAtTheRatePath(CString csInPath, CString &csOutPath)
{
	int iDotPos = csInPath.Find(_T("."));
	int iAtPos = csInPath.Find(_T('@'));
    int iHashPos = csInPath.Find(_T('#'));
	csOutPath = _T("");

	if((iDotPos > 0) && (iAtPos == 0 ||  iHashPos == 0))
	{
		csInPath.Replace(_T("\""), _T(""));
		int nPathLen = csInPath.GetLength();
		for(int i = 1; i < nPathLen; i++)
		{
			if(csInPath[i] == _T(','))	// May or may not be there!
				break;
			else
				csOutPath += csInPath[i];
		}
		m_bIsPathStyle = true;
		csOutPath = ExpandPath(csOutPath);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckPercentAndHyphenPath
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					  This is a special function as Windows allows files
					  to be executed even with the .exe extension to it
					// E.G: %SystemRoot%\system32\svchost -k DcomLaunch
					// E.G: %SystemRoot%\system32\svchost -k rpcss
					// E.G: MsiExec.exe /I{0D80391C-0A72-43BB-9BC2-143F63CC111D}
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckPercentAndHyphenPath(CString csInPath, CString &csOutPath)
{
	int iDotPos = csInPath.Find(_T("."));
	int iPercentPos = csInPath.Find(_T('%'));
	int iHyphenPos = csInPath.Find(_T('-'));
	csOutPath = _T("");
	if((iDotPos == -1) && (iPercentPos == 0) && (iHyphenPos > 0) && (iHyphenPos > iPercentPos))
	{
		//if the returned path is a folder then do not append .exe to it.	
		CString csTemp = ExpandPath(csInPath);
		if(!CheckIfFolder(csTemp))
		{
			m_bIsPathStyle = true;
			csInPath = csInPath.Left(iHyphenPos);
			csInPath.Trim();
			csInPath += _T(".exe");
		}
		csOutPath = ExpandPath(csInPath);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckBracketAndMissingDotPath
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					  This is a special function as Windows allows files
					  to be executed even with the .exe extension to it
					// E.G: MsiExec /I{0D80391C-0A72-43BB-9BC2-143F63CC111D}
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckBracketAndMissingDotPath(CString csInPath, CString &csOutPath)
{
	int iDotPos = csInPath.Find(_T("."));
	int iOpenBracketPos = csInPath.Find(_T('{'));
	int iCloseBracketPos = csInPath.Find(_T('}'));
	int iSlashPos = csInPath.Find(_T('/'));

	csOutPath = "";
	if((iDotPos == -1) && (iSlashPos != -1) && (iOpenBracketPos != -1) && (iCloseBracketPos != -1) && 
		(iSlashPos < iOpenBracketPos) && (iCloseBracketPos > iOpenBracketPos))
	{
		m_bIsPathStyle = true;
		csInPath = csInPath.Left(iSlashPos);
		csInPath.Trim();
		csInPath += _T(".exe");
		csOutPath = ExpandPath(csInPath);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckDoubleQuoteAndHyphenPath
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					  This is a special function as Windows allows files
					  to be executed even with the .exe extension to it
					// E.G: "E:\Program Files\internet explorer\iexplore" -32528
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckDoubleQuoteAndHyphenPath(CString csInPath, CString &csOutPath)
{
	int iDotPos = csInPath.Find(_T("."));
	int iQuotePos = csInPath.Find(_T('"'));
	int iHyphenPos = csInPath.Find(_T('-'));
	csOutPath = _T("");
	if((iDotPos == -1) && (iHyphenPos > 0) && (iQuotePos == 0))
	{
		csInPath = csInPath.Mid(1);
		if(csInPath.Find(_T('"')) == -1) // Must have 2 double quotes to be labled as a valid path
			return false;
		int nPathLen = csInPath.GetLength();
		for(int i = 0; i < nPathLen; i++)
		{
			if(csInPath[i] == _T('"'))
				break;
			else
				csOutPath += csInPath[i];
		}
		csOutPath.Trim();
		csOutPath += _T(".exe");
		m_bIsPathStyle = true;
		csOutPath = ExpandPath(csOutPath);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckCommaPath
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					// E.G: %SystemRoot%\System32\dmview.ocx,1
					// E.G: e:\windows\system32\netplwiz.dll,-107
					// E.G: e:\progra~1\micros~4\office11\powerpnt.exe,1
					// E.G: progman.exe,2
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckCommaPath(CString csInPath, CString &csOutPath)
{
	int iDotPos = csInPath.Find(_T("."));
	int iCommaPos = csInPath.Find(_T(','));
	csOutPath = _T("");
	if((iDotPos > 0) && (iCommaPos != -1) && iDotPos < iCommaPos) // dot must be before the comma
	{
		csOutPath = csInPath.Left(iCommaPos);
		csOutPath = ExpandPath(csOutPath);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckSquareBracketsPath
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					// E.G: E:\WINDOWS\system32\advapi32.dll[MofResourceName]
					// E.G: E:\WINDOWS\System32\Drivers\HTTP.sys[UlMofResource]
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckSquareBracketsPath(CString csInPath, CString &csOutPath)
{
	int iDotPos = csInPath.Find(_T("."));
	int iOpenBracketPos = csInPath.Find(_T('['));
	int iCloseBracketPos = csInPath.Find(_T(']'));
	csOutPath = "";
	
	if( (iDotPos > 0) && (iOpenBracketPos != -1) &&
		(iCloseBracketPos != -1) && (iDotPos < iOpenBracketPos) && // dot must be before the Open Bracket
		(iCloseBracketPos > iOpenBracketPos)) // close bracket must be after open
	{
		csOutPath = csInPath.Left(iOpenBracketPos);
		csOutPath = ExpandPath(csOutPath);
		m_bIsPathStyle = true;
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckForwardSlash
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					// E.G: explorer.exe /e,/idlist,%i,/l
					// E.G: e:\progra~1\micros~4\visio11\visio.exe /automation /invisible
					// E.G: E:\Program Files\Adobe\Acrobat 7.0\Reader\AcroRd32Info.exe /PDFShell
					// E.G: dmadmin.exe /com
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckForwardSlash(CString csInPath, CString &csOutPath)
{
	int iDotPos = csInPath.Find(_T("."));
	int iSlashPos = csInPath.Find(_T('/'));
	csOutPath = _T("");
	if((iDotPos > 0) && (iSlashPos != -1) && iDotPos < iSlashPos)
	{
		csOutPath = csInPath.Left(iSlashPos);
		csOutPath = ExpandPath(csOutPath);
		return true;
	}
    else if (iSlashPos != -1)
    {    	
        csOutPath = csInPath.Left(iSlashPos);
		csOutPath = ExpandPath(csOutPath);
        csOutPath.Trim();
        csOutPath += _T(".exe");
		return true;
    }
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckBackwardSlash
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					// E.G: E:\WINDOWS\PCHealth\HelpCtr\Binaries\HelpCtr.exe\1
					// E.G: oleacc.dll\2
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckBackwardSlash(CString csInPath, CString &csOutPath)
{
	int iDotPos = csInPath.Find(_T("."));
	int iSlashPos = csInPath.ReverseFind(_T('\\'));
	csOutPath = "";
	if(( iDotPos > 0) && ( iSlashPos != -1) && iDotPos < iSlashPos)
	{
		csOutPath = csInPath.Left(iSlashPos);
		csOutPath = ExpandPath(csOutPath);
		return true;
	}	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckBlankSpacePath
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					// E.G: E:\Program Files\Microsoft Visual Studio\Common\IDE\IDE98\devenv.exe -JITDebug
					// E.G: E:\PROGRA~1\COMMON~1\MICROS~1\VSA\7.1\VsaEnv\vsaenv.exe VSM
					// E.G: E:\PROGRA~1\COMMON~1\MICROS~1\DW\DWTRIG20.EXE -s
					// E.G: MSSOAP.DLL SoapReader class
					// E.G: %SystemRoot%\system32\test.exe %SystemRoot%\regedit.exe
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckBlankSpacePath(CString csInPath, CString &csOutPath)
{
	int iDotPos = csInPath.Find(_T("."));
	csOutPath = _T("");
	if(iDotPos > 0)
	{
		csOutPath = csInPath.Left(iDotPos);
		int nPathLen = csInPath.GetLength();
		for(int i = iDotPos; i < nPathLen; i++)
		{
			if(csInPath[i] == _T(' '))
				break;
			else
				csOutPath += csInPath[i];
		}
		csOutPath = ExpandPath(csOutPath);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckAPPDataPath
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					// E.G: %1a%\Microsoft\Speech\Files\UserLexicons\SP_78740C8D0DBE44F9A06F82EBBDD20489.dat
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckAPPDataPath(CString csInPath, CString &csOutPath)
{
	int iDotPos = csInPath.Find(_T("."));
	int iTagPos = csInPath.Find(_T("%1a%\\"));
	csOutPath = "";
	if((iDotPos > 0) && (iTagPos == 0))
	{
		csInPath.Replace(_T("%1a%"), m_AppData);
		csOutPath = ExpandPath(csInPath);
		m_bIsPathStyle = true;
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckSpecialTags
	In Parameters	: 
					CString csInPath,  File path to be parsed
					CString &csOutPath, File path after parsing
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					// E.G: res://E:\PROGRA~1\MICROS~4\OFFICE11\EXCEL.EXE/3000
					// E.G: file://%SystemRoot%\web\iejit.htm
					// E.G: E?\WINDOWS\Microsoft.NET\Framework\v1.1.4322\xjis.nlp
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckSpecialTags(CString csInPath, CString &csOutPath)
{
	int iDotPos  = csInPath.Find(_T("."));
	int iTagPos1 = csInPath.Find(_T("res://"));
	int iTagPos2 = csInPath.Find(_T("file://"));
	int iTagPos3 = csInPath.Find(_T("?\\"));
	int iTagPos4 = csInPath.Find(_T("\\??\\"));
	csOutPath = "";
	if((iDotPos > 0) && ((iTagPos1 == 0) || (iTagPos2 == 0) || (iTagPos3 == 1) || (iTagPos4 == 0)))
	{
		if(iTagPos1 == 0)
			csInPath.Replace(_T("res://"), _T(""));

		if(iTagPos2 == 0)
			csInPath.Replace(_T("file://"), _T(""));

		if(iTagPos3 == 1)
			csInPath.SetAt(1, _T(':'));

		if(iTagPos4 == 0)
			csInPath.Replace(_T("\\??\\"), _T(""));

		csOutPath = csInPath;
		m_bIsPathStyle = true;
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DoesFileOrFolderExist
	In Parameters	: CString csInPath, the file or folder to be searched for
	Out Parameters	: TRUE if the file or folder is valid else False
	Purpose			: Expands and formats the path with all possible ways to check for its existance
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckForExistance(CString csInPath)
{
	try
	{
		CString csOutPath;

		if(m_bStopScanning)
			return true;

		csInPath.Trim();
		csInPath.MakeLower();
		csInPath = _GetSingleFileName(csInPath);

		if( m_bCheckFontDirectory == true)
		{
		
			if(_CheckOnDrive(csInPath, true)) // First a blind check if the file exists!
				return true;
		}
		else
		{
			if(_CheckOnDrive(csInPath, false)) // First a blind check if the file exists!
				return true;
		}

		// Did Not matching any predetermined syntax, Expand path and give it a last chance
		csOutPath = ExpandPath(csInPath);
		if(csInPath != csOutPath)
		{
			if(_CheckOnDrive(csOutPath, false)) // Check after expanding the path
				return true;
		}

		// This is the only function where we replace the InPath before we proceed further
		// After removing the res:// we still need to parse the InPath with other funcitons
		if(_CheckSpecialTags(csInPath, csOutPath))
			csInPath = csOutPath; 
	
		if(_CheckDoubleQuotePath(csInPath, csOutPath))
		{
			if(_CheckOnDrive(csOutPath))
				return true;
		}
	
		if(_CheckAtTheRatePath(csInPath, csOutPath))
		{
			if(_CheckOnDrive(csOutPath))
				return true;
		}

		if(_CheckCommaPath(csInPath, csOutPath))
		{
			if(_CheckOnDrive(csOutPath))
				return true;
		}
		if(_CheckForwardSlash(csInPath, csOutPath))
		{
			if(_CheckOnDrive(csOutPath))
				return true;
		}
		if(_CheckBackwardSlash(csInPath, csOutPath))
		{
			if(_CheckOnDrive(csOutPath))
				return true;
		}
		if(_CheckBlankSpacePath(csInPath, csOutPath))
		{
			if(_CheckOnDrive(csOutPath))
				return true;
		}
		if(_CheckAPPDataPath(csInPath, csOutPath))
		{
			if(_CheckOnDrive(csOutPath))
				return true;
		}
		if(_CheckSquareBracketsPath(csInPath, csOutPath))
		{
			if(_CheckOnDrive(csOutPath))
				return true;
		}
		if(_CheckPercentAndHyphenPath(csInPath, csOutPath))
		{
			if(_CheckOnDrive(csOutPath))
				return true;
		}
		if(_CheckDoubleQuoteAndHyphenPath(csInPath, csOutPath))
		{
			if(_CheckOnDrive(csOutPath))
				return true;
		}
		if(_CheckBracketAndMissingDotPath(csInPath, csOutPath))
		{
			if(_CheckOnDrive(csOutPath))
				return true;
		}
		if( _CheckReverseDotSpacePath(csInPath, csOutPath))
		{
			if( _CheckOnDrive(csOutPath))
				return true;
		}
		return false;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegPathExpander::_CheckForExistance : " )+ csInPath);
		return true;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckIgnoreList
	In Parameters	: CString csInPath, the file to be searched for
	Out Parameters	: TRUE if the file pattern matches the ignore list else False
	Purpose			: This check will ignore entries which belong to drives which are
					  currently not attached to the system.
					  Checks if the file patter is in the ignore list 
					E.G: %n		(n= Any numeric value) 
					E.G: "%n"	(n= Any numeric value)
					E.G: ,1,HKCU,SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache,
					E.G: ,33,HKCU,AppEvents\Schemes\Apps\.Default\ShowBand,,
					E.G: E:\Program Files\Common Files\designer\MSDE.DLL\..\resources
					E.G: ..\src\sqlglobs.cpp
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckIgnoreList(CString csInPath)
{
	bool bReturnVal = false;

	csInPath.Replace(_T("\""), _T(""));
	csInPath.Trim();
	if(csInPath[0] == _T('%'))
	{
		bReturnVal = true;
		csInPath = csInPath.Mid(1);
		int nPathLen =  csInPath.GetLength();
		for(int iCnt = 0; iCnt < nPathLen; iCnt++)
		{
			if(csInPath[iCnt] != _T('0') && csInPath[iCnt] != _T('1') && csInPath[iCnt] != _T('2')
				&& csInPath[iCnt] != _T('3') && csInPath[iCnt] != _T('4') && csInPath[iCnt] != _T('5')
				&& csInPath[iCnt] != _T('6') && csInPath[iCnt] != _T('7') && csInPath[iCnt] != _T('8')
				&& csInPath[iCnt] != _T('9'))
			{
				bReturnVal = false;
				break;
			}
		}
	}
	if(csInPath.Find(_T("hkey_local_machine")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("hkey_current_user")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("hkey_users")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T(",hkcu,")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("hkcu\\")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("\\device\\")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("ide\\disk")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("ide\\cdrom")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("usbstor\\disk")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("..\\")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("file://")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("http://")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("\\\\?\\")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("\\*")) != -1)
		bReturnVal = true;
	if(csInPath.Find(_T("\\r\\n")) != -1)
		bReturnVal = true;
	if(csInPath[0] == _T('<'))
		bReturnVal = true;
	if(csInPath[0] == _T('>'))
		bReturnVal = true;
	if((csInPath[0] == _T('\\')) && (csInPath[1] == _T('\\')))
		bReturnVal = true;

	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
	Function		: DoesFileExist
	In Parameters	: CString csInPath, the file to be searched for
	Out Parameters	: TRUE if the file is valid else False
	Purpose			: Expands and formats the path with all possible ways to check for its existance
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::DoesFileExist(CString csInPath)
{
	m_bIsPathStyle = false;
	m_bIgnoreFolder = true;
	m_csFileFound = csInPath;

	LPTSTR szParsedFile = NULL;

	if(m_ParsedFileList.SearchItem(csInPath, szParsedFile))
	{
		m_csFileFound = szParsedFile;
		return true;
	}
	//sandip:added  for ignoring url string
	//if( ( csInPath.Find(_T(".ocx")) == -1 && csInPath.Find(_T(".exe")) == -1  
	//	&& csInPath.Find(_T(".tlb")) == -1 && csInPath.Find(_T(".dll")) == -1 && csInPath.Find(_T(".sys")) == -1) 
	//	&& (csInPath.Find(_T("www.")) != -1 || csInPath.Find(_T("http:")) != -1 || csInPath.Find(_T("https:")) != -1))
	if((csInPath.Find(_T("www.")) != -1 || csInPath.Find(_T("http:")) != -1 || csInPath.Find(_T("https:")) != -1))
	{
		m_ParsedFileList.AppendItem(csInPath, _T(""));		
		return true;
	}

	bool bFound = _TokenizeStringAndCheckPath(csInPath);

	m_ParsedFileList.AppendItem(csInPath, m_csFileFound);

	return bFound;
}

/*-------------------------------------------------------------------------------------
	Function		: DoesFileOrFolderExist
	In Parameters	: CString csInPath, the file or folder to be searched for
	Out Parameters	: TRUE if the file or folder is valid else False
	Purpose			: Expands and formats the path with all possible ways to check for its existance
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::DoesFileOrFolderExist(CString csInPath)
{
	m_bIsPathStyle = false;
	m_bIgnoreFolder = false;

	return _TokenizeStringAndCheckPath(csInPath);
}

/*-------------------------------------------------------------------------------------
	Function		: _TokenizeStringAndCheckPath
	In Parameters	: CString csInPath, the srting to be tokenize
	Out Parameters	: TRUE if the file is found else False
	Purpose			: Tokenize the string according to ';' and '.' and check for individual token
					E.G: E:\Program Files\Microsoft SDK\Lib\.;E:\Program Files\Microsoft Visual Studio .NET 2003\SDK\v1.1\Lib\
					E.G: TCP,E:\WINDOWS\system32\inetsrv\inetinfo.exe,216,LISTENING,0.0.0.0:80,0.0.0.0:0 
					E.G: n;1;E:\DOCUME~1\Darshan\LOCALS~1\Temp\IXP000.TMP\
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_TokenizeStringAndCheckPath(CString csInPath)
{
	csInPath.MakeLower();
	if(_CheckIgnoreList(csInPath))	// If this file pattern is found in our ignore list, guess what we'll ignore it :)
		return true;
	
	if(_CheckForExistance(csInPath)) // Check for the full string! Will work 99% of the time
		return true;

//#ifdef WIN64	//Checking the dll in system32 as well in syswow64 incase of 64 bit processor :Nupur
//	CString csNewPath = csInPath;
//	if( csNewPath.Replace(_T("system32"), _T("SysWOW64"))!= 0)
//	{
//		if(_CheckForExistance(csNewPath)) // Check for the full string! Will work 99% of the time
//			return true;
//	}
//	else if ( csNewPath.Replace(_T("SysWOW64"), _T("system32"))!= 0)
//	{
//		if(_CheckForExistance(csNewPath)) // Check for the full string! Will work 99% of the time
//			return true;
//	}
//#endif

	if(csInPath.Find(_T(';')) != -1)
	{
		if(_CheckForToken(csInPath, _T(";")))
			return true;
	}
	if(csInPath.Find(_T(',')) != -1)
	{
		if(_CheckForToken(csInPath, _T(",")))
			return true;
	}
	if(csInPath.Find(_T(':')) != -1)
	{
		if(_CheckForToken(csInPath, _T(":")))
			return true;
	}
	if(csInPath.Find(_T('^')) != -1)
	{
		if(_CheckForToken(csInPath, _T("^")))
			return true;
	}
	if(csInPath.Find(_T('|')) != -1)
	{
		if(_CheckForToken(csInPath, _T("|")))
			return true;
	}
	if(csInPath.Find(_T('=')) != -1)
	{
		if(_CheckForToken(csInPath, _T("=")))
			return true;
	}
	if(csInPath.Find(_T('"')) != -1)
	{
		if(_CheckForToken(csInPath, _T("\"")))
			return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckForToken
	In Parameters	: CString csInPath, const TCHAR *cToken
	Out Parameters	: bool
	Purpose			: Checks for the specified token in the path
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckForToken(CString csInPath, const TCHAR *cToken)
{
	bool bReturnVal = false;
	int iPos = 0;

	if(m_bStopScanning)
		return true;

	CString sToken = csInPath.Tokenize(cToken, iPos);
	while((sToken.GetLength() != 0) && (iPos != -1))
	{
		if(m_bStopScanning)
		{
			bReturnVal = true;
			break;
		}
		if((_wcsicmp(cToken, _T(":")) == 0) && (sToken.GetLength() == 1))
		{
			sToken += cToken;
			if(iPos != -1)
				sToken += csInPath.Tokenize(cToken, iPos);
		}
		if(_CheckForExistance(sToken)) // Check for the tokenized string one by one
		{
			bReturnVal = true;
			break;
		}
		if(iPos != -1)
			sToken = csInPath.Tokenize(cToken, iPos);
	}
	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckBlankSpacePath
	In Parameters	: 
					CString csInPath,  File path to be parsed
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					// E.G: E:\Program Files\Microsoft Visual Studio\Common\IDE\IDE98\devenv.exe -JITDebug
					// E.G: E:\PROGRA~1\COMMON~1\MICROS~1\VSA\7.1\VsaEnv\vsaenv.exe VSM
					// E.G: E:\PROGRA~1\COMMON~1\MICROS~1\DW\DWTRIG20.EXE -s
					// E.G: MSSOAP.DLL SoapReader class
					// E.G: %SystemRoot%\system32\test.exe %SystemRoot%\regedit.exe
	Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckBlankSpacePath(CString csInPath)
{
	bool bReturnVal = false;
	int iDotPos = csInPath.Find(_T("."));
	CString csOutPath = _T("");
	if(iDotPos > 0)
	{
		while(true)
		{
			iDotPos = csInPath.Find(_T("."));
			if(iDotPos == -1)
				break;
			csOutPath = csInPath.Left(iDotPos);
			int nPathLen = csInPath.GetLength();
			for(int i = iDotPos; i < nPathLen ; i++)
			{
				if(csInPath[i] == ' ')
					break;
				else
					csOutPath += csInPath[i];
			}
			if(_CheckForExistance(csOutPath)) // Check for the tokenized string one by one
			{
				bReturnVal = true;
				break;
			}
			csInPath = csInPath.Mid(csOutPath.GetLength());
			if(csInPath.GetLength() == 0)
				break;
		}
		return bReturnVal;
	}
	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
	Function		: _CheckReverseDotSpacePath
	In Parameters	: 
					CString csInPath,  File path to be parsed
	Out Parameters	: TRUE if successfully parsed Else False
	Purpose			: Parses the File path out of the given input
					// E.G: E:\Program Files\Microsoftl.Visual Studio\Common\IDE\IDE98\devenv.exe -JITDebug
	Author			: Nupur Aggarwal    23/Jan/2007
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::_CheckReverseDotSpacePath(CString csInPath, CString &csOutPath)
{
	int iDotPos = csInPath.ReverseFind(_T('.'));
	csOutPath = _T("");
	
	if(iDotPos > 0)
	{
		csOutPath = csInPath.Left(iDotPos);
		int nPathLen = csInPath.GetLength();
		for(int i = iDotPos; i < nPathLen; i++)
		{
			if(csInPath[i] == _T(' '))
				break;
			else
				csOutPath += csInPath[i];
		}
		csOutPath = ExpandPath(csOutPath);
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckIfFolder
	In Parameters	: CString filePath, file path to be checked
	Out Parameters	: bool - true if the input path is folder else false
	Purpose			: checks whether the given path is a folder or not
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
bool CRegPathExpander::CheckIfFolder(CString csPath)
{
   CFileFind finder;
   // build a string with wildcards
   CString strWildcard(csPath);
   strWildcard += _T("\\*.*");
	bool bReturn = false;
   // start working for files
   BOOL bWorking = finder.FindFile(strWildcard);
   while (bWorking)
   {
      bWorking = finder.FindNextFile();

      if (finder.IsDots())
         continue;

      if (finder.IsDirectory())
      {
			bReturn = true;
			break;
      }
   }

   finder.Close();
   return bReturn;
}


