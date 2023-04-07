/*=============================================================================
   FILE		           : FileOperation.cpp 
   ABSTRACT		       : 
   DOCUMENTS	       : Refer The System Design.doc, System Requirement Document.doc
   AUTHOR		       : 
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C)Aura:
      					Created as an unpublished copyright work.  All rights reserved.
     					This document and the information it contains is confidential and
      					proprietary to Aura.  Hence, it may not be 
      					used, copied, reproduced, transmitted, or stored in any form or by any 
      					means, electronic, recording, photocopying, mechanical or otherwise, 
      					without the prior written permission of Aura
   CREATION DATE      : 26-Jan-2006
   NOTES		      : This Class perform file / folder related opration
						like DeleteFolderTree,DeleteCache,GetSignature,QurantineBackup
   VERSION HISTORY    : 
=============================================================================*/
#include "pch.h"
#include <wininet.h>
#include "FileOperation.h"
#include "EnumProcess.h"
#include "Registry.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CFileOperation
In Parameters	: -
Out Parameters	: -
Purpose			: Constructor -Load File Signature
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CFileOperation::CFileOperation()
{
}

/*-------------------------------------------------------------------------------------
Function		: ~CFileOperation
In Parameters	: -
Out Parameters	: -
Purpose			: Destructor - Free Filesignature.dll
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CFileOperation::~CFileOperation()
{
}

/*-------------------------------------------------------------------------------------
Function		: DeleteFolderTree
In Parameters	: CString : Folder Path
Out Parameters	: bool : true(Successful)/false
Purpose			: To Remove The Files & Folders Recurssively
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CFileOperation::DeleteFolderTree(CString csFilePath, bool bSubDir, bool bDelPath,
									  DWORD &dwLastError, CString csIgnoreFolder,
									  CString csIgnoreFolder1, CString csIgnoreFile,
									  bool bAddRestartDelete)
{
	CFileFind findfile;
	CString csOldFilePath, csDirPath, csOrgFolderPath = csFilePath;
	bool bCompulsoryRestartDelete = false;		//add all log files to restart delete as they can be created after deletion also

	if(csFilePath.Find(L":") == -1)
	{
		return false;
	}
	if(bAddRestartDelete)
	{
		csOrgFolderPath.MakeLower();
		bCompulsoryRestartDelete = -1 != csOrgFolderPath.Find(_T("\\log\\*.*"));
	}

	//To Check Whether The File Is Exist Or Not
	BOOL bCheck = findfile.FindFile(csFilePath);
	if(!bCheck)
	{
		dwLastError = ERROR_FILE_NOT_FOUND;
		return false;
	}

	while(bCheck)
	{
		//To Find Next File In Same Directory
		bCheck = findfile.FindNextFile();
		if(findfile.IsDots())
		{
			continue;
		}

		//To get file path
		csFilePath = findfile.GetFilePath();
		csOldFilePath = csFilePath;

		//In Founded Is Directory
		if(findfile.IsDirectory() && bSubDir)
		{
			if(csIgnoreFolder.CompareNoCase(findfile.GetFileName()) != 0 
				&& csIgnoreFolder1.CompareNoCase(findfile.GetFileName()))
			{
				csDirPath = csFilePath;
				csFilePath = csFilePath + _T("\\*.*");

				//To Remove The Files & Folders Recurssively In that directory
				DWORD dwError=0;
				DeleteFolderTree(csFilePath, true, true, dwError, csIgnoreFolder,
									csIgnoreFolder1, _T(""), bAddRestartDelete);
				SetFileAttributes(csDirPath, 0);
				//To delete an existing empty directory.
				if(bDelPath)
				{
					DWORD dwAttrs = GetFileAttributes(csDirPath);
					if(dwAttrs != INVALID_FILE_ATTRIBUTES &&  dwAttrs & FILE_ATTRIBUTE_READONLY)
					{
						SetFileAttributes(csDirPath,dwAttrs ^ FILE_ATTRIBUTE_READONLY);
					}

					if((FALSE == RemoveDirectory(csDirPath)) || bCompulsoryRestartDelete)
					{
						if(bAddRestartDelete)
						{
							MoveFileEx(csDirPath, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
						}
					}
				}
			}
		}
		else
		{
			//To set the file attribute to archive
			SetFileAttributes(csFilePath, 0);
			if(csFilePath.Right(4).CompareNoCase(_T(".exe"))== 0 
				&& csIgnoreFile.CompareNoCase(findfile.GetFileName()) != 0)
			{
				CEnumProcess objEnumProc;
				objEnumProc.IsProcessRunning(csFilePath, true);
			}

			DWORD dwAttrs = GetFileAttributes(csFilePath);
			if(dwAttrs != INVALID_FILE_ATTRIBUTES &&  dwAttrs & FILE_ATTRIBUTE_READONLY)
			{
				SetFileAttributes(csFilePath,dwAttrs ^ FILE_ATTRIBUTE_READONLY);
			}

			if(FALSE == ::DeleteFile(csFilePath) || bCompulsoryRestartDelete)
			{
				if(bAddRestartDelete)
				{
					MoveFileEx(csFilePath, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
				}
			}
		}
	}

	//to close handle
	findfile.Close();

	if(bDelPath && bSubDir && bAddRestartDelete)
	{
		CString csTemp = csOrgFolderPath;
		csTemp.Replace(_T("\\*.*"), _T(""));

		DWORD dwAttrs = GetFileAttributes(csTemp);
		if(dwAttrs != INVALID_FILE_ATTRIBUTES &&  dwAttrs & FILE_ATTRIBUTE_READONLY)
		{
			SetFileAttributes(csTemp, dwAttrs ^ FILE_ATTRIBUTE_READONLY);
		}

		if((FALSE == RemoveDirectory(csTemp)) || bCompulsoryRestartDelete)
		{
			MoveFileEx(csTemp, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
		}
	}

	return true;
}

/*-------------------------------------------------------------------------------------
Function		: DeleteFolderTree
In Parameters	: CString : Folder Path
Out Parameters	: bool : true(Successful)/false
Purpose			: To Remove The Files & Folders Recurssively
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CFileOperation::DeleteFolderTree(CString csFilePath, bool bSubDir,
									  CString csIgnoreFolder, CString csIgnoreLogFolder)
{
	CFileFind findfile;
	CString csOldFilePath, csDirPath;

	//To Check Whether The File Is Exist Or Not
	BOOL bCheck = findfile.FindFile(csFilePath);
	if(!bCheck)
	{
		return false;
	}

	while(bCheck)
	{
		//To Find Next File In Same Directory
		bCheck = findfile.FindNextFile();
		if(findfile.IsDots())
		{
			continue;
		}

		//To get file path
		csFilePath = findfile.GetFilePath();
		csOldFilePath = csFilePath;

		//In Founded Is Directory
		if(findfile.IsDirectory() && bSubDir)
		{
			if(csIgnoreLogFolder.CompareNoCase(findfile.GetFileName()) != 0
				&& csIgnoreFolder.CompareNoCase(findfile.GetFileName()) != 0)
			{
				csDirPath = csFilePath;
				csFilePath = csFilePath + _T("\\*.*");

				//To Remove The Files & Folders Recurssively In that directory
				DeleteFolderTree(csFilePath,true,csIgnoreFolder,csIgnoreLogFolder);
				SetFileAttributes(csDirPath, 0);
				//To delete an existing empty directory.
				if(true)
				{
					if(RemoveDirectory(csDirPath)== FALSE)
					{
						continue;
					}
				}
			}
		}
		else
		{
			CString csIgnoreFile = findfile.GetFileName();
			if(csIgnoreFile.CompareNoCase(_T("Exclude.db")) != 0 
				&& csIgnoreFile.CompareNoCase(_T("SDRemoveDB.db")) != 0
				&& csIgnoreFile.CompareNoCase(_T("unins000.exe")) != 0 
				&& csIgnoreFile.CompareNoCase(_T("unins000.dat")) != 0
				&& csIgnoreFile.CompareNoCase(_T("MigrateSD.exe")) != 0
				&& csIgnoreFile.CompareNoCase(_T("sd13.db")) != 0)
			{
				//To set the file attribute to archive
				SetFileAttributes(csFilePath, 0);
				if(csFilePath.Right(4).CompareNoCase(_T(".exe"))== 0)
				{
					CEnumProcess objEnumProc;
					objEnumProc.IsProcessRunning(csFilePath, true);
				}
				::DeleteFile(csFilePath);
			}
		}
	}

	//to close handle
	findfile.Close();
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: DeleteThisFile
In Parameters	: CString csFilePath
Out Parameters	: bool : true(Successful)/false
Purpose			: To delete input file
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CFileOperation::DeleteThisFile(CString csFilePath)
{
	DWORD dwAttrs = GetFileAttributes(csFilePath);
	if(dwAttrs != INVALID_FILE_ATTRIBUTES &&  dwAttrs & FILE_ATTRIBUTE_READONLY)
	{
		SetFileAttributes(csFilePath, dwAttrs ^ FILE_ATTRIBUTE_READONLY);
	}

	return (DeleteFile(csFilePath)?true:false);
}

/*-------------------------------------------------------------------------------------
Function		: match
In Parameters	:  TCHAR const * w, TCHAR const * s
Out Parameters	: bool : true(Successful)/false
Purpose			: To compare two strings
Author			: Anand
--------------------------------------------------------------------------------------*/
bool CFileOperation::match(TCHAR const * w, TCHAR const * s)
{
	switch(*w)
	{
	case '\0':
		{
			return !*s;
		}
	case '*':
		{
			return match(w + 1, s) ||(*s && match(w, s + 1));
		}
	case '?':
		{
			return *s && match(w + 1, s + 1);
		}
	default :
		{
			return (*w == *s) && match(w + 1, s + 1);
		}
	}
}

/*-------------------------------------------------------------------------------------
Function		: MatchFilename
In Parameters	:  TCHAR const * FileName, TCHAR const * DBFileName
Out Parameters	: bool : true(Successful)/false
Purpose			: To compare two files
Author			: Anand
--------------------------------------------------------------------------------------*/
bool CFileOperation::MatchFilename(TCHAR const * FileName, TCHAR const * DBFileName)
{
	const TCHAR * p = NULL;
	TCHAR Buf1[1024]={0};
	TCHAR Buf2[1024]={0};

	p = wcsrchr(FileName, _T('\\'));
	if(p &&((p - FileName)< sizeof(Buf1)))
	{
		wcsncpy_s(Buf1,_countof(Buf1), FileName, p - FileName);
	}

	p = wcsrchr(DBFileName, _T('\\'));
	if(p &&((p - DBFileName)< sizeof(Buf2)))
	{
		wcsncpy_s(Buf2,_countof(Buf2), DBFileName, p - DBFileName);
	}

	_wcsupr_s(Buf1,_countof(Buf1));
	_wcsupr_s(Buf2,_countof(Buf2));
	if(!match(Buf1, Buf2))
	{
		return (false);
	}

	wmemset(Buf1, 0, _countof(Buf1));
	wmemset(Buf2, 0, _countof(Buf2));

	p = wcsrchr(FileName, _T('\\'));
	if(p)
	{
		p++;
		if(p && *p)
		{
			wcsncpy_s(Buf1,_countof(Buf1), p, wcslen(p));
		}
	}

	p = wcsrchr(DBFileName, '\\');
	if(p)
	{
		p++;
		if(p && *p)
		{
			wcsncpy_s(Buf2,_countof(Buf2), p, wcslen(p));
		}
	}

	_wcsupr_s(Buf1,_countof(Buf1));
	_wcsupr_s(Buf2,_countof(Buf2));

	if(!match(Buf2, Buf1))
	{
		return (false);
	}

	return (true);
}

/*-------------------------------------------------------------------------------------
Function		: ReplaceFileOnRestart
In Parameters	: TCHAR const * szExistingFileName, TCHAR const * szNewFileName
Out Parameters	: bool : true(Successful)/false
Purpose			:   This function makes an entry in the registry for a file to be
deleted or replaced by an existing file at the machine restart.
This is used to handle files which cant be then deleted because they are in use.
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CFileOperation::ReplaceFileOnRestart(TCHAR const * szExistingFileName, 
										  TCHAR const * szNewFileName)
{
	CRegistry objReg;
	CStringArray arrData;
	CString Key = _T("SYSTEM\\CurrentControlSet\\Control\\Session Manager");
	CString Value = _T("PendingFileRenameOperations2");

	objReg.Get(Key, Value, arrData, HKEY_LOCAL_MACHINE);

	arrData.Add(CString(_T("\\??\\")) + szExistingFileName);
	if(szNewFileName)
	{
		arrData.Add(CString(_T("!\\??\\")) + szNewFileName);
	}

	objReg.Set(Key, Value, arrData, HKEY_LOCAL_MACHINE);
	return true;
}