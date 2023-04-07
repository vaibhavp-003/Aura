#include "pch.h"
#include "DirectoryManager.h"
#include "MaxExceptionFilter.h"

CDirectoryManager::CDirectoryManager(void)
{
	CMaxExceptionFilter::InitializeExceptionFilter();
}

CDirectoryManager::~CDirectoryManager(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : AppendString
In Parameters  : LPTSTR szFinal, DWORD cchFinal, LPCTSTR szAppend
Out Parameters : bool
Description    : concatenate strings but return false if dest smaller
Author & Date  : Anand Srivastava & 22 July, 2011.
--------------------------------------------------------------------------------------*/
bool CDirectoryManager::AppendString(LPTSTR szFinal, DWORD cchFinal, LPCTSTR szAppend)
{
	if(_tcslen(szFinal) + _tcslen(szAppend) >= cchFinal)
	{
		return false;
	}

	_tcscat_s(szFinal, cchFinal, szAppend);
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : FormatStrings
In Parameters  : LPTSTR szFinal, DWORD cchFinal, LPCTSTR szFormat, ...
Out Parameters : bool
Description    : join strings but return false if dest smaller
Author & Date  : Anand Srivastava & 22 July, 2011.
--------------------------------------------------------------------------------------*/
bool CDirectoryManager::FormatStrings(LPTSTR szFinal, DWORD cchFinal, LPCTSTR szFormat, ...)
{
	va_list Arguments_List;
	DWORD dwReqLen = 0;
	//memset(szFinal, 0, cchFinal * sizeof(TCHAR));
	va_start(Arguments_List, szFormat);
	dwReqLen = _vsctprintf(szFormat, Arguments_List);
	if(dwReqLen >= cchFinal)
	{
		return false;
	}

	memset(szFinal, 0, cchFinal * sizeof(TCHAR));
	_vstprintf_s(szFinal, cchFinal, szFormat, Arguments_List);
	va_end(Arguments_List);
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: JoinStrings
In Parameters	: LPTSTR szDest, SIZE_T cchDest, LPCTSTR szFirst, ...
Out Parameters	: bool
Purpose			: join strings
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CDirectoryManager::JoinStrings(LPTSTR szDest, SIZE_T cchDest, LPCTSTR szFirst, ...)
{
	LPCTSTR str = szFirst;
	va_list marker ;
	bool bSuccess = true;

	memset(szDest, 0, cchDest * sizeof(TCHAR));

	va_start(marker, szFirst);
	while(str)
	{
		if(*szDest)
		{
			if (_tcslen(str) + _tcslen(szDest) >= cchDest)
			{
				bSuccess = false;
				break;
			}

			_tcscat_s(szDest, cchDest, str); 
		}
		else
		{
			if(_tcslen(str) >= cchDest)
			{
				bSuccess = false;
				break;
			}

			_tcscpy_s(szDest, cchDest, str);
		}

		str = va_arg(marker, LPCTSTR);
	}

	va_end(marker);

	if(!bSuccess)
	{
		AddLogEntry(_T("Error joining strings: %s"), szFirst);
	}

	return bSuccess;
}

/*-------------------------------------------------------------------------------------
Function		: MaxCopyDirectory
In Parameters	: LPCTSTR szDstPath, LPCTSTR szSrcPath, bool bRecursive
Out Parameters	: bool
Purpose			: copy all files from source to destination
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CDirectoryManager::MaxCopyDirectory(LPCTSTR szDstPath, LPCTSTR szSrcPath, bool bRecursive, bool bOverWrite,
										CStringArray* pcsarrIgnoreList, CStringArray* pcsarrAllowedList,
										bool bContinueIfFail)
{
	bool bSuccess = true;
	HANDLE hSearch = 0;
	WIN32_FIND_DATA Data = {0};
	TCHAR szTempPath[MAX_PATH] = {0};
	TCHAR szNewFile[MAX_PATH] = {0};
	TCHAR szExistingFile[MAX_PATH] = {0};

	if(!JoinStrings(szTempPath, _countof(szTempPath), szSrcPath, _T("\\*"), NULL))
	{
		AddLogEntry(_T("CopyDirectory() failed, Src: %s, Dst: %s"), szSrcPath, szDstPath);
		return true;
		//return false;
	}

	hSearch = FindFirstFile(szTempPath, &Data);
	if(INVALID_HANDLE_VALUE == hSearch)
	{
		AddLogEntry(_T("CopyDirectory() failed, Src: %s, Dst: %s"), szTempPath, szDstPath);
		return false;
	}

	if(_taccess_s(szDstPath,0) && !MaxCreateDirectory(szDstPath))
	{
		AddLogEntry(_T("CopyDirectory() failed, dst not found, Src: %s, Dst: %s"), szTempPath, szDstPath);
		FindClose(hSearch);
		return false;
	}

	do
	{
		if((Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x00) || 
		   (Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x2E && Data.cFileName[2] == 0x00))
		{
			continue;
		}

		if(!JoinStrings(szNewFile, _countof(szNewFile), szDstPath, _T("\\"), Data.cFileName, NULL))
		{
			//bSuccess = false;
			//break;
			AddLogEntry(_T("CopyDirectory() failed copying file, large dst path, Src: %s, Dst: %s"), Data.cFileName, szDstPath);
			continue;
		}

		if(!JoinStrings(szExistingFile, _countof(szExistingFile), szSrcPath, _T("\\"), Data.cFileName, NULL))
		{
			//bSuccess = false;
			//break;
			AddLogEntry(_T("CopyDirectory() failed copying file, large src path, Src: %s, Dst: %s"), Data.cFileName, szDstPath);
			continue;
		}

		if((Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
		{
			if(bRecursive)
			{
				if(!MaxCopyDirectory(szNewFile, szExistingFile, bRecursive, bOverWrite, pcsarrIgnoreList, pcsarrAllowedList, bContinueIfFail))
				{
					bSuccess = false;
					break;
				}
			}
		}
		else
		{
			if(IsFilePresentInList(Data.cFileName, pcsarrAllowedList) || !IsFilePresentInList(Data.cFileName, pcsarrIgnoreList))
			{
				if(!CopyFile(szExistingFile, szNewFile, !bOverWrite))
				{
					bSuccess = false;
					if(!bContinueIfFail)
					{
						AddLogEntry(_T("CopyDirectory() failure copying file, break, Src: %s, Dst: %s"), szExistingFile, szNewFile);
						break;
					}
				}
				//else
				//{
				//	AddLogEntry(_T("CopyDirectory() success copying file, Src: %s, Dst: %s"), szExistingFile, szNewFile);
				//}
			}
			else
			{
				;//AddLogEntry(_T("CopyDirectory() skipped copying file, but continue copying, Src: %s, Dst: %s"), szExistingFile, szNewFile);
			}
		}
	}while(FindNextFile(hSearch, &Data));

	FindClose(hSearch);
	return bSuccess;
}

bool CDirectoryManager::MaxMoveDirectory(LPCTSTR szDstPath, LPCTSTR szSrcPath, bool bRecursive, bool bOverWrite, bool bIgnoreOnOverWriteFail)
{
	bool bSuccess = true;
	HANDLE hSearch = 0;
	WIN32_FIND_DATA Data = {0};
	TCHAR szTempPath[MAX_PATH] = {0};
	TCHAR szNewFile[MAX_PATH] = {0};
	TCHAR szExistingFile[MAX_PATH] = {0};

	if(!JoinStrings(szTempPath, _countof(szTempPath), szSrcPath, _T("\\*"), NULL))
	{
		return true;
		//return false;
	}

	hSearch = FindFirstFile(szTempPath, &Data);
	if(INVALID_HANDLE_VALUE == hSearch)
	{
		return false;
	}

	if(_taccess_s(szDstPath,0) && !MaxCreateDirectory(szDstPath))
	{
		FindClose(hSearch);
		return false;
	}

	do
	{
		if((Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x00) || 
		   (Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x2E && Data.cFileName[2] == 0x00))
		{
			continue;
		}

		if(!JoinStrings(szNewFile, _countof(szNewFile), szDstPath, _T("\\"), Data.cFileName, NULL))
		{
			//bSuccess = false;
			//break;
			continue;
		}

		if(!JoinStrings(szExistingFile, _countof(szExistingFile), szSrcPath, _T("\\"), Data.cFileName, NULL))
		{
			//bSuccess = false;
			//break;
			continue;
		}

		if((Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
		{
			if(bRecursive)
			{
				if(!MaxMoveDirectory(szNewFile, szExistingFile, bRecursive, bOverWrite,bIgnoreOnOverWriteFail))
				{
					bSuccess = false;
					break;
				}
			}
		}
		else
		{
			if(!MoveFile(szExistingFile, szNewFile))
			{
				if (_taccess_s(szNewFile,0) == 0x00 && bIgnoreOnOverWriteFail)
				{
					//This is to handle overwrite fail problem of move file api. (Pen drive 0xA0 folder problem)
				}
				else
				{
					bSuccess = false;
					break;
				}
			}
		}
	}while(FindNextFile(hSearch, &Data));

	FindClose(hSearch);
	return bSuccess;
}

/*-------------------------------------------------------------------------------------
Function		: DeleteDirectory
In Parameters	: LPCTSTR szPath, bool bRecursive
Out Parameters	: bool
Purpose			: delete the folder, sub folder and files
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CDirectoryManager::MaxDeleteDirectory(LPCTSTR szPath, bool bRecursive)
{
	bool bSuccess = true;
	HANDLE hSearch = 0;
	WIN32_FIND_DATA Data = {0};
	TCHAR szTempPath[MAX_PATH] = {0};

	if(_tcschr(szPath, ':') == NULL)
	{
		return false;
	}

	if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, _T("\\*"), NULL))
	{
		return false;
	}

	hSearch = FindFirstFile(szTempPath, &Data);
	if(INVALID_HANDLE_VALUE == hSearch)
	{
		SetFileAttributes(szPath, 0);
		RemoveDirectory(szPath);
		return !!_taccess_s(szPath, 0);
	}

	do
	{
		if((Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x00) || 
		   (Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x2E && Data.cFileName[2] == 0x00))
		{
			continue;
		}

		if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, _T("\\"), Data.cFileName, NULL))
		{
			bSuccess = false;
			break;
		}

		if((Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
		{
			if(bRecursive)
			{
				if(!MaxDeleteDirectory(szTempPath, bRecursive))
				{
					bSuccess = false;
					break;
				}
			}
		}
		else
		{
			SetFileAttributes(szTempPath, 0);
			if(!DeleteFile(szTempPath))
			{
				bSuccess = false;
				break;
			}
		}
	}while(FindNextFile(hSearch, &Data));

	FindClose(hSearch);
	SetFileAttributes(szPath, 0);
	RemoveDirectory(szPath);
	return bSuccess;
}


bool CDirectoryManager::MaxDeleteDirectoryContents(LPCTSTR szPath, bool bRecursive)
{
	bool bSuccess = true;
	HANDLE hSearch = 0;
	WIN32_FIND_DATA Data = {0};
	TCHAR szTempPath[MAX_PATH] = {0};

	if(_tcschr(szPath, ':') == NULL)
	{
		return false;
	}

	if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, _T("\\*"), NULL))
	{
		return false;
	}

	hSearch = FindFirstFile(szTempPath, &Data);
	if(INVALID_HANDLE_VALUE == hSearch)
	{
		//SetFileAttributes(szPath, 0);
		//RemoveDirectory(szPath);
		return !!_taccess_s(szPath, 0);
	}

	do
	{
		if((Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x00) || 
		   (Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x2E && Data.cFileName[2] == 0x00))
		{
			continue;
		}

		if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, _T("\\"), Data.cFileName, NULL))
		{
			bSuccess = false;
			break;
		}

		if((Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
		{
			if(bRecursive)
			{
				if(!MaxDeleteDirectory(szTempPath, bRecursive))
				{
					SetFileAttributes(szPath, 0);
					RemoveDirectory(szPath);
					bSuccess = false;
					break;
				}
				SetFileAttributes(szPath, 0);
				RemoveDirectory(szPath);
			}
		}
		else
		{
			SetFileAttributes(szTempPath, 0);
			if(!DeleteFile(szTempPath))
			{
				bSuccess = false;
				break;
			}
		}
	}while(FindNextFile(hSearch, &Data));

	FindClose(hSearch);
	return bSuccess;
}

/*-------------------------------------------------------------------------------------
Function		: DeleteDirectory
In Parameters	: LPCTSTR szPath, LPCTSTR szIgnorePath, bool bRecursive
Out Parameters	: bool
Purpose			: delete the folder, sub folder and files
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CDirectoryManager::MaxDeleteDirectory(LPCTSTR szPath, LPCTSTR szIgnorePath, bool bRecursive)
{
	bool bSuccess = true;
	HANDLE hSearch = 0;
	WIN32_FIND_DATA Data = {0};
	TCHAR szTempPath[MAX_PATH] = {0};

	if(_tcschr(szPath, ':') == NULL)
	{
		return false;
	}

	if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, _T("\\*"), NULL))
	{
		return false;
	}

	hSearch = FindFirstFile(szTempPath, &Data);
	if(INVALID_HANDLE_VALUE == hSearch)
	{
		return !!_taccess_s(szPath, 0);
	}

	do
	{
		if((Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x00) || 
		   (Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x2E && Data.cFileName[2] == 0x00))
		{
			continue;
		}

		if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, _T("\\"), Data.cFileName, NULL))
		{
			bSuccess = false;
			break;
		}

		if((Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
		{
			if(bRecursive)
			{
				if(!szIgnorePath || _tcsicmp(Data.cFileName, szIgnorePath) != 0)
				{
					if(!MaxDeleteDirectory(szTempPath, szIgnorePath, bRecursive))
					{
						bSuccess = false;
						break;
					}
				}
			}
		}
		else
		{
			
			SetFileAttributes(szTempPath, 0);
			if(!DeleteFile(szTempPath))
			{
				bSuccess = false;
				break;
			}
		}
	}while(FindNextFile(hSearch, &Data));

	FindClose(hSearch);
	
	SetFileAttributes(szPath, 0);
	RemoveDirectory(szPath);
	return bSuccess;
}

/*-------------------------------------------------------------------------------------
Function		: DeleteDirectory
In Parameters	: LPCTSTR szPath, LPCTSTR szIgnorePath, bool bRecursive
Out Parameters	: bool
Purpose			: delete the folder, sub folder and files
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CDirectoryManager::MaxDeleteDirectory(LPCTSTR szPath, LPCTSTR szIgnorePath, bool bRecursive, bool bAddRestartDelete)
{
	bool bSuccess = true;

	__try
	{
		HANDLE hSearch = 0;
		WIN32_FIND_DATA Data = {0};
		TCHAR szTempPath[MAX_PATH] = {0};

		if(_tcschr(szPath, ':') == NULL)
		{
			return false;
		}

		if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, _T("\\*"), NULL))
		{
			return false;
		}

		hSearch = FindFirstFile(szTempPath, &Data);
		if(INVALID_HANDLE_VALUE == hSearch)
		{
			return !!_taccess_s(szPath, 0);
		}

		do
		{
			if((Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x00) || 
				(Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x2E && Data.cFileName[2] == 0x00))
			{
				continue;
			}

			if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, _T("\\"), Data.cFileName, NULL))
			{
				continue;
			}

			if((Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
			{
				if(bRecursive)
				{
					if(!szIgnorePath || _tcsicmp(Data.cFileName, szIgnorePath) != 0)
					{
						MaxDeleteDirectory(szTempPath, szIgnorePath, bRecursive, bAddRestartDelete);
					}
				}
			}
			else
			{
				SetFileAttributes(szTempPath, 0);
				if(_tcsicmp(Data.cFileName, L"index.dat") != 0)
				{
					if(FALSE == ::DeleteFile(szTempPath))
					{
						if(bAddRestartDelete)
						{
							MoveFileEx(szTempPath, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
						}
						else
						{
							AddLogEntry(_T("Del fail: %s"), szTempPath);
						}
					}
				}
			}
		}while(FindNextFile(hSearch, &Data));

		FindClose(hSearch);
		
		SetFileAttributes(szPath, 0);
		RemoveDirectory(szPath);
		if(FALSE == RemoveDirectory(szPath))
		{
			if(bAddRestartDelete)
			{
				MoveFileEx(szPath, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
			}
		}
	}

	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("DeleteDirectory"),false))
	{
	}

	return bSuccess;
}

/*-------------------------------------------------------------------------------------
Function		: MaxDeleteDirectory
In Parameters	: LPCTSTR szPath, bool bRecursive, bool bAddRestartDelete
Out Parameters	: bool
Purpose			: delete files of a specific extension in the folder
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CDirectoryManager::MaxDeleteDirectory(LPCTSTR szPath, bool bRecursive, bool bAddRestartDelete)
{
	__try
	{
		HANDLE hSearch = 0;
		WIN32_FIND_DATA Data = {0};
		TCHAR szTempPath[MAX_PATH] = {0};

		if(_tcschr(szPath, ':') == NULL)
		{
			return false;
		}

		if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, NULL))
		{
			return false;
		}

		hSearch = FindFirstFile(szTempPath, &Data);
		if(INVALID_HANDLE_VALUE == hSearch)
		{
			return true;
		}

		do
		{
			if((Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x00) || 
				(Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x2E && Data.cFileName[2] == 0x00))
			{
				continue;
			}

			if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, _T("\\"), Data.cFileName, NULL))
			{
				continue;
			}

			if((Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
			{
				if(bRecursive)
				{
					MaxDeleteDirectory(szTempPath, bRecursive, bAddRestartDelete);
				}
			}
			else
			{
				SetFileAttributes(szTempPath, 0);
				if(FALSE == ::DeleteFile(szTempPath))
				{
					AddLogEntry(_T("Del fail: %s"), szTempPath);
					if(bAddRestartDelete)
					{
						AddLogEntry(_T("add restart del list: %s"), szTempPath);
						MoveFileEx(szTempPath, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
					}
					else
					{
						AddLogEntry(_T("no action taken: %s"), szTempPath);
					}
				}
			}
		}while(FindNextFile(hSearch, &Data));

		FindClose(hSearch);
		return true;
	}

	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("DeleteDirectory-s-b-b"),false))
	{
	}

	return false;
}

/*-------------------------------------------------------------------------------------
Function		: MaxCreateDirectory
In Parameters	: LPCTSTR szPath
Out Parameters	: bool
Purpose			: creates folder and parent folder if not present
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CDirectoryManager::MaxCreateDirectory(LPCTSTR szPath)
{
	LPTSTR pSlash = NULL;
	TCHAR chBackSlash = _T('\\');
	TCHAR szPathToCreate[MAX_PATH] = {0};

	if(!JoinStrings(szPathToCreate, _countof(szPathToCreate), szPath, NULL))
	{
		return false;
	}

	pSlash = szPathToCreate;
	do
	{
		pSlash = _tcschr(pSlash, chBackSlash);
		if(pSlash)
		{
			*pSlash = 0;
		}

		if(_taccess_s(szPathToCreate, 0))
		{
			::CreateDirectory(szPathToCreate, 0);
		}

		if(pSlash)
		{
			*pSlash = chBackSlash;
			pSlash++;
		}
	}while(pSlash);

	return true;
}

bool CDirectoryManager::MaxCreateDirectoryForFile(LPCTSTR szFilePath)
{
	LPTSTR pSlash = NULL;
	TCHAR chBackSlash = _T('\\');
	TCHAR szPathToCreate[MAX_PATH] = {0};

	if(!JoinStrings(szPathToCreate, _countof(szPathToCreate), szFilePath, NULL))
	{
		return false;
	}

	pSlash = szPathToCreate;
	do
	{
		pSlash = _tcschr(pSlash, chBackSlash);
		if(pSlash)
		{
			*pSlash = 0;
		}
		else
		{
			break;
		}

		if(_taccess_s(szPathToCreate, 0))
		{
			::CreateDirectory(szPathToCreate, 0);
		}

		if(pSlash)
		{
			*pSlash = chBackSlash;
			pSlash++;
		}
	}while(pSlash);

	return true;
}

bool CDirectoryManager::IsFilePresentInList(CString csFileName, CStringArray* pcsarrList)
{
	bool bRetVal = false;
	if(!pcsarrList)
		return bRetVal;

	int iSkipTotalCount = (int)pcsarrList->GetCount();
	for(int iCount=0 ; iCount<iSkipTotalCount ; iCount++)
	{
		CString csFile = pcsarrList->GetAt(iCount);
		if(!csFile.Left(2).CompareNoCase(L"*."))
		{
			CString csExtn = csFile.Mid(2);
			int iLen = csExtn.GetLength();
			if(!csFileName.Right(iLen).CompareNoCase(csExtn))
			{
				bRetVal = true;
				break;
			}
		}
		if(!csFile.CompareNoCase(csFileName))
		{
			bRetVal = true;
			break;
		}
	}

	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: MaxDeleteTempData
In Parameters	: LPCTSTR szPath
Out Parameters	: void
Purpose			: will delete all files and folders except pop3 and smpt from TempData
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CDirectoryManager::MaxDeleteTempData(LPCTSTR szPath)
{
	HANDLE hSearch = 0;
	WIN32_FIND_DATA Data = {0};
	TCHAR szTempPath[MAX_PATH] = {0};

	if(_tcschr(szPath, _T(':')) == NULL)
	{
		return;
	}

	if(_tcschr(szPath, _T('\\')) == NULL)
	{
		return;
	}

	if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, _T("\\*"), NULL))
	{
		return;
	}

	hSearch = FindFirstFile(szTempPath, &Data);
	if(INVALID_HANDLE_VALUE == hSearch)
	{
		if(!IsImportantDir(szPath))
		{
			SetFileAttributes(szPath, 0);
			RemoveDirectory(szPath);
		}
		return;
	}

	do
	{
		if((Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x00) || 
		   (Data.cFileName[0] == 0x2E && Data.cFileName[1] == 0x2E && Data.cFileName[2] == 0x00))
		{
			continue;
		}

		if(!JoinStrings(szTempPath, _countof(szTempPath), szPath, _T("\\"), Data.cFileName, NULL))
		{
			break;
		}

		if((Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
		{
			MaxDeleteTempData(szTempPath);
		}
		else
		{
			SetFileAttributes(szTempPath, 0);
			DeleteFile(szTempPath);
		}
	}while(FindNextFile(hSearch, &Data));

	FindClose(hSearch);

	if(!IsImportantDir(szPath))
	{
		SetFileAttributes(szPath, 0);
		RemoveDirectory(szPath);
	}
	return;
}

/*-------------------------------------------------------------------------------------
Function		: IsImportantDir
In Parameters	: LPCTSTR szPath
Out Parameters	: bool
Purpose			: Important directories are POP3, SMTP, TEMPDATA & TEMPFOLDER, 
					These folder are required for the email scanner to work!
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CDirectoryManager::IsImportantDir(LPCTSTR szPath)
{
	LPCTSTR szFolderName = _tcsrchr(szPath, _T('\\'));
	if(!szFolderName)
	{
		return false;
	}

	if((_tcsicmp(szFolderName, _T("POP3")) != 0) || (_tcsicmp(szFolderName, _T("SMTP")) != 0)
		|| (_tcsicmp(szFolderName, _T("TEMPDATA")) != 0) || (_tcsicmp(szFolderName, _T("TEMPFOLDER")) != 0))
	{
		return true;
	}

	return false;
}