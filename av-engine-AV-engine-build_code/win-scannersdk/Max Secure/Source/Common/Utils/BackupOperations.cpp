/*======================================================================================
FILE             : BackupOperations.h
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : 
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 04-Jan-2007
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
#include "pch.h"
#include "BackupOperations.h"
#include "SDSystemInfo.h"
#include "Cryptor.h"
//#include "FileOperation.h"
#include "SDConstants.h"
#include "MaxConstant.h"
#include "ProductInfo.h"
#include <io.h>
#include <shlwapi.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CString CBackupOperations::m_csBackupPath;
#define MAX_VAL (4*1024*1024)

//Default Constructor
/*--------------------------------------------------------------------------------------
Function       : CBackupOperations
In Parameters  : void, 
Out Parameters : 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CBackupOperations::CBackupOperations(void)
{
}

//Default Destructor
/*--------------------------------------------------------------------------------------
Function       : ~CBackupOperations
In Parameters  : void, 
Out Parameters : 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CBackupOperations::~CBackupOperations(void)
{
}

/*-------------------------------------------------------------------------------------
Function		: GetQuarantineFolderPath
In Parameters	: -
Out Parameters	: CString : Quarantine(Backup)Folder Path
Purpose			: Get Quarantine folder path to keep backup
: and if folder is not present keep backup
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CString CBackupOperations::GetQuarantineFolderPath()
{
	if(m_csBackupPath.GetLength()== 0)
	{
		m_csBackupPath = CSystemInfo::m_strAppPath + QUARANTINEFOLDER;
		if(!::PathIsDirectory(m_csBackupPath))
		{
			CreateDirectory(m_csBackupPath, NULL);
		}
	}
	return m_csBackupPath;
}

/*-------------------------------------------------------------------------------------
Function		: GetBackupFileName
In Parameters	: CString &csFilePath - entry path
Out Parameters	: CString - backup file name
Purpose			: Get backup file name
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
CString CBackupOperations::GetBackupFileName()
{
	WCHAR wcsBackupFileName[MAX_PATH] = {0};
	GetTempFileName(static_cast<LPCTSTR>(CBackupOperations::GetQuarantineFolderPath()),
					0, 0, wcsBackupFileName);
	return CString(wcsBackupFileName);
}

/*-------------------------------------------------------------------------------------
Function		: GetAllFilePathsInFolder
In Parameters	: CString	   : Folder name
CStringArray : File path array
Out Parameters	: bool : true(Successful)/False
Purpose			: Get all file path in the given folder
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CBackupOperations::GetAllFilePathsInFolder(CString csFolder, CStringArray &csFilePathArr)
{
	CFileFind objFileFind;
	BOOL bContinue = objFileFind.FindFile(csFolder + _T("/*.*"));
	bool bIsFile;
	bIsFile = false;
	while(bContinue)
	{
		bContinue = objFileFind.FindNextFile();
		CString csFilePath = objFileFind.GetFilePath();
		if(objFileFind.GetFileName()== "." || objFileFind.GetFileName()== "..")
		{
			continue;
		}
		if(objFileFind.IsDirectory())
		{
			GetAllFilePathsInFolder(csFilePath, csFilePathArr);
		}
		else
		{
			csFilePathArr.Add(csFilePath);
			bIsFile = true;
		}
	}
	objFileFind.Close();
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : GetAllFilePathsInFolder
In Parameters  : CString csFolder, CZipArchive &oZipArc, bool bFullPAth, 
Out Parameters : bool 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CBackupOperations::GetAllFilePathsInFolder(CString csFolder, CZipArchive &oZipArc,
												bool bFullPAth)
{
	CFileFind objFileFind;
	BOOL bContinue = objFileFind.FindFile(csFolder + _T("/*.*"));
	bool bReturnVal = false;
	bReturnVal = oZipArc.AddNewFile(csFolder, -1, bFullPAth);
	while(bContinue)
	{
		bContinue = objFileFind.FindNextFile();
		CString csFilePath;
		csFilePath = objFileFind.GetFilePath();

		if(objFileFind.MatchesMask(FILE_ATTRIBUTE_REPARSE_POINT))
		{
			continue;
		}

		if(objFileFind.IsDirectory())
		{
			if(objFileFind.GetFileName() == "." || objFileFind.GetFileName() == "..")
			{
				continue;
			}
			bReturnVal = oZipArc.AddNewFile(csFilePath, -1, bFullPAth);
			GetAllFilePathsInFolder(csFilePath, oZipArc);
		}
		else
		{
			bReturnVal = oZipArc.AddNewFile(csFilePath, -1, bFullPAth);
			if(!bReturnVal)
			{
				break;
			}
		}
	}
	objFileFind.Close();
	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
Function		: CopyAndEncryptFile
In Parameters	: CString :Sorce file/folder path
CString : destination file name
Out Parameters	: bool : true(Successful)/False
Purpose			: Copy given file / folder to destination path
: and Encrypt it.
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CBackupOperations::CopyAndEncryptFile(CString csExistingFileName, CString csNewFileName)
{
	bool bRet = false;
	try
	{
		if(csExistingFileName != csNewFileName)
		{
			bRet = CryptFile(csExistingFileName, csNewFileName);
		}
		else
		{
			CString csNewFileNm = csExistingFileName + _T("__");
			bRet = CryptFile(csExistingFileName, csNewFileNm);
			if(bRet)
			{
				if(MoveFileEx(csNewFileNm, csExistingFileName, MOVEFILE_REPLACE_EXISTING))
				{
					bRet = true;
				}
				else
				{
					AddLogEntry(_T("MoveFileEx failed: %s to %s"), csNewFileNm, csExistingFileName);
				}
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBackupOperations::CopyAndEncryptFile"));
	}
	return bRet;
}

/*-------------------------------------------------------------------------------------
Function		: ExtractFile
In Parameters	: CString csZipFilePath,CString csExtractToPath
Out Parameters	: bool : true(Successful)/false
Purpose			: To Extract a file
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CBackupOperations::ExtractFile(CString csZipFilePath, CString csExtractToPath, bool bUsePassword)
{
	try
	{
		CZipArchive m_Arc;
		bool bRet = true;
		m_Arc.Open(csZipFilePath, CZipArchive::openReadOnly);

		if(bUsePassword)
		{
			m_Arc.SetPassword(_T("a@u$ecD!"));
		}
		int iCount = m_Arc.GetNoEntries();
		for(int i=0; i < iCount; i++)
		{
			CZipFileHeader fh;
			m_Arc.GetFileInfo(fh, (WORD)i);
#ifdef _SDSCANNER
			if(csExtractToPath.GetAt(0)==L'\\')
			{
				if(!m_Arc.ExtractFile((WORD)i, csExtractToPath, false))
				{
					bRet = false;
				}
			}
			else
			{
				if(!m_Arc.ExtractFile((WORD)i, csExtractToPath))
				{
					bRet = false;
				}	
			}
#else
			if(!m_Arc.ExtractFile((WORD)i, csExtractToPath))
			{
				bRet = false;
			}
#endif
		}
		m_Arc.Close();
		return bRet;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBackupOperations::ExtractFile"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: ExtractFile
In Parameters	: CString csZipFilePath,CString csExtractToPath
Out Parameters	: bool : true(Successful)/false
Purpose			: To Extract a file
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CBackupOperations::ExtractFile(CString csZipFilePath, CString csExtractToPath, bool bUsePassword, CString csFileName)
{
	try
	{
		CZipArchive m_Arc;
		bool bRet = true;
		m_Arc.Open(csZipFilePath, CZipArchive::openReadOnly);
		if(bUsePassword)
		{
			m_Arc.SetPassword(_T("a@u$ecD!"));
		}
		int iCount = m_Arc.GetNoEntries();
		for(int i=0; i < iCount; i++)
		{
			CZipFileHeader fh;
			m_Arc.GetFileInfo(fh, (WORD)i);
			if(!m_Arc.ExtractFile((WORD)i, csExtractToPath, false, csFileName))
			{
				bRet = false;
			}
		}
		m_Arc.Close();
		return bRet;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBackupOperations::ExtractFile"));
	}
	return false;
}

/*--------------------------------------------------------------------------------------
Function       : CopyNZipNCrypt
In Parameters  : CString csExistingPath, CString csZipFileName, int nMessageInfo, 
Out Parameters : bool 
Description    : 
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CBackupOperations::CopyNZipNCrypt(CString csExistingPath, CString csZipFileName,
									   int nMessageInfo, bool bSetPassword)
{
	try
	{
		CZipArchive m_Arc;
		bool bErr = true;
		m_Arc.Open(csZipFileName, CZipArchive::create);
		if(bSetPassword)
		{
			m_Arc.SetPassword(_T("a@u$ecD!"));
		}
#pragma warning(disable: 4482)
		if(nMessageInfo == SD_Message_Info::Folder)
#pragma warning(default: 4482)
		{
			bErr = GetAllFilePathsInFolder(csExistingPath, m_Arc);
		}
		else
		{
			bErr = m_Arc.AddNewFile(csExistingPath);
		}
		m_Arc.Close();

		if(bErr == false)
		{
			return false;
		}

		if(CopyAndEncryptFile(csZipFileName, csZipFileName))
		{
			return true;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBackupOperations::CopyNZipNCrypt"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: CopyAndZipFiles
In Parameters	: CStringArray :  file path (Sorce file path)
CString : New File Name(destination zip file name)
Out Parameters	: bool : true(Successful)/False
Purpose			: Copy given files to destination path
: and Zip it.
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CBackupOperations::CopyAndZipFiles(CStringArray &csExistingPathArr, CString csZipFileName)
{
	try
	{
		CZipArchive m_Arc;
		m_Arc.Open(csZipFileName, CZipArchive::create);
		bool bErr;
		bErr = true;
		for(int i =0; i < csExistingPathArr.GetCount();i++)
		{
			CString csFilePath;
			csFilePath = csExistingPathArr.GetAt(i);
			bErr = m_Arc.AddNewFile(csFilePath,-1,false);
		}
		m_Arc.Close();
		if(bErr == false)
		{
			return false;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBackupOperations::CopyAndZipFiles"));
		return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: CopyAndZipFolder
In Parameters	: CString : Folder / file path (Sorce file/folder path)
CString : New File Name(destination zip file name)
CString : Type(File / Folder)
Out Parameters	: bool : true(Successful)/False
Purpose			: Copy given file / folder to destination path
: and Zip it.
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CBackupOperations::CopyAndZipFolder(CString csExistingPath, CString csZipFileName,
										 CString csType, bool bFullPath, bool bToEncrypt, bool bSetPassword)
{
	try
	{
		CZipArchive m_Arc;
		m_Arc.Open(csZipFileName, CZipArchive::create);
		if (bSetPassword)
		{
			m_Arc.SetPassword(L"a@u$ecD!");
		}
		bool bErr;
		bErr = true;
		if(csType == "Folder")
		{
			GetAllFilePathsInFolder(csExistingPath, m_Arc, bFullPath);
		}
		else
		{
			if(!bFullPath)
			{
				bErr = m_Arc.AddNewFile(csExistingPath,-1,bFullPath);
			}
			else
			{
				bErr = m_Arc.AddNewFile(csExistingPath);
			}
		}
		m_Arc.Close();

		if(bErr == false)
		{
			return false;
		}
		
		if(bToEncrypt)
		{
			if(CopyAndEncryptFile(csZipFileName, csZipFileName))
			{
				return true;
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBackupOperations::CopyAndZipFolder"));
		return false;
	}
	return false;
}

bool CBackupOperations::CreateThreatCommunityZipBySpan(CString csExistingPath, CString csZipFileName,bool bFullPath)
{
	try
	{
		CZipArchive m_Arc;
		m_Arc.Open(csZipFileName, CZipArchive::createSpan,MAX_VAL);
		m_Arc.SetPassword(L"a@u$ecD!");

		bool bErr;
		bErr = true;
		GetAllFilePathsInFolder(csExistingPath, m_Arc, bFullPath);
		m_Arc.Close();

		CProductInfo objPrdInfo;
		CFileFind objFinder;
		BOOL bMoreFiles = FALSE;
		int iCnt = 0;

		int iFind = csZipFileName.ReverseFind ('.');
		CString csTemp = csZipFileName.Left(iFind + 1);
		bMoreFiles = objFinder.FindFile(csTemp + _T("*"));
		if(!bMoreFiles)
		{
			return false;
		}

		while(bMoreFiles)
		{
			bMoreFiles = objFinder.FindNextFile();
			if(objFinder.IsDots() || objFinder.IsDirectory())
			{
				continue;
			}
			CString csFileToZip = objFinder.GetFilePath();
			if(!CopyAndEncryptFile(csFileToZip, csFileToZip))
			{
				return false;
			}
			
		}
		objFinder.Close ();

	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBackupOperations::CopyAndZipFolder"));
		return false;
	}
	return true;
}

void CBackupOperations::InitArchieve(CString csZipFileName, bool bSetPassword)
{
	m_objMultiFilesArchieve.Open(csZipFileName, CZipArchive::create);
	if(bSetPassword)
		m_objMultiFilesArchieve.SetPassword(_T("a@u$ecD!"));
}

bool CBackupOperations::AddToArchieve(CString csExistingPath, int nMessageInfo)
{
	bool bErr = true;
#pragma warning(disable: 4482)
	if(nMessageInfo == SD_Message_Info::Folder)
#pragma warning(default: 4482)
		bErr = GetAllFilePathsInFolder(csExistingPath, m_objMultiFilesArchieve);
	else
		bErr = m_objMultiFilesArchieve.AddNewFile(csExistingPath);

	return bErr;
}

bool CBackupOperations::DeInitArchieve(CString csZipFileName)
{
	m_objMultiFilesArchieve.Close();
	return CopyAndEncryptFile(csZipFileName, csZipFileName);
}

/*-------------------------------------------------------------------------------------
Function		: CopyAndZipFolder
In Parameters	: CString : Folder / file path (Sorce file/folder path)
CString : New File Name(destination zip file name)
CString : Type(File / Folder)
Out Parameters	: bool : true(Successful)/False
Purpose			: Copy given file / folder to destination path(For Cloud Backup)
: and Zip it.
Author			: Krishna Thapa
--------------------------------------------------------------------------------------*/
bool CBackupOperations::CopyAndZipFolder(CString csExistingPath, CString csZipFileName,
										 CString csType,CString csPassword, bool bFullPath, bool bToEncrypt, bool bSetPassword)
{
	try
	{
		CZipArchive m_Arc;
		m_Arc.Open(csZipFileName, CZipArchive::create);
		if (bSetPassword)
		{
			m_Arc.SetPassword(csPassword);
		}
		bool bErr;
		bErr = true;
		if(csType == "Folder")
		{
			GetAllFilePathsInFolderForCloudbackup(csExistingPath, m_Arc, bFullPath);
		}
		else
		{
			if(!bFullPath)
			{
				bErr = m_Arc.AddNewFile(csExistingPath,-1,bFullPath);
			}
			else
			{
				bErr = m_Arc.AddNewFile(csExistingPath);
			}
		}
		m_Arc.Close();

		if(bErr == false)
		{
			return false;
		}
		
		if(bToEncrypt)
		{
			if(CopyAndEncryptFile(csZipFileName, csZipFileName))
			{
				return true;
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBackupOperations::CopyAndZipFolder"));
		return false;
	}
	return false;
}


/*--------------------------------------------------------------------------------------
Function       : GetAllFilePathsInFolder
In Parameters  : CString csFolder, CZipArchive &oZipArc, bool bFullPAth, 
Out Parameters : bool 
Description    : 
Author         : Krishna Thapa
--------------------------------------------------------------------------------------*/
bool CBackupOperations::GetAllFilePathsInFolderForCloudbackup(CString csFolder, CZipArchive &oZipArc,
												bool bFullPAth)
{
	CFileFind objFileFind;
	BOOL bContinue = objFileFind.FindFile(csFolder + _T("/*.*"));
	bool bReturnVal = false;
	//bReturnVal = oZipArc.AddNewFile(csFolder, -1, bFullPAth);
	while(bContinue)
	{
		bContinue = objFileFind.FindNextFile();
		CString csFilePath;
		csFilePath = objFileFind.GetFilePath();

		if(objFileFind.MatchesMask(FILE_ATTRIBUTE_REPARSE_POINT))
		{
			continue;
		}

		if(objFileFind.IsDirectory())
		{
			if(objFileFind.GetFileName() == "." || objFileFind.GetFileName() == "..")
			{
				continue;
			}
			bReturnVal = oZipArc.AddNewFile(csFilePath, -1, bFullPAth);
			GetAllFilePathsInFolder(csFilePath, oZipArc);
		}
		else
		{
			bReturnVal = oZipArc.AddNewFile(csFilePath, -1, bFullPAth);
			if(!bReturnVal)
			{
				break;
			}
		}
	}
	objFileFind.Close();
	return bReturnVal;
}

/*-------------------------------------------------------------------------------------
Function		: ExtractFile
In Parameters	: CString csZipFilePath,CString csExtractToPath
Out Parameters	: bool : true(Successful)/false
Purpose			: To Extract a file(Own Password for Cloud Backup)
Author			: Krishna Thapa
--------------------------------------------------------------------------------------*/
bool CBackupOperations::ExtractFile(CString csZipFilePath, CString csExtractToPath,CString csPassword, bool bUsePassword)
{
	try
	{
		CZipArchive m_Arc;
		bool bRet = true;
		m_Arc.Open(csZipFilePath, CZipArchive::openReadOnly);
		if(bUsePassword)
		{
			m_Arc.SetPassword(csPassword);
		}
		int iCount = m_Arc.GetNoEntries();
		for(int i=0; i < iCount; i++)
		{
			CZipFileHeader fh;
			m_Arc.GetFileInfo(fh, (WORD)i);
			if(!m_Arc.ExtractFile((WORD)i, csExtractToPath))
			{
				bRet = false;
			}
		}
		m_Arc.Close();
		return bRet;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBackupOperations::ExtractFile"));
	}
	return false;
}


/*-------------------------------------------------------------------------------------
Function		: CopyAndZipFiles
In Parameters	: CStringArray :  file path (Sorce file path)
CString : New File Name(destination zip file name)
Out Parameters	: bool : true(Successful)/False
Purpose			: Copy given files to destination path
: and Zip it.
Author			: Krishna
--------------------------------------------------------------------------------------*/
bool CBackupOperations::CopyAndZipFiles(CStringArray &csExistingPathArr, CString csZipFileName,bool bUsePassword)
{
	try
	{
		CZipArchive m_Arc;
		m_Arc.Open(csZipFileName, CZipArchive::create);
		if(bUsePassword)
		{
			m_Arc.SetPassword(L"a@u$ecD!");
		}
		bool bErr;
		bErr = true;
		for(int i =0; i < csExistingPathArr.GetCount();i++)
		{
			CString csFilePath;
			csFilePath = csExistingPathArr.GetAt(i);
			bErr = m_Arc.AddNewFile(csFilePath,-1,false);
		}
		m_Arc.Close();
		if(bErr == false)
		{
			return false;
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CBackupOperations::CopyAndZipFiles"));
		return false;
	}
	return true;
}