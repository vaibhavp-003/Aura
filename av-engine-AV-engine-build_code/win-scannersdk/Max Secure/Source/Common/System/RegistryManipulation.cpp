/*=============================================================================
   FILE			: RegistryManipulation.cpp
   ABSTRACT		: The class which handles the defragmentation as well as analysis. 
   DOCUMENTS	: CommonSystem DesignDoc.doc
   AUTHOR		: Avinash Bhardwaj
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 
   NOTES		:
VERSION HISTORY	: 24 Aug 2007, Avinash B : Unicode Supported
				
============================================================================*/
#include "stdafx.h"
#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include "Registry.h"
#include "CPUInfo.h"
#include "RegistryManipulation.h"

/*-----------------------------------------------------------------------------
	Function		: CRegistryManipulation ( Constructor)
	In Parameters	: -  
	Out Parameters	: - 
	Purpose			: constructor to initialize member variable
	Author			: 
-----------------------------------------------------------------------------*/
CRegistryManipulation::CRegistryManipulation(void)
{
	m_pRegistryFileInfo = NULL ;	
}

/*-----------------------------------------------------------------------------
	Function		: ~CRegistryManipulation
	In Parameters	: -
	Out Parameters	: -
	Purpose			: destructor to free the memory used
	Author			: 
-----------------------------------------------------------------------------*/
CRegistryManipulation::~CRegistryManipulation(void)
{
	try
	{
		if(m_pRegistryFileInfo)
			delete[] m_pRegistryFileInfo ; 
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::~CRegistryManipulation"));
	}
}

/*-------------------------------------------------------------------------------------
	Function		: GetFileSize
	In Parameters	: const CString &csFilePath : path of the file whose size is to be determined.
	Out Parameters	: file size
	Purpose			: returns the size of a file in kbs.
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
ULONGLONG CRegistryManipulation::GetFileSize(const CString &csFilePath)
{
	try
	{
		ULONGLONG fileSize = 0 ;
		//getting file size
		struct _stat buf;
		int result;
		result = _wstat( csFilePath, &buf );
		if(result == 0)
		fileSize = buf.st_size ;
		//converting bytes to kilo-bytes.
		fileSize = fileSize / 1024 ;

		return fileSize ;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::GetFileSize"));
	}
}

/*-------------------------------------------------------------------------------------
	Function		: CopyRegFile
	In Parameters	: CString csHive : name of the hive.
					  CString csSubKey : sub key.
					  CString csStoragePath : path of the registry file to be copied.
	Out Parameters	: true if copied successful else false.
	Purpose			: copies a registry file to a new file.
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
bool CRegistryManipulation::CopyRegFile(CString csHive , CString csSubKey ,CString csBackupFilePath)
{
	try
	{
		CRegistry objRegistry;
		HKEY hKey = objRegistry.GetHiveByName(csHive); 

		//copying the contents of registry files.
		bool bResult = objRegistry.SaveRegKeyPath(hKey,csSubKey,csBackupFilePath);
		return bResult ;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::CopyRegFile"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: MoveAFile
	In Parameters	: 
	Out Parameters	: 
	Purpose			: renames a file at boot time.
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CRegistryManipulation::MoveAFile(CString csFileToDelete , CString csFileToReplace)
{
	try
	{
		MoveFileEx( csFileToDelete,csFileToReplace, MOVEFILE_DELAY_UNTIL_REBOOT|MOVEFILE_REPLACE_EXISTING);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::MoveAFile"));
	}
}

/*-------------------------------------------------------------------------------------
	Function		: GetRegistryFileList
	In Parameters	: 
	Out Parameters	: 
	Purpose			: retrieves list of files for defragmentation, their hive, subkey etc.
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
void CRegistryManipulation::GetRegistryFileList()
{
	try
	{
		CRegistry objRegistry ; 
		CStringArray arrListOfFiles ;

		//getting the values in HKLM\SYSTEM\CurrentControlSet\Control\hivelist
		objRegistry.EnumValues(HIVE_LIST, arrListOfFiles, HKEY_LOCAL_MACHINE);
		int numOfEntries = static_cast<int>(arrListOfFiles.GetCount());
		m_iNumberOfFiles = numOfEntries; // arrListOfFiles.GetCount();

		
		//creating the drive letter mapping.
		CreateDriveMapping();

		//getting the windows installation directory.
		CString csWindowDirectory ;
		CCPUInfo objCPUInfo ;
		csWindowDirectory  = objCPUInfo.GetWindowsDir();

		m_pRegistryFileInfo = new CRegistryFileInfo[numOfEntries];

		//taking up the entries one by one and creating storge path and new path of the file.
		for(int iCount = 0 ; iCount <  arrListOfFiles.GetCount(); iCount++)
		{

			CString csValueName = arrListOfFiles.GetAt(iCount);
			//leaving the hardware and system.
			if(-1 != csValueName.Find(_T("HARDWARE")) || -1 != csValueName.Find(_T("SYSTEM")))
			{
				m_pRegistryFileInfo[iCount].m_csFileOrigPath = "";
				continue ;
			}

			//initially assuming that file does not exist.
			m_pRegistryFileInfo[iCount].m_bFileExist = false ;
			
			//getting the path of the file.
			CString csValue = _T("");
			//getting the storage path.
			objRegistry.Get(HIVE_LIST, csValueName, csValue, HKEY_LOCAL_MACHINE);
			CString csPath = _T("");
			GetLogicalPath(csValue,csPath);

			m_pRegistryFileInfo[iCount].m_csFileOrigPath = csPath ;
			int iLentgthOfString = csValue.GetLength();

			if(-1 != csValueName.Find(_T("MACHINE"))||-1 != csValueName.Find(_T("Machine"))||-1 != csValueName.Find(_T("machine")))
			{
				//setting the hive.
				m_pRegistryFileInfo[iCount].m_csHive = _T("HKEY_LOCAL_MACHINE");
				
		
			}
			if(-1 != csValueName.Find(_T("USER")) || -1 != csValueName.Find(_T("User")) || -1 != csValueName.Find(_T("user")))
			{
				//setting the hive.
				m_pRegistryFileInfo[iCount].m_csHive = _T("HKEY_USERS");
				
			}
			int iPost = csValueName.ReverseFind(_T('\\'));
			int iLen = csValueName.GetLength();
			m_pRegistryFileInfo[iCount].m_csSubKey = csValueName.Right(iLen - iPost -1);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::GetRegistryFileList"));
	}
}

/*-------------------------------------------------------------------------------------
	Function		: MoveNewFiles
	In Parameters	: 
	Out Parameters	: true if rename operation is successful else false.
	Purpose			: renames the intermediate files to original file name and removing old files.
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
bool CRegistryManipulation::MoveNewFiles()
{
	try
	{
		if(m_pRegistryFileInfo == NULL)
			return false ;

		//one by one moving new files.
		for(int index = 0 ;index < m_iNumberOfFiles ;index++)
		{
			if(m_pRegistryFileInfo[index].m_bIsNewFileCreated == false)
				continue ;

			//deleting the original file.
			MoveAFile(m_pRegistryFileInfo[index].m_csFileOrigPath ,CString(_T("")));

			//renaming the new file with the original name.
			MoveAFile(m_pRegistryFileInfo[index].m_csFileBackupPath, m_pRegistryFileInfo[index].m_csFileOrigPath);
		}

		return true ;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::MoveNewFiles"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: MakeBKFiles
	In Parameters	: 
	Out Parameters	: true if  operation is successful else false.
	Purpose			: copies the registry files and creates a new file with extension .bk .
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
bool CRegistryManipulation::MakeBKFiles(CString csBackUpPath)
{
	try
	{
		//takes the file one by one and makes a copy of it.
		if(m_pRegistryFileInfo == NULL)
			return false ;
		bool bResult = false;
		for(int index = 0 ; index < m_iNumberOfFiles ; index++)
		{
			//if registry file exists then making a copy of it with an extension *.bk
			if(m_pRegistryFileInfo[index].m_bFileExist == true)
			{	
				CString csBackupFilePath = GetBackupFilePath(csBackUpPath, m_pRegistryFileInfo[index].m_csSubKey);
				bResult = CopyRegFile( m_pRegistryFileInfo[index].m_csHive,m_pRegistryFileInfo[index].m_csSubKey,
											csBackupFilePath);
				m_pRegistryFileInfo[index].m_bIsNewFileCreated = bResult ;
				if(bResult)
					m_pRegistryFileInfo[index].m_csFileBackupPath = csBackupFilePath;
			}
			else
			{
				m_pRegistryFileInfo[index].m_bIsNewFileCreated = false ;
				
				//since the file is not created so there is no use of old storage path so destroying that also.
				m_pRegistryFileInfo[index].m_csFileOrigPath = _T("");
				m_pRegistryFileInfo[index].m_csFileBackupPath =_T("");

			}
		}
		//return true ;
		return bResult;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::MakeBKFiles"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: SearchFiles
	In Parameters	: 
	Out Parameters	: true if a single file is found else false.
	Purpose			: validates the presence of registry files.
	Author			: Avinash Bhardwaj
--------------------------------------------------------------------------------------*/
bool CRegistryManipulation::SearchFiles()
{
	try
	{
		bool bFileFound = false ;

		if(m_pRegistryFileInfo)
		{
			CFileFind objFileFind ;//object to search the files.
			bFileFound = true;
			for(int index = 0 ; index < m_iNumberOfFiles ;index++)
			{
				CString csStr = m_pRegistryFileInfo[index].m_csFileOrigPath;
				if(-1 != _waccess(m_pRegistryFileInfo[index].m_csFileOrigPath,0))
				{
					m_pRegistryFileInfo[index].m_bFileExist = true ;
				}
				else
				m_pRegistryFileInfo[index].m_bFileExist = false ;
			}
			return bFileFound;
		}
		return bFileFound ;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::SearchFiles"));
	}
	return false;
}
/*-----------------------------------------------------------------------------
	Function		: GetBackupFilePath
	In Parameters	: CString - backup folder path
					  CString - backup file path
	Out Parameters	: CString - backup file path
	Purpose			: to retrieve the backup file path
	Author			: 
-----------------------------------------------------------------------------*/
CString CRegistryManipulation::GetBackupFilePath(CString csBackupFolderPath, CString csSubKey)
{
	try
	{
		CString csBackFilePath = csBackupFolderPath + _T("\\") + csSubKey + CString(_T(".bk"));
		return csBackFilePath;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::GetBackupFilePath"));
	}
	return _T("");
}
/*-----------------------------------------------------------------------------
	Function		: CreateBackupFolder
	In Parameters	: CString& - backup folder path
					  CString& - folder name
	Out Parameters	: bool
	Purpose			: to create the backup folder
	Author			: 
-----------------------------------------------------------------------------*/
bool CRegistryManipulation::CreateBackupFolder(CString& csFolderPath, CString& csFolderName)
{
	try
	{
		CCPUInfo objSystem;
		SYSTEMTIME stCurrent = objSystem.GetCurrSystemTime();	
		CString strAppFolderDir = objSystem.GetWindowsDir();
		CString strSysBackupFolderDir = strAppFolderDir + REG_BACKUP_PATH;

		if (GetCountSubDirectories(strSysBackupFolderDir) == -1) //Directory doesnot exist
		{
			CreateDirectory((LPCTSTR)strSysBackupFolderDir,NULL);
		}
		csFolderName.Format (_T("%u%s%u%s%u%s%u%s%u"),stCurrent.wDay ,_T("-"),stCurrent.wMonth,_T("-"),stCurrent.wYear,_T("_"),stCurrent.wHour,_T("-"),stCurrent.wMinute);
		csFolderPath.Format (_T("%s%s%s"),strSysBackupFolderDir,_T("\\"),csFolderName);
		CreateDirectory((LPCTSTR)csFolderPath,NULL);	//Folder created
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::CreateBackupFolder"));
	}
	return false;
}
/*-----------------------------------------------------------------------------
	Function		: GetCountSubDirectories
	In Parameters	: CString& - dir
	Out Parameters	: int - count of sub dir
	Purpose			: to get the count of sub directory
	Author			: 
-----------------------------------------------------------------------------*/
int CRegistryManipulation::GetCountSubDirectories(CString strDirectory)
{
	try
	{
		int iCount = 0;
		
		//Check for Directory
		CFileFind findSubDir;
		BOOL bFound = findSubDir.FindFile(strDirectory);
		if(bFound == FALSE)
			return -1;
		
		bFound = findSubDir.FindFile(strDirectory + _T("/*.*"));
		if(bFound == TRUE)
		{
			while(bFound == TRUE)
			{
				bFound = findSubDir.FindNextFile();
				if (findSubDir.IsDots())	//For . and ..
				 continue;

				if(findSubDir.IsDirectory())
				{
					iCount++;
				}
			}
		}
		findSubDir.Close ();
		return iCount;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::GetCountSubDirectories"));
	}
	return -1;
}
/*-----------------------------------------------------------------------------
	Function		: RestoreBackUp
	In Parameters	: CString& - backup folder path
	Out Parameters	: int - count of sub dir
	Purpose			: to restore the backup
	Author			: 
-----------------------------------------------------------------------------*/
void CRegistryManipulation::RestoreBackUp(CString csBkUpFolderPath)
{
	try
	{
		for(int iIndex = 0 ;iIndex < m_iNumberOfFiles ;iIndex++)
		{
			CString csBackUpFileName = csBkUpFolderPath + _T("\\") + m_pRegistryFileInfo[iIndex].m_csSubKey +_T(".bk");
			if(-1 != _waccess(csBackUpFileName,0))
			{
				//deleting the original file.
				MoveAFile(m_pRegistryFileInfo[iIndex].m_csFileOrigPath ,CString(_T("")));

				//Keeping the copy of backup
				CString csCopyBackupFilePath  =  csBackUpFileName + _T(".bak");
				CopyFile(csBackUpFileName, csCopyBackupFilePath, FALSE);

				//renaming the new file with the original name.
				MoveAFile(csBackUpFileName, m_pRegistryFileInfo[iIndex].m_csFileOrigPath);
				//renaming the copy of backup to .bk
				MoveAFile(csCopyBackupFilePath, csBackUpFileName);
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::RestoreBackUp"));
	}
}
/*-----------------------------------------------------------------------------
	Function		: GetLogicalPath
	In Parameters	: CString - dos path
					  CString& - logical path
	Out Parameters	: void
	Purpose			: to retireve the logical path
	Author			: 
-----------------------------------------------------------------------------*/
void CRegistryManipulation::GetLogicalPath(CString csDosPath,CString &csLogicalPath)
{
	try
	{
		for(int i=0;i< m_csDosDevices.GetCount();i++)
		 {
			 if(csDosPath.Find(m_csDosDevices[i]) != -1)
			 {
				 //replacing that string with the logical drive letter.
				 //first removing the 
				 int iLength = m_csDosDevices[i].GetLength();
				 int iLengthOfPathStr = csDosPath.GetLength();
				 //taking the right of the path string.
				 CString csSubString = csDosPath.Right(iLengthOfPathStr - iLength);
				 //now creating logical path.
				 csLogicalPath = m_csDriveNames[i] + csSubString ;
				 break ;
			 }
		 }
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::GetLogicalPath"));
	}
}

/*-----------------------------------------------------------------------------
	Function		: CreateDriveMapping
	In Parameters	: -
	Out Parameters	: void
	Purpose			: to create the drive mapping
	Author			: 
-----------------------------------------------------------------------------*/
void CRegistryManipulation::CreateDriveMapping()
{
	try
	{
		TCHAR buf[MAX_BUFFER], dosbuf[MAX_BUFFER];
		CString csDrive;
		
		// Get logical drive strings-- a:\b:\c:\... etc.
		//fills a buffer with strings that specify valid drives in the system.
		GetLogicalDriveStrings(sizeof(buf)/sizeof(TCHAR),buf);
		for (TCHAR* s = buf; *s; s+=_tcslen(s)+1) 
		 {
			 LPCTSTR sDrivePath = s;
			 csDrive = sDrivePath ;
			 int ifind = csDrive.Find(_T("\\"),0);   
			 csDrive = csDrive.Mid(0,ifind);
			 m_csDriveNames.Add(csDrive);
			 
			 QueryDosDevice(csDrive,dosbuf,100);       
			 m_csDosDevices.Add(dosbuf);
		  }
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::CreateDriveMapping"));
	}

}
/*-----------------------------------------------------------------------------
	Function		: GetLogicalDeviceName
	In Parameters	: CString - drive name
	Out Parameters	: CString - logical device name
	Purpose			: to get the logical device name
	Author			: 
-----------------------------------------------------------------------------*/
CString CRegistryManipulation::GetLogicalDeviceName(CString DriveName)
{
   try
   {
		for(int i = 0; i < m_csDosDevices.GetCount(); i++)
			{
			  if (DriveName.CompareNoCase(m_csDosDevices.GetAt(i))== 0)
				  {
					  return m_csDriveNames.GetAt(i);
					  break;
				  }
			   }
   }
   catch(...)
	{
		AddLogEntry(_T("Exception caught in CRegistryManipulation::GetLogicalDeviceName"));
	}
	return _T("");
}