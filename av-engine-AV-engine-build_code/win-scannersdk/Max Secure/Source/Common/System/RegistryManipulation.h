/*=============================================================================
   FILE			: RegistryManipulation.h
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
VERSION HISTORY	:
				
============================================================================*/
#pragma once
#include <afxcoll.h>
//this class maintains information about each file which is to be defragged.

class CRegistryFileInfo
{
public:
	
	CString m_csFileOrigPath ;
	CString m_csFileBackupPath ;
	CString m_csHive ;
	CString m_csSubKey ;
	bool m_bFileExist ;
	bool m_bIsNewFileCreated ;
};

class CRegistryManipulation
{

public:
	CString m_csBackupFolderPath; 
	CRegistryManipulation(void);
public:
	~CRegistryManipulation(void);

	int m_iNumberOfFiles ;
	CStringArray m_csDriveNames ;
	CStringArray m_csDosDevices ;
	CStringArray m_csArrRegistryFiles ; //list of files created after defragmentation.
	CRegistryFileInfo *m_pRegistryFileInfo ;
	CString m_csOSDirectory ;

    ULONGLONG GetFileSize(const CString &csFilePath);	//returns the file size
	bool IsFileExisting(const CString &csFilePath);
	bool CopyRegFile(CString csHive , CString csSubKey,CString csStoragePath);
	void MoveAFile(CString csFileToDelete , CString csFileToReplace);
	void GetRegistryFileList();
	bool MoveNewFiles();
	bool MakeBKFiles(CString csBackupFolderPath);
	bool SearchFiles();
	CString GetNewFilePath(CString csOldFilePath,CString csSubKey);
	CString GetBackupFilePath(CString csBackupFolderPath, CString csSubKey);
	ULONGLONG FileSize(CString csDirPath ,CString csFilePath);
	int  GetCountSubDirectories(CString strDirectory);
	bool CreateBackupFolder(CString& csFolderPath, CString& csFolderName);
	void RestoreBackUp(CString csBkUpFolderPath);
	CString GetLogicalDeviceName(CString DriveName);
	void CreateDriveMapping();
	void GetLogicalPath(CString csDosPath,CString &csLogicalPath);
};
