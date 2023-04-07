/*======================================================================================
FILE             : BackupOperations.h
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Sandip Sanap
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
#pragma once

#include <string>
#include <fstream>
#include "ZipArchive.h"

using namespace std;

class CBackupOperations
{
public:
	CBackupOperations(void);
	~CBackupOperations(void);

	//static Functions
	//Overloaded
	static CString GetQuarantineFolderPath();
	static CString GetBackupFileName();
	static bool GetAllFilePathsInFolder(CString csFolder, CStringArray &csFilePathArr);
	static bool CopyAndEncryptFile(CString csExistingFileName, CString csNewFileName);
	static bool ExtractFile(CString csZipFilePath, CString csExtractToPath, bool bUsePassword = false);
	static bool ExtractFile(CString csZipFilePath, CString csExtractToPath, bool bUsePassword, CString csFileName);
	static bool CopyNZipNCrypt(CString csExistingPath, CString csZipFileName, int nMessageInfo, bool bSetPassword = false);
	static bool CopyAndZipFiles(CStringArray &csExistingPathArr, CString csZipFileName);
	static bool CopyAndZipFolder(CString csExistingPath, CString csZipFileName, CString csType, bool bFullPath = true, bool bToEncrypt = true,bool bSetPassword = false);
	static bool CreateThreatCommunityZipBySpan(CString csExistingPath, CString csZipFileName,bool bFullPath);
	void InitArchieve(CString csZipFileName, bool bSetPassword);
	bool AddToArchieve(CString csExistingPath, int nMessageInfo);
	bool DeInitArchieve(CString csZipFileName);
	//Krishna::2-07-2015(For Cloud Backup and restoring)
	bool CopyAndZipFolder(CString csExistingPath, CString csZipFileName,CString csType,CString csPassword, bool bFullPath, bool bToEncrypt, bool bSetPassword);
	bool ExtractFile(CString csZipFilePath, CString csExtractToPath,CString csPassword, bool bUsePassword);
	bool CopyAndZipFiles(CStringArray &csExistingPathArr, CString csZipFileName,bool bUsePassword);
private:
	CZipArchive m_objMultiFilesArchieve;
	static CString m_csBackupPath;
	static bool GetAllFilePathsInFolder(CString csFolder, CZipArchive &oZipArc,bool bFullPAth = true);
	static bool GetAllFilePathsInFolderForCloudbackup(CString csFolder, CZipArchive &oZipArc,bool bFullPAth = true);
};
