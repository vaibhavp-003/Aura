/*======================================================================================
   FILE				: CScapeGoatScan.cpp
   ABSTRACT			: This class is used for scanning ScapeGoat Files 
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Yuvraj 
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 26-3-2010
   NOTE				:
   VERSION HISTORY	:
					
========================================================================================*/

#include "pch.h"
#include "ScapeGoatScan.h"
#include "ExecuteProcess.h"
#include "BackupOperations.h"
#include <io.h>

bool GetMD5Signature32(const char *filepath, char *cMD5Signature);

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool bToDelete , CFileSignatureDb *pFileSigMan
	Out Parameters	: 
	Purpose			: 
	Author			: Yuvraj
	Description		: main entry point of this class for scanning scapegoat files 
--------------------------------------------------------------------------------------*/
bool CScapeGoatScan::ScanSplSpy ( bool bToDelete, CFileSignatureDb *pFileSigMan )
{
 	try
	{
		m_obj7zDLL.LoadMax7zDll();
		m_csFDPath = CSystemInfo::m_strAppPath + _T("FileData");

		if(IsStopScanningSignaled())
		{
			return m_bSplSpyFound;
		}

		if(bToDelete)
		{
			DWORD dwErr;
			CFileOperation::DeleteFolderTree(m_csFDPath, true, false, dwErr);
			CBackupOperations::CopyAndEncryptFile(CSystemInfo::m_strAppPath+_T("FileData.zip"), CSystemInfo::m_strAppPath+_T("FileData.zip"));
			CBackupOperations::ExtractFile(CSystemInfo::m_strAppPath+_T("FileData.zip"), CSystemInfo::m_strAppPath);
			CBackupOperations::CopyAndEncryptFile(CSystemInfo::m_strAppPath+_T("FileData.zip"), CSystemInfo::m_strAppPath+_T("FileData.zip"));
			WritePrivateProfileStringA("Data", "filedata", "1", CStringA(m_csFDPath) + CStringA(INI_FILE_DATA_NAME));
		}
		else
		{
			EnumerateFolder(m_csFDPath);			
		}		

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound;
		return m_bSplSpyFound;
	}

	catch( ... )
	{
		CString csErr;
		csErr.Format( _T("Exception caught in CScapeGoatScan::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry( csErr, 0, 0 );
	}
	m_obj7zDLL.UnLoadMax7zDll();
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: EnumerateFolder
	In Parameters	: const CString csFolderPath
	Out Parameters	: -
	Purpose			: Enumerate files
	Author			: Yuvraj
	Description		: Enumerate files from given folder i.e. FileData folder in SD
--------------------------------------------------------------------------------------*/
void CScapeGoatScan::EnumerateFolder(const CString csFolderPath)
{
	CFileFind objFinder ;
	CString csHoldFileName = csFolderPath;
	BOOL bMoreFiles = FALSE ;
	bool bIsMisMatch = false;

	bMoreFiles = objFinder.FindFile(csHoldFileName + _T("\\data*.*"));
	if (!bMoreFiles)
		return ;

	while(bMoreFiles)
	{
		bMoreFiles = objFinder.FindNextFile() ;
		if (objFinder.IsDots())
			continue;

		csHoldFileName = objFinder.GetFilePath() ;

		if (objFinder.IsDirectory())
		{
			EnumerateFolder(csHoldFileName);
		}
		else
		{
			csHoldFileName.MakeLower();
			if(csHoldFileName.Find(_T("filedata.ini")) != -1)
			{
				continue;
			}
			
			bIsMisMatch = CheckMD5MisMatch(csHoldFileName);
			//if(bIsMisMatch)
			//{
			//	break;
			//}
		}
	}
	objFinder.Close();
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckMD5MisMatch
	In Parameters	: const CString csFilePath
	Out Parameters	: bool
	Purpose			: Check files MD5 against MD5 from ini file
	Author			: Yuvraj
	Description		: Check MD5 of file and compare it with MD5 in FileData.ini, if MD5 
					  mismatch zip the FileData folder and copy it in Log Folder 
--------------------------------------------------------------------------------------*/
bool CScapeGoatScan::CheckMD5MisMatch(const CString csFilePath)
{
	char szStrIniMD5[33] = {0};
	char szStrFileMD5[33] = {0};
	DWORD dwMD5Len = 33;
	CString csIniPath, csFileName;
	int iIndex = 0;
	
	csIniPath = m_csFDPath + INI_FILE_DATA_NAME; 

	bool bGotMD5 = GetMD5Signature32((CStringA)csFilePath, szStrFileMD5);

	if(!bGotMD5)
	{
		return false;
	}

	iIndex = csFilePath.ReverseFind(_T('.'));
	csFileName = csFilePath.Mid(iIndex - 6, 6);

	GetPrivateProfileStringA("Data", (CStringA)csFileName, "0", szStrIniMD5, dwMD5Len, (CStringA)csIniPath);
	
	if(_stricmp(szStrIniMD5, szStrFileMD5) != 0) //MD5 mismatch, file modified
	{
		//Threatcommunity removed
		//CString csZipPath = CSystemInfo::m_strAppPath + THREAT_COMMUNITY_FOLDER +_T("\\FileData.zip");
		////csZipPath.Format(_T(""),);
		////7zip compress
		//m_obj7zDLL.Max7zArchive(csZipPath,m_csFDPath,_T("a@u$ecD!"));
		
		WritePrivateProfileStringA("Data", "filedata", "1", (CStringA)csIniPath);
		SendScanStatusToUI(Special_File_Report, m_ulSpyName, csFilePath);
		m_bSplSpyFound = true;
		return true;
	}
	return false;
}

