/*=============================================================================
   FILE		           : CommonFunctions.cpp
   ABSTRACT		       : 
   DOCUMENTS	       : Refer The Live Update Design.doc, Live Update Requirement Document.doc
   AUTHOR		       : Avinash
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C) Aura
						 Created as an unpublished copyright work.  All rights reserved.
						 This document and the information it contains is confidential and
						 proprietary to Aura.  Hence, it may not be 
						 used, copied, reproduced, transmitted, or stored in any form or by any 
						 means, electronic, recording, photocopying, mechanical or otherwise, 
						 without the prior written permission of Aura.	
   CREATION DATE      : 2/3/2005
   NOTES		      : This class containts commaon functions needed for live update.
   VERSION HISTORY    : 
				
=============================================================================*/

#include "pch.h"
#include "CommonFunctions.h"
#include "Wininet.h"
#include "LiveUpdateDLL.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: GetEmptyTempFolder
In Parameters	: -
Out Parameters	: CString
Purpose			: This function will get live update folder path and it will also
empty the folder.
Author			: Avinash Shendage.
--------------------------------------------------------------------------------------*/
CString CCommonFunctions::GetEmptyTempFolder()
{
	CString csInstallPath;
	CProductInfo objProdInfo;
	csInstallPath=objProdInfo.GetInstallPath();
	csInstallPath+="AuLiveupdate";
	CreateDirectory(csInstallPath.GetString(), NULL);

	// Make sure that this folder is empty!
	CString sPath = csInstallPath;
	sPath += "\\*.*";
	CFileFind	finder;
	BOOL bContinue = finder.FindFile(sPath);
	while(bContinue)
	{
		bContinue = finder.FindNextFile();
		::DeleteFile(finder.GetFilePath());
	}
	return CString(csInstallPath);
}

/*-------------------------------------------------------------------------------------
Function		: GetFileName
In Parameters	: CString, CString
Out Parameters	: CString
Purpose			: This function will get file names from from given section from
serverversion.txt
Author			: Avinash Shendage.
--------------------------------------------------------------------------------------*/
CString CCommonFunctions::GetFileName(CString sSectionName, CString csVersionINI)
{
	CString sFileaname = _T("");
	GetPrivateProfileString(sSectionName, _T("Filename"), _T(""), sFileaname.GetBuffer(MAX_PATH),
							MAX_PATH, csVersionINI);
	sFileaname.ReleaseBuffer();
	return sFileaname;
}

/*-------------------------------------------------------------------------------------
Function		: GetSectionName
In Parameters	: CString
Out Parameters	: CString
Purpose			: This function will get section name from CURRENT_SETTINGS_INI file
Author			: Dipali Pawar.
--------------------------------------------------------------------------------------*/
CString CCommonFunctions::GetSectionName(CString csSection)
{
	CString csSectionName;
	TCHAR szSection[MAX_PATH] = {0};
	CString csIniPath = GetModuleFilePath();
	csIniPath = csIniPath + _T("\\") + SETTING_FOLDER + CURRENT_SETTINGS_INI;
	GetPrivateProfileString(_T("Settings"), csSection, _T(""), szSection, MAX_PATH, csIniPath);
	
	csSectionName = szSection;
	



	return csSectionName;
}	

/********For X64***********/
CString CCommonFunctions::GetSectionNameForX64(CString csSection)
{
	CString csSectionName;
	TCHAR szSection[MAX_PATH] = {0};
	CString csIniPath = CSystemInfo::m_strAppPath + SETTING_FOLDER + CURRENT_SETTINGS_INI;
	GetPrivateProfileString(_T("Settings"), csSection, _T(""), szSection, MAX_PATH, csIniPath);
	
	csSectionName = szSection;

//#ifdef WIN64
	if((csSection != _T("DATABASEKEYM")) && (csSection != _T("DATABASEKEYW")) && (csSection != _T("DELTADETAILS")))
	{
		csSectionName += _T("X64");
	}
//#endif


	return csSectionName;
}	

/*-------------------------------------------------------------------------------------
Function		: CopyFolder
In Parameters	: CString, CString
Out Parameters	: BOOL
Purpose			: This function will copy the folder recursively
Author			: Swapnil D. Lokhande
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::CopyFolder(CString csDestination, CString csSource, CStringArray* pcsarrSkipFileList, CStringArray* pcsarrAllowedFileList)
{
	BOOL bRetVal = TRUE;
	CFileFind objFind;
	CString csFileName;
	int iCount=0, iSkipTotalCount=0, iAllowedTotalCount=0;
	if(pcsarrSkipFileList)
		iSkipTotalCount = (int)pcsarrSkipFileList->GetSize();
	if(pcsarrAllowedFileList)
		iAllowedTotalCount = (int)pcsarrAllowedFileList->GetSize();

	CreateDirectory(csDestination, NULL);

	BOOL bFind = objFind.FindFile(csSource+_T("\\*.*"));
	while(bFind)
	{
		bFind=objFind.FindNextFile();

		if(objFind.IsDots())
			continue;

		csFileName = objFind.GetFileName();
		if(objFind.IsDirectory())
			CopyFolder(csDestination+csFileName, csSource+csFileName);
		else
		{
			BOOL bSkipFile = FALSE, bAllowedFile = FALSE;
			for(iCount=0 ; iCount<iSkipTotalCount ; iCount++)
			{
				if(!csFileName.CompareNoCase(pcsarrSkipFileList->GetAt(iCount)))
				{
					bSkipFile = TRUE;
					break;
				}
			}
			for(iCount=0 ; iCount<iAllowedTotalCount ; iCount++)
			{
				if(!csFileName.CompareNoCase(pcsarrAllowedFileList->GetAt(iCount)))
				{
					bAllowedFile = TRUE;
					break;
				}
			}
			if(bAllowedFile || !bSkipFile)
			{
				if(!CopyFile(csSource + L"\\" + csFileName, csDestination + L"\\" + csFileName, FALSE))
					bRetVal = FALSE;
			}
		}
	}
	objFind.Close();

	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: CheckInternet
In Parameters	: -
Out Parameters	: BOOL
Purpose			: This function will check if Internet is accessible or no
Author			: Swapnil D. Lokhande
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::CheckInternet()
{
	CStringArray csPingSiteArr;
	{
		csPingSiteArr.Add(MAX_CHECK_INTERNET_CONNECTION_1);
		csPingSiteArr.Add(MAX_CHECK_INTERNET_CONNECTION_2);
	}

	for(int i = 0; i < csPingSiteArr.GetCount(); i++)
	{
		if(InternetCheckConnection(csPingSiteArr.GetAt(i), FLAG_ICC_FORCE_CONNECTION, 0))
		{
			return TRUE;
		}
	}
	return FALSE;
}

/*-------------------------------------------------------------------------------------
Function		: DeleteDirectory
In Parameters	: CString
Out Parameters	: BOOL
Purpose			: This function will delete existing directory
Author			: Swapnil D. Lokhande
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::DeleteDirectory(CString csPathName)
{
	BOOL bRetVal = FALSE;

	DWORD dwRetVal = GetFileAttributes(csPathName);
	if(dwRetVal == 0xFFFFFFFF)	//Folder doesnot exists
	{
		bRetVal = TRUE;
	}
	else
	{
		CFileFind objFind;
		BOOL bFind=objFind.FindFile(csPathName+_T("\\*.*"));
		while(bFind)
		{
			bFind=objFind.FindNextFile();

			if(objFind.IsDots())
				continue;

			if(objFind.IsDirectory())
				DeleteDirectory(csPathName + _T("\\") + objFind.GetFileName());
			else
				DeleteFile(objFind.GetFilePath());
		}
		objFind.Close();
		bRetVal = RemoveDirectory(csPathName);
	}
	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: ReCreateDirectory
In Parameters	: CString, LPSECURITY_ATTRIBUTES
Out Parameters	: BOOL
Purpose			: This function will delete existing directory and create a new one with same name
Author			: Swapnil D. Lokhande
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::ReCreateDirectory(CString csPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
	BOOL bRetVal = FALSE;

	if(DeleteDirectory(csPathName))
		bRetVal = CreateDirectory(csPathName, lpSecurityAttributes);

	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: GetServerVersionRegSectionForPatch
In Parameters	: CString, CString, CString&, CString&
Out Parameters	: BOOL
Purpose			: This function will get the server version from ini and get the Registry 
					key for getting local version
Author			: Swapnil D. Lokhande
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::GetServerVersionRegSectionForPatch(CString csPatchFile, CString csINIFile, CString& csSectionName, CString& csServerVersion)
{
	BOOL bRetVal = FALSE;
	CString csFileName;
	CStringArray objarrSections;

	GetAllSectionsInINI(csINIFile, objarrSections);
	int iTotalSections = (int)objarrSections.GetCount();
	for(int iCount=0 ; iCount<iTotalSections ; iCount++)
	{
		csSectionName = objarrSections.GetAt(iCount);
		GetPrivateProfileString(csSectionName, _T("Filename"), _T(""), csFileName.GetBuffer(100), 100, csINIFile);
		csFileName.ReleaseBuffer();
		if(!csFileName.CompareNoCase(csPatchFile))
		{
			GetPrivateProfileString(csSectionName, _T("VersionNo"), _T(""), csServerVersion.GetBuffer(100), 100, csINIFile);
			csServerVersion.ReleaseBuffer();

			bRetVal = TRUE;
			break;
		}
	}

	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: GetAllSectionsInINISid
In Parameters	: CString, CStringArray&
Out Parameters	: BOOL
Purpose			: This function give all the sections of INI in array
Author			: Swapnil D. Lokhande
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::GetAllSectionsInINI(CString csINIFile, CStringArray &objarrSections)
{
	BOOL bRetVal = FALSE;
	CString csTempBuff;
	wchar_t szBuffer[1000] = {0};
	int iLength = GetPrivateProfileString(NULL, NULL, _T(""), szBuffer,1000, csINIFile);
	for(int iCount=0 ; iCount<iLength ; iCount++)
	{
		if(szBuffer[iCount] == _T('\0'))
		{
			objarrSections.Add(csTempBuff);
			csTempBuff = _T("");

			bRetVal = TRUE;
		}
		else
			csTempBuff += szBuffer[iCount];
	}

	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: IsLocalVersionLowerThanServer
In Parameters	: CString, CString
Out Parameters	: BOOL
Purpose			: This function will check if Local Version is Lower than Server Version
Author			: Swapnil D. Lokhande
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::IsLocalVersionLowerThanServer(CString csServerVersion, CString csLocalVersion)
{
	BOOL bRetVal = FALSE;

	csLocalVersion.Replace(_T("."), _T(""));
	csServerVersion.Replace(_T("."), _T(""));

	DWORD dwLocalVer=_wtoi(csLocalVersion);
	DWORD dwServerVer=_wtoi(csServerVersion);

	if(dwLocalVer<dwServerVer)
		bRetVal = TRUE;

	return bRetVal;
}

/*-------------------------------------------------------------------------------------
Function		: MoveFolder
In Parameters	: CString , CString , CStringArray* , CStringArray* 
Out Parameters	: BOOL
Purpose			: This function will Move the folder
Author			: Swapnil D. Lokhande
--------------------------------------------------------------------------------------*/
BOOL CCommonFunctions::MoveFolder(CString csDestination, CString csSource, CStringArray* pcsarrSkipFileList, CStringArray* pcsarrAllowedFileList)
{
	BOOL bRetVal = TRUE;
	CFileFind objFind;
	CString csFileName;
	int iCount=0, iSkipTotalCount=0, iAllowedTotalCount=0;
	if(pcsarrSkipFileList)
		iSkipTotalCount = (int)pcsarrSkipFileList->GetSize();
	if(pcsarrAllowedFileList)
		iAllowedTotalCount = (int)pcsarrSkipFileList->GetSize();

	CreateDirectory(csDestination, NULL);

	BOOL bFind = objFind.FindFile(csSource+_T("\\*.*"));
	while(bFind)
	{
		bFind=objFind.FindNextFile();

		if(objFind.IsDots())
			continue;

		csFileName = objFind.GetFileName();
		if(objFind.IsDirectory())
			MoveFolder(csDestination+csFileName, csSource+csFileName);
		else
		{
			BOOL bSkipFile = FALSE, bAllowedFile = FALSE;
			for(iCount=0 ; iCount<iSkipTotalCount ; iCount++)
			{
				if(!csFileName.CompareNoCase(pcsarrSkipFileList->GetAt(iCount)))
				{
					bSkipFile = TRUE;
					break;
				}
			}
			for(iCount=0 ; iCount<iAllowedTotalCount ; iCount++)
			{
				if(!csFileName.CompareNoCase(pcsarrAllowedFileList->GetAt(iCount)))
				{
					bAllowedFile = TRUE;
					break;
				}
			}
			if(bAllowedFile || !bSkipFile)
			{
				if(!MoveFileEx(csSource + L"\\" + csFileName, csDestination + L"\\" + csFileName, MOVEFILE_REPLACE_EXISTING))
					bRetVal = FALSE;
			}
		}
	}
	objFind.Close();

	RemoveDirectory(csSource);

	return bRetVal;
}

TCHAR* CCommonFunctions::GetModuleFilePath()
{
	TCHAR *szModulePath = new TCHAR[MAX_PATH];
	DWORD dwSize = MAX_PATH;
	int iErrorCode = GetModuleFileName(NULL,szModulePath,dwSize);
	if(iErrorCode == ERROR_INSUFFICIENT_BUFFER)
	{
		delete szModulePath;
		szModulePath = new TCHAR[dwSize];
		GetModuleFileName(NULL,szModulePath,dwSize);
	}
	CString csModulePath(szModulePath);
	csModulePath = csModulePath.Left(csModulePath.ReverseFind(L'\\'));
	_stprintf_s(szModulePath,dwSize,csModulePath);
	return szModulePath;
}

