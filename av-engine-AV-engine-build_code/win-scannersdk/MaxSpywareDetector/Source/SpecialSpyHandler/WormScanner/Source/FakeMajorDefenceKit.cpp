/*======================================================================================
   FILE				: FakeMajorDefenceKit.Cpp
   ABSTRACT			: This class is used for scanning and qurantining Spyware Fake Major Defence Kit and variants
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 31/08/2010
   NOTE				:
   VERSION HISTORY	:
========================================================================================*/

#include "pch.h"
#include "FakeMajorDefenceKit.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/*-------------------------------------------------------------------------------------
	Function		: ScanSplSpy
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: Checks and remove Fake Major Defence Kit
	Author			: 
	Description		: remove Fake Major Defence Kit and variants from USER\Application Data\antispy.exe
--------------------------------------------------------------------------------------*/
bool CFakeMajorDefenceKit::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_pFileSigMan = pFileSigMan;

		if(IsStopScanningSignaled())
		{
			return false;
		}

		if(bToDelete)
		{
			m_bSplSpyFound = FixInfection();
		}
		else
		{
			m_bSplSpyFound = SearchInfection();
		}

		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound;
		return m_bSplSpyFound;
	}

	catch(...)
	{
        CString csErr;
		csErr.Format( _T("Exception caught in CFakeMajorDefenceKit::ScanSplSpy, Error : %d") ,GetLastError());
		AddLogEntry(csErr);
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: SearchInfection
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: searches for infection in pre known locations
	Author			: Anand Srivastava
	Description		: main location and file -> C:\Documents and Settings\admin\Application Data\antispy.exe
					  file is upx packed
--------------------------------------------------------------------------------------*/
bool CFakeMajorDefenceKit::SearchInfection()
{
	try
	{
		bool bFoundInfection = false;
		CFileFind objFinder;
		CString csTempPath;
		BOOL bDone = FALSE;

		if(!PreparePathsToSearch())
		{
			return false;
		}

		for(int i = 0, iTotal = (int)m_csArrSpyLocation.GetCount(); i < iTotal; i++)
		{
			if(IsStopScanningSignaled())
			{
				break;
			}

			csTempPath = m_csArrSpyLocation.GetAt(i) + _T("\\*.exe");

			bDone = objFinder.FindFile(csTempPath);
			while(bDone)
			{
				bDone = objFinder.FindNextFile();
				csTempPath = objFinder.GetFilePath();
				csTempPath.MakeLower();

				if(IsFileInfected(csTempPath))
				{
					m_bSplSpyFound = true;
					bFoundInfection = true;
					CheckAndReportInfection(csTempPath);
				}

				if(!bDone)
				{
					objFinder.Close();
				}
			}
		}

		return bFoundInfection;
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in CFakeMajorDefenceKit::SearchInfection"));
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: PreparePathsToSearch
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: prepare locations
	Author			: Anand Srivastava
	Description		: main location -> C:\Documents and Settings\admin\Application Data
--------------------------------------------------------------------------------------*/
bool CFakeMajorDefenceKit::PreparePathsToSearch()
{
	try
	{
		bool bPathMade = false;
		CString csAppPath, csUserPath;
		TCHAR szPath[MAX_PATH] = {0};
		LPVOID posUserName = NULL;
		LPTSTR strUserName = NULL;

		m_csArrSpyLocation.RemoveAll();
		LoadAvailableUsers();

		SHGetFolderPath(0, CSIDL_APPDATA, 0, 0, szPath); // get user application data path
		csAppPath = szPath;
		csAppPath.MakeLower();

		posUserName = m_objAvailableUsers.GetFirst();
		while(posUserName)
		{
			strUserName = NULL ;
			m_objAvailableUsers.GetData(posUserName, strUserName);
			if(csAppPath.Find(strUserName) != -1)
			{
				csAppPath.Replace(strUserName, _T(""));
				bPathMade = true;
				break ;
			}

			posUserName = m_objAvailableUsers.GetNext(posUserName);
		}

		if(bPathMade)
		{
			posUserName = m_objAvailableUsers.GetFirst();
			while(posUserName)
			{
				strUserName = NULL ;
				m_objAvailableUsers.GetData(posUserName, strUserName);
				csUserPath = strUserName;
				m_csArrSpyLocation.Add(csUserPath + csAppPath);
				posUserName = m_objAvailableUsers.GetNext(posUserName);
			}
		}

		return bPathMade;
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in CFakeMajorDefenceKit::PreparePathsToSearch"));
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: IsFileInfected
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: check if file is infected
	Author			: Anand Srivastava
	Description		: exe, no ver tab, upx packed, present in app_data of users(unusual loc for exe)
--------------------------------------------------------------------------------------*/
bool CFakeMajorDefenceKit::IsFileInfected(const CString& csFilePath)
{
	try
	{
		HANDLE hFile = NULL;
		bool bInfected = false;
		char SectionName[8] = {0};
		CFileVersionInfo objVerInfo;
		DWORD dwOffset = 0, dwBytesRead = 0, wSectionsCount = 0;

		if(!objVerInfo.DoTheVersionJob(csFilePath, false))
		{
			return false;
		}

		hFile = CreateFile(csFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if(INVALID_HANDLE_VALUE == hFile)
		{
			return false;
		}

		ReadFile(hFile, SectionName, 2, &dwBytesRead, 0);
		if(SectionName[0] != 'M' || SectionName[1] != 'Z')
		{
			CloseHandle(hFile);
			return false;
		}

		SetFilePointer(hFile, 0x3C, 0, FILE_BEGIN);
		ReadFile(hFile, &dwOffset, 4, &dwBytesRead, 0);
		SetFilePointer(hFile, dwOffset, 0, FILE_BEGIN);
		ReadFile(hFile, SectionName, 4, &dwBytesRead, 0);
		if(memcmp(SectionName, "PE\0\0", 4))
		{
			CloseHandle(hFile);
			return false;
		}

		SetFilePointer(hFile, 2, 0, FILE_CURRENT);
		ReadFile(hFile, &wSectionsCount, 2, &dwBytesRead, 0);
		SetFilePointer(hFile, 12, 0, FILE_CURRENT);
		dwOffset = 0;
		ReadFile(hFile, &dwOffset, 2, &dwBytesRead, 0);
		SetFilePointer(hFile, 2, 0, FILE_CURRENT);
		SetFilePointer(hFile, dwOffset, 0, FILE_CURRENT);

		for(WORD wIndex = 0; wIndex < wSectionsCount; wIndex++)
		{
			ReadFile(hFile, SectionName, 8, &dwBytesRead, 0);
			if(!memcmp(SectionName, "UPX", 3))
			{
				bInfected = true;
				break;
			}

			SetFilePointer(hFile, 32, 0, FILE_CURRENT);
		}

		CloseHandle(hFile);
		return bInfected;
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in CFakeMajorDefenceKit::IsFileInfected"));
	}

	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckAndReportInfection
	In Parameters	: void
	Out Parameters	: 
	Purpose			: check registry references and report
	Author			: Anand Srivastava
	Description		: HKU\S-1-5-21-842925246-879983540-839522115-1003\Software\Microsoft\Windows NT\
						CurrentVersion\Winlogon	#@#	Shell	#@#	%DAS.AU.APP DATA%\antispy.exe
--------------------------------------------------------------------------------------*/
void CFakeMajorDefenceKit::CheckAndReportInfection(const CString& csFilePath)
{
	CString csUserKey, csKey, csData;

	SendScanStatusToUI(Special_File, m_ulSpyName, csFilePath);

	for(int iCnt = 0; iCnt < m_arrAllUsers.GetCount(); iCnt++)
	{
		if(IsStopScanningSignaled())
		{
			break;
		}

		csUserKey = m_arrAllUsers.GetAt(iCnt);
		csData = BLANKSTRING;
		csKey = csUserKey + BACK_SLASH + WINLOGON_REG_KEY;

		m_objReg.Get(csKey, _T("Shell"), csData, HKEY_USERS);
		csData.MakeLower();

		if(-1 != csData.Find(csFilePath))
		{
			SendScanStatusToUI(RegValue_Report, m_ulSpyName, HKEY_USERS, csKey, _T("Shell"), REG_SZ,
								(LPBYTE)(LPCTSTR)csData, csData.GetLength() * sizeof(TCHAR));
			m_csArrFixKey.Add(csKey);
			csData.Replace(csFilePath, BLANKSTRING);
			m_csArrFixValue.Add(csData);
		}
	}
}

/*-------------------------------------------------------------------------------------
	Function		: FixInfection
	In Parameters	: bool
	Out Parameters	: 
	Purpose			: fix registry infection
	Author			: Anand Srivastava
	Description		: HKU\S-1-5-21-842925246-879983540-839522115-1003\Software\Microsoft\Windows NT\
						CurrentVersion\Winlogon	#@#	Shell	#@#	remove infection file name
--------------------------------------------------------------------------------------*/
bool CFakeMajorDefenceKit::FixInfection()
{
	for(int i = 0, iTotal = (int)m_csArrFixKey.GetCount() ; i < iTotal; i++)
	{
		m_objReg.Set(m_csArrFixKey[i], _T("Shell"), m_csArrFixValue[i], HKEY_USERS);
	}

	return true;
}
