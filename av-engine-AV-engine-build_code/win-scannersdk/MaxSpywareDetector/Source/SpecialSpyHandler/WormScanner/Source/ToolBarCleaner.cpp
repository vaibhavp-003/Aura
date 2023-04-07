// ToolBarCleanerDlg.cpp : implementation file
//
#include "pch.h"
#include "ToolBarCleaner.h"
#include <io.h>
#include "Shlwapi.h"
#include "ExecuteProcess.h"
#include "OptionTabFunctions.h"
#include "CPUInfo.h"

void CToolBarCleaner::ExcludeCachePaths()
{
	return;
	/*CRegistry	objRegistry;
	CString		cszLocalPath;*/

	//AddLogEntry(L"--> Test : ExcludeCachePaths Started......");

	//objRegistry.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA_LOCAL"),cszLocalPath,HKEY_LOCAL_MACHINE);

	////AddLogEntry(cszLocalPath);

	//if (cszLocalPath.IsEmpty())
	//{
	//	return;
	//}

//	COptionTabFunctions	objFunc;
	//CString csFolderToExclude;
	//CString csSpywareName = L"Userdefined";
	//DWORD dwSpyID = 0;


	////3 : Internet Explorer
	//CString	cszAppLocalPath;
	//objRegistry.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA"),cszAppLocalPath,HKEY_LOCAL_MACHINE);

	////AddLogEntry(cszAppLocalPath);

	//csFolderToExclude = cszAppLocalPath + _T("\\Microsoft\\Internet Explorer\\UserData");
	//csFolderToExclude.MakeLower();
	//objFunc.DllFunction(ENUM_OA_EXCLUDE, csFolderToExclude, NULL, csSpywareName, dwSpyID, 0);

	/*HINSTANCE hinstDLL;
	typedef bool (*ADDEXCLUDEENTRIESINDB)();
	ADDEXCLUDEENTRIESINDB AddExcludeEntriesDB;
	hinstDLL = ::LoadLibrary((LPCTSTR)BKComDll);
	if (hinstDLL)
	{
		AddExcludeEntriesDB = (ADDEXCLUDEENTRIESINDB)GetProcAddress(hinstDLL, "AddExcludeEntriesinDB");
		if (AddExcludeEntriesDB)
		{
			AddExcludeEntriesDB();
		}
		::FreeLibrary(hinstDLL);
		hinstDLL = NULL;
	}*/

	//AddLogEntry(L"--> Test : ExcludeCachePaths END !!!");

	//Sleep(100);
}
bool CToolBarCleaner::StartToolbarScanning()
{
	ExcludeCachePaths();
	AddLogEntry(L"Toolbar Scanning Started......");
	TCHAR szProgPath[MAX_PATH] = {0};
	
	memset(szProgPath, 0, sizeof(szProgPath));
	GetSystemDirectory(szProgPath, _countof(szProgPath));
	if(szProgPath[0])
	{
		m_csSysPath = szProgPath;
	}
	m_oReg.EnumSubKeys(_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\"),objSubKeyArr, HKEY_LOCAL_MACHINE);
	AddLogEntry(_T("####On Click Start"));
	CCPUInfo objSystem;	
	bIS64Bit = objSystem.isOS64bit();
	m_oReg.SetWow64Key(bIS64Bit);
	FilterINI();
	AddLogEntry(_T("####On Click Stop"));
	AddLogEntry(L"Toolbar Scanning Finished......");
	return true;
}

void CToolBarCleaner::FilterINI()
{
	char m_szFilterFile[MAX_PATH];
	/*memset(m_szFilterFile, 0, MAX_PATH);
	GetModuleFileNameA(0, m_szFilterFile, MAX_PATH);*/
	CString csRegistryName, csFilePath;
	m_oReg.Get(CSystemInfo::m_csProductRegKey,_T("AppFolder"),csFilePath,HKEY_LOCAL_MACHINE);
	csFilePath = csFilePath + _T("Filter.ini");
	//strcpy(m_szFilterFile,csFilePath.GetBuffer());
	sprintf(m_szFilterFile, "%S", csFilePath);
	AddLogEntry(CString(CStringA(m_szFilterFile)));
	if(_access(m_szFilterFile, 0))
	{
		AddLogEntry(L"%s is missing!", CString(CStringA(m_szFilterFile)));
		return;
	}
	//CString csRegistryName, csFilePath(m_szFilterFile);
	int iPathLength = 1024*2;
	AddLogEntry(_T("####UninstallerString Start"));
	m_nRegistryCount = GetPrivateProfileIntA("UninstallerString","Count",0,m_szFilterFile);
	for(int nCount = 1; nCount <= m_nRegistryCount; nCount++ )
	{
		csRegistryName.Format(_T("%d"),nCount);
		GetPrivateProfileString(_T("UninstallerString"), csRegistryName, _T("0"), csRegistryName.GetBuffer(iPathLength), iPathLength, csFilePath);
		//m_csRegistry[nCount] = szRegistryCount;
		csRegistryName.ReleaseBuffer();
		//AddLogEntry(_T("####Name: "));
		//AddLogEntry(csRegistryName);
		UninstallerFile(csRegistryName);
		if(bIS64Bit)
		{
			csRegistryName.Replace(_T("Software"),_T("Software\\Wow6432Node"));
			UninstallerFile(csRegistryName);
			csRegistryName.Replace(_T("SOFTWARE"),_T("Software\\Wow6432Node"));
			UninstallerFile(csRegistryName);
		}
	}
	AddLogEntry(_T("####UninstallerString Stop"));

	AddLogEntry(_T("####UnRegisterDll Start"));
	m_nRegistryCount = GetPrivateProfileIntA("UnRegisterDll","Count",0,m_szFilterFile);
	for(int nCount = 1; nCount <= m_nRegistryCount; nCount++ )
	{
		csRegistryName.Format(_T("%d"),nCount);
		GetPrivateProfileString(_T("UnRegisterDll"), csRegistryName, _T("0"), csRegistryName.GetBuffer(iPathLength), iPathLength, csFilePath);
		csRegistryName.ReleaseBuffer();
		//AddLogEntry(_T("####Name: "));
		//AddLogEntry(csRegistryName);
		UnRegistryDll(csRegistryName);
		if(bIS64Bit)
		{
			csRegistryName.Replace(_T("Software"),_T("Software\\Wow6432Node"));
			UnRegistryDll(csRegistryName);
			csRegistryName.Replace(_T("SOFTWARE"),_T("Software\\Wow6432Node"));
			UnRegistryDll(csRegistryName);
		}
	}
	AddLogEntry(_T("####UnRegisterDll Stop"));

	AddLogEntry(_T("####Registry_Entries_Values Start"));
	m_nRegistryCount = GetPrivateProfileIntA("Registry_Entries_Values","Count",0,m_szFilterFile);
	for(int nCount = 1; nCount <= m_nRegistryCount; nCount++ )
	{
		csRegistryName.Format(_T("%d"),nCount);
		GetPrivateProfileString(_T("Registry_Entries_Values"), csRegistryName, _T("0"), csRegistryName.GetBuffer(iPathLength), iPathLength, csFilePath);
		csRegistryName.ReleaseBuffer();
		//AddLogEntry(_T("####Name: "));
		//AddLogEntry(csRegistryName);
		CheckRegistryValue(csRegistryName);
		if(bIS64Bit)
		{
			csRegistryName.Replace(_T("Software"),_T("Software\\Wow6432Node"));
			CheckRegistryValue(csRegistryName);
			csRegistryName.Replace(_T("SOFTWARE"),_T("Software\\Wow6432Node"));
			CheckRegistryValue(csRegistryName);
		}
	}
	AddLogEntry(_T("####Registry_Entries_Values Stop"));

	AddLogEntry(_T("####Registry_Entries_KEY Start"));
	m_nRegistryCount = GetPrivateProfileIntA("Registry_Entries_KEY","Count",0,m_szFilterFile);
	for(int nCount = 1; nCount <= m_nRegistryCount; nCount++ )
	{
		csRegistryName.Format(_T("%d"),nCount);
		GetPrivateProfileString(_T("Registry_Entries_KEY"), csRegistryName, _T("0"), csRegistryName.GetBuffer(iPathLength), iPathLength, csFilePath);
		csRegistryName.ReleaseBuffer();
		//AddLogEntry(_T("####Name: "));
		//AddLogEntry(csRegistryName);
		DeleteRegistryKey(csRegistryName);
		//AddLogEntry(csRegistryName);
		if(bIS64Bit)
		{
			csRegistryName.Replace(_T("Software\\"),_T("Software\\Wow6432Node\\"));
			DeleteRegistryKey(csRegistryName);
			//AddLogEntry(csRegistryName);
			csRegistryName.Replace(_T("SOFTWARE"),_T("Software\\Wow6432Node"));
			DeleteRegistryKey(csRegistryName);
			//AddLogEntry(csRegistryName);
		}
	}

	AddLogEntry(_T("####DeleteFolderMozilla Start"));
	m_nRegistryCount = GetPrivateProfileIntA("DeleteFolderMozilla","Count",0,m_szFilterFile);
	for(int nCount = 1; nCount <= m_nRegistryCount; nCount++ )
	{
		csRegistryName.Format(_T("%d"),nCount);
		GetPrivateProfileString(_T("DeleteFolderMozilla"), csRegistryName, _T("0"), csRegistryName.GetBuffer(iPathLength), iPathLength, csFilePath);
		csRegistryName.ReleaseBuffer();
		CleanMozilla(csRegistryName);
	}
	AddLogEntry(_T("####DeleteFolderMozilla Stop"));
	m_nRegistryCount = GetPrivateProfileIntA("DeleteFile","Count",0,m_szFilterFile);
	for(int nCount = 1; nCount <= m_nRegistryCount; nCount++ )
	{
		csRegistryName.Format(_T("%d"),nCount);
		GetPrivateProfileString(_T("DeleteFile"), csRegistryName, _T("0"), csRegistryName.GetBuffer(iPathLength), iPathLength, csFilePath);
		csRegistryName.ReleaseBuffer();
		//AddLogEntry(csRegistryName);
		ReplaceTags(csRegistryName, false);

		//DeleteFolder(csRegistryName, false);
	}
	AddLogEntry(_T("####DeleteFolder"));
	m_nRegistryCount = GetPrivateProfileIntA("DeleteFolder","Count",0,m_szFilterFile);
	for(int nCount = 1; nCount <= m_nRegistryCount; nCount++ )
	{
		csRegistryName.Format(_T("%d"),nCount);
		GetPrivateProfileString(_T("DeleteFolder"), csRegistryName, _T("0"), csRegistryName.GetBuffer(iPathLength), iPathLength, csFilePath);
		csRegistryName.ReleaseBuffer();
		ReplaceTags(csRegistryName, true);
		//AddLogEntry(csRegistryName);
		///DeleteFolder(csRegistryName, true);
	}
}


int CToolBarCleaner::FindHIVE(CString &csMainKey)
{
	int iPos = csMainKey.Find(_T("###HKU"));
	if(iPos>1)
	{
		csMainKey= csMainKey.Left(iPos);
		return 1;
	}
	iPos= csMainKey.Find(_T("###HKLM"));
	if(iPos>1)
	{
		csMainKey= csMainKey.Left(iPos);
		return 2;
	}
	else
		return 3;

}
void CToolBarCleaner::DeleteRegistryKey(CString csRemovePath)
{
	int iKeyType = FindHIVE(csRemovePath);
	bool bReturn= false;
	if(iKeyType==1)
	{
		CString csRemovePath1;
		for(int i = 0; i< objSubKeyArr.GetCount(); i++)
		{
			if(objSubKeyArr.GetAt(i).GetLength()>10)
			{
				csRemovePath1 = objSubKeyArr.GetAt(i)+_T("\\")+csRemovePath;
				//AddLogEntry(_T("DeleteRegistryKey: ")+csRemovePath1);
				bReturn = m_oReg.DeleteRegKey(HKEY_USERS, csRemovePath1);
			}
		}
	}
	else if(iKeyType == 2)
		bReturn = m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, csRemovePath);
	else
	{
		m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, csRemovePath);
		CString csRemovePath1;
		for(int i = 0; i< objSubKeyArr.GetCount(); i++)
		{
			if(objSubKeyArr.GetAt(i).GetLength()>10)
			{
				csRemovePath1 = objSubKeyArr.GetAt(i)+_T("\\")+csRemovePath;
				//AddLogEntry(_T("DeleteRegistryKey: ")+csRemovePath1);
				bReturn = m_oReg.DeleteRegKey(HKEY_USERS, csRemovePath1);
			}
		}
	}
	//if(bReturn)
		//AddLogEntry(_T("Deleted"));
}

void CToolBarCleaner::CheckRegistryValue(CString csRemovePath)
{
	int iKeyType = FindHIVE(csRemovePath);
	
	int iPos = csRemovePath.ReverseFind('\\');
	CString csKeyValue = csRemovePath.Mid(iPos+1);
	csRemovePath = csRemovePath.Left(iPos);
	CString csRemovePath1;

	if(iKeyType==1)
	{
		for(int i = 0; i< objSubKeyArr.GetCount(); i++)
		{
			if(objSubKeyArr.GetAt(i).GetLength()>10)
			{
				csRemovePath1 = objSubKeyArr.GetAt(i)+_T("\\")+csRemovePath;
				//AddLogEntry(_T("CheckRegistryValue: ")+csRemovePath1);
				m_oReg.DeleteValue(csRemovePath1, csKeyValue, HKEY_USERS);
			}
		}
		
	}
	else if(iKeyType == 2)
		m_oReg.DeleteValue(csRemovePath, csKeyValue, HKEY_LOCAL_MACHINE);
	else
	{
		m_oReg.DeleteValue(csRemovePath, csKeyValue, HKEY_LOCAL_MACHINE);
		for(int i = 0; i< objSubKeyArr.GetCount(); i++)
		{
			if(objSubKeyArr.GetAt(i).GetLength()>10)
			{
				csRemovePath1 = objSubKeyArr.GetAt(i)+_T("\\")+csRemovePath;
				//AddLogEntry(_T("CheckRegistryValue: ")+csRemovePath1);
				m_oReg.DeleteValue(csRemovePath1, csKeyValue, HKEY_USERS);
			}
		}
	}
	
}

void CToolBarCleaner::RegValueDataFromDefaultFileDelete(CString csRemovePath)
{
	vector<REG_VALUE_DATA> vecRegValues;
	int iKeyType = FindHIVE(csRemovePath);
	if(iKeyType==1)
	{
		CString csRemovePath1;
		for(int i = 0; i< objSubKeyArr.GetCount(); i++)
		{
			if(objSubKeyArr.GetAt(i).GetLength()>10)
			{
				csRemovePath1 = objSubKeyArr.GetAt(i)+_T("\\")+csRemovePath;
				if(m_oReg.KeyExists(csRemovePath1,HKEY_USERS))
				{
					//AddLogEntry(_T("CheckRegistryValue: ")+csRemovePath1);
					m_oReg.EnumValues(csRemovePath1,vecRegValues,HKEY_USERS);
					break;
				}
			}
		}
		if(!csRemovePath1.IsEmpty())
		{
			csRemovePath = csRemovePath1;
		}
		
	}
	else if(iKeyType == 2)
		m_oReg.EnumValues(csRemovePath,vecRegValues,HKEY_LOCAL_MACHINE);
	
	CString csPath;
	csPath.Format(_T("%s"),vecRegValues.at(0).bData);
	int iPos = csPath.ReverseFind('\\');
	csPath = csPath.Left(iPos);
	DeleteFolder(csPath, true);
	DeleteRegistryKey(csRemovePath);
}

void CToolBarCleaner::UninstallerFile(CString csRemovePath)
{
	CStringArray Values;
	CStringArray DataValues;
	int iKeyType = FindHIVE(csRemovePath);
	int iPos = csRemovePath.ReverseFind('\\');
	CString csKeyValue = csRemovePath.Mid(iPos+1);
	csRemovePath = csRemovePath.Left(iPos);
	if(iKeyType==1)
	{
		CString csRemovePath1;
		for(int i = 0; i< objSubKeyArr.GetCount(); i++)
		{
			if(objSubKeyArr.GetAt(i).GetLength()>10)
			{
				csRemovePath1 = objSubKeyArr.GetAt(i)+_T("\\")+csRemovePath;
				if(m_oReg.KeyExists(csRemovePath1,HKEY_USERS))
				{
					AddLogEntry(_T("UninstallerFile: ")+csRemovePath1);
					m_oReg.QueryDataValue(csRemovePath1,Values,DataValues, HKEY_USERS); 
					break;
				}
			}
		}
		if(!csRemovePath1.IsEmpty())
		{
			csRemovePath = csRemovePath1;
		}
	}
	else if(iKeyType==2)
		m_oReg.QueryDataValue(csRemovePath,Values,DataValues, HKEY_LOCAL_MACHINE); 
	int iCount = 0;
	while(iCount < Values.GetCount())
	{
		if(Values.ElementAt(iCount).CompareNoCase(csKeyValue)==0)
		{
			TCHAR cCommandLine[MAX_PATH] = {0};
			
			_swprintf(cCommandLine, DataValues.ElementAt(iCount));
			AddLogEntry(cCommandLine);
			/*
			AddLogEntry(_T("Calling UninstallerFile: ")+csRemovePath);
			STARTUPINFO oStartUpInfo = {0};
			PROCESS_INFORMATION oProcessInfo = {0};
			oStartUpInfo.cb = sizeof(oStartUpInfo);
			
			if(!CreateProcess(0, cCommandLine, 0, 0, 0, 0, 0, 0, &oStartUpInfo, &oProcessInfo))
			{
				return;
			}
			*/

			
			/*
			WaitForSingleObject(oProcessInfo.hProcess, INFINITE);
			CloseHandle(oProcessInfo.hProcess);
			CloseHandle(oProcessInfo.hThread);
			*/
			m_oReg.SetWow64Key(bIS64Bit);
			CString		cszNewPath;

			cszNewPath.Format(_T("%s"),cCommandLine);
			cszNewPath.Replace(_T("\""),_T(""));
			AddLogEntry(cszNewPath);
			
			CExecuteProcess objExecuteProcess;
			//objExecuteProcess.StartProcessWithToken(cszNewPath, _T(""), EXPLORE_EXE);*/

			//int i;
			//CString sdsd;
			/*sdsd.Format(_T("Error Try: %d ==> %s "), i,cszNewPath);
			AddLogEntry(sdsd);*/

			//ShellExecute(NULL, _T("runas"), cszNewPath, 0, 0, SW_SHOWNORMAL);
			//i = GetLastError();
			//sdsd.Format(_T("ShellExecute Error Try: %d ==> %s "), i,cszNewPath);
			//AddLogEntry(sdsd);

			//TCHAR		csShortPath[MAX_PATH] = {0x00};
			//GetShortPathNameW(cszNewPath.GetBuffer(),csShortPath,MAX_PATH);
			//cszNewPath.ReleaseBuffer();

			//

			////objExecuteProcess.StartProcessWithToken(csShortPath, _T(""), EXPLORE_EXE);



			//i = GetLastError();
			//sdsd.Format(_T("Error First Try: %d ==> %s "), i,csShortPath);
			//AddLogEntry(sdsd);

			STARTUPINFO oStartUpInfo = {0};
			PROCESS_INFORMATION oProcessInfo = {0};
			oStartUpInfo.cb = sizeof(oStartUpInfo);
		
			if(!CreateProcess(0, cCommandLine, 0, 0, 0, 0, 0, 0, &oStartUpInfo, &oProcessInfo))
			{
				//AddLogEntry(_T("CreateProcess FAILED"));
				ShellExecute(NULL, _T("runas"), cszNewPath, 0, 0, SW_SHOWNORMAL);
				return;
			}
			//AddLogEntry(_T("CreateProcess SUCCESS"));
			//WaitForSingleObject(oProcessInfo.hProcess, INFINITE);
			CloseHandle(oProcessInfo.hProcess);
			CloseHandle(oProcessInfo.hThread);

		/*	objExecuteProcess.StartProcessWithToken( _T(""),csShortPath, EXPLORE_EXE);

			i = GetLastError();
			sdsd.Format(_T("Error Second Try:%d ==> %s "), i,csShortPath);
			AddLogEntry(sdsd);

			objExecuteProcess.StartProcessWithToken( _T(""),cCommandLine, EXPLORE_EXE);

			i = GetLastError();
			sdsd.Format(_T("Error Third Try:%d ==> %s "), i,cCommandLine);
			AddLogEntry(sdsd);*/

		}
		iCount++;
	}
		
}

void CToolBarCleaner::UnRegistryDll(CString csRemovePath)
{
	CString g_csAppPath, csPath;
	vector<REG_VALUE_DATA> vecRegValues;
	int iKeyType = FindHIVE(csRemovePath);
	
	if(iKeyType==1)
	{
		CString csRemovePath1;
		for(int i = 0; i< objSubKeyArr.GetCount(); i++)
		{
			if(objSubKeyArr.GetAt(i).GetLength()>10)
			{
				csRemovePath1 = objSubKeyArr.GetAt(i)+_T("\\")+csRemovePath;
				if(m_oReg.KeyExists(csRemovePath1,HKEY_USERS))
				{
					m_oReg.EnumValues(csRemovePath1,vecRegValues,HKEY_USERS);
					break;
				}
			}
		}
		if(!csRemovePath1.IsEmpty())
		{
			csRemovePath = csRemovePath1;
		}
	}
	else if(iKeyType == 2)
	{
		if(!m_oReg.KeyExists(csRemovePath,HKEY_LOCAL_MACHINE))		
			return;
			m_oReg.EnumValues(csRemovePath,vecRegValues,HKEY_LOCAL_MACHINE);
	}
	if(vecRegValues.empty() == true)
		return;
	csPath.Format(_T("%s"),vecRegValues.at(0).bData);
	
	if(m_csSysPath.IsEmpty())
		return;

	//AddLogEntry(m_csSysPath);
	ExecuteProcess(m_csSysPath + _T("\\regsvr32.exe"), _T("/u /s \"") + csPath + _T("\""), 10);
	int iPos = csRemovePath.ReverseFind('\\');
	csRemovePath = csRemovePath.Left(iPos);
	if(iKeyType==1)
	{
		m_oReg.DeleteRegKey(HKEY_USERS, csRemovePath);
	}
	else if(iKeyType == 2)
	{
		m_oReg.DeleteRegKey(HKEY_LOCAL_MACHINE, csRemovePath);
	}
	DeleteFolder(csPath,false);
	
}
void CToolBarCleaner::DeleteFolder(LPCTSTR szRemovePath, bool bFolderDelete)
{
	if(!bFolderDelete)
	{
		DeleteFile(szRemovePath);
	}
	else
	{
		m_oDirectoryManager.MaxDeleteDirectory(szRemovePath, true);
	}
}

bool CToolBarCleaner::ExecuteProcess(LPCTSTR szCommand, LPCTSTR szArguments, DWORD dwWaitSeconds)
{
	STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
	TCHAR szFullCmdLine[MAX_PATH] = {0};

	if(szCommand && szArguments)
	{
		_stprintf_s(szFullCmdLine, _countof(szFullCmdLine), _T("%s %s"), szCommand, szArguments);
	}
	else if(szCommand)
	{
		_stprintf_s(szFullCmdLine, _countof(szFullCmdLine), _T("%s"), szCommand);
	}
	else if(szArguments)
	{
		_stprintf_s(szFullCmdLine, _countof(szFullCmdLine), _T("%s"), szArguments);
	}
	else
	{
		return false;
	}

    si.cb = sizeof(si);
	si.wShowWindow = SW_HIDE;

	     // Start the child process. 
    if( !CreateProcess( NULL,			// No module name (use command line)
		szFullCmdLine,					// Command line
        NULL,							// Process handle not inheritable
        NULL,							// Thread handle not inheritable
        FALSE,							// Set handle inheritance to FALSE
        CREATE_NO_WINDOW,				// No creation flags
        NULL,							// Use parent's environment block
        NULL,           				// Use parent's starting directory 
        &si,            				// Pointer to STARTUPINFO structure
        &pi )           				// Pointer to PROCESS_INFORMATION structure
    ) 
    {
        return false;
    }

    // Wait until child process exits.

	WaitForSingleObject(pi.hProcess, dwWaitSeconds * 1000);

    // Close process and thread handles. 
    CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return true;
}

void CToolBarCleaner::CleanMozilla(CString csRemovePath)
{
	//AddLogEntry(csRemovePath);
	bool bFolder = false;
	if(csRemovePath.GetAt(csRemovePath.GetLength()-1)=='\\')
	{
		csRemovePath = csRemovePath.Left(csRemovePath.GetLength()-1);
		bFolder = true;
		//AddLogEntry(_T("Folder"));
	}
	//AddLogEntry(csRemovePath);

	//TCHAR szPath[MAX_PATH];
	CString csPath;
	int iCount = 0;
	while(iCount<2)
	{
		CString csTempPath;
		if(iCount==0)
		{
			if (m_oReg.Get(CSystemInfo::m_csProductRegKey, _T("APPDATA"), csTempPath, HKEY_LOCAL_MACHINE))
			{
				if(csTempPath.IsEmpty())
					continue;
				csPath.Format(_T("%s\\Mozilla\\Firefox\\Profiles\\"),csTempPath);
			}
		}
		else
		{
			if (m_oReg.Get(CSystemInfo::m_csProductRegKey, _T("APPDATA_LOCAL"), csTempPath, HKEY_LOCAL_MACHINE))
			{
				if(csTempPath.IsEmpty())
					continue;
				csPath.Format(_T("%s\\Mozilla\\Firefox\\Profiles\\"),csTempPath);
			}
		}
		//AddLogEntry(csPath);
		CString csTemp = csPath+_T("*");
		BOOL bFiles = FALSE;
		CFileFind Finder;
		bFiles = Finder.FindFile(csTemp) ; 
		CFile cfile;

		while(bFiles)
		{
			bFiles = Finder.FindNextFile();
			if ( Finder.IsDots() )
				continue ;

			if ( Finder.IsDirectory() )
			{
				csTemp =csPath + Finder.GetFileName();
				//AddLogEntry(csPath);
				if(::PathFileExists(csPath))
				{
					csTemp+= _T("\\")+csRemovePath;
					//AddLogEntry(csTemp);
					if(::PathFileExists(csTemp))
					{
						DeleteFolder(csTemp, bFolder);
						break;
					}
				}
			}
		}
		Finder.Close() ;
		iCount++;
	}

}
int CToolBarCleaner::ReplaceTags(CString csKey,  bool bDelete)
{
	int iRet = 0;
	CString csPath, csLog;
	TCHAR strPath[ MAX_PATH ];

	if(csKey.Find(_T("%user%"))!=-1)
	{
		m_oReg.Get(CSystemInfo::m_csProductRegKey,_T("USERPROFILE"), csPath, HKEY_LOCAL_MACHINE);
		csKey.Replace(_T("%user%"),csPath);
		DeleteFolder(csKey, bDelete);
		//csLog.Format(_T("user: %s"),);
	}
	else if(csKey.Find(_T("%userapp%"))!=-1)
	{
		CString csLocal = csKey;
		m_oReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA"), csPath, HKEY_LOCAL_MACHINE);

		if(!csPath.IsEmpty())
		{
			csLocal.Replace(_T("%userapp%"),csPath);
			DeleteFolder(csLocal, bDelete);

			m_oReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA_LOCAL"), csPath, HKEY_LOCAL_MACHINE);
			csLocal = csKey;
			csLocal.Replace(_T("%userapp%"),csPath);
			DeleteFolder(csLocal, bDelete);

			int iPos = csPath.ReverseFind(_T('\\'));
			if(iPos ==-1)
				return false;
			CString temp = csPath.Mid(iPos+1);
			if(temp.CompareNoCase(_T("Roaming")) || temp.CompareNoCase(_T("Local")))
			{
				csPath = csPath.Left(iPos+1)+_T("LocalLow");
				csLocal = csKey;
				csLocal.Replace(_T("%userapp%"),csPath);
				DeleteFolder(csLocal, bDelete);
			}
			
		}
	}
	else if(csKey.Find(_T("%alluserapp%"))!=-1)
	{
		SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, strPath);
		csPath = (CString) strPath;
		csKey.Replace(_T("%alluserapp%"),csPath);
		DeleteFolder(csPath, bDelete);
	}
	else if(csKey.Find(_T("%prog%"))!=-1)
	{
		SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, 0, strPath);
		csPath = (CString) strPath;
		csKey.Replace(_T("%prog%"),csPath);
		DeleteFolder(csPath, bDelete);
	}
	else if(csKey.Find(_T("%sysdrive%"))!=-1)
	{
		SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, 0, strPath);
		csPath = (CString) strPath;
		csPath= csPath.Left(csPath.ReverseFind('\\'));
		csKey.Replace(_T("%sysdrive%"),csPath);
		DeleteFolder(csPath, bDelete);
	}
	else if(csKey.Find(_T("%windows%"))!=-1)
	{
		SHGetFolderPath(NULL, CSIDL_WINDOWS, NULL, 0, strPath);
		csPath = (CString) strPath;
		csKey.Replace(_T("%windows%"),csPath);
		DeleteFolder(csPath, bDelete);
	}
	else if(csKey.Find(_T("%temp%"))!=-1)
	{
		m_oReg.Get(CSystemInfo::m_csProductRegKey,_T("TempFolderPath"), csPath, HKEY_LOCAL_MACHINE);
		csKey.Replace(_T("%temp%\\"),csPath);
		DeleteFolder(csPath, bDelete);
	}
	else if(csKey.Find(_T("%startupProgram%"))!=-1)
	{
		SHGetFolderPath(NULL, CSIDL_COMMON_PROGRAMS, NULL, 0, strPath);
		csPath = (CString) strPath;
		CString csLocal = csKey;
		csLocal.Replace(_T("%startupProgram%"),csPath);
		DeleteFolder(csLocal, bDelete);
		m_oReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA"), csPath, HKEY_LOCAL_MACHINE);

		if(!csPath.IsEmpty())
		{
			csLocal = csKey;
			csLocal.Replace(_T("%startupProgram%"),csPath);
			DeleteFolder(csLocal, bDelete);

			m_oReg.Get(CSystemInfo::m_csProductRegKey,_T("APPDATA_LOCAL"), csPath, HKEY_LOCAL_MACHINE);
			csLocal = csKey;
			csLocal.Replace(_T("%startupProgram%"),csPath);
			DeleteFolder(csLocal, bDelete);

			int iPos = csPath.ReverseFind(_T('\\'));
			if(iPos ==-1)
				return false;
			CString temp = csPath.Mid(iPos+1);
			if(temp.CompareNoCase(_T("Roaming")) || temp.CompareNoCase(_T("Local")))
			{
				csPath = csPath.Left(iPos+1)+_T("LocalLow");
				csLocal = csKey;
				csLocal.Replace(_T("%startupProgram%"),csPath);
				DeleteFolder(csLocal, bDelete);
			}
		}
	}
	return iRet;
	
}