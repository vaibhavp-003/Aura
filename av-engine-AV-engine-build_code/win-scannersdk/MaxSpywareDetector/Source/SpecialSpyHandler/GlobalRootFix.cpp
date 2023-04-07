#include "pch.h"
#include "GlobalRootFix.h"

bool CGlobalRootFix::ScanSplSpy(bool bToDelete, CFileSignatureDb *pFileSigMan)
{
	try
	{
		m_bToDelete = bToDelete;
		GetRegRunEntries();
		FixUSBDrives();
		CheckProgramFilesFolder();
		m_bSplSpyFound = bToDelete ? false : m_bSplSpyFound;
		return ( m_bSplSpyFound ) ;
	}
	catch(...)
	{
		CString csErr;
		csErr.Format(_T("Exception caught in CGlobalRootFix::ScanSplSpy, Error : %d"), GetLastError());
		AddLogEntry(csErr, 0, 0);
	}
	
	return false;
}
void CGlobalRootFix::CheckProgramFilesFolder(void)
{
	TCHAR	szSysdir[MAX_PATH] = {0x00};
	GetSystemDirectory(szSysdir,MAX_PATH);	
	WCHAR *cExtPtr = wcsrchr(szSysdir, ':');
	*cExtPtr = '\0';

	TCHAR szFolder[] = {0x3A, 0x5C, 0x50, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0xA0, 0x46, 0x69, 0x6C, 0x65, 0x73, 0x00};
	_tcscat_s(szSysdir, MAX_PATH, szFolder);
	
	if(FALSE != PathIsDirectory(szSysdir))
	{
		TCHAR szDir2Enum[MAX_PATH] = {0};
		_tcscpy_s(szDir2Enum, MAX_PATH, szSysdir);			
		_tcscat_s(szDir2Enum, MAX_PATH, _T("\\*.*"));

		CFileFind	m_objEnumFile;
		BOOL bFound = m_objEnumFile.FindFile(szDir2Enum);
		int iCnt = 0;
		while(bFound)
		{
			bFound = m_objEnumFile.FindNextFileW();
			if (m_objEnumFile.IsDots())
			{
				continue;
			}

			CString csFileName = m_objEnumFile.GetFileName();
			if(csFileName.CompareNoCase(L"Windows Defender") == 0 || csFileName.CompareNoCase(L"Internet Explorer") == 0)
			{
				OutputDebugString(csFileName);
				iCnt++;
				if(iCnt == 2)
				{
					m_bSplSpyFound = true;
					if(!m_bToDelete)
					{						
						TCHAR szCmd[MAX_PATH] = {0};
						_stprintf_s(szCmd, MAX_PATH, L"/c del \"\\\\.\\%s\\Internet Explorer\\con", szSysdir);
						ShellExecute(0, L"open", L"cmd.exe", szCmd, 0, SW_HIDE);

						_stprintf_s(szCmd, MAX_PATH, L"/c del \"\\\\.\\%s\\Internet Explorer\\lpt1", szSysdir);
						ShellExecute(0, L"open", L"cmd.exe", szCmd, 0, SW_HIDE);

						SendScanStatusToUI(Special_Folder, m_ulSpyName, szSysdir);							
					}
				}
			}
		}
		m_objEnumFile.Close();
	}	
}

void CGlobalRootFix::GetRegRunEntries(void)
{
	HKEY	hKeyRun = NULL;
	DWORD	dwNoofValues = NULL;
	TCHAR	szValueName[MAX_PATH] = {0x00}, szValueData[MAX_PATH] = {0x00};
	DWORD	dwValueNmLen = 0x00;
	DWORD	dwValueType = 0x00;
	DWORD	dwValueDataLen = 0x00;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run",0x00,KEY_READ | KEY_QUERY_VALUE,&hKeyRun) == ERROR_SUCCESS)
	{
		if (RegQueryInfoKey(hKeyRun,NULL,NULL,0x00,NULL,NULL,NULL,&dwNoofValues,NULL,NULL,NULL,NULL) == ERROR_SUCCESS)
		{
			if (dwNoofValues > 0x00)
			{
				for (DWORD i = 0x00; i < dwNoofValues; i++)
				{
					_stprintf_s(szValueName,MAX_PATH,L"");
					_stprintf_s(szValueData,MAX_PATH,L"");
					dwValueNmLen = MAX_PATH;
					dwValueDataLen = MAX_PATH;
					if (RegEnumValue(hKeyRun,i,&szValueName[0x00],&dwValueNmLen,0x00,&dwValueType,(LPBYTE)&szValueData[0x00],&dwValueDataLen) == ERROR_SUCCESS)
					{
						if (dwValueDataLen > 0x00 && dwValueType == REG_SZ && m_dwRegRunEntries < 0x10)
						{
							_tcslwr_s(szValueData,MAX_PATH);
							TCHAR	*pDummy = NULL;
							pDummy = _tcsstr(szValueData,L"\\temp\\");
							if(pDummy != NULL && 0 == _taccess_s(szValueData, 0))
							{
								m_bSplSpyFound = true;
								if(!m_bToDelete)
								{
									SendScanStatusToUI(
										Special_RegVal, 
										m_ulSpyName, 
										HKEY_LOCAL_MACHINE , 
										L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run", 
										szValueName,
										REG_SZ,
										(LPBYTE)szValueData,
										_tcslen(szValueData));

									SendScanStatusToUI(Special_File, m_ulSpyName, szValueData);							
								}
								else
								{
									MoveFileEx(szValueData, NULL, MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING);
								}
							}
						}
					}
				}
			}
		}
		RegCloseKey(hKeyRun);
		hKeyRun = NULL;
	}
	
	hKeyRun = NULL;
	if (RegOpenKeyEx(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",0x00,KEY_READ | KEY_QUERY_VALUE, &hKeyRun) == ERROR_SUCCESS)
	{
		_stprintf_s(szValueData,MAX_PATH,L"");
		dwValueDataLen = MAX_PATH;
		if (RegQueryValueEx(hKeyRun,L"Load",NULL,NULL,(LPBYTE)&szValueData[0x00],(LPDWORD)&dwValueDataLen) == ERROR_SUCCESS)
		{
			_tcslwr_s(szValueData,MAX_PATH);
			TCHAR	*pDummy = NULL;
			pDummy = _tcsstr(szValueData,L"\\temp\\");
			if(pDummy != NULL && 0 == _taccess_s(szValueData, 0))
			{
				m_bSplSpyFound = true;
				if(!m_bToDelete)
				{
					SendScanStatusToUI(
						Special_RegVal, 
						m_ulSpyName, 
						HKEY_CURRENT_USER , 
						L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 
						L"Load",
						REG_SZ,
						(LPBYTE)szValueData,
						_tcslen(szValueData));

					SendScanStatusToUI(Special_File, m_ulSpyName, szValueData);			
				}
				else
				{
					MoveFileEx(szValueData, NULL, MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING);					
				}
			}
		}
		RegCloseKey(hKeyRun);
		hKeyRun = NULL;
	}
}

void CGlobalRootFix::FixUSBDrives()
{
	DWORD	i = 0x00;
	TCHAR	szDriveStrings[MAX_PATH] = {0x00};
	DWORD	dwBuffLen = MAX_PATH;
	TCHAR	*pDummy = NULL;
	TCHAR	szDrive[0x10] = {0x00};

	GetLogicalDriveStrings(dwBuffLen,szDriveStrings);
	pDummy = szDriveStrings;
	while(pDummy)
	{
		_stprintf_s(szDrive,0x10,L"%s",pDummy);
		if (_tcslen(szDrive) == 0x00)
		{
			break;
		}

		if (GetDriveType(szDrive) == DRIVE_REMOVABLE)
		{
			DeleteVirusFile(szDrive);
		}

		pDummy+=(_tcslen(szDriveStrings) + 0x01);
	}

	return;
}

void CGlobalRootFix::ChangeUSBAttrib(LPCTSTR pszDrive)
{
	TCHAR	szSysdir[MAX_PATH] = {0x00};
	GetSystemDirectory(szSysdir,MAX_PATH);	
	
	TCHAR	szFinalCmdLine[MAX_PATH] = {0x00};
	_stprintf_s(szFinalCmdLine,MAX_PATH,L"%s\\attrib.exe -S -H -R /S /D %s*.*",szSysdir,pszDrive); 		

	STARTUPINFOW			siStartupInfo; 
    PROCESS_INFORMATION		piProcessInfo; 

    memset(&siStartupInfo, 0, sizeof(siStartupInfo)); 
    memset(&piProcessInfo, 0, sizeof(piProcessInfo)); 
    siStartupInfo.cb = sizeof(siStartupInfo); 

	siStartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	siStartupInfo.wShowWindow = SW_SHOWDEFAULT;

	CreateProcess(NULL, (WCHAR *)szFinalCmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, L"", NULL, &siStartupInfo, &piProcessInfo);
	Sleep(3000);

	return;
}

void CGlobalRootFix::DeleteVirusFile(LPCTSTR pszDrive)
{
	TCHAR		szPath[MAX_PATH] = {0x00};
	TCHAR		szNewPath[1024] = {0};
	CFileFind	m_objEnumFile;
	BOOL		bFound = FALSE;
	CString		cstrPath;
	bool		bAttChanged = false;
	
	_stprintf_s(szPath,MAX_PATH,L"%s*.*", pszDrive);
	bFound = m_objEnumFile.FindFile(szPath); 
	while(bFound)
	{
		bFound = FALSE;
		bFound = m_objEnumFile.FindNextFileW();
		if (m_objEnumFile.IsDots())
			continue;

		cstrPath = m_objEnumFile.GetFilePath();
		_stprintf_s(szNewPath,1024,_T("%s"),cstrPath.GetBuffer(1024));
		cstrPath.ReleaseBuffer();
		if (_tcsstr(szNewPath,L"\\~$") != NULL)
		{
			m_bSplSpyFound = true;
			if(!m_bToDelete)
			{
				SendScanStatusToUI(Special_File, m_ulSpyName, szNewPath);
			}
			if(!bAttChanged)
			{
				ChangeUSBAttrib(pszDrive);					
				bAttChanged = true;
			}
			if(m_bToDelete)
			{
				DeleteFile(szNewPath);
			}
		}
	}
	m_objEnumFile.Close();

	return;
}
