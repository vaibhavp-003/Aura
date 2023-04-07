#include "pch.h"
#include "MaxRansomMonitor.h"
#include "ActiveProtection.h"
#include "Psapi.h"
#include "EnumProcess.h"

CMaxRansomMonitor::CMaxRansomMonitor(void)
{
	m_csINIFileName = L"";
	m_pFileSig = NULL;
	m_bEnumeratingProcs = FALSE;
	m_pFileSig = new CFileSig;
	m_iWhiteDBStatus = 0;
	m_bSearchInprogress = FALSE;
	m_pWhiteDB = NULL;

	CRegistry objReg;
	DWORD dw = 0;
	theApp.m_bRanRegValue = FALSE;
	objReg.Get(CSystemInfo::m_csProductRegKey, _T("CryptMonitor"), dw, HKEY_LOCAL_MACHINE);
	if(dw)
	{
		theApp.m_bRanRegValue = TRUE;
	}
	m_pRansWatcher = NULL;
}

CMaxRansomMonitor::~CMaxRansomMonitor(void)
{
}

bool CMaxRansomMonitor::Check4IgnoreDigiSig(CString csProcPath)
{
	bool		bFound = false;
	CString		csDummyName;

	if (csProcPath.Find(L":\\windows\\splwow64.exe") != -1 || csProcPath.Find(L"\\mingw\\") != -1)
	{
		return true;
	}

	if (m_csIgnoreDigiSig.GetCount() == 0x00)
	{
		return bFound;
	}

	int		iCnt = m_csIgnoreDigiSig.GetCount();
	for (int i = 0x00; i < iCnt; i++)
	{
		csDummyName = m_csIgnoreDigiSig.GetAt(i);
		if ((csDummyName.Find(csProcPath) != -1) && (csDummyName.GetLength() == csProcPath.GetLength()))
		{
			bFound = true;
			break;
		}
	}

	return bFound;
}

bool CMaxRansomMonitor::CheckExcludeMonitors(CString csProcPath,CString csAccessFile)
{
	bool	bReturn =  false;
	if (csProcPath.IsEmpty() || csAccessFile.IsEmpty())
	{
		return bReturn;
	}

	if (csProcPath.Find(L"vscode") != -1 || csAccessFile.Find(L"vscode") != -1)
	{
		return true;	
	}

	if (csProcPath.Find(L"program files") != -1 && csAccessFile.Find(L"desktop") != -1)
	{
		return true;
	}

	CString csOwnFolder;
	csOwnFolder.Format(_T("\\%s\\"), CSystemInfo::m_csInstallProdName);
	csOwnFolder.MakeLower();
	if (csProcPath.Find(csOwnFolder) != -1 || csAccessFile.Find(csOwnFolder) != -1)
	{
		return true;
	}

	if (csProcPath.Find(L"\\ld.exe") != -1 || csProcPath.Find(L"\\powershell.exe") != -1 || csProcPath.Find(L"\\searchprotocolhost.exe") != -1) //Comment : Added powershell for L3 Performance
	{
		return true;
	}

	return bReturn;
}

bool CMaxRansomMonitor::TerminateAllSameProc(CString csPeSig)
{
	bool			bRet = false;
	CEnumProcess	objMaxEnmProc;
	CString			csLogLine;

	if (csPeSig.IsEmpty())
	{
		return bRet;
	}

	if (m_bEnumeratingProcs == TRUE)
	{
		return bRet;
	}

	m_bEnumeratingProcs = TRUE;

	DWORD aProcesses[1024], cbNeeded = 0x00, cProcesses = 0x00;
    unsigned int i;

    if (!EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
    {
		m_bEnumeratingProcs = FALSE;
        return bRet;
    }

	 cProcesses = cbNeeded / sizeof(DWORD);

	//for (int i = 100; i < 0x10000; i+=4)
	for (int  i = 0; i < cProcesses; i++ )
	{
		DWORD	dwPId = aProcesses[i];
		TCHAR	szFilePath[1024] = {0x00};
		ULONG64 ulSignature = 0;
		CString	csDummySig;

		GetProcessNameByPidEx(dwPId,&szFilePath[0x00]);
		if (_tcslen(szFilePath) > 0x00)
		{
			if(m_pFileSig == NULL)
			{
				m_pFileSig = new CFileSig;
			}
			if(m_pFileSig && SIG_STATUS_PE_SUCCESS == m_pFileSig->CreateSignature(&szFilePath[0x00], ulSignature))
			{
				csDummySig.Format(_T("%016I64X"), ulSignature);
				if (csPeSig == csDummySig)
				{
					objMaxEnmProc.KillProcess(dwPId);
				}
			}
		}
	}

	m_bEnumeratingProcs = FALSE;

	return bRet;
}

BOOL CMaxRansomMonitor::CheckforRansomware(LPCTSTR pszFilePath,LPCTSTR pszProcPath,LPCTSTR pszReserve,DWORD dwCallType, DWORD dwProcID ,DWORD dwReplicationType)
{
	BOOL		bAllowEntry = TRUE;
	CString		csProcPath, csFilePath, csExtension;

	CString		csLogLine;

	if (theApp.m_bRanRegValue == FALSE)
	{
		return bAllowEntry;
	}

	if (m_pRansWatcher == NULL)
	{
		m_pRansWatcher = new CMaxRansBehavMngr;
	}

	csProcPath.Format(L"%s",pszProcPath);
	csFilePath.Format(L"%s",pszFilePath);
	csExtension.Format(L"%s",pszReserve);

	if ((csFilePath.Find(L"\\!-")  == -1) && (csFilePath.Find(L"\\~!-")  == -1) && (csFilePath.Find(L"\\desktop")  == -1) && (csFilePath.Find(L"\\!-scpgt")  == -1) &&
		(csFilePath.Find(L"\\documents")  == -1) && (csFilePath.Find(L"\\pictures")  == -1) && (csFilePath.Find(L"\\music")  == -1) && (csFilePath.Find(L"\\videos")  == -1) && (csFilePath.Find(L"\\systemid\\") == -1))
	{
		return bAllowEntry;
	}

	if (csFilePath.Find(L"\\desktop.ini") != -1 || csFilePath.Find(L".lnk") != -1)
	{
		return bAllowEntry;
	}

	theApp.m_objMaxWhiteListMgr.ManageShortPath(csProcPath,csFilePath);

	if (CheckExcludeMonitors(csProcPath,csFilePath))
	{
		return bAllowEntry;
	}

	if (Check4IgnoreDigiSig(csProcPath) == false)
	{
		CString		csPESigWht(L"");
		if (theApp.m_objMaxWhiteListMgr.SearchDBForWhite(csProcPath) == MAX_WHITELIST_ALLOW)
		{
			bAllowEntry = TRUE;
		}
		else if (IsFilePresentInBlockINI(csProcPath) == true)
		{
			bAllowEntry = FALSE;
			CEnumProcess	objEnumProc;
			DWORD dwProcID = 0x00;
			dwProcID = objEnumProc.GetProcessIDByName(csProcPath);
			if (dwProcID > 100)
			{
				objEnumProc.KillProcess(dwProcID);
			}
			bAllowEntry = FALSE;
		}
		else if (theApp.m_objMaxWhiteListMgr.CheckAccessedFile(csFilePath,csProcPath) == true)
		{
			bAllowEntry = TRUE;
		}
		else if(theApp.m_objMaxWhiteListMgr.SearchINBlackDB(csProcPath,true) == MAX_WHITELIST_BLOCK)
		{
			bAllowEntry = FALSE;
			//m_objRansWatcher.TerminateSusProcess(csProcPath);
			m_pRansWatcher->TerminateSusProcess(csProcPath);
		}
		else //if(m_objMaxWhiteListMgr.SearchDBExt(csAccessed_1) == MAX_WHITELIST_BLOCK)
		{
			if (Check4IgnoreDigiSig(csProcPath) == false)
			{
				if (m_pRansWatcher->IsBadDigiCertFound(csProcPath) == true)
				{

					bAllowEntry = FALSE;
					//CString csTitle = _T("File Blocked (File Monitor)");
					if(theApp.m_objMaxWhiteListMgr.SearchINBlackDB(csProcPath) == MAX_WHITELIST_NEWBLOCK)
					{
						/*
						CRegistry objReg;
						DWORD dw = 0;
						objReg.Get(CSystemInfo::m_csActMonRegKey, SHOWPROCPOPUP, dw, HKEY_LOCAL_MACHINE);
						if(dw)
						{
							DisplayNotification( csTitle + ACTMON_DATA_SEPERATOR +csParentProcessName);
						}
						*/
					}
					m_pRansWatcher->TerminateSusProcess(csProcPath);
				}
				else
				{
					bool				bFound = false;
					bool				bLegitimateProcess = false;

					bFound = m_pRansWatcher->CheckValidDigiSig(csProcPath);
					if (bFound == false)
					{

						int		iSusFound = 0x00;
						iSusFound = m_pRansWatcher->IsSuspeciousBehavior(csProcPath,csFilePath);
						if (iSusFound > 0x01)
						{
							m_pRansWatcher->TerminateSusProcess(csProcPath);

							bAllowEntry = FALSE;
							//CString csTitle = _T("File Blocked (File Monitor)");
							//DisplayNotification( csTitle + ACTMON_DATA_SEPERATOR +csParentProcessName);
						}
						else
						{
							bLegitimateProcess = m_pRansWatcher->IsLegitimateWindowsProcess(csProcPath);

							if (iSusFound == 0x01 && bLegitimateProcess == false)
							{

								if(IsWhiteProcess(csProcPath,csPESigWht))
								{
									m_csIgnoreDigiSig.Add(csProcPath);
									return bAllowEntry;
								}

								Check4RandomPattern(csProcPath,csPESigWht);
								TerminateAllSameProc(csPESigWht);
								CollectRansomFile(csFilePath, csProcPath);

								bAllowEntry = FALSE;
								//CString csTitle = _T("File Blocked (File Monitor)");
								if(theApp.m_objMaxWhiteListMgr.SearchINBlackDB(csProcPath) == MAX_WHITELIST_NEWBLOCK)
								{
									/*
									CRegistry objReg;
									DWORD dw = 0;
									objReg.Get(CSystemInfo::m_csActMonRegKey, SHOWPROCPOPUP, dw, HKEY_LOCAL_MACHINE);
									if(dw)
									{
										DisplayNotification( csTitle + ACTMON_DATA_SEPERATOR +csParentProcessName);
									}
									*/
								}
							}
						}
					}
					else
					{
						m_csIgnoreDigiSig.Add(csProcPath);
					}
				}
			}
		}
	}

	return bAllowEntry;
}

bool CMaxRansomMonitor::IsFilePresentInBlockINI(CString csFilePathName)
{
	bool bFound = false;
	if(m_pFileSig == NULL)
	{
		m_pFileSig = new CFileSig;
	}
	if(m_csINIFileName.IsEmpty())
	{
		m_csINIFileName = CSystemInfo::m_strAppPath + _T("Setting\\InstantScan.ini");
	}
	TCHAR szSigPlusFilePath[MAX_PATH] = {0};
	if(_waccess(csFilePathName,0) != 0)
	{
		return bFound;
	}
	else
	{
		UINT iCount = 0;
		TCHAR szCount[20] = {0};
		ULONG64 ulSignature = 0;
		
		if(m_pFileSig && SIG_STATUS_PE_SUCCESS == m_pFileSig->CreateSignature(csFilePathName, ulSignature))
		{
			if(_tcslen(csFilePathName) + 1 < _countof(szSigPlusFilePath))
			{
				iCount = GetPrivateProfileInt(_T("Signature"), _T("Count"), 0, m_csINIFileName);
				///
				int iCtr=1;
				for(iCtr=1; iCtr <= iCount; iCtr++ )
				{
					WCHAR lpstrFileToScan[MAX_PATH] = {0};
					CString csEntry;
					csEntry.Format(_T("%d"), iCtr);
					GetPrivateProfileString(_T("Signature"), csEntry, 0, lpstrFileToScan, MAX_PATH, m_csINIFileName);
					//_tcslwr_s(lpstrFileToScan);
					CString csFilePath(lpstrFileToScan);
					TCHAR szSig[MAX_PATH] = {0};
					_stprintf_s(szSig, _countof(szSig), _T("%016I64X*"), ulSignature);
					
					if(csFilePath.Find(szSig) != -1)
					{
						bFound = true;
						break;
					}
				}
			}
		}
	}
	return bFound;
}

bool CMaxRansomMonitor::CollectRansomFile(CString csFileDataPath, CString csParentPath)
{
	//Threatcommunity removed
	/*CString csOwnFolder, csOwnFolderx86;
	csOwnFolder.Format(_T("\\program files\\%s\\filedata"), CSystemInfo::m_csInstallProdName);
	csOwnFolder.MakeLower();
	
	if((csFileDataPath.Find(csOwnFolder) != -1)
		|| (csFileDataPath.Find(_T("\\!-")) != -1)
		|| (csFileDataPath.Find(_T("\\~!-")) != -1))
	{

		CString	csRansomFileBackup;
		int iPos = csFileDataPath.ReverseFind('\\');
		if(iPos != -1)
		{
			csRansomFileBackup = csFileDataPath.Left(iPos);
			if (csRansomFileBackup.GetLength() > 0x04)
			{
				CString csZipPath = CSystemInfo::m_strAppPath + THREAT_COMMUNITY_FOLDER +_T("\\rans_ScapeData.zip");

				m_obj7zDLL.Max7zArchive(csZipPath,csRansomFileBackup,_T("a@u$ecD!"));
				return true;
			}
		}
	}*/
	return false;
}

bool CMaxRansomMonitor::IsWhiteProcess(CString csProcPath,CString &csPESig)
{
	bool	bFound = false;
	TCHAR	szLogLine[1024] = {0x00};

	if (_tcsstr(csProcPath,L"\\cmd.exe") != NULL || _tcsstr(csProcPath,L"\\wscript.exe") != NULL || _tcsstr(csProcPath,L"\\rundll32.exe") != NULL || _tcsstr(csProcPath,L"\\powershell.exe") != NULL || _tcsstr(csProcPath,L"\\msmpeng.exe") != NULL)
	{
		return bFound; 
	}

	
	if(m_pFileSig == NULL)
	{
		m_pFileSig = new CFileSig;
	}

	ULONG64 ulSignature = 0;
	ULONG ulThreatID = 0;

	if(m_pFileSig && SIG_STATUS_PE_SUCCESS == m_pFileSig->CreateSignature(csProcPath, ulSignature))
	{
		TCHAR szSig[MAX_PATH] = {0};
		_stprintf_s(szSig, _countof(szSig), _T("%016I64X"), ulSignature);	

		
		csPESig.Format(L"%s",szSig);

		//Comment Due To Crash Issue
		if (m_pWhiteDB == NULL)
		{
			m_pWhiteDB = new CWhiteSigDBManager;
		}

		if (!m_pWhiteDB)
		{
			return bFound; 
		}

		if (m_iWhiteDBStatus != 0x2)
		{
			LoadWhiteDB();
		}

		if (m_iWhiteDBStatus != 0x2)
		{
			return bFound; 
		}

		m_bSearchInprogress = TRUE;
		if(m_pWhiteDB->SearchSig(&ulSignature, &ulThreatID))
		{
			bFound = true;
		}
		m_bSearchInprogress = FALSE;
	}
	
	return bFound;

}

void CMaxRansomMonitor::GetProcessNameByPidEx(ULONG uPid, TCHAR * strFinal)
{
	char pname_buf[MAX_PATH] = {0};
	HANDLE h_process = NULL;
	HMODULE hMods[1024] = {0};
	TCHAR strLogLine[MAX_PATH] = {0};
	ULONG n;

	if (strFinal == NULL)
	{
		return;
	}

	h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, uPid);
	
	if (h_process)
	{
		HMODULE hMod;
        DWORD	cbNeeded = 0x00;
		BOOL	bResult = FALSE;
#ifdef WIN64
		//bResult = EnumProcessModules( h_process, &hMod, sizeof(hMod),&cbNeeded,LIST_MODULES_ALL);
		bResult = EnumProcessModules( h_process, &hMod, sizeof(hMod),&cbNeeded);
#else
		bResult = EnumProcessModules( h_process, &hMod, sizeof(hMod),&cbNeeded);
#endif        
		if (bResult)
        {
			TCHAR szProcessName[1024] = TEXT("");

            //GetModuleBaseName( h_process, hMod, szProcessName, sizeof(szProcessName)/sizeof(TCHAR) );
			GetModuleFileNameExW(h_process,hMod,szProcessName,sizeof(szProcessName)/sizeof(TCHAR) );
			if (_tcslen(szProcessName) > 0x00 && strFinal != NULL)
			{
				_tcscpy(strFinal,szProcessName);
			}
        }
	}

	return;
}

bool CMaxRansomMonitor::Check4RandomPattern(CString csProcPath, CString &csPeSig)
{
	bool		bResult = false;
	CString		csProc2Check = csProcPath;

	csProc2Check.MakeLower();
	MoveToIni(csProcPath,csPeSig);

	//if (csProc2Check.Find(L"\\appdata\\local\\") != -1)
	{
		//if (csProc2Check.Find(L"-") != -1)
		{
			CString	csRansomFileBackup;
			int iPos = csProc2Check.ReverseFind('\\');
			if(iPos != -1)
			{
				csRansomFileBackup = csProc2Check.Mid(iPos+1);
				iPos = csRansomFileBackup.ReverseFind('.');
				if(iPos!= -1)
				{
					csRansomFileBackup = csRansomFileBackup.Left(iPos);
				}

				//Threatcommunity removed
				/*csRansomFileBackup.Format(_T("%s%s\\rans_%s.zip"),CSystemInfo::m_strAppPath,THREAT_COMMUNITY_FOLDER,csRansomFileBackup);
				if (_waccess(csRansomFileBackup,0) != 0)
				{
					m_obj7zDLL.Max7zArchive(csRansomFileBackup,csProcPath,_T("a@u$ecD!"));
				}*/

				/*
				CEnumProcess	objEnumProc;
				DWORD dwProcID = 0x00;
				dwProcID = objEnumProc.GetProcessIDByName(csProc2Check);
				if (dwProcID > 100)
				{
					objEnumProc.KillProcess(dwProcID);
				}
				*/
				m_pRansWatcher->TerminateSusProcess(csProc2Check);
				return true;
				
			}
		}
	}

	return bResult;
}

bool CMaxRansomMonitor::MoveToIni(CString csFilePathName, CString &csPeSig)
{
	bool bRet = false;
	if(m_pFileSig == NULL)
	{
		m_pFileSig = new CFileSig;
	}
	if(m_csINIFileName.IsEmpty())
	{
		m_csINIFileName = CSystemInfo::m_strAppPath + _T("Setting\\InstantScan.ini");
	}
	TCHAR szSigPlusFilePath[MAX_PATH] = {0};
	if(_waccess(csFilePathName,0) != 0)
	{
		return bRet;
	}
	else
	{
		UINT iCount = 0;
		TCHAR szCount[20] = {0};
		ULONG64 ulSignature = 0;
		bool bDup = false;

		if (csPeSig.IsEmpty())
		{
			if(m_pFileSig && SIG_STATUS_PE_SUCCESS == m_pFileSig->CreateSignature(csFilePathName, ulSignature))
			{
				csPeSig.Format(_T("%016I64X"), ulSignature);
			}
		}
		if(!csPeSig.IsEmpty())
		{
			if(_tcslen(csFilePathName) + 1 < _countof(szSigPlusFilePath))
			{
				iCount = GetPrivateProfileInt(_T("Signature"), _T("Count"), 0, m_csINIFileName);
				///
				int iCtr=1;
				for(iCtr=1; iCtr <= iCount; iCtr++ )
				{
					WCHAR lpstrFileToScan[MAX_PATH] = {0};
					CString csEntry;
					csEntry.Format(_T("%d"), iCtr);
					GetPrivateProfileString(_T("Signature"), csEntry, 0, lpstrFileToScan, MAX_PATH, m_csINIFileName);
					//_tcslwr_s(lpstrFileToScan);
					CString csFilePath(lpstrFileToScan);
					TCHAR szSig[MAX_PATH] = {0};
					_stprintf_s(szSig, _countof(szSig), _T("%s*"), csPeSig);
					
					if(csFilePath.Find(szSig) != -1)
					{
						bDup = true;
						break;
					}
				}
				///
				if(bDup == false)
				{
					iCount++;
					_stprintf_s(szSigPlusFilePath, _countof(szSigPlusFilePath), _T("%s*%s"), csPeSig, csFilePathName);				
					_stprintf_s(szCount, _countof(szCount), _T("%u"), iCount);
					WritePrivateProfileString(_T("Signature"), _T("Count"), szCount, m_csINIFileName);
					WritePrivateProfileString(_T("Signature"), szCount, szSigPlusFilePath, m_csINIFileName);
					bRet = true;
				}
			}
		}
	}
	return bRet;
}

bool CMaxRansomMonitor::LoadWhiteDB()
{
	bool bRetStatus = false;

	if (m_iWhiteDBStatus == 1)
	{
		return bRetStatus;
	}
	else
	{
		m_iWhiteDBStatus = 1;
	}
	
	m_pWhiteDB->RemoveAll();

	CString			csDBPath;
	CSystemInfo		objSysInfo;

	CRegistry oReg;
	oReg.Get(objSysInfo.m_csProductRegKey, CURRENT_MAX_DB_VAL, csDBPath, HKEY_LOCAL_MACHINE);

	if(!m_pWhiteDB->Load(csDBPath))
	{
		m_iWhiteDBStatus = 0;
		return bRetStatus;
	}
	m_iWhiteDBStatus = 2;
	
	return true;
}