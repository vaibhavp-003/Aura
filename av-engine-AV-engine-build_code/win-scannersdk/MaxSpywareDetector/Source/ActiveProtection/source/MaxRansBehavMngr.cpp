#include "pch.h"
#include "MaxRansBehavMngr.h"
#include "EnumProcess.h"
#include <strsafe.h>
#include "Registry.h"
#include "SDSystemInfo.h"
#include "MaxMemoryScan.h"
#include "MaxDigitalSigCheck.h"
#include "CPUInfo.h"


CMaxRansBehavMngr::CMaxRansBehavMngr(void)
{
	m_pProcWatchLst = NULL;
	m_dwWatchLstCnt = 0x00;

	SetDebugPrivileges();

	_tcscpy(&m_szProcessPah[0x00],_T(""));
	_tcscpy(&m_szFileAccessed[0x00],_T(""));

	m_hDBScan = NULL;
	m_lpfnLoadDBByPath = NULL;
	m_lpfnScanFile = NULL;

	//AddLogEntry(L"CMaxRansBehavMngr : After Loading DigiSig DB");
	m_bIsWin7 = false;

	CCPUInfo	objCpuInfo;
	DWORD		dwMajorVer = 0;
	DWORD		dwMinorVer = 0;

	objCpuInfo.GetMajorAndMinorOSVersion(dwMajorVer,dwMinorVer);
	if(dwMajorVer == 6 && dwMinorVer ==1)
	{
		m_bIsWin7 = true;
	}

	m_hNTDll = NULL;
	m_hNTDll = LoadLibrary(_T("NtDll.Dll"));
	if(m_hNTDll != NULL)
	{
		NtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS) GetProcAddress(m_hNTDll,"NtQueryInformationProcess");
	}
	_tcscpy(m_szOrgProcPath,L"");
}

CMaxRansBehavMngr::~CMaxRansBehavMngr(void)
{
	if (m_dwWatchLstCnt > 0x00)
	{
		for (int i = (m_dwWatchLstCnt - 1); i >= 0x00; i++)
		{
			free(&m_pProcWatchLst[i]);
			m_pProcWatchLst[i] = NULL;
		}
	}
	free(m_pProcWatchLst);
	m_pProcWatchLst = NULL;
}

bool CMaxRansBehavMngr::IsBadDigiCertFound(LPCTSTR pszProcPath)
{
	bool bFound = false;

	return bFound;

	if (m_lpfnScanFile && pszProcPath != NULL)
	{
		DWORD dwScanResult = m_lpfnScanFile(pszProcPath);
		if (dwScanResult > 0x00)
		{
			bFound = true;	
		}
	}

	return bFound;
}

int CMaxRansBehavMngr::IsSuspeciousBehavior(LPCTSTR pszProcPath, LPCTSTR pszFileAccess)
{
	//bool	bBadFile = false;
	int		iBadFile = 0x00;
	
	if (pszFileAccess == NULL || pszProcPath == NULL)
	{
		return iBadFile;
	}

	_tcscpy(m_szProcessPah,pszProcPath);
	_tcslwr(m_szProcessPah);
	_tcscpy(m_szFileAccessed,pszFileAccess);
	_tcslwr(m_szFileAccessed);

	//TCHAR	szLogLine[1024] = {0x00};
	

	if (_tcslen(m_szProcessPah) == 0x00 || _tcslen(m_szFileAccessed) == 0x00)
	{
		return iBadFile;
	}

	if (memcmp(&m_szProcessPah[0x00],&m_szFileAccessed[0x00],(_tcslen(m_szFileAccessed) * sizeof(TCHAR))) == 0x00)
	{
		return iBadFile;
	}

	if (IsProcInIgnoreDir(m_szProcessPah) == true)
	{
		return iBadFile;
	}

	if (IsFileInIgnoreDir(m_szFileAccessed) == true)
	{
		return iBadFile;
	}

	if(DropperRansomPattern(m_szProcessPah,m_szFileAccessed) == 0x02)
	{
		iBadFile = 0x02;
		return iBadFile;
	}

	if (IsSuspeciousDropper(m_szFileAccessed) == true)
	{
		iBadFile = 0x01;
		return iBadFile;	
	}

	
	if (IsMaliciousProcess(m_szProcessPah) == true)
	{
		iBadFile = 0x01;
		return iBadFile;	
	}

	if (Check4PersonalIDFile(m_szFileAccessed) == true)
	{
		iBadFile = 0x01;
		return iBadFile;
	}

	//if (_tcsstr(m_szProcessPah, L"\\msbuild.exe") != NULL || _tcsstr(m_szProcessPah, L"\\svhost.exe") != NULL || _tcsstr(m_szProcessPah, L"\\explorer.exe") != NULL || _tcsstr(m_szProcessPah, L"\\cvtres.exe") != NULL || _tcsstr(m_szProcessPah, L"\\icacls.exe") != NULL)
	if (_tcsstr(m_szProcessPah, L"\\msbuild.exe") != NULL)// || _tcsstr(m_szProcessPah, L"\\svhost.exe") != NULL || _tcsstr(m_szProcessPah, L"\\explorer.exe") != NULL || _tcsstr(m_szProcessPah, L"\\cvtres.exe") != NULL || _tcsstr(m_szProcessPah, L"\\icacls.exe") != NULL)
	{
		TCHAR szDum[MAX_PATH] = { 0x00 };
		BOOL	bInfection = FALSE;


		CEnumProcess	objEnumProc;
		DWORD			dwProcID = 0x00;

		dwProcID = objEnumProc.GetProcessIDByName(m_szProcessPah);

		CMaxMemoryScan objMaxMemScn;
		bInfection = objMaxMemScn.ScanThreadMemoryEx(dwProcID);
		if (bInfection == TRUE)
		{
			iBadFile = 0x03;
			return iBadFile;
		}
	}

	////Tushar --> Checking for Commandline of Cmd.exe
	//if (_tcsstr(m_szProcessPah, L"\\windows\\") != NULL && _tcsstr(m_szProcessPah, L"\\temp\\") == NULL)
	//{
	//	if (_tcsstr(m_szProcessPah, L"\\cmd.exe") != NULL || _tcsstr(m_szProcessPah, L"\\wscript.exe") != NULL || _tcsstr(m_szProcessPah, L"\\rundll32.exe") != NULL || _tcsstr(m_szProcessPah, L"\\powershell.exe") != NULL || _tcsstr(m_szProcessPah, L"\\vssadmin.exe") != NULL || _tcsstr(m_szProcessPah, L"\\cscript.exe") != NULL)
	//	{
	//		//AddLogEntry(L"TEST : Checking for Process Command Line");
	//		CString		csCmdLineProc;
	//		int			iRetValue = GetCmdLineFilePath(m_szProcessPah, csCmdLineProc);
	//		if (iRetValue == 0x01)
	//		{
	//			_stprintf(m_szOrgProcPath, L"%s", m_szProcessPah);
	//			_stprintf(m_szProcessPah, L"%s", csCmdLineProc);

	//		}
	//		if (iRetValue == 0x02)
	//		{
	//			iBadFile = 0x02;
	//			return iBadFile;
	//		}
	//		//AddLogEntry(L"TEST : After Checking for Process Command Line");
	//	}
	//}
	int	iResult = WATCH_LIST_NOT_FOUND, iRecordPos = -1;

	iResult = IsPresentInWatchArray(iRecordPos);
	if (iResult == WATCH_LIST_IGNORE)
	{
		return iBadFile;
	}

	int iMalStatus = ManageProcessBehavior(iRecordPos);

	if (iMalStatus == 0x05)
	{
		iBadFile = 0x01;
		if (_tcsstr(m_szProcessPah,L"\\explorer.exe") == NULL && (_tcsstr(m_szProcessPah,L"\\regasm.exe") != NULL || _tcsstr(m_szProcessPah,L"\\msbuild.exe") != NULL || _tcsstr(m_szProcessPah,L"\\icacls.exe") != NULL))
		{
			iBadFile = 0x02;
		}
	}

	return iBadFile;
}

int	CMaxRansBehavMngr::IsSameFileAccessed(int iIRecIndex)
{
	int	iResult = 0x00;
	int	iCurIndex = 0x00;


	if (m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount >= MAX_FILE_ACCESSED_CNT)
	{
		if (m_pProcWatchLst[iIRecIndex]->dwCurRepeatCount == 0x00)
		{
			iCurIndex = m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount;
		}
		else
		{
			iCurIndex = m_pProcWatchLst[iIRecIndex]->dwCurRepeatCount;
		}
	}
	else
	{
		iCurIndex = m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount;
	}

	if (iCurIndex > 0x00)
	{
		if (_tcsstr(m_pProcWatchLst[iIRecIndex]->szFileLastAccessed[iCurIndex-1],m_szFileAccessed) != NULL)
		{
			return 0x01;
		}
	}
	return iResult;
}

int	CMaxRansBehavMngr::ManageFileAccessed(int iIRecIndex)
{
	int	iResult = 0x00;
	int	iCurIndex = 0x00;

	if (m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount > 0x00)
	{
		for (iCurIndex=0x00; iCurIndex < m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount; iCurIndex++)
		{
			if (_tcsstr(m_pProcWatchLst[iIRecIndex]->szFileLastAccessed[iCurIndex],m_szFileAccessed) != NULL)
			{
				return 0x00;
			}
		}
	}
	if (m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount >= MAX_FILE_ACCESSED_CNT)
	{
		if (m_pProcWatchLst[iIRecIndex]->dwCurRepeatCount >= MAX_FILE_ACCESSED_CNT)
		{
			m_pProcWatchLst[iIRecIndex]->dwCurRepeatCount = iCurIndex = 0x00;
		}
		else
		{
			iCurIndex = m_pProcWatchLst[iIRecIndex]->dwCurRepeatCount;
			m_pProcWatchLst[iIRecIndex]->dwCurRepeatCount++;
		}
	}
	else
	{
		iCurIndex = m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount;
	}

	_tcscpy(m_pProcWatchLst[iIRecIndex]->szFileLastAccessed[iCurIndex],m_szFileAccessed);
	if (m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount < MAX_FILE_ACCESSED_CNT)
	{
		m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount++;
	}


	return iResult;
}

//0x01 : Info Added, 0x02 : Info Modify, 0x05 : Malicious Hit
int	CMaxRansBehavMngr::ManageProcessBehavior(int iIRecIndex)
{
	int					iRetValue = 0x00,iPos = iIRecIndex;
	TCHAR				szLogLine[1024] = {0x00};
	
	//m_objCriticalSec.Lock();
	if (iPos == -1)
	{
		if (Check4Directory(m_szFileAccessed) == true)
		{
			return 0x00;
		}

		//New Record
		if (m_dwWatchLstCnt == 0x00)
		{
			m_pProcWatchLst = (LPPROCESS_BEHAV_WATCH_ARRAY *)calloc(0x01,sizeof(LPPROCESS_BEHAV_WATCH_ARRAY));
		}
		else
		{
			m_pProcWatchLst = (LPPROCESS_BEHAV_WATCH_ARRAY *)realloc(m_pProcWatchLst,(m_dwWatchLstCnt + 0x01) * sizeof(LPPROCESS_BEHAV_WATCH_ARRAY));
		}

		if (m_pProcWatchLst == NULL)
		{
			return 0x00;
		}

		m_pProcWatchLst[m_dwWatchLstCnt] = (LPPROCESS_BEHAV_WATCH_ARRAY)calloc(0x01,sizeof(PROCESS_BEHAV_WATCH_ARRAY));
		if (m_pProcWatchLst[m_dwWatchLstCnt])
		{
			_tcscpy(m_pProcWatchLst[m_dwWatchLstCnt]->szProcName,m_szProcessPah);
			_tcscpy(m_pProcWatchLst[m_dwWatchLstCnt]->szFileLastAccessed[0x00],m_szFileAccessed);
			_tcscpy(m_pProcWatchLst[m_dwWatchLstCnt]->szOrgProcName,m_szOrgProcPath);
			m_pProcWatchLst[m_dwWatchLstCnt]->bIsIgnored = false;
			m_pProcWatchLst[m_dwWatchLstCnt]->dwDiffFilesCnt = 0x01;
			m_pProcWatchLst[m_dwWatchLstCnt]->dwCurAccessedCount = 0x01;
			m_pProcWatchLst[m_dwWatchLstCnt]->dwCurRepeatCount = 0x00;
			m_pProcWatchLst[m_dwWatchLstCnt]->ctFirstWriteTime = CTime::GetCurrentTime();
			m_dwWatchLstCnt++;
			int iEcnCnt = 0x00;

			iEcnCnt = Check4EncryptedFile(0);

			if (iEcnCnt > 0x00)
			{
				m_pProcWatchLst[0]->dwDiffFilesCnt = iEcnCnt;
				if (m_pProcWatchLst[0]->dwDiffFilesCnt >= 0x04)
				{
					return 0x05; //Ramsomeware
				}

				ManageFileAccessed(0);
				m_pProcWatchLst[0]->bIsIgnored = false;


				iRetValue = 0x02;
			}
			else
			{
				iRetValue = 0x01;
			}
		}
	}
	else
	{
		//Added for Test
		if (IsSameFileAccessed(iPos) == 0x01)
		{
			return 0x00;
		}
		
		if (Check4Directory(m_szFileAccessed) == true)
		{
			return 0x00;
		}

		//if (Check4Directory(m_pProcWatchLst[iPos]->szFileLastAccessed) == false)
		{
			if (FileExists(iPos) == 0x00)
			{
				ManageFileAccessed(iPos);
				m_pProcWatchLst[iPos]->bIsIgnored = false;
				m_pProcWatchLst[iPos]->ctFirstWriteTime = CTime::GetCurrentTime();

				return 0x00;
			}
		}

		int iEcnCnt = 0x00;

		iEcnCnt = Check4EncryptedFile(iPos);

		if (iEcnCnt > 0x00)
		{
			m_pProcWatchLst[iPos]->dwDiffFilesCnt = iEcnCnt;
			if (m_pProcWatchLst[iPos]->dwDiffFilesCnt >= 0x04)
			{
				return 0x05; //Ramsomeware
			}

			ManageFileAccessed(iPos);
			m_pProcWatchLst[iPos]->bIsIgnored = false;
			
			
			iRetValue = 0x02;
		}
		else
		{
			//_tcscpy(m_szFileAccessedOld,m_pProcWatchLst[iPos]->szFileLastAccessed);
			//_tcscpy(m_pProcWatchLst[iPos]->szFileLastAccessed,m_szFileAccessed);
			ManageFileAccessed(iPos);
			m_pProcWatchLst[iPos]->bIsIgnored = false;
			m_pProcWatchLst[iPos]->ctFirstWriteTime = CTime::GetCurrentTime();
			iRetValue = 0x00;

			if (Check4SameExtFiles(iPos) > 0x00)
			{
				return 0x05; //Ramsomeware with Same extension
			}

		}
		
	}
	//m_objCriticalSec.Unlock();
	return iRetValue;
}

int	CMaxRansBehavMngr::FileExists(int iIRecIndex)
{
	int		iRetExists = 0x00;
	//TCHAR	szLogLine[1024] = {0x00};
	
	for (int iIndex = 0x00; iIndex < m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount; iIndex++)
	{
		if (_waccess(m_pProcWatchLst[iIRecIndex]->szFileLastAccessed[iIndex],0) != 0)
		{
			iRetExists++;
		}
		else
		{
			DWORD	dwFSize = 0x00;
			dwFSize = Check4FileSize(m_pProcWatchLst[iIRecIndex]->szFileLastAccessed[iIndex]);

			if (dwFSize == 0)
			{
				iRetExists++;
			}
			else if(CheckFileSizeMisMatch(dwFSize,m_pProcWatchLst[iIRecIndex]->szFileLastAccessed[iIndex]))
			{
			
				iRetExists++;
			}
			else if(Check4DateModified(m_pProcWatchLst[iIRecIndex]->szFileLastAccessed[iIndex]))
			{
				iRetExists++;			
			}
			
		}
	}

	return iRetExists;
}

bool CMaxRansBehavMngr::Check4Directory(LPCTSTR pszFile2Check)
{
	bool	bFound = false;

	if (pszFile2Check == NULL)
	{
		return bFound;
	}

	TCHAR	szFile2Find[1024] = {0x00};
	
	_stprintf(szFile2Find,L"%s",pszFile2Check);
	CFileFind	objFileFinder;

	if (szFile2Find[_tcslen(szFile2Find) - 0x01] == _T('\\'))
	{
		return true;
	}

	BOOL bRetValue = objFileFinder.FindFile(szFile2Find);

	while(bRetValue)
	{
		bRetValue = objFileFinder.FindNextFileW();
		if (objFileFinder.IsDirectory())
		{
			bFound = true;	
			break;
		}
		
		break;
	}
	objFileFinder.Close();

	return bFound;
}
int CMaxRansBehavMngr::Check4EncryptedFile(int	iIndex)
{
	int		intCount = 0x00;
	bool	bFound = 0x00;
	//TCHAR	szLogLine[1024] = {0x00};

	if (iIndex < 0x00)
	{
		return intCount;
	}
	
	for(int i = 0x00; i < m_pProcWatchLst[iIndex]->dwCurAccessedCount; i++)
	{
		if ((_tcsstr(m_pProcWatchLst[iIndex]->szFileLastAccessed[i],L"\\ultraav.lnk") != NULL) ||
			(_tcsstr(m_pProcWatchLst[iIndex]->szFileLastAccessed[i],L":\\!-scpgt") != NULL))
		{
			if (Check4RootEncryptedFile(m_pProcWatchLst[iIndex]->szFileLastAccessed[i]) == true)
			{
				m_pProcWatchLst[iIndex]->dwDiffFilesCnt = 0x05;
				intCount = 0x05;
				return intCount;
			}
			else if (_waccess(m_pProcWatchLst[iIndex]->szFileLastAccessed[i], 0) != 0)
			{
				m_pProcWatchLst[iIndex]->dwDiffFilesCnt = 0x05;
				intCount = 0x05;
				return intCount;
			}
		}
		else if(Check4PersonalIDFile(m_pProcWatchLst[iIndex]->szFileLastAccessed[i]))
		{
			m_pProcWatchLst[iIndex]->dwDiffFilesCnt = 0x05;
			intCount = 0x05;
			return intCount;
		}
		//if (_tcslen(m_pProcWatchLst[iIndex]->szFileLastAccessed[i]) > 0x00)
		//{
			bFound = Check4EncryptedFile(m_pProcWatchLst[iIndex]->szFileLastAccessed[i],iIndex);
			if (bFound)
			{
				//_tcscpy(m_pProcWatchLst[iIndex]->szFileLastAccessed[i],L"");
				intCount++;
			}
		//}
	}

	return intCount;
}

bool CMaxRansBehavMngr::IsFileAlreadyPresentInArray(LPCTSTR pszFile2Check, int iArrayPos)
{
	bool	bReturn = false;

	if (iArrayPos < 0x00 || pszFile2Check == NULL)
	{
		return bReturn;
	}
	
	for(int i = 0x00; i < m_pProcWatchLst[iArrayPos]->dwCurAccessedCount; i++)
	{
		if ((_tcsstr(m_pProcWatchLst[iArrayPos]->szFileLastAccessed[i],pszFile2Check) != NULL) && (_tcslen(m_pProcWatchLst[iArrayPos]->szFileLastAccessed[i])==_tcslen(pszFile2Check)))
		{
			bReturn = true;
			break;
		}
	}

	return bReturn;
}

bool CMaxRansBehavMngr::Check4PersonalIDFile(LPCTSTR pszFile2Check)
{
	bool	bEncryptionFound = false;

	if (_tcsstr(pszFile2Check, L":\\systemid\\personalid.txt") != NULL)
	{
		return true;
	}

	return bEncryptionFound;
}

bool CMaxRansBehavMngr::Check4RootEncryptedFile(LPCTSTR pszFile2Check)
{
	bool	bEncryptionFound = false;

	if (_tcsstr(pszFile2Check, L"\\!-scpgt") == NULL)
	{
		return bEncryptionFound;
	}

	if (_tcsstr(pszFile2Check, L":\\!-scpgt") != NULL) //c:\\!-SCPGT01.PDF
	{
		int	iFileLen = 0x00;
		iFileLen = _tcslen(pszFile2Check);
		//1 : Same Length check for extension
		if (iFileLen == 16 )
		{
			if (_tcsstr(pszFile2Check, L":\\!-scpgt04.pdf") == NULL && _tcsstr(pszFile2Check, L":\\!-scpgt01.doc") == NULL)
			{
				return true;
			}
		}
		else if (iFileLen == 17)
		{
			if (_tcsstr(pszFile2Check, L":\\!-scpgt03.jpeg") == NULL && _tcsstr(pszFile2Check, L":\\!-scpgt02.xlsx") == NULL)
			{
				return true;
			}
		}
		else if (iFileLen > 17) //2 : Different length
		{
			return true;
		}
	}
	
	return bEncryptionFound;
}

bool CMaxRansBehavMngr::Check4EncryptedFile(LPCTSTR pszFile2Check, int iArrayPos = 0x00)
{
	bool	bFound = false;

	if (pszFile2Check == NULL)
	{
		return bFound;
	}


	if (!(_tcsstr(pszFile2Check,L"\\!-") != NULL || _tcsstr(pszFile2Check,L"\\~!-") != NULL || _tcsstr(pszFile2Check,L"\\!-scpgt") != NULL)) 
	{
		if (_waccess(pszFile2Check,0) == 0)
		{
			return bFound;
		}
	}

	TCHAR	szFile2Find[1024] = {0x00};
	CString	csFilePath;

	TCHAR	szOrgFile2Check[1024] = {0x00};
	TCHAR	szFile2Check[1024] = {0x00},szFileNameOnly[MAX_PATH] = {0x00},szFileExtOnly[MAX_PATH] = {0x00},*pTmpName = NULL,*pTmpExt = NULL;

	_tcscpy(szFile2Check,pszFile2Check);
	_tcscpy(szOrgFile2Check,pszFile2Check);

	pTmpName = _tcsrchr(szFile2Check,L'\\');
	if (pTmpName != NULL)
	{
		*pTmpName = L'\0';
		pTmpName++;
	
	 	pTmpExt = _tcsrchr(pTmpName,L'.');
		if (pTmpExt != NULL)
		{
			*pTmpExt = L'\0';
			pTmpExt++;
		}
		_tcscpy(szFileNameOnly,pTmpName);
		if (pTmpExt )
		{
			_stprintf(szFileExtOnly,L".%s",pTmpExt);
			_tcslwr(szFileExtOnly);
		}
		else
		{
			_stprintf(szFileExtOnly,L".");
		}
	}
	else
	{
		return bFound;
	}

	//_stprintf(szFile2Find,L"%s*",pszFile2Check);
	_stprintf(szFile2Find,L"%s\\*%s*.*",szFile2Check,szFileNameOnly);
	CFileFind	objFileFinder;

	BOOL bRetValue = objFileFinder.FindFile(szFile2Find);

	if (bRetValue)
	{
		while(bRetValue)
		{
			bRetValue = objFileFinder.FindNextFileW();
			if (!objFileFinder.IsDirectory() && !objFileFinder.IsDots())
			{
				csFilePath = objFileFinder.GetFilePath();
				csFilePath.MakeLower();

				if ((csFilePath.GetLength() != _tcslen(pszFile2Check)) /*&& (csFilePath.Find(szFileExtOnly) != -1)*/)
				{
					csFilePath = objFileFinder.GetFileName();
					if ((csFilePath.Find(_T(".config")) == -1) && (csFilePath.Find(_T(".prefetch")) == -1))
					{
						bFound = true;
					}
					break;
				}
				else 
				{
					if (csFilePath.Find(szFileExtOnly) == -1)
					{
						csFilePath = objFileFinder.GetFileName();
						if ((csFilePath.Find(_T(".config")) == -1) && (csFilePath.Find(_T(".prefetch")) == -1))
						{
							bFound = true;
						}
						break;

					}
					else
					{
						//Original File is Present with 0kb Size
						if (_tcsstr(szOrgFile2Check,L"\\!-") != NULL || _tcsstr(szOrgFile2Check,L"\\~!-") != NULL || _tcsstr(szOrgFile2Check,L"\\!-scpgt") != NULL) 
						{
							if (_waccess(szOrgFile2Check,0) == 0)
							{
								DWORD	dwFSize = Check4FileSize(szOrgFile2Check);
								if (dwFSize == 0)
								{
									bFound = true;
									break;
								}
								else if(CheckFileSizeMisMatch(dwFSize,szOrgFile2Check))
								{
									bFound = true;
									break;
								}
								else if(Check4DateModified(szOrgFile2Check))
								{
									bFound = true;
									break;
								}
							}
						}
					}	
				}
			}
		}
		objFileFinder.Close();
	}
	else
	{
		if (_waccess(pszFile2Check,0) != 0)
		{
			bFound = true;
		}
	}
	return bFound;
}

bool CMaxRansBehavMngr::Check4DateModified(LPCTSTR pszFile2Check)
{
	bool bDateModified = false;
	TCHAR szFile2Check[MAX_PATH] = {0x00};
	_tcscpy(szFile2Check,pszFile2Check);
	_tcslwr(szFile2Check);

	if (_tcsstr(szFile2Check,L"data") == NULL)
	{
		return bDateModified;
	}
	SYSTEMTIME stUTC, stLocal;
	FILETIME ftCreated, ftModified, ftAccessed;
	TCHAR szFileModifiedDate[MAX_PATH] = {0x00};
	int iRetStatus = GetFileDateTime(szFile2Check,ftCreated, ftModified, ftAccessed);
	
	if(iRetStatus == 1)
	{
		FileTimeToSystemTime(&ftModified, &stUTC);
		SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
		StringCchPrintf(szFileModifiedDate, MAX_PATH, TEXT("%02d/%02d/%d %02d:%02d"),stLocal.wDay, stLocal.wMonth, stLocal.wYear,stLocal.wHour, stLocal.wMinute);	

		TCHAR szDateTime[MAX_PATH] = {0x00};
		CTime ct = CTime::GetCurrentTime();
		_stprintf(szDateTime,L"%s",ct.Format(L"%d/%m/%Y %H:%M"));

		if(_tcscmp(szFileModifiedDate,szDateTime) == NULL)
		{
			return true;
		}

	}

	return bDateModified;

}

int CMaxRansBehavMngr::Check4FileSize(LPCTSTR pszFile2Check)
{
	int	iRetValue = -1;

	FILE	*fp = _wfopen(pszFile2Check,L"rb");
	if (fp == NULL)
	{
		return iRetValue;
	}
	fseek(fp,0x00,SEEK_END);
	iRetValue = ftell(fp);

	fclose(fp);
	fp = NULL;
	
	return iRetValue;
}

//0 : Not Present,1 : Present in Data,2 : Ignore Mark
int CMaxRansBehavMngr::IsPresentInWatchArray(int &iIndex)
{
	int		iValue  = WATCH_LIST_NOT_FOUND;

	if (m_dwWatchLstCnt == 0x00)
	{
		return iValue;
	}
	
	for (int i = 0x00; i < m_dwWatchLstCnt; i++)
	{
		if (m_pProcWatchLst[i]->szProcName)
		{
			if(_tcsstr(m_pProcWatchLst[i]->szProcName,m_szProcessPah) != NULL)
			{
				if (m_pProcWatchLst[i]->bIsIgnored == TRUE)
				{
					return WATCH_LIST_IGNORE;
				}
				else
				{
					iIndex = i;
					return WATCH_LIST_PRESENT;
				}
			}
		}
	}

	return iValue;
}

bool CMaxRansBehavMngr::IsProcInIgnoreDir(LPCTSTR	pszProcPath)
{
	bool	bResult = false;

	//1 : Ignore all the processes running from Program Files or Windows
	/*
	if((_tcsstr(pszProcPath,_T(":\\program files")) != NULL || _tcsstr(pszProcPath,_T(":\\windows\\")) != NULL) && _tcsstr(pszProcPath,_T(":\\windows\\temp\\")) == NULL)
	{
		return true;
	}
	*/

	if(_tcsstr(pszProcPath,_T("\\setuphost.exe")) != NULL)
	{
		return true;
	}

	if(_tcsstr(pszProcPath,_T(":\\program files")) != NULL)
	{
		return true;
	}

	if (_tcsstr(pszProcPath,_T(":\\windows\\")) != NULL)
	{
		TCHAR *pTemp = NULL,*pTemp2 = NULL;

		pTemp = (TCHAR *)_tcsstr(pszProcPath,_T("\\system32\\"));
		if (pTemp != NULL && _tcslen(pTemp) > 10)
		{
			if (_tcsstr(pszProcPath,L"\\system32\\cmd.exe") == NULL && _tcsstr(pszProcPath,L"\\system32\\wscript.exe") == NULL && _tcsstr(pszProcPath,L"\\system32\\rundll32.exe") == NULL || _tcsstr(m_szProcessPah,L"\\powershell.exe") != NULL)
			{
				pTemp+=10;
				if (pTemp)
				{
					pTemp2 = _tcsrchr(pTemp,L'\\');
					if (pTemp2 == NULL)
					{
						return true;
					}
				}
			}
		}
		if (_tcsstr(pszProcPath,_T("\\windows\\explorer.exe")) != NULL || _tcsstr(pszProcPath,_T("\\windows\\notepad.exe")) != NULL )
		{
			return true;
		}
		/*
		if (_tcsstr(pszProcPath,_T("\\explorer.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\smartscreen.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\dashost.exe")) != NULL ||
			_tcsstr(pszProcPath,_T("\\system32\\csrss.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\lsass.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\smsss.exe")) != NULL ||
			_tcsstr(pszProcPath,_T("\\system32\\winlogon.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\services.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\svchost.exe")) != NULL ||
			_tcsstr(pszProcPath,_T("\\system32\\conhost.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\ctfmon.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\runtimebroker.exe")) != NULL ||
			_tcsstr(pszProcPath,_T("\\system32\\searchindexer.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\wininit.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\hkcmd.exe")) != NULL ||
			_tcsstr(pszProcPath,_T("\\system32\\fontdrvhost.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\igfxpers.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\taskhostw.exe")) != NULL ||
			_tcsstr(pszProcPath,_T("\\system32\\sgrmbroker.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\applicationframehost.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\searchui.exee")) != NULL ||
			_tcsstr(pszProcPath,_T("\\notepad.exe")) != NULL || _tcsstr(pszProcPath,_T("\\system32\\notepad.exe")) != NULL)
		{
			return true;
		}
		*/
	}
	
	TCHAR *pTemp = NULL;

	pTemp = _tcsrchr((TCHAR *)pszProcPath,L'.');
	if (pTemp != NULL)
	{
		if (_tcsstr(pTemp,L".tmp") != NULL)
		{
			return true;
		}
	}

	return false;
}


bool CMaxRansBehavMngr::IsFileInIgnoreDir(LPCTSTR pszFilePath)
{
	bool	bResult = false;

	/*
	if (_tcsrchr(pszFilePath,_T('.')) == NULL)
	{
		return TRUE;
	}
	*/
	//1 : To exclude Installer
	if(_tcsstr(pszFilePath,_T("\\temp\\")) != NULL || _tcsstr(pszFilePath,_T("\\roaming\\")) != NULL)
	{
		//if (_tcsstr(pszFilePath,L"\\desktop\\") == NULL)
		{
			return true;
		}
	}
	//2 : To Vliad Application
	if(_tcsstr(pszFilePath,_T(":\\windows")) != NULL)
	{
		return true;
	}

	TCHAR	szTemp[512] = {0x00},*pTemp = NULL;

	_tcscpy(szTemp,m_szProcessPah);
	pTemp = _tcsrchr(szTemp,_T('\\'));
	if (pTemp)
	{
		*pTemp = _T('\0');
	}
	if (_tcsstr(m_szFileAccessed,szTemp ) != NULL && _tcsstr(m_szFileAccessed,L"\\desktop\\") == NULL)
	{
		return true;
	}

	return false;
}


bool CMaxRansBehavMngr::PrintLog(LPCTSTR pszLogLine)
{
	bool	bRetValue = false;

	//if (_tcsstr(pszLogLine,_T("\\0000\\")) != NULL || _tcsstr(pszLogLine,_T("\\AAAA\\")) != NULL)
	{
		//OutputDebugString(pszLogLine);
		//AddLogEntry(pszLogLine);
	}

	return bRetValue;
}

//0 : No Command line found
//1 : Command line Found
//2 : Special Condition for BadRabbit
int CMaxRansBehavMngr::GetCmdLineFilePath(LPCTSTR pszProcPath,CString &csProcCmdLine)
{
	int		iRetValue = 0x00;
	TCHAR	szLogLine[1024] = {0x00};

	CEnumProcess	objEnumProc;
	DWORD			dwProcID = 0x00;
	CString			csCmdLine;

	SetDebugPrivileges();

	dwProcID = objEnumProc.GetProcessIDByName(pszProcPath);

	if (CheckProcessCmdLine(dwProcID,pszProcPath,csCmdLine))
	{
		if (csCmdLine.GetLength() > 0x00)
		{
			csCmdLine.MakeLower();
			csCmdLine.Replace(pszProcPath,L"");
			csCmdLine.Replace(L"/c",L"");

			csCmdLine.Replace(L"\"",L"");
			csCmdLine.Replace(L"-file ",L"");

			csCmdLine.Trim();

			csProcCmdLine.Format(L"%s",csCmdLine);

			iRetValue = 0x01;
		}
	}
  
	if(csCmdLine.Find(L"\\local\\temp\\t9eunk~1.zk,toxnkczjuhcftf9d") != -1 && csCmdLine.Find(L"\\rundll32.exe") != -1)
	{
		iRetValue = 0x02;
	}
	
	//For BadRabbit Ransomware

	if(csCmdLine.Find(L"c:\\windows\\infpub.dat,#1 15") != -1 && csCmdLine.Find(L"\\rundll32.exe") != -1)
	{
		iRetValue = 0x02;
	}

	if(csCmdLine.Find(L"\\local\\temp\\") != -1 && csCmdLine.Find(L".tmp\\") != -1 && csCmdLine.Find(L"\\cmd.exe") != -1 && csCmdLine.Find(L".bat") != -1)
	{
		iRetValue = 0x02;
	}

	if(csCmdLine.Find(L"vssadmin.exe") != -1 && csCmdLine.Find(L"delete shadows /all /quiet") != -1)
	{
		iRetValue = 0x02;
	}

	if (csCmdLine.Find(L"csscript") != -1 && csCmdLine.Find(L":jscript") != -1 && csCmdLine.Find(L".tmp\\") != -1 && csCmdLine.Find(L".bat") != -1 && csCmdLine.Find(L"-saveto con") != -1)
	{
		iRetValue = 0x02;
	}

	return iRetValue;
}

BOOL CMaxRansBehavMngr::CheckProcessCmdLine(DWORD dwProcID,LPCTSTR pszExePath,CString &csCmdLine)
{
	BOOL	bRetValue = FALSE;
	DWORD	dwSVCHostPID = 0;
	DWORD	dwSize							= 0;
	DWORD	dwSizeNeeded						= 0;
	DWORD	dwBytesRead						= 0;
	DWORD	dwBufferSize						= 0;
	HANDLE	hHeap							= 0;
	WCHAR	*pwszBuffer						= NULL;
	smPROCESSINFO spi						= {0};
	smPPROCESS_BASIC_INFORMATION pbi		= NULL;

	smPEB peb								= {0};
	smPEB_LDR_DATA peb_ldr					= {0};
	smRTL_USER_PROCESS_PARAMETERS peb_upp	= {0};

	if (dwProcID == 0x00)
	{
		return bRetValue;
	}
	if (pszExePath == NULL)
	{
		return bRetValue;
	}

	dwSVCHostPID = dwProcID;
	if (dwSVCHostPID == 0x00)
	{
		return bRetValue;
	}

	ZeroMemory(&spi, sizeof(spi));
	ZeroMemory(&peb, sizeof(peb));
	ZeroMemory(&peb_ldr, sizeof(peb_ldr));
	ZeroMemory(&peb_upp, sizeof(peb_upp));

	HANDLE	hCurProc = NULL;
	hCurProc = OpenProcess( PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,FALSE, dwSVCHostPID);
	if (hCurProc == NULL)
	{
		return FALSE;
	}

	hHeap = GetProcessHeap();
	dwSize = sizeof(smPROCESS_BASIC_INFORMATION);
	pbi = (smPPROCESS_BASIC_INFORMATION)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwSize);
	if(!pbi) 
	{
		CloseHandle(hCurProc);
		return FALSE;
	}

	NTSTATUS dwStatus = NtQueryInformationProcess(hCurProc,ProcessBasicInformation,pbi,dwSize,&dwSizeNeeded);
	if(NT_SUCCESS(dwStatus) && dwSize <= dwSizeNeeded)
	{

		if(pbi)
		{
			HeapFree(hHeap, 0, pbi);
		}

		pbi = (smPPROCESS_BASIC_INFORMATION)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwSizeNeeded);
		if(!pbi)
		{
			CloseHandle(hCurProc);
			return FALSE;
		}

		dwStatus = NtQueryInformationProcess(hCurProc,ProcessBasicInformation,pbi,dwSizeNeeded, &dwSizeNeeded);
	}

	// Did we successfully get basic info on process
	if(NT_SUCCESS(dwStatus))
	{
		spi.dwPEBBaseAddress = (DWORD)pbi->PebBaseAddress;
		// Read Process Environment Block (PEB)
		if(pbi->PebBaseAddress)
		{
			if(ReadProcessMemory(hCurProc, pbi->PebBaseAddress, &peb, sizeof(peb), (SIZE_T*)&dwBytesRead))
			{
				// if PEB read, try to read Process Parameters
				dwBytesRead = 0;
				if(ReadProcessMemory(hCurProc,peb.ProcessParameters,&peb_upp,sizeof(smRTL_USER_PROCESS_PARAMETERS),	(SIZE_T*)&dwBytesRead))
				{
					// We got Process Parameters, is CommandLine filled in
					if(peb_upp.CommandLine.Length > 0) 
					{
						pwszBuffer = (WCHAR *)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,peb_upp.CommandLine.Length);
						// If memory was allocated, continue
						if(pwszBuffer)
						{
							memset(pwszBuffer,0x00,peb_upp.CommandLine.Length);
							//peb_upp.CommandLine.Length = _tcslen()
							if(ReadProcessMemory(hCurProc,peb_upp.CommandLine.Buffer,pwszBuffer,peb_upp.CommandLine.Length,(SIZE_T*)&dwBytesRead))
							{
								if(peb_upp.CommandLine.Length >= sizeof(spi.szCmdLine))
								{
									dwBufferSize = sizeof(spi.szCmdLine) - sizeof(TCHAR);
								}
								else
								{
									dwBufferSize = peb_upp.CommandLine.Length;
								}

#if defined(UNICODE) || (_UNICODE)
								StringCbCopyN(spi.szCmdLine, sizeof(spi.szCmdLine),pwszBuffer, dwBufferSize);
#else
								WideCharToMultiByte(CP_ACP, 0, pwszBuffer,(int)(dwBufferSize / sizeof(WCHAR)),spi.szCmdLine, sizeof(spi.szCmdLine),NULL, NULL);
#endif
								if((_tcslen(spi.szCmdLine) > _tcslen(pszExePath)))
								{
									bRetValue = TRUE;
									csCmdLine.Format(L"%s",spi.szCmdLine);
								}

							}
						}
					}
				}
			}
		}
	}

	if (pwszBuffer)
	{
		HeapFree(hHeap, 0, pwszBuffer);
		pwszBuffer = NULL;
	}
	


	if(pbi != NULL)
	{
		HeapFree(hHeap, 0, pbi);
		pbi = NULL;
	}


	CloseHandle(hCurProc);

	return bRetValue;
}

int CMaxRansBehavMngr::SetDebugPrivileges(void)
{
	TOKEN_PRIVILEGES	tp_CurPriv;
	HANDLE				hToken=NULL;

	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken))
	{
		return 1;
	}
	
	tp_CurPriv.PrivilegeCount = 1;
	LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp_CurPriv.Privileges[0].Luid);
	tp_CurPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken,FALSE,&tp_CurPriv,sizeof(TOKEN_PRIVILEGES),0,0);

	CloseHandle(hToken);

	return 0;
}

bool CMaxRansBehavMngr::TerminateSusProcess(LPCTSTR pszProcPath)
{
	bool	bResult = false, bFound = false;

	if (pszProcPath == NULL)
	{
		return bResult; 
	}

	//if (m_dwWatchLstCnt == 0x00)
	{
		CEnumProcess	objEnumProc;
		DWORD			dwProcID = 0x00;
		dwProcID = objEnumProc.GetProcessIDByName(pszProcPath);
		if (dwProcID > 100)
		{
			objEnumProc.KillProcess(dwProcID);
		}
		//return bResult;
	}
	
	int i = 0x00;
	for (i = 0x00; i < m_dwWatchLstCnt; i++)
	{
		if (m_pProcWatchLst[i]->szProcName)
		{
			if(_tcsstr(m_pProcWatchLst[i]->szProcName,m_szProcessPah) != NULL)
			{
				bFound = true;
				break;
			}
		}
	}
	if (bFound)
	{
		CEnumProcess	objEnumProc;
		DWORD			dwProcID = 0x00;

		dwProcID = objEnumProc.GetProcessIDByName(m_pProcWatchLst[i]->szProcName);
		if (dwProcID > 100)
		{
			objEnumProc.KillProcess(dwProcID);
		}
		if (m_pProcWatchLst[i]->szOrgProcName)
		{
			dwProcID = objEnumProc.GetProcessIDByName(m_pProcWatchLst[i]->szOrgProcName);
			if (dwProcID > 100)
			{
				objEnumProc.KillProcess(dwProcID);
			}
		}
	}
	else
	{
		CEnumProcess	objEnumProc;
		DWORD			dwProcID = 0x00;
		dwProcID = objEnumProc.GetProcessIDByName(pszProcPath);
		if (dwProcID > 100)
		{
			objEnumProc.KillProcess(dwProcID);
		}
	}

	return bResult;
}

int CMaxRansBehavMngr::GetFileDateTime(LPCTSTR szFilePath, FILETIME &ftCreated, FILETIME &ftModified, FILETIME &ftAccessed)
{
    HANDLE hFile = CreateFile(szFilePath,
			GENERIC_READ,FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS,
			NULL);

    if(hFile == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
    BOOL bVal = GetFileTime(hFile,&ftCreated,&ftAccessed,&ftModified);

    CloseHandle(hFile);
    if(!bVal)
	{
		return 0;
	}
    return 1;
}



bool CMaxRansBehavMngr::IsLegitimateWindowsProcess(LPCTSTR pszProcPath)
{
	bool bRetStatus = false;
	if (_tcsstr(pszProcPath,L"\\windows\\") != NULL)
	{
		if (_tcsstr(pszProcPath,L"\\cmd.exe") != NULL || _tcsstr(pszProcPath,L"\\wscript.exe") != NULL || _tcsstr(pszProcPath,L"\\rundll32.exe") != NULL || _tcsstr(pszProcPath,L"\\explorer.exe") != NULL)
		{
			bRetStatus = true;
		}
	}
	return bRetStatus;

}

bool CMaxRansBehavMngr::CheckFileSizeMisMatch(DWORD	dwFileSize, const CString csFilePath)
{
	DWORD	dwFileSzFromINI = 0x00;	
	CString csFileName;
	int		iIndex = 0;

	TCHAR	szLogLine[1024] = {0x00};
	
	if (csFilePath.Find(L"!-\\") == -1)
	{
		return false;
	}

	CString csAppPath = CSystemInfo ::m_strAppPath;
	csAppPath += _T("RanFileData");
	CString csINIPath = csAppPath + _T("\\filedata.ini");

	iIndex = csFilePath.ReverseFind(_T('.'));
	csFileName = csFilePath.Mid(iIndex - 6, 6);

	dwFileSzFromINI = GetPrivateProfileInt(L"DataSZ", csFileName, 0,csINIPath);

	TCHAR	szData[MAX_PATH] = {0x00};
	GetPrivateProfileString(L"Data", csFileName,L"",szData,MAX_PATH,csINIPath);
	
	if(dwFileSzFromINI != dwFileSize) //MD5 mismatch, file modified
	{
		return true;
	}
	return false;
}

bool CMaxRansBehavMngr::CheckValidDigiSig(CString csFilePath)
{
	CMaxDigitalSigCheck objMaxDigiSign;
	bool				bFound = false;

	if (csFilePath.Find(L"\\busywin\\") != -1 || csFilePath.Find(L"\\busy21.exe") != -1)
	{
		return true;
	}

	if (csFilePath.Find(L"\\appdata\\roaming\\") != -1 && csFilePath.Find(L"\\lsass.exe") != -1)
	{
		return bFound;
	}

	if (csFilePath.Find(L"\\temp\\") != -1 && csFilePath.Find(L"\\firefox.exe") != -1)
	{
		return bFound;
	}

	if (csFilePath.Find(L"\\system32\\locator.exe") != -1)
	{
		return bFound;
	}

	if (csFilePath.Find(L"\\msbuild.exe") != -1 || csFilePath.Find(L"\\svhost.exe") != -1 || csFilePath.Find(L"\\regasm.exe") != -1 || csFilePath.Find(L"\\msmpeng.exe") != -1 || csFilePath.Find(L"\\cvtres.exe") != -1  || csFilePath.Find(L"\\icacls.exe") != -1/*|| 
		csFilePath.Find(L"\\explorer.exe") != -1  || csFilePath.Find(L"\\SearchFilterHost.exe") != 1 || csFilePath.Find(L"\\SearchIndexer.exe") != 1 ||
		csFilePath.Find(L"\\SearchProtocolHost.exe") != -1 */)
	{
		return bFound;
	}

	if (csFilePath.Find(L"\\windows\\") == -1 && csFilePath.Find(L"\\program file") == -1 && csFilePath.Find(L"\\programdata") == -1)// && csFilePath.Find(L"\\desktop\\") == -1)
	{
		return bFound;
	}

	//bFound = objMaxDigiSign.CheckDigitalSign(csFilePath);
	if (m_bIsWin7 == false)
	{
		bFound = objMaxDigiSign.CheckDigitalSign(csFilePath);
	}

	return bFound;
}

bool CMaxRansBehavMngr::IsSuspeciousDropper(LPCTSTR pszFilePath)
{
	bool	bRetValue = false;
	int		iArrayCnt = 0x00;

	if (_tcsstr(pszFilePath,L"!-\\") == NULL)
	{
		return bRetValue;
	}

	iArrayCnt = _countof(SuspeciousDroppFiles);
	
	if (iArrayCnt > 0x00)
	{
		for (int i = 0x00; i < iArrayCnt; i++)
		{
			if (_tcsstr(pszFilePath,SuspeciousDroppFiles[i]) != NULL)
			{
				return true;
			}
		}
	}

	return bRetValue;
}

bool CMaxRansBehavMngr::IsMaliciousProcess(LPCTSTR pszFilePath)
{
	bool	bRetValue = false;
	int		iArrayCnt = 0x00;

	if (_tcsstr(pszFilePath,L"\\appdata\\local\\temp") == NULL && _tcsstr(pszFilePath,L"\\appdata\\roaming") == NULL)
	{
		return bRetValue;
	}

	iArrayCnt = _countof(MaliciousProcessList);

	if (iArrayCnt > 0x00)
	{
		for (int i = 0x00; i < iArrayCnt; i++)
		{
			if (_tcsstr(pszFilePath,MaliciousProcessList[i]) != NULL)
			{
				return true;
			}
		}
	}

	return bRetValue;
}



bool CMaxRansBehavMngr::IsChapakRansomware()
{
	bool bInfectionFound = false;
	int iTaskSize = 0x00;
	iTaskSize = Check4FileSize(L"C:\\Windows\\System32\\Tasks\\Time Trigger Task");

	if(iTaskSize >= 0)
	{
		DeleteFile(L"C:\\Windows\\System32\\Tasks\\Time Trigger Task");
		bInfectionFound = true;
	}

	CRegistry oReg;
	CString csVal;

	if(oReg.DeleteValue(_T("software\\microsoft\\windows\\currentversion\\run"), _T("DisplayName"), HKEY_CURRENT_USER))
	{
		bInfectionFound = true;
	}
	return bInfectionFound;

}

int CMaxRansBehavMngr::DropperRansomPattern(LPCTSTR pszFilePath, LPCTSTR pszFileAccess)
{
	int iRetStatus = 0x00;
	//Pattern 1
	if (_tcsstr(pszFilePath,L"\\local\\") != NULL && _tcsstr(pszFilePath,L"\\lsass.exe") != NULL)
	{
		if (_tcsstr(pszFileAccess,L"desktop") != NULL && _tcsstr(pszFileAccess,L"\\@_decryptor_@.exe") != NULL)
		{
			iRetStatus = 0x02;
		}
		
	}

	return iRetStatus;

}

bool	CMaxRansBehavMngr::Check4MultiExt(LPCTSTR	pszFile2Check, LPTSTR pszLastExt)
{
	bool	bRetValue = false;

	if (pszFile2Check == NULL)
	{
		return bRetValue;
	}

	TCHAR	* pszExt = NULL;
	TCHAR	szDupFilePath[1024] = { 0x00 };

	_tcscpy(szDupFilePath, pszFile2Check);
	pszExt = _tcsrchr(szDupFilePath, L'.');
	if (pszExt == NULL)
	{
		return bRetValue;
	}
	if (pszLastExt != NULL)
	{
		_tcscpy(pszLastExt, pszExt);
	}
	*pszExt = L'\0';
	pszExt = NULL;

	pszExt = _tcsrchr(szDupFilePath, L'.');
	if (pszExt == NULL)
	{
		return bRetValue;
	}

	return true;
}

int	CMaxRansBehavMngr::Check4SameExtFiles(int iIRecIndex)
{
	int	iRetValue = 0x00; //NO Infection found
	int	iHitCount = 0x01;

	if (iRetValue < 0x00)
	{
		return iRetValue;
	}
	if (m_dwWatchLstCnt < iIRecIndex)
	{
		return iRetValue;
	}
	if (m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount >= 10)
	{
		TCHAR	szExt[512] = { 0x0 };

		if (Check4MultiExt(m_pProcWatchLst[iIRecIndex]->szFileLastAccessed[0x00], &szExt[0x00]) == false)
		{
			return iRetValue;
		}

		
		for (int i = 0x01; i < m_pProcWatchLst[iIRecIndex]->dwCurAccessedCount; i++)
		{
			TCHAR	szExt2Check[512] = { 0x0 };
			
			if (Check4MultiExt(m_pProcWatchLst[iIRecIndex]->szFileLastAccessed[i], &szExt2Check[0x00]) == true)
			{
				if (_tcsstr(szExt2Check, szExt) != NULL)
				{
					iHitCount++;
				}
			}
		}

		if (iHitCount >= 0x08)
		{
			iRetValue = iHitCount;
		}

	}
	return iRetValue;
}