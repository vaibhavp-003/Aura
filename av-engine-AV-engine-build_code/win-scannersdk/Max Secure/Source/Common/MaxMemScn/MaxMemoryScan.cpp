#include "pch.h"
#include "Psapi.h"
#include "MaxMemoryScan.h"
#include "ReqStruct.h"
#include "Shlwapi.h"



CMaxMemoryScan::CMaxMemoryScan(void)
{
	m_pProcList = NULL;
	m_dwProcListCount = 0x00;
	m_pMdlList = NULL;
	m_dwMdlListCount = 0x00;
	//m_dwCurProcIndex = 0x00;
	//m_dwCurMdlIndex = 0x00;

	m_bIs64Bit = FALSE;
	
	memset(m_szWinDir,0x00,MAX_PATH);
	memset(m_szSysDir,0x00,MAX_PATH);

	GetWindowsDirectory(m_szWinDir,MAX_PATH);
	GetSystemDirectory(m_szSysDir,MAX_PATH);

	_tcslwr_s(m_szWinDir,MAX_PATH);
	_tcslwr_s(m_szSysDir,MAX_PATH);

	m_hThreadSnap = INVALID_HANDLE_VALUE;
	memset(&m_te32,0x00,sizeof(m_te32));

	m_objKidoParam.dwKidoMainThreadFound = 0x00;
	m_objKidoParam.dwKidoThreadBaseAddress = 0x00;
	m_objKidoParam.dwKidoThreadID = 0x00;


	m_hNTDll = NULL;
	pNTQueryInformationThread = NULL;
	m_hNTDll = GetModuleHandle(L"NtDll.Dll");
	if (m_hNTDll != NULL)
	{
		pNTQueryInformationThread = (NTQUERYINFORMATIONTHREAD) GetProcAddress(m_hNTDll, "NtQueryInformationThread");
		if(pNTQueryInformationThread == NULL)
		{
			//Failed to Get Proc Address of NtQueryInformationThread
		}
	}

	m_hKrnl32 = NULL;
	pTerminateThread = NULL;

	//m_hKrnl32 = GetModuleHandle(L"kernel32.dll");
	if (m_hNTDll != NULL)
	{
		pTerminateThread = (LPFN_TerminateThread) GetProcAddress(m_hNTDll, "NtTerminateThread");
		if(pTerminateThread == NULL)
		{
			//Failed to Get Proc Address of NtQueryInformationThread
		}
	}
	SetDegubpriviledges();
}

CMaxMemoryScan::~CMaxMemoryScan(void)
{
	//if (m_hNTDll)
	//	FreeLibrary(m_hNTDll) ;

	if(m_pProcList)
	{
		for(DWORD dwIndex = 0; dwIndex < m_dwProcListCount; dwIndex++)
		{
			free(m_pProcList[dwIndex]);
			m_pProcList[dwIndex] = NULL;
		}

		free(m_pProcList);
		m_pProcList = NULL;
	}

	if(m_pMdlList)
	{
		for(DWORD dwIndex = 0; dwIndex < m_dwMdlListCount; dwIndex++)
		{
			free(m_pMdlList[dwIndex]);
			m_pMdlList[dwIndex] = NULL;
		}

		free(m_pMdlList);
		m_pMdlList = NULL;
	}
}

void CMaxMemoryScan::SetDegubpriviledges()
{
	TOKEN_PRIVILEGES	tp_CurPriv;
	HANDLE				h_Token=NULL;

	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&h_Token))
		return;
	
	tp_CurPriv.PrivilegeCount = 1;
	LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp_CurPriv.Privileges[0].Luid);
	tp_CurPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(h_Token,FALSE,&tp_CurPriv,sizeof(TOKEN_PRIVILEGES),0,0);

	CloseHandle(h_Token);

	return;
}

int CMaxMemoryScan::GetProcMemSnap()
{
	DWORD		dwProcArray[1024] = {0};
	DWORD		dwProcCnt = 0x00;
	DWORD		dwRet = 0x00;
	DWORD		i = 0x00;
	HANDLE		hCurProc = NULL;
	TCHAR		szPath[UTL_MAX_PATH] = {0};
	TCHAR		szFinalPath[UTL_MAX_PATH] = {0};

	if (!EnumProcesses(dwProcArray,sizeof(dwProcArray),&dwRet))
		return 0;
	
	dwProcCnt = dwRet / sizeof(DWORD);	
	for (i=0;i<dwProcCnt;i++)
	{
		hCurProc = OpenProcess(PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,FALSE, dwProcArray[i]);
		if (NULL != hCurProc)
		{
			_stprintf_s(szPath,UTL_MAX_PATH,L"");
			dwRet = 0x00;
			dwRet = GetModuleFileNameEx(hCurProc,NULL,szPath,UTL_MAX_PATH);
			//szPath[dwRet] = '\0';
			if (_tcslen(szPath) != 0)
			{
				_stprintf_s(szFinalPath,UTL_MAX_PATH,L"");
				GetPhysicalPath(szPath,szFinalPath);
				if (_tcslen(szFinalPath) != 0x00)
				{
					_tcslen(szFinalPath);
					AddProcess2List(szFinalPath,dwProcArray[i]);
				}
			}
			EnumModulesofProcess(hCurProc);

			CloseHandle(hCurProc);
		}
		
	}

	return 0;
}

int	CMaxMemoryScan::GetPhysicalPath(LPCTSTR pszLogicalPath,LPTSTR pszPhysicalPath)
{
	//CString		cstrData;
	TCHAR			szData[UTL_MAX_PATH] = {0};
	TCHAR			*ptrW = NULL;
	TCHAR			szOutPut[UTL_MAX_PATH] = {0};	
	BOOL			bModified = FALSE;	
	
	_stprintf_s(szData,UTL_MAX_PATH,L"%s",pszLogicalPath);
	_tcslwr_s(szData,UTL_MAX_PATH);
	ptrW = _tcsstr(szData,_T("\\systemroot"));
	if (NULL != ptrW)
	{
		ptrW+=_tcslen(L"\\systemroot");
		_stprintf_s(szOutPut,L"%s%s",m_szWinDir,ptrW);
		bModified = TRUE;
	}
	ptrW = NULL;
	ptrW = _tcsstr(szData,_T("\\??\\"));
	if (NULL != ptrW)
	{
		ptrW+=_tcslen(L"\\??\\");
		_stprintf_s(szOutPut,L"%s",ptrW);
		bModified = TRUE;
	}
	
	if (TRUE == bModified)
		_stprintf_s(pszPhysicalPath,UTL_MAX_PATH,L"%s",szOutPut);
	else
		_stprintf_s(pszPhysicalPath,UTL_MAX_PATH,L"%s",szData);

	return 0;
}

//False ==> New Entry
//True ==> Duplicate Entry
bool CMaxMemoryScan::Check4DuplicateEntries(LPCTSTR pszPath2Check)
{
	if (m_dwProcListCount == 0x00)
		return false;
	
	for(DWORD i = 0x00;i<m_dwProcListCount;i++)
	{
		if (_tcsstr(pszPath2Check,m_pProcList[i]->m_szProcPath) != NULL)
			return true;
	}

	return false;
}

//False ==> Good File
//True ==> SystemFile
bool CMaxMemoryScan::Check4SystemFile(LPCTSTR pszPath2Check)
{
	if (_tcslen(pszPath2Check) == 0x00)
		return false;
		
	TCHAR		szFileNameOnly[MAX_PATH] = {0};
	TCHAR		szFolderPath[UTL_MAX_PATH] = {0};
	TCHAR		*ptrW =  NULL;

	_stprintf_s(szFolderPath,UTL_MAX_PATH,L"%s",pszPath2Check);
	_tcslwr_s(szFolderPath,UTL_MAX_PATH);
	ptrW = _tcsrchr(szFolderPath,'\\');

	if (ptrW == NULL)
		return false;

	ptrW++;
	_stprintf_s(szFileNameOnly,MAX_PATH,L"%s",ptrW);
	ptrW--;
	*ptrW = '\0';

	if (_tcsstr(szFileNameOnly,L"explorer.exe"))
	{
		if (_tcsstr(szFolderPath,m_szWinDir))
			return true;
	}

	if (_tcsstr(L"lsass.exe;smss.exe;winlogon.exe;services.exe;svchost.exe;csrss.exe",szFileNameOnly))
	{
		if (_tcsstr(szFolderPath,m_szSysDir))
			return true;
	}

	return false;
}

int	CMaxMemoryScan::AddProcess2List(LPCTSTR pszPath2Add,DWORD dwPID)
{
	if (_tcslen(pszPath2Add) == 0x00)
		return 0;
	
	//if (Check4DuplicateEntries(pszPath2Add))
	//	return 0;

	if(m_dwProcListCount == 0x00)
		m_pProcList = (PROCESS_LIST **)malloc((m_dwProcListCount+1) * sizeof(PROCESS_LIST *));
	else	
		m_pProcList = (PROCESS_LIST **)realloc(m_pProcList,(m_dwProcListCount+1) * sizeof(PROCESS_LIST *));

	m_pProcList[m_dwProcListCount] = (LPPROCESS_LIST)calloc(0x01,sizeof(PROCESS_LIST));
	//memset(&m_pProcList[m_dwProcListCount],0x00,sizeof(PROCESS_LIST));
	_stprintf_s(m_pProcList[m_dwProcListCount]->m_szProcPath,UTL_MAX_PATH,L"%s",pszPath2Add);
	m_pProcList[m_dwProcListCount]->m_dwPID = dwPID;
	if (Check4SystemFile(pszPath2Add) == true)
		m_pProcList[m_dwProcListCount]->m_bSystemProcess = TRUE;
	else
		m_pProcList[m_dwProcListCount]->m_bSystemProcess = FALSE;

	m_dwProcListCount++;

	return 0;
}

int CMaxMemoryScan::EnumModulesofProcess(HANDLE hProcess)
{
	HMODULE		hModuleArray[1024] = {0};
	DWORD		dwRet = 0x00;
	DWORD		dwModuleCount = 0x00;	
	DWORD		i = 0x00;
	TCHAR		szPath[UTL_MAX_PATH] = {0};

	if (!EnumProcessModules(hProcess,hModuleArray,sizeof(hModuleArray),&dwRet))
		return 0x00;
	
	dwModuleCount = dwRet / sizeof(HMODULE);
	if (dwModuleCount > 0x01)
	{
		for (i=0x01;i<dwModuleCount;i++)
		{
			GetModuleFileNameEx(hProcess,hModuleArray[i],szPath,UTL_MAX_PATH);
			if (_tcslen(szPath) > 0x00)
			{
				AddModule2List(szPath);
			}
		}
	}
	return m_dwMdlListCount;
}

int	CMaxMemoryScan::AddModule2List(LPCTSTR pszPath2Add)
{
	if (_tcslen(pszPath2Add) == 0x00)
		return 0;
	
	if (Check4DuplicateModuleEntries(pszPath2Add))
		return 0;

	if(m_dwMdlListCount == 0x00)
		m_pMdlList = (MODULE_LIST **)malloc((m_dwMdlListCount+1) * sizeof(MODULE_LIST *));
	else	
		m_pMdlList = (MODULE_LIST **)realloc(m_pMdlList,(m_dwMdlListCount+1) * sizeof(MODULE_LIST *));

	m_pMdlList[m_dwMdlListCount] = (MODULE_LIST *)calloc(0x01,sizeof(MODULE_LIST));
	_stprintf_s(m_pMdlList[m_dwMdlListCount]->m_szMdlPath,UTL_MAX_PATH,L"%s",pszPath2Add);

	m_dwMdlListCount++;

	return 0;
}

//False ==> New Entry
//True ==> Duplicate Entry
bool CMaxMemoryScan::Check4DuplicateModuleEntries(LPCTSTR pszPath2Check)
{
	if (m_dwMdlListCount == 0x00)
		return false;
	
	for(DWORD i = 0x00;i<m_dwMdlListCount;i++)
	{
		if (_tcsstr(pszPath2Check,m_pMdlList[i]->m_szMdlPath) != NULL)
			return true;
	}

	return false;
}

BOOL	CMaxMemoryScan::StopThreadSanning()
{
	if (INVALID_HANDLE_VALUE != m_hThreadSnap)
	{
		_stprintf_s(szLogLine,UTL_MAX_PATH,L"[Thread] Kido Infection found so stopping Thread Enumeration");
		//m_MaxLog.Write2Log(szLogLine);
		m_objKidoParam.dwKidoMainThreadFound++;

		CloseHandle(m_hThreadSnap);
		m_hThreadSnap = INVALID_HANDLE_VALUE; 
	}
	return TRUE;
}


BOOL	CMaxMemoryScan::IsKidoThreadFound()
{
	if(m_objKidoParam.dwKidoMainThreadFound == 0x01)
		return TRUE;
	else
		return FALSE;

	return FALSE;
}

BOOL	CMaxMemoryScan::ScanThreadMemoryEx(DWORD dwProcID)
{
	BOOL			bInfection = FALSE, bFixed = FALSE;
	DWORD			dwThreadID = 0x00;
	WCHAR			szVirusName[MAX_PATH] = {0x00};

	m_hThreadSnap = INVALID_HANDLE_VALUE;
	m_hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (INVALID_HANDLE_VALUE == m_hThreadSnap)
	{
		return FALSE;
	}

	m_te32.dwSize = sizeof(THREADENTRY32);
	if(!Thread32First(m_hThreadSnap, &m_te32)) 
	{
		CloseHandle(m_hThreadSnap);
		m_hThreadSnap = INVALID_HANDLE_VALUE;
		return FALSE;
	}

	if (m_te32.th32OwnerProcessID < 0x08)
	{
		return FALSE;
	}
	do 
	{ 
		if(m_te32.th32OwnerProcessID == dwProcID )
		{
			ScanMemoryForCrypto(&bInfection,&bFixed,&dwThreadID,&szVirusName[0x00]);
		}
	} while( Thread32Next(m_hThreadSnap, &m_te32 ) );

	return bInfection;
}

BOOL CMaxMemoryScan::ScanThreadMemory4BabaxInfection(BYTE *pszBuffer,DWORD dwBytes)
{
	AddLogEntry(L"Inside ScanThreadMemory4BabaxInfection");
	int		i = 0x00;

	BYTE	bVirutThread_1[] =  {0x55, 0x8B, 0xEC, 0x51, 0xA1, 0x04};
	BYTE	bVirutThread_2[] =  {0x33, 0xC5, 0x89, 0x45, 0xFC, 0x56, 0x57, 0x8B, 0x0D, 0x5C, 0xBA};
	BYTE	bVirutThread_3[] =  {0x41, 0x8B, 0xC1, 0x89, 0x0D, 0x5C, 0xBA};
	BYTE	bVirutThread_4[] =  {0xC1, 0xE0, 0x07, 0x3D, 0x00, 0x10, 0x00, 0x00, 0x0F, 0x8F, 0xDC, 0x2D, 0x11, 0x00, 0xC1, 0xE1, 0x07, 0x8B, 0xC1, 0xE8, 0x59, 0x9F, 0xE8, 0xFF};

	BYTE	bVirutThread_X64_1[] =  {0x55, 0x8B, 0xEC, 0x51, 0xA1, 0x2C, 0x80};
	BYTE	bVirutThread_X64_2[] =  {0x6A, 0x33, 0xC5, 0x89, 0x45, 0xFC, 0x56, 0x57, 0x8B, 0x0D, 0xCC, 0x92};
	BYTE	bVirutThread_X64_3[] =  {0x6A, 0x41, 0x8B, 0xC1, 0x89, 0x0D, 0xCC, 0x92};
	BYTE	bVirutThread_X64_4[] =  {0x6A, 0xC1, 0xE0, 0x07, 0x3D, 0x00, 0x10, 0x00, 0x00, 0x0F, 0x8F, 0x5F, 0x02, 0x1B, 0x00, 0xC1, 0xE1, 0x07, 0x8B, 0xC1, 0xE8, 0x29, 0xCE, 0xF0, 0xFF};
	
	
	if((memcmp(bVirutThread_1, &pszBuffer[0x00], sizeof(bVirutThread_1)) == 0 && 
		memcmp(bVirutThread_2, &pszBuffer[0x09], sizeof(bVirutThread_2)) == 0 &&
		memcmp(bVirutThread_3, &pszBuffer[0x16], sizeof(bVirutThread_3)) == 0 &&
		memcmp(bVirutThread_4, &pszBuffer[0x1F], sizeof(bVirutThread_4)) == 0) || 
		(memcmp(bVirutThread_X64_1, &pszBuffer[0x00], sizeof(bVirutThread_X64_1)) == 0 && 
		memcmp(bVirutThread_X64_2, &pszBuffer[0x08], sizeof(bVirutThread_X64_2)) == 0 &&
		memcmp(bVirutThread_X64_3, &pszBuffer[0x15], sizeof(bVirutThread_X64_3)) == 0 &&
		memcmp(bVirutThread_X64_4, &pszBuffer[0x1E], sizeof(bVirutThread_X64_4)) == 0))
	{
		AddLogEntry(L"TRUE");
		return TRUE;
	}
	
	AddLogEntry(L"FALSE");
	return FALSE;
}
BOOL CMaxMemoryScan::FixInfectedThread(DWORD dwThID)
{
	HANDLE		hTh2Kill = NULL;
	int			iError = 0x00;
	
	//_stprintf_s(szLogLine,UTL_MAX_PATH,L"DEBUG : Closing Thread : %d ",dwThID);
	//m_MaxLog.Write2Log(szLogLine);

	hTh2Kill = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION | THREAD_TERMINATE,FALSE,dwThID);
	if (NULL == hTh2Kill)
		return FALSE;

	//_stprintf_s(szLogLine,UTL_MAX_PATH,L"DEBUG : After Open Thread for Closing : %X ",hTh2Kill);
	//m_MaxLog.Write2Log(szLogLine);

	if (SuspendThread(hTh2Kill) != (DWORD)-1)
	{
		//_stprintf_s(szLogLine,UTL_MAX_PATH,L"DEBUG : Suspend Thread Success");
		//m_MaxLog.Write2Log(szLogLine);
		try
		{
			if(pTerminateThread)
			{
				
				if(pTerminateThread(hTh2Kill,0x00) >= 0x00)
				{
					//_stprintf_s(szLogLine,UTL_MAX_PATH,L"DEBUG : Terminate Thread Success");
					//m_MaxLog.Write2Log(szLogLine);
				}
				else
				{
					iError = GetLastError();
					//_stprintf_s(szLogLine,UTL_MAX_PATH,L"DEBUG : Terminate Thread FAILED : %d",iError);
					//m_MaxLog.Write2Log(szLogLine);
				}
			}
			else
			{
				//_stprintf_s(szLogLine,UTL_MAX_PATH,L"DEBUG : Function Pointer Is NULL");
				//m_MaxLog.Write2Log(szLogLine);
			}
		}
		catch(...)
		{
			//_stprintf_s(szLogLine,UTL_MAX_PATH,L"DEBUG : Terminate Thread Failed");
			//m_MaxLog.Write2Log(szLogLine);
		}
		CloseHandle(hTh2Kill);
		return TRUE;
	}
	else
	{
		//_stprintf_s(szLogLine,UTL_MAX_PATH,L"DEBUG : Suspend Thread Failed");
		//m_MaxLog.Write2Log(szLogLine);
		CloseHandle(hTh2Kill);
		return FALSE;
	}
	
	/*
	if (TerminateThread(hTh2Kill,0x00) == 0x00)
	{
		iError = GetLastError();
		_stprintf_s(szLogLine,UTL_MAX_PATH,L"DEBUG : Terminate Thread Failed : %X : %d",hTh2Kill,iError);
		m_MaxLog.Write2Log(szLogLine);
		return FALSE;
		if (SuspendThread(hTh2Kill) != (DWORD)-1)
		{
			CloseHandle(hTh2Kill);
			return TRUE;
		}
	}
	else
	{
		_stprintf_s(szLogLine,UTL_MAX_PATH,L"DEBUG : Terminate Thread Success");
		m_MaxLog.Write2Log(szLogLine);
		CloseHandle(hTh2Kill);
		return TRUE;
	}
	*/
	
	if (NULL != hTh2Kill)
		CloseHandle(hTh2Kill);

	hTh2Kill = NULL;
	return FALSE;
}

BOOL CMaxMemoryScan::SuspendProcess(DWORD dwProcID)
{
	HANDLE						hThreadSnap = INVALID_HANDLE_VALUE; 
	THREADENTRY32				te32 = {0};
	HANDLE						hThread2Suspend = NULL;
	
	if (dwProcID < 0x08)
		return FALSE;

	if (dwProcID == GetCurrentProcessId())
		return TRUE;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
	if(hThreadSnap == INVALID_HANDLE_VALUE) 
		return FALSE;

	te32.dwSize = sizeof(THREADENTRY32);
	if(!Thread32First( hThreadSnap, &te32)) 
	{
		CloseHandle(hThreadSnap);
		return FALSE;
	}
	
	do
	{
		if (te32.th32OwnerProcessID == dwProcID)
		{
			hThread2Suspend = NULL;
			hThread2Suspend = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION | THREAD_TERMINATE,FALSE,te32.th32ThreadID);
			if (hThread2Suspend == NULL)
				continue;
			SuspendThread(hThread2Suspend);
			CloseHandle(hThread2Suspend);
		}
	} while(Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return TRUE;
}

BOOL CMaxMemoryScan::StopRunningProcess(DWORD dwPID2Check)
{
	HANDLE		hProcess2Kill = INVALID_HANDLE_VALUE;
	
	if (dwPID2Check < 0x08)
		return FALSE;

	hProcess2Kill = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE,FALSE,dwPID2Check);
	if (INVALID_HANDLE_VALUE != hProcess2Kill)
	{
		TerminateProcess(hProcess2Kill,0x00);
		CloseHandle(hProcess2Kill);
	}

	return FALSE;
}

BOOL CMaxMemoryScan::SuspendSimilarProcess(DWORD dwProcIndex)
{
	WCHAR		szData[MAX_PATH] = {0};
	WCHAR		szNextProc[MAX_PATH] = {0};
	
	_stprintf_s(szData,MAX_PATH,L"%s",m_pProcList[dwProcIndex]->m_szProcPath); 
	if (_tcslen(szData) == 0x00)
		return FALSE;

	if (dwProcIndex > 0x00)
	{
		_stprintf_s(szNextProc,MAX_PATH,L"%s",m_pProcList[dwProcIndex-1]->m_szProcPath); 
		if (_tcsstr(szData,szNextProc)!= NULL)
			SuspendProcess(m_pProcList[dwProcIndex-1]->m_dwPID);
	}

	if (dwProcIndex < (m_dwProcListCount-1))
	{
		_stprintf_s(szNextProc,MAX_PATH,L"%s",m_pProcList[dwProcIndex+1]->m_szProcPath); 
		if (_tcsstr(szData,szNextProc)!= NULL)
			SuspendProcess(m_pProcList[dwProcIndex+1]->m_dwPID);
	}


	return TRUE;
}

BOOL CMaxMemoryScan::CheckForWrongExecutionLocation(LPCTSTR pszPath2Check)
{
	BOOL	bRet = FALSE;

	//return bRet;

	if (_tcslen(pszPath2Check) == 0x00)
		return bRet;
	if (_tcslen(m_szSysDir) == 0x00)
		return bRet;
	if (_tcslen(m_szWinDir) == 0x00)
		return bRet;
		
	TCHAR		szFileNameOnly[MAX_PATH] = {0};
	TCHAR		szFolderPath[UTL_MAX_PATH] = {0};
	TCHAR		*ptrW =  NULL;

	_stprintf_s(szFolderPath,UTL_MAX_PATH,L"%s",pszPath2Check);
	_tcslwr_s(szFolderPath,UTL_MAX_PATH);
	ptrW = _tcsrchr(szFolderPath,'\\');

	if (ptrW == NULL)
		return bRet;

	_stprintf_s(szFileNameOnly,MAX_PATH,L"%s",ptrW);
	*ptrW = '\0';
/*
	if (_tcsstr(szFileNameOnly,L"\\explorer.exe"))
	{
		if (_tcsstr(szFolderPath,m_szWinDir))
			return bRet;
		else
			return TRUE;
	}

	if (_tcsstr(L"\\lsass.exe;\\smss.exe;\\winlogon.exe;\\services.exe;\\svchost.exe;\\csrss.exe",szFileNameOnly))
	{
		if (_tcsstr(szFolderPath,m_szSysDir))
			return bRet;
		else
			return TRUE;
	}*/

	if (_tcsstr(szFileNameOnly,L"\\wscript.exe"))
	{
		return TRUE;
	}
	if (_tcsstr(szFileNameOnly,L"\\msiexec.exe"))
	{
		return TRUE;
	}

	return bRet;
}

BOOL	CMaxMemoryScan::CreateFileCopy(LPCTSTR pszSrcFile, LPTSTR pszDestFile)
{
	BOOL	bRet = FALSE;
	_stprintf_s(pszDestFile,1024,L"%s.max",pszSrcFile);
	if (PathFileExists(pszDestFile))
	{
		DeleteFile(pszDestFile);
	}
	CopyFile(pszSrcFile,pszDestFile,FALSE);
	if (PathFileExists(pszDestFile))
	{
		bRet = FALSE;
	}

	return bRet;
}

BOOL	CMaxMemoryScan::EjectDll(LPCTSTR pszDll2Eject)
{
	BOOL			bRet = FALSE;
	CEjectModule	m_MaxEjectModule;
	bool			bSuccess = false;
	
	
	bSuccess = m_MaxEjectModule.EjectModule(pszDll2Eject);
	if (false == bSuccess)
	{
		bRet = FALSE;
	}
	else
	{
		bRet = TRUE;
	}
	
	return bRet;
	
}

bool CMaxMemoryScan::ScanMemoryForCrypto(BOOL *bInfection,BOOL *bFixed,DWORD *pdwThreadID,LPTSTR pszVirName)
{
	bool bRetStatus = false;

	DWORD						dwThreadStartAddress = 0x00;
	SIZE_T						dwBytesRead = 0x00;
	HANDLE						hCurrentThread = NULL;
	HANDLE						hCurrentProcess = NULL;
	THREAD_INFORMATION_CLASS	tic  = (THREAD_INFORMATION_CLASS)ThreadQuerySetWin32StartAddress ;
	BYTE						szBuffer[0x200] = {0};
	BYTE						bResult[0x10] = {0x00};
	DWORD						dwRetValue = 0x00;
	
	*bInfection = FALSE;
	*bFixed = FALSE;
	*pdwThreadID = 0x00;
	
	hCurrentThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT,FALSE,m_te32.th32ThreadID);
	if (NULL == hCurrentThread)
	{
		*bInfection = FALSE;
		return TRUE;
	}

	HANDLE hDupHandle;
	HANDLE hOurProcess = GetCurrentProcess( );
	if( !DuplicateHandle( hOurProcess, hCurrentThread, hOurProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0 ) ) 
	{
		CloseHandle(hCurrentThread);
		*bInfection = FALSE;
		
		return TRUE;
	}

	pNTQueryInformationThread(hDupHandle, tic, (PVOID)&bResult[0x00], sizeof(LPVOID),&dwRetValue);
	dwThreadStartAddress = *((DWORD *)&bResult[0x00]);
	if(0x00 == dwThreadStartAddress)
	{
		CloseHandle(hCurrentThread);
		*bInfection = FALSE;
		return TRUE;
	}

	hCurrentProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, m_te32.th32OwnerProcessID);
	if (NULL == hCurrentProcess)
	{
		CloseHandle(hCurrentThread);
		*bInfection = FALSE;
		return TRUE;
	}

	ReadProcessMemory(hCurrentProcess, (void *)dwThreadStartAddress, (LPVOID)szBuffer, 0x200, &dwBytesRead);
	if (0x00 == dwBytesRead)
	{
		CloseHandle(hCurrentProcess);
		CloseHandle(hCurrentThread);
		*bInfection = FALSE;
		return TRUE;
	}
	
	if(ScanThreadMemory4BabaxInfection(szBuffer,dwBytesRead))
	{
		AddLogEntry(L"ScanThreadMemory4BabaxInfection == TRUE");
		*bInfection = TRUE;
		_stprintf_s(pszVirName,MAX_PATH,L"W32.BABAX.THREAD");
		CloseHandle(hCurrentProcess);
		CloseHandle(hCurrentThread);
		*pdwThreadID = m_te32.th32ThreadID;

		if (FixInfectedThread(m_te32.th32ThreadID))
		{
			*bFixed = TRUE;
		}
		return TRUE;
	}

	CloseHandle(hCurrentProcess);
	CloseHandle(hCurrentThread);

	return bRetStatus;

}