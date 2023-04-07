/*======================================================================================
FILE             : TaskHostScan.cpp
ABSTRACT         : This module seraches system memory for suspicious thread
DOCUMENTS	     : 
AUTHOR		     : Tushar Kadam
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				without the prior written permission of Aura.	

CREATION DATE    : 07/2/2011 6:53:00 PM
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "Psapi.h"
#include "TaskHostScan.h"

/*-------------------------------------------------------------------------------------
	Function		: CTaskHostScan
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: construct the object and intialise message handling
--------------------------------------------------------------------------------------*/
CTaskHostScan::CTaskHostScan(void)
{
	m_pProcList = NULL;
	m_dwProcListCount = 0x00;
	m_dwExplorerPID = 0x00;
	memset(m_szWinDir,0x00,MAX_PATH);
	GetWindowsDirectory(m_szWinDir,MAX_PATH);
	_tcslwr_s(m_szWinDir,MAX_PATH);

	m_hNTDll = NULL;
	m_hNTDll = LoadLibrary(_T("NtDll.Dll"));
	if(m_hNTDll != NULL)
	{
		NtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS) GetProcAddress(m_hNTDll,"NtQueryInformationProcess");
	}
}

/*-------------------------------------------------------------------------------------
	Function		: ~CTaskHostScan
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CTaskHostScan::~CTaskHostScan(void)
{
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
	if (m_hNTDll != NULL)
		FreeLibrary(m_hNTDll);
}

/*-------------------------------------------------------------------------------------
	Function		: SetDebugPrivileges
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Allocates the system priviledges for accessing memory of other process 
--------------------------------------------------------------------------------------*/
int CTaskHostScan::SetDebugPrivileges(void)
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

/*-------------------------------------------------------------------------------------
	Function		: CheckProcessCmdLine
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Collecs the command line info of running process
					  e.g Suspicious script launches through wscript.exe (windows file)	
--------------------------------------------------------------------------------------*/
BOOL CTaskHostScan::CheckProcessCmdLine(DWORD dwProcIDIndex,LPCTSTR pszExePath)
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

	if (dwProcIDIndex == 0x00)
	{
		return bRetValue;
	}
	if (pszExePath == NULL)
	{
		return bRetValue;
	}

	dwSVCHostPID = m_pProcList[dwProcIDIndex]->m_dwPID;
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
	if(NT_SUCCESS(dwStatus) && dwSize < dwSizeNeeded)
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
								// if commandline is larger than our variable, truncate
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
								if((_tcslen(spi.szCmdLine) - _tcslen(pszExePath)) < 4 )
								{
									//CloseHandle(hCurProc);
									bRetValue = TRUE;
									//SuspendProcess(m_pProcList[dwProcIDIndex]->m_dwPID);
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

/*-------------------------------------------------------------------------------------
	Function		: ScanTaskSVCHost
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Searches process with name SVCHost with PID > explorer	
--------------------------------------------------------------------------------------*/
BOOL CTaskHostScan::ScanTaskSVCHost()
{
	TCHAR	szLogLine[1024] = {0x00};

	SetDebugPrivileges();

	GetProcMemSnap();

	for ( DWORD i = 0x00; i < m_dwProcListCount; i++)
	{
		if ((NULL != _tcsstr(m_pProcList[i]->m_szProcPath,_T("\\system32\\svchost.exe"))) || 
			(NULL != _tcsstr(m_pProcList[i]->m_szProcPath,_T("\\syswow64\\svchost.exe"))))
		{
			if(CheckProcessCmdLine(i,m_pProcList[i]->m_szProcPath))
			{
				_stprintf(szLogLine,L">>>> Suspending Process [%d]",m_pProcList[i]->m_dwPID);
				AddLogEntry(szLogLine);
				SuspendProcess(m_pProcList[i]->m_dwPID);
			}
		}
	}
	return FALSE;
}

/*-------------------------------------------------------------------------------------
	Function		: GetProcMemSnap
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Alisha Kadam
	Description		: Generates memory snapshot for running process	
--------------------------------------------------------------------------------------*/
int CTaskHostScan::GetProcMemSnap()
{
	DWORD		dwProcArray[1024] = {0};
	DWORD		dwProcCnt = 0x00;
	DWORD		dwRet = 0x00;
	DWORD		i = 0x00;
	TCHAR		szPath[UTL_MAX_PATH] = {0};
	TCHAR		szFinalPath[UTL_MAX_PATH] = {0};
	//AddLogEntry(L"I am in GetProcMemSnap");

	if (!EnumProcesses(dwProcArray,sizeof(dwProcArray),&dwRet))
		return 0;

	dwProcCnt = dwRet / sizeof(DWORD);	
	for (i=0;i<dwProcCnt;i++)
	{	
		_stprintf_s(szPath,UTL_MAX_PATH,L"");
			dwRet = 0x00;
			HANDLE	hCurProc = OpenProcess( PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,FALSE, dwProcArray[i]);

			if (NULL != hCurProc)
			{
				dwRet = GetModuleFileNameEx(hCurProc,NULL,szPath,UTL_MAX_PATH);

				if (_tcslen(szPath) != 0)
				{
					_stprintf_s(szFinalPath,UTL_MAX_PATH,L"");
					GetPhysicalPath(szPath,szFinalPath);
					if (_tcslen(szFinalPath) != 0x00)
					{
						_tcslwr(szFinalPath);
						AddProcess2List(szFinalPath,dwProcArray[i]);
					}
				}
			}
		CloseHandle(hCurProc);
	}

			
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: AddProcess2List
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Creates list of running processes
--------------------------------------------------------------------------------------*/
int	CTaskHostScan::AddProcess2List(LPCTSTR pszPath2Add,DWORD dwPID)
{
	if (_tcslen(pszPath2Add) == 0x00)
		return 0;

	//if (Check4DuplicateEntries(pszPath2Add))
	//	return 0;
	if (_tcsstr(pszPath2Add,L"\\explorer.exe") != NULL)
	{
		m_dwExplorerPID = dwPID;
	}

	if(m_dwProcListCount == 0x00)
		m_pProcList = (PROCESS_LIST1 **)malloc((m_dwProcListCount+1) * sizeof(PROCESS_LIST1 *));
	else	
		m_pProcList = (PROCESS_LIST1 **)realloc(m_pProcList,(m_dwProcListCount+1) * sizeof(PROCESS_LIST1 *));

	m_pProcList[m_dwProcListCount] = (LPPROCESS_LIST1)calloc(0x01,sizeof(PROCESS_LIST1));
	//memset(&m_pProcList[m_dwProcListCount],0x00,sizeof(PROCESS_LIST));
	_stprintf_s(m_pProcList[m_dwProcListCount]->m_szProcPath,UTL_MAX_PATH,L"%s",pszPath2Add);
	m_pProcList[m_dwProcListCount]->m_dwPID = dwPID;

	
	m_dwProcListCount++;

	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: GetPhysicalPath
	In Parameters	: LPCTSTR pszLogicalPath,LPTSTR pszPhysicalPath
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Retrieves physical path from logical path
--------------------------------------------------------------------------------------*/
int	CTaskHostScan::GetPhysicalPath(LPCTSTR pszLogicalPath,LPTSTR pszPhysicalPath)
{
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

/*-------------------------------------------------------------------------------------
	Function		: SuspendProcess
	In Parameters	: DWORD dwProcID
	Out Parameters	: TRUE is success else FALSE
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Suspends process with give PID
--------------------------------------------------------------------------------------*/
BOOL CTaskHostScan::SuspendProcess(DWORD dwProcID)
{
	CString						csProcsId;
	HANDLE						hThreadSnap = INVALID_HANDLE_VALUE; 
	THREADENTRY32				te32 = {0};
	HANDLE						hThread2Suspend = NULL;

	if (dwProcID < 0x08)
		return FALSE;

	if (dwProcID == GetCurrentProcessId())
		return TRUE;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
	if(hThreadSnap == INVALID_HANDLE_VALUE) 
	{
		return FALSE;
	}

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
			{
				continue;
			}
			SuspendThread(hThread2Suspend);
			CloseHandle(hThread2Suspend);
		}
	} while(Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return TRUE;
}

/*-------------------------------------------------------------------------------------
	Function		: ScanScriptThread
	In Parameters	: DWORD dwProcID
	Out Parameters	: TRUE is success else FALSE
	Purpose			: 
	Author			: Gaurav Phalake
	Description		: Scan process which launches script file in memory
--------------------------------------------------------------------------------------*/
BOOL CTaskHostScan::ScanScriptThread()
{
	TCHAR	szLogLine[1024] = {0x00};

	SetDebugPrivileges();

	DWORD dwInfect_Script_PID = 0;
	DWORD dwExplorerPID = 0;


	for ( DWORD i = 0x00; i < m_dwProcListCount; i++)
	{
		BOOL  bReturnStatus						= TRUE;
		DWORD dwSize							= 0;
		DWORD dwSizeNeeded						= 0;
		DWORD dwBytesRead						= 0;
		DWORD dwBufferSize						= 0;
		HANDLE hHeap							= 0;
		WCHAR *pwszBuffer						= 0;

		smPROCESSINFO spi						= {0};
		smPPROCESS_BASIC_INFORMATION pbi		= NULL;

		smPEB peb								= {0};
		smPEB_LDR_DATA peb_ldr					= {0};
		smRTL_USER_PROCESS_PARAMETERS peb_upp	= {0};

		ZeroMemory(&spi, sizeof(spi));
		ZeroMemory(&peb, sizeof(peb));
		ZeroMemory(&peb_ldr, sizeof(peb_ldr));
		ZeroMemory(&peb_upp, sizeof(peb_upp));
		HANDLE	hCurProc = OpenProcess( PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,FALSE, m_pProcList[i]->m_dwPID);

		if (NULL != hCurProc)
		{

			//Code started
			// Try to allocate buffer 
			hHeap = GetProcessHeap();
			dwSize = sizeof(smPROCESS_BASIC_INFORMATION);
			pbi = (smPPROCESS_BASIC_INFORMATION)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwSize);
			// Did we successfully allocate memory
			if(!pbi) 
			{
				CloseHandle(hCurProc);
				return FALSE;
			}
			// Attempt to get basic info on process
			NTSTATUS dwStatus = NtQueryInformationProcess(hCurProc,ProcessBasicInformation,pbi,dwSize,&dwSizeNeeded);
			// If we had error and buffer was too small, try again
			// with larger buffer size (dwSizeNeeded)
			if(dwStatus >= 0 && dwSize < dwSizeNeeded)
			{
				if(pbi)
					HeapFree(hHeap, 0, pbi);

				pbi = (smPPROCESS_BASIC_INFORMATION)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwSizeNeeded);
				if(!pbi)
				{
					CloseHandle(hCurProc);
					return FALSE;
				}

				dwStatus = NtQueryInformationProcess(hCurProc,ProcessBasicInformation,pbi,dwSizeNeeded, &dwSizeNeeded);
				//	LONG dwStatus = NtQueryInformationProcess(hCurProc,ProcessBasicInformation,pbi,dwSizeNeeded,NULL);
			}

			// Did we successfully get basic info on process
			if(dwStatus >= 0)
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
								// Yes, try to read CommandLine

								pwszBuffer = (WCHAR *)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,peb_upp.CommandLine.Length);
								// If memory was allocated, continue
								if(pwszBuffer)
								{
									//peb_upp.CommandLine.Length = _tcslen()
									if(ReadProcessMemory(hCurProc,peb_upp.CommandLine.Buffer,pwszBuffer,peb_upp.CommandLine.Length,(SIZE_T*)&dwBytesRead))
									{
										// if commandline is larger than our variable, truncate
										if(peb_upp.CommandLine.Length >= sizeof(spi.szCmdLine)) 
											dwBufferSize = sizeof(spi.szCmdLine) - sizeof(TCHAR);
										else
											dwBufferSize = peb_upp.CommandLine.Length;

#if defined(UNICODE) || (_UNICODE)
										StringCbCopyN(spi.szCmdLine, sizeof(spi.szCmdLine),pwszBuffer, dwBufferSize);
#else
										WideCharToMultiByte(CP_ACP, 0, pwszBuffer,(int)(dwBufferSize / sizeof(WCHAR)),spi.szCmdLine, sizeof(spi.szCmdLine),NULL, NULL);
#endif
										TCHAR	szFinalCmdLine[1024] = {0x00};

										_tcscpy(szFinalCmdLine,spi.szCmdLine);
										_tcslwr(szFinalCmdLine);
										//if (NULL != _tcsstr(spi.szCmdLine,_T(".exe")) && NULL != _tcsstr(spi.szCmdLine,_T(".js")))// || (NULL != _tcsstr(m_pProcList[i]->m_szProcPath,_T("\\syswow64\\svchost.exe"))))
										if (_tcslen(szFinalCmdLine) > 0x00)
										{
											if (_tcsstr(szFinalCmdLine,_T("\\windows\\")) == NULL && _tcsstr(szFinalCmdLine,_T("\\node.exe")) == NULL)
											{
												if ((NULL != _tcsstr(spi.szCmdLine,_T(".exe")) && NULL != _tcsstr(spi.szCmdLine,_T(".js"))) || (NULL != _tcsstr(spi.szCmdLine,_T(".com")) && NULL != _tcsstr(spi.szCmdLine,_T("@gmail.com"))))
												{
													_stprintf(szLogLine,L">>>> Got Process having Script command line path = %d",m_pProcList[i]->m_dwPID);
													AddLogEntry(szLogLine);
													dwInfect_Script_PID = m_pProcList[i]->m_dwPID;
													SuspendProcess(dwInfect_Script_PID);
													_stprintf(szLogLine,L">>>> Process having script file suspended successfully..! = %d",m_pProcList[i]->m_dwPID);
													AddLogEntry(szLogLine);
												}
											}
										}
										else
										{
											continue;
										}



									}
									if(!HeapFree(hHeap, 0, pwszBuffer)) 
									{
										// failed to free memory
										bReturnStatus = FALSE;
										if(pbi != NULL)
											if(!HeapFree(hHeap, 0, pbi)) 
											{
												// failed to free memory
											}
									}
								}

							}
						}
					}
				}

			}
		}
	}
	return FALSE;
}