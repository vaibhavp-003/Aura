/*=============================================================================
   FILE			: Enumprocess.cpp
   ABSTRACT		: This class will provide the enumeration of current processes
   DOCUMENTS	: 
   AUTHOR		: 
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 20/09/2006
   NOTES		:
VERSION HISTORY	: 
				   Unicode Supported
				   21 Jan 2008 Remove 98 version check code and also remove Registry.h
============================================================================*/
#include "pch.h"
#include "EnumProcess.h"
#pragma warning(disable : 4996)
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*-------------------------------------------------------------------------------------
Function		: CEnumProcess(CONSTRUCTOR)
In Parameters	: -
Out Parameters	: -
Purpose			: Initilize CEnumProcess class
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CEnumProcess::CEnumProcess()
{
	try
	{
		m_hModPSAPI = NULL;
		m_lpfnGetModuleFileNameEx = NULL;
		PSAPI = NULL;
		FEnumProcesses = NULL;		// Pointer to EnumProcess
		FEnumProcessModules = NULL; // Pointer to EnumProcessModules
		FGetModuleFileNameEx = NULL;// Pointer to GetModuleFileNameEx
		FGetModuleBaseName = NULL;// Pointer to GetModuleFileNameEx

		TOOLHELP = NULL;			//Handle to the module (Kernel32)
		FCreateToolhelp32Snapshot = NULL;
		FProcess32First = NULL;
		FProcess32Next = NULL;
		FModule32First = NULL;
		FModule32Next = NULL;
		FThread32First = NULL;
		FThread32Next = NULL;

		// Retrieve the OS version
		osver.dwOSVersionInfoSize = sizeof(osver);
		GetVersionEx(&osver);

		m_iNoOfInstances = 0;

		// Load required Dll
		InitProcessDll();

		EnablePrivilege(SE_DEBUG_NAME);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::CEnumProcess"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: ~CEnumProcess (DESTRUCTOR)
In Parameters	: -
Out Parameters	: -
Purpose			: Destruct CEnumProcess class.
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
CEnumProcess::~CEnumProcess()
{
	try
	{
		FreeProcessDll();
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::~CEnumProcess"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: InitProcessDll
In Parameters	: -
Out Parameters	: True if library is successfully loaded else false.
Purpose			: This Function Loads PSAPI library and Retrive the address of various
functions
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CEnumProcess::InitProcessDll()
{
	try
	{
		// added to load this function in all OS, rest of the family functions are loaded in supporting os only
		if(!m_hModPSAPI)
		{
			m_hModPSAPI = LoadLibrary(_T("PSAPI.DLL"));
		}

		if(m_hModPSAPI && !m_lpfnGetModuleFileNameEx)
		{
#ifdef _UNICODE
			m_lpfnGetModuleFileNameEx = (PFGetModuleFileNameEx)::GetProcAddress(m_hModPSAPI, "GetModuleFileNameExW");
#else
			m_lpfnGetModuleFileNameEx = (PFGetModuleFileNameEx)::GetProcAddress(m_hModPSAPI, "GetModuleFileNameExA");
#endif
		}

		// If Windows NT 4.0
		if(osver.dwPlatformId == VER_PLATFORM_WIN32_NT && (osver.dwMajorVersion == 4 
					|| (osver.dwMajorVersion == 5 && osver.dwMinorVersion == 0)))
		{
			if(!PSAPI)//If not already Loaded
			{
				PSAPI = ::LoadLibrary(_TEXT("PSAPI"));
				if(PSAPI == NULL)
				{
					return false;
				}

				FEnumProcesses       = (PFEnumProcesses)::GetProcAddress(PSAPI,
															LPCSTR("EnumProcesses"));
				FEnumProcessModules  = (PFEnumProcessModules)::GetProcAddress(PSAPI,
														LPCSTR("EnumProcessModules"));
#ifdef _UNICODE
				FGetModuleFileNameEx = (PFGetModuleFileNameEx)::GetProcAddress(PSAPI,
															("GetModuleFileNameExW"));
				FGetModuleBaseName   = (PFGetModuleBaseName)::GetProcAddress(PSAPI, 
															("GetModuleBaseNameW"));
#else
				FGetModuleFileNameEx = (PFGetModuleFileNameEx)::GetProcAddress(PSAPI, 
															("GetModuleFileNameExA"));
				FGetModuleBaseName	 = (PFGetModuleBaseName)::GetProcAddress(PSAPI, 
															("GetModuleBaseNameW"));
#endif
				if((!FEnumProcesses) || (!FEnumProcessModules) 
							|| (!FGetModuleFileNameEx) ||(!FGetModuleBaseName))
				{
					AddLogEntry(_T("NT: Could not get the ProcAddress for process enum!"));
					FreeLibrary(PSAPI);
					PSAPI = NULL;
					return false;
				}
			}
		}
		//Windows 9x, Windows 2000, Windows XP, Windows 2003
		else if(osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS ||
			(osver.dwPlatformId == VER_PLATFORM_WIN32_NT && osver.dwMajorVersion > 4))
		{
			if(!TOOLHELP)	//If not already Loaded
			{
				TOOLHELP = ::LoadLibrary(_TEXT("Kernel32"));
				if(TOOLHELP == NULL)
				{
					return false;
				}

				// Find ToolHelp functions
				FCreateToolhelp32Snapshot = (PFCreateToolhelp32Snapshot)::GetProcAddress
										(TOOLHELP, LPCSTR("CreateToolhelp32Snapshot"));
#ifdef _UNICODE
				FProcess32First = (PFProcess32First)::GetProcAddress
										(TOOLHELP, LPCSTR("Process32FirstW"));
				FProcess32Next = (PFProcess32Next)::GetProcAddress
										(TOOLHELP, LPCSTR("Process32NextW"));
				FModule32First = (PFModule32First)::GetProcAddress
										(TOOLHELP, LPCSTR("Module32FirstW"));
				FModule32Next = (PFModule32Next)::GetProcAddress
										(TOOLHELP, LPCSTR("Module32NextW"));
				FThread32First = (PFThread32First)::GetProcAddress
										(TOOLHELP, LPCSTR("Thread32First"));
				FThread32Next = (PFThread32Next)::GetProcAddress
										(TOOLHELP, LPCSTR("Thread32Next"));

#else
				FProcess32First = (PFProcess32First)::GetProcAddress
										(TOOLHELP, LPCSTR("Process32First"));
				FProcess32Next = (PFProcess32Next)::GetProcAddress
										(TOOLHELP, LPCSTR("Process32Next"));
				FModule32First = (PFModule32First)::GetProcAddress
										(TOOLHELP, LPCSTR("Module32First"));
				FModule32Next = (PFModule32Next)::GetProcAddress
										(TOOLHELP, LPCSTR("Module32Next"));
				FThread32First = (PFThread32First)::GetProcAddress
										(TOOLHELP, LPCSTR("Thread32First"));
				FThread32Next = (PFThread32Next)::GetProcAddress
										(TOOLHELP, LPCSTR("Thread32Next"));
#endif

				//Version: 17.3
				//Memory leak
				if((!FCreateToolhelp32Snapshot) || (!FProcess32First) ||
					(!FProcess32Next) || (!FModule32First) || (!FModule32Next))
				{
					AddLogEntry(_T("2K, XP: Could not get the ProcAddress for process enum!"));
					FreeLibrary(TOOLHELP);
					TOOLHELP = NULL;
					return false;
				}
			}
		}
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::InitProcessDll"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: FreeProcessDll
In Parameters	: -
Out Parameters	: bool : true if library is released
Purpose			: Tis function helps in relasing loaded module
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CEnumProcess::FreeProcessDll()
{
	try
	{
		if(m_hModPSAPI)
		{
			FreeLibrary(m_hModPSAPI);
		}

		m_hModPSAPI = NULL;
		m_lpfnGetModuleFileNameEx = NULL;

		if(PSAPI)
		{
			FreeLibrary (PSAPI);
			PSAPI = NULL;
		}

		if(TOOLHELP)
		{
			FreeLibrary(TOOLHELP);
			TOOLHELP = NULL;
		}
		return true;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::FreeProcessDll"));
	}
}

/*-------------------------------------------------------------------------------------
Function		: EnumRunningProcesses
In Parameters	: PROCESSHANDLER : Handle to process
: LPVOID : this pointer
Out Parameters	: bool : true if it enumerates all the running process
Purpose			: This Function enumerates all the running process
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CEnumProcess::EnumRunningProcesses(PROCESSHANDLER lpProc, LPVOID pThis)
{
	try
	{
		return HandleRequest(_T(""), false, lpProc, pThis, NULL);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::EnumRunningProcesses"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: IsProcessRunning
In Parameters	: CString : Name of process
: bool : if true terminates the process
: bool :if true retrives the ful path of process
: bool :if true it terminates whole process tree
Out Parameters	: bool : treu if satisfy user request
Purpose			: This function findout if given process is running
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CEnumProcess::IsProcessRunning(CString sProcName, bool bTerminateProcess, bool bIsFullPath,bool bTerminateTree)
{
	try
	{
		return HandleRequest(sProcName, bTerminateProcess, NULL, NULL, NULL, bIsFullPath, bTerminateTree);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::IsProcessRunning"));
	}
	return false;
}
/*-------------------------------------------------------------------------------------
Function		: KillProcess
In Parameters	: DWORD : ProcessId of process to be killed
Out Parameters	: bool : True If Process is successfully Killed else false
Purpose			: This function kills specified process
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CEnumProcess::KillProcess(DWORD ProcessID)
{
	try
	{
		HANDLE hResult;
		//to open an existing process
		hResult = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ProcessID);
		if(hResult)
		{
			TerminateProcess(hResult, 0);
			::CloseHandle(hResult);
			return true;
		}
		return false;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::KillProcess"));
	}
}
/*-------------------------------------------------------------------------------------
Function		: GetProcessModule
In Parameters	: DWORD : Process identifier of the process to be included in the snapshot.
: LPCTSTR : Tool help identifier of the process module.
: LPMODULEENTRY32 : Structure that receives data about the module.
: DWORD :Size of the buffer pointed to by the lpMe32 parameter
Out Parameters	: bool : true if  successfully obtains list of all modules else false.
Purpose			: This Function obtains a list of modules for the specified process.
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CEnumProcess::GetProcessModule(DWORD dwPID, LPCTSTR pstrModule, 
									LPMODULEENTRY32 lpMe32, DWORD cbMe32)
{
	try
	{
		BOOL			bRet;
		bool			bFound      = false;
		HANDLE			hModuleSnap = NULL;
#ifdef _UNICODE
		MODULEENTRY32W	me32        = {0};
#else
		MODULEENTRY32   me32        = {0};
#endif
		int				nLen = static_cast<int>(wcslen(pstrModule));

		if(!TOOLHELP)
		{
			return false;
		}

		if(!nLen)
		{
			return false;
		}

		hModuleSnap = FCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
		if(hModuleSnap == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		me32.dwSize = sizeof(MODULEENTRY32);
		bRet = FModule32First(hModuleSnap, &me32);
		while (bRet && !bFound)
		{
			if(me32.hModule  != INVALID_HANDLE_VALUE)
			{
				// locate the given filename in the modulelist (usually its the first anyway)
				if((_tcsnicmp(me32.szModule, pstrModule, nLen)== 0) || // For Win 2000, XP, 2003
					(_tcsnicmp(me32.szExePath, pstrModule, nLen)== 0))// For Win 95/98
				{
					CopyMemory(lpMe32, &me32, cbMe32);
					bFound = true;
				}
				bRet = FModule32Next(hModuleSnap, &me32);
			}
			else
			{
				bRet = false;
			}
		}
		CloseHandle(hModuleSnap);
		return (bFound);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::GetProcessModule"));
	}
	return false;
}
/*-------------------------------------------------------------------------------------
Function		: EnablePrivilege
In Parameters	: LPCTSTR : specifies the requested types of access to the access token
Out Parameters	: BOOL : True if Adjust the token privilege of process else false
Purpose			: To Change the Token privilege of any process
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
BOOL CEnumProcess::EnablePrivilege(LPCTSTR szPrivilege)
{
	BOOL bReturn = FALSE;
	try
	{
		HANDLE hToken;
		TOKEN_PRIVILEGES tpOld;
		if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
								&hToken))
		{
			return (FALSE);
		}

		bReturn = (EnableTokenPrivilege(hToken, szPrivilege, &tpOld));
		CloseHandle(hToken);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::EnablePrivilege"));
	}
	return (bReturn);
}
/*-------------------------------------------------------------------------------------
Function		: EnableTokenPrivilege
In Parameters	: HANDLE : Handle to process whose Access privilege hag to be changed
: LpCTSTR : Pointer to a null-terminated string that specifies the
name of the privilege
: TOKEN_PRIVILEGES : Pointer to a variable that receives the locally
unique identifier
Out Parameters	: BOOL  : TRUE if privilege is changed else False
Purpose			: This Function retives and adjust the token privilege of a process.
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
BOOL CEnumProcess::EnableTokenPrivilege(HANDLE htok, LPCTSTR szPrivilege,
										TOKEN_PRIVILEGES *tpOld)
{
	try
	{
		if(htok != INVALID_HANDLE_VALUE)
		{
			TOKEN_PRIVILEGES tp;
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if(LookupPrivilegeValue(0, szPrivilege, &tp.Privileges[0].Luid))
			{
				DWORD cbOld = sizeof (*tpOld);
				if(AdjustTokenPrivileges(htok, FALSE, &tp, cbOld, tpOld, &cbOld))
				{
					return (ERROR_NOT_ALL_ASSIGNED != GetLastError());
				}
				else
				{
					return (FALSE);
				}
			}
			else
			{
				return (FALSE);
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::EnableTokenPrivilege"));
		return (FALSE);
	}
	return (FALSE);

}
/*-------------------------------------------------------------------------------------
Function		: HandleRequest
In Parameters	: CString : Name of process
: bool : true if you want to terminate the processs else false
: PROCESSHANDLER :handle of requested process
: LPVOID : this pointer
: LPDWORD :Process id
: bool:if true retirves full path of process
: bool : if true it terminates the process tree
Out Parameters	: bool :true if satisfy the user request
Purpose			: This Function process request of user on a process
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CEnumProcess::HandleRequest(CString sProcName, bool bTerminateProcess,
								 PROCESSHANDLER lpProc, LPVOID pThis, 
								 LPDWORD pdwProdID, bool bIsFullPath, bool bTerminateTree)
{
	try
	{
		bool bReturnVal = false;
		bool bStopEnum = false;
		DWORD dwParentId = 0;
		// If Windows NT 4.0
		if(osver.dwPlatformId == VER_PLATFORM_WIN32_NT && (osver.dwMajorVersion == 4 
							|| (osver.dwMajorVersion == 5 && osver.dwMinorVersion == 0)))
		{
			if(PSAPI)
			{
				try
				{
					DWORD aProcesses[1024], cbNeeded, cProcesses;
					if(!FEnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
						throw;
					// Calculate how many process identifiers were returned.
					cProcesses = cbNeeded / sizeof(DWORD);
					for(unsigned int i=0; i <= cProcesses; i++)
					{
						CString csProcessName;
						bool bFound = false;
						TCHAR szProcessName[MAX_FILE_PATH]={0};
						// Get a handle to the process.
						HANDLE hProcess =  OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);
						if(hProcess)
						{
							HMODULE hMod = NULL;
							DWORD cbytesNeed=0;
							TCHAR    szModuleName[MAX_PATH]={0};
							// Get the process name.
							if(FEnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbytesNeed))
							{
								FGetModuleFileNameEx(hProcess, hMod, szProcessName,
													_countof(szProcessName));
								GetLongPathName(szProcessName, szProcessName, MAX_FILE_PATH);
								if(lpProc)//Request for Names only
								{
									if(FGetModuleBaseName)
									{
										FGetModuleBaseName(hProcess, hMod, szModuleName,
															_countof(szModuleName));
									}

									lpProc(szModuleName, szProcessName, aProcesses[i], hProcess, pThis, bStopEnum);
									bReturnVal = true;
									if(bStopEnum)
									{
										::CloseHandle(hProcess);
										break;
									}
								}
								else
								{
									csProcessName = szProcessName;
									if(bIsFullPath)
									{
										if(!csProcessName.CompareNoCase(sProcName))
										{
											bFound = true;
										}
									}
									else
									{
										int iFind  = csProcessName.ReverseFind('\\');
										if(iFind != -1)
										{
											csProcessName = csProcessName.Mid(iFind +1);
										}
										if(!csProcessName.CompareNoCase(sProcName))
										{
											bFound = true;
										}
									}
									if(!(CString(szProcessName).CompareNoCase(sProcName)))
									{
										bReturnVal = true;
									}
								}
							}
							else
							{
								if(!lpProc)
								{
									int iFind  = csProcessName.ReverseFind('\\');
									if(iFind != -1)
									{
										csProcessName = csProcessName.Mid(iFind +1);
									}
									if(!csProcessName.CompareNoCase(sProcName))
									{
										bFound = true;
									}
								}
							}
							if(bFound)
							{
								if(pdwProdID)//requested only procid
								{
									memcpy(pdwProdID, &aProcesses[i], sizeof(DWORD));
									bReturnVal = true;
								}
								else
								{
									if(bTerminateProcess)
									{
										dwParentId = aProcesses[i];
										bReturnVal = (TerminateProcess(hProcess, 0)== FALSE 
														? false : true);
										if (bReturnVal == false)
										{
											CString		csLog;
											csLog.Format(L"TERMINATE PROCESS 1 FAILED : %d : [%d]", dwParentId, GetLastError());
											OutputDebugString(csLog);
										}
									}
									else
									{
										m_iNoOfInstances++;
										bReturnVal = true; // Process found running!
									}
								}
							}
							///TODO: to terminate process tree.
							::CloseHandle(hProcess);
						}//if(NULL != hProcess)
					}//for(i = 0; i <= cProcesses; i++)
				}
				catch(...)
				{}
			} //if(PSAPI)
		}
		//Windows 9x, Windows 2000, Windows XP, Windows 2003
		else if(osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS ||
			(osver.dwPlatformId == VER_PLATFORM_WIN32_NT && osver.dwMajorVersion > 4))
		{
			if(TOOLHELP)
			{
				HANDLE hProcessSnap;
				try
				{
#ifdef _UNICODE
					PROCESSENTRY32W pe32 = {0};
					MODULEENTRY32W  me32 = {0};
#else
					PROCESSENTRY32 pe32 = {0};
					MODULEENTRY32  me32 = {0};
#endif

					// Setup variables
					pe32.dwSize = sizeof(pe32);
					me32.dwSize = sizeof(me32);

					hProcessSnap = FCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
					if(INVALID_HANDLE_VALUE == hProcessSnap)
					{
						return false;
					}

					if(!FProcess32First(hProcessSnap, &pe32))
					{
						return false;
					}

					while(true)
					{
						bool bFound = false;
						DWORD ProcID = pe32.th32ProcessID;
						if(osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)//IN Win95/98 we already have the full path!
						{
							if(CString(pe32.szExeFile).Right(4) != _T(".DLL"))//Ignore files with.DLL extensions!
							{
								if(lpProc)//Request for Names only
								{
									lpProc(pe32.szExeFile, pe32.szExeFile, ProcID, 0, pThis, bStopEnum);
									bReturnVal = true;
									if(bStopEnum)
									{
										break;
									}
								}
								else
								{
									if(!(CString(pe32.szExeFile).CompareNoCase(sProcName)))
									{
										bFound = true;
									}
								}
							}
						}
						else if(GetProcessModule(ProcID, pe32.szExeFile, &me32, sizeof(MODULEENTRY32)))
						{
							GetLongPathName(me32.szExePath, me32.szExePath, MAX_PATH);
							if(lpProc)//Request for Names only
							{
								HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pe32.th32ProcessID);
								lpProc(pe32.szExeFile, me32.szExePath, ProcID, hProcess, pThis, bStopEnum);
								if(hProcess)
								{
									CloseHandle(hProcess);
								}
								bReturnVal = true;
								if(bStopEnum)
								{
									break;
								}
							}
							else
							{
								if(bIsFullPath)
								{
									if(!(CString(me32.szExePath).CompareNoCase(sProcName)))
									{
										bFound = true;
									}
								}
								else
								{
									if(!(CString(pe32.szExeFile).CompareNoCase(sProcName)))
									{
										bFound = true;
									}
								}
							}
						}
						else
						{
							if(!lpProc)
							{
								//Version:15.8
								//Resource:Dipali
								//if not full path then match only names
								if(!bIsFullPath)
								{
									if(!(CString(pe32.szExeFile).CompareNoCase(sProcName)))
									{
										bFound = true;
									}
								}
							}
							else
							{
								HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pe32.th32ProcessID);
								lpProc(pe32.szExeFile, L"", ProcID, hProcess, pThis, bStopEnum);
								if(hProcess)
								{
									CloseHandle(hProcess);
								}

								bReturnVal = true;
								if(bStopEnum)
								{
									break;
								}
							}
						}

						if(bFound)
						{
							if(pdwProdID)//requested only procid
							{
								memcpy(pdwProdID, &ProcID, sizeof(DWORD));
								bReturnVal = true;
							}
							else
							{
								if(bTerminateProcess)
								{
									dwParentId = ProcID;
									HANDLE hResult;
									//to open an existing process
									hResult = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ProcID);
									if(hResult)
									{
										if(TerminateProcess(hResult, 0))
										{
											bReturnVal = true;		// Process Terminated Success!
										}
										else
										{
											CString		csLog;
											csLog.Format(L"TERMINATE PROCESS FAILED : %d : [%d]",ProcID,GetLastError());
											OutputDebugString(csLog);
											bReturnVal = false;		// Process Termination Failed!
										}
										::CloseHandle(hResult);
									}
								}
								else
								{
									m_iNoOfInstances++;
									bReturnVal = true; // Process found running!
								}
							}
						}
						//To kill processes tree
						if(bTerminateTree && dwParentId != 0)
						{
							if(dwParentId == pe32.th32ParentProcessID)
							{
								HANDLE hResult;
								//to open an existing process
								hResult = OpenProcess(PROCESS_ALL_ACCESS, TRUE, ProcID);
								if(hResult)
								{
									if(TerminateProcess(hResult, 0))
									{
										bReturnVal = true;		// Process Terminated Success!
									}
									else
									{
										bReturnVal = false;		// Process Termination Failed!
									}
									::CloseHandle(hResult);
								}
							}
						}
						if(!FProcess32Next(hProcessSnap, &pe32))
						{
							break;
						}
					}
					CloseHandle(hProcessSnap);
				}
				catch(...)
				{
					AddLogEntry(_T("Exception caught in HandleRequest"));
				}
			}
		}
		return bReturnVal;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::HandleRequest"));
	}
	return false;
}
/*-------------------------------------------------------------------------------------
Function		: RebootSystem
In Parameters	: -
Out Parameters	: void
Purpose			: This Function Reboot system
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CEnumProcess::RebootSystem(DWORD dwType)
{
	try
	{
		HANDLE hToken;
		TOKEN_PRIVILEGES tkp; 
		// Get a token for this process.
		if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{

			// Get the LUID for the shutdown privilege.
			LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);

			tkp.PrivilegeCount = 1;  // one privilege to set
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			// Get the shutdown privilege for this process.
			AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
		}
		else
		{
			CString cs;
			cs.Format(L"%d",::GetLastError());
			AddLogEntry(L"In CEnumProcess::RebootSystem()OpenProcessToken false %s"),cs;
		}


		if(dwType == 0)
		{
			// Shut down the system and force all applications to close.
			if(!ExitWindowsEx(EWX_REBOOT| EWX_FORCE, 0))
			{
				CString cs;
				cs.Format(L"%d",::GetLastError());
				AddLogEntry(L"In CEnumProcess::RebootSystem for Restart ExitWindowsEx return false = %d",cs);
			}
		}
		if(dwType == 1)
		{
			if(!ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE | EWX_POWEROFF, 0))
			{
				CString cs;
				cs.Format(L"%d",::GetLastError());
				AddLogEntry(L"In CEnumProcess::RebootSystem for ShutDown ExitWindowsEx return false = %d",cs);
			}
		}
		if(dwType == 2)
		{
			if(!ExitWindowsEx(EWX_LOGOFF| EWX_FORCE, 0))
			{
				CString cs;
				cs.Format(L"%d",::GetLastError());
				AddLogEntry(L"In CEnumProcess::RebootSystem for Log off ExitWindowsEx return false = %d",cs);
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::RebootSystem"));
	}
}
/*-------------------------------------------------------------------------------------
Function		: KillExplorer
In Parameters	: -
Out Parameters	: bool
Purpose			: This Function kills Explorer.exe
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
bool CEnumProcess::KillExplorer()
{
	try
	{
		bool isKilled = false;
		EnablePrivilege(SE_DEBUG_NAME);

		HANDLE  hProcessSnap = NULL;
		PROCESSENTRY32 pe32  = {0};
		HANDLE hExplorer;

		//  Take a snapshot of all processes in the system.
		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if(hProcessSnap == INVALID_HANDLE_VALUE)
		{
			AddLogEntry(_T("failed to take Snapshot"));
		}
		//  Fill in the size of the structure before using it.
		pe32.dwSize = sizeof(PROCESSENTRY32);

		hExplorer = _GetProcID(CString(_T("Explorer.exe")), pe32, hProcessSnap); // Getting Process Ids

		if(hExplorer != NULL)
		{
			CreateRemoteThread(hExplorer, NULL, 0, (LPTHREAD_START_ROUTINE)ExitProcess,
								(LPVOID)1, 0, NULL);
			CloseHandle(hExplorer);
			isKilled = true;
		}
		return isKilled;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::KillExplorer"));
	}
	return false;

}
/*-------------------------------------------------------------------------------------
Function		: _GetProcID
In Parameters	: CString : Process  Name
: PROCESSENTRY32 : Pointer to a PROCESSENTRY32 structure.
: HANDLE :Handle to the snapshot returned from a previous call to
the CreateToolhelp32Snapshot function.
Out Parameters	: HANDLE :returns HANDLE of Input Process if it exist.
Purpose			: This Function Retrives Handle of a process
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
HANDLE CEnumProcess::_GetProcID(CString csProcName, PROCESSENTRY32 pe32, HANDLE hSnapshot)
{
	try
	{
		HANDLE dProcId = 0;
		if(Process32First(hSnapshot, &pe32))
		{
			do
			{
				if((CString(pe32.szExeFile)).CompareNoCase (csProcName)== 0)
				{
					return dProcId =  OpenProcess(PROCESS_ALL_ACCESS, TRUE, pe32.th32ProcessID);
				}
			}while(Process32Next(hSnapshot, &pe32));
		}
		return dProcId;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::_GetProcID"));
	}
	return 0;
}

DWORD CEnumProcess::GetProcessIDByName(CString csProcName)
{
	try
	{
		DWORD dwProcID = 0;
		HandleRequest(csProcName, false, 0, 0, &dwProcID, true, false);
		return dwProcID;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::_GetProcID"));
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: RestoreExplorer
In Parameters	: -
Out Parameters	: void
Purpose			: This Function restore Explorer.exe
Author			: Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CEnumProcess::RestoreExplorer()
{
	try
	{
		WinExec("Explorer.exe",SW_NORMAL);
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::RestoreExplorer"));
	}

}

/*-------------------------------------------------------------------------------------
Function       : MyProcessModuleHandler
In Parameters  : DWORD, HANDLE, HANDLE, LPCTSTR, LPVOID, bool
Out Parameters : BOOL
Purpose		   : implements a callback function called to add modules name in the class
					local list
Author		   : Anand
-------------------------------------------------------------------------------------*/
BOOL CALLBACK MyProcessModuleHandler(DWORD dwProcessID, HANDLE hProcess, LPCTSTR szProcessPath,
									 HMODULE hModule, LPCTSTR szModulePath, LPVOID pThis, bool &bStopEnum)
{
	CEnumProcess * pEnumProc = (CEnumProcess*)pThis;
	pEnumProc->m_arrModules.Add(szModulePath);
	return (TRUE);
}

/*-------------------------------------------------------------------------------------
Function       : GetProcessModuleList
In Parameters  : DWORD dwProcessID - Process PID
CStringArray - Array of module list
Out Parameters : bool
Purpose		   : add the module names from the local class list to array argument
Author		   : Anand
-------------------------------------------------------------------------------------*/
bool CEnumProcess::GetProcessModuleList(DWORD dwProcessID, CStringArray &csarrModuleList,
										bool bIncludeExe)
{
	m_arrModules.RemoveAll();
	EnumProcessModuleList(dwProcessID, L"", (PROCESSMODULEHANDLER)MyProcessModuleHandler,
							this, bIncludeExe);
	for(int iCtr = 0; iCtr < m_arrModules.GetCount(); iCtr++)
	{
		csarrModuleList.Add(m_arrModules.GetAt(iCtr));
	}
	return (true);
}

/*-------------------------------------------------------------------------------------
Function       : EnumProcessModuleList
In Parameters  : DWORD, LPCTSTR, PROCESSMODULEHANDLER, LPVOID
Out Parameters : bool
Purpose		   : enumerate all the modules of the given process ID
Author		   : Anand
-------------------------------------------------------------------------------------*/
BOOL CEnumProcess::EnumProcessModuleList(DWORD dwProcessID, LPCTSTR szProcessPath,
										 PROCESSMODULEHANDLER pfProcModuleHandler, 
										 LPVOID lpThis, bool bIncludeExe)
{
	if(dwProcessID <= 0)
	{
		return false;
	}

	bool bStopScan = false;
	try
	{
		// If Windows NT 4.0
		if(osver.dwPlatformId == VER_PLATFORM_WIN32_NT && (osver.dwMajorVersion == 4 
			|| (osver.dwMajorVersion == 5 && osver.dwMinorVersion == 0)))
		{
			if(PSAPI)
			{
				HMODULE hModuleArray[1024];
				HANDLE  hProcess = NULL;
				DWORD   nModules = 0, cbNeeded = 0;

				// Let's open the process
				hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
										dwProcessID);
				if(!hProcess)
				{
					return false;
				}

				// EnumProcessModules function retrieves a handle for
				// each module in the specified process.
				if(!FEnumProcessModules(hProcess, hModuleArray, sizeof(hModuleArray), &cbNeeded))
				{
					::CloseHandle(hProcess);
					return false;
				}

				// Calculate number of modules in the process
				nModules = cbNeeded / sizeof(hModuleArray[0]);
				for(DWORD j = 1; j < nModules; j++)
				{
					if(bStopScan)
					{
						break;
					}
					HMODULE hModule = hModuleArray[j];
					TCHAR    szModulePath[MAX_PATH] = {0};
					TCHAR    szModuleName[MAX_PATH] = {0};
					FGetModuleFileNameEx(hProcess, hModule, szModulePath, _countof(szModuleName));
					if(pfProcModuleHandler)
					{
						if(bIncludeExe)
						{
							if(FGetModuleBaseName)
							{
								FGetModuleBaseName(hProcess, hModule, szModuleName,
													_countof(szModulePath));
							}
							CString csProcName = szModuleName;
							csProcName.MakeLower();
							if(csProcName.GetLength() >0 
								&& (csProcName.Right(4)== _T(".exe") 
								|| csProcName.Right(4)== _T(".dll")))
							{
								m_arrModules.Add(szModuleName);
							}
							else
							{
								m_arrModules.Add(_T(""));
							}
						}
						GetLongPathName(szModulePath, szModulePath, MAX_PATH);
						pfProcModuleHandler(dwProcessID, hProcess, szProcessPath, 
										hModule, szModulePath, lpThis, bStopScan);
					}
				}
				::CloseHandle(hProcess);
				return true;
			}
		}
		//Windows 9x, Windows 2000, Windows XP, Windows 2003
		else if(osver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS || 
			(osver.dwPlatformId == VER_PLATFORM_WIN32_NT && osver.dwMajorVersion > 4))
		{
			if(TOOLHELP)
			{
				BOOL			bReturnVal;
				HANDLE			hProcess = NULL;
				HANDLE			hModuleSnap = NULL;
				MODULEENTRY32	me32        = {0};

				hModuleSnap = FCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessID);
				if(hModuleSnap == INVALID_HANDLE_VALUE)
				{
					return false;
				}

				// Let's open the process
				hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
										dwProcessID);
				if(!hProcess)
				{
					CloseHandle(hModuleSnap);
					return false;
				}

				me32.dwSize = sizeof(MODULEENTRY32);
				bReturnVal = FModule32First(hModuleSnap, &me32);
				while(bReturnVal)
				{
					if(bStopScan)
					{
						break;
					}

					if(me32.hModule != INVALID_HANDLE_VALUE)
					{
						CString csProcName(me32.szExePath);
						csProcName.MakeLower();
						if(bIncludeExe || csProcName.Right(4) != ".exe")// Ignoring the exe name!
						{
							GetLongPathName(me32.szExePath, me32.szExePath, MAX_PATH);
							if(pfProcModuleHandler)
							{
								if(bIncludeExe && (csProcName.Right(4)== ".exe" || 
												csProcName.Right(4)== ".dll"))
								{
									m_arrModules.Add(me32.szModule);
								}
								else if(bIncludeExe)
								{
									m_arrModules.Add(_T(""));
								}
								pfProcModuleHandler(dwProcessID, hProcess, szProcessPath,
											me32.hModule, me32.szExePath, lpThis, bStopScan);
							}
						}
						bReturnVal = FModule32Next(hModuleSnap, &me32);
					}
					else
					{
						bReturnVal = false;
					}
				}
				CloseHandle(hProcess);
				CloseHandle(hModuleSnap);
				return bReturnVal;
			}
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in GetProcessModuleList"));
	}

	return (false);
}

/*-------------------------------------------------------------------------------------
Function       : StopSystemRestore
In Parameters  :
Out Parameters :
Purpose		   : stops the system restore option
Author		   : Anand
-------------------------------------------------------------------------------------*/
void CEnumProcess::StopSystemRestore(bool IsXP)
{
	SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); // Open Service Manager
	if(hSCM != NULL)
	{
		SC_HANDLE hService;
		if(IsXP)
		{
			hService = OpenService(hSCM, _T("srservice"), 
										SERVICE_ALL_ACCESS | SERVICE_STOP);
		}
		else
		{
			hService = OpenService(hSCM, _T("VSS"), 
										SERVICE_ALL_ACCESS | SERVICE_STOP);

		}
		if(hService != NULL)
		{
			SERVICE_STATUS ServiceStatus ={0};
			// get service names form service database managers
			ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus);
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hSCM);
	}
}

/*-------------------------------------------------------------------------------------
Function       : StartSystemRestore
In Parameters  :
Out Parameters :
Purpose		   : starts the system restore option
Author		   : Anand
-------------------------------------------------------------------------------------*/
void CEnumProcess::StartSystemRestore(bool IsXP)
{
	SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); // Open Service Manager
	if(hSCM != NULL)
	{
		SC_HANDLE hService;
		if(IsXP)
		{
			hService = OpenService(hSCM, _T("srservice"),
											SERVICE_ALL_ACCESS | SERVICE_START);
		}
		else
		{
			 hService = OpenService(hSCM, _T("VSS"),
											SERVICE_ALL_ACCESS | SERVICE_START);
		}
		if(hService != NULL)
		{
			StartService(hService, 0, 0);
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hSCM);
	}
}

/*-------------------------------------------------------------------------------------
Function       : IsOSWinNT
In Parameters  :
Out Parameters : bool
Purpose		   : return true if OS is WinNT else false
Author		   : Anand Srivastava
-------------------------------------------------------------------------------------*/
bool CEnumProcess::IsOSWinNT()
{
	if ((osver.dwPlatformId == VER_PLATFORM_WIN32_NT) &&
		(osver.dwMajorVersion == 4 || (osver.dwMajorVersion == 5 && osver.dwMinorVersion == 0)))
	{
		return true;
	}

	return false;
}

/*-------------------------------------------------------------------------------------
Function       : EnumAllThreadsInSystem
In Parameters  : THREADHANDLER, LPVOID
Out Parameters : bool
Purpose		   : enumerate all threads in the system
Author		   : Anand Srivastava
-------------------------------------------------------------------------------------*/
bool CEnumProcess::EnumAllThreadsInSystem(THREADHANDLER lpfnProcScanThreadHandler, LPVOID lpThis)
{

	try
	{
		bool bStopEnum = false;
		HANDLE hThreadSnap = 0, hProcess = 0;
		THREADENTRY32 TInfo = {0};
		TCHAR szProcImgPath[MAX_PATH] = {0};

		if(!m_lpfnGetModuleFileNameEx || !FCreateToolhelp32Snapshot || !FThread32First || !FThread32Next)
		{
			return false;
		}

		if(IsOSWinNT())
		{
			return false; // no implementation yet for WinNT
		}

		hThreadSnap = FCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if(INVALID_HANDLE_VALUE == hThreadSnap)
		{
			return false;
		}

		TInfo.dwSize = sizeof(THREADENTRY32);
		if(!FThread32First(hThreadSnap, &TInfo))
		{
			CloseHandle(hThreadSnap);
			return false;
		}

		do
		{
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, TInfo.th32OwnerProcessID);
			if(NULL == hProcess)
			{
				continue;
			}

			memset(szProcImgPath, 0, sizeof(szProcImgPath));
			m_lpfnGetModuleFileNameEx(hProcess, NULL, szProcImgPath, _countof(szProcImgPath));
			CloseHandle(hProcess);

			if(0 == szProcImgPath[0])
			{
				continue;
			}

			lpfnProcScanThreadHandler(TInfo.th32OwnerProcessID, TInfo.th32ThreadID, szProcImgPath, lpThis, bStopEnum);
		}while(!bStopEnum && FThread32Next(hThreadSnap, &TInfo));

		CloseHandle(hThreadSnap);
		return true;
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in CEnumProcess::EnumAllThreadsInSystem"));
	}

	return false;
}

BOOL CEnumProcess::SuspendProcess(DWORD dwProcID)
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

BOOL CEnumProcess::ResumeProcess(DWORD dwProcID)
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
			ResumeThread(hThread2Suspend);
			CloseHandle(hThread2Suspend);
		}
	} while(Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return TRUE;
}

void CEnumProcess::GetProcessNameByPid(ULONG uPid, TCHAR * strFinal)
{
	char pname_buf[MAX_PATH] = {0};
	HANDLE h_process = NULL;
	HMODULE hMods[1024] = {0};
	TCHAR str[MAX_PATH] = {0};
	ULONG n;

	h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, uPid);
	if(h_process)
	{
		if (h_process != NULL)
			FEnumProcessModules(h_process, hMods, 1024, &n);

		if(FGetModuleFileNameEx(h_process, hMods[0], str, MAX_PATH))
		{
		}
		CloseHandle(h_process);
	}
	return;
}