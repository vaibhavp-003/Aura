#include "pch.h"
#include "EjectModule.h"
#include "MaxMemoryScan.h"

DWORD g_dwProcCnt = 0;
DWORD g_dwProcArr[1024 * 2] = {0};

CEjectModule::CEjectModule()
{
	m_bShowErrors = false;
	m_bCheckOnlyName = false;
}

CEjectModule::~CEjectModule()
{
}

bool CEjectModule::EnablePrivilege(LPCTSTR szPrivilege)
{
	bool bReturn = false;
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp = {0}, tpOld = {0};
	DWORD cbOld = sizeof(tpOld);

	bReturn = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES, &hToken)? true:false;
	if(FALSE == bReturn || INVALID_HANDLE_VALUE == hToken)
	{
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if(!LookupPrivilegeValue(0, szPrivilege, &tp.Privileges[0].Luid))
	{
		CloseHandle(hToken);
		return false;
	}

	if(!AdjustTokenPrivileges(hToken, FALSE, &tp, cbOld, &tpOld, &cbOld))
	{
		CloseHandle(hToken);
		return false;
	}

	bReturn = ERROR_NOT_ALL_ASSIGNED != GetLastError();
	CloseHandle(hToken);
	return bReturn;
}

bool CEjectModule::KillThreadsOfThisModule(HANDLE hProcess, HMODULE hModule, DWORD dwProcID)
{
	HMODULE hNtDll = 0;
	DWORD dwReqSize = 0;
	MODULEINFO ModuleInfo = {0};
	bool bKillThreadSuccess = true;
	THREADENTRY32 ThreadEntry = {0};
	HANDLE hThread = 0, hSSThread = 0;
	LPBYTE lpThreadStart = 0, lpModStart = 0, lpModFinish = 0;
	LPFN_NTQUERYINFORMATIONTHREAD lpfnNTQueryInformationThread = NULL;

	hNtDll = GetModuleHandle(_T("NtDll.dll"));
	if(!hNtDll)
	{
		//if(m_bShowErrors) _tprintf_s(L"GetModuleHandle failed for NtDll.dll, ProcID: %u, GLE: %i\r\n", dwProcID, GetLastError());
		return false;
	}

	lpfnNTQueryInformationThread = (LPFN_NTQUERYINFORMATIONTHREAD)GetProcAddress(hNtDll, "NtQueryInformationThread");
	if(!lpfnNTQueryInformationThread)
	{
		//if(m_bShowErrors) _tprintf_s(L"GetProcAddress failed for NTQueryInformationThread, ProcID: %u, GLE: %i\r\n", dwProcID, GetLastError());
		return false;
	}

	if(!GetModuleInformation(hProcess, hModule, &ModuleInfo, sizeof(ModuleInfo)))
	{
		//if(m_bShowErrors) _tprintf_s(L"GetModuleInformation failed, ProcID: %u, GLE: %i\r\n", dwProcID, GetLastError());
		return false;
	}

	lpModStart = (LPBYTE)ModuleInfo.lpBaseOfDll;
	lpModFinish = (LPBYTE)(((SIZE_T)ModuleInfo.lpBaseOfDll) + ModuleInfo.SizeOfImage);

	hSSThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcID);
	if(INVALID_HANDLE_VALUE == hSSThread)
	{
		//if(m_bShowErrors) _tprintf_s(L"CreateToolhelp32Snapshot failed for threads, ProcID: %u, GLE: %i\r\n", dwProcID, GetLastError());
		return false;
	}

	ThreadEntry.dwSize = sizeof(ThreadEntry);
	if(!Thread32First(hSSThread, &ThreadEntry))
	{
		//if(m_bShowErrors) _tprintf_s(L"Thread32First failed, ProcID: %u, GLE: %i\r\n", dwProcID, GetLastError());
		CloseHandle(hSSThread);
		return false;
	}

	do
	{
		if(ThreadEntry.th32OwnerProcessID != dwProcID)
		{
			continue;
		}

		hThread = OpenThread(THREAD_QUERY_INFORMATION|THREAD_TERMINATE, FALSE, ThreadEntry.th32ThreadID);
		if(!hThread)
		{
			//if(m_bShowErrors) _tprintf_s(L"OpenThread failed, TID: %u, ProcID: %u, GLE: %i\r\n", ThreadEntry.th32ThreadID, dwProcID, GetLastError());
			continue;
		}

		lpfnNTQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS)ThreadQuerySetWin32StartAddress, &lpThreadStart, sizeof(lpThreadStart), &dwReqSize);
		if(!lpThreadStart)
		{
			//if(m_bShowErrors) _tprintf_s(L"lpfnNTQueryInformationThread failed, TID: %u, ProcID: %u, GLE: %i\r\n", ThreadEntry.th32ThreadID, dwProcID, GetLastError());
			CloseHandle(hThread);
			continue;
		}

		if(lpThreadStart >= lpModStart && lpThreadStart < lpModFinish)
		{
			if(!TerminateThread(hThread, 0))
			{
				bKillThreadSuccess = false;
				//_tprintf_s(L"\t[THD KIL FAILED] [ThrdID: %5u] [ProcID: %5u] GLE: %i\r\n", ThreadEntry.th32ThreadID, dwProcID, GetLastError());
			}
			else
			{
				//_tprintf_s(L"\t[THREAD  KILLED] [ThrdID: %5u] [ProcID: %5u]\r\n", ThreadEntry.th32ThreadID, dwProcID);
			}
		}

		CloseHandle(hThread);
	}while(Thread32Next(hSSThread, &ThreadEntry));

	CloseHandle(hSSThread);
	return bKillThreadSuccess;
}

bool CEjectModule::EjectThisModule(HANDLE hProcess, HMODULE hModule, DWORD dwProcID)
{
	DWORD dwThreadID = 0;
	HMODULE hkernel32 = NULL;
	LPVOID lpFreeLibrary = NULL;
	HANDLE hThread = 0;

	if(!KillThreadsOfThisModule(hProcess, hModule, dwProcID))
	{
		//if(m_bShowErrors) _tprintf_s(L"KillThreadsOfThisModule failed for ProcID: %u, GLE: %i\r\n", dwProcID, GetLastError());
		return false;
	}

	hkernel32 = GetModuleHandle(L"Kernel32.dll");
	if(!hkernel32)
	{
		//if(m_bShowErrors) _tprintf_s(L"GetModuleHandle failed, GLE: %i\r\n", GetLastError());
		return false;
	}

	lpFreeLibrary = GetProcAddress(hkernel32, "FreeLibrary");
	if(!lpFreeLibrary)
	{
		//if(m_bShowErrors) _tprintf_s(L"GetModuleHandle failed for FreeLibrary, GLE: %i\r\n", GetLastError());
		return false;
	}

	hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)lpFreeLibrary, hModule, 0, &dwThreadID);
	if(NULL == hThread)
	{
		//if(m_bShowErrors) _tprintf_s(L"CreateRemoteThread failed for ProcID: %i, GLE: %i\r\n", dwProcID, GetLastError());
		return false;
	}

	if(WAIT_OBJECT_0 != WaitForSingleObject(hThread, 1000 * 30))
	{
		TerminateThread(hThread, 0);
	}

	CloseHandle(hThread);
	return true;
}

bool CEjectModule::EnumerateModules(DWORD dwProcID, LPCTSTR szDllPath, bool& bDllFoundLoaded)
{
	HANDLE hProcess = NULL;
	HMODULE ModuleHandlesList[1024] = {0};
	DWORD dwSizeNeeded = 0;
	TCHAR szModulePath[MAX_PATH] = {0};
	LPCTSTR szOnlyName = NULL;
	DWORD dwDesiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
							PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

	hProcess = OpenProcess(dwDesiredAccess, FALSE, dwProcID);
	if(NULL == hProcess)
	{
		//if(m_bShowErrors) _tprintf_s(L"OpenProcess failed for ProcID: %i, GLE: %i\r\n", dwProcID, GetLastError());
		return false;
	}

	if(0 == EnumProcessModules(hProcess, ModuleHandlesList, sizeof(ModuleHandlesList), &dwSizeNeeded))
	{
		//if(m_bShowErrors) _tprintf_s(L"EnumProcessModules failed for ProcID: %i, GLE: %i\r\n", dwProcID, GetLastError());
		CloseHandle(hProcess);
		return false;
	}

	for(DWORD dwIndex = 0; dwIndex < dwSizeNeeded / sizeof(HMODULE); dwIndex++)
	{
		memset(szModulePath, 0, sizeof(szModulePath));
		if(0 == GetModuleFileNameEx(hProcess, ModuleHandlesList[dwIndex], szModulePath, _countof(szModulePath)))
		{
			//if(m_bShowErrors) _tprintf_s(L"GetModuleFileNameEx failed for ProcID: %i, ModHnd: %p, GLE: %i\r\n", dwProcID, ModuleHandlesList[dwIndex], GetLastError());
			continue;
		}

		if(m_bCheckOnlyName)
		{
			szOnlyName = _tcsrchr(szModulePath, _T('\\'));
			if(!szOnlyName)
			{
				szOnlyName = szModulePath;
			}
			else
			{
				szOnlyName++;
			}
		}
		else
		{
			szOnlyName = szModulePath;
		}

		if(_tcsicmp(szDllPath, szOnlyName))
		{
			continue;
		}

		bDllFoundLoaded = true;
		if(EjectThisModule(hProcess, ModuleHandlesList[dwIndex], dwProcID))
		{
			//_tprintf_s(L"\t[MODULE EJECTED] [ProcID: %5u] %s\r\n", dwProcID, szModulePath);
		}
		else
		{
			//_tprintf_s(L"\t[MOD EJT FAILED] [ProcID: %5u] %s\r\n", dwProcID, szModulePath);
		}
	}

	CloseHandle(hProcess);
	return true;
}

bool CEjectModule::IsProcessActive(DWORD dwProcID)
{
	bool bProcessActive = false;
	HANDLE hProcess = 0;
	DWORD dwExitCode = 0;

	if(0 == dwProcID || 4 == dwProcID)
	{
		return true;
	}

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, dwProcID);
	if(NULL == hProcess)
	{
		bProcessActive = GetLastError() != ERROR_INVALID_PARAMETER;
	}
	else
	{
		GetExitCodeProcess(hProcess, &dwExitCode);
		bProcessActive = dwExitCode == ERROR_NO_MORE_ITEMS;
		CloseHandle(hProcess);
	}

	return bProcessActive;
}

bool CEjectModule::EjectDllFromAllProcesses(LPCTSTR szDllPath, bool& bDllFoundLoaded)
{
	DWORD dwGap = 0, dwMaxGap = 2000;

	g_dwProcCnt = 0;
	memset(g_dwProcArr, 0, sizeof(g_dwProcArr));

	for(DWORD i = 0; dwGap < dwMaxGap && g_dwProcCnt < _countof(g_dwProcArr); i += sizeof(DWORD))
	{
		if(!IsProcessActive(i))
		{
			dwGap++;
			continue;
		}
		else
		{
			dwGap = 0;
			g_dwProcArr[g_dwProcCnt++] = i;
		}
	}

	for(DWORD dwIndex = 0; dwIndex < g_dwProcCnt; dwIndex++)
	{
		EnumerateModules(g_dwProcArr[dwIndex], szDllPath, bDllFoundLoaded);
	}

	return true;
}

bool CEjectModule::EjectModule(LPCTSTR szModFilePath)
{
	bool bSuccess = false, bDllFoundLoaded = false;
	int iMaxTries = 10;

#ifdef WIN64
	return false;
#endif


	if(!EnablePrivilege(SE_DEBUG_NAME))
	{
		//_tprintf_s(L"Error seting SE_DEBUG_NAME\r\n");
	}

	//_tprintf_s(L"\n");

	// + 1 to do one extra call to confirm if now module is ejected
	for(int i = 0; i < iMaxTries + 1; i++)
	{
		bDllFoundLoaded = false;
		if(EjectDllFromAllProcesses(szModFilePath, bDllFoundLoaded))
		{
			if(!bDllFoundLoaded)
			{
				bSuccess = true;
				break;
			}
		}
	}

	if(bSuccess)
	{
		//_tprintf_s(L"\nSuccessfully ejected module (%s).\r\n", szModFilePath);
	}
	else
	{
		//_tprintf_s(L"\nFailed to eject module (%s) even after %i tries.\r\n", szModFilePath, iMaxTries);
	}

	return bSuccess;
}
