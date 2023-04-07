#pragma once
#include "ReqStruct.h"
#include "Psapi.h"
#include <tlhelp32.h>
#include <processthreadsapi.h>

#ifndef ACTIVEPROTECTION
const int ThreadQuerySetWin32StartAddress = 0x09;
#endif

typedef NTSTATUS (WINAPI *LPFN_NTQUERYINFORMATIONTHREAD) (HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG );

class CEjectModule
{
public:

	CEjectModule();
	~CEjectModule();

	bool EjectModule(LPCTSTR szModFilePath);

private:

	bool m_bShowErrors;
	bool m_bCheckOnlyName;

	bool IsProcessActive(DWORD dwProcID);
	bool EnablePrivilege(LPCTSTR szPrivilege);
	bool KillThreadsOfThisModule(HANDLE hProcess, HMODULE hModule, DWORD dwProcID);
	bool EjectDllFromAllProcesses(LPCTSTR szDllPath, bool& bDllFoundLoaded);
	bool EnumerateModules(DWORD dwProcID, LPCTSTR szDllPath, bool& bDllFoundLoaded);
	bool EjectThisModule(HANDLE hProcess, HMODULE hModule, DWORD dwProcID);
};

