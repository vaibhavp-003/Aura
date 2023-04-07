/*=============================================================================
   FILE			: Enumprocess.h
   ABSTRACT		: This class will provide the enumeration of current processes
   DOCUMENTS	: 
   AUTHOR		: Darshan Singh Virdi
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
VERSION HISTORY	: 21 Aug 2007, Avinash B
				   Unicode Supported
============================================================================*/
#pragma once

#include <tlhelp32.h>
#include <winsvc.h>

typedef BOOL (CALLBACK *THREADHANDLER)(DWORD dwProcessID, DWORD dwThreadID, LPCTSTR szProcImgPath, LPVOID pThis, bool &bStopEnum);

typedef BOOL (CALLBACK *PROCESSHANDLER)(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, LPVOID pThis, bool &bStopEnum);

//Version: 2.5.0.2
//Resource: Anand
typedef BOOL (CALLBACK *PROCESSMODULEHANDLER)(DWORD dwProcessID, HANDLE hProcess, LPCTSTR szProcessPath, HMODULE hModule, LPCTSTR szModulePath, LPVOID pThis, bool &bStopEnum);

// Functions loaded from PSAPI
typedef BOOL (WINAPI *PFEnumProcesses)(DWORD * lpidProcess, DWORD cb, DWORD * cbNeeded);
typedef BOOL (WINAPI *PFEnumProcessModules)(HANDLE hProcess, HMODULE * lphModule, DWORD cb, LPDWORD lpcbNeeded);
typedef DWORD (WINAPI *PFGetModuleFileNameEx)(HANDLE hProcess, HMODULE hModule, LPTSTR lpFilename, DWORD nSize);
typedef DWORD (WINAPI *PFGetModuleBaseName)(HANDLE hProcess, HMODULE hModule, LPTSTR lpFilename, DWORD nSize);

//Functions loaded from Kernel32
typedef HANDLE (WINAPI *PFCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL (WINAPI *PFProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL (WINAPI *PFProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
typedef BOOL (WINAPI *PFModule32First)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef BOOL (WINAPI *PFModule32Next)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef BOOL (WINAPI *PFThread32First)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
typedef BOOL (WINAPI *PFThread32Next)(HANDLE hSnapshot, LPTHREADENTRY32 lpte);

class CEnumProcess
{
public:
	CEnumProcess();
	virtual ~CEnumProcess();

	bool EnumAllThreadsInSystem(THREADHANDLER ProcScanThreadHandler, LPVOID lpThis);
	bool EnumRunningProcesses(PROCESSHANDLER lpProc, LPVOID pThis);
	bool IsProcessRunning(CString sProcName, bool bTerminateProcess,bool bIsFullPath = true,bool bTerminateTree = false);
	bool KillProcess(DWORD ProcessID);
	void RebootSystem(DWORD dwType = 0);
	bool KillExplorer();
	void RestoreExplorer();
	BOOL EnablePrivilege(LPCTSTR szPrivilege);
	DWORD GetProcessIDByName(CString csProcName);

	bool GetProcessModuleList(DWORD dwProcessID, CStringArray &csarrModuleList,bool bIncludeExe = false);
	BOOL EnumProcessModuleList(DWORD dwProcessID, LPCTSTR szProcessPath, PROCESSMODULEHANDLER pfProcModuleHandler, LPVOID lpThis, bool bIncludeExe = false);
	void GetProcessNameByPid(ULONG uPid, TCHAR * strFinal);
	unsigned int m_iNoOfInstances;
	CStringArray m_arrModules;
	void StopSystemRestore(bool IsXP = true);
	void StartSystemRestore(bool IsXP = true);
	BOOL SuspendProcess(DWORD dwProcID);
	BOOL ResumeProcess(DWORD dwProcID);

private:
	HMODULE						PSAPI;
	PFEnumProcesses				FEnumProcesses;				// Pointer to EnumProcess
	PFEnumProcessModules		FEnumProcessModules;		// Pointer to EnumProcessModules
	PFGetModuleFileNameEx		FGetModuleFileNameEx;		// Pointer to GetModuleFileNameEx
	PFGetModuleBaseName         FGetModuleBaseName;		// Pointer to GetModuleFileName

	HMODULE						TOOLHELP;					//Handle to the module (Kernel32)
	PFCreateToolhelp32Snapshot	FCreateToolhelp32Snapshot;
	PFProcess32First			FProcess32First;
	PFProcess32Next				FProcess32Next;
	PFModule32First				FModule32First;
	PFModule32Next				FModule32Next;
	PFThread32First				FThread32First;
	PFThread32Next				FThread32Next;

	OSVERSIONINFO  osver;
	DWORD m_idExplorer;
	DWORD m_idSms;

	bool InitProcessDll();
	bool FreeProcessDll();
	bool GetProcessModule(DWORD dwPID, LPCTSTR pstrModule, LPMODULEENTRY32 lpMe32, DWORD cbMe32);
	BOOL EnableTokenPrivilege(HANDLE htok, LPCTSTR szPrivilege, TOKEN_PRIVILEGES *tpOld);
	bool HandleRequest(CString sProcName = CString(_T("")), bool bTerminateProcess = false, PROCESSHANDLER lpProc = NULL, LPVOID pThis = NULL, LPDWORD pdwProdID = NULL,bool bIsFullPath = true,bool bTerminateTree = false);
	HANDLE _GetProcID(CString csProcName, PROCESSENTRY32 pe32, HANDLE hSnapshot);

	HMODULE m_hModPSAPI;
	PFGetModuleFileNameEx m_lpfnGetModuleFileNameEx;
	bool IsOSWinNT();
};
