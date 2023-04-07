#pragma once
#include <TCHAR.H>
#include <malloc.h>
#include "MaxUtlConsts.h"
#include <tlhelp32.h>
#include "MemHookCheck.h"
//#include "MaxNimnul.h"
//#include "MaxVirusScanner.h"
#include "EjectModule.h"
/*
typedef enum _NTDLL_API_RVA
{
	NTDLL_NTCREATEFILE				= NTDLL_VIRTUAL_MEMADDR + 0xD682,
	NTDLL_NTCREATEPROCESS			= NTDLL_VIRTUAL_MEMADDR + 0xD754,
	NTDLL_NTCREATEPROCESSEx			= NTDLL_VIRTUAL_MEMADDR + 0xD769,
	NTDLL_NTOPENFILE				= NTDLL_VIRTUAL_MEMADDR + 0xDCFD,
	NTDLL_NTQUERYINFORMATIONPROCESS	= NTDLL_VIRTUAL_MEMADDR + 0xE01B,
	NTDLL_NTDEVICEIOCONTROLFILE		= NTDLL_VIRTUAL_MEMADDR + 0xD8E3
}NTDLL_API_RVA,*PNTDLL_API_RVA;
*/
typedef NTSTATUS (WINAPI *NTQUERYINFORMATIONTHREAD) (HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG ) ;
//typedef BOOL (WINAPI *LPFN_TerminateThread)(HANDLE hHandle, DWORD dwExitCode);
typedef NTSTATUS (WINAPI *LPFN_TerminateThread)(HANDLE hHandle, NTSTATUS dwExitCode);
typedef struct _PROCESS_LIST
{
	TCHAR		m_szProcPath[UTL_MAX_PATH];
	DWORD		m_dwPID;
	BOOL		m_bSystemProcess;
}PROCESS_LIST,*LPPROCESS_LIST;

typedef struct _MODULE_LIST
{
	TCHAR		m_szMdlPath[UTL_MAX_PATH];
}MODULE_LIST,*LPMODULE_LIST;

#ifndef ACTIVEPROTECTION
typedef struct _KIDO_PARAM
{
	DWORD	dwKidoThreadBaseAddress;
	DWORD	dwKidoThreadID;
	DWORD	dwKidoMainThreadFound;
}KIDO_PARAM,*LPKIDO_PARAM;
#endif

class CMaxMemoryScan
{
public:
	CMaxMemoryScan(void);
	~CMaxMemoryScan(void);
	PROCESS_LIST				**m_pProcList;
	DWORD						m_dwProcListCount;
	MODULE_LIST					**m_pMdlList;
	DWORD						m_dwMdlListCount;
	//DWORD						m_dwCurProcIndex;
	//DWORD						m_dwCurMdlIndex;
	//DWORD						m_dwCurHookCheckIndex;
	BOOL						m_bIsScannerLoaded;
	int							GetProcMemSnap();
	TCHAR						m_szWinDir[MAX_PATH];
	TCHAR						m_szSysDir[MAX_PATH];
	int							GetPhysicalPath(LPCTSTR pszLogicalPath,LPTSTR pszPhysicalPath);
	bool						Check4DuplicateEntries(LPCTSTR pszPath2Check);
	int							AddProcess2List(LPCTSTR pszPath2Add,DWORD dwPI);
	bool						Check4SystemFile(LPCTSTR pszPath2Check);
	int							EnumModulesofProcess(HANDLE	hProcess);
	int							AddModule2List(LPCTSTR pszPath2Add);
	bool						Check4DuplicateModuleEntries(LPCTSTR pszPath2Check);
	BOOL						ScanThreadMemoryEx(DWORD dwProcID);
	BOOL						SuspendProcess(DWORD dwProcID);
	BOOL						StopRunningProcess(DWORD dwPID2Check);
	BOOL						SuspendSimilarProcess(DWORD dwProcIndex);
	BOOL						CheckForWrongExecutionLocation(LPCTSTR pszPath2Check);
	BOOL						StopThreadSanning();
	BOOL						IsKidoThreadFound();
	BOOL						CreateFileCopy(LPCTSTR pszSrcFile, LPTSTR pszDestFile);
	BOOL						EjectDll(LPCTSTR pszDll2Eject);
	//BOOL						ScanSystemFile();

	//CMemHookCheck				m_MemHookCheck;

	BOOL						m_bIs64Bit;
	bool						ScanMemoryForCrypto(BOOL *bInfection,BOOL *bFixed,DWORD *pdwThreadID,LPTSTR pszVirName);

private:
	HMODULE						m_hNTDll;
	HMODULE						m_hKrnl32;
	NTQUERYINFORMATIONTHREAD	pNTQueryInformationThread;
	HANDLE						m_hThreadSnap; 
	THREADENTRY32				m_te32;
	WCHAR						szLogLine[UTL_MAX_PATH];
	LPFN_TerminateThread		pTerminateThread;
	KIDO_PARAM					m_objKidoParam;	

	BOOL						ScanThreadMemory4BabaxInfection(BYTE *pszBuffer,DWORD dwBytes);
	BOOL						FixInfectedThread(DWORD dwThID);
	void						SetDegubpriviledges();
};
