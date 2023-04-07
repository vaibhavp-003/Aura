/*======================================================================================
FILE             : TaskHostScan.h
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
#pragma once
#include <TCHAR.H>
#include <malloc.h>
#include "tlhelp32.h"
#include "ReqStruct.h"
#define STRSAFE_LIB
#include <strsafe.h>

#pragma comment(lib, "strsafe.lib")
#pragma comment(lib, "legacy_stdio_definitions.lib")

#define UTL_MAX_PATH		1024
#define MAX_UNICODE_PATH	32767L


typedef struct _PROCESS_LIST1
{
	TCHAR		m_szProcPath[UTL_MAX_PATH];
	DWORD		m_dwPID;
}PROCESS_LIST1,*LPPROCESS_LIST1;

// Used in PEB struct
typedef ULONG smPPS_POST_PROCESS_INIT_ROUTINE;

// Used in PEB struct
typedef struct _smPEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} smPEB_LDR_DATA, *smPPEB_LDR_DATA;

// Used in PEB struct
typedef struct _smRTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} smRTL_USER_PROCESS_PARAMETERS, *smPRTL_USER_PROCESS_PARAMETERS;

// Used in PROCESS_BASIC_INFORMATION struct
typedef struct _smPEB {
BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	smPPEB_LDR_DATA Ldr;
	smPRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved4[104];
	PVOID Reserved5[52];
	smPPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved6[128];
	PVOID Reserved7[1];
	ULONG SessionId;
} smPEB, *smPPEB;

// Used with NtQueryInformationProcess
typedef struct _smPROCESS_BASIC_INFORMATION {
    LONG ExitStatus;
    smPPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} smPROCESS_BASIC_INFORMATION, *smPPROCESS_BASIC_INFORMATION;

 //NtQueryInformationProcess in NTDLL.DLL

//typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
//	IN	HANDLE ProcessHandle,
//    IN	PROCESSINFOCLASS ProcessInformationClass,
//    OUT	PVOID ProcessInformation,
//    IN	ULONG ProcessInformationLength,
//    OUT	PULONG ReturnLength	OPTIONAL
//    );

//NTQUERYINFORMATIONPROCESS gNtQueryInformationProcess1;

typedef struct _smPROCESSINFO
{
	DWORD	dwPID;
	DWORD	dwPEBBaseAddress;
	TCHAR	szImgPath[MAX_UNICODE_PATH];
	TCHAR	szCmdLine[MAX_UNICODE_PATH];
} smPROCESSINFO;


class CTaskHostScan
{
	PROCESS_LIST1				**m_pProcList;
	HMODULE						m_hNTDll;
	NTQUERYINFORMATIONPROCESS NtQueryInformationProcess;
public:
	CTaskHostScan(void);
	~CTaskHostScan(void);
	TCHAR						m_szWinDir[MAX_PATH];
	DWORD						m_dwProcListCount;
	DWORD						m_dwExplorerPID;
	TCHAR						m_szLogLine[1024];
	


BOOL						ScanTaskSVCHost();
int							GetProcMemSnap();
int							AddProcess2List(LPCTSTR pszPath2Add,DWORD dwPID);
int							GetPhysicalPath(LPCTSTR pszLogicalPath,LPTSTR pszPhysicalPath);
BOOL						SuspendProcess(DWORD dwProcID);
int							SetDebugPrivileges(void);
BOOL	CheckProcessCmdLine(DWORD dwProcIDIndex,LPCTSTR pszExePath);

BOOL	ScanScriptThread();

};
