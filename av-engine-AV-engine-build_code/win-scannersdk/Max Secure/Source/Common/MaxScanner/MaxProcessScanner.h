#pragma once
#include "MaxConstant.h"
#include <processthreadsapi.h>
#include  <winternl.h>


#define	ObjectNameInformation						1
#define	SystemHandleInformation						16
#define	STATUS_INFO_LENGTH_MISMATCH					0xc0000004

const	int ThreadQuerySetWin32StartAddress = 0x09;

typedef LONG NTSTATUS;
typedef NTSTATUS (WINAPI *NTQUERYSYSTEMINFORMATION)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *NTDUPLICATEOBJECT)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (WINAPI *NTQUERYOBJECT)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *NTCLOSEHANDLE)(HANDLE);
typedef NTSTATUS (WINAPI *NTNETPWPATHCANONICALIZE)(LPVOID); 
typedef NTSTATUS (WINAPI *NTDNSQUERY_A)(LPVOID); 
typedef NTSTATUS (WINAPI *NTDNSQUERY_W)(LPVOID); 
typedef NTSTATUS (WINAPI *NTDNSQUERY_UTF8)(LPVOID); 
typedef NTSTATUS (WINAPI *NTQUERY_MAIN)(LPVOID); 

typedef struct 
{
	HANDLE			hHandle ;
	NTCLOSEHANDLE	pNtCloseHandle;	
}CLOSE_HANDLE_STRUCT, *PCLOSE_HANDLE_STRUCT;

//#ifndef _UNICODE_STRING
//typedef struct _UNICODE_STRING
//{
//    USHORT Length;
//    USHORT MaximumLength;
//    PWSTR Buffer;
//} UNICODE_STRING, *PUNICODE_STRING;
//#endif // !1

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
}SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef LONG NTSTATUS;

/*
typedef enum _THREAD_INFORMATION_CLASS
{
	ThreadBasicInformation = 0,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger
} THREAD_INFORMATION_CLASS, *PTHREAD_INFORMATION_CLASS;
*/

typedef NTSTATUS (WINAPI *LPFN_NTQUERYINFORMATIONTHREAD) (HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG );

#define SPY_ID_NIMNUL_A		(1547007)

typedef struct _KIDO_PARAM
{
	DWORD	dwKidoThreadBaseAddress;
	DWORD	dwKidoThreadID;
	DWORD	dwKidoMainThreadFound;
}KIDO_PARAM,*LPKIDO_PARAM;

class CMaxProcessScanner
{
	HMODULE m_hNtDll;
	LPFN_NTQUERYINFORMATIONTHREAD	m_lpfnNTQueryInformationThread;
	DWORD ScanBuffer(LPBYTE byBuffer, DWORD cbBuffer, PMAX_SCANNER_INFO pScanInfo);
	bool GetBytesFromOurProcess(DWORD dwAdress,int iDll2Load,BYTE *szBuff);
	KIDO_PARAM					m_objKidoParam;
	BOOL ScanThreadMemory4KidoInfection(BYTE *pszBuffer, DWORD dwBytes, DWORD ThreadAddrs, PMAX_SCANNER_INFO pScanInfo);
	BOOL m_bKidoInfectionFound;

#ifndef WIN64
	DWORD m_dwNtCreateFile;
	DWORD m_dwNtCreateProcess;
	DWORD m_dwNtCreateProcessEx;
	DWORD m_dwNtOpenFile;
	DWORD m_dwNtQueryInformationProcess;
	DWORD m_dwNtDeviceIOControlFile;
	DWORD m_dwDnsQuery_A;
	DWORD m_dwDnsQuery_W;
	DWORD m_dwDnsQuery_UTF8;
	DWORD m_dwQuery_Main;
	DWORD m_dwNetPathCanonicalize;

	bool m_bCheckHookedFunctions;
	bool GetFunctionAddress();
	void VerifyAndFixFunction(HANDLE hCurrProcess, DWORD dwFunctionAddress, DWORD dwProcessID, LPCTSTR szFunctionName);
	bool GetHookedFunctionOrdinal(BYTE *szBuff, DWORD dwBuffLen, DWORD *dwFuncOrdinal);

	NTQUERYSYSTEMINFORMATION	m_pNtQuerySystemInformation;
	NTDUPLICATEOBJECT			m_pNtDuplicateObject;
	NTQUERYOBJECT				m_pNtQueryObject;
	NTCLOSEHANDLE				m_pCloseHandle;
	CStringArray				m_csArrUserInitFilesList;
	CStringArray				m_csArrDeviceNames, m_csArrDosNames;

	bool AddNewInfectedNode(PMAX_SCANNER_INFO pScanInfo, LPCTSTR szParent, LPCTSTR szChild);
	bool InitNimnulScanning();
	bool ConvertDeviceNameToDosFileName(CString& csFilePath);
	bool InjectThreadnCloseHandle(HANDLE hProcHandle, HANDLE hReqHandle);
	bool Check4VirusHandle(LPCTSTR szFilePath, CStringArray& csArrOnlyFileName);
#endif //#ifndef WIN64

public:
	CMaxProcessScanner(void);
	virtual ~CMaxProcessScanner(void);

#ifndef WIN64
	void CheckFunctionAddress(PMAX_SCANNER_INFO pScanInfo);
	void CheckForNimnulHandles(PMAX_SCANNER_INFO pScanInfo);
#endif //#ifndef WIN64

	bool Init();
	bool DeInit();
	bool ScanThread(PMAX_SCANNER_INFO pScanInfo, bool &bStopEnum);
	BOOL IsKidoThreadFound();
	BOOL GetKidoInfectionStatus();
	void ResetKidoInfectionStatus();
};
