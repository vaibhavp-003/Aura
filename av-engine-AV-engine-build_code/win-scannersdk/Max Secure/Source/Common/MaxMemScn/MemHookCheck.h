#pragma once
#include "MaxLog.h"

typedef LONG NTSTATUS;
typedef NTSTATUS (WINAPI *NTCREATEFILE)(LPVOID); 
const  DWORD NTDLL_VIRTUAL_MEMADDR = 0x7C900000;

typedef enum _NTDLL_API_RVA
{
	NTDLL_NTCREATEFILE				= NTDLL_VIRTUAL_MEMADDR + 0xD682,
	NTDLL_NTCREATEPROCESS			= NTDLL_VIRTUAL_MEMADDR + 0xD754,
	NTDLL_NTCREATEPROCESSEx			= NTDLL_VIRTUAL_MEMADDR + 0xD769,
	NTDLL_NTOPENFILE				= NTDLL_VIRTUAL_MEMADDR + 0xDCFD,
	NTDLL_NTQUERYINFORMATIONPROCESS	= NTDLL_VIRTUAL_MEMADDR + 0xE01B,
	NTDLL_NTDEVICEIOCONTROLFILE		= NTDLL_VIRTUAL_MEMADDR + 0xD8E3,
	NETAPI_NETPWPATHCANOCALIZE		= NTDLL_VIRTUAL_MEMADDR + 0xE000,
	DNSAPI_DNSQUERY_A				= 0x1000,
	DNSAPI_DNSQUERY_W				= 0x1001,
	DNSAPI_DNSQUERY_UTF8			= 0x1002,
	DNSAPI_QUERY_MAIN				= 0x1003,
	KNLAPI_CREATEFILEW				= 0x1004,
	ADVPAPI_OPENSERVICEA			= 0x1005,
	ADVPAPI_OPENSERVICEW			= 0x1006,
	ADVPAPI_CREATESERVICEA			= 0x1007,
	ADVPAPI_CREATESERVICEW			= 0x1008
}NTDLL_API_RVA,*PNTDLL_API_RVA;

class CMemHookCheck
{
public:
	CMemHookCheck(void);
	~CMemHookCheck(void);
private:
	NTCREATEFILE	m_pNTCreateFile;
	HMODULE			m_hNTDll;
	DWORD			m_dwNtCreateFile;
	DWORD			m_dwNtCreateProcess;
	DWORD			m_dwNtCreateProcessEx;
	DWORD			m_dwNtOpenFile;
	DWORD			m_dwNtQueryInformationProcess;
	DWORD			m_dwNtDeviceIOControlFile;
	DWORD			m_dwDnsQuery_A;
	DWORD			m_dwDnsQuery_W;
	DWORD			m_dwDnsQuery_UTF8;
	DWORD			m_dwQuery_Main;

	DWORD			m_dwCreateFileW;
	DWORD			m_dwOpenServiceW;
	DWORD			m_dwOpenServiceA;
	DWORD			m_dwCreateServiceW;
	DWORD			m_dwCreateServiceA;

	DWORD			m_dwNetPathCanonicalize;
	CMaxLog			m_MaxLog;
	bool			FixHookedAPI(DWORD dwProcID,DWORD dwHookID);
	bool			GetHookedFunctionOrdinal(BYTE *szBuff,DWORD dwBuffLen,DWORD *dwFuncOrdinal);
	bool			GetBytesFromOurProcess(DWORD dwAdress,int iDll2Load,BYTE *szBuff);
public:
	DWORD			Check4HookedAPI(DWORD dwProcID,DWORD *dwInfFound,DWORD *dwInfClean);
	
};
