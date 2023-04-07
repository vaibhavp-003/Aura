#include "StdAfx.h"
#include "MemHookCheck.h"

CMemHookCheck::CMemHookCheck(void)
{
	m_pNTCreateFile = NULL;
	m_hNTDll = NULL;

	m_hNTDll = LoadLibrary(_T("NtDll.Dll"));
	if(m_hNTDll != NULL)
	{
		m_pNTCreateFile = NULL;
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "NtCreateFile");
		if(m_pNTCreateFile != NULL)
		{
			m_dwNtCreateFile = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "NtCreateProcess");
		if(m_pNTCreateFile != NULL)
		{
			m_dwNtCreateProcess = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "NtCreateProcessEx");
		if(m_pNTCreateFile != NULL)
		{
			m_dwNtCreateProcessEx = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "NtOpenFile");
		if(m_pNTCreateFile != NULL)
		{
			m_dwNtOpenFile = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "NtQueryInformationProcess");
		if(m_pNTCreateFile != NULL)
		{
			m_dwNtQueryInformationProcess = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		
		//dwNtDeviceIOControlFile = dwNtCreateFile + 0x261;
			
		FreeLibrary(m_hNTDll);
	}
	m_hNTDll = NULL;
	m_hNTDll = LoadLibrary(_T("netapi32.dll"));
	if(m_hNTDll != NULL)
	{
		m_pNTCreateFile = NULL;
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "NetpwPathCanonicalize");
		if(m_pNTCreateFile != NULL)
		{
			m_dwNetPathCanonicalize = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		FreeLibrary(m_hNTDll);
	}

	m_hNTDll = NULL;
	m_hNTDll = LoadLibrary(_T("dnsapi.dll"));
	if(m_hNTDll != NULL)
	{
		m_pNTCreateFile = NULL;
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "DnsQuery_A");
		if(m_pNTCreateFile != NULL)
		{
			m_dwDnsQuery_A = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		m_pNTCreateFile = NULL;
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "DnsQuery_W");
		if(m_pNTCreateFile != NULL)
		{
			m_dwDnsQuery_W = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		m_pNTCreateFile = NULL;
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "DnsQuery_UTF8");
		if(m_pNTCreateFile != NULL)
		{
			m_dwDnsQuery_UTF8 = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		m_pNTCreateFile = NULL;
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "Query_Main");
		if(m_pNTCreateFile != NULL)
		{
			m_dwQuery_Main = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		FreeLibrary(m_hNTDll);
	}

	//API Hookings check for Pioneer
	m_hNTDll = NULL;
	m_hNTDll = LoadLibrary(_T("Kernel32.dll"));
	if(m_hNTDll != NULL)
	{
		m_pNTCreateFile = NULL;
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "CreateFileW");
		if(m_pNTCreateFile != NULL)
		{
			m_dwCreateFileW = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		FreeLibrary(m_hNTDll);
	}

	m_hNTDll = NULL;
	m_hNTDll = LoadLibrary(_T("Advapi32.Dll"));
	if(m_hNTDll != NULL)
	{
		m_pNTCreateFile = NULL;
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "OpenServiceW");
		if(m_pNTCreateFile != NULL)
		{
			m_dwOpenServiceW = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		m_pNTCreateFile = NULL;
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "OpenServiceA");
		if(m_pNTCreateFile != NULL)
		{
			m_dwOpenServiceA = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		m_pNTCreateFile = NULL;
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "CreateServiceW");
		if(m_pNTCreateFile != NULL)
		{
			m_dwCreateServiceW = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		m_pNTCreateFile = NULL;
		m_pNTCreateFile = (NTCREATEFILE) GetProcAddress(m_hNTDll, "CreateServiceA");
		if(m_pNTCreateFile != NULL)
		{
			m_dwCreateServiceA = (DWORD)m_pNTCreateFile;
			m_pNTCreateFile = NULL;
		}
		FreeLibrary(m_hNTDll);
	}
}

CMemHookCheck::~CMemHookCheck(void)
{
}


DWORD CMemHookCheck::Check4HookedAPI(DWORD dwProcID,DWORD *dwInfFound,DWORD *dwInfClean)
{
	DWORD		dwRet = 0x00;
	DWORD		dwFixed = 0x00;
	HANDLE		hCurrProcess = NULL;
	BYTE		szNtCreateFile[0x06] = {0};
	BYTE		szNtCreateProcess[0x06] = {0};
	BYTE		szNtCreateProcessEx[0x06] = {0};
	BYTE		szNtOpenFile[0x06] = {0};
	BYTE		szNtQueryInformationProcess[0x06] = {0};
	BYTE		szNtDeviceIOControlFile[0x06] = {0};
	BYTE		szNetpwPathCanocalize[0x06] = {0};
	BYTE		szDnsQuery_A[0x06] = {0};
	BYTE		szDnsQuery_W[0x06] = {0};
	BYTE		szDnsQuery_UTF8[0x06] = {0};
	BYTE		szQuery_Main[0x06] = {0};

	BYTE		szCreateFleW[0x06] = {0};
	BYTE		szOpenServiceW[0x06] = {0};
	BYTE		szOpenServiceA[0x06] = {0};
	BYTE		szCreateServiceA[0x06] = {0};
	BYTE		szCreateServiceW[0x06] = {0};

	SIZE_T		dwBytesRead = 0x00;
	bool		bInfectionFound = false;
	WCHAR		strLogLine[1024] = {0}; 
	
	if (dwProcID < 0x08)
		return dwRet;

	hCurrProcess = NULL;
	hCurrProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, dwProcID);
	if (NULL == hCurrProcess)
		return dwRet;

	if (m_dwNetPathCanonicalize != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwNetPathCanonicalize, (LPVOID)szNetpwPathCanocalize, 0x05, &dwBytesRead);
	if (m_dwDnsQuery_A != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwDnsQuery_A, (LPVOID)szDnsQuery_A, 0x05, &dwBytesRead);
	if (m_dwDnsQuery_W != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwDnsQuery_W, (LPVOID)szDnsQuery_W, 0x05, &dwBytesRead);
	if (m_dwDnsQuery_UTF8 != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwDnsQuery_UTF8, (LPVOID)szDnsQuery_UTF8, 0x05, &dwBytesRead);
	if (m_dwQuery_Main != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwQuery_Main, (LPVOID)szQuery_Main, 0x05, &dwBytesRead);

	if (m_dwNtCreateFile != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwNtCreateFile, (LPVOID)szNtCreateFile, 0x05, &dwBytesRead);
	if (m_dwNtCreateProcess != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwNtCreateProcess, (LPVOID)szNtCreateProcess, 0x05, &dwBytesRead);
	if (m_dwNtCreateProcessEx != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwNtCreateProcessEx, (LPVOID)szNtCreateProcessEx, 0x05, &dwBytesRead);
	if (m_dwNtOpenFile != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwNtOpenFile, (LPVOID)szNtOpenFile, 0x05, &dwBytesRead);
	if (m_dwNtQueryInformationProcess != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwNtQueryInformationProcess, (LPVOID)szNtQueryInformationProcess, 0x05, &dwBytesRead);

	if (m_dwCreateFileW != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwCreateFileW, (LPVOID)szCreateFleW, 0x05, &dwBytesRead);
	if (m_dwOpenServiceA != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwOpenServiceA, (LPVOID)szOpenServiceA, 0x05, &dwBytesRead);
	if (m_dwOpenServiceW != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwOpenServiceW, (LPVOID)szOpenServiceW, 0x05, &dwBytesRead);
	if (m_dwCreateServiceA != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwCreateServiceA, (LPVOID)szCreateServiceA, 0x05, &dwBytesRead);
	if (m_dwCreateServiceW != 0x00)
		ReadProcessMemory(hCurrProcess, (void *)m_dwCreateServiceW, (LPVOID)szCreateServiceW, 0x05, &dwBytesRead);
	
	CloseHandle(hCurrProcess);
	if(dwBytesRead != 0x00)
	{
		//1 ==> NTCreateFile
		if (szNtCreateFile[0x00] == 0xE8)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found NtCreateFile API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);

			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,NTDLL_NTCREATEFILE))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed NtCreateFile API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed NtCreateFile API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}
		
		//2 ==> NTCreateProcess
		if (szNtCreateProcess[0x00] == 0xE8)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found NtCreateProcess API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,NTDLL_NTCREATEPROCESS))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed NtCreateProcess API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed NtCreateProcess API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}

		//3 ==> NTCreateProcessEx
		if (szNtCreateProcessEx[0x00] == 0xE8)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found NtCreateProcessEx API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,NTDLL_NTCREATEPROCESSEx))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed NtCreateProcessEx API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed NtCreateProcessEx API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}

		
		//5 ==> NTOpenFile
		if (szNtOpenFile[0x00] == 0xE8)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found NtOpenFile API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,NTDLL_NTOPENFILE))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed NtOpenFile API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed NtOpenFile API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}

		//6 ==> NTQueryInformationProcess
		if (szNtQueryInformationProcess[0x00] == 0xE8 || szNtQueryInformationProcess[0x00] == 0xE9)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found NtQueryInformationProcess API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,NTDLL_NTQUERYINFORMATIONPROCESS))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed NtQueryInformationProcess API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed NtQueryInformationProcess API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}
		if (szNetpwPathCanocalize[0x00] == 0xE9)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found NetpwPathCanocalize API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,NETAPI_NETPWPATHCANOCALIZE))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed NetpwPathCanocalize API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed NetpwPathCanocalize API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}
		if (szDnsQuery_A[0x00] == 0xE9)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found DnsQuery_A API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,DNSAPI_DNSQUERY_A))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed DnsQuery_A API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed DnsQuery_A API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}
		if (szDnsQuery_W[0x00] == 0xE9)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found DnsQuery_W API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,DNSAPI_DNSQUERY_W))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed DnsQuery_W API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed DnsQuery_W API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}
		if (szDnsQuery_UTF8[0x00] == 0xE9)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found DnsQuery_UTF8 API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,DNSAPI_DNSQUERY_UTF8))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed DnsQuery_UTF8 API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed DnsQuery_UTF8 API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}
		if (szQuery_Main[0x00] == 0xE9)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found QueryMain API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,DNSAPI_QUERY_MAIN))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed QueryMain API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed QueryMain API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}

		//Pioneer
		if (szCreateFleW[0x00] == 0xE8)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found CreateFileW API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,KNLAPI_CREATEFILEW))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed CreateFileW API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed CreateFileW API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}
		if (szCreateServiceA[0x00] != 0x8B && szCreateServiceA[0x00] != 0x6A)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found CreateServiceA API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,ADVPAPI_CREATESERVICEA))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed CreateServiceA API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed CreateServiceA API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}
		if (szCreateServiceW[0x00] != 0x8B && szCreateServiceW[0x00] != 0x6A)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found CreateServiceW API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,ADVPAPI_CREATESERVICEW))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed CreateServiceW API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed CreateServiceW API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}
		if (szOpenServiceA[0x00] != 0x8B && szOpenServiceA[0x00] != 0x6A)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found OpenServiceA API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,ADVPAPI_OPENSERVICEA))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed OpenServiceA API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed OpenServiceA API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}
		if (szOpenServiceW[0x00] != 0x8B && szOpenServiceW[0x00] != 0x6A)
		{
			dwRet++;
			_stprintf_s(strLogLine,L"Hooked API  : Found OpenServiceW API Hooked in %lu",dwProcID);
			m_MaxLog.Write2Log(strLogLine);
			bInfectionFound = true;
			if (FixHookedAPI(dwProcID,ADVPAPI_OPENSERVICEW))
			{
				dwFixed++;
				_stprintf_s(strLogLine,L"Repaired	: Removed OpenServiceW API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
			else
			{
				_stprintf_s(strLogLine,L"Failed	: Failed to removed OpenServiceW API Hooked from %lu process",dwProcID);
				m_MaxLog.Write2Log(strLogLine);
			}
		}

	}	

	*dwInfFound = dwRet;
	*dwInfClean = dwFixed;

	return dwRet;
}

bool CMemHookCheck::FixHookedAPI(DWORD dwProcID,DWORD dwHookID)
{
	HANDLE	hProcess = NULL;
	BYTE	szCall2Patched[] = {0xB8};
	DWORD	dwAddress2Patch = 0x00;
	SIZE_T	dwBytesWritten = 0x00;
	BYTE	szByteOrdinal[0x1A] = {0};
	SIZE_T	dwBytesRead = 0x00;
	BYTE	byOriginalByte[0x05] = {0x8B,0xFF,0x55,0x8B,0xEC};
	bool	bResult = false;

	if (dwProcID < 0x08)
		return false;

	//if (dwProcID != GetCurrentProcessId())
	//	return true;

	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,FALSE,dwProcID);
	if (NULL == hProcess)
		return false;

	switch(dwHookID)
	{
	case NTDLL_NTCREATEFILE:
		dwAddress2Patch = 0x00;
		bResult = false;
		if ((m_dwNtCreateFile - 0x19) > 0x00)
		{
			ReadProcessMemory(hProcess, (void *)(m_dwNtCreateFile - 0x19), (LPVOID)szByteOrdinal, 0x19, &dwBytesRead);
			if (GetHookedFunctionOrdinal(szByteOrdinal,dwBytesRead,&dwAddress2Patch))
			{
				if (dwAddress2Patch > 0x00)
				{
					dwAddress2Patch++;
					bResult = true;
					WriteProcessMemory(hProcess,(LPVOID)m_dwNtCreateFile,(LPCVOID)szCall2Patched,0x01,&dwBytesWritten);
					WriteProcessMemory(hProcess,(LPVOID)(m_dwNtCreateFile + 0x01),(LPCVOID)&dwAddress2Patch,sizeof(DWORD),&dwBytesWritten);
				}
			}
		}
		break;
	case NTDLL_NTCREATEPROCESS:
		dwAddress2Patch = 0x00;
		bResult = false;
		if ((m_dwNtCreateProcess - 0x19) > 0x00)
		{
			ReadProcessMemory(hProcess, (void *)(m_dwNtCreateProcess - 0x19), (LPVOID)szByteOrdinal, 0x19, &dwBytesRead);
			if (GetHookedFunctionOrdinal(szByteOrdinal,dwBytesRead,&dwAddress2Patch))
			{
				if (dwAddress2Patch > 0x00)
				{
					dwAddress2Patch++;
					bResult = true;
					WriteProcessMemory(hProcess,(LPVOID)m_dwNtCreateProcess,(LPCVOID)szCall2Patched,0x01,&dwBytesWritten);
					WriteProcessMemory(hProcess,(LPVOID)(m_dwNtCreateProcess + 0x01),(LPCVOID)&dwAddress2Patch,sizeof(DWORD),&dwBytesWritten);
				}
			}
		}
		break;
	case NTDLL_NTCREATEPROCESSEx:
		dwAddress2Patch = 0x00;
		bResult = false;
		if ((m_dwNtCreateProcessEx - 0x19) > 0x00)
		{
			ReadProcessMemory(hProcess, (void *)(m_dwNtCreateProcessEx - 0x19), (LPVOID)szByteOrdinal, 0x19, &dwBytesRead);
			if (GetHookedFunctionOrdinal(szByteOrdinal,dwBytesRead,&dwAddress2Patch))
			{
				if (dwAddress2Patch > 0x00)
				{
					dwAddress2Patch++;
					bResult = true;
					WriteProcessMemory(hProcess,(LPVOID)m_dwNtCreateProcessEx,(LPCVOID)szCall2Patched,0x01,&dwBytesWritten);
					WriteProcessMemory(hProcess,(LPVOID)(m_dwNtCreateProcessEx + 0x01),(LPCVOID)&dwAddress2Patch,sizeof(DWORD),&dwBytesWritten);
				}
			}
		}
		break;
	case NTDLL_NTDEVICEIOCONTROLFILE:
		break;
	case NTDLL_NTOPENFILE:
		dwAddress2Patch = 0x00;
		bResult = false;
		if ((m_dwNtOpenFile - 0x19) > 0x00)
		{
			ReadProcessMemory(hProcess, (void *)(m_dwNtOpenFile - 0x19), (LPVOID)szByteOrdinal, 0x19, &dwBytesRead);
			if (GetHookedFunctionOrdinal(szByteOrdinal,dwBytesRead,&dwAddress2Patch))
			{
				if (dwAddress2Patch > 0x00)
				{
					dwAddress2Patch++;
					bResult = true;
					WriteProcessMemory(hProcess,(LPVOID)m_dwNtOpenFile,(LPCVOID)szCall2Patched,0x01,&dwBytesWritten);
					WriteProcessMemory(hProcess,(LPVOID)(m_dwNtOpenFile+ 0x01),(LPCVOID)&dwAddress2Patch,sizeof(DWORD),&dwBytesWritten);
				}
			}
		}
		break;

	case NTDLL_NTQUERYINFORMATIONPROCESS:
		dwAddress2Patch = 0x00;
		bResult = false;
		if ((m_dwNtQueryInformationProcess - 0x19) > 0x00)
		{
			ReadProcessMemory(hProcess, (void *)(m_dwNtQueryInformationProcess - 0x19), (LPVOID)szByteOrdinal, 0x19, &dwBytesRead);
			if (GetHookedFunctionOrdinal(szByteOrdinal,dwBytesRead,&dwAddress2Patch))
			{
				if (dwAddress2Patch > 0x00)
				{
					dwAddress2Patch++;
					bResult = true;
					WriteProcessMemory(hProcess,(LPVOID)m_dwNtQueryInformationProcess,(LPCVOID)szCall2Patched,0x01,&dwBytesWritten);
					WriteProcessMemory(hProcess,(LPVOID)(m_dwNtQueryInformationProcess + 0x01),(LPCVOID)&dwAddress2Patch,sizeof(DWORD),&dwBytesWritten);
				}
			}
		}
		break;
	
	case NETAPI_NETPWPATHCANOCALIZE:
		dwAddress2Patch = 0x00;
		bResult = false;
		if (GetBytesFromOurProcess(m_dwNetPathCanonicalize,1,&szByteOrdinal[0x00]))
		{
			bResult = true;
			WriteProcessMemory(hProcess,(LPVOID)m_dwNetPathCanonicalize,(LPCVOID)szByteOrdinal,0x05,&dwBytesWritten);
		}
		break;
	case DNSAPI_DNSQUERY_A:
		dwAddress2Patch = 0x00;
		bResult = false;
		if (GetBytesFromOurProcess(m_dwDnsQuery_A,2,&szByteOrdinal[0x00]))
		{
			bResult = true;
			WriteProcessMemory(hProcess,(LPVOID)m_dwDnsQuery_A,(LPCVOID)szByteOrdinal,0x05,&dwBytesWritten);
		}
		break;
	case DNSAPI_DNSQUERY_W:
		dwAddress2Patch = 0x00;
		bResult = false;
		if (GetBytesFromOurProcess(m_dwDnsQuery_W,2,&szByteOrdinal[0x00]))
		{
			bResult = true;
			WriteProcessMemory(hProcess,(LPVOID)m_dwDnsQuery_W,(LPCVOID)szByteOrdinal,0x05,&dwBytesWritten);
		}
		break;
	case DNSAPI_DNSQUERY_UTF8:
		dwAddress2Patch = 0x00;
		bResult = false;
		if (GetBytesFromOurProcess(m_dwDnsQuery_UTF8,2,&szByteOrdinal[0x00]))
		{
			bResult = true;
			WriteProcessMemory(hProcess,(LPVOID)m_dwDnsQuery_UTF8,(LPCVOID)szByteOrdinal,0x05,&dwBytesWritten);
		}
		break;
	case DNSAPI_QUERY_MAIN:
		dwAddress2Patch = 0x00;
		bResult = false;
		if (GetBytesFromOurProcess(m_dwQuery_Main,2,&szByteOrdinal[0x00]))
		{
			bResult = true;
			WriteProcessMemory(hProcess,(LPVOID)m_dwQuery_Main,(LPCVOID)szByteOrdinal,0x05,&dwBytesWritten);
		}
		break;
	case KNLAPI_CREATEFILEW:
		dwAddress2Patch = 0x00;
		bResult = WriteProcessMemory(hProcess,(LPVOID)m_dwCreateFileW,(LPCVOID)byOriginalByte,0x05,&dwBytesWritten);
		break;
	case ADVPAPI_OPENSERVICEA:
		dwAddress2Patch = 0x00;
		bResult = WriteProcessMemory(hProcess,(LPVOID)m_dwOpenServiceA,(LPCVOID)byOriginalByte,0x05,&dwBytesWritten);
		break;
	case ADVPAPI_OPENSERVICEW:
		dwAddress2Patch = 0x00;
		bResult = WriteProcessMemory(hProcess,(LPVOID)m_dwOpenServiceW,(LPCVOID)byOriginalByte,0x05,&dwBytesWritten);
		break;
	case ADVPAPI_CREATESERVICEA:
		dwAddress2Patch = 0x00;
		bResult = WriteProcessMemory(hProcess,(LPVOID)m_dwCreateServiceA,(LPCVOID)byOriginalByte,0x05,&dwBytesWritten);
		break;
	case ADVPAPI_CREATESERVICEW:
		dwAddress2Patch = 0x00;
		bResult = WriteProcessMemory(hProcess,(LPVOID)m_dwCreateServiceW,(LPCVOID)byOriginalByte,0x05,&dwBytesWritten);
		break;
	}

	CloseHandle(hProcess);
	hProcess = NULL;

	return bResult;
}

bool CMemHookCheck::GetHookedFunctionOrdinal(BYTE *szBuff,DWORD dwBuffLen,DWORD *dwFuncOrdinal)
{
	if (dwBuffLen == 0x00)
		return false;

	for (DWORD i=0 ;i < (dwBuffLen - 0x5);i++)
	{
		if (szBuff[i] == 0x90 && szBuff[i+1] == 0xB8)
		{
			*dwFuncOrdinal = (DWORD)szBuff[i+2];
			break;
		}
	}

	return true;
}

bool CMemHookCheck::GetBytesFromOurProcess(DWORD dwAdress,int iDll2Load,BYTE *szBuff)
{
	HANDLE	hProcess = NULL;
	SIZE_T	dwBytesRead = 0x00;
	BYTE	szBuffer[0x06] = {0};
	HMODULE	hModule = NULL;

	switch(iDll2Load)
	{
	case 1:
		hModule = LoadLibrary(L"netapi32.dll");
		break;
	case 2:
		hModule = LoadLibrary(L"dnsapi.dll");
		break;
	}
	if (NULL == hModule)
		return false;

	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ ,FALSE,GetCurrentProcessId());
	if (NULL == hProcess)
		return false;

	ReadProcessMemory(hProcess, (void *)dwAdress, (LPVOID)szBuffer, 0x05, &dwBytesRead);
	FreeLibrary(hModule);
	if (dwBytesRead == 0x00)
	{
		CloseHandle(hProcess);
		hProcess = NULL;
		return false;
	}
	memcpy(szBuff,szBuffer,0x05);

	CloseHandle(hProcess);
	hProcess = NULL;
	return true;
}