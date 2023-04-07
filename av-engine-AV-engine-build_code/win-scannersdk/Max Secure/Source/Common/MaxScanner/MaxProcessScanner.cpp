#include "pch.h"
#include "MaxProcessScanner.h"
#include "Registry.h"

CMaxProcessScanner::CMaxProcessScanner(void)
{
	m_hNtDll = GetModuleHandle(_T("NtDll.dll"));
	if(m_hNtDll)
	{
		m_lpfnNTQueryInformationThread = (LPFN_NTQUERYINFORMATIONTHREAD)GetProcAddress(m_hNtDll, "NtQueryInformationThread");

#ifndef WIN64
		m_pNtDuplicateObject = (NTDUPLICATEOBJECT) GetProcAddress(m_hNtDll,"NtDuplicateObject");
		m_pNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION) GetProcAddress(m_hNtDll,"NtQuerySystemInformation");
		m_pNtQueryObject = (NTQUERYOBJECT) GetProcAddress(m_hNtDll,"NtQueryObject");
	}

	HMODULE hKernel32 = GetModuleHandle(L"Kernel32.dll");
	if(hKernel32)
	{
		m_pCloseHandle = (NTCLOSEHANDLE)GetProcAddress(hKernel32, "CloseHandle");
	}

	InitNimnulScanning();
#else
	}
#endif

#ifndef WIN64
	GetFunctionAddress();
#endif
	m_objKidoParam.dwKidoMainThreadFound = 0x00;
	m_objKidoParam.dwKidoThreadBaseAddress = 0x00;
	m_objKidoParam.dwKidoThreadID = 0x00;
	m_bKidoInfectionFound = FALSE;
}

CMaxProcessScanner::~CMaxProcessScanner(void)
{
}

/*-------------------------------------------------------------------------------------
Function       : Init
In Parameters  : 
Out Parameters : bool
Purpose		   : init memmbers
Author		   : Anand Srivastava
-------------------------------------------------------------------------------------*/
bool CMaxProcessScanner::Init()
{
#ifndef WIN64
	m_csArrDeviceNames.Add(_T("dummy"));
	m_csArrDeviceNames.RemoveAll();
	m_csArrDosNames.Add(_T("dummy"));
	m_csArrDosNames.RemoveAll();
#endif
	return true;
}

/*-------------------------------------------------------------------------------------
Function       : DeInit
In Parameters  : 
Out Parameters : bool
Purpose		   : deinit memmbers
Author		   : Anand Srivastava
-------------------------------------------------------------------------------------*/
bool CMaxProcessScanner::DeInit()
{
#ifndef WIN64
	m_csArrDeviceNames.Add(_T("dummy"));
	m_csArrDeviceNames.RemoveAll();
	m_csArrDosNames.Add(_T("dummy"));
	m_csArrDosNames.RemoveAll();
#endif
	return true;
}

/*-------------------------------------------------------------------------------------
Function       : ScanThread
In Parameters  : PMAX_SCANNER_INFO pScanInfo
Out Parameters : bool
Purpose		   : scan this thread
Author		   : Anand Srivastava
-------------------------------------------------------------------------------------*/
bool CMaxProcessScanner::ScanThread(PMAX_SCANNER_INFO pScanInfo, bool &bStopEnum)
{
	try
	{
		BYTE byBuffer[0x200] = {0};
		HANDLE hProcess = 0, hThread = 0;
		DWORD dwThreadStartAddress = 0, dwRetValue = 0;
		SIZE_T dwBytesRead = 0;

		if(!m_lpfnNTQueryInformationThread)
		{
			bStopEnum = true;
			return false;
		}

		if(pScanInfo->ulProcessIDToScan < 0x08)
		{
			return true;
		}

		hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_TERMINATE, FALSE, pScanInfo->ulThreadIDToScan);
		if(hThread == NULL)
		{
			return false;
		}

		m_lpfnNTQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS)ThreadQuerySetWin32StartAddress, (PVOID)&dwThreadStartAddress, sizeof(DWORD), &dwRetValue);
		if(dwThreadStartAddress == 0x00)
		{
			CloseHandle(hThread);
			return false;
		}

		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pScanInfo->ulProcessIDToScan);
		if(hProcess == NULL)
		{
			CloseHandle(hThread);
			return false;
		}

		ReadProcessMemory(hProcess, (LPVOID)dwThreadStartAddress, byBuffer, sizeof(byBuffer), &dwBytesRead);
		if(dwBytesRead == 0)
		{
			CloseHandle(hThread);
			CloseHandle(hProcess);
			return false;
		}

		pScanInfo->ulThreatID = ScanBuffer(byBuffer, (DWORD)dwBytesRead, pScanInfo);
		if(pScanInfo->ulThreatID == 0)
		{
			if(ScanThreadMemory4KidoInfection(byBuffer, (DWORD)dwBytesRead, dwThreadStartAddress, pScanInfo))
			{
				if (m_objKidoParam.dwKidoMainThreadFound == 0x01)
				{
					m_objKidoParam.dwKidoThreadID = pScanInfo->ulProcessIDToScan;
					m_objKidoParam.dwKidoThreadBaseAddress = dwThreadStartAddress - (dwThreadStartAddress % 0x10000);
					m_objKidoParam.dwKidoMainThreadFound++;
				}
				if (!(m_objKidoParam.dwKidoMainThreadFound >= 0x01 && m_objKidoParam.dwKidoThreadID == pScanInfo->ulProcessIDToScan))
				{
					CString csTemp;
					csTemp.Format(_T("%d"), pScanInfo->ulProcessIDToScan);
					AddLogEntry(_T("Secondary Kido Thread Found (Non Kido Process): %s: %s"), pScanInfo->szFileToScan, csTemp);
					pScanInfo->ulThreatID = 0;
				}
				else
				{
					CString csTemp;
					csTemp.Format(_T("%d"), pScanInfo->ulProcessIDToScan);
					AddLogEntry(_T("Secondary Kido Thread Found: %s: %s"), pScanInfo->szFileToScan, csTemp);
				}
			}
		}
		if(0 != pScanInfo->ulThreatID)
		{
			pScanInfo->ThreatDetected = 1;
			CString csThreadID;
			csThreadID.Format(_T("ThreadID: %u, %s"), pScanInfo->ulThreadIDToScan, pScanInfo->szFileToScan);
			AddLogEntry(_T("Infected Thread Found: %s"), csThreadID);

			//Adding thread id to the file name! this prevents this process from getting terminated
			// as we will be reporting this entry to UI and also call Quarantine which will try
			// to terminate this process. We only need to handle the thread in this process!
			_tcscpy_s(pScanInfo->szFileToScan, csThreadID);
			//if(0xFFFFFFFF == SuspendThread(hThread))
			if(0 == TerminateThread(hThread, 0))
			{
				csThreadID.Format(_T("Failed Terminating thread: %s"), pScanInfo->szFileToScan);
				AddLogEntry(csThreadID);
			}
			else
			{
				csThreadID.Format(_T("Successfully Terminated thread: %s"), pScanInfo->szFileToScan);
				AddLogEntry(csThreadID);
			}
		}

		CloseHandle(hThread);
		CloseHandle(hProcess);
		return true;
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in ProcessScanner::ScanThread"));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function       : ScanBuffer
In Parameters  : LPBYTE byBuffer, DWORD cbBuffer, PMAX_SCANNER_INFO pScanInfo
Out Parameters : DWORD
Purpose		   : scan this buffer read from thread
Author		   : Anand Srivastava
-------------------------------------------------------------------------------------*/
DWORD CMaxProcessScanner::ScanBuffer(LPBYTE byBuffer, DWORD cbBuffer, PMAX_SCANNER_INFO pScanInfo)
{
	try
	{
		int i = 0;
		DWORD dwRetValue = 0;
		BYTE bSalityThreadStart[] = {0xC8, 0x00, 0x00, 0x00, 0x8B, 0x6D, 0x08, 0x80, 0xBD};
		BYTE bVirutThread[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED};

		pScanInfo->ulThreatID = 0;
		if(0x60 != byBuffer[0]) // this was introduced to fix dos2usb.exe thread catching
		{
			for(i=0x00; i<0x10; i++)
			{
				if(memcmp(bVirutThread, &byBuffer[i], 0x08) == 0)
				{
					pScanInfo->ulThreatID = 315236;
					break;
				}
			}
		}

		if(!pScanInfo->ulThreatID && memcmp(bSalityThreadStart, byBuffer, 0x09) == 0)
		{
			if(cbBuffer > 0x50)
			{
				for(i = 0x09; i < 0x50; i++)
				{
					if(byBuffer[i]==0x8D && byBuffer[i+1]==0xB5)
					{
						dwRetValue++;
					}

					if(byBuffer[i]==0x8B && byBuffer[i+1]==0xBD)
					{
						dwRetValue++;
					}

					if(byBuffer[i]==0xF3 && byBuffer[i+1]==0xA4)
					{
						dwRetValue++;
					}

					if(dwRetValue == 0x03)
					{
						pScanInfo->ulThreatID = 1434496;
						break;
					}
				}
			}
		}

		if(!pScanInfo->ulThreatID && (memcmp(bVirutThread, byBuffer, 0x06) == 0))
		{
			dwRetValue = 0x00 ;
			if(cbBuffer > 0x180)
			{
				for(i = 0x120; i < 0x180; i++)
				{
					if(byBuffer[i]==0x8D && byBuffer[i+1]==0xB5)
						dwRetValue++ ;

					if(byBuffer[i]==0x8B && byBuffer[i+1]==0x06)
						dwRetValue++ ;

					if(byBuffer[i]==0xF3 && byBuffer[i+1]==0xA4)
						dwRetValue++ ;

					if(dwRetValue == 0x03)
					{
						pScanInfo->ulThreatID = 315236;
						break;
					}
				}
			}
		}
		return pScanInfo->ulThreatID;
	}

	catch(...)
	{
		AddLogEntry(_T("Exception caught in ProcessScanner::ScanBuffer"));
	}

	return false;
}

#ifndef WIN64
bool CMaxProcessScanner::GetFunctionAddress()
{
	bool bRet = false;
	m_dwNtCreateFile = m_dwNtCreateProcess = m_dwNtCreateProcessEx = m_dwNtOpenFile = m_dwNtQueryInformationProcess = 0;
	if(m_hNtDll)
	{
		FARPROC pFunction = NULL;
		pFunction = GetProcAddress(m_hNtDll, "NtCreateFile");
		m_dwNtCreateFile = (DWORD)pFunction;

		pFunction = GetProcAddress(m_hNtDll, "NtCreateProcess");
		m_dwNtCreateProcess = (DWORD)pFunction;

		pFunction = GetProcAddress(m_hNtDll, "NtCreateProcessEx");
		m_dwNtCreateProcessEx = (DWORD)pFunction;

		pFunction = GetProcAddress(m_hNtDll, "NtOpenFile");
		m_dwNtOpenFile = (DWORD)pFunction;

		pFunction = GetProcAddress(m_hNtDll, "NtQueryInformationProcess");
		m_dwNtQueryInformationProcess = (DWORD)pFunction;

		if(m_dwNtCreateFile && m_dwNtCreateProcess && m_dwNtCreateProcessEx && m_dwNtOpenFile && m_dwNtQueryInformationProcess)
		{
			bRet = true;
		}
	}
	HMODULE hNetapi32 = NULL;
	hNetapi32 = LoadLibrary(_T("netapi32.dll"));
	if(hNetapi32 != NULL)
	{
		NTNETPWPATHCANONICALIZE	pNTnetpwpathcanonicalize = NULL;
		pNTnetpwpathcanonicalize = (NTNETPWPATHCANONICALIZE) GetProcAddress(hNetapi32, "NetpwPathCanonicalize");
		if(pNTnetpwpathcanonicalize != NULL)
		{
			m_dwNetPathCanonicalize = (DWORD)pNTnetpwpathcanonicalize;
			pNTnetpwpathcanonicalize = NULL;
		}
		if(m_dwNetPathCanonicalize)
		{
			bRet = true;
		}
		FreeLibrary(hNetapi32);
	}

	HMODULE hDnsapi = NULL;
	hDnsapi = LoadLibrary(_T("dnsapi.dll"));
	if(hDnsapi != NULL)
	{
		NTDNSQUERY_A pNTdnsquery_a= NULL;
		pNTdnsquery_a = (NTDNSQUERY_A) GetProcAddress(hDnsapi, "DnsQuery_A");
		if(pNTdnsquery_a != NULL)
		{
			m_dwDnsQuery_A = (DWORD)pNTdnsquery_a;
			pNTdnsquery_a = NULL;
		}

		NTDNSQUERY_W pNTdnsquery_w = NULL;
		pNTdnsquery_w = (NTDNSQUERY_W) GetProcAddress(hDnsapi, "DnsQuery_W");
		if(pNTdnsquery_w != NULL)
		{
			m_dwDnsQuery_W = (DWORD)pNTdnsquery_w;
			pNTdnsquery_w = NULL;
		}

		NTDNSQUERY_UTF8 pNTdnsquery_utf8 = NULL;
		pNTdnsquery_utf8 = (NTDNSQUERY_UTF8) GetProcAddress(hDnsapi, "DnsQuery_UTF8");
		if(pNTdnsquery_utf8 != NULL)
		{
			m_dwDnsQuery_UTF8 = (DWORD)pNTdnsquery_utf8;
			pNTdnsquery_utf8 = NULL;
		}

		NTQUERY_MAIN pNTquery_main = NULL;
		pNTquery_main = (NTQUERY_MAIN) GetProcAddress(hDnsapi, "Query_Main");
		if(pNTquery_main != NULL)
		{
			m_dwQuery_Main = (DWORD)pNTquery_main;
			pNTquery_main = NULL;
		}

		if(m_dwDnsQuery_A && m_dwDnsQuery_W && m_dwDnsQuery_UTF8 && m_dwQuery_Main)
		{
			bRet = true;
		}
		FreeLibrary(hDnsapi);
	}

	return bRet;
}

void CMaxProcessScanner::CheckFunctionAddress(PMAX_SCANNER_INFO pScanInfo)
{
	HANDLE hCurrProcess = NULL;
	if(!m_dwNtCreateFile || !m_dwNtCreateProcess || !m_dwNtCreateProcessEx || !m_dwNtOpenFile || !m_dwNtQueryInformationProcess)
	{
		return;
	}

	hCurrProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pScanInfo->ulProcessIDToScan);

	if(!hCurrProcess)
	{
		TCHAR szLine2Write[MAX_PATH] = {0};
		_stprintf_s(szLine2Write, MAX_PATH, _T("##### Could not Open Process with Process ID: %lu"), pScanInfo->ulProcessIDToScan);
		//AddLogEntry(szLine2Write);
		return;
	}

	VerifyAndFixFunction(hCurrProcess, m_dwNtCreateFile, pScanInfo->ulProcessIDToScan, _T("NtCreateFile"));
	VerifyAndFixFunction(hCurrProcess, m_dwNtCreateProcess, pScanInfo->ulProcessIDToScan, _T("NtCreateProcess"));
	VerifyAndFixFunction(hCurrProcess, m_dwNtCreateProcessEx, pScanInfo->ulProcessIDToScan, _T("NtCreateProcessEx"));
	VerifyAndFixFunction(hCurrProcess, m_dwNtOpenFile, pScanInfo->ulProcessIDToScan, _T("NtOpenFile"));
	VerifyAndFixFunction(hCurrProcess, m_dwNtQueryInformationProcess, pScanInfo->ulProcessIDToScan, _T("NtQueryInformationProcess"));

	VerifyAndFixFunction(hCurrProcess, m_dwNetPathCanonicalize, pScanInfo->ulProcessIDToScan, _T("NetpwPathCanonicalize"));
	VerifyAndFixFunction(hCurrProcess, m_dwDnsQuery_A, pScanInfo->ulProcessIDToScan, _T("DnsQuery_A"));
	VerifyAndFixFunction(hCurrProcess, m_dwDnsQuery_UTF8, pScanInfo->ulProcessIDToScan, _T("DnsQuery_UTF8"));
	VerifyAndFixFunction(hCurrProcess, m_dwDnsQuery_W, pScanInfo->ulProcessIDToScan, _T("DnsQuery_W"));
	VerifyAndFixFunction(hCurrProcess, m_dwQuery_Main, pScanInfo->ulProcessIDToScan, _T("Query_Main"));

	CloseHandle(hCurrProcess);
	hCurrProcess = NULL;
}

void CMaxProcessScanner::VerifyAndFixFunction(HANDLE hCurrProcess, DWORD dwFunctionAddress, DWORD dwProcessID, LPCTSTR szFunctionName)
{
	DWORD dwBytesRead = 0x00;
	BYTE szByteOrdinal[0x1A] = {0};
	DWORD dwBytesWritten = 0x00;
	BYTE szBuffer[0x06] = {0};
	bool bFixedSuccessfully = false;
	TCHAR szLine2Write[MAX_PATH] = {0};
	ReadProcessMemory(hCurrProcess, (void*)dwFunctionAddress, (LPVOID)szBuffer, 0x05, &dwBytesRead);
	if(szBuffer[0x00] == 0xE8)
	{
		DWORD dwAddress2Patch = 0x00;
		_stprintf_s(szLine2Write, MAX_PATH, _T("Found Hooked API '%s' in Process: %lu"), szFunctionName, dwProcessID);
		AddLogEntry(szLine2Write);
		if((dwFunctionAddress - 0x19) > 0x00)
		{
			dwBytesRead = 0x00;
			ReadProcessMemory(hCurrProcess, (void *)(dwFunctionAddress - 0x19), (LPVOID)szByteOrdinal, 0x19, &dwBytesRead);
			if(GetHookedFunctionOrdinal(szByteOrdinal, dwBytesRead, &dwAddress2Patch))
			{
				if(dwAddress2Patch > 0x00)
				{
					BYTE szCall2Patched[] = {0xB8};

					dwAddress2Patch++;
					WriteProcessMemory(hCurrProcess, (LPVOID)dwFunctionAddress, (LPCVOID)szCall2Patched, 0x01, &dwBytesWritten);
					_stprintf_s(szLine2Write, MAX_PATH, _T("Fixed Hooked API '%s' in Process: %lu, (1) %d, 0x%02x, %d"), szFunctionName, dwProcessID, dwFunctionAddress, szCall2Patched[0], dwBytesWritten);
					AddLogEntry(szLine2Write);

					WriteProcessMemory(hCurrProcess, (LPVOID)(dwFunctionAddress + 0x01), (LPCVOID)&dwAddress2Patch, sizeof(DWORD), &dwBytesWritten);

					_stprintf_s(szLine2Write, MAX_PATH, _T("Fixed Hooked API '%s' in Process: %lu, (2) %d, 0x%08x, %d"), szFunctionName, dwProcessID, dwFunctionAddress, dwAddress2Patch, dwBytesWritten);
					AddLogEntry(szLine2Write);

					bFixedSuccessfully = true;
				}
			}
		}
		if(bFixedSuccessfully)
		{
			_stprintf_s(szLine2Write, MAX_PATH, _T("Fixed Hooked API '%s' in Process: %lu"), szFunctionName, dwProcessID);
			AddLogEntry(szLine2Write);
		}
		else
		{
			_stprintf_s(szLine2Write, MAX_PATH, _T("Failed to Fix Hooked API '%s' in Process: %lu"), szFunctionName, dwProcessID);
			AddLogEntry(szLine2Write);
		}
	}
	if(szBuffer[0x00] == 0xE9)
	{
		if(dwFunctionAddress == m_dwNetPathCanonicalize)
		{
			if (GetBytesFromOurProcess(dwFunctionAddress,1,&szByteOrdinal[0x00]))
			{
				bFixedSuccessfully = true;
				WriteProcessMemory(hCurrProcess,(LPVOID)dwFunctionAddress,(LPCVOID)szByteOrdinal,0x05,&dwBytesWritten);
				_stprintf_s(szLine2Write, MAX_PATH, _T("Fixed Hooked API '%s' in Process: %lu, (3) %d, 0x%02x%02x%02x%02x%02x, %d"), szFunctionName, dwProcessID, dwFunctionAddress, szByteOrdinal[0], szByteOrdinal[1], szByteOrdinal[2], szByteOrdinal[3], szByteOrdinal[4], dwBytesWritten);
				AddLogEntry(szLine2Write);
			}
		}
		else if(dwFunctionAddress == m_dwDnsQuery_A || dwFunctionAddress == m_dwDnsQuery_W || dwFunctionAddress == m_dwDnsQuery_UTF8 || dwFunctionAddress == m_dwQuery_Main)
		{
			if (GetBytesFromOurProcess(m_dwQuery_Main,2,&szByteOrdinal[0x00]))
			{
				bFixedSuccessfully = true;
				WriteProcessMemory(hCurrProcess,(LPVOID)dwFunctionAddress,(LPCVOID)szByteOrdinal,0x05,&dwBytesWritten);
				_stprintf_s(szLine2Write, MAX_PATH, _T("Fixed Hooked API '%s' in Process: %lu, (4) %d, 0x%02x%02x%02x%02x%02x, %d"), szFunctionName, dwProcessID, dwFunctionAddress, szByteOrdinal[0], szByteOrdinal[1], szByteOrdinal[2], szByteOrdinal[3], szByteOrdinal[4], dwBytesWritten);
				AddLogEntry(szLine2Write);
			}
		}
		else if(dwFunctionAddress == m_dwNtQueryInformationProcess)
		{
			DWORD dwAddress2Patch = 0x00;
			_stprintf_s(szLine2Write, MAX_PATH, _T("Found Hooked API '%s' in Process: %lu"), szFunctionName, dwProcessID);
			AddLogEntry(szLine2Write);
			if((dwFunctionAddress - 0x19) > 0x00)
			{
				dwBytesRead = 0x00;
				ReadProcessMemory(hCurrProcess, (void *)(dwFunctionAddress - 0x19), (LPVOID)szByteOrdinal, 0x19, &dwBytesRead);
				if(GetHookedFunctionOrdinal(szByteOrdinal, dwBytesRead, &dwAddress2Patch))
				{
					if(dwAddress2Patch > 0x00)
					{
						BYTE szCall2Patched[] = {0xB8};

						dwAddress2Patch++;
						WriteProcessMemory(hCurrProcess, (LPVOID)dwFunctionAddress, (LPCVOID)szCall2Patched, 0x01, &dwBytesWritten);
						_stprintf_s(szLine2Write, MAX_PATH, _T("Fixed Hooked API '%s' in Process: %lu, (5) %d, 0x%02x, %d"), szFunctionName, dwProcessID, dwFunctionAddress, szCall2Patched[0], dwBytesWritten);
						AddLogEntry(szLine2Write);

						WriteProcessMemory(hCurrProcess, (LPVOID)(dwFunctionAddress + 0x01), (LPCVOID)&dwAddress2Patch, sizeof(DWORD), &dwBytesWritten);

						_stprintf_s(szLine2Write, MAX_PATH, _T("Fixed Hooked API '%s' in Process: %lu, (6) %d, 0x%08x, %d"), szFunctionName, dwProcessID, dwFunctionAddress, dwAddress2Patch, dwBytesWritten);
						AddLogEntry(szLine2Write);

						bFixedSuccessfully = true;
					}
				}
			}
		}
		else
		{
			_stprintf_s(szLine2Write, MAX_PATH, _T("Unhandled Hooked API '%s' in Process: %lu"), szFunctionName, dwProcessID);
			AddLogEntry(szLine2Write);
		}
		if(bFixedSuccessfully)
		{
			_stprintf_s(szLine2Write, MAX_PATH, _T("Fixed Hooked API '%s' in Process: %lu"), szFunctionName, dwProcessID);
			AddLogEntry(szLine2Write);
		}
		else
		{
			_stprintf_s(szLine2Write, MAX_PATH, _T("Failed to Fix Hooked API '%s' in Process: %lu"), szFunctionName, dwProcessID);
			AddLogEntry(szLine2Write);
		}
	}
}

bool CMaxProcessScanner::GetHookedFunctionOrdinal(BYTE *szBuff, DWORD dwBuffLen, DWORD *dwFuncOrdinal)
{
	if(dwBuffLen == 0x00)
		return false;

	for(DWORD i=0; i < dwBuffLen - 0x5; i++)
	{
		if(szBuff[i] == 0x90 && szBuff[i+1] == 0xB8)
		{
			*dwFuncOrdinal = (DWORD)szBuff[i+2];
			break;
		}
	}
	return true;
}

bool CMaxProcessScanner::InitNimnulScanning()
{
	CRegistry objReg;
	int iContext = 0;
	CString csData, csToken;

	objReg.Get(WINLOGON_REG_KEY, _T("UserInit"), csData, HKEY_LOCAL_MACHINE);
	if(_T("") == csData)
	{
		return false;
	}

	m_csArrUserInitFilesList.RemoveAll();
	csToken = csData.Tokenize(_T(","), iContext);
	while(_T("") != csToken)
	{
		csToken.MakeLower();
		m_csArrUserInitFilesList.Add(csToken);
		csToken = csData.Tokenize(_T(","), iContext);
	}

	return true;
}

bool CMaxProcessScanner::ConvertDeviceNameToDosFileName(CString& csFilePath)
{
	INT_PTR iDosNames = 0, iDeviceNames = 0;

	iDeviceNames = m_csArrDeviceNames.GetCount();
	iDosNames = m_csArrDosNames.GetCount();

	if(0 == iDeviceNames || 0 == iDosNames || iDeviceNames != iDosNames)
	{
		TCHAR szDeviceName[MAX_PATH] = {0};

		m_csArrDosNames.RemoveAll();
		m_csArrDeviceNames.RemoveAll();

		for(TCHAR szDrive[] = _T("a:"); szDrive[0] <= _T('z'); szDrive[0]++)
		{
			memset(szDeviceName, 0, sizeof(szDeviceName));
			if(QueryDosDevice(szDrive, szDeviceName, _countof(szDeviceName)))
			{
				_tcslwr_s(szDeviceName, _countof(szDeviceName));
				m_csArrDosNames.Add(szDrive);
				m_csArrDeviceNames.Add(szDeviceName);
			}
		}

		iDeviceNames = m_csArrDeviceNames.GetCount();
		iDosNames = m_csArrDosNames.GetCount();
	}

	if(0 == iDeviceNames || 0 == iDosNames || iDeviceNames != iDosNames)
	{
		return false;
	}

	for(INT_PTR i = 0; i < iDeviceNames; i++)
	{
		if(0 == _tcsnicmp(m_csArrDeviceNames[i], csFilePath, _tcslen(m_csArrDeviceNames[i])))
		{
			csFilePath.Replace(m_csArrDeviceNames[i], m_csArrDosNames[i]);
			break;
		}
	}

	return true;
}

bool CMaxProcessScanner::AddNewInfectedNode(PMAX_SCANNER_INFO pScanInfo, LPCTSTR szParent, LPCTSTR szChild)
{
	while(pScanInfo->pNextScanInfo)
	{
		pScanInfo = pScanInfo->pNextScanInfo;
	}

	pScanInfo->pNextScanInfo = new MAX_SCANNER_INFO;
	if(!pScanInfo->pNextScanInfo)
	{
		return false;
	}

	pScanInfo->FreeNextScanInfo = true;
	pScanInfo = pScanInfo->pNextScanInfo;
	memset(pScanInfo, 0, sizeof(MAX_SCANNER_INFO));
	pScanInfo->eMessageInfo = Module_Report;
	pScanInfo->ThreatDetected = true;
	pScanInfo->eDetectedBY = Detected_BY_MaxAVModule;
	pScanInfo->ulThreatID = SPY_ID_NIMNUL_A;
	_tcscpy_s(pScanInfo->szFileToScan, _countof(pScanInfo->szFileToScan), szChild);
	_tcscpy_s(pScanInfo->szContainerFileName, _countof(pScanInfo->szContainerFileName), szParent);
	return true;
}

bool CMaxProcessScanner::Check4VirusHandle(LPCTSTR szFilePath, CStringArray& csArrOnlyFileName)
{
	bool bFound = false, bFoundInOnlyFileNameList = false;
	HANDLE hFile = 0;
	LPCTSTR szOnlyFileName = 0;
	CString csFilePath(szFilePath);

	ConvertDeviceNameToDosFileName(csFilePath);
	szFilePath = csFilePath;

	for(INT_PTR i = 0, iTotal = m_csArrUserInitFilesList.GetCount(); i < iTotal; i++)
	{
		if(!_tcscmp(m_csArrUserInitFilesList[i], szFilePath))
		{
			bFound = true;
			break;
		}
	}

	if(!bFound)
	{
		szOnlyFileName = _tcsrchr(szFilePath, _T('\\'));
		if(szOnlyFileName)
		{
			for(INT_PTR i = 0, iTotal = csArrOnlyFileName.GetCount(); !bFoundInOnlyFileNameList && i < iTotal; i++)
			{
				bFoundInOnlyFileNameList = !_tcsicmp(szOnlyFileName, csArrOnlyFileName[i]);
			}
		}
	}

	if(!bFound && !bFoundInOnlyFileNameList)
	{
		return false;
	}

	if(_taccess_s(szFilePath, 0))
	{
		return false;
	}

	hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(INVALID_HANDLE_VALUE != hFile)
	{
		CloseHandle(hFile);
		return false;
	}

	if(!bFoundInOnlyFileNameList)
	{
		szOnlyFileName = _tcsrchr(szFilePath, _T('\\'));
		if(szOnlyFileName)
		{
			csArrOnlyFileName.Add(szOnlyFileName);
		}
	}

	return true;
}

void CloseAnyHandle(CLOSE_HANDLE_STRUCT *pIP)
{
	pIP->pNtCloseHandle(pIP->hHandle);
	return;
}

bool CMaxProcessScanner::InjectThreadnCloseHandle(HANDLE hProcHandle, HANDLE hReqHandle)
{
	const DWORD				MAXINJECTSIZE = 0x1000;
	LPVOID					lp = NULL ;
	PCLOSE_HANDLE_STRUCT	pCloseStruct = NULL ;
	CLOSE_HANDLE_STRUCT		LocalCopy ;

	if(NULL == m_pCloseHandle || NULL == hReqHandle || NULL == hProcHandle)
	{
		return false;
	}

	memset(&LocalCopy, 0x00, sizeof(CLOSE_HANDLE_STRUCT)) ;
	lp = VirtualAllocEx(hProcHandle,NULL,MAXINJECTSIZE,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE );
	if (NULL == lp)
	{
		return false;
	}

	pCloseStruct = (CLOSE_HANDLE_STRUCT *)VirtualAllocEx(hProcHandle,0,sizeof(CLOSE_HANDLE_STRUCT),MEM_COMMIT, PAGE_READWRITE );
	if (NULL == pCloseStruct)
	{
		VirtualFreeEx(hProcHandle,lp,MAXINJECTSIZE,MEM_RELEASE);
		return false;
	}
	
	LocalCopy.hHandle = hReqHandle;
	LocalCopy.pNtCloseHandle = (NTCLOSEHANDLE)GetProcAddress(GetModuleHandle(L"Kernel32.dll"),"CloseHandle");
	if (LocalCopy.pNtCloseHandle == NULL)
	{
		VirtualFreeEx(hProcHandle,lp,MAXINJECTSIZE,MEM_RELEASE);
		VirtualFreeEx(hProcHandle,pCloseStruct,sizeof(CLOSE_HANDLE_STRUCT),MEM_RELEASE);
		return false;
	}

	DWORD	dwBytesWritten = 0x00;
	if (! WriteProcessMemory( hProcHandle, lp, CloseAnyHandle, MAXINJECTSIZE, &dwBytesWritten) )
	{
		VirtualFreeEx(hProcHandle,lp,MAXINJECTSIZE,MEM_RELEASE);
		VirtualFreeEx(hProcHandle,pCloseStruct,sizeof(CLOSE_HANDLE_STRUCT),MEM_RELEASE);
		return false;
	}

	dwBytesWritten = 0x00 ;
	if ( ! WriteProcessMemory( hProcHandle, pCloseStruct, &LocalCopy, sizeof(CLOSE_HANDLE_STRUCT), &dwBytesWritten ) )
	{
		VirtualFreeEx(hProcHandle,lp,MAXINJECTSIZE,MEM_RELEASE);
		VirtualFreeEx(hProcHandle,pCloseStruct,sizeof(CLOSE_HANDLE_STRUCT),MEM_RELEASE);
		return false;
	}
	
	HANDLE	hRemoteThread = NULL;
	DWORD	dwRet = 0x00;

	hRemoteThread = CreateRemoteThread(hProcHandle,0,0,(DWORD (WINAPI *)(void *))lp, pCloseStruct,0,&dwRet);
	if (hRemoteThread == NULL)
	{
		VirtualFreeEx(hProcHandle,lp,MAXINJECTSIZE,MEM_RELEASE);
		VirtualFreeEx(hProcHandle,pCloseStruct,sizeof(CLOSE_HANDLE_STRUCT),MEM_RELEASE);
		return false;
	}
	
	dwRet = WaitForSingleObject(hRemoteThread,4000);
	CloseHandle(hRemoteThread);

	return true;
}

void CMaxProcessScanner::CheckForNimnulHandles(PMAX_SCANNER_INFO pScanInfo)
{
	NTSTATUS					status;
	PSYSTEM_HANDLE_INFORMATION	pHandleInfo = NULL;
	ULONG						dwHandleInfoSize = 0x10000;
	HANDLE						hRequiredHandle = NULL;
	TCHAR						szObjName[MAX_PATH] = {0};
	CStringArray				csArrOnlyFileName;

	if(NULL == m_pNtQuerySystemInformation || NULL == m_pNtDuplicateObject || NULL == m_pNtQueryObject)
	{
		AddLogEntry(L"function pointer not found in ntdll");
		return;
	}

	pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)calloc(1,dwHandleInfoSize);
	if(NULL == pHandleInfo)
	{
		return;
	}

	if((status = m_pNtQuerySystemInformation(SystemHandleInformation,pHandleInfo,dwHandleInfoSize,&dwHandleInfoSize)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		dwHandleInfoSize += 0x1000;
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(pHandleInfo, dwHandleInfoSize);
		if(NULL == pHandleInfo)
		{
			return;
		}

		status = m_pNtQuerySystemInformation(SystemHandleInformation,pHandleInfo,dwHandleInfoSize,&dwHandleInfoSize);
	}

	if(!NT_SUCCESS(status))
	{
		free(pHandleInfo);
		return;
	}

	for(ULONG ihIndex = 0x00; ihIndex < pHandleInfo->HandleCount; ihIndex++)
	{
		SYSTEM_HANDLE	hSysHandle = pHandleInfo->Handles[ihIndex];
		HANDLE			hDuplicate = NULL;
		PVOID			pobjNameInfo = NULL;
		UNICODE_STRING	uszObjName;
		ULONG			dwReturnLen = 0x00;

		if(hSysHandle.ProcessId != pScanInfo->ulProcessIDToScan)
			continue;

		if(!NT_SUCCESS(m_pNtDuplicateObject(pScanInfo->hProcessHandleIDToScan, (HANDLE)hSysHandle.Handle, GetCurrentProcess(), &hDuplicate, 0, 0, 0)))
			continue;

		if(hSysHandle.GrantedAccess == 0x0012019F || hSysHandle.GrantedAccess == 0x001A019F || hSysHandle.GrantedAccess == 0x00120189 || hSysHandle.GrantedAccess == 0x100000)
		{
			CloseHandle(hDuplicate);
			continue;
		}

		pobjNameInfo = malloc(0x1000);
		if(!NT_SUCCESS(m_pNtQueryObject(hDuplicate,ObjectNameInformation,pobjNameInfo,0x1000,&dwReturnLen)))
		{
			pobjNameInfo = realloc(pobjNameInfo,dwReturnLen);
			if(!NT_SUCCESS(m_pNtQueryObject(hDuplicate,ObjectNameInformation,pobjNameInfo,dwReturnLen,NULL)))
			{
				free(pobjNameInfo);
				CloseHandle(hDuplicate);
				continue;
			}
		}

		uszObjName = *(PUNICODE_STRING)pobjNameInfo;
		if(uszObjName.Length)
		{
			LPTSTR	pTemp  = NULL;

			memset(szObjName, 0, sizeof(szObjName));
			_tcsncpy_s(szObjName, MAX_PATH, uszObjName.Buffer, uszObjName.Length);
			_tcslwr_s(szObjName,MAX_PATH);

			hRequiredHandle = NULL;
			if(Check4VirusHandle(szObjName, csArrOnlyFileName))
			{
				AddNewInfectedNode(pScanInfo, pScanInfo->szFileToScan, szObjName);
				hRequiredHandle = (HANDLE)(hSysHandle.Handle);
				if(!InjectThreadnCloseHandle(pScanInfo->hProcessHandleIDToScan, hRequiredHandle))
				{
					AddLogEntry(L"InjectThreadnCloseHandle failed: %s", szObjName);
				}
				Sleep(50);
			}
		}

		free(pobjNameInfo);
		CloseHandle(hDuplicate);
	}

	free(pHandleInfo);
	return;
}

#endif //#ifndef WIN64

bool CMaxProcessScanner::GetBytesFromOurProcess(DWORD dwAdress,int iDll2Load,BYTE *szBuff)
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

BOOL CMaxProcessScanner::ScanThreadMemory4KidoInfection(BYTE *pszBuffer,DWORD dwBytes, DWORD ThreadAddrs, PMAX_SCANNER_INFO pScanInfo)
{
	const BYTE bThreadData[] = {0x6A, 0x20, 0x68, 0xD8, 0x44};
	const BYTE bThreadData1[] = {0xE8, 0x83, 0xAB, 0x00, 0x00};
	const BYTE bThreadData2[] = {0x81, 0xEC, 0x98, 0x01, 0x00, 0x00, 0x53, 0x55, 0x56, 0x57, 0x68, 0x03, 0x80, 0x00};

	const BYTE bThreadData3[] = {0x51, 0x51, 0x53, 0x55, 0x56, 0x8B};
	const BYTE bThreadTemp[] = {0x55, 0x8B, 0xEC};

	if (m_objKidoParam.dwKidoMainThreadFound >= 0x01)
	{
		if (memcmp(&pszBuffer[0x00],bThreadTemp,sizeof(bThreadTemp)) == 0x00 ||
			memcmp(&pszBuffer[0x00],bThreadData3,sizeof(bThreadData3)) == 0x00)
		{
			pScanInfo->ulThreatID = 3393581;
			return TRUE;
		}
		DWORD dwDummy = 0x00;
		if(ThreadAddrs > 0x10000)
		{
			dwDummy = ThreadAddrs - (ThreadAddrs % 0x10000);
			if (m_objKidoParam.dwKidoThreadBaseAddress && m_objKidoParam.dwKidoThreadBaseAddress == dwDummy)
			{
				pScanInfo->ulThreatID = 3393581;
				return TRUE;
			}
		}
	}
	if ((memcmp(&pszBuffer[0x00],bThreadData,sizeof(bThreadData)) == 0x00 && 
		memcmp(&pszBuffer[0x07],bThreadData1,sizeof(bThreadData1)) == 0x00)||
		memcmp(&pszBuffer[0x00],bThreadData2,sizeof(bThreadData2)) == 0x00 )
	{
		m_bKidoInfectionFound = TRUE;
		m_objKidoParam.dwKidoMainThreadFound++;
		pScanInfo->ulThreatID = 3393581;
		return TRUE;
	}

	return FALSE;
}

BOOL CMaxProcessScanner::IsKidoThreadFound()
{
	if(m_objKidoParam.dwKidoMainThreadFound == 0x01)
		return TRUE;
	else
		return FALSE;
}

BOOL CMaxProcessScanner::GetKidoInfectionStatus()
{
	return m_bKidoInfectionFound;
}

void CMaxProcessScanner::ResetKidoInfectionStatus()
{
	m_bKidoInfectionFound = FALSE;
}