/*=============================================================================
   FILE			: ExecuteProcess.cpp
   DESCRIPTION	: Implementation of CExecuteProcess Class
   DOCUMENTS	: 
   AUTHOR		: Sandip Sanap
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 21-12-2007
   NOTES		:
VERSION HISTORY	: 25Dec2007 : Sandip : Ported to VS2005 with Unicoe and X64 bit Compatability.	
				Version No:19.0.0.72
				Description:Handle wait condition after child process running.
				Resource:Sandip
============================================================================*/
#include <pch.h>
#include "ExecuteProcess.h"
#include <winbase.h>
#include <tlhelp32.h>
#include "CPUInfo.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//CExecuteProcess Constructor
CExecuteProcess::CExecuteProcess(void)
{
}

//CExecuteProcess Destructor
CExecuteProcess::~CExecuteProcess(void)
{
}

/*-------------------------------------------------------------------------------------
Function		: ShellExecuteEx
In Parameters	: CString sExecCmd, CString csParam
Out Parameters	: void
Purpose			: This Function Starts any exe with ShellExecuteEx command
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CExecuteProcess::ShellExecuteEx(CString sExecCmd, CString csParam, bool bWait, CString csVerb, BOOL bShow)
{
	SHELLEXECUTEINFO ShExecInfo = {0};
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = NULL;
	ShExecInfo.lpFile = sExecCmd;
	ShExecInfo.lpParameters = csParam;
	ShExecInfo.lpDirectory = NULL;
	if(bShow)
		ShExecInfo.nShow = SW_SHOW;
	else
		ShExecInfo.nShow = SW_HIDE;

	ShExecInfo.hInstApp = NULL;
	::ShellExecuteEx(&ShExecInfo);

	if(bWait)
		WaitForSingleObject(ShExecInfo.hProcess, 60000*2); 

	if(!bShow)
	{
		Sleep(4*1000);
		TerminateProcess(ShExecInfo.hProcess, 0);
	}

	return true;
}

/*-------------------------------------------------------------------------------------
Function		: ExecuteCommand
In Parameters	: -
Out Parameters	: bool
Purpose			: This Function Starts any exe with CreateProcess
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CExecuteProcess::ExecuteCommand(CString sExecCmd, CString csParam, bool bWait)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Start the child process.
	if(!CreateProcess(sExecCmd.GetBuffer(MAX_PATH), csParam.GetBuffer(MAX_PATH), NULL, NULL,
		FALSE, 0, NULL, NULL, &si, &pi))
	{
		sExecCmd.ReleaseBuffer();
		csParam.ReleaseBuffer();
		return false;
	}
	sExecCmd.ReleaseBuffer();
	csParam.ReleaseBuffer();

	// Wait until child process exits.
	if(bWait)
		WaitForSingleObject(pi.hProcess, 1000 * 60 * 2);

	// Close process and thread handles.
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: ExecuteCommand
In Parameters	: -
Out Parameters	: bool
Purpose			: This Function Starts any exe with CreateProcess
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CExecuteProcess::ExecuteCommandWithWait(CString sExecCmd, CString csParam)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Start the child process.
	if(!CreateProcess(sExecCmd.GetBuffer(MAX_PATH), csParam.GetBuffer(MAX_PATH), NULL, NULL,
		FALSE, 0, NULL, NULL, &si, &pi))
	{
		sExecCmd.ReleaseBuffer();
		csParam.ReleaseBuffer();
		return false;
	}
	sExecCmd.ReleaseBuffer();
	csParam.ReleaseBuffer();

	// Wait until child process exits.
	WaitForSingleObject(pi.hProcess, INFINITE);

	// Close process and thread handles.
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: GetExplorerProcessHandle
In Parameters	: -
Out Parameters	: HANDLE
Purpose			: Needed to impersonate the logged in user...
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
HANDLE CExecuteProcess::GetExplorerProcessHandle(CString csAccessProcessName)
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	ZeroMemory(&pe32,sizeof(pe32));
	HANDLE temp = NULL;
	try
	{
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,NULL);
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if(Process32First(hSnapshot,&pe32))
		{
			do
			{
				CString csExeName = pe32.szExeFile;

				//Version:	: 19.0.0.015
				//Resource	: Dipali
				//On Vista Explorer.exe run as standard user with limited rights
				//So it will not able to execute process as run as admin 
				CCPUInfo objCpuInfo;
				if(objCpuInfo.GetOSVerTag() == W2K)
				{
					if(csExeName.CompareNoCase(_T("explorer.exe")) == 0)
					{
						temp = OpenProcess (PROCESS_ALL_ACCESS,FALSE, pe32.th32ProcessID);
					}
				}
				else if(csAccessProcessName)
				{
					if(csExeName.CompareNoCase(csAccessProcessName) == 0)
					{
						temp = OpenProcess (PROCESS_ALL_ACCESS,FALSE, pe32.th32ProcessID);
						break;
					}
				}
			}while(Process32Next(hSnapshot,&pe32));
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExecuteProcess::GetExplorerProcessHandle"));
	}
	return temp;
}

/*-------------------------------------------------------------------------------------
Function		: StartProcessWithToken
In Parameters	: CString csProcessPath, CString csCommandLineParam,
CString csAccessProcessName
Out Parameters	: BOOL
Purpose			: To Start process Service
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
BOOL CExecuteProcess::StartProcessWithToken(CString csProcessPath, CString csCommandLineParam,
											CString csAccessProcessName, bool bWait)
{
	try
	{
		HANDLE				hToken = NULL;
		TOKEN_USER          oUser[16];
		DWORD               u32Needed;
		TCHAR               sUserName[256], domainName[256];
		DWORD               userNameSize, domainNameSize;
		SID_NAME_USE        sidType;

		ZeroMemory(oUser,sizeof(oUser));
		BOOL bRet = OpenProcessToken(GetExplorerProcessHandle(csAccessProcessName), TOKEN_ALL_ACCESS, &hToken);
		if(!bRet)
		{
			return FALSE;
		}

		if(hToken == NULL)
		{
			if(csAccessProcessName.CompareNoCase(L"explorer.exe") !=0)
			{
				if(!OpenProcessToken(GetExplorerProcessHandle(L"explorer.exe"), TOKEN_ALL_ACCESS, &hToken))
					return FALSE;

				if(hToken == NULL)
				{
					return FALSE;
				}
			}
		}

		GetTokenInformation(hToken, TokenUser, &oUser[0], sizeof(oUser), &u32Needed);
		userNameSize		= _countof (sUserName) - 1;
		domainNameSize      = _countof (domainName) - 1;

		LookupAccountSid (NULL, oUser[0].User.Sid, sUserName, &userNameSize, domainName, &domainNameSize, &sidType);
		HDESK       hdesk = NULL;
		HWINSTA     hwinsta = NULL, hwinstaSave = NULL;
		PROCESS_INFORMATION pi;
		STARTUPINFO si;
		BOOL bResult = FALSE;
		// Save a handle to the caller's current window station.
		if((hwinstaSave = GetProcessWindowStation()) == NULL)
		{
			CloseHandle(hToken);
			return FALSE;
		}

		// Get a handle to the interactive window station.
		hwinsta = OpenWindowStation(
			_T("winsta0"),                   // the interactive window station
			FALSE,							// handle is not inheritable
			READ_CONTROL | WRITE_DAC);		// rights to read/write the DACL

		if(hwinsta == NULL)
		{
			SetProcessWindowStation (hwinstaSave);
			CloseHandle(hToken);
			return FALSE;
		}

		// To get the correct default desktop, set the caller's
		// window station to the interactive window station.
		if(!SetProcessWindowStation(hwinsta))
		{
			SetProcessWindowStation (hwinstaSave);
			CloseWindowStation(hwinsta);
			CloseHandle(hToken);
			return FALSE;
		}

		// Get a handle to the interactive desktop.
		hdesk = OpenDesktop(
			_T("default"),     // the interactive window station
			0,             // no interaction with other desktop processes
			FALSE,         // handle is not inheritable
			READ_CONTROL | // request the rights to read and write the DACL
			WRITE_DAC |
			DESKTOP_WRITEOBJECTS |
			DESKTOP_READOBJECTS);

		if(hdesk == NULL)
		{
			SetProcessWindowStation(hwinstaSave);
			CloseWindowStation(hwinsta);
			CloseHandle(hToken);
			return FALSE;
		}

		// Restore the caller's window station.
		if(!SetProcessWindowStation(hwinstaSave))
		{
			SetProcessWindowStation (hwinstaSave);
			CloseWindowStation(hwinsta);
			CloseDesktop(hdesk);
			CloseHandle(hToken);
			return FALSE;
		}

		// Impersonate client to ensure access to executable file.
		if(!ImpersonateLoggedOnUser(hToken))
		{
			SetProcessWindowStation (hwinstaSave);
			CloseWindowStation(hwinsta);
			CloseDesktop(hdesk);
			CloseHandle(hToken);
			return FALSE;
		}

		// Initialize the STARTUPINFO structure.
		// Specify that the process runs in the interactive desktop.
		ZeroMemory(	&si, sizeof(STARTUPINFO));
		si.cb		=  sizeof(STARTUPINFO);
		si.lpDesktop =  _T("winsta0\\default");

		TCHAR   csCmdParam[MAX_PATH] = {0};
		wcscpy_s(csCmdParam, _countof(csCmdParam), csCommandLineParam);

		LPVOID  pEnv = NULL;
		DWORD dwCreationFlag = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
		HMODULE hModule = LoadLibrary(L"Userenv.dll");
		if(hModule)
		{
			typedef BOOL(WINAPI* LPFN_CreateEnvironmentBlock)(__out LPVOID* lpEnvironment, __in HANDLE hToken, __in BOOL bInherit);
			LPFN_CreateEnvironmentBlock lpfnCreateEnvironmentBlock = (LPFN_CreateEnvironmentBlock)GetProcAddress(hModule, "CreateEnvironmentBlock");
			if(lpfnCreateEnvironmentBlock != NULL)
			{
				if(lpfnCreateEnvironmentBlock(&pEnv, hToken, FALSE))
				{
					dwCreationFlag |= CREATE_UNICODE_ENVIRONMENT;    
				}
				else
				{
					pEnv = NULL;
				}
			}
		}

		bResult = CreateProcessAsUser(
			hToken,            // client's access token
			csProcessPath,     // file to execute
			csCmdParam,		 // command line
			NULL,              // pointer to process SECURITY_ATTRIBUTES
			NULL,              // pointer to thread SECURITY_ATTRIBUTES
			FALSE,             // handles are not inheritable
			dwCreationFlag,    // creation flags
			pEnv,              // pointer to new environment block
			NULL,              // name of current directory
			&si,               // pointer to STARTUPINFO structure
			&pi                // receives information about new process
			);

		if(bResult && bWait && pi.hProcess)
		{
			::WaitForSingleObject(pi.hProcess, 1000 * 60 * 2);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
		}

		if(hwinstaSave)
			SetProcessWindowStation (hwinstaSave);
		if(hwinsta)
			CloseWindowStation(hwinsta);
		if(hdesk)
			CloseDesktop(hdesk);
		if(hToken)
			CloseHandle(hToken);
		if(hModule)
			FreeLibrary(hModule);

		// End impersonation of client.
		RevertToSelf();
		return bResult;
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in KeyLoggerScannerDll.cpp StartProcess "));
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: CreateProcess
In Parameters	: CString csEXEName, bool bHide, DWORD dwWaitPeriod
Out Parameters	: void
Purpose			: This Function Starts any exe with CreateProcess
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
void CExecuteProcess::RestoreEXE(CString csEXEName, LPTSTR szCmdLine, bool bHide, DWORD dwWaitPeriod)
{
	try
	{
		PROCESS_INFORMATION piInfo;
		STARTUPINFO sInfo;

		sInfo.cb = sizeof(STARTUPINFO);
		sInfo.lpReserved = NULL;
		sInfo.lpReserved2 = NULL;
		sInfo.cbReserved2 = 0;
		sInfo.lpDesktop = NULL;
		sInfo.lpTitle = NULL;
		sInfo.dwFlags = bHide? STARTF_USESHOWWINDOW: 0;
		sInfo.dwX = 0;
		sInfo.dwY = 0;
		sInfo.dwFillAttribute = 0;
		sInfo.wShowWindow = bHide? SW_HIDE: SW_SHOW;

		BOOL bSuccess = ::CreateProcess(csEXEName, szCmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &sInfo, &piInfo);
		if(bSuccess)
		{
			CloseHandle(piInfo.hThread);

			if(dwWaitPeriod)
			{
				WaitForSingleObject(piInfo.hProcess, dwWaitPeriod);
			}

			CloseHandle(piInfo.hProcess);
		}
	}
	catch(...)
	{
		AddLogEntry(_T("Exception caught in CExecuteProcess::CreateProcess"));
	}
}
/*-------------------------------------------------------------------------------------
Function		: GetTextualSid
In Parameters	: PSID pSid - binary SID, LPTSTR TextualSid - Textual representation of SID,
Out Parameters	: CString - Current User SID
Purpose			: To get current user SID
Author			: Avinash
--------------------------------------------------------------------------------------*/
BOOL CExecuteProcess::GetTextualSid(PSID pSid, // binary SID
									 LPTSTR TextualSid, // buffer for Textual representation of SID
									 LPDWORD lpdwBufferLen // required/provided TextualSid buffersize
									)
{
	PSID_IDENTIFIER_AUTHORITY psia;
	DWORD dwSubAuthorities;
	DWORD dwSidRev=SID_REVISION;
	DWORD dwCounter;
	DWORD dwSidSize;

	// Validate the binary SID.
	if(!IsValidSid(pSid))
	{
		return FALSE;
	}

	// Get the identifier authority value from the SID.
	psia = GetSidIdentifierAuthority(pSid);

	// Get the number of subauthorities in the SID.
	dwSubAuthorities = *GetSidSubAuthorityCount(pSid);

	// Compute the buffer length.
	dwSidSize=(15 + 12 + (12 * dwSubAuthorities) + 1)* sizeof(TCHAR);

	// Check input buffer length.
	// If too small, indicate the proper size and set the last error.
	if(*lpdwBufferLen < dwSidSize)
	{
		*lpdwBufferLen = dwSidSize;
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	// Add 'S' prefix and revision number to the string.
	dwSidSize=_stprintf_s(TextualSid, *lpdwBufferLen, TEXT("S-%lu-"), dwSidRev);
	// Add a SID identifier authority to the string.
	if((psia->Value[0] != 0) || (psia->Value[1] != 0))
	{
		dwSidSize+=_stprintf_s(TextualSid + lstrlen(TextualSid),*lpdwBufferLen - _tcslen(TextualSid),TEXT("0x%02hx%02hx%02hx%02hx%02hx%02hx"),(USHORT)psia->Value[0],(USHORT)psia->Value[1],(USHORT)psia->Value[2],(USHORT)psia->Value[3],(USHORT)psia->Value[4],(USHORT)psia->Value[5]);
	}
	else
	{
		dwSidSize+=_stprintf_s(TextualSid + lstrlen(TextualSid),*lpdwBufferLen - _tcslen(TextualSid),TEXT("%lu"),(ULONG)(psia->Value[5]) +(ULONG)(psia->Value[4] << 8) +(ULONG)(psia->Value[3] << 16) +(ULONG)(psia->Value[2] << 24));
	}
	// Add SID subauthorities to the string.
	for (dwCounter=0; dwCounter < dwSubAuthorities; dwCounter++)
	{
		if(dwSidSize >= *lpdwBufferLen)
			return FALSE;
		dwSidSize+=_stprintf_s(TextualSid + dwSidSize, *lpdwBufferLen - _tcslen(TextualSid),TEXT("-%lu"),*GetSidSubAuthority(pSid, dwCounter));
	}
	return TRUE;
}

/*-------------------------------------------------------------------------------------
Function		: GetCurrentUserSid
In Parameters	: HANDLE hProcHandle : Handle of process
Out Parameters	: CString - Current User SID
Purpose			: To get current user SID
Author			: Avinash
--------------------------------------------------------------------------------------*/
CString CExecuteProcess::GetCurrentUserSid(HANDLE hProcess)
{
	HANDLE hToken = NULL;
	DWORD dwBufferSize = 0;
	PTOKEN_USER pTokenUser = NULL;
	CString csMsg;

	/* Open the access token associated with the calling process.*/
	if(!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		csMsg.Format(_T("OpenProcessToken failed.GetLastError returned: %d\n"),
			GetLastError());
		return CString(_T(""));
	}

	/* get the size of the memory buffer needed for the SID */
	(void)GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);
	pTokenUser = (PTOKEN_USER)malloc(dwBufferSize);
	if(!pTokenUser)
	{
		return CString(_T(""));
	}
	memset(pTokenUser, 0, dwBufferSize);

	/* Retrieve the token information in a TOKEN_USER structure.*/
	if(!GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize,&dwBufferSize))
	{
		free(pTokenUser);
		csMsg.Format(_T("2 GetTokenInformation failed.GetLastError returned: %d\n"),
			GetLastError());
		return CString(_T(""));
	}
	CloseHandle(hToken);
	if(!IsValidSid(pTokenUser->User.Sid))
	{
		csMsg.Format(_T("The owner SID is invalid.\n"));
		free(pTokenUser);
		return CString(_T(""));
	}
	WCHAR chSID[256];
	DWORD dw = 256;
	GetTextualSid(pTokenUser->User.Sid, chSID,&dw);
	free(pTokenUser);
	return CString(chSID);

}

/*--------------------------------------------------------------------------------------
Function       : GetCurrentUserSid
In Parameters  :
Out Parameters : CString
Description    : Returns the current User Sid
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CString CExecuteProcess::GetCurrentUserSid()
{
	return GetCurrentUserSid(GetExplorerProcessHandle());
}

/*--------------------------------------------------------------------------------------
Function       : LaunchURLInBrowser
In Parameters  : CString
Out Parameters : BOOL
Description    : Returns TRUE if Browser is launched successfully otherwise FALSE
Author         : Swapnil Lokhande
--------------------------------------------------------------------------------------*/
BOOL CExecuteProcess::LaunchURLInBrowser(CString csURL, BOOL bShow)
{
	BOOL bRetVal = FALSE;
	CRegistry objReg;
	CString csDefaultBrowser;

	objReg.Get(L"http\\Shell\\open\\command", L"", csDefaultBrowser, HKEY_CLASSES_ROOT);
	csDefaultBrowser.MakeLower();
	int iPos = csDefaultBrowser.Find(L".exe");
	csDefaultBrowser = csDefaultBrowser.Left(iPos + 5);
	csDefaultBrowser.Trim();
	csDefaultBrowser.Replace(L"\"", L"");

	DWORD dwRetVal = GetFileAttributes(csDefaultBrowser);
	if(dwRetVal == 0xFFFFFFFF)	//File doesnot exists
	{
		objReg.Get(L"Applications\\iexplore.exe\\shell\\open\\command", L"", csDefaultBrowser, HKEY_CLASSES_ROOT);
		csDefaultBrowser.MakeLower();
		int iPos = csDefaultBrowser.Find(L".exe");
		csDefaultBrowser = csDefaultBrowser.Left(iPos + 5);
		csDefaultBrowser.Trim();
		csDefaultBrowser.Replace(L"\"", L"");
	}

	if(!csDefaultBrowser.GetLength())
	{
		csDefaultBrowser = csURL;
	}

	if(ShellExecuteEx(csDefaultBrowser, csURL, false, L"", bShow))
		bRetVal = TRUE;

	return bRetVal;
}

/*--------------------------------------------------------------------------------------
Function       : ExecuteProcess
In Parameters  : LPCTSTR szAppPath, LPCTSTR szCmdArgs, bool bHide, DWORD dwWait
Out Parameters : bool
Description    : Returns true if application is launched successfully otherwise false
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CExecuteProcess::ExecuteProcess(LPCTSTR szAppPath, LPCTSTR szCmdArgs, bool bHide, DWORD dwWait,bool bTeminate)
{
	CString csCmdParam;
	PROCESS_INFORMATION piInfo = {0};
	STARTUPINFO sInfo = {0};

	sInfo.cb = sizeof(STARTUPINFO);
	sInfo.lpReserved = NULL;
	sInfo.lpReserved2 = NULL;
	sInfo.cbReserved2 = 0;
	sInfo.lpDesktop = NULL;
	sInfo.lpTitle = NULL;
	sInfo.dwFlags = bHide? STARTF_USESHOWWINDOW: 0;
	sInfo.dwX = 0;
	sInfo.dwY = 0;
	sInfo.dwFillAttribute = 0;
	sInfo.wShowWindow = bHide? SW_HIDE: 0;

	if(szAppPath && szCmdArgs)
	{
		csCmdParam.Format(L"\"%s\" %s", szAppPath, szCmdArgs);
	}
	else if(szAppPath)
	{
		csCmdParam.Format(L"\"%s\"", szAppPath);
	}
	else
	{
		return false;
	}


	BOOL bSuccess = ::CreateProcess(NULL, csCmdParam.GetBuffer(), NULL, NULL, FALSE, 0, NULL, NULL, &sInfo, &piInfo);
	if(bSuccess)
	{
		DWORD	dwExitCode = 0x00;
		GetExitCodeProcess(piInfo.hProcess,&dwExitCode);
		

		if(dwWait && piInfo.hProcess)
		{
			WaitForSingleObject(piInfo.hProcess, dwWait);
		}

		if (bTeminate && piInfo.hProcess)
		{
			TerminateProcess(piInfo.hProcess,0x00);
		}

		CloseHandle(piInfo.hThread);
		CloseHandle(piInfo.hProcess);
	}
	
	csCmdParam.ReleaseBuffer();
	return bSuccess? true: false;
}
