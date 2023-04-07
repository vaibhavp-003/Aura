/*=============================================================================
   FILE			: ExecuteProcess.h
   DESCRIPTION	: Header file of CExecuteProcess Class
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
VERSION HISTORY	: 25Dec2007 : Sandip : Ported to VS2005 with Unicode and X64 bit Compatability.	
============================================================================*/
#pragma once
class CExecuteProcess
{

public:
	CExecuteProcess(void);
	~CExecuteProcess(void);
	void RestoreEXE(CString csEXEName, LPTSTR szCmdLine = NULL, bool bHide = false, DWORD dwWaitPeriod = 0);
	bool ShellExecuteEx(CString sExecCmd, CString csParam, bool bWait = false, CString csVerb = L"", BOOL bShow=TRUE);
	static bool ExecuteCommand(CString sExecCmd, CString csParam, bool bWait = false);
	BOOL StartProcessWithToken(CString csProcessPath, CString csCommandLineParam, CString csAccessProcessName, bool bWait = false);
	HANDLE GetExplorerProcessHandle(CString csAccessProcessName = _T("explorer.exe"));
	CString GetCurrentUserSid();
	CString GetCurrentUserSid(HANDLE hProcess);
	BOOL GetTextualSid(PSID pSid, LPTSTR TextualSid, LPDWORD lpdwBufferLen);
	BOOL LaunchURLInBrowser(CString csURL, BOOL bShow=TRUE);
	bool ExecuteCommandWithWait(CString sExecCmd, CString csParam);
	bool ExecuteProcess(LPCTSTR szAppPath, LPCTSTR szCmdArgs, bool bHide, DWORD dwWait = 0,bool bTeminate = false);
};
