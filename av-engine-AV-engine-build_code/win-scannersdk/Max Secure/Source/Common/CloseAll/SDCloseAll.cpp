/*======================================================================================
   FILE				: SDCloseAll.Cpp
   ABSTRACT			: Implementation file of CSDCloseAll class
   DOCUMENTS		: 
   AUTHOR			: Sandip Sanap
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 05-12-2007
   NOTE				:
   VERSION HISTORY	: 	Dec2007 : Sandip : Ported to VS2005 with Unicode and X64 bit Compatability.		
=======================================================================================*/
#include "pch.h"
#include "EnumProcess.h"
#include "SDSystemInfo.h"
#include "RemoteService.h"
#include "Registry.h"
#include "SDCloseAll.h"
//#include <shfolder.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/*--------------------------------------------------------------------------------------
Function       : CSDCloseAll
In Parameters  : void, 
Out Parameters : 
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CSDCloseAll::CSDCloseAll(void)
{
	m_iAppExeCheck = 0;
}

/*--------------------------------------------------------------------------------------
Function       : ~CSDCloseAll
In Parameters  : void, 
Out Parameters : 
Description    : 
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CSDCloseAll::~CSDCloseAll(void)
{
}

/*-------------------------------------------------------------------------------------
Function		: TerminateProc
In Parameters	: LPCTSTR szExePath
Out Parameters	: -
Purpose			: Terminate given process
Author			:
--------------------------------------------------------------------------------------*/
bool TerminateProc(LPCTSTR szExePath)
{
	CEnumProcess objEnumProc;
	return objEnumProc.IsProcessRunning(szExePath, true, false);
}

/*-------------------------------------------------------------------------------------
Function		: MyProcHandler
In Parameters	: LPCTSTR : exe name
				: LPCTSTR : exe path
				: DWORD   : Process ID
				: HANDLE  : hProcess
				: LPVOID  : Class
				: bool	  : terminate enumeration
Out Parameters	: BOOL
Purpose			: callback function called on enumerating processes
Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
BOOL CALLBACK MyProcHandler(LPCTSTR szExeName, LPCTSTR szExePath, DWORD dwProcessID, HANDLE hProcess, LPVOID pThis, bool &bStopEnum)
{
	CSDCloseAll *objSDCloseAll = (CSDCloseAll *)pThis;
	CString csFileName;
	bool bFail = TRUE;
	for(int i = 0; i < objSDCloseAll->m_arrProcessToKill.GetCount(); i++)
	{
		csFileName = objSDCloseAll->m_arrProcessToKill.GetAt(i);
		csFileName.MakeUpper();
		if(((CString)szExeName).MakeUpper().Find(csFileName) != -1)
		{
			if(objSDCloseAll->m_iAppExeCheck != 1 && objSDCloseAll->m_iAppExeCheck != 2 
												&& objSDCloseAll->m_iAppExeCheck != -1)
			{
				CString csStringToDisplay;
				csStringToDisplay = L"To complete installation ";
				csFileName += csStringToDisplay;
				csFileName += szExeName;
				csStringToDisplay =  L"will be closed.\nClick OK to continue installation process.";
				csFileName += csStringToDisplay;
			}
			if(!TerminateProc(szExeName) && objSDCloseAll->m_iAppExeCheck != -1)
			{
				bFail = FALSE;
			}
		}
	}
	return bFail;
}

/*-------------------------------------------------------------------------------------
Function		: CloseApplicationandStopService
In Parameters	: -
Out Parameters	: -
Purpose			: Close main Application Exe and Stop Service
Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
//bool  CSDCloseAll::CloseApplicationandStopService()
//{
//	bool bRet = true;
//	OutputDebugString (_T("Closing the Application"));
//	HWND hwnd=::FindWindowEx(NULL, NULL, _T("#32770"), CSystemInfo::m_csProductName);
//	if(hwnd)
//	{
//		SendMessage(hwnd, WM_CLOSE, NULL, NULL);
//	}
//	return bRet;
//}

/*-------------------------------------------------------------------------------------
Function		: KillProcesses
In Parameters	: CStringArray& arrProcesses
Out Parameters	: bool
Purpose			: Kill all processes contain an array
Author			:
--------------------------------------------------------------------------------------*/
bool CSDCloseAll::KillProcesses(CStringArray& arrProcesses, int iAppExeCheck)
{
	m_arrProcessToKill.Copy(arrProcesses);
	m_iAppExeCheck = iAppExeCheck;
	bool bFail = true;
	CEnumProcess objEnumProc;
	if(!objEnumProc.EnumRunningProcesses((PROCESSHANDLER)MyProcHandler, this) &&  m_iAppExeCheck != -1)
		bFail = false;
	return bFail;
}

/*-------------------------------------------------------------------------------------
Function		: GetIEWithPath
In Parameters	: csIEPath
Out Parameters	:
Purpose			: To get Internet Explorer executable file name with path
Author			: 
-------------------------------------------------------------------------------------*/
void CSDCloseAll::GetIEWithPath(CString &csIEPath)
{
	HKEY hKey;
	LONG lRet;
	CRegistry objRegistry;

	bool bSuccess=true;
	lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, IE_REGISTRY_KEY, 0, KEY_QUERY_VALUE, &hKey);

	if(lRet != ERROR_SUCCESS)
		bSuccess = false;
	else
	{
		objRegistry.Get(IE_REGISTRY_KEY, _T(""), csIEPath, HKEY_LOCAL_MACHINE);
		if(bSuccess == false)
		{
			if(objRegistry.Get(IE_REGISTRY_KEY, _T("Path"), csIEPath, HKEY_LOCAL_MACHINE))
			{
				int n = csIEPath.Replace(';', '\\');
				if(n == 1)
					csIEPath = csIEPath + _T("IExplore.exe");
				else
					csIEPath = csIEPath + _T("\\IExplore.exe");
				return;
			}
		}
	}
	if(bSuccess == false)
	{
		TCHAR lpszPath[MAX_PATH];
		if(SUCCEEDED(SHGetFolderPathW(0, CSIDL_PROGRAM_FILES, NULL, 0, lpszPath)))
		{
			CString csPath = lpszPath;
			csIEPath = csPath + _T("\\Internet Explorer\\iexplore.exe");
		}
		else
		{
			csIEPath = "iexplore.exe";
		}
	}
}
