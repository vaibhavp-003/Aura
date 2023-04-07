/*======================================================================================
FILE             : MaxExceptionFilter.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshit Kasliwal
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 07/09/2009
NOTES		     : Max Exception Filter Class for:
					1. Structured Exception
					2. Send Error Report Exception
					3. Invalid Param handler for CRT safety functions
					4. Creating Crash Dumps 
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "MaxExceptionFilter.h"

#ifndef SETTING_FOLDER
#define SETTING_FOLDER			_T("setting\\")
#endif
#ifndef CURRENT_SETTINGS_INI
#define CURRENT_SETTINGS_INI	_T("CurrentSettings.ini") //this file can contain any current settings for any product. : Avinash Bhardwaj
#endif
#ifndef SETTING_VAL_INI
#define SETTING_VAL_INI			_T("Settings")
#endif

#ifdef WIN64
#ifndef _IMAGEHLP_
#include "..\..\..\..\NIH\x64\DBGHELP\Dbghelp64.h"
#endif
#else
#ifndef _IMAGEHLP_
#include "..\..\..\..\NIH\Win32\DBGHELP\Dbghelp32.h"
#endif
#endif

#include <atlbase.h>

#include <string>
using namespace std;

#ifdef _UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

_invalid_parameter_handler CMaxExceptionFilter::m_lpHandler = NULL;
_invalid_parameter_handler CMaxExceptionFilter::m_lpOldHandler = NULL;

typedef	BOOL (WINAPI * MINIDUMP_WRITE_DUMP)(
	IN HANDLE			hProcess,
	IN DWORD			ProcessId,
	IN HANDLE			hFile,
	IN MINIDUMP_TYPE	DumpType,
	IN CONST PMINIDUMP_EXCEPTION_INFORMATION	ExceptionParam, OPTIONAL
	IN PMINIDUMP_USER_STREAM_INFORMATION		UserStreamParam, OPTIONAL
	IN PMINIDUMP_CALLBACK_INFORMATION			CallbackParam OPTIONAL
	);


/*--------------------------------------------------------------------------------------
Function       : CMaxExceptionFilter
In Parameters  :
Out Parameters :
Description    : C'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CMaxExceptionFilter::CMaxExceptionFilter()
{
}

/*--------------------------------------------------------------------------------------
Function       : ~CMaxExceptionFilter
In Parameters  :
Out Parameters :
Description    : d'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CMaxExceptionFilter::~CMaxExceptionFilter()
{

}

/*--------------------------------------------------------------------------------------
Function       : InitializeExceptionFilter
In Parameters  : EXFILTER_TYPE eFilterType,
Out Parameters : void
Description    : Setting the invalid param handler for CRT safety functions
Setting the Unhandled Exception Filter class
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CMaxExceptionFilter::InitializeExceptionFilter(EXFILTER_TYPE eFilterType)
{
	m_lpHandler = CMaxExceptionFilter::MaxInvalidParamHandler;
	m_lpOldHandler = _set_invalid_parameter_handler(m_lpHandler);
	// Disable the message box for assertions.
	_CrtSetReportMode(_CRT_ASSERT, 0);
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
	::SetUnhandledExceptionFilter((PTOP_LEVEL_EXCEPTION_FILTER)MaxUnhandledExceptionFilter);
}

/*--------------------------------------------------------------------------------------
Function       : MaxInvalidParamHandler
In Parameters  : const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t pReserved,
Out Parameters : void
Description    : Callback for the CRT safety functions.It is called if any of the CRT functions gets
invalid parameters E.g._tcscpy_s has source paramter length greater than the
destination function
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CMaxExceptionFilter::MaxInvalidParamHandler(const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t pReserved)
{
#ifndef NO_EXCEPTION_LOG
	AddLogEntry(_T(" == >INVALID PARAM detected for Safety Functions"));
#endif
}

/*--------------------------------------------------------------------------------------
Function       :
In Parameters  :  unsigned int code, struct _EXCEPTION_POINTERS *ep, LPCTSTR lpExMsg, LPCTSTR lpFileName, bool bTakeDump,
Out Parameters : int Filter
Description    : Exception Filter function called from the __except of the SEH
Detects the type of exception and initiates memory dump creation
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
int CMaxExceptionFilter::Filter(unsigned int code, struct _EXCEPTION_POINTERS *ep, LPCTSTR lpExMsg, LPCTSTR lpFileName, bool bTakeDump)
{
	if(!lpFileName)
	{
		return Filter(code, ep, lpExMsg, bTakeDump);
	}

	switch(code)
	{
	case EXCEPTION_ACCESS_VIOLATION:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_ACCESS_VIOLATION: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_DATATYPE_MISALIGNMENT: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_BREAKPOINT:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_BREAKPOINT: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_SINGLE_STEP:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_SINGLE_STEP: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_ARRAY_BOUNDS_EXCEEDED: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_DENORMAL_OPERAND: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_DIVIDE_BY_ZERO: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_FLT_INEXACT_RESULT:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_INEXACT_RESULT: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_FLT_INVALID_OPERATION:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_INVALID_OPERATION: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_FLT_OVERFLOW:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_OVERFLOW: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_FLT_STACK_CHECK:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_STACK_CHECK: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_FLT_UNDERFLOW:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_UNDERFLOW: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_INT_DIVIDE_BY_ZERO: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_INT_OVERFLOW:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_INT_OVERFLOW: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_PRIV_INSTRUCTION:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_PRIV_INSTRUCTION: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_IN_PAGE_ERROR:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_IN_PAGE_ERROR: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_ILLEGAL_INSTRUCTION    :
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_ILLEGAL_INSTRUCTION: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_NONCONTINUABLE_EXCEPTION: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_STACK_OVERFLOW          :
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_STACK_OVERFLOW: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_INVALID_DISPOSITION     :
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_INVALID_DISPOSITION: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_GUARD_PAGE              :
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_GUARD_PAGE: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	case EXCEPTION_INVALID_HANDLE          :
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_INVALID_HANDLE: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	default:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >Default Exception: %s, %s"), lpExMsg, lpFileName);
#endif
			break;
		}
	}
	if(bTakeDump)
	{
		__try
		{
			CreateMiniDump(ep);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >Failed in Creating MiniDump: %s, %s"), lpExMsg, lpFileName);
#endif
		}
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

/*--------------------------------------------------------------------------------------
Function       :
In Parameters  :  unsigned int code, struct _EXCEPTION_POINTERS *ep, LPCTSTR lpExMsg, bool bTakeDump,
Out Parameters : int Filter
Description    : Exception Filter function called from the __except of the SEH
Detects the type of exception and initiates memory dump creation
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
int CMaxExceptionFilter::Filter(unsigned int code, struct _EXCEPTION_POINTERS *ep,LPCTSTR lpExMsg,bool bTakeDump)
{
	switch(code)
	{
	case EXCEPTION_ACCESS_VIOLATION:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_ACCESS_VIOLATION:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_DATATYPE_MISALIGNMENT:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_BREAKPOINT:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_BREAKPOINT:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_SINGLE_STEP:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_SINGLE_STEP:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_ARRAY_BOUNDS_EXCEEDED:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_DENORMAL_OPERAND:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_DIVIDE_BY_ZERO:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_FLT_INEXACT_RESULT:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_INEXACT_RESULT:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_FLT_INVALID_OPERATION:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_INVALID_OPERATION:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_FLT_OVERFLOW:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_OVERFLOW:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_FLT_STACK_CHECK:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_STACK_CHECK:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_FLT_UNDERFLOW:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_FLT_UNDERFLOW:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_INT_DIVIDE_BY_ZERO:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_INT_OVERFLOW:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_INT_OVERFLOW:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_PRIV_INSTRUCTION:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_PRIV_INSTRUCTION:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_IN_PAGE_ERROR:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_IN_PAGE_ERROR:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_ILLEGAL_INSTRUCTION    :
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_ILLEGAL_INSTRUCTION:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_NONCONTINUABLE_EXCEPTION:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_STACK_OVERFLOW          :
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_STACK_OVERFLOW:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_INVALID_DISPOSITION     :
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_INVALID_DISPOSITION:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_GUARD_PAGE              :
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_GUARD_PAGE:%s"),lpExMsg);
#endif
			break;
		}
	case EXCEPTION_INVALID_HANDLE          :
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >EXCEPTION_INVALID_HANDLE:%s"),lpExMsg);
#endif
			break;
		}
	default:
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >Default Exception:%s"),lpExMsg);
#endif
			break;
		}
	}
	if(bTakeDump)
	{
		__try{
			CreateMiniDump(ep);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(_T(" == >Failed in Creating MiniDump"));
#endif
		}
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

/*--------------------------------------------------------------------------------------
Function       : SEHExecuteProc
In Parameters  : SEHExecProc fnPtrExecProc, LPCTSTR lpMsg,
Out Parameters : bool
Description    : Can be used for any static/gobal function by passing the Pointer to the function
The function call will be protected by SEH and the user does not need to
write exception handling code
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CMaxExceptionFilter::SEHExecuteProc(SEHExecProc fnPtrExecProc, LPCTSTR lpMsg)
{
	bool bRet = true;
	__try{
		if(fnPtrExecProc)
		{
			fnPtrExecProc();
		}

	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),lpMsg))
	{
		bRet = false;
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : MaxUnhandledExceptionFilter
In Parameters  : PEXCEPTION_POINTERS pExcPtrs,
Out Parameters : LONG
Description    : Unhandled Exception filter
When any exception occur in the entire module which is not handled
This function will be called.Curretnly we are terminating the process
by taking a memory dump
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
LONG CMaxExceptionFilter::MaxUnhandledExceptionFilter(PEXCEPTION_POINTERS pExcPtrs)
{
#ifndef NO_EXCEPTION_LOG
	AddLogEntry(_T(" == >UNHANDLED EXCEPTON FILTER: NOWHERE TO GO: Terminating!!!"));
	OutputDebugString(_T(" == >UNHANDLED EXCEPTON FILTER: NOWHERE TO GO: Terminating!!!"));
#endif
	CreateMiniDump(pExcPtrs);
	return EXCEPTION_EXECUTE_HANDLER;
}


/*--------------------------------------------------------------------------------------
Function       : CreateMiniDump
In Parameters  : EXCEPTION_POINTERS* pExceptionPointers,
Out Parameters : BOOL
Description    : Creates a mini-dump by extracting the information from the SEH caught
exception.Uses Dbghelp.dll
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
BOOL CMaxExceptionFilter::CreateMiniDump(EXCEPTION_POINTERS* pExceptionPointers)
{
	int nDumpType = GetErrorReportStatus();
	if(nDumpType == 0)
	{
		return true;
	}
	BOOL bRet = FALSE;
	HANDLE hDumpFile=NULL;
	TCHAR szFileName[MAX_PATH*2] = {0};
	::GetModuleFileName(NULL, szFileName, MAX_PATH);
	tstring strAppName = szFileName;
	tstring strDumpPath;
	size_t found = strAppName.rfind(_T("\\"));
	if(found!=string::npos)
	{
		strDumpPath = strAppName.substr(0,found+1);
		strDumpPath += _T("Log\\");
		strAppName = strAppName.substr(found+1);
	}
	SYSTEMTIME stLocalTime;
	GetLocalTime(&stLocalTime);
	SecureZeroMemory(szFileName,sizeof(szFileName));
	if(nDumpType >= 2)
	{
		_stprintf_s(szFileName, MAX_PATH*2, L"%s-%04d%02d%02d-%02d%02d%02d-%ld-%ld.dmp",
			strAppName.c_str(),stLocalTime.wYear, stLocalTime.wMonth, stLocalTime.wDay,
			stLocalTime.wHour, stLocalTime.wMinute, stLocalTime.wSecond,
			GetCurrentProcessId(), GetCurrentThreadId());
	}
	else
	{
		_stprintf_s(szFileName, MAX_PATH*2, L"%s.dmp",
			strAppName.c_str());
	}
	strDumpPath+=szFileName;
	hDumpFile = CreateFile(strDumpPath.c_str(), GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_WRITE|FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);

	if(hDumpFile == INVALID_HANDLE_VALUE)
	{
		return bRet;
	}
	MINIDUMP_EXCEPTION_INFORMATION ExpParam;
	ExpParam.ThreadId = GetCurrentThreadId();
	ExpParam.ExceptionPointers = pExceptionPointers;
	ExpParam.ClientPointers = FALSE;
	HMODULE hDbgHelp = LoadLibrary(_T("DBGHELP.DLL"));
	if(NULL == hDbgHelp)
	{
		CloseHandle(hDumpFile);
		::DeleteFile(strDumpPath.c_str());
		return bRet;
	}
	MINIDUMP_WRITE_DUMP	lpfnMiniDumpWriteDump=NULL;
	lpfnMiniDumpWriteDump = (MINIDUMP_WRITE_DUMP)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
	if(lpfnMiniDumpWriteDump)
	{
		MINIDUMP_TYPE eDumpType = static_cast<MINIDUMP_TYPE>(nDumpType);
		bRet = lpfnMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
			hDumpFile,eDumpType ,&ExpParam, NULL, NULL);
		tstring strMsg = _T("Sucessfully created Dump:");
		strMsg+=strDumpPath;

		if(bRet)
		{
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(strMsg.c_str());
#endif
		}
		else
		{
			DWORD dwErr = GetLastError();
			_stprintf_s(szFileName,_T("Failed in creating Dump%d"),dwErr);
#ifndef NO_EXCEPTION_LOG
			AddLogEntry(szFileName);
#endif
		}

	}
	CloseHandle(hDumpFile);
	if(!bRet)
	{
		::DeleteFile(strDumpPath.c_str());
	}
	FreeLibrary(hDbgHelp);
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : GetErrorReportStatus
In Parameters  :
Out Parameters : DWORD
Description    : Send Error report Registry flag
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
DWORD CMaxExceptionFilter::GetErrorReportStatus()
{
	DWORD dwStatus = 0;
	TCHAR szInstallPath[MAX_PATH] = {0};
	GetModuleFileName(0, szInstallPath, MAX_PATH);
	LPTSTR szSlash = _tcsrchr(szInstallPath,_T('\\'));
	if(szSlash == NULL)
	{
		return 1;
	}
	szSlash++;
	*szSlash = 0;
	_tcscat_s(szInstallPath,SETTING_FOLDER);
	_tcscat_s(szInstallPath,CURRENT_SETTINGS_INI);
	dwStatus = GetPrivateProfileInt(SETTING_VAL_INI, _T("DUMP_TYPE"), 0, szInstallPath);
	return dwStatus;
}