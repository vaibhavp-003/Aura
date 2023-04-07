/*======================================================================================
FILE             : Logger.cpp
ABSTRACT         : COntains the implementation of a Singleton Logger Class
DOCUMENTS	     : Refer VSS Documents folder for details
AUTHOR		     : Darshit Kasliwal
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
				  
CREATION DATE    : 9/04/2009 5:14 PM
NOTES		     : Implements the Singleton Logger class
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "Logger.h"
#include <shlwapi.h>

using namespace std;
#ifdef _UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif

const int MAX_FORMAT_LEN = 4096;
CLogger g_objLogApp;

/*--------------------------------------------------------------------------------------
Function       : CLogger
In Parameters  : 
Out Parameters : 
Description    : C'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CLogger::CLogger()
{
	m_pFile = NULL;
	m_pILogger = NULL;
	m_bShowDetails = true;
	m_bShowConsole =  true;
	::SecureZeroMemory(m_szLogFileName,sizeof(m_szLogFileName));
	m_bFirstLine = true;
};

CLogger::~CLogger()
{
	CloseLog();
}

void CLogger::CloseLog()
{
	if(m_pFile)
	{
		fclose(m_pFile);
		m_pFile = NULL;
	}
}
/*--------------------------------------------------------------------------------------
Function       : Initialize
In Parameters  : LPCTSTR szLogFileName, ILogger *pILogger, 
Out Parameters : CLogger* 
Description    : Initializes the Singleton Logger object
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CLogger::Initialize(LPCTSTR szLogFileName,bool bShowDetails, ILogger *pILogger,bool bShowConsole)
{
	if(NULL == m_pFile)
	{
		m_bShowDetails = bShowDetails;
		m_bShowConsole =  bShowConsole;
		TCHAR szFileName[MAX_PATH*2] = {0};
		tstring strAppName = szLogFileName;
		size_t found = strAppName.rfind(_T("\\"));
		tstring strLogPath;
		if (found ==string::npos)
		{
			::GetModuleFileName(NULL, szFileName, MAX_PATH);
			strAppName = szFileName;
			found = strAppName.rfind(_T("\\"));
			if (found!=string::npos)
			{
				strLogPath = strAppName.substr(0,found+1);
				strLogPath += _T("Log\\");
				if(!::PathIsDirectory(strLogPath.c_str()))
				{
					CreateDirectory(strLogPath.c_str(), NULL);
				}
				strLogPath += szLogFileName;
			}
		}
		else
		{
			strLogPath = strAppName;
		}
		_tcscpy_s(m_szLogFileName,strLogPath.c_str());
		m_pFile = _tfsopen(m_szLogFileName, _T("a"), 0x40);
		m_pILogger = pILogger;
	}
}

/*--------------------------------------------------------------------------------------
Function       : AddLog
In Parameters  : LPCTSTR szSource, LPCTSTR szDestination, LPCTSTR szFormatString,...,
Out Parameters : void
Description    : Adds log using variable params
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CLogger::AddLog(LPCTSTR szSource,LPCTSTR szDestination,LPCTSTR szFormatString,...)
{
	__try{
		if(m_pFile)
		{
			TCHAR szFormat[MAX_FORMAT_LEN] = {0};
			TCHAR szSeparator[3] = _T("\r\n");
			TCHAR szTempSource[MAX_FORMAT_LEN] = {0};
			TCHAR szTempDestination[MAX_FORMAT_LEN] = {0};
			if(szSource != NULL)
			{
				if(_tcslen(szSource) > 0)


				{
					_tcscpy_s(szTempSource,szSource);
				}
			}

			if(szDestination != NULL)
			{
				if(_tcslen(szDestination) > 0)
				{
					_tcscpy_s(szTempDestination,szDestination);
				}



			}

			if(m_bFirstLine)
			{
				_tcscpy_s(szSeparator,_T(""));
				m_bFirstLine = false;
			}

			TCHAR dbuffer[9];
			TCHAR tbuffer[9];
			_tstrdate_s(dbuffer);
			_tstrtime_s(tbuffer);
			_stprintf_s(szFormat,_T("%s[%s %s]::%d::%d::%s::%s::"),szSeparator, dbuffer, tbuffer,GetCurrentProcessId(),GetCurrentThreadId(),szTempSource,szTempDestination);
			_tprintf(szFormat);
			_ftprintf(m_pFile,szFormat);
			va_list arg_list;
			va_start(arg_list, szFormatString);
			_vftprintf(stdout, szFormatString, arg_list);






			_vftprintf(m_pFile, szFormatString, arg_list);
			_vstprintf_s(szFormat,MAX_FORMAT_LEN,szFormatString,arg_list);
			if(m_pILogger)
			{
				TCHAR szTemp[MAX_FORMAT_LEN];
				_stprintf_s(szTemp,_T("[%s %s]::%d::%d::%s::%s::%s"), dbuffer, tbuffer,GetCurrentProcessId(),GetCurrentThreadId(),szTempSource,szTempDestination,szFormat);
				m_pILogger->OnReceiveLogCallback(szTemp);
			}
			va_end(arg_list);
			fflush(m_pFile);
		}
	}__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}
}

/*--------------------------------------------------------------------------------------
Function       : AddLog
In Parameters  : LPCTSTR szFormatString, ..., 
Out Parameters : void 
Description    : Takes variable arguments as parameter list. 
                 Also calls the callback function if it is registered
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CLogger::AddLog1(LPCTSTR szFormatString, ...)
{
	if(szFormatString == NULL)
	{
		_tprintf(L"***Format String Null***");
		return;
	}
	__try{
		if(m_pFile)
		{
			TCHAR szFormat[MAX_FORMAT_LEN] = {0};
			TCHAR szSeparator[3] = _T("\r\n");
			TCHAR dbuffer[9];
			TCHAR tbuffer[9];
			if(m_bShowDetails)
			{
				_tstrdate_s(dbuffer);
				_tstrtime_s(tbuffer);
				_stprintf_s(szFormat,_T("%s[%s %s]::%d::%d::"),szSeparator, dbuffer, tbuffer,GetCurrentProcessId(),GetCurrentThreadId());

				_ftprintf(m_pFile,szFormat);
			}
			if(m_pILogger)
			{
				m_pILogger->OnReceiveLogCallback(szFormat);
				m_pILogger->OnReceiveLogCallback(LINE_SEPARATOR);
			}
			va_list arg_list;
			va_start(arg_list, szFormatString);
			if(m_bShowConsole)
			{
				_tprintf(szFormat);
				_vftprintf(stdout, szFormatString, arg_list);	
			}
			_vftprintf(m_pFile, szFormatString, arg_list);
			_vstprintf_s(szFormat,MAX_FORMAT_LEN,szFormatString,arg_list);
			if(m_pILogger)
			{
				m_pILogger->OnReceiveLogCallback(szFormat);
			}
			va_end(arg_list);
			fflush(m_pFile);
		}

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}
}

void CLogger::LogCallback(LPCTSTR szFormatString)
{
	if(m_pILogger && szFormatString)
	{
		m_pILogger->OnReceiveLogCallback(szFormatString);
	}
}