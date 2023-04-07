/*======================================================================================
FILE             : NetworkFunctions.h
ABSTRACT         : This class is used to create function pointer and to get process name
DOCUMENTS        : 
AUTHOR           : Dipali Pawar
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 30-Jun-2008
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
#include "pch.h"
#include "NetworkFunctions.h"
#include "SDSystemInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CNetworkFunctions
In Parameters  : void, 
Out Parameters : 
Description    : 
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CNetworkFunctions::CNetworkFunctions(void)
{
	m_lpGetExtendedTcpTable = NULL;
	m_lpGetModuleFileNameEx = NULL;
	m_lpGetModuleBaseName = NULL;
	m_lpSetTcpEntry = NULL;
	m_hIphlpapi = 0;
	m_hPsapi = 0;
}

/*-------------------------------------------------------------------------------------
Function		: MakeFunctionPointer
In Parameters	: void
Out Parameters	: bool : true/false
Purpose			: Load dll and make function pointer
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CNetworkFunctions::MakeFunctionPointer()
{
	// get functions from iphlpapi.dll
	m_hIphlpapi = LoadLibrary(CSystemInfo::m_strSysDir + _T("\\iphlpapi.dll"));
	if(NULL == m_hIphlpapi)
	{
		goto ERROR_EXIT;
	}

	m_lpGetExtendedTcpTable = (LPFN_GetExtendedTcpTable)GetProcAddress(m_hIphlpapi,
															"GetExtendedTcpTable");
	m_lpSetTcpEntry = (LPFN_SetTcpEntry)GetProcAddress(m_hIphlpapi, "SetTcpEntry");
	if(!m_lpGetExtendedTcpTable || !m_lpSetTcpEntry)
	{
		goto ERROR_EXIT;
	}

	// get functions from psapi.dll
	m_hPsapi = LoadLibrary(CSystemInfo::m_strSysDir + _T("\\psapi.dll"));
	if(NULL == m_hPsapi)
	{
		goto ERROR_EXIT;
	}

	m_lpGetModuleFileNameEx = (LPFN_GetModuleFileNameEx)GetProcAddress(m_hPsapi,
														"GetModuleFileNameExW");
	m_lpGetModuleBaseName = (LPFN_GetModuleBaseName)GetProcAddress(m_hPsapi,
														"GetModuleBaseNameW");
	if(!m_lpGetModuleFileNameEx || !m_lpGetModuleBaseName)
	{
		goto ERROR_EXIT;
	}

	return (true);

	//goto needed for cleanup
ERROR_EXIT:

	if(m_hPsapi)
	{
		FreeLibrary(m_hPsapi);
	}

	if(m_hIphlpapi)
	{
		FreeLibrary(m_hIphlpapi);
	}

	m_lpGetExtendedTcpTable = NULL;
	m_lpGetModuleFileNameEx = NULL;
	m_lpGetModuleBaseName = NULL;
	m_lpSetTcpEntry = NULL;
	m_hIphlpapi = NULL;
	m_hPsapi = NULL;
	return (false);
}

/*-------------------------------------------------------------------------------------
Function		: DestroyFunctionPointer
In Parameters	: void
Out Parameters	: bool - true
Purpose			: UnLoad dll and delete function pointer
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CNetworkFunctions::DestroyFunctionPointer()
{
	if(m_hIphlpapi)
	{
		FreeLibrary(m_hIphlpapi);
		m_hIphlpapi = NULL;
		m_lpGetExtendedTcpTable = NULL;
		m_lpSetTcpEntry = NULL;
	}

	if(m_hPsapi)
	{
		FreeLibrary(m_hPsapi);
		m_hPsapi = NULL;
		m_lpGetModuleFileNameEx = NULL;
		m_lpGetModuleBaseName = NULL;
	}

	return (true);
}

/*-------------------------------------------------------------------------------------
Function		: GetProcessImageNameByID
In Parameters	: DWORD dwProcID - PID of process
TCHAR * szImageName - Image name
DWORD cbImageName - size
Out Parameters	: bool
Purpose			: Get Module name for given PID
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CNetworkFunctions::GetProcessImageNameByID(DWORD dwProcID, TCHAR * szImageName, DWORD cbImageName)
{
	switch(dwProcID)
	{
	case 4:
		{
			_tcscpy_s(szImageName, cbImageName, _T("System"));
			return (true);
		}
	case 0:
		{
			_tcscpy_s(szImageName, cbImageName, _T("System Process"));
			return (true);
		}
	default:
		;
	}

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcID);
	if(NULL == hProcess)
	{
		return (false);
	}

	m_lpGetModuleFileNameEx(hProcess, 0, szImageName, cbImageName);
	CloseHandle(hProcess);
	return (true);
}

/*--------------------------------------------------------------------------------------
Function       : Convert2State
In Parameters  : DWORD dwState, 
Out Parameters : CString 
Description    : convert the connection state
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CString CNetworkFunctions::Convert2State(DWORD dwState)
{
	switch(dwState)
	{
	case MIB_TCP_STATE_CLOSED:
		{
			return L"CLOSED";
		}
	case MIB_TCP_STATE_LISTEN:
		{
			return L"LISTENING";
		}
	case MIB_TCP_STATE_SYN_SENT:
		{
			return L"SYN_SENT";
		}
	case MIB_TCP_STATE_SYN_RCVD:
		{
			return L"SYN_RECEIVED";
		}
	case MIB_TCP_STATE_ESTAB:
		{
			return L"ESTABLISHED";
		}
	case MIB_TCP_STATE_FIN_WAIT1:
		{
			return L"FIN_WAIT1";
		}
	case MIB_TCP_STATE_FIN_WAIT2:
		{
			return L"FIN_WAIT2";
		}
	case MIB_TCP_STATE_CLOSE_WAIT:
		{
			return L"CLOSE_WAIT";
		}
	case MIB_TCP_STATE_CLOSING:
		{
			return L"CLOSING";
		}
	case MIB_TCP_STATE_LAST_ACK:
		{
			return L"LAST_ACK";
		}
	case MIB_TCP_STATE_TIME_WAIT:
		{
			return L"TIME_WAIT";
		}
	case MIB_TCP_STATE_DELETE_TCB:
		{
			return L"DELETE_TCB";
		}
	default:
		{
			return L"UNKNOWN";
		}
	}
	return L"";
}

/*-------------------------------------------------------------------------------------
Function		: GetProcessImageNameByID
In Parameters	: DWORD dwProcID - PID of process
TCHAR * szImageName - Image name
DWORD cbImageName - size
Out Parameters	: bool
Purpose			: Get Module name for given PID
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CNetworkFunctions::GetProcessBaseNameByID(DWORD dwProcID, TCHAR * szImageName, DWORD cbImageName)
{
	switch(dwProcID)
	{
	case 4:
		{
			_tcscpy_s(szImageName, cbImageName, _T("System"));
			return (true);
		}
	case 0:
		{
			_tcscpy_s(szImageName, cbImageName, _T("System Process"));
			return (true);
		}
	}

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcID);
	if(NULL == hProcess)
	{
		return (false);
	}

	m_lpGetModuleBaseName(hProcess, 0, szImageName, cbImageName);
	CloseHandle(hProcess);
	return (true);
}

/*-------------------------------------------------------------------------------------
Function		: MakeStringIP
In Parameters	: TCHAR * szIPAddress - string ip address
DWORD dwSize - size of ip address
in_addr * pIpAddr - IP address
Out Parameters	: bool
Purpose			: Convert ip from in_addr to string
Author			: Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CNetworkFunctions::MakeStringIP(TCHAR * szIPAddress, DWORD dwSize, in_addr * pIpAddr)
{
	if(dwSize < 20)
	{
		return (false);
	}

	memset(szIPAddress, 0, dwSize * sizeof(TCHAR));
	_stprintf_s(szIPAddress, dwSize, _T("%d.%d.%d.%d"), pIpAddr ->S_un.S_un_b.s_b1,
														pIpAddr ->S_un.S_un_b.s_b2,
														pIpAddr ->S_un.S_un_b.s_b3,
														pIpAddr ->S_un.S_un_b.s_b4);
	return (true);
}