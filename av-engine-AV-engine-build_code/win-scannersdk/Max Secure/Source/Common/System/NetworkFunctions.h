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
#pragma once
#include <iprtrmib.h>
#include <winsock2.h>
#include <Iphlpapi.h>

#ifdef _VS_2005_
typedef enum
{
	TCP_TABLE_BASIC_LISTENER,
	TCP_TABLE_BASIC_CONNECTIONS,
	TCP_TABLE_BASIC_ALL,
	TCP_TABLE_OWNER_PID_LISTENER,
	TCP_TABLE_OWNER_PID_CONNECTIONS,
	TCP_TABLE_OWNER_PID_ALL,
	TCP_TABLE_OWNER_MODULE_LISTENER,
	TCP_TABLE_OWNER_MODULE_CONNECTIONS,
	TCP_TABLE_OWNER_MODULE_ALL
}TCP_TABLE_CLASS, *PTCP_TABLE_CLASS;
#endif

typedef DWORD(WINAPI * LPFN_GetExtendedTcpTable)(PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved);
typedef DWORD(WINAPI * LPFN_GetModuleFileNameEx)(HANDLE hProcess, HMODULE hModule, LPTSTR lpFilename, DWORD nSize);
typedef DWORD(WINAPI * LPFN_GetModuleBaseName)	(HANDLE hProcess, HMODULE hModule, LPTSTR lpBaseName, DWORD nSize);
typedef DWORD(WINAPI * LPFN_SetTcpEntry)			(PMIB_TCPROW pTcpRow);

class CNetworkFunctions
{
public:
	CNetworkFunctions(void);
	inline ~CNetworkFunctions(void){};

	bool MakeFunctionPointer();
	bool DestroyFunctionPointer();
	bool MakeStringIP(TCHAR * szIPAddress, DWORD dwSize, in_addr * pIpAddr);
	bool GetProcessImageNameByID(DWORD dwProcID, TCHAR * szImageName, DWORD cbImageName);
	bool GetProcessBaseNameByID(DWORD dwProcID, TCHAR * szImageName, DWORD cbImageName);
	CString Convert2State(DWORD dwState);

	LPFN_GetExtendedTcpTable	m_lpGetExtendedTcpTable;
	LPFN_GetModuleFileNameEx	m_lpGetModuleFileNameEx;
	LPFN_GetModuleBaseName		m_lpGetModuleBaseName;
	LPFN_SetTcpEntry			m_lpSetTcpEntry;
	HMODULE						m_hIphlpapi;
	HMODULE						m_hPsapi;
};
