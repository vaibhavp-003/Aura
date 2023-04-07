#pragma once

#include <lmshare.h>
#include <lmapibuf.h>
#include <lmerr.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/*
#ifndef NTSTATUS
	typedef	 ULONG  NTSTATUS;
#endif
*/

//typedef LPFN_RtlIpv4StringToAddressW = NTSYSAPI NTSTATUS ()(PCWSTR  szInString,BOOLEAN bStrict,LPCWSTR *pszTerminator,in_addr *Addr);
typedef INT (WSAAPI *LPFN_InetPtonW)(INT Family,PCWSTR pszAddrString,PVOID pAddrBuf);


class CMaxFileShareInfo
{
public:
	CMaxFileShareInfo(void);
	~CMaxFileShareInfo(void);

	HMODULE							m_hModuleNtDll;
	//LPFN_RtlIpv4StringToAddressW	m_LpnfRtlIpv4StringToAddressW;
	//LPFN_RtlIpv6StringToAddressW	m_LpnfRtlIpv6StringToAddressW;
	LPFN_InetPtonW					m_LpfnInetPtonW;

	BOOL GetIP4FromCompName(LPTSTR pszCompName,LPTSTR pszIpAddress);
	BOOL GetSuspComputerName(LPTSTR pszIpAddress, LPTSTR pszCompName, BOOL *bIsIPV6, LPTSTR pszIPV4Address);
	BOOL EnumSharesOfUser(LPCTSTR pszUserName, LPCTSTR pszFile2Watch);
	BOOL GetSharedFileInfo(LPCTSTR pszFile2Check, LPTSTR pszUserName, LPTSTR pszComputerName, LPTSTR pszIPV4Address, LPTSTR pszIPV6Address);
	BOOL DelUserSession(LPCTSTR pszUserName);	

	BOOL GetUnicodeString(LPCSTR pszAnsiIN, LPTSTR pszUnicodeOUT);
	BOOL GetAnsiString(LPCTSTR pszUnicodeIN,LPSTR pszAnsiOUT);
};
