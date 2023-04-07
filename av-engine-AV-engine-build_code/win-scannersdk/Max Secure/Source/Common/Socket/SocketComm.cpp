/*======================================================================================
   FILE			: SocketComm.cpp
   ABSTRACT		: Implementation of the CSocketComm and associated classes
   DOCUMENTS	: 
   AUTHOR		: Darshan Singh Virdi 
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
   CREATION DATE: 25/12/2003
   VERSION		: 
				  1.1 - Add support for Smart Addressing mode
				  1.2 - Fix various issues with address list (in UDP mode)
				  1.3 - Fix bug when sending message to broadcast address
				  11 Sept 2007, Nupur :	  Unicode Supported.
				  25-Dec-08, Dipali : merged code from nonunicode to unicode file
======================================================================================*/
#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include <process.h>
#include <crtdbg.h>
#include <direct.h>
#include <atlbase.h>
#include "CPUInfo.h"
#include "Registry.h"
#include "SocketComm.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

const DWORD DEFAULT_TIMEOUT = INFINITE;

const TCHAR *CONFORMATION_DATA	= L"DARSHAN";

struct stMessageProxy
{
	SockAddrIn	address;
	BYTE		data[BUFFER_SIZE];
};

void _AddLogEntry(CString sClientIP, CString sServerIP, CString sFormatString, 
				  CString str1 = BLANKSTRING, CString str2 = BLANKSTRING)
{
	CString sData;
	sData.Format(sFormatString, str1, str2);
	sFormatString = sData;
	sData.Format(_T("##[C-%s:S-%s] %s"),
		static_cast<LPCTSTR>(sClientIP),
		static_cast<LPCTSTR>(sServerIP),
		static_cast<LPCTSTR>(sFormatString));
}

//Struct SockAddrIn
/*-----------------------------------------------------------------------------
Function		: Copy
In Parameters	: Struct SockAddrIn
Out Parameters	:
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
SockAddrIn& SockAddrIn::Copy(const SockAddrIn& sin)
{
	memcpy(this, &sin, Size());
	return *this;
}

/*-----------------------------------------------------------------------------
Function		: IsEqual
In Parameters	: Struct SockAddrIn
Out Parameters	:
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool SockAddrIn::IsEqual(const SockAddrIn& sin)
{
	// Is it Equal? - ignore 'sin_zero'
	return (memcmp(this, &sin, Size() - sizeof(sin_zero))== 0);
}

/*-----------------------------------------------------------------------------
Function		: IsGreater
In Parameters	: Struct SockAddrIn
Out Parameters	: bool
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool SockAddrIn::IsGreater(const SockAddrIn& sin)
{
	// Is it Greater? - ignore 'sin_zero'
	return (memcmp(this, &sin, Size() - sizeof(sin_zero)) > 0);
}

/*-----------------------------------------------------------------------------
Function		: IsLower
In Parameters	: Struct SockAddrIn
Out Parameters	: bool
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool SockAddrIn::IsLower(const SockAddrIn& sin)
{
	// Is it Lower? - ignore 'sin_zero'
	return (memcmp(this, &sin, Size() - sizeof(sin_zero))< 0);
}

/*-----------------------------------------------------------------------------
Function		: CreateFrom
In Parameters	: LPCTSTR, LPCTSTR, int
Out Parameters	: bool
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool SockAddrIn::CreateFrom(LPCTSTR sAddr, LPCTSTR sService, int nFamily /*=AF_INET*/)
{
	Clear();
	sin_addr.s_addr = htonl(CSocketComm::GetIPAddress(sAddr));
	sin_port = htons(CSocketComm::GetPortNumber(sService));
	sin_family = nFamily;
	return !IsNull();
}


/*-----------------------------------------------------------------------------
Function		: CSocketComm
In Parameters	: 
Out Parameters	: 
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
CSocketComm::CSocketComm(): m_bServer(false), m_bSmartAddressing(false), 
					m_bBroadcast(false), m_hComm(INVALID_HANDLE_VALUE),
					m_hThread(NULL), m_hMutex(NULL),
m_bConnected(false)
{
	m_hDataProcessed = CreateEvent(NULL, TRUE, FALSE, NULL);
}

/*-----------------------------------------------------------------------------
Function		: ~CSocketComm
In Parameters	: 
Out Parameters	: 
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
CSocketComm::~CSocketComm()
{
	CloseHandle(m_hDataProcessed);
	StopComm();
}

/*-----------------------------------------------------------------------------
Function		: IsOpen
In Parameters	:
Out Parameters	: bool
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::IsOpen()const
{
	return (INVALID_HANDLE_VALUE != m_hComm);
}

/*-----------------------------------------------------------------------------
Function		: IsStart
In Parameters	:
Out Parameters	: bool
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::IsStart()const
{
	return (NULL != m_hThread);
}

/*-----------------------------------------------------------------------------
Function		: IsServer
In Parameters	:
Out Parameters	: bool
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::IsServer()const
{
	return m_bServer;
}

/*-----------------------------------------------------------------------------
Function		: IsBroadcast
In Parameters	:
Out Parameters	: bool
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::IsBroadcast()const
{
	return m_bBroadcast;
}

/*-----------------------------------------------------------------------------
Function		: IsSmartAddressing
In Parameters	:
Out Parameters	: bool
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::IsSmartAddressing()const
{
	return m_bSmartAddressing;
}

/*-----------------------------------------------------------------------------
Function		: GetSocket
In Parameters	:
Out Parameters	: SOCKET
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
SOCKET CSocketComm::GetSocket()const
{
	return (SOCKET)m_hComm;
}

/*-----------------------------------------------------------------------------
Function		: LockList
In Parameters	:
Out Parameters	: void
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::LockList()
{
	if(NULL != m_hMutex)
	{
		WaitForSingleObject(m_hMutex, INFINITE);
	}
}

/*-----------------------------------------------------------------------------
Function		: UnlockList
In Parameters	:
Out Parameters	: void
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::UnlockList()
{
	if(NULL != m_hMutex)
	{
		ReleaseMutex(m_hMutex);
	}
}

/*-----------------------------------------------------------------------------
Function		: AddToList
In Parameters	: Struct SockAddrIn
Out Parameters	: void
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::AddToList(const SockAddrIn& saddr_in)
{
	LockList();
	m_AddrList.insert(m_AddrList.end(), saddr_in);
	UnlockList();
}

/*-----------------------------------------------------------------------------
Function		: RemoveFromList
In Parameters	: Struct SockAddrIn
Out Parameters	: void
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::RemoveFromList(const SockAddrIn& saddr_in)
{
	LockList();
#ifndef VCHREG_NRM
	m_AddrList.remove(saddr_in);
#endif

	UnlockList();
}

/*-----------------------------------------------------------------------------
Function		: SetServerState
In Parameters	: bool
Out Parameters	: void
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::SetServerState(bool bServer)
{
	if(!IsStart())
	{
		m_bServer = bServer;
	}
}

/*-----------------------------------------------------------------------------
Function		: SetSmartAddressing
In Parameters	: bool
Out Parameters	: void
Purpose			: Address is included with message
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::SetSmartAddressing(bool bSmartAddressing)
{
	if(!IsStart())
	{
		m_bSmartAddressing = bSmartAddressing;
	}
}

/*-----------------------------------------------------------------------------
Function		: OnDataReceived
In Parameters	: LPBYTE,  DWORD, CString
Out Parameters	: void
Purpose			: This function is PURE Virtual, you MUST overwrite it. This is
called every time new data is available.
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::OnDataReceived(const LPBYTE lpBuffer, DWORD dwCount, CString &csReply)
{
}

/*-----------------------------------------------------------------------------
Function		: GetPortNumber
In Parameters	: LPCTSTR strServiceName: Service name or port string
Out Parameters	: USHORT
Purpose			: Returns a port number based on service name or port number string
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
USHORT CSocketComm::GetPortNumber(LPCTSTR strServiceName)
{
	LPSERVENT	lpservent;
	USHORT		nPortNumber = 0;

	if(_istdigit(strServiceName[0]))
	{
		nPortNumber = (USHORT)_ttoi(strServiceName);
	}
	else
	{
		CHAR pstrService[HOSTNAME_SIZE];
		WideCharToMultiByte(CP_ACP, 0, strServiceName, -1, pstrService, 
								sizeof(pstrService), NULL, NULL);

		// Convert network byte order to host byte order
		if((lpservent = getservbyname(pstrService, NULL)) != NULL)
		{
			nPortNumber = ntohs(lpservent->s_port);
		}
	}
	return nPortNumber;
}

/*-----------------------------------------------------------------------------
Function		: GetIPAddress
In Parameters	: LPCTSTR strHostName: host name to get IP address
Out Parameters	: ULONG
Purpose			: Returns an IP address.
- It tries to convert the string directly
- If that fails, it tries to resolve it as a hostname
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
ULONG CSocketComm::GetIPAddress(LPCTSTR strHostName)
{
	LPHOSTENT	lphostent;
	ULONG		uAddr = INADDR_NONE;
	TCHAR       strLocal[HOSTNAME_SIZE] ={0 };

	// if no name specified, get local
	if( (NULL==strHostName) || (!wcscmp(strHostName, L"")) )
	{
		GetLocalName(strLocal, sizeof(strLocal));
		strHostName = strLocal;
	}

	CHAR strHost[HOSTNAME_SIZE] ={0 };
	WideCharToMultiByte(CP_ACP, 0, strHostName, -1, strHost, sizeof(strHost), NULL, NULL);

	// Check for an Internet Protocol dotted address string
	uAddr = inet_addr(strHost);

	if((INADDR_NONE == uAddr) && (strcmp(strHost, "255.255.255.255")))
	{
		// It's not an address, then try to resolve it as a hostname
		if(lphostent = gethostbyname(strHost))
		{
			uAddr = *((ULONG *)lphostent->h_addr_list[0]);
		}
	}

	return ntohl(uAddr);
}

/*-----------------------------------------------------------------------------
Function		: GetLocalName
In Parameters	: LPTSTR strName: name of the computer is returned here
: UINT nSize: size max of buffer "strName"
Out Parameters	: bool
Purpose			: Get local computer name. Something like: "mycomputer.myserver.net"
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::GetLocalName(LPTSTR strName, UINT nSize)
{
	if(strName != NULL && nSize > 0)
	{
		CHAR strHost[HOSTNAME_SIZE] ={0 };

		// get host name, if fail, SetLastError is set
		if(SOCKET_ERROR != gethostname(strHost, sizeof(strHost)))
		{
			struct hostent* hp;
			hp = gethostbyname(strHost);
			if(hp != NULL)
			{
				strcpy_s(strHost, sizeof(strHost), hp->h_name);
			}

			// check if user provide enough buffer
			if(strlen(strHost) > nSize)
			{
				SetLastError(ERROR_INSUFFICIENT_BUFFER);
				return false;
			}

			return (0 != MultiByteToWideChar(CP_ACP, 0, strHost, -1, strName, nSize));
		}
	}
	else
	{
		SetLastError(ERROR_INVALID_PARAMETER);
	}
	return false;
}

/*-----------------------------------------------------------------------------
Function		: GetLocalAddress
In Parameters	: LPTSTR strAddress: pointer to hold address string, must be long enough
: UINT nSize: maximum size of this buffer
Out Parameters	: bool
Purpose			: Get TCP address of local computer in dot format ex: "127.0.0.0"
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::GetLocalAddress(LPTSTR strAddress, UINT nSize)
{
	// Get computer local address
	if(strAddress != NULL && nSize > 0)
	{
		char strHost[HOSTNAME_SIZE] ={0 };

		// get host name, if fail, SetLastError is called
		if(SOCKET_ERROR != gethostname(strHost, sizeof(strHost)))
		{
			struct hostent* hp;
			hp = gethostbyname(strHost);
			if(hp != NULL && hp->h_addr_list[0] != NULL)
			{
				// Address is four bytes (32-bit)
				if(hp->h_length < 4)
				{
					return false;
				}

				// Convert address to.format
				strHost[0] = 0;

				// Create Address string
				sprintf_s(strHost, sizeof(strHost), "%u.%u.%u.%u",
					(UINT)(((PBYTE)hp->h_addr_list[0])[0]),
					(UINT)(((PBYTE)hp->h_addr_list[0])[1]),
					(UINT)(((PBYTE)hp->h_addr_list[0])[2]),
					(UINT)(((PBYTE)hp->h_addr_list[0])[3]));

				// check if user provide enough buffer
				if(strlen(strHost) > nSize)
				{
					SetLastError(ERROR_INSUFFICIENT_BUFFER);
					return false;
				}

				return (0 != MultiByteToWideChar(CP_ACP, 0, strHost, -1, strAddress, nSize));
			}
		}
	}
	else
	{
		SetLastError(ERROR_INVALID_PARAMETER);
	}
	return false;
}

/*-----------------------------------------------------------------------------
Function		: WaitForConnection
In Parameters	: SOCKET sock: a socket capable of receiving new connection (TCP: SOCK_STREAM)
Out Parameters	: SOCKET
Purpose			: Wait for a network connection. Only for connection type of socket
This function may fail, in this case it returns "INVALID_SOCKET"
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
SOCKET CSocketComm::WaitForConnection(SOCKET sock)
{
	// Accept an incoming connection - blocking
	// no information about remote address is returned
	return accept(sock, 0, 0);
}

/*-----------------------------------------------------------------------------
Function		: ShutdownConnection
In Parameters	: SOCKET sock: Socket to close
Out Parameters	: SOCKET
Purpose			: Shutdown a connection and close socket. This will force all
transmission/reception to fail.
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::ShutdownConnection(SOCKET sock)
{
	shutdown(sock, SD_BOTH);
	return (0 == closesocket(sock));
}

/*-----------------------------------------------------------------------------
Function		: GetSockName
In Parameters	: SockAddrIn& saddr_in: object to store address
Out Parameters	: bool
Purpose			: retrieves the local name for a socket.
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::GetSockName(SockAddrIn& saddr_in)
{
	if(IsOpen())
	{
		int namelen = (int)saddr_in.Size();
		return (SOCKET_ERROR != getsockname(GetSocket(), (LPSOCKADDR)saddr_in, &namelen));
	}

	return false;
}

/*-----------------------------------------------------------------------------
Function		: GetPeerName
In Parameters	: SockAddrIn& saddr_in: object to store address
Out Parameters	: bool
Purpose			: retrieves the name of the peer to which a socket is connected.
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::GetPeerName(SockAddrIn& saddr_in)
{
	if(IsOpen())
	{
		int namelen = (int)saddr_in.Size();
		return (SOCKET_ERROR != getpeername(GetSocket(), (LPSOCKADDR)saddr_in, &namelen));
	}

	return false;
}

/*-----------------------------------------------------------------------------
Function		: CreateSocket
In Parameters	: LPCTSTR strServiceName: Service name or port number
: int nFamily: address family to use (set to AF_INET)
: int nType: type of socket to create (SOCK_STREAM, SOCK_DGRAM)
: UINT uOptions: other options to use
Out Parameters	: bool
Purpose			: This function creates a new socket for connection (SOCK_STREAM)
or an connectionless socket (SOCK_DGRAM). A connectionless
socket should not call "accept()" since it cannot receive new
connection. This is used as SERVER socket
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::CreateSocket(LPCTSTR strServiceName, int nFamily, int nType,
							   UINT uOptions /* = 0 */)
{
	// Socket is already opened
	if(IsOpen())
	{
		return false;
	}

	//	GetLocalAddress(m_sServerIPAddress.GetBuffer(MAX_PATH), MAX_PATH);
	//	m_sServerIPAddress.ReleaseBuffer();

	// Create a Socket that is bound to a specific service provide
	// nFamily: (AF_INET)
	// nType: (SOCK_STREAM, SOCK_DGRAM)

	SOCKET sock = socket(nFamily, nType, 0);
	if(INVALID_SOCKET != sock)
	{
		if(uOptions & SO_REUSEADDR)
		{
			// Inform Windows Sockets provider that a bind on a socket should not be disallowed
			// because the desired address is already in use by another socket
			BOOL optval = TRUE;
			if(SOCKET_ERROR == setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
											(char *)&optval, sizeof(BOOL)))
			{
				closesocket(sock);
				return false;
			}
		}

		if(nType == SOCK_DGRAM)
		{
			if(uOptions & SO_BROADCAST)
			{
				// Inform Windows Sockets provider that broadcast messages are allowed
				BOOL optval = TRUE;
				if(SOCKET_ERROR == setsockopt(sock, SOL_SOCKET, SO_BROADCAST, 
											(char *)&optval, sizeof(BOOL)))
				{
					closesocket(sock);
					return false;
				}

				// we may proceed
				m_bBroadcast = true;
			}

			// we need mutex only for UDP - broadcast socket
			m_hMutex = CreateMutex(NULL, FALSE, NULL);
			if(NULL == m_hMutex)
			{
				closesocket(sock);
				return false;
			}
		}

		// Associate a local address with the socket
		/*SockAddrIn sockAddr;*/
		//sockAddr.CreateFrom(NULL, strServiceName, nFamily);

		sockaddr_in sockAddr;
		sockAddr.sin_port = htons(m_iSocketPortNo);
		sockAddr.sin_addr.s_addr = inet_addr((CStringA)m_sServerIPAddress);
		sockAddr.sin_family = AF_INET;

		//if(SOCKET_ERROR == bind(sock, (LPSOCKADDR)sockAddr, (int)sockAddr.Size()))
		if(SOCKET_ERROR == bind(sock, (SOCKADDR*)&sockAddr, sizeof(sockAddr)))
		{
			closesocket(sock);
			m_bBroadcast = false;
			if(NULL != m_hMutex)
			{
				CloseHandle(m_hMutex);
			}
			m_hMutex = NULL;
			return false;
		}

		// Listen to the socket, only valid for connection socket
		if(SOCK_STREAM == nType)
		{
			if(SOCKET_ERROR == listen(sock, SOMAXCONN))
			{
				closesocket(sock);
				return false;
			}
		}

		// Success, now we may save this socket
		m_hComm = (HANDLE)sock;
	}

	return (INVALID_SOCKET != sock);
}

/*-----------------------------------------------------------------------------
Function		: ConnectTo
In Parameters	: LPCTSTR strDestination: hostname or address to connect (in.dot format)
: LPCTSTR strServiceName: Service name or port number
: int nFamily: address family to use (set to AF_INET)
: int nType: type of socket to create (SOCK_STREAM, SOCK_DGRAM)
Out Parameters	: int : Error Codes returned: 1 = successfull, 0 = firewall blocking
2 = socket already opened,  3 = invalid socket 
Purpose			: Establish connection with a server service or port
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
int CSocketComm::ConnectTo(LPCTSTR strDestination, LPCTSTR strServiceName, 
							int nFamily, int nType)
{
	// Socket is already opened
	if(IsOpen())
	{
		return ENUM_SOCKET_OPEN;
	}


	// Create a Socket that is bound to a specific service provide
	// nFamily: (AF_INET)
	// nType: (SOCK_STREAM, SOCK_DGRAM)
	SOCKET sock = socket(nFamily, nType, 0);
	if(INVALID_SOCKET != sock)
	{
		// Associate a local address with the socket
		SockAddrIn sockAddr;
		if(false == sockAddr.CreateFrom(m_sClientIPAddress, TEXT("0"), nFamily))
		{
			closesocket(sock);
			return ENUM_SOCKET_ERROR;
		}
		if(SOCKET_ERROR == bind(sock, (LPSOCKADDR)sockAddr, (int)sockAddr.Size()))
		{
			closesocket(sock);
			return ENUM_SOCKET_ERROR;
		}

		// Now get destination address & port
		sockAddr.CreateFrom(strDestination, strServiceName);
		// try to connect - if fail, server not ready
		if(SOCKET_ERROR == connect(sock, (LPSOCKADDR)sockAddr, (int)sockAddr.Size()))
		{
			closesocket(sock);
			return ENUM_FIREWALL_BLOCKING;
		}
		// Success, now we may save this socket
		m_hComm = (HANDLE)sock;
	}

	return (INVALID_SOCKET != sock);
	//return ENUM_SUCC;
}

/*-----------------------------------------------------------------------------
Function		: CloseComm
In Parameters	: void
Out Parameters	: void
Purpose			: Close Socket Communication
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::CloseComm()
{
	if(IsOpen())
	{
		ShutdownConnection((SOCKET)m_hComm);
		m_hComm = INVALID_HANDLE_VALUE;
		m_bBroadcast = false;
	}
}

/*-----------------------------------------------------------------------------
Function		: WatchComm
In Parameters	: void
Out Parameters	: void
Purpose			: Starts Socket Communication Working thread
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::WatchComm()
{
	if(!IsStart())
	{
		if(IsOpen())
		{
			HANDLE hThread;
			UINT uiThreadId = 0;
			hThread = (HANDLE)_beginthreadex(NULL,	// Security attributes
				0,	// stack
				SocketThreadProc,	// Thread proc
				this,	// Thread param
				CREATE_SUSPENDED,	// creation mode
				&uiThreadId);	// Thread ID

			if(NULL != hThread)
			{
				//SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);
				ResumeThread(hThread);
				m_hThread = hThread;
				return true;
			}
		}
	}
	return false;
}

/*-----------------------------------------------------------------------------
Function		: StopComm
In Parameters	: void
Out Parameters	: void
Purpose			: Close Socket and Stop Communication thread
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::StopComm()
{
	// Close Socket
	if(IsOpen())
	{
		CloseComm();
		Sleep(50);
	}

	// Kill Thread
	if(IsStart())
	{
		if(WaitForSingleObject(m_hThread, 5000L)== WAIT_TIMEOUT)
			TerminateThread(m_hThread, 1L);
		CloseHandle(m_hThread);
		m_hThread = NULL;
	}

	// Clear Address list
	if(!m_AddrList.empty())
	{
		m_AddrList.clear();
	}

	// Destroy Synchronization objects
	if(NULL != m_hMutex)
	{
		CloseHandle(m_hMutex);
		m_hMutex = NULL;
	}

}

/*-----------------------------------------------------------------------------
Function		: ReadComm
In Parameters	: LPBYTE lpBuffer: buffer to place new data
: DWORD dwSize: maximum size of buffer
: DWORD dwTimeout: timeout to use in millisecond
Out Parameters	: void
Purpose			: Reads the Socket Communication
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
DWORD CSocketComm::ReadComm(COMM_RAW_DATA_READ &stRawData, DWORD dwTimeout)
{
	_ASSERTE( IsOpen() );

	fd_set	fdRead  = { 0 };
	TIMEVAL	stTime;
	TIMEVAL	*pstTime = NULL;

	if(INFINITE != dwTimeout)
	{
		stTime.tv_sec = dwTimeout/1000;
		stTime.tv_usec = dwTimeout % 1000;
		pstTime = &stTime;
	}

	SOCKET s = (SOCKET) m_hComm;
	// Set Descriptor
	if(!FD_ISSET(s, &fdRead))
	{
		FD_SET(s, &fdRead);
	}

	// Select function set read timeout
	DWORD dwBytesRead = 0L;
	int res = select((int)s + 1, &fdRead, NULL, NULL, pstTime);
	if(res > 0)
	{
		if (IsBroadcast() || IsSmartAddressing())
		{
			//SockAddrIn sockAddr;
			//int nLen = (int)sockAddr.Size();
			//int nOffset = IsSmartAddressing() ? nLen : 0; // use offset for Smart addressing
			//if ( dwSize < (DWORD) nOffset)	// error - buffer to small
			//{
			//	SetLastError( ERROR_INVALID_USER_BUFFER );
			//	return (DWORD)-1L;
			//}
			//LPSTR lpszData = (LPSTR)(lpBuffer + nOffset);
			//res = recvfrom( s, lpszData, dwSize-nOffset, 0, (LPSOCKADDR)sockAddr, &nLen);

			//// clear 'sin_zero', we will ignore them with 'SockAddrIn' anyway!
			//memset(&sockAddr.sin_zero, 0, sizeof(sockAddr.sin_zero));

			//// Lock the list...
			//LockList();
			//m_AddrList.remove( sockAddr );
			//
			//if ( res >= 0)
			//{
			//	// insert unique address
			//	m_AddrList.insert(m_AddrList.end(), sockAddr);

			//	if (IsSmartAddressing())
			//	{
			//		memcpy(lpBuffer, &sockAddr, sockAddr.Size());
			//		res += (int)sockAddr.Size();
			//	}
			//}

			//UnlockList(); // unlock this object addresses-list
		}
		else
		{
			res = recv(s, (LPSTR)(&stRawData.byRawData[stRawData.dwCollectedLen]), stRawData.dwRemainingLen, 0);
			stRawData.dwCollectedLen += res;
			stRawData.dwRemainingLen -= res;
			//res = recv( s, (LPSTR)lpBuffer, dwSize, 0);
		}

		dwBytesRead = (DWORD)((res > 0)?(res) : (-1L));
	}
	else
	{
		if(res == 0)
		{
			FD_ZERO(&fdRead);
			FD_SET(s, &fdRead);
		}
	}

	return dwBytesRead;
}

/*-----------------------------------------------------------------------------
Function		: WriteComm
In Parameters	: const LPBYTE lpBuffer: data to write
: DWORD dwCount: maximum characters to write
: DWORD dwTimeout: timeout to use in millisecond
: bool bBlockingCall: Send a true to make this write a
blocking call on the socket
Out Parameters	: DWORD
Purpose			: Writes data to the Socket Communication
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
DWORD CSocketComm::WriteComm(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout,
							 bool bBlockingCall)
{
	CString csReply;
	return WriteComm(lpBuffer, dwCount, dwTimeout, bBlockingCall, csReply);
}

/*-----------------------------------------------------------------------------
Function		: WriteComm
In Parameters	: const LPBYTE lpBuffer: data to write
: DWORD dwCount: maximum characters to write
: DWORD dwTimeout: timeout to use in millisecond
: bool bBlockingCall: Send a true to make this write a
blocking call on the socket
CString csReply: Reply received from client
Out Parameters	: DWORD
Purpose			: Writes data to the Socket Communication
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
DWORD CSocketComm::WriteComm(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout,
							 bool bBlockingCall, CString &csReply)
{
	if(dwCount > TRANSFER_BUFFER_SIZE)
	{
		csReply.Format(L"SocketComm: Insufficient Buffer to Transfer: Available: %d, Required: %d", TRANSFER_BUFFER_SIZE, dwCount);
		return 0;
	}

	COMM_RAW_DATA_WRITE stRawData;
	stRawData.dwSizeOfData = dwCount;
	memcpy_s(&stRawData.byRawData, SIZE_OF_COMM_RAW_DATA_WRITE, lpBuffer, dwCount);
	return RawWriteComm((const LPBYTE)&stRawData, SIZE_OF_COMM_RAW_DATA_WRITE, dwTimeout, bBlockingCall, csReply);
}

DWORD CSocketComm::RawWriteComm(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout, bool bBlockingCall, CString &csReply)
{
	if(!IsConnected())
		return 0;

	_ASSERTE( IsOpen() );
	_ASSERTE( NULL != lpBuffer );

	// Accept 0 bytes message
	if (!IsOpen() || NULL == lpBuffer)
		return 0L;

	fd_set	fdWrite  = { 0 };
	TIMEVAL	stTime;
	TIMEVAL	*pstTime = NULL;

	if ( INFINITE != dwTimeout ) {
		stTime.tv_sec = dwTimeout/1000;
		stTime.tv_usec = dwTimeout % 1000;
		pstTime = &stTime;
	}

	SOCKET s = (SOCKET) m_hComm;
	// Set Descriptor
	if ( !FD_ISSET( s, &fdWrite ) )
		FD_SET( s, &fdWrite );

	// Select function set write timeout
	DWORD dwBytesWritten = 0L;
	int res = select((int)s+1, NULL, &fdWrite, NULL, pstTime );
	if ( res > 0)
	{
		if(!IsBroadcast() && !IsSmartAddressing())
		{
			if(bBlockingCall)
			{
				ResetEvent(m_hDataProcessed);
			}
			res = send( s, (LPCSTR)lpBuffer, dwCount, 0);
		}

		dwBytesWritten = (DWORD)((res >= 0)?(res) : (-1));
		if(bBlockingCall)
		{
			// have we sent some data, for which we need to wait until 
			// the receiver has processed the data?
			// check if full data sent as per request is sent, and that 
			// this is not a completion request, 
			// so wait for the other side to send a conformation.
			TCHAR sConfirmData[8]= {0};
			memcpy_s(&sConfirmData, 8*sizeof(TCHAR), lpBuffer, 7*sizeof(TCHAR));
			if(_tcscmp(sConfirmData, CONFORMATION_DATA) != 0)
			{
				while(true)
				{
					DWORD dwStatus = WaitForSingleObject(m_hDataProcessed, INFINITE);
					if(dwStatus == WAIT_TIMEOUT)
					{
						csReply = L"";
						break;
					}
					else
					{
						csReply = m_csReply;
						break;
					}
				}
			}
		}
	}

	return dwBytesWritten;
}

/*-----------------------------------------------------------------------------
Function		: Run
In Parameters	: None
Out Parameters	: None
Purpose			: This function runs the main thread loop, this implementation
can be overloaded.This function calls
CSocketComm::OnDataReceived()(Virtual Function)
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::Run()
{
	stMessageProxy stMsgProxy;
	DWORD	dwBytes  = 0L;
	DWORD	dwTimeout = 100; //DEFAULT_TIMEOUT;
	//LPBYTE  lpData  = (LPBYTE)&stMsgProxy;
	//DWORD	dwSize  = sizeof(stMsgProxy);
	//if (!IsSmartAddressing())
	//{
	//	lpData = stMsgProxy.data;
	//	dwSize = sizeof(stMsgProxy.data);
	//}

	// Should we run as server mode
	if (IsServer())
	{
		if (!IsBroadcast())
		{
			SOCKET sock = (SOCKET) m_hComm;
			sock = WaitForConnection( sock );

			// Get new connection socket
			if (sock != INVALID_SOCKET)
			{
				ShutdownConnection( (SOCKET) m_hComm);
				m_hComm = (HANDLE) sock;
				OnEvent( EVT_CONSUCCESS ); // connect
			}
			else
			{
				// Do not send event if we are closing
				if (IsOpen())
					OnEvent( EVT_CONFAILURE ); // wait fail
				return;
			}
		}
	}
	else
		GetPeerName( stMsgProxy.address );

	COMM_RAW_DATA_READ stRawData = {0};
	memset(&stRawData, 0, SIZE_OF_COMM_RAW_DATA_READ);
	stRawData.dwRemainingLen = SIZE_OF_COMM_RAW_DATA_WRITE;

	while(IsOpen())
	{
		// Blocking mode: Wait for event
		dwBytes = ReadComm(stRawData, dwTimeout);

		// Error? - need to signal error
		if (dwBytes == (DWORD)-1L)
		{
			// Do not send event if we are closing
			if (IsOpen())
				OnEvent( EVT_CONDROP ); // lost connection

			// special case for UDP, alert about the event but do not stop
			if (IsBroadcast())
				continue;
			else
				break;
		}

		if((dwBytes > 0L) && (stRawData.dwCollectedLen == SIZE_OF_COMM_RAW_DATA_WRITE))	//Full buffer received?
		{
			TCHAR sConfirmData[8] = {0};
			COMM_RAW_DATA_WRITE *pRawDataWrite = (COMM_RAW_DATA_WRITE *)&stRawData.byRawData;

			//restore actual sent data and its size!
			LPBYTE  lpData = pRawDataWrite->byRawData;
			dwBytes = pRawDataWrite->dwSizeOfData;

			memcpy_s(&sConfirmData, 8*sizeof(TCHAR), lpData, 7*sizeof(TCHAR));

			if(_tcscmp(sConfirmData, CONFORMATION_DATA) == 0)
			{
				m_csReply = (LPTSTR)lpData;
				m_csReply = m_csReply.Mid(7);
				SetEvent(m_hDataProcessed);
			}
			else
			{
				CString csReply;
				OnDataReceived(lpData, dwBytes, csReply);

				BYTE sConfirm[MAX_PATH]={0};
				
				if(csReply.GetLength() == 0)
				{
					memcpy_s((void*)sConfirm,MAX_PATH,(void*)CONFORMATION_DATA, (_tcslen(CONFORMATION_DATA) + 1)*sizeof(TCHAR));
				}
				else
				{
					// the data has been processed! now notify the 
					// server to send another packet!
					csReply = CONFORMATION_DATA + csReply;
					memcpy((void*)sConfirm, (void*)(LPCTSTR)csReply, (csReply.GetLength() + 1)*sizeof(TCHAR));
				}
				WriteComm(sConfirm, MAX_PATH, INFINITE);
			}
			//get ready for another set of data!
			memset(&stRawData, 0, SIZE_OF_COMM_RAW_DATA_READ);
			stRawData.dwRemainingLen = SIZE_OF_COMM_RAW_DATA_WRITE;
		}
		Sleep(2);
	}
}

/*-----------------------------------------------------------------------------
Function		: SocketThreadProc
In Parameters	: LPVOID pParam : Thread parameter - a CSocketComm pointer
Out Parameters	: UINT
Purpose			: Socket Thread function. This function is the main thread for socket
communication - Asynchronous mode.
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
UINT WINAPI CSocketComm::SocketThreadProc(LPVOID pParam)
{
	CSocketComm* pThis = reinterpret_cast<CSocketComm*>(pParam);
	_ASSERTE(pThis != NULL);

	pThis->Run();

	return 1L;
}

/*-----------------------------------------------------------------------------
Function		: CreateSockServer
In Parameters	: int iPortNumber:
Out Parameters	: bool
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::CreateSockServer(int iPortNumber,CString csIPAddress)
{
	StopComm();					// just incase it is already running!
	SetServerState(true);		// run as server
	SetSmartAddressing(false);
	m_iSocketPortNo = iPortNumber;
	m_sServerIPAddress = csIPAddress; //setting the IP address of the server.:Avinash B

	bool bSuccess = false;
	TCHAR strPortNo[16];

	_itow_s(GetSocketPortNo(), strPortNo, 10);
	bSuccess = CreateSocket(strPortNo, AF_INET, SOCK_STREAM, 0); // TCP

	if(bSuccess && WatchComm())
	{
		CString strServer, strAddr;
		GetLocalName(strServer.GetBuffer(256), 256);
		strServer.ReleaseBuffer();
		GetLocalAddress(strAddr.GetBuffer(256), 256);
		strAddr.ReleaseBuffer();
		CString strMsg  = _T("Server: ") + strServer;
		strMsg += _T(", @Address: ") + strAddr;
		strMsg += _T(" is running on port ") + CString(strPortNo) + CString("\r\n");
		_AddLogEntry(m_sClientIPAddress, m_sServerIPAddress, strMsg);
	}
	return bSuccess;
}

/*-----------------------------------------------------------------------------
Function		: CheckClientVersion
In Parameters	: CString strServer:
Out Parameters	: int
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
int CSocketComm::CheckClientVersion(CString strServer)
{
	SetServerState(false);		// run as client
	SetSmartAddressing(false);

	int iReturnCode = 1;
	TCHAR strPortNo[16];
	m_iSocketPortNo = PORT_OPTION_TYPE;
	m_sServerIPAddress = strServer;
	_itow_s(m_iSocketPortNo, strPortNo, 10);
	iReturnCode = ConnectTo(strServer, strPortNo, AF_INET, SOCK_STREAM); // TCP

	//if connection is not successful then returning error code.
	if(iReturnCode != ENUM_SUCCESS)
	{
		return iReturnCode;
	}

	if(iReturnCode ==  ENUM_SUCCESS && WatchComm())
	{
		CString strMsg;
		strMsg  = _T("Connection established with server: ") + strServer;
		strMsg += _T(" on port ") + CString(strPortNo) + CString("\r\n");
		_AddLogEntry(m_sClientIPAddress, m_sServerIPAddress, strMsg);
		GetPeerName(m_SockPeer);
		m_bConnected = true;

		OPTION_SETTINGS stOptionSettings;
		stOptionSettings.enum_Option_Settings = ENUM_OPT_GET_CLIENT_VERSION;

		CString csReplay;
		if(IsConnected())
			WriteComm((const LPBYTE)&stOptionSettings, sizeof(stOptionSettings), INFINITE, true, csReplay);

		DisconnectSock();
		CString csServerVersionNo = GetServerVersionNo();

		if(csServerVersionNo == csReplay)
		{
			return true;
		}
		else if(csReplay == BLANKSTRING)
		{
			return ENUM_FIREWALL_BLOCKING;
		}
		else
		{
			return ENUM_VERSION_DIFF;
		}
	}
	return false;
}

/*-----------------------------------------------------------------------------
Function		: GetServerVersionNo
In Parameters	: None
Out Parameters	: CString
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
CString CSocketComm::GetServerVersionNo()
{
	CRegistry objReg;
	CString csVersion;
	objReg.Get(PRODUCT_REG, _T("ServerVersionNo"), csVersion, HKEY_LOCAL_MACHINE);

	return csVersion;
}

/*-----------------------------------------------------------------------------
Function		: ConnectSockServer
In Parameters	: CString strServer :
: int iPortNumber :
: bool bVersionCheckRequired :
Out Parameters	: int
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
int CSocketComm::ConnectSockServer(CString strServer, int iPortNumber, CString csClientIP, 
								   bool bVersionCheckRequired)
{
	int iReturnCode = 1;

	m_csMachineID = strServer;
	if(strServer.Find(_T("[")) != -1)
	{
		strServer = strServer.Left(strServer.Find(_T("[")));
	}

	m_sClientIPAddress = csClientIP;
	if(m_sClientIPAddress.IsEmpty())
	{
		GetLocalAddress(m_sClientIPAddress.GetBuffer(MAX_PATH), MAX_PATH);
		m_sClientIPAddress.ReleaseBuffer();
	}

	/*This section checks the version for scan and option types.But the version check is not for all options.
	It is only for active protection enable/disable.: Avinash B
	*/
	if(bVersionCheckRequired && (iPortNumber == PORT_SCAN_OPTION || 
									iPortNumber == PORT_OPTION_TYPE))
	{
		iReturnCode = CheckClientVersion(strServer);

		//if version check is required and versions are not same.
		if(iReturnCode != ENUM_SUCCESS)
		{
			return iReturnCode;
		}
	}

	StopComm();					// just incase it is already running!
	SetServerState(false);		// run as client
	SetSmartAddressing(false);
	m_iSocketPortNo = iPortNumber;
	m_sServerIPAddress = strServer;

	TCHAR strPortNo[16];
	_itow_s(m_iSocketPortNo, strPortNo, 10);
	iReturnCode = ConnectTo(strServer, strPortNo, AF_INET, SOCK_STREAM); // TCP
	if(iReturnCode == ENUM_SUCCESS && WatchComm())
	{
		CString strMsg;
		strMsg =  _T("Connection established with server: ") + strServer;
		strMsg += _T(" on port ") + CString(strPortNo) + CString(_T("\r\n"));
		_AddLogEntry(m_sClientIPAddress, m_sServerIPAddress, strMsg);

		GetPeerName(m_SockPeer);
		m_bConnected = true;
		return ENUM_SUCCESS;
	}
	return iReturnCode;
}

/*-----------------------------------------------------------------------------
Function		: DisconnectSock
In Parameters	: None
Out Parameters	: void
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::DisconnectSock()
{
	m_bConnected = false;
	StopComm();
}

/*-----------------------------------------------------------------------------
Function		: SendSockMsg
In Parameters	: CString strText :
Out Parameters	: void
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::SendSockMsg(CString strText)
{
	BYTE byBuffer[256] ={0 };
	int nLen = strText.GetLength();
	if(nLen > 0)
	{
		strText += _T("\r\n");
		nLen = strText.GetLength() + 1;
		USES_CONVERSION;
		strcpy_s((LPSTR)byBuffer, sizeof(byBuffer), T2CA(strText));
		if(IsConnected())
		{
			WriteComm(byBuffer, nLen, INFINITE);
		}
	}
}

/*-----------------------------------------------------------------------------
Function		: GetSocketPortNo
In Parameters	: void
Out Parameters	: int
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
int CSocketComm::GetSocketPortNo()
{
	return m_iSocketPortNo;
}

/*-----------------------------------------------------------------------------
Function		: OnEvent
In Parameters	: UINT uEvent: can be one of the event value EVT_(events)
Out Parameters	: void
Purpose			: This function reports events & errors
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
void CSocketComm::OnEvent(UINT uEvent)
{
	//Set the Event incase the connection was lost!
	SetEvent(m_hDataProcessed);

	switch(uEvent)
	{
	case EVT_CONSUCCESS:
		{
			m_bConnected = true;
			_AddLogEntry(m_sClientIPAddress, m_sServerIPAddress, _T("Connection Established!"));
		}
		break;
	case EVT_CONFAILURE:
		{
			m_bConnected = false;
			_AddLogEntry(m_sClientIPAddress, m_sServerIPAddress, _T("Connection Failed"));
		}
		break;
	case EVT_CONDROP:
		{
			m_bConnected = false;
			_AddLogEntry(m_sClientIPAddress, m_sServerIPAddress, _T("Connection Abandonned"));
		}
		break;
	case EVT_ZEROLENGTH:
		{
			_AddLogEntry(m_sClientIPAddress, m_sServerIPAddress, _T("Zero Length Message"));
		}
		break;
	default:
		{
			_AddLogEntry(m_sClientIPAddress, m_sServerIPAddress, _T("Unknown Socket event"));
		}
		break;
	}
}

/*-----------------------------------------------------------------------------
Function		: IsConnected
In Parameters	: None
Out Parameters	: bool
Purpose			:
Author			: Darshan Singh Virdi
-----------------------------------------------------------------------------*/
bool CSocketComm::IsConnected()
{
	return m_bConnected;
}