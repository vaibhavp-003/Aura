///////////////////////////////////////////////////////////////////////////////
//  File:       SocketComm.cpp
//  Version:    1.4
//
//  Author:     Ernest Laurentin
//  E-mail:     elaurentin@netzero.net
//
//  Implementation of the CSocketComm and associated classes.
//
//  This code may be used in compiled form in any way you desire. This
//  file may be redistributed unmodified by any means PROVIDING it is
//  not sold for profit without the authors written consent, and
//  providing that this notice and the authors name and all copyright
//  notices remains intact.
//
//  This file is provided "as is" with no expressed or implied warranty.
//  The author accepts no liability for any damage/loss of business that
//  this c++ class may cause.
//
//  Version history
//
//  1.0 - Initial release.
//  1.1 - Add support for Smart Addressing mode
//  1.2 - Fix various issues with address list (in UDP mode)
//  1.3 - Fix bug when sending message to broadcast address
//  1.4 - Add UDP multicast support
///////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include <stdio.h>
#include <tchar.h>
#include <process.h>
#include <crtdbg.h>
#include <shlwapi.h>
#include "SocketComm.h"
#include "Logger.h"
#include "MaxExceptionFilter.h"
#include "MaxConstant.h"
///////////////////////////////////////////////////////////////////////////////
// SockAddrIn Struct

///////////////////////////////////////////////////////////////////////////////
// Copy
SockAddrIn& SockAddrIn::Copy(const SockAddrIn& sin)
{
    memcpy(this, &sin, Size());
    return *this;
}

///////////////////////////////////////////////////////////////////////////////
// IsEqual
bool SockAddrIn::IsEqual(const SockAddrIn& sin) const
{
    // Is it Equal? - ignore 'sin_zero'
    return (memcmp(this, &sin, Size()-sizeof(sin_zero)) == 0);
}

///////////////////////////////////////////////////////////////////////////////
// IsGreater
bool SockAddrIn::IsGreater(const SockAddrIn& sin) const
{
    // Is it Greater? - ignore 'sin_zero'
    return (memcmp(this, &sin, Size()-sizeof(sin_zero)) > 0);
}

///////////////////////////////////////////////////////////////////////////////
// IsLower
bool SockAddrIn::IsLower(const SockAddrIn& sin) const
{
    // Is it Lower? - ignore 'sin_zero'
    return (memcmp(this, &sin, Size()-sizeof(sin_zero)) < 0);
}

///////////////////////////////////////////////////////////////////////////////
// CreateFrom
bool SockAddrIn::CreateFrom(LPCTSTR sAddr, LPCTSTR sService, int nFamily /*=AF_INET*/)
{
    Clear();
    sin_addr.s_addr = htonl( CSocketComm::GetIPAddress(sAddr) );
    sin_port = htons( CSocketComm::GetPortNumber( sService ) );
    sin_family = nFamily;
    return !IsNull();
}


///////////////////////////////////////////////////////////////////////////////
// Construct & Destruct
CSocketComm::CSocketComm() :
    m_bServer(false), m_bSmartAddressing(false), m_bBroadcast(false),
    m_hComm(INVALID_HANDLE_VALUE), m_hThread(NULL), m_hMutex(NULL)
{
	m_pSocketCallBack = NULL;
	m_pRouterComm = NULL;
	m_pParentSocketComm = NULL;
	m_bRouter = false;
	InitSessionData();
		
}

CSocketComm::~CSocketComm()
{
	StopComm();
}


///////////////////////////////////////////////////////////////////////////////
// Members
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// IsOpen
bool CSocketComm::IsOpen() const
{
    return ( INVALID_HANDLE_VALUE != m_hComm );
}


///////////////////////////////////////////////////////////////////////////////
// IsStart
bool CSocketComm::IsStart() const
{
    return ( NULL != m_hThread );
}


void CSocketComm::SetPacketSize(DWORD dwPacketSize)
{
	m_dwPacketSize = dwPacketSize;
}
///////////////////////////////////////////////////////////////////////////////
// IsServer
bool CSocketComm::IsServer() const
{
    return m_bServer;
}


///////////////////////////////////////////////////////////////////////////////
// IsBroadcast
bool CSocketComm::IsBroadcast() const
{
    return m_bBroadcast;
}


///////////////////////////////////////////////////////////////////////////////
// IsSmartAddressing
bool CSocketComm::IsSmartAddressing() const
{
    return m_bSmartAddressing;
}


///////////////////////////////////////////////////////////////////////////////
// GetSocket
SOCKET CSocketComm::GetSocket() const
{
    return (SOCKET) m_hComm;
}


///////////////////////////////////////////////////////////////////////////////
// LockList
void CSocketComm::LockList()
{
    if (NULL != m_hMutex)
        WaitForSingleObject(m_hMutex, INFINITE);
}


///////////////////////////////////////////////////////////////////////////////
// UnlockList
void CSocketComm::UnlockList()
{
    if (NULL != m_hMutex)
        ReleaseMutex(m_hMutex);
}


///////////////////////////////////////////////////////////////////////////////
// AddToList
void CSocketComm::AddToList(const SockAddrIn& saddr_in)
{
    LockList();
    m_AddrList.insert( m_AddrList.end(), saddr_in );
    UnlockList();
}

///////////////////////////////////////////////////////////////////////////////
// RemoveFromList
void CSocketComm::RemoveFromList(const SockAddrIn& saddr_in)
{
    LockList();
    m_AddrList.remove( saddr_in );
    UnlockList();
}

///////////////////////////////////////////////////////////////////////////////
// SetServerState
void CSocketComm::SetServerState(bool bServer, ISocketCallBack *pSocketCallBack)
{
    if (!IsStart())
        m_bServer = bServer;
	if(pSocketCallBack)
	{
		m_pSocketCallBack = pSocketCallBack;
	}
}


///////////////////////////////////////////////////////////////////////////////
// SetSmartAddressing : Address is included with message
void CSocketComm::SetSmartAddressing(bool bSmartAddressing)
{
    if (!IsStart())
        m_bSmartAddressing = bSmartAddressing;
}


///////////////////////////////////////////////////////////////////////////////
// GetPortNumber
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              Returns a port number based on service name or port number string
// PARAMETERS:
//  LPCTSTR strServiceName: Service name or port string
///////////////////////////////////////////////////////////////////////////////
USHORT CSocketComm::GetPortNumber( LPCTSTR strServiceName )
{
    LPSERVENT   lpservent;
    USHORT      nPortNumber = 0;

    if ( _istdigit( strServiceName[0] ) ) {
        nPortNumber = (USHORT) _ttoi( strServiceName );
    }
    else {
#ifdef _UNICODE
        char pstrService[HOSTNAME_SIZE];
        WideCharToMultiByte(CP_ACP, 0, strServiceName, -1, pstrService, sizeof(pstrService), NULL, NULL );
#else
        LPCTSTR pstrService = strServiceName;
#endif
        // Convert network byte order to host byte order
        if ( (lpservent = getservbyname( pstrService, NULL )) != NULL )
            nPortNumber = ntohs( lpservent->s_port );
    }

    return nPortNumber;
}


///////////////////////////////////////////////////////////////////////////////
// GetIPAddress
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//      Returns an IP address.
//          - It tries to convert the string directly
//          - If that fails, it tries to resolve it as a hostname
// PARAMETERS:
//  LPCTSTR strHostName: host name to get IP address
///////////////////////////////////////////////////////////////////////////////
ULONG CSocketComm::GetIPAddress( LPCTSTR strHostName )
{
    LPHOSTENT   lphostent;
    ULONG       uAddr = INADDR_NONE;
    TCHAR       strLocal[HOSTNAME_SIZE] = { 0 };

    // if no name specified, get local
    if ( NULL == strHostName )
    {
        GetLocalName(strLocal, sizeof(strLocal));
        strHostName = strLocal;
    }

#ifdef _UNICODE
    char strHost[HOSTNAME_SIZE] = { 0 };
    WideCharToMultiByte(CP_ACP, 0, strHostName, -1, strHost, sizeof(strHost), NULL, NULL );
#else
    LPCTSTR strHost = strHostName;
#endif

    // Check for an Internet Protocol dotted address string
    uAddr = inet_addr( strHost );

    if ( (INADDR_NONE == uAddr) && (strcmp( strHost, "255.255.255.255" )) )
    {
        // It's not an address, then try to resolve it as a hostname
        if ( lphostent = gethostbyname( strHost ) )
            uAddr = *((ULONG *) lphostent->h_addr_list[0]);
		//TODO:Darshit
		//uAddr = ResolveLocalIP(strHost);
    }
    
    return ntohl( uAddr );
}


///////////////////////////////////////////////////////////////////////////////
// GetLocalName
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              Get local computer name.  Something like: "mycomputer.myserver.net"
// PARAMETERS:
//  LPTSTR strName: name of the computer is returned here
//  UINT nSize: size max of buffer "strName"
///////////////////////////////////////////////////////////////////////////////
bool CSocketComm::GetLocalName(LPTSTR strName, UINT nSize)
{
    if (strName != NULL && nSize > 0)
    {
        char strHost[HOSTNAME_SIZE] = { 0 };

        // get host name, if fail, SetLastError is set
        if (SOCKET_ERROR != gethostname(strHost, sizeof(strHost)))
        {
            struct hostent* hp;
            hp = gethostbyname(strHost);
            if (hp != NULL) {
                strncpy_s(strHost, hp->h_name, HOSTNAME_SIZE);
            }

            // check if user provide enough buffer
            if (strlen(strHost) > nSize)
            {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return false;
            }

            // Unicode conversion
#ifdef _UNICODE
            return (0 != MultiByteToWideChar(CP_ACP, 0, strHost, -1, strName, nSize ));
#else
            _tcscpy(strName, strHost);
            return true;
#endif
        }
    }
    else
        SetLastError(ERROR_INVALID_PARAMETER);
    return false;
}


///////////////////////////////////////////////////////////////////////////////
// GetLocalAddress
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              Get TCP address of local computer in dot format ex: "127.0.0.0"
// PARAMETERS:
//  LPTSTR strAddress: pointer to hold address string, must be long enough
//  UINT nSize: maximum size of this buffer
///////////////////////////////////////////////////////////////////////////////
bool CSocketComm::GetLocalAddress(LPTSTR strAddress, UINT nSize)
{
    // Get computer local address
    if (strAddress != NULL && nSize > 0)
	{
		if(_tcslen(m_szLocalHostIPAddr) > 0)
		{	
			_tcscpy_s(strAddress,nSize,m_szLocalHostIPAddr);
		}
		else
		{
			char strHost[HOSTNAME_SIZE] = { 0 };

			// get host name, if fail, SetLastError is called
			if (SOCKET_ERROR != gethostname(strHost, sizeof(strHost)))
			{
				struct hostent* hp;
				hp = gethostbyname(strHost);
				if (hp != NULL && hp->h_addr_list[0] != NULL)
				{
					// IPv4: Address is four bytes (32-bit)
					if ( hp->h_length < 4)
						return false;

					// Convert address to . format
					strHost[0] = 0;

					// IPv4: Create Address string
					sprintf_s(strHost, "%u.%u.%u.%u",
						(UINT)(((PBYTE) hp->h_addr_list[0])[0]),
						(UINT)(((PBYTE) hp->h_addr_list[0])[1]),
						(UINT)(((PBYTE) hp->h_addr_list[0])[2]),
						(UINT)(((PBYTE) hp->h_addr_list[0])[3]));

					// check if user provide enough buffer
					if (strlen(strHost) > nSize)
					{
						SetLastError(ERROR_INSUFFICIENT_BUFFER);
						return false;
					}

					// Unicode conversion
					return (0 != MultiByteToWideChar(CP_ACP, 0, strHost, -1, strAddress,nSize ));
				}
			}

		}


		return true;
	}
	return false;
}


///////////////////////////////////////////////////////////////////////////////
// WaitForConnection
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              Wait for a network connection.  Only for connection type of socket
//              This function may fail, in this case it returns "INVALID_SOCKET"
// PARAMETERS:
//  SOCKET sock: a socket capable of receiving new connection (TCP: SOCK_STREAM)
///////////////////////////////////////////////////////////////////////////////
SOCKET CSocketComm::WaitForConnection(SOCKET sock)
{
    // Accept an incoming connection - blocking
    // no information about remote address is returned
    return accept(sock, 0, 0);
}


///////////////////////////////////////////////////////////////////////////////
// ShutdownConnection
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              Shutdown a connection and close socket.  This will force all
//              transmission/reception to fail.
// PARAMETERS:
//  SOCKET sock: Socket to close
///////////////////////////////////////////////////////////////////////////////
bool CSocketComm::ShutdownConnection(SOCKET sock)
{
    shutdown(sock, SD_BOTH);
    return ( 0 == closesocket( sock ));
}


///////////////////////////////////////////////////////////////////////////////
// GetSockName
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              retrieves the local name for a socket
// PARAMETERS:
//  SockAddrIn& saddr_in: object to store address
///////////////////////////////////////////////////////////////////////////////
bool CSocketComm::GetSockName(SockAddrIn& saddr_in)
{
    if (IsOpen())
    {
        int namelen = (int)saddr_in.Size();
        return (SOCKET_ERROR != getsockname(GetSocket(), saddr_in, &namelen));
    }

    return false;
}


///////////////////////////////////////////////////////////////////////////////
// GetPeerName
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              retrieves the name of the peer to which a socket is connected
// PARAMETERS:
//  SockAddrIn& saddr_in: object to store address
///////////////////////////////////////////////////////////////////////////////
bool CSocketComm::GetPeerName(SockAddrIn& saddr_in)
{
    if (IsOpen())
    {
        int namelen = (int)saddr_in.Size();
        return (SOCKET_ERROR != getpeername(GetSocket(), saddr_in, &namelen));  
    }

    return false;
}

///////////////////////////////////////////////////////////////////////////////
// AddMembership
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              Add membership to a multicast address
// PARAMETERS:
//  LPCTSTR strAddress: ip address for membership
///////////////////////////////////////////////////////////////////////////////
bool CSocketComm::AddMembership(LPCTSTR strAddress)
{
    if ( IsOpen() )
    {
        int nType = 0;
        int nOptLen = sizeof(int);
        SOCKET sock = (SOCKET) m_hComm;
        if ( SOCKET_ERROR != getsockopt(sock, SOL_SOCKET, SO_TYPE, (char*)&nType, &nOptLen))
        {
            if ( nType == SOCK_DGRAM )
            {
                int nTTL = 5;
                if ( SOCKET_ERROR != setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&nTTL, sizeof(nTTL)))
                {
                    ip_mreq mreq;
                    mreq.imr_multiaddr.s_addr = htonl( CSocketComm::GetIPAddress( strAddress ) );
                    mreq.imr_interface.s_addr = htonl( INADDR_ANY );
                    return ( SOCKET_ERROR != setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char*)&mreq, sizeof(mreq)));
                }
            }
        }
    }
    return false;
}


///////////////////////////////////////////////////////////////////////////////
// DropMembership
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              Remove membership from a multicast address
// PARAMETERS:
//  LPCTSTR strAddress: ip address for membership
///////////////////////////////////////////////////////////////////////////////
bool CSocketComm::DropMembership(LPCTSTR strAddress)
{
    if ( IsOpen() )
    {
        int nType = 0;
        int nOptLen = sizeof(int);
        SOCKET sock = (SOCKET) m_hComm;
        if ( SOCKET_ERROR != getsockopt(sock, SOL_SOCKET, SO_TYPE, (char*)&nType, &nOptLen))
        {
            if ( nType == SOCK_DGRAM )
            {
                ip_mreq mreq;
                mreq.imr_multiaddr.s_addr = htonl( CSocketComm::GetIPAddress( strAddress ) );
                mreq.imr_interface.s_addr = htonl( INADDR_ANY );
                return ( SOCKET_ERROR != setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (const char*)&mreq, sizeof(mreq)));
            }
        }
    }
    return false;
}


///////////////////////////////////////////////////////////////////////////////
// CreateSocketEx
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              This function creates a new socket for connection (SOCK_STREAM)
//              or an connectionless socket (SOCK_DGRAM).  A connectionless
//              socket should not call "accept()" since it cannot receive new
//              connection.  This is used as SERVER socket
// PARAMETERS:
//  LPCTSTR strHost: Hostname or adapter IP address
//  LPCTSTR strServiceName: Service name or port number
//  int nFamily: address family to use (set to AF_INET)
//  int nType: type of socket to create (SOCK_STREAM, SOCK_DGRAM)
//  UINT uOptions: other options to use
///////////////////////////////////////////////////////////////////////////////
bool CSocketComm::CreateSocketEx(LPCTSTR strHost, LPCTSTR strServiceName, int nFamily, int nType, UINT uOptions /* = 0 */)
{
    // Socket is already opened
	LPTSTR szLocalHostAdd = NULL;
	if((NULL != strHost) && (_tcslen(strHost) > 0))
	{
		_tcscpy_s(m_szLocalHostIPAddr,strHost);
		_tcscpy_s(m_szLogLocalIPAddr,strHost);
		szLocalHostAdd = m_szLocalHostIPAddr;
	}

    if ( IsOpen() )
	{
        return false;
	}

    // Create a Socket that is bound to a specific service provide
    // nFamily: (AF_INET)
    // nType: (SOCK_STREAM, SOCK_DGRAM)
    SOCKET sock = socket(nFamily, nType, IPPROTO_TCP);
    if (INVALID_SOCKET != sock)
    {
        if (uOptions & SO_REUSEADDR)
        {
            // Inform Windows Sockets provider that a bind on a socket should not be disallowed
            // because the desired address is already in use by another socket
            BOOL optval = TRUE;
            if ( SOCKET_ERROR == setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, (char *) &optval, sizeof( BOOL ) ) )
            {
                closesocket( sock );
                return false;
            }
        }

        if (nType == SOCK_DGRAM)
        {
            if (uOptions & SO_BROADCAST)
            {
                // Inform Windows Sockets provider that broadcast messages are allowed
                BOOL optval = TRUE;
                if ( SOCKET_ERROR == setsockopt( sock, SOL_SOCKET, SO_BROADCAST, (char *) &optval, sizeof( BOOL ) ) )
                {
                    closesocket( sock );
                    return false;
                }
            }
        }

        // Associate a local address with the socket
        SockAddrIn sockAddr;
        sockAddr.CreateFrom(szLocalHostAdd, strServiceName, nFamily);

        if ( SOCKET_ERROR == bind(sock, sockAddr, (int)sockAddr.Size()))
        {
            closesocket( sock );
            return false;
        }

        // Listen to the socket, only valid for connection socket
        if (SOCK_STREAM == nType)
        {
            if ( SOCKET_ERROR == listen(sock, SOMAXCONN))
            {
                closesocket( sock );
                return false;
            }
        }

        // Success, now we may save this socket
        m_hComm = (HANDLE) sock;
    }
    return (INVALID_SOCKET != sock);
}

///////////////////////////////////////////////////////////////////////////////
// CreateSocket
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              This function creates a new socket for connection (SOCK_STREAM)
//              or an connectionless socket (SOCK_DGRAM).  A connectionless
//              socket should not call "accept()" since it cannot receive new
//              connection.  This is used as SERVER socket
// PARAMETERS:
//  LPCTSTR strServiceName: Service name or port number
//  int nFamily: address family to use (set to AF_INET)
//  int nType: type of socket to create (SOCK_STREAM, SOCK_DGRAM)
//  UINT uOptions: other options to use
///////////////////////////////////////////////////////////////////////////////
bool CSocketComm::CreateSocket(LPCTSTR strServiceName, int nFamily, int nType, UINT uOptions /* = 0 */)
{
    return CreateSocketEx(NULL, strServiceName, nFamily, nType, uOptions);
}


///////////////////////////////////////////////////////////////////////////////
// ConnectTo
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              Establish connection with a server service or port
// PARAMETERS:
//  LPCTSTR strDestination: hostname or address to connect (in .dot format)
//  LPCTSTR strServiceName: Service name or port number
//  int nFamily: address family to use (set to AF_INET)
//  int nType: type of socket to create (SOCK_STREAM, SOCK_DGRAM)
///////////////////////////////////////////////////////////////////////////////
bool CSocketComm::ConnectTo(LPCTSTR strDestination, LPCTSTR strServiceName, int nFamily, int nType, LPCTSTR szLocalIPAddress)
{
    // Socket is already opened
	LPTSTR szLocalIP = NULL;
	if((NULL != szLocalIPAddress) && (_tcslen(szLocalIPAddress) > 0))
	{
		_tcscpy_s(m_szLocalClientIPAddr,szLocalIPAddress);
		_tcscpy_s(m_szLogLocalIPAddr,szLocalIPAddress);		
		szLocalIP = m_szLocalClientIPAddr;
	}
	_tcscpy_s(m_szPeerIPAddr,strDestination);
    if ( IsOpen() )
        return false;

    // Create a Socket that is bound to a specific service provide
    // nFamily: (AF_INET)
    // nType: (SOCK_STREAM, SOCK_DGRAM)
    SOCKET sock = socket(nFamily, nType, 0);
    if (INVALID_SOCKET != sock)
    {
        // Associate a local address with the socket
        SockAddrIn sockAddr;
        if (false == sockAddr.CreateFrom(szLocalIP, TEXT("0"), nFamily))
        {
            closesocket( sock );
            return false;
        }

        if ( SOCKET_ERROR == bind(sock, sockAddr, (int)sockAddr.Size() ))
        {
            closesocket( sock );
            return false;
        }

        // Now get destination address & port
        sockAddr.CreateFrom( strDestination, strServiceName );

        // try to connect - if fail, server not ready
        if (SOCKET_ERROR == connect( sock, sockAddr, (int)sockAddr.Size()))
        {
            closesocket( sock );
            return false;
        }

        // Success, now we may save this socket
        m_hComm = (HANDLE) sock;
    }
    return (INVALID_SOCKET != sock);
}


///////////////////////////////////////////////////////////////////////////////
// CloseComm
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//      Close Socket Communication
// PARAMETERS:
//      None
///////////////////////////////////////////////////////////////////////////////
void CSocketComm::CloseComm()
{
    if (IsOpen())
    {
        ShutdownConnection((SOCKET)m_hComm);
        m_hComm = INVALID_HANDLE_VALUE;
        m_bBroadcast = false;
    }
}


///////////////////////////////////////////////////////////////////////////////
// WatchComm
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//      Starts Socket Communication Working thread
// PARAMETERS:
//      None
///////////////////////////////////////////////////////////////////////////////
bool CSocketComm::WatchComm()
{
    if (!IsStart())
    {
        if (IsOpen())
        {
            HANDLE hThread;
            hThread = (HANDLE)_beginthreadex(NULL,  // Security attributes
                                      0,    // stack
                        SocketThreadProc,   // Thread proc
                                    this,   // Thread param
                        CREATE_SUSPENDED,   // creation mode
                            &m_uiThreadId);   // Thread ID

            if ( NULL != hThread)
            {
                //SetThreadPriority(hThread, THREAD_PRIORITY_ABOVE_NORMAL);
                ResumeThread( hThread );
                m_hThread = hThread;
                return true;
            }
        }
    }
    return false;
}


///////////////////////////////////////////////////////////////////////////////
// StopComm
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//      Close Socket and Stop Communication thread
// PARAMETERS:
//      None
///////////////////////////////////////////////////////////////////////////////
void CSocketComm::StopComm()
{
	__try{

		// Close Socket
		if (IsOpen())
		{
			CloseComm();
		}
		m_bShutdownSocket = true;
		// Kill Thread
		if (IsStart())
		{
			if(m_uiThreadId != GetCurrentThreadId())
			{
				SleepEx(DEFAULT_TIMEOUT, TRUE);
				if (WaitForSingleObject(m_hThread, 3000L) == WAIT_TIMEOUT)
				{
					g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("Wait Timeout in Stop Comm"));   
				}
				CloseHandle(m_hThread);
				m_hThread = NULL;
			}
		}
		if(m_hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_hFile);
			m_hFile = INVALID_HANDLE_VALUE;
		}
		if(m_hThread)
		{
			CloseHandle(m_hThread);
			m_hThread = NULL;
		}
		//// Clear Address list
		//if (!m_AddrList.empty())
		//{
		//    m_AddrList.clear();
		//}

		// Destroy Synchronization objects
		if (NULL != m_hMutex)
		{
			CloseHandle( m_hMutex );
			m_hMutex = NULL;
		}
		m_pParentSocketComm = NULL;
		InitSessionData();
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Stop Comm")))
	{
	}
}


///////////////////////////////////////////////////////////////////////////////
// ReadComm
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//      Reads the Socket Communication
// PARAMETERS:
//      LPBYTE lpBuffer: buffer to place new data
//      DWORD dwSize: maximum size of buffer
//      DWORD dwTimeout: timeout to use in millisecond
///////////////////////////////////////////////////////////////////////////////
DWORD CSocketComm::ReadComm(LPBYTE lpBuffer, DWORD dwSize, DWORD dwTimeout)
{
    //_ASSERTE( IsOpen() );
    //_ASSERTE( lpBuffer != NULL );
	if (lpBuffer == NULL || dwSize < 1L)
        return 0L;

    fd_set  fdRead  = { 0 };
	
    TIMEVAL stTime;
    TIMEVAL *pstTime = NULL;

    if ( INFINITE != dwTimeout ) {
        stTime.tv_sec = dwTimeout/1000;
        stTime.tv_usec = (dwTimeout%1000)*1000;
        pstTime = &stTime;
    }

    SOCKET s = (SOCKET) m_hComm;
    // Set Descriptor
    if ( !FD_ISSET( s, &fdRead ) )
        FD_SET( s, &fdRead );

	LPBYTE lpHeadBuffer = lpBuffer;
	DWORD dwTempPacketSize = m_dwCurrentPacketSize;
    bool bWaitForHeader = false;
	int res = 0;
	// Select function set read timeout
    DWORD dwBytesRead = 0L;
	if(m_bServer)
	{
		if(m_bFirstPacket)
		{
			m_dwCurrentPacketSize = MA_HEADER_SIZE;
			dwTempPacketSize = MA_HEADER_SIZE;
		}
	}
	else
	{
		dwTempPacketSize = dwSize;
	}
	if((m_nCurrentState == MA_Control_Header) & (false == m_bRouter))
	{
		bWaitForHeader = true;
	}

	do{
		res = select((int)s+1, &fdRead, NULL, NULL, pstTime );
		if ( res > 0)
		{
			res = recv( s, (LPSTR)lpBuffer, dwTempPacketSize, 0);
			if(res <= 0)
			{
				return (-1L);
			}
			if(bWaitForHeader)
			{
				dwBytesRead += res; 
				if(dwBytesRead < SIZE_OF_MA_CONTROL_REQUEST)
				{
					dwTempPacketSize = SIZE_OF_MA_CONTROL_REQUEST - dwBytesRead;
					lpBuffer += res;
				}
				else
				{
					lpBuffer = lpHeadBuffer; 
					bWaitForHeader = false;
				}
			}
			else
			{
				dwBytesRead = (DWORD)((res > 0)?(res) : (-1L));
			}
			
		}
		else if(res < 0)
		{
			g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("***Socket Connection Break Detected"));   
			return (-1L);
		}
		else if(res == 0)
		{
			if(m_bMonitoring)
			{
				FD_ZERO(&fdRead);
				FD_SET(s, &fdRead);
			}
			else
			{
				g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("***Socket Timeout...Leaving..."));   
				return (-1L);
			}
		}
	}while (true == bWaitForHeader);
    
	//g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,L"Packets Size %d Bytes received %d ",m_dwCurrentPacketSize, dwBytesRead);
    return dwBytesRead;
}


///////////////////////////////////////////////////////////////////////////////
// WriteComm
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//      Writes data to the Socket Communication
// PARAMETERS:
//      const LPBYTE lpBuffer: data to write
//      DWORD dwCount: maximum characters to write
//      DWORD dwTimeout: timeout to use in millisecond
///////////////////////////////////////////////////////////////////////////////
DWORD CSocketComm::WriteComm(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout)
{
	
    //_ASSERTE( IsOpen() );
    _ASSERTE( NULL != lpBuffer );

    // Accept 0 bytes message
    if (!IsOpen() || NULL == lpBuffer)
        return (DWORD)(-1L);

    fd_set  fdWrite  = { 0 };
    TIMEVAL stTime;
    TIMEVAL *pstTime = NULL;

    if ( INFINITE != dwTimeout ) {
        stTime.tv_sec = dwTimeout/1000;
        stTime.tv_usec = (dwTimeout%1000)*1000;
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
        // Send message to peer or broadcast it
        bool bSmartAddressing = IsSmartAddressing();
        if (IsBroadcast() || bSmartAddressing )
        {
            // use offset for Smart addressing
            int nOffset = bSmartAddressing ? sizeof(SOCKADDR_IN) : 0;
            if (bSmartAddressing)
            {
                if ( dwCount < sizeof(SOCKADDR_IN)) // error - buffer to small
                {
                    SetLastError( ERROR_INVALID_USER_BUFFER );
                    return -1L;
                }

                // read socket address from buffer
                SockAddrIn sockAddr;
                sockAddr.SetAddr((PSOCKADDR_IN) lpBuffer);

                // Get Address and send data
                if (sockAddr.sin_addr.s_addr != htonl(INADDR_BROADCAST))
                {
                    LPSTR lpszData = (LPSTR)(lpBuffer + nOffset);
                    res = sendto( s, lpszData, dwCount-nOffset, 0, sockAddr, (int)sockAddr.Size());
                    dwBytesWritten = (DWORD)((res >= 0)?(res) : (-1));
                    return dwBytesWritten;
                }
                else
                {   // NOTE: broadcast will broadcast only to our peers
                    // Broadcast send to all connected-peers
                    LockList(); // Lock this object addresses-list

                    CSockAddrList::iterator iter = m_AddrList.begin();
                    for( ; iter != m_AddrList.end(); )
                    {
                        // Fix v1.3 - nOffset was missing
                        sockAddr = (*iter);
                        res = sendto( s, (LPCSTR)&lpBuffer[nOffset], dwCount-nOffset, 0, sockAddr, (int)iter->Size());
                        if (res < 0)
                        {
                            CSockAddrList::iterator deladdr = iter;
                            ++iter; // get next
                            m_AddrList.erase( deladdr );
                        }
                        else
                            ++iter; // get next
                    }
                    UnlockList(); // unlock this object addresses-list
                }
            }
            // always return success - UDP
            res = (int) dwCount - nOffset;
        }
        else // Send to peer-connection
		{
			if(m_bFirstPacket)
			{
				MA_HEADERINFO hdrInfo={0};
				hdrInfo.dwPacketSize = m_dwPacketSize;
				if(m_bRoutingClientRequest)
				{
					hdrInfo.m_bRouting = m_bRoutingClientRequest;
					_tcscpy_s(hdrInfo.szDestRoutingAddress,m_szDestRoutingAddress);
					_tcscpy_s(hdrInfo.szDestRoutingPort,m_szDestRoutingPort);
					_tcscpy_s(hdrInfo.szRoutingLocalIPAddr,m_szLocalRoutingIPAddr);
				}
				strcpy_s((char*)hdrInfo.MsgGUID,39,(char*)MAHEADER);
				int nLen = send( s, (LPCSTR)&hdrInfo, MA_HEADER_SIZE, 0);
				//g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,L"Write Size : %d",nLen);
				m_bFirstPacket = false;
			}
			res = send( s, (LPCSTR)lpBuffer, dwCount, 0);
		}
    }
    dwBytesWritten = (DWORD)((res > 0)?(res) : (-1L));
	//g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,L"Write Size : %d",dwBytesWritten);
    return dwBytesWritten;
}


///////////////////////////////////////////////////////////////////////////////
// Run
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//      This function runs the main thread loop
//      this implementation can be overloaded.
//      This function calls CSocketComm::OnDataReceived() (Virtual Function)
// PARAMETERS:
// NOTES:
//      You should not wait on the thread to end in this function or overloads
///////////////////////////////////////////////////////////////////////////////
void CSocketComm::Run()
{
	stMessageProxy stMsgProxy;
	stMsgProxy.byData = NULL;
	DWORD   dwBytes  = 0L;
    DWORD   dwTimeout = SOCKET_TIMEOUT;
    LPBYTE  lpData  = (LPBYTE)&stMsgProxy;
	m_bShutdownSocket = false;
    bool bSmartAddressing = IsSmartAddressing();
    

    // Should we run as server mode
    if (IsServer() && !bSmartAddressing)
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
				if(GetPeerName( stMsgProxy.address ))
				{
					if (!stMsgProxy.address.IsNull())
					{
						LONG  uAddr = stMsgProxy.address.GetIPAddr();
						BYTE* sAddr = (BYTE*) &uAddr;
						int nPort = ntohs( stMsgProxy.address.GetPort() ); // show port in host format...
						TCHAR  strAddr[DEFAULT_FIELD_SIZE]={0};
						// Address is stored in network format...
						_stprintf_s(strAddr,_T("%u.%u.%u.%u"),
							(UINT)(sAddr[0]), (UINT)(sAddr[1]),
							(UINT)(sAddr[2]), (UINT)(sAddr[3]));
						_tcscpy_s(m_szPeerIPAddr,strAddr);
						//g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("Connection Established with %s"),strAddr );
						
					}

				}

				OnEvent( EVT_CONSUCCESS, NULL ); // connect
			}
            else
			{
				// Do not send event if we are closing
				if (IsOpen())
					OnEvent( EVT_CONFAILURE, NULL ); // wait fail
				return;
			}
        }
    }
    else
    {
        GetPeerName( stMsgProxy.address );
    }
	while( IsOpen() )
    {
		if(m_bServer)
		{

			if(m_bFirstPacket && !m_bShutdownSocket)
			{

				// Blocking mode: Wait for event
				BYTE buffFirstPacket[MA_HEADER_SIZE]={0};
				dwBytes = ReadComm(buffFirstPacket, MA_HEADER_SIZE, dwTimeout);
				if (dwBytes == (DWORD)-1L)
				{
					break;
				}
				if(!CheckHeader(buffFirstPacket,dwBytes))
				{
					OnEvent( EVT_CONDROP, &stMsgProxy.address ); // lost connection
					break;
				}
				m_nCurrentState = MA_Control_Header;
				stMsgProxy.byData = new BYTE [m_dwPacketSize]; 
				ZeroMemory(stMsgProxy.byData,m_dwPacketSize);
				if ( !bSmartAddressing )
				{
					lpData = stMsgProxy.byData;
				}
				m_bFirstPacket = false;
				if(m_bRouter)
				{
					m_dwCurrentPacketSize =  m_dwPacketSize;
				}
				else
				{
					m_dwCurrentPacketSize =  SIZE_OF_MA_CONTROL_REQUEST;
				}

			}

		}
		else
		{
			m_nCurrentState = MA_Control_Header;
			m_dwCurrentPacketSize =  SIZE_OF_MA_CONTROL_REQUEST;
			stMsgProxy.byData = new BYTE [m_dwPacketSize]; 
			ZeroMemory(stMsgProxy.byData,m_dwPacketSize);
			if ( !bSmartAddressing )
			{
				lpData = stMsgProxy.byData;
			}
		}
		// Blocking mode: Wait for event
		dwBytes = ReadComm(lpData, m_dwCurrentPacketSize, dwTimeout);
		
		if(dwBytes == 0)
			Sleep(2);

        // Error? - need to signal error
        if (dwBytes == (DWORD)-1L)
        {
            // Do not send event if we are closing
            if (IsOpen())
            {
                if ( bSmartAddressing )
                {
                    RemoveFromList( stMsgProxy.address );
                }
                OnEvent( EVT_CONDROP, &stMsgProxy.address ); // lost connection
            }

            // special case for UDP, alert about the event but do not stop
            if ( bSmartAddressing )
                continue;
            else
                break;
        }

        // Chars received?
        if ( bSmartAddressing && dwBytes == sizeof(SOCKADDR_IN))
        {
            OnEvent( EVT_ZEROLENGTH, NULL );
        }
        else if (dwBytes > 0L)
        {
			OnDataReceived( lpData, dwBytes, this);
		}

    }
	if(stMsgProxy.byData)
	{
		delete [] stMsgProxy.byData;
	}
}


///////////////////////////////////////////////////////////////////////////////
// SocketThreadProc
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//     Socket Thread function.  This function is the main thread for socket
//     communication - Asynchronous mode.
// PARAMETERS:
//     LPVOID pParam : Thread parameter - a CSocketComm pointer
// NOTES:
///////////////////////////////////////////////////////////////////////////////
UINT WINAPI CSocketComm::SocketThreadProc(LPVOID pParam)
{
	HRESULT hr = CoInitialize(NULL);
	COINITIALIZE_OUTPUTDEBUGSTRING(hr);
	CSocketComm* pThis = reinterpret_cast<CSocketComm*>( pParam );
	__try
	{
		_ASSERTE( pThis != NULL );
		pThis->Run();
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Socket Comm Run Thread")))
	{
		g_objLogApp.AddLog(pThis->m_szLocalHostIPAddr,pThis->m_szPeerIPAddr,_T("****Critical Error. Exception Caught"));

	}
	CoUninitialize();
	return 1L;
} // end SocketThreadProc

//Wrapper
bool CSocketComm::OnDataReceived(const LPBYTE lpBuffer, DWORD dwCount, CSocketComm *pSocketComm)
{
	if(m_pParentSocketComm)
	{
		//THis is a router client just use the parent socket connection and Route it
		g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("Routing the response"));
		DWORD dwBytes = 0;
		m_pParentSocketComm->WriteComm(lpBuffer,dwCount, SOCKET_TIMEOUT);
		if (dwBytes == (DWORD)-1L)
		{
			g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("***Routing Reponse Failed"));
		}
		return true;
	}
	if(m_bRouter)
	{
		if(NULL == m_pRouterComm)
		{
			g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("!!Routing Packet"));
			m_pRouterComm = new CSocketComm();	
			if(m_pRouterComm)
			{
				m_pRouterComm->SetParentConnection(this);
				m_pRouterComm->SetServerState(false,m_pSocketCallBack);
				m_pRouterComm->SetSmartAddressing( false );
				m_pRouterComm->SetPacketSize(m_dwPacketSize);
				if(m_pRouterComm->ConnectTo(m_szDestRoutingAddress,m_szDestRoutingPort,AF_INET, SOCK_STREAM,m_szLocalRoutingIPAddr))
				{
					if(m_pRouterComm->WatchComm())
					{
						//g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("Connection Established with Routing Destination"));
					}
				}
			}
		}
		if(m_pRouterComm)
		{
			DWORD dwBytes = 0;
			dwBytes = m_pRouterComm->WriteComm(lpBuffer,dwCount, SOCKET_TIMEOUT);
			if (dwBytes == (DWORD)-1L)
			{
				g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("***Routing Failed"));
				m_pRouterComm->StopComm();
				if(m_pParentSocketComm)
				{
					m_pParentSocketComm->StopComm();
				}
				return false;
			}
			return true;
		}


	}

	if(m_nCurrentState == MA_Control_Header)
	{
		if(dwCount == SIZE_OF_MA_CONTROL_REQUEST)
		{
			//Get the COntrol Request Header and Process only if its a FIle Transder
			LPMA_CONTROL_REQUEST lpControlRequest = (LPMA_CONTROL_REQUEST)lpBuffer;
			if(lpControlRequest)
			{
				if(lpControlRequest->eMessageInfo == MA_Start_File_Transfer)
				{
					m_nCurrentState = MA_Start_File_Transfer;
					_tcscpy_s(m_szFileName,lpControlRequest->MA_FILE_INFORMATION.szFileName);
					_tcscpy_s(m_szOutputDirectory,lpControlRequest->szFileDestinationLocation);
					m_dwFileTransferSize = lpControlRequest->MA_FILE_INFORMATION.dwFileSize ;
					if(m_dwFileTransferSize >=  m_dwPacketSize)
					{
						m_dwCurrentPacketSize =  m_dwPacketSize;
					}
					else
					{
						m_dwCurrentPacketSize =  static_cast<DWORD>(m_dwFileTransferSize);
					}
					g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,L"MA_Start_File_Transfer:FileName:%s",m_szFileName);
					return true;
				}
				if(lpControlRequest->eMessageInfo == MA_End_File_Transfer)
				{
					CloseHandle(m_hFile);
					m_hFile  = INVALID_HANDLE_VALUE;
					m_nCurrentState = MA_Control_Header;
					m_dwCurrentPacketSize =  SIZE_OF_MA_CONTROL_REQUEST;
					m_dwTotalFileBytesRead = 0;
					m_dwFileTransferSize = 0;
					_tcscpy_s(lpControlRequest->m_szPeerName,m_szPeerIPAddr);
					if(false == m_bFileTransferSuccess)
					{
						g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("***MA_End_File_Transfer:Failed"));
						lpControlRequest->eMessageInfo = MA_File_Save_Error;
					}
					else
					{
						g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("MA_End_File_Transfer:Successful"));
						lpControlRequest->eMessageInfo = MA_File_Received;
					}
					m_bFileTransferSuccess = true;
					//MA_File_Save_Error
					//rename the file to Original Name
					if(lpControlRequest->bOverwrite)
					{
						::DeleteFile(m_szFileName);
					}
					if(!::MoveFile(m_szTempFileName,m_szFileName))
					{
						g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,L"***File renamed Failed%s", m_szFileName);
					}

					if(m_pSocketCallBack)
					{
						m_pSocketCallBack->OnDataReceived( lpBuffer, dwCount, this);
					}
					if(!SendFileInfo(*lpControlRequest))
					{
						g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("***Sending response Failed"));
					}

					return true;
				}

				if(lpControlRequest->eMessageInfo == MA_File_Received)
				{
					m_nCurrentState = MA_Control_Header;
					m_dwCurrentPacketSize =  SIZE_OF_MA_CONTROL_REQUEST;
					g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("MA_File_Received:Successful"));
					return true;
				}
			}

		}
	}
	if(m_nCurrentState == MA_Start_File_Transfer)
	{
		if(SaveFile(lpBuffer,dwCount))
		{
			m_dwTotalFileBytesRead += dwCount;
			if(m_dwTotalFileBytesRead == m_dwFileTransferSize)
			{
				m_nCurrentState = MA_Control_Header;
				m_dwCurrentPacketSize =  SIZE_OF_MA_CONTROL_REQUEST;
				return true;
			}
			LONGLONG dwBytesRemaining = 0;
			dwBytesRemaining = m_dwFileTransferSize - m_dwTotalFileBytesRead;
			if(dwBytesRemaining < m_dwPacketSize )
			{
				m_dwCurrentPacketSize =  static_cast<DWORD>(dwBytesRemaining);
				return true;
			}

		}
		else
		{
			g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("\r***nSave File Failed"));
			m_bFileTransferSuccess = false;

		}
		return true;
	}

	if(m_pSocketCallBack)
	{
		m_pSocketCallBack->OnDataReceived( lpBuffer, dwCount, this);
	}
	return true;
}

void CSocketComm::OnEvent(UINT uEvent, LPVOID lpvData)
{
	if(m_pSocketCallBack)
	{
		m_pSocketCallBack->OnEvent( uEvent, lpvData, this);
	}

}


bool CSocketComm::CheckHeader(LPBYTE lpBuffer, const DWORD &dwSize)
{
	if(MA_HEADER_SIZE != dwSize)
	{
		g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("Invalid Header Rejecting!!!"));
		return false;
	}
	LPMA_HEADERINFO lpMsgHdr = (LPMA_HEADERINFO)lpBuffer;
	if(lpMsgHdr)
	{
		if(strcmp((char*)lpMsgHdr->MsgGUID,(char*)MAHEADER) == 0)
		{
			m_dwPacketSize = lpMsgHdr->dwPacketSize;
			m_bRouter = lpMsgHdr->m_bRouting;
			if(m_bRouter)
			{
				g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("Routing Enabled For THis connection"));
				//Server Side
				_tcscpy_s(m_szDestRoutingAddress,lpMsgHdr->szDestRoutingAddress);
				_tcscpy_s(m_szDestRoutingPort,lpMsgHdr->szDestRoutingPort);
				_tcscpy_s(m_szLocalRoutingIPAddr,lpMsgHdr->szRoutingLocalIPAddr);

			}

			return true;
		}
	}
		g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("Invalid Header Rejecting!!!"));
	return false;
}

bool CSocketComm::SendFile(LPCTSTR szFileName, LPCTSTR szDestinationFolder, MA_File_Types eFileType, bool bOverwriteExisting)
{
	bool bRet = false;
	MA_CONTROL_REQUEST sControlRequest = {0};
	sControlRequest.eMessageInfo = MA_Start_File_Transfer;
	sControlRequest.vt = eFILE_INFORMATION;
	
	_tcscpy_s(sControlRequest.szFileDestinationLocation,szDestinationFolder);
	_tcscpy_s(sControlRequest.MA_FILE_INFORMATION.szFileName,sControlRequest.szFileDestinationLocation);
	_tcscat_s(sControlRequest.MA_FILE_INFORMATION.szFileName,_T("\\"));
	sControlRequest.MA_FILE_INFORMATION.wFileType = eFileType;
	sControlRequest.bOverwrite = bOverwriteExisting;
	tstring strSourceFileName = szFileName;
	size_t found = strSourceFileName.rfind(_T("\\"));
	
	if (found!=tstring::npos)
	{
		strSourceFileName = strSourceFileName.substr(found+1,strSourceFileName.length()-1);
		_tcscat_s(sControlRequest.MA_FILE_INFORMATION.szFileName,strSourceFileName.c_str());
	}
	
	bool bReadError = false ;
	if(INVALID_HANDLE_VALUE == m_hFile )
	{
		m_hFile = CreateFile ( szFileName , GENERIC_READ , FILE_SHARE_READ , 0 , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , 0 ) ;
		if ( INVALID_HANDLE_VALUE == m_hFile )
			return ( false ) ;
	}
	LONGLONG dwFileSize = 0 ;
	dwFileSize = GetFileSize ( m_hFile , 0 ) ;

	//Set The File Size
	//TODO:Set Other Attributes
	sControlRequest.MA_FILE_INFORMATION.dwFileSize = dwFileSize;
	SendFileInfo(sControlRequest );
	
	BYTE*	ReadBuffer = NULL;
	DWORD dwReadBytes = 0, dwTotalBytesWritten = 0, dwBytesWritten = 0 ;
	ReadBuffer = (BYTE*)Allocate(m_dwPacketSize);
	ZeroMemory(ReadBuffer,m_dwPacketSize);
	if(!ReadBuffer)
	{
		return bRet;
	}
	while(ReadFile(m_hFile, ReadBuffer, m_dwPacketSize, &dwReadBytes, NULL) && dwReadBytes) 
	{
		dwBytesWritten = WriteComm(ReadBuffer, dwReadBytes,FILETRANFER_TIMEOUT);
		
		if (dwBytesWritten == (DWORD)-1L)
		{
			g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,L"***WriteComm Timeout...Leaving...");
			break;
		}
		else
		{
			dwTotalBytesWritten+= dwBytesWritten;
		}
	}	

	Release( (LPVOID&)ReadBuffer);
	ReadBuffer = NULL;
	CloseHandle(m_hFile);
	m_hFile  = INVALID_HANDLE_VALUE;
	if(dwTotalBytesWritten != dwFileSize)
	{
		g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,L"***Read File Size not Matching");
		return false;
	}
	sControlRequest.eMessageInfo = MA_End_File_Transfer;
	bRet = SendFileInfo(sControlRequest);
	DWORD dwBytes = 0;
	if(bRet)
	{
		if(!m_bServer)
		{
			SetCurrentState(MA_Control_Header);
			dwBytes = ReadComm((LPBYTE)&sControlRequest,SIZE_OF_MA_CONTROL_REQUEST,FILETRANFER_TIMEOUT);
		}
		if (dwBytes == (DWORD)-1L)
		{
			bRet = false;
		}
		else
		{
			if(sControlRequest.eMessageInfo == MA_File_Received)
			{
				g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("%s:File Sent Successfully"), szFileName);
				bRet = true;
			}
			else
			{
				bRet = false;
			}

		}
	}
	return bRet;

}

bool CSocketComm::SaveFile(const LPBYTE lpBuffer, const DWORD &dwCount)
{
	//TODO:Save the file as TMP and then Rename it as zip
	bool bRet = false;
	bool bReadError = false ;
	if(INVALID_HANDLE_VALUE == m_hFile )
	{
		if(!::PathIsDirectory(m_szOutputDirectory))
		{
			CreateDirectory(m_szOutputDirectory, NULL);
		}
		_tcscpy_s(m_szTempFileName,m_szFileName);
		_tcscat_s(m_szTempFileName,_T(".tmp"));
		m_hFile = CreateFile ( m_szTempFileName , GENERIC_WRITE , FILE_SHARE_READ , 0 , CREATE_ALWAYS , FILE_ATTRIBUTE_NORMAL , 0 ) ;
		if ( INVALID_HANDLE_VALUE == m_hFile )
			return ( false ) ;
	}
	DWORD dwWriteBytes = 0, dwTotalBytesWritten = 0 ;
	if(WriteFile(m_hFile, lpBuffer, dwCount, &dwWriteBytes, NULL) && dwWriteBytes)
	{
		dwTotalBytesWritten+= dwWriteBytes;
	}
	else
	{
		g_objLogApp.AddLog(m_szLogLocalIPAddr,m_szPeerIPAddr,_T("\r***Write File Failed"));
	}
	return true;
}

LPVOID CSocketComm::Allocate (DWORD dwSize)
{
	return ( HeapAlloc ( GetProcessHeap() , HEAP_ZERO_MEMORY , dwSize ) ) ;
}

void CSocketComm::Release ( LPVOID& pVPtr )
{
	HeapFree ( GetProcessHeap() , 0 , pVPtr ) ;
	pVPtr = NULL ;
}

void CSocketComm::InitSessionData()
{
	m_dwPacketSize = DEFAULT_PACKET_SIZE;
	m_bFirstPacket = true;
	m_hFile = INVALID_HANDLE_VALUE;
	m_nCurrentState = MA_Connection_Header;
	m_dwCurrentPacketSize = MA_HEADER_SIZE;
	ZeroMemory(m_szFileName,sizeof(m_szFileName));
	ZeroMemory(m_szTempFileName,sizeof(m_szTempFileName));
	ZeroMemory(m_szOutputDirectory,sizeof(m_szOutputDirectory));
	m_uiThreadId = 0;
	m_ulIPv4LocalAddr = 0;
	ZeroMemory(m_szDestRoutingAddress,sizeof(m_szDestRoutingAddress));
	ZeroMemory(m_szDestRoutingPort,sizeof(m_szDestRoutingPort));
	ZeroMemory(m_szLocalRoutingIPAddr,sizeof(m_szLocalRoutingIPAddr));
	ZeroMemory(m_szLocalClientIPAddr,sizeof(m_szLocalClientIPAddr));
	ZeroMemory(m_szLocalHostIPAddr,sizeof(m_szLocalHostIPAddr));
	ZeroMemory(m_szPeerIPAddr,sizeof(m_szPeerIPAddr));
	ZeroMemory(m_szLogLocalIPAddr,sizeof(m_szLogLocalIPAddr));
	
	m_dwFileTransferSize = 0; 
	m_dwTotalFileBytesRead = 0;
	m_bFileTransferSuccess = true;
	if(m_pRouterComm)
	{
		m_pRouterComm->StopComm();
		delete m_pRouterComm;
		m_pRouterComm = NULL;
	}
	m_pParentSocketComm = NULL;
	m_bMonitoring = false;
	m_bRoutingClientRequest = false;
}

void CSocketComm::SetLocalIPAddr(LPCTSTR szLocalIP)
{
	_tcscpy_s(m_szLocalClientIPAddr,szLocalIP);
}

ULONG CSocketComm::ResolveLocalIP(LPCSTR strHost)
{
	LPHOSTENT   lphostent;
    struct in_addr addr;

	ULONG       uAddr = INADDR_NONE;
		if (isalpha(strHost[0])) {        /* host address is a name */
        lphostent = gethostbyname(strHost);
    }
	else {
		addr.s_addr = inet_addr(strHost);
		uAddr = inet_addr( strHost );
		if (addr.s_addr == INADDR_NONE) {
		    return 0;
		}
		else
        lphostent = gethostbyaddr((char *) &addr, 4, AF_INET);

	}

	// Check for an Internet Protocol dotted address string
	if ( lphostent )
	{
		int i = 0;
        while (lphostent->h_addr_list[i] != 0) {
            addr.s_addr = *(u_long *) lphostent->h_addr_list[i++];
			char szTempBuff[100] = {0};
			strcpy_s(szTempBuff,inet_ntoa(addr));
			if(strcmp(szTempBuff,strHost) == 0)
			{
				uAddr = addr.s_addr;
				g_objLogApp.AddLog1(_T("\tIP Address #%d: %s\n"), i, inet_ntoa(addr));
				break;
			}
		}
    }
 	//return ntohl( uAddr );
	return uAddr;
}
bool CSocketComm::SendFileInfo(MA_CONTROL_REQUEST &sControlRequest)
{
	bool bRet = true;
	DWORD dwBytes = 0;
	dwBytes = WriteComm((LPBYTE)&sControlRequest,SIZE_OF_MA_CONTROL_REQUEST,FILETRANFER_TIMEOUT);
	if (dwBytes == (DWORD)-1L)
	{
		
		bRet = false;
	}
	return bRet;
}


void CSocketComm::SetParentConnection(CSocketComm *pParentSocket)
{
	m_pParentSocketComm = pParentSocket;
}
void CSocketComm::EnableRouting(LPCTSTR szDestRoutingAddress ,LPCTSTR szDestRoutingPort, LPCTSTR szLocalRoutingIP)
{
	m_bRoutingClientRequest = true;
	if((m_szDestRoutingAddress == NULL) || (szDestRoutingPort == NULL))
	{
		return;
	}
	_tcscpy_s(m_szDestRoutingAddress, szDestRoutingAddress );
	_tcscpy_s(m_szDestRoutingPort, szDestRoutingPort);
	_tcscpy_s(m_szLocalRoutingIPAddr, szLocalRoutingIP);
	
}

bool CSocketComm::CreateZipFile(LPCTSTR szFolderPath,LPTSTR szZipFileName)
{
	bool bRet = false;
	return bRet;
}

bool CSocketComm::ExtractFile(LPCTSTR szFileName, LPCTSTR szExtractToFolder)
{
	bool bRet = false;

	return bRet;
}
void CSocketComm::GetPeerName(LPTSTR szIPAddr, DWORD dwCount)
{
	_tcscpy_s(szIPAddr,dwCount,m_szPeerIPAddr);

}