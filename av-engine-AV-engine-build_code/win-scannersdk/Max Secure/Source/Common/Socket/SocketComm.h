/*======================================================================================
   FILE			: SocketComm.cpp
   ABSTRACT		: Generic class for Socket Communication
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
======================================================================================*/
#pragma once

#include <list>
#include <stdlib.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32")

#include "SockStructures.h"

const int SOCK_TCP	= 0;
const int SOCK_UDP  = 1;

// Event value
#define EVT_CONSUCCESS		0x0000	// Connection established
#define EVT_CONFAILURE		0x0001	// General failure - Wait Connection failed
#define EVT_CONDROP			0x0002	// Connection dropped
#define EVT_ZEROLENGTH		0x0003	// Zero length message


#define BUFFER_SIZE			4096
#define HOSTNAME_SIZE		MAX_PATH
#define STRING_LENGTH		40

#pragma pack(1)
struct SockAddrIn : public SOCKADDR_IN 
{

public:
	SockAddrIn() 
	{ 
		Clear(); 
	}
	SockAddrIn( const SockAddrIn& sin) 
	{ 
		Copy( sin ); 
	}
	~SockAddrIn()
	{ 
	}
	SockAddrIn& Copy(const SockAddrIn& sin);
	
	void	Clear() 
	{ 
		SecureZeroMemory(this, sizeof(SOCKADDR_IN)); 
	}
	bool	IsEqual(const SockAddrIn& sin);
	bool	IsGreater(const SockAddrIn& sin);
	bool	IsLower(const SockAddrIn& pm);
	bool	IsNull() const 
	{ 
		return ((sin_addr.s_addr == 0L) && (sin_port == 0)); 
	}
	ULONG	GetIPAddr() const 
	{ 
		return sin_addr.s_addr; 
	}
	short	GetPort() const 
	{ 
		return sin_port; 
	}
	bool	CreateFrom(LPCTSTR sAddr, LPCTSTR sService, int nFamily = AF_INET);
	
	SockAddrIn& operator = (const SockAddrIn& sin) 
	{ 
		return Copy( sin ); 
	}
	bool	operator==(const SockAddrIn& sin) 
	{ 
		return IsEqual( sin ); 
	}
	bool	operator!=(const SockAddrIn& sin) 
	{ 
		return !IsEqual( sin ); 
	}
	bool	operator<(const SockAddrIn& sin)  
	{ 
		return IsLower( sin ); 
	}
	bool	operator>(const SockAddrIn& sin)  
	{ 
		return IsGreater( sin ); 
	}
	bool	operator<=(const SockAddrIn& sin) 
	{ 
		return !IsGreater( sin ); 
	}
	bool	operator>=(const SockAddrIn& sin) 
	{ 
		return !IsLower( sin ); 
	}
	operator LPSOCKADDR() 
	{ 
		return (LPSOCKADDR)(this); 
	}
	size_t	Size() const 
	{ 
		return sizeof(SOCKADDR_IN); 
	}
	void	SetAddr(SOCKADDR_IN* psin) 
	{ 
		memcpy(this, psin, Size()); 
	}
};

typedef std::list<SockAddrIn> CSockAddrList;

#pragma pack(1)
class CSocketComm
{
public:

	CSocketComm();
	virtual ~CSocketComm();

	bool	IsConnected();
	bool	CreateSockServer(int iPortNumber,CString csIPAddress); //changed by Avinash B
	int		ConnectSockServer(CString strServer, int iPortNumber, CString csClientIP, bool bVersionCheckRequired = true);
	int		GetSocketPortNo();
	void	DisconnectSock();
	
	// Data function
	void	SendSockMsg(CString strText);
	DWORD	WriteComm(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout, bool bBlockingCall, CString &csReply);
	DWORD	WriteComm(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout, bool bBlockingCall = false);
	DWORD CSocketComm::RawWriteComm(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout, bool bBlockingCall, CString &csReply);

	// Event function - override to get data
	virtual void	OnDataReceived(const LPBYTE lpBuffer, DWORD dwCount, CString &csReply);
	virtual void	OnEvent(UINT uEvent);

	static USHORT	GetPortNumber( LPCTSTR strServiceName );	// Get service port number
	static ULONG	GetIPAddress( LPCTSTR strHostName );	// Get IP address of a host

// SocketComm - data
protected:

	HANDLE		m_hComm;		// Serial Comm handle
	HANDLE		m_hThread;		// Thread Comm handle
	HANDLE		m_hMutex;		// Mutex object
	CSockAddrList m_AddrList;	// Connection address list for broadcast
	bool		m_bServer;		// Server mode (true)
	bool		m_bSmartAddressing;	// Smart Addressing mode (true) - many listeners
	bool		m_bBroadcast;	// Broadcast mode
	bool		m_bConnected;
	int			m_iSocketPortNo;
	CString		m_sServerIPAddress;	// IP address of Server
	CString		m_sClientIPAddress;	// IP address of Client
	CString		m_csMachineID;
	
	SockAddrIn		m_SockPeer;

	// Synchronization function
	void	LockList();			// Lock the object
	void	UnlockList();		// Unlock the object

	static UINT WINAPI SocketThreadProc(LPVOID pParam);

private:
	bool	IsOpen() const;			// Is Socket valid?
	bool	IsStart() const;		// Is Thread started?
	bool	IsServer() const;		// Is running in server mode
	bool	IsBroadcast() const;	// Is UDP Broadcast active
	bool	IsSmartAddressing() const;	// Is Smart Addressing mode support
	SOCKET	GetSocket() const;	// return socket handle
	void	SetServerState(bool bServer);	// Run as server mode if true
	void	SetSmartAddressing(bool bSmartAddressing);	// Set Smart addressing mode
	bool	GetSockName(SockAddrIn& saddr_in);	// Get Socket name - address
	bool	GetPeerName(SockAddrIn& saddr_in);	// Get Peer Socket name - address
	void	AddToList(const SockAddrIn& saddr_in);	// Add an address to the list
	void	RemoveFromList(const SockAddrIn& saddr_in);	// Remove an address from the list
	void	CloseComm();		// Close Socket
	bool	WatchComm();		// Start Socket thread
	void	StopComm();		// Stop Socket thread

	// Create a Socket - Server side
	bool	CreateSocket(LPCTSTR strServiceName, int nProtocol, int nType, UINT uOptions = 0);

	// Create a socket, connect to (Client side)
	int		ConnectTo(LPCTSTR strDestination, LPCTSTR strServiceName, int nProtocol, int nType);

	// Run function - override to implement a new behaviour
	virtual void Run();

	// Data function
	DWORD	ReadComm(COMM_RAW_DATA_READ &stRawData, DWORD dwTimeout);
	
	//Client version check
	int		CheckClientVersion(CString strServer);
	CString GetServerVersionNo();

	// Utility functions
	static SOCKET	WaitForConnection(SOCKET sock);		// Wait For a new connection (Server side)
	static bool		ShutdownConnection(SOCKET sock);	// Shutdown a connection
	static bool		GetLocalName(LPTSTR strName, UINT nSize);	// GetLocalName
	static bool		GetLocalAddress(LPTSTR strAddress, UINT nSize);	// GetLocalAddress
	
	HANDLE m_hDataProcessed;	// Event for conformation request!
	CString		m_csReply;
};
