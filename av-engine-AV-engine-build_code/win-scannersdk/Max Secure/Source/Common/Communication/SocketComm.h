///////////////////////////////////////////////////////////////////////////////
// FILE : SocketComm.h
// Header file for CSocketComm class
// CSocketComm
//     Generic class for Socket Communication
///////////////////////////////////////////////////////////////////////////////

#ifndef _SOCKETCOMM_H_
#define _SOCKETCOMM_H_
#include <list>

#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "SockStructures.h"
//#include "ZipArchive.h"

#pragma comment(lib, "ws2_32")
//TODO:Darshit
//Error Handling
//Synchornous WriteComm()
//Dynamic Creation of SocketCOmm Pool
//Optimize code
//Memory Leaks
//Redundancy
//Abstraction and Encapsulation

#define HOSTNAME_SIZE   MAX_PATH
#define STRING_LENGTH   40



struct SockAddrIn : public SOCKADDR_IN {
public:
    SockAddrIn() { Clear(); }
    SockAddrIn(const SockAddrIn& sin) { Copy( sin ); }
    ~SockAddrIn() { }
    SockAddrIn& Copy(const SockAddrIn& sin);
    void    Clear() { memset(this, 0, sizeof(SOCKADDR_IN)); }
    bool    IsEqual(const SockAddrIn& sin) const;
    bool    IsGreater(const SockAddrIn& sin) const;
    bool    IsLower(const SockAddrIn& pm) const;
    bool    IsNull() const { return ((sin_addr.s_addr==0L)&&(sin_port==0)); }
    ULONG   GetIPAddr() const { return sin_addr.s_addr; }
    short   GetPort() const { return sin_port; }
    bool    CreateFrom(LPCTSTR sAddr, LPCTSTR sService, int nFamily = AF_INET);
    SockAddrIn& operator=(const SockAddrIn& sin) { return Copy( sin ); }
    bool    operator==(const SockAddrIn& sin) { return IsEqual( sin ); }
    bool    operator!=(const SockAddrIn& sin) { return !IsEqual( sin ); }
    bool    operator<(const SockAddrIn& sin)  { return IsLower( sin ); }
    bool    operator>(const SockAddrIn& sin)  { return IsGreater( sin ); }
    bool    operator<=(const SockAddrIn& sin) { return !IsGreater( sin ); }
    bool    operator>=(const SockAddrIn& sin) { return !IsLower( sin ); }
    operator LPSOCKADDR() { return (LPSOCKADDR)(this); }
    size_t  Size() const { return sizeof(SOCKADDR_IN); }
    void    SetAddr(SOCKADDR_IN* psin) { memcpy(this, psin, Size()); }
};

typedef std::list<SockAddrIn> CSockAddrList;

typedef struct 
{
  SockAddrIn address;
  BYTE *byData;
}stMessageProxy;
class CSocketComm;
interface ISocketCallBack
{
	virtual bool OnDataReceived(const LPBYTE lpBuffer, DWORD dwCount, CSocketComm *pSocketComm)=0;
    virtual void OnEvent(UINT uEvent, LPVOID lpvData, CSocketComm *pSocketComm)=0;
};

class CSocketComm
{
public:
    CSocketComm();
    virtual ~CSocketComm();
	bool IsOpen() const;    // Is Socket valid?
    bool IsStart() const;   // Is Thread started?
    bool IsServer() const;  // Is running in server mode
    bool IsBroadcast() const; // Is UDP Broadcast active
    bool IsSmartAddressing() const; // Is Smart Addressing mode support
    SOCKET GetSocket() const;   // return socket handle
    void SetServerState(bool bServer, ISocketCallBack *pSocketCallBack);  // Run as server mode if true
    void SetPacketSize(DWORD dwPacketSize = DEFAULT_PACKET_SIZE);
	void SetLocalIPAddr(LPCTSTR szLocalIP);
	void SetMonitoring(bool bEnable)
	{
		m_bMonitoring = bEnable;
	}
	bool IsMonitoring()
	{
		return m_bMonitoring;
	}
	void SetSmartAddressing(bool bSmartAddressing); // Set Smart addressing mode
	void SetCurrentState(MA_Message_Info eMsgInfo)
	{
		m_nCurrentState = MA_Control_Header;
	}
    bool GetSockName(SockAddrIn& saddr_in); // Get Socket name - address
    bool GetPeerName(SockAddrIn& saddr_in); // Get Peer Socket name - address
    bool AddMembership(LPCTSTR strAddress);
    bool DropMembership(LPCTSTR strAddress);
    void AddToList(const SockAddrIn& saddr_in); // Add an address to the list
    void RemoveFromList(const SockAddrIn& saddr_in);    // Remove an address from the list
    void CloseComm();       // Close Socket
    bool WatchComm();       // Start Socket thread
    void StopComm();        // Stop Socket thread
	bool OnDataReceived(const LPBYTE lpBuffer, DWORD dwCount, CSocketComm *pSocketComm); //Wrapper
    void OnEvent(UINT uEvent, LPVOID lpvData);//Wrapper
    // Create a socket - Server side (support for multiple adapters)
    bool CreateSocketEx(LPCTSTR strHost, LPCTSTR strServiceName, int nFamily, int nType, UINT uOptions /* = 0 */);
    // Create a Socket - Server side
    bool CreateSocket(LPCTSTR strServiceName, int nProtocol, int nType, UINT uOptions = 0);
    // Create a socket, connect to (Client side)
    bool ConnectTo(LPCTSTR strDestination, LPCTSTR strServiceName, int nProtocol, int nType, LPCTSTR szLocalIPAddress = NULL);
	
// Run function - override to implement a new behaviour
    virtual void Run();

// Data function
    DWORD ReadComm(LPBYTE lpBuffer, DWORD dwSize, DWORD dwTimeout);
    DWORD WriteComm(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout);
	DWORD GetThreadId(){return m_uiThreadId;};
    // Utility functions
    static SOCKET WaitForConnection(SOCKET sock); // Wait For a new connection (Server side)
    static bool ShutdownConnection(SOCKET sock);  // Shutdown a connection
    static USHORT GetPortNumber( LPCTSTR strServiceName );  // Get service port number
    static ULONG GetIPAddress( LPCTSTR strHostName );   // Get IP address of a host
    static bool GetLocalName(LPTSTR strName, UINT nSize);   // GetLocalName
    bool GetLocalAddress(LPTSTR strAddress, UINT nSize); // GetLocalAddress
	//Required for Multiple Adapters
	static ULONG ResolveLocalIP(LPCSTR strHostAddr);
	// SocketComm - data
	bool SendFile(LPCTSTR szFileName, LPCTSTR szDestinationFolder, MA_File_Types eFileType, bool bOverwriteExisting = false);
	bool SendFileInfo(MA_CONTROL_REQUEST &sControlRequest);
	bool SaveFile(const LPBYTE lpBuffer, const DWORD &dwCount);
	bool CreateZipFile(LPCTSTR szFolderPath,LPTSTR szZipFileName);
	bool ExtractFile(LPCTSTR szFileName, LPCTSTR szExtractToFolder);
	//Routing Capabilities
	void EnableRouting(LPCTSTR szDestRoutingAddress ,LPCTSTR szDestRoutingPort, LPCTSTR szLocalRoutingIP);
	void GetPeerName(LPTSTR szIPAddr, DWORD dwCount);
protected:
    HANDLE      m_hComm;        // Serial Comm handle
    HANDLE      m_hThread;      // Thread Comm handle
	UINT		m_uiThreadId;
    bool        m_bServer;      // Server mode (true)
    bool        m_bSmartAddressing; // Smart Addressing mode (true) - many listeners
    bool        m_bBroadcast;   // Broadcast mode
    CSockAddrList m_AddrList;   // Connection address list for broadcast
    HANDLE      m_hMutex;       // Mutex object
// SocketComm - function
protected:
    // Synchronization function
    void LockList();            // Lock the object
    void UnlockList();          // Unlock the object

    static UINT WINAPI SocketThreadProc(LPVOID pParam);

private:
	void InitSessionData();
	bool CheckHeader(LPBYTE lpBuffer, const DWORD &dwSize);
	LPVOID Allocate (DWORD dwSize);
	void Release ( LPVOID& pVPtr );
	bool m_bFirstPacket;
	DWORD m_dwPacketSize;
	DWORD m_dwCurrentPacketSize;
	HANDLE m_hFile;
	int m_nCurrentState;
	TCHAR m_szFileName[MAX_DOUBLE_FILE_PATH];
	TCHAR m_szTempFileName[MAX_DOUBLE_FILE_PATH];
	TCHAR m_szOutputDirectory[MAX_DOUBLE_FILE_PATH];
	bool m_bShutdownSocket;
	ULONG m_ulIPv4LocalAddr;
	LONGLONG m_dwFileTransferSize;
	LONGLONG m_dwTotalFileBytesRead;
	bool m_bFileTransferSuccess;
	//Routing Capabilities
	bool m_bRouter;
	bool m_bRoutingClientRequest;
	CSocketComm *m_pRouterComm;
	CSocketComm *m_pParentSocketComm;
	void SetParentConnection(CSocketComm *pParentSocket);
	//Monitoring Capabilities
	bool m_bMonitoring;	
	TCHAR m_szDestRoutingAddress[MAX_PATH];
	TCHAR m_szDestRoutingPort[MAX_PATH];
	TCHAR m_szLocalRoutingIPAddr[MAX_PATH];
	TCHAR m_szLocalClientIPAddr[MAX_PATH];
	TCHAR m_szLocalHostIPAddr[MAX_PATH];
public:
	TCHAR m_szPeerIPAddr[DEFAULT_FIELD_SIZE];
	TCHAR m_szLogLocalIPAddr[MAX_PATH];
	ISocketCallBack *m_pSocketCallBack;
};

#endif // _SOCKETCOMM_H_
