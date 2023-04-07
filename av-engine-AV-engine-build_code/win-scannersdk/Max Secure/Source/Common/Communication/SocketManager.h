// SocketManager.h: interface for the CSocketManager class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_SOCKETMANAGER_H__7403BD71_338A_4531_BD91_3D7E5B505793__INCLUDED_)
#define AFX_SOCKETMANAGER_H__7403BD71_338A_4531_BD91_3D7E5B505793__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "SocketComm.h"
#include "SockStructures.h"

typedef void (*CallBackFunctionPtr)(const LPBYTE lpBuffer, DWORD& dwCount);

class CSocketManager : public ISocketCallBack 
{
public:
	bool CheckDuplicateswithCataLog(MAControlVector &vecList);
	bool RegisterBatchWithCataLog(MAControlVector &vecList,MA_CONTROL_REQUEST &objBatchInfo);
	bool UpdateControlStatus(MA_CONTROL_REQUEST &objControlRequest);
	void SendAlert(LPCTSTR szDescription,bool bDisplay);
	void RegisterWithWatchDog(bool bMonitor);
	void RegisterControllerWithGateway(bool bMonitor);
	void SetMaxServerConnections(int nMaxConnections)
	{
		if(nMaxConnections > 0 )
			m_nMaxServerConnections = nMaxConnections;
	}
	void EnableRouting(LPCTSTR szDestRoutingAddress ,LPCTSTR szDestRoutingPort, LPCTSTR szLocalRoutingIP);
	static void SendAutomationSMSAlert(LPCTSTR szMsg);
	CSocketManager(CallBackFunctionPtr fnPtrCallBack = NULL,bool bRouter = false, DWORD dwPacketSize = DEFAULT_PACKET_SIZE );
	virtual ~CSocketManager();
	HANDLE m_hShutdownEvent;
	static bool m_bMonitoringController;
	static HANDLE m_hCriticalSectionAlert;
	static bool AssignQueueToRequestedVM(LPMA_CONTROL_REQUEST lpControlRequest);
	static bool AssignQueueToVM(MA_Application_Type eAppType, LPMA_CONTROL_REQUEST oBatchInfo);
	static bool AssignBatchToVM(const wchar_t *strFileName, MA_CONTROL_REQUEST &oBatchInfo, bool bFromQueue);
	void SetPacketSize(DWORD dwPacketSize);
	void SetLocalHostIPAddress(DWORD dwPacketSize);
	virtual bool OnDataReceived(const LPBYTE lpBuffer, DWORD dwCount, CSocketComm *pSocketComm);
	virtual void OnEvent(UINT uEvent, LPVOID lpvData, CSocketComm *pSocketComm);
	bool SendResponse(const LPBYTE lpBuffer, DWORD dwCount, CSocketComm *pSocketComm);
	void StopComm(bool bStopAll = false);
	virtual bool StartServer(LPCTSTR szHostServerIP, LPCTSTR szPort,LPCTSTR szDestRoutingAddress = NULL, LPCTSTR szDestRoutingPort  = NULL,LPCTSTR szLocalRoutingAddress = NULL,  DWORD dwPortType = SOCK_STREAM);
	void PickNextAvailable();
	static bool InitializeWinsock();
	static void UnInitializeWinsock();
	TCHAR m_szServerPort[MAX_PATH];
	CSocketComm *m_arrSocketComm;
	CSocketComm m_SockClient;
	CSocketComm* m_pCurServer;
	TCHAR m_szDestIPAddr[MAX_PATH];

	bool Connect(LPCTSTR strDestination, LPCTSTR strServiceName, int nProtocol, int nType, LPCTSTR szLocalIPAddress = NULL);
	bool SendData(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout = SOCKET_TIMEOUT);
	bool ReadData(LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout, MA_Message_Info eMsgInfo = MA_Control_Header);
	bool SendFile(LPCTSTR szFileName,LPCTSTR szDestinationFolder, MA_File_Types eFileType,bool bOverwriteExisting = false);
	bool SendFolder(LPCTSTR szFolderName,LPCTSTR szDestinationFolder, MA_File_Types eFileType);
	bool UpdateDownloadTaskDBStatus(DWORD dwDownloadID, MA_Download_Task_Status eDownloadTaskStatus);
protected:
	void DisplayData(const LPBYTE lpData, DWORD dwCount, const SockAddrIn& sfrom);
	static bool m_bWSInitialized;
	bool m_bServer;
	bool m_bShutdown;
	bool m_bSmartAddressing;
	CallBackFunctionPtr			m_fnPtrCallBack;
private:
	void ProcessAlert(LPMA_CONTROL_REQUEST lpControlRequest, CSocketComm *lpSocketComm);
	DWORD	m_dwPacketSize;
	TCHAR m_szHostIPAddress[MAX_PATH];
	TCHAR m_szDestRoutingAddress[MAX_PATH];
	TCHAR m_szDestRoutingPort[MAX_PATH];
	TCHAR m_szLocalIPAddr[MAX_PATH];
	MAControlVector m_vecBatchList;
	int m_nBatchMsgCount;
	static HANDLE m_hCriticalSectionSys;
	int m_nMaxServerConnections;
	MA_Application_Type m_eAppType;
	bool m_bFirstThread;
};

#endif // !defined(AFX_SOCKETMANAGER_H__7403BD71_338A_4531_BD91_3D7E5B505793__INCLUDED_)
