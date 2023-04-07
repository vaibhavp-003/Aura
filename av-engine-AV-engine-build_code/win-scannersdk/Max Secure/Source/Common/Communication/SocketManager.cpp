// SocketManager.cpp: implementation of the CSocketManager class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include <atlconv.h>
#include "SocketManager.h"
#include "SockStructures.h"
#include "MaxConstant.h"

#ifdef MAX_COMMAGENT
#include "CatalogDBManager.h"
#include "MaxCommAgentApp.h"
#include "BDMConstant.h"
#endif
 
#include "Logger.h"
#import "c:\program files\common files\system\ado\msado15.dll" no_namespace rename("EOF", "adoEOF")
#import "c:\windows\system32\cdosys.dll" rename_namespace("CDO") rename("EOF", "adoEOF")
#include "cdosysstr.h"
#include "cdosyserr.h"
#include <atlbase.h>

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#endif
const char* SMS_DISTRIBUTION_LIST					="9370511222@160by2.com";
const char* SMS_FROM								="";
const char* SMS_SUBJECT								="919881473351";
const char* SMTP_SERVER								="";
const int  SMTP_SERVER_PORT							=	25;
const char* SMTP_SEND_USERNAME						="";
const char* SMTP_PASSWORD							="testing";
const char* SMTP_ACCOUNT_NAME						="Alerts";
const char* SMTP_SEND_EMAIL_ADDRESS					="";


bool CSocketManager::m_bWSInitialized = false;
HANDLE CSocketManager::m_hCriticalSectionSys = NULL;
HANDLE CSocketManager::m_hCriticalSectionAlert = NULL;
static DWORD WINAPI ProcessAlertThread(LPVOID lpParameter);
	
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
bool CSocketManager::m_bMonitoringController = false;

void ShowPopup(CString csMsg);

CSocketManager::CSocketManager(CallBackFunctionPtr fnPtrCallBack, bool bRouter, DWORD dwPacketSize)
{
	m_bServer = false;
	m_bShutdown = false;
	m_pCurServer = NULL;
	m_bSmartAddressing = false;
	ZeroMemory(m_szServerPort,sizeof(m_szServerPort));
	ZeroMemory(m_szHostIPAddress,sizeof(m_szHostIPAddress));
	ZeroMemory(m_szDestRoutingAddress,sizeof(m_szDestRoutingAddress));
	ZeroMemory(m_szDestRoutingPort,sizeof(m_szDestRoutingPort));
	ZeroMemory(m_szLocalIPAddr,sizeof(m_szLocalIPAddr));
	ZeroMemory(m_szDestIPAddr,sizeof(m_szDestIPAddr));
	
	m_fnPtrCallBack = fnPtrCallBack;
	m_dwPacketSize = dwPacketSize;
	m_hShutdownEvent = NULL;
	m_nBatchMsgCount = 0;
	m_arrSocketComm = NULL;
	m_nMaxServerConnections = MAX_CONNECTION;
	m_eAppType = eSpyware_SnapShot;
	m_bFirstThread = true;

	if(CSocketManager::m_hCriticalSectionSys == NULL)
	{
		CSocketManager::m_hCriticalSectionSys = CreateEvent(NULL, FALSE, TRUE, NULL);
	}
	if(CSocketManager::m_hCriticalSectionAlert == NULL)
	{
		CSocketManager::m_hCriticalSectionAlert = CreateEvent(NULL, FALSE, TRUE, NULL);
	}
}

CSocketManager::~CSocketManager()
{
	if(m_hShutdownEvent)
	{
		::CloseHandle(m_hShutdownEvent);
		m_hShutdownEvent = NULL;
	}
	m_vecBatchList.clear();
	if(m_arrSocketComm)
	{
		delete [] m_arrSocketComm;
		m_arrSocketComm = NULL;
	}

	// Ignoring close handle for static handles
	//CSocketManager::m_hCriticalSectionSys;
	//CSocketManager::m_hCriticalSectionAlert;
}

void CSocketManager::SetPacketSize(DWORD dwPacketSize)
{
	m_dwPacketSize = dwPacketSize;
}
void CSocketManager::DisplayData(const LPBYTE lpData, DWORD dwCount, const SockAddrIn& sfrom)
{

}

bool CSocketManager::InitializeWinsock()
{
	if(false == m_bWSInitialized)
	{
		WSADATA		WSAData = { 0 };
		if ( ERROR_SUCCESS == WSAStartup( WSA_VERSION, &WSAData ) )
		{
			m_bWSInitialized = true;
		}
		else
		{
			//OutputDebugString(_T("***WSA Startup Failed"));
		}
	}
	
	return m_bWSInitialized;
}
void CSocketManager::UnInitializeWinsock()
{
	WSACleanup();
}
//ToDO:Darshit Optimize StartServer
bool CSocketManager::StartServer(LPCTSTR szHostServerIP,LPCTSTR szPort, LPCTSTR szDestRoutingAddress ,LPCTSTR szDestRoutingPort, LPCTSTR szLocalRoutingAddress, DWORD dwPortType)
{
	if(NULL == m_hShutdownEvent)
		m_hShutdownEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	
	if(NULL == m_arrSocketComm)
	{
		m_arrSocketComm = new CSocketComm[m_nMaxServerConnections];
		//Assigning the batch type for entire server
		if(_tcsicmp(szPort,MAX_CONTROLLER_MEDUSAPORT) == 0)
		{
			m_eAppType = eWhite_SnapShot;
			
		}
	}
	LPTSTR szHost = NULL;
	if((szHostServerIP != NULL) && (_tcslen(szHostServerIP) > 0))
	{
		if(_tcslen(szHostServerIP) > 0)
		{
			_tcscpy_s(m_szHostIPAddress,szHostServerIP);
		}
		szHost = m_szHostIPAddress;
	}
	
	m_bServer = true;
	m_bShutdown = false;
	m_bSmartAddressing = false;
	PickNextAvailable();
	bool bSuccess = false;
	if(szPort == NULL)
	{
		return false;
	}
	_tcscpy_s(m_szServerPort,MAX_PATH,szPort);
	if (m_pCurServer != NULL)
	{
		// no smart addressing - we use connection oriented
		m_pCurServer->SetServerState(true,this);
		m_pCurServer->SetSmartAddressing( false );
		m_pCurServer->SetPacketSize(m_dwPacketSize);
		bSuccess = m_pCurServer->CreateSocketEx( szHost,m_szServerPort, AF_INET, SOCK_STREAM, SO_REUSEADDR); // TCP
		if(!bSuccess)
		{
			g_objLogApp.AddLog(m_szHostIPAddress,m_szHostIPAddress,_T("***CreateSocketEx Failed for the server"));
			return bSuccess;
		}

		if (bSuccess && m_pCurServer->WatchComm())
		{
			TCHAR strServer[MAX_PATH] = {0}, strAddr[MAX_PATH] = {0},strMsg[MAX_PATH] = {0};
			m_pCurServer->GetLocalName( strServer, MAX_PATH);
			m_pCurServer->GetLocalAddress( strAddr, MAX_PATH);
			if(m_bFirstThread)
			{
				_stprintf_s(strMsg,_T("Server: %s , @Address:%s is running on port %s "),strServer, strAddr, m_szServerPort );
				m_bFirstThread = false;
			}
			else
			{
				_stprintf_s(strMsg,_T("Waiting For Next Connection..."));
			}
			//g_objLogApp.AddLog(m_szHostIPAddress,m_szHostIPAddress,strMsg);
		}
		else
		{
			//g_objLogApp.AddLog(m_szHostIPAddress,m_szHostIPAddress,_T("***WatchComm Failed for the server"));
		}
	}
	else
	{
		g_objLogApp.AddLog(m_szHostIPAddress,m_szHostIPAddress,_T("***No Connection Available!!!"));
	}

	return bSuccess;
}

void CSocketManager::PickNextAvailable()
{
	m_pCurServer = NULL;
	for(int i=0; i<m_nMaxServerConnections; i++)
	{
		if (!m_arrSocketComm[i].IsOpen())
		{
			m_pCurServer = &m_arrSocketComm[i];
			break;
		}
	}

	
}

///////////////////////////////////////////////////////////////////////////////
// OnDataReceived
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              This function is PURE Virtual, you MUST override it.  This is
//              called every time new data is available.
//				It is meant for Generic or Single thread processing
// PARAMETERS:
///////////////////////////////////////////////////////////////////////////////
bool CSocketManager::OnDataReceived(const LPBYTE lpBuffer, DWORD dwCount, CSocketComm *pSocketComm)
{
	//Will be called only for Single Threaded requests	
	//Always expect a Control Request Header
	if(NULL == pSocketComm)
	{
		g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***CSocketManager::OnDataReceived:pSocketComm NULL"));
		return false;
	}
	if(dwCount == SIZE_OF_MA_CONTROL_REQUEST)
	{
		LPMA_CONTROL_REQUEST lpControlRequest = (LPMA_CONTROL_REQUEST)lpBuffer;
#ifdef MAX_COMMAGENT
		//Get the COntrol Request Header and Process only if its a FIle Transder
		if(lpControlRequest && lpControlRequest->vt == eFILE_REGISTRATION_INFORMATION)
		{
			if(lpControlRequest->eMessageInfo == MA_Notify_Duplicate_Files)
			{
				m_nBatchMsgCount = lpControlRequest->dwMsgCount; 
				m_vecBatchList.clear();
				g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("MA_Notify_Duplicate_Files:%d"), m_nBatchMsgCount);
				return true;
			}
			if(lpControlRequest->eMessageInfo == MA_Check_Duplicate_Files)
			{
				m_vecBatchList.push_back(*lpControlRequest);
				if(m_vecBatchList.size() == m_nBatchMsgCount)
				{
					WaitForSingleObject(m_hCriticalSectionSys, INFINITE);
					{
						g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("Received Duplicate check items:%d"),m_nBatchMsgCount);
						CCatalogDBManager objDuplicateCatalog(true);
						if(objDuplicateCatalog.CheckDuplicate(m_vecBatchList))
						{
							g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("Sending Response for the Duplicates...."));
							for (MAControlVector::iterator it = m_vecBatchList.begin(); it != m_vecBatchList.end(); it++)
							{
								MA_CONTROL_REQUEST TempControlRequest = {0};
								memcpy(&TempControlRequest,&(*it),SIZE_OF_MA_CONTROL_REQUEST);
								if(!SendResponse((LPBYTE)&TempControlRequest,SIZE_OF_MA_CONTROL_REQUEST, pSocketComm))
								{
									g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***SendData Failed for Check Duplicates with Catalog "));
								}
							}
							m_nBatchMsgCount = 0;
							m_vecBatchList.clear();
						}
					}
					SetEvent(m_hCriticalSectionSys);
				}
			}
			if(lpControlRequest->eMessageInfo == MA_Notify_Register_Files)
			{
				m_nBatchMsgCount = lpControlRequest->dwMsgCount; 
				m_vecBatchList.clear();
				g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("MA_Notify_Register_Files:%d"), m_nBatchMsgCount);

				return true;
			}
			if(lpControlRequest->eMessageInfo == MA_Register_Files)
			{
				m_vecBatchList.push_back(*lpControlRequest);
				if(m_vecBatchList.size() == m_nBatchMsgCount)
				{
					WaitForSingleObject(m_hCriticalSectionSys, INFINITE);
					{
						g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("Received batch Registration items:%d"),m_nBatchMsgCount);
						CCatalogDBManager objRegisterCatalog(true);
						MA_CONTROL_REQUEST sBatchInfo = {0};
						sBatchInfo.vt = eBATCH_REGISTRATION_INFORMATION;
						sBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_BATCH_INFORMATION.wBatchType = m_eAppType;
						if(objRegisterCatalog.CreateBatch(m_vecBatchList,sBatchInfo))
						{
							g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("Batch sucessfully Created BatchID: %ld Batch Name:%s..."),sBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_BATCH_INFORMATION.dwBatchID,sBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_BATCH_INFORMATION.szBatchName);
							if(!SendResponse((LPBYTE)&sBatchInfo,SIZE_OF_MA_CONTROL_REQUEST,pSocketComm))
							{
								g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***SendData Failed for Check Duplicates with Catalog "));
								m_nBatchMsgCount = 0;
								m_vecBatchList.clear();
								SetEvent(m_hCriticalSectionSys);
								return false;
							}
						}
						else
						{
							sBatchInfo.vt = eBATCH_REGISTRATION_INFORMATION;
							sBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_BATCH_INFORMATION.dwBatchID = 0;
							sBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_VM_INFORMATION.dwVMID = 0;
							g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***Create Batch Failed "));
							if(!SendResponse((LPBYTE)&sBatchInfo,SIZE_OF_MA_CONTROL_REQUEST,pSocketComm))
							{
								g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***SendResponse Failed for Check Duplicates with Catalog "));
								m_nBatchMsgCount = 0;
								m_vecBatchList.clear();
								SetEvent(m_hCriticalSectionSys);
								return false;
							}
						}
						m_nBatchMsgCount = 0;
						m_vecBatchList.clear();
					}
					SetEvent(m_hCriticalSectionSys);
				}
			}
		}
		if(lpControlRequest && lpControlRequest->vt == eBATCH_REGISTRATION_INFORMATION)
		{
			if(lpControlRequest->eMessageInfo == MA_Assign_Queue_VM)
			{
				MA_Application_Type eAppType = eSpyware_SnapShot;
				if(lpControlRequest->BATCH_REGISTRATION_INFORMATION.sMA_VM_INFORMATION.dwApplicationType == 1)
				{
					eAppType = eWhite_SnapShot;
				}
				else
				{
					eAppType = eSpyware_SnapShot;
				}
				AssignQueueToVM(eAppType, lpControlRequest);
			}
			return true;
		}

		if(lpControlRequest && lpControlRequest->vt == eVM_INFORMATION)
		{
			if(lpControlRequest->eMessageInfo == MA_Update_VM_DiskSpace)
			{
				WaitForSingleObject(m_hCriticalSectionSys, INFINITE);
				{
					//g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("Updating MA_Update_VM_DiskSpace..."));
					CCatalogDBManager objVMCatalog(true);
					if(!objVMCatalog.UpdateVMDiskSpace(lpControlRequest))
					{
						g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***VM Update Status Failed"));
					}
				}
				SetEvent(m_hCriticalSectionSys);
			}

			if(lpControlRequest->eMessageInfo == MA_Assign_Queue_VM)
			{
				WaitForSingleObject(m_hCriticalSectionSys, INFINITE);
				{
					AssignQueueToRequestedVM(lpControlRequest);
				}
				SetEvent(m_hCriticalSectionSys);
			}
			return true;
		}

		if(lpControlRequest && lpControlRequest->vt == eBATCH_INFORMATION)
		{
			if(lpControlRequest->eMessageInfo == MA_Update_Batch_Status)
			{
				WaitForSingleObject(m_hCriticalSectionSys, INFINITE);
				{
					//g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("Updating MA_Update_Batch_Status..."));
					CCatalogDBManager objBatchCatalog(true);
					MA_CONTROL_REQUEST TempControlResponse = {0};
					TempControlResponse.vt = eCONTROL_INFORMATION;
					TempControlResponse.eMessageInfo = MA_Batch_Status_Updated;
					if(!objBatchCatalog.UpdateBatchStatus(lpControlRequest))
					{
						g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("Sending  MA_Batch_Status_Failed..."));
						TempControlResponse.eMessageInfo = MA_Batch_Status_Failed;
						if(!SendResponse((LPBYTE)&TempControlResponse,SIZE_OF_MA_CONTROL_REQUEST, pSocketComm))
						{
							g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***SendData Failed for MA_Batch_Status_Failed "));
						}
						SetEvent(m_hCriticalSectionSys);
						return false;
					}
					else
					{
						//g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("Sending  MA_Batch_Status_Updated..."));
						if(!SendResponse((LPBYTE)&TempControlResponse,SIZE_OF_MA_CONTROL_REQUEST, pSocketComm))
						{
							g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***SendData Failed for MA_Update_Batch_Status "));
						}

					}
					//g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("UpdateBatchStatus Successful....") );
				}
				SetEvent(m_hCriticalSectionSys);
			}
			return true;
		}

		if(lpControlRequest && lpControlRequest->vt == eDOWNLOAD_TASK_INFORMATION)
		{
			if(lpControlRequest->eMessageInfo == MA_Update_Download_Task_Status)
			{
				WaitForSingleObject(m_hCriticalSectionSys, INFINITE);
				{
					g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("Updating MA_Update_Download_Task_Status..."));
					CCatalogDBManager objBatchCatalog(true);
					if(!objBatchCatalog.UpdateDownloadTaskStatus(lpControlRequest))
					{
						g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***MA_Update_Download_Task_Status Failed"));
						SetEvent(m_hCriticalSectionSys);
						return false;
					}
				}
				SetEvent(m_hCriticalSectionSys);
			}

			if(lpControlRequest->eMessageInfo == MA_CreateDownloadTask)
			{
				WaitForSingleObject(m_hCriticalSectionSys, INFINITE);
				{
					g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("Updating MA_Update_Download_Task_Status..."));
					CCatalogDBManager objBatchCatalog(true);
					if(!objBatchCatalog.CreateDownloadTask(lpControlRequest))
					{
						g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***MA_CreateDownloadTask Failed"));
						SetEvent(m_hCriticalSectionSys);
						return false;
					}
				}
				SetEvent(m_hCriticalSectionSys);
			}
		}
#endif
		if(lpControlRequest && lpControlRequest->vt == eCONTROL_INFORMATION)
		{
			if(lpControlRequest->eMessageInfo == MA_Generate_Alert)
			{
				g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***Received Generate Alert"));
				ProcessAlert(lpControlRequest,pSocketComm);
				return true;
			}
			if(lpControlRequest->eMessageInfo == MA_WatchDog_Register_Node)
			{
				//Generating Alert To be displayed on Controller
				pSocketComm->SetMonitoring(lpControlRequest->bMonitorConnection);
				return true;
			}

			if(lpControlRequest->eMessageInfo == MA_WatchDog_Register_Controller)
			{
				//Generating Alert To be displayed on Controller
				pSocketComm->SetMonitoring(lpControlRequest->bMonitorConnection);
				g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("Controller Got registered..."));
				m_bMonitoringController = lpControlRequest->bMonitorConnection;
				return true;
			}
		}
		if(m_fnPtrCallBack)
		{
			m_fnPtrCallBack(lpBuffer,dwCount);
		}
	}
	return true;
}


///////////////////////////////////////////////////////////////////////////////
// OnEvent
///////////////////////////////////////////////////////////////////////////////
// DESCRIPTION:
//              This function reports events & errors
// PARAMETERS:
//      UINT uEvent: can be one of the event value EVT_(events)
//      LPVOID lpvData: Event data if any
///////////////////////////////////////////////////////////////////////////////
void CSocketManager::OnEvent(UINT uEvent, LPVOID lpvData,CSocketComm *pSocketComm)
{
	switch( uEvent )
	{
		case EVT_CONSUCCESS:
			if(!m_bShutdown)
			{
				//g_objLogApp.AddLog( _T("Connection Established") );
				//TODO:Darshit
				StartServer(m_szHostIPAddress,m_szServerPort);
			}
			break;
		case EVT_CONFAILURE:
		case EVT_CONDROP:
			if(!m_bShutdown)
			{
				//g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr, _T("Connection Closed"));
				if(pSocketComm->IsMonitoring())
				{
					g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr, _T("!!!Node Disconnect"));
					MA_CONTROL_REQUEST sWDRequest = {0};
					sWDRequest.vt = eCONTROL_INFORMATION;
					sWDRequest.bMonitorConnection = true;
					if(m_bMonitoringController)
					{
						sWDRequest.eMessageInfo = MA_WatchDog_Controller_Down;
						_tcscpy_s(sWDRequest.szDescription,_T("!!!Controller Down!!!"));
					}
					else
					{
						sWDRequest.eMessageInfo = VM_WatchDog_Node_Down;
						_tcscpy_s(sWDRequest.szDescription,_T("!!!Node Down!!!"));
						_tcscpy_s(sWDRequest.m_szPeerName,pSocketComm->m_szPeerIPAddr);
						if(pSocketComm->m_pSocketCallBack)
						{
							pSocketComm->m_pSocketCallBack->OnDataReceived((LPBYTE)&sWDRequest,SIZE_OF_MA_CONTROL_REQUEST,pSocketComm);
						}
					}
					sWDRequest.bFlashAlert = true;
#ifdef MAX_COMMAGENT				
					ProcessAlert(&sWDRequest,pSocketComm);
#endif
				}
				if(pSocketComm)
				{
					pSocketComm->StopComm();
				}

				if (m_pCurServer == NULL)
				{
					//TODO:Darshit
					StartServer(m_szHostIPAddress,m_szServerPort);
				}
			}
			
			
			
			break;
		case EVT_ZEROLENGTH:
			g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr, _T("Zero Length Message") );
			break;
		case EVT_SHUTDOWN:
			if(m_hShutdownEvent)
			{
				SetEvent(m_hShutdownEvent);
			}
			g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,L"Shutdown Client Event\n");
			break;
		default:
			g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,L"Unknown Socket event\n");
			break;
	}
}

bool  CSocketManager::SendResponse(const LPBYTE lpBuffer, DWORD dwCount, CSocketComm *pSocketComm)
{
	bool bRet = false;
	DWORD dwBytes = (DWORD)-1L;
	if(pSocketComm)
	{
		dwBytes = pSocketComm->WriteComm(lpBuffer,dwCount,SOCKET_TIMEOUT);
	}
	
	if (dwBytes == (DWORD)-1L)
	{
		g_objLogApp.AddLog(m_szHostIPAddress,pSocketComm->m_szPeerIPAddr,_T("***SendResponse Failed..."));
		bRet = false;
	}
	else
	{
		bRet = true;
	}
	return bRet;
}

void CSocketManager::StopComm(bool bStopAll)
{
	if(!m_bServer)
	{
		m_SockClient.StopComm();
		return;
	}
	if(bStopAll)
	{
		m_bShutdown = true;
	}

	for(int i=0; i<m_nMaxServerConnections; i++)
	{
		if(bStopAll)
		{
			m_arrSocketComm[i].StopComm();

		}
		else
		{
			if ((m_arrSocketComm[i].GetThreadId() == GetCurrentThreadId()))
			{
				m_arrSocketComm[i].StopComm();
				break;
			}
		}
	}	
}

bool CSocketManager::Connect(LPCTSTR strDestination, LPCTSTR strServiceName, int nProtocol, int nType, LPCTSTR szLocalIPAddress)
{
	bool bRet = false;
	m_bServer = false;
	if(m_hShutdownEvent)
	{
		CloseHandle(m_hShutdownEvent);
		m_hShutdownEvent = NULL;
	}
	
	
	m_SockClient.SetServerState(false,this);
	m_SockClient.SetSmartAddressing( false );
	m_SockClient.SetPacketSize(m_dwPacketSize);
	_tcscpy_s(m_szDestIPAddr,strDestination);
	if(m_SockClient.ConnectTo(strDestination, strServiceName,nProtocol,nType,szLocalIPAddress))
	{
		//g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("Client:Connection Established with Server: %s"),strDestination);
		bRet = true;
	}
	return bRet;
}

//Only Used for Client App
bool CSocketManager::SendData(const LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout)
{
	bool bRet = true;
	DWORD dwBytes = 0;
	dwBytes = m_SockClient.WriteComm(lpBuffer,dwCount,dwTimeout);
	if (dwBytes == (DWORD)-1L)
	{
		bRet = false;
	}
	return bRet;
}

bool CSocketManager::ReadData(LPBYTE lpBuffer, DWORD dwCount, DWORD dwTimeout, MA_Message_Info eMsgInfo)
{
	bool bRet = true;
	DWORD dwBytes = 0;
	m_SockClient.SetCurrentState(eMsgInfo);
	dwBytes = m_SockClient.ReadComm(lpBuffer,dwCount,dwTimeout);
	if (dwBytes == (DWORD)-1L)
	{
		bRet = false;
	}
	return bRet;
}

bool CSocketManager::SendFile(LPCTSTR szFileName, LPCTSTR szDestinationFolder, MA_File_Types eFileType, bool bOverwriteExisting)
{
	bool bRet = false;
	if(!m_bServer)
	{
		bRet = m_SockClient.SendFile(szFileName,szDestinationFolder, eFileType,bOverwriteExisting);
	}
	if(!bRet)
	{
		g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("***File Send Failed for %s"), szFileName);
	}
	return bRet;
}


bool CSocketManager::SendFolder(LPCTSTR szFolderName,LPCTSTR szDestinationFolder, MA_File_Types eFileType)
{
	bool bRet = false;
	WIN32_FIND_DATA ffd = {0};
	LARGE_INTEGER filesize;
	TCHAR szDir[MAX_PATH]={0};
	TCHAR szFileName[MAX_PATH]={0};
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError=0;
	_tcscpy_s(szDir,szFolderName);
	_tcscat_s(szDir,_T("\\*.*"));
	hFind = FindFirstFile(szDir, &ffd);
	int nFileCount = 0;
	if (INVALID_HANDLE_VALUE == hFind) 
	{
		return bRet;
	} 

	// List all the files in the directory with some info about them.

	do
	{
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,TEXT("Skipping Directory: %s"), ffd.cFileName);
		}
		else
		{
			filesize.LowPart = ffd.nFileSizeLow;
			filesize.HighPart = ffd.nFileSizeHigh;
			g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,TEXT("Sending File:%s %ld bytes"), ffd.cFileName, filesize.QuadPart);
			_tcscpy_s(szFileName,szFolderName);
			_tcscat_s(szFileName,_T("\\"));
			_tcscat_s(szFileName,ffd.cFileName);
			if(!SendFile(szFileName,szDestinationFolder, eFileType))
			{
				g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("***File Send Failed for %s"), ffd.cFileName);
				FindClose(hFind);
				return false;
			}
			nFileCount++;
		}
	}
	while (FindNextFile(hFind, &ffd) != 0);
	g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("Total Files Send Successfully %d"), nFileCount);
	FindClose(hFind);

	return true;
}

bool CSocketManager::CheckDuplicateswithCataLog(MAControlVector &vecList)
{
	bool bRet = false;
	int nVecLen = vecList.size();
	MA_CONTROL_REQUEST sControlRequest = {0};
	sControlRequest.eMessageInfo = MA_Notify_Duplicate_Files;
	sControlRequest.vt = eFILE_REGISTRATION_INFORMATION;
	sControlRequest.dwMsgCount = nVecLen;
	if(SendData((LPBYTE)&sControlRequest,SIZE_OF_MA_CONTROL_REQUEST))
	{
		for (MAControlVector::iterator it = vecList.begin(); it != vecList.end(); it++)
		{
			MA_CONTROL_REQUEST *TempControlRequest = &(*it);
			TempControlRequest->eMessageInfo = MA_Check_Duplicate_Files;
			if(!SendData((LPBYTE)TempControlRequest,SIZE_OF_MA_CONTROL_REQUEST))
			{
				g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("***SendData Failed for Check Duplicates with Catalog "));
				return false;
			}
		}
		//Wait for the Entire List
		for (MAControlVector::iterator iter = vecList.begin(); iter != vecList.end(); iter++)
		{
			MA_CONTROL_REQUEST *TempControlRequest = &(*iter);
			MA_CONTROL_REQUEST sControlResponse = {0};
			if(!ReadData((LPBYTE)&sControlResponse,SIZE_OF_MA_CONTROL_REQUEST,SOCKET_TIMEOUT))
			{
				g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("***ReadData Failed for Check Duplicates with Catalog "));
				return false;
			}
			TempControlRequest->FILE_REGISTRATION_INFORMATION.sMA_FILE_INFORMATION.bDuplicate = sControlResponse.FILE_REGISTRATION_INFORMATION.sMA_FILE_INFORMATION.bDuplicate;
		}
		bRet = true;
		g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("Check Duplicates completed for %d Items"),nVecLen);
	}
	
	if(false == bRet)
	{
		g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("***Check Duplicates with Catalog Failed"));
	}
	return bRet;
}

bool CSocketManager::RegisterBatchWithCataLog(MAControlVector &vecList,MA_CONTROL_REQUEST &objBatchInfo)
{
	bool bRet = false;
	int nVecLen = vecList.size();
	MA_CONTROL_REQUEST sControlRequest = {0};
	sControlRequest.vt = eFILE_REGISTRATION_INFORMATION;
	sControlRequest.eMessageInfo = MA_Notify_Register_Files;
	sControlRequest.dwMsgCount = nVecLen;
	if(SendData((LPBYTE)&sControlRequest,SIZE_OF_MA_CONTROL_REQUEST))
	{
		for (MAControlVector::iterator it = vecList.begin(); it != vecList.end(); it++)
		{
			MA_CONTROL_REQUEST *TempControlRequest = &(*it);
			TempControlRequest->eMessageInfo = MA_Register_Files;
			if(!SendData((LPBYTE)TempControlRequest,SIZE_OF_MA_CONTROL_REQUEST))
			{
				g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("***SendData Failed for RegisterBatchWithCataLog "));
				return false;
			}
		}
		//Wait for the BatchID 
		MA_CONTROL_REQUEST sControlResponse = {0};
		sControlResponse.vt = eBATCH_REGISTRATION_INFORMATION;
		if(!ReadData((LPBYTE)&objBatchInfo,SIZE_OF_MA_CONTROL_REQUEST,SOCKET_TIMEOUT))
		{
			g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("***ReadData Failed for RegisterBatchWithCataLog "));
			return false;
		}
		bRet = true;
		g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("Batch ID Generated  Successfully:BatchID %ld BatchItems: %d"),objBatchInfo.MA_BATCH_INFORMATION.dwBatchID,nVecLen);
	}

	if(false == bRet)
	{
		g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("***Check Duplicates with Catalog Failed"));
	}

	return bRet;
}

bool CSocketManager::UpdateControlStatus(MA_CONTROL_REQUEST &objControlRequest)
{
	bool bRet = false;
	DWORD dwBytes = 0;
	dwBytes = m_SockClient.WriteComm((LPBYTE)&objControlRequest,SIZE_OF_MA_CONTROL_REQUEST,SOCKET_TIMEOUT);
	
	if (dwBytes == (DWORD)-1L)
	{
		g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("***Updating Control Status.Failed.."));
	}
	else
	{
		if(objControlRequest.eMessageInfo == MA_Update_Batch_Status)
		{
			//wait for Response
			MA_CONTROL_REQUEST sControlResponse = {0};
			sControlResponse.vt = eCONTROL_INFORMATION;
			if(!ReadData((LPBYTE)&sControlResponse,SIZE_OF_MA_CONTROL_REQUEST,SOCKET_TIMEOUT))
			{
				g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("***ReadData Failed for UpdateControlStatus "));
				return false;
			}
			if(sControlResponse.eMessageInfo == MA_Batch_Status_Updated)
			{
				g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("MA_Batch_Status_Updated Successful"));
				bRet = true;
			}
			else
			{
				g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("*** Received MA_Batch_Status_Failed "));
			}

		}
		else
		{
			bRet = true;
		}
	}
	return bRet;
}

void CSocketManager::SendAlert(LPCTSTR szDescription,bool bDisplay)
{
	g_objLogApp.AddLog(m_SockClient.m_szLogLocalIPAddr,m_SockClient.m_szPeerIPAddr,_T("Sending Alert!!!...%s"),szDescription);
	DWORD dwBytes = 0;
	MA_CONTROL_REQUEST sAlertRequest = {0};
	sAlertRequest.vt = eCONTROL_INFORMATION;
	sAlertRequest.eMessageInfo = MA_Generate_Alert;
	_tcscpy_s(sAlertRequest.szDescription, szDescription);
	sAlertRequest.bFlashAlert = bDisplay;
	dwBytes = m_SockClient.WriteComm((LPBYTE)&sAlertRequest,SIZE_OF_MA_CONTROL_REQUEST,ROUTING_TIMEOUT);
	if (dwBytes == (DWORD)-1L)
	{
		printf("Write bytes failed\r\n");
	}
}

DWORD WINAPI ProcessAlertThread(LPVOID lpParameter)
{
	if(NULL == lpParameter)
	{
		return 0;
	}
	HRESULT hr = CoInitialize(NULL);
	COINITIALIZE_OUTPUTDEBUGSTRING(hr);
	{
		LPMA_CONTROL_REQUEST lpTempControlRequest = (LPMA_CONTROL_REQUEST)lpParameter;
		if(lpTempControlRequest)
		{
			g_objLogApp.AddLog(0,lpTempControlRequest->m_szPeerName,_T("***!!!Automation Alert!!!%s"),lpTempControlRequest->szDescription);
			if(lpTempControlRequest->bFlashAlert)
			{
				::MessageBeep(MB_ICONERROR);
				TCHAR szMsg[MAX_PATH] = {0};
				_stprintf_s(szMsg,_T("!!!%s:"),lpTempControlRequest->m_szPeerName);
				_tcscat_s(szMsg,lpTempControlRequest->szDescription);
				g_objLogApp.AddLog(0,lpTempControlRequest->m_szPeerName,szMsg);
				//Route the message to SMS Gateway
				CSocketManager objSMSAlert;
				bool bSuccess = false;
				if(CSocketManager::m_bMonitoringController)
				{
					g_objLogApp.AddLog(0,lpTempControlRequest->m_szPeerName,_T("***!!!Sending SMS !!!%s"),lpTempControlRequest->szDescription);
					CSocketManager::SendAutomationSMSAlert(lpTempControlRequest->szDescription);
					//::MessageBox(HWND_DESKTOP,szMsg,MAX_AUTOMATION_ALERT,MB_OK);
				}
				else
				{
//#ifndef _DEBUG
					bSuccess = objSMSAlert.Connect(SMS_GATEWAY,SMS_GATEWAY_PORT, AF_INET, SOCK_STREAM,CONTROLLER_LOCAL_MEDUSA_IPADDR);
//#endif
				}
				if(bSuccess)
				{
					g_objLogApp.AddLog(0,lpTempControlRequest->m_szPeerName,_T("!!!Connected to SMS Gateway Sending SMS......"));
					objSMSAlert.SendAlert(szMsg,true);
				}
				//::MessageBox(HWND_DESKTOP,szMsg,MAX_AUTOMATION_ALERT,MB_OK);
			}

		}
		HeapFree(GetProcessHeap(),0,lpTempControlRequest);
	}
	CoUninitialize();
	return 0;
}

void CSocketManager::RegisterWithWatchDog(bool bMonitor)
{
	DWORD dwBytes = 0;
	MA_CONTROL_REQUEST sWDRequest = {0};
	sWDRequest.vt = eCONTROL_INFORMATION;
	sWDRequest.bMonitorConnection = bMonitor;
	sWDRequest.eMessageInfo = MA_WatchDog_Register_Node;
	dwBytes = m_SockClient.WriteComm((LPBYTE)&sWDRequest,SIZE_OF_MA_CONTROL_REQUEST,ROUTING_TIMEOUT);
	if (dwBytes == (DWORD)-1L)
	{
		g_objLogApp.AddLog1(L"***Registering with Watchdog failed\r\n");
	}
}

void CSocketManager::RegisterControllerWithGateway(bool bMonitor)
{
	DWORD dwBytes = 0;
	MA_CONTROL_REQUEST sWDRequest = {0};
	sWDRequest.vt = eCONTROL_INFORMATION;
	sWDRequest.bMonitorConnection = bMonitor;
	sWDRequest.eMessageInfo = MA_WatchDog_Register_Controller;
	dwBytes = m_SockClient.WriteComm((LPBYTE)&sWDRequest,SIZE_OF_MA_CONTROL_REQUEST,ROUTING_TIMEOUT);
	if (dwBytes == (DWORD)-1L)
	{
		printf("***Registering with Watchdog failed\r\n");
	}
}


void CSocketManager::ProcessAlert(LPMA_CONTROL_REQUEST lpControlRequest, CSocketComm *lpSocketComm)
{
	//Generating Alert To be displayed on Controller
	LPMA_CONTROL_REQUEST lpTempControlRequest =  (LPMA_CONTROL_REQUEST)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,SIZE_OF_MA_CONTROL_REQUEST);
	memcpy_s(lpTempControlRequest,SIZE_OF_MA_CONTROL_REQUEST,lpControlRequest,SIZE_OF_MA_CONTROL_REQUEST);
	TCHAR szPeerName[DEFAULT_FIELD_SIZE] = {0};
	if(lpSocketComm)
		lpSocketComm->GetPeerName(szPeerName,DEFAULT_FIELD_SIZE);
	_tcscpy_s(lpTempControlRequest->m_szPeerName,DEFAULT_FIELD_SIZE,szPeerName);
	DWORD dwThreadId = 0;
	HANDLE hProcessAlertThread = NULL;        // Dispatch thread for handing window messages
	hProcessAlertThread = CreateThread(NULL, 0, ProcessAlertThread, (LPVOID)lpTempControlRequest, 0, &dwThreadId); 
	if(hProcessAlertThread)
	{
		::CloseHandle(hProcessAlertThread);
	}
}

void CSocketManager::EnableRouting(LPCTSTR szDestRoutingAddress ,LPCTSTR szDestRoutingPort, LPCTSTR szLocalRoutingIP)
{
	m_SockClient.EnableRouting(szDestRoutingAddress,szDestRoutingPort,szLocalRoutingIP);
}

void CSocketManager::SendAutomationSMSAlert(LPCTSTR szMsg)
{
	HRESULT hr = S_OK;
	WaitForSingleObject(m_hCriticalSectionAlert, INFINITE);
	try
	{
		CDO::IMessagePtr pMail = NULL;
		hr = pMail.CreateInstance(__uuidof(CDO::Message));
		COCREATE_OUTPUTDEBUGSTRING(hr);
		pMail->put_To(_bstr_t(SMS_DISTRIBUTION_LIST));
		pMail->put_From(_bstr_t(SMS_FROM));
		pMail->put_Subject(_bstr_t(SMS_SUBJECT));
		pMail->put_TextBody(_bstr_t(szMsg));
		CDO::IConfigurationPtr pConfig(__uuidof(CDO::Configuration));
		FieldsPtr pFields	 = pConfig->GetFields();
		pFields->Item["http://schemas.microsoft.com/cdo/configuration/smtpserver"]->Value = _variant_t(SMTP_SERVER);	
		pFields->Item["http://schemas.microsoft.com/cdo/configuration/smtpserverport"]->Value = _variant_t((long)SMTP_SERVER_PORT);
		pFields->Item["http://schemas.microsoft.com/cdo/configuration/sendusing"]->Value = _variant_t(2);
		pFields->Item["http://schemas.microsoft.com/cdo/configuration/sendusername"]->Value = _variant_t(SMTP_SEND_USERNAME);	
		pFields->Item["http://schemas.microsoft.com/cdo/configuration/sendpassword"]->Value = _variant_t(SMTP_PASSWORD);
		pFields->Item["http://schemas.microsoft.com/cdo/configuration/smtpaccountname"]->Value = _variant_t(SMTP_ACCOUNT_NAME);
		pFields->Item["http://schemas.microsoft.com/cdo/configuration/sendemailaddress"]->Value = _variant_t(SMTP_SEND_EMAIL_ADDRESS);
		pFields->Item["http://schemas.microsoft.com/cdo/configuration/smtpauthenticate"]->Value = _variant_t((long)1);
		pFields->Update();

		pMail->Configuration	= pConfig;
		hr = pMail->Send();
		g_objLogApp.AddLog1(_T("***!!!Successfully Sent SMS !!!"));
	}
	catch(_com_error &e)
	{
		_bstr_t bstrDescription(e.Description());
		g_objLogApp.AddLog1(_T("***!!!Exception in Sending SMS:%s !!!"),bstrDescription );
	}
	SetEvent(m_hCriticalSectionAlert);
}

bool CSocketManager::AssignQueueToVM(MA_Application_Type eAppType, LPMA_CONTROL_REQUEST lpControlRequest)
{
	bool bRet = false;
#ifdef MAX_COMMAGENT
	WaitForSingleObject(m_hCriticalSectionSys, INFINITE);
	g_objLogApp.AddLog1(_T("Assigning VM Ids to Pending batches....") );
	{
		MAControlVectorPtr vecVMPtr;
		CCatalogDBManager objBatchCatalog(true);
		if(!objBatchCatalog.GetVMInfoforExistingBatches(vecVMPtr, eAppType))
		{
			g_objLogApp.AddLog1(_T("***GetVMInfoforExistingBatches Failed"));
		}
		g_objLogApp.AddLog1(_T("GetVMInfoforExistingBatches Successful....%d Items"),vecVMPtr.size());
		g_objLogApp.AddLog1(_T("Assigning %d Queue Items.."),vecVMPtr.size());
		if(vecVMPtr.size() > 0)
		{
			CString csPath;
			GetModuleFileName(0, csPath.GetBuffer(MAX_PATH), MAX_PATH);
			csPath.ReleaseBuffer();
			int iPos = csPath.ReverseFind('\\');
			csPath = csPath.Left(csPath.ReverseFind('\\'));
			csPath += L"\\Queue";

			for (MAControlVectorPtr::iterator it = vecVMPtr.begin(); it != vecVMPtr.end(); it++)
			{
				LPMA_CONTROL_REQUEST lpBatchInfo = (*it);
				lpBatchInfo->eMessageInfo = MA_Assign_Queue_VM;
				if(eBATCH_REGISTRATION_INFORMATION == lpBatchInfo->vt)
				{
					g_objLogApp.AddLog1(_T("Assign Queue Item! Batch Name: %s, Node IP: %s, VM IP: %s"), 
						lpBatchInfo->BATCH_REGISTRATION_INFORMATION.sMA_BATCH_INFORMATION.szBatchName, 
						lpBatchInfo->BATCH_REGISTRATION_INFORMATION.sMA_NODE_INFORMATION.szNodeIPAddress, 
						lpBatchInfo->BATCH_REGISTRATION_INFORMATION.sMA_VM_INFORMATION.szIPAddress);

					TCHAR szFilePath[MAX_PATH] = {0};
					_tcscpy_s(szFilePath, csPath);
					_tcscat_s(szFilePath, _T("\\"));
					_tcscat_s(szFilePath, lpBatchInfo->BATCH_REGISTRATION_INFORMATION.sMA_BATCH_INFORMATION.szBatchName);
					_tcscat_s(szFilePath, _T(".zip"));

					if(_waccess(szFilePath, 0) == 0)
					{
						AssignBatchToVM(szFilePath, *lpBatchInfo, true);
					}
				}
				bRet = true;
			}
			g_objLogApp.AddLog1(_T("Total batches sent %d.."),vecVMPtr.size());
			for (MAControlVectorPtr::iterator it = vecVMPtr.begin(); it != vecVMPtr.end(); it++)
			{
				LPMA_CONTROL_REQUEST lpBatchInfo = (*it);
				if(lpBatchInfo)
				{
					delete lpBatchInfo;
				}
			}
			vecVMPtr.clear();
		}
		else
		{
			bRet = false;
		}
	}
#endif
	SetEvent(m_hCriticalSectionSys);
	return bRet;
}

bool CSocketManager::UpdateDownloadTaskDBStatus(DWORD dwDownloadID, MA_Download_Task_Status eDownloadTaskStatus)
{
	bool bRet = false;
#ifdef MAX_COMMAGENT
	WaitForSingleObject(m_hCriticalSectionSys, INFINITE);
	{
		MA_CONTROL_REQUEST objUrlInfo = {0};
		objUrlInfo.vt = eDOWNLOAD_TASK_INFORMATION;
		objUrlInfo.eMessageInfo = MA_Update_Download_Task_Status;
		objUrlInfo.DOWNLOAD_TASK_INFORMATION.sMA_Download_Task.dwDownloadID = dwDownloadID;
		objUrlInfo.DOWNLOAD_TASK_INFORMATION.sMA_Download_Task.wStatus = eDownloadTaskStatus;
		CCatalogDBManager objCatalog(true);
		bRet = objCatalog.UpdateDownloadTaskStatus(&objUrlInfo);
	}
	SetEvent(m_hCriticalSectionSys);
#endif
	return bRet;
}

bool CSocketManager::AssignBatchToVM(const wchar_t *strFileName, MA_CONTROL_REQUEST &oBatchInfo, bool bFromQueue)
{
#ifdef MAX_COMMAGENT
	CString csPath;
	GetModuleFileName(0, csPath.GetBuffer(MAX_PATH), MAX_PATH);
	csPath.ReleaseBuffer();
	int iPos = csPath.ReverseFind('\\');
	csPath = csPath.Left(csPath.ReverseFind('\\'));
	csPath += L"\\Queue";

	if(oBatchInfo.vt != eBATCH_REGISTRATION_INFORMATION)
		return false;

	if(_waccess(strFileName, 0))
	{
		g_objLogApp.AddLog1(_T("File Already Transfered: %s"), strFileName);
		return true;
	}

	wchar_t strDestinationFolder[MAX_PATH] = {0};

	_tcscpy_s(strDestinationFolder, MAX_PATH, oBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_NODE_INFORMATION.szPartitionName);
	_tcscat_s(strDestinationFolder, MAX_PATH, _T("\\VMSetting\\"));
	_tcscat_s(strDestinationFolder, MAX_PATH, oBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_VM_INFORMATION.szIPAddress);
	if(oBatchInfo.dwPriority == 1)
		_tcscat_s(strDestinationFolder, MAX_PATH, _T("\\Priority"));
	else
		_tcscat_s(strDestinationFolder, MAX_PATH, _T("\\Input"));

	CSocketManager * sockMgr = new CSocketManager(NULL,false);
	CSocketManager::InitializeWinsock();

	bool bSuccess = sockMgr->Connect(oBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_NODE_INFORMATION.szNodeIPAddress,
		VM_HANDLER_SERVER_PORT, AF_INET, SOCK_STREAM,NULL); // TCP

	if(false == bSuccess)
	{
		CString csAlert;
		csAlert.Format(_T("Controller: Unable to connect to Node: %s"),oBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_NODE_INFORMATION.szNodeIPAddress);
		ShowPopup(csAlert);
		delete sockMgr;
		return false;
	}
	oBatchInfo.eMessageInfo = MA_Notify_VM_BatchInfo;
	if(false == sockMgr->UpdateControlStatus(oBatchInfo))
	{
		ShowPopup(L"UpdateControlStatus for MA_Notify_VM_BatchInfo failed");
		sockMgr->StopComm(false);
		delete sockMgr;
		return false;
	}

	g_objLogApp.AddLog1(_T("Assign to- Node :%s, VM: %s"), oBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_NODE_INFORMATION.szNodeIPAddress, oBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_VM_INFORMATION.szIPAddress);
	g_objLogApp.AddLog1(_T("Send File: %s"), strFileName);
	if(false == sockMgr->SendFile(strFileName, strDestinationFolder, eBatch_File))
	{
		sockMgr->StopComm(false);
		delete sockMgr;

		CString csErr;
		csErr.Format(_T("Unable to send file : %s"), strFileName);
		g_objLogApp.AddLog1(csErr);
		ShowPopup(csErr);
		if(false == bFromQueue)
		{
			//MoveFile to queue folder
			wchar_t cMoveToFullFileName[MAX_PATH] = {0};
			wsprintf(cMoveToFullFileName, L"%s\\%s.zip", csPath, oBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_BATCH_INFORMATION.szBatchName);
			MoveFile(strFileName , cMoveToFullFileName );
			DeleteFile(strFileName);
		}
		return false;
	}

	//MoveFile to Assigned folder
	wchar_t cMoveToFullFileName[MAX_PATH] = {0};
	wsprintf(cMoveToFullFileName, L"%s\\Vendor\\%s.zip", csPath, oBatchInfo.BATCH_REGISTRATION_INFORMATION.sMA_BATCH_INFORMATION.szBatchName);
	MoveFile(strFileName , cMoveToFullFileName );
	DeleteFile(strFileName);

	sockMgr->StopComm(false);
	delete sockMgr;
#endif
	return true;
}

UINT ShowPopupThread(LPVOID lpVoid)
{
	CString* pcsMsg = (CString*)lpVoid;
	CString csMsg = *pcsMsg;
	delete pcsMsg;
	pcsMsg = NULL;
	OutputDebugString(csMsg);

	return 0; //AfxMessageBox(csMsg);
}

void ShowPopup(CString csMsg)
{
	CString* pcsMsg = new CString(csMsg);
	AfxBeginThread(ShowPopupThread, pcsMsg);
}

bool CSocketManager::AssignQueueToRequestedVM(LPMA_CONTROL_REQUEST lpControlRequest)
{
#ifdef MAX_COMMAGENT
	bool bRet = false;

	if(!lpControlRequest)
		return bRet;
	if(lpControlRequest->vt != eVM_INFORMATION)
		return bRet;
	if(_tcslen(lpControlRequest->MA_VM_INFORMATION.szIPAddress) == 0)
		return bRet;

	g_objLogApp.AddLog1(_T("Assigning Batches to requested VM: %s"), lpControlRequest->MA_VM_INFORMATION.szIPAddress);
	{
		MAControlVectorPtr vecVMPtr;
		CCatalogDBManager objBatchCatalog(true);
		if(!objBatchCatalog.GetBatchesInQueue(vecVMPtr, lpControlRequest))
		{
			g_objLogApp.AddLog1(_T("***GetBatchesInQueue Failed"));
			return bRet;
		}
		g_objLogApp.AddLog1(_T("GetBatchesInQueue Successful With no of batches: %d"), vecVMPtr.size());
		if(vecVMPtr.size() > 0)
		{
			CString csPath;
			//GetModuleFileName(0, csPath.GetBuffer(MAX_PATH), MAX_PATH);
			//csPath.ReleaseBuffer();
			//int iPos = csPath.ReverseFind('\\');
			//csPath = csPath.Left(csPath.ReverseFind('\\'));
			csPath += L"F:\\BinaryDump\\Queue";

			for(MAControlVectorPtr::iterator it = vecVMPtr.begin(); it != vecVMPtr.end(); it++)
			{
				LPMA_CONTROL_REQUEST lpBatchInfo = (*it);
				lpBatchInfo->eMessageInfo = MA_Assign_Queue_VM;
				if(eBATCH_REGISTRATION_INFORMATION == lpBatchInfo->vt)
				{
					g_objLogApp.AddLog1(_T("Assign Queue Item! Batch Name: %s, Node IP: %s, VM IP: %s"), 
						lpBatchInfo->BATCH_REGISTRATION_INFORMATION.sMA_BATCH_INFORMATION.szBatchName, 
						lpBatchInfo->BATCH_REGISTRATION_INFORMATION.sMA_NODE_INFORMATION.szNodeIPAddress, 
						lpBatchInfo->BATCH_REGISTRATION_INFORMATION.sMA_VM_INFORMATION.szIPAddress);

					TCHAR szFilePath[MAX_PATH] = {0};
					_tcscpy_s(szFilePath, csPath);
					_tcscat_s(szFilePath, _T("\\"));
					_tcscat_s(szFilePath, lpBatchInfo->BATCH_REGISTRATION_INFORMATION.sMA_BATCH_INFORMATION.szBatchName);
					_tcscat_s(szFilePath, _T(".zip"));

					if(_waccess(szFilePath, 0) == 0)
					{
						AssignBatchToVM(szFilePath, *lpBatchInfo, true);
					}
				}
				bRet = true;
			}
			g_objLogApp.AddLog1(_T("Total batches sent %d.."),vecVMPtr.size());
			for(MAControlVectorPtr::iterator it = vecVMPtr.begin(); it != vecVMPtr.end(); it++)
			{
				LPMA_CONTROL_REQUEST lpBatchInfo = (*it);
				if(lpBatchInfo)
				{
					delete lpBatchInfo;
				}
			}
			vecVMPtr.clear();
		}
		else
		{
			bRet = false;
		}
	}
	return bRet;
#endif
	return true;
}