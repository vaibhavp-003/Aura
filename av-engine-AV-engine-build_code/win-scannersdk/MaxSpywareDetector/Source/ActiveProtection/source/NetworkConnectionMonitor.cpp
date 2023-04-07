/*======================================================================================
   FILE				: NetworkConnectionMonitor.cpp
   ABSTRACT			: This class will use to monitor network connection against database.
   DOCUMENTS		: Network Connection Monitor-Design Document.doc
   COPYRIGHT NOTICE:

				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				without the prior written permission of Aura.
   CREATION DATE	: 19-Jun-08
   AUTHOR			: Dipali Pawar.
   VERSION HISTORY	:
   REVISION HISTORY :	
						Resource: Dipali
						Date: 31-Dec-08
						Decsription: Added AddInLiveMonitorLog for SDEE
						Resource: Dipali
						Date: 28-Feb-09
						Decsription: Call Database read function from MaxUtils 
									instead of local function
======================================================================================*/
#include "pch.h"
#include "NetworkConnectionMonitor.h"
#include "SDSystemInfo.h"
//#include "ExcludeList.h"
#include "CPUInfo.h"
#include "EnumProcess.h"
#include "VerInfo.h"
#include "MaxConstant.h"
#include "MaxExceptionFilter.h"
#include "MaxDSrvWrapper.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

UINT StartNetworkConnectionMonitorThread(void* pParam);

//Default Constructor
CNetworkConnectionMonitor::CNetworkConnectionMonitor(void)
							:m_objNetConDB(false), m_objUserNetConDB(false)
{
	m_bUserNetDB = false;
	//m_pCapThread[NET_DEV_MAX] = 0;
	m_nCapCount = 0;
	//m_pDevList = NULL;
	m_hSingleScan = CreateEvent(NULL, FALSE, TRUE, NULL);
	m_pNetworkConnectionMonitorThread = NULL;
}

//Default Destructor
CNetworkConnectionMonitor::~CNetworkConnectionMonitor(void)
{
	WaitForSingleObject(m_hSingleScan, INFINITE); // Wait for the last event to finish its job!
	CloseHandle(m_hSingleScan);
	m_hSingleScan = NULL;

	if(m_pNetworkConnectionMonitorThread)
	{
		WaitForSingleObject(m_pNetworkConnectionMonitorThread->m_hThread, INFINITE);
		delete m_pNetworkConnectionMonitorThread;
		m_pNetworkConnectionMonitorThread = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: StartNetworkConnectionMonitorThread
	In Parameters	: void* pParam
	Out Parameters	: UINT
	Purpose			: Start 
	Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
UINT StartNetworkConnectionMonitorThread(void* pParam)
{
	__try
	{
		CNetworkConnectionMonitor *pThis = (CNetworkConnectionMonitor *) pParam;
		pThis->StartNetworkConnectionMonitor();
	}

	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),
		_T("Network Monitor Thread")))
	{

	}
	return 1;
}

/*-------------------------------------------------------------------------------------
	Function		: StartNetworkConnectionMonitor
	In Parameters	: -
	Out Parameters	: void
	Purpose			: 
	Author			: Dipali Pawar.
--------------------------------------------------------------------------------------*/
void CNetworkConnectionMonitor::StartNetworkConnectionMonitor()
{
	try
	{
		//OutputDebugString(_T("CNetworkConnectionMonitor::StartNetworkConnectionMonitor"));
		//if(!OpenDevice())
		//{
		//	return;
		//}
		//for(int i=0; i < m_nCapCount; i++) 
		//{
		//	// Create and start the thread
		//	m_pCapThread[i] = new CNetCapture(m_pCapDev[i]);
		//	m_pCapThread[i]->StartCapture(this);
		//}
		m_bStopNetMonitor = false;
		//bool keepcheck = true ;
		//PMIB_TCPTABLE_OWNER_PID pConnections;
		//DWORD dwSize = 0, iCnt = 0;
		//POSITION pos = NULL;
		//TCHAR szRemoteAddr[50] = {0};
		//TCHAR szProcName[1024] = {0};
		//TCHAR szImageName[MAX_PATH] = {0};
		//CFileVersionInfo objVerInfo;
		//CEnumProcess objEnumProc;

		//while(keepcheck)
		//{
		//	if(m_bStopNetMonitor)
		//	{
		//		break;
		//	}
		//	pConnections = NULL;
		//	dwSize = 0;
		//	iCnt = 0;
		//	
		//	in_addr IpAddr = {0};
		//	memset(szRemoteAddr, 0, 50*sizeof(TCHAR));
		//	memset(szProcName, 0, 1024*sizeof(TCHAR));
		//	memset(szImageName, 0, MAX_PATH*sizeof(TCHAR));

		//	//get function pointer of GetExtendedTcpTable function
		//	DWORD dError = m_objNetFunc.m_lpGetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
		//	pConnections = (PMIB_TCPTABLE_OWNER_PID)new unsigned char[dwSize];
		//	if(!pConnections)
		//	{
		//		m_objNetFunc.DestroyFunctionPointer();
		//		return;
		//	}

		//	//get opened connections
		//	dError = m_objNetFunc.m_lpGetExtendedTcpTable(pConnections, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
		//	if(dError != NO_ERROR)
		//	{ 
		//		//To avoid memory leakage
		//		delete [] ((unsigned char*)pConnections);
		//		AddLogEntry(L"Error Return by m_lpGetExtendedTcpTable in CNetworkConnectionMonitor::StartNetworkConnectionMonitor()");
		//		m_objNetFunc.DestroyFunctionPointer();
		//		return;
		//	}

		//	//check in database
		//	for(iCnt = 0; iCnt < pConnections->dwNumEntries; iCnt++)
		//	{
		//		pos = NULL;

		//		if(m_bStopNetMonitor)
		//		{
		//			break;
		//		}

		//		IpAddr.S_un.S_addr = (u_long)pConnections->table[iCnt].dwRemoteAddr;
		//		m_objNetFunc.MakeStringIP(szRemoteAddr, _countof(szRemoteAddr), &IpAddr);

		//		if((CString) szRemoteAddr == L"0.0.0.0")
		//		{
		//			continue;
		//		}

		//		if(pConnections->table[iCnt].dwOwningPid == 0 || pConnections->table[iCnt].dwOwningPid == 4)
		//		{
		//			continue;
		//		}

		//		ULONG ulSpyID = 0;
		//		if((m_objNetConDB.SearchItem((CString)szRemoteAddr, &ulSpyID)) || (m_bUserNetDB && m_objUserNetConDB.SearchItem((CString)szRemoteAddr, &ulSpyID)))
		//		{
		//			if(IsExcluded(ulSpyID, (CString)szRemoteAddr))
		//			{
		//				continue;
		//			}
		//		}
		//		else
		//		{
		//			continue;
		//		}

		//		KillConnection(pConnections, iCnt);
		//		objEnumProc.KillProcess(pConnections->table[iCnt].dwOwningPid);

		//		AddLogEntry(_T("Network Monitor Spyware Name: \tIP Address:%s"),(CString)szRemoteAddr);

		//		if(m_bDisplayNotification)
		//		{
		//			ReportSpywareEntry(0, szRemoteAddr, _T("IDS_NETWORK_MONITOR_EN"));
		//		}
		//	}

		//	delete [] ((unsigned char*)pConnections);
		//	Sleep(100);
		//	if(m_bStopNetMonitor)
		//	{
		//		break;
		//	}
		//}
		//m_objNetFunc.DestroyFunctionPointer();
	}
	catch(...)
	{
		//m_objNetFunc.DestroyFunctionPointer();
		AddLogEntry(L"Exception caught in CNetworkConnectionMonitor::StartNetworkConnectionMonitor");
	}
}

bool CNetworkConnectionMonitor::InstallDriver(LPCTSTR sDriverFileName, LPCTSTR sDriverName)
{
	//bool bRetVal = false;
	//TCHAR strFilePath[MAX_PATH] = {0};
	//
	////get path to ths .sys.file
	//GetModuleFileName(0, strFilePath, MAX_PATH);
	//DWORD  a = static_cast<DWORD>(wcslen(strFilePath));
	//if(a == 0)
	//{
	//	return bRetVal;
	//}
	//a--;
	//while(true)
	//{
	//	if(strFilePath[a] == '\\')
	//	{
	//		break;
	//	}
	//	if(a == 0)
	//	{
	//		return bRetVal;
	//	}
	//	a--;
	//}
	//a++;
	//wcscpy_s(&strFilePath[a], (MAX_PATH - a), sDriverFileName);

	////create service
	//SC_HANDLE hSrvManager = OpenSCManager(0 , 0, SC_MANAGER_ALL_ACCESS);
	//if(hSrvManager)
	//{
	//	SC_HANDLE hDriver = CreateService(hSrvManager, sDriverName, sDriverName, SERVICE_START | SERVICE_STOP,
	//						SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
	//						strFilePath, 0, 0, 0, 0, 0);

	//	if(hDriver != INVALID_HANDLE_VALUE)
	//	{
	//		bRetVal = true;
	//		if(hDriver)
	//		{
	//			CloseServiceHandle(hDriver);
	//			hDriver = NULL;
	//		}
	//	}
	//	CloseServiceHandle(hSrvManager);
	//}
	return true;
}

bool CNetworkConnectionMonitor::StartDriver(LPCTSTR sDriverName)
{
	bool bRetVal = false;
	SC_HANDLE hSrvManager = OpenSCManager(0, 0 , SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hDriver = OpenService(hSrvManager, sDriverName, SERVICE_START);
	
	if(hDriver)
	{
		bRetVal = (StartService(hDriver, 0, 0) == FALSE ? false : true);
		if(!bRetVal)
		{
			if(GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
			{
				bRetVal = true;
			}
		}
		CloseServiceHandle(hDriver);
		CloseServiceHandle(hSrvManager);
	}
	return bRetVal;
}

bool CNetworkConnectionMonitor::StopDriver(LPCTSTR sDriverName)
{
	SC_HANDLE hSrvManager = OpenSCManager(0, 0 , SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hDriver = OpenService(hSrvManager, sDriverName, SERVICE_STOP);

	if(hDriver)
	{
		SERVICE_STATUS sStatus;
		ControlService(hDriver, SERVICE_CONTROL_STOP, &sStatus);
		CloseServiceHandle(hDriver);
		CloseServiceHandle(hSrvManager);
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: StartNetworkConnectionMonitor
	In Parameters	: -
	Out Parameters	: void
	Purpose			: 
	Author			: Dipali Pawar.
--------------------------------------------------------------------------------------*/
bool CNetworkConnectionMonitor::StartMonitor()
{
	/*CCPUInfo objCPUInfo;
	if(objCPUInfo.GetOSVerTag() != W2K)
	{
		
	}

	if(!m_objNetConDB.Load(m_csMaxDBPath + SD_DB_NETWORK, true, false))
	{
		AddLogEntry(_T(">> Could not read DB: %s"), m_csMaxDBPath + SD_DB_NETWORK, 0);
		return false;
	}

	if(m_objUserNetConDB.Load(m_csMaxDBPath + SD_DB_USER_NETWORK, true, false))
	{
		m_bUserNetDB = true;
	}

	m_bStopNetMonitor = false ;
	m_pNetworkConnectionMonitorThread = AfxBeginThread(StartNetworkConnectionMonitorThread , (LPVOID)this, THREAD_PRIORITY_NORMAL, 0, CREATE_SUSPENDED, 0);
	if(m_pNetworkConnectionMonitorThread)
	{
		m_pNetworkConnectionMonitorThread->m_bAutoDelete = FALSE;
		m_pNetworkConnectionMonitorThread->ResumeThread();
	}
	m_bIsMonitoring = true;*/
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: StopNetworkConnectionMonitor
	In Parameters	: -
	Out Parameters	: void
	Purpose			: Stop Network Connection monitoring
	Author			: Dipali Pawar.
--------------------------------------------------------------------------------------*/
bool CNetworkConnectionMonitor::StopMonitor()
{
///	if(false == m_bStopNetMonitor)
//		return true;

	// commented on purpose!
	// this causes AuActMon to crash when network is enabled and disabled!
	//for(int i=0; i<m_nCapCount; i++) 
	//{
	//	// Close the thread...
	//	delete m_pCapThread[i];
	//	m_pCapThread[i] = NULL;
	//	pcap_close(m_pCapDev[i]);
	//}

	//if(m_pDevList) 
	//{
	//	pcap_freealldevs(m_pDevList);
	//	m_pDevList = NULL;
	//}

	// commented on purpose!
	// stopping the driver causes it to hang! and would need a system restart to start again!
	

	CloseAllThreads();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: HandleExisting
	In Parameters	: -
	Out Parameters	: bool
	Purpose			: 
	Author			: Sandip Sanap
--------------------------------------------------------------------------------------*/
bool CNetworkConnectionMonitor::HandleExisting()
{
	return true;
}
/*-------------------------------------------------------------------------------------
	Function		: OpenDevice
	In Parameters	: -
	Out Parameters	: BOOL
	Purpose			: Enumerate all available adapter
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
BOOL CNetworkConnectionMonitor::OpenDevice(int nIndex)
{
//   pcap_if_t *d;
//   char szErrBuf[PCAP_ERRBUF_SIZE] = {0};
//#ifdef PCAP_EXTEN
//   // Get the list of adapters
//   if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &m_pCapDevs, szErrBuf) == -1) 
//   {
//      AfxMessageBox(_T("Error in pcap_findalldevs\n"));
//      exit(1);
//   }
//#else   
//   // Retrieve the device list 
//   if(pcap_findalldevs(&m_pDevList, szErrBuf) == -1)
//   {
//      AddLogEntry(_T("Error in pcap_findalldevs"));
//      exit(1);
//   }
//#endif
//   if(!m_pDevList)
//   {
//     // AddLogEntry(_T("No interfaces found! Make sure pcap/Winpcap is installed."));
//      return FALSE;
//   }
//
//   /* Jump to the selected adapter */
//   int promisc=1;
//   bpf_u_int32 mask = 0;
//   bpf_u_int32 net = 0;
//   ////
//   m_nCapCount = 0;
//   int i;
//   for(i=0,d=m_pDevList; d != NULL && i < NET_DEV_MAX; d=d->next)
//   {
//      if (pcap_lookupnet(d->name, &net, &mask, szErrBuf) == -1 || net == 0 ) 
//	  {
//         //fprintf(stderr, "Can't get netmask for device %s\n", d->name);
//         net = 0;
//         mask = 0;
//         continue;
//      }
//      ////
//#ifdef PCAP_EXTEN
//      if( !d || (m_pCapDev[m_nCapCount] = pcap_open( d->name, 6*1024, promisc, 10, NULL, szErrBuf )) == NULL) 
//      {
//         AfxMessageBox("Unable to open the network adapter!");
//         continue;
//      }
//#else
//      // Open the adapter 
//      if ( !d || (m_pCapDev[m_nCapCount] = pcap_open_live(d->name,   // name of the device
//													  6*1024,     // portion of the packet to capture. 
//																	// 65536 grants that the whole packet will be captured on all the MACs.
//													  promisc,   // promiscuous mode
//													  10,      // read timeout
//													  szErrBuf     // error buffer
//													  )) == NULL)
//      {
//         continue;
//      }
//#endif
//	  //CStringA sText;
//	  //sText.Format("Attached to device: %s, %s\n", d->name, d->description);
//  	  //OutputDebugStringA(sText);
//	  m_nCapCount++;
//   }
	
   return TRUE;
}


/*-------------------------------------------------------------------------------------
	Function		: CheckForBlock
	In Parameters	: -
	Out Parameters	: BOOL
	Purpose			: Check given ip/domain name is in database.
	Author			: Dipali Pawar
--------------------------------------------------------------------------------------*/
bool CNetworkConnectionMonitor::CheckForBlock(ULONG ulSrcIP, ULONG ulDstIP, char *szURL)
{
	bool bFound = false;
	/*if(!m_bIsMonitoring)
	{
		return false;
	}
	WaitForSingleObject(m_hSingleScan, INFINITE);
	bool bFound = false;
	ULONG ulSpyID = 0;
	in_addr IpAddr = {0};
	TCHAR szRemoteAddr[50] = {0};
	CString csDisplay;
	CString szDbUrl;
	IpAddr.S_un.S_addr = (u_long)ulDstIP;
	MakeStringIP(szRemoteAddr, _countof(szRemoteAddr), &IpAddr);
	if((m_objNetConDB.SearchItem((CString)szRemoteAddr, &ulSpyID)) || (m_bUserNetDB && m_objUserNetConDB.SearchItem((CString)szRemoteAddr, &ulSpyID)))
	{
		CMaxDSrvWrapper objMaxDSrvWrapper(COINIT_MULTITHREADED);
		objMaxDSrvWrapper.InitializeDatabase();
		if(false == objMaxDSrvWrapper.IsExcluded(ulSpyID, NULL, (CString)szRemoteAddr))
		{
			csDisplay = (CString)szRemoteAddr;
			AddLogEntry(_T("Network Monitor Spyware Name: \tIP Address:%s"),(CString)szRemoteAddr);
			bFound = true;
		}
		objMaxDSrvWrapper.DeInitializeDatabase();
	}

	if(false == bFound)
	{
		IpAddr.S_un.S_addr = (u_long)ulSrcIP;
		MakeStringIP(szRemoteAddr, _countof(szRemoteAddr), &IpAddr);
		if((m_objNetConDB.SearchItem((CString)szRemoteAddr, &ulSpyID)) || (m_bUserNetDB && m_objUserNetConDB.SearchItem((CString)szRemoteAddr, &ulSpyID)))
		{
			CMaxDSrvWrapper objMaxDSrvWrapper(COINIT_MULTITHREADED);
			objMaxDSrvWrapper.InitializeDatabase();
			if(false == objMaxDSrvWrapper.IsExcluded(ulSpyID, NULL, (CString)szRemoteAddr))
			{
				csDisplay = (CString)szRemoteAddr;
				AddLogEntry(_T("Network Monitor Spyware Name: \tIP Address:%s"),(CString)szRemoteAddr);
				bFound = true;
			}
			objMaxDSrvWrapper.DeInitializeDatabase();
		}
	}

	if((false == bFound) && (strlen(szURL) > 0))
	{
		if((m_objNetConDB.SearchItem((CString)szURL, &ulSpyID)) || (m_bUserNetDB && m_objUserNetConDB.SearchItem((CString)szURL, &ulSpyID)))
		{
			CMaxDSrvWrapper objMaxDSrvWrapper(COINIT_MULTITHREADED);
			objMaxDSrvWrapper.InitializeDatabase();
			if(false == objMaxDSrvWrapper.IsExcluded(ulSpyID, NULL, (CString)szURL))
			{
				csDisplay = szURL;
				AddLogEntry(_T("Network Monitor Spyware Name: \tDomain:%s"),(CString)szURL);
				bFound = true;
			}
			objMaxDSrvWrapper.DeInitializeDatabase();
		}

		if(false == bFound)
		{
			if((FindDomainInDb(m_objNetConDB, (CString)szURL, ulSpyID, szDbUrl)) || (m_bUserNetDB && FindDomainInDb(m_objUserNetConDB, (CString)szURL, ulSpyID, szDbUrl)))
			{
				CMaxDSrvWrapper objMaxDSrvWrapper(COINIT_MULTITHREADED);
				objMaxDSrvWrapper.InitializeDatabase();
				if(false == objMaxDSrvWrapper.IsExcluded(ulSpyID, NULL, (CString)szDbUrl))
				{
					csDisplay = (CString)szURL;
					AddLogEntry(_T("Network Monitor Spyware Name: \tDomain:%s"),(CString)szURL);
					bFound = true;
				}
				objMaxDSrvWrapper.DeInitializeDatabase();
			}
		}
	}
	if(m_bDisplayNotification && bFound)
	{
		CString csKey, csVal;
		csDisplay.MakeLower();
		if(m_oLastBlockedPacket.Lookup(csDisplay, csVal) == FALSE)
		{
			if(m_oLastBlockedPacket.GetCount() == 10)
			{
				POSITION pos = m_oLastBlockedPacket.GetStartPosition();
				m_oLastBlockedPacket.GetNextAssoc(pos,csKey,csVal);
				m_oLastBlockedPacket.RemoveKey(csKey);
			}
			m_oLastBlockedPacket.SetAt(csDisplay, BLANKSTRING);
			
			ReportSpywareEntry(Network, 0, csDisplay, _T("IDS_NETWORK_MONITOR_EN"));
		}
	}
	SetEvent(m_hSingleScan);*/
	return bFound;
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
//bool CNetworkConnectionMonitor::MakeStringIP(TCHAR * szIPAddress, DWORD dwSize, in_addr * pIpAddr)
//{
	/*if(dwSize < 20)
	{
		return (false);
	}

	memset(szIPAddress, 0, dwSize * sizeof(TCHAR));
	_stprintf_s(szIPAddress, dwSize, _T("%d.%d.%d.%d"), pIpAddr ->S_un.S_un_b.s_b1,
														pIpAddr ->S_un.S_un_b.s_b2,
														pIpAddr ->S_un.S_un_b.s_b3,
														pIpAddr ->S_un.S_un_b.s_b4);*/
//	return (true);
//}

//bool CNetworkConnectionMonitor::FindDomainInDb(CS2U &objNetMonDb, CString &csDomainName, ULONG &ulSpyID, CString &csDbDomainName)
//{
	/*bool bRet = false;
	LPTSTR szDomainName;
	LPVOID posProfType = objNetMonDb.GetFirst();
	while(posProfType)
	{
		objNetMonDb.GetKey(posProfType, szDomainName);
		if(_tcsstr(csDomainName, szDomainName))
		{
			csDbDomainName = szDomainName;
			objNetMonDb.GetData(posProfType, ulSpyID);
			bRet = true;
			break;
		}
		posProfType = objNetMonDb.GetNext(posProfType);
	}*/
	//return bRet;

//}