/*=============================================================================
   FILE				: NetworkConnectionMonitor.h
   ABSTRACT			: Declaration of Class CNetworkConnectionMonitor for network connection monitor.
   DOCUMENTS		: Network Connection Monitor-Design Document.doc
   AUTHOR			: Dipali Pawar
   COMPANY			: Aura 
   COPYRIGHT NOTICE	:
					(C) Aura
      				Created as an unpublished copyright work.  All rights reserved.
     				This document and the information it contains is confidential and
      				proprietary to Aura.  Hence, it may not be 
      				used, copied, reproduced, transmitted, or stored in any form or by any 
      				means, electronic, recording, photocopying, mechanical or otherwise, 
      				with out the prior written permission of Aura
   CREATION DATE	: 19-Jun-08
   NOTES			:
   VERSION HISTORY	:
				
=============================================================================*/
#pragma once
#include "ActiveMonitor.h"
#include "stdafx.h"
//#include "NetPacket.h"
#include "S2U.h"

class CNetworkConnectionMonitor : public CActiveMonitor
{
public:
	CNetworkConnectionMonitor(void);
	virtual ~CNetworkConnectionMonitor(void);

	bool StartMonitor();
	void StartNetworkConnectionMonitor();
	bool CheckForBlock(ULONG ulSrcIP, ULONG ulDstIP, char *szURL);
	bool StopMonitor();
	bool HandleExisting();

private:
	CWinThread* m_pNetworkConnectionMonitorThread;
	bool m_bStopNetMonitor;
	CS2U m_objNetConDB;
	CS2U m_objUserNetConDB;
	bool m_bUserNetDB;
	//pcap_t *m_pCapDev[NET_DEV_MAX];
	//pcap_if_t *m_pDevList;
	//CNetCapture *m_pCapThread[NET_DEV_MAX];
	int m_nCapCount;
	HANDLE m_hSingleScan;
	CMapStringToString m_oLastBlockedPacket;

	bool InstallDriver(LPCTSTR sDriverFileName, LPCTSTR sDriverName);
	bool StartDriver(LPCTSTR sDriverName);
	bool StopDriver(LPCTSTR sDriverName);

	BOOL OpenDevice(int nIndex = -1);
//	bool MakeStringIP(TCHAR * szIPAddress, DWORD dwSize, in_addr * pIpAddr);
	//bool FindDomainInDb(CS2U &objNetMonDb, CString &csDomainName, ULONG &ulSpyID, CString &csDbDomainName);
};
