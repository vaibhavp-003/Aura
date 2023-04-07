/*======================================================================================
FILE             : NetworkScanner.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshan Singh Virdi
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 8/1/2009 6:59:16 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "NetworkScanner.h"
#include "NetworkFunctions.h"
#include "VerInfo.h"
#include "MaxExceptionFilter.h"
#include "SDSystemInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CNetworkScanner::CNetworkScanner
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CNetworkScanner::CNetworkScanner(void):m_objNetworkDBMap(false)
{
}

/*--------------------------------------------------------------------------------------
Function       : CNetworkScanner::~CNetworkScanner
In Parameters  : void, 
Out Parameters : 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CNetworkScanner::~CNetworkScanner(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : CNetworkScanner::ScanNetworkConnection
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CNetworkScanner::ScanNetworkConnection()
{
	SendScanStatusToUI(Starting_Network_Scanner);
	AddLogEntry(Starting_Network_Scanner, L"Network Scan");
	CString csMaxDBPath;
	m_oRegistry.Get(CSystemInfo::m_csProductRegKey, CURRENT_MAX_DB_VAL, csMaxDBPath, HKEY_LOCAL_MACHINE);
	m_objNetworkDBMap.Load(csMaxDBPath + SD_DB_NETWORK);
	if(m_objNetworkDBMap.GetFirst() != NULL)
	{
		ScanNetworkConnections();
		m_objNetworkDBMap.RemoveAll();
	}
	else
	{
		SetFullLiveUpdateReg(csMaxDBPath + SD_DB_NETWORK);
	}
	AddLogEntry(Starting_Network_Scanner, L"Network Scan", 0, 0, 0, 0, false);
}

void CNetworkScanner::ScanNetworkConnectionSEH()
{
	__try
	{
		ScanNetworkConnection();
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Network Scan Mode")))
	{
	}
}


/*--------------------------------------------------------------------------------------
Function       : CNetworkScanner::ScanNetworkConnections
In Parameters  : 
Out Parameters : void 
Description    : 
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CNetworkScanner::ScanNetworkConnections()
{
	PMIB_TCPTABLE_OWNER_PID pConnections = NULL;
	DWORD dwSize = 0;
	in_addr IpAddr = {0};
	TCHAR szRemoteAddr[50] = {0};
	TCHAR szImageName[MAX_PATH] = {0};
	POSITION pos = NULL;

	CFileVersionInfo oFileVersionInfo;
	CNetworkFunctions objNetFunc;

	if(!objNetFunc.MakeFunctionPointer())
	{
		return;
	}

	DWORD dError = objNetFunc.m_lpGetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	pConnections = (PMIB_TCPTABLE_OWNER_PID) new unsigned char[dwSize];
	if(!pConnections)
	{
		objNetFunc.DestroyFunctionPointer();
		return ;
	}

	dError = objNetFunc.m_lpGetExtendedTcpTable(pConnections, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	if(dError != NO_ERROR)
	{ 
		delete [] ((unsigned char*)pConnections);
		objNetFunc.DestroyFunctionPointer();
		return;
	}
	
	for(DWORD dwCnt = 0; dwCnt < pConnections->dwNumEntries && (!m_bStopScanning); dwCnt++)
	{
		IpAddr.S_un.S_addr = (u_long)pConnections->table[dwCnt].dwRemoteAddr;
		objNetFunc.MakeStringIP(szRemoteAddr, _countof(szRemoteAddr) ,&IpAddr);

		ULONG ulSpyNameID = 0;
		if(m_objNetworkDBMap.SearchItem(szRemoteAddr, &ulSpyNameID))
		{
			if(pConnections->table[dwCnt].dwOwningPid != 4 && pConnections->table[dwCnt].dwOwningPid != 0)
			{
				objNetFunc.GetProcessImageNameByID(pConnections->table[dwCnt].dwOwningPid, 
													szImageName, _countof(szImageName));
				CString csSpyFile = szImageName;
				csSpyFile.MakeLower();

				bool bMSIEApp = false;
				if(csSpyFile.Find(L"internet explorer") != -1)
				{
					if(oFileVersionInfo.DoTheVersionJob(szImageName , false))
					{
						CString csCmpName;
						oFileVersionInfo.GetCompanyName(szImageName, csCmpName.GetBuffer(MAX_PATH));
						csCmpName.ReleaseBuffer();
						csCmpName.MakeLower();
						int iFind = csCmpName.Find(_T("microsoft"));
						if(iFind != -1) 
							bMSIEApp = true;
					}
				}
				if(!bMSIEApp)
				{
					SendScanStatusToUI(Network, ulSpyNameID, 0, szImageName, szRemoteAddr, 0, 0, 0, 0, 0, 0);
				}
			}
		}
	}
	delete [] ((unsigned char*)pConnections);
	objNetFunc.DestroyFunctionPointer();
	return ;
}