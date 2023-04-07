
/*======================================================================================
FILE             : WatchDogService.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshit Kasliwal
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 5/12/2009
NOTES		     : CWatchDogService Class Declaration
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "pch.h"
#include <winsvc.h>

class CWatchDogService
{
public:
	CWatchDogService(void); 
	~CWatchDogService(void); 

	BOOL InitService(CString csServiceName);
	void StartService();
	bool IsServiceRunning();
	inline void IncrementTreadCount()
	{ 
		m_dwThreadCount++;
	}
	inline void DecrementTreadCount()
	{ 
		m_dwThreadCount--;
	}
	static DWORD SetWDServiceStopStatus(bool bEnable = true);
	static DWORD SetWDServiceStopStatusPPL();
	static DWORD SetWDServiceChangeStatus();
private:
	static SERVICE_STATUS			m_ServiceStatus; 
	static SERVICE_STATUS_HANDLE	m_ServiceStatusHandle;
	static CString					m_csServiceName;
	static DWORD					m_dwThreadCount;
	static void WINAPI	StartAdminService(DWORD dwVal, LPWSTR *lpstrName);
	static void WINAPI	RemoteAdminHandler(DWORD dwOpcode,DWORD evtype, PVOID evdata, PVOID Context);
	
	DWORD		IsService(BOOL& isService);	

};
