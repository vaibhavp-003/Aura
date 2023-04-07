/*=============================================================================
   FILE			: RemoteService.h
   DESCRIPTION	: This class provides the functionality related with the service of the remote machine
   DOCUMENTS	: 
   AUTHOR		: Sandip Sanap
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 05-12-2007
   NOTES		:
VERSION HISTORY	:
============================================================================*/
#pragma once

#include "pch.h"
#include <winsvc.h>

class CRemoteService
{
public:
	CRemoteService(void);
	~CRemoteService(void);

	BOOL InitService(CString csServiceName);
	void StartService();
	void StartRemoteService(); //SMA
	bool StartService(CString csServiceName); //SMA
	bool RegisterService(CString csServiceName,CString csAppPath,DWORD dwServiceType,DWORD dwStartType);
	bool StartRemoteService(CString csServiceName, CString csAppPath, DWORD dwServiceType = SERVICE_WIN32_OWN_PROCESS,DWORD dwStartType = SERVICE_AUTO_START, bool bSleep = true, bool bRegister = false);
	bool StopRemoteService(CString csServiceName,bool bDeleteService = true);
	bool StopRemoteService(CString csServiceName,bool bDeleteService, CString &csServicePath);
	bool IsRmoteServiceRunning(const CString &csServiceName); //SMA
	bool SetFailureActionToService(LPCTSTR strServiceName, LPTSTR strDescription = TEXT("Au Services"));
	bool DeleteRemoteService(CString csServiceName);
	void DoUpdateSvcDesc(CString csServiceName, CString csDescription);
	bool SetServiceDescription(LPCTSTR lpstrServiceName, LPCTSTR lpstrDescription);

private:
	static CString m_csServiceName;
	DWORD			IsService(BOOL& isService);
	static void WINAPI	StartAdminService(DWORD dwVal, LPWSTR *lpstrName);
	static void WINAPI	RemoteAdminHandler(DWORD Opcode);
	static SERVICE_STATUS			m_ServiceStatus;
	static SERVICE_STATUS_HANDLE	m_ServiceStatusHandle;
};
