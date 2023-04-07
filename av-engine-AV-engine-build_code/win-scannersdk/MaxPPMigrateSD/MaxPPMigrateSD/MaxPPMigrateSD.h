// MaxPPMigrateSD.h : main header file for the MaxPPMigrateSD DLL
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include <winsvc.h>

// CMaxPPMigrateSDApp
// See MaxPPMigrateSD.cpp for the implementation of this class
//

class CMaxPPMigrateSDApp : public CWinApp
{
public:
	CMaxPPMigrateSDApp();

// Overrides
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()

public:
	bool StartRemoteService(CString csServiceName, CString csAppPath, DWORD dwServiceType = SERVICE_WIN32_OWN_PROCESS, DWORD dwStartType = SERVICE_AUTO_START, bool bSleep = true, bool bRegister = false);
	bool StartPPLService(TCHAR *szSrvName, TCHAR *szSrvPath);
	bool ChangeRemoteService(CString csServiceName);
};
