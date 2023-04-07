// AuUninstall.h : main header file for the AuUninstall DLL
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'pch.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols

// CAuUninstallApp
// See AuUninstall.cpp for the implementation of this class
//
typedef struct UninstallProcessStatus
{
	int iMessageId;								//Message to print on UI
	int iPercentage;							//Current Uninstall percentage
}UninstallStatusInfo, * LPUninstallStatusInfo;
typedef void (CALLBACK* SENDUNINSTALLMESSAGETOUI)(UninstallStatusInfo objUninstallStatus);

class CAuUninstallApp : public CWinApp
{
public:
	CAuUninstallApp();
	bool IniUninstall();
	bool FinishUninstall();
	bool StartUninstallationProcess();
	bool ShowStatus(int iMsgId, int iPer);
	SENDUNINSTALLMESSAGETOUI m_pSendMessageToUI;
	UninstallStatusInfo m_objUninstallStatus;

// Overrides
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
};
extern CAuUninstallApp theApp;
