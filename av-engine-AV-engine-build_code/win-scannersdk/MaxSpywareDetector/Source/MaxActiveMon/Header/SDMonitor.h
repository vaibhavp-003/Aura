/*======================================================================================
FILE             : SDMonitor.h
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Avinash Bhardwaj
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 07/09/2008
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
#pragma once
#include "pch.h"
#include "Registry.h"
#include "ProductInfo.h"
#include "CPUInfo.h"

class CSDMonitor
{
public:
	CSDMonitor();
	~CSDMonitor();
	void SetHandler(ACTMON_MESSAGEPROCHANDLER pHandler);
	void StartActMonSwitch();
	bool StartStopMonitor(DWORD dwMonitorType, bool bStatus,bool bShutDown, int ProcessType = 0, DWORD dwPID = 0);
	void StopActMonSwitch();

private:
	bool		m_bLoadedSuccessfully = false;
	bool		m_bPCShutDown = false;
	HMODULE		m_hActiveMon = NULL;
	typedef bool(*PFSETACTIVEMONITOR)(int iType, bool bStatus, LPVOID pMessageHandler, LPVOID lpThis, bool bShutDownStatus);
	typedef bool(*PFLOADDBCACHE)();
	typedef bool(*PFMONRANREGVALUE)();
	PFSETACTIVEMONITOR			lpSetActiveMonitor = NULL;
	ACTMON_MESSAGEPROCHANDLER	m_pProcHandler = NULL;
	PFMONRANREGVALUE			lpMonRanRegValue = NULL;

	void DisplayMessage(LPCTSTR lpMessageID);
	void SetActiveMonitorOff();
	bool CheckRegistration();
	bool LoadActiveMonitorDLL();
	void UnLoadActiveMonitorDLL();
	void EnableMonitors();
	void DisableMonitors();
	bool GetStatus(CString csKey);
	HANDLE GetExplorerProcessHandle();
	BOOL StartProtection();
	void StopProtection();
	void SetRegistrationFlag(int iControlFlag);
	void GetBuyNowLink(CString &csBuyNow);
};
