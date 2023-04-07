#pragma once
#include "wscisvapi.h"
#include "wscapi.h"
class CWscRegMon
{
public:
	CWscRegMon(void);
	~CWscRegMon(void);

	bool StartStopMonitor(DWORD dwMonitorType, bool bStatus,bool bShutDown, int ProcessType = 0, DWORD dwPID = 0);
	HANDLE	hWscCallbackRegistration;
	BOOL	RegisterForChangesWSC();
	BOOL	UnRegisterForChangesWSC();
	bool	IniRegisterToWSC();
	bool	RegisterToWSC();
	bool	UnRegisterToWSC();
	bool	RegisterToWSCUpdate(int iProduct, bool bUpdate);
	bool	RegisterToWSCSubUpdate(int iProduct, WSC_SECURITY_PRODUCT_SUBSTATUS eProductStaus);
	BOOL	LastUpdate();
	bool	NotifyExpireToWSC(DWORD dwDays);
	bool	VoucherStatusCheck(DWORD dwRegister);
	bool	bWatchWscService;

	BOOL	ManageWin10Upgrade();
	//static DWORD	WINAPI OnSecurityCenterHealthChange(LPVOID lpParameter);
};
