#pragma once
#include "Netfw.h"

class CWindowsFeatures
{
public:
	CWindowsFeatures();
	~CWindowsFeatures();

	bool CheckForFirewallSettingAndConfigure(int iType);
	HRESULT WindowsFirewallIsOn(IN INetFwProfile* fwProfile, OUT BOOL* fwOn);
	HRESULT WindowsFirewallInitialize(OUT INetFwProfile** fwProfile);
	void DisbaleFirewallOnWindows7(BOOL bEnable);
	HRESULT WFCOMInitializeWin7(INetFwPolicy2** ppNetFwPolicy2);
};