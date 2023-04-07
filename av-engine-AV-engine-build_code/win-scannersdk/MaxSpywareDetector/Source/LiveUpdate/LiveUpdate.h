#pragma once

#include "resource.h"
#include "LiveUpdate.h"

class CLiveUpdate
{
public:
	CLiveUpdate();
	~CLiveUpdate();

public:
	void DoLiveUpdate();
	bool m_bAutoUpdate;
	bool m_bLiveUpdateStart;
	void OnBnClickedButtonLiveupStartStop();

	CWinThread* m_hLiveUpdateThread;
	int CheckForLiveUpdate();
	bool LoadLiveUpdate();
	LPUPDATE		m_lpLiveUpdate;
	LPSTOPUPDATE	m_lpLiveUpdateStop;
	HMODULE			m_hLiveUpdateDll;
	bool			m_bLiveUpdateThread;


};
extern CLiveUpdate theApp;
