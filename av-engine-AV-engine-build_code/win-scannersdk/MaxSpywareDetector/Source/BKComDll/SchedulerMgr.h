#pragma once
class CSchedulerMgr
{
public:
	CSchedulerMgr();
	~CSchedulerMgr();
	void GetSchedulerSettings(LPUScanSchedulerData pScanScheduler);
	void SetSchedulerSettings(UScanSchedulerData objScanScheduler);
	bool ClearScheduledScan();
private:
	int m_iSignatueScan;
	int m_iCompressScan;
	int m_iScanQuarantine;
	bool ReadRegistrySettings(LPUScanSchedulerData pScanScheduler);
	void OnCreateTask(UScanSchedulerData objScanScheduler);
};

