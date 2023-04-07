
#pragma once

class CProcessMonitor;

class CIdleScan
{
public:
	CIdleScan();
	~CIdleScan();

	bool m_bStopScanning;

	CProcessMonitor *m_pProcessMonitor;

	CString EnumerateAllDrives();
	void EnumFolder(const TCHAR *cFolderPath, bool bEnumSubFolders = true, bool bSkipFolder = true);	

public:
	void StartIdleScan();
	void StopIdleScan();
	void SetProcessMonitorPointer(LPVOID pThis);
};