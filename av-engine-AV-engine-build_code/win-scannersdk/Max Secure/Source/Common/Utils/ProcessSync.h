#pragma once

class CProcessSync
{
	HANDLE m_hLockFile;
public:

	bool SetLock(LPCTSTR szFullFilePath);
	void ReleaseLock();

	CProcessSync(void);
	virtual ~CProcessSync(void);
};
