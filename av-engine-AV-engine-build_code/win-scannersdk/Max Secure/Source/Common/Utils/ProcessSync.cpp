#include "pch.h"
#include "ProcessSync.h"

CProcessSync::CProcessSync(void)
{
	m_hLockFile = INVALID_HANDLE_VALUE;
}

CProcessSync::~CProcessSync(void)
{
	ReleaseLock();
}

bool CProcessSync::SetLock(LPCTSTR szFullFilePath)
{
	if(!szFullFilePath)
		return false;

	m_hLockFile = CreateFile(szFullFilePath, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, 0);

	if(m_hLockFile == INVALID_HANDLE_VALUE)
		return false;

	return true;
}

void CProcessSync::ReleaseLock()
{
	if(m_hLockFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hLockFile);
		m_hLockFile = INVALID_HANDLE_VALUE;
	}
}
