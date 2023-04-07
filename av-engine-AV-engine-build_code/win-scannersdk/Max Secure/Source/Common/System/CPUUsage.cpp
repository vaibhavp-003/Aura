#include "StdAfx.h"
#include <windows.h>
#include "CpuUsage.h"

CCPUUsage::CCPUUsage(void)
:m_nCCPUUsage(-1)
,m_dwLastRun(0)
,m_lRunCount(0)
{
	ZeroMemory(&m_ftPrevSysKernel, sizeof(FILETIME));
	ZeroMemory(&m_ftPrevSysUser, sizeof(FILETIME));

	ZeroMemory(&m_ftPrevProcKernel, sizeof(FILETIME));
	ZeroMemory(&m_ftPrevProcUser, sizeof(FILETIME));
	m_pfnGetSystemTimes = NULL;
	m_hModule = NULL;
	m_hModule = GetModuleHandle(_T("kernel32"));
	if(m_hModule)
	{
		m_pfnGetSystemTimes = (LPFN_GETSYSTEMTIMES)GetProcAddress(m_hModule, "GetSystemTimes");
	}
}

CCPUUsage::~CCPUUsage()
{
	if(m_pfnGetSystemTimes)
		m_pfnGetSystemTimes = NULL;
}

/**********************************************
* CCPUUsage::GetUsage
* returns the percent of the CPU that this process
* has used since the last time the method was called.
* If there is not enough information, -1 is returned.
* If the method is recalled to quickly, the previous value
* is returned.
***********************************************/
short CCPUUsage::GetUsage(HANDLE hProcess)
{
	if(!m_pfnGetSystemTimes)
		return 0;
	
	//create a local copy to protect against race conditions in setting the 
	//member variable
	short nCpuCopy = m_nCCPUUsage;
	if (::InterlockedIncrement(&m_lRunCount) == 1)
	{
		/*
		If this is called too often, the measurement itself will greatly affect the
		results.
		*/

		if (!EnoughTimePassed())
		{
			::InterlockedDecrement(&m_lRunCount);
			return nCpuCopy;
		}

		FILETIME ftSysIdle, ftSysKernel, ftSysUser;
		FILETIME ftProcCreation, ftProcExit, ftProcKernel, ftProcUser;

		if (!m_pfnGetSystemTimes(&ftSysIdle, &ftSysKernel, &ftSysUser) ||
			!GetProcessTimes(hProcess, &ftProcCreation, &ftProcExit, &ftProcKernel, &ftProcUser))
		{
			::InterlockedDecrement(&m_lRunCount);
			return nCpuCopy;
		}

		if (!IsFirstRun())
		{
			/*
			CPU usage is calculated by getting the total amount of time the system has operated
			since the last measurement (made up of kernel + user) and the total
			amount of time the process has run (kernel + user).
			*/
			ULONGLONG ftSysKernelDiff = SubtractTimes(ftSysKernel, m_ftPrevSysKernel);
			ULONGLONG ftSysUserDiff = SubtractTimes(ftSysUser, m_ftPrevSysUser);

			ULONGLONG ftProcKernelDiff = SubtractTimes(ftProcKernel, m_ftPrevProcKernel);
			ULONGLONG ftProcUserDiff = SubtractTimes(ftProcUser, m_ftPrevProcUser);

			ULONGLONG nTotalSys =  ftSysKernelDiff + ftSysUserDiff;
			ULONGLONG nTotalProc = ftProcKernelDiff + ftProcUserDiff;

			if (nTotalSys > 0)
			{
				m_nCCPUUsage = (short)((100.0 * nTotalProc) / nTotalSys);
			}
		}
		
		m_ftPrevSysKernel = ftSysKernel;
		m_ftPrevSysUser = ftSysUser;
		m_ftPrevProcKernel = ftProcKernel;
		m_ftPrevProcUser = ftProcUser;
		
		m_dwLastRun = ::GetTickCount();

		nCpuCopy = m_nCCPUUsage;
	}
	
	::InterlockedDecrement(&m_lRunCount);

	return nCpuCopy;
}

ULONGLONG CCPUUsage::SubtractTimes(const FILETIME& ftA, const FILETIME& ftB)
{
	LARGE_INTEGER a, b;
	a.LowPart = ftA.dwLowDateTime;
	a.HighPart = ftA.dwHighDateTime;

	b.LowPart = ftB.dwLowDateTime;
	b.HighPart = ftB.dwHighDateTime;

	return a.QuadPart - b.QuadPart;
}

bool CCPUUsage::EnoughTimePassed()
{
	const int minElapsedMS = 250;//milliseconds

	ULONGLONG dwCurrentTickCount = GetTickCount();
	return (dwCurrentTickCount - m_dwLastRun) > minElapsedMS; 
}