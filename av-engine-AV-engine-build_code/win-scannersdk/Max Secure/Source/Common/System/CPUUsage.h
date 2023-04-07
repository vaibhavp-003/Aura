#pragma once
#include <windows.h>

typedef BOOL (WINAPI *LPFN_GETSYSTEMTIMES)(LPFILETIME, LPFILETIME, LPFILETIME);

class CCPUUsage
{
public:
	CCPUUsage(void);
	~CCPUUsage();
	
	short  GetUsage(HANDLE hProcess);
private:
	ULONGLONG SubtractTimes(const FILETIME& ftA, const FILETIME& ftB);
	bool EnoughTimePassed();
	inline bool IsFirstRun() const { return (m_dwLastRun == 0); }
	
	//system total times
	FILETIME m_ftPrevSysKernel;
	FILETIME m_ftPrevSysUser;

	//process times
	FILETIME m_ftPrevProcKernel;
	FILETIME m_ftPrevProcUser;

	short m_nCCPUUsage;
	ULONGLONG m_dwLastRun;
	
	volatile LONG m_lRunCount;
	LPFN_GETSYSTEMTIMES m_pfnGetSystemTimes;
	HMODULE m_hModule;
};
