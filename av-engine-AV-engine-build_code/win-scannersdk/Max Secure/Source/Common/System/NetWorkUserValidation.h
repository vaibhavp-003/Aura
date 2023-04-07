#pragma once

class CNetWorkUserValidation
{
public:
	CNetWorkUserValidation(void);
	~CNetWorkUserValidation(void);
	BOOL ImpersonateLocalUser(TCHAR *szUsername, TCHAR *szPassword);
    BOOL NetworkValidation(TCHAR *szMachineName,TCHAR *szUsername, TCHAR *szPassword);
	TCHAR* GetIPAddress(TCHAR *szMachinename);
	int iLoopCount;
};
