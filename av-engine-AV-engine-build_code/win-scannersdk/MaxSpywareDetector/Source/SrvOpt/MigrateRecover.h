#pragma once
#include "S2U.h"
#include "RemoveDb.h"

class CMigrateRecover
{
public:
	CMigrateRecover(void);
	~CMigrateRecover(void);

	void AfterInstallSetup(bool bProductPatch, bool bSDNormalStart);	
	

private:
	CS2U *m_pSpyNameDb;
	DWORD GetSpyTypeID(CString &csSpyType);
	ULONG GetSpyNameID(CString csSpyName);
	BOOL InstallSDDriver(CString csName, CString csPath);
	bool InstallFilterDriver(LPCTSTR strFilePath, LPCTSTR sDriverName, LPCTSTR sAltitudeID);
    bool StartDriver(LPCTSTR sDriverName);
	BOOL CheckForBartPE();
	bool InstallDriver(LPCTSTR szFilePath, LPCTSTR szDriverName);
	bool ChangeServiceStartType(LPCTSTR sDriverName, LPCTSTR sDriverPath, DWORD dwStartType);
	void CleanUpService(LPCTSTR szName);

public:
	BOOL AskForRestart(CString csAppPath);
	
};
