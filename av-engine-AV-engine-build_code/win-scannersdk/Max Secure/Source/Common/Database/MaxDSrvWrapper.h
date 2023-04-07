#pragma once

#include "MaxConstant.h"
#include "RemoveDB.h"
#include "MaxCommunicator.h"
#include "MaxPipes.h"

const TCHAR chTRUE		= 1;

class CMaxDSrvWrapper
{
	CMaxCommunicator * m_pCommClient;
	MAX_PIPE_DATA_REG m_stData;
	bool m_bServerReady;
	bool m_bDBInit;
	HANDLE m_hEvent;

	CString GetInstallPath();
	bool ConnectServerNew();
	bool ConnectServer();
	bool DisConnectServer();

public:
	CMaxDSrvWrapper();
	virtual ~CMaxDSrvWrapper();

	bool InitializeVirusScanner();
	void DeInitializeVirusScanner();

	bool InitializeDatabase();
	void DeInitializeDatabase();

	bool ReloadDatabase();
	bool ReloadRemoveDB();
	bool ReloadMailRemoveDB();

	bool Exclude(ULONG ulThreatID, CString csThreatName, CString csPath);
	bool IsExcluded(ULONG ulThreatID, CString csThreatName, CString csPath);
	bool Recover(ULONG ulThreatID, CString csThreatName, CString csPath);

	bool GetThreatInfo(ULONG ulSpyName, CString & csSpyName, BYTE & bThreatIndex, CString & csHelpInfo, CString csKeyValue, int iTypeId);
	CString GetSpyName(ULONG ulSpyName, BYTE &iThreatIndex);

	bool AddToRemoveDB(PSYS_OBJ_FIXEDSIZE pSysObj);
	bool AddMailToRemoveDB(PSYS_OBJ_FIXEDSIZE pSysObj);
	bool AddFileToRescannedDB(LPCTSTR szFilePath, LPCTSTR szSpyName);

	bool SetGamingMode(bool bStatus);

	bool GetRemoveDBData(ULONG ulSpyID, MAX_PIPE_DATA_REG *pMaxPipeDataReg);
	bool GetMailRemoveDBData(ULONG ulSpyID, MAX_PIPE_DATA_REG *pMaxPipeDataReg);

	bool GetScanStatus(LPCTSTR szFilePath, ULONG &ulStatus);
	bool SetScanStatus(LPCTSTR szFilePath, ULONG ulStatus);
};
