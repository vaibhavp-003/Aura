#pragma once
#include "pch.h"
#include "RemoveDB.h"
#include "SDSystemInfo.h"
#include "MaxCommunicator.h"
#include "MaxConstant.h"
#include "MaxPipes.h"
#include "S2U.h"
#include "ThreatInfo.h"
#include "afxmt.h"

#define SD_DB_REMOVE			_T("Quarantine\\QuarantineRemove.DB")

typedef struct _QuarantainData
{
	LONG		iIndex;
	wchar_t		szSpyName[MAX_PATH];
	DWORD		dwSpyID;
	wchar_t		szThreatFilePath[MAX_PATH];
	wchar_t		szBackupFilePath[MAX_PATH];
	wchar_t		szDateTime[MAX_PATH];
	//wchar_t		szThreatType[MAX_PATH];
	int			iUseSpyID;
	int			iSpyNameParent;

} QuarantainData;

enum E_RECOVER_SPYWARE_ACTION
{
	E_ACTION_NONE = 0,
	E_ACTION_LOADING_SPYWARE_DB,
	E_ACTION_RECOVER,
	E_ACTION_EXCLUDE_RECOVER,
	E_ACTION_DELETE
};

class CRecoverRemovedSpywares
{
public:
	CRecoverRemovedSpywares();
	~CRecoverRemovedSpywares();

public:
	void OnClickedLoadQuarantineDB(QuarantainData* pQuarantainArray, int size);
	void RefreshUI();
	void ReadQuarantineData(QuarantainData* pQuarantainArray, int size);
	bool ManageRecoverDB();
	void EnumFolder(CString csFolderPath);
	bool DecryptAndGetFileName(CString csTempFileName, CString& csFileName);
	void ShowQuarantineData(MAX_PIPE_DATA_REG& sMaxPipeDataReg, UINT64 u64DateTime);
	bool GetThreatInfo(ULONG ulSpyName, CString& csSpyName, BYTE& bThreatIndex, CString& csHelpInfo, CString csKeyValue, int iTypeId);
	void FillQrtnData(MAX_PIPE_DATA_REG& sMaxPipeDataReg, QuarantainData& sQuarantineData);
	CString ConvertULONGtoDate(UINT64 u64DateTime);
	CThreatInfo m_objThreatInfo;
	int GetQuarantainDBCount();

	void PrepareValueForDispaly(MAX_PIPE_DATA_REG& sMaxPipeDataReg, WCHAR* strValue, int iSizeOfBuffer);
	CString GetThreatType(SD_Message_Info eWormType);

	void OnClickedRecoverFiles(QuarantainData* pQuarantainArray, int QuarantainArraySize, int iRecoverLength, int* ptrRecoveredIndexArray, int iAction);
	void StartRecoveringSpyware(QuarantainData* pQuarantainArray, int QuarantainArraySize, int iRecoverLength, int* ptrRecoveredIndexArray);
	bool IsRestoreDrivePresent(LPCTSTR pszRestorePath);
	void PostMessageToProtection(UINT message, WPARAM wParam, LPARAM lParam);
	void PauseActiveProtection(bool bStart);
	void ShutdownRecoveryScanner();

public:
	int m_iAction;
	CMaxCommunicator* m_pObjMaxCommunicator;
private:
	int m_iUIRefreshed;
	bool m_bThreadProcessing;
	CS2U	m_objQurTempFilesList;

	CCriticalSection	m_objRansCriticalSec;
};