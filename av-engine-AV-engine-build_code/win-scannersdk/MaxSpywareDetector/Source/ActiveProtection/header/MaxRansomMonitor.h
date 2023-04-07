#pragma once
#include "FileSig.h"
#include "MaxRansBehavMngr.h"
#include "C7zDLL.h"
#include "WhiteSigDBManager.h"//Added 21-12-2020

class CMaxRansomMonitor
{
	CStringArray		m_csIgnoreDigiSig;
	CString				m_csINIFileName;
	CFileSig			*m_pFileSig;
	CMaxRansBehavMngr	*m_pRansWatcher;//m_objRansWatcher;
	BOOL				m_bEnumeratingProcs;

	C7zDLL				m_obj7zDLL;
	CWhiteSigDBManager	*m_pWhiteDB;
	BOOL				m_bSearchInprogress;
	int					m_iWhiteDBStatus;// 0 : Unloaded, 1 : Loading, 2 : Loaded	
	
	bool LoadWhiteDB();

	bool CheckExcludeMonitors(CString csProcPath,CString csAccessFile);
	bool Check4IgnoreDigiSig(CString csProcPath);
	bool IsFilePresentInBlockINI(CString csFilePathName);
	bool TerminateAllSameProc(CString csPeSig);
	bool CollectRansomFile(CString csFileDataPath, CString csParentPath);
	bool IsWhiteProcess(CString csProcPath,CString &csPESig);
	void GetProcessNameByPidEx(ULONG uPid, TCHAR * strFinal);
	bool Check4RandomPattern(CString csProcPath, CString &csPeSig);
	bool MoveToIni(CString csFilePathName, CString &csPeSig);

public:
	CMaxRansomMonitor(void);
	~CMaxRansomMonitor(void);

	BOOL CheckforRansomware(LPCTSTR pszFilePath,LPCTSTR pszProcPath,LPCTSTR pszReserve,DWORD dwCallType, DWORD dwProcID ,DWORD dwReplicationType);

	
};
