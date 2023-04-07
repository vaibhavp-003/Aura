#pragma once
#include "ProcessMonitor.h"
#include "MaxRansomMonitor.h"

static BOOL	m_bPauseScan = FALSE;
static BOOL	m_bIsThreadRunning = FALSE;
static BOOL	m_bIsPriorityScanning = FALSE;
static BOOL m_bIsScanInProgress = FALSE;
static BOOL m_bIsWaitingtoFinishScan = FALSE;


struct MAX_SCAN_QUEUE;

struct MAX_SCAN_QUEUE
{
	CString				csFilePath;
	CString				csProcPath;
	CString				csReserve;
	
	DWORD				dwCallType;
	DWORD				dwTypeOfReply;
	DWORD				dwProcID;

	BOOL				bScanDone;
	BOOL				bIsInfected;
	
	MAX_SCAN_QUEUE		*pNextRec;
};
//MAX_SCAN_QUEUE,*LPMAX_SCAN_QUEUE;

class CActMonScanQueueMgr
{
	MAX_SCAN_QUEUE		*m_pScanQue = NULL;
	MAX_SCAN_QUEUE		*m_pScanQueHeader = NULL;
	MAX_SCAN_QUEUE		*m_pScanCurQuePos = NULL;
	CProcessMonitor		*m_pProcMonitor = NULL;
	//CMaxRansomMonitor	m_RansomMonitor;
	CMaxRansomMonitor	*m_pRansomMonitor = NULL;
	
public:
	CActMonScanQueueMgr(void);
	~CActMonScanQueueMgr(void);

	BOOL	SetProcMonHandle(CProcessMonitor *pProcMonitor);
	BOOL	AddInScanQueue(CString csFilePath,CString csProcPath,CString csReserve,DWORD dwCallType, DWORD dwProcID ,DWORD dwReplicationType);
	BOOL	ScanProcessWithPriority(LPCTSTR csFilePath,LPCTSTR csProcPath,LPCTSTR csReserve,DWORD dwCallType, DWORD dwProcID ,DWORD dwReplicationType);
	BOOL	ScanProcessWithPriorityEx(LPCTSTR pszFilePath,LPCTSTR pszProcPath,LPCTSTR pszReserve,DWORD dwCallType, DWORD dwProcID ,DWORD dwReplicationType);
	BOOL	IsPresentInQue(CString csFilePath);
	int		IsAlreadyScaned(CString csFilePath);
	BOOL	ScanFilesInQueue();
	BOOL	ScanFilesInQueueEx();
	BOOL	UnloadScanQue();
	BOOL	LaunchScanQueueThread();

	BOOL	SendFileforRansomCheck(LPCTSTR pszFilePath,LPCTSTR pszProcPath,LPCTSTR pszReserve,DWORD dwCallType, DWORD dwProcID ,DWORD dwReplicationType);

	//static BOOL	m_bPauseScan;
	DWORD	m_dwCounter;
	//static BOOL	m_bIsThreadRunning;

	CCriticalSection	m_objRansCriticalSec;
};
