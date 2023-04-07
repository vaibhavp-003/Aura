
#include "pch.h"
#include "ActMonScanQueueMgr.h"
#include "MaxExceptionFilter.h"

DWORD WINAPI ScanFileThread(LPVOID pParam)
{
	CActMonScanQueueMgr *pThisClass =  (CActMonScanQueueMgr *)pParam;
	
	if (pThisClass != NULL)
	{
		pThisClass->ScanFilesInQueueEx();
	}

	//m_bIsThreadRunning = FALSE;

	return 0x0l;
}

CActMonScanQueueMgr::CActMonScanQueueMgr(void)
{
	m_pScanQue = NULL;
	m_pScanQueHeader = NULL;
	m_pProcMonitor = NULL; 
	m_bIsThreadRunning = FALSE;
	m_pScanCurQuePos = NULL;
	m_bPauseScan = FALSE;
	m_dwCounter = 0;
	m_pRansomMonitor = NULL;
}

CActMonScanQueueMgr::~CActMonScanQueueMgr(void)
{
	/*
	if (m_pScanQue != NULL && m_pScanQueHeader != NULL)
	{
		MAX_SCAN_QUEUE		*pTemp = NULL;
		
		pTemp = m_pScanQueHeader;
		while(pTemp)
		{
			m_pScanQueHeader = pTemp->pNextRec;
			delete pTemp;
			pTemp = NULL;

			pTemp = m_pScanQueHeader;
		}
	}
	*/
}

BOOL CActMonScanQueueMgr::UnloadScanQue()
{
	if (m_pScanQue != NULL && m_pScanQueHeader != NULL)
	{
		MAX_SCAN_QUEUE		*pTemp = NULL;
		
		pTemp = m_pScanQueHeader;
		while(pTemp)
		{
			m_pScanQueHeader = pTemp->pNextRec;
			delete pTemp;
			pTemp = NULL;

			pTemp = m_pScanQueHeader;
		}
	}

	return TRUE;
}

BOOL CActMonScanQueueMgr::SetProcMonHandle(CProcessMonitor *pProcMonitor)
{
	m_pProcMonitor = pProcMonitor;

	return TRUE;
}

BOOL CActMonScanQueueMgr::IsPresentInQue(CString csFilePath)
{
	BOOL				bReturn = FALSE;
	MAX_SCAN_QUEUE		*pTemp = NULL;

	TCHAR				szLogLine[1024] = {0x00};


	if (m_pScanQueHeader == NULL)
	{
		return bReturn;
	}

	pTemp = m_pScanQueHeader;

	while(pTemp)
	{
		if ((pTemp->csFilePath.Find(csFilePath) != -1) && (csFilePath.GetLength() == pTemp->csFilePath.GetLength()))
		{
			bReturn = TRUE;
			if (pTemp->bIsInfected == TRUE)
			{
				pTemp->bScanDone = FALSE;
			}
			break;
		}
		pTemp = pTemp->pNextRec;
	}

	return bReturn;
}

//0 : Not Scanner
//1 : Scan Done and Clean
//2 : Scan Done amd Infected
int CActMonScanQueueMgr::IsAlreadyScaned(CString csFilePath)
{
	int					iReturn = 0x00;
	MAX_SCAN_QUEUE		*pTemp = NULL;

	TCHAR				szLogLine[1024] = {0x00};


	if (m_pScanQueHeader == NULL)
	{
		return iReturn;
	}

	pTemp = m_pScanQueHeader;

	while(pTemp)
	{
		if (pTemp->csFilePath.Find(csFilePath) != -1)
		{
			if (pTemp->bScanDone == TRUE)
			{
				if (pTemp->bIsInfected == TRUE)
				{
					iReturn = 2;
				}
				else
				{
					iReturn = 1;
				}
			}
			break;
		}
		pTemp = pTemp->pNextRec;
	}

	return iReturn;
}

BOOL CActMonScanQueueMgr::LaunchScanQueueThread()
{
	if (m_bIsThreadRunning == FALSE && m_bIsPriorityScanning == FALSE)
	{
		DWORD		dwThreadID = 0x00;
		HANDLE		hScanThread = NULL;
		hScanThread =  ::CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)ScanFileThread,(LPVOID)this,0,&dwThreadID);
		/*if (hScanThread != NULL)
		{
			SetThreadPriority(hScanThread, THREAD_PRIORITY_ABOVE_NORMAL);
		}*/
	}
	return TRUE;
}

BOOL CActMonScanQueueMgr::AddInScanQueue(CString csFilePath,CString csProcPath,CString csReserve,DWORD dwCallType, DWORD dwProcID ,DWORD dwReplicationType)
{
	BOOL				bReturn = FALSE;
	MAX_SCAN_QUEUE		*pTemp = NULL;
	
	TCHAR				szLogLine[1024] = {0x00};

	if (csFilePath.IsEmpty() == TRUE)
	{
		return bReturn;
	}

	if (IsPresentInQue(csFilePath) == TRUE)
	{
		LaunchScanQueueThread();
		return bReturn;
	}

	pTemp = new MAX_SCAN_QUEUE;
	if (!pTemp)
	{
		return bReturn;
	}
	pTemp->csFilePath.Format(L"");
	pTemp->csProcPath.Format(L"");
	pTemp->csReserve.Format(L"");
	pTemp->dwCallType = 0x00;
	pTemp->dwProcID = 0x00;
	pTemp->dwTypeOfReply = 0x00;
	pTemp->bIsInfected = FALSE;
	pTemp->bScanDone = FALSE;
	pTemp->pNextRec = NULL;

	pTemp->csFilePath.Format(L"%s",csFilePath.MakeLower());
	pTemp->csProcPath.Format(L"%s",csProcPath.MakeLower());
	pTemp->csReserve.Format(L"%s",csReserve.MakeLower());
	pTemp->dwCallType = dwCallType;
	pTemp->dwProcID = dwProcID;
	pTemp->dwTypeOfReply = dwReplicationType;
	
	if (m_pScanQue == NULL)
	{
		m_pScanQue = m_pScanQueHeader = pTemp;
	}
	else
	{
		m_pScanQue->pNextRec = pTemp;
		m_pScanQue = pTemp;
	}

	//TCHAR	szLogLine[1024] = { 0x00 };
	/*_stprintf(szLogLine, L"ADD IN QUEUE : %s [%s]", csFilePath, csProcPath);
	OutputDebugString(szLogLine);*/
	
	LaunchScanQueueThread();

	return TRUE;
}

//TRUE : Clean File
//FALSE : BLACK File
BOOL CActMonScanQueueMgr::ScanProcessWithPriority(LPCTSTR csFilePath,LPCTSTR csProcPath,LPCTSTR csReserve,DWORD dwCallType, DWORD dwProcID ,DWORD dwReplicationType)
{
	BOOL	bReturn = TRUE;

	__try
	{
		bReturn = ScanProcessWithPriorityEx(csFilePath,csProcPath,csReserve,dwCallType, dwProcID ,dwReplicationType);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught SDActMon::ScanProcessWithPriority()")))
	{
		m_bPauseScan = FALSE;
		m_bIsPriorityScanning = FALSE;
	}
	return bReturn;
}

BOOL CActMonScanQueueMgr::ScanProcessWithPriorityEx(LPCTSTR pszFilePath,LPCTSTR pszProcPath,LPCTSTR pszReserve,DWORD dwCallType, DWORD dwProcID ,DWORD dwReplicationType)
{
	BOOL		bResult = TRUE;
	TCHAR		szLogLine[1024] = {0x00};
	CString		csFilePath(L""),csProcPath(L""),csReserve(L"");

	m_bPauseScan = TRUE;
	
	if (pszFilePath == NULL)
	{
		return bResult;
	}
	csFilePath.Format(L"%s",pszFilePath);
	if (pszProcPath  != NULL)
	{
		csProcPath.Format(L"%s",pszProcPath);
	}

	if (pszReserve  != NULL)
	{
		csReserve.Format(L"%s",pszReserve);
	}

	m_bIsPriorityScanning = TRUE;

	int	iResult = IsAlreadyScaned(csFilePath);
	if (iResult == 1)//Already Scanned
	{
		m_bPauseScan = FALSE;
		
		m_bIsPriorityScanning = FALSE;

		return TRUE;
	}
	else if(iResult == 2)
	{
		m_bPauseScan = FALSE;
		
		m_bIsPriorityScanning = FALSE;
		return FALSE;
	}

	while(1)
	{
		if (m_bIsThreadRunning == TRUE)
		{
			Sleep(5);
		}
		else
		{
			break;
		}
	}

	
	iResult = IsAlreadyScaned(csFilePath);
	if (iResult == 1)
	{
		m_bPauseScan = FALSE;
		
		m_bIsPriorityScanning = FALSE;

		return TRUE;
	}
	else if(iResult == 2)
	{
		m_bPauseScan = FALSE;
		
		m_bIsPriorityScanning = FALSE;
		return FALSE;
	}
	
	if (m_bIsThreadRunning == FALSE)
	{
		try
		{
			MAX_SCAN_QUEUE *pTemp = new MAX_SCAN_QUEUE;
			if (!pTemp)
			{
				m_bPauseScan = FALSE;
				m_bIsPriorityScanning = FALSE;
				return bResult;
			}
			pTemp->csFilePath.Format(L"");
			pTemp->csProcPath.Format(L"");
			pTemp->csReserve.Format(L"");
			pTemp->dwCallType = 0x00;
			pTemp->dwProcID = 0x00;
			pTemp->dwTypeOfReply = 0x00;
			pTemp->bIsInfected = FALSE;
			pTemp->bScanDone = FALSE;
			pTemp->pNextRec = NULL;

			pTemp->csFilePath.Format(L"%s",csFilePath.MakeLower());
			pTemp->csProcPath.Format(L"%s",csProcPath.MakeLower());
			pTemp->csReserve.Format(L"%s",csReserve.MakeLower());
			pTemp->dwCallType = dwCallType;
			pTemp->dwProcID = dwProcID;
			pTemp->dwTypeOfReply = dwReplicationType;

			if (m_pScanQue == NULL)
			{
				m_pScanQue = m_pScanQueHeader = pTemp;
			}
			else
			{
				m_pScanQue->pNextRec = pTemp;
				m_pScanQue = pTemp;
			}

			bool				bStopEnum = false;
			DWORD				dwFileSize = 0;
			MAX_SCANNER_INFO	oScannerInfo = {0};

			oScannerInfo.eMessageInfo = Process;
			oScannerInfo.eScannerType = Scanner_Type_Max_ProcScan;
			if(pTemp->dwTypeOfReply == 1 || pTemp->dwTypeOfReply == 2)
			{
				oScannerInfo.ulProcessIDToScan = (ULONG)pTemp->dwProcID;
				oScannerInfo.ulReplicatingProcess = pTemp->dwTypeOfReply;
			}

			_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), pTemp->csFilePath);
			_tcscpy_s(oScannerInfo.szContainerFileName, _countof(oScannerInfo.szFileToScan), pTemp->csProcPath);

			if (m_pProcMonitor)
			{
				//pTemp->bIsInfected = m_pProcMonitor->CheckProcess(&oScannerInfo, pTemp->dwTypeOfReply, bStopEnum);
				
				//m_objRansCriticalSec.Lock();
				pTemp->bIsInfected = m_pProcMonitor->CheckProcess(&oScannerInfo, pTemp->dwCallType, bStopEnum);
				//m_objRansCriticalSec.Unlock();
				if (pTemp->bIsInfected)
				{
					bResult = FALSE;
				}
				else
				{
					//Send File for Ransomeware Scanning
					//bResult = SendFileforRansomCheck(pTemp->csFilePath, pTemp->csReserve, pTemp->csReserve, pTemp->dwCallType, pTemp->dwProcID, pTemp->dwTypeOfReply);
				}
				pTemp->bScanDone = TRUE;
			}
		}
		catch(...)
		{
			m_bPauseScan = FALSE;
		}
	}

	
	m_bPauseScan = FALSE;
	
	m_bIsPriorityScanning = FALSE;

	LaunchScanQueueThread();

	return bResult;
}

BOOL CActMonScanQueueMgr::ScanFilesInQueueEx()
{
	BOOL	bReturn = TRUE;
	__try
	{
		if (m_pProcMonitor->m_bIsMonitoring == true && m_bIsThreadRunning == FALSE)
		{
			ScanFilesInQueue();
		}
		
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught SDActMon::ScanFilesInQueue()")))
	{
		if (m_pScanCurQuePos)
		{
			m_pScanCurQuePos->bScanDone == TRUE;
		}
		m_bIsThreadRunning = FALSE;
	}
	return bReturn;
}

BOOL CActMonScanQueueMgr::ScanFilesInQueue()
{
	BOOL	bResult = FALSE;
	TCHAR	szLogLine[1024] = {0x00};
	int		iLoopCnt = 0x00;


	//MAX_SCAN_QUEUE		*pTemp = NULL;

	if (m_pScanQueHeader == NULL)
	{
		m_bIsThreadRunning = FALSE;
		return bResult;
	}

	if (m_bIsPriorityScanning == TRUE)
	{
		while (1)
		{
			Sleep(50);
			if (m_bIsPriorityScanning == FALSE)
			{
				break;
			}
		}
	}
	if (m_bIsScanInProgress == TRUE)
	{
		while (m_bIsScanInProgress)
		{
			Sleep(50);
			iLoopCnt++;
			if (m_bIsScanInProgress == FALSE)
			{
				//_stprintf(szLogLine, L"ActiveProtection : TIMEOUT FINISHED SCAN");
				//OutputDebugString(szLogLine);
				break;
			}
		}
	}

	m_bIsThreadRunning = TRUE;

	if (m_pScanQueHeader)
	{
		m_pScanCurQuePos = m_pScanQueHeader;
	}
	else
	{
		m_bIsThreadRunning = FALSE;
		return bResult;
	}
	

	while(m_pScanCurQuePos)
	{
		if (m_pProcMonitor->m_bIsMonitoring == false)
		{
			break;
		}
		if (m_bPauseScan == TRUE)
		{

			break;
		}
		try
		{
			if (m_pScanCurQuePos->bScanDone == FALSE)
			{
				if (m_pScanCurQuePos->dwCallType == 21) //RANSOMWARE call only
				{
					SendFileforRansomCheck(m_pScanCurQuePos->csFilePath, m_pScanCurQuePos->csReserve, m_pScanCurQuePos->csReserve, m_pScanCurQuePos->dwCallType, m_pScanCurQuePos->dwProcID, m_pScanCurQuePos->dwTypeOfReply);
				}
				else
				{
					int		iLoopCnt = 0x00;
					if (m_bIsScanInProgress == TRUE)
					{
						if (m_bIsWaitingtoFinishScan == FALSE)
						{
							m_bIsWaitingtoFinishScan = TRUE;
						}
						else
						{
							return TRUE;
						}
						while (1)
						{
							Sleep(50);
							iLoopCnt++;
							if (m_bIsScanInProgress == FALSE)
							{
								break;
							}
							
						}
					}
					
					m_bIsScanInProgress = TRUE;
					bool				bStopEnum = false;
					DWORD				dwFileSize = 0;
					MAX_SCANNER_INFO	oScannerInfo = { 0 };

					oScannerInfo.eMessageInfo = Process;
					oScannerInfo.eScannerType = Scanner_Type_Max_ProcScan;
					if (m_pScanCurQuePos->dwTypeOfReply == 0x00 || m_pScanCurQuePos->dwTypeOfReply == 1 || m_pScanCurQuePos->dwTypeOfReply == 2)
					{
						oScannerInfo.ulProcessIDToScan = (ULONG)m_pScanCurQuePos->dwProcID;
						oScannerInfo.ulReplicatingProcess = m_pScanCurQuePos->dwTypeOfReply;
					}

					_tcscpy_s(oScannerInfo.szFileToScan, _countof(oScannerInfo.szFileToScan), m_pScanCurQuePos->csFilePath);
					//_tcscpy_s(oScannerInfo.szContainerFileName, _countof(oScannerInfo.szFileToScan), m_pScanCurQuePos->csProcPath);

					//m_objRansCriticalSec.Lock();
					m_pScanCurQuePos->bIsInfected = m_pProcMonitor->CheckProcess(&oScannerInfo, m_pScanCurQuePos->dwCallType, bStopEnum);
					//m_objRansCriticalSec.Unlock();
					m_bIsScanInProgress = FALSE;
					if (m_pScanCurQuePos->bIsInfected)
					{
						if (m_pScanCurQuePos->dwCallType == 25) //const ULONG CALL_TYPE_N_CREATE = 25; 
						{
							CString csTitle = _T("Network Infection Found");
							m_pProcMonitor->DisplayNotification(csTitle + ACTMON_DATA_SEPERATOR + m_pScanCurQuePos->csReserve);
						}
					}
					else
					{
						//Send File for Ransomeware Scanning
						SendFileforRansomCheck(m_pScanCurQuePos->csFilePath, m_pScanCurQuePos->csReserve, m_pScanCurQuePos->csReserve, m_pScanCurQuePos->dwCallType, m_pScanCurQuePos->dwProcID, m_pScanCurQuePos->dwTypeOfReply);
					}
				}

				m_pScanCurQuePos->bScanDone = TRUE;
				Sleep(5);
			}
		}
		catch(...)
		{
			break;
		}
		if (m_pScanCurQuePos->pNextRec)
		{
			m_pScanCurQuePos = m_pScanCurQuePos->pNextRec;
		}
		else
		{
			break;
		}
	}

	Sleep(10);
	m_bIsThreadRunning = FALSE;
	return TRUE;
}

BOOL CActMonScanQueueMgr::SendFileforRansomCheck(LPCTSTR pszFilePath,LPCTSTR pszProcPath,LPCTSTR pszReserve,DWORD dwCallType, DWORD dwProcID ,DWORD dwReplicationType)
{
	BOOL		bAllowEntry = TRUE;


	if (m_pRansomMonitor == NULL)
	{
		m_pRansomMonitor = new CMaxRansomMonitor;
	}

	m_objRansCriticalSec.Lock();

	bAllowEntry = m_pRansomMonitor->CheckforRansomware(pszFilePath, pszProcPath, pszReserve, dwCallType, dwProcID ,dwReplicationType);
	if (bAllowEntry == FALSE)
	{
		CRegistry objReg;
		DWORD dw = 0;
		objReg.Get(CSystemInfo::m_csActMonRegKey, SHOWPROCPOPUP, dw, HKEY_LOCAL_MACHINE);
		if(dw)
		{
			CString csTitle = _T("File Blocked (File Monitor)");
			m_pProcMonitor->DisplayNotification( csTitle + ACTMON_DATA_SEPERATOR + pszProcPath);
		}
	}

	m_objRansCriticalSec.Unlock();
	
	return bAllowEntry;
}