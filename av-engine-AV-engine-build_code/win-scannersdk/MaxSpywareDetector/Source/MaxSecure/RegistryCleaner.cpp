#include "pch.h"
#include "RegistryCleaner.h"

SENDVOIDMESSAGETOUI CRegistryCleaner::m_pSendVoidMessageToUI	= NULL;

UINT StartRCScanning(LPVOID lpVoid);
UINT StartRCAnalyze(LPVOID lpVoid);
UINT StartRCDefrag(LPVOID lpVoid);

CRegistryCleaner::CRegistryCleaner(void)
{
	m_hRegistrCleanerDLL	= NULL;
	m_lpStartScanning		= NULL;
	m_lpStopScanning		= NULL;
	m_lpPerformRCQuarantine = NULL;
	m_lpAddEntryInIgnoreDB	= NULL;
	m_lpUpdateRemoveDB		= NULL;
	m_lpPerformRCRecover	= NULL;
	m_pRCScanning = NULL;
	m_pRCAnalyze = NULL;
	m_pRCDefrag = NULL;
}

CRegistryCleaner::~CRegistryCleaner(void)
{
	if(m_pRCScanning)
	{
		SuspendThread(m_pRCScanning->m_hThread);
		TerminateThread(m_pRCScanning->m_hThread, 0);
		m_pRCScanning = NULL;
	}
	if(m_pRCAnalyze)
	{
		SuspendThread(m_pRCAnalyze->m_hThread);
		TerminateThread(m_pRCAnalyze->m_hThread, 0);
		m_pRCAnalyze = NULL;
	}
	if(m_pRCDefrag)
	{
		SuspendThread(m_pRCDefrag->m_hThread);
		TerminateThread(m_pRCDefrag->m_hThread, 0);
		m_pRCDefrag = NULL;
	}
	if(m_hRegistrCleanerDLL)
	{
		m_lpStartScanning		= NULL;
		m_lpStopScanning		= NULL;
		m_lpPerformRCQuarantine = NULL;
		m_lpAddEntryInIgnoreDB	= NULL;
		m_lpUpdateRemoveDB		= NULL;
		m_lpPerformRCRecover	= NULL;

		FreeLibrary(m_hRegistrCleanerDLL);
		m_hRegistrCleanerDLL = NULL;
	}
}

void CRegistryCleaner::ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid)
{
	if(!m_hRegistrCleanerDLL)	//Is the DLL Loaded?
	{
		if(!LoadRegistryCleaner())
		{
			return;
		}
	}

	SetSendMessage(lpDispatchMessage->pSendVoidMessageToUI);
	m_pRCMaxPipeData = (LPRC_MAX_PIPE_DATA)lpVoid;
	if(m_pRCMaxPipeData->eMessageInfo == RC_StartScan)
	{
		m_pRCScanning = AfxBeginThread(StartRCScanning,this);
		//m_lpStartScanning((RC_SENDMESSAGETOUI)SendMessageToUI, m_pRCMaxPipeData);
	}
	else if(m_pRCMaxPipeData->eMessageInfo == RC_StopScan)
	{
		m_lpStopScanning(true);
	}
	else if(m_pRCMaxPipeData->eMessageInfo == RC_Quarantine)
	{
		m_lpPerformRCQuarantine((RC_SENDMESSAGETOUI)SendMessageToUI, m_pRCMaxPipeData);
	}
	else if(m_pRCMaxPipeData->eMessageInfo == RC_Recover)
	{
		m_lpPerformRCRecover((RC_SENDMESSAGETOUI)SendMessageToUI, m_pRCMaxPipeData);
	}
	else if(m_pRCMaxPipeData->eMessageInfo == RC_UpdateRecover)
	{
		m_lpUpdateRemoveDB(m_pRCMaxPipeData->strKey, m_pRCMaxPipeData->strValue, m_pRCMaxPipeData->strData, m_pRCMaxPipeData->strBackupFileName, m_pRCMaxPipeData->strDisplayName);
	}
	else if(m_pRCMaxPipeData->eMessageInfo == RC_Ignore_Entries)
	{
		m_lpAddEntryInIgnoreDB((RC_SENDMESSAGETOUI)SendMessageToUI, m_pRCMaxPipeData);
	}
	else if(m_pRCMaxPipeData->eMessageInfo == RC_Ignoring)
	{
		m_lpLoadIgnoreList((RC_SENDMESSAGETOUI)SendMessageToUI, m_pRCMaxPipeData);
	}
	else if(m_pRCMaxPipeData->eMessageInfo == RC_Ignore_Recover)
	{
		m_lpRemoveEntryFromIgnoreDB((RC_SENDMESSAGETOUI)SendMessageToUI, m_pRCMaxPipeData);
	}
	else if(m_pRCMaxPipeData->eMessageInfo == RC_Analyze)
	{
		m_pRCAnalyze = AfxBeginThread(StartRCAnalyze,this);
		//LPRC_DEFRAG_PIPE_DATA pRCDefragPipeData = (LPRC_DEFRAG_PIPE_DATA) m_pRCMaxPipeData;
		//pRCDefragPipeData->bStatus =  m_lpAnalyze(pRCDefragPipeData->m_ullSizeBefore,pRCDefragPipeData->m_ullSizeAfter,pRCDefragPipeData->m_ullGain);
		//pRCDefragPipeData->eMessageInfo = RC_Finished_Analyze;
		//m_pSendVoidMessageToUI(pRCDefragPipeData,sizeof(RC_DEFRAG_PIPE_DATA));
	}
	else if(m_pRCMaxPipeData->eMessageInfo == RC_Defrag)
	{
		m_pRCDefrag = AfxBeginThread(StartRCDefrag,this);
		//LPRC_DEFRAG_PIPE_DATA pRCDefragPipeData = (LPRC_DEFRAG_PIPE_DATA) m_pRCMaxPipeData;
		//pRCDefragPipeData->bStatus =  m_lpDefrag(pRCDefragPipeData->m_ullSizeBefore,pRCDefragPipeData->m_ullSizeAfter,pRCDefragPipeData->m_ullGain);
		//pRCDefragPipeData->eMessageInfo = RC_Finished_Defrag;
		//m_pSendVoidMessageToUI(pRCDefragPipeData,sizeof(RC_DEFRAG_PIPE_DATA));
	}
	else if(m_pRCMaxPipeData->eMessageInfo == RC_StopDefrag)
	{
		LPRC_DEFRAG_PIPE_DATA pRCDefragPipeData = (LPRC_DEFRAG_PIPE_DATA) m_pRCMaxPipeData;
		m_lpStopAnalyzing(pRCDefragPipeData);
		pRCDefragPipeData->eMessageInfo = RC_Finished_Stopping ;		
		m_pSendVoidMessageToUI(pRCDefragPipeData,sizeof(RC_DEFRAG_PIPE_DATA));
	}
}

bool CRegistryCleaner::LoadRegistryCleaner()
{
	m_hRegistrCleanerDLL = LoadLibrary(L"RegistryScanner.DLL");

	if(!m_hRegistrCleanerDLL)
	{
		return false;
	}

	m_lpStartScanning = (PFSTARTSCANNING)GetProcAddress(m_hRegistrCleanerDLL, "StartScanning");
	if(!m_lpStartScanning)
	{
		AddLogEntry(_T("GetProcAddress failed for StartScanning."));
		FreeLibrary(m_hRegistrCleanerDLL);
		m_hRegistrCleanerDLL = NULL;
		return false;
	}

	m_lpStopScanning = (PFSTOPSCANNING)GetProcAddress(m_hRegistrCleanerDLL, "StopScanning");
	if(!m_lpStopScanning)
	{
		AddLogEntry(_T("GetProcAddress failed for StopScanning."));
		m_lpStartScanning = NULL;
		FreeLibrary(m_hRegistrCleanerDLL);
		m_hRegistrCleanerDLL = NULL;
		return false;
	}
	
	m_lpPerformRCQuarantine = (PFPERFORMRCQUARANTINE)GetProcAddress(m_hRegistrCleanerDLL, "PerformRCQuarantine");
	if(!m_lpPerformRCQuarantine)
	{
		AddLogEntry(_T("GetProcAddress failed for PerformRCQuarantine."));
		m_lpStartScanning = NULL;
		m_lpStopScanning = NULL;
		FreeLibrary(m_hRegistrCleanerDLL);
		m_hRegistrCleanerDLL = NULL;
		return false;
	}

	m_lpPerformRCRecover = (PFPERFORMRCRECOVER)GetProcAddress(m_hRegistrCleanerDLL, "PerformRCRecover");
	if(!m_lpPerformRCRecover)
	{
		AddLogEntry(_T("GetProcAddress failed for PerformRCRecover."));
		m_lpStartScanning = NULL;
		m_lpStopScanning = NULL;
		m_lpPerformRCQuarantine = NULL;
		FreeLibrary(m_hRegistrCleanerDLL);
		m_hRegistrCleanerDLL = NULL;
		return false;
	}

	m_lpAddEntryInIgnoreDB = (PFADDENTRYINIGNOREDB)GetProcAddress(m_hRegistrCleanerDLL, "AddEntryInIgnoreDB");
	if(!m_lpAddEntryInIgnoreDB)
	{
		AddLogEntry(_T("GetProcAddress failed for AddEntryInIgnoreDB."));
		m_lpStartScanning = NULL;
		m_lpStopScanning = NULL;
		m_lpPerformRCQuarantine = NULL;
		m_lpPerformRCRecover = NULL;
		FreeLibrary(m_hRegistrCleanerDLL);
		m_hRegistrCleanerDLL = NULL;
		return false;
	}
	m_lpUpdateRemoveDB = (PFUPDATEREMOVEDB)GetProcAddress(m_hRegistrCleanerDLL, "UpdateRemoveDB");
	if(!m_lpAddEntryInIgnoreDB)
	{
		AddLogEntry(_T("GetProcAddress failed for UpdateRemoveDB."));
		m_lpStartScanning = NULL;
		m_lpStopScanning = NULL;
		m_lpPerformRCQuarantine = NULL;
		m_lpPerformRCRecover = NULL;
		m_lpAddEntryInIgnoreDB = NULL;
		FreeLibrary(m_hRegistrCleanerDLL);
		m_hRegistrCleanerDLL = NULL;
		return false;
	}
	m_lpAnalyze = (PFANALYZE)GetProcAddress(m_hRegistrCleanerDLL, "Analyze");
	if(!m_lpAnalyze)
	{
		AddLogEntry(_T("GetProcAddress failed for Analyze."));
		m_lpStartScanning = NULL;
		m_lpStopScanning = NULL;
		m_lpPerformRCQuarantine = NULL;
		m_lpPerformRCRecover = NULL;
		m_lpAddEntryInIgnoreDB = NULL;
		m_lpAnalyze = NULL;
		FreeLibrary(m_hRegistrCleanerDLL);
		m_hRegistrCleanerDLL = NULL;
		return false;
	}
	m_lpDefrag = (PFDEFRAG)GetProcAddress(m_hRegistrCleanerDLL, "Defrag");
	if(!m_lpDefrag)
	{
		AddLogEntry(_T("GetProcAddress failed for Defrag."));
		m_lpStartScanning = NULL;
		m_lpStopScanning = NULL;
		m_lpPerformRCQuarantine = NULL;
		m_lpPerformRCRecover = NULL;
		m_lpAddEntryInIgnoreDB = NULL;
		m_lpAnalyze = NULL;
		FreeLibrary(m_hRegistrCleanerDLL);
		m_hRegistrCleanerDLL = NULL;
		return false;
	}
	m_lpLoadIgnoreList = (PFLOADIGNORELIST)GetProcAddress(m_hRegistrCleanerDLL, "LoadIgnoreList");
	if(!m_lpLoadIgnoreList)
	{
		AddLogEntry(_T("GetProcAddress failed for Defrag."));
		m_lpStartScanning = NULL;
		m_lpStopScanning = NULL;
		m_lpPerformRCQuarantine = NULL;
		m_lpPerformRCRecover = NULL;
		m_lpAddEntryInIgnoreDB = NULL;
		m_lpAnalyze = NULL;
		FreeLibrary(m_hRegistrCleanerDLL);
		m_hRegistrCleanerDLL = NULL;
		m_lpLoadIgnoreList = NULL;
		return false;
	}
	m_lpRemoveEntryFromIgnoreDB = (PFREMOVEENTRYFROMIGNOREDB)GetProcAddress(m_hRegistrCleanerDLL, "RemoveEntryFromIgnoreDB");
	if(!m_lpRemoveEntryFromIgnoreDB)
	{
		AddLogEntry(_T("GetProcAddress failed for Defrag."));
		m_lpStartScanning = NULL;
		m_lpStopScanning = NULL;
		m_lpPerformRCQuarantine = NULL;
		m_lpPerformRCRecover = NULL;
		m_lpAddEntryInIgnoreDB = NULL;
		m_lpAnalyze = NULL;
		FreeLibrary(m_hRegistrCleanerDLL);
		m_hRegistrCleanerDLL = NULL;
		m_lpLoadIgnoreList = NULL;
		m_lpRemoveEntryFromIgnoreDB = NULL;
		return false;
	}

	return true;
}

BOOL CRegistryCleaner::SendMessageToUI(SD_Message_Info eTypeOfScanner, const CString &csKey, const CString &csValue, const CString &csData, const bool bIsChild, const int iWormTypeID, const int iThreatLevel, const CString &csDisplayName, const bool bIsAdminEntry, const int iWormCount)
{
	RC_MAX_PIPE_DATA oRCMaxPipeData	= {0};
	oRCMaxPipeData.eMessageInfo = eTypeOfScanner;

	oRCMaxPipeData.bIsChild = bIsChild;
	oRCMaxPipeData.bIsAdminEntry = bIsAdminEntry;
	oRCMaxPipeData.iThreatLevel = iThreatLevel;
	oRCMaxPipeData.iWormCount = iWormCount;
	oRCMaxPipeData.iWormTypeID = iWormTypeID;
	_tcscpy_s(oRCMaxPipeData.strKey, (LPCTSTR)csKey);
	_tcscpy_s(oRCMaxPipeData.strValue, (LPCTSTR)csValue);
	_tcscpy_s(oRCMaxPipeData.strData, (LPCTSTR)csData);
	_tcscpy_s(oRCMaxPipeData.strDisplayName, (LPCTSTR)csDisplayName);

	return m_pSendVoidMessageToUI(&oRCMaxPipeData, sizeof(RC_MAX_PIPE_DATA));
}

UINT StartRCScanning (LPVOID lpVoid)
{
	CRegistryCleaner *pThis = (CRegistryCleaner*)lpVoid;
	if(pThis)
	{
		pThis->StartScanner();
		pThis->m_pRCScanning = NULL;
	}
	return 0;
}

void CRegistryCleaner::StartScanner()
{
	if(m_lpStartScanning)
	{
		//AddLogEntry(L"Starting Registry Cleaner");
		LPRC_MAX_PIPE_DATA pRCMaxPipeData = new RC_MAX_PIPE_DATA;
		memcpy(pRCMaxPipeData, m_pRCMaxPipeData, sizeof(RC_MAX_PIPE_DATA));
		m_lpStartScanning((RC_SENDMESSAGETOUI)SendMessageToUI, pRCMaxPipeData);
		delete pRCMaxPipeData;
		pRCMaxPipeData = NULL;
	}
}

UINT StartRCAnalyze(LPVOID lpVoid)
{
	CRegistryCleaner *pThis = (CRegistryCleaner*)lpVoid;
	if(pThis)
	{
		pThis->StartAnalyze();
		pThis->m_pRCAnalyze = NULL;
	}
	return 0;
}

void CRegistryCleaner::StartAnalyze()
{
	if(m_lpAnalyze)
	{
		AddLogEntry(L"Starting Registry Analyze");
		LPRC_DEFRAG_PIPE_DATA pRCDefragPipeData = new RC_DEFRAG_PIPE_DATA;
		memcpy(pRCDefragPipeData, m_pRCMaxPipeData, sizeof(RC_DEFRAG_PIPE_DATA));
		pRCDefragPipeData->bStatus =  m_lpAnalyze(pRCDefragPipeData->m_ullSizeBefore, pRCDefragPipeData->m_ullSizeAfter, pRCDefragPipeData->m_ullGain);
		pRCDefragPipeData->eMessageInfo = RC_Finished_Analyze;
		m_pSendVoidMessageToUI(pRCDefragPipeData, sizeof(RC_DEFRAG_PIPE_DATA));
		delete pRCDefragPipeData;
		pRCDefragPipeData = NULL;
	}
}


UINT StartRCDefrag(LPVOID lpVoid)
{
	CRegistryCleaner *pThis = (CRegistryCleaner*)lpVoid;
	if(pThis)
	{
		pThis->StartDefrag();
		pThis->m_pRCDefrag = NULL;
	}
	return 0;
}

void CRegistryCleaner::StartDefrag()
{
	if(m_lpDefrag)
	{
		AddLogEntry(L"Starting Registry Defrag");
		LPRC_DEFRAG_PIPE_DATA pRCDefragPipeData = new RC_DEFRAG_PIPE_DATA;
		memcpy(pRCDefragPipeData, m_pRCMaxPipeData, sizeof(RC_DEFRAG_PIPE_DATA));
		pRCDefragPipeData->bStatus =  m_lpDefrag(pRCDefragPipeData->m_ullSizeBefore, pRCDefragPipeData->m_ullSizeAfter, pRCDefragPipeData->m_ullGain);
		pRCDefragPipeData->eMessageInfo = RC_Finished_Defrag;
		m_pSendVoidMessageToUI(pRCDefragPipeData,sizeof(RC_DEFRAG_PIPE_DATA));
		delete pRCDefragPipeData;
		pRCDefragPipeData = NULL;
	}
}