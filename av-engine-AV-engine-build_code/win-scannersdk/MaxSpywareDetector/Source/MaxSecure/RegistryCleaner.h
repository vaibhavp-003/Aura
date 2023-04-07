#pragma once
#include "MaxConstant.h"

class CRegistryCleaner
{
	HMODULE					m_hRegistrCleanerDLL;
	PFSTARTSCANNING			m_lpStartScanning;
	PFSTOPSCANNING			m_lpStopScanning;
	PFPERFORMRCQUARANTINE	m_lpPerformRCQuarantine;
	PFPERFORMRCRECOVER		m_lpPerformRCRecover;
	PFADDENTRYINIGNOREDB	m_lpAddEntryInIgnoreDB;
	PFUPDATEREMOVEDB		m_lpUpdateRemoveDB;
	PFANALYZE m_lpAnalyze;
	PFDEFRAG m_lpDefrag;
	PFSTOPANALYZING m_lpStopAnalyzing;
	PFLOADIGNORELIST m_lpLoadIgnoreList;
	PFREMOVEENTRYFROMIGNOREDB m_lpRemoveEntryFromIgnoreDB;
	static SENDVOIDMESSAGETOUI	m_pSendVoidMessageToUI;

	void SetSendMessage(SENDVOIDMESSAGETOUI pSendVoidMessageToUI)
	{
		m_pSendVoidMessageToUI = pSendVoidMessageToUI;
	}

	bool LoadRegistryCleaner();
	
public:
	CRegistryCleaner(void);
	virtual ~CRegistryCleaner(void);

	CWinThread* m_pRCScanning;
	CWinThread* m_pRCAnalyze;
	CWinThread* m_pRCDefrag;

	void StartScanner();
	void StartAnalyze();
	void StartDefrag();

	void ProcessMessage(LPMAX_DISPATCH_MSG lpDispatchMessage, LPVOID lpVoid);
	LPRC_MAX_PIPE_DATA m_pRCMaxPipeData;

	static BOOL CALLBACK SendMessageToUI(SD_Message_Info eTypeOfScanner, const CString &csKey, const CString &csValue, const CString &csData, const bool bIsChild, const int iWormTypeID, const int iThreatLevel, const CString &csDisplayName, const bool bIsAdminEntry, const int iWormCount);
};
