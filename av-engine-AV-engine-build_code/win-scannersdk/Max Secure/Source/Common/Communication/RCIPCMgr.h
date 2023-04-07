/*======================================================================================
   FILE				: RCIPCMgr.h (RC IPC Mgr)
   ABSTRACT			: 
   DOCUMENTS		: 
   AUTHOR			: Sunil Apte
   COMPANY			: Aura 
   COPYRIGHT NOTICE	: (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 6Nov2008
   NOTE				: 
   VERSION HISTORY	: 19 Nov 2008, Added overloaded functions for RC Options for Vista Service. Ashwinee J.
====================================================================================== */

#pragma once
#include "RCSharedData.h"
#include "ExecuteProcess.h"

class CRCIPCMgr
{
public:
	CRCIPCMgr(void);
	~CRCIPCMgr(void);

	void SetServer(bool bIsServer = true){ m_bIsServer = bIsServer; }
	bool IsMainServiceStarted(){ return m_bMainServiceIsStarted; }
	void CheckMainServiceStatus();

	void InitCommunication();
	void DeInitCommunication();

public:
	//For holding pointer to shared rc data
	PSHARED_RC_DATA m_pSharedRCData ;
	HANDLE m_hSharedRCData; //handle to shared rc data
	HANDLE m_hRCMutex;

	HANDLE m_hRCQuarantineEvent; //quarantine event handle

	HANDLE m_hRCResultEvent;
	HANDLE m_hRCRecoverEvent;
	HANDLE m_hRCDefraggerEvent;
	HANDLE m_hRCStopEvent;
	HANDLE m_hRCOptionsEvent;

	HANDLE m_hRCSetupEvent;

	// For RC Option Quarntine
	bool ProcessUsingService(const CString &csKey,const CString &csValue,const CString &csData,
					const CString &csWormType,const bool bIsAdminEntry,const CString &csFilePath);
	// For RC Option Startup Entries
	bool ProcessUsingService(const CString &csKey, const CString &csValue, const CString &csData,
		DWORD dwRegType, const CString &csFileName);
	bool ProcessUsingService(const CString &csHive, const CString &csValue, CString &csNewValue);
	// For RC Option Startup Entry, Registry Backup Startup, Restore & Delete.
	bool ProcessUsingService(const CString &csEntry, RC_OPTION nOption);
	// For RC Option Defrag
	bool ProcessUsingService(ULONGLONG &ullSizeBefore, ULONGLONG  &ullSizeAfter, ULONGLONG &ullGain,
		bool bDefrag);
	bool ProcessUsingService();
	// For RC Option Restore Point
	bool ProcessUsingService(const CString &csDESC, CString &csSeqNum, UINT &iRetNo);
	bool ProcessUsingService(const CString &csID,bool bForLiveUpdate = false);
	// For RC Option Registry Backup
	bool ProcessUsingService(RC_OPTION nOption);
	// For RC option Internet Optimize / Roolback
	bool ProcessUsingService(const bool bInetOptiSettings[], RC_OPTION nOption);
private:
	
	PSID m_pEveryoneSID ;
	PSID m_pAdminSID ;
	PACL m_pACL;
	PSECURITY_DESCRIPTOR m_pSD;
	SECURITY_ATTRIBUTES m_sa;

	CExecuteProcess m_objExecuteProcess;
	bool m_bIsServer;
	bool m_bMainServiceIsStarted;
private:
	bool CreateEvent(const CString &csEventName, HANDLE &hEventHandle);
	bool CreateMutex(const CString &csMutexName, HANDLE &hMutexHandle);
	void InitSecurityAttribute();
};
