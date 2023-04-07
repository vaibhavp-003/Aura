/*======================================================================================
   FILE				: RCSharedData.h
   ABSTRACT			: This header file is used to declare Shared object name and handle
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
   VERSION HISTORY	: 21 Nov 2008 Made changes for adding various RC Options. Ashwinee J.
====================================================================================== */

#pragma once

#define RC_MUTEX_NAME					L"Global\\RC_MUTEX"
#define RC_SHAREDMEM_NAME				L"Global\\RC_SM"

#define RC_QUARANTINE_EVENT_NAME		L"Global\\RC_QUARANTINE_EVENT"

#define RC_RESULT_EVENT_NAME			L"Global\\RC_RESULT_EVENT"
#define RC_RECOVER_EVENT_NAME			L"Global\\RC_RECOVER_EVENT"
#define RC_DEFRAGGER_EVENT_NAME			L"Global\\RC_DEFRAGGER_EVENT"
#define RC_STOP_EVENT_NAME				L"Global\\RC_STOP_EVENT"
#define RC_OPTIONS_EVENT_NAME			L"Global\\RC_OPTIONS_EVENT"
#define RC_SETUP_EVENT_NAME				L"Global\\RC_SETUP_EVENT"


//this enum will be used to hold RC Options exact function selected
enum RC_OPTION
{
	STARTUP_CHANGE,
	STARTUP_INSERT,
	STARTUP_DELETE,
	STARTUP_EXPORT,
	IO_OPTIMIZE,
	IO_ROLLBACK,
	// For Restore Point functionality
	RESTOREPOINT_CREATE,
	RESTOREPOINT_REMOVE,
	// For Registry Backup functionality
	REGISTRYBACKUP_CHECKSPACE,
	REGISTRYBACKUP_START,
	REGISTRYBACKUP_RESTORE,
	REGISTRYBACKUP_DELETE
};
const int MAX_RC_COMM_SIZE = 500;
//Shared structure to hold IPC shared data for RC functionality.
typedef struct
{
	TCHAR		m_szKey[500];
	TCHAR		m_szValue[500];
	TCHAR		m_szData[500];
	TCHAR		m_szWormType[50];
	bool		m_bIsAdminEntry;

	bool		m_bResult;

	DWORD		m_dwRegType;
	TCHAR		m_szFileName[256];  // Used for Registry backup also.
	//For Defragger functionality
	ULONGLONG	m_ullSizeBefore;
	ULONGLONG	m_ullSizeAfter;
	ULONGLONG	m_ullGain;
	bool		m_bDefrag;
	//
	RC_OPTION	m_nOption;
	//For Startup List : Change functionality
	TCHAR		m_szHive[100];
	TCHAR		m_szNewValue[500];
	//
	//For Internet Optimizer
	bool		m_bInternetOptimizerSettings[MAX_IO_SETTINGS];
	//
	// For Restore Point functionality
    UINT 		m_iRetNo;
	TCHAR	 	m_szDesc[128];
	TCHAR		m_szSeqNum[50];
	TCHAR  		m_szID[128];
	// For Clipboard delete
	HWND		m_hMainWnd;

}SHARED_RC_DATA,*PSHARED_RC_DATA;
