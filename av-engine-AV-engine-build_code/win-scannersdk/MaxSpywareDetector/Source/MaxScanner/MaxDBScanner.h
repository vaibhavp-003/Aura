/*======================================================================================
FILE             : MaxDBScanner.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshan Singh Virdi
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
CREATION DATE    : 8/1/2009 6:37:11 PM
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "MaxConstant.h"
#include "MaxCommunicator.h"

#ifndef _STANDALONE_
#include "MaxCommunicator.h"
#else
#include "MaxCommandLineFuctions.h"
#endif

class CMaxDBScanner
{
public:
	CMaxDBScanner(void);
	virtual ~CMaxDBScanner(void);

	static CString m_csScannerID;
	static CMaxCommunicator *m_pMaxWDCommunicator;
	void RestartQuarantine(MAX_PIPE_DATA *sMaxPipeData);
	void StartScanningWithParams(MAX_PIPE_DATA *sMaxPipeData, MAX_PIPE_DATA_CMD *sMAX_PIPE_DATA_CMD);
	static BOOL CALLBACK SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus = eStatus_NotApplicable, const ULONG ulSpyName = 0, 
										HKEY Hive_Type = 0, const WCHAR *strKey = 0, const WCHAR *strValue = 0, 
										int Type_Of_Data = 0, LPBYTE lpbData = 0, int iSizeOfData = 0, 
										REG_FIX_OPTIONS *psReg_Fix_Options = 0, LPBYTE lpbReplaceData = 0, 
										int iSizeOfReplaceData = 0);
#ifdef _STANDALONE_
	HANDLE m_hCMDUIEvent;
    HANDLE m_hUICMDEvent;
	void CheckForUIStartEvent(void);

	static bool m_bPromptToUser;
	static bool m_bLogOnly;
	static bool m_bNoOutputInCMD;
    static bool m_bDeleteTempIE;
	static bool m_bRegistered;
	static bool m_bStartScan;
	static bool m_bPauseScan;
	static bool m_bExitStopEventThread;
	static CMaxCommandLineFuctions m_objCommandLineFuctions;	
	static UINT CheckForStopScanEvent(LPVOID);
	static UINT CheckForUIStartEventThread(LPVOID);
#endif

private:
	HMODULE m_hScanDll;
	static MAXSECUREDISPATCHER m_pMaxSecureDispatcher;
	static MAXSECURECMDLOG m_pMaxSecureCmdLog;
	void InitScannerDLL();
	void DeInitScannerDLL();
	
	static HANDLE				m_hExitEvent;
	static MAX_PIPE_DATA		m_sMaxPipeData;
	static MAX_PIPE_DATA_REG	m_sMaxPipeData_Reg;
	static bool					m_bAutoQuarantine;

#ifndef _STANDALONE_
	static CMaxCommunicator		*m_pMaxCommunicatorScanner;
	static BOOL DeleteTempFilesSEH(LPCTSTR lpDirectoryName, BOOL bSubDir);
	static BOOL DeleteTempFiles(LPCTSTR lpDirectoryName, BOOL bSubDir);
#endif
	static void OnDataReceivedCallBack(LPVOID sMaxPipeData);

	static DWORD m_dwScanCount;
	static DWORD m_dwQSuccessCount;
	static DWORD m_dwQFailedCount;
	static bool	 m_bBackgroundScanner;
};
