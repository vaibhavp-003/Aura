/*======================================================================================
FILE             : SDScanner.h
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
CREATION DATE    : 8/1/2009 6:47:14 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include "SpyScanner.h"
#include "MaxScanner.h"
#include "ThreatManager.h"

class CSDScannerApp : public CWinApp
{
public:
	CSDScannerApp();
	void StartScanning(SENDMESSAGETOUIMS lpSendMessaegToUI, SCAN_OPTIONS &sScanOptions,
						const TCHAR *strDrivesToScan, CS2U* pobjFilesList = NULL,
						CS2U* pobjFoldersList = NULL, bool bScanReferences = false);
	void StopScanning();
	void InitializeDLL(SENDMESSAGETOUIMS lpSendMessaegToUI, bool bIsUSBScan = false, bool bIsMachineLearning = false, LPMAX_PIPE_DATA_CMD lpMaxPipeDataCmd = NULL);
	void DeInitializeDLL();
	bool ReLoadMailScannerDB();

	// Overrides
	virtual BOOL InitInstance();
	virtual int ExitInstance();

	BOOL IsAutoCleanActive();
	void SetAutomationLabStatus();
	void SetGameMode();
	
	DECLARE_MESSAGE_MAP();

public:
	CSpyScanner			*m_pSpyScanner;
	CMaxScanner			*m_pMaxScanner;
	CThreatManager		*m_pThreatManager;
	BOOL                 m_bSkipFolder; //Nil:Added for skipping a folder
	BOOL                 m_bBGScanner;
	BOOL				 m_bValidated;
};

extern CSDScannerApp theApp;