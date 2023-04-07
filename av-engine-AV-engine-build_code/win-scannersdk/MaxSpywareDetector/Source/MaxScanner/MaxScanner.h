/*======================================================================================
FILE             : MaxScanner.h
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
CREATION DATE    : 8/1/2009 6:37:36 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include "MaxCommunicator.h"
#include "MaxCommunicatorServer.h"
#include "MaxConstant.h"
#include "MaxProcessReg.h"
#include "MaxInitScanner.h"

class CMaxScannerApp : public CWinApp
{
public:
	CMaxScannerApp();
	~CMaxScannerApp();

	CMaxCommunicator m_objWatchDog;
	CMaxInitScanner m_objInitScanner;
	bool m_bRegWDThreadRunning;
	bool m_bStandAlone;
	CMaxCommunicatorServer *m_pObjMaxCommunicatorServer;
	CWinThread *m_pScannerThread;
	CString m_csGUID;
	E_TRUSTPID m_eTypeOfScanner;

	void Cleanup();
	void WDRegisterScanner(int nMessageInfo, int nActionInfo, int nAction, int ProcessType, LPCTSTR lpPipeName);

	// Overrides
	public:
	virtual BOOL InitInstance();

	// Implementation
	DECLARE_MESSAGE_MAP()

private:
	CMaxProcessReg m_obgRegProcess;
	CWinThread *m_pWinThread;
	MAX_WD_DATA m_sMaxWDData;
	void AppCrashHandler();
	HANDLE m_hAppStopEvent;
	static UINT WDConnectionThread(LPVOID lParam);
	MAX_PIPE_DATA sMaxPipeData;
public:
	virtual int ExitInstance();
};

extern CMaxScannerApp theApp;