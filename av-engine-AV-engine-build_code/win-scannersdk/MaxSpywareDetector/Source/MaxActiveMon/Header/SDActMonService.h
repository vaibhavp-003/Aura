/*======================================================================================
FILE             : SDActMonService.h
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 20 Jan 2008
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
#pragma once

#ifndef __AFXWIN_H__
#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"
#include "MaxConstant.h"
#include "MaxCommunicatorServer.h"
#include "SDMonitor.h"
#include "MaxProcessReg.h"

class CSDActMonServiceApp : public CWinApp
{
public:
	CSDActMonServiceApp();
	~CSDActMonServiceApp();

	HANDLE m_hAppStopEvent;
	bool m_bRegWDThreadRunning;
	static UINT WDConnectionThread(LPVOID lParam);

	CMaxCommunicator m_objWDMaxCommunicator;
	CMaxCommunicatorServer m_objMaxCommunicatorServer;
	CMaxProcessReg m_objRegProcess;
	CSDMonitor m_objSDMonitor;
	CWinThread *m_pWinThread;

	virtual BOOL InitInstance();
	static void OnDataReceivedCallBack(LPVOID sMaxPipeData);
	static HANDLE m_hSingleMonitorHandler;

	DECLARE_MESSAGE_MAP()

private:
	bool SingleInstance();
};

extern CSDActMonServiceApp theApp;