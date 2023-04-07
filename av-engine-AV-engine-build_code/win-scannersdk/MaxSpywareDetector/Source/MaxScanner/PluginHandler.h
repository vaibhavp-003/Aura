/*======================================================================================
FILE             : PluginHandler.h
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
CREATION DATE    : 8/1/2009 6:37:49 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "MaxCommunicatorServer.h"
#include "MaxCommunicator.h"
#include "MaxConstant.h"

class CPluginHandler
{
public:
	CPluginHandler(void);
	virtual ~CPluginHandler(void);

	bool IsThisFirstInstance();
	void StartPluginHandler(MAX_PIPE_DATA *sMaxPipeData);

private:
	static bool m_bScannerIsReady;

	HMODULE m_hScanDll;
	static MAXSECUREDISPATCHER m_pMaxSecureDispatcher;
	void InitScannerDLL();
	void DeInitScannerDLL();

	void ScanDummyFile();

	static void OnCallbackDataPluginHandler(LPVOID lpParam);
	static HANDLE m_hExitEvent;
    static CMaxCommunicatorServer	* m_pPluginServer;
	static CMaxCommunicator			*m_pMaxCommunicatorPlugin;
};