/*======================================================================================
FILE             : RecoverHandler.h
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
#include "MaxConstant.h"

#ifndef _STANDALONE_
#include "MaxCommunicator.h"
#else
#include "MaxCommandLineFuctions.h"
#endif

class CQuarentineHandler
{
public:
	CQuarentineHandler(void);
	virtual ~CQuarentineHandler(void);
	
	void InitScannerDLL();
	void DeInitScannerDLL();	
	void StartQuarentineWithParams(MAX_PIPE_DATA *sMaxPipeData);		
	static BOOL CALLBACK SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus =						eStatus_NotApplicable, const ULONG ulSpyName = 0, 
		HKEY Hive_Type = 0, const WCHAR *strKey = 0, const WCHAR *strValue = 0, 
		int Type_Of_Data = 0, LPBYTE lpbData = 0, int iSizeOfData = 0, 
		REG_FIX_OPTIONS *psReg_Fix_Options = 0, LPBYTE lpbReplaceData = 0, 
		int iSizeOfReplaceData = 0);
private:
	static HANDLE				m_hExitEvent;
	static MAXSECUREDISPATCHER	m_pMaxSecureDispatcher;
	static MAX_PIPE_DATA		m_sMaxPipeData;
	static DWORD				m_dwQSuccessCount;
	static DWORD				m_dwQFailedCount;
	HMODULE						m_hScanDll;
#ifndef _STANDALONE_
	static CMaxCommunicator		*m_pMaxCommunicatorScanner;
#endif
	static void OnDataReceivedCallBack(LPVOID sMaxPipeData);
};