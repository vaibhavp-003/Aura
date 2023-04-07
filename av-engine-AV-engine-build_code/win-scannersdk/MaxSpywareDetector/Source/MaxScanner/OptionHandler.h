/*======================================================================================
FILE             : OptionHandler.h
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
CREATION DATE    : 8/1/2009 6:37:44 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "MaxConstant.h"
#include "MaxCommunicatorServer.h"
#include "MaxCommunicator.h"
#include "OptionTabFunctions.h"

class COptionHandler
{
public:
	COptionHandler(void);
	virtual ~COptionHandler(void);
	void Cleanup();
	CString m_csHostFilePath;
	CString m_csDummyHostFilePath;    
	void StartRegFixScanner(MAX_PIPE_DATA *sMaxPipeData);

private:
    static STOPSCANNING m_lpStopScanning;
	static HANDLE m_hExitEvent;
	static CMaxCommunicator* m_pMaxCommunicatorScanner;
    static CMaxCommunicatorServer *m_pOptionObjServer;
	static PERFORMREGACTION		m_lpPerformRegAction;
	static MAX_PIPE_DATA_REG m_sMaxPipeData_Reg;
	static BOOL CALLBACK SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus = eStatus_NotApplicable, const ULONG ulSpyName = 0, 
									HKEY Hive_Type = 0, const WCHAR *strKey = 0, const WCHAR *strValue = 0, 
									int Type_Of_Data = 0, LPBYTE lpbData = 0, int iSizeOfData = 0, 
									REG_FIX_OPTIONS *psReg_Fix_Options = 0, LPBYTE lpbReplaceData = 0, 
									int iSizeOfReplaceData = 0);
	static void OnCallbackDataOptionTab(LPVOID lpParam);
	static void SetOption(int iOperation,LPCTSTR lpValue,DWORD dwSpyID);
	static bool GetSetRegRestrictionOptions(MAX_PIPE_DATA* pstMaxPipeData);
	void CopyHostFile(CString csHostFilePath ,CString csDummyHostfilePath);
	void GetHostFilePath();
	
	HMODULE m_hScanDll;
	void InitScannerDLL();
	void DeInitScannerDLL();

	static MAXSECUREDISPATCHER m_pMaxSecureDispatcher;
	static Max_Dispatch_Type GetDispatchMessageType(SD_Message_Info eMessageType);
	static BOOL CALLBACK SendVoidMessageToUI(LPVOID lpVoid, DWORD dwSize);
};
