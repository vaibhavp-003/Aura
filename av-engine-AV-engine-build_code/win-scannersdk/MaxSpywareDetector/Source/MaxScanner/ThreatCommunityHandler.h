/*======================================================================================
FILE             : ThreatCommunityHandler.h
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
CREATION DATE    : 8/1/2009 6:38:06 PM
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "MaxCommunicator.h"
#include "MaxCommunicatorServer.h"
#include "OptionTabFunctions.h"

class CThreatCommunityHandler
{	
public:
    CThreatCommunityHandler(void);
    ~CThreatCommunityHandler(void);

	void StartThreatCommunityScanning(MAX_PIPE_DATA *sMaxPipeData);
	static BOOL CALLBACK SendMessageToUI(SD_Message_Info eTypeOfScanner, eEntry_Status eStatus = eStatus_NotApplicable, const ULONG ulSpyName = 0, HKEY Hive_Type = 0, const WCHAR *strKey = 0, const WCHAR *strValue = 0, int Type_Of_Data = 0, LPBYTE lpbData = 0, int iSizeOfData = 0);
    static void CThreatCommunityHandler::OnCallbackDataHeuristicScan(LPVOID lpParam);

private:	
	static CMaxCommunicator		*m_pMaxCommunicatorScanner;
	static MAX_PIPE_DATA		m_sMaxPipeData;	
	static bool m_bThreatFound;
	static HANDLE m_hExitEvent;

	// Scanner Methods	
	static CMaxCommunicatorServer m_objMaxCommunicatorServer;
    static STOPSCANNING m_lpStopScanning;
	STARTSCANNINGTH m_lpStartScanning;
};
