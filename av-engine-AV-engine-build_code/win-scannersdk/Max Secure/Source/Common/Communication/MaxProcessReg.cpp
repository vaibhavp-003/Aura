/*======================================================================================
FILE             : MaxProcessReg.cpp
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshit Kasliwal
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 6/26/2009.
NOTES		     : Implements the WD registration process
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "MaxProcessReg.h"
#include "MaxCommunicator.h"
#include "MaxPipes.h"
#include "SDConstants.h"
#include "MaxProcessReg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

TCHAR *szMaxProcessName[12] = {_T("AuActMon.exe"),
							UI_TRAYNAME,
							UI_EXENAME,
							_T("AuWatchDogService.exe"),
							_T("AuScanner.exe"),
							_T("AuScanner.exe"),
							_T("AuScanner.exe"),
							_T("AuScanner.exe"),
							_T("AuScanner.exe"),
							_T("AuScanner.exe"),
							_T("AuDBServer.exe"),
							_T("AuMailProxy.exe")};


/*--------------------------------------------------------------------------------------
Function       : CMaxProcessReg
In Parameters  : REGISTRATION_TYPE RegType,
Out Parameters :
Description    : C'tor which takes Registrationn type as input
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CMaxProcessReg::CMaxProcessReg(REGISTRATION_TYPE RegType)
{
	m_eRegType = RegType;
	SecureZeroMemory(m_controlbuff, sizeof(m_controlbuff));
	m_bWDRegistered = false;
}

/*--------------------------------------------------------------------------------------
Function       : ~CMaxProcessReg
In Parameters  :
Out Parameters :
Description    : D'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CMaxProcessReg::~CMaxProcessReg()
{
}

/*--------------------------------------------------------------------------------------
Function       : WDRegisterProcess
In Parameters  : E_TRUSTPID eProcessType, int nMessageInfo, CMaxCommunicator *pobjWatchDog, int nActionInfo, LPCTSTR szActionPipeName,
Out Parameters : bool
Description    : Function used by Apps to register their process with WD for monitoring
and also defining the action
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CMaxProcessReg::WDRegisterProcess(E_TRUSTPID eProcessType, int nMessageInfo,CMaxCommunicator *pobjWatchDog,int nActionInfo, LPCTSTR szActionPipeName)
{
	bool bRet = false;
	if(!pobjWatchDog)
	{
		return false;
	}
	MAX_WD_DATA sMaxWDData;
	SecureZeroMemory(&sMaxWDData,sizeof(MAX_WD_DATA));
	sMaxWDData.eMessageInfo = nMessageInfo;
	sMaxWDData.dwProcessID = ::GetCurrentProcessId();
	sMaxWDData.eActionMsgInfo = nActionInfo;
	sMaxWDData.nProcessType = eProcessType;
	switch(eProcessType)
	{
	case eActMon:
	case eTrayID:
	case eWD://To be used bySDNotify
	case eScanner2://Option Handler
	case eScanner3://Recover Handler
	case eOutlookPlugin:
	case eMaxDBServer:
	case eMailProxy:
		sMaxWDData.nAction = RESTART_PROCESS;
		break;
	case eMaxSDUI:
	case eUSBScanner:
	case eScanner1:
	case eHeuristic:
		sMaxWDData.nAction = NOTIFY_PIPE;
		break;
	}
	if(szActionPipeName)
	{
		_tcscpy_s(sMaxWDData.szActionPipeName, szActionPipeName);
	}
	_tcscpy_s(sMaxWDData.szProcessName, szMaxProcessName[eProcessType]);

	if(pobjWatchDog->SendData(&sMaxWDData,sizeof(MAX_WD_DATA)))
	{
		m_bWDRegistered = true;
		bRet = true;
	}
	return bRet;
}