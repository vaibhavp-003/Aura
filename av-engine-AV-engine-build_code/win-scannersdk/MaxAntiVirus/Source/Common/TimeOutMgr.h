/*======================================================================================
FILE             : TimeOutMgr.h
ABSTRACT         : This module is thread span hadler
DOCUMENTS	     : 
AUTHOR		     : Tushar Kadam + Ravi Bisht
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

CREATION DATE    : 23/05/2010
NOTES		     : This module is thread span hadler
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "pch.h"

typedef void (*LPFN_GUARDEDFUNCTION)(void*);

class CTimeOutMgr
{

public:
	CTimeOutMgr();
	~CTimeOutMgr();

	bool	m_bTimeOut;
	bool	m_bIsReady;
	bool	m_bTriedInitOnce;
	HANDLE	m_hStartCall;
	HANDLE	m_hEndCall;
	LPVOID	m_pParameters;
	DWORD	m_dwTOInSecs;
	HANDLE	m_hWatch;
	HANDLE	m_hWorker;
	LPFN_GUARDEDFUNCTION	m_lpfnGuardedFunction;

	bool Init(DWORD dwTimeOutInSecs);
	bool DeInit();
	void ResetMembers();
	bool SetTimeOut(DWORD dwSeconds);
	bool CreateWatchThread();
	bool DestroyWatchThread();
	bool CreateWorkerThread();
	bool DestroyWorkerThread();
	bool CreateTimeOutMgrObj();
	bool DestroyTimeOutMgrObj();
	bool CallWithTimeOut(LPFN_GUARDEDFUNCTION lpfnGuardedFunction, LPVOID pParameters);
};
