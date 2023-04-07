/*======================================================================================
FILE             : TimeOutMgr.cpp
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

CREATION DATE    : 23/02/2012
NOTES		     : This module is thread span hadler
VERSION HISTORY  : 
======================================================================================*/
#include "TimeOutMgr.h"
#include "MaxExceptionFilter.h"

/*-------------------------------------------------------------------------------------
	Function		: WatchThread
	In Parameters	: LPVOID lpThreadParameter
	Out Parameters	: Time_out Status
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Thraed which watches on another thread duration
--------------------------------------------------------------------------------------*/
DWORD WINAPI WatchThread(LPVOID lpThreadParameter)
{
	bool bKeepCalling = true, bCallFunction = false;
	DWORD dwWaitResult = 0;
	CTimeOutMgr * pobjTimeOutMgr = (CTimeOutMgr*)lpThreadParameter;

	while(bKeepCalling)
	{
		bCallFunction = false;
		dwWaitResult = WaitForSingleObject(pobjTimeOutMgr->m_hStartCall, INFINITE);
		switch(dwWaitResult)
		{
		case WAIT_OBJECT_0:
			bCallFunction = true;
			break;

		case WAIT_FAILED:
		case WAIT_TIMEOUT:
		case WAIT_ABANDONED:
			bKeepCalling = false;
			break;
		}

		dwWaitResult = WaitForSingleObject(pobjTimeOutMgr->m_hEndCall, 1000 * pobjTimeOutMgr->m_dwTOInSecs);
		switch(dwWaitResult)
		{
		case WAIT_OBJECT_0:
			break;

		case WAIT_FAILED:
		case WAIT_TIMEOUT:
		case WAIT_ABANDONED:
			pobjTimeOutMgr->m_bTimeOut = true;
			AddLogEntry(_T("Terminating a long function call in TimeOut WatchThread"));
			pobjTimeOutMgr->DestroyWorkerThread();
			pobjTimeOutMgr->CreateWorkerThread();
			ResetEvent(pobjTimeOutMgr->m_hStartCall);
			SetEvent(pobjTimeOutMgr->m_hEndCall);
			break;
		}
	}

	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: WorkerThread
	In Parameters	: LPVOID lpThreadParameter
	Out Parameters	: Time_out Status
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Thraed which launches on another thread
--------------------------------------------------------------------------------------*/
DWORD WINAPI WorkerThread(LPVOID lpThreadParameter)
{
	bool bKeepCalling = true, bCallFunction = false;
	DWORD dwWaitResult = 0;
	CTimeOutMgr * pobjTimeOutMgr = (CTimeOutMgr*)lpThreadParameter;

	while(bKeepCalling)
	{
		bCallFunction = false;
		dwWaitResult = WaitForSingleObject(pobjTimeOutMgr->m_hStartCall, INFINITE);
		switch(dwWaitResult)
		{
		case WAIT_OBJECT_0:
			bCallFunction = true;
			break;

		case WAIT_FAILED:
		case WAIT_TIMEOUT:
		case WAIT_ABANDONED:
			bKeepCalling = false;
			break;
		}

		if(bCallFunction)
		{
			__try
			{
				__try
				{
					pobjTimeOutMgr->m_lpfnGuardedFunction(pobjTimeOutMgr->m_pParameters);
				}

				__finally
				{
					ResetEvent(pobjTimeOutMgr->m_hStartCall);
					SetEvent(pobjTimeOutMgr->m_hEndCall);
				}
			}

			__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught in VirusScanner Dll::WorkerThread")))
			{
			}
		}
	}

	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: CTimeOutMgr
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Constructor
--------------------------------------------------------------------------------------*/
CTimeOutMgr::CTimeOutMgr()
{
	m_bTimeOut = m_bIsReady = m_bTriedInitOnce = false;
	m_hStartCall = m_hEndCall = NULL;
	m_pParameters = NULL;
	m_dwTOInSecs = 10;
	m_hWatch = m_hWorker = NULL;
	m_lpfnGuardedFunction = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CTimeOutMgr
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Destructor
--------------------------------------------------------------------------------------*/
CTimeOutMgr::~CTimeOutMgr()
{
	ResetMembers();
}

/*-------------------------------------------------------------------------------------
	Function		: ResetMembers
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Reset memory of all the menbers
--------------------------------------------------------------------------------------*/
void CTimeOutMgr::ResetMembers()
{
	DestroyTimeOutMgrObj();
	DestroyWorkerThread();
	DestroyWatchThread();

	m_bTimeOut = m_bTriedInitOnce = m_bIsReady = false;
	m_hWatch = m_hWorker = m_hStartCall = m_hEndCall = NULL;
}

/*-------------------------------------------------------------------------------------
	Function		: Init
	In Parameters	: DWORD dwTimeOutInSecs
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Initialize Timeout status
--------------------------------------------------------------------------------------*/
bool CTimeOutMgr::Init(DWORD dwTimeOutInSecs)
{
	m_bTriedInitOnce = true;

	if(!SetTimeOut(dwTimeOutInSecs))
	{
		return false;
	}

	if(!CreateTimeOutMgrObj())
	{
		return false;
	}

	if(!CreateWatchThread())
	{
		DestroyTimeOutMgrObj();
		return false;
	}

	if(!CreateWorkerThread())
	{
		DestroyWatchThread();
		DestroyTimeOutMgrObj();
		return false;
	}

	m_bIsReady = true;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DeInit
	In Parameters	: DWORD dwTimeOutInSecs
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Deinitialize
--------------------------------------------------------------------------------------*/
bool CTimeOutMgr::DeInit()
{
	ResetMembers();
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: SetTimeOut
	In Parameters	: DWORD dwSeconds
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Sets time out value
--------------------------------------------------------------------------------------*/
bool CTimeOutMgr::SetTimeOut(DWORD dwSeconds)
{
	m_dwTOInSecs = dwSeconds;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CreateWatchThread
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Launches Watcher Thraed
--------------------------------------------------------------------------------------*/
bool CTimeOutMgr::CreateWatchThread()
{
	m_hWatch = CreateThread(NULL, 0, WatchThread, this, 0, 0);
	return NULL != m_hWatch;
}

/*-------------------------------------------------------------------------------------
	Function		: DestroyWatchThread
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Terminates Watcher Thraed
--------------------------------------------------------------------------------------*/
bool CTimeOutMgr::DestroyWatchThread()
{
	if(m_hWorker)
	{
		WaitForSingleObject(m_hWorker, 100);
		TerminateThread(m_hWorker, 0);
		CloseHandle(m_hWorker);
	}

	m_hWorker = NULL;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CreateWorkerThread
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Launches Worker Thraed
--------------------------------------------------------------------------------------*/
bool CTimeOutMgr::CreateWorkerThread()
{
	m_hWorker = CreateThread(NULL, 0, WorkerThread, this, 0, 0);
	return NULL != m_hWorker;
}

/*-------------------------------------------------------------------------------------
	Function		: DestroyWorkerThread
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Teminates Worker Thraed
--------------------------------------------------------------------------------------*/
bool CTimeOutMgr::DestroyWorkerThread()
{
	if(m_hWorker)
	{
		WaitForSingleObject(m_hWorker, 100);
		TerminateThread(m_hWorker, 0);
		CloseHandle(m_hWorker);
	}

	m_hWorker = NULL;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CreateTimeOutMgrObj
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: creates Time watcher manager object
--------------------------------------------------------------------------------------*/
bool CTimeOutMgr::CreateTimeOutMgrObj()
{
	m_hStartCall = CreateEvent(0, TRUE, FALSE, NULL);
	if(NULL == m_hStartCall)
	{
		return false;
	}

	m_hEndCall = CreateEvent(0, TRUE, FALSE, NULL);
	if(NULL == m_hEndCall)
	{
		CloseHandle(m_hStartCall);
		m_hStartCall = NULL;
		return false;
	}

	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: DestroyTimeOutMgrObj
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: Terminates Time watcher manager object
--------------------------------------------------------------------------------------*/
bool CTimeOutMgr::DestroyTimeOutMgrObj()
{
	if(m_hStartCall)
	{
		CloseHandle(m_hStartCall);
	}

	if(m_hEndCall)
	{
		CloseHandle(m_hEndCall);
	}

	m_hEndCall = NULL;
	m_hStartCall = NULL;
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CallWithTimeOut
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Ravi Bisht
	Description		: call Time watcher manager object
--------------------------------------------------------------------------------------*/
bool CTimeOutMgr::CallWithTimeOut(LPFN_GUARDEDFUNCTION lpfnGuardedFunction, LPVOID pParameters)
{
	m_bTimeOut = false;
	m_pParameters = pParameters;
	m_lpfnGuardedFunction = lpfnGuardedFunction;
	SetEvent(m_hStartCall);
	WaitForSingleObject(m_hEndCall, INFINITE);
	ResetEvent(m_hEndCall);
	return !m_bTimeOut;
}
