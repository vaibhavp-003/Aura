/*======================================================================================
FILE             : MaxThreadPool.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : 
COMPANY		     : Aura 
COPYRIGHT(NOTICE): (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura.	

CREATION DATE    : 12/25/2009 11:55:56 AM
NOTES		     : Defines the Fucntionality for Threads
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "IExecContext.h"
#include <list>
#include <map>
#include <vector>
#include "ThreadSync.h"

const int DEFAULT_POOL_SIZE = 4;
const int MAX_POOL_SIZE = 100;

enum THREAD_POOL_STATE
{
	CREATE_THRD_SUSPENDED,
	CREATE_THRD_RUNNING
};

typedef struct tagThreadData
{
	bool	bFree;
	HANDLE	WaitHandle;
	HANDLE	hNotifyLastOpHandle;
	HANDLE	hFinishLastOpHandle;
	HANDLE	hThread;
	DWORD	dwThreadId;
	THREAD_POOL_STATE ePoolState;
	IExecContext *pIContext;
} _ThreadData;

enum ThreadPriority
{
	PRIORITY_HIGH,
	PRIORITY_LOW
};

typedef map<DWORD, _ThreadData, less<DWORD>, allocator<_ThreadData>> ThreadMap;
typedef std::vector<IExecContext*> ExecutionCntxtList;

class CMaxThreadPool
{
public:
	CMaxThreadPool();
	~CMaxThreadPool(void);
	bool	CreateThreadPool(int nPoolSize);
	void	StopThreadPool();
	int	GetPoolSize();
	void	SetPoolSize(int);
	void	FinishNotify(DWORD dwThreadId);
	void	BusyNotify(DWORD dwThreadId);
	void	RunThreadPool(ThreadPriority priority = PRIORITY_HIGH, bool bSignalEvent = false);
	bool	GetThreadProc(DWORD dwThreadId, IExecContext** piExecContext);
	bool	AssignContext(IExecContext *pIContext);
	IExecContext* GetCurrentExecutionContext();
	IExecContext* GetContext(DWORD nContextIndex);
	bool	WaitForLastOperation();
	void	PauseThreadPool();
	void	ResumeThreadPool();
	void    ClearExecutionContext();
	void	SetEventName(LPCTSTR szEventName);
	void	ReInitExecContext();
private:
	static DWORD WINAPI _ThreadExecutionContextProc(LPVOID);
	void NotifyLastOperation();
	HANDLE	GetWaitHandle(bool bNotifyWaitHandle,DWORD dwThreadId);
	HANDLE	GetFinishLastOperHandle(DWORD dwThreadId);
	HANDLE	GetShutdownHandle();
	HANDLE	GetNotifyLastOperHandle(DWORD dwThreadId);
	HANDLE *m_arrNotifyWaitHandle;
	HANDLE *m_arrFinishLastOpHandle;
	HANDLE *m_arrThreadHandle;
	bool	m_bExecContextInit;
	ExecutionCntxtList m_ExecCntxtList;
	CThreadSync m_objThreadSync;
	ThreadMap m_threads;
	int     m_iThreadState;
	int		m_nPoolSize;
	HANDLE	m_hNotifyShutdown;
	TCHAR m_szEventName[MAX_PATH];
 
};
