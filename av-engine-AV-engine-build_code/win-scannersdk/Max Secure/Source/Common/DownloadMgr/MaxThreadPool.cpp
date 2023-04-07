
/*======================================================================================
FILE             : MaxThreadPool.cpp
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
				  
CREATION DATE    : 12/24/2009.
NOTES		     : Thread Pool Implementation
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "MaxThreadPool.h"
#include "IExecContext.h"
#include "Logger.h"
#ifdef DOWNLOAD_BOT
#include "SocketManager.h"
#endif
#include "MaxExceptionFilter.h"
#include "MaxConstant.h"

using namespace std;
#ifdef _UNICODE
typedef std::wstring tstring;
#else
typedef std::string tstring;
#endif

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::_ThreadExecutionContextProc
In Parameters  : LPVOID pParam,
Out Parameters : DWORD WINAPI
Description    : This is the internal thread function which will run
continuously till the Thread Pool is deleted.Any user thread
functions will run from within this function.
Author & Date  :
--------------------------------------------------------------------------------------*/
DWORD WINAPI CMaxThreadPool::_ThreadExecutionContextProc(LPVOID pParam)
{
	HRESULT hr = CoInitialize(NULL);
	COINITIALIZE_OUTPUTDEBUGSTRING(hr);
	__try
	{
		{
			DWORD					dwWait;
			CMaxThreadPool*			pool;
			DWORD					dwThreadId = GetCurrentThreadId();
			HANDLE					hWaits[3];
			IExecContext*			pIExecContext = NULL;
			bool bContinue = true;
			if(NULL == pParam)
			{
				CoUninitialize();
				return -1;
			}

			pool = static_cast<CMaxThreadPool*>(pParam);
			hWaits[0] = pool->GetWaitHandle(false,dwThreadId);
			hWaits[1] = pool->GetShutdownHandle();
			hWaits[2] = pool->GetWaitHandle(true,dwThreadId);
			if(pool->GetThreadProc(dwThreadId, &pIExecContext))
			{
				//Initialize the thread just once
				if((!pIExecContext) || (!pIExecContext->Initialize(hWaits[0])))
				{
					::SetEvent(pool->GetFinishLastOperHandle (dwThreadId));
					goto quit;
				}
			}
			do
			{
				dwWait = WaitForMultipleObjects(3, hWaits, FALSE, INFINITE);

				if(dwWait == WAIT_OBJECT_0 + 0)
				{
					//TODO:Error Handling
					pool->BusyNotify(dwThreadId);
					if(pool->GetThreadProc(dwThreadId, &pIExecContext))
					{
						if(pIExecContext)
							pIExecContext->Run();
					}
					pool->FinishNotify(dwThreadId); // tell the pool, i am now free
				}
				else
					if(dwWait == WAIT_OBJECT_0 + 1)
					{
						HANDLE hWait = pool->GetFinishLastOperHandle (dwThreadId);
						if(hWait)
						{
							::SetEvent(hWait);
						}
						bContinue = false;
					}
					else
						if(dwWait == WAIT_OBJECT_0 + 2)
						{
							pool->BusyNotify(dwThreadId);
							if(pool->GetThreadProc(dwThreadId, &pIExecContext))
							{
								if(pIExecContext)
									pIExecContext->Run(true);
							}

							pool->FinishNotify(dwThreadId); // tell the pool, i am now free
							::ResetEvent(hWaits[2]);
							::SetEvent(pool->GetFinishLastOperHandle (dwThreadId));
						}
						else if(dwWait == WAIT_TIMEOUT)
						{
							g_objLogApp.AddLog1(_T("WAIT_TIMEOUT"));
						}

			} while (bContinue);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
quit:
	CoUninitialize();
	return 0;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::CMaxThreadPool
In Parameters  :
Out Parameters :
Description    :  Constructor that Intialize the member Variables
Pool size, indicates the number of threads that will be
available in the queue.
*******************************************************************************/
CMaxThreadPool::CMaxThreadPool()
{
	m_nPoolSize = DEFAULT_POOL_SIZE;
	m_iThreadState = CREATE_THRD_SUSPENDED;
	m_arrThreadHandle = NULL;
	m_arrNotifyWaitHandle = NULL;
	m_arrFinishLastOpHandle = NULL;
	memset(m_szEventName,'\0',MAX_PATH*sizeof(TCHAR));
	m_bExecContextInit = false;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::~CMaxThreadPool
In Parameters  :
Out Parameters :
Description    : Destructor that Destorys the Memory
Author & Date  :
--------------------------------------------------------------------------------------*/
CMaxThreadPool::~CMaxThreadPool()
{
	StopThreadPool();
}

/*--------------------------------------------------------------------------------------
Function       : SetEventName(LPCTSTR szEventName)
In Parameters  :Event Name
Out Parameters :
Description    : Sets the Event Name for the thread pool
Author & Date  :
--------------------------------------------------------------------------------------*/
void CMaxThreadPool::SetEventName(LPCTSTR szEventName)
{
    _tcscat_s(m_szEventName,MAX_PATH,szEventName);
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::WaitForLastOperation()
In Parameters  :
Out Parameters :
Description    : Wait for all pool threads to complete their last operation
Author & Date  :
--------------------------------------------------------------------------------------*/
bool CMaxThreadPool::WaitForLastOperation()
{
	NotifyLastOperation();
	if(!m_arrFinishLastOpHandle)
		return false;
	WaitForMultipleObjects(m_nPoolSize, m_arrFinishLastOpHandle, TRUE, INFINITE);
	for(int nIndex = 0; nIndex < m_nPoolSize; nIndex++)
	{
		if(m_arrFinishLastOpHandle)
		{
			::ResetEvent(m_arrFinishLastOpHandle[nIndex]);
		}
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::PauseThreadPool
In Parameters  :
Out Parameters : void
Description    : Suspend Thread Pool on demand
Author & Date  : Darshit Kasliwal & 29 Dec, 2009.
--------------------------------------------------------------------------------------*/
void CMaxThreadPool::PauseThreadPool()
{
	if(!m_arrThreadHandle)
		return;

	for(int nIndex = 0; nIndex < m_nPoolSize; nIndex++)
	{
		if(m_arrThreadHandle[nIndex] != INVALID_HANDLE_VALUE)
		{
			::SuspendThread(m_arrThreadHandle[nIndex]);
		}
	}

}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::ResumeThreadPool
In Parameters  :
Out Parameters : void
Description    : Resume Thread Pool on demand
Author & Date  : Darshit Kasliwal & 29 Dec, 2009.
--------------------------------------------------------------------------------------*/
void CMaxThreadPool::ResumeThreadPool()
{
	if(!m_arrThreadHandle)
		return;

	for(int nIndex = 0; nIndex < m_nPoolSize; nIndex++)
	{
		if(m_arrThreadHandle[nIndex] != INVALID_HANDLE_VALUE)
		{
			::ResumeThread(m_arrThreadHandle[nIndex]);
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::NotifyLastOperation
In Parameters  :
Out Parameters : void
Description    : Notifying all threads to perform last operation
Author & Date  :
--------------------------------------------------------------------------------------*/

void CMaxThreadPool::NotifyLastOperation()
{
	ThreadMap::iterator iter;
	_ThreadData ThreadData;
	for(iter = m_threads.begin(); iter != m_threads.end(); iter++)
	{
		ThreadData = (*iter).second;
		::SetEvent(ThreadData.hNotifyLastOpHandle);
	}

}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::CreateThreadPool
In Parameters  : int nPoolSize,
Out Parameters : bool
Description    : Use this method to create the thread pool.The constructor of
this class by default will create the pool.Make sure you
do not call this method without first calling the Destroy()
method to release the existing pool.
Author & Date  :
--------------------------------------------------------------------------------------*/
bool CMaxThreadPool::CreateThreadPool(int nPoolSize)
{
	DWORD		dwThreadId;
	_ThreadData ThreadData;
	TCHAR		szEvtName[50]=_T("\0");
	if(m_arrThreadHandle)
	{
		return true;
	}

	if(nPoolSize <= 0)
	{
		m_nPoolSize = DEFAULT_POOL_SIZE;
	}
	m_nPoolSize = nPoolSize;
	// create the event which will signal the threads to stop
	m_hNotifyShutdown = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!m_hNotifyShutdown)
	{
		return false;
	}
	m_arrThreadHandle = new HANDLE[m_nPoolSize];
	m_arrNotifyWaitHandle = new HANDLE[m_nPoolSize];
	m_arrFinishLastOpHandle = new HANDLE[m_nPoolSize];
	// create the threads
	for(int nIndex = 0; nIndex < m_nPoolSize; nIndex++)
	{
		m_arrThreadHandle[nIndex] = CreateThread(NULL, 0, CMaxThreadPool::_ThreadExecutionContextProc,
			this, CREATE_SUSPENDED, &dwThreadId);

		_stprintf_s(szEvtName,50, _T("Thread_%d"), dwThreadId);

		if(m_arrThreadHandle[nIndex])
		{
			// add the entry to the map of threads
			ThreadData.bFree		= true;
			ThreadData.WaitHandle	= ::CreateEvent(NULL, TRUE, FALSE, szEvtName);
			m_arrNotifyWaitHandle[nIndex] = ThreadData.hNotifyLastOpHandle = ::CreateEvent(NULL, TRUE, FALSE, NULL);
			m_arrFinishLastOpHandle[nIndex] = ThreadData.hFinishLastOpHandle = ::CreateEvent(NULL, TRUE, FALSE, NULL);
			ThreadData.hThread		= m_arrThreadHandle[nIndex];
			ThreadData.dwThreadId	= dwThreadId;
			ThreadData.ePoolState   = CREATE_THRD_SUSPENDED;
			//Will be assigned later using Assign Context
			//So that the context for the same thread can be reassigned
			ThreadData.pIContext = NULL;
			m_threads.insert(ThreadMap::value_type(dwThreadId, ThreadData));
		}
		else
		{
			return false;
		}
	}

	return true;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::StopThreadPool
In Parameters  :
Out Parameters : void
Description    : Use this method to destory the thread pool.The destructor of
this class will destory the pool anyway.Make sure you
this method before calling a Create()when an existing pool is
already existing.
Author & Date  :
--------------------------------------------------------------------------------------*/
void CMaxThreadPool::StopThreadPool()
{
	if(m_arrThreadHandle == NULL)
	{
		return;
	}
	// tell all threads to shutdown.
	SetEvent(m_hNotifyShutdown);

	// lets give the thread one second atleast to terminate
	// Wait for all threads to complete the tasks
	WaitForMultipleObjects(m_nPoolSize, m_arrThreadHandle, TRUE, 30000);
	
	ThreadMap::iterator iter;
	_ThreadData ThreadData;

	// walk through the events and threads and close them all
	for(iter = m_threads.begin(); iter != m_threads.end(); iter++)
	{
		ThreadData = (*iter).second;
		CloseHandle(ThreadData.WaitHandle);
		ThreadData.WaitHandle = NULL;
		CloseHandle(ThreadData.hNotifyLastOpHandle);
		ThreadData.hNotifyLastOpHandle = NULL;
		CloseHandle(ThreadData.hFinishLastOpHandle);
		ThreadData.hFinishLastOpHandle = NULL;
		CloseHandle(ThreadData.hThread);
		ThreadData.hThread = NULL;
	}

	// close the shutdown event
	if(m_hNotifyShutdown)
	{
		::CloseHandle(m_hNotifyShutdown);
		m_hNotifyShutdown = NULL;
	}
	if(m_arrThreadHandle)
	{
		delete [] m_arrThreadHandle;
		m_arrThreadHandle = NULL;
	}

	if(m_arrNotifyWaitHandle)
	{
		delete [] m_arrNotifyWaitHandle;
		m_arrNotifyWaitHandle = NULL;
	}

	if(m_arrFinishLastOpHandle)
	{
		delete [] m_arrFinishLastOpHandle;
		m_arrFinishLastOpHandle = NULL;
	}

	// empty all collections
	m_threads.clear();
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::GetPoolSize
In Parameters  :
Out Parameters : int
Description    : Get Pool Size
Author & Date  :
--------------------------------------------------------------------------------------*/
int CMaxThreadPool::GetPoolSize()
{
	return m_nPoolSize;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::SetPoolSize
In Parameters  : int nSize,
Out Parameters : void
Description    : Sets the Pool Size
Author & Date  :
--------------------------------------------------------------------------------------*/
void CMaxThreadPool::SetPoolSize(int nSize)
{
	if(nSize <= 0)
	{
		m_nPoolSize = DEFAULT_POOL_SIZE;
		return;
	}
	m_nPoolSize = nSize;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::GetShutdownHandle
In Parameters  :
Out Parameters : HANDLE
Description    : Gets the ShutDown handle
Author & Date  :  & 24 Dec, 2009.
--------------------------------------------------------------------------------------*/
HANDLE CMaxThreadPool::GetShutdownHandle()
{
	return m_hNotifyShutdown;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::FinishNotify
In Parameters  : DWORD dwThreadId,
Out Parameters : void
Description    : When ever a thread finishes executing the user function, it
should notify the pool that it has finished executing.
Author & Date  :
--------------------------------------------------------------------------------------*/
void CMaxThreadPool::FinishNotify(DWORD dwThreadId)
{
	ThreadMap::iterator iter;

	m_objThreadSync.Acquire();
	iter = m_threads.find(dwThreadId);

	if(iter == m_threads.end())	// if search found no elements
	{
		m_objThreadSync.Release();
		return;
	}
	else
	{
		m_threads[dwThreadId].bFree = true;
		//CMaxBotApp::g_objLogApp.AddLog1(_T("Thread free"));
		// back to sleep, there is nothing that needs servicing.
		m_objThreadSync.Release();
		ResetEvent(m_threads[dwThreadId].WaitHandle);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::BusyNotify
In Parameters  : DWORD dwThreadId,
Out Parameters : void
Description    : Notify if Busy
Author & Date  :
--------------------------------------------------------------------------------------*/
void CMaxThreadPool::BusyNotify(DWORD dwThreadId)
{
	ThreadMap::iterator iter;

	m_objThreadSync.Acquire();

	iter = m_threads.find(dwThreadId);

	if(iter == m_threads.end())	// if search found no elements
	{
		m_objThreadSync.Release();
	}
	else
	{
		m_threads[dwThreadId].bFree = false;
		m_objThreadSync.Release();
	}
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::RunThreadPool
In Parameters  : ThreadPriority priority, bool bSignalEvent,
Out Parameters : void
Description    : This function is to be called by clients which want to make
use of the thread pool.
Author & Date  :
--------------------------------------------------------------------------------------*/
void CMaxThreadPool::RunThreadPool(ThreadPriority priority, bool bSignalEvent)
{
	// See if any threads are free
	ThreadMap::iterator iter;
	_ThreadData ThreadData;

	m_objThreadSync.Acquire();

	for(iter = m_threads.begin(); iter != m_threads.end(); iter++)
	{
		ThreadData = (*iter).second;
		if(ThreadData.ePoolState != CREATE_THRD_RUNNING)
		{
			ResumeThread(ThreadData.hThread);
			//TODO:Make the thread re-entrant
			m_threads[ThreadData.dwThreadId].ePoolState = CREATE_THRD_RUNNING;
		}
		if(ThreadData.bFree)
		{
			// here is a free thread, put it to work
			m_threads[ThreadData.dwThreadId].bFree = false;
			if(bSignalEvent)
				SetEvent(ThreadData.WaitHandle);
			// this thread will now call GetThreadProc()and pick up the next
			// function in the list.
			//TODO: DO we need a break in future;
			//break;
		}
	}
	m_objThreadSync.Release();
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::GetWaitHandle
In Parameters  : bool bNotifyWaitHandle, DWORD dwThreadId
Out Parameters : HANDLE
Description    : ThreadId - the id of the thread for which the wait handle is
being requested.
Author & Date  :  & 24 Dec, 2009.
--------------------------------------------------------------------------------------*/
HANDLE CMaxThreadPool::GetWaitHandle(bool bNotifyWaitHandle, DWORD dwThreadId)
{
	HANDLE hWait;
	ThreadMap::iterator iter;

	m_objThreadSync.Acquire();
	iter = m_threads.find(dwThreadId);

	if(iter == m_threads.end())	// if search found no elements
	{
		m_objThreadSync.Release();
		return NULL;
	}
	else
	{
		if(bNotifyWaitHandle)
		{
			hWait = m_threads[dwThreadId].hNotifyLastOpHandle;
		}
		else
		{
			hWait = m_threads[dwThreadId].WaitHandle;
		}
		m_objThreadSync.Release();
	}

	return hWait;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::GetFinishLastOperHandle
In Parameters  : bool bNotifyWaitHandle, DWORD dwThreadId
Out Parameters : HANDLE
Description    : ThreadId - the id of the thread for which the wait handle is
being requested.
Author & Date  :  & 24 Dec, 2009.
--------------------------------------------------------------------------------------*/
HANDLE CMaxThreadPool::GetFinishLastOperHandle(DWORD dwThreadId)
{
	HANDLE hWait;
	ThreadMap::iterator iter;

	m_objThreadSync.Acquire();
	iter = m_threads.find(dwThreadId);

	if(iter == m_threads.end())	// if search found no elements
	{
		m_objThreadSync.Release();
		return NULL;
	}
	else
	{
		hWait = m_threads[dwThreadId].hFinishLastOpHandle;
		m_objThreadSync.Release();
	}

	return hWait;
}
//------------------------------------------------------------------------------

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::GetThreadProc
In Parameters  : DWORD dwThreadId, IExecContext**piExecContext,
Out Parameters : bool
Description    :
Author & Date  :  & 24 Dec, 2009.
--------------------------------------------------------------------------------------*/
bool CMaxThreadPool::GetThreadProc(DWORD dwThreadId, IExecContext**piExecContext)
{
	bool bRet = false;
	ThreadMap::iterator iter;
	m_objThreadSync.Acquire();
	iter = m_threads.find(dwThreadId);

	if(iter != m_threads.end())	// if search found no elements
	{
		*piExecContext = m_threads[dwThreadId].pIContext;
		bRet = true;
	}
	else
	{
		*piExecContext = NULL;
	}
	m_objThreadSync.Release();
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::GetCurrentExecutionContext
In Parameters  :
Out Parameters : IExecContext*
Description    : Gets the Current Execution Context
Author & Date  :  & 24 Dec, 2009.
--------------------------------------------------------------------------------------*/
IExecContext* CMaxThreadPool::GetCurrentExecutionContext()
{
	IExecContext *pIContext = NULL;
	m_objThreadSync.Acquire();
	ThreadMap::iterator iter;
	_ThreadData ThreadData;
	for(iter = m_threads.begin(); iter != m_threads.end(); iter++)
	{
		ThreadData = (*iter).second;
		if(ThreadData.pIContext != NULL)
		{
			pIContext = m_threads[ThreadData.dwThreadId].pIContext;
			break;
		}
	}
	m_objThreadSync.Release();
	return pIContext;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::AssignContext
In Parameters  : IExecContext *pIContext,
Out Parameters : bool
Description    : Assigns Context to the Thread
Author & Date  :  & 24 Dec, 2009.
--------------------------------------------------------------------------------------*/
bool CMaxThreadPool::AssignContext(IExecContext *pIContext)
{
	bool bRet = FALSE;
	m_objThreadSync.Acquire();
	ThreadMap::iterator iter;
	_ThreadData ThreadData;
	for(iter = m_threads.begin(); iter != m_threads.end(); iter++)
	{
		ThreadData = (*iter).second;
		if(ThreadData.bFree && (ThreadData.pIContext == NULL))
		{
			m_threads[ThreadData.dwThreadId].pIContext = pIContext;
			m_ExecCntxtList.push_back(pIContext);
			bRet = true;
			break;
		}
	}
	m_objThreadSync.Release();
	if(m_ExecCntxtList.size() == m_nPoolSize)
	{
		ReInitExecContext();
	}
	return bRet;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::GetContext
In Parameters  : DWORD nContextIndex,
Out Parameters : IExecContext*
Description    : Get the Context according to Context index
Author & Date  :  & 24 Dec, 2009.
--------------------------------------------------------------------------------------*/
IExecContext* CMaxThreadPool::GetContext(DWORD nContextIndex)
{
	if(m_ExecCntxtList.size() > nContextIndex)
	{
		return m_ExecCntxtList[nContextIndex];
	}
	return NULL;
}

/*--------------------------------------------------------------------------------------
Function       : CMaxThreadPool::ClearExecutionContext
In Parameters  :
Out Parameters : void
Description    : Clears the execution list.The context object will be deleted by the caller
Author & Date  : Darshit Kasliwal & 30 Dec, 2009.
--------------------------------------------------------------------------------------*/
void CMaxThreadPool::ClearExecutionContext()
{
	if(m_arrThreadHandle == NULL)
	{
		return;
	}
	m_ExecCntxtList.clear();
	m_objThreadSync.Acquire();
	ThreadMap::iterator iter;
	_ThreadData *ThreadData;
	for(iter = m_threads.begin(); iter != m_threads.end(); iter++)
	{
		ThreadData = &(*iter).second;
		ThreadData->bFree = true;
		ThreadData->pIContext = NULL;
	}
	m_bExecContextInit = false;
	m_objThreadSync.Release();
}

void CMaxThreadPool::ReInitExecContext()
{
	m_objThreadSync.Acquire();
	ThreadMap::iterator iter;
	_ThreadData *ThreadData = NULL;
	for(iter = m_threads.begin(); iter != m_threads.end(); iter++)
	{
		ThreadData = &(*iter).second;
		ThreadData->pIContext->Initialize(ThreadData->WaitHandle);
	}
	m_objThreadSync.Release();
}