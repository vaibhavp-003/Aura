/*======================================================================================
FILE             : MaxCommunicatorServer.cpp
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
				  
CREATION DATE    : 5/14/2009
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "MaxCommunicatorServer.h"
#include "MaxNamedPipeListener.h"
#include "MaxExceptionFilter.h"

const int MAX_CLOSE_TIMEOUT = 5000;
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CMaxCommunicatorServer
In Parameters  : const TCHAR* tchPipeName, CallBackFunctionPtr fnPtrCallBack, DWORD dwSize,
Out Parameters :
Description    : C'tor Uses the Pipe Name for server and Callback ptr for Data handling
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CMaxCommunicatorServer::CMaxCommunicatorServer(const TCHAR* tchPipeName, CallBackFunctionPtr fnPtrCallBack, DWORD dwSize)
{
	_tcscpy_s(m_tchPipe, tchPipeName);
	m_fnPtrCallBack = fnPtrCallBack;
	m_dwStructSize = dwSize;
	m_bMonitorConnections = false;
	m_hServerStopEvent = ::CreateEvent(NULL, FALSE, FALSE, NULL);
	m_hLastClientDisconnectEvent = ::CreateEvent(NULL, FALSE, FALSE, NULL);
	m_bServerRunning = false;
	m_SingleEventSys = CreateEvent(NULL, FALSE, TRUE, NULL);
}

/*--------------------------------------------------------------------------------------
Function       : ~CMaxCommunicatorServer
In Parameters  :
Out Parameters :
Description    : D'tor
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
CMaxCommunicatorServer::~CMaxCommunicatorServer()
{
	if(m_bServerRunning)
	{
		StopServer();
		m_bServerRunning = false;
	}

	if(m_hServerStopEvent)
	{
		::CloseHandle(m_hServerStopEvent);
		m_hServerStopEvent = NULL;
	}

	if(m_hLastClientDisconnectEvent)
	{
		::CloseHandle(m_hLastClientDisconnectEvent);
		m_hLastClientDisconnectEvent = NULL;
	}
	CMaxNamedPipeListener::m_bStopListener = false;

	if(m_SingleEventSys)
	{
		CloseHandle(m_SingleEventSys);
		m_SingleEventSys = NULL;
	}
}


/*--------------------------------------------------------------------------------------
Function       : StopReadFileCall
In Parameters  : void,
Out Parameters : NONE
Description    : This function make sure the ReadFile call is unblocked when the server
				 is shutting down!
Author         : Darshan Singh Virdi
--------------------------------------------------------------------------------------*/
void CMaxCommunicatorServer::StopReadFileCall()
{
	for (TMaxNamedPipeListenerList::iterator it = m_PipeListenerList.begin(); it != m_PipeListenerList.end(); it++)
	{
		CMaxNamedPipeListener* pPipeListener = (*it);
		if(pPipeListener)
		{
			pPipeListener->UnBlockReadFileWait();
		}
	}
}

/*--------------------------------------------------------------------------------------
Function       : StopServer
In Parameters  :
Out Parameters : bool
Description    : Send stop request to all connections and then perform a graceful shutdown
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CMaxCommunicatorServer::StopServer()
{
	__try
	{
		// Darshan: 30-May-2012
		// We must make sure all the threads get the shutdown event.
		// They could be waiting on WaitforMultipleObject or ReadFile
		WaitForSingleObject(m_SingleEventSys, INFINITE);
		CMaxNamedPipeListener::m_bStopListener = true;

		int iCount = m_PipeListenerList.size();

		if(iCount > 0)
		{
			StopReadFileCall();
		}

		SetEvent(m_SingleEventSys);

		if(m_hServerStopEvent)
		{
			for(int iCtr = 0; iCtr < iCount; iCtr++)
			{
				SetEvent(m_hServerStopEvent);
			}
		}

		if(iCount > 0)
		{
			switch(::WaitForSingleObject(m_hLastClientDisconnectEvent, MAX_CLOSE_TIMEOUT))
			{
				case WAIT_TIMEOUT:
					break;
				default:
					break;
			}
		}

		m_bMonitorConnections = false;
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Comm Stop Server")))
	{
	}
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : Run
In Parameters  : bool bMonitorConnections, bool bSingleThreaded,
Out Parameters : bool
Description    : Start the Comm server
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CMaxCommunicatorServer::Run(bool bMonitorConnections,bool bSingleThreaded)
{
	m_bServerRunning = true;
	m_bMonitorConnections = bMonitorConnections;
	CMaxNamedPipeListener::m_bSingleThreaded = bSingleThreaded;
	return RunPipeReader();
}

/*--------------------------------------------------------------------------------------
Function       : RunPipeReader
In Parameters  :
Out Parameters : bool
Description    : Starts the Pipe reader
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CMaxCommunicatorServer::RunPipeReader()
{
	WaitForSingleObject(m_SingleEventSys, INFINITE);
	if(CMaxNamedPipeListener::m_bStopListener)
	{
		SetEvent(m_SingleEventSys);
		return false;
	}
	CMaxNamedPipeListener* pPipeListener = new CMaxNamedPipeListener(this);
	pPipeListener->m_bMonitorConnections = m_bMonitorConnections;
	pPipeListener->m_hServerStopEvent = m_hServerStopEvent;
	pPipeListener->m_hLastClientDisconnectEvent = m_hLastClientDisconnectEvent;

	m_PipeListenerList.push_back(pPipeListener);

	bool bReturnVal = pPipeListener->StartReader();
	SetEvent(m_SingleEventSys);

	return bReturnVal;
}

/*--------------------------------------------------------------------------------------
Function       : OnConnectingPipe
In Parameters  :
Out Parameters : void
Description    : Called on every new connection which also spawns the new connection thread
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CMaxCommunicatorServer::OnConnectingPipe()
{
	__try
	{
		RunPipeReader();
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Comm Run Mode")))
	{
	}
}

/*--------------------------------------------------------------------------------------
Function       : OnDisConnectingPipe
In Parameters  : CMaxNamedPipeListener* pListener,
Out Parameters : void
Description    : Callback on pipe disconnect
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CMaxCommunicatorServer::OnDisConnectingPipe(CMaxNamedPipeListener* pListener)
{
	if(NULL == pListener)
	{
		return;
	}

	WaitForSingleObject(m_SingleEventSys, INFINITE);

	if(m_PipeListenerList.size() > 0)
	{
		m_PipeListenerList.remove(pListener);
		delete pListener;
		pListener = NULL;
	}

	if((CMaxNamedPipeListener::m_bStopListener && m_PipeListenerList.size() == 0) || CMaxNamedPipeListener::m_bSingleThreaded)
	{
		if(m_hLastClientDisconnectEvent)
		{
			::SetEvent(m_hLastClientDisconnectEvent);
		}
	}
	SetEvent(m_SingleEventSys);
}

/*--------------------------------------------------------------------------------------
Function       : OnIncomingData
In Parameters  : LPVOID lpParam,
Out Parameters : void
Description    : callback from server for Data receive.Calls the user registerd callback function
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
void CMaxCommunicatorServer::OnIncomingData(LPVOID lpParam)
{
	__try
	{
		m_fnPtrCallBack(lpParam);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception from CallBack Function")))
	{

	}
}

/*--------------------------------------------------------------------------------------
Function       : GetPipeName
In Parameters  : void,
Out Parameters : TCHAR*
Description    : Returns the Pipe Name
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
TCHAR* CMaxCommunicatorServer::GetPipeName(void)
{
	return m_tchPipe;
}

/*--------------------------------------------------------------------------------------
Function       : GetStructSize
In Parameters  : void,
Out Parameters : DWORD
Description    : Returns the struct size that is used for communication
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
DWORD CMaxCommunicatorServer::GetStructSize(void)
{
	return m_dwStructSize;
}

/*--------------------------------------------------------------------------------------
Function       : SendResponse
In Parameters  : LPVOID lpData,
Out Parameters : bool
Description    : Sending a response from the communication server to the MaxComunicator
object
Author         : Darshit Kasliwal
--------------------------------------------------------------------------------------*/
bool CMaxCommunicatorServer::SendResponse(LPVOID lpData)
{
	WaitForSingleObject(m_SingleEventSys, INFINITE);
	for (TMaxNamedPipeListenerList::iterator it = m_PipeListenerList.begin(); it != m_PipeListenerList.end(); it++)
	{
		CMaxNamedPipeListener* pPipeListener = (*it);
		if(pPipeListener)
		{
			if(pPipeListener->m_nID == GetCurrentThreadId())
			{
				bool bReturnVal = pPipeListener->SendResponse(lpData);
				SetEvent(m_SingleEventSys);
				return bReturnVal;
			}
		}
	}
	SetEvent(m_SingleEventSys);
	return false;
}