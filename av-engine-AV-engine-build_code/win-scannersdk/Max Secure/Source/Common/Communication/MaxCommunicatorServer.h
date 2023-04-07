/*======================================================================================
FILE             : MaxCommunicatorServer.h
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
NOTES		     : Implements the communication server using Named pipes
                   It uses Overlapped IO and spawns a new connection thread for every
				   new connection request. Named Piped listener list is maintained for 
				   for all open connections
				   
VERSION HISTORY  : 
======================================================================================*/
#pragma once

#include <list>
#include "MaxNamedPipeListener.h"

typedef std::list<CMaxNamedPipeListener*> TMaxNamedPipeListenerList;
typedef void (*CallBackFunctionPtr)(LPVOID lpParam);

class CMaxCommunicatorServer : public IMaxNamedPipeData
{
public:
	CMaxCommunicatorServer(const TCHAR* tchPipeName, CallBackFunctionPtr fnPtrCallBack, DWORD dwSize);
	virtual ~CMaxCommunicatorServer();

	bool Run(bool bMonitorConnections = false,bool bSingleThreaded = false);
	virtual bool SendResponse(LPVOID lpData);
	virtual bool StopServer();
protected:
	virtual void OnIncomingData(LPVOID sMaxPipeData);
	virtual void OnConnectingPipe();
	virtual void OnDisConnectingPipe(CMaxNamedPipeListener* pListener);
	virtual TCHAR* GetPipeName(void);
	virtual DWORD GetStructSize(void);
private:
	bool RunPipeReader(void);
	void StopReadFileCall();
	TMaxNamedPipeListenerList	m_PipeListenerList;
	HANDLE m_SingleEventSys;
	CallBackFunctionPtr			m_fnPtrCallBack;
	TCHAR						m_tchPipe[MAX_PATH];
	DWORD						m_dwStructSize;
	bool m_bMonitorConnections;
	bool m_bServerRunning;
	HANDLE m_hServerStopEvent;
	HANDLE m_hLastClientDisconnectEvent;

};