/*======================================================================================
FILE             : MaxNamedPipeListener.h
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
NOTES		     : declares IMaxNamedPipeData interface which is used by Communication server
                   for communicating with named pipe connections
				   CMaxNamedPipeListener implements a single named pipe connection
				   which is maintained in the NamedPiped listener list
VERSION HISTORY  : 
======================================================================================*/
#pragma once;

#include "MaxConstant.h"

class CMaxNamedPipeListener;

interface IMaxNamedPipeData
{
	virtual void OnIncomingData(LPVOID lpParam) = 0;
	virtual void OnConnectingPipe() = 0;
	virtual void OnDisConnectingPipe(CMaxNamedPipeListener* pReader) = 0;
	virtual TCHAR* GetPipeName(void) = 0;
	virtual DWORD GetStructSize(void) = 0;
	virtual bool SendResponse(LPVOID lpData) = 0;
};

class CMaxNamedPipeListener
{
public:
	CMaxNamedPipeListener(IMaxNamedPipeData* pDest);
	~CMaxNamedPipeListener();

	bool StartReader(void);
	bool SendResponse(LPVOID lpResponse);
	void UnBlockReadFileWait();
	static bool m_bStopListener;
	static bool m_bSingleThreaded;
	DWORD	m_nID;
	bool m_bMonitorConnections;
	HANDLE m_hServerStopEvent;
	HANDLE m_hLastClientDisconnectEvent;

private:
	static DWORD WINAPI NamedPipeListenerThread(LPVOID lParam);
	bool ReadPipe(void);
	void Cleanup();
	
	HANDLE	m_hPipe;
	HANDLE	m_hThread;
	HANDLE m_hOverlap[2];
	IMaxNamedPipeData* m_pDest;
};