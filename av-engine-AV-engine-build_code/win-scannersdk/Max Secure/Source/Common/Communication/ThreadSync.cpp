/*======================================================================================
FILE             : ThreadSync.cpp
ABSTRACT         : Thread synchronization class, provides mutually exclusive access to code or data
DOCUMENTS	     : 
AUTHOR		     : Anand Srivastava
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created in 2011 as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 14/Mar/2011
NOTES		     : Defines the class behaviors for the application
VERSION HISTORY  : 
======================================================================================*/
#include "pch.h"
#include "ThreadSync.h"

CThreadSync::CThreadSync(LPCTSTR szMutexName)
{
	m_hMutex = CreateMutex(NULL, FALSE, szMutexName);
	if(NULL == m_hMutex)
	{
		AddLogEntry(_T("Mutex creation failed for thread synchronization"));
	}
}

CThreadSync::~CThreadSync()
{
	CloseHandle(m_hMutex);
}

void CThreadSync::Acquire()
{
	switch(WaitForSingleObject(m_hMutex, INFINITE))
	{
	case WAIT_ABANDONED_0:
		AddLogEntry(_T("Wait abandoned, protected data may be corrupt"));
		break;

	case WAIT_OBJECT_0:
		//AddLogEntry(_T("Wait successfull, got ownership of object"));
		break;

	case WAIT_TIMEOUT:
		AddLogEntry(_T("Wait timeout, should not have timed out as waiting for infinite"));
		break;

	case WAIT_FAILED:
		AddLogEntry(_T("Wait failed, may result in unexpected behaviour"));
		break;
	}
}

void CThreadSync::Release()
{
	ReleaseMutex(m_hMutex);
}
