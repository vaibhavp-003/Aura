/*======================================================================================
FILE             : ThreadSync.h
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
#pragma once

class CThreadSync
{
public:
	CThreadSync(LPCTSTR szMutexName = NULL);
	~CThreadSync();

	void Acquire();
	void Release();

private:
	HANDLE m_hMutex;
};

class CAutoThreadSync:public CThreadSync
{
public:
	CAutoThreadSync(LPCTSTR szMutexName):CThreadSync(szMutexName){Acquire();}
	~CAutoThreadSync(){Release();}
};

